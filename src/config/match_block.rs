//! `Match` block conditions for `ssh_config(5)`.
//!
//! A `Match` line is a sequence of *criteria*; the block applies iff every
//! criterion matches. Each criterion that takes a pattern-list (`host`,
//! `originalhost`, `user`, `localuser`) reuses the [`HostPattern`] matcher
//! already used for `Host` blocks (`,`-separated, `*` / `?` globs, `!`
//! negation per pattern).
//!
//! We support the subset that's meaningful for a client-side library that
//! does no hostname canonicalisation:
//!
//! - `host`, `originalhost`, `user`, `localuser` — pattern-list matches.
//! - `all` — unconditional match (alone or with other always-true criteria).
//! - `exec <cmd>` — runs `/bin/sh -c <cmd>`; matches iff exit status is 0.
//!   **Default-deny**: requires the caller to opt in via
//!   [`SshClientConfig::enable_match_exec`](super::SshClientConfig::enable_match_exec).
//!   Running shell commands during config parse is a confused-deputy hazard.
//! - `canonical` / `final` — parsed but never match in the first cut, since
//!   we don't perform `CanonicalizeHostname` (they only fire on the
//!   post-canonicalisation pass).

use core::net::IpAddr;

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use super::ConfigError;
use super::glob::{HostPattern, glob_match, host_matches};

/// One entry in a `Match address` / `Match localaddress` pattern list.
///
/// OpenSSH accepts three textual forms per entry, each optionally negated with
/// a leading `!`:
///
/// - a CIDR range (`192.0.2.0/24`, `2001:db8::/32`) — matched numerically;
/// - a bare address (`192.0.2.7`, `::1`) — treated as a `/32` (v4) or `/128`
///   (v6) CIDR;
/// - a textual glob (`192.0.2.*`, `10.?.?.?`) — matched against the address's
///   string form when it contains `*` / `?`. This is the documented OpenSSH
///   fallback for hosts whose address can't be parsed as a CIDR.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddressPattern {
    /// Whether a match on `kind` *excludes* the address (`!`-prefixed).
    pub negated: bool,
    /// The matchable body.
    pub kind: AddressKind,
}

/// The body of an [`AddressPattern`] (after stripping any `!`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AddressKind {
    /// A numeric CIDR: base address plus prefix length in bits.
    Cidr {
        /// Network base address.
        base: IpAddr,
        /// Prefix length in bits (`0..=32` for v4, `0..=128` for v6).
        prefix: u8,
    },
    /// A textual glob applied to the address's string form.
    Glob(String),
}

impl AddressPattern {
    /// Parse one comma-list entry. Never fails: an entry that is neither a
    /// valid CIDR nor a bare address is recorded as a [`AddressKind::Glob`],
    /// matching OpenSSH's "fall back to textual matching" behaviour.
    pub fn parse(token: &str) -> Self {
        let (negated, body) = match token.strip_prefix('!') {
            Some(rest) => (true, rest),
            None => (false, token),
        };
        let kind = parse_address_kind(body);
        AddressPattern { negated, kind }
    }
}

/// Parse the body (no `!`) of an address pattern into a [`AddressKind`].
fn parse_address_kind(body: &str) -> AddressKind {
    if let Some((addr_s, prefix_s)) = body.split_once('/') {
        if let (Ok(base), Ok(prefix)) = (addr_s.parse::<IpAddr>(), prefix_s.parse::<u8>()) {
            let max = if base.is_ipv4() { 32 } else { 128 };
            if prefix <= max {
                return AddressKind::Cidr { base, prefix };
            }
        }
        // Malformed CIDR → fall back to a textual glob over the raw entry.
        return AddressKind::Glob(body.to_string());
    }
    if let Ok(base) = body.parse::<IpAddr>() {
        let prefix = if base.is_ipv4() { 32 } else { 128 };
        return AddressKind::Cidr { base, prefix };
    }
    AddressKind::Glob(body.to_string())
}

/// Parse a comma-separated `Match address` argument into a list of patterns.
fn parse_address_list(s: &str) -> Vec<AddressPattern> {
    s.split(',')
        .filter(|t| !t.is_empty())
        .map(AddressPattern::parse)
        .collect()
}

/// Whether the two addresses share the same family and `addr` falls inside
/// the `base`/`prefix` network. Mixed families never match.
fn cidr_contains(base: IpAddr, prefix: u8, addr: IpAddr) -> bool {
    match (base, addr) {
        (IpAddr::V4(b), IpAddr::V4(a)) => {
            let bits = u32::from(b);
            let abits = u32::from(a);
            if prefix == 0 {
                return true;
            }
            if prefix > 32 {
                return false;
            }
            let mask = u32::MAX.checked_shl(32 - prefix as u32).unwrap_or(0);
            (bits & mask) == (abits & mask)
        }
        (IpAddr::V6(b), IpAddr::V6(a)) => {
            let bits = u128::from(b);
            let abits = u128::from(a);
            if prefix == 0 {
                return true;
            }
            if prefix > 128 {
                return false;
            }
            let mask = u128::MAX.checked_shl(128 - prefix as u32).unwrap_or(0);
            (bits & mask) == (abits & mask)
        }
        _ => false,
    }
}

/// Evaluate an address pattern list against a textual address, OpenSSH style:
/// at least one positive entry matches AND no negative entry matches. An empty
/// list never matches.
///
/// CIDR / bare-address entries are matched numerically (so `192.0.2.0/24`
/// matches `192.0.2.7`); glob entries are matched against the textual form.
pub fn address_matches(patterns: &[AddressPattern], addr_str: &str) -> bool {
    if patterns.is_empty() {
        return false;
    }
    let parsed = addr_str.parse::<IpAddr>().ok();
    let mut any_positive = false;
    let mut positive_hit = false;
    for p in patterns {
        let hit = match &p.kind {
            AddressKind::Cidr { base, prefix } => {
                matches!(parsed, Some(a) if cidr_contains(*base, *prefix, a))
            }
            AddressKind::Glob(g) => glob_match(g, addr_str),
        };
        if p.negated {
            if hit {
                return false;
            }
        } else {
            any_positive = true;
            if !positive_hit && hit {
                positive_hit = true;
            }
        }
    }
    any_positive && positive_hit
}

/// One criterion on a `Match` line.
///
/// A `Match` block matches iff **all** of its conditions evaluate to true
/// (logical AND, per ssh_config(5)).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MatchCondition {
    /// `Match host <pattern-list>` — matches against the connection target
    /// (i.e. the post-`HostName`-substitution name).
    Host(Vec<HostPattern>),
    /// `Match originalhost <pattern-list>` — matches against the host name
    /// the user originally asked for (pre-substitution).
    OriginalHost(Vec<HostPattern>),
    /// `Match user <pattern-list>` — matches against the remote username.
    User(Vec<HostPattern>),
    /// `Match localuser <pattern-list>` — matches against the **local**
    /// process username (the `getuid()` → name).
    LocalUser(Vec<HostPattern>),
    /// `Match group <pattern-list>` — **server-side**. Matches iff one of the
    /// authenticated user's group names matches the pattern list. Has no
    /// meaning client-side ([`MatchContext::groups`] is `None` there, so it
    /// never matches).
    Group(Vec<HostPattern>),
    /// `Match address <cidr/glob-list>` — **server-side**. Matches the peer's
    /// remote IP against a comma-separated list of CIDR ranges
    /// (`192.0.2.0/24`, `2001:db8::/32`), bare addresses, or `*`/`?` globs on
    /// the textual form. Each entry may be negated with a leading `!`.
    Address(Vec<AddressPattern>),
    /// `Match localaddress <cidr/glob-list>` — **server-side**. Like
    /// [`MatchCondition::Address`] but matches the address the connection was
    /// accepted *on* (`local_addr()`).
    LocalAddress(Vec<AddressPattern>),
    /// `Match localport <port-list>` — **server-side**. Matches the local
    /// (listening) port against a comma-separated list of port numbers.
    LocalPort(Vec<u16>),
    /// `Match exec <cmd>` — `/bin/sh -c <cmd>` with exit status 0 = match.
    /// Treated as "never matches" unless `enable_match_exec` is set on the
    /// loader; see the security note in the module docs.
    Exec(String),
    /// `Match all` — unconditional. OpenSSH requires that `all` appear with
    /// no other criteria *other than* `canonical` / `final`; we don't enforce
    /// that here (last-token-wins behaves the same in practice).
    All,
    /// `Match canonical` — fires only on the post-canonicalisation pass.
    /// puressh does not currently canonicalise host names, so this never
    /// matches; the keyword is accepted so configs that mention it don't
    /// hard-error.
    // TODO(canonicalize): wire this up once CanonicalizeHostname lands.
    Canonical,
    /// `Match final` — same caveat as [`MatchCondition::Canonical`].
    // TODO(canonicalize): wire this up once CanonicalizeHostname lands.
    Final,
}

/// Inputs the resolver supplies to evaluate `Match` criteria.
///
/// `host` is required; the others default to `None` when the caller doesn't
/// have that information (e.g. CLI tooling that resolves a hostname before
/// looking up the user). A `Match` criterion that depends on a `None` field
/// is treated as **not matching** — i.e. we don't silently pretend a wildcard
/// matched.
#[derive(Debug, Clone, Default)]
pub struct MatchContext<'a> {
    /// Effective connection target (post-`HostName` substitution).
    pub host: &'a str,
    /// Original CLI-supplied target. Defaults to `host` if `None`.
    pub original_host: Option<&'a str>,
    /// Remote username for this connection, if known.
    pub user: Option<&'a str>,
    /// Local OS user name, if known.
    pub local_user: Option<&'a str>,
    /// **Server-side**: the peer's remote IP address (textual form), if
    /// known. `None` ⇒ `Match address` never matches.
    pub address: Option<&'a str>,
    /// **Server-side**: the local (accepting) IP address, if known. `None` ⇒
    /// `Match localaddress` never matches.
    pub local_address: Option<&'a str>,
    /// **Server-side**: the local (listening) port, if known. `None` ⇒
    /// `Match localport` never matches.
    pub local_port: Option<u16>,
    /// **Server-side**: the authenticated user's group names, if resolved.
    /// `None` ⇒ `Match group` never matches (mirrors the user/localuser
    /// convention — a criterion that depends on a missing field is treated as
    /// not-matching, never as a silent wildcard).
    pub groups: Option<&'a [String]>,
}

impl MatchContext<'_> {
    /// Resolve `original_host`, falling back to `host` per the convention that
    /// OpenSSH uses when no rewriting has occurred.
    pub fn original_host_or_host(&self) -> &str {
        self.original_host.unwrap_or(self.host)
    }
}

/// Tokenize the arguments of a `Match` line into a vector of conditions.
///
/// Returns an error on unknown criteria or missing arguments. Recognised
/// criteria are case-insensitive (per OpenSSH); pattern-list arguments are
/// passed through verbatim (no case-folding on the pattern side).
pub fn parse_match_line(
    args: &[String],
    line_no: usize,
) -> Result<Vec<MatchCondition>, ConfigError> {
    parse_match_line_impl(args, line_no, MatchSide::Client)
}

/// Server-side variant of [`parse_match_line`]. Recognises the additional
/// `group`, `address`, `localaddress`, and `localport` criteria, and rejects
/// the client-only criteria (`host`, `originalhost`, `localuser`) plus
/// `rdomain` / `connection` as [`ConfigError::Unsupported`] — they have no
/// server-side meaning in puressh.
pub fn parse_match_line_server(
    args: &[String],
    line_no: usize,
) -> Result<Vec<MatchCondition>, ConfigError> {
    parse_match_line_impl(args, line_no, MatchSide::Server)
}

/// Which file (`ssh_config` vs `sshd_config`) a `Match` line came from. The
/// recognised criteria differ between the two sides.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MatchSide {
    Client,
    Server,
}

fn parse_match_line_impl(
    args: &[String],
    line_no: usize,
    side: MatchSide,
) -> Result<Vec<MatchCondition>, ConfigError> {
    let server = side == MatchSide::Server;
    let mut out = Vec::new();
    let mut i = 0;
    while i < args.len() {
        let kw = args[i].to_ascii_lowercase();
        match kw.as_str() {
            "all" => {
                out.push(MatchCondition::All);
                i += 1;
            }
            "canonical" => {
                out.push(MatchCondition::Canonical);
                i += 1;
            }
            "final" => {
                out.push(MatchCondition::Final);
                i += 1;
            }
            // Server-invalid criteria — `Host`/`OriginalHost`/`LocalUser` are
            // meaningless on the daemon side (the server is the host); reject
            // them rather than silently never-matching so a misplaced client
            // directive in sshd_config is loud.
            "host" | "originalhost" | "localuser" if server => {
                return Err(ConfigError::Unsupported {
                    line: line_no,
                    msg: alloc::format!("Match {kw} is not valid in sshd_config"),
                });
            }
            // sshd accepts these criteria but puressh has no notion of routing
            // domains or a generic connection tuple.
            "rdomain" | "connection" => {
                return Err(ConfigError::Unsupported {
                    line: line_no,
                    msg: alloc::format!("Match {kw} is not supported"),
                });
            }
            "host" | "originalhost" | "user" | "localuser" => {
                let patterns = take_pattern_list(args, &mut i, &kw, line_no)?;
                let cond = match kw.as_str() {
                    "host" => MatchCondition::Host(patterns),
                    "originalhost" => MatchCondition::OriginalHost(patterns),
                    "user" => MatchCondition::User(patterns),
                    "localuser" => MatchCondition::LocalUser(patterns),
                    _ => unreachable!(),
                };
                out.push(cond);
            }
            "group" if server => {
                let patterns = take_pattern_list(args, &mut i, &kw, line_no)?;
                out.push(MatchCondition::Group(patterns));
            }
            "address" | "localaddress" if server => {
                let raw = take_raw_arg(args, &mut i, &kw, line_no)?;
                let patterns = parse_address_list(&raw);
                if kw == "address" {
                    out.push(MatchCondition::Address(patterns));
                } else {
                    out.push(MatchCondition::LocalAddress(patterns));
                }
            }
            "localport" if server => {
                let raw = take_raw_arg(args, &mut i, &kw, line_no)?;
                let mut ports = Vec::new();
                for p in raw.split(',').filter(|t| !t.is_empty()) {
                    let port = p.parse::<u16>().map_err(|_| ConfigError::BadValue {
                        line: line_no,
                        keyword: "match".to_string(),
                        msg: alloc::format!("Match localport: bad port {p:?}"),
                    })?;
                    ports.push(port);
                }
                if ports.is_empty() {
                    return Err(ConfigError::BadValue {
                        line: line_no,
                        keyword: "match".to_string(),
                        msg: "Match localport requires at least one port".into(),
                    });
                }
                out.push(MatchCondition::LocalPort(ports));
            }
            "exec" => {
                if i + 1 >= args.len() {
                    return Err(ConfigError::BadValue {
                        line: line_no,
                        keyword: "match".to_string(),
                        msg: "Match exec requires a command argument".into(),
                    });
                }
                // `exec` consumes the REST of the line as a single command
                // string (joined by spaces, matching OpenSSH). The tokenizer
                // has already resolved quoting, so this is a faithful
                // reconstruction modulo runs of internal whitespace.
                let cmd = args[i + 1..].join(" ");
                out.push(MatchCondition::Exec(cmd));
                i = args.len();
            }
            other => {
                return Err(ConfigError::BadValue {
                    line: line_no,
                    keyword: "match".to_string(),
                    msg: alloc::format!("unknown Match criterion: {other:?}"),
                });
            }
        }
    }
    if out.is_empty() {
        return Err(ConfigError::BadValue {
            line: line_no,
            keyword: "match".to_string(),
            msg: "Match requires at least one criterion".into(),
        });
    }
    Ok(out)
}

/// Consume the single argument following `args[*i]` and return it raw,
/// advancing `*i` past both the keyword and the argument.
fn take_raw_arg(
    args: &[String],
    i: &mut usize,
    kw: &str,
    line_no: usize,
) -> Result<String, ConfigError> {
    if *i + 1 >= args.len() {
        return Err(ConfigError::BadValue {
            line: line_no,
            keyword: "match".to_string(),
            msg: alloc::format!("Match {kw} requires an argument"),
        });
    }
    let v = args[*i + 1].clone();
    *i += 2;
    Ok(v)
}

/// Consume the pattern-list argument following `args[*i]`, advancing `*i`.
fn take_pattern_list(
    args: &[String],
    i: &mut usize,
    kw: &str,
    line_no: usize,
) -> Result<Vec<HostPattern>, ConfigError> {
    let raw = take_raw_arg(args, i, kw, line_no)?;
    Ok(parse_match_pattern_list(&raw))
}

/// A `Match` pattern-list is comma-separated (unlike `Host`, which is
/// whitespace-separated). Each token still supports `!`-negation and `*` / `?`
/// globs.
fn parse_match_pattern_list(s: &str) -> Vec<HostPattern> {
    s.split(',')
        .filter(|t| !t.is_empty())
        .map(HostPattern::parse)
        .collect()
}

/// Evaluation policy for `Match exec` criteria.
///
/// Default-deny: the parser is happy to record `Match exec` blocks, but the
/// resolver skips (i.e. does not match) them unless the caller has opted in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecPolicy {
    /// `Match exec` always evaluates to "did not match" (block is skipped).
    Deny,
    /// Run the command via `/bin/sh -c` and use the exit status (0 = match).
    /// `std`-only; if the runner returns an error the criterion is treated as
    /// "did not match".
    Allow,
}

/// Evaluate one criterion against the supplied context using `policy` for
/// `exec` resolution.
pub fn evaluate(cond: &MatchCondition, ctx: &MatchContext<'_>, policy: ExecPolicy) -> bool {
    match cond {
        MatchCondition::All => true,
        // First-cut: we don't canonicalise, so the second-pass criteria never
        // fire. Returning `false` is the safe choice — an `all` is the
        // documented way to ask for "always match".
        MatchCondition::Canonical | MatchCondition::Final => false,
        MatchCondition::Host(patterns) => host_matches(patterns, ctx.host),
        MatchCondition::OriginalHost(patterns) => {
            host_matches(patterns, ctx.original_host_or_host())
        }
        MatchCondition::User(patterns) => match ctx.user {
            Some(u) => host_matches(patterns, u),
            None => false,
        },
        MatchCondition::LocalUser(patterns) => match ctx.local_user {
            Some(u) => host_matches(patterns, u),
            None => false,
        },
        MatchCondition::Group(patterns) => match ctx.groups {
            // Matches iff any of the user's groups is matched by the list.
            Some(groups) => groups.iter().any(|g| host_matches(patterns, g)),
            None => false,
        },
        MatchCondition::Address(patterns) => match ctx.address {
            Some(a) => address_matches(patterns, a),
            None => false,
        },
        MatchCondition::LocalAddress(patterns) => match ctx.local_address {
            Some(a) => address_matches(patterns, a),
            None => false,
        },
        MatchCondition::LocalPort(ports) => match ctx.local_port {
            Some(p) => ports.contains(&p),
            None => false,
        },
        MatchCondition::Exec(cmd) => match policy {
            ExecPolicy::Deny => false,
            ExecPolicy::Allow => run_exec_match(cmd),
        },
    }
}

/// True iff every condition in `conds` matches.
///
/// An empty list never matches — that matches the "must have at least one
/// criterion" invariant the parser enforces.
pub fn all_match(conds: &[MatchCondition], ctx: &MatchContext<'_>, policy: ExecPolicy) -> bool {
    if conds.is_empty() {
        return false;
    }
    conds.iter().all(|c| evaluate(c, ctx, policy))
}

/// Run `/bin/sh -c cmd`; return `true` iff the child exits with status 0.
///
/// Only compiled under `std`. Without `std` we can't spawn a process; the
/// caller will never invoke us because `ExecPolicy::Allow` requires the
/// std-only loader entry points anyway.
#[cfg(feature = "std")]
fn run_exec_match(cmd: &str) -> bool {
    use std::process::Command;
    #[cfg(unix)]
    let result = Command::new("/bin/sh").arg("-c").arg(cmd).status();
    #[cfg(windows)]
    let result = Command::new("cmd").arg("/C").arg(cmd).status();
    #[cfg(not(any(unix, windows)))]
    let result: Result<std::process::ExitStatus, std::io::Error> = Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "Match exec is not supported on this platform",
    ));
    match result {
        Ok(status) => status.success(),
        Err(_) => false,
    }
}

#[cfg(not(feature = "std"))]
fn run_exec_match(_cmd: &str) -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx<'a>(host: &'a str) -> MatchContext<'a> {
        MatchContext {
            host,
            original_host: None,
            user: None,
            local_user: None,
            ..MatchContext::default()
        }
    }

    #[test]
    fn parse_all_alone() {
        let args = vec!["all".to_string()];
        let conds = parse_match_line(&args, 1).unwrap();
        assert_eq!(conds, vec![MatchCondition::All]);
    }

    #[test]
    fn parse_host_with_pattern_list() {
        let args = vec!["host".to_string(), "*.example.com,!secret.*".to_string()];
        let conds = parse_match_line(&args, 1).unwrap();
        match &conds[0] {
            MatchCondition::Host(p) => {
                assert_eq!(p.len(), 2);
            }
            _ => panic!("wrong cond"),
        }
    }

    #[test]
    fn parse_missing_argument_errors() {
        let args = vec!["host".to_string()];
        let err = parse_match_line(&args, 7).unwrap_err();
        match err {
            ConfigError::BadValue { line, .. } => assert_eq!(line, 7),
            _ => panic!("wrong err: {err:?}"),
        }
    }

    #[test]
    fn parse_unknown_criterion_errors() {
        let args = vec!["address".to_string(), "1.2.3.4".to_string()];
        let err = parse_match_line(&args, 3).unwrap_err();
        match err {
            ConfigError::BadValue { line, .. } => assert_eq!(line, 3),
            _ => panic!("wrong err: {err:?}"),
        }
    }

    #[test]
    fn parse_empty_errors() {
        let err = parse_match_line(&[], 1).unwrap_err();
        match err {
            ConfigError::BadValue { .. } => {}
            _ => panic!("wrong err: {err:?}"),
        }
    }

    #[test]
    fn evaluate_all_matches() {
        let c = ctx("anything");
        assert!(evaluate(&MatchCondition::All, &c, ExecPolicy::Deny));
    }

    #[test]
    fn evaluate_canonical_never_matches() {
        let c = ctx("anything");
        assert!(!evaluate(&MatchCondition::Canonical, &c, ExecPolicy::Deny));
        assert!(!evaluate(&MatchCondition::Final, &c, ExecPolicy::Deny));
    }

    #[test]
    fn evaluate_user_missing_in_context_is_no_match() {
        let conds = parse_match_line(&["user".to_string(), "alice".to_string()], 1).unwrap();
        let c = ctx("h"); // no user
        assert!(!all_match(&conds, &c, ExecPolicy::Deny));
    }

    #[test]
    fn evaluate_exec_denied_by_default() {
        let conds = parse_match_line(&["exec".to_string(), "true".to_string()], 1).unwrap();
        let c = ctx("h");
        assert!(!all_match(&conds, &c, ExecPolicy::Deny));
    }

    #[test]
    fn parse_match_pattern_list_skips_empties() {
        let pats = parse_match_pattern_list("a,,b");
        assert_eq!(pats.len(), 2);
    }

    // ---- server-side criteria --------------------------------------------

    #[test]
    fn server_parses_address_group_localport() {
        let args = vec![
            "address".to_string(),
            "192.0.2.0/24,!192.0.2.7".to_string(),
            "group".to_string(),
            "admin,wheel".to_string(),
            "localport".to_string(),
            "22,2222".to_string(),
        ];
        let conds = parse_match_line_server(&args, 1).unwrap();
        assert_eq!(conds.len(), 3);
        assert!(matches!(conds[0], MatchCondition::Address(_)));
        assert!(matches!(conds[1], MatchCondition::Group(_)));
        assert!(matches!(&conds[2], MatchCondition::LocalPort(p) if p == &[22, 2222]));
    }

    #[test]
    fn server_rejects_client_only_criteria() {
        for kw in ["host", "originalhost", "localuser"] {
            let args = vec![kw.to_string(), "x".to_string()];
            let err = parse_match_line_server(&args, 3).unwrap_err();
            assert!(
                matches!(err, ConfigError::Unsupported { line: 3, .. }),
                "{kw}: got {err:?}"
            );
        }
    }

    #[test]
    fn server_rejects_rdomain_connection() {
        for kw in ["rdomain", "connection"] {
            let args = vec![kw.to_string(), "x".to_string()];
            let err = parse_match_line_server(&args, 5).unwrap_err();
            assert!(matches!(err, ConfigError::Unsupported { line: 5, .. }));
        }
    }

    #[test]
    fn client_still_rejects_server_criteria() {
        // `address` is a server criterion; the client parser must still treat
        // it as an unknown criterion (BadValue), preserving prior behaviour.
        let args = vec!["address".to_string(), "1.2.3.4".to_string()];
        let err = parse_match_line(&args, 1).unwrap_err();
        assert!(matches!(err, ConfigError::BadValue { line: 1, .. }));
    }

    #[test]
    fn address_cidr_v4_match() {
        let pats = parse_address_list("192.0.2.0/24");
        assert!(address_matches(&pats, "192.0.2.7"));
        assert!(!address_matches(&pats, "192.0.3.7"));
    }

    #[test]
    fn address_bare_v4_is_host_route() {
        let pats = parse_address_list("192.0.2.7");
        assert!(address_matches(&pats, "192.0.2.7"));
        assert!(!address_matches(&pats, "192.0.2.8"));
    }

    #[test]
    fn address_negation() {
        let pats = parse_address_list("192.0.2.0/24,!192.0.2.7");
        assert!(address_matches(&pats, "192.0.2.1"));
        assert!(!address_matches(&pats, "192.0.2.7"));
    }

    #[test]
    fn address_v6_cidr() {
        let pats = parse_address_list("2001:db8::/32");
        assert!(address_matches(&pats, "2001:db8::1"));
        assert!(!address_matches(&pats, "2001:dba::1"));
        // Mixed family never matches.
        assert!(!address_matches(&pats, "192.0.2.1"));
    }

    #[test]
    fn address_glob_fallback() {
        let pats = parse_address_list("192.0.2.*");
        assert!(address_matches(&pats, "192.0.2.55"));
        assert!(!address_matches(&pats, "192.0.3.55"));
    }

    #[test]
    fn address_zero_prefix_matches_family() {
        let pats = parse_address_list("0.0.0.0/0");
        assert!(address_matches(&pats, "8.8.8.8"));
        assert!(!address_matches(&pats, "::1"));
    }

    #[test]
    fn evaluate_group_any_member() {
        let conds =
            parse_match_line_server(&["group".to_string(), "wheel".to_string()], 1).unwrap();
        let groups = vec!["users".to_string(), "wheel".to_string()];
        let c = MatchContext {
            host: "h",
            groups: Some(&groups),
            ..MatchContext::default()
        };
        assert!(all_match(&conds, &c, ExecPolicy::Deny));
        // No groups in context ⇒ never matches.
        let c2 = ctx("h");
        assert!(!all_match(&conds, &c2, ExecPolicy::Deny));
    }
}
