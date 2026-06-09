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

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use super::glob::{host_matches, HostPattern};
use super::ConfigError;

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
            "host" | "originalhost" | "user" | "localuser" => {
                if i + 1 >= args.len() {
                    return Err(ConfigError::BadValue {
                        line: line_no,
                        keyword: "match".to_string(),
                        msg: alloc::format!("Match {kw} requires a pattern-list argument"),
                    });
                }
                let patterns = parse_match_pattern_list(&args[i + 1]);
                let cond = match kw.as_str() {
                    "host" => MatchCondition::Host(patterns),
                    "originalhost" => MatchCondition::OriginalHost(patterns),
                    "user" => MatchCondition::User(patterns),
                    "localuser" => MatchCondition::LocalUser(patterns),
                    _ => unreachable!(),
                };
                out.push(cond);
                i += 2;
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
}
