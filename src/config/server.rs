//! `sshd_config(5)` parsing — see [`SshServerConfig`].
//!
//! Only the keywords the puressh `sshd` binary actually consumes today are
//! recognised; any other keyword is rejected as
//! [`ConfigError::UnknownKeyword`].
//!
//! `Match` blocks are supported: the global (pre-`Match`) options live in
//! [`SshServerConfig::global`], and each `Match` block is recorded as a
//! [`ServerMatchBlock`] carrying its conditions plus its own
//! [`ServerOptions`]. Per-connection resolution
//! ([`SshServerConfig::resolve`]) starts from the global options and merges
//! every matching block with OpenSSH semantics: **first-match-wins** for
//! scalars and **concatenation** for cumulative list fields.

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use super::ConfigError;
use super::algos::{AlgoCategory, resolve_algo_list};
use super::match_block::{
    ExecPolicy, MatchCondition, MatchContext, all_match, parse_match_line_server,
};
use super::parser::{ParsedLine, tokenize};

/// `PermitRootLogin` policy.
///
/// puressh only implements public-key authentication, so the OpenSSH
/// `password`-vs-`publickey` distinction collapses: `Yes` and
/// `ProhibitPassword` both permit a root login by key, while `No` forbids
/// the root account entirely. OpenSSH's fourth value,
/// `forced-commands-only`, has no analogue here — puressh's
/// `authorized_keys` parser carries no `command=` restriction — so it is
/// rejected at parse time rather than silently behaving like `No`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PermitRootLogin {
    /// Root may log in (by key — the only method puressh offers).
    Yes,
    /// Root may never authenticate, regardless of `AllowUsers`/keys.
    No,
    /// Root may log in by public key but not by password. Equivalent to
    /// `Yes` in puressh (no password auth exists); the OpenSSH default.
    ProhibitPassword,
}

impl PermitRootLogin {
    /// Whether the root account may authenticate via public key under this
    /// policy. Only [`PermitRootLogin::No`] returns `false`.
    pub fn permits_publickey(self) -> bool {
        matches!(
            self,
            PermitRootLogin::Yes | PermitRootLogin::ProhibitPassword
        )
    }
}

/// One block of `sshd_config(5)` options.
///
/// Every field is `Option`-typed (or an empty `Vec`) so the binary can apply
/// OpenSSH precedence — CLI flag > config file > built-in default — using a
/// `pick(cli, cfg, default)` helper, and so [`SshServerConfig::resolve`] can
/// merge blocks with first-match-wins scalars and concatenated lists.
///
/// Auth/access keywords are constrained by puressh implementing only
/// public-key authentication: `PasswordAuthentication yes`,
/// `KbdInteractiveAuthentication yes`, multi-factor `AuthenticationMethods`,
/// and `PermitEmptyPasswords yes` are rejected at parse time rather than
/// silently accepted.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ServerOptions {
    /// `Port` — default 22 (OpenSSH default; puressh's CLI default differs).
    pub port: Option<u16>,
    /// `ListenAddress` entries — cumulative; one bind socket per entry. Each
    /// is a `host[:port]` literal; missing port inherits `port`. Stored as
    /// raw strings (parsed at bind time so a v6 literal `[::1]:22` stays
    /// readable).
    pub listen_addresses: Vec<String>,
    /// `HostKey` entries — cumulative.
    pub host_key_files: Vec<String>,
    /// `AuthorizedKeysFile`.
    pub authorized_keys_file: Option<String>,
    /// `AllowUsers` — cumulative; empty ⇒ "current user only" (matches the
    /// existing CLI default behaviour).
    pub allow_users: Vec<String>,
    /// `LoginGraceTime` in seconds; `0` disables.
    pub login_grace_time: Option<u32>,
    /// `MaxStartups` (first sub-field only — the OpenSSH `start:rate:full`
    /// triple is rejected as a bad value).
    pub max_startups: Option<u32>,
    /// `AllowAgentForwarding` (yes/no).
    pub allow_agent_forwarding: Option<bool>,
    /// `X11Forwarding` (yes/no).
    pub x11_forwarding: Option<bool>,
    /// `AcceptEnv` patterns — cumulative.
    pub accept_env: Vec<String>,
    /// `StrictModes` (yes/no).
    pub strict_modes: Option<bool>,
    /// `LogLevel`: 0 = QUIET/INFO, 1 = VERBOSE/DEBUG1, 2 = DEBUG2, 3 = DEBUG3.
    pub log_level: Option<u8>,
    /// puressh-specific: `SftpEnabled` (yes/no). `sshd_config(5)` expresses
    /// this via `Subsystem sftp ...`; we expose a direct toggle instead.
    pub sftp_enabled: Option<bool>,
    /// puressh-specific: `SftpReadOnly` (yes/no).
    pub sftp_read_only: Option<bool>,
    /// puressh-specific: `SftpRoot` — chroot-like root for the SFTP subsystem.
    pub sftp_root: Option<String>,
    /// puressh-specific: `ScpEnabled` (yes/no).
    pub scp_enabled: Option<bool>,
    /// `PermitRootLogin` — `yes` / `no` / `prohibit-password`
    /// (alias `without-password`). `forced-commands-only` is rejected as
    /// unsupported. Default (applied by the binary) is `prohibit-password`.
    pub permit_root_login: Option<PermitRootLogin>,
    /// `Ciphers` — resolved cipher preference list (strict-validated, list
    /// modifiers applied). `None` ⇒ built-in default.
    pub ciphers: Option<Vec<String>>,
    /// `MACs` — resolved MAC preference list.
    pub macs: Option<Vec<String>>,
    /// `KexAlgorithms` — resolved key-exchange preference list (no markers).
    pub kex_algorithms: Option<Vec<String>>,
    /// `HostKeyAlgorithms` — resolved server host-key preference list.
    pub host_key_algorithms: Option<Vec<String>>,
    /// `PubkeyAuthentication` (yes/no). `no` ⇒ public-key auth is dropped from
    /// the advertised method set, which (since it is the only honorable
    /// method) locks the connection out. `None`/`yes` ⇒ enabled.
    pub pubkey_authentication: Option<bool>,
    /// `PasswordAuthentication` (yes/no). Only `no` is honorable (puressh has
    /// no password auth); `yes` is rejected at parse time as
    /// [`ConfigError::Unsupported`]. Stored so a future password
    /// implementation can read it.
    pub password_authentication: Option<bool>,
    /// `KbdInteractiveAuthentication` (alias `ChallengeResponseAuthentication`)
    /// (yes/no). Same honorability rule as `password_authentication`.
    pub kbd_interactive_authentication: Option<bool>,
    /// `AuthenticationMethods` — only `publickey` / `any` are honorable;
    /// anything else (a non-publickey method, or a multi-factor chain) is
    /// rejected at parse time. Stored as the raw token list for diagnostics.
    pub authentication_methods: Option<Vec<String>>,
    /// `MaxAuthTries` — disconnect after this many failed auth attempts.
    pub max_auth_tries: Option<u32>,
    /// `DenyUsers` — glob patterns; a matching user is refused (highest
    /// precedence). Cumulative.
    pub deny_users: Vec<String>,
    /// `AllowGroups` — glob patterns; if non-empty, the user must belong to a
    /// matching group. Cumulative.
    pub allow_groups: Vec<String>,
    /// `DenyGroups` — glob patterns; a user in a matching group is refused.
    /// Cumulative.
    pub deny_groups: Vec<String>,
    /// `Banner` — path to a file whose contents are sent as USERAUTH_BANNER,
    /// or the literal `none` (stored as `None`). The send is wired through the
    /// auth layer (global / address-matched banners).
    pub banner: Option<String>,
}

/// One `Match` block from an `sshd_config(5)` file: the parsed conditions
/// plus the options that apply when every condition matches.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServerMatchBlock {
    /// All conditions must match (logical AND) for `opts` to apply.
    pub conditions: Vec<MatchCondition>,
    /// Options contributed by this block.
    pub opts: ServerOptions,
}

/// A parsed `sshd_config(5)` file: global options plus any `Match` blocks.
///
/// Use [`SshServerConfig::parse`] to build one from text, then
/// [`SshServerConfig::resolve`] for a given [`MatchContext`] to flatten the
/// global options with every matching block.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SshServerConfig {
    /// Pre-`Match` ("global") options, applied to every connection.
    pub global: ServerOptions,
    /// `Match` blocks in source order.
    pub match_blocks: Vec<ServerMatchBlock>,
}

impl SshServerConfig {
    /// Parse `src` (the contents of an `sshd_config` file) into an
    /// [`SshServerConfig`].
    pub fn parse(src: &str) -> Result<Self, ConfigError> {
        Self::from_lines(tokenize(src)?)
    }

    /// Build an [`SshServerConfig`] from an already-tokenized line stream.
    /// Used by the `Include`-aware loader, which expands includes before
    /// handing the flattened stream here.
    pub fn from_lines(lines: Vec<ParsedLine>) -> Result<Self, ConfigError> {
        let mut global = ServerOptions::default();
        let mut match_blocks: Vec<ServerMatchBlock> = Vec::new();
        for line in lines {
            if line.keyword == "match" {
                let conditions = parse_match_line_server(&line.args, line.line_no)?;
                match_blocks.push(ServerMatchBlock {
                    conditions,
                    opts: ServerOptions::default(),
                });
                continue;
            }
            // Route the directive to the current block (the last Match block,
            // or global if none has opened yet).
            let in_match = !match_blocks.is_empty();
            let target = match match_blocks.last_mut() {
                Some(b) => &mut b.opts,
                None => &mut global,
            };
            if in_match {
                reject_invalid_in_match(&line)?;
            }
            apply_keyword(target, &line)?;
        }
        Ok(SshServerConfig {
            global,
            match_blocks,
        })
    }

    /// Resolve the effective [`ServerOptions`] for `ctx`: start from the
    /// global options, then merge each `Match` block whose conditions all
    /// match, in source order. Scalars are first-match-wins (an earlier
    /// contributor — global counts as earliest — keeps its value); list
    /// fields concatenate.
    ///
    /// `policy` controls `Match exec` evaluation (default-deny on the server;
    /// see [`ExecPolicy`]).
    pub fn resolve(&self, ctx: &MatchContext<'_>, policy: ExecPolicy) -> ServerOptions {
        let mut out = self.global.clone();
        for block in &self.match_blocks {
            if all_match(&block.conditions, ctx, policy) {
                merge_server_options(&mut out, &block.opts);
            }
        }
        out
    }
}

/// Merge `src` into `dst` with first-match-wins scalars (an already-set scalar
/// in `dst` is kept) and concatenated list fields.
fn merge_server_options(dst: &mut ServerOptions, src: &ServerOptions) {
    macro_rules! take_scalar {
        ($field:ident) => {
            if dst.$field.is_none() {
                dst.$field = src.$field.clone();
            }
        };
    }
    take_scalar!(port);
    take_scalar!(authorized_keys_file);
    take_scalar!(login_grace_time);
    take_scalar!(max_startups);
    take_scalar!(allow_agent_forwarding);
    take_scalar!(x11_forwarding);
    take_scalar!(strict_modes);
    take_scalar!(log_level);
    take_scalar!(sftp_enabled);
    take_scalar!(sftp_read_only);
    take_scalar!(sftp_root);
    take_scalar!(scp_enabled);
    take_scalar!(permit_root_login);
    take_scalar!(ciphers);
    take_scalar!(macs);
    take_scalar!(kex_algorithms);
    take_scalar!(host_key_algorithms);
    take_scalar!(pubkey_authentication);
    take_scalar!(password_authentication);
    take_scalar!(kbd_interactive_authentication);
    take_scalar!(authentication_methods);
    take_scalar!(max_auth_tries);
    take_scalar!(banner);
    dst.listen_addresses
        .extend(src.listen_addresses.iter().cloned());
    dst.host_key_files
        .extend(src.host_key_files.iter().cloned());
    dst.allow_users.extend(src.allow_users.iter().cloned());
    dst.accept_env.extend(src.accept_env.iter().cloned());
    dst.deny_users.extend(src.deny_users.iter().cloned());
    dst.allow_groups.extend(src.allow_groups.iter().cloned());
    dst.deny_groups.extend(src.deny_groups.iter().cloned());
}

/// Keywords that OpenSSH refuses *inside* a `Match` block (they are only
/// meaningful at file scope). Reject them with [`ConfigError::Unsupported`] so
/// a misplaced directive is loud rather than silently per-connection.
fn reject_invalid_in_match(line: &ParsedLine) -> Result<(), ConfigError> {
    const INVALID_IN_MATCH: &[&str] = &[
        "port",
        "listenaddress",
        "hostkey",
        "addressfamily",
        "pidfile",
        "loglevel",
        "compression",
        "rekeylimit",
        "logingracetime",
        "maxstartups",
        "strictmodes",
        "include",
    ];
    if INVALID_IN_MATCH.contains(&line.keyword.as_str()) {
        return Err(ConfigError::Unsupported {
            line: line.line_no,
            msg: format!("{} is not valid inside a Match block", line.keyword),
        });
    }
    Ok(())
}

fn apply_keyword(opts: &mut ServerOptions, line: &ParsedLine) -> Result<(), ConfigError> {
    let kw = line.keyword.as_str();
    match kw {
        "port" => {
            opts.port = Some(parse_u16(line)?);
        }
        "listenaddress" => {
            opts.listen_addresses.push(one_arg(line)?);
        }
        "hostkey" => {
            opts.host_key_files.push(one_arg(line)?);
        }
        "authorizedkeysfile" => {
            opts.authorized_keys_file = Some(one_arg(line)?);
        }
        "allowusers" => {
            if line.args.is_empty() {
                return Err(ConfigError::BadValue {
                    line: line.line_no,
                    keyword: kw.to_string(),
                    msg: "expected at least one user name".into(),
                });
            }
            for u in &line.args {
                // The `user@host` form needs the peer address at match time;
                // not wired yet, so reject loudly rather than match the whole
                // literal (which would never match a bare username).
                if u.contains('@') {
                    return Err(ConfigError::Unsupported {
                        line: line.line_no,
                        msg: "AllowUsers user@host form is not supported".into(),
                    });
                }
                opts.allow_users.push(u.clone());
            }
        }
        "logingracetime" => {
            opts.login_grace_time = Some(parse_duration_seconds(line)?);
        }
        "maxstartups" => {
            let s = one_arg(line)?;
            if s.contains(':') {
                return Err(ConfigError::Unsupported {
                    line: line.line_no,
                    msg: "MaxStartups start:rate:full triple not yet supported".into(),
                });
            }
            opts.max_startups = Some(s.parse::<u32>().map_err(|_| ConfigError::BadValue {
                line: line.line_no,
                keyword: kw.to_string(),
                msg: format!("expected an integer, got {s:?}"),
            })?);
        }
        "allowagentforwarding" => {
            opts.allow_agent_forwarding = Some(parse_yes_no(line)?);
        }
        "x11forwarding" => {
            opts.x11_forwarding = Some(parse_yes_no(line)?);
        }
        "acceptenv" => {
            if line.args.is_empty() {
                return Err(ConfigError::BadValue {
                    line: line.line_no,
                    keyword: kw.to_string(),
                    msg: "expected at least one env pattern".into(),
                });
            }
            for p in &line.args {
                opts.accept_env.push(p.clone());
            }
        }
        "strictmodes" => {
            opts.strict_modes = Some(parse_yes_no(line)?);
        }
        "loglevel" => {
            opts.log_level = Some(parse_log_level(line)?);
        }
        "sftpenabled" => {
            opts.sftp_enabled = Some(parse_yes_no(line)?);
        }
        "sftpreadonly" => {
            opts.sftp_read_only = Some(parse_yes_no(line)?);
        }
        "sftproot" => {
            opts.sftp_root = Some(one_arg(line)?);
        }
        "scpenabled" => {
            opts.scp_enabled = Some(parse_yes_no(line)?);
        }
        "permitrootlogin" => {
            opts.permit_root_login = Some(parse_permit_root_login(line)?);
        }
        "ciphers" => {
            opts.ciphers = Some(resolve_algo_list(
                AlgoCategory::Cipher,
                &line.args,
                line.line_no,
                "Ciphers",
            )?);
        }
        "macs" => {
            opts.macs = Some(resolve_algo_list(
                AlgoCategory::Mac,
                &line.args,
                line.line_no,
                "MACs",
            )?);
        }
        "kexalgorithms" => {
            opts.kex_algorithms = Some(resolve_algo_list(
                AlgoCategory::Kex,
                &line.args,
                line.line_no,
                "KexAlgorithms",
            )?);
        }
        "hostkeyalgorithms" => {
            opts.host_key_algorithms = Some(resolve_algo_list(
                AlgoCategory::HostKey,
                &line.args,
                line.line_no,
                "HostKeyAlgorithms",
            )?);
        }
        "casignaturealgorithms" => {
            // Certificate-based host/user keys are not implemented; reject so
            // a security-relevant directive cannot appear to take effect.
            return Err(ConfigError::Unsupported {
                line: line.line_no,
                msg: "CASignatureAlgorithms: certificate authentication is not supported".into(),
            });
        }
        "pubkeyauthentication" => {
            opts.pubkey_authentication = Some(parse_yes_no(line)?);
        }
        "passwordauthentication" => {
            // Only `no` can be honored — puressh has no password auth, so
            // `yes` would advertise a method we cannot satisfy.
            let v = parse_yes_no(line)?;
            if v {
                return Err(ConfigError::Unsupported {
                    line: line.line_no,
                    msg: "PasswordAuthentication yes: password authentication is not implemented"
                        .into(),
                });
            }
            opts.password_authentication = Some(false);
        }
        "kbdinteractiveauthentication" | "challengeresponseauthentication" => {
            let v = parse_yes_no(line)?;
            if v {
                return Err(ConfigError::Unsupported {
                    line: line.line_no,
                    msg: "KbdInteractiveAuthentication yes: keyboard-interactive authentication \
                          is not implemented"
                        .into(),
                });
            }
            opts.kbd_interactive_authentication = Some(false);
        }
        "authenticationmethods" => {
            if line.args.is_empty() {
                return Err(ConfigError::BadValue {
                    line: line.line_no,
                    keyword: kw.to_string(),
                    msg: "expected at least one method list".into(),
                });
            }
            // Each space-separated argument is one alternative; each
            // alternative is a comma-separated chain of required methods.
            // The only honorable forms are a single `publickey` (or `any`) —
            // a chain or any non-publickey factor cannot be satisfied.
            for alt in &line.args {
                if alt == "any" {
                    continue;
                }
                let factors: Vec<&str> = alt.split(',').filter(|s| !s.is_empty()).collect();
                if factors.len() != 1 || factors[0] != "publickey" {
                    return Err(ConfigError::Unsupported {
                        line: line.line_no,
                        msg: format!(
                            "AuthenticationMethods {alt:?}: only `publickey` (or `any`) is \
                             supported — multi-factor chains and non-publickey methods are not"
                        ),
                    });
                }
            }
            opts.authentication_methods = Some(line.args.clone());
        }
        "maxauthtries" => {
            let s = one_arg(line)?;
            opts.max_auth_tries = Some(s.parse::<u32>().map_err(|_| ConfigError::BadValue {
                line: line.line_no,
                keyword: kw.to_string(),
                msg: format!("expected an integer, got {s:?}"),
            })?);
        }
        "denyusers" => {
            if line.args.is_empty() {
                return Err(ConfigError::BadValue {
                    line: line.line_no,
                    keyword: kw.to_string(),
                    msg: "expected at least one user pattern".into(),
                });
            }
            for u in &line.args {
                if u.contains('@') {
                    return Err(ConfigError::Unsupported {
                        line: line.line_no,
                        msg: "DenyUsers user@host form is not supported".into(),
                    });
                }
                opts.deny_users.push(u.clone());
            }
        }
        "allowgroups" => {
            if line.args.is_empty() {
                return Err(ConfigError::BadValue {
                    line: line.line_no,
                    keyword: kw.to_string(),
                    msg: "expected at least one group pattern".into(),
                });
            }
            for g in &line.args {
                opts.allow_groups.push(g.clone());
            }
        }
        "denygroups" => {
            if line.args.is_empty() {
                return Err(ConfigError::BadValue {
                    line: line.line_no,
                    keyword: kw.to_string(),
                    msg: "expected at least one group pattern".into(),
                });
            }
            for g in &line.args {
                opts.deny_groups.push(g.clone());
            }
        }
        "permitemptypasswords" => {
            // `no` is the safe default (nothing to honor since there is no
            // password auth); `yes` would assert a behaviour we can't provide.
            let v = parse_yes_no(line)?;
            if v {
                return Err(ConfigError::Unsupported {
                    line: line.line_no,
                    msg: "PermitEmptyPasswords yes: password authentication is not implemented"
                        .into(),
                });
            }
        }
        "banner" => {
            let s = one_arg(line)?;
            // `none` disables the banner (OpenSSH convention).
            if s.eq_ignore_ascii_case("none") {
                opts.banner = None;
            } else {
                opts.banner = Some(s);
            }
        }
        _ => {
            return Err(ConfigError::UnknownKeyword {
                line: line.line_no,
                keyword: kw.to_string(),
            });
        }
    }
    Ok(())
}

fn one_arg(line: &ParsedLine) -> Result<String, ConfigError> {
    if line.args.len() != 1 {
        return Err(ConfigError::BadValue {
            line: line.line_no,
            keyword: line.keyword.clone(),
            msg: format!("expected 1 value, got {}", line.args.len()),
        });
    }
    Ok(line.args[0].clone())
}

fn parse_u16(line: &ParsedLine) -> Result<u16, ConfigError> {
    let s = one_arg(line)?;
    s.parse::<u16>().map_err(|_| ConfigError::BadValue {
        line: line.line_no,
        keyword: line.keyword.clone(),
        msg: format!("expected a port number, got {s:?}"),
    })
}

fn parse_yes_no(line: &ParsedLine) -> Result<bool, ConfigError> {
    let s = one_arg(line)?.to_ascii_lowercase();
    match s.as_str() {
        "yes" | "true" | "on" => Ok(true),
        "no" | "false" | "off" => Ok(false),
        _ => Err(ConfigError::BadValue {
            line: line.line_no,
            keyword: line.keyword.clone(),
            msg: format!("expected yes/no, got {s:?}"),
        }),
    }
}

fn parse_permit_root_login(line: &ParsedLine) -> Result<PermitRootLogin, ConfigError> {
    let s = one_arg(line)?.to_ascii_lowercase();
    match s.as_str() {
        "yes" | "true" | "on" => Ok(PermitRootLogin::Yes),
        "no" | "false" | "off" => Ok(PermitRootLogin::No),
        "prohibit-password" | "without-password" => Ok(PermitRootLogin::ProhibitPassword),
        "forced-commands-only" => Err(ConfigError::Unsupported {
            line: line.line_no,
            msg: "PermitRootLogin forced-commands-only is not supported (puressh authorized_keys \
                  has no command= restriction); use yes, no, or prohibit-password"
                .into(),
        }),
        _ => Err(ConfigError::BadValue {
            line: line.line_no,
            keyword: line.keyword.clone(),
            msg: format!("expected yes/no/prohibit-password, got {s:?}"),
        }),
    }
}

fn parse_log_level(line: &ParsedLine) -> Result<u8, ConfigError> {
    let s = one_arg(line)?.to_ascii_uppercase();
    match s.as_str() {
        "QUIET" | "FATAL" | "ERROR" | "INFO" => Ok(0),
        "VERBOSE" | "DEBUG" | "DEBUG1" => Ok(1),
        "DEBUG2" => Ok(2),
        "DEBUG3" => Ok(3),
        _ => Err(ConfigError::BadValue {
            line: line.line_no,
            keyword: line.keyword.clone(),
            msg: format!("expected QUIET..DEBUG3, got {s:?}"),
        }),
    }
}

/// Parse an OpenSSH time-format duration like `30s`, `5m`, `2h`, or a bare
/// integer (interpreted as seconds). Returns the total in seconds.
fn parse_duration_seconds(line: &ParsedLine) -> Result<u32, ConfigError> {
    let s = one_arg(line)?;
    let bytes = s.as_bytes();
    let mut total: u64 = 0;
    let mut acc: u64 = 0;
    let mut has_digit = false;
    for &b in bytes {
        if b.is_ascii_digit() {
            has_digit = true;
            acc = acc * 10 + (b - b'0') as u64;
        } else {
            let mult: u64 = match b.to_ascii_lowercase() {
                b's' => 1,
                b'm' => 60,
                b'h' => 3600,
                b'd' => 86400,
                b'w' => 604800,
                _ => {
                    return Err(ConfigError::BadValue {
                        line: line.line_no,
                        keyword: line.keyword.clone(),
                        msg: format!("bad duration unit in {s:?}"),
                    });
                }
            };
            if !has_digit {
                return Err(ConfigError::BadValue {
                    line: line.line_no,
                    keyword: line.keyword.clone(),
                    msg: format!("missing number before unit in {s:?}"),
                });
            }
            total = total.saturating_add(acc.saturating_mul(mult));
            acc = 0;
            has_digit = false;
        }
    }
    if has_digit {
        total = total.saturating_add(acc);
    }
    if total > u32::MAX as u64 {
        return Err(ConfigError::BadValue {
            line: line.line_no,
            keyword: line.keyword.clone(),
            msg: format!("duration overflows u32 seconds: {s:?}"),
        });
    }
    Ok(total as u32)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_minimal() {
        let src = "\
Port 2222
ListenAddress 127.0.0.1
HostKey /etc/ssh/ssh_host_ed25519_key
AuthorizedKeysFile /etc/authkeys
AllowUsers alice bob
StrictModes yes
";
        let cfg = SshServerConfig::parse(src).unwrap().global;
        assert_eq!(cfg.port, Some(2222));
        assert_eq!(cfg.listen_addresses, vec!["127.0.0.1".to_string()]);
        assert_eq!(
            cfg.host_key_files,
            vec!["/etc/ssh/ssh_host_ed25519_key".to_string()]
        );
        assert_eq!(cfg.authorized_keys_file.as_deref(), Some("/etc/authkeys"));
        assert_eq!(
            cfg.allow_users,
            vec!["alice".to_string(), "bob".to_string()]
        );
        assert_eq!(cfg.strict_modes, Some(true));
    }

    #[test]
    fn cumulative_fields() {
        let src = "\
HostKey /a
HostKey /b
ListenAddress 127.0.0.1
ListenAddress ::1
AllowUsers alice
AllowUsers bob carol
";
        let cfg = SshServerConfig::parse(src).unwrap().global;
        assert_eq!(cfg.host_key_files, vec!["/a".to_string(), "/b".to_string()]);
        assert_eq!(
            cfg.listen_addresses,
            vec!["127.0.0.1".to_string(), "::1".to_string()]
        );
        assert_eq!(
            cfg.allow_users,
            vec!["alice".to_string(), "bob".to_string(), "carol".to_string()]
        );
    }

    #[test]
    fn match_block_parses_and_resolves() {
        let src = "Port 22\nMatch User alice\n  AllowAgentForwarding no\n";
        let cfg = SshServerConfig::parse(src).unwrap();
        assert_eq!(cfg.global.port, Some(22));
        assert_eq!(cfg.match_blocks.len(), 1);
        // No user in context ⇒ block does not apply.
        let base = cfg.resolve(&MatchContext::default(), ExecPolicy::Deny);
        assert_eq!(base.allow_agent_forwarding, None);
        // alice ⇒ block applies, AllowAgentForwarding no is merged.
        let ctx = MatchContext {
            host: "h",
            user: Some("alice"),
            ..MatchContext::default()
        };
        let eff = cfg.resolve(&ctx, ExecPolicy::Deny);
        assert_eq!(eff.allow_agent_forwarding, Some(false));
        assert_eq!(eff.port, Some(22)); // global scalar preserved
    }

    #[test]
    fn match_first_match_wins_and_cumulative() {
        let src = "\
Match User alice
  MaxAuthTries 1
  AcceptEnv FOO
Match Group dev
  MaxAuthTries 2
  AcceptEnv BAR
";
        let cfg = SshServerConfig::parse(src).unwrap();
        let groups = vec!["dev".to_string()];
        let ctx = MatchContext {
            host: "h",
            user: Some("alice"),
            groups: Some(&groups),
            ..MatchContext::default()
        };
        let eff = cfg.resolve(&ctx, ExecPolicy::Deny);
        // First matching block sets the scalar; the later one does not override.
        assert_eq!(eff.max_auth_tries, Some(1));
        // AcceptEnv concatenates across both matching blocks.
        assert_eq!(eff.accept_env, vec!["FOO".to_string(), "BAR".to_string()]);
    }

    #[test]
    fn match_address_localport_gate() {
        let src = "\
Match Address 192.0.2.0/24
  X11Forwarding no
Match LocalPort 2222
  AllowAgentForwarding no
";
        let cfg = SshServerConfig::parse(src).unwrap();
        let ctx = MatchContext {
            host: "h",
            address: Some("192.0.2.50"),
            local_port: Some(2222),
            ..MatchContext::default()
        };
        let eff = cfg.resolve(&ctx, ExecPolicy::Deny);
        assert_eq!(eff.x11_forwarding, Some(false));
        assert_eq!(eff.allow_agent_forwarding, Some(false));
        // A peer outside the range / on another port matches neither.
        let ctx2 = MatchContext {
            host: "h",
            address: Some("198.51.100.1"),
            local_port: Some(22),
            ..MatchContext::default()
        };
        let eff2 = cfg.resolve(&ctx2, ExecPolicy::Deny);
        assert_eq!(eff2.x11_forwarding, None);
        assert_eq!(eff2.allow_agent_forwarding, None);
    }

    #[test]
    fn match_password_auth_yes_unsupported() {
        let src = "Match User alice\n  PasswordAuthentication yes\n";
        let err = SshServerConfig::parse(src).unwrap_err();
        assert!(
            matches!(err, ConfigError::Unsupported { line: 2, .. }),
            "{err:?}"
        );
    }

    #[test]
    fn match_host_on_server_unsupported() {
        let src = "Match Host example.com\n  X11Forwarding no\n";
        let err = SshServerConfig::parse(src).unwrap_err();
        assert!(
            matches!(err, ConfigError::Unsupported { line: 1, .. }),
            "{err:?}"
        );
    }

    #[test]
    fn invalid_in_match_rejected() {
        // Port is valid at file scope but not inside a Match block.
        let src = "Match User alice\n  Port 2222\n";
        let err = SshServerConfig::parse(src).unwrap_err();
        assert!(
            matches!(err, ConfigError::Unsupported { line: 2, .. }),
            "{err:?}"
        );
    }

    #[test]
    fn auth_access_keywords_parse() {
        let src = "\
PubkeyAuthentication yes
PasswordAuthentication no
KbdInteractiveAuthentication no
AuthenticationMethods publickey
MaxAuthTries 3
DenyUsers baduser eve*
AllowGroups wheel admins
DenyGroups nologin
Banner /etc/ssh/banner
";
        let cfg = SshServerConfig::parse(src).unwrap().global;
        assert_eq!(cfg.pubkey_authentication, Some(true));
        assert_eq!(cfg.password_authentication, Some(false));
        assert_eq!(cfg.kbd_interactive_authentication, Some(false));
        assert_eq!(
            cfg.authentication_methods.as_deref(),
            Some(&["publickey".to_string()][..])
        );
        assert_eq!(cfg.max_auth_tries, Some(3));
        assert_eq!(
            cfg.deny_users,
            vec!["baduser".to_string(), "eve*".to_string()]
        );
        assert_eq!(
            cfg.allow_groups,
            vec!["wheel".to_string(), "admins".to_string()]
        );
        assert_eq!(cfg.deny_groups, vec!["nologin".to_string()]);
        assert_eq!(cfg.banner.as_deref(), Some("/etc/ssh/banner"));
    }

    #[test]
    fn authentication_methods_multifactor_unsupported() {
        let err = SshServerConfig::parse("AuthenticationMethods publickey,password\n").unwrap_err();
        assert!(
            matches!(err, ConfigError::Unsupported { line: 1, .. }),
            "{err:?}"
        );
        let err2 = SshServerConfig::parse("AuthenticationMethods password\n").unwrap_err();
        assert!(
            matches!(err2, ConfigError::Unsupported { line: 1, .. }),
            "{err2:?}"
        );
        // `any` and bare `publickey` are accepted.
        assert!(SshServerConfig::parse("AuthenticationMethods any\n").is_ok());
    }

    #[test]
    fn permit_empty_passwords_yes_unsupported() {
        let err = SshServerConfig::parse("PermitEmptyPasswords yes\n").unwrap_err();
        assert!(matches!(err, ConfigError::Unsupported { line: 1, .. }));
        assert!(SshServerConfig::parse("PermitEmptyPasswords no\n").is_ok());
    }

    #[test]
    fn allow_users_at_host_unsupported() {
        let err = SshServerConfig::parse("AllowUsers alice@1.2.3.4\n").unwrap_err();
        assert!(matches!(err, ConfigError::Unsupported { line: 1, .. }));
    }

    #[test]
    fn unknown_keyword_errors() {
        // `Tunnel` is a real OpenSSH keyword this parser does not implement;
        // `KexAlgorithms` is now recognised, so it can no longer serve as the
        // "unknown keyword" fixture.
        let src = "Port 22\nTunnel yes\n";
        let err = SshServerConfig::parse(src).unwrap_err();
        match err {
            ConfigError::UnknownKeyword { keyword, line } => {
                assert_eq!(keyword, "tunnel");
                assert_eq!(line, 2);
            }
            _ => panic!("wrong error: {err:?}"),
        }
    }

    #[test]
    fn algorithm_keywords_parse() {
        let src = "\
Port 22
Ciphers aes256-ctr,aes128-ctr
MACs hmac-sha2-512
KexAlgorithms curve25519-sha256
HostKeyAlgorithms ssh-ed25519,rsa-sha2-512
";
        let cfg = SshServerConfig::parse(src).unwrap().global;
        assert_eq!(
            cfg.ciphers.as_deref(),
            Some(&["aes256-ctr".to_string(), "aes128-ctr".to_string()][..])
        );
        assert_eq!(
            cfg.macs.as_deref(),
            Some(&["hmac-sha2-512".to_string()][..])
        );
        assert_eq!(
            cfg.kex_algorithms.as_deref(),
            Some(&["curve25519-sha256".to_string()][..])
        );
        assert_eq!(
            cfg.host_key_algorithms.as_deref(),
            Some(&["ssh-ed25519".to_string(), "rsa-sha2-512".to_string()][..])
        );
    }

    #[test]
    fn unknown_mac_rejected_with_line() {
        let src = "Port 22\nMACs hmac-bogus\n";
        let err = SshServerConfig::parse(src).unwrap_err();
        match err {
            ConfigError::BadValue { line, keyword, msg } => {
                assert_eq!(line, 2);
                assert_eq!(keyword, "MACs");
                assert!(msg.contains("hmac-bogus"));
            }
            other => panic!("expected BadValue, got {other:?}"),
        }
    }

    #[test]
    fn server_casignaturealgorithms_unsupported() {
        let src = "Port 22\nCASignatureAlgorithms ssh-ed25519\n";
        let err = SshServerConfig::parse(src).unwrap_err();
        assert!(matches!(err, ConfigError::Unsupported { line: 2, .. }));
    }

    #[test]
    fn kex_remove_modifier_keeps_nonempty() {
        // `-` removes by glob from the defaults; the result must be non-empty.
        let src = "Port 22\nKexAlgorithms -diffie-hellman-group*\n";
        let cfg = SshServerConfig::parse(src).unwrap().global;
        let kex = cfg.kex_algorithms.unwrap();
        assert!(kex.iter().all(|k| !k.starts_with("diffie-hellman-group")));
        assert!(kex.iter().any(|k| k == "curve25519-sha256"));
    }

    #[test]
    fn login_grace_time_units() {
        for (s, want) in [
            ("30", 30u32),
            ("30s", 30),
            ("2m", 120),
            ("1h", 3600),
            ("1m30s", 90),
        ] {
            let src = format!("LoginGraceTime {s}\n");
            let cfg = SshServerConfig::parse(&src).unwrap().global;
            assert_eq!(cfg.login_grace_time, Some(want), "case {s:?}");
        }
    }

    #[test]
    fn permit_root_login_values() {
        for (s, want) in [
            ("yes", PermitRootLogin::Yes),
            ("no", PermitRootLogin::No),
            ("prohibit-password", PermitRootLogin::ProhibitPassword),
            ("without-password", PermitRootLogin::ProhibitPassword),
        ] {
            let src = format!("PermitRootLogin {s}\n");
            let cfg = SshServerConfig::parse(&src).unwrap().global;
            assert_eq!(cfg.permit_root_login, Some(want), "case {s:?}");
        }
        assert!(PermitRootLogin::Yes.permits_publickey());
        assert!(PermitRootLogin::ProhibitPassword.permits_publickey());
        assert!(!PermitRootLogin::No.permits_publickey());
    }

    #[test]
    fn permit_root_login_forced_commands_unsupported() {
        let err = SshServerConfig::parse("PermitRootLogin forced-commands-only\n").unwrap_err();
        assert!(
            matches!(err, ConfigError::Unsupported { line: 1, .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn permit_root_login_bad_value() {
        let err = SshServerConfig::parse("PermitRootLogin maybe\n").unwrap_err();
        assert!(
            matches!(err, ConfigError::BadValue { line: 1, .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn sftp_knobs() {
        let src = "\
SftpEnabled yes
SftpReadOnly no
SftpRoot /var/sftp
ScpEnabled yes
";
        let cfg = SshServerConfig::parse(src).unwrap().global;
        assert_eq!(cfg.sftp_enabled, Some(true));
        assert_eq!(cfg.sftp_read_only, Some(false));
        assert_eq!(cfg.sftp_root.as_deref(), Some("/var/sftp"));
        assert_eq!(cfg.scp_enabled, Some(true));
    }
}
