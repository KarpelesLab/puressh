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
    /// `MaxSessions` — cap on the number of open `session` channels per
    /// connection. `0` ⇒ no sessions may be opened. `None` ⇒ no cap.
    pub max_sessions: Option<u32>,
    /// `AllowTcpForwarding` — which TCP forwarding directions are permitted.
    /// `None` ⇒ default-allow (the historical behaviour, modulo whether a
    /// handler is even attached).
    pub allow_tcp_forwarding: Option<TcpForwarding>,
    /// `PermitOpen` — destinations a `direct-tcpip` (`ssh -L`) request may
    /// target. `None` ⇒ unset (any). `Some(vec![])` ⇒ `none` (deny all).
    pub permit_open: Option<Vec<HostPort>>,
    /// `PermitListen` — bind targets a `tcpip-forward` (`ssh -R`) request may
    /// ask for. `None` ⇒ unset (any). `Some(vec![])` ⇒ `none` (deny all).
    pub permit_listen: Option<Vec<HostPort>>,
    /// `GatewayPorts` — whether remote-forward binds may use a non-loopback
    /// interface. `None` ⇒ default (`no`).
    pub gateway_ports: Option<GatewayPorts>,
    /// `ForceCommand` — overrides the client's requested command/shell with
    /// this one; the original command is exposed via `SSH_ORIGINAL_COMMAND`.
    /// The literal `internal-sftp` routes to the in-process SFTP subsystem.
    /// `None` ⇒ no forced command.
    pub force_command: Option<String>,
    /// `ChrootDirectory` — chroot for the session. Only honoured for the
    /// SFTP path (mapped onto the SFTP root); a real chroot for shell/exec is
    /// out of scope. `None` ⇒ no chroot.
    pub chroot_directory: Option<String>,
    /// `ClientAliveInterval` in seconds — server keepalive cadence. `0`/`None`
    /// ⇒ disabled.
    pub client_alive_interval: Option<u32>,
    /// `ClientAliveCountMax` — number of unanswered keepalives tolerated before
    /// the connection is dropped. `None` ⇒ default 3.
    pub client_alive_count_max: Option<u32>,
    /// `PrintMotd` (yes/no) — print `/etc/motd` for interactive shells.
    /// `None` ⇒ default (no).
    pub print_motd: Option<bool>,
    /// `Compression` — `no` / `yes` / `delayed`. `None` ⇒ default (`delayed`).
    pub compression: Option<Compression>,
    /// `RekeyLimit` — parsed `<bytes>[ <time>]` re-key thresholds. `None` ⇒
    /// default. The flags inside distinguish `default`/`none`.
    pub rekey_limit: Option<RekeyLimit>,
    /// `AddressFamily` — restrict the listener address family. `None` ⇒ any.
    pub address_family: Option<AddressFamily>,
    /// `PidFile` — path to write the daemon PID to, or `None` for the literal
    /// `none`. Distinguished from "unset" by `pid_file_set`.
    pub pid_file: Option<String>,
    /// True iff a `PidFile` line was seen (so the binary can tell `none`
    /// (`pid_file == None`, `pid_file_set == true`) from "unset").
    pub pid_file_set: bool,
    /// `Subsystem sftp internal-sftp` ⇒ enables the in-process SFTP handler
    /// (the standard `sshd_config` spelling; `SftpEnabled` remains a working
    /// alias). External-command subsystems are rejected at parse time.
    pub subsystem_sftp: Option<bool>,
}

/// `AllowTcpForwarding` policy: which forwarding directions are permitted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TcpForwarding {
    /// `no` — neither direction.
    No,
    /// `yes` / `all` — both directions.
    All,
    /// `local` — only `direct-tcpip` (`ssh -L`).
    Local,
    /// `remote` — only `tcpip-forward` (`ssh -R`).
    Remote,
}

impl TcpForwarding {
    /// Whether `direct-tcpip` (local, `ssh -L`) forwarding is allowed.
    pub fn local_allowed(self) -> bool {
        matches!(self, TcpForwarding::All | TcpForwarding::Local)
    }
    /// Whether `tcpip-forward` (remote, `ssh -R`) forwarding is allowed.
    pub fn remote_allowed(self) -> bool {
        matches!(self, TcpForwarding::All | TcpForwarding::Remote)
    }
}

/// `GatewayPorts` policy for remote-forward binds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GatewayPorts {
    /// `no` — force the listener onto loopback regardless of the client's ask.
    No,
    /// `yes` — bind on all interfaces.
    Yes,
    /// `clientspecified` — honour the client's requested bind address.
    ClientSpecified,
}

/// `Compression` policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Compression {
    /// `no` — never offer zlib.
    No,
    /// `yes` — offer zlib immediately.
    Yes,
    /// `delayed` — offer zlib only post-auth (the OpenSSH default).
    Delayed,
}

/// `AddressFamily` policy restricting the listener's address family.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AddressFamily {
    /// `any` — both IPv4 and IPv6.
    Any,
    /// `inet` — IPv4 only.
    Inet,
    /// `inet6` — IPv6 only.
    Inet6,
}

/// One `host:port` entry for `PermitOpen` / `PermitListen`. A `None` port (or
/// `host` of `*`) is a wildcard.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HostPort {
    /// Host literal, or `*` for any host.
    pub host: String,
    /// Port, or `None` for any port (`*`).
    pub port: Option<u16>,
}

impl HostPort {
    /// True iff this entry permits a request for `(host, port)`. A `*` host
    /// matches any host; a `None` port matches any port.
    pub fn matches(&self, host: &str, port: u16) -> bool {
        let host_ok = self.host == "*" || self.host == host;
        let port_ok = self.port.is_none_or(|p| p == port);
        host_ok && port_ok
    }
}

/// Parsed `RekeyLimit` thresholds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RekeyLimit {
    /// Byte threshold. `None` ⇒ `default`/unset for bytes.
    pub max_bytes: Option<u64>,
    /// Time threshold in seconds. `None` ⇒ no time-based rekey.
    pub max_seconds: Option<u32>,
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
    take_scalar!(max_sessions);
    take_scalar!(allow_tcp_forwarding);
    take_scalar!(permit_open);
    take_scalar!(permit_listen);
    take_scalar!(gateway_ports);
    take_scalar!(force_command);
    take_scalar!(chroot_directory);
    take_scalar!(client_alive_interval);
    take_scalar!(client_alive_count_max);
    take_scalar!(print_motd);
    take_scalar!(compression);
    take_scalar!(rekey_limit);
    take_scalar!(address_family);
    take_scalar!(subsystem_sftp);
    // `pid_file` is startup-only (rejected inside Match), so it can only ever
    // come from the global block; merge it first-match-wins anyway for
    // robustness, carrying the "was it set" flag alongside.
    if !dst.pid_file_set && src.pid_file_set {
        dst.pid_file = src.pid_file.clone();
        dst.pid_file_set = true;
    }
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
        "subsystem",
        "permittunnel",
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
                // The `user@host` form is matched against the connection's
                // resolved peer address at login time (see the binary's
                // `LocalAuthenticator`); a bare token matches the username
                // alone. Reject only a malformed half (empty user or host) so
                // a typo can't silently widen the rule.
                validate_user_at_host(u, kw, line.line_no)?;
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
                validate_user_at_host(u, kw, line.line_no)?;
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
        "maxsessions" => {
            let s = one_arg(line)?;
            opts.max_sessions = Some(s.parse::<u32>().map_err(|_| ConfigError::BadValue {
                line: line.line_no,
                keyword: kw.to_string(),
                msg: format!("expected an integer, got {s:?}"),
            })?);
        }
        "allowtcpforwarding" => {
            opts.allow_tcp_forwarding = Some(parse_tcp_forwarding(line)?);
        }
        "permitopen" => {
            opts.permit_open = Some(parse_host_port_list(line)?);
        }
        "permitlisten" => {
            opts.permit_listen = Some(parse_host_port_list(line)?);
        }
        "gatewayports" => {
            opts.gateway_ports = Some(parse_gateway_ports(line)?);
        }
        "forcecommand" => {
            // OpenSSH joins all tokens after the keyword into one command
            // line. An empty value is meaningless (would force "no command").
            if line.args.is_empty() {
                return Err(ConfigError::BadValue {
                    line: line.line_no,
                    keyword: kw.to_string(),
                    msg: "expected a command".into(),
                });
            }
            opts.force_command = Some(line.args.join(" "));
        }
        "chrootdirectory" => {
            let s = one_arg(line)?;
            if s.eq_ignore_ascii_case("none") {
                opts.chroot_directory = None;
            } else {
                opts.chroot_directory = Some(s);
            }
        }
        "clientaliveinterval" => {
            opts.client_alive_interval = Some(parse_duration_seconds(line)?);
        }
        "clientalivecountmax" => {
            let s = one_arg(line)?;
            opts.client_alive_count_max =
                Some(s.parse::<u32>().map_err(|_| ConfigError::BadValue {
                    line: line.line_no,
                    keyword: kw.to_string(),
                    msg: format!("expected an integer, got {s:?}"),
                })?);
        }
        "printmotd" => {
            opts.print_motd = Some(parse_yes_no(line)?);
        }
        "compression" => {
            opts.compression = Some(parse_compression(line)?);
        }
        "rekeylimit" => {
            opts.rekey_limit = Some(parse_rekey_limit(line)?);
        }
        "addressfamily" => {
            opts.address_family = Some(parse_address_family(line)?);
        }
        "pidfile" => {
            let s = one_arg(line)?;
            opts.pid_file_set = true;
            if s.eq_ignore_ascii_case("none") {
                opts.pid_file = None;
            } else {
                opts.pid_file = Some(s);
            }
        }
        "subsystem" => {
            // Standard form: `Subsystem <name> <command>`. Only the in-process
            // `sftp` → `internal-sftp` mapping is supported; an external
            // command subsystem cannot be honoured.
            if line.args.len() < 2 {
                return Err(ConfigError::BadValue {
                    line: line.line_no,
                    keyword: kw.to_string(),
                    msg: "expected `Subsystem <name> <command>`".into(),
                });
            }
            let name = line.args[0].to_ascii_lowercase();
            let command = &line.args[1];
            if name == "sftp" && command.eq_ignore_ascii_case("internal-sftp") {
                opts.subsystem_sftp = Some(true);
            } else {
                return Err(ConfigError::Unsupported {
                    line: line.line_no,
                    msg: format!(
                        "Subsystem {name:?}: only `sftp internal-sftp` is supported \
                         (external-command subsystems are not)"
                    ),
                });
            }
        }
        "permittunnel" => {
            return Err(ConfigError::Unsupported {
                line: line.line_no,
                msg: "PermitTunnel: tun/tap device forwarding is not supported".into(),
            });
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

/// Parse an `AllowTcpForwarding` value: `yes` / `no` / `all` / `local` /
/// `remote`.
fn parse_tcp_forwarding(line: &ParsedLine) -> Result<TcpForwarding, ConfigError> {
    let s = one_arg(line)?.to_ascii_lowercase();
    match s.as_str() {
        "yes" | "all" => Ok(TcpForwarding::All),
        "no" => Ok(TcpForwarding::No),
        "local" => Ok(TcpForwarding::Local),
        "remote" => Ok(TcpForwarding::Remote),
        _ => Err(ConfigError::BadValue {
            line: line.line_no,
            keyword: line.keyword.clone(),
            msg: format!("expected yes/no/all/local/remote, got {s:?}"),
        }),
    }
}

/// Parse a `GatewayPorts` value: `no` / `yes` / `clientspecified`.
fn parse_gateway_ports(line: &ParsedLine) -> Result<GatewayPorts, ConfigError> {
    let s = one_arg(line)?.to_ascii_lowercase();
    match s.as_str() {
        "no" => Ok(GatewayPorts::No),
        "yes" => Ok(GatewayPorts::Yes),
        "clientspecified" => Ok(GatewayPorts::ClientSpecified),
        _ => Err(ConfigError::BadValue {
            line: line.line_no,
            keyword: line.keyword.clone(),
            msg: format!("expected no/yes/clientspecified, got {s:?}"),
        }),
    }
}

/// Parse a `Compression` value: `no` / `yes` / `delayed`.
fn parse_compression(line: &ParsedLine) -> Result<Compression, ConfigError> {
    let s = one_arg(line)?.to_ascii_lowercase();
    match s.as_str() {
        "no" | "false" | "off" => Ok(Compression::No),
        "yes" | "true" | "on" => Ok(Compression::Yes),
        "delayed" => Ok(Compression::Delayed),
        _ => Err(ConfigError::BadValue {
            line: line.line_no,
            keyword: line.keyword.clone(),
            msg: format!("expected no/yes/delayed, got {s:?}"),
        }),
    }
}

/// Parse an `AddressFamily` value: `any` / `inet` / `inet6`.
fn parse_address_family(line: &ParsedLine) -> Result<AddressFamily, ConfigError> {
    let s = one_arg(line)?.to_ascii_lowercase();
    match s.as_str() {
        "any" => Ok(AddressFamily::Any),
        "inet" => Ok(AddressFamily::Inet),
        "inet6" => Ok(AddressFamily::Inet6),
        _ => Err(ConfigError::BadValue {
            line: line.line_no,
            keyword: line.keyword.clone(),
            msg: format!("expected any/inet/inet6, got {s:?}"),
        }),
    }
}

/// Parse a `PermitOpen` / `PermitListen` argument list into [`HostPort`]
/// entries. `any` ⇒ no restriction (returned as a single wildcard entry);
/// `none` ⇒ deny all (returned as an empty vec). A malformed `host:port` is a
/// [`ConfigError::BadValue`].
fn parse_host_port_list(line: &ParsedLine) -> Result<Vec<HostPort>, ConfigError> {
    if line.args.is_empty() {
        return Err(ConfigError::BadValue {
            line: line.line_no,
            keyword: line.keyword.clone(),
            msg: "expected at least one host:port (or any/none)".into(),
        });
    }
    // `any` / `none` are only meaningful as the sole argument.
    if line.args.len() == 1 {
        let only = line.args[0].to_ascii_lowercase();
        if only == "any" {
            return Ok(alloc::vec![HostPort {
                host: "*".into(),
                port: None,
            }]);
        }
        if only == "none" {
            return Ok(Vec::new());
        }
    }
    let mut out = Vec::with_capacity(line.args.len());
    for spec in &line.args {
        out.push(parse_host_port(spec, line)?);
    }
    Ok(out)
}

/// Parse one `host:port` token. Accepts `host:port`, `host:*`, `*:port`,
/// `[v6]:port`. A bare host with no colon is rejected (OpenSSH requires a
/// port). Returns [`ConfigError::BadValue`] on a malformed entry.
fn parse_host_port(spec: &str, line: &ParsedLine) -> Result<HostPort, ConfigError> {
    let bad = || ConfigError::BadValue {
        line: line.line_no,
        keyword: line.keyword.clone(),
        msg: format!("malformed host:port entry {spec:?}"),
    };
    // Bracketed IPv6 literal: [::1]:22
    let (host, port_str) = if let Some(rest) = spec.strip_prefix('[') {
        let close = rest.find(']').ok_or_else(bad)?;
        let host = &rest[..close];
        let after = &rest[close + 1..];
        let port = after.strip_prefix(':').ok_or_else(bad)?;
        (host.to_string(), port)
    } else {
        // Split on the LAST colon so bare IPv6 without brackets still fails
        // cleanly (it would have multiple colons → ambiguous → reject).
        let colon = spec.rfind(':').ok_or_else(bad)?;
        let host = &spec[..colon];
        let port = &spec[colon + 1..];
        // Reject bare IPv6 (additional colons in the host part).
        if host.contains(':') {
            return Err(bad());
        }
        (host.to_string(), port)
    };
    if host.is_empty() {
        return Err(bad());
    }
    let port = if port_str == "*" {
        None
    } else {
        Some(port_str.parse::<u16>().map_err(|_| bad())?)
    };
    Ok(HostPort { host, port })
}

/// Parse a `RekeyLimit` value: `<bytes>[ <time>]` where `<bytes>` accepts
/// `K`/`M`/`G` suffixes (or `default`/`none`), and `<time>` is an OpenSSH
/// duration (or `none`).
fn parse_rekey_limit(line: &ParsedLine) -> Result<RekeyLimit, ConfigError> {
    if line.args.is_empty() || line.args.len() > 2 {
        return Err(ConfigError::BadValue {
            line: line.line_no,
            keyword: line.keyword.clone(),
            msg: "expected `<bytes>[ <time>]`".into(),
        });
    }
    let bytes_tok = line.args[0].to_ascii_lowercase();
    let max_bytes = match bytes_tok.as_str() {
        "default" | "none" => None,
        other => Some(parse_size_bytes(other, line)?),
    };
    let max_seconds = match line.args.get(1) {
        None => None,
        Some(t) => {
            if t.eq_ignore_ascii_case("none") {
                None
            } else {
                Some(parse_duration_str(t, line)?)
            }
        }
    };
    Ok(RekeyLimit {
        max_bytes,
        max_seconds,
    })
}

/// Parse a size with an optional `K`/`M`/`G` suffix (binary multiples), e.g.
/// `512`, `1K`, `2M`, `1G`.
fn parse_size_bytes(s: &str, line: &ParsedLine) -> Result<u64, ConfigError> {
    let bad = || ConfigError::BadValue {
        line: line.line_no,
        keyword: line.keyword.clone(),
        msg: format!("bad size value {s:?}"),
    };
    let bytes = s.as_bytes();
    if bytes.is_empty() {
        return Err(bad());
    }
    let last = bytes[bytes.len() - 1];
    let (digits, mult): (&str, u64) = match last.to_ascii_lowercase() {
        b'k' => (&s[..s.len() - 1], 1024),
        b'm' => (&s[..s.len() - 1], 1024 * 1024),
        b'g' => (&s[..s.len() - 1], 1024 * 1024 * 1024),
        _ if last.is_ascii_digit() => (s, 1),
        _ => return Err(bad()),
    };
    let n: u64 = digits.parse().map_err(|_| bad())?;
    n.checked_mul(mult).ok_or_else(bad)
}

/// Validate an `AllowUsers`/`DenyUsers` token. A bare token is a username
/// glob; a `user@host` token additionally constrains the connection's peer
/// address (matched at login time by the binary's authenticator). Reject a
/// token with an empty user or host half, or with more than one `@`, so a
/// malformed rule fails loudly rather than silently matching nothing.
fn validate_user_at_host(token: &str, keyword: &str, line_no: usize) -> Result<(), ConfigError> {
    if let Some((user, host)) = token.split_once('@')
        && (user.is_empty() || host.is_empty() || host.contains('@'))
    {
        return Err(ConfigError::BadValue {
            line: line_no,
            keyword: keyword.to_string(),
            msg: format!("malformed user@host pattern {token:?}"),
        });
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
    parse_duration_str(&s, line)
}

/// Parse a single OpenSSH duration token (e.g. `30s`, `5m`, `2h`, or a bare
/// integer of seconds) into total seconds. Shared by `LoginGraceTime`,
/// `ClientAliveInterval`, and the time field of `RekeyLimit`.
fn parse_duration_str(s: &str, line: &ParsedLine) -> Result<u32, ConfigError> {
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
    fn allow_users_at_host_accepted() {
        // The `user@host` form is now honoured (matched against the peer
        // address at login time), so it parses and is stored verbatim.
        let cfg = SshServerConfig::parse("AllowUsers alice@1.2.3.4 bob\n").unwrap();
        assert_eq!(
            cfg.global.allow_users,
            vec!["alice@1.2.3.4".to_string(), "bob".to_string()]
        );
        // A malformed half is still a hard error.
        assert!(matches!(
            SshServerConfig::parse("AllowUsers @1.2.3.4\n").unwrap_err(),
            ConfigError::BadValue { line: 1, .. }
        ));
        assert!(matches!(
            SshServerConfig::parse("AllowUsers alice@\n").unwrap_err(),
            ConfigError::BadValue { line: 1, .. }
        ));
        // DenyUsers honours the same form.
        let cfg = SshServerConfig::parse("DenyUsers eve@*.evil.example\n").unwrap();
        assert_eq!(
            cfg.global.deny_users,
            vec!["eve@*.evil.example".to_string()]
        );
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

    // ---- W7 session / forwarding / policy keywords -----------------------

    #[test]
    fn session_forwarding_keywords_parse() {
        let src = "\
MaxSessions 4
AllowTcpForwarding local
PermitOpen 127.0.0.1:80 example.com:443
PermitListen 127.0.0.1:8080
GatewayPorts clientspecified
ForceCommand /usr/bin/uptime --pretty
ChrootDirectory /var/jail
ClientAliveInterval 30
ClientAliveCountMax 2
PrintMotd yes
Compression delayed
RekeyLimit 512M 1h
AddressFamily inet
PidFile /run/sshd.pid
Subsystem sftp internal-sftp
";
        let cfg = SshServerConfig::parse(src).unwrap().global;
        assert_eq!(cfg.max_sessions, Some(4));
        assert_eq!(cfg.allow_tcp_forwarding, Some(TcpForwarding::Local));
        let open = cfg.permit_open.unwrap();
        assert_eq!(open.len(), 2);
        assert!(open[0].matches("127.0.0.1", 80));
        assert!(open[1].matches("example.com", 443));
        assert!(!open[0].matches("127.0.0.1", 81));
        assert_eq!(cfg.permit_listen.unwrap()[0].port, Some(8080));
        assert_eq!(cfg.gateway_ports, Some(GatewayPorts::ClientSpecified));
        assert_eq!(
            cfg.force_command.as_deref(),
            Some("/usr/bin/uptime --pretty")
        );
        assert_eq!(cfg.chroot_directory.as_deref(), Some("/var/jail"));
        assert_eq!(cfg.client_alive_interval, Some(30));
        assert_eq!(cfg.client_alive_count_max, Some(2));
        assert_eq!(cfg.print_motd, Some(true));
        assert_eq!(cfg.compression, Some(Compression::Delayed));
        assert_eq!(
            cfg.rekey_limit,
            Some(RekeyLimit {
                max_bytes: Some(512 * 1024 * 1024),
                max_seconds: Some(3600),
            })
        );
        assert_eq!(cfg.address_family, Some(AddressFamily::Inet));
        assert!(cfg.pid_file_set);
        assert_eq!(cfg.pid_file.as_deref(), Some("/run/sshd.pid"));
        assert_eq!(cfg.subsystem_sftp, Some(true));
    }

    #[test]
    fn permit_open_any_and_none() {
        let any = SshServerConfig::parse("PermitOpen any\n")
            .unwrap()
            .global
            .permit_open
            .unwrap();
        assert!(any[0].matches("anything", 9999));
        let none = SshServerConfig::parse("PermitOpen none\n")
            .unwrap()
            .global
            .permit_open
            .unwrap();
        assert!(none.is_empty());
    }

    #[test]
    fn permit_open_malformed_bad_value() {
        // Bare host with no port.
        let err = SshServerConfig::parse("PermitOpen justhost\n").unwrap_err();
        assert!(
            matches!(err, ConfigError::BadValue { line: 1, .. }),
            "{err:?}"
        );
        // Non-numeric port.
        let err2 = SshServerConfig::parse("PermitOpen host:abc\n").unwrap_err();
        assert!(
            matches!(err2, ConfigError::BadValue { line: 1, .. }),
            "{err2:?}"
        );
        // PermitListen shares the parser.
        let err3 = SshServerConfig::parse("PermitListen :\n").unwrap_err();
        assert!(
            matches!(err3, ConfigError::BadValue { line: 1, .. }),
            "{err3:?}"
        );
    }

    #[test]
    fn permit_open_ipv6_bracketed() {
        let cfg = SshServerConfig::parse("PermitOpen [::1]:22\n")
            .unwrap()
            .global
            .permit_open
            .unwrap();
        assert_eq!(cfg[0].host, "::1");
        assert_eq!(cfg[0].port, Some(22));
    }

    #[test]
    fn force_command_empty_bad_value() {
        let err = SshServerConfig::parse("ForceCommand\n").unwrap_err();
        // Empty arg list ⇒ BadValue (the tokenizer drops a keyword-only line
        // before it reaches apply_keyword in some shapes; accept either the
        // BadValue from our arm or an unknown-shape error, but a value-less
        // line must not silently succeed).
        assert!(
            matches!(err, ConfigError::BadValue { line: 1, .. }),
            "{err:?}"
        );
    }

    #[test]
    fn permit_tunnel_unsupported() {
        let err = SshServerConfig::parse("PermitTunnel yes\n").unwrap_err();
        assert!(
            matches!(err, ConfigError::Unsupported { line: 1, .. }),
            "{err:?}"
        );
    }

    #[test]
    fn external_subsystem_unsupported() {
        let err =
            SshServerConfig::parse("Subsystem sftp /usr/lib/openssh/sftp-server\n").unwrap_err();
        assert!(
            matches!(err, ConfigError::Unsupported { line: 1, .. }),
            "{err:?}"
        );
    }

    #[test]
    fn subsystem_missing_command_bad_value() {
        let err = SshServerConfig::parse("Subsystem sftp\n").unwrap_err();
        assert!(
            matches!(err, ConfigError::BadValue { line: 1, .. }),
            "{err:?}"
        );
    }

    #[test]
    fn chroot_none_clears() {
        let cfg = SshServerConfig::parse("ChrootDirectory none\n")
            .unwrap()
            .global;
        assert_eq!(cfg.chroot_directory, None);
    }

    #[test]
    fn rekey_limit_default_and_none() {
        let d = SshServerConfig::parse("RekeyLimit default\n")
            .unwrap()
            .global
            .rekey_limit
            .unwrap();
        assert_eq!(d.max_bytes, None);
        assert_eq!(d.max_seconds, None);
        let n = SshServerConfig::parse("RekeyLimit 1G none\n")
            .unwrap()
            .global
            .rekey_limit
            .unwrap();
        assert_eq!(n.max_bytes, Some(1024 * 1024 * 1024));
        assert_eq!(n.max_seconds, None);
    }

    #[test]
    fn rekey_limit_bad_value() {
        let err = SshServerConfig::parse("RekeyLimit 5X\n").unwrap_err();
        assert!(
            matches!(err, ConfigError::BadValue { line: 1, .. }),
            "{err:?}"
        );
    }

    #[test]
    fn startup_keywords_rejected_in_match() {
        for kw in [
            "AddressFamily inet",
            "PidFile /x",
            "Compression no",
            "RekeyLimit 1G",
            "Subsystem sftp internal-sftp",
            "PermitTunnel yes",
        ] {
            let src = format!("Match User alice\n  {kw}\n");
            let err = SshServerConfig::parse(&src).unwrap_err();
            assert!(
                matches!(err, ConfigError::Unsupported { line: 2, .. }),
                "expected reject for {kw:?}, got {err:?}"
            );
        }
    }

    #[test]
    fn session_keywords_match_overridable() {
        // MaxSessions / AllowTcpForwarding / ForceCommand etc. are valid in a
        // Match block and resolve per-connection.
        let src = "\
MaxSessions 10
Match User alice
  MaxSessions 1
  AllowTcpForwarding no
  ForceCommand internal-sftp
";
        let cfg = SshServerConfig::parse(src).unwrap();
        let base = cfg.resolve(&MatchContext::default(), ExecPolicy::Deny);
        assert_eq!(base.max_sessions, Some(10));
        assert_eq!(base.allow_tcp_forwarding, None);
        let ctx = MatchContext {
            host: "h",
            user: Some("alice"),
            ..MatchContext::default()
        };
        let eff = cfg.resolve(&ctx, ExecPolicy::Deny);
        // First-match-wins: global set MaxSessions 10 first, so it stays.
        assert_eq!(eff.max_sessions, Some(10));
        assert_eq!(eff.allow_tcp_forwarding, Some(TcpForwarding::No));
        assert_eq!(eff.force_command.as_deref(), Some("internal-sftp"));
    }
}
