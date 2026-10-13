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
//! ([`SshServerConfig::resolve`]) merges every matching block with
//! `sshd_config(5)` semantics: **first-match-wins** for scalars among the
//! matching blocks, whose values **override** the global section (global is
//! only the fallback), and **concatenation** for cumulative list fields.

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
#[non_exhaustive]
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

    /// Whether the root account may authenticate via password (or
    /// keyboard-interactive, which is also a password-equivalent secret) under
    /// this policy. `prohibit-password` (alias `without-password`) forbids it;
    /// only [`PermitRootLogin::Yes`] permits it.
    pub fn permits_password(self) -> bool {
        matches!(self, PermitRootLogin::Yes)
    }
}

/// `PerSourcePenalties`: seconds a source address is penalised for each
/// kind of misbehaviour, accumulated (up to `max`); a source whose penalty
/// exceeds `min` has its connections refused until it expires. OpenSSH's
/// defaults.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct PerSourcePenalties {
    /// Penalties apply at all (`PerSourcePenalties no` turns them off).
    pub enabled: bool,
    /// A connection process crashed.
    pub crash: u32,
    /// Authentication was attempted and failed.
    pub authfail: u32,
    /// Authentication was attempted for an account that does not exist.
    pub invalid_user: u32,
    /// The connection ended without an authentication attempt.
    pub noauth: u32,
    /// `LoginGraceTime` ran out.
    pub grace_exceeded: u32,
    /// `RefuseConnection` refused the connection.
    pub refuse_connection: u32,
    /// A penalty becomes active (refusing) once it exceeds this.
    pub min: u32,
    /// The longest a penalty accumulates to.
    pub max: u32,
    /// Most penalised IPv4 / IPv6 sources tracked.
    pub max_sources4: u32,
    /// See [`Self::max_sources4`].
    pub max_sources6: u32,
    /// When the IPv4 table is full: refuse everyone (`deny-all`) rather
    /// than forget the oldest penalties (`permissive`).
    pub overflow_deny_all: bool,
    /// The same for IPv6.
    pub overflow6_deny_all: bool,
}

impl Default for PerSourcePenalties {
    fn default() -> Self {
        PerSourcePenalties {
            enabled: true,
            crash: 90,
            authfail: 5,
            invalid_user: 5,
            noauth: 1,
            grace_exceeded: 10,
            refuse_connection: 10,
            min: 15,
            max: 600,
            max_sources4: 65536,
            max_sources6: 65536,
            overflow_deny_all: false,
            overflow6_deny_all: false,
        }
    }
}

/// One block of `sshd_config(5)` options.
///
/// Every field is `Option`-typed (or an empty `Vec`) so the binary can apply
/// OpenSSH precedence — CLI flag > config file > built-in default — using a
/// `pick(cli, cfg, default)` helper, and so [`SshServerConfig::resolve`] can
/// merge blocks with first-match-wins scalars (Match blocks overriding
/// global) and concatenated lists.
///
/// Auth/access keywords: `PasswordAuthentication`,
/// `KbdInteractiveAuthentication`, multi-factor `AuthenticationMethods` chains,
/// and `PermitEmptyPasswords` are honored. Whether they take effect at runtime
/// additionally depends on a PAM backend being compiled into the `sshd` binary
/// (Linux + the `pam` feature); without it the methods are never advertised
/// (the binary warns).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
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
    /// `HostCertificate` entries — cumulative. Each is the path to an OpenSSH
    /// host certificate (`*-cert.pub`), paired at load time with the preceding
    /// `HostKey` whose embedded key it certifies.
    pub host_certificate_files: Vec<String>,
    /// `HostKeyAgent` — the agent socket that signs for host keys whose
    /// `HostKey` file holds only the public key; `SSH_AUTH_SOCK` names the
    /// environment's agent. `None` for `none` or unset.
    pub host_key_agent: Option<String>,
    /// `PAMServiceName` — the PAM service sshd authenticates with
    /// (`sshd` when unset).
    pub pam_service_name: Option<String>,
    /// `ExposeAuthInfo` — give sessions `SSH_USER_AUTH`, a file listing the
    /// authentication methods (and keys) that succeeded.
    pub expose_auth_info: Option<bool>,
    /// `ChannelTimeout` — `(type pattern, seconds)` pairs: a channel idle
    /// that long is closed; `global` applies to all channels together.
    /// Empty for `none`.
    pub channel_timeouts: Option<Vec<(String, u32)>>,
    /// `PerSourcePenalties`.
    pub per_source_penalties: Option<PerSourcePenalties>,
    /// `PerSourcePenaltyExemptList` — addresses (CIDR patterns) never
    /// penalised.
    pub per_source_penalty_exempt: Option<String>,
    /// `PerSourceNetBlockSize` — the IPv4 / IPv6 prefix lengths sources are
    /// grouped by (`32:128` by default).
    pub per_source_net_block_size: Option<(u8, u8)>,
    /// `TrustedUserCAKeys` — path to a file of CA public keys whose user
    /// certificates the server will accept (one key per line).
    pub trusted_user_ca_keys: Option<String>,
    /// `RevokedKeys` — path to a key-revocation list. OpenSSH accepts either a
    /// list of plain public keys (`authorized_keys` format) or a binary KRL
    /// blob (`ssh-keygen -k`); several files may be named, and a key any of
    /// them revokes is refused. A publickey / certificate a file covers is
    /// refused regardless of any other trust. `none` names no file.
    pub revoked_keys: Option<Vec<String>>,
    /// `AuthorizedPrincipalsFile` — path (with `%u`/`%h` tokens) to a file
    /// listing the certificate principals a connecting user is allowed to
    /// authenticate as. When unset, the login user must itself appear in the
    /// certificate's principals list.
    pub authorized_principals_file: Option<String>,
    /// `AuthorizedKeysCommand` — a program (absolute path) and its
    /// arguments, `%` tokens unexpanded, whose output is read as further
    /// `authorized_keys` lines. `none` ⇒ `Some(vec![])`.
    pub authorized_keys_command: Option<Vec<String>>,
    /// `AuthorizedKeysCommandUser` — the account the command runs as.
    pub authorized_keys_command_user: Option<String>,
    /// `AuthorizedPrincipalsCommand` — like `AuthorizedKeysCommand`, but
    /// its output is read as `AuthorizedPrincipalsFile` lines.
    pub authorized_principals_command: Option<Vec<String>>,
    /// `AuthorizedPrincipalsCommandUser`.
    pub authorized_principals_command_user: Option<String>,
    /// `AuthorizedKeysFile` — one or more path *templates* (space-separated
    /// on the config line), each resolved per login user: `%u` (username),
    /// `%h` (home directory) and `%%` are expanded, and a relative path is
    /// taken relative to the user's home directory. `none` ⇒ `Some(vec![])`
    /// (no file is consulted). `None` ⇒ the OpenSSH default
    /// `.ssh/authorized_keys .ssh/authorized_keys2`.
    pub authorized_keys_file: Option<Vec<String>>,
    /// `AllowUsers` — cumulative; empty ⇒ "current user only" (matches the
    /// existing CLI default behaviour).
    pub allow_users: Vec<String>,
    /// `LoginGraceTime` in seconds; `0` disables.
    pub login_grace_time: Option<u32>,
    /// `MaxStartups` (first sub-field only — the OpenSSH `start:rate:full`
    /// triple is rejected as a bad value).
    pub max_startups: Option<u32>,
    /// `MaxStartups start:rate:full` — the `(start, rate)` half: from `start`
    /// unauthenticated connections on, refuse new ones with a probability
    /// rising linearly from `rate`% to 100% at `full` (= `max_startups`).
    pub max_startups_early: Option<(u32, u32)>,
    /// `AllowAgentForwarding` (yes/no).
    pub allow_agent_forwarding: Option<bool>,
    /// `X11Forwarding` (yes/no).
    pub x11_forwarding: Option<bool>,
    /// `PermitUserRC` (yes/no): whether `~/.ssh/rc` runs at session start.
    pub permit_user_rc: Option<bool>,
    /// `TCPKeepAlive` (yes/no; default yes): `SO_KEEPALIVE` on connections.
    pub tcp_keep_alive: Option<bool>,
    /// `XAuthLocation`: the `xauth` that adds a forwarded display's cookie
    /// (`none` ⇒ never run).
    pub xauth_location: Option<String>,
    /// `AcceptEnv` patterns — cumulative.
    pub accept_env: Vec<String>,
    /// `SetEnv` `NAME=value` entries — cumulative; the first value of a
    /// name wins. They override the client's and the user's variables.
    pub set_env: Vec<String>,
    /// `PermitUserEnvironment`: `no`, `yes`, or a pattern list of the
    /// variable names `~/.ssh/environment` and `environment=` may set.
    pub permit_user_environment: Option<String>,
    /// `StrictModes` (yes/no).
    pub strict_modes: Option<bool>,
    /// `LogLevel`, numbered as OpenSSH orders them: 0 QUIET, 1 FATAL,
    /// 2 ERROR, 3 INFO (the default), 4 VERBOSE, 5 DEBUG1, 6 DEBUG2,
    /// 7 DEBUG3. See [`LOG_LEVELS`].
    pub log_level: Option<u8>,
    /// `SyslogFacility` (`AUTH` by default), upper-cased.
    pub syslog_facility: Option<String>,
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
    /// `CASignatureAlgorithms` — resolved set of signature algorithms accepted
    /// from a CA when verifying a user certificate. `None` ⇒ built-in default
    /// (`algos::CA_SIGNATURE_DEFAULTS`).
    pub ca_signature_algorithms: Option<Vec<String>>,
    /// `PubkeyAuthentication` (yes/no). `no` ⇒ public-key auth is dropped from
    /// the advertised method set, which (since it is the only honorable
    /// method) locks the connection out. `None`/`yes` ⇒ enabled.
    pub pubkey_authentication: Option<bool>,
    /// `PasswordAuthentication` (yes/no). `yes` advertises the `password`
    /// method (subject to a PAM backend being compiled in — see the crate
    /// docs); `no`/`None` ⇒ disabled.
    pub password_authentication: Option<bool>,
    /// `KbdInteractiveAuthentication` (alias `ChallengeResponseAuthentication`)
    /// (yes/no). `yes` advertises `keyboard-interactive` (subject to a PAM
    /// backend); `no`/`None` ⇒ disabled.
    pub kbd_interactive_authentication: Option<bool>,
    /// `PermitEmptyPasswords` (yes/no). When `yes`, the server will attempt to
    /// authenticate an account with an empty password (passed through to PAM);
    /// when `no`/`None` an empty password is rejected without consulting the
    /// backend.
    pub permit_empty_passwords: Option<bool>,
    /// `AuthenticationMethods` — space-separated alternatives, each a
    /// comma-separated chain of required factors (e.g.
    /// `publickey,password`). Each factor must be one of `publickey`,
    /// `password`, `keyboard-interactive`, `any`, or `none`; genuinely-unknown
    /// tokens are rejected at parse time as [`ConfigError::BadValue`]. Stored as
    /// the raw token list; the binary maps it into a multi-factor chain set.
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
    /// `ChrootDirectory` — chroot for the session. The `sshd` binary performs
    /// a real `chroot()` (in its privilege-drop hook, while still root, before
    /// `setuid`) that confines shell, exec, and the in-process SFTP subsystem
    /// alike. `%h`/`%u` tokens are expanded; the directory must be root-owned
    /// and not group/world-writable. `None` ⇒ no chroot.
    pub chroot_directory: Option<String>,
    /// `ClientAliveInterval` in seconds — server keepalive cadence. `0`/`None`
    /// ⇒ disabled.
    pub client_alive_interval: Option<u32>,
    /// `ClientAliveCountMax` — number of unanswered keepalives tolerated before
    /// the connection is dropped. `None` ⇒ default 3.
    pub client_alive_count_max: Option<u32>,
    /// `UnusedConnectionTimeout` in seconds: close a connection that has
    /// had no open channel for this long. `Some(0)` is `none`.
    pub unused_connection_timeout: Option<u32>,
    /// `PrintLastLog` (yes by default): `Last login: … from …` before an
    /// interactive pty session.
    pub print_last_log: Option<bool>,
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
    /// alias). Other subsystems are in [`Self::subsystems`].
    pub subsystem_sftp: Option<bool>,
    /// The sftp-server arguments of that `Subsystem sftp` line (`-d`,
    /// `-u`, `-R`, …), applied by the in-process server.
    pub subsystem_sftp_args: Option<Vec<String>>,
    /// Every `Subsystem` line, as written: name and command line (an
    /// `internal-sftp` / `sftp-server` command is served in-process, any
    /// other runs as an `exec` would). Valid in a `Match` block.
    pub subsystems: Option<Vec<(String, String)>>,
    /// `KnockListen` — UDP address(es) for the puressh knock rendezvous
    /// (`docs/knock.md`): `addr`, `addr:port` or `[v6]:port`. A missing port
    /// means the SSH `Port`. Cumulative; empty ⇒ knock disabled.
    pub knock_listen: Vec<String>,
    /// `KnockUsers` — optional narrowing of who may knock (literal names,
    /// cumulative). Empty ⇒ any user; logins are still subject to the usual
    /// access checks.
    pub knock_users: Vec<String>,
    /// `KnockPorts` — `lo-hi` TCP port range for rendezvous listeners.
    /// `None` ⇒ kernel-chosen ephemeral ports.
    pub knock_ports: Option<(u16, u16)>,
    /// `KnockWindow` — seconds a rendezvous listener stays open.
    pub knock_window: Option<u32>,
    /// `KnockClockSkew` — largest accepted client clock offset, seconds.
    pub knock_clock_skew: Option<u32>,
    /// `KnockMaxPending` — open rendezvous listeners per (user, key).
    pub knock_max_pending: Option<u32>,
    /// `UsePAM` (yes/no). `None` ⇒ default (PAM used when compiled in).
    pub use_pam: Option<bool>,
    /// `PermitTTY` (yes/no) — whether `pty-req` may be honoured.
    pub permit_tty: Option<bool>,
    /// `DisableForwarding` (yes/no) — `yes` refuses every kind of forwarding
    /// (TCP, StreamLocal, agent, X11), overriding the individual keywords.
    pub disable_forwarding: Option<bool>,
    /// `AllowStreamLocalForwarding` — which Unix-socket forwarding directions
    /// are permitted (in addition to the `AllowTcpForwarding` ceiling).
    pub allow_stream_local_forwarding: Option<TcpForwarding>,
    /// `PubkeyAcceptedAlgorithms` (alias `PubkeyAcceptedKeyTypes`) — the
    /// signature algorithms accepted for publickey authentication.
    pub pubkey_accepted_algorithms: Option<Vec<String>>,
    /// `RequiredRSASize` — minimum RSA modulus size, in bits, for user keys.
    pub required_rsa_size: Option<u32>,
    /// `PerSourceMaxStartups` — cap on connections per source address.
    /// `Some(0)` stands for the literal `none`.
    pub per_source_max_startups: Option<u32>,
    /// Every `Port` line, in order (OpenSSH listens on all of them; `port`
    /// keeps only the first, as `Match LocalPort` and older callers expect).
    pub ports: Vec<u16>,
    /// Non-fatal diagnostics from parsing this block: OpenSSH keywords that
    /// are accepted but not implemented, or arguments that are ignored. Never
    /// merged across blocks; see [`SshServerConfig::warnings`].
    pub warnings: Vec<String>,
}

/// `AllowTcpForwarding` policy: which forwarding directions are permitted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
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
#[non_exhaustive]
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
#[non_exhaustive]
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
#[non_exhaustive]
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
#[non_exhaustive]
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
#[non_exhaustive]
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

    /// Read `path` from disk and parse it, resolving `Include` directives
    /// recursively. Relative paths inside `Include` are anchored to the
    /// directory of the file containing the directive; `~` expands to
    /// `$HOME`; `*` / `?` globs are expanded against the filesystem.
    /// Recursion is capped at `include::MAX_INCLUDE_DEPTH` hops.
    ///
    /// Prefer this over [`Self::parse`] for on-disk `sshd_config` files:
    /// `parse` has no filesystem context and rejects any `Include` line.
    #[cfg(feature = "std")]
    pub fn load<P: AsRef<std::path::Path>>(path: P) -> Result<Self, ConfigError> {
        let lines = super::include::tokenize_file_with_includes(path.as_ref(), 0)?;
        Self::from_lines(lines)
    }

    /// Build an [`SshServerConfig`] from an already-tokenized line stream.
    /// Used by the `Include`-aware loader, which expands includes before
    /// handing the flattened stream here.
    pub fn from_lines(lines: Vec<ParsedLine>) -> Result<Self, ConfigError> {
        let mut global = ServerOptions::default();
        let mut match_blocks: Vec<ServerMatchBlock> = Vec::new();
        // The open block (`None`: global), and the ones open at each
        // enclosing `Include`, restored when its file ends (OpenSSH).
        let mut current: Option<usize> = None;
        let mut at_include: Vec<Option<usize>> = Vec::new();
        // The criteria of the `Match` block each enclosing `Include` sits in:
        // a `Match` in the included file applies only where they hold too.
        let mut guards: Vec<Vec<MatchCondition>> = Vec::new();
        for line in lines {
            match line.keyword.as_str() {
                super::parser::INCLUDE_BEGIN => {
                    at_include.push(current);
                    guards.push(
                        current.map_or_else(Vec::new, |i| match_blocks[i].conditions.clone()),
                    );
                }
                super::parser::INCLUDE_END => {
                    guards.pop();
                    let saved = at_include.pop().flatten();
                    if saved != current {
                        // Lines after the Include belong to the block open
                        // before it, coming after the included ones.
                        current = saved.map(|i| {
                            match_blocks.push(ServerMatchBlock {
                                conditions: match_blocks[i].conditions.clone(),
                                opts: ServerOptions::default(),
                            });
                            match_blocks.len() - 1
                        });
                    }
                }
                _ => {
                    Self::apply_line(&mut global, &mut match_blocks, &mut current, &line)
                        .map_err(|e| e.in_file(line.file.as_deref()))?;
                    if line.keyword == "match"
                        && let Some(block) = match_blocks.last_mut()
                    {
                        let mut conditions: Vec<MatchCondition> =
                            guards.iter().flatten().cloned().collect();
                        conditions.append(&mut block.conditions);
                        block.conditions = conditions;
                    }
                }
            }
        }
        Ok(SshServerConfig {
            global,
            match_blocks,
        })
    }

    /// Apply one line to the global section or the open `Match` block.
    fn apply_line(
        global: &mut ServerOptions,
        match_blocks: &mut Vec<ServerMatchBlock>,
        current: &mut Option<usize>,
        line: &ParsedLine,
    ) -> Result<(), ConfigError> {
        if line.keyword == "include" {
            // The Include-expansion pass runs before us when the caller
            // uses SshServerConfig::load (the std-only, file-based entry
            // point). Seeing an Include here means we were reached via
            // SshServerConfig::parse(&str), which has no filesystem
            // context — refuse rather than silently drop.
            return Err(ConfigError::Unsupported {
                line: line.line_no,
                msg: "Include requires file-based loading; use SshServerConfig::load() instead"
                    .into(),
            });
        }
        if line.keyword == "match" {
            let conditions = parse_match_line_server(&line.args, line.line_no)?;
            match_blocks.push(ServerMatchBlock {
                conditions,
                opts: ServerOptions::default(),
            });
            *current = Some(match_blocks.len() - 1);
            return Ok(());
        }
        // Route the directive to the open block: a Match block, or global.
        let in_match = current.is_some();
        let target = match *current {
            Some(i) => &mut match_blocks[i].opts,
            None => global,
        };
        if in_match {
            reject_invalid_in_match(line)?;
        }
        // sshd_config(5): "for each parameter, the first obtained value
        // will be used" (list keywords accumulate). Applying each line to
        // a scratch block and merging gives exactly that, so a later
        // drop-in or line cannot override an earlier one.
        let mut one = ServerOptions::default();
        apply_keyword(&mut one, line)?;
        target.warnings.append(&mut one.warnings);
        merge_server_options(target, &one);
        Ok(())
    }

    /// Resolve the effective [`ServerOptions`] for `ctx` with `sshd_config(5)`
    /// semantics: every `Match` block whose conditions all match is merged in
    /// source order — for a scalar keyword the *first* matching block that
    /// sets it wins — and the resulting values **override** the global
    /// section, which only supplies a keyword no matching block set. List
    /// fields concatenate (matching blocks first, then global).
    ///
    /// `policy` controls `Match exec` evaluation (default-deny on the server;
    /// see [`ExecPolicy`]).
    pub fn resolve(&self, ctx: &MatchContext<'_>, policy: ExecPolicy) -> ServerOptions {
        let mut out = ServerOptions::default();
        for block in &self.match_blocks {
            if all_match(&block.conditions, ctx, policy) {
                merge_server_options(&mut out, &block.opts);
            }
        }
        merge_server_options(&mut out, &self.global);
        out
    }

    /// Every options block in the file — the global section followed by each
    /// `Match` block's options in source order — regardless of what matches.
    /// Lets a daemon pre-validate / pre-load every file path that *could*
    /// apply to some connection (`TrustedUserCAKeys`, `RevokedKeys`, …) at
    /// startup, so a bad path fails loudly instead of at login time.
    pub fn all_blocks(&self) -> impl Iterator<Item = &ServerOptions> {
        core::iter::once(&self.global).chain(self.match_blocks.iter().map(|b| &b.opts))
    }

    /// Every non-fatal parse diagnostic, global section first: OpenSSH
    /// keywords accepted for compatibility but not implemented, and ignored
    /// arguments. A daemon should log these at startup (and for `-t`).
    pub fn warnings(&self) -> impl Iterator<Item = &str> {
        self.all_blocks()
            .flat_map(|b| b.warnings.iter().map(String::as_str))
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
    take_scalar!(max_startups_early);
    take_scalar!(allow_agent_forwarding);
    take_scalar!(x11_forwarding);
    take_scalar!(permit_user_rc);
    take_scalar!(tcp_keep_alive);
    take_scalar!(xauth_location);
    take_scalar!(strict_modes);
    take_scalar!(log_level);
    take_scalar!(print_last_log);
    take_scalar!(syslog_facility);
    take_scalar!(sftp_enabled);
    take_scalar!(sftp_read_only);
    take_scalar!(sftp_root);
    take_scalar!(scp_enabled);
    take_scalar!(permit_root_login);
    take_scalar!(ciphers);
    take_scalar!(macs);
    take_scalar!(kex_algorithms);
    take_scalar!(host_key_algorithms);
    take_scalar!(ca_signature_algorithms);
    take_scalar!(pubkey_authentication);
    take_scalar!(password_authentication);
    take_scalar!(kbd_interactive_authentication);
    take_scalar!(permit_empty_passwords);
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
    take_scalar!(unused_connection_timeout);
    take_scalar!(print_motd);
    take_scalar!(compression);
    take_scalar!(rekey_limit);
    take_scalar!(address_family);
    take_scalar!(pam_service_name);
    take_scalar!(expose_auth_info);
    take_scalar!(channel_timeouts);
    take_scalar!(per_source_penalties);
    take_scalar!(per_source_penalty_exempt);
    take_scalar!(per_source_net_block_size);
    take_scalar!(host_key_agent);
    take_scalar!(subsystem_sftp);
    take_scalar!(subsystem_sftp_args);
    take_scalar!(use_pam);
    take_scalar!(permit_tty);
    take_scalar!(disable_forwarding);
    take_scalar!(allow_stream_local_forwarding);
    take_scalar!(pubkey_accepted_algorithms);
    take_scalar!(required_rsa_size);
    take_scalar!(per_source_max_startups);
    take_scalar!(knock_ports);
    take_scalar!(knock_window);
    take_scalar!(knock_clock_skew);
    take_scalar!(knock_max_pending);
    dst.knock_listen.extend(src.knock_listen.iter().cloned());
    dst.ports.extend(src.ports.iter().copied());
    dst.knock_users.extend(src.knock_users.iter().cloned());
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
    dst.host_certificate_files
        .extend(src.host_certificate_files.iter().cloned());
    take_scalar!(trusted_user_ca_keys);
    take_scalar!(revoked_keys);
    take_scalar!(authorized_principals_file);
    take_scalar!(authorized_keys_command);
    take_scalar!(authorized_keys_command_user);
    take_scalar!(authorized_principals_command);
    take_scalar!(authorized_principals_command_user);
    dst.allow_users.extend(src.allow_users.iter().cloned());
    dst.accept_env.extend(src.accept_env.iter().cloned());
    dst.set_env.extend(src.set_env.iter().cloned());
    if dst.permit_user_environment.is_none() {
        dst.permit_user_environment = src.permit_user_environment.clone();
    }
    // Subsystems: the first definition of a name wins (a `Match` block's
    // over the global one, an earlier line's over a later one).
    if let Some(list) = &src.subsystems {
        let have = dst.subsystems.get_or_insert_with(Vec::new);
        for (name, command) in list {
            if !have.iter().any(|(n, _)| n == name) {
                have.push((name.clone(), command.clone()));
            }
        }
    }
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
        "hostcertificate",
        "hostkeyagent",
        "addressfamily",
        "pidfile",
        "loglevel",
        "compression",
        "rekeylimit",
        "logingracetime",
        "maxstartups",
        "strictmodes",
        "include",
        "permittunnel",
        // `AcceptEnv` is valid in a Match block in OpenSSH, but this server
        // applies the env allow-list once, connection-wide, from the global
        // section; a per-block list would be silently ignored, so refuse it.
        "acceptenv",
        // The knock socket and its key table are built once at startup.
        "knocklisten",
        "knockusers",
        "knockports",
        "knockwindow",
        "knockclockskew",
        "knockmaxpending",
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
            let port = parse_u16(line)?;
            opts.port = Some(port);
            opts.ports.push(port);
        }
        "listenaddress" => {
            opts.listen_addresses.push(one_arg(line)?);
        }
        "hostkey" => {
            opts.host_key_files.push(one_arg(line)?);
        }
        "hostcertificate" => {
            opts.host_certificate_files.push(one_arg(line)?);
        }
        "persourcepenalties" => {
            let mut p = PerSourcePenalties::default();
            let bad = |msg: String| ConfigError::BadValue {
                line: line.line_no,
                keyword: kw.to_string(),
                msg,
            };
            match line.args.as_slice() {
                [] => return Err(bad("expected yes, no or penalty settings".into())),
                [one] if one.eq_ignore_ascii_case("yes") => {}
                [one] if one.eq_ignore_ascii_case("no") => p.enabled = false,
                args => {
                    for spec in args {
                        let (k, v) = spec
                            .split_once(':')
                            .ok_or_else(|| bad(format!("expected name:value, got {spec:?}")))?;
                        // OpenSSH also takes (and `sshd -T` prints)
                        // fractional seconds: `crash:90.000000`.
                        let secs = || match v.parse::<f64>() {
                            Ok(f) if f.is_finite() && f >= 0.0 => Ok((f + 0.5) as u32),
                            _ => parse_duration_str(v, line),
                        };
                        let count = || {
                            v.parse::<u32>()
                                .map_err(|_| bad(format!("bad number in {spec:?}")))
                        };
                        let overflow = || match v {
                            "deny-all" => Ok(true),
                            "permissive" => Ok(false),
                            _ => Err(bad(format!("bad overflow mode {v:?}"))),
                        };
                        match k {
                            "crash" => p.crash = secs()?,
                            "authfail" => p.authfail = secs()?,
                            "invaliduser" => p.invalid_user = secs()?,
                            "noauth" => p.noauth = secs()?,
                            "grace-exceeded" => p.grace_exceeded = secs()?,
                            "refuseconnection" => p.refuse_connection = secs()?,
                            "min" => p.min = secs()?,
                            "max" => p.max = secs()?,
                            "max-sources4" => p.max_sources4 = count()?,
                            "max-sources6" => p.max_sources6 = count()?,
                            "overflow" => p.overflow_deny_all = overflow()?,
                            "overflow6" => p.overflow6_deny_all = overflow()?,
                            _ => return Err(bad(format!("unknown penalty {k:?}"))),
                        }
                    }
                }
            }
            opts.per_source_penalties = Some(p);
        }
        "persourcepenaltyexemptlist" => {
            let v = one_arg(line)?;
            opts.per_source_penalty_exempt = (!v.eq_ignore_ascii_case("none")).then_some(v);
        }
        "persourcenetblocksize" => {
            let v = one_arg(line)?;
            let bad = || ConfigError::BadValue {
                line: line.line_no,
                keyword: kw.to_string(),
                msg: format!("expected v4[:v6] prefix lengths, got {v:?}"),
            };
            let (v4, v6) = v.split_once(':').unwrap_or((v.as_str(), "128"));
            let v4: u8 = v4.parse().map_err(|_| bad())?;
            let v6: u8 = v6.parse().map_err(|_| bad())?;
            if v4 > 32 || v6 > 128 {
                return Err(bad());
            }
            opts.per_source_net_block_size = Some((v4, v6));
        }
        "channeltimeout" => {
            let mut list = Vec::new();
            if !(line.args.len() == 1 && line.args[0].eq_ignore_ascii_case("none")) {
                for spec in &line.args {
                    let Some((ty, interval)) = spec.split_once('=') else {
                        return Err(ConfigError::BadValue {
                            line: line.line_no,
                            keyword: kw.to_string(),
                            msg: format!("expected type=interval, got {spec:?}"),
                        });
                    };
                    if ty.is_empty() {
                        return Err(ConfigError::BadValue {
                            line: line.line_no,
                            keyword: kw.to_string(),
                            msg: format!("missing channel type in {spec:?}"),
                        });
                    }
                    list.push((ty.to_string(), parse_duration_str(interval, line)?));
                }
            }
            opts.channel_timeouts = Some(list);
        }
        "exposeauthinfo" => {
            opts.expose_auth_info = Some(parse_yes_no(line)?);
        }
        "pamservicename" => {
            opts.pam_service_name = Some(one_arg(line)?);
        }
        "hostkeyagent" => {
            let v = one_arg(line)?;
            opts.host_key_agent = (!v.eq_ignore_ascii_case("none")).then_some(v);
        }
        "knocklisten" => {
            opts.knock_listen.push(one_arg(line)?);
        }
        "knockusers" => {
            if line.args.is_empty() {
                return Err(ConfigError::BadValue {
                    line: line.line_no,
                    keyword: kw.to_string(),
                    msg: "expected at least one user name".into(),
                });
            }
            opts.knock_users.extend(line.args.iter().cloned());
        }
        "knockports" => {
            let s = one_arg(line)?;
            let range = s
                .split_once('-')
                .and_then(|(lo, hi)| Some((lo.parse::<u16>().ok()?, hi.parse::<u16>().ok()?)))
                .filter(|(lo, hi)| *lo > 0 && lo <= hi);
            opts.knock_ports = Some(range.ok_or_else(|| ConfigError::BadValue {
                line: line.line_no,
                keyword: kw.to_string(),
                msg: format!("expected lo-hi port range, got {s:?}"),
            })?);
        }
        "knockwindow" | "knockclockskew" => {
            let secs = parse_duration_seconds(line)?;
            if secs == 0 || secs > u16::MAX as u32 {
                return Err(ConfigError::BadValue {
                    line: line.line_no,
                    keyword: kw.to_string(),
                    msg: "expected 1..=65535 seconds".into(),
                });
            }
            if kw == "knockwindow" {
                opts.knock_window = Some(secs);
            } else {
                opts.knock_clock_skew = Some(secs);
            }
        }
        "knockmaxpending" => {
            let n = parse_u16(line)?;
            if n == 0 {
                return Err(ConfigError::BadValue {
                    line: line.line_no,
                    keyword: kw.to_string(),
                    msg: "must be at least 1".into(),
                });
            }
            opts.knock_max_pending = Some(n as u32);
        }
        "trustedusercakeys" => {
            opts.trusted_user_ca_keys = Some(one_arg(line)?);
        }
        "revokedkeys" => {
            if line.args.is_empty() {
                return Err(ConfigError::BadValue {
                    line: line.line_no,
                    keyword: kw.to_string(),
                    msg: "expected at least one file".into(),
                });
            }
            opts.revoked_keys = Some(if line.args.len() == 1 && line.args[0] == "none" {
                Vec::new()
            } else {
                line.args.clone()
            });
        }
        "syslogfacility" => {
            let f = one_arg(line)?.to_ascii_uppercase();
            const FACILITIES: &[&str] = &[
                "DAEMON", "USER", "AUTH", "AUTHPRIV", "LOCAL0", "LOCAL1", "LOCAL2", "LOCAL3",
                "LOCAL4", "LOCAL5", "LOCAL6", "LOCAL7",
            ];
            if !FACILITIES.contains(&f.as_str()) {
                return Err(ConfigError::BadValue {
                    line: line.line_no,
                    keyword: line.keyword.clone(),
                    msg: format!("unsupported log facility {f:?}"),
                });
            }
            opts.syslog_facility = Some(f);
        }
        "authorizedprincipalsfile" => {
            opts.authorized_principals_file = Some(one_arg(line)?);
        }
        "authorizedkeyscommand" | "authorizedprincipalscommand" => {
            let cmd = command_args(line)?;
            if kw == "authorizedkeyscommand" {
                opts.authorized_keys_command = Some(cmd);
            } else {
                opts.authorized_principals_command = Some(cmd);
            }
        }
        "authorizedkeyscommanduser" => {
            opts.authorized_keys_command_user = Some(one_arg(line)?);
        }
        "authorizedprincipalscommanduser" => {
            opts.authorized_principals_command_user = Some(one_arg(line)?);
        }
        "authorizedkeysfile" => {
            if line.args.is_empty() {
                return Err(ConfigError::BadValue {
                    line: line.line_no,
                    keyword: kw.to_string(),
                    msg: "expected one or more file paths, or none".into(),
                });
            }
            // `none` disables the file entirely (OpenSSH); otherwise each
            // argument is a path template resolved per user by the daemon.
            if line.args.len() == 1 && line.args[0].eq_ignore_ascii_case("none") {
                opts.authorized_keys_file = Some(Vec::new());
            } else {
                opts.authorized_keys_file = Some(line.args.clone());
            }
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
                let bad = || ConfigError::BadValue {
                    line: line.line_no,
                    keyword: kw.to_string(),
                    msg: format!(
                        "expected N or start:rate:full (start <= full, rate <= 100), got {s:?}"
                    ),
                };
                let parts: Vec<u32> = s
                    .split(':')
                    .map(|p| p.parse::<u32>())
                    .collect::<Result<_, _>>()
                    .map_err(|_| bad())?;
                let [start, rate, full] = parts[..] else {
                    return Err(bad());
                };
                if start > full || rate > 100 || full == 0 {
                    return Err(bad());
                }
                opts.max_startups = Some(full);
                opts.max_startups_early = Some((start, rate));
                return Ok(());
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
        "tcpkeepalive" => {
            opts.tcp_keep_alive = Some(parse_yes_no(line)?);
        }
        "permituserrc" => {
            opts.permit_user_rc = Some(parse_yes_no(line)?);
        }
        "xauthlocation" => {
            opts.xauth_location = Some(one_arg(line)?);
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
        "setenv" => {
            for a in &line.args {
                if !a.contains('=') || a.starts_with('=') {
                    return Err(ConfigError::BadValue {
                        line: line.line_no,
                        keyword: kw.to_string(),
                        msg: alloc::format!("expected NAME=value, got {a:?}"),
                    });
                }
                opts.set_env.push(a.clone());
            }
        }
        "permituserenvironment" => {
            let v = line.args.join(",");
            if v.is_empty() {
                return Err(ConfigError::BadValue {
                    line: line.line_no,
                    keyword: kw.to_string(),
                    msg: "expected yes, no or a pattern list".into(),
                });
            }
            opts.permit_user_environment = Some(v);
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
            opts.ca_signature_algorithms = Some(resolve_algo_list(
                AlgoCategory::CaSignature,
                &line.args,
                line.line_no,
                "CASignatureAlgorithms",
            )?);
        }
        "pubkeyauthentication" => {
            opts.pubkey_authentication = Some(parse_yes_no(line)?);
        }
        "passwordauthentication" => {
            opts.password_authentication = Some(parse_yes_no(line)?);
        }
        "kbdinteractiveauthentication" | "challengeresponseauthentication" => {
            opts.kbd_interactive_authentication = Some(parse_yes_no(line)?);
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
            // alternative is a comma-separated chain of required factors. Every
            // factor must be a method puressh understands; a genuinely-unknown
            // token is a configuration error (BadValue), not a silent accept.
            for alt in &line.args {
                if alt == "any" {
                    continue;
                }
                let factors: Vec<&str> = alt.split(',').filter(|s| !s.is_empty()).collect();
                if factors.is_empty() {
                    return Err(ConfigError::BadValue {
                        line: line.line_no,
                        keyword: kw.to_string(),
                        msg: format!("empty method list in {alt:?}"),
                    });
                }
                for factor in factors {
                    if !matches!(
                        factor,
                        "publickey" | "password" | "keyboard-interactive" | "any" | "none"
                    ) {
                        return Err(ConfigError::BadValue {
                            line: line.line_no,
                            keyword: kw.to_string(),
                            msg: format!("unknown authentication method {factor:?}"),
                        });
                    }
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
            opts.permit_empty_passwords = Some(parse_yes_no(line)?);
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
        "unusedconnectiontimeout" => {
            let v = one_arg(line)?;
            opts.unused_connection_timeout = Some(if v.eq_ignore_ascii_case("none") {
                0
            } else {
                parse_duration_str(&v, line)?
            });
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
        "printlastlog" => {
            opts.print_last_log = Some(parse_yes_no(line)?);
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
            // Standard form: `Subsystem <name> <command> [args…]`. SFTP is
            // served in-process, OpenSSH's external `sftp-server` mapped onto
            // it (Debian/Ubuntu ship that line by default); other commands
            // run as an `exec` would.
            if line.args.len() < 2 {
                return Err(ConfigError::BadValue {
                    line: line.line_no,
                    keyword: kw.to_string(),
                    msg: "expected `Subsystem <name> <command>`".into(),
                });
            }
            let command = &line.args[1];
            let base = command.rsplit('/').next().unwrap_or(command);
            if line.args[0].eq_ignore_ascii_case("sftp")
                && (command.eq_ignore_ascii_case("internal-sftp") || base == "sftp-server")
            {
                opts.subsystem_sftp = Some(true);
                apply_sftp_server_args(opts, line, &line.args[2..])?;
                opts.subsystem_sftp_args = Some(line.args[2..].to_vec());
            }
            // As written: the name is case-sensitive, and the command keeps
            // its quoting for the shell.
            let name = line.args[0].clone();
            let command = line
                .rest
                .trim_start()
                .strip_prefix(name.as_str())
                .map_or_else(|| line.args[1..].join(" "), |c| c.trim().to_string());
            opts.subsystems
                .get_or_insert_with(Vec::new)
                .push((name, command));
        }
        "permittunnel" => {
            if !one_arg(line)?.eq_ignore_ascii_case("no") {
                return Err(ConfigError::Unsupported {
                    line: line.line_no,
                    msg: "PermitTunnel: tun/tap device forwarding is not supported; \
                          only `PermitTunnel no` is accepted"
                        .into(),
                });
            }
        }
        "usepam" => {
            opts.use_pam = Some(parse_yes_no(line)?);
        }
        "permittty" => {
            opts.permit_tty = Some(parse_yes_no(line)?);
        }
        "disableforwarding" => {
            opts.disable_forwarding = Some(parse_yes_no(line)?);
        }
        "allowstreamlocalforwarding" => {
            opts.allow_stream_local_forwarding = Some(parse_tcp_forwarding(line)?);
        }
        "pubkeyacceptedalgorithms" | "pubkeyacceptedkeytypes" => {
            opts.pubkey_accepted_algorithms = Some(resolve_algo_list(
                AlgoCategory::PubkeyAccepted,
                &line.args,
                line.line_no,
                "PubkeyAcceptedAlgorithms",
            )?);
        }
        "requiredrsasize" => {
            let s = one_arg(line)?;
            opts.required_rsa_size = Some(s.parse::<u32>().map_err(|_| ConfigError::BadValue {
                line: line.line_no,
                keyword: kw.to_string(),
                msg: format!("expected a number of bits, got {s:?}"),
            })?);
        }
        "persourcemaxstartups" => {
            let s = one_arg(line)?;
            opts.per_source_max_startups = Some(if s.eq_ignore_ascii_case("none") {
                0
            } else {
                s.parse::<u32>()
                    .ok()
                    .filter(|n| *n > 0)
                    .ok_or_else(|| ConfigError::BadValue {
                        line: line.line_no,
                        keyword: kw.to_string(),
                        msg: format!("expected a positive number or `none`, got {s:?}"),
                    })?
            });
        }
        kw if IGNORED_KEYWORDS
            .iter()
            .any(|(k, _, _)| k.eq_ignore_ascii_case(kw)) =>
        {
            let (name, quiet, note) = IGNORED_KEYWORDS
                .iter()
                .find(|(k, _, _)| k.eq_ignore_ascii_case(kw))
                .expect("checked by the guard");
            let value = line.args.join(" ");
            let lower = value.to_ascii_lowercase();
            if !(quiet.contains(&"*") || quiet.contains(&lower.as_str())) {
                opts.warnings.push(format!(
                    "{}: {name} {value}: not implemented, ignored{}{note}",
                    line.location(),
                    if note.is_empty() { "" } else { " — " },
                ));
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

/// OpenSSH `sshd_config` keywords accepted for compatibility but not
/// implemented: `(keyword as OpenSSH spells it, values that need no warning,
/// note)`. `"*"` means
/// the keyword is always quiet.
///
/// Every entry is safe to ignore: dropping it never grants more access than
/// OpenSSH would. Either it is cosmetic / logging / tuning, or it enables a
/// feature this server lacks (so ignoring it fails closed: e.g. GSSAPI or
/// `AuthorizedKeysCommand` logins are simply unavailable). Keywords that
/// *restrict* access are implemented or rejected, never listed here.
const IGNORED_KEYWORDS: &[(&str, &[&str], &str)] = &[
    // Logging, DNS, network tuning, cosmetics.
    ("UseDNS", &["*"], ""),
    ("LogVerbose", &["*"], ""),
    ("IPQoS", &["*"], ""),
    ("VersionAddendum", &["*"], ""),
    ("DebianBanner", &["*"], ""),
    ("FingerprintHash", &["*"], ""),
    ("ModuliFile", &["*"], ""),
    // OpenSSH 10's helper binaries: this sshd is one program.
    ("SshdSessionPath", &["*"], ""),
    ("SshdAuthPath", &["*"], ""),
    ("X11DisplayOffset", &["*"], ""),
    ("X11UseLocalhost", &["*"], ""),
    ("StreamLocalBindMask", &["*"], ""),
    ("StreamLocalBindUnlink", &["*"], ""),
    // Features this server does not have: ignoring them fails closed.
    ("SecurityKeyProvider", &["*"], ""),
    ("PubkeyAuthOptions", &["*"], ""),
    (
        "GSSAPIAuthentication",
        &["no"],
        "GSSAPI authentication is unavailable",
    ),
    (
        "GSSAPIKeyExchange",
        &["no"],
        "GSSAPI key exchange is unavailable",
    ),
    ("GSSAPICleanupCredentials", &["*"], ""),
    ("GSSAPIStrictAcceptorCheck", &["*"], ""),
    ("GSSAPIStoreCredentialsOnRekey", &["*"], ""),
    ("GSSAPIKexAlgorithms", &["*"], ""),
    (
        "KerberosAuthentication",
        &["no"],
        "Kerberos authentication is unavailable",
    ),
    ("KerberosOrLocalPasswd", &["*"], ""),
    ("KerberosTicketCleanup", &["*"], ""),
    ("KerberosGetAFSToken", &["*"], ""),
    (
        "HostbasedAuthentication",
        &["no"],
        "host-based authentication is unavailable",
    ),
    ("HostbasedAcceptedAlgorithms", &["*"], ""),
    ("HostbasedAcceptedKeyTypes", &["*"], ""),
    ("HostbasedUsesNameFromPacketOnly", &["*"], ""),
    ("IgnoreRhosts", &["*"], ""),
    ("IgnoreUserKnownHosts", &["*"], ""),
    ("KbdInteractiveDevices", &["*"], ""),
    // Deprecated / removed in OpenSSH itself (it ignores them too).
    ("Protocol", &["*"], ""),
    ("UsePrivilegeSeparation", &["*"], ""),
    ("KeyRegenerationInterval", &["*"], ""),
    ("ServerKeyBits", &["*"], ""),
    ("RSAAuthentication", &["*"], ""),
    ("RhostsRSAAuthentication", &["*"], ""),
    ("DSAAuthentication", &["*"], ""),
    ("UseLogin", &["*"], ""),
    ("PAMAuthenticationViaKbdInt", &["*"], ""),
    ("SkeyAuthentication", &["*"], ""),
    ("KerberosTgtPassing", &["*"], ""),
    ("AFSTokenPassing", &["*"], ""),
    ("VerifyReverseMapping", &["*"], ""),
    ("ReverseMappingCheck", &["*"], ""),
];

/// Arguments after the program in `Subsystem sftp …`, as accepted by
/// OpenSSH's `sftp-server` / `internal-sftp`. `-R` (read-only) is honoured;
/// logging and start-directory options are ignored; options that restrict
/// what a client may do but are not implemented are rejected.
fn apply_sftp_server_args(
    opts: &mut ServerOptions,
    line: &ParsedLine,
    args: &[String],
) -> Result<(), ConfigError> {
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "-R" => opts.sftp_read_only = Some(true),
            "-e" | "-h" => {}
            // Start directory and umask: applied per session. Logging
            // (`-f`, `-l`) follows sshd's own.
            "-d" | "-u" | "-f" | "-l" => i += 1,
            other => {
                return Err(ConfigError::Unsupported {
                    line: line.line_no,
                    msg: format!(
                        "Subsystem sftp: option {other:?} is not supported (only -R, -d, \
                         -u, -e, -f, -l are)"
                    ),
                });
            }
        }
        i += 1;
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
pub(crate) fn parse_rekey_limit(line: &ParsedLine) -> Result<RekeyLimit, ConfigError> {
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

/// `AuthorizedKeysCommand` / `AuthorizedPrincipalsCommand`: `none`, or an
/// absolute program path followed by its arguments.
fn command_args(line: &ParsedLine) -> Result<Vec<String>, ConfigError> {
    match line.args.first() {
        Some(a) if line.args.len() == 1 && a.eq_ignore_ascii_case("none") => Ok(Vec::new()),
        Some(a) if a.starts_with('/') => Ok(line.args.clone()),
        _ => Err(ConfigError::BadValue {
            line: line.line_no,
            keyword: line.keyword.clone(),
            msg: "expected none, or an absolute path to a program".into(),
        }),
    }
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

/// `LogLevel` names, indexed by [`ServerOptions::log_level`].
pub const LOG_LEVELS: [&str; 8] = [
    "QUIET", "FATAL", "ERROR", "INFO", "VERBOSE", "DEBUG1", "DEBUG2", "DEBUG3",
];

fn parse_log_level(line: &ParsedLine) -> Result<u8, ConfigError> {
    let s = one_arg(line)?.to_ascii_uppercase();
    let s = if s == "DEBUG" {
        "DEBUG1".to_string()
    } else {
        s
    };
    LOG_LEVELS
        .iter()
        .position(|l| *l == s)
        .map(|i| i as u8)
        .ok_or_else(|| ConfigError::BadValue {
            line: line.line_no,
            keyword: line.keyword.clone(),
            msg: format!("expected QUIET..DEBUG3, got {s:?}"),
        })
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
        assert_eq!(
            cfg.authorized_keys_file.as_deref(),
            Some(&["/etc/authkeys".to_string()][..])
        );
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
  DenyUsers foo
Match Group dev
  MaxAuthTries 2
  DenyUsers bar
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
        // DenyUsers concatenates across both matching blocks.
        assert_eq!(eff.deny_users, vec!["foo".to_string(), "bar".to_string()]);
    }

    #[test]
    fn match_block_overrides_global_scalar() {
        // sshd_config(5): a keyword set in a matching Match block overrides
        // the global section; global is only the fallback. The security-
        // relevant direction is a global "yes" narrowed to "no" for some
        // peers — that must take effect, never be shadowed by global.
        let src = "\
PasswordAuthentication yes
PermitRootLogin yes
MaxAuthTries 6
Match Address 10.0.0.0/8
  PasswordAuthentication no
  PermitRootLogin no
";
        let cfg = SshServerConfig::parse(src).unwrap();
        let inside = MatchContext {
            host: "h",
            address: Some("10.1.2.3"),
            ..MatchContext::default()
        };
        let eff = cfg.resolve(&inside, ExecPolicy::Deny);
        assert_eq!(eff.password_authentication, Some(false));
        assert_eq!(eff.permit_root_login, Some(PermitRootLogin::No));
        // A scalar the block does not set falls back to global.
        assert_eq!(eff.max_auth_tries, Some(6));
        let outside = MatchContext {
            host: "h",
            address: Some("192.0.2.1"),
            ..MatchContext::default()
        };
        let eff = cfg.resolve(&outside, ExecPolicy::Deny);
        assert_eq!(eff.password_authentication, Some(true));
        assert_eq!(eff.permit_root_login, Some(PermitRootLogin::Yes));
    }

    #[test]
    fn match_access_keywords_resolve_per_connection() {
        // Access-control keywords inside Match blocks resolve into the
        // per-connection options (the daemon applies them at login time).
        let src = "\
AllowUsers alice bob
TrustedUserCAKeys /etc/ssh/ca_global.pub
Match Address 10.0.0.0/8
  DenyUsers *
  AuthorizedKeysFile /etc/ssh/keys/%u
  AuthorizedPrincipalsFile /etc/ssh/principals/%u
  TrustedUserCAKeys /etc/ssh/ca_lan.pub
  RevokedKeys /etc/ssh/lan.krl
  PermitEmptyPasswords yes
Match Group ops
  AllowGroups ops
  DenyGroups contractors
";
        let cfg = SshServerConfig::parse(src).unwrap();
        let groups = vec!["ops".to_string()];
        let lan = MatchContext {
            host: "h",
            user: Some("carol"),
            groups: Some(&groups),
            address: Some("10.9.9.9"),
            ..MatchContext::default()
        };
        let eff = cfg.resolve(&lan, ExecPolicy::Deny);
        assert_eq!(eff.deny_users, vec!["*".to_string()]);
        assert_eq!(
            eff.allow_users,
            vec!["alice".to_string(), "bob".to_string()]
        );
        assert_eq!(
            eff.authorized_keys_file.as_deref(),
            Some(&["/etc/ssh/keys/%u".to_string()][..])
        );
        assert_eq!(
            eff.authorized_principals_file.as_deref(),
            Some("/etc/ssh/principals/%u")
        );
        assert_eq!(
            eff.trusted_user_ca_keys.as_deref(),
            Some("/etc/ssh/ca_lan.pub")
        );
        assert_eq!(
            eff.revoked_keys.as_deref(),
            Some(&["/etc/ssh/lan.krl".to_string()][..])
        );
        assert_eq!(eff.permit_empty_passwords, Some(true));
        assert_eq!(eff.allow_groups, vec!["ops".to_string()]);
        assert_eq!(eff.deny_groups, vec!["contractors".to_string()]);
        // Outside the LAN block: global values only.
        let wan = MatchContext {
            host: "h",
            user: Some("carol"),
            address: Some("192.0.2.1"),
            ..MatchContext::default()
        };
        let eff = cfg.resolve(&wan, ExecPolicy::Deny);
        assert!(eff.deny_users.is_empty());
        assert_eq!(
            eff.trusted_user_ca_keys.as_deref(),
            Some("/etc/ssh/ca_global.pub")
        );
        assert_eq!(eff.revoked_keys, None);
        assert_eq!(eff.permit_empty_passwords, None);
        // `all_blocks` enumerates global + every Match block for preloading.
        let paths: Vec<_> = cfg
            .all_blocks()
            .filter_map(|o| o.trusted_user_ca_keys.clone())
            .collect();
        assert_eq!(
            paths,
            vec![
                "/etc/ssh/ca_global.pub".to_string(),
                "/etc/ssh/ca_lan.pub".to_string()
            ]
        );
    }

    #[test]
    fn set_env_and_permit_user_environment_parse() {
        let cfg = SshServerConfig::parse(
            "SetEnv A=1 \"B=two words\"\nSetEnv A=ignored\nPermitUserEnvironment LANG,TZ\n\
             Match User x\n\tSetEnv C=3\n",
        )
        .unwrap();
        assert_eq!(cfg.global.set_env, ["A=1", "B=two words", "A=ignored"]);
        assert_eq!(
            cfg.global.permit_user_environment.as_deref(),
            Some("LANG,TZ")
        );
        let ctx = MatchContext {
            user: Some("x"),
            ..MatchContext::default()
        };
        assert!(
            cfg.resolve(&ctx, ExecPolicy::Deny)
                .set_env
                .contains(&"C=3".to_string())
        );
        assert!(SshServerConfig::parse("SetEnv NOEQUALS\n").is_err());
        assert_eq!(cfg.warnings().count(), 0);
    }

    #[test]
    fn accept_env_rejected_in_match() {
        let err = SshServerConfig::parse("Match User alice\n  AcceptEnv FOO\n").unwrap_err();
        assert!(
            matches!(err, ConfigError::Unsupported { line: 2, .. }),
            "{err:?}"
        );
    }

    #[test]
    fn authorized_keys_file_list_and_none() {
        let cfg =
            SshServerConfig::parse("AuthorizedKeysFile .ssh/authorized_keys /etc/ssh/keys/%u\n")
                .unwrap()
                .global;
        assert_eq!(
            cfg.authorized_keys_file.as_deref(),
            Some(
                &[
                    ".ssh/authorized_keys".to_string(),
                    "/etc/ssh/keys/%u".to_string()
                ][..]
            )
        );
        let none = SshServerConfig::parse("AuthorizedKeysFile none\n")
            .unwrap()
            .global;
        assert_eq!(none.authorized_keys_file.as_deref(), Some(&[][..]));
        assert!(SshServerConfig::parse("AuthorizedKeysFile\n").is_err());
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
    fn match_password_auth_yes_accepted() {
        let src = "Match User alice\n  PasswordAuthentication yes\n";
        let cfg = SshServerConfig::parse(src).expect("PasswordAuthentication yes parses");
        // Resolve the Match block for `alice` and confirm it took effect.
        let ctx = MatchContext {
            user: Some("alice"),
            ..MatchContext::default()
        };
        let eff = cfg.resolve(&ctx, ExecPolicy::Deny);
        assert_eq!(eff.password_authentication, Some(true));
    }

    #[test]
    fn match_host_on_server_is_the_client_host() {
        let src = "Match Host 192.0.2.*\n  X11Forwarding no\n";
        let cfg = SshServerConfig::parse(src).unwrap();
        let ctx = MatchContext {
            host: "192.0.2.7",
            ..MatchContext::default()
        };
        assert_eq!(
            cfg.resolve(&ctx, ExecPolicy::Deny).x11_forwarding,
            Some(false)
        );
        assert!(SshServerConfig::parse("Match OriginalHost x\n").is_err());
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
    fn authentication_methods_multifactor_accepted() {
        // A multi-factor chain and a single non-publickey factor now parse.
        let cfg = SshServerConfig::parse("AuthenticationMethods publickey,password\n")
            .unwrap()
            .global;
        assert_eq!(
            cfg.authentication_methods.as_deref(),
            Some(&["publickey,password".to_string()][..])
        );
        let cfg2 = SshServerConfig::parse("AuthenticationMethods password\n")
            .unwrap()
            .global;
        assert_eq!(
            cfg2.authentication_methods.as_deref(),
            Some(&["password".to_string()][..])
        );
        // `any` is accepted too.
        assert!(SshServerConfig::parse("AuthenticationMethods any\n").is_ok());
    }

    #[test]
    fn authentication_methods_multiple_alternatives_parse() {
        // Space-separated alternatives, each its own comma chain.
        let cfg = SshServerConfig::parse(
            "AuthenticationMethods publickey,password keyboard-interactive\n",
        )
        .unwrap()
        .global;
        assert_eq!(
            cfg.authentication_methods.as_deref(),
            Some(
                &[
                    "publickey,password".to_string(),
                    "keyboard-interactive".to_string()
                ][..]
            )
        );
    }

    #[test]
    fn authentication_methods_unknown_factor_rejected() {
        let err = SshServerConfig::parse("AuthenticationMethods publickey,bogus\n").unwrap_err();
        assert!(
            matches!(err, ConfigError::BadValue { line: 1, .. }),
            "{err:?}"
        );
    }

    #[test]
    fn permit_empty_passwords_yes_accepted() {
        let cfg = SshServerConfig::parse("PermitEmptyPasswords yes\n")
            .unwrap()
            .global;
        assert_eq!(cfg.permit_empty_passwords, Some(true));
        let cfg2 = SshServerConfig::parse("PermitEmptyPasswords no\n")
            .unwrap()
            .global;
        assert_eq!(cfg2.permit_empty_passwords, Some(false));
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
    fn server_revoked_keys_accepted() {
        let src = "Port 22\nRevokedKeys /etc/ssh/revoked\n";
        let cfg = SshServerConfig::parse(src).unwrap().global;
        assert_eq!(
            cfg.revoked_keys.as_deref(),
            Some(&["/etc/ssh/revoked".to_string()][..])
        );
        let cfg = SshServerConfig::parse("RevokedKeys /dev/null /etc/ssh/krl\n")
            .unwrap()
            .global;
        assert_eq!(cfg.revoked_keys.map(|v| v.len()), Some(2));
        let cfg = SshServerConfig::parse("RevokedKeys none\n").unwrap().global;
        assert_eq!(cfg.revoked_keys, Some(Vec::new()));
    }

    #[test]
    fn server_casignaturealgorithms_accepted() {
        let src = "Port 22\nCASignatureAlgorithms ssh-ed25519,rsa-sha2-512\n";
        let cfg = SshServerConfig::parse(src).unwrap().global;
        assert_eq!(
            cfg.ca_signature_algorithms.as_deref(),
            Some(&["ssh-ed25519".to_string(), "rsa-sha2-512".to_string()][..])
        );
    }

    #[test]
    fn server_casignaturealgorithms_rejects_plain_ssh_rsa() {
        let src = "Port 22\nCASignatureAlgorithms ssh-rsa\n";
        let err = SshServerConfig::parse(src).unwrap_err();
        assert!(matches!(err, ConfigError::BadValue { line: 2, .. }));
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
    fn first_obtained_value_wins_within_a_block() {
        let cfg = SshServerConfig::parse(
            "PasswordAuthentication yes\nPasswordAuthentication no\n\
             ListenAddress a\nListenAddress b\nMaxStartups 10:30:100\n",
        )
        .unwrap();
        assert_eq!(cfg.global.password_authentication, Some(true));
        assert_eq!(cfg.global.listen_addresses, vec!["a", "b"]);
        assert_eq!(cfg.global.max_startups, Some(100));
        assert_eq!(cfg.global.max_startups_early, Some((10, 30)));
        assert!(SshServerConfig::parse("MaxStartups 10:101:100\n").is_err());
        assert!(SshServerConfig::parse("MaxStartups 50:30:10\n").is_err());
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
    fn knock_keywords_parse() {
        let cfg = SshServerConfig::parse(
            "KnockListen 0.0.0.0\nKnockListen [::]:2222\nKnockUsers alice bob\n\
             KnockPorts 40000-40100\nKnockWindow 30\nKnockClockSkew 1m\nKnockMaxPending 3\n",
        )
        .unwrap();
        let g = &cfg.global;
        assert_eq!(g.knock_listen, vec!["0.0.0.0", "[::]:2222"]);
        assert_eq!(g.knock_users, vec!["alice", "bob"]);
        assert_eq!(g.knock_ports, Some((40000, 40100)));
        assert_eq!(g.knock_window, Some(30));
        assert_eq!(g.knock_clock_skew, Some(60));
        assert_eq!(g.knock_max_pending, Some(3));
        for bad in [
            "KnockPorts 5-1",
            "KnockPorts x",
            "KnockWindow 0",
            "KnockMaxPending 0",
        ] {
            assert!(SshServerConfig::parse(bad).is_err(), "{bad}");
        }
        let err = SshServerConfig::parse("Match User a\n  KnockUsers a\n").unwrap_err();
        assert!(matches!(err, ConfigError::Unsupported { .. }));
    }

    /// Active lines of the stock Ubuntu 22.04 / 24.04 `sshd_config`
    /// (`/usr/share/openssh/sshd_config`, identical in both), minus the
    /// `Include` that `parse` cannot resolve.
    const UBUNTU_STOCK: &str = "\
KbdInteractiveAuthentication no
UsePAM yes
X11Forwarding yes
PrintMotd no
AcceptEnv LANG LC_*
Subsystem\tsftp\t/usr/lib/openssh/sftp-server
";

    #[test]
    fn ubuntu_stock_config_parses_without_warnings() {
        let cfg = SshServerConfig::parse(UBUNTU_STOCK).unwrap();
        let g = &cfg.global;
        assert_eq!(g.use_pam, Some(true));
        assert_eq!(g.subsystem_sftp, Some(true));
        assert_eq!(g.x11_forwarding, Some(true));
        assert_eq!(g.print_motd, Some(false));
        assert_eq!(
            cfg.warnings().count(),
            0,
            "{:?}",
            cfg.warnings().collect::<Vec<_>>()
        );
    }

    #[cfg(feature = "std")]
    #[test]
    fn ubuntu_stock_config_with_include_and_cloud_dropins_loads() {
        let dir = std::env::temp_dir().join(format!("puressh_stock_{}", std::process::id()));
        let d = dir.join("sshd_config.d");
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(d.join("50-cloud-init.conf"), "PasswordAuthentication yes\n").unwrap();
        std::fs::write(
            d.join("60-cloudimg-settings.conf"),
            "PasswordAuthentication no\n",
        )
        .unwrap();
        let main = dir.join("sshd_config");
        std::fs::write(
            &main,
            format!("Include {}/*.conf\n{UBUNTU_STOCK}", d.display()),
        )
        .unwrap();
        let cfg = SshServerConfig::load(&main).unwrap();
        // First match wins, in glob order: 50-cloud-init.conf.
        assert_eq!(cfg.global.password_authentication, Some(true));
        assert_eq!(cfg.global.subsystem_sftp, Some(true));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Every keyword the stock file lists commented out, uncommented with a
    /// typical value, parses.
    #[test]
    fn commonly_uncommented_keywords_parse() {
        let src = "\
Port 22
AddressFamily any
ListenAddress 0.0.0.0
ListenAddress ::
HostKey /etc/ssh/ssh_host_rsa_key
HostKey /etc/ssh/ssh_host_ecdsa_key
HostKey /etc/ssh/ssh_host_ed25519_key
RekeyLimit default none
SyslogFacility AUTH
LogLevel INFO
LoginGraceTime 2m
PermitRootLogin prohibit-password
StrictModes yes
MaxAuthTries 6
MaxSessions 10
PubkeyAuthentication yes
AuthorizedKeysFile .ssh/authorized_keys .ssh/authorized_keys2
AuthorizedPrincipalsFile none
AuthorizedKeysCommand none
AuthorizedKeysCommandUser nobody
HostbasedAuthentication no
IgnoreUserKnownHosts no
IgnoreRhosts yes
PasswordAuthentication yes
PermitEmptyPasswords no
KerberosAuthentication no
KerberosOrLocalPasswd yes
KerberosTicketCleanup yes
KerberosGetAFSToken no
GSSAPIAuthentication no
GSSAPICleanupCredentials yes
GSSAPIStrictAcceptorCheck yes
GSSAPIKeyExchange no
AllowAgentForwarding yes
AllowTcpForwarding yes
GatewayPorts no
X11DisplayOffset 10
X11UseLocalhost yes
PermitTTY yes
PrintLastLog yes
TCPKeepAlive yes
PermitUserEnvironment no
Compression delayed
ClientAliveInterval 0
ClientAliveCountMax 3
UseDNS no
PidFile /run/sshd.pid
MaxStartups 10:30:100
PermitTunnel no
ChrootDirectory none
VersionAddendum none
Banner none
ChallengeResponseAuthentication no
UsePrivilegeSeparation sandbox
";
        let cfg = SshServerConfig::parse(src).unwrap();
        assert_eq!(cfg.global.permit_tty, Some(true));
        assert_eq!(
            cfg.warnings().count(),
            0,
            "{:?}",
            cfg.warnings().collect::<Vec<_>>()
        );
    }

    #[test]
    fn unimplemented_keywords_warn_only_when_it_matters() {
        let cfg = SshServerConfig::parse(
            "GSSAPIAuthentication yes\nKerberosAuthentication yes\n\
             SetEnv FOO=bar\nUseDNS yes\nPermitUserEnvironment yes\n",
        )
        .unwrap();
        let w: Vec<_> = cfg.warnings().collect();
        assert_eq!(w.len(), 2, "{w:?}");
        assert!(w[0].contains("GSSAPIAuthentication") && w[0].contains("line 1"));
        assert!(w[1].contains("KerberosAuthentication"));
        assert!(w.iter().all(|x| !x.contains("UseDNS")));
        // Implemented now: no warning.
        assert!(
            w.iter()
                .all(|x| !x.contains("SetEnv") && !x.contains("PermitUserEnv"))
        );
    }

    #[test]
    fn subsystem_sftp_server_mapping() {
        let cfg =
            SshServerConfig::parse("Subsystem sftp /usr/lib/sftp-server -f AUTHPRIV -l INFO\n")
                .unwrap();
        assert_eq!(cfg.global.subsystem_sftp, Some(true));
        assert_eq!(cfg.global.sftp_read_only, None);
        let cfg = SshServerConfig::parse("Subsystem sftp internal-sftp -R\n").unwrap();
        assert_eq!(cfg.global.sftp_read_only, Some(true));
        // Restrictions we cannot honour are fatal, never silently dropped.
        assert!(SshServerConfig::parse("Subsystem sftp internal-sftp -P write\n").is_err());
        let cfg = SshServerConfig::parse("Subsystem sftp internal-sftp -u 077 -d %d/up\n").unwrap();
        assert_eq!(
            cfg.global.subsystem_sftp_args.as_deref(),
            Some(&["-u".to_string(), "077".into(), "-d".into(), "%d/up".into()][..])
        );
        // Other subsystems run their command, written as it was; the first
        // definition of a name wins.
        let cfg = SshServerConfig::parse(
            "Subsystem netconf /usr/bin/netconf --opt 'a b'\nSubsystem NetConf2 x\n\
             Subsystem netconf other\n",
        )
        .unwrap();
        assert_eq!(cfg.global.subsystem_sftp, None);
        assert_eq!(
            cfg.global.subsystems.as_deref(),
            Some(
                &[
                    (
                        "netconf".to_string(),
                        "/usr/bin/netconf --opt 'a b'".to_string()
                    ),
                    ("NetConf2".into(), "x".into())
                ][..]
            )
        );
        assert_eq!(cfg.warnings().count(), 0);
        // A Match block's definition wins over the global one.
        let cfg = SshServerConfig::parse("Subsystem x a\nMatch all\n  Subsystem x b\n").unwrap();
        let opts = cfg.resolve(
            &crate::config::MatchContext::default(),
            crate::config::ExecPolicy::Deny,
        );
        assert_eq!(opts.subsystems.unwrap()[0], ("x".into(), "b".into()));
    }

    #[test]
    fn restrictive_keywords_parse_and_match_override() {
        let cfg = SshServerConfig::parse(
            "PermitTTY yes\nDisableForwarding no\nAllowStreamLocalForwarding local\n\
             PubkeyAcceptedAlgorithms ssh-ed25519,rsa-sha2-512\nRequiredRSASize 3072\n\
             PerSourceMaxStartups none\n\
             Match User guest\n  PermitTTY no\n  DisableForwarding yes\n",
        )
        .unwrap();
        let g = &cfg.global;
        assert_eq!(g.allow_stream_local_forwarding, Some(TcpForwarding::Local));
        assert_eq!(
            g.pubkey_accepted_algorithms.as_deref(),
            Some(&["ssh-ed25519".to_string(), "rsa-sha2-512".to_string()][..])
        );
        assert_eq!(g.required_rsa_size, Some(3072));
        assert_eq!(g.per_source_max_startups, Some(0));
        let ctx = crate::config::MatchContext {
            user: Some("guest"),
            ..Default::default()
        };
        let r = cfg.resolve(&ctx, crate::config::match_block::ExecPolicy::Deny);
        assert_eq!(r.permit_tty, Some(false));
        assert_eq!(r.disable_forwarding, Some(true));
        // Keywords OpenSSH rejects unless they are no-ops stay strict.
        assert!(SshServerConfig::parse("PermitTunnel yes\n").is_err());
        assert!(SshServerConfig::parse("PermitTunnel no\n").is_ok());
        // DSA keys are an OpenSSH algorithm this server lacks: the line loads
        // (OpenSSH's own configs carry it) and enables nothing.
        let cfg = SshServerConfig::parse("PubkeyAcceptedKeyTypes +ssh-dss\n").unwrap();
        let r = cfg.resolve(&MatchContext::default(), ExecPolicy::Deny);
        assert!(
            !r.pubkey_accepted_algorithms
                .unwrap()
                .iter()
                .any(|a| a == "ssh-dss")
        );
        assert!(SshServerConfig::parse("PubkeyAcceptedKeyTypes +ssh-dsx\n").is_err());
    }

    #[test]
    fn startup_keywords_rejected_in_match() {
        for kw in [
            "AddressFamily inet",
            "PidFile /x",
            "Compression no",
            "RekeyLimit 1G",
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
        // A matching Match block overrides the global scalar (sshd_config(5)).
        assert_eq!(eff.max_sessions, Some(1));
        assert_eq!(eff.allow_tcp_forwarding, Some(TcpForwarding::No));
        assert_eq!(eff.force_command.as_deref(), Some("internal-sftp"));
    }

    #[cfg(feature = "std")]
    #[test]
    fn include_unsupported_in_string_parse() {
        // parse(&str) has no filesystem context, so Include must surface a
        // friendly diagnostic rather than UnknownKeyword.
        let err = SshServerConfig::parse("Include /etc/ssh/sshd_config.d/*.conf\n").unwrap_err();
        match err {
            ConfigError::Unsupported { line, msg } => {
                assert_eq!(line, 1);
                assert!(msg.contains("Include"), "msg = {msg}");
            }
            _ => panic!("wrong err: {err:?}"),
        }
    }

    #[cfg(feature = "std")]
    #[test]
    fn match_in_included_file_ends_with_it() {
        // A drop-in ending in a Match block (an SFTP jail): the main file's
        // lines after the Include are global again, as with OpenSSH.
        let dir = std::env::temp_dir().join(format!("puressh_incmatch_{}", std::process::id()));
        let d = dir.join("sshd_config.d");
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(
            d.join("50-jail.conf"),
            "Match User jailed\n\tChrootDirectory /srv/jail/%u\n\tForceCommand internal-sftp\n",
        )
        .unwrap();
        let main = dir.join("sshd_config");
        std::fs::write(
            &main,
            format!(
                "Include {}/*.conf\nAcceptEnv LANG\nX11Forwarding yes\n\
                 Match User x\n\tPermitTTY no\n\tInclude {}/*.conf\n\tX11Forwarding no\n",
                d.display(),
                d.display()
            ),
        )
        .unwrap();
        let cfg = SshServerConfig::load(&main).expect("AcceptEnv after the drop-in is global");
        let _ = std::fs::remove_dir_all(&dir);
        let user = |u| {
            cfg.resolve(
                &MatchContext {
                    user: Some(u),
                    ..MatchContext::default()
                },
                ExecPolicy::Deny,
            )
        };
        assert_eq!(cfg.global.accept_env, vec!["LANG".to_string()]);
        assert_eq!(cfg.global.x11_forwarding, Some(true));
        // Inside a Match block, the lines after the Include are that
        // block's again.
        assert_eq!(user("x").x11_forwarding, Some(false));
        assert_eq!(user("x").permit_tty, Some(false));
        assert_eq!(
            user("jailed").force_command.as_deref(),
            Some("internal-sftp")
        );
        assert_eq!(user("other").force_command, None);
    }

    #[cfg(feature = "std")]
    #[test]
    fn load_resolves_include() {
        use std::io::Write;
        use std::path::PathBuf;
        use std::time::{SystemTime, UNIX_EPOCH};

        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let dir =
            std::env::temp_dir().join(format!("puressh-sshd-inc-{}-{nanos}", std::process::id()));
        std::fs::create_dir_all(dir.join("sshd_config.d")).expect("mkdir");
        let write = |rel: &str, body: &str| {
            let p: PathBuf = dir.join(rel);
            let mut f = std::fs::File::create(&p).expect("create");
            f.write_all(body.as_bytes()).expect("write");
            p
        };
        // A bare relative Include resolves against the root file's directory.
        write("sshd_config.d/10-port.conf", "Port 2022\n");
        let root = write(
            "sshd_config",
            "Include sshd_config.d/*.conf\nMaxAuthTries 3\n",
        );

        let cfg = SshServerConfig::load(&root).expect("load resolves Include");
        let base = cfg.resolve(&MatchContext::default(), ExecPolicy::Deny);
        assert_eq!(base.port, Some(2022));
        assert_eq!(base.max_auth_tries, Some(3));

        // Warnings and errors name the included file, as OpenSSH does.
        // (Matched on the file name: Windows paths come back with `\`.)
        write(
            "sshd_config.d/20-krb.conf",
            "\nKerberosAuthentication yes\n",
        );
        let cfg = SshServerConfig::load(&root).expect("load");
        let w: Vec<_> = cfg.warnings().collect();
        assert!(
            w.iter().any(|w| w.contains("sshd_config.d")
                && w.contains("20-krb.conf line 2: KerberosAuthentication")),
            "{w:?}"
        );
        write("sshd_config.d/30-bad.conf", "Port nope\n");
        let err = SshServerConfig::load(&root).unwrap_err().to_string();
        assert!(
            err.starts_with("config: ")
                && err.contains("sshd_config.d")
                && err.contains("30-bad.conf line 1: bad value for port"),
            "{err}"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }
}
