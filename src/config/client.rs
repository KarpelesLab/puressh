//! `ssh_config(5)` parsing — see [`SshClientConfig`].
//!
//! Only the keywords the puressh client binaries actually consume today are
//! recognised; any other keyword is rejected as
//! [`ConfigError::UnknownKeyword`]. This is deliberate: the scope is "config
//! values that change observable behaviour", and silently dropping an
//! unrecognised knob is worse than failing loudly.
//!
//! The file is a sequence of blocks. `Host <pattern>` opens a host-pattern
//! block, `Match <criteria>` opens a Match block, and everything before the
//! first block belongs to an implicit "global" Host * block. Settings inside a
//! block apply when the block's selector matches the lookup target;
//! [`SshClientConfig::lookup`] walks the blocks in order with OpenSSH's
//! first-match-wins precedence (scalars) and cumulative-concatenation
//! semantics (`IdentityFile`, `LocalForward`, `RemoteForward`).

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;

use super::ConfigError;
use super::algos::{AlgoCategory, resolve_algo_list};
use super::glob::{HostPattern, host_matches};
use super::match_block::{
    ExecPolicy, MatchCondition, MatchContext, all_match, evaluate, parse_match_line,
};
use super::parser::{ParsedLine, tokenize};

/// `StrictHostKeyChecking` value — maps OpenSSH's keyword set to puressh's
/// TOFU policy. Re-exported as `puressh::config::StrictMode` and re-exported
/// once more from `src/bin/common.rs` so existing binaries keep compiling.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum StrictMode {
    /// `yes`: refuse Unknown; reject Mismatch.
    Yes,
    /// `no`: accept Unknown silently AND tolerate Mismatch (insecure).
    No,
    /// `accept-new`: silently accept Unknown; still reject Mismatch.
    AcceptNew,
    /// `ask` (OpenSSH default): prompt on Unknown; reject Mismatch.
    Ask,
}

/// `RequestTTY` value. Distinct from a CLI bool: `Auto` means "PTY if local
/// stdin is a tty" — the binary needs the original token so it can decide
/// late.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum RequestTty {
    /// `no`: never allocate.
    No,
    /// `yes`: allocate when there's an interactive session (default for
    /// interactive shells).
    Yes,
    /// `force`: always allocate.
    Force,
    /// `auto`: allocate iff local stdin is a tty.
    Auto,
}

/// `CanonicalizeHostname` value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum CanonicalizeHostname {
    /// `no` (the default): names are used as given.
    No,
    /// `yes`: canonicalise direct connections (not through a proxy).
    Yes,
    /// `always`: canonicalise proxied connections too.
    Always,
}

/// `SessionType` value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum SessionType {
    /// `none`: no session at all (like `-N`).
    None,
    /// `subsystem`: the command names a subsystem (like `-s`).
    Subsystem,
    /// `default`: a shell or command.
    Default,
}

/// `AddressFamily` value — filters the addresses a hostname resolves to
/// before we attempt a connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum AddressFamily {
    /// `any`: no filtering (default).
    Any,
    /// `inet`: IPv4 only.
    Inet,
    /// `inet6`: IPv6 only.
    Inet6,
}

/// `KnockMode` value — when the client falls back to the puressh UDP knock
/// (`docs/knock.md`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum KnockSetting {
    /// `no`: plain TCP only.
    No,
    /// `auto` (default): knock when the TCP connect is refused or slow.
    Auto,
    /// `always`: knock straight away, no plain TCP attempt.
    Always,
}

/// `GatewayPorts` value — controls the bind address of client-side
/// `-L` / `-D` listeners.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum GatewayPorts {
    /// `no`: bind loopback (`127.0.0.1`) only (default).
    No,
    /// `yes`: bind all interfaces (`0.0.0.0`).
    Yes,
    /// `clientspecified`: honour the bind address spelled out in the
    /// forward spec; fall back to loopback when none was given.
    ClientSpecified,
}

/// `IdentityAgent` value — overrides which ssh-agent socket the client
/// talks to.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum IdentityAgent {
    /// `none`: never consult an agent.
    None,
    /// A filesystem path to the agent socket. The literal token
    /// `SSH_AUTH_SOCK` (and `$SSH_AUTH_SOCK`) is preserved verbatim here
    /// and expanded against the environment at the honoring site.
    Path(String),
}

/// `ControlMaster` value — controls connection-multiplexing role.
///
/// `ask` / `autoask` would prompt the user for permission before
/// reusing/establishing a master. puressh has no interactive confirmation
/// path for this decision, so both are rejected at parse time as
/// [`ConfigError::Unsupported`] rather than silently downgraded to `yes`
/// (which would defeat the user's explicit request to be asked).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ControlMaster {
    /// `no` (default): never multiplex. Open a fresh connection.
    No,
    /// `yes`: become the master. Fails if the `ControlPath` socket already
    /// has a live master answering.
    Yes,
    /// `auto`: reuse an existing master if the socket answers; otherwise
    /// connect normally and become the master.
    Auto,
}

/// `ControlPersist` value — how long a master lingers after its foreground
/// session ends.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ControlPersist {
    /// `no`: the master exits as soon as its own foreground session ends
    /// (still serving any clients that attached, but tearing down once the
    /// initiating session finishes — matches OpenSSH `no`).
    No,
    /// `yes`: the master persists indefinitely after the foreground session
    /// ends, until explicitly stopped (or the process exits).
    Yes,
    /// `<N>` (or `<N>[smh]`): linger N seconds after the last client
    /// detaches, then unlink the socket and exit.
    Seconds(u64),
}

/// `ObscureKeystrokeTiming` value (OpenSSH 9.5+). Controls keystroke-timing
/// obfuscation on interactive (pty) sessions: when on, the client releases
/// keystrokes on a fixed cadence and pads idle gaps with `ping@openssh.com`
/// chaff so the on-wire packet rate is constant while typing.
///
/// OpenSSH syntax: `yes` (on, default interval 20 ms), `no`, or
/// `interval:<spec>` where `<spec>` is a millisecond count (`interval:80`) or
/// an OpenSSH time value with unit suffixes (`interval:1s`). The OpenSSH
/// default when the option is unset is `yes` at 20 ms.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ObscureKeystrokeTiming {
    /// `no`: disabled — keystrokes are sent immediately as today.
    Off,
    /// `yes` / `interval:<spec>`: enabled with the given cadence in
    /// milliseconds. `yes` ⇒ `On { interval_ms: 20 }`.
    On {
        /// Cadence between cadence ticks, in milliseconds.
        interval_ms: u32,
    },
}

impl ObscureKeystrokeTiming {
    /// OpenSSH's default cadence interval (20 ms) used by bare `yes`.
    pub const DEFAULT_INTERVAL_MS: u32 = 20;

    /// The effective default when the option is unset: on at 20 ms, matching
    /// OpenSSH's compiled-in default.
    pub fn default_on() -> Self {
        ObscureKeystrokeTiming::On {
            interval_ms: Self::DEFAULT_INTERVAL_MS,
        }
    }

    /// `true` if obfuscation is enabled.
    pub fn is_on(&self) -> bool {
        matches!(self, ObscureKeystrokeTiming::On { .. })
    }

    /// The cadence interval in milliseconds when on; `None` when off.
    pub fn interval_ms(&self) -> Option<u32> {
        match self {
            ObscureKeystrokeTiming::On { interval_ms } => Some(*interval_ms),
            ObscureKeystrokeTiming::Off => None,
        }
    }
}

/// One `DynamicForward` entry — a local SOCKS proxy listener. Wire form
/// `[bind:]port`, e.g. `1080` or `127.0.0.1:1080`.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct DynamicForwardSpec {
    /// Local bind address; `None` ⇒ loopback (subject to `GatewayPorts`).
    pub bind_addr: Option<String>,
    /// Local port the SOCKS listener binds.
    pub listen_port: u16,
}

impl DynamicForwardSpec {
    /// Build a spec; `bind_addr = None` binds loopback.
    pub fn new(bind_addr: Option<String>, listen_port: u16) -> Self {
        Self {
            bind_addr,
            listen_port,
        }
    }
}

/// One `LocalForward` entry. Wire form `[bind:]port host:hostport`, e.g.
/// `8080 example.com:80` or `127.0.0.1:8080 example.com:80`.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct LocalForwardSpec {
    /// Local bind address; `None` ⇒ loopback (`127.0.0.1`).
    pub bind_addr: Option<String>,
    /// Local port to listen on.
    pub listen_port: u16,
    /// Remote destination host (resolved server-side).
    pub remote_host: String,
    /// Remote destination port.
    pub remote_port: u16,
    /// A Unix socket to listen on instead of `[bind:]port`.
    pub listen_path: Option<String>,
    /// A Unix socket on the server to connect to instead of `host:port`.
    pub connect_path: Option<String>,
}

impl LocalForwardSpec {
    /// Build a spec; `bind_addr = None` binds loopback.
    pub fn new(
        bind_addr: Option<String>,
        listen_port: u16,
        remote_host: impl Into<String>,
        remote_port: u16,
    ) -> Self {
        Self {
            bind_addr,
            listen_port,
            remote_host: remote_host.into(),
            remote_port,
            listen_path: None,
            connect_path: None,
        }
    }
}

/// One `RemoteForward` entry. Wire form `[bind:]port host:hostport`, e.g.
/// `8080 127.0.0.1:8080`, or `[bind:]port` alone for a SOCKS proxy on the
/// server whose connections the client dials (see
/// [`RemoteForwardSpec::dynamic`]).
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct RemoteForwardSpec {
    /// Remote bind address; `None` ⇒ loopback on the server side.
    pub bind_addr: Option<String>,
    /// Remote port the server should bind.
    pub remote_port: u16,
    /// Local destination host (resolved client-side).
    pub local_host: String,
    /// Local destination port.
    pub local_port: u16,
    /// `RemoteForward [bind:]port` with no destination: each forwarded
    /// connection is a SOCKS request (`local_host` / `local_port` unused).
    pub dynamic: bool,
    /// A Unix socket for the server to listen on instead of `[bind:]port`.
    pub listen_path: Option<String>,
    /// A local Unix socket to connect to instead of `host:port`.
    pub connect_path: Option<String>,
}

impl RemoteForwardSpec {
    /// Build a spec; `bind_addr = None` binds loopback on the server side.
    pub fn new(
        bind_addr: Option<String>,
        remote_port: u16,
        local_host: impl Into<String>,
        local_port: u16,
    ) -> Self {
        Self {
            bind_addr,
            remote_port,
            local_host: local_host.into(),
            local_port,
            dynamic: false,
            listen_path: None,
            connect_path: None,
        }
    }

    /// A SOCKS forward: the server listens on `[bind:]remote_port` and the
    /// client dials whatever each connection asks for.
    pub fn dynamic(bind_addr: Option<String>, remote_port: u16) -> Self {
        Self {
            bind_addr,
            remote_port,
            local_host: String::new(),
            local_port: 0,
            dynamic: true,
            listen_path: None,
            connect_path: None,
        }
    }
}

/// Per-host options. Every field is `Option`-typed so callers can distinguish
/// "not set" from "set to default" and apply OpenSSH precedence (CLI > file >
/// built-in default) via a `pick(cli, cfg, default)` helper.
#[derive(Default, Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct ClientOptions {
    /// `HostName`: real hostname to connect to (the `Host` block name is just a label).
    pub host_name: Option<String>,
    /// `Port`: TCP port for the SSH session.
    pub port: Option<u16>,
    /// `User`: remote username.
    pub user: Option<String>,
    /// `IdentityFile` (cumulative across matching blocks).
    pub identity_files: Vec<String>,
    /// `CertificateFile` (cumulative across matching blocks) — paths to user
    /// certificates (`*-cert.pub`) to offer, each paired at load time with the
    /// `IdentityFile` private key whose embedded key it certifies.
    pub certificate_files: Vec<String>,
    /// `IdentitiesOnly` (yes/no).
    pub identities_only: Option<bool>,
    /// `PKCS11Provider` (`ssh -I`): the PKCS#11 module whose tokens'
    /// keys are offered; `Some("none")` turns it off.
    pub pkcs11_provider: Option<String>,
    /// `SecurityKeyProvider`: `internal` or a FIDO middleware library, for
    /// security-key identities (`$SSH_SK_PROVIDER` when unset).
    pub security_key_provider: Option<String>,
    /// `StrictHostKeyChecking`.
    pub strict_host_key: Option<StrictMode>,
    /// `UserKnownHostsFile`.
    pub user_known_hosts: Option<String>,
    /// `HashKnownHosts` (yes/no).
    pub hash_known_hosts: Option<bool>,
    /// `LocalForward` entries (cumulative).
    pub local_forwards: Vec<LocalForwardSpec>,
    /// `RemoteForward` entries (cumulative).
    pub remote_forwards: Vec<RemoteForwardSpec>,
    /// `ForwardAgent` (yes/no, or a socket: see
    /// [`Self::forward_agent_socket`]).
    pub forward_agent: Option<bool>,
    /// Keywords this build accepts but does not act on (`IPQoS`,
    /// `TunnelDevice`, …), lowercased, with the value as written: the first
    /// per keyword, for `ssh -G`.
    pub unimplemented: Vec<(String, String)>,
    /// `ForwardAgent <path>` / `ForwardAgent $VAR`: the agent socket to
    /// forward instead of `$SSH_AUTH_SOCK` (`forward_agent` is then on).
    pub forward_agent_socket: Option<String>,
    /// `ForwardX11` (yes/no).
    pub forward_x11: Option<bool>,
    /// `ForwardX11Trusted` (yes/no).
    pub forward_x11_trusted: Option<bool>,
    /// `RequestTTY` (yes/no/force/auto).
    pub request_tty: Option<RequestTty>,
    /// `CanonicalizeHostname`.
    pub canonicalize_hostname: Option<CanonicalizeHostname>,
    /// `RekeyLimit`: re-key after this much data / time.
    pub rekey_limit: Option<crate::config::RekeyLimit>,
    /// `PermitRemoteOpen`: the destinations a SOCKS `RemoteForward` may
    /// reach, as written (`any`, `none`, or `host:port` entries where either
    /// part may be `*`).
    pub permit_remote_open: Option<Vec<String>>,
    /// `CanonicalDomains`: the suffixes tried, in order.
    pub canonical_domains: Option<Vec<String>>,
    /// `CanonicalizeMaxDots` (default 1): names with more dots are taken as
    /// already qualified.
    pub canonicalize_max_dots: Option<u32>,
    /// `CanonicalizeFallbackLocal` (default yes): use the name as given when
    /// no domain qualifies it (else fail).
    pub canonicalize_fallback_local: Option<bool>,
    /// `LogLevel`, numbered as OpenSSH's (0 QUIET, 1 FATAL, 2 ERROR, 3
    /// INFO, 4 VERBOSE, 5 DEBUG1, 6 DEBUG2, 7 DEBUG3; see
    /// [`crate::config::server::LOG_LEVELS`]).
    pub log_level: Option<u8>,
    /// `Ciphers` — resolved cipher preference list (strict-validated, with
    /// list modifiers already applied). `None` ⇒ built-in default.
    pub ciphers: Option<Vec<String>>,
    /// `MACs` — resolved MAC preference list.
    pub macs: Option<Vec<String>>,
    /// `KexAlgorithms` — resolved key-exchange preference list (no markers).
    pub kex_algorithms: Option<Vec<String>>,
    /// `HostKeyAlgorithms` — resolved server host-key preference list.
    pub host_key_algorithms: Option<Vec<String>>,
    /// `PubkeyAcceptedAlgorithms` — resolved publickey-auth signature list.
    pub pubkey_accepted_algorithms: Option<Vec<String>>,
    /// `CASignatureAlgorithms` — resolved set of signature algorithms accepted
    /// from a CA when verifying a host certificate. `None` ⇒ built-in default
    /// (`algos::CA_SIGNATURE_DEFAULTS`).
    pub ca_signature_algorithms: Option<Vec<String>>,
    /// `ProxyCommand` — shell command (with `%h`/`%p`/`%r`/`%%` tokens
    /// un-expanded) to spawn and use as the connection transport. The
    /// literal `none` (kept, so it wins over later settings as in OpenSSH)
    /// means no command. Whichever of `ProxyCommand` and `ProxyJump` is
    /// obtained first is the one set.
    pub proxy_command: Option<String>,
    /// `ProxyJump` — comma-separated `[user@]host[:port]` jump-host chain
    /// to tunnel the connection through. The literal `none` (kept, like
    /// [`Self::proxy_command`]'s) means no jump host.
    pub proxy_jump: Option<String>,
    /// `Compression` (yes/no). `Some(true)` advertises
    /// `zlib@openssh.com` ahead of `none`. Requires the `compress`
    /// feature at honoring time.
    pub compression: Option<bool>,
    /// `SetEnv` — literal `NAME=VALUE` pairs to send via `env` requests
    /// (cumulative across matching blocks; later duplicates of a name are
    /// dropped at honoring time per first-wins).
    pub set_env: Vec<(String, String)>,
    /// `SendEnv` — environment-variable name patterns; matching local env
    /// vars are forwarded via `env` requests (cumulative).
    pub send_env: Vec<String>,
    /// `ConnectTimeout` — TCP connect timeout in seconds. `0` is rejected.
    pub connect_timeout: Option<u32>,
    /// `ServerAliveInterval` — seconds between keepalive probes when the
    /// connection is otherwise idle. `0` (or unset) ⇒ disabled.
    pub server_alive_interval: Option<u32>,
    /// `ServerAliveCountMax` — number of unanswered keepalives tolerated
    /// before the connection is torn down (default 3 at honoring time).
    pub server_alive_count_max: Option<u32>,
    /// `TCPKeepAlive` (yes/no) — toggles SO_KEEPALIVE on the socket.
    pub tcp_keep_alive: Option<bool>,
    /// `AddKeysToAgent` — `Some(true)`/`Some(false)`. `confirm`/`ask` are
    /// rejected at parse time (Unsupported).
    pub add_keys_to_agent: Option<bool>,
    /// `PreferredAuthentications` — ordered, comma-separated auth-method
    /// list. Only `publickey`/`password`/`keyboard-interactive`/`none`
    /// are accepted; a list naming none of the implementable methods is
    /// rejected at parse time.
    pub preferred_authentications: Option<Vec<String>>,
    /// `PubkeyAuthentication` (yes/no) — gates publickey credentials.
    pub pubkey_authentication: Option<bool>,
    /// `NumberOfPasswordPrompts` — cap on interactive password attempts
    /// (default 3). `0` disables password auth.
    pub number_of_password_prompts: Option<u32>,
    /// `BatchMode` (yes/no) — never prompt; treat `ask` strict policy as
    /// `yes` and disable password auth.
    pub batch_mode: Option<bool>,
    /// `ExitOnForwardFailure` (yes/no) — abort the connection if any
    /// requested forward fails to bind / be granted.
    pub exit_on_forward_failure: Option<bool>,
    /// `ClearAllForwardings` (yes/no) — discard all local/remote/dynamic
    /// forwards collected so far before connecting.
    pub clear_all_forwardings: Option<bool>,
    /// `DynamicForward` entries — SOCKS proxy listeners (cumulative).
    pub dynamic_forwards: Vec<DynamicForwardSpec>,
    /// `GatewayPorts` — bind-address policy for `-L`/`-D` listeners.
    pub gateway_ports: Option<GatewayPorts>,
    /// `AddressFamily` — restrict resolved addresses to a family.
    pub address_family: Option<AddressFamily>,
    /// `BindAddress` — local source address to bind before connecting.
    pub bind_address: Option<String>,
    /// `IdentityAgent` — agent-socket override (or `none`).
    pub identity_agent: Option<IdentityAgent>,
    /// `ControlMaster` — connection-multiplexing role (no/yes/auto).
    pub control_master: Option<ControlMaster>,
    /// `ControlPath` — Unix-domain control-socket path with `%`-token and
    /// `~` expansion deferred to the honoring site. The literal `none`
    /// (case-insensitive) is stored as `None` to disable multiplexing.
    pub control_path: Option<String>,
    /// `ControlPersist` — how long the master lingers after its foreground
    /// session ends (no/yes/`<N>[smh]`).
    pub control_persist: Option<ControlPersist>,
    /// `ObscureKeystrokeTiming` — keystroke-timing obfuscation for
    /// interactive sessions (`yes`/`no`/`interval:<spec>`). Unset ⇒ honoring
    /// site applies the OpenSSH default (`yes` at 20 ms).
    pub obscure_keystroke_timing: Option<ObscureKeystrokeTiming>,
    /// `KnockMode` — puressh UDP knock fallback (no/auto/always).
    pub knock_mode: Option<KnockSetting>,
    /// `KnockFallbackDelay` — ms a TCP connect may stay pending before the
    /// knock starts alongside it.
    pub knock_fallback_delay: Option<u32>,
    /// `KnockPort` — UDP port to knock on (default: the SSH port).
    pub knock_port: Option<u16>,
    /// `EscapeChar`: `Some(None)` for `none`.
    pub escape_char: Option<Option<u8>>,
    /// `RemoteCommand` (raw; `none` means no command).
    pub remote_command: Option<String>,
    /// `KnownHostsCommand` (raw; `none` means none): prints known_hosts
    /// lines for the server's key.
    pub known_hosts_command: Option<String>,
    /// `UpdateHostKeys`: `yes`, `no` or `ask` (unset: OpenSSH's default,
    /// yes unless UserKnownHostsFile names other files).
    pub update_host_keys: Option<String>,
    /// `Tag`: the name `Match tagged` compares (`ssh -P` sets it too).
    pub tag: Option<String>,
    /// `LocalCommand`: run locally once connected, when
    /// [`Self::permit_local_command`] (raw; `none` means none).
    pub local_command: Option<String>,
    /// `PermitLocalCommand` (default no).
    pub permit_local_command: Option<bool>,
    /// `SessionType`.
    pub session_type: Option<SessionType>,
    /// `StdinNull` (like `-n`).
    pub stdin_null: Option<bool>,
    /// `ForkAfterAuthentication` (like `-f`).
    pub fork_after_authentication: Option<bool>,
    /// `PasswordAuthentication`.
    pub password_authentication: Option<bool>,
    /// `KbdInteractiveAuthentication` (alias `ChallengeResponseAuthentication`).
    pub kbd_interactive_authentication: Option<bool>,
    /// `HostKeyAlias`: name the host key is looked up and recorded under.
    pub host_key_alias: Option<String>,
    /// `RevokedHostKeys` (raw; `none` disables).
    pub revoked_host_keys: Option<String>,
    /// `GlobalKnownHostsFile` (raw list; `none` disables).
    pub global_known_hosts_files: Option<Vec<String>>,
    /// `ConnectionAttempts`.
    pub connection_attempts: Option<u32>,
    /// `CheckHostIP` (default no): also check (and record) the server's
    /// address in `known_hosts`.
    pub check_host_ip: Option<bool>,
    /// `VerifyHostKeyDNS` (default no): check the host key against the
    /// host's `SSHFP` records.
    pub verify_host_key_dns: Option<VerifyHostKeyDns>,
    /// `VisualHostKey` (default no): show the host key's randomart.
    pub visual_host_key: Option<bool>,
    /// `NoHostAuthenticationForLocalhost` (default no): accept any host key
    /// from a loopback address.
    pub no_host_authentication_for_localhost: Option<bool>,
    /// `FingerprintHash`: the hash fingerprints are shown with, as OpenSSH
    /// names it (`MD5`, `SHA1`, `SHA256`, `SHA384`, `SHA512`; default
    /// `SHA256`).
    pub fingerprint_hash: Option<String>,
    /// `BindInterface`: the interface the connection is made from.
    pub bind_interface: Option<String>,
    /// `IPQoS`: the TOS / DSCP values for interactive and non-interactive
    /// traffic, each [`IPQOS_NONE`] for the system default.
    pub ip_qos: Option<(u32, u32)>,
    /// `ForwardX11Timeout` in seconds (default 1200, `0`: no timeout).
    pub forward_x11_timeout: Option<u32>,
    /// `XAuthLocation` (default `/usr/bin/xauth`).
    pub xauth_location: Option<String>,
    /// `CanonicalizePermittedCNAMEs`: `(source domains, target domains)`
    /// pattern lists, empty for `none`.
    pub canonicalize_permitted_cnames: Option<Vec<(String, String)>>,
    /// `ChannelTimeout`: `type=interval` entries as written (`none` is
    /// empty); [`parse_channel_timeout`] reads one.
    pub channel_timeouts: Option<Vec<String>>,
    /// `LogVerbose`: `file:function:line` patterns (empty for `none`).
    pub log_verbose: Option<Vec<String>>,
    /// `SyslogFacility` (default `USER`), upper-cased.
    pub syslog_facility: Option<String>,
    /// `StreamLocalBindMask` (default `0177`).
    pub stream_local_bind_mask: Option<u32>,
    /// `StreamLocalBindUnlink` (default no).
    pub stream_local_bind_unlink: Option<bool>,
    /// `RequiredRSASize` (default 1024; this library never accepts RSA
    /// keys under 2048 bits whatever the value).
    pub required_rsa_size: Option<u32>,
    /// `ProxyUseFdpass` (default no): the `ProxyCommand` passes back a
    /// connected socket instead of carrying the connection.
    pub proxy_use_fdpass: Option<bool>,
    /// `KbdInteractiveDevices`: the comma-separated `submethods` sent with
    /// keyboard-interactive authentication.
    pub kbd_interactive_devices: Option<String>,
    /// `WarnWeakCrypto` (default yes): warn when the negotiated key
    /// exchange is not post-quantum.
    pub warn_weak_crypto: Option<bool>,
    /// `VersionAddendum`: appended to the client's identification string
    /// (`none` is kept as an empty string).
    pub version_addendum: Option<String>,
    /// `RefuseConnection`: a matching block refuses the connection; this
    /// is the message (`<location>: RefuseConnection: <reason>`).
    pub refuse_connection: Option<String>,
    /// `Tunnel`: `yes`, `point-to-point`, `ethernet` or `no`, as written.
    pub tunnel: Option<String>,
    /// `TunnelDevice`: `local[:remote]`, as written.
    pub tunnel_device: Option<String>,
    /// `EnableEscapeCommandline` (default no): the `~C` command line.
    pub enable_escape_commandline: Option<bool>,
}

/// [`ClientOptions::ip_qos`]'s value for `none`: the system default.
pub const IPQOS_NONE: u32 = u32::MAX;

/// `VerifyHostKeyDNS` value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum VerifyHostKeyDns {
    /// `no`: SSHFP records are not consulted.
    No,
    /// `yes`: a key matching a DNSSEC-validated SSHFP record is trusted.
    Yes,
    /// `ask`: matching records are reported, but known_hosts still decides.
    Ask,
}

/// One block in a parsed `ssh_config` — either a `Host` block or a `Match`
/// block. Pre-block lines go into an implicit `Host *` block at index 0.
#[derive(Clone, Debug)]
pub(crate) enum Block {
    Host {
        patterns: Vec<HostPattern>,
        opts: ClientOptions,
    },
    Match {
        conditions: Vec<MatchCondition>,
        opts: ClientOptions,
    },
}

impl Block {
    fn opts(&self) -> &ClientOptions {
        match self {
            Block::Host { opts, .. } | Block::Match { opts, .. } => opts,
        }
    }
    fn opts_mut(&mut self) -> &mut ClientOptions {
        match self {
            Block::Host { opts, .. } | Block::Match { opts, .. } => opts,
        }
    }
}

/// A parsed `ssh_config(5)` file.
///
/// Use [`SshClientConfig::parse`] to construct one from text, then
/// [`SshClientConfig::lookup`] (or [`SshClientConfig::lookup_with`] for full
/// `Match` evaluation) to flatten the matching blocks for a target host.
/// Pre-`Host` lines form an implicit "global" block applied to every host
/// (OpenSSH's documented behaviour).
#[derive(Clone, Debug, Default)]
pub struct SshClientConfig {
    pub(crate) blocks: Vec<Block>,
    /// Whether `Match exec` criteria are allowed to execute. Default `false`
    /// (deny). Toggle with [`Self::enable_match_exec`].
    enable_match_exec: bool,
}

impl SshClientConfig {
    /// Parse `src` (the contents of a `ssh_config` file) into an
    /// [`SshClientConfig`]. `Match exec` evaluation is **off** by default;
    /// see [`Self::enable_match_exec`].
    ///
    /// `Include` directives are not resolved by this entry point because
    /// inline parsing has no filesystem context to anchor relative paths to.
    /// Use [`Self::load`] (or [`Self::load_with_base`]) to parse a file with
    /// Include support.
    pub fn parse(src: &str) -> Result<Self, ConfigError> {
        let lines = tokenize(src)?;
        let blocks = parse_blocks(lines)?;
        Ok(SshClientConfig {
            blocks,
            enable_match_exec: false,
        })
    }

    /// Read `path` from disk and parse it, resolving `Include` directives
    /// recursively. Relative paths inside `Include` are anchored to the
    /// directory of the file containing the directive; `~` expands to
    /// `$HOME`; `*` / `?` globs are expanded against the filesystem.
    /// Recursion is capped at `include::MAX_INCLUDE_DEPTH` hops.
    #[cfg(feature = "std")]
    pub fn load<P: AsRef<std::path::Path>>(path: P) -> Result<Self, ConfigError> {
        let lines = super::include::tokenize_file_with_includes(path.as_ref(), 0)?;
        let mut blocks = parse_blocks(lines)?;
        name_source(&mut blocks, path.as_ref());
        Ok(SshClientConfig {
            blocks,
            enable_match_exec: false,
        })
    }

    /// [`Self::load`], with each `Include` path's `%` tokens expanded by
    /// `expand` (OpenSSH expands them for the connection being made: `%h`,
    /// `%u`, …).
    #[cfg(feature = "std")]
    pub fn load_expanding<P: AsRef<std::path::Path>>(
        path: P,
        expand: &dyn Fn(&str) -> String,
    ) -> Result<Self, ConfigError> {
        let lines =
            super::include::tokenize_file_with_includes_expanding(path.as_ref(), 0, expand)?;
        let mut blocks = parse_blocks(lines)?;
        name_source(&mut blocks, path.as_ref());
        Ok(SshClientConfig {
            blocks,
            enable_match_exec: false,
        })
    }

    /// Like [`Self::load`] but parses an in-memory `src` while still
    /// honouring `Include` directives relative to `base_dir`. Useful when
    /// the config has been pre-read (e.g. from a memfd) but you still want
    /// Include semantics anchored at a known directory.
    #[cfg(feature = "std")]
    pub fn load_with_base<P: AsRef<std::path::Path>>(
        src: &str,
        base_dir: P,
    ) -> Result<Self, ConfigError> {
        let lines = tokenize(src)?;
        let expanded = super::include::expand_includes(lines, base_dir.as_ref(), 0)?;
        let blocks = parse_blocks(expanded)?;
        Ok(SshClientConfig {
            blocks,
            enable_match_exec: false,
        })
    }

    /// Append every block of `other` after this config's own, preserving
    /// source order.
    ///
    /// Used to layer a lower-precedence config (e.g. the system-wide
    /// `/etc/ssh/ssh_config`) beneath a higher-precedence one (the user's
    /// `~/.ssh/config`). Because [`lookup`](Self::lookup) is first-match-wins
    /// for scalars, `self`'s blocks keep winning while `other` still
    /// contributes to the cumulative list fields — the same result as
    /// concatenating the two files' text, but with each file's `Include`
    /// directives already resolved relative to its own directory. Both
    /// implicit `Host *` globals survive; `self`'s comes first, so it wins
    /// scalar options.
    pub fn append(&mut self, other: SshClientConfig) {
        self.blocks.extend(other.blocks);
    }

    /// Permit `Match exec <cmd>` criteria to run `/bin/sh -c <cmd>` during
    /// lookup. Off by default because evaluating arbitrary shell commands
    /// during config resolution is a confused-deputy hazard: a config loaded
    /// from an untrusted location could trigger arbitrary commands at the
    /// privilege level of whoever called `lookup`. Callers that fully trust
    /// the config source (e.g. a CLI tool loading the local user's
    /// `~/.ssh/config`) can opt in.
    pub fn enable_match_exec(mut self, allow: bool) -> Self {
        self.enable_match_exec = allow;
        self
    }

    /// `true` iff `Match exec` is currently permitted on this config.
    pub fn is_match_exec_enabled(&self) -> bool {
        self.enable_match_exec
    }

    /// Resolve the effective options for `host`, walking every matching
    /// block in source order with OpenSSH **first-match-wins** semantics for
    /// scalars and **concatenation** for cumulative list fields
    /// (`IdentityFile`, `LocalForward`, `RemoteForward`).
    ///
    /// `Match` blocks that need a username (`Match user …` / `Match localuser
    /// …`) will not match through this entry point — they require fields the
    /// bare `host`-only API doesn't carry. Use [`Self::lookup_with`] when you
    /// have that context.
    pub fn lookup(&self, host: &str) -> ClientOptions {
        self.lookup_with(MatchContext {
            host,
            original_host: None,
            user: None,
            local_user: None,
            ..MatchContext::default()
        })
    }

    /// Whether the configuration asks for a final pass (`Match final`),
    /// which OpenSSH then runs even without canonicalisation. (`Match
    /// canonical` alone does not.)
    pub fn wants_final_pass(&self) -> bool {
        self.blocks.iter().any(|b| {
            matches!(b, Block::Match { conditions, .. }
                if conditions.iter().any(|c| matches!(c, MatchCondition::Final)))
        })
    }

    /// Like [`Self::lookup`] but supplies a full [`MatchContext`] so `Match`
    /// blocks with `user` / `localuser` / `originalhost` criteria can match.
    pub fn lookup_with(&self, ctx: MatchContext<'_>) -> ClientOptions {
        let policy = if self.enable_match_exec {
            ExecPolicy::Allow
        } else {
            ExecPolicy::Deny
        };
        let mut out = ClientOptions::default();
        for block in &self.blocks {
            let matches = match block {
                Block::Host { patterns, .. } => host_matches(patterns, ctx.host),
                Block::Match { conditions, .. } => all_match(conditions, &ctx, policy),
            };
            if matches {
                merge_into(&mut out, block.opts());
            }
        }
        out
    }

    /// Like [`Self::lookup_with`], with `Match exec` decided by `exec`: it is
    /// given the command as written and the options matched so far (for
    /// expanding `%h`, `%p`, `%r`, … as OpenSSH does), and says whether the
    /// criterion matched. It is only called when the criteria before it on
    /// the line matched.
    pub fn lookup_with_exec(
        &self,
        ctx: MatchContext<'_>,
        exec: &mut dyn FnMut(&str, &ClientOptions) -> bool,
    ) -> ClientOptions {
        let mut out = ClientOptions::default();
        for block in &self.blocks {
            let matches = match block {
                Block::Host { patterns, .. } => host_matches(patterns, ctx.host),
                Block::Match { conditions, .. } => {
                    !conditions.is_empty()
                        && conditions
                            .iter()
                            .all(|c| eval_with_options(c, &ctx, &out, exec))
                }
            };
            if matches {
                merge_into(&mut out, block.opts());
            }
        }
        out
    }
}

/// Name the file a configuration was read from in the messages that
/// quote its own lines (`RefuseConnection`), as OpenSSH words them
/// (`<file> line <n>: ...`); an included file's lines name theirs already.
#[cfg(feature = "std")]
fn name_source(blocks: &mut [Block], path: &std::path::Path) {
    for b in blocks {
        if let Some(msg) = &mut b.opts_mut().refuse_connection
            && msg.starts_with("line ")
        {
            *msg = format!("{} {msg}", path.display());
        }
    }
}

/// Evaluate one `Match` criterion with the options matched so far: `exec`
/// runs through the caller, `tagged` also sees a `Tag` set by an earlier
/// block.
fn eval_with_options(
    c: &MatchCondition,
    ctx: &MatchContext<'_>,
    so_far: &ClientOptions,
    exec: &mut dyn FnMut(&str, &ClientOptions) -> bool,
) -> bool {
    match c {
        MatchCondition::Exec(cmd) => exec(cmd, so_far),
        MatchCondition::Not(inner) => !eval_with_options(inner, ctx, so_far, exec),
        MatchCondition::Tagged(patterns) => {
            let tag = ctx.tag.or(so_far.tag.as_deref()).unwrap_or("");
            crate::config::host_matches(patterns, tag)
        }
        other => evaluate(other, ctx, ExecPolicy::Deny),
    }
}

/// Walk the tokenised stream and split it into [`Block`]s. Lines outside any
/// explicit `Host` / `Match` block accumulate into the implicit `Host *`
/// block at index 0.
pub(crate) fn parse_blocks(lines: Vec<ParsedLine>) -> Result<Vec<Block>, ConfigError> {
    let mut blocks: Vec<Block> = vec![Block::Host {
        patterns: vec![HostPattern::Any],
        opts: ClientOptions::default(),
    }];
    let mut ignore_unknown: Option<String> = None;
    // The block count at each enclosing `Include`: when its file ends, the
    // block open before it is open again (OpenSSH), as a fresh block after
    // the included ones.
    let mut at_include: Vec<usize> = Vec::new();
    // The conditions of the blocks enclosing each `Include`: as in OpenSSH,
    // an included file is only read where its `Include` applies, so each
    // block it opens carries them too (a `Host` block evaluates as `Match
    // host`).
    let mut guards: Vec<Vec<MatchCondition>> = Vec::new();
    for line in lines {
        let mut apply = || -> Result<(), ConfigError> {
            let guard: Vec<MatchCondition> = guards.iter().flatten().cloned().collect();
            match line.keyword.as_str() {
                super::parser::INCLUDE_BEGIN => {
                    at_include.push(blocks.len());
                    let enclosing = match blocks.last() {
                        Some(Block::Host { patterns, .. })
                            if !matches!(patterns.as_slice(), [HostPattern::Any]) =>
                        {
                            vec![MatchCondition::Host(patterns.clone())]
                        }
                        Some(Block::Match { conditions, .. }) => conditions.clone(),
                        _ => Vec::new(),
                    };
                    // A Match block's conditions already hold the outer guards.
                    let own: Vec<MatchCondition> = enclosing
                        .into_iter()
                        .skip(if matches!(blocks.last(), Some(Block::Match { .. })) {
                            guard.len()
                        } else {
                            0
                        })
                        .collect();
                    guards.push(own);
                }
                super::parser::INCLUDE_END => {
                    guards.pop();
                    let saved = at_include.pop().unwrap_or(blocks.len());
                    if saved != blocks.len() {
                        let reopened = match &blocks[saved - 1] {
                            Block::Host { patterns, .. } => Block::Host {
                                patterns: patterns.clone(),
                                opts: ClientOptions::default(),
                            },
                            Block::Match { conditions, .. } => Block::Match {
                                conditions: conditions.clone(),
                                opts: ClientOptions::default(),
                            },
                        };
                        blocks.push(reopened);
                    }
                }
                "host" => {
                    if line.args.is_empty() {
                        return Err(ConfigError::BadValue {
                            line: line.line_no,
                            keyword: "host".to_string(),
                            msg: "Host requires at least one pattern".into(),
                        });
                    }
                    let patterns = HostPattern::parse_all(&line.args);
                    if guard.is_empty() {
                        blocks.push(Block::Host {
                            patterns,
                            opts: ClientOptions::default(),
                        });
                    } else {
                        let mut conditions = guard;
                        conditions.push(MatchCondition::Host(patterns));
                        blocks.push(Block::Match {
                            conditions,
                            opts: ClientOptions::default(),
                        });
                    }
                }
                "match" => {
                    let mut conditions = guard;
                    conditions.extend(parse_match_line(&line.args, line.line_no)?);
                    blocks.push(Block::Match {
                        conditions,
                        opts: ClientOptions::default(),
                    });
                }
                "include" => {
                    // The Include-expansion pass runs before us when the caller
                    // uses SshClientConfig::load* (the std-only entry points). If
                    // we see an Include here, the user reached us via
                    // SshClientConfig::parse(&str), which has no filesystem
                    // context — refuse rather than silently drop.
                    return Err(ConfigError::Unsupported {
                        line: line.line_no,
                        msg: "Include requires file-based loading; use SshClientConfig::load() instead"
                            .into(),
                    });
                }
                "ignoreunknown" => {
                    if ignore_unknown.is_none() {
                        ignore_unknown = Some(line.args.join(","));
                    }
                }
                _ => {
                    let current = blocks.last_mut().expect("global block always present");
                    match apply_keyword(current.opts_mut(), &line) {
                        // `IgnoreUnknown`: unknown keywords matching its
                        // patterns (seen earlier in the file) are skipped.
                        Err(ConfigError::UnknownKeyword { .. })
                            if ignore_unknown.as_deref().is_some_and(|pats| {
                                let pats: Vec<HostPattern> = pats
                                    .split(',')
                                    .map(|p| HostPattern::parse(&p.to_ascii_lowercase()))
                                    .collect();
                                host_matches(&pats, &line.keyword)
                            }) => {}
                        r => r?,
                    }
                }
            }
            Ok(())
        };
        apply().map_err(|e| e.in_file(line.file.as_deref()))?;
    }
    Ok(blocks)
}

/// Apply one parsed line to the in-progress [`ClientOptions`] of the current
/// block.
fn apply_keyword(opts: &mut ClientOptions, line: &ParsedLine) -> Result<(), ConfigError> {
    // OpenSSH's older names for current keywords.
    let kw = match line.keyword.as_str() {
        "challengeresponseauthentication" | "skeyauthentication" | "tisauthentication" => {
            "kbdinteractiveauthentication"
        }
        "dsaauthentication" => "pubkeyauthentication",
        "keepalive" => "tcpkeepalive",
        "identityfile2" => "identityfile",
        kw => kw,
    };
    let args = &line.args;
    match kw {
        "hostname" => {
            opts.host_name = Some(one_arg(line)?);
        }
        "port" => {
            opts.port = Some(parse_u16(line)?);
        }
        "user" => {
            opts.user = Some(one_arg(line)?);
        }
        "identityfile" => {
            opts.identity_files.push(one_arg(line)?);
        }
        "certificatefile" => {
            opts.certificate_files.push(one_arg(line)?);
        }
        "identitiesonly" => {
            opts.identities_only = Some(parse_yes_no(line)?);
        }
        "pkcs11provider" | "smartcarddevice" => {
            opts.pkcs11_provider = Some(one_arg(line)?);
        }
        "securitykeyprovider" => {
            opts.security_key_provider = Some(one_arg(line)?.to_string());
        }
        "stricthostkeychecking" => {
            opts.strict_host_key = Some(parse_strict(line)?);
        }
        "userknownhostsfile" => {
            // A list of files, as OpenSSH's (kept space-separated).
            if args.is_empty() {
                return Err(ConfigError::BadValue {
                    line: line.line_no,
                    keyword: line.keyword.clone(),
                    msg: "expected one or more files".into(),
                });
            }
            opts.user_known_hosts = Some(args.join(" "));
        }
        "hashknownhosts" => {
            opts.hash_known_hosts = Some(parse_yes_no(line)?);
        }
        "localforward" => {
            opts.local_forwards.push(parse_local_forward(line)?);
        }
        "remoteforward" => {
            opts.remote_forwards.push(parse_remote_forward(line)?);
        }
        "forwardagent" => {
            // yes / no, or the socket to forward (a path or `$VARIABLE`).
            match parse_yes_no(line) {
                Ok(v) => opts.forward_agent = Some(v),
                Err(_) => {
                    opts.forward_agent = Some(true);
                    opts.forward_agent_socket = Some(one_arg(line)?);
                }
            }
        }
        "forwardx11" => {
            opts.forward_x11 = Some(parse_yes_no(line)?);
        }
        "forwardx11trusted" => {
            opts.forward_x11_trusted = Some(parse_yes_no(line)?);
        }
        "requesttty" => {
            opts.request_tty = Some(parse_request_tty(line)?);
        }
        "permitremoteopen" => {
            let alone = |v: &str| v.eq_ignore_ascii_case("any") || v.eq_ignore_ascii_case("none");
            for a in args.iter() {
                let ok = if alone(a) {
                    args.len() == 1
                } else {
                    match a.rsplit_once(':') {
                        Some((h, p)) => !h.is_empty() && (p == "*" || p.parse::<u16>().is_ok()),
                        None => false,
                    }
                };
                if !ok {
                    return Err(ConfigError::BadValue {
                        line: line.line_no,
                        keyword: line.keyword.clone(),
                        msg: format!("invalid permission {a:?}"),
                    });
                }
            }
            opts.permit_remote_open = Some(args.to_vec());
        }
        "rekeylimit" => {
            opts.rekey_limit = Some(super::server::parse_rekey_limit(line)?);
        }
        "canonicalizehostname" => {
            let v = one_arg(line)?.to_ascii_lowercase();
            opts.canonicalize_hostname = Some(match v.as_str() {
                "no" | "false" => CanonicalizeHostname::No,
                "yes" | "true" => CanonicalizeHostname::Yes,
                "always" => CanonicalizeHostname::Always,
                _ => {
                    return Err(ConfigError::BadValue {
                        line: line.line_no,
                        keyword: line.keyword.clone(),
                        msg: format!("expected no/yes/always, got {v:?}"),
                    });
                }
            });
        }
        "canonicaldomains" => {
            opts.canonical_domains = Some(
                args.iter()
                    .filter(|d| !d.eq_ignore_ascii_case("none"))
                    .map(|d| d.trim_end_matches('.').to_ascii_lowercase())
                    .collect(),
            );
        }
        "canonicalizemaxdots" => {
            opts.canonicalize_max_dots = Some(parse_u32(line)?);
        }
        "canonicalizefallbacklocal" => {
            opts.canonicalize_fallback_local = Some(parse_yes_no(line)?);
        }
        "loglevel" => {
            opts.log_level = Some(parse_log_level(line)?);
        }
        "ciphers" => {
            opts.ciphers = Some(resolve_algo_list(
                AlgoCategory::Cipher,
                args,
                line.line_no,
                "Ciphers",
            )?);
        }
        "macs" => {
            opts.macs = Some(resolve_algo_list(
                AlgoCategory::Mac,
                args,
                line.line_no,
                "MACs",
            )?);
        }
        "kexalgorithms" => {
            opts.kex_algorithms = Some(resolve_algo_list(
                AlgoCategory::Kex,
                args,
                line.line_no,
                "KexAlgorithms",
            )?);
        }
        "hostkeyalgorithms" => {
            opts.host_key_algorithms = Some(resolve_algo_list(
                AlgoCategory::HostKey,
                args,
                line.line_no,
                "HostKeyAlgorithms",
            )?);
        }
        "pubkeyacceptedalgorithms" | "pubkeyacceptedkeytypes" => {
            opts.pubkey_accepted_algorithms = Some(resolve_algo_list(
                AlgoCategory::PubkeyAccepted,
                args,
                line.line_no,
                "PubkeyAcceptedAlgorithms",
            )?);
        }
        "proxycommand" => {
            // The whole rest of the line is the command. The literal `none`
            // (case-insensitive) disables any inherited ProxyCommand.
            if args.is_empty() {
                return Err(ConfigError::BadValue {
                    line: line.line_no,
                    keyword: line.keyword.clone(),
                    msg: "ProxyCommand requires a command (or 'none')".into(),
                });
            }
            // First obtained wins, and a ProxyJump obtained first excludes
            // it (OpenSSH).
            if opts.proxy_command.is_none() && opts.proxy_jump.is_none() {
                opts.proxy_command =
                    Some(if args.len() == 1 && args[0].eq_ignore_ascii_case("none") {
                        "none".to_string()
                    } else {
                        line.rest.clone()
                    });
            }
        }
        "proxyjump" => {
            let v = one_arg(line)?;
            if opts.proxy_jump.is_none() && opts.proxy_command.is_none() {
                opts.proxy_jump = Some(if v.eq_ignore_ascii_case("none") {
                    "none".to_string()
                } else {
                    v
                });
            }
        }
        "compression" => {
            let on = parse_yes_no(line)?;
            // `Compression yes` requires the `compress` feature: without it
            // the codec has no zlib implementation, so honouring the keyword
            // is impossible. Reject at parse time rather than silently
            // advertising `none` (strict mode — no parse-and-ignore).
            if on && !cfg!(feature = "compress") {
                return Err(ConfigError::Unsupported {
                    line: line.line_no,
                    msg: "Compression yes requires the `compress` feature, which is not \
                          compiled in"
                        .into(),
                });
            }
            opts.compression = Some(on);
        }
        "setenv" => {
            // OpenSSH accepts one or more NAME=VALUE tokens on a SetEnv line.
            if args.is_empty() {
                return Err(ConfigError::BadValue {
                    line: line.line_no,
                    keyword: line.keyword.clone(),
                    msg: "SetEnv requires at least one NAME=VALUE".into(),
                });
            }
            for tok in args {
                let (name, value) = tok.split_once('=').ok_or_else(|| ConfigError::BadValue {
                    line: line.line_no,
                    keyword: line.keyword.clone(),
                    msg: format!("expected NAME=VALUE, got {tok:?}"),
                })?;
                if name.is_empty() {
                    return Err(ConfigError::BadValue {
                        line: line.line_no,
                        keyword: line.keyword.clone(),
                        msg: format!("empty variable name in {tok:?}"),
                    });
                }
                opts.set_env.push((name.to_string(), value.to_string()));
            }
        }
        "sendenv" => {
            if args.is_empty() {
                return Err(ConfigError::BadValue {
                    line: line.line_no,
                    keyword: line.keyword.clone(),
                    msg: "SendEnv requires at least one pattern".into(),
                });
            }
            for pat in args {
                opts.send_env.push(pat.clone());
            }
        }
        "connecttimeout" => {
            // A time (`30`, `1m`) or `none` (kept as 0: no timeout).
            let v = one_arg(line)?;
            opts.connect_timeout = Some(if v.eq_ignore_ascii_case("none") {
                0
            } else {
                parse_time(line, &v)?
            });
        }
        "serveraliveinterval" => {
            let v = one_arg(line)?;
            opts.server_alive_interval = Some(parse_time(line, &v)?);
        }
        "serveralivecountmax" => {
            opts.server_alive_count_max = Some(parse_u32(line)?);
        }
        "tcpkeepalive" => {
            opts.tcp_keep_alive = Some(parse_yes_no(line)?);
        }
        "addkeystoagent" => {
            // OpenSSH accepts yes/no/confirm/ask. We can honour yes/no
            // (push or don't push the loaded key to the agent); the
            // interactive confirm/ask variants need a UI we don't have,
            // so reject rather than silently downgrade.
            let s = one_arg(line)?.to_ascii_lowercase();
            match s.as_str() {
                "yes" | "true" | "on" => opts.add_keys_to_agent = Some(true),
                "no" | "false" | "off" => opts.add_keys_to_agent = Some(false),
                "confirm" | "ask" => {
                    return Err(ConfigError::Unsupported {
                        line: line.line_no,
                        msg: "AddKeysToAgent confirm/ask requires interactive confirmation, \
                              which is not implemented"
                            .into(),
                    });
                }
                other => {
                    return Err(ConfigError::BadValue {
                        line: line.line_no,
                        keyword: line.keyword.clone(),
                        msg: format!("expected yes/no/confirm/ask, got {other:?}"),
                    });
                }
            }
        }
        "preferredauthentications" => {
            opts.preferred_authentications = Some(parse_preferred_auth(line)?);
        }
        "pubkeyauthentication" => {
            opts.pubkey_authentication = Some(parse_yes_no(line)?);
        }
        "numberofpasswordprompts" => {
            opts.number_of_password_prompts = Some(parse_u32(line)?);
        }
        "batchmode" => {
            opts.batch_mode = Some(parse_yes_no(line)?);
        }
        "exitonforwardfailure" => {
            opts.exit_on_forward_failure = Some(parse_yes_no(line)?);
        }
        "clearallforwardings" => {
            opts.clear_all_forwardings = Some(parse_yes_no(line)?);
        }
        "dynamicforward" => {
            opts.dynamic_forwards.push(parse_dynamic_forward(line)?);
        }
        "gatewayports" => {
            let s = one_arg(line)?.to_ascii_lowercase();
            opts.gateway_ports = Some(match s.as_str() {
                "no" | "false" | "off" => GatewayPorts::No,
                "yes" | "true" | "on" => GatewayPorts::Yes,
                "clientspecified" => GatewayPorts::ClientSpecified,
                other => {
                    return Err(ConfigError::BadValue {
                        line: line.line_no,
                        keyword: line.keyword.clone(),
                        msg: format!("expected no/yes/clientspecified, got {other:?}"),
                    });
                }
            });
        }
        "addressfamily" => {
            let s = one_arg(line)?.to_ascii_lowercase();
            opts.address_family = Some(match s.as_str() {
                "any" => AddressFamily::Any,
                "inet" => AddressFamily::Inet,
                "inet6" => AddressFamily::Inet6,
                other => {
                    return Err(ConfigError::BadValue {
                        line: line.line_no,
                        keyword: line.keyword.clone(),
                        msg: format!("expected any/inet/inet6, got {other:?}"),
                    });
                }
            });
        }
        "bindaddress" => {
            opts.bind_address = Some(one_arg(line)?);
        }
        "knockmode" => {
            let s = one_arg(line)?.to_ascii_lowercase();
            opts.knock_mode = Some(match s.as_str() {
                "no" | "never" | "false" | "off" => KnockSetting::No,
                "auto" | "yes" | "true" | "on" => KnockSetting::Auto,
                "always" => KnockSetting::Always,
                other => {
                    return Err(ConfigError::BadValue {
                        line: line.line_no,
                        keyword: line.keyword.clone(),
                        msg: format!("expected no/auto/always, got {other:?}"),
                    });
                }
            });
        }
        "knockfallbackdelay" => {
            opts.knock_fallback_delay = Some(parse_u32(line)?);
        }
        "knockport" => {
            let port = parse_u32(line)?;
            if port == 0 || port > u16::MAX as u32 {
                return Err(ConfigError::BadValue {
                    line: line.line_no,
                    keyword: line.keyword.clone(),
                    msg: "KnockPort must be 1..=65535".into(),
                });
            }
            opts.knock_port = Some(port as u16);
        }
        "identityagent" => {
            let v = one_arg(line)?;
            opts.identity_agent = Some(if v.eq_ignore_ascii_case("none") {
                IdentityAgent::None
            } else {
                IdentityAgent::Path(v)
            });
        }
        "controlmaster" => {
            let s = one_arg(line)?.to_ascii_lowercase();
            opts.control_master = Some(match s.as_str() {
                "no" | "false" | "off" => ControlMaster::No,
                "yes" | "true" | "on" => ControlMaster::Yes,
                "auto" => ControlMaster::Auto,
                // `ask` / `autoask` need an interactive confirmation path
                // we don't have. Reject rather than silently treat as
                // `yes` — the user explicitly asked to be prompted.
                "ask" | "autoask" => {
                    return Err(ConfigError::Unsupported {
                        line: line.line_no,
                        msg: "ControlMaster ask/autoask requires interactive confirmation, \
                              which is not implemented"
                            .into(),
                    });
                }
                other => {
                    return Err(ConfigError::BadValue {
                        line: line.line_no,
                        keyword: line.keyword.clone(),
                        msg: format!("expected no/yes/auto, got {other:?}"),
                    });
                }
            });
        }
        "controlpath" => {
            // The whole rest of the line (after token re-join) is the path;
            // `%`-token and `~` expansion happen at the honoring site.
            // `none` (case-insensitive) disables multiplexing.
            let v = one_arg(line)?;
            if v.eq_ignore_ascii_case("none") {
                opts.control_path = None;
            } else {
                opts.control_path = Some(v);
            }
        }
        "controlpersist" => {
            opts.control_persist = Some(parse_control_persist(line)?);
        }
        "obscurekeystroketiming" => {
            opts.obscure_keystroke_timing = Some(parse_obscure_keystroke_timing(line)?);
        }
        "casignaturealgorithms" => {
            opts.ca_signature_algorithms = Some(resolve_algo_list(
                AlgoCategory::CaSignature,
                args,
                line.line_no,
                &line.keyword,
            )?);
        }
        "escapechar" => {
            let v = one_arg(line)?;
            opts.escape_char =
                Some(parse_escape_char(&v).ok_or_else(|| ConfigError::BadValue {
                    line: line.line_no,
                    keyword: line.keyword.clone(),
                    msg: format!("expected a character, ^X or none, got {v:?}"),
                })?);
        }
        "knownhostscommand" => {
            if opts.known_hosts_command.is_none() {
                opts.known_hosts_command = Some(line.rest.clone());
            }
        }
        "updatehostkeys" => {
            let v = one_arg(line)?.to_ascii_lowercase();
            let v = match v.as_str() {
                "yes" | "true" => "yes",
                "no" | "false" => "no",
                "ask" => "ask",
                _ => {
                    return Err(ConfigError::BadValue {
                        line: line.line_no,
                        keyword: line.keyword.clone(),
                        msg: format!("expected yes/no/ask, got {v:?}"),
                    });
                }
            };
            if opts.update_host_keys.is_none() {
                opts.update_host_keys = Some(v.to_string());
            }
        }
        "tag" => {
            let v = one_arg(line)?;
            if opts.tag.is_none() {
                opts.tag = Some(v);
            }
        }
        "localcommand" => {
            // The rest of the line, verbatim.
            if opts.local_command.is_none() {
                opts.local_command = Some(line.rest.clone());
            }
        }
        "permitlocalcommand" => {
            opts.permit_local_command = Some(parse_yes_no(line)?);
        }
        "remotecommand" => {
            // The rest of the line, verbatim.
            if opts.remote_command.is_none() {
                opts.remote_command = Some(line.rest.clone());
            }
        }
        "sessiontype" => {
            let v = one_arg(line)?.to_ascii_lowercase();
            opts.session_type = Some(match v.as_str() {
                "none" => SessionType::None,
                "subsystem" => SessionType::Subsystem,
                "default" => SessionType::Default,
                _ => {
                    return Err(ConfigError::BadValue {
                        line: line.line_no,
                        keyword: line.keyword.clone(),
                        msg: format!("expected none/subsystem/default, got {v:?}"),
                    });
                }
            });
        }
        "stdinnull" => opts.stdin_null = Some(parse_yes_no(line)?),
        "forkafterauthentication" => opts.fork_after_authentication = Some(parse_yes_no(line)?),
        "passwordauthentication" => opts.password_authentication = Some(parse_yes_no(line)?),
        "kbdinteractiveauthentication" => {
            opts.kbd_interactive_authentication = Some(parse_yes_no(line)?)
        }
        "hostkeyalias" => opts.host_key_alias = Some(one_arg(line)?),
        "revokedhostkeys" => opts.revoked_host_keys = Some(one_arg(line)?),
        "globalknownhostsfile" => {
            if line.args.is_empty() {
                return Err(ConfigError::BadValue {
                    line: line.line_no,
                    keyword: line.keyword.clone(),
                    msg: "expected one or more files".into(),
                });
            }
            opts.global_known_hosts_files = Some(line.args.clone());
        }
        "connectionattempts" => {
            let v = one_arg(line)?;
            opts.connection_attempts =
                Some(v.parse::<u32>().ok().filter(|n| *n > 0).ok_or_else(|| {
                    ConfigError::BadValue {
                        line: line.line_no,
                        keyword: line.keyword.clone(),
                        msg: format!("expected a positive number, got {v:?}"),
                    }
                })?);
        }
        "checkhostip" => opts.check_host_ip = Some(parse_yes_no(line)?),
        "verifyhostkeydns" => {
            let v = one_arg(line)?.to_ascii_lowercase();
            opts.verify_host_key_dns = Some(match v.as_str() {
                "yes" | "true" => VerifyHostKeyDns::Yes,
                "no" | "false" => VerifyHostKeyDns::No,
                "ask" => VerifyHostKeyDns::Ask,
                _ => return Err(bad_value(line, format!("expected yes/no/ask, got {v:?}"))),
            });
        }
        "visualhostkey" => opts.visual_host_key = Some(parse_yes_no(line)?),
        "nohostauthenticationforlocalhost" => {
            opts.no_host_authentication_for_localhost = Some(parse_yes_no(line)?)
        }
        "fingerprinthash" => {
            let v = one_arg(line)?;
            opts.fingerprint_hash = Some(
                fingerprint_hash_name(&v)
                    .ok_or_else(|| bad_value(line, format!("Invalid hash algorithm \"{v}\"")))?
                    .to_string(),
            );
        }
        "bindinterface" => opts.bind_interface = Some(one_arg(line)?),
        "ipqos" => {
            if args.is_empty() || args.len() > 2 {
                return Err(bad_value(line, "expected one or two values".into()));
            }
            let mut values = [IPQOS_NONE; 2];
            for (slot, a) in values.iter_mut().zip(args.iter()) {
                *slot = parse_ipqos(a)
                    .ok_or_else(|| bad_value(line, format!("Bad IPQoS value: {a}")))?;
            }
            // One value is for both kinds of traffic.
            let bulk = if args.len() == 2 {
                values[1]
            } else {
                values[0]
            };
            opts.ip_qos = Some((values[0], bulk));
        }
        "forwardx11timeout" => {
            let v = one_arg(line)?;
            opts.forward_x11_timeout = Some(if v.eq_ignore_ascii_case("none") {
                0
            } else {
                parse_time(line, &v)?
            });
        }
        "xauthlocation" => opts.xauth_location = Some(one_arg(line)?),
        "canonicalizepermittedcnames" => {
            let mut rules = Vec::new();
            for a in args {
                if a.eq_ignore_ascii_case("none") {
                    if args.len() != 1 {
                        return Err(bad_value(
                            line,
                            "\"none\" argument must appear alone.".into(),
                        ));
                    }
                } else if a == "*" {
                    rules.push(("*".to_string(), "*".to_string()));
                } else {
                    match a.to_ascii_lowercase().split_once(':') {
                        Some((from, to)) if !to.is_empty() => {
                            rules.push((from.to_string(), to.to_string()))
                        }
                        _ => {
                            return Err(bad_value(
                                line,
                                format!("Invalid permitted CNAME \"{a}\""),
                            ));
                        }
                    }
                }
            }
            if args.is_empty() {
                return Err(bad_value(
                    line,
                    "no CanonicalizePermittedCNAMEs specified".into(),
                ));
            }
            if opts.canonicalize_permitted_cnames.is_none() {
                opts.canonicalize_permitted_cnames = Some(rules);
            }
        }
        "channeltimeout" => {
            let mut list = Vec::new();
            for a in args {
                if a.eq_ignore_ascii_case("none") {
                    if args.len() != 1 {
                        return Err(bad_value(
                            line,
                            "\"none\" argument must appear alone.".into(),
                        ));
                    }
                } else if parse_channel_timeout(a).is_none() {
                    return Err(bad_value(line, format!("invalid channel timeout {a}")));
                } else {
                    list.push(a.clone());
                }
            }
            if args.is_empty() {
                return Err(bad_value(line, "no ChannelTimeout specified".into()));
            }
            if opts.channel_timeouts.is_none() {
                opts.channel_timeouts = Some(list);
            }
        }
        "logverbose" => {
            let mut list = Vec::new();
            for a in args {
                if a.eq_ignore_ascii_case("none") {
                    if args.len() != 1 {
                        return Err(bad_value(
                            line,
                            "\"none\" argument must appear alone.".into(),
                        ));
                    }
                } else {
                    list.push(a.clone());
                }
            }
            // OpenSSH keeps only the first pattern of the line it takes.
            list.truncate(1);
            if opts.log_verbose.is_none() && !args.is_empty() {
                opts.log_verbose = Some(list);
            }
        }
        "syslogfacility" => {
            let v = one_arg(line)?;
            let f = syslog_facility_name(&v)
                .ok_or_else(|| bad_value(line, format!("unsupported log facility '{v}'")))?;
            opts.syslog_facility = Some(f.to_string());
        }
        "streamlocalbindmask" => {
            let v = one_arg(line)?;
            let mask = u32::from_str_radix(&v, 8)
                .ok()
                .filter(|m| *m <= 0o777)
                .ok_or_else(|| bad_value(line, "Bad mask.".into()))?;
            opts.stream_local_bind_mask = Some(mask);
        }
        "streamlocalbindunlink" => opts.stream_local_bind_unlink = Some(parse_yes_no(line)?),
        "requiredrsasize" => opts.required_rsa_size = Some(parse_u32(line)?),
        "proxyusefdpass" => opts.proxy_use_fdpass = Some(parse_yes_no(line)?),
        "kbdinteractivedevices" => opts.kbd_interactive_devices = Some(one_arg(line)?),
        "warnweakcrypto" => {
            let v = one_arg(line)?.to_ascii_lowercase();
            opts.warn_weak_crypto = Some(match v.as_str() {
                "yes" | "true" => true,
                "no" | "false" | "no-pq-kex" => false,
                _ => {
                    return Err(bad_value(
                        line,
                        format!("expected yes/no/no-pq-kex, got {v:?}"),
                    ));
                }
            });
        }
        "versionaddendum" => {
            // The rest of the line as written (OpenSSH keeps a trailing
            // `# ...` too).
            let v = line.rest.trim();
            if v.is_empty() {
                return Err(bad_value(line, "VersionAddendum missing argument.".into()));
            }
            if v.contains('\r') {
                return Err(bad_value(line, "Invalid VersionAddendum argument".into()));
            }
            if opts.version_addendum.is_none() {
                opts.version_addendum = Some(if v.eq_ignore_ascii_case("none") {
                    String::new()
                } else {
                    v.to_string()
                });
            }
        }
        "refuseconnection" => {
            // Refused when the block applies (OpenSSH stops right there).
            let reason = line
                .args
                .first()
                .filter(|a| !a.is_empty())
                .ok_or_else(|| bad_value(line, "Missing argument.".into()))?;
            if opts.refuse_connection.is_none() {
                opts.refuse_connection =
                    Some(format!("{}: RefuseConnection: {reason}", line.location()));
            }
        }
        "tunnel" => {
            let v = one_arg(line)?.to_ascii_lowercase();
            if !matches!(
                v.as_str(),
                "yes" | "true" | "no" | "false" | "point-to-point" | "ethernet"
            ) {
                return Err(bad_value(
                    line,
                    "expected yes, no, point-to-point or ethernet".into(),
                ));
            }
            opts.tunnel = Some(v);
        }
        "tunneldevice" => opts.tunnel_device = Some(one_arg(line)?),
        "enableescapecommandline" => opts.enable_escape_commandline = Some(parse_yes_no(line)?),
        _ => {
            if let Some((_, allowed, why)) = IGNORED_KEYWORDS
                .iter()
                .find(|(k, _, _)| k.eq_ignore_ascii_case(kw))
            {
                let value = line.args.join(" ");
                if allowed.is_empty()
                    || allowed.contains(&"*")
                    || allowed.iter().any(|a| a.eq_ignore_ascii_case(&value))
                {
                    if !opts.unimplemented.iter().any(|(k, _)| k == kw) {
                        opts.unimplemented.push((kw.to_string(), value));
                    }
                    return Ok(());
                }
                return Err(ConfigError::Unsupported {
                    line: line.line_no,
                    msg: format!("{} {value}: {why}", line.keyword),
                });
            }
            return Err(ConfigError::UnknownKeyword {
                line: line.line_no,
                keyword: kw.to_string(),
            });
        }
    }
    let _ = args;
    Ok(())
}

/// `EscapeChar`: a single character, `^X` for a control character, or
/// `none`.
pub fn parse_escape_char(v: &str) -> Option<Option<u8>> {
    if v.eq_ignore_ascii_case("none") {
        return Some(None);
    }
    match v.as_bytes() {
        [c] => Some(Some(*c)),
        [b'^', c] => Some(Some(c.to_ascii_uppercase() & 0x1f)),
        _ => None,
    }
}

/// OpenSSH `ssh_config` keywords this client accepts without implementing:
/// `(keyword, values accepted, why other values are refused)`. `"*"`
/// accepts any value: ignoring the keyword can only make the client
/// stricter or lose a convenience. A value whose loss would silently weaken
/// security or break the connection is refused instead.
const IGNORED_KEYWORDS: &[(&str, &[&str], &str)] = &[
    (
        "EnableSSHKeysign",
        &["no"],
        "host-based authentication is not supported",
    ),
    ("GSSAPIAuthentication", &["*"], ""),
    ("GSSAPIDelegateCredentials", &["*"], ""),
    ("GSSAPIKeyExchange", &["*"], ""),
    ("GSSAPIClientIdentity", &["*"], ""),
    ("GSSAPIServerIdentity", &["*"], ""),
    ("GSSAPIRenewalForcesRekey", &["*"], ""),
    ("GSSAPITrustDns", &["*"], ""),
    ("GSSAPIKexAlgorithms", &["*"], ""),
    ("HostbasedAcceptedAlgorithms", &["*"], ""),
    ("HostbasedKeyTypes", &["*"], ""),
    ("HostbasedAuthentication", &["*"], ""),
    ("UseKeychain", &["*"], ""),
    // Removed from OpenSSH; it ignores them with a warning.
    ("Protocol", &["*"], ""),
    ("Cipher", &["*"], ""),
    ("CompressionLevel", &["*"], ""),
    ("UseRoaming", &["*"], ""),
    ("RSAAuthentication", &["*"], ""),
    ("RhostsRSAAuthentication", &["*"], ""),
    ("RhostsAuthentication", &["*"], ""),
    ("UsePrivilegedPort", &["*"], ""),
    ("FallBackToRsh", &["*"], ""),
    ("UseRsh", &["*"], ""),
    ("GlobalKnownHostsFile2", &["*"], ""),
    ("UserKnownHostsFile2", &["*"], ""),
    ("AFSTokenPassing", &["*"], ""),
    ("KerberosAuthentication", &["*"], ""),
    ("KerberosTGTPassing", &["*"], ""),
];

impl ClientOptions {
    /// Fill every option `self` leaves unset from `lower` and append its
    /// list options after `self`'s: the first-obtained-value rule, with
    /// `self` obtained first (as `ssh -o` options are, ahead of the files).
    pub fn merge_lower(&mut self, lower: &ClientOptions) {
        merge_into(self, lower);
    }
}

/// First-match-wins merge of `src` over `dst`. Scalars only overwrite if
/// `dst` had `None`; list fields concatenate.
fn merge_into(dst: &mut ClientOptions, src: &ClientOptions) {
    for (k, v) in &src.unimplemented {
        if !dst.unimplemented.iter().any(|(d, _)| d == k) {
            dst.unimplemented.push((k.clone(), v.clone()));
        }
    }
    macro_rules! take_scalar {
        ($field:ident) => {
            if dst.$field.is_none() {
                dst.$field = src.$field.clone();
            }
        };
    }
    take_scalar!(host_name);
    take_scalar!(port);
    take_scalar!(user);
    take_scalar!(identities_only);
    take_scalar!(security_key_provider);
    take_scalar!(pkcs11_provider);
    take_scalar!(strict_host_key);
    take_scalar!(user_known_hosts);
    take_scalar!(hash_known_hosts);
    take_scalar!(forward_agent);
    take_scalar!(forward_agent_socket);
    take_scalar!(forward_x11);
    take_scalar!(forward_x11_trusted);
    take_scalar!(request_tty);
    take_scalar!(canonicalize_hostname);
    take_scalar!(rekey_limit);
    take_scalar!(permit_remote_open);
    take_scalar!(canonical_domains);
    take_scalar!(canonicalize_max_dots);
    take_scalar!(canonicalize_fallback_local);
    take_scalar!(log_level);
    // Algorithm overrides are first-match-wins scalars: the whole resolved
    // list from the earliest matching block wins (OpenSSH semantics — a
    // later block's Ciphers does not append to an earlier block's).
    take_scalar!(ciphers);
    take_scalar!(macs);
    take_scalar!(kex_algorithms);
    take_scalar!(host_key_algorithms);
    take_scalar!(pubkey_accepted_algorithms);
    take_scalar!(ca_signature_algorithms);
    // Whichever of the two was obtained first excludes the other.
    if dst.proxy_jump.is_none() {
        take_scalar!(proxy_command);
    }
    if dst.proxy_command.is_none() {
        take_scalar!(proxy_jump);
    }
    take_scalar!(compression);
    take_scalar!(connect_timeout);
    take_scalar!(server_alive_interval);
    take_scalar!(server_alive_count_max);
    take_scalar!(tcp_keep_alive);
    take_scalar!(add_keys_to_agent);
    take_scalar!(preferred_authentications);
    take_scalar!(pubkey_authentication);
    take_scalar!(number_of_password_prompts);
    take_scalar!(batch_mode);
    take_scalar!(exit_on_forward_failure);
    take_scalar!(clear_all_forwardings);
    take_scalar!(gateway_ports);
    take_scalar!(address_family);
    take_scalar!(bind_address);
    take_scalar!(identity_agent);
    take_scalar!(control_master);
    take_scalar!(control_path);
    take_scalar!(control_persist);
    take_scalar!(obscure_keystroke_timing);
    take_scalar!(knock_mode);
    take_scalar!(knock_fallback_delay);
    take_scalar!(knock_port);
    take_scalar!(escape_char);
    take_scalar!(remote_command);
    take_scalar!(local_command);
    take_scalar!(tag);
    take_scalar!(update_host_keys);
    take_scalar!(known_hosts_command);
    take_scalar!(permit_local_command);
    take_scalar!(session_type);
    take_scalar!(stdin_null);
    take_scalar!(fork_after_authentication);
    take_scalar!(password_authentication);
    take_scalar!(kbd_interactive_authentication);
    take_scalar!(host_key_alias);
    take_scalar!(revoked_host_keys);
    take_scalar!(global_known_hosts_files);
    take_scalar!(connection_attempts);
    take_scalar!(check_host_ip);
    take_scalar!(verify_host_key_dns);
    take_scalar!(visual_host_key);
    take_scalar!(no_host_authentication_for_localhost);
    take_scalar!(fingerprint_hash);
    take_scalar!(bind_interface);
    take_scalar!(ip_qos);
    take_scalar!(forward_x11_timeout);
    take_scalar!(xauth_location);
    take_scalar!(canonicalize_permitted_cnames);
    take_scalar!(channel_timeouts);
    take_scalar!(log_verbose);
    take_scalar!(syslog_facility);
    take_scalar!(stream_local_bind_mask);
    take_scalar!(stream_local_bind_unlink);
    take_scalar!(required_rsa_size);
    take_scalar!(proxy_use_fdpass);
    take_scalar!(kbd_interactive_devices);
    take_scalar!(warn_weak_crypto);
    take_scalar!(version_addendum);
    take_scalar!(refuse_connection);
    take_scalar!(tunnel);
    take_scalar!(tunnel_device);
    take_scalar!(enable_escape_commandline);
    dst.identity_files
        .extend(src.identity_files.iter().cloned());
    dst.certificate_files
        .extend(src.certificate_files.iter().cloned());
    dst.local_forwards
        .extend(src.local_forwards.iter().cloned());
    dst.remote_forwards
        .extend(src.remote_forwards.iter().cloned());
    dst.dynamic_forwards
        .extend(src.dynamic_forwards.iter().cloned());
    dst.set_env.extend(src.set_env.iter().cloned());
    dst.send_env.extend(src.send_env.iter().cloned());
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

fn parse_u32(line: &ParsedLine) -> Result<u32, ConfigError> {
    let s = one_arg(line)?;
    s.parse::<u32>().map_err(|_| ConfigError::BadValue {
        line: line.line_no,
        keyword: line.keyword.clone(),
        msg: format!("expected a non-negative integer, got {s:?}"),
    })
}

/// Parse a `PreferredAuthentications` list. OpenSSH takes a comma-separated
/// list of method names. We recognise the standard set but only honour the
/// ones the client implements; a list that names *none* of the
/// implementable methods is rejected so the directive can never look like it
/// took effect while silently leaving no usable method.
fn parse_preferred_auth(line: &ParsedLine) -> Result<Vec<String>, ConfigError> {
    // The list may arrive as one comma-joined token or several whitespace-
    // separated tokens; normalise both.
    let mut methods: Vec<String> = Vec::new();
    for tok in &line.args {
        for m in tok.split(',') {
            let m = m.trim();
            if !m.is_empty() {
                methods.push(m.to_ascii_lowercase());
            }
        }
    }
    if methods.is_empty() {
        return Err(ConfigError::BadValue {
            line: line.line_no,
            keyword: line.keyword.clone(),
            msg: "PreferredAuthentications requires at least one method".into(),
        });
    }
    // Like OpenSSH, any method name is accepted: Ansible's defaults list
    // `gssapi-keyex` and `hostbased`, which are simply never tried.
    Ok(methods)
}

/// Parse a `DynamicForward` argument: a single `[bind:]port` token.
fn parse_dynamic_forward(line: &ParsedLine) -> Result<DynamicForwardSpec, ConfigError> {
    if line.args.len() != 1 {
        return Err(ConfigError::BadValue {
            line: line.line_no,
            keyword: line.keyword.clone(),
            msg: format!("expected 1 token ([bind:]port), got {}", line.args.len()),
        });
    }
    let (bind_addr, listen_port) = split_bind_port(&line.args[0], line)?;
    Ok(DynamicForwardSpec {
        bind_addr,
        listen_port,
    })
}

/// Parse a `ControlPersist` value: `yes` / `no` / `<N>` / `<N>[smh]`.
///
/// A bare integer is seconds. A trailing `s`/`m`/`h` suffix scales to
/// seconds (`m` ⇒ ×60, `h` ⇒ ×3600). A literal `0` means "no persist"
/// (≡ `no`), matching OpenSSH. Overflow on the multiply is rejected.
/// A time as OpenSSH's `convtime` reads it: seconds, or numbers with
/// `s` / `m` / `h` / `d` / `w` units, run together (`1h30m`).
fn parse_time(line: &ParsedLine, v: &str) -> Result<u32, ConfigError> {
    let bad = || ConfigError::BadValue {
        line: line.line_no,
        keyword: line.keyword.clone(),
        msg: format!("expected a time (e.g. 30, 1m, 1h30m), got {v:?}"),
    };
    let mut total: u64 = 0;
    let mut num: Option<u64> = None;
    for c in v.chars() {
        if let Some(d) = c.to_digit(10) {
            num = Some(num.unwrap_or(0).checked_mul(10).ok_or_else(bad)? + u64::from(d));
            continue;
        }
        let scale = match c.to_ascii_lowercase() {
            's' => 1,
            'm' => 60,
            'h' => 3600,
            'd' => 86400,
            'w' => 604800,
            _ => return Err(bad()),
        };
        total = total
            .checked_add(
                num.take()
                    .ok_or_else(bad)?
                    .checked_mul(scale)
                    .ok_or_else(bad)?,
            )
            .ok_or_else(bad)?;
    }
    if let Some(n) = num {
        total = total.checked_add(n).ok_or_else(bad)?;
    } else if v.is_empty() {
        return Err(bad());
    }
    u32::try_from(total).map_err(|_| bad())
}

fn parse_control_persist(line: &ParsedLine) -> Result<ControlPersist, ConfigError> {
    let s = one_arg(line)?.to_ascii_lowercase();
    match s.as_str() {
        "no" | "false" | "off" => return Ok(ControlPersist::No),
        "yes" | "true" | "on" => return Ok(ControlPersist::Yes),
        _ => {}
    }
    let bad = |msg: String| ConfigError::BadValue {
        line: line.line_no,
        keyword: line.keyword.clone(),
        msg,
    };
    let (digits, scale): (&str, u64) = match s.as_bytes().last() {
        Some(b's') => (&s[..s.len() - 1], 1),
        Some(b'm') => (&s[..s.len() - 1], 60),
        Some(b'h') => (&s[..s.len() - 1], 3600),
        _ => (s.as_str(), 1),
    };
    if digits.is_empty() {
        return Err(bad(format!("expected yes/no/<N>[smh], got {s:?}")));
    }
    let n: u64 = digits
        .parse()
        .map_err(|_| bad(format!("expected yes/no/<N>[smh], got {s:?}")))?;
    let secs = n
        .checked_mul(scale)
        .ok_or_else(|| bad("ControlPersist duration overflows".into()))?;
    if secs == 0 {
        Ok(ControlPersist::No)
    } else {
        Ok(ControlPersist::Seconds(secs))
    }
}

/// Parse an `ObscureKeystrokeTiming` value: `yes` / `no` / `interval:<spec>`.
///
/// `yes` ⇒ on at the OpenSSH default (20 ms). `no` ⇒ off. `interval:<spec>`
/// ⇒ on with `<spec>` resolved to milliseconds: either a bare integer
/// (milliseconds, `interval:80`) or an OpenSSH time value with a unit suffix
/// (`interval:1s`, `interval:500ms`). A zero interval is rejected. STRICT:
/// anything malformed is a [`ConfigError::BadValue`].
fn parse_obscure_keystroke_timing(
    line: &ParsedLine,
) -> Result<ObscureKeystrokeTiming, ConfigError> {
    let raw = one_arg(line)?;
    let s = raw.to_ascii_lowercase();
    let bad = |msg: String| ConfigError::BadValue {
        line: line.line_no,
        keyword: line.keyword.clone(),
        msg,
    };
    match s.as_str() {
        "no" | "false" | "off" => return Ok(ObscureKeystrokeTiming::Off),
        "yes" | "true" | "on" => return Ok(ObscureKeystrokeTiming::default_on()),
        _ => {}
    }
    let Some(spec) = s.strip_prefix("interval:") else {
        return Err(bad(format!("expected yes/no/interval:<spec>, got {raw:?}")));
    };
    if spec.is_empty() {
        return Err(bad("interval: requires a value".into()));
    }
    // Resolve <spec> to milliseconds. Bare integer ⇒ ms. `ms` suffix ⇒ ms.
    // `s`/`m`/`h` suffixes ⇒ seconds/minutes/hours scaled to ms.
    let (digits, scale_ms): (&str, u64) = if let Some(d) = spec.strip_suffix("ms") {
        (d, 1)
    } else if let Some(d) = spec.strip_suffix('s') {
        (d, 1000)
    } else if let Some(d) = spec.strip_suffix('m') {
        (d, 60_000)
    } else if let Some(d) = spec.strip_suffix('h') {
        (d, 3_600_000)
    } else {
        (spec, 1)
    };
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return Err(bad(format!(
            "interval: expected <ms> or <N>[ms|s|m|h], got {spec:?}"
        )));
    }
    let n: u64 = digits
        .parse()
        .map_err(|_| bad(format!("interval: invalid number {spec:?}")))?;
    let ms = n
        .checked_mul(scale_ms)
        .ok_or_else(|| bad("interval: duration overflows".into()))?;
    if ms == 0 {
        return Err(bad("interval: must be greater than zero".into()));
    }
    let interval_ms = u32::try_from(ms).map_err(|_| bad("interval: too large".into()))?;
    Ok(ObscureKeystrokeTiming::On { interval_ms })
}

fn bad_value(line: &ParsedLine, msg: String) -> ConfigError {
    ConfigError::BadValue {
        line: line.line_no,
        keyword: line.keyword.clone(),
        msg,
    }
}

/// OpenSSH's name for the fingerprint hash `v` names (any case), as
/// `FingerprintHash` takes it.
pub fn fingerprint_hash_name(v: &str) -> Option<&'static str> {
    const NAMES: &[&str] = &["MD5", "SHA1", "SHA256", "SHA384", "SHA512"];
    NAMES.iter().find(|n| n.eq_ignore_ascii_case(v)).copied()
}

/// OpenSSH's `SyslogFacility` names.
const SYSLOG_FACILITIES: &[&str] = &[
    "DAEMON", "USER", "AUTH", "AUTHPRIV", "LOCAL0", "LOCAL1", "LOCAL2", "LOCAL3", "LOCAL4",
    "LOCAL5", "LOCAL6", "LOCAL7",
];

/// The `SyslogFacility` `v` names (any case), upper-cased.
pub fn syslog_facility_name(v: &str) -> Option<&'static str> {
    SYSLOG_FACILITIES
        .iter()
        .find(|n| n.eq_ignore_ascii_case(v))
        .copied()
}

/// OpenSSH's `IPQoS` names and their TOS values (`none`: [`IPQOS_NONE`]).
const IPQOS_NAMES: [(&str, u32); 25] = [
    ("none", IPQOS_NONE),
    ("af11", 0x28),
    ("af12", 0x30),
    ("af13", 0x38),
    ("af21", 0x48),
    ("af22", 0x50),
    ("af23", 0x58),
    ("af31", 0x68),
    ("af32", 0x70),
    ("af33", 0x78),
    ("af41", 0x88),
    ("af42", 0x90),
    ("af43", 0x98),
    ("cs0", 0x00),
    ("cs1", 0x20),
    ("cs2", 0x40),
    ("cs3", 0x60),
    ("cs4", 0x80),
    ("cs5", 0xa0),
    ("cs6", 0xc0),
    ("cs7", 0xe0),
    ("ef", 0xb8),
    ("le", 0x04),
    ("va", 0xb0),
    // Not DSCP values: OpenSSH takes the system default for them.
    ("lowdelay", IPQOS_NONE),
];

/// One `IPQoS` value: a name (`af21`, `ef`, `none`, …) or a number up to
/// 255. The deprecated `lowdelay`, `throughput` and `reliability` mean the
/// system default, as in OpenSSH.
pub fn parse_ipqos(v: &str) -> Option<u32> {
    if v.eq_ignore_ascii_case("throughput") || v.eq_ignore_ascii_case("reliability") {
        return Some(IPQOS_NONE);
    }
    for (n, tos) in IPQOS_NAMES {
        if n.eq_ignore_ascii_case(v) {
            return Some(tos);
        }
    }
    // `strtonum(cp, 0, 255)`: decimal only.
    v.parse::<u32>().ok().filter(|n| *n <= 255)
}

/// OpenSSH's spelling of an `IPQoS` value (`iptos2str`): its name, else
/// `0x..`.
pub fn ipqos_name(tos: u32) -> String {
    for (n, t) in IPQOS_NAMES {
        if t == tos && n != "lowdelay" {
            return n.to_string();
        }
    }
    format!("0x{tos:02x}")
}

/// One `ChannelTimeout` entry, `type=interval`: the type pattern and the
/// timeout in seconds (`0`: none).
pub fn parse_channel_timeout(spec: &str) -> Option<(String, u32)> {
    let (ty, interval) = spec.split_once('=')?;
    if ty.is_empty() || interval.is_empty() {
        return None;
    }
    let probe = ParsedLine {
        line_no: 0,
        keyword: String::new(),
        args: Vec::new(),
        rest: String::new(),
        file: None,
    };
    Some((ty.to_string(), parse_time(&probe, interval).ok()?))
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

fn parse_strict(line: &ParsedLine) -> Result<StrictMode, ConfigError> {
    let s = one_arg(line)?.to_ascii_lowercase();
    match s.as_str() {
        "yes" | "true" => Ok(StrictMode::Yes),
        "no" | "off" | "false" => Ok(StrictMode::No),
        "accept-new" => Ok(StrictMode::AcceptNew),
        "ask" => Ok(StrictMode::Ask),
        _ => Err(ConfigError::BadValue {
            line: line.line_no,
            keyword: line.keyword.clone(),
            msg: format!("expected yes/no/accept-new/ask/off, got {s:?}"),
        }),
    }
}

fn parse_request_tty(line: &ParsedLine) -> Result<RequestTty, ConfigError> {
    let s = one_arg(line)?.to_ascii_lowercase();
    match s.as_str() {
        "no" => Ok(RequestTty::No),
        "yes" => Ok(RequestTty::Yes),
        "force" => Ok(RequestTty::Force),
        "auto" => Ok(RequestTty::Auto),
        _ => Err(ConfigError::BadValue {
            line: line.line_no,
            keyword: line.keyword.clone(),
            msg: format!("expected no/yes/force/auto, got {s:?}"),
        }),
    }
}

fn parse_log_level(line: &ParsedLine) -> Result<u8, ConfigError> {
    let s = one_arg(line)?.to_ascii_uppercase();
    let s = if s == "DEBUG" {
        "DEBUG1".to_string()
    } else {
        s
    };
    match super::server::LOG_LEVELS.iter().position(|l| *l == s) {
        Some(n) => Ok(n as u8),
        None => Err(ConfigError::BadValue {
            line: line.line_no,
            keyword: line.keyword.clone(),
            msg: format!("expected QUIET..DEBUG3, got {s:?}"),
        }),
    }
}

/// `LocalForward listen connect`: parsed as OpenSSH does, joined with `:`
/// (see [`parse_forward`]).
fn parse_local_forward(line: &ParsedLine) -> Result<LocalForwardSpec, ConfigError> {
    let bad = || ConfigError::BadValue {
        line: line.line_no,
        keyword: line.keyword.clone(),
        msg: "Bad forwarding specification".into(),
    };
    if line.args.len() != 2 {
        return Err(bad());
    }
    let f = parse_forward(&alloc::format!("{}:{}", line.args[0], line.args[1]), false)
        .ok_or_else(bad)?;
    f.into_local().ok_or_else(bad)
}

/// `RemoteForward listen [connect]` (no `connect`: a SOCKS proxy on the
/// server), parsed as OpenSSH does (see [`parse_forward`]).
fn parse_remote_forward(line: &ParsedLine) -> Result<RemoteForwardSpec, ConfigError> {
    let bad = || ConfigError::BadValue {
        line: line.line_no,
        keyword: line.keyword.clone(),
        msg: "Bad forwarding specification".into(),
    };
    let spec = match line.args.as_slice() {
        [a] => a.clone(),
        [a, b] => alloc::format!("{a}:{b}"),
        _ => return Err(bad()),
    };
    Ok(parse_forward(&spec, true).ok_or_else(bad)?.into_remote())
}

/// One end of a forwarding: a TCP `[host:]port` or a Unix-socket path.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ForwardEndpoint {
    /// A TCP port, with the host (or bind address) when one was given.
    Tcp {
        /// Host name or address; `None` when only a port was given.
        host: Option<String>,
        /// Port (`0`: chosen by the listener, for remote forwards).
        port: u16,
    },
    /// A Unix-domain socket path.
    Path(String),
}

/// A forwarding specification as OpenSSH's `parse_forward` reads the
/// `-L` / `-R` argument and the `LocalForward` / `RemoteForward` values.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct ForwardSpec {
    /// Where to listen.
    pub listen: ForwardEndpoint,
    /// Where to connect each forwarded connection; `None` for a SOCKS proxy
    /// (`-R [bind:]port`), which takes the destination from each request.
    pub connect: Option<ForwardEndpoint>,
}

impl ForwardSpec {
    /// As a [`LocalForwardSpec`]; `None` for a SOCKS forward (that is
    /// `DynamicForward`).
    pub fn into_local(self) -> Option<LocalForwardSpec> {
        let mut out = LocalForwardSpec::new(None, 0, String::new(), 0);
        match self.listen {
            ForwardEndpoint::Tcp { host, port } => {
                out.bind_addr = host;
                out.listen_port = port;
            }
            ForwardEndpoint::Path(p) => out.listen_path = Some(p),
        }
        match self.connect? {
            ForwardEndpoint::Tcp { host, port } => {
                out.remote_host = host?;
                out.remote_port = port;
            }
            ForwardEndpoint::Path(p) => out.connect_path = Some(p),
        }
        Some(out)
    }

    /// As a [`RemoteForwardSpec`].
    pub fn into_remote(self) -> RemoteForwardSpec {
        let mut out = RemoteForwardSpec::dynamic(None, 0);
        match self.listen {
            ForwardEndpoint::Tcp { host, port } => {
                out.bind_addr = host;
                out.remote_port = port;
            }
            ForwardEndpoint::Path(p) => out.listen_path = Some(p),
        }
        match self.connect {
            None => {}
            Some(ForwardEndpoint::Tcp { host, port }) => {
                out.dynamic = false;
                out.local_host = host.unwrap_or_default();
                out.local_port = port;
            }
            Some(ForwardEndpoint::Path(p)) => {
                out.dynamic = false;
                out.connect_path = Some(p);
            }
        }
        out
    }
}

/// Parse a forwarding specification as OpenSSH's `parse_forward`:
/// `:`-separated fields, each optionally `[bracketed]` (taken literally) or
/// with `\`-escapes; a field containing `/` is a Unix socket path.
///
/// - `[bind:]port:host:hostport`, `port:/path`, `[bind:]port:/path`,
///   `/path:host:hostport`, `/path:/path` — a forward;
/// - `[bind:]port` or `/path` — a SOCKS proxy, accepted only for `remote`
///   (`-R`; locally that is `-D`).
///
/// A local listen port may not be 0. `None` for anything else.
pub fn parse_forward(spec: &str, remote: bool) -> Option<ForwardSpec> {
    struct Field {
        arg: String,
        is_path: bool,
    }
    let mut fields: Vec<Field> = Vec::new();
    let mut rest = spec.trim_start();
    while !rest.is_empty() {
        if fields.len() == 4 {
            return None;
        }
        if let Some(r) = rest.strip_prefix('[') {
            let close = r.find(']')?;
            let after = &r[close + 1..];
            if !(after.is_empty() || after.starts_with(':')) {
                return None;
            }
            fields.push(Field {
                arg: r[..close].to_string(),
                is_path: r[..close].contains('/'),
            });
            rest = after.strip_prefix(':').unwrap_or(after);
            continue;
        }
        let mut arg = String::new();
        let mut is_path = false;
        let mut chars = rest.char_indices();
        let mut next = "";
        while let Some((i, c)) = chars.next() {
            match c {
                '\\' => arg.push(chars.next()?.1),
                ':' => {
                    next = &rest[i + 1..];
                    break;
                }
                c => {
                    if c == '/' {
                        is_path = true;
                    }
                    arg.push(c);
                }
            }
        }
        fields.push(Field { arg, is_path });
        rest = next;
    }
    let port = |s: &str| s.parse::<u16>().ok();
    let tcp = |host: Option<&Field>, p: &Field| {
        Some(ForwardEndpoint::Tcp {
            host: host.map(|h| h.arg.clone()),
            port: port(&p.arg)?,
        })
    };
    let path = |f: &Field| ForwardEndpoint::Path(f.arg.clone());
    let (listen, connect) = match fields.as_slice() {
        [a] if a.is_path => (path(a), None),
        [a] => (tcp(None, a)?, None),
        [a, b] if a.is_path && b.is_path => (path(a), Some(path(b))),
        [a, b] if b.is_path => (tcp(None, a)?, Some(path(b))),
        [a, b] => (tcp(Some(a), b)?, None),
        [a, b, c] if a.is_path => (path(a), Some(tcp(Some(b), c)?)),
        [a, b, c] if c.is_path => (tcp(Some(a), b)?, Some(path(c))),
        [a, b, c] => (tcp(None, a)?, Some(tcp(Some(b), c)?)),
        [a, b, c, d] => (tcp(Some(a), b)?, Some(tcp(Some(c), d)?)),
        _ => return None,
    };
    if connect.is_none() && !remote {
        return None;
    }
    if let Some(ForwardEndpoint::Tcp { host, port }) = &connect
        && (*port == 0 || host.as_deref().is_none_or(str::is_empty))
    {
        return None;
    }
    if !remote && matches!(listen, ForwardEndpoint::Tcp { port: 0, .. }) {
        return None;
    }
    Some(ForwardSpec { listen, connect })
}

/// `[bind:]port` → `(Some("bind"), port)` or `(None, port)`. IPv6 literal
/// addresses must be bracketed (`[::1]:port`).
fn split_bind_port(s: &str, line: &ParsedLine) -> Result<(Option<String>, u16), ConfigError> {
    if let Some(rest) = s.strip_prefix('[') {
        // `[addr]:port`
        if let Some((addr, port)) = rest.split_once("]:") {
            let port = port.parse::<u16>().map_err(|_| ConfigError::BadValue {
                line: line.line_no,
                keyword: line.keyword.clone(),
                msg: format!("bad port in {s:?}"),
            })?;
            return Ok((Some(addr.to_string()), port));
        }
        return Err(ConfigError::BadValue {
            line: line.line_no,
            keyword: line.keyword.clone(),
            msg: format!("malformed bracketed bind:port {s:?}"),
        });
    }
    match s.rsplit_once(':') {
        Some((addr, port)) => {
            let port = port.parse::<u16>().map_err(|_| ConfigError::BadValue {
                line: line.line_no,
                keyword: line.keyword.clone(),
                msg: format!("bad port in {s:?}"),
            })?;
            Ok((Some(addr.to_string()), port))
        }
        None => {
            let port = s.parse::<u16>().map_err(|_| ConfigError::BadValue {
                line: line.line_no,
                keyword: line.keyword.clone(),
                msg: format!("expected port or addr:port, got {s:?}"),
            })?;
            Ok((None, port))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_minimal() {
        let src = "\
Host gw
  HostName 198.51.100.7
  User admin
  Port 2222
";
        let cfg = SshClientConfig::parse(src).unwrap();
        let eff = cfg.lookup("gw");
        assert_eq!(eff.host_name.as_deref(), Some("198.51.100.7"));
        assert_eq!(eff.port, Some(2222));
        assert_eq!(eff.user.as_deref(), Some("admin"));
    }

    #[test]
    fn algorithm_keywords_parse() {
        let src = "\
Host gw
  Ciphers aes128-ctr,aes256-ctr
  MACs hmac-sha2-256
  KexAlgorithms curve25519-sha256
  HostKeyAlgorithms ssh-ed25519
  PubkeyAcceptedAlgorithms ssh-ed25519,rsa-sha2-512
";
        let cfg = SshClientConfig::parse(src).unwrap();
        let eff = cfg.lookup("gw");
        assert_eq!(
            eff.ciphers.as_deref(),
            Some(&["aes128-ctr".to_string(), "aes256-ctr".to_string()][..])
        );
        assert_eq!(
            eff.macs.as_deref(),
            Some(&["hmac-sha2-256".to_string()][..])
        );
        assert_eq!(
            eff.kex_algorithms.as_deref(),
            Some(&["curve25519-sha256".to_string()][..])
        );
        assert_eq!(
            eff.host_key_algorithms.as_deref(),
            Some(&["ssh-ed25519".to_string()][..])
        );
        assert_eq!(
            eff.pubkey_accepted_algorithms.as_deref(),
            Some(&["ssh-ed25519".to_string(), "rsa-sha2-512".to_string()][..])
        );
    }

    #[test]
    fn host_key_algorithms_plus_ssh_rsa_accepted() {
        // `HostKeyAlgorithms +ssh-rsa` used to be rejected; it now resolves to
        // the defaults plus the legacy SHA-1 name appended (opt-in).
        let src = "Host legacy\n  HostKeyAlgorithms +ssh-rsa\n";
        let cfg = SshClientConfig::parse(src).expect("+ssh-rsa must parse");
        let eff = cfg.lookup("legacy");
        let list = eff
            .host_key_algorithms
            .as_deref()
            .expect("host_key_algorithms set");
        assert!(
            list.iter().any(|n| n == "ssh-rsa"),
            "+ssh-rsa must appear in the resolved list: {list:?}"
        );
        assert!(
            list.iter().any(|n| n == "ssh-ed25519"),
            "defaults must be preserved ahead of the appended legacy name"
        );
    }

    #[test]
    fn host_key_algorithms_bare_ssh_rsa_accepted() {
        // A bare replace naming only ssh-rsa is also accepted (explicit opt-in).
        let src = "Host legacy\n  HostKeyAlgorithms ssh-rsa\n";
        let cfg = SshClientConfig::parse(src).expect("bare ssh-rsa must parse");
        let eff = cfg.lookup("legacy");
        assert_eq!(
            eff.host_key_algorithms.as_deref(),
            Some(&["ssh-rsa".to_string()][..])
        );
    }

    #[test]
    fn pubkey_accepted_ssh_rsa_is_an_opt_in() {
        // `+ssh-rsa` appends the legacy SHA-1 name (for servers before
        // OpenSSH 7.2); it is never a default.
        let src = "Host legacy\n  PubkeyAcceptedAlgorithms +ssh-rsa\n";
        let cfg = SshClientConfig::parse(src).unwrap();
        let algs = cfg.lookup("legacy").pubkey_accepted_algorithms.unwrap();
        assert_eq!(algs.last().map(String::as_str), Some("ssh-rsa"), "{algs:?}");
        assert!(algs.iter().any(|a| a == "rsa-sha2-512"), "{algs:?}");
    }

    #[test]
    fn unknown_cipher_rejected_with_line() {
        let src = "Host gw\n  Ciphers totally-bogus\n";
        let err = SshClientConfig::parse(src).unwrap_err();
        match err {
            ConfigError::BadValue { line, keyword, msg } => {
                assert_eq!(line, 2);
                assert_eq!(keyword, "Ciphers");
                assert!(msg.contains("totally-bogus"));
            }
            other => panic!("expected BadValue, got {other:?}"),
        }
    }

    #[test]
    fn proxy_command_parses() {
        let src = "\
Host gw
  ProxyCommand /usr/bin/nc -X connect -x proxy:3128 %h %p
";
        let cfg = SshClientConfig::parse(src).unwrap();
        let eff = cfg.lookup("gw");
        assert_eq!(
            eff.proxy_command.as_deref(),
            Some("/usr/bin/nc -X connect -x proxy:3128 %h %p")
        );
    }

    #[test]
    fn proxy_command_none_clears() {
        let src = "\
Host gw
  ProxyCommand none
";
        let cfg = SshClientConfig::parse(src).unwrap();
        assert_eq!(cfg.lookup("gw").proxy_command.as_deref(), Some("none"));
    }

    #[test]
    fn match_criteria_take_values_negation_and_tags() {
        let src = "\
Match host=a !user nobody
  Port 1001
Match host=b tagged t1
  Port 1002
Match host=b !tagged t1
  Port 1003
";
        let cfg = SshClientConfig::parse(src).unwrap();
        let ctx = |host| MatchContext {
            host,
            user: Some("me"),
            ..Default::default()
        };
        assert_eq!(cfg.lookup_with(ctx("a")).port, Some(1001));
        assert_eq!(cfg.lookup_with(ctx("b")).port, Some(1003));
        let mut tagged = ctx("b");
        tagged.tag = Some("t1");
        assert_eq!(cfg.lookup_with(tagged).port, Some(1002));
    }

    #[test]
    fn proxy_jump_and_proxy_command_first_obtained_wins() {
        let cfg = SshClientConfig::parse("ProxyJump j\nProxyCommand c\n").unwrap();
        let eff = cfg.lookup("h");
        assert_eq!(
            (eff.proxy_jump.as_deref(), eff.proxy_command),
            (Some("j"), None)
        );
        let cfg = SshClientConfig::parse("ProxyCommand none\nProxyJump j\n").unwrap();
        let eff = cfg.lookup("h");
        assert_eq!(
            (eff.proxy_jump, eff.proxy_command.as_deref()),
            (None, Some("none"))
        );
    }

    #[test]
    fn proxy_command_empty_errors() {
        // `ProxyCommand` with no argument is a config error.
        let src = "ProxyCommand\n";
        let err = SshClientConfig::parse(src).unwrap_err();
        match err {
            ConfigError::BadValue { line, keyword, .. } => {
                assert_eq!(line, 1);
                assert_eq!(keyword, "proxycommand");
            }
            other => panic!("expected BadValue, got {other:?}"),
        }
    }

    #[test]
    fn proxy_jump_parses() {
        let src = "\
Host target
  ProxyJump user@bastion:2222,hop2
";
        let cfg = SshClientConfig::parse(src).unwrap();
        assert_eq!(
            cfg.lookup("target").proxy_jump.as_deref(),
            Some("user@bastion:2222,hop2")
        );
    }

    #[test]
    fn proxy_jump_none_clears() {
        let src = "\
Host target
  ProxyJump none
";
        let cfg = SshClientConfig::parse(src).unwrap();
        assert_eq!(cfg.lookup("target").proxy_jump.as_deref(), Some("none"));
    }

    #[test]
    fn casignaturealgorithms_accepted() {
        let src = "Host gw\n  CASignatureAlgorithms ssh-ed25519,rsa-sha2-512\n";
        let cfg = SshClientConfig::parse(src).unwrap();
        let eff = cfg.lookup("gw");
        assert_eq!(
            eff.ca_signature_algorithms.as_deref(),
            Some(["ssh-ed25519".to_string(), "rsa-sha2-512".to_string()].as_slice())
        );
    }

    #[test]
    fn casignaturealgorithms_rejects_plain_ssh_rsa() {
        // Plain SHA-1 ssh-rsa is not a valid CA signature algorithm.
        let src = "Host gw\n  CASignatureAlgorithms ssh-rsa\n";
        let err = SshClientConfig::parse(src).unwrap_err();
        assert!(matches!(err, ConfigError::BadValue { line: 2, .. }));
    }

    #[test]
    fn algorithms_first_match_wins() {
        // First matching block's Ciphers wins; a later block does not append.
        let src = "\
Host gw
  Ciphers aes128-ctr
Host *
  Ciphers aes256-ctr
";
        let cfg = SshClientConfig::parse(src).unwrap();
        let eff = cfg.lookup("gw");
        assert_eq!(
            eff.ciphers.as_deref(),
            Some(&["aes128-ctr".to_string()][..])
        );
    }

    #[test]
    fn global_block_applies() {
        let src = "\
User globaluser
IdentitiesOnly yes
Host gw
  Port 2222
";
        let cfg = SshClientConfig::parse(src).unwrap();
        let eff = cfg.lookup("gw");
        assert_eq!(eff.user.as_deref(), Some("globaluser"));
        assert_eq!(eff.port, Some(2222));
        assert_eq!(eff.identities_only, Some(true));
    }

    #[test]
    fn first_match_wins_for_scalars() {
        // Two matching blocks; the FIRST set wins.
        let src = "\
Host *.example.com
  User firstuser
Host *
  User otheruser
";
        let cfg = SshClientConfig::parse(src).unwrap();
        let eff = cfg.lookup("host.example.com");
        assert_eq!(eff.user.as_deref(), Some("firstuser"));
    }

    #[test]
    fn identity_files_cumulative() {
        let src = "\
Host *
  IdentityFile ~/.ssh/id_a
Host gw
  IdentityFile ~/.ssh/id_b
";
        let cfg = SshClientConfig::parse(src).unwrap();
        let eff = cfg.lookup("gw");
        assert_eq!(eff.identity_files, vec!["~/.ssh/id_a", "~/.ssh/id_b"]);
    }

    #[test]
    fn local_forward_parses() {
        let src = "\
Host gw
  LocalForward 8080 example.com:80
  LocalForward 127.0.0.1:9090 backend:443
";
        let cfg = SshClientConfig::parse(src).unwrap();
        let eff = cfg.lookup("gw");
        assert_eq!(eff.local_forwards.len(), 2);
        assert_eq!(eff.local_forwards[0].bind_addr, None);
        assert_eq!(eff.local_forwards[0].listen_port, 8080);
        assert_eq!(eff.local_forwards[0].remote_host, "example.com");
        assert_eq!(eff.local_forwards[0].remote_port, 80);
        assert_eq!(
            eff.local_forwards[1].bind_addr.as_deref(),
            Some("127.0.0.1")
        );
        assert_eq!(eff.local_forwards[1].listen_port, 9090);
    }

    #[test]
    fn ipv6_bracketed_bind() {
        let src = "\
Host gw
  LocalForward [::1]:8080 example.com:80
";
        let cfg = SshClientConfig::parse(src).unwrap();
        let eff = cfg.lookup("gw");
        assert_eq!(eff.local_forwards[0].bind_addr.as_deref(), Some("::1"));
        assert_eq!(eff.local_forwards[0].listen_port, 8080);
    }

    #[test]
    fn negated_host_excludes() {
        let src = "\
Host *.example.com !secret.example.com
  User foo
";
        let cfg = SshClientConfig::parse(src).unwrap();
        assert_eq!(cfg.lookup("ok.example.com").user.as_deref(), Some("foo"));
        assert_eq!(cfg.lookup("secret.example.com").user, None);
    }

    #[test]
    fn unknown_keyword_errors() {
        let src = "Host gw\n  NoSuchOption 9\n";
        let err = SshClientConfig::parse(src).unwrap_err();
        match err {
            ConfigError::UnknownKeyword { keyword, line } => {
                assert_eq!(keyword, "nosuchoption");
                assert_eq!(line, 2);
            }
            _ => panic!("wrong error: {err:?}"),
        }
    }

    /// Ubuntu's stock `ssh_config` and other common OpenSSH keywords parse.
    #[test]
    fn openssh_keywords_accepted() {
        let src = "Host *\n\
            \x20   SendEnv LANG LC_*\n\
            \x20   HashKnownHosts yes\n\
            \x20   GSSAPIAuthentication yes\n\
            \x20   CheckHostIP no\n\
            \x20   VisualHostKey yes\n\
            \x20   UpdateHostKeys yes\n\
            \x20   Tunnel no\n\
            \x20   ChallengeResponseAuthentication no\n\
            \x20   RevokedHostKeys /etc/ssh/ssh_revoked_hosts\n\
            \x20   HostKeyAlias gateway\n\
            \x20   EscapeChar ^]\n\
            \x20   PasswordAuthentication no\n\
            \x20   SessionType none\n\
            \x20   GlobalKnownHostsFile /etc/a /etc/b\n\
            \x20   ConnectionAttempts 3\n";
        let cfg = SshClientConfig::parse(src).unwrap();
        let o = cfg.lookup("example.com");
        assert_eq!(o.kbd_interactive_authentication, Some(false));
        assert_eq!(o.password_authentication, Some(false));
        assert_eq!(
            o.revoked_host_keys.as_deref(),
            Some("/etc/ssh/ssh_revoked_hosts")
        );
        assert_eq!(o.host_key_alias.as_deref(), Some("gateway"));
        assert_eq!(o.escape_char, Some(Some(0x1d)));
        assert_eq!(o.session_type, Some(SessionType::None));
        assert_eq!(
            o.global_known_hosts_files,
            Some(vec!["/etc/a".to_string(), "/etc/b".to_string()])
        );
        assert_eq!(o.connection_attempts, Some(3));
    }

    /// `PKCS11Provider` and `SecurityKeyProvider` are taken as given.
    #[test]
    fn token_providers_parse() {
        let cfg = SshClientConfig::parse(
            "PKCS11Provider /usr/lib/opensc-pkcs11.so\nSecurityKeyProvider internal\n",
        )
        .unwrap();
        let o = cfg.lookup("h");
        assert_eq!(
            o.pkcs11_provider.as_deref(),
            Some("/usr/lib/opensc-pkcs11.so")
        );
        assert_eq!(o.security_key_provider.as_deref(), Some("internal"));
    }

    /// Ignored keywords whose value would change behaviour are refused.
    #[test]
    fn unsupported_values_refused() {
        for src in ["EnableSSHKeysign yes\n"] {
            assert!(
                matches!(
                    SshClientConfig::parse(src),
                    Err(ConfigError::Unsupported { .. })
                ),
                "{src}"
            );
        }
    }

    /// The keywords OpenSSH's client acts on, with its value checks.
    #[test]
    fn client_keywords_parse_as_openssh() {
        let cfg = SshClientConfig::parse(
            "CheckHostIP yes\nVerifyHostKeyDNS ask\nVisualHostKey yes\n\
             NoHostAuthenticationForLocalhost yes\nFingerprintHash md5\n\
             BindInterface eth0\nIPQoS af21\nForwardX11Timeout 1h\n\
             XAuthLocation /opt/xauth\n\
             CanonicalizePermittedCNAMEs *.a.example:*.b.example *\n\
             ChannelTimeout session=5m global=0\nLogVerbose kex.c:*:1000 x.c:*\n\
             SyslogFacility local3\nStreamLocalBindMask 022\nStreamLocalBindUnlink yes\n\
             RequiredRSASize 3072\nProxyUseFdpass yes\nKbdInteractiveDevices pam\n\
             WarnWeakCrypto no-pq-kex\nVersionAddendum hello there\n\
             Tunnel ethernet\nTunnelDevice 1:2\nEnableEscapeCommandline yes\n",
        )
        .unwrap();
        let o = cfg.lookup("h");
        assert_eq!(o.check_host_ip, Some(true));
        assert_eq!(o.verify_host_key_dns, Some(VerifyHostKeyDns::Ask));
        assert_eq!(o.visual_host_key, Some(true));
        assert_eq!(o.no_host_authentication_for_localhost, Some(true));
        assert_eq!(o.fingerprint_hash.as_deref(), Some("MD5"));
        assert_eq!(o.bind_interface.as_deref(), Some("eth0"));
        assert_eq!(o.ip_qos, Some((0x48, 0x48)));
        assert_eq!(o.forward_x11_timeout, Some(3600));
        assert_eq!(o.xauth_location.as_deref(), Some("/opt/xauth"));
        assert_eq!(
            o.canonicalize_permitted_cnames,
            Some(vec![
                ("*.a.example".to_string(), "*.b.example".to_string()),
                ("*".to_string(), "*".to_string()),
            ])
        );
        assert_eq!(
            o.channel_timeouts,
            Some(vec!["session=5m".to_string(), "global=0".to_string()])
        );
        // Only the first pattern counts, as in OpenSSH.
        assert_eq!(o.log_verbose, Some(vec!["kex.c:*:1000".to_string()]));
        assert_eq!(o.syslog_facility.as_deref(), Some("LOCAL3"));
        assert_eq!(o.stream_local_bind_mask, Some(0o22));
        assert_eq!(o.stream_local_bind_unlink, Some(true));
        assert_eq!(o.required_rsa_size, Some(3072));
        assert_eq!(o.proxy_use_fdpass, Some(true));
        assert_eq!(o.kbd_interactive_devices.as_deref(), Some("pam"));
        assert_eq!(o.warn_weak_crypto, Some(false));
        assert_eq!(o.version_addendum.as_deref(), Some("hello there"));
        assert_eq!(o.tunnel.as_deref(), Some("ethernet"));
        assert_eq!(o.tunnel_device.as_deref(), Some("1:2"));
        assert_eq!(o.enable_escape_commandline, Some(true));
        assert!(o.unimplemented.is_empty(), "{:?}", o.unimplemented);

        for bad in [
            "Tunnel maybe\n",
            "IPQoS af99\n",
            "IPQoS 256\n",
            "IPQoS ef cs0 af11\n",
            "FingerprintHash crc32\n",
            "SyslogFacility kern\n",
            "StreamLocalBindMask 0999\n",
            "ChannelTimeout session\n",
            "ChannelTimeout none session=1\n",
            "CanonicalizePermittedCNAMEs a.example\n",
            "VerifyHostKeyDNS maybe\n",
            "WarnWeakCrypto maybe\n",
            "RefuseConnection\n",
        ] {
            assert!(
                matches!(
                    SshClientConfig::parse(bad),
                    Err(ConfigError::BadValue { .. })
                ),
                "{bad}"
            );
        }
    }

    /// OpenSSH's older names still work.
    #[test]
    fn obsolete_aliases() {
        let o =
            SshClientConfig::parse("KeepAlive no\nIdentityFile2 ~/.ssh/k\nTISAuthentication no\n")
                .unwrap()
                .lookup("h");
        assert_eq!(o.tcp_keep_alive, Some(false));
        assert_eq!(o.identity_files, vec!["~/.ssh/k".to_string()]);
        assert_eq!(o.kbd_interactive_authentication, Some(false));
        let o = SshClientConfig::parse("SkeyAuthentication yes\n")
            .unwrap()
            .lookup("h");
        assert_eq!(o.kbd_interactive_authentication, Some(true));
    }

    /// `RefuseConnection` in a matching block (only) refuses, naming the
    /// line; `none` values of the list keywords are empty lists.
    #[test]
    fn refuse_connection_and_none_lists() {
        let cfg = SshClientConfig::parse(
            "Host a\n  RefuseConnection \"not today\"\nHost *\n  ChannelTimeout none\n  \
             CanonicalizePermittedCNAMEs none\n  IPQoS none throughput\n  \
             VersionAddendum none\n",
        )
        .unwrap();
        assert_eq!(
            cfg.lookup("a").refuse_connection.as_deref(),
            Some("line 2: RefuseConnection: not today")
        );
        let o = cfg.lookup("b");
        assert_eq!(o.refuse_connection, None);
        assert_eq!(o.channel_timeouts, Some(Vec::new()));
        assert_eq!(o.canonicalize_permitted_cnames, Some(Vec::new()));
        assert_eq!(o.ip_qos, Some((IPQOS_NONE, IPQOS_NONE)));
        assert_eq!(o.version_addendum.as_deref(), Some(""));
        assert_eq!(ipqos_name(0xb8), "ef");
        assert_eq!(ipqos_name(16), "0x10");
        assert_eq!(
            parse_channel_timeout("x11-*=1m"),
            Some(("x11-*".into(), 60))
        );
    }

    #[test]
    fn ignore_unknown_applies_to_later_lines() {
        assert!(SshClientConfig::parse("UseFoo yes\nIgnoreUnknown UseFoo\n").is_err());
        let cfg = SshClientConfig::parse("IgnoreUnknown Use*,Bar\nUseFoo yes\nHost x\n  Bar 1\n");
        assert!(cfg.is_ok(), "{cfg:?}");
        assert!(SshClientConfig::parse("IgnoreUnknown Bar\nBaz 1\n").is_err());
    }

    #[test]
    fn escape_char_forms() {
        assert_eq!(parse_escape_char("none"), Some(None));
        assert_eq!(parse_escape_char("~"), Some(Some(b'~')));
        assert_eq!(parse_escape_char("^A"), Some(Some(1)));
        assert_eq!(parse_escape_char("ab"), None);
    }

    #[test]
    fn strict_host_key_values() {
        for (s, want) in [
            ("yes", StrictMode::Yes),
            ("no", StrictMode::No),
            ("off", StrictMode::No),
            ("accept-new", StrictMode::AcceptNew),
            ("ask", StrictMode::Ask),
        ] {
            let src = format!("StrictHostKeyChecking {s}\n");
            let cfg = SshClientConfig::parse(&src).unwrap();
            assert_eq!(cfg.lookup("anything").strict_host_key, Some(want));
        }
    }

    #[test]
    fn request_tty_values() {
        for (s, want) in [
            ("no", RequestTty::No),
            ("yes", RequestTty::Yes),
            ("force", RequestTty::Force),
            ("auto", RequestTty::Auto),
        ] {
            let src = format!("RequestTTY {s}\n");
            let cfg = SshClientConfig::parse(&src).unwrap();
            assert_eq!(cfg.lookup("anything").request_tty, Some(want));
        }
    }

    #[test]
    fn equals_separator_accepted() {
        let src = "Host gw\n  Port=2222\n";
        let cfg = SshClientConfig::parse(src).unwrap();
        assert_eq!(cfg.lookup("gw").port, Some(2222));
    }

    // ----- W4 modern-keyword tests --------------------------------------

    #[cfg(feature = "compress")]
    #[test]
    fn compression_parses_with_feature() {
        let cfg = SshClientConfig::parse("Compression yes\n").unwrap();
        assert_eq!(cfg.lookup("h").compression, Some(true));
        let cfg = SshClientConfig::parse("Compression no\n").unwrap();
        assert_eq!(cfg.lookup("h").compression, Some(false));
    }

    #[cfg(not(feature = "compress"))]
    #[test]
    fn compression_yes_unsupported_without_feature() {
        // `Compression no` still parses (nothing to honour); `yes` rejects.
        let cfg = SshClientConfig::parse("Compression no\n").unwrap();
        assert_eq!(cfg.lookup("h").compression, Some(false));
        let err = SshClientConfig::parse("Compression yes\n").unwrap_err();
        assert!(matches!(err, ConfigError::Unsupported { .. }));
    }

    #[test]
    fn set_env_parses_multiple() {
        let src = "Host gw\n  SetEnv FOO=bar BAZ=qux\n  SetEnv LANG=C\n";
        let cfg = SshClientConfig::parse(src).unwrap();
        let eff = cfg.lookup("gw");
        assert_eq!(
            eff.set_env,
            vec![
                ("FOO".to_string(), "bar".to_string()),
                ("BAZ".to_string(), "qux".to_string()),
                ("LANG".to_string(), "C".to_string()),
            ]
        );
    }

    #[test]
    fn set_env_rejects_missing_equals() {
        let err = SshClientConfig::parse("SetEnv NOTANENV\n").unwrap_err();
        assert!(matches!(err, ConfigError::BadValue { .. }));
    }

    #[test]
    fn send_env_parses() {
        let src = "Host gw\n  SendEnv LANG LC_*\n  SendEnv TERM\n";
        let cfg = SshClientConfig::parse(src).unwrap();
        assert_eq!(cfg.lookup("gw").send_env, vec!["LANG", "LC_*", "TERM"]);
    }

    #[test]
    fn connect_timeout_takes_times_and_none() {
        let t = |s: &str| {
            SshClientConfig::parse(&format!("ConnectTimeout {s}\n"))
                .map(|c| c.lookup("h").connect_timeout)
        };
        assert_eq!(t("10").unwrap(), Some(10));
        assert_eq!(t("1m30s").unwrap(), Some(90));
        assert_eq!(t("2h").unwrap(), Some(7200));
        // `none` (and 0): no timeout, kept so a later line cannot set one.
        assert_eq!(t("none").unwrap(), Some(0));
        assert!(matches!(t("10x"), Err(ConfigError::BadValue { .. })));
    }

    #[test]
    fn server_alive_parses() {
        let src = "ServerAliveInterval 15\nServerAliveCountMax 4\n";
        let cfg = SshClientConfig::parse(src).unwrap();
        let eff = cfg.lookup("h");
        assert_eq!(eff.server_alive_interval, Some(15));
        assert_eq!(eff.server_alive_count_max, Some(4));
    }

    #[test]
    fn knock_keywords_parse() {
        let cfg = SshClientConfig::parse(
            "Host a\n KnockMode always\n KnockFallbackDelay 250\n KnockPort 2222\n\
             Host *\n KnockMode no\n",
        )
        .unwrap();
        let a = cfg.lookup("a");
        assert_eq!(a.knock_mode, Some(KnockSetting::Always));
        assert_eq!(a.knock_fallback_delay, Some(250));
        assert_eq!(a.knock_port, Some(2222));
        assert_eq!(cfg.lookup("b").knock_mode, Some(KnockSetting::No));
        assert!(SshClientConfig::parse("KnockMode maybe\n").is_err());
        assert!(SshClientConfig::parse("KnockPort 0\n").is_err());
    }

    #[test]
    fn tcp_keep_alive_parses() {
        let cfg = SshClientConfig::parse("TCPKeepAlive no\n").unwrap();
        assert_eq!(cfg.lookup("h").tcp_keep_alive, Some(false));
    }

    #[test]
    fn add_keys_to_agent_yes_no() {
        assert_eq!(
            SshClientConfig::parse("AddKeysToAgent yes\n")
                .unwrap()
                .lookup("h")
                .add_keys_to_agent,
            Some(true)
        );
        assert_eq!(
            SshClientConfig::parse("AddKeysToAgent no\n")
                .unwrap()
                .lookup("h")
                .add_keys_to_agent,
            Some(false)
        );
    }

    #[test]
    fn add_keys_to_agent_confirm_unsupported() {
        for v in ["confirm", "ask"] {
            let err = SshClientConfig::parse(&format!("AddKeysToAgent {v}\n")).unwrap_err();
            assert!(
                matches!(err, ConfigError::Unsupported { .. }),
                "expected Unsupported for {v}, got {err:?}"
            );
        }
    }

    #[test]
    fn preferred_authentications_parses_and_orders() {
        let cfg = SshClientConfig::parse("PreferredAuthentications password,publickey\n").unwrap();
        assert_eq!(
            cfg.lookup("h").preferred_authentications.as_deref(),
            Some(&["password".to_string(), "publickey".to_string()][..])
        );
    }

    #[test]
    fn preferred_authentications_accepts_any_method_like_openssh() {
        // Ansible's default list; methods we lack are just never tried.
        let cfg = SshClientConfig::parse(
            "PreferredAuthentications gssapi-with-mic,gssapi-keyex,hostbased,publickey\n",
        )
        .unwrap();
        assert_eq!(
            cfg.lookup("h").preferred_authentications.unwrap(),
            ["gssapi-with-mic", "gssapi-keyex", "hostbased", "publickey"]
        );
        assert!(SshClientConfig::parse("PreferredAuthentications hostbased\n").is_ok());
    }

    #[test]
    fn pubkey_authentication_parses() {
        let cfg = SshClientConfig::parse("PubkeyAuthentication no\n").unwrap();
        assert_eq!(cfg.lookup("h").pubkey_authentication, Some(false));
    }

    #[test]
    fn number_of_password_prompts_and_batchmode() {
        let cfg = SshClientConfig::parse("NumberOfPasswordPrompts 1\nBatchMode yes\n").unwrap();
        let eff = cfg.lookup("h");
        assert_eq!(eff.number_of_password_prompts, Some(1));
        assert_eq!(eff.batch_mode, Some(true));
    }

    #[test]
    fn exit_on_forward_failure_and_clear_all() {
        let cfg =
            SshClientConfig::parse("ExitOnForwardFailure yes\nClearAllForwardings yes\n").unwrap();
        let eff = cfg.lookup("h");
        assert_eq!(eff.exit_on_forward_failure, Some(true));
        assert_eq!(eff.clear_all_forwardings, Some(true));
    }

    #[test]
    fn dynamic_forward_parses() {
        let src = "Host gw\n  DynamicForward 1080\n  DynamicForward 127.0.0.1:1081\n";
        let cfg = SshClientConfig::parse(src).unwrap();
        let eff = cfg.lookup("gw");
        assert_eq!(eff.dynamic_forwards.len(), 2);
        assert_eq!(eff.dynamic_forwards[0].bind_addr, None);
        assert_eq!(eff.dynamic_forwards[0].listen_port, 1080);
        assert_eq!(
            eff.dynamic_forwards[1].bind_addr.as_deref(),
            Some("127.0.0.1")
        );
        assert_eq!(eff.dynamic_forwards[1].listen_port, 1081);
    }

    #[test]
    fn gateway_ports_parses() {
        for (s, want) in [
            ("no", GatewayPorts::No),
            ("yes", GatewayPorts::Yes),
            ("clientspecified", GatewayPorts::ClientSpecified),
        ] {
            let cfg = SshClientConfig::parse(&format!("GatewayPorts {s}\n")).unwrap();
            assert_eq!(cfg.lookup("h").gateway_ports, Some(want));
        }
    }

    #[test]
    fn address_family_parses() {
        for (s, want) in [
            ("any", AddressFamily::Any),
            ("inet", AddressFamily::Inet),
            ("inet6", AddressFamily::Inet6),
        ] {
            let cfg = SshClientConfig::parse(&format!("AddressFamily {s}\n")).unwrap();
            assert_eq!(cfg.lookup("h").address_family, Some(want));
        }
        let err = SshClientConfig::parse("AddressFamily ipx\n").unwrap_err();
        assert!(matches!(err, ConfigError::BadValue { .. }));
    }

    #[test]
    fn bind_address_parses() {
        let cfg = SshClientConfig::parse("BindAddress 10.0.0.5\n").unwrap();
        assert_eq!(cfg.lookup("h").bind_address.as_deref(), Some("10.0.0.5"));
    }

    #[test]
    fn identity_agent_parses() {
        let cfg = SshClientConfig::parse("IdentityAgent none\n").unwrap();
        assert_eq!(cfg.lookup("h").identity_agent, Some(IdentityAgent::None));
        let cfg = SshClientConfig::parse("IdentityAgent /run/agent.sock\n").unwrap();
        assert_eq!(
            cfg.lookup("h").identity_agent,
            Some(IdentityAgent::Path("/run/agent.sock".to_string()))
        );
    }

    // ----- Match-block tests --------------------------------------------

    #[test]
    fn match_host_glob() {
        let src = "\
Match host *.example.com
  User alice
";
        let cfg = SshClientConfig::parse(src).unwrap();
        assert_eq!(cfg.lookup("web.example.com").user.as_deref(), Some("alice"));
        assert_eq!(cfg.lookup("web.other.com").user, None);
    }

    #[test]
    fn control_master_values() {
        let cfg = SshClientConfig::parse("Host h\n  ControlMaster auto\n").unwrap();
        assert_eq!(cfg.lookup("h").control_master, Some(ControlMaster::Auto));
        let cfg = SshClientConfig::parse("Host h\n  ControlMaster yes\n").unwrap();
        assert_eq!(cfg.lookup("h").control_master, Some(ControlMaster::Yes));
        let cfg = SshClientConfig::parse("Host h\n  ControlMaster no\n").unwrap();
        assert_eq!(cfg.lookup("h").control_master, Some(ControlMaster::No));
    }

    #[test]
    fn control_master_ask_unsupported() {
        let err = SshClientConfig::parse("Host h\n  ControlMaster ask\n").unwrap_err();
        assert!(matches!(err, ConfigError::Unsupported { .. }));
        let err = SshClientConfig::parse("Host h\n  ControlMaster autoask\n").unwrap_err();
        assert!(matches!(err, ConfigError::Unsupported { .. }));
    }

    #[test]
    fn control_master_bad_value() {
        let err = SshClientConfig::parse("Host h\n  ControlMaster maybe\n").unwrap_err();
        assert!(matches!(err, ConfigError::BadValue { .. }));
    }

    #[test]
    fn control_path_none_disables() {
        let cfg = SshClientConfig::parse("Host h\n  ControlPath none\n").unwrap();
        assert_eq!(cfg.lookup("h").control_path, None);
        let cfg = SshClientConfig::parse("Host h\n  ControlPath ~/.ssh/cm-%r@%h:%p\n").unwrap();
        assert_eq!(
            cfg.lookup("h").control_path.as_deref(),
            Some("~/.ssh/cm-%r@%h:%p")
        );
    }

    #[test]
    fn control_persist_values() {
        let p = |s: &str| {
            SshClientConfig::parse(&format!("Host h\n  ControlPersist {s}\n"))
                .unwrap()
                .lookup("h")
                .control_persist
        };
        assert_eq!(p("no"), Some(ControlPersist::No));
        assert_eq!(p("yes"), Some(ControlPersist::Yes));
        assert_eq!(p("30"), Some(ControlPersist::Seconds(30)));
        assert_eq!(p("30s"), Some(ControlPersist::Seconds(30)));
        assert_eq!(p("5m"), Some(ControlPersist::Seconds(300)));
        assert_eq!(p("2h"), Some(ControlPersist::Seconds(7200)));
        // `0` collapses to No, matching OpenSSH.
        assert_eq!(p("0"), Some(ControlPersist::No));
    }

    #[test]
    fn control_persist_bad_value() {
        let err = SshClientConfig::parse("Host h\n  ControlPersist soon\n").unwrap_err();
        assert!(matches!(err, ConfigError::BadValue { .. }));
        let err = SshClientConfig::parse("Host h\n  ControlPersist 10x\n").unwrap_err();
        assert!(matches!(err, ConfigError::BadValue { .. }));
    }

    #[test]
    fn match_negated_host() {
        let src = "\
Match host *.example.com,!internal.example.com
  User alice
";
        let cfg = SshClientConfig::parse(src).unwrap();
        assert_eq!(cfg.lookup("web.example.com").user.as_deref(), Some("alice"));
        assert_eq!(cfg.lookup("internal.example.com").user, None);
    }

    #[test]
    fn match_user_combined_with_host() {
        let src = "\
Match host *.example.com user alice
  Port 2222
";
        let cfg = SshClientConfig::parse(src).unwrap();
        // No user supplied → does not match.
        assert_eq!(cfg.lookup("web.example.com").port, None);
        // Wrong user → does not match.
        let ctx = MatchContext {
            host: "web.example.com",
            original_host: None,
            user: Some("bob"),
            local_user: None,
            ..MatchContext::default()
        };
        assert_eq!(cfg.lookup_with(ctx).port, None);
        // Right user → matches.
        let ctx = MatchContext {
            host: "web.example.com",
            original_host: None,
            user: Some("alice"),
            local_user: None,
            ..MatchContext::default()
        };
        assert_eq!(cfg.lookup_with(ctx).port, Some(2222));
    }

    #[test]
    fn match_all_matches_everything() {
        let src = "\
Match all
  Port 4242
";
        let cfg = SshClientConfig::parse(src).unwrap();
        assert_eq!(cfg.lookup("anything").port, Some(4242));
        assert_eq!(cfg.lookup("other").port, Some(4242));
    }

    #[test]
    fn match_canonical_never_matches_in_first_pass() {
        let src = "\
Match canonical
  Port 4242
";
        let cfg = SshClientConfig::parse(src).unwrap();
        assert_eq!(cfg.lookup("anything").port, None);
    }

    #[test]
    fn match_final_matches_only_in_the_final_pass() {
        let src = "\
Match final
  Port 4242
";
        let cfg = SshClientConfig::parse(src).unwrap();
        assert_eq!(cfg.lookup("anything").port, None);
        assert!(cfg.wants_final_pass());
        let ctx = MatchContext {
            host: "anything",
            final_pass: true,
            ..MatchContext::default()
        };
        assert_eq!(cfg.lookup_with(ctx).port, Some(4242));
        assert!(
            !SshClientConfig::parse("Host x\n  Port 1\n")
                .unwrap()
                .wants_final_pass()
        );
        let canonical_only = SshClientConfig::parse("Match canonical\n  Port 1\n").unwrap();
        assert!(!canonical_only.wants_final_pass());
    }

    #[test]
    fn canonicalize_options_parse() {
        let cfg = SshClientConfig::parse(
            "CanonicalizeHostname always\nCanonicalDomains Example.COM. b.org\n\
             CanonicalizeMaxDots 0\nCanonicalizeFallbackLocal no\n",
        )
        .unwrap();
        let o = cfg.lookup("h");
        assert_eq!(o.canonicalize_hostname, Some(CanonicalizeHostname::Always));
        assert_eq!(
            o.canonical_domains.as_deref(),
            Some(&["example.com".to_string(), "b.org".to_string()][..])
        );
        assert_eq!(o.canonicalize_max_dots, Some(0));
        assert_eq!(o.canonicalize_fallback_local, Some(false));
        assert!(SshClientConfig::parse("CanonicalizeHostname maybe\n").is_err());
    }

    #[test]
    fn match_exec_disabled_by_default() {
        // Even with a command that would succeed on every platform, the
        // block must be silently skipped while the default policy is in
        // effect.
        let src = "\
Match exec true
  Port 4242
";
        let cfg = SshClientConfig::parse(src).unwrap();
        assert!(!cfg.is_match_exec_enabled());
        assert_eq!(cfg.lookup("anything").port, None);
    }

    #[cfg(unix)]
    #[test]
    fn match_exec_enabled_runs_command() {
        // Use the shell builtins `true` / `false` (not the `/bin/true`
        // / `/bin/false` binaries) so the test is portable: macOS
        // runners ship coreutils-style helpers at `/usr/bin/true` and
        // recent macOS images don't carry `/bin/true` at all, so an
        // absolute path here breaks `macos-latest` in CI. The `sh -c`
        // wrapper this code routes through always resolves the
        // builtins.
        let src = "\
Match exec true
  Port 4242
";
        let cfg = SshClientConfig::parse(src).unwrap().enable_match_exec(true);
        assert!(cfg.is_match_exec_enabled());
        assert_eq!(cfg.lookup("anything").port, Some(4242));

        let src_false = "\
Match exec false
  Port 4242
";
        let cfg = SshClientConfig::parse(src_false)
            .unwrap()
            .enable_match_exec(true);
        assert_eq!(cfg.lookup("anything").port, None);
    }

    #[test]
    fn match_originalhost_uses_pre_substitution_name() {
        let src = "\
Match originalhost prod
  Port 2200
";
        let cfg = SshClientConfig::parse(src).unwrap();
        let ctx = MatchContext {
            host: "10.0.0.1",
            original_host: Some("prod"),
            user: None,
            local_user: None,
            ..MatchContext::default()
        };
        assert_eq!(cfg.lookup_with(ctx).port, Some(2200));
    }

    #[test]
    fn match_localuser() {
        let src = "\
Match localuser alice
  Port 2200
";
        let cfg = SshClientConfig::parse(src).unwrap();
        let ctx = MatchContext {
            host: "h",
            original_host: None,
            user: None,
            local_user: Some("alice"),
            ..MatchContext::default()
        };
        assert_eq!(cfg.lookup_with(ctx).port, Some(2200));
        let ctx = MatchContext {
            host: "h",
            original_host: None,
            user: None,
            local_user: Some("bob"),
            ..MatchContext::default()
        };
        assert_eq!(cfg.lookup_with(ctx).port, None);
    }

    #[test]
    fn match_block_with_settings_parses() {
        // Sanity: settings inside a Match block actually get applied when
        // the block matches.
        let src = "\
Match host gw
  HostName 10.0.0.1
  Port 2222
  User admin
";
        let cfg = SshClientConfig::parse(src).unwrap();
        let eff = cfg.lookup("gw");
        assert_eq!(eff.host_name.as_deref(), Some("10.0.0.1"));
        assert_eq!(eff.port, Some(2222));
        assert_eq!(eff.user.as_deref(), Some("admin"));
    }

    #[test]
    fn match_unknown_criterion_errors() {
        let src = "Match address 1.2.3.4\n  Port 22\n";
        let err = SshClientConfig::parse(src).unwrap_err();
        match err {
            ConfigError::BadValue { line, .. } => assert_eq!(line, 1),
            _ => panic!("wrong err: {err:?}"),
        }
    }

    #[test]
    fn match_empty_args_errors() {
        let src = "Match\n  Port 22\n";
        let err = SshClientConfig::parse(src).unwrap_err();
        match err {
            ConfigError::BadValue { line, .. } => assert_eq!(line, 1),
            _ => panic!("wrong err: {err:?}"),
        }
    }

    // ----- ObscureKeystrokeTiming tests --------------------------------

    #[test]
    fn obscure_keystroke_timing_yes_defaults_to_20ms() {
        let cfg = SshClientConfig::parse("ObscureKeystrokeTiming yes\n").unwrap();
        assert_eq!(
            cfg.lookup("h").obscure_keystroke_timing,
            Some(ObscureKeystrokeTiming::On { interval_ms: 20 })
        );
    }

    #[test]
    fn obscure_keystroke_timing_no_is_off() {
        let cfg = SshClientConfig::parse("ObscureKeystrokeTiming no\n").unwrap();
        assert_eq!(
            cfg.lookup("h").obscure_keystroke_timing,
            Some(ObscureKeystrokeTiming::Off)
        );
    }

    #[test]
    fn obscure_keystroke_timing_interval_ms_integer() {
        let cfg = SshClientConfig::parse("ObscureKeystrokeTiming interval:80\n").unwrap();
        assert_eq!(
            cfg.lookup("h").obscure_keystroke_timing,
            Some(ObscureKeystrokeTiming::On { interval_ms: 80 })
        );
    }

    #[test]
    fn obscure_keystroke_timing_interval_time_units() {
        let cases = [
            ("interval:1s", 1000),
            ("interval:500ms", 500),
            ("interval:2m", 120_000),
        ];
        for (spec, want) in cases {
            let cfg = SshClientConfig::parse(&format!("ObscureKeystrokeTiming {spec}\n")).unwrap();
            assert_eq!(
                cfg.lookup("h").obscure_keystroke_timing,
                Some(ObscureKeystrokeTiming::On { interval_ms: want }),
                "spec {spec}"
            );
        }
    }

    #[test]
    fn obscure_keystroke_timing_unset_is_none() {
        let cfg = SshClientConfig::parse("Host h\n  Port 22\n").unwrap();
        assert_eq!(cfg.lookup("h").obscure_keystroke_timing, None);
    }

    #[test]
    fn obscure_keystroke_timing_malformed_is_bad_value() {
        for bad in [
            "ObscureKeystrokeTiming maybe\n",
            "ObscureKeystrokeTiming interval:\n",
            "ObscureKeystrokeTiming interval:abc\n",
            "ObscureKeystrokeTiming interval:0\n",
            "ObscureKeystrokeTiming interval:-5\n",
            "ObscureKeystrokeTiming 80\n",
        ] {
            let err = SshClientConfig::parse(bad).unwrap_err();
            assert!(
                matches!(err, ConfigError::BadValue { .. }),
                "input {bad:?} gave {err:?}"
            );
        }
    }

    #[test]
    fn obscure_keystroke_timing_default_helpers() {
        assert!(ObscureKeystrokeTiming::default_on().is_on());
        assert_eq!(ObscureKeystrokeTiming::default_on().interval_ms(), Some(20));
        assert!(!ObscureKeystrokeTiming::Off.is_on());
        assert_eq!(ObscureKeystrokeTiming::Off.interval_ms(), None);
    }

    #[test]
    fn append_layers_user_over_system() {
        // Mimics the CLI's default search path: the user file is loaded
        // first (higher precedence) and the system file appended below it.
        let mut user = SshClientConfig::parse("Host gw\n  Port 2200\n  IdentityFile /u/key\n")
            .expect("user parses");
        let system = SshClientConfig::parse("Host gw\n  Port 22\n  IdentityFile /etc/key\n")
            .expect("system parses");
        user.append(system);
        let eff = user.lookup("gw");
        // First-match-wins scalar: the user file's Port survives.
        assert_eq!(eff.port, Some(2200));
        // Cumulative list: user entry first, then system.
        assert_eq!(eff.identity_files, vec!["/u/key", "/etc/key"]);
    }

    // ----- Include-directive tests -------------------------------------

    #[cfg(feature = "std")]
    #[test]
    fn include_unsupported_in_string_parse() {
        // parse(&str) cannot resolve Include — it should surface a friendly
        // diagnostic rather than UnknownKeyword.
        let src = "Include /etc/ssh/somefile\n";
        let err = SshClientConfig::parse(src).unwrap_err();
        match err {
            ConfigError::Unsupported { line, msg } => {
                assert_eq!(line, 1);
                assert!(msg.contains("Include"), "msg = {msg}");
            }
            _ => panic!("wrong err: {err:?}"),
        }
    }

    #[cfg(feature = "std")]
    mod include_io {
        use super::*;
        use std::io::Write;
        use std::path::PathBuf;

        struct TempDir {
            path: PathBuf,
        }
        impl TempDir {
            fn new(prefix: &str) -> Self {
                use std::time::{SystemTime, UNIX_EPOCH};
                let nanos = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map(|d| d.as_nanos())
                    .unwrap_or(0);
                let pid = std::process::id();
                let path =
                    std::env::temp_dir().join(format!("puressh-cfg-client-{prefix}-{pid}-{nanos}"));
                std::fs::create_dir_all(&path).expect("create tempdir");
                Self { path }
            }
            fn write(&self, name: &str, body: &str) -> PathBuf {
                let p = self.path.join(name);
                if let Some(parent) = p.parent() {
                    std::fs::create_dir_all(parent).expect("mkdir");
                }
                let mut f = std::fs::File::create(&p).expect("create file");
                f.write_all(body.as_bytes()).expect("write file");
                p
            }
        }
        impl Drop for TempDir {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.path);
            }
        }

        #[test]
        fn include_pulls_in_settings() {
            let dir = TempDir::new("pull");
            let leaf = dir.write("leaf.cfg", "Port 4242\n");
            let root = dir.write(
                "root.cfg",
                &format!("Host gw\n  HostName 10.0.0.1\nInclude {}\n", leaf.display()),
            );
            let cfg = SshClientConfig::load(&root).unwrap();
            // Include is inside the `Host gw` block — its Port applies to gw.
            assert_eq!(cfg.lookup("gw").port, Some(4242));
            assert_eq!(cfg.lookup("gw").host_name.as_deref(), Some("10.0.0.1"));
        }

        #[test]
        fn include_glob_pulls_all_matches() {
            let dir = TempDir::new("glob");
            dir.write("conf.d/01.cfg", "Host gw\n  Port 2001\n");
            dir.write("conf.d/02.cfg", "Host gw\n  User u2\n");
            dir.write("conf.d/03.cfg", "Host gw\n  IdentityFile /tmp/k3\n");
            dir.write("conf.d/skip.txt", "Host gw\n  Port 9999\n");
            let root = dir.write(
                "root.cfg",
                &format!("Include {}/conf.d/*.cfg\n", dir.path.display()),
            );
            let cfg = SshClientConfig::load(&root).unwrap();
            let eff = cfg.lookup("gw");
            // First-match-wins on Port → 2001 (alphabetical 01.cfg sorts
            // first under our deterministic sort).
            assert_eq!(eff.port, Some(2001));
            assert_eq!(eff.user.as_deref(), Some("u2"));
            assert_eq!(eff.identity_files, vec!["/tmp/k3"]);
        }

        #[test]
        fn include_inside_a_block_applies_only_where_the_block_does() {
            // As OpenSSH: an included file is read only where its Include
            // applies, so its blocks carry the enclosing condition too.
            let dir = TempDir::new("cond");
            dir.write("inc.cfg", "Host *\n  Port 2222\nMatch all\n  User inc\n");
            let root = dir.write(
                "root.cfg",
                &format!(
                    "Host gw\n  Include {}/inc.cfg\nHost *\n  Port 22\n",
                    dir.path.display()
                ),
            );
            let cfg = SshClientConfig::load(&root).unwrap();
            assert_eq!(cfg.lookup("gw").port, Some(2222));
            assert_eq!(cfg.lookup("gw").user.as_deref(), Some("inc"));
            assert_eq!(cfg.lookup("other").port, Some(22));
            assert_eq!(cfg.lookup("other").user, None);
        }

        #[test]
        fn include_paths_take_tokens_and_variables() {
            let dir = TempDir::new("tokens");
            dir.write("inc.gw", "Port 2022\n");
            let root = dir.write(
                "root.cfg",
                &format!("Include {}/inc.%h\n", dir.path.display()),
            );
            let cfg = SshClientConfig::load_expanding(&root, &|p| p.replace("%h", "gw")).unwrap();
            assert_eq!(cfg.lookup("gw").port, Some(2022));
        }

        #[test]
        fn include_relative_to_containing_file() {
            // root.cfg lives in dir/; Include uses a bare filename, which
            // must be resolved against dir/ (not the CWD).
            let dir = TempDir::new("relative");
            dir.write("sibling.cfg", "Host gw\n  Port 7777\n");
            let root = dir.write("root.cfg", "Include sibling.cfg\n");
            let cfg = SshClientConfig::load(&root).unwrap();
            assert_eq!(cfg.lookup("gw").port, Some(7777));
        }

        #[test]
        fn include_missing_file_warned_not_fatal() {
            let dir = TempDir::new("missing");
            let root = dir.write(
                "root.cfg",
                &format!(
                    "Host gw\n  Port 22\nInclude {}/nope.cfg\n",
                    dir.path.display()
                ),
            );
            let cfg = SshClientConfig::load(&root).expect("missing include is non-fatal");
            assert_eq!(cfg.lookup("gw").port, Some(22));
        }

        #[test]
        fn include_circular_capped_at_16_depth() {
            // file A includes file A → infinite loop guarded by depth cap.
            let dir = TempDir::new("circ");
            // Path-stable file under the temp dir.
            let p = dir.path.join("loop.cfg");
            let body = format!("Include {}\n", p.display());
            std::fs::write(&p, body).expect("write loop.cfg");
            // Reported in the file whose Include went one level too deep.
            let err = match SshClientConfig::load(&p).unwrap_err() {
                ConfigError::InFile { error, .. } => *error,
                e => e,
            };
            match err {
                ConfigError::Syntax { msg, .. } => {
                    assert!(msg.contains("max depth"), "msg = {msg}");
                }
                _ => panic!("wrong err: {err:?}"),
            }
        }

        #[test]
        fn include_load_with_base_resolves_relative() {
            let dir = TempDir::new("loadbase");
            dir.write("inner.cfg", "Host gw\n  Port 9999\n");
            let src = "Include inner.cfg\n";
            let cfg = SshClientConfig::load_with_base(src, &dir.path).unwrap();
            assert_eq!(cfg.lookup("gw").port, Some(9999));
        }

        #[test]
        fn host_block_in_included_file_ends_with_it() {
            // OpenSSH: the block open at the Include is open again after
            // the included file, even when that file opened its own.
            let dir = TempDir::new("blockend");
            dir.write("hosts.cfg", "Host db\n  Port 5432\n");
            let root = dir.write(
                "root.cfg",
                "Include hosts.cfg\nUser everyone\nHost gw\n  Include hosts.cfg\n  Port 2222\n",
            );
            let cfg = SshClientConfig::load(&root).unwrap();
            assert_eq!(cfg.lookup("gw").port, Some(2222));
            assert_eq!(cfg.lookup("other").user.as_deref(), Some("everyone"));
            assert_eq!(cfg.lookup("db").user.as_deref(), Some("everyone"));
            assert_eq!(cfg.lookup("db").port, Some(5432));
        }

        #[test]
        fn include_inside_match_block_only_applies_there() {
            // The Include sits inside a Host block — its settings should be
            // tagged onto that block, not bleed into a sibling block.
            let dir = TempDir::new("inblock");
            dir.write("only_gw.cfg", "Port 3300\n");
            let root = dir.write(
                "root.cfg",
                "Host gw\n  Include only_gw.cfg\nHost other\n  Port 22\n",
            );
            let cfg = SshClientConfig::load(&root).unwrap();
            assert_eq!(cfg.lookup("gw").port, Some(3300));
            assert_eq!(cfg.lookup("other").port, Some(22));
        }
    }
}
