//! High-level synchronous SSH client over `std::net::TcpStream`.
//!
//! ```ignore
//! use puressh::client::{Client, Config};
//!
//! let mut c = Client::connect("example.com:22", Config::insecure())?;
//! c.authenticate_password("alice", "hunter2")?;
//! let out = c.exec("uname -a")?;
//! print!("{}", String::from_utf8_lossy(&out.stdout));
//! ```

#![cfg(feature = "std")]

use std::collections::BTreeMap;
use std::io::{ErrorKind, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, Sender, TryRecvError};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use purecrypto::hash::{Digest, Sha256};
use purecrypto::rng::RngCore;

use crate::auth::{ClientAuth, ClientCredential, ClientStep};
use crate::channel::{
    ChannelEvent, ChannelOpen, ChannelRequest, ConnectionState, SSH_EXTENDED_DATA_STDERR,
    SSH_OPEN_ADMINISTRATIVELY_PROHIBITED,
};
use crate::driver::{ClientDriver, Event};
use crate::error::{Error, Result};
use crate::hostkey::{HostKey, HostKeyVerify, host_key_verify_by_name};
use crate::known_hosts::{KnownHosts, LookupResult};
use crate::sftp::SftpClient;
pub use crate::stream::{ChannelEgress, ChannelStream};
use crate::transport::kex::{defaults, is_strict_kex_marker};
use crate::transport::ping::encode_ping;
use crate::transport::{KexAlgorithmsOwned, KexInit, KexRunner};

/// Abstraction over the byte transport a [`Client`] runs on. The default is
/// a plain [`TcpStream`], but a client can also run over a proxied channel
/// (ProxyJump's `direct-tcpip` stream) or a spawned helper process's pipes
/// (ProxyCommand) — anything that is `Read + Write + Send` and can toggle a
/// read timeout.
///
/// `set_read_timeout` mirrors [`TcpStream::set_read_timeout`]: `None` clears
/// it (blocking reads). Transports that cannot honour a timeout (e.g. a pipe
/// to a child process) may implement it as a no-op `Ok(())` — callers that
/// rely on a real timeout (the serve / forwarding poll loops) must not be
/// driven over such a transport.
pub trait Transport: Read + Write + Send {
    /// Set the read timeout on the underlying transport. See
    /// [`TcpStream::set_read_timeout`].
    fn set_read_timeout(&mut self, t: Option<Duration>) -> std::io::Result<()>;
}

impl Transport for TcpStream {
    fn set_read_timeout(&mut self, t: Option<Duration>) -> std::io::Result<()> {
        TcpStream::set_read_timeout(self, t)
    }
}

/// Number of banner lines the handshake will skim through before giving up
/// (used to bound the handshake pump's iteration count). The driver does the
/// actual banner-scanning and enforces its own byte caps.
const MAX_BANNER_LINES: usize = 32;
/// Hard cap on accumulated exec stdout+stderr.
const MAX_EXEC_OUTPUT: usize = 64 * 1024 * 1024;
/// Maximum iterations for the KEX driver loop.
const MAX_KEX_STEPS: usize = 32;
/// Maximum iterations for the userauth loop.
const MAX_AUTH_STEPS: usize = 64;
/// Maximum iterations for the exec drain loop.
const MAX_EXEC_ITER: usize = 1_000_000;
/// Cap on the per-channel egress mpsc inside [`Client::serve`]. Mirrors the
/// server's `SUBSYSTEM_EGRESS_BACKLOG`: small enough to bound memory, large
/// enough to absorb a few full-window writes before the handler thread has
/// to block on its `Write::write`.
const SERVE_EGRESS_BACKLOG: usize = 32;
/// Outer-loop step cap for [`Client::serve`] — generous because each step is
/// either one packet or one 50 ms timeout tick.
const MAX_SERVE_STEPS: usize = 100_000_000;
/// Read timeout the serve loop installs on the socket while it has at least
/// one live channel runtime to drain. Reverts to blocking when idle.
const SERVE_POLL_INTERVAL: Duration = Duration::from_millis(50);

/// Policy for accepting (or rejecting) a server's host key.
pub enum HostKeyPolicy {
    /// Trust whatever the server presents — equivalent to OpenSSH's
    /// `StrictHostKeyChecking=no`. Insecure; do not use against untrusted peers.
    AcceptAny,
    /// Accept only if the server's host-key SHA-256 fingerprint (the raw 32
    /// bytes, exactly as `ssh-keygen -lf` reports them) matches.
    AcceptFingerprint([u8; 32]),
    /// Verify against an OpenSSH-format `known_hosts` store. Requires the
    /// host name + port to be threaded in via [`Client::connect_to_host`];
    /// constructors that take a bare socket address (`Client::connect`)
    /// degrade to `AcceptAny` when this variant is configured because we
    /// don't have an address-independent identifier to look up.
    ///
    /// See [`KnownHostsPolicy`] for the knobs.
    KnownHosts(KnownHostsPolicy),
}

/// Configuration for [`HostKeyPolicy::KnownHosts`].
///
/// `store` is shared (Arc + Mutex) so the binary can keep a handle to
/// inspect / persist independently of the client; the verifier itself
/// locks it just long enough to look up and optionally append a TOFU
/// entry. `save_path` (if set) is the file rewritten when a TOFU accept
/// adds a new entry; absent it, accepts stay in memory only.
pub struct KnownHostsPolicy {
    /// The in-memory store. Locked just long enough for lookup / add.
    pub store: Arc<Mutex<KnownHosts>>,
    /// File path the store is persisted to on TOFU-accept. If `None`,
    /// accepts stay in memory only (useful for tests).
    pub save_path: Option<PathBuf>,
    /// Hash new TOFU entries (OpenSSH's `HashKnownHosts yes`).
    pub hash_new: bool,
    /// What to do when the host is *unknown* (no entry matches).
    pub on_unknown: TofuAction,
    /// What to do when the host **is** known but the key does not match
    /// any stored entry. The OpenSSH-safe default (when constructed via
    /// [`KnownHostsPolicy::strict`]) is [`TofuAction::Reject`]; binaries
    /// honouring `StrictHostKeyChecking=no` can opt into
    /// [`TofuAction::AcceptWithWarning`] to keep insecure-but-loud
    /// parity with OpenSSH.
    pub on_mismatch: TofuAction,
}

impl KnownHostsPolicy {
    /// Build a policy with the OpenSSH-safe defaults: reject unknown
    /// hosts, reject mismatched keys.
    pub fn strict(store: Arc<Mutex<KnownHosts>>) -> Self {
        Self {
            store,
            save_path: None,
            hash_new: false,
            on_unknown: TofuAction::Reject,
            on_mismatch: TofuAction::Reject,
        }
    }
}

/// Callback type for [`TofuAction::Prompt`] — `(host, port, key_type,
/// key_blob) → accept?`.
pub type TofuPromptFn = dyn Fn(&str, u16, &str, &[u8]) -> bool + Send + Sync;

/// What to do when [`HostKeyPolicy::KnownHosts`] encounters an unknown
/// host or a key that doesn't match any stored entry.
pub enum TofuAction {
    /// Refuse the connection — equivalent to OpenSSH's
    /// `StrictHostKeyChecking=yes` against an empty `known_hosts`.
    Reject,
    /// Accept silently and add the entry — equivalent to
    /// `StrictHostKeyChecking=accept-new`.
    Accept,
    /// Ask the user. See [`TofuPromptFn`] for the callback signature.
    Prompt(Arc<TofuPromptFn>),
    /// Accept the connection but emit a loud warning to stderr. This is
    /// the only variant that makes sense for `on_mismatch` outside of
    /// `Reject`: it mirrors `StrictHostKeyChecking=no` in OpenSSH, which
    /// proceeds anyway after printing the
    /// `WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!` banner.
    /// Used for `on_unknown` it's silent like `Accept` but is included
    /// here for symmetry.
    AcceptWithWarning,
}

/// Client configuration knobs.
///
/// **Note**: `Config` deliberately does not implement [`Default`]. The
/// only sane default for `host_key_policy` would be
/// [`HostKeyPolicy::AcceptAny`], which is insecure (any peer with the
/// right port is trusted). Forcing callers to spell the policy out makes
/// the trust decision explicit at the call site — see [`Config::insecure`]
/// for an explicit opt-in equivalent of the old default, or
/// [`Config::with_known_hosts`] for the OpenSSH-style strict policy.
pub struct Config {
    /// How to decide whether a server's host key is acceptable.
    pub host_key_policy: HostKeyPolicy,
    /// Optional per-operation socket timeout.
    pub timeout: Option<Duration>,
    /// Optional overrides for the advertised crypto-algorithm preference
    /// lists, populated from `ssh_config` (`Ciphers`, `MACs`,
    /// `KexAlgorithms`, `HostKeyAlgorithms`, `PubkeyAcceptedAlgorithms`).
    /// `None` everywhere ⇒ use the built-in defaults.
    pub algorithms: AlgoOverrides,
}

/// Per-connection overrides for the advertised algorithm preference lists.
///
/// Each `None` field falls back to the built-in default for that category.
/// The strict-kex signalling markers are NOT represented here — they are
/// re-appended unconditionally by the KEXINIT builder after override
/// resolution, so a `KexAlgorithms` override can never disable the Terrapin
/// (CVE-2023-48795) mitigation.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AlgoOverrides {
    /// `Ciphers` — applied to both directions.
    pub ciphers: Option<Vec<String>>,
    /// `MACs` — applied to both directions.
    pub macs: Option<Vec<String>>,
    /// `KexAlgorithms` — real (non-marker) kex methods.
    pub kex_algorithms: Option<Vec<String>>,
    /// `HostKeyAlgorithms` — server host-key algorithms we will accept.
    pub host_key_algorithms: Option<Vec<String>>,
    /// `PubkeyAcceptedAlgorithms` — signature algorithms for our own
    /// publickey credentials. Consumed by the userauth driver, not KEXINIT.
    pub pubkey_accepted_algorithms: Option<Vec<String>>,
    /// `CASignatureAlgorithms` — signature algorithms accepted from a CA when
    /// verifying a host certificate. `None` ⇒ built-in default
    /// ([`crate::config::algos::CA_SIGNATURE_DEFAULTS`]).
    pub ca_signature_algorithms: Option<Vec<String>>,
    /// `Compression` — `Some(true)` advertises `zlib@openssh.com` ahead of
    /// `none` in both directions; `Some(false)` / `None` advertises `none`
    /// only. Honouring `Some(true)` requires the `compress` feature; the
    /// `ssh` binary rejects the keyword up front when the feature is absent,
    /// and the builder degrades to `none` defensively if it somehow slips
    /// through.
    pub compression: Option<bool>,
}

impl Config {
    /// Explicit, audit-friendly constructor for "trust whatever the peer
    /// presents" — the old behaviour of `Config::default()`. Replaces
    /// the removed `Default` impl so the trust decision shows up in
    /// `git grep` for `Config::insecure`.
    pub fn insecure() -> Self {
        Self {
            host_key_policy: HostKeyPolicy::AcceptAny,
            timeout: None,
            algorithms: AlgoOverrides::default(),
        }
    }

    /// Build a config that verifies the host key against `store` with
    /// OpenSSH-style strict semantics (reject unknown, reject mismatch).
    /// The caller is still responsible for routing connects through
    /// [`Client::connect_to_host`] so the verifier has a host name to
    /// look up.
    pub fn with_known_hosts(store: Arc<Mutex<KnownHosts>>) -> Self {
        Self {
            host_key_policy: HostKeyPolicy::KnownHosts(KnownHostsPolicy::strict(store)),
            timeout: None,
            algorithms: AlgoOverrides::default(),
        }
    }
}

/// Result of running `exec`.
pub struct ExecOutput {
    /// Captured stdout bytes.
    pub stdout: Vec<u8>,
    /// Captured stderr bytes (extended-data channel, code 1).
    pub stderr: Vec<u8>,
    /// Process exit status (POSIX exit code), if the server sent `exit-status`.
    pub exit_status: Option<u32>,
    /// Signal name (no `SIG` prefix), if the server sent `exit-signal`.
    pub exit_signal: Option<String>,
}

/// Origin info accompanying a server-initiated `forwarded-tcpip` channel
/// (RFC 4254 §7.2). Passed to [`ClientHandlers::on_forwarded_tcpip`] so the
/// callback can decide which local destination to splice the channel to.
///
/// The `bound_*` fields echo the address+port the server is listening on
/// (per a previous `tcpip-forward` global request); `orig_*` are the
/// remote-side socket coordinates of the peer that just connected to it.
#[derive(Debug, Clone)]
pub struct ForwardedTcpipOrigin {
    /// Address the server is listening on (typically what the client passed
    /// to [`Client::request_tcpip_forward`]).
    pub bound_address: String,
    /// Port the server is listening on.
    pub bound_port: u16,
    /// Originating peer's address (the side that just connected to the
    /// server's listener).
    pub orig_address: String,
    /// Originating peer's port.
    pub orig_port: u16,
}

/// Type alias for the [`ClientHandlers::on_forwarded_tcpip`] callback.
///
/// The handler takes ownership of a fresh [`ChannelStream`] wired to the
/// incoming channel. When it returns (or the stream drops), the channel is
/// torn down by the serve loop. Implementations typically spawn their own
/// thread or splice the stream against a local TCP destination — see
/// [`crate::forwarding::reverse`] for the server-side counterpart.
pub type ForwardedTcpipCallback =
    dyn Fn(ForwardedTcpipOrigin, ChannelStream) + Send + Sync + 'static;

/// Origin info accompanying a server-initiated `forwarded-streamlocal@openssh.com`
/// channel (OpenSSH extension; the Unix-socket analog of
/// [`ForwardedTcpipOrigin`]). Passed to
/// [`ClientHandlers::on_forwarded_streamlocal`] so the callback knows which
/// bound socket the connection arrived on.
#[derive(Debug, Clone)]
pub struct ForwardedStreamlocalOrigin {
    /// Path the server is listening on (typically what the client passed to
    /// [`Client::request_streamlocal_forward`]).
    pub socket_path: String,
}

/// Type alias for the [`ClientHandlers::on_forwarded_streamlocal`] callback.
///
/// The handler takes ownership of a fresh [`ChannelStream`] wired to the
/// incoming channel. When it returns (or the stream drops), the channel is
/// torn down by the serve loop. Implementations typically splice the stream
/// against a local Unix socket — see
/// [`crate::forwarding::streamlocal::splice_to_unix_socket_callback`].
pub type ForwardedStreamlocalCallback =
    dyn Fn(ForwardedStreamlocalOrigin, ChannelStream) + Send + Sync + 'static;

/// Type alias for the [`ClientHandlers::on_auth_agent`] callback.
///
/// Fires on every server-initiated `auth-agent@openssh.com` channel — one
/// per peer-side `SSH_AUTH_SOCK` connection. The handler typically splices
/// the stream against the local `$SSH_AUTH_SOCK` Unix socket, completing
/// the agent-forwarding round-trip (OpenSSH's `ssh -A`).
pub type AuthAgentCallback = dyn Fn(ChannelStream) + Send + Sync + 'static;

/// Type alias for the [`ClientHandlers::on_x11`] callback.
///
/// Fires on every server-initiated `x11` channel — one per peer-side X11
/// client connection that landed on the forwarded display. The handler
/// typically splices the stream against the local `$DISPLAY` (Unix domain
/// `/tmp/.X11-unix/X<N>` or TCP `host:6000+N`), completing the X11
/// forwarding round-trip (OpenSSH's `ssh -X` / `ssh -Y`).
pub type X11Callback = dyn Fn(ChannelStream) + Send + Sync + 'static;

/// Set of callbacks driving [`Client::serve`].
///
/// Each `on_*` field accepts a peer-initiated channel-open of the matching
/// type; unset callbacks make the serve loop reject opens of that type with
/// `SSH_OPEN_ADMINISTRATIVELY_PROHIBITED`. Setting [`Self::stop`] to `true`
/// asks the loop to exit at its next opportunity, after waiting for any
/// channels still active to drain naturally.
pub struct ClientHandlers {
    /// Callback for `"forwarded-tcpip"` channel opens (RFC 4254 §7.2, the
    /// inbound bookend of `ssh -R`). `None` ⇒ reject.
    pub on_forwarded_tcpip: Option<Arc<ForwardedTcpipCallback>>,
    /// Callback for `"forwarded-streamlocal@openssh.com"` channel opens
    /// (OpenSSH extension, the inbound bookend of `ssh -R /remote.sock:...`).
    /// `None` ⇒ reject.
    pub on_forwarded_streamlocal: Option<Arc<ForwardedStreamlocalCallback>>,
    /// Callback for `"auth-agent@openssh.com"` channel opens (server-side
    /// half of agent forwarding, `ssh -A`). `None` ⇒ reject.
    pub on_auth_agent: Option<Arc<AuthAgentCallback>>,
    /// Callback for `"x11"` channel opens (server-side half of X11
    /// forwarding, `ssh -X` / `ssh -Y`). `None` ⇒ reject.
    pub on_x11: Option<Arc<X11Callback>>,
    /// Cooperative stop signal. The loop polls this flag once per tick and
    /// returns `Ok(())` as soon as it's `true` AND no channels are open.
    pub stop: Arc<AtomicBool>,
    /// Inbound command channel — external threads (e.g. an `ssh -L`
    /// listener) push [`ServeCommand`]s here to ask the serve loop to open
    /// outbound channels. `None` when the loop has no associated
    /// [`ServeContext`]; the loop simply doesn't poll for outbound opens.
    cmd_rx: Option<Receiver<ServeCommand>>,
}

impl Default for ClientHandlers {
    fn default() -> Self {
        Self::new()
    }
}

impl ClientHandlers {
    /// Build an empty handler set with all callbacks unset.
    pub fn new() -> Self {
        Self {
            on_forwarded_tcpip: None,
            on_forwarded_streamlocal: None,
            on_auth_agent: None,
            on_x11: None,
            stop: Arc::new(AtomicBool::new(false)),
            cmd_rx: None,
        }
    }

    /// Install a `forwarded-tcpip` handler (`ssh -R` server-initiated opens).
    pub fn with_forwarded_tcpip(mut self, cb: Arc<ForwardedTcpipCallback>) -> Self {
        self.on_forwarded_tcpip = Some(cb);
        self
    }

    /// Install a `forwarded-streamlocal@openssh.com` handler
    /// (`ssh -R /remote.sock:...` server-initiated opens). For the default
    /// behaviour (splice each incoming channel against a local Unix socket),
    /// see [`crate::forwarding::streamlocal::splice_to_unix_socket_callback`].
    pub fn with_forwarded_streamlocal(mut self, cb: Arc<ForwardedStreamlocalCallback>) -> Self {
        self.on_forwarded_streamlocal = Some(cb);
        self
    }

    /// Install an `auth-agent@openssh.com` handler (`ssh -A` server-initiated
    /// opens). For the default behaviour (splice each incoming channel
    /// against the local `$SSH_AUTH_SOCK`), see
    /// [`crate::forwarding::agent::splice_to_local_agent_callback`].
    pub fn with_auth_agent(mut self, cb: Arc<AuthAgentCallback>) -> Self {
        self.on_auth_agent = Some(cb);
        self
    }

    /// Install an `x11` handler (`ssh -X` / `ssh -Y` server-initiated opens).
    /// For the default behaviour (splice each incoming channel against the
    /// local `$DISPLAY`), see
    /// [`crate::forwarding::x11::splice_to_local_display_callback`].
    pub fn with_x11(mut self, cb: Arc<X11Callback>) -> Self {
        self.on_x11 = Some(cb);
        self
    }

    /// Attach an outbound-command receiver and hand back a paired
    /// [`ServeContext`] that external threads can clone to request
    /// `direct-tcpip` opens against the running serve loop. Used by
    /// `ssh -L`'s per-listener accept thread.
    pub fn with_serve_context(mut self) -> (Self, ServeContext) {
        let (tx, rx) = mpsc::channel();
        self.cmd_rx = Some(rx);
        (self, ServeContext { cmd_tx: tx })
    }
}

/// Command an external thread sends to [`Client::serve`] via a
/// [`ServeContext`]. Currently the only variant is outbound `direct-tcpip`
/// open; future ones (e.g. agent-channel open for Phase 8) plug in the same
/// way.
pub enum ServeCommand {
    /// Open a `direct-tcpip` channel; on confirmation, send the resulting
    /// [`ChannelStream`] back through `reply`. On peer rejection, send
    /// `Err`.
    OpenDirectTcpip {
        /// Where the *server* should connect to (the `dest_host:dest_port`
        /// pair on the wire). For `ssh -L LPORT:RHOST:RPORT`, this is
        /// `RHOST:RPORT`.
        dest_host: String,
        /// Destination port the server should dial.
        dest_port: u16,
        /// Informational source-address echoed in the open. For
        /// `ssh -L`-style use, the client's accept address (e.g.
        /// `127.0.0.1`).
        orig_host: String,
        /// Informational source-port echoed in the open.
        orig_port: u16,
        /// Where to deliver the open's outcome — `Ok(stream)` on
        /// `OpenConfirmed`, `Err` on `OpenFailed` or loop teardown.
        reply: mpsc::SyncSender<Result<ChannelStream>>,
    },
    /// Open a `direct-streamlocal@openssh.com` channel; on confirmation, send
    /// the resulting [`ChannelStream`] back through `reply`. On peer
    /// rejection, send `Err`.
    OpenDirectStreamlocal {
        /// Unix-socket path the *server* should connect to.
        socket_path: String,
        /// Where to deliver the open's outcome.
        reply: mpsc::SyncSender<Result<ChannelStream>>,
    },
}

/// Handle external threads use to drive the running [`Client::serve`] loop.
///
/// Returned by [`ClientHandlers::with_serve_context`] and cloned freely
/// across the listener / accept threads that need to open outbound
/// `direct-tcpip` channels (`ssh -L`).
#[derive(Clone)]
pub struct ServeContext {
    cmd_tx: Sender<ServeCommand>,
}

impl ServeContext {
    /// Request a `direct-tcpip` channel from inside a running serve loop
    /// and block until the peer either confirms or rejects. Mirrors
    /// [`Client::open_direct_tcpip`] but works while `serve` is driving
    /// the socket — there's no other way to interleave the open with
    /// inbound traffic on the same client.
    ///
    /// Returns `Err(Error::Protocol(_))` if the serve loop has already
    /// returned (the receiver hung up).
    pub fn open_direct_tcpip(
        &self,
        dest_host: &str,
        dest_port: u16,
        orig_host: &str,
        orig_port: u16,
    ) -> Result<ChannelStream> {
        let (reply_tx, reply_rx) = mpsc::sync_channel::<Result<ChannelStream>>(1);
        self.cmd_tx
            .send(ServeCommand::OpenDirectTcpip {
                dest_host: dest_host.to_string(),
                dest_port,
                orig_host: orig_host.to_string(),
                orig_port,
                reply: reply_tx,
            })
            .map_err(|_| Error::Protocol("serve loop terminated"))?;
        reply_rx
            .recv()
            .map_err(|_| Error::Protocol("serve loop terminated"))?
    }

    /// Request a `direct-streamlocal@openssh.com` channel from inside a
    /// running serve loop and block until the peer confirms or rejects.
    /// Mirrors [`Self::open_direct_tcpip`] but for a Unix-socket destination
    /// (the wire side of `ssh -L local:/remote.sock`).
    ///
    /// Returns `Err(Error::Protocol(_))` if the serve loop has already
    /// returned (the receiver hung up).
    pub fn open_direct_streamlocal(&self, socket_path: &str) -> Result<ChannelStream> {
        let (reply_tx, reply_rx) = mpsc::sync_channel::<Result<ChannelStream>>(1);
        self.cmd_tx
            .send(ServeCommand::OpenDirectStreamlocal {
                socket_path: socket_path.to_string(),
                reply: reply_tx,
            })
            .map_err(|_| Error::Protocol("serve loop terminated"))?;
        reply_rx
            .recv()
            .map_err(|_| Error::Protocol("serve loop terminated"))?
    }
}

/// Per-channel state for an outbound channel open we've asked the serve
/// loop to drive: waiting for `OpenConfirmed` / `OpenFailed`.
struct PendingOutboundOpen {
    /// Pre-built stream handed to the caller on `OpenConfirmed`.
    stream: Option<ChannelStream>,
    /// Pre-built ingress sender; moves into the [`ServeRuntime`] on
    /// `OpenConfirmed`.
    ingress_tx: Sender<Option<Vec<u8>>>,
    /// Pre-built egress receiver; moves into the [`ServeRuntime`] on
    /// `OpenConfirmed`.
    egress_rx: Option<Receiver<ChannelEgress>>,
    /// Where to deliver the final result.
    reply: mpsc::SyncSender<Result<ChannelStream>>,
}

/// Per-channel state for an in-process handler running underneath
/// [`Client::serve`]. Parallel to the server's `SubsystemRuntime` —
/// dispatcher-side mailbox for one open channel.
struct ServeRuntime {
    /// Push peer-sent bytes (or `None` for EOF) to the handler thread.
    /// Unbounded so the dispatcher never blocks on its own dispatch path —
    /// memory is bounded by the SSH receive window.
    ingress_tx: Sender<Option<Vec<u8>>>,
    /// Drain bytes the handler wants to ship out.
    egress_rx: Receiver<ChannelEgress>,
    /// Egress data that didn't fit in the remote window on the last tick;
    /// re-tried before pulling more from `egress_rx`.
    pending_data: Vec<u8>,
    /// EOF has been pulled from the handler but not yet emitted on the wire.
    pending_eof: bool,
    /// Close has been pulled from the handler but not yet emitted on the wire.
    pending_close: bool,
    /// Whether we've already sent `CHANNEL_EOF` on the wire.
    eof_sent: bool,
    /// Whether we've already sent `CHANNEL_CLOSE` on the wire.
    close_sent: bool,
}

/// A blocking SSH client.
pub struct Client {
    stream: Box<dyn Transport>,
    /// Connection multiplexer (channel bookkeeping). The frontend owns this:
    /// the sans-IO [`ClientDriver`] surfaces decoded application payloads
    /// (post-auth), which we feed into `conn`, and we hand `conn`'s
    /// channel-protocol output back to the driver to encode and queue.
    pub(crate) conn: ConnectionState,
    /// Transport + authentication engine: version exchange, key exchange,
    /// re-key, EXT_INFO/PING handling, and the userauth state machine, all
    /// sans-IO. The frontend pumps it via `write_payload` / `read_one_packet`.
    driver: ClientDriver,
    /// Algorithm-preference overrides from config. Retained for the auth
    /// driver's PubkeyAcceptedAlgorithms / server-sig-algs policy.
    algo_overrides: AlgoOverrides,
    /// When `true`, every session-channel helper ([`Self::exec`],
    /// [`Self::exec_stream`], [`Self::shell_with_stdin`], [`Self::sftp`])
    /// issues `auth-agent-req@openssh.com` immediately after the open and
    /// before the matching shell/exec/subsystem request. Toggle with
    /// [`Self::set_request_auth_agent_forwarding`].
    request_auth_agent: bool,
    /// When `Some`, every session-channel helper issues `x11-req`
    /// immediately after the open and before the matching
    /// shell/exec/subsystem request. Toggle with
    /// [`Self::set_request_x11_forwarding`]. Carries the wire arguments —
    /// `single_connection`, `auth_protocol`, `auth_cookie`, `screen` —
    /// captured at toggle time.
    request_x11: Option<X11ReqArgs>,
    /// Environment variables to emit as `env` channel requests on every
    /// subsequent session-channel helper, between the open and the matching
    /// shell/exec request. Populated from `SetEnv` / `SendEnv`. Each pair is
    /// sent with `want_reply = false` (matching OpenSSH); the server applies
    /// its `AcceptEnv` filter silently.
    session_env: Vec<(String, String)>,
    /// Keepalive policy for [`Self::serve`]: `Some((interval, count_max))`
    /// sends a `keepalive@openssh.com` global request (with `want_reply`)
    /// after `interval` of silence, tearing the connection down once
    /// `count_max` probes go unanswered (`ServerAliveInterval` /
    /// `ServerAliveCountMax`). `None` ⇒ no keepalive.
    keepalive: Option<(Duration, u32)>,
    /// When `Some`, the next `exec` helper allocates a PTY before issuing the
    /// `exec` request — used by `RequestTTY force`/`yes` so a remote command
    /// runs under a terminal. Carries the `pty-req` wire arguments. The
    /// interactive shell path passes its PTY parameters directly, so this
    /// toggle is only consulted by [`Self::exec`].
    request_pty: Option<PtyReqArgs>,
    /// Outstanding reverse-forward grants: the set of `(bind_address,
    /// bind_port)` pairs for which [`Self::request_tcpip_forward`] succeeded
    /// and which have not been cancelled via [`Self::cancel_tcpip_forward`].
    ///
    /// Used as a defence-in-depth filter in [`serve`](Self::serve): a
    /// server-initiated `forwarded-tcpip` channel-open must correlate to a
    /// forward the client actually requested. Because the server may echo a
    /// bind address that differs textually from the one requested (e.g.
    /// `0.0.0.0` for an empty/`localhost` request) and `bind_port == 0`
    /// resolves to a server-assigned port, the matching here is
    /// deliberately conservative: the library only *rejects* a
    /// `forwarded-tcpip` open when there are **zero** outstanding grants —
    /// i.e. an unsolicited forward when the client never asked for any.
    /// Callers that need exact per-binding correlation (as the shipped
    /// `ssh` binary does) should keep doing it in their
    /// `on_forwarded_tcpip` callback.
    tcpip_forward_grants: Vec<(String, u16)>,
    /// Outstanding reverse streamlocal-forward grants: socket paths for which
    /// [`Self::request_streamlocal_forward`] succeeded and which have not been
    /// cancelled via [`Self::cancel_streamlocal_forward`]. Used as the same
    /// conservative defence-in-depth filter as [`Self::tcpip_forward_grants`]:
    /// a `forwarded-streamlocal@openssh.com` open is rejected only when there
    /// are **zero** outstanding grants.
    streamlocal_forward_grants: Vec<String>,
}

/// Wire arguments captured by [`Client::set_request_x11_forwarding`] and
/// emitted as the body of each `x11-req` channel request.
#[derive(Clone)]
struct X11ReqArgs {
    single_connection: bool,
    auth_protocol: String,
    auth_cookie: String,
    screen: u32,
}

/// Wire arguments captured by [`Client::set_request_pty`] and emitted as the
/// body of a `pty-req` channel request ahead of an `exec` (RequestTTY force).
#[derive(Clone)]
struct PtyReqArgs {
    term: String,
    cols: u32,
    rows: u32,
    px_w: u32,
    px_h: u32,
    modes: Vec<u8>,
}

impl Client {
    /// Connect, complete version exchange + KEX + NEWKEYS, leave the codec keyed
    /// and ready for userauth.
    pub fn connect<A: ToSocketAddrs>(addr: A, cfg: Config) -> Result<Self> {
        let stream = TcpStream::connect(addr)?;
        if let Some(t) = cfg.timeout {
            stream.set_read_timeout(Some(t))?;
            stream.set_write_timeout(Some(t))?;
        }
        stream.set_nodelay(true)?;
        Self::from_transport(Box::new(stream), "", 0, cfg)
    }

    /// Like [`Self::connect`], but threads the user-supplied host name and
    /// port through so [`HostKeyPolicy::KnownHosts`] has something stable
    /// to look up. Use this instead of `connect` whenever the host key
    /// policy reads `known_hosts` — `connect` accepts any `ToSocketAddrs`
    /// (including `IpAddr`) and so cannot recover the original hostname.
    pub fn connect_to_host(host: &str, port: u16, cfg: Config) -> Result<Self> {
        let stream = TcpStream::connect((host, port))?;
        if let Some(t) = cfg.timeout {
            stream.set_read_timeout(Some(t))?;
            stream.set_write_timeout(Some(t))?;
        }
        stream.set_nodelay(true)?;
        Self::from_transport(Box::new(stream), host, port, cfg)
    }

    /// Run a client over an arbitrary [`Transport`] (rather than a fresh
    /// [`TcpStream`]). Used by ProxyJump (a `direct-tcpip` channel to the
    /// next hop) and ProxyCommand (pipes to a spawned helper). `host`/`port`
    /// name the *target reached through* the transport so per-hop host-key
    /// checks (`KnownHosts`) key off the right name. The caller is
    /// responsible for any timeouts on the transport.
    pub fn connect_via(
        stream: Box<dyn Transport>,
        host: &str,
        port: u16,
        cfg: Config,
    ) -> Result<Self> {
        Self::from_transport(stream, host, port, cfg)
    }

    /// Shared construction: build the [`Client`] struct over `stream`,
    /// recording `host`/`port` for host-key lookups, then run version
    /// exchange + KEX. `host` may be empty (e.g. plain `connect`), in which
    /// case `KnownHosts` policy degrades to AcceptAny.
    fn from_transport(
        stream: Box<dyn Transport>,
        host: &str,
        port: u16,
        cfg: Config,
    ) -> Result<Self> {
        // Host-key verification is injected into the sans-IO driver as a
        // closure, capturing the policy + target so the driver stays free of
        // known-hosts I/O / prompting. Called on each `SSH_MSG_KEX_ECDH_REPLY`
        // (initial and re-key).
        let host_key_policy = cfg.host_key_policy;
        let target_host = host.to_string();
        let ca_sig_algos = cfg.algorithms.ca_signature_algorithms.clone();
        let verifier_factory: crate::driver::client::VerifierFactory =
            Box::new(move |reply: &[u8], runner: &KexRunner| {
                build_verifier(
                    reply,
                    &host_key_policy,
                    runner,
                    &target_host,
                    port,
                    ca_sig_algos.as_deref(),
                    unix_now(),
                )
            });
        let driver = ClientDriver::new(cfg.algorithms.clone(), verifier_factory);
        let mut me = Self {
            stream,
            conn: ConnectionState::new(),
            driver,
            algo_overrides: cfg.algorithms,
            request_auth_agent: false,
            request_x11: None,
            session_env: Vec::new(),
            keepalive: None,
            request_pty: None,
            tcpip_forward_grants: Vec::new(),
            streamlocal_forward_grants: Vec::new(),
        };
        me.driver.start(Instant::now())?;
        me.drive_handshake()?;
        Ok(me)
    }

    /// Try every credential in order until one succeeds or all are refused.
    ///
    /// Builds a single [`ClientAuth`] driver carrying every credential and
    /// runs it to completion on this one connection — the SERVICE_REQUEST is
    /// sent exactly once. Multiple credentials (e.g. several keys, a password,
    /// a keyboard-interactive responder) are tried in order *within the same
    /// userauth exchange*, which is what a multi-factor server expects (the
    /// driver advances on each USERAUTH_FAILURE / partial-success).
    pub fn authenticate(&mut self, user: &str, credentials: Vec<ClientCredential>) -> Result<()> {
        let mut auth = ClientAuth::new(user, self.driver.session_id().to_vec());
        // Local PubkeyAcceptedAlgorithms policy from ssh_config, applied
        // before any server-sig-algs filtering.
        if let Some(accepted) = self.algo_overrides.pubkey_accepted_algorithms.clone() {
            auth.set_pubkey_accepted(accepted);
        }
        // RFC 8308 §3.1: if the server told us which signature algorithms
        // it will accept on a publickey auth, propagate that to the auth
        // driver so we skip credentials it would reject anyway.
        if let Some(ext) = self.driver.peer_ext_info()
            && let Some(algs) = ext.server_sig_algs.as_deref()
        {
            auth.set_server_sig_algs(algs);
        }
        for c in credentials {
            auth.add_credential(c);
        }
        self.run_auth(auth)
    }

    /// Drive a fully-configured [`ClientAuth`] to a verdict on this connection.
    /// Hands the driver the auth state machine (which emits the single
    /// SERVICE_REQUEST) and pumps until it reports success or exhausts its
    /// credentials. Callers that need to inject policy (server-sig-algs,
    /// pubkey-accepted, a re-promptable password closure, a keyboard-interactive
    /// responder) build the driver themselves and hand it here — there is
    /// exactly one driver, and thus exactly one SERVICE_REQUEST, per connection.
    pub fn run_auth(&mut self, mut auth: ClientAuth) -> Result<()> {
        let first = auth.start();
        self.write_payload(&first)?;

        for _ in 0..MAX_AUTH_STEPS {
            // `read_one_packet` surfaces post-NEWKEYS payloads (userauth here)
            // from the driver; transport concerns stay inside it.
            let payload = self.read_one_packet()?;
            match auth.on_packet(&payload)? {
                ClientStep::Send(p) => self.write_payload(&p)?,
                ClientStep::Success => {
                    // Hand the post-auth transitions (compression + EXT_INFO
                    // re-arm) to the driver, which owns the codec/runner.
                    self.driver.notify_auth_success();
                    return Ok(());
                }
                ClientStep::Failed { .. } => return Err(Error::AuthFailed),
                ClientStep::Banner { .. } => {}
                ClientStep::Idle => {}
            }
        }
        Err(Error::Protocol("auth: too many steps without termination"))
    }

    /// Build a [`ClientAuth`] for `user` with this connection's resolved
    /// ssh_config policy (PubkeyAcceptedAlgorithms + server-sig-algs)
    /// pre-installed, ready for the caller to push credentials onto and then
    /// hand to [`Self::run_auth`]. This is the one-driver-per-connection entry
    /// point for callers (e.g. the `ssh` binary) that need a re-promptable
    /// password or a keyboard-interactive responder.
    pub fn new_auth_driver(&self, user: &str) -> ClientAuth {
        let mut auth = ClientAuth::new(user, self.driver.session_id().to_vec());
        if let Some(accepted) = self.algo_overrides.pubkey_accepted_algorithms.clone() {
            auth.set_pubkey_accepted(accepted);
        }
        if let Some(ext) = self.driver.peer_ext_info()
            && let Some(algs) = ext.server_sig_algs.as_deref()
        {
            auth.set_server_sig_algs(algs);
        }
        auth
    }

    /// Convenience: try password authentication only.
    pub fn authenticate_password(&mut self, user: &str, password: &str) -> Result<()> {
        self.authenticate(user, vec![ClientCredential::Password(password.into())])
    }

    /// Session identifier for this connection — the exchange hash `H` of the
    /// *first* key exchange (RFC 4253 §7.2). Stable across re-keys.
    pub fn session_id(&self) -> &[u8] {
        self.driver.session_id()
    }

    /// Most recent `SSH_MSG_EXT_INFO` (RFC 8308) received from the server,
    /// if any. Carries `server-sig-algs` and any forward-compatible
    /// extensions the server advertised. Returns `None` when neither side
    /// advertised the `ext-info-{c,s}` markers or the server simply
    /// declined to send one.
    pub fn peer_ext_info(&self) -> Option<&crate::transport::ExtInfo> {
        self.driver.peer_ext_info()
    }

    /// Convenience: try publickey authentication only.
    pub fn authenticate_publickey(
        &mut self,
        user: &str,
        key: Box<dyn HostKey + Send>,
    ) -> Result<()> {
        self.authenticate(user, vec![ClientCredential::PublicKey(key)])
    }

    /// Open a session channel that exists solely to host an
    /// `auth-agent-req@openssh.com` request, then send that request and
    /// return the channel's local id. The caller is expected to keep this
    /// channel open for the lifetime of any agent-forwarding work
    /// ([`Self::serve`] with [`ClientHandlers::on_auth_agent`] installed),
    /// then tear it down with [`Self::close_session`].
    ///
    /// On the server side, the matching `auth-agent-req` arms a
    /// per-session-channel Unix-socket listener; closing this channel
    /// unlinks the socket and stops accepting agent calls. See
    /// [`crate::forwarding::agent`] for the server side.
    pub fn open_session_for_agent_forward(&mut self) -> Result<u32> {
        let (local_id, open_payload) = self.conn.open(ChannelOpen::Session)?;
        self.write_payload(&open_payload)?;

        let mut iter_guard = 0usize;
        loop {
            iter_guard += 1;
            if iter_guard > MAX_EXEC_ITER {
                return Err(Error::Protocol("agent-forward: open loop did not converge"));
            }
            let payload = self.read_one_packet()?;
            match self.conn.on_packet(&payload)? {
                ChannelEvent::OpenConfirmed { channel } if channel == local_id => break,
                ChannelEvent::OpenFailed { channel, .. } if channel == local_id => {
                    return Err(Error::Protocol("agent-forward: channel open failed"));
                }
                _ => {}
            }
        }

        let p = self
            .conn
            .send_request(local_id, ChannelRequest::AuthAgentReq, false)?;
        self.write_payload(&p)?;
        Ok(local_id)
    }

    /// Open a session channel that exists solely to host an `x11-req`
    /// request, then send that request and return the channel's local id.
    /// The caller is expected to keep this channel open for the lifetime
    /// of any X11-forwarding work ([`Self::serve`] with
    /// [`ClientHandlers::on_x11`] installed), then tear it down with
    /// [`Self::close_session`].
    ///
    /// On the server side, the matching `x11-req` arms a per-session
    /// TCP display listener (`127.0.0.1:6000+N`); closing this channel
    /// stops it. See [`crate::forwarding::x11`] for the server side.
    pub fn open_session_for_x11_forward(
        &mut self,
        single_connection: bool,
        auth_protocol: &str,
        auth_cookie: &str,
        screen: u32,
    ) -> Result<u32> {
        let (local_id, open_payload) = self.conn.open(ChannelOpen::Session)?;
        self.write_payload(&open_payload)?;

        let mut iter_guard = 0usize;
        loop {
            iter_guard += 1;
            if iter_guard > MAX_EXEC_ITER {
                return Err(Error::Protocol("x11-forward: open loop did not converge"));
            }
            let payload = self.read_one_packet()?;
            match self.conn.on_packet(&payload)? {
                ChannelEvent::OpenConfirmed { channel } if channel == local_id => break,
                ChannelEvent::OpenFailed { channel, .. } if channel == local_id => {
                    return Err(Error::Protocol("x11-forward: channel open failed"));
                }
                _ => {}
            }
        }

        let p = self.conn.send_request(
            local_id,
            ChannelRequest::X11Req {
                single_connection,
                auth_protocol: auth_protocol.to_string(),
                auth_cookie: auth_cookie.to_string(),
                screen,
            },
            false,
        )?;
        self.write_payload(&p)?;
        Ok(local_id)
    }

    /// Set the underlying TCP socket's read timeout. `None` clears it
    /// (blocking reads, the default). Used by the SharedClient pump in
    /// interactive-shell mode to release its inner mutex periodically so
    /// sibling write threads can make progress; you generally don't need
    /// it for one-shot exec / SFTP flows where there's only one waiter.
    ///
    /// Callers that set a non-`None` value MUST tolerate
    /// `ErrorKind::WouldBlock` / `ErrorKind::TimedOut` on subsequent
    /// reads (or only use code paths that fold those into a no-op).
    pub fn set_read_timeout(&mut self, t: Option<core::time::Duration>) -> std::io::Result<()> {
        self.stream.set_read_timeout(t)
    }

    /// Send `SSH_MSG_CHANNEL_CLOSE` for `channel`. Used to tear down a
    /// session channel opened by
    /// [`Self::open_session_for_agent_forward`] once the matching serve
    /// loop has returned. Best-effort: silently swallows codec errors for
    /// channels already torn down by the peer.
    pub fn close_session(&mut self, channel: u32) -> Result<()> {
        let payload = match self.conn.send_close(channel) {
            Ok(p) => p,
            Err(_) => return Ok(()),
        };
        self.write_payload(&payload)?;
        Ok(())
    }

    /// Toggle whether the next session-channel helper ([`Self::exec`],
    /// [`Self::exec_stream`], [`Self::shell_with_stdin`], [`Self::sftp`])
    /// prefaces its shell/exec/subsystem request with
    /// `auth-agent-req@openssh.com` (the channel request that asks the
    /// server to set up an `SSH_AUTH_SOCK` Unix socket for this session
    /// channel and call back via `auth-agent@openssh.com` channels —
    /// OpenSSH's `ssh -A`).
    ///
    /// Sticky: stays set until cleared. The agent-req is sent with
    /// `want_reply = false`, matching OpenSSH; the server's response
    /// (acceptance / refusal) is observable only via whether a callback
    /// channel ever lands on a peer-installed [`ClientHandlers::on_auth_agent`].
    pub fn set_request_auth_agent_forwarding(&mut self, on: bool) {
        self.request_auth_agent = on;
    }

    /// Internal: emit `auth-agent-req@openssh.com` if the toggle is set.
    /// Called by every session-channel helper between OpenConfirmed and
    /// the matching shell/exec/subsystem request.
    pub(crate) fn maybe_send_auth_agent_req(&mut self, channel: u32) -> Result<()> {
        if self.request_auth_agent {
            let p = self
                .conn
                .send_request(channel, ChannelRequest::AuthAgentReq, false)?;
            self.write_payload(&p)?;
        }
        Ok(())
    }

    /// Arm `x11-req` to be emitted on every subsequent session-channel
    /// helper ([`Self::exec`], [`Self::exec_stream`],
    /// [`Self::shell_with_stdin`], [`Self::sftp`]) between OpenConfirmed
    /// and the matching shell/exec/subsystem request.
    ///
    /// `single_connection` follows RFC 4254 §6.3.1: `true` accepts exactly
    /// one X-client connection on the forwarded display, `false` accepts
    /// any number (the OpenSSH default for both `-X` and `-Y`).
    ///
    /// `auth_protocol` is typically `"MIT-MAGIC-COOKIE-1"`; `auth_cookie`
    /// is the matching cookie as a hex string. The server forwards both
    /// verbatim into [`crate::server::X11ForwardHandler::setup`] — cookie
    /// substitution at the X-protocol level is the responsibility of the
    /// `on_x11` handler. `screen` is the X screen number (0 in nearly all
    /// uses). Pass `None` to clear the toggle.
    pub fn set_request_x11_forwarding(&mut self, args: Option<(bool, String, String, u32)>) {
        self.request_x11 =
            args.map(
                |(single_connection, auth_protocol, auth_cookie, screen)| X11ReqArgs {
                    single_connection,
                    auth_protocol,
                    auth_cookie,
                    screen,
                },
            );
    }

    /// Internal: emit `x11-req` if the toggle is set. Called by every
    /// session-channel helper between OpenConfirmed and the matching
    /// shell/exec/subsystem request, right after
    /// [`Self::maybe_send_auth_agent_req`].
    pub(crate) fn maybe_send_x11_req(&mut self, channel: u32) -> Result<()> {
        if let Some(args) = self.request_x11.clone() {
            let p = self.conn.send_request(
                channel,
                ChannelRequest::X11Req {
                    single_connection: args.single_connection,
                    auth_protocol: args.auth_protocol,
                    auth_cookie: args.auth_cookie,
                    screen: args.screen,
                },
                false,
            )?;
            self.write_payload(&p)?;
        }
        Ok(())
    }

    /// Set the environment variables emitted as `env` channel requests on
    /// every subsequent session-channel helper ([`Self::exec`],
    /// [`Self::exec_stream`], [`Self::shell_with_stdin`]).
    ///
    /// Populated from `SetEnv` (literal pairs) and `SendEnv` (local env vars
    /// matched by pattern, resolved by the caller). Each pair is sent with
    /// `want_reply = false`, matching OpenSSH; whether the server accepts a
    /// given variable is governed by its `AcceptEnv` policy and is not
    /// observable here. Sticky: stays set until replaced.
    pub fn set_session_env(&mut self, env: Vec<(String, String)>) {
        self.session_env = env;
    }

    /// Internal: emit one `env` request per [`Self::set_session_env`] entry.
    /// Called by every session-channel helper between OpenConfirmed and the
    /// matching shell/exec request.
    pub(crate) fn maybe_send_env(&mut self, channel: u32) -> Result<()> {
        for (name, value) in self.session_env.clone() {
            let p = self
                .conn
                .send_request(channel, ChannelRequest::Env { name, value }, false)?;
            self.write_payload(&p)?;
        }
        Ok(())
    }

    /// Configure server-keepalive probing for [`Self::serve`]
    /// (`ServerAliveInterval` / `ServerAliveCountMax`).
    ///
    /// `interval_secs == 0` disables keepalive. Otherwise the serve loop
    /// sends a `keepalive@openssh.com` global request (with `want_reply`)
    /// after `interval_secs` of socket silence and tears the connection down
    /// once `count_max` consecutive probes go unanswered. Has no effect on
    /// the one-shot [`Self::exec`] path (which doesn't run the serve loop).
    pub fn set_keepalive(&mut self, interval_secs: u32, count_max: u32) {
        self.keepalive = if interval_secs == 0 {
            None
        } else {
            Some((Duration::from_secs(interval_secs as u64), count_max.max(1)))
        };
    }

    /// Arm a `pty-req` to be emitted ahead of the next [`Self::exec`]'s
    /// `exec` request, so a remote command runs under a pseudo-terminal
    /// (`RequestTTY force` / `yes`). Pass `None` to clear.
    ///
    /// The interactive shell path allocates its PTY directly via
    /// [`crate::shared::SharedClient::shell_stream`]; this toggle exists for
    /// the one-shot `exec` path only.
    pub fn set_request_pty(&mut self, args: Option<(String, u32, u32, u32, u32, Vec<u8>)>) {
        self.request_pty = args.map(|(term, cols, rows, px_w, px_h, modes)| PtyReqArgs {
            term,
            cols,
            rows,
            px_w,
            px_h,
            modes,
        });
    }

    /// Internal: emit `pty-req` if [`Self::set_request_pty`] armed one.
    pub(crate) fn maybe_send_pty_req(&mut self, channel: u32) -> Result<()> {
        if let Some(args) = self.request_pty.clone() {
            let p = self.conn.send_request(
                channel,
                ChannelRequest::PtyReq {
                    term: args.term,
                    cols: args.cols,
                    rows: args.rows,
                    px_w: args.px_w,
                    px_h: args.px_h,
                    modes: args.modes,
                },
                false,
            )?;
            self.write_payload(&p)?;
        }
        Ok(())
    }

    /// Run a remote command, draining stdout/stderr and capturing the exit
    /// status (or signal). Returns once the server has closed the channel.
    pub fn exec(&mut self, command: &str) -> Result<ExecOutput> {
        let (local_id, open_payload) = self.conn.open(ChannelOpen::Session)?;
        self.write_payload(&open_payload)?;

        let mut opened = false;
        let mut iter_guard = 0usize;
        while !opened {
            iter_guard += 1;
            if iter_guard > MAX_EXEC_ITER {
                return Err(Error::Protocol("exec: open loop did not converge"));
            }
            let payload = self.read_one_packet()?;
            match self.conn.on_packet(&payload)? {
                ChannelEvent::OpenConfirmed { channel } if channel == local_id => {
                    opened = true;
                }
                ChannelEvent::OpenFailed { channel, .. } if channel == local_id => {
                    return Err(Error::Protocol("channel open failed"));
                }
                _ => {}
            }
        }

        self.maybe_send_auth_agent_req(local_id)?;
        self.maybe_send_x11_req(local_id)?;
        self.maybe_send_env(local_id)?;
        self.maybe_send_pty_req(local_id)?;

        let exec_req = self.conn.send_request(
            local_id,
            ChannelRequest::Exec {
                command: command.into(),
            },
            true,
        )?;
        self.write_payload(&exec_req)?;

        let mut exec_accepted = false;
        iter_guard = 0;
        while !exec_accepted {
            iter_guard += 1;
            if iter_guard > MAX_EXEC_ITER {
                return Err(Error::Protocol("exec: request loop did not converge"));
            }
            let payload = self.read_one_packet()?;
            match self.conn.on_packet(&payload)? {
                ChannelEvent::Success { channel } if channel == local_id => exec_accepted = true,
                ChannelEvent::Failure { channel } if channel == local_id => {
                    return Err(Error::Protocol("exec request denied"));
                }
                _ => {}
            }
        }

        let mut out = ExecOutput {
            stdout: Vec::new(),
            stderr: Vec::new(),
            exit_status: None,
            exit_signal: None,
        };
        let mut local_eof_sent = false;
        let mut local_close_sent = false;
        let mut remote_close_seen = false;

        for _ in 0..MAX_EXEC_ITER {
            if remote_close_seen && local_close_sent {
                break;
            }
            let payload = self.read_one_packet()?;
            let ev = self.conn.on_packet(&payload)?;
            match ev {
                ChannelEvent::Data { channel, data } if channel == local_id => {
                    if out.stdout.len() + out.stderr.len() + data.len() > MAX_EXEC_OUTPUT {
                        return Err(Error::Protocol("exec output too large"));
                    }
                    let n = data.len() as u32;
                    out.stdout.extend_from_slice(&data);
                    if let Some(adj) = self.conn.replenish_window(local_id, n)? {
                        self.write_payload(&adj)?;
                    }
                }
                ChannelEvent::ExtendedData {
                    channel,
                    code,
                    data,
                } if channel == local_id => {
                    if out.stdout.len() + out.stderr.len() + data.len() > MAX_EXEC_OUTPUT {
                        return Err(Error::Protocol("exec output too large"));
                    }
                    let n = data.len() as u32;
                    if code == SSH_EXTENDED_DATA_STDERR {
                        out.stderr.extend_from_slice(&data);
                    } else {
                        out.stdout.extend_from_slice(&data);
                    }
                    if let Some(adj) = self.conn.replenish_window(local_id, n)? {
                        self.write_payload(&adj)?;
                    }
                }
                ChannelEvent::Request {
                    channel,
                    request,
                    want_reply,
                } if channel == local_id => {
                    match request {
                        ChannelRequest::ExitStatus { code } => out.exit_status = Some(code),
                        ChannelRequest::ExitSignal { name, .. } => out.exit_signal = Some(name),
                        _ => {}
                    }
                    if want_reply {
                        let p = self.conn.send_request_failure(local_id)?;
                        self.write_payload(&p)?;
                    }
                }
                ChannelEvent::Eof { channel } if channel == local_id && !local_eof_sent => {
                    let p = self.conn.send_eof(local_id)?;
                    self.write_payload(&p)?;
                    local_eof_sent = true;
                }
                ChannelEvent::Close { channel } if channel == local_id => {
                    remote_close_seen = true;
                    if !local_close_sent {
                        let p = self.conn.send_close(local_id)?;
                        self.write_payload(&p)?;
                        local_close_sent = true;
                    }
                }
                ChannelEvent::WindowAdjust { .. } => {}
                _ => {}
            }
        }

        if !(remote_close_seen && local_close_sent) {
            return Err(Error::Protocol("exec: drain loop exceeded iteration cap"));
        }
        Ok(out)
    }

    /// Open an interactive `"shell"` session with an allocated PTY, push
    /// `stdin` into the channel once, EOF, and drain the response until
    /// the server closes the channel.
    ///
    /// This is a one-shot helper aimed at scripted tests and simple
    /// interop checks — a real interactive client would interleave reads
    /// and writes with the terminal. It exists primarily so the server's
    /// `pty-req` / `shell` wiring can be exercised end-to-end.
    pub fn shell_with_stdin(
        &mut self,
        term: &str,
        cols: u32,
        rows: u32,
        stdin: &[u8],
    ) -> Result<ExecOutput> {
        let (local_id, open_payload) = self.conn.open(ChannelOpen::Session)?;
        self.write_payload(&open_payload)?;

        // Wait for OPEN_CONFIRMATION.
        let mut opened = false;
        let mut iter_guard = 0usize;
        while !opened {
            iter_guard += 1;
            if iter_guard > MAX_EXEC_ITER {
                return Err(Error::Protocol("shell: open loop did not converge"));
            }
            let payload = self.read_one_packet()?;
            match self.conn.on_packet(&payload)? {
                ChannelEvent::OpenConfirmed { channel } if channel == local_id => {
                    opened = true;
                }
                ChannelEvent::OpenFailed { channel, .. } if channel == local_id => {
                    return Err(Error::Protocol("channel open failed"));
                }
                _ => {}
            }
        }

        self.maybe_send_auth_agent_req(local_id)?;
        self.maybe_send_x11_req(local_id)?;

        // pty-req with want_reply=true.
        let pty_req = self.conn.send_request(
            local_id,
            ChannelRequest::PtyReq {
                term: term.into(),
                cols,
                rows,
                px_w: 0,
                px_h: 0,
                modes: Vec::new(),
            },
            true,
        )?;
        self.write_payload(&pty_req)?;
        self.await_request_reply(local_id, "pty-req")?;

        // shell with want_reply=true.
        let shell_req = self
            .conn
            .send_request(local_id, ChannelRequest::Shell, true)?;
        self.write_payload(&shell_req)?;
        self.await_request_reply(local_id, "shell")?;

        // Push stdin (if any), then EOF.
        if !stdin.is_empty() {
            let mut off = 0usize;
            iter_guard = 0;
            while off < stdin.len() {
                iter_guard += 1;
                if iter_guard > MAX_EXEC_ITER {
                    return Err(Error::Protocol("shell: stdin drain loop did not converge"));
                }
                let (payload, taken) = self.conn.send_data(local_id, &stdin[off..])?;
                if taken == 0 {
                    // Window full — read until we get a WINDOW_ADJUST.
                    let pkt = self.read_one_packet()?;
                    match self.conn.on_packet(&pkt)? {
                        ChannelEvent::WindowAdjust { channel, .. } if channel == local_id => {}
                        ChannelEvent::Close { channel } if channel == local_id => {
                            return Err(Error::Protocol(
                                "shell: peer closed channel before stdin drain",
                            ));
                        }
                        _ => {}
                    }
                    continue;
                }
                self.write_payload(&payload)?;
                off += taken;
            }
        }
        let eof = self.conn.send_eof(local_id)?;
        self.write_payload(&eof)?;

        // Drain until both sides have CLOSEd.
        let mut out = ExecOutput {
            stdout: Vec::new(),
            stderr: Vec::new(),
            exit_status: None,
            exit_signal: None,
        };
        let mut local_close_sent = false;
        let mut remote_close_seen = false;

        for _ in 0..MAX_EXEC_ITER {
            if remote_close_seen && local_close_sent {
                break;
            }
            let payload = self.read_one_packet()?;
            let ev = self.conn.on_packet(&payload)?;
            match ev {
                ChannelEvent::Data { channel, data } if channel == local_id => {
                    if out.stdout.len() + out.stderr.len() + data.len() > MAX_EXEC_OUTPUT {
                        return Err(Error::Protocol("shell output too large"));
                    }
                    let n = data.len() as u32;
                    out.stdout.extend_from_slice(&data);
                    if let Some(adj) = self.conn.replenish_window(local_id, n)? {
                        self.write_payload(&adj)?;
                    }
                }
                ChannelEvent::ExtendedData {
                    channel,
                    code,
                    data,
                } if channel == local_id => {
                    if out.stdout.len() + out.stderr.len() + data.len() > MAX_EXEC_OUTPUT {
                        return Err(Error::Protocol("shell output too large"));
                    }
                    let n = data.len() as u32;
                    if code == SSH_EXTENDED_DATA_STDERR {
                        out.stderr.extend_from_slice(&data);
                    } else {
                        out.stdout.extend_from_slice(&data);
                    }
                    if let Some(adj) = self.conn.replenish_window(local_id, n)? {
                        self.write_payload(&adj)?;
                    }
                }
                ChannelEvent::Request {
                    channel,
                    request,
                    want_reply,
                } if channel == local_id => {
                    match request {
                        ChannelRequest::ExitStatus { code } => out.exit_status = Some(code),
                        ChannelRequest::ExitSignal { name, .. } => out.exit_signal = Some(name),
                        _ => {}
                    }
                    if want_reply {
                        let p = self.conn.send_request_failure(local_id)?;
                        self.write_payload(&p)?;
                    }
                }
                ChannelEvent::Eof { channel } if channel == local_id => {}
                ChannelEvent::Close { channel } if channel == local_id => {
                    remote_close_seen = true;
                    if !local_close_sent {
                        let p = self.conn.send_close(local_id)?;
                        self.write_payload(&p)?;
                        local_close_sent = true;
                    }
                }
                ChannelEvent::WindowAdjust { .. } => {}
                _ => {}
            }
        }

        if !(remote_close_seen && local_close_sent) {
            return Err(Error::Protocol("shell: drain loop exceeded iteration cap"));
        }
        Ok(out)
    }

    /// One-shot subsystem helper: open a session channel, send a
    /// `subsystem` request with the given `name`, push `stdin` once, send
    /// EOF, then drain the response until the peer CLOSEs. Returns the
    /// accumulated channel data (the stream's stdout half).
    ///
    /// This is the subsystem analogue of [`exec`]: it doesn't expose the
    /// channel for streaming use (a `Client::sftp` streaming wrapper will
    /// land in a follow-up phase), but it's enough to exercise the
    /// server's subsystem dispatch end-to-end and to drive small
    /// request/response protocols.
    ///
    /// [`exec`]: Self::exec
    pub fn subsystem_once(&mut self, name: &str, stdin: &[u8]) -> Result<Vec<u8>> {
        let (local_id, open_payload) = self.conn.open(ChannelOpen::Session)?;
        self.write_payload(&open_payload)?;

        let mut opened = false;
        let mut iter_guard = 0usize;
        while !opened {
            iter_guard += 1;
            if iter_guard > MAX_EXEC_ITER {
                return Err(Error::Protocol("subsystem: open loop did not converge"));
            }
            let payload = self.read_one_packet()?;
            match self.conn.on_packet(&payload)? {
                ChannelEvent::OpenConfirmed { channel } if channel == local_id => opened = true,
                ChannelEvent::OpenFailed { channel, .. } if channel == local_id => {
                    return Err(Error::Protocol("channel open failed"));
                }
                _ => {}
            }
        }

        let sub_req = self.conn.send_request(
            local_id,
            ChannelRequest::Subsystem { name: name.into() },
            true,
        )?;
        self.write_payload(&sub_req)?;
        self.await_request_reply(local_id, "subsystem")?;

        // Push stdin (if any), then EOF.
        if !stdin.is_empty() {
            let mut off = 0usize;
            iter_guard = 0;
            while off < stdin.len() {
                iter_guard += 1;
                if iter_guard > MAX_EXEC_ITER {
                    return Err(Error::Protocol(
                        "subsystem: stdin drain loop did not converge",
                    ));
                }
                let (payload, taken) = self.conn.send_data(local_id, &stdin[off..])?;
                if taken == 0 {
                    let pkt = self.read_one_packet()?;
                    match self.conn.on_packet(&pkt)? {
                        ChannelEvent::WindowAdjust { channel, .. } if channel == local_id => {}
                        ChannelEvent::Close { channel } if channel == local_id => {
                            return Err(Error::Protocol(
                                "subsystem: peer closed channel before stdin drain",
                            ));
                        }
                        _ => {}
                    }
                    continue;
                }
                self.write_payload(&payload)?;
                off += taken;
            }
        }
        let eof = self.conn.send_eof(local_id)?;
        self.write_payload(&eof)?;

        let mut out = Vec::<u8>::new();
        let mut local_close_sent = false;
        let mut remote_close_seen = false;

        for _ in 0..MAX_EXEC_ITER {
            if remote_close_seen && local_close_sent {
                break;
            }
            let payload = self.read_one_packet()?;
            let ev = self.conn.on_packet(&payload)?;
            match ev {
                ChannelEvent::Data { channel, data } if channel == local_id => {
                    if out.len() + data.len() > MAX_EXEC_OUTPUT {
                        return Err(Error::Protocol("subsystem output too large"));
                    }
                    let n = data.len() as u32;
                    out.extend_from_slice(&data);
                    if let Some(adj) = self.conn.replenish_window(local_id, n)? {
                        self.write_payload(&adj)?;
                    }
                }
                ChannelEvent::ExtendedData {
                    channel,
                    code: _,
                    data,
                } if channel == local_id => {
                    // Subsystems shouldn't send stderr by RFC convention, but
                    // if they do, treat it like stdout for window accounting.
                    let n = data.len() as u32;
                    if let Some(adj) = self.conn.replenish_window(local_id, n)? {
                        self.write_payload(&adj)?;
                    }
                }
                ChannelEvent::Eof { channel } if channel == local_id => {}
                ChannelEvent::Close { channel } if channel == local_id => {
                    remote_close_seen = true;
                    if !local_close_sent {
                        let p = self.conn.send_close(local_id)?;
                        self.write_payload(&p)?;
                        local_close_sent = true;
                    }
                }
                ChannelEvent::WindowAdjust { .. } => {}
                _ => {}
            }
        }

        if !(remote_close_seen && local_close_sent) {
            return Err(Error::Protocol(
                "subsystem: drain loop exceeded iteration cap",
            ));
        }
        Ok(out)
    }

    /// Open an SFTP session: opens a session channel, requests the `sftp`
    /// subsystem, performs the SFTP `INIT`/`VERSION` handshake, and returns
    /// a [`SftpClient`] borrowing the channel for its lifetime.
    ///
    /// The returned client serialises one request/response at a time. When
    /// it's dropped, the channel is closed.
    #[cfg_attr(
        feature = "multichannel",
        deprecated(
            since = "0.0.2",
            note = "Use SharedClient::sftp instead; the borrow-based API \
                    prevents multiple concurrent channels on one connection."
        )
    )]
    pub fn sftp(&mut self) -> Result<SftpClient<ClientChannelStream<'_>>> {
        let (local_id, open_payload) = self.conn.open(ChannelOpen::Session)?;
        self.write_payload(&open_payload)?;

        let mut opened = false;
        let mut iter_guard = 0usize;
        while !opened {
            iter_guard += 1;
            if iter_guard > MAX_EXEC_ITER {
                return Err(Error::Protocol("sftp: open loop did not converge"));
            }
            let payload = self.read_one_packet()?;
            match self.conn.on_packet(&payload)? {
                ChannelEvent::OpenConfirmed { channel } if channel == local_id => opened = true,
                ChannelEvent::OpenFailed { channel, .. } if channel == local_id => {
                    return Err(Error::Protocol("channel open failed"));
                }
                _ => {}
            }
        }

        self.maybe_send_auth_agent_req(local_id)?;
        self.maybe_send_x11_req(local_id)?;

        let sub_req = self.conn.send_request(
            local_id,
            ChannelRequest::Subsystem {
                name: "sftp".into(),
            },
            true,
        )?;
        self.write_payload(&sub_req)?;
        self.await_request_reply(local_id, "subsystem")?;

        let stream = ClientChannelStream {
            client: self,
            channel: local_id,
            read_buf: Vec::new(),
            stderr_buf: Vec::new(),
            remote_eof: false,
            local_close_sent: false,
        };
        // SftpClient::new performs INIT/VERSION; on error we still want to
        // try to close the channel. Wrap with a manual try-catch.
        match SftpClient::new(stream) {
            Ok(c) => Ok(c),
            Err(e) => Err(Error::Protocol(match e {
                crate::sftp::SftpError::Protocol(s) => s,
                _ => "sftp: handshake failed",
            })),
        }
    }

    /// Open a session channel and ask the server to execute `command`,
    /// returning a [`ClientChannelStream`] borrowing the client for the
    /// channel's lifetime. The stream's `Read` half delivers the command's
    /// stdout, `Write` feeds stdin, and the channel is closed on drop.
    /// Stderr is buffered and can be drained with
    /// [`ClientChannelStream::take_stderr`].
    ///
    /// Mirrors [`Client::sftp`] but issues `ChannelRequest::Exec` instead
    /// of `Subsystem`. Used by [`Client::scp_send_to`] /
    /// [`Client::scp_recv_from`] to drive the remote `scp -t` / `scp -f`
    /// helper over the channel. For one-shot commands whose output you just
    /// want to collect, use [`Client::exec`] instead.
    #[cfg_attr(
        feature = "multichannel",
        deprecated(
            since = "0.0.2",
            note = "Use SharedClient::exec_stream for multi-channel support."
        )
    )]
    pub fn exec_stream(&mut self, command: &str) -> Result<ClientChannelStream<'_>> {
        let (local_id, open_payload) = self.conn.open(ChannelOpen::Session)?;
        self.write_payload(&open_payload)?;

        let mut opened = false;
        let mut iter_guard = 0usize;
        while !opened {
            iter_guard += 1;
            if iter_guard > MAX_EXEC_ITER {
                return Err(Error::Protocol("exec_stream: open loop did not converge"));
            }
            let payload = self.read_one_packet()?;
            match self.conn.on_packet(&payload)? {
                ChannelEvent::OpenConfirmed { channel } if channel == local_id => opened = true,
                ChannelEvent::OpenFailed { channel, .. } if channel == local_id => {
                    return Err(Error::Protocol("exec_stream: channel open failed"));
                }
                _ => {}
            }
        }

        self.maybe_send_auth_agent_req(local_id)?;
        self.maybe_send_x11_req(local_id)?;
        self.maybe_send_env(local_id)?;
        self.maybe_send_pty_req(local_id)?;

        let exec_req = self.conn.send_request(
            local_id,
            ChannelRequest::Exec {
                command: command.into(),
            },
            true,
        )?;
        self.write_payload(&exec_req)?;
        self.await_request_reply(local_id, "exec")?;

        Ok(ClientChannelStream {
            client: self,
            channel: local_id,
            read_buf: Vec::new(),
            stderr_buf: Vec::new(),
            remote_eof: false,
            local_close_sent: false,
        })
    }

    /// Open a `direct-tcpip` channel (RFC 4254 §7.2) that asks the server to
    /// connect to `dest_host:dest_port` and proxy bytes. Returns a
    /// `Read + Write` stream borrowing the client for the channel's
    /// lifetime; dropping it closes the channel.
    ///
    /// `orig_host`/`orig_port` are informational (the server logs them but
    /// makes no routing decision on them); pass `("127.0.0.1", 0)` if you
    /// don't have a meaningful source.
    ///
    /// Like [`Client::sftp`] / [`Client::exec`], this is a single-channel
    /// helper: while the returned stream is alive, the client cannot be
    /// used for anything else. Multi-channel multiplexing comes later via
    /// the `Client::serve` event loop.
    #[cfg_attr(
        feature = "multichannel",
        deprecated(
            since = "0.0.2",
            note = "Use SharedClient::open_direct_tcpip for multi-channel support."
        )
    )]
    pub fn open_direct_tcpip(
        &mut self,
        dest_host: &str,
        dest_port: u16,
        orig_host: &str,
        orig_port: u16,
    ) -> Result<ClientChannelStream<'_>> {
        let (local_id, open_payload) = self.conn.open(ChannelOpen::DirectTcpip {
            dest_host: dest_host.to_string(),
            dest_port: dest_port as u32,
            orig_host: orig_host.to_string(),
            orig_port: orig_port as u32,
        })?;
        self.write_payload(&open_payload)?;

        let mut iter_guard = 0usize;
        loop {
            iter_guard += 1;
            if iter_guard > MAX_EXEC_ITER {
                return Err(Error::Protocol("direct-tcpip: open loop did not converge"));
            }
            let payload = self.read_one_packet()?;
            match self.conn.on_packet(&payload)? {
                ChannelEvent::OpenConfirmed { channel } if channel == local_id => break,
                ChannelEvent::OpenFailed { channel, .. } if channel == local_id => {
                    return Err(Error::Protocol("direct-tcpip: open failed"));
                }
                _ => {}
            }
        }

        Ok(ClientChannelStream {
            client: self,
            channel: local_id,
            read_buf: Vec::new(),
            stderr_buf: Vec::new(),
            remote_eof: false,
            local_close_sent: false,
        })
    }

    /// Open a `direct-streamlocal@openssh.com` channel (OpenSSH extension; the
    /// Unix-socket analog of [`Self::open_direct_tcpip`], the wire side of
    /// `ssh -L local:/remote.sock`). Asks the server to connect to
    /// `socket_path` and proxies bytes over the returned channel.
    ///
    /// Single-channel helper: while the returned stream is alive the client
    /// cannot be used for anything else. For multi-channel use, drive
    /// [`Self::serve`] and call
    /// [`ServeContext::open_direct_streamlocal`] from another thread.
    #[cfg_attr(
        feature = "multichannel",
        deprecated(
            since = "0.0.7",
            note = "Use ServeContext::open_direct_streamlocal for multi-channel support."
        )
    )]
    pub fn open_direct_streamlocal(
        &mut self,
        socket_path: &str,
    ) -> Result<ClientChannelStream<'_>> {
        let (local_id, open_payload) = self.conn.open(ChannelOpen::DirectStreamlocal {
            socket_path: socket_path.to_string(),
        })?;
        self.write_payload(&open_payload)?;

        let mut iter_guard = 0usize;
        loop {
            iter_guard += 1;
            if iter_guard > MAX_EXEC_ITER {
                return Err(Error::Protocol(
                    "direct-streamlocal: open loop did not converge",
                ));
            }
            let payload = self.read_one_packet()?;
            match self.conn.on_packet(&payload)? {
                ChannelEvent::OpenConfirmed { channel } if channel == local_id => break,
                ChannelEvent::OpenFailed { channel, .. } if channel == local_id => {
                    return Err(Error::Protocol("direct-streamlocal: open failed"));
                }
                _ => {}
            }
        }

        Ok(ClientChannelStream {
            client: self,
            channel: local_id,
            read_buf: Vec::new(),
            stderr_buf: Vec::new(),
            remote_eof: false,
            local_close_sent: false,
        })
    }

    /// Upload one or more local sources to a remote destination via SCP.
    ///
    /// Issues `scp -t [-r] [-p] -- <quoted dest>` on the peer (a remote
    /// `scp` binary, or our own `sshd`'s in-process [`crate::server::ExecStreamHandler`]
    /// reading the SCP protocol). For each source we then drive
    /// [`crate::scp::Sender::send_path`] over the channel.
    ///
    /// Remote-path quoting refuses `'`, `\n`, and `\0` to prevent shell
    /// injection on the remote side. On error, any buffered server-side
    /// stderr is appended to the message via
    /// [`ClientChannelStream::take_stderr`].
    pub fn scp_send_to(
        &mut self,
        sources: &[&std::path::Path],
        remote_dest: &str,
        opts: crate::scp::ScpSendOptions,
    ) -> Result<()> {
        let cmd = build_scp_to_cmd(remote_dest, &opts)?;
        // Internal scp-wrapping path: uses the borrow-based exec_stream
        // because the helper itself is single-channel anyway. A future
        // SharedClient::scp_send_to could replace this; for now we
        // suppress the in-crate deprecation warning here.
        #[allow(deprecated)]
        let mut stream = self.exec_stream(&cmd)?;
        let result = (|| -> Result<()> {
            let mut sender = crate::scp::Sender::new(&mut stream)
                .map_err(|e| scp_proto(e, "scp_send_to: handshake"))?;
            for src in sources {
                sender
                    .send_path(src, &opts)
                    .map_err(|e| scp_proto(e, "scp_send_to: send_path"))?;
            }
            Ok(())
        })();
        // Drain any stderr the remote scp printed; surface it on error.
        let stderr = stream.take_stderr();
        match result {
            Ok(()) => Ok(()),
            Err(e) => {
                if !stderr.is_empty() {
                    let msg = String::from_utf8_lossy(&stderr).trim().to_string();
                    eprintln!("scp_send_to: remote stderr: {}", msg);
                }
                Err(e)
            }
        }
    }

    /// Download from a remote source to a local destination via SCP.
    ///
    /// Issues `scp -f [-r] [-p] -- <quoted source>` on the peer, then
    /// drives [`crate::scp::Receiver::run`] over the channel.
    ///
    /// `local_dest` is interpreted as a target *directory* unless
    /// `opts.recursive` is false AND `local_dest` doesn't exist as a
    /// directory — in which case it's treated as the literal file
    /// path (matches `scp remote:foo /tmp/bar`). To force file-target
    /// behaviour set the recv options' `target_is_file` flag.
    pub fn scp_recv_from(
        &mut self,
        remote_source: &str,
        local_dest: &std::path::Path,
        mut opts: crate::scp::ScpRecvOptions,
    ) -> Result<()> {
        let cmd = build_scp_from_cmd(remote_source, &opts)?;
        // If the local target is not an existing directory and the
        // caller hasn't said otherwise, treat it as a file target.
        if !opts.target_is_file && !opts.recursive {
            if let Ok(md) = std::fs::metadata(local_dest) {
                if !md.is_dir() {
                    opts.target_is_file = true;
                }
            } else {
                opts.target_is_file = true;
            }
        }
        // Residual CVE-2019-6111: when this is a single, non-recursive
        // fetch of a literal path (no glob metacharacters), we know the
        // exact basename the server is supposed to return. Pass it to the
        // receiver so it can reject a server that pushes extra or renamed
        // files. For recursive or glob requests the basename set is
        // unpredictable, so we leave the receiver in its confinement-only
        // mode (validate_name + guard_path).
        let expected_name: Option<String> = if opts.recursive {
            None
        } else {
            let base = remote_source.rsplit('/').next().unwrap_or(remote_source);
            // Glob metacharacters mean the server legitimately chooses the
            // names — don't pin a single expected basename in that case.
            let is_glob = base.contains(['*', '?', '[']);
            if base.is_empty() || is_glob {
                None
            } else {
                Some(base.to_string())
            }
        };
        // Matches scp_send_to: single-channel helper, internal use.
        #[allow(deprecated)]
        let mut stream = self.exec_stream(&cmd)?;
        let result = (|| -> Result<()> {
            let mut recv = crate::scp::Receiver::new(&mut stream, local_dest, opts)
                .map_err(|e| scp_proto(e, "scp_recv_from: handshake"))?
                .with_expected_name(expected_name.as_deref());
            recv.run().map_err(|e| scp_proto(e, "scp_recv_from: run"))?;
            Ok(())
        })();
        let stderr = stream.take_stderr();
        match result {
            Ok(()) => Ok(()),
            Err(e) => {
                if !stderr.is_empty() {
                    let msg = String::from_utf8_lossy(&stderr).trim().to_string();
                    eprintln!("scp_recv_from: remote stderr: {}", msg);
                }
                Err(e)
            }
        }
    }

    /// Send a `tcpip-forward` global request (RFC 4254 §7.1; the
    /// outbound bookend of `ssh -R`) and block until the server replies.
    ///
    /// `bind_port == 0` asks the server to pick a port; the actual port
    /// is returned. Any other value asks the server to bind that exact
    /// port and is returned verbatim on success.
    ///
    /// Returns `Err(Error::Protocol(_))` if the server replies
    /// `REQUEST_FAILURE` or if the reply tail is malformed.
    ///
    /// Note: at the time of writing the server side is bind-and-drop —
    /// connections accepted on the bound port are closed immediately.
    /// End-to-end byte forwarding (server-initiated `forwarded-tcpip`
    /// channel-opens back to the client) lands in a follow-up commit.
    pub fn request_tcpip_forward(&mut self, bind_address: &str, bind_port: u16) -> Result<u16> {
        use crate::channel::GlobalRequest;
        let payload = self.conn.send_global_request(
            GlobalRequest::TcpipForward {
                bind_address: bind_address.to_string(),
                bind_port: bind_port as u32,
            },
            true,
        );
        self.write_payload(&payload)?;
        let data = self.await_global_reply("tcpip-forward")?;
        let granted_port = if bind_port == 0 {
            let mut r = crate::format::Reader::new(&data);
            let p = r
                .read_u32()
                .map_err(|_| Error::Protocol("tcpip-forward: server omitted assigned-port tail"))?;
            if p > u16::MAX as u32 {
                return Err(Error::Protocol(
                    "tcpip-forward: server returned out-of-range port",
                ));
            }
            p as u16
        } else {
            bind_port
        };
        // Record the grant so `serve` can refuse unsolicited
        // `forwarded-tcpip` opens (see `tcpip_forward_grants`).
        self.tcpip_forward_grants
            .push((bind_address.to_string(), granted_port));
        Ok(granted_port)
    }

    /// Send a `cancel-tcpip-forward` global request (RFC 4254 §7.1) and
    /// block until the server replies. The `(bind_address, bind_port)`
    /// pair must match a previous successful `request_tcpip_forward`.
    pub fn cancel_tcpip_forward(&mut self, bind_address: &str, bind_port: u16) -> Result<()> {
        use crate::channel::GlobalRequest;
        let payload = self.conn.send_global_request(
            GlobalRequest::CancelTcpipForward {
                bind_address: bind_address.to_string(),
                bind_port: bind_port as u32,
            },
            true,
        );
        self.write_payload(&payload)?;
        let _ = self.await_global_reply("cancel-tcpip-forward")?;
        // Drop the matching grant so a later unsolicited forward is refused.
        // Match on (address, port); if the exact pair isn't found (e.g. the
        // caller cancelled by assigned port under a different address
        // spelling), fall back to dropping one grant for the same port.
        if let Some(idx) = self
            .tcpip_forward_grants
            .iter()
            .position(|(a, p)| a == bind_address && *p == bind_port)
            .or_else(|| {
                self.tcpip_forward_grants
                    .iter()
                    .position(|(_, p)| *p == bind_port)
            })
        {
            self.tcpip_forward_grants.swap_remove(idx);
        }
        Ok(())
    }

    /// Send a `streamlocal-forward@openssh.com` global request (OpenSSH
    /// extension; the Unix-socket analog of [`Self::request_tcpip_forward`],
    /// the outbound bookend of `ssh -R /remote.sock:...`) and block until the
    /// server replies.
    ///
    /// On success the server binds a Unix-domain listener at `socket_path` and
    /// will open `forwarded-streamlocal@openssh.com` channels back for each
    /// accepted connection — handle them via
    /// [`ClientHandlers::on_forwarded_streamlocal`] in [`Self::serve`].
    ///
    /// Returns `Err(Error::Protocol(_))` if the server replies
    /// `REQUEST_FAILURE`.
    pub fn request_streamlocal_forward(&mut self, socket_path: &str) -> Result<()> {
        use crate::channel::GlobalRequest;
        let payload = self.conn.send_global_request(
            GlobalRequest::StreamlocalForward {
                socket_path: socket_path.to_string(),
            },
            true,
        );
        self.write_payload(&payload)?;
        let _ = self.await_global_reply("streamlocal-forward@openssh.com")?;
        self.streamlocal_forward_grants
            .push(socket_path.to_string());
        Ok(())
    }

    /// Send a `cancel-streamlocal-forward@openssh.com` global request (OpenSSH
    /// extension) and block until the server replies. `socket_path` must match
    /// a previous successful [`Self::request_streamlocal_forward`].
    pub fn cancel_streamlocal_forward(&mut self, socket_path: &str) -> Result<()> {
        use crate::channel::GlobalRequest;
        let payload = self.conn.send_global_request(
            GlobalRequest::CancelStreamlocalForward {
                socket_path: socket_path.to_string(),
            },
            true,
        );
        self.write_payload(&payload)?;
        let _ = self.await_global_reply("cancel-streamlocal-forward@openssh.com")?;
        if let Some(idx) = self
            .streamlocal_forward_grants
            .iter()
            .position(|p| p == socket_path)
        {
            self.streamlocal_forward_grants.swap_remove(idx);
        }
        Ok(())
    }

    /// Multi-channel event loop. Run after a [`Self::request_tcpip_forward`]
    /// so server-initiated `forwarded-tcpip` channel opens land in
    /// [`ClientHandlers::on_forwarded_tcpip`].
    ///
    /// The loop polls the socket with a small read timeout
    /// (`SERVE_POLL_INTERVAL`, currently 50ms) so it can interleave wire reads
    /// with per-channel egress draining. Returns:
    ///
    /// - `Ok(())` once `handlers.stop` has been set AND every accepted
    ///   channel has been torn down (matching the server's
    ///   `do_connection_loop` exit condition).
    /// - `Err(Error::Protocol(_))` on protocol violation.
    /// - `Err(Error::Io(_))` if the peer hangs up the socket.
    ///
    /// Channel opens whose handler is unset are rejected with
    /// `SSH_OPEN_ADMINISTRATIVELY_PROHIBITED`; unrelated channel-events
    /// (e.g. for `direct-tcpip` channels the user opened via
    /// [`Self::open_direct_tcpip`] before calling `serve`) are NOT
    /// dispatched — those types own their own
    /// [`ClientChannelStream`] which would also try to drain the socket.
    /// In other words: while `serve` is running, no other Client method
    /// may be used on this client.
    pub fn serve(&mut self, handlers: ClientHandlers) -> Result<()> {
        let mut runtimes: BTreeMap<u32, ServeRuntime> = BTreeMap::new();
        let mut pending_opens: BTreeMap<u32, PendingOutboundOpen> = BTreeMap::new();
        // Always poll with a small read timeout so the loop responds to
        // `handlers.stop` even when no channels are open (e.g. between
        // forwarded connections). Reverted on return.
        let _ = self.stream.set_read_timeout(Some(SERVE_POLL_INTERVAL));
        let mut steps = 0usize;
        // Keepalive bookkeeping (ServerAliveInterval / ServerAliveCountMax).
        // `last_activity` advances on every inbound packet; `probes_pending`
        // counts unanswered keepalives. Both are inert when keepalive is off.
        let mut last_activity = Instant::now();
        let mut probes_pending: u32 = 0;
        let result = loop {
            steps += 1;
            if steps > MAX_SERVE_STEPS {
                break Err(Error::Protocol("serve: step cap exceeded"));
            }

            // Keepalive: after `interval` of silence, probe the peer. After
            // `count_max` unanswered probes, treat the connection as dead.
            if let Some((interval, count_max)) = self.keepalive
                && !self.driver.is_kexing()
                && last_activity.elapsed() >= interval
            {
                if probes_pending >= count_max {
                    break Err(Error::Protocol(
                        "serve: server keepalive timed out (ServerAliveCountMax exceeded)",
                    ));
                }
                let probe = self
                    .conn
                    .send_global_request(crate::channel::GlobalRequest::Keepalive, true);
                if let Err(e) = self.write_payload(&probe) {
                    break Err(e);
                }
                probes_pending += 1;
                // Reset the silence timer so we space probes by `interval`
                // rather than spamming once the threshold is first crossed.
                last_activity = Instant::now();
            }

            // Per-tick: process any outbound open requests from external
            // threads (ssh -L listener accepts, etc.). The driver buffers and
            // replays app payloads received during a re-KEX itself, so the
            // frontend no longer tracks a deferred queue.
            if !self.driver.is_kexing()
                && let Some(rx) = handlers.cmd_rx.as_ref()
                && let Err(e) = serve_drain_commands(self, rx, &mut pending_opens)
            {
                break Err(e);
            }

            // Per-tick: ship pending egress from each runtime onto the wire,
            // then reap any runtime whose close has been fully emitted.
            if !self.driver.is_kexing() {
                if let Err(e) = serve_drain_runtimes(self, &mut runtimes) {
                    break Err(e);
                }
                runtimes.retain(|_, rt| !rt.close_sent);
            }

            // Exit when caller asked us to stop AND every channel has been
            // torn down. Without this guard a `stop` mid-handshake would
            // leave the channel in a half-closed state on the peer.
            if handlers.stop.load(Ordering::SeqCst)
                && runtimes.is_empty()
                && pending_opens.is_empty()
            {
                break Ok(());
            }

            // RFC 4253 §9 re-key is driven inside the driver's `handle_timeout`
            // (invoked by `read_one_packet_maybe_timeout` below), so the
            // frontend no longer initiates it explicitly.
            let payload = match self.read_one_packet_maybe_timeout() {
                Ok(Some(p)) => p,
                Ok(None) => continue, // tick; re-enter drain/stop checks
                Err(e) => break Err(e),
            };
            // Any inbound packet — including the keepalive's own
            // REQUEST_SUCCESS/FAILURE reply — proves the peer is alive, so
            // clear the probe counter and restart the silence timer.
            if self.keepalive.is_some() {
                probes_pending = 0;
                last_activity = Instant::now();
            }
            if let Err(e) =
                serve_dispatch_packet(self, &handlers, &mut runtimes, &mut pending_opens, &payload)
            {
                break Err(e);
            }
        };

        // Cleanup: drop any remaining runtimes (closes their ingress mpsc so
        // handler threads see EOF and exit), revert the socket timeout.
        // Pending outbound opens get an Err reply so callers don't hang.
        let stale_opens = core::mem::take(&mut pending_opens);
        for (_ch, po) in stale_opens {
            let _ = po.reply.send(Err(Error::Protocol("serve loop terminated")));
        }
        runtimes.clear();
        let _ = self.stream.set_read_timeout(None);
        result
    }

    /// Like [`Self::read_one_packet`] but returns `Ok(None)` on a read
    /// timeout (the socket's `set_read_timeout` having elapsed) instead of
    /// erroring. Used by [`Self::serve`] to interleave wire reads with
    /// per-channel egress draining, and by the `SharedClient` pump in
    /// short-timeout (interactive) mode to release its inner mutex
    /// between reads so siblings can write.
    pub(crate) fn read_one_packet_maybe_timeout(&mut self) -> Result<Option<Vec<u8>>> {
        match self.read_one_packet() {
            Ok(p) => Ok(Some(p)),
            Err(Error::Io(e))
                if e.kind() == ErrorKind::WouldBlock || e.kind() == ErrorKind::TimedOut =>
            {
                Ok(None)
            }
            Err(e) => Err(e),
        }
    }

    /// Block until the server answers a `GLOBAL_REQUEST` with
    /// `want_reply = true`. Returns the request-specific tail bytes
    /// (empty for requests without a payload).
    fn await_global_reply(&mut self, what: &'static str) -> Result<Vec<u8>> {
        for _ in 0..MAX_EXEC_ITER {
            let payload = self.read_one_packet()?;
            match self.conn.on_packet(&payload)? {
                ChannelEvent::GlobalSuccess { data } => return Ok(data),
                ChannelEvent::GlobalFailure => {
                    let _ = what; // for future tracing
                    return Err(Error::Protocol("global request denied"));
                }
                _ => {}
            }
        }
        Err(Error::Protocol(
            "global request: reply loop did not converge",
        ))
    }

    /// Block until the peer answers a single `CHANNEL_REQUEST` we sent
    /// with `want_reply = true`. Used by [`shell_with_stdin`] to gate the
    /// pty-req → shell handoff.
    ///
    /// [`shell_with_stdin`]: Self::shell_with_stdin
    pub(crate) fn await_request_reply(&mut self, channel: u32, what: &'static str) -> Result<()> {
        for _ in 0..MAX_EXEC_ITER {
            let payload = self.read_one_packet()?;
            match self.conn.on_packet(&payload)? {
                ChannelEvent::Success { channel: c } if c == channel => return Ok(()),
                ChannelEvent::Failure { channel: c } if c == channel => {
                    let _ = what; // for future tracing
                    return Err(Error::Protocol("shell: channel request denied"));
                }
                _ => {}
            }
        }
        Err(Error::Protocol(
            "shell: request-reply loop did not converge",
        ))
    }

    /// Flush every frame the driver has queued for transmission to the wire.
    pub(crate) fn pump_out(&mut self) -> Result<()> {
        while let Some(frame) = self.driver.poll_transmit() {
            self.stream.write_all(&frame)?;
        }
        Ok(())
    }

    /// Read one chunk off the transport and feed it to the driver. Propagates
    /// the socket's `WouldBlock`/`TimedOut` error so timeout-aware callers can
    /// convert it to `Ok(None)`.
    fn read_into_driver(&mut self) -> Result<()> {
        let mut tmp = [0u8; 16 * 1024];
        let n = self.stream.read(&mut tmp)?;
        if n == 0 {
            return Err(Error::Protocol("connection closed"));
        }
        self.driver.handle_input(&tmp[..n], Instant::now())?;
        Ok(())
    }

    /// Pump the transport until the handshake (version exchange + first KEX)
    /// completes.
    fn drive_handshake(&mut self) -> Result<()> {
        for _ in 0..MAX_KEX_STEPS.saturating_mul(MAX_BANNER_LINES + 4) {
            self.pump_out()?;
            while let Some(ev) = self.driver.poll_event() {
                if matches!(ev, Event::HandshakeComplete) {
                    self.pump_out()?;
                    return Ok(());
                }
            }
            self.read_into_driver()?;
        }
        Err(Error::Protocol("kex: too many steps"))
    }

    /// Block until the driver yields the next application payload (post-auth
    /// connection-protocol packet). Transport concerns (KEX, re-key, EXT_INFO,
    /// PING/PONG) are handled inside the driver and never surface here. The
    /// returned bytes are fed to `self.conn` by the caller, exactly as before.
    pub(crate) fn read_one_packet(&mut self) -> Result<Vec<u8>> {
        loop {
            // Tick re-key / keepalive timers before each (possibly blocking or
            // timing-out) read so they advance even when the wire is idle.
            self.driver.handle_timeout(Instant::now())?;
            self.pump_out()?;
            while let Some(ev) = self.driver.poll_event() {
                if let Event::AppData(payload) = ev {
                    self.pump_out()?;
                    return Ok(payload);
                }
                // HandshakeComplete doesn't occur on this (post-handshake) path.
            }
            self.read_into_driver()?;
        }
    }

    /// Encode `payload` and send it. The sans-IO driver owns the codec, so this
    /// queues the frame and flushes the outbound queue immediately (preserving
    /// the old eager-send semantics).
    pub(crate) fn write_payload(&mut self, payload: &[u8]) -> Result<()> {
        self.driver.enqueue_payload(payload)?;
        self.pump_out()
    }

    /// Send a `ping@openssh.com` `SSH2_MSG_PING` carrying `data` over the
    /// transport. The peer answers with a `SSH2_MSG_PONG` echoing `data`,
    /// which the read loop drops. Used as constant-rate "chaff" by the
    /// `ObscureKeystrokeTiming` sender in the `ssh` binary. Must not be
    /// called while a KEX is in flight.
    pub(crate) fn send_transport_ping(&mut self, data: &[u8]) -> Result<()> {
        let ping = encode_ping(data);
        self.write_payload(&ping)
    }
}

/// Read+Write adapter wrapping a single open channel on a [`Client`],
/// driving the underlying SSH packet loop on every `read` / `write`. Used
/// by [`Client::sftp`] to feed [`SftpClient`] a synchronous transport,
/// and by [`Client::open_direct_tcpip`] to expose the channel as a plain
/// byte stream.
///
/// On `Drop` the channel is closed (CHANNEL_CLOSE is sent; the matching
/// peer CLOSE is best-effort drained).
///
/// Extended-data (stderr) is **buffered** rather than dropped — pump_one
/// appends each `SSH_EXTENDED_DATA_STDERR` payload into an internal buffer
/// (still replenishing the window). Callers that want server-side
/// diagnostic output (notably [`Client::scp_send_to`] /
/// [`Client::scp_recv_from`]) drain it via [`Self::take_stderr`]. The SFTP
/// subsystem doesn't emit extended data, so the buffer stays empty there.
pub struct ClientChannelStream<'a> {
    client: &'a mut Client,
    channel: u32,
    read_buf: Vec<u8>,
    stderr_buf: Vec<u8>,
    remote_eof: bool,
    local_close_sent: bool,
}

impl ClientChannelStream<'_> {
    /// Take ownership of any accumulated server-side stderr (extended-data
    /// channel) bytes. Leaves the buffer empty. Used by SCP error paths to
    /// surface the remote `scp` binary's diagnostic output back to the
    /// caller; for SFTP / direct-tcpip channels the buffer is normally
    /// empty.
    pub fn take_stderr(&mut self) -> Vec<u8> {
        core::mem::take(&mut self.stderr_buf)
    }

    /// Drive the SSH packet loop until either `read_buf` has bytes available
    /// or the peer closes the channel. Window-adjust packets are handled
    /// transparently; extended-data (any code) is buffered into
    /// [`Self::stderr_buf`].
    fn pump_one(&mut self) -> std::io::Result<()> {
        let payload = self.client.read_one_packet().map_err(io_err)?;
        let ev = self.client.conn.on_packet(&payload).map_err(io_err)?;
        match ev {
            ChannelEvent::Data { channel, data } if channel == self.channel => {
                let n = data.len() as u32;
                self.read_buf.extend_from_slice(&data);
                if let Some(adj) = self
                    .client
                    .conn
                    .replenish_window(self.channel, n)
                    .map_err(io_err)?
                {
                    self.client.write_payload(&adj).map_err(io_err)?;
                }
            }
            ChannelEvent::ExtendedData {
                channel,
                code: _,
                data,
            } if channel == self.channel => {
                let n = data.len() as u32;
                self.stderr_buf.extend_from_slice(&data);
                if let Some(adj) = self
                    .client
                    .conn
                    .replenish_window(self.channel, n)
                    .map_err(io_err)?
                {
                    self.client.write_payload(&adj).map_err(io_err)?;
                }
            }
            ChannelEvent::Eof { channel } if channel == self.channel => {
                self.remote_eof = true;
            }
            ChannelEvent::Close { channel } if channel == self.channel => {
                self.remote_eof = true;
                if !self.local_close_sent {
                    let p = self.client.conn.send_close(self.channel).map_err(io_err)?;
                    self.client.write_payload(&p).map_err(io_err)?;
                    self.local_close_sent = true;
                }
            }
            _ => {}
        }
        Ok(())
    }
}

impl Read for ClientChannelStream<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        // Block until we have something in the buffer, or the peer is done.
        while self.read_buf.is_empty() && !self.remote_eof {
            self.pump_one()?;
        }
        if self.read_buf.is_empty() {
            return Ok(0);
        }
        let n = core::cmp::min(buf.len(), self.read_buf.len());
        buf[..n].copy_from_slice(&self.read_buf[..n]);
        self.read_buf.drain(..n);
        Ok(n)
    }
}

impl Write for ClientChannelStream<'_> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        // Loop until we manage to put something on the wire. `send_data`
        // returns `taken == 0` when the remote window is full; we then read
        // packets (which will eventually arrive with a WindowAdjust) until
        // it opens.
        loop {
            let (payload, taken) = self
                .client
                .conn
                .send_data(self.channel, buf)
                .map_err(io_err)?;
            if taken > 0 {
                self.client.write_payload(&payload).map_err(io_err)?;
                return Ok(taken);
            }
            // Window full — pump one packet. If the peer closed we can't
            // make progress; surface as broken pipe.
            if self.remote_eof {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    "channel closed by peer mid-write",
                ));
            }
            self.pump_one()?;
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        // All writes are flushed inside `write_payload` via `write_all`.
        Ok(())
    }
}

impl Drop for ClientChannelStream<'_> {
    fn drop(&mut self) {
        // Best-effort tear-down: send EOF + CLOSE, then drain a few packets
        // so the peer's matching CLOSE doesn't get stranded in the inbox.
        if !self.local_close_sent {
            if let Ok(p) = self.client.conn.send_eof(self.channel) {
                let _ = self.client.write_payload(&p);
            }
            if let Ok(p) = self.client.conn.send_close(self.channel) {
                let _ = self.client.write_payload(&p);
            }
            self.local_close_sent = true;
        }
        // Drain up to ~MAX_DRAIN packets so the peer's CLOSE is acknowledged.
        const MAX_DRAIN: usize = 128;
        for _ in 0..MAX_DRAIN {
            if self.remote_eof {
                break;
            }
            if self.pump_one().is_err() {
                break;
            }
        }
    }
}

pub(crate) fn io_err(e: Error) -> std::io::Error {
    match e {
        Error::Io(io) => io,
        other => std::io::Error::other(format!("{:?}", other)),
    }
}

/// Encode a local Unix termios into the RFC 4254 §8 terminal-modes
/// blob expected by the `pty-req` channel request. Each significant
/// opcode is followed by a u32 value; the blob is terminated by
/// `TTY_OP_END = 0`. Pass the result through to
/// the `SharedClient::shell_stream` mirror as the `modes` parameter so
/// the remote PTY mirrors the local control characters (e.g. `^C` to
/// interrupt) and flag set (canonical mode, echo, etc.).
///
/// The full opcode list and wire format live in RFC 4254 §8. We emit
/// the opcodes OpenSSH considers core: control characters
/// `VINTR`/`VQUIT`/…/`VEOL2`, IXON/IXOFF/IXANY, ICANON/ECHO/ISIG and
/// friends, OPOST/ONLCR/OCRNL/ONLRET, CS7/CS8/PARENB/PARODD, plus the
/// two `TTY_OP_*SPEED` bauds. Unknown / non-portable opcodes are
/// skipped — the peer ignores opcodes it doesn't recognise per the
/// RFC.
///
/// Only available on Unix builds with the default `std` feature, since
/// the source `termios` type is itself a libc construct.
#[cfg(all(feature = "std", unix))]
pub fn encode_termios_modes(t: &libc::termios) -> Vec<u8> {
    // Opcode numbers per RFC 4254 §8.
    const TTY_OP_END: u8 = 0;
    const VINTR: u8 = 1;
    const VQUIT: u8 = 2;
    const VERASE: u8 = 3;
    const VKILL: u8 = 4;
    const VEOF: u8 = 5;
    const VEOL: u8 = 6;
    const VEOL2: u8 = 7;
    const VSTART: u8 = 8;
    const VSTOP: u8 = 9;
    const VSUSP: u8 = 10;
    const VREPRINT: u8 = 12;
    const VWERASE: u8 = 13;
    const VLNEXT: u8 = 14;
    const IGNPAR: u8 = 30;
    const PARMRK: u8 = 31;
    const INPCK: u8 = 32;
    const ISTRIP: u8 = 33;
    const INLCR: u8 = 34;
    const IGNCR: u8 = 35;
    const ICRNL: u8 = 36;
    const IXON: u8 = 39;
    const IXANY: u8 = 40;
    const IXOFF: u8 = 41;
    const IMAXBEL: u8 = 42;
    const ISIG: u8 = 50;
    const ICANON: u8 = 51;
    const ECHO: u8 = 53;
    const ECHOE: u8 = 54;
    const ECHOK: u8 = 55;
    const ECHONL: u8 = 56;
    const NOFLSH: u8 = 57;
    const TOSTOP: u8 = 58;
    const IEXTEN: u8 = 59;
    const ECHOCTL: u8 = 60;
    const ECHOKE: u8 = 61;
    const OPOST: u8 = 70;
    const ONLCR: u8 = 72;
    const OCRNL: u8 = 73;
    const ONOCR: u8 = 74;
    const ONLRET: u8 = 75;
    const CS7: u8 = 90;
    const CS8: u8 = 91;
    const PARENB: u8 = 92;
    const PARODD: u8 = 93;
    const TTY_OP_ISPEED: u8 = 128;
    const TTY_OP_OSPEED: u8 = 129;

    let mut out = Vec::with_capacity(128);
    let mut push = |op: u8, val: u32| {
        out.push(op);
        out.extend_from_slice(&val.to_be_bytes());
    };

    // Control characters. Each is one byte in `c_cc`; the wire field
    // is u32 so we zero-extend. Skip if the slot is at the libc
    // sentinel (0xff means "disabled" on Linux/macOS, but we just
    // forward whatever is there — the remote can interpret it).
    let cc = |i: usize| -> u32 { t.c_cc[i] as u32 };
    push(VINTR, cc(libc::VINTR));
    push(VQUIT, cc(libc::VQUIT));
    push(VERASE, cc(libc::VERASE));
    push(VKILL, cc(libc::VKILL));
    push(VEOF, cc(libc::VEOF));
    push(VEOL, cc(libc::VEOL));
    push(VEOL2, cc(libc::VEOL2));
    push(VSTART, cc(libc::VSTART));
    push(VSTOP, cc(libc::VSTOP));
    push(VSUSP, cc(libc::VSUSP));
    push(VREPRINT, cc(libc::VREPRINT));
    push(VWERASE, cc(libc::VWERASE));
    push(VLNEXT, cc(libc::VLNEXT));

    // Input modes. Wire value is 0 (clear) or non-zero (set) per the
    // RFC; we use 1 for set so the peer sees a tidy boolean.
    let iflag = t.c_iflag;
    let bit_i = |mask: libc::tcflag_t| -> u32 { if iflag & mask != 0 { 1 } else { 0 } };
    push(IGNPAR, bit_i(libc::IGNPAR));
    push(PARMRK, bit_i(libc::PARMRK));
    push(INPCK, bit_i(libc::INPCK));
    push(ISTRIP, bit_i(libc::ISTRIP));
    push(INLCR, bit_i(libc::INLCR));
    push(IGNCR, bit_i(libc::IGNCR));
    push(ICRNL, bit_i(libc::ICRNL));
    push(IXON, bit_i(libc::IXON));
    push(IXANY, bit_i(libc::IXANY));
    push(IXOFF, bit_i(libc::IXOFF));
    push(IMAXBEL, bit_i(libc::IMAXBEL));

    // Local modes.
    let lflag = t.c_lflag;
    let bit_l = |mask: libc::tcflag_t| -> u32 { if lflag & mask != 0 { 1 } else { 0 } };
    push(ISIG, bit_l(libc::ISIG));
    push(ICANON, bit_l(libc::ICANON));
    push(ECHO, bit_l(libc::ECHO));
    push(ECHOE, bit_l(libc::ECHOE));
    push(ECHOK, bit_l(libc::ECHOK));
    push(ECHONL, bit_l(libc::ECHONL));
    push(NOFLSH, bit_l(libc::NOFLSH));
    push(TOSTOP, bit_l(libc::TOSTOP));
    push(IEXTEN, bit_l(libc::IEXTEN));
    push(ECHOCTL, bit_l(libc::ECHOCTL));
    push(ECHOKE, bit_l(libc::ECHOKE));

    // Output modes.
    let oflag = t.c_oflag;
    let bit_o = |mask: libc::tcflag_t| -> u32 { if oflag & mask != 0 { 1 } else { 0 } };
    push(OPOST, bit_o(libc::OPOST));
    push(ONLCR, bit_o(libc::ONLCR));
    push(OCRNL, bit_o(libc::OCRNL));
    push(ONOCR, bit_o(libc::ONOCR));
    push(ONLRET, bit_o(libc::ONLRET));

    // Control modes (character size, parity).
    let cflag = t.c_cflag;
    let cs = cflag & libc::CSIZE;
    push(CS7, if cs == libc::CS7 { 1 } else { 0 });
    push(CS8, if cs == libc::CS8 { 1 } else { 0 });
    push(PARENB, if cflag & libc::PARENB != 0 { 1 } else { 0 });
    push(PARODD, if cflag & libc::PARODD != 0 { 1 } else { 0 });

    // Line speeds. The cf*speed accessors require unsafe FFI and the
    // value is cosmetic for a virtual PTY anyway — pin to the RFC's
    // illustrative 38400 baud so no caller has to think about it.
    // (`forbid(unsafe_code)` outside `ffi` rules out the libc path.)
    let _ = t; // suppress unused-binding lint once the cf*speed calls are gone
    push(TTY_OP_ISPEED, 38_400);
    push(TTY_OP_OSPEED, 38_400);

    out.push(TTY_OP_END);
    out
}

/// Build `scp -t [-r] [-p] -- '<dest>'` for [`Client::scp_send_to`].
fn build_scp_to_cmd(remote_dest: &str, opts: &crate::scp::ScpSendOptions) -> Result<String> {
    let quoted = single_quote_for_remote(remote_dest)?;
    let mut s = String::from("scp -t");
    if opts.recursive {
        s.push_str(" -r");
    }
    if opts.preserve_times {
        s.push_str(" -p");
    }
    s.push_str(" -- ");
    s.push_str(&quoted);
    Ok(s)
}

/// Build `scp -f [-r] [-p] -- '<source>'` for [`Client::scp_recv_from`].
fn build_scp_from_cmd(remote_source: &str, opts: &crate::scp::ScpRecvOptions) -> Result<String> {
    let quoted = single_quote_for_remote(remote_source)?;
    let mut s = String::from("scp -f");
    if opts.recursive {
        s.push_str(" -r");
    }
    if opts.preserve_times {
        s.push_str(" -p");
    }
    s.push_str(" -- ");
    s.push_str(&quoted);
    Ok(s)
}

/// Single-quote a remote path for the SSH server's command string.
/// Rejects `'`, `\n`, `\0` — these are characters our own sshd parser
/// can't safely unquote (`'` would terminate the quote; the others can
/// desync most shell parsers). Matches the validation in
/// [`crate::scp::protocol::validate_name`] but on full paths.
fn single_quote_for_remote(p: &str) -> Result<String> {
    if p.contains('\'') {
        return Err(Error::Protocol("scp: remote path contains single quote"));
    }
    if p.contains('\n') {
        return Err(Error::Protocol("scp: remote path contains newline"));
    }
    if p.contains('\0') {
        return Err(Error::Protocol("scp: remote path contains NUL"));
    }
    if p.starts_with('-') {
        return Err(Error::Protocol("scp: remote path starts with '-'"));
    }
    let mut q = String::with_capacity(p.len() + 2);
    q.push('\'');
    q.push_str(p);
    q.push('\'');
    Ok(q)
}

/// Map a [`crate::scp::ScpError`] into the lib's [`Error`] type. Drops
/// the dynamic message string into `Error::Protocol`; the caller has
/// already taken `stream.take_stderr()` so the precise wire error
/// surfaces in `eprintln` rather than the typed error.
fn scp_proto(e: crate::scp::ScpError, _stage: &'static str) -> Error {
    match e {
        crate::scp::ScpError::Io(io) => Error::Io(io),
        crate::scp::ScpError::Remote(_) => Error::Protocol("scp: remote fatal frame"),
        crate::scp::ScpError::Warning(_) => Error::Protocol("scp: remote warning frame"),
        crate::scp::ScpError::BadHeader(_) => Error::Protocol("scp: malformed header"),
        crate::scp::ScpError::BadName(_) => Error::Protocol("scp: invalid name"),
        crate::scp::ScpError::PathEscape => Error::Protocol("scp: path escapes base"),
        crate::scp::ScpError::Unexpected(_) => Error::Protocol("scp: unexpected protocol state"),
    }
}

/// `SHA256:<base64>` fingerprint, matching `ssh-keygen -lf`. Used by the
/// in-tree mismatch warning so the user can manually cross-check the
/// peer's key before deciding to clean up `known_hosts`.
fn fingerprint_b64_sha256(blob: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let d = Sha256::digest(blob);
    let bytes: &[u8] = d.as_ref();
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4 + 7);
    out.push_str("SHA256:");
    let mut i = 0;
    while i + 3 <= bytes.len() {
        let b = ((bytes[i] as u32) << 16) | ((bytes[i + 1] as u32) << 8) | (bytes[i + 2] as u32);
        out.push(ALPHABET[((b >> 18) & 0x3F) as usize] as char);
        out.push(ALPHABET[((b >> 12) & 0x3F) as usize] as char);
        out.push(ALPHABET[((b >> 6) & 0x3F) as usize] as char);
        out.push(ALPHABET[(b & 0x3F) as usize] as char);
        i += 3;
    }
    let rem = bytes.len() - i;
    if rem == 1 {
        let b = (bytes[i] as u32) << 16;
        out.push(ALPHABET[((b >> 18) & 0x3F) as usize] as char);
        out.push(ALPHABET[((b >> 12) & 0x3F) as usize] as char);
    } else if rem == 2 {
        let b = ((bytes[i] as u32) << 16) | ((bytes[i + 1] as u32) << 8);
        out.push(ALPHABET[((b >> 18) & 0x3F) as usize] as char);
        out.push(ALPHABET[((b >> 12) & 0x3F) as usize] as char);
        out.push(ALPHABET[((b >> 6) & 0x3F) as usize] as char);
    }
    out
}

/// Emit OpenSSH's `WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!`
/// banner to stderr, listing every previously-stored fingerprint we
/// would have accepted next to the one the peer is presenting now.
///
/// This is what the user sees on a host-key mismatch regardless of the
/// `on_mismatch` policy: `Reject` then refuses, `AcceptWithWarning`
/// proceeds, `Prompt` asks. The banner itself never changes — only the
/// follow-up wording does.
fn print_mismatch_banner(
    host: &str,
    port: u16,
    expected: &[(String, Vec<u8>)],
    new_key_type: &str,
    new_key_blob: &[u8],
) {
    let target = if port == 22 {
        host.to_string()
    } else {
        format!("[{host}]:{port}")
    };
    eprintln!("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@");
    eprintln!("@    WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!     @");
    eprintln!("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@");
    eprintln!("IT IS POSSIBLE THAT SOMEONE IS DOING SOMETHING NASTY!");
    eprintln!("Someone could be eavesdropping on you right now (man-in-the-middle attack)!");
    eprintln!("It is also possible that a host key has just been changed.");
    eprintln!(
        "The host key for {target} has changed; the known_hosts entry does not match \
         what the server presented."
    );
    if expected.is_empty() {
        eprintln!("Old fingerprint: <none on file>");
    } else {
        for (kt, blob) in expected {
            eprintln!("Old fingerprint: {} ({kt})", fingerprint_b64_sha256(blob));
        }
    }
    eprintln!(
        "New fingerprint: {} ({new_key_type})",
        fingerprint_b64_sha256(new_key_blob),
    );
}

/// Helper: turn an `Option<Vec<String>>` override into an owned list,
/// falling back to the given default slice when `None`.
fn owned_or_default(over: &Option<Vec<String>>, default: &[&str]) -> Vec<String> {
    match over {
        Some(v) => v.clone(),
        None => default.iter().map(|s| s.to_string()).collect(),
    }
}

/// Build the client's advertised KEXINIT, applying any config algorithm
/// overrides over the built-in defaults.
///
/// The strict-kex signalling markers (`kex-strict-{c,s}-v00@openssh.com`)
/// are re-appended here, *after* the (possibly user-supplied) kex list, so a
/// `KexAlgorithms` override can never strip the Terrapin (CVE-2023-48795)
/// mitigation. The non-marker default order is taken from `defaults::KEX`.
pub(crate) fn build_default_kexinit<R: RngCore>(rng: &mut R, over: &AlgoOverrides) -> KexInit {
    // Real (non-marker) kex default order.
    let default_kex: Vec<&str> = defaults::KEX
        .iter()
        .copied()
        .filter(|n| !is_strict_kex_marker(n))
        .collect();

    let mut kex = owned_or_default(&over.kex_algorithms, &default_kex);
    // Re-append the strict-kex markers in their canonical trailing order,
    // skipping any that somehow already slipped in.
    for marker in defaults::KEX.iter().filter(|n| is_strict_kex_marker(n)) {
        if !kex.iter().any(|k| k == marker) {
            kex.push((*marker).to_string());
        }
    }

    let ciphers = owned_or_default(&over.ciphers, defaults::CIPHERS);
    let macs = owned_or_default(&over.macs, defaults::MACS);
    // Host-key algorithms. With no explicit `HostKeyAlgorithms` override we
    // advertise the certificate key-types ahead of the matching plain keys
    // (matching OpenSSH), so a server with a host certificate can offer it.
    // Accepting an offered cert still requires a trusted CA at verify time
    // (`build_verifier` → `verify_host_cert`); merely advertising the name does
    // not weaken host verification. An explicit override is taken verbatim.
    let host_key = match &over.host_key_algorithms {
        Some(v) => v.clone(),
        None => {
            let mut v: Vec<String> = crate::cert::CERT_KEY_NAMES
                .iter()
                .map(|s| s.to_string())
                .collect();
            v.extend(defaults::HOST_KEY.iter().map(|s| s.to_string()));
            v
        }
    };
    // Compression preference. `Compression yes` advertises
    // `zlib@openssh.com` ahead of `none` so we still negotiate a session
    // with a server that lacks zlib. The delayed-zlib variant only starts
    // compressing post-auth (see ConnectionState::activate_compress), which
    // matches OpenSSH. Honoured only with the `compress` feature compiled
    // in; without it, even an explicit request degrades to `none` because
    // the codec has no zlib implementation to install.
    let comp: Vec<String> = if cfg!(feature = "compress") && over.compression == Some(true) {
        vec!["zlib@openssh.com".to_string(), "none".to_string()]
    } else {
        defaults::COMP.iter().map(|s| s.to_string()).collect()
    };

    let algs = KexAlgorithmsOwned {
        kex,
        server_host_key: host_key,
        ciphers_c2s: ciphers.clone(),
        ciphers_s2c: ciphers,
        macs_c2s: macs.clone(),
        macs_s2c: macs,
        comp_c2s: comp.clone(),
        comp_s2c: comp,
        lang_c2s: Vec::new(),
        lang_s2c: Vec::new(),
    };
    let mut cookie = [0u8; 16];
    rng.fill_bytes(&mut cookie);
    KexInit::from_algorithms_owned(algs, cookie)
}

/// Current wall-clock time as Unix seconds, injected into certificate
/// validity checks at the std edge. Falls back to 0 (which fails every
/// not-yet-valid check and is harmless for already-valid certs) on the
/// impossible pre-epoch case.
pub(crate) fn unix_now() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

pub(crate) fn build_verifier(
    reply_payload: &[u8],
    policy: &HostKeyPolicy,
    runner: &KexRunner,
    target_host: &str,
    target_port: u16,
    ca_signature_algorithms: Option<&[String]>,
    now: u64,
) -> Result<Box<dyn HostKeyVerify>> {
    if reply_payload.len() < 5 {
        return Err(Error::Format("kex-ecdh-reply too short"));
    }
    let k_s_len = u32::from_be_bytes([
        reply_payload[1],
        reply_payload[2],
        reply_payload[3],
        reply_payload[4],
    ]) as usize;
    if reply_payload.len() < 5 + k_s_len {
        return Err(Error::Format("kex-ecdh-reply truncated"));
    }
    let k_s = &reply_payload[5..5 + k_s_len];

    // Reject misconfigured KnownHosts callers *before* we touch the KEX
    // runner state — the missing-host case is a config error, not a
    // protocol error, regardless of where in the connect we are.
    if matches!(policy, HostKeyPolicy::KnownHosts(_))
        && (target_host.is_empty() || target_port == 0)
    {
        return Err(Error::Config(
            "HostKeyPolicy::KnownHosts requires Client::connect_to_host",
        ));
    }

    let neg = runner
        .negotiated()
        .ok_or(Error::Protocol("kex: no negotiated algorithms"))?;

    // Certificate host keys: `k_s` is an OpenSSH certificate, not a plain key.
    // Parse it, enforce type/validity/critical-options, then make the trust
    // decision per policy. The signature over `H` is verified against the
    // certificate's EMBEDDED key (built below); the CA signature ties the
    // embedded key to a trusted CA.
    if crate::cert::is_cert_name(&neg.host_key) {
        let cert = crate::cert::Certificate::parse(k_s)?;
        let ca_algos: Vec<&str> = match ca_signature_algorithms {
            Some(list) => list.iter().map(|s| s.as_str()).collect(),
            None => crate::config::algos::CA_SIGNATURE_DEFAULTS.to_vec(),
        };
        match policy {
            // No host verification requested: still parse and enforce the
            // cert's own constraints (type/validity/critical-options) but do
            // not require CA trust. `H` is verified against the embedded key.
            HostKeyPolicy::AcceptAny => {
                cert.check_type(crate::cert::CertType::Host)?;
                cert.check_validity(now)?;
                cert.require_known_critical_options()?;
            }
            // Pin the whole certificate blob by fingerprint.
            HostKeyPolicy::AcceptFingerprint(fp) => {
                let digest = Sha256::digest(k_s);
                if digest.as_ref() != fp {
                    return Err(Error::HostKeyRejected);
                }
                cert.check_type(crate::cert::CertType::Host)?;
                cert.check_validity(now)?;
                cert.require_known_critical_options()?;
            }
            // Trust via known_hosts `@cert-authority` (and `@revoked`).
            HostKeyPolicy::KnownHosts(kh) => {
                let store = kh.store.lock().map_err(|_| Error::HostKeyRejected)?;
                store.verify_host_cert(target_host, target_port, &cert, &ca_algos, now)?;
            }
        }
        // Build the exchange-hash verifier from the cert's embedded key, keyed
        // on the negotiated cert name (which pins the RSA hash).
        return host_key_verify_by_name(&neg.host_key, k_s);
    }

    match policy {
        HostKeyPolicy::AcceptAny => {}
        HostKeyPolicy::AcceptFingerprint(fp) => {
            let digest = Sha256::digest(k_s);
            if digest.as_ref() != fp {
                return Err(Error::HostKeyRejected);
            }
        }
        HostKeyPolicy::KnownHosts(kh) => {
            // Host-empty / port-zero already rejected above. Past this
            // point we have a real (host, port) pair, so the lookup can
            // proceed.
            let mut store = kh.store.lock().map_err(|_| Error::HostKeyRejected)?;
            let lookup = store.lookup(target_host, target_port, &neg.host_key, k_s);
            match lookup {
                LookupResult::Match => {}
                LookupResult::Mismatch { expected } => {
                    // ALWAYS print the OpenSSH-style loud banner on
                    // mismatch, before any policy decision. Shows both
                    // the previously-stored ("old") fingerprint(s) and
                    // the new one the peer just presented so the user
                    // can spot the change without digging through
                    // known_hosts manually.
                    print_mismatch_banner(target_host, target_port, &expected, &neg.host_key, k_s);

                    let accept = match &kh.on_mismatch {
                        TofuAction::Reject => false,
                        TofuAction::Accept => true,
                        TofuAction::AcceptWithWarning => {
                            // StrictHostKeyChecking=no: OpenSSH accepts
                            // for the current session but does NOT
                            // rotate the stored key. We follow suit —
                            // the warning was printed above; nothing
                            // touches the store.
                            eprintln!(
                                "Connecting anyway because StrictHostKeyChecking is set to no; \
                                 the trusted entry in known_hosts is NOT being updated."
                            );
                            true
                        }
                        TofuAction::Prompt(cb) => {
                            // Drop the lock for the duration of the
                            // callback — it may block on stdin and
                            // shouldn't hold up other policy users.
                            // The loud banner was already printed above
                            // so the callback only needs to ask the
                            // accept/refuse question.
                            drop(store);
                            let ok = cb(target_host, target_port, &neg.host_key, k_s);
                            store = kh.store.lock().map_err(|_| Error::HostKeyRejected)?;
                            ok
                        }
                    };
                    if !accept {
                        return Err(Error::HostKeyRejected);
                    }
                    // Only rotate the stored entry when the policy is a
                    // prompt that explicitly returned `true` — i.e. the
                    // user typed `yes`. `AcceptWithWarning` (the
                    // StrictHostKeyChecking=no path) deliberately
                    // leaves the store untouched: OpenSSH does the same.
                    if matches!(&kh.on_mismatch, TofuAction::Accept | TofuAction::Prompt(_)) {
                        // Replace the existing entries so future
                        // connects don't keep tripping the mismatch
                        // path. Honours the same hash-new / save-path
                        // knobs as the Unknown path.
                        let _ = store.remove(target_host, target_port);
                        store.add(target_host, target_port, &neg.host_key, k_s, kh.hash_new);
                        if let Some(path) = &kh.save_path {
                            store.save(path).map_err(Error::from)?;
                        }
                    }
                }
                LookupResult::Unknown => {
                    let accept = match &kh.on_unknown {
                        TofuAction::Reject => false,
                        TofuAction::Accept | TofuAction::AcceptWithWarning => true,
                        TofuAction::Prompt(cb) => {
                            // Drop the lock for the duration of the
                            // callback — it may block on stdin and
                            // shouldn't hold up other policy users.
                            drop(store);
                            let ok = cb(target_host, target_port, &neg.host_key, k_s);
                            store = kh.store.lock().map_err(|_| Error::HostKeyRejected)?;
                            ok
                        }
                    };
                    if !accept {
                        return Err(Error::HostKeyRejected);
                    }
                    store.add(target_host, target_port, &neg.host_key, k_s, kh.hash_new);
                    if let Some(path) = &kh.save_path {
                        store.save(path).map_err(Error::from)?;
                    }
                }
            }
        }
    }

    host_key_verify_by_name(&neg.host_key, k_s)
}

/// Pull every queued [`ServeCommand`] from `cmd_rx` (non-blocking) and
/// kick off the matching outbound open. The serve loop then waits for
/// `OpenConfirmed` / `OpenFailed` in [`serve_dispatch_packet`].
///
/// Errors here propagate out of [`Client::serve`] — they indicate a
/// failure to encode/transmit a CHANNEL_OPEN, not a peer rejection
/// (which arrives as a normal `OpenFailed` event).
fn serve_drain_commands(
    client: &mut Client,
    cmd_rx: &Receiver<ServeCommand>,
    pending_opens: &mut BTreeMap<u32, PendingOutboundOpen>,
) -> Result<()> {
    loop {
        match cmd_rx.try_recv() {
            Ok(ServeCommand::OpenDirectTcpip {
                dest_host,
                dest_port,
                orig_host,
                orig_port,
                reply,
            }) => {
                let (local_id, open_payload) = client.conn.open(ChannelOpen::DirectTcpip {
                    dest_host,
                    dest_port: dest_port as u32,
                    orig_host,
                    orig_port: orig_port as u32,
                })?;
                client.write_payload(&open_payload)?;
                let (ingress_tx, ingress_rx) = mpsc::channel::<Option<Vec<u8>>>();
                let (egress_tx, egress_rx) =
                    mpsc::sync_channel::<ChannelEgress>(SERVE_EGRESS_BACKLOG);
                let stream = ChannelStream::new(ingress_rx, egress_tx);
                pending_opens.insert(
                    local_id,
                    PendingOutboundOpen {
                        stream: Some(stream),
                        ingress_tx,
                        egress_rx: Some(egress_rx),
                        reply,
                    },
                );
            }
            Ok(ServeCommand::OpenDirectStreamlocal { socket_path, reply }) => {
                let (local_id, open_payload) =
                    client.conn.open(ChannelOpen::DirectStreamlocal { socket_path })?;
                client.write_payload(&open_payload)?;
                let (ingress_tx, ingress_rx) = mpsc::channel::<Option<Vec<u8>>>();
                let (egress_tx, egress_rx) =
                    mpsc::sync_channel::<ChannelEgress>(SERVE_EGRESS_BACKLOG);
                let stream = ChannelStream::new(ingress_rx, egress_tx);
                pending_opens.insert(
                    local_id,
                    PendingOutboundOpen {
                        stream: Some(stream),
                        ingress_tx,
                        egress_rx: Some(egress_rx),
                        reply,
                    },
                );
            }
            Err(TryRecvError::Empty) => break,
            Err(TryRecvError::Disconnected) => break,
        }
    }
    Ok(())
}

fn serve_drain_runtimes(
    client: &mut Client,
    runtimes: &mut BTreeMap<u32, ServeRuntime>,
) -> Result<()> {
    let channels: Vec<u32> = runtimes.keys().copied().collect();
    for ch in channels {
        let Some(rt) = runtimes.get_mut(&ch) else {
            continue;
        };
        if rt.close_sent {
            continue;
        }

        // 1) Re-attempt any leftover bytes from last tick.
        if !rt.pending_data.is_empty() {
            let leftover = core::mem::take(&mut rt.pending_data);
            emit_serve_data(client, ch, &leftover, rt)?;
            if !rt.pending_data.is_empty() {
                // Still window-blocked; skip this tick's drain entirely.
                continue;
            }
        }

        // 2) Pull as many egress messages as we can without blocking.
        loop {
            if !rt.pending_data.is_empty() {
                break;
            }
            match rt.egress_rx.try_recv() {
                Ok(ChannelEgress::Data(bytes)) => {
                    emit_serve_data(client, ch, &bytes, rt)?;
                }
                Ok(ChannelEgress::Eof) => {
                    rt.pending_eof = true;
                    break;
                }
                Ok(ChannelEgress::Close) => {
                    rt.pending_close = true;
                    break;
                }
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => {
                    // Handler thread vanished without an explicit Close;
                    // synthesise one so the channel still tears down cleanly.
                    rt.pending_close = true;
                    break;
                }
            }
        }

        // 3) Emit EOF / Close if we have them pending and all data shipped.
        if rt.pending_data.is_empty() {
            if rt.pending_eof && !rt.eof_sent {
                let p = client.conn.send_eof(ch)?;
                client.write_payload(&p)?;
                rt.eof_sent = true;
            }
            if rt.pending_close && !rt.close_sent {
                if !rt.eof_sent {
                    let p = client.conn.send_eof(ch)?;
                    client.write_payload(&p)?;
                    rt.eof_sent = true;
                }
                let p = client.conn.send_close(ch)?;
                client.write_payload(&p)?;
                rt.close_sent = true;
            }
        }
    }
    Ok(())
}

/// Ship `bytes` over `CHANNEL_DATA`, stashing anything the remote window
/// can't accept onto `rt.pending_data` for next tick.
fn emit_serve_data(
    client: &mut Client,
    channel: u32,
    bytes: &[u8],
    rt: &mut ServeRuntime,
) -> Result<()> {
    let mut off = 0usize;
    while off < bytes.len() {
        let (payload, taken) = client.conn.send_data(channel, &bytes[off..])?;
        if taken == 0 {
            rt.pending_data.extend_from_slice(&bytes[off..]);
            return Ok(());
        }
        client.write_payload(&payload)?;
        off += taken;
    }
    Ok(())
}

/// Process one inbound app-layer packet for [`Client::serve`].
///
/// Mirrors the server-side `dispatch_app_packet`: routes peer-initiated
/// channel opens to the matching [`ClientHandlers`] callback (or rejects),
/// fans Data/Eof/Close into the matching runtime, replenishes the SSH
/// receive window, and emits our half-close in response to peer Close.
fn serve_dispatch_packet(
    client: &mut Client,
    handlers: &ClientHandlers,
    runtimes: &mut BTreeMap<u32, ServeRuntime>,
    pending_opens: &mut BTreeMap<u32, PendingOutboundOpen>,
    payload: &[u8],
) -> Result<()> {
    let ev = client.conn.on_packet(payload)?;
    match ev {
        ChannelEvent::OpenConfirmed { channel } => {
            // Caller-initiated open succeeded: hand the pre-built stream
            // to the requester, and promote bookkeeping to a ServeRuntime.
            if let Some(mut po) = pending_opens.remove(&channel) {
                let stream = po
                    .stream
                    .take()
                    .ok_or(Error::Protocol("pending open: stream taken twice"))?;
                let egress_rx = po
                    .egress_rx
                    .take()
                    .ok_or(Error::Protocol("pending open: egress taken twice"))?;
                // If the caller hung up before we got here, just close.
                if po.reply.send(Ok(stream)).is_err() {
                    let p = client.conn.send_close(channel)?;
                    client.write_payload(&p)?;
                    return Ok(());
                }
                runtimes.insert(
                    channel,
                    ServeRuntime {
                        ingress_tx: po.ingress_tx,
                        egress_rx,
                        pending_data: Vec::new(),
                        pending_eof: false,
                        pending_close: false,
                        eof_sent: false,
                        close_sent: false,
                    },
                );
            }
        }
        ChannelEvent::OpenFailed { channel, .. } => {
            if let Some(po) = pending_opens.remove(&channel) {
                let _ = po
                    .reply
                    .send(Err(Error::Protocol("direct-tcpip: open failed")));
            }
        }
        ChannelEvent::OpenRequest { channel, kind } => match kind {
            ChannelOpen::ForwardedTcpip {
                dest_host,
                dest_port,
                orig_host,
                orig_port,
            } => {
                // Defence-in-depth: a `forwarded-tcpip` open must correlate
                // to a forward the client actually requested. We reject the
                // open if there are zero outstanding `tcpip-forward` grants
                // (an unsolicited forward when none were requested). This is
                // deliberately conservative — the server may echo a bind
                // address/port that doesn't textually match the request, so
                // a stricter per-binding match could reject legitimate
                // forwards. Callers needing exact correlation should also
                // check `origin` in their callback.
                if client.tcpip_forward_grants.is_empty() {
                    let p = client.conn.reject_open(
                        channel,
                        SSH_OPEN_ADMINISTRATIVELY_PROHIBITED,
                        "no tcpip-forward requested",
                        "",
                    )?;
                    client.write_payload(&p)?;
                    return Ok(());
                }
                if let Some(cb) = handlers.on_forwarded_tcpip.clone() {
                    let p = client.conn.accept_open(channel)?;
                    client.write_payload(&p)?;

                    let (ingress_tx, ingress_rx) = mpsc::channel::<Option<Vec<u8>>>();
                    let (egress_tx, egress_rx) =
                        mpsc::sync_channel::<ChannelEgress>(SERVE_EGRESS_BACKLOG);
                    let cs = ChannelStream::new(ingress_rx, egress_tx);
                    let origin = ForwardedTcpipOrigin {
                        bound_address: dest_host,
                        bound_port: clamp_u16(dest_port),
                        orig_address: orig_host,
                        orig_port: clamp_u16(orig_port),
                    };
                    thread::spawn(move || {
                        cb(origin, cs);
                    });
                    runtimes.insert(
                        channel,
                        ServeRuntime {
                            ingress_tx,
                            egress_rx,
                            pending_data: Vec::new(),
                            pending_eof: false,
                            pending_close: false,
                            eof_sent: false,
                            close_sent: false,
                        },
                    );
                } else {
                    let p = client.conn.reject_open(
                        channel,
                        SSH_OPEN_ADMINISTRATIVELY_PROHIBITED,
                        "forwarded-tcpip not enabled",
                        "",
                    )?;
                    client.write_payload(&p)?;
                }
            }
            ChannelOpen::ForwardedStreamlocal { socket_path } => {
                // Same conservative defence-in-depth as `forwarded-tcpip`: a
                // `forwarded-streamlocal@openssh.com` open must correlate to a
                // streamlocal-forward the client actually requested. Reject if
                // there are zero outstanding grants.
                if client.streamlocal_forward_grants.is_empty() {
                    let p = client.conn.reject_open(
                        channel,
                        SSH_OPEN_ADMINISTRATIVELY_PROHIBITED,
                        "no streamlocal-forward requested",
                        "",
                    )?;
                    client.write_payload(&p)?;
                    return Ok(());
                }
                if let Some(cb) = handlers.on_forwarded_streamlocal.clone() {
                    let p = client.conn.accept_open(channel)?;
                    client.write_payload(&p)?;

                    let (ingress_tx, ingress_rx) = mpsc::channel::<Option<Vec<u8>>>();
                    let (egress_tx, egress_rx) =
                        mpsc::sync_channel::<ChannelEgress>(SERVE_EGRESS_BACKLOG);
                    let cs = ChannelStream::new(ingress_rx, egress_tx);
                    let origin = ForwardedStreamlocalOrigin { socket_path };
                    thread::spawn(move || {
                        cb(origin, cs);
                    });
                    runtimes.insert(
                        channel,
                        ServeRuntime {
                            ingress_tx,
                            egress_rx,
                            pending_data: Vec::new(),
                            pending_eof: false,
                            pending_close: false,
                            eof_sent: false,
                            close_sent: false,
                        },
                    );
                } else {
                    let p = client.conn.reject_open(
                        channel,
                        SSH_OPEN_ADMINISTRATIVELY_PROHIBITED,
                        "forwarded-streamlocal not enabled",
                        "",
                    )?;
                    client.write_payload(&p)?;
                }
            }
            ChannelOpen::AuthAgent => {
                if let Some(cb) = handlers.on_auth_agent.clone() {
                    let p = client.conn.accept_open(channel)?;
                    client.write_payload(&p)?;

                    let (ingress_tx, ingress_rx) = mpsc::channel::<Option<Vec<u8>>>();
                    let (egress_tx, egress_rx) =
                        mpsc::sync_channel::<ChannelEgress>(SERVE_EGRESS_BACKLOG);
                    let cs = ChannelStream::new(ingress_rx, egress_tx);
                    thread::spawn(move || {
                        cb(cs);
                    });
                    runtimes.insert(
                        channel,
                        ServeRuntime {
                            ingress_tx,
                            egress_rx,
                            pending_data: Vec::new(),
                            pending_eof: false,
                            pending_close: false,
                            eof_sent: false,
                            close_sent: false,
                        },
                    );
                } else {
                    let p = client.conn.reject_open(
                        channel,
                        SSH_OPEN_ADMINISTRATIVELY_PROHIBITED,
                        "auth-agent not enabled",
                        "",
                    )?;
                    client.write_payload(&p)?;
                }
            }
            ChannelOpen::X11 {
                orig_host: _,
                orig_port: _,
            } => {
                if let Some(cb) = handlers.on_x11.clone() {
                    let p = client.conn.accept_open(channel)?;
                    client.write_payload(&p)?;

                    let (ingress_tx, ingress_rx) = mpsc::channel::<Option<Vec<u8>>>();
                    let (egress_tx, egress_rx) =
                        mpsc::sync_channel::<ChannelEgress>(SERVE_EGRESS_BACKLOG);
                    let cs = ChannelStream::new(ingress_rx, egress_tx);
                    thread::spawn(move || {
                        cb(cs);
                    });
                    runtimes.insert(
                        channel,
                        ServeRuntime {
                            ingress_tx,
                            egress_rx,
                            pending_data: Vec::new(),
                            pending_eof: false,
                            pending_close: false,
                            eof_sent: false,
                            close_sent: false,
                        },
                    );
                } else {
                    let p = client.conn.reject_open(
                        channel,
                        SSH_OPEN_ADMINISTRATIVELY_PROHIBITED,
                        "x11 not enabled",
                        "",
                    )?;
                    client.write_payload(&p)?;
                }
            }
            _ => {
                let p = client.conn.reject_open(
                    channel,
                    SSH_OPEN_ADMINISTRATIVELY_PROHIBITED,
                    "channel type not supported",
                    "",
                )?;
                client.write_payload(&p)?;
            }
        },
        ChannelEvent::Data { channel, data } => {
            if let Some(rt) = runtimes.get_mut(&channel) {
                let _ = rt.ingress_tx.send(Some(data.clone()));
            }
            if let Some(adj) = client.conn.replenish_window(channel, data.len() as u32)? {
                client.write_payload(&adj)?;
            }
        }
        ChannelEvent::ExtendedData { channel, data, .. } => {
            // forwarded-tcpip channels shouldn't carry extended-data, but if
            // we get any, just credit the window and drop the bytes.
            if let Some(adj) = client.conn.replenish_window(channel, data.len() as u32)? {
                client.write_payload(&adj)?;
            }
        }
        ChannelEvent::Eof { channel } => {
            if let Some(rt) = runtimes.get_mut(&channel) {
                // None = EOF marker; the handler's `Read::read` returns
                // `Ok(0)` next time it drains its buffer.
                let _ = rt.ingress_tx.send(None);
            }
        }
        ChannelEvent::Close { channel } => {
            if let Some(ch) = client.conn.channel(channel)
                && !ch.local_closed
            {
                let p = client.conn.send_close(channel)?;
                client.write_payload(&p)?;
            }
            // Dropping the runtime closes `ingress_tx`; the handler thread's
            // next `Read` returns `Ok(0)` and the thread exits.
            runtimes.remove(&channel);
        }
        // The peer may send its own keepalive (or any other global request)
        // at us; per RFC 4254 §4 a request we don't act on still needs a
        // REQUEST_FAILURE when want_reply is set, which is exactly what
        // OpenSSH's keepalive probe expects back. Reading the packet already
        // refreshed our own keepalive timer above.
        ChannelEvent::GlobalRequest {
            want_reply: true, ..
        } => {
            let p = client.conn.send_global_failure();
            client.write_payload(&p)?;
        }
        // Other events (OpenConfirmed/Failed for opens *we* initiated,
        // Request, GlobalSuccess/GlobalFailure for our keepalive probes,
        // etc.) need no action here — the keepalive bookkeeping in `serve`
        // already cleared on the inbound read. Silently drop.
        _ => {}
    }
    Ok(())
}

/// Saturating cast from the wire-format u32 port to a u16. The SSH spec
/// allows u32 but only 0..=65535 are meaningful; clamp rather than failing
/// so the handler still gets called with a sensible value.
fn clamp_u16(v: u32) -> u16 {
    if v > u16::MAX as u32 {
        u16::MAX
    } else {
        v as u16
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hostkey::Ed25519HostKey;
    use crate::transport::version::LOCAL_VERSION;
    use crate::transport::{PacketCodec, Role, VersionExchange};
    use purecrypto::rng::OsRng;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::thread;

    // Transport-engine details the in-process fake-server harness below needs.
    // (The driver owns these in production; the tests hand-roll a server.)
    const SSH_MSG_KEX_ECDH_REPLY: u8 = 31;
    const MAX_INBOX_BYTES: usize = 8 * 1024 * 1024;

    /// Read one `\n`-terminated line from `stream` into `buf` (test helper for
    /// the fake server's version-exchange step).
    fn read_line<S: Read>(stream: &mut S, buf: &mut Vec<u8>, max_len: usize) -> Result<()> {
        let mut byte = [0u8; 1];
        loop {
            let n = stream.read(&mut byte)?;
            if n == 0 {
                return Err(Error::Protocol("connection closed before newline"));
            }
            buf.push(byte[0]);
            if byte[0] == b'\n' {
                return Ok(());
            }
            if buf.len() >= max_len {
                return Err(Error::Protocol("banner line too long"));
            }
        }
    }

    #[test]
    fn config_insecure_constructor_is_accept_any() {
        // `Config::insecure()` replaces the old `Default` impl. The trust
        // decision now has to be spelled out explicitly at the call site;
        // see `Config::with_known_hosts` for the strict alternative.
        let cfg = Config::insecure();
        assert!(matches!(cfg.host_key_policy, HostKeyPolicy::AcceptAny));
        assert!(cfg.timeout.is_none());
    }

    #[test]
    fn known_hosts_strict_constructor_defaults_reject_reject() {
        // Sanity-check that the convenience constructor doesn't pick up
        // an `Accept*` variant accidentally.
        let store = Arc::new(Mutex::new(KnownHosts::new()));
        let p = KnownHostsPolicy::strict(store);
        assert!(matches!(p.on_unknown, TofuAction::Reject));
        assert!(matches!(p.on_mismatch, TofuAction::Reject));
        assert!(!p.hash_new);
        assert!(p.save_path.is_none());
    }

    #[test]
    fn build_verifier_fails_hard_on_empty_host() {
        // Synthesise the minimum to drive build_verifier with a
        // KnownHosts policy and an empty target_host. The KEX runner /
        // reply payload don't get inspected because the host check
        // fires first.
        use crate::transport::kex::KexAlgorithms;
        use crate::transport::{KexInit, KexRunner};
        let store = Arc::new(Mutex::new(KnownHosts::new()));
        let policy = HostKeyPolicy::KnownHosts(KnownHostsPolicy::strict(store));
        // Drive runner just enough to have a negotiated()-returning state
        // is not actually needed for this branch — the empty-host check
        // fires first. Build a dummy runner that we never call into.
        let runner = KexRunner::new(
            Role::Client,
            KexInit::from_algorithms(
                &KexAlgorithms {
                    kex: defaults::KEX,
                    server_host_key: defaults::HOST_KEY,
                    ciphers_c2s: defaults::CIPHERS,
                    ciphers_s2c: defaults::CIPHERS,
                    macs_c2s: defaults::MACS,
                    macs_s2c: defaults::MACS,
                    comp_c2s: defaults::COMP,
                    comp_s2c: defaults::COMP,
                    lang_c2s: &[],
                    lang_s2c: &[],
                },
                [0u8; 16],
            ),
        );
        // Provide a reply payload of the minimum shape (5 bytes header +
        // a 0-byte K_S). The host-empty branch fires before negotiated()
        // is consulted, so we don't need a real KEX outcome.
        let mut reply = vec![SSH_MSG_KEX_ECDH_REPLY];
        reply.extend_from_slice(&0u32.to_be_bytes());
        let err = build_verifier(&reply, &policy, &runner, "", 22, None, 0);
        assert!(matches!(err, Err(Error::Config(_))));
        let err = build_verifier(&reply, &policy, &runner, "host", 0, None, 0);
        assert!(matches!(err, Err(Error::Config(_))));
    }

    #[test]
    fn exec_output_constructible() {
        let _ = ExecOutput {
            stdout: Vec::new(),
            stderr: Vec::new(),
            exit_status: Some(0),
            exit_signal: None,
        };
    }

    fn run_server(
        listener: TcpListener,
        host_key_seed: [u8; 32],
    ) -> thread::JoinHandle<std::result::Result<Vec<u8>, String>> {
        thread::spawn(move || -> std::result::Result<Vec<u8>, String> {
            let (mut s, _) = listener.accept().map_err(|e| e.to_string())?;
            let server_hk = Ed25519HostKey::from_seed(host_key_seed);

            s.write_all(&VersionExchange::outgoing_bytes())
                .map_err(|e| e.to_string())?;
            let mut line = Vec::new();
            let v_c: Vec<u8> = {
                read_line(&mut s, &mut line, 1024).map_err(|e| format!("{e:?}"))?;
                if !line.starts_with(b"SSH-") {
                    return Err("client did not send SSH banner".into());
                }
                let parsed = VersionExchange::parse_remote(&line).map_err(|e| format!("{e:?}"))?;
                parsed.into_bytes()
            };
            let v_s = LOCAL_VERSION.as_bytes().to_vec();

            let mut codec = PacketCodec::new();
            // This minimal test server holds a single plain Ed25519 host key, so
            // it must advertise only that algorithm — not the certificate
            // key-types the client builder lists by default (which would let
            // negotiation pick a cert name this server cannot satisfy).
            let server_over = AlgoOverrides {
                host_key_algorithms: Some(vec!["ssh-ed25519".to_string()]),
                ..Default::default()
            };
            let advert = build_default_kexinit(&mut OsRng, &server_over);
            let mut runner = KexRunner::new(Role::Server, advert);

            let mut inbox: Vec<u8> = Vec::new();
            let mut rng = OsRng;

            let initial = runner.start(&mut rng).map_err(|e| format!("{e:?}"))?;
            for p in initial.outbound {
                let frame = codec.encode(&p, &mut rng).map_err(|e| format!("{e:?}"))?;
                s.write_all(&frame).map_err(|e| e.to_string())?;
            }

            let mut steps = 0;
            loop {
                steps += 1;
                if steps > MAX_KEX_STEPS {
                    return Err("server kex did not converge".into());
                }
                let payload = read_one_packet_local(&mut s, &mut codec, &mut inbox)
                    .map_err(|e| format!("{e:?}"))?;
                let adv = runner
                    .on_packet(
                        &mut rng,
                        &mut codec,
                        &payload,
                        Some(&server_hk),
                        None,
                        &v_c,
                        &v_s,
                    )
                    .map_err(|e| format!("{e:?}"))?;
                for p in adv.outbound {
                    let frame = codec.encode(&p, &mut rng).map_err(|e| format!("{e:?}"))?;
                    s.write_all(&frame).map_err(|e| e.to_string())?;
                }
                if adv.completed {
                    break;
                }
            }

            let sid = runner.session_id().unwrap().to_vec();
            Ok(sid)
        })
    }

    fn read_one_packet_local(
        s: &mut TcpStream,
        codec: &mut PacketCodec,
        inbox: &mut Vec<u8>,
    ) -> Result<Vec<u8>> {
        loop {
            if let Some((payload, consumed)) = codec.decode(inbox)? {
                inbox.drain(..consumed);
                return Ok(payload);
            }
            let mut tmp = [0u8; 4096];
            let n = s.read(&mut tmp)?;
            if n == 0 {
                return Err(Error::Protocol("connection closed"));
            }
            inbox.extend_from_slice(&tmp[..n]);
            if inbox.len() > MAX_INBOX_BYTES {
                return Err(Error::Protocol("inbound buffer too large"));
            }
        }
    }

    #[test]
    fn handshake_over_real_loopback_socket() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let mut seed = [0u8; 32];
        OsRng.fill_bytes(&mut seed);
        let server = run_server(listener, seed);

        let client = Client::connect(addr, Config::insecure()).expect("client connect");
        let server_sid = server.join().unwrap().expect("server handshake");
        assert_eq!(client.session_id(), server_sid.as_slice());
        assert!(!client.session_id().is_empty());
    }

    /// Drive the *client* read loop to answer a `ping@openssh.com` PING with
    /// a PONG echoing the data. A minimal loopback server completes KEX, sends
    /// an encrypted `SSH2_MSG_PING`, and asserts the client replies with the
    /// matching `SSH2_MSG_PONG`. Also confirms the client's read loop drops a
    /// stray inbound PONG (we send one before the PING and the client never
    /// surfaces it).
    #[test]
    fn client_answers_ping_with_pong() {
        use crate::transport::ping::{SSH_MSG_PONG, encode_ping, encode_pong};

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let mut seed = [0u8; 32];
        OsRng.fill_bytes(&mut seed);

        let server = thread::spawn(move || -> std::result::Result<Vec<u8>, String> {
            let (mut s, _) = listener.accept().map_err(|e| e.to_string())?;
            let server_hk = Ed25519HostKey::from_seed(seed);

            s.write_all(&VersionExchange::outgoing_bytes())
                .map_err(|e| e.to_string())?;
            let mut line = Vec::new();
            let v_c: Vec<u8> = {
                read_line(&mut s, &mut line, 1024).map_err(|e| format!("{e:?}"))?;
                let parsed = VersionExchange::parse_remote(&line).map_err(|e| format!("{e:?}"))?;
                parsed.into_bytes()
            };
            let v_s = LOCAL_VERSION.as_bytes().to_vec();

            let mut codec = PacketCodec::new();
            let server_over = AlgoOverrides {
                host_key_algorithms: Some(vec!["ssh-ed25519".to_string()]),
                ..Default::default()
            };
            let advert = build_default_kexinit(&mut OsRng, &server_over);
            let mut runner = KexRunner::new(Role::Server, advert);
            let mut inbox: Vec<u8> = Vec::new();
            let mut rng = OsRng;

            let initial = runner.start(&mut rng).map_err(|e| format!("{e:?}"))?;
            for p in initial.outbound {
                let frame = codec.encode(&p, &mut rng).map_err(|e| format!("{e:?}"))?;
                s.write_all(&frame).map_err(|e| e.to_string())?;
            }
            let mut steps = 0;
            loop {
                steps += 1;
                if steps > MAX_KEX_STEPS {
                    return Err("server kex did not converge".into());
                }
                let payload = read_one_packet_local(&mut s, &mut codec, &mut inbox)
                    .map_err(|e| format!("{e:?}"))?;
                let adv = runner
                    .on_packet(
                        &mut rng,
                        &mut codec,
                        &payload,
                        Some(&server_hk),
                        None,
                        &v_c,
                        &v_s,
                    )
                    .map_err(|e| format!("{e:?}"))?;
                for p in adv.outbound {
                    let frame = codec.encode(&p, &mut rng).map_err(|e| format!("{e:?}"))?;
                    s.write_all(&frame).map_err(|e| e.to_string())?;
                }
                if adv.completed {
                    break;
                }
            }

            // Post-KEX: send a stray PONG (client must drop it), then a PING.
            let stray = encode_pong(b"unsolicited");
            let frame = codec
                .encode(&stray, &mut rng)
                .map_err(|e| format!("{e:?}"))?;
            s.write_all(&frame).map_err(|e| e.to_string())?;
            let ping = encode_ping(b"chaff-1234");
            let frame = codec
                .encode(&ping, &mut rng)
                .map_err(|e| format!("{e:?}"))?;
            s.write_all(&frame).map_err(|e| e.to_string())?;

            // Expect the client's PONG echoing our PING data.
            let reply = read_one_packet_local(&mut s, &mut codec, &mut inbox)
                .map_err(|e| format!("{e:?}"))?;
            if reply.first().copied() != Some(SSH_MSG_PONG) {
                return Err(format!("expected PONG, got msg {:?}", reply.first()));
            }
            let mut r = crate::format::Reader::new(&reply);
            r.read_u8().map_err(|e| format!("{e:?}"))?;
            let data = r.read_string().map_err(|e| format!("{e:?}"))?;
            if data != b"chaff-1234" {
                return Err(format!("PONG echoed wrong data: {data:?}"));
            }
            Ok(b"ok".to_vec())
        });

        let mut client = Client::connect(addr, Config::insecure()).expect("client connect");
        // Pump the client read loop: it must drop the stray PONG and answer
        // the PING by writing a PONG back (which our server thread asserts).
        // The server closes after reading our PONG, so this eventually errors
        // with a closed connection — that's the success path here.
        let _ = client.read_one_packet();

        let res = server.join().unwrap();
        assert_eq!(res.expect("server PONG assertions"), b"ok");
    }

    #[test]
    fn fingerprint_mismatch_rejected() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let mut seed = [0u8; 32];
        OsRng.fill_bytes(&mut seed);
        let server = run_server(listener, seed);

        let cfg = Config {
            host_key_policy: HostKeyPolicy::AcceptFingerprint([0xffu8; 32]),
            timeout: None,
            algorithms: Default::default(),
        };
        let err = Client::connect(addr, cfg).err().expect("must fail");
        assert!(matches!(err, Error::HostKeyRejected));
        // The server thread may have errored after our connect dropped — that's fine.
        let _ = server.join();
    }

    #[test]
    fn client_advert_no_overrides_matches_defaults() {
        let advert = build_default_kexinit(&mut OsRng, &AlgoOverrides::default());
        // Ciphers/MACs/host-key advertise the built-in defaults.
        let want_ciphers: Vec<String> = defaults::CIPHERS.iter().map(|s| s.to_string()).collect();
        assert_eq!(advert.ciphers_c2s, want_ciphers);
        assert_eq!(advert.ciphers_s2c, want_ciphers);
        // The kex list ends with both strict-kex markers.
        let n = advert.kex.len();
        assert!(crate::transport::kex::is_strict_kex_marker(
            &advert.kex[n - 1]
        ));
        assert!(crate::transport::kex::is_strict_kex_marker(
            &advert.kex[n - 2]
        ));
    }

    #[test]
    fn client_cipher_override_replaces_and_keeps_markers() {
        let over = AlgoOverrides {
            ciphers: Some(vec!["aes128-ctr".to_string()]),
            ..Default::default()
        };
        let advert = build_default_kexinit(&mut OsRng, &over);
        assert_eq!(advert.ciphers_c2s, vec!["aes128-ctr".to_string()]);
        assert_eq!(advert.ciphers_s2c, vec!["aes128-ctr".to_string()]);
        // Markers regained even though we overrode an unrelated category.
        assert!(
            advert
                .kex
                .iter()
                .any(|k| crate::transport::kex::is_strict_kex_marker(k))
        );
    }

    #[test]
    fn client_kex_override_reappends_markers() {
        let over = AlgoOverrides {
            // A single real kex; markers must still come back.
            kex_algorithms: Some(vec!["curve25519-sha256".to_string()]),
            ..Default::default()
        };
        let advert = build_default_kexinit(&mut OsRng, &over);
        assert_eq!(advert.kex[0], "curve25519-sha256");
        let markers = advert
            .kex
            .iter()
            .filter(|k| crate::transport::kex::is_strict_kex_marker(k))
            .count();
        assert_eq!(markers, 2, "both strict-kex markers must be re-appended");
    }

    #[test]
    fn restricted_client_ciphers_negotiate_against_default_server() {
        use crate::transport::kexinit::negotiate;
        // Client restricts ciphers to a single CTR suite; server advertises
        // defaults. Negotiation must pick the client's restricted choice.
        let client_over = AlgoOverrides {
            ciphers: Some(vec!["aes128-ctr".to_string()]),
            ..Default::default()
        };
        let client =
            build_default_kexinit(&mut OsRng, &client_over).with_ext_info_marker(Role::Client);
        let server = build_default_kexinit(&mut OsRng, &AlgoOverrides::default());
        let neg = negotiate(&client, &server).expect("should negotiate");
        assert_eq!(neg.cipher_c2s, "aes128-ctr");
        assert_eq!(neg.cipher_s2c, "aes128-ctr");
        // Strict-kex survives an unrelated cipher override on the client.
        assert!(neg.strict_kex_enabled);
    }

    #[test]
    fn disjoint_ciphers_fail_with_no_common_algorithm() {
        use crate::transport::kexinit::negotiate;
        let client_over = AlgoOverrides {
            ciphers: Some(vec!["aes128-ctr".to_string()]),
            ..Default::default()
        };
        let server_over = AlgoOverrides {
            ciphers: Some(vec!["aes256-ctr".to_string()]),
            ..Default::default()
        };
        let client = build_default_kexinit(&mut OsRng, &client_over);
        let server = build_default_kexinit(&mut OsRng, &server_over);
        assert!(matches!(
            negotiate(&client, &server),
            Err(Error::NoCommonAlgorithm(_))
        ));
    }
}
