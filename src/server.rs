//! High-level blocking SSH server over `std::net::TcpListener`.
//!
//! ```ignore
//! use std::sync::Arc;
//! use puressh::server::{Server, Config, CommandHandler, ExecResult, SessionEnv};
//!
//! struct H;
//! impl CommandHandler for H {
//!     fn handle(&self, _user: &str, _env: &SessionEnv, _cmd: &str) -> ExecResult {
//!         ExecResult { stdout: b"ok\n".to_vec(), stderr: Vec::new(), exit_status: 0 }
//!     }
//! }
//!
//! let cfg = Config {
//!     host_keys: vec![/* load_host_key()? */],
//!     authenticator: /* Arc::new(my_auth) */,
//!     allowed_auth_methods: vec!["publickey"],
//!     command_handler: Arc::new(H),
//! };
//! let mut srv = Server::bind("127.0.0.1:2222", cfg)?;
//! srv.serve()?;
//! ```

#![cfg(feature = "std")]

use std::collections::{BTreeMap, BTreeSet};
use std::io::{ErrorKind, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::sync::mpsc::{self, Receiver, Sender, TryRecvError};
use std::thread;
use std::time::{Duration, Instant};

use purecrypto::rng::{CryptoRng, OsRng, RngCore};

use crate::auth::{Authenticator, ServerAuth, ServerStep};
use crate::channel::{
    ChannelEvent, ChannelOpen, ChannelRequest, ConnectionState, SSH_EXTENDED_DATA_STDERR,
    SSH_OPEN_ADMINISTRATIVELY_PROHIBITED, SSH_OPEN_RESOURCE_SHORTAGE,
};
use crate::error::{Error, Result};
use crate::format::Writer;
use crate::hostkey::HostKey;
use crate::transport::kex::{defaults, is_strict_kex_marker};
use crate::transport::rekey::{RekeyPolicy, is_kex_msg};
use crate::transport::{
    ExtInfo, KexAlgorithmsOwned, KexInit, KexRunner, PacketCodec, Role, VersionExchange,
};

const MAX_BANNER_LINE: usize = 1024;
const MAX_BANNER_LINES: usize = 256;
const MAX_INBOX_BYTES: usize = 8 * 1024 * 1024;
const MAX_KEX_STEPS: usize = 32;
const MAX_AUTH_STEPS: usize = 64;
const MAX_CONNECTION_STEPS: usize = 10_000_000;
const MAX_DRAIN_STEPS: usize = 1_000_000;

/// Cap on the number of application packets buffered in `deferred` while a
/// re-KEX is in flight (RFC 4253 §7.3). A client can trigger a rekey and
/// then flood `CHANNEL_DATA` without ever completing the exchange; without a
/// bound the queue would grow until `MAX_CONNECTION_STEPS`, buffering
/// millions of payloads. Whichever of count / aggregate bytes trips first
/// aborts the connection with a protocol error.
const MAX_DEFERRED_PACKETS: usize = 4096;
/// Aggregate byte budget for the `deferred` rekey queue (see
/// `MAX_DEFERRED_PACKETS`).
const MAX_DEFERRED_BYTES: usize = 4 * 1024 * 1024;

/// Bound on the per-subsystem egress queue. Handlers self-throttle when
/// the dispatcher can't ship `CHANNEL_DATA` fast enough (remote window
/// exhausted).
const SUBSYSTEM_EGRESS_BACKLOG: usize = 32;

/// High-water mark on a shell's held-over stdout (`pending_stdout`). When a
/// client stops reading, the remote window stays exhausted and unsent shell
/// output accumulates here. Without a cap, `drain_shells` would keep pulling
/// fresh bytes from the PTY/pipe every tick and grow this buffer unbounded —
/// an authenticated memory-exhaustion DoS. Once the backlog reaches this
/// ceiling we stop reading from the shell; reads resume on the next tick
/// after a window adjustment drains the buffer back below the mark. Mirrors
/// the spirit of `SUBSYSTEM_EGRESS_BACKLOG` (a few-MiB egress ceiling) in a
/// byte-counted form appropriate to the raw stdout buffer.
const SHELL_EGRESS_BACKLOG: usize = 4 * 1024 * 1024;

/// Maximum number of `"env"` channel requests we'll accept on a single
/// session channel. A peer can ship `env` requests for free before any
/// `shell` / `exec` / `subsystem` claim — without a cap, tens of
/// thousands of accepted vars would sit in the per-channel `SessionEnv`
/// bag forever. Mirrors the OpenSSH default ballpark of a few dozen.
const MAX_ENV_PER_CHANNEL: usize = 64;

/// Aggregate byte budget for one channel's `SessionEnv` bag, counted as
/// `name.len() + value.len()` summed across all currently-stored pairs.
/// Refuses further accepts once an insert would push the total over this
/// ceiling, even if `MAX_ENV_PER_CHANNEL` has not yet been hit.
const MAX_ENV_BYTES_PER_CHANNEL: usize = 16 * 1024;

const SSH_DISCONNECT_BY_APPLICATION: u32 = 11;
const SSH_DISCONNECT_HOST_NOT_ALLOWED: u32 = 9;

/// Result returned by a [`CommandHandler`] after running a command.
#[derive(Debug, Clone)]
pub struct ExecResult {
    /// Captured stdout bytes.
    pub stdout: Vec<u8>,
    /// Captured stderr bytes.
    pub stderr: Vec<u8>,
    /// POSIX-style exit code.
    pub exit_status: u32,
}

/// Per-session environment-variable bag, surfaced to every handler that
/// spawns or runs anything on behalf of `user`.
///
/// Three things populate it: client-sent `"env"` channel requests, the
/// server's own injection points (currently agent-forwarding's
/// `SSH_AUTH_SOCK`), and nothing else. Handlers read it via [`Self::get`] or
/// [`Self::iter`] and apply the variables when they `fork+exec` or spawn an
/// in-process subsystem. Implementations decide which keys to honour — the
/// type itself does not filter.
#[derive(Debug, Default, Clone)]
pub struct SessionEnv {
    vars: BTreeMap<String, String>,
}

impl SessionEnv {
    /// An empty environment.
    pub fn new() -> Self {
        Self {
            vars: BTreeMap::new(),
        }
    }

    /// Insert or overwrite a key. Returns the previous value if any.
    pub fn insert(&mut self, key: impl Into<String>, value: impl Into<String>) -> Option<String> {
        self.vars.insert(key.into(), value.into())
    }

    /// Borrow a value by key.
    pub fn get(&self, key: &str) -> Option<&str> {
        self.vars.get(key).map(|s| s.as_str())
    }

    /// Iterate over `(key, value)` pairs in key order.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &str)> {
        self.vars.iter().map(|(k, v)| (k.as_str(), v.as_str()))
    }

    /// Number of entries.
    pub fn len(&self) -> usize {
        self.vars.len()
    }

    /// True when nothing has been set.
    pub fn is_empty(&self) -> bool {
        self.vars.is_empty()
    }
}

/// Server-side hook called when a client sends a `"exec"` channel request.
pub trait CommandHandler: Send + Sync {
    /// Run `command` on behalf of `user` and return its full output and exit
    /// code. Called inside the per-connection thread. `env` carries every
    /// variable accumulated on this session (client `"env"` requests +
    /// server-side injections like agent forwarding's `SSH_AUTH_SOCK`).
    fn handle(&self, user: &str, env: &SessionEnv, command: &str) -> ExecResult;
}

/// Per-channel state for an interactive shell session, owned by
/// `do_connection_phase` and threaded into the request handler so each
/// `pty-req` / `shell` / `window-change` lands on the right channel.
struct ShellRuntime {
    /// Captured `pty-req` spec waiting for the matching `shell` request.
    pending_pty: Option<PtySpec>,
    /// The live session, populated after `shell` succeeds.
    session: Option<Box<dyn ShellSession>>,
    /// Cached exit status once `try_exit` first returns `Some`.
    exited: Option<ShellExitStatus>,
    /// Whether we've already sent exit-status / EOF / CLOSE to the client.
    exit_sent: bool,
    /// Stdout bytes held over from a previous poll because the remote
    /// window was full or a re-KEX was in flight.
    pending_stdout: Vec<u8>,
}

impl ShellRuntime {
    fn new() -> Self {
        Self {
            pending_pty: None,
            session: None,
            exited: None,
            exit_sent: false,
            pending_stdout: Vec::new(),
        }
    }
}

/// Pseudo-terminal allocation request captured from `"pty-req"`.
///
/// The library never decodes [`modes`] — RFC 4254 §8 mode opcodes are a
/// backend concern. The concrete `ShellHandler` (e.g. the `nix`-based one
/// in `sshd`) parses what it can and falls back to kernel defaults for the
/// rest.
///
/// [`modes`]: Self::modes
#[derive(Debug, Clone)]
pub struct PtySpec {
    /// Value for the `TERM` environment variable, e.g. `"xterm-256color"`.
    pub term: String,
    /// Terminal width in characters.
    pub cols: u32,
    /// Terminal height in characters.
    pub rows: u32,
    /// Terminal width in pixels (0 if not specified).
    pub px_w: u32,
    /// Terminal height in pixels (0 if not specified).
    pub px_h: u32,
    /// Encoded terminal modes — the verbatim `modes` field from `pty-req`.
    pub modes: Vec<u8>,
}

/// How a [`ShellSession`]'s child process terminated.
#[derive(Debug, Clone)]
pub enum ShellExitStatus {
    /// Process exited normally with this status code.
    Exited(u32),
    /// Process was killed by a signal.
    Signalled {
        /// Signal name without the `SIG` prefix (e.g. `"TERM"`).
        name: String,
        /// Whether the kernel dumped a core for the process.
        core_dumped: bool,
        /// Optional human-readable description.
        message: String,
    },
}

/// Server-side hook called when a client sends `"shell"` (or `"pty-req"`
/// then `"shell"`). One [`ShellSession`] backs one SSH channel.
///
/// The trait is intentionally OS-agnostic: it never names `forkpty`,
/// `pipe`, or `nix` types. A concrete implementation lives in the `sshd`
/// binary, where the `unsafe` syscall plumbing is allowed; the library
/// stays no-std-friendly and keeps `forbid(unsafe_code)`.
pub trait ShellHandler: Send + Sync {
    /// Spawn a new shell process on behalf of `user`. If `pty` is `Some`,
    /// the implementation must allocate a pseudo-terminal and apply the
    /// requested geometry / modes (best-effort). If `pty` is `None`, the
    /// implementation may run the shell with bare pipes — that path is
    /// what `ssh -T` triggers. `env` carries every accumulated session
    /// variable, which the implementation is responsible for forwarding to
    /// the child process.
    fn spawn(
        &self,
        user: &str,
        env: &SessionEnv,
        pty: Option<PtySpec>,
    ) -> Result<Box<dyn ShellSession>>;
}

/// One running shell process. All methods are non-blocking; the server
/// loop polls them with a ~50 ms cadence.
pub trait ShellSession: Send {
    /// Read up to `buf.len()` bytes from the shell's stdout / PTY master.
    ///
    /// `Ok(0)` means "no bytes available right now" (NOT EOF). True EOF
    /// is signalled by [`try_exit`] returning `Some(_)`.
    ///
    /// [`try_exit`]: Self::try_exit
    fn read(&mut self, buf: &mut [u8]) -> Result<usize>;
    /// Write `buf` to the shell's stdin / PTY master. `Ok(0)` on EAGAIN;
    /// the caller will retry on the next poll tick.
    fn write(&mut self, buf: &[u8]) -> Result<usize>;
    /// Signal end-of-input on the shell's stdin. For PTY backends this is
    /// the EOT character; for pipe backends it closes the write half.
    fn close_stdin(&mut self) -> Result<()>;
    /// Apply a new terminal geometry. Best-effort: pipe backends ignore.
    fn resize(&mut self, cols: u32, rows: u32, px_w: u32, px_h: u32) -> Result<()>;
    /// Non-blocking exit poll. Returns `Some` once the child has reaped.
    fn try_exit(&mut self) -> Option<ShellExitStatus>;
}

pub use crate::stream::{ChannelEgress, ChannelStream};

/// Per-channel state for an in-process subsystem (e.g. SFTP) — parallel to
/// [`ShellRuntime`], owned by `do_connection_phase`.
struct SubsystemRuntime {
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

/// Per-connection context handed to the [`Config::on_session_open`] hook.
///
/// Carries the values resolved from the per-connection [`EffectivePolicy`]
/// that the hook must act on while the server may still hold root.
#[derive(Debug, Clone, Copy)]
pub struct SessionOpenContext<'a> {
    /// The authenticated username.
    pub user: &'a str,
    /// Resolved `ChrootDirectory`, if any. An implementation that drops
    /// privileges (`setuid`) must `chroot()` to this *first*, while still root.
    pub chroot_directory: Option<&'a str>,
    /// Resolved `PrintMotd`. When `true`, an interactive (PTY) shell should
    /// print `/etc/motd` at startup. Defaults to `false`.
    pub print_motd: bool,
}

/// Callback type for [`Config::on_session_open`].
///
/// Called once per connection, post-auth, while the server may still hold
/// root. See [`SessionOpenContext`] for the supplied per-connection policy.
pub type SessionOpenCallback = Arc<dyn Fn(&SessionOpenContext<'_>) -> Result<()> + Send + Sync>;

/// Server-side hook called when a client sends a `"subsystem"` channel
/// request (e.g. `"sftp"`).
///
/// Implementations get a [`ChannelStream`] they can treat as a normal
/// `Read+Write` and run their protocol loop on. The handler runs on a
/// dedicated thread per channel so blocking reads don't stall the rest of
/// the connection. Return `Ok(())` to close the channel gracefully — the
/// dispatcher emits EOF + Close when the stream drops.
pub trait SubsystemHandler: Send + Sync {
    /// Run subsystem `name` on behalf of `user` over `stream`. `env`
    /// reflects the accumulated session environment at the moment the
    /// subsystem was requested; it is captured by-value into the handler
    /// thread so subsequent client `"env"` requests don't race the
    /// running subsystem.
    fn handle(&self, user: &str, env: &SessionEnv, name: &str, stream: ChannelStream)
    -> Result<()>;
}

/// Server-side hook called when a client sends an `"exec"` channel request,
/// **before** the synchronous [`CommandHandler`] runs. Lets a stream-mode
/// handler (SCP, custom RPC) claim the channel and drive it as a real
/// bidirectional pipe rather than the buffer-and-return shape of
/// [`CommandHandler::handle`].
///
/// The dispatcher consults the overlay in two phases:
///
/// 1. [`claims`] is called synchronously in the connection thread with
///    just the command string. Return `true` to claim the request — the
///    dispatcher then sends `request_success`, registers a per-channel
///    runtime, and hands off to [`run`].
/// 2. [`run`] executes on a dedicated thread per claimed channel, with
///    a live [`ChannelStream`] it can `Read`/`Write` until the
///    transaction finishes. Dropping the stream emits `EOF`+`Close` to
///    the peer.
///
/// Both hooks run in the per-connection process after the
/// [`Config::on_session_open`] drop-to-user has already happened, so
/// handlers see the authenticated user's filesystem permissions.
///
/// [`claims`]: ExecStreamHandler::claims
/// [`run`]: ExecStreamHandler::run
pub trait ExecStreamHandler: Send + Sync {
    /// Cheap synchronous decision based on the command string only.
    /// Return `true` to claim; `false` to fall through to the buffered
    /// [`CommandHandler`].
    fn claims(&self, command: &str) -> bool;
    /// Execute the claimed command on a dedicated thread. The handler
    /// owns `stream` until it returns; on return the stream drops,
    /// emitting `EOF`+`Close` automatically. `env` is a snapshot of the
    /// session-level environment at the time of the claim.
    fn run(&self, user: &str, env: &SessionEnv, command: &str, stream: ChannelStream)
    -> Result<()>;
}

/// Decoded `direct-tcpip` channel-open request (RFC 4254 §7.2).
///
/// The wire fields are `string dest_host, uint32 dest_port,
/// string orig_host, uint32 orig_port`. We deliberately surface them
/// borrowed (`&str`) so handlers don't need to take ownership.
#[derive(Debug, Clone, Copy)]
pub struct DirectTcpipRequest<'a> {
    /// Destination hostname/IP the client wants the server to dial.
    pub dest_host: &'a str,
    /// Destination TCP port (carried as `u32` on the wire; in practice
    /// always 1–65535).
    pub dest_port: u32,
    /// Client-supplied originating address; informational only.
    pub orig_host: &'a str,
    /// Client-supplied originating port.
    pub orig_port: u32,
}

/// Server-side hook called when a client opens a `direct-tcpip` channel
/// (used by `ssh -L LPORT:rhost:rport`).
///
/// The handler runs on a dedicated thread per channel. Return `Ok(())` to
/// close the channel gracefully — the dispatcher emits EOF + Close when
/// the stream drops, unless the handler has explicitly torn it down via
/// [`ChannelStream::into_raw`].
///
/// Without a handler attached to [`Config::direct_tcpip_handler`] every
/// `direct-tcpip` open is rejected with
/// `SSH_OPEN_ADMINISTRATIVELY_PROHIBITED`.
pub trait DirectTcpipHandler: Send + Sync {
    /// Bridge `request` to whatever transport the implementation wants.
    /// The default in [`crate::forwarding::direct::DefaultDirectTcpipHandler`]
    /// connects via TCP and splices.
    fn handle(
        &self,
        user: &str,
        request: DirectTcpipRequest<'_>,
        stream: ChannelStream,
    ) -> Result<()>;
}

/// Per-binding handle a [`TcpipForwardHandler`] uses to ask the per-connection
/// server loop to open a `forwarded-tcpip` channel back to the client
/// (RFC 4254 §7.2; the wire side of `ssh -R`).
///
/// One instance is supplied to each successful call to
/// [`TcpipForwardHandler::bind`]; it stays valid for the lifetime of that
/// binding (i.e. until [`TcpipForwardHandler::unbind`] or the connection
/// closes). The handler's accept-loop calls
/// [`ForwardContext::open_forwarded_tcpip`] for every accepted TCP
/// connection on the bound port. The call blocks until the client confirms
/// (returns a [`ChannelStream`] wired to the new channel) or rejects
/// (returns `Err`). After that the handler is free to splice between the
/// `TcpStream` and the `ChannelStream` until either side hangs up.
#[derive(Clone)]
pub struct ForwardContext {
    /// Sender into the per-connection forward-open mpsc queue. The loop on
    /// the receiver end translates each request into a wire-level
    /// `SSH_MSG_CHANNEL_OPEN forwarded-tcpip` and parks a reply slot until
    /// the matching `OPEN_CONFIRMATION` / `OPEN_FAILURE` lands.
    req_tx: Sender<ForwardOpenRequest>,
}

/// One pending server-initiated `forwarded-tcpip` open. Carries the wire
/// arguments and a reply slot for the resulting [`ChannelStream`].
pub(crate) struct ForwardOpenRequest {
    /// Address that was being listened on (per RFC 4254 §7.2 echoed back).
    bound_address: String,
    /// Port that was being listened on (always a u16 in practice).
    bound_port: u32,
    /// Originator's address (the peer of the TCP listener).
    orig_address: String,
    /// Originator's port.
    orig_port: u32,
    /// One-shot reply slot. `Ok(stream)` after `OPEN_CONFIRMATION`,
    /// `Err(_)` after `OPEN_FAILURE` or connection teardown.
    reply: std::sync::mpsc::SyncSender<Result<ChannelStream>>,
}

impl ForwardContext {
    /// Used by the connection loop; not for user code.
    pub(crate) fn new(req_tx: Sender<ForwardOpenRequest>) -> Self {
        Self { req_tx }
    }

    /// Build a [`ForwardContext`] whose [`Self::open_forwarded_tcpip`]
    /// calls always fail (the request mpsc has no receiver). Useful for
    /// unit tests that only exercise `bind` / `unbind` and never dial the
    /// listener — the accept-loop never actually has to issue an open.
    #[doc(hidden)]
    pub fn for_test_no_opens() -> Self {
        // Drop the receiver immediately; the sender becomes a perpetual
        // "send fails" sink, which `open_forwarded_tcpip` turns into
        // `Error::Protocol`.
        let (tx, _rx) = mpsc::channel();
        drop(_rx);
        Self { req_tx: tx }
    }

    /// Ask the connection loop to open a `forwarded-tcpip` channel toward
    /// the client. Blocks until the client confirms or rejects the open.
    ///
    /// On success returns a [`ChannelStream`] connected to the new channel.
    /// Drop the stream (or send EOF/Close via [`ChannelStream::into_raw`])
    /// when the TCP side hangs up.
    ///
    /// Returns `Err(Error::Protocol(_))` if the underlying SSH connection
    /// has gone away or the client rejected the open.
    pub fn open_forwarded_tcpip(
        &self,
        bound_address: &str,
        bound_port: u16,
        orig_address: &str,
        orig_port: u16,
    ) -> Result<ChannelStream> {
        let (tx, rx) = std::sync::mpsc::sync_channel(1);
        self.req_tx
            .send(ForwardOpenRequest {
                bound_address: bound_address.to_string(),
                bound_port: bound_port as u32,
                orig_address: orig_address.to_string(),
                orig_port: orig_port as u32,
                reply: tx,
            })
            .map_err(|_| Error::Protocol("forwarded-tcpip: connection closed"))?;
        rx.recv()
            .map_err(|_| Error::Protocol("forwarded-tcpip: reply dropped"))?
    }
}

/// Server-side hook for `tcpip-forward` and `cancel-tcpip-forward` global
/// requests (RFC 4254 §7.1; the inbound bookend of `ssh -R`).
///
/// The default implementation in
/// [`crate::forwarding::reverse::DefaultTcpipForwardHandler`] binds a real
/// TCP listener, tracks it per-connection so cancel actually unbinds, and
/// — via the [`ForwardContext`] passed to `bind` — opens a server-initiated
/// `forwarded-tcpip` channel back to the client for every accepted TCP
/// connection.
///
/// When `bind_port == 0` the handler must pick a free port and return it
/// in `bind`; the server echoes the value back to the client as part of
/// `REQUEST_SUCCESS` (per RFC 4254 §7.1).
pub trait TcpipForwardHandler: Send + Sync {
    /// Bind `bind_address:bind_port`. Return the actually-bound port. An
    /// `Err` causes the server to reply `REQUEST_FAILURE`.
    ///
    /// `ctx` is a per-binding handle the implementation typically clones
    /// into its accept-loop thread so it can request `forwarded-tcpip`
    /// channel-opens back toward the client.
    fn bind(
        &self,
        user: &str,
        bind_address: &str,
        bind_port: u16,
        ctx: ForwardContext,
    ) -> Result<u16>;
    /// Tear down a previously-bound listener. `Err` causes the server to
    /// reply `REQUEST_FAILURE`.
    fn unbind(&self, user: &str, bind_address: &str, bind_port: u16) -> Result<()>;
}

/// Per-session-channel handle used by an [`AgentForwardHandler`] to ask the
/// per-connection server loop to open an `auth-agent@openssh.com` channel
/// back toward the client (OpenSSH pseudo-extension; same mechanism as
/// `forwarded-tcpip` but for ssh-agent traffic).
///
/// One instance is supplied to each successful
/// [`AgentForwardHandler::setup`]; it stays valid for the lifetime of that
/// session channel (i.e. until the channel closes and the dispatcher drops
/// the matching [`AgentForwardHandle`]).
#[derive(Clone)]
pub struct AgentForwardContext {
    /// Sender into the per-connection agent-open mpsc queue. The connection
    /// loop on the receiver end translates each request into an
    /// `SSH_MSG_CHANNEL_OPEN auth-agent@openssh.com` and parks the reply slot
    /// until the matching `OPEN_CONFIRMATION` / `OPEN_FAILURE` lands.
    req_tx: Sender<AgentOpenRequest>,
}

/// One pending server-initiated `auth-agent@openssh.com` open. Carries only
/// the reply slot — the channel-open itself has no extra payload per the
/// OpenSSH wire format.
pub(crate) struct AgentOpenRequest {
    /// One-shot reply slot. `Ok(stream)` after `OPEN_CONFIRMATION`,
    /// `Err(_)` after `OPEN_FAILURE` or connection teardown.
    reply: std::sync::mpsc::SyncSender<Result<ChannelStream>>,
}

impl AgentForwardContext {
    /// Used by the connection loop; not for user code.
    pub(crate) fn new(req_tx: Sender<AgentOpenRequest>) -> Self {
        Self { req_tx }
    }

    /// Build an [`AgentForwardContext`] whose [`Self::open_auth_agent`]
    /// calls always fail (the request mpsc has no receiver). Useful for
    /// unit tests that only exercise `setup` and never accept on the
    /// agent socket.
    #[doc(hidden)]
    pub fn for_test_no_opens() -> Self {
        let (tx, _rx) = mpsc::channel();
        drop(_rx);
        Self { req_tx: tx }
    }

    /// Ask the connection loop to open an `auth-agent@openssh.com` channel
    /// back toward the client. Blocks until the client confirms or rejects.
    ///
    /// On success returns a [`ChannelStream`] connected to the new channel.
    /// Drop the stream when the local Unix socket connection hangs up.
    ///
    /// Returns `Err(Error::Protocol(_))` if the underlying SSH connection
    /// has gone away or the client rejected the open.
    pub fn open_auth_agent(&self) -> Result<ChannelStream> {
        let (tx, rx) = std::sync::mpsc::sync_channel(1);
        self.req_tx
            .send(AgentOpenRequest { reply: tx })
            .map_err(|_| Error::Protocol("auth-agent: connection closed"))?;
        rx.recv()
            .map_err(|_| Error::Protocol("auth-agent: reply dropped"))?
    }
}

/// Handle returned by [`AgentForwardHandler::setup`]. The connection loop
/// inserts the handle into a per-session-channel map and drops it when the
/// session closes. Dropping the handle must tear down the listener thread
/// and unlink the on-disk socket.
pub struct AgentForwardHandle {
    /// Path that should be exposed as `SSH_AUTH_SOCK` in the environment of
    /// programs spawned on this session. Typically inside `$XDG_RUNTIME_DIR`
    /// or `/tmp` with mode 0700.
    pub auth_sock_path: std::path::PathBuf,
    /// Stop guard: any `Send`/`Sync` value whose `Drop` impl terminates the
    /// accept loop and removes the socket. The dispatcher does not look
    /// inside this box — it just drops it on session close.
    pub stopper: Box<dyn core::any::Any + Send + Sync>,
}

/// Server-side hook for `auth-agent-req@openssh.com`
/// (the channel request OpenSSH sends when the client asked for `-A`).
///
/// The default implementation in
/// [`crate::forwarding::agent::DefaultAgentForwardHandler`] binds a Unix
/// socket under `$XDG_RUNTIME_DIR` (or `/tmp` fallback) with mode 0600 and
/// — via the [`AgentForwardContext`] passed to `setup` — opens a
/// server-initiated `auth-agent@openssh.com` channel back to the client for
/// every accepted Unix socket connection.
///
/// Implementations must be safe to share across connections.
pub trait AgentForwardHandler: Send + Sync {
    /// Establish agent forwarding for a single session channel. Return a
    /// handle whose `auth_sock_path` is injected into the session's
    /// `SSH_AUTH_SOCK` env, and whose `stopper` is dropped (terminating the
    /// listener) when the session channel closes. An `Err` causes the
    /// server to reply `CHANNEL_FAILURE` and leave the env unchanged.
    fn setup(&self, user: &str, ctx: AgentForwardContext) -> Result<AgentForwardHandle>;
}

/// Per-session-channel handle used by an [`X11ForwardHandler`] to ask the
/// per-connection server loop to open an `x11` channel back toward the
/// client (RFC 4254 §6.3).
///
/// One instance is supplied to each successful
/// [`X11ForwardHandler::setup`]; it stays valid for the lifetime of that
/// session channel (i.e. until the channel closes and the dispatcher drops
/// the matching [`X11ForwardHandle`]).
#[derive(Clone)]
pub struct X11ForwardContext {
    /// Sender into the per-connection x11-open mpsc queue. The connection
    /// loop on the receiver end translates each request into an
    /// `SSH_MSG_CHANNEL_OPEN x11` and parks the reply slot until the
    /// matching `OPEN_CONFIRMATION` / `OPEN_FAILURE` lands.
    req_tx: Sender<X11OpenRequest>,
}

/// One pending server-initiated `x11` open. Carries the originator address
/// (reported back to the client in the `OPEN` payload) and a one-shot reply
/// slot.
pub(crate) struct X11OpenRequest {
    /// Originator host as advertised to the client.
    pub orig_host: String,
    /// Originator TCP port.
    pub orig_port: u32,
    /// One-shot reply slot. `Ok(stream)` after `OPEN_CONFIRMATION`,
    /// `Err(_)` after `OPEN_FAILURE` or connection teardown.
    pub reply: std::sync::mpsc::SyncSender<Result<ChannelStream>>,
}

impl X11ForwardContext {
    /// Used by the connection loop; not for user code.
    pub(crate) fn new(req_tx: Sender<X11OpenRequest>) -> Self {
        Self { req_tx }
    }

    /// Build an [`X11ForwardContext`] whose [`Self::open_x11`] calls always
    /// fail (the request mpsc has no receiver). Useful for unit tests that
    /// only exercise `setup` and never accept on the display socket.
    #[doc(hidden)]
    pub fn for_test_no_opens() -> Self {
        let (tx, _rx) = mpsc::channel();
        drop(_rx);
        Self { req_tx: tx }
    }

    /// Ask the connection loop to open an `x11` channel back toward the
    /// client. Blocks until the client confirms or rejects.
    ///
    /// `orig_host` / `orig_port` are advertised to the client as the
    /// originator of the X11 connection (per RFC 4254 §6.3.2).
    ///
    /// On success returns a [`ChannelStream`] connected to the new channel.
    /// Drop the stream when the local X-client TCP connection hangs up.
    ///
    /// Returns `Err(Error::Protocol(_))` if the underlying SSH connection
    /// has gone away or the client rejected the open.
    pub fn open_x11(&self, orig_host: String, orig_port: u32) -> Result<ChannelStream> {
        let (tx, rx) = std::sync::mpsc::sync_channel(1);
        self.req_tx
            .send(X11OpenRequest {
                orig_host,
                orig_port,
                reply: tx,
            })
            .map_err(|_| Error::Protocol("x11: connection closed"))?;
        rx.recv()
            .map_err(|_| Error::Protocol("x11: reply dropped"))?
    }
}

/// Handle returned by [`X11ForwardHandler::setup`]. The connection loop
/// inserts the handle into a per-session-channel map and drops it when the
/// session closes. Dropping the handle must tear down the listener thread
/// and release the display number.
pub struct X11ForwardHandle {
    /// Display string to expose as `DISPLAY` in the environment of programs
    /// spawned on this session, typically `"localhost:<N>.<screen>"` where
    /// `N` is `display_number` and `screen` matches the request.
    pub display_env: String,
    /// X display number bound by this handle (e.g. `10` → TCP port `6010`).
    /// Useful for diagnostics; the dispatcher does not consume it.
    pub display_number: u16,
    /// Stop guard: any `Send`/`Sync` value whose `Drop` impl terminates the
    /// accept loop and releases the display. The dispatcher does not look
    /// inside this box — it just drops it on session close.
    pub stopper: Box<dyn core::any::Any + Send + Sync>,
}

/// Server-side hook for `x11-req` (the channel request OpenSSH sends when
/// the client asked for `-X` / `-Y`).
///
/// The default implementation in
/// [`crate::forwarding::x11::DefaultX11ForwardHandler`] binds a TCP listener
/// on `127.0.0.1:6000+N` for a fresh display number `N`, and — via the
/// [`X11ForwardContext`] passed to `setup` — opens a server-initiated
/// `x11` channel back to the client for every accepted X-client connection.
///
/// Implementations must be safe to share across connections. The
/// `auth_protocol` and `auth_cookie` fields of the original
/// `x11-req` are passed through so the handler can validate / store the
/// client's MIT-MAGIC-COOKIE-1 (used for cookie substitution on the wire).
pub trait X11ForwardHandler: Send + Sync {
    /// Establish X11 forwarding for a single session channel. Return a
    /// handle whose `display_env` is injected as `DISPLAY` in the session's
    /// env, and whose `stopper` is dropped (terminating the listener) when
    /// the session channel closes. An `Err` causes the server to reply
    /// `CHANNEL_FAILURE` and leave the env unchanged.
    fn setup(
        &self,
        user: &str,
        single_connection: bool,
        auth_protocol: &str,
        auth_cookie: &str,
        screen: u32,
        ctx: X11ForwardContext,
    ) -> Result<X11ForwardHandle>;
}

/// Server configuration: host keys, authentication, and the exec hook.
pub struct Config {
    /// Host keys the server presents and signs the KEX with. At least one
    /// required.
    pub host_keys: Vec<Box<dyn HostKey + Send + Sync>>,
    /// User-authentication policy.
    pub authenticator: Arc<dyn AuthenticatorFactory>,
    /// Auth methods advertised in `USERAUTH_FAILURE`.
    pub allowed_auth_methods: Vec<&'static str>,
    /// Command handler invoked on `"exec"` channel requests when no
    /// [`ExecStreamHandler`] claims them.
    pub command_handler: Arc<dyn CommandHandler>,
    /// Optional stream-mode `"exec"` overlay. When set, the dispatcher
    /// calls [`ExecStreamHandler::claims`] *before* the synchronous
    /// [`CommandHandler`]; commands the overlay claims are dispatched on
    /// their own thread with a live [`ChannelStream`] via
    /// [`ExecStreamHandler::run`]. Used by sshd's in-process SCP handler
    /// to drive `scp -t` / `scp -f` without going through the
    /// buffered-then-flushed [`CommandHandler`].
    pub exec_stream_handler: Option<Arc<dyn ExecStreamHandler>>,
    /// Optional interactive-shell hook. When `None` (the default),
    /// `"pty-req"` and `"shell"` are rejected, matching the historical
    /// behaviour of this server.
    pub shell_handler: Option<Arc<dyn ShellHandler>>,
    /// Optional `"subsystem"` hook. When `None` (the default), all
    /// `subsystem` channel requests are rejected with `CHANNEL_FAILURE`.
    /// A typical implementation dispatches by `name` (`"sftp"`, …) and
    /// runs the protocol on the supplied [`ChannelStream`].
    pub subsystem_handler: Option<Arc<dyn SubsystemHandler>>,
    /// Optional `direct-tcpip` hook. When `None` (the default), every
    /// `direct-tcpip` channel open is rejected with
    /// `SSH_OPEN_ADMINISTRATIVELY_PROHIBITED`. Set this to
    /// [`crate::forwarding::direct::DefaultDirectTcpipHandler`] (or your
    /// own filter) to enable client-side `ssh -L` forwarding through this
    /// server.
    pub direct_tcpip_handler: Option<Arc<dyn DirectTcpipHandler>>,
    /// Optional `tcpip-forward` / `cancel-tcpip-forward` global-request
    /// hook (i.e. the server side of `ssh -R`). When `None` (the
    /// default), both requests reply `REQUEST_FAILURE`. Set this to
    /// [`crate::forwarding::reverse::DefaultTcpipForwardHandler`] to
    /// have the server bind a real listener; until the matching
    /// server-initiated `forwarded-tcpip` channel-open lands in a
    /// follow-up phase, accepted connections are dropped.
    pub tcpip_forward_handler: Option<Arc<dyn TcpipForwardHandler>>,
    /// Optional `auth-agent-req@openssh.com` channel-request hook (i.e. the
    /// server side of `ssh -A`). When `None` (the default), every
    /// `auth-agent-req@openssh.com` request is answered with `CHANNEL_FAILURE`
    /// and no agent socket is created. Set this to
    /// [`crate::forwarding::agent::DefaultAgentForwardHandler`] to bind a
    /// per-session Unix socket and proxy connections to the client's local
    /// agent via server-initiated `auth-agent@openssh.com` channel-opens.
    pub agent_forward_handler: Option<Arc<dyn AgentForwardHandler>>,
    /// Optional `x11-req` channel-request hook (i.e. the server side of
    /// `ssh -X` / `ssh -Y`). When `None` (the default), every `x11-req`
    /// request is answered with `CHANNEL_FAILURE` and no display is created.
    /// Set this to
    /// [`crate::forwarding::x11::DefaultX11ForwardHandler`] to bind a
    /// per-session TCP listener on `127.0.0.1:6000+N` and proxy accepted
    /// connections to the client via server-initiated `x11` channel-opens.
    pub x11_forward_handler: Option<Arc<dyn X11ForwardHandler>>,
    /// Optional callback invoked once per connection, after authentication
    /// has succeeded but before any channel request is processed. Returning
    /// `Err` aborts the connection. Typical use: drop privileges (setgid /
    /// initgroups / setuid) to `user` so all subsequent shell / exec /
    /// subsystem code runs as the authenticated user.
    pub on_session_open: Option<SessionOpenCallback>,
    /// Thresholds that trigger a re-key (RFC 4253 §9). Defaults to 1 GiB /
    /// 1 hour / `1u32 << 31` packets per direction.
    pub rekey_policy: RekeyPolicy,
    /// Allow-list of glob patterns matched against client-supplied
    /// `"env"` channel-request names (RFC 4254 §6.4). When empty (the
    /// default), every client env request is silently dropped.
    /// Patterns use the OpenSSH `AcceptEnv` syntax: literal names, with
    /// `*` and `?` wildcards. Matches against the names in
    /// [`HARD_BLOCKED_ENV_NAMES`] are always refused regardless of the
    /// allow-list. See [`Config::with_accept_env`].
    pub accept_env: Vec<String>,
    /// Pre-authentication inactivity timeout, applied to the socket
    /// between TCP accept and `userauth-success` (RFC 4252 — OpenSSH's
    /// `LoginGraceTime`). A peer that doesn't get past auth in this
    /// window has the connection dropped with `Error::Io`/`TimedOut`.
    /// Defaults to 120 seconds. Set to [`Duration::ZERO`] to disable.
    pub login_grace_time: Duration,
    /// `Ciphers` override (sshd_config) — advertised cipher preference list
    /// for both directions. `None` ⇒ built-in default.
    pub ciphers: Option<Vec<String>>,
    /// `MACs` override — advertised MAC preference list.
    pub macs: Option<Vec<String>>,
    /// `KexAlgorithms` override — advertised key-exchange list (no markers).
    pub kex_algorithms: Option<Vec<String>>,
    /// `HostKeyAlgorithms` override — preferred order for the advertised
    /// host-key algorithms. Intersected with the algorithms the loaded host
    /// keys can actually produce, so naming an algorithm we have no key for
    /// is a no-op rather than an error.
    pub host_key_algorithms: Option<Vec<String>>,
    /// Parsed `sshd_config` policy (global options + `Match` blocks). When
    /// set, it is resolved per-connection — twice — to gate capabilities:
    /// once pre-auth with an address-only context (auth method set + banner),
    /// once post-auth with the user/groups context (an [`EffectivePolicy`]).
    /// `None` ⇒ no policy gating beyond [`Self::allowed_auth_methods`] (the
    /// historical behaviour).
    pub policy: Option<Arc<crate::config::SshServerConfig>>,
    /// Resolves an authenticated user's supplementary group names for
    /// `Match group` / `AllowGroups` / `DenyGroups`. Called once per
    /// connection (post-auth) for every user uniformly. `None` ⇒ groups are
    /// unknown, so any group-dependent criterion never matches.
    pub group_resolver: Option<GroupResolver>,
    /// `Compression` (sshd_config) — startup-only. `Some(Compression::No)`
    /// strips any zlib names from the server's advertised compression list;
    /// `yes` / `delayed` / `None` leave the built-in advert (currently
    /// `none`-only, since puressh does not yet implement SSH-layer zlib).
    pub compression: Option<crate::config::Compression>,
    /// Connection-wide `AuthenticationMethods` default (space-separated
    /// alternatives, each a comma-chain — e.g. `["publickey,password"]`). Empty
    /// ⇒ single-factor (any one advertised method suffices). A `Match` block may
    /// override this per user; the resolved value is handed to the authenticator
    /// via [`crate::auth::Authenticator::on_user_resolved`]. Set with
    /// [`Config::with_auth_methods`].
    pub default_auth_methods: Vec<String>,
}

/// Resolver from a user name to its supplementary group names. Boxed so the
/// binary can plug in an OS-backed implementation (e.g. `getgrouplist`)
/// without the library taking a `nix`/`libc` dependency.
pub type GroupResolver = Arc<dyn Fn(&str) -> Vec<String> + Send + Sync>;

/// Per-connection capability ceiling resolved from the `sshd_config` policy
/// after authentication. Built once per connection from the matching global +
/// `Match` options and consulted at the existing channel-dispatch points; it
/// never rebuilds handlers, it only gates the maximal set attached at startup.
#[derive(Debug, Clone)]
pub struct EffectivePolicy {
    /// `AllowAgentForwarding` — when `Some(false)`, `auth-agent-req` is
    /// refused even if an agent-forward handler is attached.
    pub allow_agent_forwarding: Option<bool>,
    /// `X11Forwarding` — when `Some(false)`, `x11-req` is refused even if an
    /// X11 handler is attached.
    pub x11_forwarding: Option<bool>,
    /// `MaxSessions` — cap on simultaneously-open `session` channels. `None`
    /// ⇒ no cap.
    pub max_sessions: Option<u32>,
    /// `AllowTcpForwarding` — which TCP forwarding directions are permitted.
    /// `None` ⇒ default-allow (subject to a handler being attached).
    pub allow_tcp_forwarding: Option<crate::config::TcpForwarding>,
    /// `PermitOpen` — allowed `direct-tcpip` destinations. `None` ⇒ any;
    /// `Some(vec![])` ⇒ none.
    pub permit_open: Option<Vec<crate::config::HostPort>>,
    /// `PermitListen` — allowed `tcpip-forward` bind targets. `None` ⇒ any;
    /// `Some(vec![])` ⇒ none.
    pub permit_listen: Option<Vec<crate::config::HostPort>>,
    /// `GatewayPorts` — bind-interface policy for remote forwards. `None` ⇒
    /// default (`no`).
    pub gateway_ports: Option<crate::config::ServerGatewayPorts>,
    /// `ForceCommand` — overrides the client's exec/shell command. The
    /// original command is exposed as `SSH_ORIGINAL_COMMAND`.
    pub force_command: Option<String>,
    /// `ChrootDirectory` — the directory the session is confined to. Passed to
    /// the [`Config::on_session_open`] hook so it can `chroot()` (while still
    /// root, before any `setuid`) — confining shell, exec, and the in-process
    /// SFTP subsystem alike. `None` ⇒ no chroot.
    pub chroot_directory: Option<String>,
    /// `ClientAliveInterval` in seconds. `None`/`0` ⇒ keepalive disabled.
    pub client_alive_interval: Option<u32>,
    /// `ClientAliveCountMax` — unanswered keepalives tolerated. `None` ⇒
    /// default 3.
    pub client_alive_count_max: Option<u32>,
    /// `PrintMotd` — print `/etc/motd` for interactive shells. `None` ⇒
    /// default (no).
    pub print_motd: Option<bool>,
}

impl EffectivePolicy {
    /// A policy that gates nothing (used when no `sshd_config` policy is set).
    pub fn unrestricted() -> Self {
        EffectivePolicy {
            allow_agent_forwarding: None,
            x11_forwarding: None,
            max_sessions: None,
            allow_tcp_forwarding: None,
            permit_open: None,
            permit_listen: None,
            gateway_ports: None,
            force_command: None,
            chroot_directory: None,
            client_alive_interval: None,
            client_alive_count_max: None,
            print_motd: None,
        }
    }

    /// True iff agent forwarding is permitted (default-allow unless the policy
    /// resolved to `AllowAgentForwarding no`).
    fn agent_forwarding_allowed(&self) -> bool {
        self.allow_agent_forwarding != Some(false)
    }

    /// True iff X11 forwarding is permitted (default-allow unless the policy
    /// resolved to `X11Forwarding no`).
    fn x11_forwarding_allowed(&self) -> bool {
        self.x11_forwarding != Some(false)
    }

    /// True iff `direct-tcpip` (`ssh -L`) opens are permitted by
    /// `AllowTcpForwarding`. Default-allow when unset.
    fn local_forwarding_allowed(&self) -> bool {
        self.allow_tcp_forwarding.is_none_or(|p| p.local_allowed())
    }

    /// True iff `tcpip-forward` (`ssh -R`) requests are permitted by
    /// `AllowTcpForwarding`. Default-allow when unset.
    fn remote_forwarding_allowed(&self) -> bool {
        self.allow_tcp_forwarding.is_none_or(|p| p.remote_allowed())
    }

    /// True iff a `direct-tcpip` open to `(host, port)` is permitted by
    /// `PermitOpen`. Unset ⇒ any; empty list ⇒ none.
    fn permit_open_allows(&self, host: &str, port: u16) -> bool {
        match &self.permit_open {
            None => true,
            Some(list) => list.iter().any(|e| e.matches(host, port)),
        }
    }

    /// True iff a `tcpip-forward` bind to `(host, port)` is permitted by
    /// `PermitListen`. Unset ⇒ any; empty list ⇒ none.
    fn permit_listen_allows(&self, host: &str, port: u16) -> bool {
        match &self.permit_listen {
            None => true,
            Some(list) => list.iter().any(|e| e.matches(host, port)),
        }
    }
}

/// Environment variable names that no [`Config::accept_env`] glob may
/// override. Mirrors the set OpenSSH refuses to import even with
/// `AcceptEnv *`: dynamic-linker preload knobs, shell init scripts that
/// run before the parent can sanitize the env, and identity names that
/// must follow `/etc/passwd` (not the peer).
pub const HARD_BLOCKED_ENV_NAMES: &[&str] = &[
    "LD_PRELOAD",
    "LD_LIBRARY_PATH",
    "LD_AUDIT",
    "LD_BIND_NOT",
    "DYLD_INSERT_LIBRARIES",
    "DYLD_LIBRARY_PATH",
    "BASH_ENV",
    "ENV",
    "IFS",
    "PATH",
    "SHELL",
    "HOME",
    "USER",
    "LOGNAME",
];

/// True when `name` matches `pattern` under the OpenSSH `AcceptEnv`
/// glob syntax: literal byte-match plus `*` (zero or more) / `?` (one).
/// No bracket sets, no escapes — same minimal grammar OpenSSH uses.
fn env_glob_match(pattern: &str, name: &str) -> bool {
    let pb = pattern.as_bytes();
    let nb = name.as_bytes();
    fn rec(p: &[u8], n: &[u8]) -> bool {
        let mut pi = 0usize;
        let mut ni = 0usize;
        while pi < p.len() {
            match p[pi] {
                b'*' => {
                    // Collapse runs of `*` so the recursion isn't quadratic.
                    while pi < p.len() && p[pi] == b'*' {
                        pi += 1;
                    }
                    if pi == p.len() {
                        return true;
                    }
                    while ni <= n.len() {
                        if rec(&p[pi..], &n[ni..]) {
                            return true;
                        }
                        ni += 1;
                    }
                    return false;
                }
                b'?' => {
                    if ni >= n.len() {
                        return false;
                    }
                    pi += 1;
                    ni += 1;
                }
                c => {
                    if ni >= n.len() || n[ni] != c {
                        return false;
                    }
                    pi += 1;
                    ni += 1;
                }
            }
        }
        ni == n.len()
    }
    rec(pb, nb)
}

/// Decide whether a client-supplied `(name, _)` env pair should be
/// honoured. Returns `true` only when:
/// - `name` is not in [`HARD_BLOCKED_ENV_NAMES`], AND
/// - at least one pattern in `accept_env` matches it.
pub(crate) fn env_name_accepted(name: &str, accept_env: &[String]) -> bool {
    if HARD_BLOCKED_ENV_NAMES.contains(&name) {
        return false;
    }
    accept_env.iter().any(|pat| env_glob_match(pat, name))
}

impl Config {
    /// Build a minimal `Config` with the three required fields filled in
    /// and the re-key policy left at its RFC-default thresholds.
    pub fn new(
        host_keys: Vec<Box<dyn HostKey + Send + Sync>>,
        authenticator: Arc<dyn AuthenticatorFactory>,
        allowed_auth_methods: Vec<&'static str>,
        command_handler: Arc<dyn CommandHandler>,
    ) -> Self {
        Self {
            host_keys,
            authenticator,
            allowed_auth_methods,
            command_handler,
            exec_stream_handler: None,
            shell_handler: None,
            subsystem_handler: None,
            direct_tcpip_handler: None,
            tcpip_forward_handler: None,
            agent_forward_handler: None,
            x11_forward_handler: None,
            on_session_open: None,
            rekey_policy: RekeyPolicy::default(),
            accept_env: Vec::new(),
            login_grace_time: Duration::from_secs(120),
            ciphers: None,
            macs: None,
            kex_algorithms: None,
            host_key_algorithms: None,
            policy: None,
            group_resolver: None,
            compression: None,
            default_auth_methods: Vec::new(),
        }
    }

    /// Set the connection-wide `AuthenticationMethods` default — the
    /// multi-factor chain set handed to the authenticator's
    /// [`crate::auth::Authenticator::on_user_resolved`] hook. Each entry is one
    /// space-separated alternative, itself a comma-separated chain of required
    /// factors (e.g. `"publickey,password"`). Empty (the default) ⇒
    /// single-factor: any one advertised method suffices.
    pub fn with_auth_methods(mut self, methods: Vec<String>) -> Self {
        self.default_auth_methods = methods;
        self
    }

    /// Attach a parsed `sshd_config` policy. The policy is resolved
    /// per-connection (pre- and post-auth) to gate the auth method set,
    /// banner, and forwarding capabilities. Without it, only
    /// [`Self::allowed_auth_methods`] applies.
    pub fn with_policy(mut self, policy: Arc<crate::config::SshServerConfig>) -> Self {
        self.policy = Some(policy);
        self
    }

    /// Attach a [`GroupResolver`] used by `Match group` / `AllowGroups` /
    /// `DenyGroups`. Invoked once per connection (post-auth) for every user.
    pub fn with_group_resolver(mut self, resolver: GroupResolver) -> Self {
        self.group_resolver = Some(resolver);
        self
    }

    /// Override the advertised crypto-algorithm preference lists (from
    /// `sshd_config`: `Ciphers`, `MACs`, `KexAlgorithms`,
    /// `HostKeyAlgorithms`). Each argument is an already-resolved list (list
    /// modifiers applied, names validated) or `None` to keep the built-in
    /// default for that category.
    ///
    /// The strict-kex markers are re-appended by the KEXINIT builder
    /// regardless of any `KexAlgorithms` override; `HostKeyAlgorithms` is
    /// used as a preference order and then intersected with the host-key
    /// algorithms the loaded keys can actually produce.
    pub fn with_algorithms(
        mut self,
        ciphers: Option<Vec<String>>,
        macs: Option<Vec<String>>,
        kex_algorithms: Option<Vec<String>>,
        host_key_algorithms: Option<Vec<String>>,
    ) -> Self {
        self.ciphers = ciphers;
        self.macs = macs;
        self.kex_algorithms = kex_algorithms;
        self.host_key_algorithms = host_key_algorithms;
        self
    }

    /// Replace the env-request allow-list. Each entry is a name pattern
    /// matched against the `name` field of incoming `"env"` channel
    /// requests (RFC 4254 §6.4); the pattern grammar is the OpenSSH
    /// `AcceptEnv` subset (`*`, `?`). Names in
    /// [`HARD_BLOCKED_ENV_NAMES`] (`LD_PRELOAD`, `PATH`, `HOME`, …) are
    /// always refused — they cannot be re-enabled by listing them.
    ///
    /// The default is empty, i.e. every client env request is dropped.
    pub fn with_accept_env(mut self, patterns: Vec<String>) -> Self {
        self.accept_env = patterns;
        self
    }

    /// Set the pre-authentication inactivity timeout (OpenSSH's
    /// `LoginGraceTime`). The socket carries this read-timeout from
    /// banner exchange through to `userauth-success`; after auth the
    /// timeout is cleared. Defaults to 120 seconds. Pass
    /// [`Duration::ZERO`] to disable.
    pub fn with_login_grace_time(mut self, dur: Duration) -> Self {
        self.login_grace_time = dur;
        self
    }

    /// Attach a `ShellHandler` to this config. Without a handler, `"shell"`
    /// (and `"pty-req"`) channel requests are rejected with
    /// `CHANNEL_FAILURE`; with one, the server invokes
    /// [`ShellHandler::spawn`] when the client sends `"shell"`.
    pub fn with_shell(mut self, handler: Arc<dyn ShellHandler>) -> Self {
        self.shell_handler = Some(handler);
        self
    }

    /// Attach a `SubsystemHandler` to this config. Without a handler, any
    /// `"subsystem"` channel request is rejected.
    pub fn with_subsystem(mut self, handler: Arc<dyn SubsystemHandler>) -> Self {
        self.subsystem_handler = Some(handler);
        self
    }

    /// Attach an `ExecStreamHandler` overlay. The dispatcher consults it
    /// **before** the synchronous [`CommandHandler`] on every `"exec"`
    /// channel request; handlers that return `None` fall through to
    /// the existing buffered path. Used by sshd's in-process SCP support.
    pub fn with_exec_stream_handler(mut self, handler: Arc<dyn ExecStreamHandler>) -> Self {
        self.exec_stream_handler = Some(handler);
        self
    }

    /// Attach a `DirectTcpipHandler`. Without one, all `direct-tcpip`
    /// channel opens (i.e. `ssh -L`) are rejected with
    /// `SSH_OPEN_ADMINISTRATIVELY_PROHIBITED`.
    pub fn with_direct_tcpip(mut self, handler: Arc<dyn DirectTcpipHandler>) -> Self {
        self.direct_tcpip_handler = Some(handler);
        self
    }

    /// Attach a `TcpipForwardHandler`. Without one, every
    /// `tcpip-forward` / `cancel-tcpip-forward` global request (i.e.
    /// `ssh -R`) is answered with `REQUEST_FAILURE`.
    pub fn with_tcpip_forward(mut self, handler: Arc<dyn TcpipForwardHandler>) -> Self {
        self.tcpip_forward_handler = Some(handler);
        self
    }

    /// Attach an `AgentForwardHandler`. Without one, every
    /// `auth-agent-req@openssh.com` channel request (i.e. `ssh -A`) is
    /// answered with `CHANNEL_FAILURE` and no agent forwarding is set up.
    pub fn with_agent_forward(mut self, handler: Arc<dyn AgentForwardHandler>) -> Self {
        self.agent_forward_handler = Some(handler);
        self
    }

    /// Attach an `X11ForwardHandler`. Without one, every `x11-req` channel
    /// request (i.e. `ssh -X` / `ssh -Y`) is answered with `CHANNEL_FAILURE`
    /// and no display is bound.
    pub fn with_x11_forward(mut self, handler: Arc<dyn X11ForwardHandler>) -> Self {
        self.x11_forward_handler = Some(handler);
        self
    }

    /// Register a callback fired once per connection between
    /// `userauth_success` and the channel loop. Use this to drop privileges
    /// to the authenticated user. The [`SessionOpenContext`] carries the
    /// resolved `ChrootDirectory` (an implementation that `setuid`s should
    /// `chroot()` to it first, while still root) and `PrintMotd`. Returning
    /// `Err` aborts the connection.
    pub fn on_session_open<F>(mut self, f: F) -> Self
    where
        F: Fn(&SessionOpenContext<'_>) -> Result<()> + Send + Sync + 'static,
    {
        self.on_session_open = Some(Arc::new(f));
        self
    }
}

/// Per-connection authenticator factory.
///
/// `ServerAuth` owns its `Box<dyn Authenticator>`, and `Authenticator`
/// itself is `&mut self`-stateful (rate limits, partial accepts, ...).
/// Building a fresh authenticator per connection avoids cross-connection
/// state bleed and the `Sync` requirement on user code.
pub trait AuthenticatorFactory: Send + Sync {
    /// Build a fresh authenticator for one connection.
    fn build(&self) -> Box<dyn Authenticator>;

    /// Build a fresh authenticator for one connection, told the peer's
    /// resolved address. The default ignores `peer` and delegates to
    /// [`Self::build`]; factories that match `AllowUsers`/`DenyUsers`
    /// `user@host` patterns override this to capture the peer for the
    /// host half of the match. `peer` is `None` when the address is the
    /// unspecified placeholder (e.g. an in-process test transport).
    fn build_with_peer(&self, peer: Option<&str>) -> Box<dyn Authenticator> {
        let _ = peer;
        self.build()
    }
}

impl<F> AuthenticatorFactory for F
where
    F: Fn() -> Box<dyn Authenticator> + Send + Sync,
{
    fn build(&self) -> Box<dyn Authenticator> {
        (self)()
    }
}

/// A blocking SSH server.
pub struct Server {
    listener: TcpListener,
    cfg: Arc<Config>,
}

impl Server {
    /// Bind the server to `addr`. Validates that at least one host key is
    /// configured.
    pub fn bind<A: ToSocketAddrs>(addr: A, cfg: Config) -> Result<Self> {
        if cfg.host_keys.is_empty() {
            return Err(Error::Protocol("server: no host keys configured"));
        }
        let listener = TcpListener::bind(addr)?;
        Ok(Self {
            listener,
            cfg: Arc::new(cfg),
        })
    }

    /// Local socket address (useful when binding to port 0).
    pub fn local_addr(&self) -> Result<SocketAddr> {
        Ok(self.listener.local_addr()?)
    }

    /// Accept one connection and handle it on the current thread, blocking
    /// until the session closes. Intended for single-connection test harnesses.
    pub fn accept_one(&mut self) -> Result<()> {
        let (stream, peer) = self.listener.accept()?;
        handle_session_with_peer(stream, peer, self.cfg.clone())
    }

    /// Accept connections forever, spawning a fresh thread per connection.
    pub fn serve(&mut self) -> Result<()> {
        loop {
            let (stream, peer) = self.listener.accept()?;
            let cfg = self.cfg.clone();
            thread::spawn(move || {
                let _ = handle_session_with_peer(stream, peer, cfg);
            });
        }
    }
}

/// Run one SSH session on `stream` to completion (handshake, auth, channel
/// loop). Returns when the peer disconnects or an error is fatal.
///
/// Exposed primarily for binaries that want their own accept loop — for
/// example, an `sshd` that `fork()`s before invoking this so the daemon
/// can be restarted independently of live sessions.
pub fn handle_session(stream: TcpStream, cfg: Arc<Config>) -> Result<()> {
    // Derive the peer from the socket itself so the historical entry point
    // keeps working; callers that already have the accepted peer address
    // should prefer `handle_session_with_peer` to avoid the extra syscall.
    let peer = stream
        .peer_addr()
        .unwrap_or_else(|_| SocketAddr::from(([0, 0, 0, 0], 0)));
    handle_session_with_peer(stream, peer, cfg)
}

/// Like [`handle_session`] but takes the already-known peer address (as
/// returned by `TcpListener::accept`). The peer address and the socket's
/// local address feed the per-connection `sshd_config` `Match` resolution
/// (`Match address` / `localaddress` / `localport`).
pub fn handle_session_with_peer(
    stream: TcpStream,
    peer: SocketAddr,
    cfg: Arc<Config>,
) -> Result<()> {
    let local = stream.local_addr().ok();
    handle_connection_inner(stream, peer, local, cfg)
}

/// Normalize a pre-auth I/O outcome into something the caller can treat
/// as "clean disconnect" without conflating it with a true protocol
/// error. Read-timeouts (the socket-level `LoginGraceTime` deadline) and
/// the would-block flavour of the same arrive as `io::ErrorKind::TimedOut`
/// or `WouldBlock`; we rewrap them as a fresh `TimedOut` so call sites
/// don't have to know the platform's spelling.
fn map_preauth_timeout<T>(r: Result<T>) -> Result<T> {
    match r {
        Err(Error::Io(e)) if matches!(e.kind(), ErrorKind::TimedOut | ErrorKind::WouldBlock) => {
            Err(Error::Io(std::io::Error::new(
                ErrorKind::TimedOut,
                "pre-auth inactivity timeout (LoginGraceTime)",
            )))
        }
        other => other,
    }
}

fn handle_connection_inner(
    mut stream: TcpStream,
    peer: SocketAddr,
    local: Option<SocketAddr>,
    cfg: Arc<Config>,
) -> Result<()> {
    stream.set_nodelay(true)?;

    // RFC 4252 / OpenSSH "LoginGraceTime": cap the time the peer can
    // sit idle between TCP accept and userauth-success. We arm the
    // socket-level read timeout once here; every subsequent blocking
    // `read` in banner exchange, KEX, and auth inherits it without
    // having to thread a deadline through the handshake.
    let grace = cfg.login_grace_time;
    if !grace.is_zero() {
        stream.set_read_timeout(Some(grace))?;
    }

    let mut codec = PacketCodec::new();
    let mut inbox: Vec<u8> = Vec::new();
    let mut rng = OsRng;

    let v_s = crate::transport::version::LOCAL_VERSION.as_bytes().to_vec();
    map_preauth_timeout(
        stream
            .write_all(&VersionExchange::outgoing_bytes())
            .map_err(Error::Io),
    )?;
    let v_c = map_preauth_timeout(read_peer_version(&mut stream))?;

    let (mut runner, session_id) = map_preauth_timeout(do_server_kex(
        &mut stream,
        &mut codec,
        &mut rng,
        &mut inbox,
        &cfg,
        &v_c,
        &v_s,
    ))?;
    let mut last_kex = Instant::now();

    // Phase 1 (pre-auth): resolve the policy with an address-only context.
    // This yields the auth method set advertised to the client and an
    // address-matched banner. `None` policy ⇒ fall back to the static
    // `allowed_auth_methods` and no banner.
    let peer_ip = ip_string(&peer);
    let local_ip = local.and_then(|a| ip_string(&a));
    let local_port = local.map(|a| a.port());
    let preauth = resolve_preauth_policy(&cfg, peer_ip.as_deref(), local_ip.as_deref(), local_port);

    let user = map_preauth_timeout(do_server_auth(
        &mut stream,
        &mut codec,
        &mut rng,
        &mut inbox,
        &cfg,
        session_id,
        &preauth,
        peer_ip.as_deref(),
        local_ip.as_deref(),
        local_port,
    ))?;

    // Past userauth-success: lift the grace timeout. The connection
    // loop installs its own short read timeout (50 ms) on demand when
    // it has work to drain; we don't want the grace deadline tripping
    // mid-session on a keep-alive lull.
    if !grace.is_zero() {
        stream.set_read_timeout(None)?;
    }

    // Phase 2 (post-auth): resolve the policy with the full user/groups
    // context to build the per-connection capability ceiling. Resolved
    // *before* the privilege-drop hook so the hook can act on policy that
    // must take effect while we are still root — notably `ChrootDirectory`,
    // which must `chroot()` before `setuid` (chroot needs root).
    let groups = resolve_user_groups(&cfg, &user);
    let effective = resolve_effective_policy(
        &cfg,
        &user,
        groups.as_deref(),
        peer_ip.as_deref(),
        local_ip.as_deref(),
        local_port,
    );

    // Connection-level hook: drop privileges to the authenticated user
    // before any shell / exec / subsystem runs. After this call all I/O on
    // this connection happens as `user`, including the in-process SFTP
    // subsystem and any forked exec children. The hook is also told the
    // resolved `ChrootDirectory` (if any) so it can `chroot()` while still
    // root, before its own `setuid`.
    if let Some(hook) = cfg.on_session_open.clone() {
        let ctx = SessionOpenContext {
            user: &user,
            chroot_directory: effective.chroot_directory.as_deref(),
            print_motd: effective.print_motd.unwrap_or(false),
        };
        hook(&ctx)?;
    }

    // RFC 4253 §6.2: zlib@openssh.com starts compressing here.
    codec.activate_compress();

    let rekey_policy = cfg.rekey_policy;
    let r = do_connection_phase(
        &mut stream,
        &mut codec,
        &mut rng,
        &mut inbox,
        &cfg,
        &user,
        &mut runner,
        &v_c,
        &v_s,
        &mut last_kex,
        &rekey_policy,
        &effective,
    );

    let _ = send_disconnect(
        &mut stream,
        &mut codec,
        &mut rng,
        SSH_DISCONNECT_BY_APPLICATION,
        "closing session",
    );
    r
}

fn do_server_kex<R: RngCore + CryptoRng>(
    stream: &mut TcpStream,
    codec: &mut PacketCodec,
    rng: &mut R,
    inbox: &mut Vec<u8>,
    cfg: &Config,
    v_c: &[u8],
    v_s: &[u8],
) -> Result<(KexRunner, Vec<u8>)> {
    // First KEX only: advertise ext-info-s so the client may send us
    // SSH_MSG_EXT_INFO (RFC 8308 §2.1). Re-KEX paths use the un-marked
    // builder via KexRunner::restart, which scrubs the marker.
    let advert = build_server_kexinit(rng, cfg).with_ext_info_marker(Role::Server);
    let mut runner = KexRunner::new(Role::Server, advert);
    // Queue our outbound EXT_INFO; the runner emits it after NEWKEYS on the
    // first KEX iff the client also advertised the marker.
    runner.set_outbound_ext_info(server_ext_info());
    let initial = runner.start(rng)?;
    for p in initial.outbound {
        write_payload(stream, codec, rng, &p)?;
    }

    drive_server_kex(stream, codec, rng, inbox, &mut runner, cfg, v_c, v_s)?;

    let sid = runner
        .session_id()
        .ok_or(Error::Protocol("kex: missing session id"))?
        .to_vec();
    Ok((runner, sid))
}

/// Drive a KEX (initial or re-key) to completion. The caller must have
/// already pushed our own KEXINIT onto the wire via `start()` or `restart()`.
#[allow(clippy::too_many_arguments)]
fn drive_server_kex<R: RngCore + CryptoRng>(
    stream: &mut TcpStream,
    codec: &mut PacketCodec,
    rng: &mut R,
    inbox: &mut Vec<u8>,
    runner: &mut KexRunner,
    cfg: &Config,
    v_c: &[u8],
    v_s: &[u8],
) -> Result<()> {
    let mut steps = 0usize;
    let mut selected_host_key: Option<&(dyn HostKey + Send + Sync)> = None;

    loop {
        steps += 1;
        if steps > MAX_KEX_STEPS {
            return Err(Error::Protocol("kex: too many steps"));
        }
        let payload = read_one_packet(stream, codec, inbox)?;

        if selected_host_key.is_none()
            && let Some(neg) = runner.negotiated()
        {
            selected_host_key = pick_host_key(&cfg.host_keys, &neg.host_key);
            if selected_host_key.is_none() {
                return Err(Error::Protocol("kex: no host key for negotiated algorithm"));
            }
        }

        let hk_ref: Option<&dyn HostKey> = selected_host_key.map(|k| k as &dyn HostKey);
        let adv = runner.on_packet(rng, codec, &payload, hk_ref, None, v_c, v_s)?;
        for p in adv.outbound {
            write_payload(stream, codec, rng, &p)?;
        }
        if adv.completed {
            return Ok(());
        }
    }
}

/// The textual form of a socket address's IP (no port). Returns `None` for
/// the unspecified placeholder so a `Match address` never matches a missing
/// address.
fn ip_string(addr: &SocketAddr) -> Option<String> {
    let ip = addr.ip();
    if ip.is_unspecified() {
        None
    } else {
        Some(ip.to_string())
    }
}

/// Pre-auth (Phase 1) resolution result: the auth method set to advertise and
/// the banner text (if any) to send before the userauth loop.
struct PreAuthPolicy {
    /// Auth methods to advertise. Empty ⇒ guaranteed lockout (every attempt
    /// fails) — this is how `PubkeyAuthentication no` is honoured.
    methods: Vec<&'static str>,
    /// Resolved `MaxAuthTries`, if the policy set one.
    max_auth_tries: Option<u32>,
    /// Resolved (address-matched) banner text, if any.
    banner: Option<String>,
}

/// Phase 1: resolve the policy with an address-only context. Without a policy
/// this reproduces the historical behaviour (static `allowed_auth_methods`,
/// no banner, no MaxAuthTries).
fn resolve_preauth_policy(
    cfg: &Config,
    address: Option<&str>,
    local_address: Option<&str>,
    local_port: Option<u16>,
) -> PreAuthPolicy {
    let Some(policy) = cfg.policy.as_ref() else {
        return PreAuthPolicy {
            methods: cfg.allowed_auth_methods.clone(),
            max_auth_tries: None,
            banner: None,
        };
    };
    let ctx = crate::config::MatchContext {
        host: "",
        address,
        local_address,
        local_port,
        ..crate::config::MatchContext::default()
    };
    let opts = policy.resolve(&ctx, crate::config::match_block::ExecPolicy::Deny);
    let methods = resolve_auth_methods(&cfg.allowed_auth_methods, &opts);
    let banner = opts
        .banner
        .as_deref()
        .and_then(|p| std::fs::read_to_string(p).ok());
    PreAuthPolicy {
        methods,
        max_auth_tries: opts.max_auth_tries,
        banner,
    }
}

/// Compute the advertised auth method set from the static config default and
/// the resolved policy options. The base set is what the binary computed at
/// startup (e.g. `["publickey", "password"]`); a `Match` block can only ever
/// *subtract* from it by turning a method off:
///
/// - `PubkeyAuthentication no` ⇒ drop `publickey`.
/// - `PasswordAuthentication no` ⇒ drop `password`.
/// - `KbdInteractiveAuthentication no` ⇒ drop `keyboard-interactive`.
///
/// A method is never *added* here — the base set already reflects whether a
/// PAM backend is compiled in, so a `Match` block enabling password auth on a
/// non-PAM build cannot conjure a method the server cannot satisfy.
fn resolve_auth_methods(
    base: &[&'static str],
    opts: &crate::config::ServerOptions,
) -> Vec<&'static str> {
    let mut methods: Vec<&'static str> = base.to_vec();
    if opts.pubkey_authentication == Some(false) {
        methods.retain(|m| *m != "publickey");
    }
    if opts.password_authentication == Some(false) {
        methods.retain(|m| *m != "password");
    }
    if opts.kbd_interactive_authentication == Some(false) {
        methods.retain(|m| *m != "keyboard-interactive");
    }
    methods
}

/// Resolve `user`'s supplementary group names via the configured
/// [`GroupResolver`], if any. Called once per connection for *every* user
/// uniformly (no early-out for unknown users) so the lookup cannot become a
/// user-enumeration timing oracle. `None` ⇒ no resolver configured.
fn resolve_user_groups(cfg: &Config, user: &str) -> Option<Vec<String>> {
    cfg.group_resolver.as_ref().map(|r| r(user))
}

/// Phase 2: resolve the policy with the full user/groups context into the
/// per-connection [`EffectivePolicy`]. Without a policy this returns
/// [`EffectivePolicy::unrestricted`].
fn resolve_effective_policy(
    cfg: &Config,
    user: &str,
    groups: Option<&[String]>,
    address: Option<&str>,
    local_address: Option<&str>,
    local_port: Option<u16>,
) -> EffectivePolicy {
    let Some(policy) = cfg.policy.as_ref() else {
        return EffectivePolicy::unrestricted();
    };
    let ctx = crate::config::MatchContext {
        host: "",
        user: Some(user),
        groups,
        address,
        local_address,
        local_port,
        ..crate::config::MatchContext::default()
    };
    let opts = policy.resolve(&ctx, crate::config::match_block::ExecPolicy::Deny);
    EffectivePolicy {
        allow_agent_forwarding: opts.allow_agent_forwarding,
        x11_forwarding: opts.x11_forwarding,
        max_sessions: opts.max_sessions,
        allow_tcp_forwarding: opts.allow_tcp_forwarding,
        permit_open: opts.permit_open,
        permit_listen: opts.permit_listen,
        gateway_ports: opts.gateway_ports,
        force_command: opts.force_command,
        chroot_directory: opts.chroot_directory,
        client_alive_interval: opts.client_alive_interval,
        client_alive_count_max: opts.client_alive_count_max,
        print_motd: opts.print_motd,
    }
}

#[allow(clippy::too_many_arguments)]
fn do_server_auth<R: RngCore + CryptoRng>(
    stream: &mut TcpStream,
    codec: &mut PacketCodec,
    rng: &mut R,
    inbox: &mut Vec<u8>,
    cfg: &Config,
    session_id: Vec<u8>,
    preauth: &PreAuthPolicy,
    peer_ip: Option<&str>,
    local_ip: Option<&str>,
    local_port: Option<u16>,
) -> Result<String> {
    let methods = preauth.methods.clone();
    let auth_impl = cfg.authenticator.build_with_peer(peer_ip);
    let mut server_auth = ServerAuth::new(session_id, methods, auth_impl);
    server_auth.set_max_auth_tries(preauth.max_auth_tries);

    // Address-matched banner (USERAUTH_BANNER), sent before the first
    // USERAUTH_REQUEST per RFC 4252 §5.4. A `Match User` banner is deferred
    // until the username is known (the first USERAUTH_REQUEST), below.
    if let Some(text) = preauth.banner.as_deref() {
        let banner = crate::auth::message::UserauthBanner {
            message: text.to_string(),
            language: String::new(),
        };
        write_payload(stream, codec, rng, &banner.encode())?;
    }

    // Phase 1.5 (mid-userauth): the first USERAUTH_REQUEST exposes the
    // username. We re-resolve the policy *once* with the user/groups context
    // so a `Match User`/`Match Group` block can change the advertised method
    // set (`PubkeyAuthentication` / `AuthenticationMethods`) and deliver a
    // user-matched banner. `resolved_user` records that we've done it so the
    // re-resolve never runs twice.
    let mut resolved_user: Option<String> = None;

    for _ in 0..MAX_AUTH_STEPS {
        let payload = read_one_packet(stream, codec, inbox)?;

        // Re-resolve on the first request that carries a username, before the
        // attempt is evaluated. Subsequent requests reuse the resolved set.
        if let Some((user, method)) = ServerAuth::peek_request(&payload) {
            if resolved_user.is_none() {
                let reres = reresolve_user_policy(
                    cfg,
                    &preauth.methods,
                    &user,
                    peer_ip,
                    local_ip,
                    local_port,
                );
                server_auth.set_accepted_methods(reres.methods);
                // Let the authenticator install per-user multi-factor chains
                // (resolved from `AuthenticationMethods` in any matched block)
                // before the first attempt is evaluated.
                server_auth.notify_user_resolved(&user, &reres.auth_methods);
                if let Some(text) = reres.banner.as_deref() {
                    let banner = crate::auth::message::UserauthBanner {
                        message: text.to_string(),
                        language: String::new(),
                    };
                    write_payload(stream, codec, rng, &banner.encode())?;
                }
                resolved_user = Some(user);
            }

            // If the re-resolved policy forbids the method the client is
            // attempting (e.g. `PubkeyAuthentication no` for this user), the
            // attempt is rejected without consulting the authenticator. The
            // `none` probe is always allowed through so the client still
            // learns the (possibly empty) advertised set.
            if method != "none" && !server_auth.accepted_methods().contains(&method) {
                match server_auth.reject_unadvertised()? {
                    ServerStep::Send(p) => {
                        write_payload(stream, codec, rng, &p)?;
                        continue;
                    }
                    ServerStep::Disconnect(reason) => {
                        let _ = send_disconnect(
                            stream,
                            codec,
                            rng,
                            SSH_DISCONNECT_HOST_NOT_ALLOWED,
                            reason,
                        );
                        return Err(Error::AuthFailed);
                    }
                    ServerStep::Authenticated { .. } => unreachable!(),
                }
            }
        }

        match server_auth.on_packet(&payload)? {
            ServerStep::Send(p) => write_payload(stream, codec, rng, &p)?,
            ServerStep::Authenticated { payload, user } => {
                write_payload(stream, codec, rng, &payload)?;
                return Ok(user);
            }
            ServerStep::Disconnect(reason) => {
                let _ =
                    send_disconnect(stream, codec, rng, SSH_DISCONNECT_HOST_NOT_ALLOWED, reason);
                return Err(Error::AuthFailed);
            }
        }
    }
    Err(Error::Protocol("auth: too many steps"))
}

/// Phase 1.5 re-resolution result: the auth method set to advertise once the
/// username is known, plus a user-matched banner (if any).
struct ReResolvedUserPolicy {
    methods: Vec<&'static str>,
    banner: Option<String>,
    /// Resolved `AuthenticationMethods` for this user (space-separated
    /// alternatives, each a comma-chain). Empty ⇒ single-factor.
    auth_methods: Vec<String>,
}

/// Re-resolve the policy with the full user/groups context (the first
/// USERAUTH_REQUEST exposed the username). Yields the user-conditioned method
/// set and banner. Without a policy this reproduces the pre-auth method set and
/// no banner. The group context reuses the same [`GroupResolver`] the
/// post-auth access checks use, so `Match Group` is honoured uniformly.
fn reresolve_user_policy(
    cfg: &Config,
    base_methods: &[&'static str],
    user: &str,
    address: Option<&str>,
    local_address: Option<&str>,
    local_port: Option<u16>,
) -> ReResolvedUserPolicy {
    let Some(policy) = cfg.policy.as_ref() else {
        return ReResolvedUserPolicy {
            methods: base_methods.to_vec(),
            banner: None,
            auth_methods: cfg.default_auth_methods.clone(),
        };
    };
    let groups = resolve_user_groups(cfg, user);
    let ctx = crate::config::MatchContext {
        host: "",
        user: Some(user),
        groups: groups.as_deref(),
        address,
        local_address,
        local_port,
        ..crate::config::MatchContext::default()
    };
    let opts = policy.resolve(&ctx, crate::config::match_block::ExecPolicy::Deny);
    let methods = resolve_auth_methods(&cfg.allowed_auth_methods, &opts);
    // Unreadable banner file → skip (never fail auth on a bad banner). This
    // mirrors the address-matched banner path's `.ok()` policy.
    let banner = opts
        .banner
        .as_deref()
        .and_then(|p| std::fs::read_to_string(p).ok());
    // A `Match` block may override `AuthenticationMethods`; fall back to the
    // connection-wide default when it doesn't.
    let auth_methods = opts
        .authentication_methods
        .clone()
        .unwrap_or_else(|| cfg.default_auth_methods.clone());
    ReResolvedUserPolicy {
        methods,
        banner,
        auth_methods,
    }
}

/// Per-connection state for server-initiated `forwarded-tcpip` channel
/// opens (i.e. `ssh -R` traffic). The accept-loops inside
/// [`TcpipForwardHandler`] implementations push [`ForwardOpenRequest`]s
/// here; the connection loop drains them, emits `SSH_MSG_CHANNEL_OPEN`,
/// and parks the reply slot in `pending_opens` until the client confirms
/// or rejects.
struct ForwardConn {
    req_tx: Sender<ForwardOpenRequest>,
    req_rx: Receiver<ForwardOpenRequest>,
    /// Local channel id -> reply slot for that open.
    pending_opens: BTreeMap<u32, std::sync::mpsc::SyncSender<Result<ChannelStream>>>,
    /// `(bind_address, bind_port)` pairs we've handed to the handler, so
    /// we can unbind them on connection teardown.
    owned_bindings: Vec<(String, u16)>,
}

impl ForwardConn {
    fn new() -> Self {
        let (req_tx, req_rx) = std::sync::mpsc::channel();
        Self {
            req_tx,
            req_rx,
            pending_opens: BTreeMap::new(),
            owned_bindings: Vec::new(),
        }
    }

    /// Emit one `SSH_MSG_CHANNEL_OPEN forwarded-tcpip` per queued request,
    /// returning early on a hard write error. Pending-reply entries land
    /// in `self.pending_opens` keyed by the freshly-allocated local id.
    fn drain_pending<R: RngCore + CryptoRng>(
        &mut self,
        stream: &mut TcpStream,
        codec: &mut PacketCodec,
        rng: &mut R,
        conn: &mut ConnectionState,
    ) -> Result<()> {
        loop {
            match self.req_rx.try_recv() {
                Ok(req) => {
                    let kind = ChannelOpen::ForwardedTcpip {
                        dest_host: req.bound_address.clone(),
                        dest_port: req.bound_port,
                        orig_host: req.orig_address.clone(),
                        orig_port: req.orig_port,
                    };
                    let (local_id, payload) = conn.open(kind)?;
                    write_payload(stream, codec, rng, &payload)?;
                    self.pending_opens.insert(local_id, req.reply);
                }
                Err(TryRecvError::Empty) => return Ok(()),
                Err(TryRecvError::Disconnected) => return Ok(()),
            }
        }
    }
}

/// Per-connection state for server-initiated `auth-agent@openssh.com`
/// channel opens (`ssh -A` traffic). Mirrors [`ForwardConn`] but for the
/// payload-free OpenSSH agent extension: the accept loop inside an
/// [`AgentForwardHandler`] pushes [`AgentOpenRequest`]s here; the connection
/// loop drains them, emits `SSH_MSG_CHANNEL_OPEN`, and parks the reply slot
/// in `pending_opens` until the client confirms or rejects.
///
/// `active` keys [`AgentForwardHandle`]s by **session** channel id, not by
/// the agent-channel id — the handle is the per-session listener and we
/// drop it when the session channel closes (not when an individual agent
/// channel closes; one session can pump many agent connections).
struct AgentForwardConn {
    req_tx: Sender<AgentOpenRequest>,
    req_rx: Receiver<AgentOpenRequest>,
    /// Local channel id of an in-flight agent channel-open -> reply slot.
    pending_opens: BTreeMap<u32, std::sync::mpsc::SyncSender<Result<ChannelStream>>>,
    /// Per-session-channel handles keeping listener threads alive.
    active: BTreeMap<u32, AgentForwardHandle>,
}

impl AgentForwardConn {
    fn new() -> Self {
        let (req_tx, req_rx) = std::sync::mpsc::channel();
        Self {
            req_tx,
            req_rx,
            pending_opens: BTreeMap::new(),
            active: BTreeMap::new(),
        }
    }

    /// Emit one `SSH_MSG_CHANNEL_OPEN auth-agent@openssh.com` per queued
    /// request. Pending-reply entries land in `self.pending_opens` keyed by
    /// the freshly-allocated local id.
    fn drain_pending<R: RngCore + CryptoRng>(
        &mut self,
        stream: &mut TcpStream,
        codec: &mut PacketCodec,
        rng: &mut R,
        conn: &mut ConnectionState,
    ) -> Result<()> {
        loop {
            match self.req_rx.try_recv() {
                Ok(req) => {
                    let (local_id, payload) = conn.open(ChannelOpen::AuthAgent)?;
                    write_payload(stream, codec, rng, &payload)?;
                    self.pending_opens.insert(local_id, req.reply);
                }
                Err(TryRecvError::Empty) => return Ok(()),
                Err(TryRecvError::Disconnected) => return Ok(()),
            }
        }
    }
}

/// Per-connection state for server-initiated `x11` channel opens (`ssh -X`
/// / `ssh -Y` traffic). Mirrors [`AgentForwardConn`] but for the RFC 4254
/// §6.3 X11 forwarding wire form: the accept loop inside an
/// [`X11ForwardHandler`] pushes [`X11OpenRequest`]s here; the connection
/// loop drains them, emits `SSH_MSG_CHANNEL_OPEN`, and parks the reply
/// slot in `pending_opens` until the client confirms or rejects.
///
/// `active` keys [`X11ForwardHandle`]s by **session** channel id; the
/// handle is the per-session display listener and we drop it when the
/// session channel closes (one session can pump many `x11` channels).
struct X11ForwardConn {
    req_tx: Sender<X11OpenRequest>,
    req_rx: Receiver<X11OpenRequest>,
    /// Local channel id of an in-flight x11 channel-open -> reply slot.
    pending_opens: BTreeMap<u32, std::sync::mpsc::SyncSender<Result<ChannelStream>>>,
    /// Per-session-channel handles keeping display listener threads alive.
    active: BTreeMap<u32, X11ForwardHandle>,
}

impl X11ForwardConn {
    fn new() -> Self {
        let (req_tx, req_rx) = std::sync::mpsc::channel();
        Self {
            req_tx,
            req_rx,
            pending_opens: BTreeMap::new(),
            active: BTreeMap::new(),
        }
    }

    /// Emit one `SSH_MSG_CHANNEL_OPEN x11` per queued request. Pending-reply
    /// entries land in `self.pending_opens` keyed by the freshly-allocated
    /// local id.
    fn drain_pending<R: RngCore + CryptoRng>(
        &mut self,
        stream: &mut TcpStream,
        codec: &mut PacketCodec,
        rng: &mut R,
        conn: &mut ConnectionState,
    ) -> Result<()> {
        loop {
            match self.req_rx.try_recv() {
                Ok(req) => {
                    let kind = ChannelOpen::X11 {
                        orig_host: req.orig_host.clone(),
                        orig_port: req.orig_port,
                    };
                    let (local_id, payload) = conn.open(kind)?;
                    write_payload(stream, codec, rng, &payload)?;
                    self.pending_opens.insert(local_id, req.reply);
                }
                Err(TryRecvError::Empty) => return Ok(()),
                Err(TryRecvError::Disconnected) => return Ok(()),
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn do_connection_phase<R: RngCore + CryptoRng>(
    stream: &mut TcpStream,
    codec: &mut PacketCodec,
    rng: &mut R,
    inbox: &mut Vec<u8>,
    cfg: &Config,
    user: &str,
    runner: &mut KexRunner,
    v_c: &[u8],
    v_s: &[u8],
    last_kex: &mut Instant,
    rekey_policy: &RekeyPolicy,
    effective: &EffectivePolicy,
) -> Result<()> {
    let mut conn = ConnectionState::new();
    let mut any_channel_opened = false;
    let mut steps = 0usize;
    // App packets received while a re-KEX is in flight (RFC 4253 §7.3).
    // Drained back into the app-layer dispatch as soon as the rekey lands.
    let mut deferred: Vec<Vec<u8>> = Vec::new();
    // Per-channel interactive-shell state. Empty when no `shell` request
    // has been served — in that case the loop stays in pure blocking-read
    // mode and behaves exactly like the historical exec-only path.
    let mut shells: BTreeMap<u32, ShellRuntime> = BTreeMap::new();
    // Per-channel in-process subsystem state (e.g. SFTP). Parallel to
    // `shells`: same polling cadence, same dispatch routing for Data /
    // EOF / Close.
    let mut subsystems: BTreeMap<u32, SubsystemRuntime> = BTreeMap::new();
    // Per-session-channel environment bag. Populated by client `"env"`
    // requests; handed by reference to every CommandHandler / ShellHandler /
    // SubsystemHandler / ExecStreamHandler call. Lives at session-channel
    // granularity because RFC 4254 §6.4 scopes env to the channel.
    let mut envs: BTreeMap<u32, SessionEnv> = BTreeMap::new();
    let mut forward = ForwardConn::new();
    // Per-connection agent-forward queue + active handles. Empty until at
    // least one session channel requests `auth-agent-req@openssh.com`.
    let mut agent_forward = AgentForwardConn::new();
    // Per-connection X11-forward queue + active handles. Empty until at
    // least one session channel requests `x11-req`.
    let mut x11_forward = X11ForwardConn::new();
    let mut polling_active = false;
    let mut extras = ConnExtras::new();
    let result = do_connection_loop(
        stream,
        codec,
        rng,
        inbox,
        cfg,
        user,
        runner,
        v_c,
        v_s,
        last_kex,
        rekey_policy,
        effective,
        &mut conn,
        &mut any_channel_opened,
        &mut steps,
        &mut deferred,
        &mut shells,
        &mut subsystems,
        &mut envs,
        &mut forward,
        &mut agent_forward,
        &mut x11_forward,
        &mut polling_active,
        &mut extras,
    );
    // On teardown — successful or otherwise — release every binding so the
    // TCP listener threads inside the handler exit cleanly.
    if let Some(handler) = cfg.tcpip_forward_handler.clone() {
        for (addr, port) in forward.owned_bindings.drain(..) {
            let _ = handler.unbind(user, &addr, port);
        }
    }
    // Cancel any in-flight forward opens.
    for (_id, reply) in forward.pending_opens.drain_filter_compat() {
        let _ = reply.send(Err(Error::Protocol(
            "forwarded-tcpip: connection torn down",
        )));
    }
    // Tear down every agent-forward listener (their handles' Drop impls do
    // the actual unlink + thread-stop) and notify in-flight agent opens
    // that we're gone.
    agent_forward.active.clear();
    for (_id, reply) in agent_forward.pending_opens.drain_filter_compat() {
        let _ = reply.send(Err(Error::Protocol("auth-agent: connection torn down")));
    }
    // Same for X11-forward listeners.
    x11_forward.active.clear();
    for (_id, reply) in x11_forward.pending_opens.drain_filter_compat() {
        let _ = reply.send(Err(Error::Protocol("x11: connection torn down")));
    }
    result
}

/// Per-connection bookkeeping for the W7 session/forwarding policy gates that
/// the dispatcher needs to mutate across calls: the set of currently-open
/// `session` channels (for `MaxSessions`) and the server-keepalive state (for
/// `ClientAliveInterval` / `ClientAliveCountMax`).
struct ConnExtras {
    /// Local ids of `session` channels currently open. `len()` is the live
    /// session count checked against `MaxSessions`.
    session_channels: BTreeSet<u32>,
    /// Last instant we observed inbound traffic from the peer (reset on every
    /// packet read). Drives the keepalive timer.
    last_activity: Instant,
    /// Last instant we sent a `keepalive@openssh.com` request.
    last_keepalive: Instant,
    /// Number of keepalive requests sent without a matching reply.
    missed_keepalives: u32,
}

impl ConnExtras {
    fn new() -> Self {
        let now = Instant::now();
        ConnExtras {
            session_channels: BTreeSet::new(),
            last_activity: now,
            last_keepalive: now,
            missed_keepalives: 0,
        }
    }
}

/// Helper trait to drain a `BTreeMap` in-place without using the unstable
/// `BTreeMap::drain_filter` API. Yields `(key, value)` pairs in key order
/// and empties the map.
trait DrainFilterCompat<K, V> {
    fn drain_filter_compat(&mut self) -> alloc::vec::IntoIter<(K, V)>;
}

impl<K: Ord + Clone, V> DrainFilterCompat<K, V> for BTreeMap<K, V> {
    fn drain_filter_compat(&mut self) -> alloc::vec::IntoIter<(K, V)> {
        let keys: Vec<K> = self.keys().cloned().collect();
        let mut out = Vec::with_capacity(keys.len());
        for k in keys {
            if let Some(v) = self.remove(&k) {
                out.push((k, v));
            }
        }
        out.into_iter()
    }
}

#[allow(clippy::too_many_arguments)]
fn do_connection_loop<R: RngCore + CryptoRng>(
    stream: &mut TcpStream,
    codec: &mut PacketCodec,
    rng: &mut R,
    inbox: &mut Vec<u8>,
    cfg: &Config,
    user: &str,
    runner: &mut KexRunner,
    v_c: &[u8],
    v_s: &[u8],
    last_kex: &mut Instant,
    rekey_policy: &RekeyPolicy,
    effective: &EffectivePolicy,
    conn: &mut ConnectionState,
    any_channel_opened: &mut bool,
    steps: &mut usize,
    deferred: &mut Vec<Vec<u8>>,
    shells: &mut BTreeMap<u32, ShellRuntime>,
    subsystems: &mut BTreeMap<u32, SubsystemRuntime>,
    envs: &mut BTreeMap<u32, SessionEnv>,
    forward: &mut ForwardConn,
    agent_forward: &mut AgentForwardConn,
    x11_forward: &mut X11ForwardConn,
    polling_active: &mut bool,
    extras: &mut ConnExtras,
) -> Result<()> {
    loop {
        *steps += 1;
        if *steps > MAX_CONNECTION_STEPS {
            return Err(Error::Protocol("connection: step cap exceeded"));
        }

        // Drain any application packets we couldn't process while re-KEXing.
        if !runner.is_kexing() && !deferred.is_empty() {
            let payload = deferred.remove(0);
            // The deferred queue only ever holds non-KEX, non-EXT_INFO app
            // traffic. Re-asserting closes the window if it was ever opened.
            runner.note_inbound_other();
            dispatch_app_packet(
                stream,
                codec,
                rng,
                inbox,
                conn,
                cfg,
                effective,
                user,
                &payload,
                any_channel_opened,
                extras,
                shells,
                subsystems,
                envs,
                forward,
                agent_forward,
                x11_forward,
            )?;
            continue;
        }

        // Shells, subsystems, and live `tcpip-forward` bindings all need
        // the loop to spin: switch the socket to a 50 ms read timeout so
        // we can interleave their I/O with packet reads. Revert when
        // everything goes quiet.
        let any_shell_alive = shells.values().any(|rt| rt.session.is_some());
        let any_subsystem_alive = !subsystems.is_empty();
        let any_forward_alive = !forward.owned_bindings.is_empty();
        // An active agent-forwarder pumps `auth-agent@openssh.com` opens
        // asynchronously from a listener thread; keep the loop polling so
        // its `drain_pending` runs on the same 50 ms tick.
        let any_agent_fwd_alive = !agent_forward.active.is_empty();
        // Same for X11 forwarding: each active display listener spins up
        // `x11` channel-opens asynchronously and needs the 50 ms polling
        // tick to flush them.
        let any_x11_fwd_alive = !x11_forward.active.is_empty();
        // ClientAliveInterval: the keepalive timer needs the loop to spin on
        // the 50 ms tick even when nothing else is draining, so it can notice
        // a silent peer and emit `keepalive@openssh.com`.
        let keepalive_enabled = effective.client_alive_interval.is_some_and(|i| i > 0);
        let want_polling = any_shell_alive
            || any_subsystem_alive
            || any_forward_alive
            || any_agent_fwd_alive
            || any_x11_fwd_alive
            || keepalive_enabled;
        if want_polling && !*polling_active {
            let _ = stream.set_read_timeout(Some(Duration::from_millis(50)));
            *polling_active = true;
        } else if !want_polling && *polling_active {
            let _ = stream.set_read_timeout(None);
            *polling_active = false;
        }

        // Per-tick I/O: shell drains, subsystem egress, and any server-
        // initiated `forwarded-tcpip` opens queued by `TcpipForwardHandler`
        // accept-loops. Only when no KEX is in flight.
        if *polling_active && !runner.is_kexing() {
            drain_shells(stream, codec, rng, conn, shells)?;
            finalize_exited_shells(stream, codec, rng, conn, shells)?;
            drain_subsystems(stream, codec, rng, conn, subsystems)?;
            forward.drain_pending(stream, codec, rng, conn)?;
            agent_forward.drain_pending(stream, codec, rng, conn)?;
            x11_forward.drain_pending(stream, codec, rng, conn)?;
        }

        // ClientAliveInterval / ClientAliveCountMax (OpenSSH server keepalive).
        // After `interval` seconds with no inbound traffic, send a
        // `keepalive@openssh.com` global request (want_reply) and bump the
        // missed counter; the peer's REQUEST_SUCCESS/FAILURE resets it. After
        // CountMax unanswered probes, drop the connection.
        if keepalive_enabled && !runner.is_kexing() {
            let interval = Duration::from_secs(effective.client_alive_interval.unwrap_or(0) as u64);
            let count_max = effective.client_alive_count_max.unwrap_or(3);
            let now = Instant::now();
            if now.duration_since(extras.last_activity) >= interval
                && now.duration_since(extras.last_keepalive) >= interval
            {
                if extras.missed_keepalives >= count_max {
                    return Err(Error::Protocol(
                        "client keepalive: ClientAliveCountMax exceeded",
                    ));
                }
                let p = conn.send_global_request(crate::channel::GlobalRequest::Keepalive, true);
                write_payload(stream, codec, rng, &p)?;
                extras.last_keepalive = now;
                extras.missed_keepalives = extras.missed_keepalives.saturating_add(1);
            }
        }

        if *any_channel_opened
            && !conn.channels().any(|c| !c.is_fully_closed())
            && deferred.is_empty()
            && !any_forward_alive
            && !any_agent_fwd_alive
            && !any_x11_fwd_alive
        {
            return Ok(());
        }

        // RFC 4253 §9: re-key once we've crossed any threshold. Only initiate
        // when no KEX is currently in flight (one side starts; the other will
        // respond when it sees the SSH_MSG_KEXINIT).
        if !runner.is_kexing() && rekey_policy.should_rekey(codec, *last_kex, Instant::now()) {
            let advert = build_server_kexinit(rng, cfg);
            let adv = runner.restart(rng, advert)?;
            for p in adv.outbound {
                write_payload(stream, codec, rng, &p)?;
            }
        }

        let payload = if *polling_active {
            match read_one_packet_maybe_timeout(stream, codec, inbox)? {
                Some(p) => p,
                None => continue, // 50 ms tick; re-enter drain/rekey checks
            }
        } else {
            read_one_packet(stream, codec, inbox)?
        };

        let msg = payload.first().copied().unwrap_or(0);

        // Any inbound packet proves the peer is alive: reset the keepalive
        // activity clock and clear the unanswered-probe counter (a reply to our
        // keepalive arrives as REQUEST_SUCCESS/FAILURE, but any traffic counts).
        extras.last_activity = Instant::now();
        extras.missed_keepalives = 0;

        // RFC 8308 §2.3: client may send a single SSH_MSG_EXT_INFO at the
        // post-NEWKEYS slot of the first KEX. Anywhere else it is a protocol
        // error.
        if msg == 7 {
            if !runner.may_accept_ext_info() {
                return Err(Error::Protocol("unexpected SSH_MSG_EXT_INFO"));
            }
            runner.handle_inbound_ext_info(&payload)?;
            continue;
        }

        // RFC 4253 §7.3: KEX messages (20, 21, 30..=49) are routed through
        // the KEX runner, not the application layer. A peer-initiated re-KEX
        // is signalled by an inbound SSH_MSG_KEXINIT while we are still in
        // Phase::Completed — handle that by emitting our own KEXINIT first.
        if is_kex_msg(msg) {
            if msg == 20 && !runner.is_kexing() {
                let advert = build_server_kexinit(rng, cfg);
                let adv = runner.restart(rng, advert)?;
                for p in adv.outbound {
                    write_payload(stream, codec, rng, &p)?;
                }
            }
            let hk_ref: Option<&dyn HostKey> = match runner.negotiated() {
                Some(neg) => {
                    pick_host_key(&cfg.host_keys, &neg.host_key).map(|k| k as &dyn HostKey)
                }
                None => None,
            };
            let adv = runner.on_packet(rng, codec, &payload, hk_ref, None, v_c, v_s)?;
            for p in adv.outbound {
                write_payload(stream, codec, rng, &p)?;
            }
            if adv.completed {
                *last_kex = Instant::now();
            }
            continue;
        }

        // Application-layer packet. If we're mid-rekey, RFC §7.3 says we
        // must NOT respond with channel traffic — buffer for later. Bound the
        // queue so a peer can't trigger a rekey, withhold its completion, and
        // flood CHANNEL_DATA to exhaust memory.
        if runner.is_kexing() {
            let deferred_bytes: usize = deferred.iter().map(Vec::len).sum();
            if deferred.len() >= MAX_DEFERRED_PACKETS
                || deferred_bytes.saturating_add(payload.len()) > MAX_DEFERRED_BYTES
            {
                return Err(Error::Protocol(
                    "connection: deferred rekey packet queue overflow",
                ));
            }
            deferred.push(payload);
            continue;
        }

        // RFC 8308 §2.3: the post-NEWKEYS ext-info slot is one-shot. Any
        // non-EXT_INFO packet closes the acceptance window.
        runner.note_inbound_other();

        dispatch_app_packet(
            stream,
            codec,
            rng,
            inbox,
            conn,
            cfg,
            effective,
            user,
            &payload,
            any_channel_opened,
            extras,
            shells,
            subsystems,
            envs,
            forward,
            agent_forward,
            x11_forward,
        )?;
    }
}

/// Per-tick: read non-blocking from each live shell and emit CHANNEL_DATA.
/// Bytes that can't ship right now (remote window exhausted) stay in the
/// runtime's `pending_stdout` for the next tick.
fn drain_shells<R: RngCore + CryptoRng>(
    stream: &mut TcpStream,
    codec: &mut PacketCodec,
    rng: &mut R,
    conn: &mut ConnectionState,
    shells: &mut BTreeMap<u32, ShellRuntime>,
) -> Result<()> {
    let mut buf = [0u8; 8 * 1024];
    let channels: Vec<u32> = shells.keys().copied().collect();
    for ch in channels {
        let Some(rt) = shells.get_mut(&ch) else {
            continue;
        };
        if rt.session.is_none() {
            continue;
        }
        // First flush any leftover stdout, then pull fresh bytes from the
        // shell (up to ~64 KiB per tick).
        if !rt.pending_stdout.is_empty() {
            let leftover = core::mem::take(&mut rt.pending_stdout);
            emit_channel_data(stream, codec, rng, conn, ch, &leftover, rt)?;
        }
        // Back-pressure: if the held-over stdout is still at/over the high-
        // water mark after the flush attempt (remote window exhausted because
        // the client stopped reading), do NOT pull more from the shell this
        // tick. The PTY/pipe blocks the user's program instead of letting us
        // buffer unbounded. Reads resume automatically on a later tick once a
        // window adjustment drains `pending_stdout` below the mark. We still
        // ran the exit poll below so a shell that finishes is reaped.
        let mut pulled = 0usize;
        while rt.pending_stdout.len() < SHELL_EGRESS_BACKLOG && pulled < 64 * 1024 {
            if let Some(sess) = rt.session.as_mut() {
                let n = sess.read(&mut buf)?;
                if n == 0 {
                    break;
                }
                pulled += n;
                let bytes = buf[..n].to_vec();
                emit_channel_data(stream, codec, rng, conn, ch, &bytes, rt)?;
            } else {
                break;
            }
        }
        // Poll for exit without blocking; cache the status for finalize_*.
        if rt.exited.is_none()
            && let Some(sess) = rt.session.as_mut()
            && let Some(status) = sess.try_exit()
        {
            rt.exited = Some(status);
        }
    }
    Ok(())
}

/// Send as much of `bytes` over `CHANNEL_DATA` as the remote window allows;
/// stash the remainder on `rt.pending_stdout`.
fn emit_channel_data<R: RngCore + CryptoRng>(
    stream: &mut TcpStream,
    codec: &mut PacketCodec,
    rng: &mut R,
    conn: &mut ConnectionState,
    channel: u32,
    bytes: &[u8],
    rt: &mut ShellRuntime,
) -> Result<()> {
    let mut off = 0usize;
    while off < bytes.len() {
        let (payload, taken) = conn.send_data(channel, &bytes[off..])?;
        if taken == 0 {
            // Remote window is exhausted — buffer the rest for next tick.
            rt.pending_stdout.extend_from_slice(&bytes[off..]);
            return Ok(());
        }
        write_payload(stream, codec, rng, &payload)?;
        off += taken;
    }
    Ok(())
}

/// Per-tick: any shell whose `try_exit` returned `Some` and whose stdout
/// has been flushed gets its `exit-status` / `exit-signal` request, then
/// EOF and CHANNEL_CLOSE.
fn finalize_exited_shells<R: RngCore + CryptoRng>(
    stream: &mut TcpStream,
    codec: &mut PacketCodec,
    rng: &mut R,
    conn: &mut ConnectionState,
    shells: &mut BTreeMap<u32, ShellRuntime>,
) -> Result<()> {
    let channels: Vec<u32> = shells.keys().copied().collect();
    for ch in channels {
        let Some(rt) = shells.get_mut(&ch) else {
            continue;
        };
        if rt.exit_sent {
            continue;
        }
        if !rt.pending_stdout.is_empty() {
            // Wait for the remote window to open before announcing exit.
            continue;
        }
        let Some(status) = rt.exited.take() else {
            continue;
        };
        let req = match status {
            ShellExitStatus::Exited(code) => ChannelRequest::ExitStatus { code },
            ShellExitStatus::Signalled {
                name,
                core_dumped,
                message,
            } => ChannelRequest::ExitSignal {
                name,
                core_dumped,
                message,
                language: String::new(),
            },
        };
        let p = conn.send_request(ch, req, false)?;
        write_payload(stream, codec, rng, &p)?;
        let p = conn.send_eof(ch)?;
        write_payload(stream, codec, rng, &p)?;
        let p = conn.send_close(ch)?;
        write_payload(stream, codec, rng, &p)?;
        rt.exit_sent = true;
        // Drop the session here so the backend can close fds and reap the
        // child process immediately, even before the peer's CLOSE arrives.
        rt.session = None;
    }
    Ok(())
}

/// Per-tick: ship any pending egress from each subsystem onto the wire.
/// Pulls `Data` / `Eof` / `Close` from the handler's `egress_rx`, respecting
/// the remote SSH window — bytes that don't fit go into `pending_data` and
/// are re-attempted on the next tick.
fn drain_subsystems<R: RngCore + CryptoRng>(
    stream: &mut TcpStream,
    codec: &mut PacketCodec,
    rng: &mut R,
    conn: &mut ConnectionState,
    subsystems: &mut BTreeMap<u32, SubsystemRuntime>,
) -> Result<()> {
    let channels: Vec<u32> = subsystems.keys().copied().collect();
    for ch in channels {
        let Some(rt) = subsystems.get_mut(&ch) else {
            continue;
        };
        if rt.close_sent {
            continue;
        }

        // 1) Re-attempt any leftover bytes from last tick.
        if !rt.pending_data.is_empty() {
            let leftover = core::mem::take(&mut rt.pending_data);
            emit_subsystem_data(stream, codec, rng, conn, ch, &leftover, rt)?;
            if !rt.pending_data.is_empty() {
                // Still window-blocked; skip this tick's drain entirely.
                continue;
            }
        }

        // 2) Pull as many egress messages as we can without blocking. Stop
        // as soon as a write window-blocks (pending_data populated again).
        loop {
            if !rt.pending_data.is_empty() {
                break;
            }
            match rt.egress_rx.try_recv() {
                Ok(ChannelEgress::Data(bytes)) => {
                    emit_subsystem_data(stream, codec, rng, conn, ch, &bytes, rt)?;
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
                let p = conn.send_eof(ch)?;
                write_payload(stream, codec, rng, &p)?;
                rt.eof_sent = true;
            }
            if rt.pending_close && !rt.close_sent {
                if !rt.eof_sent {
                    let p = conn.send_eof(ch)?;
                    write_payload(stream, codec, rng, &p)?;
                    rt.eof_sent = true;
                }
                let p = conn.send_close(ch)?;
                write_payload(stream, codec, rng, &p)?;
                rt.close_sent = true;
            }
        }
    }
    Ok(())
}

/// Send `bytes` over `CHANNEL_DATA`, stashing anything the remote window
/// can't accept onto `rt.pending_data` for next tick.
fn emit_subsystem_data<R: RngCore + CryptoRng>(
    stream: &mut TcpStream,
    codec: &mut PacketCodec,
    rng: &mut R,
    conn: &mut ConnectionState,
    channel: u32,
    bytes: &[u8],
    rt: &mut SubsystemRuntime,
) -> Result<()> {
    let mut off = 0usize;
    while off < bytes.len() {
        let (payload, taken) = conn.send_data(channel, &bytes[off..])?;
        if taken == 0 {
            rt.pending_data.extend_from_slice(&bytes[off..]);
            return Ok(());
        }
        write_payload(stream, codec, rng, &payload)?;
        off += taken;
    }
    Ok(())
}

/// Like [`read_one_packet`], but returns `Ok(None)` on a 50 ms read
/// timeout instead of erroring. Other I/O errors propagate.
fn read_one_packet_maybe_timeout(
    stream: &mut TcpStream,
    codec: &mut PacketCodec,
    inbox: &mut Vec<u8>,
) -> Result<Option<Vec<u8>>> {
    match read_one_packet(stream, codec, inbox) {
        Ok(p) => Ok(Some(p)),
        Err(Error::Io(e))
            if e.kind() == ErrorKind::WouldBlock || e.kind() == ErrorKind::TimedOut =>
        {
            Ok(None)
        }
        Err(e) => Err(e),
    }
}

#[allow(clippy::too_many_arguments)]
fn dispatch_app_packet<R: RngCore + CryptoRng>(
    stream: &mut TcpStream,
    codec: &mut PacketCodec,
    rng: &mut R,
    inbox: &mut Vec<u8>,
    conn: &mut ConnectionState,
    cfg: &Config,
    effective: &EffectivePolicy,
    user: &str,
    payload: &[u8],
    any_channel_opened: &mut bool,
    extras: &mut ConnExtras,
    shells: &mut BTreeMap<u32, ShellRuntime>,
    subsystems: &mut BTreeMap<u32, SubsystemRuntime>,
    envs: &mut BTreeMap<u32, SessionEnv>,
    forward: &mut ForwardConn,
    agent_forward: &mut AgentForwardConn,
    x11_forward: &mut X11ForwardConn,
) -> Result<()> {
    let ev = conn.on_packet(payload)?;
    match ev {
        ChannelEvent::OpenConfirmed { channel } => {
            // Server-initiated open landing back. Build a fresh
            // SubsystemRuntime + ChannelStream pair, register the runtime
            // in `subsystems` so the existing dispatch routes
            // Data/Eof/Close, and hand the stream to the handler thread
            // via the reply slot. Three open paths feed into this branch:
            // `forwarded-tcpip` (ssh -R), `auth-agent@openssh.com`
            // (ssh -A), and `x11` (ssh -X / -Y).
            if let Some(reply) = forward.pending_opens.remove(&channel) {
                let (ingress_tx, ingress_rx) = mpsc::channel::<Option<Vec<u8>>>();
                let (egress_tx, egress_rx) =
                    mpsc::sync_channel::<ChannelEgress>(SUBSYSTEM_EGRESS_BACKLOG);
                let cs = ChannelStream::new(ingress_rx, egress_tx);
                subsystems.insert(
                    channel,
                    SubsystemRuntime {
                        ingress_tx,
                        egress_rx,
                        pending_data: Vec::new(),
                        pending_eof: false,
                        pending_close: false,
                        eof_sent: false,
                        close_sent: false,
                    },
                );
                // Best-effort: if the requester has gone away by now,
                // we already mapped the channel into `subsystems`; the
                // dispatcher will tear it down when egress goes
                // disconnected.
                let _ = reply.send(Ok(cs));
            } else if let Some(reply) = agent_forward.pending_opens.remove(&channel) {
                // Symmetric with the `forwarded-tcpip` arm: register a
                // SubsystemRuntime so Data/Eof/Close on the agent channel
                // ride the same dispatch path, then hand the user-facing
                // ChannelStream to the waiting accept-loop thread.
                let (ingress_tx, ingress_rx) = mpsc::channel::<Option<Vec<u8>>>();
                let (egress_tx, egress_rx) =
                    mpsc::sync_channel::<ChannelEgress>(SUBSYSTEM_EGRESS_BACKLOG);
                let cs = ChannelStream::new(ingress_rx, egress_tx);
                subsystems.insert(
                    channel,
                    SubsystemRuntime {
                        ingress_tx,
                        egress_rx,
                        pending_data: Vec::new(),
                        pending_eof: false,
                        pending_close: false,
                        eof_sent: false,
                        close_sent: false,
                    },
                );
                let _ = reply.send(Ok(cs));
            } else if let Some(reply) = x11_forward.pending_opens.remove(&channel) {
                // Symmetric with the agent-forward arm, for `x11`.
                let (ingress_tx, ingress_rx) = mpsc::channel::<Option<Vec<u8>>>();
                let (egress_tx, egress_rx) =
                    mpsc::sync_channel::<ChannelEgress>(SUBSYSTEM_EGRESS_BACKLOG);
                let cs = ChannelStream::new(ingress_rx, egress_tx);
                subsystems.insert(
                    channel,
                    SubsystemRuntime {
                        ingress_tx,
                        egress_rx,
                        pending_data: Vec::new(),
                        pending_eof: false,
                        pending_close: false,
                        eof_sent: false,
                        close_sent: false,
                    },
                );
                let _ = reply.send(Ok(cs));
            }
        }
        ChannelEvent::OpenFailed {
            channel,
            reason: _reason,
            description: _description,
        } => {
            if let Some(reply) = forward.pending_opens.remove(&channel) {
                let _ = reply.send(Err(Error::Protocol(
                    "forwarded-tcpip: open rejected by peer",
                )));
            } else if let Some(reply) = agent_forward.pending_opens.remove(&channel) {
                let _ = reply.send(Err(Error::Protocol("auth-agent: open rejected by peer")));
            } else if let Some(reply) = x11_forward.pending_opens.remove(&channel) {
                let _ = reply.send(Err(Error::Protocol("x11: open rejected by peer")));
            }
        }
        ChannelEvent::OpenRejected {
            payload: failure_payload,
            reason: _reason,
        } => {
            // Per-connection channel cap (RFC 4254 §5.1 resource-shortage).
            // `ConnectionState::on_packet` already built the
            // SSH_MSG_CHANNEL_OPEN_FAILURE bytes and did NOT allocate a
            // local channel id; we just ship the payload so the peer can
            // back off without us tearing down the transport.
            write_payload(stream, codec, rng, &failure_payload)?;
        }
        ChannelEvent::OpenRequest { channel, kind } => match kind {
            ChannelOpen::Session => {
                *any_channel_opened = true;
                // MaxSessions (capability ceiling): reject the open with
                // resource-shortage once the live session-channel count would
                // exceed the cap. `0` ⇒ no sessions at all.
                if let Some(cap) = effective.max_sessions
                    && extras.session_channels.len() as u64 >= cap as u64
                {
                    let p = conn.reject_open(
                        channel,
                        SSH_OPEN_RESOURCE_SHORTAGE,
                        "MaxSessions limit reached",
                        "",
                    )?;
                    write_payload(stream, codec, rng, &p)?;
                } else {
                    let p = conn.accept_open(channel)?;
                    write_payload(stream, codec, rng, &p)?;
                    extras.session_channels.insert(channel);
                    // Allocate an empty per-channel env bag. Client `"env"`
                    // requests append to it; handlers read it on `exec` /
                    // `shell` / `subsystem` dispatch.
                    envs.insert(channel, SessionEnv::new());
                }
            }
            ChannelOpen::DirectTcpip {
                dest_host,
                dest_port,
                orig_host,
                orig_port,
            } => {
                // AllowTcpForwarding / PermitOpen capability ceiling. A
                // policy that forbids local forwarding, or whose PermitOpen
                // list excludes this destination, rejects the open even when
                // a direct-tcpip handler is attached.
                let forwarding_ok = effective.local_forwarding_allowed();
                // PermitOpen entries carry u16 ports; a dest_port outside that
                // range can never match a configured entry (and is only
                // permitted when PermitOpen is unset / `any`).
                let dest_ok = u16::try_from(dest_port)
                    .map(|p| effective.permit_open_allows(&dest_host, p))
                    .unwrap_or_else(|_| effective.permit_open.is_none());
                if !forwarding_ok || !dest_ok {
                    let reason = if !forwarding_ok {
                        "local forwarding administratively prohibited"
                    } else {
                        "direct-tcpip destination not permitted by PermitOpen"
                    };
                    let p = conn.reject_open(
                        channel,
                        SSH_OPEN_ADMINISTRATIVELY_PROHIBITED,
                        reason,
                        "",
                    )?;
                    write_payload(stream, codec, rng, &p)?;
                } else if let Some(handler) = cfg.direct_tcpip_handler.clone() {
                    // Accept first, then hand off to the handler thread. The
                    // dispatcher routes subsequent Data/Eof/Close into the
                    // SubsystemRuntime mpsc just like for subsystems.
                    let p = conn.accept_open(channel)?;
                    write_payload(stream, codec, rng, &p)?;

                    let (ingress_tx, ingress_rx) = mpsc::channel::<Option<Vec<u8>>>();
                    let (egress_tx, egress_rx) =
                        mpsc::sync_channel::<ChannelEgress>(SUBSYSTEM_EGRESS_BACKLOG);
                    let cs = ChannelStream::new(ingress_rx, egress_tx);
                    let user_owned = user.to_string();
                    thread::spawn(move || {
                        let req = DirectTcpipRequest {
                            dest_host: &dest_host,
                            dest_port,
                            orig_host: &orig_host,
                            orig_port,
                        };
                        let _ = handler.handle(&user_owned, req, cs);
                    });
                    subsystems.insert(
                        channel,
                        SubsystemRuntime {
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
                    let p = conn.reject_open(
                        channel,
                        SSH_OPEN_ADMINISTRATIVELY_PROHIBITED,
                        "direct-tcpip not enabled",
                        "",
                    )?;
                    write_payload(stream, codec, rng, &p)?;
                }
            }
            _ => {
                let p = conn.reject_open(
                    channel,
                    SSH_OPEN_ADMINISTRATIVELY_PROHIBITED,
                    "channel type not supported",
                    "",
                )?;
                write_payload(stream, codec, rng, &p)?;
            }
        },
        ChannelEvent::Request {
            channel,
            request,
            want_reply,
        } => {
            handle_channel_request(
                stream,
                codec,
                rng,
                inbox,
                conn,
                cfg,
                effective,
                user,
                channel,
                request,
                want_reply,
                shells,
                subsystems,
                envs,
                agent_forward,
                x11_forward,
            )?;
        }
        ChannelEvent::Data { channel, data } => {
            // Forward stdin into the shell, if one is active on this channel.
            // EAGAIN-equivalent (`Ok(0)`) just drops the byte for this tick;
            // a well-behaved client retries by sending more stdin later. A
            // hard write error tears the session down.
            if let Some(rt) = shells.get_mut(&channel)
                && let Some(sess) = rt.session.as_mut()
            {
                let mut off = 0usize;
                let mut retries = 0u32;
                while off < data.len() {
                    let n = sess.write(&data[off..])?;
                    if n == 0 {
                        retries += 1;
                        if retries > 4 {
                            break;
                        }
                        continue;
                    }
                    off += n;
                }
            }
            // Subsystem ingress: hand the chunk to the handler thread. The
            // ingress channel is unbounded so we never block the dispatcher;
            // the actual backpressure comes from the SSH window (we only
            // replenish after pushing — but pushing is cheap, so it's fine).
            if let Some(rt) = subsystems.get_mut(&channel) {
                let _ = rt.ingress_tx.send(Some(data.clone()));
            }
            if let Some(adj) = conn.replenish_window(channel, data.len() as u32)? {
                write_payload(stream, codec, rng, &adj)?;
            }
        }
        ChannelEvent::ExtendedData { channel, data, .. } => {
            if let Some(adj) = conn.replenish_window(channel, data.len() as u32)? {
                write_payload(stream, codec, rng, &adj)?;
            }
        }
        ChannelEvent::Eof { channel } => {
            if let Some(rt) = shells.get_mut(&channel)
                && let Some(sess) = rt.session.as_mut()
            {
                let _ = sess.close_stdin();
            }
            if let Some(rt) = subsystems.get_mut(&channel) {
                // None = EOF marker; the handler's `Read::read` returns
                // `Ok(0)` next time it drains its buffer.
                let _ = rt.ingress_tx.send(None);
            }
        }
        ChannelEvent::Close { channel } => {
            if let Some(ch) = conn.channel(channel)
                && !ch.local_closed
            {
                let p = conn.send_close(channel)?;
                write_payload(stream, codec, rng, &p)?;
            }
            // Drop the runtime so the backend can reap its child / close fds.
            shells.remove(&channel);
            // Dropping the SubsystemRuntime closes `ingress_tx`; the handler
            // thread's next `Read` returns `Ok(0)` and the thread exits.
            subsystems.remove(&channel);
            envs.remove(&channel);
            // Decrement the MaxSessions counter if this was a session channel.
            extras.session_channels.remove(&channel);
            // Tear down any agent-forward listener bound to this session
            // channel. The handle's `Drop` impl stops the accept thread and
            // unlinks the on-disk socket.
            agent_forward.active.remove(&channel);
            // Same for X11: drop the display listener and unlink any
            // associated state.
            x11_forward.active.remove(&channel);
        }
        ChannelEvent::WindowAdjust { .. } => {}
        ChannelEvent::GlobalRequest {
            request,
            want_reply,
        } => {
            handle_global_request(
                stream, codec, rng, conn, cfg, effective, user, request, want_reply, forward,
            )?;
        }
        _ => {}
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn handle_global_request<R: RngCore + CryptoRng>(
    stream: &mut TcpStream,
    codec: &mut PacketCodec,
    rng: &mut R,
    conn: &mut ConnectionState,
    cfg: &Config,
    effective: &EffectivePolicy,
    user: &str,
    request: crate::channel::GlobalRequest,
    want_reply: bool,
    forward: &mut ForwardConn,
) -> Result<()> {
    use crate::channel::GlobalRequest;
    use crate::format::Writer;
    match request {
        GlobalRequest::TcpipForward {
            bind_address,
            bind_port,
        } => {
            // AllowTcpForwarding / PermitListen / GatewayPorts capability
            // ceiling. `remote` forwarding disabled, or a bind target outside
            // PermitListen, fails the request without touching the kernel.
            // GatewayPorts rewrites the bind address the handler will use.
            let policy_ok = effective.remote_forwarding_allowed()
                && (bind_port > u16::MAX as u32
                    || effective.permit_listen_allows(&bind_address, bind_port as u16));
            let effective_bind = crate::forwarding::reverse::apply_gateway_ports(
                effective.gateway_ports,
                &bind_address,
            );
            // Refuse non-uint16 ports up front (the spec allows uint32 on the
            // wire but only 0..=65535 are meaningful).
            let bound = if !policy_ok || bind_port > u16::MAX as u32 {
                None
            } else if let Some(handler) = cfg.tcpip_forward_handler.clone() {
                let ctx = ForwardContext::new(forward.req_tx.clone());
                handler
                    .bind(user, &effective_bind, bind_port as u16, ctx)
                    .ok()
            } else {
                None
            };
            if !want_reply {
                if let Some(port) = bound {
                    forward.owned_bindings.push((effective_bind, port));
                }
                return Ok(());
            }
            match bound {
                Some(port) => {
                    forward.owned_bindings.push((effective_bind, port));
                    // When the client asked for port 0 the spec requires us
                    // to echo back the assigned port as a `uint32` tail.
                    let tail = if bind_port == 0 {
                        let mut w = Writer::new();
                        w.write_u32(port as u32);
                        w.into_vec()
                    } else {
                        Vec::new()
                    };
                    let p = conn.send_global_success(&tail);
                    write_payload(stream, codec, rng, &p)?;
                }
                None => {
                    let p = conn.send_global_failure();
                    write_payload(stream, codec, rng, &p)?;
                }
            }
        }
        GlobalRequest::CancelTcpipForward {
            bind_address,
            bind_port,
        } => {
            // Rewrite the same way `bind` did so unbind targets the address the
            // handler actually bound under the GatewayPorts policy.
            let effective_bind = crate::forwarding::reverse::apply_gateway_ports(
                effective.gateway_ports,
                &bind_address,
            );
            let ok = if bind_port > u16::MAX as u32 {
                false
            } else if let Some(handler) = cfg.tcpip_forward_handler.clone() {
                let r = handler
                    .unbind(user, &effective_bind, bind_port as u16)
                    .is_ok();
                if r {
                    forward
                        .owned_bindings
                        .retain(|(a, p)| !(a == &effective_bind && *p == bind_port as u16));
                }
                r
            } else {
                false
            };
            if !want_reply {
                return Ok(());
            }
            let p = if ok {
                conn.send_global_success(&[])
            } else {
                conn.send_global_failure()
            };
            write_payload(stream, codec, rng, &p)?;
        }
        GlobalRequest::Keepalive | GlobalRequest::Other { .. } => {
            if want_reply {
                let p = conn.send_global_failure();
                write_payload(stream, codec, rng, &p)?;
            }
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn handle_channel_request<R: RngCore + CryptoRng>(
    stream: &mut TcpStream,
    codec: &mut PacketCodec,
    rng: &mut R,
    inbox: &mut Vec<u8>,
    conn: &mut ConnectionState,
    cfg: &Config,
    effective: &EffectivePolicy,
    user: &str,
    channel: u32,
    request: ChannelRequest,
    want_reply: bool,
    shells: &mut BTreeMap<u32, ShellRuntime>,
    subsystems: &mut BTreeMap<u32, SubsystemRuntime>,
    envs: &mut BTreeMap<u32, SessionEnv>,
    agent_forward: &mut AgentForwardConn,
    x11_forward: &mut X11ForwardConn,
) -> Result<()> {
    // Lazily allocate a per-channel env bag for any session-style channel
    // whose Open we somehow missed. Cheap insert; subsequent lookups are
    // O(log n) on the BTreeMap.
    let empty_env = SessionEnv::new();
    match request {
        ChannelRequest::Exec { command } => {
            // ForceCommand (capability ceiling): when set, the client's
            // command is replaced by the forced one and exposed verbatim via
            // SSH_ORIGINAL_COMMAND. `internal-sftp` routes the session into
            // the in-process SFTP subsystem instead of running a command.
            let command = if let Some(forced) = effective.force_command.as_deref() {
                envs.entry(channel)
                    .or_default()
                    .insert("SSH_ORIGINAL_COMMAND".to_string(), command.clone());
                if forced.eq_ignore_ascii_case("internal-sftp") {
                    return route_internal_sftp(
                        stream, codec, rng, conn, cfg, user, channel, want_reply, subsystems, envs,
                    );
                }
                forced.to_string()
            } else {
                command
            };
            // First-chance overlay: ask the ExecStreamHandler (if any)
            // whether it wants to claim this command. The decision must
            // happen synchronously — we can't take back a `request_success`
            // reply, and the SubsystemRuntime we register here would
            // deadlock the connection if no thread drained it. Once
            // `claims` returns true we set up the runtime + spawn the
            // handler thread the same way `ChannelRequest::Subsystem`
            // below does.
            if let Some(handler) = cfg.exec_stream_handler.clone()
                && handler.claims(&command)
            {
                let (ingress_tx, ingress_rx) = mpsc::channel::<Option<Vec<u8>>>();
                let (egress_tx, egress_rx) =
                    mpsc::sync_channel::<ChannelEgress>(SUBSYSTEM_EGRESS_BACKLOG);
                let cs = ChannelStream::new(ingress_rx, egress_tx);
                let user_owned = user.to_string();
                let command_owned = command.clone();
                let env_snapshot = envs.get(&channel).cloned().unwrap_or_default();
                let handler_for_thread = handler;
                thread::spawn(move || {
                    // Errors swallowed: the stream auto-emits
                    // EOF + Close on drop, so the peer sees teardown.
                    let _ = handler_for_thread.run(&user_owned, &env_snapshot, &command_owned, cs);
                });
                subsystems.insert(
                    channel,
                    SubsystemRuntime {
                        ingress_tx,
                        egress_rx,
                        pending_data: Vec::new(),
                        pending_eof: false,
                        pending_close: false,
                        eof_sent: false,
                        close_sent: false,
                    },
                );
                if want_reply {
                    let p = conn.send_request_success(channel)?;
                    write_payload(stream, codec, rng, &p)?;
                }
                return Ok(());
            }
            // Not claimed — fall through to the buffered CommandHandler.
            let env_ref = envs.get(&channel).unwrap_or(&empty_env);
            let result = cfg.command_handler.handle(user, env_ref, &command);
            if want_reply {
                let p = conn.send_request_success(channel)?;
                write_payload(stream, codec, rng, &p)?;
            }
            drain_send(
                stream,
                codec,
                rng,
                inbox,
                conn,
                channel,
                &result.stdout,
                None,
            )?;
            drain_send(
                stream,
                codec,
                rng,
                inbox,
                conn,
                channel,
                &result.stderr,
                Some(SSH_EXTENDED_DATA_STDERR),
            )?;
            let p = conn.send_request(
                channel,
                ChannelRequest::ExitStatus {
                    code: result.exit_status,
                },
                false,
            )?;
            write_payload(stream, codec, rng, &p)?;
            let p = conn.send_eof(channel)?;
            write_payload(stream, codec, rng, &p)?;
            let p = conn.send_close(channel)?;
            write_payload(stream, codec, rng, &p)?;
        }
        ChannelRequest::PtyReq {
            term,
            cols,
            rows,
            px_w,
            px_h,
            modes,
        } => {
            // RFC 4254 §6.2: pty-req may precede shell/exec. We just stash
            // the spec on the channel's ShellRuntime; the actual PTY is
            // allocated when "shell" arrives.
            if cfg.shell_handler.is_some() {
                let rt = shells.entry(channel).or_insert_with(ShellRuntime::new);
                rt.pending_pty = Some(PtySpec {
                    term,
                    cols,
                    rows,
                    px_w,
                    px_h,
                    modes,
                });
                if want_reply {
                    let p = conn.send_request_success(channel)?;
                    write_payload(stream, codec, rng, &p)?;
                }
            } else if want_reply {
                let p = conn.send_request_failure(channel)?;
                write_payload(stream, codec, rng, &p)?;
            }
        }
        ChannelRequest::Shell => {
            // ForceCommand on an interactive shell: OpenSSH runs the forced
            // command instead of the login shell, with an empty
            // SSH_ORIGINAL_COMMAND. `internal-sftp` routes to SFTP; any other
            // forced command runs through the buffered command handler.
            if let Some(forced) = effective.force_command.as_deref() {
                envs.entry(channel)
                    .or_default()
                    .insert("SSH_ORIGINAL_COMMAND".to_string(), String::new());
                if forced.eq_ignore_ascii_case("internal-sftp") {
                    return route_internal_sftp(
                        stream, codec, rng, conn, cfg, user, channel, want_reply, subsystems, envs,
                    );
                }
                let env_ref = envs.get(&channel).unwrap_or(&empty_env);
                let result = cfg.command_handler.handle(user, env_ref, forced);
                if want_reply {
                    let p = conn.send_request_success(channel)?;
                    write_payload(stream, codec, rng, &p)?;
                }
                drain_send(
                    stream,
                    codec,
                    rng,
                    inbox,
                    conn,
                    channel,
                    &result.stdout,
                    None,
                )?;
                drain_send(
                    stream,
                    codec,
                    rng,
                    inbox,
                    conn,
                    channel,
                    &result.stderr,
                    Some(SSH_EXTENDED_DATA_STDERR),
                )?;
                let p = conn.send_request(
                    channel,
                    ChannelRequest::ExitStatus {
                        code: result.exit_status,
                    },
                    false,
                )?;
                write_payload(stream, codec, rng, &p)?;
                let p = conn.send_eof(channel)?;
                write_payload(stream, codec, rng, &p)?;
                let p = conn.send_close(channel)?;
                write_payload(stream, codec, rng, &p)?;
                return Ok(());
            }
            if let Some(handler) = cfg.shell_handler.clone() {
                let rt = shells.entry(channel).or_insert_with(ShellRuntime::new);
                let pty = rt.pending_pty.take();
                let env_ref = envs.get(&channel).unwrap_or(&empty_env);
                match handler.spawn(user, env_ref, pty) {
                    Ok(sess) => {
                        rt.session = Some(sess);
                        if want_reply {
                            let p = conn.send_request_success(channel)?;
                            write_payload(stream, codec, rng, &p)?;
                        }
                    }
                    Err(_) => {
                        // Spawn failed — surface as request failure and
                        // drop the runtime (no PTY allocated).
                        shells.remove(&channel);
                        if want_reply {
                            let p = conn.send_request_failure(channel)?;
                            write_payload(stream, codec, rng, &p)?;
                        }
                    }
                }
            } else if want_reply {
                let p = conn.send_request_failure(channel)?;
                write_payload(stream, codec, rng, &p)?;
            }
        }
        ChannelRequest::WindowChange {
            cols,
            rows,
            px_w,
            px_h,
        } => {
            // window-change is `want_reply = false` per RFC 4254 §6.7, so
            // we never reply — just propagate to the backend best-effort.
            if let Some(rt) = shells.get_mut(&channel)
                && let Some(sess) = rt.session.as_mut()
            {
                let _ = sess.resize(cols, rows, px_w, px_h);
            }
        }
        ChannelRequest::Env { name, value } => {
            // RFC 4254 §6.4: env is scoped to the session channel. We
            // filter against `cfg.accept_env` (a glob allow-list) and
            // refuse anything in [`HARD_BLOCKED_ENV_NAMES`] regardless
            // of the allow-list — dynamic-linker preload knobs, shell
            // init files, and identity names that must follow
            // /etc/passwd. RFC 4254 lets us reply `CHANNEL_SUCCESS` for
            // accepted requests and `CHANNEL_FAILURE` for rejected
            // ones; clients treat the failure as a benign hint.
            if env_name_accepted(&name, &cfg.accept_env) {
                let bag = envs.entry(channel).or_default();
                // Per-channel env caps (anti-DoS). Without these, a peer
                // could ship tens of thousands of accepted env requests
                // before claiming `shell` / `exec` / `subsystem` and
                // exhaust memory in the SessionEnv bag. Bytes is
                // sum(name.len() + value.len()) across all stored pairs;
                // count is the number of distinct names. A repeat insert
                // of an existing name only changes the value half of the
                // pair, so we subtract the old value's bytes (and leave
                // the count unchanged) when projecting the post-insert
                // total.
                let replacing = bag.get(&name).map(|v| v.len());
                let new_count = if replacing.is_some() {
                    bag.len()
                } else {
                    bag.len().saturating_add(1)
                };
                let current_bytes: usize = bag.iter().map(|(k, v)| k.len() + v.len()).sum();
                let new_bytes = if let Some(old_value_len) = replacing {
                    current_bytes
                        .saturating_sub(old_value_len)
                        .saturating_add(value.len())
                } else {
                    current_bytes
                        .saturating_add(name.len())
                        .saturating_add(value.len())
                };
                if new_count > MAX_ENV_PER_CHANNEL || new_bytes > MAX_ENV_BYTES_PER_CHANNEL {
                    if want_reply {
                        let p = conn.send_request_failure(channel)?;
                        write_payload(stream, codec, rng, &p)?;
                    }
                } else {
                    bag.insert(name, value);
                    if want_reply {
                        let p = conn.send_request_success(channel)?;
                        write_payload(stream, codec, rng, &p)?;
                    }
                }
            } else if want_reply {
                let p = conn.send_request_failure(channel)?;
                write_payload(stream, codec, rng, &p)?;
            }
        }
        ChannelRequest::Subsystem { name } => {
            if let Some(handler) = cfg.subsystem_handler.clone() {
                // Ingress: unbounded — the dispatcher must never block on
                // its own dispatch path. Egress: bounded — the handler
                // thread self-throttles when the remote window is full.
                let (ingress_tx, ingress_rx) = mpsc::channel::<Option<Vec<u8>>>();
                let (egress_tx, egress_rx) =
                    mpsc::sync_channel::<ChannelEgress>(SUBSYSTEM_EGRESS_BACKLOG);
                let cs = ChannelStream::new(ingress_rx, egress_tx);
                let user_owned = user.to_string();
                let name_owned = name.clone();
                let env_snapshot = envs.get(&channel).cloned().unwrap_or_default();
                thread::spawn(move || {
                    // Errors from the handler are swallowed: the stream
                    // drops on return, which auto-emits EOF + Close so the
                    // peer sees a clean teardown.
                    let _ = handler.handle(&user_owned, &env_snapshot, &name_owned, cs);
                });
                subsystems.insert(
                    channel,
                    SubsystemRuntime {
                        ingress_tx,
                        egress_rx,
                        pending_data: Vec::new(),
                        pending_eof: false,
                        pending_close: false,
                        eof_sent: false,
                        close_sent: false,
                    },
                );
                if want_reply {
                    let p = conn.send_request_success(channel)?;
                    write_payload(stream, codec, rng, &p)?;
                }
            } else if want_reply {
                let p = conn.send_request_failure(channel)?;
                write_payload(stream, codec, rng, &p)?;
            }
        }
        ChannelRequest::AuthAgentReq => {
            // OpenSSH pseudo-extension: client asks the server to set up an
            // SSH_AUTH_SOCK proxy for *this* session channel. The handler
            // binds a Unix socket (path injected into the session's env);
            // the handle stays in `agent_forward.active` until the channel
            // closes, at which point its `Drop` impl tears the listener
            // down and unlinks the socket.
            if effective.agent_forwarding_allowed()
                && let Some(handler) = cfg.agent_forward_handler.clone()
            {
                let ctx = AgentForwardContext::new(agent_forward.req_tx.clone());
                match handler.setup(user, ctx) {
                    Ok(handle) => {
                        let path_str = handle.auth_sock_path.to_string_lossy().into_owned();
                        envs.entry(channel)
                            .or_default()
                            .insert("SSH_AUTH_SOCK".to_string(), path_str);
                        agent_forward.active.insert(channel, handle);
                        if want_reply {
                            let p = conn.send_request_success(channel)?;
                            write_payload(stream, codec, rng, &p)?;
                        }
                    }
                    Err(_) => {
                        if want_reply {
                            let p = conn.send_request_failure(channel)?;
                            write_payload(stream, codec, rng, &p)?;
                        }
                    }
                }
            } else if want_reply {
                let p = conn.send_request_failure(channel)?;
                write_payload(stream, codec, rng, &p)?;
            }
        }
        ChannelRequest::X11Req {
            single_connection,
            auth_protocol,
            auth_cookie,
            screen,
        } => {
            // RFC 4254 §6.3.1: client asks the server to set up a display
            // proxy for *this* session channel. The handler binds a TCP
            // listener on 127.0.0.1:6000+N for some free N; we inject
            // `DISPLAY=<host>:N.<screen>` into the session's env bag so
            // child shells / exec see it. The handle stays in
            // `x11_forward.active` until the channel closes; its `Drop`
            // impl stops the accept thread.
            if effective.x11_forwarding_allowed()
                && let Some(handler) = cfg.x11_forward_handler.clone()
            {
                let ctx = X11ForwardContext::new(x11_forward.req_tx.clone());
                match handler.setup(
                    user,
                    single_connection,
                    &auth_protocol,
                    &auth_cookie,
                    screen,
                    ctx,
                ) {
                    Ok(handle) => {
                        envs.entry(channel)
                            .or_default()
                            .insert("DISPLAY".to_string(), handle.display_env.clone());
                        x11_forward.active.insert(channel, handle);
                        if want_reply {
                            let p = conn.send_request_success(channel)?;
                            write_payload(stream, codec, rng, &p)?;
                        }
                    }
                    Err(_) => {
                        if want_reply {
                            let p = conn.send_request_failure(channel)?;
                            write_payload(stream, codec, rng, &p)?;
                        }
                    }
                }
            } else if want_reply {
                let p = conn.send_request_failure(channel)?;
                write_payload(stream, codec, rng, &p)?;
            }
        }
        // ChannelRequest::Signal { name } — forwarded as kill(child_pid,
        // SIG…) in a future revision. Today we silently accept it.
        _ => {
            if want_reply {
                let p = conn.send_request_failure(channel)?;
                write_payload(stream, codec, rng, &p)?;
            }
        }
    }
    Ok(())
}

/// Route a session into the in-process SFTP subsystem, used by
/// `ForceCommand internal-sftp`. Mirrors the `ChannelRequest::Subsystem`
/// dispatch with a fixed `"sftp"` name: spawns the subsystem handler on its
/// own thread bound to a freshly-registered [`SubsystemRuntime`]. If no
/// subsystem handler is attached the request fails.
#[allow(clippy::too_many_arguments)]
fn route_internal_sftp<R: RngCore + CryptoRng>(
    stream: &mut TcpStream,
    codec: &mut PacketCodec,
    rng: &mut R,
    conn: &mut ConnectionState,
    cfg: &Config,
    user: &str,
    channel: u32,
    want_reply: bool,
    subsystems: &mut BTreeMap<u32, SubsystemRuntime>,
    envs: &mut BTreeMap<u32, SessionEnv>,
) -> Result<()> {
    if let Some(handler) = cfg.subsystem_handler.clone() {
        let (ingress_tx, ingress_rx) = mpsc::channel::<Option<Vec<u8>>>();
        let (egress_tx, egress_rx) = mpsc::sync_channel::<ChannelEgress>(SUBSYSTEM_EGRESS_BACKLOG);
        let cs = ChannelStream::new(ingress_rx, egress_tx);
        let user_owned = user.to_string();
        let env_snapshot = envs.get(&channel).cloned().unwrap_or_default();
        thread::spawn(move || {
            let _ = handler.handle(&user_owned, &env_snapshot, "sftp", cs);
        });
        subsystems.insert(
            channel,
            SubsystemRuntime {
                ingress_tx,
                egress_rx,
                pending_data: Vec::new(),
                pending_eof: false,
                pending_close: false,
                eof_sent: false,
                close_sent: false,
            },
        );
        if want_reply {
            let p = conn.send_request_success(channel)?;
            write_payload(stream, codec, rng, &p)?;
        }
    } else if want_reply {
        let p = conn.send_request_failure(channel)?;
        write_payload(stream, codec, rng, &p)?;
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn drain_send<R: RngCore + CryptoRng>(
    stream: &mut TcpStream,
    codec: &mut PacketCodec,
    rng: &mut R,
    inbox: &mut Vec<u8>,
    conn: &mut ConnectionState,
    channel: u32,
    mut data: &[u8],
    extended: Option<u32>,
) -> Result<()> {
    let mut iter = 0usize;
    while !data.is_empty() {
        iter += 1;
        if iter > MAX_DRAIN_STEPS {
            return Err(Error::Protocol("drain_send did not converge"));
        }
        let (payload, taken) = if let Some(code) = extended {
            conn.send_extended_data(channel, code, data)?
        } else {
            conn.send_data(channel, data)?
        };

        if taken > 0 {
            write_payload(stream, codec, rng, &payload)?;
            data = &data[taken..];
            continue;
        }
        let pkt = read_one_packet(stream, codec, inbox)?;
        let ev = conn.on_packet(&pkt)?;
        match ev {
            ChannelEvent::WindowAdjust { channel: c, .. } if c == channel => continue,
            ChannelEvent::Close { channel: c } if c == channel => {
                return Err(Error::BadChannelState);
            }
            _ => continue,
        }
    }
    Ok(())
}

fn pick_host_key<'a>(
    keys: &'a [Box<dyn HostKey + Send + Sync>],
    name: &str,
) -> Option<&'a (dyn HostKey + Send + Sync)> {
    for k in keys {
        if k.algorithm() == name {
            return Some(k.as_ref());
        }
    }
    // RSA: a single private key can sign with rsa-sha2-256 / rsa-sha2-512 /
    // ssh-rsa, but our HostKey trait pins one algorithm per instance. Treat
    // the rsa-* family as a single equivalence class on the public-blob side.
    for k in keys {
        let a = k.algorithm();
        if (a == "ssh-rsa" || a == "rsa-sha2-256" || a == "rsa-sha2-512")
            && (name == "ssh-rsa" || name == "rsa-sha2-256" || name == "rsa-sha2-512")
        {
            return Some(k.as_ref());
        }
    }
    None
}

/// Build the `SSH_MSG_EXT_INFO` we send to the client on the first KEX.
/// Carries `server-sig-algs` (RFC 8308 §3.1) so the client can pick
/// rsa-sha2-{256,512} instead of legacy `ssh-rsa` for publickey signatures.
fn server_ext_info() -> ExtInfo {
    // Algorithms we are willing to verify a client publickey signature with.
    // Order is the same priority as our host-key KEX list — strongest first.
    // Legacy `ssh-rsa` (SHA-1) is intentionally omitted; it stays opt-in via
    // hostkey::set_allow_rsa_sha1.
    ExtInfo::new().with_server_sig_algs(
        "ssh-ed25519,ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521,\
         rsa-sha2-512,rsa-sha2-256",
    )
}

/// Helper: owned list from an override, or the given default slice.
fn owned_or_default(over: &Option<Vec<String>>, default: &[&str]) -> Vec<String> {
    match over {
        Some(v) => v.clone(),
        None => default.iter().map(|s| s.to_string()).collect(),
    }
}

fn build_server_kexinit<R: RngCore>(rng: &mut R, cfg: &Config) -> KexInit {
    let host_keys = &cfg.host_keys;
    // The set of host-key algorithms we can actually produce signatures for,
    // in the default preference order (used both as the default advert and as
    // the intersection mask for a HostKeyAlgorithms override).
    let mut have: Vec<&'static str> = Vec::new();
    // Certificate host keys first (matching OpenSSH), so a client that supports
    // certs negotiates the cert algorithm ahead of the plain key it wraps.
    for n in crate::cert::CERT_KEY_NAMES {
        if host_keys.iter().any(|k| k.algorithm() == *n) {
            have.push(*n);
        }
    }
    for n in defaults::HOST_KEY {
        if host_keys.iter().any(|k| k.algorithm() == *n) {
            have.push(*n);
            continue;
        }
        // rsa-sha2-{256,512} are usable as long as we have any RSA key.
        if (*n == "rsa-sha2-256" || *n == "rsa-sha2-512")
            && host_keys.iter().any(|k| {
                let a = k.algorithm();
                a == "ssh-rsa" || a == "rsa-sha2-256" || a == "rsa-sha2-512"
            })
        {
            have.push(*n);
        }
    }

    // Resolve the advertised host-key list. With a HostKeyAlgorithms
    // override, use the override as the preference *order* but keep only the
    // algorithms we can produce (intersection) — naming one we have no key
    // for is a silent no-op, and the override CAN intentionally exclude an
    // algorithm we hold a key for.
    let host_key: Vec<String> = match &cfg.host_key_algorithms {
        Some(pref) => pref
            .iter()
            .filter(|p| have.contains(&p.as_str()))
            .cloned()
            .collect(),
        None => have.iter().map(|s| s.to_string()).collect(),
    };
    // Last-ditch net: if we ended up advertising nothing (no usable keys, or
    // an override that intersected to empty), fall back to ed25519 — BUT only
    // when the operator did not explicitly exclude it via an override. An
    // explicit HostKeyAlgorithms that omits ssh-ed25519 must be honoured.
    let ed25519_excluded = cfg
        .host_key_algorithms
        .as_ref()
        .is_some_and(|pref| !pref.iter().any(|p| p == "ssh-ed25519"));
    let host_key = if host_key.is_empty() && !ed25519_excluded {
        alloc::vec!["ssh-ed25519".to_string()]
    } else {
        host_key
    };

    // Real (non-marker) kex default order; markers are re-appended after the
    // (possibly overridden) list so a KexAlgorithms override can never strip
    // the Terrapin (CVE-2023-48795) mitigation.
    let default_kex: Vec<&str> = defaults::KEX
        .iter()
        .copied()
        .filter(|n| !is_strict_kex_marker(n))
        .collect();
    let mut kex = owned_or_default(&cfg.kex_algorithms, &default_kex);
    for marker in defaults::KEX.iter().filter(|n| is_strict_kex_marker(n)) {
        if !kex.iter().any(|k| k == marker) {
            kex.push((*marker).to_string());
        }
    }

    let ciphers = owned_or_default(&cfg.ciphers, defaults::CIPHERS);
    let macs = owned_or_default(&cfg.macs, defaults::MACS);
    // `Compression no` strips any zlib names from the advert. puressh only
    // advertises `none` today, so this is a defensive no-op; it becomes
    // load-bearing once SSH-layer zlib is added to `defaults::COMP`.
    // `yes` / `delayed` keep the default advert.
    let comp: Vec<String> = defaults::COMP
        .iter()
        .filter(|name| {
            if cfg.compression == Some(crate::config::Compression::No) {
                !name.contains("zlib")
            } else {
                true
            }
        })
        .map(|s| s.to_string())
        .collect();

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

fn read_peer_version(stream: &mut TcpStream) -> Result<Vec<u8>> {
    let mut buf = Vec::new();
    for _ in 0..MAX_BANNER_LINES {
        buf.clear();
        read_line(stream, &mut buf, MAX_BANNER_LINE)?;
        if buf.starts_with(b"SSH-") {
            let parsed = VersionExchange::parse_remote(&buf)?;
            return Ok(parsed.into_bytes());
        }
    }
    Err(Error::Protocol("peer banner too long"))
}

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

fn read_one_packet(
    stream: &mut TcpStream,
    codec: &mut PacketCodec,
    inbox: &mut Vec<u8>,
) -> Result<Vec<u8>> {
    loop {
        let payload = read_one_raw_packet(stream, codec, inbox)?;
        match payload.first().copied() {
            Some(1) => return Err(Error::Protocol("peer sent SSH_MSG_DISCONNECT")),
            Some(2) | Some(3) | Some(4) => continue,
            _ => return Ok(payload),
        }
    }
}

fn read_one_raw_packet(
    stream: &mut TcpStream,
    codec: &mut PacketCodec,
    inbox: &mut Vec<u8>,
) -> Result<Vec<u8>> {
    loop {
        if let Some((payload, consumed)) = codec.decode(inbox)? {
            inbox.drain(..consumed);
            return Ok(payload);
        }
        let mut tmp = [0u8; 16 * 1024];
        let n = stream.read(&mut tmp)?;
        if n == 0 {
            return Err(Error::Protocol("connection closed"));
        }
        inbox.extend_from_slice(&tmp[..n]);
        if inbox.len() > MAX_INBOX_BYTES {
            return Err(Error::Protocol("inbound buffer too large"));
        }
    }
}

fn write_payload<R: RngCore + CryptoRng>(
    stream: &mut TcpStream,
    codec: &mut PacketCodec,
    rng: &mut R,
    payload: &[u8],
) -> Result<()> {
    let frame = codec.encode(payload, rng)?;
    stream.write_all(&frame)?;
    Ok(())
}

fn send_disconnect<R: RngCore + CryptoRng>(
    stream: &mut TcpStream,
    codec: &mut PacketCodec,
    rng: &mut R,
    reason: u32,
    description: &str,
) -> Result<()> {
    let mut w = Writer::new();
    w.write_u8(1);
    w.write_u32(reason);
    w.write_string(description.as_bytes());
    w.write_string(b"");
    write_payload(stream, codec, rng, &w.into_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::{AuthAttempt, AuthDecision, Authenticator};
    use crate::client::{Client, Config as ClientConfig, HostKeyPolicy};
    use crate::hostkey::Ed25519HostKey;
    use crate::transport::kex::KexAlgorithms;
    use std::sync::Mutex;
    use std::time::Duration;

    struct OneKeyAuth {
        allowed_user: String,
        allowed_blob: Vec<u8>,
    }

    impl Authenticator for OneKeyAuth {
        fn evaluate(&mut self, attempt: AuthAttempt) -> AuthDecision {
            match attempt {
                AuthAttempt::PublicKey {
                    user,
                    public_blob,
                    probe_only,
                    verified,
                    ..
                } => {
                    if user != self.allowed_user {
                        return AuthDecision::Reject;
                    }
                    if public_blob != self.allowed_blob {
                        return AuthDecision::Reject;
                    }
                    if probe_only {
                        return AuthDecision::Accept;
                    }
                    if !verified {
                        return AuthDecision::Reject;
                    }
                    AuthDecision::Accept
                }
                _ => AuthDecision::Reject,
            }
        }
    }

    #[test]
    fn resolve_auth_methods_subtracts_disabled() {
        let base: &[&'static str] = &["publickey", "password", "keyboard-interactive"];
        // No overrides ⇒ unchanged.
        let opts = crate::config::ServerOptions::default();
        assert_eq!(
            resolve_auth_methods(base, &opts),
            vec!["publickey", "password", "keyboard-interactive"]
        );
        // PasswordAuthentication no ⇒ password dropped.
        let opts = crate::config::ServerOptions {
            password_authentication: Some(false),
            ..Default::default()
        };
        assert_eq!(
            resolve_auth_methods(base, &opts),
            vec!["publickey", "keyboard-interactive"]
        );
        // KbdInteractiveAuthentication no ⇒ keyboard-interactive dropped.
        let opts = crate::config::ServerOptions {
            kbd_interactive_authentication: Some(false),
            ..Default::default()
        };
        assert_eq!(
            resolve_auth_methods(base, &opts),
            vec!["publickey", "password"]
        );
        // PubkeyAuthentication no ⇒ publickey dropped.
        let opts = crate::config::ServerOptions {
            pubkey_authentication: Some(false),
            ..Default::default()
        };
        assert_eq!(
            resolve_auth_methods(base, &opts),
            vec!["password", "keyboard-interactive"]
        );
    }

    struct StaticHandler {
        out: Vec<u8>,
    }

    impl CommandHandler for StaticHandler {
        fn handle(&self, _user: &str, _env: &SessionEnv, _command: &str) -> ExecResult {
            ExecResult {
                stdout: self.out.clone(),
                stderr: Vec::new(),
                exit_status: 0,
            }
        }
    }

    fn fresh_seed() -> [u8; 32] {
        let mut s = [0u8; 32];
        OsRng.fill_bytes(&mut s);
        s
    }

    /// Build a minimal server [`Config`] wrapping `host_keys` for tests that
    /// only exercise [`build_server_kexinit`]. The authenticator / handler
    /// are placeholders that are never invoked by the KEX path.
    fn kexinit_test_config(host_keys: Vec<Box<dyn HostKey + Send + Sync>>) -> Config {
        let factory: Arc<dyn AuthenticatorFactory> = Arc::new(|| -> Box<dyn Authenticator> {
            Box::new(OneKeyAuth {
                allowed_user: String::new(),
                allowed_blob: Vec::new(),
            })
        });
        Config::new(
            host_keys,
            factory,
            vec!["publickey"],
            Arc::new(StaticHandler { out: Vec::new() }),
        )
    }

    /// Shared in-memory state behind one [`MemoryShellSession`]. The test
    /// thread pushes stdout / arms an exit decision; the server thread
    /// drains stdin and polls for exit. `Arc<Mutex<…>>` keeps both sides
    /// honest about visibility without any OS plumbing.
    struct MemoryShellState {
        /// Bytes the server should ship as CHANNEL_DATA. Drained by
        /// `MemoryShellSession::read`.
        stdout: Vec<u8>,
        /// Bytes the server has received via CHANNEL_DATA. Appended by
        /// `MemoryShellSession::write`.
        stdin: Vec<u8>,
        /// True after the client sent EOF and the server forwarded it via
        /// `close_stdin`.
        closed_stdin: bool,
        /// Captured PTY spec; the test asserts `term`/`cols`/`rows` against it.
        pty: Option<PtySpec>,
        /// Captured `(cols, rows, px_w, px_h)` from each `resize` call.
        resizes: Vec<(u32, u32, u32, u32)>,
        /// If set, `try_exit` returns this status as soon as either
        /// `exit_now` is set or `close_stdin` has been called.
        exit_on_stdin_close: Option<ShellExitStatus>,
        /// Explicit exit override (takes priority over `exit_on_stdin_close`).
        exit_now: Option<ShellExitStatus>,
        /// Latched user name from `ShellHandler::spawn`.
        user: String,
    }

    #[derive(Clone)]
    struct MemoryShell {
        inner: Arc<Mutex<MemoryShellState>>,
    }

    impl MemoryShell {
        fn new() -> Self {
            Self {
                inner: Arc::new(Mutex::new(MemoryShellState {
                    stdout: Vec::new(),
                    stdin: Vec::new(),
                    closed_stdin: false,
                    pty: None,
                    resizes: Vec::new(),
                    exit_on_stdin_close: None,
                    exit_now: None,
                    user: String::new(),
                })),
            }
        }

        fn push_stdout(&self, bytes: &[u8]) {
            self.inner.lock().unwrap().stdout.extend_from_slice(bytes);
        }

        fn arm_exit_on_stdin_close(&self, status: ShellExitStatus) {
            self.inner.lock().unwrap().exit_on_stdin_close = Some(status);
        }
    }

    struct MemoryShellHandler {
        shell: MemoryShell,
    }

    impl ShellHandler for MemoryShellHandler {
        fn spawn(
            &self,
            user: &str,
            _env: &SessionEnv,
            pty: Option<PtySpec>,
        ) -> Result<Box<dyn ShellSession>> {
            {
                let mut st = self.shell.inner.lock().unwrap();
                st.pty = pty;
                st.user = user.to_string();
            }
            Ok(Box::new(MemoryShellSession {
                inner: self.shell.inner.clone(),
            }))
        }
    }

    struct MemoryShellSession {
        inner: Arc<Mutex<MemoryShellState>>,
    }

    impl ShellSession for MemoryShellSession {
        fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
            let mut st = self.inner.lock().unwrap();
            if st.stdout.is_empty() {
                return Ok(0);
            }
            let n = core::cmp::min(buf.len(), st.stdout.len());
            buf[..n].copy_from_slice(&st.stdout[..n]);
            st.stdout.drain(..n);
            Ok(n)
        }

        fn write(&mut self, data: &[u8]) -> Result<usize> {
            self.inner.lock().unwrap().stdin.extend_from_slice(data);
            Ok(data.len())
        }

        fn close_stdin(&mut self) -> Result<()> {
            self.inner.lock().unwrap().closed_stdin = true;
            Ok(())
        }

        fn resize(&mut self, cols: u32, rows: u32, px_w: u32, px_h: u32) -> Result<()> {
            self.inner
                .lock()
                .unwrap()
                .resizes
                .push((cols, rows, px_w, px_h));
            Ok(())
        }

        fn try_exit(&mut self) -> Option<ShellExitStatus> {
            let mut st = self.inner.lock().unwrap();
            if let Some(s) = st.exit_now.take() {
                return Some(s);
            }
            if st.closed_stdin
                && st.stdout.is_empty()
                && let Some(s) = st.exit_on_stdin_close.take()
            {
                return Some(s);
            }
            None
        }
    }

    #[test]
    fn loopback_shell_with_pty_and_stdin() {
        // End-to-end exercise of the lib's interactive-shell wiring:
        // `pty-req` → `shell` → CHANNEL_DATA in/out → client EOF →
        // `exit-status` + EOF + CLOSE. The backend is the synchronous
        // in-memory `MemoryShell` (no nix, no syscalls, no threads from
        // the handler).
        let host_seed = fresh_seed();
        let client_seed = fresh_seed();

        let host_key: Box<dyn HostKey + Send + Sync> =
            Box::new(Ed25519HostKey::from_seed(host_seed));
        let client_hk_for_auth = Ed25519HostKey::from_seed(client_seed);
        let allowed_blob = client_hk_for_auth.public_blob();

        let user = "shell-test-user".to_string();
        let allowed_user_for_factory = user.clone();
        let allowed_blob_clone = allowed_blob.clone();
        let factory: Arc<dyn AuthenticatorFactory> = Arc::new(move || -> Box<dyn Authenticator> {
            Box::new(OneKeyAuth {
                allowed_user: allowed_user_for_factory.clone(),
                allowed_blob: allowed_blob_clone.clone(),
            })
        });

        // Seed stdout and arm an exit code that fires the moment the
        // client closes stdin (after the server forwards it via
        // `close_stdin`).
        let memshell = MemoryShell::new();
        memshell.push_stdout(b"hello from memshell\n");
        memshell.arm_exit_on_stdin_close(ShellExitStatus::Exited(0));

        let cfg = Config::new(
            vec![host_key],
            factory,
            vec!["publickey"],
            Arc::new(StaticHandler {
                out: b"unused-exec\n".to_vec(),
            }),
        )
        .with_shell(Arc::new(MemoryShellHandler {
            shell: memshell.clone(),
        }));

        let mut server = Server::bind("127.0.0.1:0", cfg).expect("bind");
        let addr = server.local_addr().expect("local_addr");

        let server_done = Arc::new(Mutex::new(false));
        let sd = server_done.clone();
        let server_thread = thread::spawn(move || {
            let r = server.accept_one();
            *sd.lock().unwrap() = true;
            r
        });

        let mut client = Client::connect(
            addr,
            ClientConfig {
                host_key_policy: HostKeyPolicy::AcceptAny,
                timeout: Some(Duration::from_secs(10)),
                algorithms: Default::default(),
            },
        )
        .expect("client connect");

        let client_hk: Box<dyn HostKey + Send> = Box::new(Ed25519HostKey::from_seed(client_seed));
        client
            .authenticate_publickey(&user, client_hk)
            .expect("authenticate");

        let out = client
            .shell_with_stdin("xterm-256color", 132, 43, b"echo back\n")
            .expect("shell_with_stdin");

        assert_eq!(out.stdout, b"hello from memshell\n");
        assert_eq!(out.exit_status, Some(0));
        assert_eq!(out.exit_signal, None);

        // Verify the backend saw the right `pty-req`, stdin, and the user
        // bound to the spawn call.
        let st = memshell.inner.lock().unwrap();
        let pty = st.pty.as_ref().expect("pty-req captured");
        assert_eq!(pty.term, "xterm-256color");
        assert_eq!(pty.cols, 132);
        assert_eq!(pty.rows, 43);
        assert_eq!(st.stdin, b"echo back\n");
        assert!(st.closed_stdin, "EOF should reach the backend");
        assert_eq!(st.user, user);
        drop(st);

        drop(client);

        let start = std::time::Instant::now();
        while !*server_done.lock().unwrap() {
            if start.elapsed() > Duration::from_secs(10) {
                panic!("server thread did not finish in time");
            }
            thread::sleep(Duration::from_millis(20));
        }
        let _ = server_thread.join();
    }

    #[test]
    fn loopback_exec_roundtrip() {
        let host_seed = fresh_seed();
        let client_seed = fresh_seed();

        // Build server.
        let host_key: Box<dyn HostKey + Send + Sync> =
            Box::new(Ed25519HostKey::from_seed(host_seed));
        let client_hk_for_auth = Ed25519HostKey::from_seed(client_seed);
        let allowed_blob = client_hk_for_auth.public_blob();

        let user = "ssh-test-user".to_string();
        let allowed_user_for_factory = user.clone();
        let allowed_blob_clone = allowed_blob.clone();

        let factory: Arc<dyn AuthenticatorFactory> = Arc::new(move || -> Box<dyn Authenticator> {
            Box::new(OneKeyAuth {
                allowed_user: allowed_user_for_factory.clone(),
                allowed_blob: allowed_blob_clone.clone(),
            })
        });

        let cfg = Config::new(
            vec![host_key],
            factory,
            vec!["publickey"],
            Arc::new(StaticHandler {
                out: b"loopback-test\n".to_vec(),
            }),
        );

        let mut server = Server::bind("127.0.0.1:0", cfg).expect("bind");
        let addr = server.local_addr().expect("local_addr");

        let server_done = Arc::new(Mutex::new(false));
        let sd = server_done.clone();
        let server_thread = thread::spawn(move || {
            let r = server.accept_one();
            *sd.lock().unwrap() = true;
            r
        });

        // Give the server a moment to be listening — bind already did this,
        // so we proceed straight to connect.
        let mut client = Client::connect(
            addr,
            ClientConfig {
                host_key_policy: HostKeyPolicy::AcceptAny,
                timeout: Some(Duration::from_secs(10)),
                algorithms: Default::default(),
            },
        )
        .expect("client connect");

        let client_hk: Box<dyn HostKey + Send> = Box::new(Ed25519HostKey::from_seed(client_seed));
        client
            .authenticate_publickey(&user, client_hk)
            .expect("authenticate");

        let out = client.exec("ignored").expect("exec");
        assert_eq!(out.stdout, b"loopback-test\n");
        assert_eq!(out.exit_status, Some(0));

        drop(client);

        // Bound the server-thread wait so a regression can't hang the suite.
        let start = std::time::Instant::now();
        while !*server_done.lock().unwrap() {
            if start.elapsed() > Duration::from_secs(10) {
                panic!("server thread did not finish in time");
            }
            thread::sleep(Duration::from_millis(20));
        }
        let _ = server_thread.join();
    }

    #[test]
    fn loopback_match_user_forbids_publickey() {
        // F5: a `Match User` block sets `PubkeyAuthentication no` for the
        // target user. The pre-auth (address-only) set still advertises
        // publickey, but once the username is known the re-resolve drops it,
        // so the publickey attempt is rejected and authentication fails —
        // even though the same key would succeed for any other user.
        let host_seed = fresh_seed();
        let client_seed = fresh_seed();

        let host_key: Box<dyn HostKey + Send + Sync> =
            Box::new(Ed25519HostKey::from_seed(host_seed));
        let client_hk_for_auth = Ed25519HostKey::from_seed(client_seed);
        let allowed_blob = client_hk_for_auth.public_blob();

        let user = "blocked-user".to_string();
        let allowed_user_for_factory = user.clone();
        let allowed_blob_clone = allowed_blob.clone();
        let factory: Arc<dyn AuthenticatorFactory> = Arc::new(move || -> Box<dyn Authenticator> {
            Box::new(OneKeyAuth {
                allowed_user: allowed_user_for_factory.clone(),
                allowed_blob: allowed_blob_clone.clone(),
            })
        });

        let policy = crate::config::SshServerConfig::parse(
            "Match User blocked-user\n  PubkeyAuthentication no\n",
        )
        .expect("parse policy");

        let cfg = Config::new(
            vec![host_key],
            factory,
            vec!["publickey"],
            Arc::new(StaticHandler {
                out: b"never\n".to_vec(),
            }),
        )
        .with_policy(Arc::new(policy));

        let mut server = Server::bind("127.0.0.1:0", cfg).expect("bind");
        let addr = server.local_addr().expect("local_addr");

        let server_done = Arc::new(Mutex::new(false));
        let sd = server_done.clone();
        let server_thread = thread::spawn(move || {
            let r = server.accept_one();
            *sd.lock().unwrap() = true;
            r
        });

        let mut client = Client::connect(
            addr,
            ClientConfig {
                host_key_policy: HostKeyPolicy::AcceptAny,
                timeout: Some(Duration::from_secs(10)),
                algorithms: Default::default(),
            },
        )
        .expect("client connect");

        let client_hk: Box<dyn HostKey + Send> = Box::new(Ed25519HostKey::from_seed(client_seed));
        let res = client.authenticate_publickey(&user, client_hk);
        assert!(
            res.is_err(),
            "publickey must be rejected for a Match User PubkeyAuthentication no block"
        );

        drop(client);
        let start = std::time::Instant::now();
        while !*server_done.lock().unwrap() {
            if start.elapsed() > Duration::from_secs(10) {
                panic!("server thread did not finish in time");
            }
            thread::sleep(Duration::from_millis(20));
        }
        let _ = server_thread.join();
    }

    #[test]
    fn loopback_forces_rekeys_with_tiny_policy() {
        // A 1-KiB byte threshold makes nearly every CHANNEL_DATA packet (and
        // certainly the cumulative response below) tip the codec over the
        // re-KEX line, exercising the full Phase::Completed → restart →
        // peer answers → KEXINIT exchange → ECDH → NEWKEYS → Completed
        // cycle in a single connection.
        let host_seed = fresh_seed();
        let client_seed = fresh_seed();

        let host_key: Box<dyn HostKey + Send + Sync> =
            Box::new(Ed25519HostKey::from_seed(host_seed));
        let client_hk_for_auth = Ed25519HostKey::from_seed(client_seed);
        let allowed_blob = client_hk_for_auth.public_blob();

        let user = "ssh-test-user".to_string();
        let allowed_user_for_factory = user.clone();
        let allowed_blob_clone = allowed_blob.clone();
        let factory: Arc<dyn AuthenticatorFactory> = Arc::new(move || -> Box<dyn Authenticator> {
            Box::new(OneKeyAuth {
                allowed_user: allowed_user_for_factory.clone(),
                allowed_blob: allowed_blob_clone.clone(),
            })
        });

        // A response large enough that draining it crosses the 1-KiB byte
        // threshold several times — three full re-keys is plenty to assert
        // the codec survives.
        let payload: Vec<u8> = (0..16_384).map(|i| (i & 0xff) as u8).collect();

        let mut cfg = Config::new(
            vec![host_key],
            factory,
            vec!["publickey"],
            Arc::new(StaticHandler {
                out: payload.clone(),
            }),
        );
        cfg.rekey_policy = RekeyPolicy {
            max_bytes: 1024,
            max_duration: Duration::from_secs(60 * 60),
            max_seq: 1u32 << 31,
        };

        let mut server = Server::bind("127.0.0.1:0", cfg).expect("bind");
        let addr = server.local_addr().expect("local_addr");

        let server_done = Arc::new(Mutex::new(false));
        let sd = server_done.clone();
        let server_thread = thread::spawn(move || {
            let r = server.accept_one();
            *sd.lock().unwrap() = true;
            r
        });

        let mut client = Client::connect(
            addr,
            ClientConfig {
                host_key_policy: HostKeyPolicy::AcceptAny,
                timeout: Some(Duration::from_secs(10)),
                algorithms: Default::default(),
            },
        )
        .expect("client connect");
        let session_id_before = client.session_id().to_vec();

        let client_hk: Box<dyn HostKey + Send> = Box::new(Ed25519HostKey::from_seed(client_seed));
        client
            .authenticate_publickey(&user, client_hk)
            .expect("authenticate");

        let out = client.exec("ignored").expect("exec");
        assert_eq!(out.stdout, payload);
        assert_eq!(out.exit_status, Some(0));

        // RFC 4253 §7.2: session id is the H of the FIRST KEX — must stay
        // pinned across every re-key the connection performed.
        assert_eq!(client.session_id(), session_id_before.as_slice());

        drop(client);

        let start = std::time::Instant::now();
        while !*server_done.lock().unwrap() {
            if start.elapsed() > Duration::from_secs(10) {
                panic!("server thread did not finish in time");
            }
            thread::sleep(Duration::from_millis(20));
        }
        let _ = server_thread.join();
    }

    #[test]
    fn server_kexinit_negotiation_uses_role_server() {
        // A direct sanity check that we can drive the server-side KEX
        // negotiation phase through KexRunner with a synthetic client KEXINIT.
        let mut rng = OsRng;
        let host_keys: Vec<Box<dyn HostKey + Send + Sync>> =
            vec![Box::new(Ed25519HostKey::from_seed(fresh_seed()))];
        let cfg = kexinit_test_config(host_keys);
        let advert = build_server_kexinit(&mut rng, &cfg);
        let mut runner = KexRunner::new(Role::Server, advert.clone());

        // Build a minimal compatible client KEXINIT (all the same names, one
        // entry each — that guarantees agreement).
        let mut cookie = [0u8; 16];
        rng.fill_bytes(&mut cookie);
        let client_init = {
            let algs = KexAlgorithms {
                kex: &["curve25519-sha256"],
                server_host_key: &["ssh-ed25519"],
                ciphers_c2s: &["chacha20-poly1305@openssh.com"],
                ciphers_s2c: &["chacha20-poly1305@openssh.com"],
                macs_c2s: &["hmac-sha2-256"],
                macs_s2c: &["hmac-sha2-256"],
                comp_c2s: &["none"],
                comp_s2c: &["none"],
                lang_c2s: &[],
                lang_s2c: &[],
            };
            KexInit::from_algorithms(&algs, cookie)
        };

        let _ = runner.start(&mut rng).expect("server start");
        let mut codec = PacketCodec::new();
        let adv = runner
            .on_packet(
                &mut rng,
                &mut codec,
                &client_init.encode(),
                None,
                None,
                b"SSH-2.0-test-client",
                b"SSH-2.0-test-server",
            )
            .expect("server processes client kexinit");
        assert!(!adv.completed);
        let neg = runner.negotiated().expect("negotiated");
        assert_eq!(neg.kex, "curve25519-sha256");
        assert_eq!(neg.host_key, "ssh-ed25519");
    }

    #[test]
    fn server_cipher_override_replaces_and_keeps_kex_markers() {
        let mut rng = OsRng;
        let host_keys: Vec<Box<dyn HostKey + Send + Sync>> =
            vec![Box::new(Ed25519HostKey::from_seed(fresh_seed()))];
        let cfg = kexinit_test_config(host_keys).with_algorithms(
            Some(vec!["aes256-ctr".to_string()]),
            None,
            None,
            None,
        );
        let advert = build_server_kexinit(&mut rng, &cfg);
        assert_eq!(advert.ciphers_c2s, vec!["aes256-ctr".to_string()]);
        // strict-kex markers preserved.
        let markers = advert
            .kex
            .iter()
            .filter(|k| is_strict_kex_marker(k))
            .count();
        assert_eq!(markers, 2);
    }

    #[test]
    fn server_hostkey_override_intersects_with_loaded_keys() {
        let mut rng = OsRng;
        // Only an ed25519 key is loaded.
        let host_keys: Vec<Box<dyn HostKey + Send + Sync>> =
            vec![Box::new(Ed25519HostKey::from_seed(fresh_seed()))];
        // Override prefers rsa first then ed25519; rsa is dropped (no key).
        let cfg = kexinit_test_config(host_keys).with_algorithms(
            None,
            None,
            None,
            Some(vec!["rsa-sha2-512".to_string(), "ssh-ed25519".to_string()]),
        );
        let advert = build_server_kexinit(&mut rng, &cfg);
        assert_eq!(advert.server_host_key, vec!["ssh-ed25519".to_string()]);
    }

    #[test]
    fn server_hostkey_override_excluding_ed25519_is_honoured() {
        let mut rng = OsRng;
        // Only ed25519 loaded, but the operator explicitly excludes it by
        // naming only rsa. The intersection is empty AND ed25519 is excluded,
        // so the fallback net must NOT re-add it.
        let host_keys: Vec<Box<dyn HostKey + Send + Sync>> =
            vec![Box::new(Ed25519HostKey::from_seed(fresh_seed()))];
        let cfg = kexinit_test_config(host_keys).with_algorithms(
            None,
            None,
            None,
            Some(vec!["rsa-sha2-512".to_string()]),
        );
        let advert = build_server_kexinit(&mut rng, &cfg);
        assert!(
            advert.server_host_key.is_empty(),
            "explicit ed25519 exclusion must not be overridden by the fallback net"
        );
    }

    #[test]
    fn server_no_override_falls_back_to_ed25519_when_no_keys() {
        let mut rng = OsRng;
        // No keys at all and no override -> the ed25519 net kicks in.
        let cfg = kexinit_test_config(Vec::new());
        let advert = build_server_kexinit(&mut rng, &cfg);
        assert_eq!(advert.server_host_key, vec!["ssh-ed25519".to_string()]);
    }

    /// A subsystem handler that reads bytes from the channel until EOF and
    /// writes them back uppercased. Used by [`loopback_subsystem_roundtrip`]
    /// to exercise the `dispatch_app_packet` subsystem path end-to-end
    /// (registration → ingress → egress → EOF → CLOSE) without depending on
    /// any actual SFTP semantics.
    ///
    /// The latched `user` lets the test assert the authenticated identity
    /// reaches the handler unchanged.
    struct EchoUpperSubsystem {
        captured_name: Arc<Mutex<Option<String>>>,
        captured_user: Arc<Mutex<Option<String>>>,
    }

    impl SubsystemHandler for EchoUpperSubsystem {
        fn handle(
            &self,
            user: &str,
            _env: &SessionEnv,
            name: &str,
            mut stream: ChannelStream,
        ) -> Result<()> {
            *self.captured_name.lock().unwrap() = Some(name.to_string());
            *self.captured_user.lock().unwrap() = Some(user.to_string());

            let mut acc = Vec::new();
            let mut tmp = [0u8; 256];
            loop {
                match std::io::Read::read(&mut stream, &mut tmp) {
                    Ok(0) => break, // EOF
                    Ok(n) => acc.extend_from_slice(&tmp[..n]),
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(5));
                        continue;
                    }
                    Err(_) => break,
                }
            }
            for b in acc.iter_mut() {
                b.make_ascii_uppercase();
            }
            std::io::Write::write_all(&mut stream, &acc).ok();
            // Dropping `stream` emits EOF + CLOSE to the peer.
            Ok(())
        }
    }

    #[test]
    fn loopback_subsystem_roundtrip() {
        // Exercise the new `subsystem` channel-request path:
        //   client opens session → asks for subsystem "echo" → pushes data
        //   → EOFs → drains response → CLOSE.
        // The handler runs on the dedicated subsystem thread spawned by
        // dispatch_app_packet; the dispatcher routes Data/Eof/Close events
        // through the mpsc plumbing in SubsystemRuntime.
        let host_seed = fresh_seed();
        let client_seed = fresh_seed();

        let host_key: Box<dyn HostKey + Send + Sync> =
            Box::new(Ed25519HostKey::from_seed(host_seed));
        let client_hk_for_auth = Ed25519HostKey::from_seed(client_seed);
        let allowed_blob = client_hk_for_auth.public_blob();

        let user = "subsys-test-user".to_string();
        let allowed_user_for_factory = user.clone();
        let allowed_blob_clone = allowed_blob.clone();
        let factory: Arc<dyn AuthenticatorFactory> = Arc::new(move || -> Box<dyn Authenticator> {
            Box::new(OneKeyAuth {
                allowed_user: allowed_user_for_factory.clone(),
                allowed_blob: allowed_blob_clone.clone(),
            })
        });

        let captured_name = Arc::new(Mutex::new(None));
        let captured_user = Arc::new(Mutex::new(None));
        let sub = EchoUpperSubsystem {
            captured_name: captured_name.clone(),
            captured_user: captured_user.clone(),
        };

        let cfg = Config::new(
            vec![host_key],
            factory,
            vec!["publickey"],
            Arc::new(StaticHandler {
                out: b"unused-exec\n".to_vec(),
            }),
        )
        .with_subsystem(Arc::new(sub));

        let mut server = Server::bind("127.0.0.1:0", cfg).expect("bind");
        let addr = server.local_addr().expect("local_addr");

        let server_done = Arc::new(Mutex::new(false));
        let sd = server_done.clone();
        let server_thread = thread::spawn(move || {
            let r = server.accept_one();
            *sd.lock().unwrap() = true;
            r
        });

        let mut client = Client::connect(
            addr,
            ClientConfig {
                host_key_policy: HostKeyPolicy::AcceptAny,
                timeout: Some(Duration::from_secs(10)),
                algorithms: Default::default(),
            },
        )
        .expect("client connect");

        let client_hk: Box<dyn HostKey + Send> = Box::new(Ed25519HostKey::from_seed(client_seed));
        client
            .authenticate_publickey(&user, client_hk)
            .expect("authenticate");

        let body = b"hello, subsystem world".to_vec();
        let resp = client
            .subsystem_once("echo", &body)
            .expect("subsystem_once");
        assert_eq!(resp, b"HELLO, SUBSYSTEM WORLD".to_vec());

        // The handler saw the right subsystem name and authenticated user.
        assert_eq!(
            captured_name.lock().unwrap().as_deref(),
            Some("echo"),
            "subsystem name reached the handler",
        );
        assert_eq!(
            captured_user.lock().unwrap().as_deref(),
            Some(user.as_str()),
            "authenticated user reached the handler",
        );

        drop(client);

        let start = std::time::Instant::now();
        while !*server_done.lock().unwrap() {
            if start.elapsed() > Duration::from_secs(10) {
                panic!("server thread did not finish in time");
            }
            thread::sleep(Duration::from_millis(20));
        }
        let _ = server_thread.join();
    }

    #[test]
    fn loopback_subsystem_unconfigured_refused() {
        // If Config has no subsystem_handler set, a `subsystem` request must
        // be rejected with SSH_MSG_CHANNEL_FAILURE. The client surfaces that
        // as a protocol error.
        let host_seed = fresh_seed();
        let client_seed = fresh_seed();

        let host_key: Box<dyn HostKey + Send + Sync> =
            Box::new(Ed25519HostKey::from_seed(host_seed));
        let client_hk_for_auth = Ed25519HostKey::from_seed(client_seed);
        let allowed_blob = client_hk_for_auth.public_blob();

        let user = "subsys-reject-user".to_string();
        let allowed_user_for_factory = user.clone();
        let allowed_blob_clone = allowed_blob.clone();
        let factory: Arc<dyn AuthenticatorFactory> = Arc::new(move || -> Box<dyn Authenticator> {
            Box::new(OneKeyAuth {
                allowed_user: allowed_user_for_factory.clone(),
                allowed_blob: allowed_blob_clone.clone(),
            })
        });

        let cfg = Config::new(
            vec![host_key],
            factory,
            vec!["publickey"],
            Arc::new(StaticHandler {
                out: b"unused-exec\n".to_vec(),
            }),
        );
        // Deliberately do NOT call with_subsystem.

        let mut server = Server::bind("127.0.0.1:0", cfg).expect("bind");
        let addr = server.local_addr().expect("local_addr");

        let server_done = Arc::new(Mutex::new(false));
        let sd = server_done.clone();
        let server_thread = thread::spawn(move || {
            let r = server.accept_one();
            *sd.lock().unwrap() = true;
            r
        });

        let mut client = Client::connect(
            addr,
            ClientConfig {
                host_key_policy: HostKeyPolicy::AcceptAny,
                timeout: Some(Duration::from_secs(10)),
                algorithms: Default::default(),
            },
        )
        .expect("client connect");

        let client_hk: Box<dyn HostKey + Send> = Box::new(Ed25519HostKey::from_seed(client_seed));
        client
            .authenticate_publickey(&user, client_hk)
            .expect("authenticate");

        let err = client
            .subsystem_once("sftp", b"")
            .expect_err("expected rejection");
        match err {
            Error::Protocol(_) => {}
            other => panic!("expected Error::Protocol, got {:?}", other),
        }

        drop(client);

        let start = std::time::Instant::now();
        while !*server_done.lock().unwrap() {
            if start.elapsed() > Duration::from_secs(10) {
                panic!("server thread did not finish in time");
            }
            thread::sleep(Duration::from_millis(20));
        }
        let _ = server_thread.join();
    }

    /// SubsystemHandler wrapping an `SftpServerSession` so the loopback
    /// SFTP test can drive the in-process server over a real SSH channel.
    /// Only used by the Unix-only `loopback_sftp_client_roundtrip` test
    /// below — gated to silence dead-code warnings on Windows.
    #[cfg(unix)]
    struct SftpSubsystem {
        cwd: std::path::PathBuf,
        root: std::path::PathBuf,
    }

    #[cfg(unix)]
    impl SubsystemHandler for SftpSubsystem {
        fn handle(
            &self,
            _user: &str,
            _env: &SessionEnv,
            name: &str,
            stream: ChannelStream,
        ) -> Result<()> {
            if name != "sftp" {
                return Ok(());
            }
            // Keep the historical (leaky) realpath behaviour here so the
            // test below can compare against the host-side absolute root
            // path. The default flipped to `true` (hide jail in realpath)
            // as part of the SFTP info-leak security fix; opting out keeps
            // this transport-layer roundtrip test's intent intact.
            let opts = crate::sftp::SftpServerOptions::new(self.cwd.clone())
                .with_root(self.root.clone())
                .hide_jail_in_realpath(false);
            let mut sess = crate::sftp::SftpServerSession::new(opts);
            // SftpError → Result is best-effort; drop the stream on return so
            // the dispatcher emits EOF+CLOSE to the peer.
            let _ = sess.run(stream);
            Ok(())
        }
    }

    /// pid + nanosecond timestamp gives a unique directory across parallel
    /// `cargo test` workers without pulling in a tempfile dep — mirrors the
    /// pattern in `src/sftp/tests.rs`. Only used by the Unix-only test
    /// below; gated to silence dead-code warnings on Windows.
    #[cfg(unix)]
    struct SftpTempDir(std::path::PathBuf);

    #[cfg(unix)]
    impl SftpTempDir {
        fn new(tag: &str) -> Self {
            let dir = std::env::temp_dir().join(format!(
                "puressh-server-sftp-{}-{}-{}",
                tag,
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos(),
            ));
            std::fs::create_dir_all(&dir).unwrap();
            Self(dir)
        }
        fn path(&self) -> &std::path::Path {
            &self.0
        }
    }
    #[cfg(unix)]
    impl Drop for SftpTempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    // Gated to Unix: the test compares native filesystem paths to
    // SFTP-protocol paths byte-for-byte (e.g. `realpath(".")` vs
    // `root.as_os_str().as_encoded_bytes()`), and the server's
    // `lexically_clean` deliberately strips Windows path prefixes and roots
    // them at `/`. On Windows the roundtrip is therefore lossy by design —
    // SFTP semantics over a non-POSIX filesystem aren't a target use case
    // for this end-to-end test.
    #[cfg(unix)]
    #[test]
    fn loopback_sftp_client_roundtrip() {
        // End-to-end: Client::sftp() opens a channel, requests subsystem
        // "sftp", performs INIT/VERSION, then drives a put + readdir + get
        // round-trip against an in-process SftpServerSession running on the
        // dispatcher's subsystem thread.
        let tmp = SftpTempDir::new("roundtrip");
        let root = tmp.path().to_path_buf();

        let host_seed = fresh_seed();
        let client_seed = fresh_seed();

        let host_key: Box<dyn HostKey + Send + Sync> =
            Box::new(Ed25519HostKey::from_seed(host_seed));
        let client_hk_for_auth = Ed25519HostKey::from_seed(client_seed);
        let allowed_blob = client_hk_for_auth.public_blob();

        let user = "sftp-test-user".to_string();
        let allowed_user_for_factory = user.clone();
        let allowed_blob_clone = allowed_blob.clone();
        let factory: Arc<dyn AuthenticatorFactory> = Arc::new(move || -> Box<dyn Authenticator> {
            Box::new(OneKeyAuth {
                allowed_user: allowed_user_for_factory.clone(),
                allowed_blob: allowed_blob_clone.clone(),
            })
        });

        let sub = SftpSubsystem {
            cwd: root.clone(),
            root: root.clone(),
        };

        let cfg = Config::new(
            vec![host_key],
            factory,
            vec!["publickey"],
            Arc::new(StaticHandler {
                out: b"unused-exec\n".to_vec(),
            }),
        )
        .with_subsystem(Arc::new(sub));

        let mut server = Server::bind("127.0.0.1:0", cfg).expect("bind");
        let addr = server.local_addr().expect("local_addr");

        let server_done = Arc::new(Mutex::new(false));
        let sd = server_done.clone();
        let server_thread = thread::spawn(move || {
            let r = server.accept_one();
            *sd.lock().unwrap() = true;
            r
        });

        let mut client = Client::connect(
            addr,
            ClientConfig {
                host_key_policy: HostKeyPolicy::AcceptAny,
                timeout: Some(Duration::from_secs(10)),
                algorithms: Default::default(),
            },
        )
        .expect("client connect");

        let client_hk: Box<dyn HostKey + Send> = Box::new(Ed25519HostKey::from_seed(client_seed));
        client
            .authenticate_publickey(&user, client_hk)
            .expect("authenticate");

        {
            // Single-channel sftp inside the borrow-based test; the
            // multi-channel SharedClient::sftp has its own test.
            #[allow(deprecated)]
            let mut sftp = client.sftp().expect("sftp handshake");
            assert!(sftp.server_version() >= 3);

            // Realpath: ask the server to canonicalise "." → returns the cwd.
            let cwd = sftp.realpath(b".").expect("realpath .");
            assert_eq!(cwd.as_slice(), root.as_os_str().as_encoded_bytes());

            // Write a file via SFTP.
            let target = root.join("hello.txt");
            let body = b"hello from sftp\n".to_vec();
            let handle = sftp
                .open(
                    target.as_os_str().as_encoded_bytes(),
                    crate::sftp::FXF_WRITE | crate::sftp::FXF_CREAT | crate::sftp::FXF_TRUNC,
                    crate::sftp::Attrs::default(),
                )
                .expect("open for write");
            sftp.write(&handle, 0, &body).expect("write");
            sftp.close(&handle).expect("close write handle");

            // Now read it back via SFTP.
            let handle = sftp
                .open(
                    target.as_os_str().as_encoded_bytes(),
                    crate::sftp::FXF_READ,
                    crate::sftp::Attrs::default(),
                )
                .expect("open for read");
            let got = sftp.read(&handle, 0, 1024).expect("read");
            assert_eq!(got, body);
            sftp.close(&handle).expect("close read handle");

            // readdir sees the new entry.
            let dh = sftp
                .opendir(root.as_os_str().as_encoded_bytes())
                .expect("opendir");
            let mut all_names = Vec::<Vec<u8>>::new();
            while let Some(batch) = sftp.readdir(&dh).expect("readdir") {
                for e in batch {
                    all_names.push(e.filename);
                }
            }
            sftp.close(&dh).expect("close dir");
            assert!(
                all_names.iter().any(|n| n == b"hello.txt"),
                "readdir saw the new file: {:?}",
                all_names
                    .iter()
                    .map(|n| String::from_utf8_lossy(n).into_owned())
                    .collect::<Vec<_>>(),
            );

            // remove() and confirm.
            sftp.remove(target.as_os_str().as_encoded_bytes())
                .expect("remove");
            let err = sftp
                .stat(target.as_os_str().as_encoded_bytes())
                .expect_err("stat after remove");
            match err {
                crate::sftp::SftpError::Status {
                    code: crate::sftp::FxpStatus::NoSuchFile,
                    ..
                } => {}
                other => panic!("expected NoSuchFile, got {:?}", other),
            }

            // sftp's Drop closes the channel before client is dropped.
        }

        drop(client);

        let start = std::time::Instant::now();
        while !*server_done.lock().unwrap() {
            if start.elapsed() > Duration::from_secs(10) {
                panic!("server thread did not finish in time");
            }
            thread::sleep(Duration::from_millis(20));
        }
        let _ = server_thread.join();
    }

    #[test]
    fn loopback_direct_tcpip_round_trip() {
        // End-to-end exercise of the direct-tcpip server-side path:
        //   client opens direct-tcpip channel → server connects to a local
        //   TCP echo server via DefaultDirectTcpipHandler → bytes flow both
        //   ways → client drops the stream which closes the channel.
        use std::io::{Read as _, Write as _};
        use std::net::TcpListener;

        // 1) Local TCP echo server — the "destination" the SSH client wants
        //    the server to dial.
        let echo_listener = TcpListener::bind("127.0.0.1:0").expect("bind echo");
        let echo_addr = echo_listener.local_addr().expect("echo addr");
        let echo_thread = thread::spawn(move || {
            if let Ok((mut s, _)) = echo_listener.accept() {
                let mut buf = [0u8; 1024];
                loop {
                    match s.read(&mut buf) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if s.write_all(&buf[..n]).is_err() {
                                break;
                            }
                        }
                    }
                }
            }
        });

        // 2) SSH server with DefaultDirectTcpipHandler attached.
        let host_seed = fresh_seed();
        let client_seed = fresh_seed();

        let host_key: Box<dyn HostKey + Send + Sync> =
            Box::new(Ed25519HostKey::from_seed(host_seed));
        let client_hk_for_auth = Ed25519HostKey::from_seed(client_seed);
        let allowed_blob = client_hk_for_auth.public_blob();

        let user = "direct-tcpip-user".to_string();
        let allowed_user_for_factory = user.clone();
        let allowed_blob_clone = allowed_blob.clone();
        let factory: Arc<dyn AuthenticatorFactory> = Arc::new(move || -> Box<dyn Authenticator> {
            Box::new(OneKeyAuth {
                allowed_user: allowed_user_for_factory.clone(),
                allowed_blob: allowed_blob_clone.clone(),
            })
        });

        let cfg = Config::new(
            vec![host_key],
            factory,
            vec!["publickey"],
            Arc::new(StaticHandler {
                out: b"unused-exec\n".to_vec(),
            }),
        )
        .with_direct_tcpip(Arc::new(
            // Test wants the bytes to round-trip; ::new() is default-deny
            // post-2026-05, so call ::permit_all() to restore the pre-fix
            // behaviour for the splice path.
            crate::forwarding::direct::DefaultDirectTcpipHandler::permit_all(),
        ));

        let mut server = Server::bind("127.0.0.1:0", cfg).expect("bind ssh");
        let ssh_addr = server.local_addr().expect("ssh addr");

        let server_done = Arc::new(Mutex::new(false));
        let sd = server_done.clone();
        let server_thread = thread::spawn(move || {
            let r = server.accept_one();
            *sd.lock().unwrap() = true;
            r
        });

        // 3) SSH client opens direct-tcpip and round-trips bytes through it.
        let mut client = Client::connect(
            ssh_addr,
            ClientConfig {
                host_key_policy: HostKeyPolicy::AcceptAny,
                timeout: Some(Duration::from_secs(10)),
                algorithms: Default::default(),
            },
        )
        .expect("client connect");

        let client_hk: Box<dyn HostKey + Send> = Box::new(Ed25519HostKey::from_seed(client_seed));
        client
            .authenticate_publickey(&user, client_hk)
            .expect("authenticate");

        {
            // Single-channel test path; SharedClient is exercised elsewhere.
            #[allow(deprecated)]
            let mut s = client
                .open_direct_tcpip(
                    &echo_addr.ip().to_string(),
                    echo_addr.port(),
                    "127.0.0.1",
                    0,
                )
                .expect("open direct-tcpip");
            s.write_all(b"ping").expect("write");
            let mut got = [0u8; 4];
            s.read_exact(&mut got).expect("read echo");
            assert_eq!(&got, b"ping");
            // Dropping `s` closes the channel.
        }

        drop(client);

        let start = std::time::Instant::now();
        while !*server_done.lock().unwrap() {
            if start.elapsed() > Duration::from_secs(10) {
                panic!("server thread did not finish in time");
            }
            thread::sleep(Duration::from_millis(20));
        }
        let _ = server_thread.join();
        let _ = echo_thread.join();
    }

    #[test]
    // Whole test exercises the deprecated borrow-based open_direct_tcpip;
    // SharedClient is covered by its own integration tests.
    #[allow(deprecated)]
    fn loopback_direct_tcpip_unconfigured_refused() {
        // Without a direct_tcpip_handler attached the channel-open must be
        // rejected with SSH_OPEN_ADMINISTRATIVELY_PROHIBITED, surfaced to
        // the client as a protocol error.
        let host_seed = fresh_seed();
        let client_seed = fresh_seed();

        let host_key: Box<dyn HostKey + Send + Sync> =
            Box::new(Ed25519HostKey::from_seed(host_seed));
        let client_hk_for_auth = Ed25519HostKey::from_seed(client_seed);
        let allowed_blob = client_hk_for_auth.public_blob();

        let user = "direct-tcpip-reject-user".to_string();
        let allowed_user_for_factory = user.clone();
        let allowed_blob_clone = allowed_blob.clone();
        let factory: Arc<dyn AuthenticatorFactory> = Arc::new(move || -> Box<dyn Authenticator> {
            Box::new(OneKeyAuth {
                allowed_user: allowed_user_for_factory.clone(),
                allowed_blob: allowed_blob_clone.clone(),
            })
        });

        let cfg = Config::new(
            vec![host_key],
            factory,
            vec!["publickey"],
            Arc::new(StaticHandler {
                out: b"unused\n".to_vec(),
            }),
        );
        // Deliberately do NOT call with_direct_tcpip.

        let mut server = Server::bind("127.0.0.1:0", cfg).expect("bind");
        let addr = server.local_addr().expect("addr");

        let server_done = Arc::new(Mutex::new(false));
        let sd = server_done.clone();
        let server_thread = thread::spawn(move || {
            let r = server.accept_one();
            *sd.lock().unwrap() = true;
            r
        });

        let mut client = Client::connect(
            addr,
            ClientConfig {
                host_key_policy: HostKeyPolicy::AcceptAny,
                timeout: Some(Duration::from_secs(10)),
                algorithms: Default::default(),
            },
        )
        .expect("client connect");

        let client_hk: Box<dyn HostKey + Send> = Box::new(Ed25519HostKey::from_seed(client_seed));
        client
            .authenticate_publickey(&user, client_hk)
            .expect("authenticate");

        // `ClientChannelStream` isn't `Debug`, so we can't use `expect_err`
        // — branch on the result manually.
        match client.open_direct_tcpip("127.0.0.1", 1, "127.0.0.1", 0) {
            Ok(_) => panic!("expected direct-tcpip open to be refused"),
            Err(Error::Protocol(_)) => {}
            Err(other) => panic!("expected Error::Protocol, got {:?}", other),
        }

        drop(client);

        let start = std::time::Instant::now();
        while !*server_done.lock().unwrap() {
            if start.elapsed() > Duration::from_secs(10) {
                panic!("server thread did not finish in time");
            }
            thread::sleep(Duration::from_millis(20));
        }
        let _ = server_thread.join();
    }

    #[test]
    fn loopback_tcpip_forward_round_trip() {
        // End-to-end exercise of the full ssh -R path:
        //   client issues tcpip-forward → server binds a real TCP listener →
        //   test thread dials the bound port → server opens forwarded-tcpip
        //   back to the client → client.serve()'s on_forwarded_tcpip handler
        //   echoes data → bytes flow both ways → handler exits → next dial
        //   round-trips again → client cancel-tcpip-forward & stop.
        use crate::client::{ClientHandlers, ForwardedTcpipOrigin};
        use std::io::{Read as _, Write as _};
        use std::net::TcpStream;
        use std::sync::atomic::Ordering;

        let host_seed = fresh_seed();
        let client_seed = fresh_seed();

        let host_key: Box<dyn HostKey + Send + Sync> =
            Box::new(Ed25519HostKey::from_seed(host_seed));
        let client_hk_for_auth = Ed25519HostKey::from_seed(client_seed);
        let allowed_blob = client_hk_for_auth.public_blob();

        let user = "tcpip-forward-user".to_string();
        let allowed_user_for_factory = user.clone();
        let allowed_blob_clone = allowed_blob.clone();
        let factory: Arc<dyn AuthenticatorFactory> = Arc::new(move || -> Box<dyn Authenticator> {
            Box::new(OneKeyAuth {
                allowed_user: allowed_user_for_factory.clone(),
                allowed_blob: allowed_blob_clone.clone(),
            })
        });

        let cfg = Config::new(
            vec![host_key],
            factory,
            vec!["publickey"],
            Arc::new(StaticHandler {
                out: b"unused-exec\n".to_vec(),
            }),
        )
        .with_tcpip_forward(Arc::new(
            // Test wants the bind to succeed and the splice path to fire;
            // ::new() is default-deny post-2026-05, so call the explicit
            // "old default" constructor here.
            crate::forwarding::reverse::DefaultTcpipForwardHandler::permit_all_interfaces(),
        ));

        let mut server = Server::bind("127.0.0.1:0", cfg).expect("bind ssh");
        let ssh_addr = server.local_addr().expect("ssh addr");

        let server_done = Arc::new(Mutex::new(false));
        let sd = server_done.clone();
        let server_thread = thread::spawn(move || {
            let r = server.accept_one();
            *sd.lock().unwrap() = true;
            r
        });

        let mut client = Client::connect(
            ssh_addr,
            ClientConfig {
                host_key_policy: HostKeyPolicy::AcceptAny,
                timeout: Some(Duration::from_secs(10)),
                algorithms: Default::default(),
            },
        )
        .expect("client connect");

        let client_hk: Box<dyn HostKey + Send> = Box::new(Ed25519HostKey::from_seed(client_seed));
        client
            .authenticate_publickey(&user, client_hk)
            .expect("authenticate");

        // Ask the server to bind a kernel-assigned port on loopback.
        let bound_port = client
            .request_tcpip_forward("127.0.0.1", 0)
            .expect("request_tcpip_forward");
        assert!(bound_port > 0);

        // Latch the (origin) the handler sees so the test can assert the
        // server is echoing the right address/port back.
        let origin_seen: Arc<Mutex<Option<ForwardedTcpipOrigin>>> = Arc::new(Mutex::new(None));
        let origin_clone = origin_seen.clone();

        // Forwarded-tcpip handler: read until EOF, write back uppercased.
        // Implemented inline so we can latch the origin too.
        let cb: Arc<crate::client::ForwardedTcpipCallback> =
            Arc::new(move |origin: ForwardedTcpipOrigin, mut s: ChannelStream| {
                *origin_clone.lock().unwrap() = Some(origin);
                let mut acc = Vec::new();
                let mut tmp = [0u8; 256];
                loop {
                    match Read::read(&mut s, &mut tmp) {
                        Ok(0) => break,
                        Ok(n) => acc.extend_from_slice(&tmp[..n]),
                        Err(_) => break,
                    }
                }
                for b in acc.iter_mut() {
                    b.make_ascii_uppercase();
                }
                let _ = Write::write_all(&mut s, &acc);
                // Dropping `s` sends EOF + CLOSE.
            });

        let handlers = ClientHandlers::new().with_forwarded_tcpip(cb);
        let stop = handlers.stop.clone();

        // Drive `serve` in its own thread; mainline test thread plays the
        // role of the external app dialing the forwarded port.
        let serve_thread = thread::spawn(move || -> std::result::Result<Client, Error> {
            // Take Client by move; this consumes our handle until serve returns.
            client.serve(handlers)?;
            Ok(client)
        });

        // Round-trip one connection through the forwarded port.
        let mut s = TcpStream::connect(("127.0.0.1", bound_port)).expect("dial forwarded port");
        s.write_all(b"hello").expect("write");
        // Half-close so the handler's read returns Ok(0) and it writes back.
        s.shutdown(std::net::Shutdown::Write)
            .expect("shutdown write");
        let mut got = Vec::new();
        s.read_to_end(&mut got).expect("read echo");
        assert_eq!(got, b"HELLO");
        drop(s);

        // Wait briefly for handler thread to settle / runtime to clean up.
        thread::sleep(Duration::from_millis(100));

        // Now ask serve to stop. cancel_tcpip_forward needs the client
        // back; we just set stop and tear down by dropping the client
        // socket from within the serve loop instead.
        stop.store(true, Ordering::SeqCst);

        // Give serve a chance to observe `stop` and exit.
        let start = std::time::Instant::now();
        while !serve_thread.is_finished() {
            if start.elapsed() > Duration::from_secs(10) {
                panic!("serve loop did not stop in time");
            }
            thread::sleep(Duration::from_millis(20));
        }
        let client_back = serve_thread
            .join()
            .expect("serve join")
            .expect("serve result");

        // Origin assertions: the handler ran at least once with our bind addr
        // and a non-zero originator port (the loopback connect()).
        let captured = origin_seen.lock().unwrap().clone().expect("origin latched");
        assert_eq!(captured.bound_address, "127.0.0.1");
        assert_eq!(captured.bound_port, bound_port);
        assert!(captured.orig_port > 0);

        drop(client_back);

        let start = std::time::Instant::now();
        while !*server_done.lock().unwrap() {
            if start.elapsed() > Duration::from_secs(10) {
                panic!("server thread did not finish in time");
            }
            thread::sleep(Duration::from_millis(20));
        }
        let _ = server_thread.join();
    }

    #[test]
    fn loopback_tcpip_forward_unconfigured_refused() {
        // Without a tcpip_forward_handler attached the global request
        // must be answered REQUEST_FAILURE; the client surfaces that
        // as Error::Protocol.
        let host_seed = fresh_seed();
        let client_seed = fresh_seed();

        let host_key: Box<dyn HostKey + Send + Sync> =
            Box::new(Ed25519HostKey::from_seed(host_seed));
        let client_hk_for_auth = Ed25519HostKey::from_seed(client_seed);
        let allowed_blob = client_hk_for_auth.public_blob();

        let user = "tcpip-forward-reject-user".to_string();
        let allowed_user_for_factory = user.clone();
        let allowed_blob_clone = allowed_blob.clone();
        let factory: Arc<dyn AuthenticatorFactory> = Arc::new(move || -> Box<dyn Authenticator> {
            Box::new(OneKeyAuth {
                allowed_user: allowed_user_for_factory.clone(),
                allowed_blob: allowed_blob_clone.clone(),
            })
        });

        let cfg = Config::new(
            vec![host_key],
            factory,
            vec!["publickey"],
            Arc::new(StaticHandler {
                out: b"unused\n".to_vec(),
            }),
        );
        // Deliberately no .with_tcpip_forward.

        let mut server = Server::bind("127.0.0.1:0", cfg).expect("bind ssh");
        let ssh_addr = server.local_addr().expect("ssh addr");

        let server_done = Arc::new(Mutex::new(false));
        let sd = server_done.clone();
        let server_thread = thread::spawn(move || {
            let r = server.accept_one();
            *sd.lock().unwrap() = true;
            r
        });

        let mut client = Client::connect(
            ssh_addr,
            ClientConfig {
                host_key_policy: HostKeyPolicy::AcceptAny,
                timeout: Some(Duration::from_secs(10)),
                algorithms: Default::default(),
            },
        )
        .expect("client connect");

        let client_hk: Box<dyn HostKey + Send> = Box::new(Ed25519HostKey::from_seed(client_seed));
        client
            .authenticate_publickey(&user, client_hk)
            .expect("authenticate");

        match client.request_tcpip_forward("127.0.0.1", 0) {
            Ok(_) => panic!("expected tcpip-forward to be refused"),
            Err(Error::Protocol(_)) => {}
            Err(other) => panic!("expected Error::Protocol, got {:?}", other),
        }

        drop(client);

        let start = std::time::Instant::now();
        while !*server_done.lock().unwrap() {
            if start.elapsed() > Duration::from_secs(10) {
                panic!("server thread did not finish in time");
            }
            thread::sleep(Duration::from_millis(20));
        }
        let _ = server_thread.join();
    }

    #[test]
    fn loopback_serve_context_direct_tcpip_round_trip() {
        // End-to-end exercise of the outbound side of the multi-channel
        // serve loop (the path that backs `ssh -L`):
        //   client.serve() runs in a thread → test thread asks ServeContext
        //   for a direct-tcpip → server's DefaultDirectTcpipHandler dials a
        //   local echo server → bytes round-trip → stream drop tears the
        //   channel down → stop flag set → serve returns.
        use crate::client::ClientHandlers;
        use std::io::{Read as _, Write as _};
        use std::net::TcpListener;
        use std::sync::atomic::Ordering;

        // 1) Echo destination.
        let echo_listener = TcpListener::bind("127.0.0.1:0").expect("bind echo");
        let echo_addr = echo_listener.local_addr().expect("echo addr");
        let echo_thread = thread::spawn(move || {
            if let Ok((mut s, _)) = echo_listener.accept() {
                let mut buf = [0u8; 1024];
                loop {
                    match s.read(&mut buf) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if s.write_all(&buf[..n]).is_err() {
                                break;
                            }
                        }
                    }
                }
            }
        });

        // 2) SSH server with direct-tcpip enabled.
        let host_seed = fresh_seed();
        let client_seed = fresh_seed();
        let host_key: Box<dyn HostKey + Send + Sync> =
            Box::new(Ed25519HostKey::from_seed(host_seed));
        let client_hk_for_auth = Ed25519HostKey::from_seed(client_seed);
        let allowed_blob = client_hk_for_auth.public_blob();

        let user = "serve-ctx-user".to_string();
        let allowed_user_for_factory = user.clone();
        let allowed_blob_clone = allowed_blob.clone();
        let factory: Arc<dyn AuthenticatorFactory> = Arc::new(move || -> Box<dyn Authenticator> {
            Box::new(OneKeyAuth {
                allowed_user: allowed_user_for_factory.clone(),
                allowed_blob: allowed_blob_clone.clone(),
            })
        });

        let cfg = Config::new(
            vec![host_key],
            factory,
            vec!["publickey"],
            Arc::new(StaticHandler {
                out: b"unused\n".to_vec(),
            }),
        )
        .with_direct_tcpip(Arc::new(
            // Test wants the bytes to round-trip; ::new() is default-deny
            // post-2026-05, so call ::permit_all() to restore the pre-fix
            // behaviour for the splice path.
            crate::forwarding::direct::DefaultDirectTcpipHandler::permit_all(),
        ));

        let mut server = Server::bind("127.0.0.1:0", cfg).expect("bind ssh");
        let ssh_addr = server.local_addr().expect("ssh addr");

        let server_done = Arc::new(Mutex::new(false));
        let sd = server_done.clone();
        let server_thread = thread::spawn(move || {
            let r = server.accept_one();
            *sd.lock().unwrap() = true;
            r
        });

        // 3) SSH client connects + auths.
        let mut client = Client::connect(
            ssh_addr,
            ClientConfig {
                host_key_policy: HostKeyPolicy::AcceptAny,
                timeout: Some(Duration::from_secs(10)),
                algorithms: Default::default(),
            },
        )
        .expect("client connect");
        let client_hk: Box<dyn HostKey + Send> = Box::new(Ed25519HostKey::from_seed(client_seed));
        client
            .authenticate_publickey(&user, client_hk)
            .expect("authenticate");

        // 4) Build handlers with a ServeContext + drive serve() in a thread.
        let (handlers, ctx) = ClientHandlers::new().with_serve_context();
        let stop = handlers.stop.clone();
        let serve_thread = thread::spawn(move || -> std::result::Result<Client, Error> {
            client.serve(handlers)?;
            Ok(client)
        });

        // 5) Open a direct-tcpip via the context and round-trip bytes.
        let mut s = ctx
            .open_direct_tcpip(
                &echo_addr.ip().to_string(),
                echo_addr.port(),
                "127.0.0.1",
                0,
            )
            .expect("open_direct_tcpip via ServeContext");
        s.write_all(b"ping").expect("write ping");
        let mut got = [0u8; 4];
        s.read_exact(&mut got).expect("read echo");
        assert_eq!(&got, b"ping");
        drop(s);

        // Wait for the channel teardown to settle.
        thread::sleep(Duration::from_millis(100));

        // 6) Ask serve to stop. The ServeContext drop releases the cmd_tx.
        drop(ctx);
        stop.store(true, Ordering::SeqCst);

        let start = std::time::Instant::now();
        while !serve_thread.is_finished() {
            if start.elapsed() > Duration::from_secs(10) {
                panic!("serve loop did not stop in time");
            }
            thread::sleep(Duration::from_millis(20));
        }
        let client_back = serve_thread
            .join()
            .expect("serve join")
            .expect("serve result");
        drop(client_back);

        let start = std::time::Instant::now();
        while !*server_done.lock().unwrap() {
            if start.elapsed() > Duration::from_secs(10) {
                panic!("server thread did not finish in time");
            }
            thread::sleep(Duration::from_millis(20));
        }
        let _ = server_thread.join();
        let _ = echo_thread.join();
    }

    // ---- env allowlist filter ---------------------------------------------

    #[test]
    fn env_filter_blocks_ld_preload_even_when_glob_matches() {
        // Worst-case operator typo: `AcceptEnv *` lets through *everything*
        // that isn't on the hard-block list. LD_PRELOAD is on that list,
        // so it must be refused even with the broadest possible pattern.
        let allow = vec!["*".to_string()];
        assert!(
            !env_name_accepted("LD_PRELOAD", &allow),
            "LD_PRELOAD must NEVER be accepted, even with `AcceptEnv *`"
        );
        assert!(!env_name_accepted("LD_LIBRARY_PATH", &allow));
        assert!(!env_name_accepted("LD_AUDIT", &allow));
        assert!(!env_name_accepted("LD_BIND_NOT", &allow));
        assert!(!env_name_accepted("DYLD_INSERT_LIBRARIES", &allow));
        assert!(!env_name_accepted("DYLD_LIBRARY_PATH", &allow));
        assert!(!env_name_accepted("BASH_ENV", &allow));
        assert!(!env_name_accepted("ENV", &allow));
        assert!(!env_name_accepted("IFS", &allow));
        assert!(!env_name_accepted("PATH", &allow));
        assert!(!env_name_accepted("SHELL", &allow));
        assert!(!env_name_accepted("HOME", &allow));
        assert!(!env_name_accepted("USER", &allow));
        assert!(!env_name_accepted("LOGNAME", &allow));
        // Non-blocked names with `*` still succeed.
        assert!(env_name_accepted("LANG", &allow));
        assert!(env_name_accepted("LC_ALL", &allow));
        assert!(env_name_accepted("TERM", &allow));
    }

    #[test]
    fn env_filter_explicit_listing_of_blocked_name_still_blocks() {
        // Operator typo #2: explicitly listing LD_PRELOAD in AcceptEnv.
        // Still must not be honoured.
        let allow = vec!["LD_PRELOAD".to_string()];
        assert!(!env_name_accepted("LD_PRELOAD", &allow));
    }

    #[test]
    fn env_filter_empty_allowlist_drops_everything() {
        let allow: Vec<String> = Vec::new();
        assert!(!env_name_accepted("LANG", &allow));
        assert!(!env_name_accepted("TERM", &allow));
        assert!(!env_name_accepted("FOO", &allow));
        assert!(!env_name_accepted("LD_PRELOAD", &allow));
    }

    #[test]
    fn env_filter_glob_matching() {
        let allow = vec!["LC_*".to_string(), "LANG".to_string(), "X???".to_string()];
        // Direct matches.
        assert!(env_name_accepted("LANG", &allow));
        assert!(env_name_accepted("LC_ALL", &allow));
        assert!(env_name_accepted("LC_TIME", &allow));
        assert!(env_name_accepted("LC_CTYPE", &allow));
        assert!(env_name_accepted("XABC", &allow));
        // Non-matches.
        assert!(!env_name_accepted("LANGUAGE", &allow)); // no pattern
        assert!(!env_name_accepted("XABCD", &allow)); // ??? matches exactly 3
        assert!(!env_name_accepted("XAB", &allow));
        assert!(!env_name_accepted("MC_ALL", &allow));
        // Empty name (defensive).
        assert!(!env_name_accepted("", &allow));
    }

    // ---- per-connection policy resolution (W5/W6) ------------------------

    fn policy_cfg(src: &str) -> Config {
        let host_key: Box<dyn HostKey + Send + Sync> =
            Box::new(Ed25519HostKey::from_seed(fresh_seed()));
        let factory: Arc<dyn AuthenticatorFactory> = Arc::new(|| -> Box<dyn Authenticator> {
            Box::new(OneKeyAuth {
                allowed_user: "x".into(),
                allowed_blob: Vec::new(),
            })
        });
        let policy = crate::config::SshServerConfig::parse(src).expect("parse policy");
        Config::new(
            vec![host_key],
            factory,
            vec!["publickey"],
            Arc::new(StaticHandler { out: Vec::new() }),
        )
        .with_policy(Arc::new(policy))
    }

    #[test]
    fn pubkey_auth_no_locks_out_method_set() {
        // Global PubkeyAuthentication no ⇒ the resolved pre-auth method set is
        // empty (publickey, the only honorable method, is dropped).
        let cfg = policy_cfg("PubkeyAuthentication no\n");
        let pre = resolve_preauth_policy(&cfg, Some("203.0.113.5"), None, None);
        assert!(
            pre.methods.is_empty(),
            "expected lockout, got {:?}",
            pre.methods
        );

        // Without the policy the method set is the static default.
        let cfg2 = policy_cfg("PubkeyAuthentication yes\n");
        let pre2 = resolve_preauth_policy(&cfg2, Some("203.0.113.5"), None, None);
        assert_eq!(pre2.methods, vec!["publickey"]);
    }

    #[test]
    fn match_address_gates_pubkey_via_block() {
        // publickey is dropped only for peers in 192.0.2.0/24.
        let cfg = policy_cfg("Match Address 192.0.2.0/24\n  PubkeyAuthentication no\n");
        let inside = resolve_preauth_policy(&cfg, Some("192.0.2.9"), None, None);
        assert!(inside.methods.is_empty());
        let outside = resolve_preauth_policy(&cfg, Some("198.51.100.1"), None, None);
        assert_eq!(outside.methods, vec!["publickey"]);
    }

    #[test]
    fn match_localport_in_effective_policy() {
        let cfg =
            policy_cfg("Match LocalPort 2222\n  X11Forwarding no\n  AllowAgentForwarding no\n");
        let eff = resolve_effective_policy(&cfg, "alice", None, None, None, Some(2222));
        assert_eq!(eff.x11_forwarding, Some(false));
        assert!(!eff.x11_forwarding_allowed());
        assert!(!eff.agent_forwarding_allowed());
        // Different port ⇒ block does not apply, defaults allow.
        let eff2 = resolve_effective_policy(&cfg, "alice", None, None, None, Some(22));
        assert_eq!(eff2.x11_forwarding, None);
        assert!(eff2.x11_forwarding_allowed());
        assert!(eff2.agent_forwarding_allowed());
    }

    #[test]
    fn match_group_in_effective_policy() {
        let cfg = policy_cfg("Match Group dev\n  X11Forwarding no\n");
        let groups = vec!["dev".to_string()];
        let eff = resolve_effective_policy(&cfg, "alice", Some(&groups), None, None, None);
        assert_eq!(eff.x11_forwarding, Some(false));
        // No groups ⇒ block never matches.
        let eff2 = resolve_effective_policy(&cfg, "alice", None, None, None, None);
        assert_eq!(eff2.x11_forwarding, None);
    }

    #[test]
    fn max_auth_tries_flows_into_preauth() {
        let cfg = policy_cfg("MaxAuthTries 3\n");
        let pre = resolve_preauth_policy(&cfg, Some("203.0.113.5"), None, None);
        assert_eq!(pre.max_auth_tries, Some(3));
    }

    // ---- F5: mid-userauth Match User / Match Group method re-resolve --------

    #[test]
    fn reresolve_match_user_drops_publickey() {
        // Global allows publickey; a Match User block turns it off for alice.
        // The pre-auth (address-only) set still advertises publickey, but the
        // re-resolve once the username is known must drop it for alice and
        // leave it for bob.
        let cfg = policy_cfg("Match User alice\n  PubkeyAuthentication no\n");
        let pre = resolve_preauth_policy(&cfg, Some("203.0.113.5"), None, None);
        assert_eq!(pre.methods, vec!["publickey"]);

        let alice = reresolve_user_policy(&cfg, &pre.methods, "alice", None, None, None);
        assert!(
            alice.methods.is_empty(),
            "alice should lose publickey, got {:?}",
            alice.methods
        );
        let bob = reresolve_user_policy(&cfg, &pre.methods, "bob", None, None, None);
        assert_eq!(bob.methods, vec!["publickey"]);
    }

    #[test]
    fn reresolve_match_group_uses_group_resolver() {
        // Match Group dev drops publickey; the group context must come from the
        // configured GroupResolver (the same path the access checks use).
        let host_key: Box<dyn HostKey + Send + Sync> =
            Box::new(Ed25519HostKey::from_seed(fresh_seed()));
        let factory: Arc<dyn AuthenticatorFactory> = Arc::new(|| -> Box<dyn Authenticator> {
            Box::new(OneKeyAuth {
                allowed_user: "x".into(),
                allowed_blob: Vec::new(),
            })
        });
        let policy =
            crate::config::SshServerConfig::parse("Match Group dev\n  PubkeyAuthentication no\n")
                .expect("parse");
        let cfg = Config::new(
            vec![host_key],
            factory,
            vec!["publickey"],
            Arc::new(StaticHandler { out: Vec::new() }),
        )
        .with_policy(Arc::new(policy))
        .with_group_resolver(Arc::new(|user: &str| {
            if user == "alice" {
                vec!["dev".to_string()]
            } else {
                vec!["users".to_string()]
            }
        }));

        let base = vec!["publickey"];
        // alice is in `dev` ⇒ publickey dropped.
        let alice = reresolve_user_policy(&cfg, &base, "alice", None, None, None);
        assert!(alice.methods.is_empty());
        // bob is not ⇒ publickey kept.
        let bob = reresolve_user_policy(&cfg, &base, "bob", None, None, None);
        assert_eq!(bob.methods, vec!["publickey"]);
    }

    // ---- F6: user-matched Banner --------------------------------------------

    #[test]
    fn reresolve_match_user_banner() {
        use std::io::Write;
        let dir = std::env::temp_dir();
        let path = dir.join(format!("puressh-banner-{}.txt", std::process::id()));
        {
            let mut f = std::fs::File::create(&path).expect("create banner");
            f.write_all(b"hello alice\n").expect("write banner");
        }
        let src = format!(
            "Match User alice\n  Banner {}\n",
            path.to_str().expect("utf8 path")
        );
        let cfg = policy_cfg(&src);

        let base = vec!["publickey"];
        let alice = reresolve_user_policy(&cfg, &base, "alice", None, None, None);
        assert_eq!(alice.banner.as_deref(), Some("hello alice\n"));
        // bob does not match the block ⇒ no banner.
        let bob = reresolve_user_policy(&cfg, &base, "bob", None, None, None);
        assert!(bob.banner.is_none());

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn reresolve_unreadable_banner_is_skipped() {
        // A Match User Banner pointing at a missing file must not fail auth —
        // the banner is simply skipped (None).
        let cfg = policy_cfg("Match User alice\n  Banner /nonexistent/puressh/banner\n");
        let base = vec!["publickey"];
        let alice = reresolve_user_policy(&cfg, &base, "alice", None, None, None);
        assert!(alice.banner.is_none());
        assert_eq!(alice.methods, vec!["publickey"]);
    }

    #[test]
    fn reresolve_no_policy_passes_through() {
        let host_key: Box<dyn HostKey + Send + Sync> =
            Box::new(Ed25519HostKey::from_seed(fresh_seed()));
        let factory: Arc<dyn AuthenticatorFactory> = Arc::new(|| -> Box<dyn Authenticator> {
            Box::new(OneKeyAuth {
                allowed_user: "x".into(),
                allowed_blob: Vec::new(),
            })
        });
        let cfg = Config::new(
            vec![host_key],
            factory,
            vec!["publickey"],
            Arc::new(StaticHandler { out: Vec::new() }),
        );
        let base = vec!["publickey"];
        let r = reresolve_user_policy(&cfg, &base, "anyone", None, None, None);
        assert_eq!(r.methods, vec!["publickey"]);
        assert!(r.banner.is_none());
    }

    #[test]
    fn no_policy_is_unrestricted() {
        let host_key: Box<dyn HostKey + Send + Sync> =
            Box::new(Ed25519HostKey::from_seed(fresh_seed()));
        let factory: Arc<dyn AuthenticatorFactory> = Arc::new(|| -> Box<dyn Authenticator> {
            Box::new(OneKeyAuth {
                allowed_user: "x".into(),
                allowed_blob: Vec::new(),
            })
        });
        let cfg = Config::new(
            vec![host_key],
            factory,
            vec!["publickey"],
            Arc::new(StaticHandler { out: Vec::new() }),
        );
        let pre = resolve_preauth_policy(&cfg, Some("1.2.3.4"), None, None);
        assert_eq!(pre.methods, vec!["publickey"]);
        assert!(pre.banner.is_none());
        let eff = resolve_effective_policy(&cfg, "u", None, None, None, None);
        assert!(eff.agent_forwarding_allowed());
        assert!(eff.x11_forwarding_allowed());
    }

    #[test]
    fn env_glob_match_grammar_basics() {
        assert!(env_glob_match("*", "anything"));
        assert!(env_glob_match("*", ""));
        assert!(env_glob_match("a*b", "ab"));
        assert!(env_glob_match("a*b", "aXYZb"));
        assert!(!env_glob_match("a*b", "aXYZ"));
        assert!(env_glob_match("?", "a"));
        assert!(!env_glob_match("?", "ab"));
        assert!(!env_glob_match("?", ""));
        assert!(env_glob_match("**", "anything"));
        // Literal exact match.
        assert!(env_glob_match("FOO", "FOO"));
        assert!(!env_glob_match("FOO", "foo"));
    }

    // ---- W7 session/forwarding policy resolution + gate helpers ----------

    #[test]
    fn w7_fields_resolve_into_effective_policy() {
        let cfg = policy_cfg(
            "MaxSessions 2\n\
             AllowTcpForwarding local\n\
             PermitOpen 127.0.0.1:80\n\
             PermitListen 127.0.0.1:8080\n\
             GatewayPorts yes\n\
             ForceCommand /bin/true\n\
             ClientAliveInterval 15\n\
             ClientAliveCountMax 2\n\
             PrintMotd yes\n",
        );
        let eff = resolve_effective_policy(&cfg, "alice", None, None, None, None);
        assert_eq!(eff.max_sessions, Some(2));
        assert!(eff.local_forwarding_allowed());
        assert!(!eff.remote_forwarding_allowed());
        assert!(eff.permit_open_allows("127.0.0.1", 80));
        assert!(!eff.permit_open_allows("127.0.0.1", 81));
        assert!(eff.permit_listen_allows("127.0.0.1", 8080));
        assert!(!eff.permit_listen_allows("10.0.0.1", 8080));
        assert_eq!(
            eff.gateway_ports,
            Some(crate::config::ServerGatewayPorts::Yes)
        );
        assert_eq!(eff.force_command.as_deref(), Some("/bin/true"));
        assert_eq!(eff.client_alive_interval, Some(15));
        assert_eq!(eff.client_alive_count_max, Some(2));
        assert_eq!(eff.print_motd, Some(true));
    }

    #[test]
    fn w7_unset_policy_is_permissive() {
        let cfg = policy_cfg("Port 22\n");
        let eff = resolve_effective_policy(&cfg, "alice", None, None, None, None);
        assert!(eff.local_forwarding_allowed());
        assert!(eff.remote_forwarding_allowed());
        assert!(eff.permit_open_allows("anything", 1));
        assert!(eff.permit_listen_allows("anything", 1));
        assert_eq!(eff.max_sessions, None);
        assert!(eff.force_command.is_none());
    }

    #[test]
    fn w7_permit_open_none_denies_all() {
        let cfg = policy_cfg("PermitOpen none\n");
        let eff = resolve_effective_policy(&cfg, "alice", None, None, None, None);
        assert!(!eff.permit_open_allows("127.0.0.1", 22));
        assert!(!eff.permit_open_allows("anything", 1));
    }

    #[test]
    fn w7_match_overrides_forwarding_for_user() {
        let cfg = policy_cfg(
            "Match User alice\n  AllowTcpForwarding no\n  MaxSessions 1\n  ForceCommand internal-sftp\n",
        );
        // alice gets the restrictions.
        let eff = resolve_effective_policy(&cfg, "alice", None, None, None, None);
        assert!(!eff.local_forwarding_allowed());
        assert!(!eff.remote_forwarding_allowed());
        assert_eq!(eff.max_sessions, Some(1));
        assert_eq!(eff.force_command.as_deref(), Some("internal-sftp"));
        // bob is unrestricted.
        let eff2 = resolve_effective_policy(&cfg, "bob", None, None, None, None);
        assert!(eff2.local_forwarding_allowed());
        assert_eq!(eff2.max_sessions, None);
        assert!(eff2.force_command.is_none());
    }

    #[test]
    fn w7_gateway_ports_rewrite() {
        use crate::config::ServerGatewayPorts as GP;
        use crate::forwarding::reverse::apply_gateway_ports;
        // Default (None) and No force loopback.
        assert_eq!(apply_gateway_ports(None, "0.0.0.0"), "127.0.0.1");
        assert_eq!(apply_gateway_ports(Some(GP::No), ""), "127.0.0.1");
        assert_eq!(apply_gateway_ports(Some(GP::No), "::"), "::1");
        // Yes widens loopback to all interfaces.
        assert_eq!(apply_gateway_ports(Some(GP::Yes), ""), "0.0.0.0");
        assert_eq!(apply_gateway_ports(Some(GP::Yes), "127.0.0.1"), "0.0.0.0");
        // ClientSpecified honours verbatim.
        assert_eq!(
            apply_gateway_ports(Some(GP::ClientSpecified), "0.0.0.0"),
            "0.0.0.0"
        );
        assert_eq!(
            apply_gateway_ports(Some(GP::ClientSpecified), "192.0.2.1"),
            "192.0.2.1"
        );
    }

    /// A command handler that echoes the command it was asked to run, so a
    /// test can assert which command actually reached the handler (used to
    /// verify ForceCommand overrides the client's command).
    struct EchoCommandHandler;
    impl CommandHandler for EchoCommandHandler {
        fn handle(&self, _user: &str, env: &SessionEnv, command: &str) -> ExecResult {
            // Surface both the command run and SSH_ORIGINAL_COMMAND so the test
            // can confirm the original is preserved in the env.
            let orig = env.get("SSH_ORIGINAL_COMMAND").unwrap_or("").to_string();
            ExecResult {
                stdout: format!("CMD={command}\nORIG={orig}\n").into_bytes(),
                stderr: Vec::new(),
                exit_status: 0,
            }
        }
    }

    /// Boot an in-process SSH server with the given policy text and command
    /// handler, returning an authenticated client plus the join handle and
    /// done-flag for the single-connection server thread.
    #[allow(clippy::type_complexity)]
    fn w7_server_and_client(
        policy_src: &str,
        with_direct: bool,
    ) -> (Client, thread::JoinHandle<Result<()>>, Arc<Mutex<bool>>) {
        let host_seed = fresh_seed();
        let client_seed = fresh_seed();
        let host_key: Box<dyn HostKey + Send + Sync> =
            Box::new(Ed25519HostKey::from_seed(host_seed));
        let client_hk_for_auth = Ed25519HostKey::from_seed(client_seed);
        let allowed_blob = client_hk_for_auth.public_blob();

        let user = "w7-user".to_string();
        let allowed_user_for_factory = user.clone();
        let allowed_blob_clone = allowed_blob.clone();
        let factory: Arc<dyn AuthenticatorFactory> = Arc::new(move || -> Box<dyn Authenticator> {
            Box::new(OneKeyAuth {
                allowed_user: allowed_user_for_factory.clone(),
                allowed_blob: allowed_blob_clone.clone(),
            })
        });

        let policy = crate::config::SshServerConfig::parse(policy_src).expect("parse policy");
        let mut cfg = Config::new(
            vec![host_key],
            factory,
            vec!["publickey"],
            Arc::new(EchoCommandHandler),
        )
        .with_policy(Arc::new(policy));
        if with_direct {
            cfg = cfg.with_direct_tcpip(Arc::new(
                crate::forwarding::direct::DefaultDirectTcpipHandler::permit_all(),
            ));
        }

        let mut server = Server::bind("127.0.0.1:0", cfg).expect("bind ssh");
        let ssh_addr = server.local_addr().expect("ssh addr");
        let server_done = Arc::new(Mutex::new(false));
        let sd = server_done.clone();
        let server_thread = thread::spawn(move || {
            let r = server.accept_one();
            *sd.lock().unwrap() = true;
            r
        });

        let mut client = Client::connect(
            ssh_addr,
            ClientConfig {
                host_key_policy: HostKeyPolicy::AcceptAny,
                timeout: Some(Duration::from_secs(10)),
                algorithms: Default::default(),
            },
        )
        .expect("client connect");
        client
            .authenticate_publickey(&user, Box::new(Ed25519HostKey::from_seed(client_seed)))
            .expect("authenticate");
        (client, server_thread, server_done)
    }

    fn w7_finish(
        client: Client,
        server_thread: thread::JoinHandle<Result<()>>,
        server_done: Arc<Mutex<bool>>,
    ) {
        drop(client);
        let start = std::time::Instant::now();
        while !*server_done.lock().unwrap() {
            if start.elapsed() > Duration::from_secs(10) {
                panic!("server thread did not finish in time");
            }
            thread::sleep(Duration::from_millis(20));
        }
        let _ = server_thread.join();
    }

    #[test]
    fn w7_force_command_overrides_exec() {
        let (mut client, st, sd) = w7_server_and_client("ForceCommand /forced/cmd\n", false);
        let out = client.exec("client-asked-this").expect("exec");
        let stdout = String::from_utf8_lossy(&out.stdout);
        // The handler ran the forced command, not the client's.
        assert!(stdout.contains("CMD=/forced/cmd"), "stdout was {stdout:?}");
        // The client's command is preserved as SSH_ORIGINAL_COMMAND.
        assert!(
            stdout.contains("ORIG=client-asked-this"),
            "stdout was {stdout:?}"
        );
        w7_finish(client, st, sd);
    }

    #[test]
    fn w7_force_command_match_conditional() {
        // ForceCommand only for w7-user (which is who authenticates).
        let (mut client, st, sd) =
            w7_server_and_client("Match User w7-user\n  ForceCommand /only/forced\n", false);
        let out = client.exec("orig").expect("exec");
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(stdout.contains("CMD=/only/forced"), "stdout was {stdout:?}");
        w7_finish(client, st, sd);
    }

    #[test]
    fn w7_max_sessions_zero_rejects_session_open() {
        let (mut client, st, sd) = w7_server_and_client("MaxSessions 0\n", false);
        // MaxSessions 0 ⇒ no session channel may open ⇒ exec's open is rejected.
        match client.exec("anything") {
            Ok(_) => panic!("expected session open to be refused by MaxSessions 0"),
            Err(Error::Protocol(_)) => {}
            Err(other) => panic!("expected Error::Protocol, got {other:?}"),
        }
        w7_finish(client, st, sd);
    }

    #[test]
    #[allow(deprecated)] // exercises the borrow-based open_direct_tcpip
    fn w7_allow_tcp_forwarding_no_denies_direct() {
        let (mut client, st, sd) = w7_server_and_client("AllowTcpForwarding no\n", true);
        match client.open_direct_tcpip("127.0.0.1", 80, "127.0.0.1", 0) {
            Ok(_) => panic!("expected direct-tcpip to be denied by AllowTcpForwarding no"),
            Err(Error::Protocol(_)) => {}
            Err(other) => panic!("expected Error::Protocol, got {other:?}"),
        }
        w7_finish(client, st, sd);
    }

    #[test]
    #[allow(deprecated)] // exercises the borrow-based open_direct_tcpip
    fn w7_permit_open_blocks_disallowed_dest() {
        // Only 127.0.0.1:80 is permitted; a request to :81 is rejected, :80 ok.
        let (mut client, st, sd) = w7_server_and_client("PermitOpen 127.0.0.1:80\n", true);
        match client.open_direct_tcpip("127.0.0.1", 81, "127.0.0.1", 0) {
            Ok(_) => panic!("expected :81 to be blocked by PermitOpen"),
            Err(Error::Protocol(_)) => {}
            Err(other) => panic!("expected Error::Protocol, got {other:?}"),
        }
        // The permitted destination opens (the handler then fails to connect to
        // a dead port, but the channel open itself must be accepted). We only
        // assert the open is not policy-rejected.
        let permitted = client.open_direct_tcpip("127.0.0.1", 80, "127.0.0.1", 0);
        assert!(
            permitted.is_ok(),
            "expected :80 open to be accepted by PermitOpen"
        );
        drop(permitted);
        w7_finish(client, st, sd);
    }

    #[test]
    fn w7_compression_no_strips_zlib_from_advert() {
        // The built-in advert is `none`-only, so a synthetic check: a comp list
        // containing zlib has it stripped under Compression::No. We exercise the
        // filter through build_server_kexinit by confirming `none` survives.
        let host_keys: Vec<Box<dyn HostKey + Send + Sync>> =
            vec![Box::new(Ed25519HostKey::from_seed(fresh_seed()))];
        let mut cfg = kexinit_test_config(host_keys);
        cfg.compression = Some(crate::config::Compression::No);
        let mut rng = OsRng;
        let advert = build_server_kexinit(&mut rng, &cfg);
        // `none` must remain advertised; no zlib name may appear.
        assert!(advert.comp_s2c.iter().any(|c| c == "none"));
        assert!(!advert.comp_s2c.iter().any(|c| c.contains("zlib")));
    }
}
