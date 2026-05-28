//! High-level blocking SSH server over `std::net::TcpListener`.
//!
//! ```ignore
//! use std::sync::Arc;
//! use puressh::server::{Server, Config, CommandHandler, ExecResult};
//!
//! struct H;
//! impl CommandHandler for H {
//!     fn handle(&self, _user: &str, _cmd: &str) -> ExecResult {
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

use std::collections::BTreeMap;
use std::io::{ErrorKind, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::sync::mpsc::{self, Receiver, Sender, SyncSender, TryRecvError};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use purecrypto::rng::{CryptoRng, OsRng, RngCore};

use crate::auth::{Authenticator, ServerAuth, ServerStep};
use crate::channel::{
    ChannelEvent, ChannelOpen, ChannelRequest, ConnectionState, SSH_EXTENDED_DATA_STDERR,
    SSH_OPEN_ADMINISTRATIVELY_PROHIBITED,
};
use crate::error::{Error, Result};
use crate::format::Writer;
use crate::hostkey::HostKey;
use crate::transport::kex::{defaults, KexAlgorithms};
use crate::transport::rekey::{is_kex_msg, RekeyPolicy};
use crate::transport::{KexInit, KexRunner, PacketCodec, Role, VersionExchange};

const MAX_BANNER_LINE: usize = 1024;
const MAX_BANNER_LINES: usize = 256;
const MAX_INBOX_BYTES: usize = 8 * 1024 * 1024;
const MAX_KEX_STEPS: usize = 32;
const MAX_AUTH_STEPS: usize = 64;
const MAX_CONNECTION_STEPS: usize = 10_000_000;
const MAX_DRAIN_STEPS: usize = 1_000_000;

/// Bound on the per-subsystem egress queue. Handlers self-throttle when
/// the dispatcher can't ship `CHANNEL_DATA` fast enough (remote window
/// exhausted).
const SUBSYSTEM_EGRESS_BACKLOG: usize = 32;

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

/// Server-side hook called when a client sends a `"exec"` channel request.
pub trait CommandHandler: Send + Sync {
    /// Run `command` on behalf of `user` and return its full output and exit
    /// code. Called inside the per-connection thread.
    fn handle(&self, user: &str, command: &str) -> ExecResult;
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
    /// what `ssh -T` triggers.
    fn spawn(&self, user: &str, pty: Option<PtySpec>) -> Result<Box<dyn ShellSession>>;
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

/// Outbound message a [`SubsystemHandler`] sends through its [`ChannelStream`].
///
/// The connection dispatcher serializes these onto the wire as
/// `CHANNEL_DATA` / `CHANNEL_EOF` / `CHANNEL_CLOSE` packets. Handlers don't
/// emit `ChannelEgress` directly — they just use `Read`/`Write` on the
/// stream, and the EOF / Close pair is sent automatically when the stream
/// drops.
pub enum ChannelEgress {
    /// Bytes destined for `CHANNEL_DATA`.
    Data(Vec<u8>),
    /// `CHANNEL_EOF`.
    Eof,
    /// `CHANNEL_CLOSE`.
    Close,
}

/// Bidirectional view of an SSH channel for use by [`SubsystemHandler`]s.
///
/// Behaviour:
/// - [`Read::read`] blocks until the peer sends `CHANNEL_DATA` or `EOF`
///   (returns `Ok(0)`).
/// - [`Write::write`] enqueues data for the dispatcher to ship; backpressure
///   comes from a bounded mpsc — if the remote window is full the dispatcher
///   stops draining and the next write blocks the handler thread.
/// - On drop the stream sends `CHANNEL_EOF` followed by `CHANNEL_CLOSE`
///   (best-effort — silently ignored if the channel is already gone).
pub struct ChannelStream {
    /// `None` after [`Self::into_raw`] has moved it out. The matching `tx`
    /// will also be `None`, so [`Self::drop`] is a no-op.
    rx: Option<Receiver<Option<Vec<u8>>>>,
    tx: Option<SyncSender<ChannelEgress>>,
    buf: Vec<u8>,
    rx_eof: bool,
}

impl ChannelStream {
    /// Used by the server dispatcher; not for user code.
    pub(crate) fn new(rx: Receiver<Option<Vec<u8>>>, tx: SyncSender<ChannelEgress>) -> Self {
        Self {
            rx: Some(rx),
            tx: Some(tx),
            buf: Vec::new(),
            rx_eof: false,
        }
    }

    /// Send an explicit EOF marker. Subsequent writes still succeed (per
    /// RFC 4254 EOF is one-directional). Most handlers don't need this —
    /// EOF and Close are sent automatically when the stream drops.
    pub fn send_eof(&mut self) -> std::io::Result<()> {
        let tx = self
            .tx
            .as_ref()
            .ok_or_else(|| std::io::Error::new(ErrorKind::BrokenPipe, "channel closed"))?;
        tx.send(ChannelEgress::Eof)
            .map_err(|_| std::io::Error::new(ErrorKind::BrokenPipe, "channel closed"))
    }

    /// Decompose the stream into raw mpsc handles so callers can drive
    /// each direction from a separate thread.
    ///
    /// - The first return is the **ingress** receiver: bytes from the peer
    ///   arrive as `Some(chunk)`, EOF arrives as `None`, and the dispatcher
    ///   tearing the channel down closes the channel (returning `Err`).
    /// - The second return is the **egress** sender. Send `Data(_)` to
    ///   ship `CHANNEL_DATA`, then `Eof` and `Close` to tear the channel
    ///   down cleanly.
    ///
    /// Unlike [`Read`]/[`Write`] on `ChannelStream`, the auto-EOF + auto-
    /// Close on drop is **suppressed** — the caller takes responsibility
    /// for sending those markers (typically once both copy loops finish).
    /// This is the right primitive for splice-style proxying like
    /// [`crate::forwarding::direct::DefaultDirectTcpipHandler`].
    pub fn into_raw(mut self) -> (Receiver<Option<Vec<u8>>>, SyncSender<ChannelEgress>) {
        let rx = self
            .rx
            .take()
            .expect("ChannelStream::into_raw called twice");
        let tx = self
            .tx
            .take()
            .expect("ChannelStream::into_raw called twice");
        (rx, tx)
    }
}

impl Read for ChannelStream {
    fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
        if !self.buf.is_empty() {
            let n = out.len().min(self.buf.len());
            out[..n].copy_from_slice(&self.buf[..n]);
            self.buf.drain(..n);
            return Ok(n);
        }
        if self.rx_eof {
            return Ok(0);
        }
        let rx = self
            .rx
            .as_ref()
            .ok_or_else(|| std::io::Error::new(ErrorKind::BrokenPipe, "channel taken"))?;
        match rx.recv() {
            Ok(Some(chunk)) => {
                self.buf = chunk;
                self.read(out)
            }
            Ok(None) | Err(_) => {
                self.rx_eof = true;
                Ok(0)
            }
        }
    }
}

impl Write for ChannelStream {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        let tx = self
            .tx
            .as_ref()
            .ok_or_else(|| std::io::Error::new(ErrorKind::BrokenPipe, "channel taken"))?;
        // Cap chunks to keep per-packet payloads sane; the dispatcher will
        // split further if the remote channel-max-packet is smaller.
        let take = data.len().min(32 * 1024);
        let chunk = data[..take].to_vec();
        tx.send(ChannelEgress::Data(chunk))
            .map_err(|_| std::io::Error::new(ErrorKind::BrokenPipe, "channel closed"))?;
        Ok(take)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Drop for ChannelStream {
    fn drop(&mut self) {
        // Best-effort: ignore failures if the channel was already torn down.
        // After `into_raw` both `tx` and `rx` are None and this is a no-op.
        if let Some(tx) = self.tx.take() {
            let _ = tx.send(ChannelEgress::Eof);
            let _ = tx.send(ChannelEgress::Close);
        }
    }
}

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

/// Callback type for [`Config::on_session_open`].
pub type SessionOpenCallback = Arc<dyn Fn(&str) -> Result<()> + Send + Sync>;

/// Server-side hook called when a client sends a `"subsystem"` channel
/// request (e.g. `"sftp"`).
///
/// Implementations get a [`ChannelStream`] they can treat as a normal
/// `Read+Write` and run their protocol loop on. The handler runs on a
/// dedicated thread per channel so blocking reads don't stall the rest of
/// the connection. Return `Ok(())` to close the channel gracefully — the
/// dispatcher emits EOF + Close when the stream drops.
pub trait SubsystemHandler: Send + Sync {
    /// Run subsystem `name` on behalf of `user` over `stream`.
    fn handle(&self, user: &str, name: &str, stream: ChannelStream) -> Result<()>;
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

/// Server configuration: host keys, authentication, and the exec hook.
pub struct Config {
    /// Host keys the server presents and signs the KEX with. At least one
    /// required.
    pub host_keys: Vec<Box<dyn HostKey + Send + Sync>>,
    /// User-authentication policy.
    pub authenticator: Arc<dyn AuthenticatorFactory>,
    /// Auth methods advertised in `USERAUTH_FAILURE`.
    pub allowed_auth_methods: Vec<&'static str>,
    /// Command handler invoked on `"exec"` channel requests.
    pub command_handler: Arc<dyn CommandHandler>,
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
    /// Optional callback invoked once per connection, after authentication
    /// has succeeded but before any channel request is processed. Returning
    /// `Err` aborts the connection. Typical use: drop privileges (setgid /
    /// initgroups / setuid) to `user` so all subsequent shell / exec /
    /// subsystem code runs as the authenticated user.
    pub on_session_open: Option<SessionOpenCallback>,
    /// Thresholds that trigger a re-key (RFC 4253 §9). Defaults to 1 GiB /
    /// 1 hour / `1u32 << 31` packets per direction.
    pub rekey_policy: RekeyPolicy,
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
            shell_handler: None,
            subsystem_handler: None,
            direct_tcpip_handler: None,
            on_session_open: None,
            rekey_policy: RekeyPolicy::default(),
        }
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

    /// Attach a `DirectTcpipHandler`. Without one, all `direct-tcpip`
    /// channel opens (i.e. `ssh -L`) are rejected with
    /// `SSH_OPEN_ADMINISTRATIVELY_PROHIBITED`.
    pub fn with_direct_tcpip(mut self, handler: Arc<dyn DirectTcpipHandler>) -> Self {
        self.direct_tcpip_handler = Some(handler);
        self
    }

    /// Register a callback fired once per connection between
    /// `userauth_success` and the channel loop. Use this to drop privileges
    /// to the authenticated user. Returning `Err` aborts the connection.
    pub fn on_session_open<F>(mut self, f: F) -> Self
    where
        F: Fn(&str) -> Result<()> + Send + Sync + 'static,
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
        let (stream, _peer) = self.listener.accept()?;
        handle_session(stream, self.cfg.clone())
    }

    /// Accept connections forever, spawning a fresh thread per connection.
    pub fn serve(&mut self) -> Result<()> {
        loop {
            let (stream, _peer) = self.listener.accept()?;
            let cfg = self.cfg.clone();
            thread::spawn(move || {
                let _ = handle_session(stream, cfg);
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
    handle_connection_inner(stream, cfg)
}

fn handle_connection_inner(mut stream: TcpStream, cfg: Arc<Config>) -> Result<()> {
    stream.set_nodelay(true)?;

    let mut codec = PacketCodec::new();
    let mut inbox: Vec<u8> = Vec::new();
    let mut rng = OsRng;

    let v_s = crate::transport::version::LOCAL_VERSION.as_bytes().to_vec();
    stream.write_all(&VersionExchange::outgoing_bytes())?;
    let v_c = read_peer_version(&mut stream)?;

    let (mut runner, session_id) = do_server_kex(
        &mut stream,
        &mut codec,
        &mut rng,
        &mut inbox,
        &cfg,
        &v_c,
        &v_s,
    )?;
    let mut last_kex = Instant::now();

    let user = do_server_auth(
        &mut stream,
        &mut codec,
        &mut rng,
        &mut inbox,
        &cfg,
        session_id,
    )?;

    // Connection-level hook: drop privileges to the authenticated user
    // before any shell / exec / subsystem runs. After this call all I/O on
    // this connection happens as `user`, including the in-process SFTP
    // subsystem and any forked exec children.
    if let Some(hook) = cfg.on_session_open.clone() {
        hook(&user)?;
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
    let advert = build_server_kexinit(rng, &cfg.host_keys);
    let mut runner = KexRunner::new(Role::Server, advert);
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

        if selected_host_key.is_none() {
            if let Some(neg) = runner.negotiated() {
                selected_host_key = pick_host_key(&cfg.host_keys, &neg.host_key);
                if selected_host_key.is_none() {
                    return Err(Error::Protocol("kex: no host key for negotiated algorithm"));
                }
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

fn do_server_auth<R: RngCore + CryptoRng>(
    stream: &mut TcpStream,
    codec: &mut PacketCodec,
    rng: &mut R,
    inbox: &mut Vec<u8>,
    cfg: &Config,
    session_id: Vec<u8>,
) -> Result<String> {
    let methods = cfg.allowed_auth_methods.clone();
    let auth_impl = cfg.authenticator.build();
    let mut server_auth = ServerAuth::new(session_id, methods, auth_impl);

    for _ in 0..MAX_AUTH_STEPS {
        let payload = read_one_packet(stream, codec, inbox)?;
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
    let mut polling_active = false;

    loop {
        steps += 1;
        if steps > MAX_CONNECTION_STEPS {
            return Err(Error::Protocol("connection: step cap exceeded"));
        }

        // Drain any application packets we couldn't process while re-KEXing.
        if !runner.is_kexing() && !deferred.is_empty() {
            let payload = deferred.remove(0);
            dispatch_app_packet(
                stream,
                codec,
                rng,
                inbox,
                &mut conn,
                cfg,
                user,
                &payload,
                &mut any_channel_opened,
                &mut shells,
                &mut subsystems,
            )?;
            continue;
        }

        // Shells and subsystems become "interesting" the moment one is
        // registered: switch the socket to a 50 ms read timeout so we can
        // interleave their I/O with packet reads. Revert when both maps
        // go quiet.
        let any_shell_alive = shells.values().any(|rt| rt.session.is_some());
        let any_subsystem_alive = !subsystems.is_empty();
        let want_polling = any_shell_alive || any_subsystem_alive;
        if want_polling && !polling_active {
            let _ = stream.set_read_timeout(Some(Duration::from_millis(50)));
            polling_active = true;
        } else if !want_polling && polling_active {
            let _ = stream.set_read_timeout(None);
            polling_active = false;
        }

        // Drain shell stdout into CHANNEL_DATA, then send exit/EOF/CLOSE
        // for any shell that has finished. Only when no KEX is in flight.
        if polling_active && !runner.is_kexing() {
            drain_shells(stream, codec, rng, &mut conn, &mut shells)?;
            finalize_exited_shells(stream, codec, rng, &mut conn, &mut shells)?;
            drain_subsystems(stream, codec, rng, &mut conn, &mut subsystems)?;
        }

        if any_channel_opened
            && !conn.channels().any(|c| !c.is_fully_closed())
            && deferred.is_empty()
        {
            return Ok(());
        }

        // RFC 4253 §9: re-key once we've crossed any threshold. Only initiate
        // when no KEX is currently in flight (one side starts; the other will
        // respond when it sees the SSH_MSG_KEXINIT).
        if !runner.is_kexing() && rekey_policy.should_rekey(codec, *last_kex, Instant::now()) {
            let advert = build_server_kexinit(rng, &cfg.host_keys);
            let adv = runner.restart(rng, advert)?;
            for p in adv.outbound {
                write_payload(stream, codec, rng, &p)?;
            }
        }

        let payload = if polling_active {
            match read_one_packet_maybe_timeout(stream, codec, inbox)? {
                Some(p) => p,
                None => continue, // 50 ms tick; re-enter drain/rekey checks
            }
        } else {
            read_one_packet(stream, codec, inbox)?
        };

        // RFC 4253 §7.3: KEX messages (20, 21, 30..=49) are routed through
        // the KEX runner, not the application layer. A peer-initiated re-KEX
        // is signalled by an inbound SSH_MSG_KEXINIT while we are still in
        // Phase::Completed — handle that by emitting our own KEXINIT first.
        let msg = payload.first().copied().unwrap_or(0);
        if is_kex_msg(msg) {
            if msg == 20 && !runner.is_kexing() {
                let advert = build_server_kexinit(rng, &cfg.host_keys);
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
        // must NOT respond with channel traffic — buffer for later.
        if runner.is_kexing() {
            deferred.push(payload);
            continue;
        }

        dispatch_app_packet(
            stream,
            codec,
            rng,
            inbox,
            &mut conn,
            cfg,
            user,
            &payload,
            &mut any_channel_opened,
            &mut shells,
            &mut subsystems,
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
        let mut pulled = 0usize;
        while pulled < 64 * 1024 {
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
        if rt.exited.is_none() {
            if let Some(sess) = rt.session.as_mut() {
                if let Some(status) = sess.try_exit() {
                    rt.exited = Some(status);
                }
            }
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
    user: &str,
    payload: &[u8],
    any_channel_opened: &mut bool,
    shells: &mut BTreeMap<u32, ShellRuntime>,
    subsystems: &mut BTreeMap<u32, SubsystemRuntime>,
) -> Result<()> {
    let ev = conn.on_packet(payload)?;
    match ev {
        ChannelEvent::OpenRequest { channel, kind } => match kind {
            ChannelOpen::Session => {
                *any_channel_opened = true;
                let p = conn.accept_open(channel)?;
                write_payload(stream, codec, rng, &p)?;
            }
            ChannelOpen::DirectTcpip {
                dest_host,
                dest_port,
                orig_host,
                orig_port,
            } => {
                if let Some(handler) = cfg.direct_tcpip_handler.clone() {
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
                stream, codec, rng, inbox, conn, cfg, user, channel, request, want_reply, shells,
                subsystems,
            )?;
        }
        ChannelEvent::Data { channel, data } => {
            // Forward stdin into the shell, if one is active on this channel.
            // EAGAIN-equivalent (`Ok(0)`) just drops the byte for this tick;
            // a well-behaved client retries by sending more stdin later. A
            // hard write error tears the session down.
            if let Some(rt) = shells.get_mut(&channel) {
                if let Some(sess) = rt.session.as_mut() {
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
            if let Some(rt) = shells.get_mut(&channel) {
                if let Some(sess) = rt.session.as_mut() {
                    let _ = sess.close_stdin();
                }
            }
            if let Some(rt) = subsystems.get_mut(&channel) {
                // None = EOF marker; the handler's `Read::read` returns
                // `Ok(0)` next time it drains its buffer.
                let _ = rt.ingress_tx.send(None);
            }
        }
        ChannelEvent::Close { channel } => {
            if let Some(ch) = conn.channel(channel) {
                if !ch.local_closed {
                    let p = conn.send_close(channel)?;
                    write_payload(stream, codec, rng, &p)?;
                }
            }
            // Drop the runtime so the backend can reap its child / close fds.
            shells.remove(&channel);
            // Dropping the SubsystemRuntime closes `ingress_tx`; the handler
            // thread's next `Read` returns `Ok(0)` and the thread exits.
            subsystems.remove(&channel);
        }
        ChannelEvent::WindowAdjust { .. } => {}
        ChannelEvent::GlobalRequest { want_reply, .. } if want_reply => {
            let p = conn.send_global_failure();
            write_payload(stream, codec, rng, &p)?;
        }
        _ => {}
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
    user: &str,
    channel: u32,
    request: ChannelRequest,
    want_reply: bool,
    shells: &mut BTreeMap<u32, ShellRuntime>,
    subsystems: &mut BTreeMap<u32, SubsystemRuntime>,
) -> Result<()> {
    match request {
        ChannelRequest::Exec { command } => {
            let result = cfg.command_handler.handle(user, &command);
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
            if let Some(handler) = cfg.shell_handler.clone() {
                let rt = shells.entry(channel).or_insert_with(ShellRuntime::new);
                let pty = rt.pending_pty.take();
                match handler.spawn(user, pty) {
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
            if let Some(rt) = shells.get_mut(&channel) {
                if let Some(sess) = rt.session.as_mut() {
                    let _ = sess.resize(cols, rows, px_w, px_h);
                }
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
                thread::spawn(move || {
                    // Errors from the handler are swallowed: the stream
                    // drops on return, which auto-emits EOF + Close so the
                    // peer sees a clean teardown.
                    let _ = handler.handle(&user_owned, &name_owned, cs);
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

fn build_server_kexinit<R: RngCore>(
    rng: &mut R,
    host_keys: &[Box<dyn HostKey + Send + Sync>],
) -> KexInit {
    // Filter advertised host-key algorithms to only those we can actually
    // produce signatures for. Preserve the default order for predictability.
    let mut have: Vec<&'static str> = Vec::new();
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
    if have.is_empty() {
        have.push("ssh-ed25519");
    }

    let algs = KexAlgorithms {
        kex: defaults::KEX,
        server_host_key: &have,
        ciphers_c2s: defaults::CIPHERS,
        ciphers_s2c: defaults::CIPHERS,
        macs_c2s: defaults::MACS,
        macs_s2c: defaults::MACS,
        comp_c2s: defaults::COMP,
        comp_s2c: defaults::COMP,
        lang_c2s: &[],
        lang_s2c: &[],
    };
    let mut cookie = [0u8; 16];
    rng.fill_bytes(&mut cookie);
    KexInit::from_algorithms(&algs, cookie)
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

    struct StaticHandler {
        out: Vec<u8>,
    }

    impl CommandHandler for StaticHandler {
        fn handle(&self, _user: &str, _command: &str) -> ExecResult {
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
        fn spawn(&self, user: &str, pty: Option<PtySpec>) -> Result<Box<dyn ShellSession>> {
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
            if st.closed_stdin && st.stdout.is_empty() {
                if let Some(s) = st.exit_on_stdin_close.take() {
                    return Some(s);
                }
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
        let advert = build_server_kexinit(&mut rng, &host_keys);
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
        fn handle(&self, user: &str, name: &str, mut stream: ChannelStream) -> Result<()> {
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
    struct SftpSubsystem {
        cwd: std::path::PathBuf,
        root: std::path::PathBuf,
    }

    impl SubsystemHandler for SftpSubsystem {
        fn handle(&self, _user: &str, name: &str, stream: ChannelStream) -> Result<()> {
            if name != "sftp" {
                return Ok(());
            }
            let opts =
                crate::sftp::SftpServerOptions::new(self.cwd.clone()).with_root(self.root.clone());
            let mut sess = crate::sftp::SftpServerSession::new(opts);
            // SftpError → Result is best-effort; drop the stream on return so
            // the dispatcher emits EOF+CLOSE to the peer.
            let _ = sess.run(stream);
            Ok(())
        }
    }

    /// pid + nanosecond timestamp gives a unique directory across parallel
    /// `cargo test` workers without pulling in a tempfile dep — mirrors the
    /// pattern in `src/sftp/tests.rs`.
    struct SftpTempDir(std::path::PathBuf);

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
    impl Drop for SftpTempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

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
            },
        )
        .expect("client connect");

        let client_hk: Box<dyn HostKey + Send> = Box::new(Ed25519HostKey::from_seed(client_seed));
        client
            .authenticate_publickey(&user, client_hk)
            .expect("authenticate");

        {
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
}
