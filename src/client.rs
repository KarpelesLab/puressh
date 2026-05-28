//! High-level synchronous SSH client over `std::net::TcpStream`.
//!
//! ```ignore
//! use puressh::client::{Client, Config};
//!
//! let mut c = Client::connect("example.com:22", Config::default())?;
//! c.authenticate_password("alice", "hunter2")?;
//! let out = c.exec("uname -a")?;
//! print!("{}", String::from_utf8_lossy(&out.stdout));
//! ```

#![cfg(feature = "std")]

use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use purecrypto::hash::{Digest, Sha256};
use purecrypto::rng::{OsRng, RngCore};

use crate::auth::{ClientAuth, ClientCredential, ClientStep};
use crate::channel::{
    ChannelEvent, ChannelOpen, ChannelRequest, ConnectionState, SSH_EXTENDED_DATA_STDERR,
};
use crate::error::{Error, Result};
use crate::hostkey::{host_key_verify_by_name, HostKey, HostKeyVerify};
use crate::known_hosts::{KnownHosts, LookupResult};
use crate::sftp::SftpClient;
use crate::transport::kex::{defaults, KexAlgorithms};
use crate::transport::rekey::{is_kex_msg, RekeyPolicy};
use crate::transport::{KexInit, KexRunner, PacketCodec, Role, VersionExchange};

/// Maximum line length when reading the peer's identification banner.
const MAX_BANNER_LINE: usize = 1024;
/// Maximum number of banner lines we'll skim through before giving up.
const MAX_BANNER_LINES: usize = 256;
/// Soft cap on the inbound packet-reassembly buffer.
const MAX_INBOX_BYTES: usize = 8 * 1024 * 1024;
/// Hard cap on accumulated exec stdout+stderr.
const MAX_EXEC_OUTPUT: usize = 64 * 1024 * 1024;
/// Maximum iterations for the KEX driver loop.
const MAX_KEX_STEPS: usize = 32;
/// Maximum iterations for the userauth loop.
const MAX_AUTH_STEPS: usize = 64;
/// Maximum iterations for the exec drain loop.
const MAX_EXEC_ITER: usize = 1_000_000;

const SSH_MSG_KEX_ECDH_REPLY: u8 = 31;

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
    /// What to do when the host is *unknown* (no entry matches). `Mismatch`
    /// is always treated as a hard error regardless of this setting.
    pub on_unknown: TofuAction,
}

/// Callback type for [`TofuAction::Prompt`] — `(host, port, key_type,
/// key_blob) → accept?`.
pub type TofuPromptFn = dyn Fn(&str, u16, &str, &[u8]) -> bool + Send + Sync;

/// What to do when [`HostKeyPolicy::KnownHosts`] encounters an unknown host.
pub enum TofuAction {
    /// Refuse the connection — equivalent to OpenSSH's
    /// `StrictHostKeyChecking=yes` against an empty `known_hosts`.
    Reject,
    /// Accept silently and add the entry — equivalent to
    /// `StrictHostKeyChecking=accept-new`.
    Accept,
    /// Ask the user. See [`TofuPromptFn`] for the callback signature.
    Prompt(Arc<TofuPromptFn>),
}

/// Client configuration knobs.
pub struct Config {
    /// How to decide whether a server's host key is acceptable.
    pub host_key_policy: HostKeyPolicy,
    /// Optional per-operation socket timeout.
    pub timeout: Option<Duration>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            host_key_policy: HostKeyPolicy::AcceptAny,
            timeout: None,
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

/// A blocking SSH client.
pub struct Client {
    stream: TcpStream,
    codec: PacketCodec,
    conn: ConnectionState,
    session_id: Vec<u8>,
    inbox: Vec<u8>,
    rng: OsRng,
    /// Persistent KEX state machine, kept alive across the connection so
    /// re-keys (RFC 4253 §9) can drive a fresh handshake without dropping
    /// the codec.
    runner: KexRunner,
    /// Local and remote version strings, recorded at the start so re-keys
    /// can re-hash them without re-reading the banner.
    v_c: Vec<u8>,
    v_s: Vec<u8>,
    /// Host-key policy retained so re-key replies can be re-verified.
    host_key_policy: HostKeyPolicy,
    /// Wall-clock instant the most recent KEX completed.
    last_kex: Instant,
    /// Thresholds that trigger a re-KEX.
    rekey_policy: RekeyPolicy,
    /// App-layer payloads received while a re-KEX was in flight (RFC 4253
    /// §7.3). Drained out by `read_one_packet` ahead of new wire reads.
    deferred: Vec<Vec<u8>>,
    /// Hostname the user passed to `connect_to_host`, used for
    /// `HostKeyPolicy::KnownHosts` lookups. Empty when the client was
    /// constructed via `connect` (in which case `KnownHosts` policy
    /// degrades to AcceptAny — see [`HostKeyPolicy::KnownHosts`] docs).
    target_host: String,
    /// Port the user passed to `connect_to_host`. 0 means "not threaded
    /// in"; lookups need a non-zero port to match.
    target_port: u16,
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

        // The runner is bootstrapped inside `do_version_and_kex`; we install
        // a placeholder advert here just so the struct field is initialised
        // (it's replaced immediately).
        let mut rng = OsRng;
        let placeholder_advert = build_default_kexinit(&mut rng);
        let mut me = Self {
            stream,
            codec: PacketCodec::new(),
            conn: ConnectionState::new(),
            session_id: Vec::new(),
            inbox: Vec::new(),
            rng,
            runner: KexRunner::new(Role::Client, placeholder_advert),
            v_c: Vec::new(),
            v_s: Vec::new(),
            host_key_policy: HostKeyPolicy::AcceptAny,
            last_kex: Instant::now(),
            rekey_policy: RekeyPolicy::default(),
            deferred: Vec::new(),
            target_host: String::new(),
            target_port: 0,
        };
        me.host_key_policy = cfg.host_key_policy;
        me.do_version_and_kex()?;
        Ok(me)
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

        let mut rng = OsRng;
        let placeholder_advert = build_default_kexinit(&mut rng);
        let mut me = Self {
            stream,
            codec: PacketCodec::new(),
            conn: ConnectionState::new(),
            session_id: Vec::new(),
            inbox: Vec::new(),
            rng,
            runner: KexRunner::new(Role::Client, placeholder_advert),
            v_c: Vec::new(),
            v_s: Vec::new(),
            host_key_policy: HostKeyPolicy::AcceptAny,
            last_kex: Instant::now(),
            rekey_policy: RekeyPolicy::default(),
            deferred: Vec::new(),
            target_host: host.to_string(),
            target_port: port,
        };
        me.host_key_policy = cfg.host_key_policy;
        me.do_version_and_kex()?;
        Ok(me)
    }

    /// Try every credential in order until one succeeds or all are refused.
    pub fn authenticate(&mut self, user: &str, credentials: Vec<ClientCredential>) -> Result<()> {
        let mut auth = ClientAuth::new(user, self.session_id.clone());
        for c in credentials {
            auth.add_credential(c);
        }
        let first = auth.start();
        self.write_payload(&first)?;

        for _ in 0..MAX_AUTH_STEPS {
            let payload = self.read_one_packet()?;
            match auth.on_packet(&payload)? {
                ClientStep::Send(p) => self.write_payload(&p)?,
                ClientStep::Success => {
                    // RFC 4253 §6.2: zlib@openssh.com starts compressing here.
                    self.codec.activate_compress();
                    return Ok(());
                }
                ClientStep::Failed { .. } => return Err(Error::AuthFailed),
                ClientStep::Banner { .. } => {}
                ClientStep::Idle => {}
            }
        }
        Err(Error::Protocol("auth: too many steps without termination"))
    }

    /// Convenience: try password authentication only.
    pub fn authenticate_password(&mut self, user: &str, password: &str) -> Result<()> {
        self.authenticate(user, vec![ClientCredential::Password(password.into())])
    }

    /// Session identifier for this connection — the exchange hash `H` of the
    /// *first* key exchange (RFC 4253 §7.2). Stable across re-keys.
    pub fn session_id(&self) -> &[u8] {
        &self.session_id
    }

    /// Convenience: try publickey authentication only.
    pub fn authenticate_publickey(
        &mut self,
        user: &str,
        key: Box<dyn HostKey + Send>,
    ) -> Result<()> {
        self.authenticate(user, vec![ClientCredential::PublicKey(key)])
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
            remote_eof: false,
            local_close_sent: false,
        })
    }

    /// Block until the peer answers a single `CHANNEL_REQUEST` we sent
    /// with `want_reply = true`. Used by [`shell_with_stdin`] to gate the
    /// pty-req → shell handoff.
    ///
    /// [`shell_with_stdin`]: Self::shell_with_stdin
    fn await_request_reply(&mut self, channel: u32, what: &'static str) -> Result<()> {
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

    fn do_version_and_kex(&mut self) -> Result<()> {
        let v_c = crate::transport::version::LOCAL_VERSION.as_bytes().to_vec();
        self.stream.write_all(&VersionExchange::outgoing_bytes())?;

        let v_s = self.read_peer_version()?;
        self.v_c = v_c;
        self.v_s = v_s;

        let advert = build_default_kexinit(&mut self.rng);
        self.runner = KexRunner::new(Role::Client, advert);
        let initial = self.runner.start(&mut self.rng)?;
        for p in initial.outbound {
            self.write_payload(&p)?;
        }

        self.drive_kex_to_completion()?;
        self.session_id = self
            .runner
            .session_id()
            .ok_or(Error::Protocol("kex: missing session id"))?
            .to_vec();
        self.last_kex = Instant::now();
        Ok(())
    }

    /// Drive the KEX state machine to `Phase::Completed`. The caller is
    /// responsible for having already pushed our own KEXINIT — and, if the
    /// peer already sent theirs, for routing that first inbound message
    /// before calling this.
    ///
    /// Non-KEX packets the peer sent while it hadn't yet seen our KEXINIT
    /// are buffered into `self.deferred` and replayed by the next
    /// `read_one_packet` call.
    fn drive_kex_to_completion(&mut self) -> Result<()> {
        let mut steps = 0usize;
        loop {
            steps += 1;
            if steps > MAX_KEX_STEPS {
                return Err(Error::Protocol("kex: too many steps"));
            }
            let payload = self.read_one_raw_kex_packet()?;
            let b = *payload.first().ok_or(Error::Format("empty payload"))?;
            if is_kex_msg(b) {
                self.dispatch_kex_packet(&payload)?;
                if self.runner.is_completed() {
                    return Ok(());
                }
            } else {
                self.deferred.push(payload);
            }
        }
    }

    /// Feed one inbound transport packet that we know belongs to the KEX
    /// stream into the runner, writing any outbound packets it produces.
    fn dispatch_kex_packet(&mut self, payload: &[u8]) -> Result<()> {
        let msg = *payload.first().ok_or(Error::Format("empty kex payload"))?;
        let verifier_box;
        let verifier: Option<&dyn HostKeyVerify> = if msg == SSH_MSG_KEX_ECDH_REPLY {
            verifier_box = Some(build_verifier(
                payload,
                &self.host_key_policy,
                &self.runner,
                &self.target_host,
                self.target_port,
            )?);
            verifier_box.as_deref()
        } else {
            None
        };

        let v_c = self.v_c.clone();
        let v_s = self.v_s.clone();
        let adv = self.runner.on_packet(
            &mut self.rng,
            &mut self.codec,
            payload,
            None,
            verifier,
            &v_c,
            &v_s,
        )?;
        for p in adv.outbound {
            self.write_payload(&p)?;
        }
        Ok(())
    }

    /// Like `read_one_raw_packet` but additionally drops transport-meta
    /// (IGNORE/UNIMPLEMENTED/DEBUG) messages so callers always see a KEX or
    /// app payload next.
    fn read_one_raw_kex_packet(&mut self) -> Result<Vec<u8>> {
        loop {
            let payload = self.read_one_raw_packet()?;
            match payload.first().copied() {
                Some(1) => return Err(Error::Protocol("peer sent SSH_MSG_DISCONNECT")),
                Some(2) | Some(3) | Some(4) => continue,
                _ => return Ok(payload),
            }
        }
    }

    fn read_peer_version(&mut self) -> Result<Vec<u8>> {
        let mut buf = Vec::new();
        for _ in 0..MAX_BANNER_LINES {
            buf.clear();
            read_line(&mut self.stream, &mut buf, MAX_BANNER_LINE)?;
            if buf.starts_with(b"SSH-") {
                let parsed = VersionExchange::parse_remote(&buf)?;
                return Ok(parsed.into_bytes());
            }
        }
        Err(Error::Protocol("peer banner too long"))
    }

    fn read_one_packet(&mut self) -> Result<Vec<u8>> {
        loop {
            // Drain any app packets we buffered during a re-KEX before
            // pulling more bytes off the wire.
            if !self.runner.is_kexing() && !self.deferred.is_empty() {
                return Ok(self.deferred.remove(0));
            }

            // RFC 4253 §9: re-key once we've crossed any threshold. We only
            // initiate when no KEX is in flight; the peer's KEXINIT (handled
            // below) will trigger our half if they fire first.
            if !self.runner.is_kexing()
                && self
                    .rekey_policy
                    .should_rekey(&self.codec, self.last_kex, Instant::now())
            {
                self.initiate_rekey()?;
            }

            let payload = self.read_one_raw_packet()?;
            match payload.first().copied() {
                // SSH_MSG_DISCONNECT — peer initiated.
                Some(1) => return Err(Error::Protocol("peer sent SSH_MSG_DISCONNECT")),
                // SSH_MSG_IGNORE, SSH_MSG_UNIMPLEMENTED, SSH_MSG_DEBUG — drop.
                Some(2) | Some(3) | Some(4) => continue,
                // KEX messages route through the runner. A SSH_MSG_KEXINIT
                // (20) while we're not already KEXing is a peer-initiated
                // re-KEX — we must answer with our own KEXINIT first.
                Some(b) if is_kex_msg(b) => {
                    if b == 20 && !self.runner.is_kexing() {
                        self.initiate_rekey()?;
                    }
                    self.dispatch_kex_packet(&payload)?;
                    if !self.runner.is_completed() {
                        self.drive_kex_to_completion()?;
                    }
                    self.last_kex = Instant::now();
                    continue;
                }
                _ => {
                    // RFC 4253 §7.3: app traffic during a re-KEX must be
                    // buffered until NEWKEYS lands. Keep reading until we
                    // have a non-KEX, non-rekeying packet to return.
                    if self.runner.is_kexing() {
                        self.deferred.push(payload);
                        continue;
                    }
                    return Ok(payload);
                }
            }
        }
    }

    /// Send our own SSH_MSG_KEXINIT to start a re-KEX. Caller must ensure
    /// the runner is currently in `Phase::Completed`.
    fn initiate_rekey(&mut self) -> Result<()> {
        let advert = build_default_kexinit(&mut self.rng);
        let adv = self.runner.restart(&mut self.rng, advert)?;
        for p in adv.outbound {
            self.write_payload(&p)?;
        }
        Ok(())
    }

    fn read_one_raw_packet(&mut self) -> Result<Vec<u8>> {
        loop {
            if let Some((payload, consumed)) = self.codec.decode(&self.inbox)? {
                self.inbox.drain(..consumed);
                return Ok(payload);
            }
            let mut tmp = [0u8; 16 * 1024];
            let n = self.stream.read(&mut tmp)?;
            if n == 0 {
                return Err(Error::Protocol("connection closed"));
            }
            self.inbox.extend_from_slice(&tmp[..n]);
            if self.inbox.len() > MAX_INBOX_BYTES {
                return Err(Error::Protocol("inbound buffer too large"));
            }
        }
    }

    fn write_payload(&mut self, payload: &[u8]) -> Result<()> {
        let frame = self.codec.encode(payload, &mut self.rng)?;
        self.stream.write_all(&frame)?;
        Ok(())
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
pub struct ClientChannelStream<'a> {
    client: &'a mut Client,
    channel: u32,
    read_buf: Vec<u8>,
    remote_eof: bool,
    local_close_sent: bool,
}

impl ClientChannelStream<'_> {
    /// Drive the SSH packet loop until either `read_buf` has bytes available
    /// or the peer closes the channel. Window-adjust packets are handled
    /// transparently; extended-data is treated as stdout (subsystems
    /// shouldn't emit stderr, but tolerate it).
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

fn io_err(e: Error) -> std::io::Error {
    match e {
        Error::Io(io) => io,
        other => std::io::Error::other(format!("{:?}", other)),
    }
}

fn build_default_kexinit<R: RngCore>(rng: &mut R) -> KexInit {
    let algs = KexAlgorithms {
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
    };
    let mut cookie = [0u8; 16];
    rng.fill_bytes(&mut cookie);
    KexInit::from_algorithms(&algs, cookie)
}

fn build_verifier(
    reply_payload: &[u8],
    policy: &HostKeyPolicy,
    runner: &KexRunner,
    target_host: &str,
    target_port: u16,
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

    let neg = runner
        .negotiated()
        .ok_or(Error::Protocol("kex: no negotiated algorithms"))?;

    match policy {
        HostKeyPolicy::AcceptAny => {}
        HostKeyPolicy::AcceptFingerprint(fp) => {
            let digest = Sha256::digest(k_s);
            if digest.as_ref() != fp {
                return Err(Error::HostKeyRejected);
            }
        }
        HostKeyPolicy::KnownHosts(kh) => {
            // No host was threaded in (caller used `connect` not
            // `connect_to_host`). We cannot do a lookup; fall through to
            // AcceptAny rather than fail hard, matching the documented
            // contract of `HostKeyPolicy::KnownHosts`.
            if target_host.is_empty() || target_port == 0 {
                // Intentionally silent — the docs on the variant explain
                // the degradation.
            } else {
                let mut store = kh.store.lock().map_err(|_| Error::HostKeyRejected)?;
                let lookup = store.lookup(target_host, target_port, &neg.host_key, k_s);
                match lookup {
                    LookupResult::Match => {}
                    LookupResult::Mismatch { .. } => {
                        return Err(Error::HostKeyRejected);
                    }
                    LookupResult::Unknown => {
                        let accept = match &kh.on_unknown {
                            TofuAction::Reject => false,
                            TofuAction::Accept => true,
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
    }

    host_key_verify_by_name(&neg.host_key, k_s)
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hostkey::Ed25519HostKey;
    use crate::transport::version::LOCAL_VERSION;
    use std::io::{Cursor, Read, Write};
    use std::net::TcpListener;
    use std::thread;

    #[test]
    fn read_line_caps_length() {
        let mut buf = Vec::new();
        let mut src = Cursor::new(vec![b'A'; 4096]);
        let err = read_line(&mut src, &mut buf, 1024);
        assert!(matches!(err, Err(Error::Protocol(_))));
    }

    #[test]
    fn read_line_returns_at_newline() {
        let mut buf = Vec::new();
        let mut src = Cursor::new(b"hello\r\n".to_vec());
        read_line(&mut src, &mut buf, 1024).unwrap();
        assert_eq!(buf, b"hello\r\n");
    }

    #[test]
    fn config_default_is_accept_any() {
        let cfg = Config::default();
        assert!(matches!(cfg.host_key_policy, HostKeyPolicy::AcceptAny));
        assert!(cfg.timeout.is_none());
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
            let advert = build_default_kexinit(&mut OsRng);
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

        let client = Client::connect(addr, Config::default()).expect("client connect");
        let server_sid = server.join().unwrap().expect("server handshake");
        assert_eq!(client.session_id, server_sid);
        assert!(!client.session_id.is_empty());
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
        };
        let err = Client::connect(addr, cfg).err().expect("must fail");
        assert!(matches!(err, Error::HostKeyRejected));
        // The server thread may have errored after our connect dropped — that's fine.
        let _ = server.join();
    }
}
