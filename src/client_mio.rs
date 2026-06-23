//! Native readiness-driven SSH client frontend (feature `mio`).
//!
//! [`MioClient`] drives the same sans-IO [`ClientDriver`] as the blocking
//! [`Client`](crate::client::Client) and the async
//! [`AsyncClient`](crate::client_async::AsyncClient), but in the
//! *readiness / non-blocking* style that suits a `mio`-driven event loop:
//! there is no `async`/`await` and no blocking. The caller owns the `Poll`,
//! registers the stream, and calls [`pump_readable`](MioClient::pump_readable) /
//! [`pump_writable`](MioClient::pump_writable) when the corresponding readiness
//! fires; the client advances its handshake → auth → exec state machine and
//! surfaces [`MioEvent`]s for the caller to react to.
//!
//! It is generic over any `std::io::Read + Write` whose `WouldBlock` signals
//! "not ready" — exactly the contract of `mio::net::TcpStream` — so the
//! library itself takes **no dependency on `mio`**. The crate is named in the
//! feature only because that is the canonical event loop you would pair it with.
//!
//! ```ignore
//! let mut poll = mio::Poll::new()?;
//! let mut sock = mio::net::TcpStream::connect(addr)?;
//! poll.registry().register(&mut sock, TOK, Interest::READABLE | Interest::WRITABLE)?;
//! let mut client = MioClient::new(sock, "host", 22, Config::insecure())?;
//! loop {
//!     poll.poll(&mut events, None)?; // or a timeout derived from client.next_timeout()
//!     for ev in &events {
//!         if ev.is_writable() { client.pump_writable()?; }
//!         if ev.is_readable() { client.pump_readable()?; }
//!     }
//!     while let Some(e) = client.poll_event() {
//!         match e {
//!             MioEvent::HandshakeComplete => client.authenticate_password("alice", "pw")?,
//!             MioEvent::Authenticated => client.exec("uname -a")?,
//!             MioEvent::Data { data, .. } => out.extend_from_slice(&data),
//!             MioEvent::ExecClosed => return Ok(out),
//!             _ => {}
//!         }
//!     }
//!     // Re-register for WRITABLE only while there is buffered output:
//!     reregister(&mut sock, client.wants_write());
//! }
//! ```

#![cfg(feature = "mio")]

use alloc::boxed::Box;
use alloc::collections::VecDeque;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use std::io::{ErrorKind, Read, Write};
use std::time::Instant;

use crate::auth::{ClientAuth, ClientCredential, ClientStep};
use crate::channel::{
    ChannelEvent, ChannelOpen, ChannelRequest, ConnectionState, SSH_EXTENDED_DATA_STDERR,
};
use crate::client::{AlgoOverrides, Config, build_verifier, unix_now};
use crate::driver::client::VerifierFactory;
use crate::driver::{ClientDriver, Event};
use crate::error::{Error, Result};
use crate::hostkey::HostKey;

const READ_CHUNK: usize = 16 * 1024;

/// An event surfaced by [`MioClient::poll_event`].
///
/// The caller drives the connection by reacting to these — e.g. authenticating
/// on [`HandshakeComplete`](MioEvent::HandshakeComplete), running a command on
/// [`Authenticated`](MioEvent::Authenticated), and collecting output from
/// [`Data`](MioEvent::Data) until [`ExecClosed`](MioEvent::ExecClosed).
#[derive(Debug, Clone)]
pub enum MioEvent {
    /// Transport handshake (version exchange + first key exchange) completed;
    /// ready for [`authenticate`](MioClient::authenticate).
    HandshakeComplete,
    /// Userauth succeeded; ready for [`exec`](MioClient::exec).
    Authenticated,
    /// Userauth exhausted all credentials without success.
    AuthFailed,
    /// A chunk of channel output. `stderr` distinguishes `SSH_MSG_CHANNEL_DATA`
    /// (`false`) from `extended-data` of type stderr (`true`).
    Data {
        /// Whether this is stderr (extended data) rather than stdout.
        stderr: bool,
        /// The bytes received.
        data: Vec<u8>,
    },
    /// The remote reported the command's exit status.
    ExitStatus(u32),
    /// The exec channel fully closed; the client is back to the authenticated
    /// state and another [`exec`](MioClient::exec) may be issued.
    ExecClosed,
    /// The peer closed the transport.
    Disconnected,
}

#[derive(Default)]
struct ExecState {
    channel: u32,
    command: String,
    /// Remote sent `CHANNEL_CLOSE`.
    remote_closed: bool,
    /// We sent `CHANNEL_CLOSE`.
    close_sent: bool,
    /// We forwarded the remote EOF with our own EOF.
    eof_sent: bool,
}

impl ExecState {
    fn new(channel: u32, command: String) -> Self {
        Self {
            channel,
            command,
            ..Default::default()
        }
    }
    fn finished(&self) -> bool {
        self.remote_closed && self.close_sent
    }
}

/// Connection phase. Owns the in-flight `ClientAuth` / `ExecState` so the state
/// machine can be re-entered on each readiness event.
enum Phase {
    Handshaking,
    Ready,
    Authenticating(ClientAuth),
    Authenticated,
    Exec(ExecState),
    Failed,
    Done,
}

/// A non-blocking, readiness-driven SSH client over a caller-supplied
/// `std::io::Read + Write` stream (typically `mio::net::TcpStream`).
///
/// Single-channel: one [`exec`](Self::exec) at a time. The caller owns the I/O
/// readiness loop; this type never blocks and never touches a socket beyond the
/// `Read`/`Write` it was handed.
pub struct MioClient<S> {
    stream: S,
    driver: ClientDriver,
    conn: ConnectionState,
    algo_overrides: AlgoOverrides,
    phase: Phase,
    events: VecDeque<MioEvent>,
    /// Buffered outbound bytes not yet accepted by the socket (partial writes /
    /// `WouldBlock`). `out_pos` is the unflushed offset.
    outbuf: Vec<u8>,
    out_pos: usize,
}

impl<S: Read + Write> MioClient<S> {
    /// Wrap an already-connected (or in-progress, non-blocking) `stream` and
    /// begin the SSH handshake. `host`/`port` name the target for host-key
    /// verification. No I/O blocks: outbound bytes are buffered until the first
    /// [`pump_writable`](Self::pump_writable).
    pub fn new(stream: S, host: &str, port: u16, cfg: Config) -> Result<Self> {
        let host_key_policy = cfg.host_key_policy;
        let target_host = host.to_string();
        let ca_sig_algos = cfg.algorithms.ca_signature_algorithms.clone();
        let verifier_factory: VerifierFactory = Box::new(move |reply, runner| {
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
            driver,
            conn: ConnectionState::new(),
            algo_overrides: cfg.algorithms,
            phase: Phase::Handshaking,
            events: VecDeque::new(),
            outbuf: Vec::new(),
            out_pos: 0,
        };
        me.driver.start(Instant::now())?;
        // Buffer the version banner + initial KEXINIT; an opportunistic flush
        // tolerates a not-yet-writable socket via `WouldBlock`.
        me.flush()?;
        Ok(me)
    }

    /// The session identifier (exchange hash `H`), available once the handshake
    /// has completed.
    pub fn session_id(&self) -> &[u8] {
        self.driver.session_id()
    }

    /// Mutable access to the underlying stream, for (re)registering it with a
    /// `mio::Registry` — e.g. to toggle `Interest::WRITABLE` based on
    /// [`wants_write`](Self::wants_write).
    pub fn get_mut(&mut self) -> &mut S {
        &mut self.stream
    }

    /// Shared access to the underlying stream.
    pub fn get_ref(&self) -> &S {
        &self.stream
    }

    /// Whether there is buffered outbound data still waiting on socket
    /// writability. Use this to decide between `Interest::READABLE` and
    /// `READABLE | WRITABLE` when (re)registering the stream.
    pub fn wants_write(&self) -> bool {
        self.out_pos < self.outbuf.len()
    }

    /// Hint for the next timer deadline (re-key / keepalive), if any. Pass the
    /// remaining duration to `Poll::poll` so timers fire on schedule.
    pub fn next_timeout(&self) -> Option<Instant> {
        self.driver.next_timeout()
    }

    /// Pull the next high-level [`MioEvent`], if one is queued.
    pub fn poll_event(&mut self) -> Option<MioEvent> {
        self.events.pop_front()
    }

    /// Begin userauth with `credentials`, tried in order within one exchange.
    /// Valid only after [`MioEvent::HandshakeComplete`]. Non-blocking: the
    /// outcome arrives later as [`MioEvent::Authenticated`] /
    /// [`MioEvent::AuthFailed`].
    pub fn authenticate(&mut self, user: &str, credentials: Vec<ClientCredential>) -> Result<()> {
        if !matches!(self.phase, Phase::Ready) {
            return Err(Error::Protocol(
                "authenticate: handshake not complete or auth already in progress",
            ));
        }
        let mut auth = ClientAuth::new(user, self.driver.session_id().to_vec());
        if let Some(accepted) = self.algo_overrides.pubkey_accepted_algorithms.clone() {
            auth.set_pubkey_accepted(accepted);
        }
        if let Some(ext) = self.driver.peer_ext_info()
            && let Some(algs) = ext.server_sig_algs.as_deref()
        {
            auth.set_server_sig_algs(algs);
        }
        for c in credentials {
            auth.add_credential(c);
        }
        let first = auth.start();
        self.driver.enqueue_payload(&first)?;
        self.phase = Phase::Authenticating(auth);
        self.flush()
    }

    /// Convenience: password auth.
    pub fn authenticate_password(&mut self, user: &str, password: &str) -> Result<()> {
        self.authenticate(
            user,
            alloc::vec![ClientCredential::Password(password.into())],
        )
    }

    /// Convenience: publickey auth with a single key.
    pub fn authenticate_publickey(&mut self, user: &str, key: Box<dyn HostKey>) -> Result<()> {
        self.authenticate(user, alloc::vec![ClientCredential::PublicKey(key)])
    }

    /// Run a command on a fresh session channel. Valid only after
    /// [`MioEvent::Authenticated`]. Non-blocking: output is delivered as
    /// [`MioEvent::Data`] / [`MioEvent::ExitStatus`] and the channel's end as
    /// [`MioEvent::ExecClosed`].
    pub fn exec(&mut self, command: &str) -> Result<()> {
        if !matches!(self.phase, Phase::Authenticated) {
            return Err(Error::Protocol("exec: not authenticated (or busy)"));
        }
        let (channel, open_payload) = self.conn.open(ChannelOpen::Session)?;
        self.driver.enqueue_payload(&open_payload)?;
        self.phase = Phase::Exec(ExecState::new(channel, command.to_string()));
        self.flush()
    }

    /// Flush buffered outbound bytes to the socket. Call on writable readiness.
    /// Stops at `WouldBlock`, leaving the remainder buffered (see
    /// [`wants_write`](Self::wants_write)).
    pub fn pump_writable(&mut self) -> Result<()> {
        self.flush()
    }

    /// Read all currently-available bytes, advance the protocol state machine,
    /// and queue any resulting [`MioEvent`]s. Call on readable readiness.
    pub fn pump_readable(&mut self) -> Result<()> {
        self.driver.handle_timeout(Instant::now())?;
        let mut tmp = [0u8; READ_CHUNK];
        loop {
            match self.stream.read(&mut tmp) {
                Ok(0) => {
                    self.events.push_back(MioEvent::Disconnected);
                    self.phase = Phase::Done;
                    return Ok(());
                }
                Ok(n) => self.driver.handle_input(&tmp[..n], Instant::now())?,
                Err(e) if e.kind() == ErrorKind::WouldBlock => break,
                Err(e) if e.kind() == ErrorKind::Interrupted => continue,
                Err(e) => return Err(Error::Io(e)),
            }
        }
        self.process_driver_events()?;
        self.flush()
    }

    // --- internals ---

    fn flush(&mut self) -> Result<()> {
        while let Some(frame) = self.driver.poll_transmit() {
            self.outbuf.extend_from_slice(&frame);
        }
        while self.out_pos < self.outbuf.len() {
            match self.stream.write(&self.outbuf[self.out_pos..]) {
                Ok(0) => return Err(Error::Protocol("write returned 0 (peer closed)")),
                Ok(n) => self.out_pos += n,
                Err(e) if e.kind() == ErrorKind::WouldBlock => break,
                Err(e) if e.kind() == ErrorKind::Interrupted => continue,
                Err(e) => return Err(Error::Io(e)),
            }
        }
        if self.out_pos == self.outbuf.len() && !self.outbuf.is_empty() {
            self.outbuf.clear();
            self.out_pos = 0;
        }
        Ok(())
    }

    fn process_driver_events(&mut self) -> Result<()> {
        while let Some(ev) = self.driver.poll_event() {
            match ev {
                Event::HandshakeComplete => {
                    if matches!(self.phase, Phase::Handshaking) {
                        self.phase = Phase::Ready;
                        self.events.push_back(MioEvent::HandshakeComplete);
                    }
                }
                Event::AppData(payload) => self.on_app_data(&payload)?,
            }
        }
        Ok(())
    }

    fn on_app_data(&mut self, payload: &[u8]) -> Result<()> {
        // Move the phase out so we can mutate `self` (driver/conn/events) while
        // owning the in-flight auth/exec state, then store the next phase back.
        match core::mem::replace(&mut self.phase, Phase::Done) {
            Phase::Authenticating(mut auth) => match auth.on_packet(payload)? {
                ClientStep::Send(p) => {
                    self.driver.enqueue_payload(&p)?;
                    self.phase = Phase::Authenticating(auth);
                }
                ClientStep::Success => {
                    self.driver.notify_auth_success();
                    self.phase = Phase::Authenticated;
                    self.events.push_back(MioEvent::Authenticated);
                }
                ClientStep::Failed { .. } => {
                    self.phase = Phase::Failed;
                    self.events.push_back(MioEvent::AuthFailed);
                }
                ClientStep::Banner { .. } | ClientStep::Idle => {
                    self.phase = Phase::Authenticating(auth);
                }
            },
            Phase::Exec(mut st) => {
                self.handle_exec_packet(&mut st, payload)?;
                if st.finished() {
                    self.phase = Phase::Authenticated;
                    self.events.push_back(MioEvent::ExecClosed);
                } else {
                    self.phase = Phase::Exec(st);
                }
            }
            other => {
                // No active consumer for app data in this phase; preserve it.
                self.phase = other;
            }
        }
        Ok(())
    }

    fn handle_exec_packet(&mut self, st: &mut ExecState, payload: &[u8]) -> Result<()> {
        match self.conn.on_packet(payload)? {
            ChannelEvent::OpenConfirmed { channel } if channel == st.channel => {
                let req = self.conn.send_request(
                    st.channel,
                    ChannelRequest::Exec {
                        command: st.command.clone(),
                    },
                    true,
                )?;
                self.driver.enqueue_payload(&req)?;
            }
            ChannelEvent::OpenFailed { channel, .. } if channel == st.channel => {
                // Treat an open failure as a terminal, already-closed channel so
                // the caller gets a single `ExecClosed`.
                st.remote_closed = true;
                st.close_sent = true;
            }
            ChannelEvent::Failure { channel } if channel == st.channel => {
                return Err(Error::Protocol("exec request denied"));
            }
            ChannelEvent::Data { channel, data } if channel == st.channel => {
                let n = data.len() as u32;
                self.events.push_back(MioEvent::Data {
                    stderr: false,
                    data,
                });
                self.replenish(st.channel, n)?;
            }
            ChannelEvent::ExtendedData {
                channel,
                code,
                data,
            } if channel == st.channel => {
                let n = data.len() as u32;
                self.events.push_back(MioEvent::Data {
                    stderr: code == SSH_EXTENDED_DATA_STDERR,
                    data,
                });
                self.replenish(st.channel, n)?;
            }
            ChannelEvent::Request {
                channel,
                request,
                want_reply,
            } if channel == st.channel => {
                if let ChannelRequest::ExitStatus { code } = request {
                    self.events.push_back(MioEvent::ExitStatus(code));
                }
                if want_reply {
                    let p = self.conn.send_request_failure(st.channel)?;
                    self.driver.enqueue_payload(&p)?;
                }
            }
            ChannelEvent::Eof { channel } if channel == st.channel && !st.eof_sent => {
                let p = self.conn.send_eof(st.channel)?;
                self.driver.enqueue_payload(&p)?;
                st.eof_sent = true;
            }
            ChannelEvent::Close { channel } if channel == st.channel => {
                st.remote_closed = true;
                if !st.close_sent {
                    let p = self.conn.send_close(st.channel)?;
                    self.driver.enqueue_payload(&p)?;
                    st.close_sent = true;
                }
            }
            _ => {}
        }
        Ok(())
    }

    fn replenish(&mut self, channel: u32, n: u32) -> Result<()> {
        if let Some(adj) = self.conn.replenish_window(channel, n)? {
            self.driver.enqueue_payload(&adj)?;
        }
        Ok(())
    }
}

// Drive the readiness frontend in a *real* mio `Poll` loop against the in-crate
// blocking `Server`, proving the WouldBlock-based pumps complete a full
// handshake → auth → exec round-trip. Built only with `--features mio`.
#[cfg(all(test, feature = "server"))]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};
    use std::thread;
    use std::time::{Duration, Instant};

    use mio::net::TcpStream as MioTcpStream;
    use mio::{Events, Interest, Poll, Token};

    use crate::auth::{AuthAttempt, AuthDecision, Authenticator};
    use crate::client::Config;
    use crate::hostkey::{Ed25519HostKey, HostKey};
    use crate::server::{
        AuthenticatorFactory, CommandHandler, Config as ServerConfig, ExecResult, Server,
        SessionEnv,
    };
    use purecrypto::rng::{OsRng, RngCore};

    struct OneKeyAuth {
        user: String,
        blob: Vec<u8>,
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
                    if user != self.user || public_blob != self.blob {
                        return AuthDecision::Reject;
                    }
                    if probe_only || verified {
                        AuthDecision::Accept
                    } else {
                        AuthDecision::Reject
                    }
                }
                _ => AuthDecision::Reject,
            }
        }
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

    #[test]
    #[cfg(feature = "mio")]
    fn mio_connect_auth_exec_round_trip() {
        let host_seed = fresh_seed();
        let client_seed = fresh_seed();
        let client_blob = Ed25519HostKey::from_seed(client_seed).public_blob();
        let user = "mio-user".to_string();
        let expected = b"hello from mio client\n".to_vec();

        let host_key: Box<dyn HostKey + Send + Sync> =
            Box::new(Ed25519HostKey::from_seed(host_seed));
        let u = user.clone();
        let b = client_blob.clone();
        let factory: Arc<dyn AuthenticatorFactory> = Arc::new(move || {
            Box::new(OneKeyAuth {
                user: u.clone(),
                blob: b.clone(),
            }) as Box<dyn Authenticator>
        });
        let cfg = ServerConfig::new(
            vec![host_key],
            factory,
            vec!["publickey"],
            Arc::new(StaticHandler {
                out: expected.clone(),
            }),
        );
        let mut server = Server::bind("127.0.0.1:0", cfg).expect("bind");
        let addr = server.local_addr().expect("addr");
        let done = Arc::new(Mutex::new(false));
        let d2 = done.clone();
        let server_thread = thread::spawn(move || {
            let _ = server.accept_one();
            *d2.lock().unwrap() = true;
        });

        // mio readiness loop.
        const TOK: Token = Token(0);
        let mut poll = Poll::new().expect("poll");
        let mut events = Events::with_capacity(16);
        let sock = MioTcpStream::connect(addr).expect("connect");
        let mut client =
            MioClient::new(sock, "localhost", addr.port(), Config::insecure()).expect("mio client");
        poll.registry()
            .register(
                client.get_mut(),
                TOK,
                Interest::READABLE | Interest::WRITABLE,
            )
            .expect("register");

        let mut out = Vec::new();
        let mut exit = None;
        let deadline = Instant::now() + Duration::from_secs(15);
        'ev: loop {
            if Instant::now() > deadline {
                panic!("mio client did not finish in time");
            }
            poll.poll(&mut events, Some(Duration::from_millis(200)))
                .expect("poll");
            for ev in events.iter() {
                if ev.is_writable() {
                    client.pump_writable().expect("write");
                }
                if ev.is_readable() {
                    client.pump_readable().expect("read");
                }
            }
            while let Some(e) = client.poll_event() {
                match e {
                    MioEvent::HandshakeComplete => client
                        .authenticate_publickey(
                            &user,
                            Box::new(Ed25519HostKey::from_seed(client_seed)),
                        )
                        .expect("auth"),
                    MioEvent::Authenticated => client.exec("hi").expect("exec"),
                    MioEvent::Data { data, .. } => out.extend_from_slice(&data),
                    MioEvent::ExitStatus(c) => exit = Some(c),
                    MioEvent::ExecClosed => break 'ev,
                    MioEvent::AuthFailed => panic!("auth failed"),
                    MioEvent::Disconnected => panic!("disconnected before exec completed"),
                }
            }
            // Ask for writable readiness only while output is backed up.
            let interest = if client.wants_write() {
                Interest::READABLE | Interest::WRITABLE
            } else {
                Interest::READABLE
            };
            poll.registry()
                .reregister(client.get_mut(), TOK, interest)
                .expect("reregister");
        }

        assert_eq!(out, expected, "mio exec stdout round-trips");
        assert_eq!(exit, Some(0));

        let start = Instant::now();
        while !*done.lock().unwrap() {
            if start.elapsed() > Duration::from_secs(10) {
                panic!("server did not finish");
            }
            thread::sleep(Duration::from_millis(20));
        }
        let _ = server_thread.join();
    }
}
