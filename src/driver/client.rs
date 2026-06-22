//! Sans-IO client connection driver.
//!
//! [`ClientDriver`] owns the transport codec, the KEX runner, the connection
//! multiplexer, and the authentication state machine, and sequences them
//! through the SSH handshake → auth → application phases. It performs no I/O:
//! the frontend feeds inbound bytes ([`ClientDriver::handle_input`]), drains
//! encoded outbound frames ([`ClientDriver::poll_transmit`]), pulls
//! [`Event`]s ([`ClientDriver::poll_event`]), and ticks timers
//! ([`ClientDriver::handle_timeout`]).
//!
//! Host-key verification is injected as a [`VerifierFactory`] closure so the
//! driver stays free of policy, prompting, and known-hosts I/O — those remain
//! a frontend concern.

use alloc::boxed::Box;
use alloc::collections::VecDeque;
use alloc::vec::Vec;
use std::time::{Duration, Instant};

use purecrypto::rng::{CryptoRng, OsRng, RngCore};

use crate::auth::{ClientAuth, ClientStep};
use crate::channel::{ChannelOpen, ChannelRequest, ConnectionState, GlobalRequest};
use crate::client::AlgoOverrides;
use crate::error::{Error, Result};
use crate::hostkey::HostKeyVerify;
use crate::transport::ping::{SSH_MSG_PING, SSH_MSG_PONG, pong_for_ping};
use crate::transport::rekey::{RekeyPolicy, is_kex_msg};
use crate::transport::{ExtInfo, KexRunner, PacketCodec, Role, VersionExchange};

use super::Event;

/// `SSH_MSG_KEX_ECDH_REPLY` — the KEX message that carries the host key, so
/// the one we must verify against policy.
const SSH_MSG_KEX_ECDH_REPLY: u8 = 31;
/// `SSH_MSG_KEXINIT`.
const SSH_MSG_KEXINIT: u8 = 20;
const SSH_MSG_EXT_INFO: u8 = 7;

const MAX_INBOX_BYTES: usize = 8 * 1024 * 1024;
const MAX_BANNER_LINE: usize = 1024;
const MAX_BANNER_LINES: usize = 32;
const MAX_BANNER_TOTAL_BYTES: usize = 64 * 1024;

/// Builds the exchange-hash host-key verifier from the `SSH_MSG_KEX_ECDH_REPLY`
/// payload, applying the frontend's host-key policy. Receives the live
/// [`KexRunner`] so it can read the negotiated host-key algorithm. Returning
/// `Err` aborts the handshake (e.g. host key rejected).
pub type VerifierFactory =
    Box<dyn FnMut(&[u8], &KexRunner) -> Result<Box<dyn HostKeyVerify>> + Send>;

/// Where the connection is in the SSH protocol lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    /// Waiting for the peer's `SSH-2.0-…` identification line.
    AwaitingVersion,
    /// First key exchange in flight.
    Kex,
    /// Handshake done; the frontend may begin authentication.
    AuthReady,
    /// `ClientAuth` driver running.
    Authenticating,
    /// Authenticated; application channels may flow.
    Established,
}

/// Sans-IO driver for the client half of an SSH connection.
///
/// See the [module docs](crate::driver) for the bytes-in / bytes-out / events
/// contract. Construct with [`ClientDriver::new`], kick off with
/// [`ClientDriver::start`], then pump.
pub struct ClientDriver {
    phase: Phase,
    codec: PacketCodec,
    runner: KexRunner,
    conn: ConnectionState,
    rng: OsRng,

    inbox: Vec<u8>,
    outbox: VecDeque<Vec<u8>>,
    events: VecDeque<Event>,
    /// Application packets received while a re-key was in flight (RFC 4253
    /// §7.3); replayed once NEWKEYS lands.
    deferred: VecDeque<Vec<u8>>,

    v_s: Vec<u8>,
    session_id: Vec<u8>,
    algo_overrides: AlgoOverrides,
    verifier_factory: VerifierFactory,

    rekey_policy: RekeyPolicy,
    last_kex: Option<Instant>,

    keepalive: Option<(Duration, u32)>,
    last_activity: Instant,
    missed_keepalives: u32,

    auth: Option<ClientAuth>,

    // Banner-scan bookkeeping for the version-exchange phase.
    banner_lines: usize,
    banner_total: usize,
}

impl ClientDriver {
    /// Build a driver. `algo_overrides` supplies the local algorithm policy
    /// used to build KEXINIT adverts (initial and re-key); `verifier_factory`
    /// applies the frontend's host-key policy at `SSH_MSG_KEX_ECDH_REPLY`.
    ///
    /// Call [`ClientDriver::start`] before pumping to emit the version line and
    /// initial KEXINIT.
    pub fn new(algo_overrides: AlgoOverrides, verifier_factory: VerifierFactory) -> Self {
        let mut rng = OsRng;
        // Placeholder advert; replaced in `start`.
        let placeholder = crate::client::build_default_kexinit(&mut rng, &algo_overrides);
        Self {
            phase: Phase::AwaitingVersion,
            codec: PacketCodec::new(),
            runner: KexRunner::new(Role::Client, placeholder),
            conn: ConnectionState::new(),
            rng,
            inbox: Vec::new(),
            outbox: VecDeque::new(),
            events: VecDeque::new(),
            deferred: VecDeque::new(),
            v_s: Vec::new(),
            session_id: Vec::new(),
            algo_overrides,
            verifier_factory,
            rekey_policy: RekeyPolicy::default(),
            last_kex: None,
            keepalive: None,
            last_activity: Instant::now(),
            missed_keepalives: 0,
            auth: None,
            banner_lines: 0,
            banner_total: 0,
        }
    }

    /// Override the re-key thresholds (defaults to [`RekeyPolicy::default`]).
    pub fn set_rekey_policy(&mut self, policy: RekeyPolicy) {
        self.rekey_policy = policy;
    }

    /// Enable connection keepalive: after `interval` of inbound silence,
    /// [`handle_timeout`](Self::handle_timeout) emits a `keepalive@openssh.com`
    /// global request, failing the connection after `count_max` unanswered
    /// probes. Mirrors `ServerAliveInterval` / `ServerAliveCountMax`.
    pub fn set_keepalive(&mut self, interval: Duration, count_max: u32) {
        self.keepalive = Some((interval, count_max));
    }

    /// Emit the local version line and the initial KEXINIT. `now` seeds the
    /// keepalive activity clock. Must be called exactly once, before pumping.
    pub fn start(&mut self, now: Instant) -> Result<()> {
        self.last_activity = now;
        self.outbox.push_back(VersionExchange::outgoing_bytes());
        // First KEX advertises ext-info-c so the server may send EXT_INFO with
        // server-sig-algs (RFC 8308 §2.1).
        let advert = crate::client::build_default_kexinit(&mut self.rng, &self.algo_overrides)
            .with_ext_info_marker(Role::Client);
        self.runner = KexRunner::new(Role::Client, advert);
        let initial = self.runner.start(&mut self.rng)?;
        for p in initial.outbound {
            self.enqueue_payload(&p)?;
        }
        Ok(())
    }

    // --- accessors the frontend needs to build auth / inspect state ---

    /// The session identifier (KEX exchange hash `H`), stable across re-keys.
    /// Empty until the handshake completes.
    pub fn session_id(&self) -> &[u8] {
        &self.session_id
    }

    /// The peer's negotiated EXT_INFO (e.g. server-sig-algs), if any.
    pub fn peer_ext_info(&self) -> Option<&ExtInfo> {
        self.runner.peer_ext_info()
    }

    /// True once authentication has succeeded.
    pub fn is_established(&self) -> bool {
        self.phase == Phase::Established
    }

    /// True while a key exchange is in flight.
    pub fn is_kexing(&self) -> bool {
        self.runner.is_kexing()
    }

    /// Shared access to the connection multiplexer (channel bookkeeping).
    pub fn conn(&self) -> &ConnectionState {
        &self.conn
    }

    /// Mutable access to the connection multiplexer. Frontends use this to
    /// build channel-protocol payloads, then ship them with
    /// [`enqueue_payload`](Self::enqueue_payload).
    pub fn conn_mut(&mut self) -> &mut ConnectionState {
        &mut self.conn
    }

    // --- pump surface ---

    /// Encode `payload` with the current keys and queue it for transmission.
    /// This is the sans-IO analog of the old `Client::write_payload`.
    pub fn enqueue_payload(&mut self, payload: &[u8]) -> Result<()> {
        let frame = self.codec.encode(payload, &mut self.rng)?;
        self.outbox.push_back(frame);
        Ok(())
    }

    /// Pop the next fully-encoded frame to write to the transport, if any.
    pub fn poll_transmit(&mut self) -> Option<Vec<u8>> {
        self.outbox.pop_front()
    }

    /// Pop the next high-level [`Event`], if any.
    pub fn poll_event(&mut self) -> Option<Event> {
        self.events.pop_front()
    }

    /// Begin authentication with a fully-configured [`ClientAuth`] driver.
    /// Emits the initial SERVICE_REQUEST; the verdict arrives later as an
    /// [`Event::AuthSuccess`] / [`Event::AuthFailure`].
    pub fn begin_auth(&mut self, mut auth: ClientAuth) -> Result<()> {
        let first = auth.start();
        self.auth = Some(auth);
        self.phase = Phase::Authenticating;
        self.enqueue_payload(&first)
    }

    /// Feed inbound transport bytes. Decodes and routes as many packets as are
    /// available, enqueuing outbound frames and events. `now` advances the
    /// keepalive activity clock.
    pub fn handle_input(&mut self, bytes: &[u8], now: Instant) -> Result<()> {
        self.inbox.extend_from_slice(bytes);
        if self.inbox.len() > MAX_INBOX_BYTES {
            return Err(Error::Protocol("inbound buffer too large"));
        }

        // Version-exchange phase: consume the peer's identification line
        // (skipping any preamble lines) before any binary packets.
        if self.phase == Phase::AwaitingVersion && !self.scan_peer_version()? {
            return Ok(()); // need more bytes for a complete line
        }

        // Framed-packet phase: decode everything currently buffered.
        loop {
            match self.codec.decode(&self.inbox)? {
                Some((payload, consumed)) => {
                    self.inbox.drain(..consumed);
                    self.route_packet(&payload, now)?;
                }
                None => return Ok(()),
            }
        }
    }

    /// Drive re-key and keepalive timers. The frontend calls this on its tick
    /// (and after `next_timeout`). Returns `Err` if keepalive has gone
    /// unanswered past `count_max`.
    pub fn handle_timeout(&mut self, now: Instant) -> Result<()> {
        if self.runner.is_kexing() {
            return Ok(());
        }
        // RFC 4253 §9: re-key once a threshold is crossed.
        if let Some(last) = self.last_kex
            && self.rekey_policy.should_rekey(&self.codec, last, now)
        {
            self.initiate_rekey()?;
            return Ok(());
        }
        // ServerAliveInterval / ServerAliveCountMax.
        if let Some((interval, count_max)) = self.keepalive
            && now.duration_since(self.last_activity) >= interval
        {
            if self.missed_keepalives >= count_max {
                return Err(Error::Protocol("keepalive: no response from peer"));
            }
            let probe = self.conn.send_global_request(GlobalRequest::Keepalive, true);
            self.enqueue_payload(&probe)?;
            self.missed_keepalives += 1;
            self.last_activity = now;
        }
        Ok(())
    }

    /// When the frontend should next call [`handle_timeout`](Self::handle_timeout).
    /// Currently driven by the keepalive interval; re-key timing is checked
    /// opportunistically on each tick.
    pub fn next_timeout(&self) -> Option<Instant> {
        self.keepalive
            .map(|(interval, _)| self.last_activity + interval)
    }

    // --- channel intents (thin wrappers that enqueue the produced payload) ---

    /// Open a channel; the `OpenConfirmed` / `OpenFailed` outcome arrives as an
    /// [`Event::Channel`]. Returns the local channel id.
    pub fn open_channel(&mut self, kind: ChannelOpen) -> Result<u32> {
        let (id, payload) = self.conn.open(kind)?;
        self.enqueue_payload(&payload)?;
        Ok(id)
    }

    /// Queue channel data, honouring the peer's window. Returns the number of
    /// bytes accepted (may be 0 when the window is full).
    pub fn send_channel_data(&mut self, channel: u32, data: &[u8]) -> Result<usize> {
        let (payload, taken) = self.conn.send_data(channel, data)?;
        if !payload.is_empty() {
            self.enqueue_payload(&payload)?;
        }
        Ok(taken)
    }

    /// Send a channel request (`exec`, `pty-req`, `subsystem`, …).
    pub fn send_channel_request(
        &mut self,
        channel: u32,
        req: ChannelRequest,
        want_reply: bool,
    ) -> Result<()> {
        let payload = self.conn.send_request(channel, req, want_reply)?;
        self.enqueue_payload(&payload)
    }

    /// Send CHANNEL_EOF for `channel`.
    pub fn send_channel_eof(&mut self, channel: u32) -> Result<()> {
        let payload = self.conn.send_eof(channel)?;
        self.enqueue_payload(&payload)
    }

    /// Send CHANNEL_CLOSE for `channel`.
    pub fn send_channel_close(&mut self, channel: u32) -> Result<()> {
        let payload = self.conn.send_close(channel)?;
        self.enqueue_payload(&payload)
    }

    /// Credit the receive window for `channel` after consuming `n` bytes.
    /// Emits a WINDOW_ADJUST if one is due.
    pub fn replenish_window(&mut self, channel: u32, n: u32) -> Result<()> {
        if let Some(payload) = self.conn.replenish_window(channel, n)? {
            self.enqueue_payload(&payload)?;
        }
        Ok(())
    }

    /// Send a global request (e.g. `tcpip-forward`, `keepalive`).
    pub fn send_global_request(&mut self, req: GlobalRequest, want_reply: bool) -> Result<()> {
        let payload = self.conn.send_global_request(req, want_reply);
        self.enqueue_payload(&payload)
    }

    // --- internal routing ---

    /// Consume version-exchange preamble + the `SSH-2.0-…` line from `inbox`.
    /// Returns `Ok(true)` once the peer version has been parsed (phase moves to
    /// `Kex`), `Ok(false)` if more bytes are needed.
    fn scan_peer_version(&mut self) -> Result<bool> {
        loop {
            let Some(pos) = self.inbox.iter().position(|&b| b == b'\n') else {
                // No complete line yet; guard against an unbounded line.
                if self.inbox.len() > MAX_BANNER_LINE {
                    return Err(Error::Protocol("banner line too long"));
                }
                return Ok(false);
            };
            let line: Vec<u8> = self.inbox.drain(..=pos).collect();
            self.banner_total = self.banner_total.saturating_add(line.len());
            if self.banner_total > MAX_BANNER_TOTAL_BYTES {
                return Err(Error::Protocol("banner too large"));
            }
            if line.starts_with(b"SSH-") {
                let parsed = VersionExchange::parse_remote(&line)?;
                self.v_s = parsed.into_bytes();
                self.phase = Phase::Kex;
                return Ok(true);
            }
            self.banner_lines += 1;
            if self.banner_lines > MAX_BANNER_LINES {
                return Err(Error::Protocol("peer banner too long"));
            }
            // Otherwise it's a preamble line; keep scanning.
        }
    }

    /// Route one decoded transport packet (the sans-IO analog of the old
    /// `Client::read_one_packet` match).
    fn route_packet(&mut self, payload: &[u8], now: Instant) -> Result<()> {
        self.note_activity(now);
        match payload.first().copied() {
            Some(1) => Err(Error::Protocol("peer sent SSH_MSG_DISCONNECT")),
            // SSH_MSG_IGNORE / UNIMPLEMENTED / DEBUG — drop.
            Some(2) | Some(3) | Some(4) => Ok(()),
            Some(SSH_MSG_PING) => {
                let pong = pong_for_ping(payload)?;
                self.enqueue_payload(&pong)
            }
            Some(SSH_MSG_PONG) => Ok(()),
            Some(SSH_MSG_EXT_INFO) => {
                if !self.runner.may_accept_ext_info() {
                    return Err(Error::Protocol("unexpected SSH_MSG_EXT_INFO"));
                }
                self.runner.handle_inbound_ext_info(payload)
            }
            Some(b) if is_kex_msg(b) => {
                // A peer KEXINIT while we're idle is a peer-initiated re-key;
                // answer with our own KEXINIT first.
                if b == SSH_MSG_KEXINIT && !self.runner.is_kexing() {
                    self.initiate_rekey()?;
                }
                self.route_kex(payload)?;
                if self.runner.is_completed() {
                    if self.phase == Phase::Kex {
                        self.session_id = self
                            .runner
                            .session_id()
                            .ok_or(Error::Protocol("kex: missing session id"))?
                            .to_vec();
                        self.phase = Phase::AuthReady;
                        self.events.push_back(Event::HandshakeComplete);
                    }
                    self.last_kex = Some(now);
                    self.drain_deferred()?;
                }
                Ok(())
            }
            _ => {
                // Application traffic. During a re-key it must be buffered
                // until NEWKEYS lands (RFC 4253 §7.3).
                if self.runner.is_kexing() {
                    self.deferred.push_back(payload.to_vec());
                    return Ok(());
                }
                self.runner.note_inbound_other();
                self.route_app(payload)
            }
        }
    }

    /// Feed one KEX-stream packet into the runner, building the host-key
    /// verifier on `SSH_MSG_KEX_ECDH_REPLY`, and enqueue its output.
    fn route_kex(&mut self, payload: &[u8]) -> Result<()> {
        let msg = *payload.first().ok_or(Error::Format("empty kex payload"))?;
        let verifier: Option<Box<dyn HostKeyVerify>> = if msg == SSH_MSG_KEX_ECDH_REPLY {
            Some((self.verifier_factory)(payload, &self.runner)?)
        } else {
            None
        };
        let v_c = crate::transport::version::LOCAL_VERSION.as_bytes().to_vec();
        let v_s = self.v_s.clone();
        let adv = self.runner.on_packet(
            &mut self.rng,
            &mut self.codec,
            payload,
            None,
            verifier.as_deref(),
            &v_c,
            &v_s,
        )?;
        for p in adv.outbound {
            self.enqueue_payload(&p)?;
        }
        Ok(())
    }

    /// Replay application packets buffered during a re-key, in arrival order.
    fn drain_deferred(&mut self) -> Result<()> {
        while !self.runner.is_kexing() {
            let Some(payload) = self.deferred.pop_front() else {
                break;
            };
            self.runner.note_inbound_other();
            self.route_app(&payload)?;
        }
        Ok(())
    }

    /// Route a (post-NEWKEYS) application packet: to the auth driver while
    /// authenticating, otherwise to the connection multiplexer.
    fn route_app(&mut self, payload: &[u8]) -> Result<()> {
        if self.phase == Phase::Authenticating {
            let auth = self
                .auth
                .as_mut()
                .ok_or(Error::Protocol("auth packet with no auth driver"))?;
            match auth.on_packet(payload)? {
                ClientStep::Send(p) => self.enqueue_payload(&p)?,
                ClientStep::Success => {
                    // RFC 4253 §6.2: zlib@openssh.com starts compressing here.
                    self.codec.activate_compress();
                    // RFC 8308 §2.3: re-open the one-shot EXT_INFO window for a
                    // possible post-auth EXT_INFO.
                    self.runner.arm_ext_info_post_auth();
                    self.phase = Phase::Established;
                    self.auth = None;
                    self.events.push_back(Event::AuthSuccess);
                }
                ClientStep::Failed { .. } => {
                    self.auth = None;
                    self.events.push_back(Event::AuthFailure);
                }
                ClientStep::Banner { message, language } => {
                    self.events.push_back(Event::AuthBanner { message, language });
                }
                ClientStep::Idle => {}
            }
            Ok(())
        } else {
            let ev = self.conn.on_packet(payload)?;
            self.events.push_back(Event::Channel(ev));
            Ok(())
        }
    }

    /// Emit our KEXINIT to start a re-key (runner must be in `Completed`).
    fn initiate_rekey(&mut self) -> Result<()> {
        let advert = crate::client::build_default_kexinit(&mut self.rng, &self.algo_overrides);
        let adv = self.runner.restart(&mut self.rng, advert)?;
        for p in adv.outbound {
            self.enqueue_payload(&p)?;
        }
        Ok(())
    }

    /// Reset the keepalive activity clock on any inbound packet.
    fn note_activity(&mut self, now: Instant) {
        self.last_activity = now;
        self.missed_keepalives = 0;
    }
}

// `OsRng` is `CryptoRng + RngCore`; assert the trait bounds we rely on so the
// generic runner/codec calls type-check without spelling them at each site.
const _: fn() = || {
    fn _assert<T: CryptoRng + RngCore>() {}
    _assert::<OsRng>();
};

// End-to-end driver test: drive a `ClientDriver` by hand over a raw TCP socket
// against the real blocking `Server`, exercising version exchange → KEX → auth
// → an exec round-trip entirely through the sans-IO surface. This also
// prototypes the Phase-2 sync pump.
#[cfg(all(test, feature = "server"))]
mod tests {
    use super::*;
    use std::io::{Read as _, Write as _};
    use std::net::TcpStream;
    use std::sync::{Arc, Mutex};
    use std::thread;
    use std::time::Duration;

    use crate::auth::{
        AuthAttempt, AuthDecision, Authenticator, ClientAuth, ClientCredential,
    };
    use crate::channel::{ChannelEvent, ChannelOpen, ChannelRequest};
    use crate::hostkey::{Ed25519HostKey, HostKey, host_key_verify_by_name};
    use crate::server::{
        AuthenticatorFactory, CommandHandler, Config as ServerConfig, ExecResult, Server,
        SessionEnv,
    };

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
                    if probe_only {
                        return AuthDecision::Accept;
                    }
                    if verified {
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

    /// `AcceptAny` host-key verifier (plain-key path): build the exchange-hash
    /// verifier straight from the presented key, no policy check.
    fn accept_any_factory() -> VerifierFactory {
        Box::new(|reply: &[u8], runner: &KexRunner| {
            if reply.len() < 5 {
                return Err(Error::Format("kex-ecdh-reply too short"));
            }
            let k_s_len =
                u32::from_be_bytes([reply[1], reply[2], reply[3], reply[4]]) as usize;
            if reply.len() < 5 + k_s_len {
                return Err(Error::Format("kex-ecdh-reply truncated"));
            }
            let k_s = &reply[5..5 + k_s_len];
            let neg = runner
                .negotiated()
                .ok_or(Error::Protocol("kex: no negotiated algorithms"))?;
            host_key_verify_by_name(&neg.host_key, k_s)
        })
    }

    #[test]
    fn driver_handshake_auth_exec_round_trip() {
        let host_seed = fresh_seed();
        let client_seed = fresh_seed();
        let client_blob = Ed25519HostKey::from_seed(client_seed).public_blob();
        let user = "driver-user".to_string();
        let expected = b"hello from sans-io driver\n".to_vec();

        // --- server on a thread ---
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

        // --- client driver over a raw socket ---
        let mut sock = TcpStream::connect(addr).expect("connect");
        sock.set_read_timeout(Some(Duration::from_millis(50))).unwrap();
        let mut driver = ClientDriver::new(Default::default(), accept_any_factory());
        driver.start(Instant::now()).expect("start");

        let mut channel: Option<u32> = None;
        let mut stdout = Vec::new();
        let mut exit: Option<u32> = None;
        let (mut eof_sent, mut close_sent, mut remote_close) = (false, false, false);

        let flush = |sock: &mut TcpStream, d: &mut ClientDriver| {
            while let Some(frame) = d.poll_transmit() {
                sock.write_all(&frame).expect("write");
            }
        };

        'pump: for _ in 0..100_000 {
            flush(&mut sock, &mut driver);
            while let Some(ev) = driver.poll_event() {
                match ev {
                    Event::HandshakeComplete => {
                        let mut auth =
                            ClientAuth::new(user.clone(), driver.session_id().to_vec());
                        auth.add_credential(ClientCredential::PublicKey(Box::new(
                            Ed25519HostKey::from_seed(client_seed),
                        )));
                        driver.begin_auth(auth).expect("begin_auth");
                    }
                    Event::AuthSuccess => {
                        channel = Some(
                            driver.open_channel(ChannelOpen::Session).expect("open"),
                        );
                    }
                    Event::AuthFailure => panic!("auth failed"),
                    Event::AuthBanner { .. } => {}
                    Event::Channel(ce) => match ce {
                        ChannelEvent::OpenConfirmed { channel: c } if Some(c) == channel => {
                            driver
                                .send_channel_request(
                                    c,
                                    ChannelRequest::Exec {
                                        command: "hi".into(),
                                    },
                                    true,
                                )
                                .expect("exec req");
                        }
                        ChannelEvent::Data { channel: c, data } if Some(c) == channel => {
                            stdout.extend_from_slice(&data);
                            driver.replenish_window(c, data.len() as u32).expect("win");
                        }
                        ChannelEvent::Request {
                            channel: c,
                            request,
                            want_reply,
                        } if Some(c) == channel => {
                            if let ChannelRequest::ExitStatus { code } = request {
                                exit = Some(code);
                            }
                            if want_reply {
                                let p = driver
                                    .conn_mut()
                                    .send_request_failure(c)
                                    .expect("req fail");
                                driver.enqueue_payload(&p).expect("enq");
                            }
                        }
                        ChannelEvent::Eof { channel: c } if Some(c) == channel && !eof_sent => {
                            driver.send_channel_eof(c).expect("eof");
                            eof_sent = true;
                        }
                        ChannelEvent::Close { channel: c } if Some(c) == channel => {
                            remote_close = true;
                            if !close_sent {
                                driver.send_channel_close(c).expect("close");
                                close_sent = true;
                            }
                        }
                        _ => {}
                    },
                }
            }
            flush(&mut sock, &mut driver);
            if remote_close && close_sent {
                break 'pump;
            }
            let mut buf = [0u8; 16 * 1024];
            match sock.read(&mut buf) {
                Ok(0) => break 'pump,
                Ok(n) => driver.handle_input(&buf[..n], Instant::now()).expect("input"),
                Err(e)
                    if e.kind() == std::io::ErrorKind::WouldBlock
                        || e.kind() == std::io::ErrorKind::TimedOut =>
                {
                    driver.handle_timeout(Instant::now()).expect("timeout");
                }
                Err(e) => panic!("read error: {e}"),
            }
        }

        assert_eq!(stdout, expected, "exec stdout round-trips through the driver");
        assert_eq!(exit, Some(0), "exit status captured");

        drop(sock);
        let start = std::time::Instant::now();
        while !*done.lock().unwrap() {
            if start.elapsed() > Duration::from_secs(10) {
                panic!("server did not finish");
            }
            thread::sleep(Duration::from_millis(20));
        }
        let _ = server_thread.join();
    }
}
