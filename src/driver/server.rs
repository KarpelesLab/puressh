//! Sans-IO server transport driver.
//!
//! [`ServerDriver`] is the server-role counterpart of
//! [`ClientDriver`](super::ClientDriver): it owns the transport codec and the
//! KEX runner and sequences the server side of the SSH handshake (version
//! exchange, key exchange, re-key, EXT_INFO/PING handling), performing no I/O.
//! The frontend feeds inbound bytes, drains outbound frames, pulls
//! [`Event`]s, and ticks timers.
//!
//! As on the client, the driver does not own the connection multiplexer or the
//! authentication state machine: once the handshake completes it surfaces each
//! decoded payload as [`Event::AppData`]. The frontend runs `ServerAuth` and
//! its session/channel handlers over those payloads — so the existing blocking
//! server's handler model (and a future async one) layer on unchanged.
//!
//! The host keys and algorithm policy come from the server [`Config`], which
//! the driver holds behind an `Arc` to build KEXINIT adverts and select the
//! host key during KEX.

#![cfg(feature = "server")]

use alloc::collections::VecDeque;
use alloc::vec::Vec;
use std::sync::Arc;
use std::time::{Duration, Instant};

use purecrypto::rng::{CryptoRng, OsRng, RngCore};

use crate::error::{Error, Result};
use crate::hostkey::HostKey;
use crate::server::{Config, build_server_kexinit, pick_host_key, server_ext_info};
use crate::transport::ping::{SSH_MSG_PING, SSH_MSG_PONG, pong_for_ping};
use crate::transport::rekey::{RekeyPolicy, is_kex_msg};
use crate::transport::{ExtInfo, KexRunner, PacketCodec, Role, VersionExchange};

use super::{
    Event, MAX_BANNER_LINE, MAX_BANNER_LINES, MAX_BANNER_TOTAL_BYTES, MAX_INBOX_BYTES,
    SSH_MSG_EXT_INFO, SSH_MSG_KEXINIT, keepalive_request,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    /// Waiting for the peer's `SSH-2.0-…` identification line.
    AwaitingVersion,
    /// First key exchange in flight.
    Kex,
    /// Handshake done; post-NEWKEYS payloads surface as [`Event::AppData`].
    PostKex,
}

/// Sans-IO driver for the transport half of an SSH server connection.
///
/// See the [module docs](crate::driver) for the bytes-in / bytes-out / events
/// contract. Construct with [`ServerDriver::new`], kick off with
/// [`ServerDriver::start`], then pump.
pub struct ServerDriver {
    phase: Phase,
    codec: PacketCodec,
    runner: KexRunner,
    rng: OsRng,
    cfg: Arc<Config>,

    inbox: Vec<u8>,
    outbox: VecDeque<Vec<u8>>,
    events: VecDeque<Event>,
    deferred: VecDeque<Vec<u8>>,

    /// The peer's (client's) identification string.
    v_c: Vec<u8>,
    session_id: Vec<u8>,

    rekey_policy: RekeyPolicy,
    last_kex: Option<Instant>,

    keepalive: Option<(Duration, u32)>,
    last_activity: Instant,
    missed_keepalives: u32,

    banner_lines: usize,
    banner_total: usize,
}

impl ServerDriver {
    /// Build a driver from the server [`Config`] (host keys + algorithm
    /// policy). Call [`ServerDriver::start`] before pumping to emit the
    /// version line and initial KEXINIT.
    pub fn new(cfg: Arc<Config>) -> Self {
        let mut rng = OsRng;
        let placeholder = build_server_kexinit(&mut rng, &cfg);
        Self {
            phase: Phase::AwaitingVersion,
            codec: PacketCodec::new(),
            runner: KexRunner::new(Role::Server, placeholder),
            rng,
            cfg,
            inbox: Vec::new(),
            outbox: VecDeque::new(),
            events: VecDeque::new(),
            deferred: VecDeque::new(),
            v_c: Vec::new(),
            session_id: Vec::new(),
            rekey_policy: RekeyPolicy::default(),
            last_kex: None,
            keepalive: None,
            last_activity: Instant::now(),
            missed_keepalives: 0,
            banner_lines: 0,
            banner_total: 0,
        }
    }

    /// Override the re-key thresholds (defaults to [`RekeyPolicy::default`]).
    pub fn set_rekey_policy(&mut self, policy: RekeyPolicy) {
        self.rekey_policy = policy;
    }

    /// Enable server keepalive (`ClientAliveInterval` / `ClientAliveCountMax`):
    /// after `interval` of inbound silence, [`handle_timeout`](Self::handle_timeout)
    /// emits a `keepalive@openssh.com` global request, failing the connection
    /// after `count_max` unanswered probes.
    pub fn set_keepalive(&mut self, interval: Duration, count_max: u32) {
        self.keepalive = Some((interval, count_max));
    }

    /// Emit the local version line and the initial KEXINIT (with the
    /// `ext-info-s` marker and queued outbound EXT_INFO). `now` seeds the
    /// keepalive clock. Call once, before pumping.
    pub fn start(&mut self, now: Instant) -> Result<()> {
        self.last_activity = now;
        self.outbox.push_back(VersionExchange::outgoing_bytes());
        let advert = build_server_kexinit(&mut self.rng, &self.cfg).with_ext_info_marker(Role::Server);
        self.runner = KexRunner::new(Role::Server, advert);
        // Queue our outbound EXT_INFO; the runner emits it after NEWKEYS iff
        // the client also advertised the marker.
        self.runner.set_outbound_ext_info(server_ext_info());
        let initial = self.runner.start(&mut self.rng)?;
        for p in initial.outbound {
            self.enqueue_payload(&p)?;
        }
        Ok(())
    }

    // --- accessors ---

    /// The session identifier (KEX exchange hash `H`). Empty until handshake.
    pub fn session_id(&self) -> &[u8] {
        &self.session_id
    }

    /// The peer's negotiated EXT_INFO, if any.
    pub fn peer_ext_info(&self) -> Option<&ExtInfo> {
        self.runner.peer_ext_info()
    }

    /// True once the handshake has completed (post-NEWKEYS).
    pub fn handshake_done(&self) -> bool {
        self.phase == Phase::PostKex
    }

    /// True while a key exchange is in flight.
    pub fn is_kexing(&self) -> bool {
        self.runner.is_kexing()
    }

    /// Notify the driver that userauth has just succeeded: activate
    /// `zlib@openssh.com` compression (RFC 4253 §6.2). The frontend calls this
    /// once its `ServerAuth` reports `Authenticated`, before the next packet.
    pub fn notify_auth_success(&mut self) {
        self.codec.activate_compress();
    }

    // --- pump surface ---

    /// Encode `payload` with the current keys and queue it for transmission.
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

    /// Feed inbound transport bytes; decode and route as many packets as are
    /// available. `now` advances the keepalive activity clock.
    pub fn handle_input(&mut self, bytes: &[u8], now: Instant) -> Result<()> {
        self.inbox.extend_from_slice(bytes);
        if self.inbox.len() > MAX_INBOX_BYTES {
            return Err(Error::Protocol("inbound buffer too large"));
        }
        if self.phase == Phase::AwaitingVersion && !self.scan_peer_version()? {
            return Ok(());
        }
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

    /// Drive re-key and keepalive timers. Returns `Err` if keepalive has gone
    /// unanswered past `count_max`.
    pub fn handle_timeout(&mut self, now: Instant) -> Result<()> {
        if self.runner.is_kexing() {
            return Ok(());
        }
        if let Some(last) = self.last_kex
            && self.rekey_policy.should_rekey(&self.codec, last, now)
        {
            self.initiate_rekey()?;
            return Ok(());
        }
        if let Some((interval, count_max)) = self.keepalive
            && now.duration_since(self.last_activity) >= interval
        {
            if self.missed_keepalives >= count_max {
                return Err(Error::Protocol("keepalive: no response from peer"));
            }
            let probe = keepalive_request();
            self.enqueue_payload(&probe)?;
            self.missed_keepalives += 1;
            self.last_activity = now;
        }
        Ok(())
    }

    /// When the frontend should next call [`handle_timeout`](Self::handle_timeout).
    pub fn next_timeout(&self) -> Option<Instant> {
        self.keepalive
            .map(|(interval, _)| self.last_activity + interval)
    }

    // --- internal routing ---

    fn scan_peer_version(&mut self) -> Result<bool> {
        loop {
            let Some(pos) = self.inbox.iter().position(|&b| b == b'\n') else {
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
                self.v_c = parsed.into_bytes();
                self.phase = Phase::Kex;
                return Ok(true);
            }
            self.banner_lines += 1;
            if self.banner_lines > MAX_BANNER_LINES {
                return Err(Error::Protocol("peer banner too long"));
            }
        }
    }

    fn route_packet(&mut self, payload: &[u8], now: Instant) -> Result<()> {
        self.note_activity(now);
        match payload.first().copied() {
            Some(1) => Err(Error::Protocol("peer sent SSH_MSG_DISCONNECT")),
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
                        self.phase = Phase::PostKex;
                        self.events.push_back(Event::HandshakeComplete);
                    }
                    self.last_kex = Some(now);
                    self.drain_deferred()?;
                }
                Ok(())
            }
            _ => {
                if self.runner.is_kexing() {
                    self.deferred.push_back(payload.to_vec());
                    return Ok(());
                }
                self.runner.note_inbound_other();
                self.events.push_back(Event::AppData(payload.to_vec()));
                Ok(())
            }
        }
    }

    /// Feed one KEX packet into the runner, selecting the host key for the
    /// negotiated algorithm, and enqueue its output. (`v_s` is our own version;
    /// `v_c` is the client's, parsed during the banner scan.)
    fn route_kex(&mut self, payload: &[u8]) -> Result<()> {
        // Select the host key once the algorithms are negotiated.
        let hk_owned: Option<&(dyn HostKey + Send + Sync)> = match self.runner.negotiated() {
            Some(neg) => {
                let hk = pick_host_key(&self.cfg.host_keys, &neg.host_key);
                if hk.is_none() {
                    return Err(Error::Protocol("kex: no host key for negotiated algorithm"));
                }
                hk
            }
            None => None,
        };
        let hk_ref: Option<&dyn HostKey> = hk_owned.map(|k| k as &dyn HostKey);
        let v_c = self.v_c.clone();
        let v_s = crate::transport::version::LOCAL_VERSION.as_bytes().to_vec();
        let adv = self.runner.on_packet(
            &mut self.rng,
            &mut self.codec,
            payload,
            hk_ref,
            None,
            &v_c,
            &v_s,
        )?;
        for p in adv.outbound {
            self.enqueue_payload(&p)?;
        }
        Ok(())
    }

    fn drain_deferred(&mut self) -> Result<()> {
        while !self.runner.is_kexing() {
            let Some(payload) = self.deferred.pop_front() else {
                break;
            };
            self.runner.note_inbound_other();
            self.events.push_back(Event::AppData(payload));
        }
        Ok(())
    }

    fn initiate_rekey(&mut self) -> Result<()> {
        let advert = build_server_kexinit(&mut self.rng, &self.cfg);
        let adv = self.runner.restart(&mut self.rng, advert)?;
        for p in adv.outbound {
            self.enqueue_payload(&p)?;
        }
        Ok(())
    }

    fn note_activity(&mut self, now: Instant) {
        self.last_activity = now;
        self.missed_keepalives = 0;
    }
}

// `OsRng` is `CryptoRng + RngCore`; assert the bounds we rely on.
const _: fn() = || {
    fn _assert<T: CryptoRng + RngCore>() {}
    _assert::<OsRng>();
};

// End-to-end: act as the server *frontend* over a `ServerDriver` (handshake)
// plus a frontend-owned `ServerAuth` and `ConnectionState`, against the real
// blocking `Client` (connect → publickey auth → exec). This proves the
// server-side sans-IO engine symmetrically to the client driver test.
#[cfg(all(test, feature = "client"))]
mod tests {
    use super::*;
    use alloc::string::{String, ToString};
    use std::io::{Read as _, Write as _};
    use std::net::TcpListener;
    use std::sync::Arc;
    use std::thread;
    use std::time::Duration;

    use crate::auth::{AuthAttempt, AuthDecision, Authenticator, ServerAuth, ServerStep};
    use crate::channel::{ChannelEvent, ChannelOpen, ChannelRequest, ConnectionState};
    use crate::client::{Client, Config as ClientConfig};
    use crate::hostkey::{Ed25519HostKey, HostKey};
    use crate::server::{
        AuthenticatorFactory, CommandHandler, Config as ServerConfig, ExecResult, SessionEnv,
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

    struct UnusedHandler;
    impl CommandHandler for UnusedHandler {
        fn handle(&self, _u: &str, _e: &SessionEnv, _c: &str) -> ExecResult {
            ExecResult {
                stdout: Vec::new(),
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
    fn server_driver_handshake_auth_exec_round_trip() {
        let host_seed = fresh_seed();
        let client_seed = fresh_seed();
        let client_key = Ed25519HostKey::from_seed(client_seed);
        let client_blob = client_key.public_blob();
        let user = "srv-driver-user".to_string();
        let reply = b"server driver says hi\n".to_vec();

        // Server config — only host keys + algorithms are used by the driver.
        let host_key: Box<dyn HostKey + Send + Sync> =
            Box::new(Ed25519HostKey::from_seed(host_seed));
        let factory: Arc<dyn AuthenticatorFactory> =
            Arc::new(|| Box::new(UnusedHandlerAuth) as Box<dyn Authenticator>);
        let cfg = Arc::new(ServerConfig::new(
            vec![host_key],
            factory,
            vec!["publickey"],
            Arc::new(UnusedHandler),
        ));

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");

        // Blocking client on a thread: connect, auth, exec, report output.
        let cu = user.clone();
        let client_thread = thread::spawn(move || -> ExecResultOut {
            let mut client =
                Client::connect(addr, ClientConfig::insecure()).expect("client connect");
            client
                .authenticate_publickey(&cu, Box::new(Ed25519HostKey::from_seed(client_seed)))
                .expect("auth");
            let out = client.exec("hi").expect("exec");
            ExecResultOut {
                stdout: out.stdout,
                exit: out.exit_status,
            }
        });

        // We are the server frontend.
        let (mut sock, _peer) = listener.accept().expect("accept");
        sock.set_read_timeout(Some(Duration::from_millis(50))).unwrap();
        let mut driver = ServerDriver::new(cfg.clone());
        driver.start(Instant::now()).expect("start");

        let mut server_auth: Option<ServerAuth> = None;
        let mut conn = ConnectionState::new();
        let mut authed = false;
        let mut session_ch: Option<u32> = None;
        let mut responded = false;
        let mut remote_close = false;

        macro_rules! flush {
            () => {
                while let Some(frame) = driver.poll_transmit() {
                    sock.write_all(&frame).expect("write");
                }
            };
        }

        'pump: for _ in 0..200_000 {
            flush!();
            while let Some(ev) = driver.poll_event() {
                match ev {
                    Event::HandshakeComplete => {
                        let auth = ServerAuth::new(
                            driver.session_id().to_vec(),
                            vec!["publickey"],
                            Box::new(OneKeyAuth {
                                user: user.clone(),
                                blob: client_blob.clone(),
                            }),
                        );
                        server_auth = Some(auth);
                    }
                    Event::AppData(payload) if !authed => {
                        let a = server_auth.as_mut().unwrap();
                        match a.on_packet(&payload).expect("auth on_packet") {
                            ServerStep::Send(p) => driver.enqueue_payload(&p).expect("enq"),
                            ServerStep::Authenticated { payload, .. } => {
                                driver.enqueue_payload(&payload).expect("enq");
                                driver.notify_auth_success();
                                authed = true;
                            }
                            ServerStep::Disconnect(_) => panic!("auth disconnect"),
                        }
                    }
                    Event::AppData(payload) => {
                        match conn.on_packet(&payload).expect("on_packet") {
                            ChannelEvent::OpenRequest { channel, kind } => {
                                if matches!(kind, ChannelOpen::Session) {
                                    let p = conn.accept_open(channel).expect("accept");
                                    driver.enqueue_payload(&p).expect("enq");
                                    session_ch = Some(channel);
                                }
                            }
                            ChannelEvent::Request {
                                channel,
                                request,
                                want_reply,
                            } if Some(channel) == session_ch => {
                                if matches!(request, ChannelRequest::Exec { .. }) {
                                    if want_reply {
                                        let p =
                                            conn.send_request_success(channel).expect("succ");
                                        driver.enqueue_payload(&p).expect("enq");
                                    }
                                    // stdout
                                    let (p, _n) =
                                        conn.send_data(channel, &reply).expect("data");
                                    driver.enqueue_payload(&p).expect("enq");
                                    // exit-status 0
                                    let p = conn
                                        .send_request(
                                            channel,
                                            ChannelRequest::ExitStatus { code: 0 },
                                            false,
                                        )
                                        .expect("exit");
                                    driver.enqueue_payload(&p).expect("enq");
                                    // eof + close
                                    let p = conn.send_eof(channel).expect("eof");
                                    driver.enqueue_payload(&p).expect("enq");
                                    let p = conn.send_close(channel).expect("close");
                                    driver.enqueue_payload(&p).expect("enq");
                                    responded = true;
                                }
                            }
                            ChannelEvent::Close { channel } if Some(channel) == session_ch => {
                                remote_close = true;
                            }
                            _ => {}
                        }
                    }
                }
            }
            flush!();
            if responded && remote_close {
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

        let out = client_thread.join().expect("client thread");
        assert_eq!(out.stdout, reply, "exec stdout round-trips through the server driver");
        assert_eq!(out.exit, Some(0));
        let _ = sock;
    }

    struct ExecResultOut {
        stdout: Vec<u8>,
        exit: Option<u32>,
    }

    // Placeholder authenticator for the server Config (the driver never uses
    // it — the test drives ServerAuth with OneKeyAuth directly).
    struct UnusedHandlerAuth;
    impl Authenticator for UnusedHandlerAuth {
        fn evaluate(&mut self, _a: AuthAttempt) -> AuthDecision {
            AuthDecision::Reject
        }
    }
}
