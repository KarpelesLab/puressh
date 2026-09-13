//! Sans-IO connection drivers.
//!
//! The protocol layers ([`crate::hazmat`]: `format`, `transport`, `channel`,
//! `auth`) are already sans-IO: they operate on byte buffers and never touch
//! sockets. This module
//! lifts the *orchestration* — the state machine that sequences version
//! exchange → key exchange → authentication → application channels, drives
//! re-key/keepalive timers, and accumulates/decodes inbound bytes — out of the
//! blocking [`crate::client::Client`] into a transport-agnostic driver.
//!
//! A driver never reads or writes a socket, never spawns a thread, and never
//! calls `Instant::now()`. The caller (a "frontend") does the I/O and clock:
//!
//! - feed inbound wire bytes with [`ClientDriver::handle_input`];
//! - drain fully-encoded outbound frames with [`ClientDriver::poll_transmit`];
//! - pull high-level [`Event`]s with [`ClientDriver::poll_event`];
//! - advance timers with [`ClientDriver::handle_timeout`] /
//!   [`ClientDriver::next_timeout`].
//!
//! This makes the same core reusable from a blocking frontend (the existing
//! [`crate::client::Client`]) and an async one, with no duplicated protocol
//! logic. See [`client::ClientDriver`] and [`server::ServerDriver`].

#[cfg(feature = "client")]
pub mod client;
#[cfg(feature = "server")]
pub mod server;

#[cfg(feature = "client")]
pub use client::{ClientDriver, VerifierFactory};
#[cfg(feature = "server")]
pub use server::ServerDriver;

// The two transport-level knobs a frontend needs to configure a driver. They
// are defined in `hazmat::transport` but documented here because the
// `client::Config` / `server::Config` setters take them by value.
pub use crate::hazmat::transport::{ext_info::ExtInfo, rekey::RekeyPolicy};

use alloc::collections::VecDeque;
use alloc::vec::Vec;

use crate::channel::{GlobalRequest, MSG_GLOBAL_REQUEST};
use crate::error::{Error, Result};
use crate::format::Writer;

// Transport-routing message bytes and buffer caps shared by both drivers.
/// `SSH_MSG_KEX_ECDH_REPLY` — the KEX message carrying the host key.
pub(crate) const SSH_MSG_KEX_ECDH_REPLY: u8 = 31;
pub(crate) const SSH_MSG_KEXINIT: u8 = 20;
pub(crate) const SSH_MSG_EXT_INFO: u8 = 7;
pub(crate) const MAX_INBOX_BYTES: usize = 8 * 1024 * 1024;
/// Cap on egress buffered while a key exchange is in flight. A re-key settles
/// in milliseconds, so anything approaching this means the KEX has wedged and
/// we would rather fail than grow without bound.
pub(crate) const MAX_DEFERRED_OUT_BYTES: usize = 8 * 1024 * 1024;
/// Cap on inbound application packets buffered while a re-key is in flight
/// (traffic the peer put on the wire before it saw our KEXINIT). Same
/// reasoning as [`MAX_DEFERRED_OUT_BYTES`]: the window is short, and a peer
/// that keeps streaming past it is not going to finish the exchange.
pub(crate) const MAX_DEFERRED_IN_BYTES: usize = 8 * 1024 * 1024;
pub(crate) const MAX_BANNER_LINE: usize = 1024;
pub(crate) const MAX_BANNER_LINES: usize = 32;
pub(crate) const MAX_BANNER_TOTAL_BYTES: usize = 64 * 1024;

/// A generic transport message (`IGNORE`, `UNIMPLEMENTED`, `DEBUG`, `PING`,
/// `PONG`) arrived while the *initial* key exchange is in flight.
///
/// Nothing is authenticated yet, so the packet may just as well come from an
/// on-path attacker. Under strict-kex (OpenSSH `PROTOCOL` §1.10, the Terrapin
/// / CVE-2023-48795 mitigation) the only acceptable answer is to terminate:
/// with the sequence counters reset at NEWKEYS an injected packet would
/// otherwise leave no trace. Without strict-kex these messages are dropped
/// on the floor, as OpenSSH does — they carry nothing the application acts
/// on. Note that strict-kex is only known once the peer's KEXINIT has been
/// negotiated; a packet slipped in *before* it is caught by the runner's
/// first-packet check instead.
pub(crate) fn generic_msg_during_initial_kex(strict_kex: bool) -> Result<()> {
    if strict_kex {
        return Err(Error::Protocol(
            "strict-kex: unexpected message during initial key exchange",
        ));
    }
    Ok(())
}

/// Buffer a non-KEX packet received while a re-key is in flight, so it can
/// be replayed to the application once NEWKEYS lands. `queued_bytes` tracks
/// the queue's total against [`MAX_DEFERRED_IN_BYTES`].
pub(crate) fn defer_inbound(
    queue: &mut VecDeque<Vec<u8>>,
    queued_bytes: &mut usize,
    payload: &[u8],
) -> Result<()> {
    *queued_bytes = queued_bytes.saturating_add(payload.len());
    if *queued_bytes > MAX_DEFERRED_IN_BYTES {
        return Err(Error::Protocol("re-key: deferred ingress buffer too large"));
    }
    queue.push_back(payload.to_vec());
    Ok(())
}

/// Build a `keepalive@openssh.com` global-request payload (want_reply = true),
/// without a `ConnectionState` (the encoding is stateless).
pub(crate) fn keepalive_request() -> Vec<u8> {
    let req = GlobalRequest::Keepalive;
    let mut w = Writer::new();
    w.write_u8(MSG_GLOBAL_REQUEST);
    w.write_string(req.name().as_bytes());
    w.write_bool(true);
    req.encode(&mut w);
    w.into_vec()
}

/// A high-level event surfaced by a driver's `poll_event`.
///
/// The driver runs the transport engine (version exchange, KEX, re-key,
/// EXT_INFO/PING handling); once the handshake completes it surfaces every
/// decoded transport payload as [`Event::AppData`] for the frontend. The
/// frontend runs userauth (feeding the auth payloads to its own
/// [`ClientAuth`](crate::auth::ClientAuth)) and then the connection protocol
/// (feeding the rest to its own [`ConnectionState`](crate::channel::ConnectionState)).
/// Transport concerns never surface.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum Event {
    /// The transport handshake (version exchange + first key exchange) has
    /// completed; the connection is keyed and ready for authentication.
    HandshakeComplete,
    /// A decoded post-handshake payload (userauth, then the connection
    /// protocol). The frontend routes it to its auth driver or
    /// [`ConnectionState`](crate::channel::ConnectionState) as appropriate.
    AppData(Vec<u8>),
}

// Re-key behaviour, checked with the two drivers wired back-to-back in
// process (no sockets): application traffic the peer put on the wire before
// it saw our KEXINIT is buffered and replayed after NEWKEYS; anything it
// sends after its own KEXINIT is a protocol violation.
#[cfg(all(test, feature = "client", feature = "server"))]
mod rekey_tests {
    use super::*;
    use std::sync::Arc;
    use std::time::Instant;

    use purecrypto::rng::{OsRng, RngCore};

    use crate::auth::{AuthAttempt, AuthDecision, Authenticator};
    use crate::hostkey::{Ed25519HostKey, HostKey, host_key_verify_by_name};
    use crate::server::{AuthenticatorFactory, CommandHandler, Config, ExecResult, SessionEnv};
    use crate::transport::KexRunner;

    struct RejectAll;
    impl Authenticator for RejectAll {
        fn evaluate(&mut self, _a: AuthAttempt) -> AuthDecision {
            AuthDecision::Reject
        }
    }

    struct NoExec;
    impl CommandHandler for NoExec {
        fn handle(&self, _u: &str, _e: &SessionEnv, _c: &str) -> ExecResult {
            ExecResult {
                stdout: Vec::new(),
                stderr: Vec::new(),
                exit_status: 0,
            }
        }
    }

    fn server_config() -> Arc<Config> {
        let mut seed = [0u8; 32];
        OsRng.fill_bytes(&mut seed);
        let host_key: Box<dyn HostKey + Send + Sync> = Box::new(Ed25519HostKey::from_seed(seed));
        let factory: Arc<dyn AuthenticatorFactory> =
            Arc::new(|| Box::new(RejectAll) as Box<dyn Authenticator>);
        Arc::new(Config::new(
            vec![host_key],
            factory,
            vec!["publickey"],
            Arc::new(NoExec),
        ))
    }

    /// Trust whatever host key the server presents (the test owns both ends).
    fn accept_any_factory() -> VerifierFactory {
        Box::new(|reply: &[u8], runner: &KexRunner| {
            let k_s_len = u32::from_be_bytes([reply[1], reply[2], reply[3], reply[4]]) as usize;
            let k_s = &reply[5..5 + k_s_len];
            let neg = runner
                .negotiated()
                .ok_or(Error::Protocol("kex: no negotiated algorithms"))?;
            host_key_verify_by_name(&neg.host_key, k_s)
        })
    }

    struct Pair {
        client: ClientDriver,
        server: ServerDriver,
        client_events: Vec<Event>,
        server_events: Vec<Event>,
    }

    impl Pair {
        fn collect_events(&mut self) {
            while let Some(ev) = self.client.poll_event() {
                self.client_events.push(ev);
            }
            while let Some(ev) = self.server.poll_event() {
                self.server_events.push(ev);
            }
        }

        /// Deliver everything the client has queued to the server. Returns
        /// how many frames moved.
        fn client_to_server(&mut self) -> Result<usize> {
            let mut moved = 0;
            while let Some(frame) = self.client.poll_transmit() {
                self.server.handle_input(&frame, Instant::now())?;
                moved += 1;
            }
            self.collect_events();
            Ok(moved)
        }

        /// Deliver everything the server has queued to the client. Returns
        /// how many frames moved.
        fn server_to_client(&mut self) -> Result<usize> {
            let mut moved = 0;
            while let Some(frame) = self.server.poll_transmit() {
                self.client.handle_input(&frame, Instant::now())?;
                moved += 1;
            }
            self.collect_events();
            Ok(moved)
        }

        /// Shuttle frames both ways until a full round moves nothing.
        fn pump(&mut self) -> Result<()> {
            for _ in 0..64 {
                let moved = self.client_to_server()? + self.server_to_client()?;
                if moved == 0 {
                    return Ok(());
                }
            }
            panic!("drivers did not go quiet");
        }
    }

    /// Two drivers, handshake complete, event logs cleared.
    fn handshake() -> Pair {
        let mut p = Pair {
            client: ClientDriver::new(Default::default(), accept_any_factory()),
            server: ServerDriver::new(server_config()),
            client_events: Vec::new(),
            server_events: Vec::new(),
        };
        p.client.start(Instant::now()).expect("client start");
        p.server.start(Instant::now()).expect("server start");
        p.pump().expect("handshake");
        assert!(p.client.handshake_done() && p.server.handshake_done());
        assert!(!p.client.is_kexing() && !p.server.is_kexing());
        assert!(matches!(
            p.client_events.as_slice(),
            [Event::HandshakeComplete]
        ));
        assert!(matches!(
            p.server_events.as_slice(),
            [Event::HandshakeComplete]
        ));
        p.client_events.clear();
        p.server_events.clear();
        p
    }

    fn channel_data(body: &[u8]) -> Vec<u8> {
        let mut v = vec![94, 0, 0, 0, 0];
        v.extend_from_slice(&(body.len() as u32).to_be_bytes());
        v.extend_from_slice(body);
        v
    }

    fn app_data_payloads(events: &[Event]) -> Vec<Vec<u8>> {
        events
            .iter()
            .filter_map(|e| match e {
                Event::AppData(p) => Some(p.clone()),
                Event::HandshakeComplete => None,
            })
            .collect()
    }

    fn protocol_err(res: Result<()>) -> &'static str {
        match res {
            Err(Error::Protocol(msg)) => msg,
            other => panic!("expected a protocol error, got {other:?}"),
        }
    }

    /// Client initiates; the server, not yet aware, keeps sending. Its data
    /// is buffered and surfaces once the re-key completes.
    #[test]
    fn client_defers_app_data_that_precedes_the_servers_kexinit() {
        let mut p = handshake();
        p.client.force_rekey().expect("rekey");
        let data = channel_data(b"sent before the server saw our KEXINIT");
        p.server.enqueue_payload(&data).expect("server app data");
        p.server_to_client().expect("deliver");
        assert!(p.client.is_kexing());
        assert!(p.client_events.is_empty(), "held back until NEWKEYS");

        p.pump().expect("re-key");
        assert!(!p.client.is_kexing());
        assert_eq!(app_data_payloads(&p.client_events), vec![data]);
    }

    /// Server initiates; symmetric to the above.
    #[test]
    fn server_defers_app_data_that_precedes_the_clients_kexinit() {
        let mut p = handshake();
        p.server.force_rekey().expect("rekey");
        let data = channel_data(b"sent before the client saw our KEXINIT");
        p.client.enqueue_payload(&data).expect("client app data");
        p.client_to_server().expect("deliver");
        assert!(p.server.is_kexing());
        assert!(p.server_events.is_empty(), "held back until NEWKEYS");

        p.pump().expect("re-key");
        assert!(!p.server.is_kexing());
        assert_eq!(app_data_payloads(&p.server_events), vec![data]);
    }

    /// Regression (T1/L1): once the server's KEXINIT has arrived, application
    /// data from it is a violation of RFC 4253 §7.1, not something to buffer.
    /// `IGNORE` stays acceptable mid-re-key.
    #[test]
    fn client_rejects_app_data_after_the_servers_kexinit() {
        let mut p = handshake();
        p.client.force_rekey().expect("rekey");
        p.client_to_server().expect("client KEXINIT");
        p.server_to_client().expect("server KEXINIT");
        assert!(p.client.is_kexing());

        // Forge frames under the server's live keys, bypassing its egress
        // deferral, to play a peer that ignores the rule.
        let ignore = p
            .server
            .codec_mut()
            .encode(&[2, 0, 0, 0, 0], &mut OsRng)
            .expect("ignore frame");
        p.client
            .handle_input(&ignore, Instant::now())
            .expect("IGNORE is fine during a re-key");
        let data = p
            .server
            .codec_mut()
            .encode(&channel_data(b"late"), &mut OsRng)
            .expect("forged frame");
        let err = protocol_err(p.client.handle_input(&data, Instant::now()));
        assert_eq!(err, "non-KEX message during key re-exchange");
        assert!(p.client.poll_event().is_none());
    }

    /// Regression (T1/L1), server side.
    #[test]
    fn server_rejects_app_data_after_the_clients_kexinit() {
        let mut p = handshake();
        p.server.force_rekey().expect("rekey");
        p.server_to_client().expect("server KEXINIT");
        // The client answers with its KEXINIT + ECDH_INIT; the server ends up
        // waiting for the client's NEWKEYS, well past the deferral window.
        p.client_to_server().expect("client KEXINIT + ECDH_INIT");
        assert!(p.server.is_kexing());

        let ignore = p
            .client
            .codec_mut()
            .encode(&[2, 0, 0, 0, 0], &mut OsRng)
            .expect("ignore frame");
        p.server
            .handle_input(&ignore, Instant::now())
            .expect("IGNORE is fine during a re-key");
        let data = p
            .client
            .codec_mut()
            .encode(&channel_data(b"late"), &mut OsRng)
            .expect("forged frame");
        let err = protocol_err(p.server.handle_input(&data, Instant::now()));
        assert_eq!(err, "non-KEX message during key re-exchange");
        assert!(p.server.poll_event().is_none());
    }

    /// The inbound deferral queue is bounded like the outbound one.
    #[test]
    fn deferred_ingress_is_capped() {
        let mut p = handshake();
        p.client.force_rekey().expect("rekey");
        let chunk = channel_data(&vec![0u8; 32 * 1024]);
        let mut result = Ok(());
        for _ in 0..(MAX_DEFERRED_IN_BYTES / chunk.len() + 2) {
            p.server.enqueue_payload(&chunk).expect("server app data");
            result = p.server_to_client().map(|_| ());
            if result.is_err() {
                break;
            }
        }
        assert_eq!(
            protocol_err(result),
            "re-key: deferred ingress buffer too large"
        );
    }
}
