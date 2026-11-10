//! A `ClientChannelStream` write that waits for send window must not buffer
//! inbound channel data without limit: a server that streams data while
//! never granting window for the client's writes makes the write fail once
//! the unread backlog passes a hard cap.

#![cfg(all(feature = "client", feature = "server"))]
// The borrow-based `Client::open_direct_tcpip` is the API under test.
#![allow(deprecated)]

use std::io::{Read, Write};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;

use puressh::auth::{AuthAttempt, AuthDecision, Authenticator};
use puressh::client::{Client, Config as ClientConfig, HostKeyPolicy};
use puressh::hostkey::{Ed25519HostKey, HostKey};
use puressh::server::{
    AuthenticatorFactory, CommandHandler, Config as ServerConfig, DirectTcpipHandler,
    DirectTcpipRequest, ExecResult, Server, SessionEnv,
};
use puressh::stream::ChannelStream;

struct AcceptKey;

impl Authenticator for AcceptKey {
    fn evaluate(&mut self, attempt: AuthAttempt) -> AuthDecision {
        match attempt {
            AuthAttempt::PublicKey {
                probe_only,
                verified,
                ..
            } if probe_only || verified => AuthDecision::Accept,
            _ => AuthDecision::Reject,
        }
    }
}

struct NoExec;

impl CommandHandler for NoExec {
    fn handle(&self, _user: &str, _env: &SessionEnv, _command: &str) -> ExecResult {
        ExecResult::new(Vec::new(), Vec::new(), 0)
    }
}

/// Streams data at the client and never reads what the client sends, so the
/// client's send window is never re-opened.
struct Flood {
    stop: Arc<AtomicBool>,
}

impl DirectTcpipHandler for Flood {
    fn handle(
        &self,
        _user: &str,
        _request: DirectTcpipRequest<'_>,
        mut stream: ChannelStream,
    ) -> puressh::Result<()> {
        let chunk = vec![0x5au8; 32 * 1024];
        while !self.stop.load(Ordering::SeqCst) {
            if stream.write_all(&chunk).is_err() {
                break;
            }
        }
        Ok(())
    }
}

#[test]
fn write_wait_fails_instead_of_buffering_a_flood() {
    let mut seed = [0u8; 32];
    purecrypto::rng::RngCore::fill_bytes(&mut purecrypto::rng::OsRng, &mut seed);
    let host_key: Box<dyn HostKey + Send + Sync> = Box::new(Ed25519HostKey::from_seed(seed));
    let factory: Arc<dyn AuthenticatorFactory> =
        Arc::new(|| -> Box<dyn Authenticator> { Box::new(AcceptKey) });
    let stop = Arc::new(AtomicBool::new(false));
    let cfg = ServerConfig::new(vec![host_key], factory, vec!["publickey"], Arc::new(NoExec))
        .with_direct_tcpip(Arc::new(Flood { stop: stop.clone() }));
    let mut server = Server::bind("127.0.0.1:0", cfg).expect("bind");
    let addr = server.local_addr().expect("addr");
    let server_thread = thread::spawn(move || {
        let _ = server.accept_one();
    });

    let mut client = Client::connect(
        addr,
        ClientConfig::new(HostKeyPolicy::AcceptAny).with_timeout(Duration::from_secs(30)),
    )
    .expect("connect");
    let key: Box<dyn HostKey + Send> = Box::new(Ed25519HostKey::from_seed([7u8; 32]));
    client.authenticate_publickey("u", key).expect("auth");

    let mut ch = client
        .open_direct_tcpip("127.0.0.1", 1, "127.0.0.1", 0)
        .expect("open direct-tcpip");
    // The handler never reads, so only a bounded amount is ever accepted;
    // without the cap this loop would buffer the flood until memory ran
    // out (or the 256 MiB budget below was written).
    let chunk = vec![0u8; 64 * 1024];
    let mut written = 0usize;
    let err = loop {
        match ch.write(&chunk) {
            Ok(n) => written += n,
            Err(e) => break e,
        }
        assert!(
            written < 256 * 1024 * 1024,
            "the server was expected to stop granting window"
        );
    };
    assert!(
        err.to_string().contains("without opening its window"),
        "unexpected error: {err}"
    );
    // The data queued before the cap is still readable.
    let mut buf = [0u8; 1024];
    assert!(ch.read(&mut buf).expect("read") > 0);

    stop.store(true, Ordering::SeqCst);
    drop(ch);
    drop(client);
    let _ = server_thread.join();
}
