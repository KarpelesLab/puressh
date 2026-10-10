//! End-to-end knock tests: a `KnockServer` in front of the library SSH server,
//! a client reaching it with `connect_or_knock`, then a full SSH session
//! (KEX pinned to the ACCEPT's host key + publickey auth + exec).

#![cfg(all(feature = "client", feature = "server", feature = "knock"))]

use std::net::{SocketAddr, TcpListener};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use purecrypto::rng::{OsRng, RngCore};
use puressh::auth::{AuthAttempt, AuthDecision, Authenticator};
use puressh::client::{
    Client, Config as ClientConfig, HostKeyPolicy, KnownHostsPolicy, TofuAction,
};
use puressh::hostkey::{Ed25519HostKey, HostKey};
use puressh::knock::{
    Connected, KnockConnectOptions, KnockIdentity, KnockKeyTable, KnockMode, KnockRequest,
    KnockServer, KnockServerConfig, KnockState, connect_or_knock, unix_ms,
};
use puressh::known_hosts::KnownHosts;
use puressh::server::{
    AuthenticatorFactory, CommandHandler, Config as ServerConfig, ExecResult, SessionEnv,
    handle_session_with_peer,
};

const USER: &str = "knocker";

fn seed() -> [u8; 32] {
    let mut s = [0u8; 32];
    OsRng.fill_bytes(&mut s);
    s
}

struct Echo;
impl CommandHandler for Echo {
    fn handle(&self, user: &str, _env: &SessionEnv, command: &str) -> ExecResult {
        ExecResult::new(format!("{user}:{command}").into_bytes(), Vec::new(), 0)
    }
}

struct OneKeyAuth {
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
            } if user == USER && public_blob == self.blob && (probe_only || verified) => {
                AuthDecision::Accept
            }
            _ => AuthDecision::Reject,
        }
    }
}

/// Start a knock server whose UDP port has no TCP listener (so plain TCP is
/// refused and the client must knock). Each knocked connection is served as
/// an SSH session. Returns the shared port.
fn spawn(host_seed: [u8; 32], client_seed: [u8; 32]) -> Option<u16> {
    let user_blob = Ed25519HostKey::from_seed(client_seed).public_blob();
    let mut table = KnockKeyTable::new();
    table.insert(USER, user_blob.clone());
    let state = KnockState::new(
        KnockServerConfig::default(),
        table,
        vec![Arc::new(Ed25519HostKey::from_seed(host_seed))],
        unix_ms() - 1000,
    );
    let mut ks = KnockServer::bind("127.0.0.1:0", state).unwrap();
    let port = ks.local_addr().unwrap().port();
    if TcpListener::bind(("127.0.0.1", port)).is_err() {
        return None; // TCP twin port taken; can't simulate "refused"
    }
    let factory: Arc<dyn AuthenticatorFactory> = Arc::new(move || -> Box<dyn Authenticator> {
        Box::new(OneKeyAuth {
            blob: user_blob.clone(),
        })
    });
    let cfg = Arc::new(ServerConfig::new(
        vec![Box::new(Ed25519HostKey::from_seed(host_seed))],
        factory,
        vec!["publickey"],
        Arc::new(Echo),
    ));
    thread::spawn(move || {
        let _ = ks.run(|c| {
            let cfg = cfg.clone();
            thread::spawn(move || {
                let _ = handle_session_with_peer(c.stream, c.peer, cfg);
            });
        });
    });
    Some(port)
}

fn connect(
    port: u16,
    client_seed: [u8; 32],
    known: Vec<Vec<u8>>,
    mode: KnockMode,
) -> puressh::Result<Connected> {
    let key = Ed25519HostKey::from_seed(client_seed);
    let mut req = KnockRequest {
        user: USER,
        identities: vec![KnockIdentity {
            signer: &key,
            sig1: None,
        }],
        known_host_keys: known,
    };
    let mut opts = KnockConnectOptions::default();
    opts.mode = mode;
    opts.connect_timeout = Some(Duration::from_secs(5));
    connect_or_knock("127.0.0.1", port, &mut req, &opts)
}

#[test]
fn ssh_session_over_knock_with_tofu() {
    let (host_seed, client_seed) = (seed(), seed());
    let Some(port) = spawn(host_seed, client_seed) else {
        return;
    };
    let Connected::Knocked { stream, accepted } =
        connect(port, client_seed, Vec::new(), KnockMode::Auto).expect("knock")
    else {
        panic!("TCP should have been refused");
    };
    assert!(!accepted.host_key_known);

    // Unknown host: the usual known_hosts TOFU runs during KEX, keyed by the
    // original host/port, and the pin ties it to the ACCEPT's key.
    let store = Arc::new(Mutex::new(KnownHosts::new()));
    let mut kh = KnownHostsPolicy::strict(store.clone());
    kh.on_unknown = TofuAction::Accept;
    let mut cfg = ClientConfig::new(HostKeyPolicy::KnownHosts(kh));
    cfg.timeout = Some(Duration::from_secs(10));
    accepted.pin(&mut cfg);
    let mut client = Client::connect_via(Box::new(stream), "127.0.0.1", port, cfg).expect("ssh");
    client
        .authenticate_publickey(USER, Box::new(Ed25519HostKey::from_seed(client_seed)))
        .expect("auth");
    let out = client.exec("hi").expect("exec");
    assert_eq!(out.stdout, format!("{USER}:hi").into_bytes());
    let host_blob = Ed25519HostKey::from_seed(host_seed).public_blob();
    assert_eq!(store.lock().unwrap().find("127.0.0.1", port).len(), 1);

    // Second time the host key is known: the knock sends host_fp and the
    // ACCEPT carries no key blob.
    let Connected::Knocked { stream, accepted } = connect(
        port,
        client_seed,
        vec![host_blob.clone()],
        KnockMode::Always,
    )
    .expect("knock 2") else {
        panic!("expected knock");
    };
    assert!(accepted.host_key_known);
    let mut cfg = ClientConfig::new(HostKeyPolicy::KnownHosts(KnownHostsPolicy::strict(store)));
    accepted.pin(&mut cfg);
    let mut client = Client::connect_via(Box::new(stream), "127.0.0.1", port, cfg).expect("ssh 2");
    client
        .authenticate_publickey(USER, Box::new(Ed25519HostKey::from_seed(client_seed)))
        .expect("auth 2");
}

#[test]
fn unauthorized_key_gets_no_answer() {
    let (host_seed, client_seed) = (seed(), seed());
    let Some(port) = spawn(host_seed, client_seed) else {
        return;
    };
    let start = std::time::Instant::now();
    let r = connect(port, seed(), Vec::new(), KnockMode::Auto);
    let err = r.expect_err("must fail");
    // The plain-TCP error is what surfaces, after the knock gave up.
    assert!(
        matches!(&err, puressh::Error::Io(e) if e.kind() == std::io::ErrorKind::ConnectionRefused),
        "{err:?}"
    );
    assert!(start.elapsed() >= Duration::from_secs(2));
}

#[test]
fn pin_rejects_a_different_host_key() {
    // A plain SSH server (no knock) presenting key A; the client pins key B.
    let host_seed = seed();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr: SocketAddr = listener.local_addr().unwrap();
    let factory: Arc<dyn AuthenticatorFactory> =
        Arc::new(|| -> Box<dyn Authenticator> { Box::new(OneKeyAuth { blob: Vec::new() }) });
    let cfg = Arc::new(ServerConfig::new(
        vec![Box::new(Ed25519HostKey::from_seed(host_seed))],
        factory,
        vec!["publickey"],
        Arc::new(Echo),
    ));
    thread::spawn(move || {
        if let Ok((s, peer)) = listener.accept() {
            let _ = handle_session_with_peer(s, peer, cfg);
        }
    });
    let mut cfg = ClientConfig::insecure();
    cfg.pinned_host_key = Some(Ed25519HostKey::from_seed(seed()).public_blob());
    let err = Client::connect(addr, cfg).err().expect("must fail");
    assert!(matches!(err, puressh::Error::HostKeyRejected), "{err:?}");
}
