//! In-process ControlMaster / ControlPath / ControlPersist e2e tests.
//!
//! Stand up a loopback puressh `Server`, connect+auth a single `Client`, hand
//! it to `mux::run_master` (which binds a Unix control socket), then attach a
//! second `mux::run_client` over the same `ControlPath` and run a command. The
//! key assertion is that the client's session reuses the master's existing SSH
//! connection — proven by an auth counter that must remain at exactly 1 even
//! after the second (mux) session runs.
//!
//! Unix-only: the mux module is gated `cfg(all(unix, feature = "client"))`.

#![cfg(all(unix, feature = "client", feature = "server", feature = "multichannel"))]

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use puressh::auth::{AuthAttempt, AuthDecision, Authenticator};
use puressh::client::{Client, Config as ClientConfig, HostKeyPolicy};
use puressh::hostkey::{Ed25519HostKey, HostKey};
use puressh::mux::{MasterConfig, Persist, ProbeOutcome, SessionRequest};
use puressh::server::{
    AuthenticatorFactory, CommandHandler, Config as ServerConfig, ExecResult, Server, SessionEnv,
};
use puressh::shared::SharedClient;

/// Accept one public key for one user, counting successful Accepts so the test
/// can prove the mux client did *not* trigger a second authentication.
struct CountingAuth {
    user: String,
    blob: Vec<u8>,
    accepts: Arc<AtomicUsize>,
}

impl Authenticator for CountingAuth {
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
                    self.accepts.fetch_add(1, Ordering::SeqCst);
                    AuthDecision::Accept
                } else {
                    AuthDecision::Reject
                }
            }
            _ => AuthDecision::Reject,
        }
    }
}

/// Exec handler that echoes back a fixed banner regardless of the command.
struct BannerHandler {
    out: Vec<u8>,
}

impl CommandHandler for BannerHandler {
    fn handle(&self, _user: &str, _env: &SessionEnv, _command: &str) -> ExecResult {
        ExecResult {
            stdout: self.out.clone(),
            stderr: Vec::new(),
            exit_status: 0,
        }
    }
}

fn fresh_seed() -> [u8; 32] {
    use purecrypto::rng::{OsRng, RngCore};
    let mut s = [0u8; 32];
    OsRng.fill_bytes(&mut s);
    s
}

fn client_cfg() -> ClientConfig {
    ClientConfig {
        host_key_policy: HostKeyPolicy::AcceptAny,
        timeout: Some(Duration::from_secs(15)),
        algorithms: Default::default(),
    }
}

struct TestServer {
    addr: std::net::SocketAddr,
    client_seed: [u8; 32],
    user: String,
    accepts: Arc<AtomicUsize>,
    handle: thread::JoinHandle<()>,
}

/// Spawn a loopback server that serves ONE connection for its whole lifetime
/// (multiple channels on that connection are fine). Returns its auth counter.
fn spawn_server(banner: &[u8]) -> TestServer {
    let host_seed = fresh_seed();
    let client_seed = fresh_seed();
    let host_key: Box<dyn HostKey + Send + Sync> = Box::new(Ed25519HostKey::from_seed(host_seed));
    let allowed_blob = Ed25519HostKey::from_seed(client_seed).public_blob();
    let user = "mux-user".to_string();
    let accepts = Arc::new(AtomicUsize::new(0));

    let auth_user = user.clone();
    let auth_blob = allowed_blob.clone();
    let auth_count = accepts.clone();
    let factory: Arc<dyn AuthenticatorFactory> = Arc::new(move || -> Box<dyn Authenticator> {
        Box::new(CountingAuth {
            user: auth_user.clone(),
            blob: auth_blob.clone(),
            accepts: auth_count.clone(),
        })
    });

    let cfg = ServerConfig::new(
        vec![host_key],
        factory,
        vec!["publickey"],
        Arc::new(BannerHandler {
            out: banner.to_vec(),
        }),
    );

    let mut server = Server::bind("127.0.0.1:0", cfg).expect("bind server");
    let addr = server.local_addr().expect("server addr");
    let handle = thread::spawn(move || {
        // One connection, served to completion (it carries every mux channel).
        let _ = server.accept_one();
    });

    TestServer {
        addr,
        client_seed,
        user,
        accepts,
        handle,
    }
}

/// Connect + authenticate a single client against `srv`, returning it wrapped
/// in a `SharedClient` ready for `run_master`.
fn connect_and_auth(srv: &TestServer) -> SharedClient {
    let mut client =
        Client::connect_to_host("127.0.0.1", srv.addr.port(), client_cfg()).expect("connect");
    let hk: Box<dyn HostKey + Send> = Box::new(Ed25519HostKey::from_seed(srv.client_seed));
    client
        .authenticate_publickey(&srv.user, hk)
        .expect("auth master");
    client.into()
}

fn unique_socket_path(tag: &str) -> PathBuf {
    use std::time::{SystemTime, UNIX_EPOCH};
    let pid = std::process::id();
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    std::env::temp_dir().join(format!("puressh-mux-{tag}-{pid}-{nanos}.sock"))
}

#[test]
fn mux_client_reuses_connection_without_second_auth() {
    let srv = spawn_server(b"banner-via-mux\n");
    let shared = connect_and_auth(&srv);
    assert_eq!(
        srv.accepts.load(Ordering::SeqCst),
        1,
        "exactly one auth after the master connects"
    );

    let sock = unique_socket_path("reuse");
    // The foreground blocks until the test flips `release`, keeping the master
    // alive while the mux client attaches and runs.
    let release = Arc::new(AtomicBool::new(false));
    let fg_release = release.clone();
    let cfg = MasterConfig {
        control_path: sock.clone(),
        persist: Persist::No,
    };

    // run_master blocks on the foreground, so drive it from a thread.
    let master = thread::spawn(move || {
        puressh::mux::run_master(cfg, shared, move |_s| {
            while !fg_release.load(Ordering::SeqCst) {
                thread::sleep(Duration::from_millis(10));
            }
            0
        })
    });

    // Wait for the socket to come up and answer HELLO.
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if puressh::mux::probe_master(&sock) == ProbeOutcome::Live {
            break;
        }
        assert!(Instant::now() < deadline, "master never came up");
        thread::sleep(Duration::from_millis(20));
    }

    // Attach a mux client and run a command over the existing connection.
    let req = SessionRequest {
        want_pty: false,
        term: String::new(),
        cols: 0,
        rows: 0,
        env: vec![],
        command: Some("echo hi".into()),
    };
    let status = puressh::mux::run_client(&sock, &req, None).expect("mux client run");
    assert_eq!(status, 0, "remote exec exit status");

    // The crucial assertion: the mux session reused the master's connection,
    // so the server saw NO second authentication.
    assert_eq!(
        srv.accepts.load(Ordering::SeqCst),
        1,
        "mux client must not trigger a second auth"
    );

    // Let the foreground (and thus the master) finish; Persist::No tears it
    // down and unlinks the socket.
    release.store(true, Ordering::SeqCst);
    let _ = master.join().expect("master thread");

    // Socket is gone after a Persist::No teardown.
    assert!(!sock.exists(), "Persist::No unlinks the control socket");

    drop(srv.accepts);
    let _ = srv.handle.join();
}

#[test]
fn control_persist_seconds_master_exits_after_idle() {
    let srv = spawn_server(b"x\n");
    let shared = connect_and_auth(&srv);

    let sock = unique_socket_path("persist");
    let cfg = MasterConfig {
        control_path: sock.clone(),
        // Linger 1 second after the (immediately-finishing) foreground +
        // last client detach, then unlink and exit.
        persist: Persist::Seconds(1),
    };

    // Foreground returns immediately; under Persist::Seconds the master keeps
    // serving in detached threads, so run_master returns promptly here.
    let _ = puressh::mux::run_master(cfg, shared, |_s| 0).expect("run_master");

    // Master should be live right away.
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if puressh::mux::probe_master(&sock) == ProbeOutcome::Live {
            break;
        }
        assert!(Instant::now() < deadline, "master never came up");
        thread::sleep(Duration::from_millis(20));
    }

    // After the linger window with no clients, the reaper unlinks the socket
    // and exits. Poll until the socket disappears (with generous slack for the
    // 200ms reaper tick + 1s linger).
    let gone_by = Instant::now() + Duration::from_secs(6);
    while sock.exists() {
        assert!(
            Instant::now() < gone_by,
            "ControlPersist=1 master did not exit after idle"
        );
        thread::sleep(Duration::from_millis(50));
    }

    drop(srv.accepts);
    let _ = srv.handle.join();
}
