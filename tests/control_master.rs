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

/// `run_master_daemon` (the entry point the ControlPersist fork() child calls):
/// it must serve mux clients with no foreground session and, under
/// `Persist::Seconds`, exit after the linger window once the last client
/// detaches. We exercise it in a thread rather than a real fork (the test
/// harness is multi-threaded, where fork() is unsafe); the daemon's blocking +
/// teardown semantics are what we verify here. The fork()+setsid() wrapper is
/// covered by the manual check documented in `become_master`/`daemonize_master`.
#[test]
fn run_master_daemon_serves_then_exits_after_idle() {
    let srv = spawn_server(b"daemon-banner\n");
    let shared = connect_and_auth(&srv);
    assert_eq!(srv.accepts.load(Ordering::SeqCst), 1, "one auth at master");

    let sock = unique_socket_path("daemon");
    let cfg = MasterConfig {
        control_path: sock.clone(),
        persist: Persist::Seconds(1),
    };

    // run_master_daemon blocks until shutdown, so drive it from a thread.
    let daemon = thread::spawn(move || {
        let _ = puressh::mux::run_master_daemon(cfg, shared);
    });

    // Master should come up.
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if puressh::mux::probe_master(&sock) == ProbeOutcome::Live {
            break;
        }
        assert!(Instant::now() < deadline, "daemon master never came up");
        thread::sleep(Duration::from_millis(20));
    }

    // A mux client runs a command over the daemon's connection — no 2nd auth.
    let req = SessionRequest {
        want_pty: false,
        term: String::new(),
        cols: 0,
        rows: 0,
        env: vec![],
        command: Some("echo hi".into()),
    };
    let status = puressh::mux::run_client(&sock, &req, None).expect("mux client run");
    assert_eq!(status, 0, "remote exec exit status over daemon");
    assert_eq!(
        srv.accepts.load(Ordering::SeqCst),
        1,
        "daemon mux client must not trigger a second auth"
    );

    // After the client detaches, the 1s linger elapses and the daemon unlinks
    // the socket and returns (its thread joins).
    let gone_by = Instant::now() + Duration::from_secs(6);
    while sock.exists() {
        assert!(
            Instant::now() < gone_by,
            "daemon master did not exit after idle linger"
        );
        thread::sleep(Duration::from_millis(50));
    }
    let _ = daemon.join();

    drop(srv.accepts);
    let _ = srv.handle.join();
}

/// Like [`spawn_server`] but permits `direct-tcpip` so a mux client can carry
/// `ssh -L` / `-D` forwards over the master's connection.
fn spawn_server_direct_tcpip(banner: &[u8]) -> TestServer {
    use puressh::forwarding::direct::DefaultDirectTcpipHandler;
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
    )
    .with_direct_tcpip(Arc::new(DefaultDirectTcpipHandler::permit_all()));

    let mut server = Server::bind("127.0.0.1:0", cfg).expect("bind server");
    let addr = server.local_addr().expect("server addr");
    let handle = thread::spawn(move || {
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

/// A tiny loopback echo server — the `-L` forward destination. Returns its
/// port and a join handle.
fn spawn_echo_server() -> (u16, thread::JoinHandle<()>) {
    use std::io::{Read, Write};
    use std::net::TcpListener;
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind echo");
    let port = listener.local_addr().unwrap().port();
    let handle = thread::spawn(move || {
        if let Ok((mut sock, _)) = listener.accept() {
            let mut buf = [0u8; 1024];
            loop {
                match sock.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        if sock.write_all(&buf[..n]).is_err() {
                            break;
                        }
                    }
                }
            }
        }
    });
    (port, handle)
}

/// `ssh -L` over a mux client: stand up a master, then use the `open_forward`
/// and `splice_forward` mux entry points (the exact calls the `ssh` binary's
/// `run_mux_forwarding` makes) to tunnel a TCP connection to a loopback echo
/// server through the master's SSH connection, without a second auth.
#[test]
fn local_forward_over_mux_client() {
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};

    let srv = spawn_server_direct_tcpip(b"unused\n");
    let shared = connect_and_auth(&srv);
    assert_eq!(srv.accepts.load(Ordering::SeqCst), 1, "one auth at master");

    let (echo_port, echo_handle) = spawn_echo_server();

    let sock = unique_socket_path("lforward");
    let release = Arc::new(AtomicBool::new(false));
    let fg_release = release.clone();
    let cfg = MasterConfig {
        control_path: sock.clone(),
        persist: Persist::No,
    };
    let master = thread::spawn(move || {
        puressh::mux::run_master(cfg, shared, move |_s| {
            while !fg_release.load(Ordering::SeqCst) {
                thread::sleep(Duration::from_millis(10));
            }
            0
        })
    });

    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if puressh::mux::probe_master(&sock) == ProbeOutcome::Live {
            break;
        }
        assert!(Instant::now() < deadline, "master never came up");
        thread::sleep(Duration::from_millis(20));
    }

    // Simulate one accepted `-L` connection via a loopback socket pair.
    let acceptor = TcpListener::bind("127.0.0.1:0").expect("bind local -L");
    let local_port = acceptor.local_addr().unwrap().port();
    let client_side = TcpStream::connect(("127.0.0.1", local_port)).expect("connect local -L");
    let (server_side, _) = acceptor.accept().expect("accept local -L");

    // Forward worker: open_forward to the echo server, splice the accepted
    // socket against the forward.
    let mux_path = sock.clone();
    let worker = thread::spawn(move || {
        let fwd = puressh::mux::open_forward(&mux_path, "127.0.0.1", echo_port, "127.0.0.1", 0)
            .expect("open_forward over mux");
        let _ = puressh::mux::splice_forward(fwd, server_side);
    });

    let mut client_side = client_side;
    client_side.write_all(b"mux -L works").expect("write");
    let mut buf = [0u8; 12];
    client_side.read_exact(&mut buf).expect("read echo");
    assert_eq!(&buf, b"mux -L works");

    assert_eq!(
        srv.accepts.load(Ordering::SeqCst),
        1,
        "mux forward must not trigger a second auth"
    );

    drop(client_side);
    let _ = worker.join();
    release.store(true, Ordering::SeqCst);
    let _ = master.join().expect("master thread");
    let _ = echo_handle.join();
    drop(srv.accepts);
    let _ = srv.handle.join();
}
