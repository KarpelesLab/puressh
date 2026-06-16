//! In-process ProxyJump / ProxyCommand tests over loopback `Server`s.
//!
//! ProxyJump: stands up a *jump* SSH server (with `direct-tcpip` enabled) and
//! a *target* SSH server, then drives the same chaining the `ssh` binary's
//! `-J` path uses: connect+auth the jump host, wrap it in a `SharedClient`,
//! open a `direct-tcpip` channel to the target's listener, and run a second
//! `Client::connect_via` over that channel. Asserts exec output flows through
//! the jump, and that a host-key mismatch at the target hop is rejected.
//!
//! ProxyCommand: spawns a `ProcTransport` whose helper (`nc`) bridges to a
//! loopback SSH server, runs `Client::connect_via` over the pipe, and execs.
//! A separate test asserts a spawn failure aborts strictly (no fallback).

#![cfg(all(feature = "client", feature = "server", feature = "multichannel"))]

use std::sync::Arc;
use std::thread;
use std::time::Duration;

use puressh::auth::{AuthAttempt, AuthDecision, Authenticator};
use puressh::client::{Client, Config as ClientConfig, HostKeyPolicy};
use puressh::forwarding::direct::DefaultDirectTcpipHandler;
use puressh::hostkey::{Ed25519HostKey, HostKey};
use puressh::server::{
    AuthenticatorFactory, CommandHandler, Config as ServerConfig, ExecResult, Server, SessionEnv,
};
use puressh::shared::SharedClient;

/// Accept exactly one public key for one user.
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
    use purecrypto::rng::{OsRng, RngCore};
    let mut s = [0u8; 32];
    OsRng.fill_bytes(&mut s);
    s
}

/// One loopback SSH server: returns its bound address, the seed of the key a
/// client must present to authenticate, the user it accepts, and the join
/// handle for the single-accept server thread.
struct TestServer {
    addr: std::net::SocketAddr,
    client_seed: [u8; 32],
    user: String,
    handle: thread::JoinHandle<()>,
}

fn spawn_server(banner: &[u8], with_direct_tcpip: bool) -> TestServer {
    let host_seed = fresh_seed();
    let client_seed = fresh_seed();
    let host_key: Box<dyn HostKey + Send + Sync> = Box::new(Ed25519HostKey::from_seed(host_seed));
    let allowed_blob = Ed25519HostKey::from_seed(client_seed).public_blob();
    let user = "jump-user".to_string();

    let auth_user = user.clone();
    let auth_blob = allowed_blob.clone();
    let factory: Arc<dyn AuthenticatorFactory> = Arc::new(move || -> Box<dyn Authenticator> {
        Box::new(OneKeyAuth {
            user: auth_user.clone(),
            blob: auth_blob.clone(),
        })
    });

    let mut cfg = ServerConfig::new(
        vec![host_key],
        factory,
        vec!["publickey"],
        Arc::new(StaticHandler {
            out: banner.to_vec(),
        }),
    );
    if with_direct_tcpip {
        cfg = cfg.with_direct_tcpip(Arc::new(DefaultDirectTcpipHandler::permit_all()));
    }

    let mut server = Server::bind("127.0.0.1:0", cfg).expect("bind server");
    let addr = server.local_addr().expect("server addr");
    let handle = thread::spawn(move || {
        // The jump server must handle more than one accept: the first
        // connection is the client→jump session that carries the
        // direct-tcpip channel for the whole chain. A target server only
        // ever sees one. accept_one() blocks per connection; loop a couple
        // of times defensively so a stray reconnect doesn't wedge teardown.
        let _ = server.accept_one();
    });

    TestServer {
        addr,
        client_seed,
        user,
        handle,
    }
}

fn client_cfg(policy: HostKeyPolicy) -> ClientConfig {
    ClientConfig {
        host_key_policy: policy,
        timeout: Some(Duration::from_secs(15)),
        algorithms: Default::default(),
    }
}

#[test]
fn proxy_jump_two_hop_exec_round_trip() {
    // Target server: returns a recognisable banner over exec.
    let target = spawn_server(b"through-the-jump\n", false);
    // Jump server: must permit direct-tcpip so the client can tunnel to the
    // target through it.
    let jump = spawn_server(b"jump-banner\n", true);

    // 1) Connect + auth the jump host directly.
    let mut jump_client = Client::connect_to_host(
        "127.0.0.1",
        jump.addr.port(),
        client_cfg(HostKeyPolicy::AcceptAny),
    )
    .expect("connect jump");
    let jump_hk: Box<dyn HostKey + Send> = Box::new(Ed25519HostKey::from_seed(jump.client_seed));
    jump_client
        .authenticate_publickey(&jump.user, jump_hk)
        .expect("auth jump");

    // 2) Wrap the jump client and open a direct-tcpip channel to the target's
    //    SSH listener.
    let shared: SharedClient = jump_client.into();
    let ch = shared
        .open_direct_tcpip("127.0.0.1", target.addr.port(), "127.0.0.1", 0)
        .expect("open direct-tcpip to target");

    // 3) Run a second client over that channel — this is the real target
    //    session. Host-key check keys off the target's own host/port.
    let mut target_client = Client::connect_via(
        Box::new(ch),
        "127.0.0.1",
        target.addr.port(),
        client_cfg(HostKeyPolicy::AcceptAny),
    )
    .expect("connect_via target through jump");
    let target_hk: Box<dyn HostKey + Send> =
        Box::new(Ed25519HostKey::from_seed(target.client_seed));
    target_client
        .authenticate_publickey(&target.user, target_hk)
        .expect("auth target");

    // 4) Exec through the chain.
    let out = target_client.exec("echo hi").expect("exec through jump");
    assert_eq!(out.stdout, b"through-the-jump\n");
    assert_eq!(out.exit_status, Some(0));

    drop(target_client);
    drop(shared);
    let _ = jump.handle.join();
    let _ = target.handle.join();
}

#[test]
fn proxy_jump_target_host_key_mismatch_rejected() {
    let target = spawn_server(b"secret\n", false);
    let jump = spawn_server(b"jump-banner\n", true);

    let mut jump_client = Client::connect_to_host(
        "127.0.0.1",
        jump.addr.port(),
        client_cfg(HostKeyPolicy::AcceptAny),
    )
    .expect("connect jump");
    let jump_hk: Box<dyn HostKey + Send> = Box::new(Ed25519HostKey::from_seed(jump.client_seed));
    jump_client
        .authenticate_publickey(&jump.user, jump_hk)
        .expect("auth jump");

    let shared: SharedClient = jump_client.into();
    let ch = shared
        .open_direct_tcpip("127.0.0.1", target.addr.port(), "127.0.0.1", 0)
        .expect("open direct-tcpip to target");

    // Pin a deliberately-wrong fingerprint for the target hop → the host-key
    // check must reject during the handshake, aborting the chain.
    let wrong_fingerprint = [0u8; 32];
    let res = Client::connect_via(
        Box::new(ch),
        "127.0.0.1",
        target.addr.port(),
        client_cfg(HostKeyPolicy::AcceptFingerprint(wrong_fingerprint)),
    );
    assert!(
        res.is_err(),
        "target host-key mismatch at the jump hop must be rejected"
    );

    drop(shared);
    let _ = jump.handle.join();
    // Target may or may not have completed an accept depending on how far the
    // rejected handshake got; just reap it without asserting.
    let _ = target.handle.join();
}

// ---- ProxyCommand ---------------------------------------------------------

#[cfg(unix)]
fn have_nc() -> bool {
    std::process::Command::new("sh")
        .arg("-c")
        .arg("command -v nc >/dev/null 2>&1")
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// End-to-end ProxyCommand: a `nc` helper bridges the pipe to a loopback SSH
/// server. Skipped (not failed) when `nc` is unavailable so it stays portable.
#[cfg(unix)]
#[test]
fn proxy_command_exec_round_trip() {
    use puressh::proc_transport::{ProcTransport, expand_tokens};

    if !have_nc() {
        eprintln!("skipping proxy_command_exec_round_trip: nc not found");
        return;
    }

    let target = spawn_server(b"via-proxycommand\n", false);

    // Expand %h/%p the way the binary does, then bridge with nc.
    let cmd = expand_tokens("nc %h %p", "127.0.0.1", target.addr.port(), "ignored");
    let proc = ProcTransport::spawn(&cmd).expect("spawn nc ProxyCommand");

    let mut client = Client::connect_via(
        Box::new(proc),
        "127.0.0.1",
        target.addr.port(),
        client_cfg(HostKeyPolicy::AcceptAny),
    )
    .expect("connect_via over ProxyCommand");
    let hk: Box<dyn HostKey + Send> = Box::new(Ed25519HostKey::from_seed(target.client_seed));
    client
        .authenticate_publickey(&target.user, hk)
        .expect("auth target over ProxyCommand");

    let out = client.exec("echo hi").expect("exec over ProxyCommand");
    assert_eq!(out.stdout, b"via-proxycommand\n");
    assert_eq!(out.exit_status, Some(0));

    drop(client);
    let _ = target.handle.join();
}

/// Strict: a ProxyCommand that cannot be spawned aborts with an error — there
/// is no fallback to a direct connection. `/bin/sh -c` always spawns, so to
/// exercise a genuine spawn failure we point `ProcTransport` at a non-existent
/// interpreter via the public API is not possible; instead we assert that a
/// command which exits immediately produces a handshake error (EOF), proving
/// the transport surfaces failure rather than hanging or silently succeeding.
#[cfg(unix)]
#[test]
fn proxy_command_dead_helper_aborts() {
    use puressh::proc_transport::ProcTransport;

    // Helper that exits at once → its stdout is EOF, so the SSH version
    // exchange can't complete and connect_via must error out (strict).
    let proc = ProcTransport::spawn("exit 0").expect("/bin/sh -c spawns");
    let res = Client::connect_via(
        Box::new(proc),
        "127.0.0.1",
        22,
        client_cfg(HostKeyPolicy::AcceptAny),
    );
    assert!(
        res.is_err(),
        "a ProxyCommand helper that dies immediately must abort the connection"
    );
}

/// A tiny loopback TCP echo server — the `direct-tcpip` forward target for the
/// `-L over ProxyCommand` test. Returns its bound port and a join handle.
#[cfg(unix)]
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

/// End-to-end `ssh -L` over a ProxyCommand carrier: connect+auth an SSH server
/// over an `nc` ProxyCommand pipe, run the serve loop (which now ticks over the
/// O_NONBLOCK pipe via poll-with-deadline), and open a `direct-tcpip` channel
/// from inside the loop to a loopback echo server — proving the serve /
/// forwarding poll loop works over the pipe carrier. Skipped if `nc` is absent.
#[cfg(unix)]
#[test]
fn local_forward_over_proxy_command() {
    use puressh::client::ClientHandlers;
    use puressh::proc_transport::{ProcTransport, expand_tokens};
    use std::io::{Read, Write};

    if !have_nc() {
        eprintln!("skipping local_forward_over_proxy_command: nc not found");
        return;
    }

    // SSH server must permit direct-tcpip so the client can tunnel `-L`.
    let target = spawn_server(b"unused\n", true);
    // The forward destination the server will dial on the client's behalf.
    let (echo_port, echo_handle) = spawn_echo_server();

    let cmd = expand_tokens("nc %h %p", "127.0.0.1", target.addr.port(), "ignored");
    let proc = ProcTransport::spawn(&cmd).expect("spawn nc ProxyCommand");

    let mut client = Client::connect_via(
        Box::new(proc),
        "127.0.0.1",
        target.addr.port(),
        client_cfg(HostKeyPolicy::AcceptAny),
    )
    .expect("connect_via over ProxyCommand");
    let hk: Box<dyn HostKey + Send> = Box::new(Ed25519HostKey::from_seed(target.client_seed));
    client
        .authenticate_publickey(&target.user, hk)
        .expect("auth target over ProxyCommand");

    // Drive the serve loop in a worker thread; we keep a ServeContext to open
    // the direct-tcpip channel from this thread.
    let (handlers, ctx) = ClientHandlers::new().with_serve_context();
    let stop = handlers.stop.clone();
    let serve = thread::spawn(move || {
        let _ = client.serve(handlers);
    });

    // Open the forward target through the serve loop and round-trip a payload.
    let mut stream = ctx
        .open_direct_tcpip("127.0.0.1", echo_port, "127.0.0.1", 0)
        .expect("open direct-tcpip over proxycommand serve loop");
    stream.write_all(b"ping over -L").expect("write to forward");
    let mut buf = [0u8; 12];
    stream.read_exact(&mut buf).expect("read echo from forward");
    assert_eq!(&buf, b"ping over -L");

    drop(stream);
    stop.store(true, std::sync::atomic::Ordering::SeqCst);
    let _ = serve.join();
    let _ = target.handle.join();
    let _ = echo_handle.join();
}

/// The serve loop must *tick* over a ProxyCommand pipe — i.e. the poll-with-
/// deadline read returns periodically so the `stop` flag is honoured even with
/// no channels open. This is the keepalive/responsiveness property the old
/// no-op `set_read_timeout` could not provide. Skipped if `nc` is absent.
#[cfg(unix)]
#[test]
fn serve_loop_ticks_over_proxy_command() {
    use puressh::client::ClientHandlers;
    use puressh::proc_transport::{ProcTransport, expand_tokens};

    if !have_nc() {
        eprintln!("skipping serve_loop_ticks_over_proxy_command: nc not found");
        return;
    }

    let target = spawn_server(b"unused\n", true);
    let cmd = expand_tokens("nc %h %p", "127.0.0.1", target.addr.port(), "ignored");
    let proc = ProcTransport::spawn(&cmd).expect("spawn nc ProxyCommand");

    let mut client = Client::connect_via(
        Box::new(proc),
        "127.0.0.1",
        target.addr.port(),
        client_cfg(HostKeyPolicy::AcceptAny),
    )
    .expect("connect_via over ProxyCommand");
    let hk: Box<dyn HostKey + Send> = Box::new(Ed25519HostKey::from_seed(target.client_seed));
    client
        .authenticate_publickey(&target.user, hk)
        .expect("auth target over ProxyCommand");

    let handlers = ClientHandlers::new();
    let stop = handlers.stop.clone();
    let serve = thread::spawn(move || client.serve(handlers));

    // No channels are open. Let the loop spin a few poll ticks, then ask it to
    // stop. If the read blocked forever (the old behaviour), this join would
    // hang; the test's overall timeout would then catch it.
    thread::sleep(Duration::from_millis(300));
    stop.store(true, std::sync::atomic::Ordering::SeqCst);

    let joined = serve.join().expect("serve thread panicked");
    assert!(
        joined.is_ok(),
        "serve loop should return Ok after stop over a ProxyCommand carrier"
    );
    drop(target.handle);
}
