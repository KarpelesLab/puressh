//! In-process tests for the W4 client keywords that need a live peer:
//!
//! - `SetEnv` ↔ server `env` request: the client arms `set_session_env`, the
//!   server records the `env` channel requests into its `SessionEnv`, and the
//!   command handler echoes a chosen variable back so we can assert it made
//!   the round trip.
//! - `DynamicForward` SOCKS path: a SOCKS5 client request is handed to the
//!   real `forwarding::socks::handshake` parser, the resulting target drives
//!   `SharedClient::open_direct_tcpip` against a `direct-tcpip`-enabled
//!   server, and bytes splice through — exactly the flow the `ssh -D`
//!   listener runs per connection.

#![cfg(all(feature = "client", feature = "server", feature = "multichannel"))]

use std::io::{Read, Write};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use puressh::auth::{AuthAttempt, AuthDecision, Authenticator};
use puressh::client::{Client, Config as ClientConfig, HostKeyPolicy};
use puressh::forwarding::direct::DefaultDirectTcpipHandler;
use puressh::forwarding::socks::{self, SocksVersion};
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

/// Command handler that echoes the value of the `PURESSH_TEST` env var the
/// client forwarded, so the test can confirm SetEnv made the round trip.
struct EchoEnvHandler;

impl CommandHandler for EchoEnvHandler {
    fn handle(&self, _user: &str, env: &SessionEnv, _command: &str) -> ExecResult {
        let val = env.get("PURESSH_TEST").unwrap_or("<unset>").to_string();
        ExecResult {
            stdout: val.into_bytes(),
            stderr: Vec::new(),
            exit_status: 0,
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

struct TestServer {
    addr: std::net::SocketAddr,
    client_seed: [u8; 32],
    user: String,
    handle: thread::JoinHandle<()>,
}

fn spawn_server<H: CommandHandler + 'static>(
    handler: H,
    with_direct_tcpip: bool,
    accept_env: &[&str],
) -> TestServer {
    let host_seed = fresh_seed();
    let client_seed = fresh_seed();
    let host_key: Box<dyn HostKey + Send + Sync> = Box::new(Ed25519HostKey::from_seed(host_seed));
    let allowed_blob = Ed25519HostKey::from_seed(client_seed).public_blob();
    let user = "kw-user".to_string();

    let auth_user = user.clone();
    let auth_blob = allowed_blob.clone();
    let factory: Arc<dyn AuthenticatorFactory> = Arc::new(move || -> Box<dyn Authenticator> {
        Box::new(OneKeyAuth {
            user: auth_user.clone(),
            blob: auth_blob.clone(),
        })
    });

    let mut cfg = ServerConfig::new(vec![host_key], factory, vec!["publickey"], Arc::new(handler));
    if with_direct_tcpip {
        cfg = cfg.with_direct_tcpip(Arc::new(DefaultDirectTcpipHandler::permit_all()));
    }
    if !accept_env.is_empty() {
        cfg = cfg.with_accept_env(accept_env.iter().map(|s| s.to_string()).collect());
    }

    let mut server = Server::bind("127.0.0.1:0", cfg).expect("bind server");
    let addr = server.local_addr().expect("server addr");
    let handle = thread::spawn(move || {
        let _ = server.accept_one();
    });

    TestServer {
        addr,
        client_seed,
        user,
        handle,
    }
}

fn client_cfg() -> ClientConfig {
    ClientConfig {
        host_key_policy: HostKeyPolicy::AcceptAny,
        timeout: Some(Duration::from_secs(15)),
        algorithms: Default::default(),
    }
}

fn connect_auth(server: &TestServer) -> Client {
    let mut client =
        Client::connect_to_host("127.0.0.1", server.addr.port(), client_cfg()).expect("connect");
    let hk: Box<dyn HostKey + Send> = Box::new(Ed25519HostKey::from_seed(server.client_seed));
    client
        .authenticate_publickey(&server.user, hk)
        .expect("auth");
    client
}

#[test]
fn set_env_round_trips_to_server() {
    let srv = spawn_server(EchoEnvHandler, false, &["PURESSH_TEST"]);
    let mut client = connect_auth(&srv);
    // This is exactly what ssh.rs does for SetEnv/SendEnv.
    client.set_session_env(vec![("PURESSH_TEST".to_string(), "hello-env".to_string())]);
    let out = client.exec("ignored").expect("exec");
    assert_eq!(out.stdout, b"hello-env");
    assert_eq!(out.exit_status, Some(0));
    drop(client);
    let _ = srv.handle.join();
}

#[test]
fn set_env_absent_when_not_armed() {
    // Control: without set_session_env the server sees no var.
    let srv = spawn_server(EchoEnvHandler, false, &["PURESSH_TEST"]);
    let mut client = connect_auth(&srv);
    let out = client.exec("ignored").expect("exec");
    assert_eq!(out.stdout, b"<unset>");
    drop(client);
    let _ = srv.handle.join();
}

#[test]
fn dynamic_forward_socks5_through_direct_tcpip() {
    // A tiny upstream TCP echo server stands in for the SOCKS-CONNECT target.
    let upstream = std::net::TcpListener::bind("127.0.0.1:0").expect("bind upstream");
    let upstream_port = upstream.local_addr().unwrap().port();
    let up_handle = thread::spawn(move || {
        if let Ok((mut s, _)) = upstream.accept() {
            let mut buf = [0u8; 64];
            if let Ok(n) = s.read(&mut buf) {
                let _ = s.write_all(&buf[..n]);
            }
        }
    });

    // SSH server with direct-tcpip enabled (the -D listener tunnels through
    // it). The command handler is unused here.
    let srv = spawn_server(StaticHandler { out: Vec::new() }, true, &[]);
    let client = connect_auth(&srv);
    let shared: SharedClient = client.into();

    // Build a SOCKS5 CONNECT request for 127.0.0.1:<upstream_port> and feed
    // it through the real handshake parser via an in-memory duplex, mirroring
    // what spawn_dynamic_forward_listener does per accepted socket.
    let mut req = vec![0x05, 1, 0x00, 0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1];
    req.extend_from_slice(&upstream_port.to_be_bytes());
    let mut mock = DuplexCursor::new(req);
    let target = socks::handshake(&mut mock).expect("socks handshake");
    assert_eq!(target.host, "127.0.0.1");
    assert_eq!(target.port, upstream_port);
    assert_eq!(target.version, SocksVersion::V5);

    // Open the direct-tcpip channel to the SOCKS target — the same call the
    // -D listener makes — and splice a probe through it.
    let mut chan = shared
        .open_direct_tcpip(&target.host, target.port, "127.0.0.1", 0)
        .expect("open direct-tcpip");
    chan.write_all(b"ping").expect("write to channel");
    let mut got = [0u8; 4];
    chan.read_exact(&mut got).expect("read echo");
    assert_eq!(&got, b"ping");

    drop(chan);
    drop(shared);
    let _ = up_handle.join();
    let _ = srv.handle.join();
}

/// In-memory bidirectional stream for driving the SOCKS handshake parser:
/// reads drain the queued request bytes, writes are discarded (the test only
/// needs the parsed target, not the reply bytes).
struct DuplexCursor {
    input: std::io::Cursor<Vec<u8>>,
}
impl DuplexCursor {
    fn new(input: Vec<u8>) -> Self {
        Self {
            input: std::io::Cursor::new(input),
        }
    }
}
impl Read for DuplexCursor {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.input.read(buf)
    }
}
impl Write for DuplexCursor {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
