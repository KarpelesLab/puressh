//! `SharedClient` accepting server-opened channels: a remote forward
//! (`ssh -R`) whose connections reach the client through
//! `set_channel_handlers`, while `pump_until_closed` services the
//! connection with no session open (`ssh -N -R`).

#![cfg(all(feature = "client", feature = "server", feature = "multichannel"))]

use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use puressh::auth::{AuthAttempt, AuthDecision, Authenticator};
use puressh::client::{
    Client, ClientHandlers, Config as ClientConfig, ForwardedTcpipCallback, ForwardedTcpipOrigin,
    HostKeyPolicy,
};
use puressh::forwarding::reverse::DefaultTcpipForwardHandler;
use puressh::hostkey::{Ed25519HostKey, HostKey};
use puressh::server::{
    AuthenticatorFactory, ChannelStream, CommandHandler, Config as ServerConfig, ExecResult,
    Server, SessionEnv,
};
use puressh::shared::SharedClient;

const USER: &str = "fwd";

struct OneKey(Vec<u8>);
impl Authenticator for OneKey {
    fn evaluate(&mut self, attempt: AuthAttempt) -> AuthDecision {
        match attempt {
            AuthAttempt::PublicKey {
                user,
                public_blob,
                probe_only,
                verified,
                ..
            } if user == USER && public_blob == self.0 && (probe_only || verified) => {
                AuthDecision::Accept
            }
            _ => AuthDecision::Reject,
        }
    }
}

struct NoExec;
impl CommandHandler for NoExec {
    fn handle(&self, _: &str, _: &SessionEnv, _: &str) -> ExecResult {
        ExecResult::new(Vec::new(), Vec::new(), 1)
    }
}

#[test]
fn remote_forward_reaches_shared_client_handler() {
    let client_seed = [7u8; 32];
    let blob = Ed25519HostKey::from_seed(client_seed).public_blob();
    let factory: Arc<dyn AuthenticatorFactory> =
        Arc::new(move || -> Box<dyn Authenticator> { Box::new(OneKey(blob.clone())) });
    let cfg = ServerConfig::new(
        vec![Box::new(Ed25519HostKey::from_seed([9u8; 32]))],
        factory,
        vec!["publickey"],
        Arc::new(NoExec),
    )
    .with_tcpip_forward(Arc::new(DefaultTcpipForwardHandler::permit_localhost_only()));
    let mut server = Server::bind("127.0.0.1:0", cfg).expect("bind");
    let addr = server.local_addr().expect("addr");
    thread::spawn(move || {
        let _ = server.accept_one();
    });

    let mut cfg = ClientConfig::new(HostKeyPolicy::AcceptAny);
    cfg.timeout = Some(Duration::from_secs(10));
    let mut client = Client::connect(addr, cfg).expect("connect");
    client
        .authenticate_publickey(USER, Box::new(Ed25519HostKey::from_seed(client_seed)))
        .expect("auth");
    let port = client
        .request_tcpip_forward("127.0.0.1", 0)
        .expect("tcpip-forward");
    assert_ne!(port, 0);

    let shared = SharedClient::from(client);
    let cb: Arc<ForwardedTcpipCallback> = Arc::new(
        move |origin: ForwardedTcpipOrigin, mut stream: ChannelStream| {
            assert_eq!(origin.bound_port, port);
            let mut buf = [0u8; 5];
            if stream.read_exact(&mut buf).is_ok() && &buf == b"ping?" {
                let _ = stream.write_all(b"pong!");
            }
        },
    );
    shared.set_channel_handlers(ClientHandlers::new().with_forwarded_tcpip(cb));
    let pump = shared.clone();
    thread::spawn(move || {
        let _ = pump.pump_until_closed();
    });

    // A connection to the server-side listener travels back to the client
    // handler as a forwarded-tcpip channel.
    let mut tcp = TcpStream::connect(("127.0.0.1", port)).expect("connect forwarded port");
    tcp.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    tcp.write_all(b"ping?").unwrap();
    let mut reply = [0u8; 5];
    tcp.read_exact(&mut reply)
        .expect("reply through the forward");
    assert_eq!(&reply, b"pong!");
}

#[test]
fn session_stream_exec_with_handlers_installed() {
    // Installing handlers does not change ordinary sessions: an exec on
    // `session_stream` runs and reports its exit status, and no handler
    // fires for a channel the client never asked for.
    let client_seed = [8u8; 32];
    let blob = Ed25519HostKey::from_seed(client_seed).public_blob();
    let factory: Arc<dyn AuthenticatorFactory> =
        Arc::new(move || -> Box<dyn Authenticator> { Box::new(OneKey(blob.clone())) });
    let cfg = ServerConfig::new(
        vec![Box::new(Ed25519HostKey::from_seed([10u8; 32]))],
        factory,
        vec!["publickey"],
        Arc::new(NoExec),
    );
    let mut server = Server::bind("127.0.0.1:0", cfg).expect("bind");
    let addr = server.local_addr().expect("addr");
    thread::spawn(move || {
        let _ = server.accept_one();
    });
    let mut cfg = ClientConfig::new(HostKeyPolicy::AcceptAny);
    cfg.timeout = Some(Duration::from_secs(10));
    let mut client = Client::connect(addr, cfg).expect("connect");
    client
        .authenticate_publickey(USER, Box::new(Ed25519HostKey::from_seed(client_seed)))
        .expect("auth");
    let shared = SharedClient::from(client);
    let called = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let c = called.clone();
    shared.set_channel_handlers(ClientHandlers::new().with_auth_agent(Arc::new(
        move |_s: ChannelStream| {
            c.store(true, std::sync::atomic::Ordering::SeqCst);
        },
    )));
    // A command still runs and returns its (failing) status.
    let mut s = shared
        .session_stream(puressh::shared::SessionRequest::Exec("x"), None)
        .expect("exec");
    let mut out = Vec::new();
    let _ = s.read_to_end(&mut out);
    assert_eq!(s.exit_status(), Some(1));
    assert!(!called.load(std::sync::atomic::Ordering::SeqCst));
}
