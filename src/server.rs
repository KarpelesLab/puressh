//! High-level blocking SSH server over `std::net::TcpListener`.
//!
//! ```ignore
//! use std::sync::Arc;
//! use puressh::server::{Server, Config, CommandHandler, ExecResult};
//!
//! struct H;
//! impl CommandHandler for H {
//!     fn handle(&self, _user: &str, _cmd: &str) -> ExecResult {
//!         ExecResult { stdout: b"ok\n".to_vec(), stderr: Vec::new(), exit_status: 0 }
//!     }
//! }
//!
//! let cfg = Config {
//!     host_keys: vec![/* load_host_key()? */],
//!     authenticator: /* Arc::new(my_auth) */,
//!     allowed_auth_methods: vec!["publickey"],
//!     command_handler: Arc::new(H),
//! };
//! let mut srv = Server::bind("127.0.0.1:2222", cfg)?;
//! srv.serve()?;
//! ```

#![cfg(feature = "std")]

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::thread;

use purecrypto::rng::{CryptoRng, OsRng, RngCore};

use crate::auth::{Authenticator, ServerAuth, ServerStep};
use crate::channel::{
    ChannelEvent, ChannelOpen, ChannelRequest, ConnectionState, SSH_EXTENDED_DATA_STDERR,
    SSH_OPEN_ADMINISTRATIVELY_PROHIBITED,
};
use crate::error::{Error, Result};
use crate::format::Writer;
use crate::hostkey::HostKey;
use crate::transport::kex::{defaults, KexAlgorithms};
use crate::transport::{KexInit, KexRunner, PacketCodec, Role, VersionExchange};

const MAX_BANNER_LINE: usize = 1024;
const MAX_BANNER_LINES: usize = 256;
const MAX_INBOX_BYTES: usize = 8 * 1024 * 1024;
const MAX_KEX_STEPS: usize = 32;
const MAX_AUTH_STEPS: usize = 64;
const MAX_CONNECTION_STEPS: usize = 10_000_000;
const MAX_DRAIN_STEPS: usize = 1_000_000;

const SSH_DISCONNECT_BY_APPLICATION: u32 = 11;
const SSH_DISCONNECT_HOST_NOT_ALLOWED: u32 = 9;

/// Result returned by a [`CommandHandler`] after running a command.
#[derive(Debug, Clone)]
pub struct ExecResult {
    /// Captured stdout bytes.
    pub stdout: Vec<u8>,
    /// Captured stderr bytes.
    pub stderr: Vec<u8>,
    /// POSIX-style exit code.
    pub exit_status: u32,
}

/// Server-side hook called when a client sends a `"exec"` channel request.
pub trait CommandHandler: Send + Sync {
    /// Run `command` on behalf of `user` and return its full output and exit
    /// code. Called inside the per-connection thread.
    fn handle(&self, user: &str, command: &str) -> ExecResult;
}

/// Server configuration: host keys, authentication, and the exec hook.
pub struct Config {
    /// Host keys the server presents and signs the KEX with. At least one
    /// required.
    pub host_keys: Vec<Box<dyn HostKey + Send + Sync>>,
    /// User-authentication policy.
    pub authenticator: Arc<dyn AuthenticatorFactory>,
    /// Auth methods advertised in `USERAUTH_FAILURE`.
    pub allowed_auth_methods: Vec<&'static str>,
    /// Command handler invoked on `"exec"` channel requests.
    pub command_handler: Arc<dyn CommandHandler>,
}

/// Per-connection authenticator factory.
///
/// `ServerAuth` owns its `Box<dyn Authenticator>`, and `Authenticator`
/// itself is `&mut self`-stateful (rate limits, partial accepts, ...).
/// Building a fresh authenticator per connection avoids cross-connection
/// state bleed and the `Sync` requirement on user code.
pub trait AuthenticatorFactory: Send + Sync {
    /// Build a fresh authenticator for one connection.
    fn build(&self) -> Box<dyn Authenticator>;
}

impl<F> AuthenticatorFactory for F
where
    F: Fn() -> Box<dyn Authenticator> + Send + Sync,
{
    fn build(&self) -> Box<dyn Authenticator> {
        (self)()
    }
}

/// A blocking SSH server.
pub struct Server {
    listener: TcpListener,
    cfg: Arc<Config>,
}

impl Server {
    /// Bind the server to `addr`. Validates that at least one host key is
    /// configured.
    pub fn bind<A: ToSocketAddrs>(addr: A, cfg: Config) -> Result<Self> {
        if cfg.host_keys.is_empty() {
            return Err(Error::Protocol("server: no host keys configured"));
        }
        let listener = TcpListener::bind(addr)?;
        Ok(Self {
            listener,
            cfg: Arc::new(cfg),
        })
    }

    /// Local socket address (useful when binding to port 0).
    pub fn local_addr(&self) -> Result<SocketAddr> {
        Ok(self.listener.local_addr()?)
    }

    /// Accept one connection and handle it on the current thread, blocking
    /// until the session closes. Intended for single-connection test harnesses.
    pub fn accept_one(&mut self) -> Result<()> {
        let (stream, _peer) = self.listener.accept()?;
        handle_connection(stream, self.cfg.clone())
    }

    /// Accept connections forever, spawning a fresh thread per connection.
    pub fn serve(&mut self) -> Result<()> {
        loop {
            let (stream, _peer) = self.listener.accept()?;
            let cfg = self.cfg.clone();
            thread::spawn(move || {
                let _ = handle_connection(stream, cfg);
            });
        }
    }
}

fn handle_connection(mut stream: TcpStream, cfg: Arc<Config>) -> Result<()> {
    stream.set_nodelay(true)?;

    let mut codec = PacketCodec::new();
    let mut inbox: Vec<u8> = Vec::new();
    let mut rng = OsRng;

    let v_s = crate::transport::version::LOCAL_VERSION.as_bytes().to_vec();
    stream.write_all(&VersionExchange::outgoing_bytes())?;
    let v_c = read_peer_version(&mut stream)?;

    let session_id = do_server_kex(
        &mut stream,
        &mut codec,
        &mut rng,
        &mut inbox,
        &cfg,
        &v_c,
        &v_s,
    )?;

    let user = do_server_auth(
        &mut stream,
        &mut codec,
        &mut rng,
        &mut inbox,
        &cfg,
        session_id,
    )?;

    let r = do_connection_phase(&mut stream, &mut codec, &mut rng, &mut inbox, &cfg, &user);

    let _ = send_disconnect(
        &mut stream,
        &mut codec,
        &mut rng,
        SSH_DISCONNECT_BY_APPLICATION,
        "closing session",
    );
    r
}

fn do_server_kex<R: RngCore + CryptoRng>(
    stream: &mut TcpStream,
    codec: &mut PacketCodec,
    rng: &mut R,
    inbox: &mut Vec<u8>,
    cfg: &Config,
    v_c: &[u8],
    v_s: &[u8],
) -> Result<Vec<u8>> {
    let advert = build_server_kexinit(rng, &cfg.host_keys);
    let mut runner = KexRunner::new(Role::Server, advert);
    let initial = runner.start(rng)?;
    for p in initial.outbound {
        write_payload(stream, codec, rng, &p)?;
    }

    let mut steps = 0usize;
    let mut selected_host_key: Option<&(dyn HostKey + Send + Sync)> = None;

    loop {
        steps += 1;
        if steps > MAX_KEX_STEPS {
            return Err(Error::Protocol("kex: too many steps"));
        }
        let payload = read_one_packet(stream, codec, inbox)?;

        if selected_host_key.is_none() {
            if let Some(neg) = runner.negotiated() {
                selected_host_key = pick_host_key(&cfg.host_keys, &neg.host_key);
                if selected_host_key.is_none() {
                    return Err(Error::Protocol("kex: no host key for negotiated algorithm"));
                }
            }
        }

        let hk_ref: Option<&dyn HostKey> = selected_host_key.map(|k| k as &dyn HostKey);
        let adv = runner.on_packet(rng, codec, &payload, hk_ref, None, v_c, v_s)?;
        for p in adv.outbound {
            write_payload(stream, codec, rng, &p)?;
        }
        if adv.completed {
            break;
        }
    }
    let sid = runner
        .session_id()
        .ok_or(Error::Protocol("kex: missing session id"))?
        .to_vec();
    Ok(sid)
}

fn do_server_auth<R: RngCore + CryptoRng>(
    stream: &mut TcpStream,
    codec: &mut PacketCodec,
    rng: &mut R,
    inbox: &mut Vec<u8>,
    cfg: &Config,
    session_id: Vec<u8>,
) -> Result<String> {
    let methods = cfg.allowed_auth_methods.clone();
    let auth_impl = cfg.authenticator.build();
    let mut server_auth = ServerAuth::new(session_id, methods, auth_impl);

    for _ in 0..MAX_AUTH_STEPS {
        let payload = read_one_packet(stream, codec, inbox)?;
        match server_auth.on_packet(&payload)? {
            ServerStep::Send(p) => write_payload(stream, codec, rng, &p)?,
            ServerStep::Authenticated { payload, user } => {
                write_payload(stream, codec, rng, &payload)?;
                return Ok(user);
            }
            ServerStep::Disconnect(reason) => {
                let _ =
                    send_disconnect(stream, codec, rng, SSH_DISCONNECT_HOST_NOT_ALLOWED, reason);
                return Err(Error::AuthFailed);
            }
        }
    }
    Err(Error::Protocol("auth: too many steps"))
}

fn do_connection_phase<R: RngCore + CryptoRng>(
    stream: &mut TcpStream,
    codec: &mut PacketCodec,
    rng: &mut R,
    inbox: &mut Vec<u8>,
    cfg: &Config,
    user: &str,
) -> Result<()> {
    let mut conn = ConnectionState::new();
    let mut any_channel_opened = false;
    let mut steps = 0usize;

    loop {
        steps += 1;
        if steps > MAX_CONNECTION_STEPS {
            return Err(Error::Protocol("connection: step cap exceeded"));
        }

        if any_channel_opened && !conn.channels().any(|c| !c.is_fully_closed()) {
            return Ok(());
        }

        let payload = read_one_packet(stream, codec, inbox)?;
        let ev = conn.on_packet(&payload)?;
        match ev {
            ChannelEvent::OpenRequest { channel, kind } => match kind {
                ChannelOpen::Session => {
                    any_channel_opened = true;
                    let p = conn.accept_open(channel)?;
                    write_payload(stream, codec, rng, &p)?;
                }
                _ => {
                    let p = conn.reject_open(
                        channel,
                        SSH_OPEN_ADMINISTRATIVELY_PROHIBITED,
                        "channel type not supported",
                        "",
                    )?;
                    write_payload(stream, codec, rng, &p)?;
                }
            },
            ChannelEvent::Request {
                channel,
                request,
                want_reply,
            } => {
                handle_channel_request(
                    stream, codec, rng, inbox, &mut conn, cfg, user, channel, request, want_reply,
                )?;
            }
            ChannelEvent::Data { channel, data } => {
                if let Some(adj) = conn.replenish_window(channel, data.len() as u32)? {
                    write_payload(stream, codec, rng, &adj)?;
                }
            }
            ChannelEvent::ExtendedData { channel, data, .. } => {
                if let Some(adj) = conn.replenish_window(channel, data.len() as u32)? {
                    write_payload(stream, codec, rng, &adj)?;
                }
            }
            ChannelEvent::Eof { .. } => {}
            ChannelEvent::Close { channel } => {
                if let Some(ch) = conn.channel(channel) {
                    if !ch.local_closed {
                        let p = conn.send_close(channel)?;
                        write_payload(stream, codec, rng, &p)?;
                    }
                }
            }
            ChannelEvent::WindowAdjust { .. } => {}
            ChannelEvent::GlobalRequest { want_reply, .. } if want_reply => {
                let p = conn.send_global_failure();
                write_payload(stream, codec, rng, &p)?;
            }
            _ => {}
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn handle_channel_request<R: RngCore + CryptoRng>(
    stream: &mut TcpStream,
    codec: &mut PacketCodec,
    rng: &mut R,
    inbox: &mut Vec<u8>,
    conn: &mut ConnectionState,
    cfg: &Config,
    user: &str,
    channel: u32,
    request: ChannelRequest,
    want_reply: bool,
) -> Result<()> {
    match request {
        ChannelRequest::Exec { command } => {
            let result = cfg.command_handler.handle(user, &command);
            if want_reply {
                let p = conn.send_request_success(channel)?;
                write_payload(stream, codec, rng, &p)?;
            }
            drain_send(
                stream,
                codec,
                rng,
                inbox,
                conn,
                channel,
                &result.stdout,
                None,
            )?;
            drain_send(
                stream,
                codec,
                rng,
                inbox,
                conn,
                channel,
                &result.stderr,
                Some(SSH_EXTENDED_DATA_STDERR),
            )?;
            let p = conn.send_request(
                channel,
                ChannelRequest::ExitStatus {
                    code: result.exit_status,
                },
                false,
            )?;
            write_payload(stream, codec, rng, &p)?;
            let p = conn.send_eof(channel)?;
            write_payload(stream, codec, rng, &p)?;
            let p = conn.send_close(channel)?;
            write_payload(stream, codec, rng, &p)?;
        }
        _ => {
            if want_reply {
                let p = conn.send_request_failure(channel)?;
                write_payload(stream, codec, rng, &p)?;
            }
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn drain_send<R: RngCore + CryptoRng>(
    stream: &mut TcpStream,
    codec: &mut PacketCodec,
    rng: &mut R,
    inbox: &mut Vec<u8>,
    conn: &mut ConnectionState,
    channel: u32,
    mut data: &[u8],
    extended: Option<u32>,
) -> Result<()> {
    let mut iter = 0usize;
    while !data.is_empty() {
        iter += 1;
        if iter > MAX_DRAIN_STEPS {
            return Err(Error::Protocol("drain_send did not converge"));
        }
        let (payload, taken) = if let Some(code) = extended {
            conn.send_extended_data(channel, code, data)?
        } else {
            conn.send_data(channel, data)?
        };

        if taken > 0 {
            write_payload(stream, codec, rng, &payload)?;
            data = &data[taken..];
            continue;
        }
        let pkt = read_one_packet(stream, codec, inbox)?;
        let ev = conn.on_packet(&pkt)?;
        match ev {
            ChannelEvent::WindowAdjust { channel: c, .. } if c == channel => continue,
            ChannelEvent::Close { channel: c } if c == channel => {
                return Err(Error::BadChannelState);
            }
            _ => continue,
        }
    }
    Ok(())
}

fn pick_host_key<'a>(
    keys: &'a [Box<dyn HostKey + Send + Sync>],
    name: &str,
) -> Option<&'a (dyn HostKey + Send + Sync)> {
    for k in keys {
        if k.algorithm() == name {
            return Some(k.as_ref());
        }
    }
    // RSA: a single private key can sign with rsa-sha2-256 / rsa-sha2-512 /
    // ssh-rsa, but our HostKey trait pins one algorithm per instance. Treat
    // the rsa-* family as a single equivalence class on the public-blob side.
    for k in keys {
        let a = k.algorithm();
        if (a == "ssh-rsa" || a == "rsa-sha2-256" || a == "rsa-sha2-512")
            && (name == "ssh-rsa" || name == "rsa-sha2-256" || name == "rsa-sha2-512")
        {
            return Some(k.as_ref());
        }
    }
    None
}

fn build_server_kexinit<R: RngCore>(
    rng: &mut R,
    host_keys: &[Box<dyn HostKey + Send + Sync>],
) -> KexInit {
    // Filter advertised host-key algorithms to only those we can actually
    // produce signatures for. Preserve the default order for predictability.
    let mut have: Vec<&'static str> = Vec::new();
    for n in defaults::HOST_KEY {
        if host_keys.iter().any(|k| k.algorithm() == *n) {
            have.push(*n);
            continue;
        }
        // rsa-sha2-{256,512} are usable as long as we have any RSA key.
        if (*n == "rsa-sha2-256" || *n == "rsa-sha2-512")
            && host_keys.iter().any(|k| {
                let a = k.algorithm();
                a == "ssh-rsa" || a == "rsa-sha2-256" || a == "rsa-sha2-512"
            })
        {
            have.push(*n);
        }
    }
    if have.is_empty() {
        have.push("ssh-ed25519");
    }

    let kex_no_gex: Vec<&str> = defaults::KEX
        .iter()
        .copied()
        .filter(|n| *n != "diffie-hellman-group-exchange-sha256")
        .collect();

    let algs = KexAlgorithms {
        kex: &kex_no_gex,
        server_host_key: &have,
        ciphers_c2s: defaults::CIPHERS,
        ciphers_s2c: defaults::CIPHERS,
        macs_c2s: defaults::MACS,
        macs_s2c: defaults::MACS,
        comp_c2s: defaults::COMP,
        comp_s2c: defaults::COMP,
        lang_c2s: &[],
        lang_s2c: &[],
    };
    let mut cookie = [0u8; 16];
    rng.fill_bytes(&mut cookie);
    KexInit::from_algorithms(&algs, cookie)
}

fn read_peer_version(stream: &mut TcpStream) -> Result<Vec<u8>> {
    let mut buf = Vec::new();
    for _ in 0..MAX_BANNER_LINES {
        buf.clear();
        read_line(stream, &mut buf, MAX_BANNER_LINE)?;
        if buf.starts_with(b"SSH-") {
            let parsed = VersionExchange::parse_remote(&buf)?;
            return Ok(parsed.into_bytes());
        }
    }
    Err(Error::Protocol("peer banner too long"))
}

fn read_line<S: Read>(stream: &mut S, buf: &mut Vec<u8>, max_len: usize) -> Result<()> {
    let mut byte = [0u8; 1];
    loop {
        let n = stream.read(&mut byte)?;
        if n == 0 {
            return Err(Error::Protocol("connection closed before newline"));
        }
        buf.push(byte[0]);
        if byte[0] == b'\n' {
            return Ok(());
        }
        if buf.len() >= max_len {
            return Err(Error::Protocol("banner line too long"));
        }
    }
}

fn read_one_packet(
    stream: &mut TcpStream,
    codec: &mut PacketCodec,
    inbox: &mut Vec<u8>,
) -> Result<Vec<u8>> {
    loop {
        let payload = read_one_raw_packet(stream, codec, inbox)?;
        match payload.first().copied() {
            Some(1) => return Err(Error::Protocol("peer sent SSH_MSG_DISCONNECT")),
            Some(2) | Some(3) | Some(4) => continue,
            _ => return Ok(payload),
        }
    }
}

fn read_one_raw_packet(
    stream: &mut TcpStream,
    codec: &mut PacketCodec,
    inbox: &mut Vec<u8>,
) -> Result<Vec<u8>> {
    loop {
        if let Some((payload, consumed)) = codec.decode(inbox)? {
            inbox.drain(..consumed);
            return Ok(payload);
        }
        let mut tmp = [0u8; 16 * 1024];
        let n = stream.read(&mut tmp)?;
        if n == 0 {
            return Err(Error::Protocol("connection closed"));
        }
        inbox.extend_from_slice(&tmp[..n]);
        if inbox.len() > MAX_INBOX_BYTES {
            return Err(Error::Protocol("inbound buffer too large"));
        }
    }
}

fn write_payload<R: RngCore + CryptoRng>(
    stream: &mut TcpStream,
    codec: &mut PacketCodec,
    rng: &mut R,
    payload: &[u8],
) -> Result<()> {
    let frame = codec.encode(payload, rng)?;
    stream.write_all(&frame)?;
    Ok(())
}

fn send_disconnect<R: RngCore + CryptoRng>(
    stream: &mut TcpStream,
    codec: &mut PacketCodec,
    rng: &mut R,
    reason: u32,
    description: &str,
) -> Result<()> {
    let mut w = Writer::new();
    w.write_u8(1);
    w.write_u32(reason);
    w.write_string(description.as_bytes());
    w.write_string(b"");
    write_payload(stream, codec, rng, &w.into_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::{AuthAttempt, AuthDecision, Authenticator};
    use crate::client::{Client, Config as ClientConfig, HostKeyPolicy};
    use crate::hostkey::Ed25519HostKey;
    use std::sync::Mutex;
    use std::time::Duration;

    struct OneKeyAuth {
        allowed_user: String,
        allowed_blob: Vec<u8>,
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
                    if user != self.allowed_user {
                        return AuthDecision::Reject;
                    }
                    if public_blob != self.allowed_blob {
                        return AuthDecision::Reject;
                    }
                    if probe_only {
                        return AuthDecision::Accept;
                    }
                    if !verified {
                        return AuthDecision::Reject;
                    }
                    AuthDecision::Accept
                }
                _ => AuthDecision::Reject,
            }
        }
    }

    struct StaticHandler {
        out: Vec<u8>,
    }

    impl CommandHandler for StaticHandler {
        fn handle(&self, _user: &str, _command: &str) -> ExecResult {
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

    #[test]
    fn loopback_exec_roundtrip() {
        let host_seed = fresh_seed();
        let client_seed = fresh_seed();

        // Build server.
        let host_key: Box<dyn HostKey + Send + Sync> =
            Box::new(Ed25519HostKey::from_seed(host_seed));
        let client_hk_for_auth = Ed25519HostKey::from_seed(client_seed);
        let allowed_blob = client_hk_for_auth.public_blob();

        let user = "ssh-test-user".to_string();
        let allowed_user_for_factory = user.clone();
        let allowed_blob_clone = allowed_blob.clone();

        let factory: Arc<dyn AuthenticatorFactory> = Arc::new(move || -> Box<dyn Authenticator> {
            Box::new(OneKeyAuth {
                allowed_user: allowed_user_for_factory.clone(),
                allowed_blob: allowed_blob_clone.clone(),
            })
        });

        let cfg = Config {
            host_keys: vec![host_key],
            authenticator: factory,
            allowed_auth_methods: vec!["publickey"],
            command_handler: Arc::new(StaticHandler {
                out: b"loopback-test\n".to_vec(),
            }),
        };

        let mut server = Server::bind("127.0.0.1:0", cfg).expect("bind");
        let addr = server.local_addr().expect("local_addr");

        let server_done = Arc::new(Mutex::new(false));
        let sd = server_done.clone();
        let server_thread = thread::spawn(move || {
            let r = server.accept_one();
            *sd.lock().unwrap() = true;
            r
        });

        // Give the server a moment to be listening — bind already did this,
        // so we proceed straight to connect.
        let mut client = Client::connect(
            addr,
            ClientConfig {
                host_key_policy: HostKeyPolicy::AcceptAny,
                timeout: Some(Duration::from_secs(10)),
            },
        )
        .expect("client connect");

        let client_hk: Box<dyn HostKey + Send> = Box::new(Ed25519HostKey::from_seed(client_seed));
        client
            .authenticate_publickey(&user, client_hk)
            .expect("authenticate");

        let out = client.exec("ignored").expect("exec");
        assert_eq!(out.stdout, b"loopback-test\n");
        assert_eq!(out.exit_status, Some(0));

        drop(client);

        // Bound the server-thread wait so a regression can't hang the suite.
        let start = std::time::Instant::now();
        while !*server_done.lock().unwrap() {
            if start.elapsed() > Duration::from_secs(10) {
                panic!("server thread did not finish in time");
            }
            thread::sleep(Duration::from_millis(20));
        }
        let _ = server_thread.join();
    }

    #[test]
    fn server_kexinit_negotiation_uses_role_server() {
        // A direct sanity check that we can drive the server-side KEX
        // negotiation phase through KexRunner with a synthetic client KEXINIT.
        let mut rng = OsRng;
        let host_keys: Vec<Box<dyn HostKey + Send + Sync>> =
            vec![Box::new(Ed25519HostKey::from_seed(fresh_seed()))];
        let advert = build_server_kexinit(&mut rng, &host_keys);
        let mut runner = KexRunner::new(Role::Server, advert.clone());

        // Build a minimal compatible client KEXINIT (all the same names, one
        // entry each — that guarantees agreement).
        let mut cookie = [0u8; 16];
        rng.fill_bytes(&mut cookie);
        let client_init = {
            let algs = KexAlgorithms {
                kex: &["curve25519-sha256"],
                server_host_key: &["ssh-ed25519"],
                ciphers_c2s: &["chacha20-poly1305@openssh.com"],
                ciphers_s2c: &["chacha20-poly1305@openssh.com"],
                macs_c2s: &["hmac-sha2-256"],
                macs_s2c: &["hmac-sha2-256"],
                comp_c2s: &["none"],
                comp_s2c: &["none"],
                lang_c2s: &[],
                lang_s2c: &[],
            };
            KexInit::from_algorithms(&algs, cookie)
        };

        let _ = runner.start(&mut rng).expect("server start");
        let mut codec = PacketCodec::new();
        let adv = runner
            .on_packet(
                &mut rng,
                &mut codec,
                &client_init.encode(),
                None,
                None,
                b"SSH-2.0-test-client",
                b"SSH-2.0-test-server",
            )
            .expect("server processes client kexinit");
        assert!(!adv.completed);
        let neg = runner.negotiated().expect("negotiated");
        assert_eq!(neg.kex, "curve25519-sha256");
        assert_eq!(neg.host_key, "ssh-ed25519");
    }
}
