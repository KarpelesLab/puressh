//! Runtime-agnostic async SSH client frontend.
//!
//! [`AsyncClient`] drives the same sans-IO [`ClientDriver`]
//! as the blocking [`Client`](crate::client::Client), but over any
//! `futures_io::AsyncRead` + `AsyncWrite` transport — so it
//! works on tokio (via `tokio_util::compat`), smol, async-std, or any other
//! executor without the library depending on a specific runtime.
//!
//! The caller brings an already-connected async stream; `AsyncClient` runs the
//! version exchange, key exchange, authentication, and channel I/O over it. The
//! protocol logic is shared with the blocking client — only the pump (the bit
//! that actually reads/writes the transport) is `async` here.
//!
//! ```ignore
//! let stream = /* any AsyncRead + AsyncWrite + Unpin, e.g. a tokio TcpStream
//!                 wrapped with tokio_util::compat::TokioAsyncReadCompatExt */;
//! let mut client = AsyncClient::connect(stream, "host", 22, Config::insecure()).await?;
//! client.authenticate_publickey("alice", key).await?;
//! let out = client.exec("uname -a").await?;
//! ```

#![cfg(feature = "async")]

use alloc::boxed::Box;
use alloc::string::ToString;
use alloc::vec::Vec;
use std::time::Instant;

use futures_util::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::auth::{ClientAuth, ClientCredential, ClientStep};
use crate::channel::{
    ChannelEvent, ChannelOpen, ChannelRequest, ConnectionState, SSH_EXTENDED_DATA_STDERR,
};
use crate::client::{AlgoOverrides, Config, ExecOutput, build_verifier, unix_now};
use crate::driver::client::VerifierFactory;
use crate::driver::{ClientDriver, Event};
use crate::error::{Error, Result};
use crate::hostkey::HostKey;

const MAX_AUTH_STEPS: usize = 64;
const MAX_EXEC_ITER: usize = 1_000_000;
const MAX_EXEC_OUTPUT: usize = 64 * 1024 * 1024;
const READ_CHUNK: usize = 16 * 1024;

/// An async SSH client over a caller-supplied `futures` transport.
///
/// Mirrors the blocking [`Client`](crate::client::Client) but with `async`
/// methods. Single-channel today (one operation at a time); multi-channel
/// async multiplexing can layer on the same driver later.
pub struct AsyncClient<S> {
    stream: S,
    driver: ClientDriver,
    /// Connection multiplexer, owned by the frontend exactly as in the
    /// blocking client.
    conn: ConnectionState,
    algo_overrides: AlgoOverrides,
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncClient<S> {
    /// Run the SSH handshake over `stream` and return a connected client ready
    /// for [`authenticate`](Self::authenticate). `host`/`port` name the target
    /// for host-key (`KnownHosts`) lookups.
    pub async fn connect(stream: S, host: &str, port: u16, cfg: Config) -> Result<Self> {
        // Same host-key verification seam as the blocking client: policy +
        // prompting + known-hosts stay out of the sans-IO driver.
        let host_key_policy = cfg.host_key_policy;
        let target_host = host.to_string();
        let ca_sig_algos = cfg.algorithms.ca_signature_algorithms.clone();
        let verifier_factory: VerifierFactory = Box::new(move |reply, runner| {
            build_verifier(
                reply,
                &host_key_policy,
                runner,
                &target_host,
                port,
                ca_sig_algos.as_deref(),
                unix_now(),
            )
        });
        let driver = ClientDriver::new(cfg.algorithms.clone(), verifier_factory);
        let mut me = Self {
            stream,
            driver,
            conn: ConnectionState::new(),
            algo_overrides: cfg.algorithms,
        };
        me.driver.start(Instant::now())?;
        me.drive_handshake().await?;
        Ok(me)
    }

    /// The session identifier (exchange hash `H`), stable across re-keys.
    pub fn session_id(&self) -> &[u8] {
        self.driver.session_id()
    }
}

/// Tokio-native entry point (feature `tokio`).
///
/// Accepts tokio's own `AsyncRead`/`AsyncWrite` streams — most commonly a
/// [`tokio::net::TcpStream`] — and bridges them to the runtime-agnostic
/// `futures` core with [`tokio_util::compat`], so the entire handshake / auth /
/// channel machinery is shared with [`AsyncClient::connect`]. The caller owns
/// the tokio runtime; the library pulls in no runtime of its own.
#[cfg(feature = "tokio")]
impl<T> AsyncClient<tokio_util::compat::Compat<T>>
where
    T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    /// Connect over an already-established tokio stream and run the SSH
    /// handshake. `host`/`port` name the target for host-key verification.
    pub async fn connect_tokio(stream: T, host: &str, port: u16, cfg: Config) -> Result<Self> {
        use tokio_util::compat::TokioAsyncReadCompatExt;
        Self::connect(stream.compat(), host, port, cfg).await
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncClient<S> {
    /// Try every credential in order within a single userauth exchange.
    pub async fn authenticate(
        &mut self,
        user: &str,
        credentials: Vec<ClientCredential>,
    ) -> Result<()> {
        let mut auth = ClientAuth::new(user, self.driver.session_id().to_vec());
        if let Some(accepted) = self.algo_overrides.pubkey_accepted_algorithms.clone() {
            auth.set_pubkey_accepted(accepted);
        }
        if let Some(ext) = self.driver.peer_ext_info()
            && let Some(algs) = ext.server_sig_algs.as_deref()
        {
            auth.set_server_sig_algs(algs);
        }
        for c in credentials {
            auth.add_credential(c);
        }
        self.run_auth(auth).await
    }

    /// Convenience: publickey auth with a single key.
    pub async fn authenticate_publickey(
        &mut self,
        user: &str,
        key: Box<dyn HostKey>,
    ) -> Result<()> {
        self.authenticate(user, vec![ClientCredential::PublicKey(key)])
            .await
    }

    /// Convenience: password auth.
    pub async fn authenticate_password(&mut self, user: &str, password: &str) -> Result<()> {
        self.authenticate(user, vec![ClientCredential::Password(password.into())])
            .await
    }

    /// Run a command and collect its stdout/stderr/exit status.
    pub async fn exec(&mut self, command: &str) -> Result<ExecOutput> {
        let local_id = self.open_session().await?;

        let exec_req = self.conn.send_request(
            local_id,
            ChannelRequest::Exec {
                command: command.into(),
            },
            true,
        )?;
        self.write_payload(&exec_req).await?;

        // Await the exec request's success/failure reply.
        let mut accepted = false;
        for _ in 0..MAX_EXEC_ITER {
            if accepted {
                break;
            }
            let payload = self.read_one_packet().await?;
            match self.conn.on_packet(&payload)? {
                ChannelEvent::Success { channel } if channel == local_id => accepted = true,
                ChannelEvent::Failure { channel } if channel == local_id => {
                    return Err(Error::Protocol("exec request denied"));
                }
                _ => {}
            }
        }
        if !accepted {
            return Err(Error::Protocol("exec: request loop did not converge"));
        }

        let mut out = ExecOutput {
            stdout: Vec::new(),
            stderr: Vec::new(),
            exit_status: None,
            exit_signal: None,
        };
        let (mut eof_sent, mut close_sent, mut remote_close) = (false, false, false);
        for _ in 0..MAX_EXEC_ITER {
            if remote_close && close_sent {
                break;
            }
            let payload = self.read_one_packet().await?;
            match self.conn.on_packet(&payload)? {
                ChannelEvent::Data { channel, data } if channel == local_id => {
                    if out.stdout.len() + out.stderr.len() + data.len() > MAX_EXEC_OUTPUT {
                        return Err(Error::Protocol("exec output too large"));
                    }
                    out.stdout.extend_from_slice(&data);
                    self.replenish(local_id, data.len() as u32).await?;
                }
                ChannelEvent::ExtendedData {
                    channel,
                    code,
                    data,
                } if channel == local_id => {
                    if out.stdout.len() + out.stderr.len() + data.len() > MAX_EXEC_OUTPUT {
                        return Err(Error::Protocol("exec output too large"));
                    }
                    if code == SSH_EXTENDED_DATA_STDERR {
                        out.stderr.extend_from_slice(&data);
                    } else {
                        out.stdout.extend_from_slice(&data);
                    }
                    self.replenish(local_id, data.len() as u32).await?;
                }
                ChannelEvent::Request {
                    channel,
                    request,
                    want_reply,
                } if channel == local_id => {
                    match request {
                        ChannelRequest::ExitStatus { code } => out.exit_status = Some(code),
                        ChannelRequest::ExitSignal { name, .. } => out.exit_signal = Some(name),
                        _ => {}
                    }
                    if want_reply {
                        let p = self.conn.send_request_failure(local_id)?;
                        self.write_payload(&p).await?;
                    }
                }
                ChannelEvent::Eof { channel } if channel == local_id && !eof_sent => {
                    let p = self.conn.send_eof(local_id)?;
                    self.write_payload(&p).await?;
                    eof_sent = true;
                }
                ChannelEvent::Close { channel } if channel == local_id => {
                    remote_close = true;
                    if !close_sent {
                        let p = self.conn.send_close(local_id)?;
                        self.write_payload(&p).await?;
                        close_sent = true;
                    }
                }
                _ => {}
            }
        }
        if !(remote_close && close_sent) {
            return Err(Error::Protocol("exec: drain loop did not converge"));
        }
        Ok(out)
    }

    /// Open a `direct-streamlocal`/`direct-tcpip`-style raw byte channel and
    /// return an [`AsyncChannel`] for streaming. Here: `direct-tcpip`.
    pub async fn open_direct_tcpip(
        &mut self,
        dest_host: &str,
        dest_port: u16,
        orig_host: &str,
        orig_port: u16,
    ) -> Result<AsyncChannel<'_, S>> {
        let local_id = self
            .open_channel(ChannelOpen::DirectTcpip {
                dest_host: dest_host.to_string(),
                dest_port: dest_port as u32,
                orig_host: orig_host.to_string(),
                orig_port: orig_port as u32,
            })
            .await?;
        Ok(AsyncChannel {
            client: self,
            channel: local_id,
            read_buf: Vec::new(),
            remote_eof: false,
            close_sent: false,
        })
    }

    // --- internal pump (the only async/I/O part) ---

    async fn open_session(&mut self) -> Result<u32> {
        self.open_channel(ChannelOpen::Session).await
    }

    async fn open_channel(&mut self, kind: ChannelOpen) -> Result<u32> {
        let (local_id, open_payload) = self.conn.open(kind)?;
        self.write_payload(&open_payload).await?;
        for _ in 0..MAX_EXEC_ITER {
            let payload = self.read_one_packet().await?;
            match self.conn.on_packet(&payload)? {
                ChannelEvent::OpenConfirmed { channel } if channel == local_id => {
                    return Ok(local_id);
                }
                ChannelEvent::OpenFailed { channel, .. } if channel == local_id => {
                    return Err(Error::Protocol("channel open failed"));
                }
                _ => {}
            }
        }
        Err(Error::Protocol("open: loop did not converge"))
    }

    async fn run_auth(&mut self, mut auth: ClientAuth) -> Result<()> {
        let first = auth.start();
        self.write_payload(&first).await?;
        for _ in 0..MAX_AUTH_STEPS {
            let payload = self.read_one_packet().await?;
            match auth.on_packet(&payload)? {
                ClientStep::Send(p) => self.write_payload(&p).await?,
                ClientStep::Success => {
                    self.driver.notify_auth_success();
                    return Ok(());
                }
                ClientStep::Failed { .. } => return Err(Error::AuthFailed),
                ClientStep::Banner { .. } | ClientStep::Idle => {}
            }
        }
        Err(Error::Protocol("auth: too many steps without termination"))
    }

    async fn drive_handshake(&mut self) -> Result<()> {
        loop {
            self.pump_out().await?;
            while let Some(ev) = self.driver.poll_event() {
                if matches!(ev, Event::HandshakeComplete) {
                    self.pump_out().await?;
                    return Ok(());
                }
            }
            self.read_into_driver().await?;
        }
    }

    async fn read_one_packet(&mut self) -> Result<Vec<u8>> {
        loop {
            self.driver.handle_timeout(Instant::now())?;
            self.pump_out().await?;
            while let Some(ev) = self.driver.poll_event() {
                if let Event::AppData(payload) = ev {
                    self.pump_out().await?;
                    return Ok(payload);
                }
            }
            self.read_into_driver().await?;
        }
    }

    async fn write_payload(&mut self, payload: &[u8]) -> Result<()> {
        self.driver.enqueue_payload(payload)?;
        self.pump_out().await
    }

    async fn pump_out(&mut self) -> Result<()> {
        while let Some(frame) = self.driver.poll_transmit() {
            self.stream.write_all(&frame).await.map_err(Error::Io)?;
        }
        self.stream.flush().await.map_err(Error::Io)?;
        Ok(())
    }

    async fn read_into_driver(&mut self) -> Result<()> {
        let mut tmp = [0u8; READ_CHUNK];
        let n = self.stream.read(&mut tmp).await.map_err(Error::Io)?;
        if n == 0 {
            return Err(Error::Protocol("connection closed"));
        }
        self.driver.handle_input(&tmp[..n], Instant::now())?;
        Ok(())
    }

    async fn replenish(&mut self, channel: u32, n: u32) -> Result<()> {
        if let Some(adj) = self.conn.replenish_window(channel, n)? {
            self.write_payload(&adj).await?;
        }
        Ok(())
    }
}

/// A raw byte channel (e.g. `direct-tcpip`) over an [`AsyncClient`], exposing
/// inherent async `read`/`write`/`send_eof`/`close`. Borrows the client, so it
/// is single-channel: only one [`AsyncChannel`] may be live at a time.
pub struct AsyncChannel<'a, S> {
    client: &'a mut AsyncClient<S>,
    channel: u32,
    read_buf: Vec<u8>,
    remote_eof: bool,
    close_sent: bool,
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncChannel<'_, S> {
    /// Read up to `buf.len()` bytes from the channel. Returns `Ok(0)` at EOF.
    pub async fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        loop {
            if !self.read_buf.is_empty() {
                let n = self.read_buf.len().min(buf.len());
                buf[..n].copy_from_slice(&self.read_buf[..n]);
                self.read_buf.drain(..n);
                return Ok(n);
            }
            if self.remote_eof {
                return Ok(0);
            }
            let payload = self.client.read_one_packet().await?;
            match self.client.conn.on_packet(&payload)? {
                ChannelEvent::Data { channel, data } if channel == self.channel => {
                    self.read_buf.extend_from_slice(&data);
                    self.client
                        .replenish(self.channel, data.len() as u32)
                        .await?;
                }
                ChannelEvent::Eof { channel } if channel == self.channel => {
                    self.remote_eof = true;
                }
                ChannelEvent::Close { channel } if channel == self.channel => {
                    self.remote_eof = true;
                    return Ok(0);
                }
                _ => {}
            }
        }
    }

    /// Write all of `data` to the channel, respecting the peer's window.
    pub async fn write(&mut self, mut data: &[u8]) -> Result<()> {
        while !data.is_empty() {
            let (payload, taken) = self.client.conn.send_data(self.channel, data)?;
            if !payload.is_empty() {
                self.client.write_payload(&payload).await?;
            }
            if taken == 0 {
                // Window full — pump one inbound packet to collect a
                // WINDOW_ADJUST, then retry.
                let p = self.client.read_one_packet().await?;
                let _ = self.client.conn.on_packet(&p)?;
                continue;
            }
            data = &data[taken..];
        }
        Ok(())
    }

    /// Half-close the channel (send CHANNEL_EOF).
    pub async fn send_eof(&mut self) -> Result<()> {
        let p = self.client.conn.send_eof(self.channel)?;
        self.client.write_payload(&p).await
    }

    /// Close the channel (send CHANNEL_CLOSE).
    pub async fn close(&mut self) -> Result<()> {
        if !self.close_sent {
            let p = self.client.conn.send_close(self.channel)?;
            self.client.write_payload(&p).await?;
            self.close_sent = true;
        }
        Ok(())
    }
}

// Exercise the async client against the real blocking `Server`. We bridge a
// std `TcpStream` to the `futures` AsyncRead/AsyncWrite traits with a
// blocking-backed adapter (`poll_*` does a blocking syscall and returns
// `Ready`), then drive the future with a minimal `block_on`. This validates
// the async pump and every `.await` point without depending on a runtime.
#[cfg(all(test, feature = "server"))]
mod tests {
    use super::*;
    use core::future::Future;
    use core::pin::Pin;
    use core::task::{Context, Poll};
    use std::io::{Read as _, Write as _};
    use std::net::TcpStream;
    use std::sync::{Arc, Mutex};
    use std::thread;
    use std::time::Duration;

    use crate::auth::{AuthAttempt, AuthDecision, Authenticator};
    use crate::hostkey::Ed25519HostKey;
    use crate::server::{
        AuthenticatorFactory, CommandHandler, Config as ServerConfig, ExecResult, Server,
        SessionEnv,
    };
    use purecrypto::rng::{OsRng, RngCore};

    /// Bridge a blocking `TcpStream` to `futures` async I/O: every `poll_*`
    /// performs the blocking syscall and returns `Ready`, so it never parks.
    struct BlockingAsync(TcpStream);

    impl AsyncRead for BlockingAsync {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &mut [u8],
        ) -> Poll<std::io::Result<usize>> {
            Poll::Ready(self.0.read(buf))
        }
    }
    impl AsyncWrite for BlockingAsync {
        fn poll_write(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            Poll::Ready(self.0.write(buf))
        }
        fn poll_flush(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<std::io::Result<()>> {
            Poll::Ready(self.0.flush())
        }
        fn poll_close(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    /// Minimal executor: our I/O adapter never returns `Pending`, so the
    /// future always advances to `Ready` and this never busy-spins.
    fn block_on<F: Future>(f: F) -> F::Output {
        let mut cx = Context::from_waker(std::task::Waker::noop());
        let mut fut = Box::pin(f);
        loop {
            if let Poll::Ready(v) = fut.as_mut().poll(&mut cx) {
                return v;
            }
        }
    }

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
        let mut s = [0u8; 32];
        OsRng.fill_bytes(&mut s);
        s
    }

    #[test]
    fn async_connect_auth_exec_round_trip() {
        let host_seed = fresh_seed();
        let client_seed = fresh_seed();
        let client_blob = Ed25519HostKey::from_seed(client_seed).public_blob();
        let user = "async-user".to_string();
        let expected = b"hello from async client\n".to_vec();

        let host_key: Box<dyn HostKey + Send + Sync> =
            Box::new(Ed25519HostKey::from_seed(host_seed));
        let u = user.clone();
        let b = client_blob.clone();
        let factory: Arc<dyn AuthenticatorFactory> = Arc::new(move || {
            Box::new(OneKeyAuth {
                user: u.clone(),
                blob: b.clone(),
            }) as Box<dyn Authenticator>
        });
        let cfg = ServerConfig::new(
            vec![host_key],
            factory,
            vec!["publickey"],
            Arc::new(StaticHandler {
                out: expected.clone(),
            }),
        );
        let mut server = Server::bind("127.0.0.1:0", cfg).expect("bind");
        let addr = server.local_addr().expect("addr");
        let done = Arc::new(Mutex::new(false));
        let d2 = done.clone();
        let server_thread = thread::spawn(move || {
            let _ = server.accept_one();
            *d2.lock().unwrap() = true;
        });

        let sock = TcpStream::connect(addr).expect("connect");
        let out = block_on(async {
            let mut client = AsyncClient::connect(
                BlockingAsync(sock),
                "localhost",
                addr.port(),
                Config::insecure(),
            )
            .await
            .expect("connect");
            client
                .authenticate_publickey(&user, Box::new(Ed25519HostKey::from_seed(client_seed)))
                .await
                .expect("auth");
            client.exec("hi").await.expect("exec")
        });

        assert_eq!(out.stdout, expected, "async exec stdout round-trips");
        assert_eq!(out.exit_status, Some(0));

        let start = std::time::Instant::now();
        while !*done.lock().unwrap() {
            if start.elapsed() > Duration::from_secs(10) {
                panic!("server did not finish");
            }
            thread::sleep(Duration::from_millis(20));
        }
        let _ = server_thread.join();
    }

    // Same round-trip, but over a real tokio runtime through the native
    // `connect_tokio` entry point — proving the tokio compat bridge drives the
    // same sans-IO core. Only built with `--features tokio`.
    #[test]
    #[cfg(feature = "tokio")]
    fn tokio_connect_auth_exec_round_trip() {
        let host_seed = fresh_seed();
        let client_seed = fresh_seed();
        let client_blob = Ed25519HostKey::from_seed(client_seed).public_blob();
        let user = "tokio-user".to_string();
        let expected = b"hello from tokio client\n".to_vec();

        let host_key: Box<dyn HostKey + Send + Sync> =
            Box::new(Ed25519HostKey::from_seed(host_seed));
        let u = user.clone();
        let b = client_blob.clone();
        let factory: Arc<dyn AuthenticatorFactory> = Arc::new(move || {
            Box::new(OneKeyAuth {
                user: u.clone(),
                blob: b.clone(),
            }) as Box<dyn Authenticator>
        });
        let cfg = ServerConfig::new(
            vec![host_key],
            factory,
            vec!["publickey"],
            Arc::new(StaticHandler {
                out: expected.clone(),
            }),
        );
        let mut server = Server::bind("127.0.0.1:0", cfg).expect("bind");
        let addr = server.local_addr().expect("addr");
        let server_thread = thread::spawn(move || {
            let _ = server.accept_one();
        });

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .build()
            .expect("tokio runtime");
        let out = rt.block_on(async {
            let tcp = tokio::net::TcpStream::connect(addr).await.expect("connect");
            let mut client =
                AsyncClient::connect_tokio(tcp, "localhost", addr.port(), Config::insecure())
                    .await
                    .expect("ssh connect");
            client
                .authenticate_publickey(&user, Box::new(Ed25519HostKey::from_seed(client_seed)))
                .await
                .expect("auth");
            client.exec("hi").await.expect("exec")
        });

        assert_eq!(out.stdout, expected, "tokio exec stdout round-trips");
        assert_eq!(out.exit_status, Some(0));
        let _ = server_thread.join();
    }
}
