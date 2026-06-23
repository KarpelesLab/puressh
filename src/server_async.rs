//! Runtime-agnostic async SSH server connection.
//!
//! [`AsyncServerConnection`] is the server-side counterpart of
//! [`AsyncClient`](crate::client_async::AsyncClient): it drives the sans-IO
//! [`ServerDriver`] over any
//! `futures_io::AsyncRead` + `AsyncWrite` transport, so an SSH
//! server can run on tokio (via compat), smol, async-std, or any executor with
//! no runtime dependency baked into the library.
//!
//! The caller accepts the TCP connection (with their runtime's listener),
//! hands the async stream to [`AsyncServerConnection::accept`] to run the
//! handshake, calls [`authenticate`](AsyncServerConnection::authenticate) with
//! an [`Authenticator`], and then drives the connection protocol over
//! [`next_packet`](AsyncServerConnection::next_packet) /
//! [`send`](AsyncServerConnection::send) using the exposed
//! [`ConnectionState`](AsyncServerConnection::conn_mut) — exactly the
//! frontend-owns-`conn` model the blocking server and the `ServerDriver` tests
//! use.
//!
//! This is a low-level foundation: it covers the transport handshake, userauth,
//! and a raw packet pump. Higher-level session/channel helpers (mapping the
//! blocking [`CommandHandler`](crate::server::CommandHandler) /
//! [`ShellHandler`](crate::server::ShellHandler) model onto async tasks) can
//! layer on top.

#![cfg(all(feature = "async", feature = "server"))]

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;
use std::sync::Arc;
use std::time::Instant;

use futures_util::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::auth::{Authenticator, ServerAuth, ServerStep};
use crate::channel::ConnectionState;
use crate::driver::{Event, ServerDriver};
use crate::error::{Error, Result};
use crate::server::Config;

const MAX_AUTH_STEPS: usize = 256;
const READ_CHUNK: usize = 16 * 1024;

/// An async SSH server connection over a caller-supplied `futures` transport.
///
/// Mirrors [`AsyncClient`](crate::client_async::AsyncClient) on the server
/// side. The frontend owns the [`ConnectionState`] (channel multiplexer); the
/// sans-IO [`ServerDriver`] handles the transport.
pub struct AsyncServerConnection<S> {
    stream: S,
    driver: ServerDriver,
    conn: ConnectionState,
}

/// Tokio-native server entry point (feature `tokio`). Accepts tokio's own
/// `AsyncRead`/`AsyncWrite` streams (e.g. [`tokio::net::TcpStream`]) directly,
/// bridging to the `futures` core with [`tokio_util::compat`].
#[cfg(feature = "tokio")]
impl<T> AsyncServerConnection<tokio_util::compat::Compat<T>>
where
    T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    /// Run the server handshake over an accepted tokio `stream`.
    pub async fn accept_tokio(stream: T, cfg: Arc<Config>) -> Result<Self> {
        use tokio_util::compat::TokioAsyncReadCompatExt;
        Self::accept(stream.compat(), cfg).await
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncServerConnection<S> {
    /// Run the server handshake over an accepted `stream`. `cfg` supplies the
    /// host keys and algorithm policy.
    pub async fn accept(stream: S, cfg: Arc<Config>) -> Result<Self> {
        let driver = ServerDriver::new(cfg);
        let mut me = Self {
            stream,
            driver,
            conn: ConnectionState::new(),
        };
        me.driver.start(Instant::now())?;
        me.drive_handshake().await?;
        Ok(me)
    }

    /// The session identifier (exchange hash `H`).
    pub fn session_id(&self) -> &[u8] {
        self.driver.session_id()
    }

    /// Mutable access to the connection multiplexer for channel handling.
    pub fn conn_mut(&mut self) -> &mut ConnectionState {
        &mut self.conn
    }

    /// Run userauth with `authenticator`, advertising `methods`. Returns the
    /// authenticated user on success.
    pub async fn authenticate(
        &mut self,
        authenticator: Box<dyn Authenticator>,
        methods: Vec<&'static str>,
    ) -> Result<String> {
        let mut auth = ServerAuth::new(self.driver.session_id().to_vec(), methods, authenticator);
        for _ in 0..MAX_AUTH_STEPS {
            let payload = self.next_packet().await?;
            match auth.on_packet(&payload)? {
                ServerStep::Send(p) => self.send(&p).await?,
                ServerStep::Authenticated { payload, user, .. } => {
                    self.send(&payload).await?;
                    self.driver.notify_auth_success();
                    return Ok(user);
                }
                ServerStep::Disconnect(reason) => return Err(Error::Protocol(reason)),
            }
        }
        Err(Error::Protocol("auth: too many steps without termination"))
    }

    /// Pump the transport until the next post-handshake application payload
    /// (userauth, then the connection protocol). Feed it to
    /// [`conn_mut`](Self::conn_mut)'s `on_packet`.
    pub async fn next_packet(&mut self) -> Result<Vec<u8>> {
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

    /// Encode and send `payload` (a connection-protocol payload built via
    /// [`conn_mut`](Self::conn_mut)).
    pub async fn send(&mut self, payload: &[u8]) -> Result<()> {
        self.driver.enqueue_payload(payload)?;
        self.pump_out().await
    }

    // --- internal pump ---

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
}

// Drive an `AsyncServerConnection` (server) against the real blocking `Client`
// over a blocking-backed async adapter under a minimal `block_on`, symmetric
// to the async-client test.
#[cfg(all(test, feature = "client"))]
mod tests {
    use super::*;
    use alloc::string::ToString;
    use core::future::Future;
    use core::pin::Pin;
    use core::task::{Context, Poll};
    use std::io::{Read as _, Write as _};
    use std::net::{TcpListener, TcpStream};
    use std::sync::Arc;
    use std::thread;

    use crate::auth::{AuthAttempt, AuthDecision, Authenticator};
    use crate::channel::{ChannelEvent, ChannelOpen, ChannelRequest};
    use crate::client::{Client, Config as ClientConfig};
    use crate::hostkey::{Ed25519HostKey, HostKey};
    use crate::server::{
        AuthenticatorFactory, CommandHandler, Config as ServerConfig, ExecResult, SessionEnv,
    };
    use purecrypto::rng::{OsRng, RngCore};

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

    struct UnusedHandler;
    impl CommandHandler for UnusedHandler {
        fn handle(&self, _u: &str, _e: &SessionEnv, _c: &str) -> ExecResult {
            ExecResult {
                stdout: Vec::new(),
                stderr: Vec::new(),
                exit_status: 0,
            }
        }
    }
    struct RejectAuth;
    impl Authenticator for RejectAuth {
        fn evaluate(&mut self, _a: AuthAttempt) -> AuthDecision {
            AuthDecision::Reject
        }
    }

    fn fresh_seed() -> [u8; 32] {
        let mut s = [0u8; 32];
        OsRng.fill_bytes(&mut s);
        s
    }

    #[test]
    fn async_server_handshake_auth_exec_round_trip() {
        let host_seed = fresh_seed();
        let client_seed = fresh_seed();
        let client_blob = Ed25519HostKey::from_seed(client_seed).public_blob();
        let user = "async-srv-user".to_string();
        let reply = b"async server says hi\n".to_vec();

        let host_key: Box<dyn HostKey + Send + Sync> =
            Box::new(Ed25519HostKey::from_seed(host_seed));
        let factory: Arc<dyn AuthenticatorFactory> =
            Arc::new(|| Box::new(RejectAuth) as Box<dyn Authenticator>);
        let cfg = Arc::new(ServerConfig::new(
            vec![host_key],
            factory,
            vec!["publickey"],
            Arc::new(UnusedHandler),
        ));

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");

        let cu = user.clone();
        let client_thread = thread::spawn(move || -> (Vec<u8>, Option<u32>) {
            let mut client =
                Client::connect(addr, ClientConfig::insecure()).expect("client connect");
            client
                .authenticate_publickey(&cu, Box::new(Ed25519HostKey::from_seed(client_seed)))
                .expect("auth");
            let out = client.exec("hi").expect("exec");
            (out.stdout, out.exit_status)
        });

        let (sock, _peer) = listener.accept().expect("accept");
        let user_for_auth = user.clone();
        let blob = client_blob.clone();
        let reply_for_srv = reply.clone();
        block_on(async move {
            let mut srv = AsyncServerConnection::accept(BlockingAsync(sock), cfg)
                .await
                .expect("accept");
            let who = srv
                .authenticate(
                    Box::new(OneKeyAuth {
                        user: user_for_auth.clone(),
                        blob,
                    }),
                    vec!["publickey"],
                )
                .await
                .expect("auth");
            assert_eq!(who, user_for_auth);

            // Session loop: accept a session channel, answer the exec.
            let mut session_ch: Option<u32> = None;
            for _ in 0..100_000 {
                let p = srv.next_packet().await.expect("packet");
                let ev = srv.conn_mut().on_packet(&p).expect("on_packet");
                match ev {
                    ChannelEvent::OpenRequest { channel, kind } => {
                        if matches!(kind, ChannelOpen::Session) {
                            let pl = srv.conn_mut().accept_open(channel).expect("accept");
                            srv.send(&pl).await.expect("send");
                            session_ch = Some(channel);
                        }
                    }
                    ChannelEvent::Request {
                        channel,
                        request,
                        want_reply,
                    } if Some(channel) == session_ch => {
                        if matches!(request, ChannelRequest::Exec { .. }) {
                            if want_reply {
                                let pl = srv.conn_mut().send_request_success(channel).expect("s");
                                srv.send(&pl).await.expect("send");
                            }
                            let (pl, _n) = srv
                                .conn_mut()
                                .send_data(channel, &reply_for_srv)
                                .expect("d");
                            srv.send(&pl).await.expect("send");
                            let pl = srv
                                .conn_mut()
                                .send_request(
                                    channel,
                                    ChannelRequest::ExitStatus { code: 0 },
                                    false,
                                )
                                .expect("e");
                            srv.send(&pl).await.expect("send");
                            let pl = srv.conn_mut().send_eof(channel).expect("eof");
                            srv.send(&pl).await.expect("send");
                            let pl = srv.conn_mut().send_close(channel).expect("close");
                            srv.send(&pl).await.expect("send");
                        }
                    }
                    ChannelEvent::Close { channel } if Some(channel) == session_ch => break,
                    _ => {}
                }
            }
        });

        let (stdout, exit) = client_thread.join().expect("client thread");
        assert_eq!(
            stdout, reply,
            "exec stdout round-trips through the async server"
        );
        assert_eq!(exit, Some(0));
    }
}
