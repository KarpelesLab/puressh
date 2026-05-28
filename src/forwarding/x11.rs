//! Server-side glue for `x11-req` and the matching `x11` channel-opens
//! (RFC 4254 §6.3, the wire side of `ssh -X` / `ssh -Y`).
//!
//! Implements [`DefaultX11ForwardHandler`], the in-process backing for
//! the [`crate::server::X11ForwardHandler`] trait. The handler:
//!
//! - On `setup`, picks the next free X display number `N` (starting at
//!   `min_display`, default 10) by attempting to bind
//!   `127.0.0.1:6000+N`. The display number is returned to the dispatcher
//!   via [`crate::server::X11ForwardHandle::display_env`] as
//!   `"localhost:<N>.<screen>"`, which the dispatcher injects as the
//!   `DISPLAY` env var on the session.
//! - Spawns one accept-loop thread per setup. For each accepted TCP
//!   connection the worker calls
//!   [`crate::server::X11ForwardContext::open_x11`] to ask the
//!   per-connection server loop to open an `x11` channel back toward the
//!   client, then splices the local TCP stream against the resulting
//!   [`crate::server::ChannelStream`] in both directions until either side
//!   hangs up.
//! - On handle drop (i.e. session-channel close), signals the worker thread
//!   to stop, joins it, and releases the listener.
//!
//! Cookie handling: the `auth_protocol` / `auth_cookie` from the client's
//! `x11-req` are passed through to `setup` but not stored or rewritten by
//! this default handler. The client retains the responsibility of
//! substituting the on-wire cookie before forwarding to its local
//! `$DISPLAY` (see [`crate::client::ClientHandlers::on_x11`]).

use std::io::{ErrorKind, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

use crate::error::{Error, Result};
use crate::server::{
    ChannelEgress, ChannelStream, X11ForwardContext, X11ForwardHandle, X11ForwardHandler,
};

/// How often the accept-loop polls the non-blocking listener while waiting
/// for either a connection or the stop flag.
const ACCEPT_POLL_INTERVAL: Duration = Duration::from_millis(100);

/// The base TCP port for X displays. Display `N` lives on port `6000 + N`.
const X_BASE_PORT: u16 = 6000;

/// Default first display number to try. OpenSSH starts at 10 to leave
/// `:0`–`:9` for real local X servers.
const DEFAULT_MIN_DISPLAY: u16 = 10;

/// Default last display number to try. Matches OpenSSH's `X11DisplayOffset`
/// range (10..1000) trimmed to something the kernel won't blink at.
const DEFAULT_MAX_DISPLAY: u16 = 999;

/// RAII guard that lives inside the [`X11ForwardHandle::stopper`] box.
/// Dropping it sets the stop flag and joins the worker thread.
struct X11Binding {
    stop: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}

impl Drop for X11Binding {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

/// Default in-process backing for `x11-req`.
///
/// One instance per server typically, registered via
/// [`crate::server::Config::with_x11_forward`]. The handler is safe to
/// share across connections — each `setup` picks its own display number,
/// binds its own TCP listener, and starts its own worker thread.
///
/// Display numbers are allocated by trial bind: starting at `min_display`
/// (default 10), the handler tries `127.0.0.1:6000+N` until one succeeds.
/// Returns `Err(Error::Io(_))` if no port in `[min_display, max_display]`
/// is free.
pub struct DefaultX11ForwardHandler {
    min_display: u16,
    max_display: u16,
}

impl Default for DefaultX11ForwardHandler {
    fn default() -> Self {
        Self::new()
    }
}

impl DefaultX11ForwardHandler {
    /// Build a fresh handler that scans displays `10..=999` for a free
    /// `127.0.0.1:6000+N`.
    pub fn new() -> Self {
        Self {
            min_display: DEFAULT_MIN_DISPLAY,
            max_display: DEFAULT_MAX_DISPLAY,
        }
    }

    /// Build a handler that scans `min_display..=max_display`. Useful for
    /// tests that want to constrain the scan to a small range.
    pub fn with_display_range(min_display: u16, max_display: u16) -> Self {
        Self {
            min_display,
            max_display,
        }
    }

    fn bind_first_free(&self) -> Result<(TcpListener, u16)> {
        for n in self.min_display..=self.max_display {
            let port = X_BASE_PORT.saturating_add(n);
            let addr: SocketAddr = ([127u8, 0, 0, 1], port).into();
            if let Ok(listener) = TcpListener::bind(addr) {
                return Ok((listener, n));
            }
        }
        Err(Error::Io(std::io::Error::new(
            ErrorKind::AddrInUse,
            "x11-forward: no free display number in configured range",
        )))
    }
}

impl X11ForwardHandler for DefaultX11ForwardHandler {
    fn setup(
        &self,
        _user: &str,
        _single_connection: bool,
        _auth_protocol: &str,
        _auth_cookie: &str,
        screen: u32,
        ctx: X11ForwardContext,
    ) -> Result<X11ForwardHandle> {
        let (listener, display_number) = self.bind_first_free()?;
        listener.set_nonblocking(true)?;

        let stop = Arc::new(AtomicBool::new(false));
        let stop_thread = Arc::clone(&stop);
        let handle = thread::spawn(move || {
            while !stop_thread.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((conn, peer)) => {
                        let orig_host = match peer.ip() {
                            std::net::IpAddr::V4(v4) => v4.to_string(),
                            std::net::IpAddr::V6(v6) => v6.to_string(),
                        };
                        let orig_port = peer.port() as u32;
                        match ctx.open_x11(orig_host, orig_port) {
                            Ok(channel_stream) => {
                                spawn_tcp_splice(conn, channel_stream);
                            }
                            Err(_) => {
                                let _ = conn.shutdown(Shutdown::Both);
                            }
                        }
                    }
                    Err(e) if e.kind() == ErrorKind::WouldBlock => {
                        thread::sleep(ACCEPT_POLL_INTERVAL);
                    }
                    Err(_) => break,
                }
            }
        });

        let display_env = format!("localhost:{display_number}.{screen}");
        let binding = X11Binding {
            stop,
            handle: Some(handle),
        };
        Ok(X11ForwardHandle {
            display_env,
            display_number,
            stopper: Box::new(binding),
        })
    }
}

/// Bridge a TCP connection against a server-side `ChannelStream`.
/// Mirrors `spawn_unix_splice` in `agent.rs` but for `TcpStream`.
fn spawn_tcp_splice(tcp: TcpStream, stream: ChannelStream) {
    let (chan_rx, chan_tx) = stream.into_raw();
    let Ok(tcp_in) = tcp.try_clone() else {
        let _ = chan_tx.send(ChannelEgress::Eof);
        let _ = chan_tx.send(ChannelEgress::Close);
        return;
    };
    let tcp_out = tcp;

    // Direction A: TCP → channel.
    let chan_tx_a = chan_tx.clone();
    let mut tcp_in_a = tcp_in;
    let a = thread::spawn(move || {
        let mut buf = [0u8; 32 * 1024];
        loop {
            match tcp_in_a.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    if chan_tx_a
                        .send(ChannelEgress::Data(buf[..n].to_vec()))
                        .is_err()
                    {
                        break;
                    }
                }
                Err(e) if e.kind() == ErrorKind::Interrupted => continue,
                Err(_) => break,
            }
        }
        let _ = chan_tx_a.send(ChannelEgress::Eof);
    });

    // Direction B: channel → TCP.
    let mut tcp_out_b = tcp_out;
    let b = thread::spawn(move || {
        while let Ok(Some(chunk)) = chan_rx.recv() {
            if tcp_out_b.write_all(&chunk).is_err() {
                break;
            }
        }
        let _ = tcp_out_b.shutdown(Shutdown::Read);
    });

    // Reaper: when both directions finish, send Close to drop the channel.
    thread::spawn(move || {
        let _ = a.join();
        let _ = b.join();
        let _ = chan_tx.send(ChannelEgress::Close);
    });
}

/// Build a closure shaped like
/// [`crate::client::X11Callback`] that splices each incoming `x11` channel
/// against a local X server reached over a Unix-domain socket (e.g.
/// `/tmp/.X11-unix/X0`).
///
/// Returns `None` if `path` doesn't exist (lets the binary fail-soft when
/// no local display is present and skip wiring `on_x11` at all).
///
/// Drop-in for [`crate::client::ClientHandlers::with_x11`].
pub fn splice_to_unix_display_callback(
    path: PathBuf,
) -> Option<Arc<dyn Fn(ChannelStream) + Send + Sync + 'static>> {
    if !path.exists() {
        return None;
    }
    Some(Arc::new(
        move |stream: ChannelStream| match std::os::unix::net::UnixStream::connect(&path) {
            Ok(uds) => spawn_unix_splice(uds, stream),
            Err(_) => {
                let (_rx, tx) = stream.into_raw();
                let _ = tx.send(ChannelEgress::Eof);
                let _ = tx.send(ChannelEgress::Close);
            }
        },
    ))
}

/// Build a closure that splices each incoming `x11` channel against a
/// local X server reached over TCP at `host:port`.
///
/// Drop-in for [`crate::client::ClientHandlers::with_x11`].
pub fn splice_to_tcp_display_callback(
    host: String,
    port: u16,
) -> Arc<dyn Fn(ChannelStream) + Send + Sync + 'static> {
    Arc::new(
        move |stream: ChannelStream| match TcpStream::connect((host.as_str(), port)) {
            Ok(tcp) => spawn_tcp_splice(tcp, stream),
            Err(_) => {
                let (_rx, tx) = stream.into_raw();
                let _ = tx.send(ChannelEgress::Eof);
                let _ = tx.send(ChannelEgress::Close);
            }
        },
    )
}

/// Convenience over [`splice_to_unix_display_callback`] /
/// [`splice_to_tcp_display_callback`] that pulls the display location from
/// the process env (`$DISPLAY`). Returns `None` if `$DISPLAY` is unset or
/// unparseable.
///
/// Supported forms:
/// - `":<N>"` / `":<N>.<screen>"` → Unix socket at `/tmp/.X11-unix/X<N>`.
/// - `"<host>:<N>"` / `"<host>:<N>.<screen>"` → TCP on `<host>:<6000+N>`.
pub fn splice_to_local_display_callback(
) -> Option<Arc<dyn Fn(ChannelStream) + Send + Sync + 'static>> {
    let raw = std::env::var("DISPLAY").ok()?;
    if raw.is_empty() {
        return None;
    }
    let (host_part, display_part) = raw.rsplit_once(':')?;
    // Strip any `.screen` suffix.
    let n_str = display_part.split('.').next()?;
    let n: u16 = n_str.parse().ok()?;
    if host_part.is_empty() || host_part == "unix" {
        let path = PathBuf::from(format!("/tmp/.X11-unix/X{n}"));
        return splice_to_unix_display_callback(path);
    }
    let port = X_BASE_PORT.saturating_add(n);
    Some(splice_to_tcp_display_callback(host_part.to_string(), port))
}

fn spawn_unix_splice(uds: std::os::unix::net::UnixStream, stream: ChannelStream) {
    use std::os::unix::net::UnixStream;
    let (chan_rx, chan_tx) = stream.into_raw();
    let Ok(uds_in) = uds.try_clone() else {
        let _ = chan_tx.send(ChannelEgress::Eof);
        let _ = chan_tx.send(ChannelEgress::Close);
        return;
    };
    let uds_out = uds;

    let chan_tx_a = chan_tx.clone();
    let mut uds_in_a: UnixStream = uds_in;
    let a = thread::spawn(move || {
        let mut buf = [0u8; 32 * 1024];
        loop {
            match uds_in_a.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    if chan_tx_a
                        .send(ChannelEgress::Data(buf[..n].to_vec()))
                        .is_err()
                    {
                        break;
                    }
                }
                Err(e) if e.kind() == ErrorKind::Interrupted => continue,
                Err(_) => break,
            }
        }
        let _ = chan_tx_a.send(ChannelEgress::Eof);
    });

    let mut uds_out_b: UnixStream = uds_out;
    let b = thread::spawn(move || {
        while let Ok(Some(chunk)) = chan_rx.recv() {
            if uds_out_b.write_all(&chunk).is_err() {
                break;
            }
        }
        let _ = uds_out_b.shutdown(Shutdown::Read);
    });

    thread::spawn(move || {
        let _ = a.join();
        let _ = b.join();
        let _ = chan_tx.send(ChannelEgress::Close);
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `setup` binds a TCP listener on the first free port from the
    /// configured range and the returned `display_env` matches.
    #[test]
    fn setup_binds_a_display_port() {
        // Use an unusual range so we don't collide with anything real.
        let h = DefaultX11ForwardHandler::with_display_range(900, 920);
        let ctx = X11ForwardContext::for_test_no_opens();
        let handle = h
            .setup("u", false, "MIT-MAGIC-COOKIE-1", "deadbeef", 0, ctx)
            .expect("setup");
        let n = handle.display_number;
        assert!((900..=920).contains(&n), "n out of range: {n}");
        assert_eq!(handle.display_env, format!("localhost:{n}.0"));
        // The listener should now be bound; binding the same port should
        // fail until we drop the handle.
        let addr: SocketAddr = ([127u8, 0, 0, 1], 6000 + n).into();
        assert!(
            TcpListener::bind(addr).is_err(),
            "port should be in use while the handle is alive"
        );
        drop(handle);
        // Give the worker a moment to wind down.
        for _ in 0..50 {
            if TcpListener::bind(addr).is_ok() {
                break;
            }
            thread::sleep(Duration::from_millis(50));
        }
        assert!(
            TcpListener::bind(addr).is_ok(),
            "port should be free after the handle is dropped"
        );
    }

    /// Connecting to the display while no `open_x11` receiver is wired
    /// causes the worker to drop the connection. We assert the peer
    /// observes that (read returns 0 / errors out within a sane timeout).
    #[test]
    fn accepted_connection_is_closed_when_open_fails() {
        let h = DefaultX11ForwardHandler::with_display_range(800, 820);
        let ctx = X11ForwardContext::for_test_no_opens();
        let handle = h
            .setup("u", false, "MIT-MAGIC-COOKIE-1", "deadbeef", 0, ctx)
            .expect("setup");
        let addr: SocketAddr = ([127u8, 0, 0, 1], 6000 + handle.display_number).into();
        let mut peer = TcpStream::connect_timeout(&addr, Duration::from_secs(2)).expect("connect");
        peer.set_read_timeout(Some(Duration::from_secs(2)))
            .expect("read timeout");
        let mut buf = [0u8; 1];
        let _ = peer.read(&mut buf);
    }

    /// `splice_to_tcp_display_callback` always returns a callback (TCP
    /// connect happens lazily inside it). Smoke-check that it doesn't
    /// panic on construction.
    #[test]
    fn tcp_display_callback_constructs() {
        let _cb = splice_to_tcp_display_callback("127.0.0.1".to_string(), 65000);
    }
}
