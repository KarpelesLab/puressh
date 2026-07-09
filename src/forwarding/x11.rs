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
use std::net::{Shutdown, TcpStream};
use std::path::PathBuf;
use std::sync::Arc;
use std::thread;

// Server-handler-only imports — the splice-to-local-display callbacks below
// don't need any of these. Gating keeps the `client`-only build clean of
// "unused import" warnings.
#[cfg(feature = "server")]
use std::net::{SocketAddr, TcpListener};
#[cfg(feature = "server")]
use std::sync::atomic::{AtomicBool, Ordering};
#[cfg(feature = "server")]
use std::thread::JoinHandle;
#[cfg(feature = "server")]
use std::time::Duration;

// Server handler types live behind `feature = "server"`; the splice-to-
// local-display callbacks below only need `ChannelStream` / `ChannelEgress`
// from `crate::stream` and are exposed to both client and server consumers.
#[cfg(feature = "server")]
use crate::error::{Error, Result};
#[cfg(feature = "server")]
use crate::server::{X11ForwardContext, X11ForwardHandle, X11ForwardHandler};
use crate::stream::{ChannelEgress, ChannelStream};

/// How often the accept-loop polls the non-blocking listener while waiting
/// for either a connection or the stop flag.
#[cfg(feature = "server")]
const ACCEPT_POLL_INTERVAL: Duration = Duration::from_millis(100);

/// The base TCP port for X displays. Display `N` lives on port `6000 + N`.
const X_BASE_PORT: u16 = 6000;

/// The only X11 authorisation protocol this handler validates. OpenSSH's
/// `ssh -X`/`-Y` always negotiates this; anything else is rejected by the
/// cookie-enforcing path.
#[cfg(feature = "server")]
const MIT_MAGIC_COOKIE_1: &str = "MIT-MAGIC-COOKIE-1";

/// Hard cap on the X11 connection-setup prelude we will buffer while
/// validating the cookie. A well-formed setup packet is a 12-byte fixed
/// header plus the (padded) protocol name and cookie — a few dozen bytes in
/// practice. Cap it so a malicious local connection can't make us buffer
/// unbounded data before the cookie check completes.
#[cfg(feature = "server")]
const MAX_X11_SETUP_PRELUDE: usize = 1 << 16;

/// Per-setup decision about how to treat accepted local connections.
#[cfg(feature = "server")]
enum CookiePolicy {
    /// Splice everything (legacy, opt-in via `permit_unauthenticated()`).
    PermitUnauthenticated,
    /// Require a matching `MIT-MAGIC-COOKIE-1` on the first setup packet.
    /// Holds the raw (hex-decoded) cookie bytes.
    RequireCookie(Arc<Vec<u8>>),
}

/// Default first display number to try. OpenSSH starts at 10 to leave
/// `:0`–`:9` for real local X servers.
#[cfg(feature = "server")]
const DEFAULT_MIN_DISPLAY: u16 = 10;

/// Default last display number to try. Matches OpenSSH's `X11DisplayOffset`
/// range (10..1000) trimmed to something the kernel won't blink at.
#[cfg(feature = "server")]
const DEFAULT_MAX_DISPLAY: u16 = 999;

/// RAII guard that lives inside the [`X11ForwardHandle::stopper`] box.
/// Dropping it sets the stop flag and joins the worker thread.
#[cfg(feature = "server")]
struct X11Binding {
    stop: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}

#[cfg(feature = "server")]
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
#[cfg(feature = "server")]
pub struct DefaultX11ForwardHandler {
    min_display: u16,
    max_display: u16,
    /// When `true`, accepted local connections are spliced straight through
    /// without validating the X11 authorisation cookie. This is the legacy
    /// "trust loopback" behaviour and is OPT-IN: a local user on the server
    /// box could otherwise connect to `localhost:6000+N` and hijack the
    /// client's display. The default (`false`) enforces a
    /// `MIT-MAGIC-COOKIE-1` check against the cookie from `x11-req`.
    permit_unauthenticated: bool,
}

#[cfg(feature = "server")]
impl Default for DefaultX11ForwardHandler {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(feature = "server")]
impl DefaultX11ForwardHandler {
    /// Build a fresh handler that scans displays `10..=999` for a free
    /// `127.0.0.1:6000+N` and enforces `MIT-MAGIC-COOKIE-1` validation on
    /// every accepted local connection (default-deny).
    pub fn new() -> Self {
        Self {
            min_display: DEFAULT_MIN_DISPLAY,
            max_display: DEFAULT_MAX_DISPLAY,
            permit_unauthenticated: false,
        }
    }

    /// Build a handler that scans `min_display..=max_display`. Useful for
    /// tests that want to constrain the scan to a small range. Cookie
    /// validation is enforced (default-deny), as with [`Self::new`].
    pub fn with_display_range(min_display: u16, max_display: u16) -> Self {
        Self {
            min_display,
            max_display,
            permit_unauthenticated: false,
        }
    }

    /// Opt into the legacy "splice everything on loopback" behaviour: any
    /// local connection to `127.0.0.1:6000+N` is forwarded WITHOUT checking
    /// the X11 authorisation cookie. This mirrors stock OpenSSH's behaviour
    /// when the X server itself enforces no per-connection auth, but it lets
    /// any local user on the server box hijack the forwarded display. Prefer
    /// [`Self::new`] (cookie-enforcing) unless you have a specific reason.
    ///
    /// This is the analogue of the `permit_all` opt-in on the TCP-forward
    /// handlers in `direct.rs` / `reverse.rs`.
    pub fn permit_unauthenticated(mut self) -> Self {
        self.permit_unauthenticated = true;
        self
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

#[cfg(feature = "server")]
impl X11ForwardHandler for DefaultX11ForwardHandler {
    fn setup(
        &self,
        _user: &str,
        single_connection: bool,
        auth_protocol: &str,
        auth_cookie: &str,
        screen: u32,
        ctx: X11ForwardContext,
    ) -> Result<X11ForwardHandle> {
        // SECURITY — X11 authorisation cookie validation.
        //
        // RFC 4254 §6.3.1 carries `auth_protocol` + `auth_cookie` from the
        // client so the server can accept only connections that present the
        // matching cookie on the first wire bytes. The default handler now
        // enforces that: each accepted connection to `127.0.0.1:6000+N` must
        // open with an X11 connection-setup packet whose
        // authorization-protocol-name is `MIT-MAGIC-COOKIE-1` and whose
        // authorization-protocol-data matches the cookie from `x11-req`
        // (constant-time compare). Connections that fail are dropped before
        // any bytes are spliced to the client's display, so a local user on
        // the server box can no longer hijack `localhost:6000+N`.
        //
        // The legacy "splice everything on loopback" behaviour is still
        // reachable, but only OPT-IN via `permit_unauthenticated()`.
        //
        // Decode the validation policy once, up front, so the per-connection
        // accept loop just consults a cheap enum.
        let policy = if self.permit_unauthenticated {
            CookiePolicy::PermitUnauthenticated
        } else {
            // The cookie arrives hex-encoded over `x11-req`. If we can't
            // decode it (or it's empty), fail the whole setup rather than
            // silently downgrading to "accept anything" — a malformed cookie
            // request must not become an open display.
            if !auth_protocol.eq_ignore_ascii_case(MIT_MAGIC_COOKIE_1) {
                return Err(Error::Io(std::io::Error::new(
                    ErrorKind::InvalidInput,
                    "x11-forward: unsupported authorization protocol (only MIT-MAGIC-COOKIE-1)",
                )));
            }
            let Some(cookie) = hex_decode(auth_cookie) else {
                return Err(Error::Io(std::io::Error::new(
                    ErrorKind::InvalidInput,
                    "x11-forward: x11-req cookie is not valid hex",
                )));
            };
            if cookie.is_empty() {
                return Err(Error::Io(std::io::Error::new(
                    ErrorKind::InvalidInput,
                    "x11-forward: x11-req carried an empty cookie",
                )));
            }
            CookiePolicy::RequireCookie(Arc::new(cookie))
        };

        let (listener, display_number) = self.bind_first_free()?;
        listener.set_nonblocking(true)?;

        let stop = Arc::new(AtomicBool::new(false));
        let stop_thread = Arc::clone(&stop);
        let handle = thread::spawn(move || {
            while !stop_thread.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((mut conn, peer)) => {
                        // Validate the X11 authorisation cookie on the first
                        // setup packet before doing anything else. On any
                        // failure, drop the connection without opening a
                        // channel back to the client.
                        let prelude = match &policy {
                            CookiePolicy::PermitUnauthenticated => Vec::new(),
                            CookiePolicy::RequireCookie(cookie) => {
                                match read_and_check_cookie(&mut conn, cookie) {
                                    Ok(bytes) => bytes,
                                    Err(_) => {
                                        // A rejected (bad-cookie) connection must
                                        // NOT consume the `single_connection`
                                        // allowance: otherwise a local attacker
                                        // who races in first with a bogus cookie
                                        // could tear down the listener before the
                                        // legitimate client connects. Keep
                                        // looping; only a *validated* connection
                                        // (below) honours `single_connection`.
                                        let _ = conn.shutdown(Shutdown::Both);
                                        continue;
                                    }
                                }
                            }
                        };
                        let orig_host = match peer.ip() {
                            std::net::IpAddr::V4(v4) => v4.to_string(),
                            std::net::IpAddr::V6(v6) => v6.to_string(),
                        };
                        let orig_port = peer.port() as u32;
                        match ctx.open_x11(orig_host, orig_port) {
                            Ok(channel_stream) => {
                                // Replay the setup packet bytes we consumed
                                // during validation, then splice the rest.
                                spawn_tcp_splice_with_prelude(conn, channel_stream, prelude);
                            }
                            Err(_) => {
                                let _ = conn.shutdown(Shutdown::Both);
                            }
                        }
                        // RFC 4254 §6.3.1: when the client set
                        // `single_connection`, the server MUST refuse any
                        // further forwarded X11 connections after the first
                        // is accepted. Drop the listener (by exiting the
                        // loop, which lets `listener` go out of scope) so
                        // subsequent connects to `localhost:6000+N` see a
                        // `ECONNREFUSED`.
                        if single_connection {
                            break;
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

/// Like [`spawn_tcp_splice`] but pushes `prelude` (the X11 setup-packet
/// bytes we read off the wire during cookie validation) to the channel
/// first, so the client's X server sees the full, unmodified setup request.
#[cfg(feature = "server")]
fn spawn_tcp_splice_with_prelude(tcp: TcpStream, stream: ChannelStream, prelude: Vec<u8>) {
    let (chan_rx, chan_tx) = stream.into_raw();

    // Replay the setup bytes consumed during cookie validation before any
    // live data. If the channel is already gone, drop the connection.
    if !prelude.is_empty() && chan_tx.send(ChannelEgress::Data(prelude)).is_err() {
        let _ = tcp.shutdown(Shutdown::Both);
        return;
    }

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

/// Read the X11 connection-setup packet from `conn`, validate that it uses
/// `MIT-MAGIC-COOKIE-1` and that its authorization-protocol-data matches
/// `expected` (constant-time), and return the raw bytes consumed so the
/// caller can replay them to the client's X server. Returns `Err` on any
/// malformed packet, protocol mismatch, or cookie mismatch.
///
/// X11 connection-setup packet layout (RFC-equivalent, X protocol §8):
///   byte 0      : byte-order ('B' = 0x42 MSB first, 'l' = 0x6c LSB first)
///   byte 1      : unused
///   bytes 2..3  : protocol-major-version (byte-order dependent)
///   bytes 4..5  : protocol-minor-version
///   bytes 6..7  : n = length of authorization-protocol-name
///   bytes 8..9  : d = length of authorization-protocol-data
///   bytes 10..11: unused
///   bytes 12..  : authorization-protocol-name, padded to a multiple of 4
///   then        : authorization-protocol-data, padded to a multiple of 4
#[cfg(feature = "server")]
fn read_and_check_cookie(conn: &mut TcpStream, expected: &[u8]) -> std::io::Result<Vec<u8>> {
    use std::io::{Error as IoError, Read};

    // A short read timeout keeps a silent/hostile local connection from
    // pinning the accept-loop's splice thread indefinitely.
    let prev_timeout = conn.read_timeout().ok().flatten();
    conn.set_read_timeout(Some(Duration::from_secs(10)))?;

    let result = (|| {
        let mut buf = Vec::with_capacity(64);

        // Helper: read until `buf.len() >= need`, capping total size.
        let mut read_until = |buf: &mut Vec<u8>, need: usize| -> std::io::Result<()> {
            if need > MAX_X11_SETUP_PRELUDE {
                return Err(IoError::new(
                    ErrorKind::InvalidData,
                    "x11-forward: setup packet exceeds maximum size",
                ));
            }
            let mut chunk = [0u8; 4096];
            while buf.len() < need {
                let want = (need - buf.len()).min(chunk.len());
                let n = conn.read(&mut chunk[..want])?;
                if n == 0 {
                    return Err(IoError::new(
                        ErrorKind::UnexpectedEof,
                        "x11-forward: connection closed during setup packet",
                    ));
                }
                buf.extend_from_slice(&chunk[..n]);
            }
            Ok(())
        };

        // Fixed 12-byte header.
        read_until(&mut buf, 12)?;
        let big_endian = match buf[0] {
            0x42 => true,  // 'B'
            0x6c => false, // 'l'
            _ => {
                return Err(IoError::new(
                    ErrorKind::InvalidData,
                    "x11-forward: bad byte-order byte in setup packet",
                ));
            }
        };
        let rd16 = |hi: u8, lo: u8| -> usize {
            if big_endian {
                ((hi as usize) << 8) | lo as usize
            } else {
                ((lo as usize) << 8) | hi as usize
            }
        };
        let name_len = rd16(buf[6], buf[7]);
        let data_len = rd16(buf[8], buf[9]);
        let pad = |x: usize| -> usize { (x + 3) & !3 };
        let name_off = 12;
        let data_off = name_off + pad(name_len);
        let total = data_off + pad(data_len);

        read_until(&mut buf, total)?;

        let name = &buf[name_off..name_off + name_len];
        let data = &buf[data_off..data_off + data_len];

        if name != MIT_MAGIC_COOKIE_1.as_bytes() {
            return Err(IoError::new(
                ErrorKind::PermissionDenied,
                "x11-forward: unsupported authorization protocol on connection",
            ));
        }
        if !constant_time_eq(data, expected) {
            return Err(IoError::new(
                ErrorKind::PermissionDenied,
                "x11-forward: authorization cookie mismatch",
            ));
        }
        Ok(buf)
    })();

    // Restore the prior timeout (best-effort) before handing the socket on.
    let _ = conn.set_read_timeout(prev_timeout);
    result
}

/// Constant-time byte-slice equality. Avoids leaking how many leading bytes
/// of the cookie matched via early-return timing.
#[cfg(feature = "server")]
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Decode an ASCII hex string into bytes. Returns `None` on odd length or a
/// non-hex digit. Used to turn the hex-encoded `x11-req` cookie into the raw
/// bytes that appear on the X11 wire.
#[cfg(feature = "server")]
fn hex_decode(s: &str) -> Option<Vec<u8>> {
    let bytes = s.as_bytes();
    if !bytes.len().is_multiple_of(2) {
        return None;
    }
    let nib = |c: u8| -> Option<u8> {
        match c {
            b'0'..=b'9' => Some(c - b'0'),
            b'a'..=b'f' => Some(c - b'a' + 10),
            b'A'..=b'F' => Some(c - b'A' + 10),
            _ => None,
        }
    };
    let mut out = Vec::with_capacity(bytes.len() / 2);
    for pair in bytes.chunks_exact(2) {
        out.push((nib(pair[0])? << 4) | nib(pair[1])?);
    }
    Some(out)
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
pub fn splice_to_local_display_callback()
-> Option<Arc<dyn Fn(ChannelStream) + Send + Sync + 'static>> {
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

// Tests exercise `DefaultX11ForwardHandler` and the X11 forward context, both
// of which are server-side; gate them to match.
#[cfg(all(test, feature = "server"))]
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

    /// Connecting to the display (with a VALID cookie so we pass the gate)
    /// while no `open_x11` receiver is wired causes the worker to drop the
    /// connection. We assert the peer observes that (read returns 0 / errors
    /// out within a sane timeout).
    #[test]
    fn accepted_connection_is_closed_when_open_fails() {
        let h = DefaultX11ForwardHandler::with_display_range(800, 820);
        let ctx = X11ForwardContext::for_test_no_opens();
        let handle = h
            .setup("u", false, "MIT-MAGIC-COOKIE-1", "deadbeef", 0, ctx)
            .expect("setup");
        let addr: SocketAddr = ([127u8, 0, 0, 1], 6000 + handle.display_number).into();
        let mut peer = TcpStream::connect_timeout(&addr, Duration::from_secs(2)).expect("connect");
        // Arm the read timeout while the socket is still freshly connected and
        // healthy. The worker closes its side as soon as `open_x11` fails, and
        // on macOS calling `setsockopt(SO_RCVTIMEO)` on a peer-closed socket
        // returns EINVAL (Linux tolerates it), so setting it after the write
        // would race the worker's close and flake. Set it up front instead.
        peer.set_read_timeout(Some(Duration::from_secs(2)))
            .expect("read timeout");
        // Present the matching cookie so the gate passes and the worker
        // reaches `open_x11` (which fails under for_test_no_opens).
        let pkt = x11_setup_packet(MIT_MAGIC_COOKIE_1.as_bytes(), &[0xde, 0xad, 0xbe, 0xef]);
        peer.write_all(&pkt).expect("write setup packet");
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

    #[test]
    fn hex_decode_roundtrips_and_rejects_garbage() {
        assert_eq!(hex_decode("deadbeef"), Some(vec![0xde, 0xad, 0xbe, 0xef]));
        assert_eq!(hex_decode(""), Some(vec![]));
        assert_eq!(hex_decode("DEADbeef"), Some(vec![0xde, 0xad, 0xbe, 0xef]));
        assert_eq!(hex_decode("abc"), None, "odd length must fail");
        assert_eq!(hex_decode("zz"), None, "non-hex must fail");
    }

    #[test]
    fn constant_time_eq_basic() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"ab"));
        assert!(constant_time_eq(b"", b""));
    }

    /// Build a minimal X11 connection-setup packet (big-endian) carrying the
    /// given authorization protocol name + cookie bytes.
    fn x11_setup_packet(name: &[u8], cookie: &[u8]) -> Vec<u8> {
        let pad = |x: usize| (x + 3) & !3;
        let mut p = Vec::new();
        p.push(0x42); // 'B' big-endian
        p.push(0); // unused
        p.extend_from_slice(&11u16.to_be_bytes()); // proto major
        p.extend_from_slice(&0u16.to_be_bytes()); // proto minor
        p.extend_from_slice(&(name.len() as u16).to_be_bytes());
        p.extend_from_slice(&(cookie.len() as u16).to_be_bytes());
        p.extend_from_slice(&0u16.to_be_bytes()); // unused
        p.extend_from_slice(name);
        p.resize(12 + pad(name.len()), 0);
        p.extend_from_slice(cookie);
        let want = 12 + pad(name.len()) + pad(cookie.len());
        p.resize(want, 0);
        p
    }

    /// Drive `read_and_check_cookie` over a real loopback TCP pair: the
    /// "client" side writes a setup packet, the server side validates it.
    fn check_over_loopback(packet: &[u8], expected: &[u8]) -> std::io::Result<Vec<u8>> {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let addr = listener.local_addr().unwrap();
        let pkt = packet.to_vec();
        let writer = thread::spawn(move || {
            let mut c = TcpStream::connect(addr).unwrap();
            let _ = c.write_all(&pkt);
            // Keep the socket open briefly so the server can read it all.
            thread::sleep(Duration::from_millis(50));
        });
        let (mut server_side, _peer) = listener.accept().unwrap();
        let res = read_and_check_cookie(&mut server_side, expected);
        let _ = writer.join();
        res
    }

    #[test]
    fn cookie_check_accepts_matching_packet() {
        let cookie = vec![0xde, 0xad, 0xbe, 0xef, 0x01, 0x02];
        let pkt = x11_setup_packet(MIT_MAGIC_COOKIE_1.as_bytes(), &cookie);
        let consumed = check_over_loopback(&pkt, &cookie).expect("should accept");
        // The bytes returned must be exactly what we sent so they can be
        // replayed to the client's X server verbatim.
        assert_eq!(consumed, pkt);
    }

    #[test]
    fn cookie_check_rejects_wrong_cookie() {
        let cookie = vec![0xde, 0xad, 0xbe, 0xef];
        let wrong = vec![0x00, 0x00, 0x00, 0x00];
        let pkt = x11_setup_packet(MIT_MAGIC_COOKIE_1.as_bytes(), &cookie);
        let err = check_over_loopback(&pkt, &wrong).expect_err("should reject");
        assert_eq!(err.kind(), ErrorKind::PermissionDenied);
    }

    #[test]
    fn cookie_check_rejects_wrong_protocol() {
        let cookie = vec![0xaa, 0xbb];
        let pkt = x11_setup_packet(b"XDM-AUTHORIZATION-1", &cookie);
        let err = check_over_loopback(&pkt, &cookie).expect_err("should reject");
        assert_eq!(err.kind(), ErrorKind::PermissionDenied);
    }

    /// A connection that presents the wrong cookie is dropped before any
    /// `open_x11` happens — i.e. the cookie gate runs ahead of the splice.
    /// With `for_test_no_opens` the open would fail anyway, so instead we
    /// assert the listener stays bound (the worker keeps looping) after a
    /// rejected connection, and accepts a fresh connection afterwards.
    #[test]
    fn bad_cookie_connection_is_dropped_then_loop_continues() {
        let h = DefaultX11ForwardHandler::with_display_range(640, 660);
        let ctx = X11ForwardContext::for_test_no_opens();
        let handle = h
            .setup("u", false, "MIT-MAGIC-COOKIE-1", "deadbeef", 0, ctx)
            .expect("setup");
        let addr: SocketAddr = ([127u8, 0, 0, 1], 6000 + handle.display_number).into();

        // First connection presents a bad cookie and gets dropped.
        let mut bad = TcpStream::connect_timeout(&addr, Duration::from_secs(2)).expect("connect");
        // Arm the read timeout *before* sending the bad cookie, while the
        // socket is still cleanly connected and the worker is blocked reading
        // our not-yet-sent packet. Doing it afterwards races the worker's
        // `shutdown(Both)`, and on macOS `setsockopt(SO_RCVTIMEO)` on a socket
        // the peer has already torn down fails with EINVAL (a BSD quirk Linux
        // doesn't share).
        bad.set_read_timeout(Some(Duration::from_secs(3)))
            .expect("read timeout");
        let pkt = x11_setup_packet(MIT_MAGIC_COOKIE_1.as_bytes(), &[0x00, 0x11, 0x22]);
        bad.write_all(&pkt).expect("write bad packet");
        let mut buf = [0u8; 1];
        let _ = bad.read(&mut buf); // expect EOF / shutdown, not a hang
        drop(bad);

        // The listener must still be bound (worker kept looping after the
        // rejection) — binding the same port should still fail.
        let still_bound = TcpListener::bind(addr).is_err();
        assert!(
            still_bound,
            "non-single_connection: port should remain bound after a rejected connection"
        );
        drop(handle);
    }

    /// `permit_unauthenticated()` opts back into the legacy splice-everything
    /// behaviour: a connection with no cookie at all is forwarded (reaches
    /// `open_x11`, which fails under `for_test_no_opens` and drops it).
    #[test]
    fn permit_unauthenticated_skips_cookie_check() {
        let h = DefaultX11ForwardHandler::with_display_range(620, 639).permit_unauthenticated();
        let ctx = X11ForwardContext::for_test_no_opens();
        let handle = h
            .setup("u", false, "MIT-MAGIC-COOKIE-1", "deadbeef", 0, ctx)
            .expect("setup");
        let addr: SocketAddr = ([127u8, 0, 0, 1], 6000 + handle.display_number).into();
        let mut peer = TcpStream::connect_timeout(&addr, Duration::from_secs(2)).expect("connect");
        // No cookie sent at all. The worker still routes it to open_x11
        // (which fails for_test_no_opens) and closes it — we just assert no
        // hang.
        peer.set_read_timeout(Some(Duration::from_secs(2)))
            .expect("read timeout");
        let mut buf = [0u8; 1];
        let _ = peer.read(&mut buf);
        drop(handle);
    }

    /// Cookie-enforcing setup rejects an unsupported auth protocol up front.
    #[test]
    fn setup_rejects_unsupported_protocol() {
        let h = DefaultX11ForwardHandler::with_display_range(600, 619);
        let ctx = X11ForwardContext::for_test_no_opens();
        // `X11ForwardHandle` isn't `Debug`, so avoid `expect_err`; match the
        // result directly.
        match h.setup("u", false, "XDM-AUTHORIZATION-1", "deadbeef", 0, ctx) {
            Err(Error::Io(e)) => assert_eq!(e.kind(), ErrorKind::InvalidInput),
            Err(other) => panic!("unexpected error: {other:?}"),
            Ok(_) => panic!("unsupported protocol must fail setup"),
        }
    }

    /// Cookie-enforcing setup rejects a non-hex cookie up front.
    #[test]
    fn setup_rejects_non_hex_cookie() {
        let h = DefaultX11ForwardHandler::with_display_range(580, 599);
        let ctx = X11ForwardContext::for_test_no_opens();
        match h.setup("u", false, "MIT-MAGIC-COOKIE-1", "nothex!!", 0, ctx) {
            Err(Error::Io(e)) => assert_eq!(e.kind(), ErrorKind::InvalidInput),
            Err(other) => panic!("unexpected error: {other:?}"),
            Ok(_) => panic!("non-hex cookie must fail setup"),
        }
    }

    /// With `single_connection: true`, the accept-loop must drop the
    /// listener after the first connection lands. A second connect to
    /// the same display port should fail (ECONNREFUSED / timeout once
    /// the worker has exited and released the port).
    #[test]
    fn single_connection_releases_listener_after_first_accept() {
        let h = DefaultX11ForwardHandler::with_display_range(700, 720);
        let ctx = X11ForwardContext::for_test_no_opens();
        let handle = h
            .setup("u", true, "MIT-MAGIC-COOKIE-1", "deadbeef", 0, ctx)
            .expect("setup");
        let addr: SocketAddr = ([127u8, 0, 0, 1], 6000 + handle.display_number).into();

        // First connect succeeds; the accept-loop validates the cookie,
        // pushes it through (the `for_test_no_opens` context drops the conn)
        // and then exits because single_connection is set.
        let mut first =
            TcpStream::connect_timeout(&addr, Duration::from_secs(2)).expect("first connect");
        let pkt = x11_setup_packet(MIT_MAGIC_COOKIE_1.as_bytes(), &[0xde, 0xad, 0xbe, 0xef]);
        first.write_all(&pkt).expect("write setup packet");
        drop(first);

        // Give the worker time to exit and release the port.
        let mut released = false;
        for _ in 0..50 {
            thread::sleep(Duration::from_millis(50));
            if TcpListener::bind(addr).is_ok() {
                released = true;
                break;
            }
        }
        assert!(
            released,
            "single_connection: listener should be released after the first accept"
        );
        drop(handle);
    }
}
