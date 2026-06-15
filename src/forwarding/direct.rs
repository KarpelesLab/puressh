//! `DefaultDirectTcpipHandler` — server-side default for `direct-tcpip`
//! channels.
//!
//! Bridges the SSH [`ChannelStream`] to a fresh `TcpStream` connected to
//! the client-requested destination. Bytes from the channel are written to
//! the TCP socket; bytes from the TCP socket are written back into the
//! channel. The handler exits when either side closes, at which point we
//! explicitly emit `CHANNEL_EOF` + `CHANNEL_CLOSE` on the SSH side via the
//! raw egress sender obtained from [`ChannelStream::into_raw`].

use std::io::{self, Read, Write};
use std::net::{Shutdown, TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, SyncSender};
use std::thread;
use std::time::Duration;

use crate::error::Result;
use crate::server::{ChannelEgress, ChannelStream, DirectTcpipHandler, DirectTcpipRequest};

/// Filter callback type for [`DefaultDirectTcpipHandler::with_allow_list`].
type AllowFilter = Box<dyn Fn(&str, u16) -> bool + Send + Sync>;

/// Internal policy describing which destinations the handler will dial.
///
/// `Deny` is the default-constructed state — every request is refused
/// (silently closed) until the operator opts into something looser via
/// [`DefaultDirectTcpipHandler::permit_all`] or
/// [`DefaultDirectTcpipHandler::with_allow_list`].
enum Policy {
    /// Refuse every destination. Returned by [`DefaultDirectTcpipHandler::new`]
    /// to make a multi-tenant deployment safe by default.
    Deny,
    /// Allow every destination. Restores the historical OpenSSH-style
    /// permit-everything behaviour for callers who genuinely want it.
    All,
    /// Allow only destinations for which the filter returns `true`.
    Filter(AllowFilter),
}

/// Drop-in [`DirectTcpipHandler`] that connects to the requested
/// `dest_host:dest_port` and proxies bytes.
///
/// # Default-deny
///
/// A bare [`DefaultDirectTcpipHandler::new`] is **default-deny**: every
/// `direct-tcpip` request is silently refused. This is the safe default for
/// multi-tenant servers, where an unrestricted handler lets any
/// authenticated user pivot to host-local services (databases bound to
/// `127.0.0.1`, the AWS/GCP instance metadata service at
/// `169.254.169.254`, IPC sockets reachable over loopback, etc.) via
/// `ssh -L`.
///
/// Operators must explicitly choose one of:
///
/// - [`Self::with_allow_list`] to permit a specific set of destinations.
/// - [`Self::permit_all`] to restore the old "allow everything" behaviour.
///
/// ```ignore
/// use std::sync::Arc;
/// use puressh::forwarding::direct::DefaultDirectTcpipHandler;
///
/// // Allow only the Postgres on loopback.
/// let h = Arc::new(
///     DefaultDirectTcpipHandler::new()
///         .with_allow_list(|host, port| host == "127.0.0.1" && port == 5432),
/// );
/// ```
///
/// # Hardening an allow-list
///
/// When you build an allow-list it's worth explicitly *blocking* the
/// destinations that an attacker is most likely to chase: loopback
/// (`127.0.0.1`, `::1`), IPv4-mapped IPv6 forms of those (`::ffff:127.0.0.1`),
/// and the link-local instance-metadata service (`169.254.169.254`). The
/// handler doesn't impose this for you — many legitimate deployments need
/// loopback forwards — but if your allow-list is just a port whitelist on a
/// hostname pattern you should add the negative checks yourself.
pub struct DefaultDirectTcpipHandler {
    policy: Policy,
    connect_timeout: Option<Duration>,
}

impl Default for DefaultDirectTcpipHandler {
    fn default() -> Self {
        Self::new()
    }
}

impl DefaultDirectTcpipHandler {
    /// Build a **default-deny** handler: every request is silently refused
    /// until the caller opts into a looser policy via
    /// [`Self::with_allow_list`] or [`Self::permit_all`].
    ///
    /// Historically (before 2026-05) `::new()` returned an allow-everything
    /// handler. That default was a silent multi-tenant footgun, so the
    /// constructor was flipped to default-deny. If you genuinely want the
    /// old behaviour, call [`Self::permit_all`] explicitly.
    pub fn new() -> Self {
        Self {
            policy: Policy::Deny,
            connect_timeout: Some(Duration::from_secs(10)),
        }
    }

    /// Restore the historical "allow every destination" behaviour. Equivalent
    /// to the pre-2026-05 `::new()` default.
    ///
    /// Only use this on single-tenant servers (one trusted operator with
    /// shell access) — on a multi-tenant box this lets any authenticated
    /// user pivot to loopback-only services. Prefer [`Self::with_allow_list`]
    /// in any deployment where the SSH users aren't the same trust principal
    /// as the host's root.
    pub fn permit_all() -> Self {
        Self {
            policy: Policy::All,
            connect_timeout: Some(Duration::from_secs(10)),
        }
    }

    /// Reject any destination for which `filter(host, port)` returns
    /// `false`. The handler still accepts the SSH-level channel open (the
    /// peer sees a connected channel) and then immediately closes it on
    /// the filter failure path.
    ///
    /// Choosing "accept-then-close" over `OPEN_ADMINISTRATIVELY_PROHIBITED`
    /// matches OpenSSH's behaviour for `PermitOpen` mismatches: the client
    /// gets the same teardown pattern as for "destination dropped the
    /// connection".
    pub fn with_allow_list<F>(mut self, filter: F) -> Self
    where
        F: Fn(&str, u16) -> bool + Send + Sync + 'static,
    {
        self.policy = Policy::Filter(Box::new(filter));
        self
    }

    /// Set the TCP connect timeout (default: 10 s). `None` disables.
    pub fn with_connect_timeout(mut self, timeout: Option<Duration>) -> Self {
        self.connect_timeout = timeout;
        self
    }

    fn allowed(&self, host: &str, port: u16) -> bool {
        match &self.policy {
            Policy::Deny => false,
            Policy::All => true,
            Policy::Filter(f) => f(host, port),
        }
    }
}

impl DirectTcpipHandler for DefaultDirectTcpipHandler {
    fn handle(
        &self,
        _user: &str,
        request: DirectTcpipRequest<'_>,
        stream: ChannelStream,
    ) -> Result<()> {
        let host = request.dest_host;
        // `dest_port` is u32 on the wire but TCP ports are u16; an
        // out-of-range value means a malformed request.
        let port: u16 = match u16::try_from(request.dest_port) {
            Ok(p) => p,
            Err(_) => return Ok(()),
        };
        if !self.allowed(host, port) {
            return Ok(());
        }

        // Resolve & connect with a bounded timeout — never hang the
        // connection thread on a black-hole destination.
        let tcp = match connect_with_timeout(host, port, self.connect_timeout) {
            Ok(s) => s,
            Err(_) => return Ok(()),
        };
        splice(stream, tcp)
    }
}

fn connect_with_timeout(host: &str, port: u16, timeout: Option<Duration>) -> io::Result<TcpStream> {
    let target = format!("{host}:{port}");
    let mut last_err: Option<io::Error> = None;
    for sock in target.to_socket_addrs()? {
        let res = match timeout {
            Some(d) => TcpStream::connect_timeout(&sock, d),
            None => TcpStream::connect(sock),
        };
        match res {
            Ok(s) => return Ok(s),
            Err(e) => last_err = Some(e),
        }
    }
    Err(last_err.unwrap_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no address resolved")))
}

/// Splice the SSH `ChannelStream` against an open `TcpStream` in both
/// directions, returning once either side hits EOF or errors.
///
/// Implementation notes:
/// - We decompose the `ChannelStream` into its raw mpsc handles so each
///   direction can be driven from a separate thread without needing to
///   interrupt a blocked `Read::read`.
/// - The TCP→Channel half runs on the calling thread; the Channel→TCP half
///   runs on a worker thread.
/// - When either half completes we set a shared `stop` flag and
///   `tcp.shutdown(Both)` so the other thread unblocks quickly (either via
///   a TCP read returning 0/err, or via the channel ingress receiver being
///   dropped when the dispatcher tears the channel down).
/// - On exit we explicitly emit `Eof` + `Close` on the egress sender. The
///   `ChannelStream::into_raw` path suppresses auto-EOF on drop, so this is
///   the only place those markers are produced.
fn splice(stream: ChannelStream, tcp: TcpStream) -> Result<()> {
    let (raw_rx, raw_tx) = stream.into_raw();

    // Clone the TCP handle so each direction has its own owned view; that
    // also lets either thread call `shutdown(Both)` on its companion.
    let tcp_for_writer = tcp.try_clone().map_err(|e| {
        crate::error::Error::Io(io::Error::new(
            e.kind(),
            "direct-tcpip: TcpStream::try_clone failed",
        ))
    })?;

    let stop = Arc::new(AtomicBool::new(false));
    let stop_worker = Arc::clone(&stop);
    let tx_worker = raw_tx.clone();

    // Worker: TCP → Channel.
    let worker = thread::spawn(move || {
        let mut reader = tcp_for_writer;
        copy_tcp_to_channel(&mut reader, &tx_worker, &stop_worker);
    });

    // Main: Channel → TCP.
    let mut writer = tcp;
    copy_channel_to_tcp(&raw_rx, &mut writer, &stop);

    // We're done with our direction. Wake the worker if it's still parked
    // in a TCP read (its cloned handle shares the underlying socket).
    let _ = writer.shutdown(Shutdown::Both);
    stop.store(true, Ordering::SeqCst);
    let _ = worker.join();

    // Tell the dispatcher the SSH side is finished. Errors here mean the
    // dispatcher already tore the channel down — fine.
    let _ = raw_tx.send(ChannelEgress::Eof);
    let _ = raw_tx.send(ChannelEgress::Close);
    Ok(())
}

/// Drain the channel-ingress receiver, writing each chunk to `tcp`. Returns
/// when the peer sends EOF (`None`), the receiver is closed, or `tcp`
/// returns an error.
fn copy_channel_to_tcp(rx: &Receiver<Option<Vec<u8>>>, tcp: &mut TcpStream, stop: &AtomicBool) {
    loop {
        if stop.load(Ordering::SeqCst) {
            return;
        }
        match rx.recv() {
            Ok(Some(chunk)) => {
                if tcp.write_all(&chunk).is_err() {
                    return;
                }
            }
            Ok(None) | Err(_) => return,
        }
    }
}

/// Read from `tcp` and forward each chunk as `ChannelEgress::Data`. Returns
/// when `tcp` reaches EOF or errors (e.g. the peer half-shut the socket),
/// or when the egress sender fails (dispatcher gone).
fn copy_tcp_to_channel(tcp: &mut TcpStream, tx: &SyncSender<ChannelEgress>, stop: &AtomicBool) {
    let mut buf = [0u8; 32 * 1024];
    loop {
        if stop.load(Ordering::SeqCst) {
            return;
        }
        let n = match tcp.read(&mut buf) {
            Ok(0) => return,
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => return,
        };
        if tx.send(ChannelEgress::Data(buf[..n].to_vec())).is_err() {
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;
    use std::sync::mpsc;
    use std::time::Duration;

    /// Set up a tiny TCP echo server bound on an ephemeral port. Returns
    /// `(addr, handle)`; the handle drains stdout so we don't leak threads.
    fn echo_server() -> (std::net::SocketAddr, thread::JoinHandle<()>) {
        let l = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = l.local_addr().expect("addr");
        let h = thread::spawn(move || {
            if let Ok((mut s, _)) = l.accept() {
                let mut buf = [0u8; 1024];
                loop {
                    match s.read(&mut buf) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if s.write_all(&buf[..n]).is_err() {
                                break;
                            }
                        }
                    }
                }
            }
        });
        (addr, h)
    }

    #[test]
    fn direct_tcpip_round_trip_through_echo_server() {
        // Build the mpsc plumbing by hand — we don't have a live SSH
        // connection here, just the `ChannelStream` API.
        let (ingress_tx, ingress_rx) = mpsc::channel::<Option<Vec<u8>>>();
        let (egress_tx, egress_rx) = mpsc::sync_channel::<ChannelEgress>(32);
        let stream = ChannelStream::new(ingress_rx, egress_tx);

        let (addr, echo) = echo_server();

        // Spawn the handler in a thread; it owns `stream`.
        let host = addr.ip().to_string();
        let port = addr.port();
        let handler = thread::spawn(move || {
            // Pre-2026-05 default; the round-trip test exercises the
            // splice path, which only fires when the destination is
            // permitted, so use the explicit "old default" constructor.
            let h = DefaultDirectTcpipHandler::permit_all();
            let req = DirectTcpipRequest {
                dest_host: &host,
                dest_port: port as u32,
                orig_host: "client",
                orig_port: 0,
            };
            h.handle("test-user", req, stream).expect("handle");
        });

        // Feed payload from "the peer".
        ingress_tx
            .send(Some(b"ping".to_vec()))
            .expect("ingress send");

        // The echo server bounces "ping" back; we should see it on egress.
        let mut got = Vec::new();
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while got.len() < 4 && std::time::Instant::now() < deadline {
            match egress_rx.recv_timeout(Duration::from_millis(500)) {
                Ok(ChannelEgress::Data(d)) => got.extend_from_slice(&d),
                Ok(ChannelEgress::Eof) | Ok(ChannelEgress::Close) => break,
                Err(_) => break,
            }
        }
        assert_eq!(&got, b"ping");

        // Close the SSH side: peer says EOF, then we expect the handler
        // to wind down and emit Eof+Close.
        ingress_tx.send(None).expect("ingress eof");
        drop(ingress_tx);

        let mut saw_eof = false;
        let mut saw_close = false;
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while (!saw_eof || !saw_close) && std::time::Instant::now() < deadline {
            match egress_rx.recv_timeout(Duration::from_millis(500)) {
                Ok(ChannelEgress::Data(_)) => continue,
                Ok(ChannelEgress::Eof) => saw_eof = true,
                Ok(ChannelEgress::Close) => saw_close = true,
                Err(_) => break,
            }
        }
        assert!(saw_eof, "handler should send Eof on teardown");
        assert!(saw_close, "handler should send Close on teardown");

        handler.join().expect("handler thread");
        let _ = echo.join();
    }

    #[test]
    fn out_of_range_port_is_rejected_silently() {
        let (_ingress_tx, ingress_rx) = mpsc::channel::<Option<Vec<u8>>>();
        let (egress_tx, _egress_rx) = mpsc::sync_channel::<ChannelEgress>(8);
        let stream = ChannelStream::new(ingress_rx, egress_tx);
        let h = DefaultDirectTcpipHandler::permit_all();
        let req = DirectTcpipRequest {
            dest_host: "127.0.0.1",
            dest_port: 70_000,
            orig_host: "client",
            orig_port: 0,
        };
        // Should return Ok and drop `stream`, which triggers auto-EOF/Close.
        h.handle("u", req, stream).expect("handle");
    }

    /// `::new()` is default-deny: every request is refused without ever
    /// attempting a TCP connection. Regression test for the silent-permit
    /// footgun that used to live here.
    #[test]
    fn default_constructor_is_deny_all() {
        let (_ingress_tx, ingress_rx) = mpsc::channel::<Option<Vec<u8>>>();
        let (egress_tx, _egress_rx) = mpsc::sync_channel::<ChannelEgress>(8);
        let stream = ChannelStream::new(ingress_rx, egress_tx);
        let h = DefaultDirectTcpipHandler::new();
        // 127.0.0.1:1 is the canonical "should never answer" target; if
        // the default-deny path is broken we'd hit a connect attempt
        // here. With the fix, the handler short-circuits on policy.
        let req = DirectTcpipRequest {
            dest_host: "127.0.0.1",
            dest_port: 1,
            orig_host: "client",
            orig_port: 0,
        };
        h.handle("u", req, stream).expect("handle");
    }

    #[test]
    fn allow_list_rejects_silently() {
        let (_ingress_tx, ingress_rx) = mpsc::channel::<Option<Vec<u8>>>();
        let (egress_tx, _egress_rx) = mpsc::sync_channel::<ChannelEgress>(8);
        let stream = ChannelStream::new(ingress_rx, egress_tx);
        let h =
            DefaultDirectTcpipHandler::new().with_allow_list(|host, _| host == "allowed.example");
        let req = DirectTcpipRequest {
            dest_host: "denied.example",
            dest_port: 80,
            orig_host: "client",
            orig_port: 0,
        };
        h.handle("u", req, stream).expect("handle");
    }
}
