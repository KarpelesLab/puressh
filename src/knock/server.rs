//! Socket half of the knock server (`docs/knock.md` §5.4): the UDP knock
//! socket and the short-lived TCP rendezvous listeners, all non-blocking so
//! they can share a caller's `poll()` loop (see [`KnockServer::process`]) or
//! run on their own ([`KnockServer::run`]).

use std::io::{self, Read};
use std::net::{
    IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener, TcpStream, ToSocketAddrs, UdpSocket,
};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use purecrypto::ct::ConstantTimeEq;
use purecrypto::rng::{OsRng, RngCore};
use zeroize::Zeroizing;

use super::state::{DropReason, KnockState, Verdict};
use super::wire::MAX_DATAGRAM;

/// Rendezvous connections still sending their token, per listener.
const MAX_CONNS_PER_RENDEZVOUS: usize = 4;
/// Wrong tokens tolerated before a listener is closed.
const MAX_STRIKES: u8 = 3;
/// Datagrams read per [`KnockServer::process`] call.
const MAX_DATAGRAMS_PER_PROCESS: usize = 1024;
/// Random ports tried in a configured range before giving up.
const PORT_ATTEMPTS: u32 = 64;

/// Milliseconds since the Unix epoch, the clock knock nonces use.
pub fn unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// A rendezvous connection that presented the right token. The SSH session
/// run on `stream` must present the host key `host_key_blob`, which the
/// server side does naturally as long as it serves that key.
#[derive(Debug)]
#[non_exhaustive]
pub struct KnockedConnection {
    /// The TCP connection, in blocking mode, positioned right after the
    /// token: the SSH server's identification string comes next.
    pub stream: TcpStream,
    /// Remote address of the connection.
    pub peer: SocketAddr,
    /// Login name the knock was made for.
    pub user: String,
    /// Fingerprint of the client key that knocked.
    pub key_fp: [u8; 32],
    /// Host key that signed the ACCEPT.
    pub host_key_blob: Vec<u8>,
}

/// Events worth logging, delivered to the callback set with
/// [`KnockServer::set_logger`].
#[derive(Debug)]
#[non_exhaustive]
pub enum KnockEvent<'a> {
    /// A datagram was dropped.
    Dropped {
        /// Source of the datagram.
        src: SocketAddr,
        /// Why.
        reason: DropReason,
    },
    /// A knock was accepted and a listener opened.
    Accepted {
        /// Source of the knock.
        src: SocketAddr,
        /// Login name.
        user: &'a str,
        /// Rendezvous port.
        port: u16,
    },
    /// A retransmitted knock got its cached ACCEPT again.
    Resent {
        /// Source of the knock.
        src: SocketAddr,
    },
    /// A rendezvous connection came from the wrong address or sent the
    /// wrong token.
    Refused {
        /// Remote address.
        peer: SocketAddr,
    },
    /// A rendezvous listener expired unused.
    Expired {
        /// Login name.
        user: &'a str,
    },
    /// Binding a listener or signing an ACCEPT failed.
    Error(&'a io::Error),
}

struct PendingConn {
    stream: TcpStream,
    peer: SocketAddr,
    buf: [u8; 32],
    got: usize,
}

struct Rendezvous {
    listener: TcpListener,
    allowed: IpAddr,
    token: Zeroizing<[u8; 32]>,
    deadline: Instant,
    token_timeout: Duration,
    strikes: u8,
    user: String,
    key_fp: [u8; 32],
    host_key_blob: Vec<u8>,
    conns: Vec<(PendingConn, Instant)>,
}

type KnockLogger = dyn FnMut(KnockEvent<'_>) + Send;

/// UDP knock socket plus the rendezvous listeners it opened.
pub struct KnockServer {
    udp: UdpSocket,
    state: KnockState,
    ports: Option<(u16, u16)>,
    rendezvous: Vec<Rendezvous>,
    logger: Option<Box<KnockLogger>>,
}

impl core::fmt::Debug for KnockServer {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("KnockServer")
            .field("udp", &self.udp.local_addr().ok())
            .field("rendezvous", &self.rendezvous.len())
            .finish_non_exhaustive()
    }
}

fn canonical(ip: IpAddr) -> IpAddr {
    ip.to_canonical()
}

impl KnockServer {
    /// Bind the UDP knock socket on `addr` (typically `0.0.0.0:22` or
    /// `[::]:22`). The socket is non-blocking.
    pub fn bind(addr: impl ToSocketAddrs, state: KnockState) -> io::Result<Self> {
        let udp = UdpSocket::bind(addr)?;
        udp.set_nonblocking(true)?;
        Ok(Self {
            udp,
            state,
            ports: None,
            rendezvous: Vec::new(),
            logger: None,
        })
    }

    /// Open rendezvous listeners on a random port in `lo..=hi` instead of a
    /// kernel-chosen ephemeral port.
    pub fn set_port_range(&mut self, lo: u16, hi: u16) {
        self.ports = if lo == 0 || hi < lo {
            None
        } else {
            Some((lo, hi))
        };
    }

    /// Receive [`KnockEvent`]s, e.g. for debug logging.
    pub fn set_logger(&mut self, f: impl FnMut(KnockEvent<'_>) + Send + 'static) {
        self.logger = Some(Box::new(f));
    }

    /// Address the UDP knock socket is bound to.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.udp.local_addr()
    }

    /// The protocol state (e.g. to swap the key table).
    pub fn state_mut(&mut self) -> &mut KnockState {
        &mut self.state
    }

    /// Number of rendezvous listeners currently open.
    pub fn open_rendezvous(&self) -> usize {
        self.rendezvous.len()
    }

    fn log(&mut self, ev: KnockEvent<'_>) {
        if let Some(l) = self.logger.as_mut() {
            l(ev);
        }
    }

    fn bind_listener(&self) -> io::Result<TcpListener> {
        let ip = match self.udp.local_addr()?.ip() {
            IpAddr::V4(v4) if v4.is_unspecified() => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            IpAddr::V6(v6) if v6.is_unspecified() => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
            ip => ip,
        };
        let Some((lo, hi)) = self.ports else {
            return TcpListener::bind((ip, 0));
        };
        let span = (hi - lo) as u32 + 1;
        let mut last = io::Error::new(io::ErrorKind::AddrInUse, "knock: port range exhausted");
        let start = OsRng.next_u32() % span;
        for i in 0..span.min(PORT_ATTEMPTS) {
            let port = lo + ((start + i) % span) as u16;
            match TcpListener::bind((ip, port)) {
                Ok(l) => return Ok(l),
                Err(e) => last = e,
            }
        }
        Err(last)
    }

    /// Do all pending non-blocking work: read knocks, open listeners, accept
    /// rendezvous connections, check tokens, expire listeners. Returns the
    /// connections that presented a valid token; hand each to the SSH
    /// server. Call when any of [`Self::poll_fds`] is readable or
    /// [`Self::next_wakeup`] passes.
    pub fn process(&mut self) -> Vec<KnockedConnection> {
        self.drain_udp();
        let mut out = Vec::new();
        let now = Instant::now();
        let mut i = 0;
        while i < self.rendezvous.len() {
            match self.service(i, now) {
                Some(conn) => {
                    let r = self.rendezvous.swap_remove(i);
                    self.state.release_pending(&r.user, &r.key_fp);
                    out.push(conn);
                }
                None => {
                    let r = &self.rendezvous[i];
                    if now >= r.deadline || r.strikes >= MAX_STRIKES {
                        let r = self.rendezvous.swap_remove(i);
                        self.state.release_pending(&r.user, &r.key_fp);
                        self.log(KnockEvent::Expired { user: &r.user });
                    } else {
                        i += 1;
                    }
                }
            }
        }
        out
    }

    fn drain_udp(&mut self) {
        let mut buf = [0u8; MAX_DATAGRAM + 1];
        // Bounded so a flood (or an error that keeps recurring) cannot
        // starve the rendezvous listeners; the rest waits for the next call.
        for _ in 0..MAX_DATAGRAMS_PER_PROCESS {
            let (n, src) = match self.udp.recv_from(&mut buf) {
                Ok(v) => v,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => return,
                // ICMP errors from earlier sends (ECONNREFUSED on Linux,
                // WSAECONNRESET on Windows) surface here; they say nothing
                // about the next datagram.
                Err(_) => continue,
            };
            if n > MAX_DATAGRAM {
                self.log(KnockEvent::Dropped {
                    src,
                    reason: DropReason::Malformed,
                });
                continue;
            }
            self.handle_datagram(&buf[..n], src);
        }
    }

    fn handle_datagram(&mut self, datagram: &[u8], src: SocketAddr) {
        let now_ms = unix_ms();
        match self.state.handle(now_ms, canonical(src.ip()), datagram) {
            Verdict::Drop(reason) => self.log(KnockEvent::Dropped { src, reason }),
            Verdict::Resend(accept) => {
                let _ = self.udp.send_to(&accept, src);
                self.log(KnockEvent::Resent { src });
            }
            Verdict::Accept(pending) => {
                let listener = match self.bind_listener().and_then(|l| {
                    l.set_nonblocking(true)?;
                    let port = l.local_addr()?.port();
                    Ok((l, port))
                }) {
                    Ok(v) => v,
                    Err(e) => {
                        self.state.release_pending(&pending.user, &pending.key_fp);
                        self.log(KnockEvent::Error(&e));
                        return;
                    }
                };
                let (listener, port) = listener;
                let done = match self.state.complete(&pending, port, now_ms) {
                    Ok(d) => d,
                    Err(e) => {
                        let e = io::Error::other(e.to_string());
                        self.log(KnockEvent::Error(&e));
                        return;
                    }
                };
                let cfg = self.state.config();
                let now = Instant::now();
                self.rendezvous.push(Rendezvous {
                    listener,
                    allowed: canonical(src.ip()),
                    token: done.token,
                    deadline: now + Duration::from_secs(cfg.window_secs.max(1) as u64),
                    token_timeout: Duration::from_secs(cfg.token_timeout_secs.max(1) as u64),
                    strikes: 0,
                    user: pending.user.clone(),
                    key_fp: pending.key_fp,
                    host_key_blob: done.host_key_blob,
                    conns: Vec::new(),
                });
                let _ = self.udp.send_to(&done.datagram, src);
                self.log(KnockEvent::Accepted {
                    src,
                    user: &pending.user,
                    port,
                });
            }
        }
    }

    /// Accept on rendezvous `i` and advance its token reads. Returns the
    /// winning connection, if any.
    fn service(&mut self, i: usize, now: Instant) -> Option<KnockedConnection> {
        let mut refused = Vec::new();
        let r = &mut self.rendezvous[i];
        loop {
            match r.listener.accept() {
                Ok((stream, peer)) => {
                    if canonical(peer.ip()) != r.allowed
                        || r.conns.len() >= MAX_CONNS_PER_RENDEZVOUS
                        || stream.set_nonblocking(true).is_err()
                    {
                        refused.push(peer);
                        continue;
                    }
                    let _ = stream.set_nodelay(true);
                    r.conns.push((
                        PendingConn {
                            stream,
                            peer,
                            buf: [0u8; 32],
                            got: 0,
                        },
                        now + r.token_timeout,
                    ));
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(_) => break,
            }
        }
        let mut winner = None;
        let mut j = 0;
        while j < r.conns.len() {
            let (c, deadline) = &mut r.conns[j];
            let mut failed = now >= *deadline;
            while !failed && c.got < 32 {
                match c.stream.read(&mut c.buf[c.got..]) {
                    Ok(0) => failed = true,
                    Ok(n) => c.got += n,
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                    Err(_) => failed = true,
                }
            }
            if !failed && c.got == 32 {
                if bool::from(c.buf.ct_eq(&*r.token)) {
                    let (c, _) = r.conns.swap_remove(j);
                    winner = Some(c);
                    break;
                }
                failed = true;
            }
            if failed {
                let (c, _) = r.conns.swap_remove(j);
                r.strikes = r.strikes.saturating_add(1);
                refused.push(c.peer);
            } else {
                j += 1;
            }
        }
        let user = r.user.clone();
        let key_fp = r.key_fp;
        let host_key_blob = r.host_key_blob.clone();
        for peer in refused {
            self.log(KnockEvent::Refused { peer });
        }
        let c = winner?;
        if c.stream.set_nonblocking(false).is_err() {
            return None;
        }
        Some(KnockedConnection {
            stream: c.stream,
            peer: c.peer,
            user,
            key_fp,
            host_key_blob,
        })
    }

    /// Earliest instant at which [`Self::process`] has timed work to do
    /// (a listener or token deadline), if any.
    pub fn next_wakeup(&self) -> Option<Instant> {
        self.rendezvous
            .iter()
            .flat_map(|r| core::iter::once(r.deadline).chain(r.conns.iter().map(|(_, d)| *d)))
            .min()
    }

    /// Every descriptor [`Self::process`] wants readability on: the UDP
    /// socket, each listener and each connection still sending its token.
    #[cfg(unix)]
    pub fn poll_fds(&self) -> Vec<std::os::fd::BorrowedFd<'_>> {
        use std::os::fd::AsFd;
        let mut v = vec![self.udp.as_fd()];
        for r in &self.rendezvous {
            v.push(r.listener.as_fd());
            v.extend(r.conns.iter().map(|(c, _)| c.stream.as_fd()));
        }
        v
    }

    /// Serve forever on the current thread, calling `on_conn` for each
    /// rendezvous connection that presented a valid token. Waits are bounded
    /// to 20 ms so listeners and token reads stay responsive without an
    /// external poller.
    pub fn run(&mut self, mut on_conn: impl FnMut(KnockedConnection)) -> io::Result<()> {
        let mut peek = [0u8; 1];
        loop {
            for c in self.process() {
                on_conn(c);
            }
            self.udp.set_nonblocking(false)?;
            self.udp.set_read_timeout(Some(Duration::from_millis(20)))?;
            let r = self.udp.peek_from(&mut peek);
            self.udp.set_nonblocking(true)?;
            match r {
                Ok(_) => {}
                Err(e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::WouldBlock
                            | io::ErrorKind::TimedOut
                            | io::ErrorKind::Interrupted
                    ) => {}
                // Pending ICMP errors and truncation are not fatal.
                Err(_) => {}
            }
        }
    }
}
