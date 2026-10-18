//! Client half of the knock protocol (`docs/knock.md` §6): send KNOCKs,
//! verify the ACCEPT, open the rendezvous connection, and the "try TCP, fall
//! back to a knock" connect helper.

use std::io::{self, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream, ToSocketAddrs, UdpSocket};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use purecrypto::ec::x25519::X25519PrivateKey;
use purecrypto::rng::OsRng;
use purecrypto::zeroize::Zeroizing;

use super::server::unix_ms;
use super::wire::{self, Accept, KnockFields, MAX_DATAGRAM};
use crate::error::{Error, Result};
use crate::hostkey::HostKey;

/// One key the client may knock with.
pub struct KnockIdentity<'a> {
    /// Signs sig1 (once) and sig2 (every knock). Ed25519, ECDSA or RSA.
    pub signer: &'a dyn HostKey,
    /// Cached sig1 for (user, this key), if known. Filled in by [`knock`]
    /// when absent so the caller can persist it.
    pub sig1: Option<Vec<u8>>,
}

impl core::fmt::Debug for KnockIdentity<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("KnockIdentity")
            .field("algorithm", &self.signer.algorithm())
            .field("sig1_cached", &self.sig1.is_some())
            .finish()
    }
}

/// What to knock with.
#[derive(Debug)]
pub struct KnockRequest<'a> {
    /// Login name (1..=64 bytes).
    pub user: &'a str,
    /// Candidate keys; one KNOCK is sent per distinct key.
    pub identities: Vec<KnockIdentity<'a>>,
    /// Host key blobs on file for the target (from `known_hosts`). Empty ⇒
    /// the knock asks for the full host key (`NEED_HOSTKEY`).
    pub known_host_keys: Vec<Vec<u8>>,
}

/// Client timing knobs. Defaults follow `docs/knock.md` §7.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct KnockClientConfig {
    /// Offsets from the first send at which the identical datagrams are
    /// sent again.
    pub retransmit: Vec<Duration>,
    /// Offset from the first send after which the knock is abandoned.
    pub give_up: Duration,
}

impl Default for KnockClientConfig {
    fn default() -> Self {
        Self {
            retransmit: vec![Duration::from_millis(500), Duration::from_millis(1500)],
            give_up: Duration::from_millis(3000),
        }
    }
}

/// A verified ACCEPT: where to connect and what host key to expect.
pub struct KnockAccepted {
    /// TCP address of the rendezvous listener.
    pub target: SocketAddr,
    /// Host key that signed the ACCEPT. The SSH session on the rendezvous
    /// connection must present exactly this key.
    pub host_key_blob: Vec<u8>,
    /// `true` if the key came from [`KnockRequest::known_host_keys`];
    /// `false` if it is new to the client and still needs the usual
    /// trust-on-first-use decision (made during the SSH key exchange).
    pub host_key_known: bool,
    /// Index into [`KnockRequest::identities`] of the key that was accepted.
    pub identity: usize,
    /// When the listener closes (client-side estimate).
    pub expires: Instant,
    token: Zeroizing<[u8; 32]>,
}

impl core::fmt::Debug for KnockAccepted {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("KnockAccepted")
            .field("target", &self.target)
            .field("host_key_known", &self.host_key_known)
            .field("identity", &self.identity)
            .finish_non_exhaustive()
    }
}

impl KnockAccepted {
    /// Connect to the rendezvous listener and send the open token. The
    /// returned stream is ready for the SSH protocol (pass it to
    /// [`Client::connect_via`](crate::client::Client::connect_via) with
    /// [`Self::pin`] applied to the config).
    pub fn connect(&self, timeout: Option<Duration>) -> io::Result<TcpStream> {
        let mut s = match timeout {
            Some(t) => TcpStream::connect_timeout(&self.target, t)?,
            None => TcpStream::connect(self.target)?,
        };
        s.set_nodelay(true)?;
        s.write_all(&self.token[..])?;
        Ok(s)
    }

    /// Pin the SSH session to the host key that signed the ACCEPT: the key
    /// exchange fails unless the server presents exactly that key, and only
    /// that key's signature algorithms are offered.
    #[cfg(feature = "client")]
    pub fn pin(&self, cfg: &mut crate::client::Config) {
        cfg.pinned_host_key = Some(self.host_key_blob.clone());
    }
}

fn host_key_rank(blob: &[u8]) -> u8 {
    match crate::format::Reader::new(blob).read_string() {
        Ok(b"ssh-ed25519") => 0,
        Ok(n) if n.starts_with(b"ecdsa-") => 1,
        _ => 2,
    }
}

struct Sent {
    datagram: Vec<u8>,
    hash: [u8; 32],
    eph: X25519PrivateKey,
    identity: usize,
}

/// Knock on `addr` (UDP) and wait for an ACCEPT.
///
/// Returns `Ok(None)` when nothing valid came back before
/// [`KnockClientConfig::give_up`], when the port answered with ICMP
/// unreachable, or when `abort()` turned true (checked about every 50 ms).
/// Fills in missing [`KnockIdentity::sig1`] values.
pub fn knock(
    addr: SocketAddr,
    req: &mut KnockRequest<'_>,
    cfg: &KnockClientConfig,
    abort: &dyn Fn() -> bool,
) -> Result<Option<KnockAccepted>> {
    let mut known: Vec<&Vec<u8>> = req
        .known_host_keys
        .iter()
        .filter(|b| wire::max_sig_blob_len(b).is_some())
        .collect();
    known.sort_by_key(|b| host_key_rank(b));
    let expected = known.first().map(|b| (*b).clone());
    let (host_fp, min_len) = match &expected {
        Some(blob) => (
            Some(wire::key_fp(blob)),
            wire::accept_len_bound(blob, false).unwrap_or(0),
        ),
        None => (None, MAX_DATAGRAM),
    };

    let mut sent: Vec<Sent> = Vec::new();
    let mut seen_fps: Vec<[u8; 32]> = Vec::new();
    let nonce = unix_ms();
    for (i, id) in req.identities.iter_mut().enumerate() {
        let blob = id.signer.public_blob();
        if wire::max_sig_blob_len(&blob).is_none() {
            continue;
        }
        let fp = wire::key_fp(&blob);
        if seen_fps.contains(&fp) {
            continue;
        }
        seen_fps.push(fp);
        if id.sig1.is_none() {
            let msg = wire::knock_id_message(req.user, &fp);
            id.sig1 = Some(wire::sign(id.signer, wire::NS_KNOCK_ID, &msg)?);
        }
        let eph = X25519PrivateKey::generate(&mut OsRng);
        let fields = KnockFields {
            user: req.user,
            key_fp: fp,
            sig1: id.sig1.as_deref().unwrap_or_default(),
            nonce,
            eph_c: eph.public_key(),
            host_fp,
        };
        let datagram = match fields.build(id.signer, min_len) {
            Ok(d) => d,
            // An oversized key (RSA > 4096) cannot knock; try the others.
            Err(Error::Unsupported(_)) => continue,
            Err(e) => return Err(e),
        };
        let hash = wire::knock_hash(&datagram);
        sent.push(Sent {
            datagram,
            hash,
            eph,
            identity: i,
        });
    }
    if sent.is_empty() {
        return Ok(None);
    }

    let local: SocketAddr = match addr.ip() {
        IpAddr::V4(_) => (Ipv4Addr::UNSPECIFIED, 0).into(),
        IpAddr::V6(_) => (Ipv6Addr::UNSPECIFIED, 0).into(),
    };
    let udp = UdpSocket::bind(local)?;
    // `connect` filters out datagrams from anyone but the knocked address
    // and turns ICMP port-unreachable into a recv error.
    udp.connect(addr)?;
    let start = Instant::now();
    let send_all = |udp: &UdpSocket| {
        for s in &sent {
            let _ = udp.send(&s.datagram);
        }
    };
    send_all(&udp);
    let mut schedule = cfg.retransmit.iter().copied().peekable();
    let mut buf = [0u8; MAX_DATAGRAM + 1];
    loop {
        let elapsed = start.elapsed();
        if elapsed >= cfg.give_up || abort() {
            return Ok(None);
        }
        if let Some(at) = schedule.peek()
            && elapsed >= *at
        {
            schedule.next();
            send_all(&udp);
            continue;
        }
        let next = schedule
            .peek()
            .copied()
            .unwrap_or(cfg.give_up)
            .min(cfg.give_up);
        let wait = next
            .saturating_sub(elapsed)
            .clamp(Duration::from_millis(1), Duration::from_millis(50));
        udp.set_read_timeout(Some(wait))?;
        let n = match udp.recv(&mut buf) {
            Ok(n) => n,
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock
                        | io::ErrorKind::TimedOut
                        | io::ErrorKind::Interrupted
                ) =>
            {
                continue;
            }
            // ICMP port unreachable: nothing listens, stop early. Linux and
            // macOS report it as ECONNREFUSED, Windows as WSAECONNRESET.
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::ConnectionRefused | io::ErrorKind::ConnectionReset
                ) =>
            {
                return Ok(None);
            }
            Err(e) => return Err(e.into()),
        };
        if n > MAX_DATAGRAM {
            continue;
        }
        if let Some(acc) = check_accept(&buf[..n], &sent, expected.as_deref(), addr) {
            return Ok(Some(acc));
        }
    }
}

fn check_accept(
    datagram: &[u8],
    sent: &[Sent],
    expected: Option<&[u8]>,
    addr: SocketAddr,
) -> Option<KnockAccepted> {
    let a = Accept::parse(datagram).ok()?;
    let s = sent.iter().find(|s| s.hash == a.knock_hash)?;
    let (blob, known) = match (expected, a.hostkey) {
        (Some(exp), None) => (exp.to_vec(), true),
        // We sent host_fp: a full key in the reply must be that same key.
        (Some(exp), Some(full)) if full == exp => (exp.to_vec(), true),
        (Some(_), Some(_)) => return None,
        (None, Some(full)) => (full.to_vec(), false),
        (None, None) => return None,
    };
    wire::verify(&blob, wire::NS_ACCEPT, a.signed, a.sig_host).ok()?;
    let shared = Zeroizing::new(s.eph.diffie_hellman(&a.eph_s).ok()?);
    let token = wire::open_token(&shared, &a.knock_hash, &a.eph_s, a.port);
    Some(KnockAccepted {
        target: SocketAddr::new(addr.ip(), a.port),
        host_key_blob: blob,
        host_key_known: known,
        identity: s.identity,
        expires: Instant::now() + Duration::from_secs(a.window as u64),
        token,
    })
}

/// When the connect helper knocks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum KnockMode {
    /// Plain TCP only.
    Never,
    /// Plain TCP first; knock if it is refused or slow (default).
    #[default]
    Auto,
    /// Knock straight away; never try plain TCP.
    Always,
}

/// Options for [`connect_or_knock`].
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct KnockConnectOptions {
    /// When to knock.
    pub mode: KnockMode,
    /// In [`KnockMode::Auto`], how long a TCP connect may stay pending
    /// before the knock starts alongside it.
    pub fallback_delay: Duration,
    /// Timeout of each TCP connect (plain and rendezvous). `None` ⇒ the
    /// operating system default.
    pub connect_timeout: Option<Duration>,
    /// UDP port to knock on. `None` ⇒ the TCP port.
    pub knock_port: Option<u16>,
    /// Knock timing.
    pub client: KnockClientConfig,
}

impl Default for KnockConnectOptions {
    fn default() -> Self {
        Self {
            mode: KnockMode::Auto,
            fallback_delay: Duration::from_millis(1500),
            connect_timeout: None,
            knock_port: None,
            client: KnockClientConfig::default(),
        }
    }
}

/// Result of [`connect_or_knock`].
#[derive(Debug)]
#[non_exhaustive]
pub enum Connected {
    /// The plain TCP connect succeeded.
    Direct(TcpStream),
    /// A knock was accepted; `stream` is the rendezvous connection with the
    /// token already sent. Apply [`KnockAccepted::pin`] to the client config.
    Knocked {
        /// Rendezvous connection.
        stream: TcpStream,
        /// The verified ACCEPT.
        accepted: KnockAccepted,
    },
}

impl Connected {
    /// The TCP stream, whichever way it was obtained.
    pub fn stream(&self) -> &TcpStream {
        match self {
            Connected::Direct(s) | Connected::Knocked { stream: s, .. } => s,
        }
    }
}

fn tcp_connect(addr: SocketAddr, timeout: Option<Duration>) -> io::Result<TcpStream> {
    match timeout {
        Some(t) => TcpStream::connect_timeout(&addr, t),
        None => TcpStream::connect(addr),
    }
}

/// Connect to `host:port`, knocking when plain TCP does not work
/// (`docs/knock.md` §6.1).
///
/// Addresses are tried in resolution order. In [`KnockMode::Auto`] a TCP
/// connect is started for each; if it is refused or still pending after
/// [`KnockConnectOptions::fallback_delay`], a knock is sent to the same IP
/// while the connect keeps running. Whichever produces a connection first
/// wins. The error of the last plain connect is returned when everything
/// fails.
pub fn connect_or_knock(
    host: &str,
    port: u16,
    req: &mut KnockRequest<'_>,
    opts: &KnockConnectOptions,
) -> Result<Connected> {
    let addrs: Vec<SocketAddr> = (host, port).to_socket_addrs()?.collect();
    let timeout = opts.connect_timeout;
    connect_or_knock_addrs(
        &addrs,
        req,
        opts,
        Arc::new(move |a| tcp_connect(a, timeout)),
    )
}

/// A plain TCP dialer for [`connect_or_knock_addrs`]. Runs on a helper
/// thread in [`KnockMode::Auto`].
pub type TcpDialer = Arc<dyn Fn(SocketAddr) -> io::Result<TcpStream> + Send + Sync>;

/// [`connect_or_knock`] over already-resolved addresses, with the plain TCP
/// connects made by `dial` (e.g. to bind a source address or set socket
/// options). Rendezvous connections still use a plain connect with
/// [`KnockConnectOptions::connect_timeout`].
pub fn connect_or_knock_addrs(
    addrs: &[SocketAddr],
    req: &mut KnockRequest<'_>,
    opts: &KnockConnectOptions,
    dial: TcpDialer,
) -> Result<Connected> {
    let mut last_err: Option<Error> = None;
    for &addr in addrs {
        let knock_addr = SocketAddr::new(addr.ip(), opts.knock_port.unwrap_or(addr.port()));
        let res = match opts.mode {
            KnockMode::Never => dial(addr).map(Connected::Direct).map_err(Error::from),
            KnockMode::Always => match knock(knock_addr, req, &opts.client, &|| false) {
                Ok(Some(acc)) => knocked(acc, opts),
                Ok(None) => Err(Error::Io(io::Error::new(
                    io::ErrorKind::ConnectionRefused,
                    "knock: no answer",
                ))),
                Err(e) => Err(e),
            },
            KnockMode::Auto => auto_one(addr, knock_addr, req, opts, dial.clone()),
        };
        match res {
            Ok(c) => return Ok(c),
            Err(e) => last_err = Some(e),
        }
    }
    Err(last_err.unwrap_or_else(|| {
        Error::Io(io::Error::new(
            io::ErrorKind::NotFound,
            "no addresses to connect to",
        ))
    }))
}

fn knocked(acc: KnockAccepted, opts: &KnockConnectOptions) -> Result<Connected> {
    let stream = acc.connect(opts.connect_timeout)?;
    Ok(Connected::Knocked {
        stream,
        accepted: acc,
    })
}

type Slot = Arc<Mutex<Option<io::Result<TcpStream>>>>;

fn auto_one(
    addr: SocketAddr,
    knock_addr: SocketAddr,
    req: &mut KnockRequest<'_>,
    opts: &KnockConnectOptions,
    dial: TcpDialer,
) -> Result<Connected> {
    let slot: Slot = Arc::new(Mutex::new(None));
    let (tx, rx) = std::sync::mpsc::channel::<()>();
    let thread_slot = slot.clone();
    let handle = std::thread::spawn(move || {
        let r = dial(addr);
        if let Ok(mut g) = thread_slot.lock() {
            *g = Some(r);
        }
        let _ = tx.send(());
    });
    let take = |slot: &Slot| slot.lock().ok().and_then(|mut g| g.take());

    // Phase 1: give plain TCP `fallback_delay` on its own.
    let _ = rx.recv_timeout(opts.fallback_delay);
    match take(&slot) {
        Some(Ok(s)) => {
            let _ = handle.join();
            return Ok(Connected::Direct(s));
        }
        Some(Err(e)) => {
            let _ = handle.join();
            // Refused / unreachable: the knock is the only option left.
            return match knock(knock_addr, req, &opts.client, &|| false)? {
                Some(acc) => knocked(acc, opts),
                None => Err(e.into()),
            };
        }
        None => {}
    }

    // Phase 2: TCP still pending — knock alongside it, abandoning the knock
    // as soon as TCP connects.
    let tcp_ok = || {
        slot.lock()
            .map(|g| matches!(*g, Some(Ok(_))))
            .unwrap_or(false)
    };
    let knocked_acc = knock(knock_addr, req, &opts.client, &tcp_ok);
    if let Ok(Some(acc)) = knocked_acc {
        // The TCP attempt is abandoned; its thread finishes on its own.
        drop(handle);
        return knocked(acc, opts);
    }
    // No knock answer: fall back to whatever TCP eventually does.
    let _ = handle.join();
    match take(&slot) {
        Some(Ok(s)) => Ok(Connected::Direct(s)),
        Some(Err(e)) => Err(e.into()),
        None => match knocked_acc {
            Err(e) => Err(e),
            _ => Err(Error::Io(io::Error::other("connect thread vanished"))),
        },
    }
}
