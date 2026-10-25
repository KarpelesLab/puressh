//! A minimal stub resolver for `VerifyHostKeyDNS`: one query of one type
//! to the `/etc/resolv.conf` name servers, over UDP (TCP when truncated),
//! as OpenSSH's `getrrsetbyname` does through the system's `res_query`.
//! Included by `ssh` via `#[path]`.
//!
//! The answer is DNSSEC-validated when the server sets the AD bit and the
//! resolver configuration trusts it (`options trust-ad`, as glibc requires
//! before it passes the bit on); like OpenSSH, nothing is validated here.

use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream, UdpSocket};
use std::time::Duration;

/// `SSHFP` (RFC 4255).
pub const TYPE_SSHFP: u16 = 44;
/// `CNAME`.
pub const TYPE_CNAME: u16 = 5;
const CLASS_IN: u16 = 1;

/// Why a lookup produced nothing, worded as OpenSSH's `dns_result_totext`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsError {
    /// The query could not be made or answered (`unknown error`).
    Fail,
    /// The name does not exist (`non-existent host`).
    NoName,
    /// The name has no records of the type (`no data`).
    NoData,
}

impl DnsError {
    /// OpenSSH's text for the error.
    pub fn text(self) -> &'static str {
        match self {
            DnsError::Fail => "unknown error",
            DnsError::NoName => "non-existent host",
            DnsError::NoData => "no data",
        }
    }
}

/// A lookup's answers: the record data of the type asked for, and whether
/// the server vouched for them (a trusted AD bit).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RrSet {
    /// Each record's RDATA, in answer order (for a CNAME, the name it
    /// points to, decompressed, as dotted text).
    pub rdatas: Vec<Vec<u8>>,
    /// `RRSET_VALIDATED`.
    pub validated: bool,
}

/// What `/etc/resolv.conf` says that matters here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvConf {
    /// `nameserver` lines (at most three are used, as the system resolver).
    pub servers: Vec<IpAddr>,
    /// `options timeout:N` (seconds, default 5).
    pub timeout: u64,
    /// `options attempts:N` (default 2).
    pub attempts: u32,
    /// `options edns0`: ask with EDNS0 (and, as OpenSSH does then, DO).
    pub edns0: bool,
    /// `options trust-ad`: believe the server's AD bit.
    pub trust_ad: bool,
}

impl ResolvConf {
    /// Parse `resolv.conf` text; no `nameserver` means the local one.
    pub fn parse(text: &str) -> Self {
        let mut rc = ResolvConf {
            servers: Vec::new(),
            timeout: 5,
            attempts: 2,
            edns0: false,
            trust_ad: false,
        };
        for line in text.lines() {
            let mut words = line.split_whitespace();
            match words.next() {
                Some("nameserver") => {
                    if let Some(ip) = words.next().and_then(|w| {
                        // A scoped IPv6 address (`fe80::1%eth0`) loses its zone.
                        w.split('%').next().and_then(|a| a.parse::<IpAddr>().ok())
                    }) && rc.servers.len() < 3
                    {
                        rc.servers.push(ip);
                    }
                }
                Some("options") => {
                    for opt in words {
                        if let Some(n) = opt.strip_prefix("timeout:") {
                            rc.timeout = n.parse().unwrap_or(rc.timeout).clamp(1, 30);
                        } else if let Some(n) = opt.strip_prefix("attempts:") {
                            rc.attempts = n.parse().unwrap_or(rc.attempts).clamp(1, 5);
                        } else if opt == "edns0" {
                            rc.edns0 = true;
                        } else if opt == "trust-ad" {
                            rc.trust_ad = true;
                        }
                    }
                }
                _ => {}
            }
        }
        if rc.servers.is_empty() {
            rc.servers.push(IpAddr::from([127, 0, 0, 1]));
        }
        rc
    }

    /// The system's configuration (`/etc/resolv.conf`).
    pub fn system() -> Self {
        Self::parse(&std::fs::read_to_string("/etc/resolv.conf").unwrap_or_default())
    }
}

/// Look `name` up for records of `rtype` (class IN), as `getrrsetbyname`.
pub fn lookup(name: &str, rtype: u16) -> Result<RrSet, DnsError> {
    lookup_with(&ResolvConf::system(), name, rtype)
}

/// [`lookup`] with the given resolver configuration.
pub fn lookup_with(rc: &ResolvConf, name: &str, rtype: u16) -> Result<RrSet, DnsError> {
    let id = query_id();
    let query = build_query(id, name, rtype, rc.edns0).ok_or(DnsError::Fail)?;
    let timeout = Duration::from_secs(rc.timeout);
    let mut last = DnsError::Fail;
    for _ in 0..rc.attempts {
        for server in &rc.servers {
            let addr = SocketAddr::new(*server, 53);
            let Some(mut reply) = udp_exchange(addr, &query, timeout) else {
                continue;
            };
            if reply.len() >= 4 && reply[2] & 0x02 != 0 {
                // Truncated: ask again over TCP.
                match tcp_exchange(addr, &query, timeout) {
                    Some(r) => reply = r,
                    None => continue,
                }
            }
            match parse_reply(&reply, id, rtype) {
                Ok(mut set) => {
                    set.validated &= rc.trust_ad;
                    return Ok(set);
                }
                // A server failure: try the next one.
                Err(DnsError::Fail) => last = DnsError::Fail,
                Err(e) => return Err(e),
            }
        }
    }
    Err(last)
}

/// A random query ID.
fn query_id() -> u16 {
    use purecrypto::rng::{OsRng, RngCore};
    let mut b = [0u8; 2];
    OsRng.fill_bytes(&mut b);
    u16::from_be_bytes(b)
}

/// The query packet: RD and AD set (as glibc asks with `trust-ad`), plus
/// an EDNS0 OPT record with DO when `edns0`.
fn build_query(id: u16, name: &str, rtype: u16, edns0: bool) -> Option<Vec<u8>> {
    let mut q = Vec::with_capacity(64);
    q.extend_from_slice(&id.to_be_bytes());
    q.extend_from_slice(&[0x01, 0x20]); // RD, AD
    q.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    q.extend_from_slice(&[0, 0, 0, 0]); // ANCOUNT, NSCOUNT
    q.extend_from_slice(&u16::from(edns0).to_be_bytes()); // ARCOUNT
    let name = name.strip_suffix('.').unwrap_or(name);
    if name.is_empty() || name.len() > 253 {
        return None;
    }
    for label in name.split('.') {
        if label.is_empty() || label.len() > 63 {
            return None;
        }
        q.push(label.len() as u8);
        q.extend_from_slice(label.as_bytes());
    }
    q.push(0);
    q.extend_from_slice(&rtype.to_be_bytes());
    q.extend_from_slice(&CLASS_IN.to_be_bytes());
    if edns0 {
        // Root name, OPT, 1232-byte UDP payload, DO.
        q.extend_from_slice(&[0, 0, 41, 0x04, 0xd0, 0, 0, 0x80, 0, 0, 0]);
    }
    Some(q)
}

fn udp_exchange(addr: SocketAddr, query: &[u8], timeout: Duration) -> Option<Vec<u8>> {
    let local: SocketAddr = if addr.is_ipv4() {
        SocketAddr::from(([0, 0, 0, 0], 0))
    } else {
        SocketAddr::from(([0u16; 8], 0))
    };
    let sock = UdpSocket::bind(local).ok()?;
    sock.connect(addr).ok()?;
    sock.set_read_timeout(Some(timeout)).ok()?;
    sock.send(query).ok()?;
    let mut buf = vec![0u8; 4096];
    // Anything that is not a reply to this query (a stale one, an ICMP
    // error reported as ConnectionReset on Windows) ends this server's turn
    // unless it is just another datagram.
    for _ in 0..4 {
        let n = sock.recv(&mut buf).ok()?;
        if n >= 2 && buf[..2] == query[..2] {
            buf.truncate(n);
            return Some(buf);
        }
    }
    None
}

fn tcp_exchange(addr: SocketAddr, query: &[u8], timeout: Duration) -> Option<Vec<u8>> {
    let mut s = TcpStream::connect_timeout(&addr, timeout).ok()?;
    s.set_read_timeout(Some(timeout)).ok()?;
    s.set_write_timeout(Some(timeout)).ok()?;
    let mut msg = (query.len() as u16).to_be_bytes().to_vec();
    msg.extend_from_slice(query);
    s.write_all(&msg).ok()?;
    let mut len = [0u8; 2];
    s.read_exact(&mut len).ok()?;
    let mut buf = vec![0u8; usize::from(u16::from_be_bytes(len))];
    s.read_exact(&mut buf).ok()?;
    Some(buf)
}

/// The (possibly compressed) name at `pos`, as dotted text.
fn read_name(msg: &[u8], mut pos: usize) -> Option<String> {
    let mut out = String::new();
    // Each pointer must go backwards, so this ends.
    let mut limit = pos;
    loop {
        let len = *msg.get(pos)?;
        match len & 0xc0 {
            0xc0 => {
                let target = usize::from(be16(msg, pos)? & 0x3fff);
                if target >= limit {
                    return None;
                }
                limit = target;
                pos = target;
            }
            0x00 if len == 0 => return Some(out),
            0x00 => {
                let label = msg.get(pos + 1..pos + 1 + usize::from(len))?;
                if !out.is_empty() {
                    out.push('.');
                }
                out.push_str(core::str::from_utf8(label).ok()?);
                pos += 1 + usize::from(len);
            }
            _ => return None,
        }
    }
}

/// Where `name` is an alias to, following CNAMEs (as the system resolver's
/// canonical name), `None` when it is not one or the lookup fails.
pub fn canonical_name(name: &str) -> Option<String> {
    let rc = ResolvConf::system();
    let mut current = name.trim_end_matches('.').to_string();
    let mut followed = false;
    // A chain longer than this is a loop.
    for _ in 0..8 {
        match lookup_with(&rc, &current, TYPE_CNAME) {
            Ok(set) => {
                let target = String::from_utf8(set.rdatas.first()?.clone()).ok()?;
                current = target;
                followed = true;
            }
            Err(_) => break,
        }
    }
    followed.then_some(current)
}

/// Skip a (possibly compressed) name at `pos`, returning the offset after it.
fn skip_name(msg: &[u8], mut pos: usize) -> Option<usize> {
    loop {
        let len = *msg.get(pos)?;
        match len & 0xc0 {
            0xc0 => return Some(pos + 2),
            0x00 if len == 0 => return Some(pos + 1),
            0x00 => pos += 1 + usize::from(len),
            _ => return None,
        }
    }
}

fn be16(msg: &[u8], pos: usize) -> Option<u16> {
    Some(u16::from_be_bytes([*msg.get(pos)?, *msg.get(pos + 1)?]))
}

/// The records of `rtype` in reply `msg` to query `id`.
fn parse_reply(msg: &[u8], id: u16, rtype: u16) -> Result<RrSet, DnsError> {
    if msg.len() < 12 || be16(msg, 0) != Some(id) || msg[2] & 0x80 == 0 {
        return Err(DnsError::Fail);
    }
    match msg[3] & 0x0f {
        0 => {}
        3 => return Err(DnsError::NoName),
        _ => return Err(DnsError::Fail),
    }
    let validated = msg[3] & 0x20 != 0;
    let qdcount = be16(msg, 4).ok_or(DnsError::Fail)?;
    let ancount = be16(msg, 6).ok_or(DnsError::Fail)?;
    if qdcount != 1 {
        return Err(DnsError::Fail);
    }
    let mut pos = skip_name(msg, 12).ok_or(DnsError::Fail)? + 4;
    let mut rdatas = Vec::new();
    for _ in 0..ancount {
        pos = skip_name(msg, pos).ok_or(DnsError::Fail)?;
        let ty = be16(msg, pos).ok_or(DnsError::Fail)?;
        let class = be16(msg, pos + 2).ok_or(DnsError::Fail)?;
        let rdlen = usize::from(be16(msg, pos + 8).ok_or(DnsError::Fail)?);
        let start = pos + 10;
        let rdata = msg.get(start..start + rdlen).ok_or(DnsError::Fail)?;
        if ty == rtype && class == CLASS_IN {
            if rtype == TYPE_CNAME {
                rdatas.push(read_name(msg, start).ok_or(DnsError::Fail)?.into_bytes());
            } else {
                rdatas.push(rdata.to_vec());
            }
        }
        pos = start + rdlen;
    }
    if rdatas.is_empty() {
        return Err(DnsError::NoData);
    }
    Ok(RrSet { rdatas, validated })
}

/// SSHFP's algorithm number for a key type (RFC 4255, 6594, 7479), `None`
/// for a key type it has none for.
pub fn sshfp_algorithm(key_type: &str) -> Option<u8> {
    match key_type {
        "ssh-rsa" => Some(1),
        "ssh-dss" => Some(2),
        t if t.starts_with("ecdsa-sha2-") => Some(3),
        "ssh-ed25519" => Some(4),
        _ => None,
    }
}

/// What the SSHFP records say about a host key, as OpenSSH's
/// `verify_host_key_dns` flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SshfpVerdict {
    /// Records were found (`DNS_VERIFY_FOUND`).
    pub found: bool,
    /// A record of the key's type matched it, none failed
    /// (`DNS_VERIFY_MATCH`).
    pub matched: bool,
    /// The records were DNSSEC-validated (`DNS_VERIFY_SECURE`).
    pub secure: bool,
}

/// Check the key (`key_type`, wire `blob`) against `set`'s SSHFP records.
/// `None`: the key has no SSHFP algorithm (OpenSSH: "Error calculating key
/// fingerprint.").
pub fn check_sshfp(set: &RrSet, key_type: &str, blob: &[u8]) -> Option<SshfpVerdict> {
    use purecrypto::hash::{Digest, Sha1, Sha256};
    let mut v = SshfpVerdict {
        found: !set.rdatas.is_empty(),
        matched: false,
        secure: set.validated,
    };
    let mut failed = false;
    for rd in &set.rdatas {
        // A record too short to hold its two type octets is skipped.
        let [alg, fptype, digest @ ..] = rd.as_slice() else {
            continue;
        };
        let ours = sshfp_algorithm(key_type)?;
        let want: Vec<u8> = match fptype {
            1 => Sha1::digest(blob).as_ref().to_vec(),
            2 => Sha256::digest(blob).as_ref().to_vec(),
            // A digest type OpenSSH does not know: not a key to compare.
            _ => return None,
        };
        if *alg == ours && want.len() == digest.len() {
            if want == digest {
                v.matched = true;
            } else {
                failed = true;
            }
        }
    }
    if failed {
        v.matched = false;
    }
    Some(v)
}

#[cfg(test)]
mod dns_tests {
    use super::*;

    #[test]
    fn resolv_conf() {
        let rc = ResolvConf::parse(
            "# c\nsearch x\nnameserver 192.0.2.1\nnameserver fe80::1%eth0\n\
             options edns0 trust-ad timeout:2 attempts:3\n",
        );
        assert_eq!(
            rc.servers,
            vec![
                "192.0.2.1".parse::<IpAddr>().unwrap(),
                "fe80::1".parse().unwrap()
            ]
        );
        assert!(rc.edns0 && rc.trust_ad);
        assert_eq!((rc.timeout, rc.attempts), (2, 3));
        let rc = ResolvConf::parse("");
        assert_eq!(rc.servers, vec![IpAddr::from([127, 0, 0, 1])]);
        assert!(!rc.trust_ad);
    }

    /// A reply, built by hand: the query echoed, then the answers.
    fn reply(id: u16, flags: [u8; 2], answers: &[(u16, &[u8])]) -> Vec<u8> {
        let q = build_query(id, "h.example", TYPE_SSHFP, false).unwrap();
        let mut m = q[..12].to_vec();
        m[2] = flags[0];
        m[3] = flags[1];
        m[6..8].copy_from_slice(&(answers.len() as u16).to_be_bytes());
        m.extend_from_slice(&q[12..]);
        for (ty, rdata) in answers {
            m.extend_from_slice(&[0xc0, 12]);
            m.extend_from_slice(&ty.to_be_bytes());
            m.extend_from_slice(&CLASS_IN.to_be_bytes());
            m.extend_from_slice(&300u32.to_be_bytes());
            m.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
            m.extend_from_slice(rdata);
        }
        m
    }

    #[test]
    fn replies_and_sshfp() {
        use purecrypto::hash::{Digest, Sha256};
        let blob = b"\0\0\0\x0bssh-ed25519\0\0\0\x20aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let mut good = vec![4u8, 2];
        good.extend_from_slice(Sha256::digest(blob).as_ref());
        let mut bad = vec![4u8, 2];
        bad.extend_from_slice(&[0u8; 32]);
        // AD set: validated.
        let set = parse_reply(
            &reply(7, [0x81, 0xa0], &[(TYPE_CNAME, b"x"), (TYPE_SSHFP, &good)]),
            7,
            TYPE_SSHFP,
        )
        .unwrap();
        assert!(set.validated);
        assert_eq!(set.rdatas, vec![good.clone()]);
        let v = check_sshfp(&set, "ssh-ed25519", blob).unwrap();
        assert!(v.found && v.matched && v.secure);
        // A failing record of the same type spoils the match.
        let set = RrSet {
            rdatas: vec![good.clone(), bad],
            validated: false,
        };
        let v = check_sshfp(&set, "ssh-ed25519", blob).unwrap();
        assert!(v.found && !v.matched && !v.secure);
        // Another key type's record neither matches nor fails.
        let v = check_sshfp(&set, "ssh-rsa", blob).unwrap();
        assert!(v.found && !v.matched);
        assert_eq!(check_sshfp(&set, "ssh-mldsa44-ed25519", blob), None);
        // NXDOMAIN, no answers, a wrong ID.
        assert_eq!(
            parse_reply(&reply(7, [0x81, 0x83], &[]), 7, TYPE_SSHFP),
            Err(DnsError::NoName)
        );
        assert_eq!(
            parse_reply(&reply(7, [0x81, 0x80], &[]), 7, TYPE_SSHFP),
            Err(DnsError::NoData)
        );
        assert_eq!(
            parse_reply(&reply(8, [0x81, 0x80], &[]), 7, TYPE_SSHFP),
            Err(DnsError::Fail)
        );
    }

    #[test]
    fn cname_targets_are_decompressed() {
        // The target `www.` + a pointer to the query's `h.example`.
        let m = reply(
            9,
            [0x81, 0x80],
            &[(TYPE_CNAME, &[3, b'w', b'w', b'w', 0xc0, 12])],
        );
        let set = parse_reply(&m, 9, TYPE_CNAME).unwrap();
        assert_eq!(set.rdatas, vec![b"www.h.example".to_vec()]);
        // A pointer forwards (or to itself) is refused.
        assert_eq!(read_name(&[0xc0, 0], 0), None);
    }

    #[test]
    fn query_shape() {
        let q = build_query(0x1234, "a.example.", TYPE_SSHFP, true).unwrap();
        assert_eq!(&q[..4], &[0x12, 0x34, 0x01, 0x20]);
        assert_eq!(&q[12..23], b"\x01a\x07example\x00");
        assert_eq!(&q[23..27], &[0, 44, 0, 1]);
        // The OPT record asks for DNSSEC records (DO).
        assert_eq!(q.len(), 27 + 11);
        assert_eq!(q[27 + 7], 0x80);
        assert!(build_query(1, "a..b", TYPE_SSHFP, false).is_none());
    }
}
