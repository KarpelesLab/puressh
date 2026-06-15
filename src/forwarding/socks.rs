//! SOCKS4 / SOCKS4a / SOCKS5 `CONNECT` handshake for client-side dynamic
//! port forwarding (`ssh -D` / `DynamicForward`).
//!
//! This module owns the wire protocol only: it reads a SOCKS request off a
//! freshly-accepted stream, decides the CONNECT target, and writes the
//! success/failure reply. It deliberately knows nothing about SSH — the
//! caller (the `ssh` binary) takes the parsed [`SocksTarget`] and opens a
//! `direct-tcpip` channel to it via the running serve loop, then splices the
//! channel against the socket in both directions.
//!
//! Supported:
//!   - SOCKS5 (RFC 1928) with the no-authentication method (`0x00`) and the
//!     `CONNECT` command. IPv4, IPv6, and domain-name address types.
//!   - SOCKS4 / SOCKS4a (with the `0.0.0.x` domain-name extension).
//!
//! Rejected in-handshake (the client never offers them to the SSH server):
//!   - `BIND` and `UDP ASSOCIATE` commands — answered with the
//!     command-not-supported reply, then the socket is dropped.
//!   - SOCKS5 authentication methods other than "no auth".
//!
//! This file is `std`-only (it speaks `std::io`), matching the rest of the
//! forwarding layer.

#![cfg(feature = "std")]

use alloc::format;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use std::io::{self, Read, Write};

/// SOCKS protocol version byte for v5.
const SOCKS5: u8 = 0x05;
/// SOCKS protocol version byte for v4.
const SOCKS4: u8 = 0x04;

/// SOCKS5 "no authentication required" method.
const METHOD_NO_AUTH: u8 = 0x00;
/// SOCKS5 "no acceptable methods" sentinel (sent on rejection).
const METHOD_NONE: u8 = 0xFF;

/// SOCKS command byte: `CONNECT`.
const CMD_CONNECT: u8 = 0x01;

/// SOCKS5 address type: IPv4.
const ATYP_IPV4: u8 = 0x01;
/// SOCKS5 address type: domain name.
const ATYP_DOMAIN: u8 = 0x03;
/// SOCKS5 address type: IPv6.
const ATYP_IPV6: u8 = 0x04;

/// SOCKS5 reply code: success.
const REP_SUCCESS: u8 = 0x00;
/// SOCKS5 reply code: general failure.
const REP_GENERAL_FAILURE: u8 = 0x01;
/// SOCKS5 reply code: command not supported.
const REP_CMD_NOT_SUPPORTED: u8 = 0x07;

/// SOCKS4 reply: request granted.
const SOCKS4_GRANTED: u8 = 0x5A;
/// SOCKS4 reply: request rejected or failed.
const SOCKS4_REJECTED: u8 = 0x5B;

/// Largest domain name we'll accept in a request (SOCKS5 caps the length
/// field at one byte anyway; this is belt-and-braces for the SOCKS4a path).
const MAX_HOST_LEN: usize = 255;

/// The CONNECT target a SOCKS client asked us to reach. The SSH client opens
/// a `direct-tcpip` channel to `(host, port)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SocksTarget {
    /// Destination host — a domain name or a textual IP literal.
    pub host: String,
    /// Destination TCP port.
    pub port: u16,
    /// Which SOCKS version the request arrived on (needed to format the
    /// reply correctly once the channel open succeeds or fails).
    pub version: SocksVersion,
}

/// SOCKS protocol version of an accepted request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SocksVersion {
    /// SOCKS4 / SOCKS4a.
    V4,
    /// SOCKS5 (RFC 1928).
    V5,
}

/// A handshake failure. `Unsupported` means we recognised the request but
/// refuse it (BIND/UDP, auth method); `Protocol` means malformed input.
/// Either way the caller should drop the connection.
#[derive(Debug)]
pub enum SocksError {
    /// Underlying socket I/O failed.
    Io(io::Error),
    /// Bytes on the wire did not match the SOCKS grammar.
    Protocol(&'static str),
    /// A recognised-but-refused request (e.g. BIND, UDP, or a non-no-auth
    /// SOCKS5 method). A best-effort rejection reply has already been
    /// written to the stream where the protocol allows it.
    Unsupported(&'static str),
}

impl core::fmt::Display for SocksError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            SocksError::Io(e) => write!(f, "socks: io: {e}"),
            SocksError::Protocol(m) => write!(f, "socks: protocol: {m}"),
            SocksError::Unsupported(m) => write!(f, "socks: unsupported: {m}"),
        }
    }
}

impl std::error::Error for SocksError {}

impl From<io::Error> for SocksError {
    fn from(e: io::Error) -> Self {
        SocksError::Io(e)
    }
}

/// Read and parse a SOCKS `CONNECT` request from `s`, returning the
/// destination target.
///
/// Dispatches on the first byte (the version). For SOCKS5 this performs the
/// method-negotiation sub-handshake first (selecting "no auth"), then reads
/// the request proper. On a refused request (BIND/UDP, bad auth) a rejection
/// reply is written before returning [`SocksError::Unsupported`].
///
/// On success the caller must follow up with [`write_reply`] once it knows
/// whether the SSH `direct-tcpip` open succeeded.
pub fn handshake<S: Read + Write>(s: &mut S) -> Result<SocksTarget, SocksError> {
    let mut ver = [0u8; 1];
    s.read_exact(&mut ver)?;
    match ver[0] {
        SOCKS5 => handshake_v5(s),
        SOCKS4 => handshake_v4(s),
        _ => Err(SocksError::Protocol("unknown SOCKS version")),
    }
}

/// SOCKS5: negotiate methods then read the CONNECT request. The leading
/// version byte has already been consumed by [`handshake`].
fn handshake_v5<S: Read + Write>(s: &mut S) -> Result<SocksTarget, SocksError> {
    // Method-selection message: nmethods, then that many method bytes.
    let mut nmethods = [0u8; 1];
    s.read_exact(&mut nmethods)?;
    let mut methods = vec![0u8; nmethods[0] as usize];
    s.read_exact(&mut methods)?;
    if !methods.contains(&METHOD_NO_AUTH) {
        // Tell the client we have no acceptable method, then bail.
        let _ = s.write_all(&[SOCKS5, METHOD_NONE]);
        return Err(SocksError::Unsupported(
            "SOCKS5: only no-authentication is supported",
        ));
    }
    s.write_all(&[SOCKS5, METHOD_NO_AUTH])?;

    // Request: VER CMD RSV ATYP DST.ADDR DST.PORT
    let mut head = [0u8; 4];
    s.read_exact(&mut head)?;
    if head[0] != SOCKS5 {
        return Err(SocksError::Protocol("SOCKS5: bad request version"));
    }
    if head[1] != CMD_CONNECT {
        // BIND (0x02) / UDP ASSOCIATE (0x03): reject in-handshake.
        write_v5_reply(s, REP_CMD_NOT_SUPPORTED);
        return Err(SocksError::Unsupported(
            "SOCKS5: only CONNECT is supported (BIND/UDP refused)",
        ));
    }
    let atyp = head[3];
    let host = match atyp {
        ATYP_IPV4 => {
            let mut a = [0u8; 4];
            s.read_exact(&mut a)?;
            format!("{}.{}.{}.{}", a[0], a[1], a[2], a[3])
        }
        ATYP_IPV6 => {
            let mut a = [0u8; 16];
            s.read_exact(&mut a)?;
            format_ipv6(&a)
        }
        ATYP_DOMAIN => {
            let mut len = [0u8; 1];
            s.read_exact(&mut len)?;
            let n = len[0] as usize;
            if n == 0 {
                return Err(SocksError::Protocol("SOCKS5: empty domain name"));
            }
            let mut name = vec![0u8; n];
            s.read_exact(&mut name)?;
            String::from_utf8(name)
                .map_err(|_| SocksError::Protocol("SOCKS5: non-UTF8 domain name"))?
        }
        _ => {
            write_v5_reply(s, REP_GENERAL_FAILURE);
            return Err(SocksError::Protocol("SOCKS5: unknown address type"));
        }
    };
    let mut port = [0u8; 2];
    s.read_exact(&mut port)?;
    let port = u16::from_be_bytes(port);
    Ok(SocksTarget {
        host,
        port,
        version: SocksVersion::V5,
    })
}

/// SOCKS4 / SOCKS4a: read the CONNECT request. The leading version byte has
/// already been consumed by [`handshake`].
///
/// Layout: CMD DSTPORT(2) DSTIP(4) USERID\0 [DOMAIN\0 if SOCKS4a].
fn handshake_v4<S: Read + Write>(s: &mut S) -> Result<SocksTarget, SocksError> {
    let mut head = [0u8; 1 + 2 + 4];
    s.read_exact(&mut head)?;
    let cmd = head[0];
    let port = u16::from_be_bytes([head[1], head[2]]);
    let ip = [head[3], head[4], head[5], head[6]];

    if cmd != CMD_CONNECT {
        write_v4_reply(s, SOCKS4_REJECTED);
        return Err(SocksError::Unsupported(
            "SOCKS4: only CONNECT is supported (BIND refused)",
        ));
    }

    // USERID, NUL-terminated. We discard it.
    read_nul_terminated(s, MAX_HOST_LEN)?;

    // SOCKS4a: a DSTIP of 0.0.0.x (x != 0) signals that a hostname follows
    // the userid field, also NUL-terminated.
    let is_socks4a = ip[0] == 0 && ip[1] == 0 && ip[2] == 0 && ip[3] != 0;
    let host = if is_socks4a {
        let name = read_nul_terminated(s, MAX_HOST_LEN)?;
        if name.is_empty() {
            return Err(SocksError::Protocol("SOCKS4a: empty domain name"));
        }
        String::from_utf8(name).map_err(|_| SocksError::Protocol("SOCKS4a: non-UTF8 domain"))?
    } else {
        format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3])
    };

    Ok(SocksTarget {
        host,
        port,
        version: SocksVersion::V4,
    })
}

/// Write the final reply telling the client whether the upstream CONNECT
/// (the SSH `direct-tcpip` open) succeeded. Call exactly once after a
/// successful [`handshake`], with `ok` reflecting the channel-open result.
pub fn write_reply<S: Write>(s: &mut S, version: SocksVersion, ok: bool) -> io::Result<()> {
    match version {
        SocksVersion::V5 => {
            let rep = if ok { REP_SUCCESS } else { REP_GENERAL_FAILURE };
            // VER REP RSV ATYP=IPv4 BND.ADDR(0.0.0.0) BND.PORT(0)
            s.write_all(&[SOCKS5, rep, 0x00, ATYP_IPV4, 0, 0, 0, 0, 0, 0])
        }
        SocksVersion::V4 => {
            let code = if ok { SOCKS4_GRANTED } else { SOCKS4_REJECTED };
            // VN=0 CD DSTPORT(2) DSTIP(4) — all dummy on the reply.
            s.write_all(&[0x00, code, 0, 0, 0, 0, 0, 0])
        }
    }
}

/// Best-effort SOCKS5 rejection reply (ignores write errors — we're about to
/// drop the socket regardless).
fn write_v5_reply<S: Write>(s: &mut S, rep: u8) {
    let _ = s.write_all(&[SOCKS5, rep, 0x00, ATYP_IPV4, 0, 0, 0, 0, 0, 0]);
}

/// Best-effort SOCKS4 rejection reply.
fn write_v4_reply<S: Write>(s: &mut S, code: u8) {
    let _ = s.write_all(&[0x00, code, 0, 0, 0, 0, 0, 0]);
}

/// Read a NUL-terminated field one byte at a time, returning the bytes
/// before the NUL. Caps the length to guard against an unbounded read from a
/// hostile client.
fn read_nul_terminated<S: Read>(s: &mut S, max: usize) -> Result<Vec<u8>, SocksError> {
    let mut out = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        s.read_exact(&mut byte)?;
        if byte[0] == 0 {
            return Ok(out);
        }
        if out.len() >= max {
            return Err(SocksError::Protocol("SOCKS: NUL-terminated field too long"));
        }
        out.push(byte[0]);
    }
}

/// Format a 16-byte IPv6 address as a textual literal. Uses the std
/// `Ipv6Addr` formatter (which applies `::` compression) so the value round-
/// trips through `TcpStream::connect`.
fn format_ipv6(a: &[u8; 16]) -> String {
    let addr = std::net::Ipv6Addr::from(*a);
    format!("{addr}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    /// A bidirectional in-memory stream: reads drain `input`, writes append
    /// to `output`.
    struct MockStream {
        input: Cursor<Vec<u8>>,
        output: Vec<u8>,
    }
    impl MockStream {
        fn new(input: Vec<u8>) -> Self {
            Self {
                input: Cursor::new(input),
                output: Vec::new(),
            }
        }
    }
    impl Read for MockStream {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            self.input.read(buf)
        }
    }
    impl Write for MockStream {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.output.extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn socks5_connect_ipv4() {
        // greeting: VER, NMETHODS=1, METHOD=no-auth
        // request : VER, CONNECT, RSV, ATYP=IPv4, 1.2.3.4, port 0x0050 (80)
        let req = vec![
            SOCKS5, 1, METHOD_NO_AUTH, SOCKS5, CMD_CONNECT, 0x00, ATYP_IPV4, 1, 2, 3, 4, 0x00, 0x50,
        ];
        let mut s = MockStream::new(req);
        let t = handshake(&mut s).unwrap();
        assert_eq!(t.host, "1.2.3.4");
        assert_eq!(t.port, 80);
        assert_eq!(t.version, SocksVersion::V5);
        // Server should have written the method-selection reply.
        assert_eq!(&s.output[..2], &[SOCKS5, METHOD_NO_AUTH]);
    }

    #[test]
    fn socks5_connect_domain() {
        let host = b"example.com";
        let mut req = vec![SOCKS5, 1, METHOD_NO_AUTH, SOCKS5, CMD_CONNECT, 0x00, ATYP_DOMAIN];
        req.push(host.len() as u8);
        req.extend_from_slice(host);
        req.extend_from_slice(&443u16.to_be_bytes());
        let mut s = MockStream::new(req);
        let t = handshake(&mut s).unwrap();
        assert_eq!(t.host, "example.com");
        assert_eq!(t.port, 443);
    }

    #[test]
    fn socks5_connect_ipv6() {
        let mut req = vec![SOCKS5, 1, METHOD_NO_AUTH, SOCKS5, CMD_CONNECT, 0x00, ATYP_IPV6];
        let addr = std::net::Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        req.extend_from_slice(&addr.octets());
        req.extend_from_slice(&8080u16.to_be_bytes());
        let mut s = MockStream::new(req);
        let t = handshake(&mut s).unwrap();
        assert_eq!(t.host, "2001:db8::1");
        assert_eq!(t.port, 8080);
    }

    #[test]
    fn socks5_rejects_non_no_auth() {
        // Offer only username/password (0x02).
        let req = vec![SOCKS5, 1, 0x02];
        let mut s = MockStream::new(req);
        let err = handshake(&mut s).unwrap_err();
        assert!(matches!(err, SocksError::Unsupported(_)));
        assert_eq!(&s.output[..2], &[SOCKS5, METHOD_NONE]);
    }

    #[test]
    fn socks5_rejects_bind() {
        let req = vec![
            SOCKS5, 1, METHOD_NO_AUTH, SOCKS5, 0x02, /* BIND */
            0x00, ATYP_IPV4, 1, 2, 3, 4, 0, 80,
        ];
        let mut s = MockStream::new(req);
        let err = handshake(&mut s).unwrap_err();
        assert!(matches!(err, SocksError::Unsupported(_)));
        // method-selection reply, then the cmd-not-supported reply.
        assert_eq!(s.output[1], METHOD_NO_AUTH);
        assert_eq!(s.output[3], REP_CMD_NOT_SUPPORTED);
    }

    #[test]
    fn socks5_rejects_udp() {
        let req = vec![
            SOCKS5, 1, METHOD_NO_AUTH, SOCKS5, 0x03, /* UDP ASSOCIATE */
            0x00, ATYP_IPV4, 0, 0, 0, 0, 0, 0,
        ];
        let mut s = MockStream::new(req);
        assert!(matches!(handshake(&mut s), Err(SocksError::Unsupported(_))));
    }

    #[test]
    fn socks4_connect_ipv4() {
        // VER=4, CMD=CONNECT, port=80, ip=1.2.3.4, userid="me\0"
        let mut req = vec![SOCKS4, CMD_CONNECT];
        req.extend_from_slice(&80u16.to_be_bytes());
        req.extend_from_slice(&[1, 2, 3, 4]);
        req.extend_from_slice(b"me\0");
        let mut s = MockStream::new(req);
        let t = handshake(&mut s).unwrap();
        assert_eq!(t.host, "1.2.3.4");
        assert_eq!(t.port, 80);
        assert_eq!(t.version, SocksVersion::V4);
    }

    #[test]
    fn socks4a_connect_domain() {
        // ip = 0.0.0.1 (4a marker), then hostname after userid.
        let mut req = vec![SOCKS4, CMD_CONNECT];
        req.extend_from_slice(&443u16.to_be_bytes());
        req.extend_from_slice(&[0, 0, 0, 1]);
        req.extend_from_slice(b"\0"); // empty userid
        req.extend_from_slice(b"example.org\0");
        let mut s = MockStream::new(req);
        let t = handshake(&mut s).unwrap();
        assert_eq!(t.host, "example.org");
        assert_eq!(t.port, 443);
    }

    #[test]
    fn socks4_rejects_bind() {
        let mut req = vec![SOCKS4, 0x02 /* BIND */];
        req.extend_from_slice(&80u16.to_be_bytes());
        req.extend_from_slice(&[1, 2, 3, 4]);
        req.extend_from_slice(b"\0");
        let mut s = MockStream::new(req);
        assert!(matches!(handshake(&mut s), Err(SocksError::Unsupported(_))));
        assert_eq!(s.output[1], SOCKS4_REJECTED);
    }

    #[test]
    fn unknown_version_rejected() {
        let mut s = MockStream::new(vec![0x06, 0, 0]);
        assert!(matches!(handshake(&mut s), Err(SocksError::Protocol(_))));
    }

    #[test]
    fn reply_v5_success_shape() {
        let mut out = Vec::new();
        write_reply(&mut out, SocksVersion::V5, true).unwrap();
        assert_eq!(out, vec![SOCKS5, REP_SUCCESS, 0, ATYP_IPV4, 0, 0, 0, 0, 0, 0]);
    }

    #[test]
    fn reply_v4_failure_shape() {
        let mut out = Vec::new();
        write_reply(&mut out, SocksVersion::V4, false).unwrap();
        assert_eq!(out, vec![0x00, SOCKS4_REJECTED, 0, 0, 0, 0, 0, 0]);
    }
}
