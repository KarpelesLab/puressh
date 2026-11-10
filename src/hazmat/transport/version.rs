//! Version-string exchange (RFC 4253 §4.2).
//!
//! Each side sends an identification string of the form
//! `SSH-2.0-softwareversion SP comments CR LF` before any binary packets.

use crate::error::{Error, Result};

/// The version string our local end identifies itself with.
pub const LOCAL_VERSION: &str = concat!("SSH-2.0-puressh_", env!("CARGO_PKG_VERSION"));

/// Result of a version exchange.
#[derive(Debug, Clone)]
pub struct VersionExchange {
    /// Our local id, without trailing CR LF.
    pub local: &'static str,
    /// Peer's id, without trailing CR LF. Borrowed for `'a`, owned in upper layers.
    pub remote: alloc::string::String,
}

#[cfg(feature = "alloc")]
extern crate alloc;

impl VersionExchange {
    /// Build the bytes to send for the local id, ending with `\r\n`.
    pub fn outgoing_bytes() -> alloc::vec::Vec<u8> {
        let mut v = alloc::vec::Vec::with_capacity(LOCAL_VERSION.len() + 2);
        v.extend_from_slice(LOCAL_VERSION.as_bytes());
        v.extend_from_slice(b"\r\n");
        v
    }

    /// Parse a single line of peer identification (with or without CR LF).
    ///
    /// Per RFC 4253 §4.2 the identification string MUST NOT exceed 255
    /// octets including the trailing CR LF. We reject anything longer so
    /// a peer cannot push us into unbounded line buffering before any
    /// authentication has occurred.
    pub fn parse_remote(line: &[u8]) -> Result<alloc::string::String> {
        if line.len() > 255 {
            return Err(Error::Protocol("version line exceeds 255 bytes"));
        }
        let trimmed = match line.strip_suffix(b"\r\n") {
            Some(t) => t,
            None => line.strip_suffix(b"\n").unwrap_or(line),
        };
        if !trimmed.starts_with(b"SSH-2.0-") && !trimmed.starts_with(b"SSH-1.99-") {
            return Err(Error::Protocol("peer is not SSH 2.0"));
        }
        let s = core::str::from_utf8(trimmed)
            .map_err(|_| Error::Protocol("version string is not valid UTF-8"))?;
        // RFC 4253 §4.2 allows printable characters only. A control
        // character has no legitimate use there, and the line is logged
        // and shown by the frontends.
        if s.bytes().any(|b| b < 0x20 || b == 0x7f) {
            return Err(Error::Protocol("control character in version string"));
        }
        Ok(alloc::string::String::from(s))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_remote_accepts_reasonable_line() {
        let v = VersionExchange::parse_remote(b"SSH-2.0-OpenSSH_9.7\r\n").unwrap();
        assert_eq!(v, "SSH-2.0-OpenSSH_9.7");
    }

    #[test]
    fn parse_remote_rejects_control_characters() {
        assert!(VersionExchange::parse_remote(b"SSH-2.0-x\x1b[2J\r\n").is_err());
        assert!(VersionExchange::parse_remote(b"SSH-2.0-x\x07\n").is_err());
        assert!(VersionExchange::parse_remote(b"SSH-2.0-x\x7f\n").is_err());
        assert!(VersionExchange::parse_remote(b"SSH-2.0-x\xff\n").is_err());
        // Spaces and a comment are fine.
        assert!(VersionExchange::parse_remote(b"SSH-2.0-x comment here\r\n").is_ok());
    }

    #[test]
    fn parse_remote_rejects_oversized_line() {
        let mut huge = alloc::vec::Vec::with_capacity(300);
        huge.extend_from_slice(b"SSH-2.0-");
        huge.extend(core::iter::repeat_n(b'X', 300 - huge.len() - 2));
        huge.extend_from_slice(b"\r\n");
        assert_eq!(huge.len(), 300);
        let err = VersionExchange::parse_remote(&huge).unwrap_err();
        match err {
            Error::Protocol(msg) => assert_eq!(msg, "version line exceeds 255 bytes"),
            other => panic!("expected Protocol, got {other:?}"),
        }
    }

    #[test]
    fn parse_remote_accepts_at_255_octets() {
        // Boundary: 255 octets including CRLF is allowed.
        let mut at_limit = alloc::vec::Vec::with_capacity(255);
        at_limit.extend_from_slice(b"SSH-2.0-");
        at_limit.extend(core::iter::repeat_n(b'A', 255 - at_limit.len() - 2));
        at_limit.extend_from_slice(b"\r\n");
        assert_eq!(at_limit.len(), 255);
        assert!(VersionExchange::parse_remote(&at_limit).is_ok());
    }

    #[test]
    fn parse_remote_rejects_non_ssh_prefix() {
        let line = b"HTTP/1.1 200 OK\r\n";
        let err = VersionExchange::parse_remote(line).unwrap_err();
        match err {
            Error::Protocol(_) => {}
            other => panic!("expected Protocol, got {other:?}"),
        }
    }
}
