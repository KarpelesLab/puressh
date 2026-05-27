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
    pub fn parse_remote(line: &[u8]) -> Result<alloc::string::String> {
        let trimmed = match line.strip_suffix(b"\r\n") {
            Some(t) => t,
            None => line.strip_suffix(b"\n").unwrap_or(line),
        };
        if !trimmed.starts_with(b"SSH-2.0-") && !trimmed.starts_with(b"SSH-1.99-") {
            return Err(Error::Protocol("peer is not SSH 2.0"));
        }
        core::str::from_utf8(trimmed)
            .map(alloc::string::String::from)
            .map_err(|_| Error::Protocol("non-ASCII in version string"))
    }
}
