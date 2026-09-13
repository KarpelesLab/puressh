//! SSH packet payload compression (RFC 4253 §6.2).
//!
//! Compression is negotiated per-direction during KEX. This module exposes:
//!
//! - [`Compress`] / [`Decompress`] — one-way streaming channels.
//! - [`NoneCompress`] / [`NoneDecompress`] — the pass-through algorithm.
//! - [`ZlibCompress`] / [`ZlibDecompress`] — RFC 1950 zlib running for the
//!   entire connection; the underlying DEFLATE stream is persistent and each
//!   packet is flushed with `Z_SYNC_FLUSH` so it can be decoded on its own.
//!   Available only with the `compress` feature.
//! - The delayed `zlib@openssh.com` variant, which behaves as `"none"` until
//!   the auth layer calls [`Compress::activate`] / [`Decompress::activate`]
//!   after `SSH_MSG_USERAUTH_SUCCESS`.
//! - [`compress_by_name`] / [`decompress_by_name`] — factories returning a
//!   boxed channel for a negotiated SSH name.
//!
//! The zlib implementation is built on the low-level
//! `miniz_oxide::deflate::core` and `miniz_oxide::inflate::core` paths
//! because SSH demands a single long-lived DEFLATE stream per direction.
//! The high-level `compress_to_vec` / `decompress_to_vec` helpers reset
//! state every call and would lose the shared dictionary required for
//! inter-packet matches.

use crate::error::Result;

use alloc::boxed::Box;
use alloc::vec::Vec;

#[cfg(feature = "compress")]
mod zlib;

#[cfg(feature = "compress")]
pub use zlib::{ZlibCompress, ZlibDecompress, ZlibOpenSshCompress, ZlibOpenSshDecompress};

/// One-way compression channel. SSH negotiates compression per direction.
pub trait Compress: Send {
    /// SSH on-the-wire algorithm name.
    fn name(&self) -> &'static str;

    /// Compress `input` and return the on-wire bytes for one packet payload.
    fn compress(&mut self, input: &[u8]) -> Result<Vec<u8>>;

    /// `true` once the compressor has been activated. For `"none"` and
    /// `"zlib"` this is always true; for `"zlib@openssh.com"` it is false
    /// until [`activate`](Compress::activate) is called.
    fn active(&self) -> bool;

    /// Switch compression on. Called by the auth layer after
    /// `SSH_MSG_USERAUTH_SUCCESS` for `"zlib@openssh.com"`; a no-op for the
    /// other algorithms.
    fn activate(&mut self);
}

/// One-way decompression channel; the inverse of [`Compress`].
pub trait Decompress: Send {
    /// SSH on-the-wire algorithm name.
    fn name(&self) -> &'static str;

    /// Decompress one packet's payload bytes.
    fn decompress(&mut self, input: &[u8]) -> Result<Vec<u8>>;

    /// `true` once the decompressor has been activated.
    fn active(&self) -> bool;

    /// Switch decompression on; mirrors [`Compress::activate`].
    fn activate(&mut self);
}

/// `"none"` — identity compressor.
pub struct NoneCompress;

impl Compress for NoneCompress {
    fn name(&self) -> &'static str {
        "none"
    }

    fn compress(&mut self, input: &[u8]) -> Result<Vec<u8>> {
        Ok(input.to_vec())
    }

    fn active(&self) -> bool {
        true
    }

    fn activate(&mut self) {}
}

/// `"none"` — identity decompressor.
pub struct NoneDecompress;

impl Decompress for NoneDecompress {
    fn name(&self) -> &'static str {
        "none"
    }

    fn decompress(&mut self, input: &[u8]) -> Result<Vec<u8>> {
        Ok(input.to_vec())
    }

    fn active(&self) -> bool {
        true
    }

    fn activate(&mut self) {}
}

/// Build a [`Compress`] channel for the negotiated SSH name, or `None` if
/// the algorithm is not supported.
///
/// Without the `compress` feature only `"none"` is recognised.
pub fn compress_by_name(name: &str) -> Option<Box<dyn Compress>> {
    match name {
        "none" => Some(Box::new(NoneCompress)),
        #[cfg(feature = "compress")]
        "zlib" => Some(Box::new(ZlibCompress::new())),
        #[cfg(feature = "compress")]
        "zlib@openssh.com" => Some(Box::new(ZlibOpenSshCompress::new())),
        _ => None,
    }
}

/// Build a [`Decompress`] channel for the negotiated SSH name, or `None`
/// if the algorithm is not supported.
///
/// Without the `compress` feature only `"none"` is recognised.
pub fn decompress_by_name(name: &str) -> Option<Box<dyn Decompress>> {
    match name {
        "none" => Some(Box::new(NoneDecompress)),
        #[cfg(feature = "compress")]
        "zlib" => Some(Box::new(ZlibDecompress::new())),
        #[cfg(feature = "compress")]
        "zlib@openssh.com" => Some(Box::new(ZlibOpenSshDecompress::new())),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn none_round_trip() {
        let mut c = NoneCompress;
        let mut d = NoneDecompress;
        for payload in [&b""[..], b"x", b"hello world"].iter() {
            let on_wire = c.compress(payload).unwrap();
            assert_eq!(on_wire.as_slice(), *payload);
            let back = d.decompress(&on_wire).unwrap();
            assert_eq!(back.as_slice(), *payload);
        }
    }

    #[test]
    fn factory_returns_named_instances() {
        assert!(compress_by_name("none").is_some());
        assert!(decompress_by_name("none").is_some());
        assert!(compress_by_name("garbage").is_none());
        assert!(decompress_by_name("garbage").is_none());
        assert_eq!(compress_by_name("none").unwrap().name(), "none");
        assert_eq!(decompress_by_name("none").unwrap().name(), "none");
    }

    #[cfg(feature = "compress")]
    #[test]
    fn factory_recognises_zlib_variants() {
        assert!(compress_by_name("zlib").is_some());
        assert!(compress_by_name("zlib@openssh.com").is_some());
        assert!(decompress_by_name("zlib").is_some());
        assert!(decompress_by_name("zlib@openssh.com").is_some());

        let zlib_dyn = compress_by_name("zlib@openssh.com").unwrap();
        assert!(!zlib_dyn.active());
    }
}
