//! SSH packet payload compression (RFC 4253 §6.2).
//!
//! Compression is negotiated per-direction during KEX. This module exposes:
//!
//! - [`Compress`] / [`Decompress`] — one-way streaming channels.
//! - [`NoneCompress`] / [`NoneDecompress`] — the pass-through algorithm.
//! - [`ZlibCompress`] / [`ZlibDecompress`] — RFC 1950 zlib running for the
//!   entire connection; the underlying DEFLATE stream is persistent and each
//!   packet is flushed with `Z_SYNC_FLUSH` so it can be decoded on its own.
//! - The delayed `zlib@openssh.com` variant, which behaves as `"none"` until
//!   the auth layer calls [`Compress::activate`] / [`Decompress::activate`]
//!   after `SSH_MSG_USERAUTH_SUCCESS`.
//! - [`compress_by_name`] / [`decompress_by_name`] — factories returning a
//!   boxed channel for a negotiated SSH name.
//!
//! The implementation is built on the low-level `miniz_oxide::deflate::core`
//! and `miniz_oxide::inflate::core` paths because SSH demands a single
//! long-lived DEFLATE stream per direction. The high-level
//! `compress_to_vec` / `decompress_to_vec` helpers reset state every call
//! and would lose the shared dictionary required for inter-packet matches.

use crate::error::{Error, Result};

use alloc::boxed::Box;
use alloc::vec;
use alloc::vec::Vec;

use miniz_oxide::deflate::core::{
    compress as deflate_step, CompressorOxide, TDEFLFlush, TDEFLStatus,
};
use miniz_oxide::inflate::core::inflate_flags::{
    TINFL_FLAG_HAS_MORE_INPUT, TINFL_FLAG_PARSE_ZLIB_HEADER,
};
use miniz_oxide::inflate::core::{decompress as inflate_step, DecompressorOxide};
use miniz_oxide::inflate::TINFLStatus;

const INFLATE_DICT_SIZE: usize = 32 * 1024;

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

struct ZlibDeflate {
    state: Box<CompressorOxide>,
}

impl ZlibDeflate {
    fn new() -> Self {
        Self {
            state: Box::new(CompressorOxide::default()),
        }
    }

    fn step(&mut self, input: &[u8]) -> Result<Vec<u8>> {
        let mut out: Vec<u8> = Vec::with_capacity(input.len() + 64);
        let mut chunk = vec![0u8; input.len().saturating_add(128).max(256)];
        let mut in_pos = 0usize;

        loop {
            let remaining_in = &input[in_pos..];
            let (status, ci, co) =
                deflate_step(&mut self.state, remaining_in, &mut chunk, TDEFLFlush::Sync);
            in_pos += ci;
            out.extend_from_slice(&chunk[..co]);

            match status {
                TDEFLStatus::BadParam | TDEFLStatus::PutBufFailed => {
                    return Err(Error::Crypto("zlib compress failed"));
                }
                TDEFLStatus::Done => return Ok(out),
                TDEFLStatus::Okay => {
                    let output_was_full = co == chunk.len();
                    if in_pos >= input.len() && !output_was_full {
                        return Ok(out);
                    }
                    if output_was_full {
                        let new_len = chunk.len().saturating_mul(2);
                        chunk = vec![0u8; new_len];
                    }
                }
            }
        }
    }
}

struct ZlibInflate {
    state: Box<DecompressorOxide>,
    ring: Vec<u8>,
    out_pos: usize,
    saw_header: bool,
}

impl ZlibInflate {
    fn new() -> Self {
        Self {
            state: Box::new(DecompressorOxide::default()),
            ring: vec![0u8; INFLATE_DICT_SIZE],
            out_pos: 0,
            saw_header: false,
        }
    }

    fn step(&mut self, input: &[u8]) -> Result<Vec<u8>> {
        let mut out = Vec::with_capacity(input.len() * 2);
        let mut input = input;
        let mut header_flag = if self.saw_header {
            0
        } else {
            TINFL_FLAG_PARSE_ZLIB_HEADER
        };

        loop {
            let flags = header_flag | TINFL_FLAG_HAS_MORE_INPUT;
            let (status, ci, co) =
                inflate_step(&mut self.state, input, &mut self.ring, self.out_pos, flags);

            for i in 0..co {
                out.push(self.ring[(self.out_pos + i) % INFLATE_DICT_SIZE]);
            }
            self.out_pos = (self.out_pos + co) % INFLATE_DICT_SIZE;
            input = &input[ci..];
            if co > 0 {
                self.saw_header = true;
                header_flag = 0;
            }

            match status {
                TINFLStatus::NeedsMoreInput => return Ok(out),
                TINFLStatus::HasMoreOutput => continue,
                TINFLStatus::Done => return Ok(out),
                _ => return Err(Error::Format("zlib decompress failed")),
            }
        }
    }
}

/// `"zlib"` — RFC 1950 zlib compression, single persistent DEFLATE stream
/// flushed with `Z_SYNC_FLUSH` after every packet (RFC 4253 §6.2).
pub struct ZlibCompress {
    inner: ZlibDeflate,
}

impl ZlibCompress {
    /// Build a fresh `"zlib"` compressor; the underlying DEFLATE stream is
    /// initialised immediately.
    pub fn new() -> Self {
        Self {
            inner: ZlibDeflate::new(),
        }
    }
}

impl Default for ZlibCompress {
    fn default() -> Self {
        Self::new()
    }
}

impl Compress for ZlibCompress {
    fn name(&self) -> &'static str {
        "zlib"
    }

    fn compress(&mut self, input: &[u8]) -> Result<Vec<u8>> {
        self.inner.step(input)
    }

    fn active(&self) -> bool {
        true
    }

    fn activate(&mut self) {}
}

/// `"zlib"` — counterpart to [`ZlibCompress`].
pub struct ZlibDecompress {
    inner: ZlibInflate,
}

impl ZlibDecompress {
    /// Build a fresh `"zlib"` decompressor.
    pub fn new() -> Self {
        Self {
            inner: ZlibInflate::new(),
        }
    }
}

impl Default for ZlibDecompress {
    fn default() -> Self {
        Self::new()
    }
}

impl Decompress for ZlibDecompress {
    fn name(&self) -> &'static str {
        "zlib"
    }

    fn decompress(&mut self, input: &[u8]) -> Result<Vec<u8>> {
        self.inner.step(input)
    }

    fn active(&self) -> bool {
        true
    }

    fn activate(&mut self) {}
}

/// `"zlib@openssh.com"` — delayed-start zlib.
///
/// Behaves as `"none"` until [`activate`](Compress::activate) is invoked
/// (after `SSH_MSG_USERAUTH_SUCCESS`); thereafter behaves as `"zlib"`. The
/// DEFLATE stream is created fresh at activation, with no state carried
/// from the inactive phase.
pub struct ZlibOpenSshCompress {
    inner: Option<ZlibDeflate>,
}

impl ZlibOpenSshCompress {
    /// Construct an inactive `"zlib@openssh.com"` compressor.
    pub fn new() -> Self {
        Self { inner: None }
    }
}

impl Default for ZlibOpenSshCompress {
    fn default() -> Self {
        Self::new()
    }
}

impl Compress for ZlibOpenSshCompress {
    fn name(&self) -> &'static str {
        "zlib@openssh.com"
    }

    fn compress(&mut self, input: &[u8]) -> Result<Vec<u8>> {
        match self.inner.as_mut() {
            None => Ok(input.to_vec()),
            Some(s) => s.step(input),
        }
    }

    fn active(&self) -> bool {
        self.inner.is_some()
    }

    fn activate(&mut self) {
        if self.inner.is_none() {
            self.inner = Some(ZlibDeflate::new());
        }
    }
}

/// `"zlib@openssh.com"` — counterpart to [`ZlibOpenSshCompress`].
pub struct ZlibOpenSshDecompress {
    inner: Option<ZlibInflate>,
}

impl ZlibOpenSshDecompress {
    /// Construct an inactive `"zlib@openssh.com"` decompressor.
    pub fn new() -> Self {
        Self { inner: None }
    }
}

impl Default for ZlibOpenSshDecompress {
    fn default() -> Self {
        Self::new()
    }
}

impl Decompress for ZlibOpenSshDecompress {
    fn name(&self) -> &'static str {
        "zlib@openssh.com"
    }

    fn decompress(&mut self, input: &[u8]) -> Result<Vec<u8>> {
        match self.inner.as_mut() {
            None => Ok(input.to_vec()),
            Some(s) => s.step(input),
        }
    }

    fn active(&self) -> bool {
        self.inner.is_some()
    }

    fn activate(&mut self) {
        if self.inner.is_none() {
            self.inner = Some(ZlibInflate::new());
        }
    }
}

/// Build a [`Compress`] channel for the negotiated SSH name, or `None` if
/// the algorithm is not supported.
pub fn compress_by_name(name: &str) -> Option<Box<dyn Compress>> {
    match name {
        "none" => Some(Box::new(NoneCompress)),
        "zlib" => Some(Box::new(ZlibCompress::new())),
        "zlib@openssh.com" => Some(Box::new(ZlibOpenSshCompress::new())),
        _ => None,
    }
}

/// Build a [`Decompress`] channel for the negotiated SSH name, or `None`
/// if the algorithm is not supported.
pub fn decompress_by_name(name: &str) -> Option<Box<dyn Decompress>> {
    match name {
        "none" => Some(Box::new(NoneDecompress)),
        "zlib" => Some(Box::new(ZlibDecompress::new())),
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
    fn zlib_round_trip_streaming() {
        let mut c = ZlibCompress::new();
        let mut d = ZlibDecompress::new();

        let small = b"hello".to_vec();
        let medium: Vec<u8> = (0..10_000u32).map(|i| (i & 0xff) as u8).collect();
        let mut large = Vec::with_capacity(100_000);
        let chunk = b"the quick brown fox jumps over the lazy dog -- ";
        while large.len() < 100_000 {
            large.extend_from_slice(chunk);
        }

        for payload in [&small[..], &medium[..], &large[..]] {
            let on_wire = c.compress(payload).unwrap();
            let back = d.decompress(&on_wire).unwrap();
            assert_eq!(back.as_slice(), payload);
        }
    }

    #[test]
    fn zlib_dictionary_carries_state() {
        let mut c = ZlibCompress::new();
        let payload = b"repeated payload repeated payload repeated payload";

        let first = c.compress(payload).unwrap();
        let second = c.compress(payload).unwrap();
        assert_ne!(
            first, second,
            "second packet must differ once the dictionary contains the first"
        );

        let mut d = ZlibDecompress::new();
        assert_eq!(d.decompress(&first).unwrap(), payload);
        assert_eq!(d.decompress(&second).unwrap(), payload);
    }

    #[test]
    fn zlib_openssh_delayed_activation() {
        let mut inactive = ZlibOpenSshCompress::new();
        let mut activated = ZlibOpenSshCompress::new();
        let payload = b"some bytes to compare";

        assert!(!inactive.active());
        let pass = inactive.compress(payload).unwrap();
        assert_eq!(pass.as_slice(), payload);

        activated.activate();
        assert!(activated.active());
        let compressed = activated.compress(payload).unwrap();
        assert_ne!(compressed.as_slice(), payload);

        let mut d = ZlibOpenSshDecompress::new();
        d.activate();
        assert_eq!(d.decompress(&compressed).unwrap(), payload);

        let mut d2 = ZlibOpenSshDecompress::new();
        assert_eq!(d2.decompress(payload).unwrap(), payload);
    }

    #[test]
    fn zlib_openssh_activated_matches_zlib() {
        let mut a = ZlibOpenSshCompress::new();
        a.activate();
        let mut b = ZlibCompress::new();
        let payload = b"identical setup, identical output";
        let oa = a.compress(payload).unwrap();
        let ob = b.compress(payload).unwrap();
        assert_eq!(oa, ob);
    }

    #[test]
    fn cross_instance_loses_state_after_first_packet() {
        let mut c = ZlibCompress::new();
        let payload = b"shared dictionary payload shared dictionary payload";
        let first = c.compress(payload).unwrap();
        let _second = c.compress(payload).unwrap();

        let mut d_fresh = ZlibDecompress::new();
        let back_first = d_fresh.decompress(&first).unwrap();
        assert_eq!(back_first.as_slice(), payload);
    }

    #[test]
    fn factory_returns_named_instances() {
        assert!(compress_by_name("none").is_some());
        assert!(compress_by_name("zlib").is_some());
        assert!(compress_by_name("zlib@openssh.com").is_some());
        assert!(compress_by_name("garbage").is_none());

        assert!(decompress_by_name("none").is_some());
        assert!(decompress_by_name("zlib").is_some());
        assert!(decompress_by_name("zlib@openssh.com").is_some());
        assert!(decompress_by_name("garbage").is_none());

        assert_eq!(compress_by_name("none").unwrap().name(), "none");
        assert_eq!(compress_by_name("zlib").unwrap().name(), "zlib");
        assert_eq!(
            compress_by_name("zlib@openssh.com").unwrap().name(),
            "zlib@openssh.com"
        );

        let zlib_dyn = compress_by_name("zlib@openssh.com").unwrap();
        assert!(!zlib_dyn.active());
    }

    #[test]
    fn factory_round_trip_through_boxed_traits() {
        let mut c = compress_by_name("zlib").unwrap();
        let mut d = decompress_by_name("zlib").unwrap();
        let payload = b"payload through trait objects";
        let on_wire = c.compress(payload).unwrap();
        assert_eq!(d.decompress(&on_wire).unwrap().as_slice(), payload);
    }
}
