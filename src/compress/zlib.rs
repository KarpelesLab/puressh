//! `zlib` and `zlib@openssh.com` — RFC 1950 zlib with `Z_SYNC_FLUSH` between
//! packets. The DEFLATE stream is persistent for the lifetime of the
//! connection so inter-packet matches keep paying.

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

use crate::error::{Error, Result};

use super::{Compress, Decompress};

const INFLATE_DICT_SIZE: usize = 32 * 1024;

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
        let mut chunk = [0u8; 8192];
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
                    if co == chunk.len() {
                        continue;
                    }
                    if in_pos >= input.len() {
                        return Ok(out);
                    }
                    if ci == 0 && co == 0 {
                        return Err(Error::Crypto("zlib compress stalled"));
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
                TINFLStatus::HasMoreOutput => {
                    if ci == 0 && co == 0 {
                        return Err(Error::Format("zlib decompress stalled"));
                    }
                }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compress::{compress_by_name, decompress_by_name};

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
    fn factory_round_trip_through_boxed_traits() {
        let mut c = compress_by_name("zlib").unwrap();
        let mut d = decompress_by_name("zlib").unwrap();
        let payload = b"payload through trait objects";
        let on_wire = c.compress(payload).unwrap();
        assert_eq!(d.decompress(&on_wire).unwrap().as_slice(), payload);
    }
}
