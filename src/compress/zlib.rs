//! `zlib` and `zlib@openssh.com` — RFC 1950 zlib with `Z_SYNC_FLUSH` between
//! packets. The DEFLATE stream is persistent for the lifetime of the
//! connection so inter-packet matches keep paying.
//!
//! Backed by `compcol::zlib`. Per packet we drive the encoder with
//! [`compcol::Encoder::encode`] to consume the plaintext and then call
//! [`compcol::Encoder::flush`] with [`compcol::Flush::Sync`] to emit the
//! `Z_SYNC_FLUSH` marker (RFC 4253 §6.2). The decoder is a straightforward
//! [`compcol::Decoder::decode`] drain — `Z_SYNC_FLUSH` markers are regular
//! DEFLATE empty stored blocks, which the inflate side consumes without
//! special-casing.

use alloc::vec::Vec;

use compcol::zlib::{Decoder as CcDecoder, Encoder as CcEncoder};
use compcol::{Decoder as _, Encoder as _, Flush, Status};

use crate::error::{Error, Result};

use super::{Compress, Decompress};

/// Output staging chunk used per inner-loop step. 8 KiB matches the size
/// the previous miniz_oxide path used and keeps copy granularity well
/// under typical SSH payload sizes.
const CHUNK: usize = 8 * 1024;

struct ZlibDeflate {
    enc: CcEncoder,
}

impl ZlibDeflate {
    fn new() -> Self {
        Self {
            enc: CcEncoder::new(),
        }
    }

    /// Compress one SSH packet of `input` and return the bytes that go on
    /// the wire (deflate output up to and including the `Z_SYNC_FLUSH`
    /// marker). The encoder state — sliding window, Huffman histograms,
    /// bit-writer alignment — persists for the next call.
    fn step(&mut self, input: &[u8]) -> Result<Vec<u8>> {
        let mut out: Vec<u8> = Vec::with_capacity(input.len() + 64);
        let mut chunk = [0u8; CHUNK];

        // ── push input ───────────────────────────────────────────────────
        let mut consumed = 0usize;
        while consumed < input.len() {
            let (progress, status) = self
                .enc
                .encode(&input[consumed..], &mut chunk)
                .map_err(|_| Error::Crypto("zlib compress failed"))?;
            consumed += progress.consumed;
            out.extend_from_slice(&chunk[..progress.written]);
            match status {
                Status::InputEmpty => break,
                Status::OutputFull => {
                    if progress.consumed == 0 && progress.written == 0 {
                        return Err(Error::Crypto("zlib compress stalled"));
                    }
                }
                Status::StreamEnd => return Err(Error::Crypto("zlib compress closed")),
            }
        }

        // ── per-packet sync flush ─────────────────────────────────────────
        loop {
            let (progress, status) = self
                .enc
                .flush(&mut chunk, Flush::Sync)
                .map_err(|_| Error::Crypto("zlib compress failed"))?;
            out.extend_from_slice(&chunk[..progress.written]);
            match status {
                Status::InputEmpty => break,
                Status::OutputFull => {
                    if progress.written == 0 {
                        return Err(Error::Crypto("zlib compress stalled"));
                    }
                }
                Status::StreamEnd => return Err(Error::Crypto("zlib compress closed")),
            }
        }

        Ok(out)
    }
}

struct ZlibInflate {
    dec: CcDecoder,
}

impl ZlibInflate {
    fn new() -> Self {
        Self {
            dec: CcDecoder::new(),
        }
    }

    /// Decompress one SSH packet of `input`. `Z_SYNC_FLUSH` markers are
    /// regular deflate blocks to the inflate side, so the persistent
    /// sliding window seamlessly bridges packet boundaries.
    fn step(&mut self, input: &[u8]) -> Result<Vec<u8>> {
        let mut out: Vec<u8> = Vec::with_capacity(input.len() * 2);
        let mut chunk = [0u8; CHUNK];

        let mut consumed = 0usize;
        loop {
            let (progress, status) = self
                .dec
                .decode(&input[consumed..], &mut chunk)
                .map_err(|_| Error::Format("zlib decompress failed"))?;
            consumed += progress.consumed;
            out.extend_from_slice(&chunk[..progress.written]);
            match status {
                // All of this packet's bytes consumed; output drained.
                Status::InputEmpty => return Ok(out),
                // More to come — drain `chunk` and loop. If neither side
                // moved we'd spin forever, so treat that as a stall.
                Status::OutputFull => {
                    if progress.consumed == 0 && progress.written == 0 {
                        return Err(Error::Format("zlib decompress stalled"));
                    }
                }
                // SSH zlib never ends the deflate stream — `Z_SYNC_FLUSH`
                // emits BFINAL=0 blocks. If we ever see StreamEnd the peer
                // closed the stream, which violates the protocol.
                Status::StreamEnd => return Err(Error::Format("zlib decompress closed")),
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
