//! SSH Binary Packet Protocol (RFC 4253 §6).
//!
//! Each packet is:
//!
//! ```text
//! uint32  packet_length    — length of [padding_length || payload || padding]
//! byte    padding_length
//! byte[n] payload          — n = packet_length - padding_length - 1
//! byte[p] random_padding   — p = padding_length, ≥ 4
//! byte[m] mac              — only when a MAC has been negotiated
//! ```
//!
//! For AES-GCM and ChaCha20-Poly1305 the framing differs slightly — see
//! [`crate::cipher`] for the per-suite encrypt/decrypt entry points.

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

use crate::error::Result;

/// Minimum cipher block size assumed when no cipher has been negotiated yet.
pub const BLOCK_SIZE_DEFAULT: usize = 8;

/// A decoded packet: the bare payload (no length/padding/MAC).
#[cfg(feature = "alloc")]
#[derive(Debug, Clone)]
pub struct Packet {
    /// The message-type byte is `payload[0]`.
    pub payload: Vec<u8>,
}

/// Stateful encoder/decoder for the binary packet protocol.
///
/// Holds the per-direction sequence number (which is included in MACs / AEAD
/// nonces) plus the negotiated cipher and MAC. The first packet is exchanged
/// in cleartext; after `NEWKEYS` the codec is switched to the negotiated suite.
#[cfg(feature = "alloc")]
pub struct PacketCodec {
    /// Inbound sequence counter — increments per packet, wraps at u32::MAX.
    pub seq_in: u32,
    /// Outbound sequence counter.
    pub seq_out: u32,
    // Cipher / MAC state is plugged in once kex completes.
    // (kept private and added in a later iteration)
}

#[cfg(feature = "alloc")]
impl PacketCodec {
    /// Build a fresh codec with both sequence counters at zero.
    pub fn new() -> Self {
        Self { seq_in: 0, seq_out: 0 }
    }

    /// Encode `payload` into a freshly-allocated frame ready to be sent.
    ///
    /// Stubbed: this currently returns `Unsupported` because the cipher/MAC
    /// pipeline is being wired up incrementally.
    pub fn encode(&mut self, _payload: &[u8]) -> Result<Vec<u8>> {
        Err(crate::error::Error::Unsupported("packet encode (WIP)"))
    }

    /// Decode the next packet out of `inbuf`, returning the payload and the
    /// number of bytes consumed.
    pub fn decode(&mut self, _inbuf: &[u8]) -> Result<Option<(Packet, usize)>> {
        Err(crate::error::Error::Unsupported("packet decode (WIP)"))
    }
}

#[cfg(feature = "alloc")]
impl Default for PacketCodec {
    fn default() -> Self {
        Self::new()
    }
}
