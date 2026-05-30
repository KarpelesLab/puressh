//! SSH Binary Packet Protocol (RFC 4253 §6) plus the OpenSSH AEAD variants
//! (RFC 5647 AES-GCM and `chacha20-poly1305@openssh.com`).
//!
//! Frame layout (legacy / CTR):
//!
//! ```text
//! uint32  packet_length     — length of [padding_length || payload || padding]
//! byte    padding_length
//! byte[]  payload           — n = packet_length - padding_length - 1
//! byte[]  random_padding    — p = padding_length, ≥ 4
//! byte[]  mac               — only when a non-AEAD MAC has been negotiated
//! ```
//!
//! AEAD suites either transmit the length field as cleartext AAD (GCM) or
//! encrypt it with a separate stream key (ChaCha20-Poly1305); in both cases
//! the integrity tag is bound to the cipher and the negotiated MAC field is
//! empty.

#[cfg(feature = "alloc")]
use alloc::boxed::Box;
#[cfg(feature = "alloc")]
use alloc::vec;
#[cfg(feature = "alloc")]
use alloc::vec::Vec;

use purecrypto::rng::{CryptoRng, RngCore};

use crate::cipher::SshCipher;
#[cfg(feature = "alloc")]
use crate::compress::{Compress, Decompress, NoneCompress, NoneDecompress};
use crate::error::{Error, Result};
use crate::mac::SshMac;

/// Block size assumed when no cipher has been negotiated yet (RFC 4253 §6).
pub const BLOCK_SIZE_DEFAULT: usize = 8;

/// Maximum packet length accepted by [`PacketCodec::decode`] (RFC 4253 §6.1).
pub const MAX_PACKET_LEN: u32 = 35_000;

/// Minimum total on-the-wire packet length before MAC, per RFC 4253 §6.
const MIN_TOTAL_LEN: usize = 16;

/// A decoded packet: the bare payload (no length / padding / MAC bytes).
#[cfg(feature = "alloc")]
#[derive(Debug, Clone)]
pub struct Packet {
    /// The message-type byte is `payload[0]`.
    pub payload: Vec<u8>,
}

#[cfg(feature = "alloc")]
enum CipherSlot {
    None,
    Stream {
        cipher: SshCipher,
        mac: Box<dyn SshMac + Send + Sync>,
    },
    Gcm(SshCipher),
    ChaChaPoly(SshCipher),
}

#[cfg(feature = "alloc")]
fn classify(cipher: SshCipher, mac: Option<Box<dyn SshMac + Send + Sync>>) -> Result<CipherSlot> {
    match (&cipher, cipher.is_aead()) {
        (SshCipher::Ctr(_), _) => {
            let mac = mac.ok_or(Error::Protocol("MAC required for non-AEAD cipher"))?;
            Ok(CipherSlot::Stream { cipher, mac })
        }
        (SshCipher::Gcm(_), _) => Ok(CipherSlot::Gcm(cipher)),
        (SshCipher::ChaChaPoly(_), _) => Ok(CipherSlot::ChaChaPoly(cipher)),
    }
}

/// Stateful encoder/decoder for the SSH binary packet protocol.
///
/// Holds per-direction sequence counters plus the negotiated cipher and MAC
/// state. Before NEWKEYS the codec runs in cleartext mode with an 8-byte
/// block alignment.
#[cfg(feature = "alloc")]
pub struct PacketCodec {
    /// Inbound sequence counter — increments per packet, wraps at u32::MAX.
    pub seq_in: u32,
    /// Outbound sequence counter — increments per packet, wraps at u32::MAX.
    pub seq_out: u32,
    /// Total on-wire bytes encoded since this codec was created. Counts the
    /// post-compression, post-encryption framing (length + body + MAC/tag),
    /// matching what RFC 4253 §9 measures when deciding to re-key.
    pub bytes_out: u64,
    /// Total on-wire bytes decoded since this codec was created.
    pub bytes_in: u64,
    outbound: CipherSlot,
    inbound: CipherSlot,
    /// Cached first decrypted block when peeking at the length field of an
    /// EaM CTR packet that hasn't fully arrived yet.
    pending_first_block: Option<Vec<u8>>,
    /// Outbound compression channel; defaults to `NoneCompress`.
    outbound_compress: Box<dyn Compress>,
    /// Inbound decompression channel; defaults to `NoneDecompress`.
    inbound_decompress: Box<dyn Decompress>,
}

#[cfg(feature = "alloc")]
impl Default for PacketCodec {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(feature = "alloc")]
impl PacketCodec {
    /// Build a fresh codec in cleartext mode with both sequence counters at
    /// zero.
    pub fn new() -> Self {
        Self {
            seq_in: 0,
            seq_out: 0,
            bytes_out: 0,
            bytes_in: 0,
            outbound: CipherSlot::None,
            inbound: CipherSlot::None,
            pending_first_block: None,
            outbound_compress: Box::new(NoneCompress),
            inbound_decompress: Box::new(NoneDecompress),
        }
    }

    /// Install outbound cipher state and (optionally) MAC after NEWKEYS.
    /// `mac` must be `Some` for non-AEAD ciphers and is `None` for AEAD.
    ///
    /// Returns `Err(Error::Protocol("MAC required for non-AEAD cipher"))`
    /// when the cipher/MAC pair is inconsistent. Previously this panicked,
    /// which let an attacker (in principle) crash the process by feeding
    /// us a cipher/MAC pair that survived negotiation but failed
    /// classification.
    pub fn install_outbound(
        &mut self,
        cipher: SshCipher,
        mac: Option<Box<dyn SshMac + Send + Sync>>,
    ) -> Result<()> {
        self.outbound = classify(cipher, mac)?;
        Ok(())
    }

    /// Install inbound cipher state and (optionally) MAC after NEWKEYS.
    ///
    /// Returns `Err(Error::Protocol("MAC required for non-AEAD cipher"))`
    /// when the cipher/MAC pair is inconsistent. See
    /// [`install_outbound`](Self::install_outbound) for the rationale.
    pub fn install_inbound(
        &mut self,
        cipher: SshCipher,
        mac: Option<Box<dyn SshMac + Send + Sync>>,
    ) -> Result<()> {
        self.inbound = classify(cipher, mac)?;
        self.pending_first_block = None;
        Ok(())
    }

    /// Reset both sequence counters to zero. Used by the strict-kex
    /// (Terrapin / CVE-2023-48795) mitigation at NEWKEYS: the OpenSSH
    /// `PROTOCOL` document and commit `1edb00c58` specify that when strict
    /// KEX is enabled, `seq_in` and `seq_out` are reset to 0 right after
    /// the NEWKEYS exchange — this prevents an attacker from manipulating
    /// the sequence-counter state via injected packets during KEX.
    pub fn reset_sequence_numbers(&mut self) {
        self.seq_in = 0;
        self.seq_out = 0;
    }

    /// Reset the outbound sequence counter only. Strict-kex direction-
    /// specific reset: called right after this side sends NEWKEYS.
    pub fn reset_outbound_sequence(&mut self) {
        self.seq_out = 0;
    }

    /// Reset the inbound sequence counter only. Strict-kex direction-
    /// specific reset: called right after this side receives peer NEWKEYS.
    pub fn reset_inbound_sequence(&mut self) {
        self.seq_in = 0;
    }

    /// Install the outbound compression channel for this direction. The KEX
    /// runner calls this alongside [`install_outbound`](Self::install_outbound)
    /// after NEWKEYS. Callers who never invoke this leave the codec on the
    /// default `"none"` pass-through.
    ///
    /// Compression dictionaries are stateful, so re-installing the same
    /// algorithm after a re-KEX would discard the shared dictionary the peer
    /// relies on. This method therefore leaves the channel untouched when the
    /// algorithm name matches the one already installed.
    pub fn install_outbound_compress(&mut self, c: Box<dyn Compress>) {
        if self.outbound_compress.name() == c.name() {
            return;
        }
        self.outbound_compress = c;
    }

    /// Install the inbound decompression channel; counterpart to
    /// [`install_outbound_compress`](Self::install_outbound_compress).
    pub fn install_inbound_decompress(&mut self, d: Box<dyn Decompress>) {
        if self.inbound_decompress.name() == d.name() {
            return;
        }
        self.inbound_decompress = d;
    }

    /// Activate compression on both sides. For `"zlib"` and `"none"` this is
    /// a no-op; for `"zlib@openssh.com"` it starts the persistent DEFLATE
    /// stream after the auth layer reports `SSH_MSG_USERAUTH_SUCCESS`.
    pub fn activate_compress(&mut self) {
        self.outbound_compress.activate();
        self.inbound_decompress.activate();
    }

    /// Algorithm name currently in use for the outbound compression channel.
    pub fn outbound_compress_name(&self) -> &'static str {
        self.outbound_compress.name()
    }

    /// Algorithm name currently in use for the inbound decompression channel.
    pub fn inbound_decompress_name(&self) -> &'static str {
        self.inbound_decompress.name()
    }

    /// Encrypt `payload` into a complete on-wire frame.
    pub fn encode<R: CryptoRng + RngCore>(
        &mut self,
        payload: &[u8],
        rng: &mut R,
    ) -> Result<Vec<u8>> {
        // Compression runs ahead of the codec: dictionaries persist across
        // re-KEXes, and the encrypted/MACed bytes we hand back are the
        // compressed body (RFC 4253 §6.2).
        let compressed;
        let to_frame: &[u8] =
            if self.outbound_compress.active() && self.outbound_compress.name() != "none" {
                compressed = self.outbound_compress.compress(payload)?;
                &compressed
            } else {
                payload
            };
        let frame = match &mut self.outbound {
            CipherSlot::None => encode_cleartext(to_frame, rng)?,
            CipherSlot::Stream { cipher, mac } => {
                encode_stream(self.seq_out, to_frame, rng, cipher, mac.as_ref())?
            }
            CipherSlot::Gcm(cipher) => encode_gcm(to_frame, rng, cipher)?,
            CipherSlot::ChaChaPoly(cipher) => {
                encode_chachapoly(self.seq_out, to_frame, rng, cipher)?
            }
        };
        self.seq_out = self.seq_out.wrapping_add(1);
        self.bytes_out = self.bytes_out.saturating_add(frame.len() as u64);
        Ok(frame)
    }

    /// Try to decode the next packet out of `buf`. Returns `Ok(Some((payload,
    /// consumed)))` when a full packet is available, `Ok(None)` if more
    /// bytes are required, and `Err` on protocol or authentication failure.
    pub fn decode(&mut self, buf: &[u8]) -> Result<Option<(Vec<u8>, usize)>> {
        let r = match &mut self.inbound {
            CipherSlot::None => decode_cleartext(buf),
            CipherSlot::Stream { cipher, mac } => decode_stream(
                self.seq_in,
                buf,
                cipher,
                mac.as_ref(),
                &mut self.pending_first_block,
            ),
            CipherSlot::Gcm(cipher) => decode_gcm(buf, cipher),
            CipherSlot::ChaChaPoly(cipher) => decode_chachapoly(self.seq_in, buf, cipher),
        }?;
        if let Some((payload, consumed)) = r {
            self.seq_in = self.seq_in.wrapping_add(1);
            self.bytes_in = self.bytes_in.saturating_add(consumed as u64);
            let payload =
                if self.inbound_decompress.active() && self.inbound_decompress.name() != "none" {
                    self.inbound_decompress.decompress(&payload)?
                } else {
                    payload
                };
            Ok(Some((payload, consumed)))
        } else {
            Ok(None)
        }
    }
}

/// Upper bound on the SSH payload length we ever attempt to encode. The
/// guard is conservative: it leaves room (~256 bytes) for header, padding,
/// MAC/tag and any compression-side overhead so the encoder's arithmetic
/// stays in u32/u64 range and we fail cleanly instead of wrapping or
/// panicking on absurd input.
const MAX_ENCODABLE_PAYLOAD: usize = (MAX_PACKET_LEN as usize).saturating_sub(256);

/// Returns `true` if `payload_len` is small enough that the encoder won't
/// overflow when adding header, padding and MAC.
fn payload_within_limit(payload_len: usize) -> bool {
    payload_len < MAX_ENCODABLE_PAYLOAD
}

fn padding_for(payload_len: usize, block_size: usize, encrypts_length: bool) -> usize {
    // Bound the input so the arithmetic below stays in usize.
    debug_assert!(payload_within_limit(payload_len));
    let bs = block_size.max(8);
    let unit = if encrypts_length {
        4 + 1 + payload_len
    } else {
        1 + payload_len
    };
    let rem = unit % bs;
    let mut pad = bs - rem;
    if pad < 4 {
        pad += bs;
    }
    // RFC 4253 §6's "total >= 16" applies only when the length field is part
    // of the encrypted/aligned block. For AEAD suites (AES-GCM and
    // chacha20-poly1305@openssh.com) the length sits outside the block and
    // OpenSSH only requires `body` to be block-aligned — packets as small as
    // 12 bytes on the wire (length=8) are legal.
    if encrypts_length {
        while 4 + 1 + payload_len + pad < MIN_TOTAL_LEN {
            pad += bs;
        }
    }
    pad
}

fn fill_padding<R: CryptoRng + RngCore>(rng: &mut R, out: &mut [u8]) {
    rng.fill_bytes(out);
}

#[cfg(feature = "alloc")]
fn encode_cleartext<R: CryptoRng + RngCore>(payload: &[u8], rng: &mut R) -> Result<Vec<u8>> {
    if !payload_within_limit(payload.len()) {
        return Err(Error::Protocol("payload exceeds encoder limit"));
    }
    let pad = padding_for(payload.len(), BLOCK_SIZE_DEFAULT, true);
    let packet_length = 1 + payload.len() + pad;
    if packet_length + 4 < MIN_TOTAL_LEN {
        return Err(Error::Protocol("packet too short"));
    }
    let mut frame = Vec::with_capacity(4 + packet_length);
    frame.extend_from_slice(&(packet_length as u32).to_be_bytes());
    frame.push(pad as u8);
    frame.extend_from_slice(payload);
    let pad_start = frame.len();
    frame.resize(pad_start + pad, 0);
    fill_padding(rng, &mut frame[pad_start..]);
    Ok(frame)
}

#[cfg(feature = "alloc")]
fn decode_cleartext(buf: &[u8]) -> Result<Option<(Vec<u8>, usize)>> {
    if buf.len() < 5 {
        return Ok(None);
    }
    let packet_length = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
    if packet_length > MAX_PACKET_LEN {
        return Err(Error::Protocol("packet length exceeds limit"));
    }
    let total = 4 + packet_length as usize;
    if total < MIN_TOTAL_LEN {
        return Err(Error::Protocol("packet too short"));
    }
    if !(packet_length + 4).is_multiple_of(BLOCK_SIZE_DEFAULT as u32) {
        return Err(Error::Protocol("packet length not block-aligned"));
    }
    if buf.len() < total {
        return Ok(None);
    }
    let pad_len = buf[4] as usize;
    if !(4..=255).contains(&pad_len) {
        return Err(Error::BadPadding);
    }
    let payload_end = 4 + packet_length as usize - pad_len;
    if payload_end < 5 {
        return Err(Error::BadPadding);
    }
    let payload = buf[5..payload_end].to_vec();
    Ok(Some((payload, total)))
}

#[cfg(feature = "alloc")]
fn encode_stream<R: CryptoRng + RngCore>(
    seq: u32,
    payload: &[u8],
    rng: &mut R,
    cipher: &mut SshCipher,
    mac: &dyn SshMac,
) -> Result<Vec<u8>> {
    if !payload_within_limit(payload.len()) {
        return Err(Error::Protocol("payload exceeds encoder limit"));
    }
    let block_size = 16usize;
    let etm = mac.etm();
    let pad = padding_for(payload.len(), block_size, !etm);
    let packet_length = 1 + payload.len() + pad;
    if packet_length + 4 < MIN_TOTAL_LEN {
        return Err(Error::Protocol("packet too short"));
    }

    let mut frame = Vec::with_capacity(4 + packet_length + mac.tag_len());
    frame.extend_from_slice(&(packet_length as u32).to_be_bytes());
    frame.push(pad as u8);
    frame.extend_from_slice(payload);
    let pad_start = frame.len();
    frame.resize(pad_start + pad, 0);
    fill_padding(rng, &mut frame[pad_start..]);

    let tag_len = mac.tag_len();
    let mac_input_end = frame.len();

    if etm {
        cipher.stream(&mut frame[4..mac_input_end])?;
        let mut tag = vec![0u8; tag_len];
        mac.compute(seq, &frame[..mac_input_end], &mut tag)?;
        frame.extend_from_slice(&tag);
    } else {
        let mut tag = vec![0u8; tag_len];
        mac.compute(seq, &frame[..mac_input_end], &mut tag)?;
        cipher.stream(&mut frame[..mac_input_end])?;
        frame.extend_from_slice(&tag);
    }

    Ok(frame)
}

#[cfg(feature = "alloc")]
fn decode_stream(
    seq: u32,
    buf: &[u8],
    cipher: &mut SshCipher,
    mac: &dyn SshMac,
    pending: &mut Option<Vec<u8>>,
) -> Result<Option<(Vec<u8>, usize)>> {
    let block_size = 16usize;
    let tag_len = mac.tag_len();
    let etm = mac.etm();

    if etm {
        if buf.len() < 4 {
            return Ok(None);
        }
        let packet_length = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
        if packet_length > MAX_PACKET_LEN {
            return Err(Error::Protocol("packet length exceeds limit"));
        }
        let body_len = packet_length as usize;
        if !(body_len).is_multiple_of(block_size) {
            return Err(Error::Protocol("packet body not block-aligned"));
        }
        let total = 4 + body_len + tag_len;
        if 4 + body_len < MIN_TOTAL_LEN {
            return Err(Error::Protocol("packet too short"));
        }
        if buf.len() < total {
            return Ok(None);
        }
        let mac_input = &buf[..4 + body_len];
        let tag = &buf[4 + body_len..total];
        mac.verify(seq, mac_input, tag)?;
        let mut body = buf[4..4 + body_len].to_vec();
        cipher.stream(&mut body)?;
        let pad_len = body[0] as usize;
        if !(4..=255).contains(&pad_len) {
            return Err(Error::BadPadding);
        }
        if pad_len + 1 > body.len() {
            return Err(Error::BadPadding);
        }
        let payload = body[1..body.len() - pad_len].to_vec();
        return Ok(Some((payload, total)));
    }

    if buf.len() < block_size {
        return Ok(None);
    }
    let first_block = match pending.take() {
        Some(b) => b,
        None => {
            let mut b = buf[..block_size].to_vec();
            cipher.stream(&mut b)?;
            b
        }
    };
    let packet_length = u32::from_be_bytes([
        first_block[0],
        first_block[1],
        first_block[2],
        first_block[3],
    ]);
    if packet_length > MAX_PACKET_LEN {
        return Err(Error::Protocol("packet length exceeds limit"));
    }
    let body_len = packet_length as usize;
    if !(4 + body_len).is_multiple_of(block_size) {
        return Err(Error::Protocol("packet not block-aligned"));
    }
    if 4 + body_len < MIN_TOTAL_LEN {
        return Err(Error::Protocol("packet too short"));
    }
    let total = 4 + body_len + tag_len;
    if buf.len() < total {
        *pending = Some(first_block);
        return Ok(None);
    }

    let mut plain = Vec::with_capacity(4 + body_len);
    plain.extend_from_slice(&first_block);
    if 4 + body_len > block_size {
        let mut rest = buf[block_size..4 + body_len].to_vec();
        cipher.stream(&mut rest)?;
        plain.extend_from_slice(&rest);
    }

    let tag = &buf[4 + body_len..total];
    mac.verify(seq, &plain, tag)?;

    let pad_len = plain[4] as usize;
    if !(4..=255).contains(&pad_len) {
        return Err(Error::BadPadding);
    }
    if 5 + pad_len > plain.len() {
        return Err(Error::BadPadding);
    }
    let payload = plain[5..plain.len() - pad_len].to_vec();
    Ok(Some((payload, total)))
}

#[cfg(feature = "alloc")]
fn encode_gcm<R: CryptoRng + RngCore>(
    payload: &[u8],
    rng: &mut R,
    cipher: &mut SshCipher,
) -> Result<Vec<u8>> {
    if !payload_within_limit(payload.len()) {
        return Err(Error::Protocol("payload exceeds encoder limit"));
    }
    let block_size = 16usize;
    let pad = padding_for(payload.len(), block_size, false);
    let packet_length = 1 + payload.len() + pad;

    let mut frame = Vec::with_capacity(4 + packet_length + 16);
    frame.extend_from_slice(&(packet_length as u32).to_be_bytes());
    frame.push(pad as u8);
    frame.extend_from_slice(payload);
    let pad_start = frame.len();
    frame.resize(pad_start + pad, 0);
    fill_padding(rng, &mut frame[pad_start..]);

    let length_field = [frame[0], frame[1], frame[2], frame[3]];
    let tag = cipher.aead_seal_len_aad(&length_field, &mut frame[4..])?;
    frame.extend_from_slice(&tag);
    Ok(frame)
}

#[cfg(feature = "alloc")]
fn decode_gcm(buf: &[u8], cipher: &mut SshCipher) -> Result<Option<(Vec<u8>, usize)>> {
    if buf.len() < 4 {
        return Ok(None);
    }
    let packet_length = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
    if packet_length > MAX_PACKET_LEN {
        return Err(Error::Protocol("packet length exceeds limit"));
    }
    let body_len = packet_length as usize;
    if !body_len.is_multiple_of(16) {
        return Err(Error::Protocol("packet body not block-aligned"));
    }
    if body_len < 16 {
        return Err(Error::Protocol("packet too short"));
    }
    let total = 4 + body_len + 16;
    if buf.len() < total {
        return Ok(None);
    }
    let length_field = [buf[0], buf[1], buf[2], buf[3]];
    let mut body = buf[4..4 + body_len].to_vec();
    let tag = &buf[4 + body_len..total];
    cipher.aead_open_len_aad(&length_field, &mut body, tag)?;
    let pad_len = body[0] as usize;
    if !(4..=255).contains(&pad_len) {
        return Err(Error::BadPadding);
    }
    if pad_len + 1 > body.len() {
        return Err(Error::BadPadding);
    }
    let payload = body[1..body.len() - pad_len].to_vec();
    Ok(Some((payload, total)))
}

#[cfg(feature = "alloc")]
fn encode_chachapoly<R: CryptoRng + RngCore>(
    seq: u32,
    payload: &[u8],
    rng: &mut R,
    cipher: &mut SshCipher,
) -> Result<Vec<u8>> {
    if !payload_within_limit(payload.len()) {
        return Err(Error::Protocol("payload exceeds encoder limit"));
    }
    let block_size = 8usize;
    let pad = padding_for(payload.len(), block_size, false);
    let packet_length = 1 + payload.len() + pad;

    let seq64 = seq as u64;
    let mut frame = Vec::with_capacity(4 + packet_length + 16);
    frame.extend_from_slice(&(packet_length as u32).to_be_bytes());
    frame.push(pad as u8);
    frame.extend_from_slice(payload);
    let pad_start = frame.len();
    frame.resize(pad_start + pad, 0);
    fill_padding(rng, &mut frame[pad_start..]);

    cipher.cp_xor_length(seq64, &mut frame[..4])?;
    cipher.cp_xor_payload(seq64, &mut frame[4..])?;
    let (len_part, body_part) = frame.split_at(4);
    let tag = cipher.cp_tag(seq64, len_part, body_part)?;
    frame.extend_from_slice(&tag);
    Ok(frame)
}

#[cfg(feature = "alloc")]
fn decode_chachapoly(
    seq: u32,
    buf: &[u8],
    cipher: &mut SshCipher,
) -> Result<Option<(Vec<u8>, usize)>> {
    if buf.len() < 4 {
        return Ok(None);
    }
    let seq64 = seq as u64;
    let mut enc_len = [buf[0], buf[1], buf[2], buf[3]];
    cipher.cp_xor_length(seq64, &mut enc_len)?;
    let packet_length = u32::from_be_bytes(enc_len);
    if packet_length > MAX_PACKET_LEN {
        return Err(Error::Protocol("packet length exceeds limit"));
    }
    let body_len = packet_length as usize;
    if !body_len.is_multiple_of(8) {
        return Err(Error::Protocol("packet body not block-aligned"));
    }
    if body_len < 8 {
        return Err(Error::Protocol("packet too short"));
    }
    let total = 4 + body_len + 16;
    if buf.len() < total {
        return Ok(None);
    }
    let enc_len_wire = &buf[..4];
    let enc_payload = &buf[4..4 + body_len];
    let tag = &buf[4 + body_len..total];
    cipher.cp_verify_tag(seq64, enc_len_wire, enc_payload, tag)?;
    let mut body = enc_payload.to_vec();
    cipher.cp_xor_payload(seq64, &mut body)?;
    let pad_len = body[0] as usize;
    if !(4..=255).contains(&pad_len) {
        return Err(Error::BadPadding);
    }
    if pad_len + 1 > body.len() {
        return Err(Error::BadPadding);
    }
    let payload = body[1..body.len() - pad_len].to_vec();
    Ok(Some((payload, total)))
}

#[cfg(all(test, feature = "alloc"))]
mod tests {
    use super::*;
    use crate::cipher::cipher_by_name;
    use crate::mac::mac_by_name;
    use purecrypto::rng::OsRng;

    fn round_trip(enc: &mut PacketCodec, dec: &mut PacketCodec, payload: &[u8]) {
        let mut rng = OsRng;
        let frame = enc.encode(payload, &mut rng).unwrap();
        let (got, consumed) = dec.decode(&frame).unwrap().expect("full frame");
        assert_eq!(consumed, frame.len());
        assert_eq!(got, payload);
    }

    #[test]
    fn cleartext_roundtrip_various_lengths() {
        let mut enc = PacketCodec::new();
        let mut dec = PacketCodec::new();
        for len in [0usize, 1, 5, 8, 15, 16, 17, 64, 255, 1024] {
            let payload: Vec<u8> = (0..len).map(|i| (i & 0xff) as u8).collect();
            round_trip(&mut enc, &mut dec, &payload);
        }
        assert_eq!(enc.seq_out, 10);
        assert_eq!(dec.seq_in, 10);
    }

    fn install_ctr(codec_out: &mut PacketCodec, codec_in: &mut PacketCodec, etm: bool) {
        let key = [0x11u8; 32];
        let iv = [0x22u8; 16];
        let mac_name = if etm {
            "hmac-sha2-256-etm@openssh.com"
        } else {
            "hmac-sha2-256"
        };
        let mac_key = [0x55u8; 32];
        let out_cipher = cipher_by_name("aes256-ctr", &key, &iv).unwrap().unwrap();
        let in_cipher = cipher_by_name("aes256-ctr", &key, &iv).unwrap().unwrap();
        let out_mac = mac_by_name(mac_name, &mac_key).unwrap();
        let in_mac = mac_by_name(mac_name, &mac_key).unwrap();
        codec_out
            .install_outbound(out_cipher, Some(out_mac))
            .unwrap();
        codec_in.install_inbound(in_cipher, Some(in_mac)).unwrap();
    }

    #[test]
    fn ctr_eam_roundtrip() {
        let mut a = PacketCodec::new();
        let mut b = PacketCodec::new();
        install_ctr(&mut a, &mut b, false);
        for n in [0usize, 1, 16, 100, 500, 4096] {
            let payload: Vec<u8> = (0..n).map(|i| ((i * 7) & 0xff) as u8).collect();
            round_trip(&mut a, &mut b, &payload);
        }
    }

    #[test]
    fn ctr_etm_roundtrip() {
        let mut a = PacketCodec::new();
        let mut b = PacketCodec::new();
        install_ctr(&mut a, &mut b, true);
        for n in [0usize, 1, 16, 100, 500, 4096] {
            let payload: Vec<u8> = (0..n).map(|i| ((i * 13) & 0xff) as u8).collect();
            round_trip(&mut a, &mut b, &payload);
        }
    }

    fn install_gcm(codec_out: &mut PacketCodec, codec_in: &mut PacketCodec) {
        let key = [0xaau8; 16];
        let iv = [0xbbu8; 12];
        let oc = cipher_by_name("aes128-gcm@openssh.com", &key, &iv)
            .unwrap()
            .unwrap();
        let ic = cipher_by_name("aes128-gcm@openssh.com", &key, &iv)
            .unwrap()
            .unwrap();
        codec_out.install_outbound(oc, None).unwrap();
        codec_in.install_inbound(ic, None).unwrap();
    }

    #[test]
    fn gcm_roundtrip() {
        let mut a = PacketCodec::new();
        let mut b = PacketCodec::new();
        install_gcm(&mut a, &mut b);
        for n in [0usize, 1, 16, 100, 500, 4096] {
            let payload: Vec<u8> = (0..n).map(|i| ((i * 5) & 0xff) as u8).collect();
            round_trip(&mut a, &mut b, &payload);
        }
    }

    fn install_chachapoly(codec_out: &mut PacketCodec, codec_in: &mut PacketCodec) {
        let key = [0x77u8; 64];
        let oc = cipher_by_name("chacha20-poly1305@openssh.com", &key, &[])
            .unwrap()
            .unwrap();
        let ic = cipher_by_name("chacha20-poly1305@openssh.com", &key, &[])
            .unwrap()
            .unwrap();
        codec_out.install_outbound(oc, None).unwrap();
        codec_in.install_inbound(ic, None).unwrap();
    }

    #[test]
    fn chachapoly_roundtrip_with_seq_advance() {
        let mut a = PacketCodec::new();
        let mut b = PacketCodec::new();
        install_chachapoly(&mut a, &mut b);
        a.seq_out = 42;
        b.seq_in = 42;
        for n in [0usize, 1, 32, 200, 4096] {
            let payload: Vec<u8> = (0..n).map(|i| ((i ^ 0xa5) & 0xff) as u8).collect();
            round_trip(&mut a, &mut b, &payload);
        }
        assert_eq!(a.seq_out, 47);
        assert_eq!(b.seq_in, 47);
    }

    #[test]
    fn many_packets_seq_counters_match() {
        let mut a = PacketCodec::new();
        let mut b = PacketCodec::new();
        install_ctr(&mut a, &mut b, true);
        let mut rng = OsRng;
        let mut wire: Vec<u8> = Vec::new();
        for i in 0..32u32 {
            let payload = vec![i as u8; (i as usize) * 3 + 7];
            wire.extend_from_slice(&a.encode(&payload, &mut rng).unwrap());
        }
        assert_eq!(a.seq_out, 32);
        let mut pos = 0;
        for i in 0..32u32 {
            let (got, consumed) = b.decode(&wire[pos..]).unwrap().expect("frame");
            pos += consumed;
            let expect = vec![i as u8; (i as usize) * 3 + 7];
            assert_eq!(got, expect);
        }
        assert_eq!(b.seq_in, 32);
        assert_eq!(pos, wire.len());
    }

    #[test]
    fn corrupt_ctr_eam_mac_rejected() {
        let mut a = PacketCodec::new();
        let mut b = PacketCodec::new();
        install_ctr(&mut a, &mut b, false);
        let mut rng = OsRng;
        let mut frame = a.encode(b"hello world", &mut rng).unwrap();
        let n = frame.len();
        frame[n - 1] ^= 0x01;
        assert!(matches!(b.decode(&frame), Err(Error::BadMac)));
    }

    #[test]
    fn corrupt_ctr_etm_mac_rejected() {
        let mut a = PacketCodec::new();
        let mut b = PacketCodec::new();
        install_ctr(&mut a, &mut b, true);
        let mut rng = OsRng;
        let mut frame = a.encode(b"hello world", &mut rng).unwrap();
        let n = frame.len();
        frame[n - 1] ^= 0x80;
        assert!(matches!(b.decode(&frame), Err(Error::BadMac)));
    }

    #[test]
    fn corrupt_gcm_tag_rejected() {
        let mut a = PacketCodec::new();
        let mut b = PacketCodec::new();
        install_gcm(&mut a, &mut b);
        let mut rng = OsRng;
        let mut frame = a.encode(b"gcm-data", &mut rng).unwrap();
        let n = frame.len();
        frame[n - 1] ^= 0x01;
        assert!(matches!(b.decode(&frame), Err(Error::BadTag)));
    }

    #[test]
    fn corrupt_chachapoly_tag_rejected() {
        let mut a = PacketCodec::new();
        let mut b = PacketCodec::new();
        install_chachapoly(&mut a, &mut b);
        let mut rng = OsRng;
        let mut frame = a.encode(b"chacha-data", &mut rng).unwrap();
        let n = frame.len();
        frame[n - 1] ^= 0x01;
        assert!(matches!(b.decode(&frame), Err(Error::BadTag)));
    }

    #[test]
    fn padding_under_four_rejected() {
        // packet_length = 12, padding_length = 3 (< 4). Total = 16 bytes,
        // (packet_length + 4) = 16 is a multiple of 8.
        let mut frame = Vec::new();
        frame.extend_from_slice(&12u32.to_be_bytes());
        frame.push(3u8);
        frame.extend_from_slice(&[0u8; 8]);
        frame.extend_from_slice(&[0u8; 3]);
        let mut codec = PacketCodec::new();
        assert!(matches!(codec.decode(&frame), Err(Error::BadPadding)));
    }

    #[test]
    fn install_outbound_returns_err_for_missing_mac_on_non_aead() {
        let key = [0x11u8; 32];
        let iv = [0x22u8; 16];
        let cipher = cipher_by_name("aes256-ctr", &key, &iv).unwrap().unwrap();
        let mut codec = PacketCodec::new();
        let res = codec.install_outbound(cipher, None);
        match res {
            Err(Error::Protocol(_)) => {}
            other => panic!("expected Protocol error, got {other:?}"),
        }
    }

    #[test]
    fn encode_rejects_oversized_payload() {
        // Larger than MAX_ENCODABLE_PAYLOAD (~MAX_PACKET_LEN - 256).
        let payload = vec![0u8; MAX_PACKET_LEN as usize];
        let mut codec = PacketCodec::new();
        let mut rng = OsRng;
        let err = codec.encode(&payload, &mut rng).unwrap_err();
        match err {
            Error::Protocol(msg) => assert_eq!(msg, "payload exceeds encoder limit"),
            other => panic!("expected Protocol, got {other:?}"),
        }
    }

    #[test]
    fn packet_length_cap_enforced() {
        let mut frame = Vec::new();
        frame.extend_from_slice(&100_000u32.to_be_bytes());
        frame.push(8u8);
        frame.extend_from_slice(&[0u8; 8]);
        let mut codec = PacketCodec::new();
        assert!(matches!(codec.decode(&frame), Err(Error::Protocol(_))));
    }

    #[test]
    fn decode_partial_returns_none() {
        let mut a = PacketCodec::new();
        let mut b = PacketCodec::new();
        install_ctr(&mut a, &mut b, false);
        let mut rng = OsRng;
        let frame = a.encode(b"some payload", &mut rng).unwrap();
        for cut in 1..frame.len() {
            let r = b.decode(&frame[..cut]).unwrap();
            assert!(r.is_none(), "expected None at cut={}", cut);
        }
        let (got, consumed) = b.decode(&frame).unwrap().expect("full");
        assert_eq!(consumed, frame.len());
        assert_eq!(got, b"some payload");
    }

    #[test]
    fn byte_counters_track_wire_size() {
        let mut a = PacketCodec::new();
        let mut b = PacketCodec::new();
        install_ctr(&mut a, &mut b, true);
        let mut rng = OsRng;
        let mut wire_total = 0u64;
        for n in [16usize, 100, 1024] {
            let payload: Vec<u8> = (0..n).map(|i| (i & 0xff) as u8).collect();
            let frame = a.encode(&payload, &mut rng).unwrap();
            wire_total += frame.len() as u64;
            let (_, consumed) = b.decode(&frame).unwrap().expect("full frame");
            assert_eq!(consumed, frame.len());
        }
        assert_eq!(a.bytes_out, wire_total);
        assert_eq!(b.bytes_in, wire_total);
    }

    #[cfg(feature = "compress")]
    #[test]
    fn zlib_roundtrip_through_codec() {
        use crate::compress::{compress_by_name, decompress_by_name};

        let mut a = PacketCodec::new();
        let mut b = PacketCodec::new();
        install_chachapoly(&mut a, &mut b);
        a.install_outbound_compress(compress_by_name("zlib").unwrap());
        b.install_inbound_decompress(decompress_by_name("zlib").unwrap());

        let mut rng = OsRng;
        // A highly-compressible payload to confirm compression really ran.
        let payload = vec![b'a'; 4096];
        let frame = a.encode(&payload, &mut rng).unwrap();
        assert!(
            frame.len() < payload.len(),
            "frame {} should be smaller than payload {}",
            frame.len(),
            payload.len()
        );
        let (got, consumed) = b.decode(&frame).unwrap().expect("full frame");
        assert_eq!(consumed, frame.len());
        assert_eq!(got, payload);
    }

    #[cfg(feature = "compress")]
    #[test]
    fn zlib_openssh_delayed_activation_through_codec() {
        use crate::compress::{compress_by_name, decompress_by_name};

        let mut a = PacketCodec::new();
        let mut b = PacketCodec::new();
        install_chachapoly(&mut a, &mut b);
        a.install_outbound_compress(compress_by_name("zlib@openssh.com").unwrap());
        b.install_inbound_decompress(decompress_by_name("zlib@openssh.com").unwrap());

        // Pre-activation: pass-through (matches what the codec must do during
        // the userauth phase for `zlib@openssh.com`).
        let mut rng = OsRng;
        let pre = vec![b'x'; 64];
        let frame_pre = a.encode(&pre, &mut rng).unwrap();
        let (got_pre, _) = b.decode(&frame_pre).unwrap().expect("pre");
        assert_eq!(got_pre, pre);

        // Activate both sides and re-test with a compressible payload.
        a.activate_compress();
        b.activate_compress();
        let post = vec![b'y'; 4096];
        let frame_post = a.encode(&post, &mut rng).unwrap();
        assert!(frame_post.len() < post.len());
        let (got_post, _) = b.decode(&frame_post).unwrap().expect("post");
        assert_eq!(got_post, post);
    }

    #[cfg(feature = "compress")]
    #[test]
    fn install_same_compression_keeps_dictionary() {
        use crate::compress::{compress_by_name, decompress_by_name};

        // After the first KEX installed "zlib", a re-KEX re-installs the same
        // algorithm — we must NOT discard the dictionary that the peer has
        // built up. install_outbound_compress is a no-op when the algorithm
        // name matches; the same goes for the inbound side.
        let mut a = PacketCodec::new();
        let mut b = PacketCodec::new();
        install_chachapoly(&mut a, &mut b);
        a.install_outbound_compress(compress_by_name("zlib").unwrap());
        b.install_inbound_decompress(decompress_by_name("zlib").unwrap());
        let mut rng = OsRng;
        let payload = vec![b'q'; 4096];
        let f1 = a.encode(&payload, &mut rng).unwrap();
        let (got1, _) = b.decode(&f1).unwrap().expect("frame 1");
        assert_eq!(got1, payload);
        // Re-install both sides — same name, dictionaries must survive.
        a.install_outbound_compress(compress_by_name("zlib").unwrap());
        b.install_inbound_decompress(decompress_by_name("zlib").unwrap());
        let f2 = a.encode(&payload, &mut rng).unwrap();
        let (got2, _) = b.decode(&f2).unwrap().expect("frame 2 (dict survived)");
        assert_eq!(got2, payload);
        // The shared dictionary means the second frame is at least as small
        // as the first — the second compression draws on the prior content.
        assert!(f2.len() <= f1.len());
    }
}
