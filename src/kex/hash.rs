//! Exchange-hash builder and RFC 4253 §7.2 key derivation.

use alloc::vec::Vec;

use purecrypto::hash::Digest;
use zeroize::{Zeroize, Zeroizing};

/// Builder for the SSH key-exchange "exchange hash" `H`.
///
/// Per RFC 4253 §8 and the algorithm-specific RFCs (5656 §4, 8731 §4,
/// 4419 §3, 8268 §2), `H` is the digest of a concatenation of length-prefixed
/// fields. Strings (`V_C`, `V_S`, `I_C`, `I_S`, `K_S`, ECDH `Q_C`/`Q_S`) and
/// integers (`e`, `f`, `K`) all encode as a `uint32` length followed by their
/// bytes — but `string`s carry their raw payload, whereas `mpint`s strip
/// leading zeros and prepend `0x00` when the magnitude's MSB is set.
pub struct ExchangeHash<D: Digest> {
    hasher: D,
}

impl<D: Digest> Default for ExchangeHash<D> {
    fn default() -> Self {
        Self::new()
    }
}

impl<D: Digest> ExchangeHash<D> {
    /// Start a new exchange-hash builder.
    pub fn new() -> Self {
        ExchangeHash { hasher: D::new() }
    }

    /// Append an SSH `string`: a 4-byte big-endian length followed by `s`.
    pub fn write_string(&mut self, s: &[u8]) {
        let len = s.len() as u32;
        self.hasher.update(&len.to_be_bytes());
        self.hasher.update(s);
    }

    /// Append a raw `uint32`.
    pub fn write_u32(&mut self, v: u32) {
        self.hasher.update(&v.to_be_bytes());
    }

    /// Append an unsigned magnitude encoded as an SSH `mpint`.
    ///
    /// Leading zeros are stripped; a `0x00` sign byte is prepended if the
    /// resulting MSB is set. The empty magnitude encodes as a zero-length
    /// string (the canonical SSH encoding of zero).
    pub fn write_mpint(&mut self, magnitude: &[u8]) {
        let mut start = 0usize;
        while start < magnitude.len() && magnitude[start] == 0 {
            start += 1;
        }
        let m = &magnitude[start..];
        if m.is_empty() {
            self.write_u32(0);
            return;
        }
        if m[0] & 0x80 != 0 {
            self.write_u32((m.len() + 1) as u32);
            self.hasher.update(&[0u8]);
            self.hasher.update(m);
        } else {
            self.write_u32(m.len() as u32);
            self.hasher.update(m);
        }
    }

    /// Append raw bytes with no length prefix.
    pub fn write_raw(&mut self, b: &[u8]) {
        self.hasher.update(b);
    }

    /// Finish and return the digest as a `Vec<u8>` of length `D::OUTPUT_LEN`.
    pub fn finalize(self) -> Vec<u8> {
        let out = self.hasher.finalize();
        out.as_ref().to_vec()
    }
}

/// Encode an unsigned magnitude as an SSH `mpint` byte string (length-prefixed).
///
/// Used to materialise `K` for the KDF input, where `K` is fed as an
/// `mpint` (length prefix included).
pub fn mpint_bytes(magnitude: &[u8]) -> Vec<u8> {
    let mut start = 0usize;
    while start < magnitude.len() && magnitude[start] == 0 {
        start += 1;
    }
    let m = &magnitude[start..];
    let mut out = Vec::with_capacity(4 + m.len() + 1);
    if m.is_empty() {
        out.extend_from_slice(&0u32.to_be_bytes());
        return out;
    }
    if m[0] & 0x80 != 0 {
        out.extend_from_slice(&((m.len() + 1) as u32).to_be_bytes());
        out.push(0);
        out.extend_from_slice(m);
    } else {
        out.extend_from_slice(&(m.len() as u32).to_be_bytes());
        out.extend_from_slice(m);
    }
    out
}

/// RFC 4253 §7.2 key derivation.
///
/// `k_mpint` is `K` already encoded as an SSH `mpint` (length-prefixed,
/// two's-complement). `h` is the current exchange hash. `session_id` is the
/// exchange hash from the first KEX of the connection (equal to `h` on the
/// initial exchange). `letter` is one of `b'A'..=b'F'` selecting which of the
/// six derived values to compute:
///
/// * `A` — initial IV, client to server
/// * `B` — initial IV, server to client
/// * `C` — encryption key, client to server
/// * `D` — encryption key, server to client
/// * `E` — integrity key, client to server
/// * `F` — integrity key, server to client
///
/// The construction iterates `K1 = HASH(K || H || letter || session_id)` and
/// `K_{n+1} = HASH(K || H || K_1 || ... || K_n)` until at least `out_len`
/// bytes have been produced, then truncates.
pub fn derive<D: Digest>(
    k_mpint: &[u8],
    h: &[u8],
    session_id: &[u8],
    letter: u8,
    out_len: usize,
) -> Zeroizing<Vec<u8>> {
    let mut out: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::with_capacity(out_len));
    if out_len == 0 {
        return out;
    }
    let mut hasher = D::new();
    hasher.update(k_mpint);
    hasher.update(h);
    hasher.update(&[letter]);
    hasher.update(session_id);
    let first = hasher.finalize();
    out.extend_from_slice(first.as_ref());
    while out.len() < out_len {
        let mut h2 = D::new();
        h2.update(k_mpint);
        h2.update(h);
        h2.update(&out);
        let next = h2.finalize();
        out.extend_from_slice(next.as_ref());
    }
    // The final hash block usually over-produces; `Vec::truncate` drops the
    // excess length but leaves those key bytes in the backing buffer. Wipe the
    // tail explicitly before shrinking so no derived key material lingers.
    out[out_len..].zeroize();
    out.truncate(out_len);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use purecrypto::hash::Sha256;

    #[test]
    fn mpint_zero_is_empty_string() {
        let mut eh = ExchangeHash::<Sha256>::new();
        eh.write_mpint(&[]);
        let b = mpint_bytes(&[]);
        assert_eq!(b, &[0, 0, 0, 0]);
        let _ = eh.finalize();
    }

    #[test]
    fn mpint_strips_leading_zero() {
        let b = mpint_bytes(&[0, 0, 0x12, 0x34]);
        assert_eq!(b, &[0, 0, 0, 2, 0x12, 0x34]);
    }

    #[test]
    fn mpint_adds_sign_byte() {
        let b = mpint_bytes(&[0x80, 0x00]);
        assert_eq!(b, &[0, 0, 0, 3, 0x00, 0x80, 0x00]);
    }

    #[test]
    fn mpint_strips_then_adds_sign() {
        let b = mpint_bytes(&[0x00, 0xff, 0x01]);
        assert_eq!(b, &[0, 0, 0, 3, 0x00, 0xff, 0x01]);
    }

    #[test]
    fn derive_extends_past_one_block() {
        let k = mpint_bytes(&[1, 2, 3]);
        let h = [0xAAu8; 32];
        let sid = [0xBBu8; 32];
        let out = derive::<Sha256>(&k, &h, &sid, b'A', 80);
        assert_eq!(out.len(), 80);
        let mut h2 = derive::<Sha256>(&k, &h, &sid, b'A', 32);
        assert_eq!(&out[..32], &h2[..]);
        h2 = derive::<Sha256>(&k, &h, &sid, b'A', 64);
        assert_eq!(&out[..64], &h2[..]);
    }

    #[test]
    fn derive_letters_differ() {
        let k = mpint_bytes(&[7, 7]);
        let h = [0xCCu8; 32];
        let sid = h;
        let a = derive::<Sha256>(&k, &h, &sid, b'A', 32);
        let b = derive::<Sha256>(&k, &h, &sid, b'B', 32);
        assert_ne!(a, b);
    }
}
