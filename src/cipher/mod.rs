//! SSH cipher suite adapters over [`purecrypto::cipher`].
//!
//! Three families of suites are surfaced:
//!
//! - **`aes*-ctr`** (RFC 4344) — paired with a separate HMAC, possibly in EtM mode.
//! - **`aes*-gcm@openssh.com`** (RFC 5647) — AEAD with implicit 12-byte nonce.
//! - **`chacha20-poly1305@openssh.com`** — AEAD with two ChaCha20 keys (one
//!   for the length field, one for the payload) and a Poly1305 tag.

/// SSH-side identifier and key/iv/block geometry for a cipher suite.
#[derive(Debug, Clone, Copy)]
pub struct CipherSpec {
    /// On-the-wire SSH name (e.g. `"aes256-ctr"`).
    pub name: &'static str,
    /// Key length in bytes.
    pub key_len: usize,
    /// IV (or nonce) length in bytes — 16 for CTR, 12 for GCM, 8 for ChaCha20.
    pub iv_len: usize,
    /// Block size in bytes (for length-field rounding); 16 for AES, 8 for ChaCha20 stream.
    pub block_size: usize,
    /// Whether this suite is AEAD (integrity built in — no separate MAC).
    pub aead: bool,
    /// AEAD tag length in bytes (0 if non-AEAD).
    pub tag_len: usize,
}

/// Catalogue of suites this build supports.
pub const ALL: &[CipherSpec] = &[
    CipherSpec {
        name: "chacha20-poly1305@openssh.com",
        key_len: 64, // two 256-bit ChaCha20 keys
        iv_len: 0,   // sequence number is used as the nonce
        block_size: 8,
        aead: true,
        tag_len: 16,
    },
    CipherSpec {
        name: "aes256-gcm@openssh.com",
        key_len: 32,
        iv_len: 12,
        block_size: 16,
        aead: true,
        tag_len: 16,
    },
    CipherSpec {
        name: "aes128-gcm@openssh.com",
        key_len: 16,
        iv_len: 12,
        block_size: 16,
        aead: true,
        tag_len: 16,
    },
    CipherSpec {
        name: "aes256-ctr",
        key_len: 32,
        iv_len: 16,
        block_size: 16,
        aead: false,
        tag_len: 0,
    },
    CipherSpec {
        name: "aes192-ctr",
        key_len: 24,
        iv_len: 16,
        block_size: 16,
        aead: false,
        tag_len: 0,
    },
    CipherSpec {
        name: "aes128-ctr",
        key_len: 16,
        iv_len: 16,
        block_size: 16,
        aead: false,
        tag_len: 0,
    },
];

/// Look up a [`CipherSpec`] by SSH name.
pub fn by_name(name: &str) -> Option<&'static CipherSpec> {
    ALL.iter().find(|c| c.name == name)
}
