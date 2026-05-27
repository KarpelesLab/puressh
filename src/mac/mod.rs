//! Message Authentication Codes over [`purecrypto::hash`] (HMAC family).
//!
//! SSH MACs use either Encrypt-and-MAC (legacy) or Encrypt-then-MAC (`-etm@openssh.com`).
//! AEAD ciphers (GCM, ChaCha20-Poly1305) provide their own integrity and ignore
//! the negotiated MAC.

/// SSH-side identifier and key/tag geometry for a MAC.
#[derive(Debug, Clone, Copy)]
pub struct MacSpec {
    /// On-the-wire SSH name.
    pub name: &'static str,
    /// Underlying hash output size in bytes (= HMAC key length).
    pub key_len: usize,
    /// Tag length appended to each packet, in bytes.
    pub tag_len: usize,
    /// Encrypt-then-MAC (true for `*-etm@openssh.com`).
    pub etm: bool,
}

/// Catalogue of MACs this build supports.
pub const ALL: &[MacSpec] = &[
    MacSpec { name: "hmac-sha2-256-etm@openssh.com", key_len: 32, tag_len: 32, etm: true },
    MacSpec { name: "hmac-sha2-512-etm@openssh.com", key_len: 64, tag_len: 64, etm: true },
    MacSpec { name: "hmac-sha2-256", key_len: 32, tag_len: 32, etm: false },
    MacSpec { name: "hmac-sha2-512", key_len: 64, tag_len: 64, etm: false },
];

/// Look up a [`MacSpec`] by SSH name.
pub fn by_name(name: &str) -> Option<&'static MacSpec> {
    ALL.iter().find(|m| m.name == name)
}
