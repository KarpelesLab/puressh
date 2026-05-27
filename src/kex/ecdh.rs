//! `ecdh-sha2-nistp{256,384,521}` (RFC 5656).
//!
//! Backed by [`purecrypto::ec::boxed`] for runtime curve dispatch.

use super::Kex;

/// `ecdh-sha2-nistp256` — P-256 ECDH with SHA-256.
pub struct EcdhSha2Nistp256;
impl Kex for EcdhSha2Nistp256 {
    const NAME: &'static str = "ecdh-sha2-nistp256";
    const HASH_LEN: usize = 32;
}

/// `ecdh-sha2-nistp384` — P-384 ECDH with SHA-384.
pub struct EcdhSha2Nistp384;
impl Kex for EcdhSha2Nistp384 {
    const NAME: &'static str = "ecdh-sha2-nistp384";
    const HASH_LEN: usize = 48;
}

/// `ecdh-sha2-nistp521` — P-521 ECDH with SHA-512.
pub struct EcdhSha2Nistp521;
impl Kex for EcdhSha2Nistp521 {
    const NAME: &'static str = "ecdh-sha2-nistp521";
    const HASH_LEN: usize = 64;
}
