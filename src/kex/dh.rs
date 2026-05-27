//! `diffie-hellman-group{14,16,18}-sha{256,512}` (RFC 8268) and
//! `diffie-hellman-group-exchange-sha256` (RFC 4419).
//!
//! Backed by [`purecrypto::dh`]: `group14()` … `group18()` and
//! `DhPrivateKey::generate` for ephemeral keys, with the shared secret
//! produced by `DhPrivateKey::shared_secret`.

use super::Kex;

/// `diffie-hellman-group14-sha256` — RFC 3526 2048-bit group, SHA-256.
pub struct Group14Sha256;
impl Kex for Group14Sha256 {
    const NAME: &'static str = "diffie-hellman-group14-sha256";
    const HASH_LEN: usize = 32;
}

/// `diffie-hellman-group16-sha512` — RFC 3526 4096-bit group, SHA-512.
pub struct Group16Sha512;
impl Kex for Group16Sha512 {
    const NAME: &'static str = "diffie-hellman-group16-sha512";
    const HASH_LEN: usize = 64;
}

/// `diffie-hellman-group18-sha512` — RFC 3526 8192-bit group, SHA-512.
pub struct Group18Sha512;
impl Kex for Group18Sha512 {
    const NAME: &'static str = "diffie-hellman-group18-sha512";
    const HASH_LEN: usize = 64;
}

/// `diffie-hellman-group-exchange-sha256` — RFC 4419 GEX, SHA-256.
pub struct GexSha256;
impl Kex for GexSha256 {
    const NAME: &'static str = "diffie-hellman-group-exchange-sha256";
    const HASH_LEN: usize = 32;
}
