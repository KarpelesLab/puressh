//! `ecdsa-sha2-nistp{256,384,521}` (RFC 5656) — ECDSA host keys.
//!
//! Backed by [`purecrypto::ec::boxed`] (runtime-dispatched ECDSA over the
//! three NIST primes).

use super::HostKeyAlgorithm;

/// `ecdsa-sha2-nistp256`.
pub struct EcdsaP256;
impl HostKeyAlgorithm for EcdsaP256 {
    const NAME: &'static str = "ecdsa-sha2-nistp256";
}

/// `ecdsa-sha2-nistp384`.
pub struct EcdsaP384;
impl HostKeyAlgorithm for EcdsaP384 {
    const NAME: &'static str = "ecdsa-sha2-nistp384";
}

/// `ecdsa-sha2-nistp521`.
pub struct EcdsaP521;
impl HostKeyAlgorithm for EcdsaP521 {
    const NAME: &'static str = "ecdsa-sha2-nistp521";
}
