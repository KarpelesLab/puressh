//! Key-exchange algorithms.
//!
//! Each algorithm produces a shared secret `K` and an exchange hash `H`. `H`
//! is the session identifier on the first KEX, and is what host-key signatures
//! cover. `K` and `H` together seed the key derivation (RFC 4253 §7.2).

pub mod curve25519;
pub mod ecdh;
pub mod dh;

/// Trait implemented by each KEX algorithm module.
pub trait Kex {
    /// SSH name (e.g. `"curve25519-sha256"`).
    const NAME: &'static str;
    /// Hash length (in bytes) used for both `H` and key derivation.
    const HASH_LEN: usize;
}
