//! Key-exchange algorithms.
//!
//! Each algorithm produces a shared secret `K` and an exchange hash `H`. `H`
//! is the session identifier on the first KEX, and is what host-key signatures
//! cover. `K` and `H` together seed the key derivation (RFC 4253 §7.2).

mod common;
pub mod curve25519;
pub mod dh;
pub mod ecdh;
mod hash;
pub mod mlkem768x25519;

pub use common::{KexContext, KexInitOut, KexOutput};
pub use curve25519::Curve25519Sha256;
pub use dh::{GexClientState, GexRequest, GexSha256, Group14Sha256, Group16Sha512, Group18Sha512};
pub use ecdh::{EcdhSha2Nistp256, EcdhSha2Nistp384, EcdhSha2Nistp521};
pub use hash::{ExchangeHash, derive, mpint_bytes};
pub use mlkem768x25519::MlKem768X25519Sha256;

/// Trait implemented by each KEX algorithm module.
pub trait Kex {
    /// SSH name (e.g. `"curve25519-sha256"`).
    const NAME: &'static str;
    /// Hash length (in bytes) used for both `H` and key derivation.
    const HASH_LEN: usize;
}
