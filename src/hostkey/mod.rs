//! Host-key / public-key signature algorithms (RFC 4253 §6.6, RFC 8332).
//!
//! These show up in three places:
//!
//! 1. The server's host key, used to sign the KEX exchange hash `H`.
//! 2. The "server host key algorithms" KEX-init list.
//! 3. User publickey authentication (RFC 4252 §7), where the same wire format
//!    is reused.

#[cfg(feature = "alloc")]
use alloc::boxed::Box;
#[cfg(feature = "alloc")]
use alloc::vec::Vec;

pub mod ecdsa;
pub mod ed25519;
pub mod rsa;

#[cfg(feature = "alloc")]
pub use ecdsa::{EcdsaP256HostKey, EcdsaP384HostKey, EcdsaP521HostKey};
#[cfg(feature = "alloc")]
pub use ed25519::Ed25519HostKey;
#[cfg(feature = "alloc")]
pub use rsa::{RsaSha1HostKey, RsaSha2_256HostKey, RsaSha2_512HostKey};

/// A signature algorithm exposed to the rest of the crate.
pub trait HostKeyAlgorithm {
    /// SSH algorithm name (e.g. `"ssh-ed25519"`, `"rsa-sha2-256"`).
    const NAME: &'static str;
}

/// A host key able to produce SSH-formatted signatures.
#[cfg(feature = "alloc")]
pub trait HostKey {
    /// The SSH algorithm name advertised for signatures from this key.
    fn algorithm(&self) -> &'static str;

    /// The public part of this key in SSH wire format.
    fn public_blob(&self) -> Vec<u8>;

    /// Sign `msg` and return the SSH wire-format signature blob.
    fn sign(&self, msg: &[u8]) -> crate::Result<Vec<u8>>;
}

/// A host key able to verify SSH-formatted signatures.
#[cfg(feature = "alloc")]
pub trait HostKeyVerify {
    /// The SSH algorithm name this verifier accepts.
    fn algorithm(&self) -> &'static str;

    /// Verify `sig_blob` over `msg`.
    fn verify(&self, msg: &[u8], sig_blob: &[u8]) -> crate::Result<()>;

    /// Parse a public-key blob in SSH wire format.
    fn from_public_blob(blob: &[u8]) -> crate::Result<Self>
    where
        Self: Sized;
}

/// Dispatch a public-key blob to the appropriate `HostKeyVerify` based on
/// the algorithm name from KEX or a signature.
///
/// `ssh-rsa`, `rsa-sha2-256`, and `rsa-sha2-512` all share the `"ssh-rsa"`
/// public-key blob layout — RFC 8332 §3 — so the same `(n, e)` blob is
/// reusable across hash choices; only the resulting signature blob differs.
#[cfg(feature = "alloc")]
pub fn host_key_verify_by_name(name: &str, blob: &[u8]) -> crate::Result<Box<dyn HostKeyVerify>> {
    match name {
        "ssh-ed25519" => Ok(Box::new(Ed25519HostKey::from_public_blob(blob)?)),
        "ecdsa-sha2-nistp256" => Ok(Box::new(EcdsaP256HostKey::from_public_blob(blob)?)),
        "ecdsa-sha2-nistp384" => Ok(Box::new(EcdsaP384HostKey::from_public_blob(blob)?)),
        "ecdsa-sha2-nistp521" => Ok(Box::new(EcdsaP521HostKey::from_public_blob(blob)?)),
        "ssh-rsa" => Ok(Box::new(RsaSha1HostKey::from_public_blob(blob)?)),
        "rsa-sha2-256" => Ok(Box::new(RsaSha2_256HostKey::from_public_blob(blob)?)),
        "rsa-sha2-512" => Ok(Box::new(RsaSha2_512HostKey::from_public_blob(blob)?)),
        _ => Err(crate::Error::Unsupported("host-key algorithm")),
    }
}
