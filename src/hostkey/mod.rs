//! Host-key / public-key signature algorithms (RFC 4253 §6.6, RFC 8332).
//!
//! These show up in three places:
//!
//! 1. The server's host key, used to sign the KEX exchange hash `H`.
//! 2. The "server host key algorithms" KEX-init list.
//! 3. User publickey authentication (RFC 4252 §7), where the same wire format
//!    is reused.

pub mod ed25519;
pub mod ecdsa;
pub mod rsa;

/// A signature algorithm exposed to the rest of the crate.
pub trait HostKeyAlgorithm {
    /// SSH algorithm name (e.g. `"ssh-ed25519"`, `"rsa-sha2-256"`).
    const NAME: &'static str;
}
