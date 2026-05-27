//! `ssh-ed25519` (RFC 8709) — Ed25519 signatures over SSH.
//!
//! Wire format for the public key:
//!
//! ```text
//! string "ssh-ed25519"
//! string raw 32-byte public key
//! ```
//!
//! Wire format for the signature:
//!
//! ```text
//! string "ssh-ed25519"
//! string raw 64-byte signature (R || S)
//! ```
//!
//! Backed by [`purecrypto::ec::ed25519`].

use super::HostKeyAlgorithm;

/// Marker for the `ssh-ed25519` algorithm.
pub struct SshEd25519;

impl HostKeyAlgorithm for SshEd25519 {
    const NAME: &'static str = "ssh-ed25519";
}
