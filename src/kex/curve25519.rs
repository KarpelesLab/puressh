//! `curve25519-sha256` (RFC 8731) — X25519 ECDH with SHA-256.
//!
//! Backed by [`purecrypto::ec::x25519`] for the scalar multiplication and
//! [`purecrypto::hash::Sha256`] for the exchange hash.

use super::Kex;

/// Marker type implementing the `curve25519-sha256` KEX.
pub struct Curve25519Sha256;

impl Kex for Curve25519Sha256 {
    const NAME: &'static str = "curve25519-sha256";
    const HASH_LEN: usize = 32;
}

// Implementation:
//   - generate ephemeral X25519 keypair via purecrypto::ec::x25519 + rng::OsRng
//   - SSH_MSG_KEX_ECDH_INIT carries our public key
//   - SSH_MSG_KEX_ECDH_REPLY carries server public host key, server public, signature on H
//   - compute K = X25519(our_priv, peer_pub)
//   - H = SHA256( V_C || V_S || I_C || I_S || K_S || Q_C || Q_S || K )
//   - verify signature on H using host key
// (left as TODO — fleshed out once the packet codec is wired up)
