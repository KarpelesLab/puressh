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

use core::sync::atomic::{AtomicBool, Ordering};

pub mod ecdsa;
pub mod ed25519;
pub mod rsa;

/// Process-wide opt-in for the legacy `ssh-rsa` (SHA-1) signature algorithm.
///
/// Defaults to `false`. When `false`, [`host_key_verify_by_name`] refuses the
/// `"ssh-rsa"` name with [`crate::Error::Unsupported`]. The modern
/// `"rsa-sha2-256"` / `"rsa-sha2-512"` (RFC 8332) names are unaffected and
/// remain available regardless of this flag — only the SHA-1 form is gated.
///
/// This is a single global atomic for the whole process; flipping it affects
/// every future call from every thread. There is intentionally no per-call
/// or per-connection knob: SHA-1 is broken, and the only legitimate use case
/// is interop with ancient peers in known-controlled environments.
static ALLOW_RSA_SHA1: AtomicBool = AtomicBool::new(false);

/// Opt in (or out) of the legacy `ssh-rsa` (SHA-1) signature algorithm
/// process-wide.
///
/// See the `ALLOW_RSA_SHA1` static for the rationale. The default is `false`
/// and callers should leave it that way unless they have a concrete interop
/// requirement.
pub fn set_allow_rsa_sha1(allow: bool) {
    ALLOW_RSA_SHA1.store(allow, Ordering::Relaxed);
}

/// Returns whether `ssh-rsa` (SHA-1) is currently permitted process-wide.
pub fn allow_rsa_sha1() -> bool {
    ALLOW_RSA_SHA1.load(Ordering::Relaxed)
}

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

    /// If the server's `server-sig-algs` (RFC 8308 §3.1, comma-separated)
    /// lets us upgrade this signer to a stronger same-key variant — most
    /// commonly an `ssh-rsa` (SHA-1) signer being re-used under
    /// `rsa-sha2-512` / `rsa-sha2-256` over the same RSA key material —
    /// return the upgraded signer.
    ///
    /// The default is `None` — Ed25519, ECDSA, and already-SHA-2 RSA
    /// signers have nothing stronger to switch to over the same key.
    ///
    /// Implementations MUST NOT downgrade (e.g. `rsa-sha2-512` → `…-256`)
    /// from this hook; the auth layer relies on the caller's chosen
    /// minimum.
    fn upgraded_for(&self, _server_sig_algs: &str) -> Option<Box<dyn HostKey>> {
        None
    }
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
        "ssh-rsa" => {
            if !allow_rsa_sha1() {
                return Err(crate::Error::Unsupported(
                    "ssh-rsa (SHA-1) is disabled by default; call hostkey::set_allow_rsa_sha1(true) to opt in",
                ));
            }
            Ok(Box::new(RsaSha1HostKey::from_public_blob(blob)?))
        }
        "rsa-sha2-256" => Ok(Box::new(RsaSha2_256HostKey::from_public_blob(blob)?)),
        "rsa-sha2-512" => Ok(Box::new(RsaSha2_512HostKey::from_public_blob(blob)?)),
        _ => Err(crate::Error::Unsupported("host-key algorithm")),
    }
}

#[cfg(all(test, feature = "alloc"))]
mod tests {
    use super::*;

    /// Serialize all `ssh-rsa`-gate tests onto one mutex; they all touch the
    /// process-wide [`ALLOW_RSA_SHA1`] atomic and would otherwise race when
    /// the test runner schedules them in parallel.
    static GATE_MUTEX: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn sample_rsa_public_blob() -> Vec<u8> {
        use purecrypto::bignum::BoxedUint;
        let mut n_bytes = alloc::vec![0u8; 256];
        n_bytes[0] = 0xc0;
        for (i, b) in n_bytes.iter_mut().enumerate().skip(1) {
            *b = (i as u8).wrapping_mul(31).wrapping_add(7) | 0x01;
        }
        let n = BoxedUint::from_be_bytes(&n_bytes);
        let e = BoxedUint::from_u64(65537);
        RsaSha2_256HostKey::from_public_components(n, e)
            .unwrap()
            .public_blob()
    }

    #[test]
    fn ssh_rsa_sha1_rejected_by_default() {
        let _guard = GATE_MUTEX.lock().unwrap();
        // Ensure the default-off invariant even if a previous test toggled it.
        set_allow_rsa_sha1(false);
        let blob = sample_rsa_public_blob();
        let result = host_key_verify_by_name("ssh-rsa", &blob);
        match result {
            Err(crate::Error::Unsupported(_)) => {}
            Err(other) => panic!("expected Unsupported, got {other:?}"),
            Ok(_) => panic!("expected ssh-rsa to be rejected by default"),
        }
    }

    #[test]
    fn ssh_rsa_sha1_allowed_after_opt_in() {
        let _guard = GATE_MUTEX.lock().unwrap();
        let blob = sample_rsa_public_blob();
        set_allow_rsa_sha1(true);
        let result = host_key_verify_by_name("ssh-rsa", &blob);
        // Reset before asserting, so a panic doesn't leak the opt-in to
        // sibling tests running later in the same process.
        set_allow_rsa_sha1(false);
        result.expect("ssh-rsa should parse once explicitly opted in");
    }

    #[test]
    fn rsa_sha2_names_unaffected_by_gate() {
        let _guard = GATE_MUTEX.lock().unwrap();
        set_allow_rsa_sha1(false);
        let blob = sample_rsa_public_blob();
        host_key_verify_by_name("rsa-sha2-256", &blob)
            .expect("rsa-sha2-256 must remain enabled regardless of the SHA-1 gate");
        host_key_verify_by_name("rsa-sha2-512", &blob)
            .expect("rsa-sha2-512 must remain enabled regardless of the SHA-1 gate");
    }
}
