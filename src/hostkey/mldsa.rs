//! `ssh-mldsa44-ed25519` — OpenSSH's post-quantum composite
//! signature (OpenSSH 10.3+): ML-DSA-44 (FIPS 204) and Ed25519 over the same
//! message, both of which must verify, following the IETF LAMPS composite
//! signatures (`COMPSIG-MLDSA44-Ed25519-SHA512`).
//!
//! ```text
//! public key:  string "ssh-mldsa44-ed25519"
//!              string ML-DSA-44 public key (1312 B) || Ed25519 public key (32 B)
//! signature:   string "ssh-mldsa44-ed25519"
//!              string ML-DSA-44 signature (2420 B) || Ed25519 signature (64 B)
//! private key: ML-DSA-44 seed (32 B) || Ed25519 seed (32 B)
//! ```
//!
//! Both components sign `M' = "CompositeAlgorithmSignatures2025" || label ||
//! u8(0) || SHA512(message)`; ML-DSA additionally takes the label as its
//! context string.

use alloc::vec::Vec;

use purecrypto::ec::{Ed25519PrivateKey, Ed25519PublicKey, Ed25519Signature};
use purecrypto::hash::{Digest, Sha512};
use purecrypto::mldsa::{MlDsa44PrivateKey, MlDsa44PublicKey};
use purecrypto::zeroize::Zeroizing;

use super::{HostKey, HostKeyAlgorithm, HostKeyVerify};
use crate::error::{Error, Result};
use crate::format::{Reader, Writer};

/// Marker for the `ssh-mldsa44-ed25519` algorithm.
pub struct SshMlDsa44Ed25519;

impl HostKeyAlgorithm for SshMlDsa44Ed25519 {
    const NAME: &'static str = "ssh-mldsa44-ed25519";
}

/// ML-DSA-44 public key length.
const MLDSA_PK: usize = 1312;
/// ML-DSA-44 signature length.
const MLDSA_SIG: usize = 2420;
/// Composite public key length (ML-DSA-44 || Ed25519).
pub const PUBLIC_KEY_BYTES: usize = MLDSA_PK + 32;
/// Composite private key length (two 32-byte seeds).
pub const PRIVATE_KEY_BYTES: usize = 64;
/// Composite signature length.
pub const SIGNATURE_BYTES: usize = MLDSA_SIG + 64;

const PREFIX: &[u8] = b"CompositeAlgorithmSignatures2025";
const LABEL: &[u8] = b"COMPSIG-MLDSA44-Ed25519-SHA512";

/// The message both components sign (empty composite context).
fn m_prime(msg: &[u8]) -> Vec<u8> {
    let mut m = Vec::with_capacity(PREFIX.len() + LABEL.len() + 1 + 64);
    m.extend_from_slice(PREFIX);
    m.extend_from_slice(LABEL);
    m.push(0);
    m.extend_from_slice(Sha512::digest(msg).as_ref());
    m
}

/// The composite public key for a private key (two seeds).
pub fn public_from_seeds(seeds: &[u8; PRIVATE_KEY_BYTES]) -> Vec<u8> {
    let mut mldsa_seed = Zeroizing::new([0u8; 32]);
    mldsa_seed.copy_from_slice(&seeds[..32]);
    let mut ed_seed = Zeroizing::new([0u8; 32]);
    ed_seed.copy_from_slice(&seeds[32..]);
    let (_, mldsa_pk) = MlDsa44PrivateKey::from_seed(&mldsa_seed);
    let ed_pk = Ed25519PrivateKey::from_bytes(*ed_seed).public_key();
    let mut pk = Vec::with_capacity(PUBLIC_KEY_BYTES);
    pk.extend_from_slice(mldsa_pk.to_bytes());
    pk.extend_from_slice(&ed_pk.to_bytes());
    pk
}

/// An `ssh-mldsa44-ed25519` key: a verifier, and a signer when
/// built from the private seeds.
pub struct MlDsa44Ed25519HostKey {
    seeds: Option<Zeroizing<[u8; PRIVATE_KEY_BYTES]>>,
    public: Vec<u8>,
}

impl MlDsa44Ed25519HostKey {
    /// A signing key from its private part (ML-DSA seed || Ed25519 seed).
    pub fn from_seeds(seeds: [u8; PRIVATE_KEY_BYTES]) -> Self {
        let public = public_from_seeds(&seeds);
        MlDsa44Ed25519HostKey {
            seeds: Some(Zeroizing::new(seeds)),
            public,
        }
    }

    /// A verify-only key from the raw composite public key.
    pub fn from_public(raw: &[u8]) -> Result<Self> {
        if raw.len() != PUBLIC_KEY_BYTES {
            return Err(Error::Format("mldsa44-ed25519: public key length"));
        }
        Ok(MlDsa44Ed25519HostKey {
            seeds: None,
            public: raw.to_vec(),
        })
    }

    /// The raw composite public key.
    pub fn public_bytes(&self) -> &[u8] {
        &self.public
    }

    /// The raw composite signature over `msg`.
    fn sign_raw(&self, msg: &[u8]) -> Result<Vec<u8>> {
        let seeds = self
            .seeds
            .as_ref()
            .ok_or(Error::Crypto("mldsa44-ed25519: no private key"))?;
        let m = m_prime(msg);
        let mut mldsa_seed = Zeroizing::new([0u8; 32]);
        mldsa_seed.copy_from_slice(&seeds[..32]);
        let mut ed_seed = Zeroizing::new([0u8; 32]);
        ed_seed.copy_from_slice(&seeds[32..]);
        let (mldsa_sk, _) = MlDsa44PrivateKey::from_seed(&mldsa_seed);
        #[cfg(feature = "std")]
        let mldsa_sig = mldsa_sk.sign(&mut purecrypto::rng::OsRng, &m, LABEL);
        #[cfg(not(feature = "std"))]
        let mldsa_sig = mldsa_sk.sign_deterministic(&m, LABEL);
        let mldsa_sig = mldsa_sig.map_err(|_| Error::Crypto("mldsa44-ed25519: sign"))?;
        let ed_sig = Ed25519PrivateKey::from_bytes(*ed_seed).sign(&m);
        let mut sig = Vec::with_capacity(SIGNATURE_BYTES);
        sig.extend_from_slice(&mldsa_sig);
        sig.extend_from_slice(&ed_sig.to_bytes());
        Ok(sig)
    }

    /// Whether `sig` (raw composite) is valid over `msg`: both halves must be.
    fn verify_raw(&self, msg: &[u8], sig: &[u8]) -> bool {
        if sig.len() != SIGNATURE_BYTES {
            return false;
        }
        let Ok(mldsa_pk) = MlDsa44PublicKey::from_bytes(&self.public[..MLDSA_PK]) else {
            return false;
        };
        let mut ed_pk = [0u8; 32];
        ed_pk.copy_from_slice(&self.public[MLDSA_PK..]);
        let mut ed_sig = [0u8; 64];
        ed_sig.copy_from_slice(&sig[MLDSA_SIG..]);
        let m = m_prime(msg);
        let mldsa_ok = mldsa_pk.verify(&sig[..MLDSA_SIG], &m, LABEL);
        let ed_ok = Ed25519PublicKey::from_bytes(ed_pk)
            .verify(&m, &Ed25519Signature::from_bytes(ed_sig))
            .is_ok();
        mldsa_ok & ed_ok
    }
}

impl HostKey for MlDsa44Ed25519HostKey {
    fn algorithm(&self) -> &'static str {
        SshMlDsa44Ed25519::NAME
    }

    fn public_blob(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(4 + 31 + 4 + PUBLIC_KEY_BYTES);
        w.write_string(SshMlDsa44Ed25519::NAME.as_bytes());
        w.write_string(&self.public);
        w.into_vec()
    }

    fn sign(&self, msg: &[u8]) -> Result<Vec<u8>> {
        let sig = self.sign_raw(msg)?;
        let mut w = Writer::with_capacity(4 + 31 + 4 + SIGNATURE_BYTES);
        w.write_string(SshMlDsa44Ed25519::NAME.as_bytes());
        w.write_string(&sig);
        Ok(w.into_vec())
    }
}

impl HostKeyVerify for MlDsa44Ed25519HostKey {
    fn algorithm(&self) -> &'static str {
        SshMlDsa44Ed25519::NAME
    }

    fn verify(&self, msg: &[u8], sig_blob: &[u8]) -> Result<()> {
        let mut r = Reader::new(sig_blob);
        if r.read_string()? != SshMlDsa44Ed25519::NAME.as_bytes() {
            return Err(Error::Format(
                "mldsa44-ed25519: signature algorithm mismatch",
            ));
        }
        let sig = r.read_string()?;
        if !r.is_empty() {
            return Err(Error::Format("mldsa44-ed25519: signature trailing data"));
        }
        if self.verify_raw(msg, sig) {
            Ok(())
        } else {
            Err(Error::BadSignature)
        }
    }

    fn from_public_blob(blob: &[u8]) -> Result<Self> {
        let mut r = Reader::new(blob);
        if r.read_string()? != SshMlDsa44Ed25519::NAME.as_bytes() {
            return Err(Error::Format("mldsa44-ed25519: public key type mismatch"));
        }
        let raw = r.read_string()?;
        if !r.is_empty() {
            return Err(Error::Format("mldsa44-ed25519: public key trailing data"));
        }
        Self::from_public(raw)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_verify_roundtrip() {
        let mut seeds = [0u8; 64];
        for (i, b) in seeds.iter_mut().enumerate() {
            *b = i as u8;
        }
        let k = MlDsa44Ed25519HostKey::from_seeds(seeds);
        let sig = k.sign(b"hello").unwrap();
        let v = MlDsa44Ed25519HostKey::from_public_blob(&k.public_blob()).unwrap();
        v.verify(b"hello", &sig).unwrap();
        assert!(v.verify(b"hellO", &sig).is_err());
        // Either half alone is not enough.
        let mut bad = sig.clone();
        let n = bad.len();
        bad[n - 1] ^= 1;
        assert!(v.verify(b"hello", &bad).is_err());
        let mut bad = sig;
        bad[40] ^= 1;
        assert!(v.verify(b"hello", &bad).is_err());
    }
}
