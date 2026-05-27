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

#[cfg(feature = "alloc")]
use alloc::vec::Vec;
#[cfg(feature = "alloc")]
use purecrypto::ec::{Ed25519PrivateKey, Ed25519PublicKey, Ed25519Signature};

#[cfg(feature = "alloc")]
use crate::error::{Error, Result};
#[cfg(feature = "alloc")]
use crate::format::{Reader, Writer};
#[cfg(feature = "alloc")]
use super::{HostKey, HostKeyVerify};

/// Marker for the `ssh-ed25519` algorithm.
pub struct SshEd25519;

impl HostKeyAlgorithm for SshEd25519 {
    const NAME: &'static str = "ssh-ed25519";
}

/// An `ssh-ed25519` host key: holds both signer and verifier state.
#[cfg(feature = "alloc")]
pub struct Ed25519HostKey {
    private: Option<Ed25519PrivateKey>,
    public: Ed25519PublicKey,
}

#[cfg(feature = "alloc")]
impl Ed25519HostKey {
    /// Build a host key from a 32-byte seed (private key material).
    pub fn from_seed(seed: [u8; 32]) -> Self {
        let private = Ed25519PrivateKey::from_bytes(seed);
        let public = private.public_key();
        Ed25519HostKey {
            private: Some(private),
            public,
        }
    }

    /// Build a verifier-only host key from a 32-byte public key.
    pub fn from_public(pk: [u8; 32]) -> Self {
        Ed25519HostKey {
            private: None,
            public: Ed25519PublicKey::from_bytes(pk),
        }
    }

    /// The raw 32-byte public key.
    pub fn public_bytes(&self) -> [u8; 32] {
        self.public.to_bytes()
    }
}

#[cfg(feature = "alloc")]
impl HostKey for Ed25519HostKey {
    fn algorithm(&self) -> &'static str {
        SshEd25519::NAME
    }

    fn public_blob(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(4 + 11 + 4 + 32);
        w.write_string(SshEd25519::NAME.as_bytes());
        w.write_string(&self.public.to_bytes());
        w.into_vec()
    }

    fn sign(&self, msg: &[u8]) -> Result<Vec<u8>> {
        let sk = self
            .private
            .as_ref()
            .ok_or(Error::Crypto("ed25519: no private key"))?;
        let sig = sk.sign(msg);
        let bytes = sig.to_bytes();
        let mut w = Writer::with_capacity(4 + 11 + 4 + 64);
        w.write_string(SshEd25519::NAME.as_bytes());
        w.write_string(&bytes);
        Ok(w.into_vec())
    }
}

#[cfg(feature = "alloc")]
impl HostKeyVerify for Ed25519HostKey {
    fn algorithm(&self) -> &'static str {
        SshEd25519::NAME
    }

    fn verify(&self, msg: &[u8], sig_blob: &[u8]) -> Result<()> {
        let mut r = Reader::new(sig_blob);
        let name = r.read_string()?;
        if name != SshEd25519::NAME.as_bytes() {
            return Err(Error::Format("ed25519: signature algorithm mismatch"));
        }
        let raw = r.read_string()?;
        if raw.len() != 64 {
            return Err(Error::Format("ed25519: signature length"));
        }
        if !r.is_empty() {
            return Err(Error::Format("ed25519: signature trailing data"));
        }
        let mut buf = [0u8; 64];
        buf.copy_from_slice(raw);
        let sig = Ed25519Signature::from_bytes(buf);
        self.public
            .verify(msg, &sig)
            .map_err(|_| Error::BadSignature)
    }

    fn from_public_blob(blob: &[u8]) -> Result<Self> {
        let mut r = Reader::new(blob);
        let name = r.read_string()?;
        if name != SshEd25519::NAME.as_bytes() {
            return Err(Error::Format("ed25519: public key type mismatch"));
        }
        let raw = r.read_string()?;
        if raw.len() != 32 {
            return Err(Error::Format("ed25519: public key length"));
        }
        if !r.is_empty() {
            return Err(Error::Format("ed25519: public key trailing data"));
        }
        let mut buf = [0u8; 32];
        buf.copy_from_slice(raw);
        Ok(Ed25519HostKey {
            private: None,
            public: Ed25519PublicKey::from_bytes(buf),
        })
    }
}

#[cfg(all(test, feature = "alloc"))]
mod tests {
    use super::*;

    const RFC8032_SEED: [u8; 32] = [
        0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c,
        0xc4, 0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae,
        0x7f, 0x60,
    ];
    const RFC8032_PUB: [u8; 32] = [
        0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07,
        0x3a, 0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07,
        0x51, 0x1a,
    ];

    #[test]
    fn public_blob_roundtrip() {
        let hk = Ed25519HostKey::from_seed(RFC8032_SEED);
        let blob = hk.public_blob();
        let parsed = Ed25519HostKey::from_public_blob(&blob).unwrap();
        assert_eq!(parsed.public_bytes(), RFC8032_PUB);
    }

    #[test]
    fn sign_verify_roundtrip() {
        let hk = Ed25519HostKey::from_seed(RFC8032_SEED);
        let sig = hk.sign(b"hello ssh").unwrap();
        hk.verify(b"hello ssh", &sig).unwrap();
        assert!(hk.verify(b"goodbye ssh", &sig).is_err());
    }

    #[test]
    fn verify_rejects_wrong_algorithm() {
        let hk = Ed25519HostKey::from_seed(RFC8032_SEED);
        let mut bad = Writer::new();
        bad.write_string(b"ssh-rsa");
        bad.write_string(&[0u8; 64]);
        assert!(hk.verify(b"x", &bad.into_vec()).is_err());
    }

    #[test]
    fn rejects_bad_lengths() {
        let hk = Ed25519HostKey::from_seed(RFC8032_SEED);
        let mut bad = Writer::new();
        bad.write_string(b"ssh-ed25519");
        bad.write_string(&[0u8; 63]);
        assert!(hk.verify(b"x", &bad.into_vec()).is_err());
    }
}
