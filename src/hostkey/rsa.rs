//! RSA host keys (RFC 8332):
//!
//! - `ssh-rsa`       — RSA + SHA-1 (legacy; disabled by default in modern OpenSSH)
//! - `rsa-sha2-256`  — RSA + SHA-256 (PKCS#1 v1.5)
//! - `rsa-sha2-512`  — RSA + SHA-512 (PKCS#1 v1.5)
//!
//! All three share the same public-key blob layout under the algorithm
//! string `"ssh-rsa"` (RFC 8332 §3); only the signature blob differs.
//!
//! Backed by [`purecrypto::rsa::BoxedRsaPrivateKey`] (signing via
//! `sign_pkcs1v15::<D>`) and [`purecrypto::rsa::BoxedRsaPublicKey`]
//! (`verify_pkcs1v15::<D>`); the SSH public blob is built directly from
//! `BoxedRsaPublicKey::{modulus, exponent}`.

use super::HostKeyAlgorithm;

#[cfg(feature = "alloc")]
use alloc::vec::Vec;
#[cfg(feature = "alloc")]
use purecrypto::bignum::BoxedUint;
#[cfg(feature = "alloc")]
use purecrypto::hash::{Sha1, Sha256, Sha512};
#[cfg(feature = "alloc")]
use purecrypto::rsa::{BoxedRsaPrivateKey, BoxedRsaPublicKey};

#[cfg(feature = "alloc")]
use crate::error::{Error, Result};
#[cfg(feature = "alloc")]
use crate::format::{Reader, Writer, read_mpint, write_mpint};
#[cfg(feature = "alloc")]
use super::{HostKey, HostKeyVerify};

/// `ssh-rsa` (RSA-SHA1, legacy).
pub struct SshRsa;
impl HostKeyAlgorithm for SshRsa {
    const NAME: &'static str = "ssh-rsa";
}

/// `rsa-sha2-256`.
pub struct RsaSha2_256;
impl HostKeyAlgorithm for RsaSha2_256 {
    const NAME: &'static str = "rsa-sha2-256";
}

/// `rsa-sha2-512`.
pub struct RsaSha2_512;
impl HostKeyAlgorithm for RsaSha2_512 {
    const NAME: &'static str = "rsa-sha2-512";
}

/// The hash variant used in an RSA signature.
#[cfg(feature = "alloc")]
#[derive(Clone, Copy)]
enum RsaHash {
    Sha1,
    Sha256,
    Sha512,
}

#[cfg(feature = "alloc")]
impl RsaHash {
    const fn algorithm(self) -> &'static str {
        match self {
            RsaHash::Sha1 => SshRsa::NAME,
            RsaHash::Sha256 => RsaSha2_256::NAME,
            RsaHash::Sha512 => RsaSha2_512::NAME,
        }
    }
}

/// Convert mpint bytes (two's-complement big-endian) into a non-negative
/// `BoxedUint`, rejecting negative encodings.
#[cfg(feature = "alloc")]
fn mpint_to_uint(bytes: &[u8]) -> Result<BoxedUint> {
    if bytes.is_empty() {
        return Ok(BoxedUint::from_u64(0));
    }
    if (bytes[0] & 0x80) != 0 {
        return Err(Error::Format("rsa: negative mpint"));
    }
    let mut start = 0usize;
    while start + 1 < bytes.len() && bytes[start] == 0 {
        start += 1;
    }
    Ok(BoxedUint::from_be_bytes(&bytes[start..]))
}

#[cfg(feature = "alloc")]
fn parse_rsa_public_blob(blob: &[u8]) -> Result<(BoxedRsaPublicKey, usize)> {
    let mut r = Reader::new(blob);
    let name = r.read_string()?;
    if name != SshRsa::NAME.as_bytes() {
        return Err(Error::Format("rsa: public key type mismatch"));
    }
    let e_raw = read_mpint(&mut r)?;
    let n_raw = read_mpint(&mut r)?;
    if !r.is_empty() {
        return Err(Error::Format("rsa: public key trailing data"));
    }
    let e = mpint_to_uint(e_raw)?;
    let n = mpint_to_uint(n_raw)?;
    if n.is_zero() {
        return Err(Error::Format("rsa: zero modulus"));
    }
    let k = n.bit_len().div_ceil(8);
    let pk = BoxedRsaPublicKey::try_new(n, e)
        .map_err(|_| Error::Format("rsa: modulus out of accepted range"))?;
    Ok((pk, k))
}

#[cfg(feature = "alloc")]
fn build_rsa_public_blob(pk: &BoxedRsaPublicKey) -> Vec<u8> {
    let n = pk.modulus();
    let e = pk.exponent();
    let mut w = Writer::new();
    w.write_string(SshRsa::NAME.as_bytes());
    let nbytes = n.to_be_bytes(n.bit_len().div_ceil(8).max(1));
    let ebytes = e.to_be_bytes(e.bit_len().div_ceil(8).max(1));
    write_mpint(&mut w, &ebytes);
    write_mpint(&mut w, &nbytes);
    w.into_vec()
}

#[cfg(feature = "alloc")]
fn sign_rsa(hash: RsaHash, sk: &BoxedRsaPrivateKey, msg: &[u8]) -> Result<Vec<u8>> {
    let raw = match hash {
        RsaHash::Sha1 => sk.sign_pkcs1v15::<Sha1>(msg),
        RsaHash::Sha256 => sk.sign_pkcs1v15::<Sha256>(msg),
        RsaHash::Sha512 => sk.sign_pkcs1v15::<Sha512>(msg),
    }
    .map_err(|_| Error::Crypto("rsa: signing failed"))?;

    let mut w = Writer::with_capacity(4 + hash.algorithm().len() + 4 + raw.len());
    w.write_string(hash.algorithm().as_bytes());
    w.write_string(&raw);
    Ok(w.into_vec())
}

#[cfg(feature = "alloc")]
fn verify_rsa(
    hash: RsaHash,
    pk: &BoxedRsaPublicKey,
    k: usize,
    msg: &[u8],
    sig_blob: &[u8],
) -> Result<()> {
    let mut r = Reader::new(sig_blob);
    let name = r.read_string()?;
    if name != hash.algorithm().as_bytes() {
        return Err(Error::Format("rsa: signature algorithm mismatch"));
    }
    let raw = r.read_string()?;
    if !r.is_empty() {
        return Err(Error::Format("rsa: signature trailing data"));
    }
    if raw.len() != k {
        return Err(Error::Format("rsa: signature length mismatch"));
    }
    match hash {
        RsaHash::Sha1 => pk.verify_pkcs1v15::<Sha1>(msg, raw),
        RsaHash::Sha256 => pk.verify_pkcs1v15::<Sha256>(msg, raw),
        RsaHash::Sha512 => pk.verify_pkcs1v15::<Sha512>(msg, raw),
    }
    .map_err(|_| Error::BadSignature)
}

macro_rules! rsa_host_key {
    ($name:ident, $hash:expr, $algname:expr, $doc:expr) => {
        #[cfg(feature = "alloc")]
        #[doc = $doc]
        pub struct $name {
            private: Option<BoxedRsaPrivateKey>,
            public: BoxedRsaPublicKey,
            k: usize,
        }

        #[cfg(feature = "alloc")]
        impl $name {
            /// Build a host key from its `(n, e, d)` components.
            ///
            /// Without the prime factors `(p, q)`, base-blinding is disabled
            /// on the private path — see `BoxedRsaPrivateKey::from_components`.
            pub fn from_components(
                n: BoxedUint,
                e: BoxedUint,
                d: BoxedUint,
            ) -> Result<Self> {
                let public = BoxedRsaPublicKey::try_new(n.clone(), e.clone())
                    .map_err(|_| Error::Crypto("rsa: modulus out of accepted range"))?;
                let k = n.bit_len().div_ceil(8);
                let private = BoxedRsaPrivateKey::from_components(n, e, d);
                Ok(Self {
                    private: Some(private),
                    public,
                    k,
                })
            }

            /// Build a verifier-only host key from `(n, e)`.
            pub fn from_public_components(n: BoxedUint, e: BoxedUint) -> Result<Self> {
                let k = n.bit_len().div_ceil(8);
                let public = BoxedRsaPublicKey::try_new(n, e)
                    .map_err(|_| Error::Crypto("rsa: modulus out of accepted range"))?;
                Ok(Self { private: None, public, k })
            }

            /// The modulus byte length (`k` per PKCS#1).
            pub fn modulus_bytes(&self) -> usize {
                self.k
            }
        }

        #[cfg(feature = "alloc")]
        impl HostKey for $name {
            fn algorithm(&self) -> &'static str {
                $algname
            }

            fn public_blob(&self) -> Vec<u8> {
                build_rsa_public_blob(&self.public)
            }

            fn sign(&self, msg: &[u8]) -> Result<Vec<u8>> {
                let sk = self
                    .private
                    .as_ref()
                    .ok_or(Error::Crypto("rsa: no private key"))?;
                sign_rsa($hash, sk, msg)
            }
        }

        #[cfg(feature = "alloc")]
        impl HostKeyVerify for $name {
            fn algorithm(&self) -> &'static str {
                $algname
            }

            fn verify(&self, msg: &[u8], sig_blob: &[u8]) -> Result<()> {
                verify_rsa($hash, &self.public, self.k, msg, sig_blob)
            }

            fn from_public_blob(blob: &[u8]) -> Result<Self> {
                let (public, k) = parse_rsa_public_blob(blob)?;
                Ok(Self { private: None, public, k })
            }
        }
    };
}

rsa_host_key!(
    RsaSha1HostKey,
    RsaHash::Sha1,
    SshRsa::NAME,
    "RSA host key signing with `ssh-rsa` (RSA + SHA-1)."
);
rsa_host_key!(
    RsaSha2_256HostKey,
    RsaHash::Sha256,
    RsaSha2_256::NAME,
    "RSA host key signing with `rsa-sha2-256` (RSA + SHA-256)."
);
rsa_host_key!(
    RsaSha2_512HostKey,
    RsaHash::Sha512,
    RsaSha2_512::NAME,
    "RSA host key signing with `rsa-sha2-512` (RSA + SHA-512)."
);

#[cfg(all(test, feature = "alloc"))]
mod tests {
    use super::*;

    fn known_n_e() -> (BoxedUint, BoxedUint) {
        let mut n_bytes = alloc::vec![0u8; 256];
        n_bytes[0] = 0xc0;
        for (i, b) in n_bytes.iter_mut().enumerate().skip(1) {
            *b = (i as u8).wrapping_mul(31).wrapping_add(7) | 0x01;
        }
        let n = BoxedUint::from_be_bytes(&n_bytes);
        let e = BoxedUint::from_u64(65537);
        (n, e)
    }

    #[test]
    fn rsa_public_blob_roundtrip() {
        let (n, e) = known_n_e();
        let hk = RsaSha2_256HostKey::from_public_components(n.clone(), e.clone()).unwrap();
        let blob = hk.public_blob();

        let parsed = RsaSha2_256HostKey::from_public_blob(&blob).unwrap();
        let mut r = Reader::new(&blob);
        let name = r.read_string().unwrap();
        assert_eq!(name, SshRsa::NAME.as_bytes());
        let e_raw = read_mpint(&mut r).unwrap();
        let n_raw = read_mpint(&mut r).unwrap();
        assert_eq!(mpint_to_uint(e_raw).unwrap().to_be_bytes(3), e.to_be_bytes(3));
        assert_eq!(
            mpint_to_uint(n_raw).unwrap().to_be_bytes(256),
            n.to_be_bytes(256)
        );
        assert_eq!(parsed.modulus_bytes(), hk.modulus_bytes());
    }

    #[test]
    fn rsa_signature_blob_format_smoke() {
        let (n, e) = known_n_e();
        let pk = RsaSha2_256HostKey::from_public_components(n, e).unwrap();
        let mut bogus = Writer::new();
        bogus.write_string(b"rsa-sha2-256");
        bogus.write_string(&alloc::vec![0u8; pk.modulus_bytes()]);
        assert!(matches!(
            pk.verify(b"x", &bogus.into_vec()),
            Err(Error::BadSignature)
        ));
    }

    #[test]
    fn rsa_signature_rejects_wrong_algorithm_name() {
        let (n, e) = known_n_e();
        let pk = RsaSha2_256HostKey::from_public_components(n, e).unwrap();
        let mut bad = Writer::new();
        bad.write_string(b"ssh-rsa");
        bad.write_string(&alloc::vec![0u8; pk.modulus_bytes()]);
        assert!(matches!(
            pk.verify(b"x", &bad.into_vec()),
            Err(Error::Format(_))
        ));
    }

    #[test]
    fn rsa_signature_rejects_wrong_length() {
        let (n, e) = known_n_e();
        let pk = RsaSha2_256HostKey::from_public_components(n, e).unwrap();
        let mut bad = Writer::new();
        bad.write_string(b"rsa-sha2-256");
        bad.write_string(&alloc::vec![0u8; 1]);
        assert!(matches!(
            pk.verify(b"x", &bad.into_vec()),
            Err(Error::Format(_))
        ));
    }

    #[test]
    fn rsa_public_blob_uses_ssh_rsa_for_all_hashes() {
        let (n, e) = known_n_e();
        let s256 = RsaSha2_256HostKey::from_public_components(n.clone(), e.clone()).unwrap();
        let s512 = RsaSha2_512HostKey::from_public_components(n.clone(), e.clone()).unwrap();
        let s1 = RsaSha1HostKey::from_public_components(n, e).unwrap();
        assert_eq!(s256.public_blob(), s512.public_blob());
        assert_eq!(s256.public_blob(), s1.public_blob());
    }
}
