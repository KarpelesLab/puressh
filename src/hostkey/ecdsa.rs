//! `ecdsa-sha2-nistp{256,384,521}` (RFC 5656) — ECDSA host keys.
//!
//! Backed by [`purecrypto::ec::boxed`] (runtime-dispatched ECDSA over the
//! three NIST primes).

use super::HostKeyAlgorithm;

#[cfg(feature = "alloc")]
use alloc::vec::Vec;
#[cfg(feature = "alloc")]
use purecrypto::bignum::BoxedUint;
#[cfg(feature = "alloc")]
use purecrypto::ec::{BoxedEcdsaPrivateKey, BoxedEcdsaPublicKey, BoxedEcdsaSignature, CurveId};
#[cfg(feature = "alloc")]
use purecrypto::hash::{Sha256, Sha384, Sha512};

#[cfg(feature = "alloc")]
use super::{HostKey, HostKeyVerify};
#[cfg(feature = "alloc")]
use crate::error::{Error, Result};
#[cfg(feature = "alloc")]
use crate::format::{read_mpint, write_mpint, Reader, Writer};

/// `ecdsa-sha2-nistp256`.
pub struct EcdsaP256;
impl HostKeyAlgorithm for EcdsaP256 {
    const NAME: &'static str = "ecdsa-sha2-nistp256";
}

/// `ecdsa-sha2-nistp384`.
pub struct EcdsaP384;
impl HostKeyAlgorithm for EcdsaP384 {
    const NAME: &'static str = "ecdsa-sha2-nistp384";
}

/// `ecdsa-sha2-nistp521`.
pub struct EcdsaP521;
impl HostKeyAlgorithm for EcdsaP521 {
    const NAME: &'static str = "ecdsa-sha2-nistp521";
}

#[cfg(feature = "alloc")]
#[derive(Clone, Copy)]
enum EcdsaHash {
    Sha256,
    Sha384,
    Sha512,
}

#[cfg(feature = "alloc")]
struct EcdsaParams {
    algorithm: &'static str,
    curve_id_str: &'static str,
    curve: CurveId,
    hash: EcdsaHash,
}

#[cfg(feature = "alloc")]
const P256_PARAMS: EcdsaParams = EcdsaParams {
    algorithm: EcdsaP256::NAME,
    curve_id_str: "nistp256",
    curve: CurveId::P256,
    hash: EcdsaHash::Sha256,
};

#[cfg(feature = "alloc")]
const P384_PARAMS: EcdsaParams = EcdsaParams {
    algorithm: EcdsaP384::NAME,
    curve_id_str: "nistp384",
    curve: CurveId::P384,
    hash: EcdsaHash::Sha384,
};

#[cfg(feature = "alloc")]
const P521_PARAMS: EcdsaParams = EcdsaParams {
    algorithm: EcdsaP521::NAME,
    curve_id_str: "nistp521",
    curve: CurveId::P521,
    hash: EcdsaHash::Sha512,
};

#[cfg(feature = "alloc")]
fn build_public_blob(params: &EcdsaParams, sec1: &[u8]) -> Vec<u8> {
    let mut w = Writer::new();
    w.write_string(params.algorithm.as_bytes());
    w.write_string(params.curve_id_str.as_bytes());
    w.write_string(sec1);
    w.into_vec()
}

#[cfg(feature = "alloc")]
fn parse_public_blob(params: &EcdsaParams, blob: &[u8]) -> Result<BoxedEcdsaPublicKey> {
    let mut r = Reader::new(blob);
    let name = r.read_string()?;
    if name != params.algorithm.as_bytes() {
        return Err(Error::Format("ecdsa: public key type mismatch"));
    }
    let curve = r.read_string()?;
    if curve != params.curve_id_str.as_bytes() {
        return Err(Error::Format("ecdsa: curve identifier mismatch"));
    }
    let sec1 = r.read_string()?;
    if !r.is_empty() {
        return Err(Error::Format("ecdsa: public key trailing data"));
    }
    BoxedEcdsaPublicKey::from_sec1(params.curve, sec1)
        .map_err(|_| Error::Format("ecdsa: invalid SEC1 point"))
}

#[cfg(feature = "alloc")]
fn sign_with(params: &EcdsaParams, priv_key: &BoxedEcdsaPrivateKey, msg: &[u8]) -> Result<Vec<u8>> {
    let sig = match params.hash {
        EcdsaHash::Sha256 => priv_key.sign::<Sha256>(msg),
        EcdsaHash::Sha384 => priv_key.sign::<Sha384>(msg),
        EcdsaHash::Sha512 => priv_key.sign::<Sha512>(msg),
    }
    .map_err(|_| Error::Crypto("ecdsa: signing failed"))?;
    Ok(encode_signature(params, &sig))
}

#[cfg(feature = "alloc")]
fn encode_signature(params: &EcdsaParams, sig: &BoxedEcdsaSignature) -> Vec<u8> {
    let r_bytes = sig.r_bytes(params.curve);
    let s_bytes = sig.s_bytes(params.curve);

    let mut inner = Writer::new();
    write_mpint(&mut inner, &r_bytes);
    write_mpint(&mut inner, &s_bytes);
    let inner = inner.into_vec();

    let mut outer = Writer::with_capacity(4 + params.algorithm.len() + 4 + inner.len());
    outer.write_string(params.algorithm.as_bytes());
    outer.write_string(&inner);
    outer.into_vec()
}

#[cfg(feature = "alloc")]
fn verify_with(
    params: &EcdsaParams,
    pub_key: &BoxedEcdsaPublicKey,
    msg: &[u8],
    sig_blob: &[u8],
) -> Result<()> {
    let mut r = Reader::new(sig_blob);
    let name = r.read_string()?;
    if name != params.algorithm.as_bytes() {
        return Err(Error::Format("ecdsa: signature algorithm mismatch"));
    }
    let inner = r.read_string()?;
    if !r.is_empty() {
        return Err(Error::Format("ecdsa: signature trailing data"));
    }
    let mut ir = Reader::new(inner);
    let r_raw = read_mpint(&mut ir)?;
    let s_raw = read_mpint(&mut ir)?;
    if !ir.is_empty() {
        return Err(Error::Format("ecdsa: signature blob trailing data"));
    }

    let r_uint = mpint_to_uint(r_raw)?;
    let s_uint = mpint_to_uint(s_raw)?;
    let sig = BoxedEcdsaSignature::from_components(r_uint, s_uint);

    match params.hash {
        EcdsaHash::Sha256 => pub_key.verify::<Sha256>(msg, &sig),
        EcdsaHash::Sha384 => pub_key.verify::<Sha384>(msg, &sig),
        EcdsaHash::Sha512 => pub_key.verify::<Sha512>(msg, &sig),
    }
    .map_err(|_| Error::BadSignature)
}

#[cfg(feature = "alloc")]
fn mpint_to_uint(bytes: &[u8]) -> Result<BoxedUint> {
    if bytes.is_empty() {
        return Ok(BoxedUint::from_u64(0));
    }
    if (bytes[0] & 0x80) != 0 {
        return Err(Error::Format("ecdsa: negative mpint in signature"));
    }
    let mut start = 0usize;
    while start + 1 < bytes.len() && bytes[start] == 0 {
        start += 1;
    }
    Ok(BoxedUint::from_be_bytes(&bytes[start..]))
}

macro_rules! ecdsa_host_key {
    ($name:ident, $params:ident) => {
        #[cfg(feature = "alloc")]
        #[doc = concat!("Host key for `", stringify!($params), "`.")]
        pub struct $name {
            private: Option<BoxedEcdsaPrivateKey>,
            public: BoxedEcdsaPublicKey,
        }

        #[cfg(feature = "alloc")]
        impl $name {
            /// Build a host key from a raw scalar.
            pub fn from_scalar(scalar: &[u8]) -> Result<Self> {
                let private = BoxedEcdsaPrivateKey::from_bytes($params.curve, scalar)
                    .map_err(|_| Error::Crypto("ecdsa: invalid private scalar"))?;
                let public = private.public_key();
                Ok(Self {
                    private: Some(private),
                    public,
                })
            }

            /// Build a verifier-only host key from an uncompressed SEC1 point.
            pub fn from_sec1(point: &[u8]) -> Result<Self> {
                let public = BoxedEcdsaPublicKey::from_sec1($params.curve, point)
                    .map_err(|_| Error::Format("ecdsa: invalid SEC1 point"))?;
                Ok(Self {
                    private: None,
                    public,
                })
            }

            /// The SEC1 uncompressed-point encoding of the public key.
            pub fn public_sec1(&self) -> Vec<u8> {
                self.public.to_sec1()
            }
        }

        #[cfg(feature = "alloc")]
        impl HostKey for $name {
            fn algorithm(&self) -> &'static str {
                $params.algorithm
            }

            fn public_blob(&self) -> Vec<u8> {
                build_public_blob(&$params, &self.public.to_sec1())
            }

            fn sign(&self, msg: &[u8]) -> Result<Vec<u8>> {
                let sk = self
                    .private
                    .as_ref()
                    .ok_or(Error::Crypto("ecdsa: no private key"))?;
                sign_with(&$params, sk, msg)
            }
        }

        #[cfg(feature = "alloc")]
        impl HostKeyVerify for $name {
            fn algorithm(&self) -> &'static str {
                $params.algorithm
            }

            fn verify(&self, msg: &[u8], sig_blob: &[u8]) -> Result<()> {
                verify_with(&$params, &self.public, msg, sig_blob)
            }

            fn from_public_blob(blob: &[u8]) -> Result<Self> {
                let public = parse_public_blob(&$params, blob)?;
                Ok(Self {
                    private: None,
                    public,
                })
            }
        }
    };
}

ecdsa_host_key!(EcdsaP256HostKey, P256_PARAMS);
ecdsa_host_key!(EcdsaP384HostKey, P384_PARAMS);
ecdsa_host_key!(EcdsaP521HostKey, P521_PARAMS);

#[cfg(all(test, feature = "alloc"))]
mod tests {
    use super::*;

    fn known_scalar(curve: CurveId) -> Vec<u8> {
        let len = match curve {
            CurveId::P256 => 32,
            CurveId::P384 => 48,
            CurveId::P521 => 66,
            _ => unreachable!(),
        };
        let mut v = alloc::vec![0u8; len];
        v[len - 1] = 0x42;
        v
    }

    #[test]
    fn p256_public_blob_roundtrip() {
        let hk = EcdsaP256HostKey::from_scalar(&known_scalar(CurveId::P256)).unwrap();
        let blob = hk.public_blob();
        let parsed = EcdsaP256HostKey::from_public_blob(&blob).unwrap();
        assert_eq!(parsed.public_sec1(), hk.public_sec1());
    }

    #[test]
    fn p256_sign_verify_roundtrip() {
        let hk = EcdsaP256HostKey::from_scalar(&known_scalar(CurveId::P256)).unwrap();
        let sig = hk.sign(b"hello p256").unwrap();
        hk.verify(b"hello p256", &sig).unwrap();
        assert!(hk.verify(b"hello P256", &sig).is_err());
    }

    #[test]
    fn p384_sign_verify_roundtrip() {
        let hk = EcdsaP384HostKey::from_scalar(&known_scalar(CurveId::P384)).unwrap();
        let sig = hk.sign(b"hello p384").unwrap();
        hk.verify(b"hello p384", &sig).unwrap();
        let blob = hk.public_blob();
        let parsed = EcdsaP384HostKey::from_public_blob(&blob).unwrap();
        parsed.verify(b"hello p384", &sig).unwrap();
    }

    #[test]
    fn p521_sign_verify_roundtrip() {
        let hk = EcdsaP521HostKey::from_scalar(&known_scalar(CurveId::P521)).unwrap();
        let sig = hk.sign(b"hello p521").unwrap();
        hk.verify(b"hello p521", &sig).unwrap();
        let blob = hk.public_blob();
        let parsed = EcdsaP521HostKey::from_public_blob(&blob).unwrap();
        parsed.verify(b"hello p521", &sig).unwrap();
    }

    #[test]
    fn p256_rejects_p384_curve_id() {
        let hk = EcdsaP256HostKey::from_scalar(&known_scalar(CurveId::P256)).unwrap();
        let mut bad = Writer::new();
        bad.write_string(b"ecdsa-sha2-nistp256");
        bad.write_string(b"nistp384");
        bad.write_string(&hk.public_sec1());
        assert!(EcdsaP256HostKey::from_public_blob(&bad.into_vec()).is_err());
    }
}
