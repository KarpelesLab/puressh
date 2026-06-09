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
use alloc::boxed::Box;
#[cfg(feature = "alloc")]
use alloc::vec::Vec;
#[cfg(feature = "alloc")]
use purecrypto::bignum::BoxedUint;
#[cfg(feature = "alloc")]
use purecrypto::hash::{Sha1, Sha256, Sha512};
#[cfg(feature = "alloc")]
use purecrypto::rsa::{BoxedRsaPrivateKey, BoxedRsaPublicKey};

#[cfg(feature = "alloc")]
use super::{HostKey, HostKeyVerify};
#[cfg(feature = "alloc")]
use crate::error::{Error, Result};
#[cfg(feature = "alloc")]
use crate::format::{read_mpint, write_mpint, Reader, Writer};

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
    // Enforce a 2048-bit minimum modulus. purecrypto's BoxedRsaPublicKey
    // accepts anything down to ~1024 bits, but 1024-bit RSA is considered
    // broken for SSH host-key authentication (NIST SP 800-131A withdrew it
    // and OpenSSH 7.6+ rejects shorter-than-2048 by default). We refuse
    // here at parse time rather than at verify time so callers cannot hold
    // a `dyn HostKeyVerify` for a key that will never be safely usable.
    if n.bit_len() < 2048 {
        return Err(Error::Format("rsa: modulus shorter than 2048 bits"));
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
    ($name:ident, $hash:expr, $algname:expr, $doc:expr, $upgrade:expr) => {
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
            pub fn from_components(n: BoxedUint, e: BoxedUint, d: BoxedUint) -> Result<Self> {
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
                Ok(Self {
                    private: None,
                    public,
                    k,
                })
            }

            /// The modulus byte length (`k` per PKCS#1).
            pub fn modulus_bytes(&self) -> usize {
                self.k
            }

            /// Build a same-key variant of a sibling RSA host key type
            /// (used by `upgraded_for` to promote `ssh-rsa` → `rsa-sha2-*`
            /// over the same `(n, e[, d])` material).
            #[doc(hidden)]
            #[allow(dead_code)]
            pub(crate) fn from_rsa_parts(
                private: Option<BoxedRsaPrivateKey>,
                public: BoxedRsaPublicKey,
                k: usize,
            ) -> Self {
                Self { private, public, k }
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

            fn upgraded_for(&self, server_sig_algs: &str) -> Option<Box<dyn HostKey>> {
                #[allow(clippy::redundant_closure_call)]
                ($upgrade)(self, server_sig_algs)
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
                Ok(Self {
                    private: None,
                    public,
                    k,
                })
            }
        }
    };
}

/// Returns the preferred RSA SHA-2 algorithm name (`rsa-sha2-512` first,
/// then `rsa-sha2-256`) that the server advertised in its
/// `server-sig-algs`, or `None` if neither is available. Pure parsing —
/// no side effects.
#[cfg(feature = "alloc")]
fn preferred_rsa_sha2(server_sig_algs: &str) -> Option<&'static str> {
    let mut has_512 = false;
    let mut has_256 = false;
    for algo in server_sig_algs.split(',') {
        match algo.trim() {
            "rsa-sha2-512" => has_512 = true,
            "rsa-sha2-256" => has_256 = true,
            _ => {}
        }
    }
    if has_512 {
        Some(RsaSha2_512::NAME)
    } else if has_256 {
        Some(RsaSha2_256::NAME)
    } else {
        None
    }
}

/// Clone an RSA host key's inner `(private, public, k)` triple so a
/// sibling variant (e.g. SHA-1 → SHA-512 over the same key) can be
/// constructed from the same material.
#[cfg(feature = "alloc")]
fn clone_rsa_parts(
    private: &Option<BoxedRsaPrivateKey>,
    public: &BoxedRsaPublicKey,
    k: usize,
) -> (Option<BoxedRsaPrivateKey>, BoxedRsaPublicKey, usize) {
    (private.clone(), public.clone(), k)
}

rsa_host_key!(
    RsaSha1HostKey,
    RsaHash::Sha1,
    SshRsa::NAME,
    "RSA host key signing with `ssh-rsa` (RSA + SHA-1).",
    (|this: &RsaSha1HostKey, sig_algs: &str| -> Option<Box<dyn HostKey>> {
        let name = preferred_rsa_sha2(sig_algs)?;
        let (private, public, k) = clone_rsa_parts(&this.private, &this.public, this.k);
        match name {
            "rsa-sha2-512" => Some(
                Box::new(RsaSha2_512HostKey::from_rsa_parts(private, public, k))
                    as Box<dyn HostKey>,
            ),
            "rsa-sha2-256" => Some(
                Box::new(RsaSha2_256HostKey::from_rsa_parts(private, public, k))
                    as Box<dyn HostKey>,
            ),
            _ => None,
        }
    })
);
rsa_host_key!(
    RsaSha2_256HostKey,
    RsaHash::Sha256,
    RsaSha2_256::NAME,
    "RSA host key signing with `rsa-sha2-256` (RSA + SHA-256).",
    (|_: &RsaSha2_256HostKey, _: &str| -> Option<Box<dyn HostKey>> { None })
);
rsa_host_key!(
    RsaSha2_512HostKey,
    RsaHash::Sha512,
    RsaSha2_512::NAME,
    "RSA host key signing with `rsa-sha2-512` (RSA + SHA-512).",
    (|_: &RsaSha2_512HostKey, _: &str| -> Option<Box<dyn HostKey>> { None })
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
        assert_eq!(
            mpint_to_uint(e_raw).unwrap().to_be_bytes(3),
            e.to_be_bytes(3)
        );
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
    fn rsa_parse_rejects_short_modulus() {
        // 1024-bit modulus encoded as a public blob: must be refused by the
        // 2048-bit floor in parse_rsa_public_blob.
        let mut n_bytes = alloc::vec![0u8; 128];
        n_bytes[0] = 0xc0;
        for (i, b) in n_bytes.iter_mut().enumerate().skip(1) {
            *b = (i as u8).wrapping_mul(31).wrapping_add(7) | 0x01;
        }
        let n = BoxedUint::from_be_bytes(&n_bytes);
        let e = BoxedUint::from_u64(65537);
        let hk = RsaSha2_256HostKey::from_public_components(n, e).unwrap();
        let blob = hk.public_blob();
        match RsaSha2_256HostKey::from_public_blob(&blob) {
            Err(Error::Format(msg)) => assert!(
                msg.contains("2048"),
                "expected 2048-bit floor error, got {msg:?}"
            ),
            Err(other) => panic!("expected Format(2048), got {other:?}"),
            Ok(_) => panic!("expected 1024-bit modulus to be rejected"),
        }
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

    #[test]
    fn rsa_sha1_upgrades_to_sha512_when_server_advertises_it() {
        let (n, e) = known_n_e();
        let s1 = RsaSha1HostKey::from_public_components(n.clone(), e.clone()).unwrap();
        let expected_blob = s1.public_blob();
        let upgraded = s1
            .upgraded_for("rsa-sha2-512,rsa-sha2-256,ssh-ed25519")
            .expect("server advertises rsa-sha2-512, must upgrade");
        assert_eq!(upgraded.algorithm(), "rsa-sha2-512");
        // The public blob is identical for ssh-rsa / rsa-sha2-{256,512}
        // (RFC 8332 §3) — proves we're reusing the same RSA key.
        assert_eq!(upgraded.public_blob(), expected_blob);
    }

    #[test]
    fn rsa_sha1_upgrades_to_sha256_when_only_256_advertised() {
        let (n, e) = known_n_e();
        let s1 = RsaSha1HostKey::from_public_components(n, e).unwrap();
        let upgraded = s1
            .upgraded_for("rsa-sha2-256,ssh-ed25519")
            .expect("server advertises rsa-sha2-256, must upgrade");
        assert_eq!(upgraded.algorithm(), "rsa-sha2-256");
    }

    #[test]
    fn rsa_sha1_no_upgrade_when_server_only_offers_ssh_rsa() {
        let (n, e) = known_n_e();
        let s1 = RsaSha1HostKey::from_public_components(n, e).unwrap();
        assert!(
            s1.upgraded_for("ssh-rsa,ssh-ed25519").is_none(),
            "no rsa-sha2-{{256,512}} on the server: must not upgrade",
        );
    }

    #[test]
    fn rsa_sha1_no_upgrade_when_server_sig_algs_empty() {
        let (n, e) = known_n_e();
        let s1 = RsaSha1HostKey::from_public_components(n, e).unwrap();
        assert!(s1.upgraded_for("").is_none());
    }

    #[test]
    fn rsa_sha1_prefers_sha512_over_sha256_when_both_advertised() {
        // Order-independent: server can list them in any order, we still
        // pick the strongest available.
        let (n, e) = known_n_e();
        let s1 = RsaSha1HostKey::from_public_components(n, e).unwrap();
        let upgraded = s1
            .upgraded_for("rsa-sha2-256,rsa-sha2-512")
            .expect("must upgrade");
        assert_eq!(upgraded.algorithm(), "rsa-sha2-512");
    }

    #[test]
    fn rsa_sha2_256_signer_does_not_upgrade() {
        let (n, e) = known_n_e();
        let s256 = RsaSha2_256HostKey::from_public_components(n, e).unwrap();
        // Even when the server advertises sha2-512, the typed
        // RsaSha2_256HostKey deliberately stays put — the caller picked
        // 256 explicitly, and the auth layer's exact-match path
        // already keeps it as-is.
        assert!(s256.upgraded_for("rsa-sha2-512").is_none());
    }

    #[test]
    fn rsa_sha2_512_signer_does_not_upgrade() {
        let (n, e) = known_n_e();
        let s512 = RsaSha2_512HostKey::from_public_components(n, e).unwrap();
        assert!(s512.upgraded_for("rsa-sha2-512,rsa-sha2-256").is_none());
    }
}
