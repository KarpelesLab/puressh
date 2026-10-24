//! Key formats other than OpenSSH's own, for `ssh-keygen -m`, `-e` and
//! `-i`: PKCS#1 / SEC1 ("PEM") and PKCS#8 private keys, and RFC 4716,
//! SubjectPublicKeyInfo and PKCS#1 public keys.
//!
//! Private keys are written plain or, with a passphrase, encrypted as
//! OpenSSH has OpenSSL do it (see `encrypted`).

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use purecrypto::bignum::BoxedUint;
use purecrypto::der::{
    self, encode_bit_string, encode_context, encode_integer, encode_null, encode_octet_string,
    encode_sequence, pem_encode,
};

use purecrypto::rng::{CryptoRng, RngCore};
use purecrypto::zeroize::Zeroizing;

use super::{PrivateKey, PublicKey};
use crate::error::{Error, Result};

const OID_RSA: &[u64] = &[1, 2, 840, 113549, 1, 1, 1];
const OID_EC_PUBLIC_KEY: &[u64] = &[1, 2, 840, 10045, 2, 1];
const OID_P256: &[u64] = &[1, 2, 840, 10045, 3, 1, 7];
const OID_P384: &[u64] = &[1, 3, 132, 0, 34];
const OID_P521: &[u64] = &[1, 3, 132, 0, 35];
const OID_ED25519: &[u64] = &[1, 3, 101, 112];

fn oid(arcs: &[u64]) -> Vec<u8> {
    der::oid_tlv(arcs)
}

fn trim(b: &[u8]) -> &[u8] {
    let i = b.iter().position(|x| *x != 0).unwrap_or(b.len());
    &b[i..]
}

fn seq(parts: &[&[u8]]) -> Vec<u8> {
    encode_sequence(&parts.concat())
}

/// [`seq`] over secret parts: the parts (taken as encoded), their
/// concatenation and the result are all wiped on drop.
fn secret_seq(parts: &[Zeroizing<Vec<u8>>]) -> Zeroizing<Vec<u8>> {
    let mut body = Zeroizing::new(Vec::with_capacity(parts.iter().map(|p| p.len()).sum()));
    for part in parts {
        body.extend_from_slice(part);
    }
    Zeroizing::new(encode_sequence(&body))
}

/// A secret-bearing DER encoding, wiped on drop.
fn secret(der: Vec<u8>) -> Zeroizing<Vec<u8>> {
    Zeroizing::new(der)
}

fn curve_oid(pk: &PrivateKey) -> Option<(&'static [u64], usize)> {
    match pk {
        PrivateKey::EcdsaP256 { .. } => Some((OID_P256, 32)),
        PrivateKey::EcdsaP384 { .. } => Some((OID_P384, 48)),
        PrivateKey::EcdsaP521 { .. } => Some((OID_P521, 66)),
        _ => None,
    }
}

/// `d mod (p - 1)` and `d mod (q - 1)`, the PKCS#1 CRT exponents.
fn crt_exponents(d: &[u8], p: &[u8], q: &[u8]) -> (Zeroizing<Vec<u8>>, Zeroizing<Vec<u8>>) {
    let d = BoxedUint::from_be_bytes(trim(d));
    let one = BoxedUint::from_be_bytes(&[1]);
    let reduce = |prime: &[u8]| {
        let m = BoxedUint::from_be_bytes(trim(prime)).sub(&one);
        Zeroizing::new(d.reduce(&m).to_be_bytes(prime.len()))
    };
    (reduce(p), reduce(q))
}

impl PrivateKey {
    fn pkcs1_der(&self) -> Result<Zeroizing<Vec<u8>>> {
        let PrivateKey::Rsa {
            n,
            e,
            d,
            p,
            q,
            iqmp,
            ..
        } = self
        else {
            return Err(Error::Unsupported("PKCS#1 is for RSA keys"));
        };
        if trim(p).is_empty() || trim(q).is_empty() {
            return Err(Error::Unsupported("RSA key without its primes"));
        }
        let (dp, dq) = crt_exponents(d, p, q);
        Ok(secret_seq(&[
            secret(encode_integer(&[0])),
            secret(encode_integer(n)),
            secret(encode_integer(e)),
            secret(encode_integer(d)),
            secret(encode_integer(p)),
            secret(encode_integer(q)),
            secret(encode_integer(&dp)),
            secret(encode_integer(&dq)),
            secret(encode_integer(iqmp)),
        ]))
    }

    /// SEC1 `ECPrivateKey`; `with_params` adds the curve (the standalone
    /// form does, the PKCS#8-wrapped one does not).
    fn sec1_der(&self, with_params: bool) -> Result<Zeroizing<Vec<u8>>> {
        let (d, point) = match self {
            PrivateKey::EcdsaP256 { d, point, .. }
            | PrivateKey::EcdsaP384 { d, point, .. }
            | PrivateKey::EcdsaP521 { d, point, .. } => (d, point),
            _ => return Err(Error::Unsupported("SEC1 is for ECDSA keys")),
        };
        let (curve, len) = curve_oid(self).expect("ECDSA");
        let d = trim(d);
        if d.len() > len {
            return Err(Error::Format("ECDSA scalar too long"));
        }
        let mut scalar = Zeroizing::new(Vec::with_capacity(len));
        scalar.resize(len - d.len(), 0);
        scalar.extend_from_slice(d);
        let mut parts = alloc::vec![
            secret(encode_integer(&[1])),
            secret(encode_octet_string(&scalar)),
        ];
        if with_params {
            parts.push(secret(encode_context(0, &oid(curve))));
        }
        parts.push(secret(encode_context(1, &encode_bit_string(point))));
        Ok(secret_seq(&parts))
    }

    /// OpenSSH's `-m PEM`: PKCS#1 `RSA PRIVATE KEY` or SEC1 `EC PRIVATE
    /// KEY`. Ed25519 keys have no such form.
    pub fn to_traditional_pem(&self) -> Result<String> {
        match self {
            PrivateKey::Rsa { .. } => Ok(pem_encode("RSA PRIVATE KEY", &self.pkcs1_der()?)),
            PrivateKey::Ed25519 { .. } => Err(Error::Unsupported(
                "Ed25519 keys have no PEM form; use PKCS8",
            )),
            _ => Ok(pem_encode("EC PRIVATE KEY", &self.sec1_der(true)?)),
        }
    }

    /// [`Self::to_traditional_pem`], encrypted with `passphrase`
    /// (AES-128-CBC, `DEK-Info` headers).
    pub fn to_traditional_pem_encrypted<R: CryptoRng + RngCore>(
        &self,
        rng: &mut R,
        passphrase: &[u8],
    ) -> Result<String> {
        let (label, der) = match self {
            PrivateKey::Rsa { .. } => ("RSA PRIVATE KEY", self.pkcs1_der()?),
            PrivateKey::Ed25519 { .. } => {
                return Err(Error::Unsupported(
                    "Ed25519 keys have no PEM form; use PKCS8",
                ));
            }
            _ => ("EC PRIVATE KEY", self.sec1_der(true)?),
        };
        Ok(super::encrypted::encrypt_traditional(
            rng, label, &der, passphrase,
        ))
    }

    /// [`Self::to_pkcs8_pem`], encrypted with `passphrase`: an
    /// `ENCRYPTED PRIVATE KEY` (PBES2).
    pub fn to_pkcs8_pem_encrypted<R: CryptoRng + RngCore>(
        &self,
        rng: &mut R,
        passphrase: &[u8],
    ) -> Result<String> {
        let der = super::encrypted::encrypt_pkcs8(rng, &self.pkcs8_der()?, passphrase);
        Ok(pem_encode("ENCRYPTED PRIVATE KEY", &der))
    }

    /// PKCS#8 `PRIVATE KEY` (OpenSSH's `-m PKCS8`).
    pub fn to_pkcs8_pem(&self) -> Result<String> {
        Ok(pem_encode("PRIVATE KEY", &self.pkcs8_der()?))
    }

    /// The PKCS#8 `PrivateKeyInfo` DER.
    fn pkcs8_der(&self) -> Result<Zeroizing<Vec<u8>>> {
        let (alg, inner) = match self {
            PrivateKey::Rsa { .. } => (seq(&[&oid(OID_RSA), &encode_null()]), self.pkcs1_der()?),
            PrivateKey::Ed25519 { seed, .. } => {
                (seq(&[&oid(OID_ED25519)]), secret(encode_octet_string(seed)))
            }
            _ => {
                let (curve, _) = curve_oid(self).expect("ECDSA");
                (
                    seq(&[&oid(OID_EC_PUBLIC_KEY), &oid(curve)]),
                    self.sec1_der(false)?,
                )
            }
        };
        Ok(secret_seq(&[
            secret(encode_integer(&[0])),
            secret(alg),
            secret(encode_octet_string(&inner)),
        ]))
    }
}

/// OpenSSH's label for `-e` comments and `ssh-keygen -l` (`RSA`, …).
fn type_label(pk: &PublicKey) -> &'static str {
    match pk {
        PublicKey::Ed25519 { .. } => "ED25519",
        PublicKey::Rsa { .. } => "RSA",
        PublicKey::MlDsa44Ed25519 { .. } => "MLDSA44-ED25519",
        _ => "ECDSA",
    }
}

impl PublicKey {
    /// RFC 4716 (`---- BEGIN SSH2 PUBLIC KEY ----`), with OpenSSH's comment
    /// line `"<bits>-bit <TYPE>, converted by <who> from OpenSSH"`.
    pub fn to_rfc4716(&self, converted_by: &str) -> String {
        let b64 = super::base64::encode(&self.wire_blob());
        let mut out = String::from("---- BEGIN SSH2 PUBLIC KEY ----\n");
        out.push_str(&format!(
            "Comment: \"{}-bit {}, converted by {converted_by} from OpenSSH\"\n",
            self.bit_length(),
            type_label(self)
        ));
        for chunk in b64.as_bytes().chunks(70) {
            out.push_str(core::str::from_utf8(chunk).unwrap_or_default());
            out.push('\n');
        }
        out.push_str("---- END SSH2 PUBLIC KEY ----\n");
        out
    }

    fn spki_der(&self) -> Option<Vec<u8>> {
        let (alg, key) = match self {
            PublicKey::Rsa { n, e, .. } => (
                seq(&[&oid(OID_RSA), &encode_null()]),
                seq(&[&encode_integer(n), &encode_integer(e)]),
            ),
            PublicKey::Ed25519 { raw, .. } => (seq(&[&oid(OID_ED25519)]), raw.to_vec()),
            PublicKey::EcdsaP256 { point, .. } => (
                seq(&[&oid(OID_EC_PUBLIC_KEY), &oid(OID_P256)]),
                point.clone(),
            ),
            PublicKey::EcdsaP384 { point, .. } => (
                seq(&[&oid(OID_EC_PUBLIC_KEY), &oid(OID_P384)]),
                point.clone(),
            ),
            PublicKey::EcdsaP521 { point, .. } => (
                seq(&[&oid(OID_EC_PUBLIC_KEY), &oid(OID_P521)]),
                point.clone(),
            ),
            PublicKey::MlDsa44Ed25519 { .. } => return None,
        };
        Some(seq(&[&alg, &encode_bit_string(&key)]))
    }

    /// SubjectPublicKeyInfo `PUBLIC KEY` (`-e -m PKCS8`). Empty for a key
    /// type without one (the ML-DSA composite).
    pub fn to_spki_pem(&self) -> String {
        self.spki_der()
            .map(|der| pem_encode("PUBLIC KEY", &der))
            .unwrap_or_default()
    }

    /// `-e -m PEM`: PKCS#1 `RSA PUBLIC KEY` for RSA; other keys have no
    /// PKCS#1 form and use SubjectPublicKeyInfo, as with OpenSSH.
    pub fn to_pem(&self) -> String {
        match self {
            PublicKey::Rsa { n, e, .. } => pem_encode(
                "RSA PUBLIC KEY",
                &seq(&[&encode_integer(n), &encode_integer(e)]),
            ),
            _ => self.to_spki_pem(),
        }
    }

    /// Parse a public key in RFC 4716, `PUBLIC KEY` (SubjectPublicKeyInfo)
    /// or `RSA PUBLIC KEY` (PKCS#1) form (`ssh-keygen -i`).
    pub fn parse_foreign(text: &str) -> Result<Self> {
        if text.contains("---- BEGIN SSH2 PUBLIC KEY ----") {
            return Self::parse_rfc4716(text);
        }
        if text.contains("-----BEGIN RSA PUBLIC KEY-----") {
            let der = der::pem_decode(text, "RSA PUBLIC KEY")
                .map_err(|_| Error::Format("bad RSA PUBLIC KEY"))?;
            let mut r = der::Reader::new(&der);
            let mut s = r
                .read_sequence()
                .map_err(|_| Error::Format("bad RSA PUBLIC KEY"))?;
            let n = s
                .read_unsigned_integer_bytes()
                .map_err(|_| Error::Format("bad modulus"))?;
            let e = s
                .read_unsigned_integer_bytes()
                .map_err(|_| Error::Format("bad exponent"))?;
            return Self::from_rsa_parts(n, e);
        }
        if text.contains("-----BEGIN PUBLIC KEY-----") {
            let der =
                der::pem_decode(text, "PUBLIC KEY").map_err(|_| Error::Format("bad PUBLIC KEY"))?;
            return Self::from_spki_der(&der);
        }
        Err(Error::Format("not an RFC 4716, PKCS#8 or PEM public key"))
    }

    fn from_rsa_parts(n: &[u8], e: &[u8]) -> Result<Self> {
        let mut w = crate::format::Writer::new();
        w.write_string(b"ssh-rsa");
        crate::format::write_mpint(&mut w, e);
        crate::format::write_mpint(&mut w, n);
        Self::parse_wire_blob(&w.into_vec())
    }

    fn from_spki_der(der_bytes: &[u8]) -> Result<Self> {
        let bad = || Error::Format("bad SubjectPublicKeyInfo");
        let mut r = der::Reader::new(der_bytes);
        let mut spki = r.read_sequence().map_err(|_| bad())?;
        let mut alg = spki.read_sequence().map_err(|_| bad())?;
        let alg_oid = alg.read_oid().map_err(|_| bad())?;
        // The unused-bits octet is already stripped.
        let key = spki.read_bit_string().map_err(|_| bad())?;
        let is =
            |arcs: &[u64]| oid(arcs).ends_with(alg_oid) && oid(arcs).len() == alg_oid.len() + 2;
        let mut w = crate::format::Writer::new();
        if is(OID_RSA) {
            let mut k = der::Reader::new(key);
            let mut s = k.read_sequence().map_err(|_| bad())?;
            let n = s.read_unsigned_integer_bytes().map_err(|_| bad())?;
            let e = s.read_unsigned_integer_bytes().map_err(|_| bad())?;
            return Self::from_rsa_parts(n, e);
        } else if is(OID_ED25519) {
            w.write_string(b"ssh-ed25519");
            w.write_string(key);
        } else if is(OID_EC_PUBLIC_KEY) {
            let curve = alg.read_oid().map_err(|_| bad())?;
            let (name, id): (&[u8], &[u8]) = if oid(OID_P256).ends_with(curve) {
                (b"ecdsa-sha2-nistp256", b"nistp256")
            } else if oid(OID_P384).ends_with(curve) {
                (b"ecdsa-sha2-nistp384", b"nistp384")
            } else if oid(OID_P521).ends_with(curve) {
                (b"ecdsa-sha2-nistp521", b"nistp521")
            } else {
                return Err(Error::Unsupported("EC curve"));
            };
            w.write_string(name);
            w.write_string(id);
            w.write_string(key);
        } else {
            return Err(Error::Unsupported("public key algorithm"));
        }
        Self::parse_wire_blob(&w.into_vec())
    }

    fn parse_rfc4716(text: &str) -> Result<Self> {
        let start = text
            .find("---- BEGIN SSH2 PUBLIC KEY ----")
            .ok_or(Error::Format("RFC 4716: no BEGIN line"))?;
        let body = &text[start..];
        let end = body
            .find("---- END SSH2 PUBLIC KEY ----")
            .ok_or(Error::Format("RFC 4716: no END line"))?;
        let mut b64 = String::new();
        let mut continued = false;
        for line in body[..end].lines().skip(1) {
            let line = line.trim();
            // Header lines (`Tag: value`, possibly continued with `\`).
            if continued || line.contains(':') {
                continued = line.ends_with('\\');
                continue;
            }
            b64.push_str(line);
        }
        let blob = super::base64::decode(b64.as_bytes())?;
        Self::parse_wire_blob(&blob)
    }
}
