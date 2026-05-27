//! openssh-key-v1 PEM writer, key generators, and SHA-256 fingerprint.
//!
//! Mirrors the parser in `super`: encodes the binary payload, optionally
//! encrypts the inner block with `aes256-ctr` keyed by `bcrypt_pbkdf`, and
//! wraps the result in PEM at 70 columns.

use alloc::string::String;
use alloc::vec::Vec;

use purecrypto::bignum::{inv_mod_boxed, BoxedUint};
use purecrypto::cipher::{Aes256, Ctr};
use purecrypto::der::Reader as DerReader;
use purecrypto::ec::{BoxedEcdsaPrivateKey, CurveId, Ed25519PrivateKey};
use purecrypto::hash::{Digest, Sha256};
use purecrypto::kdf::bcrypt_pbkdf;
#[cfg(feature = "std")]
use purecrypto::rng::OsRng;
use purecrypto::rng::{CryptoRng, RngCore};
use purecrypto::rsa::BoxedRsaPrivateKey;

use super::{base64, PrivateKey, PublicKey, MAGIC};
use crate::error::{Error, Result};
use crate::format::{write_mpint, Writer};

/// Selectable ECDSA curve for [`PrivateKey::generate_ecdsa`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EcdsaCurve {
    /// NIST P-256.
    P256,
    /// NIST P-384.
    P384,
    /// NIST P-521.
    P521,
}

const PEM_BEGIN: &str = "-----BEGIN OPENSSH PRIVATE KEY-----";
const PEM_END: &str = "-----END OPENSSH PRIVATE KEY-----";
const PEM_WRAP: usize = 70;

const BCRYPT_ROUNDS: u32 = 16;
const SALT_LEN: usize = 16;
const KEY_LEN: usize = 32;
const IV_LEN: usize = 16;

impl PublicKey {
    /// SHA-256 fingerprint of the wire-format public-key blob, formatted as
    /// `"SHA256:<base64>"` with no `=` padding — matches `ssh-keygen -lf`.
    pub fn sha256_fingerprint(&self) -> String {
        let digest = Sha256::digest(&self.wire_blob());
        let mut s = base64::encode(&digest);
        while s.ends_with('=') {
            s.pop();
        }
        let mut out = String::with_capacity(7 + s.len());
        out.push_str("SHA256:");
        out.push_str(&s);
        out
    }

    /// Approximate "bit length" reported by `ssh-keygen -l`: the modulus bit
    /// length for RSA, the curve bit length for ECDSA, 256 for Ed25519.
    pub fn bit_length(&self) -> u32 {
        match self {
            PublicKey::Ed25519 { .. } => 256,
            PublicKey::EcdsaP256 { .. } => 256,
            PublicKey::EcdsaP384 { .. } => 384,
            PublicKey::EcdsaP521 { .. } => 521,
            PublicKey::Rsa { n, .. } => modulus_bit_len(n),
        }
    }
}

fn modulus_bit_len(n: &[u8]) -> u32 {
    let mut i = 0usize;
    while i < n.len() && n[i] == 0 {
        i += 1;
    }
    if i == n.len() {
        return 0;
    }
    let leading = n[i].leading_zeros();
    ((n.len() - i) as u32) * 8 - leading
}

impl PrivateKey {
    /// Generate a new ssh-ed25519 keypair.
    pub fn generate_ed25519<R: CryptoRng + RngCore>(rng: &mut R, comment: String) -> Self {
        let sk = Ed25519PrivateKey::generate(rng);
        let seed = sk.to_bytes();
        let public = sk.public_key().to_bytes();
        PrivateKey::Ed25519 {
            seed,
            public,
            comment,
        }
    }

    /// Generate a new ECDSA keypair on the chosen NIST curve.
    pub fn generate_ecdsa<R: CryptoRng + RngCore>(
        rng: &mut R,
        curve: EcdsaCurve,
        comment: String,
    ) -> Self {
        let (cid, order_len) = match curve {
            EcdsaCurve::P256 => (CurveId::P256, 32usize),
            EcdsaCurve::P384 => (CurveId::P384, 48),
            EcdsaCurve::P521 => (CurveId::P521, 66),
        };
        let sk = BoxedEcdsaPrivateKey::generate(cid, rng);
        let point = sk.public_key().to_sec1();
        let d = scalar_from_ecdsa(&sk, order_len);
        match curve {
            EcdsaCurve::P256 => PrivateKey::EcdsaP256 { d, point, comment },
            EcdsaCurve::P384 => PrivateKey::EcdsaP384 { d, point, comment },
            EcdsaCurve::P521 => PrivateKey::EcdsaP521 { d, point, comment },
        }
    }

    /// Generate a new RSA keypair (public exponent 65537, Miller-Rabin = 40).
    pub fn generate_rsa<R: CryptoRng + RngCore>(
        rng: &mut R,
        bits: usize,
        comment: String,
    ) -> Result<Self> {
        if !(2048..=16384).contains(&bits) || !bits.is_multiple_of(256) {
            return Err(Error::Crypto("rsa: invalid key size"));
        }
        let e_u = BoxedUint::from_u64(65537);
        let sk = BoxedRsaPrivateKey::generate(bits, e_u, rng, 40);
        let RsaComponents { n, e, d, p, q } = rsa_components_from_pkcs1(&sk)?;
        let p_u = BoxedUint::from_be_bytes(strip_leading_zeros(&p));
        let q_u = BoxedUint::from_be_bytes(strip_leading_zeros(&q));
        let iqmp_u = inv_mod_boxed(&q_u, &p_u).ok_or(Error::Crypto("rsa: gcd(p,q) != 1"))?;
        let iqmp_len = strip_leading_zeros(&p).len();
        let iqmp = iqmp_u.to_be_bytes(iqmp_len);
        Ok(PrivateKey::Rsa {
            n,
            e,
            d,
            p,
            q,
            iqmp,
            comment,
        })
    }

    /// Encode this key as an openssh-key-v1 PEM document, using the host
    /// `OsRng` for the checkint and (if encrypting) the bcrypt salt. Pass
    /// `None` for an unencrypted key; pass a non-empty passphrase to encrypt
    /// with `aes256-ctr` keyed by `bcrypt_pbkdf`.
    ///
    /// Available only with the `std` feature; in `no_std` builds call
    /// [`PrivateKey::to_openssh_pem_with_rng`] and supply a `CryptoRng` of
    /// your choice.
    #[cfg(feature = "std")]
    pub fn to_openssh_pem(&self, passphrase: Option<&[u8]>) -> Result<String> {
        let mut rng = OsRng;
        self.to_openssh_pem_with_rng(&mut rng, passphrase)
    }

    /// `to_openssh_pem` variant that takes the entropy source explicitly. The
    /// RNG drives the openssh-key-v1 checkint and, if `passphrase` is set, the
    /// 16-byte bcrypt salt — both quantities must be unpredictable, so pass a
    /// real `CryptoRng`.
    pub fn to_openssh_pem_with_rng<R: CryptoRng + RngCore>(
        &self,
        rng: &mut R,
        passphrase: Option<&[u8]>,
    ) -> Result<String> {
        let encrypt = matches!(passphrase, Some(p) if !p.is_empty());
        let block = if encrypt { 16 } else { 8 };

        let inner = encode_inner_block(rng, self, block);
        let pub_blob = self.public_key().wire_blob();

        let (ciphername, kdfname, kdfoptions, payload) = if encrypt {
            let pass = passphrase.expect("checked above");
            let mut salt = [0u8; SALT_LEN];
            rng.fill_bytes(&mut salt);
            let derived = bcrypt_pbkdf(pass, &salt, BCRYPT_ROUNDS, KEY_LEN + IV_LEN)
                .map_err(|_| Error::Crypto("bcrypt_pbkdf: invalid parameters"))?;
            let mut key = [0u8; KEY_LEN];
            key.copy_from_slice(&derived[..KEY_LEN]);
            let mut iv = [0u8; IV_LEN];
            iv.copy_from_slice(&derived[KEY_LEN..KEY_LEN + IV_LEN]);
            let mut buf = inner;
            let mut ctr = Ctr::new(Aes256::new(&key), &iv);
            ctr.apply_keystream(&mut buf);
            let mut opts = Writer::new();
            opts.write_string(&salt);
            opts.write_u32(BCRYPT_ROUNDS);
            ("aes256-ctr", "bcrypt", opts.into_vec(), buf)
        } else {
            ("none", "none", Vec::new(), inner)
        };

        let mut w = Writer::new();
        w.write_raw(MAGIC);
        w.write_string(ciphername.as_bytes());
        w.write_string(kdfname.as_bytes());
        w.write_string(&kdfoptions);
        w.write_u32(1);
        w.write_string(&pub_blob);
        w.write_string(&payload);
        let bin = w.into_vec();

        let b64 = base64::encode(&bin);
        Ok(wrap_pem(&b64))
    }
}

fn encode_inner_block<R: CryptoRng + RngCore>(
    rng: &mut R,
    pk: &PrivateKey,
    block: usize,
) -> Vec<u8> {
    let mut check = [0u8; 4];
    rng.fill_bytes(&mut check);
    let checkint = u32::from_be_bytes(check);

    let mut w = Writer::new();
    w.write_u32(checkint);
    w.write_u32(checkint);
    match pk {
        PrivateKey::Ed25519 {
            seed,
            public,
            comment,
        } => {
            w.write_string(b"ssh-ed25519");
            w.write_string(public);
            let mut sk = [0u8; 64];
            sk[..32].copy_from_slice(seed);
            sk[32..].copy_from_slice(public);
            w.write_string(&sk);
            w.write_string(comment.as_bytes());
        }
        PrivateKey::EcdsaP256 { d, point, comment } => {
            w.write_string(b"ecdsa-sha2-nistp256");
            w.write_string(b"nistp256");
            w.write_string(point);
            write_mpint(&mut w, d);
            w.write_string(comment.as_bytes());
        }
        PrivateKey::EcdsaP384 { d, point, comment } => {
            w.write_string(b"ecdsa-sha2-nistp384");
            w.write_string(b"nistp384");
            w.write_string(point);
            write_mpint(&mut w, d);
            w.write_string(comment.as_bytes());
        }
        PrivateKey::EcdsaP521 { d, point, comment } => {
            w.write_string(b"ecdsa-sha2-nistp521");
            w.write_string(b"nistp521");
            w.write_string(point);
            write_mpint(&mut w, d);
            w.write_string(comment.as_bytes());
        }
        PrivateKey::Rsa {
            n,
            e,
            d,
            p,
            q,
            iqmp,
            comment,
        } => {
            w.write_string(b"ssh-rsa");
            write_mpint(&mut w, n);
            write_mpint(&mut w, e);
            write_mpint(&mut w, d);
            write_mpint(&mut w, iqmp);
            write_mpint(&mut w, p);
            write_mpint(&mut w, q);
            w.write_string(comment.as_bytes());
        }
    }
    let mut buf = w.into_vec();
    let pad_remainder = buf.len() % block;
    if pad_remainder != 0 {
        let pad_n = block - pad_remainder;
        let mut next = 1u8;
        let mut count = 0usize;
        while count < pad_n {
            buf.push(next);
            next = next.wrapping_add(1);
            count += 1;
        }
    }
    buf
}

fn wrap_pem(b64: &str) -> String {
    let mut out = String::with_capacity(b64.len() + b64.len() / PEM_WRAP + 80);
    out.push_str(PEM_BEGIN);
    out.push('\n');
    let bytes = b64.as_bytes();
    let mut i = 0usize;
    let max_iter = bytes.len() / PEM_WRAP + 2;
    let mut guard = 0usize;
    while i < bytes.len() {
        let end = (i + PEM_WRAP).min(bytes.len());
        out.push_str(core::str::from_utf8(&bytes[i..end]).expect("base64 is ASCII"));
        out.push('\n');
        i = end;
        guard += 1;
        if guard > max_iter {
            break;
        }
    }
    out.push_str(PEM_END);
    out.push('\n');
    out
}

fn scalar_from_ecdsa(sk: &BoxedEcdsaPrivateKey, order_len: usize) -> Vec<u8> {
    // BoxedEcdsaPrivateKey exposes its scalar only through to_sec1_der, which
    // wraps the scalar as an OCTET STRING inside an ECPrivateKey SEQUENCE.
    let der = sk.to_sec1_der();
    if let Some(d) = parse_sec1_priv_octet(&der, order_len) {
        return d;
    }
    alloc::vec![0]
}

fn parse_sec1_priv_octet(der: &[u8], order_len: usize) -> Option<Vec<u8>> {
    let mut outer = DerReader::new(der);
    let mut seq = outer.read_sequence().ok()?;
    let _ver = seq.read_integer_bytes().ok()?;
    let priv_bytes = seq.read_octet_string().ok()?;
    if priv_bytes.len() < order_len {
        let mut v = alloc::vec![0u8; order_len];
        v[order_len - priv_bytes.len()..].copy_from_slice(priv_bytes);
        return Some(v);
    }
    Some(priv_bytes.to_vec())
}

fn strip_leading_zeros(b: &[u8]) -> &[u8] {
    let mut i = 0;
    while i < b.len() && b[i] == 0 {
        i += 1;
    }
    &b[i..]
}

struct RsaComponents {
    n: Vec<u8>,
    e: Vec<u8>,
    d: Vec<u8>,
    p: Vec<u8>,
    q: Vec<u8>,
}

fn rsa_components_from_pkcs1(sk: &BoxedRsaPrivateKey) -> Result<RsaComponents> {
    let der = sk.to_pkcs1_der();
    let mut outer = DerReader::new(&der);
    let mut seq = outer
        .read_sequence()
        .map_err(|_| Error::Format("rsa: bad pkcs1 sequence"))?;
    let _ver = seq
        .read_integer_bytes()
        .map_err(|_| Error::Format("rsa: bad version"))?;
    let n = seq
        .read_integer_bytes()
        .map_err(|_| Error::Format("rsa: bad n"))?
        .to_vec();
    let e = seq
        .read_integer_bytes()
        .map_err(|_| Error::Format("rsa: bad e"))?
        .to_vec();
    let d = seq
        .read_integer_bytes()
        .map_err(|_| Error::Format("rsa: bad d"))?
        .to_vec();
    let p = seq
        .read_integer_bytes()
        .map_err(|_| Error::Format("rsa: bad p"))?
        .to_vec();
    let q = seq
        .read_integer_bytes()
        .map_err(|_| Error::Format("rsa: bad q"))?
        .to_vec();
    Ok(RsaComponents { n, e, d, p, q })
}
