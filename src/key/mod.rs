//! OpenSSH key file parsing and serialisation.
//!
//! Public keys use the single-line `<algorithm> <base64-blob> [comment]` form
//! (RFC 4716 is the older multi-line variant). Private keys use the OpenSSH
//! "new" PEM format with magic `b"openssh-key-v1\0"`, optionally encrypted
//! with `bcrypt_pbkdf` + a symmetric cipher (typically `aes256-ctr`).
//!
//! Passphrase-protected keys are derived via [`purecrypto::kdf::bcrypt_pbkdf`].
//!
//! The two top-level types are [`PublicKey`] and [`PrivateKey`], algorithm-
//! tagged enums covering ssh-ed25519, ecdsa-sha2-nistp{256,384,521} and
//! ssh-rsa. See each method for entry points (`parse_authorized_keys_line`,
//! `parse_openssh_pem`, etc.).

#![cfg(feature = "alloc")]

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use purecrypto::cipher::{Aes128, Aes256, Ctr};
use purecrypto::kdf::bcrypt_pbkdf;

use crate::error::{Error, Result};
use crate::format::{read_mpint, write_mpint, Reader, Writer};

mod base64;
mod writer;

pub use writer::EcdsaCurve;

/// SSH public key, tagged by algorithm.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PublicKey {
    /// `ssh-ed25519` — 32-byte raw public key.
    Ed25519 {
        /// Raw 32-byte public key.
        raw: [u8; 32],
        /// Trailing comment.
        comment: String,
    },
    /// `ecdsa-sha2-nistp256` — uncompressed SEC1 point.
    EcdsaP256 {
        /// Uncompressed EC point (`0x04 || X || Y`).
        point: Vec<u8>,
        /// Trailing comment.
        comment: String,
    },
    /// `ecdsa-sha2-nistp384`.
    EcdsaP384 {
        /// Uncompressed EC point.
        point: Vec<u8>,
        /// Trailing comment.
        comment: String,
    },
    /// `ecdsa-sha2-nistp521`.
    EcdsaP521 {
        /// Uncompressed EC point.
        point: Vec<u8>,
        /// Trailing comment.
        comment: String,
    },
    /// `ssh-rsa` — RSA public key (n, e).
    Rsa {
        /// Public exponent (big-endian magnitude).
        e: Vec<u8>,
        /// Modulus (big-endian magnitude).
        n: Vec<u8>,
        /// Trailing comment.
        comment: String,
    },
}

/// SSH private key, tagged by algorithm.
#[derive(Debug, Clone)]
pub enum PrivateKey {
    /// `ssh-ed25519` — 32-byte seed + 32-byte public.
    Ed25519 {
        /// 32-byte private seed.
        seed: [u8; 32],
        /// 32-byte public key.
        public: [u8; 32],
        /// Trailing comment.
        comment: String,
    },
    /// `ecdsa-sha2-nistp256`.
    EcdsaP256 {
        /// Private scalar (big-endian magnitude).
        d: Vec<u8>,
        /// Uncompressed EC point.
        point: Vec<u8>,
        /// Trailing comment.
        comment: String,
    },
    /// `ecdsa-sha2-nistp384`.
    EcdsaP384 {
        /// Private scalar.
        d: Vec<u8>,
        /// Uncompressed EC point.
        point: Vec<u8>,
        /// Trailing comment.
        comment: String,
    },
    /// `ecdsa-sha2-nistp521`.
    EcdsaP521 {
        /// Private scalar.
        d: Vec<u8>,
        /// Uncompressed EC point.
        point: Vec<u8>,
        /// Trailing comment.
        comment: String,
    },
    /// `ssh-rsa`.
    Rsa {
        /// Modulus n.
        n: Vec<u8>,
        /// Public exponent e.
        e: Vec<u8>,
        /// Private exponent d.
        d: Vec<u8>,
        /// First prime factor.
        p: Vec<u8>,
        /// Second prime factor.
        q: Vec<u8>,
        /// q^-1 mod p (CRT coefficient).
        iqmp: Vec<u8>,
        /// Trailing comment.
        comment: String,
    },
}

const ED25519: &str = "ssh-ed25519";
const ECDSA_P256: &str = "ecdsa-sha2-nistp256";
const ECDSA_P384: &str = "ecdsa-sha2-nistp384";
const ECDSA_P521: &str = "ecdsa-sha2-nistp521";
const RSA: &str = "ssh-rsa";

const NISTP256: &str = "nistp256";
const NISTP384: &str = "nistp384";
const NISTP521: &str = "nistp521";

const MAGIC: &[u8] = b"openssh-key-v1\0";

impl PublicKey {
    /// SSH algorithm name (e.g. `"ssh-ed25519"`).
    pub fn algorithm(&self) -> &'static str {
        match self {
            PublicKey::Ed25519 { .. } => ED25519,
            PublicKey::EcdsaP256 { .. } => ECDSA_P256,
            PublicKey::EcdsaP384 { .. } => ECDSA_P384,
            PublicKey::EcdsaP521 { .. } => ECDSA_P521,
            PublicKey::Rsa { .. } => RSA,
        }
    }

    /// Comment string (the trailing word on an `authorized_keys` line).
    pub fn comment(&self) -> &str {
        match self {
            PublicKey::Ed25519 { comment, .. }
            | PublicKey::EcdsaP256 { comment, .. }
            | PublicKey::EcdsaP384 { comment, .. }
            | PublicKey::EcdsaP521 { comment, .. }
            | PublicKey::Rsa { comment, .. } => comment,
        }
    }

    /// SSH wire-format public-key blob (the bytes that go inside an SSH
    /// `string` in an `SSH_MSG_USERAUTH_REQUEST` "publickey" method, in
    /// `authorized_keys`, etc.). Does not include the outer length prefix.
    pub fn wire_blob(&self) -> Vec<u8> {
        let mut w = Writer::new();
        match self {
            PublicKey::Ed25519 { raw, .. } => {
                w.write_string(ED25519.as_bytes());
                w.write_string(raw);
            }
            PublicKey::EcdsaP256 { point, .. } => {
                w.write_string(ECDSA_P256.as_bytes());
                w.write_string(NISTP256.as_bytes());
                w.write_string(point);
            }
            PublicKey::EcdsaP384 { point, .. } => {
                w.write_string(ECDSA_P384.as_bytes());
                w.write_string(NISTP384.as_bytes());
                w.write_string(point);
            }
            PublicKey::EcdsaP521 { point, .. } => {
                w.write_string(ECDSA_P521.as_bytes());
                w.write_string(NISTP521.as_bytes());
                w.write_string(point);
            }
            PublicKey::Rsa { e, n, comment: _ } => {
                w.write_string(RSA.as_bytes());
                write_mpint(&mut w, e);
                write_mpint(&mut w, n);
            }
        }
        w.into_vec()
    }

    /// Parse a single-line `authorized_keys` / `.pub` entry.
    ///
    /// Format: `<algorithm> <base64(wire_blob)> [comment...]`. Leading
    /// `from=...`/`command=...` option prefixes are not supported.
    pub fn parse_authorized_keys_line(s: &str) -> Result<Self> {
        let line = s.trim_end_matches(['\n', '\r']).trim_start();
        let mut it = line.splitn(3, ' ');
        let algo = it
            .next()
            .ok_or(Error::Format("authorized_keys: empty line"))?;
        let b64 = it
            .next()
            .ok_or(Error::Format("authorized_keys: missing key blob"))?;
        let comment = it.next().unwrap_or("").trim().to_string();
        let blob = base64::decode(b64.as_bytes())?;
        let mut pk = Self::parse_wire_blob(&blob)?;
        match &mut pk {
            PublicKey::Ed25519 { comment: c, .. }
            | PublicKey::EcdsaP256 { comment: c, .. }
            | PublicKey::EcdsaP384 { comment: c, .. }
            | PublicKey::EcdsaP521 { comment: c, .. }
            | PublicKey::Rsa { comment: c, .. } => *c = comment,
        }
        if pk.algorithm() != algo {
            return Err(Error::Format("authorized_keys: algorithm tag mismatch"));
        }
        Ok(pk)
    }

    /// Serialise as a single-line `authorized_keys` entry (no trailing
    /// newline). Comment is omitted if empty.
    pub fn to_authorized_keys_line(&self) -> String {
        let b64 = base64::encode(&self.wire_blob());
        let mut out = String::with_capacity(self.algorithm().len() + 1 + b64.len());
        out.push_str(self.algorithm());
        out.push(' ');
        out.push_str(&b64);
        let c = self.comment();
        if !c.is_empty() {
            out.push(' ');
            out.push_str(c);
        }
        out
    }

    /// Parse a SSH wire-format public-key blob.
    pub fn parse_wire_blob(blob: &[u8]) -> Result<Self> {
        let mut r = Reader::new(blob);
        let algo = r.read_string()?;
        let key = match algo {
            b if b == ED25519.as_bytes() => {
                let raw = r.read_string()?;
                if raw.len() != 32 {
                    return Err(Error::Format("ed25519: public key length"));
                }
                let mut arr = [0u8; 32];
                arr.copy_from_slice(raw);
                PublicKey::Ed25519 {
                    raw: arr,
                    comment: String::new(),
                }
            }
            b if b == ECDSA_P256.as_bytes() => {
                parse_ecdsa_public(&mut r, NISTP256, |p, c| PublicKey::EcdsaP256 {
                    point: p,
                    comment: c,
                })?
            }
            b if b == ECDSA_P384.as_bytes() => {
                parse_ecdsa_public(&mut r, NISTP384, |p, c| PublicKey::EcdsaP384 {
                    point: p,
                    comment: c,
                })?
            }
            b if b == ECDSA_P521.as_bytes() => {
                parse_ecdsa_public(&mut r, NISTP521, |p, c| PublicKey::EcdsaP521 {
                    point: p,
                    comment: c,
                })?
            }
            b if b == RSA.as_bytes() => {
                let e = read_mpint(&mut r)?.to_vec();
                let n = read_mpint(&mut r)?.to_vec();
                PublicKey::Rsa {
                    e,
                    n,
                    comment: String::new(),
                }
            }
            _ => return Err(Error::Unsupported("openssh public key algorithm")),
        };
        if !r.is_empty() {
            return Err(Error::Format("public key: trailing data"));
        }
        Ok(key)
    }
}

fn parse_ecdsa_public<F>(r: &mut Reader<'_>, curve: &str, ctor: F) -> Result<PublicKey>
where
    F: FnOnce(Vec<u8>, String) -> PublicKey,
{
    let c = r.read_string()?;
    if c != curve.as_bytes() {
        return Err(Error::Format("ecdsa: curve name mismatch"));
    }
    let point = r.read_string()?.to_vec();
    Ok(ctor(point, String::new()))
}

impl PrivateKey {
    /// SSH algorithm name.
    pub fn algorithm(&self) -> &'static str {
        match self {
            PrivateKey::Ed25519 { .. } => ED25519,
            PrivateKey::EcdsaP256 { .. } => ECDSA_P256,
            PrivateKey::EcdsaP384 { .. } => ECDSA_P384,
            PrivateKey::EcdsaP521 { .. } => ECDSA_P521,
            PrivateKey::Rsa { .. } => RSA,
        }
    }

    /// Comment.
    pub fn comment(&self) -> &str {
        match self {
            PrivateKey::Ed25519 { comment, .. }
            | PrivateKey::EcdsaP256 { comment, .. }
            | PrivateKey::EcdsaP384 { comment, .. }
            | PrivateKey::EcdsaP521 { comment, .. }
            | PrivateKey::Rsa { comment, .. } => comment,
        }
    }

    /// Convert this private key into a boxed `HostKey` signer.
    ///
    /// For RSA keys, defaults to `rsa-sha2-512` (modern OpenSSH preference).
    pub fn into_host_key(self) -> Result<alloc::boxed::Box<dyn crate::hostkey::HostKey + Send>> {
        use purecrypto::bignum::BoxedUint;
        match self {
            PrivateKey::Ed25519 { seed, .. } => Ok(alloc::boxed::Box::new(
                crate::hostkey::Ed25519HostKey::from_seed(seed),
            )),
            PrivateKey::EcdsaP256 { d, .. } => Ok(alloc::boxed::Box::new(
                crate::hostkey::EcdsaP256HostKey::from_scalar(&d)?,
            )),
            PrivateKey::EcdsaP384 { d, .. } => Ok(alloc::boxed::Box::new(
                crate::hostkey::EcdsaP384HostKey::from_scalar(&d)?,
            )),
            PrivateKey::EcdsaP521 { d, .. } => Ok(alloc::boxed::Box::new(
                crate::hostkey::EcdsaP521HostKey::from_scalar(&d)?,
            )),
            PrivateKey::Rsa { n, e, d, .. } => {
                let n_u = BoxedUint::from_be_bytes(trim_leading_zeros(&n));
                let e_u = BoxedUint::from_be_bytes(trim_leading_zeros(&e));
                let d_u = BoxedUint::from_be_bytes(trim_leading_zeros(&d));
                Ok(alloc::boxed::Box::new(
                    crate::hostkey::RsaSha2_512HostKey::from_components(n_u, e_u, d_u)?,
                ))
            }
        }
    }

    /// Derive the matching [`PublicKey`] (cloning the public parts).
    pub fn public_key(&self) -> PublicKey {
        match self {
            PrivateKey::Ed25519 {
                public, comment, ..
            } => PublicKey::Ed25519 {
                raw: *public,
                comment: comment.clone(),
            },
            PrivateKey::EcdsaP256 { point, comment, .. } => PublicKey::EcdsaP256 {
                point: point.clone(),
                comment: comment.clone(),
            },
            PrivateKey::EcdsaP384 { point, comment, .. } => PublicKey::EcdsaP384 {
                point: point.clone(),
                comment: comment.clone(),
            },
            PrivateKey::EcdsaP521 { point, comment, .. } => PublicKey::EcdsaP521 {
                point: point.clone(),
                comment: comment.clone(),
            },
            PrivateKey::Rsa { e, n, comment, .. } => PublicKey::Rsa {
                e: e.clone(),
                n: n.clone(),
                comment: comment.clone(),
            },
        }
    }

    /// Parse an OpenSSH "new" PEM-encoded private key.
    ///
    /// Pass `passphrase = None` for unencrypted keys. If the PEM is
    /// encrypted, `passphrase` must be supplied; if the passphrase is wrong
    /// the embedded `checkint1 == checkint2` check fails and we return
    /// [`Error::Crypto`]`("wrong passphrase")`.
    pub fn parse_openssh_pem(pem: &str, passphrase: Option<&[u8]>) -> Result<Self> {
        let body = strip_pem(pem)?;
        let raw = base64::decode(body.as_bytes())?;
        if raw.len() < MAGIC.len() || &raw[..MAGIC.len()] != MAGIC {
            return Err(Error::Format("openssh key: bad magic"));
        }
        let mut r = Reader::new(&raw[MAGIC.len()..]);
        let ciphername = r.read_string()?;
        let kdfname = r.read_string()?;
        let kdfoptions = r.read_string()?;
        let nkeys = r.read_u32()?;
        if nkeys != 1 {
            return Err(Error::Unsupported("openssh key: multiple keys"));
        }
        let public_blob = r.read_string()?.to_vec();
        let encrypted = r.read_string()?;
        if !r.is_empty() {
            return Err(Error::Format("openssh key: trailing data"));
        }

        let plain = decrypt_payload(ciphername, kdfname, kdfoptions, encrypted, passphrase)?;
        let mut pr = Reader::new(&plain);
        let checkint1 = pr.read_u32()?;
        let checkint2 = pr.read_u32()?;
        if checkint1 != checkint2 {
            // OpenSSH uses this pair as a passphrase-correctness probe: random
            // u32 written twice in the cleartext payload. Mismatch implies
            // the symmetric key was wrong (or the file is corrupt).
            return Err(Error::Crypto("wrong passphrase"));
        }

        let pk = parse_private_fields(&mut pr)?;

        let comment_bytes = pr.read_string()?;
        let comment = core::str::from_utf8(comment_bytes)
            .map_err(|_| Error::Format("comment is not utf-8"))?
            .to_string();

        // Trailing padding: bytes 1, 2, 3, ... up to the cipher block size.
        let mut expected = 1u8;
        while !pr.is_empty() {
            let b = pr.read_u8()?;
            if b != expected {
                return Err(Error::Format("openssh key: bad padding"));
            }
            expected = expected.wrapping_add(1);
        }

        // Sanity-check: the embedded public-key blob must match the private
        // key's derived public side.
        let pk_with_comment = attach_comment(pk, comment);
        let embedded = PublicKey::parse_wire_blob(&public_blob)?;
        if !public_parts_match(&pk_with_comment.public_key(), &embedded) {
            return Err(Error::Format(
                "openssh key: embedded public key does not match private fields",
            ));
        }
        Ok(pk_with_comment)
    }
}

fn attach_comment(mut pk: PrivateKey, comment: String) -> PrivateKey {
    match &mut pk {
        PrivateKey::Ed25519 { comment: c, .. }
        | PrivateKey::EcdsaP256 { comment: c, .. }
        | PrivateKey::EcdsaP384 { comment: c, .. }
        | PrivateKey::EcdsaP521 { comment: c, .. }
        | PrivateKey::Rsa { comment: c, .. } => *c = comment,
    }
    pk
}

fn public_parts_match(a: &PublicKey, b: &PublicKey) -> bool {
    match (a, b) {
        (PublicKey::Ed25519 { raw: x, .. }, PublicKey::Ed25519 { raw: y, .. }) => x == y,
        (PublicKey::EcdsaP256 { point: x, .. }, PublicKey::EcdsaP256 { point: y, .. })
        | (PublicKey::EcdsaP384 { point: x, .. }, PublicKey::EcdsaP384 { point: y, .. })
        | (PublicKey::EcdsaP521 { point: x, .. }, PublicKey::EcdsaP521 { point: y, .. }) => x == y,
        (PublicKey::Rsa { e: e1, n: n1, .. }, PublicKey::Rsa { e: e2, n: n2, .. }) => {
            trim_leading_zeros(e1) == trim_leading_zeros(e2)
                && trim_leading_zeros(n1) == trim_leading_zeros(n2)
        }
        _ => false,
    }
}

fn trim_leading_zeros(b: &[u8]) -> &[u8] {
    let mut i = 0;
    while i < b.len() && b[i] == 0 {
        i += 1;
    }
    &b[i..]
}

fn parse_private_fields(r: &mut Reader<'_>) -> Result<PrivateKey> {
    let algo = r.read_string()?;
    match algo {
        b if b == ED25519.as_bytes() => {
            let pub_raw = r.read_string()?;
            if pub_raw.len() != 32 {
                return Err(Error::Format("ed25519: public length"));
            }
            let sk = r.read_string()?;
            if sk.len() != 64 {
                return Err(Error::Format("ed25519: secret length"));
            }
            let mut seed = [0u8; 32];
            let mut pubk = [0u8; 32];
            seed.copy_from_slice(&sk[..32]);
            pubk.copy_from_slice(&sk[32..]);
            if pubk != pub_raw {
                return Err(Error::Format(
                    "ed25519: public key in secret does not match",
                ));
            }
            Ok(PrivateKey::Ed25519 {
                seed,
                public: pubk,
                comment: String::new(),
            })
        }
        b if b == ECDSA_P256.as_bytes() => {
            parse_ecdsa_private(r, NISTP256, |d, point| PrivateKey::EcdsaP256 {
                d,
                point,
                comment: String::new(),
            })
        }
        b if b == ECDSA_P384.as_bytes() => {
            parse_ecdsa_private(r, NISTP384, |d, point| PrivateKey::EcdsaP384 {
                d,
                point,
                comment: String::new(),
            })
        }
        b if b == ECDSA_P521.as_bytes() => {
            parse_ecdsa_private(r, NISTP521, |d, point| PrivateKey::EcdsaP521 {
                d,
                point,
                comment: String::new(),
            })
        }
        b if b == RSA.as_bytes() => {
            let n = read_mpint(r)?.to_vec();
            let e = read_mpint(r)?.to_vec();
            let d = read_mpint(r)?.to_vec();
            let iqmp = read_mpint(r)?.to_vec();
            let p = read_mpint(r)?.to_vec();
            let q = read_mpint(r)?.to_vec();
            Ok(PrivateKey::Rsa {
                n,
                e,
                d,
                p,
                q,
                iqmp,
                comment: String::new(),
            })
        }
        _ => Err(Error::Unsupported("openssh private key algorithm")),
    }
}

fn parse_ecdsa_private<F>(r: &mut Reader<'_>, curve: &str, ctor: F) -> Result<PrivateKey>
where
    F: FnOnce(Vec<u8>, Vec<u8>) -> PrivateKey,
{
    let c = r.read_string()?;
    if c != curve.as_bytes() {
        return Err(Error::Format("ecdsa: curve mismatch"));
    }
    let point = r.read_string()?.to_vec();
    let d = read_mpint(r)?.to_vec();
    Ok(ctor(d, point))
}

fn strip_pem(pem: &str) -> Result<&str> {
    const BEGIN: &str = "-----BEGIN OPENSSH PRIVATE KEY-----";
    const END: &str = "-----END OPENSSH PRIVATE KEY-----";
    let start = pem
        .find(BEGIN)
        .ok_or(Error::Format("openssh key: missing BEGIN marker"))?
        + BEGIN.len();
    let rest = &pem[start..];
    let end = rest
        .find(END)
        .ok_or(Error::Format("openssh key: missing END marker"))?;
    Ok(&rest[..end])
}

fn decrypt_payload(
    ciphername: &[u8],
    kdfname: &[u8],
    kdfoptions: &[u8],
    encrypted: &[u8],
    passphrase: Option<&[u8]>,
) -> Result<Vec<u8>> {
    if ciphername == b"none" {
        if kdfname != b"none" {
            return Err(Error::Format(
                "openssh key: cipher 'none' with non-none kdf",
            ));
        }
        return Ok(encrypted.to_vec());
    }

    let pass = passphrase.ok_or(Error::Crypto("passphrase required"))?;

    let (key_len, iv_len) = match ciphername {
        b"aes256-ctr" => (32usize, 16usize),
        b"aes128-ctr" => (16, 16),
        _ => return Err(Error::Unsupported("openssh key cipher")),
    };

    if kdfname != b"bcrypt" {
        return Err(Error::Unsupported("openssh key kdf"));
    }

    let mut kr = Reader::new(kdfoptions);
    let salt = kr.read_string()?;
    let rounds = kr.read_u32()?;
    if !kr.is_empty() {
        return Err(Error::Format("openssh key: trailing kdfoptions"));
    }

    let derived = bcrypt_pbkdf(pass, salt, rounds, key_len + iv_len)
        .map_err(|_| Error::Crypto("bcrypt_pbkdf: invalid parameters"))?;

    if !encrypted.len().is_multiple_of(16) {
        return Err(Error::Format("openssh key: encrypted length not aligned"));
    }

    let mut iv = [0u8; 16];
    iv.copy_from_slice(&derived[key_len..key_len + iv_len]);

    let mut out = encrypted.to_vec();
    match ciphername {
        b"aes256-ctr" => {
            let mut k = [0u8; 32];
            k.copy_from_slice(&derived[..32]);
            let mut ctr = Ctr::new(Aes256::new(&k), &iv);
            ctr.apply_keystream(&mut out);
        }
        b"aes128-ctr" => {
            let mut k = [0u8; 16];
            k.copy_from_slice(&derived[..16]);
            let mut ctr = Ctr::new(Aes128::new(&k), &iv);
            ctr.apply_keystream(&mut out);
        }
        _ => unreachable!(),
    }
    Ok(out)
}

#[cfg(test)]
mod tests;
