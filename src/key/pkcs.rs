//! Non-OpenSSH private-key formats: PKCS#1, SEC1, and PKCS#8 PEM.
//!
//! OpenSSH's own `-----BEGIN OPENSSH PRIVATE KEY-----` container is handled by
//! [`super::PrivateKey::parse_openssh_pem`]. This module adds the *other* PEM
//! encodings commonly produced by `openssl`, older `ssh-keygen -m PEM`, and
//! various language ecosystems, so a user can point an identity file at a key
//! that was not minted by recent OpenSSH:
//!
//! - `-----BEGIN RSA PRIVATE KEY-----`  — PKCS#1 `RSAPrivateKey` (RFC 8017).
//! - `-----BEGIN EC PRIVATE KEY-----`   — SEC1 `ECPrivateKey` (RFC 5915).
//! - `-----BEGIN PRIVATE KEY-----`      — PKCS#8 `PrivateKeyInfo` (RFC 5958),
//!   dispatched by algorithm OID to RSA / ECDSA (nistp256/384/521) / Ed25519.
//!
//! Encrypted variants (`-----BEGIN ENCRYPTED PRIVATE KEY-----`, and the legacy
//! `Proc-Type: 4,ENCRYPTED` / `DEK-Info` headers on traditional PEM) are
//! recognised but rejected with a clear [`Error::Unsupported`] rather than
//! mis-parsed — passphrase-protected keys in these formats are out of scope for
//! now (the OpenSSH container remains the encrypted-key path).
//!
//! DER component extraction is done with [`purecrypto::der::Reader`]; the
//! resulting big-endian integers map directly onto the SSH `mpint` convention
//! already used by [`super::PrivateKey`] (both are minimal big-endian with a
//! `0x00` sign byte when the high bit is set), and [`write_mpint`] normalises on
//! serialisation regardless. ECDSA/Ed25519 public parts are *derived* from the
//! private scalar/seed via `purecrypto`, so a missing or inconsistent embedded
//! public key cannot smuggle in a mismatched point.
//!
//! [`write_mpint`]: crate::format::write_mpint

use alloc::string::String;
use alloc::vec::Vec;

use purecrypto::der::Reader as DerReader;
use purecrypto::der::pem_decode;
use purecrypto::ec::{BoxedEcdsaPrivateKey, CurveId, Ed25519PrivateKey};

use super::PrivateKey;
use crate::error::{Error, Result};

// --- Object identifiers (encoded body bytes, i.e. the OID value without the
// outer tag/length). Compared by slice equality against `Reader::read_oid`. ---

/// `rsaEncryption` — 1.2.840.113549.1.1.1.
const OID_RSA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01];
/// `id-ecPublicKey` — 1.2.840.10045.2.1.
const OID_EC_PUBLICKEY: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];
/// `id-Ed25519` — 1.3.101.112.
const OID_ED25519: &[u8] = &[0x2b, 0x65, 0x70];
/// `secp256r1` (prime256v1) — 1.2.840.10045.3.1.7.
const OID_P256: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
/// `secp384r1` — 1.3.132.0.34.
const OID_P384: &[u8] = &[0x2b, 0x81, 0x04, 0x00, 0x22];
/// `secp521r1` — 1.3.132.0.35.
const OID_P521: &[u8] = &[0x2b, 0x81, 0x04, 0x00, 0x23];

/// EXPLICIT context tag `[0]` (constructed) — SEC1 `parameters`.
const TAG_CTX0: u8 = 0xa0;
/// EXPLICIT context tag `[1]` (constructed) — SEC1 `publicKey`.
const TAG_CTX1: u8 = 0xa1;
/// Universal `OBJECT IDENTIFIER` tag.
const TAG_OID: u8 = 0x06;
/// Universal `NULL` tag.
const TAG_NULL: u8 = 0x05;

fn der_err(_e: purecrypto::der::Error) -> Error {
    Error::Format("der: malformed private key structure")
}

impl PrivateKey {
    /// Parse a PEM private key in any supported container, auto-detecting the
    /// format from the `-----BEGIN <label>-----` marker.
    ///
    /// Supported labels:
    /// - `OPENSSH PRIVATE KEY` — delegates to [`Self::parse_openssh_pem`]
    ///   (the only container that currently supports a `passphrase`).
    /// - `RSA PRIVATE KEY` — PKCS#1.
    /// - `EC PRIVATE KEY` — SEC1.
    /// - `PRIVATE KEY` — PKCS#8 (RSA / ECDSA nistp256/384/521 / Ed25519).
    ///
    /// `passphrase` is honoured only for the OpenSSH container. Encrypted
    /// PKCS#8 (`ENCRYPTED PRIVATE KEY`) and legacy `DEK-Info` traditional PEM
    /// are rejected with [`Error::Unsupported`].
    ///
    /// This is the entry point identity-file loaders should prefer over
    /// [`Self::parse_openssh_pem`] when the on-disk format is not known ahead of
    /// time.
    pub fn parse_pem(pem: &str, passphrase: Option<&[u8]>) -> Result<Self> {
        let label = detect_pem_label(pem)?;
        match label {
            "OPENSSH PRIVATE KEY" => Self::parse_openssh_pem(pem, passphrase),
            "ENCRYPTED PRIVATE KEY" => Err(Error::Unsupported(
                "encrypted PKCS#8 private keys are not supported (convert with `ssh-keygen -p`)",
            )),
            "RSA PRIVATE KEY" => {
                reject_if_dek_encrypted(pem)?;
                parse_pkcs1_rsa_der(&pem_decode(pem, label).map_err(der_err)?)
            }
            "EC PRIVATE KEY" => {
                reject_if_dek_encrypted(pem)?;
                parse_sec1_ec_der(&pem_decode(pem, label).map_err(der_err)?, None)
            }
            "PRIVATE KEY" => parse_pkcs8_der(&pem_decode(pem, label).map_err(der_err)?),
            _ => Err(Error::Unsupported("unrecognised PEM private-key type")),
        }
    }
}

/// Extract the label from the first `-----BEGIN <label>-----` marker.
fn detect_pem_label(pem: &str) -> Result<&str> {
    const BEGIN: &str = "-----BEGIN ";
    let start = pem
        .find(BEGIN)
        .ok_or(Error::Format("pem: missing BEGIN marker"))?
        + BEGIN.len();
    let rest = &pem[start..];
    let end = rest
        .find("-----")
        .ok_or(Error::Format("pem: malformed BEGIN marker"))?;
    Ok(rest[..end].trim())
}

/// Reject traditional PEM that carries an encrypted body (`Proc-Type` /
/// `DEK-Info` headers, RFC 1421 / OpenSSL legacy encryption).
fn reject_if_dek_encrypted(pem: &str) -> Result<()> {
    if pem.contains("DEK-Info") || pem.contains("Proc-Type") {
        return Err(Error::Unsupported(
            "encrypted traditional PEM (DEK-Info) is not supported (convert with `ssh-keygen -p`)",
        ));
    }
    Ok(())
}

/// PKCS#1 `RSAPrivateKey` (RFC 8017 §A.1.2):
/// `SEQUENCE { version, n, e, d, p, q, dP, dQ, qInv }`.
fn parse_pkcs1_rsa_der(der: &[u8]) -> Result<PrivateKey> {
    let mut top = DerReader::new(der);
    let mut seq = top.read_sequence().map_err(der_err)?;
    let version = seq.read_unsigned_integer_bytes().map_err(der_err)?;
    // version 0 = two-prime; multi-prime (1) carries extra fields we don't model.
    if version != [0u8] {
        return Err(Error::Unsupported("rsa: only two-prime keys are supported"));
    }
    let n = seq.read_unsigned_integer_bytes().map_err(der_err)?.to_vec();
    let e = seq.read_unsigned_integer_bytes().map_err(der_err)?.to_vec();
    let d = seq.read_unsigned_integer_bytes().map_err(der_err)?.to_vec();
    let p = seq.read_unsigned_integer_bytes().map_err(der_err)?.to_vec();
    let q = seq.read_unsigned_integer_bytes().map_err(der_err)?.to_vec();
    let _dp = seq.read_unsigned_integer_bytes().map_err(der_err)?;
    let _dq = seq.read_unsigned_integer_bytes().map_err(der_err)?;
    let iqmp = seq.read_unsigned_integer_bytes().map_err(der_err)?.to_vec();
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

/// SEC1 `ECPrivateKey` (RFC 5915 §3):
/// `SEQUENCE { version(1), privateKey OCTET STRING, [0] parameters OPTIONAL,
///  [1] publicKey OPTIONAL }`.
///
/// `curve_hint` supplies the curve OID when this structure is nested inside a
/// PKCS#8 wrapper (which carries the curve in its `AlgorithmIdentifier` and may
/// omit the inner `[0] parameters`).
fn parse_sec1_ec_der(der: &[u8], curve_hint: Option<&[u8]>) -> Result<PrivateKey> {
    let mut top = DerReader::new(der);
    let mut seq = top.read_sequence().map_err(der_err)?;
    let version = seq.read_unsigned_integer_bytes().map_err(der_err)?;
    if version != [0x01] {
        return Err(Error::Format("ec: unexpected SEC1 version"));
    }
    let d_raw = seq.read_octet_string().map_err(der_err)?;

    // Optional [0] parameters (named-curve OID) and [1] publicKey. We prefer an
    // inline [0] OID, falling back to the PKCS#8 hint. The [1] public key is
    // ignored: we derive the point from the scalar instead.
    let mut curve_oid: Option<Vec<u8>> = curve_hint.map(|o| o.to_vec());
    while !seq.is_empty() {
        let (tag, content) = seq.read_any().map_err(der_err)?;
        if tag == TAG_CTX0 {
            // EXPLICIT [0] wraps ECParameters; the namedCurve choice is an OID.
            let mut inner = DerReader::new(content);
            curve_oid = Some(inner.read_oid().map_err(der_err)?.to_vec());
        } else if tag == TAG_CTX1 {
            // publicKey BIT STRING — derived, not trusted.
        }
    }

    let oid = curve_oid.ok_or(Error::Format("ec: missing curve identifier"))?;
    let (curve, ctor) = curve_from_oid(&oid)?;
    let sk = BoxedEcdsaPrivateKey::from_bytes(curve, d_raw)
        .map_err(|_| Error::Crypto("ec: private scalar out of range"))?;
    let point = sk.public_key().to_sec1();
    Ok(ctor(trim_leading_zeros(d_raw).to_vec(), point))
}

/// PKCS#8 `PrivateKeyInfo` (RFC 5958 §2):
/// `SEQUENCE { version, AlgorithmIdentifier { OID, params OPTIONAL },
///  privateKey OCTET STRING }`.
fn parse_pkcs8_der(der: &[u8]) -> Result<PrivateKey> {
    let mut top = DerReader::new(der);
    let mut seq = top.read_sequence().map_err(der_err)?;
    let _version = seq.read_unsigned_integer_bytes().map_err(der_err)?;

    let mut alg = seq.read_sequence().map_err(der_err)?;
    let alg_oid = alg.read_oid().map_err(der_err)?;
    // Algorithm parameters: NULL for RSA, the curve OID for EC, absent for
    // Ed25519.
    let params_oid: Option<&[u8]> = match alg.peek_tag() {
        Some(TAG_OID) => Some(alg.read_oid().map_err(der_err)?),
        Some(TAG_NULL) => {
            alg.read_null().map_err(der_err)?;
            None
        }
        _ => None,
    };

    let priv_key = seq.read_octet_string().map_err(der_err)?;

    if alg_oid == OID_RSA {
        parse_pkcs1_rsa_der(priv_key)
    } else if alg_oid == OID_EC_PUBLICKEY {
        parse_sec1_ec_der(priv_key, params_oid)
    } else if alg_oid == OID_ED25519 {
        parse_pkcs8_ed25519(priv_key)
    } else {
        Err(Error::Unsupported("pkcs8: unsupported key algorithm"))
    }
}

/// The Ed25519 PKCS#8 `privateKey` field is a `CurvePrivateKey` — itself a DER
/// `OCTET STRING` wrapping the 32-byte seed (RFC 8410 §7).
fn parse_pkcs8_ed25519(inner: &[u8]) -> Result<PrivateKey> {
    let mut r = DerReader::new(inner);
    let seed_bytes = r.read_octet_string().map_err(der_err)?;
    if seed_bytes.len() != 32 {
        return Err(Error::Format("ed25519: seed length"));
    }
    let mut seed = [0u8; 32];
    seed.copy_from_slice(seed_bytes);
    let public = Ed25519PrivateKey::from_bytes(seed).public_key().to_bytes();
    Ok(PrivateKey::Ed25519 {
        seed,
        public,
        comment: String::new(),
    })
}

type EcdsaCtor = fn(Vec<u8>, Vec<u8>) -> PrivateKey;

/// Map a named-curve OID to its `purecrypto` curve and the matching
/// [`PrivateKey`] constructor.
fn curve_from_oid(oid: &[u8]) -> Result<(CurveId, EcdsaCtor)> {
    if oid == OID_P256 {
        Ok((CurveId::P256, |d, point| PrivateKey::EcdsaP256 {
            d,
            point,
            comment: String::new(),
        }))
    } else if oid == OID_P384 {
        Ok((CurveId::P384, |d, point| PrivateKey::EcdsaP384 {
            d,
            point,
            comment: String::new(),
        }))
    } else if oid == OID_P521 {
        Ok((CurveId::P521, |d, point| PrivateKey::EcdsaP521 {
            d,
            point,
            comment: String::new(),
        }))
    } else {
        Err(Error::Unsupported("ec: unsupported curve"))
    }
}

fn trim_leading_zeros(b: &[u8]) -> &[u8] {
    let mut i = 0;
    while i + 1 < b.len() && b[i] == 0 {
        i += 1;
    }
    &b[i..]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key::PublicKey;

    // Fixtures generated with OpenSSL 3.x; expected public keys are what
    // `ssh-keygen -y` derives from the same private key. Each test asserts
    // `parse_pem(...).public_key()` wire-encodes identically.

    // RSA PKCS#1
    const RSA_PKCS1_PEM: &str = r#"-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAuoOwifkXY4RFX0rRS+ako4Pea0LCZmkkzHKUJ0Voo5lXZzMc
t09FKCOnkca6L6MMZdYg41JgAouI5kj+DMJJl14oY/IAdGeMsXlF+oIMQP6w5RtZ
vIwjcMnXhdDrN1FZECtbICW60kVup3LBSNQ1obaKE7d/k166tKOV7iA1VRhB/Ott
/EgcCd/2goYLM+n1dQBQFHQ17PYc6I+sgajKAs0USqkISMk9ojfpjQEEihHssEle
iZrMI/KRXJTB7dgVo55hnkpNdedCMy1sFhtsLT3G+po4D9LSpMlHokopUdtQ+vNP
l+pwke5WN2A6frnWQS0Hujc/LpzQijlsAT5+vQIDAQABAoIBAB838qEtdco89gWc
tsqPCOirpltqubI9kCC+Xujx17Fmdbg62GggVxGAYkhmrHxTvLwA6tFR1OsoItp0
xj0pefrhkj4kYAob2PNNurZS9S0d1EsM2GjURgxXZIEr9mr0bUVlFGQdnJcccwiJ
DywbBP0T2imxsaNfnD2nEe3hKzwaQaPRRdnUyNyzNqBmTRTUjIdSpwKpa03CnG4S
CNvU3sv3SzeIQwqIalLOEUK1HeSUuwawSs+02rxtVuInwLaVkzvf82fHNdVKBkiJ
T+XigZ+huCp/FgcyAZmFCBObpKRjMqdRI7KUZsXcQrPc9zsgEcueS0oSSNgsbKyy
PuNA/9sCgYEA4i4l1HvmzMtiXpyP5nB6StWuGrhDP/C8hrZYiBD9OfTKto8AImGU
xPBiDs6OIQARNKT7DKTmkygvqMUSUfkqYf0s/XUx2EJTSP93VMn9uoymvUDIrqdr
bOHUMHWJJwjCGtHuOegnLVGzfAs30S2yqCd6ePvPwwkq9hZQ2I6SO8MCgYEA0xrF
s2FZjpgL1s08t2mtaLJ0HyKzfOsJ9lSam6+VIeflqCYFRw/KLzko+B6OIgg4bz6y
/2JHY8oV+4q9osPih8DtNpDE9y3pDGJKY+jXPOnfiltUvT7Q10A6zBVXY7f3efGH
PLyVmENYO4uItgxB3SlpxTFxxF1syus8E0pZM38CgYEArIyCJbkkWUYr1HviN+3F
DgQ334CFJWl1mdvQbHVxid5bK6yqcJA7G4c7d4pS2ZAgkCXwtDO1B7zXpww5LrpE
gB7STMY0cYQf34etNM0oOUIGDkk3EC7/AEDETPfN2y6OTkGrWRfnk2ZJ5C72tSkE
q836XAPW+zaqRLS/loYlv1sCgYEAwp84DTx+2FuM7qeghmfDG3cKX3oah9wY/yTY
tReXIf8tV2xWCUGhYRANmVJyLyXtAYKIe7IbpwA0bAdo9ZoqSoWvLFMjg86rwGMN
ujZ72Qi0slWpNh+nYgsxKd2zB5gfbCkkSPaD5DCSM7NcgpmiT0dS4B3JiQOovRtJ
827j9fkCgYAKbuq/sVyD/EVg93MSRrRwbcJVVtgyymDlOvGEH3bIpHoqKZvYE8eb
35grBuD7g0WBNNcEH8/tF7KZ7S17JqAj8Alji1xhyWFRsdqgvigKCDMUHHUHsUjR
p7tR7RREmqGD45hEXj26BHrBZZ4SB9nm6dgyYX/bopL/w3jPSuatpw==
-----END RSA PRIVATE KEY-----
"#;
    const RSA_PKCS1_PUB: &str = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC6g7CJ+RdjhEVfStFL5qSjg95rQsJmaSTMcpQnRWijmVdnMxy3T0UoI6eRxrovowxl1iDjUmACi4jmSP4MwkmXXihj8gB0Z4yxeUX6ggxA/rDlG1m8jCNwydeF0Os3UVkQK1sgJbrSRW6ncsFI1DWhtooTt3+TXrq0o5XuIDVVGEH86238SBwJ3/aChgsz6fV1AFAUdDXs9hzoj6yBqMoCzRRKqQhIyT2iN+mNAQSKEeywSV6Jmswj8pFclMHt2BWjnmGeSk1150IzLWwWG2wtPcb6mjgP0tKkyUeiSilR21D680+X6nCR7lY3YDp+udZBLQe6Nz8unNCKOWwBPn69";

    #[test]
    fn parse_rsa_pkcs1() {
        let sk = PrivateKey::parse_pem(RSA_PKCS1_PEM, None).expect("parse RSA PKCS#1");
        let got = sk.public_key().wire_blob();
        let want = PublicKey::parse_authorized_keys_line(RSA_PKCS1_PUB)
            .expect("parse pub line")
            .wire_blob();
        assert_eq!(got, want, "RSA PKCS#1 public key mismatch");
    }

    // RSA PKCS#8
    const RSA_PKCS8_PEM: &str = r#"-----BEGIN PRIVATE KEY-----
MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQDA93kiEeIrouzF
UfNhLCBVkulKal5z4qCPRSIK3AWKibNID/AwD5KRx09tYjDUY/xJJb6+01DL8SBI
0aUdFeOGgnS/IkFdBwzjEhXNbKg6wCuzmSbCtZVeVP43/AHT5uAj1no83Zhg6YpP
0toXkhuCGOKwWWoyh/6AiEpSLw7qdOplWlDYdb4KSO7MPkodk7C9udiYEe8Ns8Tl
tT91JE7V0F8vFeMwLVaGZoaAXWq2T0RRyu4UmcGi4Z8Ghhj5U4ImEr9IiWlAWhn0
ae5AbDM4bt0j+RVll+w+MIPQuLcPJsWwjxh4ZjbxHti+t1YJQPfC+7YNmUiZtLRm
/Gz435r3AgMBAAECggEACa6hH6osDKp2cjQkH7+6DkZ6eXxlftpj2gHLAnvQX1zS
EmSSVacCYK7Sd8I8gaZUAKDp4DiezjeBZNtNYJc6PQPgsxJsmywBDoetcQrpqgD9
xbDX4V8rvnmfQ9SGNvQCUmoEOiJC72HodGGNBdppPO7eDkvTk0jVkUIauzhB6aub
ySjmMTBWtj4CoR1sM6rtrhwTL0ToqZn7XdtBzgWNOiE3A61xViWw+DTPHclMsUMy
xztANc0s5ttDvlkLN1LwoOh673PbshWqntzF+VIbcra8uONAEwPHPY4Gvuz5YlaN
27ItqVB/rCj0VJ5GvRSEq3JMKO/Yc6UwhI8nfzgKUQKBgQDpabzPE39EwUIiouzf
Sl700VbO0UW6/bNJnbzQAFNis0WH8b1D4RoCG8XZLlL34o6rtdFXZIX+Tohuu7KZ
9m8aFZ9tBsSHOfHGZoGnovTkl3GpHjXV0taPsuvOOlWshf3yk4qpGuqJp3xpN+4F
6Deq7FCbgf0OzY+uXUjDayjMPwKBgQDTo8Wf6rSECQ3+6RZAd5Czb0YAuBOZGWxv
+rg8FDODqGK8fkOnQXMNKjXQfRyng7Q9mA3flAVU7y5ZjrqQ3Mj0alwiR60F5JDo
4hyGzxOmYYAJalKF52qxiAef8tgASXtvay1HakpEvAAulITNY7VsFeLMPCZhioSp
7wzmsH9jSQKBgCvkemDmZbRkMy+YO7rxnVGkXBKgP+Cd/K0HQI5MwWF6HMUnrFOr
bNygpF/m2itLK1EW67rnaFseIYHRQhC5ysK49jXmY+aZ+uE4PYFsn2itIe6Pg8gl
0btMBhPN3HaI6+xF2nlaWmhwWnDe15+8v1sg/TeBBjlWZoJ/gENfT1i5AoGAd57P
ao3MLfy4LmYsL4/k96ZjGLDyUsxt3/UEAOEiJL4d4JA1SOnTT5OWCxtMANqOG2pA
HSiawuDVf8UOaiaAZrVfEfkVMIl55kc2/HM6lgXxymCP+CNOyL0sIhmuQKtH2zfm
xcCr7aGdMLa9QSGkP003fVxaDTOvvCTjU9haiBECgYAqpmBs/vKZAnFQFcktuvul
Pf4agLFFuWrfNThc4C+iYlcPNMZg3G1xFQdDobyXecZ2mzdkThqAS373G6/iAeQm
GFguBHgHO+sCCfMRhMwW3bplJFVNKMe5Xrv+pc+RMqr6XyKgKzmVDpl/gvG+8Paw
pu2Ky0+HlTAsmJeIT82J9w==
-----END PRIVATE KEY-----
"#;
    const RSA_PKCS8_PUB: &str = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDA93kiEeIrouzFUfNhLCBVkulKal5z4qCPRSIK3AWKibNID/AwD5KRx09tYjDUY/xJJb6+01DL8SBI0aUdFeOGgnS/IkFdBwzjEhXNbKg6wCuzmSbCtZVeVP43/AHT5uAj1no83Zhg6YpP0toXkhuCGOKwWWoyh/6AiEpSLw7qdOplWlDYdb4KSO7MPkodk7C9udiYEe8Ns8TltT91JE7V0F8vFeMwLVaGZoaAXWq2T0RRyu4UmcGi4Z8Ghhj5U4ImEr9IiWlAWhn0ae5AbDM4bt0j+RVll+w+MIPQuLcPJsWwjxh4ZjbxHti+t1YJQPfC+7YNmUiZtLRm/Gz435r3";

    #[test]
    fn parse_rsa_pkcs8() {
        let sk = PrivateKey::parse_pem(RSA_PKCS8_PEM, None).expect("parse RSA PKCS#8");
        let got = sk.public_key().wire_blob();
        let want = PublicKey::parse_authorized_keys_line(RSA_PKCS8_PUB)
            .expect("parse pub line")
            .wire_blob();
        assert_eq!(got, want, "RSA PKCS#8 public key mismatch");
    }

    // EC P-256 SEC1
    const EC256_SEC1_PEM: &str = r#"-----BEGIN EC PRIVATE KEY-----
MHcCAQEEILFDwV5hD/WGaxAwsL0+4RM9BWoFD3guvOY9StpE4qKUoAoGCCqGSM49
AwEHoUQDQgAEGDth3Wb7vNXwZkIMmSuUqxSegrh24cbqquuSh+kfTriQXUiB2NdQ
nspg0xSDpqAvFDKr0XYI2L9Qxf13Nw3KkA==
-----END EC PRIVATE KEY-----
"#;
    const EC256_SEC1_PUB: &str = "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBBg7Yd1m+7zV8GZCDJkrlKsUnoK4duHG6qrrkofpH064kF1IgdjXUJ7KYNMUg6agLxQyq9F2CNi/UMX9dzcNypA=";

    #[test]
    fn parse_ec256_sec1() {
        let sk = PrivateKey::parse_pem(EC256_SEC1_PEM, None).expect("parse EC P-256 SEC1");
        let got = sk.public_key().wire_blob();
        let want = PublicKey::parse_authorized_keys_line(EC256_SEC1_PUB)
            .expect("parse pub line")
            .wire_blob();
        assert_eq!(got, want, "EC P-256 SEC1 public key mismatch");
    }

    // EC P-384 PKCS#8
    const EC384_PKCS8_PEM: &str = r#"-----BEGIN PRIVATE KEY-----
MIG2AgEAMBAGByqGSM49AgEGBSuBBAAiBIGeMIGbAgEBBDAcZoOGillHQMgY10Tr
RN4gQVMzc4ngW3PVnkh2rmYVhuLvwnZjvrqDrq+t00bDP1GhZANiAAR/6kcPeCJc
D95p/PQgjmHocMa1GTm4K7rRwQZs/2wlQk0E5yNaqID+WmL/D+5l0/wCJR7AL5xF
lSHx1Sg95PpFjx6RXp+0EclH/o7VOKigfnwqbofZphrLM+C889HPMc4=
-----END PRIVATE KEY-----
"#;
    const EC384_PKCS8_PUB: &str = "ecdsa-sha2-nistp384 AAAAE2VjZHNhLXNoYTItbmlzdHAzODQAAAAIbmlzdHAzODQAAABhBH/qRw94IlwP3mn89CCOYehwxrUZObgrutHBBmz/bCVCTQTnI1qogP5aYv8P7mXT/AIlHsAvnEWVIfHVKD3k+kWPHpFen7QRyUf+jtU4qKB+fCpuh9mmGssz4Lzz0c8xzg==";

    #[test]
    fn parse_ec384_pkcs8() {
        let sk = PrivateKey::parse_pem(EC384_PKCS8_PEM, None).expect("parse EC P-384 PKCS#8");
        let got = sk.public_key().wire_blob();
        let want = PublicKey::parse_authorized_keys_line(EC384_PKCS8_PUB)
            .expect("parse pub line")
            .wire_blob();
        assert_eq!(got, want, "EC P-384 PKCS#8 public key mismatch");
    }

    // EC P-521 SEC1
    const EC521_SEC1_PEM: &str = r#"-----BEGIN EC PRIVATE KEY-----
MIHcAgEBBEIAYhIacWBDw+8E3atTLo+d3TF+xKThZwlQmQ6aZYVMOTCXAKeRfrKB
sfDdOKTHjUx4uw85sPg/MsIIAIdX7p1xNragBwYFK4EEACOhgYkDgYYABADAVpJo
cLJaF1YZudfnzbH2mqQe8gCdjCcVnEf/Pak0Y2vzdJW6ejAxfYPM8OE500U/YZqK
fE6/ut4Jmq34ENlZywCh1o6C+VZSZkk0zdt7GN2Uk9bCikgB/yMcAj3IsNlcoqs5
v5mIrMxqlNfjUdXxjqhQSuqNMC5f7tYuQ7qN4hdZ9A==
-----END EC PRIVATE KEY-----
"#;
    const EC521_SEC1_PUB: &str = "ecdsa-sha2-nistp521 AAAAE2VjZHNhLXNoYTItbmlzdHA1MjEAAAAIbmlzdHA1MjEAAACFBADAVpJocLJaF1YZudfnzbH2mqQe8gCdjCcVnEf/Pak0Y2vzdJW6ejAxfYPM8OE500U/YZqKfE6/ut4Jmq34ENlZywCh1o6C+VZSZkk0zdt7GN2Uk9bCikgB/yMcAj3IsNlcoqs5v5mIrMxqlNfjUdXxjqhQSuqNMC5f7tYuQ7qN4hdZ9A==";

    #[test]
    fn parse_ec521_sec1() {
        let sk = PrivateKey::parse_pem(EC521_SEC1_PEM, None).expect("parse EC P-521 SEC1");
        let got = sk.public_key().wire_blob();
        let want = PublicKey::parse_authorized_keys_line(EC521_SEC1_PUB)
            .expect("parse pub line")
            .wire_blob();
        assert_eq!(got, want, "EC P-521 SEC1 public key mismatch");
    }

    // Ed25519 PKCS#8
    const ED25519_PKCS8_PEM: &str = r#"-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIP25lZxmkjhgqz9jZyWGosODPfV94yOgGOShmCsQ0PE2
-----END PRIVATE KEY-----
"#;
    const ED25519_PKCS8_PUB: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFc41t1QcqkM/1tPl3AjtTRpdgQ2GB/zwzSE9mfdlg6d";

    #[test]
    fn parse_ed25519_pkcs8() {
        let sk = PrivateKey::parse_pem(ED25519_PKCS8_PEM, None).expect("parse Ed25519 PKCS#8");
        let got = sk.public_key().wire_blob();
        let want = PublicKey::parse_authorized_keys_line(ED25519_PKCS8_PUB)
            .expect("parse pub line")
            .wire_blob();
        assert_eq!(got, want, "Ed25519 PKCS#8 public key mismatch");
    }

    #[test]
    fn encrypted_pkcs8_is_rejected() {
        let pem = "-----BEGIN ENCRYPTED PRIVATE KEY-----\nMIIB\n-----END ENCRYPTED PRIVATE KEY-----\n";
        let err = PrivateKey::parse_pem(pem, None).unwrap_err();
        assert!(matches!(err, Error::Unsupported(_)), "got {err:?}");
    }

    #[test]
    fn dek_encrypted_traditional_pem_is_rejected() {
        let pem = "-----BEGIN RSA PRIVATE KEY-----\n\
            Proc-Type: 4,ENCRYPTED\n\
            DEK-Info: AES-128-CBC,0123\n\n\
            MIIB\n-----END RSA PRIVATE KEY-----\n";
        let err = PrivateKey::parse_pem(pem, None).unwrap_err();
        assert!(matches!(err, Error::Unsupported(_)), "got {err:?}");
    }

    // OpenSSH container must still route through the unified entry point.
    const OPENSSH_ED25519_PEM: &str = r#"-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACCV2RwhUUTL0ZDRCTgmIVYHuhMQsQEGoJG9QPzpqDuC3AAAAJgL3BQnC9wU
JwAAAAtzc2gtZWQyNTUxOQAAACCV2RwhUUTL0ZDRCTgmIVYHuhMQsQEGoJG9QPzpqDuC3A
AAAECX0yUsam9RmPlOW8GBsnP2u3nojzfs7v5gFDA7OVhvvJXZHCFRRMvRkNEJOCYhVge6
ExCxAQagkb1A/OmoO4LcAAAAD29wZW5zc2gtZml4dHVyZQECAwQFBg==
-----END OPENSSH PRIVATE KEY-----
"#;
    const OPENSSH_ED25519_PUB: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJXZHCFRRMvRkNEJOCYhVge6ExCxAQagkb1A/OmoO4Lc openssh-fixture";

    #[test]
    fn openssh_container_still_routes_through_parse_pem() {
        let sk = PrivateKey::parse_pem(OPENSSH_ED25519_PEM, None).expect("openssh via parse_pem");
        let got = sk.public_key().wire_blob();
        let want = PublicKey::parse_authorized_keys_line(OPENSSH_ED25519_PUB)
            .expect("parse pub line")
            .wire_blob();
        assert_eq!(got, want);
    }
}
