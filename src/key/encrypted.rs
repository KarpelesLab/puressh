//! Passphrase-protected private keys in the formats OpenSSL writes:
//! traditional PEM with `Proc-Type: 4,ENCRYPTED` / `DEK-Info` (what OpenSSH
//! before 7.8 wrote for every key with a passphrase, and `ssh-keygen -m PEM`
//! still does) and PKCS#8 `ENCRYPTED PRIVATE KEY` (PBES2).
//!
//! A wrong passphrase is reported as [`Error::Crypto`], like the OpenSSH
//! container, so callers ask again.

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use purecrypto::cipher::{Aes128, Aes192, Aes256, Cbc, Cbc64, Des, TdesEde3};
use purecrypto::der::{self, Reader as DerReader};
use purecrypto::hash::{Digest, Md5, Sha1, Sha256};
use zeroize::Zeroizing;

use crate::error::{Error, Result};

fn bad_passphrase() -> Error {
    Error::Crypto("incorrect passphrase supplied to decrypt private key")
}

/// Strip PKCS#7 padding, which also catches most wrong passphrases.
fn unpad(mut data: Zeroizing<Vec<u8>>, block: usize) -> Result<Zeroizing<Vec<u8>>> {
    let n = *data.last().ok_or_else(bad_passphrase)? as usize;
    if n == 0
        || n > block
        || n > data.len()
        || data[data.len() - n..].iter().any(|b| *b as usize != n)
    {
        return Err(bad_passphrase());
    }
    let len = data.len() - n;
    data.truncate(len);
    Ok(data)
}

/// Decrypt CBC with the named cipher (`AES-128-CBC`, `DES-EDE3-CBC`, …).
fn cbc_decrypt(cipher: &str, key: &[u8], iv: &[u8], data: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    let mut buf = Zeroizing::new(data.to_vec());
    let bad = || Error::Format("encrypted key: bad length");
    macro_rules! aes {
        ($t:ty, $n:expr) => {{
            let k: &[u8; $n] = key.try_into().map_err(|_| bad())?;
            let iv: &[u8; 16] = iv.try_into().map_err(|_| bad())?;
            Cbc::new(<$t>::new(k), iv)
                .decrypt(&mut buf)
                .map_err(|_| bad())?;
            return unpad(buf, 16);
        }};
    }
    match cipher {
        "AES-128-CBC" => aes!(Aes128, 16),
        "AES-192-CBC" => aes!(Aes192, 24),
        "AES-256-CBC" => aes!(Aes256, 32),
        "DES-EDE3-CBC" => {
            let k: &[u8; 24] = key.try_into().map_err(|_| bad())?;
            let iv: &[u8; 8] = iv.try_into().map_err(|_| bad())?;
            Cbc64::new(TdesEde3::new(k), iv)
                .decrypt(&mut buf)
                .map_err(|_| bad())?;
        }
        "DES-CBC" => {
            let k: &[u8; 8] = key.try_into().map_err(|_| bad())?;
            let iv: &[u8; 8] = iv.try_into().map_err(|_| bad())?;
            Cbc64::new(Des::new(k), iv)
                .decrypt(&mut buf)
                .map_err(|_| bad())?;
        }
        _ => return Err(Error::Unsupported("encrypted key: unsupported cipher")),
    }
    unpad(buf, 8)
}

fn key_len(cipher: &str) -> Option<usize> {
    Some(match cipher {
        "AES-128-CBC" => 16,
        "AES-192-CBC" | "DES-EDE3-CBC" => 24,
        "AES-256-CBC" => 32,
        "DES-CBC" => 8,
        _ => return None,
    })
}

/// OpenSSL's `EVP_BytesToKey` with MD5 and one iteration (traditional PEM).
fn bytes_to_key(pass: &[u8], salt: &[u8], len: usize) -> Zeroizing<Vec<u8>> {
    let mut out = Zeroizing::new(Vec::with_capacity(len + 16));
    let mut prev: Vec<u8> = Vec::new();
    while out.len() < len {
        let mut h = Md5::new();
        h.update(&prev);
        h.update(pass);
        h.update(salt);
        prev = h.finalize().as_ref().to_vec();
        out.extend_from_slice(&prev);
    }
    out.truncate(len);
    out
}

fn hex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

/// Whether a traditional PEM block carries `Proc-Type: 4,ENCRYPTED`.
pub(crate) fn is_encrypted_traditional(pem: &str) -> bool {
    pem.lines()
        .any(|l| l.trim().eq_ignore_ascii_case("Proc-Type: 4,ENCRYPTED"))
}

/// Decrypt a traditional `-----BEGIN <label>-----` block with `DEK-Info`
/// headers; returns the inner DER.
pub(crate) fn decrypt_traditional(
    pem: &str,
    passphrase: Option<&[u8]>,
) -> Result<Zeroizing<Vec<u8>>> {
    let mut dek = None;
    let mut b64 = String::new();
    let mut inside = false;
    for line in pem.lines() {
        let line = line.trim();
        if line.starts_with("-----BEGIN ") {
            inside = true;
            continue;
        }
        if line.starts_with("-----END ") {
            break;
        }
        if !inside || line.is_empty() {
            continue;
        }
        if let Some((name, value)) = line.split_once(':') {
            if name.trim().eq_ignore_ascii_case("DEK-Info") {
                dek = Some(value.trim().to_string());
            }
            continue;
        }
        b64.push_str(line);
    }
    let dek = dek.ok_or(Error::Format("encrypted PEM: no DEK-Info"))?;
    let (cipher, iv_hex) = dek
        .split_once(',')
        .ok_or(Error::Format("encrypted PEM: bad DEK-Info"))?;
    let cipher = cipher.trim().to_ascii_uppercase();
    let iv = hex(iv_hex.trim()).ok_or(Error::Format("encrypted PEM: bad IV"))?;
    let len = key_len(&cipher).ok_or(Error::Unsupported("encrypted PEM: unsupported cipher"))?;
    if iv.len() < 8 {
        return Err(Error::Format("encrypted PEM: bad IV"));
    }
    let pass = passphrase.ok_or(Error::Crypto("passphrase required"))?;
    let data = der::base64_decode(&b64).map_err(|_| Error::Format("encrypted PEM: bad base64"))?;
    let key = bytes_to_key(pass, &iv[..8], len);
    cbc_decrypt(&cipher, &key, &iv, &data)
}

/// Decrypt a PKCS#8 `EncryptedPrivateKeyInfo` (PBES2: PBKDF2 with
/// HMAC-SHA1/SHA256, AES-CBC or 3DES-CBC); returns the `PrivateKeyInfo`
/// DER. Iteration counts up to 10 million are accepted (OpenSSL long
/// used 2048).
pub(crate) fn decrypt_pkcs8(
    der_bytes: &[u8],
    passphrase: Option<&[u8]>,
) -> Result<Zeroizing<Vec<u8>>> {
    const PBES2: &[u64] = &[1, 2, 840, 113549, 1, 5, 13];
    const PBKDF2: &[u64] = &[1, 2, 840, 113549, 1, 5, 12];
    const HMAC_SHA1: &[u64] = &[1, 2, 840, 113549, 2, 7];
    const HMAC_SHA256: &[u64] = &[1, 2, 840, 113549, 2, 9];
    const MAX_ITERATIONS: u64 = 10_000_000;
    let bad = || Error::Format("encrypted PKCS#8: malformed");
    let is = |body: &[u8], arcs: &[u64]| der::encode_oid_arcs(arcs) == body;

    let mut top = DerReader::new(der_bytes);
    let mut info = top.read_sequence().map_err(|_| bad())?;
    let mut alg = info.read_sequence().map_err(|_| bad())?;
    if !is(alg.read_oid().map_err(|_| bad())?, PBES2) {
        return Err(Error::Unsupported(
            "encrypted PKCS#8: only PBES2 is supported",
        ));
    }
    let mut params = alg.read_sequence().map_err(|_| bad())?;
    let mut kdf = params.read_sequence().map_err(|_| bad())?;
    if !is(kdf.read_oid().map_err(|_| bad())?, PBKDF2) {
        return Err(Error::Unsupported(
            "encrypted PKCS#8: only PBKDF2 is supported",
        ));
    }
    let mut kp = kdf.read_sequence().map_err(|_| bad())?;
    let salt = kp.read_octet_string().map_err(|_| bad())?.to_vec();
    let iter_bytes = kp.read_unsigned_integer_bytes().map_err(|_| bad())?;
    if iter_bytes.len() > 8 {
        return Err(bad());
    }
    let iterations = iter_bytes
        .iter()
        .fold(0u64, |a, b| (a << 8) | u64::from(*b));
    if iterations == 0 || iterations > MAX_ITERATIONS {
        return Err(Error::Format(
            "encrypted PKCS#8: unreasonable iteration count",
        ));
    }
    // Optional keyLength, then optional prf (default HMAC-SHA1).
    let mut sha256 = false;
    if kp.peek_tag() == Some(der::tag::INTEGER) {
        kp.read_unsigned_integer_bytes().map_err(|_| bad())?;
    }
    if kp.peek_tag() == Some(der::tag::SEQUENCE) {
        let mut prf = kp.read_sequence().map_err(|_| bad())?;
        let oid = prf.read_oid().map_err(|_| bad())?;
        if is(oid, HMAC_SHA256) {
            sha256 = true;
        } else if !is(oid, HMAC_SHA1) {
            return Err(Error::Unsupported("encrypted PKCS#8: unsupported PRF"));
        }
    }
    let mut enc = params.read_sequence().map_err(|_| bad())?;
    let enc_oid = enc.read_oid().map_err(|_| bad())?;
    let cipher = [
        (&[2, 16, 840, 1, 101, 3, 4, 1, 2][..], "AES-128-CBC"),
        (&[2, 16, 840, 1, 101, 3, 4, 1, 22][..], "AES-192-CBC"),
        (&[2, 16, 840, 1, 101, 3, 4, 1, 42][..], "AES-256-CBC"),
        (&[1, 2, 840, 113549, 3, 7][..], "DES-EDE3-CBC"),
    ]
    .iter()
    .find(|(arcs, _)| is(enc_oid, arcs))
    .map(|(_, name)| *name)
    .ok_or(Error::Unsupported("encrypted PKCS#8: unsupported cipher"))?;
    let iv = enc.read_octet_string().map_err(|_| bad())?.to_vec();
    let data = info.read_octet_string().map_err(|_| bad())?;

    let pass = passphrase.ok_or(Error::Crypto("passphrase required"))?;
    let len = key_len(cipher).expect("listed cipher");
    let mut key = Zeroizing::new(alloc::vec![0u8; len]);
    let iterations = iterations as u32;
    if sha256 {
        purecrypto::kdf::pbkdf2::<Sha256>(pass, &salt, iterations, &mut key);
    } else {
        purecrypto::kdf::pbkdf2::<Sha1>(pass, &salt, iterations, &mut key);
    }
    cbc_decrypt(cipher, &key, &iv, data)
}
