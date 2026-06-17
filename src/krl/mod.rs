//! OpenSSH key-revocation-list (KRL) binary format reader.
//!
//! A KRL is a compact, admin-provided blob (produced by `ssh-keygen -k`) that
//! enumerates revoked keys and certificates. `sshd` consults it via the
//! `RevokedKeys` directive: a publickey / certificate that the KRL covers is
//! refused regardless of any other trust the gate would otherwise grant.
//!
//! # Wire format (from OpenSSH `PROTOCOL.krl`)
//!
//! Header (in order):
//!
//! ```text
//! u64     magic = "SSHKRL\n\0"   (0x5353484b524c0a00)
//! u32     format_version = 1
//! u64     krl_version
//! u64     generated_date
//! u64     flags
//! string  reserved
//! string  comment
//! ```
//!
//! Then a sequence of sections. Every non-signature section is:
//!
//! ```text
//! u8      section_type
//! string  section_data
//! ```
//!
//! Section types: `1` certificates, `2` explicit-key, `3` fingerprint-sha1,
//! `4` signature, `5` fingerprint-sha256, `255` extension.
//!
//! The **certificates** section body is `string ca_key` (empty ⇒ applies to
//! every CA), `string reserved`, then one or more cert subsections, each
//! `u8 cert_section_type` + `string cert_section_data`:
//!
//! - `0x20` serial-list: a run of `u64` serials.
//! - `0x21` serial-range: `u64 min`, `u64 max` (inclusive).
//! - `0x22` serial-bitmap: `u64 offset`, `mpint bitmap` (bit *N* ⇒ serial
//!   `offset + N` revoked).
//! - `0x23` key-id: a run of `string key_id`.
//! - `0x39` cert-extension: ignored (skipped) defensively.
//!
//! # Security
//!
//! Parsing is defensive: every length is bounded against the remaining input
//! by the underlying [`Reader`], counts are implicitly capped by the section
//! length, and trailing data inside a section is rejected. A hostile KRL can
//! at worst be rejected with [`Error::Format`]; it can never widen trust.
//!
//! The **signature** section (type 4) is *parse-and-ignore*: its body is
//! skipped and never used to grant trust. OpenSSH itself does not support KRL
//! signatures, and a `RevokedKeys` file is a trusted local file the admin
//! points at — so validating the KRL's own signature would add nothing here.
//! We never treat a signed KRL as more (or less) trusted than an unsigned one;
//! the section is simply not load-bearing. See [`Krl::parse`].

use alloc::string::String;
use alloc::vec::Vec;

use crate::error::{Error, Result};
use crate::format::{Reader, read_mpint};
use purecrypto::hash::{Digest, Sha1, Sha256};

/// KRL magic: `"SSHKRL\n\0"`.
const KRL_MAGIC: u64 = 0x5353_484b_524c_0a00;
/// The only format version OpenSSH emits / accepts.
const KRL_FORMAT_VERSION: u32 = 1;

// Top-level section types.
const SECTION_CERTIFICATES: u8 = 1;
const SECTION_EXPLICIT_KEY: u8 = 2;
const SECTION_FINGERPRINT_SHA1: u8 = 3;
const SECTION_SIGNATURE: u8 = 4;
const SECTION_FINGERPRINT_SHA256: u8 = 5;
const SECTION_EXTENSION: u8 = 255;

// Certificate subsection types.
const CERT_SERIAL_LIST: u8 = 0x20;
const CERT_SERIAL_RANGE: u8 = 0x21;
const CERT_SERIAL_BITMAP: u8 = 0x22;
const CERT_KEY_ID: u8 = 0x23;
const CERT_EXTENSION: u8 = 0x39;

/// Hard cap on a serial bitmap's byte length, so a hostile KRL cannot make us
/// allocate / scan an enormous run. A 1 MiB bitmap already covers ~8 million
/// consecutive serials — far beyond any realistic deployment.
const MAX_BITMAP_BYTES: usize = 1 << 20;

/// Per-CA revocation facts extracted from a certificates section.
struct CaRevocation {
    /// The CA public-key blob this block applies to. Empty ⇒ applies to *all*
    /// CAs (OpenSSH's wildcard convention).
    ca_key_blob: Vec<u8>,
    /// Explicitly-listed revoked serial numbers.
    serials: Vec<u64>,
    /// Inclusive `(min, max)` revoked serial ranges.
    serial_ranges: Vec<(u64, u64)>,
    /// `(offset, bitmap-bytes)` bitmaps; bit *N* (LSB-first within the
    /// big-endian magnitude) ⇒ serial `offset + N` revoked.
    serial_bitmaps: Vec<(u64, Vec<u8>)>,
    /// Revoked certificate key-ids.
    key_ids: Vec<String>,
}

impl CaRevocation {
    /// True if a cert with `serial` / `key_id` issued by this CA is revoked.
    fn covers(&self, serial: u64, key_id: &str) -> bool {
        if serial != 0 && self.serials.contains(&serial) {
            return true;
        }
        for &(lo, hi) in &self.serial_ranges {
            if serial != 0 && serial >= lo && serial <= hi {
                return true;
            }
        }
        for (offset, bits) in &self.serial_bitmaps {
            if serial >= *offset {
                let idx = serial - *offset;
                if bit_is_set(bits, idx) {
                    return true;
                }
            }
        }
        if !key_id.is_empty() && self.key_ids.iter().any(|k| k == key_id) {
            return true;
        }
        false
    }
}

/// A parsed key-revocation list.
pub struct Krl {
    /// Per-CA certificate revocations.
    cert_revocations: Vec<CaRevocation>,
    /// Wire blobs of explicitly-revoked plain public keys (section 2).
    explicit_keys: Vec<Vec<u8>>,
    /// SHA-1 hashes of revoked public-key blobs (section 3).
    fp_sha1: Vec<[u8; 20]>,
    /// SHA-256 hashes of revoked public-key blobs (section 5).
    fp_sha256: Vec<[u8; 32]>,
}

/// Test whether bit `idx` (counting from the least-significant bit of the
/// big-endian `mpint` magnitude) is set. The magnitude is big-endian, so the
/// LSB lives in the *last* byte; bit `idx` is byte `len-1 - idx/8`, bit
/// `idx%8`. An out-of-range index is simply unset.
fn bit_is_set(magnitude: &[u8], idx: u64) -> bool {
    let byte_from_end = (idx / 8) as usize;
    if byte_from_end >= magnitude.len() {
        return false;
    }
    let byte = magnitude[magnitude.len() - 1 - byte_from_end];
    let bit = (idx % 8) as u8;
    (byte >> bit) & 1 == 1
}

impl Krl {
    /// Parse a KRL blob. Returns [`Error::Format`] on any malformed input
    /// (bad magic / version, truncated section, trailing bytes), never
    /// panicking. An empty / minimal KRL with no sections parses to a list
    /// that revokes nothing.
    pub fn parse(blob: &[u8]) -> Result<Self> {
        let mut r = Reader::new(blob);

        if r.read_u64()? != KRL_MAGIC {
            return Err(Error::Format("krl: bad magic"));
        }
        if r.read_u32()? != KRL_FORMAT_VERSION {
            return Err(Error::Format("krl: unsupported format version"));
        }
        let _krl_version = r.read_u64()?;
        let _generated_date = r.read_u64()?;
        let _flags = r.read_u64()?;
        let _reserved = r.read_string()?;
        let _comment = r.read_string()?;

        let mut krl = Krl {
            cert_revocations: Vec::new(),
            explicit_keys: Vec::new(),
            fp_sha1: Vec::new(),
            fp_sha256: Vec::new(),
        };

        while !r.is_empty() {
            let section_type = r.read_u8()?;
            // Every section (including signature, per the format) carries a
            // length-prefixed body, so we can skip an unknown one safely.
            let body = r.read_string()?;
            match section_type {
                SECTION_CERTIFICATES => krl.parse_certificates(body)?,
                SECTION_EXPLICIT_KEY => parse_blob_list(body, &mut krl.explicit_keys)?,
                SECTION_FINGERPRINT_SHA1 => parse_hash_list(body, &mut krl.fp_sha1)?,
                SECTION_FINGERPRINT_SHA256 => parse_hash_list(body, &mut krl.fp_sha256)?,
                // Parse-and-ignore: the KRL's own signature is not validated
                // (a trusted local file needs no self-signature) and never
                // grants trust. We already consumed its body above.
                SECTION_SIGNATURE => {}
                // Unknown / extension sections are tolerated and skipped.
                SECTION_EXTENSION => {}
                _ => {}
            }
        }
        Ok(krl)
    }

    /// Parse a `certificates` (type 1) section body into a [`CaRevocation`].
    fn parse_certificates(&mut self, body: &[u8]) -> Result<()> {
        let mut r = Reader::new(body);
        let ca_key_blob = r.read_string()?.to_vec();
        // `reserved` — ignored, but must be present.
        let _reserved = r.read_string()?;

        let mut rev = CaRevocation {
            ca_key_blob,
            serials: Vec::new(),
            serial_ranges: Vec::new(),
            serial_bitmaps: Vec::new(),
            key_ids: Vec::new(),
        };

        while !r.is_empty() {
            let sub_type = r.read_u8()?;
            let sub = r.read_string()?;
            match sub_type {
                CERT_SERIAL_LIST => {
                    let mut sr = Reader::new(sub);
                    while !sr.is_empty() {
                        rev.serials.push(sr.read_u64()?);
                    }
                }
                CERT_SERIAL_RANGE => {
                    let mut sr = Reader::new(sub);
                    let lo = sr.read_u64()?;
                    let hi = sr.read_u64()?;
                    if !sr.is_empty() {
                        return Err(Error::Format("krl: trailing serial-range data"));
                    }
                    rev.serial_ranges.push((lo, hi));
                }
                CERT_SERIAL_BITMAP => {
                    let mut sr = Reader::new(sub);
                    let offset = sr.read_u64()?;
                    let bits = read_mpint(&mut sr)?;
                    if bits.len() > MAX_BITMAP_BYTES {
                        return Err(Error::Format("krl: serial bitmap too large"));
                    }
                    if !sr.is_empty() {
                        return Err(Error::Format("krl: trailing serial-bitmap data"));
                    }
                    rev.serial_bitmaps.push((offset, bits.to_vec()));
                }
                CERT_KEY_ID => {
                    let mut sr = Reader::new(sub);
                    while !sr.is_empty() {
                        let id = sr.read_string()?;
                        let s = core::str::from_utf8(id)
                            .map_err(|_| Error::Format("krl: non-utf8 key-id"))?;
                        rev.key_ids.push(s.into());
                    }
                }
                // Cert extensions are advisory; skip (body already consumed).
                CERT_EXTENSION => {}
                _ => {}
            }
        }
        self.cert_revocations.push(rev);
        Ok(())
    }

    /// True if a certificate signed by `ca_key_blob` with the given `serial`
    /// and `key_id` is revoked. A serial of `0` (unset) is matched only by
    /// key-id. A certificates block whose `ca_key_blob` is empty applies to
    /// every CA.
    pub fn is_revoked_cert(&self, ca_key_blob: &[u8], serial: u64, key_id: &str) -> bool {
        self.cert_revocations.iter().any(|rev| {
            (rev.ca_key_blob.is_empty() || rev.ca_key_blob == ca_key_blob)
                && rev.covers(serial, key_id)
        })
    }

    /// True if a plain public key (given by its wire blob) is revoked, by
    /// explicit-key listing or by SHA-1 / SHA-256 fingerprint.
    pub fn is_revoked_key(&self, pubkey_blob: &[u8]) -> bool {
        if self.explicit_keys.iter().any(|k| k == pubkey_blob) {
            return true;
        }
        if !self.fp_sha1.is_empty() {
            let h = Sha1::digest(pubkey_blob);
            if self.fp_sha1.iter().any(|fp| fp == &h) {
                return true;
            }
        }
        if !self.fp_sha256.is_empty() {
            let h = Sha256::digest(pubkey_blob);
            if self.fp_sha256.iter().any(|fp| fp == &h) {
                return true;
            }
        }
        false
    }

    /// True if this KRL revokes nothing (no certificate blocks, no explicit
    /// keys, no fingerprints). Useful for a caller that wants to warn about a
    /// `RevokedKeys` file that ended up empty.
    pub fn is_empty(&self) -> bool {
        self.cert_revocations.is_empty()
            && self.explicit_keys.is_empty()
            && self.fp_sha1.is_empty()
            && self.fp_sha256.is_empty()
    }
}

/// Parse a section body that is a bare run of `string` blobs (explicit-key).
fn parse_blob_list(body: &[u8], out: &mut Vec<Vec<u8>>) -> Result<()> {
    let mut r = Reader::new(body);
    while !r.is_empty() {
        out.push(r.read_string()?.to_vec());
    }
    Ok(())
}

/// Parse a section body that is a run of fixed-width `string` hashes into a
/// vector of `[u8; N]`. A hash whose length is not exactly `N` is rejected.
fn parse_hash_list<const N: usize>(body: &[u8], out: &mut Vec<[u8; N]>) -> Result<()> {
    let mut r = Reader::new(body);
    while !r.is_empty() {
        let h = r.read_string()?;
        let arr: [u8; N] = h
            .try_into()
            .map_err(|_| Error::Format("krl: bad fingerprint length"))?;
        out.push(arr);
    }
    Ok(())
}

#[cfg(test)]
mod tests;
