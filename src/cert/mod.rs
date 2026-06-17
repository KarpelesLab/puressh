//! OpenSSH certificate parsing and verification (`*-cert-v01@openssh.com`).
//!
//! An OpenSSH certificate is a CA-signed wrapper around an ordinary SSH public
//! key. The wire blob (the bytes that appear where a plain key blob would
//! otherwise sit — in a KEX `K_S`, in `authorized_keys`, in a userauth
//! request) has this layout (PROTOCOL.certkeys):
//!
//! ```text
//! string    type        (e.g. "ssh-ed25519-cert-v01@openssh.com")
//! string    nonce
//! <type-specific public-key fields>
//! uint64    serial
//! uint32    type         (1 = user, 2 = host)
//! string    key id
//! string    valid principals   (a list-of-strings, itself length-prefixed)
//! uint64    valid after
//! uint64    valid before
//! string    critical options   (a list of (name,data) pairs)
//! string    extensions         (a list of (name,data) pairs)
//! string    reserved
//! string    signature key       (the CA's plain public-key blob)
//! string    signature           (the CA's signature over everything before it)
//! ```
//!
//! The CA signs `raw[..signed_len]` where `signed_len` is the offset of the
//! final `signature` string (i.e. everything up to and including the
//! `signature key` field). [`Certificate::verify_ca_signature`] reconstructs a
//! verifier for the CA's key and checks that signature, additionally requiring
//! the CA's signature algorithm to be in a caller-supplied allow-list
//! (`CASignatureAlgorithms`).
//!
//! This module deliberately does **not** make any trust decision: parsing and
//! CA-signature verification say "this blob is a well-formed certificate signed
//! by the key it names as its CA". Whether that CA is *trusted*, and whether
//! the certificate authorizes a given host or login, is decided by the caller
//! (the client's known-hosts `@cert-authority` logic, the server's
//! `TrustedUserCAKeys` / `authorized_keys` logic).

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use crate::error::{Error, Result};
use crate::format::{Reader, Writer};
use crate::hostkey::host_key_verify_by_name;

/// Maximum accepted size of a raw certificate blob. OpenSSH certs are a few
/// hundred bytes to a couple of kilobytes; 64 KiB is a generous ceiling that
/// still bounds memory and parser work against a hostile peer.
pub const MAX_CERT_BLOB: usize = 64 * 1024;

/// Maximum number of entries in a list field (principals, critical options,
/// extensions). OpenSSH itself caps principals at 256.
const MAX_LIST_ENTRIES: usize = 256;

/// Maximum length of a single list element (a principal name, an option name,
/// or an option's embedded data string).
const MAX_LIST_ELEM: usize = 8 * 1024;

/// The certificate's `type` field: user (1) or host (2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertType {
    /// A user certificate (client authenticates to a server).
    User,
    /// A host certificate (server authenticates to a client).
    Host,
}

impl CertType {
    fn from_u32(v: u32) -> Result<Self> {
        match v {
            1 => Ok(CertType::User),
            2 => Ok(CertType::Host),
            _ => Err(Error::Format("cert: unknown certificate type")),
        }
    }
}

/// The certificate key-type names this build understands.
///
/// These are the names OpenSSH puts on the wire (KEX host-key list,
/// userauth publickey method, `authorized_keys`). There is exactly one RSA
/// certificate type, `ssh-rsa-cert-v01@openssh.com`; the SHA-2 hash actually
/// used for a given signature is carried in the signature blob itself, not in
/// the certificate type name.
///
/// Order matches descending host-key preference.
pub const CERT_KEY_NAMES: &[&str] = &[
    "ssh-ed25519-cert-v01@openssh.com",
    "ecdsa-sha2-nistp256-cert-v01@openssh.com",
    "ecdsa-sha2-nistp384-cert-v01@openssh.com",
    "ecdsa-sha2-nistp521-cert-v01@openssh.com",
    "rsa-sha2-512-cert-v01@openssh.com",
    "rsa-sha2-256-cert-v01@openssh.com",
];

/// Returns true if `name` is one of the OpenSSH certificate key-type names.
pub fn is_cert_name(name: &str) -> bool {
    name.ends_with("-cert-v01@openssh.com")
}

/// Map a *negotiated* certificate key-type name (the one that appears on the
/// wire in the KEX host-key list or the userauth publickey method) to the plain
/// signature algorithm name used to verify `H` / the userauth signature with
/// the cert's *embedded* key.
///
/// RSA certs are negotiated under three names —
/// `ssh-rsa-cert-v01@openssh.com` (legacy SHA-1) and the SHA-2 variants
/// `rsa-sha2-{256,512}-cert-v01@openssh.com` (RFC 8332-style upgrade) — even
/// though the certificate blob's own type string is always
/// `ssh-rsa-cert-v01@openssh.com`. The signature hash is pinned by the
/// negotiated name here, exactly as for plain RSA keys.
pub fn cert_name_to_plain(name: &str) -> Option<&'static str> {
    match name {
        "ssh-ed25519-cert-v01@openssh.com" => Some("ssh-ed25519"),
        "ecdsa-sha2-nistp256-cert-v01@openssh.com" => Some("ecdsa-sha2-nistp256"),
        "ecdsa-sha2-nistp384-cert-v01@openssh.com" => Some("ecdsa-sha2-nistp384"),
        "ecdsa-sha2-nistp521-cert-v01@openssh.com" => Some("ecdsa-sha2-nistp521"),
        "rsa-sha2-512-cert-v01@openssh.com" => Some("rsa-sha2-512"),
        "rsa-sha2-256-cert-v01@openssh.com" => Some("rsa-sha2-256"),
        "ssh-rsa-cert-v01@openssh.com" => Some("ssh-rsa"),
        _ => None,
    }
}

/// Map the *certificate blob's own* type string (the first field of the blob)
/// to the plain key-type used to reconstruct the embedded public key. This is
/// the canonical-form name; for RSA it is always `ssh-rsa-cert-v01@openssh.com`
/// regardless of how the algorithm was negotiated on the wire.
fn blob_type_to_plain(name: &str) -> Option<&'static str> {
    match name {
        "ssh-ed25519-cert-v01@openssh.com" => Some("ssh-ed25519"),
        "ecdsa-sha2-nistp256-cert-v01@openssh.com" => Some("ecdsa-sha2-nistp256"),
        "ecdsa-sha2-nistp384-cert-v01@openssh.com" => Some("ecdsa-sha2-nistp384"),
        "ecdsa-sha2-nistp521-cert-v01@openssh.com" => Some("ecdsa-sha2-nistp521"),
        "ssh-rsa-cert-v01@openssh.com" => Some("ssh-rsa"),
        _ => None,
    }
}

/// A parsed OpenSSH certificate.
///
/// All owned fields are bounded by [`MAX_CERT_BLOB`] and the per-list caps
/// applied at [`parse`](Certificate::parse) time.
#[derive(Debug, Clone)]
pub struct Certificate {
    /// The cert key-type name, e.g. `"ssh-ed25519-cert-v01@openssh.com"`.
    pub key_type: String,
    /// The 16- (or 32-) byte CA-chosen nonce, defeating hash-collision tricks.
    pub nonce: Vec<u8>,
    /// The reconstructed *plain* public-key blob of the embedded key, in the
    /// wire format [`host_key_verify_by_name`] understands.
    pub embedded_pubkey_blob: Vec<u8>,
    /// Monotonic CA-assigned serial number (0 if unset).
    pub serial: u64,
    /// User or host.
    pub cert_type: CertType,
    /// Free-form identity string the CA stamped in (shows up in logs).
    pub key_id: String,
    /// The principals this cert is valid for (host names for host certs, login
    /// users for user certs). An empty list means "any principal".
    pub valid_principals: Vec<String>,
    /// Start of the validity window (seconds since the Unix epoch).
    pub valid_after: u64,
    /// End of the validity window (seconds since the Unix epoch, exclusive).
    pub valid_before: u64,
    /// Critical options as ordered `(name, data)` pairs. MUST be understood.
    pub critical_options: Vec<(String, Vec<u8>)>,
    /// Extensions as ordered `(name, data)` pairs. Advisory; unknown tolerated.
    pub extensions: Vec<(String, Vec<u8>)>,
    /// The CA's plain public-key blob (the key that signed this cert).
    pub signature_key_blob: Vec<u8>,
    /// The CA's signature blob over `raw[..signed_len]`.
    pub signature: Vec<u8>,
    /// Offset in `raw` of the start of the `signature` field — i.e. the number
    /// of bytes the CA signed.
    pub signed_len: usize,
    /// The full raw certificate blob, as received.
    pub raw: Vec<u8>,
}

/// Read a length-prefixed string with a cap, returning an owned copy.
fn read_capped(r: &mut Reader<'_>, cap: usize, what: &'static str) -> Result<Vec<u8>> {
    let s = r.read_string()?;
    if s.len() > cap {
        return Err(Error::Format(what));
    }
    Ok(s.to_vec())
}

/// Parse an inner "list of strings" (each element itself a length-prefixed
/// string), bounded by the per-list caps.
fn parse_string_list(blob: &[u8]) -> Result<Vec<String>> {
    let mut r = Reader::new(blob);
    let mut out = Vec::new();
    while !r.is_empty() {
        if out.len() >= MAX_LIST_ENTRIES {
            return Err(Error::Format("cert: too many list entries"));
        }
        let elem = r.read_string()?;
        if elem.len() > MAX_LIST_ELEM {
            return Err(Error::Format("cert: list element too long"));
        }
        let s = core::str::from_utf8(elem)
            .map_err(|_| Error::Format("cert: non-utf8 principal"))?
            .to_string();
        out.push(s);
    }
    Ok(out)
}

/// Parse an inner "list of (name, data)" pairs (critical options / extensions).
/// Each entry is a `string name` followed by a `string data`. OpenSSH requires
/// the names to be sorted with no duplicates; we enforce strictly-ascending
/// order so a hostile cert can't smuggle a duplicate option past the
/// understood-options check.
fn parse_pair_list(blob: &[u8]) -> Result<Vec<(String, Vec<u8>)>> {
    let mut r = Reader::new(blob);
    let mut out: Vec<(String, Vec<u8>)> = Vec::new();
    while !r.is_empty() {
        if out.len() >= MAX_LIST_ENTRIES {
            return Err(Error::Format("cert: too many option entries"));
        }
        let name = r.read_string()?;
        if name.len() > MAX_LIST_ELEM {
            return Err(Error::Format("cert: option name too long"));
        }
        let data = r.read_string()?;
        if data.len() > MAX_LIST_ELEM {
            return Err(Error::Format("cert: option data too long"));
        }
        let name = core::str::from_utf8(name)
            .map_err(|_| Error::Format("cert: non-utf8 option name"))?
            .to_string();
        if let Some((last, _)) = out.last()
            && name.as_str() <= last.as_str()
        {
            return Err(Error::Format(
                "cert: option names must be strictly ascending (duplicate or unsorted)",
            ));
        }
        out.push((name, data.to_vec()));
    }
    Ok(out)
}

/// Reconstruct the plain public-key blob from a certificate's type-specific
/// fields, leaving the reader positioned just after those fields.
fn read_embedded_pubkey(key_type: &str, r: &mut Reader<'_>) -> Result<Vec<u8>> {
    let mut w = Writer::new();
    match key_type {
        "ssh-ed25519-cert-v01@openssh.com" => {
            let pk = r.read_string()?;
            if pk.len() != 32 {
                return Err(Error::Format("cert: ed25519 key length"));
            }
            w.write_string(b"ssh-ed25519");
            w.write_string(pk);
        }
        "ecdsa-sha2-nistp256-cert-v01@openssh.com"
        | "ecdsa-sha2-nistp384-cert-v01@openssh.com"
        | "ecdsa-sha2-nistp521-cert-v01@openssh.com" => {
            let plain = blob_type_to_plain(key_type).expect("matched arm");
            let curve = r.read_string()?;
            let point = r.read_string()?;
            // Sanity: curve identifier must match the algorithm's curve.
            let want_curve: &[u8] = match plain {
                "ecdsa-sha2-nistp256" => b"nistp256",
                "ecdsa-sha2-nistp384" => b"nistp384",
                "ecdsa-sha2-nistp521" => b"nistp521",
                _ => unreachable!(),
            };
            if curve != want_curve {
                return Err(Error::Format("cert: ecdsa curve mismatch"));
            }
            w.write_string(plain.as_bytes());
            w.write_string(curve);
            w.write_string(point);
        }
        "ssh-rsa-cert-v01@openssh.com" => {
            // RSA cert public fields are `mpint e, mpint n` — note the order
            // (e then n), matching the plain ssh-rsa blob.
            let e = r.read_string()?;
            let n = r.read_string()?;
            w.write_string(b"ssh-rsa");
            w.write_string(e);
            w.write_string(n);
        }
        _ => return Err(Error::Format("cert: unsupported certificate key type")),
    }
    Ok(w.into_vec())
}

impl Certificate {
    /// Parse a certificate blob.
    ///
    /// Rejects oversized blobs (> [`MAX_CERT_BLOB`]), unknown key types, list
    /// overflow, and any trailing bytes after the final `signature` field.
    pub fn parse(blob: &[u8]) -> Result<Self> {
        if blob.len() > MAX_CERT_BLOB {
            return Err(Error::Format("cert: blob exceeds maximum size"));
        }
        let mut r = Reader::new(blob);

        let key_type_b = r.read_string()?;
        let key_type = core::str::from_utf8(key_type_b)
            .map_err(|_| Error::Format("cert: non-utf8 key type"))?
            .to_string();
        if blob_type_to_plain(&key_type).is_none() {
            return Err(Error::Format("cert: unsupported certificate key type"));
        }

        let nonce = read_capped(&mut r, MAX_LIST_ELEM, "cert: nonce too long")?;

        let embedded_pubkey_blob = read_embedded_pubkey(&key_type, &mut r)?;

        let serial = r.read_u64()?;
        let cert_type = CertType::from_u32(r.read_u32()?)?;
        let key_id = {
            let b = read_capped(&mut r, MAX_LIST_ELEM, "cert: key id too long")?;
            String::from_utf8(b).map_err(|_| Error::Format("cert: non-utf8 key id"))?
        };

        let principals_blob = read_capped(
            &mut r,
            MAX_LIST_ENTRIES * MAX_LIST_ELEM,
            "cert: principals list too long",
        )?;
        let valid_principals = parse_string_list(&principals_blob)?;

        let valid_after = r.read_u64()?;
        let valid_before = r.read_u64()?;
        if valid_after > valid_before {
            return Err(Error::Format("cert: valid_after after valid_before"));
        }

        let crit_blob = read_capped(
            &mut r,
            MAX_LIST_ENTRIES * (2 * MAX_LIST_ELEM),
            "cert: critical options too long",
        )?;
        let critical_options = parse_pair_list(&crit_blob)?;

        let ext_blob = read_capped(
            &mut r,
            MAX_LIST_ENTRIES * (2 * MAX_LIST_ELEM),
            "cert: extensions too long",
        )?;
        let extensions = parse_pair_list(&ext_blob)?;

        // reserved — must be present, currently always empty; ignore content.
        let _reserved = read_capped(&mut r, MAX_LIST_ELEM, "cert: reserved too long")?;

        let signature_key_blob =
            read_capped(&mut r, MAX_LIST_ELEM, "cert: signature key too long")?;

        // The CA signs everything up to (but not including) the final
        // signature string. After reading the signature-key string, the
        // reader is positioned exactly at the start of the signature's length
        // prefix; the bytes consumed so far are the signed region.
        let signed_len = blob.len() - r.remaining();

        let signature = read_capped(&mut r, MAX_LIST_ELEM, "cert: signature too long")?;

        if !r.is_empty() {
            return Err(Error::Format("cert: trailing data after certificate"));
        }

        Ok(Certificate {
            key_type,
            nonce,
            embedded_pubkey_blob,
            serial,
            cert_type,
            key_id,
            valid_principals,
            valid_after,
            valid_before,
            critical_options,
            extensions,
            signature_key_blob,
            signature,
            signed_len,
            raw: blob.to_vec(),
        })
    }

    /// Parse a certificate from an OpenSSH single-line public form:
    /// `<cert-key-type> <base64-blob> [comment]` (the contents of a
    /// `*-cert.pub` file). The leading key-type token must be one of
    /// [`CERT_KEY_NAMES`]; the returned certificate's blob type is validated
    /// against it.
    pub fn parse_openssh_line(line: &str) -> Result<Self> {
        let line = line.trim();
        let mut it = line.split_whitespace();
        let name = it.next().ok_or(Error::Format("cert: empty line"))?;
        if !CERT_KEY_NAMES.contains(&name) {
            return Err(Error::Format("cert: line is not an OpenSSH certificate"));
        }
        let b64 = it
            .next()
            .ok_or(Error::Format("cert: missing base64 blob"))?;
        let blob = crate::key::base64_decode(b64.as_bytes())?;
        let cert = Self::parse(&blob)?;
        // The negotiated/file name must be consistent with the blob's own type.
        if cert_name_to_plain(name) != blob_type_to_plain(&cert.key_type) {
            return Err(Error::Format("cert: line key-type disagrees with blob"));
        }
        Ok(cert)
    }

    /// The plain key-type name of the embedded key (e.g. `"ssh-ed25519"`,
    /// `"ssh-rsa"`). For RSA this is the SHA-1-era name; the actual signature
    /// hash is taken from the signature blob — see [`embedded_verifier`].
    ///
    /// [`embedded_verifier`]: Certificate::embedded_verifier
    pub fn embedded_algorithm(&self) -> &'static str {
        blob_type_to_plain(&self.key_type).expect("validated at parse")
    }

    /// Build a `HostKeyVerify` over the *embedded* key, using the signature
    /// algorithm named inside `sig_blob` (the signature that will be verified).
    ///
    /// This is what verifies the KEX exchange-hash signature (host certs) or
    /// the userauth signature (user certs): the cert's embedded key signed `H`
    /// / the userauth blob, and the algorithm it used is carried in the
    /// signature itself. For ed25519/ECDSA the algorithm is fixed; for RSA the
    /// signer may have used `rsa-sha2-256` or `rsa-sha2-512`, both of which are
    /// accepted here (plain SHA-1 `ssh-rsa` remains gated by
    /// [`crate::hostkey::set_allow_rsa_sha1`]).
    ///
    /// The named algorithm must be consistent with the embedded key type, so a
    /// cert wrapping an ed25519 key cannot have its `H` "verified" by an RSA
    /// signature blob.
    pub fn embedded_verifier(
        &self,
        sig_blob: &[u8],
    ) -> Result<alloc::boxed::Box<dyn crate::hostkey::HostKeyVerify>> {
        let mut r = Reader::new(sig_blob);
        let sig_algo = r.read_string()?;
        let sig_algo =
            core::str::from_utf8(sig_algo).map_err(|_| Error::Format("cert: non-utf8 sig algo"))?;
        let embedded = self.embedded_algorithm();
        let compatible = match embedded {
            "ssh-ed25519" => sig_algo == "ssh-ed25519",
            "ecdsa-sha2-nistp256" => sig_algo == "ecdsa-sha2-nistp256",
            "ecdsa-sha2-nistp384" => sig_algo == "ecdsa-sha2-nistp384",
            "ecdsa-sha2-nistp521" => sig_algo == "ecdsa-sha2-nistp521",
            "ssh-rsa" => {
                matches!(sig_algo, "ssh-rsa" | "rsa-sha2-256" | "rsa-sha2-512")
            }
            _ => false,
        };
        if !compatible {
            return Err(Error::Format(
                "cert: signature algorithm not compatible with key",
            ));
        }
        host_key_verify_by_name(sig_algo, &self.embedded_pubkey_blob)
    }

    /// The reconstructed plain public-key blob of the embedded key.
    pub fn embedded_pubkey_blob(&self) -> &[u8] {
        &self.embedded_pubkey_blob
    }

    /// The CA's signature algorithm, read from the `signature` blob's leading
    /// algorithm-name string. This is the *actual* algorithm the CA used (e.g.
    /// `rsa-sha2-512`), which may differ from the CA key's nominal type.
    pub fn ca_algorithm(&self) -> Result<&str> {
        let mut r = Reader::new(&self.signature);
        let name = r.read_string()?;
        core::str::from_utf8(name).map_err(|_| Error::Format("cert: non-utf8 CA signature algo"))
    }

    /// Verify the CA's signature over the signed region, requiring the CA's
    /// signature algorithm to be in `allowed_ca_algos`.
    ///
    /// `allowed_ca_algos` is the resolved `CASignatureAlgorithms` set. An empty
    /// slice is treated as "reject everything" — callers must pass the
    /// effective default list, never an empty one, if they mean "any default".
    pub fn verify_ca_signature(&self, allowed_ca_algos: &[&str]) -> Result<()> {
        let ca_algo = self.ca_algorithm().map_err(|_| Error::CertBadCaSignature)?;
        if !allowed_ca_algos.contains(&ca_algo) {
            return Err(Error::CertBadCaSignature);
        }
        let verifier = host_key_verify_by_name(ca_algo, &self.signature_key_blob)
            .map_err(|_| Error::CertBadCaSignature)?;
        verifier
            .verify(&self.raw[..self.signed_len], &self.signature)
            .map_err(|_| Error::CertBadCaSignature)
    }

    /// Check the validity window: `valid_after <= now < valid_before`.
    pub fn check_validity(&self, now: u64) -> Result<()> {
        if now < self.valid_after {
            return Err(Error::CertNotYetValid);
        }
        if now >= self.valid_before {
            return Err(Error::CertExpired);
        }
        Ok(())
    }

    /// Check that `name` is among the valid principals. An empty principals
    /// list authorizes any principal (OpenSSH semantics).
    pub fn check_principal(&self, name: &str) -> Result<()> {
        if self.valid_principals.is_empty() {
            return Ok(());
        }
        if self.valid_principals.iter().any(|p| p == name) {
            Ok(())
        } else {
            Err(Error::CertPrincipalMismatch)
        }
    }

    /// Check the certificate is of the expected type (user vs host).
    pub fn check_type(&self, want: CertType) -> Result<()> {
        if self.cert_type == want {
            Ok(())
        } else {
            Err(Error::CertTypeMismatch)
        }
    }

    /// Return the names of any critical options this build does not know how to
    /// honor. Per the spec, a non-empty result means the cert MUST be rejected.
    ///
    /// The understood set is `force-command` and `source-address`; everything
    /// else is unknown.
    pub fn unknown_critical_options(&self) -> Vec<&str> {
        self.critical_options
            .iter()
            .filter(|(name, _)| !matches!(name.as_str(), "force-command" | "source-address"))
            .map(|(name, _)| name.as_str())
            .collect()
    }

    /// Convenience: reject the certificate outright if it carries any critical
    /// option we don't understand.
    pub fn require_known_critical_options(&self) -> Result<()> {
        if self.unknown_critical_options().is_empty() {
            Ok(())
        } else {
            Err(Error::CertUnknownCriticalOption)
        }
    }

    /// The data for a critical option by name, if present.
    pub fn critical_option(&self, name: &str) -> Option<&[u8]> {
        self.critical_options
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, d)| d.as_slice())
    }

    /// True if the named extension is present.
    pub fn has_extension(&self, name: &str) -> bool {
        self.extensions.iter().any(|(n, _)| n == name)
    }
}

#[cfg(test)]
mod tests;
