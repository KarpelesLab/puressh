//! `RevokedHostKeys` (`ssh_config(5)`): host keys the client must refuse,
//! given as an OpenSSH KRL or as a text file of public keys.

use std::io;
use std::path::Path;

use crate::cert::Certificate;
use crate::krl::Krl;

/// A revoked host key list.
#[non_exhaustive]
pub enum RevokedHostKeys {
    /// A binary OpenSSH key revocation list.
    Krl(Krl),
    /// Public-key wire blobs, one per line of a text file
    /// (`keytype base64 [comment]`; blank lines and `#` comments skipped).
    Keys(Vec<Vec<u8>>),
}

impl core::fmt::Debug for RevokedHostKeys {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Krl(_) => f.write_str("RevokedHostKeys::Krl(..)"),
            Self::Keys(k) => write!(f, "RevokedHostKeys::Keys({} keys)", k.len()),
        }
    }
}

impl RevokedHostKeys {
    /// Parse a file's contents: a KRL if it is one, else a key list. A line
    /// that is not a public key fails the whole file, so a typo can never
    /// silently un-revoke a key.
    pub fn parse(data: &[u8]) -> crate::Result<Self> {
        if let Ok(krl) = Krl::parse(data) {
            return Ok(Self::Krl(krl));
        }
        let text = core::str::from_utf8(data)
            .map_err(|_| crate::Error::Format("revoked host keys: not a KRL or key list"))?;
        let mut keys = Vec::new();
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let b64 = line
                .split_whitespace()
                .nth(1)
                .ok_or(crate::Error::Format("revoked host keys: bad line"))?;
            keys.push(crate::key::base64_decode(b64.as_bytes())?);
        }
        Ok(Self::Keys(keys))
    }

    /// Read and parse `path`. As with OpenSSH, an unreadable file is an
    /// error: the caller must refuse the connection rather than skip the
    /// check.
    pub fn load(path: impl AsRef<Path>) -> io::Result<Self> {
        let data = std::fs::read(path)?;
        Self::parse(&data).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))
    }

    /// Whether the plain host key `blob` is revoked.
    pub fn is_revoked_key(&self, blob: &[u8]) -> bool {
        match self {
            Self::Krl(krl) => krl.is_revoked_key(blob),
            Self::Keys(keys) => keys.iter().any(|k| k == blob),
        }
    }

    /// Whether a host certificate is revoked: its own key, its CA's key,
    /// or (KRL) the certificate itself by serial or key id.
    pub fn is_revoked_cert(&self, cert: &Certificate) -> bool {
        if self.is_revoked_key(&cert.embedded_pubkey_blob)
            || self.is_revoked_key(&cert.signature_key_blob)
        {
            return true;
        }
        match self {
            Self::Krl(krl) => {
                krl.is_revoked_cert(&cert.signature_key_blob, cert.serial, &cert.key_id)
            }
            Self::Keys(_) => false,
        }
    }
}
