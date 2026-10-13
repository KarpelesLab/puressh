//! OpenSSH signatures: `ssh-keygen -Y sign / verify` (OpenSSH
//! `PROTOCOL.sshsig`), the format git uses for SSH commit and tag signing.
//!
//! A signature binds a message to a *namespace* (`git`, `file`, …) so it
//! cannot be replayed in another context. What gets signed is
//!
//! ```text
//! "SSHSIG" ‖ string namespace ‖ string reserved ‖ string hash_algorithm ‖ string H(message)
//! ```
//!
//! and the result travels as an armored blob
//! (`-----BEGIN SSH SIGNATURE-----`).

use alloc::string::String;
use alloc::vec::Vec;

use purecrypto::hash::{Digest, Sha256, Sha512};

use crate::error::{Error, Result};
use crate::format::{Reader, Writer};

const MAGIC: &[u8; 6] = b"SSHSIG";
const VERSION: u32 = 1;
const BEGIN: &str = "-----BEGIN SSH SIGNATURE-----";
const END: &str = "-----END SSH SIGNATURE-----";

/// Message digest of a signature.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum HashAlg {
    /// `sha256`.
    Sha256,
    /// `sha512` (OpenSSH's default).
    Sha512,
}

impl HashAlg {
    /// The name used on the wire.
    pub fn name(self) -> &'static str {
        match self {
            HashAlg::Sha256 => "sha256",
            HashAlg::Sha512 => "sha512",
        }
    }

    /// Parse a wire name.
    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "sha256" => Some(HashAlg::Sha256),
            "sha512" => Some(HashAlg::Sha512),
            _ => None,
        }
    }

    /// Digest `message` in one go.
    pub fn digest(self, message: &[u8]) -> Vec<u8> {
        match self {
            HashAlg::Sha256 => Sha256::digest(message).as_ref().to_vec(),
            HashAlg::Sha512 => Sha512::digest(message).as_ref().to_vec(),
        }
    }

    /// Digest everything `r` yields (for large files).
    #[cfg(feature = "std")]
    pub fn digest_reader<R: std::io::Read>(self, mut r: R) -> std::io::Result<Vec<u8>> {
        let mut buf = vec![0u8; 64 * 1024];
        match self {
            HashAlg::Sha256 => {
                let mut h = Sha256::new();
                loop {
                    let n = r.read(&mut buf)?;
                    if n == 0 {
                        break;
                    }
                    h.update(&buf[..n]);
                }
                Ok(h.finalize().as_ref().to_vec())
            }
            HashAlg::Sha512 => {
                let mut h = Sha512::new();
                loop {
                    let n = r.read(&mut buf)?;
                    if n == 0 {
                        break;
                    }
                    h.update(&buf[..n]);
                }
                Ok(h.finalize().as_ref().to_vec())
            }
        }
    }
}

/// The bytes a signature covers, given the message digest.
pub fn signed_data(namespace: &str, hash: HashAlg, message_digest: &[u8]) -> Vec<u8> {
    let mut w = Writer::new();
    w.write_raw(MAGIC);
    w.write_string(namespace.as_bytes());
    w.write_string(b"");
    w.write_string(hash.name().as_bytes());
    w.write_string(message_digest);
    w.into_vec()
}

/// A parsed SSHSIG signature.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Signature {
    /// Signer's public key (SSH wire blob).
    pub public_key: Vec<u8>,
    /// Namespace the signature was made for.
    pub namespace: String,
    /// Message digest algorithm.
    pub hash: HashAlg,
    /// SSH signature blob (`string alg ‖ string sig`).
    pub signature: Vec<u8>,
}

impl Signature {
    /// Sign a message digest (made with `hash`) under `namespace`; `sign`
    /// produces an SSH signature blob for the key `public_key` over the
    /// bytes it is given (a [`crate::hostkey::HostKey`], an agent, …).
    pub fn create(
        public_key: Vec<u8>,
        namespace: &str,
        hash: HashAlg,
        message_digest: &[u8],
        sign: impl FnOnce(&[u8]) -> Result<Vec<u8>>,
    ) -> Result<Self> {
        if namespace.is_empty() {
            return Err(Error::Config("sshsig: empty namespace"));
        }
        let signature = sign(&signed_data(namespace, hash, message_digest))?;
        Ok(Self {
            public_key,
            namespace: namespace.into(),
            hash,
            signature,
        })
    }

    /// The binary blob (`"SSHSIG" ‖ version ‖ …`).
    pub fn to_blob(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.write_raw(MAGIC);
        w.write_u32(VERSION);
        w.write_string(&self.public_key);
        w.write_string(self.namespace.as_bytes());
        w.write_string(b"");
        w.write_string(self.hash.name().as_bytes());
        w.write_string(&self.signature);
        w.into_vec()
    }

    /// Parse the binary blob.
    pub fn from_blob(blob: &[u8]) -> Result<Self> {
        let mut r = Reader::new(blob);
        if r.take(6)? != MAGIC {
            return Err(Error::Format("sshsig: bad magic"));
        }
        if r.read_u32()? != VERSION {
            return Err(Error::Unsupported("sshsig: version"));
        }
        let public_key = r.read_string()?.to_vec();
        let namespace = core::str::from_utf8(r.read_string()?)
            .map_err(|_| Error::Format("sshsig: namespace not UTF-8"))?
            .into();
        let _reserved = r.read_string()?;
        let hash = core::str::from_utf8(r.read_string()?)
            .ok()
            .and_then(HashAlg::from_name)
            .ok_or(Error::Unsupported("sshsig: hash algorithm"))?;
        let signature = r.read_string()?.to_vec();
        if !r.is_empty() {
            return Err(Error::Format("sshsig: trailing data"));
        }
        Ok(Self {
            public_key,
            namespace,
            hash,
            signature,
        })
    }

    /// The armored form written to `.sig` files.
    pub fn to_armored(&self) -> String {
        let b64 = crate::key::base64::encode(&self.to_blob());
        let mut out = String::with_capacity(b64.len() + 80);
        out.push_str(BEGIN);
        out.push('\n');
        for chunk in b64.as_bytes().chunks(70) {
            out.push_str(core::str::from_utf8(chunk).unwrap_or_default());
            out.push('\n');
        }
        out.push_str(END);
        out.push('\n');
        out
    }

    /// Parse the armored form.
    pub fn from_armored(text: &str) -> Result<Self> {
        let start = text
            .find(BEGIN)
            .ok_or(Error::Format("sshsig: missing BEGIN SSH SIGNATURE"))?
            + BEGIN.len();
        let rest = &text[start..];
        let end = rest
            .find(END)
            .ok_or(Error::Format("sshsig: missing END SSH SIGNATURE"))?;
        let b64: String = rest[..end].chars().filter(|c| !c.is_whitespace()).collect();
        Self::from_blob(&crate::key::base64_decode(b64.as_bytes())?)
    }

    /// Whether the signing key is a certificate.
    pub fn is_certificate(&self) -> bool {
        Reader::new(&self.public_key)
            .read_string()
            .ok()
            .and_then(|t| core::str::from_utf8(t).ok())
            .is_some_and(crate::cert::is_cert_name)
    }

    /// Check the signature over a message digest (made with [`Self::hash`])
    /// for `namespace`, against the embedded public key. Deciding whether
    /// that key is *trusted* is the caller's job (`allowed_signers`).
    pub fn verify(&self, namespace: &str, message_digest: &[u8]) -> Result<()> {
        if namespace != self.namespace {
            return Err(Error::BadSignature);
        }
        // A certificate signs with the key it certifies.
        let cert;
        let key_blob = if self.is_certificate() {
            cert = crate::cert::Certificate::parse(&self.public_key)?;
            cert.embedded_pubkey_blob()
        } else {
            &self.public_key[..]
        };
        let key_alg = Reader::new(key_blob).read_string()?;
        let sig_alg = Reader::new(&self.signature).read_string()?;
        let sig_alg = core::str::from_utf8(sig_alg).map_err(|_| Error::BadSignature)?;
        // OpenSSH refuses SHA-1 RSA signatures here.
        let family_ok = match key_alg {
            b"ssh-rsa" => matches!(sig_alg, "rsa-sha2-256" | "rsa-sha2-512"),
            other => sig_alg.as_bytes() == other,
        };
        if !family_ok {
            return Err(Error::BadSignature);
        }
        let verifier = crate::hostkey::host_key_verify_by_name(sig_alg, key_blob)?;
        verifier.verify(
            &signed_data(namespace, self.hash, message_digest),
            &self.signature,
        )
    }
}

/// Parse an OpenSSH absolute time, `YYYYMMDD[HHMM[SS]][Z]`, into Unix
/// seconds. Without the `Z` suffix the time is local:
/// `local_offset` is the local zone's offset east of UTC, in seconds.
pub fn parse_time(s: &str, local_offset: i64) -> Option<i64> {
    let (digits, utc) = match s.strip_suffix(['Z', 'z']) {
        Some(d) => (d, true),
        None => (s, false),
    };
    if !digits.bytes().all(|b| b.is_ascii_digit()) || !matches!(digits.len(), 8 | 12 | 14) {
        return None;
    }
    let num = |r: core::ops::Range<usize>| -> i64 {
        digits.get(r).and_then(|d| d.parse().ok()).unwrap_or(0)
    };
    let (y, mo, d) = (num(0..4), num(4..6), num(6..8));
    let (h, mi, sec) = (num(8..10), num(10..12), num(12..14));
    if !(1..=12).contains(&mo) || !(1..=31).contains(&d) || h > 23 || mi > 59 || sec > 60 {
        return None;
    }
    // Days since 1970-01-01 (Howard Hinnant's days_from_civil).
    let yy = if mo <= 2 { y - 1 } else { y };
    let era = yy.div_euclid(400);
    let yoe = yy - era * 400;
    let mp = (mo + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    let t = days * 86_400 + h * 3600 + mi * 60 + sec;
    Some(if utc { t } else { t - local_offset })
}

/// One line of an `allowed_signers` file (`ssh-keygen(1)`, "ALLOWED
/// SIGNERS"): `principals [options] keytype base64 [comment]`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct AllowedSigner {
    /// The principals field: comma-separated patterns (`*`, `?`, `!neg`).
    pub principals: String,
    /// `cert-authority`: the key is a CA trusted to certify principals.
    pub cert_authority: bool,
    /// `namespaces="…"`: patterns of the namespaces the key may sign for.
    pub namespaces: Option<String>,
    /// `valid-after=…`, as Unix seconds.
    pub valid_after: Option<i64>,
    /// `valid-before=…`, as Unix seconds.
    pub valid_before: Option<i64>,
    /// The key's SSH wire blob.
    pub public_key: Vec<u8>,
}

/// Split off the next whitespace-delimited token, honouring double quotes.
fn next_token(s: &str) -> Option<(&str, &str)> {
    let s = s.trim_start();
    if s.is_empty() {
        return None;
    }
    let mut quoted = false;
    for (i, c) in s.char_indices() {
        match c {
            '"' => quoted = !quoted,
            c if c.is_whitespace() && !quoted => return Some((&s[..i], &s[i..])),
            _ => {}
        }
    }
    Some((s, ""))
}

fn unquote(s: &str) -> &str {
    s.strip_prefix('"')
        .and_then(|s| s.strip_suffix('"'))
        .unwrap_or(s)
}

/// Whether `name` matches a comma-separated OpenSSH pattern list.
fn pattern_list_matches(list: &str, name: &str) -> bool {
    let pats: Vec<crate::config::HostPattern> = list
        .split(',')
        .map(|p| crate::config::HostPattern::parse(p.trim()))
        .collect();
    crate::config::host_matches(&pats, name)
}

impl AllowedSigner {
    /// Parse one line; `Ok(None)` for blank lines and comments. Times
    /// without `Z` are local (see [`parse_time`]).
    pub fn parse_line(line: &str, local_offset: i64) -> Result<Option<Self>> {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            return Ok(None);
        }
        let (principals, rest) = next_token(line).ok_or(Error::Format("allowed_signers"))?;
        let mut signer = AllowedSigner {
            principals: unquote(principals).into(),
            cert_authority: false,
            namespaces: None,
            valid_after: None,
            valid_before: None,
            public_key: Vec::new(),
        };
        let (mut tok, mut rest) =
            next_token(rest).ok_or(Error::Format("allowed_signers: missing key"))?;
        // An options list unless the token is a key type (`ssh-…`,
        // `ecdsa-…`, `sk-…`, or anything with `@`).
        let is_key_type =
            |t: &str| t.starts_with("ssh-") || t.starts_with("ecdsa-") || t.starts_with("sk-");
        if !is_key_type(tok) {
            let mut opts = tok;
            while !opts.is_empty() {
                // Split at the first comma outside quotes.
                let mut quoted = false;
                let mut end = opts.len();
                for (i, c) in opts.char_indices() {
                    match c {
                        '"' => quoted = !quoted,
                        ',' if !quoted => {
                            end = i;
                            break;
                        }
                        _ => {}
                    }
                }
                let opt = &opts[..end];
                opts = opts.get(end + 1..).unwrap_or("");
                let (name, value) = match opt.split_once('=') {
                    Some((n, v)) => (n, Some(unquote(v))),
                    None => (opt, None),
                };
                match (name.to_ascii_lowercase().as_str(), value) {
                    ("cert-authority", None) => signer.cert_authority = true,
                    ("namespaces", Some(v)) => signer.namespaces = Some(v.into()),
                    ("valid-after", Some(v)) => {
                        signer.valid_after = Some(
                            parse_time(v, local_offset)
                                .ok_or(Error::Format("allowed_signers: bad valid-after"))?,
                        )
                    }
                    ("valid-before", Some(v)) => {
                        signer.valid_before = Some(
                            parse_time(v, local_offset)
                                .ok_or(Error::Format("allowed_signers: bad valid-before"))?,
                        )
                    }
                    _ => return Err(Error::Format("allowed_signers: unknown option")),
                }
            }
            (tok, rest) = next_token(rest).ok_or(Error::Format("allowed_signers: missing key"))?;
        }
        let (b64, _comment) =
            next_token(rest).ok_or(Error::Format("allowed_signers: missing key blob"))?;
        let blob = crate::key::base64_decode(b64.as_bytes())?;
        if Reader::new(&blob).read_string()? != tok.as_bytes() {
            return Err(Error::Format("allowed_signers: key type mismatch"));
        }
        signer.public_key = blob;
        Ok(Some(signer))
    }

    /// Parse a whole file. Like OpenSSH, a malformed line does not void the
    /// file: it is skipped and reported (1-based line number) in the second
    /// list.
    pub fn parse_file(text: &str, local_offset: i64) -> (Vec<Self>, Vec<(usize, Error)>) {
        let mut out = Vec::new();
        let mut bad = Vec::new();
        for (i, line) in text.lines().enumerate() {
            match Self::parse_line(line, local_offset) {
                Ok(Some(s)) => out.push(s),
                Ok(None) => {}
                Err(e) => bad.push((i + 1, e)),
            }
        }
        (out, bad)
    }

    /// Whether `principal` matches the principals patterns.
    pub fn matches_principal(&self, principal: &str) -> bool {
        pattern_list_matches(&self.principals, principal)
    }

    /// Whether the key may sign for `namespace`.
    pub fn allows_namespace(&self, namespace: &str) -> bool {
        self.namespaces
            .as_deref()
            .is_none_or(|l| pattern_list_matches(l, namespace))
    }

    /// Whether the key is valid at Unix time `now`.
    pub fn valid_at(&self, now: i64) -> bool {
        self.valid_after.is_none_or(|t| now >= t) && self.valid_before.is_none_or(|t| now <= t)
    }

    /// Whether this (plain, non-CA) entry is `public_key`, valid at `now`.
    pub fn is_key(&self, public_key: &[u8], now: i64) -> bool {
        !self.cert_authority && self.public_key == public_key && self.valid_at(now)
    }

    /// For a `cert-authority` entry: the principals of the user
    /// certificate `public_key` that this CA vouches for at `now` — the
    /// certificate is signed by the entry's key, valid then, and its
    /// principals that match the entry's patterns are returned (OpenSSH's
    /// `cert_filter_principals`). `None` when the entry does not apply.
    pub fn certified_principals(&self, public_key: &[u8], now: i64) -> Option<Vec<String>> {
        if !self.cert_authority || !self.valid_at(now) {
            return None;
        }
        let cert = crate::cert::Certificate::parse(public_key).ok()?;
        if cert.signature_key_blob != self.public_key
            || cert.check_type(crate::cert::CertType::User).is_err()
            || cert.check_validity(u64::try_from(now).ok()?).is_err()
            || cert
                .verify_ca_signature(crate::config::algos::CA_SIGNATURE_DEFAULTS)
                .is_err()
        {
            return None;
        }
        let principals: Vec<String> = cert
            .valid_principals
            .iter()
            .filter(|p| pattern_list_matches(&self.principals, p))
            .cloned()
            .collect();
        (!principals.is_empty()).then_some(principals)
    }

    /// Whether this entry lets `principal` sign with `public_key` at `now`:
    /// the key itself, or a user certificate for `principal` from this CA.
    pub fn accepts(&self, public_key: &[u8], principal: &str, now: i64) -> bool {
        self.matches_principal(principal)
            && (self.is_key(public_key, now)
                || self
                    .certified_principals(public_key, now)
                    .is_some_and(|ps| ps.iter().any(|p| p == principal)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hostkey::{Ed25519HostKey, HostKey};

    #[test]
    fn round_trip_and_tamper() {
        let k = Ed25519HostKey::from_seed([3u8; 32]);
        let digest = HashAlg::Sha512.digest(b"hello");
        let sig = Signature::create(k.public_blob(), "git", HashAlg::Sha512, &digest, |d| {
            k.sign(d)
        })
        .unwrap();
        let armored = sig.to_armored();
        assert!(armored.starts_with(BEGIN));
        let back = Signature::from_armored(&armored).unwrap();
        assert_eq!(back, sig);
        back.verify("git", &digest).unwrap();
        assert!(back.verify("file", &digest).is_err());
        assert!(
            back.verify("git", &HashAlg::Sha512.digest(b"hellp"))
                .is_err()
        );
    }

    /// A signature made by OpenSSH's `ssh-keygen -Y sign -n file` over the
    /// bytes `hello\n`.
    #[test]
    fn verifies_openssh_signature() {
        let armored = "-----BEGIN SSH SIGNATURE-----
U1NIU0lHAAAAAQAAADMAAAALc3NoLWVkMjU1MTkAAAAgs7+QuQzU/yQ4EllhQAh6dCmy3d
KJfG6C1q+3rOimMN8AAAAEZmlsZQAAAAAAAAAGc2hhNTEyAAAAUwAAAAtzc2gtZWQyNTUx
OQAAAEAI9Ntbxi+23+prlNNxjEHVu6Ia95CmEVAjiv98gKf+CdSMmTeO04JyyBcp/cuXA0
NAvsE8MkuMT1B7DXfOZDcN
-----END SSH SIGNATURE-----
";
        let sig = Signature::from_armored(armored).unwrap();
        assert_eq!(sig.namespace, "file");
        assert_eq!(sig.hash, HashAlg::Sha512);
        sig.verify("file", &HashAlg::Sha512.digest(b"hello\n"))
            .unwrap();
        assert!(
            sig.verify("file", &HashAlg::Sha512.digest(b"hello"))
                .is_err()
        );
    }

    #[test]
    fn times() {
        assert_eq!(parse_time("19700101Z", 0), Some(0));
        assert_eq!(parse_time("20240229123456Z", 0), Some(1_709_210_096));
        assert_eq!(parse_time("202402291234", 3600), Some(1_709_210_040 - 3600));
        assert_eq!(parse_time("2024022", 0), None);
        assert_eq!(parse_time("20241301", 0), None);
    }

    #[test]
    fn allowed_signers_lines() {
        let k = Ed25519HostKey::from_seed([3u8; 32]);
        let b64 = crate::key::base64::encode(&k.public_blob());
        let text = alloc::format!(
            "# comment\n\n\
             alice@example.com,*@corp.example ssh-ed25519 {b64} alice\n\
             \"bob@x\" namespaces=\"git,file\",valid-after=20200101Z ssh-ed25519 {b64}\n\
             ca@x cert-authority ssh-ed25519 {b64}\n"
        );
        let (signers, bad) = AllowedSigner::parse_file(&text, 0);
        assert!(bad.is_empty());
        assert_eq!(signers.len(), 3);
        assert!(signers[0].matches_principal("joe@corp.example"));
        assert!(!signers[0].matches_principal("joe@other"));
        assert!(signers[0].allows_namespace("anything"));
        assert_eq!(signers[1].principals, "bob@x");
        assert!(signers[1].allows_namespace("git"));
        assert!(!signers[1].allows_namespace("ssh"));
        assert!(!signers[1].valid_at(0));
        assert!(signers[1].is_key(&k.public_blob(), 1_700_000_000));
        assert!(signers[2].cert_authority);
        assert!(!signers[2].is_key(&k.public_blob(), 0));
        assert!(
            AllowedSigner::parse_line(&alloc::format!("x bogus=1 ssh-ed25519 {b64}"), 0).is_err()
        );
        assert!(AllowedSigner::parse_line(&alloc::format!("x ssh-rsa {b64}"), 0).is_err());
    }
}
