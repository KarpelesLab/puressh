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

use purecrypto::bignum::BoxedUint;
use purecrypto::cipher::{Aes128, Aes256, Ctr};
use purecrypto::ec::{BoxedEcdsaPrivateKey, BoxedEcdsaPublicKey, CurveId, Ed25519PrivateKey};
use purecrypto::kdf::bcrypt_pbkdf;
use purecrypto::zeroize::{Zeroize, Zeroizing};

use crate::error::{Error, Result};
use crate::format::{Reader, Writer, read_mpint, write_mpint};

pub(crate) mod base64;
mod encrypted;
mod export;
mod pkcs;
mod writer;

pub use writer::EcdsaCurve;

/// Decode standard (padded) base64, as used in `authorized_keys` / `.pub` /
/// `*-cert.pub` files. Exposed crate-wide so the certificate module can parse
/// OpenSSH single-line public forms without duplicating the decoder.
pub(crate) fn base64_decode(input: &[u8]) -> Result<Vec<u8>> {
    base64::decode(input)
}

/// The options of an `authorized_keys` line (`sshd(8)`, "AUTHORIZED_KEYS
/// FILE FORMAT"), parsed by
/// [`PublicKey::parse_authorized_keys_line_with_options`].
///
/// Every OpenSSH option is understood; an unknown or malformed one makes the
/// whole line invalid, as with OpenSSH (never silently dropped).
#[derive(Debug, Default, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct AuthorizedKeyOptions {
    /// The `cert-authority` flag: this key is a CA whose certificates are
    /// trusted (rather than a directly-authorized user key).
    pub cert_authority: bool,
    /// `principals="a,b,c"` — the principals this line authorizes. Empty when
    /// the option was absent.
    pub principals: Vec<String>,
    /// `command="..."`: run this instead of what the client asks for.
    pub command: Option<String>,
    /// `from="pattern-list"`: client addresses / names the key is valid from.
    pub from: Option<String>,
    /// `environment="NAME=value"` (only with `PermitUserEnvironment`).
    pub environment: Vec<String>,
    /// `permitopen="host:port"`: allowed `-L` destinations (repeatable).
    pub permit_open: Vec<String>,
    /// `permitlisten="[host:]port"`: allowed `-R` listeners (repeatable).
    pub permit_listen: Vec<String>,
    /// `expiry-time="timespec"`: the key is refused after this time.
    pub expiry_time: Option<String>,
    /// `restrict`: everything below off unless re-enabled.
    pub restrict: bool,
    /// `pty` / `no-pty`.
    pub pty: Option<bool>,
    /// `port-forwarding` / `no-port-forwarding`.
    pub port_forwarding: Option<bool>,
    /// `agent-forwarding` / `no-agent-forwarding`.
    pub agent_forwarding: Option<bool>,
    /// `X11-forwarding` / `no-X11-forwarding`.
    pub x11_forwarding: Option<bool>,
    /// `user-rc` / `no-user-rc`.
    pub user_rc: Option<bool>,
    /// `tunnel="n"`.
    pub tunnel: Option<String>,
    /// `no-touch-required` (security keys).
    pub no_touch_required: bool,
    /// `verify-required` (security keys).
    pub verify_required: bool,
}

impl AuthorizedKeyOptions {
    /// Whether a pty may be allocated (`pty` / `no-pty` / `restrict`).
    pub fn allows_pty(&self) -> bool {
        self.pty.unwrap_or(!self.restrict)
    }

    /// Whether `~/.ssh/rc` may run (`no-user-rc`, or `restrict` without
    /// `user-rc`, forbid it).
    pub fn allows_user_rc(&self) -> bool {
        self.user_rc.unwrap_or(!self.restrict)
    }

    /// Whether port forwarding is allowed.
    pub fn allows_port_forwarding(&self) -> bool {
        self.port_forwarding.unwrap_or(!self.restrict)
    }

    /// Whether agent forwarding is allowed.
    pub fn allows_agent_forwarding(&self) -> bool {
        self.agent_forwarding.unwrap_or(!self.restrict)
    }

    /// Whether X11 forwarding is allowed.
    pub fn allows_x11_forwarding(&self) -> bool {
        self.x11_forwarding.unwrap_or(!self.restrict)
    }

    /// Whether the line restricts anything at all.
    pub fn is_unrestricted(&self) -> bool {
        self.command.is_none()
            && self.permit_open.is_empty()
            && self.permit_listen.is_empty()
            && self.allows_pty()
            && self.allows_port_forwarding()
            && self.allows_agent_forwarding()
            && self.allows_x11_forwarding()
            && self.allows_user_rc()
            && self.environment.is_empty()
            && self.tunnel.is_none()
            && !self.no_touch_required
            && !self.verify_required
    }

    /// Parse a comma-separated option list (the leading field of an
    /// `authorized_keys` line). Values are double-quoted, with `\"` for a
    /// quote inside. Option names are case-insensitive.
    pub fn parse(list: &str) -> Result<Self> {
        let mut out = AuthorizedKeyOptions::default();
        for opt in split_options(list)? {
            let opt = opt.trim();
            if opt.is_empty() {
                continue;
            }
            let (name, value) = match opt.split_once('=') {
                Some((n, v)) => (n.to_ascii_lowercase(), Some(dequote(v.trim())?)),
                None => (opt.to_ascii_lowercase(), None),
            };
            let flag = |v: &Option<String>| {
                if v.is_some() {
                    Err(Error::Format("authorized_keys: option takes no value"))
                } else {
                    Ok(())
                }
            };
            let need =
                |v: Option<String>| v.ok_or(Error::Format("authorized_keys: option needs a value"));
            match name.as_str() {
                "cert-authority" => {
                    flag(&value)?;
                    out.cert_authority = true;
                }
                "principals" => {
                    out.principals = need(value)?
                        .split(',')
                        .map(|s| s.trim().to_string())
                        .filter(|s| !s.is_empty())
                        .collect();
                }
                "command" => out.command = Some(need(value)?),
                "from" => out.from = Some(need(value)?),
                "environment" => {
                    let v = need(value)?;
                    if !v.contains('=') {
                        return Err(Error::Format("authorized_keys: bad environment"));
                    }
                    out.environment.push(v);
                }
                "permitopen" => out.permit_open.push(need(value)?),
                "permitlisten" => out.permit_listen.push(need(value)?),
                "expiry-time" => out.expiry_time = Some(need(value)?),
                "tunnel" => {
                    // A device number or `any`, as OpenSSH's a2tun.
                    let v = need(value)?;
                    if !v.eq_ignore_ascii_case("any")
                        && v.parse::<u32>().ok().filter(|u| *u < 0x7fff_ffff).is_none()
                    {
                        return Err(Error::Format("authorized_keys: invalid tun device"));
                    }
                    out.tunnel = Some(v);
                }
                "restrict" => {
                    flag(&value)?;
                    out.restrict = true;
                }
                other => {
                    flag(&value)?;
                    let (on, what) = match other.strip_prefix("no-") {
                        Some(w) => (false, w),
                        None => (true, other),
                    };
                    match what {
                        "pty" => out.pty = Some(on),
                        "port-forwarding" => out.port_forwarding = Some(on),
                        "agent-forwarding" => out.agent_forwarding = Some(on),
                        "x11-forwarding" => out.x11_forwarding = Some(on),
                        "user-rc" => out.user_rc = Some(on),
                        "touch-required" if !on => out.no_touch_required = true,
                        "verify-required" if on => out.verify_required = true,
                        _ => {
                            return Err(Error::Format(
                                "authorized_keys: unknown option — refusing rather than silently dropping",
                            ));
                        }
                    }
                }
            }
        }
        Ok(out)
    }
}

/// Remove the surrounding double quotes of an option value, unescaping
/// `\"`.
fn dequote(v: &str) -> Result<String> {
    let inner = v
        .strip_prefix('"')
        .and_then(|v| v.strip_suffix('"'))
        .ok_or(Error::Format(
            "authorized_keys: option value must be quoted",
        ))?;
    let mut out = String::with_capacity(inner.len());
    let mut chars = inner.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\\' && chars.peek() == Some(&'"') {
            out.push('"');
            chars.next();
        } else {
            out.push(c);
        }
    }
    Ok(out)
}

/// Split an `authorized_keys` option list on commas that are not inside a
/// double-quoted value (`\"` does not end a value). Rejects an unterminated
/// quote.
fn split_options(list: &str) -> Result<Vec<String>> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut in_quotes = false;
    let mut escaped = false;
    for ch in list.chars() {
        match ch {
            '\\' if in_quotes && !escaped => {
                escaped = true;
                cur.push(ch);
                continue;
            }
            '"' if !escaped => {
                in_quotes = !in_quotes;
                cur.push(ch);
            }
            ',' if !in_quotes => {
                out.push(core::mem::take(&mut cur));
            }
            _ => cur.push(ch),
        }
        escaped = false;
    }
    if in_quotes {
        return Err(Error::Format(
            "authorized_keys: unterminated quote in options",
        ));
    }
    out.push(cur);
    Ok(out)
}

/// Length of the options field at the start of an `authorized_keys` line:
/// up to the first whitespace outside double quotes.
fn options_field_len(line: &str) -> usize {
    let mut in_quotes = false;
    let mut escaped = false;
    for (i, ch) in line.char_indices() {
        match ch {
            '\\' if in_quotes && !escaped => {
                escaped = true;
                continue;
            }
            '"' if !escaped => in_quotes = !in_quotes,
            c if c.is_whitespace() && !in_quotes => return i,
            _ => {}
        }
        escaped = false;
    }
    line.len()
}

/// SSH public key, tagged by algorithm.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
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
    /// `ssh-mldsa44-ed25519@openssh.com` — ML-DSA-44 + Ed25519 composite.
    MlDsa44Ed25519 {
        /// ML-DSA-44 public key (1312 bytes) || Ed25519 public key (32).
        raw: Vec<u8>,
        /// Trailing comment.
        comment: String,
    },
    /// `sk-ecdsa-sha2-nistp256@openssh.com` — a FIDO security key.
    SkEcdsaP256 {
        /// Uncompressed EC point.
        point: Vec<u8>,
        /// FIDO application (relying party), normally `ssh:`.
        application: String,
        /// Trailing comment.
        comment: String,
    },
    /// `sk-ssh-ed25519@openssh.com` — a FIDO security key.
    SkEd25519 {
        /// Raw 32-byte public key.
        raw: [u8; 32],
        /// FIDO application (relying party), normally `ssh:`.
        application: String,
        /// Trailing comment.
        comment: String,
    },
}

/// SSH private key, tagged by algorithm.
///
/// `Debug` is implemented manually and renders only the algorithm, the
/// comment and the public half; the seed / scalar / RSA private components
/// are replaced by `"<redacted>"` so a stray `{:?}` (a `tracing` field, an
/// `unwrap` panic message, `dbg!`) cannot leak key material into logs.
#[derive(Clone)]
#[non_exhaustive]
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
    /// `ssh-mldsa44-ed25519@openssh.com`.
    MlDsa44Ed25519 {
        /// ML-DSA-44 seed (32 bytes) || Ed25519 seed (32 bytes).
        seeds: [u8; 64],
        /// The composite public key.
        public: Vec<u8>,
        /// Trailing comment.
        comment: String,
    },
    /// `sk-ecdsa-sha2-nistp256@openssh.com`: a handle to a key held by a
    /// FIDO authenticator, which alone can sign with it.
    SkEcdsaP256 {
        /// Uncompressed EC point.
        point: Vec<u8>,
        /// The authenticator's credential for the key.
        sk: SkCredential,
        /// Trailing comment.
        comment: String,
    },
    /// `sk-ssh-ed25519@openssh.com`: a FIDO-held Ed25519 key.
    SkEd25519 {
        /// Raw 32-byte public key.
        public: [u8; 32],
        /// The authenticator's credential for the key.
        sk: SkCredential,
        /// Trailing comment.
        comment: String,
    },
}

/// What a security-key private key file holds instead of a secret: the
/// FIDO application, the enrolment flags and the authenticator's opaque
/// key handle (OpenSSH `PROTOCOL.u2f`).
#[derive(Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct SkCredential {
    /// FIDO application (relying party), normally `ssh:`.
    pub application: String,
    /// Enrolment flags: `0x01` user presence required (cleared by
    /// `no-touch-required`), `0x04` user verification required, `0x20`
    /// resident (discoverable) credential.
    pub flags: u8,
    /// The authenticator's key handle (credential ID).
    pub key_handle: Vec<u8>,
    /// Reserved; empty in keys OpenSSH writes.
    pub reserved: Vec<u8>,
}

impl SkCredential {
    /// A credential for `application` with `flags` and `key_handle`.
    pub fn new(application: String, flags: u8, key_handle: Vec<u8>) -> Self {
        Self {
            application,
            flags,
            key_handle,
            reserved: Vec::new(),
        }
    }

    fn read(r: &mut Reader<'_>) -> Result<Self> {
        let application = core::str::from_utf8(r.read_string()?)
            .map_err(|_| Error::Format("sk: application is not utf-8"))?
            .to_string();
        let flags = r.read_u8()?;
        let key_handle = r.read_string()?.to_vec();
        let reserved = r.read_string()?.to_vec();
        Ok(Self {
            application,
            flags,
            key_handle,
            reserved,
        })
    }

    pub(crate) fn write(&self, w: &mut Writer) {
        w.write_string(self.application.as_bytes());
        w.write_u8(self.flags);
        w.write_string(&self.key_handle);
        w.write_string(&self.reserved);
    }
}

impl core::fmt::Debug for SkCredential {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SkCredential")
            .field("application", &self.application)
            .field("flags", &self.flags)
            .finish_non_exhaustive()
    }
}

impl core::fmt::Debug for PrivateKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PrivateKey")
            .field("algorithm", &self.algorithm())
            .field("comment", &self.comment())
            .field("public", &self.public_key())
            .field("secret", &"<redacted>")
            .finish()
    }
}

const ED25519: &str = "ssh-ed25519";
const ECDSA_P256: &str = "ecdsa-sha2-nistp256";
const ECDSA_P384: &str = "ecdsa-sha2-nistp384";
const ECDSA_P521: &str = "ecdsa-sha2-nistp521";
const RSA: &str = "ssh-rsa";
const MLDSA44_ED25519: &str = "ssh-mldsa44-ed25519@openssh.com";
const SK_ECDSA: &str = crate::hostkey::sk::SK_ECDSA;
const SK_ED25519: &str = crate::hostkey::sk::SK_ED25519;

const NISTP256: &str = "nistp256";
const NISTP384: &str = "nistp384";
const NISTP521: &str = "nistp521";

const MAGIC: &[u8] = b"openssh-key-v1\0";

/// Whitelist of SSH public-key algorithm names we accept as the first
/// token on an `authorized_keys` / `.pub` line. Anything else — most
/// notably an options prefix like `from="..."` — is refused by
/// [`PublicKey::parse_authorized_keys_line`].
fn is_known_algorithm_name(s: &str) -> bool {
    matches!(
        s,
        ED25519
            | ECDSA_P256
            | ECDSA_P384
            | ECDSA_P521
            | RSA
            | "rsa-sha2-256"
            | "rsa-sha2-512"
            | MLDSA44_ED25519
            | SK_ECDSA
            | SK_ED25519
    )
}

impl PublicKey {
    /// SSH algorithm name (e.g. `"ssh-ed25519"`).
    pub fn algorithm(&self) -> &'static str {
        match self {
            PublicKey::Ed25519 { .. } => ED25519,
            PublicKey::EcdsaP256 { .. } => ECDSA_P256,
            PublicKey::EcdsaP384 { .. } => ECDSA_P384,
            PublicKey::EcdsaP521 { .. } => ECDSA_P521,
            PublicKey::Rsa { .. } => RSA,
            PublicKey::MlDsa44Ed25519 { .. } => MLDSA44_ED25519,
            PublicKey::SkEcdsaP256 { .. } => SK_ECDSA,
            PublicKey::SkEd25519 { .. } => SK_ED25519,
        }
    }

    /// Comment string (the trailing word on an `authorized_keys` line).
    pub fn comment(&self) -> &str {
        match self {
            PublicKey::Ed25519 { comment, .. }
            | PublicKey::EcdsaP256 { comment, .. }
            | PublicKey::EcdsaP384 { comment, .. }
            | PublicKey::EcdsaP521 { comment, .. }
            | PublicKey::Rsa { comment, .. }
            | PublicKey::MlDsa44Ed25519 { comment, .. }
            | PublicKey::SkEcdsaP256 { comment, .. }
            | PublicKey::SkEd25519 { comment, .. } => comment,
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
            PublicKey::MlDsa44Ed25519 { raw, .. } => {
                w.write_string(MLDSA44_ED25519.as_bytes());
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
            PublicKey::SkEcdsaP256 {
                point, application, ..
            } => {
                w.write_string(SK_ECDSA.as_bytes());
                w.write_string(NISTP256.as_bytes());
                w.write_string(point);
                w.write_string(application.as_bytes());
            }
            PublicKey::SkEd25519 {
                raw, application, ..
            } => {
                w.write_string(SK_ED25519.as_bytes());
                w.write_string(raw);
                w.write_string(application.as_bytes());
            }
        }
        w.into_vec()
    }

    /// Parse a single-line `authorized_keys` / `.pub` entry.
    ///
    /// Format: `<algorithm> <base64(wire_blob)> [comment...]`. Whitespace
    /// between fields can be any run of spaces or tabs (matches sshd's
    /// behaviour). Leading `from=...`/`command=...`/etc. option prefixes
    /// are explicitly refused — silently treating an options-prefixed
    /// line as a bare key would drop those restrictions and grant the
    /// key broader access than the file author intended.
    pub fn parse_authorized_keys_line(s: &str) -> Result<Self> {
        let line = s.trim_end_matches(['\n', '\r']).trim();
        if line.is_empty() || line.starts_with('#') {
            return Err(Error::Format("authorized_keys: empty or comment line"));
        }

        // First whitespace-separated token. If it isn't one of the known
        // SSH algorithm names — i.e. it contains '=', or has a comma, or
        // is any other shape sshd uses for the optional restriction list
        // — refuse loudly. We don't try to parse the options here;
        // dropping them silently would be the security regression.
        let mut it = line.split_whitespace();
        let first = it
            .next()
            .ok_or(Error::Format("authorized_keys: empty line"))?;
        if !is_known_algorithm_name(first) {
            return Err(Error::Format(
                "authorized_keys: line begins with options or unknown tag — refusing rather than silently dropping",
            ));
        }
        let algo = first;
        let b64 = it
            .next()
            .ok_or(Error::Format("authorized_keys: missing key blob"))?;
        // The rest of the line (already split) is the comment, rejoined
        // with single spaces — comments are free-form so the exact
        // whitespace doesn't survive a roundtrip, which matches OpenSSH.
        let comment_parts: Vec<&str> = it.collect();
        let comment = comment_parts.join(" ");

        let blob = base64::decode(b64.as_bytes())?;
        let mut pk = Self::parse_wire_blob(&blob)?;
        match &mut pk {
            PublicKey::Ed25519 { comment: c, .. }
            | PublicKey::EcdsaP256 { comment: c, .. }
            | PublicKey::EcdsaP384 { comment: c, .. }
            | PublicKey::EcdsaP521 { comment: c, .. }
            | PublicKey::Rsa { comment: c, .. }
            | PublicKey::MlDsa44Ed25519 { comment: c, .. }
            | PublicKey::SkEcdsaP256 { comment: c, .. }
            | PublicKey::SkEd25519 { comment: c, .. } => *c = comment,
        }
        if pk.algorithm() != algo {
            return Err(Error::Format("authorized_keys: algorithm tag mismatch"));
        }
        Ok(pk)
    }

    /// Parse a single `authorized_keys` line that may carry a leading option
    /// list, returning the decoded key blob alongside the recognised options.
    ///
    /// Unlike [`Self::parse_authorized_keys_line`] (which refuses any options
    /// prefix outright), this understands the certificate-relevant options
    /// `cert-authority` (a flag marking the key as a CA) and `principals="..."`
    /// (a comma-separated allow-list). It KEEPS the strict stance for anything
    /// else: an unrecognised option is an error, never silently dropped.
    ///
    /// Returns `(blob, options)` where `blob` is the raw key/cert wire blob (the
    /// base64-decoded second field) and `options` records the parsed flags.
    pub fn parse_authorized_keys_line_with_options(
        s: &str,
    ) -> Result<(Vec<u8>, AuthorizedKeyOptions)> {
        let line = s.trim_end_matches(['\n', '\r']).trim();
        if line.is_empty() || line.starts_with('#') {
            return Err(Error::Format("authorized_keys: empty or comment line"));
        }

        // The line is `[options] <algo> <base64> [comment]`. The first field
        // is an algorithm name iff it is a known key/cert type; otherwise it
        // is the option list, which ends at the first whitespace outside
        // double quotes (`command="a b"` keeps its spaces).
        let first_ws = line.find(char::is_whitespace);
        let first_tok = match first_ws {
            Some(i) => &line[..i],
            None => return Err(Error::Format("authorized_keys: missing key blob")),
        };

        let mut options = AuthorizedKeyOptions::default();
        let (algo_tok, after_algo) =
            if is_known_algorithm_name(first_tok) || crate::cert::is_cert_name(first_tok) {
                // No options prefix.
                (first_tok, line[first_tok.len()..].trim_start())
            } else {
                let opt_len = options_field_len(line);
                options = AuthorizedKeyOptions::parse(&line[..opt_len])?;
                let rest = line[opt_len..].trim_start();
                let i = rest.find(char::is_whitespace).ok_or(Error::Format(
                    "authorized_keys: missing key blob after options",
                ))?;
                (&rest[..i], rest[i..].trim_start())
            };

        if !(is_known_algorithm_name(algo_tok) || crate::cert::is_cert_name(algo_tok)) {
            return Err(Error::Format(
                "authorized_keys: unknown key/cert algorithm tag",
            ));
        }
        let b64 = after_algo
            .split_whitespace()
            .next()
            .ok_or(Error::Format("authorized_keys: missing key blob"))?;
        let blob = base64::decode(b64.as_bytes())?;
        Ok((blob, options))
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
            b if b == MLDSA44_ED25519.as_bytes() => {
                let raw = r.read_string()?;
                crate::hostkey::MlDsa44Ed25519HostKey::from_public(raw)?;
                PublicKey::MlDsa44Ed25519 {
                    raw: raw.to_vec(),
                    comment: String::new(),
                }
            }
            b if b == ECDSA_P256.as_bytes() => {
                parse_ecdsa_public(&mut r, NISTP256, CurveId::P256, |p, c| {
                    PublicKey::EcdsaP256 {
                        point: p,
                        comment: c,
                    }
                })?
            }
            b if b == ECDSA_P384.as_bytes() => {
                parse_ecdsa_public(&mut r, NISTP384, CurveId::P384, |p, c| {
                    PublicKey::EcdsaP384 {
                        point: p,
                        comment: c,
                    }
                })?
            }
            b if b == ECDSA_P521.as_bytes() => {
                parse_ecdsa_public(&mut r, NISTP521, CurveId::P521, |p, c| {
                    PublicKey::EcdsaP521 {
                        point: p,
                        comment: c,
                    }
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
            b if b == SK_ECDSA.as_bytes() => {
                let PublicKey::EcdsaP256 { point, .. } =
                    parse_ecdsa_public(&mut r, NISTP256, CurveId::P256, |p, c| {
                        PublicKey::EcdsaP256 {
                            point: p,
                            comment: c,
                        }
                    })?
                else {
                    unreachable!()
                };
                PublicKey::SkEcdsaP256 {
                    point,
                    application: read_application(&mut r)?,
                    comment: String::new(),
                }
            }
            b if b == SK_ED25519.as_bytes() => {
                let raw: [u8; 32] = r
                    .read_string()?
                    .try_into()
                    .map_err(|_| Error::Format("ed25519: public key length"))?;
                PublicKey::SkEd25519 {
                    raw,
                    application: read_application(&mut r)?,
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

/// The FIDO application string of a security-key public blob.
fn read_application(r: &mut Reader<'_>) -> Result<String> {
    core::str::from_utf8(r.read_string()?)
        .map(String::from)
        .map_err(|_| Error::Format("sk: application is not utf-8"))
}

fn parse_ecdsa_public<F>(
    r: &mut Reader<'_>,
    curve_name: &str,
    curve_id: CurveId,
    ctor: F,
) -> Result<PublicKey>
where
    F: FnOnce(Vec<u8>, String) -> PublicKey,
{
    let c = r.read_string()?;
    if c != curve_name.as_bytes() {
        return Err(Error::Format("ecdsa: curve name mismatch"));
    }
    let point = r.read_string()?.to_vec();
    // Validate the SEC1 point eagerly at parse time. Without this the
    // PublicKey would hold an opaque byte string that only fails later
    // when used (e.g. by an authorized_keys check), and a malformed or
    // off-curve point could otherwise sneak through to the verifier
    // construction site. BoxedEcdsaPublicKey::from_sec1 enforces the
    // SEC1 uncompressed prefix, length, and on-curve membership.
    BoxedEcdsaPublicKey::from_sec1(curve_id, &point)
        .map_err(|_| Error::Format("ecdsa: invalid SEC1 point"))?;
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
            PrivateKey::MlDsa44Ed25519 { .. } => MLDSA44_ED25519,
            PrivateKey::SkEcdsaP256 { .. } => SK_ECDSA,
            PrivateKey::SkEd25519 { .. } => SK_ED25519,
        }
    }

    /// The private key for a security key's public half and credential
    /// (what `ssh-keygen` writes after enrolment).
    pub fn from_security_key(public: PublicKey, sk: SkCredential) -> Result<Self> {
        match public {
            PublicKey::SkEcdsaP256 { point, comment, .. } => {
                Ok(PrivateKey::SkEcdsaP256 { point, sk, comment })
            }
            PublicKey::SkEd25519 { raw, comment, .. } => Ok(PrivateKey::SkEd25519 {
                public: raw,
                sk,
                comment,
            }),
            _ => Err(Error::Config("not a security key")),
        }
    }

    /// The security-key credential, for a key held by an authenticator.
    pub fn sk_credential(&self) -> Option<&SkCredential> {
        match self {
            PrivateKey::SkEcdsaP256 { sk, .. } | PrivateKey::SkEd25519 { sk, .. } => Some(sk),
            _ => None,
        }
    }

    /// Replace the comment.
    pub fn set_comment(&mut self, comment: impl Into<String>) {
        match self {
            PrivateKey::Ed25519 { comment: c, .. }
            | PrivateKey::EcdsaP256 { comment: c, .. }
            | PrivateKey::EcdsaP384 { comment: c, .. }
            | PrivateKey::EcdsaP521 { comment: c, .. }
            | PrivateKey::Rsa { comment: c, .. }
            | PrivateKey::MlDsa44Ed25519 { comment: c, .. }
            | PrivateKey::SkEcdsaP256 { comment: c, .. }
            | PrivateKey::SkEd25519 { comment: c, .. } => *c = comment.into(),
        }
    }

    /// Comment.
    pub fn comment(&self) -> &str {
        match self {
            PrivateKey::Ed25519 { comment, .. }
            | PrivateKey::EcdsaP256 { comment, .. }
            | PrivateKey::EcdsaP384 { comment, .. }
            | PrivateKey::EcdsaP521 { comment, .. }
            | PrivateKey::Rsa { comment, .. }
            | PrivateKey::MlDsa44Ed25519 { comment, .. }
            | PrivateKey::SkEcdsaP256 { comment, .. }
            | PrivateKey::SkEd25519 { comment, .. } => comment,
        }
    }

    /// Convert this private key into a boxed `HostKey` signer.
    ///
    /// For RSA keys, defaults to `rsa-sha2-512` (modern OpenSSH preference).
    pub fn into_host_key(self) -> Result<alloc::boxed::Box<dyn crate::hostkey::HostKey + Send>> {
        Ok(self.into_host_key_sync()?)
    }

    /// Like [`Self::into_host_key`], but returns a `Send + Sync` signer. The
    /// concrete signer types ([`crate::hostkey::Ed25519HostKey`], the ECDSA and
    /// RSA host keys) hold only `Sync`-safe state, so this is always available;
    /// it exists for callers (the server's `Config.host_keys`, a `CertHostKey`
    /// inner) that require `Sync`.
    pub fn into_host_key_sync(
        mut self,
    ) -> Result<alloc::boxed::Box<dyn crate::hostkey::HostKey + Send + Sync>> {
        let signer = self.host_key();
        // The signer holds its own copy; wipe this one rather than leave it
        // in freed memory.
        self.wipe();
        signer
    }

    /// The signer for this key (`rsa-sha2-512` for RSA), built from a
    /// borrow so the key need not be cloned.
    fn host_key(&self) -> Result<alloc::boxed::Box<dyn crate::hostkey::HostKey + Send + Sync>> {
        match self {
            PrivateKey::Ed25519 { seed, .. } => Ok(alloc::boxed::Box::new(
                crate::hostkey::Ed25519HostKey::from_seed(*seed),
            )),
            PrivateKey::EcdsaP256 { d, .. } => Ok(alloc::boxed::Box::new(
                crate::hostkey::EcdsaP256HostKey::from_scalar(d)?,
            )),
            PrivateKey::EcdsaP384 { d, .. } => Ok(alloc::boxed::Box::new(
                crate::hostkey::EcdsaP384HostKey::from_scalar(d)?,
            )),
            PrivateKey::EcdsaP521 { d, .. } => Ok(alloc::boxed::Box::new(
                crate::hostkey::EcdsaP521HostKey::from_scalar(d)?,
            )),
            PrivateKey::Rsa { n, e, d, p, q, .. } => {
                Ok(alloc::boxed::Box::new(rsa_host_key(n, e, d, p, q)?))
            }
            PrivateKey::MlDsa44Ed25519 { seeds, .. } => Ok(alloc::boxed::Box::new(
                crate::hostkey::MlDsa44Ed25519HostKey::from_seeds(*seeds),
            )),
            // Only the authenticator holds the secret: signing goes through
            // a security-key provider.
            PrivateKey::SkEcdsaP256 { .. } | PrivateKey::SkEd25519 { .. } => Err(
                Error::Unsupported("security key: signing needs the authenticator"),
            ),
        }
    }

    /// Overwrite the secret half (seed, scalar, RSA private components)
    /// with zeros, for a key about to be dropped. The key is unusable after.
    /// `PrivateKey` has no zeroizing `Drop` (it would forbid moving its
    /// fields out, which its public variants allow), so holders that
    /// outlive a short scope call this.
    pub(crate) fn wipe(&mut self) {
        match self {
            PrivateKey::Ed25519 { seed, .. } => seed.zeroize(),
            PrivateKey::EcdsaP256 { d, .. }
            | PrivateKey::EcdsaP384 { d, .. }
            | PrivateKey::EcdsaP521 { d, .. } => d.zeroize(),
            PrivateKey::Rsa { d, p, q, iqmp, .. } => {
                d.zeroize();
                p.zeroize();
                q.zeroize();
                iqmp.zeroize();
            }
            PrivateKey::MlDsa44Ed25519 { seeds, .. } => seeds.zeroize(),
            // Not a secret by itself, but OpenSSH treats it as one.
            PrivateKey::SkEcdsaP256 { sk, .. } | PrivateKey::SkEd25519 { sk, .. } => {
                sk.key_handle.zeroize()
            }
        }
    }

    /// Check that the private material actually corresponds to the stored
    /// public half, by *deriving* the public key from the secret:
    ///
    /// - Ed25519: `public == [seed]B`.
    /// - ECDSA: `point == [d]G` (also range-checks `d`).
    /// - RSA: `p * q == n` and `e * d ≡ 1 (mod p-1)` / `(mod q-1)` when the
    ///   prime factors are present.
    ///
    /// The file parsers call this so a key whose public field was
    /// tampered with (or whose secret half is corrupt) is rejected up front
    /// instead of producing signatures that never verify — or, for RSA,
    /// exposing the CRT signing path to inconsistent parameters.
    pub fn check_consistency(&self) -> Result<()> {
        match self {
            PrivateKey::Ed25519 { seed, public, .. } => {
                let derived = Ed25519PrivateKey::from_bytes(*seed).public_key().to_bytes();
                if &derived != public {
                    return Err(Error::Format(
                        "ed25519: public key does not match private seed",
                    ));
                }
            }
            PrivateKey::EcdsaP256 { d, point, .. } => check_ecdsa(CurveId::P256, d, point)?,
            PrivateKey::EcdsaP384 { d, point, .. } => check_ecdsa(CurveId::P384, d, point)?,
            PrivateKey::EcdsaP521 { d, point, .. } => check_ecdsa(CurveId::P521, d, point)?,
            PrivateKey::Rsa { n, e, d, p, q, .. } => check_rsa_private(n, e, d, p, q)?,
            PrivateKey::MlDsa44Ed25519 { seeds, public, .. } => {
                if crate::hostkey::mldsa44_ed25519_public(seeds) != *public {
                    return Err(Error::Format(
                        "mldsa44-ed25519: public key does not match private seeds",
                    ));
                }
            }
            // Nothing to derive from: the secret is on the authenticator.
            PrivateKey::SkEcdsaP256 { point, .. } => {
                BoxedEcdsaPublicKey::from_sec1(CurveId::P256, point)
                    .map_err(|_| Error::Format("ecdsa: invalid SEC1 point"))?;
            }
            PrivateKey::SkEd25519 { .. } => {}
        }
        Ok(())
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
            PrivateKey::MlDsa44Ed25519 {
                public, comment, ..
            } => PublicKey::MlDsa44Ed25519 {
                raw: public.clone(),
                comment: comment.clone(),
            },
            PrivateKey::SkEcdsaP256 { point, sk, comment } => PublicKey::SkEcdsaP256 {
                point: point.clone(),
                application: sk.application.clone(),
                comment: comment.clone(),
            },
            PrivateKey::SkEd25519 {
                public,
                sk,
                comment,
            } => PublicKey::SkEd25519 {
                raw: *public,
                application: sk.application.clone(),
                comment: comment.clone(),
            },
        }
    }

    /// The public key of a private key file without decrypting it: the
    /// OpenSSH container keeps it in the clear (other formats are parsed,
    /// so an encrypted PEM / PKCS#8 key needs its `.pub` file instead).
    pub fn public_key_from_pem(pem: &str) -> Result<PublicKey> {
        if !pem.contains("-----BEGIN OPENSSH PRIVATE KEY-----") {
            return Self::parse_pem(pem, None).map(|k| k.public_key());
        }
        let body = strip_pem(pem)?;
        let raw = base64::decode(body.as_bytes())?;
        if raw.len() < MAGIC.len() || &raw[..MAGIC.len()] != MAGIC {
            return Err(Error::Format("openssh key: bad magic"));
        }
        let mut r = Reader::new(&raw[MAGIC.len()..]);
        let _ciphername = r.read_string()?;
        let _kdfname = r.read_string()?;
        let _kdfoptions = r.read_string()?;
        if r.read_u32()? != 1 {
            return Err(Error::Unsupported("openssh key: multiple keys"));
        }
        PublicKey::parse_wire_blob(r.read_string()?)
    }

    /// Parse an OpenSSH "new" PEM-encoded private key.
    ///
    /// Pass `passphrase = None` for unencrypted keys. If the PEM is
    /// encrypted, `passphrase` must be supplied; if the passphrase is wrong
    /// the embedded `checkint1 == checkint2` check fails and we return
    /// [`Error::Crypto`]`("wrong passphrase")`.
    pub fn parse_openssh_pem(pem: &str, passphrase: Option<&[u8]>) -> Result<Self> {
        let body = strip_pem(pem)?;
        // `raw` holds the (possibly still encrypted) private-key container;
        // for an unencrypted key that *is* the cleartext secret. Wipe it on
        // every exit path.
        let raw: Zeroizing<Vec<u8>> = Zeroizing::new(base64::decode(body.as_bytes())?);
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

        // Sanity-check: the outer (cleartext) public-key blob must match the
        // inner private section's public fields ...
        let pk_with_comment = attach_comment(pk, comment);
        let embedded = PublicKey::parse_wire_blob(&public_blob)?;
        if !public_parts_match(&pk_with_comment.public_key(), &embedded) {
            return Err(Error::Format(
                "openssh key: embedded public key does not match private fields",
            ));
        }
        // ... and both must match what the *secret* actually derives to;
        // comparing two file-supplied copies against each other would let
        // a tampered file carry a public half unrelated to its private half.
        pk_with_comment.check_consistency()?;
        Ok(pk_with_comment)
    }
}

/// Derive the public point from an ECDSA scalar and compare it to `point`.
fn check_ecdsa(curve: CurveId, d: &[u8], point: &[u8]) -> Result<()> {
    let sk = BoxedEcdsaPrivateKey::from_bytes(curve, trim_leading_zeros(d))
        .map_err(|_| Error::Crypto("ecdsa: private scalar out of range"))?;
    if sk.public_key().to_sec1() != point {
        return Err(Error::Format(
            "ecdsa: public point does not match private scalar",
        ));
    }
    Ok(())
}

/// True if the RSA prime factors are present (an RSA key built by hand, or
/// read from a container that omits them, has empty `p`/`q`).
fn rsa_has_primes(p: &[u8], q: &[u8]) -> bool {
    !trim_leading_zeros(p).is_empty() && !trim_leading_zeros(q).is_empty()
}

/// Validate RSA private components: when the primes are present, require
/// `p * q == n` and `e * d ≡ 1` modulo both `p - 1` and `q - 1` (i.e. `d`
/// really is the inverse of `e` mod `λ(n)`).
fn check_rsa_private(n: &[u8], e: &[u8], d: &[u8], p: &[u8], q: &[u8]) -> Result<()> {
    if !rsa_has_primes(p, q) {
        return Ok(());
    }
    let n_u = BoxedUint::from_be_bytes(trim_leading_zeros(n));
    let p_u = BoxedUint::from_be_bytes(trim_leading_zeros(p));
    let q_u = BoxedUint::from_be_bytes(trim_leading_zeros(q));
    crate::hostkey::rsa::check_rsa_primes(&n_u, &p_u, &q_u)?;
    let e_u = BoxedUint::from_be_bytes(trim_leading_zeros(e));
    let d_u = BoxedUint::from_be_bytes(trim_leading_zeros(d));
    let one = BoxedUint::from_u64(1);
    let ed = e_u.mul(&d_u);
    if ed.reduce(&p_u.sub(&one)) != one || ed.reduce(&q_u.sub(&one)) != one {
        return Err(Error::Format(
            "rsa: private exponent does not match public exponent and primes",
        ));
    }
    Ok(())
}

impl PrivateKey {
    /// A signer for an agent `SSH_AGENTC_SIGN_REQUEST` with `flags`: for
    /// RSA, `SSH_AGENT_RSA_SHA2_512` (4) selects `rsa-sha2-512`,
    /// `SSH_AGENT_RSA_SHA2_256` (2) `rsa-sha2-256`, and no flag the legacy
    /// SHA-1 `ssh-rsa`; other key types ignore the flags.
    #[cfg(all(feature = "agent", unix))]
    pub(crate) fn agent_signer(
        &self,
        flags: u32,
    ) -> Result<Box<dyn crate::hostkey::HostKey + Send>> {
        let PrivateKey::Rsa { n, e, d, p, q, .. } = self else {
            return Ok(self.host_key()?);
        };
        let num = |b: &[u8]| BoxedUint::from_be_bytes(trim_leading_zeros(b));
        let primes = rsa_has_primes(p, q);
        macro_rules! build {
            ($ty:ty) => {
                if primes {
                    <$ty>::from_components_with_primes(num(n), num(e), num(d), num(p), num(q))
                } else {
                    <$ty>::from_components(num(n), num(e), num(d))
                }
                .map(|k| Box::new(k) as Box<dyn crate::hostkey::HostKey + Send>)
            };
        }
        if flags & 4 != 0 {
            build!(crate::hostkey::RsaSha2_512HostKey)
        } else if flags & 2 != 0 {
            build!(crate::hostkey::RsaSha2_256HostKey)
        } else {
            build!(crate::hostkey::RsaSha1HostKey)
        }
    }
}

/// Build the `rsa-sha2-512` signer for an RSA private key, keeping base
/// blinding enabled by passing the prime factors through whenever the key
/// carries them (openssh-key-v1, PKCS#1 and PKCS#8 all do). A key without
/// primes falls back to the unblinded `(n, e, d)` constructor.
fn rsa_host_key(
    n: &[u8],
    e: &[u8],
    d: &[u8],
    p: &[u8],
    q: &[u8],
) -> Result<crate::hostkey::RsaSha2_512HostKey> {
    let n_u = BoxedUint::from_be_bytes(trim_leading_zeros(n));
    let e_u = BoxedUint::from_be_bytes(trim_leading_zeros(e));
    let d_u = BoxedUint::from_be_bytes(trim_leading_zeros(d));
    if rsa_has_primes(p, q) {
        let p_u = BoxedUint::from_be_bytes(trim_leading_zeros(p));
        let q_u = BoxedUint::from_be_bytes(trim_leading_zeros(q));
        crate::hostkey::RsaSha2_512HostKey::from_components_with_primes(n_u, e_u, d_u, p_u, q_u)
    } else {
        crate::hostkey::RsaSha2_512HostKey::from_components(n_u, e_u, d_u)
    }
}

fn attach_comment(mut pk: PrivateKey, comment: String) -> PrivateKey {
    match &mut pk {
        PrivateKey::Ed25519 { comment: c, .. }
        | PrivateKey::EcdsaP256 { comment: c, .. }
        | PrivateKey::EcdsaP384 { comment: c, .. }
        | PrivateKey::EcdsaP521 { comment: c, .. }
        | PrivateKey::Rsa { comment: c, .. }
        | PrivateKey::MlDsa44Ed25519 { comment: c, .. }
        | PrivateKey::SkEcdsaP256 { comment: c, .. }
        | PrivateKey::SkEd25519 { comment: c, .. } => *c = comment,
    }
    pk
}

fn public_parts_match(a: &PublicKey, b: &PublicKey) -> bool {
    match (a, b) {
        (PublicKey::Ed25519 { raw: x, .. }, PublicKey::Ed25519 { raw: y, .. }) => x == y,
        (PublicKey::MlDsa44Ed25519 { raw: x, .. }, PublicKey::MlDsa44Ed25519 { raw: y, .. }) => {
            x == y
        }
        (PublicKey::EcdsaP256 { point: x, .. }, PublicKey::EcdsaP256 { point: y, .. })
        | (PublicKey::EcdsaP384 { point: x, .. }, PublicKey::EcdsaP384 { point: y, .. })
        | (PublicKey::EcdsaP521 { point: x, .. }, PublicKey::EcdsaP521 { point: y, .. }) => x == y,
        (PublicKey::Rsa { e: e1, n: n1, .. }, PublicKey::Rsa { e: e2, n: n2, .. }) => {
            trim_leading_zeros(e1) == trim_leading_zeros(e2)
                && trim_leading_zeros(n1) == trim_leading_zeros(n2)
        }
        (
            PublicKey::SkEcdsaP256 {
                point: x,
                application: a,
                ..
            },
            PublicKey::SkEcdsaP256 {
                point: y,
                application: b,
                ..
            },
        ) => x == y && a == b,
        (
            PublicKey::SkEd25519 {
                raw: x,
                application: a,
                ..
            },
            PublicKey::SkEd25519 {
                raw: y,
                application: b,
                ..
            },
        ) => x == y && a == b,
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

impl PrivateKey {
    /// Decode the key of an agent `SSH_AGENTC_ADD_IDENTITY` request (the
    /// layout [`Self::to_agent_add_body`] produces: key type, private
    /// fields, comment), consuming it from `r`. The key is checked for
    /// internal consistency before it is returned.
    #[cfg(all(feature = "agent", unix))]
    pub(crate) fn from_agent_add_body(r: &mut Reader<'_>) -> Result<Self> {
        let pk = parse_private_fields(r)?;
        let comment = String::from_utf8_lossy(r.read_string()?).into_owned();
        let pk = attach_comment(pk, comment);
        pk.check_consistency()?;
        Ok(pk)
    }

    /// Decode the key of an agent `SSH_AGENTC_ADD_IDENTITY` request adding
    /// a certificate (the layout [`Self::to_agent_add_cert_body`]
    /// produces), returning the key and the certificate blob. The private
    /// fields are checked against the certificate's embedded key.
    #[cfg(all(feature = "agent", unix))]
    pub(crate) fn from_agent_add_cert_body(r: &mut Reader<'_>) -> Result<(Self, Vec<u8>)> {
        let cert_type = r.read_string()?;
        let cert_blob = r.read_string()?.to_vec();
        let cert = crate::cert::Certificate::parse(&cert_blob)?;
        if cert.key_type.as_bytes() != cert_type {
            return Err(Error::Format("agent certificate: type mismatch"));
        }
        let embedded = cert.embedded_pubkey_blob().to_vec();
        let pk = match PublicKey::parse_wire_blob(&embedded)? {
            PublicKey::Ed25519 { raw, .. } => {
                let pub_raw = r.read_string()?;
                let sk = r.read_string()?;
                if pub_raw != raw || sk.len() != 64 || sk[32..] != raw {
                    return Err(Error::Format("ed25519: certificate key mismatch"));
                }
                let mut seed = [0u8; 32];
                seed.copy_from_slice(&sk[..32]);
                PrivateKey::Ed25519 {
                    seed,
                    public: raw,
                    comment: String::new(),
                }
            }
            PublicKey::MlDsa44Ed25519 { raw, .. } => {
                let sk = r.read_string()?;
                if sk.len() != 64 {
                    return Err(Error::Format("mldsa44-ed25519: secret length"));
                }
                let mut seeds = [0u8; 64];
                seeds.copy_from_slice(sk);
                PrivateKey::MlDsa44Ed25519 {
                    seeds,
                    public: raw,
                    comment: String::new(),
                }
            }
            PublicKey::EcdsaP256 { point, .. } => PrivateKey::EcdsaP256 {
                d: read_mpint(r)?.to_vec(),
                point,
                comment: String::new(),
            },
            PublicKey::EcdsaP384 { point, .. } => PrivateKey::EcdsaP384 {
                d: read_mpint(r)?.to_vec(),
                point,
                comment: String::new(),
            },
            PublicKey::EcdsaP521 { point, .. } => PrivateKey::EcdsaP521 {
                d: read_mpint(r)?.to_vec(),
                point,
                comment: String::new(),
            },
            PublicKey::Rsa { n, e, .. } => {
                let d = read_mpint(r)?.to_vec();
                let iqmp = read_mpint(r)?.to_vec();
                let p = read_mpint(r)?.to_vec();
                let q = read_mpint(r)?.to_vec();
                PrivateKey::Rsa {
                    n,
                    e,
                    d,
                    p,
                    q,
                    iqmp,
                    comment: String::new(),
                }
            }
            // A security-key certificate: only the credential follows.
            PublicKey::SkEcdsaP256 { point, .. } => PrivateKey::SkEcdsaP256 {
                point,
                sk: SkCredential::read(r)?,
                comment: String::new(),
            },
            PublicKey::SkEd25519 { raw, .. } => {
                if r.read_string()? != raw {
                    return Err(Error::Format("ed25519: certificate key mismatch"));
                }
                PrivateKey::SkEd25519 {
                    public: raw,
                    sk: SkCredential::read(r)?,
                    comment: String::new(),
                }
            }
        };
        let comment = String::from_utf8_lossy(r.read_string()?).into_owned();
        let pk = attach_comment(pk, comment);
        pk.check_consistency()?;
        if pk.public_key().wire_blob() != embedded {
            return Err(Error::Format("agent certificate: key mismatch"));
        }
        Ok((pk, cert_blob))
    }
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
        b if b == MLDSA44_ED25519.as_bytes() => {
            let public = r.read_string()?;
            crate::hostkey::MlDsa44Ed25519HostKey::from_public(public)?;
            let sk = r.read_string()?;
            if sk.len() != 64 {
                return Err(Error::Format("mldsa44-ed25519: secret length"));
            }
            let mut seeds = [0u8; 64];
            seeds.copy_from_slice(sk);
            Ok(PrivateKey::MlDsa44Ed25519 {
                seeds,
                public: public.to_vec(),
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
        b if b == SK_ECDSA.as_bytes() => {
            if r.read_string()? != NISTP256.as_bytes() {
                return Err(Error::Format("ecdsa: curve mismatch"));
            }
            let point = r.read_string()?.to_vec();
            Ok(PrivateKey::SkEcdsaP256 {
                point,
                sk: SkCredential::read(r)?,
                comment: String::new(),
            })
        }
        b if b == SK_ED25519.as_bytes() => {
            let public: [u8; 32] = r
                .read_string()?
                .try_into()
                .map_err(|_| Error::Format("ed25519: public length"))?;
            Ok(PrivateKey::SkEd25519 {
                public,
                sk: SkCredential::read(r)?,
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
) -> Result<Zeroizing<Vec<u8>>> {
    if ciphername == b"none" {
        if kdfname != b"none" {
            return Err(Error::Format(
                "openssh key: cipher 'none' with non-none kdf",
            ));
        }
        return Ok(Zeroizing::new(encrypted.to_vec()));
    }

    // Treat an empty passphrase as "no passphrase". Callers occasionally
    // wire Some(b"") through (e.g. a CLI prompt where the user pressed
    // Enter on an encrypted key, or a config that left the field blank),
    // and accepting it would attempt to derive a key against the empty
    // string — which silently succeeds at the bcrypt step and produces a
    // garbage AES key, surfacing only at the post-decrypt magic check
    // with the same generic error as a real wrong passphrase. Fail loud
    // and early with the same error as None.
    let pass = match passphrase {
        Some(p) if !p.is_empty() => p,
        _ => return Err(Error::Crypto("passphrase required")),
    };

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

    // Cap rounds. bcrypt_pbkdf's cost is linear in the rounds count, and
    // a malicious key file could otherwise pin a victim's thread on the
    // KDF for an unbounded amount of time before they ever learn the
    // passphrase is wrong. OpenSSH's `-a` defaults to 16 and `-a 100` is
    // common hardening advice (about 0.5 s); 10000 rounds still loads
    // (about 50 s) while bounding the worst case.
    const MAX_BCRYPT_ROUNDS: u32 = 10_000;
    if rounds == 0 {
        return Err(Error::Format("openssh key: bcrypt rounds must be > 0"));
    }
    if rounds > MAX_BCRYPT_ROUNDS {
        return Err(Error::Format(
            "openssh key: bcrypt rounds exceeds 10000 (DoS guard)",
        ));
    }

    // `derived` is passphrase-equivalent (it yields the AES key + IV that
    // protect the private key); `k`/`iv` are copies of it and `out` is the
    // cleartext private section. All are wiped on drop.
    let derived: Zeroizing<Vec<u8>> = Zeroizing::new(
        bcrypt_pbkdf(pass, salt, rounds, key_len + iv_len)
            .map_err(|_| Error::Crypto("bcrypt_pbkdf: invalid parameters"))?,
    );

    if !encrypted.len().is_multiple_of(16) {
        return Err(Error::Format("openssh key: encrypted length not aligned"));
    }

    let mut iv: Zeroizing<[u8; 16]> = Zeroizing::new([0u8; 16]);
    iv.copy_from_slice(&derived[key_len..key_len + iv_len]);

    let mut out: Zeroizing<Vec<u8>> = Zeroizing::new(encrypted.to_vec());
    match ciphername {
        b"aes256-ctr" => {
            let mut k: Zeroizing<[u8; 32]> = Zeroizing::new([0u8; 32]);
            k.copy_from_slice(&derived[..32]);
            let mut ctr = Ctr::new(Aes256::new(&k), &iv);
            ctr.apply_keystream(&mut out);
        }
        b"aes128-ctr" => {
            let mut k: Zeroizing<[u8; 16]> = Zeroizing::new([0u8; 16]);
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
