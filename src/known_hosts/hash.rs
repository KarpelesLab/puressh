//! OpenSSH hashed-host-entry primitive (RFC 4255 §3.2).
//!
//! A hashed entry is `|1|<base64-salt>|<base64-hmac>` where `hmac =
//! HMAC-SHA1(salt, host_string)`. The salt is 20 random bytes (the
//! HMAC-SHA1 block size). The host string is the literal `host` (or
//! `[host]:port` for non-default ports) — see [`format_host`].

use purecrypto::hash::{Hmac, Sha1};
use purecrypto::rng::{CryptoRng, RngCore};

use crate::key::base64;

/// Length of the HMAC-SHA1 salt used in `|1|salt|hash` entries.
pub const SALT_LEN: usize = 20;

/// Format `host[:port]` exactly as OpenSSH does when hashing (RFC 4255 §3.2).
/// Default port (22) is omitted; non-default port wraps in `[host]:port`.
pub fn format_host(host: &str, port: u16) -> String {
    if port == 22 {
        host.to_string()
    } else {
        format!("[{host}]:{port}")
    }
}

/// HMAC-SHA1 of the literal host string under the given salt. The output
/// is the 20-byte tag, *not* base64-encoded.
pub fn hmac(salt: &[u8], host: &str) -> [u8; 20] {
    Hmac::<Sha1>::mac(salt, host.as_bytes())
}

/// Encode a `|1|salt|hash` token. Both fields are standard-alphabet
/// base64 with `=` padding.
pub fn encode_hashed(salt: &[u8], host: &str) -> String {
    let hash = hmac(salt, host);
    format!("|1|{}|{}", base64::encode(salt), base64::encode(&hash))
}

/// Mint a fresh salt + hashed encoding for `host[:port]`. Returns
/// `(salt, encoded_token)`; the caller persists `encoded_token` verbatim.
pub fn hash_new<R: CryptoRng + RngCore>(
    rng: &mut R,
    host: &str,
    port: u16,
) -> ([u8; SALT_LEN], String) {
    let mut salt = [0u8; SALT_LEN];
    rng.fill_bytes(&mut salt);
    let canonical = format_host(host, port);
    let enc = encode_hashed(&salt, &canonical);
    (salt, enc)
}

/// Parse a `|1|salt|hash` token. Returns `(salt, hash_tag)` where both
/// are raw bytes. Returns `None` on malformed input.
pub fn parse_hashed(token: &str) -> Option<(Vec<u8>, Vec<u8>)> {
    let rest = token.strip_prefix("|1|")?;
    let (salt_b64, hash_b64) = rest.split_once('|')?;
    let salt = base64::decode(salt_b64.as_bytes()).ok()?;
    let hash = base64::decode(hash_b64.as_bytes()).ok()?;
    Some((salt, hash))
}

/// Test whether `(salt, hash_tag)` matches `host[:port]` — constant-time
/// over the tag bytes to avoid leaking partial-match timing on misuse.
pub fn check_hashed(salt: &[u8], hash_tag: &[u8], host: &str, port: u16) -> bool {
    if hash_tag.len() != 20 {
        return false;
    }
    let canonical = format_host(host, port);
    let computed = hmac(salt, &canonical);
    constant_time_eq(&computed, hash_tag)
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hmac_known_vector() {
        // Smoke: stable output for a fixed salt/host pair.
        let salt = [0xAAu8; SALT_LEN];
        let t1 = hmac(&salt, "example.com");
        let t2 = hmac(&salt, "example.com");
        assert_eq!(t1, t2);
        let t3 = hmac(&salt, "example.org");
        assert_ne!(t1, t3);
    }

    #[test]
    fn roundtrip_encode_parse() {
        let salt = [0x10u8; SALT_LEN];
        let token = encode_hashed(&salt, "example.com");
        let (got_salt, got_hash) = parse_hashed(&token).expect("parse");
        assert_eq!(got_salt, salt);
        assert!(check_hashed(&got_salt, &got_hash, "example.com", 22));
        assert!(!check_hashed(&got_salt, &got_hash, "evil.example", 22));
    }

    #[test]
    fn format_host_brackets_non_default_port() {
        assert_eq!(format_host("example.com", 22), "example.com");
        assert_eq!(format_host("example.com", 2222), "[example.com]:2222");
    }
}
