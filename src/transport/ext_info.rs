//! `SSH_MSG_EXT_INFO` — RFC 8308 extension negotiation.
//!
//! After both sides have sent `SSH_MSG_NEWKEYS` on the **first** key
//! exchange, a peer that observed the matching `ext-info-{c,s}` marker in
//! the other side's `SSH_MSG_KEXINIT.kex_algorithms` list MAY send a single
//! `SSH_MSG_EXT_INFO` carrying advisory extension names. The client may
//! additionally send (and the server may receive) one as the first packet
//! after `SSH_MSG_USERAUTH_SUCCESS`.
//!
//! Wire layout:
//!
//! ```text
//! byte      SSH_MSG_EXT_INFO  (= 7)
//! uint32    nr-extensions
//! repeated nr-extensions times:
//!   string  extension-name
//!   string  extension-value
//! ```
//!
//! The `server-sig-algs` extension (§3.1) carries a **string** containing a
//! comma-separated list of signature algorithm names — NOT a name-list
//! length-prefix. We preserve the raw string verbatim and split on demand.

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use crate::error::{Error, Result};
use crate::format::{Reader, Writer};

/// `SSH_MSG_EXT_INFO` message type byte (RFC 8308 §2.2).
pub const SSH_MSG_EXT_INFO: u8 = 7;

/// Marker advertised by the client in its `kex_algorithms` list when it
/// wants to receive `SSH_MSG_EXT_INFO` from the server (RFC 8308 §2.1).
pub const EXT_INFO_CLIENT_MARKER: &str = "ext-info-c";
/// Marker advertised by the server in its `kex_algorithms` list when it
/// wants to receive `SSH_MSG_EXT_INFO` from the client (RFC 8308 §2.1).
pub const EXT_INFO_SERVER_MARKER: &str = "ext-info-s";

/// Returns `true` if `name` is one of the ext-info signalling markers. The
/// kexinit negotiator skips these when picking a real KEX algorithm.
pub fn is_ext_info_marker(name: &str) -> bool {
    name == EXT_INFO_CLIENT_MARKER || name == EXT_INFO_SERVER_MARKER
}

/// Parsed `SSH_MSG_EXT_INFO` contents.
///
/// `server_sig_algs` and `publickey_algorithms_in_use` are pre-extracted from
/// `raw` for ergonomic access; `raw` keeps the original ordered list of
/// `(name, value)` pairs so callers can inspect forward-compatible
/// extensions we don't model directly.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ExtInfo {
    /// RFC 8308 §3.1 — comma-separated list of signature algorithm names
    /// the **server** accepts on a `publickey` userauth signature.
    pub server_sig_algs: Option<String>,
    /// RFC 8332 §3.5 (informational) / draft-ietf-curdle-ssh-ext-info —
    /// comma-separated list of pubkey algorithms a peer intends to use.
    pub publickey_algorithms_in_use: Option<String>,
    /// All `(name, value)` pairs as they appeared on the wire, in order.
    pub raw: Vec<(String, String)>,
}

impl ExtInfo {
    /// Build an empty `ExtInfo`. Convenience for callers that conditionally
    /// fill in known extensions.
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert (or replace) the `server-sig-algs` extension. `value` is the
    /// comma-separated list of accepted signature algorithm names.
    pub fn with_server_sig_algs(mut self, value: impl Into<String>) -> Self {
        let v = value.into();
        self.set_raw("server-sig-algs", &v);
        self.server_sig_algs = Some(v);
        self
    }

    /// Insert (or replace) the `publickey-algorithms-in-use` extension.
    pub fn with_publickey_algorithms_in_use(mut self, value: impl Into<String>) -> Self {
        let v = value.into();
        self.set_raw("publickey-algorithms-in-use", &v);
        self.publickey_algorithms_in_use = Some(v);
        self
    }

    fn set_raw(&mut self, name: &str, value: &str) {
        if let Some(pair) = self.raw.iter_mut().find(|(n, _)| n == name) {
            pair.1 = value.to_string();
        } else {
            self.raw.push((name.to_string(), value.to_string()));
        }
    }

    /// `server-sig-algs` as a slice-of-`&str` iterator, splitting the
    /// underlying comma-separated string. Returns `None` if the extension
    /// was not present.
    pub fn server_sig_algs_iter(&self) -> Option<impl Iterator<Item = &str>> {
        self.server_sig_algs
            .as_deref()
            .map(|s| s.split(',').map(str::trim).filter(|s| !s.is_empty()))
    }

    /// Encode as a complete SSH payload (message-type byte included). The
    /// result is suitable to hand to the packet codec.
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(32 + self.raw.iter().map(estimated_size).sum::<usize>());
        w.write_u8(SSH_MSG_EXT_INFO);
        w.write_u32(self.raw.len() as u32);
        for (name, value) in &self.raw {
            w.write_string(name.as_bytes());
            w.write_string(value.as_bytes());
        }
        w.into_vec()
    }

    /// Decode a complete SSH payload (message-type byte included). Trailing
    /// bytes after the last extension pair are rejected. Non-UTF8 names or
    /// values fail with `Error::Format`.
    pub fn decode(payload: &[u8]) -> Result<Self> {
        let mut r = Reader::new(payload);
        let msg = r.read_u8()?;
        if msg != SSH_MSG_EXT_INFO {
            return Err(Error::Protocol("expected SSH_MSG_EXT_INFO"));
        }
        let n = r.read_u32()? as usize;
        // RFC 8308 puts no hard cap on nr-extensions but 64 KiB of pairs
        // is already astronomical; bound it well below the BPP limit so a
        // malformed peer cannot exhaust memory.
        if n > 1024 {
            return Err(Error::Format("EXT_INFO nr-extensions too large"));
        }
        let mut out = Self::default();
        for _ in 0..n {
            let name = r.read_string()?;
            let value = r.read_string()?;
            let name = core::str::from_utf8(name)
                .map_err(|_| Error::Format("EXT_INFO non-UTF8 name"))?
                .to_string();
            let value = core::str::from_utf8(value)
                .map_err(|_| Error::Format("EXT_INFO non-UTF8 value"))?
                .to_string();
            match name.as_str() {
                "server-sig-algs" => out.server_sig_algs = Some(value.clone()),
                "publickey-algorithms-in-use" => {
                    out.publickey_algorithms_in_use = Some(value.clone())
                }
                _ => {}
            }
            out.raw.push((name, value));
        }
        if !r.is_empty() {
            return Err(Error::Format("EXT_INFO trailing bytes"));
        }
        Ok(out)
    }
}

fn estimated_size(pair: &(String, String)) -> usize {
    4 + pair.0.len() + 4 + pair.1.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_server_sig_algs() {
        let ext = ExtInfo::new().with_server_sig_algs("rsa-sha2-512,rsa-sha2-256");
        let bytes = ext.encode();
        assert_eq!(bytes[0], SSH_MSG_EXT_INFO);
        let parsed = ExtInfo::decode(&bytes).unwrap();
        assert_eq!(parsed, ext);
        assert_eq!(
            parsed.server_sig_algs.as_deref(),
            Some("rsa-sha2-512,rsa-sha2-256"),
        );
        let algs: Vec<&str> = parsed.server_sig_algs_iter().unwrap().collect();
        assert_eq!(algs, vec!["rsa-sha2-512", "rsa-sha2-256"]);
    }

    #[test]
    fn round_trip_multiple_extensions_preserves_order() {
        let ext = ExtInfo::new()
            .with_server_sig_algs("ssh-ed25519,rsa-sha2-512")
            .with_publickey_algorithms_in_use("ssh-ed25519");
        let bytes = ext.encode();
        let parsed = ExtInfo::decode(&bytes).unwrap();
        assert_eq!(parsed.raw.len(), 2);
        assert_eq!(parsed.raw[0].0, "server-sig-algs");
        assert_eq!(parsed.raw[1].0, "publickey-algorithms-in-use");
        assert_eq!(
            parsed.publickey_algorithms_in_use.as_deref(),
            Some("ssh-ed25519"),
        );
    }

    #[test]
    fn unknown_extensions_are_preserved_in_raw() {
        let mut ext = ExtInfo::new();
        ext.raw
            .push(("custom@example.com".into(), "payload".into()));
        let bytes = ext.encode();
        let parsed = ExtInfo::decode(&bytes).unwrap();
        assert_eq!(parsed.raw.len(), 1);
        assert_eq!(parsed.raw[0].0, "custom@example.com");
        assert!(parsed.server_sig_algs.is_none());
    }

    #[test]
    fn decode_rejects_wrong_message_type() {
        let buf = [42u8, 0, 0, 0, 0];
        match ExtInfo::decode(&buf) {
            Err(Error::Protocol(_)) => {}
            other => panic!("expected Protocol, got {other:?}"),
        }
    }

    #[test]
    fn decode_rejects_truncated() {
        // Says nr-extensions = 1 but doesn't include any pair.
        let buf = [SSH_MSG_EXT_INFO, 0, 0, 0, 1];
        assert!(ExtInfo::decode(&buf).is_err());

        // Says nr-extensions = 1 and a name but no value.
        let mut w = Writer::with_capacity(16);
        w.write_u8(SSH_MSG_EXT_INFO);
        w.write_u32(1);
        w.write_string(b"server-sig-algs");
        // missing value string entirely
        assert!(ExtInfo::decode(&w.into_vec()).is_err());
    }

    #[test]
    fn decode_rejects_trailing_bytes() {
        let mut bytes = ExtInfo::new().with_server_sig_algs("ssh-ed25519").encode();
        bytes.push(0xff);
        match ExtInfo::decode(&bytes) {
            Err(Error::Format(_)) => {}
            other => panic!("expected Format, got {other:?}"),
        }
    }

    #[test]
    fn decode_rejects_obscene_nr_extensions() {
        let buf = [SSH_MSG_EXT_INFO, 0, 0, 0xff, 0xff];
        match ExtInfo::decode(&buf) {
            Err(Error::Format(_)) => {}
            other => panic!("expected Format, got {other:?}"),
        }
    }

    #[test]
    fn empty_ext_info_is_legal() {
        let bytes = ExtInfo::new().encode();
        let parsed = ExtInfo::decode(&bytes).unwrap();
        assert!(parsed.raw.is_empty());
        assert!(parsed.server_sig_algs.is_none());
        assert!(parsed.publickey_algorithms_in_use.is_none());
    }

    #[test]
    fn is_ext_info_marker_matches_only_the_two_names() {
        assert!(is_ext_info_marker("ext-info-c"));
        assert!(is_ext_info_marker("ext-info-s"));
        assert!(!is_ext_info_marker("ext-info-x"));
        assert!(!is_ext_info_marker("curve25519-sha256"));
    }
}
