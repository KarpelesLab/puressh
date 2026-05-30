//! `SSH_MSG_KEXINIT` (RFC 4253 §7.1) — the algorithm-advert message exchanged
//! at the start of every KEX (initial and re-keys alike).
//!
//! Layout, with the message-type byte included:
//!
//! ```text
//! byte         SSH_MSG_KEXINIT (= 20)
//! byte[16]     cookie
//! name-list    kex_algorithms
//! name-list    server_host_key_algorithms
//! name-list    encryption_algorithms_client_to_server
//! name-list    encryption_algorithms_server_to_client
//! name-list    mac_algorithms_client_to_server
//! name-list    mac_algorithms_server_to_client
//! name-list    compression_algorithms_client_to_server
//! name-list    compression_algorithms_server_to_client
//! name-list    languages_client_to_server
//! name-list    languages_server_to_client
//! boolean      first_kex_packet_follows
//! uint32       reserved (= 0)
//! ```
//!
//! The full encoded payload (starting with byte 20) is what gets hashed as
//! `I_C` / `I_S` when building the exchange hash.

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use crate::error::{Error, Result};
use crate::format::{NameList, Reader, Writer};

/// `SSH_MSG_KEXINIT` message type, RFC 4253 §12.
pub const SSH_MSG_KEXINIT: u8 = 20;
/// `SSH_MSG_NEWKEYS` message type, RFC 4253 §7.3.
pub const SSH_MSG_NEWKEYS: u8 = 21;

/// One side's advertised algorithm preferences, owned.
///
/// `KexAlgorithms` (the borrowed view in `kex.rs`) is the input the caller
/// hands us; `KexInit` is the owned, wire-encodable form.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KexInit {
    /// 16-byte random cookie.
    pub cookie: [u8; 16],
    /// Key-exchange algorithms.
    pub kex: Vec<String>,
    /// Server host-key algorithms.
    pub server_host_key: Vec<String>,
    /// Ciphers, client->server.
    pub ciphers_c2s: Vec<String>,
    /// Ciphers, server->client.
    pub ciphers_s2c: Vec<String>,
    /// MACs, client->server.
    pub macs_c2s: Vec<String>,
    /// MACs, server->client.
    pub macs_s2c: Vec<String>,
    /// Compression, client->server.
    pub comp_c2s: Vec<String>,
    /// Compression, server->client.
    pub comp_s2c: Vec<String>,
    /// Languages, client->server.
    pub lang_c2s: Vec<String>,
    /// Languages, server->client.
    pub lang_s2c: Vec<String>,
    /// `true` if the sender included an early KEX-init guess packet
    /// immediately after this KEXINIT.
    pub first_kex_packet_follows: bool,
}

impl KexInit {
    /// Build a `KexInit` from a borrowed [`KexAlgorithms`](super::KexAlgorithms)
    /// plus a random cookie.
    pub fn from_algorithms(algs: &super::KexAlgorithms<'_>, cookie: [u8; 16]) -> Self {
        Self {
            cookie,
            kex: collect(algs.kex),
            server_host_key: collect(algs.server_host_key),
            ciphers_c2s: collect(algs.ciphers_c2s),
            ciphers_s2c: collect(algs.ciphers_s2c),
            macs_c2s: collect(algs.macs_c2s),
            macs_s2c: collect(algs.macs_s2c),
            comp_c2s: collect(algs.comp_c2s),
            comp_s2c: collect(algs.comp_s2c),
            lang_c2s: collect(algs.lang_c2s),
            lang_s2c: collect(algs.lang_s2c),
            first_kex_packet_follows: false,
        }
    }

    /// Encode the full payload (including the leading message-type byte).
    /// The result is exactly what gets fed in as `I_C` or `I_S` to the
    /// exchange-hash builder.
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(256);
        w.write_u8(SSH_MSG_KEXINIT);
        w.write_raw(&self.cookie);
        write_name_list(&mut w, &self.kex);
        write_name_list(&mut w, &self.server_host_key);
        write_name_list(&mut w, &self.ciphers_c2s);
        write_name_list(&mut w, &self.ciphers_s2c);
        write_name_list(&mut w, &self.macs_c2s);
        write_name_list(&mut w, &self.macs_s2c);
        write_name_list(&mut w, &self.comp_c2s);
        write_name_list(&mut w, &self.comp_s2c);
        write_name_list(&mut w, &self.lang_c2s);
        write_name_list(&mut w, &self.lang_s2c);
        w.write_bool(self.first_kex_packet_follows);
        w.write_u32(0);
        w.into_vec()
    }

    /// Decode the full payload (message-type byte included). Trailing bytes
    /// after the reserved `uint32` are rejected.
    pub fn decode(payload: &[u8]) -> Result<Self> {
        let mut r = Reader::new(payload);
        let msg = r.read_u8()?;
        if msg != SSH_MSG_KEXINIT {
            return Err(Error::Protocol("expected SSH_MSG_KEXINIT"));
        }
        let cookie_slice = r.take(16)?;
        let mut cookie = [0u8; 16];
        cookie.copy_from_slice(cookie_slice);

        let kex = read_name_list(&mut r)?;
        let server_host_key = read_name_list(&mut r)?;
        let ciphers_c2s = read_name_list(&mut r)?;
        let ciphers_s2c = read_name_list(&mut r)?;
        let macs_c2s = read_name_list(&mut r)?;
        let macs_s2c = read_name_list(&mut r)?;
        let comp_c2s = read_name_list(&mut r)?;
        let comp_s2c = read_name_list(&mut r)?;
        let lang_c2s = read_name_list(&mut r)?;
        let lang_s2c = read_name_list(&mut r)?;
        let first_kex_packet_follows = r.read_bool()?;
        let _reserved = r.read_u32()?;
        if !r.is_empty() {
            return Err(Error::Format("KEXINIT trailing bytes"));
        }
        Ok(Self {
            cookie,
            kex,
            server_host_key,
            ciphers_c2s,
            ciphers_s2c,
            macs_c2s,
            macs_s2c,
            comp_c2s,
            comp_s2c,
            lang_c2s,
            lang_s2c,
            first_kex_packet_follows,
        })
    }
}

fn collect(items: &[&str]) -> Vec<String> {
    items.iter().map(|s| (*s).to_string()).collect()
}

fn write_name_list(w: &mut Writer, names: &[String]) {
    let mut joined = Vec::new();
    for (i, n) in names.iter().enumerate() {
        if i > 0 {
            joined.push(b',');
        }
        joined.extend_from_slice(n.as_bytes());
    }
    w.write_string(&joined);
}

fn read_name_list(r: &mut Reader<'_>) -> Result<Vec<String>> {
    let nl = NameList::read(r)?;
    let mut out = Vec::new();
    for entry in nl.iter() {
        let s =
            core::str::from_utf8(entry).map_err(|_| Error::Format("non-UTF8 name in name-list"))?;
        out.push(s.to_string());
    }
    Ok(out)
}

/// Result of negotiation between two KEXINITs.
#[derive(Debug, Clone)]
pub struct NegotiatedOwned {
    /// Chosen key-exchange method.
    pub kex: String,
    /// Chosen server host-key method.
    pub host_key: String,
    /// Chosen client->server cipher.
    pub cipher_c2s: String,
    /// Chosen server->client cipher.
    pub cipher_s2c: String,
    /// Chosen client->server MAC (empty when the cipher is AEAD).
    pub mac_c2s: String,
    /// Chosen server->client MAC.
    pub mac_s2c: String,
    /// Chosen client->server compression.
    pub comp_c2s: String,
    /// Chosen server->client compression.
    pub comp_s2c: String,
    /// True when the early-KEX guess included by either side was wrong and
    /// must be discarded (RFC 4253 §7.1).
    pub first_kex_packet_follows_wrong_guess: bool,
    /// True when both sides advertised the matching strict-kex marker
    /// (`kex-strict-c-v00@openssh.com` in the client's `kex_algorithms`
    /// AND `kex-strict-s-v00@openssh.com` in the server's). Enables the
    /// Terrapin mitigation (CVE-2023-48795): the transport resets sequence
    /// counters at NEWKEYS and rejects non-KEX packets between KEXINIT and
    /// NEWKEYS.
    pub strict_kex_enabled: bool,
}

/// Walk the **client's** list in order; the first name that also appears in
/// the **server's** list is the agreed algorithm (RFC 4253 §7.1). For the
/// KEX category, strict-kex signalling markers
/// (`kex-strict-{c,s}-v00@openssh.com`) are ignored — they are *not* real
/// algorithms.
fn pick<'a>(category: &'static str, client: &'a [String], server: &[String]) -> Result<&'a str> {
    let is_kex = category == "kex algorithm";
    for name in client {
        if is_kex && super::kex::is_strict_kex_marker(name) {
            continue;
        }
        if server.iter().any(|s| s == name) {
            return Ok(name.as_str());
        }
    }
    Err(Error::NoCommonAlgorithm(category))
}

/// Negotiate algorithms between a `client` KEXINIT and a `server` KEXINIT.
///
/// The cipher/MAC pairs are negotiated independently per direction, so the
/// agreed values for client->server and server->client may differ.
///
/// If either side set `first_kex_packet_follows`, the runner needs to know
/// whether the guess was right: per RFC 4253 §7.1 the guess covers the kex
/// algorithm AND the host-key algorithm. The returned
/// `first_kex_packet_follows_wrong_guess` flag captures exactly that.
pub fn negotiate(client: &KexInit, server: &KexInit) -> Result<NegotiatedOwned> {
    let kex = pick("kex algorithm", &client.kex, &server.kex)?;
    let host_key = pick(
        "host-key algorithm",
        &client.server_host_key,
        &server.server_host_key,
    )?;
    let cipher_c2s = pick("cipher c2s", &client.ciphers_c2s, &server.ciphers_c2s)?;
    let cipher_s2c = pick("cipher s2c", &client.ciphers_s2c, &server.ciphers_s2c)?;

    let c_aead = crate::cipher::by_name(cipher_c2s)
        .map(|s| s.aead)
        .unwrap_or(false);
    let s_aead = crate::cipher::by_name(cipher_s2c)
        .map(|s| s.aead)
        .unwrap_or(false);

    let mac_c2s = if c_aead {
        ""
    } else {
        pick("mac c2s", &client.macs_c2s, &server.macs_c2s)?
    };
    let mac_s2c = if s_aead {
        ""
    } else {
        pick("mac s2c", &client.macs_s2c, &server.macs_s2c)?
    };
    let comp_c2s = pick("compression c2s", &client.comp_c2s, &server.comp_c2s)?;
    let comp_s2c = pick("compression s2c", &client.comp_s2c, &server.comp_s2c)?;

    let guesser_present = client.first_kex_packet_follows || server.first_kex_packet_follows;
    let wrong = if guesser_present {
        // RFC 4253 §7.1: guess is right iff both sides agree on the kex and
        // host-key algorithms with each side's first preference.
        let client_first_kex = client.kex.first().map(String::as_str);
        let server_first_kex = server.kex.first().map(String::as_str);
        let client_first_hk = client.server_host_key.first().map(String::as_str);
        let server_first_hk = server.server_host_key.first().map(String::as_str);
        !(client_first_kex == server_first_kex && client_first_hk == server_first_hk)
    } else {
        false
    };

    // Strict-kex (Terrapin / CVE-2023-48795): only enabled when each side
    // saw the OTHER side's matching marker in its kex_algorithms list.
    let client_advertised = client
        .kex
        .iter()
        .any(|s| s == super::kex::STRICT_KEX_CLIENT_MARKER);
    let server_advertised = server
        .kex
        .iter()
        .any(|s| s == super::kex::STRICT_KEX_SERVER_MARKER);
    let strict_kex_enabled = client_advertised && server_advertised;

    Ok(NegotiatedOwned {
        kex: kex.to_string(),
        host_key: host_key.to_string(),
        cipher_c2s: cipher_c2s.to_string(),
        cipher_s2c: cipher_s2c.to_string(),
        mac_c2s: mac_c2s.to_string(),
        mac_s2c: mac_s2c.to_string(),
        comp_c2s: comp_c2s.to_string(),
        comp_s2c: comp_s2c.to_string(),
        first_kex_packet_follows_wrong_guess: wrong,
        strict_kex_enabled,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::kex::{defaults, KexAlgorithms};

    fn defaults_algorithms() -> KexAlgorithms<'static> {
        KexAlgorithms {
            kex: defaults::KEX,
            server_host_key: defaults::HOST_KEY,
            ciphers_c2s: defaults::CIPHERS,
            ciphers_s2c: defaults::CIPHERS,
            macs_c2s: defaults::MACS,
            macs_s2c: defaults::MACS,
            comp_c2s: defaults::COMP,
            comp_s2c: defaults::COMP,
            lang_c2s: &[],
            lang_s2c: &[],
        }
    }

    #[test]
    fn round_trip_encode_decode() {
        let algs = defaults_algorithms();
        let mut cookie = [0u8; 16];
        for (i, b) in cookie.iter_mut().enumerate() {
            *b = i as u8;
        }
        let ki = KexInit::from_algorithms(&algs, cookie);
        let bytes = ki.encode();
        assert_eq!(bytes[0], SSH_MSG_KEXINIT);
        assert_eq!(&bytes[1..17], &cookie[..]);
        let decoded = KexInit::decode(&bytes).unwrap();
        assert_eq!(decoded, ki);
    }

    #[test]
    fn decode_rejects_wrong_message_type() {
        let mut buf = Vec::from([21u8]);
        buf.extend_from_slice(&[0u8; 16]);
        for _ in 0..10 {
            buf.extend_from_slice(&[0, 0, 0, 0]);
        }
        buf.push(0);
        buf.extend_from_slice(&[0, 0, 0, 0]);
        assert!(matches!(KexInit::decode(&buf), Err(Error::Protocol(_))));
    }

    #[test]
    fn decode_rejects_trailing_bytes() {
        let algs = defaults_algorithms();
        let mut ki = KexInit::from_algorithms(&algs, [0u8; 16]);
        let mut bytes = ki.encode();
        bytes.push(0xff);
        assert!(matches!(KexInit::decode(&bytes), Err(Error::Format(_))));
        ki.cookie[0] = 1;
    }

    #[test]
    fn negotiate_picks_clients_first_common() {
        let mut a = KexInit::from_algorithms(&defaults_algorithms(), [0u8; 16]);
        a.kex = ["curve25519-sha256", "ecdh-sha2-nistp256"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let mut b = a.clone();
        b.kex = ["ecdh-sha2-nistp256", "curve25519-sha256"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let neg = negotiate(&a, &b).unwrap();
        assert_eq!(neg.kex, "curve25519-sha256");
    }

    #[test]
    fn negotiate_rejects_no_overlap() {
        let mut a = KexInit::from_algorithms(&defaults_algorithms(), [0u8; 16]);
        let mut b = a.clone();
        a.kex = vec!["curve25519-sha256".into()];
        b.kex = vec!["diffie-hellman-group14-sha256".into()];
        assert!(matches!(
            negotiate(&a, &b),
            Err(Error::NoCommonAlgorithm(_))
        ));
    }

    #[test]
    fn negotiate_strict_kex_requires_both_markers() {
        use crate::transport::kex::{STRICT_KEX_CLIENT_MARKER, STRICT_KEX_SERVER_MARKER};

        let base = KexInit::from_algorithms(&defaults_algorithms(), [0u8; 16]);

        // Both sides advertise the appropriate marker -> enabled.
        let neg = negotiate(&base, &base).unwrap();
        assert!(neg.strict_kex_enabled);

        // Client missing -c marker -> disabled.
        let mut a = base.clone();
        a.kex.retain(|n| n != STRICT_KEX_CLIENT_MARKER);
        let neg = negotiate(&a, &base).unwrap();
        assert!(!neg.strict_kex_enabled);

        // Server missing -s marker -> disabled.
        let mut b = base.clone();
        b.kex.retain(|n| n != STRICT_KEX_SERVER_MARKER);
        let neg = negotiate(&base, &b).unwrap();
        assert!(!neg.strict_kex_enabled);
    }

    #[test]
    fn negotiate_does_not_pick_strict_kex_marker_as_algorithm() {
        use crate::transport::kex::STRICT_KEX_CLIENT_MARKER;

        let mut a = KexInit::from_algorithms(&defaults_algorithms(), [0u8; 16]);
        let mut b = a.clone();
        // Only common entries are the strict markers. Picker must reject.
        a.kex = vec![STRICT_KEX_CLIENT_MARKER.to_string()];
        b.kex = vec![STRICT_KEX_CLIENT_MARKER.to_string()];
        assert!(matches!(
            negotiate(&a, &b),
            Err(Error::NoCommonAlgorithm(_))
        ));
    }

    #[test]
    fn negotiate_skips_mac_for_aead() {
        let mut a = KexInit::from_algorithms(&defaults_algorithms(), [0u8; 16]);
        let mut b = a.clone();
        a.ciphers_c2s = vec!["chacha20-poly1305@openssh.com".into()];
        a.ciphers_s2c = vec!["chacha20-poly1305@openssh.com".into()];
        b.ciphers_c2s = vec!["chacha20-poly1305@openssh.com".into()];
        b.ciphers_s2c = vec!["chacha20-poly1305@openssh.com".into()];
        a.macs_c2s.clear();
        a.macs_s2c.clear();
        b.macs_c2s.clear();
        b.macs_s2c.clear();
        let neg = negotiate(&a, &b).unwrap();
        assert_eq!(neg.cipher_c2s, "chacha20-poly1305@openssh.com");
        assert_eq!(neg.mac_c2s, "");
        assert_eq!(neg.mac_s2c, "");
    }
}
