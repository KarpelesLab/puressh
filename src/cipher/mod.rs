//! SSH cipher suite adapters over [`purecrypto::cipher`].
//!
//! Three families of suites are surfaced:
//!
//! - **`aes*-ctr`** (RFC 4344) — paired with a separate HMAC, possibly in EtM mode.
//! - **`aes*-gcm@openssh.com`** (RFC 5647) — AEAD with implicit 12-byte nonce.
//! - **`chacha20-poly1305@openssh.com`** — AEAD with two ChaCha20 keys (one
//!   for the length field, one for the payload) and a Poly1305 tag.

mod chachapoly;
mod ctr;
mod gcm;

use chachapoly::ChaChaPoly;
use ctr::AesCtr;
use gcm::GcmState;

use crate::error::{Error, Result};

/// SSH-side identifier and key/iv/block geometry for a cipher suite.
#[derive(Debug, Clone, Copy)]
pub struct CipherSpec {
    /// On-the-wire SSH name (e.g. `"aes256-ctr"`).
    pub name: &'static str,
    /// Key length in bytes.
    pub key_len: usize,
    /// IV (or nonce) length in bytes — 16 for CTR, 12 for GCM, 8 for ChaCha20.
    pub iv_len: usize,
    /// Block size in bytes (for length-field rounding); 16 for AES, 8 for ChaCha20 stream.
    pub block_size: usize,
    /// Whether this suite is AEAD (integrity built in — no separate MAC).
    pub aead: bool,
    /// AEAD tag length in bytes (0 if non-AEAD).
    pub tag_len: usize,
}

/// Catalogue of suites this build supports.
pub const ALL: &[CipherSpec] = &[
    CipherSpec {
        name: "chacha20-poly1305@openssh.com",
        key_len: 64,
        iv_len: 0,
        block_size: 8,
        aead: true,
        tag_len: 16,
    },
    CipherSpec {
        name: "aes256-gcm@openssh.com",
        key_len: 32,
        iv_len: 12,
        block_size: 16,
        aead: true,
        tag_len: 16,
    },
    CipherSpec {
        name: "aes128-gcm@openssh.com",
        key_len: 16,
        iv_len: 12,
        block_size: 16,
        aead: true,
        tag_len: 16,
    },
    CipherSpec {
        name: "aes256-ctr",
        key_len: 32,
        iv_len: 16,
        block_size: 16,
        aead: false,
        tag_len: 0,
    },
    CipherSpec {
        name: "aes192-ctr",
        key_len: 24,
        iv_len: 16,
        block_size: 16,
        aead: false,
        tag_len: 0,
    },
    CipherSpec {
        name: "aes128-ctr",
        key_len: 16,
        iv_len: 16,
        block_size: 16,
        aead: false,
        tag_len: 0,
    },
];

/// Look up a [`CipherSpec`] by SSH name.
pub fn by_name(name: &str) -> Option<&'static CipherSpec> {
    ALL.iter().find(|c| c.name == name)
}

/// Direction-agnostic SSH cipher state.
///
/// Each suite exposes only the operations the packet codec actually drives:
///
/// - CTR ciphers are stream ciphers, so the codec uses [`SshCipher::stream`]
///   for both encrypt and decrypt and pairs it with a separate MAC.
/// - AES-GCM is AEAD; the packet length is transmitted in cleartext and bound
///   to the tag as AAD. The codec drives [`SshCipher::aead_seal_len_aad`] /
///   [`SshCipher::aead_open_len_aad`].
/// - `chacha20-poly1305@openssh.com` encrypts the length field separately with
///   a second ChaCha20 key. The codec drives [`SshCipher::cp_xor_length`] for
///   the length field, [`SshCipher::cp_tag`] / [`SshCipher::cp_verify_tag`] to
///   produce or check the Poly1305 tag, and [`SshCipher::cp_xor_payload`] to
///   apply the payload keystream once the tag has been verified.
pub enum SshCipher {
    /// `aes128-ctr` / `aes192-ctr` / `aes256-ctr`.
    Ctr(AesCtr),
    /// `aes128-gcm@openssh.com` / `aes256-gcm@openssh.com`.
    Gcm(GcmState),
    /// `chacha20-poly1305@openssh.com`.
    ChaChaPoly(ChaChaPoly),
}

impl SshCipher {
    /// Constructs a cipher state from its SSH name, key, and IV. The lengths
    /// of `key` and `iv` must match the corresponding [`CipherSpec`].
    pub fn new(name: &str, key: &[u8], iv: &[u8]) -> Result<Self> {
        match name {
            "aes128-ctr" => Ok(SshCipher::Ctr(AesCtr::new_128(key, iv)?)),
            "aes192-ctr" => Ok(SshCipher::Ctr(AesCtr::new_192(key, iv)?)),
            "aes256-ctr" => Ok(SshCipher::Ctr(AesCtr::new_256(key, iv)?)),
            "aes128-gcm@openssh.com" => Ok(SshCipher::Gcm(GcmState::new_128(key, iv)?)),
            "aes256-gcm@openssh.com" => Ok(SshCipher::Gcm(GcmState::new_256(key, iv)?)),
            "chacha20-poly1305@openssh.com" => Ok(SshCipher::ChaChaPoly(ChaChaPoly::new(key)?)),
            _ => Err(Error::Unsupported("cipher")),
        }
    }

    /// Whether this suite is an AEAD (no separate MAC).
    pub fn is_aead(&self) -> bool {
        !matches!(self, SshCipher::Ctr(_))
    }

    /// Whether this suite encrypts the binary-packet length field on the wire.
    /// AES-GCM transmits the length in cleartext (as AAD); the others encrypt it.
    pub fn encrypts_length(&self) -> bool {
        !matches!(self, SshCipher::Gcm(_))
    }

    /// Streaming encrypt/decrypt for non-AEAD CTR ciphers. XORs the keystream
    /// into `buf` in place across arbitrary call chunks.
    ///
    /// # Errors
    /// Returns [`Error::Unsupported`] when called on an AEAD suite.
    pub fn stream(&mut self, buf: &mut [u8]) -> Result<()> {
        match self {
            SshCipher::Ctr(c) => {
                c.apply_keystream(buf);
                Ok(())
            }
            _ => Err(Error::Unsupported("stream op on AEAD cipher")),
        }
    }

    /// AES-GCM seal: encrypts `payload` in place with the 4-byte unencrypted
    /// length field bound as AAD, and returns the 16-byte tag. The internal
    /// invocation counter advances on success.
    ///
    /// # Errors
    /// Returns [`Error::Unsupported`] when called on a non-GCM suite.
    pub fn aead_seal_len_aad(&mut self, length: &[u8], payload: &mut [u8]) -> Result<[u8; 16]> {
        match self {
            SshCipher::Gcm(g) => g.seal(length, payload),
            _ => Err(Error::Unsupported("GCM seal on non-GCM cipher")),
        }
    }

    /// AES-GCM open: verifies `tag` against `length || ciphertext` and
    /// decrypts `payload` in place on success. On tag mismatch the buffer is
    /// left as ciphertext and the invocation counter is not advanced.
    ///
    /// # Errors
    /// - [`Error::BadTag`] if the tag does not match.
    /// - [`Error::Unsupported`] when called on a non-GCM suite.
    pub fn aead_open_len_aad(
        &mut self,
        length: &[u8],
        payload: &mut [u8],
        tag: &[u8],
    ) -> Result<()> {
        match self {
            SshCipher::Gcm(g) => g.open(length, payload, tag),
            _ => Err(Error::Unsupported("GCM open on non-GCM cipher")),
        }
    }

    /// chacha20-poly1305: XOR the 4-byte length-field keystream into `buf`.
    /// Symmetric — works for both encrypt and decrypt.
    pub fn cp_xor_length(&self, seq: u64, buf: &mut [u8]) -> Result<()> {
        match self {
            SshCipher::ChaChaPoly(c) => {
                c.xor_length(seq, buf);
                Ok(())
            }
            _ => Err(Error::Unsupported("chacha20-poly1305 op on other cipher")),
        }
    }

    /// chacha20-poly1305: XOR the payload keystream into `buf`. Counter starts
    /// at 1; counter 0 is consumed by the Poly1305 OTK derivation.
    pub fn cp_xor_payload(&self, seq: u64, buf: &mut [u8]) -> Result<()> {
        match self {
            SshCipher::ChaChaPoly(c) => {
                c.xor_payload(seq, buf);
                Ok(())
            }
            _ => Err(Error::Unsupported("chacha20-poly1305 op on other cipher")),
        }
    }

    /// chacha20-poly1305: compute the Poly1305 tag over
    /// `encrypted_length || encrypted_payload`.
    pub fn cp_tag(&self, seq: u64, enc_len: &[u8], enc_payload: &[u8]) -> Result<[u8; 16]> {
        match self {
            SshCipher::ChaChaPoly(c) => Ok(c.tag(seq, enc_len, enc_payload)),
            _ => Err(Error::Unsupported("chacha20-poly1305 op on other cipher")),
        }
    }

    /// chacha20-poly1305: verify the Poly1305 tag in constant time.
    pub fn cp_verify_tag(
        &self,
        seq: u64,
        enc_len: &[u8],
        enc_payload: &[u8],
        tag: &[u8],
    ) -> Result<()> {
        match self {
            SshCipher::ChaChaPoly(c) => c.verify_tag(seq, enc_len, enc_payload, tag),
            _ => Err(Error::Unsupported("chacha20-poly1305 op on other cipher")),
        }
    }
}

/// Construct a cipher state for the named SSH suite. Returns `None` for
/// unknown names; lengths of `key` and `iv` are validated by the underlying
/// adapter.
pub fn cipher_by_name(name: &str, key: &[u8], iv: &[u8]) -> Option<Result<SshCipher>> {
    by_name(name).map(|_| SshCipher::new(name, key, iv))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn factory_dispatches_known_names() {
        for spec in ALL {
            let key = vec![0u8; spec.key_len];
            let iv = vec![0u8; spec.iv_len];
            let r = cipher_by_name(spec.name, &key, &iv).expect("known");
            r.unwrap();
        }
    }

    #[test]
    fn factory_rejects_unknown() {
        assert!(cipher_by_name("nope", &[], &[]).is_none());
    }

    #[test]
    fn ctr_roundtrip_via_trait() {
        let key = [0x42u8; 16];
        let iv = [0x10u8; 16];
        let mut enc = SshCipher::new("aes128-ctr", &key, &iv).unwrap();
        let mut dec = SshCipher::new("aes128-ctr", &key, &iv).unwrap();
        let plain = b"hello ssh world!".to_vec();
        let mut buf = plain.clone();
        enc.stream(&mut buf).unwrap();
        assert_ne!(buf, plain);
        dec.stream(&mut buf).unwrap();
        assert_eq!(buf, plain);
    }

    #[test]
    fn gcm_roundtrip_via_trait() {
        let key = [0x01u8; 16];
        let iv = [0x02u8; 12];
        let mut enc = SshCipher::new("aes128-gcm@openssh.com", &key, &iv).unwrap();
        let mut dec = SshCipher::new("aes128-gcm@openssh.com", &key, &iv).unwrap();
        let aad = [0u8, 0, 0, 16];
        let plain = [0xabu8; 16];
        let mut buf = plain;
        let tag = enc.aead_seal_len_aad(&aad, &mut buf).unwrap();
        dec.aead_open_len_aad(&aad, &mut buf, &tag).unwrap();
        assert_eq!(buf, plain);
    }

    #[test]
    fn chachapoly_roundtrip_via_trait() {
        let mut key = [0u8; 64];
        for (i, b) in key.iter_mut().enumerate() {
            *b = i as u8;
        }
        let enc = SshCipher::new("chacha20-poly1305@openssh.com", &key, &[]).unwrap();
        let dec = SshCipher::new("chacha20-poly1305@openssh.com", &key, &[]).unwrap();

        let seq = 42u64;
        let mut len_buf = [0u8, 0, 0, 16];
        let plain_len = len_buf;
        enc.cp_xor_length(seq, &mut len_buf).unwrap();
        assert_ne!(len_buf, plain_len);

        let mut payload = [0xa5u8; 16];
        let plain_payload = payload;
        enc.cp_xor_payload(seq, &mut payload).unwrap();
        let tag = enc.cp_tag(seq, &len_buf, &payload).unwrap();

        dec.cp_verify_tag(seq, &len_buf, &payload, &tag).unwrap();
        dec.cp_xor_payload(seq, &mut payload).unwrap();
        assert_eq!(payload, plain_payload);
        dec.cp_xor_length(seq, &mut len_buf).unwrap();
        assert_eq!(len_buf, plain_len);
    }

    #[test]
    fn cross_kind_ops_return_unsupported() {
        let mut g = SshCipher::new("aes128-gcm@openssh.com", &[0u8; 16], &[0u8; 12]).unwrap();
        assert!(matches!(g.stream(&mut []), Err(Error::Unsupported(_))));
        let mut c = SshCipher::new("aes128-ctr", &[0u8; 16], &[0u8; 16]).unwrap();
        assert!(matches!(
            c.aead_seal_len_aad(&[], &mut []),
            Err(Error::Unsupported(_))
        ));
    }
}
