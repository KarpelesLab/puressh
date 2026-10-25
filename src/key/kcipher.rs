//! The ciphers an openssh-key-v1 container may be encrypted with: those
//! of OpenSSH's `cipher.c` table, keyed (key ‖ IV) by `bcrypt_pbkdf`. The
//! AEAD ones (`aes*-gcm@openssh.com`, `chacha20-poly1305@openssh.com`)
//! append their tag after the encrypted section; `none` leaves it in the
//! clear.

use alloc::vec::Vec;

use crate::cipher::SshCipher;
use crate::error::{Error, Result};

/// The cipher names a private key may use (`ssh-keygen -Z`), as OpenSSH's.
pub const OPENSSH_KEY_CIPHERS: &[&str] = &[
    "3des-cbc",
    "aes128-cbc",
    "aes192-cbc",
    "aes256-cbc",
    "aes128-ctr",
    "aes192-ctr",
    "aes256-ctr",
    "aes128-gcm@openssh.com",
    "aes256-gcm@openssh.com",
    "chacha20-poly1305@openssh.com",
    "none",
];

/// A cipher's geometry for the key container (OpenSSH's `cipher_keylen`,
/// `cipher_ivlen`, `cipher_blocksize`, `cipher_authlen`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct KeyCipher {
    pub name: &'static str,
    pub key_len: usize,
    pub iv_len: usize,
    pub block: usize,
    pub tag_len: usize,
}

impl KeyCipher {
    /// The cipher named `name`, if a key may use it.
    pub fn by_name(name: &[u8]) -> Option<Self> {
        let (key_len, iv_len, block, tag_len) = match name {
            b"3des-cbc" => (24, 8, 8, 0),
            b"aes128-cbc" | b"aes128-ctr" => (16, 16, 16, 0),
            b"aes192-cbc" | b"aes192-ctr" => (24, 16, 16, 0),
            b"aes256-cbc" | b"aes256-ctr" => (32, 16, 16, 0),
            b"aes128-gcm@openssh.com" => (16, 12, 16, 16),
            b"aes256-gcm@openssh.com" => (32, 12, 16, 16),
            b"chacha20-poly1305@openssh.com" => (64, 0, 8, 16),
            b"none" => (0, 8, 8, 0),
            _ => return None,
        };
        // An explicit loop: rustc --release once hung on a closure `find`
        // over a const array.
        let mut found = None;
        for n in OPENSSH_KEY_CIPHERS {
            if n.as_bytes() == name {
                found = Some(*n);
                break;
            }
        }
        Some(Self {
            name: found?,
            key_len,
            iv_len,
            block,
            tag_len,
        })
    }

    fn state(&self, key_iv: &[u8]) -> Result<SshCipher> {
        let (key, iv) = key_iv.split_at(self.key_len);
        SshCipher::new(self.name, key, &iv[..self.iv_len])
    }

    /// Encrypt `buf` (a whole number of blocks) in place with `key_iv`
    /// (`key_len + iv_len` bytes), returning the tag (empty unless AEAD).
    pub fn seal(&self, key_iv: &[u8], buf: &mut [u8]) -> Result<Vec<u8>> {
        if self.name == "none" {
            return Ok(Vec::new());
        }
        let mut c = self.state(key_iv)?;
        Ok(match &c {
            SshCipher::Gcm(_) => c.aead_seal_len_aad(&[], buf)?.to_vec(),
            SshCipher::ChaChaPoly(_) => {
                c.cp_xor_payload(0, buf)?;
                c.cp_tag(0, &[], buf)?.to_vec()
            }
            _ => {
                c.encrypt_blocks(buf)?;
                Vec::new()
            }
        })
    }

    /// Check `tag` and decrypt `buf` in place; a bad tag is a wrong
    /// passphrase.
    pub fn open(&self, key_iv: &[u8], buf: &mut [u8], tag: &[u8]) -> Result<()> {
        if self.name == "none" {
            return Ok(());
        }
        let mut c = self.state(key_iv)?;
        let r = match &c {
            SshCipher::Gcm(_) => c.aead_open_len_aad(&[], buf, tag),
            SshCipher::ChaChaPoly(_) => c
                .cp_verify_tag(0, &[], buf, tag)
                .and_then(|()| c.cp_xor_payload(0, buf)),
            _ => c.decrypt_blocks(buf),
        };
        r.map_err(|e| match e {
            Error::BadTag => Error::Crypto("wrong passphrase"),
            e => e,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_cipher_round_trips() {
        for name in OPENSSH_KEY_CIPHERS {
            let c = KeyCipher::by_name(name.as_bytes()).unwrap();
            let key_iv: Vec<u8> = (0..c.key_len + c.iv_len).map(|i| i as u8).collect();
            let plain: Vec<u8> = (0..c.block * 3).map(|i| (i * 7) as u8).collect();
            let mut buf = plain.clone();
            let tag = c.seal(&key_iv, &mut buf).unwrap();
            assert_eq!(tag.len(), c.tag_len, "{name}");
            if *name != "none" {
                assert_ne!(buf, plain, "{name}");
            }
            c.open(&key_iv, &mut buf, &tag).unwrap();
            assert_eq!(buf, plain, "{name}");
            if c.tag_len > 0 {
                let mut bad = tag.clone();
                bad[0] ^= 1;
                c.seal(&key_iv, &mut buf).unwrap();
                assert!(c.open(&key_iv, &mut buf, &bad).is_err(), "{name}");
            }
        }
        assert!(KeyCipher::by_name(b"blowfish-cbc").is_none());
    }
}
