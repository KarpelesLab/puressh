//! `aes*-ctr` (RFC 4344) — non-AEAD streaming ciphers paired with a separate MAC.

use purecrypto::cipher::{Aes128, Aes192, Aes256, Ctr};

use crate::error::{Error, Result};

// No `Clone`: each variant holds a live CTR keystream position; cloning would
// resume the same counter twice and reuse keystream under the same key.
pub enum AesCtr {
    Aes128(Ctr<Aes128>),
    Aes192(Ctr<Aes192>),
    Aes256(Ctr<Aes256>),
}

impl AesCtr {
    pub(crate) fn new_128(key: &[u8], iv: &[u8]) -> Result<Self> {
        let k: &[u8; 16] = key
            .try_into()
            .map_err(|_| Error::Format("aes128-ctr key len"))?;
        let i: &[u8; 16] = iv.try_into().map_err(|_| Error::Format("aes-ctr iv len"))?;
        Ok(AesCtr::Aes128(Ctr::new(Aes128::new(k), i)))
    }

    pub(crate) fn new_192(key: &[u8], iv: &[u8]) -> Result<Self> {
        let k: &[u8; 24] = key
            .try_into()
            .map_err(|_| Error::Format("aes192-ctr key len"))?;
        let i: &[u8; 16] = iv.try_into().map_err(|_| Error::Format("aes-ctr iv len"))?;
        Ok(AesCtr::Aes192(Ctr::new(Aes192::new(k), i)))
    }

    pub(crate) fn new_256(key: &[u8], iv: &[u8]) -> Result<Self> {
        let k: &[u8; 32] = key
            .try_into()
            .map_err(|_| Error::Format("aes256-ctr key len"))?;
        let i: &[u8; 16] = iv.try_into().map_err(|_| Error::Format("aes-ctr iv len"))?;
        Ok(AesCtr::Aes256(Ctr::new(Aes256::new(k), i)))
    }

    pub(crate) fn apply_keystream(&mut self, buf: &mut [u8]) {
        match self {
            AesCtr::Aes128(c) => c.apply_keystream(buf),
            AesCtr::Aes192(c) => c.apply_keystream(buf),
            AesCtr::Aes256(c) => c.apply_keystream(buf),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(s: &str) -> Vec<u8> {
        let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
        hex::decode(s).unwrap()
    }

    // NIST SP 800-38A F.5.1 CTR-AES128.
    #[test]
    fn aes128_ctr_nist() {
        let key = h("2b7e151628aed2a6abf7158809cf4f3c");
        let iv = h("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
        let plaintext = h("6bc1bee22e409f96e93d7e117393172a\
             ae2d8a571e03ac9c9eb76fac45af8e51\
             30c81c46a35ce411e5fbc1191a0a52ef\
             f69f2445df4f9b17ad2b417be66c3710");
        let expected = h("874d6191b620e3261bef6864990db6ce\
             9806f66b7970fdff8617187bb9fffdff\
             5ae4df3edbd5d35e5b4f09020db03eab\
             1e031dda2fbe03d1792170a0f3009cee");

        let mut buf = plaintext.clone();
        let mut c = AesCtr::new_128(&key, &iv).unwrap();
        c.apply_keystream(&mut buf);
        assert_eq!(buf, expected);

        let mut c2 = AesCtr::new_128(&key, &iv).unwrap();
        c2.apply_keystream(&mut buf);
        assert_eq!(buf, plaintext);
    }

    // NIST SP 800-38A F.5.5 CTR-AES256.
    #[test]
    fn aes256_ctr_nist() {
        let key = h("603deb1015ca71be2b73aef0857d7781\
             1f352c073b6108d72d9810a30914dff4");
        let iv = h("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
        let plaintext = h("6bc1bee22e409f96e93d7e117393172a\
             ae2d8a571e03ac9c9eb76fac45af8e51\
             30c81c46a35ce411e5fbc1191a0a52ef\
             f69f2445df4f9b17ad2b417be66c3710");
        let expected = h("601ec313775789a5b7a7f504bbf3d228\
             f443e3ca4d62b59aca84e990cacaf5c5\
             2b0930daa23de94ce87017ba2d84988d\
             dfc9c58db67aada613c2dd08457941a6");

        let mut buf = plaintext;
        let mut c = AesCtr::new_256(&key, &iv).unwrap();
        c.apply_keystream(&mut buf);
        assert_eq!(buf, expected);
    }

    #[test]
    fn streaming_matches_oneshot() {
        let key = h("2b7e151628aed2a6abf7158809cf4f3c");
        let iv = h("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
        let plaintext = h("6bc1bee22e409f96e93d7e117393172a\
             ae2d8a571e03ac9c9eb76fac45af8e51\
             30c81c46a35ce411e5fbc1191a0a52ef\
             f69f2445df4f9b17ad2b417be66c3710");

        let mut oneshot = plaintext.clone();
        AesCtr::new_128(&key, &iv)
            .unwrap()
            .apply_keystream(&mut oneshot);

        let mut chunked = plaintext;
        let mut c = AesCtr::new_128(&key, &iv).unwrap();
        let mut start = 0;
        for len in [1usize, 14, 1, 30, 18] {
            c.apply_keystream(&mut chunked[start..start + len]);
            start += len;
        }
        assert_eq!(chunked, oneshot);
    }

    #[test]
    fn bad_key_length_is_format_error() {
        let iv = [0u8; 16];
        assert!(matches!(
            AesCtr::new_128(&[0u8; 15], &iv),
            Err(Error::Format(_))
        ));
        assert!(matches!(
            AesCtr::new_256(&[0u8; 31], &iv),
            Err(Error::Format(_))
        ));
    }
}
