//! `aes*-cbc` and `3des-cbc` (RFC 4253 §6.3):
//! legacy non-AEAD block ciphers paired with a separate MAC. OpenSSH still
//! implements them but offers none by default; they are here for old
//! servers and devices that offer nothing else, when configured.

use purecrypto::cipher::{Aes128, Aes192, Aes256, Cbc, Cbc64, TdesEde3};

use crate::error::{Error, Result};

/// One direction's CBC state (the chain carries over between packets, as
/// RFC 4253 specifies).
pub enum CbcState {
    Aes128(Cbc<Aes128>),
    Aes192(Cbc<Aes192>),
    Aes256(Cbc<Aes256>),
    Tdes(Cbc64<TdesEde3>),
}

fn arr<const N: usize>(b: &[u8], what: &'static str) -> Result<[u8; N]> {
    b.try_into().map_err(|_| Error::Format(what))
}

impl CbcState {
    pub(crate) fn new(name: &str, key: &[u8], iv: &[u8]) -> Result<Self> {
        Ok(match name {
            "aes128-cbc" => CbcState::Aes128(Cbc::new(
                Aes128::new(&arr(key, "aes128-cbc key len")?),
                &arr(iv, "aes-cbc iv len")?,
            )),
            "aes192-cbc" => CbcState::Aes192(Cbc::new(
                Aes192::new(&arr(key, "aes192-cbc key len")?),
                &arr(iv, "aes-cbc iv len")?,
            )),
            "aes256-cbc" => CbcState::Aes256(Cbc::new(
                Aes256::new(&arr(key, "aes256-cbc key len")?),
                &arr(iv, "aes-cbc iv len")?,
            )),
            "3des-cbc" => CbcState::Tdes(Cbc64::new(
                TdesEde3::new(&arr(key, "3des-cbc key len")?),
                &arr(iv, "3des-cbc iv len")?,
            )),
            _ => return Err(Error::Unsupported("cipher")),
        })
    }

    pub(crate) fn block_size(&self) -> usize {
        match self {
            CbcState::Tdes(_) => 8,
            _ => 16,
        }
    }

    pub(crate) fn encrypt(&mut self, buf: &mut [u8]) -> Result<()> {
        let r = match self {
            CbcState::Aes128(c) => c.encrypt(buf),
            CbcState::Aes192(c) => c.encrypt(buf),
            CbcState::Aes256(c) => c.encrypt(buf),
            CbcState::Tdes(c) => c.encrypt(buf),
        };
        r.map_err(|_| Error::Protocol("CBC input not block-aligned"))
    }

    pub(crate) fn decrypt(&mut self, buf: &mut [u8]) -> Result<()> {
        let r = match self {
            CbcState::Aes128(c) => c.decrypt(buf),
            CbcState::Aes192(c) => c.decrypt(buf),
            CbcState::Aes256(c) => c.decrypt(buf),
            CbcState::Tdes(c) => c.decrypt(buf),
        };
        r.map_err(|_| Error::Protocol("CBC input not block-aligned"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(s: &str) -> Vec<u8> {
        let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
        hex::decode(s).unwrap()
    }

    // NIST SP 800-38A F.2.1 / F.2.2 CBC-AES128, fed in two calls to show the
    // chain carries over.
    #[test]
    fn aes128_cbc_nist() {
        let key = h("2b7e151628aed2a6abf7158809cf4f3c");
        let iv = h("000102030405060708090a0b0c0d0e0f");
        let plain = h("6bc1bee22e409f96e93d7e117393172a ae2d8a571e03ac9c9eb76fac45af8e51");
        let want = h("7649abac8119b246cee98e9b12e9197d 5086cb9b507219ee95db113a917678b2");
        let mut buf = plain.clone();
        let mut c = CbcState::new("aes128-cbc", &key, &iv).unwrap();
        c.encrypt(&mut buf[..16]).unwrap();
        c.encrypt(&mut buf[16..]).unwrap();
        assert_eq!(buf, want);
        let mut d = CbcState::new("aes128-cbc", &key, &iv).unwrap();
        d.decrypt(&mut buf[..16]).unwrap();
        d.decrypt(&mut buf[16..]).unwrap();
        assert_eq!(buf, plain);
    }

    #[test]
    fn tdes_round_trip_and_alignment() {
        let mut c = CbcState::new("3des-cbc", &[7u8; 24], &[1u8; 8]).unwrap();
        let mut d = CbcState::new("3des-cbc", &[7u8; 24], &[1u8; 8]).unwrap();
        assert_eq!(c.block_size(), 8);
        let mut buf = *b"sixteen bytes!!!";
        c.encrypt(&mut buf).unwrap();
        assert_ne!(&buf, b"sixteen bytes!!!");
        d.decrypt(&mut buf).unwrap();
        assert_eq!(&buf, b"sixteen bytes!!!");
        assert!(c.encrypt(&mut [0u8; 12]).is_err());
    }
}
