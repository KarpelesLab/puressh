//! `aes*-gcm@openssh.com` (RFC 5647) — AEAD with implicit 12-byte nonce.
//!
//! The 12-byte IV from key derivation is split into a 4-byte fixed prefix and
//! an 8-byte invocation counter. The invocation counter is treated as a 64-bit
//! big-endian integer and incremented by one after every packet. The packet
//! length field is transmitted in cleartext but bound to the tag as AAD.

use purecrypto::cipher::{Aes128, Aes256};
use purecrypto::cipher::{Aes128Gcm, Aes256Gcm, Gcm, TagMismatch};

use crate::error::{Error, Result};

#[derive(Clone)]
pub(crate) enum AesGcm {
    Aes128(Gcm<Aes128>),
    Aes256(Gcm<Aes256>),
}

#[derive(Clone)]
pub struct GcmState {
    cipher: AesGcm,
    fixed: [u8; 4],
    invocation: u64,
}

impl GcmState {
    pub(crate) fn new_128(key: &[u8], iv: &[u8]) -> Result<Self> {
        let k: &[u8; 16] = key
            .try_into()
            .map_err(|_| Error::Format("aes128-gcm key len"))?;
        let (fixed, invocation) = split_iv(iv)?;
        Ok(GcmState {
            cipher: AesGcm::Aes128(Aes128Gcm::new(Aes128::new(k))),
            fixed,
            invocation,
        })
    }

    pub(crate) fn new_256(key: &[u8], iv: &[u8]) -> Result<Self> {
        let k: &[u8; 32] = key
            .try_into()
            .map_err(|_| Error::Format("aes256-gcm key len"))?;
        let (fixed, invocation) = split_iv(iv)?;
        Ok(GcmState {
            cipher: AesGcm::Aes256(Aes256Gcm::new(Aes256::new(k))),
            fixed,
            invocation,
        })
    }

    fn nonce(&self) -> [u8; 12] {
        let mut n = [0u8; 12];
        n[..4].copy_from_slice(&self.fixed);
        n[4..].copy_from_slice(&self.invocation.to_be_bytes());
        n
    }

    /// Advance the 64-bit invocation counter, hard-failing on overflow.
    ///
    /// RFC 5647 §7.1 mandates a rekey before this counter can wrap; a wrap
    /// would reuse the (fixed || invocation) nonce under the same key, which
    /// is catastrophic for AES-GCM (trivial forgery plus plaintext recovery
    /// from any two ciphertexts sharing a nonce). The higher-level rekey
    /// policy in `src/transport/rekey.rs` is the primary defence, but we
    /// refuse to ever emit the wrapped nonce here as defence-in-depth so a
    /// bug or misconfiguration in that layer cannot translate into a nonce
    /// reuse on the wire.
    fn step(&mut self) -> Result<()> {
        self.invocation = self
            .invocation
            .checked_add(1)
            .ok_or(Error::Crypto("aes-gcm invocation counter exhausted"))?;
        Ok(())
    }

    /// Seals `payload` in place and returns the 16-byte tag. `aad` is the
    /// 4-byte unencrypted length field.
    pub(crate) fn seal(&mut self, aad: &[u8], payload: &mut [u8]) -> Result<[u8; 16]> {
        let nonce = self.nonce();
        let tag = match &self.cipher {
            AesGcm::Aes128(g) => g.encrypt(&nonce, aad, payload),
            AesGcm::Aes256(g) => g.encrypt(&nonce, aad, payload),
        };
        self.step()?;
        Ok(tag)
    }

    /// Verifies `tag` and decrypts `payload` in place on success. The buffer
    /// is left as ciphertext on tag mismatch.
    pub(crate) fn open(&mut self, aad: &[u8], payload: &mut [u8], tag: &[u8]) -> Result<()> {
        let t: &[u8; 16] = tag
            .try_into()
            .map_err(|_| Error::Format("aes-gcm tag len"))?;
        let nonce = self.nonce();
        let r = match &self.cipher {
            AesGcm::Aes128(g) => g.decrypt(&nonce, aad, payload, t),
            AesGcm::Aes256(g) => g.decrypt(&nonce, aad, payload, t),
        };
        match r {
            Ok(()) => {
                self.step()?;
                Ok(())
            }
            Err(TagMismatch) => Err(Error::BadTag),
        }
    }
}

fn split_iv(iv: &[u8]) -> Result<([u8; 4], u64)> {
    if iv.len() != 12 {
        return Err(Error::Format("aes-gcm iv len"));
    }
    let mut fixed = [0u8; 4];
    fixed.copy_from_slice(&iv[..4]);
    let mut ic = [0u8; 8];
    ic.copy_from_slice(&iv[4..]);
    Ok((fixed, u64::from_be_bytes(ic)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(s: &str) -> Vec<u8> {
        let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
        hex::decode(s).unwrap()
    }

    // McGrew & Viega AES-128-GCM test case 3 — verify our adapter agrees with
    // the underlying purecrypto Gcm at the chosen nonce.
    #[test]
    fn aes128_gcm_tc3() {
        let key = h("feffe9928665731c6d6a8f9467308308");
        let mut iv = [0u8; 12];
        iv.copy_from_slice(&h("cafebabefacedbaddecaf888"));

        let mut g = GcmState::new_128(&key, &iv).unwrap();
        let mut buf = h(
            "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72\
             1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255",
        );
        let tag = g.seal(&[], &mut buf).unwrap();
        assert_eq!(
            buf,
            h(
                "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e\
                 21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091473f5985"
            )
        );
        assert_eq!(tag.to_vec(), h("4d5c2af327cd64a62cf35abd2ba6fab4"));
    }

    #[test]
    fn roundtrip_with_aad_increments_counter() {
        let key = h("feffe9928665731c6d6a8f9467308308");
        let iv = h("cafebabefacedbaddecaf888");
        let mut enc = GcmState::new_128(&key, &iv).unwrap();
        let mut dec = GcmState::new_128(&key, &iv).unwrap();

        for pkt in 0..3u8 {
            let aad = [0, 0, 0, 32u8];
            let plain = [pkt; 32];
            let mut buf = plain;
            let tag = enc.seal(&aad, &mut buf).unwrap();
            dec.open(&aad, &mut buf, &tag).unwrap();
            assert_eq!(buf, plain);
        }
    }

    #[test]
    fn bad_tag_rejected_and_counter_held() {
        let key = h("feffe9928665731c6d6a8f9467308308");
        let iv = h("cafebabefacedbaddecaf888");
        let mut enc = GcmState::new_128(&key, &iv).unwrap();
        let mut dec = GcmState::new_128(&key, &iv).unwrap();

        let aad = [0, 0, 0, 16u8];
        let plain = [0xaau8; 16];
        let mut buf = plain;
        let tag = enc.seal(&aad, &mut buf).unwrap();
        let mut bad = tag;
        bad[0] ^= 1;
        assert!(matches!(dec.open(&aad, &mut buf, &bad), Err(Error::BadTag)));
        // Counter must not have advanced — opening with the real tag still works.
        dec.open(&aad, &mut buf, &tag).unwrap();
        assert_eq!(buf, plain);
    }

    #[test]
    fn invocation_counter_wraps_into_nonce() {
        let key = [0u8; 16];
        let mut iv = [0u8; 12];
        iv[..4].copy_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
        iv[4..].copy_from_slice(&u64::MAX.to_be_bytes());
        let g = GcmState::new_128(&key, &iv).unwrap();
        let n = g.nonce();
        assert_eq!(&n[..4], &[0xde, 0xad, 0xbe, 0xef]);
        assert_eq!(&n[4..], &u64::MAX.to_be_bytes());
    }
}
