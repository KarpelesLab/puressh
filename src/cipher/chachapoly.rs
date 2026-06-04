//! `chacha20-poly1305@openssh.com`.
//!
//! The 64-byte key from KEX is split with bytes `0..32` as the payload key
//! (also used to derive the per-packet Poly1305 one-time key) and bytes
//! `32..64` as the length-field key — the convention from OpenSSH's
//! `PROTOCOL.chacha20poly1305`. For each packet the nonce is the 64-bit
//! sequence number encoded big-endian and zero-padded to the 12-byte RFC 8439
//! ChaCha20 nonce. The Poly1305 tag covers the encrypted length followed by
//! the encrypted payload, with no AAD padding and no length trailer.

use purecrypto::cipher::{ChaCha20, Poly1305};
use purecrypto::ct::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::error::{Error, Result};

#[derive(Clone)]
pub struct ChaChaPoly {
    payload_key: ChaCha20,
    length_key: ChaCha20,
}

impl ChaChaPoly {
    pub(crate) fn new(key: &[u8]) -> Result<Self> {
        if key.len() != 64 {
            return Err(Error::Format("chacha20-poly1305 key len"));
        }
        // Wrap the locally-materialised K_2 (payload) and K_1 (length-field)
        // keys in `Zeroizing` so the 32-byte ChaCha20 raw key bytes are wiped
        // from the caller's stack frame after `ChaCha20::new` has folded them
        // into the upstream cipher state. The cipher state itself is owned by
        // `purecrypto::cipher::ChaCha20` and not zeroized by us.
        let mut k2: Zeroizing<[u8; 32]> = Zeroizing::new([0u8; 32]);
        let mut k1: Zeroizing<[u8; 32]> = Zeroizing::new([0u8; 32]);
        k2.copy_from_slice(&key[..32]);
        k1.copy_from_slice(&key[32..]);
        Ok(ChaChaPoly {
            payload_key: ChaCha20::new(&k2),
            length_key: ChaCha20::new(&k1),
        })
    }

    fn nonce(seq: u64) -> [u8; 12] {
        let mut n = [0u8; 12];
        n[4..].copy_from_slice(&seq.to_be_bytes());
        n
    }

    /// XORs the length-field keystream into `buf`. The same call serves
    /// encrypt and decrypt.
    pub(crate) fn xor_length(&self, seq: u64, buf: &mut [u8]) {
        let n = Self::nonce(seq);
        self.length_key.apply_keystream(&n, 0, buf);
    }

    /// XORs the payload keystream into `buf`, starting at block counter 1.
    /// Counter 0 is reserved for the Poly1305 one-time key.
    pub(crate) fn xor_payload(&self, seq: u64, buf: &mut [u8]) {
        let n = Self::nonce(seq);
        self.payload_key.apply_keystream(&n, 1, buf);
    }

    /// Computes the Poly1305 tag over `enc_len || enc_payload`.
    pub(crate) fn tag(&self, seq: u64, enc_len: &[u8], enc_payload: &[u8]) -> [u8; 16] {
        let n = Self::nonce(seq);
        let block0 = self.payload_key.block(&n, 0);
        // The Poly1305 one-time key is per-packet but lets a holder forge a
        // tag for that packet, so wipe the locally-materialised copy after
        // it has been folded into the MAC state.
        let mut otk: Zeroizing<[u8; 32]> = Zeroizing::new([0u8; 32]);
        otk.copy_from_slice(&block0[..32]);
        let mut mac = Poly1305::new(&otk);
        mac.update(enc_len);
        mac.update(enc_payload);
        mac.finish()
    }

    pub(crate) fn verify_tag(
        &self,
        seq: u64,
        enc_len: &[u8],
        enc_payload: &[u8],
        tag: &[u8],
    ) -> Result<()> {
        if tag.len() != 16 {
            return Err(Error::Format("chacha20-poly1305 tag len"));
        }
        let expected = self.tag(seq, enc_len, enc_payload);
        if bool::from(expected[..].ct_eq(tag)) {
            Ok(())
        } else {
            Err(Error::BadTag)
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

    // draft-ietf-sshm-chacha20-poly1305 worked example. Note the draft swaps
    // the K_1/K_2 labels from openssh's PROTOCOL.chacha20poly1305 but both
    // agree that bytes 0..32 of the key encrypt the payload and bytes 32..64
    // encrypt the length field. Sequence number is 7.
    //
    // 64-byte key: bytes 0..32 (payload + Poly1305 OTK derivation),
    //              bytes 32..64 (length field).
    //
    // The draft prints them in the wire-encoded "K_1 first, K_2 second" order
    // matching this same byte layout — so we feed the bytes verbatim.
    #[test]
    fn openssh_worked_example() {
        let key = h("8b bf f6 85  5f c1 02 33  8c 37 3e 73  aa c0 c9 14
             f0 76 a9 05  b2 44 4a 32  ee ca ff ea  e2 2b ec c5
             e9 b7 a7 a5  82 5a 82 49  34 6e c1 c2  83 01 cf 39
             45 43 fc 75  69 88 7d 76  e1 68 f3 75  62 ac 07 40");
        let cp = ChaChaPoly::new(&key).unwrap();
        let seq = 7u64;

        // Plaintext length field: 0x00000048 (72 bytes).
        let mut len_buf = [0x00u8, 0x00, 0x00, 0x48];
        cp.xor_length(seq, &mut len_buf);
        assert_eq!(len_buf, [0x2c, 0x3e, 0xcc, 0xe4]);

        let plaintext = h("06 5e 00 00  00 00 00 00  00 38 4c 6f
             72 65 6d 20  69 70 73 75  6d 20 64 6f  6c 6f 72 20
             73 69 74 20  61 6d 65 74  2c 20 63 6f  6e 73 65 63
             74 65 74 75  72 20 61 64  69 70 69 73  69 63 69 6e
             67 20 65 6c  69 74 4e 43  e8 04 dc 6c");
        let mut payload = plaintext.clone();
        cp.xor_payload(seq, &mut payload);
        let expected_ct = h("a5 bc 05 89  5b f0 7a 7b  a9 56 b6 c6  88 29 ac 7c
             83 b7 80 b7  00 0e cd e7  45 af c7 05  bb c3 78 ce
             03 a2 80 23  6b 87 b5 3b  ed 58 39 66  23 02 b1 64
             b6 28 6a 48  cd 1e 09 71  38 e3 cb 90  9b 8b 2b 82
             9d d1 8d 2a  35 ff 82 d9");
        assert_eq!(payload, expected_ct);

        let tag = cp.tag(seq, &len_buf, &payload);
        assert_eq!(
            tag.to_vec(),
            h("95 34 9e 85  5b f0 2c 29  8e f7 75 f2  d1 a7 e8 b8")
        );

        cp.verify_tag(seq, &len_buf, &payload, &tag).unwrap();
        cp.xor_payload(seq, &mut payload);
        assert_eq!(payload, plaintext);
    }

    #[test]
    fn bad_tag_rejected() {
        let key = h("8b bf f6 85  5f c1 02 33  8c 37 3e 73  aa c0 c9 14
             f0 76 a9 05  b2 44 4a 32  ee ca ff ea  e2 2b ec c5
             e9 b7 a7 a5  82 5a 82 49  34 6e c1 c2  83 01 cf 39
             45 43 fc 75  69 88 7d 76  e1 68 f3 75  62 ac 07 40");
        let cp = ChaChaPoly::new(&key).unwrap();
        let len = [0x2c, 0x3e, 0xcc, 0xe4];
        let payload = [0u8; 16];
        let bad = [0u8; 16];
        assert!(matches!(
            cp.verify_tag(7, &len, &payload, &bad),
            Err(Error::BadTag)
        ));
    }

    #[test]
    fn bad_key_length_is_format_error() {
        assert!(matches!(ChaChaPoly::new(&[0u8; 63]), Err(Error::Format(_))));
    }
}
