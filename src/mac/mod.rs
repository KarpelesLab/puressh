//! Message Authentication Codes over [`purecrypto::hash`] (HMAC family).
//!
//! SSH MACs use either Encrypt-and-MAC (legacy) or Encrypt-then-MAC (`-etm@openssh.com`).
//! AEAD ciphers (GCM, ChaCha20-Poly1305) provide their own integrity and ignore
//! the negotiated MAC.
//!
//! This module exposes:
//!
//! - [`MacSpec`] — purely descriptive metadata (name, key/tag geometry, EtM flag).
//! - [`SshMac`]  — the runtime interface used by the packet codec to compute and
//!   verify tags. Implementations wrap [`purecrypto::hash::Hmac`] keyed for the
//!   life of the session.
//! - [`mac_by_name`] — factory turning a negotiated SSH name plus a session key
//!   into a boxed [`SshMac`].
//!
//! The SSH MAC input is `seq_u32_be || packet_bytes`; whether `packet_bytes`
//! refers to the encrypted or the plaintext packet depends on the suite's EtM
//! flag, but that selection is the codec's responsibility — this module simply
//! consumes whatever bytes the caller hands it.

use crate::error::{Error, Result};

#[cfg(feature = "alloc")]
use alloc::boxed::Box;

use purecrypto::hash::{HmacSha256, HmacSha512};

/// SSH-side identifier and key/tag geometry for a MAC.
#[derive(Debug, Clone, Copy)]
pub struct MacSpec {
    /// On-the-wire SSH name.
    pub name: &'static str,
    /// Underlying hash output size in bytes (= HMAC key length).
    pub key_len: usize,
    /// Tag length appended to each packet, in bytes.
    pub tag_len: usize,
    /// Encrypt-then-MAC (true for `*-etm@openssh.com`).
    pub etm: bool,
}

/// Catalogue of MACs this build supports.
pub const ALL: &[MacSpec] = &[
    MacSpec {
        name: "hmac-sha2-256-etm@openssh.com",
        key_len: 32,
        tag_len: 32,
        etm: true,
    },
    MacSpec {
        name: "hmac-sha2-512-etm@openssh.com",
        key_len: 64,
        tag_len: 64,
        etm: true,
    },
    MacSpec {
        name: "hmac-sha2-256",
        key_len: 32,
        tag_len: 32,
        etm: false,
    },
    MacSpec {
        name: "hmac-sha2-512",
        key_len: 64,
        tag_len: 64,
        etm: false,
    },
];

/// Look up a [`MacSpec`] by SSH name.
pub fn by_name(name: &str) -> Option<&'static MacSpec> {
    ALL.iter().find(|m| m.name == name)
}

/// A keyed MAC instance bound to one direction of an SSH session.
///
/// The MAC primitive itself is identical between EtM and non-EtM suites; the
/// only behavioural difference visible here is what [`etm`](SshMac::etm)
/// reports, so the codec knows when to feed pre- vs post-encryption bytes.
pub trait SshMac {
    /// Length of tags produced by [`compute`](SshMac::compute) and expected
    /// by [`verify`](SshMac::verify), in bytes.
    fn tag_len(&self) -> usize;

    /// `true` if this suite is an Encrypt-then-MAC variant.
    fn etm(&self) -> bool;

    /// Computes the tag over `seq_u32_be || msg` and writes exactly
    /// [`tag_len`](SshMac::tag_len) bytes into `out`.
    fn compute(&self, seq: u32, msg: &[u8], out: &mut [u8]) -> Result<()>;

    /// Verifies `tag` against `seq_u32_be || msg` in constant time.
    fn verify(&self, seq: u32, msg: &[u8], tag: &[u8]) -> Result<()>;
}

struct HmacSha256Mac {
    key: [u8; 32],
    etm: bool,
}

impl SshMac for HmacSha256Mac {
    fn tag_len(&self) -> usize {
        32
    }

    fn etm(&self) -> bool {
        self.etm
    }

    fn compute(&self, seq: u32, msg: &[u8], out: &mut [u8]) -> Result<()> {
        if out.len() != 32 {
            return Err(Error::Crypto("hmac-sha2-256: tag buffer must be 32 bytes"));
        }
        let mut h = HmacSha256::new(&self.key);
        h.update(&seq.to_be_bytes());
        h.update(msg);
        let tag = h.finalize();
        out.copy_from_slice(tag.as_ref());
        Ok(())
    }

    fn verify(&self, seq: u32, msg: &[u8], tag: &[u8]) -> Result<()> {
        if tag.len() != 32 {
            return Err(Error::BadMac);
        }
        let mut h = HmacSha256::new(&self.key);
        h.update(&seq.to_be_bytes());
        h.update(msg);
        if bool::from(h.verify(tag)) {
            Ok(())
        } else {
            Err(Error::BadMac)
        }
    }
}

struct HmacSha512Mac {
    key: [u8; 64],
    etm: bool,
}

impl SshMac for HmacSha512Mac {
    fn tag_len(&self) -> usize {
        64
    }

    fn etm(&self) -> bool {
        self.etm
    }

    fn compute(&self, seq: u32, msg: &[u8], out: &mut [u8]) -> Result<()> {
        if out.len() != 64 {
            return Err(Error::Crypto("hmac-sha2-512: tag buffer must be 64 bytes"));
        }
        let mut h = HmacSha512::new(&self.key);
        h.update(&seq.to_be_bytes());
        h.update(msg);
        let tag = h.finalize();
        out.copy_from_slice(tag.as_ref());
        Ok(())
    }

    fn verify(&self, seq: u32, msg: &[u8], tag: &[u8]) -> Result<()> {
        if tag.len() != 64 {
            return Err(Error::BadMac);
        }
        let mut h = HmacSha512::new(&self.key);
        h.update(&seq.to_be_bytes());
        h.update(msg);
        if bool::from(h.verify(tag)) {
            Ok(())
        } else {
            Err(Error::BadMac)
        }
    }
}

/// Construct an [`SshMac`] for the negotiated `name`, keyed with `key`.
///
/// Returns `None` if the name is unknown or if `key.len()` does not match
/// the suite's [`MacSpec::key_len`]; this rejects accidentally mis-sized
/// keying material before any tag is produced.
#[cfg(feature = "alloc")]
pub fn mac_by_name(name: &str, key: &[u8]) -> Option<Box<dyn SshMac + Send + Sync>> {
    match name {
        "hmac-sha2-256" | "hmac-sha2-256-etm@openssh.com" => {
            if key.len() != 32 {
                return None;
            }
            let mut k = [0u8; 32];
            k.copy_from_slice(key);
            Some(Box::new(HmacSha256Mac {
                key: k,
                etm: name == "hmac-sha2-256-etm@openssh.com",
            }))
        }
        "hmac-sha2-512" | "hmac-sha2-512-etm@openssh.com" => {
            if key.len() != 64 {
                return None;
            }
            let mut k = [0u8; 64];
            k.copy_from_slice(key);
            Some(Box::new(HmacSha512Mac {
                key: k,
                etm: name == "hmac-sha2-512-etm@openssh.com",
            }))
        }
        _ => None,
    }
}

#[cfg(all(test, feature = "alloc"))]
mod tests {
    use super::*;

    fn unhex(s: &str) -> alloc::vec::Vec<u8> {
        let s: alloc::string::String = s.chars().filter(|c| !c.is_whitespace()).collect();
        hex::decode(s).expect("valid hex")
    }

    fn hmac_sha256_tag(key: &[u8], data: &[u8]) -> [u8; 32] {
        let mut h = HmacSha256::new(key);
        h.update(data);
        let t = h.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(t.as_ref());
        out
    }

    fn hmac_sha512_tag(key: &[u8], data: &[u8]) -> [u8; 64] {
        let mut h = HmacSha512::new(key);
        h.update(data);
        let t = h.finalize();
        let mut out = [0u8; 64];
        out.copy_from_slice(t.as_ref());
        out
    }

    #[test]
    fn rfc4231_tc1_sha256() {
        let key = [0x0bu8; 20];
        let data = b"Hi There";
        let expected = unhex(
            "b0344c61d8db38535ca8afceaf0bf12b\
             881dc200c9833da726e9376c2e32cff7",
        );
        assert_eq!(&hmac_sha256_tag(&key, data)[..], &expected[..]);
    }

    #[test]
    fn rfc4231_tc1_sha512() {
        let key = [0x0bu8; 20];
        let data = b"Hi There";
        let expected = unhex(
            "87aa7cdea5ef619d4ff0b4241a1d6cb0\
             2379f4e2ce4ec2787ad0b30545e17cde\
             daa833b7d6b8a702038b274eaea3f4e4\
             be9d914eeb61f1702e696c203a126854",
        );
        assert_eq!(&hmac_sha512_tag(&key, data)[..], &expected[..]);
    }

    #[test]
    fn rfc4231_tc2_sha256() {
        let key = b"Jefe";
        let data = b"what do ya want for nothing?";
        let expected = unhex(
            "5bdcc146bf60754e6a042426089575c7\
             5a003f089d2739839dec58b964ec3843",
        );
        assert_eq!(&hmac_sha256_tag(key, data)[..], &expected[..]);
    }

    #[test]
    fn rfc4231_tc2_sha512() {
        let key = b"Jefe";
        let data = b"what do ya want for nothing?";
        let expected = unhex(
            "164b7a7bfcf819e2e395fbe73b56e0a3\
             87bd64222e831fd610270cd7ea250554\
             9758bf75c05a994a6d034f65f8f0e6fd\
             caeab1a34d4a6b4b636e070a38bce737",
        );
        assert_eq!(&hmac_sha512_tag(key, data)[..], &expected[..]);
    }

    #[test]
    fn factory_unknown_name() {
        assert!(mac_by_name("hmac-md5", &[0u8; 16]).is_none());
    }

    #[test]
    fn factory_wrong_key_len() {
        assert!(mac_by_name("hmac-sha2-256", &[0u8; 31]).is_none());
        assert!(mac_by_name("hmac-sha2-256", &[0u8; 33]).is_none());
        assert!(mac_by_name("hmac-sha2-512", &[0u8; 63]).is_none());
        assert!(mac_by_name("hmac-sha2-512", &[0u8; 65]).is_none());
    }

    #[test]
    fn etm_flag_matches_suite() {
        let m = mac_by_name("hmac-sha2-256", &[0u8; 32]).unwrap();
        assert!(!m.etm());
        assert_eq!(m.tag_len(), 32);

        let m = mac_by_name("hmac-sha2-256-etm@openssh.com", &[0u8; 32]).unwrap();
        assert!(m.etm());
        assert_eq!(m.tag_len(), 32);

        let m = mac_by_name("hmac-sha2-512", &[0u8; 64]).unwrap();
        assert!(!m.etm());
        assert_eq!(m.tag_len(), 64);

        let m = mac_by_name("hmac-sha2-512-etm@openssh.com", &[0u8; 64]).unwrap();
        assert!(m.etm());
        assert_eq!(m.tag_len(), 64);
    }

    #[test]
    fn ssh_mac_includes_seq_prefix_sha256() {
        let key = [0x42u8; 32];
        let seq: u32 = 0x01020304;
        let msg = b"the quick brown fox jumps over the lazy dog";

        let mac = mac_by_name("hmac-sha2-256", &key).unwrap();
        let mut got = [0u8; 32];
        mac.compute(seq, msg, &mut got).unwrap();

        let mut framed = alloc::vec::Vec::new();
        framed.extend_from_slice(&seq.to_be_bytes());
        framed.extend_from_slice(msg);
        let expected = hmac_sha256_tag(&key, &framed);

        assert_eq!(&got[..], &expected[..]);

        mac.verify(seq, msg, &got).unwrap();

        let mut bad = got;
        bad[0] ^= 1;
        assert!(matches!(mac.verify(seq, msg, &bad), Err(Error::BadMac)));

        assert!(matches!(
            mac.verify(seq.wrapping_add(1), msg, &got),
            Err(Error::BadMac)
        ));

        assert!(matches!(
            mac.verify(seq, msg, &got[..31]),
            Err(Error::BadMac)
        ));
    }

    #[test]
    fn ssh_mac_includes_seq_prefix_sha512() {
        let key = [0x7eu8; 64];
        let seq: u32 = 0xdeadbeef;
        let msg = b"another packet payload";

        let mac = mac_by_name("hmac-sha2-512-etm@openssh.com", &key).unwrap();
        assert!(mac.etm());

        let mut got = [0u8; 64];
        mac.compute(seq, msg, &mut got).unwrap();

        let mut framed = alloc::vec::Vec::new();
        framed.extend_from_slice(&seq.to_be_bytes());
        framed.extend_from_slice(msg);
        let expected = hmac_sha512_tag(&key, &framed);
        assert_eq!(&got[..], &expected[..]);

        mac.verify(seq, msg, &got).unwrap();

        let mut bad = got;
        bad[63] ^= 0x80;
        assert!(matches!(mac.verify(seq, msg, &bad), Err(Error::BadMac)));
    }

    #[test]
    fn compute_rejects_wrong_out_len() {
        let mac = mac_by_name("hmac-sha2-256", &[0u8; 32]).unwrap();
        let mut too_short = [0u8; 31];
        assert!(mac.compute(0, b"", &mut too_short).is_err());
        let mut too_long = [0u8; 33];
        assert!(mac.compute(0, b"", &mut too_long).is_err());

        let mac = mac_by_name("hmac-sha2-512", &[0u8; 64]).unwrap();
        let mut too_short = [0u8; 63];
        assert!(mac.compute(0, b"", &mut too_short).is_err());
    }
}
