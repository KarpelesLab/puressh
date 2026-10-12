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

use purecrypto::hash::{Digest, Hmac, Md5, Sha1, Sha256, Sha512};
#[cfg(test)]
use purecrypto::hash::{HmacSha256, HmacSha512};
use purecrypto::mac::{Umac64, Umac128};

/// SSH-side identifier and key/tag geometry for a MAC.
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub struct MacSpec {
    /// On-the-wire SSH name.
    pub name: &'static str,
    /// MAC key length in bytes (the HMAC hash's output size; 16 for UMAC).
    pub key_len: usize,
    /// Tag length appended to each packet, in bytes.
    pub tag_len: usize,
    /// Encrypt-then-MAC (true for `*-etm@openssh.com`).
    pub etm: bool,
}

const fn spec(name: &'static str, key_len: usize, tag_len: usize, etm: bool) -> MacSpec {
    MacSpec {
        name,
        key_len,
        tag_len,
        etm,
    }
}

/// Catalogue of MACs this build supports: OpenSSH's (its defaults first, in
/// its order, then the ones it only uses when configured).
pub const ALL: &[MacSpec] = &[
    spec("umac-64-etm@openssh.com", 16, 8, true),
    spec("umac-128-etm@openssh.com", 16, 16, true),
    spec("hmac-sha2-256-etm@openssh.com", 32, 32, true),
    spec("hmac-sha2-512-etm@openssh.com", 64, 64, true),
    spec("hmac-sha1-etm@openssh.com", 20, 20, true),
    spec("umac-64@openssh.com", 16, 8, false),
    spec("umac-128@openssh.com", 16, 16, false),
    spec("hmac-sha2-256", 32, 32, false),
    spec("hmac-sha2-512", 64, 64, false),
    spec("hmac-sha1", 20, 20, false),
    spec("hmac-sha1-96-etm@openssh.com", 20, 12, true),
    spec("hmac-md5-etm@openssh.com", 16, 16, true),
    spec("hmac-md5-96-etm@openssh.com", 16, 12, true),
    spec("hmac-sha1-96", 20, 12, false),
    spec("hmac-md5", 16, 16, false),
    spec("hmac-md5-96", 16, 12, false),
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

/// Constant-time equality of two equal-length byte strings.
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// HMAC over `seq_u32_be || msg` (RFC 4253 §6.4), possibly truncated (the
/// `-96` suites). The keyed state is computed once and cloned per packet;
/// [`Hmac`] wipes itself on drop.
struct HmacMac<D: Digest> {
    keyed: Hmac<D>,
    tag_len: usize,
    etm: bool,
}

impl<D: Digest> HmacMac<D> {
    fn tag(&self, seq: u32, msg: &[u8]) -> D::Output {
        let mut h = self.keyed.clone();
        h.update(&seq.to_be_bytes());
        h.update(msg);
        h.finalize()
    }
}

impl<D: Digest> SshMac for HmacMac<D> {
    fn tag_len(&self) -> usize {
        self.tag_len
    }

    fn etm(&self) -> bool {
        self.etm
    }

    fn compute(&self, seq: u32, msg: &[u8], out: &mut [u8]) -> Result<()> {
        if out.len() != self.tag_len {
            return Err(Error::Crypto("hmac: tag buffer has the wrong length"));
        }
        out.copy_from_slice(&self.tag(seq, msg).as_ref()[..self.tag_len]);
        Ok(())
    }

    fn verify(&self, seq: u32, msg: &[u8], tag: &[u8]) -> Result<()> {
        if tag.len() == self.tag_len && ct_eq(&self.tag(seq, msg).as_ref()[..self.tag_len], tag) {
            Ok(())
        } else {
            Err(Error::BadMac)
        }
    }
}

/// `umac-64@openssh.com` / `umac-128@openssh.com` (and their EtM forms):
/// UMAC (RFC 4418) over the packet, with the sequence number as the 8-byte
/// big-endian nonce, as OpenSSH's `mac_compute` does.
#[derive(Clone)]
enum Umac {
    U64(Box<Umac64>),
    U128(Box<Umac128>),
}

struct UmacMac {
    keyed: Umac,
    etm: bool,
}

impl UmacMac {
    fn tag(&self, seq: u32, msg: &[u8], out: &mut [u8]) {
        let nonce = u64::from(seq).to_be_bytes();
        match self.keyed.clone() {
            Umac::U64(mut u) => {
                u.update(msg);
                out.copy_from_slice(&u.finalize(&nonce));
            }
            Umac::U128(mut u) => {
                u.update(msg);
                out.copy_from_slice(&u.finalize(&nonce));
            }
        }
    }
}

impl SshMac for UmacMac {
    fn tag_len(&self) -> usize {
        match self.keyed {
            Umac::U64(_) => 8,
            Umac::U128(_) => 16,
        }
    }

    fn etm(&self) -> bool {
        self.etm
    }

    fn compute(&self, seq: u32, msg: &[u8], out: &mut [u8]) -> Result<()> {
        if out.len() != self.tag_len() {
            return Err(Error::Crypto("umac: tag buffer has the wrong length"));
        }
        self.tag(seq, msg, out);
        Ok(())
    }

    fn verify(&self, seq: u32, msg: &[u8], tag: &[u8]) -> Result<()> {
        let mut want = [0u8; 16];
        let want = &mut want[..self.tag_len()];
        self.tag(seq, msg, want);
        if ct_eq(want, tag) {
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
    let spec = by_name(name)?;
    if key.len() != spec.key_len {
        return None;
    }
    let (tag_len, etm) = (spec.tag_len, spec.etm);
    let base = name.strip_suffix("-etm@openssh.com").unwrap_or(name);
    Some(match base {
        "hmac-sha2-256" => Box::new(HmacMac::<Sha256> {
            keyed: Hmac::new(key),
            tag_len,
            etm,
        }),
        "hmac-sha2-512" => Box::new(HmacMac::<Sha512> {
            keyed: Hmac::new(key),
            tag_len,
            etm,
        }),
        "hmac-sha1" | "hmac-sha1-96" => Box::new(HmacMac::<Sha1> {
            keyed: Hmac::new(key),
            tag_len,
            etm,
        }),
        "hmac-md5" | "hmac-md5-96" => Box::new(HmacMac::<Md5> {
            keyed: Hmac::new(key),
            tag_len,
            etm,
        }),
        "umac-64" | "umac-64@openssh.com" | "umac-128" | "umac-128@openssh.com" => {
            let k: &[u8; 16] = key.try_into().ok()?;
            let keyed = if base.starts_with("umac-64") {
                Umac::U64(Box::new(Umac64::new(k)))
            } else {
                Umac::U128(Box::new(Umac128::new(k)))
            };
            Box::new(UmacMac { keyed, etm })
        }
        _ => return None,
    })
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
    fn every_catalogued_mac_round_trips() {
        for spec in ALL {
            let key = alloc::vec![0x5au8; spec.key_len];
            let mac = mac_by_name(spec.name, &key).expect(spec.name);
            assert_eq!(mac.tag_len(), spec.tag_len, "{}", spec.name);
            assert_eq!(mac.etm(), spec.etm, "{}", spec.name);
            let mut tag = alloc::vec![0u8; spec.tag_len];
            mac.compute(7, b"packet", &mut tag).unwrap();
            mac.verify(7, b"packet", &tag).unwrap();
            assert!(mac.verify(8, b"packet", &tag).is_err(), "{}", spec.name);
            assert!(
                mac.verify(7, b"packet", &tag[1..]).is_err(),
                "{}",
                spec.name
            );
        }
    }

    #[test]
    fn hmac_sha1_and_md5_rfc2202_tc2() {
        // RFC 2202 test case 2 ("Jefe"), with the 4-byte sequence number
        // taken from the front of the message.
        let data = b"what do ya want for nothing?";
        let seq = u32::from_be_bytes(data[..4].try_into().unwrap());
        let mut key = alloc::vec![0u8; 20];
        key[..4].copy_from_slice(b"Jefe");
        let mac = mac_by_name("hmac-sha1", &key).unwrap();
        let mut tag = [0u8; 20];
        mac.compute(seq, &data[4..], &mut tag).unwrap();
        assert_eq!(
            &tag[..],
            &unhex("effcdf6ae5eb2fa2d27416d5f184df9c259a7c79")[..]
        );
        let mac = mac_by_name("hmac-sha1-96", &key).unwrap();
        let mut tag = [0u8; 12];
        mac.compute(seq, &data[4..], &mut tag).unwrap();
        assert_eq!(&tag[..], &unhex("effcdf6ae5eb2fa2d27416d5")[..]);
        let mac = mac_by_name("hmac-md5", &key[..16]).unwrap();
        let mut tag = [0u8; 16];
        mac.compute(seq, &data[4..], &mut tag).unwrap();
        assert_eq!(&tag[..], &unhex("750c783e6ab0b503eaa86e310a5db738")[..]);
    }

    #[test]
    fn factory_unknown_name() {
        assert!(mac_by_name("hmac-md4", &[0u8; 16]).is_none());
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
