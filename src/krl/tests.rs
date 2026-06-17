//! KRL parser tests.
//!
//! The serial / explicit-key / key-id / bitmap fixtures are real KRL blobs
//! produced by `ssh-keygen -k` (OpenSSH 9.x) against a fixed ed25519 CA and
//! user key; the fingerprint fixtures are constructed by hand from the
//! parser's own hash output so the test is self-consistent on any platform.

use super::*;
use alloc::vec;

/// Minimal compile-time hex literal helper (avoids a dev-dep on `hex` for the
/// library's own unit tests, which build without dev-dependencies in some
/// configurations).
macro_rules! hex {
    ($s:literal) => {{
        const S: &str = $s;
        const N: usize = S.len() / 2;
        const fn nib(c: u8) -> u8 {
            match c {
                b'0'..=b'9' => c - b'0',
                b'a'..=b'f' => c - b'a' + 10,
                b'A'..=b'F' => c - b'A' + 10,
                _ => 0,
            }
        }
        const fn decode() -> [u8; N] {
            let bytes = S.as_bytes();
            let mut out = [0u8; N];
            let mut i = 0;
            while i < N {
                out[i] = (nib(bytes[i * 2]) << 4) | nib(bytes[i * 2 + 1]);
                i += 1;
            }
            out
        }
        decode()
    }};
}

/// Raw wire blob of the test CA's ed25519 public key.
const CA_BLOB: &[u8] = &hex!(
    "0000000b7373682d65643235353139000000203659ea41e0a2e1c0267e70c0254840aef8de6f3200bd86b2400bcd6261d9279a"
);
/// Raw wire blob of the test user's ed25519 public key.
const USERKEY_BLOB: &[u8] = &hex!(
    "0000000b7373682d6564323535313900000020dac8c367fff423cc766d20abff4f2620880f421ea7e2c58a47100892e490547f"
);

/// `ssh-keygen -k` revoking serials `10` and the range `100-200` against CA.
const KRL_SERIAL: &[u8] = &hex!(
    "5353484b524c0a00000000010000000000000000000000006a31ff2800000000000000000000000000000000010000005d000000330000000b7373682d65643235353139000000203659ea41e0a2e1c0267e70c0254840aef8de6f3200bd86b2400bcd6261d9279a000000002000000008000000000000000a2100000010000000000000006400000000000000c8"
);

/// `ssh-keygen -k` revoking the explicit user public key.
const KRL_EXPLICIT: &[u8] = &hex!(
    "5353484b524c0a00000000010000000000000000000000006a31ff28000000000000000000000000000000000200000037000000330000000b7373682d6564323535313900000020dac8c367fff423cc766d20abff4f2620880f421ea7e2c58a47100892e490547f"
);

/// `ssh-keygen -k` revoking cert key-id `revoked-id-1` against CA.
const KRL_KEYID: &[u8] = &hex!(
    "5353484b524c0a00000000010000000000000000000000006a31ff28000000000000000000000000000000000100000050000000330000000b7373682d65643235353139000000203659ea41e0a2e1c0267e70c0254840aef8de6f3200bd86b2400bcd6261d9279a0000000023000000100000000c7265766f6b65642d69642d31"
);

/// `ssh-keygen -k` revoking serials 1,2,3,5,8 (bitmap encoding) against CA.
const KRL_BITMAP: &[u8] = &hex!(
    "5353484b524c0a00000000010000000000000000000000006a31ff3900000000000000000000000000000000010000004e000000330000000b7373682d65643235353139000000203659ea41e0a2e1c0267e70c0254840aef8de6f3200bd86b2400bcd6261d9279a00000000220000000e0000000000000001000000020097"
);

#[test]
fn serial_list_and_range() {
    let krl = Krl::parse(KRL_SERIAL).expect("parse");
    // Serial-list: only 10.
    assert!(krl.is_revoked_cert(CA_BLOB, 10, ""));
    assert!(!krl.is_revoked_cert(CA_BLOB, 11, ""));
    // Serial-range 100..=200 inclusive.
    assert!(krl.is_revoked_cert(CA_BLOB, 100, ""));
    assert!(krl.is_revoked_cert(CA_BLOB, 150, ""));
    assert!(krl.is_revoked_cert(CA_BLOB, 200, ""));
    assert!(!krl.is_revoked_cert(CA_BLOB, 99, ""));
    assert!(!krl.is_revoked_cert(CA_BLOB, 201, ""));
    // A different CA is unaffected (this block names a specific CA).
    assert!(!krl.is_revoked_cert(USERKEY_BLOB, 10, ""));
    // Plain-key checks find nothing here.
    assert!(!krl.is_revoked_key(USERKEY_BLOB));
}

#[test]
fn explicit_key() {
    let krl = Krl::parse(KRL_EXPLICIT).expect("parse");
    assert!(krl.is_revoked_key(USERKEY_BLOB));
    assert!(!krl.is_revoked_key(CA_BLOB));
    // No cert section ⇒ no cert revocations.
    assert!(!krl.is_revoked_cert(CA_BLOB, 10, ""));
}

#[test]
fn cert_key_id() {
    let krl = Krl::parse(KRL_KEYID).expect("parse");
    assert!(krl.is_revoked_cert(CA_BLOB, 0, "revoked-id-1"));
    assert!(krl.is_revoked_cert(CA_BLOB, 12345, "revoked-id-1"));
    assert!(!krl.is_revoked_cert(CA_BLOB, 0, "other-id"));
    // An empty key-id never matches the key-id list.
    assert!(!krl.is_revoked_cert(CA_BLOB, 0, ""));
}

#[test]
fn serial_bitmap() {
    let krl = Krl::parse(KRL_BITMAP).expect("parse");
    for s in [1u64, 2, 3, 5, 8] {
        assert!(
            krl.is_revoked_cert(CA_BLOB, s, ""),
            "serial {s} should revoke"
        );
    }
    for s in [4u64, 6, 7, 9, 100] {
        assert!(
            !krl.is_revoked_cert(CA_BLOB, s, ""),
            "serial {s} should NOT revoke"
        );
    }
}

#[test]
fn fingerprint_sha1_and_sha256() {
    // Hand-build a KRL with one fp-sha1 section and one fp-sha256 section
    // covering USERKEY_BLOB, computed via the same digests the parser uses.
    let h1 = Sha1::digest(USERKEY_BLOB);
    let h256 = Sha256::digest(USERKEY_BLOB);

    let mut blob = vec![];
    // Header.
    blob.extend_from_slice(&KRL_MAGIC.to_be_bytes());
    blob.extend_from_slice(&KRL_FORMAT_VERSION.to_be_bytes());
    blob.extend_from_slice(&0u64.to_be_bytes()); // krl_version
    blob.extend_from_slice(&0u64.to_be_bytes()); // generated_date
    blob.extend_from_slice(&0u64.to_be_bytes()); // flags
    blob.extend_from_slice(&0u32.to_be_bytes()); // reserved (empty)
    blob.extend_from_slice(&0u32.to_be_bytes()); // comment (empty)

    let push_section = |out: &mut alloc::vec::Vec<u8>, ty: u8, body: &[u8]| {
        out.push(ty);
        out.extend_from_slice(&(body.len() as u32).to_be_bytes());
        out.extend_from_slice(body);
    };
    let push_hash = |out: &mut alloc::vec::Vec<u8>, h: &[u8]| {
        out.extend_from_slice(&(h.len() as u32).to_be_bytes());
        out.extend_from_slice(h);
    };

    let mut body1 = vec![];
    push_hash(&mut body1, &h1);
    push_section(&mut blob, SECTION_FINGERPRINT_SHA1, &body1);

    let mut body256 = vec![];
    push_hash(&mut body256, &h256);
    push_section(&mut blob, SECTION_FINGERPRINT_SHA256, &body256);

    let krl = Krl::parse(&blob).expect("parse");
    assert!(krl.is_revoked_key(USERKEY_BLOB));
    assert!(!krl.is_revoked_key(CA_BLOB));
}

#[test]
fn wildcard_ca_applies_to_all() {
    // Build a certificates section with an EMPTY ca_key (wildcard) + a
    // serial-list revoking serial 7.
    let mut sec = vec![];
    sec.extend_from_slice(&0u32.to_be_bytes()); // ca_key (empty)
    sec.extend_from_slice(&0u32.to_be_bytes()); // reserved (empty)
    sec.push(super::CERT_SERIAL_LIST);
    sec.extend_from_slice(&8u32.to_be_bytes()); // body len
    sec.extend_from_slice(&7u64.to_be_bytes());

    let mut blob = vec![];
    blob.extend_from_slice(&KRL_MAGIC.to_be_bytes());
    blob.extend_from_slice(&KRL_FORMAT_VERSION.to_be_bytes());
    blob.extend_from_slice(&0u64.to_be_bytes());
    blob.extend_from_slice(&0u64.to_be_bytes());
    blob.extend_from_slice(&0u64.to_be_bytes());
    blob.extend_from_slice(&0u32.to_be_bytes());
    blob.extend_from_slice(&0u32.to_be_bytes());
    blob.push(SECTION_CERTIFICATES);
    blob.extend_from_slice(&(sec.len() as u32).to_be_bytes());
    blob.extend_from_slice(&sec);

    let krl = Krl::parse(&blob).expect("parse");
    // Wildcard CA ⇒ any CA's serial 7 is revoked.
    assert!(krl.is_revoked_cert(CA_BLOB, 7, ""));
    assert!(krl.is_revoked_cert(USERKEY_BLOB, 7, ""));
    assert!(!krl.is_revoked_cert(CA_BLOB, 8, ""));
}

#[test]
fn signature_section_is_parse_and_ignore() {
    // A trailing signature section (type 4) must parse without error and not
    // affect revocation results.
    let mut blob = KRL_SERIAL.to_vec();
    // Append a signature section with arbitrary body bytes.
    blob.push(SECTION_SIGNATURE);
    let sig_body = [0xAAu8; 16];
    blob.extend_from_slice(&(sig_body.len() as u32).to_be_bytes());
    blob.extend_from_slice(&sig_body);

    let krl = Krl::parse(&blob).expect("signed KRL parses");
    assert!(krl.is_revoked_cert(CA_BLOB, 10, ""));
}

#[test]
fn rejects_bad_magic() {
    let mut blob = KRL_SERIAL.to_vec();
    blob[0] ^= 0xff;
    assert!(Krl::parse(&blob).is_err());
}

#[test]
fn rejects_truncated() {
    assert!(Krl::parse(&KRL_SERIAL[..KRL_SERIAL.len() - 4]).is_err());
    assert!(Krl::parse(b"SSHK").is_err());
    assert!(Krl::parse(b"").is_err());
}

#[test]
fn empty_krl_revokes_nothing() {
    let mut blob = vec![];
    blob.extend_from_slice(&KRL_MAGIC.to_be_bytes());
    blob.extend_from_slice(&KRL_FORMAT_VERSION.to_be_bytes());
    blob.extend_from_slice(&0u64.to_be_bytes());
    blob.extend_from_slice(&0u64.to_be_bytes());
    blob.extend_from_slice(&0u64.to_be_bytes());
    blob.extend_from_slice(&0u32.to_be_bytes());
    blob.extend_from_slice(&0u32.to_be_bytes());
    let krl = Krl::parse(&blob).expect("parse");
    assert!(krl.is_empty());
    assert!(!krl.is_revoked_cert(CA_BLOB, 1, "x"));
    assert!(!krl.is_revoked_key(USERKEY_BLOB));
}
