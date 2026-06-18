//! Unit tests for certificate parsing/verification, driven by fixtures
//! generated with `ssh-keygen -s` (see `tests/fixtures/cert/`).

use super::*;
use crate::key::base64;

/// Load a `*-cert.pub` fixture (`<type> <base64> <comment>`), returning the
/// decoded certificate blob.
fn load_cert_blob(name: &str) -> Vec<u8> {
    let path = concat_fixture(name);
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {path}: {e}"));
    let b64 = text
        .split_whitespace()
        .nth(1)
        .unwrap_or_else(|| panic!("fixture {path} has no base64 field"));
    base64::decode(b64.as_bytes()).expect("decode cert base64")
}

/// Load a plain `.pub` fixture, returning its wire blob.
fn load_pub_blob(name: &str) -> Vec<u8> {
    let path = concat_fixture(name);
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {path}: {e}"));
    let b64 = text.split_whitespace().nth(1).expect("base64 field");
    base64::decode(b64.as_bytes()).expect("decode pub base64")
}

fn concat_fixture(name: &str) -> String {
    format!(
        "{}/tests/fixtures/cert/{}",
        env!("CARGO_MANIFEST_DIR"),
        name
    )
}

/// The default CA-signature allow-list used by these tests (mirrors the
/// Phase 2 default, minus plain ssh-rsa).
const CA_ALGOS: &[&str] = &[
    "ssh-ed25519",
    "ecdsa-sha2-nistp256",
    "ecdsa-sha2-nistp384",
    "ecdsa-sha2-nistp521",
    "rsa-sha2-512",
    "rsa-sha2-256",
];

/// A "now" inside the 2020..2099 fixture window.
const NOW: u64 = 1_700_000_000; // 2023-11-14

#[test]
fn parse_ed25519_user_cert() {
    let blob = load_cert_blob("u_ed25519-cert.pub");
    let cert = Certificate::parse(&blob).unwrap();
    assert_eq!(cert.key_type, "ssh-ed25519-cert-v01@openssh.com");
    assert_eq!(cert.embedded_algorithm(), "ssh-ed25519");
    assert_eq!(cert.cert_type, CertType::User);
    assert_eq!(cert.serial, 1);
    assert_eq!(cert.key_id, "alice");
    assert_eq!(cert.valid_principals, vec!["alice", "bob"]);
    // The reconstructed embedded blob must equal the plain key's wire blob.
    assert_eq!(cert.embedded_pubkey_blob(), load_pub_blob("u_ed25519.pub"));
}

#[test]
fn parse_ecdsa_user_cert() {
    for (file, algo) in [
        ("u_ecdsa-cert.pub", "ecdsa-sha2-nistp256"),
        ("u_ecdsa384-cert.pub", "ecdsa-sha2-nistp384"),
        ("u_ecdsa521-cert.pub", "ecdsa-sha2-nistp521"),
    ] {
        let blob = load_cert_blob(file);
        let cert = Certificate::parse(&blob).unwrap();
        assert_eq!(cert.embedded_algorithm(), algo, "{file}");
        assert_eq!(cert.cert_type, CertType::User);
        cert.verify_ca_signature(CA_ALGOS).unwrap();
    }
}

#[test]
fn parse_rsa_user_cert() {
    let blob = load_cert_blob("u_rsa-cert.pub");
    let cert = Certificate::parse(&blob).unwrap();
    assert_eq!(cert.key_type, "ssh-rsa-cert-v01@openssh.com");
    assert_eq!(cert.embedded_algorithm(), "ssh-rsa");
    // The CA signed this cert with rsa-sha2-512 (carried in the signature).
    assert_eq!(cert.ca_algorithm().unwrap(), "rsa-sha2-512");
    assert_eq!(cert.cert_type, CertType::User);
    assert_eq!(cert.embedded_pubkey_blob(), load_pub_blob("u_rsa.pub"));
    cert.verify_ca_signature(CA_ALGOS).unwrap();
}

#[test]
fn parse_host_cert() {
    let blob = load_cert_blob("h_ed25519-cert.pub");
    let cert = Certificate::parse(&blob).unwrap();
    assert_eq!(cert.cert_type, CertType::Host);
    assert_eq!(
        cert.valid_principals,
        vec!["host.example.com", "host2.example.com"]
    );
    cert.verify_ca_signature(CA_ALGOS).unwrap();
    cert.check_type(CertType::Host).unwrap();
    cert.check_principal("host.example.com").unwrap();
    assert!(cert.check_principal("evil.example.com").is_err());
}

#[test]
fn good_ca_signature_verifies() {
    let blob = load_cert_blob("u_ed25519-cert.pub");
    let cert = Certificate::parse(&blob).unwrap();
    cert.verify_ca_signature(CA_ALGOS).unwrap();
}

#[test]
fn tampered_cert_fails_ca_signature() {
    let mut blob = load_cert_blob("u_ed25519-cert.pub");
    // Flip a byte in the key-id region (well inside the signed range).
    let cert = Certificate::parse(&blob).unwrap();
    // Mutate a byte that lies before signed_len but is not in a length prefix
    // we depend on for parsing — flip a byte in the embedded principals area.
    let idx = cert.signed_len / 2;
    blob[idx] ^= 0xff;
    // It may still parse (or not); if it parses, the CA sig must fail.
    if let Ok(c2) = Certificate::parse(&blob) {
        assert!(matches!(
            c2.verify_ca_signature(CA_ALGOS),
            Err(Error::CertBadCaSignature)
        ));
    }
}

#[test]
fn wrong_ca_algo_set_rejected() {
    let blob = load_cert_blob("u_ed25519-cert.pub");
    let cert = Certificate::parse(&blob).unwrap();
    // CA signed with ssh-ed25519; an allow-list without it must reject.
    assert!(matches!(
        cert.verify_ca_signature(&["rsa-sha2-512"]),
        Err(Error::CertBadCaSignature)
    ));
    // Empty set rejects everything.
    assert!(matches!(
        cert.verify_ca_signature(&[]),
        Err(Error::CertBadCaSignature)
    ));
}

#[test]
fn wrong_ca_key_rejected() {
    // Take the ed25519 cert but swap in a different CA key blob: re-encode the
    // cert with signature_key_blob replaced by the ecdsa CA's blob. The CA
    // algorithm in the signature then won't match the swapped key, or the
    // signature won't verify.
    let blob = load_cert_blob("u_ecdsa-cert.pub");
    let cert = Certificate::parse(&blob).unwrap();
    // Build a verifier whose CA key is the ed25519 CA but algo claims ecdsa —
    // the cleanest "wrong CA" test is: parse a cert and verify against an
    // allow-list that permits the algo but the embedded signature_key is from a
    // different CA. We simulate by checking that the *ecdsa* cert does not
    // verify if we corrupt its signature_key_blob.
    let mut raw = cert.raw.clone();
    // Corrupt within the signed region's signature-key area: flip last byte of
    // signed region.
    raw[cert.signed_len - 1] ^= 0xff;
    if let Ok(c2) = Certificate::parse(&raw) {
        assert!(c2.verify_ca_signature(CA_ALGOS).is_err());
    }
}

#[test]
fn expired_cert_rejected() {
    let blob = load_cert_blob("u_ed25519_expired-cert.pub");
    let cert = Certificate::parse(&blob).unwrap();
    cert.verify_ca_signature(CA_ALGOS).unwrap(); // signature is still valid
    assert!(matches!(cert.check_validity(NOW), Err(Error::CertExpired)));
}

#[test]
fn not_yet_valid_cert_rejected() {
    let blob = load_cert_blob("u_ed25519_notyet-cert.pub");
    let cert = Certificate::parse(&blob).unwrap();
    assert!(matches!(
        cert.check_validity(NOW),
        Err(Error::CertNotYetValid)
    ));
}

#[test]
fn principal_mismatch_rejected() {
    let blob = load_cert_blob("u_ecdsa-cert.pub"); // principals = ["bob"]
    let cert = Certificate::parse(&blob).unwrap();
    cert.check_principal("bob").unwrap();
    assert!(matches!(
        cert.check_principal("alice"),
        Err(Error::CertPrincipalMismatch)
    ));
}

#[test]
fn host_principal_match_is_case_insensitive() {
    // Host-cert principals are DNS host names: case-insensitive per OpenSSH.
    let mut cert = Certificate::parse(&load_cert_blob("h_ed25519-cert.pub")).unwrap();
    assert_eq!(cert.cert_type, CertType::Host);
    assert_eq!(
        cert.valid_principals,
        vec!["host.example.com", "host2.example.com"]
    );
    // Mixed-case query must match a lowercase principal for a host cert.
    cert.check_principal("Host.Example.Com").unwrap();
    cert.check_principal("HOST2.EXAMPLE.COM").unwrap();
    // A genuinely different host still fails.
    assert!(matches!(
        cert.check_principal("evil.example.com"),
        Err(Error::CertPrincipalMismatch)
    ));

    // Sanity: forcing the *same* cert to user type makes the comparison
    // case-sensitive, so the mixed-case query no longer matches.
    cert.cert_type = CertType::User;
    assert!(matches!(
        cert.check_principal("Host.Example.Com"),
        Err(Error::CertPrincipalMismatch)
    ));
    cert.check_principal("host.example.com").unwrap();
}

#[test]
fn user_principal_match_is_case_sensitive() {
    // User-cert principals are login names: case-sensitive per OpenSSH.
    let cert = Certificate::parse(&load_cert_blob("u_ed25519-cert.pub")).unwrap();
    assert_eq!(cert.cert_type, CertType::User);
    assert_eq!(cert.valid_principals, vec!["alice", "bob"]);
    cert.check_principal("alice").unwrap();
    // A case variant must NOT match a user-cert login name.
    assert!(matches!(
        cert.check_principal("Alice"),
        Err(Error::CertPrincipalMismatch)
    ));
    assert!(matches!(
        cert.check_principal("BOB"),
        Err(Error::CertPrincipalMismatch)
    ));
}

#[test]
fn type_mismatch_rejected() {
    let user = Certificate::parse(&load_cert_blob("u_ed25519-cert.pub")).unwrap();
    assert!(matches!(
        user.check_type(CertType::Host),
        Err(Error::CertTypeMismatch)
    ));
    let host = Certificate::parse(&load_cert_blob("h_ed25519-cert.pub")).unwrap();
    assert!(matches!(
        host.check_type(CertType::User),
        Err(Error::CertTypeMismatch)
    ));
}

#[test]
fn critical_options_parsed_and_known() {
    let blob = load_cert_blob("u_ed25519_crit-cert.pub");
    let cert = Certificate::parse(&blob).unwrap();
    // force-command and source-address are both understood.
    assert!(cert.unknown_critical_options().is_empty());
    cert.require_known_critical_options().unwrap();
    assert_eq!(
        cert.critical_option("force-command").unwrap(),
        // Inner string is itself length-prefixed per PROTOCOL.certkeys.
        encode_str(b"/usr/bin/uptime").as_slice()
    );
}

#[test]
fn unknown_critical_option_rejected() {
    // Synthesize a cert with an unknown critical option by re-encoding the
    // crit fixture's critical-options field. Easiest: hand-build a tiny cert is
    // overkill; instead assert the predicate on a constructed Certificate.
    let mut cert = Certificate::parse(&load_cert_blob("u_ed25519-cert.pub")).unwrap();
    cert.critical_options
        .push(("totally-unknown-option".to_string(), Vec::new()));
    assert_eq!(
        cert.unknown_critical_options(),
        vec!["totally-unknown-option"]
    );
    assert!(matches!(
        cert.require_known_critical_options(),
        Err(Error::CertUnknownCriticalOption)
    ));
}

#[test]
fn oversized_blob_rejected() {
    let big = vec![0u8; MAX_CERT_BLOB + 1];
    assert!(Certificate::parse(&big).is_err());
}

#[test]
fn trailing_data_rejected() {
    let mut blob = load_cert_blob("u_ed25519-cert.pub");
    blob.push(0x00); // one stray byte after the signature
    assert!(matches!(Certificate::parse(&blob), Err(Error::Format(_))));
}

#[test]
fn truncated_blob_rejected() {
    let blob = load_cert_blob("u_ed25519-cert.pub");
    assert!(Certificate::parse(&blob[..blob.len() / 2]).is_err());
}

#[test]
fn embedded_verifier_matches_underlying_key() {
    // Sign a message with each user key's private half (loaded from the
    // OpenSSH private key fixture) and verify via the cert's embedded verifier.
    use crate::key::PrivateKey;

    for (cert_file, priv_file) in [
        ("u_ed25519-cert.pub", "u_ed25519"),
        ("u_ecdsa-cert.pub", "u_ecdsa"),
        ("u_rsa-cert.pub", "u_rsa"),
    ] {
        let cert = Certificate::parse(&load_cert_blob(cert_file)).unwrap();
        let pem = std::fs::read_to_string(concat_fixture(priv_file)).unwrap();
        let sk = PrivateKey::parse_openssh_pem(&pem, None).unwrap();
        let signer = sk.into_host_key().unwrap();
        let msg = b"exchange-hash stand-in";
        let sig = signer.sign(msg).unwrap();
        let verifier = cert.embedded_verifier(&sig).unwrap();
        verifier.verify(msg, &sig).unwrap();
        // A tampered message must fail.
        assert!(verifier.verify(b"different", &sig).is_err());
    }
}

/// Helper mirroring SSH string encoding for the force-command assertion.
fn encode_str(s: &[u8]) -> Vec<u8> {
    let mut w = Writer::new();
    w.write_string(s);
    w.into_vec()
}
