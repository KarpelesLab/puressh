use super::*;
use crate::hostkey::HostKey;

/// A self-signed P-384 certificate for `/C=JP/O=Karpeles Lab/CN=token cert`
/// (`openssl req -x509 -newkey ec`).
const CERT_PEM: &str = include_str!("../../tests/fixtures/pkcs11/p384-cert.pem");

#[test]
fn rsa_digest_info_prefixes() {
    // DER: SEQUENCE { SEQUENCE { OID, NULL }, OCTET STRING (digest) }, the
    // lengths matching each digest's size.
    for (prefix, len) in [
        (DIGEST_INFO_SHA1, 20),
        (DIGEST_INFO_SHA256, 32),
        (DIGEST_INFO_SHA512, 64),
    ] {
        assert_eq!(prefix[1] as usize, prefix.len() - 2 + len);
        assert_eq!(*prefix.last().unwrap() as usize, len);
    }
}

#[test]
fn curves_and_points() {
    assert_eq!(
        ec_curve(&[0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07]),
        Some(("ecdsa-sha2-nistp256", "nistp256"))
    );
    assert_eq!(
        ec_curve(&[0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22])
            .unwrap()
            .1,
        "nistp384"
    );
    assert!(ec_curve(&[0x06, 0x03, 0x2b, 0x65, 0x70]).is_none());
    // An OCTET STRING around the point, or the bare point.
    assert_eq!(
        ec_point(&[0x04, 0x03, 0x04, 0xaa, 0xbb]),
        &[0x04, 0xaa, 0xbb]
    );
    assert_eq!(
        ec_point(&[0x04, 0xaa, 0xbb, 0xcc]),
        &[0x04, 0xaa, 0xbb, 0xcc]
    );
}

#[test]
fn x509_subject_and_key() {
    let der = purecrypto::der::pem_decode(CERT_PEM, "CERTIFICATE").unwrap();
    let spki = x509::subject_public_key_info(&der).unwrap();
    let key = PublicKey::from_spki_der(spki).unwrap();
    assert_eq!(key.algorithm(), "ecdsa-sha2-nistp384");
    // The certificate's subject, as `CKA_SUBJECT` holds it.
    let mut r = purecrypto::der::Reader::new(&der);
    let mut tbs = r.read_sequence().unwrap().read_sequence().unwrap();
    tbs.read_any().unwrap(); // version
    for _ in 0..4 {
        tbs.read_any().unwrap();
    }
    let subject = tbs.read_element().unwrap();
    assert_eq!(
        x509::name_oneline(subject).unwrap(),
        "/C=JP/O=Karpeles Lab/CN=token cert"
    );
}

#[test]
fn x509_name_oneline_matches_openssl() {
    // SEQUENCE { SET { SEQUENCE { OID 2.5.4.6, PrintableString "JP" } },
    //            SET { SEQUENCE { OID 2.5.4.3, UTF8String "a\u{e9}" } } }
    let name = [
        0x30, 0x1b, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, b'J', b'P',
        0x31, 0x0c, 0x30, 0x0a, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x03, b'a', 0xc3, 0xa9,
    ];
    assert_eq!(x509::name_oneline(&name).unwrap(), "/C=JP/CN=a\\xC3\\xA9");
}

/// `PKCS11_MODULE`: a module (e.g. SoftHSM 2) with a token whose user PIN
/// is `PKCS11_PIN`, holding an RSA, an ECDSA and an Ed25519 key: listing
/// them and signing with each, as `ssh-keygen -D` and `ssh -I` do.
#[test]
fn module_lists_and_signs() {
    let (Ok(module), Ok(pin)) = (std::env::var("PKCS11_MODULE"), std::env::var("PKCS11_PIN"))
    else {
        return;
    };
    // Without a PIN or a way to ask, a token requiring login is refused.
    assert!(matches!(
        load(&module, None, None),
        Err(Error::Pkcs11(Pkcs11Error::PinRequired))
    ));
    let keys = load(&module, Some(&pin), None).unwrap();
    assert!(!keys.is_empty());
    let mut seen = Vec::new();
    for k in &keys {
        let blob = k.public_key().wire_blob();
        let algs: &[&str] = match k.public_key() {
            PublicKey::Rsa { .. } => &["rsa-sha2-512", "rsa-sha2-256"],
            other => &[other.algorithm()],
        };
        for alg in algs {
            let sig = k.sign_with(alg, b"message").unwrap();
            crate::hostkey::host_key_verify_by_name(alg, &blob)
                .unwrap()
                .verify(b"message", &sig)
                .unwrap();
        }
        let sig = k.sign(b"other").unwrap();
        crate::hostkey::verify_signature(HostKey::algorithm(&**k), &blob, b"other", &sig).unwrap();
        seen.push(k.public_key().algorithm());
    }
    for alg in ["ssh-rsa", "ecdsa-sha2-nistp256", "ssh-ed25519"] {
        assert!(seen.contains(&alg), "{alg} missing from {seen:?}");
    }
    // A wrong PIN.
    assert!(load(&module, Some("0000"), None).is_err());
}
