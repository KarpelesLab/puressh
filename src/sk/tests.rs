use super::*;
use crate::hostkey::HostKey;
use purecrypto::ec::{BoxedEcdsaPrivateKey, CurveId, Ed25519PrivateKey};
use purecrypto::hash::{Digest, Sha256};
use purecrypto::rng::{OsRng, RngCore};
use std::sync::Mutex;

/// A software authenticator, as OpenSSH's `sk-dummy`: the key handle is the
/// private key itself. It signs what a real one does (`SHA256(app) ||
/// flags || counter || SHA256(data)`), with user presence unless enrolled
/// `no-touch-required`, and wants a PIN for a verify-required key.
#[derive(Default)]
struct SoftAuthenticator {
    counter: Mutex<u32>,
    resident: Mutex<Vec<ResidentKey>>,
}

const PIN: &str = "123456";

impl Provider for SoftAuthenticator {
    fn enroll(
        &self,
        alg: Algorithm,
        _challenge: &[u8],
        application: &str,
        flags: u8,
        _pin: Option<&str>,
        _options: &[SkOption],
    ) -> core::result::Result<EnrollResponse, SkError> {
        let (public_key, key_handle) = match alg {
            Algorithm::EcdsaP256 => loop {
                let mut d = alloc::vec![0u8; 32];
                OsRng.fill_bytes(&mut d);
                if let Ok(sk) = BoxedEcdsaPrivateKey::from_bytes(CurveId::P256, &d) {
                    break (sk.public_key().to_sec1(), d);
                }
            },
            Algorithm::Ed25519 => {
                let sk = Ed25519PrivateKey::generate(&mut OsRng);
                (sk.public_key().to_bytes().to_vec(), sk.to_bytes().to_vec())
            }
        };
        let resp = EnrollResponse {
            flags,
            public_key,
            key_handle,
            signature: b"attestation-signature".to_vec(),
            attestation_cert: b"attestation-certificate".to_vec(),
            authdata: b"authdata".to_vec(),
        };
        if flags & RESIDENT_KEY != 0 {
            self.resident.lock().unwrap().push(ResidentKey {
                algorithm: alg,
                slot: 0,
                application: application.into(),
                key: resp.clone(),
                flags,
                user_id: b"user".to_vec(),
            });
        }
        Ok(resp)
    }

    fn sign(
        &self,
        alg: Algorithm,
        data: &[u8],
        application: &str,
        key_handle: &[u8],
        flags: u8,
        pin: Option<&str>,
        _options: &[SkOption],
    ) -> core::result::Result<SignResponse, SkError> {
        let mut out_flags = flags & USER_PRESENCE_REQD;
        if flags & USER_VERIFICATION_REQD != 0 {
            match pin {
                Some(PIN) => out_flags |= USER_VERIFICATION_REQD,
                Some(_) => return Err(SkError::General),
                None => return Err(SkError::PinRequired),
            }
        }
        let counter = {
            let mut c = self.counter.lock().unwrap();
            *c += 1;
            *c
        };
        let mut m = Vec::new();
        m.extend_from_slice(Sha256::digest(application.as_bytes()).as_ref());
        m.push(out_flags);
        m.extend_from_slice(&counter.to_be_bytes());
        m.extend_from_slice(Sha256::digest(data).as_ref());
        let (sig_r, sig_s) = match alg {
            Algorithm::EcdsaP256 => {
                let sk = BoxedEcdsaPrivateKey::from_bytes(CurveId::P256, key_handle).unwrap();
                let sig = sk.sign::<Sha256>(&m).unwrap();
                (sig.r_bytes(CurveId::P256), sig.s_bytes(CurveId::P256))
            }
            Algorithm::Ed25519 => {
                let seed: [u8; 32] = key_handle.try_into().unwrap();
                (
                    Ed25519PrivateKey::from_bytes(seed)
                        .sign(&m)
                        .to_bytes()
                        .to_vec(),
                    Vec::new(),
                )
            }
        };
        Ok(SignResponse {
            flags: out_flags,
            counter,
            sig_r,
            sig_s,
        })
    }

    fn load_resident_keys(
        &self,
        _pin: Option<&str>,
        _options: &[SkOption],
    ) -> core::result::Result<Vec<ResidentKey>, SkError> {
        Ok(self.resident.lock().unwrap().clone())
    }
}

struct FixedPin;
impl Prompt for FixedPin {
    fn touch(&self, _key: &PrivateKey) {}
    fn pin(&self, _key: &PrivateKey) -> Option<Zeroizing<String>> {
        Some(Zeroizing::new(PIN.into()))
    }
}

fn verify(key: &PrivateKey, msg: &[u8], sig: &[u8]) -> crate::Result<()> {
    let blob = key.public_key().wire_blob();
    crate::hostkey::host_key_verify_by_name(key.algorithm(), &blob)?.verify(msg, sig)
}

#[test]
fn enroll_sign_verify() {
    let auth = SoftAuthenticator::default();
    for alg in [Algorithm::EcdsaP256, Algorithm::Ed25519] {
        let e = enroll(&auth, alg, "ssh:", USER_PRESENCE_REQD, None, None, &[]).unwrap();
        assert_eq!(e.key.algorithm(), alg.name());
        assert!(e.attestation.starts_with(b"\0\0\0\x11ssh-sk-attest-v01"));
        let sig = sign(&auth, &e.key, b"message", None).unwrap();
        verify(&e.key, b"message", &sig).unwrap();
        assert!(verify(&e.key, b"other", &sig).is_err());
        let flags = crate::hostkey::sk::sk_signature_flags(&sig).unwrap();
        assert_eq!(flags & USER_PRESENCE_REQD, USER_PRESENCE_REQD);

        // The key round-trips through a private key file.
        let pem = e.key.to_openssh_pem(None).unwrap();
        let again = PrivateKey::parse_openssh_pem(&pem, None).unwrap();
        let sig = sign(&auth, &again, b"message", None).unwrap();
        verify(&e.key, b"message", &sig).unwrap();
    }
}

#[test]
fn signer_asks_for_a_pin_when_needed() {
    let auth: Arc<dyn Provider> = Arc::new(SoftAuthenticator::default());
    let e = enroll(
        &*auth,
        Algorithm::Ed25519,
        "ssh:",
        USER_PRESENCE_REQD | USER_VERIFICATION_REQD,
        None,
        None,
        &[],
    )
    .unwrap();
    // Without a way to ask, the PIN requirement surfaces.
    let silent = SkSigner::new(e.key.clone(), auth.clone(), None).unwrap();
    assert!(matches!(
        silent.sign(b"m"),
        Err(Error::SecurityKey(SkError::PinRequired))
    ));
    let signer = SkSigner::new(e.key.clone(), auth, Some(Arc::new(FixedPin))).unwrap();
    let sig = signer.sign(b"m").unwrap();
    verify(&e.key, b"m", &sig).unwrap();
    let flags = crate::hostkey::sk::sk_signature_flags(&sig).unwrap();
    assert_eq!(flags & USER_VERIFICATION_REQD, USER_VERIFICATION_REQD);
}

#[test]
fn resident_keys_are_filtered_and_flagged() {
    let auth = SoftAuthenticator::default();
    enroll(
        &auth,
        Algorithm::EcdsaP256,
        "ssh:work",
        RESIDENT_KEY,
        None,
        None,
        &[],
    )
    .unwrap();
    enroll(
        &auth,
        Algorithm::Ed25519,
        "webauthn.example",
        RESIDENT_KEY,
        None,
        None,
        &[],
    )
    .unwrap();
    let keys = load_resident_keys(&auth, None, &[]).unwrap();
    assert_eq!(keys.len(), 1, "only ssh: applications");
    let sk = keys[0].key.sk_credential().unwrap();
    assert_eq!(sk.application, "ssh:work");
    assert_eq!(sk.flags, USER_PRESENCE_REQD | RESIDENT_KEY);
    assert_eq!(keys[0].user_id, b"user");
    let sig = sign(&auth, &keys[0].key, b"m", None).unwrap();
    verify(&keys[0].key, b"m", &sig).unwrap();
}

#[test]
fn bad_responses_are_refused() {
    let resp = EnrollResponse {
        public_key: alloc::vec![4u8; 65],
        key_handle: alloc::vec![1],
        ..EnrollResponse::default()
    };
    assert!(key_from_response(Algorithm::EcdsaP256, "ssh:", 1, &resp).is_err());
    let resp = EnrollResponse {
        public_key: alloc::vec![0u8; 31],
        key_handle: alloc::vec![1],
        ..EnrollResponse::default()
    };
    assert!(key_from_response(Algorithm::Ed25519, "ssh:", 1, &resp).is_err());
    let mut seed = [0u8; 32];
    OsRng.fill_bytes(&mut seed);
    let resp = EnrollResponse {
        public_key: Ed25519PrivateKey::from_bytes(seed)
            .public_key()
            .to_bytes()
            .to_vec(),
        key_handle: Vec::new(),
        ..EnrollResponse::default()
    };
    assert!(key_from_response(Algorithm::Ed25519, "ssh:", 1, &resp).is_err());
}

/// OpenSSH's `sk-dummy` provider, when `SK_DUMMY` names a build of it
/// (`regress/misc/sk-dummy/sk-dummy.so`): enrolment and signatures through
/// the real middleware API.
#[test]
fn external_sk_dummy() {
    let Ok(path) = std::env::var("SK_DUMMY") else {
        return;
    };
    let p = open_provider(&path).unwrap();
    for alg in [Algorithm::EcdsaP256, Algorithm::Ed25519] {
        let e = enroll(&*p, alg, "ssh:", USER_PRESENCE_REQD, None, None, &[]).unwrap();
        let sig = sign(&*p, &e.key, b"message", None).unwrap();
        verify(&e.key, b"message", &sig).unwrap();
        assert!(verify(&e.key, b"other", &sig).is_err());
    }
    let bogus = open_provider("/nonexistent/provider.so");
    assert!(matches!(bogus, Err(SkError::Provider(_))));
}
