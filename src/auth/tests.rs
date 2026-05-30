//! Integration tests for the client/server state machines.

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use crate::hostkey::{Ed25519HostKey, HostKey};

use super::client::{ClientAuth, ClientCredential, ClientStep, KeyboardInteractiveResponder};
use super::message::{
    encode_success, AuthMethodPayload, ServiceAccept, UserauthBanner, UserauthFailure,
    UserauthInfoRequest, UserauthPkOk, UserauthRequest,
};
use super::server::{AuthAttempt, AuthDecision, Authenticator, ServerAuth, ServerStep};

const TEST_SEED: [u8; 32] = [7u8; 32];
const TEST_SID: &[u8] = b"test-session-id-32-bytes--------";

struct AlwaysReject;
impl Authenticator for AlwaysReject {
    fn evaluate(&mut self, _attempt: AuthAttempt) -> AuthDecision {
        AuthDecision::Reject
    }
}

struct OnlyPassword {
    user: &'static str,
    pw: &'static str,
}
impl Authenticator for OnlyPassword {
    fn evaluate(&mut self, attempt: AuthAttempt) -> AuthDecision {
        match attempt {
            AuthAttempt::Password { user, password } => {
                if user == self.user && password == self.pw {
                    AuthDecision::Accept
                } else {
                    AuthDecision::Reject
                }
            }
            _ => AuthDecision::Reject,
        }
    }
}

struct OnlyPublicKey;
impl Authenticator for OnlyPublicKey {
    fn evaluate(&mut self, attempt: AuthAttempt) -> AuthDecision {
        match attempt {
            AuthAttempt::PublicKey {
                probe_only,
                verified,
                ..
            } => {
                if probe_only || verified {
                    AuthDecision::Accept
                } else {
                    AuthDecision::Reject
                }
            }
            _ => AuthDecision::Reject,
        }
    }
}

struct StaticKbdResponder {
    answers: Vec<String>,
}
impl KeyboardInteractiveResponder for StaticKbdResponder {
    fn respond(
        &mut self,
        _name: &str,
        _instruction: &str,
        prompts: &[(String, bool)],
    ) -> Vec<String> {
        prompts
            .iter()
            .zip(
                self.answers
                    .iter()
                    .cloned()
                    .chain(core::iter::repeat(String::new())),
            )
            .map(|(_, a)| a)
            .collect()
    }
}

#[test]
fn client_emits_service_request() {
    let mut c = ClientAuth::new("alice", TEST_SID.to_vec());
    let payload = c.start();
    assert_eq!(payload[0], super::message::SSH_MSG_SERVICE_REQUEST);
    let req = super::message::ServiceRequest::decode(&payload).unwrap();
    assert_eq!(req.service, "ssh-userauth");
}

#[test]
fn client_none_then_password_fallback() {
    let mut c = ClientAuth::new("alice", TEST_SID.to_vec());
    c.add_credential(ClientCredential::None);
    c.add_credential(ClientCredential::Password("hunter2".into()));

    let _ = c.start();
    let accept = ServiceAccept {
        service: "ssh-userauth".into(),
    }
    .encode();
    let step = c.on_packet(&accept).unwrap();
    let none_req = match step {
        ClientStep::Send(p) => p,
        _ => panic!("expected Send"),
    };
    let parsed = UserauthRequest::decode(&none_req).unwrap();
    assert_eq!(parsed.method.method_name(), "none");

    let failure = UserauthFailure {
        continuations: vec!["password".into()],
        partial_success: false,
    }
    .encode();
    let step = c.on_packet(&failure).unwrap();
    let pw_req = match step {
        ClientStep::Send(p) => p,
        _ => panic!("expected Send"),
    };
    let parsed = UserauthRequest::decode(&pw_req).unwrap();
    assert_eq!(parsed.method.method_name(), "password");

    let step = c.on_packet(&encode_success()).unwrap();
    assert!(matches!(step, ClientStep::Success));
}

#[test]
fn client_failed_when_credentials_exhausted() {
    let mut c = ClientAuth::new("alice", TEST_SID.to_vec());
    c.add_credential(ClientCredential::Password("a".into()));
    let _ = c.start();
    c.on_packet(
        &ServiceAccept {
            service: "ssh-userauth".into(),
        }
        .encode(),
    )
    .unwrap();
    let step = c
        .on_packet(
            &UserauthFailure {
                continuations: vec!["publickey".into()],
                partial_success: false,
            }
            .encode(),
        )
        .unwrap();
    match step {
        ClientStep::Failed { continuations, .. } => {
            assert_eq!(continuations, vec!["publickey".to_string()]);
        }
        _ => panic!("expected Failed"),
    }
}

#[test]
fn banner_does_not_change_state() {
    let mut c = ClientAuth::new("alice", TEST_SID.to_vec());
    c.add_credential(ClientCredential::Password("a".into()));
    let _ = c.start();
    c.on_packet(
        &ServiceAccept {
            service: "ssh-userauth".into(),
        }
        .encode(),
    )
    .unwrap();

    let banner = UserauthBanner {
        message: "welcome".into(),
        language: "".into(),
    }
    .encode();
    let step = c.on_packet(&banner).unwrap();
    match step {
        ClientStep::Banner { message, .. } => assert_eq!(message, "welcome"),
        _ => panic!("expected Banner"),
    }

    let step = c.on_packet(&encode_success()).unwrap();
    assert!(matches!(step, ClientStep::Success));
}

#[test]
fn client_publickey_probe_then_signed() {
    let hk = Ed25519HostKey::from_seed(TEST_SEED);
    let public_blob = hk.public_blob();

    let mut c = ClientAuth::new("alice", TEST_SID.to_vec());
    c.add_credential(ClientCredential::PublicKey(Box::new(
        Ed25519HostKey::from_seed(TEST_SEED),
    )));

    let _ = c.start();
    c.on_packet(
        &ServiceAccept {
            service: "ssh-userauth".into(),
        }
        .encode(),
    )
    .unwrap();

    let pk_ok = UserauthPkOk {
        algorithm: "ssh-ed25519".into(),
        public_blob: public_blob.clone(),
    }
    .encode();

    // First Send is the probe (signature_present == false).
    // The state machine emitted it in response to the SERVICE_ACCEPT.
    // The next step now triggers the PK_OK -> signed re-send.
    let step = c.on_packet(&pk_ok).unwrap();
    let signed = match step {
        ClientStep::Send(p) => p,
        _ => panic!("expected Send"),
    };
    let parsed = UserauthRequest::decode(&signed).unwrap();
    match parsed.method {
        AuthMethodPayload::PublicKey {
            signature_present,
            signature,
            ..
        } => {
            assert!(signature_present);
            assert!(signature.is_some());
        }
        _ => panic!("expected publickey"),
    }

    // Verify signature using the same key.
    let signed_data = super::message::publickey_signed_data(
        TEST_SID,
        "alice",
        "ssh-connection",
        "ssh-ed25519",
        &public_blob,
    );
    let sig = match UserauthRequest::decode(&signed).unwrap().method {
        AuthMethodPayload::PublicKey {
            signature: Some(s), ..
        } => s,
        _ => panic!(),
    };
    use crate::hostkey::HostKeyVerify;
    hk.verify(&signed_data, &sig).unwrap();
}

#[test]
fn server_service_accept_flow() {
    let server = ServerAuth::new(TEST_SID.to_vec(), vec!["password"], Box::new(AlwaysReject));
    let mut s = server;

    let sreq = super::message::ServiceRequest {
        service: "ssh-userauth".into(),
    }
    .encode();
    let step = s.on_packet(&sreq).unwrap();
    match step {
        ServerStep::Send(p) => {
            let a = super::message::ServiceAccept::decode(&p).unwrap();
            assert_eq!(a.service, "ssh-userauth");
        }
        _ => panic!("expected Send"),
    }
}

#[test]
fn server_password_accept() {
    let mut s = ServerAuth::new(
        TEST_SID.to_vec(),
        vec!["password"],
        Box::new(OnlyPassword {
            user: "alice",
            pw: "hunter2",
        }),
    );

    let _ = s.on_packet(
        &super::message::ServiceRequest {
            service: "ssh-userauth".into(),
        }
        .encode(),
    );
    let req = UserauthRequest {
        user: "alice".into(),
        service: "ssh-connection".into(),
        method: AuthMethodPayload::Password {
            new_password: None,
            password: "hunter2".into(),
        },
    }
    .encode();
    let step = s.on_packet(&req).unwrap();
    match step {
        ServerStep::Authenticated { user, payload } => {
            assert_eq!(user, "alice");
            assert_eq!(payload[0], super::message::SSH_MSG_USERAUTH_SUCCESS);
        }
        _ => panic!("expected Authenticated"),
    }
}

#[test]
fn server_password_reject() {
    let mut s = ServerAuth::new(
        TEST_SID.to_vec(),
        vec!["password"],
        Box::new(OnlyPassword {
            user: "alice",
            pw: "hunter2",
        }),
    );
    let _ = s.on_packet(
        &super::message::ServiceRequest {
            service: "ssh-userauth".into(),
        }
        .encode(),
    );
    let req = UserauthRequest {
        user: "alice".into(),
        service: "ssh-connection".into(),
        method: AuthMethodPayload::Password {
            new_password: None,
            password: "wrong".into(),
        },
    }
    .encode();
    let step = s.on_packet(&req).unwrap();
    match step {
        ServerStep::Send(p) => {
            let f = UserauthFailure::decode(&p).unwrap();
            assert_eq!(f.continuations, vec!["password".to_string()]);
        }
        _ => panic!("expected Send(failure)"),
    }
}

#[test]
fn server_malformed_payload() {
    let mut s = ServerAuth::new(TEST_SID.to_vec(), vec![], Box::new(AlwaysReject));
    assert!(s.on_packet(&[]).is_err());
    assert!(s.on_packet(&[99]).is_err());
}

#[test]
fn server_publickey_bad_signature_emits_failure() {
    let hk = Ed25519HostKey::from_seed(TEST_SEED);
    let public_blob = hk.public_blob();
    let bad_sig = {
        use crate::format::Writer;
        let mut w = Writer::new();
        w.write_string(b"ssh-ed25519");
        w.write_string(&[0u8; 64]);
        w.into_vec()
    };

    let mut s = ServerAuth::new(
        TEST_SID.to_vec(),
        vec!["publickey"],
        Box::new(OnlyPublicKey),
    );
    let _ = s.on_packet(
        &super::message::ServiceRequest {
            service: "ssh-userauth".into(),
        }
        .encode(),
    );
    let req = UserauthRequest {
        user: "alice".into(),
        service: "ssh-connection".into(),
        method: AuthMethodPayload::PublicKey {
            signature_present: true,
            algorithm: "ssh-ed25519".into(),
            public_blob,
            signature: Some(bad_sig),
        },
    }
    .encode();
    let step = s.on_packet(&req).unwrap();
    match step {
        ServerStep::Send(p) => {
            UserauthFailure::decode(&p).unwrap();
        }
        _ => panic!("expected Send(failure)"),
    }
}

#[test]
fn server_publickey_good_signature_emits_success() {
    let hk = Ed25519HostKey::from_seed(TEST_SEED);
    let public_blob = hk.public_blob();
    let signed_data = super::message::publickey_signed_data(
        TEST_SID,
        "alice",
        "ssh-connection",
        "ssh-ed25519",
        &public_blob,
    );
    let sig = hk.sign(&signed_data).unwrap();

    let mut s = ServerAuth::new(
        TEST_SID.to_vec(),
        vec!["publickey"],
        Box::new(OnlyPublicKey),
    );
    let _ = s.on_packet(
        &super::message::ServiceRequest {
            service: "ssh-userauth".into(),
        }
        .encode(),
    );
    let req = UserauthRequest {
        user: "alice".into(),
        service: "ssh-connection".into(),
        method: AuthMethodPayload::PublicKey {
            signature_present: true,
            algorithm: "ssh-ed25519".into(),
            public_blob,
            signature: Some(sig),
        },
    }
    .encode();
    let step = s.on_packet(&req).unwrap();
    match step {
        ServerStep::Authenticated { user, .. } => assert_eq!(user, "alice"),
        _ => panic!("expected Authenticated"),
    }
}

#[test]
fn server_publickey_probe_replies_pk_ok() {
    let hk = Ed25519HostKey::from_seed(TEST_SEED);
    let public_blob = hk.public_blob();

    let mut s = ServerAuth::new(
        TEST_SID.to_vec(),
        vec!["publickey"],
        Box::new(OnlyPublicKey),
    );
    let _ = s.on_packet(
        &super::message::ServiceRequest {
            service: "ssh-userauth".into(),
        }
        .encode(),
    );
    let req = UserauthRequest {
        user: "alice".into(),
        service: "ssh-connection".into(),
        method: AuthMethodPayload::PublicKey {
            signature_present: false,
            algorithm: "ssh-ed25519".into(),
            public_blob: public_blob.clone(),
            signature: None,
        },
    }
    .encode();
    let step = s.on_packet(&req).unwrap();
    match step {
        ServerStep::Send(p) => {
            let pk_ok = UserauthPkOk::decode(&p).unwrap();
            assert_eq!(pk_ok.algorithm, "ssh-ed25519");
            assert_eq!(pk_ok.public_blob, public_blob);
        }
        _ => panic!("expected Send(pk_ok)"),
    }
}

#[test]
fn end_to_end_password_loopback() {
    let mut c = ClientAuth::new("alice", TEST_SID.to_vec());
    c.add_credential(ClientCredential::Password("hunter2".into()));

    let mut s = ServerAuth::new(
        TEST_SID.to_vec(),
        vec!["password"],
        Box::new(OnlyPassword {
            user: "alice",
            pw: "hunter2",
        }),
    );

    let sreq = c.start();
    let saccept = match s.on_packet(&sreq).unwrap() {
        ServerStep::Send(p) => p,
        _ => panic!(),
    };
    let pwreq = match c.on_packet(&saccept).unwrap() {
        ClientStep::Send(p) => p,
        _ => panic!(),
    };
    let success_payload = match s.on_packet(&pwreq).unwrap() {
        ServerStep::Authenticated { payload, user } => {
            assert_eq!(user, "alice");
            payload
        }
        _ => panic!(),
    };
    let done = c.on_packet(&success_payload).unwrap();
    assert!(matches!(done, ClientStep::Success));
}

#[test]
fn end_to_end_publickey_loopback() {
    let mut c = ClientAuth::new("alice", TEST_SID.to_vec());
    c.add_credential(ClientCredential::PublicKey(Box::new(
        Ed25519HostKey::from_seed(TEST_SEED),
    )));

    let mut s = ServerAuth::new(
        TEST_SID.to_vec(),
        vec!["publickey"],
        Box::new(OnlyPublicKey),
    );

    let sreq = c.start();
    let saccept = match s.on_packet(&sreq).unwrap() {
        ServerStep::Send(p) => p,
        _ => panic!(),
    };
    let probe = match c.on_packet(&saccept).unwrap() {
        ClientStep::Send(p) => p,
        _ => panic!(),
    };
    let pk_ok = match s.on_packet(&probe).unwrap() {
        ServerStep::Send(p) => p,
        _ => panic!(),
    };
    let signed = match c.on_packet(&pk_ok).unwrap() {
        ClientStep::Send(p) => p,
        _ => panic!(),
    };
    let success_payload = match s.on_packet(&signed).unwrap() {
        ServerStep::Authenticated { payload, .. } => payload,
        _ => panic!(),
    };
    let done = c.on_packet(&success_payload).unwrap();
    assert!(matches!(done, ClientStep::Success));
}

#[test]
fn auth_attempt_password_debug_is_redacted() {
    let a = AuthAttempt::Password {
        user: "alice".into(),
        password: "the-actual-secret".into(),
    };
    let s = alloc::format!("{a:?}");
    assert!(
        !s.contains("the-actual-secret"),
        "password leaked in Debug output: {s}"
    );
    assert!(
        s.contains("redacted"),
        "redaction marker missing in Debug output: {s}"
    );
}

#[test]
fn end_to_end_kbdint_loopback() {
    struct KbdAuth;
    impl Authenticator for KbdAuth {
        fn evaluate(&mut self, attempt: AuthAttempt) -> AuthDecision {
            match attempt {
                AuthAttempt::KeyboardInteractive { .. } => AuthDecision::InteractiveRequest {
                    name: "Login".into(),
                    instruction: "".into(),
                    prompts: vec![("Password: ".into(), false)],
                },
                _ => AuthDecision::Reject,
            }
        }
        fn evaluate_interactive(&mut self, _user: &str, responses: Vec<String>) -> AuthDecision {
            if responses.first().map(|s| s.as_str()) == Some("hunter2") {
                AuthDecision::Accept
            } else {
                AuthDecision::Reject
            }
        }
    }

    let mut c = ClientAuth::new("alice", TEST_SID.to_vec());
    c.add_credential(ClientCredential::KeyboardInteractive(Box::new(
        StaticKbdResponder {
            answers: vec!["hunter2".into()],
        },
    )));

    let mut s = ServerAuth::new(
        TEST_SID.to_vec(),
        vec!["keyboard-interactive"],
        Box::new(KbdAuth),
    );

    let sreq = c.start();
    let saccept = match s.on_packet(&sreq).unwrap() {
        ServerStep::Send(p) => p,
        _ => panic!(),
    };
    let kreq = match c.on_packet(&saccept).unwrap() {
        ClientStep::Send(p) => p,
        _ => panic!(),
    };
    let info_req = match s.on_packet(&kreq).unwrap() {
        ServerStep::Send(p) => p,
        _ => panic!(),
    };
    UserauthInfoRequest::decode(&info_req).unwrap();
    let info_resp = match c.on_packet(&info_req).unwrap() {
        ClientStep::Send(p) => p,
        _ => panic!(),
    };
    let success_payload = match s.on_packet(&info_resp).unwrap() {
        ServerStep::Authenticated { payload, .. } => payload,
        _ => panic!(),
    };
    let done = c.on_packet(&success_payload).unwrap();
    assert!(matches!(done, ClientStep::Success));
}
