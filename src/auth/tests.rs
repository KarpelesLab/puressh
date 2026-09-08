//! Integration tests for the client/server state machines.

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use crate::hostkey::{Ed25519HostKey, HostKey, RsaSha1HostKey};

use super::client::{ClientAuth, ClientCredential, ClientStep, KeyboardInteractiveResponder};
use super::message::{
    AuthMethodPayload, ServiceAccept, UserauthBanner, UserauthFailure, UserauthInfoRequest,
    UserauthPkOk, UserauthRequest, encode_success,
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
        ServerStep::Authenticated { user, payload, .. } => {
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
        ServerStep::Authenticated { payload, user, .. } => {
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

struct AlwaysAccept;
impl Authenticator for AlwaysAccept {
    fn evaluate(&mut self, _attempt: AuthAttempt) -> AuthDecision {
        AuthDecision::Accept
    }
}

#[test]
fn server_rejects_none_by_default_even_when_authenticator_accepts() {
    // The default-on `none` gate must short-circuit `AuthAttempt::None`
    // *before* the authenticator runs. An accept-everything backend used
    // to be enough to let an unauthenticated client in — that footgun
    // is the whole reason the gate exists.
    let mut s = ServerAuth::new(TEST_SID.to_vec(), vec!["password"], Box::new(AlwaysAccept));
    let _ = s
        .on_packet(
            &super::message::ServiceRequest {
                service: "ssh-userauth".into(),
            }
            .encode(),
        )
        .unwrap();
    let req = UserauthRequest {
        user: "alice".into(),
        service: "ssh-connection".into(),
        method: AuthMethodPayload::None,
    }
    .encode();
    let step = s.on_packet(&req).unwrap();
    match step {
        ServerStep::Send(p) => {
            UserauthFailure::decode(&p).unwrap();
        }
        _ => panic!("expected Send(failure), got something else"),
    }
}

#[test]
fn server_accepts_none_only_when_opted_in() {
    // Same flow as above, but `allow_none(true)` lets the authenticator
    // see the `None` attempt and answer `Accept`. This is the only path
    // where `none` should ever succeed.
    let mut s = ServerAuth::new(TEST_SID.to_vec(), vec!["password"], Box::new(AlwaysAccept));
    s.allow_none(true);
    let _ = s
        .on_packet(
            &super::message::ServiceRequest {
                service: "ssh-userauth".into(),
            }
            .encode(),
        )
        .unwrap();
    let req = UserauthRequest {
        user: "alice".into(),
        service: "ssh-connection".into(),
        method: AuthMethodPayload::None,
    }
    .encode();
    let step = s.on_packet(&req).unwrap();
    match step {
        ServerStep::Authenticated { user, .. } => assert_eq!(user, "alice"),
        _ => panic!("expected Authenticated"),
    }
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

#[test]
fn end_to_end_kbdint_two_prompts_wrong_then_right() {
    // A 2-prompt keyboard-interactive round; the first attempt is wrong, the
    // server fails it (still offering keyboard-interactive), and a second round
    // with the right answers succeeds — all on one connection.
    struct TwoPromptAuth;
    impl Authenticator for TwoPromptAuth {
        fn evaluate(&mut self, attempt: AuthAttempt) -> AuthDecision {
            match attempt {
                AuthAttempt::KeyboardInteractive { .. } => AuthDecision::InteractiveRequest {
                    name: "MFA".into(),
                    instruction: "enter token and PIN".into(),
                    prompts: vec![("Token: ".into(), true), ("PIN: ".into(), false)],
                },
                _ => AuthDecision::Reject,
            }
        }
        fn evaluate_interactive(&mut self, _user: &str, responses: Vec<String>) -> AuthDecision {
            let ok = responses.first().map(|s| s.as_str()) == Some("token-123")
                && responses.get(1).map(|s| s.as_str()) == Some("4242");
            if ok {
                AuthDecision::Accept
            } else {
                AuthDecision::Reject
            }
        }
    }

    // A responder that gives wrong answers (round 1).
    struct WrongResponder;
    impl KeyboardInteractiveResponder for WrongResponder {
        fn respond(
            &mut self,
            _name: &str,
            _instruction: &str,
            prompts: &[(String, bool)],
        ) -> Vec<String> {
            assert_eq!(prompts.len(), 2);
            vec!["nope".into(), "0000".into()]
        }
    }
    // A responder with the right answers (round 2). The driver advances to the
    // next credential after the first kbdint failure (server still offers it).
    struct RightResponder;
    impl KeyboardInteractiveResponder for RightResponder {
        fn respond(
            &mut self,
            _name: &str,
            _instruction: &str,
            _prompts: &[(String, bool)],
        ) -> Vec<String> {
            vec!["token-123".into(), "4242".into()]
        }
    }
    let mut c = ClientAuth::new("alice", TEST_SID.to_vec());
    c.add_credential(ClientCredential::KeyboardInteractive(Box::new(
        WrongResponder,
    )));
    c.add_credential(ClientCredential::KeyboardInteractive(Box::new(
        RightResponder,
    )));

    let mut s = ServerAuth::new(
        TEST_SID.to_vec(),
        vec!["keyboard-interactive"],
        Box::new(TwoPromptAuth),
    );

    let sreq = c.start();
    let saccept = match s.on_packet(&sreq).unwrap() {
        ServerStep::Send(p) => p,
        _ => panic!(),
    };
    // Round 1: client requests kbdint, server sends INFO_REQUEST.
    let kreq = match c.on_packet(&saccept).unwrap() {
        ClientStep::Send(p) => p,
        _ => panic!("kbdint request"),
    };
    let info = match s.on_packet(&kreq).unwrap() {
        ServerStep::Send(p) => p,
        _ => panic!("info request"),
    };
    let resp = match c.on_packet(&info).unwrap() {
        ClientStep::Send(p) => p,
        _ => panic!("info response"),
    };
    // Wrong answers ⇒ server fails (still offering kbdint).
    let failure = match s.on_packet(&resp).unwrap() {
        ServerStep::Send(p) => p,
        _ => panic!("expected failure for wrong answers"),
    };
    UserauthFailure::decode(&failure).unwrap();
    // Round 2: client advances to the next kbdint credential.
    let kreq2 = match c.on_packet(&failure).unwrap() {
        ClientStep::Send(p) => p,
        _ => panic!("second kbdint request"),
    };
    let info2 = match s.on_packet(&kreq2).unwrap() {
        ServerStep::Send(p) => p,
        _ => panic!("second info request"),
    };
    let resp2 = match c.on_packet(&info2).unwrap() {
        ClientStep::Send(p) => p,
        _ => panic!("second info response"),
    };
    let success = match s.on_packet(&resp2).unwrap() {
        ServerStep::Authenticated { payload, .. } => payload,
        _ => panic!("expected Authenticated on right answers"),
    };
    assert!(matches!(
        c.on_packet(&success).unwrap(),
        ClientStep::Success
    ));
}

/// An authenticator that requires the `publickey,password` chain: publickey
/// then password (set-membership, order-independent), accepting only when both
/// have succeeded.
struct ChainAuth {
    user: &'static str,
    pw: &'static str,
    satisfied: Vec<&'static str>,
}
impl ChainAuth {
    fn record_and_decide(&mut self, method: &'static str) -> AuthDecision {
        if !self.satisfied.contains(&method) {
            self.satisfied.push(method);
        }
        let need = ["publickey", "password"];
        if need.iter().all(|m| self.satisfied.contains(m)) {
            AuthDecision::Accept
        } else {
            let still: Vec<String> = need
                .iter()
                .filter(|m| !self.satisfied.contains(*m))
                .map(|m| (*m).to_string())
                .collect();
            AuthDecision::PartialAccept {
                still_required: still,
            }
        }
    }
}
impl Authenticator for ChainAuth {
    fn evaluate(&mut self, attempt: AuthAttempt) -> AuthDecision {
        match attempt {
            AuthAttempt::PublicKey {
                probe_only,
                verified,
                ..
            } => {
                if probe_only {
                    // Probe just signals the client to sign; doesn't satisfy.
                    AuthDecision::Accept
                } else if verified {
                    self.record_and_decide("publickey")
                } else {
                    AuthDecision::Reject
                }
            }
            AuthAttempt::Password { user, password } => {
                if user == self.user && password == self.pw {
                    self.record_and_decide("password")
                } else {
                    AuthDecision::Reject
                }
            }
            _ => AuthDecision::Reject,
        }
    }
}

#[test]
fn end_to_end_multifactor_publickey_then_password() {
    // The client offers a publickey credential then a password; the server
    // requires both (a `publickey,password` chain). The publickey leg should
    // PartialAccept (partial_success), the client should advance to password
    // on the SAME connection (no second SERVICE_REQUEST), and the server then
    // Accepts.
    let mut c = ClientAuth::new("alice", TEST_SID.to_vec());
    c.add_credential(ClientCredential::PublicKey(Box::new(
        Ed25519HostKey::from_seed(TEST_SEED),
    )));
    c.add_credential(ClientCredential::Password("hunter2".into()));

    let mut s = ServerAuth::new(
        TEST_SID.to_vec(),
        vec!["publickey", "password"],
        Box::new(ChainAuth {
            user: "alice",
            pw: "hunter2",
            satisfied: Vec::new(),
        }),
    );

    // Count SERVICE_REQUESTs the server sees — must be exactly one.
    let mut service_requests = 0usize;

    let sreq = c.start();
    if sreq.first() == Some(&super::message::SSH_MSG_SERVICE_REQUEST) {
        service_requests += 1;
    }
    let saccept = match s.on_packet(&sreq).unwrap() {
        ServerStep::Send(p) => p,
        _ => panic!("expected service accept"),
    };

    // Client emits the publickey probe.
    let probe = match c.on_packet(&saccept).unwrap() {
        ClientStep::Send(p) => p,
        _ => panic!("expected probe"),
    };
    // Server replies PK_OK.
    let pk_ok = match s.on_packet(&probe).unwrap() {
        ServerStep::Send(p) => p,
        _ => panic!("expected pk_ok"),
    };
    // Client sends the signed request.
    let signed = match c.on_packet(&pk_ok).unwrap() {
        ClientStep::Send(p) => p,
        _ => panic!("expected signed pk"),
    };
    // Server PartialAccepts (partial_success) — the publickey factor is in.
    let partial = match s.on_packet(&signed).unwrap() {
        ServerStep::Send(p) => p,
        _ => panic!("expected partial failure (Send), not immediate Accept"),
    };
    let pf = UserauthFailure::decode(&partial).unwrap();
    assert!(
        pf.partial_success,
        "publickey leg must be a partial success"
    );
    assert_eq!(pf.continuations, vec!["password".to_string()]);

    // Client advances to the password credential on the SAME connection.
    let pw_req = match c.on_packet(&partial).unwrap() {
        ClientStep::Send(p) => p,
        _ => panic!("expected password request"),
    };
    // It must NOT be another SERVICE_REQUEST.
    assert_ne!(
        pw_req.first(),
        Some(&super::message::SSH_MSG_SERVICE_REQUEST),
        "client must not re-send SERVICE_REQUEST mid-userauth"
    );
    let parsed = UserauthRequest::decode(&pw_req).unwrap();
    assert_eq!(parsed.method.method_name(), "password");

    // Server now Accepts (both factors satisfied).
    let success = match s.on_packet(&pw_req).unwrap() {
        ServerStep::Authenticated { payload, user, .. } => {
            assert_eq!(user, "alice");
            payload
        }
        _ => panic!("expected Authenticated"),
    };
    let done = c.on_packet(&success).unwrap();
    assert!(matches!(done, ClientStep::Success));
    assert_eq!(service_requests, 1, "exactly one SERVICE_REQUEST expected");
}

#[test]
fn client_skips_publickey_not_in_server_sig_algs() {
    // ssh-ed25519 key, server-sig-algs advertises rsa-sha2-{256,512} only.
    // The client should skip the ed25519 credential entirely (no probe
    // emitted) and fall through to the next credential — here, password.
    let hk = Box::new(Ed25519HostKey::from_seed(TEST_SEED));
    let mut c = ClientAuth::new("alice", TEST_SID.to_vec());
    c.set_server_sig_algs("rsa-sha2-512,rsa-sha2-256");
    c.add_credential(ClientCredential::PublicKey(hk));
    c.add_credential(ClientCredential::Password("hunter2".into()));

    let _ = c.start();
    let step = c
        .on_packet(
            &ServiceAccept {
                service: "ssh-userauth".into(),
            }
            .encode(),
        )
        .unwrap();
    let payload = match step {
        ClientStep::Send(p) => p,
        _ => panic!("expected Send"),
    };
    // The first emitted request should be the password fallback, not the
    // disallowed-by-server-sig-algs publickey probe.
    let parsed = UserauthRequest::decode(&payload).unwrap();
    assert!(
        matches!(parsed.method, AuthMethodPayload::Password { .. }),
        "expected password fallback, got non-password method",
    );
}

#[test]
fn client_accepts_publickey_listed_in_server_sig_algs() {
    // ssh-ed25519 key, server-sig-algs includes it: probe must go out.
    let hk = Box::new(Ed25519HostKey::from_seed(TEST_SEED));
    let mut c = ClientAuth::new("alice", TEST_SID.to_vec());
    c.set_server_sig_algs("ssh-ed25519,rsa-sha2-512");
    c.add_credential(ClientCredential::PublicKey(hk));

    let _ = c.start();
    let step = c
        .on_packet(
            &ServiceAccept {
                service: "ssh-userauth".into(),
            }
            .encode(),
        )
        .unwrap();
    let payload = match step {
        ClientStep::Send(p) => p,
        _ => panic!("expected Send"),
    };
    let parsed = UserauthRequest::decode(&payload).unwrap();
    match parsed.method {
        AuthMethodPayload::PublicKey {
            signature_present,
            algorithm,
            ..
        } => {
            assert!(!signature_present, "first publickey msg is a probe");
            assert_eq!(algorithm, "ssh-ed25519");
        }
        _ => panic!("expected publickey probe"),
    }
}

#[test]
fn ssh_rsa_credential_with_server_advertising_rsa_sha2_512_signs_with_512() {
    // The user supplies an `ssh-rsa` (SHA-1) credential. The server's
    // server-sig-algs lists only `rsa-sha2-{256,512}`. The old W4
    // filter would have skipped this credential entirely; with the
    // upgrade hook it should be promoted to `rsa-sha2-512` (the
    // strongest variant the server advertises) and the publickey
    // probe must go out under the new name.
    use purecrypto::bignum::BoxedUint;
    // Same vector the hostkey tests use — only the public components
    // are needed to exercise the credential walk; the probe is sent
    // before any sign() call.
    let mut n_bytes = vec![0u8; 256];
    n_bytes[0] = 0xc0;
    for (i, b) in n_bytes.iter_mut().enumerate().skip(1) {
        *b = (i as u8).wrapping_mul(31).wrapping_add(7) | 0x01;
    }
    let n = BoxedUint::from_be_bytes(&n_bytes);
    let e = BoxedUint::from_u64(65537);
    let rsa_sha1 = Box::new(RsaSha1HostKey::from_public_components(n, e).unwrap());

    let mut c = ClientAuth::new("alice", TEST_SID.to_vec());
    c.set_server_sig_algs("rsa-sha2-512,rsa-sha2-256");
    c.add_credential(ClientCredential::PublicKey(rsa_sha1));

    let _ = c.start();
    let step = c
        .on_packet(
            &ServiceAccept {
                service: "ssh-userauth".into(),
            }
            .encode(),
        )
        .unwrap();
    let payload = match step {
        ClientStep::Send(p) => p,
        _ => panic!("expected the upgraded publickey probe, got non-Send"),
    };
    let parsed = UserauthRequest::decode(&payload).unwrap();
    match parsed.method {
        AuthMethodPayload::PublicKey {
            signature_present,
            algorithm,
            ..
        } => {
            assert!(!signature_present, "first publickey msg is a probe");
            assert_eq!(
                algorithm, "rsa-sha2-512",
                "ssh-rsa credential must be upgraded to rsa-sha2-512",
            );
        }
        _ => panic!("expected upgraded publickey probe"),
    }
}

#[test]
fn ssh_rsa_credential_upgrades_to_256_when_only_256_advertised() {
    use purecrypto::bignum::BoxedUint;
    let mut n_bytes = vec![0u8; 256];
    n_bytes[0] = 0xc0;
    for (i, b) in n_bytes.iter_mut().enumerate().skip(1) {
        *b = (i as u8).wrapping_mul(31).wrapping_add(7) | 0x01;
    }
    let n = BoxedUint::from_be_bytes(&n_bytes);
    let e = BoxedUint::from_u64(65537);
    let rsa_sha1 = Box::new(RsaSha1HostKey::from_public_components(n, e).unwrap());

    let mut c = ClientAuth::new("alice", TEST_SID.to_vec());
    c.set_server_sig_algs("rsa-sha2-256,ssh-ed25519");
    c.add_credential(ClientCredential::PublicKey(rsa_sha1));

    let _ = c.start();
    let step = c
        .on_packet(
            &ServiceAccept {
                service: "ssh-userauth".into(),
            }
            .encode(),
        )
        .unwrap();
    let payload = match step {
        ClientStep::Send(p) => p,
        _ => panic!("expected probe"),
    };
    let parsed = UserauthRequest::decode(&payload).unwrap();
    match parsed.method {
        AuthMethodPayload::PublicKey { algorithm, .. } => {
            assert_eq!(algorithm, "rsa-sha2-256");
        }
        _ => panic!("expected publickey"),
    }
}

#[test]
fn ssh_rsa_credential_skipped_when_server_advertises_neither_sha2() {
    // Server lists only ssh-ed25519 — the RSA credential has no
    // upgrade target and must be dropped, falling through to the
    // password fallback rather than emitting an ssh-rsa probe.
    use purecrypto::bignum::BoxedUint;
    let mut n_bytes = vec![0u8; 256];
    n_bytes[0] = 0xc0;
    for (i, b) in n_bytes.iter_mut().enumerate().skip(1) {
        *b = (i as u8).wrapping_mul(31).wrapping_add(7) | 0x01;
    }
    let n = BoxedUint::from_be_bytes(&n_bytes);
    let e = BoxedUint::from_u64(65537);
    let rsa_sha1 = Box::new(RsaSha1HostKey::from_public_components(n, e).unwrap());

    let mut c = ClientAuth::new("alice", TEST_SID.to_vec());
    c.set_server_sig_algs("ssh-ed25519");
    c.add_credential(ClientCredential::PublicKey(rsa_sha1));
    c.add_credential(ClientCredential::Password("hunter2".into()));

    let _ = c.start();
    let step = c
        .on_packet(
            &ServiceAccept {
                service: "ssh-userauth".into(),
            }
            .encode(),
        )
        .unwrap();
    let payload = match step {
        ClientStep::Send(p) => p,
        _ => panic!("expected Send"),
    };
    let parsed = UserauthRequest::decode(&payload).unwrap();
    assert!(
        matches!(parsed.method, AuthMethodPayload::Password { .. }),
        "expected password fallback after RSA credential dropped",
    );
}

#[test]
fn client_unset_server_sig_algs_does_not_filter() {
    // No call to set_server_sig_algs — every credential is tried.
    let hk = Box::new(Ed25519HostKey::from_seed(TEST_SEED));
    let mut c = ClientAuth::new("alice", TEST_SID.to_vec());
    c.add_credential(ClientCredential::PublicKey(hk));

    let _ = c.start();
    let step = c
        .on_packet(
            &ServiceAccept {
                service: "ssh-userauth".into(),
            }
            .encode(),
        )
        .unwrap();
    let payload = match step {
        ClientStep::Send(p) => p,
        _ => panic!("expected Send"),
    };
    let parsed = UserauthRequest::decode(&payload).unwrap();
    assert!(matches!(parsed.method, AuthMethodPayload::PublicKey { .. }));
}

// --- Finding B1: keyboard-interactive response count must equal prompt count.
#[test]
fn server_kbdint_wrong_response_count_rejected() {
    // The server issues a single-prompt InteractiveRequest; a forged
    // INFO_RESPONSE carrying two responses (count != prompt count, RFC 4256
    // §3.4) must be treated as a failed attempt — emit_failure — and the
    // authenticator's evaluate_interactive must never be consulted.
    struct OnePromptAuth {
        interactive_called: bool,
    }
    impl Authenticator for OnePromptAuth {
        fn evaluate(&mut self, attempt: AuthAttempt) -> AuthDecision {
            match attempt {
                AuthAttempt::KeyboardInteractive { .. } => AuthDecision::InteractiveRequest {
                    name: "Login".into(),
                    instruction: String::new(),
                    prompts: vec![("Password: ".into(), false)],
                },
                _ => AuthDecision::Reject,
            }
        }
        fn evaluate_interactive(&mut self, _user: &str, _responses: Vec<String>) -> AuthDecision {
            self.interactive_called = true;
            AuthDecision::Accept
        }
    }

    let mut s = ServerAuth::new(
        TEST_SID.to_vec(),
        vec!["keyboard-interactive"],
        Box::new(OnePromptAuth {
            interactive_called: false,
        }),
    );
    let _ = s.on_packet(
        &super::message::ServiceRequest {
            service: "ssh-userauth".into(),
        }
        .encode(),
    );
    let kreq = UserauthRequest {
        user: "alice".into(),
        service: "ssh-connection".into(),
        method: AuthMethodPayload::KeyboardInteractive {
            language_tag: String::new(),
            submethods: String::new(),
        },
    }
    .encode();
    // Server emits a one-prompt InfoRequest.
    let info_req = match s.on_packet(&kreq).unwrap() {
        ServerStep::Send(p) => p,
        _ => panic!("expected InfoRequest Send"),
    };
    let ir = UserauthInfoRequest::decode(&info_req).unwrap();
    assert_eq!(ir.prompts.len(), 1);
    // Forge a two-response INFO_RESPONSE (wrong count).
    let bad_resp = super::message::UserauthInfoResponse {
        responses: vec!["a".into(), "b".into()],
    }
    .encode();
    let step = s.on_packet(&bad_resp).unwrap();
    match step {
        ServerStep::Send(p) => {
            // It is a USERAUTH_FAILURE, not a success.
            UserauthFailure::decode(&p).unwrap();
        }
        _ => panic!("expected Send(failure)"),
    }
}

// --- Finding B2: a username change mid-userauth disconnects.
#[test]
fn server_username_change_disconnects() {
    let mut s = ServerAuth::new(TEST_SID.to_vec(), vec!["password"], Box::new(AlwaysReject));
    let _ = s.on_packet(
        &super::message::ServiceRequest {
            service: "ssh-userauth".into(),
        }
        .encode(),
    );
    // First request pins the username to "alice" (rejected, but pins).
    let req_alice = UserauthRequest {
        user: "alice".into(),
        service: "ssh-connection".into(),
        method: AuthMethodPayload::Password {
            new_password: None,
            password: "x".into(),
        },
    }
    .encode();
    assert!(matches!(
        s.on_packet(&req_alice).unwrap(),
        ServerStep::Send(_)
    ));
    // A second request that switches to "bob" must disconnect.
    let req_bob = UserauthRequest {
        user: "bob".into(),
        service: "ssh-connection".into(),
        method: AuthMethodPayload::Password {
            new_password: None,
            password: "x".into(),
        },
    }
    .encode();
    match s.on_packet(&req_bob).unwrap() {
        ServerStep::Disconnect(reason) => {
            assert_eq!(reason, "auth: username changed mid-authentication");
        }
        _ => panic!("expected Disconnect"),
    }
}

// ---------------------------------------------------------------------------
// Certificate userauth helpers shared by the cert-hardening tests below.
// ---------------------------------------------------------------------------

/// A "now" inside the fixtures' 2020..2099 validity window.
const CERT_NOW: u64 = 1_700_000_000;

/// Accepts any *verified* publickey attempt (and any probe) — the trust
/// decision is not what these tests exercise.
struct AcceptVerified;
impl Authenticator for AcceptVerified {
    fn evaluate(&mut self, attempt: AuthAttempt) -> AuthDecision {
        match attempt {
            AuthAttempt::PublicKey {
                probe_only,
                verified,
                ..
            } if probe_only || verified => AuthDecision::Accept,
            _ => AuthDecision::Reject,
        }
    }
}

fn cert_server() -> ServerAuth {
    let mut s = ServerAuth::new(
        TEST_SID.to_vec(),
        vec!["publickey"],
        Box::new(AcceptVerified),
    );
    s.set_now(CERT_NOW);
    let _ = s.on_packet(
        &super::message::ServiceRequest {
            service: "ssh-userauth".into(),
        }
        .encode(),
    );
    s
}

/// A signed publickey USERAUTH_REQUEST for `user` offering `algorithm` /
/// `blob`, with the signature produced by `signer`.
fn signed_pubkey_request(
    user: &str,
    algorithm: &str,
    blob: &[u8],
    signer: &dyn HostKey,
) -> Vec<u8> {
    let signed =
        super::message::publickey_signed_data(TEST_SID, user, "ssh-connection", algorithm, blob);
    let sig = signer.sign(&signed).unwrap();
    UserauthRequest {
        user: user.into(),
        service: "ssh-connection".into(),
        method: AuthMethodPayload::PublicKey {
            signature_present: true,
            algorithm: algorithm.into(),
            public_blob: blob.to_vec(),
            signature: Some(sig),
        },
    }
    .encode()
}

fn assert_failure(step: ServerStep) {
    match step {
        ServerStep::Send(p) => {
            UserauthFailure::decode(&p).expect("USERAUTH_FAILURE");
        }
        ServerStep::Authenticated { .. } => panic!("must not authenticate"),
        ServerStep::Disconnect(r) => panic!("unexpected disconnect: {r}"),
    }
}

/// Build a signed ed25519 user certificate blob in process, wrapping the
/// public key of `user_key` and signed by `ca`. `critical` is the sorted
/// list of `(name, raw payload)` critical options.
fn build_ed25519_user_cert(
    ca: &Ed25519HostKey,
    user_key: &Ed25519HostKey,
    principals: &[&str],
    critical: &[(&str, Vec<u8>)],
) -> Vec<u8> {
    use crate::format::Writer;
    let mut w = Writer::new();
    w.write_string(b"ssh-ed25519-cert-v01@openssh.com");
    w.write_string(&[0x42u8; 16]); // nonce
    w.write_string(&user_key.public_bytes());
    w.write_u64(7); // serial
    w.write_u32(1); // type = user
    w.write_string(b"unit"); // key id
    let mut princ = Writer::new();
    for p in principals {
        princ.write_string(p.as_bytes());
    }
    w.write_string(&princ.into_vec());
    w.write_u64(0); // valid after
    w.write_u64(u64::MAX); // valid before
    let mut crit = Writer::new();
    for (name, data) in critical {
        crit.write_string(name.as_bytes());
        crit.write_string(data);
    }
    w.write_string(&crit.into_vec());
    w.write_string(b""); // extensions
    w.write_string(b""); // reserved
    w.write_string(&ca.public_blob()); // signature key
    let signed = w.into_vec();
    let signature = ca.sign(&signed).unwrap();
    let mut full = signed;
    let mut sw = Writer::new();
    sw.write_string(&signature);
    full.extend_from_slice(&sw.into_vec());
    full
}

fn ssh_string(s: &[u8]) -> Vec<u8> {
    let mut w = crate::format::Writer::new();
    w.write_string(s);
    w.into_vec()
}

// ---------------------------------------------------------------------------
// A5: malformed critical-option payloads fail closed.
// ---------------------------------------------------------------------------
#[test]
fn cert_userauth_malformed_force_command_fails_closed() {
    let ca = Ed25519HostKey::from_seed([0x11; 32]);
    let user_key = Ed25519HostKey::from_seed([0x22; 32]);

    // Positive control: a well-formed force-command is decoded into the caps.
    let cert = build_ed25519_user_cert(
        &ca,
        &user_key,
        &["alice"],
        &[("force-command", ssh_string(b"/usr/bin/uptime"))],
    );
    let mut s = cert_server();
    let req = signed_pubkey_request(
        "alice",
        "ssh-ed25519-cert-v01@openssh.com",
        &cert,
        &user_key,
    );
    match s.on_packet(&req).unwrap() {
        ServerStep::Authenticated { cert_caps, .. } => {
            let caps = cert_caps.expect("cert caps");
            assert_eq!(caps.force_command.as_deref(), Some("/usr/bin/uptime"));
        }
        _ => panic!("expected Authenticated"),
    }

    // A payload that is not a well-formed SSH string must reject the cert
    // (OpenSSH: "certificate has unparseable critical option") rather than
    // authenticate with `force_command: None`.
    for bad in [
        vec![0xffu8, 0xff, 0xff, 0xff],
        vec![0x00u8, 0x00, 0x00, 0x09, b'/', b'b', b'i', b'n'],
        Vec::new(),
    ] {
        let cert = build_ed25519_user_cert(
            &ca,
            &user_key,
            &["alice"],
            &[("force-command", bad.clone())],
        );
        let mut s = cert_server();
        let req = signed_pubkey_request(
            "alice",
            "ssh-ed25519-cert-v01@openssh.com",
            &cert,
            &user_key,
        );
        assert_failure(s.on_packet(&req).unwrap());
    }
    // Same for source-address.
    let cert = build_ed25519_user_cert(
        &ca,
        &user_key,
        &["alice"],
        &[("source-address", vec![0xffu8, 0xff, 0xff, 0xff])],
    );
    let mut s = cert_server();
    let req = signed_pubkey_request(
        "alice",
        "ssh-ed25519-cert-v01@openssh.com",
        &cert,
        &user_key,
    );
    assert_failure(s.on_packet(&req).unwrap());
}

// ---------------------------------------------------------------------------
// A4: certificate userauth binds the offered algorithm name to the cert type
// and to the signature algorithm.
// ---------------------------------------------------------------------------

/// Read a `tests/fixtures/cert/` file.
fn cert_fixture(name: &str) -> String {
    let path = format!(
        "{}/tests/fixtures/cert/{}",
        env!("CARGO_MANIFEST_DIR"),
        name
    );
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {path}: {e}"))
}

/// The decoded blob of a `*-cert.pub` fixture.
fn cert_fixture_blob(name: &str) -> Vec<u8> {
    let text = cert_fixture(name);
    let b64 = text.split_whitespace().nth(1).expect("base64 field");
    crate::key::base64::decode(b64.as_bytes()).expect("decode cert")
}

fn probe_pubkey_request(user: &str, algorithm: &str, blob: &[u8]) -> Vec<u8> {
    UserauthRequest {
        user: user.into(),
        service: "ssh-connection".into(),
        method: AuthMethodPayload::PublicKey {
            signature_present: false,
            algorithm: algorithm.into(),
            public_blob: blob.to_vec(),
            signature: None,
        },
    }
    .encode()
}

fn trim_zeros(b: &[u8]) -> &[u8] {
    let mut i = 0;
    while i + 1 < b.len() && b[i] == 0 {
        i += 1;
    }
    &b[i..]
}

/// The fixture RSA user key as `rsa-sha2-512` and `rsa-sha2-256` signers
/// over the same key material.
fn rsa_fixture_signers() -> (
    crate::hostkey::RsaSha2_512HostKey,
    crate::hostkey::RsaSha2_256HostKey,
) {
    use purecrypto::bignum::BoxedUint;
    let pem = cert_fixture("u_rsa");
    let key = crate::key::PrivateKey::parse_openssh_pem(&pem, None).unwrap();
    let crate::key::PrivateKey::Rsa { n, e, d, .. } = key else {
        panic!("fixture is not RSA");
    };
    let parts = || {
        (
            BoxedUint::from_be_bytes(trim_zeros(&n)),
            BoxedUint::from_be_bytes(trim_zeros(&e)),
            BoxedUint::from_be_bytes(trim_zeros(&d)),
        )
    };
    let (n1, e1, d1) = parts();
    let (n2, e2, d2) = parts();
    (
        crate::hostkey::RsaSha2_512HostKey::from_components(n1, e1, d1).unwrap(),
        crate::hostkey::RsaSha2_256HostKey::from_components(n2, e2, d2).unwrap(),
    )
}

#[test]
fn cert_userauth_rsa_sha512_name_with_sha512_signature_is_accepted() {
    // Positive control: the negotiated name and the signature agree.
    let cert = cert_fixture_blob("u_rsa-cert.pub");
    let (s512, _) = rsa_fixture_signers();
    let mut s = cert_server();
    let req = signed_pubkey_request("carol", "rsa-sha2-512-cert-v01@openssh.com", &cert, &s512);
    match s.on_packet(&req).unwrap() {
        ServerStep::Authenticated {
            user, cert_caps, ..
        } => {
            assert_eq!(user, "carol");
            assert!(cert_caps.is_some());
        }
        _ => panic!("expected Authenticated"),
    }
}

#[test]
fn cert_userauth_rsa_sha256_name_with_sha256_signature_is_accepted() {
    // `rsa-sha2-256-cert-v01@openssh.com` legitimately pins SHA-256.
    let cert = cert_fixture_blob("u_rsa-cert.pub");
    let (_, s256) = rsa_fixture_signers();
    let mut s = cert_server();
    let req = signed_pubkey_request("carol", "rsa-sha2-256-cert-v01@openssh.com", &cert, &s256);
    assert!(matches!(
        s.on_packet(&req).unwrap(),
        ServerStep::Authenticated { .. }
    ));
}

#[test]
fn cert_userauth_rejects_signature_algorithm_weaker_than_negotiated_name() {
    // Offer `rsa-sha2-512-cert-v01@openssh.com` but sign with a *genuine*
    // rsa-sha2-256 signature over the same key. Before the fix the verifier
    // was built from the signature blob's own name, so this was accepted.
    let cert = cert_fixture_blob("u_rsa-cert.pub");
    let (_, s256) = rsa_fixture_signers();
    let mut s = cert_server();
    let req = signed_pubkey_request("carol", "rsa-sha2-512-cert-v01@openssh.com", &cert, &s256);
    assert_failure(s.on_packet(&req).unwrap());
}

#[test]
fn cert_userauth_rejects_name_from_other_key_family() {
    // An ed25519 user cert offered under an RSA cert name (with a valid
    // ed25519 signature by its own key) must be refused — both the signed
    // step and the probe.
    let pem = cert_fixture("u_ed25519");
    let signer = crate::key::PrivateKey::parse_openssh_pem(&pem, None)
        .unwrap()
        .into_host_key()
        .unwrap();
    let cert = cert_fixture_blob("u_ed25519-cert.pub");

    let mut s = cert_server();
    let req = signed_pubkey_request(
        "alice",
        "rsa-sha2-512-cert-v01@openssh.com",
        &cert,
        signer.as_ref(),
    );
    assert_failure(s.on_packet(&req).unwrap());

    let mut s = cert_server();
    let probe = probe_pubkey_request("alice", "rsa-sha2-512-cert-v01@openssh.com", &cert);
    assert_failure(s.on_packet(&probe).unwrap());

    // And under its own name it still works, signed and probed.
    let mut s = cert_server();
    let probe = probe_pubkey_request("alice", "ssh-ed25519-cert-v01@openssh.com", &cert);
    match s.on_packet(&probe).unwrap() {
        ServerStep::Send(p) => {
            UserauthPkOk::decode(&p).expect("PK_OK");
        }
        _ => panic!("expected PK_OK"),
    }
    let req = signed_pubkey_request(
        "alice",
        "ssh-ed25519-cert-v01@openssh.com",
        &cert,
        signer.as_ref(),
    );
    assert!(matches!(
        s.on_packet(&req).unwrap(),
        ServerStep::Authenticated { .. }
    ));
}

#[test]
fn cert_userauth_rejects_unknown_cert_name() {
    let pem = cert_fixture("u_ed25519");
    let signer = crate::key::PrivateKey::parse_openssh_pem(&pem, None)
        .unwrap()
        .into_host_key()
        .unwrap();
    let cert = cert_fixture_blob("u_ed25519-cert.pub");
    let mut s = cert_server();
    let req = signed_pubkey_request(
        "alice",
        "ssh-dss-cert-v01@openssh.com",
        &cert,
        signer.as_ref(),
    );
    assert_failure(s.on_packet(&req).unwrap());
}

// ---------------------------------------------------------------------------
// A2: a first request rejected as "method not advertised" must still pin the
// username, so a second request under a different name is a username change
// (disconnect), not a fresh evaluation under the first user's policy.
// ---------------------------------------------------------------------------
#[test]
fn server_unadvertised_rejection_pins_username() {
    // Advertised set: password only. Request 1 uses a bogus method for
    // user "alice" and is rejected by the server loop via
    // `reject_unadvertised` (never reaching `on_packet`).
    let mut s = ServerAuth::new(TEST_SID.to_vec(), vec!["password"], Box::new(AlwaysReject));
    let _ = s.on_packet(
        &super::message::ServiceRequest {
            service: "ssh-userauth".into(),
        }
        .encode(),
    );
    let req_alice = UserauthRequest {
        user: "alice".into(),
        service: "ssh-connection".into(),
        method: AuthMethodPayload::Other {
            method: "bogus".into(),
            tail: Vec::new(),
        },
    }
    .encode();
    // Mirror the server loop: peek, see an unadvertised method, reject.
    let (user, method) = ServerAuth::peek_request(&req_alice).expect("decodes");
    assert_eq!(user, "alice");
    assert!(!s.accepted_methods().contains(&method));
    match s.reject_unadvertised(&user).unwrap() {
        ServerStep::Send(p) => {
            UserauthFailure::decode(&p).unwrap();
        }
        _ => panic!("expected Send(failure)"),
    }
    // Request 2 switches to "bob" with an advertised method: must be treated
    // as a username change and disconnect, never evaluated.
    let req_bob = UserauthRequest {
        user: "bob".into(),
        service: "ssh-connection".into(),
        method: AuthMethodPayload::Password {
            new_password: None,
            password: "x".into(),
        },
    }
    .encode();
    match s.on_packet(&req_bob).unwrap() {
        ServerStep::Disconnect(reason) => {
            assert_eq!(reason, "auth: username changed mid-authentication");
        }
        _ => panic!("expected Disconnect"),
    }
}
