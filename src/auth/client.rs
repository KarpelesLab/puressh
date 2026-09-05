//! Client-side user authentication state machine (RFC 4252).

use alloc::boxed::Box;
use alloc::collections::VecDeque;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use crate::error::{Error, Result};

use super::message::{
    AuthMethodPayload, SSH_MSG_SERVICE_ACCEPT, SSH_MSG_USERAUTH_BANNER, SSH_MSG_USERAUTH_FAILURE,
    SSH_MSG_USERAUTH_PASSWD_CHANGEREQ, SSH_MSG_USERAUTH_PK_OK, SSH_MSG_USERAUTH_SUCCESS,
    SecretString, ServiceAccept, ServiceRequest, UserauthBanner, UserauthFailure,
    UserauthInfoRequest, UserauthInfoResponse, UserauthPkOk, UserauthRequest,
};

/// Callback hook for keyboard-interactive (RFC 4256).
pub trait KeyboardInteractiveResponder: Send {
    /// Produce one response per prompt in `prompts`.
    fn respond(&mut self, name: &str, instruction: &str, prompts: &[(String, bool)])
    -> Vec<String>;
}

/// A credential the client offers in turn.
pub enum ClientCredential {
    /// `none` — used as a probe to learn allowed methods.
    None,
    /// Plaintext password, held in zeroize-on-drop storage so its bytes
    /// are wiped when the credential is dropped.
    Password(SecretString),
    /// Lazily-produced, re-promptable password. The closure is invoked each
    /// time the `password` method is attempted; the `bool` argument is `true`
    /// on a retry (a prior password attempt failed and the server still offers
    /// `password`). Returning `None` stops further password attempts (e.g. the
    /// user pressed Ctrl-D, `BatchMode` is on, or `NumberOfPasswordPrompts` is
    /// exhausted — the closure owns that cap). Method name `"password"`.
    PasswordPrompt(Box<dyn FnMut(bool) -> Option<SecretString> + Send>),
    /// Publickey — signs the request with the private side.
    PublicKey(Box<dyn crate::hostkey::HostKey>),
    /// Keyboard-interactive — defers prompt answering to a responder.
    KeyboardInteractive(Box<dyn KeyboardInteractiveResponder>),
}

impl ClientCredential {
    fn method_name(&self) -> &'static str {
        match self {
            ClientCredential::None => "none",
            ClientCredential::Password(_) => "password",
            ClientCredential::PasswordPrompt(_) => "password",
            ClientCredential::PublicKey(_) => "publickey",
            ClientCredential::KeyboardInteractive(_) => "keyboard-interactive",
        }
    }
}

/// What the harness should do next on behalf of the client.
pub enum ClientStep {
    /// Emit this payload as the next outbound packet.
    Send(Vec<u8>),
    /// Authentication succeeded.
    Success,
    /// Authentication exhausted all credentials.
    Failed {
        /// Continuation methods last advertised by the server.
        continuations: Vec<String>,
        /// Whether the last failure was a partial success.
        partial_success: bool,
    },
    /// Banner received; caller may display it.
    Banner {
        /// The banner text.
        message: String,
        /// RFC 3066 language tag.
        language: String,
    },
    /// Waiting for more data from the peer.
    Idle,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    Initial,
    AwaitingServiceAccept,
    AwaitingPkOk,
    AwaitingPkResult,
    AwaitingPasswordResult,
    AwaitingNoneResult,
    AwaitingKbdintResult,
    Done,
}

/// Client-side userauth driver.
pub struct ClientAuth {
    user: String,
    service: &'static str,
    session_id: Vec<u8>,
    credentials: VecDeque<ClientCredential>,
    current: Option<ClientCredential>,
    server_continuations: Vec<String>,
    last_partial_success: bool,
    /// Set when the just-failed credential was a re-promptable
    /// [`ClientCredential::PasswordPrompt`] re-queued for another try, so the
    /// next prompt call passes `retry = true`.
    password_retry: bool,
    state: State,
    /// `server-sig-algs` from `SSH_MSG_EXT_INFO` (RFC 8308 §3.1). When
    /// present, publickey credentials whose `HostKey::algorithm()` is
    /// not in this list are skipped before we even probe the server.
    server_sig_algs: Option<Vec<String>>,
    /// `PubkeyAcceptedAlgorithms` from `ssh_config` (RFC-independent, our
    /// local policy). When present, a publickey credential whose signature
    /// algorithm is not on this list is upgraded to an acceptable same-key
    /// variant (e.g. `ssh-rsa` → `rsa-sha2-512`) or skipped. Applied
    /// *before* the server `server-sig-algs` filter — the client's own
    /// policy takes precedence over what the server is willing to verify.
    pubkey_accepted: Option<Vec<String>>,
}

/// The signature algorithm a public-key algorithm actually signs with.
///
/// OpenSSH certificate algorithms (`*-cert-v01@openssh.com`) sign with their
/// base algorithm — `ssh-ed25519-cert-v01@openssh.com` signs `ssh-ed25519`,
/// `rsa-sha2-512-cert-v01@openssh.com` signs `rsa-sha2-512`. RFC 8308 §3.1
/// `server-sig-algs` lists signature algorithms, so the certificate names
/// never appear there and must be reduced before matching.
fn signature_algorithm(algo: &str) -> &str {
    algo.strip_suffix("-cert-v01@openssh.com").unwrap_or(algo)
}

impl ClientAuth {
    /// Build a new client. `session_id` is the SSH session identifier (the
    /// first KEX exchange hash `H`).
    pub fn new(user: impl Into<String>, session_id: Vec<u8>) -> Self {
        Self {
            user: user.into(),
            service: "ssh-connection",
            session_id,
            credentials: VecDeque::new(),
            current: None,
            server_continuations: Vec::new(),
            last_partial_success: false,
            password_retry: false,
            state: State::Initial,
            server_sig_algs: None,
            pubkey_accepted: None,
        }
    }

    /// Queue a credential to try; tried in FIFO order.
    pub fn add_credential(&mut self, cred: ClientCredential) {
        self.credentials.push_back(cred);
    }

    /// Install the comma-separated `server-sig-algs` value learned from
    /// `SSH_MSG_EXT_INFO` (RFC 8308 §3.1). When set, publickey credentials
    /// whose signature algorithm name is not in the list are skipped
    /// rather than probed — this prevents the legacy `ssh-rsa` fallback on
    /// modern OpenSSH servers that only accept `rsa-sha2-{256,512}`.
    pub fn set_server_sig_algs(&mut self, csv: &str) {
        let algs: Vec<String> = csv
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        self.server_sig_algs = Some(algs);
    }

    /// Install the local `PubkeyAcceptedAlgorithms` policy (already resolved
    /// from `ssh_config`). When set, a publickey credential whose signature
    /// algorithm is not on the list is upgraded to an acceptable same-key
    /// variant or skipped — applied before the server's `server-sig-algs`
    /// filter so the client's own policy is the stricter gate.
    pub fn set_pubkey_accepted(&mut self, algs: Vec<String>) {
        self.pubkey_accepted = Some(algs);
    }

    /// Build the very first outbound payload: SERVICE_REQUEST("ssh-userauth").
    pub fn start(&mut self) -> Vec<u8> {
        self.state = State::AwaitingServiceAccept;
        ServiceRequest {
            service: "ssh-userauth".into(),
        }
        .encode()
    }

    /// Process an inbound payload.
    pub fn on_packet(&mut self, payload: &[u8]) -> Result<ClientStep> {
        if payload.is_empty() {
            return Err(Error::Format("auth: empty payload"));
        }
        let msg_type = payload[0];

        if msg_type == SSH_MSG_USERAUTH_BANNER {
            let banner = UserauthBanner::decode(payload)?;
            return Ok(ClientStep::Banner {
                message: banner.message,
                language: banner.language,
            });
        }

        match self.state {
            State::Initial => Err(Error::Protocol("auth: client not started")),
            State::AwaitingServiceAccept => {
                if msg_type != SSH_MSG_SERVICE_ACCEPT {
                    return Err(Error::Protocol("auth: expected SERVICE_ACCEPT"));
                }
                let accept = ServiceAccept::decode(payload)?;
                if accept.service != "ssh-userauth" {
                    return Err(Error::Protocol("auth: wrong service accepted"));
                }
                self.advance_to_next_credential()
            }
            State::AwaitingPkOk => self.on_pk_probe_reply(payload),
            State::AwaitingPkResult => self.on_auth_result(payload),
            State::AwaitingPasswordResult => {
                // RFC 4252 §8: the server may answer a password request with
                // SSH_MSG_USERAUTH_PASSWD_CHANGEREQ (msg 60) to demand a new
                // password. We do not implement the change-password exchange;
                // surface a clear, actionable error rather than a generic
                // "unexpected packet".
                if msg_type == SSH_MSG_USERAUTH_PASSWD_CHANGEREQ {
                    return Err(Error::Protocol(
                        "server requires password change; not supported",
                    ));
                }
                self.on_auth_result(payload)
            }
            State::AwaitingNoneResult => self.on_auth_result(payload),
            State::AwaitingKbdintResult => self.on_kbdint_reply(payload),
            State::Done => Ok(ClientStep::Idle),
        }
    }

    fn advance_to_next_credential(&mut self) -> Result<ClientStep> {
        loop {
            let cred = match self.credentials.pop_front() {
                Some(c) => c,
                None => {
                    self.state = State::Done;
                    return Ok(ClientStep::Failed {
                        continuations: core::mem::take(&mut self.server_continuations),
                        partial_success: self.last_partial_success,
                    });
                }
            };
            // Method-level gating against the latest USERAUTH_FAILURE
            // continuations (empty = no prior failure, all methods still on
            // the table).
            if !self.server_continuations.is_empty() {
                let name = cred.method_name();
                if !self.server_continuations.iter().any(|m| m == name) {
                    continue;
                }
            }
            // Local `PubkeyAcceptedAlgorithms` policy (from ssh_config),
            // applied BEFORE the server's `server-sig-algs`. A publickey
            // credential whose signature algorithm is not on our own accept
            // list is upgraded to a same-key variant we do accept, or
            // skipped. Non-publickey credentials and the unset case pass
            // through untouched.
            let cred = match (cred, self.pubkey_accepted.as_ref()) {
                (ClientCredential::PublicKey(hk), Some(allowed)) => {
                    let algo = hk.algorithm();
                    if allowed.iter().any(|a| a == algo) {
                        ClientCredential::PublicKey(hk)
                    } else {
                        let csv = allowed.join(",");
                        match hk.upgraded_for(&csv) {
                            Some(upgraded) => ClientCredential::PublicKey(upgraded),
                            None => continue,
                        }
                    }
                }
                (other, _) => other,
            };
            // RFC 8308 §3.1 publickey filtering. When the server advertised
            // `server-sig-algs`, a publickey credential whose signature
            // algorithm is not on the list is either upgraded to a
            // same-key variant (e.g. `ssh-rsa` → `rsa-sha2-512`) or
            // skipped entirely. If `server-sig-algs` was never sent we
            // keep the credential as-is — the server told us nothing, so
            // we fall back to old-OpenSSH behaviour and let it answer.
            //
            // Match on the *signature* algorithm, not the public-key
            // algorithm: they differ for certificates. Unlike ssh_config's
            // `PubkeyAcceptedAlgorithms` above — which does name certificate
            // algorithms — `server-sig-algs` enumerates signature algorithms
            // only, so OpenSSH never advertises `*-cert-v01@openssh.com`.
            // Comparing a certificate credential on its certificate name
            // matches nothing, drops the credential, and leaves the client
            // reporting `AuthFailed` without ever sending a userauth request.
            let cred = match (cred, self.server_sig_algs.as_ref()) {
                (ClientCredential::PublicKey(hk), Some(allowed)) => {
                    let algo = signature_algorithm(hk.algorithm());
                    if allowed.iter().any(|a| a == algo) {
                        ClientCredential::PublicKey(hk)
                    } else {
                        // Build the original csv back so the HostKey impl
                        // can decide on its own (it already encodes the
                        // "no downgrade" policy).
                        let csv = allowed.join(",");
                        match hk.upgraded_for(&csv) {
                            Some(upgraded) => ClientCredential::PublicKey(upgraded),
                            None => continue,
                        }
                    }
                }
                (other, _) => other,
            };
            self.current = Some(cred);
            return self.emit_current_request();
        }
    }

    fn emit_current_request(&mut self) -> Result<ClientStep> {
        // `PasswordPrompt` needs a mutable borrow to call its closure (and may
        // decline, returning `None`, which means "skip me, try the next
        // credential"). Handle it before the shared-borrow match below.
        if matches!(self.current, Some(ClientCredential::PasswordPrompt(_))) {
            let retry = self.password_retry;
            let pw = match &mut self.current {
                Some(ClientCredential::PasswordPrompt(f)) => f(retry),
                _ => unreachable!(),
            };
            match pw {
                Some(secret) => {
                    let req = UserauthRequest {
                        user: self.user.clone(),
                        service: self.service.into(),
                        method: AuthMethodPayload::Password {
                            new_password: None,
                            password: secret,
                        },
                    };
                    self.state = State::AwaitingPasswordResult;
                    return Ok(ClientStep::Send(req.encode()));
                }
                None => {
                    // The closure declined (Ctrl-D / BatchMode / prompt cap):
                    // drop this credential and advance to the next.
                    self.current = None;
                    self.password_retry = false;
                    return self.advance_to_next_credential();
                }
            }
        }

        let cred = self
            .current
            .as_ref()
            .ok_or(Error::Protocol("auth: no current credential"))?;
        let (method, next_state) = match cred {
            ClientCredential::None => (AuthMethodPayload::None, State::AwaitingNoneResult),
            ClientCredential::PasswordPrompt(_) => {
                // Handled above; unreachable here.
                return Err(Error::Protocol("auth: password prompt mis-dispatched"));
            }
            ClientCredential::Password(pw) => (
                AuthMethodPayload::Password {
                    new_password: None,
                    // `pw` is borrowed from `self.current`, so we still
                    // clone here — but `SecretString::clone` produces a
                    // zeroize-on-drop copy, so the per-request duplicate is
                    // wiped when the request payload is dropped rather than
                    // leaking the password into freed heap memory.
                    password: pw.clone(),
                },
                State::AwaitingPasswordResult,
            ),
            ClientCredential::PublicKey(hk) => (
                AuthMethodPayload::PublicKey {
                    signature_present: false,
                    algorithm: hk.algorithm().into(),
                    public_blob: hk.public_blob(),
                    signature: None,
                },
                State::AwaitingPkOk,
            ),
            ClientCredential::KeyboardInteractive(_) => (
                AuthMethodPayload::KeyboardInteractive {
                    language_tag: String::new(),
                    submethods: String::new(),
                },
                State::AwaitingKbdintResult,
            ),
        };
        let req = UserauthRequest {
            user: self.user.clone(),
            service: self.service.into(),
            method,
        };
        self.state = next_state;
        Ok(ClientStep::Send(req.encode()))
    }

    fn on_pk_probe_reply(&mut self, payload: &[u8]) -> Result<ClientStep> {
        let msg_type = payload[0];
        if msg_type == SSH_MSG_USERAUTH_PK_OK {
            let pk_ok = UserauthPkOk::decode(payload)?;
            self.send_pk_signed(&pk_ok)
        } else if msg_type == SSH_MSG_USERAUTH_FAILURE {
            self.on_auth_result(payload)
        } else if msg_type == SSH_MSG_USERAUTH_SUCCESS {
            self.state = State::Done;
            self.current = None;
            Ok(ClientStep::Success)
        } else {
            Err(Error::Protocol(
                "auth: unexpected packet after publickey probe",
            ))
        }
    }

    fn send_pk_signed(&mut self, pk_ok: &UserauthPkOk) -> Result<ClientStep> {
        let cred = self
            .current
            .as_ref()
            .ok_or(Error::Protocol("auth: pk-ok without current credential"))?;
        let hk = match cred {
            ClientCredential::PublicKey(hk) => hk,
            _ => return Err(Error::Protocol("auth: pk-ok for non-publickey credential")),
        };
        if hk.algorithm() != pk_ok.algorithm {
            return Err(Error::Protocol("auth: pk-ok algorithm mismatch"));
        }
        let public_blob = hk.public_blob();
        if public_blob != pk_ok.public_blob {
            return Err(Error::Protocol("auth: pk-ok public-key mismatch"));
        }
        let signed = super::message::publickey_signed_data(
            &self.session_id,
            &self.user,
            self.service,
            hk.algorithm(),
            &public_blob,
        );
        let signature = hk.sign(&signed)?;
        let req = UserauthRequest {
            user: self.user.clone(),
            service: self.service.into(),
            method: AuthMethodPayload::PublicKey {
                signature_present: true,
                algorithm: hk.algorithm().into(),
                public_blob,
                signature: Some(signature),
            },
        };
        self.state = State::AwaitingPkResult;
        Ok(ClientStep::Send(req.encode()))
    }

    fn on_auth_result(&mut self, payload: &[u8]) -> Result<ClientStep> {
        let msg_type = payload[0];
        if msg_type == SSH_MSG_USERAUTH_SUCCESS {
            super::message::decode_success(payload)?;
            self.state = State::Done;
            self.current = None;
            Ok(ClientStep::Success)
        } else if msg_type == SSH_MSG_USERAUTH_FAILURE {
            let failure = UserauthFailure::decode(payload)?;
            self.server_continuations = failure.continuations;
            self.last_partial_success = failure.partial_success;
            // Re-promptable password: if the just-failed attempt used a
            // `PasswordPrompt` and the server still offers `password`, re-queue
            // it at the front for another try. The closure (which owns the
            // `NumberOfPasswordPrompts` cap and `BatchMode`) decides whether to
            // actually prompt again; returning `None` then skips it. A
            // partial_success failure is *not* a wrong-password retry — the
            // factor was accepted and the server wants a different method — so
            // we do not re-prompt in that case.
            let was_prompt = matches!(self.current, Some(ClientCredential::PasswordPrompt(_)));
            if was_prompt
                && !failure.partial_success
                && self.server_continuations.iter().any(|m| m == "password")
                && let Some(cred) = self.current.take()
            {
                self.credentials.push_front(cred);
                self.password_retry = true;
            } else {
                self.current = None;
                self.password_retry = false;
            }
            self.advance_to_next_credential()
        } else {
            Err(Error::Protocol("auth: unexpected packet for auth result"))
        }
    }

    fn on_kbdint_reply(&mut self, payload: &[u8]) -> Result<ClientStep> {
        let msg_type = payload[0];
        match msg_type {
            SSH_MSG_USERAUTH_SUCCESS => {
                super::message::decode_success(payload)?;
                self.state = State::Done;
                self.current = None;
                Ok(ClientStep::Success)
            }
            SSH_MSG_USERAUTH_FAILURE => {
                let failure = UserauthFailure::decode(payload)?;
                self.server_continuations = failure.continuations;
                self.last_partial_success = failure.partial_success;
                self.current = None;
                self.advance_to_next_credential()
            }
            // INFO_REQUEST shares msg-type 60 with PK_OK; the current state tells us which.
            60 => {
                let info = UserauthInfoRequest::decode(payload)?;
                let cred = self
                    .current
                    .as_mut()
                    .ok_or(Error::Protocol("auth: kbdint without current credential"))?;
                let responder = match cred {
                    ClientCredential::KeyboardInteractive(r) => r,
                    _ => return Err(Error::Protocol("auth: kbdint reply on wrong credential")),
                };
                let responses = responder.respond(&info.name, &info.instruction, &info.prompts);
                if responses.len() != info.prompts.len() {
                    return Err(Error::Protocol("auth: wrong number of kbdint responses"));
                }
                let resp = UserauthInfoResponse { responses };
                Ok(ClientStep::Send(resp.encode()))
            }
            _ => Err(Error::Protocol("auth: unexpected packet in kbdint")),
        }
    }
}

#[cfg(test)]
mod tests {

    #[test]
    fn signature_algorithm_reduces_certificate_names() {
        // `server-sig-algs` carries signature algorithms, so a certificate
        // credential has to be matched on the algorithm it actually signs
        // with, not on its certificate name.
        assert_eq!(
            signature_algorithm("ssh-ed25519-cert-v01@openssh.com"),
            "ssh-ed25519"
        );
        assert_eq!(
            signature_algorithm("rsa-sha2-512-cert-v01@openssh.com"),
            "rsa-sha2-512"
        );
        assert_eq!(
            signature_algorithm("ecdsa-sha2-nistp256-cert-v01@openssh.com"),
            "ecdsa-sha2-nistp256"
        );
        // Plain algorithms pass through untouched.
        assert_eq!(signature_algorithm("ssh-ed25519"), "ssh-ed25519");
        assert_eq!(signature_algorithm("rsa-sha2-256"), "rsa-sha2-256");
    }
    use super::*;
    use crate::auth::message::{ServiceAccept, UserauthFailure, UserauthRequest};
    use crate::hostkey::HostKey;

    fn service_accept_payload() -> Vec<u8> {
        ServiceAccept {
            service: "ssh-userauth".into(),
        }
        .encode()
    }

    #[test]
    fn password_prompt_invoked_and_sends_password() {
        let mut c = ClientAuth::new("u", Vec::new());
        c.add_credential(ClientCredential::PasswordPrompt(Box::new(|retry| {
            assert!(!retry, "first call is not a retry");
            Some(SecretString::from("hunter2"))
        })));
        let _ = c.start();
        let step = c.on_packet(&service_accept_payload()).unwrap();
        let p = match step {
            ClientStep::Send(p) => p,
            _ => panic!("expected Send"),
        };
        let req = UserauthRequest::decode(&p).unwrap();
        assert_eq!(req.method.method_name(), "password");
    }

    #[test]
    fn password_prompt_none_yields_failed_no_packet() {
        // BatchMode-style closure: declines immediately. The driver must report
        // Failed without ever emitting a password packet.
        let mut c = ClientAuth::new("u", Vec::new());
        c.add_credential(ClientCredential::PasswordPrompt(Box::new(|_retry| None)));
        let _ = c.start();
        let step = c.on_packet(&service_accept_payload()).unwrap();
        assert!(
            matches!(step, ClientStep::Failed { .. }),
            "declined prompt must yield Failed, not a Send"
        );
    }

    #[test]
    fn password_prompt_reprompts_on_failure() {
        use core::sync::atomic::{AtomicU32, Ordering};
        use std::sync::Arc;
        // The closure is called twice: first attempt, then a retry after the
        // server's USERAUTH_FAILURE that still offers `password`.
        let calls = Arc::new(AtomicU32::new(0));
        let calls2 = calls.clone();
        let mut c = ClientAuth::new("u", Vec::new());
        c.add_credential(ClientCredential::PasswordPrompt(Box::new(move |retry| {
            let n = calls2.fetch_add(1, Ordering::SeqCst) + 1;
            if n == 1 {
                assert!(!retry);
                Some(SecretString::from("wrong"))
            } else if n == 2 {
                assert!(retry, "second call must be flagged as a retry");
                Some(SecretString::from("right"))
            } else {
                None
            }
        })));
        let _ = c.start();
        // First password request.
        let p1 = match c.on_packet(&service_accept_payload()).unwrap() {
            ClientStep::Send(p) => p,
            _ => panic!("expected first password Send"),
        };
        assert_eq!(
            UserauthRequest::decode(&p1).unwrap().method.method_name(),
            "password"
        );
        // Server rejects but still offers password ⇒ re-prompt.
        let failure = UserauthFailure {
            continuations: vec!["password".into()],
            partial_success: false,
        }
        .encode();
        let p2 = match c.on_packet(&failure).unwrap() {
            ClientStep::Send(p) => p,
            _ => panic!("expected re-prompt Send, not Failed"),
        };
        assert_eq!(
            UserauthRequest::decode(&p2).unwrap().method.method_name(),
            "password"
        );
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn passwd_changereq_is_clear_error() {
        // Msg type 60 in the AwaitingPasswordResult state is
        // SSH_MSG_USERAUTH_PASSWD_CHANGEREQ; we surface a specific error.
        let mut c = ClientAuth::new("u", Vec::new());
        c.add_credential(ClientCredential::Password("pw".into()));
        let _ = c.start();
        let _ = c.on_packet(&service_accept_payload()).unwrap(); // sends password
        let changereq = vec![SSH_MSG_USERAUTH_PASSWD_CHANGEREQ];
        match c.on_packet(&changereq) {
            Err(Error::Protocol(m)) => assert!(
                m.contains("password change"),
                "expected password-change error, got {m:?}"
            ),
            Err(other) => panic!("expected Protocol error, got {other:?}"),
            Ok(_) => panic!("expected an error for PASSWD_CHANGEREQ"),
        }
    }

    /// A test double for [`HostKey`]: reports a fixed algorithm name and,
    /// optionally, upgrades to another name when `upgraded_for` is asked and
    /// the target appears in the supplied csv. No real crypto involved.
    struct FakeHostKey {
        algo: &'static str,
        upgrade_to: Option<&'static str>,
    }

    impl HostKey for FakeHostKey {
        fn algorithm(&self) -> &'static str {
            self.algo
        }
        fn public_blob(&self) -> Vec<u8> {
            alloc::vec![0xab, 0xcd]
        }
        fn sign(&self, _msg: &[u8]) -> Result<Vec<u8>> {
            Ok(alloc::vec![0u8; 4])
        }
        fn upgraded_for(&self, server_sig_algs: &str) -> Option<Box<dyn HostKey>> {
            let target = self.upgrade_to?;
            if server_sig_algs.split(',').any(|a| a == target) {
                Some(Box::new(FakeHostKey {
                    algo: target,
                    upgrade_to: None,
                }))
            } else {
                None
            }
        }
    }

    fn service_accept() -> Vec<u8> {
        ServiceAccept {
            service: "ssh-userauth".into(),
        }
        .encode()
    }

    /// Run start() + SERVICE_ACCEPT and return the algorithm of the first
    /// publickey request emitted, or None if the driver gave up (Failed).
    fn first_pubkey_algo(mut auth: ClientAuth) -> Option<String> {
        let _ = auth.start();
        match auth.on_packet(&service_accept()).expect("service accept") {
            ClientStep::Send(p) => {
                let req = UserauthRequest::decode(&p).expect("decode request");
                match req.method {
                    AuthMethodPayload::PublicKey { algorithm, .. } => Some(algorithm),
                    _ => None,
                }
            }
            ClientStep::Failed { .. } => None,
            _ => panic!("unexpected step from service-accept"),
        }
    }

    #[test]
    fn pubkey_accepted_skips_excluded_credential() {
        let mut auth = ClientAuth::new("u", Vec::new());
        auth.set_pubkey_accepted(alloc::vec!["ssh-ed25519".to_string()]);
        // The only credential is an ECDSA key, not on the accept list and with
        // no upgrade path -> the driver must skip it and report Failed.
        auth.add_credential(ClientCredential::PublicKey(Box::new(FakeHostKey {
            algo: "ecdsa-sha2-nistp256",
            upgrade_to: None,
        })));
        assert_eq!(first_pubkey_algo(auth), None);
    }

    #[test]
    fn pubkey_accepted_keeps_listed_credential() {
        let mut auth = ClientAuth::new("u", Vec::new());
        auth.set_pubkey_accepted(alloc::vec!["ssh-ed25519".to_string()]);
        auth.add_credential(ClientCredential::PublicKey(Box::new(FakeHostKey {
            algo: "ssh-ed25519",
            upgrade_to: None,
        })));
        assert_eq!(first_pubkey_algo(auth).as_deref(), Some("ssh-ed25519"));
    }

    #[test]
    fn pubkey_accepted_upgrades_ssh_rsa_to_sha2_512() {
        let mut auth = ClientAuth::new("u", Vec::new());
        // Client policy accepts only rsa-sha2-512; the credential is a legacy
        // ssh-rsa signer that knows how to upgrade itself to rsa-sha2-512.
        auth.set_pubkey_accepted(alloc::vec!["rsa-sha2-512".to_string()]);
        auth.add_credential(ClientCredential::PublicKey(Box::new(FakeHostKey {
            algo: "ssh-rsa",
            upgrade_to: Some("rsa-sha2-512"),
        })));
        assert_eq!(first_pubkey_algo(auth).as_deref(), Some("rsa-sha2-512"));
    }

    #[test]
    fn no_pubkey_policy_keeps_credential_as_is() {
        // Without a PubkeyAcceptedAlgorithms policy, the credential passes
        // through untouched (old-OpenSSH behaviour).
        let mut auth = ClientAuth::new("u", Vec::new());
        auth.add_credential(ClientCredential::PublicKey(Box::new(FakeHostKey {
            algo: "ssh-rsa",
            upgrade_to: None,
        })));
        assert_eq!(first_pubkey_algo(auth).as_deref(), Some("ssh-rsa"));
    }
}
