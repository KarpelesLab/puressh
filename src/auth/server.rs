//! Server-side user authentication state machine (RFC 4252).

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;

use crate::error::{Error, Result};
use crate::hostkey::{HostKeyVerify, host_key_verify_by_name};

use super::message::{
    AuthMethodPayload, SSH_MSG_SERVICE_REQUEST, SSH_MSG_USERAUTH_INFO_RESPONSE,
    SSH_MSG_USERAUTH_REQUEST, SecretString, ServiceAccept, ServiceRequest, UserauthFailure,
    UserauthInfoRequest, UserauthInfoResponse, UserauthPkOk, UserauthRequest, encode_success,
};

/// A single authentication attempt presented by the client.
///
/// `Debug` is implemented manually so the cleartext `password` field is
/// never rendered — it is replaced by `"<redacted>"`. This prevents
/// accidental leakage through `tracing::debug!`, `dbg!`, `Result::unwrap`'s
/// `{:?}` formatter, and similar developer-ergonomics paths.
pub enum AuthAttempt {
    /// `none` — bare probe.
    None {
        /// Requested user name.
        user: String,
    },
    /// `password` authentication.
    Password {
        /// Requested user name.
        user: String,
        /// Plaintext password, held in zeroize-on-drop storage so its
        /// bytes are wiped when the attempt is dropped. **Not** rendered by
        /// the [`core::fmt::Debug`] impl.
        password: SecretString,
    },
    /// `publickey` authentication.
    PublicKey {
        /// Requested user name.
        user: String,
        /// SSH algorithm name (e.g. `"ssh-ed25519"`).
        algorithm: String,
        /// Wire-format public-key blob.
        public_blob: Vec<u8>,
        /// True if the client only probed (no signature); false if a signature
        /// was attached and verified successfully.
        probe_only: bool,
        /// True iff the signature was both present and verified by this layer.
        verified: bool,
    },
    /// `keyboard-interactive` request.
    KeyboardInteractive {
        /// Requested user name.
        user: String,
    },
}

impl core::fmt::Debug for AuthAttempt {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            AuthAttempt::None { user } => f.debug_struct("None").field("user", user).finish(),
            AuthAttempt::Password { user, password: _ } => f
                .debug_struct("Password")
                .field("user", user)
                .field("password", &"<redacted>")
                .finish(),
            AuthAttempt::PublicKey {
                user,
                algorithm,
                public_blob,
                probe_only,
                verified,
            } => f
                .debug_struct("PublicKey")
                .field("user", user)
                .field("algorithm", algorithm)
                .field("public_blob", public_blob)
                .field("probe_only", probe_only)
                .field("verified", verified)
                .finish(),
            AuthAttempt::KeyboardInteractive { user } => f
                .debug_struct("KeyboardInteractive")
                .field("user", user)
                .finish(),
        }
    }
}

/// Authenticator's verdict on an attempt.
#[derive(Debug, Clone)]
pub enum AuthDecision {
    /// Accept fully — emit USERAUTH_SUCCESS.
    Accept,
    /// Partial accept — record the success but require more methods.
    PartialAccept {
        /// Methods the client must still satisfy.
        still_required: Vec<String>,
    },
    /// Reject — emit USERAUTH_FAILURE.
    Reject,
    /// Drive a keyboard-interactive round with these prompts.
    InteractiveRequest {
        /// Title block.
        name: String,
        /// Instructions to show.
        instruction: String,
        /// `(prompt, echo)` pairs.
        prompts: Vec<(String, bool)>,
    },
}

/// Pluggable policy: a server-side credential checker.
pub trait Authenticator: Send {
    /// Evaluate a one-shot attempt (none/password/publickey/keyboard-interactive request).
    fn evaluate(&mut self, attempt: AuthAttempt) -> AuthDecision;

    /// Evaluate the responses to a previously-issued `InteractiveRequest`.
    fn evaluate_interactive(&mut self, user: &str, responses: Vec<String>) -> AuthDecision {
        let _ = (user, responses);
        AuthDecision::Reject
    }
}

/// What the harness should do next on behalf of the server.
pub enum ServerStep {
    /// Send this payload to the peer.
    Send(Vec<u8>),
    /// Authentication finished; send this payload (USERAUTH_SUCCESS) and treat
    /// the connection as authenticated for `user`.
    Authenticated {
        /// The USERAUTH_SUCCESS payload to transmit.
        payload: Vec<u8>,
        /// The validated user name.
        user: String,
    },
    /// Disconnect the peer with the given (static) reason.
    Disconnect(&'static str),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    AwaitingServiceRequest,
    AwaitingRequest,
    AwaitingInfoResponse,
    Done,
}

/// Server-side userauth driver.
pub struct ServerAuth {
    service: &'static str,
    session_id: Vec<u8>,
    accepted_methods: Vec<&'static str>,
    auth: Box<dyn Authenticator>,
    state: State,
    pending_user: Option<String>,
    /// Default-off opt-in: when false (the default), any `AuthAttempt::None`
    /// is short-circuited to `AuthDecision::Reject` **before** the
    /// [`Authenticator`] sees it. This protects against an
    /// accept-everything authenticator silently letting unauthenticated
    /// clients in via the bare-probe `"none"` method.
    allow_none: bool,
    /// `MaxAuthTries` (OpenSSH): disconnect after this many failed attempts.
    /// `None` ⇒ unlimited (the historical behaviour, modulo `MAX_AUTH_STEPS`
    /// in the server loop).
    max_auth_tries: Option<u32>,
    /// Count of failed attempts so far (each USERAUTH_FAILURE without partial
    /// success). Compared against `max_auth_tries`.
    failed_attempts: u32,
}

impl ServerAuth {
    /// Build a new server-side driver. `methods` advertises what we accept in
    /// USERAUTH_FAILURE continuations (e.g. `["publickey", "password"]`).
    ///
    /// By default, the `"none"` method is hard-rejected before the
    /// [`Authenticator`] sees it (see [`Self::allow_none`]).
    pub fn new(
        session_id: Vec<u8>,
        methods: Vec<&'static str>,
        auth: Box<dyn Authenticator>,
    ) -> Self {
        Self {
            service: "ssh-connection",
            session_id,
            accepted_methods: methods,
            auth,
            state: State::AwaitingServiceRequest,
            pending_user: None,
            allow_none: false,
            max_auth_tries: None,
            failed_attempts: 0,
        }
    }

    /// Set the `MaxAuthTries` limit. After this many failed attempts the
    /// driver emits [`ServerStep::Disconnect`] instead of another
    /// USERAUTH_FAILURE. `None` (the default) means unlimited.
    pub fn set_max_auth_tries(&mut self, max: Option<u32>) -> &mut Self {
        self.max_auth_tries = max;
        self
    }

    /// Opt in to letting the [`Authenticator`] see `AuthAttempt::None`.
    ///
    /// By default this is `false` and the server short-circuits every
    /// `"none"` userauth method to a [`UserauthFailure`] before invoking
    /// the authenticator — RFC 4252 §5.2 describes `"none"` as a probe
    /// the client uses to *learn* which methods the server allows, not
    /// as a credential. Letting an accept-everything authenticator
    /// answer that probe with `Accept` would silently authenticate any
    /// client; the gate prevents that footgun.
    ///
    /// Enable only if your authenticator deliberately uses `"none"` as
    /// a real credential (e.g. an anonymous-access tier that does not
    /// require any secret).
    pub fn allow_none(&mut self, allow: bool) -> &mut Self {
        self.allow_none = allow;
        self
    }

    /// Process an inbound payload from the peer.
    pub fn on_packet(&mut self, payload: &[u8]) -> Result<ServerStep> {
        if payload.is_empty() {
            return Err(Error::Format("auth: empty payload"));
        }
        let msg_type = payload[0];
        match self.state {
            State::AwaitingServiceRequest => {
                if msg_type != SSH_MSG_SERVICE_REQUEST {
                    return Err(Error::Protocol("auth: expected SERVICE_REQUEST"));
                }
                let req = ServiceRequest::decode(payload)?;
                if req.service != "ssh-userauth" {
                    return Err(Error::Protocol("auth: unknown service requested"));
                }
                self.state = State::AwaitingRequest;
                let accept = ServiceAccept {
                    service: "ssh-userauth".into(),
                };
                Ok(ServerStep::Send(accept.encode()))
            }
            State::AwaitingRequest => {
                if msg_type != SSH_MSG_USERAUTH_REQUEST {
                    return Err(Error::Protocol("auth: expected USERAUTH_REQUEST"));
                }
                let req = UserauthRequest::decode(payload)?;
                if req.service != self.service {
                    return self.emit_failure();
                }
                self.handle_request(req)
            }
            State::AwaitingInfoResponse => {
                if msg_type != SSH_MSG_USERAUTH_INFO_RESPONSE {
                    return Err(Error::Protocol("auth: expected INFO_RESPONSE"));
                }
                let mut resp = UserauthInfoResponse::decode(payload)?;
                let user = self
                    .pending_user
                    .take()
                    .ok_or(Error::Protocol("auth: info response without pending user"))?;
                // `core::mem::take` the responses out instead of moving the
                // field (which `UserauthInfoResponse`'s zeroizing `Drop` impl
                // forbids). The drained source leaves an empty Vec behind;
                // ownership of the response strings passes to the
                // authenticator via the `Vec<String>` trait API.
                let responses = core::mem::take(&mut resp.responses);
                let decision = self.auth.evaluate_interactive(&user, responses);
                self.state = State::AwaitingRequest;
                self.apply_decision(decision, &user)
            }
            State::Done => Ok(ServerStep::Disconnect("auth: already finished")),
        }
    }

    fn handle_request(&mut self, req: UserauthRequest) -> Result<ServerStep> {
        let user = req.user.clone();
        match req.method {
            AuthMethodPayload::None => {
                // Hard gate: refuse `"none"` unless the caller explicitly
                // opted in via `allow_none(true)`. Without this gate an
                // overly-permissive [`Authenticator`] (e.g. one that returns
                // `Accept` for any well-formed request) would let an
                // unauthenticated client through the bare RFC 4252 §5.2
                // probe. The authenticator is never consulted in this path.
                if !self.allow_none {
                    return self.emit_failure();
                }
                let decision = self.auth.evaluate(AuthAttempt::None { user: user.clone() });
                self.apply_decision(decision, &user)
            }
            AuthMethodPayload::Password {
                password,
                new_password: _,
            } => {
                let decision = self.auth.evaluate(AuthAttempt::Password {
                    user: user.clone(),
                    password,
                });
                self.apply_decision(decision, &user)
            }
            AuthMethodPayload::PublicKey {
                signature_present,
                algorithm,
                public_blob,
                signature,
            } => self.handle_publickey(user, signature_present, algorithm, public_blob, signature),
            AuthMethodPayload::KeyboardInteractive {
                language_tag: _,
                submethods: _,
            } => {
                let decision = self
                    .auth
                    .evaluate(AuthAttempt::KeyboardInteractive { user: user.clone() });
                self.apply_decision(decision, &user)
            }
            AuthMethodPayload::Other { .. } => self.emit_failure(),
        }
    }

    fn handle_publickey(
        &mut self,
        user: String,
        signature_present: bool,
        algorithm: String,
        public_blob: Vec<u8>,
        signature: Option<Vec<u8>>,
    ) -> Result<ServerStep> {
        if !signature_present {
            let decision = self.auth.evaluate(AuthAttempt::PublicKey {
                user: user.clone(),
                algorithm: algorithm.clone(),
                public_blob: public_blob.clone(),
                probe_only: true,
                verified: false,
            });
            return match decision {
                AuthDecision::Accept | AuthDecision::PartialAccept { .. } => {
                    let pk_ok = UserauthPkOk {
                        algorithm,
                        public_blob,
                    };
                    Ok(ServerStep::Send(pk_ok.encode()))
                }
                AuthDecision::Reject => self.emit_failure(),
                AuthDecision::InteractiveRequest { .. } => {
                    Err(Error::Protocol("auth: interactive on publickey probe"))
                }
            };
        }

        let sig = match signature {
            Some(s) => s,
            None => return Err(Error::Format("auth: missing signature")),
        };

        let verifier: Box<dyn HostKeyVerify> = host_key_verify_by_name(&algorithm, &public_blob)?;
        let signed = super::message::publickey_signed_data(
            &self.session_id,
            &user,
            self.service,
            &algorithm,
            &public_blob,
        );
        if verifier.verify(&signed, &sig).is_err() {
            return self.emit_failure();
        }

        let decision = self.auth.evaluate(AuthAttempt::PublicKey {
            user: user.clone(),
            algorithm,
            public_blob,
            probe_only: false,
            verified: true,
        });
        self.apply_decision(decision, &user)
    }

    fn apply_decision(&mut self, decision: AuthDecision, user: &str) -> Result<ServerStep> {
        match decision {
            AuthDecision::Accept => {
                self.state = State::Done;
                Ok(ServerStep::Authenticated {
                    payload: encode_success(),
                    user: user.into(),
                })
            }
            AuthDecision::PartialAccept { still_required } => {
                let failure = UserauthFailure {
                    continuations: still_required,
                    partial_success: true,
                };
                Ok(ServerStep::Send(failure.encode()))
            }
            AuthDecision::Reject => self.emit_failure(),
            AuthDecision::InteractiveRequest {
                name,
                instruction,
                prompts,
            } => {
                let req = UserauthInfoRequest {
                    name,
                    instruction,
                    language: String::new(),
                    prompts,
                };
                self.state = State::AwaitingInfoResponse;
                self.pending_user = Some(user.into());
                Ok(ServerStep::Send(req.encode()))
            }
        }
    }

    #[cfg(test)]
    fn failed_attempts(&self) -> u32 {
        self.failed_attempts
    }

    fn emit_failure(&mut self) -> Result<ServerStep> {
        // A USERAUTH_FAILURE (without partial success) is a failed attempt;
        // count it and disconnect once MaxAuthTries is exceeded. OpenSSH
        // counts the attempt then drops the connection on the *next* failure
        // past the limit; we disconnect as soon as the count exceeds the
        // limit so a limit of N permits exactly N failed attempts.
        self.failed_attempts = self.failed_attempts.saturating_add(1);
        if let Some(max) = self.max_auth_tries
            && self.failed_attempts > max
        {
            self.state = State::Done;
            return Ok(ServerStep::Disconnect("Too many authentication failures"));
        }
        let cont: Vec<String> = self.accepted_methods.iter().map(|s| (*s).into()).collect();
        let failure = UserauthFailure {
            continuations: cont,
            partial_success: false,
        };
        Ok(ServerStep::Send(failure.encode()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::message::{AuthMethodPayload, SecretString, ServiceRequest, UserauthRequest};

    struct RejectAll;
    impl Authenticator for RejectAll {
        fn evaluate(&mut self, _attempt: AuthAttempt) -> AuthDecision {
            AuthDecision::Reject
        }
    }

    fn service_req() -> Vec<u8> {
        ServiceRequest {
            service: "ssh-userauth".into(),
        }
        .encode()
    }

    fn password_req() -> Vec<u8> {
        UserauthRequest {
            user: "alice".into(),
            service: "ssh-connection".into(),
            method: AuthMethodPayload::Password {
                password: SecretString::from("wrong"),
                new_password: None,
            },
        }
        .encode()
    }

    #[test]
    fn max_auth_tries_disconnects() {
        let mut sa = ServerAuth::new(vec![1, 2, 3], vec!["password"], Box::new(RejectAll));
        sa.set_max_auth_tries(Some(2));
        // Service request → accept.
        assert!(matches!(
            sa.on_packet(&service_req()).unwrap(),
            ServerStep::Send(_)
        ));
        // First two failures emit USERAUTH_FAILURE.
        assert!(matches!(
            sa.on_packet(&password_req()).unwrap(),
            ServerStep::Send(_)
        ));
        assert!(matches!(
            sa.on_packet(&password_req()).unwrap(),
            ServerStep::Send(_)
        ));
        assert_eq!(sa.failed_attempts(), 2);
        // Third failure exceeds the limit ⇒ Disconnect.
        assert!(matches!(
            sa.on_packet(&password_req()).unwrap(),
            ServerStep::Disconnect(_)
        ));
    }

    #[test]
    fn no_limit_keeps_failing() {
        let mut sa = ServerAuth::new(vec![1], vec!["password"], Box::new(RejectAll));
        sa.on_packet(&service_req()).unwrap();
        for _ in 0..10 {
            assert!(matches!(
                sa.on_packet(&password_req()).unwrap(),
                ServerStep::Send(_)
            ));
        }
    }
}
