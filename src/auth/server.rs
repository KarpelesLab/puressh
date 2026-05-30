//! Server-side user authentication state machine (RFC 4252).

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;

use crate::error::{Error, Result};
use crate::hostkey::{host_key_verify_by_name, HostKeyVerify};

use super::message::{
    encode_success, AuthMethodPayload, ServiceAccept, ServiceRequest, UserauthFailure,
    UserauthInfoRequest, UserauthInfoResponse, UserauthPkOk, UserauthRequest,
    SSH_MSG_SERVICE_REQUEST, SSH_MSG_USERAUTH_INFO_RESPONSE, SSH_MSG_USERAUTH_REQUEST,
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
        /// Plaintext password. **Not** rendered by the [`core::fmt::Debug`] impl.
        password: String,
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
}

impl ServerAuth {
    /// Build a new server-side driver. `methods` advertises what we accept in
    /// USERAUTH_FAILURE continuations (e.g. `["publickey", "password"]`).
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
        }
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
                let resp = UserauthInfoResponse::decode(payload)?;
                let user = self
                    .pending_user
                    .take()
                    .ok_or(Error::Protocol("auth: info response without pending user"))?;
                let decision = self.auth.evaluate_interactive(&user, resp.responses);
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

    fn emit_failure(&mut self) -> Result<ServerStep> {
        let cont: Vec<String> = self.accepted_methods.iter().map(|s| (*s).into()).collect();
        let failure = UserauthFailure {
            continuations: cont,
            partial_success: false,
        };
        Ok(ServerStep::Send(failure.encode()))
    }
}
