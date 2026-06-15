//! Client-side user authentication state machine (RFC 4252).

use alloc::boxed::Box;
use alloc::collections::VecDeque;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use crate::error::{Error, Result};

use super::message::{
    AuthMethodPayload, SSH_MSG_SERVICE_ACCEPT, SSH_MSG_USERAUTH_BANNER, SSH_MSG_USERAUTH_FAILURE,
    SSH_MSG_USERAUTH_PK_OK, SSH_MSG_USERAUTH_SUCCESS, SecretString, ServiceAccept, ServiceRequest,
    UserauthBanner, UserauthFailure, UserauthInfoRequest, UserauthInfoResponse, UserauthPkOk,
    UserauthRequest,
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
    state: State,
    /// `server-sig-algs` from `SSH_MSG_EXT_INFO` (RFC 8308 §3.1). When
    /// present, publickey credentials whose `HostKey::algorithm()` is
    /// not in this list are skipped before we even probe the server.
    server_sig_algs: Option<Vec<String>>,
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
            state: State::Initial,
            server_sig_algs: None,
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
            State::AwaitingPasswordResult => self.on_auth_result(payload),
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
            // RFC 8308 §3.1 publickey filtering. When the server advertised
            // `server-sig-algs`, a publickey credential whose signature
            // algorithm is not on the list is either upgraded to a
            // same-key variant (e.g. `ssh-rsa` → `rsa-sha2-512`) or
            // skipped entirely. If `server-sig-algs` was never sent we
            // keep the credential as-is — the server told us nothing, so
            // we fall back to old-OpenSSH behaviour and let it answer.
            let cred = match (cred, self.server_sig_algs.as_ref()) {
                (ClientCredential::PublicKey(hk), Some(allowed)) => {
                    let algo = hk.algorithm();
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
        let cred = self
            .current
            .as_ref()
            .ok_or(Error::Protocol("auth: no current credential"))?;
        let (method, next_state) = match cred {
            ClientCredential::None => (AuthMethodPayload::None, State::AwaitingNoneResult),
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
            self.current = None;
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
