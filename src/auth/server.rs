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
        /// SSH algorithm name (e.g. `"ssh-ed25519"`). For a certificate this is
        /// the cert key-type name (e.g. `"ssh-ed25519-cert-v01@openssh.com"`).
        algorithm: String,
        /// Wire-format public-key blob. For a certificate this is the full
        /// certificate blob; the authenticator should consult `cert` instead of
        /// treating the blob as a plain key.
        public_blob: Vec<u8>,
        /// True if the client only probed (no signature); false if a signature
        /// was attached and verified successfully.
        probe_only: bool,
        /// True iff the signature was both present and verified by this layer.
        /// For a certificate, this additionally means the CA signature verified
        /// and the certificate's type/validity were accepted (the *trust* in
        /// the CA itself is still the authenticator's call).
        verified: bool,
        /// `Some` iff `algorithm` is an OpenSSH certificate key-type. Carries
        /// the parsed certificate facts the trust decision needs (CA key,
        /// principals, critical options, …). `None` for a plain public key, so
        /// existing plain-key authenticators are unaffected.
        cert: Option<CertInfo>,
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
                cert,
            } => f
                .debug_struct("PublicKey")
                .field("user", user)
                .field("algorithm", algorithm)
                .field("public_blob", public_blob)
                .field("probe_only", probe_only)
                .field("verified", verified)
                .field("cert", cert)
                .finish(),
            AuthAttempt::KeyboardInteractive { user } => f
                .debug_struct("KeyboardInteractive")
                .field("user", user)
                .finish(),
        }
    }
}

/// The parsed certificate facts handed to an authenticator alongside a
/// certificate-based [`AuthAttempt::PublicKey`].
///
/// The auth layer has already verified the CA signature (under the configured
/// `CASignatureAlgorithms`) and the cert's type/validity by the time this is
/// produced for a *verified* attempt; the authenticator's remaining job is the
/// **trust** decision (is `ca_key_blob` a CA we accept?) and the **principal**
/// decision (is the login user authorized by `valid_principals` / an
/// `AuthorizedPrincipalsFile`?), plus honoring critical options.
#[derive(Debug, Clone)]
#[cfg(feature = "alloc")]
pub struct CertInfo {
    /// The CA's public-key blob (`signature_key_blob`) — the key the
    /// authenticator must check against its trusted-CA set.
    pub ca_key_blob: Vec<u8>,
    /// The CA's signature algorithm (e.g. `"ssh-ed25519"`, `"rsa-sha2-512"`).
    pub ca_algorithm: String,
    /// The certificate's key-id (free-form CA-stamped identity, for logging).
    pub key_id: String,
    /// Monotonic serial number assigned by the CA.
    pub serial: u64,
    /// The principals the certificate authorizes (empty ⇒ any).
    pub valid_principals: Vec<String>,
    /// Critical options as ordered `(name, data)` pairs — MUST be understood.
    pub critical_options: Vec<(String, Vec<u8>)>,
    /// Extensions as ordered `(name, data)` pairs — advisory.
    pub extensions: Vec<(String, Vec<u8>)>,
    /// Start of the validity window (Unix seconds).
    pub valid_after: u64,
    /// End of the validity window (Unix seconds, exclusive).
    pub valid_before: u64,
}

#[cfg(feature = "alloc")]
impl CertInfo {
    /// Build a `CertInfo` view from a parsed [`crate::cert::Certificate`].
    pub fn from_certificate(cert: &crate::cert::Certificate) -> Result<Self> {
        Ok(CertInfo {
            ca_key_blob: cert.signature_key_blob.clone(),
            ca_algorithm: cert.ca_algorithm()?.into(),
            key_id: cert.key_id.clone(),
            serial: cert.serial,
            valid_principals: cert.valid_principals.clone(),
            critical_options: cert.critical_options.clone(),
            extensions: cert.extensions.clone(),
            valid_after: cert.valid_after,
            valid_before: cert.valid_before,
        })
    }

    /// True if the named extension is present.
    pub fn has_extension(&self, name: &str) -> bool {
        self.extensions.iter().any(|(n, _)| n == name)
    }

    /// The data of a critical option by name, if present.
    pub fn critical_option(&self, name: &str) -> Option<&[u8]> {
        self.critical_options
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, d)| d.as_slice())
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

    /// Hook fired once, the first time the username for this connection is
    /// known (before the first attempt is evaluated). `methods` is the resolved
    /// `AuthenticationMethods` value for this user (space-separated
    /// alternatives, each a comma-separated chain — e.g.
    /// `["publickey,password", "publickey,keyboard-interactive"]`), or empty
    /// when no `AuthenticationMethods` is configured (single-factor: any one
    /// advertised method suffices). A multi-factor authenticator uses it to
    /// install the per-user chain set. The default is a no-op. Implementations
    /// that key off the username must reject a later username change themselves
    /// (OpenSSH terminates auth if the client switches usernames
    /// mid-userauth).
    fn on_user_resolved(&mut self, user: &str, methods: &[String]) {
        let _ = (user, methods);
    }
}

/// Per-connection capability facts carried out of a *successful* user-certificate
/// authentication, for the connection phase to enforce.
///
/// OpenSSH user certificates carry **extensions** that are default-deny: when an
/// extension is absent the corresponding capability is refused for the whole
/// connection. The auth layer captures the winning certificate's extension set
/// (and its `force-command` critical option) here so the connection phase can
/// gate `pty-req` / forwarding / agent / X11 — and apply the forced command —
/// without re-parsing the certificate.
///
/// `None` (i.e. plain public-key, password, or keyboard-interactive auth)
/// leaves every capability allowed, exactly as before certificates existed.
#[derive(Debug, Clone)]
#[cfg(feature = "alloc")]
pub struct AuthCertCaps {
    /// `permit-pty` extension present ⇒ a `pty-req` may be honoured.
    pub permit_pty: bool,
    /// `permit-port-forwarding` present ⇒ `direct-tcpip` / `tcpip-forward` allowed.
    pub permit_port_forwarding: bool,
    /// `permit-agent-forwarding` present ⇒ `auth-agent-req@openssh.com` allowed.
    pub permit_agent_forwarding: bool,
    /// `permit-X11-forwarding` present ⇒ `x11-req` allowed.
    pub permit_x11_forwarding: bool,
    /// The decoded `force-command` critical option (an SSH `string`), if present.
    /// The connection phase runs this in place of the client's command/shell.
    pub force_command: Option<String>,
}

#[cfg(feature = "alloc")]
impl AuthCertCaps {
    /// Build the capability view from a verified user certificate's `CertInfo`.
    /// The `force-command` payload is itself a length-prefixed SSH `string`; it
    /// is decoded here so callers don't repeat the unwrap.
    pub fn from_cert_info(ci: &CertInfo) -> Self {
        let force_command = ci
            .critical_option("force-command")
            .and_then(decode_ssh_string);
        AuthCertCaps {
            permit_pty: ci.has_extension("permit-pty"),
            permit_port_forwarding: ci.has_extension("permit-port-forwarding"),
            permit_agent_forwarding: ci.has_extension("permit-agent-forwarding"),
            permit_x11_forwarding: ci.has_extension("permit-X11-forwarding"),
            force_command,
        }
    }
}

/// Decode an SSH `string` (4-byte BE length + bytes) into UTF-8. Used for the
/// `force-command` critical-option payload, which is itself a length-prefixed
/// string.
#[cfg(feature = "alloc")]
fn decode_ssh_string(data: &[u8]) -> Option<String> {
    let mut r = crate::format::Reader::new(data);
    let s = r.read_string().ok()?;
    if !r.is_empty() {
        return None;
    }
    core::str::from_utf8(s).ok().map(String::from)
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
        /// `Some` iff the credential that completed authentication was a user
        /// certificate; carries that cert's connection-phase capability gates
        /// (default-deny extensions + `force-command`). `None` for plain-key /
        /// password / keyboard-interactive auth (all capabilities allowed).
        cert_caps: Option<AuthCertCaps>,
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
    /// Number of prompts issued in the in-flight keyboard-interactive
    /// `InteractiveRequest`, retained so the matching INFO_RESPONSE can be
    /// rejected when its response count does not equal the prompt count
    /// (RFC 4256 §3.4). `Some` only while [`State::AwaitingInfoResponse`];
    /// `.take()`n alongside `pending_user`.
    pending_prompt_count: Option<usize>,
    /// The username carried by the *first* USERAUTH_REQUEST seen. Once set,
    /// every later request must carry the same name — OpenSSH terminates
    /// authentication if the client switches usernames mid-userauth. `None`
    /// until the first request that carries a username.
    first_user: Option<String>,
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
    /// Current wall-clock time (Unix seconds), injected by the server at the
    /// std edge for certificate validity checks. `0` (the default) makes every
    /// not-yet-valid certificate fail closed, which is the safe default if a
    /// caller forgets to thread real time in.
    now: u64,
    /// Resolved `CASignatureAlgorithms` — the signature algorithms a CA may use
    /// when signing a user certificate. Empty ⇒ the built-in default set.
    ca_signature_algorithms: Vec<String>,
    /// Capability facts captured from the most recent *verified* user-cert
    /// publickey attempt (extensions + `force-command`). Held across a possible
    /// multi-factor PartialAccept so the eventual `Authenticated` step can carry
    /// it. `None` until a verified cert attempt is seen.
    pending_cert_caps: Option<AuthCertCaps>,
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
            pending_prompt_count: None,
            first_user: None,
            allow_none: false,
            max_auth_tries: None,
            failed_attempts: 0,
            now: 0,
            ca_signature_algorithms: Vec::new(),
            pending_cert_caps: None,
        }
    }

    /// Inject the current wall-clock time (Unix seconds) used for certificate
    /// validity checks. Servers should set this from `SystemTime` at accept
    /// time; left unset it defaults to `0`, which fails every certificate's
    /// not-yet-valid check (fail-closed).
    pub fn set_now(&mut self, now: u64) -> &mut Self {
        self.now = now;
        self
    }

    /// Set the resolved `CASignatureAlgorithms` allow-list used when verifying
    /// a user certificate's CA signature. Empty (the default) ⇒ the built-in
    /// default set ([`crate::config::algos::CA_SIGNATURE_DEFAULTS`]).
    pub fn set_ca_signature_algorithms(&mut self, algos: Vec<String>) -> &mut Self {
        self.ca_signature_algorithms = algos;
        self
    }

    /// Set the `MaxAuthTries` limit. After this many failed attempts the
    /// driver emits [`ServerStep::Disconnect`] instead of another
    /// USERAUTH_FAILURE. `None` (the default) means unlimited.
    pub fn set_max_auth_tries(&mut self, max: Option<u32>) -> &mut Self {
        self.max_auth_tries = max;
        self
    }

    /// Replace the advertised method set (the `USERAUTH_FAILURE`
    /// continuations). The server re-resolves its `sshd_config` policy once the
    /// username is first known — a `Match User`/`Match Group` block may then
    /// change `PubkeyAuthentication` / `AuthenticationMethods`, which adjusts
    /// what is offered for the remaining attempts.
    pub fn set_accepted_methods(&mut self, methods: Vec<&'static str>) -> &mut Self {
        self.accepted_methods = methods;
        self
    }

    /// The currently-advertised method set (the `USERAUTH_FAILURE`
    /// continuations).
    pub fn accepted_methods(&self) -> &[&'static str] {
        &self.accepted_methods
    }

    /// Notify the underlying [`Authenticator`] that the connection's username
    /// is now known (see [`Authenticator::on_user_resolved`]). The server loop
    /// calls this once, on the first USERAUTH_REQUEST that carries a username,
    /// alongside the `Match`-based method-set re-resolve. `methods` is the
    /// resolved `AuthenticationMethods` chain set for this user.
    pub fn notify_user_resolved(&mut self, user: &str, methods: &[String]) {
        self.auth.on_user_resolved(user, methods);
    }

    /// The method name carried by an inbound `USERAUTH_REQUEST` payload, or
    /// `None` if `payload` is not a well-formed request. Lets the caller learn
    /// the username/method *before* the attempt is evaluated, so a re-resolved
    /// policy can be applied (see [`Self::set_accepted_methods`]).
    pub fn peek_request(payload: &[u8]) -> Option<(String, &'static str)> {
        let req = UserauthRequest::decode(payload).ok()?;
        let method = match req.method {
            AuthMethodPayload::None => "none",
            AuthMethodPayload::Password { .. } => "password",
            AuthMethodPayload::PublicKey { .. } => "publickey",
            AuthMethodPayload::KeyboardInteractive { .. } => "keyboard-interactive",
            AuthMethodPayload::Other { .. } => return Some((req.user, "")),
        };
        Some((req.user, method))
    }

    /// Reject an attempt whose method is no longer advertised (e.g. a
    /// `Match User` block dropped `publickey`). Counts as a failed attempt for
    /// `MaxAuthTries` and emits `USERAUTH_FAILURE` (or `Disconnect` once the
    /// limit is exceeded) carrying the *current* method set — without ever
    /// consulting the [`Authenticator`].
    pub fn reject_unadvertised(&mut self) -> Result<ServerStep> {
        self.emit_failure()
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
                let prompt_count = self.pending_prompt_count.take();
                // `core::mem::take` the responses out instead of moving the
                // field (which `UserauthInfoResponse`'s zeroizing `Drop` impl
                // forbids). The drained source leaves an empty Vec behind;
                // ownership of the response strings passes to the
                // authenticator via the `Vec<String>` trait API.
                let responses = core::mem::take(&mut resp.responses);
                self.state = State::AwaitingRequest;
                // RFC 4256 §3.4: num-responses MUST equal the num-prompts the
                // server issued. A mismatch is a malformed/forged response —
                // treat it as a failed attempt rather than forwarding the
                // wrong-shaped responses to the authenticator.
                if prompt_count != Some(responses.len()) {
                    return self.emit_failure();
                }
                let decision = self.auth.evaluate_interactive(&user, responses);
                self.apply_decision(decision, &user)
            }
            State::Done => Ok(ServerStep::Disconnect("auth: already finished")),
        }
    }

    fn handle_request(&mut self, req: UserauthRequest) -> Result<ServerStep> {
        let user = req.user.clone();
        // Pin the username to the first request's value. OpenSSH disconnects
        // if the client changes the login name mid-userauth; every probe and
        // every real attempt for a connection must carry the same name. (The
        // `none`- and pubkey-probe flows all reuse the same username, so this
        // only fires on an actual switch.)
        match &self.first_user {
            Some(prev) if *prev != user => {
                return Ok(ServerStep::Disconnect(
                    "auth: username changed mid-authentication",
                ));
            }
            None => self.first_user = Some(user.clone()),
            _ => {}
        }
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
        let is_cert = crate::cert::is_cert_name(&algorithm);

        if !signature_present {
            // Probe (no signature). For a certificate, parse it so the
            // authenticator can decide whether to invite a signature, but do
            // not yet require CA validity — the binding signature comes next.
            let cert_info = if is_cert {
                match crate::cert::Certificate::parse(&public_blob) {
                    Ok(c) => Some(CertInfo::from_certificate(&c)?),
                    // A malformed cert blob is not a probe we can honour.
                    Err(_) => return self.emit_failure(),
                }
            } else {
                None
            };
            let decision = self.auth.evaluate(AuthAttempt::PublicKey {
                user: user.clone(),
                algorithm: algorithm.clone(),
                public_blob: public_blob.clone(),
                probe_only: true,
                verified: false,
                cert: cert_info,
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

        // For a certificate, verify the CA signature, type, validity and
        // critical-options BEFORE the userauth signature check, then build the
        // userauth-signature verifier from the cert's EMBEDDED key. The signed
        // data hashes the cert key-type name + the full cert blob, which is
        // already what `algorithm` / `public_blob` carry — so the standard
        // `publickey_signed_data` is correct as-is.
        let (verifier, cert_info): (Box<dyn HostKeyVerify>, Option<CertInfo>) = if is_cert {
            let cert = match crate::cert::Certificate::parse(&public_blob) {
                Ok(c) => c,
                Err(_) => return self.emit_failure(),
            };
            if cert.check_type(crate::cert::CertType::User).is_err()
                || cert.check_validity(self.now).is_err()
                || cert.require_known_critical_options().is_err()
            {
                return self.emit_failure();
            }
            let ca_algos: Vec<&str> = if self.ca_signature_algorithms.is_empty() {
                crate::config::algos::CA_SIGNATURE_DEFAULTS.to_vec()
            } else {
                self.ca_signature_algorithms
                    .iter()
                    .map(|s| s.as_str())
                    .collect()
            };
            if cert.verify_ca_signature(&ca_algos).is_err() {
                return self.emit_failure();
            }
            let v = match cert.embedded_verifier(&sig) {
                Ok(v) => v,
                Err(_) => return self.emit_failure(),
            };
            (v, Some(CertInfo::from_certificate(&cert)?))
        } else {
            (host_key_verify_by_name(&algorithm, &public_blob)?, None)
        };

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

        // Capture the cert's connection-phase capability gates (default-deny
        // extensions + `force-command`) BEFORE evaluating, so an eventual
        // Accept — possibly several factors later under a multi-factor chain —
        // can carry them. The authenticator still owns the *trust* verdict; we
        // only record what a successful cert would authorize. Overwrites any
        // previously-captured caps so the last verified cert wins (matching the
        // last-cert-verified semantics of a repeated publickey factor).
        if let Some(ci) = &cert_info {
            self.pending_cert_caps = Some(AuthCertCaps::from_cert_info(ci));
        }

        let decision = self.auth.evaluate(AuthAttempt::PublicKey {
            user: user.clone(),
            algorithm,
            public_blob,
            probe_only: false,
            verified: true,
            cert: cert_info,
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
                    cert_caps: self.pending_cert_caps.take(),
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
                let prompt_count = prompts.len();
                let req = UserauthInfoRequest {
                    name,
                    instruction,
                    language: String::new(),
                    prompts,
                };
                self.state = State::AwaitingInfoResponse;
                self.pending_user = Some(user.into());
                self.pending_prompt_count = Some(prompt_count);
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
    fn peek_request_extracts_user_and_method() {
        let (user, method) = ServerAuth::peek_request(&password_req()).expect("decoded");
        assert_eq!(user, "alice");
        assert_eq!(method, "password");
        // A non-request payload yields None.
        assert!(ServerAuth::peek_request(&service_req()).is_none());
    }

    #[test]
    fn reject_unadvertised_counts_and_uses_current_methods() {
        let mut sa = ServerAuth::new(vec![1, 2, 3], vec!["publickey"], Box::new(RejectAll));
        // A Match block re-resolve drops publickey for this user.
        sa.set_accepted_methods(vec![]);
        assert!(sa.accepted_methods().is_empty());
        assert!(matches!(
            sa.reject_unadvertised().unwrap(),
            ServerStep::Send(_)
        ));
        assert_eq!(sa.failed_attempts(), 1);
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
