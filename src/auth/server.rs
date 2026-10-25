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

/// The account a userauth user name refers to: OpenSSH accepts
/// `user:style` (a BSD authentication style) and authenticates `user`.
fn account_name(user: &str) -> &str {
    user.split_once(':').map_or(user, |(u, _)| u)
}

/// A single authentication attempt presented by the client.
///
/// `Debug` is implemented manually so the cleartext `password` field is
/// never rendered — it is replaced by `"<redacted>"`. This prevents
/// accidental leakage through `tracing::debug!`, `dbg!`, `Result::unwrap`'s
/// `{:?}` formatter, and similar developer-ergonomics paths.
// `PublicKey` carries the parsed certificate facts inline; the other variants
// are a username and (for `Password`) one secret. The asymmetry is inherent —
// the attempt is short-lived and never stored in bulk — so boxing `CertInfo`
// would only add an allocation per publickey attempt.
#[allow(clippy::large_enum_variant)]
#[non_exhaustive]
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
        /// `Some` for a verified security-key signature: its flags, and
        /// what the server requires of them. An authenticator that accepts
        /// the key should check them against the key's own options with
        /// [`SkSignature::check`] (the server re-checks either way).
        security_key: Option<SkSignature>,
    },
    /// `keyboard-interactive` request.
    KeyboardInteractive {
        /// Requested user name.
        user: String,
    },
}

/// A verified FIDO security-key signature's details (OpenSSH
/// `PROTOCOL.u2f`), with the server-wide requirements on them
/// (`PubkeyAuthOptions`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct SkSignature {
    /// The authenticator's flags: `0x01` user presence, `0x04` user
    /// verification.
    pub flags: u8,
    /// The authenticator's signature counter.
    pub counter: u32,
    /// `PubkeyAuthOptions touch-required`.
    pub server_touch_required: bool,
    /// `PubkeyAuthOptions verify-required`.
    pub server_verify_required: bool,
}

/// A requirement a security-key signature failed to meet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SkRequirement {
    /// User presence (an authenticator touch).
    UserPresence,
    /// User verification (PIN, biometric).
    UserVerification,
}

impl SkSignature {
    /// Check the flags as OpenSSH's sshd does, given the restrictions of
    /// the key that accepted the attempt (`caps`: its `authorized_keys`
    /// options and, for a certificate, its extensions): user presence
    /// unless the key waives it with `no-touch-required` and the server
    /// doesn't insist, user verification if either asks for it.
    pub fn check(&self, caps: Option<&AuthCertCaps>) -> core::result::Result<(), SkRequirement> {
        use crate::hostkey::sk::{SK_USER_PRESENCE, SK_USER_VERIFICATION};
        let no_touch = caps.is_some_and(|c| c.no_touch_required);
        let verify = caps.is_some_and(|c| c.verify_required);
        if (self.server_touch_required || !no_touch) && self.flags & SK_USER_PRESENCE == 0 {
            return Err(SkRequirement::UserPresence);
        }
        if (self.server_verify_required || verify) && self.flags & SK_USER_VERIFICATION == 0 {
            return Err(SkRequirement::UserVerification);
        }
        Ok(())
    }
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
                security_key,
            } => f
                .debug_struct("PublicKey")
                .field("user", user)
                .field("algorithm", algorithm)
                .field("public_blob", public_blob)
                .field("probe_only", probe_only)
                .field("verified", verified)
                .field("cert", cert)
                .field("security_key", security_key)
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
#[non_exhaustive]
pub struct CertInfo {
    /// The CA's public-key blob (`signature_key_blob`) — the key the
    /// authenticator must check against its trusted-CA set.
    pub ca_key_blob: Vec<u8>,
    /// The plain wire blob of the key *embedded* in the certificate (the key
    /// the client actually signed with). A KRL that revokes this key as a
    /// plain key must also refuse any certificate wrapping it — OpenSSH checks
    /// the embedded key, not the certificate blob, for explicit-key /
    /// fingerprint revocations.
    pub embedded_pubkey_blob: Vec<u8>,
    /// The CA's signature algorithm (e.g. `"ssh-ed25519"`, `"rsa-sha2-512"`).
    pub ca_algorithm: String,
    /// The certificate's key-id (free-form CA-stamped identity, for logging).
    pub key_id: String,
    /// Monotonic serial number assigned by the CA.
    pub serial: u64,
    /// The principals the certificate authorizes (never empty for a
    /// certificate that can authenticate: an empty list is refused).
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
    /// Build a `CertInfo` by hand — for authenticator tests and tooling that
    /// has no wire certificate to parse. The validity window defaults to
    /// "always valid" (`0..u64::MAX`) and `critical_options` / `extensions`
    /// start empty; assign those fields afterwards as needed. Real
    /// connections go through [`CertInfo::from_certificate`].
    pub fn new(
        ca_key_blob: Vec<u8>,
        embedded_pubkey_blob: Vec<u8>,
        ca_algorithm: impl Into<String>,
        key_id: impl Into<String>,
        serial: u64,
        valid_principals: Vec<String>,
    ) -> Self {
        CertInfo {
            ca_key_blob,
            embedded_pubkey_blob,
            ca_algorithm: ca_algorithm.into(),
            key_id: key_id.into(),
            serial,
            valid_principals,
            critical_options: Vec::new(),
            extensions: Vec::new(),
            valid_after: 0,
            valid_before: u64::MAX,
        }
    }

    /// Build a `CertInfo` view from a parsed [`crate::cert::Certificate`].
    pub fn from_certificate(cert: &crate::cert::Certificate) -> Result<Self> {
        Ok(CertInfo {
            ca_key_blob: cert.signature_key_blob.clone(),
            embedded_pubkey_blob: cert.embedded_pubkey_blob.clone(),
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
#[non_exhaustive]
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

    /// Restrictions for the session from the key that was just accepted
    /// (a verified publickey attempt): typically its `authorized_keys`
    /// options. Combined with a certificate's own restrictions.
    #[cfg(feature = "alloc")]
    fn key_restrictions(&mut self, user: &str, public_blob: &[u8]) -> Option<AuthCertCaps> {
        let _ = (user, public_blob);
        None
    }

    /// The methods a USERAUTH_FAILURE lists as able to continue. `offered`
    /// is every method the server accepts; the default lists them all. A
    /// policy with ordered requirements (OpenSSH's `AuthenticationMethods`)
    /// lists only those that can still lead to success, as OpenSSH does,
    /// so clients do not prompt for credentials that cannot help.
    #[cfg(feature = "alloc")]
    fn continuable_methods(&self, offered: &[&'static str]) -> Vec<String> {
        offered.iter().map(|m| (*m).into()).collect()
    }

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
#[non_exhaustive]
pub struct AuthCertCaps {
    /// `permit-pty` extension present ⇒ a `pty-req` may be honoured.
    pub permit_pty: bool,
    /// `permit-port-forwarding` present ⇒ `direct-tcpip` / `tcpip-forward` allowed.
    pub permit_port_forwarding: bool,
    /// `permit-agent-forwarding` present ⇒ `auth-agent-req@openssh.com` allowed.
    pub permit_agent_forwarding: bool,
    /// `permit-X11-forwarding` present ⇒ `x11-req` allowed.
    pub permit_x11_forwarding: bool,
    /// `permit-user-rc` present (or no `no-user-rc` key option) ⇒ the
    /// session may run `~/.ssh/rc`.
    pub permit_user_rc: bool,
    /// `environment="NAME=value"` key options, set in the session when
    /// `PermitUserEnvironment` allows.
    pub environment: Vec<String>,
    /// The decoded `force-command` critical option (an SSH `string`), if present.
    /// The connection phase runs this in place of the client's command/shell.
    pub force_command: Option<String>,
    /// `permitopen=` (authorized_keys): allowed `direct-tcpip` destinations,
    /// on top of `PermitOpen`. `None` ⇒ no extra restriction.
    pub permit_open: Option<Vec<crate::config::HostPort>>,
    /// `permitlisten=` (authorized_keys): allowed `tcpip-forward` binds, on
    /// top of `PermitListen`. `None` ⇒ no extra restriction.
    pub permit_listen: Option<Vec<crate::config::HostPort>>,
    /// `tunnel="n"` (authorized_keys): the only tun device unit a client may
    /// forward (`0x7fffffff` for any). `None` ⇒ the client's choice.
    pub force_tun_device: Option<u32>,
    /// A security-key signature may omit user presence (no touch): the
    /// `no-touch-required` key option or certificate extension. Both must
    /// grant it when a certificate is trusted through `authorized_keys`.
    pub no_touch_required: bool,
    /// A security-key signature must carry user verification (PIN,
    /// biometric): the `verify-required` key option or critical option.
    pub verify_required: bool,
}

#[cfg(feature = "alloc")]
impl AuthCertCaps {
    /// Build the capability view from a verified user certificate's `CertInfo`.
    /// The `force-command` payload is itself a length-prefixed SSH `string`; it
    /// is decoded here so callers don't repeat the unwrap.
    ///
    /// A malformed `force-command` payload decodes to `None` here; the auth
    /// layer never reaches this point with one, because
    /// [`crate::cert::Certificate::require_known_critical_options`] rejects
    /// the certificate (fail-closed) before the userauth signature is even
    /// checked. Callers constructing this from their own `CertInfo` should
    /// apply the same check first.
    pub fn from_cert_info(ci: &CertInfo) -> Self {
        let force_command = ci
            .critical_option("force-command")
            .and_then(crate::cert::decode_option_string);
        AuthCertCaps {
            permit_pty: ci.has_extension("permit-pty"),
            permit_port_forwarding: ci.has_extension("permit-port-forwarding"),
            permit_agent_forwarding: ci.has_extension("permit-agent-forwarding"),
            permit_x11_forwarding: ci.has_extension("permit-X11-forwarding"),
            permit_user_rc: ci.has_extension("permit-user-rc"),
            environment: Vec::new(),
            force_command,
            permit_open: None,
            permit_listen: None,
            force_tun_device: None,
            no_touch_required: ci.has_extension("no-touch-required"),
            verify_required: ci.critical_option("verify-required").is_some(),
        }
    }

    /// Everything permitted, no forced command: the identity for
    /// [`Self::intersect`].
    pub fn unrestricted() -> Self {
        AuthCertCaps {
            permit_pty: true,
            permit_port_forwarding: true,
            permit_agent_forwarding: true,
            permit_x11_forwarding: true,
            permit_user_rc: true,
            environment: Vec::new(),
            force_command: None,
            permit_open: None,
            permit_listen: None,
            force_tun_device: None,
            no_touch_required: true,
            verify_required: false,
        }
    }

    /// Restrictions from an `authorized_keys` line's options (`restrict`,
    /// `no-pty`, `command=`, `permitopen=`, …).
    pub fn from_key_options(o: &crate::key::AuthorizedKeyOptions) -> Self {
        let list = |v: &[String]| {
            (!v.is_empty()).then(|| v.iter().filter_map(|e| parse_permit(e)).collect())
        };
        AuthCertCaps {
            permit_pty: o.allows_pty(),
            permit_port_forwarding: o.allows_port_forwarding(),
            permit_agent_forwarding: o.allows_agent_forwarding(),
            permit_x11_forwarding: o.allows_x11_forwarding(),
            permit_user_rc: o.allows_user_rc(),
            environment: o.environment.clone(),
            force_command: o.command.clone(),
            permit_open: list(&o.permit_open),
            permit_listen: list(&o.permit_listen),
            force_tun_device: o.tunnel.as_deref().and_then(|t| {
                if t.eq_ignore_ascii_case("any") {
                    Some(0x7fff_ffff)
                } else {
                    t.parse().ok()
                }
            }),
            no_touch_required: o.no_touch_required,
            verify_required: o.verify_required,
        }
    }

    /// Both sets of restrictions at once (a certificate and the
    /// `authorized_keys` line that trusted it). `None` when they force
    /// different commands, which OpenSSH refuses too.
    pub fn intersect(self, other: AuthCertCaps) -> Option<AuthCertCaps> {
        let force_command = match (self.force_command, other.force_command) {
            (Some(a), Some(b)) if a != b => return None,
            (a, b) => a.or(b),
        };
        let both = |a: Option<Vec<crate::config::HostPort>>, b: Option<Vec<_>>| match (a, b) {
            (Some(a), Some(b)) => Some(a.into_iter().filter(|e| b.contains(e)).collect()),
            (a, b) => a.or(b),
        };
        let mut environment = self.environment;
        environment.extend(other.environment);
        Some(AuthCertCaps {
            permit_pty: self.permit_pty && other.permit_pty,
            permit_port_forwarding: self.permit_port_forwarding && other.permit_port_forwarding,
            permit_agent_forwarding: self.permit_agent_forwarding && other.permit_agent_forwarding,
            permit_x11_forwarding: self.permit_x11_forwarding && other.permit_x11_forwarding,
            permit_user_rc: self.permit_user_rc && other.permit_user_rc,
            environment,
            force_command,
            permit_open: both(self.permit_open, other.permit_open),
            permit_listen: both(self.permit_listen, other.permit_listen),
            force_tun_device: self.force_tun_device.or(other.force_tun_device),
            no_touch_required: self.no_touch_required && other.no_touch_required,
            verify_required: self.verify_required || other.verify_required,
        })
    }
}

/// Combine two optional restriction sets (`None` = unrestricted). The outer
/// `None` means they conflict (different forced commands).
#[cfg(feature = "alloc")]
fn merge_caps(a: Option<AuthCertCaps>, b: Option<AuthCertCaps>) -> Option<Option<AuthCertCaps>> {
    match (a, b) {
        (Some(a), Some(b)) => a.intersect(b).map(Some),
        (a, b) => Some(a.or(b)),
    }
}

/// `host:port`, `[v6]:port` or (for `permitlisten`) a bare `port`; `*` for
/// any port.
#[cfg(feature = "alloc")]
fn parse_permit(spec: &str) -> Option<crate::config::HostPort> {
    let (host, port) = if let Some(rest) = spec.strip_prefix('[') {
        let (h, p) = rest.split_once("]:")?;
        (String::from(h), p)
    } else if let Some((h, p)) = spec.rsplit_once(':') {
        (String::from(h), p)
    } else {
        (String::from("*"), spec)
    };
    let port = if port == "*" {
        None
    } else {
        Some(port.parse().ok()?)
    };
    Some(crate::config::HostPort { host, port })
}

/// What the harness should do next on behalf of the server.
#[non_exhaustive]
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
        /// The methods that succeeded, one per line as OpenSSH's sshd
        /// records them for `ExposeAuthInfo` (`publickey ssh-ed25519
        /// AAAA…`, `password`, `keyboard-interactive/pam`).
        auth_info: String,
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
    /// The keys (a certificate's embedded key) already accepted as a factor
    /// of a multi-factor chain: OpenSSH refuses one offered again, so
    /// `publickey,publickey` takes two different keys.
    used_keys: Vec<Vec<u8>>,
    /// The host key this server presented in the key exchange, which a
    /// `publickey-hostbound-v00@openssh.com` request must name.
    host_key: Option<Vec<u8>>,
    /// One line per method that succeeded (see `ServerStep::Authenticated`).
    auth_info: String,
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
    /// `PubkeyAuthOptions touch-required`: every security-key signature must
    /// show user presence, whatever the key's options say.
    sk_touch_required: bool,
    /// `PubkeyAuthOptions verify-required`: every security-key signature
    /// must show user verification.
    sk_verify_required: bool,
    /// `PubkeyAuthOptions max-pk-ok`: rejected public key queries that do
    /// not count against `MaxAuthTries`, and how many there were.
    max_pk_ok: u32,
    pk_ok_failures: u32,
}

/// OpenSSH's default `max-pk-ok` (its `DEFAULT_AUTH_FAIL_MAX`).
pub const DEFAULT_MAX_PK_OK: u32 = 6;

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
            used_keys: Vec::new(),
            host_key: None,
            auth_info: String::new(),
            pending_prompt_count: None,
            first_user: None,
            allow_none: false,
            max_auth_tries: None,
            failed_attempts: 0,
            now: 0,
            ca_signature_algorithms: Vec::new(),
            pending_cert_caps: None,
            sk_touch_required: false,
            sk_verify_required: false,
            max_pk_ok: DEFAULT_MAX_PK_OK,
            pk_ok_failures: 0,
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
    /// default set (`config::algos::CA_SIGNATURE_DEFAULTS`).
    pub fn set_ca_signature_algorithms(&mut self, algos: Vec<String>) -> &mut Self {
        self.ca_signature_algorithms = algos;
        self
    }

    /// `PubkeyAuthOptions`: require user presence (`touch-required`) and/or
    /// user verification (`verify-required`) on every security-key
    /// signature, on top of what each key's options require. Without them a
    /// touch is still required unless the key allows `no-touch-required`.
    pub fn set_pubkey_auth_options(
        &mut self,
        touch_required: bool,
        verify_required: bool,
    ) -> &mut Self {
        self.sk_touch_required = touch_required;
        self.sk_verify_required = verify_required;
        self
    }

    /// `PubkeyAuthOptions max-pk-ok:N`: the first `n` rejected public key
    /// queries (a key offered without a signature) are answered without
    /// counting against `MaxAuthTries`, as OpenSSH 10.6 does; later ones
    /// count. [`DEFAULT_MAX_PK_OK`] by default.
    pub fn set_max_pk_ok(&mut self, n: u32) -> &mut Self {
        self.max_pk_ok = n;
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
    /// policy can be applied (see [`Self::set_accepted_methods`]). The name
    /// is the account's: a `user:style` suffix is dropped.
    pub fn peek_request(payload: &[u8]) -> Option<(String, &'static str)> {
        let req = UserauthRequest::decode(payload).ok()?;
        let method = match req.method {
            AuthMethodPayload::None => "none",
            AuthMethodPayload::Password { .. } => "password",
            AuthMethodPayload::PublicKey { .. } => "publickey",
            AuthMethodPayload::KeyboardInteractive { .. } => "keyboard-interactive",
            AuthMethodPayload::Other { .. } => "",
        };
        Some((String::from(account_name(&req.user)), method))
    }

    /// Reject an attempt whose method is no longer advertised (e.g. a
    /// `Match User` block dropped `publickey`). Counts as a failed attempt for
    /// `MaxAuthTries` and emits `USERAUTH_FAILURE` (or `Disconnect` once the
    /// limit is exceeded) carrying the *current* method set — without ever
    /// consulting the [`Authenticator`].
    ///
    /// `user` is the username the rejected request carried (from
    /// [`Self::peek_request`]). It is pinned exactly as [`Self::on_packet`]
    /// pins it: the first username seen on the connection is the only one
    /// accepted for the rest of userauth, and a later request under a
    /// different name yields [`ServerStep::Disconnect`]. Without this, a
    /// client whose *first* request was rejected here could switch names on
    /// its second request and have it evaluated under the first user's
    /// re-resolved policy.
    pub fn reject_unadvertised(&mut self, user: &str) -> Result<ServerStep> {
        if let Some(step) = self.pin_user(user) {
            return Ok(step);
        }
        self.emit_failure()
    }

    /// Pin the connection's username to the first request's value. OpenSSH
    /// disconnects if the client changes the login name mid-userauth; every
    /// probe and every real attempt for a connection must carry the same
    /// name. (The `none`- and pubkey-probe flows all reuse the same
    /// username, so this only fires on an actual switch.) Returns the
    /// `Disconnect` step on a switch, `None` when the name is consistent.
    fn pin_user(&mut self, user: &str) -> Option<ServerStep> {
        match &self.first_user {
            Some(prev) if prev != user => Some(ServerStep::Disconnect(
                "auth: username changed mid-authentication",
            )),
            None => {
                self.first_user = Some(user.into());
                None
            }
            _ => None,
        }
    }

    /// The host key this server presented in the key exchange: a client's
    /// `publickey-hostbound-v00@openssh.com` request must name it.
    pub fn set_host_key(&mut self, host_key: Vec<u8>) {
        self.host_key = Some(host_key);
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
                // Pin the username before *any* verdict on this request —
                // including the service-name rejection below — so no
                // rejected first request leaves the name unpinned.
                if let Some(step) = self.pin_user(account_name(&req.user)) {
                    return Ok(step);
                }
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
                self.record_success(&decision, "keyboard-interactive/pam".into());
                self.apply_decision(decision, &user)
            }
            State::Done => Ok(ServerStep::Disconnect("auth: already finished")),
        }
    }

    fn handle_request(&mut self, req: UserauthRequest) -> Result<ServerStep> {
        // `user:style` names the account `user` (OpenSSH's BSD auth style,
        // ignored here); a signature covers the name as sent.
        let wire_user = req.user.clone();
        let user = String::from(account_name(&req.user));
        // The username was pinned by `on_packet` (see `pin_user`) before we
        // got here.
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
                self.record_success(&decision, "password".into());
                self.apply_decision(decision, &user)
            }
            AuthMethodPayload::PublicKey {
                signature_present,
                algorithm,
                public_blob,
                signature,
                host_key,
            } => {
                // `publickey-hostbound-v00@openssh.com` names this server's
                // host key, or the request is refused (OpenSSH's check).
                if let Some(named) = &host_key
                    && self.host_key.as_ref() != Some(named)
                {
                    return self.emit_failure();
                }
                self.handle_publickey(
                    user,
                    &wire_user,
                    signature_present,
                    algorithm,
                    public_blob,
                    signature,
                    host_key,
                )
            }
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

    #[allow(clippy::too_many_arguments)]
    fn handle_publickey(
        &mut self,
        user: String,
        wire_user: &str,
        signature_present: bool,
        algorithm: String,
        public_blob: Vec<u8>,
        signature: Option<Vec<u8>>,
        host_key: Option<Vec<u8>>,
    ) -> Result<ServerStep> {
        let is_cert = crate::cert::is_cert_name(&algorithm);
        // The key itself, whether offered plain or as a certificate.
        let key_blob = if is_cert {
            match crate::cert::Certificate::parse(&public_blob) {
                Ok(c) => c.embedded_pubkey_blob().to_vec(),
                Err(_) => return self.emit_failure(),
            }
        } else {
            public_blob.clone()
        };
        if self.used_keys.contains(&key_blob) {
            return self.emit_failure();
        }

        if !signature_present {
            // Probe (no signature). For a certificate, run the same CA
            // signature, type, validity and critical-option checks as the
            // signed step before consulting the authenticator: otherwise an
            // unauthenticated client could forge a cert naming a trusted CA
            // key and use the PK_OK / FAILURE answer to enumerate users and
            // principals.
            let cert_info = if is_cert {
                match crate::cert::Certificate::parse(&public_blob) {
                    // The offered algorithm name must be one we know and
                    // must belong to the embedded key's family, exactly as
                    // for the signed step — otherwise the PK_OK we would
                    // echo back invites a signature we can never accept.
                    Ok(c)
                        if cert_plain_algorithm(&algorithm, &c).is_some()
                            && self.user_cert_valid(&c) =>
                    {
                        Some(CertInfo::from_certificate(&c)?)
                    }
                    // A malformed cert blob is not a probe we can honour.
                    _ => return self.emit_probe_failure(),
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
                security_key: None,
            });
            return match decision {
                AuthDecision::Accept | AuthDecision::PartialAccept { .. } => {
                    let pk_ok = UserauthPkOk {
                        algorithm,
                        public_blob,
                    };
                    Ok(ServerStep::Send(pk_ok.encode()))
                }
                AuthDecision::Reject => self.emit_probe_failure(),
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
            // Bind the request's `algorithm` to the certificate and to the
            // signature (RFC 8332 §3.2, OpenSSH `sshkey_check_sigtype`): the
            // cert name must be one we know, its plain form must belong to
            // the embedded key's family, and the signature blob must be
            // made with exactly that plain algorithm. Otherwise a client
            // could offer `rsa-sha2-512-cert-v01@openssh.com` and sign with
            // `rsa-sha2-256` (or SHA-1 `ssh-rsa`, if enabled) — the
            // advertised hash would be meaningless.
            let plain = match cert_plain_algorithm(&algorithm, &cert) {
                Some(p) => p,
                None => return self.emit_failure(),
            };
            let sig_alg = signature_algorithm(&sig);
            let webauthn = plain == crate::hostkey::sk::SK_ECDSA
                && sig_alg == Some(crate::hostkey::sk::WEBAUTHN_SK_ECDSA);
            if sig_alg != Some(plain) && !webauthn {
                return self.emit_failure();
            }
            if !self.user_cert_valid(&cert) {
                return self.emit_failure();
            }
            // The verifier is keyed on the *negotiated* plain name (which
            // also applies the `ssh-rsa` SHA-1 gate), never on whatever
            // name the signature blob happens to carry.
            let v = match host_key_verify_by_name(plain, cert.embedded_pubkey_blob()) {
                Ok(v) => v,
                Err(_) => return self.emit_failure(),
            };
            (v, Some(CertInfo::from_certificate(&cert)?))
        } else {
            (host_key_verify_by_name(&algorithm, &public_blob)?, None)
        };

        let signed = super::message::publickey_signed_data_bound(
            &self.session_id,
            wire_user,
            self.service,
            &algorithm,
            &public_blob,
            host_key.as_deref(),
        );
        if verifier.verify(&signed, &sig).is_err() {
            return self.emit_failure();
        }

        // The cert's connection-phase capability gates (default-deny
        // extensions + `force-command`). Kept local until the authenticator
        // accepts this attempt: a rejected attempt must never change the
        // restrictions an earlier factor recorded.
        let cert_caps = cert_info.as_ref().map(AuthCertCaps::from_cert_info);

        let security_key =
            crate::hostkey::sk::sk_signature_details(&sig).map(|(flags, counter)| SkSignature {
                flags,
                counter,
                server_touch_required: self.sk_touch_required,
                server_verify_required: self.sk_verify_required,
            });
        let decision = self.auth.evaluate(AuthAttempt::PublicKey {
            user: user.clone(),
            algorithm,
            public_blob: public_blob.clone(),
            probe_only: false,
            verified: true,
            cert: cert_info,
            security_key,
        });
        // The accepted key's own restrictions (authorized_keys options),
        // on top of a certificate's, on top of whatever earlier factors of a
        // multi-factor chain recorded — the most restrictive wins, and
        // conflicting forced commands refuse the attempt.
        let decision = match decision {
            d @ (AuthDecision::Accept | AuthDecision::PartialAccept { .. }) => {
                let key_caps = self.auth.key_restrictions(&user, &public_blob);
                let attempt = merge_caps(cert_caps, key_caps);
                let sk_ok = security_key
                    .is_none_or(|sk| sk.check(attempt.as_ref().and_then(Option::as_ref)).is_ok());
                let merged = attempt.and_then(|c| merge_caps(self.pending_cert_caps.clone(), c));
                match merged.filter(|_| sk_ok) {
                    Some(c) => {
                        self.pending_cert_caps = c;
                        d
                    }
                    None => AuthDecision::Reject,
                }
            }
            other => other,
        };
        if matches!(decision, AuthDecision::PartialAccept { .. }) {
            self.used_keys.push(key_blob);
        }
        let key_type = crate::format::Reader::new(&public_blob)
            .read_string()
            .ok()
            .and_then(|t| core::str::from_utf8(t).ok())
            .unwrap_or("");
        let line = alloc::format!(
            "publickey {key_type} {}",
            crate::key::base64::encode(&public_blob)
        );
        self.record_success(&decision, line);
        self.apply_decision(decision, &user)
    }

    /// A user certificate's own validity: type, validity window, critical
    /// options and CA signature (with the configured CA algorithms). The
    /// authenticator still decides whether the CA is trusted.
    fn user_cert_valid(&self, cert: &crate::cert::Certificate) -> bool {
        if cert.check_type(crate::cert::CertType::User).is_err()
            || cert.check_validity(self.now).is_err()
            || cert.require_known_critical_options().is_err()
        {
            return false;
        }
        let ca_algos: Vec<&str> = if self.ca_signature_algorithms.is_empty() {
            crate::config::algos::CA_SIGNATURE_DEFAULTS.to_vec()
        } else {
            self.ca_signature_algorithms
                .iter()
                .map(|s| s.as_str())
                .collect()
        };
        cert.verify_ca_signature(&ca_algos).is_ok()
    }

    /// Note a method that succeeded (fully or as one factor).
    fn record_success(&mut self, decision: &AuthDecision, line: String) {
        if matches!(
            decision,
            AuthDecision::Accept | AuthDecision::PartialAccept { .. }
        ) {
            self.auth_info.push_str(&line);
            self.auth_info.push('\n');
        }
    }

    fn apply_decision(&mut self, decision: AuthDecision, user: &str) -> Result<ServerStep> {
        match decision {
            AuthDecision::Accept => {
                self.state = State::Done;
                Ok(ServerStep::Authenticated {
                    payload: encode_success(),
                    user: user.into(),
                    cert_caps: self.pending_cert_caps.take(),
                    auth_info: core::mem::take(&mut self.auth_info),
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

    /// The username pinned by the first USERAUTH_REQUEST, if any.
    #[cfg(test)]
    fn pinned_user(&self) -> Option<&str> {
        self.first_user.as_deref()
    }

    /// A rejected public key query: a failure that counts against
    /// `MaxAuthTries` only once the `max-pk-ok` budget is spent.
    fn emit_probe_failure(&mut self) -> Result<ServerStep> {
        self.pk_ok_failures = self.pk_ok_failures.saturating_add(1);
        if self.pk_ok_failures > self.max_pk_ok {
            return self.emit_failure();
        }
        let failure = UserauthFailure {
            continuations: self.auth.continuable_methods(&self.accepted_methods),
            partial_success: false,
        };
        Ok(ServerStep::Send(failure.encode()))
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
        let cont = self.auth.continuable_methods(&self.accepted_methods);
        let failure = UserauthFailure {
            continuations: cont,
            partial_success: false,
        };
        Ok(ServerStep::Send(failure.encode()))
    }
}

/// Resolve the plain signature-algorithm name a userauth `algorithm` of
/// certificate type pins, checking it against the certificate's embedded key
/// family. `None` if the name is unknown or names a different key family
/// (an ed25519 cert offered as `rsa-sha2-512-cert-v01@openssh.com`, say).
/// Mirrors the KEX-side check in `host_key_verify_by_name`'s cert branch.
fn cert_plain_algorithm(algorithm: &str, cert: &crate::cert::Certificate) -> Option<&'static str> {
    let plain = crate::cert::cert_name_to_plain(algorithm)?;
    let family_ok = match cert.embedded_algorithm() {
        "ssh-rsa" => matches!(plain, "rsa-sha2-256" | "rsa-sha2-512" | "ssh-rsa"),
        other => plain == other,
    };
    family_ok.then_some(plain)
}

/// The leading algorithm-name string of an SSH signature blob.
fn signature_algorithm(sig_blob: &[u8]) -> Option<&str> {
    let mut r = crate::format::Reader::new(sig_blob);
    core::str::from_utf8(r.read_string().ok()?).ok()
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

    /// The security-key policy, as OpenSSH's sshd applies it: a touch
    /// unless both the key and its certificate waive it (and the server
    /// doesn't insist), user verification if anything asks for it.
    #[test]
    fn sk_signature_policy() {
        use crate::hostkey::sk::{SK_USER_PRESENCE as UP, SK_USER_VERIFICATION as UV};
        let sig = |flags, touch, verify| SkSignature {
            flags,
            counter: 0,
            server_touch_required: touch,
            server_verify_required: verify,
        };
        let caps = |no_touch, verify| {
            let mut c = AuthCertCaps::unrestricted();
            c.no_touch_required = no_touch;
            c.verify_required = verify;
            c
        };
        let ok = |s: SkSignature, c: Option<&AuthCertCaps>| s.check(c).is_ok();
        // No key options at all: touch required, no verification.
        assert!(ok(sig(UP, false, false), None));
        assert_eq!(
            sig(0, false, false).check(None),
            Err(SkRequirement::UserPresence)
        );
        assert!(!ok(sig(UV, false, false), None));
        // `no-touch-required`.
        assert!(ok(sig(0, false, false), Some(&caps(true, false))));
        // A certificate waiving it on a key that doesn't: still required.
        let both = caps(true, false).intersect(caps(false, false)).unwrap();
        assert!(!ok(sig(0, false, false), Some(&both)));
        // `verify-required` from either side.
        let v = caps(false, false).intersect(caps(false, true)).unwrap();
        assert_eq!(
            sig(UP, false, false).check(Some(&v)),
            Err(SkRequirement::UserVerification)
        );
        assert!(ok(sig(UP | UV, false, false), Some(&v)));
        // `PubkeyAuthOptions` overrides the key.
        assert!(!ok(sig(0, true, false), Some(&caps(true, false))));
        assert!(!ok(sig(UP, false, true), None));
        assert!(ok(sig(UP | UV, false, true), None));
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

    /// OpenSSH 10.6's `max-pk-ok`: rejected public key queries are free
    /// up to the budget, then count against `MaxAuthTries` like any other
    /// failure.
    #[test]
    fn rejected_probes_spend_max_pk_ok_first() {
        let probe = UserauthRequest {
            user: "alice".into(),
            service: "ssh-connection".into(),
            method: AuthMethodPayload::PublicKey {
                signature_present: false,
                algorithm: "ssh-ed25519".into(),
                public_blob: crate::hostkey::HostKey::public_blob(
                    &crate::hostkey::Ed25519HostKey::from_seed([3; 32]),
                ),
                signature: None,
                host_key: None,
            },
        }
        .encode();
        let mut sa = ServerAuth::new(vec![1, 2, 3], vec!["publickey"], Box::new(RejectAll));
        sa.set_max_auth_tries(Some(1)).set_max_pk_ok(3);
        assert!(matches!(
            sa.on_packet(&service_req()).unwrap(),
            ServerStep::Send(_)
        ));
        for _ in 0..3 {
            assert!(matches!(sa.on_packet(&probe).unwrap(), ServerStep::Send(_)));
        }
        assert_eq!(sa.failed_attempts(), 0, "within max-pk-ok");
        // The fourth counts (MaxAuthTries 1), the fifth disconnects.
        assert!(matches!(sa.on_packet(&probe).unwrap(), ServerStep::Send(_)));
        assert_eq!(sa.failed_attempts(), 1);
        assert!(matches!(
            sa.on_packet(&probe).unwrap(),
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
            sa.reject_unadvertised("alice").unwrap(),
            ServerStep::Send(_)
        ));
        assert_eq!(sa.failed_attempts(), 1);
        // The rejected request's username is pinned exactly like a request
        // that reached the authenticator would have been.
        assert_eq!(sa.pinned_user(), Some("alice"));
        // A later unadvertised attempt under a different name disconnects
        // without counting as another failure.
        assert!(matches!(
            sa.reject_unadvertised("bob").unwrap(),
            ServerStep::Disconnect(_)
        ));
        assert_eq!(sa.failed_attempts(), 1);
    }

    #[test]
    fn service_mismatch_rejection_still_pins_username() {
        // A first request refused for naming the wrong service must still
        // pin its username, so the next request cannot switch names.
        let mut sa = ServerAuth::new(vec![1, 2, 3], vec!["password"], Box::new(RejectAll));
        sa.on_packet(&service_req()).unwrap();
        let bad_service = UserauthRequest {
            user: "alice".into(),
            service: "not-ssh-connection".into(),
            method: AuthMethodPayload::None,
        }
        .encode();
        assert!(matches!(
            sa.on_packet(&bad_service).unwrap(),
            ServerStep::Send(_)
        ));
        assert_eq!(sa.pinned_user(), Some("alice"));
        let bob = UserauthRequest {
            user: "bob".into(),
            service: "ssh-connection".into(),
            method: AuthMethodPayload::Password {
                password: SecretString::from("x"),
                new_password: None,
            },
        }
        .encode();
        assert!(matches!(
            sa.on_packet(&bob).unwrap(),
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
