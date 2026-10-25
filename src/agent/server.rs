//! The request handling of an `ssh-agent`, without the socket: feed it one
//! decoded message (type byte + body) at a time with [`AgentState::handle`]
//! and send back what it returns. The `ssh-agent` binary wraps it with a
//! Unix socket and a thread per connection.
//!
//! Supported (draft-miller-ssh-agent / OpenSSH `PROTOCOL.agent`): listing,
//! signing (RSA `rsa-sha2-256` / `rsa-sha2-512` flags, legacy SHA-1 when no
//! flag), adding keys and certificates with lifetime, `confirm` (when a
//! confirmation callback is set) and destination
//! (`restrict-destination-v00@openssh.com`) constraints, removing one or
//! all keys, locking / unlocking with a passphrase, and the `query` and
//! `session-bind@openssh.com` extensions. Requests this agent cannot honour
//! — smartcards, security-key providers, other extensions — are refused,
//! never silently weakened.
//!
//! Destination constraints follow OpenSSH's `ssh-agent`: each connection
//! records the sessions `ssh` bound it to ([`ConnectionState`]), and a
//! constrained key is only listed, and only signs `publickey` requests,
//! along a path of hops its constraints allow.

use alloc::vec::Vec;
use std::time::{Duration, Instant};

use purecrypto::ct::ConstantTimeEq;
use purecrypto::hash::{Digest, Sha512};
use purecrypto::rng::{OsRng, RngCore};
use purecrypto::zeroize::Zeroizing;

use super::protocol::*;
use crate::format::{Reader, Writer};
use crate::key::PrivateKey;

/// A held key: in memory, or on a PKCS#11 token (`ssh-add -s`).
enum HeldKey {
    Soft(PrivateKey),
    #[cfg(feature = "pkcs11")]
    Token {
        key: alloc::sync::Arc<crate::pkcs11::Pkcs11Key>,
        /// The module's canonical path (`ssh-add -e` removes by it).
        provider: String,
    },
}

impl HeldKey {
    fn public_key(&self) -> crate::key::PublicKey {
        match self {
            HeldKey::Soft(k) => k.public_key(),
            #[cfg(feature = "pkcs11")]
            HeldKey::Token { key, .. } => key.public_key().clone(),
        }
    }

    fn soft(&self) -> Option<&PrivateKey> {
        match self {
            HeldKey::Soft(k) => Some(k),
            #[cfg(feature = "pkcs11")]
            HeldKey::Token { .. } => None,
        }
    }
}

struct Held {
    key: HeldKey,
    blob: Vec<u8>,
    comment: String,
    expires: Option<Instant>,
    confirm: bool,
    dest: Vec<DestConstraint>,
    /// A security key's `sk-provider@openssh.com` (canonical path, or
    /// `internal`).
    sk_provider: Option<String>,
}

impl Drop for Held {
    /// Removed, expired or dropped with the agent: wipe the key.
    fn drop(&mut self) {
        if let HeldKey::Soft(k) = &mut self.key {
            k.wipe();
        }
    }
}

/// One hop of a destination constraint: a user pattern, a host name and
/// its host (or CA) keys.
#[derive(Debug, Default, Clone)]
struct Hop {
    user: Option<String>,
    hostname: Option<String>,
    /// `(key blob, is a CA key)`.
    keys: Vec<(Vec<u8>, bool)>,
}

/// `from > to`: the key may be used to reach `to` from `from` (from the
/// origin when `from` has no host).
#[derive(Debug, Clone)]
struct DestConstraint {
    from: Hop,
    to: Hop,
}

/// A session an agent connection was bound to by `ssh`
/// (`session-bind@openssh.com`).
#[derive(Debug)]
struct Bind {
    host_key: Vec<u8>,
    session_id: Vec<u8>,
    forwarded: bool,
}

/// Most bindings one connection may record, longest session ID, most
/// destination constraints per key, longest user pattern (OpenSSH's).
const MAX_SESSION_IDS: usize = 16;
const MAX_SID_LEN: usize = 128;
const MAX_DEST_CONSTRAINTS: usize = 1024;
const MAX_USER_PATTERN: usize = 256;

/// CA signature algorithms a host certificate in a destination constraint
/// may be signed with (OpenSSH's `SSH_ALLOWED_CA_SIGALGS`).
const ALLOWED_CA_SIGALGS: &[&str] = &[
    "ssh-ed25519",
    "ecdsa-sha2-nistp256",
    "ecdsa-sha2-nistp384",
    "ecdsa-sha2-nistp521",
    "rsa-sha2-512",
    "rsa-sha2-256",
    "ssh-mldsa44-ed25519",
];

/// What one agent connection has been bound to: the sessions `ssh`
/// recorded on it, oldest (the first hop) first. Requests on a connection
/// go through [`AgentState::handle_on`] with its state.
#[derive(Debug, Default)]
pub struct ConnectionState {
    binds: Vec<Bind>,
    bind_attempted: bool,
}

/// Asks the user whether a key may be used: given the prompt, returns
/// `true` to allow it.
pub type ConfirmFn = Box<dyn FnMut(&str) -> bool + Send>;

/// A locked agent's passphrase: SHA-512 over a random salt and it.
struct Lock {
    salt: [u8; 16],
    digest: Zeroizing<[u8; 64]>,
}

impl Lock {
    fn new(pass: &[u8]) -> Self {
        let mut salt = [0u8; 16];
        OsRng.fill_bytes(&mut salt);
        let digest = lock_digest(&salt, pass);
        Self { salt, digest }
    }

    fn matches(&self, pass: &[u8]) -> bool {
        bool::from(self.digest.ct_eq(&*lock_digest(&self.salt, pass)))
    }
}

fn lock_digest(salt: &[u8], pass: &[u8]) -> Zeroizing<[u8; 64]> {
    let mut input = Zeroizing::new(Vec::with_capacity(salt.len() + pass.len()));
    input.extend_from_slice(salt);
    input.extend_from_slice(pass);
    Zeroizing::new(Sha512::digest(&input[..]))
}

/// Pause after each failed unlock: this much per failure so far, up to
/// [`UNLOCK_MAX_DELAY`] (OpenSSH's `ssh-agent` sleeps as long).
const UNLOCK_DELAY_STEP: Duration = Duration::from_millis(100);
const UNLOCK_MAX_DELAY: Duration = Duration::from_secs(10);

/// The keys an agent holds and its lock state.
pub struct AgentState {
    keys: Vec<Held>,
    /// The lock passphrase while locked.
    locked: Option<Lock>,
    /// Failed unlocks since the last successful one, and when the next
    /// attempt is heard: until then unlocks are refused unchecked (rather
    /// than sleeping, which would stall every connection sharing the
    /// state).
    unlock_failures: u32,
    unlock_after: Option<Instant>,
    default_lifetime: Option<Duration>,
    confirm: Option<ConfirmFn>,
    /// `-P`: the security-key (and PKCS#11) providers that may be loaded.
    allowed_providers: String,
    /// `-O allow-remote-pkcs11`: a forwarded connection may add providers.
    remote_add_provider: bool,
    /// `-O websafe-allow=` (`ssh:*` by default), `None` with `-O
    /// no-restrict-websafe`: the FIDO applications that may sign anything;
    /// a key for any other (a web origin) signs only SSH requests.
    websafe_allowlist: Option<String>,
    #[cfg(feature = "security-key")]
    sk_prompt: Option<alloc::sync::Arc<dyn crate::sk::Prompt>>,
    /// The hash of fingerprints in prompts (`ssh-agent -E`).
    fingerprint_hash: String,
}

/// The providers `ssh-agent` loads by default (`-P`).
pub const DEFAULT_ALLOWED_PROVIDERS: &str = "/usr/lib*/*,/usr/local/lib*/*";

/// Whether `s` matches the comma-separated `list` of `*`/`?` patterns
/// (`!` negating), case-sensitively, as OpenSSH's `match_pattern_list`.
fn pattern_list_matches(list: &str, s: &str) -> bool {
    let patterns: Vec<crate::config::HostPattern> = list
        .split(',')
        .map(crate::config::HostPattern::parse)
        .collect();
    crate::config::host_matches(&patterns, s)
}

impl Default for AgentState {
    fn default() -> Self {
        Self::new()
    }
}

impl core::fmt::Debug for AgentState {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("AgentState")
            .field("keys", &self.keys.len())
            .field("locked", &self.locked.is_some())
            .finish()
    }
}

fn reply(msg_type: u8, body: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(1 + body.len());
    v.push(msg_type);
    v.extend_from_slice(body);
    v
}

fn failure() -> Vec<u8> {
    vec![SSH_AGENT_FAILURE]
}

fn success() -> Vec<u8> {
    vec![SSH_AGENT_SUCCESS]
}

impl AgentState {
    /// An empty, unlocked agent.
    pub fn new() -> Self {
        Self {
            keys: Vec::new(),
            locked: None,
            unlock_failures: 0,
            unlock_after: None,
            default_lifetime: None,
            confirm: None,
            allowed_providers: DEFAULT_ALLOWED_PROVIDERS.into(),
            remote_add_provider: false,
            websafe_allowlist: Some("ssh:*".into()),
            #[cfg(feature = "security-key")]
            sk_prompt: None,
            fingerprint_hash: "sha256".into(),
        }
    }

    /// `ssh-agent -P`: the provider libraries keys may name (patterns,
    /// comma-separated), [`DEFAULT_ALLOWED_PROVIDERS`] by default.
    pub fn set_allowed_providers(&mut self, list: &str) {
        self.allowed_providers = list.into();
    }

    /// `ssh-agent -O allow-remote-pkcs11`: let forwarded connections add
    /// keys naming a provider library.
    pub fn set_remote_add_provider(&mut self, allow: bool) {
        self.remote_add_provider = allow;
    }

    /// `ssh-agent -O websafe-allow=` (`Some`, `ssh:*` by default) or `-O
    /// no-restrict-websafe` (`None`): which FIDO applications may sign any
    /// data. A key for another application (a web origin, which a browser
    /// could ask to sign a login challenge) only signs SSH user
    /// authentication requests and SSHSIG signatures.
    pub fn set_websafe_allowlist(&mut self, list: Option<&str>) {
        self.websafe_allowlist = list.map(Into::into);
    }

    /// How a security key asks for a touch or its PIN when it signs.
    #[cfg(feature = "security-key")]
    pub fn set_security_key_prompt(&mut self, prompt: alloc::sync::Arc<dyn crate::sk::Prompt>) {
        self.sk_prompt = Some(prompt);
    }

    /// Forget every key (`ssh-agent` on SIGUSR1).
    pub fn remove_all(&mut self) {
        self.keys.clear();
    }

    /// Accept the `confirm` constraint (`ssh-add -c`), asking `confirm`
    /// before each use of such a key. Without it, keys added with the
    /// constraint are refused.
    pub fn set_confirm(&mut self, confirm: ConfirmFn) {
        self.confirm = Some(confirm);
    }

    /// Give keys added without a lifetime constraint this lifetime
    /// (`ssh-agent -t`).
    pub fn set_default_lifetime(&mut self, lifetime: Option<Duration>) {
        self.default_lifetime = lifetime;
    }

    /// The hash of the fingerprints in confirmation prompts
    /// (`ssh-agent -E`): `md5`, `sha1`, `sha256` (the default), `sha384`
    /// or `sha512`. `false`, and no change, for another name.
    pub fn set_fingerprint_hash(&mut self, hash: &str) -> bool {
        let known = crate::key::is_fingerprint_hash(hash);
        if known {
            self.fingerprint_hash = hash.to_string();
        }
        known
    }

    /// Number of keys held (expired ones excluded).
    pub fn len(&mut self) -> usize {
        self.expire();
        self.keys.len()
    }

    /// `true` when no key is held.
    pub fn is_empty(&mut self) -> bool {
        self.len() == 0
    }

    fn expire(&mut self) {
        let now = Instant::now();
        self.keys.retain(|k| k.expires.is_none_or(|t| now < t));
    }

    /// Handle one request (`type byte ‖ body`) and return the reply
    /// (`type byte ‖ body`), ready to be length-prefixed onto the socket.
    /// The request is taken as coming from a connection of its own, never
    /// bound to a session; a server keeps a [`ConnectionState`] per
    /// connection and uses [`Self::handle_on`].
    pub fn handle(&mut self, request: &[u8]) -> Vec<u8> {
        self.handle_on(&mut ConnectionState::default(), request)
    }

    /// Handle one request received on the connection `conn`.
    pub fn handle_on(&mut self, conn: &mut ConnectionState, request: &[u8]) -> Vec<u8> {
        self.expire();
        let Some((&msg_type, body)) = request.split_first() else {
            return failure();
        };
        let locked = self.locked.is_some();
        if locked && msg_type != SSH_AGENTC_UNLOCK {
            // A session bind refused here still marks the connection, so
            // it is not taken as a local one once the agent is unlocked.
            if msg_type == SSH_AGENTC_EXTENSION
                && matches!(
                    Reader::new(body).read_string(),
                    Ok(b"session-bind@openssh.com")
                )
            {
                conn.bind_attempted = true;
            }
            // A locked agent lists nothing and refuses everything else.
            return if msg_type == SSH_AGENTC_REQUEST_IDENTITIES {
                reply(SSH_AGENT_IDENTITIES_ANSWER, &0u32.to_be_bytes())
            } else {
                failure()
            };
        }
        match msg_type {
            SSH_AGENTC_REQUEST_IDENTITIES => {
                let mut w = Writer::new();
                // Keys not permitted along this connection's path are
                // not shown.
                let shown: Vec<&Held> = self
                    .keys
                    .iter()
                    .filter(|k| identity_permitted(k, conn, None))
                    .collect();
                w.write_u32(shown.len() as u32);
                for k in shown {
                    w.write_string(&k.blob);
                    w.write_string(k.comment.as_bytes());
                }
                reply(SSH_AGENT_IDENTITIES_ANSWER, w.as_slice())
            }
            SSH_AGENTC_SIGN_REQUEST => self.sign(conn, body).unwrap_or_else(failure),
            SSH_AGENTC_ADD_IDENTITY | SSH_AGENTC_ADD_ID_CONSTRAINED => self
                .add(conn, body, msg_type == SSH_AGENTC_ADD_ID_CONSTRAINED)
                .unwrap_or_else(failure),
            #[cfg(feature = "pkcs11")]
            SSH_AGENTC_ADD_SMARTCARD_KEY | SSH_AGENTC_ADD_SMARTCARD_KEY_CONSTRAINED => self
                .add_smartcard(
                    conn,
                    body,
                    msg_type == SSH_AGENTC_ADD_SMARTCARD_KEY_CONSTRAINED,
                )
                .unwrap_or_else(failure),
            #[cfg(feature = "pkcs11")]
            SSH_AGENTC_REMOVE_SMARTCARD_KEY => self.remove_smartcard(body).unwrap_or_else(failure),
            SSH_AGENTC_REMOVE_IDENTITY => {
                let mut r = Reader::new(body);
                let Ok(blob) = r.read_string() else {
                    return failure();
                };
                // A key this connection cannot see cannot be removed.
                match self.keys.iter().position(|k| k.blob == blob) {
                    Some(i) if identity_permitted(&self.keys[i], conn, None) => {
                        self.keys.remove(i);
                        success()
                    }
                    _ => failure(),
                }
            }
            SSH_AGENTC_REMOVE_ALL_IDENTITIES => {
                self.keys.clear();
                success()
            }
            SSH_AGENTC_LOCK => {
                let mut r = Reader::new(body);
                let Ok(pass) = r.read_string() else {
                    return failure();
                };
                self.locked = Some(Lock::new(pass));
                success()
            }
            SSH_AGENTC_UNLOCK if locked => {
                let mut r = Reader::new(body);
                let Ok(pass) = r.read_string() else {
                    return failure();
                };
                let now = Instant::now();
                if self.unlock_after.is_some_and(|t| now < t) {
                    return failure();
                }
                if self.locked.as_ref().is_some_and(|l| l.matches(pass)) {
                    self.locked = None;
                    self.unlock_failures = 0;
                    self.unlock_after = None;
                    success()
                } else {
                    self.unlock_failures = self.unlock_failures.saturating_add(1);
                    let delay = UNLOCK_DELAY_STEP
                        .saturating_mul(self.unlock_failures)
                        .min(UNLOCK_MAX_DELAY);
                    self.unlock_after = Some(now + delay);
                    failure()
                }
            }
            SSH_AGENTC_EXTENSION => {
                let mut r = Reader::new(body);
                match r.read_string() {
                    Ok(b"query") => {
                        let mut w = Writer::new();
                        w.write_string(b"query");
                        w.write_string(b"session-bind@openssh.com");
                        reply(SSH_AGENT_EXTENSION_RESPONSE, w.as_slice())
                    }
                    Ok(b"session-bind@openssh.com") => {
                        if session_bind(conn, &mut r) {
                            success()
                        } else {
                            vec![SSH_AGENT_EXTENSION_FAILURE]
                        }
                    }
                    _ => failure(),
                }
            }
            _ => failure(),
        }
    }

    fn sign(&mut self, conn: &ConnectionState, body: &[u8]) -> Option<Vec<u8>> {
        let mut r = Reader::new(body);
        let blob = r.read_string().ok()?;
        let data = r.read_string().ok()?;
        let flags = r.read_u32().unwrap_or(0);
        let held = self.keys.iter().find(|k| k.blob == blob)?;
        let mut sig_dest = None;
        if !held.dest.is_empty() {
            // A destination-constrained key signs only a `publickey`
            // request for the session most recently bound, along a path
            // its constraints allow.
            let last = conn.binds.last()?;
            let req = parse_userauth_request(data, blob)?;
            if !identity_permitted(held, conn, Some(&req.user)) || req.session_id != last.session_id
            {
                return None;
            }
            match &req.host_key {
                None if conn.binds.len() > 1 => return None,
                Some(k) if *k != last.host_key => return None,
                _ => {}
            }
            sig_dest = Some(format!(
                "public key authentication request for user \"{}\" to listed host",
                req.user
            ));
        }
        if held.confirm {
            let pk = held.key.public_key();
            let fp = pk
                .fingerprint(&self.fingerprint_hash)
                .unwrap_or_else(|| pk.sha256_fingerprint());
            let mut prompt = format!("Allow use of key {}?\nKey fingerprint {fp}.", held.comment);
            if let Some(d) = sig_dest {
                prompt.push('\n');
                prompt.push_str(&d);
            }
            if !self.confirm.as_mut().is_some_and(|ask| ask(&prompt)) {
                return None;
            }
        }
        #[cfg(feature = "pkcs11")]
        if let HeldKey::Token { key, .. } = &held.key {
            // SSH_AGENT_RSA_SHA2_512 / _256, as for a key in memory.
            let alg = match key.public_key() {
                crate::key::PublicKey::Rsa { .. } if flags & 4 != 0 => "rsa-sha2-512",
                crate::key::PublicKey::Rsa { .. } if flags & 2 != 0 => "rsa-sha2-256",
                crate::key::PublicKey::Rsa { .. } => "ssh-rsa",
                other => other.algorithm(),
            };
            let sig = key.sign_with(alg, data).ok()?;
            let mut w = Writer::new();
            w.write_string(&sig);
            return Some(reply(SSH_AGENT_SIGN_RESPONSE, w.as_slice()));
        }
        let key = held.key.soft()?;
        let sig = if let Some(sk) = key.sk_credential() {
            // A web-origin key never signs a challenge a site could use.
            if let Some(allow) = &self.websafe_allowlist
                && !pattern_list_matches(allow, &sk.application)
                && parse_userauth_request(data, blob).is_none()
                && !data.starts_with(b"SSHSIG")
            {
                return None;
            }
            self.sign_security_key(held, data)?
        } else {
            key.agent_signer(flags).ok()?.sign(data).ok()?
        };
        let mut w = Writer::new();
        w.write_string(&sig);
        Some(reply(SSH_AGENT_SIGN_RESPONSE, w.as_slice()))
    }

    /// A security key's signature, made through its provider.
    #[cfg(feature = "security-key")]
    fn sign_security_key(&self, held: &Held, data: &[u8]) -> Option<Vec<u8>> {
        use crate::hostkey::HostKey;
        let provider = crate::sk::open_provider(held.sk_provider.as_deref()?).ok()?;
        crate::sk::SkSigner::new(held.key.soft()?.clone(), provider, self.sk_prompt.clone())
            .ok()?
            .sign(data)
            .ok()
    }

    #[cfg(not(feature = "security-key"))]
    fn sign_security_key(&self, _held: &Held, _data: &[u8]) -> Option<Vec<u8>> {
        None
    }

    fn add(&mut self, conn: &ConnectionState, body: &[u8], constrained: bool) -> Option<Vec<u8>> {
        let mut r = Reader::new(body);
        let is_cert = Reader::new(body)
            .read_string()
            .ok()
            .and_then(|t| core::str::from_utf8(t).ok())
            .is_some_and(crate::cert::is_cert_name);
        // A certificate is held as its own identity: listed and signed
        // for under the certificate blob, with the key it certifies.
        let (key, cert) = if is_cert {
            let (key, cert) = PrivateKey::from_agent_add_cert_body(&mut r).ok()?;
            (key, Some(cert))
        } else {
            (PrivateKey::from_agent_add_body(&mut r).ok()?, None)
        };
        let c = if constrained {
            self.parse_constraints(&mut r, true, false)?
        } else if !r.is_empty() {
            return None;
        } else {
            Constraints::default()
        };
        let mut sk_provider = c.sk_provider;
        if let Some(p) = sk_provider.as_mut() {
            key.sk_credential()?;
            if !p.eq_ignore_ascii_case("internal") {
                // Only a provider on the allowlist, and from a forwarded
                // connection only when allowed.
                *p = self.allowed_provider(conn, p)?;
            }
        }
        let blob = cert.unwrap_or_else(|| key.public_key().wire_blob());
        let comment = key.comment().to_string();
        let held = Held {
            key: HeldKey::Soft(key),
            blob,
            comment,
            expires: None,
            confirm: c.confirm,
            dest: c.dest,
            sk_provider,
        };
        self.insert(conn, held, c.lifetime).then(success)
    }

    /// Hold `held` (with `lifetime`, else the default one), replacing the
    /// same key, unless this connection could not see that one.
    fn insert(
        &mut self,
        conn: &ConnectionState,
        mut held: Held,
        lifetime: Option<Duration>,
    ) -> bool {
        held.expires = lifetime
            .or(self.default_lifetime)
            .map(|d| Instant::now() + d);
        if let Some(i) = self.keys.iter().position(|k| k.blob == held.blob) {
            if !identity_permitted(&self.keys[i], conn, None) {
                return false;
            }
            self.keys.remove(i);
        }
        self.keys.push(held);
        true
    }

    /// Key constraints (`SSH_AGENT_CONSTRAIN_*` to the end of the request):
    /// `sk-provider@openssh.com` for an identity, the associated
    /// certificates for a smartcard.
    fn parse_constraints(
        &self,
        r: &mut Reader<'_>,
        sk: bool,
        smartcard: bool,
    ) -> Option<Constraints> {
        let mut c = Constraints::default();
        let (mut have_life, mut have_dest, mut have_certs) = (false, false, false);
        while !r.is_empty() {
            match r.read_u8().ok()? {
                SSH_AGENT_CONSTRAIN_LIFETIME if !have_life => {
                    have_life = true;
                    c.lifetime = Some(Duration::from_secs(r.read_u32().ok()? as u64));
                }
                // Without a way to ask, a key to confirm is refused
                // rather than held unconfirmed.
                SSH_AGENT_CONSTRAIN_CONFIRM if !c.confirm && self.confirm.is_some() => {
                    c.confirm = true;
                }
                SSH_AGENT_CONSTRAIN_EXTENSION => match r.read_string().ok()? {
                    b"restrict-destination-v00@openssh.com" if !have_dest => {
                        have_dest = true;
                        let mut b = Reader::new(r.read_string().ok()?);
                        while !b.is_empty() {
                            if c.dest.len() >= MAX_DEST_CONSTRAINTS {
                                return None;
                            }
                            c.dest.push(parse_dest_constraint(&mut b)?);
                        }
                    }
                    b"sk-provider@openssh.com" if sk && c.sk_provider.is_none() => {
                        c.sk_provider = Some(
                            core::str::from_utf8(r.read_string().ok()?)
                                .ok()?
                                .to_string(),
                        );
                    }
                    b"associated-certs-v00@openssh.com" if smartcard && !have_certs => {
                        have_certs = true;
                        c.cert_only = r.read_u8().ok()? != 0;
                        let mut b = Reader::new(r.read_string().ok()?);
                        while !b.is_empty() {
                            if c.certs.len() >= MAX_ASSOCIATED_CERTS {
                                return None;
                            }
                            c.certs.push(b.read_string().ok()?.to_vec());
                        }
                    }
                    _ => return None,
                },
                _ => return None,
            }
        }
        Some(c)
    }

    /// The provider `path`, canonical, if this connection may load it
    /// (`-P`, and `-O allow-remote-pkcs11` for a forwarded connection).
    fn allowed_provider(&self, conn: &ConnectionState, path: &str) -> Option<String> {
        let remote = conn.bind_attempted || !conn.binds.is_empty();
        if remote && !self.remote_add_provider {
            return None;
        }
        let p = std::fs::canonicalize(path).ok()?.to_str()?.to_string();
        pattern_list_matches(&self.allowed_providers, &p).then_some(p)
    }

    /// `SSH_AGENTC_ADD_SMARTCARD_KEY[_CONSTRAINED]` (`ssh-add -s`): load
    /// the PKCS#11 module with the PIN and hold its keys, and the given
    /// certificates for them, as OpenSSH's agent does.
    #[cfg(feature = "pkcs11")]
    fn add_smartcard(
        &mut self,
        conn: &ConnectionState,
        body: &[u8],
        constrained: bool,
    ) -> Option<Vec<u8>> {
        let mut r = Reader::new(body);
        let provider = core::str::from_utf8(r.read_string().ok()?)
            .ok()?
            .to_string();
        let pin = Zeroizing::new(
            core::str::from_utf8(r.read_string().ok()?)
                .ok()?
                .to_string(),
        );
        let c = if constrained {
            self.parse_constraints(&mut r, false, true)?
        } else if !r.is_empty() {
            return None;
        } else {
            Constraints::default()
        };
        let provider = self.allowed_provider(conn, &provider)?;
        let keys = crate::pkcs11::load(&provider, Some(&pin), None).ok()?;
        let mut added = false;
        for key in keys {
            let blob = key.public_key().wire_blob();
            let comment = match key.public_key().comment() {
                "" => provider.clone(),
                c => c.to_string(),
            };
            for cert in &c.certs {
                let Ok(parsed) = crate::cert::Certificate::parse(cert) else {
                    continue;
                };
                if parsed.embedded_pubkey_blob() != blob {
                    continue;
                }
                let held = Held {
                    key: HeldKey::Token {
                        key: key.clone(),
                        provider: provider.clone(),
                    },
                    blob: cert.clone(),
                    comment: comment.clone(),
                    expires: None,
                    confirm: c.confirm,
                    dest: c.dest.clone(),
                    sk_provider: None,
                };
                added |= self.insert(conn, held, c.lifetime);
            }
            if !c.cert_only && !self.keys.iter().any(|k| k.blob == blob) {
                let held = Held {
                    key: HeldKey::Token {
                        key,
                        provider: provider.clone(),
                    },
                    blob,
                    comment,
                    expires: None,
                    confirm: c.confirm,
                    dest: c.dest.clone(),
                    sk_provider: None,
                };
                added |= self.insert(conn, held, c.lifetime);
            }
        }
        added.then(success)
    }

    /// `SSH_AGENTC_REMOVE_SMARTCARD_KEY` (`ssh-add -e`): forget every key
    /// from that module.
    #[cfg(feature = "pkcs11")]
    fn remove_smartcard(&mut self, body: &[u8]) -> Option<Vec<u8>> {
        let mut r = Reader::new(body);
        let provider = core::str::from_utf8(r.read_string().ok()?).ok()?;
        let provider = std::fs::canonicalize(provider).ok()?;
        let provider = provider.to_str()?;
        let before = self.keys.len();
        self.keys
            .retain(|k| !matches!(&k.key, HeldKey::Token { provider: p, .. } if p == provider));
        (self.keys.len() != before).then(success)
    }
}

/// What an add request constrains.
#[derive(Default)]
struct Constraints {
    lifetime: Option<Duration>,
    confirm: bool,
    dest: Vec<DestConstraint>,
    sk_provider: Option<String>,
    /// `associated-certs-v00@openssh.com` (smartcards): certificates to
    /// hold for the token's keys, and whether to hold only those.
    certs: Vec<Vec<u8>>,
    cert_only: bool,
}

/// Most certificates one smartcard request may associate (OpenSSH's).
const MAX_ASSOCIATED_CERTS: usize = 1024;

/// `session-bind@openssh.com`: record that `conn` serves the session whose
/// ID the host key signed (`forwarded`: for a forwarded agent rather than
/// authentication). Returns whether the binding was accepted.
fn session_bind(conn: &mut ConnectionState, r: &mut Reader<'_>) -> bool {
    conn.bind_attempted = true;
    let parsed = (|| {
        let key = r.read_string().ok()?.to_vec();
        let sid = r.read_string().ok()?.to_vec();
        let sig = r.read_string().ok()?.to_vec();
        let fwd = r.read_u8().ok()? != 0;
        Some((key, sid, sig, fwd))
    })();
    let Some((host_key, session_id, sig, forwarded)) = parsed else {
        return false;
    };
    if session_id.len() > MAX_SID_LEN || !verify_by_key(&host_key, &session_id, &sig) {
        return false;
    }
    for b in &conn.binds {
        // A connection used for authentication is not reused for another
        // session.
        if !b.forwarded {
            return false;
        }
        if b.session_id == session_id {
            return b.host_key == host_key;
        }
    }
    if conn.binds.len() >= MAX_SESSION_IDS {
        return false;
    }
    conn.binds.push(Bind {
        host_key,
        session_id,
        forwarded,
    });
    true
}

/// Verify `sig` over `data` with the key (or certificate's key) `key`.
fn verify_by_key(key: &[u8], data: &[u8], sig: &[u8]) -> bool {
    let plain;
    let blob = if is_cert_blob(key) {
        match crate::cert::Certificate::parse(key) {
            Ok(c) => {
                plain = c.embedded_pubkey_blob().to_vec();
                &plain[..]
            }
            Err(_) => return false,
        }
    } else {
        key
    };
    let Some(alg) = Reader::new(sig)
        .read_string()
        .ok()
        .and_then(|a| core::str::from_utf8(a).ok())
    else {
        return false;
    };
    crate::hostkey::host_key_verify_by_name(alg, blob)
        .and_then(|v| v.verify(data, sig))
        .is_ok()
}

fn is_cert_blob(blob: &[u8]) -> bool {
    Reader::new(blob)
        .read_string()
        .ok()
        .and_then(|t| core::str::from_utf8(t).ok())
        .is_some_and(crate::cert::is_cert_name)
}

/// The key type a signature algorithm is made with (`rsa-sha2-512` is an
/// `ssh-rsa` key's).
fn key_type_of(alg: &[u8]) -> &[u8] {
    match alg {
        b"rsa-sha2-256" | b"rsa-sha2-512" => b"ssh-rsa",
        b"rsa-sha2-256-cert-v01@openssh.com" | b"rsa-sha2-512-cert-v01@openssh.com" => {
            b"ssh-rsa-cert-v01@openssh.com"
        }
        other => other,
    }
}

/// The parts of a `publickey` userauth request an agent checks.
struct UserauthRequest {
    session_id: Vec<u8>,
    user: String,
    host_key: Option<Vec<u8>>,
}

/// Parse `data` as the `publickey` (or `publickey-hostbound-v00`) userauth
/// request a key signs, for the key `key`; `None` if it is anything else.
fn parse_userauth_request(data: &[u8], key: &[u8]) -> Option<UserauthRequest> {
    let mut r = Reader::new(data);
    let session_id = r.read_string().ok()?.to_vec();
    if session_id.is_empty() || r.read_u8().ok()? != 50 {
        return None;
    }
    let user = core::str::from_utf8(r.read_string().ok()?)
        .ok()?
        .to_string();
    let service = r.read_string().ok()?;
    let method = r.read_string().ok()?;
    let sig_follows = r.read_u8().ok()?;
    let pkalg = r.read_string().ok()?;
    let mkey = r.read_string().ok()?;
    let key_type = Reader::new(key).read_string().ok()?;
    if sig_follows != 1
        || service != b"ssh-connection"
        || mkey != key
        || key_type_of(pkalg) != key_type
    {
        return None;
    }
    let host_key = match method {
        b"publickey-hostbound-v00@openssh.com" => Some(r.read_string().ok()?.to_vec()),
        b"publickey" => None,
        _ => return None,
    };
    if !r.is_empty() {
        return None;
    }
    Some(UserauthRequest {
        session_id,
        user,
        host_key,
    })
}

fn parse_hop(b: &[u8]) -> Option<Hop> {
    let mut r = Reader::new(b);
    let user = core::str::from_utf8(r.read_string().ok()?).ok()?;
    let hostname = core::str::from_utf8(r.read_string().ok()?).ok()?;
    if !r.read_string().ok()?.is_empty() || user.len() > MAX_USER_PATTERN {
        return None;
    }
    let mut hop = Hop {
        user: (!user.is_empty()).then(|| user.to_string()),
        hostname: (!hostname.is_empty()).then(|| hostname.to_string()),
        keys: Vec::new(),
    };
    while !r.is_empty() {
        let key = r.read_string().ok()?;
        crate::key::PublicKey::parse_wire_blob(key)
            .map(|_| ())
            .or_else(|_| crate::cert::Certificate::parse(key).map(|_| ()))
            .ok()?;
        let is_ca = r.read_u8().ok()? != 0;
        hop.keys.push((key.to_vec(), is_ca));
    }
    Some(hop)
}

fn parse_dest_constraint(m: &mut Reader<'_>) -> Option<DestConstraint> {
    let mut r = Reader::new(m.read_string().ok()?);
    let from = parse_hop(r.read_string().ok()?)?;
    let to = parse_hop(r.read_string().ok()?)?;
    if !r.read_string().ok()?.is_empty() {
        return None;
    }
    // `from` names a host with its keys, or neither (the origin), and
    // never a user; `to` always names a host with keys.
    if from.hostname.is_none() != from.keys.is_empty()
        || from.user.is_some()
        || to.hostname.is_none()
        || to.keys.is_empty()
    {
        return None;
    }
    Some(DestConstraint { from, to })
}

/// Whether the host key (or host certificate) `key` is one of `hop`'s:
/// a plain key listed as such, or a certificate for the hop's host name
/// signed by a CA key listed for it.
fn match_key_hop(key: &[u8], hop: &Hop) -> bool {
    let cert = if is_cert_blob(key) {
        match crate::cert::Certificate::parse(key) {
            Ok(c) => Some(c),
            Err(_) => return false,
        }
    } else {
        None
    };
    let hostname = hop.hostname.as_deref().unwrap_or("(ORIGIN)");
    hop.keys.iter().any(|(k, is_ca)| match &cert {
        None => !is_ca && k == key,
        Some(c) => {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_secs());
            *is_ca
                && c.signature_key_blob == *k
                && c.check_type(crate::cert::CertType::Host).is_ok()
                && c.check_validity(now).is_ok()
                && (c.valid_principals.is_empty()
                    || c.valid_principals.iter().any(|p| p == hostname))
                && c.verify_ca_signature(ALLOWED_CA_SIGALGS).is_ok()
        }
    })
}

/// Whether one of `held`'s constraints allows the hop from `from` (the
/// origin when `None`) to `to` (any host when `None`) for `user`.
fn permitted_by_dest_constraints(
    from: Option<&[u8]>,
    to: Option<&[u8]>,
    held: &Held,
    user: Option<&str>,
) -> bool {
    held.dest.iter().any(|d| {
        let from_ok = match from {
            None => d.from.hostname.is_none() && d.from.keys.is_empty(),
            Some(k) => match_key_hop(k, &d.from),
        };
        let to_ok = to.is_none_or(|k| match_key_hop(k, &d.to));
        let user_ok = match (&d.to.user, user) {
            (Some(pat), Some(u)) => crate::config::glob::glob_match(pat, u),
            _ => true,
        };
        from_ok && to_ok && user_ok
    })
}

/// OpenSSH's `identity_permitted`: whether `held` may be seen or used on
/// `conn`, walking the hops the connection was bound along; `user` is the
/// target user of a signature request.
fn identity_permitted(held: &Held, conn: &ConnectionState, user: Option<&str>) -> bool {
    if held.dest.is_empty() {
        return true;
    }
    if conn.binds.is_empty() {
        // Local use, unless a bind was attempted and failed.
        return !conn.bind_attempted;
    }
    let last = conn.binds.len() - 1;
    let mut from: Option<&[u8]> = None;
    for (i, b) in conn.binds.iter().enumerate() {
        let mut test_user = None;
        if i == last {
            // The user can only be checked at the final hop, which must
            // not be a forwarding when signing.
            test_user = user;
            if b.forwarded && user.is_some() {
                return false;
            }
        } else if !b.forwarded {
            return false;
        }
        if !permitted_by_dest_constraints(from, Some(&b.host_key), held, test_user) {
            return false;
        }
        from = Some(&b.host_key);
    }
    // Listing through a forwarding: only keys usable beyond this host.
    let b = &conn.binds[last];
    if b.forwarded && user.is_none() {
        return permitted_by_dest_constraints(Some(&b.host_key), None, held, None);
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent::client::Agent;

    fn fixture(name: &str) -> PrivateKey {
        let path = format!("{}/tests/fixtures/cert/{name}", env!("CARGO_MANIFEST_DIR"));
        PrivateKey::parse_openssh_pem(&std::fs::read_to_string(path).unwrap(), None).unwrap()
    }

    fn msg(t: u8, body: &[u8]) -> Vec<u8> {
        reply(t, body)
    }

    /// A security key added with `sk-provider@openssh.com`: `internal` and
    /// allow-listed libraries are taken, others refused, and the
    /// constraint is refused on a key that is not a security key.
    #[test]
    fn sk_provider_constraint() {
        let sk_key = {
            let path = format!(
                "{}/tests/fixtures/sk/ed25519-sk",
                env!("CARGO_MANIFEST_DIR")
            );
            PrivateKey::parse_openssh_pem(&std::fs::read_to_string(path).unwrap(), None).unwrap()
        };
        let with_provider = |key: &PrivateKey, p: &str| {
            let mut body = key.to_agent_add_body();
            let mut w = Writer::new();
            w.write_u8(SSH_AGENT_CONSTRAIN_EXTENSION);
            w.write_string(b"sk-provider@openssh.com");
            w.write_string(p.as_bytes());
            body.extend_from_slice(w.as_slice());
            msg(SSH_AGENTC_ADD_ID_CONSTRAINED, &body)
        };
        let mut s = AgentState::new();
        assert_eq!(
            s.handle(&with_provider(&sk_key, "internal"))[0],
            SSH_AGENT_SUCCESS
        );
        assert_eq!(s.keys[0].sk_provider.as_deref(), Some("internal"));
        // Not under /usr/lib*: refused.
        let here = std::env::current_exe().unwrap();
        let mut s = AgentState::new();
        assert_eq!(
            s.handle(&with_provider(&sk_key, here.to_str().unwrap()))[0],
            SSH_AGENT_FAILURE
        );
        // Allowed by -P, and canonicalised.
        s.set_allowed_providers(here.parent().unwrap().join("*").to_str().unwrap());
        assert_eq!(
            s.handle(&with_provider(&sk_key, here.to_str().unwrap()))[0],
            SSH_AGENT_SUCCESS
        );
        // A provider for a key held in memory is refused.
        let mut s = AgentState::new();
        assert_eq!(
            s.handle(&with_provider(&fixture("u_ed25519"), "internal"))[0],
            SSH_AGENT_FAILURE
        );
    }

    fn add(state: &mut AgentState, key: &PrivateKey) -> u8 {
        state.handle(&msg(SSH_AGENTC_ADD_IDENTITY, &key.to_agent_add_body()))[0]
    }

    fn sign(state: &mut AgentState, blob: &[u8], data: &[u8], flags: u32) -> Option<Vec<u8>> {
        let mut w = Writer::new();
        w.write_string(blob);
        w.write_string(data);
        w.write_u32(flags);
        let r = state.handle(&msg(SSH_AGENTC_SIGN_REQUEST, w.as_slice()));
        if r[0] != SSH_AGENT_SIGN_RESPONSE {
            return None;
        }
        Some(Reader::new(&r[1..]).read_string().unwrap().to_vec())
    }

    fn count(state: &mut AgentState) -> u32 {
        let r = state.handle(&[SSH_AGENTC_REQUEST_IDENTITIES]);
        assert_eq!(r[0], SSH_AGENT_IDENTITIES_ANSWER);
        Reader::new(&r[1..]).read_u32().unwrap()
    }

    fn sig_alg(sig: &[u8]) -> String {
        String::from_utf8(Reader::new(sig).read_string().unwrap().to_vec()).unwrap()
    }

    #[test]
    fn add_list_sign_verify() {
        let mut s = AgentState::new();
        let ed = fixture("u_ed25519");
        let rsa = fixture("u_rsa");
        assert_eq!(add(&mut s, &ed), SSH_AGENT_SUCCESS);
        assert_eq!(add(&mut s, &rsa), SSH_AGENT_SUCCESS);
        assert_eq!(count(&mut s), 2);
        // Re-adding replaces rather than duplicates.
        assert_eq!(add(&mut s, &ed), SSH_AGENT_SUCCESS);
        assert_eq!(count(&mut s), 2);

        let ed_blob = ed.public_key().wire_blob();
        let sig = sign(&mut s, &ed_blob, b"data", 0).unwrap();
        crate::hostkey::host_key_verify_by_name("ssh-ed25519", &ed_blob)
            .unwrap()
            .verify(b"data", &sig)
            .unwrap();

        let rsa_blob = rsa.public_key().wire_blob();
        for (flags, alg) in [(4, "rsa-sha2-512"), (2, "rsa-sha2-256")] {
            let sig = sign(&mut s, &rsa_blob, b"data", flags).unwrap();
            assert_eq!(sig_alg(&sig), alg);
            crate::hostkey::host_key_verify_by_name(alg, &rsa_blob)
                .unwrap()
                .verify(b"data", &sig)
                .unwrap();
        }
        assert_eq!(
            sig_alg(&sign(&mut s, &rsa_blob, b"data", 0).unwrap()),
            "ssh-rsa"
        );
        // Unknown key.
        assert!(sign(&mut s, b"nope", b"data", 0).is_none());
    }

    #[test]
    fn certificates_are_held_as_identities() {
        let mut s = AgentState::new();
        for (name, alg) in [
            ("u_ed25519", "ssh-ed25519"),
            ("u_ecdsa", "ecdsa-sha2-nistp256"),
            ("u_ecdsa384", "ecdsa-sha2-nistp384"),
            ("u_ecdsa521", "ecdsa-sha2-nistp521"),
            ("u_rsa", "rsa-sha2-512"),
        ] {
            let key = fixture(name);
            let path = format!(
                "{}/tests/fixtures/cert/{name}-cert.pub",
                env!("CARGO_MANIFEST_DIR")
            );
            let cert = crate::cert::Certificate::parse_openssh_line(
                std::fs::read_to_string(path).unwrap().trim(),
            )
            .unwrap();
            let body = key.to_agent_add_cert_body(&cert.raw);
            assert_eq!(
                s.handle(&msg(SSH_AGENTC_ADD_IDENTITY, &body))[0],
                SSH_AGENT_SUCCESS,
                "{name}"
            );
            // Signed for under the certificate, with its key.
            let sig = sign(&mut s, &cert.raw, b"data", 4).unwrap();
            crate::hostkey::host_key_verify_by_name(alg, cert.embedded_pubkey_blob())
                .unwrap()
                .verify(b"data", &sig)
                .unwrap();
        }
        assert_eq!(count(&mut s), 5);
        // A certificate sent with another key's private half is refused.
        let cert_line = std::fs::read_to_string(format!(
            "{}/tests/fixtures/cert/u_ed25519-cert.pub",
            env!("CARGO_MANIFEST_DIR")
        ))
        .unwrap();
        let cert = crate::cert::Certificate::parse_openssh_line(cert_line.trim()).unwrap();
        let PrivateKey::Ed25519 { public, .. } = fixture("u_ed25519") else {
            unreachable!()
        };
        let other = PrivateKey::Ed25519 {
            seed: [7; 32],
            public,
            comment: String::new(),
        };
        let body = other.to_agent_add_cert_body(&cert.raw);
        assert_eq!(
            s.handle(&msg(SSH_AGENTC_ADD_IDENTITY, &body))[0],
            SSH_AGENT_FAILURE
        );
    }

    /// `session-bind@openssh.com` for `host` over `sid`.
    fn bind(
        state: &mut AgentState,
        conn: &mut ConnectionState,
        host: &PrivateKey,
        sid: &[u8],
        fwd: bool,
    ) -> u8 {
        let sig = host.agent_signer(0).unwrap().sign(sid).unwrap();
        let mut w = Writer::new();
        w.write_string(b"session-bind@openssh.com");
        w.write_string(&host.public_key().wire_blob());
        w.write_string(sid);
        w.write_string(&sig);
        w.write_u8(u8::from(fwd));
        state.handle_on(conn, &msg(SSH_AGENTC_EXTENSION, w.as_slice()))[0]
    }

    /// The data a client signs for `publickey-hostbound-v00`.
    fn userauth(sid: &[u8], user: &str, key: &[u8], host: &[u8]) -> Vec<u8> {
        let mut w = Writer::new();
        w.write_string(sid);
        w.write_u8(50);
        w.write_string(user.as_bytes());
        w.write_string(b"ssh-connection");
        w.write_string(b"publickey-hostbound-v00@openssh.com");
        w.write_u8(1);
        w.write_string(b"ssh-ed25519");
        w.write_string(key);
        w.write_string(host);
        w.into_vec()
    }

    fn sign_on(state: &mut AgentState, conn: &mut ConnectionState, blob: &[u8], data: &[u8]) -> u8 {
        let mut w = Writer::new();
        w.write_string(blob);
        w.write_string(data);
        w.write_u32(0);
        state.handle_on(conn, &msg(SSH_AGENTC_SIGN_REQUEST, w.as_slice()))[0]
    }

    fn listed(state: &mut AgentState, conn: &mut ConnectionState) -> u32 {
        let r = state.handle_on(conn, &[SSH_AGENTC_REQUEST_IDENTITIES]);
        Reader::new(&r[1..]).read_u32().unwrap()
    }

    #[test]
    fn destination_constraints() {
        let mut s = AgentState::new();
        let user_key = fixture("u_ed25519");
        let host = fixture("h_ed25519");
        let other_host = fixture("u_ecdsa");
        let host_blob = host.public_key().wire_blob();
        let key_blob = user_key.public_key().wire_blob();

        // Usable as alice (pattern) at `host`, from the origin.
        let mut c = crate::agent::AddConstraints::default();
        c.destinations
            .push(crate::agent::DestinationConstraint::new(
                crate::agent::DestinationHop::default(),
                crate::agent::DestinationHop::new(
                    Some("ali*".into()),
                    Some("host".into()),
                    vec![(host_blob.clone(), false)],
                ),
            ));
        let mut body = user_key.to_agent_add_body();
        let mut probe = Writer::new();
        probe.write_u8(SSH_AGENT_CONSTRAIN_EXTENSION);
        probe.write_string(b"restrict-destination-v00@openssh.com");
        let mut list = Writer::new();
        for d in &c.destinations {
            let mut w = Writer::new();
            w.write_string(&d.from.encode_for_test());
            w.write_string(&d.to.encode_for_test());
            w.write_string(b"");
            list.write_string(w.as_slice());
        }
        probe.write_string(list.as_slice());
        body.extend_from_slice(probe.as_slice());
        assert_eq!(
            s.handle(&msg(SSH_AGENTC_ADD_ID_CONSTRAINED, &body))[0],
            SSH_AGENT_SUCCESS
        );

        // Local, unbound use: listed, but signing needs a bound session.
        let mut local = ConnectionState::default();
        assert_eq!(listed(&mut s, &mut local), 1);
        let sid = b"session-id-1";
        let data = userauth(sid, "alice", &key_blob, &host_blob);
        assert_eq!(
            sign_on(&mut s, &mut local, &key_blob, &data),
            SSH_AGENT_FAILURE
        );

        // Bound to `host`: signs for alice, not for bob or another session.
        let mut conn = ConnectionState::default();
        assert_eq!(
            bind(&mut s, &mut conn, &host, sid, false),
            SSH_AGENT_SUCCESS
        );
        assert_eq!(
            sign_on(&mut s, &mut conn, &key_blob, &data),
            SSH_AGENT_SIGN_RESPONSE
        );
        let bob = userauth(sid, "bob", &key_blob, &host_blob);
        assert_eq!(
            sign_on(&mut s, &mut conn, &key_blob, &bob),
            SSH_AGENT_FAILURE
        );
        let stale = userauth(b"other", "alice", &key_blob, &host_blob);
        assert_eq!(
            sign_on(&mut s, &mut conn, &key_blob, &stale),
            SSH_AGENT_FAILURE
        );
        // A connection used for authentication is not rebound.
        assert_eq!(
            bind(&mut s, &mut conn, &host, b"session-id-2", false),
            SSH_AGENT_EXTENSION_FAILURE
        );

        // Bound to another host: the key is hidden and refuses to sign.
        let mut elsewhere = ConnectionState::default();
        assert_eq!(
            bind(&mut s, &mut elsewhere, &other_host, sid, false),
            SSH_AGENT_SUCCESS
        );
        assert_eq!(listed(&mut s, &mut elsewhere), 0);
        let data = userauth(
            sid,
            "alice",
            &key_blob,
            &other_host.public_key().wire_blob(),
        );
        assert_eq!(
            sign_on(&mut s, &mut elsewhere, &key_blob, &data),
            SSH_AGENT_FAILURE
        );

        // Forwarded to `host`: nothing beyond it is allowed, so hidden.
        let mut fwd = ConnectionState::default();
        assert_eq!(bind(&mut s, &mut fwd, &host, sid, true), SSH_AGENT_SUCCESS);
        assert_eq!(listed(&mut s, &mut fwd), 0);

        // A bad binding signature is refused, and then nothing signs.
        let mut bad = ConnectionState::default();
        let mut w = Writer::new();
        w.write_string(b"session-bind@openssh.com");
        w.write_string(&host_blob);
        w.write_string(sid);
        w.write_string(&other_host.agent_signer(0).unwrap().sign(sid).unwrap());
        w.write_u8(0);
        assert_eq!(
            s.handle_on(&mut bad, &msg(SSH_AGENTC_EXTENSION, w.as_slice()))[0],
            SSH_AGENT_EXTENSION_FAILURE
        );
        assert_eq!(listed(&mut s, &mut bad), 0);
    }

    #[test]
    fn query_extension() {
        let mut s = AgentState::new();
        let mut w = Writer::new();
        w.write_string(b"query");
        let r = s.handle(&msg(SSH_AGENTC_EXTENSION, w.as_slice()));
        assert_eq!(r[0], SSH_AGENT_EXTENSION_RESPONSE);
        let mut r = Reader::new(&r[1..]);
        assert_eq!(r.read_string().unwrap(), b"query");
        assert_eq!(r.read_string().unwrap(), b"session-bind@openssh.com");
        let mut w = Writer::new();
        w.write_string(b"nope@example.com");
        assert_eq!(
            s.handle(&msg(SSH_AGENTC_EXTENSION, w.as_slice()))[0],
            SSH_AGENT_FAILURE
        );
    }

    #[test]
    fn constraints_lock_and_remove() {
        let mut s = AgentState::new();
        let ed = fixture("u_ed25519");
        let ec = fixture("u_ecdsa");
        // Lifetime 0 s: already expired on the next request.
        let mut body = ed.to_agent_add_body();
        body.push(SSH_AGENT_CONSTRAIN_LIFETIME);
        body.extend_from_slice(&0u32.to_be_bytes());
        assert_eq!(
            s.handle(&msg(SSH_AGENTC_ADD_ID_CONSTRAINED, &body))[0],
            SSH_AGENT_SUCCESS
        );
        assert_eq!(count(&mut s), 0);
        // `confirm` cannot be honoured: refused, key not held.
        let mut body = ed.to_agent_add_body();
        body.push(2);
        assert_eq!(
            s.handle(&msg(SSH_AGENTC_ADD_ID_CONSTRAINED, &body))[0],
            SSH_AGENT_FAILURE
        );
        assert_eq!(count(&mut s), 0);

        add(&mut s, &ed);
        add(&mut s, &ec);
        let mut w = Writer::new();
        w.write_string(b"pw");
        let lock = msg(SSH_AGENTC_LOCK, w.as_slice());
        assert_eq!(s.handle(&lock)[0], SSH_AGENT_SUCCESS);
        assert_eq!(count(&mut s), 0, "locked agent lists nothing");
        assert!(sign(&mut s, &ed.public_key().wire_blob(), b"x", 0).is_none());
        assert_eq!(add(&mut s, &ed), SSH_AGENT_FAILURE);
        let mut bad = Writer::new();
        bad.write_string(b"wrong");
        assert_eq!(
            s.handle(&msg(SSH_AGENTC_UNLOCK, bad.as_slice()))[0],
            SSH_AGENT_FAILURE
        );
        std::thread::sleep(UNLOCK_DELAY_STEP);
        assert_eq!(
            s.handle(&msg(SSH_AGENTC_UNLOCK, w.as_slice()))[0],
            SSH_AGENT_SUCCESS
        );
        assert_eq!(count(&mut s), 2);

        let mut r = Writer::new();
        r.write_string(&ec.public_key().wire_blob());
        assert_eq!(
            s.handle(&msg(SSH_AGENTC_REMOVE_IDENTITY, r.as_slice()))[0],
            SSH_AGENT_SUCCESS
        );
        assert_eq!(count(&mut s), 1);
        assert_eq!(
            s.handle(&[SSH_AGENTC_REMOVE_ALL_IDENTITIES])[0],
            SSH_AGENT_SUCCESS
        );
        assert_eq!(count(&mut s), 0);
        // An extension request without a name does not parse.
        assert_eq!(s.handle(&[SSH_AGENTC_EXTENSION])[0], SSH_AGENT_FAILURE);
        assert_eq!(s.handle(&[99])[0], SSH_AGENT_FAILURE);
        assert_eq!(s.handle(&[])[0], SSH_AGENT_FAILURE);
    }

    /// Failed unlocks back off: until the penalty passes even the right
    /// passphrase is refused, and each failure lengthens it.
    #[test]
    fn unlock_backs_off_after_failures() {
        let mut s = AgentState::new();
        let pass = |p: &[u8]| {
            let mut w = Writer::new();
            w.write_string(p);
            w.as_slice().to_vec()
        };
        assert_eq!(
            s.handle(&msg(SSH_AGENTC_LOCK, &pass(b"pw")))[0],
            SSH_AGENT_SUCCESS
        );
        let unlock = |s: &mut AgentState, p: &[u8]| s.handle(&msg(SSH_AGENTC_UNLOCK, &pass(p)))[0];
        // The penalty set by the failure that started at `before`. Checked
        // and expired by hand, not with sleeps, so a stalled CI runner
        // cannot outlast it mid-test.
        let penalty = |s: &AgentState, before: Instant| s.unlock_after.unwrap() - before;
        let expire = |s: &mut AgentState| s.unlock_after = Some(Instant::now());
        let before = Instant::now();
        assert_eq!(unlock(&mut s, b"bad"), SSH_AGENT_FAILURE);
        assert!(penalty(&s, before) >= UNLOCK_DELAY_STEP);
        assert_eq!(
            unlock(&mut s, b"pw"),
            SSH_AGENT_FAILURE,
            "within the penalty"
        );
        expire(&mut s);
        let before = Instant::now();
        assert_eq!(unlock(&mut s, b"bad"), SSH_AGENT_FAILURE);
        assert_eq!(s.unlock_failures, 2);
        assert!(
            penalty(&s, before) >= UNLOCK_DELAY_STEP * 2,
            "penalty grows"
        );
        assert_eq!(unlock(&mut s, b"pw"), SSH_AGENT_FAILURE);
        expire(&mut s);
        assert_eq!(unlock(&mut s, b"pw"), SSH_AGENT_SUCCESS);
        assert_eq!(s.unlock_failures, 0);
        // A new lock salts afresh.
        assert_eq!(
            s.handle(&msg(SSH_AGENTC_LOCK, &pass(b"pw")))[0],
            SSH_AGENT_SUCCESS
        );
        let salt = s.locked.as_ref().unwrap().salt;
        assert_eq!(unlock(&mut s, b"pw"), SSH_AGENT_SUCCESS);
        s.handle(&msg(SSH_AGENTC_LOCK, &pass(b"pw")));
        assert_ne!(s.locked.as_ref().unwrap().salt, salt);
    }

    /// A session bind sent while locked still marks the connection as
    /// bound-attempted, so it is not treated as local after the unlock.
    #[test]
    fn session_bind_while_locked_marks_connection() {
        let mut s = AgentState::new();
        let mut conn = ConnectionState::default();
        let mut w = Writer::new();
        w.write_string(b"pw");
        let pw = w.as_slice().to_vec();
        s.handle_on(&mut conn, &msg(SSH_AGENTC_LOCK, &pw));
        let mut b = Writer::new();
        b.write_string(b"session-bind@openssh.com");
        b.write_string(b"key");
        b.write_string(b"sid");
        b.write_string(b"sig");
        b.write_u8(1);
        assert_eq!(
            s.handle_on(&mut conn, &msg(SSH_AGENTC_EXTENSION, b.as_slice()))[0],
            SSH_AGENT_FAILURE
        );
        assert!(conn.bind_attempted);
        assert_eq!(
            s.handle_on(&mut conn, &msg(SSH_AGENTC_UNLOCK, &pw))[0],
            SSH_AGENT_SUCCESS
        );
        assert!(conn.binds.is_empty() && conn.bind_attempted);
    }

    /// The client's new requests against this agent, over a real socket.
    #[test]
    fn client_round_trip() {
        use std::io::{Read, Write};
        let dir = std::env::temp_dir().join(format!("puressh-agent-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("sock");
        let _ = std::fs::remove_file(&path);
        let listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
        std::thread::spawn(move || {
            let (mut conn, _) = listener.accept().unwrap();
            let mut state = AgentState::new();
            let mut len = [0u8; 4];
            while conn.read_exact(&mut len).is_ok() {
                let mut req = vec![0u8; u32::from_be_bytes(len) as usize];
                conn.read_exact(&mut req).unwrap();
                let resp = state.handle(&req);
                conn.write_all(&(resp.len() as u32).to_be_bytes()).unwrap();
                conn.write_all(&resp).unwrap();
            }
        });
        let mut a = Agent::connect(&path).unwrap();
        let ed = fixture("u_ed25519");
        a.add_identity_with_lifetime(&ed, 600).unwrap();
        assert_eq!(a.identities().unwrap().len(), 1);
        a.lock(b"pw").unwrap();
        assert!(a.identities().unwrap().is_empty());
        assert!(a.unlock(b"bad").is_err());
        std::thread::sleep(UNLOCK_DELAY_STEP);
        a.unlock(b"pw").unwrap();
        a.remove_identity(&ed.public_key().wire_blob()).unwrap();
        assert!(a.remove_identity(&ed.public_key().wire_blob()).is_err());
        a.add_identity(&ed).unwrap();
        a.remove_all_identities().unwrap();
        assert!(a.identities().unwrap().is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn confirm_prompt_fingerprint_hash() {
        let ed = fixture("u_ed25519");
        let blob = ed.public_key().wire_blob();
        let mut body = ed.to_agent_add_body();
        body.push(SSH_AGENT_CONSTRAIN_CONFIRM);
        for (hash, want) in [
            ("sha256", ed.public_key().sha256_fingerprint()),
            (
                "md5",
                "MD5:05:cf:97:c7:22:3d:df:5b:87:d6:93:67:f8:60:25:79".into(),
            ),
        ] {
            let seen = std::sync::Arc::new(std::sync::Mutex::new(String::new()));
            let mut s = AgentState::new();
            let log = seen.clone();
            s.set_confirm(Box::new(move |p| {
                *log.lock().unwrap() = p.to_string();
                true
            }));
            assert!(s.set_fingerprint_hash(hash));
            assert_eq!(
                s.handle(&msg(SSH_AGENTC_ADD_ID_CONSTRAINED, &body))[0],
                SSH_AGENT_SUCCESS
            );
            assert!(sign(&mut s, &blob, b"data", 0).is_some());
            let prompt = seen.lock().unwrap().clone();
            assert!(
                prompt.contains(&format!("Key fingerprint {want}.")),
                "{prompt}"
            );
        }
    }
}
