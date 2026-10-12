//! `Agent` — synchronous ssh-agent client over a Unix socket.

use std::ffi::OsString;
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::error::{Error, Result};

use super::protocol::{
    IdentityEntry, MAX_REPLY_LEN, SSH_AGENT_CONSTRAIN_LIFETIME, SSH_AGENT_FAILURE,
    SSH_AGENT_IDENTITIES_ANSWER, SSH_AGENT_SIGN_RESPONSE, SSH_AGENT_SUCCESS,
    SSH_AGENTC_ADD_ID_CONSTRAINED, SSH_AGENTC_ADD_IDENTITY, SSH_AGENTC_LOCK,
    SSH_AGENTC_REMOVE_ALL_IDENTITIES, SSH_AGENTC_REMOVE_IDENTITY, SSH_AGENTC_UNLOCK,
    decode_identities_answer, decode_sign_response, encode_message, encode_request_identities,
    encode_sign_request,
};

/// Default per-call socket timeout. Agents are nearly always
/// loopback / local-Unix-socket, so anything over a second indicates
/// the agent is wedged.
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(10);

/// One identity loaded into the agent — public key + comment.
///
/// `key_blob` is the SSH wire-format public-key blob; the algorithm
/// name is the first `string` field inside it.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct AgentIdentity {
    /// SSH wire-format public key (`string algorithm || …`).
    pub key_blob: Vec<u8>,
    /// `ssh-add`-supplied comment, often the original key's path.
    pub comment: String,
}

impl AgentIdentity {
    /// Extract the algorithm name (first SSH `string` inside `key_blob`).
    /// Returns the empty string if the blob is malformed.
    pub fn algorithm(&self) -> String {
        // `Reader` bounds-checks the length prefix without the unchecked
        // `4 + len` arithmetic that could wrap on 32-bit targets.
        crate::format::Reader::new(&self.key_blob)
            .read_string()
            .map(|s| String::from_utf8_lossy(s).into_owned())
            .unwrap_or_default()
    }

    /// Free-form comment.
    pub fn comment(&self) -> &str {
        &self.comment
    }

    /// SSH wire-format key blob.
    pub fn key_blob(&self) -> &[u8] {
        &self.key_blob
    }
}

/// Synchronous ssh-agent client.
///
/// Each public method is one round-trip: request → reply. Errors are
/// surfaced as `Error::Protocol` / `Error::Format` for wire faults and
/// `Error::Io` for socket faults; agent-reported `SSH_AGENT_FAILURE`
/// becomes `Error::Protocol("agent: failure")`.
pub struct Agent {
    stream: UnixStream,
}

impl Agent {
    /// Connect to the agent at `path`.
    pub fn connect(path: impl AsRef<Path>) -> Result<Self> {
        let stream = UnixStream::connect(path.as_ref()).map_err(Error::from)?;
        stream
            .set_read_timeout(Some(DEFAULT_TIMEOUT))
            .map_err(Error::from)?;
        stream
            .set_write_timeout(Some(DEFAULT_TIMEOUT))
            .map_err(Error::from)?;
        Ok(Self { stream })
    }

    /// Connect to the agent named by `$SSH_AUTH_SOCK`: `Ok(None)` when it is
    /// unset or empty; an error when it names no Unix-domain socket (a
    /// stale path after a logout) or the connection fails.
    ///
    /// As OpenSSH, the path is taken as given: a symlink to the socket (a
    /// `~/.ssh/auth_sock` kept for tmux, 1Password's `agent.sock`) and an
    /// agent owned by another user (`sudo` with `SSH_AUTH_SOCK` kept) are
    /// used; access is the filesystem's to grant.
    pub fn connect_env() -> Result<Option<Self>> {
        let raw: OsString = match std::env::var_os("SSH_AUTH_SOCK") {
            Some(v) if !v.is_empty() => v,
            _ => return Ok(None),
        };
        let path = PathBuf::from(raw);
        if let Err(why) = validate_auth_sock(&path) {
            return Err(Error::Io(std::io::Error::other(why)));
        }
        Self::connect(path).map(Some)
    }

    /// List all identities the agent currently holds.
    pub fn identities(&mut self) -> Result<Vec<AgentIdentity>> {
        self.write_frame(&encode_request_identities())?;
        let (msg_type, body) = self.read_frame()?;
        if msg_type == SSH_AGENT_FAILURE {
            return Err(Error::Protocol("agent: failure on identities request"));
        }
        if msg_type != SSH_AGENT_IDENTITIES_ANSWER {
            return Err(Error::Protocol("agent: unexpected identities-reply type"));
        }
        let raw = decode_identities_answer(&body)?;
        Ok(raw
            .into_iter()
            .map(|IdentityEntry { key_blob, comment }| AgentIdentity { key_blob, comment })
            .collect())
    }

    /// Ask the agent to sign `data` under the identity whose public
    /// blob equals `key_blob`. `flags` is the bitmask from
    /// the agent protocol module (`SSH_AGENT_RSA_SHA2_*` for RSA).
    ///
    /// Returns the SSH wire-format signature blob (`string algorithm ||
    /// string raw_sig`).
    pub fn sign(&mut self, key_blob: &[u8], data: &[u8], flags: u32) -> Result<Vec<u8>> {
        self.write_frame(&encode_sign_request(key_blob, data, flags))?;
        let (msg_type, body) = self.read_frame()?;
        if msg_type == SSH_AGENT_FAILURE {
            return Err(Error::Protocol("agent: failure on sign request"));
        }
        if msg_type != SSH_AGENT_SIGN_RESPONSE {
            return Err(Error::Protocol("agent: unexpected sign-reply type"));
        }
        decode_sign_response(&body)
    }

    /// Add a private identity to the agent (`SSH_AGENTC_ADD_IDENTITY`,
    /// `PROTOCOL.agent` §4.2) — the wire half of `AddKeysToAgent yes`.
    ///
    /// The agent stores the key in memory and will offer it for subsequent
    /// `sign` requests. Returns `Ok(())` on `SSH_AGENT_SUCCESS`, and a
    /// protocol error on `SSH_AGENT_FAILURE` (e.g. the agent refuses to add
    /// keys, or doesn't support the key type).
    pub fn add_identity(&mut self, key: &crate::key::PrivateKey) -> Result<()> {
        // Both the request body and the framed message carry the cleartext
        // private key; wipe them once written.
        let body = zeroize::Zeroizing::new(key.to_agent_add_body());
        let frame = zeroize::Zeroizing::new(encode_message(SSH_AGENTC_ADD_IDENTITY, &body));
        self.write_frame(&frame)?;
        let (msg_type, _) = self.read_frame()?;
        match msg_type {
            SSH_AGENT_SUCCESS => Ok(()),
            SSH_AGENT_FAILURE => Err(Error::Protocol("agent: failure adding identity")),
            _ => Err(Error::Protocol("agent: unexpected reply to add-identity")),
        }
    }

    /// Add a private identity that the agent forgets after `lifetime`
    /// seconds (`SSH_AGENTC_ADD_ID_CONSTRAINED`, `ssh-add -t`).
    pub fn add_identity_with_lifetime(
        &mut self,
        key: &crate::key::PrivateKey,
        lifetime: u32,
    ) -> Result<()> {
        let mut body = zeroize::Zeroizing::new(key.to_agent_add_body());
        body.push(SSH_AGENT_CONSTRAIN_LIFETIME);
        body.extend_from_slice(&lifetime.to_be_bytes());
        let frame = zeroize::Zeroizing::new(encode_message(SSH_AGENTC_ADD_ID_CONSTRAINED, &body));
        self.simple_request(&frame, "add-identity")
    }

    /// Remove the identity whose public blob is `key_blob` (`ssh-add -d`).
    pub fn remove_identity(&mut self, key_blob: &[u8]) -> Result<()> {
        let mut w = crate::format::Writer::new();
        w.write_string(key_blob);
        let frame = encode_message(SSH_AGENTC_REMOVE_IDENTITY, w.as_slice());
        self.simple_request(&frame, "remove-identity")
    }

    /// Remove every identity (`ssh-add -D`).
    pub fn remove_all_identities(&mut self) -> Result<()> {
        let frame = encode_message(SSH_AGENTC_REMOVE_ALL_IDENTITIES, &[]);
        self.simple_request(&frame, "remove-all-identities")
    }

    /// Lock the agent with `passphrase` (`ssh-add -x`): it lists and signs
    /// nothing until unlocked.
    pub fn lock(&mut self, passphrase: &[u8]) -> Result<()> {
        let mut w = crate::format::Writer::new();
        w.write_string(passphrase);
        let frame = zeroize::Zeroizing::new(encode_message(SSH_AGENTC_LOCK, w.as_slice()));
        self.simple_request(&frame, "lock")
    }

    /// Unlock the agent (`ssh-add -X`).
    pub fn unlock(&mut self, passphrase: &[u8]) -> Result<()> {
        let mut w = crate::format::Writer::new();
        w.write_string(passphrase);
        let frame = zeroize::Zeroizing::new(encode_message(SSH_AGENTC_UNLOCK, w.as_slice()));
        self.simple_request(&frame, "unlock")
    }

    fn simple_request(&mut self, frame: &[u8], what: &'static str) -> Result<()> {
        self.write_frame(frame)?;
        let (msg_type, _) = self.read_frame()?;
        match msg_type {
            SSH_AGENT_SUCCESS => Ok(()),
            SSH_AGENT_FAILURE => Err(Error::Protocol(match what {
                "lock" => "agent: lock refused (already locked?)",
                "unlock" => "agent: unlock refused (wrong passphrase?)",
                "remove-identity" => "agent: no such identity",
                _ => "agent: request refused",
            })),
            _ => Err(Error::Protocol("agent: unexpected reply")),
        }
    }

    fn write_frame(&mut self, frame: &[u8]) -> Result<()> {
        self.stream.write_all(frame).map_err(Error::from)?;
        Ok(())
    }

    /// Read one length-prefixed frame, returning `(type, body)`.
    fn read_frame(&mut self) -> Result<(u8, Vec<u8>)> {
        let mut len_buf = [0u8; 4];
        self.stream.read_exact(&mut len_buf).map_err(Error::from)?;
        let len = u32::from_be_bytes(len_buf) as usize;
        if len == 0 {
            return Err(Error::Format("agent: zero-length frame"));
        }
        if len > MAX_REPLY_LEN {
            return Err(Error::Format("agent: reply exceeds MAX_REPLY_LEN"));
        }
        let mut buf = vec![0u8; len];
        self.stream.read_exact(&mut buf).map_err(Error::from)?;
        let msg_type = buf[0];
        let body = buf.split_off(1);
        Ok((msg_type, body))
    }
}

/// Whether `path` is a Unix-domain socket (following symlinks, as
/// OpenSSH's `connect(2)` does). The reason when not: `No such file or
/// directory` for a stale path. Crate-visible so agent *forwarding*
/// (`forwarding::agent`) skips a missing agent the same way.
pub(crate) fn validate_auth_sock(path: &Path) -> core::result::Result<(), String> {
    use std::os::unix::fs::FileTypeExt;
    let md = std::fs::metadata(path).map_err(|e| {
        let s = e.to_string();
        s.split(" (os error").next().unwrap_or(&s).to_string()
    })?;
    if !md.file_type().is_socket() {
        return Err("not a Unix-domain socket".into());
    }
    Ok(())
}

#[cfg(test)]
mod auth_sock_tests {
    use super::*;
    use std::os::unix::net::UnixListener;

    /// Helper: create a fresh Unix socket in a tempdir, return its path
    /// and the listener (held by the caller so the socket stays alive).
    fn make_socket() -> (PathBuf, UnixListener) {
        let dir = std::env::temp_dir();
        // A counter as well: macOS clocks tick in microseconds, so two
        // tests running at once could otherwise pick the same name.
        static N: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        let unique = format!(
            "puressh-auth-sock-test-{}-{}-{}",
            N.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.subsec_nanos())
                .unwrap_or(0),
        );
        let p = dir.join(unique);
        let _ = std::fs::remove_file(&p);
        let l = UnixListener::bind(&p).expect("bind unix listener");
        // Tighten mode to 0o600 in case the umask left g/o bits set.
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600));
        (p, l)
    }

    #[test]
    fn valid_owned_socket_is_accepted() {
        let (p, _l) = make_socket();
        let r = validate_auth_sock(&p);
        std::fs::remove_file(&p).ok();
        assert!(r.is_ok(), "expected Ok, got {r:?}");
    }

    #[test]
    fn nonexistent_is_rejected() {
        let p = std::env::temp_dir().join(format!(
            "puressh-noent-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.subsec_nanos())
                .unwrap_or(0),
        ));
        assert!(validate_auth_sock(&p).is_err());
    }

    #[test]
    fn regular_file_is_rejected() {
        let p = std::env::temp_dir().join(format!(
            "puressh-regular-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.subsec_nanos())
                .unwrap_or(0),
        ));
        std::fs::write(&p, b"hello").unwrap();
        // Tighten mode so the rejection is about S_IFMT, not 0o077.
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();
        let r = validate_auth_sock(&p);
        std::fs::remove_file(&p).ok();
        let msg = r.unwrap_err();
        assert!(msg.contains("not a Unix-domain socket"), "got: {msg}");
    }

    #[test]
    fn symlink_to_a_socket_is_accepted() {
        // As OpenSSH (a ~/.ssh/auth_sock for tmux, 1Password's agent.sock).
        let (target, _l) = make_socket();
        let link = std::env::temp_dir().join(format!(
            "puressh-symlink-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.subsec_nanos())
                .unwrap_or(0),
        ));
        let _ = std::fs::remove_file(&link);
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let r = validate_auth_sock(&link);
        std::fs::remove_file(&link).ok();
        std::fs::remove_file(&target).ok();
        assert!(r.is_ok(), "{r:?}");
    }

    #[test]
    fn group_accessible_socket_is_accepted() {
        // Desktop keyring agents' sockets are often group-accessible; the
        // filesystem decides who may connect, as with OpenSSH.
        let (p, _l) = make_socket();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o775)).unwrap();
        let r = validate_auth_sock(&p);
        std::fs::remove_file(&p).ok();
        assert!(r.is_ok(), "{r:?}");
    }
}
