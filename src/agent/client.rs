//! `Agent` — synchronous ssh-agent client over a Unix socket.

use std::ffi::OsString;
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::error::{Error, Result};

use super::protocol::{
    decode_identities_answer, decode_sign_response, encode_request_identities, encode_sign_request,
    IdentityEntry, MAX_REPLY_LEN, SSH_AGENT_FAILURE, SSH_AGENT_IDENTITIES_ANSWER,
    SSH_AGENT_SIGN_RESPONSE,
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
        if self.key_blob.len() < 4 {
            return String::new();
        }
        let len = u32::from_be_bytes([
            self.key_blob[0],
            self.key_blob[1],
            self.key_blob[2],
            self.key_blob[3],
        ]) as usize;
        if self.key_blob.len() < 4 + len {
            return String::new();
        }
        String::from_utf8_lossy(&self.key_blob[4..4 + len]).into_owned()
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

    /// Connect using `$SSH_AUTH_SOCK`. Returns `None` if the env var is
    /// unset or empty — callers typically degrade to "no agent
    /// available" rather than treating that as an error.
    ///
    /// Security: a malicious or careless setup can point `SSH_AUTH_SOCK`
    /// at a symlink, a regular file, or a socket owned by another user
    /// (or world-writable) and trick this process into asking the wrong
    /// agent to sign challenges — i.e. impersonate us against any server
    /// we contact. Before connecting we therefore validate the path with
    /// `lstat`-equivalent semantics:
    ///
    /// - the path must exist and not be a symlink (`symlink_metadata`,
    ///   `file_type().is_symlink()` check);
    /// - it must be a Unix-domain socket (the file type bits via
    ///   `libc::stat`, since the standard library does not expose
    ///   `is_socket()` directly);
    /// - it must be owned by the calling user (`st_uid == geteuid()`);
    /// - it must not be group- or world-accessible
    ///   (`st_mode & 0o077 == 0`).
    ///
    /// Any failure is reported on stderr and the function returns
    /// `Ok(None)` so the caller falls back to other auth methods rather
    /// than aborting the whole session. We only return `Err` when the
    /// underlying connect itself fails after the path passed validation.
    pub fn connect_env() -> Result<Option<Self>> {
        let raw: OsString = match std::env::var_os("SSH_AUTH_SOCK") {
            Some(v) if !v.is_empty() => v,
            _ => return Ok(None),
        };
        let path = PathBuf::from(raw);
        if let Err(why) = validate_auth_sock(&path) {
            eprintln!(
                "warning: SSH_AUTH_SOCK={} rejected: {why}; ignoring agent",
                path.display()
            );
            return Ok(None);
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
    /// [`super::protocol`] (`SSH_AGENT_RSA_SHA2_*` for RSA).
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

/// Validate a candidate `SSH_AUTH_SOCK` path. See [`Agent::connect_env`]
/// for the security rationale. Returns the human-readable reason on
/// failure so callers can log it.
fn validate_auth_sock(path: &Path) -> core::result::Result<(), String> {
    // `symlink_metadata` does not follow symlinks; combined with the
    // `is_symlink()` check this means a symlink anywhere in the *final*
    // component is rejected outright. We intentionally do NOT canonicalize
    // — canonicalization would silently follow the symlink we're trying to
    // diagnose. Symlinks earlier in the path (parent directories) are still
    // allowed because they typically belong to the OS (e.g. `/tmp` on macOS
    // is a symlink to `/private/tmp`).
    let md = std::fs::symlink_metadata(path)
        .map_err(|e| format!("cannot stat: {e} (does the agent socket exist?)"))?;
    if md.file_type().is_symlink() {
        return Err(
            "path is a symlink (a malicious symlink could redirect to another agent)".into(),
        );
    }

    // The standard library exposes file_type().is_file() / .is_dir() but
    // not .is_socket(); on Unix, std::os::unix::fs::FileTypeExt gives us
    // is_socket() and MetadataExt exposes raw st_mode / st_uid bits — both
    // routed through the already-fetched `md`, avoiding both a second
    // syscall and any unsafe libc surface. (The library forbids
    // `unsafe_code` outside the `ffi` feature; nix::unistd::geteuid wraps
    // the syscall safely for us.)
    use std::os::unix::fs::{FileTypeExt, MetadataExt};
    if !md.file_type().is_socket() {
        return Err("path is not a Unix-domain socket".into());
    }

    let euid = nix::unistd::geteuid().as_raw();
    if md.uid() != euid {
        return Err(format!(
            "socket is owned by uid {} but we are euid {} (refusing to trust another user's agent)",
            md.uid(),
            euid
        ));
    }

    // Group + other bits must all be clear. World-writable agents are an
    // obvious foot-gun; group-writable is also unsafe in any multi-user
    // setup. OpenSSH enforces the same on `ssh-agent -a`. The constant is
    // 0o077 (rwx for group and other).
    let mode = md.mode();
    if (mode & 0o077) != 0 {
        return Err(format!(
            "socket is group/world-accessible (mode {:o}); refusing to use it",
            mode & 0o777
        ));
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
        let unique = format!(
            "puressh-auth-sock-test-{}-{}",
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
    fn symlink_is_rejected() {
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
        let msg = r.unwrap_err();
        assert!(msg.contains("symlink"), "got: {msg}");
    }

    #[test]
    fn group_or_world_accessible_is_rejected() {
        let (p, _l) = make_socket();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o666)).unwrap();
        let r = validate_auth_sock(&p);
        std::fs::remove_file(&p).ok();
        let msg = r.unwrap_err();
        assert!(msg.contains("group/world-accessible"), "got: {msg}");
    }
}
