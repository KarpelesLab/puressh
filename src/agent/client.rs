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
    pub fn connect_env() -> Result<Option<Self>> {
        let raw: OsString = match std::env::var_os("SSH_AUTH_SOCK") {
            Some(v) if !v.is_empty() => v,
            _ => return Ok(None),
        };
        let path = PathBuf::from(raw);
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
