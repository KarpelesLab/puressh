//! Wire protocol for `ssh-agent` (OpenSSH `PROTOCOL.agent`).
//!
//! Frame: `uint32 length || byte type || payload`. The length covers
//! `type + payload` but not itself. All integers are big-endian; all
//! "string" fields are `uint32`-length-prefixed byte blobs (RFC 4251
//! §5).

use crate::error::{Error, Result};
use crate::format::{Reader, Writer};

// ----- Message type bytes (see `PROTOCOL.agent` §2) ----------------------

/// `SSH_AGENT_FAILURE` — agent could not service the request.
pub const SSH_AGENT_FAILURE: u8 = 5;
/// `SSH_AGENT_SUCCESS` — generic OK for unit ops that don't return data.
pub const SSH_AGENT_SUCCESS: u8 = 6;
/// Client → agent: add a private identity (`SSH_AGENTC_ADD_IDENTITY`).
pub const SSH_AGENTC_ADD_IDENTITY: u8 = 17;
/// Client → agent: list loaded identities.
pub const SSH_AGENTC_REQUEST_IDENTITIES: u8 = 11;
/// Agent → client: response to [`SSH_AGENTC_REQUEST_IDENTITIES`].
pub const SSH_AGENT_IDENTITIES_ANSWER: u8 = 12;
/// Client → agent: sign data with the named key.
pub const SSH_AGENTC_SIGN_REQUEST: u8 = 13;
/// Agent → client: signature in response to a sign request.
pub const SSH_AGENT_SIGN_RESPONSE: u8 = 14;

// ----- Sign-request flag bits (`PROTOCOL.agent` §4.5.1) ------------------

/// Request an RSA SHA-2-256 signature (`rsa-sha2-256`, RFC 8332).
pub const SSH_AGENT_RSA_SHA2_256: u32 = 2;
/// Request an RSA SHA-2-512 signature (`rsa-sha2-512`).
pub const SSH_AGENT_RSA_SHA2_512: u32 = 4;

/// Cap on how large a single agent reply we'll buffer. The OpenSSH
/// agent reports its own ~256 KiB ceiling — we go larger to tolerate
/// pathological identity counts but still refuse a runaway peer.
pub const MAX_REPLY_LEN: usize = 4 * 1024 * 1024;

/// Encode a request payload `(type, body)` into a wire-format frame.
pub fn encode_message(msg_type: u8, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + 1 + body.len());
    out.extend_from_slice(&(1u32 + body.len() as u32).to_be_bytes());
    out.push(msg_type);
    out.extend_from_slice(body);
    out
}

/// Encode `SSH_AGENTC_REQUEST_IDENTITIES`. Body is empty.
pub fn encode_request_identities() -> Vec<u8> {
    encode_message(SSH_AGENTC_REQUEST_IDENTITIES, &[])
}

/// Encode `SSH_AGENTC_SIGN_REQUEST` (`PROTOCOL.agent` §4.5).
pub fn encode_sign_request(key_blob: &[u8], data: &[u8], flags: u32) -> Vec<u8> {
    let mut w = Writer::new();
    w.write_string(key_blob);
    w.write_string(data);
    w.write_u32(flags);
    encode_message(SSH_AGENTC_SIGN_REQUEST, w.as_slice())
}

/// Decoded identity entry returned by `SSH_AGENT_IDENTITIES_ANSWER`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentityEntry {
    /// SSH wire-format public key blob (the same bytes that appear
    /// after the algorithm name in an `authorized_keys` line, decoded
    /// from base64).
    pub key_blob: Vec<u8>,
    /// Free-form comment supplied at `ssh-add` time.
    pub comment: String,
}

/// Decode an `SSH_AGENT_IDENTITIES_ANSWER` reply body (i.e. the bytes
/// *after* the message-type byte).
pub fn decode_identities_answer(body: &[u8]) -> Result<Vec<IdentityEntry>> {
    let mut r = Reader::new(body);
    let count = r.read_u32()? as usize;
    if count > 1024 {
        // OpenSSH never reports more than a few dozen; bail before
        // allocating an outsized Vec on hostile input.
        return Err(Error::Format("agent: identity count exceeds sanity cap"));
    }
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        let key_blob = r.read_string()?.to_vec();
        let comment = r.read_string()?.to_vec();
        let comment = String::from_utf8(comment).unwrap_or_default();
        out.push(IdentityEntry { key_blob, comment });
    }
    Ok(out)
}

/// Decode an `SSH_AGENT_SIGN_RESPONSE` reply body. Returns the
/// SSH-wire-format signature blob (a `string` containing `string
/// algorithm || string raw_sig`).
pub fn decode_sign_response(body: &[u8]) -> Result<Vec<u8>> {
    let mut r = Reader::new(body);
    let sig = r.read_string()?;
    Ok(sig.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_identities_frame_is_5_bytes() {
        // length = 1 (just the type byte), then the type byte itself.
        assert_eq!(encode_request_identities(), [0, 0, 0, 1, 11]);
    }

    #[test]
    fn sign_request_round_trips_body() {
        let key = b"keyblob".as_ref();
        let data = b"msg-to-sign".as_ref();
        let flags = SSH_AGENT_RSA_SHA2_256;
        let frame = encode_sign_request(key, data, flags);

        // Header: length || type
        assert_eq!(frame[4], SSH_AGENTC_SIGN_REQUEST);
        let len = u32::from_be_bytes(frame[..4].try_into().unwrap()) as usize;
        // `len` covers type + body; total frame is 4 + len bytes.
        assert_eq!(frame.len(), 4 + len);

        // Parse the body back out using our Reader to keep the test
        // honest about the wire layout.
        let body = &frame[5..];
        let mut r = Reader::new(body);
        assert_eq!(r.read_string().unwrap(), key);
        assert_eq!(r.read_string().unwrap(), data);
        assert_eq!(r.read_u32().unwrap(), flags);
    }

    #[test]
    fn identities_answer_round_trip() {
        // Build a synthetic answer body and decode it.
        let mut w = Writer::new();
        w.write_u32(2);
        w.write_string(b"blob-A");
        w.write_string(b"first key");
        w.write_string(b"blob-B");
        w.write_string(b"second key");
        let ids = decode_identities_answer(w.as_slice()).unwrap();
        assert_eq!(ids.len(), 2);
        assert_eq!(ids[0].key_blob, b"blob-A");
        assert_eq!(ids[0].comment, "first key");
        assert_eq!(ids[1].key_blob, b"blob-B");
        assert_eq!(ids[1].comment, "second key");
    }

    #[test]
    fn identities_answer_refuses_outsized_count() {
        let mut w = Writer::new();
        w.write_u32(u32::MAX); // way past the 1024-entry cap
        assert!(decode_identities_answer(w.as_slice()).is_err());
    }

    #[test]
    fn sign_response_round_trip() {
        let sig_blob = b"raw-signature-bytes".as_ref();
        let mut w = Writer::new();
        w.write_string(sig_blob);
        assert_eq!(decode_sign_response(w.as_slice()).unwrap(), sig_blob);
    }
}
