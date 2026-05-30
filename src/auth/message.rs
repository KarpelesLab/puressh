//! Wire-format encoding/decoding for the RFC 4252 / RFC 4256 message set.
//!
//! These are sans-I/O: each `encode` returns the *payload* bytes (starting with
//! the SSH message-type byte), and each `decode` takes a payload slice that
//! still includes the message-type byte and returns the parsed value.

#![allow(missing_docs)]

use alloc::string::String;
use alloc::vec::Vec;

use crate::error::{Error, Result};
use crate::format::{Reader, Writer};

pub const SSH_MSG_SERVICE_REQUEST: u8 = 5;
pub const SSH_MSG_SERVICE_ACCEPT: u8 = 6;
pub const SSH_MSG_USERAUTH_REQUEST: u8 = 50;
pub const SSH_MSG_USERAUTH_FAILURE: u8 = 51;
pub const SSH_MSG_USERAUTH_SUCCESS: u8 = 52;
pub const SSH_MSG_USERAUTH_BANNER: u8 = 53;
pub const SSH_MSG_USERAUTH_PK_OK: u8 = 60;
pub const SSH_MSG_USERAUTH_INFO_REQUEST: u8 = 60;
pub const SSH_MSG_USERAUTH_INFO_RESPONSE: u8 = 61;

/// Per-field upper bound on userauth strings. RFC 4252 / RFC 4256 don't
/// fix a maximum, but every real-world field (user name, prompts,
/// responses, banner text, public-key blob, signature) fits in well
/// under this; capping protects against a peer sending a 4 GiB string
/// length and forcing a huge allocation before any validation runs.
const MAX_USERAUTH_STRING: usize = 64 * 1024;

fn read_utf8(r: &mut Reader<'_>) -> Result<String> {
    let bytes = read_bytes_capped(r)?;
    core::str::from_utf8(bytes)
        .map(|s| s.into())
        .map_err(|_| Error::Format("auth: invalid utf-8"))
}

/// Read an SSH `string` (uint32 length + bytes), rejecting any length
/// above [`MAX_USERAUTH_STRING`]. Used in every per-field decode path
/// in this module so we never allocate a multi-megabyte buffer just
/// because the peer claimed to send one.
fn read_bytes_capped<'a>(r: &mut Reader<'a>) -> Result<&'a [u8]> {
    // We peek at the length first by reading u32 and then taking bytes
    // ourselves, so the cap fires before `Reader::read_string` would
    // attempt the take.
    let len = r.read_u32()? as usize;
    if len > MAX_USERAUTH_STRING {
        return Err(Error::Format("userauth string too large"));
    }
    r.take(len)
}

fn ensure_empty(r: &Reader<'_>) -> Result<()> {
    if !r.is_empty() {
        return Err(Error::Format("auth: trailing data"));
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceRequest {
    pub service: String,
}

impl ServiceRequest {
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(5 + self.service.len());
        w.write_u8(SSH_MSG_SERVICE_REQUEST);
        w.write_string(self.service.as_bytes());
        w.into_vec()
    }

    pub fn decode(payload: &[u8]) -> Result<Self> {
        let mut r = Reader::new(payload);
        if r.read_u8()? != SSH_MSG_SERVICE_REQUEST {
            return Err(Error::Format("auth: not SERVICE_REQUEST"));
        }
        let service = read_utf8(&mut r)?;
        ensure_empty(&r)?;
        Ok(Self { service })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceAccept {
    pub service: String,
}

impl ServiceAccept {
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(5 + self.service.len());
        w.write_u8(SSH_MSG_SERVICE_ACCEPT);
        w.write_string(self.service.as_bytes());
        w.into_vec()
    }

    pub fn decode(payload: &[u8]) -> Result<Self> {
        let mut r = Reader::new(payload);
        if r.read_u8()? != SSH_MSG_SERVICE_ACCEPT {
            return Err(Error::Format("auth: not SERVICE_ACCEPT"));
        }
        let service = read_utf8(&mut r)?;
        ensure_empty(&r)?;
        Ok(Self { service })
    }
}

/// Method-specific tail of a `SSH_MSG_USERAUTH_REQUEST` packet.
///
/// `Debug` is implemented manually so the cleartext `password` /
/// `new_password` fields of the `Password` variant are never rendered —
/// they appear as `"<redacted>"`. The redaction protects against
/// accidental leakage through `tracing` or ad-hoc `dbg!()` prints.
#[derive(Clone, PartialEq, Eq)]
pub enum AuthMethodPayload {
    None,
    Password {
        new_password: Option<String>,
        password: String,
    },
    PublicKey {
        signature_present: bool,
        algorithm: String,
        public_blob: Vec<u8>,
        signature: Option<Vec<u8>>,
    },
    KeyboardInteractive {
        language_tag: String,
        submethods: String,
    },
    Other {
        method: String,
        tail: Vec<u8>,
    },
}

impl core::fmt::Debug for AuthMethodPayload {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            AuthMethodPayload::None => f.write_str("None"),
            AuthMethodPayload::Password {
                new_password,
                password: _,
            } => f
                .debug_struct("Password")
                .field(
                    "new_password",
                    &new_password.as_ref().map(|_| "<redacted>"),
                )
                .field("password", &"<redacted>")
                .finish(),
            AuthMethodPayload::PublicKey {
                signature_present,
                algorithm,
                public_blob,
                signature,
            } => f
                .debug_struct("PublicKey")
                .field("signature_present", signature_present)
                .field("algorithm", algorithm)
                .field("public_blob", public_blob)
                .field("signature", signature)
                .finish(),
            AuthMethodPayload::KeyboardInteractive {
                language_tag,
                submethods,
            } => f
                .debug_struct("KeyboardInteractive")
                .field("language_tag", language_tag)
                .field("submethods", submethods)
                .finish(),
            AuthMethodPayload::Other { method, tail } => f
                .debug_struct("Other")
                .field("method", method)
                .field("tail", tail)
                .finish(),
        }
    }
}

impl AuthMethodPayload {
    pub fn method_name(&self) -> &str {
        match self {
            AuthMethodPayload::None => "none",
            AuthMethodPayload::Password { .. } => "password",
            AuthMethodPayload::PublicKey { .. } => "publickey",
            AuthMethodPayload::KeyboardInteractive { .. } => "keyboard-interactive",
            AuthMethodPayload::Other { method, .. } => method,
        }
    }

    fn write_tail(&self, w: &mut Writer) {
        match self {
            AuthMethodPayload::None => {}
            AuthMethodPayload::Password {
                new_password,
                password,
            } => {
                w.write_bool(new_password.is_some());
                w.write_string(password.as_bytes());
                if let Some(np) = new_password {
                    w.write_string(np.as_bytes());
                }
            }
            AuthMethodPayload::PublicKey {
                signature_present,
                algorithm,
                public_blob,
                signature,
            } => {
                w.write_bool(*signature_present);
                w.write_string(algorithm.as_bytes());
                w.write_string(public_blob);
                if *signature_present {
                    if let Some(sig) = signature {
                        w.write_string(sig);
                    } else {
                        w.write_string(&[]);
                    }
                }
            }
            AuthMethodPayload::KeyboardInteractive {
                language_tag,
                submethods,
            } => {
                w.write_string(language_tag.as_bytes());
                w.write_string(submethods.as_bytes());
            }
            AuthMethodPayload::Other { tail, .. } => {
                w.write_raw(tail);
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserauthRequest {
    pub user: String,
    pub service: String,
    pub method: AuthMethodPayload,
}

impl UserauthRequest {
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(64);
        w.write_u8(SSH_MSG_USERAUTH_REQUEST);
        w.write_string(self.user.as_bytes());
        w.write_string(self.service.as_bytes());
        w.write_string(self.method.method_name().as_bytes());
        self.method.write_tail(&mut w);
        w.into_vec()
    }

    pub fn decode(payload: &[u8]) -> Result<Self> {
        let mut r = Reader::new(payload);
        if r.read_u8()? != SSH_MSG_USERAUTH_REQUEST {
            return Err(Error::Format("auth: not USERAUTH_REQUEST"));
        }
        let user = read_utf8(&mut r)?;
        let service = read_utf8(&mut r)?;
        let method_name = read_utf8(&mut r)?;
        let method = match method_name.as_str() {
            "none" => {
                ensure_empty(&r)?;
                AuthMethodPayload::None
            }
            "password" => {
                let change = r.read_bool()?;
                let password = read_utf8(&mut r)?;
                let new_password = if change {
                    Some(read_utf8(&mut r)?)
                } else {
                    None
                };
                ensure_empty(&r)?;
                AuthMethodPayload::Password {
                    new_password,
                    password,
                }
            }
            "publickey" => {
                let signature_present = r.read_bool()?;
                let algorithm = read_utf8(&mut r)?;
                let public_blob = read_bytes_capped(&mut r)?.to_vec();
                let signature = if signature_present {
                    Some(read_bytes_capped(&mut r)?.to_vec())
                } else {
                    None
                };
                ensure_empty(&r)?;
                AuthMethodPayload::PublicKey {
                    signature_present,
                    algorithm,
                    public_blob,
                    signature,
                }
            }
            "keyboard-interactive" => {
                let language_tag = read_utf8(&mut r)?;
                let submethods = read_utf8(&mut r)?;
                ensure_empty(&r)?;
                AuthMethodPayload::KeyboardInteractive {
                    language_tag,
                    submethods,
                }
            }
            _ => {
                let tail = r.take(r.remaining())?.to_vec();
                AuthMethodPayload::Other {
                    method: method_name,
                    tail,
                }
            }
        };
        Ok(Self {
            user,
            service,
            method,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserauthFailure {
    pub continuations: Vec<String>,
    pub partial_success: bool,
}

impl UserauthFailure {
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(16);
        w.write_u8(SSH_MSG_USERAUTH_FAILURE);
        let mut joined = String::new();
        for (i, name) in self.continuations.iter().enumerate() {
            if i > 0 {
                joined.push(',');
            }
            joined.push_str(name);
        }
        w.write_string(joined.as_bytes());
        w.write_bool(self.partial_success);
        w.into_vec()
    }

    pub fn decode(payload: &[u8]) -> Result<Self> {
        let mut r = Reader::new(payload);
        if r.read_u8()? != SSH_MSG_USERAUTH_FAILURE {
            return Err(Error::Format("auth: not USERAUTH_FAILURE"));
        }
        let raw = read_bytes_capped(&mut r)?;
        let partial_success = r.read_bool()?;
        ensure_empty(&r)?;
        let mut continuations = Vec::new();
        for part in raw.split(|&b| b == b',') {
            if part.is_empty() {
                continue;
            }
            let s = core::str::from_utf8(part).map_err(|_| Error::Format("auth: invalid utf-8"))?;
            continuations.push(s.into());
        }
        Ok(Self {
            continuations,
            partial_success,
        })
    }
}

pub fn encode_success() -> Vec<u8> {
    let mut w = Writer::with_capacity(1);
    w.write_u8(SSH_MSG_USERAUTH_SUCCESS);
    w.into_vec()
}

pub fn decode_success(payload: &[u8]) -> Result<()> {
    if payload.len() != 1 || payload[0] != SSH_MSG_USERAUTH_SUCCESS {
        return Err(Error::Format("auth: not USERAUTH_SUCCESS"));
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserauthBanner {
    pub message: String,
    pub language: String,
}

impl UserauthBanner {
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(16 + self.message.len() + self.language.len());
        w.write_u8(SSH_MSG_USERAUTH_BANNER);
        w.write_string(self.message.as_bytes());
        w.write_string(self.language.as_bytes());
        w.into_vec()
    }

    pub fn decode(payload: &[u8]) -> Result<Self> {
        let mut r = Reader::new(payload);
        if r.read_u8()? != SSH_MSG_USERAUTH_BANNER {
            return Err(Error::Format("auth: not USERAUTH_BANNER"));
        }
        let message = read_utf8(&mut r)?;
        let language = read_utf8(&mut r)?;
        ensure_empty(&r)?;
        Ok(Self { message, language })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserauthPkOk {
    pub algorithm: String,
    pub public_blob: Vec<u8>,
}

impl UserauthPkOk {
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(16 + self.algorithm.len() + self.public_blob.len());
        w.write_u8(SSH_MSG_USERAUTH_PK_OK);
        w.write_string(self.algorithm.as_bytes());
        w.write_string(&self.public_blob);
        w.into_vec()
    }

    pub fn decode(payload: &[u8]) -> Result<Self> {
        let mut r = Reader::new(payload);
        if r.read_u8()? != SSH_MSG_USERAUTH_PK_OK {
            return Err(Error::Format("auth: not USERAUTH_PK_OK"));
        }
        let algorithm = read_utf8(&mut r)?;
        let public_blob = read_bytes_capped(&mut r)?.to_vec();
        ensure_empty(&r)?;
        Ok(Self {
            algorithm,
            public_blob,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserauthInfoRequest {
    pub name: String,
    pub instruction: String,
    pub language: String,
    pub prompts: Vec<(String, bool)>,
}

impl UserauthInfoRequest {
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(32);
        w.write_u8(SSH_MSG_USERAUTH_INFO_REQUEST);
        w.write_string(self.name.as_bytes());
        w.write_string(self.instruction.as_bytes());
        w.write_string(self.language.as_bytes());
        w.write_u32(self.prompts.len() as u32);
        for (prompt, echo) in &self.prompts {
            w.write_string(prompt.as_bytes());
            w.write_bool(*echo);
        }
        w.into_vec()
    }

    pub fn decode(payload: &[u8]) -> Result<Self> {
        let mut r = Reader::new(payload);
        if r.read_u8()? != SSH_MSG_USERAUTH_INFO_REQUEST {
            return Err(Error::Format("auth: not USERAUTH_INFO_REQUEST"));
        }
        let name = read_utf8(&mut r)?;
        let instruction = read_utf8(&mut r)?;
        let language = read_utf8(&mut r)?;
        let n = r.read_u32()? as usize;
        if n > 1024 {
            return Err(Error::Format("auth: too many prompts"));
        }
        let mut prompts = Vec::with_capacity(n);
        for _ in 0..n {
            let prompt = read_utf8(&mut r)?;
            let echo = r.read_bool()?;
            prompts.push((prompt, echo));
        }
        ensure_empty(&r)?;
        Ok(Self {
            name,
            instruction,
            language,
            prompts,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserauthInfoResponse {
    pub responses: Vec<String>,
}

impl UserauthInfoResponse {
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(8);
        w.write_u8(SSH_MSG_USERAUTH_INFO_RESPONSE);
        w.write_u32(self.responses.len() as u32);
        for resp in &self.responses {
            w.write_string(resp.as_bytes());
        }
        w.into_vec()
    }

    pub fn decode(payload: &[u8]) -> Result<Self> {
        let mut r = Reader::new(payload);
        if r.read_u8()? != SSH_MSG_USERAUTH_INFO_RESPONSE {
            return Err(Error::Format("auth: not USERAUTH_INFO_RESPONSE"));
        }
        let n = r.read_u32()? as usize;
        if n > 1024 {
            return Err(Error::Format("auth: too many responses"));
        }
        let mut responses = Vec::with_capacity(n);
        for _ in 0..n {
            responses.push(read_utf8(&mut r)?);
        }
        ensure_empty(&r)?;
        Ok(Self { responses })
    }
}

/// Build the buffer signed for a publickey USERAUTH_REQUEST per RFC 4252 §7:
///
/// ```text
/// string   session_id
/// byte     SSH_MSG_USERAUTH_REQUEST
/// string   user_name
/// string   service_name
/// string   "publickey"
/// boolean  TRUE
/// string   public_key_algorithm
/// string   public_key_blob
/// ```
pub fn publickey_signed_data(
    session_id: &[u8],
    user: &str,
    service: &str,
    algorithm: &str,
    public_blob: &[u8],
) -> Vec<u8> {
    let mut w = Writer::with_capacity(64 + session_id.len() + public_blob.len());
    w.write_string(session_id);
    w.write_u8(SSH_MSG_USERAUTH_REQUEST);
    w.write_string(user.as_bytes());
    w.write_string(service.as_bytes());
    w.write_string(b"publickey");
    w.write_bool(true);
    w.write_string(algorithm.as_bytes());
    w.write_string(public_blob);
    w.into_vec()
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn service_request_roundtrip() {
        let msg = ServiceRequest {
            service: "ssh-userauth".into(),
        };
        let enc = msg.encode();
        assert_eq!(enc[0], SSH_MSG_SERVICE_REQUEST);
        let dec = ServiceRequest::decode(&enc).unwrap();
        assert_eq!(dec, msg);
    }

    #[test]
    fn service_accept_roundtrip() {
        let msg = ServiceAccept {
            service: "ssh-userauth".into(),
        };
        let dec = ServiceAccept::decode(&msg.encode()).unwrap();
        assert_eq!(dec, msg);
    }

    #[test]
    fn userauth_request_none_roundtrip() {
        let msg = UserauthRequest {
            user: "alice".into(),
            service: "ssh-connection".into(),
            method: AuthMethodPayload::None,
        };
        let dec = UserauthRequest::decode(&msg.encode()).unwrap();
        assert_eq!(dec, msg);
    }

    #[test]
    fn userauth_request_password_roundtrip() {
        let msg = UserauthRequest {
            user: "alice".into(),
            service: "ssh-connection".into(),
            method: AuthMethodPayload::Password {
                new_password: None,
                password: "hunter2".into(),
            },
        };
        let dec = UserauthRequest::decode(&msg.encode()).unwrap();
        assert_eq!(dec, msg);
    }

    #[test]
    fn userauth_request_publickey_probe_roundtrip() {
        let msg = UserauthRequest {
            user: "alice".into(),
            service: "ssh-connection".into(),
            method: AuthMethodPayload::PublicKey {
                signature_present: false,
                algorithm: "ssh-ed25519".into(),
                public_blob: vec![1, 2, 3, 4],
                signature: None,
            },
        };
        let dec = UserauthRequest::decode(&msg.encode()).unwrap();
        assert_eq!(dec, msg);
    }

    #[test]
    fn userauth_request_publickey_signed_roundtrip() {
        let msg = UserauthRequest {
            user: "alice".into(),
            service: "ssh-connection".into(),
            method: AuthMethodPayload::PublicKey {
                signature_present: true,
                algorithm: "ssh-ed25519".into(),
                public_blob: vec![1, 2, 3, 4],
                signature: Some(vec![9, 8, 7, 6]),
            },
        };
        let dec = UserauthRequest::decode(&msg.encode()).unwrap();
        assert_eq!(dec, msg);
    }

    #[test]
    fn userauth_request_kbdint_roundtrip() {
        let msg = UserauthRequest {
            user: "alice".into(),
            service: "ssh-connection".into(),
            method: AuthMethodPayload::KeyboardInteractive {
                language_tag: "".into(),
                submethods: "".into(),
            },
        };
        let dec = UserauthRequest::decode(&msg.encode()).unwrap();
        assert_eq!(dec, msg);
    }

    #[test]
    fn userauth_failure_roundtrip() {
        let msg = UserauthFailure {
            continuations: vec!["password".into(), "publickey".into()],
            partial_success: false,
        };
        let dec = UserauthFailure::decode(&msg.encode()).unwrap();
        assert_eq!(dec, msg);
    }

    #[test]
    fn userauth_failure_empty_continuations() {
        let msg = UserauthFailure {
            continuations: vec![],
            partial_success: true,
        };
        let dec = UserauthFailure::decode(&msg.encode()).unwrap();
        assert_eq!(dec, msg);
    }

    #[test]
    fn success_roundtrip() {
        let enc = encode_success();
        decode_success(&enc).unwrap();
        assert!(decode_success(&[]).is_err());
        assert!(decode_success(&[99]).is_err());
    }

    #[test]
    fn banner_roundtrip() {
        let msg = UserauthBanner {
            message: "welcome\n".into(),
            language: "en-US".into(),
        };
        let dec = UserauthBanner::decode(&msg.encode()).unwrap();
        assert_eq!(dec, msg);
    }

    #[test]
    fn pk_ok_roundtrip() {
        let msg = UserauthPkOk {
            algorithm: "ssh-ed25519".into(),
            public_blob: vec![1, 2, 3],
        };
        let dec = UserauthPkOk::decode(&msg.encode()).unwrap();
        assert_eq!(dec, msg);
    }

    #[test]
    fn info_request_roundtrip() {
        let msg = UserauthInfoRequest {
            name: "Login".into(),
            instruction: "Enter creds".into(),
            language: "".into(),
            prompts: vec![("Password: ".into(), false), ("Token: ".into(), true)],
        };
        let dec = UserauthInfoRequest::decode(&msg.encode()).unwrap();
        assert_eq!(dec, msg);
    }

    #[test]
    fn info_response_roundtrip() {
        let msg = UserauthInfoResponse {
            responses: vec!["secret".into(), "12345".into()],
        };
        let dec = UserauthInfoResponse::decode(&msg.encode()).unwrap();
        assert_eq!(dec, msg);
    }

    #[test]
    fn malformed_userauth_request() {
        assert!(UserauthRequest::decode(&[]).is_err());
        assert!(UserauthRequest::decode(&[50]).is_err());
        assert!(UserauthRequest::decode(&[50, 0, 0, 0, 100]).is_err());
    }

    #[test]
    fn password_debug_is_redacted() {
        use alloc::format;
        let m = AuthMethodPayload::Password {
            new_password: Some("brand-new-secret".into()),
            password: "super-secret-pw".into(),
        };
        let s = format!("{m:?}");
        assert!(
            !s.contains("super-secret-pw"),
            "password leaked in Debug output: {s}"
        );
        assert!(
            !s.contains("brand-new-secret"),
            "new_password leaked in Debug output: {s}"
        );
        assert!(
            s.contains("redacted"),
            "redaction marker missing in Debug output: {s}"
        );
    }

    #[test]
    fn userauth_string_cap_rejects_oversize_length() {
        // Hand-craft a USERAUTH_REQUEST whose `user` string claims to be
        // 1 GiB long. The cap must fire on the length header alone,
        // before any allocation, and surface as Error::Format.
        let payload = [
            SSH_MSG_USERAUTH_REQUEST,
            // user: length = 0x4000_0000 (1 GiB)
            0x40,
            0x00,
            0x00,
            0x00,
        ];
        let err = UserauthRequest::decode(&payload).expect_err("must reject oversize string");
        match err {
            Error::Format(msg) => assert!(
                msg.contains("too large"),
                "expected 'too large' error, got: {msg}"
            ),
            other => panic!("unexpected error variant: {other:?}"),
        }
    }

    #[test]
    fn userauth_request_debug_is_redacted() {
        use alloc::format;
        let req = UserauthRequest {
            user: "alice".into(),
            service: "ssh-connection".into(),
            method: AuthMethodPayload::Password {
                new_password: None,
                password: "hunter2".into(),
            },
        };
        let s = format!("{req:?}");
        assert!(!s.contains("hunter2"), "password leaked: {s}");
    }
}
