//! Common state types and message-type constants shared by the KEX modules.

use alloc::vec::Vec;

/// `SSH_MSG_KEX_ECDH_INIT` / `SSH_MSG_KEXDH_INIT` (numerically the same byte —
/// RFC 4253 §12, RFC 5656 §7).
pub const SSH_MSG_KEX_ECDH_INIT: u8 = 30;
/// `SSH_MSG_KEX_ECDH_REPLY` / `SSH_MSG_KEXDH_REPLY`.
pub const SSH_MSG_KEX_ECDH_REPLY: u8 = 31;

/// `SSH_MSG_KEX_DH_GEX_REQUEST_OLD` — RFC 4419 §5 (deprecated form).
#[allow(dead_code)]
pub const SSH_MSG_KEX_DH_GEX_REQUEST_OLD: u8 = 30;
/// `SSH_MSG_KEX_DH_GEX_GROUP` — RFC 4419 §3.
pub const SSH_MSG_KEX_DH_GEX_GROUP: u8 = 31;
/// `SSH_MSG_KEX_DH_GEX_INIT` — RFC 4419 §3.
pub const SSH_MSG_KEX_DH_GEX_INIT: u8 = 32;
/// `SSH_MSG_KEX_DH_GEX_REPLY` — RFC 4419 §3.
pub const SSH_MSG_KEX_DH_GEX_REPLY: u8 = 33;
/// `SSH_MSG_KEX_DH_GEX_REQUEST` — RFC 4419 §3 (min/n/max form).
pub const SSH_MSG_KEX_DH_GEX_REQUEST: u8 = 34;

/// Static context shared between the participants of a KEX, fed verbatim
/// into the exchange hash.
#[derive(Clone)]
pub struct KexContext<'a> {
    /// Client's SSH-version line, without trailing CR/LF.
    pub v_c: &'a [u8],
    /// Server's SSH-version line, without trailing CR/LF.
    pub v_s: &'a [u8],
    /// The raw `SSH_MSG_KEXINIT` payload the client sent (message-type byte
    /// included, padding stripped).
    pub i_c: &'a [u8],
    /// The raw `SSH_MSG_KEXINIT` payload the server sent.
    pub i_s: &'a [u8],
}

/// Output of `client_init` / `server_reply` describing the payload to send
/// and the local state to retain for the next step.
#[derive(Debug, Clone)]
pub struct KexInitOut {
    /// Wire-format payload, message-type byte included.
    pub payload: Vec<u8>,
}

/// Final agreed values shared by both ends after a successful exchange.
#[derive(Debug, Clone)]
pub struct KexOutput {
    /// The shared secret `K` as an SSH `mpint` byte string (length-prefixed,
    /// two's-complement). This is what RFC 4253 §7.2 feeds into the KDF.
    pub k: Vec<u8>,
    /// The exchange hash `H`.
    pub h: Vec<u8>,
}
