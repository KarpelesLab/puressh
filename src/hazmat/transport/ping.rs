//! `ping@openssh.com` PING/PONG extension (OpenSSH 9.5+).
//!
//! Two transport-layer messages in the RFC 4251 §7 private-use range
//! (`192..=255`):
//!
//! - `SSH2_MSG_PING` (192): `byte(192) string(data)`
//! - `SSH2_MSG_PONG` (193): `byte(193) string(data)` echoing the PING's
//!   `data` verbatim.
//!
//! Either peer may send a PING at any time after the first key exchange;
//! the receiver must answer with a PONG carrying the same payload. A
//! received PONG is simply dropped. OpenSSH uses PINGs as constant-rate
//! "chaff" during interactive sessions so that inter-keystroke timing is
//! not observable on the wire (see `ObscureKeystrokeTiming`).

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

use crate::error::{Error, Result};
use crate::format::Reader;

/// `SSH2_MSG_PING` message number (RFC 4251 §7 private range).
pub const SSH_MSG_PING: u8 = 192;
/// `SSH2_MSG_PONG` message number (RFC 4251 §7 private range).
pub const SSH_MSG_PONG: u8 = 193;

/// Encode a `SSH2_MSG_PING`: `byte(192) string(data)`.
#[cfg(feature = "alloc")]
pub fn encode_ping(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + 4 + data.len());
    out.push(SSH_MSG_PING);
    out.extend_from_slice(&(data.len() as u32).to_be_bytes());
    out.extend_from_slice(data);
    out
}

/// Encode a `SSH2_MSG_PONG`: `byte(193) string(data)`.
#[cfg(feature = "alloc")]
pub fn encode_pong(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + 4 + data.len());
    out.push(SSH_MSG_PONG);
    out.extend_from_slice(&(data.len() as u32).to_be_bytes());
    out.extend_from_slice(data);
    out
}

/// Given an inbound `SSH2_MSG_PING` payload (message byte included),
/// build the matching `SSH2_MSG_PONG` reply echoing the PING's `data`.
///
/// Returns an error if `payload` is not a well-formed PING.
#[cfg(feature = "alloc")]
pub fn pong_for_ping(payload: &[u8]) -> Result<Vec<u8>> {
    let mut r = Reader::new(payload);
    let msg = r.read_u8()?;
    if msg != SSH_MSG_PING {
        return Err(Error::Protocol("ping: not a SSH_MSG_PING"));
    }
    let data = r.read_string()?;
    Ok(encode_pong(data))
}

#[cfg(all(test, feature = "alloc"))]
mod tests {
    use super::*;

    #[test]
    fn ping_roundtrips_into_pong_with_echoed_data() {
        let ping = encode_ping(b"hello");
        assert_eq!(ping[0], SSH_MSG_PING);
        let pong = pong_for_ping(&ping).expect("valid ping");
        assert_eq!(pong[0], SSH_MSG_PONG);

        // The PONG must echo the PING's data verbatim.
        let mut r = Reader::new(&pong);
        assert_eq!(r.read_u8().unwrap(), SSH_MSG_PONG);
        assert_eq!(r.read_string().unwrap(), b"hello");
    }

    #[test]
    fn empty_ping_echoes_empty_pong() {
        let pong = pong_for_ping(&encode_ping(b"")).unwrap();
        assert_eq!(pong, encode_pong(b""));
        let mut r = Reader::new(&pong);
        assert_eq!(r.read_u8().unwrap(), SSH_MSG_PONG);
        assert_eq!(r.read_string().unwrap(), b"");
    }

    #[test]
    fn pong_for_non_ping_is_rejected() {
        // A PONG (193) is not a PING; must error.
        assert!(pong_for_ping(&encode_pong(b"x")).is_err());
        // Truncated / empty payloads must error, not panic.
        assert!(pong_for_ping(&[]).is_err());
        assert!(pong_for_ping(&[SSH_MSG_PING]).is_err());
        assert!(pong_for_ping(&[SSH_MSG_PING, 0, 0, 0, 5, b'a']).is_err());
    }
}
