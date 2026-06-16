//! Client connection multiplexing (`ControlMaster` / `ControlPath` /
//! `ControlPersist`) over a Unix-domain control socket.
//!
//! A *master* connection performs the normal TCP / KEX / userauth dance once,
//! then binds a `UnixListener` at the configured `ControlPath` and moves its
//! [`Client`] into a [`SharedClient`]. Subsequent `ssh` invocations whose
//! `ControlMaster` is `auto`/`no` connect that socket and run their session as
//! a brand-new *channel* on the master's existing connection — no second TCP
//! handshake, KEX, or authentication.
//!
//! # Wire protocol
//!
//! This is **not** OpenSSH-mux-wire-compatible. Frames are length-prefixed:
//!
//! ```text
//! u32 length | u8 type | payload[length-1]
//! ```
//!
//! `length` counts the type byte plus the payload. Multi-byte integers are
//! big-endian; strings are `u32` length-prefixed byte blobs. See [`Frame`] for
//! the message set and [`Frame::encode`] / [`Frame::decode`] for the codec.
//!
//! The codec ([`Frame`], [`FrameCodec`]) is pure and I/O-free, so it is unit-
//! testable in isolation. The networking pieces ([`run_master`],
//! [`run_client`]) live behind the same `cfg(all(unix, feature = "client"))`
//! gate as this module and are only reachable from the `ssh` binary.
//!
//! [`Client`]: crate::client::Client
//! [`SharedClient`]: crate::shared::SharedClient

#![cfg(all(unix, feature = "client"))]

use std::io::{self, Read, Write};

mod codec;
pub use codec::{Frame, FrameCodec, MAX_FRAME_LEN, MuxError, PROTOCOL_VERSION};

mod path;
pub use path::{
    connection_hash, expand_control_path, expand_tokens_with_hash, local_hostname, socket_path_for,
};

// The master / client *roles* drive a real connection and need
// `SharedClient` (master side) / blocking socket I/O. They live behind the
// `multichannel` feature; the codec + path helpers above stay available with
// just `client` so the lib still compiles in `multichannel`-off builds.
#[cfg(feature = "multichannel")]
mod server;
#[cfg(feature = "multichannel")]
pub use server::{MasterConfig, Persist, run_master, run_master_daemon};

#[cfg(feature = "multichannel")]
mod client;
#[cfg(feature = "multichannel")]
pub use client::{
    ControlCommand, ProbeOutcome, SessionRequest, TryCloneStream, open_forward, probe_master,
    run_client, send_control_command, splice_forward,
};

/// Read exactly one framed message from `r`, blocking until a full frame is
/// available. Returns `Ok(None)` on a clean EOF *between* frames (the peer
/// closed without starting a new frame).
pub fn read_frame<R: Read>(r: &mut R) -> Result<Option<Frame>, MuxError> {
    let mut len_buf = [0u8; 4];
    match r.read_exact(&mut len_buf) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(MuxError::Io(e)),
    }
    let len = u32::from_be_bytes(len_buf) as usize;
    if len == 0 {
        return Err(MuxError::Malformed("zero-length frame"));
    }
    if len > MAX_FRAME_LEN {
        return Err(MuxError::Malformed("frame exceeds MAX_FRAME_LEN"));
    }
    let mut body = vec![0u8; len];
    r.read_exact(&mut body).map_err(MuxError::Io)?;
    // body = type byte + payload; decode_body expects exactly that.
    Frame::decode_body(&body).map(Some)
}

/// Encode `frame` and write it to `w` in one shot (length prefix + body).
pub fn write_frame<W: Write>(w: &mut W, frame: &Frame) -> Result<(), MuxError> {
    let bytes = frame.encode();
    w.write_all(&bytes).map_err(MuxError::Io)?;
    w.flush().map_err(MuxError::Io)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_write_round_trip_over_pipe() {
        let frames = vec![
            Frame::Hello {
                version: PROTOCOL_VERSION,
            },
            Frame::OpenSession {
                want_pty: true,
                term: "xterm-256color".into(),
                cols: 80,
                rows: 24,
                env: vec![("LANG".into(), "C.UTF-8".into())],
                command: None,
            },
            Frame::StdinData(b"echo hi\n".to_vec()),
            Frame::StdoutData(b"hi\n".to_vec()),
            Frame::Eof,
            Frame::ExitStatus { code: 0 },
        ];
        // Serialise all frames into one buffer, then read them back.
        let mut buf = Vec::new();
        for f in &frames {
            write_frame(&mut buf, f).unwrap();
        }
        let mut cursor = io::Cursor::new(buf);
        let mut got = Vec::new();
        while let Some(f) = read_frame(&mut cursor).unwrap() {
            got.push(f);
        }
        assert_eq!(got, frames);
    }

    #[test]
    fn read_frame_clean_eof_between_frames() {
        let mut cursor = io::Cursor::new(Vec::<u8>::new());
        assert!(read_frame(&mut cursor).unwrap().is_none());
    }

    #[test]
    fn read_frame_rejects_oversize_length() {
        // length field = MAX_FRAME_LEN + 1, no body needed (we reject before read).
        let mut buf = ((MAX_FRAME_LEN + 1) as u32).to_be_bytes().to_vec();
        buf.push(0); // would-be type byte
        let mut cursor = io::Cursor::new(buf);
        assert!(matches!(
            read_frame(&mut cursor),
            Err(MuxError::Malformed(_))
        ));
    }
}
