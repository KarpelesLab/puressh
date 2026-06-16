//! Pure, I/O-free codec for the mux control-socket protocol.
//!
//! See the [module-level docs](super) for the frame layout. Every [`Frame`]
//! variant has a single-byte type tag and a self-describing payload; the codec
//! is symmetric ([`Frame::encode`] / [`Frame::decode`]) and exhaustively
//! round-trip tested.

use std::fmt;

/// Protocol version carried in [`Frame::Hello`]. Bumped on any incompatible
/// wire change; a master refuses a client whose `HELLO` version differs.
pub const PROTOCOL_VERSION: u32 = 1;

/// Upper bound on a single frame's body length (type byte + payload). Guards
/// the reader against a hostile/garbled length prefix demanding an unbounded
/// allocation. 16 MiB is far above any legitimate stdin/stdout chunk (the
/// pumps use 32 KiB buffers).
pub const MAX_FRAME_LEN: usize = 16 * 1024 * 1024;

// Frame type tags.
const T_HELLO: u8 = 1;
const T_OPEN_SESSION: u8 = 2;
const T_STDIN_DATA: u8 = 3;
const T_STDOUT_DATA: u8 = 4;
const T_STDERR_DATA: u8 = 5;
const T_EOF: u8 = 6;
const T_WINDOW_CHANGE: u8 = 7;
const T_EXIT_STATUS: u8 = 8;
const T_EXIT_SIGNAL: u8 = 9;
const T_ALIVE_CHECK: u8 = 10;
const T_ALIVE_OK: u8 = 11;
const T_EXIT_REQUEST: u8 = 12;
const T_OPEN_DIRECT_TCPIP: u8 = 13;
const T_OPEN_OK: u8 = 14;
const T_OPEN_FAIL: u8 = 15;

/// A decoded mux control-socket message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Frame {
    /// First frame in either direction: protocol-version handshake.
    Hello {
        /// Sender's [`PROTOCOL_VERSION`].
        version: u32,
    },
    /// Client → master: open a new session channel.
    OpenSession {
        /// Allocate a PTY for the session.
        want_pty: bool,
        /// `$TERM` value (empty when `want_pty` is false).
        term: String,
        /// Terminal width in columns.
        cols: u32,
        /// Terminal height in rows.
        rows: u32,
        /// Environment variables to set on the remote session.
        env: Vec<(String, String)>,
        /// Remote command to exec; `None` requests an interactive shell.
        command: Option<String>,
    },
    /// Client → master: bytes for the session's stdin.
    StdinData(Vec<u8>),
    /// Master → client: bytes from the session's stdout.
    StdoutData(Vec<u8>),
    /// Master → client: bytes from the session's stderr.
    StderrData(Vec<u8>),
    /// Either direction: the sender's write side is finished (half-close).
    Eof,
    /// Client → master: terminal resize.
    WindowChange {
        /// New width in columns.
        cols: u32,
        /// New height in rows.
        rows: u32,
    },
    /// Master → client: the remote session exited with this status code.
    ExitStatus {
        /// Remote exit code (0–255).
        code: u32,
    },
    /// Master → client: the remote session was killed by a signal.
    ExitSignal {
        /// Signal name without the `SIG` prefix (e.g. `TERM`, `KILL`).
        name: String,
    },
    /// Client → master: liveness probe (used by `probe_master`).
    AliveCheck,
    /// Master → client: liveness reply to [`Frame::AliveCheck`].
    AliveOk,
    /// Client → master: ask the master to shut down (`ssh -O exit`).
    ExitRequest,
    /// Client → master: open a `direct-tcpip` channel on the master's SSH
    /// connection (the mux carrier for `ssh -L` / `ssh -D`). The master dials
    /// `dest_host:dest_port` *through the server* and, on success, splices the
    /// resulting channel against this control connection using the same
    /// `StdinData`/`StdoutData`/`Eof` frames a session uses.
    OpenDirectTcpip {
        /// Destination host the *server* should connect to.
        dest_host: String,
        /// Destination port the server should connect to.
        dest_port: u32,
        /// Informational originator address echoed in the channel open.
        orig_host: String,
        /// Informational originator port echoed in the channel open.
        orig_port: u32,
    },
    /// Master → client: the requested channel open succeeded; byte splicing
    /// follows. Sent in reply to [`Frame::OpenDirectTcpip`].
    OpenOk,
    /// Master → client: the requested channel open failed. `reason` is a
    /// human-readable diagnostic. Sent in reply to [`Frame::OpenDirectTcpip`].
    OpenFail {
        /// Human-readable failure reason.
        reason: String,
    },
}

impl Frame {
    /// Serialise the frame into a `length(u32) | type(u8) | payload` byte
    /// vector ready to write to the socket.
    pub fn encode(&self) -> Vec<u8> {
        let mut body = Vec::new();
        self.encode_body(&mut body);
        let mut out = Vec::with_capacity(4 + body.len());
        out.extend_from_slice(&(body.len() as u32).to_be_bytes());
        out.extend_from_slice(&body);
        out
    }

    /// Encode just the body (`type | payload`), without the length prefix.
    fn encode_body(&self, out: &mut Vec<u8>) {
        match self {
            Frame::Hello { version } => {
                out.push(T_HELLO);
                out.extend_from_slice(&version.to_be_bytes());
            }
            Frame::OpenSession {
                want_pty,
                term,
                cols,
                rows,
                env,
                command,
            } => {
                out.push(T_OPEN_SESSION);
                out.push(*want_pty as u8);
                put_str(out, term);
                out.extend_from_slice(&cols.to_be_bytes());
                out.extend_from_slice(&rows.to_be_bytes());
                out.extend_from_slice(&(env.len() as u32).to_be_bytes());
                for (k, v) in env {
                    put_str(out, k);
                    put_str(out, v);
                }
                // command: 1-byte present flag, then the string when present.
                match command {
                    Some(c) => {
                        out.push(1);
                        put_str(out, c);
                    }
                    None => out.push(0),
                }
            }
            Frame::StdinData(d) => {
                out.push(T_STDIN_DATA);
                out.extend_from_slice(d);
            }
            Frame::StdoutData(d) => {
                out.push(T_STDOUT_DATA);
                out.extend_from_slice(d);
            }
            Frame::StderrData(d) => {
                out.push(T_STDERR_DATA);
                out.extend_from_slice(d);
            }
            Frame::Eof => out.push(T_EOF),
            Frame::WindowChange { cols, rows } => {
                out.push(T_WINDOW_CHANGE);
                out.extend_from_slice(&cols.to_be_bytes());
                out.extend_from_slice(&rows.to_be_bytes());
            }
            Frame::ExitStatus { code } => {
                out.push(T_EXIT_STATUS);
                out.extend_from_slice(&code.to_be_bytes());
            }
            Frame::ExitSignal { name } => {
                out.push(T_EXIT_SIGNAL);
                put_str(out, name);
            }
            Frame::AliveCheck => out.push(T_ALIVE_CHECK),
            Frame::AliveOk => out.push(T_ALIVE_OK),
            Frame::ExitRequest => out.push(T_EXIT_REQUEST),
            Frame::OpenDirectTcpip {
                dest_host,
                dest_port,
                orig_host,
                orig_port,
            } => {
                out.push(T_OPEN_DIRECT_TCPIP);
                put_str(out, dest_host);
                out.extend_from_slice(&dest_port.to_be_bytes());
                put_str(out, orig_host);
                out.extend_from_slice(&orig_port.to_be_bytes());
            }
            Frame::OpenOk => out.push(T_OPEN_OK),
            Frame::OpenFail { reason } => {
                out.push(T_OPEN_FAIL);
                put_str(out, reason);
            }
        }
    }

    /// Decode a complete `length | type | payload` frame from `bytes`.
    /// Convenience for tests; the streaming reader strips the length prefix
    /// itself and calls [`Frame::decode_body`].
    pub fn decode(bytes: &[u8]) -> Result<Frame, MuxError> {
        if bytes.len() < 4 {
            return Err(MuxError::Malformed("frame shorter than length prefix"));
        }
        let len = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize;
        let body = &bytes[4..];
        if body.len() != len {
            return Err(MuxError::Malformed("length prefix mismatches body"));
        }
        Frame::decode_body(body)
    }

    /// Decode the body (`type | payload`) of a frame whose length prefix has
    /// already been consumed.
    pub fn decode_body(body: &[u8]) -> Result<Frame, MuxError> {
        let mut r = Cursor::new(body);
        let tag = r.u8()?;
        let frame = match tag {
            T_HELLO => Frame::Hello { version: r.u32()? },
            T_OPEN_SESSION => {
                let want_pty = r.u8()? != 0;
                let term = r.str()?;
                let cols = r.u32()?;
                let rows = r.u32()?;
                let n = r.u32()? as usize;
                let mut env = Vec::with_capacity(n.min(64));
                for _ in 0..n {
                    let k = r.str()?;
                    let v = r.str()?;
                    env.push((k, v));
                }
                let command = match r.u8()? {
                    0 => None,
                    1 => Some(r.str()?),
                    _ => return Err(MuxError::Malformed("OPEN_SESSION: bad command flag")),
                };
                Frame::OpenSession {
                    want_pty,
                    term,
                    cols,
                    rows,
                    env,
                    command,
                }
            }
            T_STDIN_DATA => Frame::StdinData(r.rest().to_vec()),
            T_STDOUT_DATA => Frame::StdoutData(r.rest().to_vec()),
            T_STDERR_DATA => Frame::StderrData(r.rest().to_vec()),
            T_EOF => Frame::Eof,
            T_WINDOW_CHANGE => Frame::WindowChange {
                cols: r.u32()?,
                rows: r.u32()?,
            },
            T_EXIT_STATUS => Frame::ExitStatus { code: r.u32()? },
            T_EXIT_SIGNAL => Frame::ExitSignal { name: r.str()? },
            T_ALIVE_CHECK => Frame::AliveCheck,
            T_ALIVE_OK => Frame::AliveOk,
            T_EXIT_REQUEST => Frame::ExitRequest,
            T_OPEN_DIRECT_TCPIP => {
                let dest_host = r.str()?;
                let dest_port = r.u32()?;
                let orig_host = r.str()?;
                let orig_port = r.u32()?;
                Frame::OpenDirectTcpip {
                    dest_host,
                    dest_port,
                    orig_host,
                    orig_port,
                }
            }
            T_OPEN_OK => Frame::OpenOk,
            T_OPEN_FAIL => Frame::OpenFail { reason: r.str()? },
            other => return Err(MuxError::UnknownType(other)),
        };
        // Variants with fixed-length payloads must consume the whole body;
        // the open-ended *Data variants legitimately swallow `rest()`.
        if !matches!(
            frame,
            Frame::StdinData(_) | Frame::StdoutData(_) | Frame::StderrData(_)
        ) && !r.is_empty()
        {
            return Err(MuxError::Malformed("trailing bytes after frame payload"));
        }
        Ok(frame)
    }
}

/// Stateless codec marker. The actual work lives on [`Frame`]; this type
/// exists so callers can name the codec in signatures / docs.
#[derive(Clone, Copy, Debug, Default)]
pub struct FrameCodec;

impl FrameCodec {
    /// Encode one frame (delegates to [`Frame::encode`]).
    pub fn encode(frame: &Frame) -> Vec<u8> {
        frame.encode()
    }

    /// Decode one complete frame (delegates to [`Frame::decode`]).
    pub fn decode(bytes: &[u8]) -> Result<Frame, MuxError> {
        Frame::decode(bytes)
    }
}

/// Errors from the mux codec / framed I/O layer.
#[derive(Debug)]
pub enum MuxError {
    /// Underlying socket I/O failed.
    Io(std::io::Error),
    /// A frame's bytes did not match the protocol grammar.
    Malformed(&'static str),
    /// The type tag is not one this version understands.
    UnknownType(u8),
    /// Peer reported an incompatible [`PROTOCOL_VERSION`] in its `HELLO`.
    VersionMismatch {
        /// Version this build speaks.
        ours: u32,
        /// Version the peer advertised.
        theirs: u32,
    },
    /// The peer sent an unexpected frame for the current protocol state
    /// (e.g. a non-`HELLO` first frame).
    Unexpected(&'static str),
    /// The master refused an `OpenDirectTcpip` (`ssh -L`/`-D` over mux); the
    /// payload is the master's human-readable reason.
    ForwardFailed(String),
}

impl fmt::Display for MuxError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MuxError::Io(e) => write!(f, "mux io: {e}"),
            MuxError::Malformed(s) => write!(f, "mux malformed frame: {s}"),
            MuxError::UnknownType(t) => write!(f, "mux unknown frame type {t}"),
            MuxError::VersionMismatch { ours, theirs } => {
                write!(
                    f,
                    "mux protocol version mismatch: ours={ours} theirs={theirs}"
                )
            }
            MuxError::Unexpected(s) => write!(f, "mux unexpected frame: {s}"),
            MuxError::ForwardFailed(s) => write!(f, "mux forward refused: {s}"),
        }
    }
}

impl std::error::Error for MuxError {}

impl From<std::io::Error> for MuxError {
    fn from(e: std::io::Error) -> Self {
        MuxError::Io(e)
    }
}

/// Append a `u32`-length-prefixed string to `out`.
fn put_str(out: &mut Vec<u8>, s: &str) {
    out.extend_from_slice(&(s.len() as u32).to_be_bytes());
    out.extend_from_slice(s.as_bytes());
}

/// Minimal big-endian reader over a byte slice with bounds checks.
struct Cursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Cursor { buf, pos: 0 }
    }

    fn is_empty(&self) -> bool {
        self.pos >= self.buf.len()
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], MuxError> {
        let end = self
            .pos
            .checked_add(n)
            .ok_or(MuxError::Malformed("length overflow"))?;
        if end > self.buf.len() {
            return Err(MuxError::Malformed("frame truncated"));
        }
        let s = &self.buf[self.pos..end];
        self.pos = end;
        Ok(s)
    }

    fn u8(&mut self) -> Result<u8, MuxError> {
        Ok(self.take(1)?[0])
    }

    fn u32(&mut self) -> Result<u32, MuxError> {
        let b = self.take(4)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    fn str(&mut self) -> Result<String, MuxError> {
        let n = self.u32()? as usize;
        let b = self.take(n)?;
        String::from_utf8(b.to_vec()).map_err(|_| MuxError::Malformed("string is not UTF-8"))
    }

    fn rest(&mut self) -> &'a [u8] {
        let s = &self.buf[self.pos..];
        self.pos = self.buf.len();
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn round_trip(f: Frame) {
        let bytes = f.encode();
        let back = Frame::decode(&bytes).expect("decode");
        assert_eq!(f, back, "round-trip mismatch");
        // decode_body alone (no length prefix) must agree.
        let body = &bytes[4..];
        assert_eq!(Frame::decode_body(body).unwrap(), f);
    }

    #[test]
    fn round_trip_all_variants() {
        round_trip(Frame::Hello { version: 1 });
        round_trip(Frame::Hello {
            version: 0xDEAD_BEEF,
        });
        round_trip(Frame::OpenSession {
            want_pty: true,
            term: "xterm".into(),
            cols: 120,
            rows: 40,
            env: vec![
                ("A".into(), "1".into()),
                ("LONGKEY".into(), "a value with spaces".into()),
            ],
            command: Some("ls -la /tmp".into()),
        });
        round_trip(Frame::OpenSession {
            want_pty: false,
            term: String::new(),
            cols: 0,
            rows: 0,
            env: vec![],
            command: None,
        });
        round_trip(Frame::StdinData(vec![]));
        round_trip(Frame::StdinData(b"some bytes \x00\xff".to_vec()));
        round_trip(Frame::StdoutData(b"out".to_vec()));
        round_trip(Frame::StderrData(b"err".to_vec()));
        round_trip(Frame::Eof);
        round_trip(Frame::WindowChange { cols: 80, rows: 24 });
        round_trip(Frame::ExitStatus { code: 0 });
        round_trip(Frame::ExitStatus { code: 255 });
        round_trip(Frame::ExitSignal {
            name: "TERM".into(),
        });
        round_trip(Frame::AliveCheck);
        round_trip(Frame::AliveOk);
        round_trip(Frame::ExitRequest);
        round_trip(Frame::OpenDirectTcpip {
            dest_host: "example.com".into(),
            dest_port: 443,
            orig_host: "127.0.0.1".into(),
            orig_port: 51234,
        });
        round_trip(Frame::OpenDirectTcpip {
            dest_host: "2001:db8::1".into(),
            dest_port: 0,
            orig_host: String::new(),
            orig_port: 0,
        });
        round_trip(Frame::OpenOk);
        round_trip(Frame::OpenFail {
            reason: "connect refused".into(),
        });
    }

    #[test]
    fn open_session_unicode_and_empty_env() {
        round_trip(Frame::OpenSession {
            want_pty: true,
            term: "scréen-256".into(),
            cols: 1,
            rows: 1,
            env: vec![],
            command: Some("écho café".into()),
        });
    }

    #[test]
    fn length_prefix_is_body_length() {
        let f = Frame::ExitStatus { code: 7 };
        let bytes = f.encode();
        let len = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize;
        assert_eq!(len, bytes.len() - 4);
        // body = T_EXIT_STATUS (1) + u32 code (4) = 5 bytes
        assert_eq!(len, 5);
    }

    #[test]
    fn decode_unknown_type_errors() {
        let body = [200u8]; // unknown tag, no payload
        assert!(matches!(
            Frame::decode_body(&body),
            Err(MuxError::UnknownType(200))
        ));
    }

    #[test]
    fn decode_truncated_errors() {
        // T_EXIT_STATUS expects 4 more bytes; give it 2.
        let body = [T_EXIT_STATUS, 0, 0];
        assert!(matches!(
            Frame::decode_body(&body),
            Err(MuxError::Malformed(_))
        ));
    }

    #[test]
    fn decode_trailing_bytes_errors() {
        // EOF takes no payload; appending a byte must be rejected.
        let body = [T_EOF, 0xAA];
        assert!(matches!(
            Frame::decode_body(&body),
            Err(MuxError::Malformed(_))
        ));
    }

    #[test]
    fn decode_empty_body_errors() {
        assert!(matches!(
            Frame::decode_body(&[]),
            Err(MuxError::Malformed(_))
        ));
    }

    #[test]
    fn data_frames_keep_trailing_bytes() {
        // The *Data variants intentionally absorb the entire remaining body,
        // including bytes that look like a tag.
        let f = Frame::StdoutData(vec![T_EOF, T_HELLO, 0, 0]);
        round_trip(f);
    }

    #[test]
    fn framecodec_delegates() {
        let f = Frame::AliveCheck;
        let b = FrameCodec::encode(&f);
        assert_eq!(FrameCodec::decode(&b).unwrap(), f);
    }
}
