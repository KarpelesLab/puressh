//! SCP wire-format encode/decode — pure functions, no I/O.
//!
//! Each unit of work is a single-line header (`C`/`D`/`E`/`T`) followed
//! by raw payload bytes (for `C` only). Each header sent to the peer is
//! acknowledged with a one-byte status code: `0x00` (OK), `0x01` (warning,
//! followed by a `\n`-terminated message), or `0x02` (fatal error, ditto).
//!
//! Wire grammar (whitespace is literal U+0020):
//!
//! ```text
//! C<mode>:octal SP <size>:dec SP <name>:bytes LF      (regular file)
//! D<mode>:octal SP 0          SP <name>:bytes LF      (directory entry, push)
//! E LF                                                (directory pop)
//! T<mtime>:dec SP 0 SP <atime>:dec SP 0 LF            (optional time preamble)
//! ```
//!
//! `<name>` is the file's basename only — full path is reconstructed by
//! the receiver from the current directory stack (`D`/`E` push/pop).
//! Names containing `\0` or `\n` are illegal on the wire. Names starting
//! with `-` are rejected per OpenSSH (CVE-2020-15778) to keep callers
//! from synthesising option-looking strings.

use std::fmt;
use std::io::{ErrorKind, Read, Write};

/// SCP protocol error.
#[derive(Debug)]
pub enum ScpError {
    /// Wrapped `std::io::Error` from the underlying transport.
    Io(std::io::Error),
    /// The peer sent a malformed header (bad UTF-8, missing fields,
    /// non-numeric size/mode, etc).
    BadHeader(&'static str),
    /// The peer sent a `0x02 message\n` (fatal) ack frame. The string
    /// is the message body.
    Remote(String),
    /// The peer sent a `0x01 message\n` (warning) ack frame. The string
    /// is the message body. Senders typically log-and-continue.
    Warning(String),
    /// A filename was rejected: contains `\0`, `\n`, or starts with `-`.
    BadName(&'static str),
    /// A header tried to write outside the receiver's base path.
    PathEscape,
    /// We expected one header kind and got another (e.g. `E` at top
    /// level, or `C` payload was truncated).
    Unexpected(&'static str),
}

impl fmt::Display for ScpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ScpError::Io(e) => write!(f, "scp: io: {}", e),
            ScpError::BadHeader(m) => write!(f, "scp: bad header: {}", m),
            ScpError::Remote(m) => write!(f, "scp: remote error: {}", m),
            ScpError::Warning(m) => write!(f, "scp: remote warning: {}", m),
            ScpError::BadName(m) => write!(f, "scp: bad name: {}", m),
            ScpError::PathEscape => f.write_str("scp: path escapes base directory"),
            ScpError::Unexpected(m) => write!(f, "scp: unexpected: {}", m),
        }
    }
}

impl std::error::Error for ScpError {}

impl From<std::io::Error> for ScpError {
    fn from(e: std::io::Error) -> Self {
        ScpError::Io(e)
    }
}

/// Result of [`read_header`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Header {
    /// `C<mode> <size> <name>` — incoming regular file. Caller reads
    /// `size` bytes of payload then a single `\0` terminator.
    File {
        /// POSIX mode bits (the 12-bit `st_mode` low part — typically
        /// 0644, 0755, etc).
        mode: u32,
        /// Payload size in bytes.
        size: u64,
        /// Basename of the file.
        name: String,
    },
    /// `D<mode> 0 <name>` — push a directory level. Recursive mode only.
    Dir {
        /// POSIX mode bits for the new directory.
        mode: u32,
        /// Basename of the directory.
        name: String,
    },
    /// `E` — pop a directory level. Recursive mode only.
    EndDir,
    /// `T<mtime> 0 <atime> 0` — preamble carrying access/modify times
    /// for the next `C` or `D`. Sent only when `preserve_times` is set.
    Times {
        /// Modify time (Unix seconds).
        mtime: i64,
        /// Access time (Unix seconds).
        atime: i64,
    },
}

/// Validate a filename before sending or after receiving. The rules
/// (no `\0`, no `\n`, no `/`, not `.`, not `..`, not starting with `-`)
/// match OpenSSH's `do_localcopy`/`source_file` hardening; together they
/// prevent the receiver from being tricked into writing under arbitrary
/// paths and keep the sender from synthesising "scp option" strings.
///
/// `.` is rejected because using it as a basename would let a peer
/// re-target the *current* directory entry on the receiver — replacing
/// its mode/contents — which the directory stack does not anticipate.
pub fn validate_name(name: &str) -> Result<(), ScpError> {
    if name.is_empty() {
        return Err(ScpError::BadName("empty"));
    }
    if name.contains('\0') {
        return Err(ScpError::BadName("contains NUL"));
    }
    if name.contains('\n') {
        return Err(ScpError::BadName("contains newline"));
    }
    if name.starts_with('-') {
        return Err(ScpError::BadName("starts with '-'"));
    }
    if name == "." || name == ".." || name.contains('/') {
        return Err(ScpError::BadName("path component"));
    }
    Ok(())
}

/// Write a single header line. Adds the terminating `\n`. Does not write
/// any payload bytes; for `C` headers the caller follows up with `size`
/// raw bytes and a single `0x00` terminator using [`write_payload_term`].
pub fn write_header<W: Write>(w: &mut W, h: &Header) -> Result<(), ScpError> {
    match h {
        Header::File { mode, size, name } => {
            validate_name(name)?;
            writeln!(w, "C{:04o} {} {}", mode & 0o7777, size, name)?;
        }
        Header::Dir { mode, name } => {
            validate_name(name)?;
            writeln!(w, "D{:04o} 0 {}", mode & 0o7777, name)?;
        }
        Header::EndDir => {
            w.write_all(b"E\n")?;
        }
        Header::Times { mtime, atime } => {
            // OpenSSH uses %lld for both — they fit in a u64 either way.
            writeln!(w, "T{} 0 {} 0", *mtime, *atime)?;
        }
    }
    w.flush()?;
    Ok(())
}

/// Read one header line up to `\n`. Returns `Ok(None)` if the peer
/// hangs up cleanly before the first byte (graceful EOF — the loop
/// terminates).
///
/// Validates names against [`validate_name`].
pub fn read_header<R: Read>(r: &mut R) -> Result<Option<Header>, ScpError> {
    let mut first = [0u8; 1];
    match r.read(&mut first) {
        Ok(0) => return Ok(None),
        Ok(_) => {}
        Err(e) if e.kind() == ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(ScpError::Io(e)),
    }

    // Allow OpenSSH-style ack-frame-as-error: a 0x01/0x02 byte where we
    // expected a header type is a warning/fatal from the peer. Surface
    // it as `Remote`/`Warning` so the loop can react.
    if first[0] == 0x01 || first[0] == 0x02 {
        let msg = read_line(r)?;
        return if first[0] == 0x02 {
            Err(ScpError::Remote(msg))
        } else {
            Err(ScpError::Warning(msg))
        };
    }

    let kind = first[0] as char;
    if !matches!(kind, 'C' | 'D' | 'E' | 'T') {
        return Err(ScpError::BadHeader("unknown header kind"));
    }

    let rest = read_line(r)?;
    match kind {
        'E' => {
            if !rest.is_empty() {
                return Err(ScpError::BadHeader("E has trailing data"));
            }
            Ok(Some(Header::EndDir))
        }
        'C' | 'D' => {
            // "<mode> <size> <name>" or "<mode> 0 <name>"
            let mut parts = rest.splitn(3, ' ');
            let mode_s = parts.next().ok_or(ScpError::BadHeader("missing mode"))?;
            let size_s = parts.next().ok_or(ScpError::BadHeader("missing size"))?;
            let name = parts.next().ok_or(ScpError::BadHeader("missing name"))?;
            let mode =
                u32::from_str_radix(mode_s, 8).map_err(|_| ScpError::BadHeader("bad mode"))?;
            let size = size_s
                .parse::<u64>()
                .map_err(|_| ScpError::BadHeader("bad size"))?;
            validate_name(name)?;
            if kind == 'C' {
                Ok(Some(Header::File {
                    mode,
                    size,
                    name: name.to_string(),
                }))
            } else {
                if size != 0 {
                    return Err(ScpError::BadHeader("D header with non-zero size"));
                }
                Ok(Some(Header::Dir {
                    mode,
                    name: name.to_string(),
                }))
            }
        }
        'T' => {
            // "<mtime> 0 <atime> 0"
            let mut parts = rest.split(' ');
            let mtime_s = parts.next().ok_or(ScpError::BadHeader("T missing mtime"))?;
            let zero1 = parts.next().ok_or(ScpError::BadHeader("T missing zero"))?;
            let atime_s = parts.next().ok_or(ScpError::BadHeader("T missing atime"))?;
            let zero2 = parts
                .next()
                .ok_or(ScpError::BadHeader("T missing trailing zero"))?;
            if parts.next().is_some() {
                return Err(ScpError::BadHeader("T trailing junk"));
            }
            if zero1 != "0" || zero2 != "0" {
                return Err(ScpError::BadHeader("T non-zero microseconds"));
            }
            let mtime = mtime_s
                .parse::<i64>()
                .map_err(|_| ScpError::BadHeader("T bad mtime"))?;
            let atime = atime_s
                .parse::<i64>()
                .map_err(|_| ScpError::BadHeader("T bad atime"))?;
            Ok(Some(Header::Times { mtime, atime }))
        }
        _ => unreachable!(),
    }
}

/// Read a line of UTF-8 up to (and consuming) the `\n` terminator.
/// Lines longer than 4 KiB are rejected — SCP headers / messages are
/// short by construction.
fn read_line<R: Read>(r: &mut R) -> Result<String, ScpError> {
    const MAX_LINE: usize = 4096;
    let mut out = Vec::with_capacity(64);
    let mut byte = [0u8; 1];
    loop {
        match r.read(&mut byte) {
            Ok(0) => return Err(ScpError::BadHeader("EOF mid-line")),
            Ok(_) => {}
            Err(e) => return Err(ScpError::Io(e)),
        }
        if byte[0] == b'\n' {
            break;
        }
        if out.len() >= MAX_LINE {
            return Err(ScpError::BadHeader("line too long"));
        }
        out.push(byte[0]);
    }
    String::from_utf8(out).map_err(|_| ScpError::BadHeader("non-UTF-8 line"))
}

/// Write a single `0x00` byte — the success ack. Used after each
/// header and after each payload body to tell the peer "go ahead".
pub fn write_ok<W: Write>(w: &mut W) -> Result<(), ScpError> {
    w.write_all(&[0x00])?;
    w.flush()?;
    Ok(())
}

/// Write a fatal error frame: `0x02 <message>\n`. The peer treats this
/// as terminal and stops sending.
pub fn write_fatal<W: Write>(w: &mut W, msg: &str) -> Result<(), ScpError> {
    let mut buf = Vec::with_capacity(2 + msg.len() + 1);
    buf.push(0x02);
    // Strip any embedded NUL/newline so we don't desync the frame.
    for &b in msg.as_bytes() {
        if b == b'\n' || b == 0 {
            buf.push(b' ');
        } else {
            buf.push(b);
        }
    }
    buf.push(b'\n');
    w.write_all(&buf)?;
    w.flush()?;
    Ok(())
}

/// Read a single ack byte from the peer. `0x00` returns Ok; `0x01`/`0x02`
/// read the message body and surface as `Warning`/`Remote`. Any other byte
/// is `BadHeader`.
pub fn read_ack<R: Read>(r: &mut R) -> Result<(), ScpError> {
    let mut b = [0u8; 1];
    match r.read(&mut b) {
        Ok(0) => return Err(ScpError::Unexpected("EOF awaiting ack")),
        Ok(_) => {}
        Err(e) => return Err(ScpError::Io(e)),
    }
    match b[0] {
        0x00 => Ok(()),
        0x01 => Err(ScpError::Warning(read_line(r)?)),
        0x02 => Err(ScpError::Remote(read_line(r)?)),
        _ => Err(ScpError::BadHeader("non-ack byte")),
    }
}

/// Write `size` bytes from `src` to `w`, then a single `0x00` payload
/// terminator. The caller is responsible for ensuring `src` produces
/// exactly `size` bytes; over-/under-supply desyncs the channel.
pub fn write_payload_term<R: Read, W: Write>(
    w: &mut W,
    src: &mut R,
    size: u64,
) -> Result<(), ScpError> {
    let mut remaining = size;
    let mut buf = [0u8; 32 * 1024];
    while remaining > 0 {
        let take = (remaining as usize).min(buf.len());
        let n = src.read(&mut buf[..take])?;
        if n == 0 {
            return Err(ScpError::Unexpected("local payload shorter than header"));
        }
        w.write_all(&buf[..n])?;
        remaining -= n as u64;
    }
    // OpenSSH sends a 0x00 after the payload as the file's own ack.
    w.write_all(&[0x00])?;
    w.flush()?;
    Ok(())
}

/// Read exactly `size` payload bytes into `dst`, then the single `0x00`
/// terminator byte that follows. Returns an error on under-read or if
/// the terminator is not `0x00` (which would indicate a peer-level
/// error frame in the wrong place).
pub fn read_payload_term<R: Read, W: Write>(
    r: &mut R,
    dst: &mut W,
    size: u64,
) -> Result<(), ScpError> {
    let mut remaining = size;
    let mut buf = [0u8; 32 * 1024];
    while remaining > 0 {
        let take = (remaining as usize).min(buf.len());
        let n = r.read(&mut buf[..take])?;
        if n == 0 {
            return Err(ScpError::Unexpected("EOF mid-payload"));
        }
        dst.write_all(&buf[..n])?;
        remaining -= n as u64;
    }
    let mut term = [0u8; 1];
    match r.read(&mut term) {
        Ok(0) => return Err(ScpError::Unexpected("EOF awaiting payload terminator")),
        Ok(_) => {}
        Err(e) => return Err(ScpError::Io(e)),
    }
    if term[0] != 0x00 {
        return Err(ScpError::BadHeader("payload terminator was not 0x00"));
    }
    Ok(())
}

#[cfg(test)]
mod unit {
    use super::*;

    #[test]
    fn round_trip_file_header() {
        let mut buf = Vec::new();
        write_header(
            &mut buf,
            &Header::File {
                mode: 0o644,
                size: 1234,
                name: "hello.txt".into(),
            },
        )
        .unwrap();
        assert_eq!(buf, b"C0644 1234 hello.txt\n");
        let mut cur = std::io::Cursor::new(buf);
        match read_header(&mut cur).unwrap().unwrap() {
            Header::File { mode, size, name } => {
                assert_eq!(mode, 0o644);
                assert_eq!(size, 1234);
                assert_eq!(name, "hello.txt");
            }
            _ => panic!("expected File"),
        }
    }

    #[test]
    fn round_trip_dir_and_end() {
        let mut buf = Vec::new();
        write_header(
            &mut buf,
            &Header::Dir {
                mode: 0o755,
                name: "sub".into(),
            },
        )
        .unwrap();
        write_header(&mut buf, &Header::EndDir).unwrap();
        assert_eq!(buf, b"D0755 0 sub\nE\n");
        let mut cur = std::io::Cursor::new(buf);
        assert!(matches!(
            read_header(&mut cur).unwrap().unwrap(),
            Header::Dir { .. }
        ));
        assert!(matches!(
            read_header(&mut cur).unwrap().unwrap(),
            Header::EndDir
        ));
    }

    #[test]
    fn round_trip_times() {
        let mut buf = Vec::new();
        write_header(
            &mut buf,
            &Header::Times {
                mtime: 1_700_000_000,
                atime: 1_700_000_001,
            },
        )
        .unwrap();
        assert_eq!(buf, b"T1700000000 0 1700000001 0\n");
        let mut cur = std::io::Cursor::new(buf);
        match read_header(&mut cur).unwrap().unwrap() {
            Header::Times { mtime, atime } => {
                assert_eq!(mtime, 1_700_000_000);
                assert_eq!(atime, 1_700_000_001);
            }
            _ => panic!("expected Times"),
        }
    }

    #[test]
    fn reject_leading_dash_name() {
        assert!(matches!(validate_name("-rf"), Err(ScpError::BadName(_))));
    }

    #[test]
    fn reject_newline_in_name() {
        assert!(matches!(validate_name("a\nb"), Err(ScpError::BadName(_))));
    }

    #[test]
    fn reject_slash_in_name() {
        assert!(matches!(validate_name("a/b"), Err(ScpError::BadName(_))));
    }

    #[test]
    fn ack_ok() {
        let mut cur = std::io::Cursor::new(vec![0x00u8]);
        assert!(read_ack(&mut cur).is_ok());
    }

    #[test]
    fn ack_remote_error_carries_message() {
        let mut cur = std::io::Cursor::new(b"\x02boom\n".to_vec());
        match read_ack(&mut cur) {
            Err(ScpError::Remote(m)) => assert_eq!(m, "boom"),
            other => panic!("unexpected {:?}", other),
        }
    }

    #[test]
    fn read_header_returns_none_on_eof() {
        let mut cur = std::io::Cursor::new(Vec::<u8>::new());
        assert!(read_header(&mut cur).unwrap().is_none());
    }

    #[test]
    fn write_fatal_strips_newlines() {
        let mut buf = Vec::new();
        write_fatal(&mut buf, "line1\nline2").unwrap();
        // 0x02, "line1 line2\n"
        assert_eq!(buf, b"\x02line1 line2\n");
    }
}
