//! Client role: attach to a running master over the control socket and run a
//! session as a new channel on the master's existing SSH connection.
//!
//! No SSH state lives here — the client just speaks the mux frame protocol
//! ([`super::Frame`]) over the Unix socket and pumps local stdin/stdout/stderr
//! against it. The master does the real channel work.

use std::io::{self, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;

use super::codec::{Frame, MuxError, PROTOCOL_VERSION};
use super::{read_frame, write_frame};

/// What a [`probe_master`] connection attempt found at a `ControlPath`.
#[derive(Debug, PartialEq, Eq)]
pub enum ProbeOutcome {
    /// A live master answered `HELLO` with a compatible version — reuse it.
    Live,
    /// The socket file does not exist (nothing to reuse).
    Absent,
    /// The path exists but no live master answered (stale socket / wrong
    /// version / connect refused). Safe to unlink and replace.
    Stale,
}

/// The session a mux client wants the master to open on its behalf.
#[derive(Clone, Debug)]
pub struct SessionRequest {
    /// Request a PTY for the session.
    pub want_pty: bool,
    /// `$TERM` value (ignored when `want_pty` is false).
    pub term: String,
    /// Initial terminal width.
    pub cols: u32,
    /// Initial terminal height.
    pub rows: u32,
    /// Environment variables to forward to the remote session.
    pub env: Vec<(String, String)>,
    /// Remote command, or `None` for an interactive shell.
    pub command: Option<String>,
}

/// Probe `path` for a live master: connect, send `HELLO`, and expect a
/// compatible `HELLO` back within a short timeout.
///
/// This is non-destructive — it never unlinks anything. The caller decides
/// what to do with a [`ProbeOutcome::Stale`] result.
pub fn probe_master(path: &Path) -> ProbeOutcome {
    if !path.exists() {
        return ProbeOutcome::Absent;
    }
    match UnixStream::connect(path) {
        Ok(mut sock) => {
            let _ = sock.set_read_timeout(Some(Duration::from_millis(500)));
            let _ = sock.set_write_timeout(Some(Duration::from_millis(500)));
            if write_frame(
                &mut sock,
                &Frame::Hello {
                    version: PROTOCOL_VERSION,
                },
            )
            .is_err()
            {
                return ProbeOutcome::Stale;
            }
            match read_frame(&mut sock) {
                Ok(Some(Frame::Hello { version })) if version == PROTOCOL_VERSION => {
                    ProbeOutcome::Live
                }
                _ => ProbeOutcome::Stale,
            }
        }
        // Path exists but nothing is listening (or perms) — stale.
        Err(_) => ProbeOutcome::Stale,
    }
}

/// Attach to the master at `path` and run `req` to completion, splicing local
/// stdin/stdout/stderr against the multiplexed session. Returns the remote
/// exit status (0–255), or 255 if the session ended without a status.
///
/// `resize` is an optional callback returning the current `(cols, rows)`; when
/// supplied, a watcher thread sends [`Frame::WindowChange`] on changes (the
/// `ssh` binary wires this to its SIGWINCH handler). Pass `None` for the
/// non-PTY path.
pub fn run_client(
    path: &Path,
    req: &SessionRequest,
    resize: Option<Arc<dyn Fn() -> (u32, u32) + Send + Sync>>,
) -> Result<i32, MuxError> {
    let mut sock = UnixStream::connect(path).map_err(MuxError::Io)?;

    // HELLO handshake.
    write_frame(
        &mut sock,
        &Frame::Hello {
            version: PROTOCOL_VERSION,
        },
    )?;
    match read_frame(&mut sock)? {
        Some(Frame::Hello { version }) if version == PROTOCOL_VERSION => {}
        Some(Frame::Hello { version }) => {
            return Err(MuxError::VersionMismatch {
                ours: PROTOCOL_VERSION,
                theirs: version,
            });
        }
        _ => return Err(MuxError::Unexpected("expected HELLO from master")),
    }

    // OPEN_SESSION.
    write_frame(
        &mut sock,
        &Frame::OpenSession {
            want_pty: req.want_pty,
            term: req.term.clone(),
            cols: req.cols,
            rows: req.rows,
            env: req.env.clone(),
            command: req.command.clone(),
        },
    )?;

    let done = Arc::new(AtomicBool::new(false));

    // A write-half clone for the stdin and resize threads. UnixStream is
    // full-duplex and try_clone shares the same fd, so concurrent writes from
    // stdin + resize must not interleave a single frame — we serialise them
    // through a small mutex.
    let write_half = Arc::new(std::sync::Mutex::new(
        sock.try_clone().map_err(MuxError::Io)?,
    ));

    // stdin → STDIN_DATA frames.
    let in_write = write_half.clone();
    let in_done = done.clone();
    let t_in = thread::spawn(move || {
        let mut buf = [0u8; 32 * 1024];
        let mut stdin = io::stdin();
        loop {
            if in_done.load(Ordering::Relaxed) {
                break;
            }
            match stdin.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    let mut g = match in_write.lock() {
                        Ok(g) => g,
                        Err(_) => break,
                    };
                    if write_frame(&mut *g, &Frame::StdinData(buf[..n].to_vec())).is_err() {
                        break;
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(_) => break,
            }
        }
        // Half-close: tell the master no more stdin is coming.
        if let Ok(mut g) = in_write.lock() {
            let _ = write_frame(&mut *g, &Frame::Eof);
        }
    });

    // Optional resize watcher.
    let t_winch = resize.map(|get| {
        let w = write_half.clone();
        let stop = done.clone();
        thread::spawn(move || {
            let mut last = get();
            while !stop.load(Ordering::Relaxed) {
                thread::sleep(Duration::from_millis(100));
                let cur = get();
                if cur != last {
                    last = cur;
                    if let Ok(mut g) = w.lock() {
                        let _ = write_frame(
                            &mut *g,
                            &Frame::WindowChange {
                                cols: cur.0,
                                rows: cur.1,
                            },
                        );
                    }
                }
            }
        })
    });

    // Main loop: read frames from the master, fan out to stdout/stderr, and
    // capture the exit status. This thread owns the read half.
    let mut exit_code: i32 = 255;
    let mut stdout = io::stdout();
    let mut stderr = io::stderr();
    loop {
        match read_frame(&mut sock) {
            Ok(Some(Frame::StdoutData(d))) => {
                if stdout.write_all(&d).is_err() {
                    break;
                }
                let _ = stdout.flush();
            }
            Ok(Some(Frame::StderrData(d))) => {
                if stderr.write_all(&d).is_err() {
                    break;
                }
                let _ = stderr.flush();
            }
            Ok(Some(Frame::ExitStatus { code })) => {
                exit_code = code as i32;
                // Status is the last meaningful frame; the master closes after.
            }
            Ok(Some(Frame::ExitSignal { name })) => {
                let _ = writeln!(stderr, "\r\nsession terminated by signal: {name}");
                exit_code = 255;
            }
            Ok(Some(Frame::Eof)) => {
                // Master signalled end of session output.
                break;
            }
            Ok(Some(Frame::AliveOk)) => { /* ignore stray keepalive replies */ }
            Ok(Some(_)) => { /* ignore unexpected control frames */ }
            Ok(None) => break, // master closed the socket
            Err(_) => break,
        }
    }

    done.store(true, Ordering::Relaxed);
    // Shut the socket so the stdin thread's next write fails fast and it can
    // observe `done`. (stdin.read itself is uninterruptible, but the next
    // frame write will error once the socket is down.)
    let _ = sock.shutdown(std::net::Shutdown::Both);
    drop(t_in);
    if let Some(h) = t_winch {
        drop(h);
    }
    Ok(exit_code)
}
