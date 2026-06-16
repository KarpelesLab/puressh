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

/// Open a `direct-tcpip` forward through a running master and return the
/// connected control socket, already past HELLO + OPEN_OK, ready to splice
/// against a local TCP socket.
///
/// This is the mux-carrier equivalent of [`crate::client::ServeContext::open_direct_tcpip`]:
/// the master dials `dest_host:dest_port` over its SSH connection and, on
/// success, byte-splices the resulting channel against the returned socket
/// using the same `StdinData`/`StdoutData`/`Eof` frames a session uses. The
/// caller drives that splice with [`splice_forward`].
///
/// `orig_host`/`orig_port` are the informational originator address echoed in
/// the channel open (typically the local accept peer for `ssh -L`/`-D`).
pub fn open_forward(
    path: &Path,
    dest_host: &str,
    dest_port: u16,
    orig_host: &str,
    orig_port: u16,
) -> Result<UnixStream, MuxError> {
    let mut sock = UnixStream::connect(path).map_err(MuxError::Io)?;

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

    write_frame(
        &mut sock,
        &Frame::OpenDirectTcpip {
            dest_host: dest_host.to_string(),
            dest_port: dest_port as u32,
            orig_host: orig_host.to_string(),
            orig_port: orig_port as u32,
        },
    )?;

    match read_frame(&mut sock)? {
        Some(Frame::OpenOk) => Ok(sock),
        Some(Frame::OpenFail { reason }) => Err(MuxError::ForwardFailed(reason)),
        _ => Err(MuxError::Unexpected(
            "expected OPEN_OK/OPEN_FAIL from master",
        )),
    }
}

/// Splice a mux forward control socket (from [`open_forward`]) against a local
/// byte stream `local` (e.g. an accepted `ssh -L` TCP socket): local→master is
/// sent as `StdinData`, master→local arrives as `StdoutData`, and either side's
/// EOF tears the pair down. Blocks until the forward closes.
///
/// `local` must be cloneable into independent read/write halves (the splicing
/// uses one thread per direction); a `TcpStream` satisfies this via `try_clone`.
pub fn splice_forward<S>(sock: UnixStream, local: S) -> Result<(), MuxError>
where
    S: Read + Write + TryCloneStream + Send + 'static,
{
    let local_read = local.try_clone_stream().map_err(MuxError::Io)?;
    let mut local_write = local;

    let sock_read = sock.try_clone().map_err(MuxError::Io)?;
    let sock_write = Arc::new(std::sync::Mutex::new(sock));

    // local → master: read local bytes, frame them as StdinData.
    let up_write = sock_write.clone();
    let t_up = thread::spawn(move || {
        let mut local_read = local_read;
        let mut buf = [0u8; 32 * 1024];
        loop {
            match local_read.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    let mut g = match up_write.lock() {
                        Ok(g) => g,
                        Err(_) => break,
                    };
                    if write_frame(&mut *g, &Frame::StdinData(buf[..n].to_vec())).is_err() {
                        break;
                    }
                }
                Err(ref e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(_) => break,
            }
        }
        // Half-close upstream.
        if let Ok(mut g) = up_write.lock() {
            let _ = write_frame(&mut *g, &Frame::Eof);
        }
    });

    // master → local: read StdoutData frames, write to the local socket.
    let mut sock_read = sock_read;
    loop {
        match read_frame(&mut sock_read) {
            Ok(Some(Frame::StdoutData(d))) => {
                if local_write.write_all(&d).is_err() {
                    break;
                }
                let _ = local_write.flush();
            }
            Ok(Some(Frame::Eof)) | Ok(None) => break,
            Ok(Some(_)) => { /* ignore stray control frames */ }
            Err(_) => break,
        }
    }

    // Tear down: shut the control socket so the upstream thread's next frame
    // write fails fast, then join it.
    if let Ok(g) = sock_write.lock() {
        let _ = g.shutdown(std::net::Shutdown::Both);
    }
    let _ = t_up.join();
    Ok(())
}

/// A byte stream whose read/write halves can be split for bidirectional
/// splicing. Implemented for [`std::net::TcpStream`] (via `try_clone`).
pub trait TryCloneStream {
    /// Clone the stream into an independent handle over the same connection.
    fn try_clone_stream(&self) -> io::Result<Self>
    where
        Self: Sized;
}

impl TryCloneStream for std::net::TcpStream {
    fn try_clone_stream(&self) -> io::Result<Self> {
        self.try_clone()
    }
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

/// A `ssh -O` control command directed at a running master.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ControlCommand {
    /// `-O check`: probe whether the master is alive (HELLO + ALIVE_CHECK).
    Check,
    /// `-O exit` / `-O stop`: ask the master to tear down and unlink its
    /// socket (HELLO + EXIT_REQUEST).
    Exit,
}

/// Send a `ssh -O` control command to the master at `path` after a HELLO
/// handshake.
///
/// * [`ControlCommand::Check`] returns `Ok(true)` if the master answered
///   `ALIVE_OK`, `Ok(false)` if the path has no live master (absent / stale /
///   wrong version).
/// * [`ControlCommand::Exit`] sends `EXIT_REQUEST`; the master tears down and
///   unlinks its socket. Returns `Ok(true)` once the request was delivered.
///
/// Connection / protocol failures against an *existing* path surface as `Err`;
/// a missing socket is reported as `Ok(false)` for `Check`.
pub fn send_control_command(path: &Path, cmd: ControlCommand) -> Result<bool, MuxError> {
    let mut sock = match UnixStream::connect(path) {
        Ok(s) => s,
        // No live master to talk to.
        Err(_) if cmd == ControlCommand::Check => return Ok(false),
        Err(e) => return Err(MuxError::Io(e)),
    };
    let _ = sock.set_read_timeout(Some(Duration::from_millis(2000)));
    let _ = sock.set_write_timeout(Some(Duration::from_millis(2000)));

    // HELLO handshake.
    write_frame(
        &mut sock,
        &Frame::Hello {
            version: PROTOCOL_VERSION,
        },
    )?;
    match read_frame(&mut sock) {
        Ok(Some(Frame::Hello { version })) if version == PROTOCOL_VERSION => {}
        _ if cmd == ControlCommand::Check => return Ok(false),
        Ok(Some(Frame::Hello { version })) => {
            return Err(MuxError::VersionMismatch {
                ours: PROTOCOL_VERSION,
                theirs: version,
            });
        }
        Ok(_) => return Err(MuxError::Unexpected("expected HELLO from master")),
        Err(e) => return Err(e),
    }

    match cmd {
        ControlCommand::Check => {
            write_frame(&mut sock, &Frame::AliveCheck)?;
            match read_frame(&mut sock) {
                Ok(Some(Frame::AliveOk)) => Ok(true),
                _ => Ok(false),
            }
        }
        ControlCommand::Exit => {
            write_frame(&mut sock, &Frame::ExitRequest)?;
            // The master closes the socket as it tears down; we don't need a
            // reply. Best-effort: a clean EOF here confirms it acted on it.
            let _ = read_frame(&mut sock);
            Ok(true)
        }
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
