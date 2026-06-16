//! `ProxyCommand` transport: run the SSH session over a spawned helper
//! process's stdio instead of a direct socket.
//!
//! `ssh_config(5)`'s `ProxyCommand` names a shell command whose stdin/stdout
//! become the byte transport to the server (e.g. `nc -X connect -x
//! proxy:3128 %h %p`). puressh spawns it under `/bin/sh -c` with piped
//! stdin/stdout and inherited stderr, then drives a [`Client`] over the
//! pipes via [`Client::connect_via`].
//!
//! [`Client`]: crate::client::Client
//! [`Client::connect_via`]: crate::client::Client::connect_via

#![cfg(all(unix, feature = "client"))]

use std::io::{self, Read, Write};
use std::os::fd::AsFd;
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::time::{Duration, Instant};

use nix::fcntl::{FcntlArg, OFlag, fcntl};
use nix::poll::{PollFd, PollFlags, PollTimeout, poll};

use crate::client::Transport;

/// Expand OpenSSH-style `%`-tokens in a `ProxyCommand` / `ProxyJump` host
/// string.
///
/// Supported tokens:
/// - `%h` → target host
/// - `%p` → target port
/// - `%r` → remote (login) user
/// - `%%` → a literal `%`
///
/// Any other `%x` sequence is passed through verbatim (the `%` and the
/// following char are both kept), matching OpenSSH's lenient handling of
/// unknown tokens in these particular directives.
pub fn expand_tokens(s: &str, host: &str, port: u16, user: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c != '%' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some('h') => out.push_str(host),
            Some('p') => {
                use core::fmt::Write as _;
                let _ = write!(out, "{port}");
            }
            Some('r') => out.push_str(user),
            Some('%') => out.push('%'),
            Some(other) => {
                out.push('%');
                out.push(other);
            }
            None => out.push('%'),
        }
    }
    out
}

/// A [`Transport`] backed by a spawned `ProxyCommand` helper process.
///
/// Writes go to the child's stdin; reads come from its stdout. The child's
/// stderr is inherited so any diagnostics surface on the terminal. The
/// child is killed (and reaped) on drop.
///
/// # Read timeouts over a pipe
///
/// A plain anonymous pipe has no `SO_RCVTIMEO`-style knob, so the serve /
/// forwarding poll loops (which expect [`Transport::set_read_timeout`] to
/// produce a periodic [`io::ErrorKind::WouldBlock`] tick) historically could
/// not run over a `ProxyCommand`. We give them one anyway: the child's stdout
/// fd is switched to `O_NONBLOCK`, and [`Transport::set_read_timeout`] records
/// a deadline. With a timeout set, [`Read::read`] uses `poll(2)` to wait up to
/// the deadline for readability and translates the empty-poll case into
/// `WouldBlock` — exactly the signal the serve loop already handles for a
/// `TcpStream` read timeout. With no timeout the read blocks (via an infinite
/// `poll`) so the blocking KEX / userauth phases behave as before.
pub struct ProcTransport {
    child: Child,
    stdin: ChildStdin,
    stdout: ChildStdout,
    /// Current read timeout. `None` ⇒ block until data (or EOF). `Some(d)` ⇒
    /// each `read` waits at most `d` for readability, then returns
    /// `WouldBlock`. The stdout fd is always `O_NONBLOCK`; this field only
    /// decides how long `poll(2)` waits before giving up.
    read_timeout: Option<Duration>,
}

impl ProcTransport {
    /// Spawn `command` under `/bin/sh -c` with piped stdin/stdout and
    /// inherited stderr. `command` should already have its `%`-tokens
    /// expanded (see [`expand_tokens`]). Returns an error if the helper
    /// cannot be spawned — there is intentionally **no** fallback to a
    /// direct connection.
    pub fn spawn(command: &str) -> io::Result<Self> {
        let mut child = Command::new("/bin/sh")
            .arg("-c")
            .arg(command)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()?;
        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| io::Error::other("ProxyCommand: child stdin not captured"))?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| io::Error::other("ProxyCommand: child stdout not captured"))?;
        // Put the read side into non-blocking mode up front: every read goes
        // through `poll(2)` + a non-blocking `read`, regardless of whether a
        // timeout is currently armed (a `None` timeout polls with no deadline).
        set_nonblocking(&stdout)?;
        Ok(Self {
            child,
            stdin,
            stdout,
            read_timeout: None,
        })
    }
}

/// Flip `O_NONBLOCK` on for `fd` via `fcntl(F_GETFL)` + `fcntl(F_SETFL)`.
fn set_nonblocking<F: AsFd>(fd: &F) -> io::Result<()> {
    let borrowed = fd.as_fd();
    let cur = fcntl(borrowed, FcntlArg::F_GETFL).map_err(io::Error::from)?;
    let flags = OFlag::from_bits_truncate(cur) | OFlag::O_NONBLOCK;
    fcntl(borrowed, FcntlArg::F_SETFL(flags)).map_err(io::Error::from)?;
    Ok(())
}

impl Read for ProcTransport {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        // The fd is O_NONBLOCK, so a bare `read` returns `WouldBlock` instead
        // of parking. We wrap it in `poll(2)` to get the wait semantics the
        // serve loop expects:
        //   * `read_timeout = None`  → poll with no deadline (block for data).
        //   * `read_timeout = Some`  → poll up to the deadline, surfacing
        //     `WouldBlock` if nothing arrives so the caller can tick.
        let deadline = self.read_timeout.map(|d| Instant::now() + d);
        loop {
            // Compute the remaining poll budget for this iteration.
            let timeout: PollTimeout = match deadline {
                None => PollTimeout::NONE,
                Some(end) => {
                    let now = Instant::now();
                    if now >= end {
                        return Err(io::Error::from(io::ErrorKind::WouldBlock));
                    }
                    let remaining = end - now;
                    // Clamp to u16 ms (PollTimeout's largest finite value is
                    // ~65s; our timeouts are tens of ms, so saturation is fine).
                    let ms = remaining.as_millis().min(u16::MAX as u128) as u16;
                    PollTimeout::from(ms)
                }
            };

            let mut fds = [PollFd::new(self.stdout.as_fd(), PollFlags::POLLIN)];
            match poll(&mut fds, timeout) {
                Ok(0) => {
                    // poll timed out without readiness → no data yet.
                    return Err(io::Error::from(io::ErrorKind::WouldBlock));
                }
                Ok(_) => {
                    // Readable (or hangup): attempt the read. On a real pipe a
                    // POLLHUP fd reads as EOF (0), which we surface as Ok(0).
                    match self.stdout.read(buf) {
                        // Spurious wakeup (poll said readable but the read
                        // raced to empty) — loop and re-poll within budget.
                        Err(e) if e.kind() == io::ErrorKind::WouldBlock => continue,
                        other => return other,
                    }
                }
                Err(nix::errno::Errno::EINTR) => continue,
                Err(e) => return Err(io::Error::from(e)),
            }
        }
    }
}

impl Write for ProcTransport {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.stdin.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.stdin.flush()
    }
}

impl Transport for ProcTransport {
    /// Arm (or clear) a read timeout. The child stdout fd is already
    /// `O_NONBLOCK`; this just records the deadline [`Read::read`] enforces
    /// via `poll(2)`. `Some(d)` makes reads return [`io::ErrorKind::WouldBlock`]
    /// after `d` of no data (the periodic tick the serve / forwarding loops
    /// rely on); `None` reverts to a blocking read.
    fn set_read_timeout(&mut self, t: Option<Duration>) -> io::Result<()> {
        self.read_timeout = t;
        Ok(())
    }
}

impl Drop for ProcTransport {
    fn drop(&mut self) {
        // Best-effort: kill the helper and reap it so we don't leave a
        // zombie. Ignore errors — the child may have already exited.
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expand_basic_tokens() {
        assert_eq!(
            expand_tokens("nc %h %p", "example.com", 2222, "alice"),
            "nc example.com 2222"
        );
        assert_eq!(expand_tokens("login=%r", "h", 22, "bob"), "login=bob");
        assert_eq!(expand_tokens("100%%done", "h", 22, "u"), "100%done");
    }

    #[test]
    fn expand_unknown_token_passthrough() {
        // %z isn't a recognised token → kept verbatim.
        assert_eq!(expand_tokens("a%zb", "h", 22, "u"), "a%zb");
        // trailing lone % is kept.
        assert_eq!(expand_tokens("end%", "h", 22, "u"), "end%");
    }

    #[test]
    fn spawn_failure_is_strict_error() {
        // A command that cannot possibly run still *spawns* /bin/sh (sh
        // exists), so to exercise the strict no-fallback path we instead
        // verify that a command exiting immediately yields EOF on read
        // rather than silently succeeding. The genuine spawn-failure path
        // (e.g. /bin/sh missing) is exercised by the binary's error
        // propagation; here we just confirm the transport surfaces the
        // child's premature exit as a clean EOF.
        let mut t = ProcTransport::spawn("exit 0").expect("sh -c spawns");
        let mut buf = [0u8; 16];
        let n = t.read(&mut buf).expect("read after child exit");
        assert_eq!(n, 0, "closed child stdout should read as EOF");
    }

    #[test]
    fn round_trip_through_cat() {
        // `cat` echoes stdin to stdout — a trivial loopback transport.
        let mut t = ProcTransport::spawn("cat").expect("spawn cat");
        t.write_all(b"hello pipe").expect("write");
        t.flush().expect("flush");
        let mut buf = [0u8; 10];
        t.read_exact(&mut buf).expect("read echo");
        assert_eq!(&buf, b"hello pipe");
    }

    #[test]
    fn read_timeout_ticks_as_wouldblock() {
        // `sleep` produces no output, so a read with a short timeout must
        // surface WouldBlock (the serve-loop tick) rather than blocking.
        let mut t = ProcTransport::spawn("sleep 5").expect("spawn sleep");
        t.set_read_timeout(Some(Duration::from_millis(50)))
            .expect("set timeout");
        let mut buf = [0u8; 16];
        let start = Instant::now();
        let err = t.read(&mut buf).expect_err("should time out");
        assert_eq!(err.kind(), io::ErrorKind::WouldBlock);
        // It should have actually waited ~the timeout, not busy-returned.
        assert!(
            start.elapsed() >= Duration::from_millis(40),
            "poll should have waited out the deadline, took {:?}",
            start.elapsed()
        );
    }

    #[test]
    fn read_timeout_still_delivers_data() {
        // With a timeout armed, data that *does* arrive must still be read.
        let mut t = ProcTransport::spawn("printf abc; sleep 5").expect("spawn");
        t.set_read_timeout(Some(Duration::from_millis(500)))
            .expect("set timeout");
        let mut buf = [0u8; 3];
        t.read_exact(&mut buf).expect("read the printf output");
        assert_eq!(&buf, b"abc");
    }

    #[test]
    fn blocking_read_after_clearing_timeout() {
        // `set_read_timeout(None)` reverts to a blocking poll: a delayed
        // write is still delivered (no premature WouldBlock).
        let mut t = ProcTransport::spawn("sleep 0.1; printf ok").expect("spawn");
        t.set_read_timeout(None).expect("clear timeout");
        let mut buf = [0u8; 2];
        t.read_exact(&mut buf)
            .expect("blocking read waits for data");
        assert_eq!(&buf, b"ok");
    }
}
