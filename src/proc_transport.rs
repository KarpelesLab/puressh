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
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::time::Duration;

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
pub struct ProcTransport {
    child: Child,
    stdin: ChildStdin,
    stdout: ChildStdout,
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
        Ok(Self {
            child,
            stdin,
            stdout,
        })
    }
}

impl Read for ProcTransport {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.stdout.read(buf)
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
    /// No-op: anonymous pipes carry no read-timeout knob. Callers that need
    /// a real timeout (the serve / forwarding poll loops) must not run over
    /// a `ProxyCommand` transport — the `ssh` binary rejects `-L`/`-R`/`-N`
    /// in that case.
    fn set_read_timeout(&mut self, _t: Option<Duration>) -> io::Result<()> {
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
}
