//! `ProxyCommand` transport: run the SSH session over a spawned helper
//! process's stdio instead of a direct socket.
//!
//! `ssh_config(5)`'s `ProxyCommand` names a shell command whose stdin/stdout
//! become the byte transport to the server (e.g. `nc -X connect -x
//! proxy:3128 %h %p`). puressh spawns it as `/bin/sh -c "exec …"` with piped
//! stdin/stdout and inherited stderr, then drives a [`Client`] over the
//! pipes via [`Client::connect_via`].
//!
//! [`Client`]: crate::client::Client
//! [`Client::connect_via`]: crate::client::Client::connect_via

#![cfg(all(unix, feature = "client"))]

use std::io::{self, Read, Write};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::mpsc::{Receiver, RecvTimeoutError, sync_channel};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::client::{Transport, TransportReader};
use crate::error::{Error, Result};

/// Is `host` safe to substitute into a shell command line?
///
/// Mirrors OpenSSH's `valid_hostname()` (the CVE-2023-51385 fix): only
/// ASCII alphanumerics, `.`, `-` and `_`, plus the IPv6-literal
/// characters `:`, `[`, `]` and `%` (zone id), are allowed; the name must
/// be non-empty and must not start with `-` (so it can never be parsed as
/// an option by the helper it is handed to).
pub fn valid_hostname(host: &str) -> bool {
    if host.is_empty() || host.starts_with('-') {
        return false;
    }
    host.bytes().all(|b| {
        b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_' | b':' | b'[' | b']' | b'%')
    })
}

/// Is `user` safe to substitute into a shell command line?
///
/// Mirrors OpenSSH's `valid_ruser()` (a strict superset of its deny-list):
/// rejects a leading `-`, any whitespace or control character, and the
/// shell metacharacters `` ' ` \ " ; & | ( ) { } < > $ ``. Any other
/// character is accepted, as OpenSSH allows locale-specific login names.
pub fn valid_ruser(user: &str) -> bool {
    if user.starts_with('-') {
        return false;
    }
    !user.chars().any(|c| {
        c.is_whitespace()
            || c.is_control()
            || matches!(
                c,
                '\'' | '`' | '\\' | '"' | ';' | '&' | '|' | '(' | ')' | '{' | '}' | '<' | '>' | '$'
            )
    })
}

/// [`expand_tokens`] for strings that will be handed to `/bin/sh -c`
/// (`ProxyCommand`): the `%h` host and `%r` user are validated with
/// [`valid_hostname`] / [`valid_ruser`] before being spliced in, so a
/// hostname such as `` `id` `` or `-oProxyCommand=...` coming from an
/// untrusted source (a `.git/config`, a URL, a `ProxyJump` chain) cannot
/// inject shell syntax or options into the helper command. Only tokens
/// that actually appear in `s` are checked. Returns [`Error::Config`]
/// on an invalid value.
pub fn expand_tokens_checked(s: &str, host: &str, port: u16, user: &str) -> Result<String> {
    if uses_token(s, 'h') && !valid_hostname(host) {
        return Err(Error::Config(
            "ProxyCommand: hostname contains characters that are not permitted \
             in a shell command",
        ));
    }
    if uses_token(s, 'r') && !valid_ruser(user) {
        return Err(Error::Config(
            "ProxyCommand: remote user name contains characters that are not \
             permitted in a shell command",
        ));
    }
    Ok(expand_tokens(s, host, port, user))
}

/// Does `s` contain the `%<tok>` sequence (with `%%` escaping honoured)?
fn uses_token(s: &str, tok: char) -> bool {
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c == '%' && chars.next() == Some(tok) {
            return true;
        }
    }
    false
}

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
///
/// This performs **no validation** of `host` / `user` and is suitable for
/// values that are not interpreted by a shell (e.g. `ControlPath`). For a
/// string destined for `/bin/sh -c` use [`expand_tokens_checked`].
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
/// not run over a `ProxyCommand`. We give them one anyway: a thread reads
/// the child's stdout and hands the chunks over a channel, and
/// [`Read::read`] waits on that channel for at most the timeout
/// [`Transport::set_read_timeout`] recorded, translating an expired wait
/// into `WouldBlock` — exactly the signal the serve loop already handles for
/// a `TcpStream` read timeout. With no timeout the read blocks, so the
/// blocking KEX / userauth phases behave as before.
pub struct ProcTransport {
    child: Child,
    stdin: ChildStdin,
    stdout: Arc<Mutex<PipeReader>>,
    /// Current read timeout. `None` ⇒ block until data (or EOF). `Some(d)` ⇒
    /// each `read` waits at most `d` for data, then returns `WouldBlock`.
    read_timeout: Option<Duration>,
}

impl ProcTransport {
    /// Spawn `command` as `/bin/sh -c "exec <command>"` with piped
    /// stdin/stdout and inherited stderr, the way OpenSSH runs a
    /// `ProxyCommand`. `command` should already have its `%`-tokens
    /// expanded (see [`expand_tokens`]). Returns an error if the helper
    /// cannot be spawned — there is intentionally **no** fallback to a
    /// direct connection.
    ///
    /// The `exec` makes the helper itself the child we kill on drop. Without
    /// it a shell that forks for `-c` (dash, Debian/Ubuntu's `/bin/sh`)
    /// would be killed in its place, orphaning the helper — and since the
    /// stdout reader thread keeps the pipe open, a helper like `nc` would
    /// then hold its connection open forever. As with OpenSSH, only the
    /// first command of a list runs; wrap one in `sh -c '…'` instead.
    pub fn spawn(command: &str) -> io::Result<Self> {
        let mut child = Command::new("/bin/sh")
            .arg("-c")
            .arg(format!("exec {command}"))
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
            stdout: Arc::new(Mutex::new(PipeReader::spawn(stdout)?)),
            read_timeout: None,
        })
    }
}

/// The child's stdout, read by a thread of its own so a read can give up
/// after a timeout. The thread ends at EOF (the child exiting or being
/// killed on drop) or once the receiving side is gone.
struct PipeReader {
    rx: Receiver<io::Result<Vec<u8>>>,
    /// The part of the last chunk not yet returned.
    chunk: Vec<u8>,
    pos: usize,
    eof: bool,
}

/// Chunks (of up to 16 KiB) the stdout thread may read ahead of the client.
const PIPE_READ_AHEAD: usize = 8;

impl PipeReader {
    fn spawn(mut stdout: ChildStdout) -> io::Result<Self> {
        // Bounded: the thread reads ahead at most a few chunks, so a
        // command that outpaces the client cannot grow memory without limit.
        let (tx, rx) = sync_channel(PIPE_READ_AHEAD);
        std::thread::Builder::new()
            .name("proxycommand-stdout".into())
            .spawn(move || {
                let mut buf = vec![0u8; 16 * 1024];
                loop {
                    let r = match stdout.read(&mut buf) {
                        Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                        r => r.map(|n| buf[..n].to_vec()),
                    };
                    let last = !matches!(&r, Ok(chunk) if !chunk.is_empty());
                    if tx.send(r).is_err() || last {
                        return;
                    }
                }
            })?;
        Ok(Self {
            rx,
            chunk: Vec::new(),
            pos: 0,
            eof: false,
        })
    }

    fn read_within(&mut self, buf: &mut [u8], timeout: Option<Duration>) -> io::Result<usize> {
        if self.pos == self.chunk.len() {
            if self.eof {
                return Ok(0);
            }
            let next = match timeout {
                None => self.rx.recv().map_err(|_| RecvTimeoutError::Disconnected),
                Some(t) => self.rx.recv_timeout(t),
            };
            match next {
                Ok(Ok(chunk)) if !chunk.is_empty() => {
                    self.chunk = chunk;
                    self.pos = 0;
                }
                Ok(Ok(_)) | Err(RecvTimeoutError::Disconnected) => {
                    self.eof = true;
                    return Ok(0);
                }
                Ok(Err(e)) => {
                    self.eof = true;
                    return Err(e);
                }
                Err(RecvTimeoutError::Timeout) => {
                    return Err(io::Error::from(io::ErrorKind::WouldBlock));
                }
            }
        }
        let n = (self.chunk.len() - self.pos).min(buf.len());
        buf[..n].copy_from_slice(&self.chunk[self.pos..self.pos + n]);
        self.pos += n;
        Ok(n)
    }
}

/// A second handle on [`ProcTransport`]'s stdout, for
/// [`Transport::split_reader`].
struct ProcReader(Arc<Mutex<PipeReader>>);

impl TransportReader for ProcReader {
    fn read_within(&mut self, buf: &mut [u8], timeout: Option<Duration>) -> io::Result<usize> {
        lock_pipe(&self.0)?.read_within(buf, timeout)
    }
}

fn lock_pipe(p: &Mutex<PipeReader>) -> io::Result<std::sync::MutexGuard<'_, PipeReader>> {
    p.lock()
        .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "ProxyCommand reader poisoned"))
}

impl Read for ProcTransport {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        lock_pipe(&self.stdout)?.read_within(buf, self.read_timeout)
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
    /// Arm (or clear) a read timeout: how long [`Read::read`] waits for
    /// data. `Some(d)` makes reads return [`io::ErrorKind::WouldBlock`]
    /// after `d` of no data (the periodic tick the serve / forwarding loops
    /// rely on); `None` reverts to a blocking read.
    fn set_read_timeout(&mut self, t: Option<Duration>) -> io::Result<()> {
        self.read_timeout = t;
        Ok(())
    }

    /// The helper's stdout, so a shared connection waits for it without
    /// holding its lock.
    fn split_reader(&self) -> Option<Box<dyn TransportReader>> {
        Some(Box::new(ProcReader(self.stdout.clone())))
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
    use std::time::Instant;

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
    fn valid_hostname_matches_openssh_rules() {
        for ok in [
            "example.com",
            "10.0.0.1",
            "[::1]",
            "::1",
            "fe80::1%eth0",
            "host_1",
            "a-b.c",
            "LOCALHOST",
        ] {
            assert!(valid_hostname(ok), "{ok:?} should be accepted");
        }
        for bad in [
            "",
            "`id`",
            "$(id)",
            "a;b",
            "-oProxyCommand=x",
            "-",
            "a b",
            "a|b",
            "a&b",
            "a'b",
            "a\"b",
            "a\\b",
            "a/b",
            "a\nb",
            "a\tb",
            "hôst",
            "a>b",
            "a<b",
            "a(b)",
        ] {
            assert!(!valid_hostname(bad), "{bad:?} should be rejected");
        }
    }

    #[test]
    fn valid_ruser_matches_openssh_rules() {
        for ok in ["alice", "bob.smith", "user_1", "u-1", "", "李雷", "a@b"] {
            assert!(valid_ruser(ok), "{ok:?} should be accepted");
        }
        for bad in [
            "-bob", "a b", "a;b", "$(id)", "`id`", "a|b", "a&b", "a'b", "a\"b", "a\\b", "a(b",
            "a)b", "a<b", "a>b", "a\nb", "a\x1bb",
        ] {
            assert!(!valid_ruser(bad), "{bad:?} should be rejected");
        }
    }

    #[test]
    fn expand_tokens_checked_rejects_shell_metacharacters() {
        // Injection via the host or user reaching a `%h` / `%r` token fails
        // closed with a config error rather than reaching `/bin/sh -c`.
        for host in ["`id`", "$(id)", "a;b", "-oProxyCommand=x"] {
            let err = expand_tokens_checked("nc %h %p", host, 22, "u")
                .err()
                .unwrap_or_else(|| panic!("{host:?} must be rejected"));
            assert!(matches!(err, Error::Config(_)));
        }
        for user in ["-x", "a;b", "$(id)"] {
            assert!(expand_tokens_checked("ssh -l %r jump", "h", 22, user).is_err());
        }
        // Valid values expand exactly like the unchecked variant.
        for host in ["example.com", "10.0.0.1", "[::1]", "host_1"] {
            assert_eq!(
                expand_tokens_checked("nc %h %p", host, 2222, "u").unwrap(),
                format!("nc {host} 2222")
            );
        }
        // Values are only checked when the corresponding token is used —
        // a command that never interpolates the host cannot be injected
        // through it — and `%%h` is an escaped literal, not a token.
        assert_eq!(
            expand_tokens_checked("nc proxy 3128", "`id`", 22, "$(id)").unwrap(),
            "nc proxy 3128"
        );
        assert_eq!(
            expand_tokens_checked("echo 100%%h", "`id`", 22, "u").unwrap(),
            "echo 100%h"
        );
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
        let mut t = ProcTransport::spawn("true").expect("sh -c spawns");
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
            "the read should have waited out the deadline, took {:?}",
            start.elapsed()
        );
    }

    #[test]
    fn read_timeout_still_delivers_data() {
        // With a timeout armed, data that *does* arrive must still be read.
        let mut t = ProcTransport::spawn("sh -c 'printf abc; sleep 5'").expect("spawn");
        t.set_read_timeout(Some(Duration::from_millis(500)))
            .expect("set timeout");
        let mut buf = [0u8; 3];
        t.read_exact(&mut buf).expect("read the printf output");
        assert_eq!(&buf, b"abc");
    }

    #[test]
    fn blocking_read_after_clearing_timeout() {
        // `set_read_timeout(None)` reverts to a blocking read: a delayed
        // write is still delivered (no premature WouldBlock).
        let mut t = ProcTransport::spawn("sh -c 'sleep 0.1; printf ok'").expect("spawn");
        t.set_read_timeout(None).expect("clear timeout");
        let mut buf = [0u8; 2];
        t.read_exact(&mut buf)
            .expect("blocking read waits for data");
        assert_eq!(&buf, b"ok");
    }
}
