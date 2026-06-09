//! Shared helpers for the puressh client-side binaries (`ssh`, `sftp`,
//! `scp`). Each binary pulls this module in via
//! `#[path = "common.rs"] mod common;` so Cargo doesn't need a separate
//! `[[bin]]` entry for the helpers.
//!
//! Every helper is `#[allow(dead_code)]` at the function level, because no
//! single binary uses all of them — pulling the module in via `#[path]`
//! produces an independent copy per binary, and Rust's dead-code lint
//! complains otherwise.
//!
//! Helpers cluster around four concerns:
//!
//! - **User resolution** (`resolve_user`, `parse_userhost`,
//!   `parse_userhost_path`): turning command-line targets into
//!   `(user, host[, path])` triples consistently.
//! - **Credentials** (`load_identity`, `connect_agent_credentials`,
//!   `read_password_from_stdin`): collecting whatever the user gave us into
//!   the lib's [`ClientCredential`] vector.
//! - **Host-key policy** (`build_host_key_policy`, `default_known_hosts_path`,
//!   `tofu_prompt`, `fingerprint_b64_sha256`, `base64_no_pad`): mapping
//!   OpenSSH-style `StrictHostKeyChecking` semantics into a
//!   [`HostKeyPolicy`].
//! - **`StrictMode`**: the four-valued enum that drives the policy choice.

#![allow(dead_code)]

use core::sync::atomic::{AtomicU8, Ordering};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

#[cfg(unix)]
use puressh::agent::{Agent, AgentHostKey};
use puressh::auth::ClientCredential;
use puressh::client::{HostKeyPolicy, KnownHostsPolicy, TofuAction};
use puressh::key::PrivateKey;
use puressh::known_hosts::KnownHosts;
use puressh::Error;
use zeroize::Zeroizing;

// `StrictMode` lives in the lib so the config parser and the binaries share
// one definition. Re-exported here so existing `use common::StrictMode;`
// sites keep compiling unchanged.
pub use puressh::config::StrictMode;

/// Pick the effective username for an SSH session, in OpenSSH's order of
/// precedence: explicit `-l user` wins; otherwise `user@host` syntax;
/// otherwise the calling user's `$USER`.
pub fn resolve_user(cli_user: Option<&str>, user_in_host: Option<&str>) -> Result<String, String> {
    if let Some(u) = cli_user {
        return Ok(u.to_string());
    }
    if let Some(u) = user_in_host {
        return Ok(u.to_string());
    }
    std::env::var("USER").map_err(|_| "no user specified and $USER is unset".into())
}

/// Split a `[user@]host` token. The host portion is whatever follows the
/// first `@` — for an unadorned `host`, the user half is `None`.
pub fn parse_userhost(target: &str) -> (Option<String>, String) {
    match target.split_once('@') {
        Some((u, h)) => (Some(u.to_string()), h.to_string()),
        None => (None, target.to_string()),
    }
}

/// Split a `[user@]host[:port]` CLI target. The host half goes through
/// [`puressh::config::parse_host_port`] so bracketed IPv6 literals
/// (`[2001:db8::1]:22`) and bare IPv6 literals (`2001:db8::1`, no
/// port) work. The returned port is `Some(p)` when the target carried
/// an explicit port (either `host:port` or `[v6]:port`), and `None`
/// when it didn't — callers decide whether `-p`/config/22 wins.
///
/// Returns `(user, host, port)`. `user` is `None` when the target had no
/// `@`. Errors are stringified for the bin's existing error-reporting
/// flow.
pub fn parse_target(target: &str) -> Result<(Option<String>, String, Option<u16>), String> {
    let (user, host_with_port) = parse_userhost(target);
    if host_with_port.is_empty() {
        return Err("empty host".into());
    }
    // We pass a sentinel default of 0 to parse_host_port and reconstruct
    // the "was a port given?" bit afterwards. Port 0 is reserved for
    // OS-assigned binds; it's never a meaningful connect target, so
    // using it as the "no port given" marker is unambiguous.
    let (host, port) =
        puressh::config::parse_host_port(&host_with_port, 0).map_err(|e| format!("{e}"))?;
    let port_opt = if port == 0 { None } else { Some(port) };
    Ok((user, host, port_opt))
}

/// Split a `[user@]host:path` token used by `scp(1)` / `sftp(1)` local-or-
/// remote arguments. Returns `None` when there's no `:` — that signals a
/// plain local path. The user prefix is optional (as in `host:path`).
///
/// We deliberately accept colons in the path portion (after the first one)
/// to match OpenSSH's behaviour; the caller decides whether to refuse them.
///
/// IPv6 literals must be bracketed in this position so the `:` separator
/// is unambiguous: `[user@][2001:db8::1]:/etc/motd`. A bare v6 host
/// (`2001:db8::1:/path`) is not accepted because there is no way to
/// distinguish the address from the path. This matches OpenSSH `scp(1)`
/// behaviour.
pub fn parse_userhost_path(target: &str) -> Option<(Option<String>, String, String)> {
    // Refuse a bare absolute path (`/foo/bar:baz` is local, not remote).
    if target.starts_with('/') {
        return None;
    }

    // Pull the optional `user@` prefix off the front first. We split on
    // the FIRST `@` because that matches the existing parse_userhost
    // semantics; v6 in brackets does not contain `@`.
    let (user, after_user) = parse_userhost(target);

    // Now look for the host/path separator. With a bracketed v6, the `]`
    // ends the host and the next char must be `:` then the path.
    let (host, path) = if let Some(rest) = after_user.strip_prefix('[') {
        // [host]:path — find the closing `]`. Everything in between is
        // the host (taken verbatim, no v6 validation here because scp is
        // happy to forward any string to its peer's resolver).
        let close = rest.find(']')?;
        let host = rest[..close].to_string();
        let after_bracket = &rest[close + 1..];
        let path = after_bracket.strip_prefix(':')?;
        (host, path.to_string())
    } else {
        // Plain `host:path` — split on the first `:`.
        let (h, p) = after_user.split_once(':')?;
        (h.to_string(), p.to_string())
    };

    if host.is_empty() {
        return None;
    }
    Some((user, host, path))
}

/// Read a passphrase from stdin (or `$SSH_ASKPASS` if set) without
/// echoing it. Returns a [`Zeroizing<String>`] so the buffer is wiped on
/// drop — callers should not clone the inner `String` and should drop
/// the wrapper as soon as auth completes.
///
/// Lookup order:
/// 1. `$SSH_ASKPASS` is set AND we have no controlling tty (matches
///    OpenSSH): run the named helper, take its first stdout line.
/// 2. Stdin is a TTY (Unix): disable echo via `tcsetattr(ECHO off)`,
///    read one line, restore the old settings via a `Drop` guard.
/// 3. Anything else (non-TTY stdin, no helper, or non-Unix platform):
///    fall back to plain `read_line` with a warning printed once — the
///    password *will* be echoed.
pub fn read_password_from_stdin() -> std::io::Result<Zeroizing<String>> {
    // Honour $SSH_ASKPASS the OpenSSH way: only use it when there's no
    // controlling tty (or when SSH_ASKPASS_REQUIRE=force).
    if let Some(out) = try_ssh_askpass()? {
        return Ok(out);
    }

    eprint!("password: ");
    std::io::stderr().flush()?;

    #[cfg(unix)]
    {
        if let Some(out) = read_password_no_echo_unix()? {
            return Ok(out);
        }
    }

    // Non-Unix or non-tty stdin: warn once, then read with echo. This
    // mirrors the v0 behaviour but at least announces it.
    eprintln!();
    eprintln!("(warning: terminal echo could not be disabled; password will be visible)");
    let mut buf = String::new();
    read_one_line(&mut buf, 4096)?;
    Ok(Zeroizing::new(buf))
}

/// Pull one line off stdin into `buf`, stopping at `\n` (which is
/// consumed but not appended). `\r` is dropped. Capped at `max_len`
/// bytes to bound memory if the source is unbounded.
fn read_one_line(buf: &mut String, max_len: usize) -> std::io::Result<()> {
    let mut byte = [0u8; 1];
    let mut stdin = std::io::stdin();
    loop {
        let n = stdin.read(&mut byte)?;
        if n == 0 || byte[0] == b'\n' {
            break;
        }
        if byte[0] == b'\r' {
            continue;
        }
        buf.push(byte[0] as char);
        if buf.len() > max_len {
            break;
        }
    }
    Ok(())
}

/// Unix-only no-echo password read. Returns `Ok(None)` if stdin isn't
/// a tty (so caller falls back to plain read with the warning). On
/// success the terminal echo bit is restored via a `Drop` guard,
/// even if the read fails or panics.
#[cfg(unix)]
fn read_password_no_echo_unix() -> std::io::Result<Option<Zeroizing<String>>> {
    use std::os::unix::io::AsRawFd;
    let fd = std::io::stdin().as_raw_fd();
    // SAFETY: zero-init is the documented way to allocate a termios
    // struct before tcgetattr fills it in.
    let mut term: libc::termios = unsafe { core::mem::zeroed() };
    // SAFETY: `fd` is a valid file descriptor (stdin); `term` is a
    // writable termios.
    if unsafe { libc::tcgetattr(fd, &mut term as *mut _) } != 0 {
        // Not a tty (or some other failure); fall back.
        return Ok(None);
    }
    let original = term;

    // Drop guard restores echo even on panic/early-return.
    struct EchoGuard {
        fd: libc::c_int,
        original: libc::termios,
    }
    impl Drop for EchoGuard {
        fn drop(&mut self) {
            // SAFETY: we captured the original termios just above; the
            // fd is still stdin, valid for the lifetime of the process.
            unsafe { libc::tcsetattr(self.fd, libc::TCSANOW, &self.original) };
        }
    }

    term.c_lflag &= !libc::ECHO;
    // SAFETY: `term` is a valid termios value derived from
    // `tcgetattr`, with only ECHO cleared.
    if unsafe { libc::tcsetattr(fd, libc::TCSANOW, &term) } != 0 {
        return Ok(None);
    }
    let _guard = EchoGuard { fd, original };

    let mut buf = String::new();
    let res = read_one_line(&mut buf, 4096);
    // Print the missing newline so subsequent output doesn't run into
    // the prompt line.
    eprintln!();
    res?;
    Ok(Some(Zeroizing::new(buf)))
}

/// Drop-guard wrapper around a saved `termios` snapshot that switches
/// stdin into raw mode on construction and restores it on drop. Used
/// by the interactive-shell path in `ssh.rs` so a panic, signal, or
/// early-return through any of the I/O threads still leaves the
/// user's terminal usable.
///
/// "Raw" here mirrors the bit-clear set OpenSSH applies for
/// `ssh -tt`: clear `ICANON | ECHO | ECHOE | ECHOK | ECHONL | ISIG |
/// IEXTEN` on `c_lflag`, `IXON | ICRNL | BRKINT | INPCK | ISTRIP` on
/// `c_iflag`, `OPOST` on `c_oflag`, plus `VMIN=1 / VTIME=0` so reads
/// return as soon as a single byte arrives.
///
/// In addition to the `Drop` restore (which covers normal exit + panic
/// unwind), `install` arms an async-signal-safe handler for
/// SIGINT/SIGTERM/SIGHUP/SIGQUIT that runs `tcsetattr` back to the
/// saved settings *before* the process dies — otherwise Ctrl-C from
/// the local tty would leave the user's shell in raw mode, no echo,
/// no line discipline, and they'd have to type `reset` blind. The
/// handler is installed with `SA_RESETHAND` so the second occurrence
/// of the same signal kills the process with the default disposition
/// (and the correct WIFSIGNALED exit code); the first occurrence both
/// restores termios and re-raises the signal after re-installing the
/// previous disposition.
///
/// Nested guards on the same fd are NOT supported: `install` will
/// fall back to a Drop-only guard (no signal handler) when one is
/// already armed, so the outer guard's handler stays in place and
/// the inner guard is a no-op for signal purposes. The current call
/// site in `ssh.rs` never nests, so this is a defensive contract,
/// not a hot path.
#[cfg(unix)]
pub struct TermiosRawGuard {
    fd: libc::c_int,
    original: libc::termios,
    /// `true` when *this* guard owns the installed signal handlers
    /// and must tear them down on drop; `false` for a nested
    /// guard (which restores termios on drop but leaves the
    /// outer guard's handler in place).
    owns_handler: bool,
}

#[cfg(unix)]
mod termios_signal {
    //! Signal-handler state for [`super::TermiosRawGuard`].
    //!
    //! Everything here is laid out so the handler can run from
    //! inside `sigaction(2)` without touching anything that isn't
    //! on POSIX's async-signal-safe list (`tcsetattr`, `sigaction`,
    //! `raise`, atomic loads/stores). No `Mutex`, no allocation,
    //! no `eprintln!`, no `Drop`.
    use core::cell::UnsafeCell;
    use core::mem::MaybeUninit;
    use core::sync::atomic::{AtomicBool, AtomicI32, Ordering};

    /// `true` while a [`super::TermiosRawGuard`] holds the
    /// install slot. Set by `try_install` (compare-exchange) and
    /// cleared by `uninstall`. Read by both the install path and,
    /// indirectly (via the saved state), the handler.
    pub(super) static INSTALLED: AtomicBool = AtomicBool::new(false);

    /// fd to call `tcsetattr` on from inside the handler. `-1`
    /// means "no install active" — the handler must check this
    /// to avoid acting on stale state if it ever races with
    /// `uninstall` (which it shouldn't, since we `SA_RESETHAND`
    /// and tear down the disposition before clearing `INSTALLED`,
    /// but the read is free).
    pub(super) static SAVED_FD: AtomicI32 = AtomicI32::new(-1);

    /// Saved termios bytes. Written by `try_install` *before*
    /// `sigaction` arms the handler, read by the handler. The
    /// store/arm ordering is the only thing that makes this
    /// safe to read from the handler.
    ///
    /// Not behind a `Mutex` on purpose: the handler may not
    /// lock. Outside the handler, accesses are gated by
    /// `INSTALLED` (a single guard owns the slot at a time).
    pub(super) struct TermiosCell(pub UnsafeCell<MaybeUninit<libc::termios>>);
    // SAFETY: writes are gated by `INSTALLED` (only one guard at
    // a time); the handler reads via a raw pointer and `tcsetattr`
    // treats the buffer as read-only.
    unsafe impl Sync for TermiosCell {}
    pub(super) static SAVED_TERMIOS: TermiosCell =
        TermiosCell(UnsafeCell::new(MaybeUninit::uninit()));

    /// Previous `sigaction` for SIGINT/SIGTERM/SIGHUP/SIGQUIT,
    /// captured at install time and restored on uninstall. Indexed
    /// in the same order as [`SIGNALS`].
    pub(super) struct SigactionCell(pub UnsafeCell<MaybeUninit<libc::sigaction>>);
    // SAFETY: same `INSTALLED`-gated access pattern as `TermiosCell`.
    unsafe impl Sync for SigactionCell {}
    pub(super) static PREV_SIGACTIONS: [SigactionCell; 4] = [
        SigactionCell(UnsafeCell::new(MaybeUninit::uninit())),
        SigactionCell(UnsafeCell::new(MaybeUninit::uninit())),
        SigactionCell(UnsafeCell::new(MaybeUninit::uninit())),
        SigactionCell(UnsafeCell::new(MaybeUninit::uninit())),
    ];

    /// Signals we intercept. Order matches `PREV_SIGACTIONS`.
    pub(super) const SIGNALS: [libc::c_int; 4] =
        [libc::SIGINT, libc::SIGTERM, libc::SIGHUP, libc::SIGQUIT];

    /// Async-signal-safe handler. Restores the saved termios,
    /// then re-raises `sig` so the process dies with the proper
    /// WIFSIGNALED exit code. We armed via `SA_RESETHAND`, so
    /// the disposition has already reverted to the default by the
    /// time we re-enter (no `sigaction` call needed from inside
    /// the handler).
    ///
    /// Only async-signal-safe libc calls are used:
    ///   - `tcsetattr` (POSIX-listed)
    ///   - `raise` (POSIX-listed)
    ///
    /// Atomic loads/stores are lock-free on every Unix tier-1
    /// target and are safe from a signal handler.
    pub(super) extern "C" fn handler(sig: libc::c_int) {
        let fd = SAVED_FD.load(Ordering::Relaxed);
        if fd >= 0 {
            // SAFETY: `SAVED_TERMIOS` was initialised before
            // `sigaction` armed this handler, by the install
            // path which set `SAVED_FD` last. So whenever
            // `fd >= 0` the cell holds a valid `libc::termios`
            // that the handler may read. `tcsetattr` only reads
            // the buffer. Failure (-1) is intentionally ignored
            // — we cannot `eprintln!` from here.
            unsafe {
                let ptr = SAVED_TERMIOS.0.get();
                libc::tcsetattr(fd, libc::TCSANOW, (*ptr).as_ptr());
            }
        }
        // SA_RESETHAND already restored the default disposition;
        // re-raise so the process dies with the correct status.
        // Ignore the return — there's nothing useful to do on
        // failure, and `raise` is async-signal-safe.
        unsafe {
            libc::raise(sig);
        }
    }
}

#[cfg(unix)]
impl TermiosRawGuard {
    /// Switch fd 0 into raw mode and return a guard that restores the
    /// passed-in `original` termios on drop. Best-effort: if the
    /// `tcsetattr` call fails (e.g. stdin isn't a tty after all), the
    /// returned guard still restores on drop — no observable effect
    /// in that case.
    ///
    /// Also arms a signal-safe handler for SIGINT/SIGTERM/SIGHUP/
    /// SIGQUIT that runs `tcsetattr` back to `original` before the
    /// process dies — see the type-level docs for the rationale.
    /// Failure to arm a handler is non-fatal: the guard still works
    /// for the panic / clean-exit case.
    pub fn install(original: &libc::termios) -> Self {
        let fd: libc::c_int = 0;
        let mut raw = *original;
        raw.c_lflag &= !(libc::ICANON
            | libc::ECHO
            | libc::ECHOE
            | libc::ECHOK
            | libc::ECHONL
            | libc::ISIG
            | libc::IEXTEN);
        raw.c_iflag &= !(libc::IXON | libc::ICRNL | libc::BRKINT | libc::INPCK | libc::ISTRIP);
        raw.c_oflag &= !libc::OPOST;
        raw.c_cc[libc::VMIN] = 1;
        raw.c_cc[libc::VTIME] = 0;
        // SAFETY: `raw` is derived from `original` (which the caller
        // got from a successful tcgetattr); the fd is stdin and valid
        // for the process lifetime.
        unsafe {
            libc::tcsetattr(fd, libc::TCSANOW, &raw);
        }
        // Arm the signal handler. Returns false if one is already
        // installed (nested guard) — in that case we leave the outer
        // guard's handler in charge and the inner guard becomes
        // Drop-only.
        let owns_handler = install_signal_handler(fd, original);
        TermiosRawGuard {
            fd,
            original: *original,
            owns_handler,
        }
    }
}

#[cfg(unix)]
impl Drop for TermiosRawGuard {
    fn drop(&mut self) {
        if self.owns_handler {
            // Tear down the signal handler *before* the termios
            // restore: the handler is now a no-op-ish path
            // (SAVED_FD will be set to -1), and if a signal lands
            // between the two operations the default disposition
            // (or whatever was there before us) is exactly what we
            // want — the user's shell will already be in cooked
            // mode by then because we're about to do the
            // tcsetattr below.
            uninstall_signal_handler();
        }
        // SAFETY: same justification as `install` — we captured a
        // valid termios; the fd is stdin.
        unsafe {
            libc::tcsetattr(self.fd, libc::TCSANOW, &self.original);
        }
    }
}

/// Arm the signal-safe restore handler. Returns `true` if this call
/// installed the handlers (and the caller must call
/// [`uninstall_signal_handler`] later), `false` if a handler was
/// already installed (nested guard — leave the outer handler alone).
///
/// On `sigaction` failure for any of the four signals, the slot is
/// left in its prior state and we keep going: any signal we did
/// manage to install on still restores the tty; a SIGTERM we
/// couldn't install on still kills the process, but the Drop guard
/// handles the clean-exit path too.
#[cfg(unix)]
fn install_signal_handler(fd: libc::c_int, original: &libc::termios) -> bool {
    use core::sync::atomic::Ordering;
    // CAS: refuse to install when another guard already owns the slot.
    if termios_signal::INSTALLED
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return false;
    }
    // SAFETY: we hold the install slot (the CAS above), so we're the
    // only writer to these statics. The termios store *must* happen
    // before SAVED_FD is set (the handler keys off SAVED_FD >= 0).
    unsafe {
        (*termios_signal::SAVED_TERMIOS.0.get()).write(*original);
    }
    // Publish `fd` last; this is the "data ready" signal for the
    // handler. Release ordering pairs with the Relaxed load in the
    // handler — relaxed is fine on the handler side because signal
    // delivery already establishes a synchronizes-with relation with
    // the kernel's sigaction install.
    termios_signal::SAVED_FD.store(fd, Ordering::Release);

    let mut all_ok = true;
    // SAFETY: caller-owned `sigaction` structs, well-formed. The
    // handler we point at uses only async-signal-safe calls.
    unsafe {
        for (idx, &sig) in termios_signal::SIGNALS.iter().enumerate() {
            let mut sa: libc::sigaction = core::mem::zeroed();
            sa.sa_sigaction = termios_signal::handler as *const () as usize;
            // SA_RESETHAND: a second signal of the same type after
            // the first one's been handled gets the default
            // disposition — which is what we want, since we'll have
            // re-raised the signal at the end of the handler and the
            // default is "die with WIFSIGNALED set". Also avoids any
            // re-entrancy worry on the rare path where the handler
            // is interrupted by a second SIGINT.
            sa.sa_flags = libc::SA_RESETHAND;
            libc::sigemptyset(&mut sa.sa_mask);
            let prev_ptr = termios_signal::PREV_SIGACTIONS[idx].0.get();
            if libc::sigaction(sig, &sa, (*prev_ptr).as_mut_ptr()) != 0 {
                // Mark the slot as uninitialised so uninstall
                // doesn't try to restore garbage. We do this by
                // zero-initialising the prev — `sigaction(sig, prev, NULL)`
                // with a zeroed sigaction installs SIG_DFL, which is
                // the safest fallback for a signal we couldn't manage.
                (*prev_ptr).write(core::mem::zeroed());
                all_ok = false;
            }
        }
    }
    let _ = all_ok;
    true
}

/// Tear down the signal-safe restore handler installed by
/// [`install_signal_handler`]. Restores the previous `sigaction` for
/// each of SIGINT/SIGTERM/SIGHUP/SIGQUIT (which is `SIG_DFL` in the
/// common case where the process never installed its own), clears
/// the install slot, and zeros `SAVED_FD` so any stray late delivery
/// is a no-op.
#[cfg(unix)]
fn uninstall_signal_handler() {
    use core::sync::atomic::Ordering;
    // Reset SAVED_FD first: a signal racing with uninstall will see
    // -1 and skip the tcsetattr (the Drop guard runs the restore
    // synchronously right after this anyway). Release pairs with the
    // handler's Relaxed load.
    termios_signal::SAVED_FD.store(-1, Ordering::Release);
    // SAFETY: we own the install slot; only writer to these statics.
    unsafe {
        for (idx, &sig) in termios_signal::SIGNALS.iter().enumerate() {
            let prev_ptr = termios_signal::PREV_SIGACTIONS[idx].0.get();
            // The prev sigaction was either populated by a successful
            // sigaction() in install (real previous disposition) or
            // zeroed by install on failure (which restores SIG_DFL,
            // the safe fallback). Either way the buffer is valid to
            // hand back to sigaction().
            libc::sigaction(sig, (*prev_ptr).as_ptr(), core::ptr::null_mut());
        }
    }
    // Release the install slot last so any future install can
    // observe the cleared SAVED_FD via the Acquire CAS.
    termios_signal::INSTALLED.store(false, Ordering::Release);
}

/// Honour `$SSH_ASKPASS` when set: invoke the named helper, take its
/// first stdout line as the password. The helper conventionally takes
/// the prompt string as its sole argument. Returns `Ok(None)` if the
/// env var is unset.
fn try_ssh_askpass() -> std::io::Result<Option<Zeroizing<String>>> {
    let askpass = match std::env::var_os("SSH_ASKPASS") {
        Some(v) if !v.is_empty() => v,
        _ => return Ok(None),
    };
    // OpenSSH consults SSH_ASKPASS_REQUIRE: `force` -> always, `prefer`
    // -> always if SSH_ASKPASS is set, `never` -> never. We treat any
    // other value (including unset) as `prefer`, mirroring how the
    // helper is typically wired up.
    if let Some(req) = std::env::var_os("SSH_ASKPASS_REQUIRE") {
        if req == "never" {
            return Ok(None);
        }
    }
    let mut cmd = std::process::Command::new(askpass);
    cmd.arg("password: ");
    cmd.stdin(std::process::Stdio::null());
    cmd.stdout(std::process::Stdio::piped());
    cmd.stderr(std::process::Stdio::inherit());
    let out = match cmd.output() {
        Ok(o) => o,
        Err(_) => return Ok(None),
    };
    if !out.status.success() {
        return Ok(None);
    }
    // Take the first line, drop the trailing newline if present.
    let mut s = String::from_utf8_lossy(&out.stdout).into_owned();
    if let Some(idx) = s.find('\n') {
        s.truncate(idx);
    }
    if s.ends_with('\r') {
        s.pop();
    }
    Ok(Some(Zeroizing::new(s)))
}

/// Read an OpenSSH PEM identity file off disk and parse it. We refuse
/// passphrase-protected keys here (the bins don't have the prompting
/// infrastructure); users can pre-decrypt with `ssh-keygen -p`.
pub fn load_identity(path: &str) -> Result<PrivateKey, String> {
    let pem = std::fs::read_to_string(path).map_err(|e| format!("read {path}: {e}"))?;
    PrivateKey::parse_openssh_pem(&pem, None)
        .map_err(|e| format!("parse {path}: {e} (passphrase-protected keys not supported here)"))
}

/// Connect to `$SSH_AUTH_SOCK` (if set), list identities, and wrap each as a
/// publickey credential backed by [`AgentHostKey`]. Returns `Ok(empty)` when
/// no agent is reachable — that's an expected "no agent" state, not an
/// error.
///
/// On non-Unix platforms there is no `ssh-agent` to talk to (the
/// `puressh::agent` module is `cfg(unix)`); the function returns
/// `Ok(empty)` so callers can keep the "agent first, identity files
/// second" credential layering without platform checks.
#[cfg(unix)]
pub fn connect_agent_credentials() -> Result<Vec<ClientCredential>, String> {
    let agent = match Agent::connect_env().map_err(|e| format!("connect: {e}"))? {
        Some(a) => a,
        None => return Ok(Vec::new()),
    };
    let agent = Arc::new(Mutex::new(agent));
    let identities = {
        let mut a = agent
            .lock()
            .map_err(|_| "agent mutex poisoned".to_string())?;
        a.identities().map_err(|e| format!("identities: {e}"))?
    };
    let mut creds: Vec<ClientCredential> = Vec::with_capacity(identities.len());
    for ident in identities {
        match AgentHostKey::from_identity(Arc::clone(&agent), ident.key_blob.clone()) {
            Ok(hk) => creds.push(ClientCredential::PublicKey(Box::new(hk))),
            Err(e) => eprintln!(
                "warning: agent identity {:?}: skipping: {e}",
                ident.comment()
            ),
        }
    }
    Ok(creds)
}

/// Non-Unix stub: no `ssh-agent` to consult, so return an empty list.
#[cfg(not(unix))]
pub fn connect_agent_credentials() -> Result<Vec<ClientCredential>, String> {
    Ok(Vec::new())
}

/// Compute the user's default known_hosts path: `$HOME/.ssh/known_hosts`.
/// Returns `None` if `$HOME` is unset.
pub fn default_known_hosts_path() -> Option<PathBuf> {
    let home = std::env::var_os("HOME")?;
    Some(PathBuf::from(home).join(".ssh").join("known_hosts"))
}

/// SHA-256 fingerprint, base64-encoded (no padding), formatted as
/// `SHA256:<base64>` — matches `ssh-keygen -lf`.
pub fn fingerprint_b64_sha256(blob: &[u8]) -> String {
    use purecrypto::hash::{Digest, Sha256};
    let digest = Sha256::digest(blob);
    let s = base64_no_pad(digest.as_ref());
    format!("SHA256:{s}")
}

/// Standard base64 (RFC 4648 alphabet), no padding. Matches OpenSSH's
/// fingerprint encoding.
pub fn base64_no_pad(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    let mut i = 0;
    while i + 3 <= bytes.len() {
        let b = ((bytes[i] as u32) << 16) | ((bytes[i + 1] as u32) << 8) | (bytes[i + 2] as u32);
        out.push(ALPHABET[((b >> 18) & 0x3F) as usize] as char);
        out.push(ALPHABET[((b >> 12) & 0x3F) as usize] as char);
        out.push(ALPHABET[((b >> 6) & 0x3F) as usize] as char);
        out.push(ALPHABET[(b & 0x3F) as usize] as char);
        i += 3;
    }
    let rem = bytes.len() - i;
    if rem == 1 {
        let b = (bytes[i] as u32) << 16;
        out.push(ALPHABET[((b >> 18) & 0x3F) as usize] as char);
        out.push(ALPHABET[((b >> 12) & 0x3F) as usize] as char);
    } else if rem == 2 {
        let b = ((bytes[i] as u32) << 16) | ((bytes[i + 1] as u32) << 8);
        out.push(ALPHABET[((b >> 18) & 0x3F) as usize] as char);
        out.push(ALPHABET[((b >> 12) & 0x3F) as usize] as char);
        out.push(ALPHABET[((b >> 6) & 0x3F) as usize] as char);
    }
    out
}

/// The first-time / unknown-host TOFU prompt — mimics OpenSSH's
/// wording so muscle-memory ports. Returns `true` if the user answers
/// `yes` (or `y`), `false` otherwise (including on stdin EOF).
///
/// **Do not** reuse this for the mismatch path: a "yes" here is a
/// trust-on-first-use decision, not a "the key I trusted yesterday is
/// gone and I'm fine with that" decision. See [`tofu_mismatch_prompt`]
/// for the mismatch variant, which is preceded by the loud
/// `WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!` banner (emitted
/// by `client::build_verifier`) and requires the user to type `yes`
/// in full — no `y` shortcut.
pub fn tofu_prompt(host: &str, port: u16, key_type: &str, key_blob: &[u8]) -> bool {
    let fp = fingerprint_b64_sha256(key_blob);
    let target = if port == 22 {
        host.to_string()
    } else {
        format!("[{host}]:{port}")
    };
    eprintln!("The authenticity of host '{target}' can't be established.");
    eprintln!("{key_type} key fingerprint is {fp}.");
    eprint!("Are you sure you want to continue connecting (yes/no)? ");
    let _ = std::io::stderr().flush();
    let answer = read_short_stdin_line();
    matches!(answer.as_str(), "yes" | "y")
}

/// The mismatch TOFU prompt — used when the host IS already in
/// `known_hosts` but the key the server just presented does NOT match
/// any stored entry. The loud `WARNING: REMOTE HOST IDENTIFICATION
/// HAS CHANGED!` banner (with both old and new fingerprints) is
/// already printed by the verifier in `client::build_verifier` before
/// this function runs.
///
/// Compared to [`tofu_prompt`] this is intentionally more frictional:
///
/// - Default on empty input is **deny**, same as `tofu_prompt`, but
///   here it really matters — users have muscle-memory for hitting
///   Enter through TOFU prompts.
/// - The shortcut `y` is **not** accepted; the user must type `yes`
///   in full.
///
/// This matches OpenSSH's `StrictHostKeyChecking=ask` behaviour for
/// mismatches: refuse unless the user types something deliberate.
pub fn tofu_mismatch_prompt(host: &str, port: u16, key_type: &str, key_blob: &[u8]) -> bool {
    let fp = fingerprint_b64_sha256(key_blob);
    let target = if port == 22 {
        host.to_string()
    } else {
        format!("[{host}]:{port}")
    };
    eprintln!(
        "Host key verification for '{target}' FAILED: the {key_type} key the server presented \
         ({fp}) does not match any entry in your known_hosts file."
    );
    eprintln!(
        "If you are absolutely sure this is the new legitimate key for this host, type `yes` \
         to accept it and overwrite the trusted entry. Anything else (including just pressing \
         Enter) will refuse the connection."
    );
    eprint!("Accept the new key and replace the trusted entry (type `yes` to confirm)? ");
    let _ = std::io::stderr().flush();
    let answer = read_short_stdin_line();
    // Deliberately strict: `y` is NOT accepted, only the full word
    // `yes`. Forces the user to slow down past the muscle-memory point.
    answer == "yes"
}

/// Read a single short line from stdin, lowercase + trim it, and cap
/// at 16 bytes (longer answers are truncated since we only care about
/// `yes`/`no`/short variants). Returns an empty string on EOF.
fn read_short_stdin_line() -> String {
    let mut line = String::new();
    let mut byte = [0u8; 1];
    let mut stdin = std::io::stdin();
    while let Ok(n) = stdin.read(&mut byte) {
        if n == 0 || byte[0] == b'\n' {
            break;
        }
        if byte[0] == b'\r' {
            continue;
        }
        line.push(byte[0] as char);
        if line.len() > 16 {
            break;
        }
    }
    line.trim().to_ascii_lowercase()
}

/// Build the [`HostKeyPolicy`] for a given strict mode + optional override
/// path + hash-on-write flag. Every variant loads the known_hosts store —
/// even `StrictMode::No`, which mirrors OpenSSH's loud-but-tolerant
/// `StrictHostKeyChecking=no`: unknown hosts are accepted silently
/// (matching `accept-new`), but a *changed* key still triggers the
/// `WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!` banner before the
/// connection proceeds. Pre-2026 puressh degraded `No` to
/// `HostKeyPolicy::AcceptAny`, which dropped the mismatch warning on
/// the floor; that gap is the reason this helper now never returns
/// `AcceptAny`.
pub fn build_host_key_policy(
    strict: StrictMode,
    explicit_path: Option<PathBuf>,
    hash_known_hosts: bool,
) -> Result<HostKeyPolicy, String> {
    let path = match explicit_path {
        Some(p) => p,
        None => default_known_hosts_path()
            .ok_or_else(|| "no $HOME, cannot locate default known_hosts".to_string())?,
    };
    let store = KnownHosts::load(&path).map_err(|e| format!("load {}: {e}", path.display()))?;

    let (on_unknown, on_mismatch) = match strict {
        StrictMode::Yes => (TofuAction::Reject, TofuAction::Reject),
        // `accept-new` ONLY auto-accepts truly new hosts — never a
        // changed key. Mismatches still go through the strict
        // mismatch prompt so the user has a chance to see the loud
        // banner and explicitly accept (or, more likely, refuse).
        StrictMode::AcceptNew => (
            TofuAction::Accept,
            TofuAction::Prompt(Arc::new(tofu_mismatch_prompt)),
        ),
        StrictMode::Ask => (
            TofuAction::Prompt(Arc::new(tofu_prompt)),
            TofuAction::Prompt(Arc::new(tofu_mismatch_prompt)),
        ),
        // `No` mirrors OpenSSH: silently accept unknown, and proceed
        // on mismatch *with a very loud banner* (handled in
        // `client::build_verifier` via `TofuAction::AcceptWithWarning`).
        // The known_hosts file is still consulted but NOT mutated —
        // OpenSSH does the same: the warning is the deterrent, not a
        // silent key rotation.
        StrictMode::No => (TofuAction::Accept, TofuAction::AcceptWithWarning),
    };

    Ok(HostKeyPolicy::KnownHosts(KnownHostsPolicy {
        store: Arc::new(Mutex::new(store)),
        save_path: Some(path),
        hash_new: hash_known_hosts,
        on_unknown,
        on_mismatch,
    }))
}

/// Binary-local verbosity level (`-v` / `-vv` / `-vvv`). One copy per
/// binary because `common.rs` is `#[path]`-included rather than shared
/// as a crate — that's fine, since each binary's process only ever sees
/// its own.
///
/// Levels: 0 = silent (default), 1..=3 = OpenSSH-style debug1/2/3. Held
/// in an atomic so [`vlog`] callers don't need to thread a handle
/// through every helper (which would noisify every signature for a
/// debug aid).
static VERBOSE: AtomicU8 = AtomicU8::new(0);

/// Bump the binary-local verbosity to `level`, clamped to `0..=3`.
/// Idempotent; call once after `parse_args` returns.
pub fn set_verbose(level: u8) {
    VERBOSE.store(level.min(3), Ordering::Relaxed);
}

/// Current verbose level (0..=3). Cheap; safe to call on the hot path.
pub fn verbose_level() -> u8 {
    VERBOSE.load(Ordering::Relaxed)
}

/// Emit `"debug{level}: {msg}"` to stderr iff the current verbose
/// level is at least `level`. Mirrors OpenSSH's `debug1:` /
/// `debug2:` / `debug3:` prefix convention so users porting muscle
/// memory get the same shape of output.
///
/// `level` is clamped to `1..=3`; passing 0 means "always print" but
/// callers should just `eprintln!` directly in that case.
pub fn vlog(level: u8, msg: &str) {
    let level = level.clamp(1, 3);
    if VERBOSE.load(Ordering::Relaxed) >= level {
        eprintln!("debug{level}: {msg}");
    }
}

/// OpenSSH-style default identity paths under `$HOME/.ssh/`, in
/// preference order. Returns an empty vector when `$HOME` is unset
/// (no defaults to try, no error — callers fall back to the password
/// flow).
///
/// We deliberately omit:
///   - `id_dsa` — DSA is removed from modern OpenSSH defaults; our
///     key parser doesn't accept it.
///   - `id_ecdsa_sk`, `id_ed25519_sk` — FIDO/U2F security-key keys
///     need a hardware-token handshake (`sk-*` algorithms) that
///     puressh doesn't implement yet.
///
/// The returned paths are absolute and may not exist on disk; pair
/// each with [`try_load_default_identity`] which silently treats a
/// missing file as "skip".
pub fn default_identity_paths() -> Vec<PathBuf> {
    let Some(home) = std::env::var_os("HOME") else {
        return Vec::new();
    };
    let dot_ssh = PathBuf::from(home).join(".ssh");
    ["id_ed25519", "id_ecdsa", "id_rsa"]
        .iter()
        .map(|name| dot_ssh.join(name))
        .collect()
}

/// Load a default-discovery identity *silently*.
///
/// Returns:
///   - `Ok(None)` when the file is missing — that's the common case
///     for any default path the user doesn't actually have.
///   - `Ok(None)` when the file exists but is passphrase-protected
///     and we have no passphrase. OpenSSH prompts; for now we skip,
///     matching the explicit-`-i` policy in [`load_identity`] which
///     also refuses passphrase-protected keys. Distinguishes
///     "encrypted, no key material" from "broken file" via the
///     `Error::Crypto("passphrase required")` sentinel produced by
///     `PrivateKey::parse_openssh_pem`.
///   - `Ok(Some(_))` when the key parsed.
///   - `Err(_)` when the file exists but is malformed — surfaced
///     so the caller can warn once, since a broken default identity
///     is almost certainly a real misconfiguration the user wants
///     to know about.
pub fn try_load_default_identity(path: &Path) -> Result<Option<PrivateKey>, String> {
    let pem = match std::fs::read_to_string(path) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(format!("read {}: {e}", path.display())),
    };
    match PrivateKey::parse_openssh_pem(&pem, None) {
        Ok(pk) => Ok(Some(pk)),
        Err(Error::Crypto("passphrase required")) => Ok(None),
        Err(e) => Err(format!("parse {}: {e}", path.display())),
    }
}

// ---------------------------------------------------------------------------
// SSH config file discovery + loading
// ---------------------------------------------------------------------------

/// Load an `ssh_config(5)` for client binaries.
///
/// When `explicit` is `Some`, ONLY that file is parsed (matching OpenSSH's
/// `-F` behaviour). When `None`, both `~/.ssh/config` and
/// `/etc/ssh/ssh_config` are read in that order — the user file wins for
/// scalar options and both contribute to cumulative lists.
///
/// A missing file is silently skipped; the only error path is a file that
/// exists but won't parse.
pub fn load_client_config(
    explicit: Option<&Path>,
) -> Result<puressh::config::SshClientConfig, String> {
    use puressh::config::SshClientConfig;
    if let Some(path) = explicit {
        let src =
            std::fs::read_to_string(path).map_err(|e| format!("read {}: {e}", path.display()))?;
        return SshClientConfig::parse(&src).map_err(|e| format!("{}: {e}", path.display()));
    }
    // Default search path: user file first (wins), then system file. The
    // two are concatenated with a newline so block boundaries stay intact.
    let mut combined = String::new();
    if let Some(home) = std::env::var_os("HOME") {
        let user = PathBuf::from(home).join(".ssh").join("config");
        if let Ok(s) = std::fs::read_to_string(&user) {
            combined.push_str(&s);
            combined.push('\n');
        }
    }
    let system = Path::new("/etc/ssh/ssh_config");
    if let Ok(s) = std::fs::read_to_string(system) {
        combined.push_str(&s);
        combined.push('\n');
    }
    if combined.is_empty() {
        return Ok(SshClientConfig::default());
    }
    SshClientConfig::parse(&combined).map_err(|e| format!("ssh_config: {e}"))
}

/// Load an `sshd_config(5)` for the `sshd` binary. Returns an error if the
/// file is missing — server-side config is opt-in (`-f path`), so the caller
/// asked for this exact file.
pub fn load_server_config(path: &Path) -> Result<puressh::config::SshServerConfig, String> {
    let src = std::fs::read_to_string(path).map_err(|e| format!("read {}: {e}", path.display()))?;
    puressh::config::SshServerConfig::parse(&src).map_err(|e| format!("{}: {e}", path.display()))
}

/// OpenSSH precedence helper: returns the first `Some` of `cli`, `cfg`,
/// otherwise `default`. The standard scalar-option resolution pattern is
/// `pick(cli_flag, cfg_value, builtin_default)`.
pub fn pick<T>(cli: Option<T>, cfg: Option<T>, default: T) -> T {
    cli.or(cfg).unwrap_or(default)
}

/// Expand a leading `~/` or `~` in a config-supplied path to `$HOME`. Other
/// strings pass through verbatim. We deliberately do NOT expand `~user/` —
/// OpenSSH does, but our binaries don't currently consume cross-user paths.
pub fn expand_tilde(path: &str) -> String {
    if path == "~" {
        return std::env::var("HOME").unwrap_or_else(|_| "~".into());
    }
    if let Some(rest) = path.strip_prefix("~/") {
        if let Ok(home) = std::env::var("HOME") {
            return format!("{home}/{rest}");
        }
    }
    path.to_string()
}

#[cfg(test)]
mod target_tests {
    //! Cross-platform tests for the `[user@]host[:port]` and
    //! `[user@]host:path` CLI parsers. These don't need a tty so they're
    //! not gated to `cfg(unix)` (unlike the signal-handler tests below,
    //! which do).
    use super::*;

    #[test]
    fn parse_target_plain_host_no_port() {
        let (u, h, p) = parse_target("example.com").unwrap();
        assert_eq!(u, None);
        assert_eq!(h, "example.com");
        assert_eq!(p, None);
    }

    #[test]
    fn parse_target_user_at_host() {
        let (u, h, p) = parse_target("alice@example.com").unwrap();
        assert_eq!(u.as_deref(), Some("alice"));
        assert_eq!(h, "example.com");
        assert_eq!(p, None);
    }

    #[test]
    fn parse_target_host_with_port() {
        let (u, h, p) = parse_target("example.com:2222").unwrap();
        assert_eq!(u, None);
        assert_eq!(h, "example.com");
        assert_eq!(p, Some(2222));
    }

    #[test]
    fn parse_target_user_host_port() {
        let (u, h, p) = parse_target("alice@example.com:2222").unwrap();
        assert_eq!(u.as_deref(), Some("alice"));
        assert_eq!(h, "example.com");
        assert_eq!(p, Some(2222));
    }

    #[test]
    fn parse_target_bare_v6() {
        let (u, h, p) = parse_target("2001:db8::1").unwrap();
        assert_eq!(u, None);
        assert_eq!(h, "2001:db8::1");
        assert_eq!(p, None);
    }

    #[test]
    fn parse_target_bracketed_v6_with_port() {
        let (u, h, p) = parse_target("[2001:db8::1]:2222").unwrap();
        assert_eq!(u, None);
        assert_eq!(h, "2001:db8::1");
        assert_eq!(p, Some(2222));
    }

    #[test]
    fn parse_target_user_at_bracketed_v6() {
        let (u, h, p) = parse_target("alice@[2001:db8::1]:2222").unwrap();
        assert_eq!(u.as_deref(), Some("alice"));
        assert_eq!(h, "2001:db8::1");
        assert_eq!(p, Some(2222));
    }

    #[test]
    fn parse_target_user_at_bare_v6() {
        // Bare v6 after `user@` — the `@` split removes the user, then
        // parse_host_port sees the bare v6 and accepts it.
        let (u, h, p) = parse_target("alice@2001:db8::1").unwrap();
        assert_eq!(u.as_deref(), Some("alice"));
        assert_eq!(h, "2001:db8::1");
        assert_eq!(p, None);
    }

    #[test]
    fn parse_target_rejects_empty_host() {
        assert!(parse_target("alice@").is_err());
        assert!(parse_target("").is_err());
    }

    #[test]
    fn parse_target_rejects_unmatched_bracket() {
        assert!(parse_target("[2001:db8::1").is_err());
    }

    #[test]
    fn parse_userhost_path_plain() {
        let (u, h, p) = parse_userhost_path("alice@example.com:/etc/motd").unwrap();
        assert_eq!(u.as_deref(), Some("alice"));
        assert_eq!(h, "example.com");
        assert_eq!(p, "/etc/motd");
    }

    #[test]
    fn parse_userhost_path_no_user() {
        let (u, h, p) = parse_userhost_path("example.com:/etc/motd").unwrap();
        assert_eq!(u, None);
        assert_eq!(h, "example.com");
        assert_eq!(p, "/etc/motd");
    }

    #[test]
    fn parse_userhost_path_local_rejects_absolute() {
        // A bare absolute path is local, not remote.
        assert!(parse_userhost_path("/etc/motd").is_none());
    }

    #[test]
    fn parse_userhost_path_local_rejects_no_colon() {
        // No `:` -> local path.
        assert!(parse_userhost_path("relative/path").is_none());
    }

    #[test]
    fn parse_userhost_path_bracketed_v6() {
        let (u, h, p) = parse_userhost_path("[2001:db8::1]:/etc/motd").unwrap();
        assert_eq!(u, None);
        assert_eq!(h, "2001:db8::1");
        assert_eq!(p, "/etc/motd");
    }

    #[test]
    fn parse_userhost_path_user_at_bracketed_v6() {
        let (u, h, p) = parse_userhost_path("alice@[2001:db8::1]:/etc/motd").unwrap();
        assert_eq!(u.as_deref(), Some("alice"));
        assert_eq!(h, "2001:db8::1");
        assert_eq!(p, "/etc/motd");
    }

    #[test]
    fn parse_userhost_path_preserves_colons_in_path() {
        // Path may contain extra colons (Windows-style drive letters or
        // SCP-of-SCP-style nested targets); only the first separator is
        // used as the host/path boundary.
        let (u, h, p) = parse_userhost_path("host:/a:b:c").unwrap();
        assert_eq!(u, None);
        assert_eq!(h, "host");
        assert_eq!(p, "/a:b:c");
    }

    #[test]
    fn parse_userhost_path_bracketed_v6_path_with_colons() {
        let (u, h, p) = parse_userhost_path("[2001:db8::1]:/a:b").unwrap();
        assert_eq!(u, None);
        assert_eq!(h, "2001:db8::1");
        assert_eq!(p, "/a:b");
    }

    #[test]
    fn parse_userhost_path_bracketed_v6_unmatched_bracket() {
        assert!(parse_userhost_path("[2001:db8::1/path").is_none());
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use core::sync::atomic::Ordering;

    /// Read back the current `sigaction` for `sig` via `sigaction(NULL, prev)`.
    /// Returns the handler pointer value (`sa_sigaction`) — `0` is SIG_DFL,
    /// `1` is SIG_IGN, anything else is a function pointer.
    fn current_handler_ptr(sig: libc::c_int) -> usize {
        // SAFETY: passing NULL for the new disposition leaves the signal
        // alone; we only read the previous via the out param.
        unsafe {
            let mut prev: libc::sigaction = core::mem::zeroed();
            let rc = libc::sigaction(sig, core::ptr::null(), &mut prev);
            assert_eq!(rc, 0, "sigaction(read) failed");
            prev.sa_sigaction
        }
    }

    /// Install/uninstall the signal handler on its own (without going
    /// through `TermiosRawGuard::install`, which would also try to
    /// `tcsetattr` stdin — fine in cargo test where stdin is not a tty
    /// and the call is a silent no-op, but the bookkeeping is what we
    /// care about here).
    ///
    /// Asserts that:
    ///   1. After `install_signal_handler` returns true, the four signal
    ///      handlers point at our `termios_signal::handler`.
    ///   2. A second `install_signal_handler` call returns false (the
    ///      slot is already owned).
    ///   3. After `uninstall_signal_handler`, none of the four signals
    ///      still has *our* handler installed — they've reverted to
    ///      whatever was there before (typically SIG_DFL in the test
    ///      runner, though the test does not assert that exact value
    ///      because libtest is free to install its own dispositions).
    ///   4. A fresh `install_signal_handler` after the clean uninstall
    ///      succeeds.
    #[test]
    fn signal_handler_install_cycle_is_clean() {
        // Capture pre-install dispositions so we can assert the
        // uninstall path restored *something other than* our handler.
        let pre = [
            current_handler_ptr(libc::SIGINT),
            current_handler_ptr(libc::SIGTERM),
            current_handler_ptr(libc::SIGHUP),
            current_handler_ptr(libc::SIGQUIT),
        ];

        // SAFETY: zero-init is the documented way to allocate a termios
        // struct; we never call `tcsetattr` with it in this test, we
        // only stash a copy in the static.
        let original: libc::termios = unsafe { core::mem::zeroed() };

        // First install.
        let installed = install_signal_handler(0, &original);
        assert!(installed, "first install should succeed");
        assert!(
            termios_signal::INSTALLED.load(Ordering::Acquire),
            "INSTALLED must be true after first install"
        );
        let our_handler = termios_signal::handler as *const () as usize;
        for &sig in &termios_signal::SIGNALS {
            assert_eq!(
                current_handler_ptr(sig),
                our_handler,
                "signal {sig} should now point at our handler"
            );
        }

        // Second install must refuse (nested guard contract).
        let second = install_signal_handler(0, &original);
        assert!(!second, "second install while one is active must fail");

        // Uninstall.
        uninstall_signal_handler();
        assert!(
            !termios_signal::INSTALLED.load(Ordering::Acquire),
            "INSTALLED must be false after uninstall"
        );
        assert_eq!(
            termios_signal::SAVED_FD.load(Ordering::Acquire),
            -1,
            "SAVED_FD must be cleared after uninstall"
        );
        for (sig, &prev_ptr) in termios_signal::SIGNALS.iter().zip(pre.iter()) {
            let now = current_handler_ptr(*sig);
            assert_ne!(
                now, our_handler,
                "signal {sig} still points at our handler after uninstall"
            );
            assert_eq!(
                now, prev_ptr,
                "signal {sig} disposition was not restored to its pre-install value"
            );
        }

        // Fresh install after a clean uninstall must succeed.
        let reinstall = install_signal_handler(0, &original);
        assert!(reinstall, "fresh install after uninstall must succeed");
        uninstall_signal_handler();
    }
}
