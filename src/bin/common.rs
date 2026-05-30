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

use std::io::{Read, Write};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

#[cfg(unix)]
use puressh::agent::{Agent, AgentHostKey};
use puressh::auth::ClientCredential;
use puressh::client::{HostKeyPolicy, KnownHostsPolicy, TofuAction};
use puressh::key::PrivateKey;
use puressh::known_hosts::KnownHosts;
use zeroize::Zeroizing;

/// Maps `StrictHostKeyChecking` modes to TOFU behaviour. Mirrors the
/// OpenSSH-ssh_config knob; the `ssh` binary parses `-o StrictHostKeyChecking=…`
/// straight into this enum.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StrictMode {
    /// `yes`: refuse Unknown; reject Mismatch.
    Yes,
    /// `no`: accept Unknown silently AND tolerate Mismatch (insecure).
    No,
    /// `accept-new`: silently accept Unknown; still reject Mismatch.
    AcceptNew,
    /// `ask` (OpenSSH default): prompt on Unknown; reject Mismatch.
    Ask,
}

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
/// last `@` — for an unadorned `host`, the user half is `None`.
pub fn parse_userhost(target: &str) -> (Option<String>, String) {
    match target.split_once('@') {
        Some((u, h)) => (Some(u.to_string()), h.to_string()),
        None => (None, target.to_string()),
    }
}

/// Split a `[user@]host:path` token used by `scp(1)` / `sftp(1)` local-or-
/// remote arguments. Returns `None` when there's no `:` — that signals a
/// plain local path. The user prefix is optional (as in `host:path`).
///
/// We deliberately accept colons in the path portion (after the first one)
/// to match OpenSSH's behaviour; the caller decides whether to refuse them.
pub fn parse_userhost_path(target: &str) -> Option<(Option<String>, String, String)> {
    // Refuse a bare absolute path (`/foo/bar:baz` is local, not remote).
    if target.starts_with('/') {
        return None;
    }
    let (head, path) = target.split_once(':')?;
    // A path token with no `@` and no `.` and no `/` in the head is
    // ambiguous; we treat anything before the first `:` as the host (with
    // optional `user@` prefix). This is OpenSSH's behaviour: `foo:bar` is
    // a remote copy.
    let (user, host) = parse_userhost(head);
    if host.is_empty() {
        return None;
    }
    Some((user, host, path.to_string()))
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

/// The TOFU prompt — mimics OpenSSH's wording so muscle-memory ports.
/// Returns `true` if the user answers "yes" (or "y"), `false` otherwise
/// (including on stdin EOF).
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
    matches!(line.trim().to_ascii_lowercase().as_str(), "yes" | "y")
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
        StrictMode::AcceptNew => (TofuAction::Accept, TofuAction::Reject),
        StrictMode::Ask => (
            TofuAction::Prompt(Arc::new(tofu_prompt)),
            TofuAction::Reject,
        ),
        // `No` mirrors OpenSSH: silently accept unknown, and proceed on
        // mismatch *with a very loud banner* (handled in
        // `client::build_verifier` via `TofuAction::AcceptWithWarning`).
        // The known_hosts file is still consulted/saved so the warning
        // can compare against the previously-stored fingerprint.
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
