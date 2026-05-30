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
#[cfg(unix)]
pub struct TermiosRawGuard {
    fd: libc::c_int,
    original: libc::termios,
}

#[cfg(unix)]
impl TermiosRawGuard {
    /// Switch fd 0 into raw mode and return a guard that restores the
    /// passed-in `original` termios on drop. Best-effort: if the
    /// `tcsetattr` call fails (e.g. stdin isn't a tty after all), the
    /// returned guard still restores on drop — no observable effect
    /// in that case.
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
        TermiosRawGuard {
            fd,
            original: *original,
        }
    }
}

#[cfg(unix)]
impl Drop for TermiosRawGuard {
    fn drop(&mut self) {
        // SAFETY: same justification as `install` — we captured a
        // valid termios; the fd is stdin.
        unsafe {
            libc::tcsetattr(self.fd, libc::TCSANOW, &self.original);
        }
    }
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
