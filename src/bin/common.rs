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

use puressh::agent::{Agent, AgentHostKey};
use puressh::auth::ClientCredential;
use puressh::client::{HostKeyPolicy, KnownHostsPolicy, TofuAction};
use puressh::key::PrivateKey;
use puressh::known_hosts::KnownHosts;

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

/// Read a single line from stdin into a `String`. Used for password prompts;
/// echo is NOT suppressed because doing so portably requires a dependency
/// the lib doesn't carry. Documented in the help text.
pub fn read_password_from_stdin() -> std::io::Result<String> {
    eprint!("password: ");
    std::io::stderr().flush()?;
    let mut s = String::new();
    let mut byte = [0u8; 1];
    let mut stdin = std::io::stdin();
    loop {
        let n = stdin.read(&mut byte)?;
        if n == 0 {
            break;
        }
        if byte[0] == b'\n' {
            break;
        }
        if byte[0] == b'\r' {
            continue;
        }
        s.push(byte[0] as char);
        if s.len() > 4096 {
            break;
        }
    }
    Ok(s)
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
/// path + hash-on-write flag. With `StrictMode::No`, the policy is
/// [`HostKeyPolicy::AcceptAny`] (no known_hosts touched at all); otherwise
/// the file is loaded (or starts empty), and the action on Unknown depends
/// on the mode.
pub fn build_host_key_policy(
    strict: StrictMode,
    explicit_path: Option<PathBuf>,
    hash_known_hosts: bool,
) -> Result<HostKeyPolicy, String> {
    if strict == StrictMode::No {
        return Ok(HostKeyPolicy::AcceptAny);
    }

    let path = match explicit_path {
        Some(p) => p,
        None => default_known_hosts_path()
            .ok_or_else(|| "no $HOME, cannot locate default known_hosts".to_string())?,
    };
    let store = KnownHosts::load(&path).map_err(|e| format!("load {}: {e}", path.display()))?;

    let on_unknown = match strict {
        StrictMode::Yes => TofuAction::Reject,
        StrictMode::AcceptNew => TofuAction::Accept,
        StrictMode::Ask => TofuAction::Prompt(Arc::new(tofu_prompt)),
        StrictMode::No => unreachable!(),
    };

    Ok(HostKeyPolicy::KnownHosts(KnownHostsPolicy {
        store: Arc::new(Mutex::new(store)),
        save_path: Some(path),
        hash_new: hash_known_hosts,
        on_unknown,
    }))
}
