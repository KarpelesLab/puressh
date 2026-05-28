//! `ssh` — puressh's SSH client driver.
//!
//! ```text
//! ssh [-p port] [-i identity_file] [-l user]
//!     [-o StrictHostKeyChecking={yes,no,accept-new,ask}]
//!     [-o UserKnownHostsFile=PATH]
//!     [-o HashKnownHosts={yes,no}]
//!     [-o IdentitiesOnly={yes,no}]
//!     [user@]host [command...]
//! ```

use std::io::{Read, Write};
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::{Arc, Mutex};

use puressh::agent::{Agent, AgentHostKey};
use puressh::auth::ClientCredential;
use puressh::client::{Client, Config, HostKeyPolicy, KnownHostsPolicy, TofuAction};
use puressh::key::PrivateKey;
use puressh::known_hosts::KnownHosts;

const VERSION: &str = env!("CARGO_PKG_VERSION");

const USAGE: &str = "usage: ssh [-p port] [-i identity_file] [-l user] \
                     [-o StrictHostKeyChecking={yes,no,accept-new,ask}] \
                     [-o UserKnownHostsFile=PATH] [-o HashKnownHosts={yes,no}] \
                     [-o IdentitiesOnly={yes,no}] \
                     [user@]host [command...]";

/// Maps `StrictHostKeyChecking` modes to TOFU behaviour.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum StrictMode {
    /// `yes`: refuse Unknown; reject Mismatch.
    Yes,
    /// `no`: accept Unknown silently AND tolerate Mismatch (insecure).
    No,
    /// `accept-new`: silently accept Unknown; still reject Mismatch.
    AcceptNew,
    /// `ask` (OpenSSH default): prompt on Unknown; reject Mismatch.
    Ask,
}

struct Cli {
    port: u16,
    identities: Vec<String>,
    cli_user: Option<String>,
    strict: StrictMode,
    known_hosts_path: Option<PathBuf>,
    hash_known_hosts: bool,
    identities_only: bool,
    host: String,
    user_in_host: Option<String>,
    command: Option<String>,
}

fn parse_args(args: &[String]) -> Result<Cli, String> {
    let mut port = 22u16;
    let mut identities: Vec<String> = Vec::new();
    let mut cli_user: Option<String> = None;
    let mut strict = StrictMode::Ask;
    let mut known_hosts_path: Option<PathBuf> = None;
    let mut hash_known_hosts = false;
    let mut identities_only = false;
    let mut positional: Vec<String> = Vec::new();

    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
        if a == "--" {
            positional.extend_from_slice(&args[i + 1..]);
            break;
        }
        match a.as_str() {
            "-p" => {
                i += 1;
                let v = args.get(i).ok_or("-p requires a value")?;
                port = v.parse::<u16>().map_err(|_| "invalid port".to_string())?;
            }
            "-i" => {
                i += 1;
                let v = args.get(i).ok_or("-i requires a value")?.clone();
                identities.push(v);
            }
            "-l" => {
                i += 1;
                let v = args.get(i).ok_or("-l requires a value")?.clone();
                cli_user = Some(v);
            }
            "-o" => {
                i += 1;
                let v = args.get(i).ok_or("-o requires a value")?;
                let (k, val) = v
                    .split_once('=')
                    .ok_or_else(|| format!("-o expects KEY=VALUE, got {v:?}"))?;
                match k.to_ascii_lowercase().as_str() {
                    "stricthostkeychecking" => {
                        strict = match val.to_ascii_lowercase().as_str() {
                            "yes" => StrictMode::Yes,
                            "no" | "off" => StrictMode::No,
                            "accept-new" => StrictMode::AcceptNew,
                            "ask" => StrictMode::Ask,
                            other => return Err(format!("unknown StrictHostKeyChecking={other}")),
                        };
                    }
                    "userknownhostsfile" => {
                        known_hosts_path = Some(PathBuf::from(val));
                    }
                    "hashknownhosts" => {
                        hash_known_hosts =
                            matches!(val.to_ascii_lowercase().as_str(), "yes" | "on");
                    }
                    "identitiesonly" => {
                        identities_only = matches!(val.to_ascii_lowercase().as_str(), "yes" | "on");
                    }
                    other => {
                        return Err(format!("unsupported -o option: {other}={val}"));
                    }
                }
            }
            s if s.starts_with('-') => {
                return Err(format!("unknown flag: {s}"));
            }
            _ => positional.push(a.clone()),
        }
        i += 1;
    }

    if positional.is_empty() {
        return Err("missing host argument".into());
    }
    let target = positional.remove(0);
    let (user_in_host, host) = match target.split_once('@') {
        Some((u, h)) => (Some(u.to_string()), h.to_string()),
        None => (None, target),
    };
    if host.is_empty() {
        return Err("empty host".into());
    }
    let command = if positional.is_empty() {
        None
    } else {
        Some(positional.join(" "))
    };

    Ok(Cli {
        port,
        identities,
        cli_user,
        strict,
        known_hosts_path,
        hash_known_hosts,
        identities_only,
        host,
        user_in_host,
        command,
    })
}

fn resolve_user(cli: &Cli) -> Result<String, String> {
    if let Some(u) = &cli.cli_user {
        return Ok(u.clone());
    }
    if let Some(u) = &cli.user_in_host {
        return Ok(u.clone());
    }
    std::env::var("USER").map_err(|_| "no user specified and $USER is unset".into())
}

fn read_password_from_stdin() -> std::io::Result<String> {
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

fn load_identity(path: &str) -> Result<PrivateKey, String> {
    let pem = std::fs::read_to_string(path).map_err(|e| format!("read {path}: {e}"))?;
    PrivateKey::parse_openssh_pem(&pem, None)
        .map_err(|e| format!("parse {path}: {e} (passphrase-protected keys not supported here)"))
}

/// Connect to `$SSH_AUTH_SOCK` (if set), list identities, and wrap each as a
/// publickey credential backed by [`AgentHostKey`]. Returns `Ok(empty)` when
/// no agent is reachable — that's an expected "no agent" state, not an
/// error.
fn connect_agent_credentials() -> Result<Vec<ClientCredential>, String> {
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
fn default_known_hosts_path() -> Option<PathBuf> {
    let home = std::env::var_os("HOME")?;
    Some(PathBuf::from(home).join(".ssh").join("known_hosts"))
}

/// SHA-256 fingerprint, base64-encoded (no padding), formatted as
/// `SHA256:<base64>` — matches `ssh-keygen -lf`.
fn fingerprint_b64_sha256(blob: &[u8]) -> String {
    use purecrypto::hash::{Digest, Sha256};
    let digest = Sha256::digest(blob);
    // Standard base64, no padding, as OpenSSH renders.
    let s = base64_no_pad(digest.as_ref());
    format!("SHA256:{s}")
}

fn base64_no_pad(bytes: &[u8]) -> String {
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

/// Build the [`HostKeyPolicy`] for the requested strict mode + path.
fn build_host_key_policy(cli: &Cli) -> Result<HostKeyPolicy, String> {
    // `StrictHostKeyChecking=no` is the historical OpenSSH "trust on every
    // connect" mode. We approximate it as AcceptAny since the user has
    // explicitly opted out of the check.
    if cli.strict == StrictMode::No {
        return Ok(HostKeyPolicy::AcceptAny);
    }

    let path = match &cli.known_hosts_path {
        Some(p) => p.clone(),
        None => default_known_hosts_path()
            .ok_or_else(|| "no $HOME, cannot locate default known_hosts".to_string())?,
    };
    let store = KnownHosts::load(&path).map_err(|e| format!("load {}: {e}", path.display()))?;

    let on_unknown = match cli.strict {
        StrictMode::Yes => TofuAction::Reject,
        StrictMode::AcceptNew => TofuAction::Accept,
        StrictMode::Ask => TofuAction::Prompt(Arc::new(tofu_prompt)),
        StrictMode::No => unreachable!(),
    };

    Ok(HostKeyPolicy::KnownHosts(KnownHostsPolicy {
        store: Arc::new(Mutex::new(store)),
        save_path: Some(path),
        hash_new: cli.hash_known_hosts,
        on_unknown,
    }))
}

/// The TOFU prompt — mimics OpenSSH's wording so muscle-memory ports.
fn tofu_prompt(host: &str, port: u16, key_type: &str, key_blob: &[u8]) -> bool {
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

fn run() -> Result<i32, String> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.iter().any(|a| a == "-h" || a == "--help") {
        println!("{USAGE}");
        println!();
        println!("A pure-Rust SSH client built on puressh {VERSION}.");
        return Ok(0);
    }
    if args.iter().any(|a| a == "-V" || a == "--version") {
        println!("puressh ssh {VERSION}");
        return Ok(0);
    }

    let cli = parse_args(&args).map_err(|e| format!("{e}\n{USAGE}"))?;
    let user = resolve_user(&cli)?;

    let policy = build_host_key_policy(&cli)?;
    let cfg = Config {
        host_key_policy: policy,
        timeout: None,
    };

    // Use connect_to_host so KnownHosts can look the host up by its
    // user-supplied name.
    let mut client = Client::connect_to_host(cli.host.as_str(), cli.port, cfg)
        .map_err(|e| format!("connect: {e}"))?;

    // Collect publickey credentials. Per OpenSSH default, agent identities
    // are tried first (when `$SSH_AUTH_SOCK` is set and `IdentitiesOnly=no`),
    // then `-i` identity files in command-line order.
    let mut credentials: Vec<ClientCredential> = Vec::new();
    if !cli.identities_only {
        match connect_agent_credentials() {
            Ok(mut from_agent) => credentials.append(&mut from_agent),
            Err(e) => eprintln!("warning: agent: {e}"),
        }
    }
    for id_path in &cli.identities {
        let pk = match load_identity(id_path) {
            Ok(p) => p,
            Err(e) => {
                eprintln!("warning: {e}");
                continue;
            }
        };
        match pk.into_host_key() {
            Ok(hk) => credentials.push(ClientCredential::PublicKey(hk)),
            Err(e) => eprintln!("warning: identity {id_path}: {e}"),
        }
    }

    let authed = if !credentials.is_empty() {
        match client.authenticate(&user, credentials) {
            Ok(()) => true,
            Err(e) => {
                eprintln!("publickey auth: {e}");
                false
            }
        }
    } else {
        false
    };

    if !authed {
        // v0 limitation: password input is echoed to the terminal — there is no
        // portable in-tree way to disable terminal echo without adding a dep.
        let password = read_password_from_stdin().map_err(|e| format!("read password: {e}"))?;
        client
            .authenticate_password(&user, &password)
            .map_err(|e| format!("Auth failed: {e}"))?;
    }

    let command = cli
        .command
        .ok_or_else(|| "interactive shell not yet implemented".to_string())?;

    let out = client.exec(&command).map_err(|e| format!("exec: {e}"))?;
    let _ = std::io::stdout().write_all(&out.stdout);
    let _ = std::io::stderr().write_all(&out.stderr);
    Ok(out.exit_status.map(|s| s as i32).unwrap_or(255))
}

fn main() -> ExitCode {
    match run() {
        Ok(code) => {
            let clamped = code.clamp(0, 255) as u8;
            ExitCode::from(clamped)
        }
        Err(msg) => {
            eprintln!("ssh: {msg}");
            ExitCode::from(255)
        }
    }
}
