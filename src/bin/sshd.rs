//! `sshd` — puressh's SSH server daemon.
//!
//! ```text
//! sshd [-d] [-p port] [-h host_key_file]... [-A authorized_keys_file]
//!      [-u allowed_user]...
//! ```

use std::collections::HashSet;
use std::process::{Command, ExitCode};
use std::sync::Arc;

use puressh::auth::{AuthAttempt, AuthDecision, Authenticator};
use puressh::hostkey::HostKey;
use puressh::key::{PrivateKey, PublicKey};
use puressh::server::{AuthenticatorFactory, CommandHandler, Config, ExecResult, Server};

const VERSION: &str = env!("CARGO_PKG_VERSION");

const USAGE: &str = "usage: sshd [-d] [-p port] [-h host_key_file]... \
                     [-A authorized_keys_file] [-u allowed_user]...";

struct Cli {
    port: u16,
    host_key_files: Vec<String>,
    authorized_keys_file: Option<String>,
    allowed_users: Vec<String>,
    debug: bool,
}

fn parse_args(args: &[String]) -> Result<Cli, String> {
    let mut port: u16 = 2222;
    let mut host_key_files: Vec<String> = Vec::new();
    let mut authorized_keys_file: Option<String> = None;
    let mut allowed_users: Vec<String> = Vec::new();
    let mut debug = false;

    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
        match a.as_str() {
            "-p" => {
                i += 1;
                let v = args.get(i).ok_or("-p requires a value")?;
                port = v.parse::<u16>().map_err(|_| "invalid port".to_string())?;
            }
            "-h" => {
                i += 1;
                let v = args.get(i).ok_or("-h requires a value")?.clone();
                host_key_files.push(v);
            }
            "-A" => {
                i += 1;
                let v = args.get(i).ok_or("-A requires a value")?.clone();
                authorized_keys_file = Some(v);
            }
            "-u" => {
                i += 1;
                let v = args.get(i).ok_or("-u requires a value")?.clone();
                allowed_users.push(v);
            }
            "-d" => debug = true,
            s if s.starts_with('-') => {
                return Err(format!("unknown flag: {s}"));
            }
            _ => return Err(format!("unexpected argument: {a}")),
        }
        i += 1;
    }

    if host_key_files.is_empty() {
        return Err("at least one -h host_key_file is required".into());
    }
    Ok(Cli {
        port,
        host_key_files,
        authorized_keys_file,
        allowed_users,
        debug,
    })
}

fn load_host_keys(paths: &[String]) -> Result<Vec<Box<dyn HostKey + Send + Sync>>, String> {
    let mut out: Vec<Box<dyn HostKey + Send + Sync>> = Vec::new();
    for path in paths {
        let pem = std::fs::read_to_string(path).map_err(|e| format!("read {path}: {e}"))?;
        let priv_key =
            PrivateKey::parse_openssh_pem(&pem, None).map_err(|e| format!("parse {path}: {e}"))?;
        let hk = priv_key
            .into_host_key()
            .map_err(|e| format!("convert {path}: {e}"))?;
        // PrivateKey::into_host_key returns `Box<dyn HostKey + Send>` —
        // upgrade to `Send + Sync` by wrapping. Our concrete signers (Ed25519,
        // ECDSA, RSA) hold only `Sync`-safe types internally; we expose this
        // via a small thunk that just defers to the boxed signer.
        out.push(SyncHostKey::wrap(hk));
    }
    Ok(out)
}

struct SyncHostKey {
    inner: std::sync::Mutex<Box<dyn HostKey + Send>>,
    algorithm: &'static str,
    blob: Vec<u8>,
}

impl SyncHostKey {
    fn wrap(hk: Box<dyn HostKey + Send>) -> Box<dyn HostKey + Send + Sync> {
        let algorithm_str = hk.algorithm();
        let blob = hk.public_blob();
        Box::new(SyncHostKey {
            algorithm: algorithm_str,
            blob,
            inner: std::sync::Mutex::new(hk),
        })
    }
}

impl HostKey for SyncHostKey {
    fn algorithm(&self) -> &'static str {
        self.algorithm
    }
    fn public_blob(&self) -> Vec<u8> {
        self.blob.clone()
    }
    fn sign(&self, msg: &[u8]) -> puressh::Result<Vec<u8>> {
        // The KEX path only signs once per handshake, so the mutex never
        // contends in the common case.
        let g = self
            .inner
            .lock()
            .map_err(|_| puressh::Error::Crypto("host-key mutex poisoned"))?;
        g.sign(msg)
    }
}

fn load_authorized_keys(path: &str) -> Result<Vec<PublicKey>, String> {
    let body = std::fs::read_to_string(path).map_err(|e| format!("read {path}: {e}"))?;
    let mut keys: Vec<PublicKey> = Vec::new();
    for (idx, line) in body.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        match PublicKey::parse_authorized_keys_line(trimmed) {
            Ok(k) => keys.push(k),
            Err(e) => {
                eprintln!("sshd: skipping authorized_keys line {}: {e}", idx + 1);
            }
        }
    }
    Ok(keys)
}

struct LocalAuthenticator {
    allowed_users: HashSet<String>,
    authorized_blobs: Vec<Vec<u8>>,
    debug: bool,
}

impl Authenticator for LocalAuthenticator {
    fn evaluate(&mut self, attempt: AuthAttempt) -> AuthDecision {
        match attempt {
            AuthAttempt::None { user } => {
                if self.debug {
                    eprintln!("sshd: auth none rejected for user {user}");
                }
                AuthDecision::Reject
            }
            AuthAttempt::Password { user, .. } => {
                if self.debug {
                    eprintln!("sshd: auth password rejected (not implemented) for user {user}");
                }
                AuthDecision::Reject
            }
            AuthAttempt::PublicKey {
                user,
                public_blob,
                probe_only,
                verified,
                ..
            } => {
                if !self.allowed_users.contains(&user) {
                    if self.debug {
                        eprintln!("sshd: auth publickey: user {user} not in allowed set");
                    }
                    return AuthDecision::Reject;
                }
                if !self.authorized_blobs.contains(&public_blob) {
                    if self.debug {
                        eprintln!("sshd: auth publickey: key not in authorized_keys");
                    }
                    return AuthDecision::Reject;
                }
                if probe_only {
                    return AuthDecision::Accept;
                }
                if !verified {
                    return AuthDecision::Reject;
                }
                if self.debug {
                    eprintln!("sshd: auth publickey: accepted user {user}");
                }
                AuthDecision::Accept
            }
            AuthAttempt::KeyboardInteractive { .. } => AuthDecision::Reject,
        }
    }
}

#[derive(Clone)]
struct LocalAuthFactory {
    allowed_users: Arc<HashSet<String>>,
    authorized_blobs: Arc<Vec<Vec<u8>>>,
    debug: bool,
}

impl AuthenticatorFactory for LocalAuthFactory {
    fn build(&self) -> Box<dyn Authenticator> {
        Box::new(LocalAuthenticator {
            allowed_users: (*self.allowed_users).clone(),
            authorized_blobs: (*self.authorized_blobs).clone(),
            debug: self.debug,
        })
    }
}

struct ShellCommandHandler {
    debug: bool,
}

impl CommandHandler for ShellCommandHandler {
    fn handle(&self, user: &str, command: &str) -> ExecResult {
        if self.debug {
            eprintln!("sshd: exec by {user}: {command}");
        }
        match Command::new("sh").args(["-c", command]).output() {
            Ok(out) => {
                let code = out.status.code().unwrap_or(255);
                let code_u32 = if code < 0 { 255u32 } else { code as u32 };
                ExecResult {
                    stdout: out.stdout,
                    stderr: out.stderr,
                    exit_status: code_u32,
                }
            }
            Err(e) => ExecResult {
                stdout: Vec::new(),
                stderr: format!("sshd: failed to spawn sh: {e}\n").into_bytes(),
                exit_status: 255,
            },
        }
    }
}

fn current_user() -> Result<String, String> {
    std::env::var("USER")
        .or_else(|_| std::env::var("LOGNAME"))
        .map_err(|_| "could not determine current user (set $USER)".into())
}

fn run() -> Result<i32, String> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.iter().any(|a| a == "-?" || a == "--help") {
        println!("{USAGE}");
        println!();
        println!("A pure-Rust SSH server daemon built on puressh {VERSION}.");
        return Ok(0);
    }
    if args.iter().any(|a| a == "-V" || a == "--version") {
        println!("puressh sshd {VERSION}");
        return Ok(0);
    }

    let cli = parse_args(&args).map_err(|e| format!("{e}\n{USAGE}"))?;

    let host_keys = load_host_keys(&cli.host_key_files)?;
    let authorized_blobs: Vec<Vec<u8>> = match &cli.authorized_keys_file {
        Some(path) => load_authorized_keys(path)?
            .into_iter()
            .map(|k| k.wire_blob())
            .collect(),
        None => Vec::new(),
    };

    let allowed_users: HashSet<String> = if cli.allowed_users.is_empty() {
        let u = current_user()?;
        let mut s = HashSet::new();
        s.insert(u);
        s
    } else {
        cli.allowed_users.iter().cloned().collect()
    };

    let factory = Arc::new(LocalAuthFactory {
        allowed_users: Arc::new(allowed_users),
        authorized_blobs: Arc::new(authorized_blobs),
        debug: cli.debug,
    });

    let cfg = Config::new(
        host_keys,
        factory,
        vec!["publickey"],
        Arc::new(ShellCommandHandler { debug: cli.debug }),
    );

    let addr = format!("127.0.0.1:{}", cli.port);
    let mut server = Server::bind(&addr, cfg).map_err(|e| format!("bind {addr}: {e}"))?;

    eprintln!("puressh sshd listening on {addr}");

    // Single-threaded accept loop bounded by the kernel — no in-process loop
    // limit needed; the kernel returns errors when the listener is closed.
    loop {
        match server.accept_one() {
            Ok(()) => {
                if cli.debug {
                    eprintln!("sshd: connection finished");
                }
            }
            Err(e) => {
                eprintln!("sshd: connection error: {e}");
            }
        }
    }
}

fn main() -> ExitCode {
    match run() {
        Ok(code) => {
            let clamped = code.clamp(0, 255) as u8;
            ExitCode::from(clamped)
        }
        Err(msg) => {
            eprintln!("sshd: {msg}");
            ExitCode::from(2)
        }
    }
}
