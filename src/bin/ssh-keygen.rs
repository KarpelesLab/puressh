//! `ssh-keygen` — puressh's key-generation and key-inspection tool.
//!
//! ```text
//! ssh-keygen -t TYPE [-b BITS] [-N passphrase] [-C comment] -f path
//! ssh-keygen -l -f path[.pub]
//! ssh-keygen -y -f path [-N passphrase]
//! ssh-keygen -p -f path [-P old] -N new
//! ssh-keygen -R host [-f known_hosts_path]            (remove entries)
//! ssh-keygen -F host [-f known_hosts_path]            (find / print entries)
//! ssh-keygen -H [-f known_hosts_path]                 (hash all entries)
//! ```

use std::fs;
use std::io::{Read, Write};
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::process::ExitCode;

/// Open a file with `create_new` semantics, applying the requested Unix mode
/// when available. On non-Unix targets the mode is silently ignored (the
/// filesystem lacks the bits anyway).
fn open_create_new(path: &str, _mode: u32) -> std::io::Result<fs::File> {
    let mut opts = fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        opts.mode(_mode);
    }
    opts.open(path)
}

use purecrypto::rng::OsRng;
use puressh::key::{EcdsaCurve, PrivateKey, PublicKey};
use puressh::known_hosts::format::format_entry;
use puressh::known_hosts::KnownHosts;
use zeroize::Zeroizing;

const VERSION: &str = env!("CARGO_PKG_VERSION");

const USAGE: &str = "usage: ssh-keygen -t TYPE [-b BITS] [-N passphrase] [-C comment] -f path  (generate)\n       \
                     ssh-keygen -l -f path[.pub]                                          (fingerprint)\n       \
                     ssh-keygen -y -f path [-N passphrase]                                (extract public)\n       \
                     ssh-keygen -p -f path [-P old_passphrase] -N new_passphrase          (change passphrase)\n       \
                     ssh-keygen -R host [-f known_hosts_path]                             (remove host entries)\n       \
                     ssh-keygen -F host [-f known_hosts_path]                             (find host entries)\n       \
                     ssh-keygen -H [-f known_hosts_path]                                  (hash all entries)";

#[derive(Default)]
struct Args {
    type_: Option<String>,
    bits: Option<usize>,
    new_pass: Option<String>,
    new_pass_set: bool,
    old_pass: Option<String>,
    comment: Option<String>,
    file: Option<String>,
    fingerprint: bool,
    derive_pub: bool,
    change_pass: bool,
    /// `-R host`: remove every entry matching `host` from known_hosts.
    remove_host: Option<String>,
    /// `-F host`: find / print entries matching `host`.
    find_host: Option<String>,
    /// `-H`: hash every plain entry in the file in place.
    hash_all: bool,
    /// `-p` (in known_hosts mode means port — but ssh-keygen historically
    /// uses `host` directly; we accept `[host]:port` syntax via the
    /// pattern matcher instead and don't reuse `-p`).
    port: u16,
}

fn parse_args(args: &[String]) -> Result<Args, String> {
    let mut out = Args {
        port: 22,
        ..Args::default()
    };
    let mut i = 0;
    let max = args.len() + 1;
    let mut guard = 0;
    while i < args.len() {
        guard += 1;
        if guard > max {
            return Err("argument loop overflow".into());
        }
        let a = &args[i];
        match a.as_str() {
            "-t" => {
                i += 1;
                out.type_ = Some(args.get(i).ok_or("-t requires a value")?.clone());
            }
            "-b" => {
                i += 1;
                let v = args.get(i).ok_or("-b requires a value")?;
                out.bits = Some(
                    v.parse::<usize>()
                        .map_err(|_| "-b: bad number".to_string())?,
                );
            }
            "-N" => {
                // -N may be "" (empty passphrase); next arg is the value.
                i += 1;
                let v = args
                    .get(i)
                    .ok_or("-N requires a value (use \"\" for none)")?;
                out.new_pass = Some(v.clone());
                out.new_pass_set = true;
            }
            "-P" => {
                i += 1;
                let v = args.get(i).ok_or("-P requires a value")?;
                out.old_pass = Some(v.clone());
            }
            "-C" => {
                i += 1;
                out.comment = Some(args.get(i).ok_or("-C requires a value")?.clone());
            }
            "-f" => {
                i += 1;
                out.file = Some(args.get(i).ok_or("-f requires a value")?.clone());
            }
            "-l" => out.fingerprint = true,
            "-y" => out.derive_pub = true,
            "-p" => out.change_pass = true,
            "-R" => {
                i += 1;
                out.remove_host = Some(args.get(i).ok_or("-R requires a host")?.clone());
            }
            "-F" => {
                i += 1;
                out.find_host = Some(args.get(i).ok_or("-F requires a host")?.clone());
            }
            "-H" => out.hash_all = true,
            s if s.starts_with('-') => return Err(format!("unknown flag: {s}")),
            _ => return Err(format!("unexpected argument: {a}")),
        }
        i += 1;
    }
    Ok(out)
}

fn read_to_string(path: &str) -> Result<String, String> {
    fs::read_to_string(path).map_err(|e| format!("read {path}: {e}"))
}

fn write_private(path: &str, contents: &str) -> Result<(), String> {
    let p = Path::new(path);
    if let Some(parent) = p.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent).map_err(|e| format!("mkdir {parent:?}: {e}"))?;
        }
    }
    if p.exists() {
        return Err(format!("{path} already exists"));
    }
    let mut f = open_create_new(path, 0o600).map_err(|e| format!("open {path}: {e}"))?;
    f.write_all(contents.as_bytes())
        .map_err(|e| format!("write {path}: {e}"))?;
    Ok(())
}

fn write_public(path: &str, contents: &str) -> Result<(), String> {
    if Path::new(path).exists() {
        return Err(format!("{path} already exists"));
    }
    let mut f = open_create_new(path, 0o644).map_err(|e| format!("open {path}: {e}"))?;
    f.write_all(contents.as_bytes())
        .map_err(|e| format!("write {path}: {e}"))?;
    Ok(())
}

/// Prompt the user for a passphrase. Returns a [`Zeroizing<String>`] so
/// the buffer is wiped on drop; on Unix tty inputs the terminal echo
/// bit is cleared via `tcsetattr` and restored via a `Drop` guard,
/// matching OpenSSH ssh-keygen behaviour.
fn read_passphrase_interactive(prompt: &str) -> Result<Zeroizing<String>, String> {
    eprint!("{prompt}");
    let _ = std::io::stderr().flush();

    #[cfg(unix)]
    {
        if let Some(out) =
            read_passphrase_no_echo_unix().map_err(|e| format!("read passphrase: {e}"))?
        {
            return Ok(out);
        }
    }

    // Non-Unix or non-tty: announce the echo gap once, then read with echo.
    eprintln!();
    eprintln!("(warning: terminal echo could not be disabled; passphrase will be visible)");
    let mut s = String::new();
    let mut byte = [0u8; 1];
    let mut stdin = std::io::stdin();
    let max_len = 4096usize;
    loop {
        let n = stdin
            .read(&mut byte)
            .map_err(|e| format!("read passphrase: {e}"))?;
        if n == 0 || byte[0] == b'\n' {
            break;
        }
        if byte[0] == b'\r' {
            continue;
        }
        s.push(byte[0] as char);
        if s.len() > max_len {
            break;
        }
    }
    Ok(Zeroizing::new(s))
}

#[cfg(unix)]
fn read_passphrase_no_echo_unix() -> std::io::Result<Option<Zeroizing<String>>> {
    use std::os::unix::io::AsRawFd;
    let fd = std::io::stdin().as_raw_fd();
    // SAFETY: zero-init is the documented way to allocate termios.
    let mut term: libc::termios = unsafe { core::mem::zeroed() };
    // SAFETY: fd valid (stdin), term writable.
    if unsafe { libc::tcgetattr(fd, &mut term as *mut _) } != 0 {
        return Ok(None);
    }
    let original = term;

    struct EchoGuard {
        fd: libc::c_int,
        original: libc::termios,
    }
    impl Drop for EchoGuard {
        fn drop(&mut self) {
            // SAFETY: original captured from a successful tcgetattr.
            unsafe { libc::tcsetattr(self.fd, libc::TCSANOW, &self.original) };
        }
    }

    term.c_lflag &= !libc::ECHO;
    // SAFETY: term valid (derived via tcgetattr).
    if unsafe { libc::tcsetattr(fd, libc::TCSANOW, &term) } != 0 {
        return Ok(None);
    }
    let _guard = EchoGuard { fd, original };

    let mut s = String::new();
    let mut byte = [0u8; 1];
    let mut stdin = std::io::stdin();
    let max_len = 4096usize;
    loop {
        let n = stdin.read(&mut byte)?;
        if n == 0 || byte[0] == b'\n' {
            break;
        }
        if byte[0] == b'\r' {
            continue;
        }
        s.push(byte[0] as char);
        if s.len() > max_len {
            break;
        }
    }
    eprintln!();
    Ok(Some(Zeroizing::new(s)))
}

fn algorithm_label(pk: &PublicKey) -> &'static str {
    match pk {
        PublicKey::Ed25519 { .. } => "ED25519",
        PublicKey::EcdsaP256 { .. } => "ECDSA",
        PublicKey::EcdsaP384 { .. } => "ECDSA",
        PublicKey::EcdsaP521 { .. } => "ECDSA",
        PublicKey::Rsa { .. } => "RSA",
    }
}

fn load_public(path: &str) -> Result<PublicKey, String> {
    let text = read_to_string(path)?;
    // Try authorized_keys/.pub line first.
    if let Ok(p) = PublicKey::parse_authorized_keys_line(text.trim()) {
        return Ok(p);
    }
    // Fall back: maybe a private key was passed.
    let pk = PrivateKey::parse_openssh_pem(&text, None).map_err(|e| {
        format!("{path}: not a public key line and not an unencrypted private key ({e})")
    })?;
    Ok(pk.public_key())
}

fn ensure_file_in(file: &Option<String>) -> Result<String, String> {
    file.clone().ok_or_else(|| "-f is required".into())
}

fn run_generate(args: &Args) -> Result<i32, String> {
    let file = ensure_file_in(&args.file)?;
    let pub_path = format!("{file}.pub");
    let ty = args
        .type_
        .as_deref()
        .ok_or("-t TYPE is required for generation")?
        .to_lowercase();

    let comment = args
        .comment
        .clone()
        .unwrap_or_else(|| match std::env::var("USER") {
            Ok(u) => format!("{u}@puressh"),
            Err(_) => "puressh".into(),
        });

    let mut rng = OsRng;
    let sk = match ty.as_str() {
        "ed25519" => PrivateKey::generate_ed25519(&mut rng, comment),
        "ecdsa" => {
            let bits = args.bits.unwrap_or(256);
            let curve = match bits {
                256 => EcdsaCurve::P256,
                384 => EcdsaCurve::P384,
                521 => EcdsaCurve::P521,
                _ => {
                    return Err(format!(
                        "ecdsa: unsupported bit length {bits} (256|384|521)"
                    ))
                }
            };
            PrivateKey::generate_ecdsa(&mut rng, curve, comment)
        }
        "rsa" => {
            let bits = args.bits.unwrap_or(3072);
            PrivateKey::generate_rsa(&mut rng, bits, comment)
                .map_err(|e| format!("rsa generation: {e}"))?
        }
        other => return Err(format!("unsupported key type: {other}")),
    };

    let passphrase = args.new_pass.as_deref().filter(|p| !p.is_empty());
    let pem = sk
        .to_openssh_pem(passphrase.map(|s| s.as_bytes()))
        .map_err(|e| format!("encode: {e}"))?;

    let pub_line = sk.public_key().to_authorized_keys_line();
    let mut pub_full = pub_line;
    pub_full.push('\n');

    write_private(&file, &pem)?;
    write_public(&pub_path, &pub_full)?;

    let fp = sk.public_key().sha256_fingerprint();
    println!("Your identification has been saved in {file}");
    println!("Your public key has been saved in {pub_path}");
    println!("The key fingerprint is:");
    println!("{fp} {}", sk.public_key().comment());
    Ok(0)
}

fn run_fingerprint(args: &Args) -> Result<i32, String> {
    let file = ensure_file_in(&args.file)?;
    // Accept either a .pub line, an authorized_keys line, or a private key.
    let pk = load_public(&file)?;
    let fp = pk.sha256_fingerprint();
    let bits = pk.bit_length();
    let comment = pk.comment();
    let comment = if comment.is_empty() {
        "no comment"
    } else {
        comment
    };
    let label = algorithm_label(&pk);
    println!("{bits} {fp} {comment} ({label})");
    Ok(0)
}

fn run_extract_public(args: &Args) -> Result<i32, String> {
    let file = ensure_file_in(&args.file)?;
    let text = read_to_string(&file)?;
    let pem_pass = args.new_pass.as_deref().filter(|p| !p.is_empty());
    let sk = match PrivateKey::parse_openssh_pem(&text, pem_pass.map(|s| s.as_bytes())) {
        Ok(sk) => sk,
        Err(_) if pem_pass.is_none() => {
            let pp = read_passphrase_interactive("Enter passphrase: ")?;
            PrivateKey::parse_openssh_pem(
                &text,
                if pp.is_empty() {
                    None
                } else {
                    Some(pp.as_bytes())
                },
            )
            .map_err(|e| format!("parse {file}: {e}"))?
        }
        Err(e) => return Err(format!("parse {file}: {e}")),
    };
    let pub_line = sk.public_key().to_authorized_keys_line();
    println!("{pub_line}");
    Ok(0)
}

fn run_change_passphrase(args: &Args) -> Result<i32, String> {
    let file = ensure_file_in(&args.file)?;
    let text = read_to_string(&file)?;
    let old_pass = args.old_pass.as_deref().filter(|p| !p.is_empty());
    let sk = match PrivateKey::parse_openssh_pem(&text, old_pass.map(|s| s.as_bytes())) {
        Ok(sk) => sk,
        Err(_) if old_pass.is_none() => {
            let pp = read_passphrase_interactive("Enter old passphrase: ")?;
            PrivateKey::parse_openssh_pem(
                &text,
                if pp.is_empty() {
                    None
                } else {
                    Some(pp.as_bytes())
                },
            )
            .map_err(|e| format!("parse {file}: {e}"))?
        }
        Err(e) => return Err(format!("parse {file}: {e}")),
    };

    let new_pass: Zeroizing<String> = if args.new_pass_set {
        Zeroizing::new(args.new_pass.clone().unwrap_or_default())
    } else {
        read_passphrase_interactive("Enter new passphrase: ")?
    };

    let pem = sk
        .to_openssh_pem(if new_pass.is_empty() {
            None
        } else {
            Some(new_pass.as_bytes())
        })
        .map_err(|e| format!("encode: {e}"))?;

    let tmp = format!("{file}.tmp");
    if Path::new(&tmp).exists() {
        let _ = fs::remove_file(&tmp);
    }
    {
        let mut f = open_create_new(&tmp, 0o600).map_err(|e| format!("open {tmp}: {e}"))?;
        f.write_all(pem.as_bytes())
            .map_err(|e| format!("write {tmp}: {e}"))?;
    }
    fs::rename(&tmp, &file).map_err(|e| format!("rename {tmp} -> {file}: {e}"))?;
    println!("Your identification has been updated.");
    Ok(0)
}

/// Resolve `-f`, falling back to `$HOME/.ssh/known_hosts` for the
/// `-R`/`-F`/`-H` modes (matching OpenSSH).
fn resolve_known_hosts_path(args: &Args) -> Result<String, String> {
    if let Some(f) = &args.file {
        return Ok(f.clone());
    }
    let home = std::env::var("HOME").map_err(|_| {
        "no -f given and $HOME is unset; cannot locate default known_hosts".to_string()
    })?;
    Ok(format!("{home}/.ssh/known_hosts"))
}

fn run_known_hosts_remove(args: &Args, host: &str) -> Result<i32, String> {
    let path = resolve_known_hosts_path(args)?;
    let mut kh = KnownHosts::load(&path).map_err(|e| format!("load {path}: {e}"))?;
    let removed = kh.remove(host, args.port);
    if removed == 0 {
        eprintln!("ssh-keygen: no matching entries found in {path}");
        return Ok(1);
    }
    kh.save(&path).map_err(|e| format!("save {path}: {e}"))?;
    println!("# Host {host} found: line(s) removed: {removed}");
    println!("# Updated {path}");
    Ok(0)
}

fn run_known_hosts_find(args: &Args, host: &str) -> Result<i32, String> {
    let path = resolve_known_hosts_path(args)?;
    let kh = KnownHosts::load(&path).map_err(|e| format!("load {path}: {e}"))?;
    let matches = kh.find(host, args.port);
    if matches.is_empty() {
        // OpenSSH exits 1 with no output when nothing matches.
        return Ok(1);
    }
    println!("# Host {host} found: line(s): {}", matches.len());
    for entry in matches {
        println!("{}", format_entry(entry));
    }
    Ok(0)
}

fn run_known_hosts_hash(args: &Args) -> Result<i32, String> {
    let path = resolve_known_hosts_path(args)?;
    let mut kh = KnownHosts::load(&path).map_err(|e| format!("load {path}: {e}"))?;
    kh.hash_in_place();
    kh.save(&path).map_err(|e| format!("save {path}: {e}"))?;
    println!("# Hashed {path}");
    Ok(0)
}

fn run() -> Result<i32, i32> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.iter().any(|a| a == "-h" || a == "--help") {
        println!("{USAGE}");
        println!("\nA pure-Rust ssh-keygen built on puressh {VERSION}.");
        return Ok(0);
    }
    if args.iter().any(|a| a == "-V" || a == "--version") {
        println!("puressh ssh-keygen {VERSION}");
        return Ok(0);
    }

    let parsed = match parse_args(&args) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("ssh-keygen: {e}");
            eprintln!("{USAGE}");
            return Err(2);
        }
    };

    let mode_count = [
        parsed.fingerprint as u8,
        parsed.derive_pub as u8,
        parsed.change_pass as u8,
        parsed.type_.is_some() as u8,
        parsed.remove_host.is_some() as u8,
        parsed.find_host.is_some() as u8,
        parsed.hash_all as u8,
    ]
    .iter()
    .sum::<u8>();
    if mode_count == 0 {
        eprintln!("{USAGE}");
        return Err(2);
    }
    if mode_count > 1 {
        eprintln!("ssh-keygen: -t / -l / -y / -p / -R / -F / -H are mutually exclusive");
        return Err(2);
    }

    let res = if parsed.fingerprint {
        run_fingerprint(&parsed)
    } else if parsed.derive_pub {
        run_extract_public(&parsed)
    } else if parsed.change_pass {
        run_change_passphrase(&parsed)
    } else if let Some(host) = &parsed.remove_host {
        run_known_hosts_remove(&parsed, host)
    } else if let Some(host) = &parsed.find_host {
        run_known_hosts_find(&parsed, host)
    } else if parsed.hash_all {
        run_known_hosts_hash(&parsed)
    } else {
        run_generate(&parsed)
    };

    match res {
        Ok(code) => Ok(code),
        Err(msg) => {
            eprintln!("ssh-keygen: {msg}");
            let lower = msg.to_lowercase();
            let crypto = lower.contains("passphrase")
                || lower.contains("signature")
                || lower.contains("crypto")
                || lower.contains("bcrypt")
                || lower.contains("decrypt")
                || lower.contains("encode");
            Err(if crypto { 3 } else { 1 })
        }
    }
}

fn main() -> ExitCode {
    match run() {
        Ok(code) => {
            let clamped = code.clamp(0, 255) as u8;
            ExitCode::from(clamped)
        }
        Err(code) => {
            let clamped = code.clamp(0, 255) as u8;
            ExitCode::from(clamped)
        }
    }
}
