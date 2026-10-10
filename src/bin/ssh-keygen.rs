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
//! ssh-keygen -s ca_key -I id [-h] [-U] [-n principals] [-O option] [-V interval] [-z serial] file ...
//! ssh-keygen -L -f cert_file                           (print a certificate)
//! ssh-keygen -Y sign -f key_file -n namespace [-U] [-O option] file ...
//! ssh-keygen -Y verify -f allowed_signers -I principal -n namespace -s sig_file
//! ssh-keygen -Y find-principals -f allowed_signers -s sig_file
//! ssh-keygen -Y match-principals -f allowed_signers -I principal
//! ssh-keygen -Y check-novalidate -n namespace -s sig_file
//! ```

use std::fs;
use std::io::{Read, Write};
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::process::ExitCode;

use purecrypto::rng::{OsRng, RngCore};
use puressh::key::{EcdsaCurve, PrivateKey, PublicKey};
use puressh::known_hosts::KnownHosts;
use puressh::known_hosts::format_entry;
use zeroize::Zeroizing;

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

/// Build a per-call unique temporary path next to `path`. The suffix
/// combines the process id and a fresh `u64` from `OsRng`, so two
/// concurrent invocations cannot collide on the same tmp name and an
/// attacker with write access to the directory cannot pre-create the
/// tmp path as a symlink. Pair with `open_create_new` for O_EXCL.
fn unique_tmp_path(path: &str) -> String {
    let mut rng = OsRng;
    let mut nonce = [0u8; 8];
    rng.fill_bytes(&mut nonce);
    let nonce = u64::from_le_bytes(nonce);
    let pid = std::process::id();
    let p = Path::new(path);
    let file_name = p
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("ssh-keygen");
    let tmp_name = format!(".{file_name}.tmp.{pid}.{nonce:016x}");
    match p.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => {
            parent.join(tmp_name).to_string_lossy().into_owned()
        }
        _ => tmp_name,
    }
}

const VERSION: &str = env!("CARGO_PKG_VERSION");

const USAGE: &str = "usage: ssh-keygen -t TYPE [-b BITS] [-N passphrase] [-C comment] -f path  (generate)\n       \
                     ssh-keygen -l -f path[.pub]                                          (fingerprint)\n       \
                     ssh-keygen -y -f path [-N passphrase]                                (extract public)\n       \
                     ssh-keygen -p -f path [-P old_passphrase] -N new_passphrase          (change passphrase)\n       \
                     ssh-keygen -R host [-f known_hosts_path]                             (remove host entries)\n       \
                     ssh-keygen -F host [-f known_hosts_path]                             (find host entries)\n       \
                     ssh-keygen -H [-f known_hosts_path]                                  (hash all entries)\n       \
                     ssh-keygen -A [-f prefix] [-q]                                       (create missing host keys)\n       \
                     ssh-keygen -s ca_key -I certificate_identity [-h] [-U] [-n principals]\n                  \
                     [-O option] [-V validity_interval] [-z serial_number] file ...\n       \
                     ssh-keygen -L [-f input_keyfile]\n       \
                     ssh-keygen -Y sign -f key_file -n namespace [-U] [-O option] file ...\n       \
                     ssh-keygen -Y verify -f allowed_signers_file -I signer_identity\n                  \
                     -n namespace -s signature_file [-O option]\n       \
                     ssh-keygen -Y find-principals -f allowed_signers_file -s signature_file\n       \
                     ssh-keygen -Y match-principals -f allowed_signers_file -I signer_identity\n       \
                     ssh-keygen -Y check-novalidate -n namespace -s signature_file";

#[derive(Default)]
struct Args {
    type_: Option<String>,
    bits: Option<usize>,
    /// `-N`: new passphrase. `Zeroizing` so the copy taken off argv is
    /// wiped on drop (argv itself is the kernel's; we can't help that).
    new_pass: Option<Zeroizing<String>>,
    new_pass_set: bool,
    /// `-P`: old passphrase (see `new_pass`).
    old_pass: Option<Zeroizing<String>>,
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
    /// `-A`: create every missing default host key (`-f` is then a root
    /// prefix, as in OpenSSH).
    host_keys: bool,
    /// `-q`: quiet.
    quiet: bool,
    /// `-Y op`: SSH signature operation (`sign`, `verify`, …).
    sig_op: Option<String>,
    /// `-n`: signature namespace.
    namespace: Option<String>,
    /// `-I`: signer identity (principal).
    identity: Option<String>,
    /// `-s`: signature file.
    sig_file: Option<String>,
    /// `-O`: options (`hashalg=`, `verify-time=`, `print-pubkey`).
    sig_options: Vec<String>,
    /// `-U`: the key is in the agent.
    use_agent: bool,
    /// Positional arguments (files to sign).
    rest: Vec<String>,
    /// `-h`: sign a host certificate.
    host_cert: bool,
    /// `-V`: certificate validity interval.
    validity: Option<String>,
    /// `-z`: certificate serial number.
    serial: Option<String>,
    /// `-L`: print certificate contents.
    list_cert: bool,
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
        // `-Ovalue` / `-nvalue` etc.: the value attached to the flag.
        if a.len() > 2
            && let Some(v) = a.strip_prefix("-O")
        {
            out.sig_options.push(v.to_string());
            i += 1;
            continue;
        }
        match a.as_str() {
            "-Y" => {
                i += 1;
                out.sig_op = Some(args.get(i).ok_or("-Y requires an operation")?.clone());
            }
            "-n" => {
                i += 1;
                out.namespace = Some(args.get(i).ok_or("-n requires a namespace")?.clone());
            }
            "-I" => {
                i += 1;
                out.identity = Some(args.get(i).ok_or("-I requires an identity")?.clone());
            }
            "-s" => {
                i += 1;
                out.sig_file = Some(args.get(i).ok_or("-s requires a file")?.clone());
            }
            "-O" => {
                i += 1;
                out.sig_options
                    .push(args.get(i).ok_or("-O requires an option")?.clone());
            }
            "-U" => out.use_agent = true,
            "-h" => out.host_cert = true,
            "-L" => out.list_cert = true,
            "-V" => {
                i += 1;
                out.validity = Some(args.get(i).ok_or("-V requires an interval")?.clone());
            }
            "-z" => {
                i += 1;
                out.serial = Some(args.get(i).ok_or("-z requires a serial number")?.clone());
            }
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
                out.new_pass = Some(Zeroizing::new(v.clone()));
                out.new_pass_set = true;
            }
            "-P" => {
                i += 1;
                let v = args.get(i).ok_or("-P requires a value")?;
                out.old_pass = Some(Zeroizing::new(v.clone()));
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
            "-A" => out.host_keys = true,
            "-q" => out.quiet = true,
            "-" => out.rest.push(a.clone()),
            s if s.starts_with('-') => return Err(format!("unknown flag: {s}")),
            _ => out.rest.push(a.clone()),
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
    if let Some(parent) = p.parent()
        && !parent.as_os_str().is_empty()
    {
        // Detect whether `parent` already existed so we know whether
        // we are responsible for tightening its mode. We only touch
        // the leaf directory we just created — never anything we
        // inherit from the user (e.g. $HOME).
        let existed_before = parent.exists();
        fs::create_dir_all(parent).map_err(|e| format!("mkdir {parent:?}: {e}"))?;
        #[cfg(unix)]
        {
            if !existed_before {
                use std::os::unix::fs::PermissionsExt as _;
                // 0o700 matches OpenSSH's expectation for ~/.ssh:
                // owner-only traversal so directory listings (and
                // therefore the set of identities present) cannot
                // be enumerated by other local users.
                let _ = fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700));
            }
        }
        #[cfg(not(unix))]
        {
            let _ = existed_before; // silence unused warning
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

/// Ask for a *new* passphrase the way `ssh-keygen(1)` does: prompt, then
/// `Enter same passphrase again:`, and loop until the two match. An empty
/// passphrase (twice) means "unencrypted".
///
/// Without a terminal on stdin there is nothing to ask — return the empty
/// passphrase so the key is written unencrypted, which is what OpenSSH does
/// when `-N` is absent and no tty is available. We never read a passphrase
/// off a redirected stdin.
fn read_new_passphrase_confirmed(prompt: &str) -> Result<Zeroizing<String>, String> {
    use std::io::IsTerminal;
    if !std::io::stdin().is_terminal() {
        return Ok(Zeroizing::new(String::new()));
    }
    loop {
        let first = read_passphrase_interactive(prompt)?;
        let second = read_passphrase_interactive("Enter same passphrase again: ")?;
        if first == second {
            return Ok(first);
        }
        eprintln!("Passphrases do not match.  Try again.");
    }
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
        // A key family added to the library after this binary was written.
        _ => "UNKNOWN",
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
                    ));
                }
            };
            PrivateKey::generate_ecdsa(&mut rng, curve, comment)
        }
        "rsa" => {
            let bits = args.bits.unwrap_or(3072);
            // OpenSSH refuses RSA keys below 1024 bits and recommends at
            // least 2048; enforce a 2048-bit floor so a too-small `-b` can't
            // produce a weak key.
            if bits < 2048 {
                return Err("RSA key size must be at least 2048 bits".to_string());
            }
            PrivateKey::generate_rsa(&mut rng, bits, comment)
                .map_err(|e| format!("rsa generation: {e}"))?
        }
        other => return Err(format!("unsupported key type: {other}")),
    };

    // `-N` given ⇒ use it verbatim (empty ⇒ unencrypted). Otherwise ask on
    // the terminal, twice, like OpenSSH; with no terminal the key is written
    // unencrypted (OpenSSH behaviour) rather than reading a passphrase off
    // a redirected stdin.
    let passphrase: Zeroizing<String> = if args.new_pass_set {
        args.new_pass.clone().unwrap_or_default()
    } else {
        read_new_passphrase_confirmed("Enter passphrase (empty for no passphrase): ")?
    };
    let pem = sk
        .to_openssh_pem(if passphrase.is_empty() {
            None
        } else {
            Some(passphrase.as_bytes())
        })
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

/// `ssh-keygen -A`: for each default host key type (RSA 3072, ECDSA P-256,
/// Ed25519) whose private key does not exist under `<prefix>/etc/ssh`,
/// generate one, unencrypted, commented `root@<hostname>`. Each key is
/// written to a temporary name and renamed into place, so a crash never
/// leaves a half-written key. Existing keys are never touched.
fn run_host_keys(args: &Args) -> Result<i32, String> {
    let prefix = args.file.clone().unwrap_or_default();
    let dir = format!("{}/etc/ssh", prefix.trim_end_matches('/'));
    let host = fs::read_to_string("/proc/sys/kernel/hostname")
        .or_else(|_| fs::read_to_string("/etc/hostname"))
        .map(|h| h.trim().to_string())
        .ok()
        .filter(|h| !h.is_empty())
        .unwrap_or_else(|| "localhost".into());
    let comment = format!("root@{host}");
    // Like OpenSSH: the directory is created world-readable (0755 under
    // the usual umask); only the private keys are 0600.
    fs::create_dir_all(&dir).map_err(|e| format!("mkdir {dir}: {e}"))?;
    let mut made = Vec::new();
    for (ty, label) in [("rsa", "RSA"), ("ecdsa", "ECDSA"), ("ed25519", "ED25519")] {
        let path = format!("{dir}/ssh_host_{ty}_key");
        if Path::new(&path).exists() {
            continue;
        }
        if made.is_empty() && !args.quiet {
            print!("ssh-keygen: generating new host keys: ");
        }
        let mut rng = OsRng;
        let sk = match ty {
            "rsa" => PrivateKey::generate_rsa(&mut rng, 3072, comment.clone())
                .map_err(|e| format!("rsa generation: {e}"))?,
            "ecdsa" => PrivateKey::generate_ecdsa(&mut rng, EcdsaCurve::P256, comment.clone()),
            _ => PrivateKey::generate_ed25519(&mut rng, comment.clone()),
        };
        let pem = sk
            .to_openssh_pem(None)
            .map_err(|e| format!("encode: {e}"))?;
        let mut pub_line = sk.public_key().to_authorized_keys_line();
        pub_line.push('\n');
        let tmp = format!("{path}.{}.tmp", std::process::id());
        let tmp_pub = format!("{tmp}.pub");
        let _ = fs::remove_file(&tmp);
        let _ = fs::remove_file(&tmp_pub);
        write_private(&tmp, &pem)?;
        write_public(&tmp_pub, &pub_line)?;
        fs::rename(&tmp_pub, format!("{path}.pub"))
            .map_err(|e| format!("rename {tmp_pub}: {e}"))?;
        fs::rename(&tmp, &path).map_err(|e| format!("rename {tmp}: {e}"))?;
        if !args.quiet {
            print!("{label} ");
        }
        made.push(label);
    }
    if !made.is_empty() && !args.quiet {
        println!();
    }
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
    let pem_pass = args
        .new_pass
        .as_deref()
        .map(String::as_str)
        .filter(|p| !p.is_empty());
    let sk = match PrivateKey::parse_openssh_pem(&text, pem_pass.map(str::as_bytes)) {
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
    let old_pass = args
        .old_pass
        .as_deref()
        .map(String::as_str)
        .filter(|p| !p.is_empty());
    let sk = match PrivateKey::parse_openssh_pem(&text, old_pass.map(str::as_bytes)) {
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
        args.new_pass.clone().unwrap_or_default()
    } else {
        read_new_passphrase_confirmed("Enter new passphrase (empty for no passphrase): ")?
    };

    let pem = sk
        .to_openssh_pem(if new_pass.is_empty() {
            None
        } else {
            Some(new_pass.as_bytes())
        })
        .map_err(|e| format!("encode: {e}"))?;

    // Per-call unique tmp name + O_EXCL so two concurrent rotations
    // cannot race on the same temporary path, and an attacker with
    // write access to the parent directory cannot pre-create the path
    // as a symlink to bait us into clobbering an arbitrary file.
    let tmp = unique_tmp_path(&file);
    let write_result = (|| -> Result<(), String> {
        let mut f = open_create_new(&tmp, 0o600).map_err(|e| format!("open {tmp}: {e}"))?;
        f.write_all(pem.as_bytes())
            .map_err(|e| format!("write {tmp}: {e}"))?;
        f.sync_all().map_err(|e| format!("fsync {tmp}: {e}"))?;
        Ok(())
    })();
    if let Err(e) = write_result {
        let _ = fs::remove_file(&tmp);
        return Err(e);
    }
    if let Err(e) = fs::rename(&tmp, &file) {
        let _ = fs::remove_file(&tmp);
        return Err(format!("rename {tmp} -> {file}: {e}"));
    }
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
    if args.iter().any(|a| a == "--help") || args == ["-h"] {
        println!("{USAGE}");
        println!("\nA pure-Rust ssh-keygen built on puressh {VERSION}.");
        return Ok(0);
    }
    if args.iter().any(|a| a == "--version") || args == ["-V"] {
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
    if let Some(op) = &parsed.sig_op {
        return match sig::run(op, &parsed) {
            Ok(code) => Ok(code),
            Err(msg) => {
                eprintln!("{msg}");
                Err(255)
            }
        };
    }
    if let Some(a) = parsed.rest.first().filter(|_| parsed.sig_file.is_none()) {
        eprintln!("ssh-keygen: unexpected argument: {a}");
        eprintln!("{USAGE}");
        return Err(2);
    }

    let mode_count = [
        parsed.fingerprint as u8,
        parsed.derive_pub as u8,
        parsed.change_pass as u8,
        parsed.type_.is_some() as u8,
        parsed.remove_host.is_some() as u8,
        parsed.find_host.is_some() as u8,
        parsed.hash_all as u8,
        parsed.host_keys as u8,
        parsed.sig_file.is_some() as u8,
        parsed.list_cert as u8,
    ]
    .iter()
    .sum::<u8>();
    if mode_count == 0 {
        eprintln!("{USAGE}");
        return Err(2);
    }
    if mode_count > 1 {
        eprintln!(
            "ssh-keygen: -t / -l / -y / -p / -R / -F / -H / -A / -s / -L are mutually exclusive"
        );
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
    } else if parsed.host_keys {
        run_host_keys(&parsed)
    } else if parsed.sig_file.is_some() {
        certs::sign(&parsed)
    } else if parsed.list_cert {
        certs::list(&parsed)
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

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// The local zone's offset east of UTC at `t`, in seconds.
#[cfg(unix)]
fn local_offset(t: i64) -> i64 {
    let tt = t as libc::time_t;
    // SAFETY: `tm` is plain data; localtime_r fills it or returns NULL.
    let mut tm: libc::tm = unsafe { core::mem::zeroed() };
    if unsafe { libc::localtime_r(&tt, &mut tm) }.is_null() {
        return 0;
    }
    tm.tm_gmtoff as i64
}

#[cfg(not(unix))]
fn local_offset(_t: i64) -> i64 {
    0
}

/// Format Unix time `t` as local `YYYY-MM-DDTHH:MM:SS`, like OpenSSH.
fn format_local_time(t: u64) -> String {
    let t = i64::try_from(t).unwrap_or(i64::MAX);
    let local = t.saturating_add(local_offset(t));
    let days = local.div_euclid(86_400);
    let secs = local.rem_euclid(86_400);
    // Howard Hinnant's civil_from_days.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}",
        secs / 3600,
        secs / 60 % 60,
        secs % 60
    )
}

/// `-Y`: SSH signatures (OpenSSH `PROTOCOL.sshsig`), as used by git.
mod sig {
    use super::{
        Args, PrivateKey, PublicKey, algorithm_label, local_offset, now,
        read_passphrase_interactive,
    };
    use puressh::sshsig::{AllowedSigner, HashAlg, Signature};
    use std::io::{Read, Write};

    pub(super) fn run(op: &str, args: &Args) -> Result<i32, String> {
        let mut hash = HashAlg::Sha512;
        let mut verify_time = None;
        let mut print_pubkey = false;
        for o in &args.sig_options {
            let (name, value) = o.split_once('=').unwrap_or((o, ""));
            match name.to_ascii_lowercase().as_str() {
                "hashalg" => {
                    hash = HashAlg::from_name(value)
                        .ok_or_else(|| format!("Unsupported hash algorithm \"{value}\""))?
                }
                "verify-time" => {
                    verify_time = Some(
                        puressh::sshsig::parse_time(value, local_offset(now()))
                            .ok_or_else(|| format!("Invalid \"verify-time\" option: {value}"))?,
                    )
                }
                "print-pubkey" => print_pubkey = true,
                _ => return Err(format!("Invalid option \"{o}\"")),
            }
        }
        let now = verify_time.unwrap_or_else(now);
        match op {
            "sign" => sign(args, hash),
            "verify" => verify(args, now, print_pubkey, true),
            "check-novalidate" => verify(args, now, print_pubkey, false),
            "find-principals" => find_principals(args, now),
            "match-principals" => match_principals(args),
            _ => Err(format!("Unsupported operation for -Y: \"{op}\"")),
        }
    }

    fn require<'a>(v: &'a Option<String>, what: &str) -> Result<&'a str, String> {
        v.as_deref().ok_or_else(|| format!("Missing {what}"))
    }

    fn read_signature(path: &str) -> Result<Signature, String> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| format!("Couldn't read signature file: {e}"))?;
        Signature::from_armored(&text).map_err(|e| format!("Couldn't parse signature: {e}"))
    }

    fn read_allowed_signers(path: &str, at: i64) -> Result<Vec<AllowedSigner>, String> {
        let text = std::fs::read_to_string(path).map_err(|e| format!("open {path}: {e}"))?;
        let (signers, bad) = AllowedSigner::parse_file(&text, local_offset(at));
        for (line, e) in bad {
            eprintln!("{path}:{line}: {e}");
        }
        Ok(signers)
    }

    /// A signer: the private key from `-f`, or the agent holding it.
    pub(super) enum Signer {
        Key(Box<dyn puressh::hostkey::HostKey + Send>),
        #[cfg(unix)]
        Agent(puressh::agent::Agent, u32),
    }

    impl Signer {
        /// An SSH signature blob over `data` by the key `pk`.
        pub(super) fn sign(&mut self, pk: &PublicKey, data: &[u8]) -> puressh::Result<Vec<u8>> {
            #[cfg(not(unix))]
            let _ = pk;
            match self {
                Signer::Key(k) => k.sign(data),
                #[cfg(unix)]
                Signer::Agent(a, flags) => a.sign(&pk.wire_blob(), data, *flags),
            }
        }
    }

    pub(super) fn load_signer(path: &str, use_agent: bool) -> Result<(Signer, PublicKey), String> {
        let text =
            std::fs::read_to_string(path).map_err(|e| format!("Couldn't load {path}: {e}"))?;
        let public = PublicKey::parse_authorized_keys_line(text.trim()).ok();
        if use_agent || public.is_some() {
            #[cfg(not(unix))]
            return Err("signing with an agent is not supported on this platform".into());
            #[cfg(unix)]
            {
                let pk = match public {
                    Some(pk) => pk,
                    None => super::load_public(&format!("{path}.pub"))
                        .or_else(|_| super::load_public(path))?,
                };
                let agent = puressh::agent::Agent::connect_env()
                    .ok()
                    .flatten()
                    .ok_or("Couldn't get agent socket")?;
                // SSH_AGENT_RSA_SHA2_512: OpenSSH signs with rsa-sha2-512.
                let flags = if matches!(pk, PublicKey::Rsa { .. }) {
                    4
                } else {
                    0
                };
                return Ok((Signer::Agent(agent, flags), pk));
            }
        }
        let sk = match PrivateKey::parse_openssh_pem(&text, None) {
            Ok(k) => k,
            Err(_) => {
                let pp =
                    read_passphrase_interactive(&format!("Enter passphrase for \"{path}\": "))?;
                PrivateKey::parse_openssh_pem(&text, Some(pp.as_bytes()))
                    .map_err(|e| format!("Couldn't load key {path}: {e}"))?
            }
        };
        let pk = sk.public_key();
        let key = sk.into_host_key().map_err(|e| format!("{path}: {e}"))?;
        Ok((Signer::Key(key), pk))
    }

    fn sign_digest(
        signer: &mut Signer,
        pk: &PublicKey,
        namespace: &str,
        hash: HashAlg,
        digest: &[u8],
    ) -> Result<String, String> {
        let sig = Signature::create(pk.wire_blob(), namespace, hash, digest, |data| {
            signer.sign(pk, data)
        })
        .map_err(|e| format!("Signing failed: {e}"))?;
        Ok(sig.to_armored())
    }

    fn sign(args: &Args, hash: HashAlg) -> Result<i32, String> {
        let key_path = require(&args.file, "key file (-f)")?;
        let namespace = require(&args.namespace, "namespace (-n)")?;
        let (mut signer, pk) = load_signer(key_path, args.use_agent)?;
        let files: Vec<&str> = if args.rest.is_empty() {
            vec!["-"]
        } else {
            args.rest.iter().map(String::as_str).collect()
        };
        for f in files {
            if f == "-" {
                let digest = hash
                    .digest_reader(std::io::stdin().lock())
                    .map_err(|e| format!("read stdin: {e}"))?;
                let armored = sign_digest(&mut signer, &pk, namespace, hash, &digest)?;
                std::io::stdout()
                    .write_all(armored.as_bytes())
                    .map_err(|e| format!("write: {e}"))?;
                continue;
            }
            if !args.quiet {
                eprintln!("Signing file {f}");
            }
            let file = std::fs::File::open(f).map_err(|e| format!("Cannot open {f}: {e}"))?;
            let digest = hash
                .digest_reader(std::io::BufReader::new(file))
                .map_err(|e| format!("read {f}: {e}"))?;
            let armored = sign_digest(&mut signer, &pk, namespace, hash, &digest)?;
            let out = format!("{f}.sig");
            if std::path::Path::new(&out).exists() && !confirm_overwrite(&out) {
                return Err(format!("{out} exists, not overwriting"));
            }
            std::fs::write(&out, armored).map_err(|e| format!("Cannot write {out}: {e}"))?;
            if !args.quiet {
                eprintln!("Write signature to {out}");
            }
        }
        Ok(0)
    }

    fn confirm_overwrite(path: &str) -> bool {
        println!("{path} already exists.");
        print!("Overwrite (y/n)? ");
        let _ = std::io::stdout().flush();
        let mut line = String::new();
        let mut byte = [0u8; 1];
        while std::io::stdin()
            .read(&mut byte)
            .map(|n| n == 1)
            .unwrap_or(false)
            && byte[0] != b'\n'
        {
            line.push(byte[0] as char);
        }
        line.starts_with('y')
    }

    fn verify(args: &Args, now: i64, print_pubkey: bool, validate: bool) -> Result<i32, String> {
        let namespace = require(&args.namespace, "namespace (-n)")?;
        let sig = read_signature(require(&args.sig_file, "signature file (-s)")?)?;
        let digest = sig
            .hash
            .digest_reader(std::io::stdin().lock())
            .map_err(|e| format!("read stdin: {e}"))?;
        let pk = PublicKey::parse_wire_blob(&sig.public_key);
        let mut result = sig
            .verify(namespace, &digest)
            .map_err(|e| format!("Signature verification failed: {e}"));
        let mut principal = None;
        if validate && result.is_ok() {
            let allowed =
                read_allowed_signers(require(&args.file, "allowed signers file (-f)")?, now)?;
            let id = require(&args.identity, "signer identity (-I)")?;
            let found = allowed.iter().any(|s| {
                s.is_key(&sig.public_key, now)
                    && s.matches_principal(id)
                    && s.allows_namespace(namespace)
            });
            result = if found {
                principal = Some(id);
                Ok(())
            } else {
                Err(format!(
                    "Signature verification failed: no allowed signer \"{id}\" \
                     for this key and namespace \"{namespace}\""
                ))
            };
        }
        match (result, pk) {
            (Ok(()), Ok(pk)) => {
                if !args.quiet {
                    let fp = pk.sha256_fingerprint();
                    let ty = algorithm_label(&pk);
                    match principal {
                        Some(p) => {
                            println!("Good \"{namespace}\" signature for {p} with {ty} key {fp}")
                        }
                        None => println!("Good \"{namespace}\" signature with {ty} key {fp}"),
                    }
                }
                if print_pubkey {
                    println!("{}", pk.to_authorized_keys_line());
                }
                Ok(0)
            }
            (res, _) => {
                if let Err(e) = res {
                    eprintln!("{e}");
                }
                if !args.quiet {
                    println!("Could not verify signature.");
                }
                Ok(255)
            }
        }
    }

    fn find_principals(args: &Args, now: i64) -> Result<i32, String> {
        let sig = read_signature(require(&args.sig_file, "signature file (-s)")?)?;
        let allowed = read_allowed_signers(require(&args.file, "allowed signers file (-f)")?, now)?;
        let mut found = false;
        for s in allowed.iter().filter(|s| s.is_key(&sig.public_key, now)) {
            for p in s.principals.split(',') {
                println!("{p}");
            }
            found = true;
        }
        if found {
            Ok(0)
        } else {
            Err("No principal matched.".into())
        }
    }

    fn match_principals(args: &Args) -> Result<i32, String> {
        let id = require(&args.identity, "signer identity (-I)")?;
        let allowed =
            read_allowed_signers(require(&args.file, "allowed signers file (-f)")?, now())?;
        let mut found = false;
        for s in allowed.iter().filter(|s| s.matches_principal(id)) {
            println!("{}", s.principals);
            found = true;
        }
        if found {
            Ok(0)
        } else {
            Err("No principal matched.".into())
        }
    }
}

/// `-s` / `-L`: OpenSSH certificates.
mod certs {
    use super::{Args, PublicKey, algorithm_label, format_local_time, local_offset, now};
    use purecrypto::rng::{OsRng, RngCore};
    use puressh::cert::{
        CertType, Certificate, CertificateBuilder, DEFAULT_USER_EXTENSIONS, encode_option_string,
    };

    /// `[+-]1w2d3h4m5s` relative to `now`.
    fn parse_relative(s: &str, now: u64) -> Option<u64> {
        let (neg, body) = match s.as_bytes().first()? {
            b'+' => (false, &s[1..]),
            b'-' => (true, &s[1..]),
            _ => return None,
        };
        if body.is_empty() {
            return None;
        }
        let mut total = 0u64;
        let mut num = String::new();
        for c in body.chars() {
            if c.is_ascii_digit() {
                num.push(c);
                continue;
            }
            let n: u64 = num.parse().ok()?;
            num.clear();
            let unit = match c.to_ascii_lowercase() {
                's' => 1,
                'm' => 60,
                'h' => 3600,
                'd' => 86_400,
                'w' => 604_800,
                _ => return None,
            };
            total = total.checked_add(n.checked_mul(unit)?)?;
        }
        if !num.is_empty() {
            total = total.checked_add(num.parse().ok()?)?;
        }
        if neg {
            Some(now.saturating_sub(total))
        } else {
            now.checked_add(total)
        }
    }

    fn parse_absolute(s: &str) -> Option<u64> {
        if let Some(hex) = s.strip_prefix("0x") {
            return u64::from_str_radix(hex, 16).ok();
        }
        let t = puressh::sshsig::parse_time(s, local_offset(now()))?;
        u64::try_from(t).ok()
    }

    /// `-V`: `from:to`, or a lone `+relative` end (starting a minute ago).
    fn parse_validity(spec: &str, now: u64) -> Result<(u64, u64), String> {
        let bad = || format!("Invalid certificate life specification {spec}");
        let (from, to) = match spec.split_once(':') {
            Some((f, t)) => {
                let from = match f {
                    "always" => 0,
                    f if f.starts_with(['+', '-']) => parse_relative(f, now).ok_or_else(bad)?,
                    f => parse_absolute(f).ok_or_else(bad)?,
                };
                let to = match t {
                    "forever" => u64::MAX,
                    t if t.starts_with(['+', '-']) => parse_relative(t, now).ok_or_else(bad)?,
                    t => parse_absolute(t).ok_or_else(bad)?,
                };
                (from, to)
            }
            None if spec.starts_with('+') => (
                (now / 60).saturating_sub(1) * 60,
                parse_relative(spec, now).ok_or_else(bad)?,
            ),
            None => return Err(bad()),
        };
        if from >= to {
            return Err("Empty certificate validity interval".into());
        }
        Ok((from, to))
    }

    fn validity_text(from: u64, to: u64) -> String {
        match (from, to) {
            (0, u64::MAX) => "forever".into(),
            (0, to) => format!("before {}", format_local_time(to)),
            (from, u64::MAX) => format!("after {}", format_local_time(from)),
            (from, to) => format!(
                "from {} to {}",
                format_local_time(from),
                format_local_time(to)
            ),
        }
    }

    fn set(list: &mut Vec<(String, Vec<u8>)>, name: &str, data: Vec<u8>) {
        list.retain(|(n, _)| n != name);
        list.push((name.to_string(), data));
    }

    /// Apply the `-O` options to a user certificate.
    fn apply_options(b: &mut CertificateBuilder, options: &[String]) -> Result<(), String> {
        for o in options {
            let lower = o.to_ascii_lowercase();
            // `permit-pty` / `no-pty`, …: toggle a standard extension.
            let standard = DEFAULT_USER_EXTENSIONS.iter().find_map(|e| {
                let short = e["permit-".len()..].to_ascii_lowercase();
                if lower == e.to_ascii_lowercase() {
                    Some((*e, true))
                } else if lower == format!("no-{short}") {
                    Some((*e, false))
                } else {
                    None
                }
            });
            if lower == "clear" {
                b.critical_options.clear();
                b.extensions.clear();
            } else if let Some((e, on)) = standard {
                if on {
                    set(&mut b.extensions, e, Vec::new());
                } else {
                    b.extensions.retain(|(n, _)| n != e);
                }
            } else if lower == "no-touch-required" {
                set(&mut b.extensions, "no-touch-required", Vec::new());
            } else if lower == "verify-required" {
                set(&mut b.critical_options, "verify-required", Vec::new());
            } else if let Some(v) = strip_ci(o, "force-command=") {
                set(
                    &mut b.critical_options,
                    "force-command",
                    encode_option_string(v),
                );
            } else if let Some(v) = strip_ci(o, "source-address=") {
                set(
                    &mut b.critical_options,
                    "source-address",
                    encode_option_string(v),
                );
            } else if let Some(v) = strip_ci(o, "critical:") {
                let (name, data) = custom(v);
                set(&mut b.critical_options, name, data);
            } else if let Some(v) = strip_ci(o, "extension:") {
                let (name, data) = custom(v);
                set(&mut b.extensions, name, data);
            } else {
                return Err(format!("Unsupported certificate option \"{o}\""));
            }
        }
        Ok(())
    }

    fn strip_ci<'a>(s: &'a str, prefix: &str) -> Option<&'a str> {
        s.get(..prefix.len())
            .filter(|p| p.eq_ignore_ascii_case(prefix))
            .map(|_| &s[prefix.len()..])
    }

    /// `name[=value]`: a flag, or a string-valued option.
    fn custom(v: &str) -> (&str, Vec<u8>) {
        match v.split_once('=') {
            Some((n, val)) => (n, encode_option_string(val)),
            None => (v, Vec::new()),
        }
    }

    fn cert_path(path: &str) -> String {
        format!("{}-cert.pub", path.strip_suffix(".pub").unwrap_or(path))
    }

    pub(super) fn sign(args: &Args) -> Result<i32, String> {
        let ca_path = args.sig_file.as_deref().unwrap_or_default();
        let key_id = args
            .identity
            .as_deref()
            .ok_or("Must specify key id (-I) when certifying")?;
        if args.rest.is_empty() {
            return Err("Too few arguments.".into());
        }
        let now = now() as u64;
        let (valid_after, valid_before) = match &args.validity {
            Some(spec) => parse_validity(spec, now)?,
            None => (0, u64::MAX),
        };
        let (mut serial, auto_increment) = match args.serial.as_deref() {
            None => (0, false),
            Some(z) => {
                let (digits, inc) = match z.strip_prefix('+') {
                    Some(d) => (d, true),
                    None => (z, false),
                };
                let n = digits
                    .parse::<u64>()
                    .map_err(|_| format!("Invalid serial number \"{z}\""))?;
                (n, inc)
            }
        };
        let principals: Vec<String> = args
            .namespace
            .as_deref()
            .map(|n| n.split(',').map(str::to_string).collect())
            .unwrap_or_default();
        let (mut signer, ca_pk) = super::sig::load_signer(ca_path, args.use_agent)?;
        let cert_type = if args.host_cert {
            CertType::Host
        } else {
            CertType::User
        };
        for path in &args.rest {
            let text = std::fs::read_to_string(path).map_err(|e| format!("{path}: {e}"))?;
            let pk = PublicKey::parse_authorized_keys_line(text.trim())
                .map_err(|e| format!("{path}: {e}"))?;
            let mut nonce = vec![0u8; 32];
            OsRng.fill_bytes(&mut nonce);
            let mut b = CertificateBuilder::new(pk.wire_blob(), cert_type, nonce);
            b.serial = serial;
            b.key_id = key_id.to_string();
            b.valid_principals = principals.clone();
            b.valid_after = valid_after;
            b.valid_before = valid_before;
            // Host certificates carry no options, as with OpenSSH.
            if cert_type == CertType::User {
                b.extensions = DEFAULT_USER_EXTENSIONS
                    .iter()
                    .map(|e| (e.to_string(), Vec::new()))
                    .collect();
                apply_options(&mut b, &args.sig_options)?;
            }
            let cert = b
                .sign(&ca_pk.wire_blob(), |data| signer.sign(&ca_pk, data))
                .map_err(|e| format!("Couldn't certify key {path}: {e}"))?;
            let out = cert_path(path);
            std::fs::write(&out, cert.to_openssh_line(pk.comment()) + "\n")
                .map_err(|e| format!("Could not write certified key to {out}: {e}"))?;
            if !args.quiet {
                if principals.is_empty() {
                    eprintln!("Warning: certificate will contain no principals (-n)");
                }
                let kind = if args.host_cert { "host" } else { "user" };
                let who = if principals.is_empty() {
                    String::new()
                } else {
                    format!("for {} ", principals.join(","))
                };
                eprintln!(
                    "Signed {kind} key {out}: id \"{key_id}\" serial {serial} {who}valid {}",
                    validity_text(valid_after, valid_before)
                );
            }
            if auto_increment {
                serial = serial.wrapping_add(1);
            }
        }
        Ok(0)
    }

    /// One critical option or extension, as `ssh-keygen -L` shows it.
    fn describe(known_flags: &[&str], (name, data): &(String, Vec<u8>)) -> String {
        if matches!(name.as_str(), "force-command" | "source-address")
            && let Some(v) = Certificate::option_string(data)
        {
            format!("{name} {v}")
        } else if data.is_empty() && known_flags.contains(&name.as_str()) {
            name.clone()
        } else if data.is_empty() {
            format!("{name} UNKNOWN FLAG OPTION")
        } else {
            let hex: String = data.iter().map(|b| format!("{b:02x}")).collect();
            format!("{name} UNKNOWN OPTION: {hex} (len {})", data.len())
        }
    }

    fn print_list(title: &str, items: Vec<String>) {
        if items.is_empty() {
            println!("        {title}: (none)");
        } else {
            println!("        {title}: ");
            for i in items {
                println!("                {i}");
            }
        }
    }

    pub(super) fn list(args: &Args) -> Result<i32, String> {
        let path = args.file.as_deref().ok_or("-f is required")?;
        let text = std::fs::read_to_string(path).map_err(|e| format!("{path}: {e}"))?;
        let cert = Certificate::parse_openssh_line(text.trim())
            .map_err(|e| format!("{path} is not a certificate: {e}"))?;
        let key = PublicKey::parse_wire_blob(cert.embedded_pubkey_blob())
            .map_err(|e| format!("{path}: {e}"))?;
        let ca = PublicKey::parse_wire_blob(&cert.signature_key_blob)
            .map_err(|e| format!("{path}: {e}"))?;
        let kind = match cert.cert_type {
            CertType::User => "user",
            CertType::Host => "host",
        };
        println!("{path}:");
        println!("        Type: {} {kind} certificate", cert.key_type);
        println!(
            "        Public key: {}-CERT {}",
            algorithm_label(&key),
            key.sha256_fingerprint()
        );
        println!(
            "        Signing CA: {} {} (using {})",
            algorithm_label(&ca),
            ca.sha256_fingerprint(),
            cert.ca_algorithm().unwrap_or("unknown")
        );
        println!("        Key ID: \"{}\"", cert.key_id);
        println!("        Serial: {}", cert.serial);
        println!(
            "        Valid: {}",
            validity_text(cert.valid_after, cert.valid_before)
        );
        print_list("Principals", cert.valid_principals.clone());
        print_list(
            "Critical Options",
            cert.critical_options
                .iter()
                .map(|o| describe(&["verify-required"], o))
                .collect(),
        );
        let mut known = DEFAULT_USER_EXTENSIONS.to_vec();
        known.push("no-touch-required");
        print_list(
            "Extensions",
            cert.extensions
                .iter()
                .map(|o| describe(&known, o))
                .collect(),
        );
        Ok(0)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rsa_1024_is_rejected_before_writing() {
        let args = Args {
            type_: Some("rsa".into()),
            bits: Some(1024),
            file: Some("/tmp/puressh-ssh-keygen-test-should-not-be-written".into()),
            ..Args::default()
        };
        let err = run_generate(&args).unwrap_err();
        assert!(
            err.contains("at least 2048 bits"),
            "expected RSA floor error, got: {err}"
        );
        // The guard must fire before any key material is written.
        assert!(!std::path::Path::new(args.file.as_ref().unwrap()).exists());
    }

    #[test]
    fn rsa_just_below_floor_is_rejected() {
        // 2048 is the minimum accepted value; 2047 must still be refused.
        let args = Args {
            type_: Some("rsa".into()),
            bits: Some(2047),
            file: Some("/tmp/puressh-ssh-keygen-test-should-not-be-written".into()),
            ..Args::default()
        };
        let err = run_generate(&args).unwrap_err();
        assert!(err.contains("at least 2048 bits"), "got: {err}");
    }
}
