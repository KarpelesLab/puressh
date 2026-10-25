//! `ssh-keygen` — puressh's key-generation and key-inspection tool.
//!
//! ```text
//! ssh-keygen [-q] [-a rounds] [-b bits] [-C comment] [-f path] [-m format] [-N pass] [-t type]
//! ssh-keygen -l [-v] [-E sha256|md5] -f path[.pub]     (also -B: bubblebabble)
//! ssh-keygen -e|-i [-m RFC4716|PKCS8|PEM] -f path      (export / import)
//! ssh-keygen -r hostname [-g] [-f path]                (SSHFP records)
//! ssh-keygen -k -f krl [-u] [-s ca.pub] [-z version] file ...
//! ssh-keygen -Q [-l] -f krl file ...
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

#[cfg(unix)]
#[path = "unix_sys.rs"]
mod unix_sys;
use std::path::Path;
use std::process::ExitCode;

use purecrypto::rng::{OsRng, RngCore};
use purecrypto::zeroize::Zeroizing;
use puressh::key::{EcdsaCurve, PrivateKey, PublicKey};

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

const USAGE: &str = "usage: ssh-keygen [-q] [-a rounds] [-b bits] [-C comment] [-f output_keyfile]\n                  \
                     [-m format] [-N new_passphrase] [-t ecdsa | ed25519 | mldsa44-ed25519 | rsa]\n       \
                     ssh-keygen -l [-v] [-E fingerprint_hash] [-f input_keyfile]\n       \
                     ssh-keygen -B [-f input_keyfile]\n       \
                     ssh-keygen -e [-f input_keyfile] [-m key_format]\n       \
                     ssh-keygen -i [-f input_keyfile] [-m key_format]\n       \
                     ssh-keygen -r hostname [-g] [-f input_keyfile]\n       \
                     ssh-keygen -k -f krl_file [-u] [-s ca_public] [-z version_number] file ...\n       \
                     ssh-keygen -Q [-l] -f krl_file file ...\n       \
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
    /// `-m`: key format (`RFC4716`, `PKCS8`, `PEM`).
    format: Option<String>,
    /// `-e`: export a key in `-m` format; `-i`: import one.
    export: bool,
    import: bool,
    /// `-E`: fingerprint hash (`sha256`, `md5`).
    fp_hash: Option<String>,
    /// `-B`: bubblebabble digest; `-v`: with `-l`, the randomart image.
    bubble: bool,
    visual: bool,
    /// `-a`: bcrypt KDF rounds for new or re-encrypted keys.
    rounds: Option<u32>,
    /// `-k`: build a KRL (`-u`: update an existing one); `-Q`: test keys
    /// against one.
    krl: bool,
    krl_update: bool,
    krl_query: bool,
    /// `-r host`: print SSHFP records (`-g`: generic format).
    sshfp: Option<String>,
    sshfp_generic: bool,
    /// `-M generate|screen`: moduli generation / screening.
    moduli: Option<String>,
    /// `-w provider`: the FIDO `SecurityKeyProvider`.
    sk_provider: Option<String>,
    /// `-K`: download the authenticator's resident keys.
    download_sk: bool,
}

/// Split getopt-style arguments as OpenSSH's ssh-keygen takes them: flags
/// may be grouped (`-lf key`, `-qN ''`) and a value may follow its option
/// directly (`-ted25519`).
fn split_getopt(args: &[String]) -> Vec<String> {
    const VALUE_OPTS: &str = "CDEFIMNOPRVYZabfmnrstwz";
    const FLAG_OPTS: &str = "ABHKLQUXceghiklopquvy";
    let mut split = Vec::with_capacity(args.len());
    let mut it = args.iter();
    while let Some(a) = it.next() {
        if a == "--" {
            split.push(a.clone());
            split.extend(it.cloned());
            break;
        }
        let Some(rest) = a
            .strip_prefix('-')
            .filter(|r| !r.starts_with('-') && r.len() > 1)
        else {
            split.push(a.clone());
            continue;
        };
        let chars: Vec<char> = rest.chars().collect();
        let start = split.len();
        for (k, &c) in chars.iter().enumerate() {
            if VALUE_OPTS.contains(c) {
                split.push(format!("-{c}"));
                let tail: String = chars[k + 1..].iter().collect();
                if !tail.is_empty() {
                    split.push(tail);
                }
                break;
            }
            if !FLAG_OPTS.contains(c) {
                // Not an option: report it as written.
                split.truncate(start);
                split.push(a.clone());
                break;
            }
            split.push(format!("-{c}"));
        }
    }
    split
}

fn parse_args(args: &[String]) -> Result<Args, String> {
    let args = &split_getopt(args)[..];
    let mut out = Args { ..Args::default() };
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
            "-M" => {
                i += 1;
                out.moduli = Some(args.get(i).ok_or("-M requires a value")?.clone());
            }
            "-f" => {
                i += 1;
                out.file = Some(args.get(i).ok_or("-f requires a value")?.clone());
            }
            "-l" => out.fingerprint = true,
            "-e" => out.export = true,
            "-k" => out.krl = true,
            "-u" => out.krl_update = true,
            "-Q" => out.krl_query = true,
            "-g" => out.sshfp_generic = true,
            "-r" => {
                i += 1;
                out.sshfp = Some(args.get(i).ok_or("-r requires a host name")?.clone());
            }
            "-i" => out.import = true,
            "-B" => out.bubble = true,
            "-v" | "-vv" | "-vvv" => out.visual = true,
            "-lv" | "-vl" => {
                out.fingerprint = true;
                out.visual = true;
            }
            "-m" => {
                i += 1;
                out.format = Some(args.get(i).ok_or("-m requires a format")?.clone());
            }
            "-E" => {
                i += 1;
                out.fp_hash = Some(
                    args.get(i)
                        .ok_or("-E requires a hash")?
                        .to_ascii_lowercase(),
                );
            }
            "-a" => {
                i += 1;
                let v = args.get(i).ok_or("-a requires a number")?;
                out.rounds = Some(
                    v.parse::<u32>()
                        .ok()
                        .filter(|r| (1..=10_000).contains(r))
                        .ok_or_else(|| format!("Invalid number: {v}"))?,
                );
            }
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
            "-K" => out.download_sk = true,
            "-w" => {
                i += 1;
                out.sk_provider = Some(args.get(i).ok_or("-w requires a provider")?.clone());
            }
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
    fs::read_to_string(path).map_err(|e| format!("{path}: {}", io_reason(&e)))
}

/// Marks an error message printed as is, without the `ssh-keygen: ` prefix
/// (OpenSSH words some failures that way).
const RAW: char = '\u{1}';

/// Why a private key could not be loaded, as OpenSSH says it.
fn load_reason(e: &puressh::Error) -> String {
    match e {
        puressh::Error::Crypto(m) if m.contains("passphrase") => {
            "incorrect passphrase supplied to decrypt private key".into()
        }
        other => other.to_string(),
    }
}

/// Write `contents` to `path` (replacing it), readable by the owner only:
/// OpenSSH's `sshbuf_write_file` under `umask(077)`.
#[cfg_attr(not(feature = "security-key"), allow(dead_code))]
fn write_private_bytes(path: &str, contents: &[u8]) -> std::io::Result<()> {
    let mut o = fs::OpenOptions::new();
    o.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(0o600);
    }
    o.open(path)?.write_all(contents)
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

/// Write a public key file, replacing one already there (OpenSSH's
/// `sshkey_save_public`: only the private key is asked about).
fn write_public(path: &str, contents: &str) -> Result<(), String> {
    let mut opts = fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        opts.mode(0o644);
    }
    let mut f = opts.open(path).map_err(|e| format!("open {path}: {e}"))?;
    f.write_all(contents.as_bytes())
        .map_err(|e| format!("write {path}: {e}"))?;
    Ok(())
}

/// OpenSSH's `sshkey_load_public`: `path` as a public key, else
/// `path.pub`, else the public half of the private key at `path`.
fn load_public_any(path: &str) -> Result<PublicKey, String> {
    let text = read_to_string(path)?;
    if let Ok(pk) = PublicKey::parse_authorized_keys_line(text.trim()) {
        return Ok(pk);
    }
    if let Ok(pubtext) = fs::read_to_string(format!("{path}.pub"))
        && let Ok(pk) = PublicKey::parse_authorized_keys_line(pubtext.trim())
    {
        return Ok(pk);
    }
    PrivateKey::public_key_from_pem(&text).map_err(|e| format!("{path}: {e}"))
}

/// OpenSSH's `read_passphrase(prompt, RP_ALLOW_STDIN)` askpass rules: the
/// helper (`$SSH_ASKPASS`, else `/usr/bin/ssh-askpass`) is used with
/// `SSH_ASKPASS_REQUIRE=force`, or when a display is available and either
/// `SSH_ASKPASS_REQUIRE=prefer` or stdin is not a terminal; `never` rules
/// it out. A helper that fails answers with an empty passphrase.
fn askpass(prompt: &str) -> Option<Zeroizing<String>> {
    use std::io::IsTerminal;
    let set = |v: &str| std::env::var_os(v).is_some_and(|s| !s.is_empty());
    let mut allow = set("DISPLAY") || set("WAYLAND_DISPLAY");
    let mut use_it = false;
    match std::env::var("SSH_ASKPASS_REQUIRE")
        .unwrap_or_default()
        .to_ascii_lowercase()
        .as_str()
    {
        "force" => {
            use_it = true;
            allow = true;
        }
        "prefer" => use_it = allow,
        "never" => allow = false,
        _ => {}
    }
    if !std::io::stdin().is_terminal() {
        use_it = true;
    }
    if !(use_it && allow) {
        return None;
    }
    let helper = std::env::var_os("SSH_ASKPASS")
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "/usr/bin/ssh-askpass".into());
    let out = std::process::Command::new(helper)
        .arg(prompt)
        .stdin(std::process::Stdio::null())
        .stderr(std::process::Stdio::inherit())
        .output();
    let answer = match out {
        Ok(o) if o.status.success() => {
            let text = String::from_utf8_lossy(&o.stdout);
            text.split(['\r', '\n']).next().unwrap_or("").to_string()
        }
        _ => String::new(),
    };
    Some(Zeroizing::new(answer))
}

/// Prompt the user for a passphrase. Returns a [`Zeroizing<String>`] so
/// the buffer is wiped on drop; on Unix tty inputs the terminal echo
/// bit is cleared via `tcsetattr` and restored via a `Drop` guard,
/// matching OpenSSH ssh-keygen behaviour.
fn read_passphrase_interactive(prompt: &str) -> Result<Zeroizing<String>, String> {
    if let Some(answer) = askpass(prompt) {
        return Ok(answer);
    }
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
        if *first == *second {
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
        PublicKey::MlDsa44Ed25519 { .. } => "MLDSA44-ED25519",
        PublicKey::SkEcdsaP256 { .. } => "ECDSA-SK",
        PublicKey::SkEd25519 { .. } => "ED25519-SK",
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
    let pk = PrivateKey::parse_pem(&text, None).map_err(|e| {
        format!("{path}: not a public key line and not an unencrypted private key ({e})")
    })?;
    Ok(pk.public_key())
}

/// The key `-l` fingerprints, as OpenSSH's `fingerprint_private`: a public
/// key file, else the private key's `.pub` (with its comment), else its
/// public half; the comment then comes from the private key when it can
/// be read without a passphrase.
fn fingerprint_key(path: &str) -> Result<PublicKey, String> {
    let text = read_to_string(path)?;
    if let Ok(pk) = PublicKey::parse_authorized_keys_line(text.trim()) {
        return Ok(pk);
    }
    let from_pub = fs::read_to_string(format!("{path}.pub"))
        .ok()
        .and_then(|t| PublicKey::parse_authorized_keys_line(t.trim()).ok());
    if let Some(pk) = &from_pub
        && !pk.comment().is_empty()
    {
        return Ok(pk.clone());
    }
    match PrivateKey::parse_pem(&text, None) {
        Ok(sk) => {
            let pk = from_pub.unwrap_or_else(|| sk.public_key());
            if sk.comment().is_empty() {
                return Ok(pk);
            }
            let full = pk.to_authorized_keys_line();
            let bare: Vec<&str> = full.split_whitespace().take(2).collect();
            let line = format!("{} {}", bare.join(" "), sk.comment());
            Ok(PublicKey::parse_authorized_keys_line(&line).unwrap_or(pk))
        }
        Err(_) => from_pub
            .map(Ok)
            .unwrap_or_else(|| PrivateKey::public_key_from_pem(&text))
            .map_err(|_| format!("{path} is not a key file.")),
    }
}

fn ensure_file_in(file: &Option<String>) -> Result<String, String> {
    file.clone().ok_or_else(|| "-f is required".into())
}

/// Ask a question on the terminal (stdout prompt, stdin answer), like
/// OpenSSH's file / overwrite prompts. `None` at end of input.
fn ask(prompt: &str) -> Option<String> {
    print!("{prompt}");
    let _ = std::io::stdout().flush();
    let mut line = String::new();
    match std::io::stdin().read_line(&mut line) {
        Ok(0) | Err(_) => None,
        Ok(_) => Some(line.trim_end_matches(['\n', '\r']).to_string()),
    }
}

fn run_generate(args: &Args) -> Result<i32, String> {
    // OpenSSH's default type is Ed25519.
    // A short name (any case) or a key algorithm name, as OpenSSH's
    // `sshkey_type_from_shortname`; an ECDSA algorithm name also picks the
    // curve when `-b` does not.
    let named = args.type_.as_deref().unwrap_or("ed25519");
    let (ty, curve_bits) = match named {
        "ssh-ed25519" => ("ed25519".to_string(), None),
        "ssh-mldsa44-ed25519@openssh.com" => ("mldsa44-ed25519".to_string(), None),
        "ssh-rsa" | "rsa-sha2-256" | "rsa-sha2-512" => ("rsa".to_string(), None),
        "ecdsa-sha2-nistp256" => ("ecdsa".to_string(), Some(256)),
        "ecdsa-sha2-nistp384" => ("ecdsa".to_string(), Some(384)),
        "ecdsa-sha2-nistp521" => ("ecdsa".to_string(), Some(521)),
        "sk-ecdsa-sha2-nistp256@openssh.com" => ("ecdsa-sk".to_string(), None),
        "sk-ssh-ed25519@openssh.com" => ("ed25519-sk".to_string(), None),
        other => (other.to_lowercase(), None),
    };
    if !args.quiet {
        println!("Generating public/private {ty} key pair.");
    }
    let file = match &args.file {
        Some(f) => f.clone(),
        None => {
            let home = std::env::var("HOME").map_err(|_| "$HOME is not set")?;
            let default = format!("{home}/.ssh/id_{}", ty.replace('-', "_"));
            let answer = ask(&format!(
                "Enter file in which to save the key ({default}): "
            ))
            .ok_or("no file name given")?;
            let file = if answer.is_empty() { default } else { answer };
            if let Some(dir) = Path::new(&file).parent()
                && !dir.as_os_str().is_empty()
                && !dir.exists()
            {
                fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let _ = fs::set_permissions(dir, fs::Permissions::from_mode(0o700));
                }
                println!("Created directory '{}'.", dir.display());
            }
            file
        }
    };
    if Path::new(&file).exists() {
        let answer = ask(&format!("{file} already exists.\nOverwrite (y/n)? ")).unwrap_or_default();
        if !answer.starts_with(['y', 'Y']) {
            return Ok(1);
        }
        let _ = fs::remove_file(&file);
        let _ = fs::remove_file(format!("{file}.pub"));
    }
    let pub_path = format!("{file}.pub");

    let comment = args.comment.clone().unwrap_or_else(user_at_host);

    let mut rng = OsRng;
    #[cfg_attr(not(feature = "security-key"), allow(unused_mut))]
    let mut attestation: Option<(String, Vec<u8>)> = None;
    let sk = match ty.as_str() {
        #[cfg(feature = "security-key")]
        "ecdsa-sk" | "ed25519-sk" => {
            let (mut key, attest) = security_key::enroll(args, &ty)?;
            key.set_comment(comment);
            attestation = attest;
            key
        }
        "ed25519" => PrivateKey::generate_ed25519(&mut rng, comment),
        "mldsa44-ed25519" => PrivateKey::generate_mldsa44_ed25519(&mut rng, comment),
        "ecdsa" => {
            let bits = args.bits.or(curve_bits).unwrap_or(256);
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
    let pem = encode_private(&sk, args, &passphrase)
        .map_err(|e| format!("Saving key \"{file}\" failed: {e}"))?;

    let pub_line = sk.public_key().to_authorized_keys_line();
    let mut pub_full = pub_line;
    pub_full.push('\n');

    write_private(&file, &pem)?;
    write_public(&pub_path, &pub_full)?;
    if let Some((path, blob)) = attestation {
        write_private_bytes(&path, &blob)
            .map_err(|e| format!("{RAW}Unable to write attestation data \"{path}\": {e}"))?;
        if !args.quiet {
            println!("Your FIDO attestation certificate has been saved in {path}");
        }
    }

    if !args.quiet {
        let pk = sk.public_key();
        println!("Your identification has been saved in {file}");
        println!("Your public key has been saved in {pub_path}");
        println!("The key fingerprint is:");
        println!("{} {}", pk.sha256_fingerprint(), pk.comment());
        println!("The key's randomart image is:");
        println!("{}", randomart(&pk, &sha256(&pk.wire_blob()), "SHA256"));
    }
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
    for (ty, label) in [
        ("rsa", "RSA"),
        ("ecdsa", "ECDSA"),
        ("ed25519", "ED25519"),
        ("mldsa44-ed25519", "MLDSA44-ED25519"),
    ] {
        let path = format!("{dir}/ssh_host_{}_key", ty.replace('-', "_"));
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
            "mldsa44-ed25519" => PrivateKey::generate_mldsa44_ed25519(&mut rng, comment.clone()),
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

/// The fingerprint of `pk` as `ssh-keygen -l` prints it (`-E`, `-B`).
fn fingerprint_text(pk: &PublicKey, args: &Args) -> Result<String, String> {
    if args.bubble {
        return Ok(bubblebabble(&sha1(&pk.wire_blob())));
    }
    match args.fp_hash.as_deref().unwrap_or("sha256") {
        "sha256" => Ok(pk.sha256_fingerprint()),
        "md5" => Ok(format!(
            "MD5:{}",
            md5(&pk.wire_blob())
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<Vec<_>>()
                .join(":")
        )),
        other => Err(format!("Invalid hash algorithm \"{other}\"")),
    }
}

fn sha1(data: &[u8]) -> Vec<u8> {
    use purecrypto::hash::{Digest, Sha1};
    Sha1::digest(data).as_ref().to_vec()
}

fn md5(data: &[u8]) -> Vec<u8> {
    use purecrypto::hash::{Digest, Md5};
    Md5::digest(data).as_ref().to_vec()
}

fn sha256(data: &[u8]) -> Vec<u8> {
    use purecrypto::hash::{Digest, Sha256};
    Sha256::digest(data).as_ref().to_vec()
}

/// OpenSSH's bubblebabble encoding of a digest (`ssh-keygen -B`).
fn bubblebabble(d: &[u8]) -> String {
    const VOWELS: &[u8] = b"aeiouy";
    const CONSONANTS: &[u8] = b"bcdfghklmnprstvzx";
    let rounds = d.len() / 2 + 1;
    let mut seed = 1usize;
    let mut out = String::from("x");
    for i in 0..rounds {
        if i + 1 < rounds || !d.len().is_multiple_of(2) {
            let b = d[2 * i] as usize;
            out.push(VOWELS[(((b >> 6) & 3) + seed) % 6] as char);
            out.push(CONSONANTS[(b >> 2) & 15] as char);
            out.push(VOWELS[((b & 3) + seed / 6) % 6] as char);
            if i + 1 < rounds {
                let c = d[2 * i + 1] as usize;
                out.push(CONSONANTS[(c >> 4) & 15] as char);
                out.push('-');
                out.push(CONSONANTS[c & 15] as char);
                seed = (seed * 5 + b * 7 + c) % 36;
            }
        } else {
            out.push(VOWELS[seed % 6] as char);
            out.push(CONSONANTS[16] as char);
            out.push(VOWELS[seed / 6] as char);
        }
    }
    out.push('x');
    out
}

/// OpenSSH's "drunken bishop" randomart for a key's digest.
fn randomart(pk: &PublicKey, digest: &[u8], hash_name: &str) -> String {
    const AUG: &[u8] = b" .o+=*BOX@%&#/^SE";
    const W: usize = 17;
    const H: usize = 9;
    // As in OpenSSH: the last two symbols mark the start and end.
    let len = AUG.len() - 1;
    let mut field = [[0usize; H]; W];
    let (mut x, mut y) = (W as isize / 2, H as isize / 2);
    for byte in digest {
        let mut input = *byte;
        for _ in 0..4 {
            x += if input & 1 != 0 { 1 } else { -1 };
            y += if input & 2 != 0 { 1 } else { -1 };
            x = x.clamp(0, W as isize - 1);
            y = y.clamp(0, H as isize - 1);
            let cell = &mut field[x as usize][y as usize];
            if *cell < len - 2 {
                *cell += 1;
            }
            input >>= 2;
        }
    }
    field[W / 2][H / 2] = len - 1;
    field[x as usize][y as usize] = len;
    let border = |label: &str| {
        let mut line = String::from("+");
        let pad = W.saturating_sub(label.len()) / 2;
        line.push_str(&"-".repeat(pad));
        line.push_str(label);
        line.push_str(&"-".repeat(W.saturating_sub(pad + label.len())));
        line.push('+');
        line
    };
    let mut out = border(&format!("[{} {}]", algorithm_label(pk), pk.bit_length()));
    out.push('\n');
    for row in 0..H {
        out.push('|');
        for col in field.iter() {
            out.push(AUG[col[row].min(len)] as char);
        }
        out.push_str("|\n");
    }
    out.push_str(&border(&format!("[{hash_name}]")));
    out
}

fn run_fingerprint(args: &Args) -> Result<i32, String> {
    let file = ensure_file_in(&args.file)?;
    // A key file, or every key line of an authorized_keys / known_hosts
    // style file.
    // (key, the comment to show: a known_hosts line's host field).
    let keys: Vec<(PublicKey, Option<String>)> = match fingerprint_key(&file) {
        Ok(pk) => vec![(pk, None)],
        Err(e) => {
            let text = read_to_string(&file)?;
            let keys: Vec<(PublicKey, Option<String>)> = text
                .lines()
                .filter_map(|l| {
                    let l = l.trim();
                    if l.is_empty() || l.starts_with('#') {
                        return None;
                    }
                    if let Ok(pk) = PublicKey::parse_authorized_keys_line(l) {
                        return Some((pk, None));
                    }
                    // known_hosts: `hosts keytype base64`; OpenSSH skips
                    // the @cert-authority / @revoked lines.
                    if l.starts_with('@') {
                        return None;
                    }
                    let (hosts, rest) = l.split_once(char::is_whitespace)?;
                    PublicKey::parse_authorized_keys_line(rest.trim())
                        .ok()
                        .map(|pk| (pk, Some(hosts.to_string())))
                })
                .collect();
            if keys.is_empty() {
                return Err(e);
            }
            keys
        }
    };
    for (pk, hosts) in keys {
        let fp = fingerprint_text(&pk, args)?;
        let comment = match &hosts {
            Some(h) => h.as_str(),
            None if pk.comment().is_empty() => "no comment",
            None => pk.comment(),
        };
        println!(
            "{} {fp} {comment} ({})",
            pk.bit_length(),
            algorithm_label(&pk)
        );
        if args.visual && !args.bubble {
            let (digest, name) = match args.fp_hash.as_deref() {
                Some("md5") => (md5(&pk.wire_blob()), "MD5"),
                _ => (sha256(&pk.wire_blob()), "SHA256"),
            };
            println!("{}", randomart(&pk, &digest, name));
        }
    }
    Ok(0)
}

/// `user@host`, the default key comment and RFC 4716 "converted by".
fn user_at_host() -> String {
    #[cfg(unix)]
    let pw = unix_sys::passwd_entry(unix_sys::getuid()).map(|(name, _)| name);
    #[cfg(not(unix))]
    let pw: Option<String> = None;
    let user = pw
        .or_else(|| std::env::var("USER").ok())
        .or_else(|| std::env::var("LOGNAME").ok())
        .unwrap_or_else(|| "user".into());
    let host = fs::read_to_string("/proc/sys/kernel/hostname")
        .or_else(|_| fs::read_to_string("/etc/hostname"))
        .map(|h| h.trim().to_string())
        .ok()
        .filter(|h| !h.is_empty())
        .or_else(|| std::env::var("HOSTNAME").ok())
        .unwrap_or_else(|| "localhost".into());
    format!("{user}@{host}")
}

/// `-e`: print a key (public, or a private key's public half) in the `-m`
/// format: RFC 4716 (default), PKCS8 (SubjectPublicKeyInfo) or PEM.
fn run_export(args: &Args) -> Result<i32, String> {
    let file = ensure_file_in(&args.file)?;
    let pk = load_public(&file)?;
    let out = match args
        .format
        .as_deref()
        .unwrap_or("RFC4716")
        .to_ascii_uppercase()
        .as_str()
    {
        "RFC4716" => pk.to_rfc4716(&user_at_host()),
        "PKCS8" | "PEM" if matches!(pk, PublicKey::MlDsa44Ed25519 { .. }) => {
            return Err("unsupported key type MLDSA44-ED25519".into());
        }
        "PKCS8" => pk.to_spki_pem(),
        "PEM" => pk.to_pem(),
        other => return Err(format!("Unsupported conversion format \"{other}\"")),
    };
    print!("{out}");
    Ok(0)
}

/// `-i`: read an RFC 4716, PKCS8 or PEM public key and print it in
/// OpenSSH format.
fn run_import(args: &Args) -> Result<i32, String> {
    let file = ensure_file_in(&args.file)?;
    let text = read_to_string(&file)?;
    let pk = PublicKey::parse_foreign(&text).map_err(|e| format!("{file}: {e}"))?;
    println!("{}", pk.to_authorized_keys_line());
    Ok(0)
}

/// A private key serialised in the `-m` format: the OpenSSH container
/// (default, or `RFC4716`), `PEM` or `PKCS8`.
fn encode_private(sk: &PrivateKey, args: &Args, passphrase: &str) -> Result<String, String> {
    let format = args
        .format
        .as_deref()
        .unwrap_or("RFC4716")
        .to_ascii_uppercase();
    match format.as_str() {
        "RFC4716" | "OPENSSH" => match args.rounds {
            Some(r) => sk.to_openssh_pem_with_rounds(
                (!passphrase.is_empty()).then_some(passphrase.as_bytes()),
                r,
            ),
            None => sk.to_openssh_pem((!passphrase.is_empty()).then_some(passphrase.as_bytes())),
        }
        .map_err(|e| format!("encode: {e}")),
        "PEM" if !passphrase.is_empty() => sk
            .to_traditional_pem_encrypted(&mut purecrypto::rng::OsRng, passphrase.as_bytes())
            .map_err(|e| format!("invalid format: {e}")),
        "PKCS8" if !passphrase.is_empty() => sk
            .to_pkcs8_pem_encrypted(&mut purecrypto::rng::OsRng, passphrase.as_bytes())
            .map_err(|e| format!("invalid format: {e}")),
        "PEM" => sk
            .to_traditional_pem()
            .map_err(|e| format!("invalid format: {e}")),
        "PKCS8" => sk
            .to_pkcs8_pem()
            .map_err(|e| format!("invalid format: {e}")),
        other => Err(format!("Unsupported key format \"{other}\"")),
    }
}

fn run_extract_public(args: &Args) -> Result<i32, String> {
    let file = ensure_file_in(&args.file)?;
    let text = read_to_string(&file)?;
    // `-P` as with OpenSSH (`-N` still accepted).
    let pem_pass = args
        .old_pass
        .as_deref()
        .or(args.new_pass.as_deref())
        .map(String::as_str)
        .filter(|p| !p.is_empty());
    let sk = match PrivateKey::parse_pem(&text, pem_pass.map(str::as_bytes)) {
        Ok(sk) => sk,
        Err(_) if pem_pass.is_none() => {
            let pp = read_passphrase_interactive("Enter passphrase: ")?;
            PrivateKey::parse_pem(
                &text,
                if pp.is_empty() {
                    None
                } else {
                    Some(pp.as_bytes())
                },
            )
            .map_err(|e| format!("{RAW}Load key \"{file}\": {}", load_reason(&e)))?
        }
        Err(e) => return Err(format!("{RAW}Load key \"{file}\": {}", load_reason(&e))),
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
    let sk = match PrivateKey::parse_pem(&text, old_pass.map(str::as_bytes)) {
        Ok(sk) => sk,
        Err(_) if old_pass.is_none() => {
            let pp = read_passphrase_interactive("Enter old passphrase: ")?;
            PrivateKey::parse_pem(
                &text,
                if pp.is_empty() {
                    None
                } else {
                    Some(pp.as_bytes())
                },
            )
            .map_err(|e| format!("{RAW}Failed to load key {file}: {}", load_reason(&e)))?
        }
        Err(e) => {
            return Err(format!(
                "{RAW}Failed to load key {file}: {}",
                load_reason(&e)
            ));
        }
    };

    let new_pass: Zeroizing<String> = if args.new_pass_set {
        args.new_pass.clone().unwrap_or_default()
    } else {
        read_new_passphrase_confirmed("Enter new passphrase (empty for no passphrase): ")?
    };

    let pem = encode_private(&sk, args, &new_pass)?;

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

/// What OpenSSH's `hostkeys_foreach` makes of a known_hosts line.
#[derive(Clone, Copy, PartialEq, Eq)]
enum KhStatus {
    Comment,
    Ok,
    Matched,
    Invalid,
}

/// One known_hosts line, as OpenSSH's `hostkeys_foreach` hands it on.
struct KhLine<'a> {
    num: usize,
    line: &'a str,
    status: KhStatus,
    /// `CA` / `REVOKED`, or empty.
    marker: &'static str,
    hosts: &'a str,
    /// The key and what follows it.
    rawkey: &'a str,
    /// Parsed when asked for (fingerprints).
    key: Option<PublicKey>,
}

/// Key type names OpenSSH knows (`sshkey_type_from_name`), for lines whose
/// key is not parsed.
fn known_key_type(name: &str) -> bool {
    name.starts_with("ssh-ed25519")
        || name.starts_with("ecdsa-sha2-nistp")
        || name.starts_with("ssh-rsa")
        || name.starts_with("rsa-sha2-")
        || name.starts_with("sk-ecdsa-sha2-nistp256")
        || name.starts_with("sk-ssh-ed25519")
        || name.starts_with("ssh-mldsa44-ed25519")
        || name.starts_with("webauthn-sk-")
}

/// `*` / `?` glob, ASCII case-insensitive.
fn kh_glob(pat: &[u8], s: &[u8]) -> bool {
    let (mut p, mut i, mut star, mut mark) = (0usize, 0usize, None, 0usize);
    while i < s.len() {
        if p < pat.len() && (pat[p] == b'?' || pat[p].eq_ignore_ascii_case(&s[i])) {
            p += 1;
            i += 1;
        } else if p < pat.len() && pat[p] == b'*' {
            star = Some(p);
            p += 1;
            mark = i;
        } else if let Some(sp) = star {
            p = sp + 1;
            mark += 1;
            i = mark;
        } else {
            return false;
        }
    }
    while p < pat.len() && pat[p] == b'*' {
        p += 1;
    }
    p == pat.len()
}

/// OpenSSH's `match_maybe_hashed`: `Some(true)` when `host` is one of
/// `hosts` (a `|1|salt|hash` token, or a pattern list where a negated
/// match wins), `None` for a malformed hash.
fn kh_match(host: &str, hosts: &str) -> Option<bool> {
    use puressh::known_hosts::hash::{check_hashed, parse_hashed};
    if hosts.starts_with('|') {
        let (salt, tag) = parse_hashed(hosts)?;
        return Some(check_hashed(&salt, &tag, host, 22));
    }
    let host = host.to_ascii_lowercase();
    let mut matched = false;
    for pat in hosts.split(',') {
        let (neg, pat) = match pat.strip_prefix('!') {
            Some(p) => (true, p),
            None => (false, pat),
        };
        if kh_glob(pat.as_bytes(), host.as_bytes()) {
            if neg {
                return Some(false);
            }
            matched = true;
        }
    }
    Some(matched)
}

/// OpenSSH's `hostkeys_foreach` over `text`: with `host`, lines are
/// matched against it, and with `want_match` only matching ones are
/// returned; `parse_key` parses each line's key.
fn kh_scan<'a>(
    text: &'a str,
    host: Option<&str>,
    want_match: bool,
    parse_key: bool,
) -> Vec<KhLine<'a>> {
    let ws = |c: char| c == ' ' || c == '\t';
    let mut out = Vec::new();
    for (i, line) in text.lines().enumerate() {
        let mut l = KhLine {
            num: i + 1,
            line,
            status: KhStatus::Ok,
            marker: "",
            hosts: "",
            rawkey: "",
            key: None,
        };
        let mut cp = line.trim_start_matches(ws);
        if cp.is_empty() || cp.starts_with('#') {
            if !want_match {
                l.status = KhStatus::Comment;
                out.push(l);
            }
            continue;
        }
        let bad = |mut l: KhLine<'a>, out: &mut Vec<KhLine<'a>>| {
            l.status = KhStatus::Invalid;
            out.push(l);
        };
        if cp.starts_with('@') {
            let (m, rest) = cp.split_at(cp.find(ws).unwrap_or(cp.len()));
            match m {
                "@cert-authority" if !rest.is_empty() => l.marker = "CA",
                "@revoked" if !rest.is_empty() => l.marker = "REVOKED",
                _ => {
                    if !want_match {
                        bad(l, &mut out);
                    }
                    continue;
                }
            }
            cp = rest.trim_start_matches(ws);
        }
        let Some(end) = cp.find(ws) else {
            if !want_match {
                bad(l, &mut out);
            }
            continue;
        };
        l.hosts = &cp[..end];
        if let Some(h) = host {
            match kh_match(h, l.hosts) {
                None => {
                    bad(l, &mut out);
                    continue;
                }
                Some(true) => l.status = KhStatus::Matched,
                Some(false) => {}
            }
            if want_match && l.status != KhStatus::Matched {
                continue;
            }
        }
        let rest = cp[end..].trim_start_matches(ws);
        if rest.is_empty() || rest.starts_with('#') {
            bad(l, &mut out);
            continue;
        }
        l.rawkey = rest;
        if parse_key {
            match PublicKey::parse_authorized_keys_line(rest) {
                Ok(k) => l.key = Some(k),
                Err(_) => {
                    bad(l, &mut out);
                    continue;
                }
            }
        } else {
            let tl = rest.find(ws).unwrap_or(rest.len());
            let ktype = &rest[..tl];
            let after = rest[tl..].trim_start_matches(ws);
            if tl <= 1 || tl >= 128 || tl == rest.len() {
                bad(l, &mut out);
                continue;
            }
            if !known_key_type(ktype) || after.is_empty() || after.starts_with('#') {
                bad(l, &mut out);
                continue;
            }
        }
        out.push(l);
    }
    out
}

/// A fresh `|1|salt|hash` for `host`.
fn kh_hash(host: &str) -> String {
    let mut salt = [0u8; 20];
    OsRng.fill_bytes(&mut salt);
    puressh::known_hosts::hash::encode_hashed(&salt, host)
}

/// OpenSSH's `known_hosts_hash` for one line: hashed lines, ones with
/// wildcards or a marker are kept; otherwise each of its names becomes a
/// hashed line of its own. Returns the lines to write and whether any
/// names were hashed.
fn kh_hash_line(l: &KhLine<'_>, path: &str, find: bool) -> (Vec<String>, bool) {
    let has_wild = l.hosts.contains(['*', '?', '!']);
    let was_hashed = l.hosts.starts_with('|');
    match l.status {
        KhStatus::Ok | KhStatus::Matched => {
            if was_hashed || has_wild || !l.marker.is_empty() {
                if has_wild && !find {
                    let shown: String = l.hosts.chars().take(64).collect();
                    eprintln!(
                        "{path}:{}: ignoring host name with wildcard: {shown}",
                        l.num
                    );
                }
                return (vec![l.line.to_string()], false);
            }
            let lines: Vec<String> = l
                .hosts
                .split(',')
                .take_while(|h| !h.is_empty())
                .map(|h| format!("{} {}", kh_hash(&h.to_ascii_lowercase()), l.rawkey))
                .collect();
            let any = !lines.is_empty();
            (lines, any)
        }
        _ => (vec![l.line.to_string()], false),
    }
}

/// Replace `path` with `contents`, keeping the original as `path.old`, and
/// say so, as OpenSSH's `do_known_hosts`.
fn kh_replace(path: &str, contents: &str) -> Result<(), String> {
    let old = format!("{path}.old");
    let tmp = format!("{path}.{:010}", OsRng.next_u32());
    std::fs::write(&tmp, contents).map_err(|e| format!("{tmp}: {}", io_reason(&e)))?;
    if let Ok(meta) = std::fs::metadata(path) {
        let _ = std::fs::set_permissions(&tmp, meta.permissions());
    }
    let _ = std::fs::remove_file(&old);
    if let Err(e) = std::fs::hard_link(path, &old) {
        let _ = std::fs::remove_file(&tmp);
        return Err(format!("link {path} to {old}: {}", io_reason(&e)));
    }
    if let Err(e) = std::fs::rename(&tmp, path) {
        let _ = std::fs::remove_file(&tmp);
        let _ = std::fs::remove_file(&old);
        return Err(format!("rename\"{tmp}\" to \"{path}\": {}", io_reason(&e)));
    }
    println!("{path} updated.");
    println!("Original contents retained as {old}");
    Ok(())
}

/// The refusal for a known_hosts file with invalid lines.
fn kh_invalid(path: &str, inplace: bool) -> i32 {
    eprintln!("{path} is not a valid known_hosts file.");
    if inplace {
        eprintln!("Not replacing existing known_hosts file because of errors");
    }
    1
}

/// `-R host`: remove the host's lines (not `@cert-authority` /
/// `@revoked` ones), as OpenSSH: the original is kept as `<file>.old`.
fn run_known_hosts_remove(args: &Args, host: &str) -> Result<i32, String> {
    let path = resolve_known_hosts_path(args)?;
    let text = std::fs::read_to_string(&path).map_err(|e| format!("{path}: {}", io_reason(&e)))?;
    let mut kept = String::with_capacity(text.len());
    let (mut found, mut invalid) = (false, false);
    for l in kh_scan(&text, Some(host), false, false) {
        if l.status == KhStatus::Matched && l.marker.is_empty() {
            found = true;
            if !args.quiet {
                println!("# Host {host} found: line {}", l.num);
            }
            continue;
        }
        if l.status == KhStatus::Invalid {
            invalid = true;
            eprintln!("{path}:{}: invalid line", l.num);
        }
        kept.push_str(l.line);
        kept.push('\n');
    }
    if invalid {
        return Ok(kh_invalid(&path, true));
    }
    if !found {
        eprintln!("Host {host} not found in {path}");
        return Ok(0);
    }
    kh_replace(&path, &kept)?;
    Ok(0)
}

/// `-F host`: print the host's lines, each after OpenSSH's `# Host …
/// found: line N` header (`-q`: lines only); `-H` prints them hashed and
/// `-l` as fingerprints. Exit 1 if none.
fn run_known_hosts_find(args: &Args, host: &str) -> Result<i32, String> {
    let path = resolve_known_hosts_path(args)?;
    let text = std::fs::read_to_string(&path).map_err(|e| format!("{path}: {}", io_reason(&e)))?;
    let mut found = false;
    for l in kh_scan(&text, Some(host), true, args.fingerprint) {
        if l.status != KhStatus::Matched {
            continue;
        }
        found = true;
        if !args.quiet {
            println!("# Host {host} found: line {} {}", l.num, l.marker);
        }
        if args.hash_all {
            for line in kh_hash_line(&l, &path, true).0 {
                println!("{line}");
            }
        } else if let Some(pk) = l.key.as_ref().filter(|_| args.fingerprint) {
            let fp = fingerprint_text(pk, args)?;
            let comment = pk.comment();
            let sep = if comment.is_empty() { "" } else { " " };
            println!("{host} {} {fp}{sep}{comment}", algorithm_label(pk));
        } else {
            println!("{}", l.line);
        }
    }
    Ok(if found { 0 } else { 1 })
}

/// An I/O error as OpenSSH words it (`No such file or directory`).
fn io_reason(e: &std::io::Error) -> String {
    let s = e.to_string();
    match s.find(" (os error") {
        Some(i) => s[..i].to_string(),
        None => s,
    }
}

/// `-H`: hash every name in the file, as OpenSSH: lines already hashed,
/// with wildcards or a marker are kept as they are; the original is kept
/// as `<file>.old`.
fn run_known_hosts_hash(args: &Args) -> Result<i32, String> {
    let path = resolve_known_hosts_path(args)?;
    let text = std::fs::read_to_string(&path).map_err(|e| format!("{path}: {}", io_reason(&e)))?;
    let mut out = String::with_capacity(text.len() * 2);
    let (mut invalid, mut unhashed) = (false, false);
    for l in kh_scan(&text, None, false, false) {
        if l.status == KhStatus::Invalid {
            invalid = true;
            eprintln!("{path}:{}: invalid line", l.num);
        }
        let (lines, any) = kh_hash_line(&l, &path, false);
        unhashed |= any;
        for line in lines {
            out.push_str(&line);
            out.push('\n');
        }
    }
    if invalid {
        return Ok(kh_invalid(&path, true));
    }
    kh_replace(&path, &out)?;
    if unhashed {
        eprintln!("WARNING: {path}.old contains unhashed entries");
        eprintln!("Delete this file to ensure privacy of hostnames");
    }
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
    if let Some(mode) = &parsed.moduli {
        return match moduli::run(mode, &parsed) {
            Ok(code) => Ok(code),
            Err(msg) => {
                eprintln!("{msg}");
                Err(255)
            }
        };
    }
    if let Some(op) = &parsed.sig_op {
        return match sig::run(op, &parsed) {
            Ok(code) => Ok(code),
            Err(msg) => {
                eprintln!("{msg}");
                Err(255)
            }
        };
    }
    if let Some(a) = parsed
        .rest
        .first()
        .filter(|_| parsed.sig_file.is_none() && !parsed.krl && !parsed.krl_query)
    {
        eprintln!("ssh-keygen: unexpected argument: {a}");
        eprintln!("{USAGE}");
        return Err(2);
    }

    let mut parsed = parsed;
    // KRL and SSHFP modes reuse -s / -z / -l / -f; handle them first.
    let early = if parsed.krl {
        Some(krl::build(&parsed))
    } else if parsed.krl_query {
        Some(krl::query(&parsed))
    } else {
        parsed.sshfp.as_ref().map(|host| run_sshfp(&parsed, host))
    };
    if let Some(res) = early {
        return match res {
            Ok(code) => Ok(code),
            Err(msg) => {
                eprintln!("ssh-keygen: {msg}");
                Err(1)
            }
        };
    }
    if parsed.bubble {
        parsed.fingerprint = true;
    }
    // `-H` and `-l` modify `-F` (hashed / fingerprinted output).
    let finding = parsed.find_host.is_some();
    let mode_count = [
        (parsed.fingerprint && !finding) as u8,
        parsed.export as u8,
        parsed.import as u8,
        parsed.derive_pub as u8,
        parsed.change_pass as u8,
        parsed.type_.is_some() as u8,
        parsed.remove_host.is_some() as u8,
        parsed.find_host.is_some() as u8,
        (parsed.hash_all && !finding) as u8,
        parsed.host_keys as u8,
        parsed.sig_file.is_some() as u8,
        parsed.list_cert as u8,
    ]
    .iter()
    .sum::<u8>();
    // No mode: generate a key, as with OpenSSH (Ed25519 by default).
    if mode_count > 1 {
        eprintln!(
            "ssh-keygen: -t / -l / -y / -p / -R / -F / -H / -A / -s / -L are mutually exclusive"
        );
        return Err(2);
    }

    #[cfg(feature = "security-key")]
    if let Some(p) = &parsed.sk_provider {
        let _ = security_key::PROVIDER.set(p.clone());
    }
    let res = if parsed.fingerprint && !finding {
        run_fingerprint(&parsed)
    } else if parsed.export {
        run_export(&parsed)
    } else if parsed.import {
        run_import(&parsed)
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
    } else if parsed.download_sk {
        #[cfg(feature = "security-key")]
        {
            security_key::download(&parsed)
        }
        #[cfg(not(feature = "security-key"))]
        Err("security key support not enabled".into())
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
            match msg.strip_prefix(RAW) {
                Some(raw) => eprintln!("{raw}"),
                None => eprintln!("ssh-keygen: {msg}"),
            }
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
        /// The agent, its signature flags, and the identity to sign with
        /// when not the key itself (a certificate).
        #[cfg(unix)]
        Agent(puressh::agent::Agent, u32, Option<Vec<u8>>),
    }

    impl Signer {
        /// An SSH signature blob over `data` by the key `pk`.
        pub(super) fn sign(&mut self, pk: &PublicKey, data: &[u8]) -> puressh::Result<Vec<u8>> {
            #[cfg(not(unix))]
            let _ = pk;
            match self {
                Signer::Key(k) => k.sign(data),
                #[cfg(unix)]
                Signer::Agent(a, flags, ident) => match ident {
                    Some(blob) => a.sign(blob, data, *flags),
                    None => a.sign(&pk.wire_blob(), data, *flags),
                },
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
                return Ok((Signer::Agent(agent, flags, None), pk));
            }
        }
        load_private_signer(path, &text)
    }

    /// The private key at `path` (`text`), asking for its passphrase.
    fn load_private_signer(path: &str, text: &str) -> Result<(Signer, PublicKey), String> {
        let sk = match PrivateKey::parse_pem(text, None) {
            Ok(k) => k,
            Err(_) => {
                let pp =
                    read_passphrase_interactive(&format!("Enter passphrase for \"{path}\": "))?;
                PrivateKey::parse_pem(text, Some(pp.as_bytes()))
                    .map_err(|e| format!("Couldn't load key {path}: {e}"))?
            }
        };
        let pk = sk.public_key();
        #[cfg(feature = "security-key")]
        if sk.sk_credential().is_some() {
            return Ok((Signer::Key(super::security_key::signer(path, sk)?), pk));
        }
        let key = sk.into_host_key().map_err(|e| format!("{path}: {e}"))?;
        Ok((Signer::Key(key), pk))
    }

    /// The public half `-Y sign -f path` names, as `sshkey_load_public`:
    /// the file as a key or certificate, else `path.pub`, else derived
    /// from the private key. Returns the key and the identity signatures
    /// carry (the certificate, when it is one).
    fn load_signing_public(path: &str) -> Result<(PublicKey, Vec<u8>), String> {
        let parse = |text: &str| -> Option<(PublicKey, Vec<u8>)> {
            let line = text.trim();
            if let Ok(c) = puressh::cert::Certificate::parse_openssh_line(line) {
                let pk = PublicKey::parse_wire_blob(c.embedded_pubkey_blob()).ok()?;
                return Some((pk, c.raw));
            }
            let pk = PublicKey::parse_authorized_keys_line(line).ok()?;
            let blob = pk.wire_blob();
            Some((pk, blob))
        };
        let text = std::fs::read_to_string(path)
            .map_err(|e| format!("Couldn't load public key {path}: {e}"))?;
        if let Some(v) = parse(&text) {
            return Ok(v);
        }
        if let Some(v) = std::fs::read_to_string(format!("{path}.pub"))
            .ok()
            .and_then(|t| parse(&t))
        {
            return Ok(v);
        }
        let pk = PrivateKey::public_key_from_pem(&text)
            .map_err(|e| format!("Couldn't load public key {path}: {e}"))?;
        let blob = pk.wire_blob();
        Ok((pk, blob))
    }

    /// OpenSSH's `sig_sign` key choice: the agent when it holds the key
    /// (required with `-U`), else the private key at `path` without its
    /// `-cert.pub` / `.pub` suffix. Returns the signer, the key and the
    /// identity the signature carries (a certificate signs as itself).
    fn load_sign_key(
        path: &str,
        require_agent: bool,
    ) -> Result<(Signer, PublicKey, Vec<u8>), String> {
        let (pk, ident) = load_signing_public(path)?;
        #[cfg(unix)]
        match puressh::agent::Agent::connect_env() {
            Ok(Some(mut agent)) => {
                let has = agent
                    .identities()
                    .is_ok_and(|ids| ids.iter().any(|i| i.key_blob() == ident.as_slice()));
                if has {
                    // SSH_AGENT_RSA_SHA2_512: OpenSSH signs with rsa-sha2-512.
                    let flags = if matches!(pk, PublicKey::Rsa { .. }) {
                        4
                    } else {
                        0
                    };
                    let id = (ident != pk.wire_blob()).then(|| ident.clone());
                    return Ok((Signer::Agent(agent, flags, id), pk, ident));
                }
                if require_agent {
                    return Err("Couldn't find key in agent".into());
                }
            }
            _ if require_agent => return Err("Couldn't get agent socket".into()),
            _ => {}
        }
        #[cfg(not(unix))]
        if require_agent {
            return Err("signing with an agent is not supported on this platform".into());
        }
        let mut privpath = path;
        for suffix in ["-cert.pub", ".pub"] {
            if let Some(p) = privpath.strip_suffix(suffix).filter(|p| !p.is_empty()) {
                privpath = p;
            }
        }
        let text = std::fs::read_to_string(privpath)
            .map_err(|e| format!("Couldn't load key {privpath}: {e}"))?;
        let (signer, sk_pk) = load_private_signer(privpath, &text)?;
        if sk_pk.wire_blob() != pk.wire_blob() {
            return Err(format!(
                "Public key {path} doesn't match private {privpath}"
            ));
        }
        Ok((signer, pk, ident))
    }

    fn sign_digest(
        signer: &mut Signer,
        (pk, ident): (&PublicKey, &[u8]),
        namespace: &str,
        hash: HashAlg,
        digest: &[u8],
    ) -> Result<String, String> {
        let sig = Signature::create(ident.to_vec(), namespace, hash, digest, |data| {
            signer.sign(pk, data)
        })
        .map_err(|e| format!("Signing failed: {e}"))?;
        Ok(sig.to_armored())
    }

    fn sign(args: &Args, hash: HashAlg) -> Result<i32, String> {
        let key_path = require(&args.file, "key file (-f)")?;
        let namespace = require(&args.namespace, "namespace (-n)")?;
        let (mut signer, pk, ident) = load_sign_key(key_path, args.use_agent)?;
        let files: Vec<&str> = if args.rest.is_empty() {
            vec!["-"]
        } else {
            args.rest.iter().map(String::as_str).collect()
        };
        for f in files {
            if f == "-" {
                if !args.quiet {
                    eprintln!("Signing data on standard input");
                }
                let digest = hash
                    .digest_reader(std::io::stdin().lock())
                    .map_err(|e| format!("read stdin: {e}"))?;
                let armored = sign_digest(&mut signer, (&pk, &ident), namespace, hash, &digest)?;
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
            let armored = sign_digest(&mut signer, (&pk, &ident), namespace, hash, &digest)?;
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
        // A certificate is shown as the key it certifies.
        let pk = match puressh::cert::Certificate::parse(&sig.public_key) {
            Ok(c) => PublicKey::parse_wire_blob(c.embedded_pubkey_blob()),
            Err(_) => PublicKey::parse_wire_blob(&sig.public_key),
        };
        let mut result = sig
            .verify(namespace, &digest)
            .map_err(|e| format!("Signature verification failed: {e}"));
        // `-r`: a revoked key (or certificate CA) fails the check.
        if result.is_ok()
            && let Some(rev) = &args.sshfp
            && revoked(rev, &sig.public_key)?
        {
            result = Err("Signature key is revoked".into());
        }
        let mut principal = None;
        if validate && result.is_ok() {
            let allowed =
                read_allowed_signers(require(&args.file, "allowed signers file (-f)")?, now)?;
            let id = require(&args.identity, "signer identity (-I)")?;
            let found = allowed
                .iter()
                .any(|s| s.accepts(&sig.public_key, id, now) && s.allows_namespace(namespace));
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
                    let cert = if sig.is_certificate() { "-CERT" } else { "" };
                    let ty = format!("{}{cert}", algorithm_label(&pk));
                    match principal {
                        Some(p) => {
                            println!("Good \"{namespace}\" signature for {p} with {ty} key {fp}")
                        }
                        None => println!("Good \"{namespace}\" signature with {ty} key {fp}"),
                    }
                }
                if print_pubkey {
                    // The key the signature carries (a certificate as is).
                    match puressh::cert::Certificate::parse(&sig.public_key) {
                        Ok(c) => println!("{}", c.to_openssh_line("")),
                        Err(_) => {
                            let line = pk.to_authorized_keys_line();
                            let bare: Vec<&str> = line.split_whitespace().take(2).collect();
                            println!("{}", bare.join(" "));
                        }
                    }
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

    /// OpenSSH's `sshkey_check_revoked`: whether the revocation file
    /// (a KRL, or a list of keys) revokes `key`, or for a certificate, its
    /// key or its CA.
    fn revoked(path: &str, key: &[u8]) -> Result<bool, String> {
        let data = std::fs::read(path).map_err(|e| format!("{path}: {e}"))?;
        let cert = puressh::cert::Certificate::parse(key).ok();
        let plain = cert.as_ref().map_or(key, |c| c.embedded_pubkey_blob());
        if let Ok(krl) = puressh::krl::Krl::parse(&data) {
            return Ok(krl.is_revoked_key(plain)
                || cert.as_ref().is_some_and(|c| {
                    krl.is_revoked_cert(&c.signature_key_blob, c.serial, &c.key_id)
                        || krl.is_revoked_key(&c.signature_key_blob)
                }));
        }
        let text = String::from_utf8_lossy(&data);
        for line in text.lines().map(str::trim) {
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let listed = match puressh::cert::Certificate::parse_openssh_line(line) {
                Ok(c) => c.embedded_pubkey_blob().to_vec(),
                Err(_) => match PublicKey::parse_authorized_keys_line(line) {
                    Ok(pk) => pk.wire_blob(),
                    Err(_) => continue,
                },
            };
            if listed == plain
                || cert
                    .as_ref()
                    .is_some_and(|c| listed == c.signature_key_blob)
            {
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn find_principals(args: &Args, now: i64) -> Result<i32, String> {
        let sig = read_signature(require(&args.sig_file, "signature file (-s)")?)?;
        let allowed = read_allowed_signers(require(&args.file, "allowed signers file (-f)")?, now)?;
        let mut found = false;
        for s in &allowed {
            if s.is_key(&sig.public_key, now) {
                for p in s.principals.split(',') {
                    println!("{p}");
                }
                found = true;
            } else if let Some(ps) = s.certified_principals(&sig.public_key, now) {
                println!("{}", ps.join(","));
                found = true;
            }
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

/// `-r host`: DNS SSHFP records for a key (`-f`) or every host key.
fn run_sshfp(args: &Args, host: &str) -> Result<i32, String> {
    // `-O hashalg=sha1|sha256`: that digest only.
    let mut only: Option<u8> = None;
    for o in &args.sig_options {
        match o.strip_prefix("hashalg=") {
            Some(a) if a.eq_ignore_ascii_case("sha1") => only = Some(1),
            Some(a) if a.eq_ignore_ascii_case("sha256") => only = Some(2),
            Some(a) => return Err(format!("Unsupported hash algorithm \"{a}\"")),
            None => return Err(format!("Invalid option \"{o}\"")),
        }
    }
    let files: Vec<String> = match &args.file {
        Some(f) => vec![f.clone()],
        None => ["rsa", "ecdsa", "ed25519", "mldsa44_ed25519"]
            .iter()
            .map(|t| format!("/etc/ssh/ssh_host_{t}_key.pub"))
            .filter(|p| Path::new(p).exists())
            .collect(),
    };
    for f in files {
        let pk = load_public(&f)?;
        let Some(alg) = pk.sshfp_algorithm() else {
            continue;
        };
        for (fptype, digest) in [(1u8, sha1(&pk.wire_blob())), (2, sha256(&pk.wire_blob()))] {
            if only.is_some_and(|t| t != fptype) {
                continue;
            }
            let hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
            if args.sshfp_generic {
                println!(
                    "{host} IN TYPE44 \\# {} {alg:02x} {fptype:02x} {hex}",
                    2 + digest.len()
                );
            } else {
                println!("{host} IN SSHFP {alg} {fptype} {hex}");
            }
        }
    }
    Ok(0)
}

/// `-k` / `-Q`: key revocation lists.
mod krl {
    use super::{Args, PublicKey, load_public, read_to_string};
    use puressh::cert::Certificate;
    use puressh::krl::Krl;

    fn decode_fp(v: &str) -> Option<(bool, Vec<u8>)> {
        let (sha256, b64) = if let Some(b) = v.strip_prefix("SHA256:") {
            (true, b)
        } else {
            (false, v.strip_prefix("SHA1:")?)
        };
        let mut padded = b64.to_string();
        while padded.len() % 4 != 0 {
            padded.push('=');
        }
        let raw = purecrypto::der::base64_decode(&padded).ok()?;
        let want = if sha256 { 32 } else { 20 };
        (raw.len() == want).then_some((sha256, raw))
    }

    fn revoke_line_key(krl: &mut Krl, line: &str) -> Result<(), String> {
        if let Ok(cert) = Certificate::parse_openssh_line(line) {
            if cert.serial != 0 || cert.key_id.is_empty() {
                krl.revoke_cert_serials(&cert.signature_key_blob, cert.serial, cert.serial);
            } else {
                krl.revoke_cert_key_id(&cert.signature_key_blob, &cert.key_id);
            }
            return Ok(());
        }
        let pk = PublicKey::parse_authorized_keys_line(line).map_err(|e| e.to_string())?;
        krl.revoke_key(&pk.wire_blob());
        Ok(())
    }

    fn parse_serial(v: &str) -> Option<u64> {
        match v.strip_prefix("0x") {
            Some(h) => u64::from_str_radix(h, 16).ok(),
            None => v.parse().ok(),
        }
    }

    fn update_from(krl: &mut Krl, ca: Option<&[u8]>, path: &str) -> Result<(), String> {
        let text = if path == "-" {
            let mut s = String::new();
            std::io::Read::read_to_string(&mut std::io::stdin(), &mut s)
                .map_err(|e| format!("stdin: {e}"))?;
            s
        } else {
            read_to_string(path)?
        };
        for (n, raw) in text.lines().enumerate() {
            let line = raw.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let at = |e: String| format!("{path}:{}: {e}", n + 1);
            let need_ca = || ca.ok_or_else(|| at("missing CA key (-s)".into()));
            let (kw, val) = match line.split_once(':') {
                Some((k, v)) if !k.contains(' ') => (k.to_ascii_lowercase(), v.trim()),
                _ => (String::new(), line),
            };
            match kw.as_str() {
                "serial" => {
                    let ca = need_ca()?;
                    let (lo, hi) = match val.split_once('-') {
                        Some((a, b)) => (parse_serial(a.trim()), parse_serial(b.trim())),
                        None => (parse_serial(val), parse_serial(val)),
                    };
                    let (Some(lo), Some(hi)) = (lo, hi) else {
                        return Err(at(format!("invalid serial \"{val}\"")));
                    };
                    if lo > hi {
                        return Err(at(format!("invalid serial range \"{val}\"")));
                    }
                    krl.revoke_cert_serials(ca, lo, hi);
                }
                "id" => krl.revoke_cert_key_id(need_ca()?, val),
                "key" => revoke_line_key(krl, val).map_err(at)?,
                "sha1" | "sha256" => {
                    let blob = PublicKey::parse_authorized_keys_line(val)
                        .map(|k| k.wire_blob())
                        .map_err(|e| at(e.to_string()))?;
                    if kw == "sha1" {
                        krl.revoke_sha1(super::sha1(&blob).try_into().expect("20 bytes"));
                    } else {
                        krl.revoke_sha256(super::sha256(&blob).try_into().expect("32 bytes"));
                    }
                }
                "hash" => match decode_fp(val) {
                    Some((true, raw)) => krl.revoke_sha256(raw.try_into().expect("32 bytes")),
                    Some((false, raw)) => krl.revoke_sha1(raw.try_into().expect("20 bytes")),
                    None => return Err(at(format!("invalid fingerprint \"{val}\""))),
                },
                // A plain public key or certificate line (its key type
                // contains no ':').
                _ => revoke_line_key(krl, line).map_err(at)?,
            }
        }
        Ok(())
    }

    pub(super) fn build(args: &Args) -> Result<i32, String> {
        let path = args.file.as_deref().ok_or("-f krl_file is required")?;
        let mut krl = if args.krl_update {
            let data = std::fs::read(path).map_err(|e| format!("{path}: {e}"))?;
            Krl::parse(&data).map_err(|e| format!("{path}: {e}"))?
        } else {
            Krl::new()
        };
        // `-s none`: serial and key id revocations for any CA.
        let ca = match &args.sig_file {
            Some(f) if f.eq_ignore_ascii_case("none") => Some(Vec::new()),
            Some(f) => Some(load_public(f)?.wire_blob()),
            None => None,
        };
        if let Some(z) = &args.serial {
            krl.set_version(
                z.parse()
                    .map_err(|_| format!("Invalid KRL version \"{z}\""))?,
            );
        }
        for f in &args.rest {
            update_from(&mut krl, ca.as_deref(), f)?;
        }
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        std::fs::write(path, krl.to_bytes(now)).map_err(|e| format!("{path}: {e}"))?;
        Ok(0)
    }

    pub(super) fn query(args: &Args) -> Result<i32, String> {
        let path = args.file.as_deref().ok_or("-f krl_file is required")?;
        let data = std::fs::read(path).map_err(|e| format!("{path}: {e}"))?;
        let krl = Krl::parse(&data).map_err(|e| format!("{path}: {e}"))?;
        if args.fingerprint {
            println!("# KRL version {}", krl.version());
            if !krl.comment().is_empty() {
                println!("# Comment: {}", krl.comment());
            }
        }
        let mut revoked_any = false;
        for f in &args.rest {
            let text = read_to_string(f)?;
            for line in text
                .lines()
                .map(str::trim)
                .filter(|l| !l.is_empty() && !l.starts_with('#'))
            {
                let (revoked, comment) = if let Ok(cert) = Certificate::parse_openssh_line(line) {
                    let r =
                        krl.is_revoked_cert(&cert.signature_key_blob, cert.serial, &cert.key_id)
                            || krl.is_revoked_key(cert.embedded_pubkey_blob())
                            || krl.is_revoked_key(&cert.signature_key_blob);
                    (r, line.split_whitespace().nth(2).unwrap_or("").to_string())
                } else {
                    let pk = PublicKey::parse_authorized_keys_line(line)
                        .map_err(|e| format!("{f}: {e}"))?;
                    (
                        krl.is_revoked_key(&pk.wire_blob()),
                        pk.comment().to_string(),
                    )
                };
                let label = if comment.is_empty() {
                    f.clone()
                } else {
                    format!("{f} ({comment})")
                };
                println!("{label}: {}", if revoked { "REVOKED" } else { "ok" });
                revoked_any |= revoked;
            }
        }
        Ok(if revoked_any { 1 } else { 0 })
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
            let pk = super::load_public_any(path)?;
            let mut nonce = vec![0u8; 32];
            OsRng.fill_bytes(&mut nonce);
            let mut b = CertificateBuilder::new(pk.wire_blob(), cert_type, nonce);
            b.serial = serial;
            b.key_id = key_id.to_string();
            b.valid_principals = principals.clone();
            b.valid_after = valid_after;
            b.valid_before = valid_before;
            // Host certificates start without the default user
            // extensions; options given with -O apply to both, as with
            // OpenSSH (a host certificate with critical options is then
            // refused by clients).
            if cert_type == CertType::User {
                b.extensions = DEFAULT_USER_EXTENSIONS
                    .iter()
                    .map(|e| (e.to_string(), Vec::new()))
                    .collect();
            }
            apply_options(&mut b, &args.sig_options)?;
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
        let text = std::fs::read_to_string(path)
            .map_err(|e| format!("{path}: {}", super::io_reason(&e)))?;
        let cert = Certificate::parse_openssh_line(text.trim())
            .map_err(|_| format!("{}{path}:1 is not a certificate", super::RAW))?;
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

/// `-M generate` / `-M screen`: Diffie-Hellman group moduli, a port of
/// OpenSSH's `moduli.c`. Generation sieves candidate Sophie Germain
/// primes `q` (with `p = 2q + 1`) from a random start; screening runs
/// Miller-Rabin over candidates and keeps the safe primes, in the
/// `/etc/ssh/moduli` format.
mod moduli {
    use super::{Args, local_offset, now};
    use purecrypto::bignum::{BoxedMontModulus, BoxedUint};
    use purecrypto::rng::{OsRng, RngCore};
    use std::io::{BufRead, Write};

    const MODULI_TYPE_UNKNOWN: u32 = 0;
    const MODULI_TYPE_UNSTRUCTURED: u32 = 1;
    const MODULI_TYPE_SAFE: u32 = 2;
    const MODULI_TYPE_SCHNORR: u32 = 3;
    const MODULI_TYPE_SOPHIE_GERMAIN: u32 = 4;
    const MODULI_TYPE_STRONG: u32 = 5;
    const MODULI_TESTS_COMPOSITE: u32 = 0x01;
    const MODULI_TESTS_SIEVE: u32 = 0x02;
    const MODULI_TESTS_MILLER_RABIN: u32 = 0x04;

    const QSIZE_MINIMUM: u32 = 511;
    const TEST_MAXIMUM: u32 = 1 << 16;
    const TEST_MINIMUM: u32 = QSIZE_MINIMUM + 1;
    const TRIAL_MINIMUM: u32 = 4;
    const TINY_NUMBER: u32 = 1 << 16;
    const SMALL_MAXIMUM: u64 = 0xffff_ffff;
    /// Megabytes of sieve, as OpenSSH (its `LARGE_MAXIMUM`).
    const LARGE_MAXIMUM: u32 = 127;
    const DEFAULT_BITS: u32 = 3072;

    /// A big-endian unsigned number as bytes, minimal length.
    type Num = Vec<u8>;

    fn trim(mut n: Num) -> Num {
        let z = n.iter().take_while(|b| **b == 0).count();
        n.drain(..z.min(n.len().saturating_sub(1)));
        n
    }

    fn from_hex(s: &str) -> Option<Num> {
        let s = s.trim();
        if s.is_empty() || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
            return None;
        }
        let padded = if s.len() % 2 == 1 {
            format!("0{s}")
        } else {
            s.to_string()
        };
        let bytes = (0..padded.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&padded[i..i + 2], 16).ok())
            .collect::<Option<Vec<u8>>>()?;
        Some(trim(bytes))
    }

    /// Upper-case hex without leading zeros (`BN_print_fp`).
    fn to_hex(n: &[u8]) -> String {
        let s: String = n.iter().map(|b| format!("{b:02X}")).collect();
        let t = s.trim_start_matches('0');
        if t.is_empty() { "0".into() } else { t.into() }
    }

    fn bits(n: &[u8]) -> u32 {
        match n.iter().position(|b| *b != 0) {
            Some(i) => (n.len() - i) as u32 * 8 - n[i].leading_zeros(),
            None => 0,
        }
    }

    fn mod_word(n: &[u8], w: u64) -> u64 {
        n.iter().fold(0u64, |r, b| (r * 256 + u64::from(*b)) % w)
    }

    /// `n` as big-endian 64-bit limbs, for repeated [`mod_limbs`].
    fn limbs(n: &[u8]) -> Vec<u64> {
        let pad = (8 - n.len() % 8) % 8;
        let mut padded = vec![0u8; pad];
        padded.extend_from_slice(n);
        padded
            .as_chunks::<8>()
            .0
            .iter()
            .map(|c| u64::from_be_bytes(*c))
            .collect()
    }

    /// `n mod w` over 64-bit limbs (the sieve's hot path).
    fn mod_limbs(n: &[u64], w: u64) -> u64 {
        let w = u128::from(w);
        n.iter()
            .fold(0u128, |r, l| ((r << 64) | u128::from(*l)) % w) as u64
    }

    fn add_small(n: &[u8], k: u64) -> Num {
        let mut out = n.to_vec();
        let mut carry = k;
        for b in out.iter_mut().rev() {
            if carry == 0 {
                break;
            }
            let v = u64::from(*b) + (carry & 0xff);
            *b = v as u8;
            carry = (carry >> 8) + (v >> 8);
        }
        while carry > 0 {
            out.insert(0, carry as u8);
            carry >>= 8;
        }
        trim(out)
    }

    fn shl1(n: &[u8]) -> Num {
        let mut out = vec![0u8; n.len() + 1];
        for (i, b) in n.iter().enumerate() {
            out[i] |= b >> 7;
            out[i + 1] = b << 1;
        }
        trim(out)
    }

    fn shr1(n: &[u8]) -> Num {
        let mut out = vec![0u8; n.len()];
        let mut carry = 0u8;
        for (i, b) in n.iter().enumerate() {
            out[i] = (b >> 1) | carry;
            carry = b << 7;
        }
        trim(out)
    }

    /// Odd primes below 2000, for trial division ahead of Miller-Rabin.
    fn small_primes() -> Vec<u64> {
        (3u64..2000)
            .step_by(2)
            .filter(|n| {
                (3..)
                    .step_by(2)
                    .take_while(|d| d * d <= *n)
                    .all(|d| n % d != 0)
            })
            .collect()
    }

    /// Miller-Rabin with `rounds` random bases (after trial division by
    /// small primes, as OpenSSL's `BN_is_prime_ex`).
    fn is_probable_prime(n: &[u8], rounds: u32, primes: &[u64]) -> bool {
        if bits(n) < 3 || n[n.len() - 1] & 1 == 0 {
            return false;
        }
        for &p in primes {
            if mod_word(n, p) == 0 {
                return bits(n) <= 11 && n.iter().fold(0u64, |a, b| a * 256 + u64::from(*b)) == p;
            }
        }
        let len = n.len();
        let nn = BoxedUint::from_be_bytes(n);
        let mont = BoxedMontModulus::new(&nn);
        let mut n1 = n.to_vec();
        n1[len - 1] &= 0xfe; // n - 1 (n is odd)
        let n_minus_1 = BoxedUint::from_be_bytes(&n1);
        let s = n1
            .iter()
            .rev()
            .position(|b| *b != 0)
            .map_or(0, |i| i * 8 + n1[len - 1 - i].trailing_zeros() as usize);
        let d = n_minus_1.shr_bits(s);
        let n_minus_3 = BoxedUint::from_be_bytes(&{
            let mut v = n1.clone();
            // n - 3 = (n - 1) - 2; n - 1 is even and > 2 here.
            let mut borrow = 2u16;
            for b in v.iter_mut().rev() {
                let cur = u16::from(*b);
                if cur >= borrow {
                    *b = (cur - borrow) as u8;
                    break;
                }
                *b = (cur + 256 - borrow) as u8;
                borrow = 1;
            }
            v
        });
        let eq = |a: &BoxedUint, b: &BoxedUint| a.to_be_bytes(len) == b.to_be_bytes(len);
        let one = BoxedUint::from_u64(1);
        let mut rng = OsRng;
        'rounds: for _ in 0..rounds {
            let mut r = vec![0u8; len + 8];
            rng.fill_bytes(&mut r);
            let a = BoxedUint::from_be_bytes(&r)
                .reduce(&n_minus_3)
                .add(&BoxedUint::from_u64(2));
            let mut x = mont.pow_public(&a, &d);
            if eq(&x, &one) || eq(&x, &n_minus_1) {
                continue;
            }
            for _ in 1..s {
                x = mont.mul_mod(&x, &x);
                if eq(&x, &n_minus_1) {
                    continue 'rounds;
                }
                if eq(&x, &one) {
                    return false;
                }
            }
            return false;
        }
        true
    }

    /// `ctime()`'s first 24 characters, local time.
    fn ctime(t: i64) -> String {
        let local = t + local_offset(t);
        let days = local.div_euclid(86_400);
        let secs = local.rem_euclid(86_400);
        let (y, m, d) = civil(days);
        const WD: [&str; 7] = ["Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed"];
        const MON: [&str; 12] = [
            "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
        ];
        format!(
            "{} {} {d:2} {:02}:{:02}:{:02} {y}",
            WD[days.rem_euclid(7) as usize],
            MON[(m - 1) as usize],
            secs / 3600,
            secs / 60 % 60,
            secs % 60
        )
    }

    /// Howard Hinnant's `civil_from_days`.
    fn civil(z: i64) -> (i64, i64, i64) {
        let z = z + 719_468;
        let era = z.div_euclid(146_097);
        let doe = z.rem_euclid(146_097);
        let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
        let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
        let mp = (5 * doy + 2) / 153;
        let d = doy - (153 * mp + 2) / 5 + 1;
        let m = if mp < 10 { mp + 3 } else { mp - 9 };
        (yoe + era * 400 + i64::from(m <= 2), m, d)
    }

    /// One `moduli` line, timestamped in UTC (`qfileout`).
    fn line(
        otype: u32,
        tests: u32,
        tries: u32,
        size: u32,
        generator: u32,
        modulus: &[u8],
    ) -> String {
        let t = now();
        let (y, m, d) = civil(t.div_euclid(86_400));
        let s = t.rem_euclid(86_400);
        format!(
            "{y:04}{m:02}{d:02}{:02}{:02}{:02} {otype} {tests} {tries} {size} {generator:x} {}\n",
            s / 3600,
            s / 60 % 60,
            s % 60,
            to_hex(modulus)
        )
    }

    fn open_out(path: &str, append: bool) -> Result<Box<dyn Write>, String> {
        if path == "-" {
            return Ok(Box::new(std::io::stdout()));
        }
        let f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .append(append)
            .truncate(!append)
            .open(path)
            .map_err(|e| {
                if append {
                    format!("Couldn't open moduli file \"{path}\": {e}")
                } else {
                    format!("Couldn't open modulus candidate file \"{path}\": {e}")
                }
            })?;
        Ok(Box::new(f))
    }

    pub(super) fn run(mode: &str, args: &Args) -> Result<i32, String> {
        let out = args.rest.first().ok_or("Moduli output file is required")?;
        match mode {
            "generate" => generate(args, out),
            "screen" => screen(args, out),
            other => Err(format!("Unsupported moduli option {other}")),
        }
    }

    fn generate(args: &Args, out_path: &str) -> Result<i32, String> {
        let mut start = None;
        let mut power = 0u32;
        for o in &args.sig_options {
            if let Some(v) = o.strip_prefix("start=") {
                start = Some(from_hex(v).ok_or("Invalid start point.")?);
            } else if let Some(v) = o.strip_prefix("bits=") {
                power = v
                    .parse()
                    .ok()
                    .filter(|b| *b >= 1)
                    .ok_or_else(|| format!("Invalid number: {v}"))?;
            } else {
                return Err(format!(
                    "Option \"{o}\" is unsupported for moduli generation"
                ));
            }
        }
        if power == 0 {
            power = DEFAULT_BITS;
        }
        if power > TEST_MAXIMUM {
            return Err(format!("Too many bits: {power} > {TEST_MAXIMUM}"));
        }
        if power < TEST_MINIMUM {
            return Err(format!("Too few bits: {power} < {TEST_MINIMUM}"));
        }
        let mut out = open_out(out_path, false)?;
        let power = power - 1;
        let largewords = (LARGE_MAXIMUM as usize) << 18;
        let largebits = (largewords * 32) as u64;
        let mut large = vec![0u32; largewords];
        let mut largetries = 0u32;
        let set = |sieve: &mut [u32], n: u64| sieve[(n >> 5) as usize] |= 1 << (n & 31);
        let test = |sieve: &[u32], n: u64| sieve[(n >> 5) as usize] & (1 << (n & 31)) != 0;

        // The random (or given) odd start point, `power` bits.
        let mut base = match start {
            Some(s) => s,
            None => {
                let nbytes = power.div_ceil(8) as usize;
                let mut b = vec![0u8; nbytes];
                OsRng.fill_bytes(&mut b);
                let extra = nbytes as u32 * 8 - power;
                b[0] &= 0xff >> extra;
                // BN_rand(top=1): the two most significant bits set.
                let top = power - 1 - (nbytes as u32 - 1) * 8;
                b[0] |= 1 << top;
                if top > 0 {
                    b[0] |= 1 << (top - 1);
                } else if nbytes > 1 {
                    b[1] |= 0x80;
                }
                b
            }
        };
        let last = base.len() - 1;
        base[last] |= 1;
        let t0 = now();
        eprintln!(
            "{} Sieve next {} plus {power}-bit",
            ctime(t0),
            (largebits * 2) as u32
        );

        let base_limbs = limbs(&base);
        let mut sieve_large = |s: u64, large: &mut [u32]| {
            largetries += 1;
            let r = mod_limbs(&base_limbs, s);
            let mut u = if r == 0 { 0 } else { s - r };
            if u < largebits * 2 {
                if u & 1 == 1 {
                    u += s;
                }
                u /= 2;
                while u < largebits {
                    set(large, u);
                    u += s;
                }
            }
            let r = (2 * r + 1) % s;
            let mut u = if r == 0 { 0 } else { s - r };
            if u < largebits * 4 {
                while u & 3 != 0 {
                    if SMALL_MAXIMUM - u < s {
                        return;
                    }
                    u += s;
                }
                u /= 4;
                while u < largebits {
                    set(large, u);
                    u += s;
                }
            }
        };

        let tinywords = (TINY_NUMBER >> 6) as usize;
        let tinybits = (tinywords * 32) as u64;
        let mut tiny = vec![0u32; tinywords];
        let mut small = vec![0u32; tinywords];
        let smallbits = tinybits;
        for i in 0..tinybits {
            if test(&tiny, i) {
                continue;
            }
            let t = 2 * i + 3;
            let mut j = i + t;
            while j < tinybits {
                set(&mut tiny, j);
                j += t;
            }
            sieve_large(t, &mut large);
        }
        let mut smallbase = u64::from(TINY_NUMBER) + 3;
        while smallbase < SMALL_MAXIMUM - u64::from(TINY_NUMBER) {
            for i in 0..tinybits {
                if test(&tiny, i) {
                    continue;
                }
                let t = 2 * i + 3;
                let r = smallbase % t;
                let mut s = if r == 0 { 0 } else { t - r };
                if s & 1 == 1 {
                    s += t;
                }
                s /= 2;
                while s < smallbits {
                    set(&mut small, s);
                    s += t;
                }
            }
            for i in 0..smallbits {
                if !test(&small, i) {
                    sieve_large(2 * i + smallbase, &mut large);
                }
            }
            small.iter_mut().for_each(|w| *w = 0);
            smallbase += u64::from(TINY_NUMBER);
        }
        let t1 = now();
        eprintln!(
            "{} Sieved with {largetries} small primes in {} seconds",
            ctime(t1),
            t1 - t0
        );
        let mut found = 0u32;
        for j in 0..largebits {
            if test(&large, j) {
                continue;
            }
            let q = add_small(&base, 2 * j);
            out.write_all(
                line(
                    MODULI_TYPE_SOPHIE_GERMAIN,
                    MODULI_TESTS_SIEVE,
                    largetries,
                    power - 1,
                    0,
                    &q,
                )
                .as_bytes(),
            )
            .map_err(|e| format!("write: {e}"))?;
            found += 1;
        }
        let _ = out.flush();
        eprintln!("{} Found {found} candidates", ctime(now()));
        Ok(0)
    }

    fn screen(args: &Args, out_path: &str) -> Result<i32, String> {
        let mut checkpoint: Option<String> = None;
        let mut generator_wanted = 0u32;
        let mut start_lineno = 0u64;
        let mut lines = 0u64;
        let mut trials = 0u32;
        for o in &args.sig_options {
            if let Some(v) = o.strip_prefix("lines=") {
                lines = v.parse().unwrap_or(0);
            } else if let Some(v) = o.strip_prefix("start-line=") {
                start_lineno = v.parse().unwrap_or(0);
            } else if let Some(v) = o.strip_prefix("checkpoint=") {
                checkpoint = Some(v.to_string());
            } else if let Some(v) = o.strip_prefix("generator=") {
                generator_wanted = v
                    .parse()
                    .ok()
                    .filter(|g| *g >= 1)
                    .ok_or_else(|| format!("Generator invalid: {v}"))?;
            } else if let Some(v) = o.strip_prefix("prime-tests=") {
                trials = v
                    .parse()
                    .ok()
                    .filter(|t| *t >= 1)
                    .ok_or_else(|| format!("Invalid number: {v}"))?;
            } else {
                return Err(format!(
                    "Option \"{o}\" is unsupported for moduli screening"
                ));
            }
        }
        let trials = if trials == 0 { 100 } else { trials };
        if trials < TRIAL_MINIMUM {
            return Err(format!("Minimum primality trials is {TRIAL_MINIMUM}"));
        }
        let input: Box<dyn BufRead> = match args.file.as_deref() {
            Some(f) if f != "-" => Box::new(std::io::BufReader::new(
                std::fs::File::open(f)
                    .map_err(|e| format!("Couldn't open modulus candidate file \"{f}\": {e}"))?,
            )),
            _ => Box::new(std::io::BufReader::new(std::io::stdin())),
        };
        let mut out = open_out(out_path, true)?;
        let end_lineno = if lines == 0 {
            u64::MAX
        } else {
            start_lineno + lines
        };
        let mut last_processed = 0u64;
        if let Some(cp) = &checkpoint
            && let Ok(text) = std::fs::read_to_string(cp)
        {
            match text.trim().parse::<u64>() {
                Ok(n) => {
                    eprintln!("Loaded checkpoint from '{cp}' line {n}");
                    last_processed = n;
                }
                Err(_) => eprintln!("Failed to load checkpoint from '{cp}'"),
            }
        }
        let last_processed = last_processed.max(start_lineno);
        let primes = small_primes();
        let t0 = now();
        let (mut count_in, mut count_out, mut count_possible) = (0u64, 0u32, 0u32);
        for l in input.lines() {
            let Ok(lp) = l else { break };
            if count_in >= end_lineno {
                break;
            }
            count_in += 1;
            if count_in <= last_processed {
                continue;
            }
            if let Some(cp) = &checkpoint {
                let tmp = format!("{cp}.{:010}", OsRng.next_u32());
                if std::fs::write(&tmp, format!("{count_in}\n")).is_err()
                    || std::fs::rename(&tmp, cp).is_err()
                {
                    let _ = std::fs::remove_file(&tmp);
                    eprintln!("failed to write to checkpoint file '{cp}'");
                }
            }
            if lp.len() < 14 || lp.starts_with('!') || lp.starts_with('#') {
                continue;
            }
            let mut f = lp[14..].split_whitespace();
            let mut num = |radix: u32| {
                f.next()
                    .and_then(|v| u32::from_str_radix(v, radix).ok())
                    .unwrap_or(0)
            };
            let in_type = num(10);
            let in_tests = num(10);
            let mut in_tries = num(10);
            let mut in_size = num(10);
            let mut generator = num(16);
            let Some(modulus) = f.next().and_then(from_hex) else {
                continue;
            };
            if in_tests & MODULI_TESTS_COMPOSITE != 0 {
                continue;
            }
            let (p, q) = match in_type {
                MODULI_TYPE_SOPHIE_GERMAIN => {
                    in_size += 1;
                    generator = 0;
                    (add_small(&shl1(&modulus), 1), modulus)
                }
                MODULI_TYPE_UNSTRUCTURED
                | MODULI_TYPE_SAFE
                | MODULI_TYPE_SCHNORR
                | MODULI_TYPE_STRONG
                | MODULI_TYPE_UNKNOWN => {
                    let q = shr1(&modulus);
                    (modulus, q)
                }
                _ => continue,
            };
            if bits(&p) != in_size + 1 || in_size < QSIZE_MINIMUM {
                continue;
            }
            in_tries = if in_tests & MODULI_TESTS_MILLER_RABIN != 0 {
                in_tries + trials
            } else {
                trials
            };
            if generator == 0 {
                if mod_word(&p, 24) == 11 {
                    generator = 2;
                } else if matches!(mod_word(&p, 10), 3 | 7) {
                    generator = 5;
                }
            }
            if generator_wanted > 0 && generator_wanted != generator {
                continue;
            }
            if generator == 0 {
                continue;
            }
            count_possible += 1;
            // One quick round on q first; p in full; then q in full.
            if !is_probable_prime(&q, 1, &primes)
                || !is_probable_prime(&p, trials, &primes)
                || !is_probable_prime(&q, trials - 1, &primes)
            {
                continue;
            }
            out.write_all(
                line(
                    MODULI_TYPE_SAFE,
                    in_tests | MODULI_TESTS_MILLER_RABIN,
                    in_tries,
                    in_size,
                    generator,
                    &p,
                )
                .as_bytes(),
            )
            .map_err(|e| format!("write: {e}"))?;
            count_out += 1;
        }
        let _ = out.flush();
        if let Some(cp) = &checkpoint {
            let _ = std::fs::remove_file(cp);
        }
        eprintln!(
            "{} Found {count_out} safe primes of {count_possible} candidates in {} seconds",
            ctime(now()),
            now() - t0
        );
        Ok(0)
    }
}

/// FIDO security keys: enrolment (`-t ecdsa-sk|ed25519-sk`) and resident
/// key download (`-K`), as OpenSSH's ssh-keygen does them.
#[cfg(feature = "security-key")]
mod security_key {
    use super::{
        Args, RAW, ask, encode_private, read_new_passphrase_confirmed, read_passphrase_interactive,
        write_private, write_public,
    };
    use purecrypto::zeroize::Zeroizing;
    use puressh::Error;
    use puressh::key::PrivateKey;
    use puressh::sk::{self, Algorithm, SkError};
    use std::io::Write;

    /// `-w`, for the operations that sign with a security key.
    pub(super) static PROVIDER: std::sync::OnceLock<String> = std::sync::OnceLock::new();

    fn provider(args: &Args) -> Result<std::sync::Arc<dyn sk::Provider>, String> {
        let path = sk::provider_path(args.sk_provider.as_deref());
        sk::open_provider(&path).map_err(|e| format!("{RAW}{e}"))
    }

    /// What signing asks for, as OpenSSH's ssh-keygen asks it.
    struct TtyPrompt(String);

    impl sk::Prompt for TtyPrompt {
        fn touch(&self, key: &PrivateKey) {
            let pk = key.public_key();
            eprintln!(
                "Confirm user presence for key {} {}",
                pk.type_label(),
                pk.sha256_fingerprint()
            );
        }

        fn pin(&self, key: &PrivateKey) -> Option<Zeroizing<String>> {
            let prompt = format!(
                "Enter PIN for {} key {}: ",
                key.public_key().type_label(),
                self.0
            );
            read_passphrase_interactive(&prompt)
                .ok()
                .filter(|p| !p.is_empty())
        }
    }

    /// A signer for the security key `key` (the file `path`).
    pub(super) fn signer(
        path: &str,
        key: PrivateKey,
    ) -> Result<Box<dyn puressh::hostkey::HostKey + Send>, String> {
        let provider = sk::lazy_provider(&sk::provider_path(PROVIDER.get().map(String::as_str)));
        let prompt = std::sync::Arc::new(TtyPrompt(path.to_string()));
        sk::SkSigner::new(key, provider, Some(prompt))
            .map(|s| Box::new(s) as Box<dyn puressh::hostkey::HostKey + Send>)
            .map_err(|e| format!("{path}: {e}"))
    }

    /// `Enter PIN for authenticator: `, empty ⇒ none.
    fn read_pin() -> Result<Option<Zeroizing<String>>, String> {
        let pin = read_passphrase_interactive("Enter PIN for authenticator: ")?;
        Ok((!pin.is_empty()).then_some(pin))
    }

    /// Enrol a key with the `-O` options OpenSSH takes, retrying for a PIN
    /// (three times) and, for a resident key, an overwrite. Returns the key
    /// and the attestation to write (`write-attestation=`).
    pub(super) fn enroll(
        args: &Args,
        ty: &str,
    ) -> Result<(PrivateKey, Option<Attestation>), String> {
        let alg = Algorithm::from_name(ty).ok_or("unsupported key type")?;
        let mut flags = sk::USER_PRESENCE_REQD;
        let (mut device, mut user, mut application) = (None, None, None);
        let mut challenge = None;
        let mut attestation_path = None;
        for o in &args.sig_options {
            let lower = o.to_ascii_lowercase();
            let value = |prefix: &str| {
                lower
                    .starts_with(prefix)
                    .then(|| o[prefix.len()..].to_string())
            };
            if lower == "no-touch-required" {
                flags &= !sk::USER_PRESENCE_REQD;
            } else if lower == "verify-required" {
                flags |= sk::USER_VERIFICATION_REQD;
            } else if lower == "resident" {
                flags |= sk::RESIDENT_KEY;
            } else if let Some(v) = value("device=") {
                device = Some(v);
            } else if let Some(v) = value("user=") {
                user = Some(v);
            } else if let Some(v) = value("challenge=") {
                challenge = Some(std::fs::read(&v).map_err(|e| {
                    format!("{RAW}Unable to load FIDO enrollment challenge \"{v}\": {e}")
                })?);
            } else if let Some(v) = value("write-attestation=") {
                attestation_path = Some(v);
            } else if let Some(v) = value("application=") {
                if !v.starts_with("ssh:") {
                    return Err(format!(
                        "{RAW}FIDO application string must begin with \"ssh:\""
                    ));
                }
                application = Some(v);
            } else {
                return Err(format!(
                    "{RAW}Option \"{o}\" is unsupported for FIDO authenticator enrollment"
                ));
            }
        }
        let provider = provider(args)?;
        let options = sk::options(device.as_deref(), user.as_deref());
        let app = application.clone().unwrap_or_else(|| "ssh:".into());
        let mut pin: Option<Zeroizing<String>> = None;
        let mut again = false;
        let mut tries = 0;
        let enrolled = loop {
            if !args.quiet {
                println!(
                    "You may need to touch your authenticator{} to authorize key generation.",
                    if again { " again" } else { "" }
                );
            }
            let _ = std::io::stdout().flush();
            match sk::enroll(
                &*provider,
                alg,
                &app,
                flags,
                pin.as_deref().map(|p| p.as_str()),
                challenge.as_deref(),
                &options,
            ) {
                Ok(e) => break e,
                Err(Error::SecurityKey(SkError::CredentialExists))
                    if flags & sk::RESIDENT_KEY != 0 && flags & sk::FORCE_OPERATION == 0 =>
                {
                    println!(
                        "A resident key scoped to '{}' with user id '{}' already exists.",
                        application.as_deref().unwrap_or("ssh:"),
                        user.as_deref().unwrap_or("null")
                    );
                    if !ask("Overwrite key in token (y/n)? ")
                        .is_some_and(|a| a.starts_with(['y', 'Y']))
                    {
                        return Err(format!(
                            "{RAW}Key enrollment failed: {}",
                            SkError::CredentialExists
                        ));
                    }
                    flags |= sk::FORCE_OPERATION;
                }
                Err(Error::SecurityKey(SkError::PinRequired)) => {
                    if pin.take().is_some() {
                        eprintln!("PIN incorrect");
                    }
                    tries += 1;
                    if tries >= 3 {
                        return Err(format!("{RAW}Too many incorrect PINs"));
                    }
                    pin = read_pin()?;
                }
                Err(e) => return Err(format!("{RAW}Key enrollment failed: {e}")),
            }
            again = true;
        };
        let attestation = attestation_path.map(|p| (p, enrolled.attestation));
        Ok((enrolled.key, attestation))
    }

    /// Where to write the attestation (`write-attestation=`), and the blob.
    pub(super) type Attestation = (String, Vec<u8>);

    /// The file name suffix OpenSSH derives from a resident key's
    /// application and user ID (`sk_suffix`).
    fn suffix(application: &str, user_id: &[u8]) -> String {
        let mut out = application
            .strip_prefix("ssh://")
            .or_else(|| application.strip_prefix("ssh:"))
            .unwrap_or(application)
            .to_string();
        let len = user_id.iter().rposition(|&b| b != 0).map_or(0, |i| i + 1);
        if len > 0 {
            let mut user = String::from_utf8_lossy(&user_id[..len]).into_owned();
            // Never a path or control character in a file name.
            if user.contains('/') || user.contains("..") || user.contains('\\') {
                user = user_id[..len].iter().map(|b| format!("{b:02x}")).collect();
            }
            if !out.is_empty() {
                out.push('_');
            }
            out.push_str(&user);
        }
        out
    }

    /// `ssh-keygen -K`: save each resident key as `id_<type>_rk[_suffix]`
    /// in the current directory.
    pub(super) fn download(args: &Args) -> Result<i32, String> {
        let provider = provider(args)?;
        let pin = read_pin()?;
        if !args.quiet {
            println!("You may need to touch your authenticator to authorize key download.");
        }
        let device = args
            .sig_options
            .iter()
            .find_map(|o| o.strip_prefix("device="));
        let keys = match sk::load_resident_keys(
            &*provider,
            pin.as_deref().map(|p| p.as_str()),
            &sk::options(device, None),
        ) {
            Ok(k) => k,
            Err(e) => {
                eprintln!("Unable to load resident keys: {e}");
                return Ok(255);
            }
        };
        drop(pin);
        if keys.is_empty() {
            eprintln!("No keys to download");
        }
        let mut pass: Option<Zeroizing<String>> = None;
        for rk in keys {
            let mut key = rk.key;
            let sk = key.sk_credential().ok_or("not a security key")?;
            let application = sk.application.clone();
            let ext = suffix(&application, &rk.user_id);
            let kind = if matches!(key, PrivateKey::SkEcdsaP256 { .. }) {
                "ecdsa_sk"
            } else {
                "ed25519_sk"
            };
            let path = format!("id_{kind}_rk{}{ext}", if ext.is_empty() { "" } else { "_" });
            if std::path::Path::new(&path).exists() {
                println!("{path} already exists.");
                if !ask("Overwrite (y/n)? ").is_some_and(|a| a.starts_with(['y', 'Y'])) {
                    return Ok(255);
                }
            }
            // The application string is the comment, as with OpenSSH.
            key.set_comment(application.clone());
            if pass.is_none() {
                pass = Some(match (&args.old_pass, &args.new_pass) {
                    (Some(p), _) | (None, Some(p)) => p.clone(),
                    (None, None) => read_new_passphrase_confirmed(&format!(
                        "Enter passphrase for \"{path}\" (empty for no passphrase): "
                    ))?,
                });
            }
            let pem = encode_private(&key, args, pass.as_deref().map_or("", |p| p.as_str()))
                .map_err(|e| format!("{RAW}Saving key \"{path}\" failed: {e}"))?;
            write_private(&path, &pem)?;
            if !args.quiet {
                println!(
                    "Saved {} key{}{} to {path}",
                    key.public_key().type_label(),
                    if ext.is_empty() { "" } else { " " },
                    if ext.is_empty() {
                        ""
                    } else {
                        application.as_str()
                    },
                );
            }
            let mut line = key.public_key().to_authorized_keys_line();
            line.push('\n');
            write_public(&format!("{path}.pub"), &line)?;
        }
        Ok(0)
    }

    #[cfg(test)]
    mod tests {
        #[test]
        fn suffix_matches_openssh() {
            assert_eq!(super::suffix("ssh:", &[0; 32]), "");
            assert_eq!(super::suffix("ssh:work", &[0; 32]), "work");
            assert_eq!(super::suffix("ssh://srv", b"alice\0\0"), "srv_alice");
            assert_eq!(super::suffix("ssh:", b"bob"), "bob");
            assert_eq!(super::suffix("ssh:", b"../x"), "2e2e2f78");
        }
    }
}
