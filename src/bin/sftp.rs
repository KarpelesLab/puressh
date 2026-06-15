//! `sftp` — puressh's SFTP client driver.
//!
//! ```text
//! sftp [-P port] [-i identity_file] [-l user]
//!      [-o StrictHostKeyChecking={yes,no,accept-new,ask}]
//!      [-o UserKnownHostsFile=PATH]
//!      [-o HashKnownHosts={yes,no}]
//!      [-o IdentitiesOnly={yes,no}]
//!      [user@]host
//! ```
//!
//! Drops into an interactive REPL after authentication. Supports the
//! common subset of OpenSSH `sftp(1)` commands:
//! `ls`, `cd`, `lcd`, `pwd`, `lpwd`, `get`, `put`, `mkdir`, `rmdir`,
//! `rm`, `mv`, `chmod`, `quit` / `exit` / `bye`.
//!
//! Path resolution is dumb on purpose — relative remote paths are joined
//! with the SFTP session's virtual cwd via `realpath`; relative local
//! paths are joined with the process cwd. Glob patterns are not expanded.
//!
//! Host-key policy mirrors the `ssh` and `scp` binaries — default is
//! `StrictHostKeyChecking=ask`. Earlier versions of this binary hard-
//! coded `HostKeyPolicy::AcceptAny`, which trusted anything on the wire;
//! that's no longer the default.

use std::io::{BufRead, Read, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use puressh::auth::ClientCredential;
use puressh::client::{Client, Config};
use puressh::sftp::{
    Attrs, FXF_CREAT, FXF_READ, FXF_TRUNC, FXF_WRITE, FxpStatus, SftpClient, SftpError,
};

#[path = "common.rs"]
mod common;
use common::{
    StrictMode, build_host_key_policy, connect_agent_credentials, default_identity_paths,
    expand_tilde, load_identity, parse_target, read_password_from_stdin, resolve_user, set_verbose,
    try_load_default_identity, vlog,
};

const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Scrub bytes that are unsafe to emit to an interactive terminal.
///
/// SFTP `longname`/`filename`/`realpath` fields arrive as opaque,
/// unvalidated bytes from the server. A malicious server can embed ANSI
/// or OSC control sequences (e.g. `ESC[...m`, `ESC]0;...BEL`) that, when
/// written verbatim to a TTY, rewrite the screen, retitle the window, or
/// otherwise hijack the operator's terminal. Following OpenSSH sftp's
/// `strnvis`/`ctrl` handling, replace every control byte — anything below
/// `0x20` (including ESC `0x1b`, TAB `0x09`, CR/LF) and DEL `0x7f` — with
/// a `?` placeholder. The `ls -l` long format uses spaces, not tabs, for
/// column alignment, so scrubbing TAB does not disturb the layout.
fn sanitize_terminal_bytes(src: &[u8]) -> Vec<u8> {
    src.iter()
        .map(|&b| if b < 0x20 || b == 0x7f { b'?' } else { b })
        .collect()
}

const USAGE: &str = "usage: sftp [-v[v[v]]] [-F configfile] [-P port] [-i identity_file] [-l user] \
                     [-o StrictHostKeyChecking={yes,no,accept-new,ask}] \
                     [-o UserKnownHostsFile=PATH] [-o HashKnownHosts={yes,no}] \
                     [-o IdentitiesOnly={yes,no}] [user@]host";

struct Cli {
    /// `-F path`: load this `ssh_config` instead of the defaults.
    config_file: Option<PathBuf>,
    /// `None` ⇒ ssh_config `Port` wins (else built-in default 22).
    port: Option<u16>,
    identities: Vec<String>,
    cli_user: Option<String>,
    strict: Option<StrictMode>,
    known_hosts_path: Option<PathBuf>,
    hash_known_hosts: Option<bool>,
    identities_only: Option<bool>,
    /// OpenSSH-style verbose level: `-v` → 1, `-vv` → 2, `-vvv` → 3.
    /// See [`common::set_verbose`].
    verbose: u8,
    host: String,
    user_in_host: Option<String>,
}

fn parse_args(args: &[String]) -> Result<Cli, String> {
    let mut config_file: Option<PathBuf> = None;
    let mut port: Option<u16> = None;
    let mut identities: Vec<String> = Vec::new();
    let mut cli_user: Option<String> = None;
    let mut strict: Option<StrictMode> = None;
    let mut known_hosts_path: Option<PathBuf> = None;
    let mut hash_known_hosts: Option<bool> = None;
    let mut identities_only: Option<bool> = None;
    let mut verbose: u8 = 0;
    let mut positional: Vec<String> = Vec::new();

    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
        if a == "--" {
            positional.extend_from_slice(&args[i + 1..]);
            break;
        }
        match a.as_str() {
            "-P" => {
                i += 1;
                let v = args.get(i).ok_or("-P requires a value")?;
                port = Some(v.parse::<u16>().map_err(|_| "invalid port".to_string())?);
            }
            "-F" => {
                i += 1;
                let v = args.get(i).ok_or("-F requires a value")?.clone();
                config_file = Some(PathBuf::from(v));
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
                        strict = Some(match val.to_ascii_lowercase().as_str() {
                            "yes" => StrictMode::Yes,
                            "no" | "off" => StrictMode::No,
                            "accept-new" => StrictMode::AcceptNew,
                            "ask" => StrictMode::Ask,
                            other => return Err(format!("unknown StrictHostKeyChecking={other}")),
                        });
                    }
                    "userknownhostsfile" => {
                        known_hosts_path = Some(PathBuf::from(val));
                    }
                    "hashknownhosts" => {
                        hash_known_hosts =
                            Some(matches!(val.to_ascii_lowercase().as_str(), "yes" | "on"));
                    }
                    "identitiesonly" => {
                        identities_only =
                            Some(matches!(val.to_ascii_lowercase().as_str(), "yes" | "on"));
                    }
                    other => {
                        return Err(format!("unsupported -o option: {other}={val}"));
                    }
                }
            }
            "-v" => {
                verbose = verbose.saturating_add(1).min(3);
            }
            "-vv" => {
                verbose = verbose.max(2);
            }
            "-vvv" => {
                verbose = 3;
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
    // parse_target accepts `[user@]host[:port]` with bare /
    // bracketed IPv6 (`2001:db8::1`, `[2001:db8::1]:22`). When the
    // target carries an explicit `:port`, `-P` still wins if given
    // (mirroring how `-p` works for ssh).
    let (user_in_host, host, target_port) = parse_target(&target)?;
    if port.is_none() {
        port = target_port;
    }

    Ok(Cli {
        config_file,
        port,
        identities,
        cli_user,
        strict,
        known_hosts_path,
        hash_known_hosts,
        identities_only,
        verbose,
        host,
        user_in_host,
    })
}

/// Resolve a remote path token against the session's virtual cwd.
fn remote_join(cwd: &[u8], rel: &str) -> Vec<u8> {
    if rel.starts_with('/') {
        rel.as_bytes().to_vec()
    } else {
        let mut out = cwd.to_vec();
        if !out.ends_with(b"/") {
            out.push(b'/');
        }
        out.extend_from_slice(rel.as_bytes());
        out
    }
}

fn sftp_err_to_string(e: SftpError) -> String {
    match e {
        SftpError::Status { code, message } => {
            if message.is_empty() {
                format!("{code:?}")
            } else {
                format!("{code:?}: {message}")
            }
        }
        other => format!("{other:?}"),
    }
}

/// REPL state. `remote_cwd` is the SFTP virtual cwd reported by `realpath
/// "."` on first interaction and kept in sync by `cd`.
struct Repl<T: Read + Write> {
    sftp: SftpClient<T>,
    remote_cwd: Vec<u8>,
    local_cwd: PathBuf,
}

impl<T: Read + Write> Repl<T> {
    fn new(mut sftp: SftpClient<T>) -> Result<Self, String> {
        let remote_cwd = sftp.realpath(b".").map_err(sftp_err_to_string)?;
        let local_cwd = std::env::current_dir().map_err(|e| format!("getcwd: {e}"))?;
        Ok(Self {
            sftp,
            remote_cwd,
            local_cwd,
        })
    }

    fn run(&mut self) -> Result<(), String> {
        let stdin = std::io::stdin();
        let mut stdin = stdin.lock();
        let mut line = String::new();
        loop {
            eprint!("sftp> ");
            std::io::stderr().flush().ok();
            line.clear();
            let n = match stdin.read_line(&mut line) {
                Ok(n) => n,
                Err(e) => return Err(format!("stdin: {e}")),
            };
            if n == 0 {
                eprintln!();
                return Ok(());
            }
            let cmd: Vec<&str> = line.split_whitespace().collect();
            if cmd.is_empty() {
                continue;
            }
            match cmd[0] {
                "quit" | "exit" | "bye" => return Ok(()),
                "pwd" => {
                    // `remote_cwd` is the server's `realpath` reply — opaque
                    // peer-supplied bytes. Scrub control bytes before echoing
                    // to the TTY (terminal escape injection).
                    let safe = sanitize_terminal_bytes(&self.remote_cwd);
                    println!(
                        "Remote working directory: {}",
                        String::from_utf8_lossy(&safe)
                    );
                }
                "lpwd" => println!("Local working directory: {}", self.local_cwd.display()),
                "cd" => {
                    if let Err(e) = self.cmd_cd(cmd.get(1).copied().unwrap_or("")) {
                        eprintln!("cd: {e}");
                    }
                }
                "lcd" => {
                    if let Err(e) = self.cmd_lcd(cmd.get(1).copied().unwrap_or("")) {
                        eprintln!("lcd: {e}");
                    }
                }
                "ls" => {
                    if let Err(e) = self.cmd_ls(cmd.get(1).copied()) {
                        eprintln!("ls: {e}");
                    }
                }
                "get" => {
                    if cmd.len() < 2 {
                        eprintln!("usage: get remote-path [local-path]");
                        continue;
                    }
                    let local = cmd.get(2).copied();
                    if let Err(e) = self.cmd_get(cmd[1], local) {
                        eprintln!("get: {e}");
                    }
                }
                "put" => {
                    if cmd.len() < 2 {
                        eprintln!("usage: put local-path [remote-path]");
                        continue;
                    }
                    let remote = cmd.get(2).copied();
                    if let Err(e) = self.cmd_put(cmd[1], remote) {
                        eprintln!("put: {e}");
                    }
                }
                "mkdir" => {
                    if cmd.len() < 2 {
                        eprintln!("usage: mkdir remote-path");
                        continue;
                    }
                    let abs = remote_join(&self.remote_cwd, cmd[1]);
                    if let Err(e) = self.sftp.mkdir(&abs, Attrs::default()) {
                        eprintln!("mkdir: {}", sftp_err_to_string(e));
                    }
                }
                "rmdir" => {
                    if cmd.len() < 2 {
                        eprintln!("usage: rmdir remote-path");
                        continue;
                    }
                    let abs = remote_join(&self.remote_cwd, cmd[1]);
                    if let Err(e) = self.sftp.rmdir(&abs) {
                        eprintln!("rmdir: {}", sftp_err_to_string(e));
                    }
                }
                "rm" => {
                    if cmd.len() < 2 {
                        eprintln!("usage: rm remote-path");
                        continue;
                    }
                    let abs = remote_join(&self.remote_cwd, cmd[1]);
                    if let Err(e) = self.sftp.remove(&abs) {
                        eprintln!("rm: {}", sftp_err_to_string(e));
                    }
                }
                "mv" | "rename" => {
                    if cmd.len() < 3 {
                        eprintln!("usage: mv oldpath newpath");
                        continue;
                    }
                    let from = remote_join(&self.remote_cwd, cmd[1]);
                    let to = remote_join(&self.remote_cwd, cmd[2]);
                    if let Err(e) = self.sftp.rename(&from, &to) {
                        eprintln!("mv: {}", sftp_err_to_string(e));
                    }
                }
                "chmod" => {
                    if cmd.len() < 3 {
                        eprintln!("usage: chmod mode remote-path");
                        continue;
                    }
                    let mode = match u32::from_str_radix(cmd[1], 8) {
                        Ok(m) => m,
                        Err(_) => {
                            eprintln!("chmod: invalid mode (octal expected): {}", cmd[1]);
                            continue;
                        }
                    };
                    let abs = remote_join(&self.remote_cwd, cmd[2]);
                    let attrs = Attrs {
                        permissions: Some(mode),
                        ..Attrs::default()
                    };
                    if let Err(e) = self.sftp.setstat(&abs, attrs) {
                        eprintln!("chmod: {}", sftp_err_to_string(e));
                    }
                }
                "help" | "?" => {
                    eprintln!("commands: ls cd lcd pwd lpwd get put mkdir rmdir rm mv chmod quit");
                }
                other => eprintln!("unknown command: {other} (try 'help')"),
            }
        }
    }

    fn cmd_cd(&mut self, arg: &str) -> Result<(), String> {
        let target = if arg.is_empty() { "." } else { arg };
        let abs = remote_join(&self.remote_cwd, target);
        // Verify the path is a directory by opendir/close.
        let h = self.sftp.opendir(&abs).map_err(sftp_err_to_string)?;
        let _ = self.sftp.close(&h);
        let canon = self.sftp.realpath(&abs).map_err(sftp_err_to_string)?;
        self.remote_cwd = canon;
        Ok(())
    }

    fn cmd_lcd(&mut self, arg: &str) -> Result<(), String> {
        let target = if arg.is_empty() {
            std::env::var_os("HOME")
                .map(PathBuf::from)
                .ok_or_else(|| "$HOME not set".to_string())?
        } else {
            let p = Path::new(arg);
            if p.is_absolute() {
                p.to_path_buf()
            } else {
                self.local_cwd.join(p)
            }
        };
        let meta = std::fs::metadata(&target).map_err(|e| format!("{}: {e}", target.display()))?;
        if !meta.is_dir() {
            return Err(format!("{}: not a directory", target.display()));
        }
        self.local_cwd = target;
        Ok(())
    }

    fn cmd_ls(&mut self, arg: Option<&str>) -> Result<(), String> {
        let target = match arg {
            Some(s) => remote_join(&self.remote_cwd, s),
            None => self.remote_cwd.clone(),
        };
        let h = self.sftp.opendir(&target).map_err(sftp_err_to_string)?;
        let stdout = std::io::stdout();
        let mut out = stdout.lock();
        while let Some(batch) = self.sftp.readdir(&h).map_err(sftp_err_to_string)? {
            for e in batch {
                // `longname` is server-formatted (typically ls -l) and
                // arrives as opaque, unvalidated bytes from the peer. A
                // hostile server can embed ANSI/OSC escape sequences to
                // hijack the operator's terminal, so scrub control bytes
                // before writing them to the TTY (CVE-class: terminal
                // escape injection; mirrors OpenSSH sftp's strnvis).
                let _ = out.write_all(&sanitize_terminal_bytes(&e.longname));
                let _ = out.write_all(b"\n");
            }
        }
        let _ = self.sftp.close(&h);
        Ok(())
    }

    fn cmd_get(&mut self, remote: &str, local: Option<&str>) -> Result<(), String> {
        let abs = remote_join(&self.remote_cwd, remote);
        let local_path = match local {
            Some(s) => {
                let p = Path::new(s);
                if p.is_absolute() {
                    p.to_path_buf()
                } else {
                    self.local_cwd.join(p)
                }
            }
            None => {
                // Take the basename of the remote path.
                let base = remote.rsplit('/').next().unwrap_or("file");
                self.local_cwd.join(base)
            }
        };

        let h = self
            .sftp
            .open(&abs, FXF_READ, Attrs::default())
            .map_err(sftp_err_to_string)?;
        let mut f = std::fs::File::create(&local_path)
            .map_err(|e| format!("{}: {e}", local_path.display()))?;
        let mut offset: u64 = 0;
        let chunk: u32 = 32 * 1024;
        loop {
            let data = self
                .sftp
                .read(&h, offset, chunk)
                .map_err(sftp_err_to_string)?;
            if data.is_empty() {
                break;
            }
            offset += data.len() as u64;
            f.write_all(&data).map_err(|e| format!("write: {e}"))?;
        }
        let _ = self.sftp.close(&h);
        Ok(())
    }

    fn cmd_put(&mut self, local: &str, remote: Option<&str>) -> Result<(), String> {
        let local_path = {
            let p = Path::new(local);
            if p.is_absolute() {
                p.to_path_buf()
            } else {
                self.local_cwd.join(p)
            }
        };
        let remote_path = match remote {
            Some(s) => remote_join(&self.remote_cwd, s),
            None => {
                let base = local.rsplit('/').next().unwrap_or("file");
                remote_join(&self.remote_cwd, base)
            }
        };

        let data =
            std::fs::read(&local_path).map_err(|e| format!("{}: {e}", local_path.display()))?;
        let h = self
            .sftp
            .open(
                &remote_path,
                FXF_WRITE | FXF_CREAT | FXF_TRUNC,
                Attrs::default(),
            )
            .map_err(sftp_err_to_string)?;
        let mut offset: u64 = 0;
        let chunk: usize = 32 * 1024;
        while offset < data.len() as u64 {
            let end = std::cmp::min(offset as usize + chunk, data.len());
            self.sftp
                .write(&h, offset, &data[offset as usize..end])
                .map_err(sftp_err_to_string)?;
            offset = end as u64;
        }
        let _ = self.sftp.close(&h);
        // suppress unused-var warning when FxpStatus isn't matched explicitly
        let _ = FxpStatus::Ok;
        Ok(())
    }
}

fn run() -> Result<i32, String> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.iter().any(|a| a == "-h" || a == "--help") {
        println!("{USAGE}");
        println!();
        println!("A pure-Rust SFTP client built on puressh {VERSION}.");
        return Ok(0);
    }
    if args.iter().any(|a| a == "-V" || a == "--version") {
        println!("puressh sftp {VERSION}");
        return Ok(0);
    }

    let cli = parse_args(&args).map_err(|e| format!("{e}\n{USAGE}"))?;
    set_verbose(cli.verbose);

    let ssh_cfg = common::load_client_config(cli.config_file.as_deref())?;
    let cfg_block = ssh_cfg.lookup(&cli.host);
    if cli.verbose == 0
        && let Some(level) = cfg_block.log_level
    {
        set_verbose(level);
    }
    let cli_user = cli.cli_user.clone().or_else(|| cfg_block.user.clone());
    let user = resolve_user(cli_user.as_deref(), cli.user_in_host.as_deref())?;
    let strict = common::pick(cli.strict, cfg_block.strict_host_key, StrictMode::Ask);
    let known_hosts_path = cli
        .known_hosts_path
        .clone()
        .or_else(|| cfg_block.user_known_hosts.as_ref().map(PathBuf::from));
    let hash_known_hosts = common::pick(cli.hash_known_hosts, cfg_block.hash_known_hosts, false);
    let identities_only = common::pick(cli.identities_only, cfg_block.identities_only, false);
    let port = common::pick(cli.port, cfg_block.port, 22);
    let connect_host = cfg_block
        .host_name
        .clone()
        .unwrap_or_else(|| cli.host.clone());

    let policy = build_host_key_policy(strict, known_hosts_path, hash_known_hosts)?;
    let cfg = Config {
        host_key_policy: policy,
        timeout: None,
    };
    vlog(1, &format!("connecting to {connect_host}:{port}"));
    // Use connect_to_host so KnownHosts can look the host up by its
    // user-supplied name (HostKeyPolicy::KnownHosts now fails hard if
    // the host name is missing, since silently degrading to AcceptAny
    // would defeat the whole point of the check).
    let mut client = Client::connect_to_host(connect_host.as_str(), port, cfg)
        .map_err(|e| format!("connect: {e}"))?;
    vlog(1, &format!("connected to {connect_host}:{port}"));

    // Collect publickey credentials (agent first unless IdentitiesOnly=yes).
    let mut credentials: Vec<ClientCredential> = Vec::new();
    if !identities_only {
        match connect_agent_credentials() {
            Ok(mut from_agent) => {
                vlog(
                    1,
                    &format!("agent: offered {} identities", from_agent.len()),
                );
                credentials.append(&mut from_agent);
            }
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
            Ok(hk) => {
                vlog(1, &format!("identity {id_path}: loaded"));
                credentials.push(ClientCredential::PublicKey(hk));
            }
            Err(e) => eprintln!("warning: identity {id_path}: {e}"),
        }
    }
    // Identities listed in the matching ssh_config block.
    for id_path_raw in &cfg_block.identity_files {
        let id_path = expand_tilde(id_path_raw);
        let pk = match load_identity(&id_path) {
            Ok(p) => p,
            Err(e) => {
                eprintln!("warning: {e}");
                continue;
            }
        };
        match pk.into_host_key() {
            Ok(hk) => {
                vlog(1, &format!("config identity {id_path}: loaded"));
                credentials.push(ClientCredential::PublicKey(hk));
            }
            Err(e) => eprintln!("warning: config identity {id_path}: {e}"),
        }
    }
    // OpenSSH-style default identities: tried after agent + explicit -i,
    // suppressed entirely by IdentitiesOnly=yes (which also disables the
    // agent above).
    if !identities_only {
        for path in default_identity_paths() {
            match try_load_default_identity(&path) {
                Ok(Some(pk)) => match pk.into_host_key() {
                    Ok(hk) => {
                        vlog(1, &format!("default identity {}: loaded", path.display()));
                        credentials.push(ClientCredential::PublicKey(hk));
                    }
                    Err(e) => {
                        eprintln!("warning: default identity {}: {e}", path.display());
                    }
                },
                Ok(None) => {
                    vlog(2, &format!("default identity {}: skipped", path.display()));
                }
                Err(msg) => eprintln!("warning: {msg}"),
            }
        }
    }

    let authed = if !credentials.is_empty() {
        vlog(
            1,
            &format!(
                "trying publickey auth as {} ({} credentials)",
                user,
                credentials.len()
            ),
        );
        match client.authenticate(&user, credentials) {
            Ok(()) => {
                vlog(1, &format!("authenticated as {user} via publickey"));
                true
            }
            Err(e) => {
                eprintln!("publickey auth: {e}");
                false
            }
        }
    } else {
        false
    };
    if !authed {
        vlog(1, &format!("trying password auth as {user}"));
        let password = read_password_from_stdin().map_err(|e| format!("read password: {e}"))?;
        client
            .authenticate_password(&user, &password)
            .map_err(|e| format!("Auth failed: {e}"))?;
        vlog(1, &format!("authenticated as {user} via password"));
    }

    // The interactive sftp shell is single-channel by design; the
    // borrow-based `Client::sftp` fits, even though it's now deprecated
    // for new multi-channel callers (use `SharedClient::sftp`).
    #[allow(deprecated)]
    let sftp = client.sftp().map_err(|e| format!("sftp: {e}"))?;
    let mut repl = Repl::new(sftp)?;
    repl.run()?;
    Ok(0)
}

fn main() -> ExitCode {
    match run() {
        Ok(code) => {
            let clamped = code.clamp(0, 255) as u8;
            ExitCode::from(clamped)
        }
        Err(msg) => {
            eprintln!("sftp: {msg}");
            ExitCode::from(255)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::sanitize_terminal_bytes;

    #[test]
    fn strips_ansi_and_control_bytes() {
        // ESC-based ANSI/OSC sequences and other control bytes are scrubbed.
        let evil = b"\x1b[31mred\x1b]0;pwned\x07 file\x7f\nname\tcol\r";
        let got = sanitize_terminal_bytes(evil);
        assert_eq!(&got, b"?[31mred?]0;pwned? file??name?col?");
    }

    #[test]
    fn preserves_printable_ascii() {
        let s = b"-rw-r--r-- 1 user group 1024 Jan  1 00:00 hello.txt";
        assert_eq!(sanitize_terminal_bytes(s), s.to_vec());
    }
}
