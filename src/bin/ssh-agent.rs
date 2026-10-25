//! `ssh-agent` — hold private keys in memory and sign on behalf of clients.
//!
//! ```text
//! ssh-agent [-c | -s] [-DdU] [-T | -A directory | -a bind_address]
//!           [-E fingerprint_hash] [-O option] [-P allowed_providers]
//!           [-t life] [command [arg ...]]
//! ssh-agent [-c | -s] -k
//! ssh-agent -u
//! ssh-agent -V
//! ```
//!
//! Compatible with OpenSSH's agent and its clients (`ssh`, `ssh-add`, git):
//! the socket speaks the standard agent protocol (see
//! `puressh::agent::AgentState` for what is supported). Without a command
//! the agent forks into the background and prints the shell commands that
//! set `SSH_AUTH_SOCK` / `SSH_AGENT_PID` (`eval $(ssh-agent)`); with one, it
//! runs the command with those variables set and exits when it does.
//!
//! As OpenSSH 10.6's, the socket goes in `~/.ssh/agent/` by default (stale
//! sockets there are removed first, unless `-U`; `-u` only does that),
//! under a fresh directory in `/tmp` with `-T`, or where `-A` says.

#[cfg(not(unix))]
fn main() -> std::process::ExitCode {
    eprintln!("ssh-agent: only supported on Unix-like systems");
    std::process::ExitCode::from(1)
}

#[cfg(unix)]
fn main() -> std::process::ExitCode {
    imp::main()
}

#[cfg(unix)]
mod imp {
    use std::io::{ErrorKind, Read, Write};
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::os::unix::process::CommandExt;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use nix::libc;
    use puressh::agent::{AgentState, ConnectionState};

    const USAGE: &str = "usage: ssh-agent [-c | -s] [-DdU] [-T | -A directory | -a bind_address]
                 [-E fingerprint_hash] [-O option]
                 [-P allowed_providers] [-t life]
       ssh-agent [-U] [-T | -A directory | -a bind_address]
                 [-E fingerprint_hash] [-O option]
                 [-P allowed_providers] [-t life] command [arg ...]
       ssh-agent [-c | -s] -k
       ssh-agent -u
       ssh-agent -V";

    const VERSION: &str = env!("CARGO_PKG_VERSION");

    pub fn main() -> std::process::ExitCode {
        let code = match run() {
            Ok(code) => code as u8,
            Err(Exit::Usage(msg)) => {
                if let Some(m) = msg {
                    eprintln!("{m}");
                }
                eprintln!("{USAGE}");
                1
            }
            Err(Exit::Fatal(m)) => {
                eprintln!("{m}");
                255
            }
            Err(Exit::Fail(m)) => {
                eprintln!("{m}");
                1
            }
            Err(Exit::Version) => {
                eprintln!("puressh_{VERSION} (pure-Rust SSH, OpenSSH-compatible)");
                0
            }
        };
        std::process::ExitCode::from(code)
    }

    /// Largest request accepted (the agent protocol caps messages at 256 KiB).
    const MAX_REQUEST: usize = 256 * 1024;

    static STOP: AtomicBool = AtomicBool::new(false);
    /// SIGUSR1 drops every key (OpenSSH's agent does the same).
    static KEYDROP: AtomicBool = AtomicBool::new(false);

    extern "C" fn on_keydrop(_: libc::c_int) {
        KEYDROP.store(true, Ordering::Relaxed);
    }

    /// Act on a pending SIGUSR1.
    fn drop_keys_if_signalled(state: &mut AgentState) {
        if KEYDROP.swap(false, Ordering::Relaxed) {
            state.remove_all();
        }
    }

    extern "C" fn on_signal(_: libc::c_int) {
        STOP.store(true, Ordering::Relaxed);
    }

    struct Opts {
        csh: bool,
        foreground: bool,
        debug: bool,
        kill: bool,
        bind: Option<PathBuf>,
        /// `-A` / `-T`: where to make the socket (`user:` or `shared:`).
        dirspec: String,
        /// `-u` (twice: whichever host made the sockets).
        clean_only: u32,
        /// `-U`: leave stale sockets alone.
        keep_stale: bool,
        lifetime: Option<Duration>,
        /// `-E md5`.
        md5: bool,
        /// `-O` and `-P` settings, for security-key and PKCS#11 providers.
        providers: ProviderOpts,
        command: Vec<String>,
    }

    /// What `-O` and `-P` set.
    #[derive(Default)]
    struct ProviderOpts {
        /// `-O no-restrict-websafe` clears it.
        restrict_websafe: bool,
        /// `-O websafe-allow=`: application pattern-list.
        websafe_allow: Option<String>,
        /// `-O allow-remote-pkcs11`.
        remote_add_provider: bool,
        /// `-P`: library path pattern-list.
        allowed_providers: Option<String>,
    }

    /// The default socket directory, `~/.ssh/agent`.
    const SOCKET_DIR: &str = "user:.ssh/agent";
    /// `-T`'s.
    const SOCKET_TMPDIR: &str = "shared:/tmp";

    /// How `ssh-agent` stops without serving: OpenSSH's `usage()` (exit 1,
    /// after an optional message), `fatal()` (exit 255), another error
    /// (exit 1) or `-V` (exit 0).
    #[derive(Debug, PartialEq)]
    pub enum Exit {
        Usage(Option<String>),
        Fatal(String),
        Fail(String),
        Version,
    }

    /// OpenSSH's `convtime`: `90`, `90s`, `1.5`, `10m`, `1h30m`, `2d`,
    /// `1w`, in seconds (`0` is "no limit").
    fn parse_lifetime(v: &str) -> Option<u64> {
        if v.is_empty() {
            return None;
        }
        let mut total = 0f64;
        let mut seen_seconds = false;
        let mut rest = v;
        while !rest.is_empty() {
            let end = rest
                .find(|c: char| !c.is_ascii_digit() && c != '.')
                .unwrap_or(rest.len());
            let (num, tail) = rest.split_at(end);
            let val: f64 = num.parse().ok()?;
            let mut chars = tail.chars();
            let mult = match chars.next() {
                None | Some('s' | 'S') => {
                    if seen_seconds {
                        return None;
                    }
                    seen_seconds = true;
                    1.0
                }
                Some('m' | 'M') => 60.0,
                Some('h' | 'H') => 3600.0,
                Some('d' | 'D') => 86400.0,
                Some('w' | 'W') => 604800.0,
                Some(_) => return None,
            };
            // A fraction only for seconds, and with digits after the dot.
            if num.contains('.') && (mult > 1.0 || num.ends_with('.')) {
                return None;
            }
            total += val * mult;
            rest = chars.as_str();
        }
        (total <= i32::MAX as f64).then_some(total as u64)
    }

    fn parse_args(args: &[String]) -> Result<Opts, Exit> {
        let mut o = Opts {
            csh: false,
            foreground: false,
            debug: false,
            kill: false,
            bind: None,
            dirspec: String::new(),
            clean_only: 0,
            keep_stale: false,
            lifetime: None,
            md5: false,
            providers: ProviderOpts {
                restrict_websafe: true,
                ..ProviderOpts::default()
            },
            command: Vec::new(),
        };
        let (mut c_flag, mut s_flag, mut t_flag) = (false, false, false);
        let mut dir_arg: Option<String> = None;
        let mut i = 0;
        while i < args.len() {
            let a = &args[i];
            if a == "--" {
                o.command = args[i + 1..].to_vec();
                break;
            }
            if !a.starts_with('-') || a == "-" {
                o.command = args[i..].to_vec();
                break;
            }
            let chars: Vec<char> = a[1..].chars().collect();
            let mut j = 0;
            while j < chars.len() {
                let c = chars[j];
                if "AEaOPt".contains(c) {
                    let attached: String = chars[j + 1..].iter().collect();
                    let v = if !attached.is_empty() {
                        attached
                    } else {
                        i += 1;
                        args.get(i)
                            .ok_or_else(|| {
                                Exit::Usage(Some(format!("option requires an argument -- {c}")))
                            })?
                            .clone()
                    };
                    match c {
                        'A' => dir_arg = Some(v),
                        'a' => o.bind = Some(PathBuf::from(v)),
                        'E' => match v.to_ascii_lowercase().as_str() {
                            "md5" => o.md5 = true,
                            "sha256" => o.md5 = false,
                            _ => {
                                return Err(Exit::Fatal(format!("Invalid hash algorithm \"{v}\"")));
                            }
                        },
                        'O' => {
                            let p = &mut o.providers;
                            if v == "no-restrict-websafe" {
                                p.restrict_websafe = false;
                            } else if v == "allow-remote-pkcs11" {
                                p.remote_add_provider = true;
                            } else if let Some(list) = v.strip_prefix("websafe-allow=") {
                                if p.websafe_allow.is_some() {
                                    return Err(Exit::Fatal("websafe-allow already set".into()));
                                }
                                p.websafe_allow = Some(list.to_string());
                            } else {
                                return Err(Exit::Fatal("Unknown -O option".into()));
                            }
                        }
                        'P' => {
                            if o.providers.allowed_providers.is_some() {
                                return Err(Exit::Fatal("-P option already specified".into()));
                            }
                            o.providers.allowed_providers = Some(v);
                        }
                        't' => match parse_lifetime(&v) {
                            Some(0) => o.lifetime = None,
                            Some(n) => o.lifetime = Some(Duration::from_secs(n)),
                            None => return Err(Exit::Usage(Some("Invalid lifetime".into()))),
                        },
                        _ => unreachable!(),
                    }
                    break;
                }
                match c {
                    'c' if s_flag => return Err(Exit::Usage(None)),
                    'c' => c_flag = true,
                    's' if c_flag => return Err(Exit::Usage(None)),
                    's' => s_flag = true,
                    'D' | 'd' if o.foreground => return Err(Exit::Usage(None)),
                    'D' => o.foreground = true,
                    'd' => {
                        o.foreground = true;
                        o.debug = true;
                    }
                    'k' => o.kill = true,
                    'T' => t_flag = true,
                    'u' => o.clean_only += 1,
                    'U' => o.keep_stale = true,
                    'V' => return Err(Exit::Version),
                    _ => return Err(Exit::Usage(Some(format!("unknown option -- {c}")))),
                }
                j += 1;
            }
            i += 1;
        }
        if !o.command.is_empty() && (c_flag || s_flag || o.kill || o.foreground || o.clean_only > 0)
        {
            return Err(Exit::Usage(None));
        }
        // Only one of -a, -A and -T.
        if usize::from(dir_arg.is_some()) + usize::from(o.bind.is_some()) + usize::from(t_flag) > 1
        {
            return Err(Exit::Usage(None));
        }
        o.dirspec = if t_flag {
            SOCKET_TMPDIR.into()
        } else {
            dir_arg.unwrap_or_else(|| SOCKET_DIR.into())
        };
        o.csh = c_flag
            || (o.command.is_empty()
                && !s_flag
                && std::env::var("SHELL").is_ok_and(|s| s.len() > 2 && s.ends_with("csh")));
        Ok(o)
    }

    /// OpenSSH's `argv_assemble` of one word: `\`, `'` and `"` escaped,
    /// the whole double-quoted if it has blanks.
    fn shell_word(s: &str) -> String {
        let mut out = String::with_capacity(s.len() + 2);
        for c in s.chars() {
            if matches!(c, '\\' | '\'' | '"') {
                out.push('\\');
            }
            out.push(c);
        }
        if s.contains([' ', '\t']) {
            format!("\"{out}\"")
        } else {
            out
        }
    }

    /// The commands that set the agent's variables (in the foreground,
    /// with no `pid`, only `SSH_AUTH_SOCK`, as OpenSSH's).
    fn env_lines(o: &Opts, sock: &Path, pid: Option<u32>, echo_pid: u32) -> String {
        let sock = shell_word(&sock.to_string_lossy());
        let set = |name: &str, val: &str| {
            if o.csh {
                format!("setenv {name} {val};\n")
            } else {
                format!("{name}={val}; export {name};\n")
            }
        };
        let mut out = set("SSH_AUTH_SOCK", &sock);
        if let Some(pid) = pid {
            out.push_str(&set("SSH_AGENT_PID", &pid.to_string()));
        }
        out.push_str(&format!("echo Agent pid {echo_pid};\n"));
        out
    }

    /// `ssh-agent -k`: stop the agent named by `$SSH_AGENT_PID`.
    fn kill_agent(o: &Opts) -> Result<i32, String> {
        let Ok(var) = std::env::var("SSH_AGENT_PID") else {
            return Err("SSH_AGENT_PID not set, cannot kill agent".into());
        };
        let bad = |why: &str| format!("SSH_AGENT_PID=\"{var}\", which is not a good PID: {why}");
        let pid: i32 = match var.parse::<i64>() {
            Ok(n) if n < 2 => return Err(bad("too small")),
            Ok(n) if n > i32::MAX as i64 => return Err(bad("too large")),
            Ok(n) => n as i32,
            Err(_) => return Err(bad("invalid")),
        };
        // SAFETY: plain kill(2).
        if unsafe { libc::kill(pid, libc::SIGTERM) } != 0 {
            return Err(format!(
                "kill: {}",
                strerror(&std::io::Error::last_os_error())
            ));
        }
        if o.csh {
            print!(
                "unsetenv SSH_AUTH_SOCK;\nunsetenv SSH_AGENT_PID;\necho Agent pid {pid} killed;\n"
            );
        } else {
            print!("unset SSH_AUTH_SOCK;\nunset SSH_AGENT_PID;\necho Agent pid {pid} killed;\n");
        }
        Ok(0)
    }

    /// `$HOME`, else the password database's (OpenSSH's `get_homedir`).
    fn home_dir() -> Option<String> {
        if let Some(h) = std::env::var_os("HOME").filter(|h| !h.is_empty()) {
            return Some(h.to_string_lossy().into_owned());
        }
        let user = nix::unistd::User::from_uid(nix::unistd::getuid()).ok()??;
        Some(user.dir.to_string_lossy().into_owned())
    }

    /// `-A`'s directory with its `%u` / `%U` / `%h` tokens and a leading
    /// `~` expanded, relative to `home` unless absolute.
    fn expand_dirspec(spec: &str, home: &str) -> Result<PathBuf, String> {
        use nix::unistd::User;
        let uid = nix::unistd::getuid();
        let mut out = String::new();
        let mut chars = spec.chars();
        while let Some(c) = chars.next() {
            if c != '%' {
                out.push(c);
                continue;
            }
            let failed =
                |why: String| format!("vdollar_percent_expand: {why}\npercent_expand: failed");
            match chars.next() {
                Some('%') => out.push('%'),
                Some('u') => {
                    let name = User::from_uid(uid).ok().flatten().map(|u| u.name);
                    out.push_str(&name.unwrap_or_default());
                }
                Some('U') => out.push_str(&uid.to_string()),
                Some('h') => out.push_str(home),
                Some(k) => return Err(failed(format!("unknown key %{k}"))),
                None => return Err(failed("invalid format".into())),
            }
        }
        // OpenSSH's tilde_expand: `~` / `~user`, from the password database.
        if let Some(rest) = out.strip_prefix('~') {
            let (user, path) = rest.split_once('/').unwrap_or((rest, ""));
            let pw = if user.is_empty() {
                User::from_uid(uid).ok().flatten()
            } else {
                User::from_name(user).ok().flatten()
            };
            let Some(pw) = pw else {
                return Err(if user.is_empty() {
                    format!("tilde_expand: No such uid {uid}")
                } else {
                    format!("tilde_expand: No such user {user}")
                });
            };
            out = pw
                .dir
                .join(path.trim_start_matches('/'))
                .to_string_lossy()
                .into_owned();
        }
        let dir = PathBuf::from(out);
        Ok(if dir.is_absolute() {
            dir
        } else {
            Path::new(home).join(dir)
        })
    }

    /// OpenSSH's alphabet for the random and hashed parts of socket names.
    const PRESENTATION: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

    /// `n` characters of [`PRESENTATION`], at random.
    fn random_chars(n: usize) -> String {
        use purecrypto::rng::{OsRng, RngCore};
        let mut out = String::with_capacity(n);
        while out.len() < n {
            let mut b = [0u8; 1];
            OsRng.fill_bytes(&mut b);
            // 248 = 4 * 62: no bias.
            if b[0] < 248 {
                out.push(PRESENTATION[b[0] as usize % PRESENTATION.len()] as char);
            }
        }
        out
    }

    /// Ten characters derived from the host name, so the sockets in a home
    /// directory shared between hosts can be told apart (OpenSSH's).
    fn hostname_hash() -> String {
        use purecrypto::hash::{Digest, Sha512};
        let mut buf = [0u8; 256];
        // SAFETY: the buffer is writable for its whole length.
        let r = unsafe { libc::gethostname(buf.as_mut_ptr().cast(), buf.len()) };
        let len = if r == 0 {
            buf.iter().position(|b| *b == 0).unwrap_or(buf.len())
        } else {
            0
        };
        Sha512::digest(&buf[..len])
            .iter()
            .take(10)
            .map(|b| PRESENTATION[*b as usize % PRESENTATION.len()] as char)
            .collect()
    }

    /// Bind `path` owner-only, like OpenSSH's (umask 0177).
    fn bind_private(path: &Path) -> std::io::Result<UnixListener> {
        // SAFETY: umask(2) cannot fail.
        let old_umask = unsafe { libc::umask(0o177) };
        let listener = UnixListener::bind(path);
        unsafe { libc::umask(old_umask) };
        let listener = listener?;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
        Ok(listener)
    }

    /// A failed bind as OpenSSH's `unix_listener` / `unix_listener_tmp`
    /// (`func`) reports it.
    fn bind_error(func: &str, path: &Path, e: &std::io::Error) -> String {
        let path = path.display();
        if e.kind() == ErrorKind::InvalidInput {
            format!("{func}: path \"{path}\" too long for Unix domain socket")
        } else if func == "unix_listener" {
            format!("{func}: cannot bind to path {path}: {}", strerror(e))
        } else {
            format!("{func}: bind \"{path}\": {}", strerror(e))
        }
    }

    /// An error as `strerror(3)` words it (without Rust's ` (os error N)`).
    fn strerror(e: &std::io::Error) -> String {
        let s = e.to_string();
        match s.find(" (os error ") {
            Some(i) => s[..i].to_string(),
            None => s,
        }
    }

    /// A listening socket as OpenSSH's `agent_listener`, with its path
    /// and, for a `shared:` parent, the directory made for it:
    /// `user:dir` binds `dir/s.<host>.local.<pid>.<random>` (making `dir`
    /// 0700 if missing), `shared:dir` binds
    /// `dir/ssh-<random>/agent.local.<pid>`.
    fn listen_dirspec(
        spec: &str,
        home: &str,
    ) -> Result<(UnixListener, PathBuf, Option<PathBuf>), String> {
        let pid = std::process::id();
        if spec.is_empty() {
            return Err("agent_listener: no agent path specified".into());
        }
        if let Some(parent) = spec.strip_prefix("shared:") {
            if !parent.starts_with('/') {
                return Err("agent_listener: shared agent socket paths must be absolute".into());
            }
            let parent = expand_dirspec(parent, home)?;
            let dir = loop {
                let dir = parent.join(format!("ssh-{}", random_chars(12)));
                match std::fs::DirBuilder::new().mode(0o700).create(&dir) {
                    Ok(()) => break dir,
                    Err(e) if e.kind() == ErrorKind::AlreadyExists => continue,
                    Err(e) => {
                        return Err(format!(
                            "agent_listener_shared: failed to create temporary directory in \"{}\": {}",
                            dir.display(),
                            strerror(&e)
                        ));
                    }
                }
            };
            let path = dir.join(format!("agent.local.{pid}"));
            match bind_private(&path) {
                Ok(l) => Ok((l, path, Some(dir))),
                Err(e) => {
                    let _ = std::fs::remove_dir(&dir);
                    Err(bind_error("unix_listener", &path, &e))
                }
            }
        } else if let Some(dir) = spec.strip_prefix("user:") {
            let dir = expand_dirspec(dir, home)?;
            let made = std::fs::DirBuilder::new()
                .mode(0o700)
                .recursive(true)
                .create(&dir);
            if let Err(e) = made {
                return Err(format!(
                    "mkdir_path: mkdir(\"{}\"): {}\nagent_listener_user: failed to create agent socket parent directory",
                    dir.display(),
                    strerror(&e)
                ));
            }
            let host = hostname_hash();
            loop {
                let path = dir.join(format!("s.{host}.local.{pid}.{}", random_chars(10)));
                match bind_private(&path) {
                    Ok(l) => return Ok((l, path, None)),
                    Err(e) if e.kind() == ErrorKind::AddrInUse => continue,
                    Err(e) => {
                        return Err(bind_error("unix_listener_tmp", &path, &e));
                    }
                }
            }
        } else {
            Err(format!(
                "agent_listener: unsupported agent path specification {spec}"
            ))
        }
    }

    /// OpenSSH's `agent_cleanup_stale`: remove the sockets in a `user:`
    /// directory that are over an hour old and that no agent listens on;
    /// only those made on this host unless `any_host`.
    fn cleanup_stale(spec: &str, home: &str, any_host: bool) {
        use std::os::unix::fs::FileTypeExt;
        let Some(dir) = spec.strip_prefix("user:") else {
            return;
        };
        let Ok(dir) = expand_dirspec(dir, home) else {
            return;
        };
        let Ok(entries) = std::fs::read_dir(&dir) else {
            return;
        };
        let cutoff = std::time::SystemTime::now() - Duration::from_secs(3600);
        let prefix = format!("s.{}.", hostname_hash());
        for entry in entries.flatten() {
            let path = entry.path();
            let Ok(meta) = std::fs::symlink_metadata(&path) else {
                continue;
            };
            if !meta.file_type().is_socket() || meta.modified().is_ok_and(|m| m > cutoff) {
                continue;
            }
            if !any_host && !entry.file_name().to_string_lossy().starts_with(&prefix) {
                continue;
            }
            if UnixStream::connect(&path).is_err() {
                let _ = std::fs::remove_file(&path);
            }
        }
    }

    /// A listening socket handed over by a service manager (`LISTEN_FDS=1`
    /// for this process: fd 3), as OpenSSH's socket activation.
    fn activated_socket() -> Result<Option<UnixListener>, String> {
        use std::os::fd::FromRawFd;
        let (Ok(pid), Ok(fds)) = (std::env::var("LISTEN_PID"), std::env::var("LISTEN_FDS")) else {
            return Ok(None);
        };
        if fds != "1" {
            return Err(format!(
                "unexpected LISTEN_FDS contents (want: \"1\" got\"{fds}\""
            ));
        }
        // SAFETY: F_GETFL only probes the descriptor.
        if unsafe { libc::fcntl(3, libc::F_GETFL) } == -1 {
            return Err("LISTEN_FDS set but fd 3 unavailable".into());
        }
        let pid = match pid.parse::<i64>() {
            Ok(n) if n < 1 => return Err("invalid LISTEN_PID: too small".into()),
            Ok(n) if n > i32::MAX as i64 => return Err("invalid LISTEN_PID: too large".into()),
            Ok(n) => n,
            Err(_) => return Err("invalid LISTEN_PID: invalid".into()),
        };
        let me = std::process::id();
        if pid != i64::from(me) {
            return Err(format!("bad LISTEN_PID: {pid} vs pid {me}"));
        }
        // SAFETY: fd 3 is open (checked above) and ours to own.
        Ok(Some(unsafe { UnixListener::from_raw_fd(3) }))
    }

    /// Only the agent's own user (or root) may talk to it.
    fn peer_allowed(stream: &UnixStream) -> bool {
        #[cfg(any(target_os = "linux", target_os = "android"))]
        {
            use nix::sys::socket::{getsockopt, sockopt};
            match getsockopt(stream, sockopt::PeerCredentials) {
                Ok(cred) => {
                    let me = nix::unistd::geteuid().as_raw();
                    cred.uid() == me || cred.uid() == 0
                }
                Err(_) => false,
            }
        }
        // The BSDs and Apple platforms: getpeereid(3), on top of the 0700
        // socket directory. Fails closed.
        #[cfg(any(
            target_vendor = "apple",
            target_os = "freebsd",
            target_os = "netbsd",
            target_os = "openbsd",
            target_os = "dragonfly",
        ))]
        {
            match nix::unistd::getpeereid(stream) {
                Ok((uid, _)) => {
                    let me = nix::unistd::geteuid();
                    uid == me || uid.is_root()
                }
                Err(_) => false,
            }
        }
        #[cfg(not(any(
            target_os = "linux",
            target_os = "android",
            target_vendor = "apple",
            target_os = "freebsd",
            target_os = "netbsd",
            target_os = "openbsd",
            target_os = "dragonfly",
        )))]
        {
            // Elsewhere the 0700 socket directory is the access control.
            let _ = stream;
            true
        }
    }

    fn serve_conn(mut stream: UnixStream, state: Arc<Mutex<AgentState>>, debug: bool) {
        if !peer_allowed(&stream) {
            if debug {
                eprintln!("ssh-agent: refused a connection from another user");
            }
            return;
        }
        let mut conn = ConnectionState::default();
        let mut len = [0u8; 4];
        loop {
            if stream.read_exact(&mut len).is_err() {
                return;
            }
            let n = u32::from_be_bytes(len) as usize;
            if n == 0 || n > MAX_REQUEST {
                return;
            }
            let mut req = purecrypto::zeroize::Zeroizing::new(vec![0u8; n]);
            if stream.read_exact(&mut req).is_err() {
                return;
            }
            let resp = match state.lock() {
                Ok(mut s) => {
                    drop_keys_if_signalled(&mut s);
                    s.handle_on(&mut conn, &req)
                }
                Err(_) => return,
            };
            if debug {
                eprintln!(
                    "ssh-agent: request type {} -> reply type {}",
                    req[0], resp[0]
                );
            }
            let mut out = Vec::with_capacity(4 + resp.len());
            out.extend_from_slice(&(resp.len() as u32).to_be_bytes());
            out.extend_from_slice(&resp);
            if stream.write_all(&out).is_err() {
                return;
            }
        }
    }

    /// Remove the socket (and its directory) — only if the path still is
    /// the socket this agent created, so a restarted agent that re-bound
    /// the same path keeps its socket.
    fn cleanup(sock: &Path, dir: Option<&Path>, ours: Option<(u64, u64)>) {
        use std::os::unix::fs::MetadataExt;
        let same = std::fs::symlink_metadata(sock)
            .ok()
            .is_some_and(|m| Some((m.dev(), m.ino())) == ours);
        if same {
            let _ = std::fs::remove_file(sock);
        }
        if let Some(d) = dir {
            let _ = std::fs::remove_dir(d);
        }
    }

    /// Accept loop until a signal arrives, or until `watch_pid` (the
    /// command's process) is gone.
    fn serve(
        listener: UnixListener,
        state: Arc<Mutex<AgentState>>,
        debug: bool,
        watch_pid: Option<i32>,
    ) {
        let _ = listener.set_nonblocking(true);
        while !STOP.load(Ordering::Relaxed) {
            if let Ok(mut s) = state.lock() {
                drop_keys_if_signalled(&mut s);
            }
            match listener.accept() {
                Ok((stream, _)) => {
                    let _ = stream.set_nonblocking(false);
                    let st = state.clone();
                    std::thread::spawn(move || serve_conn(stream, st, debug));
                }
                Err(e) if e.kind() == ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(100));
                    // SAFETY: kill(pid, 0) only probes for existence.
                    if let Some(pid) = watch_pid
                        && unsafe { libc::kill(pid, 0) } != 0
                    {
                        break;
                    }
                }
                Err(e) if e.kind() == ErrorKind::Interrupted => {}
                Err(e) => {
                    eprintln!("ssh-agent: accept: {e}");
                    std::thread::sleep(Duration::from_millis(100));
                }
            }
        }
    }

    /// OpenSSH's `ask_permission`: run the askpass helper (`$SSH_ASKPASS`,
    /// with `SSH_ASKPASS_PROMPT=confirm`) when a display is available (or
    /// `SSH_ASKPASS_REQUIRE=force`); an empty answer or "yes" allows.
    fn ask_permission(prompt: &str) -> bool {
        let set = |v: &str| std::env::var_os(v).is_some_and(|s| !s.is_empty());
        let require = std::env::var("SSH_ASKPASS_REQUIRE").unwrap_or_default();
        let allowed = if require.eq_ignore_ascii_case("force") {
            true
        } else if require.eq_ignore_ascii_case("never") {
            false
        } else {
            set("DISPLAY") || set("WAYLAND_DISPLAY")
        };
        if !allowed {
            return false;
        }
        let askpass = std::env::var_os("SSH_ASKPASS")
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "/usr/bin/ssh-askpass".into());
        let Ok(out) = std::process::Command::new(askpass)
            .arg(prompt)
            .env("SSH_ASKPASS_PROMPT", "confirm")
            .stdin(std::process::Stdio::null())
            .stderr(std::process::Stdio::inherit())
            .output()
        else {
            return false;
        };
        let answer = String::from_utf8_lossy(&out.stdout);
        let answer = answer.split(['\r', '\n']).next().unwrap_or("");
        out.status.success() && (answer.is_empty() || answer.eq_ignore_ascii_case("yes"))
    }

    /// Whether askpass may be shown (a display, or `SSH_ASKPASS_REQUIRE`).
    fn askpass_allowed() -> bool {
        let set = |v: &str| std::env::var_os(v).is_some_and(|s| !s.is_empty());
        let require = std::env::var("SSH_ASKPASS_REQUIRE").unwrap_or_default();
        if require.eq_ignore_ascii_case("force") {
            true
        } else if require.eq_ignore_ascii_case("never") {
            false
        } else {
            set("DISPLAY") || set("WAYLAND_DISPLAY")
        }
    }

    fn askpass_command() -> std::process::Command {
        let askpass = std::env::var_os("SSH_ASKPASS")
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "/usr/bin/ssh-askpass".into());
        std::process::Command::new(askpass)
    }

    /// What a security key asks for while the agent signs with it, as
    /// OpenSSH's agent asks: a notification (askpass with
    /// `SSH_ASKPASS_PROMPT=none`, closed once signed) to touch it, and its
    /// PIN through askpass.
    #[cfg(feature = "security-key")]
    #[derive(Default)]
    struct AskpassSkPrompt {
        notifier: Mutex<Option<std::process::Child>>,
    }

    #[cfg(feature = "security-key")]
    impl puressh::sk::Prompt for AskpassSkPrompt {
        fn touch(&self, key: &puressh::key::PrivateKey) {
            let pk = key.public_key();
            let msg = format!(
                "Confirm user presence for key {} {}",
                pk.type_label(),
                pk.sha256_fingerprint()
            );
            if !askpass_allowed() {
                eprintln!("{msg}");
                return;
            }
            let child = askpass_command()
                .arg(&msg)
                .env("SSH_ASKPASS_PROMPT", "none")
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::null())
                .spawn()
                .ok();
            if let Ok(mut n) = self.notifier.lock() {
                *n = child;
            }
        }

        fn pin(
            &self,
            key: &puressh::key::PrivateKey,
        ) -> Option<purecrypto::zeroize::Zeroizing<String>> {
            if !askpass_allowed() {
                return None;
            }
            let pk = key.public_key();
            let touch = key
                .sk_credential()
                .is_some_and(|c| c.flags & puressh::sk::USER_PRESENCE_REQD != 0);
            let prompt = format!(
                "Enter PIN{}for {} key {}: ",
                if touch {
                    " and confirm user presence "
                } else {
                    " "
                },
                pk.type_label(),
                pk.sha256_fingerprint()
            );
            let out = askpass_command()
                .arg(prompt)
                .stdin(std::process::Stdio::null())
                .stderr(std::process::Stdio::inherit())
                .output()
                .ok()?;
            let pin = purecrypto::zeroize::Zeroizing::new(
                String::from_utf8_lossy(&out.stdout)
                    .split(['\r', '\n'])
                    .next()
                    .unwrap_or("")
                    .to_string(),
            );
            let mut raw = out.stdout;
            purecrypto::zeroize::Zeroize::zeroize(&mut raw);
            (out.status.success() && !pin.is_empty()).then_some(pin)
        }

        fn done(&self) {
            if let Ok(mut n) = self.notifier.lock()
                && let Some(mut child) = n.take()
            {
                let _ = child.kill();
                let _ = child.wait();
            }
        }
    }

    fn install_signals() {
        // SAFETY: the handler only stores into an AtomicBool.
        unsafe {
            for sig in [libc::SIGTERM, libc::SIGINT, libc::SIGHUP] {
                libc::signal(sig, on_signal as *const () as libc::sighandler_t);
            }
            libc::signal(libc::SIGPIPE, libc::SIG_IGN);
            libc::signal(libc::SIGUSR1, on_keydrop as *const () as libc::sighandler_t);
        }
    }

    fn disable_tracing() {
        #[cfg(any(target_os = "linux", target_os = "android"))]
        // SAFETY: PR_SET_DUMPABLE takes plain integer arguments.
        unsafe {
            libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0);
        }
        #[cfg(target_os = "macos")]
        // SAFETY: PT_DENY_ATTACH takes no address or data.
        unsafe {
            libc::ptrace(libc::PT_DENY_ATTACH, 0, std::ptr::null_mut(), 0);
        }
    }

    /// Where the agent listens: its socket, the path it made (`None` for
    /// a socket handed over by socket activation) and, for a `shared:`
    /// directory, the directory to remove with it.
    type Listening = (UnixListener, Option<PathBuf>, Option<PathBuf>);

    fn listen(o: &Opts) -> Result<Listening, Exit> {
        if o.bind.is_none()
            && o.command.is_empty()
            && o.foreground
            && let Some(l) = activated_socket().map_err(Exit::Fatal)?
        {
            return Ok((l, None, None));
        }
        if let Some(path) = &o.bind {
            let l = bind_private(path)
                .map_err(|e| Exit::Fail(bind_error("unix_listener", path, &e)))?;
            return Ok((l, Some(path.clone()), None));
        }
        let home =
            home_dir().ok_or_else(|| Exit::Fatal("Couldn't determine home directory".into()))?;
        if !o.keep_stale {
            cleanup_stale(&o.dirspec, &home, false);
        }
        let (l, path, dir) = listen_dirspec(&o.dirspec, &home)
            .map_err(|e| Exit::Fatal(format!("{e}\nmain: Couldn't prepare agent socket")))?;
        Ok((l, Some(path), dir))
    }

    pub fn run() -> Result<i32, Exit> {
        let args: Vec<String> = std::env::args().skip(1).collect();
        let o = parse_args(&args)?;
        if o.kill {
            return kill_agent(&o).map_err(Exit::Fail);
        }
        if o.clean_only > 0 {
            let home = home_dir()
                .ok_or_else(|| Exit::Fatal("Couldn't determine home directory".into()))?;
            cleanup_stale(&o.dirspec, &home, o.clean_only > 1);
            // Sic: OpenSSH prints the directory spec after the `~/`.
            println!("Deleted stale agent sockets in ~/{SOCKET_DIR}");
            return Ok(0);
        }
        // Like OpenSSH: keep other processes of the same user from attaching
        // to the agent (ptrace, /proc/<pid>/mem) and from getting a core
        // dump with the keys in it. Not in debug mode, as with OpenSSH.
        if !o.debug {
            disable_tracing();
        }

        let (listener, sock, dir) = listen(&o)?;
        let ours = sock.as_ref().and_then(|s| {
            use std::os::unix::fs::MetadataExt;
            std::fs::symlink_metadata(s)
                .ok()
                .map(|m| (m.dev(), m.ino()))
        });
        let cleanup_all = || {
            if let Some(s) = &sock {
                cleanup(s, dir.as_deref(), ours);
            }
        };

        let mut state = AgentState::new();
        state.set_default_lifetime(o.lifetime);
        state.set_md5_fingerprints(o.md5);
        state.set_confirm(Box::new(ask_permission));
        if let Some(p) = &o.providers.allowed_providers {
            state.set_allowed_providers(p);
        }
        state.set_remote_add_provider(o.providers.remote_add_provider);
        if !o.providers.restrict_websafe {
            state.set_websafe_allowlist(None);
        } else if let Some(list) = &o.providers.websafe_allow {
            state.set_websafe_allowlist(Some(list));
        }
        #[cfg(feature = "security-key")]
        state.set_security_key_prompt(Arc::new(AskpassSkPrompt::default()));
        let state = Arc::new(Mutex::new(state));

        if o.foreground {
            if let Some(s) = &sock {
                print!("{}", env_lines(&o, s, None, std::process::id()));
                let _ = std::io::stdout().flush();
            }
            install_signals();
            serve(listener, state, o.debug, None);
            cleanup_all();
            return Ok(0);
        }
        let sock = sock.clone().expect("only socket activation has no path");

        // SAFETY: single-threaded at this point; both branches continue
        // with ordinary code.
        let parent_pid = std::process::id() as i32;
        match unsafe { libc::fork() } {
            -1 => Err(Exit::Fail(format!(
                "fork: {}",
                strerror(&std::io::Error::last_os_error())
            ))),
            0 => {
                // The agent.
                // SAFETY: setsid / chdir / dup2 in the freshly forked child.
                unsafe {
                    libc::setsid();
                    libc::chdir(c"/".as_ptr());
                }
                if let Ok(null) = std::fs::OpenOptions::new()
                    .read(true)
                    .write(true)
                    .open("/dev/null")
                {
                    let _ = nix::unistd::dup2_stdin(&null);
                    let _ = nix::unistd::dup2_stdout(&null);
                    if !o.debug {
                        let _ = nix::unistd::dup2_stderr(&null);
                    }
                }
                install_signals();
                let watch = (!o.command.is_empty()).then_some(parent_pid);
                serve(listener, state, o.debug, watch);
                cleanup_all();
                // SAFETY: leave without running the parent's atexit state.
                unsafe { libc::_exit(0) }
            }
            child => {
                drop(listener);
                if o.command.is_empty() {
                    print!("{}", env_lines(&o, &sock, Some(child as u32), child as u32));
                    let _ = std::io::stdout().flush();
                    return Ok(0);
                }
                // Run the command with the agent's variables; the agent
                // exits once this process is gone.
                let err = std::process::Command::new(&o.command[0])
                    .args(&o.command[1..])
                    .env("SSH_AUTH_SOCK", &sock)
                    .env("SSH_AGENT_PID", child.to_string())
                    .exec();
                // SAFETY: plain kill(2) of our own child.
                unsafe { libc::kill(child, libc::SIGTERM) };
                Err(Exit::Fail(format!("{}: {}", o.command[0], strerror(&err))))
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        fn parse(args: &[&str]) -> Result<Opts, Exit> {
            let v: Vec<String> = args.iter().map(|s| s.to_string()).collect();
            parse_args(&v)
        }

        #[test]
        fn lifetimes() {
            assert_eq!(parse_lifetime("90"), Some(90));
            assert_eq!(parse_lifetime("1h30m"), Some(5400));
            assert_eq!(parse_lifetime("1h30"), Some(3630));
            assert_eq!(parse_lifetime("2d"), Some(172800));
            assert_eq!(parse_lifetime("1.5"), Some(1));
            assert_eq!(parse_lifetime("0"), Some(0));
            assert_eq!(parse_lifetime("1.5m"), None);
            assert_eq!(parse_lifetime("1s2"), None);
            assert_eq!(parse_lifetime("1x"), None);
            assert_eq!(parse_lifetime(""), None);
        }

        #[test]
        fn conflicting_options_are_usage_errors() {
            for args in [
                &["-c", "-s"][..],
                &["-s", "-c"],
                &["-d", "-D"],
                &["-D", "-D"],
                &["-a", "x", "-T"],
                &["-A", "user:x", "-a", "y"],
                &["-c", "true"],
                &["-u", "true"],
            ] {
                assert_eq!(parse(args).err(), Some(Exit::Usage(None)), "{args:?}");
            }
            assert!(parse(&["-U", "-T", "true"]).is_ok());
        }

        #[test]
        fn option_values_are_checked() {
            assert_eq!(
                parse(&["-E", "sha1"]).err(),
                Some(Exit::Fatal("Invalid hash algorithm \"sha1\"".into()))
            );
            assert!(parse(&["-E", "md5"]).unwrap().md5);
            assert_eq!(
                parse(&["-O", "bogus"]).err(),
                Some(Exit::Fatal("Unknown -O option".into()))
            );
            assert_eq!(
                parse(&["-O", "websafe-allow=a", "-O", "websafe-allow=b"]).err(),
                Some(Exit::Fatal("websafe-allow already set".into()))
            );
            let o = parse(&["-O", "no-restrict-websafe", "-O", "allow-remote-pkcs11"]).unwrap();
            assert!(!o.providers.restrict_websafe && o.providers.remote_add_provider);
            assert_eq!(
                parse(&["-P", "a", "-P", "b"]).err(),
                Some(Exit::Fatal("-P option already specified".into()))
            );
            assert_eq!(
                parse(&["-t", "1y"]).err(),
                Some(Exit::Usage(Some("Invalid lifetime".into())))
            );
            assert_eq!(parse(&["-V", "-x"]).err(), Some(Exit::Version));
        }

        #[test]
        fn socket_directories() {
            assert_eq!(parse(&[]).unwrap().dirspec, SOCKET_DIR);
            assert_eq!(parse(&["-T"]).unwrap().dirspec, SOCKET_TMPDIR);
            assert_eq!(
                expand_dirspec("x/%U/%%", "/home/u").unwrap(),
                PathBuf::from(format!("/home/u/x/{}/%", nix::unistd::getuid()))
            );
            assert_eq!(
                expand_dirspec("/a/%h", "/h").unwrap(),
                PathBuf::from("/a//h")
            );
            assert!(expand_dirspec("%z", "/h").is_err());
            assert!(listen_dirspec("nope", "/h").is_err());
            assert!(listen_dirspec("shared:rel", "/h").is_err());
        }

        #[test]
        fn socket_names_are_quoted_as_openssh() {
            assert_eq!(shell_word("/tmp/a"), "/tmp/a");
            assert_eq!(shell_word("/tmp/a b"), "\"/tmp/a b\"");
            assert_eq!(shell_word("/tmp/a\"b"), "/tmp/a\\\"b");
        }
    }
}
