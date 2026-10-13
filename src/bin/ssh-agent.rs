//! `ssh-agent` — hold private keys in memory and sign on behalf of clients.
//!
//! ```text
//! ssh-agent [-c | -s] [-Dd] [-a bind_address] [-t life] [command [arg ...]]
//! ssh-agent [-c | -s] -k
//! ```
//!
//! Compatible with OpenSSH's agent and its clients (`ssh`, `ssh-add`, git):
//! the socket speaks the standard agent protocol (see
//! `puressh::agent::AgentState` for what is supported). Without a command
//! the agent forks into the background and prints the shell commands that
//! set `SSH_AUTH_SOCK` / `SSH_AGENT_PID` (`eval $(ssh-agent)`); with one, it
//! runs the command with those variables set and exits when it does.

#[cfg(not(unix))]
fn main() -> std::process::ExitCode {
    eprintln!("ssh-agent: only supported on Unix-like systems");
    std::process::ExitCode::from(1)
}

#[cfg(unix)]
fn main() -> std::process::ExitCode {
    match imp::run() {
        Ok(code) => std::process::ExitCode::from(code as u8),
        Err(e) => {
            eprintln!("ssh-agent: {e}");
            std::process::ExitCode::from(1)
        }
    }
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

    const USAGE: &str = "usage: ssh-agent [-c | -s] [-Dd] [-a bind_address] [-E fingerprint_hash]\n                 [-O option] [-P allowed_providers] [-t life]\n       ssh-agent [-c | -s] [-Dd] [-a bind_address] [-E fingerprint_hash]\n                 [-O option] [-P allowed_providers] [-t life] command [arg ...]\n       ssh-agent [-c | -s] -k";

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
        lifetime: Option<Duration>,
        command: Vec<String>,
    }

    /// OpenSSH time format: `90`, `90s`, `10m`, `1h30m`, `2d`, `1w`.
    fn parse_lifetime(v: &str) -> Option<Duration> {
        let mut total = 0u64;
        let mut num = String::new();
        for c in v.chars() {
            if c.is_ascii_digit() {
                num.push(c);
                continue;
            }
            let n: u64 = num.parse().ok()?;
            num.clear();
            total += n * match c.to_ascii_lowercase() {
                's' => 1,
                'm' => 60,
                'h' => 3600,
                'd' => 86400,
                'w' => 604800,
                _ => return None,
            };
        }
        if !num.is_empty() {
            total += num.parse::<u64>().ok()?;
        }
        (total > 0).then(|| Duration::from_secs(total))
    }

    fn parse_args(args: &[String]) -> Result<Opts, String> {
        let shell_is_csh = std::env::var("SHELL").is_ok_and(|s| s.ends_with("csh"));
        let mut o = Opts {
            csh: shell_is_csh,
            foreground: false,
            debug: false,
            kill: false,
            bind: None,
            lifetime: None,
            command: Vec::new(),
        };
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
                if "aEOPt".contains(c) {
                    let attached: String = chars[j + 1..].iter().collect();
                    let v = if !attached.is_empty() {
                        attached
                    } else {
                        i += 1;
                        args.get(i)
                            .ok_or_else(|| format!("option requires an argument -- {c}\n{USAGE}"))?
                            .clone()
                    };
                    match c {
                        'a' => o.bind = Some(PathBuf::from(v)),
                        't' => {
                            o.lifetime = Some(
                                parse_lifetime(&v)
                                    .ok_or_else(|| format!("Invalid lifetime {v}"))?,
                            )
                        }
                        // Fingerprint hash, PKCS#11 providers, options:
                        // nothing to configure in this agent.
                        _ => {}
                    }
                    break;
                }
                match c {
                    'c' => o.csh = true,
                    's' => o.csh = false,
                    'D' => o.foreground = true,
                    'd' => {
                        o.foreground = true;
                        o.debug = true;
                    }
                    'k' => o.kill = true,
                    _ => return Err(format!("unknown option -- {c}\n{USAGE}")),
                }
                j += 1;
            }
            i += 1;
        }
        Ok(o)
    }

    fn env_lines(o: &Opts, sock: &Path, pid: u32) -> String {
        let sock = sock.display();
        if o.csh {
            format!(
                "setenv SSH_AUTH_SOCK {sock};\nsetenv SSH_AGENT_PID {pid};\necho Agent pid {pid};\n"
            )
        } else {
            format!(
                "SSH_AUTH_SOCK={sock}; export SSH_AUTH_SOCK;\nSSH_AGENT_PID={pid}; export SSH_AGENT_PID;\necho Agent pid {pid};\n"
            )
        }
    }

    /// `ssh-agent -k`: stop the agent named by `$SSH_AGENT_PID`.
    fn kill_agent(o: &Opts) -> Result<i32, String> {
        let pid: i32 = std::env::var("SSH_AGENT_PID")
            .map_err(|_| "SSH_AGENT_PID not set, cannot kill agent".to_string())?
            .parse()
            .map_err(|_| "SSH_AGENT_PID not a valid pid".to_string())?;
        // SAFETY: plain kill(2).
        if pid < 1 || unsafe { libc::kill(pid, libc::SIGTERM) } != 0 {
            return Err(format!("kill: {}", std::io::Error::last_os_error()));
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

    /// `$TMPDIR/ssh-XXXXXXXXXX/agent.<ppid>`, the directory created 0700.
    fn default_socket() -> Result<(PathBuf, Option<PathBuf>), String> {
        use purecrypto::rng::{OsRng, RngCore};
        let tmp = std::env::var_os("TMPDIR")
            .map(PathBuf::from)
            .filter(|p| p.is_absolute())
            .unwrap_or_else(|| PathBuf::from("/tmp"));
        const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        for _ in 0..16 {
            let mut raw = [0u8; 10];
            OsRng.fill_bytes(&mut raw);
            let suffix: String = raw
                .iter()
                .map(|b| ALPHABET[*b as usize % ALPHABET.len()] as char)
                .collect();
            let dir = tmp.join(format!("ssh-{suffix}"));
            match std::fs::DirBuilder::new().mode(0o700).create(&dir) {
                Ok(()) => {
                    // SAFETY: getppid(2) cannot fail.
                    let ppid = unsafe { libc::getppid() };
                    return Ok((dir.join(format!("agent.{ppid}")), Some(dir)));
                }
                Err(e) if e.kind() == ErrorKind::AlreadyExists => continue,
                Err(e) => return Err(format!("mkdir {}: {e}", dir.display())),
            }
        }
        Err("could not create a socket directory".into())
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
        #[cfg(not(any(target_os = "linux", target_os = "android")))]
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
            let mut req = zeroize::Zeroizing::new(vec![0u8; n]);
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

    pub fn run() -> Result<i32, String> {
        let args: Vec<String> = std::env::args().skip(1).collect();
        let o = parse_args(&args)?;
        if o.kill {
            return kill_agent(&o);
        }
        // Like OpenSSH: keep other processes of the same user from attaching
        // to the agent (ptrace, /proc/<pid>/mem) and from getting a core
        // dump with the keys in it. Not in debug mode, as with OpenSSH.
        if !o.debug {
            disable_tracing();
        }

        let (sock, dir) = match &o.bind {
            Some(p) => (p.clone(), None),
            None => default_socket()?,
        };
        // The socket is created owner-only, like OpenSSH's (umask 0177).
        // SAFETY: umask(2) cannot fail.
        let old_umask = unsafe { libc::umask(0o177) };
        let listener = UnixListener::bind(&sock);
        unsafe { libc::umask(old_umask) };
        let listener = listener.map_err(|e| format!("bind {}: {e}", sock.display()))?;
        let _ = std::fs::set_permissions(&sock, std::fs::Permissions::from_mode(0o600));
        let ours = {
            use std::os::unix::fs::MetadataExt;
            std::fs::symlink_metadata(&sock)
                .ok()
                .map(|m| (m.dev(), m.ino()))
        };

        let mut state = AgentState::new();
        state.set_default_lifetime(o.lifetime);
        state.set_confirm(Box::new(ask_permission));
        let state = Arc::new(Mutex::new(state));

        if o.foreground {
            print!("{}", env_lines(&o, &sock, std::process::id()));
            let _ = std::io::stdout().flush();
            install_signals();
            serve(listener, state, o.debug, None);
            cleanup(&sock, dir.as_deref(), ours);
            return Ok(0);
        }

        // SAFETY: single-threaded at this point; both branches continue
        // with ordinary code.
        let parent_pid = std::process::id() as i32;
        match unsafe { libc::fork() } {
            -1 => Err(format!("fork: {}", std::io::Error::last_os_error())),
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
                cleanup(&sock, dir.as_deref(), ours);
                // SAFETY: leave without running the parent's atexit state.
                unsafe { libc::_exit(0) }
            }
            child => {
                drop(listener);
                if o.command.is_empty() {
                    print!("{}", env_lines(&o, &sock, child as u32));
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
                Err(format!("{}: {err}", o.command[0]))
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn lifetimes() {
            assert_eq!(parse_lifetime("90"), Some(Duration::from_secs(90)));
            assert_eq!(parse_lifetime("1h30m"), Some(Duration::from_secs(5400)));
            assert_eq!(parse_lifetime("2d"), Some(Duration::from_secs(172800)));
            assert_eq!(parse_lifetime("1x"), None);
            assert_eq!(parse_lifetime("0"), None);
        }
    }
}
