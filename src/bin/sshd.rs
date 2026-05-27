//! `sshd` — puressh's SSH server daemon.
//!
//! ```text
//! sshd [-d] [-p port] [-h host_key_file]... [-A authorized_keys_file]
//!      [-u allowed_user]...
//! ```
//!
//! Each accepted connection is handled by a freshly `fork()`ed child
//! process. The daemon parent keeps the listener and immediately returns
//! to `accept()`. Killing the daemon does **not** kill live sessions —
//! children are reparented to PID 1 and keep running. The child drops the
//! listener fd so the daemon can be restarted on the same port without
//! waiting on `SO_REUSEADDR` semantics.
//!
//! Interactive shells (`pty-req` + `shell`) are wired through a second
//! `forkpty()` inside the connection child. The grandchild's exit status
//! is reaped via `waitpid(WNOHANG)` and forwarded to the client as
//! `exit-status` / `exit-signal`.
//!
//! Windows builds compile but `main` prints "not supported" — every line
//! of the implementation lives behind `#[cfg(unix)]`.

#[cfg(not(unix))]
fn main() -> std::process::ExitCode {
    eprintln!("puressh sshd: only supported on Unix-like systems");
    std::process::ExitCode::from(2)
}

#[cfg(unix)]
fn main() -> std::process::ExitCode {
    imp::main()
}

#[cfg(unix)]
mod imp {
    use std::collections::HashSet;
    use std::os::fd::{AsFd, AsRawFd, OwnedFd};
    use std::process::{Command, ExitCode};
    use std::sync::Arc;

    use nix::errno::Errno;
    use nix::fcntl::{fcntl, FcntlArg, OFlag};
    use nix::libc;
    use nix::sys::signal::{kill, signal, SigHandler, Signal};
    use nix::sys::wait::{waitpid, WaitPidFlag, WaitStatus};
    use nix::unistd::{execvp, fork, ForkResult, Pid};

    use puressh::auth::{AuthAttempt, AuthDecision, Authenticator};
    use puressh::hostkey::HostKey;
    use puressh::key::{PrivateKey, PublicKey};
    use puressh::server::{
        handle_session, AuthenticatorFactory, CommandHandler, Config, ExecResult, PtySpec,
        ShellExitStatus, ShellHandler, ShellSession,
    };

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
            let priv_key = PrivateKey::parse_openssh_pem(&pem, None)
                .map_err(|e| format!("parse {path}: {e}"))?;
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

    // -------------------------------------------------------------------------
    // NixShellHandler — backend for `pty-req` + `shell`. Spawns the user's
    // login shell under `forkpty()`, exposes the master fd as a non-blocking
    // `ShellSession`.
    // -------------------------------------------------------------------------

    struct NixShellHandler {
        debug: bool,
    }

    impl ShellHandler for NixShellHandler {
        fn spawn(
            &self,
            user: &str,
            pty: Option<PtySpec>,
        ) -> puressh::Result<Box<dyn ShellSession>> {
            match pty {
                Some(spec) => spawn_pty_shell(user, &spec, self.debug),
                None => spawn_pipe_shell(user, self.debug),
            }
        }
    }

    /// Build a `puressh::Error` from a `nix::errno::Errno` by wrapping the
    /// raw OS error as an `io::Error`. Avoids leaking nix types through the
    /// trait surface.
    fn nix_io(e: Errno) -> puressh::Error {
        puressh::Error::Io(std::io::Error::from_raw_os_error(e as i32))
    }

    fn spawn_pty_shell(
        user: &str,
        spec: &PtySpec,
        debug: bool,
    ) -> puressh::Result<Box<dyn ShellSession>> {
        let _ = user; // Not yet used — would drive setuid/getpwnam in a future revision.
        let ws = nix::pty::Winsize {
            ws_row: clamp_u16(spec.rows),
            ws_col: clamp_u16(spec.cols),
            ws_xpixel: clamp_u16(spec.px_w),
            ws_ypixel: clamp_u16(spec.px_h),
        };
        // SAFETY: `forkpty` is `unsafe` because the child runs in a
        // post-fork window where only async-signal-safe ops are guaranteed
        // safe until exec. We exec immediately in the child branch.
        let fp = unsafe { nix::pty::forkpty(&ws, None) }.map_err(nix_io)?;
        match fp {
            nix::pty::ForkptyResult::Child => {
                // Restore default signal handlers so the user's shell isn't
                // born with our SIG_IGN'd SIGCHLD masking its children.
                // (The connection child already reset SIGCHLD to SIG_DFL
                // before this point, but be explicit.)
                let _ = unsafe { signal(Signal::SIGCHLD, SigHandler::SigDfl) };
                // execvp the user's shell. /bin/sh -l keeps the dependency
                // surface tiny; a fuller impl would consult getpwnam.
                let sh = c"/bin/sh";
                let arg0 = c"sh";
                let argl = c"-l";
                let _ = execvp(sh, &[arg0, argl]);
                // execvp failed (binary missing, ENOEXEC, …). Use _exit
                // rather than exit so we don't run stdlib atexit handlers
                // inherited from the parent.
                unsafe { libc::_exit(127) };
            }
            nix::pty::ForkptyResult::Parent { child, master } => {
                // Make the master non-blocking so `ShellSession::read`/`write`
                // can return EAGAIN → Ok(0) instead of stalling the per-tick
                // poll loop.
                let raw = master.as_raw_fd();
                let cur = fcntl(master.as_fd(), FcntlArg::F_GETFL).map_err(nix_io)?;
                let new = OFlag::from_bits_truncate(cur) | OFlag::O_NONBLOCK;
                fcntl(master.as_fd(), FcntlArg::F_SETFL(new)).map_err(nix_io)?;
                if debug {
                    eprintln!(
                        "sshd: spawned pty shell pid={} master_fd={}",
                        child.as_raw(),
                        raw
                    );
                }
                Ok(Box::new(NixShellSession {
                    master: Some(master),
                    child_pid: child,
                    cached_exit: None,
                }))
            }
        }
    }

    fn spawn_pipe_shell(_user: &str, _debug: bool) -> puressh::Result<Box<dyn ShellSession>> {
        // `ssh -T` (no PTY) lands here. We don't implement the pipe path
        // yet — clients that want a shell without a PTY get a polite
        // protocol-level failure.
        Err(puressh::Error::Unsupported(
            "shell without pty-req is not yet supported by this sshd",
        ))
    }

    fn clamp_u16(v: u32) -> u16 {
        if v > u16::MAX as u32 {
            u16::MAX
        } else {
            v as u16
        }
    }

    /// One live PTY-shell session, holding the master fd and the child's PID.
    struct NixShellSession {
        master: Option<OwnedFd>,
        child_pid: Pid,
        cached_exit: Option<ShellExitStatus>,
    }

    impl ShellSession for NixShellSession {
        fn read(&mut self, buf: &mut [u8]) -> puressh::Result<usize> {
            let Some(master) = self.master.as_ref() else {
                return Ok(0);
            };
            match nix::unistd::read(master.as_fd(), buf) {
                Ok(n) => Ok(n),
                // EAGAIN and EWOULDBLOCK alias on every platform we support,
                // so a single arm is enough — listing both triggers a
                // `unreachable_patterns` warning.
                Err(Errno::EAGAIN) => Ok(0),
                // On Linux, reading the master fd after the slave is fully
                // closed returns EIO. macOS returns 0. Both mean "no more
                // bytes ever" — surface as Ok(0); `try_exit` will pick up
                // the child's status on the next tick.
                Err(Errno::EIO) => Ok(0),
                Err(e) => Err(nix_io(e)),
            }
        }

        fn write(&mut self, data: &[u8]) -> puressh::Result<usize> {
            let Some(master) = self.master.as_ref() else {
                return Ok(0);
            };
            match nix::unistd::write(master.as_fd(), data) {
                Ok(n) => Ok(n),
                Err(Errno::EAGAIN) => Ok(0),
                Err(e) => Err(nix_io(e)),
            }
        }

        fn close_stdin(&mut self) -> puressh::Result<()> {
            // No half-close on a PTY master, so send EOT (Ctrl-D) — the
            // line discipline turns this into EOF for ICANON readers.
            if let Some(master) = self.master.as_ref() {
                let _ = nix::unistd::write(master.as_fd(), &[0x04u8]);
            }
            Ok(())
        }

        fn resize(&mut self, cols: u32, rows: u32, px_w: u32, px_h: u32) -> puressh::Result<()> {
            let Some(master) = self.master.as_ref() else {
                return Ok(0).map(|_| ());
            };
            let ws = libc::winsize {
                ws_row: clamp_u16(rows),
                ws_col: clamp_u16(cols),
                ws_xpixel: clamp_u16(px_w),
                ws_ypixel: clamp_u16(px_h),
            };
            // SAFETY: TIOCSWINSZ takes `*const struct winsize`; we pass a
            // pointer to a local. `ioctl` is variadic in libc; the cast on
            // the request constant covers platform-specific types
            // (`c_ulong` on Linux, `u_long` on BSD).
            let rc = unsafe {
                libc::ioctl(
                    master.as_raw_fd(),
                    libc::TIOCSWINSZ as _,
                    &ws as *const libc::winsize,
                )
            };
            if rc == -1 {
                return Err(puressh::Error::Io(std::io::Error::last_os_error()));
            }
            Ok(())
        }

        fn try_exit(&mut self) -> Option<ShellExitStatus> {
            if let Some(s) = self.cached_exit.clone() {
                return Some(s);
            }
            match waitpid(self.child_pid, Some(WaitPidFlag::WNOHANG)) {
                Ok(WaitStatus::Exited(_, code)) => {
                    let code_u32 = if code < 0 { 255u32 } else { code as u32 };
                    let s = ShellExitStatus::Exited(code_u32);
                    self.cached_exit = Some(s.clone());
                    Some(s)
                }
                Ok(WaitStatus::Signaled(_, sig, core)) => {
                    let name = strip_sig_prefix(&format!("{sig:?}"));
                    let s = ShellExitStatus::Signalled {
                        name,
                        core_dumped: core,
                        message: String::new(),
                    };
                    self.cached_exit = Some(s.clone());
                    Some(s)
                }
                // StillAlive / Stopped / Continued: keep waiting.
                Ok(_) => None,
                // ECHILD: child already reaped (e.g. by SIG_IGN before we
                // overrode it). Treat as clean exit so the channel closes.
                Err(Errno::ECHILD) => {
                    let s = ShellExitStatus::Exited(0);
                    self.cached_exit = Some(s.clone());
                    Some(s)
                }
                Err(_) => None,
            }
        }
    }

    impl Drop for NixShellSession {
        fn drop(&mut self) {
            // Best-effort: HUP the child, give it a tick to die, then reap.
            if self.cached_exit.is_none() {
                let _ = kill(self.child_pid, Signal::SIGHUP);
                let _ = waitpid(self.child_pid, Some(WaitPidFlag::WNOHANG));
            }
            // master OwnedFd auto-closes on drop.
        }
    }

    fn strip_sig_prefix(s: &str) -> String {
        s.strip_prefix("SIG").unwrap_or(s).to_string()
    }

    // -------------------------------------------------------------------------
    // Accept loop with fork() per connection.
    // -------------------------------------------------------------------------

    /// Set SIGCHLD to SIG_IGN so the kernel auto-reaps connection children
    /// — no zombies pile up in the daemon, even under heavy connection
    /// churn. The connection child resets SIGCHLD to SIG_DFL before its
    /// own forkpty so it can `waitpid(WNOHANG)` for the user shell's
    /// real exit status.
    fn install_parent_sigchld() -> Result<(), String> {
        // SAFETY: setting SIGCHLD=SIG_IGN is async-signal-safe and changes
        // no async invariants the daemon depends on.
        unsafe { signal(Signal::SIGCHLD, SigHandler::SigIgn) }
            .map(|_| ())
            .map_err(|e| format!("signal(SIGCHLD, SIG_IGN): {e}"))
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

        let cfg = Arc::new(
            Config::new(
                host_keys,
                factory,
                vec!["publickey"],
                Arc::new(ShellCommandHandler { debug: cli.debug }),
            )
            .with_shell(Arc::new(NixShellHandler { debug: cli.debug })),
        );

        install_parent_sigchld()?;

        let addr = format!("127.0.0.1:{}", cli.port);
        let listener =
            std::net::TcpListener::bind(&addr).map_err(|e| format!("bind {addr}: {e}"))?;

        eprintln!(
            "puressh sshd listening on {addr} (pid {})",
            std::process::id()
        );

        loop {
            let (stream, peer) = match listener.accept() {
                Ok(p) => p,
                Err(e) => {
                    eprintln!("sshd: accept: {e}");
                    continue;
                }
            };
            // SAFETY: the daemon parent is single-threaded — no `thread::spawn`
            // in this loop — so the `fork()` is followed by ordinary Rust
            // code with no async-signal-safety concerns. The kernel
            // duplicates fds across fork; the child inherits its own copy of
            // `stream` and `listener`.
            match unsafe { fork() } {
                Ok(ForkResult::Parent { child }) => {
                    if cli.debug {
                        eprintln!("sshd: forked connection {peer} -> pid {}", child.as_raw());
                    }
                    // Parent has no further use for this socket — its
                    // refcount in the child keeps it alive.
                    drop(stream);
                }
                Ok(ForkResult::Child) => {
                    // CRUCIAL: release the listener fd before we enter the
                    // long session loop. Without this, restarting the
                    // daemon on the same port keeps hitting EADDRINUSE
                    // because the kernel sees an open listener.
                    drop(listener);
                    // Restore default SIGCHLD so our forkpty grandchildren
                    // can be reaped via waitpid(WNOHANG).
                    // SAFETY: same justification as the parent — we run in
                    // a single-threaded process here.
                    let _ = unsafe { signal(Signal::SIGCHLD, SigHandler::SigDfl) };

                    let rc = match handle_session(stream, cfg.clone()) {
                        Ok(()) => 0,
                        Err(e) => {
                            if cli.debug {
                                eprintln!("sshd[child]: session error: {e}");
                            }
                            1
                        }
                    };
                    // Skip atexit machinery — we've already cleanly
                    // returned from handle_session.
                    unsafe { libc::_exit(rc) };
                }
                Err(e) => {
                    eprintln!("sshd: fork: {e}");
                    drop(stream);
                    // Keep serving — a transient fork failure (EAGAIN
                    // under fork-bomb-style load) is not fatal.
                }
            }
        }
    }

    pub fn main() -> ExitCode {
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
}
