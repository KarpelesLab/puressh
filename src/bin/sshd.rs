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
//! Interactive shells (`pty-req` + `shell`) allocate a PTY with
//! `openpty()` and fork manually so the slave path is known up-front —
//! the PAM session is opened with `PAM_TTY = /dev/pts/N` *before* the
//! grandchild forks off into the user's shell. The grandchild's exit
//! status is reaped via `waitpid(WNOHANG)` and forwarded to the client
//! as `exit-status` / `exit-signal`.
//!
//! When the `pam` feature is on (default), every successful SSH
//! authentication is followed by `pam_acct_mgmt` + `pam_open_session`
//! against service `sshd` — `pam_env` contributions land in the user's
//! shell environment and `pam_close_session` runs at connection
//! teardown. Building with `--no-default-features` (or any combination
//! that omits `pam`) drops the libpam runtime dep entirely; the binary
//! still works but offers no session management.
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
    use std::ffi::OsStr;
    use std::os::fd::{AsFd, AsRawFd, OwnedFd};
    use std::os::unix::ffi::OsStrExt;
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

    // -------------------------------------------------------------------------
    // PAM session gate.
    //
    // The `pam` feature compiles the real implementation against
    // `pam-client2`; without the feature, a no-op stub provides the same
    // surface so the rest of the binary doesn't need feature-gates. Either
    // way `ensure(user, tty)` is the only entry point handlers use.
    //
    // Lifetime model: the `PamGate` is wrapped in `Arc` and shared across
    // `ShellCommandHandler` + `NixShellHandler`. Because each connection
    // runs in its own `fork()`ed child, the gate's state (the live PAM
    // context, the cached env list, the peer address) is COW-isolated per
    // connection — there's no cross-connection bleed even though the
    // daemon's parent process never opens any PAM session itself.
    // -------------------------------------------------------------------------
    #[cfg(feature = "pam")]
    mod pam_gate {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;
        use std::sync::{Arc, Mutex};

        use pam_client2::conv_null::Conversation;
        use pam_client2::{Context, Flag, SessionToken};

        /// Holds the live PAM `Context` and the leaked session handle.
        /// Drop order matters: the leaked `Session` must be re-acquired
        /// (via `unleak_session`) so its own `Drop` calls
        /// `pam_close_session`, *then* the boxed context drops and calls
        /// `pam_end`.
        struct PamHolder {
            context: Box<Context<Conversation>>,
            token: Option<SessionToken>,
        }

        impl Drop for PamHolder {
            fn drop(&mut self) {
                if let Some(token) = self.token.take() {
                    // Re-attach the session to its context; the returned
                    // `Session` drops in place, closing the PAM session.
                    let _session = self.context.unleak_session(token);
                }
                // Box<Context<…>> drops next: pam_end.
            }
        }

        pub struct PamGate {
            service: &'static str,
            peer: Mutex<Option<String>>,
            envs: Mutex<Vec<(CString, CString)>>,
            inner: Mutex<Option<PamHolder>>,
            debug: bool,
        }

        impl PamGate {
            pub fn new(debug: bool) -> Arc<Self> {
                Arc::new(Self {
                    service: "sshd",
                    peer: Mutex::new(None),
                    envs: Mutex::new(Vec::new()),
                    inner: Mutex::new(None),
                    debug,
                })
            }

            /// Stash the peer address (used as `PAM_RHOST`). Should be
            /// called inside the per-connection child before any handler
            /// triggers `ensure`.
            pub fn set_peer(&self, peer: String) {
                *self.peer.lock().unwrap() = Some(peer);
            }

            /// Lazily open the PAM session for `user` with PAM_TTY set
            /// to `tty`. Strict: on failure, returns `Err` — the caller
            /// is expected to surface that as a CHANNEL_FAILURE or as
            /// `exit_status = 255`. Idempotent: subsequent calls return
            /// the same cached env list without re-opening.
            pub fn ensure(
                &self,
                user: &str,
                tty: &str,
            ) -> puressh::Result<Vec<(CString, CString)>> {
                let mut guard = self.inner.lock().unwrap();
                if guard.is_some() {
                    return Ok(self.envs.lock().unwrap().clone());
                }

                let mut ctx = Box::new(
                    Context::new(self.service, Some(user), Conversation::new())
                        .map_err(|e| pam_err("pam_start", e))?,
                );
                if let Some(rhost) = self.peer.lock().unwrap().clone() {
                    ctx.set_rhost(Some(&rhost))
                        .map_err(|e| pam_err("set_rhost", e))?;
                }
                ctx.set_tty(Some(tty)).map_err(|e| pam_err("set_tty", e))?;
                ctx.acct_mgmt(Flag::NONE)
                    .map_err(|e| pam_err("acct_mgmt", e))?;

                let session = ctx
                    .open_session(Flag::NONE)
                    .map_err(|e| pam_err("open_session", e))?;

                // Snapshot the PAM env. `iter_tuples` yields
                // `(&OsStr, &OsStr)`; we keep `CString`s because the
                // post-fork shell needs `*const c_char` for `setenv`.
                let envs: Vec<(CString, CString)> = session
                    .envlist()
                    .iter_tuples()
                    .filter_map(|(k, v)| {
                        let k = CString::new(k.as_bytes()).ok()?;
                        let v = CString::new(v.as_bytes()).ok()?;
                        Some((k, v))
                    })
                    .collect();

                let token = session.leak();
                *self.envs.lock().unwrap() = envs.clone();
                *guard = Some(PamHolder {
                    context: ctx,
                    token: Some(token),
                });
                if self.debug {
                    eprintln!(
                        "sshd: PAM session opened (user={user}, tty={tty}, envs={})",
                        envs.len()
                    );
                }
                Ok(envs)
            }
        }

        fn pam_err<E: std::fmt::Display>(phase: &'static str, e: E) -> puressh::Error {
            puressh::Error::Io(std::io::Error::other(format!("PAM {phase}: {e}")))
        }
    }

    #[cfg(not(feature = "pam"))]
    mod pam_gate {
        use std::ffi::CString;
        use std::sync::Arc;

        /// Stub gate used when the `pam` feature is off. All operations
        /// are no-ops so the rest of the binary can ignore the feature
        /// state.
        pub struct PamGate;

        impl PamGate {
            pub fn new(_debug: bool) -> Arc<Self> {
                Arc::new(PamGate)
            }
            pub fn set_peer(&self, _peer: String) {}
            pub fn ensure(
                &self,
                _user: &str,
                _tty: &str,
            ) -> puressh::Result<Vec<(CString, CString)>> {
                Ok(Vec::new())
            }
        }
    }

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
        pam: Arc<pam_gate::PamGate>,
        debug: bool,
    }

    impl CommandHandler for ShellCommandHandler {
        fn handle(&self, user: &str, command: &str) -> ExecResult {
            if self.debug {
                eprintln!("sshd: exec by {user}: {command}");
            }
            // Open the PAM session before spawning the child. `exec`
            // requests don't have a real tty, so we use "ssh" — matches
            // OpenSSH's behaviour for non-PTY channels. `ExecResult`
            // has no error channel, so PAM failure surfaces as exit
            // status 255 with the error message on stderr.
            let envs = match self.pam.ensure(user, "ssh") {
                Ok(e) => e,
                Err(e) => {
                    return ExecResult {
                        stdout: Vec::new(),
                        stderr: format!("sshd: PAM session open failed: {e}\n").into_bytes(),
                        exit_status: 255,
                    };
                }
            };
            let mut cmd = Command::new("sh");
            cmd.args(["-c", command]).env_clear();
            for (k, v) in &envs {
                cmd.env(
                    OsStr::from_bytes(k.to_bytes()),
                    OsStr::from_bytes(v.to_bytes()),
                );
            }
            match cmd.output() {
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
        pam: Arc<pam_gate::PamGate>,
        debug: bool,
    }

    impl ShellHandler for NixShellHandler {
        fn spawn(
            &self,
            user: &str,
            pty: Option<PtySpec>,
        ) -> puressh::Result<Box<dyn ShellSession>> {
            match pty {
                Some(spec) => spawn_pty_shell(&self.pam, user, &spec, self.debug),
                None => spawn_pipe_shell(&self.pam, user, self.debug),
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
        pam: &Arc<pam_gate::PamGate>,
        user: &str,
        spec: &PtySpec,
        debug: bool,
    ) -> puressh::Result<Box<dyn ShellSession>> {
        let ws = nix::pty::Winsize {
            ws_row: clamp_u16(spec.rows),
            ws_col: clamp_u16(spec.cols),
            ws_xpixel: clamp_u16(spec.px_w),
            ws_ypixel: clamp_u16(spec.px_h),
        };
        // Allocate the master/slave pair *before* forking. PAM_TTY must
        // be the slave's path on disk so PAM modules (pam_loginuid,
        // pam_systemd, pam_lastlog, …) can stat it; `forkpty` doesn't
        // expose that path pre-fork, hence the manual split.
        let pty = nix::pty::openpty(Some(&ws), None).map_err(nix_io)?;
        let slave_path = nix::unistd::ttyname(&pty.slave)
            .map_err(nix_io)?
            .to_string_lossy()
            .into_owned();

        // Open the PAM session with the slave path as PAM_TTY. Strict:
        // failure here propagates as `puressh::Error` and the channel
        // request is rejected upstream.
        let pam_envs = pam.ensure(user, &slave_path)?;

        // SAFETY: fork() in single-threaded code is safe; the child
        // branch performs only async-signal-safe ops (with the known
        // caveat about setenv, documented inline below) before execvp.
        let pid = unsafe { fork() }.map_err(nix_io)?;
        match pid {
            ForkResult::Child => {
                // Child does not need the master end — close it so the
                // pty drains correctly when the user's shell exits.
                drop(pty.master);
                // Become a fresh session leader, then claim the slave
                // as the controlling tty. Without TIOCSCTTY, programs
                // like `vim` and `top` won't get SIGWINCH on resize.
                let _ = nix::unistd::setsid();
                // SAFETY: TIOCSCTTY on a slave pty in a fresh session
                // is well-defined; dup2 rewires stdio onto it.
                unsafe {
                    libc::ioctl(pty.slave.as_raw_fd(), libc::TIOCSCTTY as _, 0);
                    libc::dup2(pty.slave.as_raw_fd(), 0);
                    libc::dup2(pty.slave.as_raw_fd(), 1);
                    libc::dup2(pty.slave.as_raw_fd(), 2);
                }
                drop(pty.slave);
                // Restore default SIGCHLD so the user's shell can reap
                // its own children via waitpid(WNOHANG).
                let _ = unsafe { signal(Signal::SIGCHLD, SigHandler::SigDfl) };
                // Apply PAM environment. `setenv` isn't strictly
                // async-signal-safe per POSIX, but our post-fork
                // process is single-threaded and the env list is
                // bounded — this is the same approach OpenSSH uses in
                // `do_setup_env` → `child_set_env`.
                for (k, v) in &pam_envs {
                    // SAFETY: k, v are NUL-terminated `CString`s we
                    // own; the third argument 1 says "overwrite".
                    unsafe {
                        libc::setenv(k.as_ptr(), v.as_ptr(), 1);
                    }
                }
                // execvp the user's shell. /bin/sh -l keeps the
                // dependency surface tiny; a fuller impl would
                // consult getpwnam(user).pw_shell.
                let sh = c"/bin/sh";
                let arg0 = c"sh";
                let argl = c"-l";
                let _ = execvp(sh, &[arg0, argl]);
                // execvp failed (binary missing, ENOEXEC, …). Use
                // _exit so we don't run stdlib atexit handlers
                // inherited from the parent.
                unsafe { libc::_exit(127) };
            }
            ForkResult::Parent { child } => {
                // Parent doesn't need the slave — close it so EOF
                // semantics work when the child exits.
                drop(pty.slave);
                let master = pty.master;
                let raw = master.as_raw_fd();
                let cur = fcntl(master.as_fd(), FcntlArg::F_GETFL).map_err(nix_io)?;
                let new = OFlag::from_bits_truncate(cur) | OFlag::O_NONBLOCK;
                fcntl(master.as_fd(), FcntlArg::F_SETFL(new)).map_err(nix_io)?;
                if debug {
                    eprintln!(
                        "sshd: spawned pty shell pid={} master_fd={} pts={}",
                        child.as_raw(),
                        raw,
                        slave_path,
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

    fn spawn_pipe_shell(
        pam: &Arc<pam_gate::PamGate>,
        user: &str,
        _debug: bool,
    ) -> puressh::Result<Box<dyn ShellSession>> {
        // `ssh -T` (no PTY) lands here. Open the PAM session anyway —
        // strict mode wants to surface auth/account failures before we
        // return the user-facing "unsupported" message — then bail.
        let _ = pam.ensure(user, "ssh")?;
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

        // One PamGate per accept-loop iteration's child. The parent
        // holds a clone too, but fork's COW gives each connection its
        // own copy — no cross-connection state bleed.
        let pam_gate = pam_gate::PamGate::new(cli.debug);

        let cfg = Arc::new(
            Config::new(
                host_keys,
                factory,
                vec!["publickey"],
                Arc::new(ShellCommandHandler {
                    pam: pam_gate.clone(),
                    debug: cli.debug,
                }),
            )
            .with_shell(Arc::new(NixShellHandler {
                pam: pam_gate.clone(),
                debug: cli.debug,
            })),
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
                    // Restore default SIGCHLD so the grandchild shell
                    // can be reaped via waitpid(WNOHANG).
                    // SAFETY: same justification as the parent — we run
                    // in a single-threaded process here.
                    let _ = unsafe { signal(Signal::SIGCHLD, SigHandler::SigDfl) };

                    // Stash the peer address on *this child's* PamGate
                    // copy — set_peer mutates state behind a Mutex but
                    // post-fork COW means only this child sees it.
                    pam_gate.set_peer(peer.to_string());

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
