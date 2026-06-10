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
    use std::collections::{HashMap, HashSet};
    use std::ffi::OsStr;
    use std::net::IpAddr;
    use std::os::fd::{AsFd, AsRawFd, OwnedFd};
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::process::CommandExt;
    use std::process::{Command, ExitCode};
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex, OnceLock};

    use nix::errno::Errno;
    use nix::fcntl::{fcntl, FcntlArg, OFlag};
    use nix::libc;
    use nix::sys::signal::{kill, signal, SigHandler, Signal};
    use nix::sys::wait::{waitpid, WaitPidFlag, WaitStatus};
    use nix::unistd::{execvp, fork, ForkResult, Pid};

    use puressh::auth::{AuthAttempt, AuthDecision, Authenticator};
    use puressh::hostkey::HostKey;
    use puressh::key::{PrivateKey, PublicKey};
    use puressh::scp::{
        Receiver as ScpReceiver, ScpRecvOptions, ScpSendOptions, Sender as ScpSender,
    };
    use puressh::server::{
        handle_session, AuthenticatorFactory, ChannelStream, CommandHandler, Config, ExecResult,
        ExecStreamHandler, PtySpec, SessionEnv, ShellExitStatus, ShellHandler, ShellSession,
        SubsystemHandler, HARD_BLOCKED_ENV_NAMES,
    };
    use puressh::sftp::{SftpServerOptions, SftpServerSession};

    const VERSION: &str = env!("CARGO_PKG_VERSION");

    const USAGE: &str = "usage: sshd [-d] [-f configfile] [-p port] [-b address]... \
                         [-h host_key_file]... [-A authorized_keys_file] \
                         [-u allowed_user]... [--no-sftp] [--sftp-read-only] \
                         [--sftp-root PATH] [--no-scp] [--no-agent-forward] \
                         [--no-x11-forward] [--no-strict-modes] [--debug-commands] \
                         [--accept-env GLOB]... [--login-grace-time SECONDS] \
                         [--max-startups N] [--per-source-max N] \
                         [--permit-root-login yes|no|prohibit-password]";

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
    // The real PAM gate compiles only when both the `pam` feature is enabled
    // AND we're targeting Linux — `pam-client2` itself is dep-gated to Linux
    // because it references Linux-PAM constants that OpenPAM (macOS / *BSD)
    // doesn't expose. Every other configuration (Linux without `pam`, macOS
    // with `--all-features`, etc.) falls through to the stub below.
    #[cfg(all(feature = "pam", target_os = "linux"))]
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

    #[cfg(not(all(feature = "pam", target_os = "linux")))]
    mod pam_gate {
        use std::ffi::CString;
        use std::sync::Arc;

        /// Stub gate used when the `pam` feature is off, or when the
        /// target isn't Linux (the `pam-client2` dep is Linux-only — see
        /// the cfg gate on the real `pam_gate` module above). All
        /// operations are no-ops so the rest of the binary can ignore
        /// the feature state.
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
        /// `-f path`: read this `sshd_config` before processing CLI flags
        /// (CLI still wins on scalars).
        config_file: Option<String>,
        port: Option<u16>,
        /// `-b ADDR`: bind to ADDR (host or `host:port`). Repeats are
        /// recognised; v1 uses only the first one and warns about extras
        /// until multi-address bind lands. Config `ListenAddress` lines
        /// fold into the same list.
        listen_addresses: Vec<String>,
        host_key_files: Vec<String>,
        authorized_keys_file: Option<String>,
        allowed_users: Vec<String>,
        debug: bool,
        /// SFTP subsystem on by default; `--no-sftp` disables it.
        sftp: Option<bool>,
        /// Refuse any operation that would mutate the filesystem.
        sftp_read_only: Option<bool>,
        /// If set, refuse paths that escape this root.
        sftp_root: Option<String>,
        /// SCP support (in-process `scp -t/-f`) on by default; `--no-scp`
        /// disables it. With SCP off, an `exec scp …` request falls through
        /// to the buffered command handler — which refuses unknown commands.
        scp: Option<bool>,
        /// Agent forwarding on by default; `--no-agent-forward` disables
        /// it. When off, any client `auth-agent-req@openssh.com` is
        /// refused.
        agent_forward: Option<bool>,
        /// X11 forwarding on by default; `--no-x11-forward` disables it.
        /// When off, any client `x11-req` is refused.
        x11_forward: Option<bool>,
        /// `--no-strict-modes`: skip the 0o077 / 0o022 file-permission
        /// checks on host keys / authorized_keys.
        strict_modes: Option<bool>,
        /// `--debug-commands`: log full exec command lines (otherwise
        /// only the first whitespace token is logged in debug mode).
        debug_commands: bool,
        /// `--accept-env GLOB`: OpenSSH-style env name allowlist; can be
        /// repeated, supports `*`/`?` wildcards. Empty = drop everything.
        accept_env: Vec<String>,
        /// `--login-grace-time SECONDS`: pre-auth inactivity timeout
        /// applied to the connection's read side. 0 disables.
        login_grace_time: Option<u32>,
        /// `--max-startups N`: cap on concurrent unauthenticated /
        /// authenticated children (0 = unlimited).
        max_startups: Option<u32>,
        /// `--per-source-max N`: cap on simultaneous connections from any
        /// single peer IP (0 = unlimited).
        per_source_max: u32,
        /// `--permit-root-login yes|no|prohibit-password`: whether the root
        /// account (uid 0) may authenticate. Default (config/built-in) is
        /// `prohibit-password`, which permits root by key since puressh has
        /// no password auth; `no` blocks root entirely.
        permit_root_login: Option<puressh::config::PermitRootLogin>,
    }

    /// OpenSSH precedence helper: returns the first `Some` of `cli`, `cfg`,
    /// otherwise `default`. The standard scalar-option resolution pattern is
    /// `pick(cli_flag, cfg_value, builtin_default)`.
    fn pick<T>(cli: Option<T>, cfg: Option<T>, default: T) -> T {
        cli.or(cfg).unwrap_or(default)
    }

    /// Read and parse a single `sshd_config`-format file. There is no default
    /// search path on the server side: distros disagree on where the file
    /// lives, and the user explicitly opts in via `-f`.
    fn load_server_config(
        path: &std::path::Path,
    ) -> Result<puressh::config::SshServerConfig, String> {
        let src =
            std::fs::read_to_string(path).map_err(|e| format!("read {}: {e}", path.display()))?;
        puressh::config::SshServerConfig::parse(&src)
            .map_err(|e| format!("{}: {e}", path.display()))
    }

    fn parse_args(args: &[String]) -> Result<Cli, String> {
        let mut config_file: Option<String> = None;
        let mut port: Option<u16> = None;
        let mut listen_addresses: Vec<String> = Vec::new();
        let mut host_key_files: Vec<String> = Vec::new();
        let mut authorized_keys_file: Option<String> = None;
        let mut allowed_users: Vec<String> = Vec::new();
        let mut debug = false;
        let mut sftp: Option<bool> = None;
        let mut sftp_read_only: Option<bool> = None;
        let mut sftp_root: Option<String> = None;
        let mut scp: Option<bool> = None;
        let mut agent_forward: Option<bool> = None;
        let mut x11_forward: Option<bool> = None;
        let mut strict_modes: Option<bool> = None;
        let mut debug_commands = false;
        let mut accept_env: Vec<String> = Vec::new();
        let mut login_grace_time: Option<u32> = None;
        let mut max_startups: Option<u32> = None;
        let mut per_source_max: u32 = 10;
        let mut permit_root_login: Option<puressh::config::PermitRootLogin> = None;

        let mut i = 0;
        while i < args.len() {
            let a = &args[i];
            match a.as_str() {
                "-f" => {
                    i += 1;
                    let v = args.get(i).ok_or("-f requires a value")?.clone();
                    config_file = Some(v);
                }
                "-p" => {
                    i += 1;
                    let v = args.get(i).ok_or("-p requires a value")?;
                    port = Some(v.parse::<u16>().map_err(|_| "invalid port".to_string())?);
                }
                "-b" => {
                    i += 1;
                    let v = args.get(i).ok_or("-b requires a value")?.clone();
                    listen_addresses.push(v);
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
                "--no-sftp" => sftp = Some(false),
                "--sftp-read-only" => sftp_read_only = Some(true),
                "--sftp-root" => {
                    i += 1;
                    let v = args.get(i).ok_or("--sftp-root requires a value")?.clone();
                    sftp_root = Some(v);
                }
                "--no-scp" => scp = Some(false),
                "--no-agent-forward" => agent_forward = Some(false),
                "--no-x11-forward" => x11_forward = Some(false),
                "--no-strict-modes" => strict_modes = Some(false),
                "--debug-commands" => debug_commands = true,
                "--accept-env" => {
                    i += 1;
                    let v = args.get(i).ok_or("--accept-env requires a value")?.clone();
                    accept_env.push(v);
                }
                "--login-grace-time" => {
                    i += 1;
                    let v = args.get(i).ok_or("--login-grace-time requires a value")?;
                    login_grace_time = Some(
                        v.parse::<u32>()
                            .map_err(|_| "invalid --login-grace-time".to_string())?,
                    );
                }
                "--max-startups" => {
                    i += 1;
                    let v = args.get(i).ok_or("--max-startups requires a value")?;
                    max_startups = Some(
                        v.parse::<u32>()
                            .map_err(|_| "invalid --max-startups".to_string())?,
                    );
                }
                "--per-source-max" => {
                    i += 1;
                    let v = args.get(i).ok_or("--per-source-max requires a value")?;
                    per_source_max = v
                        .parse::<u32>()
                        .map_err(|_| "invalid --per-source-max".to_string())?;
                }
                "--permit-root-login" => {
                    use puressh::config::PermitRootLogin;
                    i += 1;
                    let v = args.get(i).ok_or("--permit-root-login requires a value")?;
                    permit_root_login = Some(match v.to_ascii_lowercase().as_str() {
                        "yes" | "true" | "on" => PermitRootLogin::Yes,
                        "no" | "false" | "off" => PermitRootLogin::No,
                        "prohibit-password" | "without-password" => {
                            PermitRootLogin::ProhibitPassword
                        }
                        other => {
                            return Err(format!(
                                "invalid --permit-root-login {other:?} \
                                 (expected yes, no, or prohibit-password)"
                            ));
                        }
                    });
                }
                s if s.starts_with('-') => {
                    return Err(format!("unknown flag: {s}"));
                }
                _ => return Err(format!("unexpected argument: {a}")),
            }
            i += 1;
        }

        // `-h` validation moves to run() after config merge so a config file
        // that supplies `HostKey` is sufficient.
        Ok(Cli {
            config_file,
            port,
            listen_addresses,
            host_key_files,
            authorized_keys_file,
            allowed_users,
            debug,
            sftp,
            sftp_read_only,
            sftp_root,
            scp,
            agent_forward,
            x11_forward,
            strict_modes,
            debug_commands,
            accept_env,
            login_grace_time,
            max_startups,
            per_source_max,
            permit_root_login,
        })
    }

    fn load_host_keys(
        paths: &[String],
        strict_modes: bool,
    ) -> Result<Vec<Box<dyn HostKey + Send + Sync>>, String> {
        let mut out: Vec<Box<dyn HostKey + Send + Sync>> = Vec::new();
        for path in paths {
            if strict_modes {
                check_mode_strict(path, 0o077, "host key")?;
            }
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

    /// Refuse to read `path` when its Unix mode shares any forbidden bit
    /// with `forbidden_mask` (e.g. `0o077` for host keys — "not readable
    /// by group or world"). Matches OpenSSH's `StrictModes`. The
    /// `--no-strict-modes` CLI flag short-circuits this check.
    ///
    /// `kind` is just a human label for the error message ("host key",
    /// "authorized_keys file").
    fn check_mode_strict(path: &str, forbidden_mask: u32, kind: &str) -> Result<(), String> {
        use std::os::unix::fs::MetadataExt;
        let md = std::fs::metadata(path).map_err(|e| format!("stat {path}: {e}"))?;
        if !md.is_file() {
            return Err(format!("{kind} {path}: not a regular file"));
        }
        let mode = md.mode() & 0o777;
        if (mode as u32) & forbidden_mask != 0 {
            return Err(format!(
                "{kind} {path}: insecure mode 0o{mode:o} (must not have any of 0o{forbidden_mask:o}); \
                 fix with `chmod 0{:o} {path}` or override with --no-strict-modes",
                mode & !forbidden_mask & 0o777
            ));
        }
        Ok(())
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

    fn load_authorized_keys(path: &str, strict_modes: bool) -> Result<Vec<PublicKey>, String> {
        if strict_modes {
            check_mode_strict(path, 0o022, "authorized_keys file")?;
        }
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
        /// Requested usernames that resolve to the root account (uid 0),
        /// precomputed from `AllowUsers` at startup. Checked against the
        /// `PermitRootLogin` policy to gate root authentication.
        root_users: HashSet<String>,
        permit_root_login: puressh::config::PermitRootLogin,
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
                    // Always run *both* checks unconditionally so an
                    // attacker can't distinguish "unknown user" from
                    // "known user / wrong key" via wall-clock timing.
                    // The HashSet lookup is O(1); the linear scan over
                    // authorized_blobs is the dominant cost — running
                    // it for every attempt keeps the two paths uniform.
                    let user_ok = self.allowed_users.contains(&user);
                    let blob_ok = self.authorized_blobs.contains(&public_blob);
                    // PermitRootLogin gate: if the requested user is the root
                    // account (uid 0) and policy forbids it, deny regardless
                    // of key match. Computed as an O(1) set lookup so the
                    // accept/reject paths keep uniform timing.
                    let root_denied =
                        self.root_users.contains(&user) && !self.permit_root_login.permits_publickey();
                    let allow = user_ok && blob_ok && !root_denied;

                    // probe_only attempts (no signature) only need
                    // user+blob to be acceptable so the client knows it
                    // can move on to the signed step.
                    if probe_only {
                        return if allow {
                            AuthDecision::Accept
                        } else {
                            if self.debug {
                                if root_denied {
                                    eprintln!(
                                        "sshd: auth publickey probe: root login denied by PermitRootLogin for {user}"
                                    );
                                } else if !user_ok {
                                    eprintln!(
                                        "sshd: auth publickey probe: user {user} not in allowed set"
                                    );
                                } else {
                                    eprintln!(
                                        "sshd: auth publickey probe: key not in authorized_keys for {user}"
                                    );
                                }
                            }
                            AuthDecision::Reject
                        };
                    }

                    if !(allow && verified) {
                        if self.debug {
                            if root_denied {
                                eprintln!(
                                    "sshd: auth publickey: root login denied by PermitRootLogin for {user}"
                                );
                            } else if !user_ok {
                                eprintln!("sshd: auth publickey: user {user} not in allowed set");
                            } else if !blob_ok {
                                eprintln!(
                                    "sshd: auth publickey: key not in authorized_keys for {user}"
                                );
                            } else {
                                eprintln!(
                                    "sshd: auth publickey: signature missing or unverified for {user}"
                                );
                            }
                        }
                        return AuthDecision::Reject;
                    }
                    if self.debug {
                        eprintln!("sshd: auth publickey: accepted user {user}");
                    }
                    AuthDecision::Accept
                }
                AuthAttempt::KeyboardInteractive { user } => {
                    // We never advertise "keyboard-interactive" in
                    // Config::allowed_auth_methods, so the auth core
                    // should never dispatch a KI attempt here.  Catch
                    // mis-wired configs in debug builds before they
                    // become a silent prompt-loop in production.
                    debug_assert!(
                        false,
                        "LocalAuthenticator received KeyboardInteractive but \
                         keyboard-interactive is not enabled in allowed_auth_methods \
                         (user={user})",
                    );
                    if self.debug {
                        eprintln!("sshd: auth keyboard-interactive rejected for user {user}");
                    }
                    AuthDecision::Reject
                }
            }
        }
    }

    #[derive(Clone)]
    struct LocalAuthFactory {
        allowed_users: Arc<HashSet<String>>,
        authorized_blobs: Arc<Vec<Vec<u8>>>,
        root_users: Arc<HashSet<String>>,
        permit_root_login: puressh::config::PermitRootLogin,
        debug: bool,
    }

    impl AuthenticatorFactory for LocalAuthFactory {
        fn build(&self) -> Box<dyn Authenticator> {
            Box::new(LocalAuthenticator {
                allowed_users: (*self.allowed_users).clone(),
                authorized_blobs: (*self.authorized_blobs).clone(),
                root_users: (*self.root_users).clone(),
                permit_root_login: self.permit_root_login,
                debug: self.debug,
            })
        }
    }

    struct ShellCommandHandler {
        pam: Arc<pam_gate::PamGate>,
        debug: bool,
        /// When `false` (the default), debug-mode exec logs print only the
        /// first whitespace-separated token of the command — secrets passed
        /// on the command line (e.g. `mysql -p<pass>`, `curl
        /// https://u:p@host`) never reach stderr/journald.  `--debug-commands`
        /// opts in to full command logging for development.
        debug_commands: bool,
    }

    impl CommandHandler for ShellCommandHandler {
        fn handle(&self, user: &str, env: &SessionEnv, command: &str) -> ExecResult {
            if self.debug {
                if self.debug_commands {
                    eprintln!("sshd: exec by {user}: {command}");
                } else {
                    // Log only the first token (the program name) plus an
                    // argument count, so operators can see *what* ran
                    // without leaking secrets passed on the command line.
                    // Use char_indices so we never split inside a UTF-8
                    // codepoint and don't allocate a Vec to count args.
                    let name = command.split_whitespace().next().unwrap_or("");
                    let extra = command.split_whitespace().skip(1).count();
                    eprintln!("sshd: exec by {user}: {name} (+{extra} args, redacted)");
                }
            }

            // Resolve the target user in /etc/passwd first — every
            // subsequent step (PAM open, env layering, setuid) depends
            // on these values. A missing user is a hard fail.
            let info = match lookup_user(user) {
                Ok(i) => i,
                Err(e) => {
                    return ExecResult {
                        stdout: Vec::new(),
                        stderr: format!("sshd: user lookup failed: {e}\n").into_bytes(),
                        exit_status: 255,
                    };
                }
            };

            // Open the PAM session before spawning the child. `exec`
            // requests don't have a real tty, so we use "ssh" — matches
            // OpenSSH's behaviour for non-PTY channels. `ExecResult`
            // has no error channel, so PAM failure surfaces as exit
            // status 255 with the error message on stderr.
            let mut envs = match self.pam.ensure(user, "ssh") {
                Ok(e) => e,
                Err(e) => {
                    return ExecResult {
                        stdout: Vec::new(),
                        stderr: format!("sshd: PAM session open failed: {e}\n").into_bytes(),
                        exit_status: 255,
                    };
                }
            };
            apply_login_envs(&mut envs, &info);

            // Run the command via the user's login shell so that
            // /etc/passwd-configured shells (zsh, fish, …) are honoured.
            let mut cmd = Command::new(&info.shell_str);
            cmd.args(["-c", command]).env_clear();
            for (k, v) in &envs {
                cmd.env(
                    OsStr::from_bytes(k.to_bytes()),
                    OsStr::from_bytes(v.to_bytes()),
                );
            }
            // Layer the per-channel SSH `env` requests *over* PAM env so the
            // client's LANG / LC_* / TERM / user-supplied variables win.
            // RFC 4254 §6.4 makes this scope per-session-channel; the
            // dispatcher already discards the env on channel close.
            // safe_session_env enforces a defense-in-depth blocklist
            // (LD_PRELOAD/IFS/PATH/etc.) on top of the server's filter.
            for (k, v) in safe_session_env(env) {
                cmd.env(k, v);
            }

            // Drop to the user inside the spawned child via pre_exec.
            // We can't use Command::uid()/.gid()/.current_dir() because
            // std calls them in the wrong order for `initgroups` — std
            // does setgid → setgroups([]) → setuid → chdir, blowing
            // away the supplementary groups we want and forcing chdir
            // after setuid. Do the whole dance ourselves.
            if !already_matches(&info) {
                let uid = info.uid;
                let gid = info.gid;
                let name_c = info.name_c.clone();
                let home_c = info.home_c.clone();
                // SAFETY: pre_exec runs in the post-fork child between
                // fork and exec. We only call POSIX-defined functions
                // (setgid, initgroups, setuid, chdir) — all used in
                // OpenSSH's drop-to-user path and considered safe in
                // the single-threaded post-fork window.
                unsafe {
                    cmd.pre_exec(move || {
                        // setgroups([]) → setgid → initgroups → setuid
                        // (see drop_to_user for the full rationale).
                        setgroups_clear().map_err(to_io)?;
                        nix::unistd::setgid(gid).map_err(to_io)?;
                        initgroups_libc(&name_c, gid).map_err(to_io)?;
                        nix::unistd::setuid(uid).map_err(to_io)?;
                        // Post-setuid sanity: the kernel can silently
                        // refuse setuid if we lack CAP_SETUID, leaving
                        // the child running as root.  Refuse to exec.
                        verify_post_setuid(uid, gid).map_err(to_io)?;
                        // chdir best-effort: a missing/unreadable home
                        // shouldn't refuse the exec — fall back to /.
                        if libc::chdir(home_c.as_ptr()) != 0 {
                            let _ = libc::chdir(c"/".as_ptr());
                        }
                        Ok(())
                    });
                }
            } else {
                // Same uid → still chdir for clean cwd semantics.
                cmd.current_dir(&info.home_str);
            }

            // Spawn + manually drain so we can cap total buffered
            // output. `cmd.output()` would grow each stream
            // unboundedly — a long-running `find /` or `cat /dev/zero`
            // would let the daemon OOM. 16 MiB per stream is more than
            // any sane `ssh host cmd` produces; if a workload needs to
            // ship more, it should use SFTP / a streaming
            // ExecStreamHandler / a pty shell instead.
            const EXEC_BUFFER_CAP: usize = 16 * 1024 * 1024;
            cmd.stdin(std::process::Stdio::null());
            cmd.stdout(std::process::Stdio::piped());
            cmd.stderr(std::process::Stdio::piped());
            let mut child = match cmd.spawn() {
                Ok(c) => c,
                Err(e) => {
                    return ExecResult {
                        stdout: Vec::new(),
                        stderr: format!("sshd: failed to spawn {}: {e}\n", info.shell_str)
                            .into_bytes(),
                        exit_status: 255,
                    };
                }
            };

            // Drain stdout and stderr on dedicated threads so a slow
            // reader on one doesn't deadlock the producer (kernel-pipe
            // backpressure → child blocks → other stream never read).
            let mut out_pipe = child.stdout.take().expect("stdout piped");
            let mut err_pipe = child.stderr.take().expect("stderr piped");
            let out_thr = std::thread::spawn(move || drain_capped(&mut out_pipe, EXEC_BUFFER_CAP));
            let err_thr = std::thread::spawn(move || drain_capped(&mut err_pipe, EXEC_BUFFER_CAP));

            let status = match child.wait() {
                Ok(s) => s,
                Err(e) => {
                    return ExecResult {
                        stdout: Vec::new(),
                        stderr: format!("sshd: wait failed: {e}\n").into_bytes(),
                        exit_status: 255,
                    };
                }
            };
            let (mut stdout_buf, stdout_overflow) = out_thr.join().unwrap_or_default();
            let (mut stderr_buf, stderr_overflow) = err_thr.join().unwrap_or_default();
            if stdout_overflow {
                stderr_buf.extend_from_slice(b"\nsshd: stdout exceeded 16 MiB cap (truncated)\n");
            }
            if stderr_overflow {
                stderr_buf.extend_from_slice(b"\nsshd: stderr exceeded 16 MiB cap (truncated)\n");
            }
            let code = status.code().unwrap_or(255);
            let code_u32 = if code < 0 { 255u32 } else { code as u32 };
            // If we capped, force a non-zero exit so the client knows
            // its command's output was lossy (matches the "abort the
            // channel beyond that" intent from finding #6).
            let final_code = if (stdout_overflow || stderr_overflow) && code_u32 == 0 {
                stdout_buf.clear();
                255u32
            } else {
                code_u32
            };
            ExecResult {
                stdout: stdout_buf,
                stderr: stderr_buf,
                exit_status: final_code,
            }
        }
    }

    /// Read from `r` until EOF, capping the returned buffer at `cap`
    /// bytes. Returns `(buf, overflowed)`: `overflowed` is true when at
    /// least one extra byte was on the wire — the caller treats this as
    /// "channel aborted".
    fn drain_capped<R: std::io::Read>(r: &mut R, cap: usize) -> (Vec<u8>, bool) {
        let mut buf = Vec::with_capacity(8 * 1024);
        let mut chunk = [0u8; 8 * 1024];
        let mut overflow = false;
        loop {
            match r.read(&mut chunk) {
                Ok(0) => break,
                Ok(n) => {
                    if buf.len() + n > cap {
                        let room = cap.saturating_sub(buf.len());
                        if room > 0 {
                            buf.extend_from_slice(&chunk[..room]);
                        }
                        overflow = true;
                        // Keep draining so the child's pipe doesn't
                        // back up — but discard everything past the
                        // cap. Without this the producer eventually
                        // blocks on PIPE-full and we hang in
                        // `child.wait()`.
                        continue;
                    }
                    buf.extend_from_slice(&chunk[..n]);
                }
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(_) => break,
            }
        }
        (buf, overflow)
    }

    /// `pre_exec` closures need a closed `io::Error`-returning path; nix
    /// errnos must be lifted here. Lives at module scope so the closure
    /// stays `'static`-friendly.
    fn to_io(e: Errno) -> std::io::Error {
        std::io::Error::from_raw_os_error(e as i32)
    }

    /// Apple targets dropped `nix::unistd::initgroups` (see the cfg gate at
    /// `nix-0.30/src/unistd.rs`), so we call the libc function directly. The
    /// signature is POSIX-stable across Linux and macOS; the gid type
    /// (`libc::gid_t`) matches `nix::unistd::Gid` byte-for-byte.
    ///
    /// SAFETY: `user` must be a valid NUL-terminated C string. The pre-fork
    /// callers all pass `info.name_c.as_ptr()` from a long-lived `CString`.
    fn initgroups_libc(user: &std::ffi::CStr, gid: nix::unistd::Gid) -> nix::Result<()> {
        // SAFETY: `user.as_ptr()` is a valid NUL-terminated string for the
        // duration of the call (CStr's invariant).
        let rc = unsafe { libc::initgroups(user.as_ptr(), gid.as_raw() as _) };
        if rc == 0 {
            Ok(())
        } else {
            Err(Errno::last())
        }
    }

    /// Drop every supplementary group from the calling process.
    ///
    /// `initgroups(user, gid)` reads /etc/group for the *target* user, but
    /// if we never explicitly clear the root daemon's supplementary groups
    /// first, certain libc implementations have historically retained
    /// extras across the call (and a misconfigured /etc/group can simply
    /// fail to assign new ones, leaving the daemon's groups intact in the
    /// child). Call `setgroups([])` immediately before `initgroups` so the
    /// post-setuid process is *guaranteed* to start from an empty
    /// supplementary group list — matching OpenSSH's behaviour.
    ///
    /// SAFETY: We're the only thread in the post-fork child (or we hold
    /// root in the pre-fork path); passing a 0-length list is well-defined
    /// across Linux and the BSDs.
    fn setgroups_clear() -> nix::Result<()> {
        // SAFETY: `count=0` with a null/dangling pointer is the documented
        // way to clear the supplementary group list on Linux and macOS.
        let rc = unsafe { libc::setgroups(0, core::ptr::null()) };
        if rc == 0 {
            Ok(())
        } else {
            Err(Errno::last())
        }
    }

    /// Confirm the calling process really dropped to `(uid, gid)`. Any
    /// mismatch on real/effective/saved uid or real/effective gid means
    /// the kernel call silently failed (or the binary lacks the necessary
    /// capability) — refuse to continue rather than running the user's
    /// shell with mixed privileges.
    fn verify_post_setuid(uid: nix::unistd::Uid, gid: nix::unistd::Gid) -> nix::Result<()> {
        // SAFETY: getresuid/getresgid only write to caller-owned locals.
        // On non-Linux platforms we fall back to geteuid/getuid/getegid/
        // getgid which are universally available.
        #[cfg(target_os = "linux")]
        {
            let mut ruid: libc::uid_t = 0;
            let mut euid: libc::uid_t = 0;
            let mut suid: libc::uid_t = 0;
            let mut rgid: libc::gid_t = 0;
            let mut egid: libc::gid_t = 0;
            let mut sgid: libc::gid_t = 0;
            // SAFETY: pointers refer to live stack locals.
            if unsafe { libc::getresuid(&mut ruid, &mut euid, &mut suid) } != 0 {
                return Err(Errno::last());
            }
            if unsafe { libc::getresgid(&mut rgid, &mut egid, &mut sgid) } != 0 {
                return Err(Errno::last());
            }
            let want_u = uid.as_raw();
            let want_g = gid.as_raw();
            if ruid != want_u || euid != want_u || suid != want_u {
                return Err(Errno::EPERM);
            }
            if rgid != want_g || egid != want_g || sgid != want_g {
                return Err(Errno::EPERM);
            }
            Ok(())
        }
        #[cfg(not(target_os = "linux"))]
        {
            // SAFETY: get{e,}{u,g}id never fail per POSIX.
            let ruid = unsafe { libc::getuid() };
            let euid = unsafe { libc::geteuid() };
            let rgid = unsafe { libc::getgid() };
            let egid = unsafe { libc::getegid() };
            if ruid != uid.as_raw() || euid != uid.as_raw() {
                return Err(Errno::EPERM);
            }
            if rgid != gid.as_raw() || egid != gid.as_raw() {
                return Err(Errno::EPERM);
            }
            Ok(())
        }
    }

    fn current_user() -> Result<String, String> {
        std::env::var("USER")
            .or_else(|_| std::env::var("LOGNAME"))
            .map_err(|_| "could not determine current user (set $USER)".into())
    }

    /// Defense-in-depth: scrub the per-channel SSH `env` list of any name
    /// in `HARD_BLOCKED_ENV_NAMES` before we layer it onto the child
    /// process's environment. The server's accept-env filter already runs
    /// upstream (see `puressh::server::env_name_accepted`), so under
    /// normal operation no blocked name should ever reach here. This is a
    /// belt-and-suspenders check: a future bug, a misconfigured custom
    /// `ChannelRequest::Env` interceptor, or a downstream caller that
    /// bypasses the server layer must not be able to slip
    /// LD_PRELOAD/IFS/PATH/etc. into the user's shell.
    ///
    /// Names with embedded NUL are dropped too — they can't safely make
    /// it into a `setenv`/`Command::env` call anyway.
    fn safe_session_env(env: &SessionEnv) -> Vec<(&str, &str)> {
        env.iter()
            .filter(|(k, v)| {
                !k.contains('\0') && !v.contains('\0') && !HARD_BLOCKED_ENV_NAMES.contains(k)
            })
            .collect()
    }

    /// Same filter as [`safe_session_env`], but on an owned `(String,
    /// String)` snapshot already in hand. Kept as a separate helper so
    /// the borrow-vs-owned call sites don't need to allocate twice.
    fn safe_owned_env(env: &[(String, String)]) -> Vec<(String, String)> {
        env.iter()
            .filter(|(k, v)| {
                !k.contains('\0')
                    && !v.contains('\0')
                    && !HARD_BLOCKED_ENV_NAMES.contains(&k.as_str())
            })
            .cloned()
            .collect()
    }

    // -------------------------------------------------------------------------
    // User lookup + drop-to-user plumbing.
    //
    // Authentication only proves the SSH peer holds a private key; it
    // doesn't switch identity. After PAM session-open succeeds we look
    // up the target user in `/etc/passwd` and drop our euid/egid before
    // executing the shell, so the user's processes really run as them
    // and not as whatever uid the daemon was launched with. Soft-mode:
    // when the daemon's already running as the target uid (e.g. an
    // unprivileged smoke test where `-u $USER`), the drop is a no-op.
    // -------------------------------------------------------------------------

    /// Resolved POSIX identity for a login user. Captured pre-fork so
    /// every field is already owned and async-signal-safe to consume
    /// from the post-fork child.
    #[derive(Clone)]
    struct UserInfo {
        name: String,
        /// `name` as a `CString` — used directly by `initgroups`,
        /// which only takes `&CStr` and isn't safe to allocate against
        /// post-fork.
        name_c: std::ffi::CString,
        uid: nix::unistd::Uid,
        gid: nix::unistd::Gid,
        /// Home directory as a `CString` — fed straight to `chdir`.
        /// Falls back to `/` if the entry's home is unreadable so the
        /// shell still has a working cwd.
        home_c: std::ffi::CString,
        home_str: String,
        /// Login shell as a `CString` for `execvp`. Defaults to
        /// `/bin/sh` if `pw_shell` is empty or non-UTF-8.
        shell_c: std::ffi::CString,
        shell_str: String,
        /// Login-shell argv0 — `"-"` followed by the basename of
        /// `shell` (bash/zsh/sh treat this as "behave as a login shell"
        /// and source profile files).
        argv0_c: std::ffi::CString,
    }

    fn lookup_user(name: &str) -> puressh::Result<UserInfo> {
        let user = nix::unistd::User::from_name(name)
            .map_err(nix_io)?
            .ok_or_else(|| {
                puressh::Error::Io(std::io::Error::other(format!("user '{name}' not found")))
            })?;

        let name_c = std::ffi::CString::new(user.name.clone()).map_err(|_| {
            puressh::Error::Io(std::io::Error::other("user name contains NUL byte"))
        })?;

        let home_str = user.dir.to_string_lossy().into_owned();
        let home_for_c = if home_str.is_empty() { "/" } else { &home_str };
        let home_c = std::ffi::CString::new(home_for_c.as_bytes()).map_err(|_| {
            puressh::Error::Io(std::io::Error::other("home directory contains NUL byte"))
        })?;

        let shell_str = {
            let s = user.shell.to_string_lossy();
            if s.is_empty() {
                "/bin/sh".to_string()
            } else {
                s.into_owned()
            }
        };
        let shell_c = std::ffi::CString::new(shell_str.as_bytes()).map_err(|_| {
            puressh::Error::Io(std::io::Error::other("shell path contains NUL byte"))
        })?;

        // argv0 = "-" + basename(shell). Login-shell convention.
        let basename = std::path::Path::new(&shell_str)
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("sh");
        let argv0 = format!("-{basename}");
        let argv0_c = std::ffi::CString::new(argv0).map_err(|_| {
            puressh::Error::Io(std::io::Error::other("shell argv0 contains NUL byte"))
        })?;

        Ok(UserInfo {
            name: user.name,
            name_c,
            uid: user.uid,
            gid: user.gid,
            home_c,
            home_str,
            shell_c,
            shell_str,
            argv0_c,
        })
    }

    /// Layer login env vars (HOME/USER/LOGNAME/SHELL) on top of the
    /// snapshot returned by PAM. Conventional names — pam_env may have
    /// supplied some of them already; we overwrite with the resolved
    /// `/etc/passwd` truth.
    fn apply_login_envs(envs: &mut Vec<(std::ffi::CString, std::ffi::CString)>, info: &UserInfo) {
        // CString::new can't fail on these (no interior NUL by
        // construction in lookup_user). Use unwrap_or_default as a
        // belt-and-braces fallback.
        let pairs: [(&str, &std::ffi::CString); 4] = [
            ("HOME", &info.home_c),
            ("USER", &info.name_c),
            ("LOGNAME", &info.name_c),
            ("SHELL", &info.shell_c),
        ];
        for (k, v) in pairs {
            let key = std::ffi::CString::new(k).unwrap_or_default();
            // Overwrite any pam_env contribution: /etc/passwd wins.
            if let Some(slot) = envs
                .iter_mut()
                .find(|(kk, _)| kk.as_bytes() == k.as_bytes())
            {
                slot.1 = v.clone();
            } else {
                envs.push((key, v.clone()));
            }
        }
    }

    /// True iff we're already running as `info`'s uid/gid — in which
    /// case the setuid/setgid/initgroups dance is unnecessary (and
    /// would in fact fail for non-root daemons).
    fn already_matches(info: &UserInfo) -> bool {
        nix::unistd::geteuid() == info.uid && nix::unistd::getegid() == info.gid
    }

    // -------------------------------------------------------------------------
    // NixShellHandler — backend for `pty-req` + `shell`. Allocates a PTY
    // with `openpty()`, forks manually so PAM_TTY can be set pre-fork,
    // drops to the target user's uid/gid, then `execvp`s their login
    // shell. Exposes the master fd as a non-blocking `ShellSession`.
    // -------------------------------------------------------------------------

    struct NixShellHandler {
        pam: Arc<pam_gate::PamGate>,
        debug: bool,
    }

    impl ShellHandler for NixShellHandler {
        fn spawn(
            &self,
            user: &str,
            env: &SessionEnv,
            pty: Option<PtySpec>,
        ) -> puressh::Result<Box<dyn ShellSession>> {
            // Snapshot the per-channel env into an owned vector. spawn_pty_shell
            // forks and then setenv()s post-fork; the child can't hold a borrow
            // across that boundary, so we hand it owned (key, value) pairs.
            // safe_session_env enforces a defense-in-depth blocklist
            // (LD_PRELOAD/IFS/PATH/etc.) on top of the server's filter.
            let env_pairs: Vec<(String, String)> = safe_session_env(env)
                .into_iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect();
            match pty {
                Some(spec) => spawn_pty_shell(&self.pam, user, &env_pairs, &spec, self.debug),
                None => spawn_pipe_shell(&self.pam, user, &env_pairs, self.debug),
            }
        }
    }

    // -------------------------------------------------------------------------
    // SftpSubsystemHandler — backend for `subsystem("sftp")`. Runs in-process
    // (no fork, no execvp): a fresh thread is spawned for each SFTP channel,
    // and the protocol loop reads/writes the channel via a `ChannelStream`.
    //
    // Privilege drop happens once per *connection* (see `drop_to_user` /
    // `Config::on_session_open` below), so all SFTP threads on a given
    // connection already run as the authenticated user — no per-channel
    // setuid is needed. The per-session virtual cwd carried by
    // `SftpServerSession` is what prevents concurrent SFTP channels from
    // stomping each other's working directory.
    // -------------------------------------------------------------------------

    struct SftpSubsystemHandler {
        read_only: bool,
        root: Option<std::path::PathBuf>,
        debug: bool,
    }

    impl SubsystemHandler for SftpSubsystemHandler {
        fn handle(
            &self,
            user: &str,
            _env: &SessionEnv,
            name: &str,
            stream: ChannelStream,
        ) -> puressh::Result<()> {
            if name != "sftp" {
                if self.debug {
                    eprintln!("sshd: refusing unknown subsystem '{name}' for {user}");
                }
                return Ok(()); // dropping `stream` sends EOF + Close
            }

            // Start the per-session virtual cwd at the user's home directory
            // so relative paths behave like a freshly-logged-in shell. If
            // the lookup fails (rare on a configured system), fall back to
            // root: `SftpServerSession` will still operate, just less
            // intuitively.
            let cwd = lookup_user(user)
                .ok()
                .map(|i| std::path::PathBuf::from(&i.home_str))
                .unwrap_or_else(|| std::path::PathBuf::from("/"));

            let mut opts = SftpServerOptions::new(cwd);
            if let Some(root) = &self.root {
                opts = opts.with_root(root.clone());
            }
            if self.read_only {
                opts = opts.read_only();
            }

            let mut session = SftpServerSession::new(opts);
            if self.debug {
                eprintln!("sshd: sftp session opened for {user}");
            }
            // Map SFTP-protocol errors into the generic puressh error type;
            // the dispatcher only cares whether the handler returned cleanly.
            session
                .run(stream)
                .map_err(|e| puressh::Error::Io(std::io::Error::other(format!("sftp: {e:?}"))))?;
            if self.debug {
                eprintln!("sshd: sftp session closed for {user}");
            }
            Ok(())
        }
    }

    // -------------------------------------------------------------------------
    // ScpExecHandler — intercept `exec scp -t …` / `exec scp -f …` requests
    // and run the in-process SCP sender/receiver on the channel. Anything
    // that doesn't look like an `scp` invocation falls through to the
    // buffered command handler (which then either runs it or refuses).
    //
    // We deliberately do NOT spawn a shell. The command string is parsed
    // ourselves with a single-quote-aware tokenizer; anything more elaborate
    // (pipes, redirections, command substitution, env assignments) is
    // refused. That gives us CVE-2020-15778-style protection without
    // depending on the user's shell quoting.
    //
    // Privilege drop already happened in `Config::on_session_open`, so the
    // handler thread runs as the authenticated user. The output path is
    // resolved against the user's home directory — that's the cwd both real
    // sshd and our own session loop expose to scp(1).
    // -------------------------------------------------------------------------

    struct ScpExecHandler {
        debug: bool,
    }

    impl ExecStreamHandler for ScpExecHandler {
        fn claims(&self, command: &str) -> bool {
            // Cheap pre-check before tokenising. We're after the literal
            // `scp ` prefix optionally preceded by whitespace.
            let t = command.trim_start();
            t.starts_with("scp ") || t == "scp"
        }

        fn run(
            &self,
            user: &str,
            _env: &SessionEnv,
            command: &str,
            stream: ChannelStream,
        ) -> puressh::Result<()> {
            let argv = match tokenize_argv(command) {
                Ok(a) => a,
                Err(e) => {
                    if self.debug {
                        eprintln!("sshd: scp: refusing command {command:?}: {e}");
                    }
                    return Err(puressh::Error::Io(std::io::Error::other(format!(
                        "scp: {e}"
                    ))));
                }
            };
            let parsed = match parse_scp_args(&argv) {
                Ok(p) => p,
                Err(e) => {
                    if self.debug {
                        eprintln!("sshd: scp: bad args {argv:?}: {e}");
                    }
                    return Err(puressh::Error::Io(std::io::Error::other(format!(
                        "scp: {e}"
                    ))));
                }
            };

            // Resolve the target path against $HOME if relative. After the
            // connection-level priv drop the process cwd is wherever the
            // daemon was started — we don't want scp's bare-name argument
            // landing in /etc/sshd just because that's where systemd
            // started us.
            let home = lookup_user(user)
                .ok()
                .map(|i| std::path::PathBuf::from(&i.home_str))
                .unwrap_or_else(|| std::path::PathBuf::from("/"));
            let abs_path = if parsed.path.is_absolute() {
                parsed.path.clone()
            } else {
                home.join(&parsed.path)
            };

            if self.debug {
                eprintln!(
                    "sshd: scp {:?} {:?} (recursive={}, preserve_times={}) for {user}",
                    parsed.role, abs_path, parsed.recursive, parsed.preserve_times
                );
            }

            match parsed.role {
                ScpRole::To => {
                    // `scp -t` — the peer is the sender, we receive.
                    let opts = ScpRecvOptions {
                        recursive: parsed.recursive,
                        preserve_times: parsed.preserve_times,
                        // If the local destination already exists as a
                        // directory we use it as the parent; otherwise it's
                        // the literal file path.
                        target_is_file: !abs_path.is_dir(),
                    };
                    let mut rx = ScpReceiver::new(stream, &abs_path, opts).map_err(|e| {
                        puressh::Error::Io(std::io::Error::other(format!("scp: {e}")))
                    })?;
                    rx.run().map_err(|e| {
                        puressh::Error::Io(std::io::Error::other(format!("scp: {e}")))
                    })?;
                }
                ScpRole::From => {
                    // `scp -f` — we read from disk and send to the peer.
                    let opts = ScpSendOptions {
                        recursive: parsed.recursive,
                        preserve_times: parsed.preserve_times,
                    };
                    let mut tx = ScpSender::new(stream).map_err(|e| {
                        puressh::Error::Io(std::io::Error::other(format!("scp: {e}")))
                    })?;
                    tx.send_path(&abs_path, &opts).map_err(|e| {
                        puressh::Error::Io(std::io::Error::other(format!("scp: {e}")))
                    })?;
                }
            }
            Ok(())
        }
    }

    /// One `scp` invocation's worth of parsed arguments. We only care about
    /// the role flag (`-t` or `-f`), the recursive/preserve_times modes, and
    /// the single positional path. Anything else is a hard reject.
    #[derive(Debug)]
    struct ParsedScp {
        role: ScpRole,
        recursive: bool,
        preserve_times: bool,
        path: std::path::PathBuf,
    }

    #[derive(Debug)]
    enum ScpRole {
        /// `-t`: the peer is the sender; we write to disk.
        To,
        /// `-f`: the peer is the receiver; we read from disk.
        From,
    }

    /// Tokenize a command string with single-quote support — enough to
    /// handle the way OpenSSH's `scp(1)` quotes its remote arg list. We
    /// refuse anything that smells like shell metacharacters (`$`, `` ` ``,
    /// `&`, `|`, `;`, `<`, `>`, `(`, `)`, `\`, `"`, `*`, `?`, `[`, `]`,
    /// `{`, `}`, `~`, `!`) outside quotes, because the local-side `scp`
    /// crafts its remote command itself and never needs them.
    fn tokenize_argv(command: &str) -> Result<Vec<String>, String> {
        let mut out: Vec<String> = Vec::new();
        let mut cur = String::new();
        let mut in_word = false;
        let mut in_quote = false;
        let bytes = command.as_bytes();
        let mut i = 0;
        while i < bytes.len() {
            let c = bytes[i] as char;
            if in_quote {
                if c == '\'' {
                    in_quote = false;
                } else if c == '\n' || c == '\0' {
                    return Err("control character in quoted arg".into());
                } else {
                    cur.push(c);
                }
            } else if c == '\'' {
                in_quote = true;
                in_word = true;
            } else if c == ' ' || c == '\t' {
                if in_word {
                    out.push(std::mem::take(&mut cur));
                    in_word = false;
                }
            } else if matches!(
                c,
                '$' | '`'
                    | '&'
                    | '|'
                    | ';'
                    | '<'
                    | '>'
                    | '('
                    | ')'
                    | '\\'
                    | '"'
                    | '*'
                    | '?'
                    | '['
                    | ']'
                    | '{'
                    | '}'
                    | '~'
                    | '!'
                    | '\n'
                    | '\r'
                    | '\0'
            ) {
                return Err(format!("unsupported character {c:?} in command"));
            } else {
                cur.push(c);
                in_word = true;
            }
            i += 1;
        }
        if in_quote {
            return Err("unterminated single quote".into());
        }
        if in_word {
            out.push(cur);
        }
        Ok(out)
    }

    /// Parse `scp [-r] [-p] [-d] [-v] [-t|-f] [--] PATH`. We accept the
    /// usual mode flags plus `-d` (target must be a dir — informational only
    /// for us) and `-v` (verbose; ignored). Anything else is rejected.
    fn parse_scp_args(argv: &[String]) -> Result<ParsedScp, String> {
        if argv.is_empty() || argv[0] != "scp" {
            return Err("not an scp invocation".into());
        }
        let mut role: Option<ScpRole> = None;
        let mut recursive = false;
        let mut preserve_times = false;
        let mut positional: Vec<&str> = Vec::new();
        let mut i = 1;
        while i < argv.len() {
            let a = argv[i].as_str();
            match a {
                "-t" => role = Some(ScpRole::To),
                "-f" => role = Some(ScpRole::From),
                "-r" => recursive = true,
                "-p" => preserve_times = true,
                // Innocent flags scp(1) sometimes adds — accept and ignore.
                "-d" | "-v" | "-q" | "-B" | "-C" | "-1" | "-2" | "-3" | "-4" | "-6" => {}
                "--" => {
                    i += 1;
                    while i < argv.len() {
                        positional.push(argv[i].as_str());
                        i += 1;
                    }
                    break;
                }
                s if s.starts_with('-') => return Err(format!("unsupported flag: {s}")),
                _ => positional.push(a),
            }
            i += 1;
        }
        let role = role.ok_or_else(|| "missing -t or -f".to_string())?;
        if positional.len() != 1 {
            return Err(format!(
                "expected exactly one path argument, got {}",
                positional.len()
            ));
        }
        let path = std::path::PathBuf::from(positional[0]);
        Ok(ParsedScp {
            role,
            recursive,
            preserve_times,
            path,
        })
    }

    /// Drop the calling process to `user`'s primary uid/gid (with supplementary
    /// groups via `initgroups`). Idempotent — if we already match `info`'s
    /// ids, the function is a no-op. Called from `Config::on_session_open`
    /// once per connection, after PAM session-open succeeded.
    fn drop_to_user(user: &str, debug: bool) -> puressh::Result<()> {
        let info = lookup_user(user)?;
        if already_matches(&info) {
            if debug {
                eprintln!(
                    "sshd: connection already running as {user} (uid={})",
                    info.uid
                );
            }
            return Ok(());
        }
        // setgroups([]) → setgid → initgroups → setuid. Clearing
        // supplementary groups *before* initgroups guarantees the post-drop
        // process starts from an empty list (a misconfigured /etc/group
        // could leave initgroups a no-op that retains daemon groups).
        // setuid is the point of no return; we verify the result
        // afterwards to catch any silent capability/policy failure.
        setgroups_clear().map_err(nix_io)?;
        nix::unistd::setgid(info.gid).map_err(nix_io)?;
        initgroups_libc(&info.name_c, info.gid).map_err(nix_io)?;
        nix::unistd::setuid(info.uid).map_err(nix_io)?;
        verify_post_setuid(info.uid, info.gid).map_err(nix_io)?;
        if debug {
            eprintln!(
                "sshd: dropped connection to {user} (uid={} gid={})",
                info.uid, info.gid
            );
        }
        Ok(())
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
        session_env: &[(String, String)],
        spec: &PtySpec,
        debug: bool,
    ) -> puressh::Result<Box<dyn ShellSession>> {
        let ws = nix::pty::Winsize {
            ws_row: clamp_u16(spec.rows),
            ws_col: clamp_u16(spec.cols),
            ws_xpixel: clamp_u16(spec.px_w),
            ws_ypixel: clamp_u16(spec.px_h),
        };

        // Resolve the target user. Must happen pre-fork — getpwnam_r
        // allocates and isn't safe in the post-fork window.
        let info = lookup_user(user)?;
        let drop_privs = !already_matches(&info);

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
        let mut pam_envs = pam.ensure(user, &slave_path)?;
        apply_login_envs(&mut pam_envs, &info);

        // Convert the per-channel SSH `env` requests into NUL-terminated
        // bytes pre-fork — CString::new allocates, and we can't allocate
        // safely between fork and execvp. Reject any pair with interior
        // NUL bytes (would smuggle past setenv's terminator otherwise);
        // such pairs cannot reach us through a well-formed SSH peer.
        //
        // Re-run the hard blocklist here as a final defense-in-depth
        // barrier — the caller already filtered via safe_session_env,
        // but the spawn_pty_shell signature accepts any
        // `&[(String,String)]` and a future caller might forget.
        let session_env = safe_owned_env(session_env);
        let mut channel_envs: Vec<(std::ffi::CString, std::ffi::CString)> =
            Vec::with_capacity(session_env.len());
        for (k, v) in &session_env {
            let kc = std::ffi::CString::new(k.as_bytes()).map_err(|_| {
                puressh::Error::Io(std::io::Error::other("channel env name contains NUL byte"))
            })?;
            let vc = std::ffi::CString::new(v.as_bytes()).map_err(|_| {
                puressh::Error::Io(std::io::Error::other("channel env value contains NUL byte"))
            })?;
            channel_envs.push((kc, vc));
        }

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
                //
                // Treat TIOCSCTTY failure as fatal: if we can't claim the
                // pty as the controlling tty, foreground job control is
                // broken (Ctrl-C / Ctrl-Z won't work, no SIGWINCH on
                // resize) and the shell would silently misbehave.  Better
                // to refuse the session than to hand the user a half-wired
                // pty. _exit(126) matches the "could not execute"
                // convention used elsewhere in this file.
                unsafe {
                    if libc::ioctl(pty.slave.as_raw_fd(), libc::TIOCSCTTY as _, 0) != 0 {
                        libc::_exit(126);
                    }
                    libc::dup2(pty.slave.as_raw_fd(), 0);
                    libc::dup2(pty.slave.as_raw_fd(), 1);
                    libc::dup2(pty.slave.as_raw_fd(), 2);
                }
                drop(pty.slave);
                // Restore default SIGCHLD so the user's shell can reap
                // its own children via waitpid(WNOHANG).
                let _ = unsafe { signal(Signal::SIGCHLD, SigHandler::SigDfl) };

                // Drop privileges to the target user before applying
                // env / chdir / exec. Order matters:
                //   setgroups([]) — clear daemon supplementary groups
                //   setgid       — set primary group (still root)
                //   initgroups   — install target's supplementary set
                //   setuid       — point of no return
                // verify_post_setuid catches a silent failure where the
                // kernel returned 0 but the ids didn't actually change
                // (e.g. seccomp filter, missing CAP_SETUID).
                if drop_privs
                    && (setgroups_clear().is_err()
                        || nix::unistd::setgid(info.gid).is_err()
                        || initgroups_libc(&info.name_c, info.gid).is_err()
                        || nix::unistd::setuid(info.uid).is_err()
                        || verify_post_setuid(info.uid, info.gid).is_err())
                {
                    // Any step failing means we can't safely
                    // continue — refuse rather than running the
                    // shell with mixed privileges.
                    unsafe { libc::_exit(126) };
                }

                // chdir(home). Best-effort: if home is unreadable
                // post-drop, fall back to / so the shell still runs.
                // SAFETY: `info.home_c` is a valid NUL-terminated
                // CString we own.
                unsafe {
                    if libc::chdir(info.home_c.as_ptr()) != 0 {
                        let _ = libc::chdir(c"/".as_ptr());
                    }
                }

                // Scrub the daemon's inherited environment before layering
                // the PAM + login + channel vars. Without this the whole
                // sshd environment (the parent's PATH, any operator-set
                // vars, etc.) leaks into the user's interactive login shell.
                // Mirrors the exec path's `cmd.env_clear()`. `clearenv`
                // runs in the single-threaded post-fork child and only
                // resets the environ pointer — no allocation — so it is
                // safe in the fork→exec window.
                // SAFETY: single-threaded post-fork child; clearenv just
                // empties the process environment.
                unsafe {
                    libc::clearenv();
                }

                // Apply PAM environment (now layered with HOME/USER/
                // LOGNAME/SHELL via apply_login_envs above). `setenv`
                // isn't strictly async-signal-safe per POSIX, but
                // our post-fork process is single-threaded and the
                // env list is bounded — the same approach OpenSSH
                // uses in `do_setup_env` → `child_set_env`.
                for (k, v) in &pam_envs {
                    // SAFETY: k, v are NUL-terminated `CString`s we
                    // own; the third argument 1 says "overwrite".
                    unsafe {
                        libc::setenv(k.as_ptr(), v.as_ptr(), 1);
                    }
                }
                // Layer per-channel SSH env (`env` requests) over the
                // PAM-derived env so the client's LANG / LC_* / user
                // variables win. Same async-signal-safe caveats as
                // above; the list is bounded by the channel's request
                // count and converted to CString pre-fork.
                for (k, v) in &channel_envs {
                    unsafe {
                        libc::setenv(k.as_ptr(), v.as_ptr(), 1);
                    }
                }

                // execvp the user's actual login shell from passwd,
                // with argv0 prefixed by "-" so bash/zsh/sh source
                // their login profile files.
                let _ = execvp(&info.shell_c, &[info.argv0_c.as_c_str()]);
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
                        "sshd: spawned pty shell pid={} master_fd={} pts={} user={} shell={}",
                        child.as_raw(),
                        raw,
                        slave_path,
                        info.name,
                        info.shell_str,
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
        _session_env: &[(String, String)],
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

    // -------------------------------------------------------------------------
    // Parent-side state for connection caps and graceful shutdown.
    //
    // All three of these are touched from `extern "C"` signal handlers, so
    // they must use only async-signal-safe primitives. `AtomicUsize` and
    // `AtomicBool` qualify (lock-free on every target we ship to); a
    // `Mutex<HashMap>` would not. Per-IP counts are kept in a parking-lot
    // `Mutex<HashMap>` accessed only from the main accept loop (never
    // from signal context) — see `OnIpScope` below.
    // -------------------------------------------------------------------------

    /// Live (unreaped + serving) connection children.  Incremented after
    /// a successful `fork()`, decremented on `SIGCHLD` once `waitpid`
    /// confirms the child exited.
    static LIVE_CHILDREN: AtomicUsize = AtomicUsize::new(0);

    /// Set to `true` by the SIGTERM/SIGINT handler. The accept loop polls
    /// it before each `accept()` and exits cleanly when it flips, letting
    /// in-flight children drain to their own SIGCHLD without orphaning
    /// them.
    static SHUTDOWN_REQUESTED: AtomicBool = AtomicBool::new(false);

    /// Per-peer-IP simultaneous-connection counts. Touched only by the
    /// main accept loop (`OnIpScope::new` / `OnIpScope::drop`) — never
    /// from signal context — so a `Mutex` is fine. Wrapped in a
    /// `OnceLock` so we get a stable-API one-shot initialiser without
    /// pulling in `once_cell`.
    static PER_IP_COUNTS: OnceLock<Mutex<HashMap<IpAddr, usize>>> = OnceLock::new();

    fn per_ip_counts() -> &'static Mutex<HashMap<IpAddr, usize>> {
        PER_IP_COUNTS.get_or_init(|| Mutex::new(HashMap::new()))
    }

    /// SIGCHLD handler: drain every reapable child via `waitpid(WNOHANG)`
    /// and decrement `LIVE_CHILDREN` per kid. Replaces the previous
    /// `SIG_IGN` setup so we keep an accurate live-children count for
    /// `--max-startups`.
    ///
    /// SAFETY: handler runs in signal context; uses only async-signal-safe
    /// calls (`waitpid` and atomic ops).
    extern "C" fn sigchld_handler(_sig: libc::c_int) {
        loop {
            // SAFETY: WNOHANG waitpid in a signal handler is documented
            // safe on every Unix we target.
            let r = unsafe { libc::waitpid(-1, core::ptr::null_mut(), libc::WNOHANG) };
            if r > 0 {
                // Reaped one. Saturate at 0 in case of double-decrement
                // races (shouldn't happen, but cheap insurance).
                let prev = LIVE_CHILDREN.load(Ordering::Relaxed);
                if prev > 0 {
                    LIVE_CHILDREN.fetch_sub(1, Ordering::Relaxed);
                }
                continue;
            }
            // 0: no more reapable. <0: error (typically ECHILD).
            break;
        }
    }

    /// SIGTERM / SIGINT handler: flip the shutdown flag so the accept
    /// loop exits at the next iteration. We deliberately do *not* try to
    /// signal in-flight children — they each carry their own client
    /// socket and the natural EOF on shutdown will tear them down.
    ///
    /// SAFETY: signal-context safe — just a single relaxed atomic store.
    extern "C" fn shutdown_handler(_sig: libc::c_int) {
        SHUTDOWN_REQUESTED.store(true, Ordering::Relaxed);
    }

    /// Install SIGCHLD (zombie reaper + live-count tracking) and
    /// SIGTERM/SIGINT (graceful shutdown). Replaces the prior
    /// `install_parent_sigchld` SIG_IGN setup.
    fn install_parent_signals() -> Result<(), String> {
        // SAFETY: `sigaction` with caller-owned `sigaction` structs is
        // POSIX-defined; the handler funcs we install reference only
        // statics + async-signal-safe APIs.
        unsafe {
            let mut sa: libc::sigaction = core::mem::zeroed();
            sa.sa_sigaction = sigchld_handler as *const () as usize;
            // SA_NOCLDSTOP: don't notify on stopped/continued children.
            // SA_RESTART:  let accept() restart on EINTR rather than
            //              fail out — the loop already handles EAGAIN
            //              backoff but spurious EINTR shouldn't error.
            sa.sa_flags = libc::SA_NOCLDSTOP | libc::SA_RESTART;
            libc::sigemptyset(&mut sa.sa_mask);
            if libc::sigaction(libc::SIGCHLD, &sa, core::ptr::null_mut()) != 0 {
                return Err(format!(
                    "sigaction(SIGCHLD): {}",
                    std::io::Error::last_os_error()
                ));
            }
            let mut sa: libc::sigaction = core::mem::zeroed();
            sa.sa_sigaction = shutdown_handler as *const () as usize;
            // Deliberately no SA_RESTART: we *want* SIGTERM/SIGINT to
            // wake a blocked accept() so the loop can observe the flag.
            sa.sa_flags = 0;
            libc::sigemptyset(&mut sa.sa_mask);
            if libc::sigaction(libc::SIGTERM, &sa, core::ptr::null_mut()) != 0 {
                return Err(format!(
                    "sigaction(SIGTERM): {}",
                    std::io::Error::last_os_error()
                ));
            }
            if libc::sigaction(libc::SIGINT, &sa, core::ptr::null_mut()) != 0 {
                return Err(format!(
                    "sigaction(SIGINT): {}",
                    std::io::Error::last_os_error()
                ));
            }
        }
        Ok(())
    }

    /// RAII guard that increments `PER_IP_COUNTS[ip]` on construction and
    /// decrements on drop. Returned by [`admit_connection`] when the new
    /// connection is allowed under both caps; held by the parent for the
    /// lifetime of the child PID so a `kill -9` of the parent simply
    /// vaporises the counts (no cleanup needed). Held by the *parent*,
    /// not the forked child — drop runs only when the parent loop drops
    /// the guard at child-spawn time, so the live count is the count of
    /// in-flight admits, not of finished children. To reconcile: the
    /// SIGCHLD handler bounds the lifetime via `LIVE_CHILDREN`.
    struct OnIpScope {
        ip: IpAddr,
    }

    impl Drop for OnIpScope {
        fn drop(&mut self) {
            if let Ok(mut m) = per_ip_counts().lock() {
                if let Some(c) = m.get_mut(&self.ip) {
                    *c = c.saturating_sub(1);
                    if *c == 0 {
                        m.remove(&self.ip);
                    }
                }
            }
        }
    }

    /// Apply the two connection caps (global `--max-startups` and
    /// per-source `--per-source-max`) atomically. Returns the per-IP
    /// scope guard on admission, or `Err(reason)` for refusal — the
    /// caller logs the reason and closes the socket.
    fn admit_connection(
        peer: &std::net::SocketAddr,
        max_startups: u32,
        per_source_max: u32,
    ) -> Result<OnIpScope, &'static str> {
        if max_startups > 0 && LIVE_CHILDREN.load(Ordering::Relaxed) >= max_startups as usize {
            return Err("max-startups");
        }
        let ip = peer.ip();
        if per_source_max > 0 {
            let mut m = per_ip_counts().lock().map_err(|_| "per-ip-lock")?;
            let c = m.entry(ip).or_insert(0);
            if *c >= per_source_max as usize {
                return Err("per-source-max");
            }
            *c += 1;
        }
        Ok(OnIpScope { ip })
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

        // Load sshd_config if `-f` was supplied; otherwise an empty config
        // so every `pick()` falls through to the CLI value or the built-in
        // default. CLI flags always win over the config file (so adminstrators
        // can override a baked-in config without editing it).
        let sshd_cfg = match cli.config_file.as_deref() {
            Some(p) => load_server_config(std::path::Path::new(p))?,
            None => puressh::config::SshServerConfig::default(),
        };

        // Resolve effective values: CLI > config > built-in default.
        let port = pick(cli.port, sshd_cfg.port, 2222u16);
        let strict_modes = pick(cli.strict_modes, sshd_cfg.strict_modes, true);
        let sftp_enabled = pick(cli.sftp, sshd_cfg.sftp_enabled, true);
        let sftp_read_only = pick(cli.sftp_read_only, sshd_cfg.sftp_read_only, false);
        let sftp_root: Option<std::path::PathBuf> = cli
            .sftp_root
            .as_deref()
            .or(sshd_cfg.sftp_root.as_deref())
            .map(std::path::PathBuf::from);
        let scp_enabled = pick(cli.scp, sshd_cfg.scp_enabled, true);
        let agent_forward = pick(cli.agent_forward, sshd_cfg.allow_agent_forwarding, true);
        let x11_forward = pick(cli.x11_forward, sshd_cfg.x11_forwarding, true);
        let login_grace_time = pick(cli.login_grace_time, sshd_cfg.login_grace_time, 120u32);
        let max_startups = pick(cli.max_startups, sshd_cfg.max_startups, 100u32);

        // CLI host-keys, then any HostKey lines from config (cumulative).
        let mut host_key_files = cli.host_key_files.clone();
        host_key_files.extend(sshd_cfg.host_key_files.iter().cloned());
        if host_key_files.is_empty() {
            return Err(
                "at least one -h host_key_file (or HostKey in sshd_config) is required".into(),
            );
        }

        let authorized_keys_file = cli
            .authorized_keys_file
            .clone()
            .or_else(|| sshd_cfg.authorized_keys_file.clone());

        // CLI `-u`, then `AllowUsers` from config (cumulative across blocks).
        let mut allowed_user_list = cli.allowed_users.clone();
        allowed_user_list.extend(sshd_cfg.allow_users.iter().cloned());

        // Likewise `--accept-env` ++ `AcceptEnv`.
        let mut accept_env = cli.accept_env.clone();
        accept_env.extend(sshd_cfg.accept_env.iter().cloned());

        // Pick the bind address. We support a single listener for v1; warn
        // if more than one ListenAddress / -b was supplied.
        let mut bind_specs = cli.listen_addresses.clone();
        bind_specs.extend(sshd_cfg.listen_addresses.iter().cloned());
        if bind_specs.len() > 1 {
            eprintln!(
                "sshd: warning: {} ListenAddress entries supplied; binding only the first \
                 (multi-address listen is a follow-up). Extras: {:?}",
                bind_specs.len(),
                &bind_specs[1..]
            );
        }
        let bind_addr = match bind_specs.first() {
            Some(s) => {
                // Bare host → add the effective port. `host:port` passes through.
                if s.contains(':') && !s.contains("::") {
                    s.clone()
                } else if s.starts_with('[') {
                    // [v6]:port literal — already complete
                    s.clone()
                } else {
                    // bare host or bare IPv6 → append :port
                    if s.contains(':') {
                        // bare IPv6 literal
                        format!("[{s}]:{port}")
                    } else {
                        format!("{s}:{port}")
                    }
                }
            }
            None => format!("127.0.0.1:{port}"),
        };

        let host_keys = load_host_keys(&host_key_files, strict_modes)?;
        let authorized_blobs: Vec<Vec<u8>> = match &authorized_keys_file {
            Some(path) => load_authorized_keys(path, strict_modes)?
                .into_iter()
                .map(|k| k.wire_blob())
                .collect(),
            None => Vec::new(),
        };

        let allowed_users: HashSet<String> = if allowed_user_list.is_empty() {
            let u = current_user()?;
            let mut s = HashSet::new();
            s.insert(u);
            s
        } else {
            allowed_user_list.into_iter().collect()
        };

        // PermitRootLogin: CLI > config > built-in `prohibit-password`
        // (OpenSSH's default; permits root-by-key since puressh has no
        // password auth). Precompute which allowed usernames resolve to the
        // root account (uid 0) so the authenticator gate is an O(1) lookup.
        // The name "root" is always treated as root even if the passwd
        // lookup fails; any other name is root only if it resolves to uid 0.
        let permit_root_login = pick(
            cli.permit_root_login,
            sshd_cfg.permit_root_login,
            puressh::config::PermitRootLogin::ProhibitPassword,
        );
        let root_users: HashSet<String> = allowed_users
            .iter()
            .filter(|name| {
                name.as_str() == "root"
                    || matches!(
                        nix::unistd::User::from_name(name),
                        Ok(Some(u)) if u.uid.as_raw() == 0
                    )
            })
            .cloned()
            .collect();
        if cli.debug && !root_users.is_empty() {
            eprintln!(
                "sshd: PermitRootLogin={permit_root_login:?}; root-equivalent allowed users: {root_users:?}"
            );
        }

        let factory = Arc::new(LocalAuthFactory {
            allowed_users: Arc::new(allowed_users),
            authorized_blobs: Arc::new(authorized_blobs),
            root_users: Arc::new(root_users),
            permit_root_login,
            debug: cli.debug,
        });

        // One PamGate per accept-loop iteration's child. The parent
        // holds a clone too, but fork's COW gives each connection its
        // own copy — no cross-connection state bleed.
        let pam_gate = pam_gate::PamGate::new(cli.debug);

        let mut config = Config::new(
            host_keys,
            factory,
            vec!["publickey"],
            Arc::new(ShellCommandHandler {
                pam: pam_gate.clone(),
                debug: cli.debug,
                debug_commands: cli.debug_commands,
            }),
        )
        .with_shell(Arc::new(NixShellHandler {
            pam: pam_gate.clone(),
            debug: cli.debug,
        }));

        if sftp_enabled {
            let sftp = SftpSubsystemHandler {
                read_only: sftp_read_only,
                root: sftp_root.clone(),
                debug: cli.debug,
            };
            config = config.with_subsystem(Arc::new(sftp));
        }

        if scp_enabled {
            let scp = ScpExecHandler { debug: cli.debug };
            config = config.with_exec_stream_handler(Arc::new(scp));
        }

        if agent_forward {
            use puressh::forwarding::agent::DefaultAgentForwardHandler;
            config = config.with_agent_forward(Arc::new(DefaultAgentForwardHandler::new()));
        }

        if x11_forward {
            use puressh::forwarding::x11::DefaultX11ForwardHandler;
            config = config.with_x11_forward(Arc::new(DefaultX11ForwardHandler::new()));
        }

        // Connection-level session open. Two steps, in this order, exactly
        // once per connection:
        //
        //   1. pam.ensure() — pam_acct_mgmt + pam_open_session against
        //      service `sshd`, run while we are still root so pam_loginuid /
        //      pam_limits / pam_systemd (which need privilege) work, and so
        //      EVERY session type (shell / exec / SFTP / SCP) is uniformly
        //      gated by the authoritative account check. If PAM rejects the
        //      account (expired/locked, /etc/nologin, pam_time, pam_access)
        //      ensure() returns Err and we refuse the connection here —
        //      before any privilege drop and before any handler runs.
        //   2. drop_to_user() — drop to the authenticated user's uid/gid.
        //      Subsequent shell forks discover `already_matches(&info)` true
        //      and skip their own drop; SFTP/SCP run as the user in-process.
        //
        // The PAM session opened here stays valid for the connection's life;
        // the eventual pam_close_session runs at teardown as the user, which
        // works for every PAM module shipped by Linux distros today. The
        // per-handler ensure() calls are now idempotent no-ops (the gate is
        // once-guarded) and simply return the cached PAM env list.
        let debug = cli.debug;
        let session_pam = pam_gate.clone();
        config = config.on_session_open(move |user: &str| {
            // PAM_TTY = "ssh" matches OpenSSH's value for the session-level
            // gate; PTY shells later re-call ensure() (a no-op) for env.
            session_pam.ensure(user, "ssh")?;
            drop_to_user(user, debug)
        });

        // Plumb finding-#1 (env allowlist) and finding-#2 (pre-auth
        // inactivity timeout) into the server config. with_accept_env
        // accepts an empty vec to mean "drop every client env" — which
        // is the secure default. login_grace_time = 0 disables the
        // timeout for users who want OpenSSH's classic "no limit"
        // behaviour.
        config = config.with_accept_env(accept_env);
        if login_grace_time > 0 {
            config = config
                .with_login_grace_time(std::time::Duration::from_secs(login_grace_time.into()));
        } else {
            // Pass Duration::ZERO so the server can treat 0 as "disabled".
            config = config.with_login_grace_time(std::time::Duration::ZERO);
        }

        let cfg = Arc::new(config);

        install_parent_signals()?;

        let addr = bind_addr;
        let listener =
            std::net::TcpListener::bind(&addr).map_err(|e| format!("bind {addr}: {e}"))?;

        eprintln!(
            "puressh sshd listening on {addr} (pid {})",
            std::process::id()
        );

        // Exponential backoff for `fork()` EAGAIN — under a fork-bomb a
        // tight `continue` loop just makes the kernel keep saying no.
        // Reset to `MIN` on any successful fork.
        const FORK_BACKOFF_MIN_MS: u64 = 10;
        const FORK_BACKOFF_MAX_MS: u64 = 1_000;
        let mut fork_backoff_ms: u64 = FORK_BACKOFF_MIN_MS;

        loop {
            if SHUTDOWN_REQUESTED.load(Ordering::Relaxed) {
                eprintln!("sshd: shutdown requested, exiting accept loop");
                break;
            }
            let (stream, peer) = match listener.accept() {
                Ok(p) => p,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {
                    // Was probably our SIGTERM/SIGINT — loop and let the
                    // shutdown flag check catch it.
                    continue;
                }
                Err(e) => {
                    eprintln!("sshd: accept: {e}");
                    continue;
                }
            };

            // Enforce both connection caps *before* fork so a flood
            // can't OOM us via per-process accounting. On refusal we
            // simply drop the socket — RST tells the client to retry.
            let scope = match admit_connection(&peer, max_startups, cli.per_source_max) {
                Ok(s) => s,
                Err(reason) => {
                    if cli.debug {
                        eprintln!("sshd: refused {peer}: {reason}");
                    }
                    drop(stream);
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
                    fork_backoff_ms = FORK_BACKOFF_MIN_MS;
                    // Account the child against `--max-startups` once we
                    // know fork() succeeded; SIGCHLD will decrement it
                    // back on reap.
                    LIVE_CHILDREN.fetch_add(1, Ordering::Relaxed);
                    if cli.debug {
                        eprintln!(
                            "sshd: forked connection {peer} -> pid {} (live={})",
                            child.as_raw(),
                            LIVE_CHILDREN.load(Ordering::Relaxed),
                        );
                    }
                    // Parent has no further use for this socket — its
                    // refcount in the child keeps it alive.
                    drop(stream);
                    // OnIpScope auto-drops at end of iteration —
                    // explicit drop here makes the lifetime clear.
                    drop(scope);
                }
                Ok(ForkResult::Child) => {
                    // Child doesn't own the parent's per-IP scope.
                    // `mem::forget` so dropping in the child doesn't
                    // touch the parent's count and *decrement someone
                    // else's per-IP entry*.
                    core::mem::forget(scope);
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
                    // Likewise restore default SIGTERM/SIGINT so the
                    // child dies cleanly on signal rather than getting
                    // the parent's "set the shutdown flag" handler.
                    let _ = unsafe { signal(Signal::SIGTERM, SigHandler::SigDfl) };
                    let _ = unsafe { signal(Signal::SIGINT, SigHandler::SigDfl) };

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
                    eprintln!("sshd: fork: {e} (backoff {fork_backoff_ms}ms)");
                    drop(stream);
                    drop(scope);
                    // Bounded exponential backoff so a sustained EAGAIN
                    // (rlimit, OOM-killer pressure) doesn't pin a core.
                    std::thread::sleep(std::time::Duration::from_millis(fork_backoff_ms));
                    fork_backoff_ms = (fork_backoff_ms * 2).min(FORK_BACKOFF_MAX_MS);
                }
            }
        }
        Ok(0)
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
