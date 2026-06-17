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
    use std::collections::HashMap;
    use std::ffi::OsStr;
    use std::net::IpAddr;
    use std::os::fd::{AsFd, AsRawFd, OwnedFd};
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::process::CommandExt;
    use std::process::{Command, ExitCode};
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex, OnceLock};

    use nix::errno::Errno;
    use nix::fcntl::{FcntlArg, OFlag, fcntl};
    use nix::libc;
    use nix::sys::signal::{SigHandler, Signal, kill, signal};
    use nix::sys::wait::{WaitPidFlag, WaitStatus, waitpid};
    use nix::unistd::{ForkResult, Pid, execvp, fork};

    use puressh::auth::{AuthAttempt, AuthDecision, Authenticator};
    use puressh::hostkey::HostKey;
    use puressh::key::{PrivateKey, PublicKey};
    use puressh::scp::{
        Receiver as ScpReceiver, ScpRecvOptions, ScpSendOptions, Sender as ScpSender,
    };
    use puressh::server::{
        AuthenticatorFactory, ChannelStream, CommandHandler, Config, ExecResult, ExecStreamHandler,
        HARD_BLOCKED_ENV_NAMES, PtySpec, SessionEnv, SessionOpenContext, ShellExitStatus,
        ShellHandler, ShellSession, SubsystemHandler, handle_session_with_peer,
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
        use std::ffi::{CStr, CString};
        use std::os::unix::ffi::OsStrExt;
        use std::sync::{Arc, Mutex};

        use pam_client2::conv_null::Conversation;
        use pam_client2::{Context, ConversationHandler, ErrorCode, Flag, SessionToken};
        use zeroize::Zeroizing;

        /// A one-shot PAM conversation that answers every
        /// `PAM_PROMPT_ECHO_OFF` (the password prompt) with a fixed secret,
        /// held in a [`Zeroizing`] buffer so its bytes are wiped on drop.
        /// Echo-on prompts (username) and info/error messages are ignored —
        /// the username is already bound via `Context::new`, and we never
        /// surface PAM text to the network here. This is the
        /// non-interactive "verify this password" conversation; a full
        /// multi-step PAM challenge (e.g. an OTP module that asks a second
        /// question) is not handled and will fail closed.
        struct PasswordConv {
            password: Zeroizing<Vec<u8>>,
        }

        impl ConversationHandler for PasswordConv {
            fn prompt_echo_on(&mut self, _prompt: &CStr) -> Result<CString, ErrorCode> {
                // Username/echo-on prompts: nothing to supply (the context
                // already carries the target user). Empty answer.
                CString::new(Vec::new()).map_err(|_| ErrorCode::CONV_ERR)
            }
            fn prompt_echo_off(&mut self, _prompt: &CStr) -> Result<CString, ErrorCode> {
                // The password may not contain an interior NUL.
                CString::new(self.password.to_vec()).map_err(|_| ErrorCode::CONV_ERR)
            }
            fn text_info(&mut self, _msg: &CStr) {}
            fn error_msg(&mut self, _msg: &CStr) {}
        }

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

            /// Verify `password` for `user` against PAM, *without* opening a
            /// session (that still happens later in `ensure`/
            /// `on_session_open`). A fresh, throw-away `Context` is created
            /// with a [`PasswordConv`] conversation that answers the password
            /// prompt; `authenticate()` + `acct_mgmt()` must both succeed. The
            /// context is dropped at the end of this call (running `pam_end`),
            /// so this never disturbs the cached session state.
            ///
            /// Runs in the per-connection forked child while still root, which
            /// is what PAM auth (e.g. reading `/etc/shadow`) requires; the
            /// privilege drop happens afterwards in `on_session_open`.
            ///
            /// MANUAL e2e (not a hermetic unit test — installing a PAM service
            /// file needs root + writes to `/etc/pam.d`, which CI can't do):
            ///   1. Create `/etc/pam.d/sshd` containing only
            ///      `auth required pam_permit.so` / `account required
            ///      pam_permit.so` and confirm any password authenticates;
            ///      swap `pam_permit.so` for `pam_deny.so` and confirm none do.
            ///   2. With the real system `sshd` service, confirm a correct
            ///      account password authenticates and a wrong one is rejected,
            ///      and that `PermitEmptyPasswords no` refuses an empty one.
            pub fn pam_check_password(
                &self,
                user: &str,
                password: Zeroizing<Vec<u8>>,
                rhost: Option<&str>,
            ) -> puressh::Result<()> {
                let conv = PasswordConv { password };
                let mut ctx = Context::new(self.service, Some(user), conv)
                    .map_err(|e| pam_err("pam_start", e))?;
                if let Some(rhost) = rhost {
                    ctx.set_rhost(Some(rhost))
                        .map_err(|e| pam_err("set_rhost", e))?;
                }
                ctx.authenticate(Flag::NONE)
                    .map_err(|e| pam_err("authenticate", e))?;
                ctx.acct_mgmt(Flag::NONE)
                    .map_err(|e| pam_err("acct_mgmt", e))?;
                // `ctx` (and the embedded `PasswordConv`, whose buffer is
                // `Zeroizing`) drops here — pam_end runs, no session opened.
                Ok(())
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
            /// No PAM backend compiled in: password verification always
            /// fails. The server additionally never advertises the
            /// password/keyboard-interactive methods on such a build (the
            /// method set is computed from `cfg!(all(feature="pam",
            /// target_os="linux"))`), so this is belt-and-braces. The buffer
            /// is dropped (and zeroized) here.
            pub fn pam_check_password(
                &self,
                _user: &str,
                _password: zeroize::Zeroizing<Vec<u8>>,
                _rhost: Option<&str>,
            ) -> puressh::Result<()> {
                Err(puressh::Error::Io(std::io::Error::other(
                    "password authentication unavailable: no PAM backend compiled",
                )))
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

    /// Read and parse a single `sshd_config`-format file, resolving any
    /// `Include` directives recursively. There is no default search path on
    /// the server side: distros disagree on where the file lives, and the
    /// user explicitly opts in via `-f`. Relative includes resolve against the
    /// directory of the file being parsed (and, for the system entry point at
    /// `/etc/ssh/...`, that is `/etc/ssh`).
    fn load_server_config(
        path: &std::path::Path,
    ) -> Result<puressh::config::SshServerConfig, String> {
        let lines = puressh::config::include::tokenize_file_with_includes(path, 0)
            .map_err(|e| format!("{}: {e}", path.display()))?;
        puressh::config::SshServerConfig::from_lines(lines)
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

    /// A user→group-names resolver. Boxed so tests can inject a mock; the
    /// production value is [`lookup_user_groups`].
    type GroupLookup = Arc<dyn Fn(&str) -> Vec<String> + Send + Sync>;

    /// One `AllowUsers`/`DenyUsers` token. A bare token (`alice`, `!bob`,
    /// `dev-*`) constrains the username only; a `user@host` token additionally
    /// constrains the connection's peer address. OpenSSH negation (`!`) applies
    /// to the whole token and is stored separately from the globs so a `user`
    /// or `host` half can each carry the `*`/`?` grammar.
    #[derive(Clone)]
    struct UserHostPattern {
        /// True iff the token had a leading `!` (a match *excludes*).
        negated: bool,
        /// Username glob (the part before `@`, or the whole token).
        user: puressh::config::HostPattern,
        /// Host glob (the part after `@`), or `None` for a bare-user token.
        host: Option<puressh::config::HostPattern>,
    }

    impl UserHostPattern {
        /// Parse one whitespace-separated `AllowUsers`/`DenyUsers` token.
        fn parse(token: &str) -> Self {
            let (negated, body) = match token.strip_prefix('!') {
                Some(rest) => (true, rest),
                None => (false, token),
            };
            match body.split_once('@') {
                Some((user, host)) => UserHostPattern {
                    negated,
                    // The `!` already lives on the compound token; the inner
                    // globs are always positive patterns.
                    user: puressh::config::HostPattern::parse(user),
                    host: Some(puressh::config::HostPattern::parse(host)),
                },
                None => UserHostPattern {
                    negated,
                    user: puressh::config::HostPattern::parse(body),
                    host: None,
                },
            }
        }

        fn parse_all(tokens: &[String]) -> Vec<UserHostPattern> {
            tokens.iter().map(|t| UserHostPattern::parse(t)).collect()
        }

        /// True iff this token's positive globs match `(user, peer)`. The host
        /// half (if present) is matched against `peer`; a `user@host` token
        /// with no known peer address never matches.
        fn positive_match(&self, user: &str, peer: Option<&str>) -> bool {
            let user_ok =
                puressh::config::glob::host_matches(core::slice::from_ref(&self.user), user);
            if !user_ok {
                return false;
            }
            match &self.host {
                None => true,
                Some(h) => match peer {
                    Some(p) => puressh::config::glob::host_matches(core::slice::from_ref(h), p),
                    None => false,
                },
            }
        }
    }

    /// OpenSSH list semantics over [`UserHostPattern`]s: the list matches
    /// `(user, peer)` iff at least one positive token matches AND no negative
    /// token matches. An empty list never matches (the caller treats "empty
    /// AllowUsers" as "no restriction", handled separately).
    fn user_host_list_matches(
        patterns: &[UserHostPattern],
        user: &str,
        peer: Option<&str>,
    ) -> bool {
        let mut any_positive = false;
        let mut positive_hit = false;
        for p in patterns {
            if p.negated {
                if p.positive_match(user, peer) {
                    return false;
                }
            } else {
                any_positive = true;
                if p.positive_match(user, peer) {
                    positive_hit = true;
                }
            }
        }
        any_positive && positive_hit
    }

    struct LocalAuthenticator {
        /// `AllowUsers` patterns (`user[@host]`, OpenSSH `Host`-style globs).
        /// Empty ⇒ the historical "current user only" default applied by the
        /// caller (it seeds this with the single resolved current user as a
        /// literal).
        allow_users: Vec<UserHostPattern>,
        /// `DenyUsers` patterns (`user[@host]`). Highest precedence.
        deny_users: Vec<UserHostPattern>,
        /// `AllowGroups` patterns (glob). Non-empty ⇒ the user must belong to
        /// a matching group.
        allow_groups: Vec<puressh::config::HostPattern>,
        /// `DenyGroups` patterns (glob).
        deny_groups: Vec<puressh::config::HostPattern>,
        authorized_blobs: Vec<Vec<u8>>,
        permit_root_login: puressh::config::PermitRootLogin,
        /// Shared PAM gate (per-connection, COW-isolated by `fork`). Used to
        /// verify passwords via `pam_check_password`. On a non-PAM build the
        /// stub always fails — but the binary also never advertises
        /// password/keyboard-interactive there, so this is belt-and-braces.
        pam: Arc<pam_gate::PamGate>,
        /// `PasswordAuthentication` enabled for this build/config (advertised).
        /// When false, a `password` attempt is rejected outright.
        password_enabled: bool,
        /// `KbdInteractiveAuthentication` enabled for this build/config.
        kbd_interactive_enabled: bool,
        /// `PermitEmptyPasswords` — when false (the default), an empty password
        /// is rejected without ever consulting PAM.
        permit_empty_passwords: bool,
        /// Multi-factor chain set, resolved per-user from
        /// `AuthenticationMethods` (each inner Vec is one comma-chain of
        /// required methods). Empty ⇒ single-factor (any one advertised method
        /// suffices). Installed by `on_user_resolved`.
        chains: Vec<Vec<&'static str>>,
        /// Methods satisfied so far on this connection, in order. Used by
        /// `record_and_decide` to test chain completion. `none` never appears
        /// here.
        satisfied: Vec<&'static str>,
        /// The username bound to this connection once the first request is
        /// seen. A later attempt with a different username is rejected (OpenSSH
        /// terminates auth on a mid-userauth username change).
        bound_user: Option<String>,
        /// Per-connection memoization of `resolves_to_root(user)`. The
        /// passwd lookup happens at auth (login) time, not daemon startup,
        /// so it reflects the current database; the cache only avoids
        /// re-resolving the same username across this connection's repeated
        /// attempts (probe then signature, multiple offered keys).
        root_uid0_cache: std::collections::HashMap<String, bool>,
        /// Per-connection memoization of the user's group names (parallel to
        /// `root_uid0_cache`); resolved once, reused across attempts.
        group_cache: std::collections::HashMap<String, Vec<String>>,
        /// Group resolver (production: `lookup_user_groups`; tests: a mock).
        group_lookup: GroupLookup,
        /// Resolved peer address (IP/hostname) for this connection, used by the
        /// host half of `AllowUsers`/`DenyUsers` `user@host` patterns. `None`
        /// when the address is the unspecified placeholder (e.g. an in-process
        /// test transport); a `user@host` rule never matches a `None` peer.
        peer: Option<String>,
        debug: bool,
    }

    impl LocalAuthenticator {
        /// Apply the OpenSSH access precedence — DenyUsers → AllowUsers →
        /// DenyGroups → AllowGroups — returning `true` iff `user` is allowed.
        ///
        /// `AllowUsers`/`DenyUsers` `user@host` tokens additionally match the
        /// host half against this connection's resolved peer address.
        ///
        /// Group lookups are memoized per connection and resolved for *every*
        /// user uniformly (the caller never short-circuits on an
        /// already-failed user check), so the resolution cannot leak whether a
        /// user exists via timing.
        fn access_allowed(&mut self, user: &str) -> bool {
            let peer = self.peer.as_deref();
            // Resolve groups up front (uniform cost) so every branch below
            // sees the same work regardless of which check decides.
            let groups = match self.group_cache.get(user) {
                Some(g) => g.clone(),
                None => {
                    let g = (self.group_lookup)(user);
                    self.group_cache.insert(user.to_string(), g.clone());
                    g
                }
            };
            let in_group = |pats: &[puressh::config::HostPattern]| {
                groups
                    .iter()
                    .any(|g| puressh::config::glob::host_matches(pats, g))
            };

            // 1. DenyUsers wins outright.
            if !self.deny_users.is_empty() && user_host_list_matches(&self.deny_users, user, peer) {
                return false;
            }
            // 2. AllowUsers: if set, the user must match one.
            if !self.allow_users.is_empty()
                && !user_host_list_matches(&self.allow_users, user, peer)
            {
                return false;
            }
            // 3. DenyGroups: a matching group refuses.
            if !self.deny_groups.is_empty() && in_group(&self.deny_groups) {
                return false;
            }
            // 4. AllowGroups: if set, the user must be in a matching group.
            if !self.allow_groups.is_empty() && !in_group(&self.allow_groups) {
                return false;
            }
            true
        }

        /// Memoized `resolves_to_root(user)` for this connection.
        fn is_root(&mut self, user: &str) -> bool {
            match self.root_uid0_cache.get(user) {
                Some(&r) => r,
                None => {
                    let r = resolves_to_root(user);
                    self.root_uid0_cache.insert(user.to_string(), r);
                    r
                }
            }
        }

        /// Bind / verify the connection username. Returns `false` if the client
        /// switched usernames mid-userauth (OpenSSH rejects this). The first
        /// call binds; subsequent calls must match.
        fn check_user_binding(&mut self, user: &str) -> bool {
            match &self.bound_user {
                None => {
                    self.bound_user = Some(user.to_string());
                    true
                }
                Some(bound) => bound == user,
            }
        }

        /// Decide whether an empty password may even be attempted, *before* any
        /// PAM call. Extracted as a pure, PAM-independent helper so the policy
        /// (empty password refused unless `PermitEmptyPasswords`) is unit-
        /// testable without a live PAM stack.
        ///
        /// `true` ⇒ the password is non-empty, or empty passwords are
        /// permitted, so the caller may proceed to verify it. `false` ⇒ reject
        /// without consulting the backend.
        fn empty_password_allowed(permit_empty: bool, password: &[u8]) -> bool {
            !password.is_empty() || permit_empty
        }

        /// Full password-verification path shared by the `password` and
        /// `keyboard-interactive` methods: access control + PermitRootLogin +
        /// empty-password policy + PAM.
        ///
        /// Timing uniformity: the PAM call (the dominant, shadow-hashing cost)
        /// runs for *every* attempt regardless of whether access control or the
        /// root gate would refuse the user — PAM returns USER_UNKNOWN/AUTH_ERR
        /// after a comparable delay for unknown users, so an attacker cannot
        /// distinguish "no such user / not allowed" from "wrong password" by
        /// wall-clock. The access/root verdicts only AND into the final result;
        /// the only short-circuit is the empty-password refusal, which is gated
        /// on the *client-supplied input* (an empty password), not on any
        /// per-user secret, so it leaks nothing about which users exist.
        /// Returns the chain-aware decision via `record_and_decide` on success,
        /// or `Reject`.
        fn verify_password(
            &mut self,
            user: &str,
            method: &'static str,
            password: zeroize::Zeroizing<Vec<u8>>,
        ) -> AuthDecision {
            // Mid-userauth username change ⇒ reject (don't leak which half
            // failed).
            if !self.check_user_binding(user) {
                if self.debug {
                    eprintln!("sshd: auth {method}: username changed mid-userauth, rejecting");
                }
                return AuthDecision::Reject;
            }

            // Empty-password refusal is input-dependent (not user-dependent), so
            // short-circuiting here introduces no user-enumeration oracle.
            if !Self::empty_password_allowed(self.permit_empty_passwords, &password) {
                if self.debug {
                    eprintln!("sshd: auth {method}: empty password refused for {user}");
                }
                return AuthDecision::Reject;
            }

            // Access control + root gate. Computed up front but applied *after*
            // the PAM call so the call always runs (uniform timing).
            let user_ok = self.access_allowed(user);
            let is_root = self.is_root(user);
            let root_denied = is_root && !self.permit_root_login.permits_password();

            let rhost = self.peer.clone();
            let pam_ok = self
                .pam
                .pam_check_password(user, password, rhost.as_deref())
                .is_ok();

            if pam_ok && user_ok && !root_denied {
                if self.debug {
                    eprintln!("sshd: auth {method}: accepted user {user}");
                }
                return self.record_and_decide(method);
            }
            if self.debug {
                if !pam_ok {
                    eprintln!("sshd: auth {method}: PAM rejected user {user}");
                } else if root_denied {
                    eprintln!(
                        "sshd: auth {method}: root login denied by PermitRootLogin for {user}"
                    );
                } else {
                    eprintln!("sshd: auth {method}: user {user} not in allowed set");
                }
            }
            AuthDecision::Reject
        }

        /// Record a satisfied factor and decide whether authentication is
        /// complete given the per-user multi-factor chain set.
        ///
        /// - No chains configured ⇒ single-factor: any one method accepts.
        /// - Some chain fully covered by the satisfied set ⇒ Accept.
        /// - Otherwise ⇒ PartialAccept whose `still_required` is the union of
        ///   the next-needed methods across every chain still viable (a chain
        ///   is viable iff every method satisfied so far is one of its
        ///   members).
        ///
        /// Membership is set-based, not positional: a chain `publickey,password`
        /// is considered satisfied once *both* methods have succeeded in any
        /// order. This deviates from OpenSSH, which enforces the listed order;
        /// the deviation is documented and intentional (it never *weakens* the
        /// requirement — the same set of factors is still mandatory).
        /// `none` is never recorded and never counts toward a chain.
        fn record_and_decide(&mut self, method: &'static str) -> AuthDecision {
            if method != "none" && !self.satisfied.contains(&method) {
                self.satisfied.push(method);
            }

            // Single-factor: no chains ⇒ one success is enough.
            if self.chains.is_empty() {
                return AuthDecision::Accept;
            }

            let satisfied_all = |chain: &[&'static str]| -> bool {
                chain
                    .iter()
                    .all(|m| *m == "none" || self.satisfied.contains(m))
            };

            // Any chain fully satisfied ⇒ done.
            if self.chains.iter().any(|c| satisfied_all(c)) {
                return AuthDecision::Accept;
            }

            // Otherwise gather the next-needed methods across viable chains. A
            // chain is viable iff everything we've satisfied so far belongs to
            // it (we haven't "used up" a factor it doesn't want — though since
            // extra factors never hurt, we treat any chain that still has
            // unmet members as viable and offer those members).
            let mut next: Vec<String> = Vec::new();
            for chain in &self.chains {
                for m in chain {
                    if *m != "none" && !self.satisfied.contains(m) {
                        let s = (*m).to_string();
                        if !next.contains(&s) {
                            next.push(s);
                        }
                    }
                }
            }
            AuthDecision::PartialAccept {
                still_required: next,
            }
        }
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
                    // The access check (DenyUsers/AllowUsers/DenyGroups/
                    // AllowGroups, with a memoized group lookup) and the
                    // linear scan over authorized_blobs both run for every
                    // attempt so the paths stay uniform.
                    let user_bound = self.check_user_binding(&user);
                    let user_ok = self.access_allowed(&user);
                    let blob_ok = self.authorized_blobs.contains(&public_blob);
                    // PermitRootLogin gate: if the requested user resolves to
                    // the root account (uid 0) and policy forbids it, deny
                    // regardless of key match. The username is resolved at
                    // login time (memoized per connection) rather than from a
                    // daemon-startup snapshot, so a uid-0 alias added after
                    // startup is still caught. Resolved for every requested
                    // user (not only allowed ones) so the lookup doesn't add a
                    // user-enumeration timing signal.
                    let is_root = self.is_root(&user);
                    let root_denied = is_root && !self.permit_root_login.permits_publickey();
                    let allow = user_bound && user_ok && blob_ok && !root_denied;

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
                        eprintln!("sshd: auth publickey: verified user {user}");
                    }
                    // A verified signature satisfies the `publickey` factor. In
                    // single-factor mode this Accepts; under a multi-factor
                    // chain it may PartialAccept and ask for the next factor.
                    self.record_and_decide("publickey")
                }
                AuthAttempt::Password { user, password } => {
                    if !self.password_enabled {
                        if self.debug {
                            eprintln!("sshd: auth password rejected (disabled) for user {user}");
                        }
                        return AuthDecision::Reject;
                    }
                    // Copy the secret bytes into a zeroize-on-drop buffer; the
                    // source `SecretString` is itself zeroizing and drops at the
                    // end of this arm.
                    let pw = zeroize::Zeroizing::new(password.as_bytes().to_vec());
                    self.verify_password(&user, "password", pw)
                }
                AuthAttempt::KeyboardInteractive { user } => {
                    if !self.kbd_interactive_enabled {
                        if self.debug {
                            eprintln!(
                                "sshd: auth keyboard-interactive rejected (disabled) for user {user}"
                            );
                        }
                        return AuthDecision::Reject;
                    }
                    // Bind the username now (so a later switch is caught) and
                    // drive a single password prompt. The actual verification
                    // happens in `evaluate_interactive` once the client answers.
                    if !self.check_user_binding(&user) {
                        if self.debug {
                            eprintln!(
                                "sshd: auth keyboard-interactive: username changed mid-userauth"
                            );
                        }
                        return AuthDecision::Reject;
                    }
                    AuthDecision::InteractiveRequest {
                        name: String::new(),
                        instruction: String::new(),
                        // Single non-echoed password prompt. A full multi-step
                        // PAM conversation (e.g. an OTP module that asks a
                        // second question) is a deferred follow-up.
                        prompts: alloc_prompts(),
                    }
                }
            }
        }

        fn evaluate_interactive(&mut self, user: &str, responses: Vec<String>) -> AuthDecision {
            if !self.kbd_interactive_enabled {
                return AuthDecision::Reject;
            }
            // The response strings come from `UserauthInfoResponse`, whose Drop
            // zeroizes its buffer; we copy the first answer into a zeroizing
            // buffer and let `responses` drop normally.
            let pw = responses
                .first()
                .map(|s| zeroize::Zeroizing::new(s.as_bytes().to_vec()))
                .unwrap_or_default();
            self.verify_password(user, "keyboard-interactive", pw)
        }

        fn on_user_resolved(&mut self, user: &str, methods: &[String]) {
            // Bind the username on first sight (the publickey/password arms also
            // bind, but this fires first via the server's re-resolve hook).
            let _ = self.check_user_binding(user);
            self.chains = parse_auth_method_chains(methods);
            if self.debug && !self.chains.is_empty() {
                eprintln!(
                    "sshd: auth: multi-factor chains for {user}: {:?}",
                    self.chains
                );
            }
        }
    }

    /// The single keyboard-interactive prompt set: one non-echoed
    /// `"Password: "` prompt.
    fn alloc_prompts() -> Vec<(String, bool)> {
        vec![("Password: ".to_string(), false)]
    }

    /// Map a resolved `AuthenticationMethods` value (space-separated
    /// alternatives, each a comma-chain) into the internal chain set. Each
    /// factor is interned to a `&'static str` the rest of the machine compares
    /// by identity; `any` collapses to "no constraint" (an empty chain set, i.e.
    /// single-factor), and unknown tokens are dropped (the config parser already
    /// rejected genuinely-unknown ones, so this is defensive).
    fn parse_auth_method_chains(methods: &[String]) -> Vec<Vec<&'static str>> {
        let mut chains: Vec<Vec<&'static str>> = Vec::new();
        for alt in methods {
            if alt == "any" {
                // `any` means single-factor — clear any accumulated constraint
                // and stop (an empty chain set is the single-factor signal).
                return Vec::new();
            }
            let mut chain: Vec<&'static str> = Vec::new();
            for factor in alt.split(',').filter(|s| !s.is_empty()) {
                match factor {
                    "publickey" => chain.push("publickey"),
                    "password" => chain.push("password"),
                    "keyboard-interactive" => chain.push("keyboard-interactive"),
                    "none" => {} // never counts toward a chain
                    _ => {}      // unknown: defensively ignore
                }
            }
            if !chain.is_empty() {
                chains.push(chain);
            }
        }
        chains
    }

    #[derive(Clone)]
    struct LocalAuthFactory {
        allow_users: Arc<Vec<UserHostPattern>>,
        deny_users: Arc<Vec<UserHostPattern>>,
        allow_groups: Arc<Vec<puressh::config::HostPattern>>,
        deny_groups: Arc<Vec<puressh::config::HostPattern>>,
        authorized_blobs: Arc<Vec<Vec<u8>>>,
        permit_root_login: puressh::config::PermitRootLogin,
        group_lookup: GroupLookup,
        /// Shared PAM gate for password verification (see `LocalAuthenticator`).
        pam: Arc<pam_gate::PamGate>,
        password_enabled: bool,
        kbd_interactive_enabled: bool,
        permit_empty_passwords: bool,
        debug: bool,
    }

    impl LocalAuthFactory {
        fn build_inner(&self, peer: Option<&str>) -> Box<dyn Authenticator> {
            Box::new(LocalAuthenticator {
                allow_users: (*self.allow_users).clone(),
                deny_users: (*self.deny_users).clone(),
                allow_groups: (*self.allow_groups).clone(),
                deny_groups: (*self.deny_groups).clone(),
                authorized_blobs: (*self.authorized_blobs).clone(),
                permit_root_login: self.permit_root_login,
                pam: self.pam.clone(),
                password_enabled: self.password_enabled,
                kbd_interactive_enabled: self.kbd_interactive_enabled,
                permit_empty_passwords: self.permit_empty_passwords,
                chains: Vec::new(),
                satisfied: Vec::new(),
                bound_user: None,
                root_uid0_cache: std::collections::HashMap::new(),
                group_cache: std::collections::HashMap::new(),
                group_lookup: self.group_lookup.clone(),
                peer: peer.map(str::to_string),
                debug: self.debug,
            })
        }
    }

    impl AuthenticatorFactory for LocalAuthFactory {
        fn build(&self) -> Box<dyn Authenticator> {
            self.build_inner(None)
        }

        fn build_with_peer(&self, peer: Option<&str>) -> Box<dyn Authenticator> {
            self.build_inner(peer)
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
        if rc == 0 { Ok(()) } else { Err(Errno::last()) }
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
        if rc == 0 { Ok(()) } else { Err(Errno::last()) }
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

    /// Whether `name` resolves to the root account (uid 0) in the passwd
    /// database *right now*. The literal name `root` always counts (so the
    /// policy holds even if the passwd lookup transiently fails); any other
    /// name is root only if it currently maps to uid 0 — this catches
    /// uid-0 aliases like `toor`. Resolved at login time, never cached
    /// across connections, so it can't go stale against the daemon's
    /// lifetime.
    fn resolves_to_root(name: &str) -> bool {
        name == "root"
            || matches!(
                nix::unistd::User::from_name(name),
                Ok(Some(u)) if u.uid.as_raw() == 0
            )
    }

    /// Resolve `name`'s supplementary group names via `getgrouplist(3)` plus
    /// its primary group, for `Match group` / `AllowGroups` / `DenyGroups`.
    /// Returns an empty vec for an unknown user or on any lookup failure —
    /// resolved uniformly at login time (mirrors [`resolves_to_root`]) so the
    /// call cannot become a user-enumeration timing oracle.
    /// Platform-portable group-gid list for `name` with primary `gid`.
    /// Uses `getgrouplist(3)` where nix exposes it; elsewhere falls back to
    /// the primary group only.
    #[cfg(not(any(
        target_os = "macos",
        target_os = "ios",
        target_os = "aix",
        target_os = "illumos",
        target_os = "solaris",
        target_os = "redox",
    )))]
    fn group_gids(name: &str, primary: nix::unistd::Gid) -> Vec<nix::unistd::Gid> {
        let cname = match std::ffi::CString::new(name) {
            Ok(c) => c,
            Err(_) => return vec![primary],
        };
        nix::unistd::getgrouplist(&cname, primary).unwrap_or_else(|_| vec![primary])
    }

    #[cfg(any(
        target_os = "macos",
        target_os = "ios",
        target_os = "aix",
        target_os = "illumos",
        target_os = "solaris",
        target_os = "redox",
    ))]
    fn group_gids(_name: &str, primary: nix::unistd::Gid) -> Vec<nix::unistd::Gid> {
        vec![primary]
    }

    fn lookup_user_groups(name: &str) -> Vec<String> {
        use nix::unistd::{Gid, Group, User};
        let Ok(Some(user)) = User::from_name(name) else {
            return Vec::new();
        };
        // getgrouplist returns the user's group gids (primary + supplementary)
        // on platforms that expose it; fall back to just the primary group if
        // it fails or is unavailable (macOS / Solaris / AIX don't have it in
        // nix). The primary group still feeds AllowGroups/DenyGroups there.
        let gids: Vec<Gid> = group_gids(name, user.gid);
        let mut names: Vec<String> = Vec::new();
        for gid in gids {
            if let Ok(Some(g)) = Group::from_gid(gid)
                && !names.contains(&g.name)
            {
                names.push(g.name);
            }
        }
        names
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
        /// Per-connection `PrintMotd`, written by `on_session_open` and read at
        /// shell spawn. Shared via `Arc` so the (COW-isolated, per-fork) child
        /// sees the value the hook resolved for this connection. Only the PTY
        /// path consults it — `/etc/motd` is for interactive logins.
        print_motd: Arc<std::sync::atomic::AtomicBool>,
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
                Some(spec) => {
                    let print_motd = self.print_motd.load(std::sync::atomic::Ordering::Relaxed);
                    spawn_pty_shell(&self.pam, user, &env_pairs, &spec, self.debug, print_motd)
                }
                None => spawn_pipe_shell(&self.pam, user, &env_pairs, self.debug),
            }
        }
    }

    /// Read `/etc/motd` and return its bytes with bare `\n` line endings
    /// rewritten to `\r\n` so the message displays correctly on the raw PTY
    /// (a terminal in raw mode does not translate `\n`). Returns `None` (and,
    /// in debug, warns) if the file is missing or unreadable — a missing motd
    /// is normal and must never block the shell.
    fn read_motd_for_pty(debug: bool) -> Option<Vec<u8>> {
        match std::fs::read("/etc/motd") {
            Ok(bytes) => Some(crlf_for_pty(&bytes)),
            Err(e) => {
                if debug {
                    eprintln!("sshd: PrintMotd: cannot read /etc/motd: {e}");
                }
                None
            }
        }
    }

    /// Rewrite bare `\n` to `\r\n` for display on a raw-mode PTY. An existing
    /// `\r\n` is left intact (the `\r` is copied, then the `\n` does not get a
    /// second `\r` prepended because the byte before it was already `\r`).
    fn crlf_for_pty(bytes: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(bytes.len() + 16);
        let mut prev = 0u8;
        for &b in bytes {
            if b == b'\n' && prev != b'\r' {
                out.push(b'\r');
            }
            out.push(b);
            prev = b;
        }
        out
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

    /// Expand the OpenSSH `%h` (home) / `%u` (user) / `%%` tokens in a
    /// `ChrootDirectory` template against the target user's passwd entry.
    /// Unknown `%X` sequences are rejected so a typo can't silently produce a
    /// surprising path.
    fn expand_chroot_tokens(template: &str, info: &UserInfo) -> Result<String, String> {
        let mut out = String::with_capacity(template.len());
        let mut chars = template.chars();
        while let Some(c) = chars.next() {
            if c != '%' {
                out.push(c);
                continue;
            }
            match chars.next() {
                Some('h') => out.push_str(&info.home_str),
                Some('u') => out.push_str(&info.name),
                Some('%') => out.push('%'),
                Some(other) => {
                    return Err(format!("unknown ChrootDirectory token %{other}"));
                }
                None => return Err("trailing % in ChrootDirectory".to_string()),
            }
        }
        Ok(out)
    }

    /// StrictModes-style validation of a resolved `ChrootDirectory`: the
    /// directory and every parent component up to `/` must be owned by root
    /// (uid 0) and not group- or world-writable, exactly as OpenSSH requires
    /// (`safely_chroot`). Returns the resolved path on success.
    fn validate_chroot_dir(path: &str) -> Result<(), String> {
        use std::os::unix::fs::MetadataExt;
        let md =
            std::fs::metadata(path).map_err(|e| format!("stat ChrootDirectory {path}: {e}"))?;
        if !md.is_dir() {
            return Err(format!("ChrootDirectory {path}: not a directory"));
        }
        // Walk this component and every ancestor; each must be root-owned and
        // not group/world-writable. OpenSSH refuses a chroot whose path is
        // writable by anyone but root, since a writable parent lets a
        // non-root user swap the target out from under the daemon.
        let mut cur: Option<&std::path::Path> = Some(std::path::Path::new(path));
        while let Some(p) = cur {
            let md = std::fs::metadata(p).map_err(|e| format!("stat {}: {e}", p.display()))?;
            if md.uid() != 0 {
                return Err(format!(
                    "ChrootDirectory component {} must be owned by root (uid 0), is uid {}",
                    p.display(),
                    md.uid()
                ));
            }
            if md.mode() & 0o022 != 0 {
                return Err(format!(
                    "ChrootDirectory component {} is group/world-writable (mode 0o{:o})",
                    p.display(),
                    md.mode() & 0o777
                ));
            }
            cur = p.parent();
        }
        Ok(())
    }

    /// Resolve, validate, and `chroot()` into `template` for `user`, then
    /// `chdir("/")` inside the new root. Must run **while still root**, before
    /// any `setuid` — `chroot(2)` requires `CAP_SYS_CHROOT`. Called from
    /// `Config::on_session_open` ahead of [`drop_to_user`].
    fn apply_chroot(user: &str, template: &str, debug: bool) -> puressh::Result<()> {
        let info = lookup_user(user)?;
        let resolved = expand_chroot_tokens(template, &info).map_err(|e| {
            puressh::Error::Io(std::io::Error::new(std::io::ErrorKind::InvalidInput, e))
        })?;
        validate_chroot_dir(&resolved).map_err(|e| {
            puressh::Error::Io(std::io::Error::new(std::io::ErrorKind::PermissionDenied, e))
        })?;
        nix::unistd::chroot(resolved.as_str()).map_err(nix_io)?;
        nix::unistd::chdir("/").map_err(nix_io)?;
        if debug {
            eprintln!("sshd: chrooted {user} into {resolved}");
        }
        Ok(())
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

    /// Empty the process environment in the post-fork child, before the
    /// PAM / login / channel vars are layered back on. POSIX has no portable
    /// `clearenv()`: glibc/Linux provides it, but macOS and the BSDs do not,
    /// so on those we point libc's `environ` at an empty, NUL-terminated list
    /// (a single pointer write — async-signal-safe in the fork→exec window).
    /// A subsequent `setenv()` allocates a fresh environ from there.
    ///
    /// # Safety
    /// Must run in the single-threaded post-fork child only.
    unsafe fn clear_environ() {
        unsafe {
            #[cfg(target_os = "linux")]
            {
                libc::clearenv();
            }
            #[cfg(not(target_os = "linux"))]
            {
                // A 'static, never-mutated empty environ (just the terminator).
                // Raw pointers aren't `Sync`, so wrap the array in a newtype we
                // assert `Sync` for — sound because it is read-only.
                struct EnvironList([*const libc::c_char; 1]);
                unsafe impl Sync for EnvironList {}
                static EMPTY: EnvironList = EnvironList([core::ptr::null()]);
                let empty = EMPTY.0.as_ptr() as *mut *mut libc::c_char;
                #[cfg(target_os = "macos")]
                {
                    *libc::_NSGetEnviron() = empty;
                }
                #[cfg(not(target_os = "macos"))]
                {
                    unsafe extern "C" {
                        static mut environ: *mut *mut libc::c_char;
                    }
                    core::ptr::write(core::ptr::addr_of_mut!(environ), empty);
                }
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
        session_env: &[(String, String)],
        spec: &PtySpec,
        debug: bool,
        print_motd: bool,
    ) -> puressh::Result<Box<dyn ShellSession>> {
        // PrintMotd: read /etc/motd in the parent (we may already be inside the
        // ChrootDirectory and dropped to the user — the file is read from the
        // session's view of the filesystem). The bytes are written to the
        // slave pty in the child just before exec so they land on the terminal
        // ahead of the shell prompt. Default is off, so this is skipped unless
        // PrintMotd=yes — which avoids double-printing when PAM's pam_motd is
        // already configured.
        let motd: Option<Vec<u8>> = if print_motd {
            read_motd_for_pty(debug)
        } else {
            None
        };

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
                // Mirrors the exec path's `cmd.env_clear()`. Runs in the
                // single-threaded post-fork child and only resets the environ
                // pointer — no allocation — so it is safe in the fork→exec
                // window.
                // SAFETY: single-threaded post-fork child; clear_environ just
                // empties the process environment.
                unsafe {
                    clear_environ();
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

                // PrintMotd: write /etc/motd to the terminal (fd 1 is the
                // slave pty after the dup2 above) before handing control to the
                // shell. `write(2)` is async-signal-safe; the byte buffer was
                // read in the parent. Best-effort — a short write or error must
                // not block the login.
                if let Some(bytes) = &motd {
                    // SAFETY: fd 1 is the slave pty; `bytes` is an owned, live
                    // buffer. write() is async-signal-safe in the post-fork
                    // child. Ignore the result (best-effort motd).
                    unsafe {
                        let _ = libc::write(1, bytes.as_ptr() as *const libc::c_void, bytes.len());
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
            if let Ok(mut m) = per_ip_counts().lock()
                && let Some(c) = m.get_mut(&self.ip)
            {
                *c = c.saturating_sub(1);
                if *c == 0 {
                    m.remove(&self.ip);
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

        // LogLevel (sshd_config): VERBOSE/DEBUG* (level >= 1) turns on the same
        // verbose diagnostics as `-d`, so the config keyword actually controls
        // output. `-d` always wins (it can't be turned back off). Rebind `cli`
        // so every downstream `cli.debug` reflects the effective level.
        let log_level = sshd_cfg.global.log_level.unwrap_or(0);
        let cli = {
            let mut c = cli;
            c.debug = c.debug || log_level >= 1;
            c
        };

        // Resolve effective values: CLI > config > built-in default.
        let port = pick(cli.port, sshd_cfg.global.port, 2222u16);
        let strict_modes = pick(cli.strict_modes, sshd_cfg.global.strict_modes, true);
        // SFTP is on when either the puressh `SftpEnabled` knob OR the standard
        // `Subsystem sftp internal-sftp` line enables it (CLI still wins).
        let sftp_enabled = pick(
            cli.sftp,
            sshd_cfg
                .global
                .sftp_enabled
                .or(sshd_cfg.global.subsystem_sftp),
            true,
        );
        let sftp_read_only = pick(cli.sftp_read_only, sshd_cfg.global.sftp_read_only, false);
        // SFTP virtual-root precedence: CLI `--sftp-root` > puressh `SftpRoot`.
        // This is an in-process path jail that needs no privilege. The standard
        // `ChrootDirectory` is no longer mapped here: it now drives a *real*
        // `chroot()` in `on_session_open` (see `apply_chroot`), which confines
        // shell / exec / SFTP uniformly — the in-process SFTP subsystem runs
        // after that hook, so it already operates inside the new root. (A real
        // chroot requires root, exactly as OpenSSH's `ChrootDirectory` does.)
        let sftp_root: Option<std::path::PathBuf> = cli
            .sftp_root
            .as_deref()
            .or(sshd_cfg.global.sftp_root.as_deref())
            .map(std::path::PathBuf::from);
        let scp_enabled = pick(cli.scp, sshd_cfg.global.scp_enabled, true);
        let agent_forward = pick(
            cli.agent_forward,
            sshd_cfg.global.allow_agent_forwarding,
            true,
        );
        let x11_forward = pick(cli.x11_forward, sshd_cfg.global.x11_forwarding, true);
        let login_grace_time = pick(
            cli.login_grace_time,
            sshd_cfg.global.login_grace_time,
            120u32,
        );
        let max_startups = pick(cli.max_startups, sshd_cfg.global.max_startups, 100u32);

        // CLI host-keys, then any HostKey lines from config (cumulative).
        let mut host_key_files = cli.host_key_files.clone();
        host_key_files.extend(sshd_cfg.global.host_key_files.iter().cloned());
        if host_key_files.is_empty() {
            return Err(
                "at least one -h host_key_file (or HostKey in sshd_config) is required".into(),
            );
        }

        let authorized_keys_file = cli
            .authorized_keys_file
            .clone()
            .or_else(|| sshd_cfg.global.authorized_keys_file.clone());

        // CLI `-u`, then `AllowUsers` from config (cumulative across blocks).
        let mut allowed_user_list = cli.allowed_users.clone();
        allowed_user_list.extend(sshd_cfg.global.allow_users.iter().cloned());

        // Likewise `--accept-env` ++ `AcceptEnv`.
        let mut accept_env = cli.accept_env.clone();
        accept_env.extend(sshd_cfg.global.accept_env.iter().cloned());

        // Pick the bind address. We support a single listener for v1; warn
        // if more than one ListenAddress / -b was supplied.
        let mut bind_specs = cli.listen_addresses.clone();
        bind_specs.extend(sshd_cfg.global.listen_addresses.iter().cloned());
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

        // AllowUsers is matched as OpenSSH `Host`-style globs (a literal name
        // is just a glob with no metacharacters). Empty ⇒ the historical
        // "current user only" default, seeded as a single literal pattern.
        let allow_user_tokens: Vec<String> = if allowed_user_list.is_empty() {
            vec![current_user()?]
        } else {
            allowed_user_list
        };
        let allow_users = UserHostPattern::parse_all(&allow_user_tokens);
        let deny_users = UserHostPattern::parse_all(&sshd_cfg.global.deny_users);
        let allow_groups = puressh::config::HostPattern::parse_all(&sshd_cfg.global.allow_groups);
        let deny_groups = puressh::config::HostPattern::parse_all(&sshd_cfg.global.deny_groups);
        let group_lookup: GroupLookup = Arc::new(lookup_user_groups);

        // PermitRootLogin: CLI > config > built-in `prohibit-password`
        // (OpenSSH's default; permits root-by-key since puressh has no
        // password auth). The root-account check itself happens at login
        // time — in the authenticator during userauth, plus a backstop in the
        // on_session_open gate — resolving the requested username against the
        // live passwd database rather than a daemon-startup snapshot.
        let permit_root_login = pick(
            cli.permit_root_login,
            sshd_cfg.global.permit_root_login,
            puressh::config::PermitRootLogin::ProhibitPassword,
        );
        if cli.debug {
            eprintln!("sshd: PermitRootLogin={permit_root_login:?}");
        }

        // One PamGate per accept-loop iteration's child. The parent
        // holds a clone too, but fork's COW gives each connection its
        // own copy — no cross-connection state bleed. The authenticator
        // borrows a clone for password verification.
        let pam_gate = pam_gate::PamGate::new(cli.debug);

        // Whether a real PAM backend is compiled in. Password and
        // keyboard-interactive auth are *only* advertised when both the config
        // enables them AND this is a PAM build — otherwise we'd offer a method
        // we cannot satisfy. `pam_check_password` on a non-PAM build always
        // fails, so this is the authoritative gate.
        let pam_available = cfg!(all(feature = "pam", target_os = "linux"));

        let cfg_password = sshd_cfg.global.password_authentication == Some(true);
        let cfg_kbdint = sshd_cfg.global.kbd_interactive_authentication == Some(true);
        let pubkey_enabled = sshd_cfg.global.pubkey_authentication != Some(false);
        let password_enabled = cfg_password && pam_available;
        let kbd_interactive_enabled = cfg_kbdint && pam_available;
        let permit_empty_passwords = sshd_cfg.global.permit_empty_passwords == Some(true);

        if (cfg_password || cfg_kbdint) && !pam_available {
            eprintln!(
                "sshd: warning: PasswordAuthentication/KbdInteractiveAuthentication requested but \
                 no PAM backend is compiled in (need the `pam` feature on Linux); these methods \
                 will NOT be advertised"
            );
        }

        // Compute the advertised method set from config: start with publickey
        // (unless disabled), add password / keyboard-interactive when enabled
        // and backed by PAM.
        let mut advertised: Vec<&'static str> = Vec::new();
        if pubkey_enabled {
            advertised.push("publickey");
        }
        if password_enabled {
            advertised.push("password");
        }
        if kbd_interactive_enabled {
            advertised.push("keyboard-interactive");
        }
        if cli.debug {
            eprintln!("sshd: advertised auth methods: {advertised:?}");
        }

        // Connection-wide AuthenticationMethods default (multi-factor chains),
        // threaded into the authenticator via on_user_resolved.
        let default_auth_methods = sshd_cfg
            .global
            .authentication_methods
            .clone()
            .unwrap_or_default();

        let factory = Arc::new(LocalAuthFactory {
            allow_users: Arc::new(allow_users),
            deny_users: Arc::new(deny_users),
            allow_groups: Arc::new(allow_groups),
            deny_groups: Arc::new(deny_groups),
            authorized_blobs: Arc::new(authorized_blobs),
            permit_root_login,
            group_lookup: group_lookup.clone(),
            pam: pam_gate.clone(),
            password_enabled,
            kbd_interactive_enabled,
            permit_empty_passwords,
            debug: cli.debug,
        });

        // Per-connection `PrintMotd`, resolved by `on_session_open` and read by
        // the PTY shell handler. Shared by `Arc` so the (COW-isolated) forked
        // child sees the value the hook wrote for *this* connection.
        let print_motd_flag = Arc::new(std::sync::atomic::AtomicBool::new(false));

        let mut config = Config::new(
            host_keys,
            factory,
            advertised,
            Arc::new(ShellCommandHandler {
                pam: pam_gate.clone(),
                debug: cli.debug,
                debug_commands: cli.debug_commands,
            }),
        )
        .with_auth_methods(default_auth_methods)
        .with_shell(Arc::new(NixShellHandler {
            pam: pam_gate.clone(),
            debug: cli.debug,
            print_motd: print_motd_flag.clone(),
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
        let session_print_motd = print_motd_flag.clone();
        config = config.on_session_open(move |ctx: &SessionOpenContext<'_>| {
            let user = ctx.user;
            // PermitRootLogin backstop, evaluated at login time before we
            // open a PAM session or drop privilege. The authenticator already
            // denies root during userauth; this re-checks against the live
            // passwd database so a uid-0 login cannot proceed even if it
            // reached session-open by some other path. Resolved here (not at
            // startup) so it reflects the current database.
            if resolves_to_root(user) && !permit_root_login.permits_publickey() {
                if debug {
                    eprintln!(
                        "sshd: refusing session for root user {user}: PermitRootLogin forbids it"
                    );
                }
                return Err(puressh::Error::Io(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "root login not permitted",
                )));
            }
            // Stash the resolved PrintMotd for this connection so the PTY shell
            // handler (which runs later, in a COW-isolated forked child) can
            // read it. Default-off; only printed when PrintMotd=yes — which
            // avoids double-printing alongside PAM's pam_motd.
            session_print_motd.store(ctx.print_motd, std::sync::atomic::Ordering::Relaxed);
            // PAM_TTY = "ssh" matches OpenSSH's value for the session-level
            // gate; PTY shells later re-call ensure() (a no-op) for env.
            session_pam.ensure(user, "ssh")?;
            // ChrootDirectory: chroot() while we still hold root, *before*
            // drop_to_user's setuid (chroot(2) needs CAP_SYS_CHROOT). This
            // confines shell / exec / SFTP alike — the SFTP subsystem runs
            // in-process after this hook, so it inherits the new root too.
            // The path is validated StrictModes-style (root-owned, not
            // group/world-writable) before the chroot.
            if let Some(dir) = ctx.chroot_directory {
                apply_chroot(user, dir, debug)?;
            }
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

        // Crypto-algorithm overrides from sshd_config (already strict-validated
        // by the config parser). HostKeyAlgorithms is used as a preference
        // order and intersected with the loaded host keys; the strict-kex
        // markers are re-appended by the server regardless of KexAlgorithms.
        config = config.with_algorithms(
            sshd_cfg.global.ciphers.clone(),
            sshd_cfg.global.macs.clone(),
            sshd_cfg.global.kex_algorithms.clone(),
            sshd_cfg.global.host_key_algorithms.clone(),
        );

        // RekeyLimit (startup-only): map the parsed thresholds onto the
        // server's RekeyPolicy. `default`/unset bytes keep the built-in cap;
        // an explicit time threshold replaces the duration. (No-op on builds
        // without the `std` feature, where max_duration does not exist.)
        if let Some(rk) = sshd_cfg.global.rekey_limit {
            let mut policy = config.rekey_policy;
            if let Some(b) = rk.max_bytes {
                policy.max_bytes = b;
            }
            #[cfg(feature = "std")]
            if let Some(secs) = rk.max_seconds {
                policy.max_duration = std::time::Duration::from_secs(secs as u64);
            }
            config.rekey_policy = policy;
        }

        // Compression (startup-only): `no` strips zlib from the KEXINIT advert.
        config.compression = sshd_cfg.global.compression;

        // AddressFamily (startup-only): restrict the listener family.
        let address_family = sshd_cfg.global.address_family;
        // PidFile (startup-only): write our PID after bind unless `none`.
        let pid_file = if sshd_cfg.global.pid_file_set {
            sshd_cfg.global.pid_file.clone()
        } else {
            None
        };

        // Per-connection policy: the whole parsed sshd_config (global + Match
        // blocks) is resolved twice per connection (pre-auth address-only,
        // post-auth user/groups) to gate the auth method set, banner, and
        // forwarding capabilities. The group resolver feeds `Match group`.
        config = config
            .with_policy(Arc::new(sshd_cfg))
            .with_group_resolver(group_lookup);

        let cfg = Arc::new(config);

        install_parent_signals()?;

        let addr = bind_addr;
        // AddressFamily filter: refuse to bind an address of the wrong family
        // rather than silently ignoring the directive.
        if let Some(af) = address_family {
            let parsed: Option<std::net::IpAddr> = addr
                .rsplit_once(':')
                .and_then(|(h, _)| h.trim_matches(['[', ']']).parse().ok());
            let mismatch = match (af, parsed) {
                (puressh::config::ServerAddressFamily::Inet, Some(ip)) => ip.is_ipv6(),
                (puressh::config::ServerAddressFamily::Inet6, Some(ip)) => ip.is_ipv4(),
                _ => false,
            };
            if mismatch {
                return Err(format!(
                    "bind {addr}: AddressFamily {af:?} excludes this listener address"
                ));
            }
        }
        let listener =
            std::net::TcpListener::bind(&addr).map_err(|e| format!("bind {addr}: {e}"))?;

        // PidFile: write our PID now that the listener is up.
        if let Some(path) = pid_file.as_deref()
            && let Err(e) = std::fs::write(path, format!("{}\n", std::process::id()))
        {
            eprintln!("sshd: warning: could not write PidFile {path}: {e}");
        }

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

                    let rc = match handle_session_with_peer(stream, peer, cfg.clone()) {
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

    #[cfg(test)]
    mod tests {
        use super::*;
        use puressh::config::HostPattern;

        /// Build a `LocalAuthenticator` with a mock group resolver for access
        /// precedence tests. `groups` maps user→group-names.
        fn auth_with(
            allow_users: &[&str],
            deny_users: &[&str],
            allow_groups: &[&str],
            deny_groups: &[&str],
            groups: std::collections::HashMap<String, Vec<String>>,
        ) -> LocalAuthenticator {
            auth_with_peer(
                allow_users,
                deny_users,
                allow_groups,
                deny_groups,
                groups,
                None,
            )
        }

        /// Like [`auth_with`] but pins the connection's resolved peer address,
        /// so `AllowUsers`/`DenyUsers` `user@host` tokens can be exercised.
        fn auth_with_peer(
            allow_users: &[&str],
            deny_users: &[&str],
            allow_groups: &[&str],
            deny_groups: &[&str],
            groups: std::collections::HashMap<String, Vec<String>>,
            peer: Option<&str>,
        ) -> LocalAuthenticator {
            let to_uh = |xs: &[&str]| {
                UserHostPattern::parse_all(&xs.iter().map(|s| s.to_string()).collect::<Vec<_>>())
            };
            let to_pats = |xs: &[&str]| {
                HostPattern::parse_all(&xs.iter().map(|s| s.to_string()).collect::<Vec<_>>())
            };
            let groups = std::sync::Arc::new(groups);
            let lookup: GroupLookup =
                std::sync::Arc::new(move |u: &str| groups.get(u).cloned().unwrap_or_default());
            LocalAuthenticator {
                allow_users: to_uh(allow_users),
                deny_users: to_uh(deny_users),
                allow_groups: to_pats(allow_groups),
                deny_groups: to_pats(deny_groups),
                authorized_blobs: Vec::new(),
                permit_root_login: puressh::config::PermitRootLogin::ProhibitPassword,
                pam: pam_gate::PamGate::new(false),
                password_enabled: false,
                kbd_interactive_enabled: false,
                permit_empty_passwords: false,
                chains: Vec::new(),
                satisfied: Vec::new(),
                bound_user: None,
                root_uid0_cache: std::collections::HashMap::new(),
                group_cache: std::collections::HashMap::new(),
                group_lookup: lookup,
                peer: peer.map(str::to_string),
                debug: false,
            }
        }

        #[test]
        fn deny_users_wins_over_allow_users() {
            let mut a = auth_with(&["alice", "bob"], &["bob"], &[], &[], Default::default());
            assert!(a.access_allowed("alice"));
            // bob is allowed *and* denied — DenyUsers has higher precedence.
            assert!(!a.access_allowed("bob"));
        }

        // ---- FD: password / multi-factor helpers ---------------------------

        #[test]
        fn empty_password_policy() {
            // Non-empty password is always allowed to proceed.
            assert!(LocalAuthenticator::empty_password_allowed(false, b"secret"));
            assert!(LocalAuthenticator::empty_password_allowed(true, b"secret"));
            // Empty password: refused unless PermitEmptyPasswords.
            assert!(!LocalAuthenticator::empty_password_allowed(false, b""));
            assert!(LocalAuthenticator::empty_password_allowed(true, b""));
        }

        #[test]
        fn parse_chains_any_is_single_factor() {
            assert!(parse_auth_method_chains(&["any".to_string()]).is_empty());
            assert!(parse_auth_method_chains(&[]).is_empty());
        }

        #[test]
        fn parse_chains_maps_factors() {
            let chains = parse_auth_method_chains(&["publickey,password".to_string()]);
            assert_eq!(chains, vec![vec!["publickey", "password"]]);
            // `none` never counts toward a chain.
            let chains2 = parse_auth_method_chains(&["publickey,none".to_string()]);
            assert_eq!(chains2, vec![vec!["publickey"]]);
            // Multiple alternatives.
            let chains3 = parse_auth_method_chains(&[
                "publickey,password".to_string(),
                "keyboard-interactive".to_string(),
            ]);
            assert_eq!(
                chains3,
                vec![vec!["publickey", "password"], vec!["keyboard-interactive"]]
            );
        }

        #[test]
        fn record_and_decide_single_factor_accepts_immediately() {
            let mut a = auth_with(&["*"], &[], &[], &[], Default::default());
            // No chains installed ⇒ single-factor: one success accepts.
            assert!(matches!(
                a.record_and_decide("publickey"),
                AuthDecision::Accept
            ));
        }

        #[test]
        fn record_and_decide_multifactor_partial_then_accept() {
            let mut a = auth_with(&["*"], &[], &[], &[], Default::default());
            a.chains = vec![vec!["publickey", "password"]];
            // First factor ⇒ PartialAccept asking for the remaining one.
            match a.record_and_decide("publickey") {
                AuthDecision::PartialAccept { still_required } => {
                    assert_eq!(still_required, vec!["password".to_string()]);
                }
                other => panic!("expected PartialAccept, got {other:?}"),
            }
            // Second factor completes the chain ⇒ Accept.
            assert!(matches!(
                a.record_and_decide("password"),
                AuthDecision::Accept
            ));
        }

        #[test]
        fn record_and_decide_order_independent() {
            // Set-membership: satisfying the chain in reverse order still
            // accepts (documented deviation from OpenSSH's ordered enforcement).
            let mut a = auth_with(&["*"], &[], &[], &[], Default::default());
            a.chains = vec![vec!["publickey", "password"]];
            assert!(matches!(
                a.record_and_decide("password"),
                AuthDecision::PartialAccept { .. }
            ));
            assert!(matches!(
                a.record_and_decide("publickey"),
                AuthDecision::Accept
            ));
        }

        #[test]
        fn user_binding_rejects_username_switch() {
            let mut a = auth_with(&["*"], &[], &[], &[], Default::default());
            assert!(a.check_user_binding("alice"));
            assert!(a.check_user_binding("alice")); // same user OK
            assert!(!a.check_user_binding("bob")); // switch rejected
        }

        #[test]
        fn allow_users_glob() {
            let mut a = auth_with(&["dev-*"], &[], &[], &[], Default::default());
            assert!(a.access_allowed("dev-1"));
            assert!(!a.access_allowed("prod-1"));
        }

        #[test]
        fn allow_groups_requires_membership() {
            let mut groups = std::collections::HashMap::new();
            groups.insert("alice".to_string(), vec!["wheel".to_string()]);
            groups.insert("bob".to_string(), vec!["users".to_string()]);
            let mut a = auth_with(&["*"], &[], &["wheel"], &[], groups);
            assert!(a.access_allowed("alice")); // in wheel
            assert!(!a.access_allowed("bob")); // not in wheel
        }

        #[test]
        fn deny_groups_precedes_allow_groups() {
            let mut groups = std::collections::HashMap::new();
            groups.insert(
                "eve".to_string(),
                vec!["wheel".to_string(), "banned".to_string()],
            );
            let mut a = auth_with(&["*"], &[], &["wheel"], &["banned"], groups);
            // eve is in wheel (allowed) but also banned (denied) — DenyGroups
            // is evaluated before AllowGroups, so she is refused.
            assert!(!a.access_allowed("eve"));
        }

        // ---- F8: AllowUsers/DenyUsers user@host -----------------------------

        #[test]
        fn allow_users_at_host_matches_peer() {
            // alice@10.0.0.0/8-ish glob: only from 10.* hosts.
            let mut a = auth_with_peer(
                &["alice@10.*"],
                &[],
                &[],
                &[],
                Default::default(),
                Some("10.1.2.3"),
            );
            assert!(a.access_allowed("alice"));
            // Wrong user.
            assert!(!a.access_allowed("bob"));

            // Same rule, peer outside the host glob ⇒ denied.
            let mut b = auth_with_peer(
                &["alice@10.*"],
                &[],
                &[],
                &[],
                Default::default(),
                Some("192.168.0.1"),
            );
            assert!(!b.access_allowed("alice"));

            // A user@host rule with no known peer never matches.
            let mut c = auth_with_peer(&["alice@10.*"], &[], &[], &[], Default::default(), None);
            assert!(!c.access_allowed("alice"));
        }

        #[test]
        fn allow_users_mixed_bare_and_at_host() {
            // bob matches by bare username from any host; alice only from 10.*.
            let mut a = auth_with_peer(
                &["bob", "alice@10.*"],
                &[],
                &[],
                &[],
                Default::default(),
                Some("203.0.113.9"),
            );
            assert!(a.access_allowed("bob")); // bare token, host-independent
            assert!(!a.access_allowed("alice")); // alice only from 10.*
        }

        #[test]
        fn deny_users_at_host_blocks_by_peer() {
            // eve is allowed by the wildcard, but denied specifically from the
            // evil host range.
            let mut a = auth_with_peer(
                &["*"],
                &["eve@10.6.6.*"],
                &[],
                &[],
                Default::default(),
                Some("10.6.6.66"),
            );
            assert!(!a.access_allowed("eve"));
            // Same eve from a different host is fine.
            let mut b = auth_with_peer(
                &["*"],
                &["eve@10.6.6.*"],
                &[],
                &[],
                Default::default(),
                Some("10.0.0.1"),
            );
            assert!(b.access_allowed("eve"));
        }

        #[test]
        fn user_host_pattern_parse() {
            let p = UserHostPattern::parse("alice@1.2.3.4");
            assert!(!p.negated);
            assert!(p.positive_match("alice", Some("1.2.3.4")));
            assert!(!p.positive_match("alice", Some("1.2.3.5")));
            assert!(!p.positive_match("bob", Some("1.2.3.4")));

            let neg = UserHostPattern::parse("!alice@1.2.3.4");
            assert!(neg.negated);
            assert!(neg.positive_match("alice", Some("1.2.3.4")));

            let bare = UserHostPattern::parse("dev-*");
            assert!(bare.host.is_none());
            assert!(bare.positive_match("dev-1", None));
        }

        // ---- F7: ChrootDirectory path resolution + ownership check ----------

        #[test]
        fn chroot_token_expansion() {
            let info = lookup_user_for_test();
            let out = expand_chroot_tokens("/chroots/%u", &info).expect("expand");
            assert_eq!(out, format!("/chroots/{}", info.name));
            let out2 = expand_chroot_tokens("%h/jail", &info).expect("expand");
            assert_eq!(out2, format!("{}/jail", info.home_str));
            assert_eq!(
                expand_chroot_tokens("100%%", &info).expect("expand"),
                "100%"
            );
            // Unknown token rejected.
            assert!(expand_chroot_tokens("%z", &info).is_err());
            assert!(expand_chroot_tokens("trailing%", &info).is_err());
        }

        /// Resolve a real user for token-expansion tests: prefer $USER, fall
        /// back to root (always present).
        fn lookup_user_for_test() -> UserInfo {
            std::env::var("USER")
                .ok()
                .filter(|n| !n.is_empty())
                .and_then(|n| lookup_user(&n).ok())
                .or_else(|| lookup_user("root").ok())
                .expect("a resolvable test user")
        }

        #[test]
        fn chroot_validation_rejects_non_root_owned() {
            // A temp dir created by the (non-root) test process is owned by the
            // test user, not root ⇒ the StrictModes-style check must refuse it.
            // Skip when the suite happens to run as root (the dir would then be
            // root-owned and pass the ownership half).
            if nix::unistd::geteuid().is_root() {
                return;
            }
            let dir = std::env::temp_dir().join(format!("puressh-chroot-{}", std::process::id()));
            let _ = std::fs::create_dir(&dir);
            let res = validate_chroot_dir(dir.to_str().unwrap());
            assert!(
                res.is_err(),
                "a non-root-owned chroot dir must be rejected: {res:?}"
            );
            let _ = std::fs::remove_dir(&dir);
        }

        #[test]
        fn chroot_validation_root_passes_ownership_but_checks_writability() {
            // `/` is root-owned and not group/world-writable on a sane system,
            // so the validator accepts it. (This documents the happy path
            // without needing root to create a fixture.)
            // Only assert when `/` actually has secure modes (it does on
            // standard installs); otherwise skip to avoid CI flakiness.
            use std::os::unix::fs::MetadataExt;
            if let Ok(md) = std::fs::metadata("/")
                && md.uid() == 0
                && md.mode() & 0o022 == 0
            {
                assert!(validate_chroot_dir("/").is_ok());
            }
        }

        /// End-to-end chroot confinement. Requires root (chroot(2) needs
        /// CAP_SYS_CHROOT) and is therefore `#[ignore]`d by default; run with
        /// `sudo cargo test --bin sshd -- --ignored chroot_confines`.
        ///
        /// Builds a root-owned jail containing a single marker file, forks,
        /// `apply_chroot`s in the child, and asserts that (a) the marker is now
        /// reachable at `/marker` and (b) a host-only path outside the jail is
        /// no longer reachable — i.e. the process is genuinely confined.
        #[test]
        #[ignore = "needs root: chroot(2) requires CAP_SYS_CHROOT"]
        fn chroot_confines_filesystem() {
            use std::io::Write;
            use std::os::unix::fs::PermissionsExt;

            assert!(
                nix::unistd::geteuid().is_root(),
                "this #[ignore] test must run as root"
            );

            let jail = std::env::temp_dir().join(format!("puressh-jail-{}", std::process::id()));
            std::fs::create_dir_all(&jail).expect("mkdir jail");
            // Root-owned (we are root) and 0755 — passes the StrictModes check.
            std::fs::set_permissions(&jail, std::fs::Permissions::from_mode(0o755))
                .expect("chmod jail");
            {
                let mut f = std::fs::File::create(jail.join("marker")).expect("marker");
                f.write_all(b"inside").expect("write marker");
            }

            // A sentinel that exists on the host but NOT inside the jail.
            let host_only =
                std::env::temp_dir().join(format!("puressh-host-only-{}", std::process::id()));
            std::fs::File::create(&host_only).expect("host-only");

            // Fork so the chroot does not poison the rest of the test process.
            // SAFETY: single-threaded test child; only does fs reads + _exit.
            match unsafe { fork() }.expect("fork") {
                ForkResult::Child => {
                    let ok = apply_chroot("root", jail.to_str().unwrap(), false).is_ok()
                        && std::fs::read("/marker")
                            .map(|b| b == b"inside")
                            .unwrap_or(false)
                        && !std::path::Path::new(host_only.to_str().unwrap()).exists();
                    unsafe { libc::_exit(if ok { 0 } else { 1 }) };
                }
                ForkResult::Parent { child } => {
                    let status = nix::sys::wait::waitpid(child, None).expect("waitpid");
                    let _ = std::fs::remove_file(&host_only);
                    let _ = std::fs::remove_dir_all(&jail);
                    assert!(
                        matches!(status, nix::sys::wait::WaitStatus::Exited(_, 0)),
                        "child reported chroot confinement failure: {status:?}"
                    );
                }
            }
        }

        // ---- F6: PrintMotd CRLF rewriting -----------------------------------

        #[test]
        fn motd_crlf_rewrite() {
            // Bare LF gets a CR; existing CRLF is preserved (no doubled CR).
            assert_eq!(crlf_for_pty(b"hello\nworld\n"), b"hello\r\nworld\r\n");
            assert_eq!(crlf_for_pty(b"a\r\nb"), b"a\r\nb");
            assert_eq!(crlf_for_pty(b"no newline"), b"no newline");
            assert_eq!(crlf_for_pty(b""), b"");
        }

        #[test]
        fn lookup_user_groups_includes_real_primary() {
            // The current test user always exists; its group list is non-empty
            // (at least the primary group resolves to a name on normal
            // systems). This guards the getgrouplist plumbing.
            if let Ok(name) = std::env::var("USER")
                && !name.is_empty()
            {
                let groups = lookup_user_groups(&name);
                // Not asserting exact contents (CI users vary); just that the
                // call returns without panicking. A known user usually yields
                // at least one group.
                let _ = groups;
            }
            // An impossible user name resolves to no groups.
            assert!(lookup_user_groups("\u{0}no-such-user-xyzzy").is_empty());
        }
    }
}
