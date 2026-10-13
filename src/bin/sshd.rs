//! `sshd` — puressh's SSH server daemon.
//!
//! ```text
//! sshd [-46DdeqTt] [-C connection_spec] [-f config] [-p port]... [-h host_key_file]... [-o option]...
//!      [-A authorized_keys_file] [-u allowed_user]... [--x11-forward] ...
//! ```
//!
//! Defaults follow OpenSSH so the binary can replace it: the configuration
//! is `/etc/ssh/sshd_config` (when present; `-f` overrides, `-o` options win
//! over the file), the host keys are `/etc/ssh/ssh_host_{rsa,ecdsa,ed25519,mldsa44_ed25519}_key`
//! (whichever load), the daemon listens on port 22 of every address (one
//! `IPV6_V6ONLY` socket per family), and any user may log in subject to
//! `AllowUsers` / `DenyUsers` and authentication. It always stays in the
//! foreground (`-D` / `-e` are accepted no-ops); `-t` checks the
//! configuration and host keys and exits; SIGHUP re-executes the daemon to
//! reload the configuration, unless the new configuration fails to load.
//!
//! Public keys are looked up **per user**, as OpenSSH does: `AuthorizedKeysFile`
//! (default `.ssh/authorized_keys .ssh/authorized_keys2`) names one or more
//! path templates, `%u` / `%h` / `%%` are expanded against the login user's
//! passwd entry, a relative path is taken under that user's home directory,
//! and the resulting files are read — while the daemon still holds root, so
//! `~/.ssh` may be mode 0700 — and StrictModes-checked against that user
//! (file and every ancestor owned by root or the user, none group/world
//! writable). `cert-authority` lines in a user's own file trust that CA for
//! that user only, and honour `principals="a,b"`.
//!
//! `-A FILE` is different and deliberately narrow: it names ONE global
//! `authorized_keys` file whose every key logs in as the single allowed user.
//! It is refused unless exactly one literal user is allowed (`-u USER`, or
//! one `AllowUsers` name with no wildcard / `@host`), because a shared file
//! plus several allowed users would let any listed key log in as any of
//! them. It exists for single-user / test deployments; production setups
//! should use `AuthorizedKeysFile`.
//!
//! Each accepted connection is handled by a freshly `fork()`ed child
//! process. The daemon parent keeps the listener and immediately returns
//! to `accept()`. Killing the daemon does **not** kill live sessions —
//! children are reparented to PID 1 and keep running. The child drops the
//! listener fd so the daemon can be restarted on the same port without
//! waiting on `SO_REUSEADDR` semantics.
//!
//! The parent tracks every live child (pid → peer IP, auth state) and
//! reaps in its accept loop, never from the signal handler. `MaxStartups`
//! (`--max-startups`) caps the number of children that have not yet
//! authenticated — each child reports userauth success over an inherited
//! pipe — and `--per-source-max` caps live children per peer IP for their
//! whole lifetime.
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
#[path = "sshd_log.rs"]
mod sshd_log;

#[cfg(all(target_os = "linux", target_env = "gnu"))]
#[path = "sshd_login.rs"]
mod sshd_login;

#[cfg(unix)]
mod imp {
    use crate::sshd_log;
    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    use crate::sshd_login;
    use std::collections::HashMap;
    use std::ffi::OsStr;
    use std::net::IpAddr;
    use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd};
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::process::CommandExt;
    use std::process::{Command, ExitCode};
    use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
    use std::sync::{Arc, Mutex};

    use nix::errno::Errno;
    use nix::fcntl::{FcntlArg, FdFlag, OFlag, fcntl};
    use nix::libc;
    use nix::poll::{PollFd, PollFlags, PollTimeout, poll};
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
        ShellHandler, ShellSession, SubsystemHandler, handle_session_with_addrs,
        handle_session_with_peer,
    };
    use puressh::sftp::{SftpServerOptions, SftpServerSession};

    const VERSION: &str = env!("CARGO_PKG_VERSION");

    const USAGE: &str = "usage: sshd [-46DdeqTt] [-C connection_spec] [-f configfile] [-p port]... \
                         [-b address]... \
                         [-h host_key_file]... [-c host_cert_file]... [-o option]... \
                         [-E log_file] [-g login_grace_time] [-A authorized_keys_file] \
                         [-u allowed_user]... [--no-sftp] [--sftp-read-only] \
                         [--sftp-root PATH] [--no-scp] [--no-agent-forward] \
                         [--x11-forward] [--no-strict-modes] [--debug-commands] \
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
        use std::sync::mpsc::{Receiver, Sender, channel};
        use std::sync::{Arc, Mutex};
        use std::thread::JoinHandle;

        use pam_client2::conv_null::Conversation;
        use pam_client2::{Context, ConversationHandler, ErrorCode, Flag, SessionToken};
        use zeroize::Zeroizing;

        /// One step of a live keyboard-interactive PAM conversation, returned
        /// by [`KbdConversation::next`].
        pub enum KbdStep {
            /// PAM asked a prompt. `instruction` carries any `text_info` /
            /// `error_msg` the module emitted just before it (often the OTP
            /// challenge text). `echo` is true for a visible prompt.
            Prompt {
                /// Instruction / info text to show above the prompt.
                instruction: String,
                /// The prompt label (e.g. `"Password: "`, `"OTP: "`).
                prompt: String,
                /// Whether the client should echo the typed answer.
                echo: bool,
            },
            /// The PAM `authenticate()` + `acct_mgmt()` finished. `true` ⇒ both
            /// succeeded (accept); `false` ⇒ rejected.
            Done(bool),
        }

        /// A message sent FROM the worker thread (running PAM) TO the
        /// authenticator (driving the SSH wire).
        enum FromWorker {
            /// PAM wants an answer to this prompt.
            Prompt {
                instruction: String,
                prompt: String,
                echo: bool,
            },
            /// PAM finished with this overall verdict.
            Done(bool),
        }

        /// The reply the authenticator hands back for a prompt: the user's
        /// answer, wiped on drop. A `None` answer (channel closed / no
        /// response) is treated by the worker as a conversation error.
        type ToWorker = Zeroizing<Vec<u8>>;

        /// A keyboard-interactive PAM conversation in flight.
        ///
        /// The PAM `Context` lives on a dedicated worker thread (`handle`); its
        /// conversation callback blocks on `to_worker`, handing each prompt out
        /// over `from_worker` and waiting for the answer. The authenticator
        /// holds the channel ends + the join handle here. Dropping this struct
        /// (on disconnect, or when `LoginGraceTime` fires) closes `to_worker`,
        /// which unblocks the worker's conversation with a `RecvError` → PAM
        /// aborts → the thread exits and is joined.
        pub struct KbdConversation {
            from_worker: Receiver<FromWorker>,
            to_worker: Sender<ToWorker>,
            handle: Option<JoinHandle<()>>,
            /// Set once a terminal `Done` has been observed, so a stray extra
            /// `answer`/`next` cannot wedge on a dead worker.
            finished: bool,
        }

        /// The conversation handler that runs ON the worker thread. Each
        /// per-message PAM callback sends one prompt to the authenticator and
        /// blocks for its answer.
        struct BridgeConv {
            to_main: Sender<FromWorker>,
            from_main: Receiver<ToWorker>,
            /// `text_info` / `error_msg` text accumulated since the last
            /// prompt, attached to the next prompt's instruction.
            pending_info: String,
        }

        impl BridgeConv {
            /// Block until the authenticator supplies the answer to `prompt`.
            /// A closed channel (authenticator dropped the conversation) maps
            /// to a PAM conversation error so `authenticate()` aborts cleanly.
            fn ask(&mut self, prompt: &CStr, echo: bool) -> Result<CString, ErrorCode> {
                let instruction = core::mem::take(&mut self.pending_info);
                let prompt = String::from_utf8_lossy(prompt.to_bytes()).into_owned();
                self.to_main
                    .send(FromWorker::Prompt {
                        instruction,
                        prompt,
                        echo,
                    })
                    .map_err(|_| ErrorCode::CONV_ERR)?;
                let answer = self.from_main.recv().map_err(|_| ErrorCode::CONV_ERR)?;
                // The answer may not contain an interior NUL.
                CString::new(answer.to_vec()).map_err(|_| ErrorCode::CONV_ERR)
            }
        }

        impl ConversationHandler for BridgeConv {
            fn prompt_echo_on(&mut self, prompt: &CStr) -> Result<CString, ErrorCode> {
                self.ask(prompt, true)
            }
            fn prompt_echo_off(&mut self, prompt: &CStr) -> Result<CString, ErrorCode> {
                self.ask(prompt, false)
            }
            fn text_info(&mut self, msg: &CStr) {
                let s = String::from_utf8_lossy(msg.to_bytes());
                if !self.pending_info.is_empty() {
                    self.pending_info.push('\n');
                }
                self.pending_info.push_str(&s);
            }
            fn error_msg(&mut self, msg: &CStr) {
                // Surface errors as instruction text too (e.g. "Account
                // locked"); they precede the next prompt or are dropped if the
                // conversation ends.
                self.text_info(msg);
            }
        }

        impl KbdConversation {
            /// Pull the next step from the worker: either a prompt to send to
            /// the client, or the terminal verdict. After a `Done`, further
            /// calls return `Done` with the same verdict without blocking.
            pub fn next(&mut self) -> KbdStep {
                if self.finished {
                    return KbdStep::Done(false);
                }
                match self.from_worker.recv() {
                    Ok(FromWorker::Prompt {
                        instruction,
                        prompt,
                        echo,
                    }) => KbdStep::Prompt {
                        instruction,
                        prompt,
                        echo,
                    },
                    Ok(FromWorker::Done(ok)) => {
                        self.finished = true;
                        KbdStep::Done(ok)
                    }
                    // Worker died without a verdict ⇒ reject.
                    Err(_) => {
                        self.finished = true;
                        KbdStep::Done(false)
                    }
                }
            }

            /// Hand the user's answer for the outstanding prompt to the worker.
            /// Returns `false` if the worker is already gone.
            pub fn answer(&mut self, response: Zeroizing<Vec<u8>>) -> bool {
                if self.finished {
                    return false;
                }
                self.to_worker.send(response).is_ok()
            }
        }

        impl Drop for KbdConversation {
            fn drop(&mut self) {
                // Dropping `to_worker` closes the response channel; a worker
                // blocked in `recv()` wakes with `RecvError`, returns
                // CONV_ERR, and PAM `authenticate()` unwinds. Then join.
                // (Replace the sender with a fresh, immediately-dropped one to
                // force-close without needing `to_worker` to be an Option.)
                let (dead, _) = channel::<ToWorker>();
                drop(core::mem::replace(&mut self.to_worker, dead));
                if let Some(h) = self.handle.take() {
                    let _ = h.join();
                }
            }
        }

        /// A one-shot PAM conversation that answers every
        /// `PAM_PROMPT_ECHO_OFF` (the password prompt) with a fixed secret,
        /// held in a [`Zeroizing`] buffer so its bytes are wiped on drop.
        /// Echo-on prompts (username) and info/error messages are ignored —
        /// the username is already bound via `Context::new`, and we never
        /// surface PAM text to the network here. This is the
        /// non-interactive "verify this password" conversation used by the
        /// SSH `password` method, which is single-prompt by nature. A genuine
        /// multi-step PAM challenge (e.g. an OTP module that asks a second
        /// question) is driven instead by [`BridgeConv`] /
        /// [`KbdConversation`] over the `keyboard-interactive` method.
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
            /// `service`: the PAM service (`PAMServiceName`, `sshd` by
            /// default).
            pub fn new(debug: bool, service: &'static str) -> Arc<Self> {
                Arc::new(Self {
                    service,
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

            /// Begin a genuine multi-step keyboard-interactive PAM
            /// conversation for `user`. PAM `authenticate()` runs on a
            /// dedicated worker thread whose conversation callback bridges each
            /// prompt to the SSH `USERAUTH_INFO_REQUEST`/`_RESPONSE` rounds via
            /// channels (see [`KbdConversation`]). The returned handle is
            /// driven by [`KbdConversation::next`] / [`KbdConversation::answer`]
            /// and torn down on drop.
            ///
            /// Like [`Self::pam_check_password`], this opens **no** session —
            /// it only authenticates (`authenticate()` + `acct_mgmt()`); the
            /// session is opened later in `ensure`. A throw-away `Context`
            /// lives entirely on the worker thread, so its (`!Sync`) PAM handle
            /// never crosses back to the authenticator.
            ///
            /// MANUAL e2e against a real 2-prompt PAM service (not hermetic —
            /// installing a PAM service file needs root + writes to
            /// `/etc/pam.d`):
            ///   1. Install a second-factor PAM module that prompts after the
            ///      password — e.g. `pam_google_authenticator.so` — into
            ///      `/etc/pam.d/sshd`:
            ///        ```text
            ///        auth required pam_unix.so
            ///        auth required pam_google_authenticator.so
            ///        account required pam_unix.so
            ///        ```
            ///   2. Run sshd with `KbdInteractiveAuthentication yes`, connect
            ///      with `ssh -o PreferredAuthentications=keyboard-interactive`,
            ///      and confirm the client is asked the password FIRST, then the
            ///      `Verification code:` prompt, and that a correct code logs in
            ///      while a wrong one (or an empty password under
            ///      `PermitEmptyPasswords no`) is refused.
            ///   3. A simpler 2-prompt stand-in is `pam_listfile`/`pam_exec`
            ///      with a script that echoes a `PAM_PROMPT_ECHO_OFF` message;
            ///      the bridge issues each as its own `USERAUTH_INFO_REQUEST`.
            pub fn start_kbd_interactive(
                &self,
                user: &str,
                rhost: Option<&str>,
            ) -> KbdConversation {
                let (to_main, from_worker) = channel::<FromWorker>();
                let (to_worker, from_main) = channel::<ToWorker>();
                let service = self.service;
                let user = user.to_string();
                let rhost = rhost.map(str::to_string);

                let handle = std::thread::spawn(move || {
                    let conv = BridgeConv {
                        to_main: to_main.clone(),
                        from_main,
                        pending_info: String::new(),
                    };
                    // Build the context on THIS thread; the PAM handle never
                    // leaves it.
                    let mut ctx = match Context::new(service, Some(&user), conv) {
                        Ok(c) => c,
                        Err(_) => {
                            let _ = to_main.send(FromWorker::Done(false));
                            return;
                        }
                    };
                    if let Some(rhost) = rhost.as_deref()
                        && ctx.set_rhost(Some(rhost)).is_err()
                    {
                        let _ = to_main.send(FromWorker::Done(false));
                        return;
                    }
                    // authenticate() drives the conversation: each prompt
                    // blocks in BridgeConv::ask until the authenticator answers.
                    let ok =
                        ctx.authenticate(Flag::NONE).is_ok() && ctx.acct_mgmt(Flag::NONE).is_ok();
                    let _ = to_main.send(FromWorker::Done(ok));
                    // `ctx` drops here on the worker thread → pam_end.
                });

                KbdConversation {
                    from_worker,
                    to_worker,
                    handle: Some(handle),
                    finished: false,
                }
            }
        }

        fn pam_err<E: std::fmt::Display>(phase: &'static str, e: E) -> puressh::Error {
            puressh::Error::Io(std::io::Error::other(format!("PAM {phase}: {e}")))
        }

        #[cfg(test)]
        impl KbdConversation {
            /// Build a conversation backed by a scripted *fake* worker instead
            /// of a real PAM `Context`, for hermetic state-machine tests. The
            /// worker emits each `(instruction, prompt, echo)` in `script`,
            /// blocking for the answer after each (recording it into
            /// `received`), then emits `Done(verdict)`. This exercises the exact
            /// channel protocol `BridgeConv` + the real worker use, without
            /// requiring a multi-prompt PAM module to be installed.
            pub fn fake_for_test(
                script: Vec<(String, String, bool)>,
                verdict: bool,
                received: std::sync::Arc<Mutex<Vec<Vec<u8>>>>,
            ) -> Self {
                let (to_main, from_worker) = channel::<FromWorker>();
                let (to_worker, from_main) = channel::<ToWorker>();
                let handle = std::thread::spawn(move || {
                    for (instruction, prompt, echo) in script {
                        if to_main
                            .send(FromWorker::Prompt {
                                instruction,
                                prompt,
                                echo,
                            })
                            .is_err()
                        {
                            return;
                        }
                        match from_main.recv() {
                            Ok(answer) => received.lock().unwrap().push(answer.to_vec()),
                            // Authenticator dropped us (disconnect / grace
                            // timeout) — exit like the real worker would.
                            Err(_) => return,
                        }
                    }
                    let _ = to_main.send(FromWorker::Done(verdict));
                });
                KbdConversation {
                    from_worker,
                    to_worker,
                    handle: Some(handle),
                    finished: false,
                }
            }
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

        /// Stub mirror of the real [`KbdStep`]. On a non-PAM build a
        /// keyboard-interactive conversation can never start, so this is only
        /// ever observed as `Done(false)`. The `Prompt` variant exists purely
        /// for type parity with the real module's `kbd_pump` match arms, so it
        /// is never constructed here.
        #[allow(dead_code)]
        pub enum KbdStep {
            /// Never produced on this build (kept for type parity).
            Prompt {
                /// Instruction text.
                instruction: String,
                /// Prompt label.
                prompt: String,
                /// Echo flag.
                echo: bool,
            },
            /// Terminal verdict; always `false` here.
            Done(bool),
        }

        /// Stub mirror of the real `KbdConversation` for non-PAM builds. It
        /// always reports a rejecting `Done(false)` and accepts no answers.
        pub struct KbdConversation {
            done: bool,
        }

        impl KbdConversation {
            pub fn next(&mut self) -> KbdStep {
                self.done = true;
                KbdStep::Done(false)
            }
            pub fn answer(&mut self, _response: zeroize::Zeroizing<Vec<u8>>) -> bool {
                let _ = self.done;
                false
            }
        }

        impl PamGate {
            pub fn new(_debug: bool, _service: &'static str) -> Arc<Self> {
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
            /// No PAM backend: a keyboard-interactive conversation cannot run.
            /// Returns a stub that immediately rejects. The server also never
            /// advertises `keyboard-interactive` on such a build.
            pub fn start_kbd_interactive(
                &self,
                _user: &str,
                _rhost: Option<&str>,
            ) -> KbdConversation {
                KbdConversation { done: false }
            }
        }
    }

    struct Cli {
        /// `-f path`: the `sshd_config` to read. `None` ⇒ the OpenSSH default
        /// [`DEFAULT_CONFIG`] (CLI flags still win on scalars).
        config_file: Option<String>,
        /// `-o KEYWORD=value` / `-o "KEYWORD value"`: config lines that take
        /// precedence over the file (first value wins, as in OpenSSH).
        config_options: Vec<String>,
        /// `-p port`, repeatable. Empty ⇒ `Port` lines, else 22.
        ports: Vec<u16>,
        /// `-T`: print the effective configuration and exit.
        dump_config: bool,
        /// `-C spec` (repeatable): connection parameters (`user=`, `addr=`,
        /// …) whose `Match` blocks `-T` applies.
        connection_spec: Vec<String>,
        /// `-t`: check the configuration and host keys, then exit.
        test_only: bool,
        /// `-i`: serve one connection on stdin / stdout (inetd mode, and
        /// OpenSSH's `ProxyCommand sshd -i` testing setups).
        inetd: bool,
        /// `-D`: stay in the foreground. Without it (and without `-d`), the
        /// daemon detaches once it is listening, as OpenSSH's does.
        no_detach: bool,
        /// `-4` / `-6`.
        address_family: Option<puressh::config::ServerAddressFamily>,
        /// `-E file`: append diagnostics to `file` instead of stderr.
        log_file: Option<String>,
        /// `-e`: log to stderr instead of syslog.
        log_stderr: bool,
        /// `-q`: log nothing.
        quiet: bool,
        /// `-b ADDR`: bind to ADDR (host or `host:port`). Repeats are
        /// recognised; v1 uses only the first one and warns about extras
        /// until multi-address bind lands. Config `ListenAddress` lines
        /// fold into the same list.
        listen_addresses: Vec<String>,
        host_key_files: Vec<String>,
        host_certificate_files: Vec<String>,
        /// `-A FILE`: one global authorized_keys file for the single allowed
        /// user (see the module docs). `None` ⇒ per-user `AuthorizedKeysFile`.
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
        /// X11 forwarding is **off** by default (OpenSSH's default);
        /// `--x11-forward` (or `X11Forwarding yes`) enables it. When off,
        /// any client `x11-req` is refused. `--no-x11-forward` is still
        /// accepted and forces it off over the config.
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
        /// `--max-startups N`: cap on concurrent *unauthenticated*
        /// connection children, as OpenSSH's `MaxStartups` (0 = unlimited).
        /// A child leaves the count once it reports authentication success
        /// to the parent (see `AUTH_NOTIFY_FD`).
        max_startups: Option<u32>,
        /// `--per-source-max N`: cap on simultaneous connections (for their
        /// whole lifetime, authenticated or not) from any single peer IP
        /// (0 = unlimited). `None` ⇒ `PerSourceMaxStartups`, else 10.
        per_source_max: Option<u32>,
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
    /// Resolve `-b` / `ListenAddress` specs into the addresses to listen on,
    /// with OpenSSH's syntax: `host`, `host:port`, `[v6]`, `[v6]:port`, or a
    /// bare IPv6 literal. A spec without a port listens on every port in
    /// `ports`. No spec ⇒ the wildcard address of each allowed family.
    fn listen_addrs(
        specs: &[String],
        ports: &[u16],
        af: Option<puressh::config::ServerAddressFamily>,
    ) -> Result<Vec<std::net::SocketAddr>, String> {
        use puressh::config::ServerAddressFamily as Af;
        use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs};
        let family_ok = |a: &SocketAddr| match af {
            Some(Af::Inet) => a.is_ipv4(),
            Some(Af::Inet6) => a.is_ipv6(),
            _ => true,
        };
        let mut out: Vec<SocketAddr> = Vec::new();
        let mut push = |a: SocketAddr| {
            if family_ok(&a) && !out.contains(&a) {
                out.push(a);
            }
        };
        if specs.is_empty() {
            for &p in ports {
                push(SocketAddr::from((Ipv6Addr::UNSPECIFIED, p)));
                push(SocketAddr::from((Ipv4Addr::UNSPECIFIED, p)));
            }
        }
        for spec in specs {
            let mut words = spec.split_whitespace();
            let addr = words.next().unwrap_or("");
            if let Some(extra) = words.next() {
                return Err(format!(
                    "ListenAddress {spec:?}: {extra} (routing domains) is not supported"
                ));
            }
            let bad_port = || format!("ListenAddress {spec:?}: bad port");
            // (host, explicit port)
            let (host, port): (&str, Option<u16>) = if let Some(rest) = addr.strip_prefix('[') {
                let (h, tail) = rest
                    .split_once(']')
                    .ok_or_else(|| format!("ListenAddress {spec:?}: unterminated '['"))?;
                let port = match tail.strip_prefix(':') {
                    Some(p) => Some(p.parse().map_err(|_| bad_port())?),
                    None if tail.is_empty() => None,
                    None => return Err(format!("ListenAddress {spec:?}: junk after ']'")),
                };
                (h, port)
            } else if addr.matches(':').count() == 1 {
                let (h, p) = addr.split_once(':').unwrap_or((addr, ""));
                (h, Some(p.parse().map_err(|_| bad_port())?))
            } else {
                (addr, None)
            };
            let want: Vec<u16> = match port {
                Some(p) => vec![p],
                None => ports.to_vec(),
            };
            for p in want {
                let resolved = (host, p)
                    .to_socket_addrs()
                    .map_err(|e| format!("ListenAddress {spec:?}: {e}"))?;
                for a in resolved {
                    push(a);
                }
            }
        }
        if out.is_empty() {
            return Err("no listen address left after AddressFamily filtering".into());
        }
        Ok(out)
    }

    /// Bind a listening TCP socket. IPv6 sockets are `IPV6_V6ONLY` (as in
    /// OpenSSH) so `[::]` and `0.0.0.0` coexist and IPv4 peers keep their
    /// IPv4 addresses for `AllowUsers` / `Match Address`.
    fn bind_listener(addr: std::net::SocketAddr) -> std::io::Result<std::net::TcpListener> {
        use nix::sys::socket::{
            AddressFamily, Backlog, SockFlag, SockType, SockaddrIn, SockaddrIn6, bind, listen,
            setsockopt, socket, sockopt,
        };
        let family = if addr.is_ipv6() {
            AddressFamily::Inet6
        } else {
            AddressFamily::Inet
        };
        let fd = socket(family, SockType::Stream, SockFlag::empty(), None)?;
        fcntl(&fd, FcntlArg::F_SETFD(FdFlag::FD_CLOEXEC))?;
        setsockopt(&fd, sockopt::ReuseAddr, &true)?;
        match addr {
            std::net::SocketAddr::V6(v6) => {
                setsockopt(&fd, sockopt::Ipv6V6Only, &true)?;
                bind(fd.as_raw_fd(), &SockaddrIn6::from(v6))?;
            }
            std::net::SocketAddr::V4(v4) => bind(fd.as_raw_fd(), &SockaddrIn::from(v4))?,
        }
        listen(&fd, Backlog::new(128).unwrap_or(Backlog::MAXCONN))?;
        Ok(std::net::TcpListener::from(fd))
    }

    /// The `sshd_config` read when `-f` is not given (OpenSSH's default).
    const DEFAULT_CONFIG: &str = "/etc/ssh/sshd_config";

    /// Host keys tried when neither `-h` nor `HostKey` names any (OpenSSH's
    /// defaults); missing files are skipped.
    const DEFAULT_HOST_KEYS: &[&str] = &[
        "/etc/ssh/ssh_host_rsa_key",
        "/etc/ssh/ssh_host_ecdsa_key",
        "/etc/ssh/ssh_host_ed25519_key",
        "/etc/ssh/ssh_host_mldsa44_ed25519_key",
    ];

    /// The effective configuration: `-o` options first (so they win, since
    /// the first obtained value is used), then the file (`-f`, or
    /// [`DEFAULT_CONFIG`] if it exists).
    fn load_effective_config(cli: &Cli) -> Result<puressh::config::SshServerConfig, String> {
        let mut lines = Vec::new();
        for o in &cli.config_options {
            let toks = puressh::config::tokenize(o).map_err(|e| format!("-o {o:?}: {e}"))?;
            if toks.len() != 1 || toks[0].keyword == "match" || toks[0].keyword == "include" {
                return Err(format!(
                    "-o {o:?}: expected a single `Keyword value` option"
                ));
            }
            lines.extend(toks);
        }
        let path = match cli.config_file.as_deref() {
            Some(p) => Some(std::path::PathBuf::from(p)),
            None => {
                let p = std::path::PathBuf::from(DEFAULT_CONFIG);
                p.exists().then_some(p)
            }
        };
        if let Some(path) = &path {
            lines.extend(
                puressh::config::tokenize_file_with_includes(path, 0)
                    .map_err(|e| format!("{}: {e}", path.display()))?,
            );
        }
        puressh::config::SshServerConfig::from_lines(lines).map_err(|e| match &path {
            Some(p) => format!("{}: {e}", p.display()),
            None => e.to_string(),
        })
    }

    /// Fill unset global options with OpenSSH's defaults where this daemon's
    /// built-in defaults differ (`Match` blocks can still override them).
    fn apply_openssh_defaults(g: &mut puressh::config::ServerOptions) {
        g.print_motd.get_or_insert(true);
        if g.max_startups.is_none() {
            // MaxStartups 10:30:100
            g.max_startups = Some(100);
            g.max_startups_early = Some((10, 30));
        }
    }

    /// `Type=notify` (as OpenSSH's units on Ubuntu are): tell systemd the
    /// daemon is listening by sending `READY=1` to `$NOTIFY_SOCKET`. A
    /// re-exec on SIGHUP sends it again, which systemd accepts.
    fn notify_ready() {
        use std::os::unix::net::UnixDatagram;
        let Some(path) = std::env::var_os("NOTIFY_SOCKET") else {
            return;
        };
        let Ok(sock) = UnixDatagram::unbound() else {
            return;
        };
        let msg = format!("READY=1\nMAINPID={}", std::process::id());
        let sent = match path.as_encoded_bytes().strip_prefix(b"@") {
            // An abstract socket (systemd's usual choice).
            #[cfg(any(target_os = "linux", target_os = "android"))]
            Some(name) => {
                use std::os::linux::net::SocketAddrExt;
                std::os::unix::net::SocketAddr::from_abstract_name(name)
                    .and_then(|a| sock.send_to_addr(msg.as_bytes(), &a))
            }
            #[cfg(not(any(target_os = "linux", target_os = "android")))]
            Some(_) => return,
            None => sock.send_to(msg.as_bytes(), &path),
        };
        if let Err(e) = sent {
            eprintln!("sshd: warning: could not notify systemd: {e}");
        }
    }

    /// `-T [-C spec]`: print the effective configuration like OpenSSH's
    /// `sshd -T`: lowercase keywords, every setting with its default, and
    /// the `Match` blocks selected by `-C` applied.
    fn dump_config(cli: &Cli, cfg: &puressh::config::SshServerConfig) -> Result<i32, String> {
        use puressh::config::{
            Compression, ExecPolicy, MatchContext, PermitRootLogin, ServerAddressFamily as Af,
            ServerGatewayPorts as GatewayPorts, TcpForwarding,
        };

        // `-C user=…,addr=…` (any order, repeatable).
        let (mut user, mut host, mut addr, mut laddr, mut lport) = (None, None, None, None, None);
        let mut invalid_user = false;
        let mut rdomain = None;
        for spec in &cli.connection_spec {
            for kv in spec.split(',').filter(|kv| !kv.is_empty()) {
                if kv == "invalid-user" {
                    invalid_user = true;
                    continue;
                }
                let (k, v) = kv
                    .split_once('=')
                    .ok_or_else(|| format!("Invalid test mode specification {kv}"))?;
                match k.to_ascii_lowercase().as_str() {
                    "user" => user = Some(v.to_string()),
                    "host" => host = Some(v.to_string()),
                    "addr" => addr = Some(v.to_string()),
                    "laddr" => laddr = Some(v.to_string()),
                    "lport" => {
                        lport = Some(v.parse::<u16>().map_err(|_| format!("Invalid port {v}"))?)
                    }
                    "rdomain" => rdomain = Some(v.to_string()),
                    _ => return Err(format!("Invalid test mode specification {kv}")),
                }
            }
        }
        let opts = if cli.connection_spec.is_empty() {
            cfg.global.clone()
        } else {
            let groups = user.as_deref().map(lookup_user_groups);
            let mut ctx = MatchContext::default();
            ctx.host = host.as_deref().unwrap_or("");
            ctx.invalid_user = Some(invalid_user);
            ctx.rdomain = rdomain.as_deref();
            ctx.user = user.as_deref();
            ctx.groups = groups.as_deref();
            ctx.address = addr.as_deref();
            ctx.local_address = laddr.as_deref();
            ctx.local_port = lport;
            cfg.resolve(&ctx, ExecPolicy::Deny)
        };

        let mut out = String::new();
        let mut line = |k: &str, v: &str| {
            out.push_str(k);
            out.push(' ');
            out.push_str(v);
            out.push('\n');
        };
        let yn = |b: bool| if b { "yes" } else { "no" };
        let fwd = |f: Option<TcpForwarding>| match f {
            None | Some(TcpForwarding::All) => "yes",
            Some(TcpForwarding::No) => "no",
            Some(TcpForwarding::Local) => "local",
            Some(TcpForwarding::Remote) => "remote",
            Some(_) => "yes",
        };
        let list = |v: &Option<Vec<String>>, default: &[&str]| match v {
            Some(v) => v.join(","),
            None => default
                .iter()
                .filter(|a| !a.starts_with("kex-strict-"))
                .copied()
                .collect::<Vec<_>>()
                .join(","),
        };
        let none_or = |v: &Option<String>| v.clone().unwrap_or_else(|| "none".into());

        let ports: Vec<u16> = if !cli.ports.is_empty() {
            cli.ports.clone()
        } else if !opts.ports.is_empty() {
            opts.ports.clone()
        } else {
            vec![22]
        };
        for p in &ports {
            line("port", &p.to_string());
        }
        let af = cli.address_family.or(opts.address_family);
        line(
            "addressfamily",
            match af {
                Some(Af::Inet) => "inet",
                Some(Af::Inet6) => "inet6",
                _ => "any",
            },
        );
        let mut specs = cli.listen_addresses.clone();
        specs.extend(opts.listen_addresses.iter().cloned());
        for a in listen_addrs(&specs, &ports, af)? {
            line("listenaddress", &a.to_string());
        }
        let mut host_keys = cli.host_key_files.clone();
        host_keys.extend(opts.host_key_files.iter().cloned());
        if host_keys.is_empty() {
            host_keys = DEFAULT_HOST_KEYS.iter().map(|s| s.to_string()).collect();
        }
        for k in &host_keys {
            line("hostkey", k);
        }
        let mut certs = cli.host_certificate_files.clone();
        certs.extend(opts.host_certificate_files.iter().cloned());
        for c in &certs {
            line("hostcertificate", c);
        }
        if let Some(a) = &opts.host_key_agent {
            line("hostkeyagent", a);
        }
        line(
            "pamservicename",
            opts.pam_service_name.as_deref().unwrap_or("sshd"),
        );
        line(
            "usepam",
            yn(opts
                .use_pam
                .unwrap_or(cfg!(all(feature = "pam", target_os = "linux")))),
        );
        line(
            "logingracetime",
            &cli.login_grace_time
                .or(opts.login_grace_time)
                .unwrap_or(120)
                .to_string(),
        );
        line(
            "maxauthtries",
            &opts
                .max_auth_tries
                .unwrap_or(puressh::server::DEFAULT_MAX_AUTH_TRIES)
                .to_string(),
        );
        line("maxsessions", &opts.max_sessions.unwrap_or(10).to_string());
        let full = opts.max_startups.unwrap_or(100);
        match opts.max_startups_early {
            Some((start, rate)) => line("maxstartups", &format!("{start}:{rate}:{full}")),
            None => line("maxstartups", &format!("{full}:100:{full}")),
        }
        line(
            "persourcemaxstartups",
            &match opts.per_source_max_startups {
                None | Some(0) => "none".to_string(),
                Some(n) => n.to_string(),
            },
        );
        line(
            "clientaliveinterval",
            &opts.client_alive_interval.unwrap_or(0).to_string(),
        );
        line(
            "clientalivecountmax",
            &opts.client_alive_count_max.unwrap_or(3).to_string(),
        );
        line(
            "unusedconnectiontimeout",
            &match opts.unused_connection_timeout {
                None | Some(0) => "none".to_string(),
                Some(t) => t.to_string(),
            },
        );
        line(
            "requiredrsasize",
            &opts
                .required_rsa_size
                .unwrap_or(DEFAULT_REQUIRED_RSA_SIZE)
                .to_string(),
        );
        line(
            "permitrootlogin",
            match cli.permit_root_login.or(opts.permit_root_login) {
                Some(PermitRootLogin::Yes) => "yes",
                Some(PermitRootLogin::No) => "no",
                _ => "without-password",
            },
        );
        line(
            "pubkeyauthentication",
            yn(opts.pubkey_authentication != Some(false)),
        );
        line(
            "passwordauthentication",
            yn(opts.password_authentication != Some(false)),
        );
        line(
            "kbdinteractiveauthentication",
            yn(opts.kbd_interactive_authentication != Some(false)),
        );
        line(
            "permitemptypasswords",
            yn(opts.permit_empty_passwords == Some(true)),
        );
        line(
            "strictmodes",
            yn(cli.strict_modes.or(opts.strict_modes).unwrap_or(true)),
        );
        line(
            "x11forwarding",
            yn(cli.x11_forward.or(opts.x11_forwarding).unwrap_or(false)),
        );
        line(
            "allowagentforwarding",
            yn(cli
                .agent_forward
                .or(opts.allow_agent_forwarding)
                .unwrap_or(true)),
        );
        line("allowtcpforwarding", fwd(opts.allow_tcp_forwarding));
        line(
            "allowstreamlocalforwarding",
            fwd(opts.allow_stream_local_forwarding),
        );
        line(
            "gatewayports",
            match opts.gateway_ports {
                Some(GatewayPorts::Yes) => "yes",
                Some(GatewayPorts::ClientSpecified) => "clientspecified",
                _ => "no",
            },
        );
        line(
            "disableforwarding",
            yn(opts.disable_forwarding == Some(true)),
        );
        line("permittty", yn(opts.permit_tty != Some(false)));
        line("printmotd", yn(opts.print_motd.unwrap_or(true)));
        line("printlastlog", yn(opts.print_last_log.unwrap_or(true)));
        line(
            "compression",
            yn(!matches!(opts.compression, Some(Compression::No))),
        );
        line(
            "loglevel",
            puressh::config::server::LOG_LEVELS[usize::from(opts.log_level.unwrap_or(3).min(7))],
        );
        line(
            "syslogfacility",
            opts.syslog_facility.as_deref().unwrap_or("AUTH"),
        );
        match &opts.authorized_keys_file {
            Some(files) => line("authorizedkeysfile", &files.join(" ")),
            None => line(
                "authorizedkeysfile",
                &default_authorized_keys_files().join(" "),
            ),
        }
        line(
            "authorizedprincipalsfile",
            &none_or(&opts.authorized_principals_file),
        );
        let command = |c: &Option<Vec<String>>| match c {
            Some(c) if !c.is_empty() => c.join(" "),
            _ => "none".to_string(),
        };
        line(
            "authorizedkeyscommand",
            &command(&opts.authorized_keys_command),
        );
        line(
            "authorizedkeyscommanduser",
            &none_or(&opts.authorized_keys_command_user),
        );
        line(
            "authorizedprincipalscommand",
            &command(&opts.authorized_principals_command),
        );
        line(
            "authorizedprincipalscommanduser",
            &none_or(&opts.authorized_principals_command_user),
        );
        line("trustedusercakeys", &none_or(&opts.trusted_user_ca_keys));
        line(
            "revokedkeys",
            &none_or(
                &opts
                    .revoked_keys
                    .as_ref()
                    .filter(|v| !v.is_empty())
                    .map(|v| v.join(" ")),
            ),
        );
        line("banner", &none_or(&opts.banner));
        line("forcecommand", &none_or(&opts.force_command));
        line("chrootdirectory", &none_or(&opts.chroot_directory));
        line("permituserrc", yn(opts.permit_user_rc.unwrap_or(true)));
        line("tcpkeepalive", yn(opts.tcp_keep_alive.unwrap_or(true)));
        line(
            "permituserenvironment",
            opts.permit_user_environment.as_deref().unwrap_or("no"),
        );
        for e in &opts.set_env {
            line("setenv", e);
        }
        line(
            "xauthlocation",
            opts.xauth_location.as_deref().unwrap_or("/usr/bin/xauth"),
        );
        line(
            "pidfile",
            &if opts.pid_file_set {
                none_or(&opts.pid_file)
            } else {
                "/run/sshd.pid".to_string()
            },
        );
        match &opts.authentication_methods {
            Some(m) => line("authenticationmethods", &m.join(" ")),
            None => line("authenticationmethods", "any"),
        }
        let hostport = |hp: &Option<Vec<puressh::config::HostPort>>| match hp {
            None => "any".to_string(),
            Some(v) if v.is_empty() => "none".to_string(),
            // What `any` parses to.
            Some(v) if v.len() == 1 && v[0].host == "*" && v[0].port.is_none() => "any".to_string(),
            Some(v) => v
                .iter()
                .map(|h| match h.port {
                    Some(p) => format!("{}:{p}", h.host),
                    None => format!("{}:*", h.host),
                })
                .collect::<Vec<_>>()
                .join(" "),
        };
        line("permitopen", &hostport(&opts.permit_open));
        line("permitlisten", &hostport(&opts.permit_listen));
        let (bytes, secs) = opts
            .rekey_limit
            .map(|rk| (rk.max_bytes.unwrap_or(0), rk.max_seconds.unwrap_or(0)))
            .unwrap_or((0, 0));
        line("rekeylimit", &format!("{bytes} {secs}"));
        use puressh::hazmat::transport::kex::defaults;
        line("ciphers", &list(&opts.ciphers, defaults::CIPHERS));
        line("macs", &list(&opts.macs, defaults::MACS));
        line("kexalgorithms", &list(&opts.kex_algorithms, defaults::KEX));
        // Certificate algorithms first, as OpenSSH lists them.
        let with_certs: Vec<&str> = puressh::cert::CERT_KEY_NAMES
            .iter()
            .chain(defaults::HOST_KEY)
            .copied()
            .collect();
        line(
            "hostkeyalgorithms",
            &list(&opts.host_key_algorithms, &with_certs),
        );
        line(
            "pubkeyacceptedalgorithms",
            &list(&opts.pubkey_accepted_algorithms, &with_certs),
        );
        line(
            "casignaturealgorithms",
            &list(&opts.ca_signature_algorithms, defaults::HOST_KEY),
        );
        // Features this daemon does not have, shown with the value that
        // describes its behaviour (the config parser only accepts these).
        for (k, v) in [
            ("hostbasedauthentication", "no"),
            ("ignorerhosts", "yes"),
            ("gssapiauthentication", "no"),
            ("permittunnel", "no"),
            ("exposeauthinfo", "no"),
            ("usedns", "no"),
            ("fingerprinthash", "SHA256"),
        ] {
            line(k, v);
        }
        let subsystems = opts.subsystems.clone().unwrap_or_default();
        if !subsystems.iter().any(|(n, _)| n == "sftp")
            && opts.subsystem_sftp != Some(false)
            && opts.sftp_enabled != Some(false)
        {
            line("subsystem", "sftp internal-sftp");
        }
        for (name, command) in &subsystems {
            line("subsystem", &format!("{name} {command}"));
        }
        for (k, v) in [
            ("allowusers", &opts.allow_users),
            ("denyusers", &opts.deny_users),
            ("allowgroups", &opts.allow_groups),
            ("denygroups", &opts.deny_groups),
            ("acceptenv", &opts.accept_env),
        ] {
            for item in v {
                line(k, item);
            }
        }
        print!("{out}");
        Ok(0)
    }

    fn parse_args(args: &[String]) -> Result<Cli, String> {
        let mut config_file: Option<String> = None;
        let mut config_options: Vec<String> = Vec::new();
        let mut ports: Vec<u16> = Vec::new();
        let mut dump_config = false;
        let mut connection_spec: Vec<String> = Vec::new();
        let mut test_only = false;
        let mut inetd = false;
        let mut no_detach = false;
        let mut log_stderr = false;
        let mut quiet = false;
        let mut address_family: Option<puressh::config::ServerAddressFamily> = None;
        let mut log_file: Option<String> = None;
        let mut listen_addresses: Vec<String> = Vec::new();
        let mut host_key_files: Vec<String> = Vec::new();
        let mut host_certificate_files: Vec<String> = Vec::new();
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
        let mut per_source_max: Option<u32> = None;
        let mut permit_root_login: Option<puressh::config::PermitRootLogin> = None;

        // OpenSSH's getopt: flags may be grouped (`-De`) and a value may
        // follow its option directly (`-E/path`, `-p2222`).
        const VALUE_OPTS: &str = "CEbcfghkopuA";
        const FLAG_OPTS: &str = "46DGQRTdeiqrtV";
        let mut split: Vec<String> = Vec::with_capacity(args.len());
        let mut j = 0;
        while j < args.len() {
            let a = &args[j];
            j += 1;
            let Some(rest) = a
                .strip_prefix('-')
                .filter(|r| !r.starts_with('-') && r.len() > 1)
            else {
                split.push(a.clone());
                continue;
            };
            let chars: Vec<char> = rest.chars().collect();
            let mut k = 0;
            while k < chars.len() {
                let c = chars[k];
                split.push(format!("-{c}"));
                if VALUE_OPTS.contains(c) {
                    let tail: String = chars[k + 1..].iter().collect();
                    if !tail.is_empty() {
                        split.push(tail);
                    }
                    break;
                }
                if !FLAG_OPTS.contains(c) {
                    // Not an OpenSSH option: report it as written.
                    split.truncate(split.len() - 1);
                    split.push(a.clone());
                    break;
                }
                k += 1;
            }
        }
        let args = &split[..];
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
                    ports.push(v.parse::<u16>().map_err(|_| "invalid port".to_string())?);
                }
                "-o" => {
                    i += 1;
                    let v = args.get(i).ok_or("-o requires a value")?.clone();
                    config_options.push(v);
                }
                "-t" => test_only = true,
                "-i" => inetd = true,
                "-T" => dump_config = true,
                "-C" => {
                    i += 1;
                    connection_spec.push(args.get(i).ok_or("-C requires a value")?.clone());
                }
                "-4" => address_family = Some(puressh::config::ServerAddressFamily::Inet),
                "-6" => address_family = Some(puressh::config::ServerAddressFamily::Inet6),
                "-c" => {
                    i += 1;
                    let v = args.get(i).ok_or("-c requires a value")?.clone();
                    host_certificate_files.push(v);
                }
                "-E" => {
                    i += 1;
                    log_file = Some(args.get(i).ok_or("-E requires a value")?.clone());
                }
                "-g" => {
                    i += 1;
                    let v = args.get(i).ok_or("-g requires a value")?;
                    login_grace_time = Some(
                        v.trim_end_matches('s')
                            .parse::<u32>()
                            .map_err(|_| "invalid -g (seconds)".to_string())?,
                    );
                }
                // `-e`: log to stderr rather than syslog; `-q`: log nothing.
                "-e" => log_stderr = true,
                "-q" => quiet = true,
                "-D" => no_detach = true,
                // OpenSSH compatibility no-ops: `-r` no re-exec, `-k`
                // obsolete key regeneration.
                "-r" => {}
                "-k" => i += 1,
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
                "--host-certificate" => {
                    i += 1;
                    let v = args
                        .get(i)
                        .ok_or("--host-certificate requires a value")?
                        .clone();
                    host_certificate_files.push(v);
                }
                "-A" => {
                    i += 1;
                    let v = args.get(i).ok_or("-A requires a value")?.clone();
                    authorized_keys_file = Some(v);
                }
                "-u" => {
                    i += 1;
                    let v = args.get(i).ok_or("-u requires a value")?.clone();
                    // OpenSSH's `-u len` (utmp host-name length) is numeric
                    // and ignorable; anything else is puressh's allowed user.
                    if v.parse::<u32>().is_err() {
                        allowed_users.push(v);
                    }
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
                "--x11-forward" => x11_forward = Some(true),
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
                    per_source_max = Some(
                        v.parse::<u32>()
                            .map_err(|_| "invalid --per-source-max".to_string())?,
                    );
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
            config_options,
            ports,
            dump_config,
            connection_spec,
            test_only,
            inetd,
            no_detach,
            address_family,
            log_file,
            log_stderr,
            quiet,
            listen_addresses,
            host_key_files,
            host_certificate_files,
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

    /// Load each `HostKey`, then for each `HostCertificate` path wrap the
    /// matching plain host key (paired by embedded-key equality) in a
    /// `CertHostKey` so KEX can advertise the certificate algorithm. The
    /// certificate-wrapped key is inserted *ahead of* the plain key it
    /// certifies, so `build_server_kexinit` advertises the cert name first.
    fn load_host_keys_with_certs(
        key_paths: &[String],
        cert_paths: &[String],
        strict_modes: bool,
        agent: Option<&str>,
    ) -> Result<Vec<Box<dyn HostKey + Send + Sync>>, String> {
        use puressh::cert::Certificate;
        use puressh::hostkey::CertHostKey;
        use std::sync::Arc;

        // Load plain keys as shared (Arc) signers, retaining their public blob
        // for cert pairing. Sharing lets the same key material back both the
        // plain host-key entry and a CertHostKey wrapper without re-reading the
        // private key file.
        struct Loaded {
            blob: Vec<u8>,
            key: Arc<dyn HostKey + Send + Sync>,
        }
        let mut loaded: Vec<Loaded> = Vec::new();
        for path in key_paths {
            // As in OpenSSH, a host key that cannot be used (missing file,
            // unsupported type such as DSA, bad permissions) is reported and
            // skipped; only having no usable key at all is fatal.
            let loaded_key = (|| -> Result<Box<dyn HostKey + Send>, String> {
                if strict_modes {
                    check_owner_mode(path, 0o077, "host key")?;
                }
                let pem = std::fs::read_to_string(path).map_err(|e| format!("read {path}: {e}"))?;
                let priv_key = PrivateKey::parse_openssh_pem(&pem, None)
                    .map_err(|e| format!("parse {path}: {e}"))?;
                priv_key
                    .into_host_key()
                    .map_err(|e| format!("convert {path}: {e}"))
            })();
            // No private key there: with `HostKeyAgent`, its public key (the
            // file itself or `<path>.pub`) is signed for by the agent.
            let key: Arc<dyn HostKey + Send + Sync> = match loaded_key {
                // PrivateKey::into_host_key returns `Box<dyn HostKey + Send>` —
                // upgrade to `Send + Sync` by wrapping. Our concrete signers
                // (Ed25519, ECDSA, RSA) hold only `Sync`-safe types internally;
                // we expose this via a small thunk that just defers to the boxed
                // signer.
                Ok(hk) => Arc::from(SyncHostKey::wrap(hk)),
                Err(e) => match agent.map(|sock| AgentSocketHostKey::load(sock, path)) {
                    Some(Ok(k)) => Arc::new(k),
                    Some(Err(agent_err)) => {
                        eprintln!("sshd: warning: unable to load host key {path}: {agent_err}");
                        continue;
                    }
                    None => {
                        eprintln!("sshd: warning: unable to load host key: {e}");
                        continue;
                    }
                },
            };
            loaded.push(Loaded {
                blob: key.public_blob(),
                key,
            });
        }

        // Parse all host certificates up front, pairing by embedded-key
        // equality below.
        let mut certs: Vec<(Certificate, &'static str)> = Vec::new();
        for path in cert_paths {
            let text = std::fs::read_to_string(path).map_err(|e| format!("read {path}: {e}"))?;
            let cert = Certificate::parse_openssh_line(&text)
                .map_err(|e| format!("{path}: parse host certificate: {e}"))?;
            if !matches!(cert.cert_type, puressh::cert::CertType::Host) {
                return Err(format!("{path}: not a host certificate"));
            }
            let cert_name = puressh::cert::cert_name_for_key_type(cert.embedded_algorithm())
                .ok_or_else(|| format!("{path}: unsupported certificate family"))?;
            certs.push((cert, cert_name));
        }

        // Build the output list. For each loaded key, if a certificate
        // certifies it, emit the CertHostKey first (so KEX advertises the cert
        // name ahead of the plain key), then the plain key.
        let mut out: Vec<Box<dyn HostKey + Send + Sync>> = Vec::new();
        for item in loaded {
            if let Some(pos) = certs
                .iter()
                .position(|(c, _)| c.embedded_pubkey_blob == item.blob)
            {
                let (cert, cert_name) = certs.remove(pos);
                let cert_key =
                    CertHostKey::new(Box::new(SharedSigner(item.key.clone())), &cert, cert_name)
                        .map_err(|e| format!("host certificate does not match its key: {e}"))?;
                out.push(Box::new(cert_key));
            }
            out.push(Box::new(SharedSigner(item.key)));
        }

        if let Some((_, name)) = certs.first() {
            return Err(format!(
                "HostCertificate present but no matching HostKey for {name}"
            ));
        }
        if out.is_empty() {
            return Err(format!("no usable host key among {key_paths:?}"));
        }
        Ok(out)
    }

    /// A host key whose private half is held by an `ssh-agent`
    /// (`HostKeyAgent`): each signature is one request on a fresh connection
    /// to the agent's socket (connections are never shared between the
    /// per-connection processes).
    struct AgentSocketHostKey {
        socket: String,
        blob: Vec<u8>,
        algorithm: &'static str,
        /// `SSH_AGENT_RSA_SHA2_*` for an RSA key (0: SHA-1).
        flags: u32,
        rsa: bool,
    }

    impl AgentSocketHostKey {
        /// The public key of host key `path` (the file, or `<path>.pub`),
        /// which the agent at `socket` must hold.
        fn load(socket: &str, path: &str) -> Result<Self, String> {
            let parse = |p: &str| {
                std::fs::read_to_string(p).ok().and_then(|t| {
                    t.lines()
                        .find(|l| !l.trim().is_empty())
                        .and_then(|l| PublicKey::parse_authorized_keys_line(l.trim()).ok())
                })
            };
            let public = parse(path)
                .or_else(|| parse(&format!("{path}.pub")))
                .ok_or_else(|| format!("{path}: no private or public key"))?;
            let blob = public.wire_blob();
            let mut agent = puressh::agent::Agent::connect(socket)
                .map_err(|e| format!("HostKeyAgent {socket}: {e}"))?;
            let held = agent
                .identities()
                .map_err(|e| format!("HostKeyAgent {socket}: {e}"))?
                .iter()
                .any(|i| i.key_blob == blob);
            if !held {
                return Err(format!("{path}: the agent does not hold this key"));
            }
            let rsa = public.algorithm() == "ssh-rsa";
            let (algorithm, flags) = if rsa {
                ("rsa-sha2-512", AGENT_RSA_SHA2_512)
            } else {
                (public.algorithm(), 0)
            };
            Ok(AgentSocketHostKey {
                socket: socket.to_string(),
                blob,
                algorithm,
                flags,
                rsa,
            })
        }
    }

    const AGENT_RSA_SHA2_256: u32 = 2;
    const AGENT_RSA_SHA2_512: u32 = 4;

    impl HostKey for AgentSocketHostKey {
        fn algorithm(&self) -> &'static str {
            self.algorithm
        }
        fn public_blob(&self) -> Vec<u8> {
            self.blob.clone()
        }
        fn sign(&self, msg: &[u8]) -> puressh::Result<Vec<u8>> {
            puressh::agent::Agent::connect(&self.socket)?.sign(&self.blob, msg, self.flags)
        }
        /// The same RSA key signing with the hash `algs` names.
        fn upgraded_for(&self, algs: &str) -> Option<Box<dyn HostKey>> {
            if !self.rsa {
                return None;
            }
            let listed = |n: &str| algs.split(',').any(|a| a.trim() == n);
            let (algorithm, flags) = if listed("rsa-sha2-512") {
                ("rsa-sha2-512", AGENT_RSA_SHA2_512)
            } else if listed("rsa-sha2-256") {
                ("rsa-sha2-256", AGENT_RSA_SHA2_256)
            } else if listed("ssh-rsa") && puressh::hostkey::allow_rsa_sha1() {
                ("ssh-rsa", 0)
            } else {
                return None;
            };
            (algorithm != self.algorithm).then(|| {
                Box::new(AgentSocketHostKey {
                    socket: self.socket.clone(),
                    blob: self.blob.clone(),
                    algorithm,
                    flags,
                    rsa: true,
                }) as Box<dyn HostKey>
            })
        }
    }

    /// A `HostKey` backed by a shared `Arc` signer, so one loaded private key
    /// can stand behind both a plain host-key entry and its `CertHostKey`.
    struct SharedSigner(std::sync::Arc<dyn HostKey + Send + Sync>);

    impl HostKey for SharedSigner {
        fn algorithm(&self) -> &'static str {
            self.0.algorithm()
        }
        fn public_blob(&self) -> Vec<u8> {
            self.0.public_blob()
        }
        fn sign(&self, msg: &[u8]) -> puressh::Result<Vec<u8>> {
            self.0.sign(msg)
        }
        fn upgraded_for(&self, algs: &str) -> Option<Box<dyn HostKey>> {
            self.0.upgraded_for(algs)
        }
    }

    /// Refuse to read `path` when its Unix mode shares any forbidden bit
    /// with `forbidden_mask` (e.g. `0o077` for host keys — "not readable
    /// by group or world"). Matches OpenSSH's `StrictModes`. The
    /// `--no-strict-modes` CLI flag short-circuits this check.
    ///
    /// Beyond the mode bits, this also enforces OpenSSH's ownership and
    /// ancestor-writability rules (`secure_filename`): the file must be
    /// owned by root (uid 0) or, when `allowed_uid` is set, the target
    /// user; and no path component from the file up to `/` may be group-
    /// or world-writable. A correctly-permissioned root- or owner-owned
    /// file in non-writable directories continues to pass unchanged.
    /// The ancestor walk + ownership check mirror `validate_chroot_dir`.
    ///
    /// `kind` is just a human label for the error message ("host key",
    /// "authorized_keys file").
    /// Checks on a server-wide file (host key, TrustedUserCAKeys): none of
    /// the `forbidden_mask` mode bits, and owned by root or by the user sshd
    /// runs as. Unlike [`check_mode_strict`], its directories are not
    /// checked; OpenSSH checks host keys no further.
    fn check_owner_mode(path: &str, forbidden_mask: u32, kind: &str) -> Result<(), String> {
        use std::os::unix::fs::MetadataExt;
        let md = std::fs::metadata(path).map_err(|e| format!("stat {path}: {e}"))?;
        let mode = md.mode() & 0o777;
        if mode & forbidden_mask != 0 {
            return Err(format!(
                "{kind} {path}: insecure mode 0o{mode:o} (must not have any of \
                 0o{forbidden_mask:o}); fix with `chmod 0{:o} {path}` or override with \
                 --no-strict-modes",
                mode & !forbidden_mask
            ));
        }
        let euid = nix::unistd::geteuid().as_raw();
        if md.uid() != 0 && md.uid() != euid {
            return Err(format!(
                "{kind} {path}: must be owned by root or uid {euid}, is uid {}; \
                 override with --no-strict-modes",
                md.uid()
            ));
        }
        Ok(())
    }

    fn check_mode_strict(
        path: &str,
        forbidden_mask: u32,
        kind: &str,
        allowed_uid: Option<nix::unistd::Uid>,
    ) -> Result<(), String> {
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
        // Ownership: the file must be owned by root, or by the target user
        // when one is known. A file owned by an untrusted third party is
        // rejected even if its mode bits look benign.
        let allowed = allowed_uid.map(|u| u.as_raw());
        if md.uid() != 0 && Some(md.uid()) != allowed {
            return Err(format!(
                "{kind} {path}: must be owned by root (uid 0){}, is uid {}; \
                 override with --no-strict-modes",
                allowed.map(|u| format!(" or uid {u}")).unwrap_or_default(),
                md.uid()
            ));
        }
        // Ancestor walk: no directory from the file up to / may be group-
        // or world-writable, otherwise a non-trusted user could swap the
        // file (or a parent dir) out from under us. Same logic as
        // validate_chroot_dir, but each component may be owned by root or
        // the target user (OpenSSH's secure_filename allows the owner).
        let mut cur = std::path::Path::new(path).parent();
        while let Some(p) = cur {
            // An empty parent ("" from a relative leaf) means we've run out
            // of components to check.
            if p.as_os_str().is_empty() {
                break;
            }
            let dmd = std::fs::metadata(p).map_err(|e| format!("stat {}: {e}", p.display()))?;
            if dmd.uid() != 0 && Some(dmd.uid()) != allowed {
                return Err(format!(
                    "{kind} {path}: ancestor {} is owned by uid {} (must be root{}); \
                     override with --no-strict-modes",
                    p.display(),
                    dmd.uid(),
                    allowed.map(|u| format!(" or uid {u}")).unwrap_or_default(),
                ));
            }
            if dmd.mode() & 0o022 != 0 {
                return Err(format!(
                    "{kind} {path}: ancestor {} is group/world-writable (mode 0o{:o}); \
                     override with --no-strict-modes",
                    p.display(),
                    dmd.mode() & 0o777
                ));
            }
            cur = p.parent();
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
        fn upgraded_for(&self, algs: &str) -> Option<Box<dyn HostKey>> {
            self.inner.lock().ok()?.upgraded_for(algs)
        }
    }

    /// The parsed contents of one user's `authorized_keys` file(s).
    #[derive(Clone, Debug, Default)]
    struct AuthorizedKeys {
        /// Wire blobs of directly-authorized plain keys.
        blobs: Vec<Vec<u8>>,
        /// `cert-authority` lines: the CA key blob plus, when the line carries
        /// a `principals="a,b"` option, the principal patterns a certificate
        /// must match (replacing the login-user-must-be-a-principal rule).
        /// `None` ⇒ no `principals=` option on that line.
        cas: Vec<(Vec<u8>, Option<Vec<String>>)>,
        /// The options of each `blobs` line (same index; a missing entry is
        /// an unrestricted line).
        options: Vec<Arc<puressh::key::AuthorizedKeyOptions>>,
        /// The options of each `cas` line (same index, likewise).
        ca_options: Vec<Arc<puressh::key::AuthorizedKeyOptions>>,
    }

    impl AuthorizedKeys {
        fn append(&mut self, mut other: AuthorizedKeys) {
            // Keep the option lists aligned with their key lists.
            self.options.resize_with(self.blobs.len(), Default::default);
            self.ca_options
                .resize_with(self.cas.len(), Default::default);
            other
                .options
                .resize_with(other.blobs.len(), Default::default);
            other
                .ca_options
                .resize_with(other.cas.len(), Default::default);
            self.blobs.append(&mut other.blobs);
            self.cas.append(&mut other.cas);
            self.options.append(&mut other.options);
            self.ca_options.append(&mut other.ca_options);
        }
    }

    /// Whether an `authorized_keys` line applies to this connection: its
    /// `from=` patterns (addresses, `*`/`?` globs, CIDRs, `!` to exclude)
    /// admit the client, and its `expiry-time=` has not passed.
    fn key_line_applies(
        opts: &puressh::key::AuthorizedKeyOptions,
        peer: Option<&str>,
        debug: bool,
    ) -> bool {
        if let Some(from) = &opts.from {
            let Some(ip) = peer.and_then(parse_peer_ip) else {
                return false;
            };
            let ip_s = ip.to_string();
            let mut admitted = false;
            for pat in from.split(',').map(str::trim).filter(|p| !p.is_empty()) {
                let (negated, p) = match pat.strip_prefix('!') {
                    Some(p) => (true, p),
                    None => (false, pat),
                };
                let hit = if p.contains('/') {
                    cidr_matches(p, ip)
                } else {
                    puressh::config::host_matches(&[puressh::config::HostPattern::parse(p)], &ip_s)
                };
                if hit && negated {
                    admitted = false;
                    break;
                }
                admitted |= hit;
            }
            if !admitted {
                if debug {
                    eprintln!("sshd: authorized_keys: from=\"{from}\" does not admit {ip_s}");
                }
                return false;
            }
        }
        if let Some(exp) = &opts.expiry_time {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs() as i64)
                .unwrap_or(0);
            let offset = {
                let tt = now as libc::time_t;
                // SAFETY: `tm` is plain data; localtime_r fills it or fails.
                let mut tm: libc::tm = unsafe { std::mem::zeroed() };
                if unsafe { libc::localtime_r(&tt, &mut tm) }.is_null() {
                    0
                } else {
                    tm.tm_gmtoff as i64
                }
            };
            match puressh::sshsig::parse_time(exp, offset) {
                Some(t) if now < t => {}
                _ => {
                    if debug {
                        eprintln!("sshd: authorized_keys: key expired (expiry-time {exp})");
                    }
                    return false;
                }
            }
        }
        true
    }

    /// The OpenSSH default `AuthorizedKeysFile` list, relative to the login
    /// user's home directory.
    fn default_authorized_keys_files() -> Vec<String> {
        vec![
            ".ssh/authorized_keys".to_string(),
            ".ssh/authorized_keys2".to_string(),
        ]
    }

    /// Parse an `authorized_keys` file: directly-authorized keys, plus the CA
    /// keys (and any `principals=` restriction) from `cert-authority` lines.
    /// Lines that fail the strict option-aware parser are logged and skipped.
    ///
    /// Under StrictModes the file must be owned by root or `owner_uid` (the
    /// login user, for a per-user file; `None` for the global `-A` file), not
    /// group/world writable, and every ancestor directory must satisfy the
    /// same rule — so a user cannot plant keys in another user's file, and a
    /// writable `~` or `~/.ssh` cannot be used to swap the file out.
    fn load_authorized_keys_and_cas(
        path: &str,
        strict_modes: bool,
        owner_uid: Option<nix::unistd::Uid>,
    ) -> Result<AuthorizedKeys, String> {
        if strict_modes {
            check_mode_strict(path, 0o022, "authorized_keys file", owner_uid)?;
        }
        let body = std::fs::read_to_string(path).map_err(|e| format!("read {path}: {e}"))?;
        Ok(parse_authorized_keys(&body, path))
    }

    /// Parse `authorized_keys` lines (a file's or an `AuthorizedKeysCommand`'s
    /// output); `source` names them in warnings about skipped lines.
    fn parse_authorized_keys(body: &str, source: &str) -> AuthorizedKeys {
        let mut out = AuthorizedKeys::default();
        for (idx, line) in body.lines().enumerate() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            match PublicKey::parse_authorized_keys_line_with_options(trimmed) {
                Ok((blob, opts)) => {
                    if opts.cert_authority {
                        // The option parser yields an empty list both for a
                        // missing `principals=` and for `principals=""`; the
                        // latter must restrict (to nothing), never widen, so
                        // the raw line is consulted for the option's presence.
                        let restricted =
                            !opts.principals.is_empty() || trimmed.contains("principals=");
                        let principals = restricted.then(|| opts.principals.clone());
                        out.cas.push((blob, principals));
                        out.ca_options.push(Arc::new(opts));
                    } else {
                        out.blobs.push(blob);
                        out.options.push(Arc::new(opts));
                    }
                }
                Err(e) => {
                    eprintln!("sshd: skipping {source} line {}: {e}", idx + 1);
                }
            }
        }
        out
    }

    /// Knock keys (a user's authorized keys), read on demand: the knock state
    /// asks for a user's keys only when a well-formed knock names that user,
    /// and caches the answer for 60 s. Any user may knock unless `KnockUsers`
    /// narrows it; users outside it are refused without touching the disk.
    /// Who may actually log in is still decided by the usual access checks
    /// and authentication on the rendezvous connection.
    #[derive(Clone)]
    #[cfg_attr(not(feature = "knock"), allow(dead_code))]
    struct KnockKeys {
        /// `KnockUsers`, or `None` for any user.
        users: Option<Vec<String>>,
        /// `-A` mode: the one user the global file authorizes, and its keys.
        global: Option<(String, Arc<AuthorizedKeys>)>,
        files: Vec<String>,
        strict_modes: bool,
        debug: bool,
    }

    /// Plain keys only: certificate authorities are not knock material, a
    /// knock names a concrete key.
    #[cfg(feature = "knock")]
    impl puressh::knock::KnockKeySource for KnockKeys {
        fn keys_for(&mut self, user: &str) -> Vec<Vec<u8>> {
            if let Some(users) = &self.users
                && !users.iter().any(|u| u == user)
            {
                return Vec::new();
            }
            let keys = match &self.global {
                Some((only, g)) if only == user => g.blobs.clone(),
                Some(_) => Vec::new(),
                None => {
                    load_user_authorized_keys(user, &self.files, self.strict_modes, self.debug)
                        .blobs
                }
            };
            if self.debug {
                eprintln!("sshd: knock: loaded {} key(s) for {user}", keys.len());
            }
            keys
        }
    }

    /// `KnockListen` value → `host:port`, defaulting the port to the SSH one.
    #[cfg(feature = "knock")]
    fn knock_listen_addr(spec: &str, port: u16) -> String {
        if spec.starts_with('[') {
            if spec.contains("]:") {
                spec.to_string()
            } else {
                format!("{spec}:{port}")
            }
        } else if spec.contains("::") || spec.matches(':').count() > 1 {
            format!("[{spec}]:{port}")
        } else if spec.contains(':') {
            spec.to_string()
        } else {
            format!("{spec}:{port}")
        }
    }

    /// The daemon's knock sockets (`docs/knock.md`): UDP knock servers whose
    /// rendezvous connections join the accept loop. Empty when `KnockListen`
    /// is unset; a no-op shell when built without the `knock` feature.
    struct KnockFrontend {
        #[cfg(feature = "knock")]
        servers: Vec<puressh::knock::KnockServer>,
    }

    #[cfg(feature = "knock")]
    impl KnockFrontend {
        /// Bind one knock server per `KnockListen` address, signing ACCEPTs
        /// with the daemon's plain host keys.
        fn bind(
            g: &puressh::config::ServerOptions,
            port: u16,
            keys: KnockKeys,
            host_key_files: &[String],
            debug: bool,
        ) -> Result<Self, String> {
            let servers = Self::bind_servers(g, port, &keys, host_key_files, debug)?;
            Ok(Self { servers })
        }

        fn bind_servers(
            g: &puressh::config::ServerOptions,
            port: u16,
            keys: &KnockKeys,
            host_key_files: &[String],
            debug: bool,
        ) -> Result<Vec<puressh::knock::KnockServer>, String> {
            use puressh::knock::{
                KnockHostKey, KnockServer, KnockServerConfig, KnockState, unix_ms,
            };
            if g.knock_listen.is_empty() {
                return Ok(Vec::new());
            }
            let mut host_keys: Vec<KnockHostKey> = Vec::new();
            for path in host_key_files {
                // Unusable keys were already reported by the main loader.
                let Ok(pem) = std::fs::read_to_string(path) else {
                    continue;
                };
                if let Ok(key) =
                    PrivateKey::parse_openssh_pem(&pem, None).and_then(|k| k.into_host_key_sync())
                {
                    host_keys.push(Arc::from(key));
                }
            }
            let mut cfg = KnockServerConfig::default();
            if let Some(w) = g.knock_window {
                cfg.window_secs = w as u16;
            }
            if let Some(s) = g.knock_clock_skew {
                cfg.clock_skew_ms = s as u64 * 1000;
            }
            if let Some(n) = g.knock_max_pending {
                cfg.max_pending = n;
            }
            match &keys.users {
                Some(u) => eprintln!("sshd: knock: users {u:?} may knock; keys read on demand"),
                None => eprintln!("sshd: knock: any user may knock; keys read on demand"),
            }
            let mut out = Vec::new();
            for spec in &g.knock_listen {
                let addr = knock_listen_addr(spec, port);
                let state =
                    KnockState::new(cfg.clone(), keys.clone(), host_keys.clone(), unix_ms());
                let mut ks = KnockServer::bind(&addr, state)
                    .map_err(|e| format!("knock: bind udp {addr}: {e}"))?;
                if let Some((lo, hi)) = g.knock_ports {
                    ks.set_port_range(lo, hi);
                }
                if debug {
                    ks.set_logger(|ev| eprintln!("sshd: knock: {ev:?}"));
                }
                eprintln!("sshd: knock listening on udp {addr}");
                out.push(ks);
            }
            Ok(out)
        }

        fn next_wakeup(&self) -> Option<std::time::Instant> {
            self.servers.iter().filter_map(|k| k.next_wakeup()).min()
        }

        fn poll_fds(&self) -> Vec<std::os::fd::BorrowedFd<'_>> {
            self.servers.iter().flat_map(|k| k.poll_fds()).collect()
        }

        /// Rendezvous connections that presented their token, with the
        /// knock's user.
        fn process(&mut self) -> Vec<(std::net::TcpStream, std::net::SocketAddr, String)> {
            let mut out = Vec::new();
            for ks in &mut self.servers {
                out.extend(ks.process().into_iter().map(|c| (c.stream, c.peer, c.user)));
            }
            out
        }
    }

    #[cfg(not(feature = "knock"))]
    impl KnockFrontend {
        fn bind(
            g: &puressh::config::ServerOptions,
            _port: u16,
            _keys: KnockKeys,
            _host_key_files: &[String],
            _debug: bool,
        ) -> Result<Self, String> {
            if !g.knock_listen.is_empty() {
                return Err("KnockListen: this sshd was built without the `knock` feature".into());
            }
            Ok(Self {})
        }

        fn next_wakeup(&self) -> Option<std::time::Instant> {
            None
        }

        fn poll_fds(&self) -> Vec<std::os::fd::BorrowedFd<'_>> {
            Vec::new()
        }

        fn process(&mut self) -> Vec<(std::net::TcpStream, std::net::SocketAddr, String)> {
            Vec::new()
        }
    }

    /// OpenSSH's default `RequiredRSASize`.
    const DEFAULT_REQUIRED_RSA_SIZE: u32 = 1024;

    /// Bit length of the modulus of an `ssh-rsa` key blob; `None` for any
    /// other key type (or a malformed blob, which never authenticates).
    fn rsa_modulus_bits(blob: &[u8]) -> Option<usize> {
        match PublicKey::parse_wire_blob(blob).ok()? {
            PublicKey::Rsa { n, .. } => {
                let n: Vec<u8> = n.into_iter().skip_while(|b| *b == 0).collect();
                let lead = *n.first()?;
                Some((n.len() - 1) * 8 + (8 - lead.leading_zeros() as usize))
            }
            _ => None,
        }
    }

    /// Expand every `AuthorizedKeysFile` template for `user` and read the
    /// files that exist, StrictModes-checked against `user`'s uid. Any
    /// failure (unknown user, bad template, StrictModes refusal,
    /// unreadable file) contributes no keys — never a wider set. A file
    /// that simply does not exist is silently skipped, as in OpenSSH.
    fn load_user_authorized_keys(
        user: &str,
        authorized_keys_files: &[String],
        strict_modes: bool,
        debug: bool,
    ) -> AuthorizedKeys {
        let mut out = AuthorizedKeys::default();
        let info = match lookup_user(user) {
            Ok(i) => i,
            Err(e) => {
                if debug {
                    eprintln!("sshd: AuthorizedKeysFile: user lookup failed for {user}: {e}");
                }
                return out;
            }
        };
        for template in authorized_keys_files {
            let path = match expand_pct_tokens(template, &info) {
                Ok(p) => p,
                Err(e) => {
                    if debug {
                        eprintln!("sshd: AuthorizedKeysFile: bad path template {template:?}: {e}");
                    }
                    continue;
                }
            };
            let path = if path.starts_with('/') {
                path
            } else {
                let home = if info.home_str.is_empty() {
                    "/"
                } else {
                    info.home_str.as_str()
                };
                format!("{}/{path}", home.trim_end_matches('/'))
            };
            // A glob names every matching file, as in OpenSSH.
            let paths = puressh::config::glob_paths(&path);
            if paths.is_empty() && debug {
                eprintln!("sshd: AuthorizedKeysFile {path}: not present");
            }
            for path in paths {
                let path = path.to_string_lossy();
                match load_authorized_keys_and_cas(&path, strict_modes, Some(info.uid)) {
                    Ok(set) => {
                        if debug {
                            eprintln!(
                                "sshd: AuthorizedKeysFile {path}: {} key(s), {} cert-authority \
                                 line(s)",
                                set.blobs.len(),
                                set.cas.len()
                            );
                        }
                        out.append(set);
                    }
                    Err(e) => {
                        if debug {
                            eprintln!("sshd: AuthorizedKeysFile {path}: {e}");
                        }
                    }
                }
            }
        }
        out
    }

    /// The longest an `AuthorizedKeysCommand` / `AuthorizedPrincipalsCommand`
    /// may run (OpenSSH bounds it only by LoginGraceTime).
    const AUTH_COMMAND_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);
    /// The most output read from such a command.
    const AUTH_COMMAND_OUTPUT_MAX: usize = 4 << 20;

    /// Expand the `%` tokens of one command argument; `%%` is a literal `%`.
    /// A token the command kind does not define refuses the command, as
    /// OpenSSH refuses the configuration.
    fn expand_command_arg(arg: &str, tokens: &[(char, String)]) -> Result<String, String> {
        let mut out = String::with_capacity(arg.len());
        let mut chars = arg.chars();
        while let Some(c) = chars.next() {
            if c != '%' {
                out.push(c);
                continue;
            }
            match chars.next() {
                Some('%') => out.push('%'),
                Some(t) => match tokens.iter().find(|(k, _)| *k == t) {
                    Some((_, v)) => out.push_str(v),
                    None => return Err(format!("unknown token %{t}")),
                },
                None => return Err("trailing %".into()),
            }
        }
        Ok(out)
    }

    /// A key or certificate blob as command tokens: its SHA256 fingerprint,
    /// base64 encoding and type name.
    fn blob_tokens(blob: &[u8]) -> (String, String, String) {
        use purecrypto::hash::{Digest, Sha256};
        let b64 = purecrypto::der::base64_encode(&Sha256::digest(blob));
        let fp = format!("SHA256:{}", b64.trim_end_matches('='));
        let kind = blob
            .get(..4)
            .map(|l| u32::from_be_bytes([l[0], l[1], l[2], l[3]]) as usize)
            .and_then(|n| blob.get(4..4 + n))
            .and_then(|t| std::str::from_utf8(t).ok())
            .unwrap_or("")
            .to_string();
        (fp, purecrypto::der::base64_encode(blob), kind)
    }

    /// The tokens every authorization command knows: `%C` (client address
    /// and port, server address and port), `%D` (routing domain, none here),
    /// `%h`, `%U` and `%u` (the login user's home, uid and name).
    fn connection_tokens(info: &UserInfo) -> Vec<(char, String)> {
        let endpoints = conn_addrs()
            .map(|(peer, local)| {
                let (lip, lport) =
                    local.map_or((String::new(), 0), |l| (l.ip().to_string(), l.port()));
                format!("{} {} {lip} {lport}", peer.ip(), peer.port())
            })
            .unwrap_or_default();
        vec![
            ('C', endpoints),
            ('D', String::new()),
            ('h', info.home_str.clone()),
            ('U', info.uid.as_raw().to_string()),
            ('u', info.name.clone()),
        ]
    }

    /// Run an `AuthorizedKeysCommand` / `AuthorizedPrincipalsCommand` as
    /// OpenSSH does. `argv[0]` must be an absolute path to a regular file
    /// that, with every directory above it, is owned by root (or by this
    /// daemon's own user when it is not root) and writable by nobody else;
    /// StrictModes off skips that check. The command runs as `run_as`
    /// (`*CommandUser`, required) with the minimal environment OpenSSH gives
    /// it, stdin from `/dev/null` and stderr discarded unless debugging. Its
    /// output counts only when it exits with status 0 within
    /// [`AUTH_COMMAND_TIMEOUT`].
    fn run_auth_command(
        kind: &str,
        argv: &[String],
        run_as: Option<&str>,
        strict_modes: bool,
        debug: bool,
    ) -> Option<String> {
        use std::io::Read;
        use std::os::unix::process::CommandExt;
        let fail = |msg: String| {
            eprintln!("sshd: {kind}: {msg}");
            None
        };
        let program = argv.first()?;
        let Some(run_as) = run_as else {
            return fail(format!("no {kind}User specified, skipping"));
        };
        let info = match lookup_user(run_as) {
            Ok(i) => i,
            Err(e) => return fail(format!("{kind}User {run_as}: {e}")),
        };
        if strict_modes
            && let Err(e) = check_mode_strict(program, 0o022, kind, Some(nix::unistd::geteuid()))
        {
            return fail(e);
        }
        let switch = !already_matches(&info);
        if switch && !nix::unistd::geteuid().is_root() {
            return fail(format!("cannot run as {run_as} without root privileges"));
        }
        if debug {
            eprintln!("sshd: {kind}: running {argv:?} as {run_as}");
        }
        let mut cmd = std::process::Command::new(program);
        cmd.args(&argv[1..])
            .env_clear()
            .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
            .env("USER", &info.name)
            .env("LOGNAME", &info.name)
            .env("HOME", &info.home_str)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(if debug {
                std::process::Stdio::inherit()
            } else {
                std::process::Stdio::null()
            });
        if let Ok(lang) = std::env::var("LANG") {
            cmd.env("LANG", lang);
        }
        if switch {
            let (uid, gid, name_c) = (info.uid, info.gid, info.name_c.clone());
            // SAFETY: runs in the forked child before exec, calling only the
            // same set*id/initgroups sequence as the session drop below.
            unsafe {
                cmd.pre_exec(move || {
                    setgroups_clear().map_err(to_io)?;
                    nix::unistd::setgid(gid).map_err(to_io)?;
                    initgroups_libc(&name_c, gid).map_err(to_io)?;
                    nix::unistd::setuid(uid).map_err(to_io)?;
                    verify_post_setuid(uid, gid).map_err(to_io)?;
                    Ok(())
                });
            }
        }
        let mut child = match cmd.spawn() {
            Ok(c) => c,
            Err(e) => return fail(format!("{program}: {e}")),
        };
        let mut stdout = child.stdout.take()?;
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let mut buf = Vec::new();
            let r = (&mut stdout)
                .take(AUTH_COMMAND_OUTPUT_MAX as u64 + 1)
                .read_to_end(&mut buf);
            let _ = tx.send(r.map(|_| buf));
        });
        let out = match rx.recv_timeout(AUTH_COMMAND_TIMEOUT) {
            Ok(Ok(buf)) if buf.len() <= AUTH_COMMAND_OUTPUT_MAX => Some(buf),
            Ok(Ok(_)) => {
                eprintln!("sshd: {kind}: {program}: output too long");
                None
            }
            Ok(Err(e)) => {
                eprintln!("sshd: {kind}: {program}: read: {e}");
                None
            }
            Err(_) => {
                eprintln!("sshd: {kind}: {program}: timed out");
                None
            }
        };
        if out.is_none() {
            let _ = child.kill();
        }
        let status = child.wait();
        let out = out?;
        match status {
            Ok(st) if st.success() => Some(String::from_utf8_lossy(&out).into_owned()),
            Ok(st) => fail(format!("{program} returned {st}")),
            Err(e) => fail(format!("{program}: wait: {e}")),
        }
    }

    /// Parse `AuthorizedPrincipalsFile` / `AuthorizedPrincipalsCommand` lines:
    /// a principal name, optionally preceded by `authorized_keys` options
    /// (OpenSSH takes the last field as the name). Lines whose options do not
    /// parse are skipped.
    fn parse_principals(body: &str, source: &str) -> Vec<AuthorizedPrincipal> {
        let mut out = Vec::new();
        for (idx, line) in body.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let (opts, name) = match line.rfind([' ', '\t']) {
                None => (Default::default(), line),
                Some(i) => match puressh::key::AuthorizedKeyOptions::parse(line[..i].trim()) {
                    Ok(o) => (o, line[i + 1..].trim()),
                    Err(e) => {
                        eprintln!("sshd: skipping {source} line {}: {e}", idx + 1);
                        continue;
                    }
                },
            };
            out.push(AuthorizedPrincipal {
                name: name.to_string(),
                options: Arc::new(opts),
            });
        }
        out
    }

    /// `AuthorizedKeysCommand` / `AuthorizedPrincipalsCommand` and the users
    /// they run as; an empty command is none.
    #[derive(Clone, Debug, Default)]
    struct AuthCommands {
        keys: Vec<String>,
        keys_user: Option<String>,
        principals: Vec<String>,
        principals_user: Option<String>,
    }

    impl AuthCommands {
        fn from_options(opts: &puressh::config::ServerOptions) -> Self {
            AuthCommands {
                keys: opts.authorized_keys_command.clone().unwrap_or_default(),
                keys_user: opts.authorized_keys_command_user.clone(),
                principals: opts
                    .authorized_principals_command
                    .clone()
                    .unwrap_or_default(),
                principals_user: opts.authorized_principals_command_user.clone(),
            }
        }
    }

    /// One line of an `AuthorizedPrincipalsFile` (or command output).
    #[derive(Clone, Debug)]
    struct AuthorizedPrincipal {
        name: String,
        options: Arc<puressh::key::AuthorizedKeyOptions>,
    }

    /// Whether a `-u` / `AllowUsers` token names exactly one literal user (no
    /// glob metacharacters, no negation, no `@host` half).
    fn is_literal_user_token(token: &str) -> bool {
        !token.is_empty() && !token.contains(['*', '?', '!', '@'])
    }

    /// The effective `AllowUsers` token list for a connection: CLI `-u`
    /// tokens, then the config's (global + matched `Match` blocks). When
    /// nothing is configured the historical puressh default applies — only
    /// the daemon's own user (`$USER`) may log in — and if even that is
    /// unknown the list is a never-matching pattern, i.e. nobody. (An empty
    /// list would mean "no restriction" downstream, which must never happen
    /// by accident.)
    fn effective_allow_users(
        cli: &[String],
        cfg: &[String],
        default_user: Option<&str>,
    ) -> Vec<String> {
        let mut out: Vec<String> = cli.to_vec();
        out.extend(cfg.iter().cloned());
        // Nothing configured ⇒ the default user if one is given, else no
        // restriction at all (an empty list allows everyone).
        if out.is_empty()
            && let Some(u) = default_user
        {
            out.push(u.to_string());
        }
        out
    }

    /// Load and parse a binary KRL (`ssh-keygen -k`). A configured but
    /// unreadable / unparsable file is a hard error — failing closed beats
    /// silently running with no revocation.
    /// Every `RevokedKeys` file, combined.
    fn load_krls(paths: &[String], debug: bool) -> Result<puressh::krl::Krl, String> {
        let mut all = puressh::krl::Krl::new();
        for path in paths {
            all.merge(load_krl(path, debug)?);
        }
        Ok(all)
    }

    /// One `RevokedKeys` file: a binary KRL, or a list of public keys (a
    /// certificate's line revokes its key), as OpenSSH reads either.
    fn load_krl(path: &str, debug: bool) -> Result<puressh::krl::Krl, String> {
        let bytes = std::fs::read(path).map_err(|e| format!("RevokedKeys {path}: {e}"))?;
        let krl = if bytes.starts_with(b"SSHKRL\n\0") {
            puressh::krl::Krl::parse(&bytes)
                .map_err(|e| format!("RevokedKeys {path}: parse failed: {e}"))?
        } else {
            let text = String::from_utf8_lossy(&bytes);
            let mut krl = puressh::krl::Krl::new();
            for line in text.lines().map(str::trim) {
                if line.is_empty() || line.starts_with('#') {
                    continue;
                }
                if let Ok(k) = PublicKey::parse_authorized_keys_line(line) {
                    krl.revoke_key(&k.wire_blob());
                } else if let Ok(c) = puressh::cert::Certificate::parse_openssh_line(line) {
                    krl.revoke_key(c.embedded_pubkey_blob());
                } else {
                    return Err(format!("RevokedKeys {path}: unreadable key line"));
                }
            }
            krl
        };
        if debug {
            eprintln!(
                "sshd: loaded RevokedKeys from {path} ({} bytes, empty={})",
                bytes.len(),
                krl.is_empty()
            );
        }
        Ok(krl)
    }

    /// Load a file of CA public keys (one `authorized_keys`-style key per line),
    /// returning their wire blobs. Used for `TrustedUserCAKeys`.
    fn load_ca_keys_file(path: &str, strict_modes: bool) -> Result<Vec<Vec<u8>>, String> {
        if strict_modes {
            check_owner_mode(path, 0o022, "TrustedUserCAKeys file")?;
        }
        let body = std::fs::read_to_string(path).map_err(|e| format!("read {path}: {e}"))?;
        let mut out = Vec::new();
        for (idx, line) in body.lines().enumerate() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            match PublicKey::parse_authorized_keys_line(trimmed) {
                Ok(k) => out.push(k.wire_blob()),
                Err(e) => eprintln!("sshd: skipping TrustedUserCAKeys line {}: {e}", idx + 1),
            }
        }
        Ok(out)
    }

    /// Load an `AuthorizedPrincipalsFile` (see [`parse_principals`]).
    fn load_principals_file(
        path: &str,
        strict_modes: bool,
        owner_uid: Option<nix::unistd::Uid>,
    ) -> Result<Vec<AuthorizedPrincipal>, String> {
        if strict_modes {
            check_mode_strict(path, 0o022, "AuthorizedPrincipalsFile", owner_uid)?;
        }
        let body = std::fs::read_to_string(path).map_err(|e| format!("read {path}: {e}"))?;
        Ok(parse_principals(&body, path))
    }

    /// Longest peer-controlled string echoed into a log line.
    const LOG_FIELD_MAX: usize = 128;

    /// Make a peer-controlled string safe to print in a log line: every
    /// control byte (`< 0x20` and `0x7f`) becomes `?` so a client cannot forge
    /// log lines / move the terminal cursor with embedded `\n`, `\r`, or
    /// escape sequences, and the result is truncated to [`LOG_FIELD_MAX`]
    /// characters (with a `…` marker) so a multi-kilobyte username cannot
    /// flood the log.
    fn sanitize_log(s: &str) -> String {
        let mut out = String::with_capacity(s.len().min(LOG_FIELD_MAX + 1));
        for (i, c) in s.chars().enumerate() {
            if i >= LOG_FIELD_MAX {
                out.push('…');
                break;
            }
            if c.is_control() {
                out.push('?');
            } else {
                out.push(c);
            }
        }
        out
    }

    /// Longest username accepted on the wire, in bytes. POSIX login names are
    /// far shorter (`LOGIN_NAME_MAX` is 256 on Linux including the NUL); a
    /// longer one cannot name a real account and is refused up front.
    const USERNAME_MAX: usize = 255;

    /// Whether a username received in a USERAUTH_REQUEST is acceptable at all:
    /// non-empty, at most [`USERNAME_MAX`] bytes, and free of control
    /// characters (which could never be a passwd name and would otherwise be
    /// echoed into log lines). Rejected names never reach access control, the
    /// passwd lookup, or the debug logs unsanitised.
    fn valid_username(user: &str) -> bool {
        !user.is_empty() && user.len() <= USERNAME_MAX && !user.chars().any(|c| c.is_control())
    }

    /// Decode an SSH `string` (4-byte BE length + bytes) into UTF-8. Used for
    /// the inner payload of certificate critical options (`force-command`,
    /// `source-address`), which are themselves length-prefixed strings.
    fn decode_ssh_string(data: &[u8]) -> Option<String> {
        if data.len() < 4 {
            return None;
        }
        let len = u32::from_be_bytes([data[0], data[1], data[2], data[3]]) as usize;
        if data.len() != 4 + len {
            return None;
        }
        std::str::from_utf8(&data[4..]).ok().map(|s| s.to_string())
    }

    /// Parse a peer descriptor (`"ip:port"`, `"[v6]:port"`, or a bare IP) into
    /// an `IpAddr`. Returns `None` if no IP can be recovered.
    fn parse_peer_ip(peer: &str) -> Option<std::net::IpAddr> {
        // Try the full socket-addr form first, then a bracketed v6, then bare.
        if let Ok(sa) = peer.parse::<std::net::SocketAddr>() {
            return Some(sa.ip());
        }
        if let Some(inner) = peer.strip_prefix('[').and_then(|s| s.split(']').next())
            && let Ok(ip) = inner.parse()
        {
            return Some(ip);
        }
        if let Some((host, _port)) = peer.rsplit_once(':')
            && let Ok(ip) = host.parse()
        {
            return Some(ip);
        }
        peer.parse().ok()
    }

    /// Does `ip` fall within `cidr` (e.g. `"10.0.0.0/8"`, `"192.168.1.5"`,
    /// `"2001:db8::/32"`)? A bare address with no `/` is treated as a `/32`
    /// (v4) or `/128` (v6) exact match. Address-family mismatches never match.
    fn cidr_matches(cidr: &str, ip: std::net::IpAddr) -> bool {
        use std::net::IpAddr;
        let (net_str, prefix_str) = match cidr.split_once('/') {
            Some((n, p)) => (n, Some(p)),
            None => (cidr, None),
        };
        let Ok(net) = net_str.parse::<IpAddr>() else {
            return false;
        };
        match (net, ip) {
            (IpAddr::V4(net), IpAddr::V4(ip)) => {
                let bits: u32 = match prefix_str {
                    Some(p) => match p.parse() {
                        Ok(b) if b <= 32 => b,
                        _ => return false,
                    },
                    None => 32,
                };
                let mask = if bits == 0 {
                    0
                } else {
                    u32::MAX << (32 - bits)
                };
                (u32::from(net) & mask) == (u32::from(ip) & mask)
            }
            (IpAddr::V6(net), IpAddr::V6(ip)) => {
                let bits: u32 = match prefix_str {
                    Some(p) => match p.parse() {
                        Ok(b) if b <= 128 => b,
                        _ => return false,
                    },
                    None => 128,
                };
                let net = u128::from(net);
                let ip = u128::from(ip);
                let mask = if bits == 0 {
                    0
                } else {
                    u128::MAX << (128 - bits)
                };
                (net & mask) == (ip & mask)
            }
            _ => false,
        }
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
            let user_ok = puressh::config::host_matches(core::slice::from_ref(&self.user), user);
            if !user_ok {
                return false;
            }
            match &self.host {
                None => true,
                Some(h) => match peer {
                    Some(p) => puressh::config::host_matches(core::slice::from_ref(h), p),
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
        /// `-A FILE`: the one global authorized_keys set, loaded at startup
        /// for the single allowed user. `None` ⇒ per-user files.
        global_authorized_keys: Option<Arc<AuthorizedKeys>>,
        /// `AuthorizedKeysFile` path templates in force for this connection
        /// (`%u`/`%h`/`%%` tokens; relative ⇒ under the user's home).
        authorized_keys_files: Vec<String>,
        /// The bound user's authorized keys, loaded lazily on the first
        /// publickey attempt (see [`Self::resolved_authorized_keys`]). `None`
        /// until then.
        authorized_keys: Option<AuthorizedKeys>,
        /// The options of the `authorized_keys` line that accepted the last
        /// publickey attempt, for [`Authenticator::key_restrictions`].
        accepted_options: Option<Arc<puressh::key::AuthorizedKeyOptions>>,
        /// CA public-key blobs from `TrustedUserCAKeys` (the file in force for
        /// this connection). A user cert signed by one of these is CA-trusted;
        /// principal authorization is checked separately. CAs from the user's
        /// own `authorized_keys` `cert-authority` lines live in
        /// `authorized_keys` and are trusted for that user only.
        trusted_user_ca_blobs: Vec<Vec<u8>>,
        /// Parsed `RevokedKeys` KRL in force for this connection (shared,
        /// read-only). `None` ⇒ no revocation list. A publickey / certificate
        /// the KRL covers is refused regardless of any other trust.
        revoked_keys: Option<Arc<puressh::krl::Krl>>,
        /// The parsed `sshd_config` plus the startup inputs needed to re-derive
        /// the access policy per connection from `Match` blocks
        /// (`on_user_resolved`). `None` ⇒ no config file / unit tests: the
        /// fields above stay at their global values.
        policy: Option<Arc<ConnPolicy>>,
        /// Set when the per-connection policy names a `TrustedUserCAKeys` /
        /// `RevokedKeys` file that was not preloaded at startup. Cannot happen
        /// for a config the daemon itself loaded; if it does, every attempt on
        /// this connection is refused rather than evaluated with a partial
        /// trust / revocation set.
        policy_broken: bool,
        /// `AuthorizedPrincipalsFile` path *template* (may contain `%u`/`%h`/
        /// `%%` tokens), or `None` when no file is configured. Resolved and
        /// loaded lazily per connection once the login user is known (the home
        /// directory needed for `%h` is only knowable then). See
        /// [`Self::resolved_principals`].
        authorized_principals_file: Option<String>,
        /// StrictModes ownership/permission check for the principals file.
        strict_modes: bool,
        /// Lazily-resolved `AuthorizedPrincipalsFile` contents for the bound
        /// user: `None` until first resolved; the inner `Option` is `None` when
        /// no file is configured (login user must itself be a cert principal,
        /// the OpenSSH default) or `Some(list)` of the file's lines.
        authorized_principals: Option<Option<Vec<AuthorizedPrincipal>>>,
        /// `AuthorizedKeysCommand` / `AuthorizedPrincipalsCommand` in force.
        auth_commands: AuthCommands,
        /// Their outputs on this connection, by expanded command line.
        command_cache: std::collections::BTreeMap<Vec<String>, Option<String>>,
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
        /// Live multi-step keyboard-interactive PAM conversation, if one is in
        /// flight. The PAM `Context` runs on a worker thread; this holds the
        /// channel ends + join handle (see `pam_gate::KbdConversation`). `Some`
        /// between the first `keyboard-interactive` request and the terminal
        /// PAM verdict; reset to `None` on accept/reject so a fresh attempt
        /// starts a new conversation. Dropping it tears the worker down.
        kbd_conv: Option<pam_gate::KbdConversation>,
        /// True while the next keyboard-interactive answer would be the FIRST
        /// of a conversation, so the empty-password policy applies to it; reset
        /// once the opening answer is consumed, and re-armed when a new
        /// conversation starts.
        pending_first_prompt: bool,
        /// `PermitEmptyPasswords` — when false (the default), an empty password
        /// is rejected without ever consulting PAM.
        permit_empty_passwords: bool,
        /// `PubkeyAcceptedAlgorithms`: signature algorithms accepted for
        /// publickey auth. `None` ⇒ everything the auth layer verifies.
        pubkey_accepted: Option<Vec<String>>,
        /// `RequiredRSASize`: minimum RSA modulus bits for user keys.
        required_rsa_size: u32,
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
                    .any(|g| puressh::config::host_matches(pats, g))
            };

            // 0. A knocked connection is bound to the knock's user.
            if knock_user().is_some_and(|k| k != user) {
                return false;
            }
            // OpenSSH says why an existing user is refused, once.
            let refuse = |why: &str| {
                sshd_log::with_conn(|c| {
                    if c.invalid_prefix().is_empty() && c.first("not allowed") {
                        let ip = peer.and_then(parse_peer_ip).map(sshd_log::addr_str);
                        sshd_log::info(&format!(
                            "User {user} from {} not allowed because {why}",
                            ip.unwrap_or_default()
                        ));
                    }
                });
                false
            };
            // 1. DenyUsers wins outright.
            if !self.deny_users.is_empty() && user_host_list_matches(&self.deny_users, user, peer) {
                return refuse("listed in DenyUsers");
            }
            // 2. AllowUsers: if set, the user must match one.
            if !self.allow_users.is_empty()
                && !user_host_list_matches(&self.allow_users, user, peer)
            {
                return refuse("not listed in AllowUsers");
            }
            // 3. DenyGroups: a matching group refuses.
            if !self.deny_groups.is_empty() && in_group(&self.deny_groups) {
                return refuse("a group is listed in DenyGroups");
            }
            // 4. AllowGroups: if set, the user must be in a matching group.
            if !self.allow_groups.is_empty() && !in_group(&self.allow_groups) {
                return refuse("none of user's groups are listed in AllowGroups");
            }
            true
        }

        /// `ROOT LOGIN REFUSED FROM …`, once, when PermitRootLogin refuses.
        fn log_root_refused(&self, denied: bool) {
            if denied {
                sshd_log::with_conn(|c| {
                    if c.first("root refused") {
                        sshd_log::info(&format!("ROOT LOGIN REFUSED FROM {}", c.peer()));
                    }
                });
            }
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

        /// Trust decision for a verified user certificate: the CA must be in
        /// our trusted set, the login `user` must be an authorized principal,
        /// and any `source-address` critical option must admit the peer.
        ///
        /// The CA signature, cert type, validity and critical-option
        /// understanding were already enforced by the auth layer before this is
        /// reached; this is purely the trust + authorization gate.
        fn cert_trusted(
            &mut self,
            ci: &puressh::auth::CertInfo,
            user: &str,
            cert_blob: &[u8],
        ) -> bool {
            // 0. KRL revocation wins outright: a cert whose (CA, serial) or
            //    (CA, key-id) the KRL covers — or whose CA key itself is
            //    revoked as a plain key — is refused before any trust check.
            if let Some(krl) = self.revoked_keys.as_ref() {
                if krl.is_revoked_cert(&ci.ca_key_blob, ci.serial, &ci.key_id) {
                    if self.debug {
                        eprintln!(
                            "sshd: cert auth: certificate revoked by KRL (serial {}, key-id {:?})",
                            ci.serial, ci.key_id
                        );
                    }
                    return false;
                }
                if krl.is_revoked_key(&ci.ca_key_blob) {
                    if self.debug {
                        eprintln!("sshd: cert auth: signing CA key revoked by KRL");
                    }
                    return false;
                }
            }

            // 1 + 2. Is the signing CA trusted, and is the login user an
            //        authorized principal? Two independent routes, either of
            //        which suffices (OpenSSH tries authorized_keys first, then
            //        TrustedUserCAKeys):
            //
            //   a. a `cert-authority` line of the user's authorized_keys (or
            //      AuthorizedKeysCommand output) names this CA. With a
            //      `principals="..."` option the cert must carry a listed
            //      principal; without one, the login name, unless the cert
            //      lists no principals at all.
            //   b. the CA is in `TrustedUserCAKeys` and the cert lists
            //      principals: one of them must be in AuthorizedPrincipalsFile
            //      / AuthorizedPrincipalsCommand output when either is
            //      configured, otherwise the login name must be.
            //
            // Both routes are evaluated unconditionally so the cost does not
            // depend on which one decides.
            let peer = self.peer.clone();
            let debug = self.debug;
            let mut set = self.resolved_authorized_keys(user).clone();
            if let Some(more) = self.command_keys(user, cert_blob) {
                set.append(more);
            }
            let ca_line = set.cas.iter().enumerate().find(|(i, (blob, principals))| {
                *blob == ci.ca_key_blob
                    && set
                        .ca_options
                        .get(*i)
                        .is_none_or(|o| key_line_applies(o, peer.as_deref(), debug))
                    && match principals {
                        Some(list) => principals_match_option(list, &ci.valid_principals),
                        // A certificate without principals is refused, as
                        // OpenSSH refuses it.
                        None => ci.valid_principals.iter().any(|p| p == user),
                    }
            });
            let ca_opts = ca_line.map(|(i, _)| set.ca_options.get(i).cloned().unwrap_or_default());
            let global_trusted = self.trusted_user_ca_blobs.contains(&ci.ca_key_blob);
            let principal = self.cert_principal_line(ci, user, cert_blob);
            let global_ok = global_trusted && principal.is_some();
            if ca_opts.is_none() && !global_trusted {
                if self.debug {
                    eprintln!(
                        "sshd: cert auth: signing CA is not trusted for {user} (key-id {:?})",
                        ci.key_id
                    );
                }
                return false;
            }
            if ca_opts.is_none() && !global_ok {
                if self.debug {
                    eprintln!("sshd: cert auth: user {user} not an authorized principal");
                }
                return false;
            }
            // The options in force: the cert-authority line's, else those of
            // the principals line that matched.
            self.accepted_options = ca_opts.or_else(|| principal.flatten());

            // 3. source-address critical option (if present) must admit the peer.
            if let Some(data) = ci.critical_option("source-address") {
                let allowed_cidrs = decode_ssh_string(data);
                let peer_ip = self.peer.as_deref().and_then(parse_peer_ip);
                let ok = match (allowed_cidrs, peer_ip) {
                    (Some(list), Some(ip)) => list
                        .split(',')
                        .filter(|s| !s.is_empty())
                        .any(|cidr| cidr_matches(cidr.trim(), ip)),
                    // Option present but we can't determine the peer, or the
                    // option payload is malformed → fail closed.
                    _ => false,
                };
                if !ok {
                    if self.debug {
                        eprintln!("sshd: cert auth: peer not in source-address for {user}");
                    }
                    return false;
                }
            }
            true
        }

        /// The `TrustedUserCAKeys` principal rule. A certificate without
        /// principals is refused. With an AuthorizedPrincipalsFile or
        /// AuthorizedPrincipalsCommand, a line that applies to this
        /// connection must name one of the certificate's principals: returns
        /// `Some(Some(options))` of that line. Without either, the login name
        /// must be a principal: `Some(None)`.
        fn cert_principal_line(
            &mut self,
            ci: &puressh::auth::CertInfo,
            user: &str,
            cert_blob: &[u8],
        ) -> Option<Option<Arc<puressh::key::AuthorizedKeyOptions>>> {
            if ci.valid_principals.is_empty() {
                if self.debug {
                    eprintln!("sshd: cert auth: certificate lacks principal list");
                }
                return None;
            }
            let peer = self.peer.clone();
            let debug = self.debug;
            let mut lines = self.resolved_principals(user).clone();
            if let Some(more) = self.command_principals(user, ci, cert_blob) {
                lines.get_or_insert_with(Vec::new).extend(more);
            }
            match lines {
                None => ci
                    .valid_principals
                    .iter()
                    .any(|p| p == user)
                    .then_some(None),
                Some(lines) => lines
                    .into_iter()
                    .find(|l| {
                        ci.valid_principals.contains(&l.name)
                            && key_line_applies(&l.options, peer.as_deref(), debug)
                    })
                    .map(|l| Some(l.options)),
            }
        }

        /// `AuthorizedKeysCommand` output for `user` and the offered key or
        /// certificate `blob`, parsed; `None` when no command is configured
        /// or it fails. Runs are cached per expanded command line, so the
        /// probe and the signed attempt run it once.
        fn command_keys(&mut self, user: &str, blob: &[u8]) -> Option<AuthorizedKeys> {
            let template = self.auth_commands.keys.clone();
            if template.is_empty() {
                return None;
            }
            let info = lookup_user(user).ok()?;
            let (fp, b64, kind) = blob_tokens(blob);
            let mut tokens = connection_tokens(&info);
            tokens.extend([('f', fp), ('k', b64), ('t', kind)]);
            let mut argv = self.expand_command("AuthorizedKeysCommand", &template, &tokens)?;
            // No arguments: the user name, as OpenSSH has always passed it.
            if argv.len() == 1 {
                argv.push(info.name.clone());
            }
            let user_opt = self.auth_commands.keys_user.clone();
            let out = self.run_cached("AuthorizedKeysCommand", argv, user_opt)?;
            Some(parse_authorized_keys(&out, "AuthorizedKeysCommand output"))
        }

        /// `AuthorizedPrincipalsCommand` output for a certificate, parsed.
        fn command_principals(
            &mut self,
            user: &str,
            ci: &puressh::auth::CertInfo,
            cert_blob: &[u8],
        ) -> Option<Vec<AuthorizedPrincipal>> {
            let template = self.auth_commands.principals.clone();
            if template.is_empty() {
                return None;
            }
            let info = lookup_user(user).ok()?;
            let (fp, b64, kind) = blob_tokens(cert_blob);
            let (ca_fp, ca_b64, ca_kind) = blob_tokens(&ci.ca_key_blob);
            let mut tokens = connection_tokens(&info);
            tokens.extend([
                ('f', fp),
                ('k', b64),
                ('t', kind),
                ('F', ca_fp),
                ('K', ca_b64),
                ('T', ca_kind),
                ('i', ci.key_id.clone()),
                ('s', ci.serial.to_string()),
            ]);
            let argv = self.expand_command("AuthorizedPrincipalsCommand", &template, &tokens)?;
            let user_opt = self.auth_commands.principals_user.clone();
            let out = self.run_cached("AuthorizedPrincipalsCommand", argv, user_opt)?;
            Some(parse_principals(&out, "AuthorizedPrincipalsCommand output"))
        }

        /// Expand a command's arguments (not the program path).
        fn expand_command(
            &self,
            kind: &str,
            template: &[String],
            tokens: &[(char, String)],
        ) -> Option<Vec<String>> {
            let mut argv = vec![template[0].clone()];
            for arg in &template[1..] {
                match expand_command_arg(arg, tokens) {
                    Ok(a) => argv.push(a),
                    Err(e) => {
                        eprintln!("sshd: {kind}: {arg:?}: {e}");
                        return None;
                    }
                }
            }
            Some(argv)
        }

        /// [`run_auth_command`], once per connection for a given command line.
        fn run_cached(
            &mut self,
            kind: &str,
            argv: Vec<String>,
            run_as: Option<String>,
        ) -> Option<String> {
            if let Some(out) = self.command_cache.get(&argv) {
                return out.clone();
            }
            let out = run_auth_command(
                kind,
                &argv,
                run_as.as_deref(),
                self.strict_modes,
                self.debug,
            );
            self.command_cache.insert(argv, out.clone());
            out
        }

        /// The bound user's authorized keys, loaded on first use: the global
        /// `-A` set when one is configured, otherwise every
        /// `AuthorizedKeysFile` template expanded and read for `user`.
        fn resolved_authorized_keys(&mut self, user: &str) -> &AuthorizedKeys {
            if self.authorized_keys.is_none() {
                let set = match &self.global_authorized_keys {
                    Some(g) => (**g).clone(),
                    None => self.load_authorized_keys_for(user),
                };
                self.authorized_keys = Some(set);
            }
            // Safe: just populated above.
            self.authorized_keys.as_ref().unwrap()
        }

        /// Whether `blob` is authorized for `user` by a line that applies to
        /// this connection (`from=`, `expiry-time=`); that line's options are
        /// kept for [`Authenticator::key_restrictions`].
        fn key_authorized(&mut self, user: &str, blob: &[u8]) -> bool {
            let peer = self.peer.clone();
            let debug = self.debug;
            let find = |set: &AuthorizedKeys| {
                set.blobs
                    .iter()
                    .enumerate()
                    .find(|(i, b)| {
                        b.as_slice() == blob
                            && set
                                .options
                                .get(*i)
                                .is_none_or(|o| key_line_applies(o, peer.as_deref(), debug))
                    })
                    .map(|(i, _)| set.options.get(i).cloned().unwrap_or_default())
            };
            // The files first, then AuthorizedKeysCommand, as OpenSSH.
            let mut opts = find(self.resolved_authorized_keys(user));
            if opts.is_none()
                && let Some(set) = self.command_keys(user, blob)
            {
                opts = find(&set);
            }
            let ok = opts.is_some();
            self.accepted_options = opts;
            ok
        }

        /// [`load_user_authorized_keys`] with this connection's settings.
        fn load_authorized_keys_for(&self, user: &str) -> AuthorizedKeys {
            load_user_authorized_keys(
                user,
                &self.authorized_keys_files,
                self.strict_modes,
                self.debug,
            )
        }

        /// Re-derive the per-connection access policy from the `sshd_config`
        /// `Match` blocks that apply to `(user, groups, peer, local socket)`,
        /// replacing the global values this authenticator was built with.
        /// Called once, from `on_user_resolved`, before the first attempt is
        /// evaluated.
        fn apply_conn_policy(&mut self, pol: &ConnPolicy, user: &str) {
            let groups = match self.group_cache.get(user) {
                Some(g) => g.clone(),
                None => {
                    let g = (self.group_lookup)(user);
                    self.group_cache.insert(user.to_string(), g.clone());
                    g
                }
            };
            let opts = resolve_conn_options(&pol.config, user, &groups, self.peer.as_deref());

            self.allow_users = UserHostPattern::parse_all(&effective_allow_users(
                &pol.cli_allow_users,
                &opts.allow_users,
                pol.default_allow_user.as_deref(),
            ));
            self.deny_users = UserHostPattern::parse_all(&opts.deny_users);
            self.allow_groups = puressh::config::HostPattern::parse_all(&opts.allow_groups);
            self.deny_groups = puressh::config::HostPattern::parse_all(&opts.deny_groups);
            self.permit_root_login = pol
                .cli_permit_root_login
                .or(opts.permit_root_login)
                .unwrap_or(puressh::config::PermitRootLogin::ProhibitPassword);
            self.permit_empty_passwords = opts.permit_empty_passwords == Some(true);
            self.pubkey_accepted = opts.pubkey_accepted_algorithms.clone();
            self.required_rsa_size = opts.required_rsa_size.unwrap_or(DEFAULT_REQUIRED_RSA_SIZE);
            self.auth_commands = AuthCommands::from_options(&opts);
            self.command_cache.clear();
            self.authorized_principals_file = opts.authorized_principals_file;
            self.authorized_principals = None;
            if self.global_authorized_keys.is_none() {
                self.authorized_keys_files = opts
                    .authorized_keys_file
                    .unwrap_or_else(default_authorized_keys_files);
                self.authorized_keys = None;
            }
            self.trusted_user_ca_blobs = match &opts.trusted_user_ca_keys {
                None => Vec::new(),
                Some(path) => match pol.ca_files.get(path) {
                    Some(cas) => (**cas).clone(),
                    None => {
                        eprintln!("sshd: TrustedUserCAKeys {path}: not preloaded; refusing auth");
                        self.policy_broken = true;
                        Vec::new()
                    }
                },
            };
            self.revoked_keys = match &opts.revoked_keys {
                None => None,
                Some(paths) if paths.is_empty() => None,
                Some(path) => match pol.krls.get(path) {
                    Some(k) => Some(k.clone()),
                    None => {
                        eprintln!("sshd: RevokedKeys {path:?}: not preloaded; refusing auth");
                        self.policy_broken = true;
                        None
                    }
                },
            };
        }

        /// Resolve (and cache) the `AuthorizedPrincipalsFile` contents for the
        /// login `user`, expanding `%u`/`%h`/`%%` tokens in the configured path
        /// template against the user's passwd entry. Loaded at most once per
        /// connection.
        ///
        /// Returns a reference to the cached value: `None` ⇒ no file configured
        /// (the login user must itself be a cert principal — OpenSSH default);
        /// `Some(list)` ⇒ the principal names the file grants. A file that is
        /// configured but unreadable / fails StrictModes / has an unexpandable
        /// path resolves to `Some(vec![])` (no principals), which fails the
        /// authorization closed rather than silently widening it.
        fn resolved_principals(&mut self, user: &str) -> &Option<Vec<AuthorizedPrincipal>> {
            if self.authorized_principals.is_none() {
                let template = self
                    .authorized_principals_file
                    .clone()
                    .filter(|t| !t.eq_ignore_ascii_case("none"));
                let resolved = template.map(|t| self.load_principals_for(&t, user));
                self.authorized_principals = Some(resolved);
            }
            // Safe: just populated above.
            self.authorized_principals.as_ref().unwrap()
        }

        /// Expand a principals-file path template for `user` and load it,
        /// returning its lines (empty on any failure — fail closed).
        fn load_principals_for(&self, template: &str, user: &str) -> Vec<AuthorizedPrincipal> {
            let info = match lookup_user(user) {
                Ok(i) => i,
                Err(e) => {
                    if self.debug {
                        eprintln!(
                            "sshd: AuthorizedPrincipalsFile: user lookup failed for {user}: {e}"
                        );
                    }
                    return Vec::new();
                }
            };
            let path = match expand_pct_tokens(template, &info) {
                Ok(p) => p,
                Err(e) => {
                    if self.debug {
                        eprintln!("sshd: AuthorizedPrincipalsFile: bad path template: {e}");
                    }
                    return Vec::new();
                }
            };
            let path = if path.starts_with('/') {
                path
            } else {
                format!("{}/{path}", info.home_str.trim_end_matches('/'))
            };
            // A glob names every matching file, read in order, as in OpenSSH.
            let mut out = Vec::new();
            for file in puressh::config::glob_paths(&path) {
                let file = file.to_string_lossy();
                match load_principals_file(&file, self.strict_modes, Some(info.uid)) {
                    Ok(list) => out.extend(list),
                    Err(e) => {
                        if self.debug {
                            eprintln!("sshd: AuthorizedPrincipalsFile {file}: {e}");
                        }
                    }
                }
            }
            out
        }

        /// Bind / verify the connection username. Returns `false` if the client
        /// switched usernames mid-userauth (OpenSSH rejects this). The first
        /// call binds; subsequent calls must match.
        ///
        /// A syntactically invalid username (see [`valid_username`]) never
        /// binds and always returns `false`, so no later step logs or resolves
        /// it.
        fn check_user_binding(&mut self, user: &str) -> bool {
            if !valid_username(user) {
                if self.debug {
                    eprintln!(
                        "sshd: auth: refusing invalid username {:?}",
                        sanitize_log(user)
                    );
                }
                return false;
            }
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
            self.log_root_refused(root_denied);

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

        /// Pull the next step from the live keyboard-interactive PAM
        /// conversation and translate it into an [`AuthDecision`].
        ///
        /// - A `Prompt` becomes an `InteractiveRequest` carrying that single
        ///   prompt (and any instruction/info text PAM emitted before it). The
        ///   conversation stays open; the client's answer arrives in the next
        ///   `evaluate_interactive`.
        /// - A terminal `Done(ok)` ends the conversation: the worker is torn
        ///   down (by clearing `kbd_conv`). On `ok` the same access-control +
        ///   PermitRootLogin gates as the password path are ANDed in, and a
        ///   pass yields the chain-aware verdict via `record_and_decide`. Any
        ///   failure yields `Reject`.
        fn kbd_pump(&mut self, user: &str) -> AuthDecision {
            let step = match self.kbd_conv.as_mut() {
                Some(c) => c.next(),
                None => return AuthDecision::Reject,
            };
            match step {
                pam_gate::KbdStep::Prompt {
                    instruction,
                    prompt,
                    echo,
                } => AuthDecision::InteractiveRequest {
                    name: String::new(),
                    instruction,
                    prompts: vec![(prompt, echo)],
                },
                pam_gate::KbdStep::Done(ok) => {
                    // Conversation finished; drop the worker.
                    self.kbd_conv = None;
                    if !ok {
                        if self.debug {
                            eprintln!("sshd: auth keyboard-interactive: PAM rejected user {user}");
                        }
                        return AuthDecision::Reject;
                    }
                    // PAM accepted. AND in the access + root gates (the same
                    // ones the password path applies). Resolve both uniformly.
                    let user_ok = self.access_allowed(user);
                    let is_root = self.is_root(user);
                    let root_denied = is_root && !self.permit_root_login.permits_password();
                    self.log_root_refused(root_denied);
                    if user_ok && !root_denied {
                        if self.debug {
                            eprintln!("sshd: auth keyboard-interactive: accepted user {user}");
                        }
                        self.record_and_decide("keyboard-interactive")
                    } else {
                        if self.debug {
                            if root_denied {
                                eprintln!(
                                    "sshd: auth keyboard-interactive: root login denied by PermitRootLogin for {user}"
                                );
                            } else {
                                eprintln!(
                                    "sshd: auth keyboard-interactive: user {user} not in allowed set"
                                );
                            }
                        }
                        AuthDecision::Reject
                    }
                }
            }
        }

        /// Record a satisfied factor and decide whether authentication is
        /// complete given the per-user multi-factor chain set, enforcing
        /// **positional (listed) order** as OpenSSH does.
        ///
        /// - No chains configured ⇒ single-factor: any one method accepts.
        /// - The methods must be completed in the order the chain lists them: a
        ///   chain stays *alive* only while the ordered `satisfied` sequence is
        ///   a positional prefix of it. Completing a method that no alive chain
        ///   expects *next* is out-of-order and is rejected (the method is not
        ///   committed to `satisfied`).
        /// - When some alive chain is fully covered (its length equals the
        ///   satisfied length) ⇒ Accept.
        /// - Otherwise ⇒ PartialAccept whose `still_required` is the set of the
        ///   *next* methods (`chain[satisfied.len()]`) across every alive chain
        ///   — never the whole remaining set.
        ///
        /// `none` is never recorded and never appears in a parsed chain.
        fn record_and_decide(&mut self, method: &'static str) -> AuthDecision {
            // Single-factor: no chains ⇒ one success is enough.
            if self.chains.is_empty() {
                return AuthDecision::Accept;
            }

            if method == "none" {
                // `none` cannot advance a chain; re-offer the current step.
                return self.partial_or_reject_for_current();
            }

            // Tentatively extend the ordered satisfied sequence and require the
            // result to remain a positional prefix of at least one chain. If
            // not, the just-completed method was offered out of order (or isn't
            // part of any chain) ⇒ reject without committing it.
            let candidate_len = self.satisfied.len() + 1;
            let mut any_alive = false;
            for chain in &self.chains {
                if chain.len() >= candidate_len
                    && chain[..self.satisfied.len()] == self.satisfied[..]
                    && chain[self.satisfied.len()] == method
                {
                    any_alive = true;
                    break;
                }
            }
            if !any_alive {
                if self.debug {
                    eprintln!(
                        "sshd: auth: method {method} completed out of order for the configured \
                         AuthenticationMethods chain(s); rejecting"
                    );
                }
                return AuthDecision::Reject;
            }
            self.satisfied.push(method);

            self.partial_or_reject_for_current()
        }

        /// Given the current ordered `satisfied` prefix, decide Accept (some
        /// alive chain is fully covered) or PartialAccept with the next-needed
        /// methods across alive chains. A chain is *alive* iff `satisfied` is a
        /// positional prefix of it. Never returns Reject here (callers handle
        /// the out-of-order reject before committing).
        fn partial_or_reject_for_current(&self) -> AuthDecision {
            let is_alive = |chain: &[&'static str]| -> bool {
                chain.len() >= self.satisfied.len()
                    && chain[..self.satisfied.len()] == self.satisfied[..]
            };

            // Any alive chain fully covered ⇒ done.
            if self
                .chains
                .iter()
                .any(|c| is_alive(c) && c.len() == self.satisfied.len())
            {
                return AuthDecision::Accept;
            }

            // Offer only the *next* method of each alive chain (positional).
            let mut next: Vec<String> = Vec::new();
            for chain in &self.chains {
                if is_alive(chain) && chain.len() > self.satisfied.len() {
                    let s = chain[self.satisfied.len()].to_string();
                    if !next.contains(&s) {
                        next.push(s);
                    }
                }
            }
            AuthDecision::PartialAccept {
                still_required: next,
            }
        }

        /// Log an attempt's outcome as OpenSSH does: `Accepted …` (and the
        /// connection is authenticated), `Partial …`, `Failed …` — at INFO
        /// for an invalid user or a password, VERBOSE otherwise. A probe
        /// that a key is acceptable is not an outcome.
        fn log_decision(&mut self, note: &AttemptNote, decision: &AuthDecision) {
            let _ = self;
            sshd_log::with_conn(|c| {
                let peer = c.peer();
                let (user, key) = (&note.user, &note.key);
                match decision {
                    AuthDecision::Accept if !note.probe => {
                        sshd_log::info(&format!(
                            "Accepted {} for {user} from {peer} ssh2{key}",
                            note.method
                        ));
                    }
                    AuthDecision::PartialAccept { .. } if !note.probe => {
                        sshd_log::verbose(&format!(
                            "Partial {} for {user} from {peer} ssh2{key}",
                            note.method
                        ));
                    }
                    AuthDecision::Reject => {
                        let invalid = c.invalid_prefix();
                        let level = if sshd_log::failure_is_loud(c, note.method) {
                            sshd_log::Level::Info
                        } else {
                            sshd_log::Level::Verbose
                        };
                        if note.method != "none" {
                            c.failures += 1;
                        }
                        sshd_log::log(
                            level,
                            &format!(
                                "Failed {} for {invalid}{user} from {peer} ssh2{key}",
                                note.method
                            ),
                        );
                    }
                    _ => {}
                }
            });
            if matches!(decision, AuthDecision::Accept) && !note.probe {
                sshd_log::conn_authenticated();
            }
        }
    }

    /// What an auth attempt's log line names.
    struct AttemptNote {
        /// `none`, `password`, `publickey`, `keyboard-interactive/pam`.
        method: &'static str,
        user: String,
        /// A publickey query without a signature.
        probe: bool,
        /// `: ED25519 SHA256:…` for a key, empty otherwise.
        key: String,
    }

    impl AttemptNote {
        fn of(attempt: &AuthAttempt) -> Self {
            let (method, user, probe, key) = match attempt {
                AuthAttempt::None { user } => ("none", user, false, String::new()),
                AuthAttempt::Password { user, .. } => ("password", user, false, String::new()),
                AuthAttempt::KeyboardInteractive { user } => {
                    ("keyboard-interactive/pam", user, false, String::new())
                }
                AuthAttempt::PublicKey {
                    user,
                    public_blob,
                    probe_only,
                    cert,
                    ..
                } => (
                    "publickey",
                    user,
                    *probe_only,
                    key_description(public_blob, cert.as_ref()),
                ),
                _ => ("unknown", &String::new(), false, String::new()),
            };
            AttemptNote {
                method,
                user: user.clone(),
                probe,
                key,
            }
        }
    }

    /// A key as OpenSSH's auth log names it: `: ED25519 SHA256:…`, or for a
    /// certificate `: ED25519-CERT SHA256:… ID id (serial n) CA ED25519
    /// SHA256:…`.
    fn key_description(blob: &[u8], cert: Option<&puressh::auth::CertInfo>) -> String {
        fn label(kind: &str) -> &'static str {
            let plain = kind.split("-cert-v01@").next().unwrap_or(kind);
            match plain {
                "ssh-ed25519" => "ED25519",
                "ssh-rsa" | "rsa-sha2-256" | "rsa-sha2-512" => "RSA",
                k if k.starts_with("ecdsa-sha2-") => "ECDSA",
                k if k.starts_with("sk-ssh-ed25519") => "ED25519-SK",
                k if k.starts_with("sk-ecdsa") => "ECDSA-SK",
                k if k.starts_with("ssh-mldsa44-ed25519") => "MLDSA44-ED25519",
                _ => "UNKNOWN",
            }
        }
        match cert {
            None => {
                let (fp, _, kind) = blob_tokens(blob);
                format!(": {} {fp}", label(&kind))
            }
            Some(ci) => {
                let (fp, _, kind) = blob_tokens(&ci.embedded_pubkey_blob);
                let (ca_fp, _, ca_kind) = blob_tokens(&ci.ca_key_blob);
                format!(
                    ": {}-CERT {fp} ID {} (serial {}) CA {} {ca_fp}",
                    label(&kind),
                    ci.key_id,
                    ci.serial,
                    label(&ca_kind)
                )
            }
        }
    }

    impl Authenticator for LocalAuthenticator {
        fn continuable_methods(&self, offered: &[&'static str]) -> Vec<String> {
            if self.chains.is_empty() {
                return offered.iter().map(|m| (*m).into()).collect();
            }
            // The next method of each chain still consistent with what has
            // been satisfied, if the server offers it (OpenSSH's
            // authmethods_get with AuthenticationMethods).
            match self.partial_or_reject_for_current() {
                AuthDecision::PartialAccept { still_required } => still_required
                    .into_iter()
                    .filter(|m| offered.contains(&m.as_str()))
                    .collect(),
                _ => Vec::new(),
            }
        }

        fn key_restrictions(
            &mut self,
            _user: &str,
            _public_blob: &[u8],
        ) -> Option<puressh::auth::AuthCertCaps> {
            self.accepted_options
                .take()
                .filter(|o| !o.is_unrestricted())
                .map(|o| puressh::auth::AuthCertCaps::from_key_options(&o))
        }

        fn evaluate(&mut self, attempt: AuthAttempt) -> AuthDecision {
            let note = AttemptNote::of(&attempt);
            let decision = (|| {
                if self.policy_broken {
                    return AuthDecision::Reject;
                }
                match attempt {
                    AuthAttempt::None { user } => {
                        if self.debug {
                            eprintln!("sshd: auth none rejected for user {}", sanitize_log(&user));
                        }
                        AuthDecision::Reject
                    }
                    AuthAttempt::PublicKey {
                        user,
                        algorithm,
                        public_blob,
                        probe_only,
                        verified,
                        cert,
                    } => {
                        // An invalid username, or a username switched
                        // mid-userauth, is refused before anything else. Both
                        // verdicts depend only on the client's own input (never on
                        // whether an account exists), so the early return leaks
                        // nothing. Every `{user}` logged below has passed this
                        // check and is therefore free of control characters.
                        if !self.check_user_binding(&user) {
                            if self.debug {
                                eprintln!(
                                    "sshd: auth publickey: username rejected or changed mid-userauth"
                                );
                            }
                            return AuthDecision::Reject;
                        }
                        // Always run *both* remaining checks unconditionally so an
                        // attacker can't distinguish "unknown user" from
                        // "known user / wrong key" via wall-clock timing.
                        // The access check (DenyUsers/AllowUsers/DenyGroups/
                        // AllowGroups, with a memoized group lookup) and the
                        // scan over the user's authorized keys (loaded once per
                        // connection) both run for every attempt so the paths
                        // stay uniform.
                        let user_ok = self.access_allowed(&user);
                        // For a certificate, "blob_ok" becomes: the CA is trusted,
                        // the login user is an authorized principal, and any
                        // source-address critical option admits this peer. (The
                        // auth layer already verified the CA signature, the cert
                        // type/validity, and that all critical options are
                        // understood, before producing a `verified` cert attempt.)
                        // KRL revocation applies uniformly to plain keys and to a
                        // certificate's full wire blob (OpenSSH's explicit-key /
                        // fingerprint sections can name a cert blob directly). For
                        // a certificate the key *embedded* in it is checked as
                        // well: revoking a plain key must also refuse every
                        // certificate wrapping that key (OpenSSH checks the
                        // embedded key, not just the cert). A revoked blob forces
                        // `blob_ok` false regardless of the authorized-keys /
                        // cert-trust verdict.
                        let blob_revoked = self
                            .revoked_keys
                            .as_ref()
                            .as_ref()
                            .map(|krl| {
                                krl.is_revoked_key(&public_blob)
                                    || cert.as_ref().is_some_and(|ci| {
                                        krl.is_revoked_key(&ci.embedded_pubkey_blob)
                                    })
                            })
                            .unwrap_or(false);
                        if blob_revoked && self.debug {
                            eprintln!(
                                "sshd: auth publickey: key/cert blob revoked by KRL for {user}"
                            );
                        }
                        // PubkeyAcceptedAlgorithms / RequiredRSASize: a policy on
                        // the key itself, folded into `blob_ok` (no early return,
                        // so timing stays uniform).
                        let alg_ok = self
                            .pubkey_accepted
                            .as_ref()
                            .is_none_or(|l| l.iter().any(|a| a == &algorithm));
                        let key_blob = cert.as_ref().map_or(public_blob.as_slice(), |ci| {
                            ci.embedded_pubkey_blob.as_slice()
                        });
                        let size_ok = rsa_modulus_bits(key_blob)
                            .is_none_or(|bits| bits >= self.required_rsa_size as usize);
                        if self.debug && !(alg_ok && size_ok) {
                            eprintln!(
                                "sshd: auth publickey: {} for {user}",
                                if alg_ok {
                                    "RSA key below RequiredRSASize"
                                } else {
                                    "algorithm not in PubkeyAcceptedAlgorithms"
                                }
                            );
                        }
                        let blob_ok = !blob_revoked
                            && alg_ok
                            && size_ok
                            && match &cert {
                                Some(ci) => self.cert_trusted(ci, &user, &public_blob),
                                None => self.key_authorized(&user, &public_blob),
                            };
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
                        self.log_root_refused(root_denied);
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
                                    eprintln!(
                                        "sshd: auth publickey: user {user} not in allowed set"
                                    );
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
                        // A verified user certificate's `force-command` critical
                        // option (and its default-deny extensions) are captured by
                        // the auth layer into `AuthCertCaps`, folded into the
                        // per-connection `EffectivePolicy`, and enforced by the
                        // server connection-phase dispatcher uniformly with the
                        // config `ForceCommand` / forwarding gates. Nothing to
                        // record here.
                        //
                        // A verified signature satisfies the `publickey` factor. In
                        // single-factor mode this Accepts; under a multi-factor
                        // chain it may PartialAccept and ask for the next factor.
                        self.record_and_decide("publickey")
                    }
                    AuthAttempt::Password { user, password } => {
                        if !self.password_enabled {
                            if self.debug {
                                eprintln!(
                                    "sshd: auth password rejected (disabled) for user {user}"
                                );
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
                        // Bind the username now (so a later switch is caught).
                        if !self.check_user_binding(&user) {
                            if self.debug {
                                eprintln!(
                                    "sshd: auth keyboard-interactive: username changed mid-userauth"
                                );
                            }
                            return AuthDecision::Reject;
                        }
                        // Start a fresh PAM conversation on a worker thread. Any
                        // previous (abandoned) conversation is dropped here, tearing
                        // down its worker. The first `next()` blocks until PAM
                        // either asks a prompt (→ InteractiveRequest) or finishes
                        // immediately (e.g. pam_permit with no prompts → decide).
                        let rhost = self.peer.clone();
                        let conv = self.pam.start_kbd_interactive(&user, rhost.as_deref());
                        self.kbd_conv = Some(conv);
                        self.pending_first_prompt = true;
                        let user = user.clone();
                        self.kbd_pump(&user)
                    }
                    // An auth method this binary predates: never accept it.
                    _ => AuthDecision::Reject,
                }
            })();
            self.log_decision(&note, &decision);
            decision
        }

        fn evaluate_interactive(&mut self, user: &str, responses: Vec<String>) -> AuthDecision {
            let note = AttemptNote {
                method: "keyboard-interactive/pam",
                user: user.to_string(),
                probe: false,
                key: String::new(),
            };
            let decision = (|| {
                if !self.kbd_interactive_enabled || self.policy_broken {
                    return AuthDecision::Reject;
                }
                // Username must not change mid-conversation.
                if !self.check_user_binding(user) {
                    if self.debug {
                        eprintln!("sshd: auth keyboard-interactive: username changed mid-userauth");
                    }
                    self.kbd_conv = None;
                    return AuthDecision::Reject;
                }
                // Feed the answer (we issue one prompt per round, so exactly one
                // response is expected) into the running conversation, then pump
                // for the next step. The response strings come from
                // `UserauthInfoResponse`, whose Drop zeroizes its buffer; we copy
                // the answer into a zeroizing buffer first.
                let answer = responses
                    .first()
                    .map(|s| zeroize::Zeroizing::new(s.as_bytes().to_vec()))
                    .unwrap_or_default();

                // Empty-password policy: refuse an empty answer to the first prompt
                // unless PermitEmptyPasswords, mirroring the password path. This is
                // input-dependent (not user-dependent), so it leaks no user-
                // existence oracle. `pending_first_prompt` tracks whether this is
                // the opening answer.
                if self.pending_first_prompt && answer.is_empty() && !self.permit_empty_passwords {
                    if self.debug {
                        eprintln!(
                            "sshd: auth keyboard-interactive: empty password refused for {user}"
                        );
                    }
                    self.kbd_conv = None;
                    return AuthDecision::Reject;
                }
                self.pending_first_prompt = false;

                let conv = match self.kbd_conv.as_mut() {
                    Some(c) => c,
                    None => return AuthDecision::Reject,
                };
                if !conv.answer(answer) {
                    // Worker already gone (e.g. PAM aborted) ⇒ reject.
                    self.kbd_conv = None;
                    return AuthDecision::Reject;
                }
                let user = user.to_string();
                self.kbd_pump(&user)
            })();
            self.log_decision(&note, &decision);
            decision
        }

        fn on_user_resolved(&mut self, user: &str, methods: &[String]) {
            // Bind the username on first sight (the publickey/password arms also
            // bind, but this fires first via the server's re-resolve hook).
            let bound = self.check_user_binding(user);
            if bound {
                sshd_log::conn_user(user, lookup_user(user).is_ok());
            }
            // Match-block access policy for this (user, peer, local socket):
            // AllowUsers/DenyUsers/AllowGroups/DenyGroups, PermitRootLogin,
            // PermitEmptyPasswords, AuthorizedKeysFile,
            // AuthorizedPrincipalsFile, TrustedUserCAKeys, RevokedKeys.
            if bound && let Some(pol) = self.policy.clone() {
                self.apply_conn_policy(&pol, user);
            }
            self.chains = parse_auth_method_chains(methods);
            if self.debug && bound && !self.chains.is_empty() {
                eprintln!(
                    "sshd: auth: multi-factor chains for {user}: {:?}",
                    self.chains
                );
            }
        }
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

    /// Whether any of `list` (OpenSSH pattern-list entries, globs allowed)
    /// matches one of the certificate's principals. An empty certificate
    /// principal list never matches — a `principals=` option demands a named
    /// principal.
    fn principals_match_option(list: &[String], cert_principals: &[String]) -> bool {
        let pats = puressh::config::HostPattern::parse_all(list);
        cert_principals
            .iter()
            .any(|p| puressh::config::host_matches(&pats, p))
    }

    /// Startup inputs the authenticator (and the session-open hook) need to
    /// re-derive the access policy per connection from `Match` blocks.
    struct ConnPolicy {
        /// The whole parsed `sshd_config` (global + `Match` blocks).
        config: Arc<puressh::config::SshServerConfig>,
        /// CLI `-u` tokens: always in force, ahead of any config `AllowUsers`.
        cli_allow_users: Vec<String>,
        /// The daemon's own user, the only login allowed when no `AllowUsers`
        /// / `-u` applies. `None` if `$USER` is unknown (⇒ nobody).
        default_allow_user: Option<String>,
        /// `--permit-root-login`, which wins over every config block.
        cli_permit_root_login: Option<puressh::config::PermitRootLogin>,
        /// Every `TrustedUserCAKeys` file named anywhere in the config, loaded
        /// at startup, keyed by path.
        ca_files: HashMap<String, Arc<Vec<Vec<u8>>>>,
        /// Every `RevokedKeys` KRL named anywhere in the config, parsed at
        /// startup, keyed by path.
        krls: HashMap<Vec<String>, Arc<puressh::krl::Krl>>,
    }

    /// Per-connection socket addresses `(peer, local)`, recorded by the forked
    /// child before it enters the session loop. Fork's copy-on-write isolates
    /// the value per connection; the daemon parent never sets it. Read by the
    /// `Match LocalAddress` / `Match LocalPort` context and the session-open
    /// hook's peer lookup.
    static CONN_ADDRS: Mutex<Option<(std::net::SocketAddr, Option<std::net::SocketAddr>)>> =
        Mutex::new(None);

    /// Login name of the knock (`docs/knock.md`) that opened this
    /// connection's rendezvous, recorded by the forked child; `None` for a
    /// connection on the regular listener. A knocked connection may only log
    /// in as that user.
    static KNOCK_USER: Mutex<Option<String>> = Mutex::new(None);

    fn knock_user() -> Option<String> {
        KNOCK_USER.lock().ok().and_then(|g| g.clone())
    }

    /// `sshd -i`: the connection is stdin / stdout, not a socket.
    static INETD: AtomicBool = AtomicBool::new(false);

    /// `sshd -i`: serve one connection whose client is on stdin / stdout.
    /// A TCP socket there (inetd, systemd `Accept=yes`) is served as an
    /// accepted connection. Anything else (a pipe, as from a `ProxyCommand`)
    /// is bridged to a loopback connection, served as one from an unknown
    /// peer: like OpenSSH's, it matches no `from=` or `Match Address`.
    fn serve_inetd(cfg: Arc<puressh::server::Config>) -> Result<i32, String> {
        use std::io::{Read, Write};
        use std::os::fd::{FromRawFd, IntoRawFd};
        let io = |e: std::io::Error| format!("inetd: {e}");
        // SAFETY: fd 0 is open for the process's lifetime; the stream is
        // released again (not closed) unless it is used as the connection.
        let stdin_sock = unsafe { std::net::TcpStream::from_raw_fd(0) };
        if let Ok(peer) = stdin_sock.peer_addr() {
            if let Ok(mut g) = CONN_ADDRS.lock() {
                *g = Some((peer, stdin_sock.local_addr().ok()));
            }
            let result = handle_session_with_peer(stdin_sock, peer, cfg);
            return Ok(if result.is_ok() { 0 } else { 255 });
        }
        let _ = stdin_sock.into_raw_fd();
        INETD.store(true, Ordering::Relaxed);
        let l = std::net::TcpListener::bind(("127.0.0.1", 0)).map_err(io)?;
        let outer = std::net::TcpStream::connect(l.local_addr().map_err(io)?).map_err(io)?;
        let (inner, _) = l.accept().map_err(io)?;
        drop(l);
        let peer = std::net::SocketAddr::from(([0, 0, 0, 0], 65535));
        let mut to_session = outer.try_clone().map_err(io)?;
        std::thread::spawn(move || {
            let mut stdin = std::io::stdin().lock();
            let mut buf = [0u8; 32 * 1024];
            loop {
                match stdin.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        if to_session.write_all(&buf[..n]).is_err() {
                            break;
                        }
                    }
                }
            }
            let _ = to_session.shutdown(std::net::Shutdown::Write);
        });
        let mut from_session = outer;
        let out = std::thread::spawn(move || {
            let mut stdout = std::io::stdout().lock();
            let mut buf = [0u8; 32 * 1024];
            loop {
                match from_session.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        if stdout
                            .write_all(&buf[..n])
                            .and_then(|()| stdout.flush())
                            .is_err()
                        {
                            break;
                        }
                    }
                }
            }
        });
        if let Ok(mut g) = CONN_ADDRS.lock() {
            *g = Some((peer, None));
        }
        let result = handle_session_with_addrs(inner, peer, None, cfg);
        let _ = out.join();
        Ok(if result.is_ok() { 0 } else { 255 })
    }

    fn conn_addrs() -> Option<(std::net::SocketAddr, Option<std::net::SocketAddr>)> {
        CONN_ADDRS.lock().ok().and_then(|g| *g)
    }

    /// The connection's peer IP in the textual form `Match Address` uses, or
    /// `None` when unknown / unspecified (then `Match Address` never matches).
    fn conn_peer_ip() -> Option<String> {
        conn_addrs()
            .map(|(peer, _)| peer.ip())
            .filter(|ip| !ip.is_unspecified())
            .map(|ip| ip.to_string())
    }

    /// Resolve the `sshd_config` policy for a connection once the login user
    /// is known: user, groups, peer address, and this child's local socket
    /// (for `Match LocalAddress` / `LocalPort`).
    fn resolve_conn_options(
        config: &puressh::config::SshServerConfig,
        user: &str,
        groups: &[String],
        peer_ip: Option<&str>,
    ) -> puressh::config::ServerOptions {
        let local = conn_addrs().and_then(|(_, local)| local);
        let local_ip = local.map(|a| a.ip().to_string());
        let mut ctx = puressh::config::MatchContext::default();
        ctx.user = Some(user);
        ctx.groups = Some(groups);
        ctx.address = peer_ip;
        // `Match host`: the client's address (OpenSSH's `UseDNS no`).
        ctx.host = peer_ip.unwrap_or("UNKNOWN");
        ctx.invalid_user = Some(lookup_user(user).is_err());
        ctx.local_address = local_ip.as_deref();
        ctx.local_port = local.map(|a| a.port());
        config.resolve(&ctx, puressh::config::ExecPolicy::Deny)
    }

    /// The `PermitRootLogin` in force for `user` on this connection: CLI flag
    /// > matched `Match` blocks > global > built-in `prohibit-password`.
    fn conn_permit_root_login(pol: &ConnPolicy, user: &str) -> puressh::config::PermitRootLogin {
        let groups = lookup_user_groups(user);
        let peer = conn_peer_ip();
        let opts = resolve_conn_options(&pol.config, user, &groups, peer.as_deref());
        pol.cli_permit_root_login
            .or(opts.permit_root_login)
            .unwrap_or(puressh::config::PermitRootLogin::ProhibitPassword)
    }

    #[derive(Clone)]
    struct LocalAuthFactory {
        allow_users: Arc<Vec<UserHostPattern>>,
        deny_users: Arc<Vec<UserHostPattern>>,
        allow_groups: Arc<Vec<puressh::config::HostPattern>>,
        deny_groups: Arc<Vec<puressh::config::HostPattern>>,
        /// `-A FILE`: the one global authorized_keys set. `None` ⇒ per-user.
        global_authorized_keys: Option<Arc<AuthorizedKeys>>,
        /// Global `AuthorizedKeysFile` templates (a `Match` block may replace
        /// them per connection).
        authorized_keys_files: Vec<String>,
        /// Trusted user-CA blobs from the global `TrustedUserCAKeys`.
        trusted_user_ca_blobs: Arc<Vec<Vec<u8>>>,
        /// Parsed global `RevokedKeys` KRL, shared read-only across connections.
        revoked_keys: Option<Arc<puressh::krl::Krl>>,
        /// Match-block policy inputs (see [`ConnPolicy`]).
        policy: Option<Arc<ConnPolicy>>,
        /// `AuthorizedPrincipalsFile` path *template* (may contain `%u`/`%h`/
        /// `%%`), shared across connections. `None` ⇒ no file configured. Each
        /// connection expands + loads it lazily for its own login user.
        authorized_principals_file: Option<String>,
        /// StrictModes for the principals file (and other strict checks).
        strict_modes: bool,
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
                global_authorized_keys: self.global_authorized_keys.clone(),
                authorized_keys_files: self.authorized_keys_files.clone(),
                authorized_keys: None,
                accepted_options: None,
                trusted_user_ca_blobs: (*self.trusted_user_ca_blobs).clone(),
                revoked_keys: self.revoked_keys.clone(),
                policy: self.policy.clone(),
                policy_broken: false,
                authorized_principals_file: self.authorized_principals_file.clone(),
                strict_modes: self.strict_modes,
                authorized_principals: None,
                auth_commands: AuthCommands::default(),
                command_cache: Default::default(),
                permit_root_login: self.permit_root_login,
                pam: self.pam.clone(),
                password_enabled: self.password_enabled,
                kbd_interactive_enabled: self.kbd_interactive_enabled,
                kbd_conv: None,
                pending_first_prompt: true,
                permit_empty_passwords: self.permit_empty_passwords,
                pubkey_accepted: None,
                required_rsa_size: DEFAULT_REQUIRED_RSA_SIZE,
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

    impl ShellCommandHandler {
        /// Everything needed to run `command` for `user`, short of spawning:
        /// logging, the passwd lookup, PAM session, environment and the
        /// privilege drop (in `pre_exec`). `Err` is a message for stderr.
        /// `command: None` runs the login shell itself (a `shell` request
        /// without a terminal), as OpenSSH: argv0 `-bash`, commands on stdin.
        fn prepare(
            &self,
            user: &str,
            env: &SessionEnv,
            command: Option<&str>,
        ) -> Result<Command, String> {
            // Both the config `ForceCommand` directive and a user certificate's
            // `force-command` critical option are applied uniformly by the
            // server connection-phase dispatcher (it rewrites `command` to the
            // forced one and injects `$SSH_ORIGINAL_COMMAND` into the session
            // env before this handler runs). The handler therefore sees the
            // already-forced command and the populated env — no separate
            // force-command path lives here.
            if self.debug
                && let Some(command) = command
            {
                if self.debug_commands {
                    eprintln!("sshd: exec by {user}: {}", sanitize_log(command));
                } else {
                    // Log only the first token (the program name) plus an
                    // argument count, so operators can see *what* ran
                    // without leaking secrets passed on the command line.
                    // Use char_indices so we never split inside a UTF-8
                    // codepoint and don't allocate a Vec to count args.
                    let name = command.split_whitespace().next().unwrap_or("");
                    let extra = command.split_whitespace().skip(1).count();
                    eprintln!(
                        "sshd: exec by {user}: {} (+{extra} args, redacted)",
                        sanitize_log(name)
                    );
                }
            }

            // Resolve the target user in /etc/passwd first — every
            // subsequent step (PAM open, env layering, setuid) depends
            // on these values. A missing user is a hard fail.
            let info = lookup_user(user).map_err(|e| format!("sshd: user lookup failed: {e}\n"))?;

            // Open the PAM session before spawning the child. `exec`
            // requests don't have a real tty, so we use "ssh" — matches
            // OpenSSH's behaviour for non-PTY channels. `ExecResult`
            // has no error channel, so PAM failure surfaces as exit
            // status 255 with the error message on stderr.
            let mut envs = self
                .pam
                .ensure(user, "ssh")
                .map_err(|e| format!("sshd: PAM session open failed: {e}\n"))?;
            apply_login_envs(&mut envs, &info);

            // Run the command via the user's login shell so that
            // /etc/passwd-configured shells (zsh, fish, …) are honoured.
            let mut cmd = Command::new(&info.shell_str);
            match command {
                Some(command) => {
                    cmd.args(["-c", command]);
                }
                None => {
                    cmd.arg0(OsStr::from_bytes(info.argv0_c.to_bytes()));
                }
            }
            cmd.env_clear();
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
            for (k, v) in session_vars(env, &info.home_str) {
                cmd.env(k, v);
            }
            for (k, v) in connection_env(None) {
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
                cmd.current_dir(if std::path::Path::new(&info.home_str).is_dir() {
                    info.home_str.as_str()
                } else {
                    "/"
                });
            }
            // The rc files / xauth, as the user, in the home directory, with
            // the session's environment (std only installs it at exec).
            let vars: Vec<(String, String)> = cmd
                .get_envs()
                .filter_map(|(k, v)| Some((k.to_str()?.to_string(), v?.to_str()?.to_string())))
                .collect();
            if let Some(rc) = startup_rc(&info, env, false, Some(vars)) {
                // SAFETY: runs after the privilege drop above (closures run
                // in order); `run_startup_rc` is post-fork safe.
                unsafe {
                    cmd.pre_exec(move || {
                        run_startup_rc(&rc);
                        Ok(())
                    });
                }
            }
            Ok(cmd)
        }

        /// Run `command` streaming: channel data feeds its stdin (EOF
        /// closes it), its stdout and stderr go out as they are produced,
        /// then its exit status. This is what `ssh host command` (git,
        /// rsync, `tail -f`, `cat > file`) needs.
        fn run_streaming(
            &self,
            user: &str,
            env: &SessionEnv,
            command: Option<&str>,
            mut stream: ChannelStream,
        ) -> puressh::Result<()> {
            use puressh::server::ChannelEgress;
            use std::io::{Read, Write};
            let mut cmd = match self.prepare(user, env, command) {
                Ok(c) => c,
                Err(msg) => {
                    let _ = stream.write_stderr(msg.as_bytes());
                    let _ = stream.send_exit_status(255);
                    return Ok(());
                }
            };
            cmd.stdin(std::process::Stdio::piped());
            cmd.stdout(std::process::Stdio::piped());
            cmd.stderr(std::process::Stdio::piped());
            let mut child = match cmd.spawn() {
                Ok(c) => c,
                Err(e) => {
                    let _ = stream.write_stderr(format!("sshd: failed to spawn: {e}\n").as_bytes());
                    let _ = stream.send_exit_status(255);
                    return Ok(());
                }
            };
            let (rx, tx) = stream.into_raw();

            // channel → stdin. Not joined: it ends when the client sends EOF
            // or the channel goes away.
            if let Some(mut child_in) = child.stdin.take() {
                std::thread::spawn(move || {
                    while let Ok(Some(bytes)) = rx.recv() {
                        if child_in.write_all(&bytes).is_err() {
                            break;
                        }
                    }
                    // Dropping `child_in` closes the command's stdin.
                });
            }

            fn pump<R: Read + Send + 'static>(
                mut r: R,
                tx: std::sync::mpsc::SyncSender<ChannelEgress>,
                stderr: bool,
            ) -> std::thread::JoinHandle<()> {
                std::thread::spawn(move || {
                    let mut buf = vec![0u8; 32 * 1024];
                    loop {
                        match r.read(&mut buf) {
                            Ok(0) => break,
                            Ok(n) => {
                                let chunk = buf[..n].to_vec();
                                let msg = if stderr {
                                    ChannelEgress::Stderr(chunk)
                                } else {
                                    ChannelEgress::Data(chunk)
                                };
                                if tx.send(msg).is_err() {
                                    break;
                                }
                            }
                            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                            Err(_) => break,
                        }
                    }
                })
            }
            let t_out = child.stdout.take().map(|o| pump(o, tx.clone(), false));
            let t_err = child.stderr.take().map(|e| pump(e, tx.clone(), true));
            if let Some(t) = t_out {
                let _ = t.join();
            }
            if let Some(t) = t_err {
                let _ = t.join();
            }
            if let Ok(status) = child.wait() {
                // A command killed by a signal has no exit status; the
                // client then reports 255, like OpenSSH.
                if let Some(code) = status.code() {
                    let _ = tx.send(ChannelEgress::ExitStatus(code as u32));
                }
            }
            let _ = tx.send(ChannelEgress::Eof);
            let _ = tx.send(ChannelEgress::Close);
            Ok(())
        }
    }

    impl CommandHandler for ShellCommandHandler {
        fn handle(&self, user: &str, env: &SessionEnv, command: &str) -> ExecResult {
            let mut cmd = match self.prepare(user, env, Some(command)) {
                Ok(c) => c,
                Err(msg) => return ExecResult::new(Vec::new(), msg.into_bytes(), 255),
            };

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
                    return ExecResult::new(
                        Vec::new(),
                        format!("sshd: failed to spawn: {e}\n").into_bytes(),
                        255,
                    );
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
                    return ExecResult::new(
                        Vec::new(),
                        format!("sshd: wait failed: {e}\n").into_bytes(),
                        255,
                    );
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
            ExecResult::new(stdout_buf, stderr_buf, final_code)
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
        // The password database first: services and containers often run
        // without $USER.
        if let Ok(Some(u)) = nix::unistd::User::from_uid(nix::unistd::getuid()) {
            return Ok(u.name);
        }
        std::env::var("USER")
            .or_else(|_| std::env::var("LOGNAME"))
            .map_err(|_| "could not determine current user".into())
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

    /// The session's variables, layered as OpenSSH does: the client's
    /// (`AcceptEnv`) and `environment=` key options, then the user's
    /// `~/.ssh/environment` where `PermitUserEnvironment` allows, then the
    /// administrator's `SetEnv`, which wins. `home` is read as the user.
    fn session_vars(env: &SessionEnv, home: &str) -> Vec<(String, String)> {
        let mut vars: Vec<(String, String)> = safe_session_env(env)
            .into_iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        let mut set = |k: &str, v: &str| {
            if k.is_empty() || k.contains('\0') || v.contains('\0') {
                return;
            }
            match vars.iter_mut().find(|(n, _)| n == k) {
                Some(slot) => slot.1 = v.to_string(),
                None => vars.push((k.to_string(), v.to_string())),
            }
        };
        if env.user_environment_enabled() {
            // OpenSSH's read_environment_file: NAME=value lines, comments
            // and blank lines skipped, at most 1000 entries.
            let path = format!("{home}/.ssh/environment");
            if let Ok(text) = std::fs::read_to_string(&path) {
                for line in text.lines().take(1000) {
                    let line = line.trim_start();
                    if line.is_empty() || line.starts_with('#') {
                        continue;
                    }
                    if let Some((k, v)) = line.split_once('=')
                        && env.user_environment_permits(k)
                        && !HARD_BLOCKED_ENV_NAMES.contains(&k)
                    {
                        set(k, v);
                    }
                }
            }
        }
        for (k, v) in env.admin_env() {
            set(k, v);
        }
        vars
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

    /// `XAuthLocation` (`None`: `none`), set once at startup.
    static XAUTH_LOCATION: std::sync::OnceLock<Option<String>> = std::sync::OnceLock::new();

    /// What runs in the session process just before its shell or command,
    /// as OpenSSH's do_rc_files: `~/.ssh/rc` (through the user's shell,
    /// when allowed), else `/etc/ssh/sshrc`, each fed `proto cookie` of a
    /// forwarded X11 display on stdin; else, for X11, `xauth` adding the
    /// display's cookie. Built before the fork: running it only uses
    /// async-signal-safe calls.
    struct StartupRc {
        _strings: Vec<std::ffi::CString>,
        argv: Vec<*const libc::c_char>,
        /// `None`: the current environment (the pty child has set it up).
        envp: Option<Vec<*const libc::c_char>>,
        input: Vec<u8>,
    }

    // SAFETY: the pointers point into `_strings` (or into CStrings owned by
    // the same closure), which live as long as the plan and never move.
    unsafe impl Send for StartupRc {}
    unsafe impl Sync for StartupRc {}

    /// The plan for a session of `info` with `env` (`None`: nothing runs).
    /// `subsystem`: only `/etc/ssh/sshrc` applies, as in OpenSSH.
    fn startup_rc(
        info: &UserInfo,
        env: &SessionEnv,
        subsystem: bool,
        envp: Option<Vec<(String, String)>>,
    ) -> Option<StartupRc> {
        let x11 = env.x11_auth();
        let cookie_line = x11.map(|(proto, cookie, _)| format!("{proto} {cookie}\n"));
        let user_rc = format!("{}/.ssh/rc", info.home_str);
        let (command, input) =
            if !subsystem && env.user_rc_allowed() && std::path::Path::new(&user_rc).exists() {
                (
                    format!("{} -c '/bin/sh {user_rc}'", info.shell_str),
                    cookie_line,
                )
            } else if std::path::Path::new("/etc/ssh/sshrc").exists() {
                ("/bin/sh /etc/ssh/sshrc".to_string(), cookie_line)
            } else if let (Some((proto, cookie, display)), Some(Some(xauth))) =
                (x11, XAUTH_LOCATION.get())
            {
                (
                    format!("{xauth} -q -"),
                    Some(format!(
                        "remove {display}\nadd {display} {proto} {cookie}\n"
                    )),
                )
            } else {
                return None;
            };
        let mut strings = Vec::new();
        for a in ["/bin/sh", "-c", command.as_str()] {
            strings.push(std::ffi::CString::new(a).ok()?);
        }
        let n_argv = strings.len();
        if let Some(vars) = &envp {
            for (k, v) in vars {
                strings.push(std::ffi::CString::new(format!("{k}={v}")).ok()?);
            }
        }
        let ptrs: Vec<*const libc::c_char> = strings.iter().map(|s| s.as_ptr()).collect();
        let mut argv = ptrs[..n_argv].to_vec();
        argv.push(std::ptr::null());
        let envp = envp.map(|_| {
            let mut e = ptrs[n_argv..].to_vec();
            e.push(std::ptr::null());
            e
        });
        Some(StartupRc {
            _strings: strings,
            argv,
            envp,
            input: input.unwrap_or_default().into_bytes(),
        })
    }

    /// Run `rc` and wait for it, feeding its stdin; its stdout / stderr are
    /// the session's. Post-fork safe: no allocation.
    fn run_startup_rc(rc: &StartupRc) {
        // SAFETY: plain fd / process syscalls on fds this function owns;
        // argv / envp are NUL-terminated arrays of live C strings.
        unsafe {
            let mut fds = [0 as libc::c_int; 2];
            if libc::pipe(fds.as_mut_ptr()) != 0 {
                return;
            }
            // Writing to an rc that does not read must not kill us.
            let old = libc::signal(libc::SIGPIPE, libc::SIG_IGN);
            let pid = libc::fork();
            if pid == 0 {
                libc::signal(libc::SIGPIPE, libc::SIG_DFL);
                libc::dup2(fds[0], 0);
                libc::close(fds[0]);
                libc::close(fds[1]);
                match &rc.envp {
                    Some(envp) => libc::execve(rc.argv[0], rc.argv.as_ptr(), envp.as_ptr()),
                    None => libc::execv(rc.argv[0], rc.argv.as_ptr()),
                };
                libc::_exit(127);
            }
            libc::close(fds[0]);
            if pid > 0 {
                let mut off = 0;
                while off < rc.input.len() {
                    let n = libc::write(
                        fds[1],
                        rc.input[off..].as_ptr() as *const libc::c_void,
                        rc.input.len() - off,
                    );
                    if n <= 0 {
                        if n < 0
                            && std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR)
                        {
                            continue;
                        }
                        break;
                    }
                    off += n as usize;
                }
            }
            libc::close(fds[1]);
            if pid > 0 {
                let mut status = 0;
                while libc::waitpid(pid, &mut status, 0) < 0
                    && std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR)
                {
                }
            }
            libc::signal(libc::SIGPIPE, old);
        }
    }

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

    /// The authenticated user's identity as resolved by the session-open
    /// hook from the *real* passwd database, before any `ChrootDirectory`.
    /// Fork's copy-on-write isolates it per connection. Once set,
    /// [`lookup_user`] answers for that name from here, so a jail without an
    /// `/etc/passwd` still works and a jail *with* a writable one cannot
    /// feed the daemon a different uid/home/shell.
    static SESSION_USER: Mutex<Option<UserInfo>> = Mutex::new(None);

    fn remember_session_user(info: &UserInfo) {
        if let Ok(mut g) = SESSION_USER.lock() {
            *g = Some(info.clone());
        }
    }

    fn lookup_user(name: &str) -> puressh::Result<UserInfo> {
        if let Ok(g) = SESSION_USER.lock()
            && let Some(info) = g.as_ref()
            && info.name == name
        {
            return Ok(info.clone());
        }
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

    /// The variables OpenSSH gives every session: `SSH_CLIENT` (client
    /// address and port, server port), `SSH_CONNECTION` (client address and
    /// port, server address and port) and, on a pty, `SSH_TTY`. Set after
    /// the client's `env` requests, which cannot replace them.
    fn connection_env(tty: Option<&str>) -> Vec<(&'static str, String)> {
        let mut out = Vec::new();
        if INETD.load(Ordering::Relaxed) {
            // stdin is not a socket: OpenSSH's placeholders.
            out.push(("SSH_CLIENT", "UNKNOWN 65535 65535".to_string()));
            out.push(("SSH_CONNECTION", "UNKNOWN 65535 UNKNOWN 65535".to_string()));
        } else if let Some((peer, local)) = conn_addrs() {
            let (lip, lport) = local.map_or((String::new(), 0), |l| {
                (sshd_log::addr_str(l.ip()), l.port())
            });
            let pip = sshd_log::addr_str(peer.ip());
            out.push(("SSH_CLIENT", format!("{pip} {} {lport}", peer.port())));
            out.push((
                "SSH_CONNECTION",
                format!("{pip} {} {lip} {lport}", peer.port()),
            ));
        }
        if let Some(t) = tty {
            out.push(("SSH_TTY", t.to_string()));
        }
        out
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
            let env_pairs = lookup_user(user)
                .map(|info| session_vars(env, &info.home_str))
                .unwrap_or_default();
            match pty {
                Some(spec) => {
                    let print_motd = self.print_motd.load(std::sync::atomic::Ordering::Relaxed);
                    let startup = lookup_user(user)
                        .ok()
                        .and_then(|info| startup_rc(&info, env, false, None));
                    spawn_pty_shell(
                        &self.pam, user, &env_pairs, &spec, self.debug, print_motd, None, startup,
                    )
                }
                None => spawn_pipe_shell(&self.pam, user, &env_pairs, self.debug),
            }
        }

        /// `ssh -t host command`: the command, through the user's shell,
        /// on a pseudo-terminal. No motd (OpenSSH prints it only for an
        /// interactive login).
        fn spawn_command(
            &self,
            user: &str,
            env: &SessionEnv,
            pty: PtySpec,
            command: &str,
        ) -> puressh::Result<Box<dyn ShellSession>> {
            let env_pairs = lookup_user(user)
                .map(|info| session_vars(env, &info.home_str))
                .unwrap_or_default();
            let startup = lookup_user(user)
                .ok()
                .and_then(|info| startup_rc(&info, env, false, None));
            spawn_pty_shell(
                &self.pam,
                user,
                &env_pairs,
                &pty,
                self.debug,
                false,
                Some(command),
                startup,
            )
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
        /// `subsystem sftp` requests are served (a forced `internal-sftp`
        /// is, regardless).
        enabled: bool,
        read_only: bool,
        root: Option<std::path::PathBuf>,
        /// The `Subsystem sftp` line's sftp-server arguments.
        args: Vec<String>,
        debug: bool,
    }

    impl SubsystemHandler for SftpSubsystemHandler {
        fn serves(&self, name: &str) -> bool {
            self.enabled && name == "sftp"
        }

        fn handle(
            &self,
            user: &str,
            _env: &SessionEnv,
            name: &str,
            stream: ChannelStream,
        ) -> puressh::Result<()> {
            if name != "sftp" || !self.enabled {
                if self.debug {
                    eprintln!(
                        "sshd: refusing unknown subsystem '{}' for {user}",
                        sanitize_log(name)
                    );
                }
                return Ok(()); // dropping `stream` sends EOF + Close
            }
            self.serve(user, &self.args, stream)
        }

        fn handle_with_args(
            &self,
            user: &str,
            _env: &SessionEnv,
            _name: &str,
            args: &[String],
            stream: ChannelStream,
        ) -> puressh::Result<()> {
            self.serve(user, args, stream)
        }
    }

    impl SftpSubsystemHandler {
        /// One SFTP session, configured by sftp-server's arguments: `-d`
        /// (start directory, `%d` / `%u` expanded), `-u` (umask), `-R`
        /// (read-only). Logging options follow sshd's own; any other option
        /// (`-P` / `-p` request lists) refuses the session.
        fn serve(
            &self,
            user: &str,
            args: &[String],
            mut stream: ChannelStream,
        ) -> puressh::Result<()> {
            let info = lookup_user(user).ok();
            let mut read_only = self.read_only;
            let mut start_dir = None;
            let mut it = args.iter();
            while let Some(a) = it.next() {
                match a.as_str() {
                    "-R" => read_only = true,
                    "-d" => start_dir = it.next().cloned(),
                    "-u" => {
                        let mask = it.next().and_then(|m| u32::from_str_radix(m, 8).ok());
                        match mask {
                            // SAFETY: umask only swaps the process's mask.
                            Some(m) if m <= 0o777 => unsafe {
                                libc::umask(m as libc::mode_t);
                            },
                            _ => {
                                eprintln!("sftp-server: Invalid umask");
                                let _ = stream.send_exit_status(1);
                                return Ok(());
                            }
                        }
                    }
                    "-f" | "-l" => {
                        it.next();
                    }
                    "-e" | "-h" => {}
                    // Request allow / deny lists are not implemented: refuse
                    // the session rather than serve it unrestricted.
                    other => {
                        eprintln!("sftp-server: option {other} is not supported");
                        let _ = stream.send_exit_status(1);
                        return Ok(());
                    }
                }
            }

            // As OpenSSH: the home directory when it exists (inside a
            // ChrootDirectory it usually does not), else the root; `-d`
            // names another.
            let home = info
                .as_ref()
                .map(|i| std::path::PathBuf::from(&i.home_str))
                .filter(|h| h.is_dir());
            let mut cwd = home
                .clone()
                .unwrap_or_else(|| std::path::PathBuf::from("/"));
            if let Some(dir) = start_dir {
                let expanded = info.as_ref().map_or(Ok(dir.clone()), |i| {
                    expand_command_arg(&dir, &[('d', i.home_str.clone()), ('u', i.name.clone())])
                });
                let dir = match expanded {
                    Ok(d) => cwd.join(d),
                    Err(e) => {
                        eprintln!("sftp-server: -d: {e}");
                        let _ = stream.send_exit_status(1);
                        return Ok(());
                    }
                };
                if dir.is_dir() {
                    cwd = dir;
                } else {
                    eprintln!("sftp-server: chdir to \"{}\" failed", dir.display());
                }
            }

            let mut opts = SftpServerOptions::new(cwd);
            if let Some(root) = &self.root {
                opts = opts.with_root(root.clone());
            }
            if read_only {
                opts = opts.read_only();
            }

            let mut session = SftpServerSession::new(opts);
            if self.debug {
                eprintln!("sshd: sftp session opened for {user}");
            }
            // Report an exit status like OpenSSH's sftp-server process does:
            // scp and sftp treat a session without one as a failure.
            let res = session.run(&mut stream);
            let _ = stream.send_exit_status(if res.is_ok() { 0 } else { 1 });
            // Map SFTP-protocol errors into the generic puressh error type;
            // the dispatcher only cares whether the handler returned cleanly.
            res.map_err(|e| puressh::Error::Io(std::io::Error::other(format!("sftp: {e:?}"))))?;
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

    /// Every `exec` request: in-process `scp` when enabled and asked for,
    /// otherwise the command through the user's shell, streamed.
    struct ExecDispatch {
        scp: Option<ScpExecHandler>,
        shell: Arc<ShellCommandHandler>,
    }

    impl ExecStreamHandler for ExecDispatch {
        fn claims(&self, _command: &str) -> bool {
            true
        }

        fn run(
            &self,
            user: &str,
            env: &SessionEnv,
            command: &str,
            stream: ChannelStream,
        ) -> puressh::Result<()> {
            match &self.scp {
                Some(scp) if scp.claims(command) => scp.run(user, env, command, stream),
                _ => self.shell.run_streaming(user, env, Some(command), stream),
            }
        }

        fn claims_login_shell(&self) -> bool {
            true
        }

        fn run_login_shell(
            &self,
            user: &str,
            env: &SessionEnv,
            stream: ChannelStream,
        ) -> puressh::Result<()> {
            self.shell.run_streaming(user, env, None, stream)
        }
    }

    impl ExecStreamHandler for ScpExecHandler {
        fn claims(&self, command: &str) -> bool {
            // Cheap pre-check before tokenising. We're after the literal
            // `scp ` prefix optionally preceded by whitespace.
            let t = command.trim_start();
            if !(t.starts_with("scp ") || t == "scp") {
                return false;
            }
            // Only a plain `scp -t|-f path` runs in-process; anything else
            // (a remote glob such as `scp -f -- *.txt`, other flags) goes to
            // the user's shell and the system scp, as with OpenSSH.
            tokenize_argv(command)
                .ok()
                .is_some_and(|argv| parse_scp_args(&argv).is_ok())
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

            let mut stream = stream;
            let res = match parsed.role {
                // Several sources (`-d`) need a directory to land in: refuse
                // before the transfer starts, as OpenSSH's sink does.
                ScpRole::To if parsed.target_dir && !abs_path.is_dir() => {
                    let msg = format!("\x01scp: {}: Not a directory\n", abs_path.display());
                    let _ = std::io::Write::write_all(&mut stream, msg.as_bytes());
                    Err(puressh::scp::ScpError::Remote(format!(
                        "{}: Not a directory",
                        abs_path.display()
                    )))
                }
                ScpRole::To => {
                    // `scp -t` — the peer is the sender, we receive.
                    let mut opts = ScpRecvOptions::default();
                    opts.recursive = parsed.recursive;
                    opts.preserve_times = parsed.preserve_times;
                    // If the local destination already exists as a
                    // directory we use it as the parent; otherwise it's
                    // the literal file path.
                    opts.target_is_file = !abs_path.is_dir();
                    ScpReceiver::new(&mut stream, &abs_path, opts).and_then(|mut rx| rx.run())
                }
                ScpRole::From => {
                    // `scp -f` — we read from disk and send to the peer.
                    let mut opts = ScpSendOptions::default();
                    opts.recursive = parsed.recursive;
                    opts.preserve_times = parsed.preserve_times;
                    ScpSender::new(&mut stream).and_then(|mut tx| tx.send_path(&abs_path, &opts))
                }
            };
            // An exit status, as the scp process would have: the client
            // treats a session without one as a failure.
            let _ = stream.send_exit_status(if res.is_ok() { 0 } else { 1 });
            res.map_err(|e| puressh::Error::Io(std::io::Error::other(format!("scp: {e}"))))?;
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
        /// `-d`: the target must be a directory (several sources).
        target_dir: bool,
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
        let mut target_dir = false;
        let mut positional: Vec<&str> = Vec::new();
        let mut i = 1;
        while i < argv.len() {
            let a = argv[i].as_str();
            match a {
                "-t" => role = Some(ScpRole::To),
                "-f" => role = Some(ScpRole::From),
                "-r" => recursive = true,
                "-p" => preserve_times = true,
                "-d" => target_dir = true,
                // Innocent flags scp(1) sometimes adds — accept and ignore.
                "-v" | "-q" | "-B" | "-C" | "-1" | "-2" | "-3" | "-4" | "-6" => {}
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
            target_dir,
            path,
        })
    }

    /// Expand the OpenSSH `%h` (home) / `%u` (user) / `%%` tokens in a path
    /// template (`ChrootDirectory`, `AuthorizedPrincipalsFile`) against the
    /// target user's passwd entry. Unknown `%X` sequences are rejected so a typo
    /// can't silently produce a surprising path.
    fn expand_pct_tokens(template: &str, info: &UserInfo) -> Result<String, String> {
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
                    return Err(format!("unknown token %{other}"));
                }
                None => return Err("trailing % in path template".to_string()),
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

    /// Resolve, validate, and `chroot()` into `template` for the user `info`
    /// (already looked up from the real passwd database), then `chdir("/")`
    /// inside the new root. Must run **while still root**, before any
    /// `setuid` — `chroot(2)` requires `CAP_SYS_CHROOT`. Called from
    /// `Config::on_session_open` ahead of [`drop_to_user`].
    fn apply_chroot(info: &UserInfo, template: &str, debug: bool) -> puressh::Result<()> {
        let user = info.name.as_str();
        let resolved = expand_pct_tokens(template, info).map_err(|e| {
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

    /// Drop the calling process to `info`'s uid/gid with the supplementary
    /// group list `gids` — both resolved by the caller from the **real**
    /// passwd/group databases *before* any `ChrootDirectory` was applied.
    /// Nothing here consults `/etc/passwd` or `/etc/group` (which, inside
    /// the jail, may be missing or attacker-writable): the ids are installed
    /// with `setgroups(2)` on the pre-resolved list, never `initgroups(3)`.
    /// Idempotent — if we already match `info`'s ids, the function is a
    /// no-op. Called from `Config::on_session_open` once per connection,
    /// after PAM session-open succeeded.
    fn drop_to_user(
        info: &UserInfo,
        gids: &[nix::unistd::Gid],
        debug: bool,
    ) -> puressh::Result<()> {
        let user = info.name.as_str();
        if already_matches(info) {
            if debug {
                eprintln!(
                    "sshd: connection already running as {user} (uid={})",
                    info.uid
                );
            }
            return Ok(());
        }
        // setgroups([]) → setgid → setgroups(list) → setuid. Clearing first
        // guarantees the post-drop process starts from an empty list even
        // if installing the resolved list somehow retained daemon groups.
        // setuid is the point of no return; we verify the result
        // afterwards to catch any silent capability/policy failure.
        setgroups_clear().map_err(nix_io)?;
        nix::unistd::setgid(info.gid).map_err(nix_io)?;
        setgroups_list(gids).map_err(nix_io)?;
        nix::unistd::setuid(info.uid).map_err(nix_io)?;
        verify_post_setuid(info.uid, info.gid).map_err(nix_io)?;
        if debug {
            eprintln!(
                "sshd: dropped connection to {user} (uid={} gid={} groups={})",
                info.uid,
                info.gid,
                gids.len()
            );
        }
        Ok(())
    }

    /// Install `gids` as the supplementary group list (`setgroups(2)`), via
    /// libc for the same portability reasons as [`setgroups_clear`].
    fn setgroups_list(gids: &[nix::unistd::Gid]) -> nix::Result<()> {
        let raw: Vec<libc::gid_t> = gids.iter().map(|g| g.as_raw()).collect();
        // SAFETY: `raw` is a live, correctly-sized array of gid_t for the
        // duration of the call; the count argument matches its length.
        let rc = unsafe { libc::setgroups(raw.len() as _, raw.as_ptr()) };
        if rc == 0 { Ok(()) } else { Err(Errno::last()) }
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

    /// `pipe(2)` with both ends marked close-on-exec.
    ///
    /// `pipe2(O_CLOEXEC)` would do this atomically, but nix only exposes it on
    /// Linux and the BSDs — macOS has no `pipe2` — and CI lints every target.
    /// The tiny window between `pipe` and `fcntl` only matters if another
    /// thread forks in between; every caller runs on the single-threaded
    /// accept loop (or in a test), so `pipe` + `F_SETFD` is equivalent here.
    fn pipe_cloexec() -> nix::Result<(OwnedFd, OwnedFd)> {
        let (rx, tx) = nix::unistd::pipe()?;
        for fd in [rx.as_fd(), tx.as_fd()] {
            fcntl(fd, FcntlArg::F_SETFD(FdFlag::FD_CLOEXEC))?;
        }
        Ok((rx, tx))
    }

    /// Spawn the user's login shell — or, with `command`, `shell -c command`
    /// (non-login argv0, as OpenSSH runs `exec` requests) — on a new pty.
    #[allow(clippy::too_many_arguments)]
    fn spawn_pty_shell(
        pam: &Arc<pam_gate::PamGate>,
        user: &str,
        session_env: &[(String, String)],
        spec: &PtySpec,
        debug: bool,
        print_motd: bool,
        command: Option<&str>,
        startup: Option<StartupRc>,
    ) -> puressh::Result<Box<dyn ShellSession>> {
        // argv for `shell -c command`, built pre-fork (allocation is not
        // async-signal-safe after fork).
        let command_argv: Option<[std::ffi::CString; 3]> = match command {
            Some(cmd) => Some([
                {
                    let shell = lookup_user(user)?.shell_c;
                    let base = shell
                        .as_bytes()
                        .rsplit(|b| *b == b'/')
                        .next()
                        .unwrap_or(b"sh");
                    std::ffi::CString::new(base).map_err(|_| {
                        puressh::Error::Io(std::io::Error::other("shell name has NUL"))
                    })?
                },
                c"-c".to_owned(),
                std::ffi::CString::new(cmd).map_err(|_| {
                    puressh::Error::Io(std::io::Error::other("command contains NUL byte"))
                })?,
            ]),
            None => None,
        };
        // PrintMotd: read /etc/motd in the parent (we may already be inside the
        // ChrootDirectory and dropped to the user — the file is read from the
        // session's view of the filesystem). The bytes are written to the
        // slave pty in the child just before exec so they land on the terminal
        // ahead of the shell prompt. Default is off, so this is skipped unless
        // PrintMotd=yes — which avoids double-printing when PAM's pam_motd is
        // already configured.
        // OpenSSH's check_quietlogin: a command, or ~/.hushlogin, silences
        // the motd and the last-login line.
        let quiet = command.is_some() || {
            let home = lookup_user(user)?.home_str;
            std::path::Path::new(&home).join(".hushlogin").exists()
        };
        let motd: Option<Vec<u8>> = if print_motd && !quiet {
            read_motd_for_pty(debug)
        } else {
            None
        };
        // PrintLastLog: the previous login, read before this one is recorded.
        #[cfg(all(target_os = "linux", target_env = "gnu"))]
        let last_login: Option<Vec<u8>> = if PRINT_LAST_LOG.load(Ordering::Relaxed) && !quiet {
            sshd_login::last_login_message(lookup_user(user)?.uid.as_raw()).map(String::into_bytes)
        } else {
            None
        };
        #[cfg(not(all(target_os = "linux", target_env = "gnu")))]
        let last_login: Option<Vec<u8>> = None;

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
        // Both ends close-on-exec: this connection process may later spawn
        // other children (an `exec` request's command, a second shell) and
        // none of them may inherit this channel's PTY master — a sibling
        // session could otherwise read/inject on the first one's terminal.
        // The slave is `dup2`'d onto stdio in the shell child below, which
        // clears the flag on the new descriptors, so it is harmless there.
        for fd in [pty.master.as_fd(), pty.slave.as_fd()] {
            fcntl(fd, FcntlArg::F_SETFD(FdFlag::FD_CLOEXEC)).map_err(nix_io)?;
        }

        // pty_setowner parity with OpenSSH: while still root and before the
        // fork hands the slave to the unprivileged shell, set the slave's
        // ownership to the authenticated user and mode to 0620 (user rw,
        // tty-group w). Without this the slave stays root-owned and, on a
        // permissively-configured devpts, another local user could snoop or
        // inject into the victim's tty. The tty group is resolved by name,
        // falling back to the user's primary gid when no "tty" group exists.
        //
        // Only meaningful when we are privileged and dropping to a different
        // user; when the daemon already runs as the target (e.g. unprivileged
        // single-user testing) the kernel already allocated the slave to that
        // uid and a self-chown would need privileges we don't have, so skip it.
        if drop_privs {
            let tty_gid = match nix::unistd::Group::from_name("tty").map_err(nix_io)? {
                Some(g) => g.gid,
                None => info.gid,
            };
            nix::unistd::fchown(pty.slave.as_fd(), Some(info.uid), Some(tty_gid))
                .map_err(nix_io)?;
            nix::sys::stat::fchmod(
                pty.slave.as_fd(),
                nix::sys::stat::Mode::from_bits_truncate(0o620),
            )
            .map_err(nix_io)?;
        }

        apply_pty_modes(pty.slave.as_raw_fd(), &spec.modes);

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
        // TERM from the pty request (it wins over a client `env` TERM, as
        // with OpenSSH), then the connection variables.
        let term = (!spec.term.is_empty()).then(|| ("TERM", spec.term.clone()));
        for (k, v) in term.into_iter().chain(connection_env(Some(&slave_path))) {
            if let (Ok(k), Ok(v)) = (std::ffi::CString::new(k), std::ffi::CString::new(v)) {
                channel_envs.push((k, v));
            }
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
                // The last-login line comes first, as with OpenSSH.
                for bytes in [&last_login, &motd].into_iter().flatten() {
                    // SAFETY: fd 1 is the slave pty; `bytes` is an owned, live
                    // buffer. write() is async-signal-safe in the post-fork
                    // child. Ignore the result (best-effort motd).
                    unsafe {
                        let _ = libc::write(1, bytes.as_ptr() as *const libc::c_void, bytes.len());
                    }
                }

                // The rc files / xauth (environment and cwd are set up),
                // then SIGPIPE back to its default: Rust ignores it, and an
                // ignored signal would survive into the user's shell
                // (`yes | head` complaining of a broken pipe).
                if let Some(rc) = &startup {
                    run_startup_rc(rc);
                }
                // SAFETY: resetting a disposition; async-signal-safe.
                unsafe {
                    libc::signal(libc::SIGPIPE, libc::SIG_DFL);
                }

                // `exec` on a pty: `shell -c command`, plain argv0.
                if let Some(argv) = &command_argv {
                    let _ = execvp(&info.shell_c, argv);
                    unsafe { libc::_exit(127) };
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
                // utmp / wtmp / lastlog.
                let login = record_login(child.as_raw(), &slave_path, user, info.uid.as_raw());
                Ok(Box::new(NixShellSession {
                    master: Some(master),
                    child_pid: child,
                    cached_exit: None,
                    login,
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

    /// Apply a `pty-req`'s terminal modes to the new pty, as OpenSSH's
    /// tty_parse_modes does: control characters (255: disabled), flags,
    /// character size and parity, line speeds. Unknown opcodes are skipped.
    fn apply_pty_modes(fd: std::os::fd::RawFd, modes: &[u8]) {
        // SAFETY: termios is plain data, filled in by tcgetattr.
        let mut t: libc::termios = unsafe { std::mem::zeroed() };
        if unsafe { libc::tcgetattr(fd, &mut t) } != 0 {
            return;
        }
        #[cfg(target_os = "linux")]
        const VDISABLE: libc::cc_t = 0;
        #[cfg(not(target_os = "linux"))]
        const VDISABLE: libc::cc_t = 0xff;
        let cc = |v: u32| if v == 255 { VDISABLE } else { v as libc::cc_t };
        for (op, v) in puressh::server::decode_terminal_modes(modes) {
            let on = v != 0;
            let set = |field: &mut libc::tcflag_t, bit: libc::tcflag_t| {
                if on {
                    *field |= bit;
                } else {
                    *field &= !bit;
                }
            };
            match op {
                1 => t.c_cc[libc::VINTR] = cc(v),
                2 => t.c_cc[libc::VQUIT] = cc(v),
                3 => t.c_cc[libc::VERASE] = cc(v),
                4 => t.c_cc[libc::VKILL] = cc(v),
                5 => t.c_cc[libc::VEOF] = cc(v),
                6 => t.c_cc[libc::VEOL] = cc(v),
                7 => t.c_cc[libc::VEOL2] = cc(v),
                8 => t.c_cc[libc::VSTART] = cc(v),
                9 => t.c_cc[libc::VSTOP] = cc(v),
                10 => t.c_cc[libc::VSUSP] = cc(v),
                12 => t.c_cc[libc::VREPRINT] = cc(v),
                13 => t.c_cc[libc::VWERASE] = cc(v),
                14 => t.c_cc[libc::VLNEXT] = cc(v),
                18 => t.c_cc[libc::VDISCARD] = cc(v),
                30 => set(&mut t.c_iflag, libc::IGNPAR),
                31 => set(&mut t.c_iflag, libc::PARMRK),
                32 => set(&mut t.c_iflag, libc::INPCK),
                33 => set(&mut t.c_iflag, libc::ISTRIP),
                34 => set(&mut t.c_iflag, libc::INLCR),
                35 => set(&mut t.c_iflag, libc::IGNCR),
                36 => set(&mut t.c_iflag, libc::ICRNL),
                #[cfg(target_os = "linux")]
                37 => set(&mut t.c_iflag, libc::IUCLC),
                38 => set(&mut t.c_iflag, libc::IXON),
                39 => set(&mut t.c_iflag, libc::IXANY),
                40 => set(&mut t.c_iflag, libc::IXOFF),
                41 => set(&mut t.c_iflag, libc::IMAXBEL),
                42 => set(&mut t.c_iflag, libc::IUTF8),
                50 => set(&mut t.c_lflag, libc::ISIG),
                51 => set(&mut t.c_lflag, libc::ICANON),
                53 => set(&mut t.c_lflag, libc::ECHO),
                54 => set(&mut t.c_lflag, libc::ECHOE),
                55 => set(&mut t.c_lflag, libc::ECHOK),
                56 => set(&mut t.c_lflag, libc::ECHONL),
                57 => set(&mut t.c_lflag, libc::NOFLSH),
                58 => set(&mut t.c_lflag, libc::TOSTOP),
                59 => set(&mut t.c_lflag, libc::IEXTEN),
                60 => set(&mut t.c_lflag, libc::ECHOCTL),
                61 => set(&mut t.c_lflag, libc::ECHOKE),
                62 => set(&mut t.c_lflag, libc::PENDIN),
                70 => set(&mut t.c_oflag, libc::OPOST),
                #[cfg(target_os = "linux")]
                71 => set(&mut t.c_oflag, libc::OLCUC),
                72 => set(&mut t.c_oflag, libc::ONLCR),
                73 => set(&mut t.c_oflag, libc::OCRNL),
                74 => set(&mut t.c_oflag, libc::ONOCR),
                75 => set(&mut t.c_oflag, libc::ONLRET),
                90 | 91 if on => {
                    t.c_cflag &= !libc::CSIZE;
                    t.c_cflag |= if op == 90 { libc::CS7 } else { libc::CS8 };
                }
                92 => set(&mut t.c_cflag, libc::PARENB),
                93 => set(&mut t.c_cflag, libc::PARODD),
                128 | 129 => {
                    let speed = match v {
                        9600 => libc::B9600,
                        19200 => libc::B19200,
                        38400 => libc::B38400,
                        57600 => libc::B57600,
                        115200 => libc::B115200,
                        230400 => libc::B230400,
                        _ => continue,
                    };
                    // SAFETY: plain setters on the local termios.
                    unsafe {
                        if op == 128 {
                            libc::cfsetispeed(&mut t, speed);
                        } else {
                            libc::cfsetospeed(&mut t, speed);
                        }
                    }
                }
                _ => {}
            }
        }
        // SAFETY: a valid fd and a fully initialised termios.
        unsafe { libc::tcsetattr(fd, libc::TCSANOW, &t) };
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
        /// The utmp/wtmp login, closed when the session ends.
        login: Option<LoginRecord>,
    }

    impl NixShellSession {
        /// Record the logout, once.
        fn logged_out(&mut self) {
            if let Some(l) = self.login.take() {
                record_logout(&l);
            }
        }
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
            // A pty has no half-close, and the client's EOF is not typed
            // into it (OpenSSH ignores it too): a ^D would reach a raw-mode
            // reader as data, and one typed ahead of the shell is lost.
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
            let status = self.wait_child();
            if status.is_some() {
                self.logged_out();
            }
            status
        }
    }

    impl NixShellSession {
        fn wait_child(&mut self) -> Option<ShellExitStatus> {
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
            self.logged_out();
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
    // The signal handlers touch ONLY the two atomics below (async-signal-
    // safe). Everything else — the child table with its per-IP counts and
    // auth-notification pipes — is owned by the accept loop and reconciled
    // there (`ChildTable::reap` / `ChildTable::poll_auth`), never from signal
    // context.
    // -------------------------------------------------------------------------

    /// Set by the SIGCHLD handler; the accept loop reaps on its next pass. The
    /// handler installs without `SA_RESTART`, so a child exit also wakes a
    /// `poll()` that is waiting for connections.
    static SIGCHLD_PENDING: AtomicBool = AtomicBool::new(false);

    /// Set to `true` by the SIGTERM/SIGINT handler. The accept loop polls
    /// it before each `accept()` and exits cleanly when it flips, letting
    /// in-flight children drain on their own without orphaning them.
    static SHUTDOWN_REQUESTED: AtomicBool = AtomicBool::new(false);

    /// SIGCHLD handler: just raise the flag. Reaping (`waitpid`) and the
    /// bookkeeping it drives happen in the accept loop, where a `Mutex` /
    /// `HashMap` may be touched.
    ///
    /// SAFETY: signal-context safe — a single relaxed atomic store.
    extern "C" fn sigchld_handler(_sig: libc::c_int) {
        SIGCHLD_PENDING.store(true, Ordering::Relaxed);
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

    /// `PrintLastLog` (global only, as in OpenSSH).
    static PRINT_LAST_LOG: AtomicBool = AtomicBool::new(true);

    /// Set by SIGHUP: re-read the configuration (by re-executing).
    static RELOAD_REQUESTED: AtomicBool = AtomicBool::new(false);

    /// SIGHUP handler. SAFETY: signal-context safe — one atomic store.
    extern "C" fn reload_handler(_sig: libc::c_int) {
        RELOAD_REQUESTED.store(true, Ordering::Relaxed);
    }

    /// SIGHUP: like OpenSSH, re-execute this binary with the original
    /// arguments, so the new process reads the configuration (and host keys)
    /// afresh. Live sessions are separate processes and are unaffected. The
    /// new configuration is checked first: if it does not load, the daemon
    /// keeps running with the old one rather than exiting. Returns only on
    /// failure.
    fn reload(cli: &Cli, args: &[String]) {
        if let Err(e) = load_effective_config(cli) {
            eprintln!("sshd: SIGHUP: new configuration rejected, keeping the old one: {e}");
            return;
        }
        // argv[0] when absolute (systemd starts us by absolute path, and it
        // still names the *new* binary after a package upgrade), else
        // /proc/self/exe.
        let exe = std::env::args_os()
            .next()
            .map(std::path::PathBuf::from)
            .filter(|p| p.is_absolute())
            .or_else(|| std::env::current_exe().ok());
        let Some(exe) = exe else {
            eprintln!("sshd: SIGHUP: cannot find our own executable; not reloading");
            return;
        };
        eprintln!("sshd: SIGHUP: re-executing {}", exe.display());
        // Listening sockets are close-on-exec; the new process binds afresh.
        // A detached daemon stays this process (same PID, PidFile right).
        let mut args = args.to_vec();
        if !cli.no_detach {
            args.push("-D".into());
        }
        let err = Command::new(&exe).args(&args).exec();
        eprintln!("sshd: SIGHUP: exec {}: {err}", exe.display());
    }

    /// Become a background daemon (see the caller).
    fn detach(keep_stderr: bool) -> Result<(), String> {
        // SAFETY: the daemon parent has no other threads at this point.
        match unsafe { nix::unistd::fork() } {
            Ok(ForkResult::Parent { .. }) => std::process::exit(0),
            Ok(ForkResult::Child) => {}
            Err(e) => return Err(format!("fork: {e}")),
        }
        nix::unistd::setsid().map_err(|e| format!("setsid: {e}"))?;
        let _ = std::env::set_current_dir("/");
        let null = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/null")
            .map_err(|e| format!("/dev/null: {e}"))?;
        let _ = nix::unistd::dup2_stdin(&null);
        let _ = nix::unistd::dup2_stdout(&null);
        if !keep_stderr {
            let _ = nix::unistd::dup2_stderr(&null);
        }
        Ok(())
    }

    /// Install SIGCHLD (wake the accept loop to reap) and SIGTERM/SIGINT
    /// (graceful shutdown).
    fn install_parent_signals() -> Result<(), String> {
        // SAFETY: `sigaction` with caller-owned `sigaction` structs is
        // POSIX-defined; the handler funcs we install reference only
        // statics + async-signal-safe APIs.
        unsafe {
            let mut sa: libc::sigaction = core::mem::zeroed();
            sa.sa_sigaction = sigchld_handler as *const () as usize;
            // SA_NOCLDSTOP: don't notify on stopped/continued children.
            // No SA_RESTART: a child exit must interrupt the accept loop's
            // `poll()` so the exit is reaped promptly (the loop treats
            // EINTR as "go around again").
            sa.sa_flags = libc::SA_NOCLDSTOP;
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
            // wake the blocked poll() so the loop can observe the flag.
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
            let mut sa: libc::sigaction = core::mem::zeroed();
            sa.sa_sigaction = reload_handler as *const () as usize;
            sa.sa_flags = 0;
            libc::sigemptyset(&mut sa.sa_mask);
            if libc::sigaction(libc::SIGHUP, &sa, core::ptr::null_mut()) != 0 {
                return Err(format!(
                    "sigaction(SIGHUP): {}",
                    std::io::Error::last_os_error()
                ));
            }
        }
        Ok(())
    }

    /// The byte a connection child writes to its auth-notification pipe once
    /// userauth has succeeded.
    const AUTH_OK_BYTE: u8 = b'A';

    /// Write end of *this* connection child's auth-notification pipe, as a raw
    /// fd (`-1` = none). The parent stores it just before `fork()` and clears
    /// it right after; fork's copy-on-write leaves the child with its own
    /// value, which the session-open hook consumes via
    /// [`notify_parent_authenticated`].
    static AUTH_NOTIFY_FD: AtomicI32 = AtomicI32::new(-1);

    /// Tell the daemon parent that this connection has authenticated, so it
    /// stops counting against `MaxStartups`: write one byte and close the
    /// pipe. Idempotent; a no-op when no pipe was set up (tests, or a
    /// pipe() failure at accept time).
    fn notify_parent_authenticated() {
        tell_parent(&[AUTH_OK_BYTE, b'\n']);
    }

    /// Send one message line to the daemon parent over this connection's
    /// pipe, which stays open for the connection's life: `A` (authenticated),
    /// `L pid tty user uid` / `O pid tty` (a pty login / logout to record —
    /// the parent is root and the connection no longer is). False when there
    /// is no pipe (tests, a pipe() failure at accept time).
    fn tell_parent(line: &[u8]) -> bool {
        let fd = AUTH_NOTIFY_FD.load(Ordering::Relaxed);
        if fd < 0 {
            return false;
        }
        // SAFETY: the fd was created by `pipe_cloexec` in the parent and its
        // ownership handed to this static at fork; nothing closes it.
        let tx = unsafe { BorrowedFd::borrow_raw(fd) };
        nix::unistd::write(tx, line).is_ok_and(|n| n == line.len())
    }

    /// A pty login being recorded: by the daemon parent (normally), or
    /// directly when there is no parent to ask.
    enum LoginRecord {
        Parent {
            pid: i32,
            tty: String,
        },
        #[cfg(all(target_os = "linux", target_env = "gnu"))]
        Local(sshd_login::Session),
    }

    /// Record a pty login (utmp, wtmp, lastlog) of `user` on `tty`.
    fn record_login(pid: i32, tty: &str, user: &str, uid: u32) -> Option<LoginRecord> {
        let msg = format!("L\t{pid}\t{tty}\t{user}\t{uid}\n");
        if tell_parent(msg.as_bytes()) {
            return Some(LoginRecord::Parent {
                pid,
                tty: tty.to_string(),
            });
        }
        #[cfg(all(target_os = "linux", target_env = "gnu"))]
        {
            let peer = conn_addrs().map(|(p, _)| p.ip());
            let host = peer.map(sshd_log::addr_str).unwrap_or_default();
            Some(LoginRecord::Local(sshd_login::login(
                pid, tty, user, uid, &host, peer,
            )))
        }
        #[cfg(not(all(target_os = "linux", target_env = "gnu")))]
        None
    }

    fn record_logout(rec: &LoginRecord) {
        match rec {
            LoginRecord::Parent { pid, tty } => {
                tell_parent(format!("O\t{pid}\t{tty}\n").as_bytes());
            }
            #[cfg(all(target_os = "linux", target_env = "gnu"))]
            LoginRecord::Local(s) => sshd_login::logout(s),
        }
    }

    /// One forked connection child, as tracked by the daemon parent.
    struct ChildRecord {
        /// Peer IP, for `--per-source-max`. Counted for the child's whole
        /// lifetime.
        ip: IpAddr,
        /// Read end of the auth-notification pipe, held while the child has
        /// not yet reported success. `None` once it has (or once it closed
        /// the pipe without doing so, e.g. exited pre-auth).
        auth_rx: Option<OwnedFd>,
        /// True once the child reported userauth success; such children no
        /// longer count against `MaxStartups`.
        authenticated: bool,
        /// Unprocessed bytes from the pipe (messages are lines).
        buf: Vec<u8>,
        /// Pty logins recorded for this child, closed when it says so or
        /// when it is reaped.
        #[cfg(all(target_os = "linux", target_env = "gnu"))]
        logins: Vec<sshd_login::Session>,
    }

    impl ChildRecord {
        /// Handle one message line from the child (see `tell_parent`).
        fn message(&mut self, line: &[u8]) {
            if line == [AUTH_OK_BYTE] {
                self.authenticated = true;
            } else {
                #[cfg(all(target_os = "linux", target_env = "gnu"))]
                self.login_message(line);
            }
        }

        /// `L …` / `O …`: record a pty login or logout.
        #[cfg(all(target_os = "linux", target_env = "gnu"))]
        fn login_message(&mut self, line: &[u8]) {
            {
                let Ok(line) = std::str::from_utf8(line) else {
                    return;
                };
                let f: Vec<&str> = line.split('\t').collect();
                match f.as_slice() {
                    ["L", pid, tty, user, uid] if self.authenticated && self.logins.len() < 64 => {
                        let (Ok(pid), Ok(uid)) = (pid.parse::<i32>(), uid.parse::<u32>()) else {
                            return;
                        };
                        if !login_claim_ok(tty, user, uid) {
                            return;
                        }
                        // The peer as this parent knows it, not as claimed.
                        let host = sshd_log::addr_str(self.ip);
                        self.logins.push(sshd_login::login(
                            pid,
                            tty,
                            user,
                            uid,
                            &host,
                            Some(self.ip),
                        ));
                    }
                    ["O", pid, tty] => {
                        let Ok(pid) = pid.parse::<i32>() else {
                            return;
                        };
                        if let Some(i) = self.logins.iter().position(|l| l.is(pid, tty)) {
                            sshd_login::logout(&self.logins.remove(i));
                        }
                    }
                    _ => {}
                }
            }
        }

        /// Close every login still open (the connection is gone).
        fn close_logins(&mut self) {
            #[cfg(all(target_os = "linux", target_env = "gnu"))]
            for l in self.logins.drain(..) {
                sshd_login::logout(&l);
            }
        }
    }

    /// A child's login claim holds: `tty` is a pty owned by `uid`, which is
    /// `user`'s. (The child runs as that user: it can only own its ptys.)
    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    fn login_claim_ok(tty: &str, user: &str, uid: u32) -> bool {
        use std::os::unix::fs::MetadataExt;
        let Some(n) = tty.strip_prefix("/dev/pts/") else {
            return false;
        };
        !n.is_empty()
            && n.bytes().all(|b| b.is_ascii_digit())
            && std::fs::metadata(tty).is_ok_and(|m| m.uid() == uid)
            && lookup_user(user).is_ok_and(|i| i.uid.as_raw() == uid)
    }

    /// The daemon parent's table of live connection children, keyed by pid.
    /// Owned by the accept loop; never touched from signal context.
    #[derive(Default)]
    struct ChildTable {
        children: HashMap<Pid, ChildRecord>,
    }

    impl ChildTable {
        fn len(&self) -> usize {
            self.children.len()
        }

        /// Children that have not yet reported authentication success.
        fn unauthenticated(&self) -> usize {
            self.children.values().filter(|c| !c.authenticated).count()
        }

        /// Live children (any auth state) from `ip`.
        fn count_from_ip(&self, ip: IpAddr) -> usize {
            self.children.values().filter(|c| c.ip == ip).count()
        }

        /// Record a freshly forked child.
        fn insert(&mut self, pid: Pid, ip: IpAddr, auth_rx: Option<OwnedFd>) {
            self.children.insert(
                pid,
                ChildRecord {
                    ip,
                    auth_rx,
                    authenticated: false,
                    buf: Vec::new(),
                    #[cfg(all(target_os = "linux", target_env = "gnu"))]
                    logins: Vec::new(),
                },
            );
        }

        /// Reap every exited child (`waitpid(WNOHANG)` loop) and drop its
        /// record — releasing its per-IP slot and closing its pipe.
        fn reap(&mut self, debug: bool) {
            loop {
                match waitpid(None, Some(WaitPidFlag::WNOHANG)) {
                    Ok(WaitStatus::StillAlive) | Err(_) => break,
                    Ok(status) => {
                        if let Some(pid) = status.pid()
                            && let Some(mut rec) = self.children.remove(&pid)
                        {
                            rec.close_logins();
                        } else {
                            continue;
                        }
                        if let Some(pid) = status.pid()
                            && debug
                        {
                            eprintln!(
                                "sshd: reaped connection pid {} (live={}, unauth={})",
                                pid.as_raw(),
                                self.len(),
                                self.unauthenticated()
                            );
                        }
                    }
                }
            }
        }

        /// Collect auth-success notifications: a non-blocking `poll()` over
        /// every unauthenticated child's pipe. A child that wrote
        /// [`AUTH_OK_BYTE`] moves to the authenticated column; a pipe that
        /// closed without it (child exited pre-auth) is just released — the
        /// record itself goes when the child is reaped.
        fn poll_auth(&mut self) {
            let pids: Vec<Pid> = self
                .children
                .iter()
                .filter(|(_, c)| c.auth_rx.is_some())
                .map(|(pid, _)| *pid)
                .collect();
            if pids.is_empty() {
                return;
            }
            let mut fds: Vec<PollFd<'_>> = pids
                .iter()
                .map(|pid| {
                    let rx = self.children[pid].auth_rx.as_ref().expect("filtered above");
                    PollFd::new(rx.as_fd(), PollFlags::POLLIN)
                })
                .collect();
            match poll(&mut fds, PollTimeout::ZERO) {
                Ok(n) if n > 0 => {}
                _ => return,
            }
            let ready: Vec<Pid> = pids
                .iter()
                .zip(fds.iter())
                .filter(|(_, f)| f.any().unwrap_or(false))
                .map(|(pid, _)| *pid)
                .collect();
            drop(fds);
            for pid in ready {
                let Some(rec) = self.children.get_mut(&pid) else {
                    continue;
                };
                let Some(rx) = rec.auth_rx.as_ref() else {
                    continue;
                };
                let mut chunk = [0u8; 4096];
                match nix::unistd::read(rx, &mut chunk) {
                    Ok(n) if n > 0 => rec.buf.extend_from_slice(&chunk[..n]),
                    Err(Errno::EINTR | Errno::EAGAIN) => continue,
                    // EOF (the child exited) or an error: the pipe is done.
                    _ => {
                        rec.auth_rx = None;
                    }
                }
                while let Some(i) = rec.buf.iter().position(|b| *b == b'\n') {
                    let line: Vec<u8> = rec.buf.drain(..=i).collect();
                    rec.message(&line[..line.len() - 1]);
                }
                // A child that will not end its lines gets no more hearing.
                if rec.buf.len() > 4096 {
                    rec.buf.clear();
                    rec.auth_rx = None;
                }
            }
        }

        /// Every open child pipe, for the accept loop's poll set.
        fn pipe_fds(&self) -> Vec<BorrowedFd<'_>> {
            self.children
                .values()
                .filter_map(|c| c.auth_rx.as_ref().map(|fd| fd.as_fd()))
                .collect()
        }

        /// Apply the two connection caps: `MaxStartups` over the
        /// *unauthenticated* children only (an authenticated peer cannot
        /// exhaust it, and a flood of idle pre-auth connections cannot block
        /// logins beyond its own budget), and `--per-source-max` over every
        /// live child from the peer's IP. `Err(reason)` ⇒ refuse (the caller
        /// logs and closes the socket).
        fn admit(
            &self,
            peer: &std::net::SocketAddr,
            max_startups: u32,
            early: Option<(u32, u32)>,
            per_source_max: u32,
        ) -> Result<(), &'static str> {
            let unauth = self.unauthenticated();
            if max_startups > 0 && unauth >= max_startups as usize {
                return Err("max-startups");
            }
            // `MaxStartups start:rate:full`: random early drop, `rate`% at
            // `start` rising linearly to 100% at `full` (OpenSSH's formula).
            if let Some((start, rate)) = early
                && max_startups > 0
                && unauth >= start as usize
            {
                let (start, full, unauth) = (start as u64, max_startups as u64, unauth as u64);
                let p = if full > start {
                    (100 - rate as u64) * (unauth - start) / (full - start) + rate as u64
                } else {
                    100
                };
                use purecrypto::rng::{OsRng, RngCore};
                if (OsRng.next_u32() % 100) < p as u32 {
                    return Err("max-startups (early drop)");
                }
            }
            if per_source_max > 0 && self.count_from_ip(peer.ip()) >= per_source_max as usize {
                return Err("per-source-max");
            }
            Ok(())
        }
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

        // `-E file`: append diagnostics to `file` from here on.
        if let Some(path) = cli.log_file.as_deref() {
            let f = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)
                .map_err(|e| format!("-E {path}: {e}"))?;
            nix::unistd::dup2_stderr(&f).map_err(|e| format!("-E {path}: {e}"))?;
        }

        // sshd_config: `-o` options, then `-f` (default /etc/ssh/sshd_config
        // when present), with OpenSSH's defaults for anything left unset.
        // CLI flags always win over the config file.
        let mut sshd_cfg = load_effective_config(&cli)?;
        apply_openssh_defaults(&mut sshd_cfg.global);
        let _ = XAUTH_LOCATION.set(match sshd_cfg.global.xauth_location.as_deref() {
            Some(p) if p.eq_ignore_ascii_case("none") => None,
            Some(p) => Some(p.to_string()),
            None => Some("/usr/bin/xauth".to_string()),
        });
        // `PubkeyAcceptedAlgorithms +ssh-rsa` (global or in a Match block):
        // accept old clients' SHA-1 RSA signatures, as OpenSSH then does.
        let names_ssh_rsa = |o: &puressh::config::ServerOptions| {
            o.pubkey_accepted_algorithms.as_ref().is_some_and(|l| {
                l.iter()
                    .any(|a| a == "ssh-rsa" || a == "ssh-rsa-cert-v01@openssh.com")
            })
        };
        let host_key_ssh_rsa = sshd_cfg
            .global
            .host_key_algorithms
            .as_ref()
            .is_some_and(|l| {
                l.iter()
                    .any(|a| a == "ssh-rsa" || a == "ssh-rsa-cert-v01@openssh.com")
            });
        if host_key_ssh_rsa
            || names_ssh_rsa(&sshd_cfg.global)
            || sshd_cfg.match_blocks.iter().any(|b| names_ssh_rsa(&b.opts))
        {
            puressh::hostkey::set_allow_rsa_sha1(true);
        }
        let sshd_cfg = Arc::new(sshd_cfg);
        // OpenSSH keywords we accept but do not implement, ignored arguments.
        for w in sshd_cfg.warnings() {
            eprintln!("sshd: warning: config {w}");
        }
        if cli.dump_config {
            return dump_config(&cli, &sshd_cfg);
        }

        // LogLevel (sshd_config): VERBOSE/DEBUG* (level >= 1) turns on the same
        // verbose diagnostics as `-d`, so the config keyword actually controls
        // output. `-d` always wins (it can't be turned back off). Rebind `cli`
        // so every downstream `cli.debug` reflects the effective level.
        let log_level = sshd_cfg.global.log_level.unwrap_or(3);
        // OpenSSH's logging: syslog (SyslogFacility) at LogLevel, or stderr
        // with -d / -e / -E; -d raises the level to DEBUG1, -q silences it.
        {
            let configured = puressh::config::server::LOG_LEVELS[usize::from(log_level.min(7))];
            let mut level = sshd_log::Level::parse(configured).unwrap_or(sshd_log::Level::Info);
            if cli.debug {
                level = level.max(sshd_log::Level::Debug1);
            }
            if cli.quiet {
                level = sshd_log::Level::Quiet;
            }
            let facility = sshd_cfg
                .global
                .syslog_facility
                .as_deref()
                .and_then(sshd_log::facility)
                .unwrap_or(libc::LOG_AUTH);
            let to_stderr = cli.debug || cli.log_stderr || cli.log_file.is_some() || cli.test_only;
            sshd_log::init(level, facility, to_stderr);
            PRINT_LAST_LOG.store(
                sshd_cfg.global.print_last_log.unwrap_or(true),
                Ordering::Relaxed,
            );
            sshd_log::set_max_auth_tries(
                sshd_cfg
                    .global
                    .max_auth_tries
                    .unwrap_or(puressh::server::DEFAULT_MAX_AUTH_TRIES),
            );
        }
        // `-d` itself (not LogLevel DEBUG) keeps the daemon in the foreground.
        let debug_flag = cli.debug;
        let cli = {
            let mut c = cli;
            c.debug = c.debug || log_level >= 5;
            c
        };

        // Resolve effective values: CLI > config > built-in default.
        // Ports: `-p` (repeatable), else every `Port` line, else 22.
        let ports: Vec<u16> = if !cli.ports.is_empty() {
            cli.ports.clone()
        } else if !sshd_cfg.global.ports.is_empty() {
            sshd_cfg.global.ports.clone()
        } else {
            vec![22]
        };
        // The first one names the daemon in diagnostics and is the knock's
        // default UDP port.
        let port = ports[0];
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
        // X11Forwarding defaults to `no`, as in OpenSSH.
        let x11_forward = pick(cli.x11_forward, sshd_cfg.global.x11_forwarding, false);
        let login_grace_time = pick(
            cli.login_grace_time,
            sshd_cfg.global.login_grace_time,
            120u32,
        );
        let max_startups = pick(cli.max_startups, sshd_cfg.global.max_startups, 100u32);
        // `--per-source-max` > `PerSourceMaxStartups` > no cap (OpenSSH's
        // default; `none` is 0 as well).
        let per_source_max = pick(
            cli.per_source_max,
            sshd_cfg.global.per_source_max_startups,
            0u32,
        );

        // CLI host-keys, then any HostKey lines from config (cumulative).
        let mut host_key_files = cli.host_key_files.clone();
        host_key_files.extend(sshd_cfg.global.host_key_files.iter().cloned());
        if host_key_files.is_empty() {
            // OpenSSH's defaults, skipping the ones that do not exist.
            host_key_files = DEFAULT_HOST_KEYS
                .iter()
                .filter(|p| std::path::Path::new(p).exists())
                .map(|p| p.to_string())
                .collect();
        }
        if host_key_files.is_empty() {
            return Err(format!(
                "no host keys: none of {} exist (generate them with `ssh-keygen -A`), \
                 and no -h / HostKey was given",
                DEFAULT_HOST_KEYS.join(", ")
            ));
        }

        // CLI `-u`, then `AllowUsers` from the global section. `AllowUsers`
        // lines inside `Match` blocks are added per connection by the
        // authenticator once the user / peer are known.
        let mut allowed_user_list = cli.allowed_users.clone();
        allowed_user_list.extend(sshd_cfg.global.allow_users.iter().cloned());

        // Likewise `--accept-env` ++ `AcceptEnv`.
        let mut accept_env = cli.accept_env.clone();
        accept_env.extend(sshd_cfg.global.accept_env.iter().cloned());

        // Listen addresses: `-b` + `ListenAddress` (cumulative), on `ports`.
        let mut bind_specs = cli.listen_addresses.clone();
        bind_specs.extend(sshd_cfg.global.listen_addresses.iter().cloned());

        let mut host_certificate_files = cli.host_certificate_files.clone();
        host_certificate_files.extend(sshd_cfg.global.host_certificate_files.iter().cloned());
        // `HostKeyAgent SSH_AUTH_SOCK` names the environment's agent.
        let host_key_agent = sshd_cfg.global.host_key_agent.as_deref().and_then(|a| {
            if a == "SSH_AUTH_SOCK" {
                std::env::var("SSH_AUTH_SOCK")
                    .ok()
                    .filter(|s| !s.is_empty())
            } else {
                Some(a.to_string())
            }
        });
        let host_keys = load_host_keys_with_certs(
            &host_key_files,
            &host_certificate_files,
            strict_modes,
            host_key_agent.as_deref(),
        )?;
        // Authorized keys come in two mutually exclusive modes:
        //
        //  * Per-user (the default, OpenSSH semantics): `AuthorizedKeysFile`
        //    templates, expanded and read by each connection for its own
        //    login user (`LocalAuthenticator::resolved_authorized_keys`),
        //    StrictModes-checked against that user. Nothing is read here.
        //
        //  * `-A FILE`: ONE global file whose every key authorizes the single
        //    allowed user. Loaded now, as the daemon's user, with the
        //    root-owned StrictModes rule. Because the file cannot say *which*
        //    user a key belongs to, it is refused unless exactly one literal
        //    user is allowed anywhere in the configuration.
        // The single user a `-A` file authorizes, for the knock key source.
        let mut global_keys_user: Option<String> = None;
        let global_authorized_keys: Option<Arc<AuthorizedKeys>> = match &cli.authorized_keys_file {
            Some(path) => {
                let mut all_allowed: Vec<String> = allowed_user_list.clone();
                for block in &sshd_cfg.match_blocks {
                    all_allowed.extend(block.opts.allow_users.iter().cloned());
                }
                all_allowed.sort();
                all_allowed.dedup();
                let single = match all_allowed.as_slice() {
                    [] => current_user()?,
                    [one] if is_literal_user_token(one) => one.clone(),
                    _ => {
                        return Err(format!(
                            "-A {path}: a global authorized_keys file authorizes every key in it \
                             for every allowed user, so it requires exactly one literal allowed \
                             user (-u USER, or a single AllowUsers name with no wildcard/@host); \
                             configured: {all_allowed:?}. Use AuthorizedKeysFile (per-user, \
                             with %u/%h tokens) instead."
                        ));
                    }
                };
                let set = load_authorized_keys_and_cas(path, strict_modes, None)?;
                eprintln!(
                    "sshd: -A {path}: {} key(s) and {} cert-authority line(s) authorize user \
                     {single:?} (global file; every listed key logs in as that user)",
                    set.blobs.len(),
                    set.cas.len()
                );
                global_keys_user = Some(single);
                Some(Arc::new(set))
            }
            None => None,
        };
        let authorized_keys_files: Vec<String> = sshd_cfg
            .global
            .authorized_keys_file
            .clone()
            .unwrap_or_else(default_authorized_keys_files);
        let knock_keys = KnockKeys {
            users: (!sshd_cfg.global.knock_users.is_empty())
                .then(|| sshd_cfg.global.knock_users.clone()),
            global: global_keys_user.clone().zip(global_authorized_keys.clone()),
            files: authorized_keys_files.clone(),
            strict_modes,
            debug: cli.debug,
        };
        // A template with no per-user token is one shared file: every key in
        // it logs in as any allowed user. Legal (as in OpenSSH), but loud.
        for block in sshd_cfg.all_blocks() {
            for t in block.authorized_keys_file.iter().flatten() {
                if t.starts_with('/') && !t.contains("%u") && !t.contains("%h") {
                    eprintln!(
                        "sshd: WARNING: AuthorizedKeysFile {t} has no %u/%h token: every key in \
                         it can log in as ANY allowed user"
                    );
                }
            }
        }

        // TrustedUserCAKeys / RevokedKeys: load every file named in the global
        // section *or any Match block* now, so a bad path is a startup error
        // (failing closed beats silently running with no revocation), and each
        // connection just picks the set its matched blocks name.
        let mut ca_files: HashMap<String, Arc<Vec<Vec<u8>>>> = HashMap::new();
        let mut krls: HashMap<Vec<String>, Arc<puressh::krl::Krl>> = HashMap::new();
        for block in sshd_cfg.all_blocks() {
            if let Some(path) = &block.trusted_user_ca_keys
                && !ca_files.contains_key(path)
            {
                let cas = load_ca_keys_file(path, strict_modes)
                    .map_err(|e| format!("TrustedUserCAKeys: {e}"))?;
                ca_files.insert(path.clone(), Arc::new(cas));
            }
            if let Some(path) = &block.revoked_keys
                && !krls.contains_key(path)
            {
                krls.insert(path.clone(), Arc::new(load_krls(path, cli.debug)?));
            }
        }
        let trusted_user_ca_blobs: Vec<Vec<u8>> = sshd_cfg
            .global
            .trusted_user_ca_keys
            .as_ref()
            .and_then(|p| ca_files.get(p))
            .map(|v| (**v).clone())
            .unwrap_or_default();
        let revoked_keys: Option<Arc<puressh::krl::Krl>> = sshd_cfg
            .global
            .revoked_keys
            .as_ref()
            .and_then(|p| krls.get(p).cloned());

        // AuthorizedPrincipalsFile: keep the raw path *template* (it may carry
        // `%u`/`%h` tokens). Each connection expands it against its own login
        // user's passwd entry and loads it lazily in the authenticator — `%h`
        // is only knowable once the user is bound.
        let authorized_principals_file: Option<String> =
            sshd_cfg.global.authorized_principals_file.clone();

        // AllowUsers is matched as OpenSSH `Host`-style globs (a literal name
        // is just a glob with no metacharacters). Empty ⇒ no restriction, as
        // in OpenSSH (a daemon not running as root can only ever serve its
        // own user anyway: it cannot switch to anyone else).
        let default_allow_user: Option<String> = None;
        let allow_users = UserHostPattern::parse_all(&effective_allow_users(
            &cli.allowed_users,
            &sshd_cfg.global.allow_users,
            default_allow_user.as_deref(),
        ));
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
        // `PAMServiceName`: kept for the daemon's lifetime.
        let pam_service: &'static str = match &sshd_cfg.global.pam_service_name {
            Some(s) => Box::leak(s.clone().into_boxed_str()),
            None => "sshd",
        };
        let pam_gate = pam_gate::PamGate::new(cli.debug, pam_service);

        // Whether a real PAM backend is compiled in. Password and
        // keyboard-interactive auth are *only* advertised when both the config
        // enables them AND this is a PAM build — otherwise we'd offer a method
        // we cannot satisfy. `pam_check_password` on a non-PAM build always
        // fails, so this is the authoritative gate.
        let pam_available = cfg!(all(feature = "pam", target_os = "linux"));
        if pam_available && sshd_cfg.global.use_pam == Some(false) {
            eprintln!(
                "sshd: warning: UsePAM no: PAM account and session checks still run (this \
                 build has no non-PAM account checks to fall back on)"
            );
        }

        // OpenSSH defaults both to yes (Ubuntu's stock file turns
        // keyboard-interactive off).
        // What this build can offer. Whether a method is on for a connection
        // (`PubkeyAuthentication`, `PasswordAuthentication`,
        // `KbdInteractiveAuthentication`, globally or in a `Match` block, which
        // may turn one back on) is resolved per connection by the server, which
        // refuses an attempt at any other method before the authenticator sees
        // it.
        let password_enabled = pam_available;
        let kbd_interactive_enabled = pam_available;
        let permit_empty_passwords = sshd_cfg.global.permit_empty_passwords == Some(true);

        let asked_password = sshd_cfg.global.password_authentication == Some(true)
            || sshd_cfg.global.kbd_interactive_authentication == Some(true);
        if asked_password && !pam_available {
            eprintln!(
                "sshd: warning: PasswordAuthentication/KbdInteractiveAuthentication requested but \
                 no PAM backend is compiled in (need the `pam` feature on Linux); these methods \
                 will NOT be advertised"
            );
        }

        let mut advertised: Vec<&'static str> =
            vec!["publickey", "password", "keyboard-interactive"];
        if !pam_available {
            advertised.retain(|m| *m == "publickey");
        }
        if cli.debug {
            eprintln!("sshd: auth methods available: {advertised:?}");
        }

        // Connection-wide AuthenticationMethods default (multi-factor chains),
        // threaded into the authenticator via on_user_resolved.
        let default_auth_methods = sshd_cfg
            .global
            .authentication_methods
            .clone()
            .unwrap_or_default();

        let conn_policy = Arc::new(ConnPolicy {
            config: sshd_cfg.clone(),
            cli_allow_users: cli.allowed_users.clone(),
            default_allow_user,
            cli_permit_root_login: cli.permit_root_login,
            ca_files,
            krls,
        });

        let factory = Arc::new(LocalAuthFactory {
            allow_users: Arc::new(allow_users),
            deny_users: Arc::new(deny_users),
            allow_groups: Arc::new(allow_groups),
            deny_groups: Arc::new(deny_groups),
            global_authorized_keys,
            authorized_keys_files,
            trusted_user_ca_blobs: Arc::new(trusted_user_ca_blobs),
            revoked_keys,
            policy: Some(conn_policy.clone()),
            authorized_principals_file,
            strict_modes,
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

        let shell_commands = Arc::new(ShellCommandHandler {
            pam: pam_gate.clone(),
            debug: cli.debug,
            debug_commands: cli.debug_commands,
        });
        let mut config = Config::new(host_keys, factory, advertised, shell_commands.clone())
            .with_auth_methods(default_auth_methods)
            .with_shell(Arc::new(NixShellHandler {
                pam: pam_gate.clone(),
                debug: cli.debug,
                print_motd: print_motd_flag.clone(),
            }));

        // Resolved CASignatureAlgorithms for user-certificate verification.
        if let Some(ca) = sshd_cfg.global.ca_signature_algorithms.clone() {
            config.ca_signature_algorithms = ca;
        }

        // Always installed: a forced `internal-sftp` runs it even without a
        // `Subsystem sftp` line, as OpenSSH's does.
        config = config.with_subsystem(Arc::new(SftpSubsystemHandler {
            enabled: sftp_enabled,
            read_only: sftp_read_only,
            root: sftp_root.clone(),
            args: sshd_cfg
                .global
                .subsystem_sftp_args
                .clone()
                .unwrap_or_default(),
            debug: cli.debug,
        }));
        for (name, command) in sshd_cfg.global.subsystems.iter().flatten() {
            config = config.with_subsystem_command(name, command);
        }

        // TCP and Unix-socket forwarding (`ssh -L/-R/-D/-W`), on by default
        // as in OpenSSH. The handlers accept what reaches them: the server's
        // per-user policy layer applies AllowTcpForwarding, PermitOpen,
        // PermitListen, GatewayPorts (bind-address rewrite),
        // AllowStreamLocalForwarding and DisableForwarding first, and the
        // connection already runs as the logged-in user.
        config = config
            .with_direct_tcpip(Arc::new(
                puressh::forwarding::direct::DefaultDirectTcpipHandler::permit_all(),
            ))
            .with_tcpip_forward(Arc::new(
                puressh::forwarding::reverse::DefaultTcpipForwardHandler::permit_all_interfaces(),
            ))
            .with_direct_streamlocal(Arc::new(
                puressh::forwarding::direct_streamlocal::DefaultDirectStreamlocalHandler::permit_all(),
            ))
            .with_streamlocal_forward(Arc::new(
                puressh::forwarding::streamlocal::DefaultStreamlocalForwardHandler::permit_all(),
            ));

        // `exec` requests stream (stdin, stdout, stderr, exit status);
        // `scp` is served in-process when enabled.
        config = config.with_exec_stream_handler(Arc::new(ExecDispatch {
            scp: scp_enabled.then_some(ScpExecHandler { debug: cli.debug }),
            shell: shell_commands,
        }));

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
        let hook_policy = conn_policy.clone();
        config = config.on_session_open(move |ctx: &SessionOpenContext<'_>| {
            let user = ctx.user;
            // Userauth has succeeded by the time this hook runs: tell the
            // daemon parent so this connection stops counting against
            // `MaxStartups` (whatever happens below, it is no longer an
            // unauthenticated connection an attacker could be holding open).
            notify_parent_authenticated();
            // PermitRootLogin backstop, evaluated at login time before we
            // open a PAM session or drop privilege. The authenticator already
            // denies root during userauth; this re-checks against the live
            // passwd database so a uid-0 login cannot proceed even if it
            // reached session-open by some other path. Resolved here (not at
            // startup) so it reflects the current database and the `Match`
            // blocks that apply to this connection.
            let permit_root_login = conn_permit_root_login(&hook_policy, user);
            // Resolve the identity we will drop to — uid, gid, supplementary
            // groups — from the REAL passwd/group databases now, before any
            // ChrootDirectory is entered. Everything below uses this resolved
            // value; nothing re-reads `<jail>/etc/passwd` or `<jail>/etc/group`
            // (a jail without them would fail closed, and a jail whose /etc is
            // writable by the user could otherwise map the login to uid 0 and
            // skip the drop entirely). The value is also cached so later
            // per-handler lookups (shell, home) inside the jail see it.
            let info = lookup_user(user)?;
            let gids = group_gids(&info.name, info.gid);
            let is_root = user == "root" || resolves_to_root(user) || info.uid.is_root();
            if is_root && !permit_root_login.permits_publickey() {
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
            remember_session_user(&info);
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
                apply_chroot(&info, dir, debug)?;
            }
            drop_to_user(&info, &gids, debug)
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
        config.pubkey_accepted_algorithms = sshd_cfg.global.pubkey_accepted_algorithms.clone();

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

        // AddressFamily (startup-only): `-4`/`-6` > config; restricts the
        // listener family.
        let address_family = cli.address_family.or(sshd_cfg.global.address_family);
        let listen = listen_addrs(&bind_specs, &ports, address_family)?;
        // PidFile (startup-only): write our PID after bind unless `none`;
        // OpenSSH's /run/sshd.pid by default (as root: elsewhere it could
        // not be written).
        let pid_file = if sshd_cfg.global.pid_file_set {
            sshd_cfg.global.pid_file.clone()
        } else if nix::unistd::geteuid().is_root() {
            Some("/run/sshd.pid".to_string())
        } else {
            None
        };

        // Per-connection policy: the whole parsed sshd_config (global + Match
        // blocks) is resolved twice per connection (pre-auth address-only,
        // post-auth user/groups) to gate the auth method set, banner, and
        // forwarding capabilities. The group resolver feeds `Match group`.
        config = config
            .with_policy(sshd_cfg.clone())
            .with_group_resolver(group_lookup);

        let cfg = Arc::new(config);

        // `-t`: everything above parsed and loaded; stop before binding.
        if cli.test_only {
            if cli.debug {
                eprintln!("sshd: configuration OK; would listen on {listen:?}");
            }
            return Ok(0);
        }

        // `-i`: one connection, on stdin / stdout.
        if cli.inetd {
            return serve_inetd(cfg);
        }

        // As OpenSSH does for its session processes: no ptrace attach and no
        // core dumps (host keys, session keys). Forked connection handlers
        // inherit it; the users' programs (exec) get the default back. Only
        // as root: a daemon run by an ordinary user holds keys that user can
        // read anyway, and non-dumpable makes /proc/self root-owned, which
        // breaks PAM modules (pam_loginuid) that user's sessions go through.
        #[cfg(any(target_os = "linux", target_os = "android"))]
        if nix::unistd::geteuid().is_root() {
            // SAFETY: PR_SET_DUMPABLE takes plain integer arguments.
            unsafe {
                libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0);
            }
        }

        install_parent_signals()?;

        // The parent holds a pipe per live connection (login records): use
        // the whole open-file allowance (systemd's soft default is 1024).
        // SAFETY: getrlimit/setrlimit on a local, fully initialised struct.
        unsafe {
            let mut lim: libc::rlimit = std::mem::zeroed();
            if libc::getrlimit(libc::RLIMIT_NOFILE, &mut lim) == 0 && lim.rlim_cur < lim.rlim_max {
                lim.rlim_cur = lim.rlim_max;
                libc::setrlimit(libc::RLIMIT_NOFILE, &lim);
            }
        }

        // As in OpenSSH, an address that cannot be bound (e.g. `::` on a host
        // without IPv6) is reported and skipped; only binding none is fatal.
        let mut listeners = Vec::with_capacity(listen.len());
        let mut bound = Vec::with_capacity(listen.len());
        let mut bind_errors = Vec::new();
        for a in &listen {
            match bind_listener(*a) {
                Ok(l) => {
                    listeners.push(l);
                    bound.push(*a);
                }
                Err(e) => {
                    eprintln!("sshd: warning: bind {a}: {e}");
                    bind_errors.push(format!("{a}: {e}"));
                }
            }
        }
        if listeners.is_empty() {
            return Err(format!(
                "could not bind any address: {}",
                bind_errors.join("; ")
            ));
        }
        let listen = bound;
        let mut knock = KnockFrontend::bind(
            &sshd_cfg.global,
            port,
            knock_keys,
            &host_key_files,
            cli.debug,
        )?;

        // Without `-D` (or `-d`): detach now that the listeners are up (so a
        // bind failure still reaches the terminal and the exit status), as
        // OpenSSH's daemon(0, 0): fork, the parent exits, a new session,
        // `/` as the working directory, stdio on /dev/null (except a `-E`
        // log, which is stderr). The parent is still single-threaded.
        if !cli.no_detach && !debug_flag {
            detach(cli.log_file.is_some())?;
        }

        // PidFile: write our PID now that the listener is up.
        if let Some(path) = pid_file.as_deref()
            && let Err(e) = std::fs::write(path, format!("{}\n", std::process::id()))
        {
            eprintln!("sshd: warning: could not write PidFile {path}: {e}");
        }

        for a in &listen {
            sshd_log::info(&format!(
                "Server listening on {} port {}.",
                sshd_log::addr_str(a.ip()),
                a.port()
            ));
        }
        notify_ready();

        // Exponential backoff for `fork()` EAGAIN — under a fork-bomb a
        // tight `continue` loop just makes the kernel keep saying no.
        // Reset to `MIN` on any successful fork.
        const FORK_BACKOFF_MIN_MS: u64 = 10;
        const FORK_BACKOFF_MAX_MS: u64 = 1_000;
        let mut fork_backoff_ms: u64 = FORK_BACKOFF_MIN_MS;

        // Live connection children: per-IP accounting for `--per-source-max`
        // and the unauthenticated count for `MaxStartups`. Reconciled at the
        // top of every pass (reap exits, collect auth notifications) — the
        // only place the caps are consulted is right before a fork, so that
        // is exactly when the table must be current.
        let mut children = ChildTable::default();
        // How long `poll()` waits for a connection before the loop goes
        // around anyway to reap / check the shutdown flag. A signal (SIGCHLD,
        // SIGTERM) interrupts it earlier — `poll()` is not restarted on
        // EINTR, unlike std's `accept()`, which retries internally and would
        // otherwise swallow the wake-up.
        let accept_tick = PollTimeout::from(1_000u16);

        loop {
            if SHUTDOWN_REQUESTED.load(Ordering::Relaxed) {
                sshd_log::info("Received signal 15; terminating.");
                if cli.debug {
                    eprintln!("sshd: shutdown requested, exiting accept loop");
                }
                break;
            }
            if RELOAD_REQUESTED.swap(false, Ordering::Relaxed) {
                reload(&cli, &args);
            }
            if SIGCHLD_PENDING.swap(false, Ordering::Relaxed) || children.len() > 0 {
                children.reap(cli.debug);
            }
            children.poll_auth();

            // Wait on the listener plus every knock socket / rendezvous
            // listener, waking early for the knock's own deadlines.
            let tick = match knock.next_wakeup() {
                Some(d) => {
                    let ms = d
                        .saturating_duration_since(std::time::Instant::now())
                        .as_millis()
                        .clamp(1, 1_000) as u16;
                    PollTimeout::from(ms)
                }
                None => accept_tick,
            };
            let ready_listeners: Vec<usize> = {
                let mut wait: Vec<PollFd<'_>> = listeners
                    .iter()
                    .map(|l| PollFd::new(l.as_fd(), PollFlags::POLLIN))
                    .collect();
                wait.extend(
                    knock
                        .poll_fds()
                        .into_iter()
                        .map(|fd| PollFd::new(fd, PollFlags::POLLIN)),
                );
                // Children's messages (logins to record) wake the loop too.
                wait.extend(
                    children
                        .pipe_fds()
                        .into_iter()
                        .map(|fd| PollFd::new(fd, PollFlags::POLLIN)),
                );
                match poll(&mut wait, tick) {
                    Ok(_) => {}
                    Err(Errno::EINTR) => continue, // signal: flags checked above
                    Err(e) => {
                        eprintln!("sshd: poll: {e}");
                        std::thread::sleep(std::time::Duration::from_millis(FORK_BACKOFF_MIN_MS));
                        continue;
                    }
                }
                (0..listeners.len())
                    .filter(|&i| wait[i].revents().is_some_and(|r| !r.is_empty()))
                    .collect()
            };

            // Connections to hand off this pass: knocked rendezvous
            // connections (bound to the knock's user), then the listener.
            let mut incoming: Vec<(std::net::TcpStream, std::net::SocketAddr, Option<String>)> =
                Vec::new();
            for (stream, peer, user) in knock.process() {
                if cli.debug {
                    eprintln!("sshd: knock: rendezvous from {peer} for {user}");
                }
                incoming.push((stream, peer, Some(user)));
            }
            for i in ready_listeners {
                match listeners[i].accept() {
                    Ok((stream, peer)) => incoming.push((stream, peer, None)),
                    Err(e)
                        if matches!(
                            e.kind(),
                            std::io::ErrorKind::Interrupted | std::io::ErrorKind::WouldBlock
                        ) => {}
                    Err(e) => eprintln!("sshd: accept: {e}"),
                }
            }

            // TCPKeepAlive (default yes, as OpenSSH): a peer that vanished
            // is noticed and its session cleaned up.
            if sshd_cfg.global.tcp_keep_alive != Some(false) {
                for (stream, _, _) in &incoming {
                    let _ = nix::sys::socket::setsockopt(
                        stream,
                        nix::sys::socket::sockopt::KeepAlive,
                        &true,
                    );
                }
            }
            let mut incoming = incoming.into_iter();
            #[allow(clippy::while_let_on_iterator)] // the child drops `incoming` mid-loop
            while let Some((stream, peer, knock_user)) = incoming.next() {
                // Enforce both connection caps *before* fork so a flood
                // can't OOM us via per-process accounting. On refusal we
                // simply drop the socket — RST tells the client to retry.
                if let Err(reason) = children.admit(
                    &peer,
                    max_startups,
                    sshd_cfg.global.max_startups_early,
                    per_source_max,
                ) {
                    if cli.debug {
                        eprintln!(
                            "sshd: refused {peer}: {reason} (live={}, unauth={}, from-ip={})",
                            children.len(),
                            children.unauthenticated(),
                            children.count_from_ip(peer.ip())
                        );
                    }
                    drop(stream);
                    continue;
                }

                // Auth-notification pipe: the child writes one byte on userauth
                // success so the parent moves it out of the `MaxStartups`
                // count. Close-on-exec on both ends, so no program the child
                // later spawns inherits either. If the pipe cannot be created
                // the child is simply counted as unauthenticated for life
                // (fail closed for the cap; the connection still works).
                let (auth_rx, auth_tx) = match pipe_cloexec() {
                    Ok(p) => (Some(p.0), Some(p.1)),
                    Err(e) => {
                        eprintln!("sshd: pipe for auth notification: {e}");
                        (None, None)
                    }
                };
                AUTH_NOTIFY_FD.store(
                    auth_tx.as_ref().map(|fd| fd.as_raw_fd()).unwrap_or(-1),
                    Ordering::Relaxed,
                );

                // SAFETY: the daemon parent is single-threaded — no `thread::spawn`
                // in this loop — so the `fork()` is followed by ordinary Rust
                // code with no async-signal-safety concerns. The kernel
                // duplicates fds across fork; the child inherits its own copy of
                // `stream` and `listener`.
                match unsafe { fork() } {
                    Ok(ForkResult::Parent { child }) => {
                        fork_backoff_ms = FORK_BACKOFF_MIN_MS;
                        // The write end now belongs to the child alone: close
                        // ours so its EOF is observable, and forget the fd.
                        AUTH_NOTIFY_FD.store(-1, Ordering::Relaxed);
                        drop(auth_tx);
                        // Account the child (per-IP slot, unauthenticated) for as
                        // long as it lives; `reap` releases it.
                        children.insert(child, peer.ip(), auth_rx);
                        if cli.debug {
                            eprintln!(
                                "sshd: forked connection {peer} -> pid {} (live={}, unauth={})",
                                child.as_raw(),
                                children.len(),
                                children.unauthenticated(),
                            );
                        }
                        // Parent has no further use for this socket — its
                        // refcount in the child keeps it alive.
                        drop(stream);
                    }
                    Ok(ForkResult::Child) => {
                        // The child owns nothing in the parent's table: close the
                        // inherited read ends (this one's and every sibling's).
                        // Its own write end is now owned by `AUTH_NOTIFY_FD`, so
                        // the `OwnedFd` wrapper must not close it here.
                        drop(children);
                        drop(auth_rx);
                        if let Some(tx) = auth_tx {
                            core::mem::forget(tx);
                        }
                        // CRUCIAL: release the listener fd before we enter the
                        // long session loop. Without this, restarting the
                        // daemon on the same port keeps hitting EADDRINUSE
                        // because the kernel sees an open listener.
                        drop(listeners);
                        // Likewise the knock sockets, and every other connection
                        // of this batch (each is the parent's / a sibling's).
                        #[allow(clippy::drop_non_drop)] // empty without `knock`
                        drop(knock);
                        drop(incoming);
                        if let Ok(mut g) = KNOCK_USER.lock() {
                            *g = knock_user;
                        }
                        // Restore default SIGCHLD so the grandchild shell
                        // can be reaped via waitpid(WNOHANG).
                        // SAFETY: same justification as the parent — we run
                        // in a single-threaded process here.
                        let _ = unsafe { signal(Signal::SIGCHLD, SigHandler::SigDfl) };
                        // Likewise restore default SIGTERM/SIGINT/SIGHUP so
                        // the child dies cleanly on signal rather than getting
                        // the parent's shutdown / reload handlers.
                        let _ = unsafe { signal(Signal::SIGTERM, SigHandler::SigDfl) };
                        let _ = unsafe { signal(Signal::SIGINT, SigHandler::SigDfl) };
                        let _ = unsafe { signal(Signal::SIGHUP, SigHandler::SigDfl) };

                        // Stash the peer address on *this child's* PamGate
                        // copy — set_peer mutates state behind a Mutex but
                        // post-fork COW means only this child sees it.
                        pam_gate.set_peer(peer.to_string());
                        // Likewise record this connection's socket addresses for
                        // the `Match LocalAddress`/`LocalPort` context and the
                        // session-open hook (COW-isolated per child).
                        if let Ok(mut g) = CONN_ADDRS.lock() {
                            *g = Some((peer, stream.local_addr().ok()));
                        }
                        sshd_log::conn_begin(peer, stream.local_addr().ok());

                        let result = handle_session_with_peer(stream, peer, cfg.clone());
                        sshd_log::conn_end(match &result {
                            Ok(()) => sshd_log::End::Closed,
                            Err(puressh::Error::Disconnected {
                                reason,
                                description,
                            }) => sshd_log::End::PeerDisconnect {
                                reason: *reason,
                                description,
                            },
                            Err(puressh::Error::AuthFailed) => sshd_log::End::AuthFailed,
                            Err(puressh::Error::Io(e))
                                if e.kind() == std::io::ErrorKind::TimedOut =>
                            {
                                sshd_log::End::GraceTimeout
                            }
                            // The client going away is a close, not an error.
                            Err(puressh::Error::Protocol("connection closed")) => {
                                sshd_log::End::Closed
                            }
                            Err(puressh::Error::Io(e))
                                if matches!(
                                    e.kind(),
                                    std::io::ErrorKind::ConnectionReset
                                        | std::io::ErrorKind::BrokenPipe
                                        | std::io::ErrorKind::UnexpectedEof
                                        | std::io::ErrorKind::ConnectionAborted
                                ) =>
                            {
                                sshd_log::End::Closed
                            }
                            Err(e) => match e.openssh_negotiation_message(false) {
                                Some(m) => sshd_log::End::NoMatch(m),
                                None => sshd_log::End::Error(e.to_string()),
                            },
                        });
                        let rc = match result {
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
                        AUTH_NOTIFY_FD.store(-1, Ordering::Relaxed);
                        drop(auth_tx);
                        drop(auth_rx);
                        drop(stream);
                        // Bounded exponential backoff so a sustained EAGAIN
                        // (rlimit, OOM-killer pressure) doesn't pin a core.
                        std::thread::sleep(std::time::Duration::from_millis(fork_backoff_ms));
                        fork_backoff_ms = (fork_backoff_ms * 2).min(FORK_BACKOFF_MAX_MS);
                    }
                }
            }
        }
        // As OpenSSH's daemon on SIGTERM: the PidFile goes with it.
        if let Some(path) = pid_file.as_deref() {
            let _ = std::fs::remove_file(path);
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

        #[test]
        fn cidr_matches_ipv4() {
            let ip = "10.1.2.3".parse().unwrap();
            assert!(cidr_matches("10.0.0.0/8", ip));
            assert!(cidr_matches("10.1.2.3", ip)); // bare = /32 exact
            assert!(!cidr_matches("10.1.2.4", ip));
            assert!(!cidr_matches("192.168.0.0/16", ip));
            // Family mismatch never matches.
            assert!(!cidr_matches("2001:db8::/32", ip));
            // Malformed prefix rejects.
            assert!(!cidr_matches("10.0.0.0/99", ip));
        }

        #[test]
        fn cidr_matches_ipv6() {
            let ip = "2001:db8::1".parse().unwrap();
            assert!(cidr_matches("2001:db8::/32", ip));
            assert!(!cidr_matches("2001:dead::/32", ip));
        }

        #[test]
        fn parse_peer_ip_forms() {
            assert_eq!(
                parse_peer_ip("10.0.0.5:2222"),
                Some("10.0.0.5".parse().unwrap())
            );
            assert_eq!(parse_peer_ip("10.0.0.5"), Some("10.0.0.5".parse().unwrap()));
            assert_eq!(
                parse_peer_ip("[2001:db8::1]:22"),
                Some("2001:db8::1".parse().unwrap())
            );
        }

        #[test]
        fn sanitize_log_strips_control_chars_and_truncates() {
            assert_eq!(sanitize_log("alice"), "alice");
            assert_eq!(sanitize_log("a\nb\rc\x1b[2Jd\x7f"), "a?b?c?[2Jd?");
            let long = "x".repeat(LOG_FIELD_MAX + 10);
            let out = sanitize_log(&long);
            assert_eq!(out.chars().count(), LOG_FIELD_MAX + 1);
            assert!(out.ends_with('…'));
        }

        #[test]
        fn invalid_usernames_never_bind() {
            assert!(valid_username("alice"));
            assert!(!valid_username(""));
            assert!(!valid_username("ali\nce"));
            assert!(!valid_username(&"a".repeat(USERNAME_MAX + 1)));
            let mut a = auth_with(&["*"], &[], &[], &[], Default::default());
            assert!(!a.check_user_binding("eve\x1b[2J"));
            assert!(a.bound_user.is_none(), "an invalid name must not bind");
            // A publickey attempt with such a name is refused outright.
            let decision = a.evaluate(AuthAttempt::PublicKey {
                user: "eve\r\nforged: line".into(),
                algorithm: "ssh-ed25519".into(),
                public_blob: vec![1, 2, 3],
                probe_only: true,
                verified: false,
                cert: None,
            });
            assert!(matches!(decision, AuthDecision::Reject));
        }

        #[test]
        fn decode_ssh_string_roundtrip() {
            // "force-command"="echo hi" inner payload is an SSH string.
            let mut blob = Vec::new();
            let s = b"echo hi";
            blob.extend_from_slice(&(s.len() as u32).to_be_bytes());
            blob.extend_from_slice(s);
            assert_eq!(decode_ssh_string(&blob).as_deref(), Some("echo hi"));
            // Truncated / mismatched length rejects.
            assert_eq!(decode_ssh_string(&blob[..blob.len() - 1]), None);
        }

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
                global_authorized_keys: None,
                authorized_keys_files: Vec::new(),
                authorized_keys: Some(AuthorizedKeys::default()),
                trusted_user_ca_blobs: Vec::new(),
                revoked_keys: None,
                policy: None,
                policy_broken: false,
                authorized_principals_file: None,
                strict_modes: false,
                authorized_principals: None,
                auth_commands: AuthCommands::default(),
                command_cache: Default::default(),
                permit_root_login: puressh::config::PermitRootLogin::ProhibitPassword,
                pam: pam_gate::PamGate::new(false, "sshd"),
                password_enabled: false,
                kbd_interactive_enabled: false,
                kbd_conv: None,
                pending_first_prompt: true,
                permit_empty_passwords: false,
                pubkey_accepted: None,
                required_rsa_size: DEFAULT_REQUIRED_RSA_SIZE,
                chains: Vec::new(),
                satisfied: Vec::new(),
                bound_user: None,
                root_uid0_cache: std::collections::HashMap::new(),
                group_cache: std::collections::HashMap::new(),
                group_lookup: lookup,
                peer: peer.map(str::to_string),
                debug: false,
                accepted_options: None,
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
        fn failure_lists_only_methods_that_can_continue() {
            let offered = ["publickey", "password", "keyboard-interactive"];
            let mut a = auth_with(&["*"], &[], &[], &[], Default::default());
            // Single-factor: everything offered.
            assert_eq!(a.continuable_methods(&offered), offered);
            // `AuthenticationMethods publickey,password publickey,keyboard-interactive`.
            a.chains = vec![
                vec!["publickey", "password"],
                vec!["publickey", "keyboard-interactive"],
            ];
            assert_eq!(a.continuable_methods(&offered), ["publickey"]);
            a.satisfied = vec!["publickey"];
            assert_eq!(
                a.continuable_methods(&offered),
                ["password", "keyboard-interactive"]
            );
            // A method the server does not offer is never listed.
            assert_eq!(
                a.continuable_methods(&["publickey", "password"]),
                ["password"]
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
        fn record_and_decide_enforces_listed_order() {
            // OpenSSH positional order: for `publickey,password`, completing
            // `password` FIRST is out of order and rejected; only `publickey`
            // first advances the chain.
            let mut a = auth_with(&["*"], &[], &[], &[], Default::default());
            a.chains = vec![vec!["publickey", "password"]];
            // password-first ⇒ rejected, chain not advanced.
            assert!(matches!(
                a.record_and_decide("password"),
                AuthDecision::Reject
            ));
            assert!(a.satisfied.is_empty(), "rejected method must not commit");
            // publickey first ⇒ PartialAccept asking for password next.
            match a.record_and_decide("publickey") {
                AuthDecision::PartialAccept { still_required } => {
                    assert_eq!(still_required, vec!["password".to_string()]);
                }
                other => panic!("expected PartialAccept, got {other:?}"),
            }
            // now password completes the chain in order.
            assert!(matches!(
                a.record_and_decide("password"),
                AuthDecision::Accept
            ));
        }

        #[test]
        fn record_and_decide_still_required_is_next_not_set() {
            // With two alternative chains sharing a first factor, `still_required`
            // after the shared first factor lists only the *next* methods, in the
            // listed order — never the full remaining set.
            let mut a = auth_with(&["*"], &[], &[], &[], Default::default());
            a.chains = vec![
                vec!["publickey", "password"],
                vec!["publickey", "keyboard-interactive"],
            ];
            match a.record_and_decide("publickey") {
                AuthDecision::PartialAccept { still_required } => {
                    assert_eq!(
                        still_required,
                        vec!["password".to_string(), "keyboard-interactive".to_string()]
                    );
                }
                other => panic!("expected PartialAccept, got {other:?}"),
            }
            // Completing the second factor of either alternative accepts.
            assert!(matches!(
                a.record_and_decide("keyboard-interactive"),
                AuthDecision::Accept
            ));
        }

        #[test]
        fn record_and_decide_three_factor_order() {
            // A three-factor chain must be completed strictly in order.
            let mut a = auth_with(&["*"], &[], &[], &[], Default::default());
            a.chains = vec![vec!["publickey", "keyboard-interactive", "password"]];
            assert!(matches!(
                a.record_and_decide("publickey"),
                AuthDecision::PartialAccept { .. }
            ));
            // Skipping to `password` (the 3rd) before the 2nd is rejected.
            assert!(matches!(
                a.record_and_decide("password"),
                AuthDecision::Reject
            ));
            // The expected 2nd factor advances.
            assert!(matches!(
                a.record_and_decide("keyboard-interactive"),
                AuthDecision::PartialAccept { .. }
            ));
            assert!(matches!(
                a.record_and_decide("password"),
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
            let out = expand_pct_tokens("/chroots/%u", &info).expect("expand");
            assert_eq!(out, format!("/chroots/{}", info.name));
            let out2 = expand_pct_tokens("%h/jail", &info).expect("expand");
            assert_eq!(out2, format!("{}/jail", info.home_str));
            assert_eq!(expand_pct_tokens("100%%", &info).expect("expand"), "100%");
            // Unknown token rejected.
            assert!(expand_pct_tokens("%z", &info).is_err());
            assert!(expand_pct_tokens("trailing%", &info).is_err());
        }

        #[test]
        fn authorized_principals_file_expands_u_token() {
            // Build an AuthorizedPrincipalsFile path containing `%u`, write a
            // principals list at the expanded path, and confirm the lazy loader
            // resolves + reads it for the bound user.
            let info = lookup_user_for_test();
            let user = info.name.clone();
            let dir = std::env::temp_dir().join(format!("puressh-princ-{}", std::process::id()));
            std::fs::create_dir_all(&dir).expect("mkdir");
            // Path template uses %u; the resolved file is named after the user.
            let template = format!("{}/%u.principals", dir.display());
            let expanded = format!("{}/{}.principals", dir.display(), user);
            std::fs::write(&expanded, "alice\nbob\n# comment\n\n").expect("write principals");

            let mut a = auth_with(&["*"], &[], &[], &[], Default::default());
            a.authorized_principals_file = Some(template);
            a.strict_modes = false; // temp file isn't root-owned

            let resolved = a
                .resolved_principals(&user)
                .clone()
                .map(|l| l.into_iter().map(|p| p.name).collect::<Vec<_>>());
            std::fs::remove_file(&expanded).ok();
            std::fs::remove_dir(&dir).ok();

            assert_eq!(
                resolved,
                Some(vec!["alice".to_string(), "bob".to_string()]),
                "%u-expanded AuthorizedPrincipalsFile must load the user's file"
            );
        }

        #[test]
        fn authorized_principals_file_none_is_no_constraint() {
            // No file configured ⇒ resolves to `None` (login user must itself be
            // a cert principal — OpenSSH default).
            let mut a = auth_with(&["*"], &[], &[], &[], Default::default());
            a.authorized_principals_file = None;
            assert!(a.resolved_principals("anyone").is_none());
        }

        #[test]
        fn authorized_principals_file_missing_fails_closed() {
            // A configured-but-missing file resolves to `Some(vec![])` — no
            // principals — which fails authorization closed (never widens it).
            let info = lookup_user_for_test();
            let mut a = auth_with(&["*"], &[], &[], &[], Default::default());
            a.authorized_principals_file = Some("/nonexistent/puressh/%u.principals".to_string());
            a.strict_modes = false;
            assert!(
                a.resolved_principals(&info.name)
                    .as_ref()
                    .is_some_and(Vec::is_empty)
            );
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
        fn session_user_cache_answers_lookup_without_passwd() {
            // Once the session-open hook has resolved the identity, a lookup
            // for that name is served from the cache (as it would be inside a
            // jail with no /etc/passwd), and other names still hit the
            // database.
            let mut info = lookup_user_for_test();
            info.name = "puressh-cached-user-xyzzy".to_string();
            info.home_str = "/cached-home".to_string();
            remember_session_user(&info);
            let got = lookup_user("puressh-cached-user-xyzzy").expect("served from cache");
            assert_eq!(got.home_str, "/cached-home");
            assert_eq!(got.uid, info.uid);
            assert!(lookup_user("\u{0}no-such-user-xyzzy").is_err());
            if let Ok(mut g) = SESSION_USER.lock() {
                *g = None;
            }
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
                    let root = lookup_user("root").expect("root passwd entry");
                    let ok = apply_chroot(&root, jail.to_str().unwrap(), false).is_ok()
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

        // ---- KRL revocation wiring -----------------------------------------

        /// Decode a hex string to bytes (test-only helper).
        fn unhex(s: &str) -> Vec<u8> {
            (0..s.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
                .collect()
        }

        /// Real `ssh-keygen -k` explicit-key KRL revoking the user key below.
        const KRL_EXPLICIT_HEX: &str = "5353484b524c0a00000000010000000000000000000000006a31ff28000000000000000000000000000000000200000037000000330000000b7373682d6564323535313900000020dac8c367fff423cc766d20abff4f2620880f421ea7e2c58a47100892e490547f";
        /// Raw wire blob of that user's ed25519 public key.
        const USERKEY_BLOB_HEX: &str = "0000000b7373682d6564323535313900000020dac8c367fff423cc766d20abff4f2620880f421ea7e2c58a47100892e490547f";

        #[test]
        fn krl_revokes_authorized_plain_key() {
            let blob = unhex(USERKEY_BLOB_HEX);
            let krl =
                puressh::krl::Krl::parse(&unhex(KRL_EXPLICIT_HEX)).expect("parse fixture KRL");

            // Build an authenticator that *authorizes* the key, then revokes it.
            let mut a = auth_with(&["*"], &[], &[], &[], Default::default());
            a.authorized_keys = Some(AuthorizedKeys {
                blobs: vec![blob.clone()],
                cas: Vec::new(),
                ..Default::default()
            });
            a.revoked_keys = Some(std::sync::Arc::new(krl));

            // A verified publickey attempt for an authorized-but-revoked key is
            // rejected.
            let decision = a.evaluate(AuthAttempt::PublicKey {
                user: "alice".into(),
                algorithm: "ssh-ed25519".into(),
                public_blob: blob.clone(),
                probe_only: false,
                verified: true,
                cert: None,
            });
            assert!(matches!(decision, AuthDecision::Reject));
        }

        fn verified_attempt(alg: &str, blob: &[u8]) -> AuthAttempt {
            AuthAttempt::PublicKey {
                user: "alice".into(),
                algorithm: alg.into(),
                public_blob: blob.to_vec(),
                probe_only: false,
                verified: true,
                cert: None,
            }
        }

        fn authorizing(blob: &[u8]) -> LocalAuthenticator {
            let mut a = auth_with(&["*"], &[], &[], &[], Default::default());
            a.authorized_keys = Some(AuthorizedKeys {
                blobs: vec![blob.to_vec()],
                cas: Vec::new(),
                ..Default::default()
            });
            a
        }

        #[test]
        fn pubkey_accepted_algorithms_gate_userauth() {
            let blob = unhex(USERKEY_BLOB_HEX);
            let mut a = authorizing(&blob);
            assert!(matches!(
                a.evaluate(verified_attempt("ssh-ed25519", &blob)),
                AuthDecision::Accept
            ));
            let mut a = authorizing(&blob);
            a.pubkey_accepted = Some(vec!["rsa-sha2-512".into()]);
            assert!(matches!(
                a.evaluate(verified_attempt("ssh-ed25519", &blob)),
                AuthDecision::Reject
            ));
        }

        #[test]
        fn required_rsa_size_gates_userauth() {
            let rsa = |bits: usize| {
                let mut n = vec![0u8; bits / 8];
                n[0] = 0x80;
                PublicKey::Rsa {
                    e: vec![1, 0, 1],
                    n,
                    comment: String::new(),
                }
                .wire_blob()
            };
            let small = rsa(1024);
            assert_eq!(rsa_modulus_bits(&small), Some(1024));
            assert_eq!(rsa_modulus_bits(&unhex(USERKEY_BLOB_HEX)), None);
            let mut a = authorizing(&small);
            assert!(!matches!(
                a.evaluate(verified_attempt("rsa-sha2-512", &small)),
                AuthDecision::Reject
            ));
            let mut a = authorizing(&small);
            a.required_rsa_size = 2048;
            assert!(matches!(
                a.evaluate(verified_attempt("rsa-sha2-512", &small)),
                AuthDecision::Reject
            ));
            let tiny = rsa(768);
            let mut a = authorizing(&tiny);
            assert!(matches!(
                a.evaluate(verified_attempt("rsa-sha2-512", &tiny)),
                AuthDecision::Reject
            ));
        }

        /// A `CertInfo` wrapping `USERKEY_BLOB_HEX` as its embedded key, signed
        /// by a (fake) CA blob, with `alice` as its sole principal. The CA
        /// signature was already verified by the auth layer by the time the
        /// authenticator sees a `verified` attempt, so no real signature is
        /// needed to exercise the trust gate.
        fn cert_info_for(ca_blob: &[u8], principals: &[&str]) -> puressh::auth::CertInfo {
            puressh::auth::CertInfo::new(
                ca_blob.to_vec(),
                unhex(USERKEY_BLOB_HEX),
                "ssh-ed25519",
                "test-cert",
                7,
                principals.iter().map(|s| s.to_string()).collect(),
            )
        }

        #[test]
        fn krl_revoked_plain_key_also_refuses_certificate_wrapping_it() {
            // The KRL revokes the plain user key. A certificate whose
            // *embedded* key is that plain key must be refused even though the
            // cert blob itself (a different byte string) is not listed and the
            // CA is trusted.
            let krl =
                puressh::krl::Krl::parse(&unhex(KRL_EXPLICIT_HEX)).expect("parse fixture KRL");
            let ca_blob =
                b"\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20fakeCAfakeCAfakeCAfakeCAfakeCAfa"
                    .to_vec();
            let ci = cert_info_for(&ca_blob, &["alice"]);
            let cert_blob = b"not-the-plain-key-blob".to_vec();

            let mut a = auth_with(&["*"], &[], &[], &[], Default::default());
            a.trusted_user_ca_blobs = vec![ca_blob.clone()];
            // Sanity: without a KRL the certificate is accepted.
            let ok = a.evaluate(AuthAttempt::PublicKey {
                user: "alice".into(),
                algorithm: "ssh-ed25519-cert-v01@openssh.com".into(),
                public_blob: cert_blob.clone(),
                probe_only: false,
                verified: true,
                cert: Some(ci.clone()),
            });
            assert!(matches!(ok, AuthDecision::Accept), "{ok:?}");

            let mut b = auth_with(&["*"], &[], &[], &[], Default::default());
            b.trusted_user_ca_blobs = vec![ca_blob];
            b.revoked_keys = Some(std::sync::Arc::new(krl));
            let decision = b.evaluate(AuthAttempt::PublicKey {
                user: "alice".into(),
                algorithm: "ssh-ed25519-cert-v01@openssh.com".into(),
                public_blob: cert_blob,
                probe_only: false,
                verified: true,
                cert: Some(ci),
            });
            assert!(matches!(decision, AuthDecision::Reject), "{decision:?}");
        }

        /// The fixture user key as an `authorized_keys` line.
        const USERKEY_LINE: &str =
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINrIw2f/9CPMdm0gq/9PJiCID0Iep+LFikcQCJLkkFR/ test";

        fn cert_attempt(user: &str, ci: &puressh::auth::CertInfo) -> AuthAttempt {
            AuthAttempt::PublicKey {
                user: user.into(),
                algorithm: "ssh-ed25519-cert-v01@openssh.com".into(),
                public_blob: b"cert-blob".to_vec(),
                probe_only: false,
                verified: true,
                cert: Some(ci.clone()),
            }
        }

        // ---- S7: principals= on cert-authority lines ------------------------

        #[test]
        fn cert_authority_line_principals_option_replaces_username_check() {
            let ca = b"fake-ca-blob-1".to_vec();
            // A CA trusted only via the user's own authorized_keys, restricted
            // to certs carrying the `deploy` principal.
            let ak = AuthorizedKeys {
                blobs: Vec::new(),
                cas: vec![(ca.clone(), Some(vec!["deploy".to_string()]))],
                ..Default::default()
            };
            // Cert lists `deploy` but NOT the login user: accepted, because the
            // principals= list replaces the login-user-must-be-a-principal rule.
            let mut a = auth_with(&["*"], &[], &[], &[], Default::default());
            a.authorized_keys = Some(ak.clone());
            let ci = cert_info_for(&ca, &["deploy"]);
            assert!(matches!(
                a.evaluate(cert_attempt("alice", &ci)),
                AuthDecision::Accept
            ));

            // Cert lists the login user but not `deploy`: refused.
            let mut b = auth_with(&["*"], &[], &[], &[], Default::default());
            b.authorized_keys = Some(ak.clone());
            let ci = cert_info_for(&ca, &["alice"]);
            assert!(matches!(
                b.evaluate(cert_attempt("alice", &ci)),
                AuthDecision::Reject
            ));

            // A cert with NO principals never satisfies a principals= list.
            let mut c = auth_with(&["*"], &[], &[], &[], Default::default());
            c.authorized_keys = Some(ak);
            let ci = cert_info_for(&ca, &[]);
            assert!(matches!(
                c.evaluate(cert_attempt("alice", &ci)),
                AuthDecision::Reject
            ));

            // Without principals=, the standard rule applies: login user must
            // be a principal.
            let plain = AuthorizedKeys {
                blobs: Vec::new(),
                cas: vec![(ca.clone(), None)],
                ..Default::default()
            };
            let mut d = auth_with(&["*"], &[], &[], &[], Default::default());
            d.authorized_keys = Some(plain.clone());
            let ci = cert_info_for(&ca, &["alice"]);
            assert!(matches!(
                d.evaluate(cert_attempt("alice", &ci)),
                AuthDecision::Accept
            ));
            let mut e = auth_with(&["*"], &[], &[], &[], Default::default());
            e.authorized_keys = Some(plain);
            let ci = cert_info_for(&ca, &["bob"]);
            assert!(matches!(
                e.evaluate(cert_attempt("alice", &ci)),
                AuthDecision::Reject
            ));

            // An unrelated CA is not trusted at all.
            let mut f = auth_with(&["*"], &[], &[], &[], Default::default());
            f.authorized_keys = Some(AuthorizedKeys::default());
            let ci = cert_info_for(&ca, &["alice"]);
            assert!(matches!(
                f.evaluate(cert_attempt("alice", &ci)),
                AuthDecision::Reject
            ));
        }

        #[test]
        fn principals_option_matching_is_glob() {
            let list = vec!["deploy-*".to_string(), "ops".to_string()];
            assert!(principals_match_option(&list, &["deploy-eu".to_string()]));
            assert!(principals_match_option(
                &list,
                &["x".to_string(), "ops".to_string()]
            ));
            assert!(!principals_match_option(&list, &["dev".to_string()]));
            assert!(!principals_match_option(&list, &[]));
            assert!(!principals_match_option(&[], &["ops".to_string()]));
        }

        #[test]
        fn authorized_keys_principals_option_parsed_from_file() {
            let dir = tempdir_for_test("ak-principals");
            let path = dir.join("authorized_keys");
            std::fs::write(
                &path,
                format!(
                    "cert-authority,principals=\"deploy,ops-*\" {USERKEY_LINE}\n\
                     cert-authority {USERKEY_LINE}\n\
                     cert-authority,principals=\"\" {USERKEY_LINE}\n\
                     {USERKEY_LINE}\n"
                ),
            )
            .expect("write");
            let set =
                load_authorized_keys_and_cas(path.to_str().unwrap(), false, None).expect("load");
            assert_eq!(set.blobs, vec![unhex(USERKEY_BLOB_HEX)]);
            assert_eq!(set.cas.len(), 3);
            assert_eq!(
                set.cas[0].1.as_deref(),
                Some(&["deploy".to_string(), "ops-*".to_string()][..])
            );
            assert_eq!(set.cas[1].1, None);
            // `principals=""` restricts to nothing rather than widening.
            assert_eq!(set.cas[2].1.as_deref(), Some(&[][..]));
            let _ = std::fs::remove_dir_all(&dir);
        }

        // ---- S1: per-user AuthorizedKeysFile -------------------------------

        fn tempdir_for_test(tag: &str) -> std::path::PathBuf {
            use std::sync::atomic::{AtomicU64, Ordering};
            static SEQ: AtomicU64 = AtomicU64::new(0);
            let dir = std::env::temp_dir().join(format!(
                "puressh-sshd-{tag}-{}-{}",
                std::process::id(),
                SEQ.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir_all(&dir).expect("mkdir");
            dir
        }

        #[test]
        fn authorized_keys_file_expands_u_token_per_user() {
            let info = lookup_user_for_test();
            let dir = tempdir_for_test("akf");
            // Only the real test user's file carries the key; another user's
            // file (same template) does not exist.
            std::fs::write(dir.join(format!("{}.keys", info.name)), USERKEY_LINE).expect("write");
            let template = format!("{}/%u.keys", dir.display());

            let mut a = auth_with(&["*"], &[], &[], &[], Default::default());
            a.authorized_keys = None; // force the lazy per-user load
            a.authorized_keys_files = vec![template];
            a.strict_modes = false;
            let set = a.resolved_authorized_keys(&info.name).clone();
            assert_eq!(set.blobs, vec![unhex(USERKEY_BLOB_HEX)]);

            // The key authorizes that user…
            let decision = a.evaluate(AuthAttempt::PublicKey {
                user: info.name.clone(),
                algorithm: "ssh-ed25519".into(),
                public_blob: unhex(USERKEY_BLOB_HEX),
                probe_only: false,
                verified: true,
                cert: None,
            });
            assert!(matches!(decision, AuthDecision::Accept), "{decision:?}");

            // …and nobody else: a different (nonexistent-file) user gets an
            // empty set from the same template.
            let mut b = auth_with(&["*"], &[], &[], &[], Default::default());
            b.authorized_keys = None;
            b.authorized_keys_files = a.authorized_keys_files.clone();
            b.strict_modes = false;
            assert!(b.load_authorized_keys_for("root").blobs.is_empty() || info.name == "root");
            let _ = std::fs::remove_dir_all(&dir);
        }

        #[test]
        fn authorized_keys_file_unknown_user_or_bad_template_is_empty() {
            let mut a = auth_with(&["*"], &[], &[], &[], Default::default());
            a.strict_modes = false;
            a.authorized_keys_files = vec!["/nonexistent/%u".to_string(), "%z".to_string()];
            assert!(
                a.load_authorized_keys_for("\u{0}no-such-user")
                    .blobs
                    .is_empty()
            );
            let info = lookup_user_for_test();
            assert!(a.load_authorized_keys_for(&info.name).blobs.is_empty());
        }

        #[test]
        fn global_authorized_keys_set_is_used_verbatim() {
            let mut a = auth_with(&["*"], &[], &[], &[], Default::default());
            a.authorized_keys = None;
            a.global_authorized_keys = Some(std::sync::Arc::new(AuthorizedKeys {
                blobs: vec![vec![9, 9, 9]],
                cas: Vec::new(),
                ..Default::default()
            }));
            assert_eq!(
                a.resolved_authorized_keys("anyone").blobs,
                vec![vec![9, 9, 9]]
            );
        }

        #[test]
        fn allow_users_default_and_literal_token_rules() {
            assert!(is_literal_user_token("alice"));
            assert!(!is_literal_user_token("dev-*"));
            assert!(!is_literal_user_token("!alice"));
            assert!(!is_literal_user_token("alice@10.*"));
            assert!(!is_literal_user_token(""));
            assert_eq!(
                effective_allow_users(&["a".into()], &["b".into()], Some("me")),
                vec!["a".to_string(), "b".to_string()]
            );
            assert_eq!(
                effective_allow_users(&[], &[], Some("me")),
                vec!["me".to_string()]
            );
            // Nothing configured and no default user ⇒ no AllowUsers
            // restriction (OpenSSH semantics; authentication still decides).
            assert!(effective_allow_users(&[], &[], None).is_empty());
        }

        // ---- S6: Match-block access policy per connection ------------------

        fn conn_policy_for(src: &str) -> std::sync::Arc<ConnPolicy> {
            std::sync::Arc::new(ConnPolicy {
                config: std::sync::Arc::new(
                    puressh::config::SshServerConfig::parse(src).expect("parse config"),
                ),
                cli_allow_users: Vec::new(),
                default_allow_user: Some("me".to_string()),
                cli_permit_root_login: None,
                ca_files: HashMap::new(),
                krls: HashMap::new(),
            })
        }

        #[test]
        fn match_address_deny_users_applies_per_connection() {
            let pol =
                conn_policy_for("AllowUsers alice\nMatch Address 10.0.0.0/8\n  DenyUsers *\n");
            let mut lan =
                auth_with_peer(&["*"], &[], &[], &[], Default::default(), Some("10.1.2.3"));
            lan.policy = Some(pol.clone());
            lan.on_user_resolved("alice", &[]);
            assert!(
                !lan.access_allowed("alice"),
                "DenyUsers inside Match Address must apply"
            );

            let mut wan =
                auth_with_peer(&["*"], &[], &[], &[], Default::default(), Some("192.0.2.1"));
            wan.policy = Some(pol);
            wan.on_user_resolved("alice", &[]);
            assert!(wan.access_allowed("alice"));
            // Global AllowUsers still applies: bob is not listed.
            assert!(!wan.access_allowed("bob"));
        }

        #[test]
        fn match_user_root_login_and_empty_passwords_apply_per_connection() {
            let pol = conn_policy_for(
                "PermitRootLogin yes\nMatch User alice\n  PermitRootLogin no\n  PermitEmptyPasswords yes\n",
            );
            let mut a = auth_with(&["*"], &[], &[], &[], Default::default());
            a.policy = Some(pol.clone());
            a.on_user_resolved("alice", &[]);
            assert_eq!(a.permit_root_login, puressh::config::PermitRootLogin::No);
            assert!(a.permit_empty_passwords);

            let mut b = auth_with(&["*"], &[], &[], &[], Default::default());
            b.policy = Some(pol);
            b.on_user_resolved("bob", &[]);
            assert_eq!(b.permit_root_login, puressh::config::PermitRootLogin::Yes);
            assert!(!b.permit_empty_passwords);
        }

        #[test]
        fn match_group_allow_groups_uses_group_resolver() {
            let pol = conn_policy_for(
                "AllowUsers carol dave\nMatch Group ops\n  AllowGroups ops\n  DenyGroups contractors\n",
            );
            let mut groups = std::collections::HashMap::new();
            groups.insert(
                "carol".to_string(),
                vec!["ops".to_string(), "contractors".to_string()],
            );
            groups.insert("dave".to_string(), vec!["ops".to_string()]);
            let mut carol = auth_with(&["*"], &[], &[], &[], groups.clone());
            carol.policy = Some(pol.clone());
            carol.on_user_resolved("carol", &[]);
            assert!(
                !carol.access_allowed("carol"),
                "DenyGroups from the matched block applies"
            );
            let mut dave = auth_with(&["*"], &[], &[], &[], groups);
            dave.policy = Some(pol);
            dave.on_user_resolved("dave", &[]);
            assert!(dave.access_allowed("dave"));
        }

        #[test]
        fn match_block_file_paths_select_preloaded_sets() {
            let mut pol_inner = ConnPolicy {
                config: std::sync::Arc::new(
                    puressh::config::SshServerConfig::parse(
                        "TrustedUserCAKeys /ca/global\nMatch User alice\n  TrustedUserCAKeys /ca/alice\n  RevokedKeys /krl/alice\n  AuthorizedKeysFile /keys/%u\n  AuthorizedPrincipalsFile /principals/%u\n",
                    )
                    .expect("parse"),
                ),
                cli_allow_users: Vec::new(),
                default_allow_user: Some("me".to_string()),
                cli_permit_root_login: None,
                ca_files: HashMap::new(),
                krls: HashMap::new(),
            };
            pol_inner.ca_files.insert(
                "/ca/global".into(),
                std::sync::Arc::new(vec![b"g".to_vec()]),
            );
            pol_inner
                .ca_files
                .insert("/ca/alice".into(), std::sync::Arc::new(vec![b"a".to_vec()]));
            let krl = puressh::krl::Krl::parse(&unhex(KRL_EXPLICIT_HEX)).expect("krl");
            pol_inner
                .krls
                .insert(vec!["/krl/alice".into()], std::sync::Arc::new(krl));
            let pol = std::sync::Arc::new(pol_inner);

            let mut a = auth_with(&["*"], &[], &[], &[], Default::default());
            a.policy = Some(pol.clone());
            a.on_user_resolved("alice", &[]);
            assert_eq!(a.trusted_user_ca_blobs, vec![b"a".to_vec()]);
            assert!(a.revoked_keys.is_some());
            assert_eq!(a.authorized_keys_files, vec!["/keys/%u".to_string()]);
            assert_eq!(
                a.authorized_principals_file.as_deref(),
                Some("/principals/%u")
            );
            assert!(!a.policy_broken);

            let mut b = auth_with(&["*"], &[], &[], &[], Default::default());
            b.policy = Some(pol);
            b.on_user_resolved("bob", &[]);
            assert_eq!(b.trusted_user_ca_blobs, vec![b"g".to_vec()]);
            assert!(b.revoked_keys.is_none());
            assert_eq!(b.authorized_keys_files, default_authorized_keys_files());
        }

        #[test]
        fn match_block_naming_unloaded_file_fails_closed() {
            let pol = conn_policy_for("Match User alice\n  RevokedKeys /krl/missing\n");
            let mut a = auth_with(&["*"], &[], &[], &[], Default::default());
            a.authorized_keys = Some(AuthorizedKeys {
                blobs: vec![unhex(USERKEY_BLOB_HEX)],
                cas: Vec::new(),
                ..Default::default()
            });
            a.policy = Some(pol);
            a.on_user_resolved("alice", &[]);
            assert!(a.policy_broken);
            let decision = a.evaluate(AuthAttempt::PublicKey {
                user: "alice".into(),
                algorithm: "ssh-ed25519".into(),
                public_blob: unhex(USERKEY_BLOB_HEX),
                probe_only: false,
                verified: true,
                cert: None,
            });
            assert!(matches!(decision, AuthDecision::Reject));
        }

        // ---- S3/S4: parent-side child accounting ---------------------------

        #[test]
        fn child_table_caps_count_unauthenticated_and_per_ip_for_lifetime() {
            let ip4: IpAddr = "10.0.0.1".parse().unwrap();
            let peer_a: std::net::SocketAddr = "10.0.0.1:1000".parse().unwrap();
            let peer_b: std::net::SocketAddr = "10.0.0.2:1000".parse().unwrap();
            let mut t = ChildTable::default();
            t.insert(Pid::from_raw(100_001), ip4, None);
            t.insert(Pid::from_raw(100_002), ip4, None);
            assert_eq!(t.len(), 2);
            assert_eq!(t.unauthenticated(), 2);
            assert_eq!(t.count_from_ip(ip4), 2);
            // MaxStartups over unauthenticated children.
            assert_eq!(t.admit(&peer_b, 2, None, 0), Err("max-startups"));
            assert_eq!(t.admit(&peer_b, 3, None, 0), Ok(()));
            // Per-source cap over live children from that IP.
            assert_eq!(t.admit(&peer_a, 0, None, 2), Err("per-source-max"));
            assert_eq!(t.admit(&peer_b, 0, None, 2), Ok(()));
            // An authenticated child leaves the MaxStartups count but keeps
            // its per-IP slot for life.
            t.children
                .get_mut(&Pid::from_raw(100_001))
                .unwrap()
                .authenticated = true;
            assert_eq!(t.unauthenticated(), 1);
            assert_eq!(t.admit(&peer_b, 2, None, 0), Ok(()));
            assert_eq!(t.admit(&peer_a, 0, None, 2), Err("per-source-max"));
            // Caps of 0 are unlimited.
            assert_eq!(t.admit(&peer_a, 0, None, 0), Ok(()));
            // MaxStartups start:rate:full: 1 unauthenticated child, start 1 at
            // rate 100 ⇒ always dropped; start 2 ⇒ never.
            assert!(t.admit(&peer_b, 10, Some((1, 100)), 0).is_err());
            assert_eq!(t.admit(&peer_b, 10, Some((2, 100)), 0), Ok(()));
            assert_eq!(t.admit(&peer_b, 10, Some((1, 0)), 0), Ok(()));
        }

        #[test]
        fn child_table_auth_pipe_and_reap_with_real_child() {
            // Fork a real child that reports auth success through the pipe
            // exactly as the session-open hook does, then exits. The parent
            // must see it move to "authenticated" and then be reaped (per-IP
            // slot released).
            let ip: IpAddr = "192.0.2.7".parse().unwrap();
            let (rx, tx) = pipe_cloexec().expect("pipe");
            AUTH_NOTIFY_FD.store(tx.as_raw_fd(), Ordering::Relaxed);
            // SAFETY: single-threaded test child; it only writes a byte and exits.
            let pid = match unsafe { fork() }.expect("fork") {
                ForkResult::Child => {
                    core::mem::forget(tx);
                    notify_parent_authenticated();
                    unsafe { libc::_exit(0) };
                }
                ForkResult::Parent { child } => child,
            };
            AUTH_NOTIFY_FD.store(-1, Ordering::Relaxed);
            drop(tx);
            let mut t = ChildTable::default();
            t.insert(pid, ip, Some(rx));
            assert_eq!(t.unauthenticated(), 1);
            // Wait for the byte (bounded), then collect it.
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
            while t.unauthenticated() == 1 && std::time::Instant::now() < deadline {
                t.poll_auth();
                std::thread::sleep(std::time::Duration::from_millis(5));
            }
            assert_eq!(t.unauthenticated(), 0, "auth notification not received");
            assert_eq!(t.count_from_ip(ip), 1, "per-IP slot held until reaped");
            // Now reap: the child has exited.
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
            while t.len() == 1 && std::time::Instant::now() < deadline {
                t.reap(false);
                std::thread::sleep(std::time::Duration::from_millis(5));
            }
            assert_eq!(t.len(), 0, "exited child not reaped");
            assert_eq!(t.count_from_ip(ip), 0);
        }

        #[test]
        fn child_table_pipe_closed_without_success_stays_unauthenticated() {
            let ip: IpAddr = "192.0.2.8".parse().unwrap();
            let (rx, tx) = pipe_cloexec().expect("pipe");
            let mut t = ChildTable::default();
            t.insert(Pid::from_raw(100_003), ip, Some(rx));
            // Peer "exits pre-auth": write end closed with no byte.
            drop(tx);
            // Poll until the hang-up is observed rather than once: a sibling
            // test in this binary forks a real child, and `fork` copies every
            // open descriptor — including our `tx` — into it (close-on-exec
            // only applies at `exec`). Until that child exits the pipe still
            // has a writer and `poll` reports nothing, which made this test
            // flake on CI when the two ran concurrently.
            let pid = Pid::from_raw(100_003);
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
            while t.children[&pid].auth_rx.is_some() && std::time::Instant::now() < deadline {
                t.poll_auth();
                std::thread::sleep(std::time::Duration::from_millis(5));
            }
            assert_eq!(t.unauthenticated(), 1);
            assert!(
                t.children[&pid].auth_rx.is_none(),
                "pipe hang-up never observed"
            );
        }

        // ---- Multi-step keyboard-interactive bridge ------------------------
        //
        // These drive the LocalAuthenticator's kbd-interactive state machine
        // through the real `pam_gate::KbdConversation` channel protocol via a
        // scripted *fake* worker (no real PAM module needed). Gated to the
        // Linux+PAM build, where the conversation type and its test helper
        // live.

        #[cfg(all(feature = "pam", target_os = "linux"))]
        #[test]
        fn kbd_interactive_two_prompt_accept() {
            use std::sync::{Arc, Mutex};
            let received = Arc::new(Mutex::new(Vec::new()));
            let script = vec![
                (String::new(), "Password: ".to_string(), false),
                ("One-time code".to_string(), "OTP: ".to_string(), false),
            ];
            let conv = pam_gate::KbdConversation::fake_for_test(script, true, received.clone());

            let mut a = auth_with(&["*"], &[], &[], &[], Default::default());
            a.kbd_interactive_enabled = true;
            a.permit_empty_passwords = false;
            let _ = a.check_user_binding("alice");
            a.kbd_conv = Some(conv);
            a.pending_first_prompt = true;

            // First pump: PAM asked the password prompt.
            match a.kbd_pump("alice") {
                AuthDecision::InteractiveRequest { prompts, .. } => {
                    assert_eq!(prompts, vec![("Password: ".to_string(), false)]);
                }
                other => panic!("expected first prompt, got {other:?}"),
            }
            // Answer it → second prompt (OTP), with instruction text attached.
            match a.evaluate_interactive("alice", vec!["hunter2".to_string()]) {
                AuthDecision::InteractiveRequest {
                    prompts,
                    instruction,
                    ..
                } => {
                    assert_eq!(prompts, vec![("OTP: ".to_string(), false)]);
                    assert_eq!(instruction, "One-time code");
                }
                other => panic!("expected second prompt, got {other:?}"),
            }
            // Answer the OTP → PAM Done(true) → Accept (single-factor: no
            // chains; alice is allowed by "*", non-root).
            assert!(matches!(
                a.evaluate_interactive("alice", vec!["123456".to_string()]),
                AuthDecision::Accept
            ));
            // Both answers were threaded to the worker in order.
            assert_eq!(
                *received.lock().unwrap(),
                vec![b"hunter2".to_vec(), b"123456".to_vec()]
            );
            // Conversation cleared after the terminal verdict.
            assert!(a.kbd_conv.is_none());
        }

        #[cfg(all(feature = "pam", target_os = "linux"))]
        #[test]
        fn kbd_interactive_pam_reject() {
            use std::sync::{Arc, Mutex};
            let received = Arc::new(Mutex::new(Vec::new()));
            let script = vec![(String::new(), "Password: ".to_string(), false)];
            let conv = pam_gate::KbdConversation::fake_for_test(script, false, received);

            let mut a = auth_with(&["*"], &[], &[], &[], Default::default());
            a.kbd_interactive_enabled = true;
            let _ = a.check_user_binding("alice");
            a.kbd_conv = Some(conv);
            a.pending_first_prompt = true;

            assert!(matches!(
                a.kbd_pump("alice"),
                AuthDecision::InteractiveRequest { .. }
            ));
            // Wrong answer → PAM Done(false) → Reject.
            assert!(matches!(
                a.evaluate_interactive("alice", vec!["wrong".to_string()]),
                AuthDecision::Reject
            ));
            assert!(a.kbd_conv.is_none());
        }

        #[cfg(all(feature = "pam", target_os = "linux"))]
        #[test]
        fn kbd_interactive_empty_password_refused() {
            use std::sync::{Arc, Mutex};
            let received = Arc::new(Mutex::new(Vec::new()));
            let script = vec![(String::new(), "Password: ".to_string(), false)];
            // Verdict would be accept, but the empty-password policy must short-
            // circuit BEFORE the worker ever sees the answer.
            let conv = pam_gate::KbdConversation::fake_for_test(script, true, received.clone());

            let mut a = auth_with(&["*"], &[], &[], &[], Default::default());
            a.kbd_interactive_enabled = true;
            a.permit_empty_passwords = false;
            let _ = a.check_user_binding("alice");
            a.kbd_conv = Some(conv);
            a.pending_first_prompt = true;

            assert!(matches!(
                a.kbd_pump("alice"),
                AuthDecision::InteractiveRequest { .. }
            ));
            // Empty first answer ⇒ refused without consulting the worker.
            assert!(matches!(
                a.evaluate_interactive("alice", vec![String::new()]),
                AuthDecision::Reject
            ));
            assert!(received.lock().unwrap().is_empty());
            assert!(a.kbd_conv.is_none());
        }

        #[cfg(all(feature = "pam", target_os = "linux"))]
        #[test]
        fn kbd_interactive_username_change_rejected() {
            use std::sync::{Arc, Mutex};
            let received = Arc::new(Mutex::new(Vec::new()));
            let script = vec![(String::new(), "Password: ".to_string(), false)];
            let conv = pam_gate::KbdConversation::fake_for_test(script, true, received);

            let mut a = auth_with(&["*"], &[], &[], &[], Default::default());
            a.kbd_interactive_enabled = true;
            let _ = a.check_user_binding("alice");
            a.kbd_conv = Some(conv);
            a.pending_first_prompt = true;
            assert!(matches!(
                a.kbd_pump("alice"),
                AuthDecision::InteractiveRequest { .. }
            ));
            // A response that claims a different user mid-conversation ⇒ reject.
            assert!(matches!(
                a.evaluate_interactive("mallory", vec!["x".to_string()]),
                AuthDecision::Reject
            ));
        }

        #[test]
        fn krl_absent_allows_authorized_plain_key() {
            // Sanity: the same authorized key WITHOUT a KRL is accepted, so the
            // rejection above is attributable to revocation, not the harness.
            let blob = unhex(USERKEY_BLOB_HEX);
            let mut a = auth_with(&["*"], &[], &[], &[], Default::default());
            a.authorized_keys = Some(AuthorizedKeys {
                blobs: vec![blob.clone()],
                cas: Vec::new(),
                ..Default::default()
            });
            let decision = a.evaluate(AuthAttempt::PublicKey {
                user: "alice".into(),
                algorithm: "ssh-ed25519".into(),
                public_blob: blob,
                probe_only: false,
                verified: true,
                cert: None,
            });
            assert!(matches!(decision, AuthDecision::Accept));
        }
    }
}
