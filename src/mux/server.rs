//! Master role: own the SSH connection, bind the control socket, and serve
//! attached mux clients by opening a fresh channel per [`Frame::OpenSession`].
//!
//! The master moves its authenticated [`Client`](crate::client::Client) into a
//! [`SharedClient`](crate::shared::SharedClient) and runs an accept loop. Each
//! incoming Unix connection becomes one session channel; bytes are spliced
//! socket↔channel mirroring the `ssh` binary's interactive threads.
//!
//! ControlPersist lifetime is tracked by a live-client counter plus a flag for
//! whether the master's own foreground session has finished — see
//! [`run_master`] for the exact policy.

use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use crate::shared::{OwnedChannelStream, SharedClient};

use super::client::{ProbeOutcome, probe_master};
use super::codec::{Frame, PROTOCOL_VERSION};
use super::{read_frame, write_frame};

/// ControlPersist policy for a master, matching the parsed config value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Persist {
    /// Exit as soon as the foreground session ends.
    No,
    /// Persist indefinitely (until the process exits / `-O exit`).
    Yes,
    /// Linger N seconds after the last client detaches.
    Seconds(u64),
}

/// Inputs to [`run_master`].
#[non_exhaustive]
pub struct MasterConfig {
    /// Resolved control-socket path (already length-checked).
    pub control_path: PathBuf,
    /// ControlPersist behaviour.
    pub persist: Persist,
    /// Called (after the control socket is unlinked) when an attached client
    /// sends `-O exit`. A master whose foreground never returns on its own
    /// (`ssh -M -N -D …`) uses it to end the process, as OpenSSH's does.
    pub on_exit: Option<Arc<dyn Fn() + Send + Sync>>,
    /// Adds or removes a forward for `ssh -O forward` / `-O cancel`: given
    /// the option letter (`b'L'`, `b'R'`, `b'D'`), the specification and
    /// whether to cancel, the port the server chose (`-R 0:…`, else 0) or
    /// why it failed. Without it those commands are refused.
    pub on_forward: Option<ForwardHook>,
    /// Describes the connection for `ssh -O conninfo`.
    pub on_conninfo: Option<Arc<dyn Fn() -> String + Send + Sync>>,
    /// Decides whether an accepted control-socket connection may be served
    /// (OpenSSH lets in only its own user and root, by peer credentials).
    /// The library cannot read peer credentials itself; without a check,
    /// the owner-only socket is the access control.
    pub peer_check: Option<PeerCheck>,
}

/// See [`MasterConfig::on_forward`].
pub type ForwardHook = Arc<dyn Fn(u8, &str, bool) -> Result<u16, String> + Send + Sync>;

/// See [`MasterConfig::peer_check`].
pub type PeerCheck = Arc<dyn Fn(&UnixStream) -> bool + Send + Sync>;

impl MasterConfig {
    /// Pair a (length-checked) control-socket path with a persist policy.
    pub fn new(control_path: PathBuf, persist: Persist) -> Self {
        Self {
            control_path,
            persist,
            on_exit: None,
            on_forward: None,
            on_conninfo: None,
            peer_check: None,
        }
    }

    /// Serve `ssh -O forward` / `-O cancel` with `f` (see
    /// [`MasterConfig::on_forward`]).
    pub fn with_on_forward(
        mut self,
        f: impl Fn(u8, &str, bool) -> Result<u16, String> + Send + Sync + 'static,
    ) -> Self {
        self.on_forward = Some(Arc::new(f));
        self
    }

    /// Serve `ssh -O conninfo` with `f`.
    pub fn with_on_conninfo(mut self, f: impl Fn() -> String + Send + Sync + 'static) -> Self {
        self.on_conninfo = Some(Arc::new(f));
        self
    }

    /// Run `f` when an `-O exit` request arrives (see [`MasterConfig::on_exit`]).
    pub fn with_on_exit(mut self, f: impl Fn() + Send + Sync + 'static) -> Self {
        self.on_exit = Some(Arc::new(f));
        self
    }

    /// Serve only the control-socket connections `f` accepts (see
    /// [`MasterConfig::peer_check`]).
    pub fn with_peer_check(
        mut self,
        f: impl Fn(&UnixStream) -> bool + Send + Sync + 'static,
    ) -> Self {
        self.peer_check = Some(Arc::new(f));
        self
    }
}

/// Shared liveness state for the accept loop and the reaper.
struct MasterState {
    /// Number of attached clients currently running a session.
    live_clients: AtomicU64,
    /// Set once the master's own foreground session has finished.
    foreground_done: AtomicBool,
    /// Set to request the accept loop + master shut down (socket unlinked).
    shutdown: AtomicBool,
    /// Last time the client count dropped to zero (for the Seconds linger).
    last_idle: Mutex<Option<Instant>>,
    /// The control socket, unlinked before `on_exit` runs.
    control_path: PathBuf,
    /// See [`MasterConfig::on_exit`].
    on_exit: Option<Arc<dyn Fn() + Send + Sync>>,
    /// See [`MasterConfig::on_forward`].
    on_forward: Option<ForwardHook>,
    /// See [`MasterConfig::on_conninfo`].
    on_conninfo: Option<Arc<dyn Fn() -> String + Send + Sync>>,
    /// See [`MasterConfig::peer_check`].
    peer_check: Option<PeerCheck>,
}

/// Bind the control socket at `cfg.control_path`, taking care not to clobber a
/// live master. Returns the bound listener, or an error if a live master is
/// already answering (`ControlMaster yes` must refuse rather than steal it).
fn bind_socket(path: &Path) -> Result<UnixListener, String> {
    match probe_master(path) {
        ProbeOutcome::Live => {
            return Err(format!(
                "ControlPath {} already has a live master; refusing to clobber it",
                path.display()
            ));
        }
        ProbeOutcome::Stale => {
            // A dead socket file is in the way — remove it before binding.
            let _ = fs::remove_file(path);
        }
        ProbeOutcome::Absent => {}
    }
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
        && !parent.exists()
    {
        return Err(format!(
            "ControlPath parent directory {} does not exist",
            parent.display()
        ));
    }
    match bind_private(path) {
        Ok(l) => return Ok(l),
        // The temporary name did not fit in a socket address (a very short
        // ControlPath file name): bind in place below.
        Err(e) if e.kind() == std::io::ErrorKind::InvalidInput => {}
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            return Err(format!(
                "ControlPath {} already has a live master; refusing to clobber it",
                path.display()
            ));
        }
        Err(e) => return Err(format!("bind control socket {}: {e}", path.display())),
    }
    let listener = UnixListener::bind(path)
        .map_err(|e| format!("bind control socket {}: {e}", path.display()))?;
    // 0600: only the owner may connect to the multiplexed connection.
    if let Err(e) = fs::set_permissions(path, fs::Permissions::from_mode(0o600)) {
        let _ = fs::remove_file(path);
        return Err(format!("chmod 0600 {}: {e}", path.display()));
    }
    Ok(listener)
}

/// Bind a listener at `path` that nobody else can reach at any point.
///
/// A plain bind creates the socket `0777 & ~umask` and the chmod after it
/// leaves a window where another user can connect. OpenSSH binds a
/// temporary name under umask 0177 and link(2)s it into place; the library
/// cannot change the umask (`forbid(unsafe_code)`), so it binds inside a
/// fresh 0700 directory next to `path` instead, makes the socket 0600 there
/// and then links it to `path` — which, unlike a rename, fails rather than
/// replace a master that bound `path` in the meantime.
fn bind_private(path: &Path) -> std::io::Result<UnixListener> {
    use std::os::unix::fs::DirBuilderExt;
    let parent = match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    };
    let seed = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.subsec_nanos())
        ^ std::process::id().rotate_left(16);
    let mut dir = None;
    for i in 0..16u32 {
        // Kept short: the socket inside must still fit in `sun_path`.
        let d = parent.join(format!(".m{:06x}", seed.wrapping_add(i) & 0xff_ffff));
        match fs::DirBuilder::new().mode(0o700).create(&d) {
            Ok(()) => {
                dir = Some(d);
                break;
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e),
        }
    }
    let Some(dir) = dir else {
        return Err(std::io::Error::other("no free temporary directory name"));
    };
    let tmp = dir.join("s");
    let res = UnixListener::bind(&tmp).and_then(|l| {
        fs::set_permissions(&tmp, fs::Permissions::from_mode(0o600))?;
        fs::hard_link(&tmp, path)?;
        Ok(l)
    });
    let _ = fs::remove_file(&tmp);
    let _ = fs::remove_dir(&dir);
    res
}

/// Become the master: bind the socket and serve clients until the
/// ControlPersist policy says to exit. `foreground` runs the master's *own*
/// session (the invoking `ssh`'s command/shell) against `shared`; when it
/// returns, its value is the master process's exit status under
/// `ControlPersist no`. Under `yes`/`Seconds`, the master keeps serving in a
/// detached thread after `foreground` returns and this call still returns the
/// foreground status promptly so the invoking terminal is freed.
///
/// This in-process variant is used for `ControlPersist no` (the master is
/// tied to the foreground session's lifetime) and as the implementation the
/// daemonized path delegates to. For `yes`/`<N>` the `ssh` binary forks a
/// daemon that calls [`run_master_daemon`] instead, so the master survives the
/// launching process exiting.
pub fn run_master<F>(cfg: MasterConfig, shared: SharedClient, foreground: F) -> Result<i32, String>
where
    F: FnOnce(&SharedClient) -> i32 + Send + 'static,
{
    let listener = bind_socket(&cfg.control_path)?;

    let state = Arc::new(MasterState {
        live_clients: AtomicU64::new(0),
        foreground_done: AtomicBool::new(false),
        shutdown: AtomicBool::new(false),
        last_idle: Mutex::new(Some(Instant::now())),
        control_path: cfg.control_path.clone(),
        on_exit: cfg.on_exit.clone(),
        on_forward: cfg.on_forward.clone(),
        on_conninfo: cfg.on_conninfo.clone(),
        peer_check: cfg.peer_check.clone(),
    });

    // Accept loop in its own thread so the foreground session can run
    // concurrently on the same SharedClient.
    let accept_shared = shared.clone();
    let accept_state = state.clone();
    let accept = thread::spawn(move || {
        accept_loop(listener, accept_shared, accept_state);
    });

    // Reaper: enforces the persist policy and flips `shutdown` when due.
    let reaper_state = state.clone();
    let persist = cfg.persist;
    let reaper_path = cfg.control_path.clone();
    let reaper = thread::spawn(move || {
        reaper_loop(persist, reaper_state, &reaper_path);
    });

    // Run the foreground session.
    let status = foreground(&shared);
    state.foreground_done.store(true, Ordering::SeqCst);

    match cfg.persist {
        Persist::No => {
            // Tear down immediately: stop accepting, unlink, join.
            state.shutdown.store(true, Ordering::SeqCst);
            let _ = fs::remove_file(&cfg.control_path);
            let _ = accept.join();
            let _ = reaper.join();
            Ok(status)
        }
        Persist::Yes | Persist::Seconds(_) => {
            // Persist: keep the master alive in the background threads. The
            // reaper owns teardown (Seconds linger / never for Yes). We detach
            // both threads so this call returns and frees the terminal.
            //
            // NOTE: this keeps the master inside *this* process rather than
            // daemonizing — documented limitation above.
            drop(accept);
            drop(reaper);
            Ok(status)
        }
    }
}

/// Run a *daemonized* master: bind the control socket and serve attached mux
/// clients, blocking the calling thread until the ControlPersist policy (or an
/// `ssh -O exit`) tears the master down.
///
/// Unlike [`run_master`], there is **no** foreground session here — the
/// launching process's own session runs separately as an ordinary mux client
/// over the control socket. This is the entry point the `ssh` binary's
/// `fork()`+`setsid()` daemon child calls so the master survives the launcher
/// exiting (`ControlPersist yes`/`<N>`).
///
/// `foreground_done` is treated as already-true (the master never had a local
/// foreground), so the `Seconds(n)` linger timer keys purely off attached
/// clients: the master lingers `n` seconds after the last client detaches,
/// then unlinks the socket and returns. `Yes` blocks until `-O exit`.
pub fn run_master_daemon(cfg: MasterConfig, shared: SharedClient) -> Result<(), String> {
    let listener = bind_socket(&cfg.control_path)?;

    let state = Arc::new(MasterState {
        live_clients: AtomicU64::new(0),
        // No local foreground session: mark it done so the Seconds linger
        // begins counting from the first idle moment rather than waiting for a
        // foreground that never runs.
        foreground_done: AtomicBool::new(true),
        shutdown: AtomicBool::new(false),
        last_idle: Mutex::new(Some(Instant::now())),
        control_path: cfg.control_path.clone(),
        on_exit: cfg.on_exit.clone(),
        on_forward: cfg.on_forward.clone(),
        on_conninfo: cfg.on_conninfo.clone(),
        peer_check: cfg.peer_check.clone(),
    });

    let accept_shared = shared.clone();
    let accept_state = state.clone();
    let accept = thread::spawn(move || {
        accept_loop(listener, accept_shared, accept_state);
    });

    let reaper_state = state.clone();
    let persist = cfg.persist;
    let reaper_path = cfg.control_path.clone();
    let reaper = thread::spawn(move || {
        reaper_loop(persist, reaper_state, &reaper_path);
    });

    // Keep the connection read even while no client runs a session: the
    // server's channel opens (`-R`, `-A`, `-X`) and keepalives arrive at any
    // time. Its end (the server went away) ends the master too.
    let pump_shared = shared.clone();
    let pump_state = state.clone();
    let pump = thread::spawn(move || {
        let _ = pump_shared.pump_while(|| !pump_state.shutdown.load(Ordering::SeqCst));
        pump_state.shutdown.store(true, Ordering::SeqCst);
    });

    // Block here until something flips `shutdown` — the reaper (Seconds linger),
    // an `-O exit` handler, or the connection ending. Then make sure the
    // socket is gone and join.
    while !state.shutdown.load(Ordering::SeqCst) {
        thread::sleep(Duration::from_millis(100));
    }
    let _ = fs::remove_file(&cfg.control_path);
    let _ = accept.join();
    let _ = reaper.join();
    let _ = pump.join();
    Ok(())
}

/// How often the accept loop looks at the shutdown flag between clients.
const ACCEPT_POLL: Duration = Duration::from_millis(50);

/// Accept incoming mux clients and spawn a session handler per connection,
/// until `shutdown`. The listener is polled rather than blocked on, so
/// shutdown never depends on reaching it through its path (which may be
/// gone: `-O exit` callers and tmp cleaners remove it).
fn accept_loop(listener: UnixListener, shared: SharedClient, state: Arc<MasterState>) {
    if listener.set_nonblocking(true).is_err() {
        return;
    }
    while !state.shutdown.load(Ordering::SeqCst) {
        let stream = match listener.accept() {
            Ok((s, _)) => s,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(ACCEPT_POLL);
                continue;
            }
            Err(_) => {
                thread::sleep(ACCEPT_POLL);
                continue;
            }
        };
        // macOS hands accepted sockets the listener's O_NONBLOCK.
        if stream.set_nonblocking(false).is_err() {
            continue;
        }
        if let Some(check) = &state.peer_check
            && !check(&stream)
        {
            continue;
        }
        let s = shared.clone();
        let st = state.clone();
        thread::spawn(move || {
            handle_client(stream, s, st);
        });
    }
}

/// Reaper: poll the live-client count and enforce ControlPersist.
fn reaper_loop(persist: Persist, state: Arc<MasterState>, path: &Path) {
    loop {
        if state.shutdown.load(Ordering::SeqCst) {
            // Shutdown may have been flipped externally — by `run_master`'s
            // Persist::No teardown, by `run_master_daemon`'s main loop, or by
            // an `-O exit` (`Frame::ExitRequest`) handler. Make the socket
            // teardown idempotent so an ExitRequest under in-process
            // Persist::Yes still unlinks it.
            let _ = fs::remove_file(path);
            return;
        }
        thread::sleep(Duration::from_millis(200));

        let live = state.live_clients.load(Ordering::SeqCst);
        let fg_done = state.foreground_done.load(Ordering::SeqCst);

        match persist {
            Persist::Yes => {
                // Never self-terminate; only an explicit shutdown ends us.
            }
            Persist::No => {
                // Handled by run_master's foreground path; nothing to do here.
            }
            Persist::Seconds(n) => {
                if !fg_done {
                    continue;
                }
                if live > 0 {
                    *state.last_idle.lock().unwrap() = None;
                    continue;
                }
                // Idle with foreground done: start / check the linger timer.
                let mut idle = state.last_idle.lock().unwrap();
                let since = idle.get_or_insert_with(Instant::now);
                if since.elapsed() >= Duration::from_secs(n) {
                    drop(idle);
                    state.shutdown.store(true, Ordering::SeqCst);
                    let _ = fs::remove_file(path);
                    return;
                }
            }
        }
    }
}

/// Serve one attached client: HELLO handshake, OPEN_SESSION, then splice.
fn handle_client(stream: UnixStream, shared: SharedClient, state: Arc<MasterState>) {
    let mut ctrl = stream;

    // HELLO exchange.
    match read_frame(&mut ctrl) {
        Ok(Some(Frame::Hello { version })) if version == PROTOCOL_VERSION => {}
        _ => return, // bad/absent HELLO (or a bare probe that already closed)
    }
    if write_frame(
        &mut ctrl,
        &Frame::Hello {
            version: PROTOCOL_VERSION,
        },
    )
    .is_err()
    {
        return;
    }

    // The next frame decides what this connection is. A probe sends HELLO and
    // disconnects; a real client follows with OPEN_SESSION (or a control op).
    let open = match read_frame(&mut ctrl) {
        Ok(Some(f)) => f,
        _ => return,
    };
    let (want_pty, term, cols, rows, env, command, subsystem) = match open {
        Frame::OpenSession {
            want_pty,
            term,
            cols,
            rows,
            env,
            command,
            subsystem,
        } => (want_pty, term, cols, rows, env, command, subsystem),
        Frame::ExitRequest => {
            // `ssh -O exit`: ask the whole master to shut down.
            state.shutdown.store(true, Ordering::SeqCst);
            if let Some(f) = &state.on_exit {
                let _ = fs::remove_file(&state.control_path);
                f();
            }
            return;
        }
        Frame::AliveCheck => {
            let _ = write_frame(&mut ctrl, &Frame::AliveOk);
            return;
        }
        Frame::Forward { kind, spec, cancel } => {
            let reply = match &state.on_forward {
                // No new forwards over a host key that did not match
                // known_hosts (cancelling an existing one is fine).
                Some(_) if !cancel && shared.host_key_mismatched() => Frame::OpenFail {
                    reason: crate::client::HOST_KEY_MISMATCH_DISABLED.into(),
                },
                Some(f) => match f(kind, &spec, cancel) {
                    Ok(port) => Frame::ForwardOk { port: port as u32 },
                    Err(reason) => Frame::OpenFail { reason },
                },
                None => Frame::OpenFail {
                    reason: "forwarding requests are not supported by this master".into(),
                },
            };
            let _ = write_frame(&mut ctrl, &reply);
            return;
        }
        Frame::ConnInfo => {
            let text = state.on_conninfo.as_ref().map_or_else(String::new, |f| f());
            let _ = write_frame(&mut ctrl, &Frame::ConnInfoReply { text });
            return;
        }
        Frame::OpenDirectTcpip {
            dest_host,
            dest_port,
            orig_host,
            orig_port,
        } => {
            handle_direct_tcpip(
                ctrl, shared, state, &dest_host, dest_port, &orig_host, orig_port,
            );
            return;
        }
        _ => return,
    };

    // Apply any env the client forwarded before opening the channel. This sets
    // the SharedClient's shared session-env list, which the channel open then
    // consumes. Concurrent OPEN_SESSIONs with *different* env could race on
    // this list; phase-1 mux env-forwarding is best-effort per connection.
    if !env.is_empty() {
        shared.with_session_env(env);
    }

    // Open the channel on the shared connection.
    // A command or subsystem keeps its pty when one was asked for (`ssh -t
    // host top`), as a shell does.
    let what = match command.as_deref() {
        Some(name) if subsystem => crate::shared::SessionRequest::Subsystem(name),
        Some(cmd) => crate::shared::SessionRequest::Exec(cmd),
        None => crate::shared::SessionRequest::Shell,
    };
    let pty = want_pty.then(|| crate::shared::PtyRequest::new(term.as_str(), cols, rows));
    let stream_res = shared.session_stream(what, pty);
    let chan = match stream_res {
        Ok(c) => c,
        Err(e) => {
            let _ = write_frame(
                &mut ctrl,
                &Frame::StderrData(format!("mux: open session failed: {e}\n").into_bytes()),
            );
            let _ = write_frame(&mut ctrl, &Frame::ExitStatus { code: 255 });
            return;
        }
    };

    // Count this as a live client for the duration of the splice.
    state.live_clients.fetch_add(1, Ordering::SeqCst);
    *state.last_idle.lock().unwrap() = None;
    splice(ctrl, chan, &shared);
    state.live_clients.fetch_sub(1, Ordering::SeqCst);
    if state.live_clients.load(Ordering::SeqCst) == 0 {
        *state.last_idle.lock().unwrap() = Some(Instant::now());
    }
}

/// Serve an `OpenDirectTcpip` request: dial `dest_host:dest_port` *through the
/// server* over the master's SSH connection, reply OK/FAIL, then splice the
/// resulting channel against the control socket exactly like a session (the
/// mux client pumps the local TCP socket's bytes as `StdinData` and writes
/// `StdoutData` back to it).
#[allow(clippy::too_many_arguments)]
fn handle_direct_tcpip(
    mut ctrl: UnixStream,
    shared: SharedClient,
    state: Arc<MasterState>,
    dest_host: &str,
    dest_port: u32,
    orig_host: &str,
    orig_port: u32,
) {
    // Ports arrive as `u32` over the mux control protocol but SSH (and the
    // `as u16` cast below) only carries 16-bit port numbers. Reject anything
    // out of range explicitly: a silent `as u16` truncation would dial an
    // unintended port (e.g. 65558 → 22) instead of failing.
    if dest_port > 0xFFFF || orig_port > 0xFFFF {
        let _ = write_frame(
            &mut ctrl,
            &Frame::OpenFail {
                reason: format!(
                    "direct-tcpip {dest_host}:{dest_port}: invalid port (out of range)"
                ),
            },
        );
        return;
    }
    let chan =
        match shared.open_direct_tcpip(dest_host, dest_port as u16, orig_host, orig_port as u16) {
            Ok(c) => c,
            Err(e) => {
                let _ = write_frame(
                    &mut ctrl,
                    &Frame::OpenFail {
                        reason: format!("direct-tcpip {dest_host}:{dest_port}: {e}"),
                    },
                );
                return;
            }
        };
    if write_frame(&mut ctrl, &Frame::OpenOk).is_err() {
        return;
    }

    // Count this as a live client for the duration of the splice so the
    // ControlPersist reaper keeps the master alive while a forward is active.
    state.live_clients.fetch_add(1, Ordering::SeqCst);
    *state.last_idle.lock().unwrap() = None;
    splice(ctrl, chan, &shared);
    state.live_clients.fetch_sub(1, Ordering::SeqCst);
    if state.live_clients.load(Ordering::SeqCst) == 0 {
        *state.last_idle.lock().unwrap() = Some(Instant::now());
    }
}

/// Splice a mux control socket against a session channel:
///   socket STDIN_DATA → channel write; channel stdout → socket STDOUT_DATA;
///   channel stderr → socket STDERR_DATA; channel exit → socket EXIT_STATUS.
fn splice(ctrl: UnixStream, chan: OwnedChannelStream, shared: &SharedClient) {
    let channel_id = chan.channel_id();
    // Keep the pump from parking forever in a quiescent read so the writer
    // (control→channel) thread can squeeze in (mirrors the interactive path).
    let _ = shared.set_read_timeout(Some(Duration::from_millis(50)));

    let ctrl_read = match ctrl.try_clone() {
        Ok(c) => c,
        Err(_) => return,
    };
    let ctrl_write = Arc::new(Mutex::new(ctrl));

    // control STDIN_DATA → channel data; control EOF → channel EOF.
    let in_shared = shared.clone();
    let mut ctrl_in = ctrl_read;
    let t_in = thread::spawn(move || {
        loop {
            match read_frame(&mut ctrl_in) {
                Ok(Some(Frame::StdinData(d))) => {
                    let mut off = 0;
                    while off < d.len() {
                        match in_shared.channel_send_data(channel_id, &d[off..]) {
                            Ok(0) | Err(_) => return,
                            Ok(n) => off += n,
                        }
                    }
                }
                Ok(Some(Frame::Eof)) => {
                    let _ = in_shared.channel_send_eof(channel_id);
                }
                Ok(Some(Frame::WindowChange { cols, rows })) => {
                    let _ = in_shared.send_window_change(channel_id, cols, rows, 0, 0);
                }
                Ok(Some(Frame::ExitRequest)) => return,
                Ok(Some(_)) => { /* ignore */ }
                Ok(None) | Err(_) => return,
            }
        }
    });

    // channel stderr → control STDERR_DATA.
    let err_shared = shared.clone();
    let err_write = ctrl_write.clone();
    let t_err = thread::spawn(move || {
        let mut buf = [0u8; 32 * 1024];
        loop {
            match err_shared.channel_recv_stderr(channel_id, &mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    let mut g = match err_write.lock() {
                        Ok(g) => g,
                        Err(_) => break,
                    };
                    if write_frame(&mut *g, &Frame::StderrData(buf[..n].to_vec())).is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });

    // channel stdout → control STDOUT_DATA (this thread owns the channel).
    let mut chan = chan;
    let mut buf = [0u8; 32 * 1024];
    loop {
        match chan.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                let mut g = match ctrl_write.lock() {
                    Ok(g) => g,
                    Err(_) => break,
                };
                if write_frame(&mut *g, &Frame::StdoutData(buf[..n].to_vec())).is_err() {
                    break;
                }
            }
            Err(_) => break,
        }
    }
    // The exit status can come after EOF (OpenSSH's server sends EOF first
    // for a command that printed nothing): wait for it, else a failure
    // would be reported as success.
    let _ = chan.wait_exit_status(None);

    let _ = t_err.join();

    // Forward exit status / signal, then EOF, then close the control socket.
    if let Ok(mut g) = ctrl_write.lock() {
        if let Some(sig) = chan.exit_signal() {
            let _ = write_frame(&mut *g, &Frame::ExitSignal { name: sig });
        }
        // No status (the server closed the channel, a ChannelTimeout say):
        // 255, as OpenSSH's client exits.
        let code = chan.exit_status().unwrap_or(255);
        let _ = write_frame(&mut *g, &Frame::ExitStatus { code: code as u32 });
        let _ = write_frame(&mut *g, &Frame::Eof);
        let _ = g.flush();
        let _ = g.shutdown(std::net::Shutdown::Both);
    }
    drop(t_in);
    drop(chan);
}

#[cfg(test)]
mod bind_tests {
    use super::*;

    #[test]
    fn control_socket_is_bound_owner_only_and_never_clobbered() {
        let dir = PathBuf::from("/tmp").join(format!("p-muxb-{:x}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let sock = dir.join("control-socket");
        let l = bind_private(&sock).unwrap();
        let mode = fs::symlink_metadata(&sock).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
        // The temporary directory is gone; only the socket is left.
        let names: Vec<_> = fs::read_dir(&dir)
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(names, vec![std::ffi::OsString::from("control-socket")]);
        // The listener answers at the final name.
        let _c = UnixStream::connect(&sock).unwrap();
        assert!(l.accept().is_ok());
        // A second master does not replace the first.
        let e = bind_private(&sock).unwrap_err();
        assert_eq!(e.kind(), std::io::ErrorKind::AlreadyExists);
        assert_eq!(fs::read_dir(&dir).unwrap().count(), 1);
        let _ = fs::remove_dir_all(&dir);
    }
}
