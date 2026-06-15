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
pub enum Persist {
    /// Exit as soon as the foreground session ends.
    No,
    /// Persist indefinitely (until the process exits / `-O exit`).
    Yes,
    /// Linger N seconds after the last client detaches.
    Seconds(u64),
}

/// Inputs to [`run_master`].
pub struct MasterConfig {
    /// Resolved control-socket path (already length-checked).
    pub control_path: PathBuf,
    /// ControlPersist behaviour.
    pub persist: Persist,
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
    let listener = UnixListener::bind(path)
        .map_err(|e| format!("bind control socket {}: {e}", path.display()))?;
    // 0600: only the owner may connect to the multiplexed connection.
    if let Err(e) = fs::set_permissions(path, fs::Permissions::from_mode(0o600)) {
        let _ = fs::remove_file(path);
        return Err(format!("chmod 0600 {}: {e}", path.display()));
    }
    Ok(listener)
}

/// Become the master: bind the socket and serve clients until the
/// ControlPersist policy says to exit. `foreground` runs the master's *own*
/// session (the invoking `ssh`'s command/shell) against `shared`; when it
/// returns, its value is the master process's exit status under
/// `ControlPersist no`. Under `yes`/`Seconds`, the master keeps serving in a
/// detached thread after `foreground` returns and this call still returns the
/// foreground status promptly so the invoking terminal is freed.
///
/// # Daemonization limitation
///
/// `ControlPersist yes`/`<N>` does **not** double-fork into a separate daemon
/// process. The master stays alive inside the *first* `ssh` process, in a
/// detached background thread, after the foreground session returns. The
/// process therefore lingers (without a controlling session) until the persist
/// policy fires. True OpenSSH-style daemonization is a follow-up.
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
            wake_accept(&cfg.control_path);
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

/// Wake a blocked `accept()` by making one throwaway connection to the socket.
fn wake_accept(path: &Path) {
    let _ = UnixStream::connect(path);
}

/// Accept incoming mux clients and spawn a session handler per connection.
fn accept_loop(listener: UnixListener, shared: SharedClient, state: Arc<MasterState>) {
    for conn in listener.incoming() {
        if state.shutdown.load(Ordering::SeqCst) {
            break;
        }
        let stream = match conn {
            Ok(s) => s,
            Err(_) => continue,
        };
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
                    wake_accept(path);
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
    let (want_pty, term, cols, rows, env, command) = match open {
        Frame::OpenSession {
            want_pty,
            term,
            cols,
            rows,
            env,
            command,
        } => (want_pty, term, cols, rows, env, command),
        Frame::ExitRequest => {
            // `ssh -O exit`: ask the whole master to shut down.
            state.shutdown.store(true, Ordering::SeqCst);
            return;
        }
        Frame::AliveCheck => {
            let _ = write_frame(&mut ctrl, &Frame::AliveOk);
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
    let stream_res = if let Some(cmd) = command.as_deref() {
        shared.exec_stream(cmd)
    } else if want_pty {
        shared.shell_stream(&term, cols, rows, 0, 0, Vec::new())
    } else {
        shared.shell_stream_no_pty()
    };
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

    let _ = t_err.join();

    // Forward exit status / signal, then EOF, then close the control socket.
    if let Ok(mut g) = ctrl_write.lock() {
        if let Some(sig) = chan.exit_signal() {
            let _ = write_frame(&mut *g, &Frame::ExitSignal { name: sig });
        }
        let code = chan.exit_status().unwrap_or(0);
        let _ = write_frame(&mut *g, &Frame::ExitStatus { code: code as u32 });
        let _ = write_frame(&mut *g, &Frame::Eof);
        let _ = g.flush();
        let _ = g.shutdown(std::net::Shutdown::Both);
    }
    drop(t_in);
    drop(chan);
}
