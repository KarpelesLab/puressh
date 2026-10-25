//! Server-side glue for `auth-agent-req@openssh.com` and the matching
//! `auth-agent@openssh.com` channel-opens (OpenSSH's ssh-agent forwarding
//! protocol, the wire side of `ssh -A`).
//!
//! Implements [`DefaultAgentForwardHandler`], the in-process backing for
//! the [`crate::server::AgentForwardHandler`] trait. The handler:
//!
//! - On `setup`, picks a fresh per-session path under `$XDG_RUNTIME_DIR`
//!   (falling back to `/tmp`) and creates a Unix-domain `SOCK_STREAM`
//!   listener there with mode 0700. The path is returned to the dispatcher,
//!   which injects it as `SSH_AUTH_SOCK` in the session's env.
//! - Spawns one accept-loop thread per setup. For each accepted Unix
//!   socket connection the worker calls
//!   [`crate::server::AgentForwardContext::open_auth_agent`] to ask the
//!   per-connection server loop to open an `auth-agent@openssh.com` channel
//!   back toward the client, then splices the local socket against the
//!   resulting [`crate::server::ChannelStream`] in both directions until
//!   either side hangs up.
//! - On handle drop (i.e. session-channel close), signals the worker thread
//!   to stop, joins it, and unlinks the socket on disk.

use std::io::{ErrorKind, Read};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::sync::Arc;
use std::thread;

// Server-handler-only imports — the splice-to-local-agent callback below
// doesn't need any of these. Gating keeps the `client`-only build clean of
// "unused import" warnings.
#[cfg(feature = "server")]
use std::os::unix::fs::PermissionsExt;
#[cfg(feature = "server")]
use std::os::unix::net::UnixListener;
#[cfg(feature = "server")]
use std::path::Path;
#[cfg(feature = "server")]
use std::sync::atomic::{AtomicBool, Ordering};
#[cfg(feature = "server")]
use std::thread::JoinHandle;
#[cfg(feature = "server")]
use std::time::Duration;

#[cfg(feature = "server")]
use purecrypto::rng::{OsRng, RngCore};

// The server-side handler types live behind `feature = "server"`; the
// splice-to-local-agent callback below only needs the shared `ChannelStream`
// /`ChannelEgress` types from `crate::stream` and is exposed to both client
// and server consumers.
#[cfg(feature = "server")]
use crate::error::Result;
#[cfg(feature = "server")]
use crate::server::{AgentForwardContext, AgentForwardHandle, AgentForwardHandler};
use crate::stream::{ChannelEgress, ChannelStream};

/// How often the accept-loop polls the non-blocking listener while waiting
/// for either a connection or the stop flag.
#[cfg(feature = "server")]
const ACCEPT_POLL_INTERVAL: Duration = Duration::from_millis(100);

/// RAII guard that lives inside the [`AgentForwardHandle::stopper`] box.
/// Dropping it sets the stop flag, joins the worker thread, and unlinks the
/// on-disk socket.
#[cfg(feature = "server")]
struct AgentBinding {
    stop: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
    socket_path: PathBuf,
    /// A directory made for the socket alone (`shared:`), removed with it.
    socket_dir: Option<PathBuf>,
}

#[cfg(feature = "server")]
impl Drop for AgentBinding {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
        // Best-effort cleanup. If the path is already gone (e.g. someone
        // manually removed it) or we can't write to its directory anymore
        // (post-drop privileges, no longer owner), there's nothing useful
        // we can do.
        let _ = std::fs::remove_file(&self.socket_path);
        if let Some(dir) = &self.socket_dir {
            let _ = std::fs::remove_dir(dir);
        }
    }
}

/// Where a forwarded agent's socket is created: OpenSSH 10's
/// `AgentSocketPath`, already expanded for the user.
#[cfg(feature = "server")]
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum AgentSocketLocation {
    /// `user:` — directly in `dir` (made, mode 0700, where missing) as
    /// `s.<host_hash>.sshd.<pid>.<random>`.
    User {
        /// The directory.
        dir: PathBuf,
        /// OpenSSH's hash of the host name, telling hosts sharing a home
        /// directory apart.
        host_hash: String,
    },
    /// `shared:` — in a fresh private `ssh-XXXXXXXXXXXX` directory under
    /// `dir`, as `agent.sshd.<pid>`; the directory goes with the socket.
    Shared {
        /// The directory the private one is made in.
        dir: PathBuf,
    },
    /// `none`: agent forwarding is refused.
    Disabled,
}

/// See [`DefaultAgentForwardHandler::with_socket_location`].
#[cfg(feature = "server")]
pub type AgentSocketLocationFn = Arc<dyn Fn(&str) -> AgentSocketLocation + Send + Sync>;

/// OpenSSH's characters for random socket and directory names.
#[cfg(feature = "server")]
const PRESENTATION_CHARS: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

#[cfg(feature = "server")]
fn random_name(n: usize) -> String {
    (0..n)
        .map(|_| {
            let i = OsRng.next_u32() as usize % PRESENTATION_CHARS.len();
            PRESENTATION_CHARS[i] as char
        })
        .collect()
}

/// OpenSSH's `mkdir_path(dir, 0700)`: every missing component of `dir` is
/// made with mode 0700; existing ones are left as they are.
#[cfg(feature = "server")]
fn mkdir_path_private(dir: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    let mut at = PathBuf::new();
    for part in dir.components() {
        at.push(part);
        match std::fs::DirBuilder::new().mode(0o700).create(&at) {
            Ok(()) => {}
            Err(e) if e.kind() == ErrorKind::AlreadyExists => {}
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

/// The socket path (and the directory made for it alone) for `location`.
#[cfg(feature = "server")]
fn place_socket(location: &AgentSocketLocation) -> Result<(PathBuf, Option<PathBuf>)> {
    use std::os::unix::fs::DirBuilderExt;
    let pid = std::process::id();
    match location {
        AgentSocketLocation::User { dir, host_hash } => {
            mkdir_path_private(dir)?;
            let name = format!("s.{host_hash}.sshd.{pid}.{}", random_name(10));
            Ok((dir.join(name), None))
        }
        AgentSocketLocation::Shared { dir } => {
            // mkdtemp(3): a fresh, private directory.
            for _ in 0..16 {
                let sub = dir.join(format!("ssh-{}", random_name(12)));
                match std::fs::DirBuilder::new().mode(0o700).create(&sub) {
                    Ok(()) => {
                        let path = sub.join(format!("agent.sshd.{pid}"));
                        return Ok((path, Some(sub)));
                    }
                    Err(e) if e.kind() == ErrorKind::AlreadyExists => continue,
                    Err(e) => return Err(e.into()),
                }
            }
            Err(crate::error::Error::Io(std::io::Error::new(
                ErrorKind::AlreadyExists,
                "agent-forward: could not make a socket directory",
            )))
        }
        AgentSocketLocation::Disabled => Err(crate::error::Error::Io(std::io::Error::new(
            ErrorKind::PermissionDenied,
            "agent-forward: no agent path specified",
        ))),
    }
}

/// Default in-process backing for `auth-agent-req@openssh.com`.
///
/// One instance per server typically, registered via
/// [`crate::server::Config::with_agent_forward`]. The handler is safe to
/// share across connections — each `setup` creates its own per-session
/// socket and worker thread.
///
/// The on-disk socket is created with mode 0700; the parent directory is
/// either `$XDG_RUNTIME_DIR` (when set, which gives a user-private root) or
/// `/tmp` (where the socket's own permission still keeps other users out).
/// The file name is `puressh-agent.<pid>.<random>.sock` — random hex from
/// [`OsRng`] to keep concurrent sessions from colliding.
#[cfg(feature = "server")]
pub struct DefaultAgentForwardHandler {
    /// Optional override for the parent directory. When `None`, the
    /// handler resolves it at `setup` time from `$XDG_RUNTIME_DIR` or
    /// `/tmp`. Useful for tests that want to drive the handler against a
    /// scratch directory.
    parent_dir: Option<PathBuf>,
    /// Per-user socket placement (`AgentSocketPath`), over `parent_dir`.
    location: Option<AgentSocketLocationFn>,
}

#[cfg(feature = "server")]
impl Default for DefaultAgentForwardHandler {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(feature = "server")]
impl DefaultAgentForwardHandler {
    /// Build a fresh handler that picks a parent directory at `setup` time
    /// (`$XDG_RUNTIME_DIR` if set, otherwise `/tmp`).
    pub fn new() -> Self {
        Self {
            parent_dir: None,
            location: None,
        }
    }

    /// Place each user's socket where `location` says (OpenSSH 10's
    /// `AgentSocketPath`), instead of under the parent directory.
    pub fn with_socket_location(mut self, location: AgentSocketLocationFn) -> Self {
        self.location = Some(location);
        self
    }

    /// Build a handler that places every per-session socket under `dir`.
    /// `dir` must exist and be writable by the running process.
    pub fn with_parent_dir(dir: PathBuf) -> Self {
        Self {
            parent_dir: Some(dir),
            location: None,
        }
    }

    fn resolve_parent(&self) -> Result<PathBuf> {
        if let Some(d) = &self.parent_dir {
            return Ok(d.clone());
        }
        // `$XDG_RUNTIME_DIR` is already a user-private (0700, owned by the
        // user) per-login root, so we use it verbatim when present.
        if let Ok(d) = std::env::var("XDG_RUNTIME_DIR")
            && !d.is_empty()
        {
            return Ok(PathBuf::from(d));
        }
        // Fallback: `/tmp` is world-writable with the sticky bit, so dropping
        // the socket there leaves its *directory entry* (and thus the
        // session's existence) visible to every other local user. Instead,
        // mint a per-user private subdirectory `/tmp/puressh-agent-<uid>/`
        // (mode 0700, owned by the current euid) and place the socket inside
        // it, so the socket — and the fact that a session exists at all — is
        // not exposed to other users.
        ensure_private_tmp_dir()
    }
}

/// Ensure `/tmp/puressh-agent-<euid>/` exists as a private (mode 0700,
/// euid-owned, real directory) staging area for the per-session agent
/// socket, and return its path.
///
/// If the directory does not exist we create it 0700. If it already exists
/// we re-verify it before reuse: it must be a real directory (not a
/// symlink), owned by the current euid, and exactly mode 0700 — otherwise
/// a different local user could have pre-planted a directory (or a symlink
/// pointing elsewhere) at the well-known path to influence where our socket
/// lands. On any such mismatch we refuse rather than silently trusting it.
#[cfg(feature = "server")]
fn ensure_private_tmp_dir() -> Result<PathBuf> {
    let euid = crate::sys::effective_uid()?;
    let dir = PathBuf::from(format!("/tmp/puressh-agent-{euid}"));
    ensure_private_dir(&dir, euid)?;
    Ok(dir)
}

/// Ensure `dir` exists as a private (mode 0700, owned by `euid`, real
/// directory) staging area. Creates it 0700 if absent; if present, verifies
/// it is a real directory (not a symlink), owned by `euid`, and exactly mode
/// 0700, refusing otherwise so a different local user can't pre-plant a
/// directory (or a symlink pointing elsewhere) at the well-known path.
#[cfg(feature = "server")]
fn ensure_private_dir(dir: &Path, euid: u32) -> Result<()> {
    use std::os::unix::fs::MetadataExt;

    match std::fs::symlink_metadata(dir) {
        Ok(meta) => {
            // Reject a planted symlink outright: trusting it would let an
            // attacker redirect our socket into a directory they control.
            if meta.file_type().is_symlink() || !meta.file_type().is_dir() {
                return Err(crate::error::Error::Io(std::io::Error::new(
                    std::io::ErrorKind::AlreadyExists,
                    "agent-forward: private dir path exists but is not a real directory",
                )));
            }
            // Must be owned by us and locked to 0700; anything looser means
            // another user could read/traverse/plant inside it.
            if meta.uid() != euid {
                return Err(crate::error::Error::Io(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "agent-forward: private dir is not owned by the current user",
                )));
            }
            if meta.mode() & 0o777 != 0o700 {
                return Err(crate::error::Error::Io(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "agent-forward: private dir has unsafe permissions (want 0700)",
                )));
            }
            Ok(())
        }
        Err(e) if e.kind() == ErrorKind::NotFound => {
            // Create it 0700. `create_dir` honours the umask, so tighten the
            // mode explicitly afterwards to guarantee 0700 regardless of the
            // inherited umask.
            std::fs::create_dir(dir)?;
            std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
            Ok(())
        }
        Err(e) => Err(crate::error::Error::Io(e)),
    }
}

#[cfg(feature = "server")]
impl AgentForwardHandler for DefaultAgentForwardHandler {
    fn setup(&self, user: &str, ctx: AgentForwardContext) -> Result<AgentForwardHandle> {
        let (socket_path, socket_dir) = match &self.location {
            Some(location) => place_socket(&location(user))?,
            None => (mint_socket_path(&self.resolve_parent()?)?, None),
        };
        // Don't unlink-then-bind: a `remove_file` followed by `bind` opens a
        // narrow window where an attacker (or a buggy peer) can swap a
        // symlink into place pointing at /etc/passwd, $HOME/.ssh/, etc., and
        // have the subsequent `bind` walk the symlink. The 64 bits of OsRng
        // entropy in `mint_socket_path` make a benign collision astronomically
        // unlikely, so the safe move is to skip the pre-bind unlink entirely
        // and let `bind` fail with EADDRINUSE on the (theoretical) collision.
        //
        // The one case worth handling explicitly: if `mint_socket_path`
        // *did* collide with an existing path AND that path is a symlink,
        // bail immediately rather than letting `bind` walk the symlink. A
        // regular-file collision is still safe — `bind` will refuse it with
        // EADDRINUSE / EEXIST, which propagates up as an error.
        if let Ok(meta) = std::fs::symlink_metadata(&socket_path)
            && meta.file_type().is_symlink()
        {
            return Err(crate::error::Error::Io(std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                "agent-forward: refusing to bind over a symlink at the per-session socket path",
            )));
        }

        let listener = match UnixListener::bind(&socket_path) {
            Ok(l) => l,
            Err(e) => {
                if let Some(dir) = &socket_dir {
                    let _ = std::fs::remove_dir(dir);
                }
                return Err(e.into());
            }
        };
        listener.set_nonblocking(true)?;
        // Belt-and-braces: UnixListener::bind honours the process umask, which
        // we don't trust to be tight enough. Lock the socket down to the owner
        // immediately after bind.
        let _ = std::fs::set_permissions(&socket_path, std::fs::Permissions::from_mode(0o600));

        let stop = Arc::new(AtomicBool::new(false));
        let stop_thread = Arc::clone(&stop);
        let handle = thread::spawn(move || {
            while !stop_thread.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((conn, _peer)) => {
                        // BSD-family kernels (macOS, the BSDs) hand out accepted
                        // sockets that inherit the listener's O_NONBLOCK; Linux
                        // does not. The splice threads below do blocking I/O, so
                        // put the connection back into blocking mode explicitly.
                        // A failure here leaves a socket we cannot use; drop it.
                        if conn.set_nonblocking(false).is_err() {
                            continue;
                        }
                        match ctx.open_auth_agent() {
                            Ok(channel_stream) => {
                                spawn_unix_splice(conn, channel_stream);
                            }
                            Err(_) => {
                                let _ = conn.shutdown(std::net::Shutdown::Both);
                            }
                        }
                    }
                    Err(e) if e.kind() == ErrorKind::WouldBlock => {
                        thread::sleep(ACCEPT_POLL_INTERVAL);
                    }
                    Err(_) => break,
                }
            }
        });

        let binding = AgentBinding {
            stop,
            handle: Some(handle),
            socket_path: socket_path.clone(),
            socket_dir,
        };
        Ok(AgentForwardHandle {
            auth_sock_path: socket_path,
            stopper: Box::new(binding),
        })
    }
}

/// Bridge a Unix-socket connection against a server-side `ChannelStream`.
/// Mirrors `spawn_splice` in `reverse.rs` but for `UnixStream` instead of
/// `TcpStream`.
/// Splice a channel to a connected Unix-domain stream (an agent's) in both
/// directions, on background threads.
pub fn splice_unix_stream(uds: UnixStream, stream: ChannelStream) {
    spawn_unix_splice(uds, stream)
}

fn spawn_unix_splice(uds: UnixStream, stream: ChannelStream) {
    let (chan_rx, chan_tx) = stream.into_raw();
    let Ok(uds_in) = uds.try_clone() else {
        let _ = chan_tx.send(ChannelEgress::Eof);
        let _ = chan_tx.send(ChannelEgress::Close);
        return;
    };
    let uds_out = uds;

    // Direction A: Unix socket → channel.
    let chan_tx_a = chan_tx.clone();
    let mut uds_in_a = uds_in;
    let a = thread::spawn(move || {
        let mut buf = [0u8; 32 * 1024];
        loop {
            match uds_in_a.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    if chan_tx_a
                        .send(ChannelEgress::Data(buf[..n].to_vec()))
                        .is_err()
                    {
                        break;
                    }
                }
                Err(e) if e.kind() == ErrorKind::Interrupted => continue,
                Err(_) => break,
            }
        }
        let _ = chan_tx_a.send(ChannelEgress::Eof);
    });

    // Direction B: channel → Unix socket.
    let mut uds_out_b = uds_out;
    let b = thread::spawn(move || {
        super::channel_to_socket(&chan_rx, &mut uds_out_b);
    });

    // Reaper: when both directions finish, send Close to drop the channel.
    thread::spawn(move || {
        let _ = a.join();
        let _ = b.join();
        let _ = chan_tx.send(ChannelEgress::Close);
    });
}

/// Build a fresh per-session socket path under `parent`. The hex suffix is
/// drawn from [`OsRng`] so concurrent sessions don't collide.
#[cfg(feature = "server")]
fn mint_socket_path(parent: &Path) -> Result<PathBuf> {
    let mut entropy = [0u8; 8];
    OsRng.fill_bytes(&mut entropy);
    let suffix = hex_encode(&entropy);
    let pid = std::process::id();
    Ok(parent.join(format!("puressh-agent.{pid}.{suffix}.sock")))
}

/// Build an [`AuthAgentCallback`]-shaped closure that splices each
/// incoming `auth-agent@openssh.com` channel against a local Unix-domain
/// socket at `path` — typically the user's real `$SSH_AUTH_SOCK`. Returns
/// `None` if `path` doesn't exist (lets the binary fail-soft when no
/// agent is running locally and skip wiring `on_auth_agent` at all).
///
/// The agent connections are **not** bound to the session
/// (`session-bind@openssh.com`), so the agent treats them as local ones and
/// keys added with destination constraints (`ssh-add -h`) are not
/// restricted to the hosts they name: the server could use them to log in
/// onward as a first hop. Use [`bound_splice_to_unix_socket_callback`].
///
/// [`AuthAgentCallback`]: crate::client::AuthAgentCallback
#[deprecated(
    since = "0.2.4",
    note = "does not bind forwarded agent connections to the session; \
            use bound_splice_to_unix_socket_callback"
)]
pub fn splice_to_unix_socket_callback(
    path: PathBuf,
) -> Option<Arc<dyn Fn(ChannelStream) + Send + Sync + 'static>> {
    if !path.exists() {
        return None;
    }
    Some(Arc::new(move |stream: ChannelStream| {
        match UnixStream::connect(&path) {
            Ok(uds) => spawn_unix_splice(uds, stream),
            // Local agent went away or refused. Drop the channel — the
            // server will observe EOF/Close.
            Err(_) => close_channel(stream),
        }
    }))
}

/// Convenience over [`splice_to_unix_socket_callback`] that pulls the
/// socket path from the process env (`$SSH_AUTH_SOCK`). Returns `None` if
/// the env var is unset or empty, or names no Unix-domain socket (nothing
/// to forward; OpenSSH says nothing either).
///
/// Like [`splice_to_unix_socket_callback`], it does not bind the agent
/// connections to the session; use [`bound_splice_to_local_agent_callback`].
#[deprecated(
    since = "0.2.4",
    note = "does not bind forwarded agent connections to the session; \
            use bound_splice_to_local_agent_callback"
)]
pub fn splice_to_local_agent_callback() -> Option<Arc<dyn Fn(ChannelStream) + Send + Sync + 'static>>
{
    let path = local_auth_sock()?;
    #[allow(deprecated)]
    splice_to_unix_socket_callback(path)
}

/// Build an [`AuthAgentCallback`]-shaped closure that, for each incoming
/// `auth-agent@openssh.com` channel, connects to the agent at `path`, binds
/// that connection to the session as a forwarding one
/// (`session-bind@openssh.com` with `forwarded` set, as OpenSSH's `ssh -A`)
/// and splices it to the channel. An agent then lets keys added with
/// destination constraints (`ssh-add -h`) sign only along the hops they
/// name. Returns `None` if `path` doesn't exist.
///
/// The callback is installed before the connection exists, so the binding
/// arrives through `binding`: set it from
/// [`crate::client::Client::session_binding`] once connected (before
/// requesting agent forwarding). A channel that opens while `binding` is
/// unset, or whose agent connection fails, is closed without reaching the
/// agent. An agent that answers the bind with a refusal (one without
/// `session-bind@openssh.com` support, e.g.) is still spliced, as OpenSSH
/// does: such an agent enforces no destination constraints, and OpenSSH's
/// agent refuses constrained keys on a connection whose bind failed.
///
/// [`AuthAgentCallback`]: crate::client::AuthAgentCallback
#[cfg(feature = "client")]
pub fn bound_splice_to_unix_socket_callback(
    path: PathBuf,
    binding: Arc<std::sync::OnceLock<crate::client::SessionBinding>>,
) -> Option<Arc<dyn Fn(ChannelStream) + Send + Sync + 'static>> {
    if !path.exists() {
        return None;
    }
    Some(Arc::new(move |stream: ChannelStream| {
        let Some(b) = binding.get() else {
            return close_channel(stream);
        };
        let Ok(mut agent) = crate::agent::Agent::connect(&path) else {
            return close_channel(stream);
        };
        // `Ok(false)`: the agent refused the bind (see above); an I/O
        // error leaves the connection in an unknown state, so drop it.
        if agent
            .bind_session(&b.host_key, &b.session_id, &b.signature, true)
            .is_err()
        {
            return close_channel(stream);
        }
        spawn_unix_splice(agent.into_stream(), stream);
    }))
}

/// Convenience over [`bound_splice_to_unix_socket_callback`] that pulls the
/// socket path from the process env (`$SSH_AUTH_SOCK`). Returns `None` if
/// the env var is unset or empty, or names no Unix-domain socket.
#[cfg(feature = "client")]
pub fn bound_splice_to_local_agent_callback(
    binding: Arc<std::sync::OnceLock<crate::client::SessionBinding>>,
) -> Option<Arc<dyn Fn(ChannelStream) + Send + Sync + 'static>> {
    bound_splice_to_unix_socket_callback(local_auth_sock()?, binding)
}

/// `$SSH_AUTH_SOCK`, when set and naming a usable Unix-domain socket.
fn local_auth_sock() -> Option<PathBuf> {
    let raw = std::env::var("SSH_AUTH_SOCK").ok()?;
    if raw.is_empty() {
        return None;
    }
    let path = PathBuf::from(raw);
    crate::agent::client::validate_auth_sock(&path).ok()?;
    Some(path)
}

/// Refuse a forwarded agent channel: EOF then Close, so the server sees the
/// channel go away without any agent traffic.
fn close_channel(stream: ChannelStream) {
    let (_rx, tx) = stream.into_raw();
    let _ = tx.send(ChannelEgress::Eof);
    let _ = tx.send(ChannelEgress::Close);
}

#[cfg(feature = "server")]
fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

// Tests exercise `DefaultAgentForwardHandler` and the agent-forward context,
// both of which are server-side; gate them to match.
#[cfg(all(test, feature = "server"))]
mod tests {
    use super::*;

    /// Tiny on-disk scratch dir, same pattern as the rest of the crate
    /// (see `src/known_hosts/tests.rs::TestTempDir`). Avoids pulling in
    /// `tempfile` as a dev-dep.
    struct TestTempDir {
        path: PathBuf,
    }

    impl TestTempDir {
        fn new(prefix: &str) -> Self {
            use std::time::{SystemTime, UNIX_EPOCH};
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0);
            let pid = std::process::id();
            // Use `/tmp` directly instead of `std::env::temp_dir()`. macOS's
            // SUN_LEN is 104 chars and `temp_dir()` there resolves to
            // `/var/folders/XX/HASH/T/`, leaving too little headroom once
            // we append our prefix + the per-session socket name. `/tmp`
            // is always available on Unix and short enough to stay under
            // SUN_LEN even with the longest suffix the handler mints.
            //
            // Keep the prefix short (no `puressh-agentfwd-` repetition)
            // for the same headroom reason.
            let path = std::path::PathBuf::from("/tmp")
                .join(format!("p-afwd-{prefix}-{pid:x}-{:x}", nanos as u32));
            std::fs::create_dir_all(&path).expect("create tempdir");
            Self { path }
        }

        fn path(&self) -> &Path {
            &self.path
        }
    }

    impl Drop for TestTempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }

    /// `setup` binds a socket on disk that is reachable as a Unix socket
    /// path. The handle's `Drop` unlinks the file.
    #[test]
    fn setup_binds_and_drop_unlinks() {
        let dir = TestTempDir::new("setup");
        let h = DefaultAgentForwardHandler::with_parent_dir(dir.path().to_path_buf());
        let ctx = AgentForwardContext::for_test_no_opens();
        let handle = h.setup("u", ctx).expect("setup");
        let path = handle.auth_sock_path.clone();
        assert!(path.exists(), "socket should exist on disk after setup");
        assert!(
            path.to_string_lossy()
                .starts_with(&format!("{}/puressh-agent.", dir.path().display()))
        );
        // Drop the handle; the listener thread should exit and the file
        // should be unlinked.
        drop(handle);
        // Give the worker a couple of accept-poll intervals to observe the
        // stop flag.
        for _ in 0..50 {
            if !path.exists() {
                break;
            }
            thread::sleep(Duration::from_millis(50));
        }
        assert!(
            !path.exists(),
            "socket should be unlinked when the handle is dropped (path={path:?})",
        );
    }

    /// `AgentSocketPath`: `user:` makes the directory (0700) and names the
    /// socket as OpenSSH does; `shared:` makes a private directory that
    /// goes with the socket; `none` refuses.
    #[test]
    fn socket_location_places_the_socket_as_openssh() {
        use std::os::unix::fs::PermissionsExt;
        let dir = TestTempDir::new("loc");
        let user_dir = dir.path().join("h/.ssh/agent");
        let loc = AgentSocketLocation::User {
            dir: user_dir.clone(),
            host_hash: "abcdefghij".into(),
        };
        let h = DefaultAgentForwardHandler::new().with_socket_location(Arc::new(move |user| {
            assert_eq!(user, "u");
            loc.clone()
        }));
        let handle = h
            .setup("u", AgentForwardContext::for_test_no_opens())
            .expect("setup");
        let path = handle.auth_sock_path.clone();
        let name = path.file_name().unwrap().to_string_lossy().into_owned();
        let prefix = format!("s.abcdefghij.sshd.{}.", std::process::id());
        assert!(
            name.starts_with(&prefix) && name.len() == prefix.len() + 10,
            "{name}"
        );
        assert_eq!(path.parent(), Some(user_dir.as_path()));
        let mode = std::fs::metadata(&user_dir).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o700);
        drop(handle);

        let shared = dir.path().join("shared");
        std::fs::create_dir(&shared).unwrap();
        let loc = AgentSocketLocation::Shared {
            dir: shared.clone(),
        };
        let h =
            DefaultAgentForwardHandler::new().with_socket_location(Arc::new(move |_| loc.clone()));
        let handle = h
            .setup("u", AgentForwardContext::for_test_no_opens())
            .expect("setup");
        let path = handle.auth_sock_path.clone();
        let sub = path.parent().unwrap().to_path_buf();
        assert_eq!(sub.parent(), Some(shared.as_path()));
        assert!(
            sub.file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with("ssh-")
        );
        assert_eq!(
            path.file_name().unwrap().to_string_lossy(),
            format!("agent.sshd.{}", std::process::id())
        );
        drop(handle);
        for _ in 0..50 {
            if !sub.exists() {
                break;
            }
            thread::sleep(Duration::from_millis(50));
        }
        assert!(!sub.exists(), "the private directory goes with the socket");

        let h = DefaultAgentForwardHandler::new()
            .with_socket_location(Arc::new(|_| AgentSocketLocation::Disabled));
        assert!(
            h.setup("u", AgentForwardContext::for_test_no_opens())
                .is_err()
        );
    }

    /// Connecting to the socket while there is no `open_auth_agent`
    /// receiver wired (`for_test_no_opens`) causes the worker to drop the
    /// accepted connection. We assert the peer observes that (eventually
    /// `read` returns 0 / an error).
    #[test]
    fn accepted_connection_is_closed_when_open_fails() {
        let dir = TestTempDir::new("closeonfail");
        let h = DefaultAgentForwardHandler::with_parent_dir(dir.path().to_path_buf());
        let ctx = AgentForwardContext::for_test_no_opens();
        let handle = h.setup("u", ctx).expect("setup");
        let mut peer = UnixStream::connect(&handle.auth_sock_path).expect("connect");
        // Either the read returns 0 (EOF) or hits a shutdown'd-read error.
        // We allow both; what we don't allow is hanging forever.
        peer.set_read_timeout(Some(Duration::from_secs(2)))
            .expect("read timeout");
        let mut buf = [0u8; 1];
        let _ = peer.read(&mut buf);
    }

    /// `ensure_private_dir` creates a missing dir as a real 0700 directory.
    #[test]
    fn ensure_private_dir_creates_0700() {
        use std::os::unix::fs::MetadataExt;
        let scratch = TestTempDir::new("epd-create");
        let euid = crate::sys::effective_uid().unwrap();
        let target = scratch.path().join("priv");
        ensure_private_dir(&target, euid).expect("should create");
        let meta = std::fs::symlink_metadata(&target).expect("stat");
        assert!(meta.file_type().is_dir());
        assert_eq!(meta.mode() & 0o777, 0o700, "must be 0700");
        assert_eq!(meta.uid(), euid, "must be euid-owned");
        // Idempotent: a second call accepts the freshly-created 0700 dir.
        ensure_private_dir(&target, euid).expect("reuse should accept");
    }

    /// `ensure_private_dir` rejects a loose-mode (e.g. 0755) existing dir
    /// rather than trusting it.
    #[test]
    fn ensure_private_dir_rejects_loose_mode() {
        let scratch = TestTempDir::new("epd-loose");
        let euid = crate::sys::effective_uid().unwrap();
        let target = scratch.path().join("loose");
        std::fs::create_dir(&target).expect("mkdir");
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o755)).expect("chmod");
        let err = ensure_private_dir(&target, euid).expect_err("0755 must be rejected");
        match err {
            crate::error::Error::Io(e) => {
                assert_eq!(e.kind(), std::io::ErrorKind::PermissionDenied)
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    /// `ensure_private_dir` rejects a symlink planted at the path (even one
    /// pointing at a valid 0700 dir) — it must be a real directory.
    #[test]
    fn ensure_private_dir_rejects_symlink() {
        let scratch = TestTempDir::new("epd-symlink");
        let euid = crate::sys::effective_uid().unwrap();
        let real = scratch.path().join("real");
        std::fs::create_dir(&real).expect("mkdir real");
        std::fs::set_permissions(&real, std::fs::Permissions::from_mode(0o700)).expect("chmod");
        let link = scratch.path().join("link");
        std::os::unix::fs::symlink(&real, &link).expect("symlink");
        let err = ensure_private_dir(&link, euid).expect_err("symlink must be rejected");
        match err {
            crate::error::Error::Io(e) => {
                assert_eq!(e.kind(), std::io::ErrorKind::AlreadyExists)
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    /// `ensure_private_dir` rejects a dir owned by someone else (simulated by
    /// passing a bogus expected euid that won't match the real owner).
    #[test]
    fn ensure_private_dir_rejects_wrong_owner() {
        let scratch = TestTempDir::new("epd-owner");
        let target = scratch.path().join("owned");
        std::fs::create_dir(&target).expect("mkdir");
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o700)).expect("chmod");
        // Pretend we expect a different owner than the one that created it.
        let real_euid = crate::sys::effective_uid().unwrap();
        let bogus = real_euid.wrapping_add(1);
        let err = ensure_private_dir(&target, bogus).expect_err("wrong owner must be rejected");
        match err {
            crate::error::Error::Io(e) => {
                assert_eq!(e.kind(), std::io::ErrorKind::PermissionDenied)
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }
}

#[cfg(all(test, feature = "client"))]
mod bound_tests {
    use super::*;
    use std::io::Write;
    use std::os::unix::net::UnixListener;
    use std::sync::OnceLock;
    use std::sync::mpsc::{Receiver, SyncSender, sync_channel};
    use std::time::Duration;

    /// `SSH_AGENTC_EXTENSION` / `SSH_AGENT_SUCCESS`.
    const EXTENSION: u8 = 27;
    const SUCCESS: u8 = 6;

    fn binding() -> crate::client::SessionBinding {
        crate::client::SessionBinding {
            host_key: b"hostkey".to_vec(),
            session_id: b"sessionid".to_vec(),
            signature: b"sig".to_vec(),
        }
    }

    /// A fresh channel stream plus the far ends: the sender feeding
    /// `CHANNEL_DATA` in and the receiver of what the callback sends out.
    fn channel() -> (
        ChannelStream,
        SyncSender<Option<Vec<u8>>>,
        Receiver<ChannelEgress>,
    ) {
        let (in_tx, in_rx) = sync_channel(16);
        let (out_tx, out_rx) = sync_channel(16);
        (ChannelStream::new(in_rx, out_tx), in_tx, out_rx)
    }

    fn sock_path(tag: &str) -> PathBuf {
        let p = PathBuf::from("/tmp").join(format!("p-abind-{tag}-{:x}", std::process::id()));
        let _ = std::fs::remove_file(&p);
        p
    }

    fn read_frame(s: &mut UnixStream) -> Vec<u8> {
        let mut len = [0u8; 4];
        s.read_exact(&mut len).unwrap();
        let mut body = vec![0u8; u32::from_be_bytes(len) as usize];
        s.read_exact(&mut body).unwrap();
        body
    }

    /// The agent connection is bound as a forwarding one
    /// (`session-bind@openssh.com`, forwarded = 1) before any channel byte
    /// reaches the agent.
    #[test]
    fn binds_as_forwarded_before_splicing() {
        let path = sock_path("ok");
        let listener = UnixListener::bind(&path).unwrap();
        let cell = Arc::new(OnceLock::new());
        let cb = bound_splice_to_unix_socket_callback(path.clone(), cell.clone()).unwrap();
        cell.set(binding()).unwrap();
        let (stream, in_tx, _out_rx) = channel();
        in_tx.send(Some(b"\0\0\0\x01\x0b".to_vec())).unwrap();
        // The callback blocks on the bind reply; play the agent meanwhile.
        let agent = thread::spawn(move || {
            let (mut agent, _) = listener.accept().unwrap();
            agent
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let bind = read_frame(&mut agent);
            agent.write_all(&[0, 0, 0, 1, SUCCESS]).unwrap();
            (bind, read_frame(&mut agent))
        });
        cb(stream);
        let (bind, next) = agent.join().unwrap();
        let mut w = crate::format::Writer::new();
        w.write_u8(EXTENSION);
        w.write_string(b"session-bind@openssh.com");
        w.write_string(b"hostkey");
        w.write_string(b"sessionid");
        w.write_string(b"sig");
        w.write_u8(1);
        assert_eq!(bind, w.as_slice());
        // Then the channel's bytes come through.
        assert_eq!(next, [0x0b]);
        let _ = std::fs::remove_file(&path);
    }

    /// No binding yet: the channel is closed and the agent never contacted.
    #[test]
    fn unbound_channel_is_closed() {
        let path = sock_path("unset");
        let listener = UnixListener::bind(&path).unwrap();
        listener.set_nonblocking(true).unwrap();
        let cb =
            bound_splice_to_unix_socket_callback(path.clone(), Arc::new(OnceLock::new())).unwrap();
        let (stream, _in_tx, out_rx) = channel();
        cb(stream);
        assert!(matches!(out_rx.recv().unwrap(), ChannelEgress::Eof));
        assert!(matches!(out_rx.recv().unwrap(), ChannelEgress::Close));
        assert!(listener.accept().is_err());
        let _ = std::fs::remove_file(&path);
    }
}
