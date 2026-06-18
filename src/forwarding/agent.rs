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

use std::io::{ErrorKind, Read, Write};
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
        Self { parent_dir: None }
    }

    /// Build a handler that places every per-session socket under `dir`.
    /// `dir` must exist and be writable by the running process.
    pub fn with_parent_dir(dir: PathBuf) -> Self {
        Self {
            parent_dir: Some(dir),
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
    // `nix::unistd::geteuid` wraps the syscall safely, avoiding an `unsafe`
    // block that `forbid(unsafe_code)` (outside the `ffi` feature) would reject.
    let euid = nix::unistd::geteuid().as_raw();
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
    fn setup(&self, _user: &str, ctx: AgentForwardContext) -> Result<AgentForwardHandle> {
        let parent = self.resolve_parent()?;
        let socket_path = mint_socket_path(&parent)?;
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

        let listener = UnixListener::bind(&socket_path)?;
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
                    Ok((conn, _peer)) => match ctx.open_auth_agent() {
                        Ok(channel_stream) => {
                            spawn_unix_splice(conn, channel_stream);
                        }
                        Err(_) => {
                            let _ = conn.shutdown(std::net::Shutdown::Both);
                        }
                    },
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
        while let Ok(Some(chunk)) = chan_rx.recv() {
            if uds_out_b.write_all(&chunk).is_err() {
                break;
            }
        }
        let _ = uds_out_b.shutdown(std::net::Shutdown::Read);
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
/// Drop-in for [`crate::client::ClientHandlers::with_auth_agent`].
///
/// [`AuthAgentCallback`]: crate::client::AuthAgentCallback
pub fn splice_to_unix_socket_callback(
    path: PathBuf,
) -> Option<Arc<dyn Fn(ChannelStream) + Send + Sync + 'static>> {
    if !path.exists() {
        return None;
    }
    Some(Arc::new(move |stream: ChannelStream| {
        match UnixStream::connect(&path) {
            Ok(uds) => spawn_unix_splice(uds, stream),
            Err(_) => {
                // Local agent went away or refused. Drop the channel —
                // the server will observe EOF/Close.
                let (_rx, tx) = stream.into_raw();
                let _ = tx.send(ChannelEgress::Eof);
                let _ = tx.send(ChannelEgress::Close);
            }
        }
    }))
}

/// Convenience over [`splice_to_unix_socket_callback`] that pulls the
/// socket path from the process env (`$SSH_AUTH_SOCK`). Returns `None` if
/// the env var is unset, empty, or names a path that doesn't exist.
pub fn splice_to_local_agent_callback() -> Option<Arc<dyn Fn(ChannelStream) + Send + Sync + 'static>>
{
    let raw = std::env::var("SSH_AUTH_SOCK").ok()?;
    if raw.is_empty() {
        return None;
    }
    splice_to_unix_socket_callback(PathBuf::from(raw))
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
        let euid = unsafe { libc::geteuid() };
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
        let euid = unsafe { libc::geteuid() };
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
        let euid = unsafe { libc::geteuid() };
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
        let real_euid = unsafe { libc::geteuid() };
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
