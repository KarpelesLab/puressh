//! Server-side glue for `streamlocal-forward@openssh.com` /
//! `cancel-streamlocal-forward@openssh.com` and the matching
//! `forwarded-streamlocal@openssh.com` channel-opens (OpenSSH extension; the
//! Unix-socket analog of [`crate::forwarding::reverse`], the wire side of
//! `ssh -R /path/to/remote.sock:...`).
//!
//! Implements [`DefaultStreamlocalForwardHandler`], the in-process backing
//! for the [`crate::server::StreamlocalForwardHandler`] trait. The handler:
//!
//! - On `bind`, opens a real [`std::os::unix::net::UnixListener`] at the
//!   requested socket path.
//! - Spawns one worker thread per binding. For each accepted Unix-socket
//!   connection the worker calls
//!   [`crate::server::StreamlocalForwardContext::open_forwarded_streamlocal`]
//!   to ask the per-connection server loop to open a
//!   `forwarded-streamlocal@openssh.com` channel back toward the client, then
//!   splices the socket against the resulting [`ChannelStream`] in both
//!   directions until either side hangs up.
//! - On `unbind` (or connection teardown), signals the worker thread to stop,
//!   joins it, and unlinks the socket on disk.
//!
//! The client-side splice helper [`splice_to_unix_socket_callback`] is the
//! counterpart used by `ssh -R`'s client: it dials a local Unix socket for
//! each inbound `forwarded-streamlocal@openssh.com` channel.

use std::io::{ErrorKind, Read};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::sync::Arc;
use std::thread;

#[cfg(feature = "server")]
use std::collections::BTreeMap;
#[cfg(feature = "server")]
use std::os::unix::net::UnixListener;
#[cfg(feature = "server")]
use std::sync::Mutex;
#[cfg(feature = "server")]
use std::sync::atomic::{AtomicBool, Ordering};
#[cfg(feature = "server")]
use std::thread::JoinHandle;
#[cfg(feature = "server")]
use std::time::Duration;

#[cfg(feature = "server")]
use crate::error::{Error, Result};
#[cfg(feature = "server")]
use crate::server::{StreamlocalForwardContext, StreamlocalForwardHandler};
use crate::stream::{ChannelEgress, ChannelStream};

/// How often the accept-loop polls the non-blocking listener while waiting
/// for either a connection or the stop flag: often, so a dropped binding's
/// socket is gone at once (a client reconnecting right away may ask for the
/// same path).
#[cfg(feature = "server")]
const ACCEPT_POLL_INTERVAL: Duration = Duration::from_millis(10);

/// One live `streamlocal-forward` binding. Dropping it signals the worker
/// thread to stop, joins it, and unlinks the on-disk socket.
#[cfg(feature = "server")]
struct Binding {
    /// The authenticated user that created the binding; only they may
    /// cancel it.
    owner: String,
    stop: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
    socket_path: PathBuf,
    /// `(st_dev, st_ino)` of the socket file this binding created, so the
    /// drop only unlinks *our* socket, never one somebody else has since put
    /// at the same path.
    socket_id: (u64, u64),
}

#[cfg(feature = "server")]
impl Drop for Binding {
    fn drop(&mut self) {
        use std::os::unix::fs::MetadataExt;
        self.stop.store(true, Ordering::SeqCst);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
        // Best-effort cleanup of the socket file — only if it is still the
        // very socket we bound.
        if let Ok(meta) = std::fs::symlink_metadata(&self.socket_path)
            && (meta.dev(), meta.ino()) == self.socket_id
        {
            let _ = std::fs::remove_file(&self.socket_path);
        }
    }
}

/// Whether the file at `path` is a stale socket left behind by an earlier
/// listener of ours: a socket, owned by our effective uid, that nobody is
/// listening on any more (connecting is refused). Only such a socket is
/// unlinked to make room for a new binding; a live one, or another user's,
/// is left alone and the bind fails with `EADDRINUSE`.
#[cfg(feature = "server")]
fn is_stale_own_socket(path: &std::path::Path, meta: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::{FileTypeExt, MetadataExt};
    if !meta.file_type().is_socket() {
        return false;
    }
    if crate::sys::effective_uid().ok() != Some(meta.uid()) {
        return false;
    }
    matches!(
        UnixStream::connect(path),
        Err(e) if e.kind() == ErrorKind::ConnectionRefused
    )
}

/// Bind a listening socket at `path`, owner-only (OpenSSH's default
/// `StreamLocalBindMask 0177`), and return it with the `(st_dev, st_ino)` of
/// the socket file.
///
/// The umask is process-wide (and the server is multi-threaded), so the
/// socket is created under it and immediately `chmod`ed to `0600`, before
/// the accept loop starts. Any connection that slipped in during that window
/// is drained from the backlog and dropped unserved.
#[cfg(feature = "server")]
fn bind_owner_only(path: &std::path::Path) -> Result<(UnixListener, (u64, u64))> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let listener = UnixListener::bind(path)?;
    let finish = || -> Result<(u64, u64)> {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
        let meta = std::fs::symlink_metadata(path)?;
        listener.set_nonblocking(true)?;
        while listener.accept().is_ok() {}
        Ok((meta.dev(), meta.ino()))
    };
    match finish() {
        Ok(id) => Ok((listener, id)),
        Err(e) => {
            let _ = std::fs::remove_file(path);
            Err(e)
        }
    }
}

/// Filter callback type for [`DefaultStreamlocalForwardHandler::with_allow_filter`].
#[cfg(feature = "server")]
type AllowFilter = Box<dyn Fn(&str, &str) -> bool + Send + Sync>;

/// Internal policy describing which bind requests the handler will honour.
#[cfg(feature = "server")]
enum Policy {
    /// Refuse every bind. The default constructed by
    /// [`DefaultStreamlocalForwardHandler::new`].
    Deny,
    /// Permit any bind path.
    All,
    /// Defer the decision to a per-request `(user, socket_path)` filter.
    Filter(AllowFilter),
}

/// Default in-process backing for `streamlocal-forward@openssh.com` /
/// `cancel-streamlocal-forward@openssh.com`.
///
/// One instance per server typically, registered via
/// [`crate::server::Config::with_streamlocal_forward`]. The handler is safe
/// to share across connections — each `bind` opens its own listener and
/// tracks it by socket path.
///
/// # Default-deny
///
/// A bare [`DefaultStreamlocalForwardHandler::new`] is **default-deny**:
/// every request is refused at the policy layer (surfaced as
/// `REQUEST_FAILURE`). Binding an attacker-chosen path on a multi-tenant host
/// is a footgun (it can clobber or shadow other sockets), so operators must
/// explicitly opt into a policy:
///
/// - [`Self::permit_all`] — honour any requested path.
/// - [`Self::with_allow_filter`] — a custom per-request decision over
///   `(user, socket_path)`.
#[cfg(feature = "server")]
pub struct DefaultStreamlocalForwardHandler {
    bindings: Mutex<BTreeMap<String, Binding>>,
    policy: Policy,
}

#[cfg(feature = "server")]
impl Default for DefaultStreamlocalForwardHandler {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(feature = "server")]
impl DefaultStreamlocalForwardHandler {
    /// Build a **default-deny** handler with no active bindings.
    pub fn new() -> Self {
        Self {
            bindings: Mutex::new(BTreeMap::new()),
            policy: Policy::Deny,
        }
    }

    /// Permit every bind request, honouring the requested socket path
    /// verbatim. Only safe on single-tenant servers.
    pub fn permit_all() -> Self {
        Self {
            bindings: Mutex::new(BTreeMap::new()),
            policy: Policy::All,
        }
    }

    /// Attach an allow filter. Each `bind` request passes
    /// `(user, socket_path)` through the filter; a `false` return value
    /// surfaces to the peer as a `REQUEST_FAILURE` (no listener is created).
    pub fn with_allow_filter<F>(mut self, filter: F) -> Self
    where
        F: Fn(&str, &str) -> bool + Send + Sync + 'static,
    {
        self.policy = Policy::Filter(Box::new(filter));
        self
    }

    fn allowed(&self, user: &str, socket_path: &str) -> bool {
        match &self.policy {
            Policy::Deny => false,
            Policy::All => true,
            Policy::Filter(f) => f(user, socket_path),
        }
    }

    /// Number of bindings currently held. Useful for tests / monitoring.
    pub fn binding_count(&self) -> usize {
        self.bindings.lock().map(|m| m.len()).unwrap_or(0)
    }
}

#[cfg(feature = "server")]
impl StreamlocalForwardHandler for DefaultStreamlocalForwardHandler {
    fn bind(&self, user: &str, socket_path: &str, ctx: StreamlocalForwardContext) -> Result<()> {
        if !self.allowed(user, socket_path) {
            return Err(Error::Protocol(
                "streamlocal-forward: bind refused by policy",
            ));
        }
        let path = PathBuf::from(socket_path);

        // The map is shared by every connection: a path somebody already
        // forwards is refused, never replaced (replacing would unlink their
        // live socket, and the evicted binding's drop would then delete
        // ours). The lock is held until the new entry is inserted so two
        // concurrent binds of one path cannot both pass this check.
        let mut map = self
            .bindings
            .lock()
            .map_err(|_| Error::Protocol("streamlocal-forward: lock poisoned"))?;
        if map.contains_key(socket_path) {
            return Err(Error::Protocol("streamlocal-forward: path already bound"));
        }

        if let Ok(meta) = std::fs::symlink_metadata(&path) {
            // Refuse to bind over a symlink: following it could plant our
            // socket (and redirect connections) into a directory an attacker
            // controls.
            if meta.file_type().is_symlink() {
                return Err(Error::Protocol(
                    "streamlocal-forward: refusing to bind over a symlink",
                ));
            }
            // OpenSSH's default (`StreamLocalBindUnlink no`) never unlinks an
            // existing file. We unlink only a stale socket of our own uid, so
            // a reconnecting client can reuse its path; a live socket, or
            // anything else, makes the bind fail.
            if is_stale_own_socket(&path, &meta) {
                let _ = std::fs::remove_file(&path);
            }
        }

        let (listener, socket_id) = bind_owner_only(&path)?;

        let stop = Arc::new(AtomicBool::new(false));
        let stop_thread = Arc::clone(&stop);
        let bind_path_owned = socket_path.to_string();
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
                        // Ask the per-connection server loop to open a
                        // `forwarded-streamlocal@openssh.com` channel back to
                        // the client. If the client refuses (or the SSH
                        // connection is gone), drop the socket connection.
                        match ctx.open_forwarded_streamlocal(&bind_path_owned) {
                            Ok(channel_stream) => spawn_unix_splice(conn, channel_stream),
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

        map.insert(
            socket_path.to_string(),
            Binding {
                owner: user.to_string(),
                stop,
                handle: Some(handle),
                socket_path: path,
                socket_id,
            },
        );
        Ok(())
    }

    fn unbind(&self, user: &str, socket_path: &str) -> Result<()> {
        let mut map = self
            .bindings
            .lock()
            .map_err(|_| Error::Protocol("streamlocal-forward: lock poisoned"))?;
        // Only the user that created a binding may cancel it.
        if map.get(socket_path).is_some_and(|b| b.owner != user) {
            return Err(Error::Protocol(
                "cancel-streamlocal-forward: binding owned by another user",
            ));
        }
        if let Some(binding) = map.remove(socket_path) {
            // Drop outside the lock to keep `unbind` fast for concurrent
            // callers — the `Drop` impl joins the worker thread.
            drop(map);
            drop(binding);
            Ok(())
        } else {
            Err(Error::Protocol(
                "cancel-streamlocal-forward: no such binding",
            ))
        }
    }
}

/// Bridge a Unix-socket connection against a `ChannelStream`. Each direction
/// runs on its own thread; when one direction closes we forward EOF/Close on
/// the SSH side and shut down the socket so the other thread unblocks.
/// Mirrors `spawn_unix_splice` in [`crate::forwarding::agent`].
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

/// Build a [`crate::client::ForwardedStreamlocalCallback`]-shaped closure
/// that splices each inbound `forwarded-streamlocal@openssh.com` channel
/// against a local Unix-domain socket at `path`. This is the client side of
/// `ssh -R /remote.sock:/local.sock`.
///
/// Drop-in for [`crate::client::ClientHandlers::with_forwarded_streamlocal`].
#[cfg(feature = "client")]
pub fn splice_to_unix_socket_callback(
    path: PathBuf,
) -> Arc<dyn Fn(crate::client::ForwardedStreamlocalOrigin, ChannelStream) + Send + Sync + 'static> {
    Arc::new(
        move |_origin: crate::client::ForwardedStreamlocalOrigin, stream: ChannelStream| {
            match UnixStream::connect(&path) {
                Ok(uds) => spawn_unix_splice(uds, stream),
                Err(_) => {
                    // Local socket went away or refused. Drop the channel —
                    // the server will observe EOF/Close.
                    let (_rx, tx) = stream.into_raw();
                    let _ = tx.send(ChannelEgress::Eof);
                    let _ = tx.send(ChannelEgress::Close);
                }
            }
        },
    )
}

#[cfg(all(test, feature = "server"))]
mod tests {
    use super::*;

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
            let path =
                PathBuf::from("/tmp").join(format!("p-slf-{prefix}-{pid:x}-{:x}", nanos as u32));
            std::fs::create_dir_all(&path).expect("create tempdir");
            Self { path }
        }
    }

    impl Drop for TestTempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }

    #[test]
    fn bind_creates_socket_and_unbind_releases_it() {
        let dir = TestTempDir::new("bind");
        let sock = dir.path.join("fwd.sock");
        let sock_str = sock.to_string_lossy().to_string();
        let h = DefaultStreamlocalForwardHandler::permit_all();
        h.bind(
            "u",
            &sock_str,
            StreamlocalForwardContext::for_test_no_opens(),
        )
        .expect("bind");
        assert!(sock.exists(), "socket should exist on disk after bind");
        assert_eq!(h.binding_count(), 1);
        h.unbind("u", &sock_str).expect("unbind");
        assert_eq!(h.binding_count(), 0);
        // Give the worker a moment to unlink the socket on drop.
        for _ in 0..50 {
            if !sock.exists() {
                break;
            }
            thread::sleep(Duration::from_millis(50));
        }
        assert!(!sock.exists(), "socket should be unlinked after unbind");
    }

    /// FWD-6: the socket is owner-only (StreamLocalBindMask 0177).
    #[test]
    fn bound_socket_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = TestTempDir::new("mode");
        let sock = dir.path.join("fwd.sock");
        let sock_str = sock.to_string_lossy().to_string();
        let h = DefaultStreamlocalForwardHandler::permit_all();
        h.bind(
            "u",
            &sock_str,
            StreamlocalForwardContext::for_test_no_opens(),
        )
        .expect("bind");
        let mode = std::fs::metadata(&sock).expect("stat").permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "mode {mode:o}");
        h.unbind("u", &sock_str).expect("unbind");
    }

    /// FWD-5: another user can neither displace nor cancel a binding, and
    /// the binding's live socket survives both attempts.
    #[test]
    fn binding_is_owned_by_its_user() {
        let dir = TestTempDir::new("owner");
        let sock = dir.path.join("fwd.sock");
        let sock_str = sock.to_string_lossy().to_string();
        let h = DefaultStreamlocalForwardHandler::permit_all();
        h.bind(
            "alice",
            &sock_str,
            StreamlocalForwardContext::for_test_no_opens(),
        )
        .expect("bind");
        assert!(
            h.bind(
                "mallory",
                &sock_str,
                StreamlocalForwardContext::for_test_no_opens()
            )
            .is_err()
        );
        assert!(h.unbind("mallory", &sock_str).is_err());
        assert_eq!(h.binding_count(), 1);
        assert!(UnixStream::connect(&sock).is_ok(), "alice's socket is live");
        h.unbind("alice", &sock_str).expect("owner unbind");
    }

    /// FWD-5: dropping a binding never unlinks a socket that has since been
    /// replaced by someone else's at the same path.
    #[test]
    fn unbind_leaves_a_replacement_socket_alone() {
        let dir = TestTempDir::new("replace");
        let sock = dir.path.join("fwd.sock");
        let sock_str = sock.to_string_lossy().to_string();
        let h = DefaultStreamlocalForwardHandler::permit_all();
        h.bind(
            "u",
            &sock_str,
            StreamlocalForwardContext::for_test_no_opens(),
        )
        .expect("bind");
        std::fs::remove_file(&sock).expect("unlink");
        let other = UnixListener::bind(&sock).expect("rebind elsewhere");
        h.unbind("u", &sock_str).expect("unbind");
        assert!(sock.exists(), "the replacement socket must survive");
        drop(other);
    }

    /// FWD-6: a stale socket of ours is replaced; a live one is not.
    #[test]
    fn only_a_stale_existing_socket_is_unlinked() {
        let dir = TestTempDir::new("stale");
        let sock = dir.path.join("fwd.sock");
        let sock_str = sock.to_string_lossy().to_string();
        let h = DefaultStreamlocalForwardHandler::permit_all();

        let live = UnixListener::bind(&sock).expect("live listener");
        assert!(
            h.bind(
                "u",
                &sock_str,
                StreamlocalForwardContext::for_test_no_opens()
            )
            .is_err(),
            "a live socket must not be replaced"
        );
        assert!(UnixStream::connect(&sock).is_ok(), "live socket intact");
        drop(live); // leaves the (now stale) socket file behind

        h.bind(
            "u",
            &sock_str,
            StreamlocalForwardContext::for_test_no_opens(),
        )
        .expect("stale socket replaced");
        h.unbind("u", &sock_str).expect("unbind");

        // A regular file is never removed.
        std::fs::write(&sock, b"x").expect("write");
        assert!(
            h.bind(
                "u",
                &sock_str,
                StreamlocalForwardContext::for_test_no_opens()
            )
            .is_err()
        );
        assert_eq!(std::fs::read(&sock).expect("read"), b"x");
    }

    #[test]
    fn default_constructor_is_deny_all() {
        let dir = TestTempDir::new("deny");
        let sock = dir.path.join("fwd.sock");
        let h = DefaultStreamlocalForwardHandler::new();
        assert!(
            h.bind(
                "u",
                &sock.to_string_lossy(),
                StreamlocalForwardContext::for_test_no_opens(),
            )
            .is_err()
        );
        assert_eq!(h.binding_count(), 0);
        assert!(!sock.exists());
    }

    #[test]
    fn unbind_of_unknown_binding_errors() {
        let h = DefaultStreamlocalForwardHandler::new();
        assert!(h.unbind("u", "/tmp/nope.sock").is_err());
    }

    #[test]
    fn allow_filter_sees_user_and_path() {
        let dir = TestTempDir::new("filter");
        let sock = dir.path.join("fwd.sock");
        let sock_str = sock.to_string_lossy().to_string();
        let h = DefaultStreamlocalForwardHandler::new()
            .with_allow_filter(|user, _path| user == "alice");
        assert!(
            h.bind(
                "bob",
                &sock_str,
                StreamlocalForwardContext::for_test_no_opens()
            )
            .is_err()
        );
        h.bind(
            "alice",
            &sock_str,
            StreamlocalForwardContext::for_test_no_opens(),
        )
        .expect("alice bind allowed");
        h.unbind("alice", &sock_str).expect("unbind");
    }
}
