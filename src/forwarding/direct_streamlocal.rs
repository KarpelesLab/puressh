//! `DefaultDirectStreamlocalHandler` — server-side default for
//! `direct-streamlocal@openssh.com` channels (the Unix-socket analog of
//! [`crate::forwarding::direct::DefaultDirectTcpipHandler`]).
//!
//! Bridges the SSH [`ChannelStream`] to a fresh [`UnixStream`] connected to
//! the client-requested socket path. Bytes from the channel are written to
//! the Unix socket; bytes from the socket are written back into the channel.
//! The handler exits when either side closes, at which point we explicitly
//! emit `CHANNEL_EOF` + `CHANNEL_CLOSE` on the SSH side via the raw egress
//! sender obtained from [`ChannelStream::into_raw`].

use std::io::{self, Read, Write};
use std::net::Shutdown;
use std::os::unix::net::UnixStream;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, SyncSender};
use std::thread;

use crate::error::Result;
use crate::server::{
    ChannelEgress, ChannelStream, DirectStreamlocalHandler, DirectStreamlocalRequest,
};

/// Filter callback type for [`DefaultDirectStreamlocalHandler::with_allow_list`].
type AllowFilter = Box<dyn Fn(&str) -> bool + Send + Sync>;

/// Internal policy describing which socket paths the handler will dial.
///
/// `Deny` is the default-constructed state — every request is refused
/// (silently closed) until the operator opts into something looser via
/// [`DefaultDirectStreamlocalHandler::permit_all`] or
/// [`DefaultDirectStreamlocalHandler::with_allow_list`].
enum Policy {
    /// Refuse every socket path. Returned by
    /// [`DefaultDirectStreamlocalHandler::new`] to make a multi-tenant
    /// deployment safe by default.
    Deny,
    /// Allow every socket path.
    All,
    /// Allow only paths for which the filter returns `true`.
    Filter(AllowFilter),
}

/// Drop-in [`DirectStreamlocalHandler`] that connects to the requested Unix
/// socket path and proxies bytes.
///
/// # Default-deny
///
/// A bare [`DefaultDirectStreamlocalHandler::new`] is **default-deny**: every
/// `direct-streamlocal@openssh.com` request is silently refused. This is the
/// safe default for multi-tenant servers, where an unrestricted handler lets
/// any authenticated user reach host-local Unix sockets (the Docker daemon
/// socket, database sockets, IPC endpoints, etc.) via `ssh -L`.
///
/// Operators must explicitly choose one of:
///
/// - [`Self::with_allow_list`] to permit a specific set of paths.
/// - [`Self::permit_all`] to allow every path.
///
/// ```ignore
/// use std::sync::Arc;
/// use puressh::forwarding::direct_streamlocal::DefaultDirectStreamlocalHandler;
///
/// // Allow only the Docker daemon socket.
/// let h = Arc::new(
///     DefaultDirectStreamlocalHandler::new()
///         .with_allow_list(|path| path == "/var/run/docker.sock"),
/// );
/// ```
pub struct DefaultDirectStreamlocalHandler {
    policy: Policy,
}

impl Default for DefaultDirectStreamlocalHandler {
    fn default() -> Self {
        Self::new()
    }
}

impl DefaultDirectStreamlocalHandler {
    /// Build a **default-deny** handler: every request is silently refused
    /// until the caller opts into a looser policy via
    /// [`Self::with_allow_list`] or [`Self::permit_all`].
    pub fn new() -> Self {
        Self {
            policy: Policy::Deny,
        }
    }

    /// Allow every socket path. Only safe on single-tenant servers (one
    /// trusted operator with shell access); prefer [`Self::with_allow_list`]
    /// anywhere the SSH users aren't the same trust principal as the host.
    pub fn permit_all() -> Self {
        Self {
            policy: Policy::All,
        }
    }

    /// Reject any socket path for which `filter(path)` returns `false`. The
    /// handler still accepts the SSH-level channel open (the peer sees a
    /// connected channel) and then immediately closes it on the filter
    /// failure path — matching OpenSSH's accept-then-close behaviour for
    /// `PermitOpen` mismatches.
    pub fn with_allow_list<F>(mut self, filter: F) -> Self
    where
        F: Fn(&str) -> bool + Send + Sync + 'static,
    {
        self.policy = Policy::Filter(Box::new(filter));
        self
    }

    fn allowed(&self, path: &str) -> bool {
        match &self.policy {
            Policy::Deny => false,
            Policy::All => true,
            Policy::Filter(f) => f(path),
        }
    }
}

impl DirectStreamlocalHandler for DefaultDirectStreamlocalHandler {
    fn handle(
        &self,
        _user: &str,
        request: DirectStreamlocalRequest<'_>,
        stream: ChannelStream,
    ) -> Result<()> {
        let path = request.socket_path;
        if !self.allowed(path) {
            return Ok(());
        }
        let uds = match UnixStream::connect(path) {
            Ok(s) => s,
            Err(_) => return Ok(()),
        };
        splice(stream, uds)
    }
}

/// Splice the SSH `ChannelStream` against an open `UnixStream` in both
/// directions, returning once either side hits EOF or errors. Mirrors
/// `splice` in [`crate::forwarding::direct`] but for `UnixStream`.
fn splice(stream: ChannelStream, uds: UnixStream) -> Result<()> {
    let (raw_rx, raw_tx) = stream.into_raw();

    let uds_for_writer = uds.try_clone().map_err(|e| {
        crate::error::Error::Io(io::Error::new(
            e.kind(),
            "direct-streamlocal: UnixStream::try_clone failed",
        ))
    })?;

    let stop = Arc::new(AtomicBool::new(false));
    let stop_worker = Arc::clone(&stop);
    let tx_worker = raw_tx.clone();

    // Worker: Unix socket → channel.
    let worker = thread::spawn(move || {
        let mut reader = uds_for_writer;
        copy_uds_to_channel(&mut reader, &tx_worker, &stop_worker);
    });

    // Main: channel → Unix socket.
    let mut writer = uds;
    copy_channel_to_uds(&raw_rx, &mut writer, &stop);

    let _ = writer.shutdown(Shutdown::Both);
    stop.store(true, Ordering::SeqCst);
    let _ = worker.join();

    let _ = raw_tx.send(ChannelEgress::Eof);
    let _ = raw_tx.send(ChannelEgress::Close);
    Ok(())
}

fn copy_channel_to_uds(rx: &Receiver<Option<Vec<u8>>>, uds: &mut UnixStream, stop: &AtomicBool) {
    loop {
        if stop.load(Ordering::SeqCst) {
            return;
        }
        match rx.recv() {
            Ok(Some(chunk)) => {
                if uds.write_all(&chunk).is_err() {
                    return;
                }
            }
            Ok(None) | Err(_) => return,
        }
    }
}

fn copy_uds_to_channel(uds: &mut UnixStream, tx: &SyncSender<ChannelEgress>, stop: &AtomicBool) {
    let mut buf = [0u8; 32 * 1024];
    loop {
        if stop.load(Ordering::SeqCst) {
            return;
        }
        let n = match uds.read(&mut buf) {
            Ok(0) => return,
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => return,
        };
        if tx.send(ChannelEgress::Data(buf[..n].to_vec())).is_err() {
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixListener;
    use std::sync::mpsc;
    use std::time::Duration;

    /// Tiny on-disk scratch dir (same pattern as the agent-forward tests).
    struct TestTempDir {
        path: std::path::PathBuf,
    }

    impl TestTempDir {
        fn new(prefix: &str) -> Self {
            use std::time::{SystemTime, UNIX_EPOCH};
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0);
            let pid = std::process::id();
            let path = std::path::PathBuf::from("/tmp")
                .join(format!("p-dsl-{prefix}-{pid:x}-{:x}", nanos as u32));
            std::fs::create_dir_all(&path).expect("create tempdir");
            Self { path }
        }
    }

    impl Drop for TestTempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }

    /// Tiny Unix-socket echo server bound at `path`. Returns its join handle.
    fn echo_server(path: std::path::PathBuf) -> thread::JoinHandle<()> {
        let l = UnixListener::bind(&path).expect("bind");
        thread::spawn(move || {
            if let Ok((mut s, _)) = l.accept() {
                let mut buf = [0u8; 1024];
                loop {
                    match s.read(&mut buf) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if s.write_all(&buf[..n]).is_err() {
                                break;
                            }
                        }
                    }
                }
            }
        })
    }

    #[test]
    fn direct_streamlocal_round_trip_through_echo_server() {
        let dir = TestTempDir::new("rt");
        let sock = dir.path.join("echo.sock");
        let echo = echo_server(sock.clone());

        let (ingress_tx, ingress_rx) = mpsc::channel::<Option<Vec<u8>>>();
        let (egress_tx, egress_rx) = mpsc::sync_channel::<ChannelEgress>(32);
        let stream = ChannelStream::new(ingress_rx, egress_tx);

        let path = sock.to_string_lossy().to_string();
        let handler = thread::spawn(move || {
            let h = DefaultDirectStreamlocalHandler::permit_all();
            let req = DirectStreamlocalRequest { socket_path: &path };
            h.handle("test-user", req, stream).expect("handle");
        });

        ingress_tx
            .send(Some(b"ping".to_vec()))
            .expect("ingress send");

        let mut got = Vec::new();
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while got.len() < 4 && std::time::Instant::now() < deadline {
            match egress_rx.recv_timeout(Duration::from_millis(500)) {
                Ok(ChannelEgress::Data(d)) => got.extend_from_slice(&d),
                Ok(ChannelEgress::Eof) | Ok(ChannelEgress::Close) => break,
                Err(_) => break,
            }
        }
        assert_eq!(&got, b"ping");

        ingress_tx.send(None).expect("ingress eof");
        drop(ingress_tx);
        handler.join().expect("handler thread");
        let _ = echo.join();
    }

    /// `::new()` is default-deny: a request is refused without ever
    /// attempting a Unix-socket connection.
    #[test]
    fn default_constructor_is_deny_all() {
        let (_ingress_tx, ingress_rx) = mpsc::channel::<Option<Vec<u8>>>();
        let (egress_tx, _egress_rx) = mpsc::sync_channel::<ChannelEgress>(8);
        let stream = ChannelStream::new(ingress_rx, egress_tx);
        let h = DefaultDirectStreamlocalHandler::new();
        let req = DirectStreamlocalRequest {
            socket_path: "/nonexistent/should-never-dial.sock",
        };
        h.handle("u", req, stream).expect("handle");
    }

    #[test]
    fn allow_list_rejects_silently() {
        let (_ingress_tx, ingress_rx) = mpsc::channel::<Option<Vec<u8>>>();
        let (egress_tx, _egress_rx) = mpsc::sync_channel::<ChannelEgress>(8);
        let stream = ChannelStream::new(ingress_rx, egress_tx);
        let h =
            DefaultDirectStreamlocalHandler::new().with_allow_list(|path| path == "/allowed.sock");
        let req = DirectStreamlocalRequest {
            socket_path: "/denied.sock",
        };
        h.handle("u", req, stream).expect("handle");
    }
}
