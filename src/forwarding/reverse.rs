//! Server-side glue for `tcpip-forward` / `cancel-tcpip-forward`
//! (RFC 4254 §7.1).
//!
//! Implements [`DefaultTcpipForwardHandler`], the in-process backing for
//! the [`crate::server::TcpipForwardHandler`] trait. The handler:
//!
//! - On `bind`, opens a real [`std::net::TcpListener`] for the requested
//!   address and port (`port == 0` picks any free port), and returns the
//!   actually-assigned port back to the server, which echoes it to the
//!   client per the RFC.
//! - Spawns one *accept-and-drop* worker thread per binding. Connections
//!   to the bound port are accepted and immediately torn down. **Bytes
//!   are not yet proxied** — that requires server-initiated
//!   `forwarded-tcpip` channel-opens back to the client, which lands in a
//!   follow-up commit alongside the matching client-side multi-channel
//!   dispatcher.
//! - On `unbind`, signals the worker thread to stop and drops the
//!   listener.
//!
//! The accept-and-drop semantics are not a security risk on their own —
//! the user's TCP stack would behave identically without the listener,
//! except connections would `ECONNREFUSED` immediately. With the
//! listener present, the kernel completes the three-way handshake and we
//! close the socket without writing anything.

use std::collections::BTreeMap;
use std::io::ErrorKind;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use crate::error::{Error, Result};
use crate::server::TcpipForwardHandler;

/// How often the accept-loop polls the non-blocking listener while
/// waiting for either a connection or the stop flag.
const ACCEPT_POLL_INTERVAL: Duration = Duration::from_millis(100);

/// One live `tcpip-forward` binding. Dropping it signals the worker
/// thread to stop and joins it. The thread observes the flag in between
/// `accept()` polls, then exits, releasing the [`TcpListener`].
struct Binding {
    stop: Arc<AtomicBool>,
    /// Carrying an `Option` so the destructor can take ownership of the
    /// `JoinHandle` and call `.join()`.
    handle: Option<JoinHandle<()>>,
}

impl Drop for Binding {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

/// Default in-process backing for `tcpip-forward` / `cancel-tcpip-forward`.
///
/// One instance per server typically, registered via
/// [`crate::server::Config::with_tcpip_forward`]. The handler is safe to
/// share across connections — each `bind` opens its own listener and
/// tracks it by the (`bind_address`, returned-port) key.
///
/// **Important**: connections accepted on a bound port are currently
/// closed immediately. End-to-end byte forwarding requires the
/// `forwarded-tcpip` back-channel work in a follow-up commit.
pub struct DefaultTcpipForwardHandler {
    bindings: Mutex<BTreeMap<(String, u16), Binding>>,
}

impl Default for DefaultTcpipForwardHandler {
    fn default() -> Self {
        Self::new()
    }
}

impl DefaultTcpipForwardHandler {
    /// Build a fresh handler with no active bindings.
    pub fn new() -> Self {
        Self {
            bindings: Mutex::new(BTreeMap::new()),
        }
    }

    /// Number of bindings currently held. Useful for tests / monitoring.
    pub fn binding_count(&self) -> usize {
        self.bindings.lock().map(|m| m.len()).unwrap_or(0)
    }
}

fn resolve_bind(bind_address: &str, port: u16) -> Result<SocketAddr> {
    // RFC 4254 §7.1: "" / "0.0.0.0" → all interfaces; "localhost" →
    // loopback; anything else must parse as a literal IP. We deliberately
    // do not perform DNS resolution here — the SSH server should not
    // open arbitrary outbound DNS lookups based on a client request.
    match bind_address {
        "" | "0.0.0.0" => Ok(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port)),
        "::" => Ok(SocketAddr::new(
            IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED),
            port,
        )),
        "localhost" | "127.0.0.1" => Ok(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port)),
        "::1" => Ok(SocketAddr::new(
            IpAddr::V6(std::net::Ipv6Addr::LOCALHOST),
            port,
        )),
        other => other
            .parse::<IpAddr>()
            .map(|ip| SocketAddr::new(ip, port))
            .map_err(|_| Error::Protocol("tcpip-forward: invalid bind address")),
    }
}

impl TcpipForwardHandler for DefaultTcpipForwardHandler {
    fn bind(&self, _user: &str, bind_address: &str, bind_port: u16) -> Result<u16> {
        let addr = resolve_bind(bind_address, bind_port)?;
        let listener = TcpListener::bind(addr)?;
        let actual_port = listener.local_addr()?.port();
        listener.set_nonblocking(true)?;

        let stop = Arc::new(AtomicBool::new(false));
        let stop_thread = Arc::clone(&stop);
        let handle = thread::spawn(move || {
            // Accept-and-drop loop. Real `forwarded-tcpip` channel-opens
            // back to the client are deferred to a follow-up phase.
            while !stop_thread.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((conn, _peer)) => {
                        // We have nowhere to forward bytes yet. Close
                        // cleanly so the client observes ECONNRESET
                        // rather than a hung connection.
                        let _ = conn.shutdown(std::net::Shutdown::Both);
                    }
                    Err(e) if e.kind() == ErrorKind::WouldBlock => {
                        thread::sleep(ACCEPT_POLL_INTERVAL);
                    }
                    Err(_) => break,
                }
            }
        });

        let mut map = self
            .bindings
            .lock()
            .map_err(|_| Error::Protocol("tcpip-forward: lock poisoned"))?;
        let key = (bind_address.to_string(), actual_port);
        // If somehow we already have a binding under that key (e.g. the
        // peer asked twice), drop the existing one first to keep the map
        // invariant clean.
        if let Some(existing) = map.remove(&key) {
            drop(existing);
        }
        map.insert(
            key,
            Binding {
                stop,
                handle: Some(handle),
            },
        );
        Ok(actual_port)
    }

    fn unbind(&self, _user: &str, bind_address: &str, bind_port: u16) -> Result<()> {
        let mut map = self
            .bindings
            .lock()
            .map_err(|_| Error::Protocol("tcpip-forward: lock poisoned"))?;
        let key = (bind_address.to_string(), bind_port);
        if let Some(binding) = map.remove(&key) {
            // Drop outside the lock to keep `unbind` fast for concurrent
            // callers — the `Drop` impl on `Binding` joins the worker
            // thread, which can take up to one poll interval.
            drop(map);
            drop(binding);
            Ok(())
        } else {
            Err(Error::Protocol("cancel-tcpip-forward: no such binding"))
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::TcpStream;
    use std::time::Duration;

    use super::*;

    #[test]
    fn bind_port_zero_picks_and_returns_a_port() {
        let h = DefaultTcpipForwardHandler::new();
        let port = h.bind("u", "127.0.0.1", 0).expect("bind");
        assert!(port > 0, "kernel-assigned port should be non-zero");
        assert_eq!(h.binding_count(), 1);
        h.unbind("u", "127.0.0.1", port).expect("unbind");
        assert_eq!(h.binding_count(), 0);
    }

    #[test]
    fn accepted_connection_is_immediately_closed() {
        let h = DefaultTcpipForwardHandler::new();
        let port = h.bind("u", "127.0.0.1", 0).expect("bind");
        let mut tcp = TcpStream::connect(("127.0.0.1", port)).expect("connect");
        tcp.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
        let mut buf = [0u8; 4];
        // Read returns Ok(0) on a graceful peer close; that's what we
        // expect from the accept-and-drop stub.
        let n = std::io::Read::read(&mut tcp, &mut buf).expect("read");
        assert_eq!(n, 0, "stub accept-and-drop should close the peer end");
        h.unbind("u", "127.0.0.1", port).expect("unbind");
    }

    #[test]
    fn unbind_releases_the_listener_so_a_fresh_bind_succeeds() {
        let h = DefaultTcpipForwardHandler::new();
        let port = h.bind("u", "127.0.0.1", 0).expect("first bind");
        h.unbind("u", "127.0.0.1", port).expect("unbind");
        // Re-binding the *same* port (now released) must succeed.
        let again = h
            .bind("u", "127.0.0.1", port)
            .expect("rebind released port");
        assert_eq!(again, port);
        h.unbind("u", "127.0.0.1", port).expect("final unbind");
    }

    #[test]
    fn unbind_of_unknown_binding_errors() {
        let h = DefaultTcpipForwardHandler::new();
        assert!(h.unbind("u", "127.0.0.1", 12345).is_err());
    }

    #[test]
    fn invalid_bind_address_is_rejected() {
        let h = DefaultTcpipForwardHandler::new();
        // Names that aren't literal IPs (or the documented shortcuts) get
        // refused without ever touching the network. The server then
        // turns that into REQUEST_FAILURE.
        assert!(h.bind("u", "not-an-ip-or-name", 0).is_err());
    }
}
