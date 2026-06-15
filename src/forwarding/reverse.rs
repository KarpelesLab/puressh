//! Server-side glue for `tcpip-forward` / `cancel-tcpip-forward`
//! (RFC 4254 §7.1) and the matching `forwarded-tcpip` channel-opens
//! (RFC 4254 §7.2).
//!
//! Implements [`DefaultTcpipForwardHandler`], the in-process backing for
//! the [`crate::server::TcpipForwardHandler`] trait. The handler:
//!
//! - On `bind`, opens a real [`std::net::TcpListener`] for the requested
//!   address and port (`port == 0` picks any free port), and returns the
//!   actually-assigned port back to the server, which echoes it to the
//!   client per the RFC.
//! - Spawns one worker thread per binding. For each accepted TCP
//!   connection on the bound port the worker calls
//!   [`crate::server::ForwardContext::open_forwarded_tcpip`] to ask the
//!   per-connection server loop to open a `forwarded-tcpip` channel back
//!   toward the client, then splices the TCP socket against the resulting
//!   [`crate::server::ChannelStream`] in both directions until either
//!   side hangs up.
//! - On `unbind`, signals the worker thread to stop and drops the
//!   listener.

use std::collections::BTreeMap;
use std::io::{ErrorKind, Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use crate::error::{Error, Result};
use crate::server::{ChannelEgress, ForwardContext, TcpipForwardHandler};

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

/// Filter callback type for [`DefaultTcpipForwardHandler::with_allow_filter`].
type AllowFilter = Box<dyn Fn(&str, &str, u16) -> bool + Send + Sync>;

/// Internal policy describing which bind requests the handler will honour
/// and which bind address it ultimately listens on.
enum Policy {
    /// Refuse every bind. The default constructed by [`DefaultTcpipForwardHandler::new`].
    Deny,
    /// Permit any bind but force the kernel-facing listener onto loopback
    /// (`127.0.0.1` for IPv4, `::1` for IPv6) regardless of what the client
    /// asked for. Matches OpenSSH's `GatewayPorts=no` (the default).
    LocalhostOnly,
    /// Honour the client's bind address verbatim (including `0.0.0.0` /
    /// `::`). Restores the pre-2026-05 default — only safe on
    /// single-tenant servers.
    AllInterfaces,
    /// Defer the decision to a per-request filter. The filter sees the
    /// authenticated user plus the address/port the client asked for. The
    /// bind address is honoured verbatim if the filter returns `true`.
    Filter(AllowFilter),
}

/// Default in-process backing for `tcpip-forward` / `cancel-tcpip-forward`.
///
/// One instance per server typically, registered via
/// [`crate::server::Config::with_tcpip_forward`]. The handler is safe to
/// share across connections — each `bind` opens its own listener and
/// tracks it by the (`bind_address`, returned-port) key.
///
/// # Default-deny
///
/// A bare [`DefaultTcpipForwardHandler::new`] is **default-deny**: every
/// `tcpip-forward` request is refused at the policy layer (the per-
/// connection dispatcher surfaces it as `SSH_MSG_REQUEST_FAILURE` on the
/// wire). This is the safe default on a multi-tenant bastion, where the
/// historical "allow everything, bind on all interfaces" behaviour let any
/// authenticated user publish a tunnel on the host's public IP.
///
/// Operators must explicitly choose one of:
///
/// - [`Self::permit_localhost_only`] — the OpenSSH `GatewayPorts=no`
///   default. Honours the bind request but forces the kernel-facing
///   listener onto `127.0.0.1` (or `::1`) regardless of what the client
///   asked for. Even a client that asks for `0.0.0.0` ends up on loopback
///   — there is no way for an authenticated user to publish on the public
///   IP under this policy.
/// - [`Self::permit_all_interfaces`] — the pre-2026-05 default. Lets the
///   client bind anything, including `0.0.0.0` / `::`. Only safe on
///   single-tenant servers (one trusted operator).
/// - [`Self::with_allow_filter`] — a custom per-request decision (e.g.
///   "alice may bind any port on 127.0.0.1; bob may not bind anything").
///   The bind address is honoured verbatim, so the filter is responsible
///   for refusing `""` / `0.0.0.0` / `::` if the operator doesn't want
///   gateway-port behaviour.
///
/// ```ignore
/// use puressh::forwarding::reverse::DefaultTcpipForwardHandler;
///
/// // OpenSSH GatewayPorts=no equivalent.
/// let h = DefaultTcpipForwardHandler::permit_localhost_only();
/// ```
pub struct DefaultTcpipForwardHandler {
    bindings: Mutex<BTreeMap<(String, u16), Binding>>,
    policy: Policy,
}

impl Default for DefaultTcpipForwardHandler {
    fn default() -> Self {
        Self::new()
    }
}

impl DefaultTcpipForwardHandler {
    /// Build a **default-deny** handler with no active bindings.
    ///
    /// Historically (before 2026-05) `::new()` returned an allow-everything
    /// handler that also honoured `0.0.0.0` binds, letting any authenticated
    /// user publish a tunnel on the bastion's public IP. The constructor was
    /// flipped to default-deny; callers must opt into a permission policy
    /// via [`Self::permit_localhost_only`], [`Self::permit_all_interfaces`],
    /// or [`Self::with_allow_filter`].
    pub fn new() -> Self {
        Self {
            bindings: Mutex::new(BTreeMap::new()),
            policy: Policy::Deny,
        }
    }

    /// Permit every bind request but force the kernel-facing listener onto
    /// loopback (`127.0.0.1` for IPv4 / IPv4-defaulted requests, `::1` for
    /// `::`). Matches OpenSSH's `GatewayPorts=no` (the OpenSSH default).
    ///
    /// Concretely, the bind address the client sent is rewritten before the
    /// `TcpListener` is opened:
    ///
    /// | client requested | actually bound on |
    /// |---|---|
    /// | `""` / `0.0.0.0` / `127.0.0.1` / `localhost` | `127.0.0.1` |
    /// | `::` / `::1` | `::1` |
    /// | any other literal IP | refused with [`Error::Protocol`] |
    ///
    /// The protocol-level `bind_address` field reported back to the peer is
    /// **not** rewritten — the wire reply still names the address the client
    /// asked for, which mirrors OpenSSH's behaviour and lets the client log
    /// the request faithfully.
    pub fn permit_localhost_only() -> Self {
        Self {
            bindings: Mutex::new(BTreeMap::new()),
            policy: Policy::LocalhostOnly,
        }
    }

    /// Permit every bind request and honour the requested bind address
    /// verbatim, including `0.0.0.0` / `::`. Restores the pre-2026-05
    /// default. Only safe on single-tenant servers.
    pub fn permit_all_interfaces() -> Self {
        Self {
            bindings: Mutex::new(BTreeMap::new()),
            policy: Policy::AllInterfaces,
        }
    }

    /// Attach an allow filter. Each `bind` request passes
    /// `(user, bind_address, bind_port)` through the filter; a `false`
    /// return value surfaces to the peer as a `REQUEST_FAILURE` for the
    /// global request (no listener is created).
    ///
    /// Unlike [`Self::permit_localhost_only`] the bind address is **not**
    /// rewritten — if the filter returns `true` for a `0.0.0.0` request the
    /// listener will bind on all interfaces. Filters that want
    /// `GatewayPorts=no` semantics should reject the wildcard addresses
    /// explicitly (or build atop [`Self::permit_localhost_only`] instead).
    pub fn with_allow_filter<F>(mut self, filter: F) -> Self
    where
        F: Fn(&str, &str, u16) -> bool + Send + Sync + 'static,
    {
        self.policy = Policy::Filter(Box::new(filter));
        self
    }

    fn allowed(&self, user: &str, bind_address: &str, bind_port: u16) -> bool {
        match &self.policy {
            Policy::Deny => false,
            Policy::LocalhostOnly | Policy::AllInterfaces => true,
            Policy::Filter(f) => f(user, bind_address, bind_port),
        }
    }

    /// Number of bindings currently held. Useful for tests / monitoring.
    pub fn binding_count(&self) -> usize {
        self.bindings.lock().map(|m| m.len()).unwrap_or(0)
    }
}

/// Bridge a TCP socket against a server-side `ChannelStream`. Each
/// direction runs on its own thread so a slow peer in one direction can't
/// stall the other; when one direction closes we forward EOF/Close on the
/// SSH side and shut down the TCP socket so the other thread unblocks and
/// exits.
fn spawn_splice(tcp: TcpStream, stream: crate::server::ChannelStream) {
    // Peel the channel down to its raw mpsc handles so each direction can
    // be driven independently. This also suppresses the auto-EOF/Close on
    // drop — we emit those explicitly once the TCP→channel direction has
    // finished, which is the canonical splice teardown.
    let (chan_rx, chan_tx) = stream.into_raw();
    let Ok(tcp_in) = tcp.try_clone() else {
        // try_clone shouldn't fail on a freshly-accepted socket; if it
        // does, give up rather than half-spliced.
        let _ = chan_tx.send(ChannelEgress::Eof);
        let _ = chan_tx.send(ChannelEgress::Close);
        return;
    };
    let tcp_out = tcp;

    // Direction A: TCP → channel.
    let chan_tx_a = chan_tx.clone();
    let mut tcp_in_a = tcp_in;
    let a = thread::spawn(move || {
        let mut buf = [0u8; 32 * 1024];
        loop {
            match tcp_in_a.read(&mut buf) {
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
        // Local TCP side hit EOF or error — signal half-close on the SSH
        // side. Don't send Close yet; the channel-side reader may still
        // have bytes flowing the other way.
        let _ = chan_tx_a.send(ChannelEgress::Eof);
    });

    // Direction B: channel → TCP.
    let mut tcp_out_b = tcp_out;
    let b = thread::spawn(move || {
        while let Ok(Some(chunk)) = chan_rx.recv() {
            if tcp_out_b.write_all(&chunk).is_err() {
                break;
            }
        }
        // Channel-side returned None (EOF) or an Err (channel torn down).
        // Stop reading on the local TCP side so the other thread's `read`
        // returns Ok(0) and exits.
        let _ = tcp_out_b.shutdown(std::net::Shutdown::Read);
    });

    // Reaper: when both directions have finished, send Close to drop the
    // channel cleanly.
    thread::spawn(move || {
        let _ = a.join();
        let _ = b.join();
        let _ = chan_tx.send(ChannelEgress::Close);
    });
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

/// `GatewayPorts=no` rewrite: silently coerce any wildcard / IPv4-loopback
/// request to `127.0.0.1`, any IPv6 wildcard / loopback to `::1`, and
/// refuse any other literal IP (the request is sourced from the
/// authenticated peer, so a "bind on a specific public IP" request from
/// them under a localhost-only policy is a policy violation, not a typo).
fn coerce_to_loopback(bind_address: &str, port: u16) -> Result<SocketAddr> {
    match bind_address {
        "" | "0.0.0.0" | "127.0.0.1" | "localhost" => {
            Ok(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port))
        }
        "::" | "::1" => Ok(SocketAddr::new(
            IpAddr::V6(std::net::Ipv6Addr::LOCALHOST),
            port,
        )),
        other => match other.parse::<IpAddr>() {
            Ok(ip) if ip.is_loopback() => Ok(SocketAddr::new(ip, port)),
            // Non-loopback literal under permit_localhost_only is a
            // policy violation; refuse rather than silently widening.
            _ => Err(Error::Protocol(
                "tcpip-forward: permit_localhost_only refuses non-loopback bind",
            )),
        },
    }
}

impl TcpipForwardHandler for DefaultTcpipForwardHandler {
    fn bind(
        &self,
        user: &str,
        bind_address: &str,
        bind_port: u16,
        ctx: ForwardContext,
    ) -> Result<u16> {
        // Filter-first: refuse the request without ever touching the kernel
        // if the operator's policy says no. Surface as a protocol error so
        // the per-connection dispatcher turns it into REQUEST_FAILURE on
        // the wire.
        if !self.allowed(user, bind_address, bind_port) {
            return Err(Error::Protocol("tcpip-forward: bind refused by policy"));
        }
        // `permit_localhost_only` silently rewrites the requested address to
        // loopback before opening the listener; the other policies honour
        // the client's request verbatim (the policy gate above already
        // decided whether to honour it at all).
        let addr = match self.policy {
            Policy::LocalhostOnly => coerce_to_loopback(bind_address, bind_port)?,
            Policy::Deny | Policy::AllInterfaces | Policy::Filter(_) => {
                resolve_bind(bind_address, bind_port)?
            }
        };
        let listener = TcpListener::bind(addr)?;
        let actual_port = listener.local_addr()?.port();
        listener.set_nonblocking(true)?;

        let stop = Arc::new(AtomicBool::new(false));
        let stop_thread = Arc::clone(&stop);
        let bind_address_owned = bind_address.to_string();
        let handle = thread::spawn(move || {
            while !stop_thread.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((conn, peer)) => {
                        // Ask the per-connection server loop to open a
                        // `forwarded-tcpip` channel back to the client.
                        // Blocks until OPEN_CONFIRMATION / OPEN_FAILURE
                        // lands. If the client refuses (or the SSH
                        // connection is gone), drop the TCP socket — the
                        // user's app sees ECONNRESET, which matches
                        // OpenSSH's behaviour when no listener answers.
                        let (orig_host, orig_port) = match peer {
                            SocketAddr::V4(a) => (a.ip().to_string(), a.port()),
                            SocketAddr::V6(a) => (a.ip().to_string(), a.port()),
                        };
                        match ctx.open_forwarded_tcpip(
                            &bind_address_owned,
                            actual_port,
                            &orig_host,
                            orig_port,
                        ) {
                            Ok(channel_stream) => {
                                spawn_splice(conn, channel_stream);
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
    use super::*;

    #[test]
    fn bind_port_zero_picks_and_returns_a_port() {
        // Old-default behaviour exercised via the explicit constructor.
        let h = DefaultTcpipForwardHandler::permit_all_interfaces();
        let port = h
            .bind("u", "127.0.0.1", 0, ForwardContext::for_test_no_opens())
            .expect("bind");
        assert!(port > 0, "kernel-assigned port should be non-zero");
        assert_eq!(h.binding_count(), 1);
        h.unbind("u", "127.0.0.1", port).expect("unbind");
        assert_eq!(h.binding_count(), 0);
    }

    #[test]
    fn unbind_releases_the_listener_so_a_fresh_bind_succeeds() {
        let h = DefaultTcpipForwardHandler::permit_all_interfaces();
        let port = h
            .bind("u", "127.0.0.1", 0, ForwardContext::for_test_no_opens())
            .expect("first bind");
        h.unbind("u", "127.0.0.1", port).expect("unbind");
        // Re-binding the *same* port (now released) must succeed.
        let again = h
            .bind("u", "127.0.0.1", port, ForwardContext::for_test_no_opens())
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
        let h = DefaultTcpipForwardHandler::permit_all_interfaces();
        // Names that aren't literal IPs (or the documented shortcuts) get
        // refused without ever touching the network. The server then
        // turns that into REQUEST_FAILURE.
        assert!(
            h.bind(
                "u",
                "not-an-ip-or-name",
                0,
                ForwardContext::for_test_no_opens(),
            )
            .is_err()
        );
    }

    #[test]
    fn allow_filter_can_refuse_bind() {
        // Loopback-only policy: 127.0.0.1 accepted, 0.0.0.0 refused.
        let h = DefaultTcpipForwardHandler::new()
            .with_allow_filter(|_user, addr, _port| addr == "127.0.0.1");
        let port = h
            .bind("u", "127.0.0.1", 0, ForwardContext::for_test_no_opens())
            .expect("loopback bind allowed");
        assert!(
            h.bind("u", "0.0.0.0", 0, ForwardContext::for_test_no_opens())
                .is_err()
        );
        // Filter refusal must NOT silently bind something; the binding
        // count must still be 1 (the loopback bind we made above).
        assert_eq!(h.binding_count(), 1);
        h.unbind("u", "127.0.0.1", port).expect("unbind");
    }

    #[test]
    fn allow_filter_sees_user() {
        // Refuse everyone but "alice".
        let h = DefaultTcpipForwardHandler::new()
            .with_allow_filter(|user, _addr, _port| user == "alice");
        assert!(
            h.bind("bob", "127.0.0.1", 0, ForwardContext::for_test_no_opens())
                .is_err()
        );
        let port = h
            .bind("alice", "127.0.0.1", 0, ForwardContext::for_test_no_opens())
            .expect("alice bind allowed");
        h.unbind("alice", "127.0.0.1", port).expect("unbind");
    }

    /// `::new()` is default-deny: every bind is refused at the policy
    /// gate, even loopback ones.
    #[test]
    fn default_constructor_is_deny_all() {
        let h = DefaultTcpipForwardHandler::new();
        assert!(
            h.bind("u", "127.0.0.1", 0, ForwardContext::for_test_no_opens())
                .is_err()
        );
        assert!(
            h.bind("u", "0.0.0.0", 0, ForwardContext::for_test_no_opens())
                .is_err()
        );
        assert_eq!(h.binding_count(), 0);
    }

    /// `permit_localhost_only` rewrites a wildcard request to `127.0.0.1`
    /// rather than refusing it (matches OpenSSH `GatewayPorts=no`). The
    /// `binding_count` is keyed by the *client-requested* address, so it
    /// reflects the original string — but the kernel-facing listener must
    /// be on loopback.
    ///
    /// We can't reliably probe "is this bound on 0.0.0.0 or 127.0.0.1?" from
    /// within a test (a 127.0.0.1 listener still blocks a subsequent
    /// 0.0.0.0:port bind), so this test exercises the success path and
    /// trusts the `coerce_to_loopback` unit test below for the address
    /// rewrite itself.
    #[test]
    fn permit_localhost_only_accepts_wildcard_request() {
        let h = DefaultTcpipForwardHandler::permit_localhost_only();
        let port = h
            .bind("u", "0.0.0.0", 0, ForwardContext::for_test_no_opens())
            .expect("wildcard bind rewritten to loopback");
        // Loopback connect must reach the listener.
        let conn = std::net::TcpStream::connect(("127.0.0.1", port));
        assert!(conn.is_ok(), "loopback should reach the rewritten listener");
        let _ = conn.unwrap().shutdown(std::net::Shutdown::Both);
        h.unbind("u", "0.0.0.0", port).expect("unbind");
    }

    /// Direct unit test for the rewrite table — proves that every
    /// "the user asked for any-interface or loopback" spelling lands on
    /// the canonical loopback addresses.
    #[test]
    fn coerce_to_loopback_rewrite_table() {
        for v4 in ["", "0.0.0.0", "127.0.0.1", "localhost"] {
            let addr = coerce_to_loopback(v4, 22).expect("ipv4-ish should rewrite");
            assert_eq!(
                addr,
                SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 22),
                "spelling {v4:?} should rewrite to 127.0.0.1",
            );
        }
        for v6 in ["::", "::1"] {
            let addr = coerce_to_loopback(v6, 22).expect("ipv6-ish should rewrite");
            assert_eq!(
                addr,
                SocketAddr::new(IpAddr::V6(std::net::Ipv6Addr::LOCALHOST), 22),
                "spelling {v6:?} should rewrite to ::1",
            );
        }
        // A literal non-loopback IP under permit_localhost_only is a
        // policy violation, not a silent widen.
        assert!(coerce_to_loopback("192.0.2.1", 22).is_err());
        assert!(coerce_to_loopback("bogus", 22).is_err());
    }

    /// `permit_localhost_only` refuses a literal non-loopback IP request
    /// (no silent widening; the client meant a specific public IP, we
    /// don't have one to give them under this policy).
    #[test]
    fn permit_localhost_only_refuses_non_loopback_literal() {
        let h = DefaultTcpipForwardHandler::permit_localhost_only();
        assert!(
            h.bind("u", "192.0.2.1", 0, ForwardContext::for_test_no_opens(),)
                .is_err()
        );
    }
}
