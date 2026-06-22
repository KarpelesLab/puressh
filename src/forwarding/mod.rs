//! Port-forwarding building blocks used by `puressh::server` (and `client`
//! in a follow-up commit).
//!
//! Two channel types live here:
//!
//! - **`direct-tcpip`** (RFC 4254 §7.2): the client asks the server to
//!   connect to a TCP destination and proxy bytes over the SSH channel.
//!   This is what `ssh -L` opens. The server-side glue is
//!   [`direct::DefaultDirectTcpipHandler`] plus the
//!   [`crate::server::DirectTcpipHandler`] trait.
//! - **`tcpip-forward`** + **`forwarded-tcpip`** (RFC 4254 §7.1, §7.2):
//!   the inbound bookend of `ssh -R`. A client global-request asks the
//!   server to bind a TCP listener; once bound, the server is meant to
//!   open a `forwarded-tcpip` channel back to the client for each
//!   accepted connection on that port. The bind/unbind half lives in
//!   [`reverse::DefaultTcpipForwardHandler`] plus the
//!   [`crate::server::TcpipForwardHandler`] trait; the back-channel
//!   opens land in a follow-up commit alongside the matching
//!   client-side multi-channel dispatcher.
//! - **`auth-agent-req@openssh.com`** + **`auth-agent@openssh.com`**
//!   (OpenSSH's ssh-agent forwarding, `ssh -A`): the client asks the
//!   server to expose a Unix-domain socket inside the session env as
//!   `SSH_AUTH_SOCK`. Each connection on that socket triggers an
//!   `auth-agent@openssh.com` channel-open back toward the client, which
//!   the client proxies to its own local agent. Server-side glue lives
//!   in [`agent::DefaultAgentForwardHandler`] plus the
//!   [`crate::server::AgentForwardHandler`] trait.
//! - **`direct-streamlocal@openssh.com`** (OpenSSH extension): the
//!   Unix-socket analog of `direct-tcpip`. The client asks the server to
//!   connect to a Unix-domain socket and proxy bytes over the SSH channel
//!   (what `ssh -L local:/remote.sock` opens). Server-side glue lives in
//!   [`direct_streamlocal::DefaultDirectStreamlocalHandler`] plus the
//!   [`crate::server::DirectStreamlocalHandler`] trait.
//! - **`streamlocal-forward@openssh.com`** +
//!   **`forwarded-streamlocal@openssh.com`** (OpenSSH extension): the
//!   Unix-socket analog of `tcpip-forward` / `forwarded-tcpip`, the wire side
//!   of `ssh -R /remote.sock:...`. A client global-request asks the server to
//!   bind a Unix-domain listener; each accepted connection triggers a
//!   `forwarded-streamlocal@openssh.com` channel-open back toward the client.
//!   Server-side glue lives in
//!   [`streamlocal::DefaultStreamlocalForwardHandler`] plus the
//!   [`crate::server::StreamlocalForwardHandler`] trait; the client-side
//!   splice helper is [`streamlocal::splice_to_unix_socket_callback`].
//! - **`x11-req`** + **`x11`** (RFC 4254 §6.3, `ssh -X` / `ssh -Y`):
//!   the client asks the server to set up an X display proxy. The
//!   server binds `127.0.0.1:6000+N` for some free display number `N`
//!   and injects `DISPLAY=localhost:N.<screen>` into the session env.
//!   Each accepted TCP connection on that port triggers an `x11`
//!   channel-open back toward the client, which the client proxies to
//!   its own local `$DISPLAY`. Server-side glue lives in
//!   [`x11::DefaultX11ForwardHandler`] plus the
//!   [`crate::server::X11ForwardHandler`] trait.

#![cfg(feature = "std")]

// Agent and X11 forwarding depend on Unix-domain sockets and Unix-only
// permission bits; gate them out on Windows. The other two modules
// (direct-tcpip, reverse port-forward) are TCP-only and stay portable.
//
// `direct` and `reverse` are entirely server-side handlers (no client-
// callable helpers), so they're additionally gated on `feature = "server"`.
// `agent` and `x11` straddle the line: their `Default*Handler` types are
// server-only, but they also expose `splice_to_local_*_callback` helpers the
// client binary uses, so each file uses per-item `#[cfg(feature = "server")]`
// internally rather than a single module-level gate.
#[cfg(unix)]
pub mod agent;
#[cfg(feature = "server")]
pub mod direct;
// direct-streamlocal is a server-side handler over Unix-domain sockets.
#[cfg(all(feature = "server", unix))]
pub mod direct_streamlocal;
#[cfg(feature = "server")]
pub mod reverse;
// streamlocal reverse-forward straddles the line like `agent`/`x11`: the
// `Default*Handler` is server-only, but `splice_to_unix_socket_callback` is a
// client helper, so it uses per-item `#[cfg(feature = "...")]` internally.
#[cfg(unix)]
pub mod streamlocal;
// SOCKS dynamic-forward (`ssh -D`) is purely client-side and TCP-only, so it
// is gated on the `client` feature and stays portable across platforms.
#[cfg(feature = "client")]
pub mod socks;
#[cfg(unix)]
pub mod x11;
