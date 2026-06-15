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
#[cfg(feature = "server")]
pub mod reverse;
// SOCKS dynamic-forward (`ssh -D`) is purely client-side and TCP-only, so it
// is gated on the `client` feature and stays portable across platforms.
#[cfg(feature = "client")]
pub mod socks;
#[cfg(unix)]
pub mod x11;
