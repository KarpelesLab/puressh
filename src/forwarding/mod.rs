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

#![cfg(feature = "std")]

pub mod agent;
pub mod direct;
pub mod reverse;
