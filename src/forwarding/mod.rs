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
//! - **`forwarded-tcpip`** (RFC 4254 §7.2): the server, having previously
//!   honoured a `tcpip-forward` global request, opens a channel back at
//!   the client for each accepted connection on the bound port. Lands in a
//!   follow-up commit alongside the reverse-forward machinery.

#![cfg(feature = "std")]

pub mod direct;
