//! Sans-IO connection drivers.
//!
//! The protocol layers (`format`, `transport`, `channel`, `auth`) are already
//! sans-IO: they operate on byte buffers and never touch sockets. This module
//! lifts the *orchestration* — the state machine that sequences version
//! exchange → key exchange → authentication → application channels, drives
//! re-key/keepalive timers, and accumulates/decodes inbound bytes — out of the
//! blocking [`crate::client::Client`] into a transport-agnostic driver.
//!
//! A driver never reads or writes a socket, never spawns a thread, and never
//! calls `Instant::now()`. The caller (a "frontend") does the I/O and clock:
//!
//! - feed inbound wire bytes with [`ClientDriver::handle_input`];
//! - drain fully-encoded outbound frames with [`ClientDriver::poll_transmit`];
//! - pull high-level [`Event`]s with [`ClientDriver::poll_event`];
//! - advance timers with [`ClientDriver::handle_timeout`] /
//!   [`ClientDriver::next_timeout`].
//!
//! This makes the same core reusable from a blocking frontend (the existing
//! [`crate::client::Client`]) and an async one, with no duplicated protocol
//! logic. See [`client::ClientDriver`] and [`server::ServerDriver`].

#[cfg(feature = "client")]
pub mod client;
#[cfg(feature = "server")]
pub mod server;

#[cfg(feature = "client")]
pub use client::{ClientDriver, VerifierFactory};
#[cfg(feature = "server")]
pub use server::ServerDriver;

use alloc::vec::Vec;

use crate::channel::{GlobalRequest, MSG_GLOBAL_REQUEST};
use crate::format::Writer;

// Transport-routing message bytes and buffer caps shared by both drivers.
/// `SSH_MSG_KEX_ECDH_REPLY` — the KEX message carrying the host key.
pub(crate) const SSH_MSG_KEX_ECDH_REPLY: u8 = 31;
pub(crate) const SSH_MSG_KEXINIT: u8 = 20;
pub(crate) const SSH_MSG_EXT_INFO: u8 = 7;
pub(crate) const MAX_INBOX_BYTES: usize = 8 * 1024 * 1024;
pub(crate) const MAX_BANNER_LINE: usize = 1024;
pub(crate) const MAX_BANNER_LINES: usize = 32;
pub(crate) const MAX_BANNER_TOTAL_BYTES: usize = 64 * 1024;

/// Build a `keepalive@openssh.com` global-request payload (want_reply = true),
/// without a `ConnectionState` (the encoding is stateless).
pub(crate) fn keepalive_request() -> Vec<u8> {
    let req = GlobalRequest::Keepalive;
    let mut w = Writer::new();
    w.write_u8(MSG_GLOBAL_REQUEST);
    w.write_string(req.name().as_bytes());
    w.write_bool(true);
    req.encode(&mut w);
    w.into_vec()
}

/// A high-level event surfaced by a driver's `poll_event`.
///
/// The driver runs the transport engine (version exchange, KEX, re-key,
/// EXT_INFO/PING handling); once the handshake completes it surfaces every
/// decoded transport payload as [`Event::AppData`] for the frontend. The
/// frontend runs userauth (feeding the auth payloads to its own
/// [`ClientAuth`](crate::auth::ClientAuth)) and then the connection protocol
/// (feeding the rest to its own [`ConnectionState`](crate::channel::ConnectionState)).
/// Transport concerns never surface.
#[derive(Debug, Clone)]
pub enum Event {
    /// The transport handshake (version exchange + first key exchange) has
    /// completed; the connection is keyed and ready for authentication.
    HandshakeComplete,
    /// A decoded post-handshake payload (userauth, then the connection
    /// protocol). The frontend routes it to its auth driver or
    /// [`ConnectionState`](crate::channel::ConnectionState) as appropriate.
    AppData(Vec<u8>),
}
