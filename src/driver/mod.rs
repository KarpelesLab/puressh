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
//! logic. See [`client::ClientDriver`].

#![cfg(feature = "client")]

mod client;

pub use client::ClientDriver;

use alloc::string::String;

use crate::channel::ChannelEvent;

/// A high-level event surfaced by a driver's `poll_event`.
///
/// Channel- and connection-protocol events are re-surfaced verbatim as
/// [`Event::Channel`] so frontends can reuse the same match arms they used
/// against [`ChannelEvent`]; handshake and authentication milestones get their
/// own variants.
#[derive(Debug, Clone)]
pub enum Event {
    /// The transport handshake (version exchange + first key exchange) has
    /// completed; the connection is keyed and ready for authentication.
    HandshakeComplete,
    /// The server sent a `SSH_MSG_USERAUTH_BANNER` during authentication.
    AuthBanner {
        /// Banner text.
        message: String,
        /// RFC 3066 language tag.
        language: String,
    },
    /// Authentication succeeded; the connection layer is open for channels.
    AuthSuccess,
    /// Authentication exhausted every offered credential.
    AuthFailure,
    /// A connection-protocol event (channel open/data/eof/close, global
    /// request/reply, …) decoded from an application packet.
    Channel(ChannelEvent),
}
