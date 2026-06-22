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

pub mod client;

pub use client::{ClientDriver, VerifierFactory};

use alloc::vec::Vec;

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
