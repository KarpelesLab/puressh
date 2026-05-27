//! Connection protocol — RFC 4254.
//!
//! This module is sans-I/O: every function either *produces* the bytes of a
//! payload (the part of an SSH packet after framing and encryption) or
//! *consumes* such bytes. The transport layer is responsible for wrapping and
//! unwrapping these payloads as binary packets.
//!
//! The top-level type is [`ConnectionState`], a channel multiplexer that tracks
//! all open channels for one peer and turns wire-level events into structured
//! [`ChannelEvent`]s.
//!
//! Channel kinds:
//!
//! - `"session"`            — interactive shell, exec, subsystem.
//! - `"direct-tcpip"`       — outbound TCP tunnels (RFC 4254 §7.2).
//! - `"forwarded-tcpip"`    — inbound TCP tunnels delivered by the server.
//!
//! Flow control follows RFC 4254 §5.2: each peer advertises a window the
//! other may fill with `CHANNEL_DATA` / `CHANNEL_EXTENDED_DATA`; the window
//! is replenished with `CHANNEL_WINDOW_ADJUST`. Individual data payloads are
//! also capped by `maximum_packet_size`.

#![cfg(feature = "alloc")]

mod global;
mod msg;
mod request;
mod state;

#[cfg(test)]
mod tests;

pub use msg::{
    MSG_CHANNEL_CLOSE, MSG_CHANNEL_DATA, MSG_CHANNEL_EOF, MSG_CHANNEL_EXTENDED_DATA,
    MSG_CHANNEL_FAILURE, MSG_CHANNEL_OPEN, MSG_CHANNEL_OPEN_CONFIRMATION, MSG_CHANNEL_OPEN_FAILURE,
    MSG_CHANNEL_REQUEST, MSG_CHANNEL_SUCCESS, MSG_CHANNEL_WINDOW_ADJUST, MSG_GLOBAL_REQUEST,
    MSG_REQUEST_FAILURE, MSG_REQUEST_SUCCESS, SSH_EXTENDED_DATA_STDERR,
    SSH_OPEN_ADMINISTRATIVELY_PROHIBITED, SSH_OPEN_CONNECT_FAILED, SSH_OPEN_RESOURCE_SHORTAGE,
    SSH_OPEN_UNKNOWN_CHANNEL_TYPE,
};

pub use global::GlobalRequest;
pub use request::ChannelRequest;
pub use state::{ChannelEvent, ChannelOpen, ChannelState, ConnectionState};

/// Default initial window advertised for new local channels (256 KiB).
pub const DEFAULT_WINDOW: u32 = 256 * 1024;

/// Default maximum SSH packet payload we're willing to receive (32 KiB).
pub const DEFAULT_MAX_PACKET: u32 = 32 * 1024;
