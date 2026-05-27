//! Connection protocol — RFC 4254.
//!
//! Once authenticated, peers open multiplexed channels. Each side maintains
//! its own initial window size (≥ payload it's willing to receive) and
//! maximum packet size, then exchanges `SSH_MSG_CHANNEL_*` messages.
//!
//! Common channel types:
//!
//! - `"session"`            — interactive shell, exec, subsystem
//! - `"direct-tcpip"`       — outbound TCP tunnels (local port forwarding)
//! - `"forwarded-tcpip"`    — inbound TCP tunnels (remote port forwarding)
//! - `"x11"`                — X display forwarding

#[cfg(feature = "alloc")]
use alloc::string::String;

/// Per-side channel state.
#[derive(Debug)]
#[cfg(feature = "alloc")]
pub struct Channel {
    /// Our channel id; the peer addresses us by this.
    pub local_id: u32,
    /// Peer's channel id; we address them by this.
    pub remote_id: u32,
    /// Bytes the peer may still send us before we must advertise more window.
    pub local_window: u32,
    /// Bytes we may still send to the peer.
    pub remote_window: u32,
    /// Maximum SSH packet we're willing to receive.
    pub local_max_packet: u32,
    /// Maximum SSH packet the peer is willing to receive.
    pub remote_max_packet: u32,
    /// Channel type as advertised in `SSH_MSG_CHANNEL_OPEN`.
    pub kind: String,
    /// True once both sides have sent `SSH_MSG_CHANNEL_EOF`.
    pub eof: bool,
    /// True once both sides have sent `SSH_MSG_CHANNEL_CLOSE`.
    pub closed: bool,
}
