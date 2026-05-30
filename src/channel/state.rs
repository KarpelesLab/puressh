//! Channel multiplexer state machine.

use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use crate::error::{Error, Result};
use crate::format::{Reader, Writer};

use super::global::GlobalRequest;
use super::msg::*;
use super::request::ChannelRequest;
use super::{DEFAULT_MAX_PACKET, DEFAULT_WINDOW};

/// Default ceiling on simultaneously-tracked channels per connection.
///
/// The peer can open and tear down channels freely, but at any instant we
/// will not accept a new `SSH_MSG_CHANNEL_OPEN` once the live count reaches
/// this value — the dispatcher returns an `SSH_MSG_CHANNEL_OPEN_FAILURE`
/// payload with reason `SSH_OPEN_RESOURCE_SHORTAGE` (RFC 4254 §5.1) for the
/// caller to ship, and the offending channel is never inserted into the
/// per-connection map. Mirrors the OpenSSH ballpark of
/// `MaxSessions * fanout`.
pub const DEFAULT_MAX_CHANNELS_PER_CONNECTION: u32 = 256;

/// One channel's bookkeeping.
#[derive(Debug, Clone)]
pub struct ChannelState {
    /// Our channel id; the peer addresses us by this.
    pub local_id: u32,
    /// Peer's channel id; we address them by this.
    pub remote_id: u32,
    /// Bytes the peer may still send us.
    pub local_window: u32,
    /// Bytes we may still send to the peer.
    pub remote_window: u32,
    /// Max packet payload we accept from the peer.
    pub local_max_packet: u32,
    /// Max packet payload the peer accepts from us.
    pub remote_max_packet: u32,
    /// Channel type as advertised in `SSH_MSG_CHANNEL_OPEN`.
    pub kind: String,
    /// `CHANNEL_EOF` already sent locally.
    pub local_eof: bool,
    /// `CHANNEL_EOF` received from the peer.
    pub remote_eof: bool,
    /// `CHANNEL_CLOSE` already sent locally.
    pub local_closed: bool,
    /// `CHANNEL_CLOSE` received from the peer.
    pub remote_closed: bool,

    initial_local_window: u32,
    pending_replenish: u32,
    open_confirmed: bool,
    /// True iff we sent `CHANNEL_OPEN` (vs. a peer-initiated open we
    /// allocated via `on_channel_open`).
    ///
    /// Defence-in-depth against a peer attempting to "force-confirm" an
    /// inbound channel-open by sending us `OPEN_CONFIRMATION` for the local
    /// id we minted to track its `CHANNEL_OPEN`. Only channels we initiated
    /// may transition open via inbound `OPEN_CONFIRMATION`.
    initiated_by_us: bool,
}

impl ChannelState {
    /// True once both sides have sent `CHANNEL_CLOSE`. The id may be reused.
    pub fn is_fully_closed(&self) -> bool {
        self.local_closed && self.remote_closed
    }

    /// True once the peer accepted (or we accepted) the open.
    pub fn is_open(&self) -> bool {
        self.open_confirmed && !self.local_closed && !self.remote_closed
    }
}

/// Channel-open kinds: the type-specific tail of `CHANNEL_OPEN` (RFC 4254 §5.1, §7.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChannelOpen {
    /// `"session"` — RFC 4254 §6.1.
    Session,
    /// `"direct-tcpip"` — client asks server to open a TCP connection (RFC 4254 §7.2).
    DirectTcpip {
        /// Final destination hostname/IP.
        dest_host: String,
        /// Final destination TCP port.
        dest_port: u32,
        /// Originator's IP address.
        orig_host: String,
        /// Originator's TCP port.
        orig_port: u32,
    },
    /// `"forwarded-tcpip"` — server delivers an incoming forwarded connection.
    ForwardedTcpip {
        /// Address that was being listened on.
        dest_host: String,
        /// Port that was being listened on.
        dest_port: u32,
        /// Originator's IP address.
        orig_host: String,
        /// Originator's TCP port.
        orig_port: u32,
    },
    /// `"auth-agent@openssh.com"` — server-initiated channel that proxies a
    /// connection on the per-session forwarded agent socket back to the
    /// client's local `$SSH_AUTH_SOCK`. RFC pseudo-extension as deployed by
    /// OpenSSH; the open carries no type-specific payload.
    AuthAgent,
    /// `"x11"` — server-initiated channel that proxies a connection on the
    /// per-session forwarded X11 display back to the client's local
    /// `$DISPLAY`. RFC 4254 §6.3.2.
    X11 {
        /// Originator's IP address as reported by the X server side.
        orig_host: String,
        /// Originator's TCP port.
        orig_port: u32,
    },
    /// Unknown / not-yet-supported channel type, raw type-specific bytes preserved.
    Other {
        /// Channel-type name.
        kind: String,
        /// Type-specific body verbatim.
        raw: Vec<u8>,
    },
}

impl ChannelOpen {
    /// The `channel_type` field value.
    pub fn kind(&self) -> &str {
        match self {
            ChannelOpen::Session => "session",
            ChannelOpen::DirectTcpip { .. } => "direct-tcpip",
            ChannelOpen::ForwardedTcpip { .. } => "forwarded-tcpip",
            ChannelOpen::AuthAgent => "auth-agent@openssh.com",
            ChannelOpen::X11 { .. } => "x11",
            ChannelOpen::Other { kind, .. } => kind.as_str(),
        }
    }

    fn encode_tail(&self, w: &mut Writer) {
        match self {
            ChannelOpen::Session => {}
            ChannelOpen::DirectTcpip {
                dest_host,
                dest_port,
                orig_host,
                orig_port,
            }
            | ChannelOpen::ForwardedTcpip {
                dest_host,
                dest_port,
                orig_host,
                orig_port,
            } => {
                w.write_string(dest_host.as_bytes());
                w.write_u32(*dest_port);
                w.write_string(orig_host.as_bytes());
                w.write_u32(*orig_port);
            }
            ChannelOpen::AuthAgent => {}
            ChannelOpen::X11 {
                orig_host,
                orig_port,
            } => {
                w.write_string(orig_host.as_bytes());
                w.write_u32(*orig_port);
            }
            ChannelOpen::Other { raw, .. } => {
                w.write_raw(raw);
            }
        }
    }

    fn decode(kind: &str, body: &[u8]) -> Result<Self> {
        let mut r = Reader::new(body);
        match kind {
            "session" => Ok(ChannelOpen::Session),
            "direct-tcpip" => {
                let dest_host = read_utf8(&mut r)?;
                let dest_port = r.read_u32()?;
                let orig_host = read_utf8(&mut r)?;
                let orig_port = r.read_u32()?;
                Ok(ChannelOpen::DirectTcpip {
                    dest_host,
                    dest_port,
                    orig_host,
                    orig_port,
                })
            }
            "forwarded-tcpip" => {
                let dest_host = read_utf8(&mut r)?;
                let dest_port = r.read_u32()?;
                let orig_host = read_utf8(&mut r)?;
                let orig_port = r.read_u32()?;
                Ok(ChannelOpen::ForwardedTcpip {
                    dest_host,
                    dest_port,
                    orig_host,
                    orig_port,
                })
            }
            "auth-agent@openssh.com" => Ok(ChannelOpen::AuthAgent),
            "x11" => {
                let orig_host = read_utf8(&mut r)?;
                let orig_port = r.read_u32()?;
                Ok(ChannelOpen::X11 {
                    orig_host,
                    orig_port,
                })
            }
            other => Ok(ChannelOpen::Other {
                kind: other.to_string(),
                raw: body.to_vec(),
            }),
        }
    }
}

/// A decoded inbound event, surfaced by [`ConnectionState::on_packet`].
#[derive(Debug, Clone)]
pub enum ChannelEvent {
    /// `SSH_MSG_CHANNEL_OPEN` from the peer.
    OpenRequest {
        /// Local id we allocated to track this channel.
        channel: u32,
        /// The channel-type-specific body.
        kind: ChannelOpen,
    },
    /// `SSH_MSG_CHANNEL_OPEN_CONFIRMATION` for a channel we opened.
    OpenConfirmed {
        /// Local id.
        channel: u32,
    },
    /// `SSH_MSG_CHANNEL_OPEN_FAILURE` for a channel we opened.
    OpenFailed {
        /// Local id (now released).
        channel: u32,
        /// `reason_code`.
        reason: u32,
        /// `description` field.
        description: String,
    },
    /// We refused a peer-initiated `SSH_MSG_CHANNEL_OPEN` before allocating
    /// any local state for it (e.g. because [`ConnectionState::max_channels`]
    /// was already reached). The wire `SSH_MSG_CHANNEL_OPEN_FAILURE` payload
    /// the caller must forward is in [`payload`]; no [`ChannelState`] was
    /// inserted, so there is nothing else to clean up.
    ///
    /// [`payload`]: Self::OpenRejected::payload
    OpenRejected {
        /// Pre-built `SSH_MSG_CHANNEL_OPEN_FAILURE` bytes to ship to the peer.
        payload: Vec<u8>,
        /// `reason_code` we put in the payload (e.g.
        /// [`SSH_OPEN_RESOURCE_SHORTAGE`]).
        reason: u32,
    },
    /// `SSH_MSG_CHANNEL_DATA`.
    Data {
        /// Local id.
        channel: u32,
        /// The data bytes.
        data: Vec<u8>,
    },
    /// `SSH_MSG_CHANNEL_EXTENDED_DATA`.
    ExtendedData {
        /// Local id.
        channel: u32,
        /// Extended-data type code (e.g. `1` for stderr).
        code: u32,
        /// The data bytes.
        data: Vec<u8>,
    },
    /// `SSH_MSG_CHANNEL_WINDOW_ADJUST`.
    WindowAdjust {
        /// Local id.
        channel: u32,
        /// Bytes the peer just credited to our send window.
        added: u32,
    },
    /// `SSH_MSG_CHANNEL_EOF`.
    Eof {
        /// Local id.
        channel: u32,
    },
    /// `SSH_MSG_CHANNEL_CLOSE`.
    Close {
        /// Local id.
        channel: u32,
    },
    /// `SSH_MSG_CHANNEL_REQUEST`.
    Request {
        /// Local id.
        channel: u32,
        /// Decoded request body.
        request: ChannelRequest,
        /// Whether the peer wants a reply.
        want_reply: bool,
    },
    /// `SSH_MSG_CHANNEL_SUCCESS` to a request we sent with `want_reply = true`.
    Success {
        /// Local id.
        channel: u32,
    },
    /// `SSH_MSG_CHANNEL_FAILURE` to a request we sent with `want_reply = true`.
    Failure {
        /// Local id.
        channel: u32,
    },
    /// `SSH_MSG_GLOBAL_REQUEST` from the peer.
    GlobalRequest {
        /// Decoded request body.
        request: GlobalRequest,
        /// Whether the peer wants a reply.
        want_reply: bool,
    },
    /// `SSH_MSG_REQUEST_SUCCESS` to a global request we sent.
    GlobalSuccess {
        /// Any request-specific tail bytes.
        data: Vec<u8>,
    },
    /// `SSH_MSG_REQUEST_FAILURE` to a global request we sent.
    GlobalFailure,
}

/// Channel multiplexer for one peer.
#[derive(Debug, Clone)]
pub struct ConnectionState {
    channels: BTreeMap<u32, ChannelState>,
    next_local_id: u32,
    /// Initial window we advertise for new local channels.
    pub default_window: u32,
    /// Max packet size we advertise for new local channels.
    pub default_max_packet: u32,
    /// Per-connection cap on simultaneously-tracked channels. Inbound
    /// `SSH_MSG_CHANNEL_OPEN` once `channels.len() >= max_channels as usize`
    /// is refused with reason `SSH_OPEN_RESOURCE_SHORTAGE` (RFC 4254 §5.1)
    /// instead of being allocated. Defaults to
    /// [`DEFAULT_MAX_CHANNELS_PER_CONNECTION`]. Outbound opens initiated by
    /// `open()` are not throttled here — they are bounded by the caller's
    /// own willingness to wait for confirmation.
    pub max_channels: u32,
}

impl Default for ConnectionState {
    fn default() -> Self {
        Self::new()
    }
}

impl ConnectionState {
    /// Build an empty connection state with reasonable defaults.
    pub fn new() -> Self {
        Self {
            channels: BTreeMap::new(),
            next_local_id: 0,
            default_window: DEFAULT_WINDOW,
            default_max_packet: DEFAULT_MAX_PACKET,
            max_channels: DEFAULT_MAX_CHANNELS_PER_CONNECTION,
        }
    }

    /// Look up a channel by local id.
    pub fn channel(&self, id: u32) -> Option<&ChannelState> {
        self.channels.get(&id)
    }

    /// Iterate over all currently tracked channels.
    pub fn channels(&self) -> impl Iterator<Item = &ChannelState> {
        self.channels.values()
    }

    fn allocate_local_id(&mut self) -> u32 {
        loop {
            let id = self.next_local_id;
            self.next_local_id = self.next_local_id.wrapping_add(1);
            if !self.channels.contains_key(&id) {
                return id;
            }
        }
    }

    fn get_mut(&mut self, id: u32) -> Result<&mut ChannelState> {
        self.channels.get_mut(&id).ok_or(Error::BadChannelState)
    }

    fn ensure_sendable(ch: &ChannelState) -> Result<()> {
        if ch.local_closed || ch.remote_closed {
            return Err(Error::BadChannelState);
        }
        Ok(())
    }

    /// Open a new outgoing channel.
    ///
    /// Returns `(local_id, payload)` where `payload` is the bytes of the
    /// `SSH_MSG_CHANNEL_OPEN` to hand off to the transport. The channel is
    /// tracked but not yet `open`; the peer must reply with
    /// `OPEN_CONFIRMATION` (turning it into [`ChannelEvent::OpenConfirmed`])
    /// or `OPEN_FAILURE` (turning it into [`ChannelEvent::OpenFailed`] and
    /// dropping the entry).
    pub fn open(&mut self, kind: ChannelOpen) -> Result<(u32, Vec<u8>)> {
        let local_id = self.allocate_local_id();
        let local_window = self.default_window;
        let local_max_packet = self.default_max_packet;

        let state = ChannelState {
            local_id,
            remote_id: 0,
            local_window,
            remote_window: 0,
            local_max_packet,
            remote_max_packet: 0,
            kind: kind.kind().to_string(),
            local_eof: false,
            remote_eof: false,
            local_closed: false,
            remote_closed: false,
            initial_local_window: local_window,
            pending_replenish: 0,
            open_confirmed: false,
            initiated_by_us: true,
        };
        self.channels.insert(local_id, state);

        let mut w = Writer::new();
        w.write_u8(MSG_CHANNEL_OPEN);
        w.write_string(kind.kind().as_bytes());
        w.write_u32(local_id);
        w.write_u32(local_window);
        w.write_u32(local_max_packet);
        kind.encode_tail(&mut w);
        Ok((local_id, w.into_vec()))
    }

    /// Build an `OPEN_CONFIRMATION` payload accepting a peer-initiated open.
    ///
    /// `local_id` must reference a channel currently in the `OpenRequest`
    /// state (i.e. created by [`Self::on_packet`] but not yet confirmed).
    pub fn accept_open(&mut self, local_id: u32) -> Result<Vec<u8>> {
        let ch = self.get_mut(local_id)?;
        if ch.open_confirmed {
            return Err(Error::BadChannelState);
        }
        ch.open_confirmed = true;
        let remote_id = ch.remote_id;
        let local_window = ch.local_window;
        let local_max_packet = ch.local_max_packet;

        let mut w = Writer::new();
        w.write_u8(MSG_CHANNEL_OPEN_CONFIRMATION);
        w.write_u32(remote_id);
        w.write_u32(local_id);
        w.write_u32(local_window);
        w.write_u32(local_max_packet);
        Ok(w.into_vec())
    }

    /// Build an `OPEN_FAILURE` payload rejecting a peer-initiated open.
    ///
    /// The local-side bookkeeping for the channel is dropped.
    pub fn reject_open(
        &mut self,
        local_id: u32,
        reason: u32,
        description: &str,
        language: &str,
    ) -> Result<Vec<u8>> {
        let ch = self
            .channels
            .remove(&local_id)
            .ok_or(Error::BadChannelState)?;
        if ch.open_confirmed {
            self.channels.insert(local_id, ch);
            return Err(Error::BadChannelState);
        }
        let remote_id = ch.remote_id;

        let mut w = Writer::new();
        w.write_u8(MSG_CHANNEL_OPEN_FAILURE);
        w.write_u32(remote_id);
        w.write_u32(reason);
        w.write_string(description.as_bytes());
        w.write_string(language.as_bytes());
        Ok(w.into_vec())
    }

    /// Build a `CHANNEL_REQUEST` payload.
    pub fn send_request(
        &mut self,
        channel: u32,
        req: ChannelRequest,
        want_reply: bool,
    ) -> Result<Vec<u8>> {
        let ch = self.get_mut(channel)?;
        Self::ensure_sendable(ch)?;
        let remote_id = ch.remote_id;

        let mut w = Writer::new();
        w.write_u8(MSG_CHANNEL_REQUEST);
        w.write_u32(remote_id);
        w.write_string(req.name().as_bytes());
        w.write_bool(want_reply);
        req.encode(&mut w);
        Ok(w.into_vec())
    }

    /// Build a `CHANNEL_SUCCESS` reply.
    pub fn send_request_success(&mut self, channel: u32) -> Result<Vec<u8>> {
        let ch = self.get_mut(channel)?;
        let remote_id = ch.remote_id;
        let mut w = Writer::new();
        w.write_u8(MSG_CHANNEL_SUCCESS);
        w.write_u32(remote_id);
        Ok(w.into_vec())
    }

    /// Build a `CHANNEL_FAILURE` reply.
    pub fn send_request_failure(&mut self, channel: u32) -> Result<Vec<u8>> {
        let ch = self.get_mut(channel)?;
        let remote_id = ch.remote_id;
        let mut w = Writer::new();
        w.write_u8(MSG_CHANNEL_FAILURE);
        w.write_u32(remote_id);
        Ok(w.into_vec())
    }

    /// Send up to `data.len()` bytes via `CHANNEL_DATA`, capped by both the
    /// peer's advertised window and its `maximum_packet_size`. Returns the
    /// payload to transmit plus the number of `data` bytes actually included.
    /// A return of `0` bytes means the peer's window is exhausted; the caller
    /// must wait for a `WindowAdjust` event before retrying.
    pub fn send_data(&mut self, channel: u32, data: &[u8]) -> Result<(Vec<u8>, usize)> {
        let ch = self.get_mut(channel)?;
        Self::ensure_sendable(ch)?;
        if ch.local_eof {
            return Err(Error::BadChannelState);
        }
        let remote_id = ch.remote_id;
        let cap = data_capacity(ch);
        let take = data.len().min(cap);
        let chunk = &data[..take];

        let mut w = Writer::new();
        w.write_u8(MSG_CHANNEL_DATA);
        w.write_u32(remote_id);
        w.write_string(chunk);

        ch.remote_window = ch.remote_window.saturating_sub(take as u32);
        Ok((w.into_vec(), take))
    }

    /// Same as [`Self::send_data`] for `CHANNEL_EXTENDED_DATA`.
    pub fn send_extended_data(
        &mut self,
        channel: u32,
        code: u32,
        data: &[u8],
    ) -> Result<(Vec<u8>, usize)> {
        let ch = self.get_mut(channel)?;
        Self::ensure_sendable(ch)?;
        if ch.local_eof {
            return Err(Error::BadChannelState);
        }
        let remote_id = ch.remote_id;
        let cap = extended_data_capacity(ch);
        let take = data.len().min(cap);
        let chunk = &data[..take];

        let mut w = Writer::new();
        w.write_u8(MSG_CHANNEL_EXTENDED_DATA);
        w.write_u32(remote_id);
        w.write_u32(code);
        w.write_string(chunk);

        ch.remote_window = ch.remote_window.saturating_sub(take as u32);
        Ok((w.into_vec(), take))
    }

    /// Build a `CHANNEL_EOF` payload.
    pub fn send_eof(&mut self, channel: u32) -> Result<Vec<u8>> {
        let ch = self.get_mut(channel)?;
        if ch.local_closed {
            return Err(Error::BadChannelState);
        }
        ch.local_eof = true;
        let remote_id = ch.remote_id;
        let mut w = Writer::new();
        w.write_u8(MSG_CHANNEL_EOF);
        w.write_u32(remote_id);
        Ok(w.into_vec())
    }

    /// Build a `CHANNEL_CLOSE` payload. If both sides have now sent CLOSE the
    /// channel entry is dropped and its id may be reused.
    pub fn send_close(&mut self, channel: u32) -> Result<Vec<u8>> {
        let ch = self.get_mut(channel)?;
        if ch.local_closed {
            return Err(Error::BadChannelState);
        }
        ch.local_closed = true;
        let remote_id = ch.remote_id;
        let fully_closed = ch.is_fully_closed();
        let mut w = Writer::new();
        w.write_u8(MSG_CHANNEL_CLOSE);
        w.write_u32(remote_id);
        if fully_closed {
            self.channels.remove(&channel);
        }
        Ok(w.into_vec())
    }

    /// Build a `GLOBAL_REQUEST` payload.
    pub fn send_global_request(&self, req: GlobalRequest, want_reply: bool) -> Vec<u8> {
        let mut w = Writer::new();
        w.write_u8(MSG_GLOBAL_REQUEST);
        w.write_string(req.name().as_bytes());
        w.write_bool(want_reply);
        req.encode(&mut w);
        w.into_vec()
    }

    /// Build a `REQUEST_SUCCESS` payload, optionally with a request-specific tail.
    pub fn send_global_success(&self, data: &[u8]) -> Vec<u8> {
        let mut w = Writer::new();
        w.write_u8(MSG_REQUEST_SUCCESS);
        w.write_raw(data);
        w.into_vec()
    }

    /// Build a `REQUEST_FAILURE` payload (no body).
    pub fn send_global_failure(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.write_u8(MSG_REQUEST_FAILURE);
        w.into_vec()
    }

    /// Credit `by` bytes back to the peer's send window after the caller has
    /// consumed that many inbound payload bytes. The bytes are accumulated
    /// against an internal counter; once the counter crosses half the channel's
    /// initial window we flush a `CHANNEL_WINDOW_ADJUST` payload and reset.
    /// Returns the payload to send, or `None` if the threshold wasn't reached.
    pub fn replenish_window(&mut self, channel: u32, by: u32) -> Result<Option<Vec<u8>>> {
        let ch = self.get_mut(channel)?;
        if ch.local_closed {
            return Err(Error::BadChannelState);
        }
        if by == 0 {
            return Ok(None);
        }
        ch.pending_replenish = ch.pending_replenish.saturating_add(by);
        let threshold = (ch.initial_local_window / 2).max(1);
        if ch.pending_replenish < threshold {
            return Ok(None);
        }
        let added = ch.pending_replenish;
        ch.pending_replenish = 0;
        ch.local_window = ch.local_window.saturating_add(added);
        let remote_id = ch.remote_id;
        let mut w = Writer::new();
        w.write_u8(MSG_CHANNEL_WINDOW_ADJUST);
        w.write_u32(remote_id);
        w.write_u32(added);
        Ok(Some(w.into_vec()))
    }

    /// Parse one inbound payload (first byte = message type) and update internal
    /// state, returning the structured event.
    pub fn on_packet(&mut self, payload: &[u8]) -> Result<ChannelEvent> {
        let mut r = Reader::new(payload);
        let msg = r.read_u8()?;
        match msg {
            MSG_GLOBAL_REQUEST => self.on_global_request(&mut r),
            MSG_REQUEST_SUCCESS => {
                let n = r.remaining();
                let data = r.take(n)?.to_vec();
                Ok(ChannelEvent::GlobalSuccess { data })
            }
            MSG_REQUEST_FAILURE => Ok(ChannelEvent::GlobalFailure),
            MSG_CHANNEL_OPEN => self.on_channel_open(&mut r),
            MSG_CHANNEL_OPEN_CONFIRMATION => self.on_open_confirmation(&mut r),
            MSG_CHANNEL_OPEN_FAILURE => self.on_open_failure(&mut r),
            MSG_CHANNEL_WINDOW_ADJUST => self.on_window_adjust(&mut r),
            MSG_CHANNEL_DATA => self.on_channel_data(&mut r),
            MSG_CHANNEL_EXTENDED_DATA => self.on_extended_data(&mut r),
            MSG_CHANNEL_EOF => self.on_channel_eof(&mut r),
            MSG_CHANNEL_CLOSE => self.on_channel_close(&mut r),
            MSG_CHANNEL_REQUEST => self.on_channel_request(&mut r),
            MSG_CHANNEL_SUCCESS => self.on_channel_success(&mut r),
            MSG_CHANNEL_FAILURE => self.on_channel_failure(&mut r),
            _ => Err(Error::Protocol("unexpected message for channel layer")),
        }
    }

    fn on_global_request(&mut self, r: &mut Reader<'_>) -> Result<ChannelEvent> {
        let name = read_utf8_borrowed(r)?;
        let want_reply = r.read_bool()?;
        let n = r.remaining();
        let tail = r.take(n)?;
        let request = GlobalRequest::decode(name, tail)?;
        Ok(ChannelEvent::GlobalRequest {
            request,
            want_reply,
        })
    }

    fn on_channel_open(&mut self, r: &mut Reader<'_>) -> Result<ChannelEvent> {
        let kind_name = read_utf8_borrowed(r)?.to_string();
        let remote_id = r.read_u32()?;
        let initial_window = r.read_u32()?;
        let max_packet = r.read_u32()?;
        let n = r.remaining();
        let tail = r.take(n)?;
        let kind = ChannelOpen::decode(&kind_name, tail)?;

        // RFC 4254 §5.1 resource-shortage cap. Refuse before allocating any
        // state so a flood of opens can never grow the per-connection map
        // past `max_channels`; the peer is expected to back off after the
        // failure reply, not tear down the whole transport.
        if self.channels.len() >= self.max_channels as usize {
            let mut w = Writer::new();
            w.write_u8(MSG_CHANNEL_OPEN_FAILURE);
            w.write_u32(remote_id);
            w.write_u32(SSH_OPEN_RESOURCE_SHORTAGE);
            w.write_string(b"channel limit reached");
            w.write_string(b"");
            return Ok(ChannelEvent::OpenRejected {
                payload: w.into_vec(),
                reason: SSH_OPEN_RESOURCE_SHORTAGE,
            });
        }

        let local_id = self.allocate_local_id();
        let local_window = self.default_window;
        let local_max_packet = self.default_max_packet;

        let state = ChannelState {
            local_id,
            remote_id,
            local_window,
            remote_window: initial_window,
            local_max_packet,
            remote_max_packet: max_packet,
            kind: kind_name,
            local_eof: false,
            remote_eof: false,
            local_closed: false,
            remote_closed: false,
            initial_local_window: local_window,
            pending_replenish: 0,
            open_confirmed: false,
            initiated_by_us: false,
        };
        self.channels.insert(local_id, state);
        Ok(ChannelEvent::OpenRequest {
            channel: local_id,
            kind,
        })
    }

    fn on_open_confirmation(&mut self, r: &mut Reader<'_>) -> Result<ChannelEvent> {
        let local_id = r.read_u32()?;
        let remote_id = r.read_u32()?;
        let initial_window = r.read_u32()?;
        let max_packet = r.read_u32()?;
        let ch = self
            .channels
            .get_mut(&local_id)
            .ok_or(Error::Protocol("open-confirm for unknown channel"))?;
        if ch.open_confirmed {
            return Err(Error::Protocol("double open-confirm"));
        }
        // A peer may not confirm a channel we never asked them to open.
        // Inbound peer-initiated channels are confirmed locally via
        // `accept_open`; OPEN_CONFIRMATION on the wire is only legal for
        // channels for which we previously sent `CHANNEL_OPEN`.
        if !ch.initiated_by_us {
            return Err(Error::Protocol(
                "open-confirm for channel not initiated by us",
            ));
        }
        ch.remote_id = remote_id;
        ch.remote_window = initial_window;
        ch.remote_max_packet = max_packet;
        ch.open_confirmed = true;
        Ok(ChannelEvent::OpenConfirmed { channel: local_id })
    }

    fn on_open_failure(&mut self, r: &mut Reader<'_>) -> Result<ChannelEvent> {
        let local_id = r.read_u32()?;
        let reason = r.read_u32()?;
        let description_bytes = r.read_string()?;
        let description = core::str::from_utf8(description_bytes)
            .map_err(|_| Error::Format("invalid utf-8 in open-failure description"))?
            .to_string();
        let _lang = r.read_string()?;
        self.channels
            .remove(&local_id)
            .ok_or(Error::Protocol("open-failure for unknown channel"))?;
        Ok(ChannelEvent::OpenFailed {
            channel: local_id,
            reason,
            description,
        })
    }

    fn on_window_adjust(&mut self, r: &mut Reader<'_>) -> Result<ChannelEvent> {
        let local_id = r.read_u32()?;
        let added = r.read_u32()?;
        let ch = self.get_mut(local_id)?;
        ch.remote_window = ch.remote_window.saturating_add(added);
        Ok(ChannelEvent::WindowAdjust {
            channel: local_id,
            added,
        })
    }

    fn on_channel_data(&mut self, r: &mut Reader<'_>) -> Result<ChannelEvent> {
        let local_id = r.read_u32()?;
        let data = r.read_string()?.to_vec();
        let ch = self.get_mut(local_id)?;
        if !ch.open_confirmed {
            return Err(Error::Protocol("channel not yet open"));
        }
        if ch.remote_eof || ch.remote_closed {
            return Err(Error::Protocol("data after EOF/close"));
        }
        let len = data.len() as u32;
        if len > ch.local_window {
            return Err(Error::Protocol("peer exceeded advertised window"));
        }
        if len > ch.local_max_packet {
            return Err(Error::Protocol("peer exceeded max packet"));
        }
        ch.local_window -= len;
        Ok(ChannelEvent::Data {
            channel: local_id,
            data,
        })
    }

    fn on_extended_data(&mut self, r: &mut Reader<'_>) -> Result<ChannelEvent> {
        let local_id = r.read_u32()?;
        let code = r.read_u32()?;
        let data = r.read_string()?.to_vec();
        let ch = self.get_mut(local_id)?;
        if !ch.open_confirmed {
            return Err(Error::Protocol("channel not yet open"));
        }
        if ch.remote_eof || ch.remote_closed {
            return Err(Error::Protocol("extended data after EOF/close"));
        }
        let len = data.len() as u32;
        if len > ch.local_window {
            return Err(Error::Protocol("peer exceeded advertised window"));
        }
        if len > ch.local_max_packet {
            return Err(Error::Protocol("peer exceeded max packet"));
        }
        ch.local_window -= len;
        Ok(ChannelEvent::ExtendedData {
            channel: local_id,
            code,
            data,
        })
    }

    fn on_channel_eof(&mut self, r: &mut Reader<'_>) -> Result<ChannelEvent> {
        let local_id = r.read_u32()?;
        let ch = self.get_mut(local_id)?;
        if !ch.open_confirmed {
            return Err(Error::Protocol("channel not yet open"));
        }
        ch.remote_eof = true;
        Ok(ChannelEvent::Eof { channel: local_id })
    }

    fn on_channel_close(&mut self, r: &mut Reader<'_>) -> Result<ChannelEvent> {
        let local_id = r.read_u32()?;
        let ch = self.get_mut(local_id)?;
        if !ch.open_confirmed {
            return Err(Error::Protocol("channel not yet open"));
        }
        ch.remote_closed = true;
        let fully_closed = ch.is_fully_closed();
        if fully_closed {
            self.channels.remove(&local_id);
        }
        Ok(ChannelEvent::Close { channel: local_id })
    }

    fn on_channel_request(&mut self, r: &mut Reader<'_>) -> Result<ChannelEvent> {
        let local_id = r.read_u32()?;
        let name = read_utf8_borrowed(r)?.to_string();
        let want_reply = r.read_bool()?;
        let n = r.remaining();
        let tail = r.take(n)?;
        let request = ChannelRequest::decode(&name, tail)?;
        let ch = self.channels.get(&local_id).ok_or(Error::BadChannelState)?;
        if !ch.open_confirmed {
            return Err(Error::Protocol("channel not yet open"));
        }
        Ok(ChannelEvent::Request {
            channel: local_id,
            request,
            want_reply,
        })
    }

    fn on_channel_success(&mut self, r: &mut Reader<'_>) -> Result<ChannelEvent> {
        let local_id = r.read_u32()?;
        if !self.channels.contains_key(&local_id) {
            return Err(Error::BadChannelState);
        }
        Ok(ChannelEvent::Success { channel: local_id })
    }

    fn on_channel_failure(&mut self, r: &mut Reader<'_>) -> Result<ChannelEvent> {
        let local_id = r.read_u32()?;
        if !self.channels.contains_key(&local_id) {
            return Err(Error::BadChannelState);
        }
        Ok(ChannelEvent::Failure { channel: local_id })
    }
}

fn data_capacity(ch: &ChannelState) -> usize {
    if ch.remote_max_packet < 9 {
        return 0;
    }
    let pkt_room = (ch.remote_max_packet - 9) as usize;
    let window = ch.remote_window as usize;
    pkt_room.min(window)
}

fn extended_data_capacity(ch: &ChannelState) -> usize {
    if ch.remote_max_packet < 13 {
        return 0;
    }
    let pkt_room = (ch.remote_max_packet - 13) as usize;
    let window = ch.remote_window as usize;
    pkt_room.min(window)
}

fn read_utf8(r: &mut Reader<'_>) -> Result<String> {
    let bytes = r.read_string()?;
    core::str::from_utf8(bytes)
        .map(|s| s.to_string())
        .map_err(|_| Error::Format("invalid utf-8"))
}

fn read_utf8_borrowed<'a>(r: &mut Reader<'a>) -> Result<&'a str> {
    let bytes = r.read_string()?;
    core::str::from_utf8(bytes).map_err(|_| Error::Format("invalid utf-8"))
}

#[cfg(test)]
mod cap_tests {
    use super::*;

    /// Opening up to `max_channels` peer-initiated channels succeeds; the
    /// (cap+1)th open is refused with `SSH_OPEN_RESOURCE_SHORTAGE` and no
    /// new state is allocated.
    #[test]
    fn peer_open_cap_returns_resource_shortage() {
        let mut server = ConnectionState::new();
        server.max_channels = 3;

        // Drive `cap` peer-initiated session opens through a fresh peer.
        let mut peer = ConnectionState::new();
        for _ in 0..server.max_channels {
            let (_, open_payload) = peer.open(ChannelOpen::Session).unwrap();
            let ev = server.on_packet(&open_payload).unwrap();
            match ev {
                ChannelEvent::OpenRequest { channel, .. } => {
                    let _ = server.accept_open(channel).unwrap();
                }
                other => panic!("expected OpenRequest, got {:?}", other),
            }
        }
        assert_eq!(server.channels().count(), server.max_channels as usize);

        // The next open must be refused; the wire payload is
        // SSH_MSG_CHANNEL_OPEN_FAILURE with reason 4 and we must not have
        // grown the channel map.
        let before = server.channels().count();
        let (_, open_payload) = peer.open(ChannelOpen::Session).unwrap();
        let ev = server.on_packet(&open_payload).unwrap();
        let (payload, reason) = match ev {
            ChannelEvent::OpenRejected { payload, reason } => (payload, reason),
            other => panic!("expected OpenRejected, got {:?}", other),
        };
        assert_eq!(reason, SSH_OPEN_RESOURCE_SHORTAGE);
        assert_eq!(server.channels().count(), before);
        assert_eq!(payload[0], MSG_CHANNEL_OPEN_FAILURE);
        // Bytes 1..5 = recipient (peer's local id we just minted)
        // Bytes 5..9 = reason code
        let reason_on_wire = u32::from_be_bytes(payload[5..9].try_into().unwrap());
        assert_eq!(reason_on_wire, SSH_OPEN_RESOURCE_SHORTAGE);
    }
}
