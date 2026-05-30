//! Owned-handle wrapper around [`Client`] that supports **multiple
//! concurrent channel sessions** on a single SSH connection.
//!
//! `Client::sftp`/`exec_stream`/`open_direct_tcpip` each return a stream
//! that mutably borrows the [`Client`], so only one channel can be in
//! flight at a time at the type-system level. That's fine for the
//! command-line tools and the existing single-shot helpers, but the C
//! ABI surface (and any user wrapping the lib in a long-lived service)
//! needs to hold *multiple* SFTP sessions simultaneously over the same
//! underlying transport.
//!
//! [`SharedClient`] wraps the connected [`Client`] in `Arc<Mutex<...>>`
//! and tags each open channel with a per-channel byte queue, so a stream
//! waiting for response data on channel A doesn't lose packets that
//! arrived for channel B. [`OwnedChannelStream`] is the [`Read`]+[`Write`]
//! adapter — it locks the mutex on every `read`/`write`, pumps the wire
//! as needed, dispatches inbound packets to the right queue, and only
//! returns to the caller once *its* channel has bytes.
//!
//! ## Concurrency model
//!
//! Calls serialise on a single mutex. Two threads using two
//! [`SftpSession`]s on the same [`SharedClient`] both make progress, but
//! they take turns at the wire: while thread A is blocked on a TCP read
//! inside `OwnedChannelStream::read`, thread B is blocked on the mutex.
//! When A's `read_one_packet` returns, A either consumes the packet
//! (queue full → returns) or queues it for some other channel and loops.
//! Either way the mutex is eventually released and B gets in.
//!
//! This is correct for the common case (synchronous request/response
//! SFTP), allows arbitrary numbers of independent SFTP handles, and
//! avoids the complexity of a dedicated reader thread. It is **not**
//! suitable for genuinely concurrent reads on different channels with
//! independent flow control — that would need an evented reactor, which
//! is out of scope here.

#![cfg(feature = "std")]

use std::collections::{BTreeMap, VecDeque};
use std::io::{Read, Write};
use std::sync::{Arc, Mutex};

use crate::channel::{ChannelEvent, ChannelOpen, ChannelRequest};
use crate::client::{io_err, Client};
use crate::error::{Error, Result};
use crate::sftp::{SftpClient, SftpError};

/// Local alias for SFTP-flavoured results, since
/// [`crate::error::Result`] only takes one generic parameter (and pins
/// the error to [`crate::error::Error`]).
type SftpResult<T> = core::result::Result<T, SftpError>;

/// Iteration cap on the open / subsystem-request loop inside
/// [`SharedClient::sftp`]. Matches `MAX_EXEC_ITER` in `client.rs`.
const MAX_OPEN_ITER: usize = 1_000_000;

/// Per-channel mailbox kept inside [`Inner`]. Packets that
/// [`OwnedChannelStream::read`] pumps off the wire for some channel
/// other than the one currently being read get queued here so the next
/// reader on that channel finds them.
#[derive(Default)]
struct ChannelQueue {
    /// Inbound data bytes (`SSH_MSG_CHANNEL_DATA`), oldest first.
    data: VecDeque<u8>,
    /// Inbound extended-data bytes (`SSH_MSG_CHANNEL_EXTENDED_DATA`, any
    /// code). SFTP doesn't produce these; exec_stream / scp do.
    stderr: VecDeque<u8>,
    /// The peer has sent EOF for this channel.
    remote_eof: bool,
    /// The peer has sent CLOSE for this channel.
    remote_close: bool,
}

/// Shared state: the underlying [`Client`] and a per-channel mailbox map.
/// All access goes through [`SharedClient`]'s `Arc<Mutex<Inner>>`.
struct Inner {
    client: Client,
    /// Keyed by *local* channel id (the value
    /// [`crate::channel::ConnectionState::open`] returned when the
    /// channel was opened).
    queues: BTreeMap<u32, ChannelQueue>,
}

/// Owned, clonable handle to a connected [`Client`] that supports
/// concurrent channel sessions. Build with `SharedClient::from(client)`.
///
/// Cloning is a cheap `Arc` bump — every clone points at the same
/// underlying connection. All access goes through an internal mutex.
#[derive(Clone)]
pub struct SharedClient {
    inner: Arc<Mutex<Inner>>,
}

impl From<Client> for SharedClient {
    fn from(client: Client) -> Self {
        Self {
            inner: Arc::new(Mutex::new(Inner {
                client,
                queues: BTreeMap::new(),
            })),
        }
    }
}

impl SharedClient {
    /// Open a session channel, request the `sftp` subsystem, perform the
    /// SFTP `INIT`/`VERSION` handshake, and return an owned
    /// [`SftpSession`]. Multiple sessions per `SharedClient` are
    /// supported — each one rides on its own SSH channel.
    pub fn sftp(&self) -> Result<SftpSession> {
        // Open the channel + send Subsystem(sftp). Hold the lock for
        // the whole open flow so a second SharedClient::sftp() racing
        // against us doesn't see a half-built channel.
        let local_id = {
            let mut g = self.inner.lock().expect("SharedClient mutex poisoned");
            let (local_id, open_payload) =
                g.client.conn.open(ChannelOpen::Session).map_err(map_err)?;
            g.client.write_payload(&open_payload).map_err(map_err)?;

            // Drive the wire until our open is confirmed. Any other
            // channels' events get queued.
            let mut opened = false;
            let mut iter_guard = 0usize;
            while !opened {
                iter_guard += 1;
                if iter_guard > MAX_OPEN_ITER {
                    return Err(Error::Protocol("sftp: open loop did not converge"));
                }
                let payload = g.client.read_one_packet().map_err(map_err)?;
                let ev = g.client.conn.on_packet(&payload).map_err(map_err)?;
                match ev {
                    ChannelEvent::OpenConfirmed { channel } if channel == local_id => {
                        opened = true;
                    }
                    ChannelEvent::OpenFailed { channel, .. } if channel == local_id => {
                        return Err(Error::Protocol("sftp: channel open failed"));
                    }
                    other => stash_event(&mut g.queues, other),
                }
            }

            g.client
                .maybe_send_auth_agent_req(local_id)
                .map_err(map_err)?;
            g.client.maybe_send_x11_req(local_id).map_err(map_err)?;

            let sub_req = g
                .client
                .conn
                .send_request(
                    local_id,
                    ChannelRequest::Subsystem {
                        name: "sftp".into(),
                    },
                    true,
                )
                .map_err(map_err)?;
            g.client.write_payload(&sub_req).map_err(map_err)?;

            // Drive the wire until the request is acknowledged. Same
            // event-stash pattern.
            let mut done = false;
            let mut iter_guard = 0usize;
            while !done {
                iter_guard += 1;
                if iter_guard > MAX_OPEN_ITER {
                    return Err(Error::Protocol(
                        "sftp: subsystem-reply loop did not converge",
                    ));
                }
                let payload = g.client.read_one_packet().map_err(map_err)?;
                let ev = g.client.conn.on_packet(&payload).map_err(map_err)?;
                match ev {
                    ChannelEvent::Success { channel } if channel == local_id => {
                        done = true;
                    }
                    ChannelEvent::Failure { channel } if channel == local_id => {
                        return Err(Error::Protocol("sftp: subsystem request denied"));
                    }
                    other => stash_event(&mut g.queues, other),
                }
            }

            g.queues.entry(local_id).or_default();
            local_id
        };

        // Lock dropped: now build the stream and run INIT/VERSION
        // through it. Each transport call re-locks the inner Mutex,
        // which is fine.
        let stream = OwnedChannelStream {
            shared: self.clone(),
            channel: local_id,
            local_close_sent: false,
        };
        match SftpClient::new(stream) {
            Ok(c) => Ok(SftpSession {
                _shared: self.clone(),
                inner: c,
            }),
            Err(e) => {
                // Best-effort tear-down — the stream has been moved into
                // SftpClient and dropped on the error path, so its Drop
                // already attempted to send CHANNEL_CLOSE.
                Err(Error::Protocol(match e {
                    SftpError::Protocol(s) => s,
                    _ => "sftp: handshake failed",
                }))
            }
        }
    }

    /// Lock the inner client for one synchronous operation. Internal helper
    /// for the FFI layer's `pcssh_client_exec` and friends, which run a
    /// single self-contained method on `Client` while holding the mutex.
    ///
    /// This is `pub(crate)` because library users normally don't need it —
    /// they should call methods on [`SharedClient`] or [`SftpSession`].
    /// The C ABI is the asymmetric case where the wrapped `Client` is
    /// where state lives.
    #[allow(dead_code)] // wired up by Phase 2 (FFI client migration)
    pub(crate) fn with_client<R>(&self, f: impl FnOnce(&mut Client) -> R) -> R {
        let mut g = self.inner.lock().expect("SharedClient mutex poisoned");
        f(&mut g.client)
    }
}

/// File the inbound `ChannelEvent` into the appropriate per-channel
/// mailbox. Window-adjust events have already updated
/// `ConnectionState`'s internal flow-control bookkeeping inside
/// `on_packet`, so we don't need to touch them here. Open/close/request
/// events on channels other than the one we're actively opening are
/// dropped (we don't currently expose a global event API on the shared
/// client).
fn stash_event(queues: &mut BTreeMap<u32, ChannelQueue>, ev: ChannelEvent) {
    match ev {
        ChannelEvent::Data { channel, data } => {
            queues.entry(channel).or_default().data.extend(data);
        }
        ChannelEvent::ExtendedData { channel, data, .. } => {
            queues.entry(channel).or_default().stderr.extend(data);
        }
        ChannelEvent::Eof { channel } => {
            queues.entry(channel).or_default().remote_eof = true;
        }
        ChannelEvent::Close { channel } => {
            let q = queues.entry(channel).or_default();
            q.remote_eof = true;
            q.remote_close = true;
        }
        _ => {}
    }
}

/// Map a [`crate::error::Error`] through unchanged. Helper for the
/// `map_err` calls inside [`SharedClient::sftp`] — Rust can't otherwise
/// infer the closure type without a hint.
fn map_err(e: Error) -> Error {
    e
}

/// Read+Write adapter wrapping a single open channel on a
/// [`SharedClient`]. Locks the underlying mutex on every operation and
/// pumps the wire as needed, queuing inbound packets for other channels
/// in the shared per-channel mailbox map. On drop, sends EOF + CLOSE if
/// it hasn't already.
pub struct OwnedChannelStream {
    /// The shared client this stream rides on.
    shared: SharedClient,
    /// Local channel id this stream owns.
    channel: u32,
    /// Whether we've already emitted CHANNEL_CLOSE locally.
    local_close_sent: bool,
}

impl OwnedChannelStream {
    /// Drain bytes from our channel's queue into `buf`. Returns the
    /// number of bytes written. Caller is responsible for window
    /// replenishment.
    fn drain_into(queue: &mut ChannelQueue, buf: &mut [u8]) -> usize {
        let n = core::cmp::min(buf.len(), queue.data.len());
        for slot in buf.iter_mut().take(n) {
            *slot = queue.data.pop_front().unwrap();
        }
        n
    }

    /// Pump one packet off the wire and dispatch its event. If the
    /// event is `Close` for `my_channel` and `local_close_sent` is
    /// still `false`, also emit our own CLOSE reply so the peer can
    /// complete its tear-down (and flip the flag).
    ///
    /// Implemented as an associated function rather than `&mut self`
    /// because the borrow chain `self.shared.inner.lock()` already pins
    /// `self` immutably for the duration of the lock, so a `&mut self`
    /// pump call wouldn't typecheck. Caller passes the bits we need
    /// (channel id by value, close flag by mut ref) explicitly.
    fn pump_one(
        g: &mut Inner,
        my_channel: u32,
        local_close_sent: &mut bool,
    ) -> std::io::Result<()> {
        let payload = g.client.read_one_packet().map_err(io_err)?;
        let ev = g.client.conn.on_packet(&payload).map_err(io_err)?;
        match ev {
            ChannelEvent::Data { channel, data } => {
                let n = data.len() as u32;
                g.queues.entry(channel).or_default().data.extend(data);
                if let Some(adj) = g.client.conn.replenish_window(channel, n).map_err(io_err)? {
                    g.client.write_payload(&adj).map_err(io_err)?;
                }
            }
            ChannelEvent::ExtendedData { channel, data, .. } => {
                let n = data.len() as u32;
                g.queues.entry(channel).or_default().stderr.extend(data);
                if let Some(adj) = g.client.conn.replenish_window(channel, n).map_err(io_err)? {
                    g.client.write_payload(&adj).map_err(io_err)?;
                }
            }
            ChannelEvent::Eof { channel } => {
                g.queues.entry(channel).or_default().remote_eof = true;
            }
            ChannelEvent::Close { channel } => {
                let q = g.queues.entry(channel).or_default();
                q.remote_eof = true;
                q.remote_close = true;
                // If it's our channel and we haven't already closed, ack now.
                if channel == my_channel && !*local_close_sent {
                    let p = g.client.conn.send_close(my_channel).map_err(io_err)?;
                    g.client.write_payload(&p).map_err(io_err)?;
                    *local_close_sent = true;
                }
            }
            _ => {}
        }
        Ok(())
    }
}

impl Read for OwnedChannelStream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let mut g = self
            .shared
            .inner
            .lock()
            .expect("SharedClient mutex poisoned");
        loop {
            // 1. Look at our queue first.
            let queue = g.queues.entry(self.channel).or_default();
            if !queue.data.is_empty() {
                let n = Self::drain_into(queue, buf);
                // Replenish window. Drop the borrow on queue first so we
                // can re-borrow g.client mutably.
                if let Some(adj) = g
                    .client
                    .conn
                    .replenish_window(self.channel, n as u32)
                    .map_err(io_err)?
                {
                    g.client.write_payload(&adj).map_err(io_err)?;
                }
                return Ok(n);
            }
            // 2. EOF / closed?
            if queue.remote_eof {
                return Ok(0);
            }
            // 3. Pump the wire.
            Self::pump_one(&mut g, self.channel, &mut self.local_close_sent)?;
        }
    }
}

impl Write for OwnedChannelStream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let mut g = self
            .shared
            .inner
            .lock()
            .expect("SharedClient mutex poisoned");
        loop {
            let (payload, taken) = g.client.conn.send_data(self.channel, buf).map_err(io_err)?;
            if taken > 0 {
                g.client.write_payload(&payload).map_err(io_err)?;
                return Ok(taken);
            }
            // Window full — pump packets until the peer credits us.
            let queue = g.queues.entry(self.channel).or_default();
            if queue.remote_close {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    "channel closed by peer mid-write",
                ));
            }
            Self::pump_one(&mut g, self.channel, &mut self.local_close_sent)?;
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        // write_payload uses write_all on the underlying socket; no
        // user-level buffering to flush.
        Ok(())
    }
}

impl Drop for OwnedChannelStream {
    fn drop(&mut self) {
        let Ok(mut g) = self.shared.inner.lock() else {
            return; // poisoned — can't recover, just leak the channel id
        };
        if !self.local_close_sent {
            if let Ok(p) = g.client.conn.send_eof(self.channel) {
                let _ = g.client.write_payload(&p);
            }
            if let Ok(p) = g.client.conn.send_close(self.channel) {
                let _ = g.client.write_payload(&p);
            }
            self.local_close_sent = true;
        }
        // Drain a few packets so the peer's matching CLOSE is acked.
        const MAX_DRAIN: usize = 128;
        for _ in 0..MAX_DRAIN {
            let already_closed = g
                .queues
                .get(&self.channel)
                .map(|q| q.remote_close)
                .unwrap_or(false);
            if already_closed {
                break;
            }
            if Self::pump_one(&mut g, self.channel, &mut self.local_close_sent).is_err() {
                break;
            }
        }
        // Reclaim mailbox space.
        g.queues.remove(&self.channel);
    }
}

/// Owned SFTP session built on top of a [`SharedClient`]. Wraps an
/// [`SftpClient`] driven by an [`OwnedChannelStream`], plus an
/// `Arc` clone of the underlying client so dropping this session
/// doesn't accidentally tear down the connection.
///
/// Methods mirror [`SftpClient`] one-to-one. All paths are byte slices
/// because SFTP wire encoding is not character-encoded.
pub struct SftpSession {
    /// Keeps the underlying SharedClient alive while this session
    /// exists. Not used directly — the channel stream owns its own
    /// clone — but tests want to drop the session and then the client
    /// and have neither operation panic.
    _shared: SharedClient,
    inner: SftpClient<OwnedChannelStream>,
}

impl SftpSession {
    /// SFTP version reported by the server.
    pub fn server_version(&self) -> u32 {
        self.inner.server_version()
    }

    /// Server-advertised extensions.
    pub fn extensions(&self) -> &[(Vec<u8>, Vec<u8>)] {
        self.inner.extensions()
    }

    /// `SSH_FXP_OPEN`. Returns the opaque server-side handle.
    pub fn open(
        &mut self,
        path: &[u8],
        pflags: u32,
        attrs: crate::sftp::Attrs,
    ) -> SftpResult<Vec<u8>> {
        self.inner.open(path, pflags, attrs)
    }

    /// `SSH_FXP_CLOSE`.
    pub fn close(&mut self, handle: &[u8]) -> SftpResult<()> {
        self.inner.close(handle)
    }

    /// `SSH_FXP_READ`. Reads up to `len` bytes at `offset`. Returns the
    /// bytes actually read; an empty vector means EOF.
    pub fn read(&mut self, handle: &[u8], offset: u64, len: u32) -> SftpResult<Vec<u8>> {
        self.inner.read(handle, offset, len)
    }

    /// `SSH_FXP_WRITE`. Writes `data` at `offset`.
    pub fn write(&mut self, handle: &[u8], offset: u64, data: &[u8]) -> SftpResult<()> {
        self.inner.write(handle, offset, data)
    }

    /// `SSH_FXP_STAT` — follows symlinks.
    pub fn stat(&mut self, path: &[u8]) -> SftpResult<crate::sftp::Attrs> {
        self.inner.stat(path)
    }

    /// `SSH_FXP_LSTAT` — does not follow the final symlink.
    pub fn lstat(&mut self, path: &[u8]) -> SftpResult<crate::sftp::Attrs> {
        self.inner.lstat(path)
    }

    /// `SSH_FXP_FSTAT`.
    pub fn fstat(&mut self, handle: &[u8]) -> SftpResult<crate::sftp::Attrs> {
        self.inner.fstat(handle)
    }

    /// `SSH_FXP_SETSTAT`.
    pub fn setstat(&mut self, path: &[u8], attrs: crate::sftp::Attrs) -> SftpResult<()> {
        self.inner.setstat(path, attrs)
    }

    /// `SSH_FXP_FSETSTAT`.
    pub fn fsetstat(&mut self, handle: &[u8], attrs: crate::sftp::Attrs) -> SftpResult<()> {
        self.inner.fsetstat(handle, attrs)
    }

    /// `SSH_FXP_OPENDIR`. Returns the server-side directory handle.
    pub fn opendir(&mut self, path: &[u8]) -> SftpResult<Vec<u8>> {
        self.inner.opendir(path)
    }

    /// `SSH_FXP_READDIR`. Returns a chunk of entries; `Ok(None)` on EOF.
    pub fn readdir(&mut self, handle: &[u8]) -> SftpResult<Option<Vec<crate::sftp::NameEntry>>> {
        self.inner.readdir(handle)
    }

    /// `SSH_FXP_MKDIR`.
    pub fn mkdir(&mut self, path: &[u8], attrs: crate::sftp::Attrs) -> SftpResult<()> {
        self.inner.mkdir(path, attrs)
    }

    /// `SSH_FXP_RMDIR`.
    pub fn rmdir(&mut self, path: &[u8]) -> SftpResult<()> {
        self.inner.rmdir(path)
    }

    /// `SSH_FXP_REMOVE`.
    pub fn remove(&mut self, path: &[u8]) -> SftpResult<()> {
        self.inner.remove(path)
    }

    /// `SSH_FXP_RENAME`.
    pub fn rename(&mut self, oldpath: &[u8], newpath: &[u8]) -> SftpResult<()> {
        self.inner.rename(oldpath, newpath)
    }

    /// `SSH_FXP_SYMLINK`.
    pub fn symlink(&mut self, target_path: &[u8], link_path: &[u8]) -> SftpResult<()> {
        self.inner.symlink(target_path, link_path)
    }

    /// `SSH_FXP_READLINK`. Returns the link target.
    pub fn readlink(&mut self, path: &[u8]) -> SftpResult<Vec<u8>> {
        self.inner.readlink(path)
    }

    /// `SSH_FXP_REALPATH`. Returns the absolute, canonicalised path.
    pub fn realpath(&mut self, path: &[u8]) -> SftpResult<Vec<u8>> {
        self.inner.realpath(path)
    }
}

#[cfg(test)]
mod tests {
    //! Pure-logic unit tests. End-to-end multi-handle SFTP coverage
    //! lives in `tests/e2e_shared_sftp.rs` (ignored, requires `sshd`).

    use super::*;

    #[test]
    fn channel_queue_default_is_empty() {
        let q = ChannelQueue::default();
        assert!(q.data.is_empty());
        assert!(q.stderr.is_empty());
        assert!(!q.remote_eof);
        assert!(!q.remote_close);
    }

    #[test]
    fn drain_into_partial() {
        let mut q = ChannelQueue::default();
        q.data.extend(b"hello".iter().copied());
        let mut buf = [0u8; 3];
        let n = OwnedChannelStream::drain_into(&mut q, &mut buf);
        assert_eq!(n, 3);
        assert_eq!(&buf, b"hel");
        assert_eq!(q.data.iter().copied().collect::<Vec<_>>(), b"lo");
    }

    #[test]
    fn drain_into_overflow() {
        let mut q = ChannelQueue::default();
        q.data.extend(b"hi".iter().copied());
        let mut buf = [0u8; 8];
        let n = OwnedChannelStream::drain_into(&mut q, &mut buf);
        assert_eq!(n, 2);
        assert_eq!(&buf[..2], b"hi");
        assert!(q.data.is_empty());
    }

    #[test]
    fn stash_event_data_appends_to_right_channel() {
        let mut queues: BTreeMap<u32, ChannelQueue> = BTreeMap::new();
        stash_event(
            &mut queues,
            ChannelEvent::Data {
                channel: 7,
                data: b"abc".to_vec(),
            },
        );
        stash_event(
            &mut queues,
            ChannelEvent::Data {
                channel: 7,
                data: b"def".to_vec(),
            },
        );
        stash_event(
            &mut queues,
            ChannelEvent::Data {
                channel: 9,
                data: b"x".to_vec(),
            },
        );
        assert_eq!(
            queues[&7].data.iter().copied().collect::<Vec<_>>(),
            b"abcdef"
        );
        assert_eq!(queues[&9].data.iter().copied().collect::<Vec<_>>(), b"x");
    }

    #[test]
    fn stash_event_eof_and_close_set_flags() {
        let mut queues: BTreeMap<u32, ChannelQueue> = BTreeMap::new();
        stash_event(&mut queues, ChannelEvent::Eof { channel: 3 });
        assert!(queues[&3].remote_eof);
        assert!(!queues[&3].remote_close);

        stash_event(&mut queues, ChannelEvent::Close { channel: 3 });
        assert!(queues[&3].remote_eof);
        assert!(queues[&3].remote_close);
    }

    #[test]
    fn stash_event_ignores_irrelevant() {
        let mut queues: BTreeMap<u32, ChannelQueue> = BTreeMap::new();
        stash_event(&mut queues, ChannelEvent::OpenConfirmed { channel: 1 });
        stash_event(
            &mut queues,
            ChannelEvent::OpenFailed {
                channel: 1,
                reason: 0,
                description: String::new(),
            },
        );
        stash_event(
            &mut queues,
            ChannelEvent::WindowAdjust {
                channel: 1,
                added: 100,
            },
        );
        assert!(queues.is_empty());
    }
}
