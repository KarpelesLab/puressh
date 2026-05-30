//! Cross-cutting bidirectional channel adapter used by server-side
//! [`crate::server::SubsystemHandler`] / [`crate::server::DirectTcpipHandler`]
//! plumbing AND by the client-side multi-channel event loop
//! ([`crate::client::Client::serve`]).
//!
//! [`ChannelStream`] hides the per-channel mpsc plumbing the dispatch
//! loop sets up: ingress bytes from the peer arrive on a receiver, and
//! egress bytes the handler wants to ship out get pushed onto a bounded
//! sender. The dispatcher then serializes those egress messages onto the
//! SSH wire as `CHANNEL_DATA` / `CHANNEL_EOF` / `CHANNEL_CLOSE`.
//!
//! Handlers normally only need `Read` and `Write`. For splice-style
//! proxying that wants to drive each direction from a separate thread
//! (so a slow peer in one direction doesn't stall the other), use
//! [`ChannelStream::into_raw`] to peel the mpsc handles out.

#![cfg(feature = "std")]

use std::io::{ErrorKind, Read, Write};
use std::sync::mpsc::{Receiver, SyncSender};

use alloc::vec::Vec;

/// Outbound message a [`ChannelStream`] sends through its egress mpsc.
///
/// The connection dispatcher (server or client side) serializes these
/// onto the wire as `CHANNEL_DATA` / `CHANNEL_EOF` / `CHANNEL_CLOSE`
/// packets. Handlers don't emit `ChannelEgress` directly — they just
/// use `Read` / `Write` on the stream, and the EOF / Close pair is sent
/// automatically when the stream drops.
pub enum ChannelEgress {
    /// Bytes destined for `CHANNEL_DATA`.
    Data(Vec<u8>),
    /// `CHANNEL_EOF`.
    Eof,
    /// `CHANNEL_CLOSE`.
    Close,
}

/// Bidirectional view of an SSH channel.
///
/// Behaviour:
/// - [`Read::read`] blocks until the peer sends `CHANNEL_DATA` or `EOF`
///   (returns `Ok(0)`).
/// - [`Write::write`] enqueues data for the dispatcher to ship;
///   backpressure comes from a bounded mpsc — if the remote window is
///   full the dispatcher stops draining and the next write blocks the
///   handler thread.
/// - On drop the stream sends `CHANNEL_EOF` followed by `CHANNEL_CLOSE`
///   (best-effort — silently ignored if the channel is already gone).
pub struct ChannelStream {
    /// `None` after [`Self::into_raw`] has moved it out. The matching `tx`
    /// will also be `None`, so [`Self::drop`] is a no-op.
    rx: Option<Receiver<Option<Vec<u8>>>>,
    tx: Option<SyncSender<ChannelEgress>>,
    buf: Vec<u8>,
    rx_eof: bool,
}

impl ChannelStream {
    /// Used by the dispatcher; not for user code.
    pub(crate) fn new(rx: Receiver<Option<Vec<u8>>>, tx: SyncSender<ChannelEgress>) -> Self {
        Self {
            rx: Some(rx),
            tx: Some(tx),
            buf: Vec::new(),
            rx_eof: false,
        }
    }

    /// Send an explicit EOF marker. Subsequent writes still succeed (per
    /// RFC 4254 EOF is one-directional). Most handlers don't need this —
    /// EOF and Close are sent automatically when the stream drops.
    pub fn send_eof(&mut self) -> std::io::Result<()> {
        let tx = self
            .tx
            .as_ref()
            .ok_or_else(|| std::io::Error::new(ErrorKind::BrokenPipe, "channel closed"))?;
        tx.send(ChannelEgress::Eof)
            .map_err(|_| std::io::Error::new(ErrorKind::BrokenPipe, "channel closed"))
    }

    /// Decompose the stream into raw mpsc handles so callers can drive
    /// each direction from a separate thread.
    ///
    /// - The first return is the **ingress** receiver: bytes from the
    ///   peer arrive as `Some(chunk)`, EOF arrives as `None`, and the
    ///   dispatcher tearing the channel down closes the channel
    ///   (returning `Err`).
    /// - The second return is the **egress** sender. Send `Data(_)` to
    ///   ship `CHANNEL_DATA`, then `Eof` and `Close` to tear the channel
    ///   down cleanly.
    ///
    /// Unlike [`Read`] / [`Write`] on `ChannelStream`, the auto-EOF +
    /// auto-Close on drop is **suppressed** — the caller takes
    /// responsibility for sending those markers (typically once both
    /// copy loops finish). This is the right primitive for splice-style
    /// proxying.
    ///
    /// Panics: at the type level this method cannot fail — it takes
    /// `self` by value, so by definition the `rx` / `tx` cells haven't
    /// been moved out before. The internal asserts below are there to
    /// catch a future logic bug if a constructor is added that leaves
    /// either field `None`; new callers that want a non-panicking API
    /// should use [`Self::try_into_raw`].
    pub fn into_raw(mut self) -> (Receiver<Option<Vec<u8>>>, SyncSender<ChannelEgress>) {
        let rx = self.rx.take().unwrap_or_else(|| {
            unreachable!("ChannelStream invariant: rx populated until into_raw consumes self")
        });
        let tx = self.tx.take().unwrap_or_else(|| {
            unreachable!("ChannelStream invariant: tx populated until into_raw consumes self")
        });
        (rx, tx)
    }

    /// Fallible variant of [`Self::into_raw`]. Returns `None` if either
    /// half of the duplex has already been moved out. Provided so future
    /// constructors / sub-takers can compose without an `unreachable!`.
    ///
    /// Today this always returns `Some(_)` for a `ChannelStream` produced
    /// by [`Self::new`], because the only path that nulls `rx` / `tx` is
    /// `into_raw` itself, which consumes the value. Defensive callers
    /// that prefer a `?` over a panic should use this method.
    #[allow(clippy::type_complexity)] // mirrors `into_raw`'s public tuple
    pub fn try_into_raw(
        mut self,
    ) -> Option<(Receiver<Option<Vec<u8>>>, SyncSender<ChannelEgress>)> {
        let rx = self.rx.take()?;
        let tx = self.tx.take()?;
        Some((rx, tx))
    }
}

impl Read for ChannelStream {
    fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
        if !self.buf.is_empty() {
            let n = out.len().min(self.buf.len());
            out[..n].copy_from_slice(&self.buf[..n]);
            self.buf.drain(..n);
            return Ok(n);
        }
        if self.rx_eof {
            return Ok(0);
        }
        let rx = self
            .rx
            .as_ref()
            .ok_or_else(|| std::io::Error::new(ErrorKind::BrokenPipe, "channel taken"))?;
        match rx.recv() {
            Ok(Some(chunk)) => {
                self.buf = chunk;
                self.read(out)
            }
            Ok(None) | Err(_) => {
                self.rx_eof = true;
                Ok(0)
            }
        }
    }
}

impl Write for ChannelStream {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        let tx = self
            .tx
            .as_ref()
            .ok_or_else(|| std::io::Error::new(ErrorKind::BrokenPipe, "channel taken"))?;
        // Cap chunks to keep per-packet payloads sane; the dispatcher
        // will split further if the remote channel-max-packet is smaller.
        let take = data.len().min(32 * 1024);
        let chunk = data[..take].to_vec();
        tx.send(ChannelEgress::Data(chunk))
            .map_err(|_| std::io::Error::new(ErrorKind::BrokenPipe, "channel closed"))?;
        Ok(take)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Drop for ChannelStream {
    fn drop(&mut self) {
        // Best-effort: ignore failures if the channel was already torn
        // down. After `into_raw` both `tx` and `rx` are None and this is
        // a no-op.
        if let Some(tx) = self.tx.take() {
            let _ = tx.send(ChannelEgress::Eof);
            let _ = tx.send(ChannelEgress::Close);
        }
    }
}
