//! Owned-handle wrapper around [`Client`] that supports **multiple
//! concurrent channel sessions of every type** on a single SSH
//! connection — SFTP, exec, interactive shells, and direct-tcpip
//! forwards all coexisting on the same transport.
//!
//! `Client::sftp` / `exec_stream` / `shell_with_stdin` /
//! `open_direct_tcpip` each return a stream that mutably borrows the
//! [`Client`], so only one channel can be in flight at a time at the
//! type-system level. That's fine for the command-line tools and the
//! single-shot helpers, but the C ABI surface (and any user wrapping
//! the lib in a long-lived service) needs to hold *multiple* sessions
//! simultaneously over the same underlying transport — possibly a mix
//! of two SFTP sessions, a shell, and two port forwards on one client.
//!
//! [`SharedClient`] wraps the connected [`Client`] in `Arc<Mutex<...>>`
//! and tags each open channel with a per-channel byte queue, so a stream
//! waiting for response data on channel A doesn't lose packets that
//! arrived for channel B. [`OwnedChannelStream`] is the [`Read`]+[`Write`]
//! adapter — it locks the mutex on every `read`/`write`, pumps the wire
//! as needed, dispatches inbound packets to the right queue, and only
//! returns to the caller once *its* channel has bytes.
//!
//! ## Surface
//!
//! - [`SharedClient::sftp`] — open an SFTP session (returns
//!   [`SftpSession`]).
//! - [`SharedClient::exec_stream`] — run a remote command, returning a
//!   raw [`OwnedChannelStream`] over its stdin/stdout pair.
//! - [`SharedClient::shell`] — open an interactive shell with a PTY,
//!   returning an [`OwnedChannelStream`].
//! - [`SharedClient::open_direct_tcpip`] — open a `direct-tcpip` channel
//!   for a port-forward.
//!
//! All four return an owned handle that keeps the connection alive
//! via an `Arc` clone. Any combination can be live at once.
//!
//! ## Concurrency model
//!
//! Multiple [`OwnedChannelStream`]s (from any combination of SFTP / exec
//! / shell / forward handles) coexist on a single [`SharedClient`].
//! Threads using them serialise on a single mutex, but only one thread
//! is the *pumper* at any moment — the one actively driving the wire.
//! All other threads sleep on a per-channel [`std::sync::Condvar`].
//!
//! Read flow under the mutex:
//!
//! 1. If our channel's mailbox already holds bytes, drain into the
//!    caller's buffer, replenish the receive window for the drained
//!    bytes, and return.
//! 2. Else, if no thread is currently pumping, claim the pump seat,
//!    pump exactly one packet off the wire, dispatch it into the right
//!    channel's mailbox, signal that channel's notifier, release the
//!    pump seat, and loop.
//! 3. Else, wait on our channel's notifier with a 500 ms safety-net
//!    timeout. The pumper signals our notifier when it deposits data
//!    for us; the timeout catches the rare missed notify (e.g. a
//!    panicked pumper).
//!
//! Write flow follows the same pattern: if `send_data` reports zero
//! bytes taken (peer window credit is zero), become pumper or wait,
//! hoping for a window-adjust to arrive on the next packet.
//!
//! Backpressure: receive-window credit is replenished only at drain
//! time in [`Read::read`], never on enqueue inside the pumper. A
//! reader that stops draining its channel lets the SSH per-channel
//! window naturally cap the in-memory mailbox at the initial window
//! size, which in turn stops the peer from sending more.
//!
//! ### Limitations
//!
//! `Client::read_one_packet` is a blocking socket read on a bare
//! `TcpStream`. While the pumper is parked there no
//! other thread can grab the mutex — including a thread whose data is
//! already in its mailbox. In practice this only matters when one
//! channel is genuinely quiet for long stretches; the typical
//! request/response SFTP workload doesn't trigger it. Lifting this
//! fully needs either a dedicated reader thread or splitting the
//! read-half of the `TcpStream` — both deferred.

#![cfg(feature = "std")]

use std::collections::{BTreeMap, VecDeque};
use std::io::{Read, Write};
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

use crate::channel::{ChannelEvent, ChannelOpen, ChannelRequest};
use crate::client::{Client, Transport, io_err};
use crate::error::{Error, Result};
use crate::sftp::{SftpClient, SftpError};

/// Safety-net wake interval for non-pumping waiters. If the pumper
/// panics or otherwise fails to fire a notification, waiters reawaken
/// on this cadence and re-check their mailbox. Short enough that
/// latency is human-tolerable, long enough that idle channels do not
/// burn CPU.
const WAIT_TIMEOUT: Duration = Duration::from_millis(500);

/// Lock the shared mutex, mapping poison to `Error::Protocol`. Used by
/// fallible API paths whose return type is `Result<_, crate::Error>` —
/// they propagate poisoning as a hard error rather than panicking the
/// thread, so callers in long-lived programs (servers, the FFI, etc.)
/// can free the [`SharedClient`] and reconnect.
///
/// Finding #9 (Medium). Panicking on `lock()` poisoning meant that one
/// panic in any pumper or session worker tore down the entire process
/// instead of being contained to that connection. The Drop / Read / Write
/// paths that return `std::io::Result` translate poisoning into a
/// `BrokenPipe` via [`lock_or_poison_io`] for the same reason.
fn lock_or_poison<'a>(m: &'a Mutex<Inner>) -> Result<std::sync::MutexGuard<'a, Inner>> {
    m.lock()
        .map_err(|_| Error::Protocol("SharedClient mutex poisoned"))
}

/// `std::io::Result` flavour of [`lock_or_poison`]. Maps poisoning to a
/// `BrokenPipe` so the `Read` / `Write` impls below can surface it the
/// same way they surface "channel closed".
fn lock_or_poison_io<'a>(m: &'a Mutex<Inner>) -> std::io::Result<std::sync::MutexGuard<'a, Inner>> {
    m.lock().map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::BrokenPipe,
            "SharedClient mutex poisoned",
        )
    })
}

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
    /// Latest `exit-status` request the peer sent on this channel
    /// (RFC 4254 §6.10). Set by the pump path when the request lands.
    exit_status: Option<i32>,
    /// Latest `exit-signal` request the peer sent on this channel
    /// (RFC 4254 §6.10). Carries the signal *name* — e.g. `"TERM"`,
    /// `"KILL"`. Set by the pump path when the request lands.
    exit_signal: Option<String>,
    /// True once we have already half-closed our write side via
    /// `SSH_MSG_CHANNEL_EOF` on this channel — used to make
    /// [`OwnedChannelStream::send_eof`] idempotent.
    local_eof_sent: bool,
}

/// Shared state: the underlying [`Client`], a per-channel mailbox map,
/// per-channel waiter notifiers, and a single-occupancy pump flag.
/// All access goes through [`SharedClient`]'s `Arc<Mutex<Inner>>`.
struct Inner {
    client: Client,
    /// Per-channel mailboxes, keyed by *local* channel id (the value
    /// [`crate::channel::ConnectionState::open`] returned when the
    /// channel was opened).
    queues: BTreeMap<u32, ChannelQueue>,
    /// Wake-up notifier per channel. The pumper signals these whenever
    /// it deposits data / EOF / close for the corresponding channel.
    /// Get-or-create one via [`notifier_for`]. Removed by `Drop` when
    /// a stream goes away, so the map size tracks live channels.
    notifiers: BTreeMap<u32, Arc<Condvar>>,
    /// True iff some thread is currently inside
    /// [`OwnedChannelStream::pump_one_step`] for this connection.
    /// Only one pumper at a time; everyone else either drains its
    /// mailbox (returns immediately) or waits on its channel notifier.
    pumping: bool,
}

/// Owned, clonable handle to a connected [`Client`] that supports
/// concurrent channel sessions. Build with `SharedClient::from(client)`.
///
/// Cloning is a cheap `Arc` bump — every clone points at the same
/// underlying connection. All access goes through an internal mutex.
#[derive(Clone)]
pub struct SharedClient {
    inner: Arc<Mutex<Inner>>,
    /// Number of threads currently in a `read_stream` /
    /// `channel_recv_stderr` / `channel_send_data` / `channel_send_eof`
    /// call — i.e. *contending for* the inner mutex. Bumped on entry by
    /// each such call (via [`LockTicket`]) and decremented on exit. Sits
    /// outside the mutex so the read-pump can observe it without
    /// locking.
    ///
    /// The pump path consults this counter between iterations and
    /// yields generously when it sees a sibling waiting (`> 1` means
    /// "more than just self"). Linux `std::sync::Mutex` is unfair: a
    /// thread that releases and immediately re-acquires can starve a
    /// contended waiter indefinitely without an explicit yield window.
    /// In the interactive-shell case this manifested as the stderr-
    /// reader thread (which becomes pumper first) monopolising the
    /// lock, starving the data-reader thread that would otherwise
    /// drain SHELL prompt bytes.
    lock_waiters: Arc<core::sync::atomic::AtomicUsize>,
}

impl From<Client> for SharedClient {
    fn from(client: Client) -> Self {
        Self {
            inner: Arc::new(Mutex::new(Inner {
                client,
                queues: BTreeMap::new(),
                notifiers: BTreeMap::new(),
                pumping: false,
            })),
            lock_waiters: Arc::new(core::sync::atomic::AtomicUsize::new(0)),
        }
    }
}

/// RAII guard: bumps [`SharedClient::lock_waiters`] on construction and
/// decrements on Drop. Held for the full duration of any read / write
/// entry point on `SharedClient` / `OwnedChannelStream` so the read-pump
/// can detect "another thread also wants the lock" and yield enough for
/// the kernel to actually schedule that thread onto the freshly-released
/// mutex (Linux `std::sync::Mutex` is unfair — see [`SharedClient::lock_waiters`]).
struct LockTicket<'a> {
    counter: &'a core::sync::atomic::AtomicUsize,
}

impl<'a> LockTicket<'a> {
    fn new(counter: &'a core::sync::atomic::AtomicUsize) -> Self {
        counter.fetch_add(1, core::sync::atomic::Ordering::SeqCst);
        Self { counter }
    }
}

impl Drop for LockTicket<'_> {
    fn drop(&mut self) {
        self.counter
            .fetch_sub(1, core::sync::atomic::Ordering::SeqCst);
    }
}

impl SharedClient {
    /// Open a session channel, request the `sftp` subsystem, perform the
    /// SFTP `INIT`/`VERSION` handshake, and return an owned
    /// [`SftpSession`]. Multiple SFTP sessions per `SharedClient` are
    /// supported and can coexist with shells / exec / forwards.
    pub fn sftp(&self) -> Result<SftpSession> {
        let local_id = {
            let mut g = lock_or_poison(&self.inner)?;
            let id = open_session_under_lock(&mut g, "sftp")?;
            send_request_and_await(
                &mut g,
                id,
                ChannelRequest::Subsystem {
                    name: "sftp".into(),
                },
                "sftp: subsystem",
            )?;
            id
        };

        // Lock dropped: build the stream and run INIT/VERSION through
        // it. Each transport call re-locks the inner Mutex, which is
        // fine.
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
                // The stream has been moved into SftpClient and dropped
                // on the error path, so its Drop already attempted to
                // send CHANNEL_CLOSE.
                Err(Error::Protocol(match e {
                    SftpError::Protocol(s) => s,
                    _ => "sftp: handshake failed",
                }))
            }
        }
    }

    /// Open a session channel and ask the server to execute `command`,
    /// returning an owned [`OwnedChannelStream`] over the channel's
    /// stdin/stdout pair. Stderr lands in the channel's stderr mailbox
    /// (currently not exposed on the owned stream — exec callers should
    /// rely on stdout-only output for now; full stderr accessors land in
    /// a follow-up).
    ///
    /// Multiple concurrent exec streams are supported, and they can
    /// coexist with SFTP / shell / forward handles on the same client.
    pub fn exec_stream(&self, command: &str) -> Result<OwnedChannelStream> {
        let local_id = {
            let mut g = lock_or_poison(&self.inner)?;
            let id = open_session_under_lock(&mut g, "exec")?;
            send_request_and_await(
                &mut g,
                id,
                ChannelRequest::Exec {
                    command: command.into(),
                },
                "exec: command",
            )?;
            id
        };
        Ok(OwnedChannelStream {
            shared: self.clone(),
            channel: local_id,
            local_close_sent: false,
        })
    }

    /// Open a session channel, request a PTY, and start a remote shell.
    /// Returns an owned [`OwnedChannelStream`] over the shell's
    /// stdin/stdout pair.
    ///
    /// `term` / `cols` / `rows` follow the PTY-req convention from
    /// RFC 4254 §6.2. For a non-PTY shell, issue `exec_stream("")`
    /// against your login shell instead.
    ///
    /// This is a convenience wrapper around [`Self::shell_stream`] with
    /// zero pixel dimensions and no terminal modes — adequate for
    /// scripted use. Interactive callers should prefer
    /// [`Self::shell_stream`].
    pub fn shell(&self, term: &str, cols: u32, rows: u32) -> Result<OwnedChannelStream> {
        self.shell_stream(term, cols, rows, 0, 0, Vec::new())
    }

    /// Open a session channel with a PTY allocated to `term` /
    /// `cols`×`rows` / `px_w`×`px_h` and the encoded terminal `modes`
    /// blob (RFC 4254 §8), then start a remote shell. Returns an owned
    /// [`OwnedChannelStream`] over the shell's stdin/stdout pair.
    ///
    /// `modes` is the opcode-encoded modes payload — pass an empty
    /// [`Vec`] for "server defaults", or build one from a local
    /// `termios` with [`crate::client::encode_termios_modes`].
    ///
    /// To resize the PTY after open, call [`Self::send_window_change`]
    /// with the same channel id (use
    /// [`OwnedChannelStream::channel_id`]). To learn the remote exit
    /// status when the shell terminates, drain the stream to EOF, then
    /// call [`OwnedChannelStream::exit_status`] /
    /// [`OwnedChannelStream::exit_signal`].
    pub fn shell_stream(
        &self,
        term: &str,
        cols: u32,
        rows: u32,
        px_w: u32,
        px_h: u32,
        modes: Vec<u8>,
    ) -> Result<OwnedChannelStream> {
        let local_id = {
            let mut g = lock_or_poison(&self.inner)?;
            let id = open_session_under_lock(&mut g, "shell")?;
            send_request_and_await(
                &mut g,
                id,
                ChannelRequest::PtyReq {
                    term: term.into(),
                    cols,
                    rows,
                    px_w,
                    px_h,
                    modes,
                },
                "shell: pty-req",
            )?;
            send_request_and_await(&mut g, id, ChannelRequest::Shell, "shell: shell-req")?;
            id
        };
        Ok(OwnedChannelStream {
            shared: self.clone(),
            channel: local_id,
            local_close_sent: false,
        })
    }

    /// Open a session channel and start a remote shell **without**
    /// allocating a PTY. Returns an owned [`OwnedChannelStream`] over
    /// the shell's stdin/stdout pair.
    ///
    /// This is the non-interactive fallback path: the client uses it
    /// when its own stdin is not a TTY (matching `ssh host` with stdin
    /// redirected). The remote shell will run in line-buffered
    /// non-canonical mode and won't see terminal control sequences;
    /// the channel still carries data + stderr as usual.
    pub fn shell_stream_no_pty(&self) -> Result<OwnedChannelStream> {
        let local_id = {
            let mut g = lock_or_poison(&self.inner)?;
            let id = open_session_under_lock(&mut g, "shell")?;
            send_request_and_await(&mut g, id, ChannelRequest::Shell, "shell: shell-req")?;
            id
        };
        Ok(OwnedChannelStream {
            shared: self.clone(),
            channel: local_id,
            local_close_sent: false,
        })
    }

    /// Send a `window-change` request (RFC 4254 §6.7) on a previously
    /// opened session channel. `want_reply` is always false per the
    /// RFC, so this call returns as soon as the packet is on the wire.
    ///
    /// Pass the channel id returned by
    /// [`OwnedChannelStream::channel_id`]. Calling this from a SIGWINCH
    /// handler thread on a sibling [`SharedClient`] clone is supported
    /// — the call serialises through the same mutex as the I/O
    /// threads but does not block waiting for any reply.
    pub fn send_window_change(
        &self,
        channel: u32,
        cols: u32,
        rows: u32,
        px_w: u32,
        px_h: u32,
    ) -> Result<()> {
        let mut g = lock_or_poison(&self.inner)?;
        let payload = g.client.conn.send_request(
            channel,
            ChannelRequest::WindowChange {
                cols,
                rows,
                px_w,
                px_h,
            },
            false,
        )?;
        g.client.write_payload(&payload)?;
        Ok(())
    }

    /// Write up to `data.len()` bytes on `channel`'s data stream,
    /// respecting peer flow-control. Returns the number of bytes actually
    /// taken (the rest must be retried — same semantics as
    /// [`std::io::Write::write`]).
    ///
    /// Lets a caller that already holds the channel id (e.g. from
    /// [`OwnedChannelStream::channel_id`]) send data **without** going
    /// through the owning stream's `&mut self` — useful for the
    /// interactive shell, where the stdout-reader thread holds the
    /// stream and a sibling stdin thread needs to push input without
    /// contending on an outer mutex.
    pub fn channel_send_data(&self, channel: u32, data: &[u8]) -> std::io::Result<usize> {
        if data.is_empty() {
            return Ok(0);
        }
        let _ticket = LockTicket::new(&self.lock_waiters);
        loop {
            let mut g = lock_or_poison_io(&self.inner)?;
            let (payload, taken) = g.client.conn.send_data(channel, data).map_err(io_err)?;
            if taken > 0 {
                g.client.write_payload(&payload).map_err(io_err)?;
                return Ok(taken);
            }
            // Zero credit: bail if the peer already closed us, otherwise
            // become pumper (or wait for one) so a window-adjust can land.
            let queue = g.queues.entry(channel).or_default();
            if queue.remote_close {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    "channel closed by peer mid-write",
                ));
            }
            if !g.pumping {
                g.pumping = true;
                let res = OwnedChannelStream::pump_one_step(&mut g);
                g.pumping = false;
                for cv in g.notifiers.values() {
                    cv.notify_one();
                }
                drop(g);
                res?;
            } else {
                let cv = notifier_for(&mut g, channel);
                let waited = cv.wait_timeout(g, WAIT_TIMEOUT).map_err(|_| {
                    std::io::Error::new(
                        std::io::ErrorKind::BrokenPipe,
                        "SharedClient mutex poisoned",
                    )
                })?;
                drop(waited.0);
            }
        }
    }

    /// Drain bytes from `channel`'s stderr (extended-data) mailbox.
    /// Same semantics as [`std::io::Read::read`] on the stream: `Ok(0)`
    /// means EOF, `Ok(n)` returns up to `buf.len()` bytes. Blocks while
    /// pumping the wire if no bytes are buffered yet. Returns
    /// immediately on the next yield window if a sibling thread is
    /// currently pumping.
    ///
    /// Use this from a thread that does not own the channel's
    /// [`OwnedChannelStream`] (e.g. an interactive shell's
    /// dedicated-stderr thread, where the main reader thread holds the
    /// stream for the data side).
    pub fn channel_recv_stderr(&self, channel: u32, buf: &mut [u8]) -> std::io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let _ticket = LockTicket::new(&self.lock_waiters);
        loop {
            let mut g = lock_or_poison_io(&self.inner)?;
            let queue = g.queues.entry(channel).or_default();
            if !queue.stderr.is_empty() {
                let n = OwnedChannelStream::drain_into(queue, Stream::Stderr, buf);
                replenish_under_lock(&mut g, channel, n as u32)?;
                return Ok(n);
            }
            if queue.remote_eof {
                return Ok(0);
            }
            if !g.pumping {
                g.pumping = true;
                let res = OwnedChannelStream::pump_one_step(&mut g);
                g.pumping = false;
                for cv in g.notifiers.values() {
                    cv.notify_one();
                }
                drop(g);
                res?;
                // Symmetric with `read_stream`'s pump branch: yield CPU
                // long enough for any sibling thread that's also waiting
                // for the lock (other reader half of this channel, or a
                // writer) to actually be scheduled onto the freshly
                // released mutex. Without this, t_err's tight
                // pump→re-acquire loop monopolises the lock and starves
                // the data-side reader of the interactive shell.
                if self.lock_waiters.load(core::sync::atomic::Ordering::SeqCst) > 1 {
                    std::thread::sleep(Duration::from_millis(1));
                } else {
                    std::thread::sleep(Duration::from_micros(100));
                }
            } else {
                let cv = notifier_for(&mut g, channel);
                let waited = cv.wait_timeout(g, WAIT_TIMEOUT).map_err(|_| {
                    std::io::Error::new(
                        std::io::ErrorKind::BrokenPipe,
                        "SharedClient mutex poisoned",
                    )
                })?;
                drop(waited.0);
            }
        }
    }

    /// Send `SSH_MSG_CHANNEL_EOF` on `channel`. Idempotent (silently
    /// skipped if EOF was already emitted on this channel via this
    /// SharedClient).
    pub fn channel_send_eof(&self, channel: u32) -> std::io::Result<()> {
        let _ticket = LockTicket::new(&self.lock_waiters);
        let mut g = lock_or_poison_io(&self.inner)?;
        let q = g.queues.entry(channel).or_default();
        if q.local_eof_sent {
            return Ok(());
        }
        q.local_eof_sent = true;
        let payload = g.client.conn.send_eof(channel).map_err(io_err)?;
        g.client.write_payload(&payload).map_err(io_err)?;
        Ok(())
    }

    /// Configure the underlying TCP socket's read timeout. Delegates to
    /// [`Client::set_read_timeout`]. Pass `None` to clear the timeout
    /// (the default; long blocking reads). Pass `Some(d)` to make the
    /// pump release its inner mutex at least every `d`, so siblings
    /// (e.g. the write half of an interactive shell, or other channels
    /// sharing this client) can squeeze in.
    ///
    /// Recommended for interactive (`shell_stream` + concurrent stdin
    /// thread) workloads: typically 50–100 ms. Not needed for
    /// request/response SFTP / exec flows.
    pub fn set_read_timeout(&self, t: Option<core::time::Duration>) -> Result<()> {
        let mut g = lock_or_poison(&self.inner)?;
        g.client.set_read_timeout(t).map_err(Error::Io)
    }

    /// Send a `ping@openssh.com` `SSH2_MSG_PING` over the transport carrying
    /// `data`. The peer replies with a `SSH2_MSG_PONG` echoing `data`, which
    /// the pump silently drops. This is the connection-level "chaff"
    /// mechanism used by the `ObscureKeystrokeTiming` keystroke obfuscator;
    /// it is independent of any channel. Thread-safe: takes the inner mutex,
    /// so it serialises with the concurrent channel pump and other senders.
    pub fn send_ping(&self, data: &[u8]) -> Result<()> {
        let mut g = lock_or_poison(&self.inner)?;
        g.client.send_transport_ping(data)
    }

    /// Open a `direct-tcpip` channel (RFC 4254 §7.2) — the server
    /// connects to `dest_host:dest_port` and proxies bytes across the
    /// returned stream. `orig_host` / `orig_port` are informational.
    ///
    /// Multiple concurrent forwards are supported and can coexist with
    /// SFTP / shell / exec handles.
    pub fn open_direct_tcpip(
        &self,
        dest_host: &str,
        dest_port: u16,
        orig_host: &str,
        orig_port: u16,
    ) -> Result<OwnedChannelStream> {
        let local_id = {
            let mut g = lock_or_poison(&self.inner)?;
            open_direct_tcpip_under_lock(&mut g, dest_host, dest_port, orig_host, orig_port)?
        };
        Ok(OwnedChannelStream {
            shared: self.clone(),
            channel: local_id,
            local_close_sent: false,
        })
    }

    /// Lock the inner client for one synchronous operation. Internal helper
    /// for the FFI layer's `pcssh_client_exec` and friends, which run a
    /// single self-contained method on `Client` while holding the mutex.
    ///
    /// This is `pub(crate)` because library users normally don't need it —
    /// they should call methods on [`SharedClient`] or [`SftpSession`].
    /// The C ABI is the asymmetric case where the wrapped `Client` is
    /// where state lives.
    #[cfg_attr(not(feature = "ffi"), allow(dead_code))]
    pub(crate) fn with_client<R>(&self, f: impl FnOnce(&mut Client) -> R) -> R {
        // This helper exists for the FFI surface, which expects an infallible
        // return, so it cannot propagate poisoning as a `Result` the way the
        // `lock_or_poison` family does. Finding E (Medium): the previous
        // `.expect()` panicked on a poisoned mutex, and that panic unwinds
        // across the C ABI — UB / a process abort — turning one connection's
        // fault into a whole-process crash, the exact thing the surrounding
        // code (line-99 note, Finding #9) tries to contain. Recover the guard
        // instead (same `unwrap_or_else(|e| e.into_inner())` recovery the
        // poison helpers rely on) so the lock never causes an unwind. Callers
        // that *can* observe poisoning should prefer `try_with_client`; the
        // multi-channel entry points (`sftp`, `exec_stream`, `shell`, …) use
        // `lock_or_poison` and propagate `Error::Protocol` instead.
        let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        f(&mut g.client)
    }

    /// Fallible variant of [`Self::with_client`] for callers that can
    /// propagate poisoning. New FFI surfaces should prefer this.
    #[allow(dead_code)]
    pub(crate) fn try_with_client<R>(&self, f: impl FnOnce(&mut Client) -> R) -> Result<R> {
        let mut g = lock_or_poison(&self.inner)?;
        Ok(f(&mut g.client))
    }

    /// Set the session-env list the next channel-open will forward via `env`
    /// requests. Used by the mux master to honour a client's forwarded
    /// environment before opening that client's channel. Poisoning is
    /// swallowed (best-effort): a failed env set still lets the open proceed
    /// with no forwarded env rather than aborting the session.
    pub fn with_session_env(&self, env: Vec<(String, String)>) {
        if let Ok(mut g) = self.inner.lock() {
            g.client.set_session_env(env);
        }
    }
}

/// Open a session channel under an already-held lock guard. Returns the
/// new local channel id with its mailbox slot initialised; the caller is
/// responsible for sending whatever subsystem / exec / shell request it
/// needs next (still under the same lock).
///
/// `what` is a short tag used in error messages.
fn open_session_under_lock(g: &mut Inner, what: &'static str) -> Result<u32> {
    let (local_id, open_payload) = g.client.conn.open(ChannelOpen::Session)?;
    g.client.write_payload(&open_payload)?;

    let mut opened = false;
    let mut iter_guard = 0usize;
    while !opened {
        iter_guard += 1;
        if iter_guard > MAX_OPEN_ITER {
            return Err(Error::Protocol(open_loop_msg(what)));
        }
        let payload = g.client.read_one_packet()?;
        let ev = g.client.conn.on_packet(&payload)?;
        match ev {
            ChannelEvent::OpenConfirmed { channel } if channel == local_id => {
                opened = true;
            }
            ChannelEvent::OpenFailed { channel, .. } if channel == local_id => {
                return Err(Error::Protocol(open_failed_msg(what)));
            }
            other => dispatch_event(&mut *g, other),
        }
    }

    g.client.maybe_send_auth_agent_req(local_id)?;
    g.client.maybe_send_x11_req(local_id)?;
    g.client.maybe_send_env(local_id)?;
    g.queues.entry(local_id).or_default();
    Ok(local_id)
}

/// Open a `direct-tcpip` channel under an already-held lock guard.
/// Direct-tcpip channels don't take a follow-on request — once the open
/// is confirmed, the channel is ready for raw byte I/O.
fn open_direct_tcpip_under_lock(
    g: &mut Inner,
    dest_host: &str,
    dest_port: u16,
    orig_host: &str,
    orig_port: u16,
) -> Result<u32> {
    let (local_id, open_payload) = g.client.conn.open(ChannelOpen::DirectTcpip {
        dest_host: dest_host.to_string(),
        dest_port: dest_port as u32,
        orig_host: orig_host.to_string(),
        orig_port: orig_port as u32,
    })?;
    g.client.write_payload(&open_payload)?;

    let mut iter_guard = 0usize;
    loop {
        iter_guard += 1;
        if iter_guard > MAX_OPEN_ITER {
            return Err(Error::Protocol(open_loop_msg("direct-tcpip")));
        }
        let payload = g.client.read_one_packet()?;
        let ev = g.client.conn.on_packet(&payload)?;
        match ev {
            ChannelEvent::OpenConfirmed { channel } if channel == local_id => break,
            ChannelEvent::OpenFailed { channel, .. } if channel == local_id => {
                return Err(Error::Protocol(open_failed_msg("direct-tcpip")));
            }
            other => dispatch_event(&mut *g, other),
        }
    }
    g.queues.entry(local_id).or_default();
    Ok(local_id)
}

/// Send a channel request and drain inbound packets until the matching
/// Success / Failure lands. Other channels' events are stashed.
fn send_request_and_await(
    g: &mut Inner,
    local_id: u32,
    req: ChannelRequest,
    what: &'static str,
) -> Result<()> {
    let payload = g.client.conn.send_request(local_id, req, true)?;
    g.client.write_payload(&payload)?;

    let mut iter_guard = 0usize;
    loop {
        iter_guard += 1;
        if iter_guard > MAX_OPEN_ITER {
            return Err(Error::Protocol(reply_loop_msg(what)));
        }
        let payload = g.client.read_one_packet()?;
        let ev = g.client.conn.on_packet(&payload)?;
        match ev {
            ChannelEvent::Success { channel } if channel == local_id => return Ok(()),
            ChannelEvent::Failure { channel } if channel == local_id => {
                return Err(Error::Protocol(reply_failed_msg(what)));
            }
            other => dispatch_event(&mut *g, other),
        }
    }
}

/// Produce a `&'static str` for an open-loop divergence message. Hard-codes
/// the known short tags so we don't have to allocate or use `format!` in
/// an error path that returns `Error::Protocol(&'static str)`.
fn open_loop_msg(what: &'static str) -> &'static str {
    match what {
        "sftp" => "sftp: open loop did not converge",
        "exec" => "exec: open loop did not converge",
        "shell" => "shell: open loop did not converge",
        "direct-tcpip" => "direct-tcpip: open loop did not converge",
        _ => "channel: open loop did not converge",
    }
}

fn open_failed_msg(what: &'static str) -> &'static str {
    match what {
        "sftp" => "sftp: channel open failed",
        "exec" => "exec: channel open failed",
        "shell" => "shell: channel open failed",
        "direct-tcpip" => "direct-tcpip: open failed",
        _ => "channel: open failed",
    }
}

fn reply_loop_msg(what: &'static str) -> &'static str {
    match what {
        "sftp: subsystem" => "sftp: subsystem-reply loop did not converge",
        "exec: command" => "exec: command-reply loop did not converge",
        "shell: pty-req" => "shell: pty-req-reply loop did not converge",
        "shell: shell-req" => "shell: shell-req-reply loop did not converge",
        _ => "channel: request-reply loop did not converge",
    }
}

fn reply_failed_msg(what: &'static str) -> &'static str {
    match what {
        "sftp: subsystem" => "sftp: subsystem request denied",
        "exec: command" => "exec: command request denied",
        "shell: pty-req" => "shell: pty-req denied",
        "shell: shell-req" => "shell: shell-req denied",
        _ => "channel: request denied",
    }
}

/// Get-or-create the [`Condvar`] for `channel`. Returned as an `Arc` so
/// the caller can hold a clone while releasing the [`Inner`] mutex
/// inside [`Condvar::wait_timeout`].
fn notifier_for(g: &mut Inner, channel: u32) -> Arc<Condvar> {
    g.notifiers
        .entry(channel)
        .or_insert_with(|| Arc::new(Condvar::new()))
        .clone()
}

/// File the inbound event into the right mailbox **and** wake any
/// waiter sleeping on the target channel's notifier. The pump path and
/// the under-lock open helpers both go through this so the CV
/// notification can't be forgotten on one path and not the other.
fn dispatch_event(g: &mut Inner, ev: ChannelEvent) {
    let target = match &ev {
        ChannelEvent::Data { channel, .. }
        | ChannelEvent::ExtendedData { channel, .. }
        | ChannelEvent::Eof { channel }
        | ChannelEvent::Close { channel } => Some(*channel),
        _ => None,
    };
    stash_event(&mut g.queues, ev);
    if let Some(ch) = target
        && let Some(cv) = g.notifiers.get(&ch)
    {
        cv.notify_all();
    }
}

/// File the inbound `ChannelEvent` into the appropriate per-channel
/// mailbox. Window-adjust events have already updated
/// `ConnectionState`'s internal flow-control bookkeeping inside
/// `on_packet`, so we don't need to touch them here. Open/close/request
/// events on channels other than the one we're actively opening are
/// dropped (we don't currently expose a global event API on the shared
/// client).
///
/// Pure routing — does **not** notify any [`Condvar`]. Use
/// [`dispatch_event`] from runtime paths; this helper is kept separate
/// so it can be unit-tested without constructing an [`Inner`] (which
/// requires a real [`Client`]).
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
        ChannelEvent::Request {
            channel, request, ..
        } => {
            // Capture exit-status / exit-signal so the caller can
            // surface a meaningful exit code from an interactive shell
            // / exec stream. All other request types (eow, env, etc.)
            // are silently dropped — we don't currently surface them.
            let q = queues.entry(channel).or_default();
            match request {
                ChannelRequest::ExitStatus { code } => q.exit_status = Some(code as i32),
                ChannelRequest::ExitSignal { name, .. } => q.exit_signal = Some(name),
                _ => {}
            }
        }
        _ => {}
    }
}

/// Receive-window credit, under an already-held [`Inner`] lock guard,
/// for `n` bytes that the consumer just drained out of its channel's
/// mailbox. If the connection-state asks us to emit a
/// `SSH_MSG_CHANNEL_WINDOW_ADJUST`, that payload is written here. This
/// is the **single point** at which window credit goes back to the
/// peer — the pumper deliberately does not credit on enqueue, so a
/// reader that stops draining lets the SSH per-channel window cap the
/// in-memory mailbox at the initial window size.
fn replenish_under_lock(g: &mut Inner, channel: u32, n: u32) -> std::io::Result<()> {
    if n == 0 {
        return Ok(());
    }
    if let Some(adj) = g.client.conn.replenish_window(channel, n).map_err(io_err)? {
        g.client.write_payload(&adj).map_err(io_err)?;
    }
    Ok(())
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

/// Which queue inside a [`ChannelQueue`] a drain or stash should target.
#[derive(Clone, Copy)]
enum Stream {
    /// `SSH_MSG_CHANNEL_DATA` — stdout / main payload.
    Data,
    /// `SSH_MSG_CHANNEL_EXTENDED_DATA` — stderr (the only extended type
    /// SSH currently defines).
    Stderr,
}

impl OwnedChannelStream {
    /// Local channel id this stream owns. Pass this to
    /// [`SharedClient::send_window_change`] (or any sibling control
    /// method that takes a channel id) when driving the channel from a
    /// thread that doesn't own the stream.
    pub fn channel_id(&self) -> u32 {
        self.channel
    }

    /// Send `SSH_MSG_CHANNEL_EOF` on this channel — half-close our
    /// write side without closing the channel. The peer can still send
    /// us data; we just won't send any more. Idempotent: calling twice
    /// is a no-op.
    ///
    /// Interactive shell consumers call this when local stdin hits
    /// EOF — telling the remote shell "no more input is coming" so it
    /// can exit cleanly.
    pub fn send_eof(&mut self) -> std::io::Result<()> {
        let mut g = lock_or_poison_io(&self.shared.inner)?;
        let q = g.queues.entry(self.channel).or_default();
        if q.local_eof_sent {
            return Ok(());
        }
        q.local_eof_sent = true;
        let payload = g.client.conn.send_eof(self.channel).map_err(io_err)?;
        g.client.write_payload(&payload).map_err(io_err)?;
        Ok(())
    }

    /// Snapshot of the most recent `exit-status` request the peer sent
    /// on this channel (RFC 4254 §6.10). `None` until a request lands.
    /// Drain the stream to EOF before calling — exit-status normally
    /// arrives just before the peer sends EOF/CLOSE.
    pub fn exit_status(&self) -> Option<i32> {
        let g = self.shared.inner.lock().ok()?;
        g.queues.get(&self.channel).and_then(|q| q.exit_status)
    }

    /// Snapshot of the most recent `exit-signal` request name (e.g.
    /// `"TERM"`, `"KILL"`) the peer sent on this channel, if any.
    pub fn exit_signal(&self) -> Option<String> {
        let g = self.shared.inner.lock().ok()?;
        g.queues
            .get(&self.channel)
            .and_then(|q| q.exit_signal.clone())
    }

    /// Drain bytes from the chosen stream of the given channel queue
    /// into `buf`. Returns the number of bytes written. Caller is
    /// responsible for window replenishment.
    fn drain_into(queue: &mut ChannelQueue, stream: Stream, buf: &mut [u8]) -> usize {
        let src = match stream {
            Stream::Data => &mut queue.data,
            Stream::Stderr => &mut queue.stderr,
        };
        // Iterate up to `buf.len()` slots, but stop as soon as `src` empties.
        // `zip` with `pop_front()` returning `Option<u8>` would shorten the
        // sequence early on its own; the `while let` form keeps the loop body
        // panic-free without needing the previous `unwrap()` after a manual
        // `min` (which assumed `src.len()` couldn't change under our feet).
        let mut n = 0;
        for slot in buf.iter_mut() {
            match src.pop_front() {
                Some(b) => {
                    *slot = b;
                    n += 1;
                }
                None => break,
            }
        }
        n
    }

    /// Shared body for `Read::read` (stdout) and [`read_stderr`]
    /// (stderr). Drains from the chosen [`Stream`] or pumps until data
    /// arrives, replenishing the receive window for whatever it
    /// drained — the single backpressure point.
    ///
    /// [`read_stderr`]: Self::read_stderr
    fn read_stream(&mut self, stream: Stream, buf: &mut [u8]) -> std::io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let _ticket = LockTicket::new(&self.shared.lock_waiters);
        loop {
            let mut g = lock_or_poison_io(&self.shared.inner)?;
            // 1. Drain our mailbox if non-empty.
            let queue = g.queues.entry(self.channel).or_default();
            let avail = match stream {
                Stream::Data => !queue.data.is_empty(),
                Stream::Stderr => !queue.stderr.is_empty(),
            };
            if avail {
                let n = Self::drain_into(queue, stream, buf);
                // Single point of receive-window credit: replenish only
                // for what we just drained. Extended-data shares the
                // same window as data per RFC 4254.
                replenish_under_lock(&mut g, self.channel, n as u32)?;
                return Ok(n);
            }
            // 2. EOF for our channel (with no buffered bytes) is the
            //    standard zero-byte-read signal.
            if queue.remote_eof {
                return Ok(0);
            }
            // 3. Become pumper or wait on our channel's notifier. Each
            //    pump iteration releases and re-acquires the inner lock
            //    (the outer `loop` drops `g` on continue) so concurrent
            //    write threads on sibling channels — or the write half of
            //    the same channel in an interactive shell — get a chance
            //    to push their data through. When a read timeout is
            //    configured (via `Client::set_read_timeout`), the pumper
            //    additionally yields the lock every timeout interval even
            //    while no bytes are arriving.
            if !g.pumping {
                g.pumping = true;
                let res = Self::pump_one_step(&mut g);
                g.pumping = false;
                // Wake one waiter per registered channel. The pumper
                // already notified the target channel's CV inside
                // dispatch_event; this catches any waiter that was
                // sleeping on a *different* channel and now has a chance
                // to become the next pumper.
                for cv in g.notifiers.values() {
                    cv.notify_one();
                }
                drop(g);
                res?;
                // std::sync::Mutex on Linux is not fair: a thread that
                // releases and immediately re-acquires can starve a
                // contended waiter (writers, or sibling readers on the
                // same / a different channel). Check the lock-waiters
                // counter (bumped by every read/write entry point via
                // [`LockTicket`]) and, if more than just self is
                // contending, sleep long enough for the kernel to
                // schedule the waiter onto the freshly-released mutex
                // before we re-acquire. When no one else is waiting we
                // keep the short 100 µs yield — it's enough for sibling
                // channels' read paths to grab the lock without
                // measurably hurting bulk throughput.
                if self
                    .shared
                    .lock_waiters
                    .load(core::sync::atomic::Ordering::SeqCst)
                    > 1
                {
                    std::thread::sleep(Duration::from_millis(1));
                } else {
                    std::thread::sleep(Duration::from_micros(100));
                }
                // Loop: drop above released the lock so siblings can
                // squeeze in; we'll re-acquire at the top.
            } else {
                let cv = notifier_for(&mut g, self.channel);
                // Bounded wait so a missed notify (e.g. pumper panicked
                // and unwound through the mutex guard) cannot strand us.
                // Explicitly drop the re-acquired guard so the next loop
                // iteration starts clean.
                let waited = cv.wait_timeout(g, WAIT_TIMEOUT).map_err(|_| {
                    std::io::Error::new(
                        std::io::ErrorKind::BrokenPipe,
                        "SharedClient mutex poisoned",
                    )
                })?;
                drop(waited.0);
            }
        }
    }

    /// Read from the stderr (extended-data) side of this channel.
    /// Same semantics as [`Read::read`] but drains the channel's
    /// `SSH_MSG_CHANNEL_EXTENDED_DATA` stream instead of the main one.
    ///
    /// Backpressure: the receive-window credit is shared between data
    /// and stderr per RFC 4254 §5.2, so calling this drains the same
    /// pool that `read` does — a consumer that ignores stderr will
    /// eventually stall the data side too. Read both, or read neither.
    pub fn read_stderr(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.read_stream(Stream::Stderr, buf)
    }

    /// Pump exactly one packet off the wire under an already-held
    /// [`Inner`] lock guard, decode it, and file the resulting event
    /// into the right mailbox via [`dispatch_event`] (which also wakes
    /// any waiter sleeping on that channel's notifier).
    ///
    /// Does **not** replenish the receive window — the drain path in
    /// [`Read::read`] owns that, so the SSH per-channel window can
    /// backpressure the peer if no one is reading.
    ///
    /// Does **not** auto-ack peer CLOSE. Local CLOSE is emitted from
    /// [`OwnedChannelStream`]'s [`Drop`] only, which keeps the wire
    /// emission rule trivially safe (one CLOSE per stream, period) and
    /// avoids a double-close race between the pumper and Drop.
    fn pump_one_step(g: &mut Inner) -> std::io::Result<()> {
        // Use the timeout-tolerant variant so a `Client::set_read_timeout`
        // configuration (used by the interactive shell to keep the inner
        // mutex from being held across long quiescent reads) returns
        // `Ok(None)` instead of `WouldBlock` / `TimedOut`. Either way the
        // pumper releases the lock immediately after this call and the
        // outer `read_stream` loop re-acquires it.
        let Some(payload) = g.client.read_one_packet_maybe_timeout().map_err(io_err)? else {
            return Ok(());
        };
        let ev = g.client.conn.on_packet(&payload).map_err(io_err)?;
        dispatch_event(g, ev);
        Ok(())
    }
}

impl Read for OwnedChannelStream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.read_stream(Stream::Data, buf)
    }
}

impl Write for OwnedChannelStream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let mut g = lock_or_poison_io(&self.shared.inner)?;
        loop {
            let (payload, taken) = g.client.conn.send_data(self.channel, buf).map_err(io_err)?;
            if taken > 0 {
                g.client.write_payload(&payload).map_err(io_err)?;
                return Ok(taken);
            }
            // Zero credit: peer either closed us, or hasn't extended the
            // send window yet. Check for close, otherwise become pumper
            // (or wait for one) so a window-adjust can land.
            let queue = g.queues.entry(self.channel).or_default();
            if queue.remote_close {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    "channel closed by peer mid-write",
                ));
            }
            if !g.pumping {
                g.pumping = true;
                let res = Self::pump_one_step(&mut g);
                g.pumping = false;
                for cv in g.notifiers.values() {
                    cv.notify_one();
                }
                res?;
            } else {
                let cv = notifier_for(&mut g, self.channel);
                g = cv
                    .wait_timeout(g, WAIT_TIMEOUT)
                    .map_err(|_| {
                        std::io::Error::new(
                            std::io::ErrorKind::BrokenPipe,
                            "SharedClient mutex poisoned",
                        )
                    })?
                    .0;
            }
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        // write_payload uses write_all on the underlying socket; no
        // user-level buffering to flush.
        Ok(())
    }
}

impl Transport for OwnedChannelStream {
    /// Forward the read timeout to the *jump* client's underlying TCP
    /// socket (the SharedClient this channel rides on). A timeout there
    /// bounds how long a blocking pump on this channel can park, which is
    /// what the serve / forwarding poll loops on a client running *over*
    /// this channel rely on.
    fn set_read_timeout(&mut self, t: Option<Duration>) -> std::io::Result<()> {
        self.shared.set_read_timeout(t).map_err(io_err)
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
        // Drain a bounded number of packets so the peer's matching
        // CLOSE is observed. Drop holds the mutex exclusively (Rust
        // ownership guarantees no other thread holds an
        // OwnedChannelStream-mediated lock right now), so we can pump
        // without consulting the `pumping` flag.
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
            if Self::pump_one_step(&mut g).is_err() {
                break;
            }
        }
        // Reclaim mailbox + notifier space.
        g.queues.remove(&self.channel);
        g.notifiers.remove(&self.channel);
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
        let n = OwnedChannelStream::drain_into(&mut q, Stream::Data, &mut buf);
        assert_eq!(n, 3);
        assert_eq!(&buf, b"hel");
        assert_eq!(q.data.iter().copied().collect::<Vec<_>>(), b"lo");
    }

    #[test]
    fn drain_into_overflow() {
        let mut q = ChannelQueue::default();
        q.data.extend(b"hi".iter().copied());
        let mut buf = [0u8; 8];
        let n = OwnedChannelStream::drain_into(&mut q, Stream::Data, &mut buf);
        assert_eq!(n, 2);
        assert_eq!(&buf[..2], b"hi");
        assert!(q.data.is_empty());
    }

    #[test]
    fn drain_into_stderr() {
        let mut q = ChannelQueue::default();
        q.stderr.extend(b"err".iter().copied());
        q.data.extend(b"std".iter().copied());
        let mut buf = [0u8; 8];
        let n = OwnedChannelStream::drain_into(&mut q, Stream::Stderr, &mut buf);
        assert_eq!(n, 3);
        assert_eq!(&buf[..3], b"err");
        assert!(q.stderr.is_empty());
        // Data side untouched.
        assert_eq!(q.data.iter().copied().collect::<Vec<_>>(), b"std");
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
    fn notifier_map_round_trips_arc_identity() {
        // notifier_for is a get-or-create helper; a second call for the
        // same channel id must return a CV that's `Arc::ptr_eq` to the
        // first, so a waiter cloned from one call wakes on a notify
        // issued through the other.
        let mut notifiers: BTreeMap<u32, Arc<Condvar>> = BTreeMap::new();
        let cv1 = notifiers
            .entry(7)
            .or_insert_with(|| Arc::new(Condvar::new()))
            .clone();
        let cv2 = notifiers
            .entry(7)
            .or_insert_with(|| Arc::new(Condvar::new()))
            .clone();
        assert!(Arc::ptr_eq(&cv1, &cv2));
        // Distinct channels get distinct CVs.
        let cv3 = notifiers
            .entry(9)
            .or_insert_with(|| Arc::new(Condvar::new()))
            .clone();
        assert!(!Arc::ptr_eq(&cv1, &cv3));
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
