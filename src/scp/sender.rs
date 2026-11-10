//! Sender side of SCP: walks the local filesystem and drives the
//! protocol over a `Read+Write` stream. The peer is either a remote
//! `scp -t` (when we're uploading from a client), or a local
//! `scp -t`-equivalent receiver running in a client process consuming
//! a server-side `scp -f` source.
//!
//! The sender always **reads** an ack from the peer after each header
//! line and each payload body. A `0x02 ...\n` from the peer surfaces as
//! [`ScpError::Remote`] and ends the loop.

use std::fs::{File, Metadata};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use super::protocol::{Header, ScpError, read_ack, validate_name, write_header};

/// Knobs for [`Sender`].
#[derive(Default, Clone, Copy)]
#[non_exhaustive]
pub struct ScpSendOptions {
    /// Walk directories recursively (`scp -r`).
    pub recursive: bool,
    /// Send `T` time-preamble headers before each `C`/`D` (`scp -p`).
    /// The peer applies them with `utime` post-write if it also has `-p`.
    pub preserve_times: bool,
}

/// Wraps the protocol stream and exposes the high-level send methods.
/// Each method returns once the *header acks* and the optional payload
/// terminator ack are drained from the peer.
///
/// An error leaves the stream usable for the next source when nothing of
/// the failed one is outstanding: the source could not be read before its
/// header was sent, the peer refused it with a warning, or its payload
/// was completed with padding. Any other error (the transport failing, a
/// fatal frame, a malformed ack) leaves the peer in an unknown state:
/// [`Sender::is_desynced`] is then true and every later send is refused
/// without writing, so a caller that carries on with its next source
/// cannot have it read as the previous one's contents.
pub struct Sender<S: Read + Write> {
    stream: S,
    desynced: bool,
}

/// What a send answers once the stream is out of sync.
const DESYNCED: ScpError = ScpError::Unexpected("stream out of sync after an earlier error");

impl<S: Read + Write> Sender<S> {
    /// Wrap a transport. Before sending anything, the sender reads an
    /// initial `0x00` ack from the peer — OpenSSH `scp -t` issues one
    /// to signal "ready to receive".
    pub fn new(mut stream: S) -> Result<Self, ScpError> {
        read_ack(&mut stream)?;
        Ok(Self {
            stream,
            desynced: false,
        })
    }

    /// Whether an earlier error left the peer in an unknown state: nothing
    /// more can be sent on this stream.
    pub fn is_desynced(&self) -> bool {
        self.desynced
    }

    /// Record the outcome of an exchange with the peer: anything but
    /// success or a warning (which the peer sends in place of an ack, and
    /// then waits for the next header) means the stream is lost.
    fn note<T>(&mut self, r: Result<T, ScpError>) -> Result<T, ScpError> {
        if let Err(e) = &r
            && !matches!(e, ScpError::Warning(_))
        {
            self.desynced = true;
        }
        r
    }

    /// Send a header and read its ack.
    fn exchange(&mut self, h: &Header) -> Result<(), ScpError> {
        let r = write_header(&mut self.stream, h).and_then(|()| read_ack(&mut self.stream));
        self.note(r)
    }

    /// Send one source. Routes to file or directory based on metadata;
    /// returns an error if `recursive == false` and `source` is a
    /// directory.
    pub fn send_path(&mut self, source: &Path, opts: &ScpSendOptions) -> Result<(), ScpError> {
        if self.desynced {
            return Err(DESYNCED);
        }
        let md = std::fs::metadata(source).map_err(ScpError::Io)?;
        if md.is_dir() {
            if !opts.recursive {
                return Err(ScpError::Unexpected("source is a directory but -r not set"));
            }
            self.send_dir(source, opts)
        } else if md.is_file() {
            self.send_file(source, &md, opts)
        } else {
            Err(ScpError::Unexpected("source is neither file nor directory"))
        }
    }

    /// Send a single regular file. Emits `T` preamble (if requested),
    /// then `C<mode> <size> <basename>`, then payload + terminator,
    /// then awaits the post-payload ack.
    ///
    /// The file is opened before anything is sent, and the header carries
    /// the size and mode of the file that was opened (not `md`'s), so a
    /// file that cannot be read costs the peer nothing. If it turns out
    /// shorter than that size while it is read, the payload is completed
    /// with zeros and an error is sent in place of the terminator, as
    /// OpenSSH does: the stream stays in step and the error is returned.
    pub fn send_file(
        &mut self,
        source: &Path,
        md: &Metadata,
        opts: &ScpSendOptions,
    ) -> Result<(), ScpError> {
        if self.desynced {
            return Err(DESYNCED);
        }
        let _ = md;
        let name = basename_or(source)?;
        validate_name(&name)?;
        let mut f = File::open(source).map_err(ScpError::Io)?;
        let md = f.metadata().map_err(ScpError::Io)?;
        if !md.is_file() {
            return Err(ScpError::Unexpected("source is neither file nor directory"));
        }
        if opts.preserve_times {
            let (mtime, atime) = times_of(&md);
            self.exchange(&Header::Times { mtime, atime })?;
        }
        let mode = mode_of(&md);
        let size = md.len();
        self.exchange(&Header::File {
            mode,
            size,
            name: name.clone(),
        })?;
        self.send_payload(&mut f, &name, size)
    }

    /// The `size` payload bytes the `C` header for `name` announced, from
    /// `src`, then the terminator and its ack. Always `size` bytes: see
    /// [`Sender::send_file`].
    fn send_payload<R: Read>(
        &mut self,
        src: &mut R,
        name: &str,
        size: u64,
    ) -> Result<(), ScpError> {
        let mut local_err: Option<ScpError> = None;
        let mut remaining = size;
        let mut buf = [0u8; 32 * 1024];
        while remaining > 0 {
            let take = usize::try_from(remaining).map_or(buf.len(), |r| r.min(buf.len()));
            let n = if local_err.is_some() {
                take
            } else {
                match src.read(&mut buf[..take]) {
                    Ok(0) => {
                        local_err = Some(ScpError::Unexpected("local payload shorter than header"));
                        buf.fill(0);
                        continue;
                    }
                    Ok(n) => n,
                    Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                    Err(e) => {
                        local_err = Some(ScpError::Io(e));
                        buf.fill(0);
                        continue;
                    }
                }
            };
            let r = self.stream.write_all(&buf[..n]).map_err(ScpError::Io);
            self.note(r)?;
            remaining -= n as u64;
        }
        // The file's own ack: `0x00`, or the reason its contents are not
        // what they should be.
        let term = match &local_err {
            None => vec![0x00],
            Some(e) => {
                let reason = match e {
                    ScpError::Io(e) => e.to_string(),
                    _ => "file changed size during transfer".to_string(),
                };
                let mut frame = vec![0x01];
                frame.extend(
                    format!("scp: {name}: {reason}")
                        .bytes()
                        .map(|b| if b < 0x20 || b == 0x7f { b' ' } else { b }),
                );
                frame.push(b'\n');
                frame
            }
        };
        let r = self
            .stream
            .write_all(&term)
            .and_then(|()| self.stream.flush())
            .map_err(ScpError::Io);
        self.note(r)?;
        // OpenSSH expects an ack to the payload terminator.
        let ack = read_ack(&mut self.stream);
        match (self.note(ack), local_err) {
            // The peer's verdict on a stream that is now lost comes first.
            (Err(e), _) if self.desynced => Err(e),
            (_, Some(e)) | (Err(e), None) => Err(e),
            (Ok(()), None) => Ok(()),
        }
    }

    /// Recursive directory send: emit `D` for the dir, then each child
    /// (sorted by name for determinism — matches OpenSSH 9.x), then
    /// `E` to pop.
    ///
    /// A child that cannot be sent does not end the directory: the others
    /// follow, the `E` is sent, and the first such error is returned.
    pub fn send_dir(&mut self, source: &Path, opts: &ScpSendOptions) -> Result<(), ScpError> {
        if self.desynced {
            return Err(DESYNCED);
        }
        let name = basename_or(source)?;
        validate_name(&name)?;
        let md = std::fs::metadata(source).map_err(ScpError::Io)?;
        // Read before the `D` goes out: a directory that cannot be listed
        // must not leave the peer inside it.
        let mut entries: Vec<PathBuf> = std::fs::read_dir(source)
            .map_err(ScpError::Io)?
            .filter_map(|r| r.ok().map(|e| e.path()))
            .collect();
        entries.sort();

        if opts.preserve_times {
            let (mtime, atime) = times_of(&md);
            self.exchange(&Header::Times { mtime, atime })?;
        }
        let mode = mode_of(&md);
        self.exchange(&Header::Dir { mode, name })?;

        let mut first_err = None;
        for child in entries {
            let res = match std::fs::metadata(&child) {
                Ok(cmd) if cmd.is_dir() => self.send_dir(&child, opts),
                Ok(cmd) if cmd.is_file() => self.send_file(&child, &cmd, opts),
                // Skip sockets/fifos/etc, matching OpenSSH.
                Ok(_) => continue,
                Err(e) => Err(ScpError::Io(e)),
            };
            if let Err(e) = res {
                if self.desynced {
                    return Err(e);
                }
                first_err.get_or_insert(e);
            }
        }

        self.exchange(&Header::EndDir)?;
        first_err.map_or(Ok(()), Err)
    }

    /// Surface any pending stream bytes (e.g. on error). The mutable
    /// reference lets the SCP client drain stderr from the underlying
    /// channel without giving up ownership of the sender.
    pub fn stream_mut(&mut self) -> &mut S {
        &mut self.stream
    }
}

fn basename_or(p: &Path) -> Result<String, ScpError> {
    p.file_name()
        .and_then(|n| n.to_str())
        .map(|s| s.to_string())
        .ok_or(ScpError::BadName("non-UTF-8 basename"))
}

#[cfg(unix)]
fn mode_of(md: &Metadata) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    md.permissions().mode() & 0o7777
}

#[cfg(not(unix))]
fn mode_of(md: &Metadata) -> u32 {
    if md.permissions().readonly() {
        0o444
    } else if md.is_dir() {
        0o755
    } else {
        0o644
    }
}

fn times_of(md: &Metadata) -> (i64, i64) {
    let mtime = md
        .modified()
        .ok()
        .and_then(|t| t.duration_since(SystemTime::UNIX_EPOCH).ok())
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let atime = md
        .accessed()
        .ok()
        .and_then(|t| t.duration_since(SystemTime::UNIX_EPOCH).ok())
        .map(|d| d.as_secs() as i64)
        .unwrap_or(mtime);
    (mtime, atime)
}

/// XFER-15: an error on one source must not leave the peer reading the
/// next one as its contents.
#[cfg(test)]
mod sync_tests {
    use super::*;

    /// A scripted peer: the acks it will give, and what it was sent.
    struct Peer {
        acks: std::io::Cursor<Vec<u8>>,
        sent: Vec<u8>,
    }

    impl Peer {
        fn new(acks: &[u8]) -> Self {
            Peer {
                acks: std::io::Cursor::new(acks.to_vec()),
                sent: Vec::new(),
            }
        }
    }

    impl Read for Peer {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            self.acks.read(buf)
        }
    }

    impl Write for Peer {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.sent.extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    struct Tmp(PathBuf);

    impl Tmp {
        fn new(label: &str) -> Self {
            let dir = std::env::temp_dir()
                .join(format!("puressh-send-sync-{label}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).expect("tmp dir");
            Tmp(dir)
        }
    }

    impl Drop for Tmp {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn a_file_that_shrinks_is_padded_and_reported() {
        // Ready, then the ack of the padded payload.
        let mut s = Sender::new(Peer::new(b"\0\0")).unwrap();
        let mut short = &b"abc"[..];
        let err = s.send_payload(&mut short, "f", 8).unwrap_err();
        assert!(matches!(err, ScpError::Unexpected(_)), "{err:?}");
        assert_eq!(
            s.stream.sent,
            b"abc\0\0\0\0\0\x01scp: f: file changed size during transfer\n"
        );
        // Every announced byte went out: the next header is a header.
        assert!(!s.is_desynced());
    }

    #[test]
    fn a_complete_payload_ends_with_the_plain_terminator() {
        let mut s = Sender::new(Peer::new(b"\0\0")).unwrap();
        s.send_payload(&mut &b"abc"[..], "f", 3).unwrap();
        assert_eq!(s.stream.sent, b"abc\0");
        assert!(!s.is_desynced());
    }

    #[test]
    fn a_missing_source_sends_nothing_and_the_next_one_goes_through() {
        let tmp = Tmp::new("missing");
        std::fs::write(tmp.0.join("b"), b"B").unwrap();
        // Ready, then `b`'s header and payload acks.
        let mut s = Sender::new(Peer::new(b"\0\0\0")).unwrap();
        let opts = ScpSendOptions::default();
        let md = std::fs::metadata(tmp.0.join("b")).unwrap();
        // Gone between the caller's stat and the send: no header for it.
        assert!(s.send_file(&tmp.0.join("a"), &md, &opts).is_err());
        assert!(s.stream.sent.is_empty());
        assert!(!s.is_desynced());
        s.send_path(&tmp.0.join("b"), &opts).unwrap();
        let sent = String::from_utf8_lossy(&s.stream.sent).into_owned();
        assert!(
            sent.starts_with('C') && sent.ends_with(" 1 b\nB\0"),
            "{sent:?}"
        );
    }

    #[test]
    fn the_header_carries_the_opened_files_size() {
        let tmp = Tmp::new("size");
        std::fs::write(tmp.0.join("small"), b"12").unwrap();
        std::fs::write(tmp.0.join("big"), b"123456789").unwrap();
        let mut s = Sender::new(Peer::new(b"\0\0\0")).unwrap();
        // A stale stat (another file's) must not decide the size.
        let stale = std::fs::metadata(tmp.0.join("big")).unwrap();
        s.send_file(&tmp.0.join("small"), &stale, &ScpSendOptions::default())
            .unwrap();
        let sent = String::from_utf8_lossy(&s.stream.sent).into_owned();
        assert!(sent.ends_with(" 2 small\n12\0"), "{sent:?}");
    }

    #[cfg(unix)]
    #[test]
    fn an_unreadable_child_does_not_leave_the_peer_in_the_directory() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = Tmp::new("child");
        let dir = tmp.0.join("d");
        std::fs::create_dir(&dir).unwrap();
        std::fs::write(dir.join("a"), b"A").unwrap();
        std::fs::write(dir.join("b"), b"B").unwrap();
        std::fs::set_permissions(dir.join("a"), std::fs::Permissions::from_mode(0o000)).unwrap();
        if File::open(dir.join("a")).is_ok() {
            // Root reads anything: nothing to test.
            return;
        }
        let opts = ScpSendOptions {
            recursive: true,
            preserve_times: false,
        };
        // Ready, `D`, `b`'s header and payload, `E`.
        let mut s = Sender::new(Peer::new(b"\0\0\0\0\0")).unwrap();
        assert!(matches!(s.send_path(&dir, &opts), Err(ScpError::Io(_))));
        assert!(!s.is_desynced());
        let sent = String::from_utf8_lossy(&s.stream.sent).into_owned();
        let lines: Vec<&str> = sent.split('\n').collect();
        assert!(
            lines[0].starts_with('D') && lines[0].ends_with(" 0 d"),
            "{sent:?}"
        );
        assert!(
            lines[1].starts_with('C') && lines[1].ends_with(" 1 b"),
            "{sent:?}"
        );
        assert_eq!(&lines[2..], ["B\0E", ""], "{sent:?}");
    }

    #[test]
    fn a_lost_stream_refuses_later_sources_without_writing() {
        let tmp = Tmp::new("lost");
        std::fs::write(tmp.0.join("a"), b"A").unwrap();
        std::fs::write(tmp.0.join("b"), b"B").unwrap();
        let opts = ScpSendOptions::default();
        // Ready, `a`'s header acked, then the peer is gone.
        let mut s = Sender::new(Peer::new(b"\0\0")).unwrap();
        assert!(s.send_path(&tmp.0.join("a"), &opts).is_err());
        assert!(s.is_desynced());
        let before = s.stream.sent.len();
        assert!(matches!(
            s.send_path(&tmp.0.join("b"), &opts),
            Err(ScpError::Unexpected(_))
        ));
        assert_eq!(s.stream.sent.len(), before);
    }

    #[test]
    fn a_refused_file_leaves_the_stream_usable() {
        let tmp = Tmp::new("refused");
        std::fs::write(tmp.0.join("a"), b"A").unwrap();
        std::fs::write(tmp.0.join("b"), b"B").unwrap();
        let opts = ScpSendOptions::default();
        // Ready; `a`'s header refused with a warning; `b` accepted.
        let mut s = Sender::new(Peer::new(b"\0\x01scp: a: Permission denied\n\0\0")).unwrap();
        assert!(matches!(
            s.send_path(&tmp.0.join("a"), &opts),
            Err(ScpError::Warning(_))
        ));
        assert!(!s.is_desynced());
        s.send_path(&tmp.0.join("b"), &opts).unwrap();
        let sent = String::from_utf8_lossy(&s.stream.sent).into_owned();
        assert!(sent.ends_with(" 1 b\nB\0"), "{sent:?}");
        // `a`'s contents were not sent after the refusal.
        assert!(!sent.contains("\nA\0"), "{sent:?}");
    }
}
