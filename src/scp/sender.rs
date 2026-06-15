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

use super::protocol::{Header, ScpError, read_ack, write_header, write_payload_term};

/// Knobs for [`Sender`].
#[derive(Default, Clone, Copy)]
pub struct ScpSendOptions {
    /// Walk directories recursively (`scp -r`).
    pub recursive: bool,
    /// Send `T` time-preamble headers before each `C`/`D` (`scp -p`).
    /// The peer applies them with `utime` post-write if it also has `-p`.
    pub preserve_times: bool,
}

/// Wraps the protocol stream and exposes the high-level send methods.
/// Each method returns once the *header acks* and the optional payload
/// terminator ack are drained from the peer; on protocol error the
/// stream is left in an undefined state.
pub struct Sender<S: Read + Write> {
    stream: S,
}

impl<S: Read + Write> Sender<S> {
    /// Wrap a transport. Before sending anything, the sender reads an
    /// initial `0x00` ack from the peer — OpenSSH `scp -t` issues one
    /// to signal "ready to receive".
    pub fn new(mut stream: S) -> Result<Self, ScpError> {
        read_ack(&mut stream)?;
        Ok(Self { stream })
    }

    /// Send one source. Routes to file or directory based on metadata;
    /// returns an error if `recursive == false` and `source` is a
    /// directory.
    pub fn send_path(&mut self, source: &Path, opts: &ScpSendOptions) -> Result<(), ScpError> {
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
    pub fn send_file(
        &mut self,
        source: &Path,
        md: &Metadata,
        opts: &ScpSendOptions,
    ) -> Result<(), ScpError> {
        if opts.preserve_times {
            let (mtime, atime) = times_of(md);
            write_header(&mut self.stream, &Header::Times { mtime, atime })?;
            read_ack(&mut self.stream)?;
        }
        let mode = mode_of(md);
        let name = basename_or(source)?;
        let size = md.len();
        write_header(
            &mut self.stream,
            &Header::File {
                mode,
                size,
                name: name.clone(),
            },
        )?;
        read_ack(&mut self.stream)?;
        let mut f = File::open(source).map_err(ScpError::Io)?;
        write_payload_term(&mut self.stream, &mut f, size)?;
        // OpenSSH expects an ack to the payload terminator.
        read_ack(&mut self.stream)?;
        Ok(())
    }

    /// Recursive directory send: emit `D` for the dir, then each child
    /// (sorted by name for determinism — matches OpenSSH 9.x), then
    /// `E` to pop.
    pub fn send_dir(&mut self, source: &Path, opts: &ScpSendOptions) -> Result<(), ScpError> {
        let md = std::fs::metadata(source).map_err(ScpError::Io)?;
        if opts.preserve_times {
            let (mtime, atime) = times_of(&md);
            write_header(&mut self.stream, &Header::Times { mtime, atime })?;
            read_ack(&mut self.stream)?;
        }
        let mode = mode_of(&md);
        let name = basename_or(source)?;
        write_header(
            &mut self.stream,
            &Header::Dir {
                mode,
                name: name.clone(),
            },
        )?;
        read_ack(&mut self.stream)?;

        let mut entries: Vec<PathBuf> = std::fs::read_dir(source)
            .map_err(ScpError::Io)?
            .filter_map(|r| r.ok().map(|e| e.path()))
            .collect();
        entries.sort();

        for child in entries {
            let cmd = std::fs::metadata(&child).map_err(ScpError::Io)?;
            if cmd.is_dir() {
                self.send_dir(&child, opts)?;
            } else if cmd.is_file() {
                self.send_file(&child, &cmd, opts)?;
            } else {
                // Skip sockets/fifos/etc, matching OpenSSH.
                continue;
            }
        }

        write_header(&mut self.stream, &Header::EndDir)?;
        read_ack(&mut self.stream)?;
        Ok(())
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
