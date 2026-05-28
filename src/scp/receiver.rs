//! Receiver side of SCP: consumes the protocol from a `Read+Write`
//! stream and writes files into a base directory. The peer is either a
//! remote `scp -f` (when we're downloading from a client), or a local
//! `scp -f`-equivalent source running in a server process feeding a
//! remote `scp -t`.
//!
//! The receiver maintains a *directory stack* (push on `D`, pop on `E`)
//! that determines where the next `C`/`D` lands. All file paths the
//! receiver writes to are checked against the original `base_path` for
//! lexical escape — names are validated by [`super::protocol::validate_name`]
//! at parse time, but a defence-in-depth check on the resolved path still
//! refuses anything that would land outside the base.

use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use super::protocol::{read_header, read_payload_term, write_fatal, write_ok, Header, ScpError};

/// Knobs for [`Receiver`].
#[derive(Default, Clone, Copy)]
pub struct ScpRecvOptions {
    /// Accept `D`/`E` headers (`scp -r`). When false, any `D`/`E` is a
    /// protocol violation.
    pub recursive: bool,
    /// Apply `T` time preambles to the next file/dir via `utimes`
    /// (`scp -p`). When false, `T` preambles are still accepted but
    /// silently ignored.
    pub preserve_times: bool,
    /// Treat `base_path` as the target *file path* for the first
    /// (non-directory) header rather than the destination directory.
    /// This matches `scp remote:foo /tmp/bar` where the local file
    /// should be `/tmp/bar` regardless of `foo`'s basename.
    ///
    /// Ignored once the receiver sees a `D` header — at that point
    /// `base_path` becomes the parent directory the tree is rooted at.
    pub target_is_file: bool,
}

/// Wraps the protocol stream and runs the receive loop. Each method
/// returns once the peer sends its terminating EOF (no more headers) or
/// emits a `0x02 ...\n` frame (surfaces as [`ScpError::Remote`]).
pub struct Receiver<S: Read + Write> {
    stream: S,
    base: PathBuf,
    /// Directory stack pushed by `D` and popped by `E`. The current
    /// directory for an incoming `C` is `stack.last()` when non-empty,
    /// else `base` (top level).
    stack: Vec<PathBuf>,
    /// Pending `T` preamble for the next `C`/`D`. Cleared after use.
    pending_times: Option<(i64, i64)>,
    opts: ScpRecvOptions,
}

impl<S: Read + Write> Receiver<S> {
    /// Wrap a transport. Sends the initial `0x00` ack to tell the peer
    /// "ready" — the OpenSSH convention is that the `-t` (toward)
    /// receiver sends ack before the first header.
    pub fn new(mut stream: S, base_path: &Path, opts: ScpRecvOptions) -> Result<Self, ScpError> {
        write_ok(&mut stream)?;
        Ok(Self {
            stream,
            base: base_path.to_path_buf(),
            stack: Vec::new(),
            pending_times: None,
            opts,
        })
    }

    /// Run the receive loop to completion. Reads headers in a loop and
    /// dispatches; returns `Ok(())` when the peer hangs up cleanly
    /// (`read_header` returns `None`), or an error otherwise.
    pub fn run(&mut self) -> Result<(), ScpError> {
        loop {
            let h = match read_header(&mut self.stream) {
                Ok(Some(h)) => h,
                Ok(None) => return Ok(()),
                Err(e) => {
                    // Try to surface a sensible fatal frame to the peer
                    // so its sender thread unblocks cleanly. Best-effort.
                    let _ = write_fatal(&mut self.stream, &e.to_string());
                    return Err(e);
                }
            };
            match h {
                Header::Times { mtime, atime } => {
                    self.pending_times = Some((mtime, atime));
                    write_ok(&mut self.stream)?;
                }
                Header::Dir { mode, name } => {
                    if !self.opts.recursive {
                        let msg = "directory entry but -r not set";
                        let _ = write_fatal(&mut self.stream, msg);
                        return Err(ScpError::Unexpected("directory entry but -r not set"));
                    }
                    self.recv_dir(mode, &name)?;
                }
                Header::EndDir => {
                    if self.stack.pop().is_none() {
                        let _ = write_fatal(&mut self.stream, "E at top level");
                        return Err(ScpError::Unexpected("E at top level"));
                    }
                    // Reset pending_times — they pertained to the dir.
                    self.pending_times = None;
                    write_ok(&mut self.stream)?;
                }
                Header::File { mode, size, name } => {
                    self.recv_file(mode, size, &name)?;
                }
            }
        }
    }

    fn recv_dir(&mut self, mode: u32, name: &str) -> Result<(), ScpError> {
        let parent = self.current_dir();
        let target = parent.join(name);
        self.guard_path(&target)?;
        if let Err(e) = fs::create_dir_all(&target) {
            let _ = write_fatal(&mut self.stream, &e.to_string());
            return Err(ScpError::Io(e));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&target, fs::Permissions::from_mode(mode & 0o7777));
        }
        #[cfg(not(unix))]
        let _ = mode;
        if let Some((mtime, atime)) = self.pending_times.take() {
            if self.opts.preserve_times {
                let _ = set_times(&target, mtime, atime);
            }
        }
        self.stack.push(target);
        write_ok(&mut self.stream)?;
        Ok(())
    }

    fn recv_file(&mut self, mode: u32, size: u64, name: &str) -> Result<(), ScpError> {
        let target = self.resolve_file_target(name);
        self.guard_path(&target)?;
        // Ack the C header — OpenSSH expects this before payload starts.
        write_ok(&mut self.stream)?;
        if let Some(parent) = target.parent() {
            // Best-effort: create intermediate dirs (only relevant when
            // target_is_file with a deep relative path).
            let _ = fs::create_dir_all(parent);
        }
        let f = match OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&target)
        {
            Ok(f) => f,
            Err(e) => {
                let _ = write_fatal(&mut self.stream, &e.to_string());
                return Err(ScpError::Io(e));
            }
        };
        let mut f = f;
        if let Err(e) = read_payload_term(&mut self.stream, &mut f, size) {
            // Try to write fatal so the peer unblocks.
            let _ = write_fatal(&mut self.stream, &e.to_string());
            return Err(e);
        }
        // Apply mode + times.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&target, fs::Permissions::from_mode(mode & 0o7777));
        }
        #[cfg(not(unix))]
        let _ = mode;
        if let Some((mtime, atime)) = self.pending_times.take() {
            if self.opts.preserve_times {
                let _ = set_times(&target, mtime, atime);
            }
        }
        // Ack the payload.
        write_ok(&mut self.stream)?;
        Ok(())
    }

    fn current_dir(&self) -> PathBuf {
        match self.stack.last() {
            Some(d) => d.clone(),
            None => self.base.clone(),
        }
    }

    /// Pick the file path for an incoming `C`. At top level with
    /// `target_is_file == true`, the base path itself is the target;
    /// otherwise the file lands inside the current directory under its
    /// basename.
    fn resolve_file_target(&self, name: &str) -> PathBuf {
        if self.stack.is_empty() && self.opts.target_is_file {
            self.base.clone()
        } else {
            self.current_dir().join(name)
        }
    }

    /// Lexical-escape guard: the resolved path (after `..` normalisation)
    /// must remain under `base`. The receiver never follows symlinks on
    /// directory components for traversal — they're created fresh — so
    /// this check is sufficient.
    fn guard_path(&mut self, target: &Path) -> Result<(), ScpError> {
        let norm = lexical_normalize(target);
        let base_norm = lexical_normalize(&self.base);
        if !norm.starts_with(&base_norm) && norm != base_norm {
            let _ = write_fatal(&mut self.stream, "path escapes base directory");
            return Err(ScpError::PathEscape);
        }
        Ok(())
    }
}

/// Drop `.` components, fold `..` against the preceding non-`..` segment
/// (or leave it dangling on absolute paths — which then can't `starts_with`
/// any base under the current root, surfacing as escape).
fn lexical_normalize(p: &Path) -> PathBuf {
    let mut out: Vec<std::path::Component<'_>> = Vec::new();
    for comp in p.components() {
        match comp {
            std::path::Component::ParentDir => {
                // Only fold over a Normal component; keep an absolute
                // root, and leave dangling `..` so escape is observable.
                if let Some(std::path::Component::Normal(_)) = out.last() {
                    out.pop();
                } else {
                    out.push(comp);
                }
            }
            std::path::Component::CurDir => {}
            other => out.push(other),
        }
    }
    let mut buf = PathBuf::new();
    for c in out {
        buf.push(c.as_os_str());
    }
    buf
}

#[cfg(unix)]
fn set_times(path: &Path, mtime: i64, atime: i64) -> std::io::Result<()> {
    use std::time::{Duration, SystemTime};
    let m = SystemTime::UNIX_EPOCH + Duration::from_secs(mtime.max(0) as u64);
    let a = SystemTime::UNIX_EPOCH + Duration::from_secs(atime.max(0) as u64);
    let f = std::fs::File::options().write(true).open(path)?;
    f.set_modified(m)?;
    // set_times is on FileTimes since 1.75; for now we set modified
    // (atime requires libc::utimes — defer to a follow-up).
    let _ = a;
    let _ = f;
    Ok(())
}

#[cfg(not(unix))]
fn set_times(_path: &Path, _mtime: i64, _atime: i64) -> std::io::Result<()> {
    Ok(())
}
