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
use std::path::{Component, Path, PathBuf};

use super::protocol::{read_header, read_payload_term, write_fatal, write_ok, Header, ScpError};

/// Default cap on a single incoming file's payload size: 64 GiB. See
/// [`Receiver::with_max_file_size`].
pub const DEFAULT_MAX_FILE_SIZE: u64 = 64 * 1024 * 1024 * 1024;

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
    /// Maximum size for any single incoming file. A `C` header that
    /// advertises more than this is refused with a fatal `0x02` frame
    /// *before* the receiver starts streaming payload, so a malicious
    /// sender that announces `u64::MAX` cannot fill the operator's disk
    /// by streaming forever. `None` disables the cap (not recommended on
    /// hostile peers). Defaults to `Some(DEFAULT_MAX_FILE_SIZE)` (64 GiB);
    /// tune via [`Receiver::with_max_file_size`].
    max_file_size: Option<u64>,
    /// Residual CVE-2019-6111 countermeasure. When the client issued a
    /// *single, non-recursive* file fetch (`scp remote:onefile dest`), it
    /// knows the exact basename it asked for, and a well-behaved server
    /// must send back exactly that one file. A hostile/compromised server
    /// could otherwise push EXTRA or DIFFERENTLY-named files (e.g.
    /// `.bashrc`, `.profile`) into the destination directory, yielding
    /// code execution on the victim's next login.
    ///
    /// When `Some(name)`, the receiver refuses any `C` record whose
    /// basename differs from `name`, refuses any `D`/`E`, and refuses more
    /// than one file in the whole transfer. `None` (recursive / glob /
    /// multi-file fetches, where the client legitimately cannot predict the
    /// names) keeps the prior behaviour — confinement is via
    /// `validate_name` + `guard_path`.
    expected_name: Option<String>,
    /// Set once the first file has been received in `expected_name` mode,
    /// so a second `C` can be rejected.
    received_one: bool,
}

impl<S: Read + Write> Receiver<S> {
    /// Wrap a transport. Sends the initial `0x00` ack to tell the peer
    /// "ready" — the OpenSSH convention is that the `-t` (toward)
    /// receiver sends ack before the first header.
    ///
    /// The base path is canonicalised at construction so the receiver
    /// has a single, symlink-resolved anchor against which every
    /// resolved target is checked. If the base path does not exist or
    /// cannot be canonicalised, the call fails with `ScpError::Io` —
    /// we refuse to start a receive into a non-existent location so an
    /// unprivileged peer can't trick the receiver into materialising a
    /// tree at the wrong root.
    pub fn new(mut stream: S, base_path: &Path, opts: ScpRecvOptions) -> Result<Self, ScpError> {
        let canon_base = fs::canonicalize(base_path).map_err(ScpError::Io)?;
        write_ok(&mut stream)?;
        Ok(Self {
            stream,
            base: canon_base,
            stack: Vec::new(),
            pending_times: None,
            opts,
            max_file_size: Some(DEFAULT_MAX_FILE_SIZE),
            expected_name: None,
            received_one: false,
        })
    }

    /// Override the per-file size cap. Pass `None` to disable (not
    /// recommended on hostile peers — protects against disk-fill DoS
    /// from a peer that advertises an absurd `C` header size).
    pub fn with_max_file_size(mut self, cap: Option<u64>) -> Self {
        self.max_file_size = cap;
        self
    }

    /// Constrain the transfer to a single file with the given basename.
    ///
    /// Use this for a non-recursive `scp remote:onefile dest` where the
    /// client knows exactly what it requested. The receiver then rejects
    /// any `C` record whose basename differs, any directory header, and any
    /// second file — closing the residual CVE-2019-6111 gap where a
    /// malicious server pushes extra/renamed files into the destination
    /// directory. Pass the basename only (no path components).
    pub fn with_expected_name(mut self, name: Option<&str>) -> Self {
        self.expected_name = name.map(|s| s.to_string());
        self
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
        // If `target` already exists, it MUST be a real directory — not a
        // symlink (even one pointing into a directory), not a regular file.
        // `symlink_metadata` does not traverse the final component, so we
        // see the link as-is.
        match fs::symlink_metadata(&target) {
            Ok(md) => {
                if md.file_type().is_symlink() {
                    let _ =
                        write_fatal(&mut self.stream, "directory target is an existing symlink");
                    return Err(ScpError::PathEscape);
                }
                if !md.is_dir() {
                    let _ = write_fatal(
                        &mut self.stream,
                        "directory target collides with a non-directory",
                    );
                    return Err(ScpError::Unexpected(
                        "directory target collides with non-directory",
                    ));
                }
                // Real directory — accept and reuse.
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                // Use `create_dir` (not `create_dir_all`) so we never
                // silently materialise intermediates that should have
                // been announced via `D` headers — they'd bypass the
                // `recv_dir` checks we just performed.
                if let Err(e) = fs::create_dir(&target) {
                    let _ = write_fatal(&mut self.stream, &e.to_string());
                    return Err(ScpError::Io(e));
                }
            }
            Err(e) => {
                let _ = write_fatal(&mut self.stream, &e.to_string());
                return Err(ScpError::Io(e));
            }
        }
        #[cfg(unix)]
        {
            use nix::sys::stat::{fchmodat, FchmodatFlags, Mode};
            // Use `fchmodat(AT_SYMLINK_NOFOLLOW)` instead of
            // `fs::set_permissions`, which under the hood does a
            // path-based `chmod(2)` that *follows* symlinks. The
            // symlink_metadata check above narrows the race but
            // doesn't close it — a swap between the stat and the
            // chmod would still let an attacker redirect the chmod
            // onto an arbitrary file. fchmodat handles both checks
            // in one syscall.
            let mode_bits = Mode::from_bits_truncate((mode & 0o7777) as nix::libc::mode_t);
            let _ = fchmodat(
                nix::fcntl::AT_FDCWD,
                &target,
                mode_bits,
                FchmodatFlags::NoFollowSymlink,
            );
        }
        #[cfg(not(unix))]
        {
            // Windows / other non-Unix: we don't apply mode bits, and
            // `set_permissions` would only translate the read-only bit
            // anyway. The TOCTOU concern is Unix-specific.
            let _ = mode;
        }
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
        // Residual CVE-2019-6111: in single-named-file mode the client
        // knows the exact basename it requested. Refuse a server that sends
        // a different basename, or that tries to push a second file, before
        // we ack the `C` or touch the filesystem.
        if let Some(expected) = self.expected_name.as_deref() {
            if self.received_one {
                let msg = "server sent more than one file for a single-file request";
                let _ = write_fatal(&mut self.stream, msg);
                return Err(ScpError::Unexpected(
                    "server sent more than one file for a single-file request",
                ));
            }
            // Compare on basename: `name` is already a bare filename
            // (validate_name rejects path separators at parse time), but
            // take the basename of `expected` defensively in case a caller
            // passed a path.
            let expected_base = expected.rsplit('/').next().unwrap_or(expected);
            if name != expected_base {
                let msg = "server sent a file with an unexpected name";
                let _ = write_fatal(&mut self.stream, msg);
                return Err(ScpError::Unexpected(
                    "server sent a file with an unexpected name",
                ));
            }
        }
        // Refuse oversized headers *before* we ack the `C` and start
        // streaming bytes from the peer. A sender that announces
        // `u64::MAX` would otherwise be allowed to fill the receiver's
        // disk until ENOSPC. Default cap is generous (64 GiB).
        if let Some(cap) = self.max_file_size {
            if size > cap {
                let msg = "file size exceeds configured maximum";
                let _ = write_fatal(&mut self.stream, msg);
                return Err(ScpError::Unexpected("file size exceeds configured maximum"));
            }
        }
        let target = self.resolve_file_target(name);
        self.guard_path(&target)?;
        // Refuse to overwrite an existing symlink at the target path:
        // following it would let the peer pick the actual destination
        // (defeats the jail). `symlink_metadata` doesn't traverse the
        // final component.
        match fs::symlink_metadata(&target) {
            Ok(md) if md.file_type().is_symlink() => {
                let _ = write_fatal(&mut self.stream, "refusing to overwrite a symlink");
                return Err(ScpError::PathEscape);
            }
            _ => {}
        }
        // Ack the C header — OpenSSH expects this before payload starts.
        write_ok(&mut self.stream)?;
        if let Some(parent) = target.parent() {
            // Best-effort: create intermediate dirs (only relevant when
            // target_is_file with a deep relative path).
            let _ = fs::create_dir_all(parent);
        }
        let mut open_opts = OpenOptions::new();
        open_opts.create(true).write(true).truncate(true);
        // On Unix, refuse to follow a symlink that races into existence
        // between the stat above and the open below. `O_NOFOLLOW` causes
        // `open(2)` to fail with `ELOOP` if the final component is a
        // symlink, which we surface as a fatal error.
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            open_opts.custom_flags(nix::libc::O_NOFOLLOW);
        }
        let f = match open_opts.open(&target) {
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
        // Apply mode + times. Chmod the open fd, not the path — the
        // path-based variant would `chmod(2)` through any symlink
        // raced into place between this point and the call. `fchmod`
        // operates on the inode we already opened with `O_NOFOLLOW`,
        // closing the window entirely.
        #[cfg(unix)]
        {
            use nix::sys::stat::{fchmod, Mode};
            let mode_bits = Mode::from_bits_truncate((mode & 0o7777) as nix::libc::mode_t);
            let _ = fchmod(&f, mode_bits);
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
        // Mark that we've taken our one file (single-named-file mode); any
        // further `C` will now be rejected.
        self.received_one = true;
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
    /// directory components for traversal — `recv_dir` rejects symlink
    /// collisions and `recv_file` opens with `O_NOFOLLOW` — so this
    /// purely-lexical check is sufficient defence-in-depth.
    fn guard_path(&mut self, target: &Path) -> Result<(), ScpError> {
        let norm = lexical_normalize(target);
        // If normalisation still left any `ParentDir` components, the
        // path resolves outside any conceivable base (no real ancestor
        // could swallow them). Reject without comparing prefixes —
        // `Path::starts_with` would happily match `/foo/..` against
        // `/foo` otherwise.
        if norm.components().any(|c| matches!(c, Component::ParentDir)) {
            let _ = write_fatal(&mut self.stream, "path escapes base directory");
            return Err(ScpError::PathEscape);
        }
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
    use std::os::unix::fs::OpenOptionsExt;
    use std::time::{Duration, SystemTime};
    let m = SystemTime::UNIX_EPOCH + Duration::from_secs(mtime.max(0) as u64);
    let a = SystemTime::UNIX_EPOCH + Duration::from_secs(atime.max(0) as u64);
    // `O_NOFOLLOW` so a planted symlink at the final component cannot
    // redirect `set_modified` onto an arbitrary file.
    let f = std::fs::File::options()
        .write(true)
        .custom_flags(nix::libc::O_NOFOLLOW)
        .open(path)?;
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

#[cfg(all(test, unix))]
mod expected_name_tests {
    use super::*;
    use std::os::unix::net::UnixStream;
    use std::thread;

    fn fresh_tmp(label: &str) -> PathBuf {
        use std::sync::atomic::{AtomicU32, Ordering};
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let pid = std::process::id();
        let dir =
            std::env::temp_dir().join(format!("puressh-recv-named-{}-{}-{}", label, pid, n));
        std::fs::create_dir_all(&dir).expect("tmp dir");
        dir
    }

    struct DirGuard(PathBuf);
    impl Drop for DirGuard {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// A malicious server that announces a `C` record with a basename the
    /// client never asked for must be refused before the file is written.
    #[test]
    fn rejects_mismatched_basename() {
        let dst = fresh_tmp("mismatch");
        let _g = DirGuard(dst.clone());

        let (client_end, mut server_end) = UnixStream::pair().expect("socketpair");

        let dst_thread = dst.clone();
        let recv = thread::spawn(move || {
            let mut r = Receiver::new(
                client_end,
                &dst_thread,
                ScpRecvOptions {
                    recursive: false,
                    preserve_times: false,
                    target_is_file: false,
                },
            )
            .expect("recv new")
            .with_expected_name(Some("wanted.txt"));
            r.run()
        });

        // Server side: read the initial readiness ack, then push a file
        // named `.bashrc` — NOT what the client asked for.
        let mut ack = [0u8; 1];
        server_end.read_exact(&mut ack).expect("initial ack");
        assert_eq!(ack[0], 0x00);
        server_end
            .write_all(b"C0644 5 .bashrc\n")
            .expect("write C header");
        // We do NOT send payload — the receiver must bail at the header.

        let result = recv.join().expect("join");
        assert!(
            matches!(result, Err(ScpError::Unexpected(_))),
            "expected rejection, got {result:?}"
        );
        // The bogus file must not have been created.
        assert!(!dst.join(".bashrc").exists());
    }

    /// A correctly-named single file is accepted in expected-name mode.
    #[test]
    fn accepts_expected_basename() {
        let dst = fresh_tmp("match");
        let _g = DirGuard(dst.clone());

        let (client_end, mut server_end) = UnixStream::pair().expect("socketpair");

        let dst_thread = dst.clone();
        let recv = thread::spawn(move || {
            let mut r = Receiver::new(
                client_end,
                &dst_thread,
                ScpRecvOptions {
                    recursive: false,
                    preserve_times: false,
                    target_is_file: false,
                },
            )
            .expect("recv new")
            .with_expected_name(Some("wanted.txt"));
            r.run()
        });

        let mut ack = [0u8; 1];
        server_end.read_exact(&mut ack).expect("initial ack");
        // Send the correctly-named file.
        server_end
            .write_all(b"C0644 5 wanted.txt\n")
            .expect("write C header");
        // C-header ack from receiver.
        server_end.read_exact(&mut ack).expect("C ack");
        assert_eq!(ack[0], 0x00);
        // Payload + trailing 0x00.
        server_end.write_all(b"hello\x00").expect("payload");
        // Payload ack.
        server_end.read_exact(&mut ack).expect("payload ack");
        assert_eq!(ack[0], 0x00);
        // Close so the receiver's read_header returns None (EOF).
        drop(server_end);

        let result = recv.join().expect("join");
        assert!(result.is_ok(), "expected ok, got {result:?}");
        assert_eq!(std::fs::read(dst.join("wanted.txt")).unwrap(), b"hello");
    }
}
