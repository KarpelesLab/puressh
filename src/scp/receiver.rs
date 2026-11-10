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

use super::protocol::{Header, ScpError, read_header, read_payload_term, write_fatal, write_ok};

/// Default cap on a single incoming file's payload size: 64 GiB. See
/// [`Receiver::with_max_file_size`].
pub const DEFAULT_MAX_FILE_SIZE: u64 = 64 * 1024 * 1024 * 1024;

/// Knobs for [`Receiver`].
#[derive(Default, Clone, Copy)]
#[non_exhaustive]
pub struct ScpRecvOptions {
    /// Accept `D`/`E` headers (`scp -r`). When false, any `D`/`E` is a
    /// protocol violation.
    pub recursive: bool,
    /// `scp -p`: apply `T` time preambles to the next file/dir, and give
    /// every file and directory exactly the mode the peer sent, existing
    /// ones included. When false, `T` preambles are still accepted but
    /// silently ignored, and as with OpenSSH's sink the peer's mode only
    /// applies to what the transfer creates, reduced by the process umask
    /// and without setuid, setgid or sticky bits.
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
    stack: Vec<DirLevel>,
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
    /// names) leaves confinement to `validate_name` + `guard_path`, plus
    /// `top_level_filter` when the caller sets one.
    expected_name: Option<String>,
    /// Set once the first file has been received in `expected_name` mode,
    /// so a second `C` can be rejected.
    received_one: bool,
    /// CVE-2019-6111 countermeasure for glob and recursive requests: when
    /// set, every top-level `C`/`D` name (outside any `D` the receiver has
    /// entered) must satisfy this predicate, typically "matches one of the
    /// requested basename patterns", as OpenSSH's sink does.
    top_level_filter: Option<NameFilter>,
}

/// A directory the receiver has entered.
struct DirLevel {
    path: PathBuf,
    /// What to do to its mode once its `E` arrives: while it is being
    /// filled, a directory the transfer made stays writable for us.
    on_end: Option<DirMode>,
}

#[derive(Clone, Copy)]
enum DirMode {
    /// `-p`: exactly this mode.
    Set(u32),
    /// A new directory, without `-p`: take back the owner bits that were
    /// added to the peer's mode so it could be filled.
    Drop(u32),
}

/// Predicate on a top-level entry name, see [`Receiver::with_top_level_filter`].
type NameFilter = Box<dyn Fn(&str) -> bool + Send + Sync>;

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
        // `canonicalize` requires the path to exist, but the ordinary
        // `scp remote:foo /tmp/newfile` case names a destination file that
        // does not exist yet. Canonicalizing the parent and re-attaching the
        // basename keeps `base` symlink-resolved — which is what
        // `guard_path` relies on — without demanding the target pre-exist.
        // A missing *parent* is still an error: we will not create one.
        let canon_base = match fs::canonicalize(base_path) {
            Ok(p) => p,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                let name = base_path
                    .file_name()
                    .ok_or(ScpError::Unexpected("scp: destination has no file name"))?;
                let parent = match base_path.parent() {
                    Some(p) if !p.as_os_str().is_empty() => p,
                    _ => Path::new("."),
                };
                fs::canonicalize(parent).map_err(ScpError::Io)?.join(name)
            }
            Err(e) => return Err(ScpError::Io(e)),
        };
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
            top_level_filter: None,
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

    /// Only accept top-level `C`/`D` records (those not inside a `D` the
    /// receiver has entered) whose name satisfies `filter`.
    ///
    /// Use this when the client cannot know the exact name it will get
    /// (a glob, brace or recursive request) but does know which names it
    /// asked for: `filter` typically matches the name against the
    /// requested basename pattern(s), so a malicious server cannot push
    /// arbitrary extra entries (e.g. `.bashrc`) into the destination
    /// directory. Entries below a top-level directory are not checked.
    pub fn with_top_level_filter(
        mut self,
        filter: impl Fn(&str) -> bool + Send + Sync + 'static,
    ) -> Self {
        self.top_level_filter = Some(Box::new(filter));
        self
    }

    /// Refuse a top-level name the [`Self::with_top_level_filter`]
    /// predicate rejects, before acking or touching the filesystem.
    fn check_top_level_name(&mut self, name: &str) -> Result<(), ScpError> {
        if self.stack.is_empty()
            && let Some(filter) = self.top_level_filter.as_ref()
            && !filter(name)
        {
            let msg = "filename does not match request";
            let _ = write_fatal(&mut self.stream, msg);
            return Err(ScpError::Unexpected("filename does not match request"));
        }
        Ok(())
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
                    self.check_top_level_name(&name)?;
                    self.recv_dir(mode, &name)?;
                }
                Header::EndDir => {
                    let Some(level) = self.stack.pop() else {
                        let _ = write_fatal(&mut self.stream, "E at top level");
                        return Err(ScpError::Unexpected("E at top level"));
                    };
                    if let Some(mode) = level.on_end {
                        finish_dir_mode(&level.path, mode);
                    }
                    // Reset pending_times — they pertained to the dir.
                    self.pending_times = None;
                    write_ok(&mut self.stream)?;
                }
                Header::File { mode, size, name } => {
                    self.check_top_level_name(&name)?;
                    self.recv_file(mode, size, &name)?;
                }
            }
        }
    }

    fn recv_dir(&mut self, mode: u32, name: &str) -> Result<(), ScpError> {
        // As with OpenSSH's sink, a top-level directory sent to a target
        // that is not an existing directory becomes the target itself
        // (`scp -r dir host:newname`).
        let target = if self.stack.is_empty() && self.opts.target_is_file {
            self.base.clone()
        } else {
            self.current_dir().join(name)
        };
        self.guard_path(&target)?;
        // If `target` already exists, it MUST be a real directory — not a
        // symlink (even one pointing into a directory), not a regular file.
        // `symlink_metadata` does not traverse the final component, so we
        // see the link as-is.
        let created = match fs::symlink_metadata(&target) {
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
                false
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                // Use `create_dir` (not `create_dir_all`) so we never
                // silently materialise intermediates that should have
                // been announced via `D` headers — they'd bypass the
                // `recv_dir` checks we just performed.
                //
                // Made with the peer's permission bits, which the kernel
                // reduces by the umask, plus ours to fill it (as OpenSSH's
                // sink: `mkdir(np, mode | S_IRWXU)`).
                if let Err(e) = create_dir_mode(&target, (mode & 0o777) | 0o700) {
                    let _ = write_fatal(&mut self.stream, &e.to_string());
                    return Err(ScpError::Io(e));
                }
                true
            }
            Err(e) => {
                let _ = write_fatal(&mut self.stream, &e.to_string());
                return Err(ScpError::Io(e));
            }
        };
        // The peer's mode is for what the transfer creates; a directory
        // that was already there keeps its own unless `-p` asks otherwise.
        // Either way it is applied when the directory is complete (`E`).
        let on_end = if self.opts.preserve_times {
            Some(DirMode::Set(mode & 0o7777))
        } else if created && mode & 0o700 != 0o700 {
            Some(DirMode::Drop(0o700 & !mode))
        } else {
            None
        };
        if let Some((mtime, atime)) = self.pending_times.take()
            && self.opts.preserve_times
        {
            let _ = set_times(&target, mtime, atime);
        }
        self.stack.push(DirLevel {
            path: target,
            on_end,
        });
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
        if let Some(cap) = self.max_file_size
            && size > cap
        {
            let msg = "file size exceeds configured maximum";
            let _ = write_fatal(&mut self.stream, msg);
            return Err(ScpError::Unexpected("file size exceeds configured maximum"));
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
        // Not truncated on open: as OpenSSH's sink, the file is cut to the
        // new size after the payload, so copying a file onto itself works.
        let mut open_opts = OpenOptions::new();
        open_opts.create(true).write(true).truncate(false);
        // On Unix, refuse to follow a symlink that races into existence
        // between the stat above and the open below. `O_NOFOLLOW` causes
        // `open(2)` to fail with `ELOOP` if the final component is a
        // symlink, which we surface as a fatal error.
        //
        // A file this creates gets the peer's permission bits, which the
        // kernel reduces by the umask; one that exists keeps its mode
        // (unless `-p`, below), as with OpenSSH's sink.
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            open_opts.custom_flags(libc::O_NOFOLLOW);
            open_opts.mode(mode & 0o777);
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
        if f.metadata().is_ok_and(|m| m.is_file()) {
            let _ = f.set_len(size);
        }
        // Apply mode + times. `-p` only: the peer's exact mode, on an
        // existing file too. Chmod the open fd, not the path — the
        // path-based variant would `chmod(2)` through any symlink
        // raced into place between this point and the call. `fchmod`
        // operates on the inode we already opened with `O_NOFOLLOW`,
        // closing the window entirely.
        #[cfg(unix)]
        if self.opts.preserve_times {
            use std::os::unix::fs::PermissionsExt;
            let _ = f.set_permissions(fs::Permissions::from_mode(mode & 0o7777));
        }
        #[cfg(not(unix))]
        let _ = mode;
        if let Some((mtime, atime)) = self.pending_times.take()
            && self.opts.preserve_times
        {
            let _ = set_times(&target, mtime, atime);
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
            Some(d) => d.path.clone(),
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

/// `mkdir(path, mode)`: the umask applies.
#[cfg(unix)]
fn create_dir_mode(path: &Path, mode: u32) -> std::io::Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    fs::DirBuilder::new().mode(mode).create(path)
}

#[cfg(not(unix))]
fn create_dir_mode(path: &Path, _mode: u32) -> std::io::Result<()> {
    fs::create_dir(path)
}

/// Give a received directory its final mode (best effort).
#[cfg(unix)]
fn finish_dir_mode(path: &Path, mode: DirMode) {
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    // Chmod a descriptor opened with `O_NOFOLLOW` instead of the path:
    // `fs::set_permissions` does a path-based `chmod(2)` that *follows*
    // symlinks, so a swap of the directory for a link would redirect the
    // chmod onto an arbitrary file. Opening refuses a symlink, and
    // `fchmod` then acts on the directory we opened.
    let Ok(dir) = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_DIRECTORY)
        .open(path)
    else {
        return;
    };
    let mode = match mode {
        DirMode::Set(mode) => mode,
        DirMode::Drop(bits) => match dir.metadata() {
            Ok(md) => md.permissions().mode() & 0o7777 & !bits,
            Err(_) => return,
        },
    };
    let _ = dir.set_permissions(fs::Permissions::from_mode(mode));
}

#[cfg(not(unix))]
fn finish_dir_mode(_path: &Path, mode: DirMode) {
    // Windows / other non-Unix: mode bits are not applied.
    let (DirMode::Set(bits) | DirMode::Drop(bits)) = mode;
    let _ = bits;
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
        .custom_flags(libc::O_NOFOLLOW)
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

/// XFER-12: whose mode a received file or directory gets.
#[cfg(all(test, unix))]
mod mode_tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    /// A scripted peer: what it sends, and somewhere for the acks.
    struct Script(std::io::Cursor<Vec<u8>>);

    impl Read for Script {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            self.0.read(buf)
        }
    }

    impl Write for Script {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
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
                .join(format!("puressh-recv-mode-{label}-{}", std::process::id()));
            let _ = fs::remove_dir_all(&dir);
            fs::create_dir_all(&dir).expect("tmp dir");
            Tmp(dir)
        }
    }

    impl Drop for Tmp {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn receive(dir: &Path, preserve: bool, script: &[u8]) {
        let opts = ScpRecvOptions {
            recursive: true,
            preserve_times: preserve,
            target_is_file: false,
        };
        Receiver::new(Script(std::io::Cursor::new(script.to_vec())), dir, opts)
            .expect("recv new")
            .run()
            .expect("recv run");
    }

    fn mode(p: &Path) -> u32 {
        fs::metadata(p).unwrap().permissions().mode() & 0o7777
    }

    fn chmod(p: &Path, mode: u32) {
        fs::set_permissions(p, fs::Permissions::from_mode(mode)).unwrap();
    }

    #[test]
    fn existing_objects_keep_their_mode_without_preserve() {
        let tmp = Tmp::new("existing");
        fs::write(tmp.0.join("f"), b"old contents").unwrap();
        chmod(&tmp.0.join("f"), 0o600);
        fs::create_dir(tmp.0.join("d")).unwrap();
        chmod(&tmp.0.join("d"), 0o700);
        receive(&tmp.0, false, b"C0666 1 f\nx\0D0777 0 d\nE\n");
        assert_eq!(fs::read(tmp.0.join("f")).unwrap(), b"x");
        assert_eq!(mode(&tmp.0.join("f")), 0o600);
        assert_eq!(mode(&tmp.0.join("d")), 0o700);
    }

    #[test]
    fn created_objects_get_the_permission_bits_only_without_preserve() {
        let tmp = Tmp::new("created");
        receive(
            &tmp.0,
            false,
            b"C6755 1 f\nx\0D7755 0 d\nE\nD0500 0 ro\nC0400 1 in\nx\0E\n",
        );
        // No setuid/setgid/sticky, and nothing the peer did not grant
        // (the umask may take more away).
        let f = mode(&tmp.0.join("f"));
        assert_eq!(f & !0o755, 0, "{f:o}");
        assert_eq!(f & 0o700, 0o700, "{f:o}");
        let d = mode(&tmp.0.join("d"));
        assert_eq!(d & !0o755 & !0o2000, 0, "{d:o}");
        // A directory the owner may not write to is still filled, then
        // loses the bits that were added for that.
        assert_eq!(fs::read(tmp.0.join("ro/in")).unwrap(), b"x");
        assert_eq!(mode(&tmp.0.join("ro")) & !0o2000, 0o500);
        assert_eq!(mode(&tmp.0.join("ro/in")), 0o400);
        chmod(&tmp.0.join("ro"), 0o700);
    }

    #[test]
    fn preserve_applies_the_peer_mode_to_everything() {
        let tmp = Tmp::new("preserve");
        fs::write(tmp.0.join("f"), b"old").unwrap();
        chmod(&tmp.0.join("f"), 0o600);
        fs::create_dir(tmp.0.join("d")).unwrap();
        chmod(&tmp.0.join("d"), 0o700);
        receive(
            &tmp.0,
            true,
            b"C0666 1 f\nx\0D0777 0 d\nC0640 1 new\nx\0E\nD0500 0 ro\nC0444 1 in\nx\0E\n",
        );
        assert_eq!(mode(&tmp.0.join("f")), 0o666);
        assert_eq!(mode(&tmp.0.join("d")), 0o777);
        assert_eq!(mode(&tmp.0.join("d/new")), 0o640);
        assert_eq!(mode(&tmp.0.join("ro")) & !0o2000, 0o500);
        assert_eq!(mode(&tmp.0.join("ro/in")), 0o444);
        chmod(&tmp.0.join("ro"), 0o700);
    }
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
        let dir = std::env::temp_dir().join(format!("puressh-recv-named-{}-{}-{}", label, pid, n));
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
