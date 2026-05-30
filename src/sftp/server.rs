//! In-process SFTP v3 server session.
//!
//! [`SftpServerSession::run`] takes any `Read+Write` transport (typically a
//! channel stream from the SSH connection layer) and serves SFTP requests
//! until the peer closes. Each session owns a private virtual cwd, so
//! concurrent SFTP channels on the same process never share `chdir()`
//! state.

use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions, ReadDir};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use super::packet::{self, read_packet, write_packet, Packet};
use super::path::resolve;
use super::types::{
    Attrs, FxpStatus, NameEntry, SftpError, FXF_APPEND, FXF_CREAT, FXF_EXCL, FXF_READ, FXF_TRUNC,
    FXF_WRITE, SFTP_VERSION,
};

/// Default cap on client-requested `set_len` values (1 GiB). See
/// [`SftpServerOptions::max_set_len`].
pub const DEFAULT_MAX_SET_LEN: u64 = 1024 * 1024 * 1024;

/// Tunables for a single SFTP server session.
#[derive(Debug, Clone)]
pub struct SftpServerOptions {
    /// Initial virtual cwd for relative-path requests.
    pub cwd: PathBuf,
    /// Optional jail root.
    ///
    /// When set, every resolved path must lie inside this subtree.
    /// Operations that would open or stat through a symlink are additionally
    /// refused on Unix via `O_NOFOLLOW` / `symlink_metadata`, and absolute
    /// symlink targets are refused at create time.
    ///
    /// This is **best-effort** mitigation, not a full chroot. A confined
    /// daemon should still rely on operating-system mechanisms such as
    /// `openat2(RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS)` or a real
    /// `chroot(2)` for hard isolation.
    pub root: Option<PathBuf>,
    /// If `true`, refuse every mutating operation.
    pub read_only: bool,
    /// Maximum file size a client may set via `setstat`/`fsetstat`. Larger
    /// requests are refused with [`FxpStatus::PermissionDenied`]. Defaults
    /// to [`DEFAULT_MAX_SET_LEN`] (1 GiB).
    pub max_set_len: u64,
    /// If `false` (the default), the high bits of an incoming `permissions`
    /// attribute are masked to `0o0777` — refusing to honour setuid/setgid/
    /// sticky bits supplied by an SFTP peer. Set `true` only for trusted
    /// callers that need to upload mode bits verbatim.
    pub allow_special_bits: bool,
    /// When `true` and a jail is configured, `op_realpath` strips the
    /// jail prefix from the returned path so the client sees paths
    /// relative to the jail root (e.g. `/foo/bar` instead of
    /// `/srv/jail/u/foo/bar`). Defaults to `false` so the historical
    /// behaviour — returning the host-side absolute path — is preserved
    /// unless the operator explicitly opts in; new deployments that
    /// don't want to leak the host filesystem layout should set this
    /// to `true`.
    pub hide_jail_in_realpath: bool,
}

impl SftpServerOptions {
    /// Construct with the given virtual cwd. No jail; writable.
    pub fn new(cwd: impl Into<PathBuf>) -> Self {
        Self {
            cwd: cwd.into(),
            root: None,
            read_only: false,
            max_set_len: DEFAULT_MAX_SET_LEN,
            allow_special_bits: false,
            hide_jail_in_realpath: false,
        }
    }

    /// Apply a jail root.
    ///
    /// Best-effort mitigation only — see the field-level docs on
    /// [`SftpServerOptions::root`].
    pub fn with_root(mut self, root: impl Into<PathBuf>) -> Self {
        self.root = Some(root.into());
        self
    }

    /// Refuse mutating operations.
    pub fn read_only(mut self) -> Self {
        self.read_only = true;
        self
    }

    /// Override the cap on client-requested `set_len`. Pass `u64::MAX` to
    /// disable the cap (not recommended on hostile peers).
    pub fn with_max_set_len(mut self, max: u64) -> Self {
        self.max_set_len = max;
        self
    }

    /// Opt in to honouring setuid/setgid/sticky bits in incoming mode
    /// attributes. Off by default.
    pub fn allow_special_bits(mut self, allow: bool) -> Self {
        self.allow_special_bits = allow;
        self
    }

    /// Hide the jail prefix in `op_realpath` so the client sees paths
    /// relative to the jail root (`/foo/bar` instead of
    /// `/srv/jail/u/foo/bar`). Off by default to preserve historical
    /// behaviour.
    pub fn hide_jail_in_realpath(mut self, hide: bool) -> Self {
        self.hide_jail_in_realpath = hide;
        self
    }
}

// On Windows `std::fs::ReadDir` is much larger than on Unix (it carries the
// FindFirst handle + a 64 KiB-class `WIN32_FIND_DATA` buffer inline), which
// trips `clippy::large_enum_variant` even though the asymmetry is unavoidable
// at this layer. There's typically a single-digit number of open handles per
// SFTP session, so boxing the iterator just to silence the lint would cost an
// allocation per directory open with no measurable benefit.
#[allow(clippy::large_enum_variant)]
enum FileHandle {
    File {
        file: File,
        path: PathBuf,
        append: bool,
    },
    Dir {
        iter: Option<ReadDir>,
        path: PathBuf,
        eof_sent: bool,
    },
}

/// An SFTP server session. Holds open file/dir handles and the virtual cwd.
pub struct SftpServerSession {
    opts: SftpServerOptions,
    handles: BTreeMap<u64, FileHandle>,
    next: u64,
}

impl SftpServerSession {
    /// Construct a fresh session with the given options.
    pub fn new(opts: SftpServerOptions) -> Self {
        Self {
            opts,
            handles: BTreeMap::new(),
            next: 1,
        }
    }

    /// Drive the protocol on `t` until EOF or fatal error.
    ///
    /// The first packet must be `SSH_FXP_INIT`; this function replies with
    /// `SSH_FXP_VERSION` and then loops dispatching requests. Returns
    /// `Ok(())` on a clean peer-side EOF.
    pub fn run<T: Read + Write>(&mut self, mut t: T) -> Result<(), SftpError> {
        let body = read_packet(&mut t)?;
        match Packet::decode(&body)? {
            Packet::Init { version, .. } => {
                if version < 3 {
                    return Err(SftpError::Protocol("sftp: client version < 3"));
                }
            }
            _ => return Err(SftpError::Protocol("sftp: expected INIT")),
        }
        write_packet(
            &mut t,
            &Packet::Version {
                version: SFTP_VERSION,
                extensions: vec![],
            },
        )?;

        loop {
            let body = match read_packet(&mut t) {
                Ok(b) => b,
                Err(SftpError::Io(e))
                    if matches!(
                        e.kind(),
                        io::ErrorKind::UnexpectedEof
                            | io::ErrorKind::BrokenPipe
                            | io::ErrorKind::ConnectionReset
                    ) =>
                {
                    return Ok(());
                }
                Err(e) => return Err(e),
            };
            let pkt = Packet::decode(&body)?;
            let reply = self.handle_packet(pkt);
            write_packet(&mut t, &reply)?;
        }
    }

    fn handle_packet(&mut self, pkt: Packet) -> Packet {
        let id = pkt.id().unwrap_or(0);
        match self.dispatch(pkt) {
            Ok(reply) => reply,
            Err(e) => status_from_err(id, e),
        }
    }

    fn dispatch(&mut self, pkt: Packet) -> Result<Packet, SftpError> {
        match pkt {
            Packet::Open {
                id,
                path,
                pflags,
                attrs,
            } => self.op_open(id, path, pflags, attrs),
            Packet::Close { id, handle } => self.op_close(id, handle),
            Packet::Read {
                id,
                handle,
                offset,
                len,
            } => self.op_read(id, handle, offset, len),
            Packet::Write {
                id,
                handle,
                offset,
                data,
            } => self.op_write(id, handle, offset, data),
            Packet::Lstat { id, path } => self.op_stat(id, path, false),
            Packet::Stat { id, path } => self.op_stat(id, path, true),
            Packet::Fstat { id, handle } => self.op_fstat(id, handle),
            Packet::Setstat { id, path, attrs } => self.op_setstat(id, path, attrs),
            Packet::Fsetstat { id, handle, attrs } => self.op_fsetstat(id, handle, attrs),
            Packet::Opendir { id, path } => self.op_opendir(id, path),
            Packet::Readdir { id, handle } => self.op_readdir(id, handle),
            Packet::Remove { id, path } => self.op_remove(id, path),
            Packet::Mkdir { id, path, attrs } => self.op_mkdir(id, path, attrs),
            Packet::Rmdir { id, path } => self.op_rmdir(id, path),
            Packet::Realpath { id, path } => self.op_realpath(id, path),
            Packet::Rename {
                id,
                oldpath,
                newpath,
            } => self.op_rename(id, oldpath, newpath),
            Packet::Readlink { id, path } => self.op_readlink(id, path),
            Packet::Symlink {
                id,
                target_path,
                link_path,
            } => self.op_symlink(id, target_path, link_path),
            Packet::Extended { id, .. } => Ok(status_pkt(
                id,
                FxpStatus::OpUnsupported,
                "extension not supported",
            )),
            // INIT/VERSION mid-stream, or responses from a peer that should
            // be sending requests: both are protocol violations.
            _ => Err(SftpError::Protocol("sftp: unexpected packet from client")),
        }
    }

    fn alloc_handle(&mut self, h: FileHandle) -> Vec<u8> {
        // Skip any wrapped id that's still live (extremely unlikely with a
        // u64 counter but the previous code could in theory overwrite an
        // existing entry on wraparound).
        let mut id;
        loop {
            id = self.next;
            self.next = self.next.wrapping_add(1).max(1);
            if !self.handles.contains_key(&id) {
                break;
            }
        }
        self.handles.insert(id, h);
        id.to_le_bytes().to_vec()
    }

    fn resolve(&self, raw: &[u8]) -> Result<PathBuf, SftpError> {
        resolve(&self.opts.cwd, raw, self.opts.root.as_deref())
    }

    fn require_writable(&self) -> Result<(), SftpError> {
        if self.opts.read_only {
            Err(SftpError::status_msg(
                FxpStatus::PermissionDenied,
                "read-only server",
            ))
        } else {
            Ok(())
        }
    }

    fn op_open(
        &mut self,
        id: u32,
        path: Vec<u8>,
        pflags: u32,
        attrs: Attrs,
    ) -> Result<Packet, SftpError> {
        let p = self.resolve(&path)?;
        let want_write = pflags & (FXF_WRITE | FXF_APPEND) != 0;
        if want_write {
            self.require_writable()?;
        }
        let mut opt = OpenOptions::new();
        opt.read(pflags & FXF_READ != 0);
        if want_write {
            opt.write(true);
        }
        if pflags & FXF_APPEND != 0 {
            opt.append(true);
        }
        if pflags & FXF_TRUNC != 0 {
            opt.truncate(true);
        }
        if pflags & FXF_EXCL != 0 {
            opt.create_new(true);
        } else if pflags & FXF_CREAT != 0 {
            opt.create(true);
        }

        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            // Inside a jail, refuse to traverse a symlink at the final
            // component. Combined with the lexical jail check on the
            // resolved path, this prevents an attacker who planted (or
            // received-uploaded) a symlink inside the jail from escaping
            // via open. Best-effort: TOCTOU on intermediate components is
            // still possible — see SftpServerOptions::root for the real
            // confinement caveat.
            if self.opts.root.is_some() {
                opt.custom_flags(nix::libc::O_NOFOLLOW);
            }
            if let Some(perm) = attrs.permissions {
                let masked = mask_mode(perm, self.opts.allow_special_bits);
                opt.mode(masked);
            }
        }
        let _ = &attrs;

        let file = match opt.open(&p) {
            Ok(f) => f,
            Err(e) => return Err(map_open_err(e)),
        };
        let handle = self.alloc_handle(FileHandle::File {
            file,
            path: p,
            append: pflags & FXF_APPEND != 0,
        });
        Ok(Packet::Handle { id, handle })
    }

    fn op_close(&mut self, id: u32, handle: Vec<u8>) -> Result<Packet, SftpError> {
        let h = parse_handle(&handle)?;
        if self.handles.remove(&h).is_none() {
            return Ok(status_pkt(id, FxpStatus::Failure, "invalid handle"));
        }
        Ok(status_ok(id))
    }

    fn op_read(
        &mut self,
        id: u32,
        handle: Vec<u8>,
        offset: u64,
        len: u32,
    ) -> Result<Packet, SftpError> {
        let h = parse_handle(&handle)?;
        let entry = self
            .handles
            .get_mut(&h)
            .ok_or_else(|| SftpError::status_msg(FxpStatus::Failure, "invalid handle"))?;
        let file = match entry {
            FileHandle::File { file, .. } => file,
            _ => return Ok(status_pkt(id, FxpStatus::Failure, "handle is not a file")),
        };
        file.seek(SeekFrom::Start(offset))?;
        let cap = (len as usize).min((packet::MAX_PACKET_SIZE / 2) as usize);
        let mut buf = vec![0u8; cap];
        let n = file.read(&mut buf)?;
        if n == 0 {
            return Ok(status_pkt(id, FxpStatus::Eof, "eof"));
        }
        buf.truncate(n);
        Ok(Packet::Data { id, data: buf })
    }

    fn op_write(
        &mut self,
        id: u32,
        handle: Vec<u8>,
        offset: u64,
        data: Vec<u8>,
    ) -> Result<Packet, SftpError> {
        self.require_writable()?;
        let h = parse_handle(&handle)?;
        let entry = self
            .handles
            .get_mut(&h)
            .ok_or_else(|| SftpError::status_msg(FxpStatus::Failure, "invalid handle"))?;
        let (file, append) = match entry {
            FileHandle::File { file, append, .. } => (file, *append),
            _ => return Ok(status_pkt(id, FxpStatus::Failure, "handle is not a file")),
        };
        if !append {
            file.seek(SeekFrom::Start(offset))?;
        }
        file.write_all(&data)?;
        Ok(status_ok(id))
    }

    fn op_stat(&mut self, id: u32, path: Vec<u8>, follow: bool) -> Result<Packet, SftpError> {
        let p = self.resolve(&path)?;
        // Inside a jail, never traverse the final symlink: a symlink
        // pointing outside the jail would otherwise leak attributes.
        // (op_lstat below also lands here with `follow=false`.)
        let jailed = self.opts.root.is_some();
        let md = if follow && !jailed {
            fs::metadata(&p)?
        } else {
            fs::symlink_metadata(&p)?
        };
        Ok(Packet::Attrs {
            id,
            attrs: attrs_from_metadata(&md),
        })
    }

    fn op_fstat(&mut self, id: u32, handle: Vec<u8>) -> Result<Packet, SftpError> {
        let h = parse_handle(&handle)?;
        let entry = self
            .handles
            .get(&h)
            .ok_or_else(|| SftpError::status_msg(FxpStatus::Failure, "invalid handle"))?;
        let md = match entry {
            FileHandle::File { file, .. } => file.metadata()?,
            FileHandle::Dir { path, .. } => fs::metadata(path)?,
        };
        Ok(Packet::Attrs {
            id,
            attrs: attrs_from_metadata(&md),
        })
    }

    fn op_setstat(&mut self, id: u32, path: Vec<u8>, attrs: Attrs) -> Result<Packet, SftpError> {
        self.require_writable()?;
        let p = self.resolve(&path)?;
        apply_attrs(
            &p,
            &attrs,
            self.opts.root.is_some(),
            self.opts.max_set_len,
            self.opts.allow_special_bits,
        )?;
        Ok(status_ok(id))
    }

    fn op_fsetstat(&mut self, id: u32, handle: Vec<u8>, attrs: Attrs) -> Result<Packet, SftpError> {
        self.require_writable()?;
        let h = parse_handle(&handle)?;
        let p = match self
            .handles
            .get(&h)
            .ok_or_else(|| SftpError::status_msg(FxpStatus::Failure, "invalid handle"))?
        {
            FileHandle::File { path, .. } => path.clone(),
            FileHandle::Dir { path, .. } => path.clone(),
        };
        apply_attrs(
            &p,
            &attrs,
            self.opts.root.is_some(),
            self.opts.max_set_len,
            self.opts.allow_special_bits,
        )?;
        Ok(status_ok(id))
    }

    fn op_opendir(&mut self, id: u32, path: Vec<u8>) -> Result<Packet, SftpError> {
        let p = self.resolve(&path)?;
        let iter = fs::read_dir(&p)?;
        let handle = self.alloc_handle(FileHandle::Dir {
            iter: Some(iter),
            path: p,
            eof_sent: false,
        });
        Ok(Packet::Handle { id, handle })
    }

    fn op_readdir(&mut self, id: u32, handle: Vec<u8>) -> Result<Packet, SftpError> {
        let h = parse_handle(&handle)?;
        let entry = self
            .handles
            .get_mut(&h)
            .ok_or_else(|| SftpError::status_msg(FxpStatus::Failure, "invalid handle"))?;
        let (iter, eof_sent) = match entry {
            FileHandle::Dir { iter, eof_sent, .. } => (iter, eof_sent),
            _ => return Ok(status_pkt(id, FxpStatus::Failure, "handle is not a dir")),
        };
        if *eof_sent {
            return Ok(status_pkt(id, FxpStatus::Eof, "eof"));
        }
        let mut entries = Vec::new();
        if let Some(it) = iter.as_mut() {
            for _ in 0..128 {
                match it.next() {
                    Some(Ok(de)) => {
                        let filename = de.file_name().to_string_lossy().into_owned().into_bytes();
                        let md = match de.metadata() {
                            Ok(m) => m,
                            Err(_) => continue,
                        };
                        let attrs = attrs_from_metadata(&md);
                        let longname = format_long_name(&filename, &attrs);
                        entries.push(NameEntry {
                            filename,
                            longname,
                            attrs,
                        });
                    }
                    Some(Err(_)) => continue,
                    None => {
                        *eof_sent = true;
                        break;
                    }
                }
            }
        }
        if entries.is_empty() {
            *eof_sent = true;
            return Ok(status_pkt(id, FxpStatus::Eof, "eof"));
        }
        Ok(Packet::Name { id, entries })
    }

    fn op_remove(&mut self, id: u32, path: Vec<u8>) -> Result<Packet, SftpError> {
        self.require_writable()?;
        let p = self.resolve(&path)?;
        fs::remove_file(&p)?;
        Ok(status_ok(id))
    }

    fn op_mkdir(&mut self, id: u32, path: Vec<u8>, attrs: Attrs) -> Result<Packet, SftpError> {
        self.require_writable()?;
        let p = self.resolve(&path)?;
        fs::create_dir(&p)?;
        let _ = apply_attrs(
            &p,
            &attrs,
            self.opts.root.is_some(),
            self.opts.max_set_len,
            self.opts.allow_special_bits,
        );
        Ok(status_ok(id))
    }

    fn op_rmdir(&mut self, id: u32, path: Vec<u8>) -> Result<Packet, SftpError> {
        self.require_writable()?;
        let p = self.resolve(&path)?;
        fs::remove_dir(&p)?;
        Ok(status_ok(id))
    }

    fn op_realpath(&mut self, id: u32, path: Vec<u8>) -> Result<Packet, SftpError> {
        let p = self.resolve(&path)?;
        // When a jail is configured AND the operator opted in via
        // `hide_jail_in_realpath`, present paths to the client relative
        // to the jail root so the absolute filesystem layout doesn't
        // leak (e.g. the client sees `/u/foo` rather than
        // `/srv/jail/u/foo`). Default is off to preserve historical
        // behaviour for existing callers that still depend on the
        // unconfined path.
        let display = if self.opts.hide_jail_in_realpath {
            if let Some(root) = self.opts.root.as_deref() {
                let root_clean = super::path::lexically_clean(root);
                match p.strip_prefix(&root_clean) {
                    Ok(suffix) => {
                        let mut out = PathBuf::from("/");
                        if suffix.as_os_str().is_empty() {
                            out
                        } else {
                            out.push(suffix);
                            out
                        }
                    }
                    Err(_) => PathBuf::from("/"),
                }
            } else {
                p
            }
        } else {
            p
        };
        let bytes = display.to_string_lossy().into_owned().into_bytes();
        let entry = NameEntry {
            filename: bytes.clone(),
            longname: bytes,
            attrs: Attrs::default(),
        };
        Ok(Packet::Name {
            id,
            entries: vec![entry],
        })
    }

    fn op_rename(
        &mut self,
        id: u32,
        oldpath: Vec<u8>,
        newpath: Vec<u8>,
    ) -> Result<Packet, SftpError> {
        self.require_writable()?;
        let from = self.resolve(&oldpath)?;
        let to = self.resolve(&newpath)?;
        // SFTP v3 RENAME refuses to overwrite the destination.
        if to.exists() {
            return Ok(status_pkt(id, FxpStatus::Failure, "destination exists"));
        }
        fs::rename(&from, &to)?;
        Ok(status_ok(id))
    }

    fn op_readlink(&mut self, id: u32, path: Vec<u8>) -> Result<Packet, SftpError> {
        let p = self.resolve(&path)?;
        let tgt = fs::read_link(&p)?;
        let bytes = tgt.to_string_lossy().into_owned().into_bytes();
        Ok(Packet::Name {
            id,
            entries: vec![NameEntry {
                filename: bytes.clone(),
                longname: bytes,
                attrs: Attrs::default(),
            }],
        })
    }

    fn op_symlink(
        &mut self,
        id: u32,
        target_path: Vec<u8>,
        link_path: Vec<u8>,
    ) -> Result<Packet, SftpError> {
        self.require_writable()?;
        // OpenSSH order: (target, link). We resolve only link_path against
        // the jail; the target is stored verbatim in the symlink, as POSIX
        // doesn't require it to exist or be inside any tree.
        let link = self.resolve(&link_path)?;
        let target_s = std::str::from_utf8(&target_path)
            .map_err(|_| SftpError::status(FxpStatus::BadMessage))?;
        // When a jail is configured, refuse to create symlinks that
        // explicitly point outside it via an absolute target.
        //
        // Note: this does NOT block escape via a relative `..` target —
        // that requires resolve-time confinement. Open-time `O_NOFOLLOW`
        // (applied in op_open above) is what actually keeps a relative
        // traversal symlink from being used to read /etc/passwd.
        if self.opts.root.is_some() && Path::new(target_s).is_absolute() {
            return Ok(status_pkt(
                id,
                FxpStatus::PermissionDenied,
                "absolute symlink target rejected by jail",
            ));
        }
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(target_s, &link)?;
            Ok(status_ok(id))
        }
        #[cfg(not(unix))]
        {
            let _ = (target_s, link);
            Ok(status_pkt(id, FxpStatus::OpUnsupported, "symlink"))
        }
    }
}

fn parse_handle(raw: &[u8]) -> Result<u64, SftpError> {
    if raw.len() != 8 {
        return Err(SftpError::status_msg(FxpStatus::Failure, "invalid handle"));
    }
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(raw);
    Ok(u64::from_le_bytes(bytes))
}

fn attrs_from_metadata(md: &fs::Metadata) -> Attrs {
    let mut a = Attrs {
        size: Some(md.len()),
        ..Default::default()
    };
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        a.uid_gid = Some((md.uid(), md.gid()));
        a.permissions = Some(md.mode());
        let atime = md.atime().clamp(0, u32::MAX as i64) as u32;
        let mtime = md.mtime().clamp(0, u32::MAX as i64) as u32;
        a.atime_mtime = Some((atime, mtime));
    }
    #[cfg(not(unix))]
    {
        let mode = if md.is_dir() { 0o040755 } else { 0o100644 };
        a.permissions = Some(mode);
    }
    a
}

/// Mask the file-type and special bits out of a mode supplied by an SFTP
/// peer. By default we strip setuid/setgid/sticky (0o7000) to prevent a
/// hostile uploader from planting suid binaries; the high file-type bits
/// (0o170000) are always stripped because the syscalls below take just the
/// permission portion.
fn mask_mode(mode: u32, allow_special_bits: bool) -> u32 {
    if allow_special_bits {
        mode & 0o7777
    } else {
        mode & 0o0777
    }
}

/// Translate an `open(2)` error into an `SftpError`, mapping the `ELOOP`
/// raised by `O_NOFOLLOW` to `FX_NO_SUCH_FILE` so a client probing for a
/// planted symlink can't distinguish "absent" from "is a symlink".
fn map_open_err(e: io::Error) -> SftpError {
    #[cfg(unix)]
    {
        if let Some(40) = e.raw_os_error() {
            // ELOOP on Linux
            return SftpError::status_msg(FxpStatus::NoSuchFile, "symlink rejected");
        }
        if let Some(62) = e.raw_os_error() {
            // ELOOP on macOS/BSD
            return SftpError::status_msg(FxpStatus::NoSuchFile, "symlink rejected");
        }
    }
    SftpError::Io(e)
}

fn apply_attrs(
    path: &Path,
    a: &Attrs,
    jailed: bool,
    max_set_len: u64,
    allow_special_bits: bool,
) -> Result<(), SftpError> {
    if let Some(size) = a.size {
        if size > max_set_len {
            return Err(SftpError::status_msg(
                FxpStatus::PermissionDenied,
                "set_len above configured maximum",
            ));
        }
        // Open with O_NOFOLLOW when jailed so we can't be lured into
        // truncating a file outside the jail through a planted symlink.
        let mut opt = OpenOptions::new();
        opt.write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            if jailed {
                opt.custom_flags(nix::libc::O_NOFOLLOW);
            }
        }
        let _ = jailed;
        match opt.open(path) {
            Ok(f) => f.set_len(size)?,
            Err(e) => return Err(map_open_err(e)),
        }
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        use std::os::unix::fs::PermissionsExt;
        if let Some(mode) = a.permissions {
            let masked = mask_mode(mode, allow_special_bits);
            if jailed {
                // To prevent traversal through a symlink, open the target
                // with O_NOFOLLOW first and apply permissions via the fd
                // (fchmod). If open fails (typically ELOOP on a planted
                // symlink), refuse — falling back to a path-based chmod
                // would defeat the safety.
                let mut opt = OpenOptions::new();
                opt.read(true);
                opt.custom_flags(nix::libc::O_NOFOLLOW);
                match opt.open(path) {
                    Ok(f) => f.set_permissions(fs::Permissions::from_mode(masked))?,
                    Err(e) => {
                        // Directories can't always be opened O_RDONLY;
                        // verify with symlink_metadata that the target
                        // isn't a symlink and then chmod by path.
                        let _ = map_open_err(e);
                        let md = fs::symlink_metadata(path)?;
                        if md.file_type().is_symlink() {
                            return Err(SftpError::status_msg(
                                FxpStatus::NoSuchFile,
                                "symlink rejected",
                            ));
                        }
                        fs::set_permissions(path, fs::Permissions::from_mode(masked))?;
                    }
                }
            } else {
                fs::set_permissions(path, fs::Permissions::from_mode(masked))?;
            }
        }
        // chown and atime/mtime require either root or the libc utimes()
        // wrappers; we punt on them for now (they're rarely exercised by
        // SFTP clients) and return Ok so partial setstat is honoured.
    }
    #[cfg(not(unix))]
    {
        let _ = (a, allow_special_bits);
    }
    Ok(())
}

fn format_long_name(name: &[u8], a: &Attrs) -> Vec<u8> {
    let mode = a.permissions.unwrap_or(0);
    let kind_ch = match mode & 0o170000 {
        0o040000 => 'd',
        0o120000 => 'l',
        0o020000 => 'c',
        0o060000 => 'b',
        0o010000 => 'p',
        0o140000 => 's',
        _ => '-',
    };
    let perm = |bit: u32, ch: char| -> char {
        if mode & bit != 0 {
            ch
        } else {
            '-'
        }
    };
    let p = format!(
        "{}{}{}{}{}{}{}{}{}{}",
        kind_ch,
        perm(0o400, 'r'),
        perm(0o200, 'w'),
        perm(0o100, 'x'),
        perm(0o040, 'r'),
        perm(0o020, 'w'),
        perm(0o010, 'x'),
        perm(0o004, 'r'),
        perm(0o002, 'w'),
        perm(0o001, 'x'),
    );
    let size = a.size.unwrap_or(0);
    let (uid, gid) = a.uid_gid.unwrap_or((0, 0));
    let name_str = String::from_utf8_lossy(name);
    format!("{p} 1 {uid:>8} {gid:>8} {size:>10} Jan  1 00:00 {name_str}").into_bytes()
}

fn status_ok(id: u32) -> Packet {
    Packet::Status {
        id,
        code: FxpStatus::Ok,
        message: b"ok".to_vec(),
        lang: vec![],
    }
}

fn status_pkt(id: u32, code: FxpStatus, msg: &str) -> Packet {
    Packet::Status {
        id,
        code,
        message: msg.as_bytes().to_vec(),
        lang: vec![],
    }
}

fn status_from_err(id: u32, e: SftpError) -> Packet {
    match e {
        SftpError::Status { code, message } => Packet::Status {
            id,
            code,
            message: message.into_bytes(),
            lang: vec![],
        },
        SftpError::Io(io_err) => {
            let code = FxpStatus::from_io(&io_err);
            Packet::Status {
                id,
                code,
                message: io_err.to_string().into_bytes(),
                lang: vec![],
            }
        }
        SftpError::Format(s) => status_pkt(id, FxpStatus::BadMessage, s),
        SftpError::Protocol(s) => status_pkt(id, FxpStatus::BadMessage, s),
    }
}
