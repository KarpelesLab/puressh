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

/// Tunables for a single SFTP server session.
#[derive(Debug, Clone)]
pub struct SftpServerOptions {
    /// Initial virtual cwd for relative-path requests.
    pub cwd: PathBuf,
    /// Optional jail root. Any resolved path outside this subtree is
    /// rejected with [`FxpStatus::PermissionDenied`].
    pub root: Option<PathBuf>,
    /// If `true`, refuse every mutating operation.
    pub read_only: bool,
}

impl SftpServerOptions {
    /// Construct with the given virtual cwd. No jail; writable.
    pub fn new(cwd: impl Into<PathBuf>) -> Self {
        Self {
            cwd: cwd.into(),
            root: None,
            read_only: false,
        }
    }

    /// Apply a jail root.
    pub fn with_root(mut self, root: impl Into<PathBuf>) -> Self {
        self.root = Some(root.into());
        self
    }

    /// Refuse mutating operations.
    pub fn read_only(mut self) -> Self {
        self.read_only = true;
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
        let id = self.next;
        self.next = self.next.wrapping_add(1).max(1);
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
        if let Some(perm) = attrs.permissions {
            use std::os::unix::fs::OpenOptionsExt;
            opt.mode(perm & 0o7777);
        }
        let _ = &attrs;

        let file = opt.open(&p)?;
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
        let md = if follow {
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
        apply_attrs(&p, &attrs)?;
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
        apply_attrs(&p, &attrs)?;
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
        let _ = apply_attrs(&p, &attrs);
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
        let bytes = p.to_string_lossy().into_owned().into_bytes();
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

fn apply_attrs(path: &Path, a: &Attrs) -> Result<(), SftpError> {
    if let Some(size) = a.size {
        if let Ok(f) = OpenOptions::new().write(true).open(path) {
            f.set_len(size)?;
        }
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Some(mode) = a.permissions {
            fs::set_permissions(path, fs::Permissions::from_mode(mode & 0o7777))?;
        }
        // chown and atime/mtime require either root or the libc utimes()
        // wrappers; we punt on them for now (they're rarely exercised by
        // SFTP clients) and return Ok so partial setstat is honoured.
    }
    #[cfg(not(unix))]
    {
        let _ = a;
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
