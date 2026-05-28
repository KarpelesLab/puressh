//! SFTP v3 wire-format packet types and encoding/decoding.
//!
//! Every packet on the wire has the shape `uint32 length || byte type ||
//! payload`. This module exposes a single [`Packet`] enum covering every
//! `SSH_FXP_*` message; [`Packet::encode`] returns a complete frame
//! (including the length prefix), [`Packet::decode`] parses a body
//! (without the length prefix), and [`read_packet`] / [`write_packet`] do
//! framed stream I/O.

use std::io::{Read, Write};

use crate::format::{Reader, Writer};

use super::types::{
    Attrs, FxpStatus, NameEntry, SftpError, ATTR_ACMODTIME, ATTR_EXTENDED, ATTR_PERMISSIONS,
    ATTR_SIZE, ATTR_UIDGID,
};

/// `SSH_FXP_INIT` — client → server handshake.
pub const SSH_FXP_INIT: u8 = 1;
/// `SSH_FXP_VERSION` — server → client handshake reply.
pub const SSH_FXP_VERSION: u8 = 2;
/// `SSH_FXP_OPEN` — open or create a file.
pub const SSH_FXP_OPEN: u8 = 3;
/// `SSH_FXP_CLOSE` — close an open handle.
pub const SSH_FXP_CLOSE: u8 = 4;
/// `SSH_FXP_READ` — read from a file handle.
pub const SSH_FXP_READ: u8 = 5;
/// `SSH_FXP_WRITE` — write to a file handle.
pub const SSH_FXP_WRITE: u8 = 6;
/// `SSH_FXP_LSTAT` — stat without following symlinks.
pub const SSH_FXP_LSTAT: u8 = 7;
/// `SSH_FXP_FSTAT` — stat by handle.
pub const SSH_FXP_FSTAT: u8 = 8;
/// `SSH_FXP_SETSTAT` — set attributes on a path.
pub const SSH_FXP_SETSTAT: u8 = 9;
/// `SSH_FXP_FSETSTAT` — set attributes on a handle.
pub const SSH_FXP_FSETSTAT: u8 = 10;
/// `SSH_FXP_OPENDIR` — open a directory for reading.
pub const SSH_FXP_OPENDIR: u8 = 11;
/// `SSH_FXP_READDIR` — read directory entries.
pub const SSH_FXP_READDIR: u8 = 12;
/// `SSH_FXP_REMOVE` — unlink a file.
pub const SSH_FXP_REMOVE: u8 = 13;
/// `SSH_FXP_MKDIR` — create a directory.
pub const SSH_FXP_MKDIR: u8 = 14;
/// `SSH_FXP_RMDIR` — remove a directory.
pub const SSH_FXP_RMDIR: u8 = 15;
/// `SSH_FXP_REALPATH` — canonicalise a path.
pub const SSH_FXP_REALPATH: u8 = 16;
/// `SSH_FXP_STAT` — stat following symlinks.
pub const SSH_FXP_STAT: u8 = 17;
/// `SSH_FXP_RENAME` — rename a file or directory.
pub const SSH_FXP_RENAME: u8 = 18;
/// `SSH_FXP_READLINK` — read the target of a symlink.
pub const SSH_FXP_READLINK: u8 = 19;
/// `SSH_FXP_SYMLINK` — create a symlink.
pub const SSH_FXP_SYMLINK: u8 = 20;
/// `SSH_FXP_STATUS` — generic response (success/error).
pub const SSH_FXP_STATUS: u8 = 101;
/// `SSH_FXP_HANDLE` — response carrying a handle string.
pub const SSH_FXP_HANDLE: u8 = 102;
/// `SSH_FXP_DATA` — response carrying file data.
pub const SSH_FXP_DATA: u8 = 103;
/// `SSH_FXP_NAME` — response carrying one or more directory entries.
pub const SSH_FXP_NAME: u8 = 104;
/// `SSH_FXP_ATTRS` — response carrying attributes.
pub const SSH_FXP_ATTRS: u8 = 105;
/// `SSH_FXP_EXTENDED` — vendor extension request.
pub const SSH_FXP_EXTENDED: u8 = 200;
/// `SSH_FXP_EXTENDED_REPLY` — vendor extension reply.
pub const SSH_FXP_EXTENDED_REPLY: u8 = 201;

/// Maximum packet body length we accept on the wire (256 KiB), matching
/// OpenSSH's `SFTP_MAX_MSG_LENGTH`.
pub const MAX_PACKET_SIZE: u32 = 256 * 1024;

/// SFTP version-handshake extension list: `(name, data)` pairs.
pub type Extensions = Vec<(Vec<u8>, Vec<u8>)>;

/// One SFTP message, before/after wire encoding.
#[allow(missing_docs)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Packet {
    Init {
        version: u32,
        extensions: Extensions,
    },
    Version {
        version: u32,
        extensions: Extensions,
    },
    Open {
        id: u32,
        path: Vec<u8>,
        pflags: u32,
        attrs: Attrs,
    },
    Close {
        id: u32,
        handle: Vec<u8>,
    },
    Read {
        id: u32,
        handle: Vec<u8>,
        offset: u64,
        len: u32,
    },
    Write {
        id: u32,
        handle: Vec<u8>,
        offset: u64,
        data: Vec<u8>,
    },
    Lstat {
        id: u32,
        path: Vec<u8>,
    },
    Fstat {
        id: u32,
        handle: Vec<u8>,
    },
    Setstat {
        id: u32,
        path: Vec<u8>,
        attrs: Attrs,
    },
    Fsetstat {
        id: u32,
        handle: Vec<u8>,
        attrs: Attrs,
    },
    Opendir {
        id: u32,
        path: Vec<u8>,
    },
    Readdir {
        id: u32,
        handle: Vec<u8>,
    },
    Remove {
        id: u32,
        path: Vec<u8>,
    },
    Mkdir {
        id: u32,
        path: Vec<u8>,
        attrs: Attrs,
    },
    Rmdir {
        id: u32,
        path: Vec<u8>,
    },
    Realpath {
        id: u32,
        path: Vec<u8>,
    },
    Stat {
        id: u32,
        path: Vec<u8>,
    },
    Rename {
        id: u32,
        oldpath: Vec<u8>,
        newpath: Vec<u8>,
    },
    Readlink {
        id: u32,
        path: Vec<u8>,
    },
    /// Symlink creation. **Note**: OpenSSH ships the arguments in the order
    /// (target, link) — the opposite of the protocol draft. We match
    /// OpenSSH's order for interop.
    Symlink {
        id: u32,
        target_path: Vec<u8>,
        link_path: Vec<u8>,
    },
    Extended {
        id: u32,
        request: Vec<u8>,
        data: Vec<u8>,
    },
    Status {
        id: u32,
        code: FxpStatus,
        message: Vec<u8>,
        lang: Vec<u8>,
    },
    Handle {
        id: u32,
        handle: Vec<u8>,
    },
    Data {
        id: u32,
        data: Vec<u8>,
    },
    Name {
        id: u32,
        entries: Vec<NameEntry>,
    },
    Attrs {
        id: u32,
        attrs: Attrs,
    },
    ExtendedReply {
        id: u32,
        data: Vec<u8>,
    },
}

impl Packet {
    /// The request id (every packet except `INIT`/`VERSION` carries one).
    pub fn id(&self) -> Option<u32> {
        match self {
            Packet::Init { .. } | Packet::Version { .. } => None,
            Packet::Open { id, .. }
            | Packet::Close { id, .. }
            | Packet::Read { id, .. }
            | Packet::Write { id, .. }
            | Packet::Lstat { id, .. }
            | Packet::Fstat { id, .. }
            | Packet::Setstat { id, .. }
            | Packet::Fsetstat { id, .. }
            | Packet::Opendir { id, .. }
            | Packet::Readdir { id, .. }
            | Packet::Remove { id, .. }
            | Packet::Mkdir { id, .. }
            | Packet::Rmdir { id, .. }
            | Packet::Realpath { id, .. }
            | Packet::Stat { id, .. }
            | Packet::Rename { id, .. }
            | Packet::Readlink { id, .. }
            | Packet::Symlink { id, .. }
            | Packet::Extended { id, .. }
            | Packet::Status { id, .. }
            | Packet::Handle { id, .. }
            | Packet::Data { id, .. }
            | Packet::Name { id, .. }
            | Packet::Attrs { id, .. }
            | Packet::ExtendedReply { id, .. } => Some(*id),
        }
    }

    /// Encode into a complete wire frame (`uint32 length || byte type ||
    /// payload`).
    pub fn encode(&self) -> Vec<u8> {
        let mut body = Writer::new();
        self.encode_body(&mut body);
        let mut out = Writer::with_capacity(4 + body.len());
        out.write_u32(body.len() as u32);
        out.write_raw(body.as_slice());
        out.into_vec()
    }

    fn encode_body(&self, w: &mut Writer) {
        match self {
            Packet::Init {
                version,
                extensions,
            } => {
                w.write_u8(SSH_FXP_INIT);
                w.write_u32(*version);
                encode_extensions(w, extensions);
            }
            Packet::Version {
                version,
                extensions,
            } => {
                w.write_u8(SSH_FXP_VERSION);
                w.write_u32(*version);
                encode_extensions(w, extensions);
            }
            Packet::Open {
                id,
                path,
                pflags,
                attrs,
            } => {
                w.write_u8(SSH_FXP_OPEN);
                w.write_u32(*id);
                w.write_string(path);
                w.write_u32(*pflags);
                encode_attrs(w, attrs);
            }
            Packet::Close { id, handle } => {
                w.write_u8(SSH_FXP_CLOSE);
                w.write_u32(*id);
                w.write_string(handle);
            }
            Packet::Read {
                id,
                handle,
                offset,
                len,
            } => {
                w.write_u8(SSH_FXP_READ);
                w.write_u32(*id);
                w.write_string(handle);
                w.write_u64(*offset);
                w.write_u32(*len);
            }
            Packet::Write {
                id,
                handle,
                offset,
                data,
            } => {
                w.write_u8(SSH_FXP_WRITE);
                w.write_u32(*id);
                w.write_string(handle);
                w.write_u64(*offset);
                w.write_string(data);
            }
            Packet::Lstat { id, path } => {
                w.write_u8(SSH_FXP_LSTAT);
                w.write_u32(*id);
                w.write_string(path);
            }
            Packet::Fstat { id, handle } => {
                w.write_u8(SSH_FXP_FSTAT);
                w.write_u32(*id);
                w.write_string(handle);
            }
            Packet::Setstat { id, path, attrs } => {
                w.write_u8(SSH_FXP_SETSTAT);
                w.write_u32(*id);
                w.write_string(path);
                encode_attrs(w, attrs);
            }
            Packet::Fsetstat { id, handle, attrs } => {
                w.write_u8(SSH_FXP_FSETSTAT);
                w.write_u32(*id);
                w.write_string(handle);
                encode_attrs(w, attrs);
            }
            Packet::Opendir { id, path } => {
                w.write_u8(SSH_FXP_OPENDIR);
                w.write_u32(*id);
                w.write_string(path);
            }
            Packet::Readdir { id, handle } => {
                w.write_u8(SSH_FXP_READDIR);
                w.write_u32(*id);
                w.write_string(handle);
            }
            Packet::Remove { id, path } => {
                w.write_u8(SSH_FXP_REMOVE);
                w.write_u32(*id);
                w.write_string(path);
            }
            Packet::Mkdir { id, path, attrs } => {
                w.write_u8(SSH_FXP_MKDIR);
                w.write_u32(*id);
                w.write_string(path);
                encode_attrs(w, attrs);
            }
            Packet::Rmdir { id, path } => {
                w.write_u8(SSH_FXP_RMDIR);
                w.write_u32(*id);
                w.write_string(path);
            }
            Packet::Realpath { id, path } => {
                w.write_u8(SSH_FXP_REALPATH);
                w.write_u32(*id);
                w.write_string(path);
            }
            Packet::Stat { id, path } => {
                w.write_u8(SSH_FXP_STAT);
                w.write_u32(*id);
                w.write_string(path);
            }
            Packet::Rename {
                id,
                oldpath,
                newpath,
            } => {
                w.write_u8(SSH_FXP_RENAME);
                w.write_u32(*id);
                w.write_string(oldpath);
                w.write_string(newpath);
            }
            Packet::Readlink { id, path } => {
                w.write_u8(SSH_FXP_READLINK);
                w.write_u32(*id);
                w.write_string(path);
            }
            Packet::Symlink {
                id,
                target_path,
                link_path,
            } => {
                w.write_u8(SSH_FXP_SYMLINK);
                w.write_u32(*id);
                w.write_string(target_path);
                w.write_string(link_path);
            }
            Packet::Extended { id, request, data } => {
                w.write_u8(SSH_FXP_EXTENDED);
                w.write_u32(*id);
                w.write_string(request);
                w.write_raw(data);
            }
            Packet::Status {
                id,
                code,
                message,
                lang,
            } => {
                w.write_u8(SSH_FXP_STATUS);
                w.write_u32(*id);
                w.write_u32(code.code());
                w.write_string(message);
                w.write_string(lang);
            }
            Packet::Handle { id, handle } => {
                w.write_u8(SSH_FXP_HANDLE);
                w.write_u32(*id);
                w.write_string(handle);
            }
            Packet::Data { id, data } => {
                w.write_u8(SSH_FXP_DATA);
                w.write_u32(*id);
                w.write_string(data);
            }
            Packet::Name { id, entries } => {
                w.write_u8(SSH_FXP_NAME);
                w.write_u32(*id);
                w.write_u32(entries.len() as u32);
                for e in entries {
                    w.write_string(&e.filename);
                    w.write_string(&e.longname);
                    encode_attrs(w, &e.attrs);
                }
            }
            Packet::Attrs { id, attrs } => {
                w.write_u8(SSH_FXP_ATTRS);
                w.write_u32(*id);
                encode_attrs(w, attrs);
            }
            Packet::ExtendedReply { id, data } => {
                w.write_u8(SSH_FXP_EXTENDED_REPLY);
                w.write_u32(*id);
                w.write_raw(data);
            }
        }
    }

    /// Decode a packet body (the byte after the length prefix is the
    /// type byte).
    pub fn decode(body: &[u8]) -> Result<Packet, SftpError> {
        let mut r = Reader::new(body);
        let typ = r.read_u8()?;
        match typ {
            SSH_FXP_INIT => {
                let version = r.read_u32()?;
                let extensions = decode_extensions(&mut r)?;
                Ok(Packet::Init {
                    version,
                    extensions,
                })
            }
            SSH_FXP_VERSION => {
                let version = r.read_u32()?;
                let extensions = decode_extensions(&mut r)?;
                Ok(Packet::Version {
                    version,
                    extensions,
                })
            }
            SSH_FXP_OPEN => {
                let id = r.read_u32()?;
                let path = r.read_string()?.to_vec();
                let pflags = r.read_u32()?;
                let attrs = decode_attrs(&mut r)?;
                Ok(Packet::Open {
                    id,
                    path,
                    pflags,
                    attrs,
                })
            }
            SSH_FXP_CLOSE => {
                let id = r.read_u32()?;
                let handle = r.read_string()?.to_vec();
                Ok(Packet::Close { id, handle })
            }
            SSH_FXP_READ => {
                let id = r.read_u32()?;
                let handle = r.read_string()?.to_vec();
                let offset = r.read_u64()?;
                let len = r.read_u32()?;
                Ok(Packet::Read {
                    id,
                    handle,
                    offset,
                    len,
                })
            }
            SSH_FXP_WRITE => {
                let id = r.read_u32()?;
                let handle = r.read_string()?.to_vec();
                let offset = r.read_u64()?;
                let data = r.read_string()?.to_vec();
                Ok(Packet::Write {
                    id,
                    handle,
                    offset,
                    data,
                })
            }
            SSH_FXP_LSTAT => {
                let id = r.read_u32()?;
                let path = r.read_string()?.to_vec();
                Ok(Packet::Lstat { id, path })
            }
            SSH_FXP_FSTAT => {
                let id = r.read_u32()?;
                let handle = r.read_string()?.to_vec();
                Ok(Packet::Fstat { id, handle })
            }
            SSH_FXP_SETSTAT => {
                let id = r.read_u32()?;
                let path = r.read_string()?.to_vec();
                let attrs = decode_attrs(&mut r)?;
                Ok(Packet::Setstat { id, path, attrs })
            }
            SSH_FXP_FSETSTAT => {
                let id = r.read_u32()?;
                let handle = r.read_string()?.to_vec();
                let attrs = decode_attrs(&mut r)?;
                Ok(Packet::Fsetstat { id, handle, attrs })
            }
            SSH_FXP_OPENDIR => {
                let id = r.read_u32()?;
                let path = r.read_string()?.to_vec();
                Ok(Packet::Opendir { id, path })
            }
            SSH_FXP_READDIR => {
                let id = r.read_u32()?;
                let handle = r.read_string()?.to_vec();
                Ok(Packet::Readdir { id, handle })
            }
            SSH_FXP_REMOVE => {
                let id = r.read_u32()?;
                let path = r.read_string()?.to_vec();
                Ok(Packet::Remove { id, path })
            }
            SSH_FXP_MKDIR => {
                let id = r.read_u32()?;
                let path = r.read_string()?.to_vec();
                let attrs = decode_attrs(&mut r)?;
                Ok(Packet::Mkdir { id, path, attrs })
            }
            SSH_FXP_RMDIR => {
                let id = r.read_u32()?;
                let path = r.read_string()?.to_vec();
                Ok(Packet::Rmdir { id, path })
            }
            SSH_FXP_REALPATH => {
                let id = r.read_u32()?;
                let path = r.read_string()?.to_vec();
                Ok(Packet::Realpath { id, path })
            }
            SSH_FXP_STAT => {
                let id = r.read_u32()?;
                let path = r.read_string()?.to_vec();
                Ok(Packet::Stat { id, path })
            }
            SSH_FXP_RENAME => {
                let id = r.read_u32()?;
                let oldpath = r.read_string()?.to_vec();
                let newpath = r.read_string()?.to_vec();
                Ok(Packet::Rename {
                    id,
                    oldpath,
                    newpath,
                })
            }
            SSH_FXP_READLINK => {
                let id = r.read_u32()?;
                let path = r.read_string()?.to_vec();
                Ok(Packet::Readlink { id, path })
            }
            SSH_FXP_SYMLINK => {
                let id = r.read_u32()?;
                let target_path = r.read_string()?.to_vec();
                let link_path = r.read_string()?.to_vec();
                Ok(Packet::Symlink {
                    id,
                    target_path,
                    link_path,
                })
            }
            SSH_FXP_EXTENDED => {
                let id = r.read_u32()?;
                let request = r.read_string()?.to_vec();
                let data = body[body.len() - r.remaining()..].to_vec();
                Ok(Packet::Extended { id, request, data })
            }
            SSH_FXP_STATUS => {
                let id = r.read_u32()?;
                let code = FxpStatus::from_code(r.read_u32()?);
                // Earlier SFTP v3 servers omit the trailing message / lang
                // fields. Treat absence as empty.
                let message = if r.is_empty() {
                    Vec::new()
                } else {
                    r.read_string()?.to_vec()
                };
                let lang = if r.is_empty() {
                    Vec::new()
                } else {
                    r.read_string()?.to_vec()
                };
                Ok(Packet::Status {
                    id,
                    code,
                    message,
                    lang,
                })
            }
            SSH_FXP_HANDLE => {
                let id = r.read_u32()?;
                let handle = r.read_string()?.to_vec();
                Ok(Packet::Handle { id, handle })
            }
            SSH_FXP_DATA => {
                let id = r.read_u32()?;
                let data = r.read_string()?.to_vec();
                Ok(Packet::Data { id, data })
            }
            SSH_FXP_NAME => {
                let id = r.read_u32()?;
                let count = r.read_u32()?;
                if count > 1 << 20 {
                    return Err(SftpError::Format("sftp: NAME count too large"));
                }
                let mut entries = Vec::with_capacity(count.min(1024) as usize);
                for _ in 0..count {
                    let filename = r.read_string()?.to_vec();
                    let longname = r.read_string()?.to_vec();
                    let attrs = decode_attrs(&mut r)?;
                    entries.push(NameEntry {
                        filename,
                        longname,
                        attrs,
                    });
                }
                Ok(Packet::Name { id, entries })
            }
            SSH_FXP_ATTRS => {
                let id = r.read_u32()?;
                let attrs = decode_attrs(&mut r)?;
                Ok(Packet::Attrs { id, attrs })
            }
            SSH_FXP_EXTENDED_REPLY => {
                let id = r.read_u32()?;
                let data = body[body.len() - r.remaining()..].to_vec();
                Ok(Packet::ExtendedReply { id, data })
            }
            _ => Err(SftpError::Format("sftp: unknown packet type")),
        }
    }
}

/// Encode an SFTP `Attrs` record (without flags) into `w`.
pub fn encode_attrs(w: &mut Writer, a: &Attrs) {
    let mut flags = 0u32;
    if a.size.is_some() {
        flags |= ATTR_SIZE;
    }
    if a.uid_gid.is_some() {
        flags |= ATTR_UIDGID;
    }
    if a.permissions.is_some() {
        flags |= ATTR_PERMISSIONS;
    }
    if a.atime_mtime.is_some() {
        flags |= ATTR_ACMODTIME;
    }
    if !a.extended.is_empty() {
        flags |= ATTR_EXTENDED;
    }
    w.write_u32(flags);
    if let Some(sz) = a.size {
        w.write_u64(sz);
    }
    if let Some((uid, gid)) = a.uid_gid {
        w.write_u32(uid);
        w.write_u32(gid);
    }
    if let Some(p) = a.permissions {
        w.write_u32(p);
    }
    if let Some((at, mt)) = a.atime_mtime {
        w.write_u32(at);
        w.write_u32(mt);
    }
    if !a.extended.is_empty() {
        w.write_u32(a.extended.len() as u32);
        for (k, v) in &a.extended {
            w.write_string(k);
            w.write_string(v);
        }
    }
}

/// Decode an SFTP `Attrs` record from `r`.
pub fn decode_attrs(r: &mut Reader<'_>) -> Result<Attrs, SftpError> {
    let flags = r.read_u32()?;
    let mut a = Attrs::default();
    if flags & ATTR_SIZE != 0 {
        a.size = Some(r.read_u64()?);
    }
    if flags & ATTR_UIDGID != 0 {
        a.uid_gid = Some((r.read_u32()?, r.read_u32()?));
    }
    if flags & ATTR_PERMISSIONS != 0 {
        a.permissions = Some(r.read_u32()?);
    }
    if flags & ATTR_ACMODTIME != 0 {
        a.atime_mtime = Some((r.read_u32()?, r.read_u32()?));
    }
    if flags & ATTR_EXTENDED != 0 {
        let n = r.read_u32()?;
        if n > 1024 {
            return Err(SftpError::Format("sftp: too many extended attrs"));
        }
        for _ in 0..n {
            let k = r.read_string()?.to_vec();
            let v = r.read_string()?.to_vec();
            a.extended.push((k, v));
        }
    }
    Ok(a)
}

fn encode_extensions(w: &mut Writer, exts: &[(Vec<u8>, Vec<u8>)]) {
    for (k, v) in exts {
        w.write_string(k);
        w.write_string(v);
    }
}

fn decode_extensions(r: &mut Reader<'_>) -> Result<Extensions, SftpError> {
    let mut out = Vec::new();
    while !r.is_empty() {
        let k = r.read_string()?.to_vec();
        let v = r.read_string()?.to_vec();
        out.push((k, v));
        if out.len() > 1024 {
            return Err(SftpError::Format("sftp: too many extensions"));
        }
    }
    Ok(out)
}

/// Read one SFTP packet body from `r`. The returned buffer does **not**
/// include the leading length prefix; feed it to [`Packet::decode`].
pub fn read_packet<R: Read>(r: &mut R) -> Result<Vec<u8>, SftpError> {
    let mut len_buf = [0u8; 4];
    r.read_exact(&mut len_buf)?;
    let len = u32::from_be_bytes(len_buf);
    if len == 0 || len > MAX_PACKET_SIZE {
        return Err(SftpError::Format("sftp: invalid packet length"));
    }
    let mut buf = vec![0u8; len as usize];
    r.read_exact(&mut buf)?;
    Ok(buf)
}

/// Encode `pkt` and write the resulting framed bytes to `w`.
pub fn write_packet<W: Write>(w: &mut W, pkt: &Packet) -> Result<(), SftpError> {
    let bytes = pkt.encode();
    w.write_all(&bytes)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(p: &Packet) {
        let bytes = p.encode();
        // Strip length prefix
        let body = &bytes[4..];
        let decoded = Packet::decode(body).expect("decode");
        assert_eq!(p, &decoded, "packet round-trip mismatch");
    }

    #[test]
    fn roundtrip_init_version() {
        roundtrip(&Packet::Init {
            version: 3,
            extensions: vec![(b"foo".to_vec(), b"1".to_vec())],
        });
        roundtrip(&Packet::Version {
            version: 3,
            extensions: vec![],
        });
    }

    #[test]
    fn roundtrip_open_read_write_close() {
        let attrs = Attrs {
            permissions: Some(0o100644),
            ..Default::default()
        };
        roundtrip(&Packet::Open {
            id: 1,
            path: b"/tmp/x".to_vec(),
            pflags: 0x1f,
            attrs,
        });
        roundtrip(&Packet::Read {
            id: 2,
            handle: vec![0, 1, 2, 3],
            offset: 1024,
            len: 32 * 1024,
        });
        roundtrip(&Packet::Write {
            id: 3,
            handle: vec![0, 1, 2, 3],
            offset: 0,
            data: b"hello world".to_vec(),
        });
        roundtrip(&Packet::Close {
            id: 4,
            handle: vec![0, 1, 2, 3],
        });
    }

    #[test]
    fn roundtrip_stat_attrs() {
        let attrs = Attrs {
            size: Some(123),
            uid_gid: Some((1000, 1000)),
            permissions: Some(0o100644),
            atime_mtime: Some((1, 2)),
            extended: vec![(b"k".to_vec(), b"v".to_vec())],
        };
        roundtrip(&Packet::Attrs { id: 5, attrs });
    }

    #[test]
    fn roundtrip_name() {
        let entries = vec![
            NameEntry {
                filename: b"a".to_vec(),
                longname: b"-rw-r--r-- 1 user user 0 Jan 1 12:00 a".to_vec(),
                attrs: Attrs {
                    permissions: Some(0o100644),
                    ..Default::default()
                },
            },
            NameEntry {
                filename: b"b".to_vec(),
                longname: b"drwxr-xr-x 2 user user 0 Jan 1 12:00 b".to_vec(),
                attrs: Attrs {
                    permissions: Some(0o040755),
                    ..Default::default()
                },
            },
        ];
        roundtrip(&Packet::Name { id: 6, entries });
    }

    #[test]
    fn roundtrip_status() {
        roundtrip(&Packet::Status {
            id: 7,
            code: FxpStatus::NoSuchFile,
            message: b"no such file".to_vec(),
            lang: b"en".to_vec(),
        });
    }

    #[test]
    fn roundtrip_symlink_openssh_order() {
        roundtrip(&Packet::Symlink {
            id: 8,
            target_path: b"/etc/passwd".to_vec(),
            link_path: b"/tmp/passwd".to_vec(),
        });
    }
}
