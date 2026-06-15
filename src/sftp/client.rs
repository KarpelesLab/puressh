//! SFTP v3 client.
//!
//! [`SftpClient::new`] takes any `Read+Write` transport (typically a
//! [`puressh::client::Client`](crate::client) channel running the `sftp`
//! subsystem) and exposes one method per SFTP operation. Each call writes
//! a request, reads the matching response, and validates the id round-trip
//! — there is no request pipelining at this layer.

use std::io::{Read, Write};

use super::packet::{Packet, read_packet, write_packet};
use super::types::{Attrs, FxpStatus, NameEntry, SFTP_VERSION, SftpError};

/// Borrowing SFTP v3 client over any `Read+Write` transport.
pub struct SftpClient<T: Read + Write> {
    transport: T,
    next_id: u32,
    extensions: Vec<(Vec<u8>, Vec<u8>)>,
    server_version: u32,
}

impl<T: Read + Write> SftpClient<T> {
    /// Perform the `INIT`/`VERSION` handshake and return a ready client.
    pub fn new(mut transport: T) -> Result<Self, SftpError> {
        write_packet(
            &mut transport,
            &Packet::Init {
                version: SFTP_VERSION,
                extensions: vec![],
            },
        )?;
        let body = read_packet(&mut transport)?;
        let (server_version, extensions) = match Packet::decode(&body)? {
            Packet::Version {
                version,
                extensions,
            } => {
                if version < 3 {
                    return Err(SftpError::Protocol("sftp: server version < 3"));
                }
                (version, extensions)
            }
            _ => return Err(SftpError::Protocol("sftp: expected VERSION")),
        };
        Ok(Self {
            transport,
            next_id: 1,
            extensions,
            server_version,
        })
    }

    /// SFTP version reported by the server.
    pub fn server_version(&self) -> u32 {
        self.server_version
    }

    /// Server-advertised extensions (name, version-or-data pairs).
    pub fn extensions(&self) -> &[(Vec<u8>, Vec<u8>)] {
        &self.extensions
    }

    fn next_id(&mut self) -> u32 {
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1).max(1);
        id
    }

    fn request(&mut self, mut pkt: Packet) -> Result<Packet, SftpError> {
        let id = self.next_id();
        set_id(&mut pkt, id);
        write_packet(&mut self.transport, &pkt)?;
        let body = read_packet(&mut self.transport)?;
        let resp = Packet::decode(&body)?;
        match resp.id() {
            Some(rid) if rid == id => Ok(resp),
            _ => Err(SftpError::Protocol("sftp: response id mismatch")),
        }
    }

    /// Open or create a file. `pflags` is a bitmask of `FXF_*`.
    pub fn open(&mut self, path: &[u8], pflags: u32, attrs: Attrs) -> Result<Vec<u8>, SftpError> {
        let resp = self.request(Packet::Open {
            id: 0,
            path: path.to_vec(),
            pflags,
            attrs,
        })?;
        expect_handle(resp)
    }

    /// Close an open file or directory handle.
    pub fn close(&mut self, handle: &[u8]) -> Result<(), SftpError> {
        let resp = self.request(Packet::Close {
            id: 0,
            handle: handle.to_vec(),
        })?;
        expect_ok(resp)
    }

    /// Read up to `len` bytes from `handle` starting at `offset`. Returns
    /// an empty vec if the server signalled EOF.
    pub fn read(&mut self, handle: &[u8], offset: u64, len: u32) -> Result<Vec<u8>, SftpError> {
        let resp = self.request(Packet::Read {
            id: 0,
            handle: handle.to_vec(),
            offset,
            len,
        })?;
        match resp {
            Packet::Data { data, .. } => Ok(data),
            Packet::Status {
                code: FxpStatus::Eof,
                ..
            } => Ok(Vec::new()),
            Packet::Status { code, message, .. } => Err(SftpError::Status {
                code,
                message: String::from_utf8_lossy(&message).into_owned(),
            }),
            _ => Err(SftpError::Protocol("sftp: expected DATA or STATUS")),
        }
    }

    /// Write `data` to `handle` at `offset`.
    pub fn write(&mut self, handle: &[u8], offset: u64, data: &[u8]) -> Result<(), SftpError> {
        let resp = self.request(Packet::Write {
            id: 0,
            handle: handle.to_vec(),
            offset,
            data: data.to_vec(),
        })?;
        expect_ok(resp)
    }

    /// Stat a path, following symlinks.
    pub fn stat(&mut self, path: &[u8]) -> Result<Attrs, SftpError> {
        self.stat_inner(Packet::Stat {
            id: 0,
            path: path.to_vec(),
        })
    }

    /// Stat a path without following symlinks.
    pub fn lstat(&mut self, path: &[u8]) -> Result<Attrs, SftpError> {
        self.stat_inner(Packet::Lstat {
            id: 0,
            path: path.to_vec(),
        })
    }

    /// Stat a handle.
    pub fn fstat(&mut self, handle: &[u8]) -> Result<Attrs, SftpError> {
        self.stat_inner(Packet::Fstat {
            id: 0,
            handle: handle.to_vec(),
        })
    }

    fn stat_inner(&mut self, pkt: Packet) -> Result<Attrs, SftpError> {
        let resp = self.request(pkt)?;
        match resp {
            Packet::Attrs { attrs, .. } => Ok(attrs),
            Packet::Status { code, message, .. } => Err(SftpError::Status {
                code,
                message: String::from_utf8_lossy(&message).into_owned(),
            }),
            _ => Err(SftpError::Protocol("sftp: expected ATTRS")),
        }
    }

    /// Apply attributes to a path.
    pub fn setstat(&mut self, path: &[u8], attrs: Attrs) -> Result<(), SftpError> {
        let resp = self.request(Packet::Setstat {
            id: 0,
            path: path.to_vec(),
            attrs,
        })?;
        expect_ok(resp)
    }

    /// Apply attributes to an open handle.
    pub fn fsetstat(&mut self, handle: &[u8], attrs: Attrs) -> Result<(), SftpError> {
        let resp = self.request(Packet::Fsetstat {
            id: 0,
            handle: handle.to_vec(),
            attrs,
        })?;
        expect_ok(resp)
    }

    /// Open a directory for iteration.
    pub fn opendir(&mut self, path: &[u8]) -> Result<Vec<u8>, SftpError> {
        let resp = self.request(Packet::Opendir {
            id: 0,
            path: path.to_vec(),
        })?;
        expect_handle(resp)
    }

    /// Read a batch of directory entries. Returns `None` when the directory
    /// is exhausted (the server replied with `SSH_FX_EOF`).
    pub fn readdir(&mut self, handle: &[u8]) -> Result<Option<Vec<NameEntry>>, SftpError> {
        let resp = self.request(Packet::Readdir {
            id: 0,
            handle: handle.to_vec(),
        })?;
        match resp {
            Packet::Name { entries, .. } => Ok(Some(entries)),
            Packet::Status {
                code: FxpStatus::Eof,
                ..
            } => Ok(None),
            Packet::Status { code, message, .. } => Err(SftpError::Status {
                code,
                message: String::from_utf8_lossy(&message).into_owned(),
            }),
            _ => Err(SftpError::Protocol("sftp: expected NAME or STATUS")),
        }
    }

    /// Create a directory.
    pub fn mkdir(&mut self, path: &[u8], attrs: Attrs) -> Result<(), SftpError> {
        let resp = self.request(Packet::Mkdir {
            id: 0,
            path: path.to_vec(),
            attrs,
        })?;
        expect_ok(resp)
    }

    /// Remove a directory (must be empty).
    pub fn rmdir(&mut self, path: &[u8]) -> Result<(), SftpError> {
        let resp = self.request(Packet::Rmdir {
            id: 0,
            path: path.to_vec(),
        })?;
        expect_ok(resp)
    }

    /// Remove a file.
    pub fn remove(&mut self, path: &[u8]) -> Result<(), SftpError> {
        let resp = self.request(Packet::Remove {
            id: 0,
            path: path.to_vec(),
        })?;
        expect_ok(resp)
    }

    /// Rename `oldpath` to `newpath`. SFTP v3 refuses to overwrite.
    pub fn rename(&mut self, oldpath: &[u8], newpath: &[u8]) -> Result<(), SftpError> {
        let resp = self.request(Packet::Rename {
            id: 0,
            oldpath: oldpath.to_vec(),
            newpath: newpath.to_vec(),
        })?;
        expect_ok(resp)
    }

    /// Canonicalise a path against the server's virtual cwd.
    pub fn realpath(&mut self, path: &[u8]) -> Result<Vec<u8>, SftpError> {
        let resp = self.request(Packet::Realpath {
            id: 0,
            path: path.to_vec(),
        })?;
        match resp {
            Packet::Name { mut entries, .. } if !entries.is_empty() => {
                Ok(entries.remove(0).filename)
            }
            Packet::Status { code, message, .. } => Err(SftpError::Status {
                code,
                message: String::from_utf8_lossy(&message).into_owned(),
            }),
            _ => Err(SftpError::Protocol("sftp: expected NAME")),
        }
    }

    /// Create a symlink. Arguments use OpenSSH's order: (target_path,
    /// link_path) — i.e. "symlink pointing at `target_path` created at
    /// `link_path`".
    pub fn symlink(&mut self, target_path: &[u8], link_path: &[u8]) -> Result<(), SftpError> {
        let resp = self.request(Packet::Symlink {
            id: 0,
            target_path: target_path.to_vec(),
            link_path: link_path.to_vec(),
        })?;
        expect_ok(resp)
    }

    /// Read the target of a symlink.
    pub fn readlink(&mut self, path: &[u8]) -> Result<Vec<u8>, SftpError> {
        let resp = self.request(Packet::Readlink {
            id: 0,
            path: path.to_vec(),
        })?;
        match resp {
            Packet::Name { mut entries, .. } if !entries.is_empty() => {
                Ok(entries.remove(0).filename)
            }
            Packet::Status { code, message, .. } => Err(SftpError::Status {
                code,
                message: String::from_utf8_lossy(&message).into_owned(),
            }),
            _ => Err(SftpError::Protocol("sftp: expected NAME")),
        }
    }
}

fn expect_handle(p: Packet) -> Result<Vec<u8>, SftpError> {
    match p {
        Packet::Handle { handle, .. } => Ok(handle),
        Packet::Status { code, message, .. } => Err(SftpError::Status {
            code,
            message: String::from_utf8_lossy(&message).into_owned(),
        }),
        _ => Err(SftpError::Protocol("sftp: expected HANDLE")),
    }
}

fn expect_ok(p: Packet) -> Result<(), SftpError> {
    match p {
        Packet::Status {
            code: FxpStatus::Ok,
            ..
        } => Ok(()),
        Packet::Status { code, message, .. } => Err(SftpError::Status {
            code,
            message: String::from_utf8_lossy(&message).into_owned(),
        }),
        _ => Err(SftpError::Protocol("sftp: expected STATUS")),
    }
}

fn set_id(pkt: &mut Packet, new_id: u32) {
    match pkt {
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
        | Packet::Extended { id, .. } => *id = new_id,
        _ => {}
    }
}
