//! SFTP v3 client.
//!
//! [`SftpClient::new`] takes any `Read+Write` transport (typically a
//! [`puressh::client::Client`](crate::client) channel running the `sftp`
//! subsystem) and exposes one method per SFTP operation. Each call writes
//! a request, reads the matching response, and validates the id round-trip
//! — there is no request pipelining at this layer.

use std::io::{Read, Write};

use crate::format::Reader;

use super::packet::{Packet, read_packet, write_packet};
use super::types::{Attrs, FxpStatus, NameEntry, SFTP_VERSION, SftpError};

/// User names and group names, as returned by
/// [`SftpClient::users_groups_by_id`].
pub type NameLists = (Vec<Vec<u8>>, Vec<Vec<u8>>);

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

    /// Whether the server advertised the extension `name` (for example
    /// `posix-rename@openssh.com`).
    pub fn has_extension(&self, name: &str) -> bool {
        self.extensions.iter().any(|(n, _)| n == name.as_bytes())
    }

    /// Send an `SSH_FXP_EXTENDED` request: `Some(data)` for an
    /// `EXTENDED_REPLY`, `None` for a success status.
    pub fn extended(&mut self, request: &str, data: &[u8]) -> Result<Option<Vec<u8>>, SftpError> {
        let resp = self.request(Packet::Extended {
            id: 0,
            request: request.as_bytes().to_vec(),
            data: data.to_vec(),
        })?;
        match resp {
            Packet::ExtendedReply { data, .. } => Ok(Some(data)),
            other => expect_ok(other).map(|()| None),
        }
    }

    /// `posix-rename@openssh.com`: rename, replacing an existing target.
    pub fn posix_rename(&mut self, oldpath: &[u8], newpath: &[u8]) -> Result<(), SftpError> {
        let mut d = Vec::new();
        put_string(&mut d, oldpath);
        put_string(&mut d, newpath);
        self.extended("posix-rename@openssh.com", &d).map(|_| ())
    }

    /// `copy-data`: copy `len` bytes (0: to the end) from offset
    /// `read_offset` of the open file `read_handle` into `write_handle` at
    /// `write_offset`, on the server.
    pub fn copy_data(
        &mut self,
        read_handle: &[u8],
        read_offset: u64,
        len: u64,
        write_handle: &[u8],
        write_offset: u64,
    ) -> Result<(), SftpError> {
        let mut d = Vec::new();
        put_string(&mut d, read_handle);
        d.extend_from_slice(&read_offset.to_be_bytes());
        d.extend_from_slice(&len.to_be_bytes());
        put_string(&mut d, write_handle);
        d.extend_from_slice(&write_offset.to_be_bytes());
        self.extended("copy-data", &d).map(|_| ())
    }

    /// `hardlink@openssh.com`: make `newpath` a hard link to `oldpath`.
    pub fn hardlink(&mut self, oldpath: &[u8], newpath: &[u8]) -> Result<(), SftpError> {
        let mut d = Vec::new();
        put_string(&mut d, oldpath);
        put_string(&mut d, newpath);
        self.extended("hardlink@openssh.com", &d).map(|_| ())
    }

    /// `lsetstat@openssh.com`: `setstat` that does not follow a final
    /// symlink (sftp's `chmod -h` & co.).
    pub fn lsetstat(&mut self, path: &[u8], attrs: &Attrs) -> Result<(), SftpError> {
        let mut d = Vec::new();
        put_string(&mut d, path);
        let mut w = crate::format::Writer::new();
        super::packet::encode_attrs(&mut w, attrs);
        d.extend_from_slice(&w.into_vec());
        self.extended("lsetstat@openssh.com", &d).map(|_| ())
    }

    /// `fsync@openssh.com`: flush an open file to stable storage.
    pub fn fsync(&mut self, handle: &[u8]) -> Result<(), SftpError> {
        let mut d = Vec::new();
        put_string(&mut d, handle);
        self.extended("fsync@openssh.com", &d).map(|_| ())
    }

    /// `users-groups-by-id@openssh.com`: the user names for `uids` and the
    /// group names for `gids`, in order (empty for an unknown id).
    pub fn users_groups_by_id(
        &mut self,
        uids: &[u32],
        gids: &[u32],
    ) -> Result<NameLists, SftpError> {
        let pack = |ids: &[u32]| {
            ids.iter()
                .flat_map(|i| i.to_be_bytes())
                .collect::<Vec<u8>>()
        };
        let mut d = Vec::new();
        put_string(&mut d, &pack(uids));
        put_string(&mut d, &pack(gids));
        let data =
            self.extended("users-groups-by-id@openssh.com", &d)?
                .ok_or(SftpError::Protocol(
                    "sftp: users-groups-by-id without a reply",
                ))?;
        let mut outer = Reader::new(&data);
        let mut list = |n: usize| -> Result<Vec<Vec<u8>>, SftpError> {
            let blob = outer
                .read_string()
                .map_err(|_| SftpError::Format("sftp: bad name list"))?;
            let mut r = Reader::new(blob);
            let mut out = Vec::with_capacity(n);
            for _ in 0..n {
                out.push(
                    r.read_string()
                        .map_err(|_| SftpError::Format("sftp: bad name list"))?
                        .to_vec(),
                );
            }
            Ok(out)
        };
        let users = list(uids.len())?;
        let groups = list(gids.len())?;
        Ok((users, groups))
    }

    /// `statvfs@openssh.com`: the eleven `struct statvfs` fields (bsize,
    /// frsize, blocks, bfree, bavail, files, ffree, favail, fsid, flag,
    /// namemax) of the filesystem holding `path`.
    pub fn statvfs(&mut self, path: &[u8]) -> Result<[u64; 11], SftpError> {
        let mut d = Vec::new();
        put_string(&mut d, path);
        let data = self
            .extended("statvfs@openssh.com", &d)?
            .ok_or(SftpError::Protocol("sftp: statvfs without a reply"))?;
        if data.len() < 88 {
            return Err(SftpError::Protocol("sftp: short statvfs reply"));
        }
        let mut out = [0u64; 11];
        for (i, v) in out.iter_mut().enumerate() {
            *v = u64::from_be_bytes(data[i * 8..i * 8 + 8].try_into().expect("8 bytes"));
        }
        Ok(out)
    }

    /// Send a request without waiting for its reply; returns its id.
    fn send(&mut self, mut pkt: Packet) -> Result<u32, SftpError> {
        let id = self.next_id();
        set_id(&mut pkt, id);
        write_packet(&mut self.transport, &pkt)?;
        Ok(id)
    }

    /// Receive the next reply, whatever request it answers.
    fn recv(&mut self) -> Result<(u32, Packet), SftpError> {
        let body = read_packet(&mut self.transport)?;
        let resp = Packet::decode(&body)?;
        let id = resp
            .id()
            .ok_or(SftpError::Protocol("sftp: reply without an id"))?;
        Ok((id, resp))
    }

    /// Read replies to the given outstanding requests and discard them, so
    /// the session stays in sync after an error.
    fn drain(&mut self, mut outstanding: usize) {
        while outstanding > 0 && self.recv().is_ok() {
            outstanding -= 1;
        }
    }

    /// Copy everything from `offset` to the end of the file behind `handle`
    /// into `sink`, keeping up to `depth` READ requests of `chunk` bytes in
    /// flight (OpenSSH's `-R` / `-B`), so throughput is not bounded by one
    /// round trip per chunk. Data reaches `sink` in order; `progress` gets
    /// the running byte count. Returns the bytes copied.
    pub fn read_to<W: Write>(
        &mut self,
        handle: &[u8],
        offset: u64,
        chunk: u32,
        depth: usize,
        sink: &mut W,
        mut progress: impl FnMut(u64),
    ) -> Result<u64, SftpError> {
        use std::collections::BTreeMap;
        let chunk = chunk.max(1);
        let depth = depth.max(1);
        let mut outstanding: BTreeMap<u32, (u64, u32)> = BTreeMap::new();
        let mut received: BTreeMap<u64, Vec<u8>> = BTreeMap::new();
        let mut next = offset;
        let mut written = offset;
        let mut eof: Option<u64> = None;
        let fail = |this: &mut Self, n: usize, e: SftpError| {
            this.drain(n);
            Err(e)
        };
        // Never run more than `depth` chunks ahead of what reached `sink`:
        // a server answering the lowest range a byte at a time while
        // completing later ones would otherwise grow `received` without
        // bound. The range at `written` is always outstanding (or past
        // EOF), so this cannot stall.
        let window = depth as u64 * u64::from(chunk);
        loop {
            while outstanding.len() < depth
                && next - written < window
                && eof.is_none_or(|e| next < e)
            {
                let id = self.send(Packet::Read {
                    id: 0,
                    handle: handle.to_vec(),
                    offset: next,
                    len: chunk,
                })?;
                outstanding.insert(id, (next, chunk));
                next += u64::from(chunk);
            }
            if outstanding.is_empty() {
                break;
            }
            let (id, resp) = self.recv()?;
            let Some((off, len)) = outstanding.remove(&id) else {
                return fail(
                    self,
                    outstanding.len(),
                    SftpError::Protocol("sftp: unexpected reply id"),
                );
            };
            match resp {
                Packet::Data { data, .. } if !data.is_empty() => {
                    let got = data.len() as u64;
                    if got > u64::from(len) {
                        return fail(
                            self,
                            outstanding.len(),
                            SftpError::Protocol("sftp: oversized DATA"),
                        );
                    }
                    if got < u64::from(len) && eof.is_none_or(|e| off + got < e) {
                        // Short read: ask for the rest of this range.
                        let rest = len - got as u32;
                        let id = self.send(Packet::Read {
                            id: 0,
                            handle: handle.to_vec(),
                            offset: off + got,
                            len: rest,
                        })?;
                        outstanding.insert(id, (off + got, rest));
                    }
                    received.insert(off, data);
                }
                Packet::Data { .. }
                | Packet::Status {
                    code: FxpStatus::Eof,
                    ..
                } => {
                    eof = Some(eof.map_or(off, |e| e.min(off)));
                }
                Packet::Status { code, message, .. } => {
                    return fail(
                        self,
                        outstanding.len(),
                        SftpError::Status {
                            code,
                            message: String::from_utf8_lossy(&message).into_owned(),
                        },
                    );
                }
                _ => {
                    return fail(
                        self,
                        outstanding.len(),
                        SftpError::Protocol("sftp: expected DATA or STATUS"),
                    );
                }
            }
            while let Some(data) = received.remove(&written) {
                if let Err(e) = sink.write_all(&data) {
                    return fail(self, outstanding.len(), SftpError::Io(e));
                }
                written += data.len() as u64;
                progress(written - offset);
            }
        }
        if !received.is_empty() {
            return Err(SftpError::Protocol("sftp: gap in file data"));
        }
        Ok(written - offset)
    }

    /// Write everything `src` yields to the file behind `handle` from
    /// `offset` on, keeping up to `depth` WRITE requests of `chunk` bytes in
    /// flight. `progress` gets the running byte count once each write is
    /// acknowledged. Returns the bytes written.
    pub fn write_from<R: Read>(
        &mut self,
        handle: &[u8],
        offset: u64,
        chunk: u32,
        depth: usize,
        src: &mut R,
        mut progress: impl FnMut(u64),
    ) -> Result<u64, SftpError> {
        let chunk = chunk.max(1) as usize;
        let depth = depth.max(1);
        let mut outstanding: Vec<(u32, u64)> = Vec::new();
        let mut next = offset;
        let mut acked = 0u64;
        let mut done = false;
        let mut buf = vec![0u8; chunk];
        loop {
            while !done && outstanding.len() < depth {
                // Fill a whole chunk unless the source ends.
                let mut n = 0;
                while n < chunk {
                    match src.read(&mut buf[n..]) {
                        Ok(0) => break,
                        Ok(k) => n += k,
                        Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                        Err(e) => {
                            let left = outstanding.len();
                            self.drain(left);
                            return Err(SftpError::Io(e));
                        }
                    }
                }
                if n == 0 {
                    done = true;
                    break;
                }
                let id = self.send(Packet::Write {
                    id: 0,
                    handle: handle.to_vec(),
                    offset: next,
                    data: buf[..n].to_vec(),
                })?;
                outstanding.push((id, n as u64));
                next += n as u64;
                if n < chunk {
                    done = true;
                }
            }
            if outstanding.is_empty() {
                break;
            }
            let (id, resp) = self.recv()?;
            let Some(pos) = outstanding.iter().position(|(i, _)| *i == id) else {
                let left = outstanding.len();
                self.drain(left);
                return Err(SftpError::Protocol("sftp: unexpected reply id"));
            };
            let (_, len) = outstanding.swap_remove(pos);
            if let Err(e) = expect_ok(resp) {
                let left = outstanding.len();
                self.drain(left);
                return Err(e);
            }
            acked += len;
            progress(acked);
        }
        Ok(next - offset)
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

fn put_string(out: &mut Vec<u8>, s: &[u8]) {
    out.extend_from_slice(&(s.len() as u32).to_be_bytes());
    out.extend_from_slice(s);
}
