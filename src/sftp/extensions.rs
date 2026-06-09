//! OpenSSH SFTP-extension handlers.
//!
//! These implement the `*@openssh.com` extensions OpenSSH's `sftp-server`
//! advertises in its `SSH_FXP_VERSION` reply and accepts via
//! `SSH_FXP_EXTENDED`. The wire formats follow the openssh-portable
//! `PROTOCOL` document, section "SFTP extensions".
//!
//! The extension dispatcher is invoked from [`super::server`] when an
//! `SSH_FXP_EXTENDED` packet arrives; unknown extension names collapse to
//! `SSH_FX_OP_UNSUPPORTED`.

use super::types::FxpStatus;

/// `posix-rename@openssh.com` — atomic `rename(2)`, overwriting destination.
pub const EXT_POSIX_RENAME: &str = "posix-rename@openssh.com";
/// `statvfs@openssh.com` — `statvfs(3)` by path.
pub const EXT_STATVFS: &str = "statvfs@openssh.com";
/// `fstatvfs@openssh.com` — `fstatvfs(3)` by handle.
pub const EXT_FSTATVFS: &str = "fstatvfs@openssh.com";
/// `hardlink@openssh.com` — `link(2)`.
pub const EXT_HARDLINK: &str = "hardlink@openssh.com";
/// `fsync@openssh.com` — `fsync(2)` on an open handle.
pub const EXT_FSYNC: &str = "fsync@openssh.com";

/// OpenSSH's `SSH_FXE_STATVFS_ST_RDONLY` mount-flag bit. Wire-level value.
pub const SSH_FXE_STATVFS_ST_RDONLY: u64 = 0x1;
/// OpenSSH's `SSH_FXE_STATVFS_ST_NOSUID` mount-flag bit. Wire-level value.
pub const SSH_FXE_STATVFS_ST_NOSUID: u64 = 0x2;

/// The `(name, version)` pairs we advertise in our `SSH_FXP_VERSION` reply.
pub const ADVERTISED_EXTENSIONS: &[(&str, &str)] = &[
    (EXT_POSIX_RENAME, "1"),
    (EXT_STATVFS, "2"),
    (EXT_FSTATVFS, "2"),
    (EXT_HARDLINK, "1"),
    (EXT_FSYNC, "1"),
];

/// Wire-format payload for the `statvfs@openssh.com` / `fstatvfs@openssh.com`
/// reply. Fields mirror the POSIX `struct statvfs`.
#[cfg(unix)]
#[derive(Debug, Clone, Copy)]
pub struct StatvfsReply {
    /// `f_bsize` — fundamental block size.
    pub bsize: u64,
    /// `f_frsize` — fragment size.
    pub frsize: u64,
    /// `f_blocks` — total blocks (in units of `f_frsize`).
    pub blocks: u64,
    /// `f_bfree` — free blocks.
    pub bfree: u64,
    /// `f_bavail` — free blocks for unprivileged users.
    pub bavail: u64,
    /// `f_files` — total inodes.
    pub files: u64,
    /// `f_ffree` — free inodes.
    pub ffree: u64,
    /// `f_favail` — free inodes for unprivileged users.
    pub favail: u64,
    /// `f_fsid` — filesystem id.
    pub fsid: u64,
    /// `f_flag` — already mapped to OpenSSH's `SSH_FXE_STATVFS_*` bits.
    pub flag: u64,
    /// `f_namemax` — maximum filename length.
    pub namemax: u64,
}

#[cfg(unix)]
impl StatvfsReply {
    /// Build from a `nix::sys::statvfs::Statvfs` and map the OS-specific
    /// flag bits to the wire-level `SSH_FXE_STATVFS_*` values OpenSSH
    /// expects.
    pub fn from_nix(s: &nix::sys::statvfs::Statvfs) -> Self {
        let nix_flags = s.flags();
        let mut flag: u64 = 0;
        if nix_flags.contains(nix::sys::statvfs::FsFlags::ST_RDONLY) {
            flag |= SSH_FXE_STATVFS_ST_RDONLY;
        }
        if nix_flags.contains(nix::sys::statvfs::FsFlags::ST_NOSUID) {
            flag |= SSH_FXE_STATVFS_ST_NOSUID;
        }
        // The accessor return types are libc-defined and vary by target:
        // `c_ulong` is `u64` on 64-bit Linux but `u32` on 32-bit platforms,
        // and `fsblkcnt_t` / `fsfilcnt_t` can be either too. `as u64` is the
        // portable widen — clippy on a 64-bit host calls it redundant, but
        // dropping the cast breaks 32-bit builds. Silence the lint here.
        #[allow(clippy::unnecessary_cast)]
        Self {
            bsize: s.block_size() as u64,
            frsize: s.fragment_size() as u64,
            blocks: s.blocks() as u64,
            bfree: s.blocks_free() as u64,
            bavail: s.blocks_available() as u64,
            files: s.files() as u64,
            ffree: s.files_free() as u64,
            favail: s.files_available() as u64,
            fsid: s.filesystem_id() as u64,
            flag,
            namemax: s.name_max() as u64,
        }
    }

    /// Encode as the eleven `uint64`s the OpenSSH protocol expects in the
    /// `SSH_FXP_EXTENDED_REPLY` body.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(8 * 11);
        for v in [
            self.bsize,
            self.frsize,
            self.blocks,
            self.bfree,
            self.bavail,
            self.files,
            self.ffree,
            self.favail,
            self.fsid,
            self.flag,
            self.namemax,
        ] {
            out.extend_from_slice(&v.to_be_bytes());
        }
        out
    }
}

/// Translate a `nix::errno::Errno` into the closest SFTP status code.
#[cfg(unix)]
pub fn fxp_status_from_errno(e: nix::errno::Errno) -> FxpStatus {
    use nix::errno::Errno;
    match e {
        Errno::ENOENT => FxpStatus::NoSuchFile,
        Errno::EACCES | Errno::EPERM => FxpStatus::PermissionDenied,
        _ => FxpStatus::Failure,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn advertised_extensions_include_all_five() {
        let names: Vec<&str> = ADVERTISED_EXTENSIONS.iter().map(|(n, _)| *n).collect();
        assert!(names.contains(&EXT_POSIX_RENAME));
        assert!(names.contains(&EXT_STATVFS));
        assert!(names.contains(&EXT_FSTATVFS));
        assert!(names.contains(&EXT_HARDLINK));
        assert!(names.contains(&EXT_FSYNC));
    }

    #[cfg(unix)]
    #[test]
    fn statvfs_reply_encodes_eleven_u64s() {
        let r = StatvfsReply {
            bsize: 1,
            frsize: 2,
            blocks: 3,
            bfree: 4,
            bavail: 5,
            files: 6,
            ffree: 7,
            favail: 8,
            fsid: 9,
            flag: 10,
            namemax: 11,
        };
        let bytes = r.encode();
        assert_eq!(bytes.len(), 8 * 11);
        // Last 8 bytes should be 11 as big-endian u64.
        assert_eq!(&bytes[80..], &11u64.to_be_bytes());
    }
}
