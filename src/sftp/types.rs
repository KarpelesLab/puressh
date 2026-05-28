//! SFTP v3 types: attributes, status codes, errors.

use std::fmt;
use std::io;

/// SFTP version this implementation speaks
/// ([draft-ietf-secsh-filexfer-02](https://datatracker.ietf.org/doc/html/draft-ietf-secsh-filexfer-02)).
pub const SFTP_VERSION: u32 = 3;

/// File open flag: read access.
pub const FXF_READ: u32 = 0x00000001;
/// File open flag: write access.
pub const FXF_WRITE: u32 = 0x00000002;
/// File open flag: append-only (writes seek to end first).
pub const FXF_APPEND: u32 = 0x00000004;
/// File open flag: create if absent.
pub const FXF_CREAT: u32 = 0x00000008;
/// File open flag: truncate on open.
pub const FXF_TRUNC: u32 = 0x00000010;
/// File open flag: fail if the file already exists.
pub const FXF_EXCL: u32 = 0x00000020;

/// Attribute presence flag: `size` field is included.
pub const ATTR_SIZE: u32 = 0x00000001;
/// Attribute presence flag: `uid`/`gid` fields are included.
pub const ATTR_UIDGID: u32 = 0x00000002;
/// Attribute presence flag: `permissions` field is included.
pub const ATTR_PERMISSIONS: u32 = 0x00000004;
/// Attribute presence flag: `atime`/`mtime` fields are included.
pub const ATTR_ACMODTIME: u32 = 0x00000008;
/// Attribute presence flag: vendor-specific extended attributes follow.
pub const ATTR_EXTENDED: u32 = 0x80000000;

/// SFTP status code (`SSH_FX_*`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FxpStatus {
    /// `SSH_FX_OK` — success.
    Ok,
    /// `SSH_FX_EOF` — end of file reached on a read/readdir.
    Eof,
    /// `SSH_FX_NO_SUCH_FILE` — file/directory not found.
    NoSuchFile,
    /// `SSH_FX_PERMISSION_DENIED` — caller is not allowed to perform the op.
    PermissionDenied,
    /// `SSH_FX_FAILURE` — generic failure (used when no specific code fits).
    Failure,
    /// `SSH_FX_BAD_MESSAGE` — the packet was malformed.
    BadMessage,
    /// `SSH_FX_NO_CONNECTION` — pseudo-error, see RFC.
    NoConnection,
    /// `SSH_FX_CONNECTION_LOST` — pseudo-error, see RFC.
    ConnectionLost,
    /// `SSH_FX_OP_UNSUPPORTED` — request is not implemented.
    OpUnsupported,
}

impl FxpStatus {
    /// Wire-format integer code for this status.
    pub fn code(self) -> u32 {
        match self {
            FxpStatus::Ok => 0,
            FxpStatus::Eof => 1,
            FxpStatus::NoSuchFile => 2,
            FxpStatus::PermissionDenied => 3,
            FxpStatus::Failure => 4,
            FxpStatus::BadMessage => 5,
            FxpStatus::NoConnection => 6,
            FxpStatus::ConnectionLost => 7,
            FxpStatus::OpUnsupported => 8,
        }
    }

    /// Decode a wire-format code into the corresponding status. Unknown codes
    /// collapse to [`FxpStatus::Failure`].
    pub fn from_code(code: u32) -> Self {
        match code {
            0 => FxpStatus::Ok,
            1 => FxpStatus::Eof,
            2 => FxpStatus::NoSuchFile,
            3 => FxpStatus::PermissionDenied,
            5 => FxpStatus::BadMessage,
            6 => FxpStatus::NoConnection,
            7 => FxpStatus::ConnectionLost,
            8 => FxpStatus::OpUnsupported,
            _ => FxpStatus::Failure,
        }
    }

    /// Map a Rust I/O error kind to the closest SFTP status code.
    pub fn from_io(e: &io::Error) -> Self {
        use io::ErrorKind::*;
        match e.kind() {
            NotFound => FxpStatus::NoSuchFile,
            PermissionDenied => FxpStatus::PermissionDenied,
            AlreadyExists => FxpStatus::Failure,
            Unsupported => FxpStatus::OpUnsupported,
            _ => FxpStatus::Failure,
        }
    }
}

/// SFTP attribute record. Only fields whose `Option` is `Some` are sent on the wire.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Attrs {
    /// File size in bytes.
    pub size: Option<u64>,
    /// `(uid, gid)`.
    pub uid_gid: Option<(u32, u32)>,
    /// POSIX `st_mode` (including file-type bits).
    pub permissions: Option<u32>,
    /// `(atime, mtime)` as Unix seconds.
    pub atime_mtime: Option<(u32, u32)>,
    /// Vendor-specific extended attributes.
    pub extended: Vec<(Vec<u8>, Vec<u8>)>,
}

impl Attrs {
    /// True iff `permissions` declares this entry as a directory.
    pub fn is_dir(&self) -> bool {
        self.permissions.is_some_and(|m| (m & 0o170000) == 0o040000)
    }

    /// True iff `permissions` declares this entry as a regular file.
    pub fn is_file(&self) -> bool {
        self.permissions.is_some_and(|m| (m & 0o170000) == 0o100000)
    }

    /// True iff `permissions` declares this entry as a symbolic link.
    pub fn is_symlink(&self) -> bool {
        self.permissions.is_some_and(|m| (m & 0o170000) == 0o120000)
    }
}

/// One directory entry returned by `SSH_FXP_READDIR`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NameEntry {
    /// Bare file name (no path components).
    pub filename: Vec<u8>,
    /// `ls -l`-style line for display (server-formatted).
    pub longname: Vec<u8>,
    /// File attributes.
    pub attrs: Attrs,
}

/// Error type returned by SFTP client / server operations.
#[derive(Debug)]
pub enum SftpError {
    /// Underlying transport I/O failed.
    Io(io::Error),
    /// Wire format was malformed.
    Format(&'static str),
    /// Protocol invariant violated by the peer.
    Protocol(&'static str),
    /// Server returned an explicit SFTP status code.
    Status {
        /// The status code from the server.
        code: FxpStatus,
        /// Human-readable message (may be empty).
        message: String,
    },
}

impl fmt::Display for SftpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SftpError::Io(e) => write!(f, "sftp io: {e}"),
            SftpError::Format(s) => write!(f, "sftp format: {s}"),
            SftpError::Protocol(s) => write!(f, "sftp protocol: {s}"),
            SftpError::Status { code, message } => {
                if message.is_empty() {
                    write!(f, "sftp status: {code:?}")
                } else {
                    write!(f, "sftp status: {code:?} ({message})")
                }
            }
        }
    }
}

impl std::error::Error for SftpError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            SftpError::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<io::Error> for SftpError {
    fn from(e: io::Error) -> Self {
        SftpError::Io(e)
    }
}

impl From<crate::Error> for SftpError {
    fn from(e: crate::Error) -> Self {
        match e {
            crate::Error::Format(s) => SftpError::Format(s),
            crate::Error::Io(e) => SftpError::Io(e),
            other => SftpError::Protocol(match other {
                crate::Error::Protocol(s) => s,
                _ => "transport error",
            }),
        }
    }
}

impl SftpError {
    /// Construct a status-only error with no message.
    pub fn status(code: FxpStatus) -> Self {
        SftpError::Status {
            code,
            message: String::new(),
        }
    }

    /// Construct a status error with a message.
    pub fn status_msg(code: FxpStatus, message: impl Into<String>) -> Self {
        SftpError::Status {
            code,
            message: message.into(),
        }
    }
}
