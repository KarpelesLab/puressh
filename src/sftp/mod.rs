//! SFTP v3 protocol implementation
//! ([draft-ietf-secsh-filexfer-02](https://datatracker.ietf.org/doc/html/draft-ietf-secsh-filexfer-02)).
//!
//! Pure-Rust and transport-agnostic. Both [`SftpClient`] and
//! [`SftpServerSession`] take any `Read+Write` — typically a channel
//! stream from the SSH connection layer running the `sftp` subsystem.
//!
//! # Layering
//!
//! - wire constants, [`Attrs`], [`FxpStatus`], [`SftpError`] — re-exported here;
//! - [`SftpServerSession`] — the server side;
//! - [`SftpClient`] — the client side.
//!
//! The packet codec, virtual-cwd path resolution and the `*@openssh.com`
//! extension tables are crate-private implementation details.

mod client;
pub(crate) mod extensions;
pub(crate) mod packet;
pub(crate) mod path;
mod server;
mod types;

#[cfg(test)]
mod tests;

pub use client::SftpClient;
pub use server::{SftpServerOptions, SftpServerSession};
pub use types::{
    ATTR_ACMODTIME, ATTR_EXTENDED, ATTR_PERMISSIONS, ATTR_SIZE, ATTR_UIDGID, Attrs, FXF_APPEND,
    FXF_CREAT, FXF_EXCL, FXF_READ, FXF_TRUNC, FXF_WRITE, FxpStatus, NameEntry, SFTP_VERSION,
    SftpError,
};
