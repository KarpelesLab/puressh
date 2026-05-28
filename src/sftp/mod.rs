//! SFTP v3 protocol implementation
//! ([draft-ietf-secsh-filexfer-02](https://datatracker.ietf.org/doc/html/draft-ietf-secsh-filexfer-02)).
//!
//! Pure-Rust and transport-agnostic. Both [`SftpClient`] and
//! [`SftpServerSession`] take any `Read+Write` — typically a channel
//! stream from the SSH connection layer running the `sftp` subsystem.
//!
//! # Layering
//!
//! - [`types`] — wire constants, [`Attrs`], [`FxpStatus`], [`SftpError`].
//! - [`packet`] — message types and encode/decode.
//! - [`path`] — virtual-cwd resolution with optional jail-root checking.
//! - [`server`] — [`SftpServerSession`].
//! - [`client`] — [`SftpClient`].

pub mod client;
pub mod packet;
pub mod path;
pub mod server;
pub mod types;

#[cfg(test)]
mod tests;

pub use client::SftpClient;
pub use server::{SftpServerOptions, SftpServerSession};
pub use types::{
    Attrs, FxpStatus, NameEntry, SftpError, ATTR_ACMODTIME, ATTR_EXTENDED, ATTR_PERMISSIONS,
    ATTR_SIZE, ATTR_UIDGID, FXF_APPEND, FXF_CREAT, FXF_EXCL, FXF_READ, FXF_TRUNC, FXF_WRITE,
    SFTP_VERSION,
};
