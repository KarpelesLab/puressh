//! SCP (Secure CoPy) protocol — the wire format spoken by `scp -t` /
//! `scp -f` between a local and a remote OpenSSH `scp` binary. The
//! protocol predates SFTP and is loosely specified (the closest thing to
//! a reference is OpenSSH's own `scp.c`); the encoding is line-headers +
//! raw payload + single-byte acks, transported over any `Read+Write`
//! stream — typically a [`crate::client::ClientChannelStream`] driving
//! the remote `scp -t`/`scp -f` helper.
//!
//! # Layering
//!
//! - [`protocol`] — pure encode/decode of the four header kinds
//!   (`C`, `D`, `E`, `T`) and the three ack frames (`0x00`/`0x01`/`0x02`).
//!   No I/O.
//! - [`sender`] — [`Sender`] walks the local filesystem and writes the
//!   protocol to a stream. Used by the SCP client (`scp local: remote:`
//!   upload, server-side `scp -f` download).
//! - [`receiver`] — [`Receiver`] consumes the protocol on a stream and
//!   writes files into a base directory. Used by the SCP client
//!   (`scp remote: local:` download, server-side `scp -t` upload).
//!
//! Both sides refuse names containing `\0`, `\n`, or a leading `-` —
//! matching OpenSSH's hardening for CVE-2020-15778-class shell-injection
//! holes. They also refuse paths that lexically escape the base path on
//! the receiving side.
//!
//! # Note
//!
//! OpenSSH 9.0+ deprecated SCP in favour of SFTP-over-SSH. New code
//! should prefer [`crate::sftp::SftpClient`]. SCP support here exists for
//! interop with legacy infrastructure and the OpenSSH `scp` CLI.

#![cfg(feature = "std")]

pub mod protocol;
pub mod receiver;
pub mod sender;

#[cfg(test)]
mod tests;

pub use protocol::{Header, ScpError};
pub use receiver::{Receiver, ScpRecvOptions};
pub use sender::{ScpSendOptions, Sender};
