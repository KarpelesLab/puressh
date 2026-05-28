//! OpenSSH `known_hosts` format: parse, store, lookup, and rewrite.
//!
//! [`KnownHosts`] holds an in-memory model of an OpenSSH-format
//! `known_hosts` file. It supports:
//!
//! - Plain entries: `host[,host…] keytype base64-key [comment]`
//! - Bracketed-host-with-port: `[host]:port keytype base64-key`
//! - Hashed entries (RFC 4255 §3.2 / OpenSSH `HashKnownHosts`):
//!   `|1|<base64-salt>|<base64-hmac-sha1-of-host> keytype base64-key`
//! - Marker lines: `@cert-authority host keytype base64-key`,
//!   `@revoked host keytype base64-key`
//!
//! Lookups return one of [`LookupResult::Match`], [`LookupResult::Mismatch`],
//! or [`LookupResult::Unknown`]. `Mismatch` is the security-relevant case:
//! the host is known but the key is wrong (or the key is `@revoked`).
//!
//! ```ignore
//! use puressh::known_hosts::KnownHosts;
//!
//! let mut kh = KnownHosts::load("/home/user/.ssh/known_hosts")?;
//! match kh.lookup("example.com", 22, b"\0\0\0...") {
//!     puressh::known_hosts::LookupResult::Match => { /* connect */ }
//!     puressh::known_hosts::LookupResult::Mismatch { .. } => { /* refuse */ }
//!     puressh::known_hosts::LookupResult::Unknown => {
//!         kh.add("example.com", 22, "ssh-ed25519", b"\0\0\0...");
//!         kh.save("/home/user/.ssh/known_hosts")?;
//!     }
//! }
//! ```

#![cfg(feature = "std")]

pub mod format;
pub mod hash;
pub mod store;

#[cfg(test)]
mod tests;

pub use store::{KnownHosts, LookupResult};
