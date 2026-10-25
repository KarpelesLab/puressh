//! C ABI / FFI surface for `puressh`.
//!
//! Exposes a client-side API to C callers covering:
//!
//! - Connect + KEX, password/publickey authentication, command exec
//!   ([`mod@client`]).
//! - More surfaces (SFTP, known_hosts, agent) land in follow-up modules
//!   under this directory.
//!
//! Errors are returned as small negative integers; see
//! [`pcssh_error_message`] for human-readable descriptions.
//!
//! This module is gated behind the `ffi` feature and only built with
//! `std`. Compiled as `staticlib` / `cdylib`, it produces `libpuressh.a`
//! and a platform-appropriate shared library.
//!
//! ## Invariants
//!
//! - Without `ffi`, the crate root forbids `unsafe` (denies it, with an
//!   exemption for the provider loader `sk`, when `security-key` is on):
//!   `unsafe` belongs in this directory tree and in that loader only.
//! - All entry points wrap their body in
//!   `catch_unwind(AssertUnwindSafe(...))` and return [`PCSSH_ERR_PANIC`]
//!   on unwind.
//! - Buffer-out APIs follow the "caller passes `cap`, callee writes
//!   required `out_len`, mismatch returns [`PCSSH_ERR_BUFFER_TOO_SMALL`]"
//!   pattern.

#![cfg(feature = "std")]
#![deny(unsafe_op_in_unsafe_fn)]
#![allow(clippy::missing_safety_doc)]

#[cfg(unix)]
pub mod agent;
pub mod client;
pub mod common;
pub mod known_hosts;
pub mod sftp;

#[cfg(unix)]
pub use agent::*;
pub use client::*;
pub use common::*;
pub use known_hosts::*;
pub use sftp::*;
