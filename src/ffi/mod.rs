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
//! - `#![cfg_attr(not(feature = "ffi"), forbid(unsafe_code))]` at the
//!   crate root (`src/lib.rs:1`) — any `unsafe` outside this directory
//!   tree is a build break.
//! - All entry points wrap their body in
//!   `catch_unwind(AssertUnwindSafe(...))` and return [`PCSSH_ERR_PANIC`]
//!   on unwind.
//! - Buffer-out APIs follow the "caller passes `cap`, callee writes
//!   required `out_len`, mismatch returns [`PCSSH_ERR_BUFFER_TOO_SMALL`]"
//!   pattern.

#![cfg(feature = "std")]
#![deny(unsafe_op_in_unsafe_fn)]
#![allow(clippy::missing_safety_doc)]

pub mod client;
pub mod common;

pub use client::*;
pub use common::*;
