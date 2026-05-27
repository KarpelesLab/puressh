#![cfg_attr(not(feature = "std"), no_std)]
#![cfg_attr(not(feature = "ffi"), forbid(unsafe_code))]
#![deny(rust_2018_idioms)]
#![warn(missing_docs)]

//! puressh — a pure-Rust SSH (Secure Shell) protocol library.
//!
//! Built on [`purecrypto`] for all cryptographic primitives, with no
//! foreign code in the dependency tree.
//!
//! The crate is split along the layers of RFC 4251–4254:
//!
//! - [`mod@format`] — SSH wire format primitives (`mpint`, `string`, `name-list`).
//! - [`transport`] — binary packet protocol, version exchange, KEX state machine.
//! - [`kex`]      — key-exchange algorithms (`curve25519-sha256`, `ecdh-sha2-nistp*`).
//! - [`cipher`]   — symmetric ciphers (`aes*-ctr`, `aes*-gcm`, `chacha20-poly1305`).
//! - [`mac`]      — message authentication codes (`hmac-sha2-*`, `*-etm`).
//! - [`hostkey`]  — host-key/signature algorithms (`ssh-ed25519`, `ecdsa-sha2-*`, `rsa-sha2-*`).
//! - [`auth`]     — userauth (RFC 4252).
//! - [`channel`]  — channels (RFC 4254).
//! - [`key`]      — OpenSSH key file parsing and serialisation.
//! - [`client`]   — high-level client API (feature `client`).
//! - [`server`]   — high-level server API (feature `server`).
//!
//! [`purecrypto`]: https://crates.io/crates/purecrypto

#[cfg(feature = "alloc")]
extern crate alloc;

pub mod auth;
pub mod channel;
pub mod cipher;
pub mod error;
pub mod format;
pub mod hostkey;
pub mod kex;
pub mod key;
pub mod mac;
pub mod transport;

#[cfg(feature = "compress")]
pub mod compress;

#[cfg(feature = "client")]
pub mod client;

#[cfg(feature = "server")]
pub mod server;

#[cfg(feature = "ffi")]
pub mod ffi;

pub use error::{Error, Result};
