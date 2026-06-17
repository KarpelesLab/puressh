//! User authentication — RFC 4252 (with RFC 4256 keyboard-interactive).
//!
//! The transport layer first carries a `SSH_MSG_SERVICE_REQUEST` for
//! `"ssh-userauth"`; once accepted, the peer sends `SSH_MSG_USERAUTH_REQUEST`
//! messages whose `method` field selects one of:
//!
//! - `"none"`                 — probe to learn allowed methods
//! - `"password"`             — RFC 4252 §8
//! - `"publickey"`            — RFC 4252 §7
//! - `"keyboard-interactive"` — RFC 4256
//! - `"hostbased"`            — RFC 4252 §9 (not implemented here)
//!
//! Everything in this module is sans-I/O: state machines consume and produce
//! SSH *payload* bytes (the message-type byte plus method-specific fields)
//! and never touch sockets directly.

#[cfg(feature = "alloc")]
pub mod message;

#[cfg(feature = "alloc")]
mod client;

#[cfg(feature = "alloc")]
mod server;

#[cfg(feature = "alloc")]
pub use client::{ClientAuth, ClientCredential, ClientStep, KeyboardInteractiveResponder};

#[cfg(feature = "alloc")]
pub use server::{
    AuthAttempt, AuthCertCaps, AuthDecision, Authenticator, CertInfo, ServerAuth, ServerStep,
};

#[cfg(all(test, feature = "alloc"))]
mod tests;
