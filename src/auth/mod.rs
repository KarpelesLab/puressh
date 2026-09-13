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

/// Wire-format codecs for the userauth messages (plumbing).
///
/// Only the sans-IO state machines need these; they are re-exported for
/// alternative frontends under [`crate::hazmat::auth::message`].
#[cfg(feature = "alloc")]
#[doc(hidden)]
pub mod message;

#[cfg(feature = "alloc")]
mod client;

#[cfg(feature = "alloc")]
mod server;

#[cfg(feature = "alloc")]
pub use client::{ClientCredential, KeyboardInteractiveResponder};
#[cfg(feature = "alloc")]
pub use message::SecretString;
#[cfg(feature = "alloc")]
pub use server::{AuthAttempt, AuthCertCaps, AuthDecision, Authenticator, CertInfo};

// The sans-IO step machines are plumbing the drivers are built from. They
// stay `pub` here because `client::Client::new_auth_driver` / `run_auth`
// hand them across module boundaries, but their documented home is
// `crate::hazmat::auth`.
#[cfg(feature = "alloc")]
#[doc(hidden)]
pub use client::{ClientAuth, ClientStep};
#[cfg(feature = "alloc")]
#[doc(hidden)]
pub use server::{ServerAuth, ServerStep};

#[cfg(all(test, feature = "alloc"))]
mod tests;
