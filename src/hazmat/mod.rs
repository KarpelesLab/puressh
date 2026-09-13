//! Low-level, sans-IO protocol building blocks. **Hazardous materials.**
//!
//! Everything under `hazmat` is the raw machinery the [`driver`](crate::driver)
//! state machines are assembled from: wire-format codecs, the binary packet
//! protocol, key-exchange algorithms, cipher and MAC adapters, payload
//! compression and the RFC 4254 channel multiplexer. Each piece transforms
//! byte buffers and never touches a socket, but each also assumes its caller
//! is *the rest of this crate* and honours the invariants the layers above
//! enforce.
//!
//! These modules are exposed so that people building alternative frontends,
//! protocol tooling or conformance tests can reach them. They are **not**
//! part of the crate's stable API:
//!
//! - They carry no stability promise beyond the exact crate version you
//!   compiled against. Signatures, module layout and semantics may change in
//!   any release, including patch releases, without notice.
//! - Misuse can silently weaken security. Examples include reusing an AEAD
//!   nonce or packet sequence number, installing new keys in the wrong order
//!   around `SSH_MSG_NEWKEYS`, forgetting to bind the exchange hash to the
//!   negotiated algorithm lists, or feeding a decompressor untrusted data
//!   without the size limits the transport applies. None of these produce an
//!   error; they produce a connection that looks fine and is not.
//!
//! Ordinary users should use [`client`](crate::client), [`server`](crate::server)
//! (or their async/mio counterparts) and, for custom I/O, the sans-IO
//! [`driver`](crate::driver) instead. Those APIs are the ones this crate keeps
//! stable.

pub mod cipher;
pub mod format;
pub mod kex;
pub mod mac;
pub mod transport;

#[cfg(feature = "alloc")]
pub mod channel;

#[cfg(feature = "alloc")]
pub mod compress;

/// Sans-IO userauth (RFC 4252) state machines and wire messages.
///
/// The user-facing pieces of userauth — [`Authenticator`](crate::auth::Authenticator),
/// [`ClientCredential`](crate::auth::ClientCredential), [`SecretString`](crate::auth::SecretString),
/// … — live in [`crate::auth`]. This module re-exports the plumbing the
/// drivers use to run the exchange: the client/server step machines and the
/// raw message codecs.
#[cfg(feature = "alloc")]
pub mod auth {
    pub use crate::auth::message;
    pub use crate::auth::{ClientAuth, ClientStep, ServerAuth, ServerStep};
}
