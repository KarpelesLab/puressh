//! User authentication — RFC 4252.
//!
//! The transport carries an "ssh-userauth" service request, and from there the
//! peer sends `SSH_MSG_USERAUTH_REQUEST` messages whose `method` field selects
//! one of:
//!
//! - `"none"`         — probe to learn allowed methods
//! - `"password"`     — RFC 4252 §8
//! - `"publickey"`    — RFC 4252 §7
//! - `"keyboard-interactive"` — RFC 4256
//! - `"hostbased"`    — RFC 4252 §9
//!
//! Currently only `none`, `password`, and `publickey` are scaffolded.

/// Credentials a client can present.
#[derive(Debug, Clone)]
#[cfg(feature = "alloc")]
pub enum ClientCredential {
    /// Just probe the server for accepted methods.
    None,
    /// Password authentication.
    Password(alloc::string::String),
    /// Publickey — carries a host-key algorithm and a parsed private key.
    PublicKey {
        /// SSH algorithm name (e.g. `"ssh-ed25519"`).
        algorithm: &'static str,
        /// Serialised wire-format public-key blob.
        public_blob: alloc::vec::Vec<u8>,
        /// Owned private key material (algorithm-specific encoding).
        private_blob: alloc::vec::Vec<u8>,
    },
}

/// Outcome of a single authentication attempt.
#[derive(Debug, Clone)]
#[cfg(feature = "alloc")]
pub enum AuthOutcome {
    /// `SSH_MSG_USERAUTH_SUCCESS` — fully authenticated.
    Success,
    /// `SSH_MSG_USERAUTH_FAILURE` with the methods we can still try, and the
    /// `partial_success` flag.
    Failure {
        /// Methods the server still wants to see.
        continuations: alloc::vec::Vec<alloc::string::String>,
        /// Whether the failed attempt counted toward a multi-step success.
        partial_success: bool,
    },
}
