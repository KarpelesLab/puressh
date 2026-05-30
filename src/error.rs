//! Crate-wide error type.

use core::fmt;

/// Convenience `Result` alias used throughout the crate.
pub type Result<T> = core::result::Result<T, Error>;

/// Errors produced by `puressh`.
#[non_exhaustive]
#[derive(Debug)]
pub enum Error {
    /// A wire-format value was malformed or truncated.
    Format(&'static str),
    /// Negotiation failed: no common algorithm between peers.
    NoCommonAlgorithm(&'static str),
    /// A protocol-level invariant was violated by the peer.
    Protocol(&'static str),
    /// MAC verification failed on an inbound packet.
    BadMac,
    /// AEAD authentication tag did not match.
    BadTag,
    /// Decryption produced an invalid plaintext (e.g. bad padding).
    BadPadding,
    /// Host-key signature failed to verify.
    BadSignature,
    /// Peer's host key was rejected by policy / known-hosts.
    HostKeyRejected,
    /// Authentication was refused or exhausted.
    AuthFailed,
    /// Requested channel operation is not valid in the current state.
    BadChannelState,
    /// A feature was requested that this build does not support.
    Unsupported(&'static str),
    /// I/O error (only with `std`).
    #[cfg(feature = "std")]
    Io(std::io::Error),
    /// Error originating from the `purecrypto` backend.
    Crypto(&'static str),
    /// A configuration value supplied to the library was internally
    /// inconsistent or insufficient (e.g. a `HostKeyPolicy::KnownHosts`
    /// without a connect target). Distinct from `Protocol` so callers can
    /// tell "I configured this wrong" from "the peer is misbehaving".
    Config(&'static str),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Format(s) => write!(f, "ssh wire format: {s}"),
            Error::NoCommonAlgorithm(s) => write!(f, "no common {s}"),
            Error::Protocol(s) => write!(f, "protocol error: {s}"),
            Error::BadMac => f.write_str("bad MAC"),
            Error::BadTag => f.write_str("bad AEAD tag"),
            Error::BadPadding => f.write_str("bad padding"),
            Error::BadSignature => f.write_str("bad signature"),
            Error::HostKeyRejected => f.write_str("host key rejected"),
            Error::AuthFailed => f.write_str("authentication failed"),
            Error::BadChannelState => f.write_str("bad channel state"),
            Error::Unsupported(s) => write!(f, "unsupported: {s}"),
            #[cfg(feature = "std")]
            Error::Io(e) => write!(f, "io: {e}"),
            Error::Crypto(s) => write!(f, "crypto: {s}"),
            Error::Config(s) => write!(f, "config error: {s}"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Io(e) => Some(e),
            _ => None,
        }
    }
}

#[cfg(feature = "std")]
impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Io(e)
    }
}
