//! OpenSSH key file parsing and serialisation.
//!
//! Public keys use the single-line `<algorithm> <base64-blob> <comment>` form
//! (RFC 4716 is the older multi-line variant). Private keys use the OpenSSH
//! "new" PEM format with magic `b"openssh-key-v1\0"`, optionally encrypted
//! with `bcrypt_pbkdf` + a symmetric cipher.
//!
//! ⚠️ Decryption of password-protected OpenSSH keys requires `bcrypt_pbkdf`,
//! which is not in `purecrypto` v0.0.7. Until that lands, only **unencrypted**
//! OpenSSH private keys can be loaded. See `README.md` § "purecrypto gaps".

/// A parsed SSH public key — algorithm name and wire-format blob.
#[derive(Debug, Clone)]
#[cfg(feature = "alloc")]
pub struct PublicKey {
    /// SSH algorithm name (e.g. `"ssh-ed25519"`).
    pub algorithm: alloc::string::String,
    /// Wire-format public-key blob (the value that goes in a `string` field).
    pub blob: alloc::vec::Vec<u8>,
    /// Free-form comment (the trailing field on the `authorized_keys` line).
    pub comment: alloc::string::String,
}

/// A parsed OpenSSH private key.
#[derive(Debug)]
#[cfg(feature = "alloc")]
pub struct PrivateKey {
    /// SSH algorithm name.
    pub algorithm: alloc::string::String,
    /// Owned private-key bytes (algorithm-specific encoding).
    pub secret: alloc::vec::Vec<u8>,
    /// Matching public-key blob.
    pub public_blob: alloc::vec::Vec<u8>,
    /// Free-form comment.
    pub comment: alloc::string::String,
}
