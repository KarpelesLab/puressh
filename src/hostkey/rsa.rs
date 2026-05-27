//! RSA host keys (RFC 8332):
//!
//! - `ssh-rsa`       — RSA + SHA-1 (legacy; disabled by default in modern OpenSSH)
//! - `rsa-sha2-256`  — RSA + SHA-256 (PKCS#1 v1.5)
//! - `rsa-sha2-512`  — RSA + SHA-512 (PKCS#1 v1.5)
//!
//! Backed by [`purecrypto::rsa::BoxedRsaPrivateKey`] (signing via
//! `sign_pkcs1v15::<D>`) and [`purecrypto::rsa::BoxedRsaPublicKey`]
//! (`verify_pkcs1v15::<D>`). Wire-format public key is `(n, e)` as two
//! `mpint`s; built from `BoxedRsaPublicKey::try_new(BoxedUint, BoxedUint)`.

use super::HostKeyAlgorithm;

/// `ssh-rsa` (RSA-SHA1, legacy).
pub struct SshRsa;
impl HostKeyAlgorithm for SshRsa {
    const NAME: &'static str = "ssh-rsa";
}

/// `rsa-sha2-256`.
pub struct RsaSha2_256;
impl HostKeyAlgorithm for RsaSha2_256 {
    const NAME: &'static str = "rsa-sha2-256";
}

/// `rsa-sha2-512`.
pub struct RsaSha2_512;
impl HostKeyAlgorithm for RsaSha2_512 {
    const NAME: &'static str = "rsa-sha2-512";
}
