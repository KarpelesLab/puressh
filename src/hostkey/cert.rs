//! Certificate host keys: a [`HostKey`] that presents an OpenSSH certificate
//! blob as its public part while signing with the underlying private key.
//!
//! The server uses this on both sides of certificate authentication:
//!
//! - **Host certs**: wrap the server's host key so KEX advertises the cert
//!   key-type and `public_blob()` returns the certificate (which the client
//!   parses and verifies against its trusted CA). `sign()` still uses the
//!   underlying key — the embedded key is what signs `H`.
//! - **User certs** (client side): wrap the user's identity key so the
//!   userauth publickey method offers the certificate; `sign()` signs the
//!   userauth request with the underlying private key.

use alloc::boxed::Box;
use alloc::vec::Vec;

use super::HostKey;
use crate::cert::Certificate;
use crate::error::{Error, Result};

/// A host key that presents a certificate as its public blob but signs with the
/// wrapped underlying key.
pub struct CertHostKey {
    inner: Box<dyn HostKey + Send + Sync>,
    cert_blob: Vec<u8>,
    cert_algo: &'static str,
}

impl CertHostKey {
    /// Wrap `inner` so it presents `cert`'s blob under the negotiated cert
    /// algorithm name `cert_algo` (e.g.
    /// `"ssh-ed25519-cert-v01@openssh.com"`).
    ///
    /// Verifies that the certificate's embedded public key matches `inner`'s
    /// public key — otherwise the server would advertise a cert for a key it
    /// cannot sign with, and KEX (whose exchange hash binds the cert blob but
    /// is signed by the embedded key) would fail at the client.
    pub fn new(
        inner: Box<dyn HostKey + Send + Sync>,
        cert: &Certificate,
        cert_algo: &'static str,
    ) -> Result<Self> {
        if inner.public_blob() != cert.embedded_pubkey_blob {
            return Err(Error::Config(
                "certificate embedded key does not match the host/identity key",
            ));
        }
        Ok(CertHostKey {
            inner,
            cert_blob: cert.raw.clone(),
            cert_algo,
        })
    }

    /// The wrapped underlying signer.
    pub fn inner(&self) -> &(dyn HostKey + Send + Sync) {
        self.inner.as_ref()
    }
}

impl HostKey for CertHostKey {
    fn algorithm(&self) -> &'static str {
        self.cert_algo
    }

    fn public_blob(&self) -> Vec<u8> {
        self.cert_blob.clone()
    }

    fn sign(&self, msg: &[u8]) -> Result<Vec<u8>> {
        // The certificate's embedded key signs H / the userauth blob. The
        // signature's own algorithm name (ssh-ed25519, rsa-sha2-512, …) is
        // exactly what the verifier expects from `Certificate::embedded_verifier`.
        self.inner.sign(msg)
    }
}

#[cfg(all(test, feature = "alloc"))]
mod tests {
    use super::*;
    use crate::hostkey::Ed25519HostKey;

    fn load(name: &str) -> Vec<u8> {
        let path = format!(
            "{}/tests/fixtures/cert/{}",
            env!("CARGO_MANIFEST_DIR"),
            name
        );
        let text = std::fs::read_to_string(path).unwrap();
        let b64 = text.split_whitespace().nth(1).unwrap();
        crate::key::base64::decode(b64.as_bytes()).unwrap()
    }

    #[test]
    fn mismatched_key_rejected() {
        let cert = Certificate::parse(&load("h_ed25519-cert.pub")).unwrap();
        // A random key that is NOT the cert's embedded key.
        let wrong = Box::new(Ed25519HostKey::from_seed([7u8; 32]));
        assert!(CertHostKey::new(wrong, &cert, "ssh-ed25519-cert-v01@openssh.com").is_err());
    }

    #[test]
    fn matched_key_presents_cert_blob() {
        let cert = Certificate::parse(&load("h_ed25519-cert.pub")).unwrap();
        let direct = Box::new(Ed25519HostKey::from_seed(seed_of("h_ed25519")));
        let ch = CertHostKey::new(direct, &cert, "ssh-ed25519-cert-v01@openssh.com").unwrap();
        assert_eq!(ch.algorithm(), "ssh-ed25519-cert-v01@openssh.com");
        assert_eq!(ch.public_blob(), cert.raw);
        // sign() delegates to the embedded key.
        let sig = ch.sign(b"H").unwrap();
        let verifier = cert.embedded_verifier(&sig).unwrap();
        verifier.verify(b"H", &sig).unwrap();
    }

    /// Pull the 32-byte ed25519 seed out of an OpenSSH private key fixture.
    fn seed_of(name: &str) -> [u8; 32] {
        let pem = std::fs::read_to_string(format!(
            "{}/tests/fixtures/cert/{}",
            env!("CARGO_MANIFEST_DIR"),
            name
        ))
        .unwrap();
        let sk = crate::key::PrivateKey::parse_openssh_pem(&pem, None).unwrap();
        match sk {
            crate::key::PrivateKey::Ed25519 { seed, .. } => seed,
            _ => panic!("not ed25519"),
        }
    }
}
