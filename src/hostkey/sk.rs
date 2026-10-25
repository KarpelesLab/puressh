//! FIDO/U2F security-key public keys (OpenSSH `PROTOCOL.u2f`):
//! `sk-ecdsa-sha2-nistp256@openssh.com` and `sk-ssh-ed25519@openssh.com`,
//! verification only. The private half lives on the authenticator.
//!
//! The authenticator does not sign the message itself but
//! `SHA256(application) || flags || counter || [extensions] || SHA256(msg)`,
//! and the signature blob carries the `flags` and `counter` it used. A
//! verifier accepts the signature; whether the flags meet the policy (user
//! presence, user verification) is the caller's decision, through
//! [`sk_signature_flags`].
//!
//! `webauthn-sk-ecdsa-sha2-nistp256@openssh.com` signatures (made by a
//! browser on behalf of an `sk-ecdsa` key) sign a WebAuthn `clientData`
//! JSON whose challenge is the message instead of the message's hash; they
//! verify against the same `sk-ecdsa` public key.

use alloc::vec::Vec;

use purecrypto::ec::{BoxedEcdsaPublicKey, Ed25519PublicKey, Ed25519Signature};
use purecrypto::hash::{Digest, Sha256};

use super::HostKeyVerify;
use crate::error::{Error, Result};
use crate::format::{Reader, Writer};

/// `sk-ecdsa-sha2-nistp256@openssh.com`.
pub const SK_ECDSA: &str = "sk-ecdsa-sha2-nistp256@openssh.com";
/// `sk-ssh-ed25519@openssh.com`.
pub const SK_ED25519: &str = "sk-ssh-ed25519@openssh.com";
/// The signature name of an `sk-ecdsa` key signed through WebAuthn.
pub const WEBAUTHN_SK_ECDSA: &str = "webauthn-sk-ecdsa-sha2-nistp256@openssh.com";

/// Signature flag: the user touched the authenticator.
pub const SK_USER_PRESENCE: u8 = 0x01;
/// Signature flag: the authenticator verified the user (PIN, biometric).
pub const SK_USER_VERIFICATION: u8 = 0x04;

/// WebAuthn authenticator-data flags that must agree with the signature.
const WEBAUTHN_AD: u8 = 0x40;
const WEBAUTHN_ED: u8 = 0x80;

/// The `flags` byte of a security-key signature blob, or `None` for any
/// other signature (or a malformed one).
pub fn sk_signature_flags(sig_blob: &[u8]) -> Option<u8> {
    let mut r = Reader::new(sig_blob);
    let name = r.read_string().ok()?;
    if name != SK_ECDSA.as_bytes()
        && name != SK_ED25519.as_bytes()
        && name != WEBAUTHN_SK_ECDSA.as_bytes()
    {
        return None;
    }
    r.read_string().ok()?;
    r.read_u8().ok()
}

/// The `flags` and `counter` of a security-key signature blob, or `None`
/// for any other signature (or a malformed one).
pub fn sk_signature_details(sig_blob: &[u8]) -> Option<(u8, u32)> {
    sk_signature_flags(sig_blob)?;
    let mut r = Reader::new(sig_blob);
    r.read_string().ok()?;
    r.read_string().ok()?;
    Some((r.read_u8().ok()?, r.read_u32().ok()?))
}

/// Whether `name` is a security-key algorithm (plain or certificate, and
/// the WebAuthn signature name).
pub fn is_sk_algorithm(name: &str) -> bool {
    name.starts_with("sk-") || name.starts_with("webauthn-sk-")
}

/// `SHA256(application) || flags || counter || extensions || msghash`:
/// what the authenticator signed.
fn signed_data(
    application: &[u8],
    flags: u8,
    counter: u32,
    exts: &[u8],
    msghash: &[u8],
) -> Vec<u8> {
    let mut w = Writer::new();
    w.write_raw(Sha256::digest(application).as_ref());
    w.write_u8(flags);
    w.write_u32(counter);
    w.write_raw(exts);
    w.write_raw(msghash);
    w.into_vec()
}

/// Read the `application` string that ends a security-key public blob.
fn read_application<'a>(r: &mut Reader<'a>) -> Result<&'a [u8]> {
    let app = r.read_string()?;
    if !r.is_empty() {
        return Err(Error::Format("sk: public key trailing data"));
    }
    Ok(app)
}

/// An `sk-ecdsa-sha2-nistp256@openssh.com` public key.
pub struct SkEcdsaP256Key {
    public: BoxedEcdsaPublicKey,
    application: Vec<u8>,
}

impl SkEcdsaP256Key {
    /// The FIDO application (relying party) the key was enrolled for,
    /// normally `ssh:`.
    pub fn application(&self) -> &[u8] {
        &self.application
    }
}

impl HostKeyVerify for SkEcdsaP256Key {
    fn algorithm(&self) -> &'static str {
        SK_ECDSA
    }

    fn verify(&self, msg: &[u8], sig_blob: &[u8]) -> Result<()> {
        let mut r = Reader::new(sig_blob);
        let name = r.read_string()?;
        let webauthn = if name == WEBAUTHN_SK_ECDSA.as_bytes() {
            true
        } else if name == SK_ECDSA.as_bytes() {
            false
        } else {
            return Err(Error::Format("sk-ecdsa: signature algorithm mismatch"));
        };
        let inner = r.read_string()?;
        let flags = r.read_u8()?;
        let counter = r.read_u32()?;
        let (msghash, exts) = if webauthn {
            let origin = r.read_string()?;
            let client_data = r.read_string()?;
            let exts = r.read_string()?;
            (webauthn_hash(msg, origin, client_data, flags, exts)?, exts)
        } else {
            (Sha256::digest(msg).as_ref().to_vec(), &[][..])
        };
        if !r.is_empty() {
            return Err(Error::Format("sk-ecdsa: signature trailing data"));
        }
        let signed = signed_data(&self.application, flags, counter, exts, &msghash);
        super::ecdsa::verify_p256_inner(&self.public, &signed, inner)
    }

    fn from_public_blob(blob: &[u8]) -> Result<Self> {
        let mut r = Reader::new(blob);
        if r.read_string()? != SK_ECDSA.as_bytes() {
            return Err(Error::Format("sk-ecdsa: public key type mismatch"));
        }
        if r.read_string()? != b"nistp256" {
            return Err(Error::Format("sk-ecdsa: curve identifier mismatch"));
        }
        let public = super::ecdsa::p256_from_sec1(r.read_string()?)?;
        let application = read_application(&mut r)?.to_vec();
        Ok(Self {
            public,
            application,
        })
    }
}

/// The hash a WebAuthn signature covers in place of `SHA256(msg)`: that of
/// the `clientData` JSON, after checking it opens with the challenge (`msg`)
/// and `origin` in their canonical places, as OpenSSH does. Extra fields
/// after them (`crossOrigin`, …) are not inspected.
fn webauthn_hash(
    msg: &[u8],
    origin: &[u8],
    client_data: &[u8],
    flags: u8,
    exts: &[u8],
) -> Result<Vec<u8>> {
    if origin.contains(&b'"')
        || flags & WEBAUTHN_AD != 0
        || (flags & WEBAUTHN_ED == 0) != exts.is_empty()
    {
        return Err(Error::Format("sk-ecdsa: inconsistent webauthn signature"));
    }
    let mut want = Vec::new();
    want.extend_from_slice(b"{\"type\":\"webauthn.get\",\"challenge\":\"");
    base64url_nopad(msg, &mut want);
    want.extend_from_slice(b"\",\"origin\":\"");
    want.extend_from_slice(origin);
    want.push(b'"');
    if !client_data.starts_with(&want) {
        return Err(Error::BadSignature);
    }
    Ok(Sha256::digest(client_data).as_ref().to_vec())
}

/// Unpadded base64url (RFC 4648 §5), as WebAuthn encodes the challenge.
fn base64url_nopad(data: &[u8], out: &mut Vec<u8>) {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    for chunk in data.chunks(3) {
        let n = chunk
            .iter()
            .enumerate()
            .fold(0u32, |n, (i, &b)| n | u32::from(b) << (16 - 8 * i));
        for i in 0..=chunk.len() {
            out.push(ALPHABET[(n >> (18 - 6 * i) & 63) as usize]);
        }
    }
}

/// An `sk-ssh-ed25519@openssh.com` public key.
pub struct SkEd25519Key {
    public: Ed25519PublicKey,
    application: Vec<u8>,
}

impl SkEd25519Key {
    /// The FIDO application (relying party) the key was enrolled for,
    /// normally `ssh:`.
    pub fn application(&self) -> &[u8] {
        &self.application
    }
}

impl HostKeyVerify for SkEd25519Key {
    fn algorithm(&self) -> &'static str {
        SK_ED25519
    }

    fn verify(&self, msg: &[u8], sig_blob: &[u8]) -> Result<()> {
        let mut r = Reader::new(sig_blob);
        if r.read_string()? != SK_ED25519.as_bytes() {
            return Err(Error::Format("sk-ed25519: signature algorithm mismatch"));
        }
        let raw = r.read_string()?;
        let flags = r.read_u8()?;
        let counter = r.read_u32()?;
        if !r.is_empty() {
            return Err(Error::Format("sk-ed25519: signature trailing data"));
        }
        let raw: [u8; 64] = raw
            .try_into()
            .map_err(|_| Error::Format("sk-ed25519: signature length"))?;
        let signed = signed_data(
            &self.application,
            flags,
            counter,
            &[],
            Sha256::digest(msg).as_ref(),
        );
        self.public
            .verify(&signed, &Ed25519Signature::from_bytes(raw))
            .map_err(|_| Error::BadSignature)
    }

    fn from_public_blob(blob: &[u8]) -> Result<Self> {
        let mut r = Reader::new(blob);
        if r.read_string()? != SK_ED25519.as_bytes() {
            return Err(Error::Format("sk-ed25519: public key type mismatch"));
        }
        let pk: [u8; 32] = r
            .read_string()?
            .try_into()
            .map_err(|_| Error::Format("sk-ed25519: public key length"))?;
        let application = read_application(&mut r)?.to_vec();
        Ok(Self {
            public: Ed25519PublicKey::from_bytes(pk),
            application,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A file made by OpenSSH 10.6's `ssh-keygen` with its `sk-dummy`
    /// software authenticator.
    #[cfg(feature = "std")]
    fn fixture(name: &str) -> std::string::String {
        let path = std::format!("{}/tests/fixtures/sk/{name}", env!("CARGO_MANIFEST_DIR"));
        std::fs::read_to_string(path).unwrap()
    }

    /// OpenSSH's `ssh-keygen -Y sign` signatures verify, and fail over any
    /// other message.
    #[cfg(feature = "std")]
    #[test]
    fn openssh_signatures_verify() {
        let msg = fixture("msg");
        for t in ["ecdsa-sk", "ed25519-sk"] {
            let sig =
                crate::sshsig::Signature::from_armored(&fixture(&std::format!("{t}.sig"))).unwrap();
            let key = crate::key::PublicKey::parse_authorized_keys_line(&fixture(&std::format!(
                "{t}.pub"
            )))
            .unwrap();
            assert_eq!(sig.public_key, key.wire_blob(), "{t}");
            sig.verify("file", &sig.hash.digest(msg.as_bytes()))
                .unwrap();
            assert!(
                sig.verify("file", &sig.hash.digest(b"other")).is_err(),
                "{t}"
            );
            assert!(
                sig.verify("git", &sig.hash.digest(msg.as_bytes())).is_err(),
                "{t}"
            );
        }
    }

    /// The signature flags reach the caller: `sk-dummy` signs with user
    /// presence set.
    #[cfg(feature = "std")]
    #[test]
    fn openssh_signature_flags() {
        for t in ["ecdsa-sk", "ed25519-sk"] {
            let sig =
                crate::sshsig::Signature::from_armored(&fixture(&std::format!("{t}.sig"))).unwrap();
            let flags = sk_signature_flags(&sig.signature).unwrap();
            assert_eq!(flags & SK_USER_PRESENCE, SK_USER_PRESENCE, "{t}");
        }
    }

    /// Security-key private key files and certificates as OpenSSH writes
    /// them: the key round-trips, and the certificate carries the
    /// security-key options and embeds the same key.
    #[cfg(feature = "std")]
    #[test]
    fn openssh_key_files_and_certificates() {
        for t in ["ecdsa-sk", "ed25519-sk"] {
            let pk = crate::key::PrivateKey::parse_openssh_pem(&fixture(t), None).unwrap();
            let public = crate::key::PublicKey::parse_authorized_keys_line(&fixture(
                &std::format!("{t}.pub"),
            ))
            .unwrap();
            assert_eq!(pk.public_key().wire_blob(), public.wire_blob(), "{t}");
            let sk = pk.sk_credential().unwrap();
            assert_eq!(sk.application, "ssh:");
            assert!(!sk.key_handle.is_empty());
            let written = pk.to_openssh_pem(None).unwrap();
            let again = crate::key::PrivateKey::parse_openssh_pem(&written, None).unwrap();
            assert_eq!(again.sk_credential(), pk.sk_credential(), "{t}");
            assert_eq!(again.public_key().wire_blob(), public.wire_blob(), "{t}");

            let cert = crate::cert::Certificate::parse_openssh_line(&fixture(&std::format!(
                "{t}-cert.pub"
            )))
            .unwrap();
            assert_eq!(cert.embedded_pubkey_blob(), public.wire_blob(), "{t}");
            cert.require_known_critical_options().unwrap();
            assert!(cert.critical_option("verify-required").is_some());
            assert!(
                cert.extensions
                    .iter()
                    .any(|(n, _)| n == "no-touch-required")
            );
            cert.verify_ca_signature(crate::config::algos::CA_SIGNATURE_DEFAULTS)
                .unwrap();
        }
    }

    #[test]
    fn base64url_matches_rfc4648() {
        for (input, want) in [
            (&b""[..], ""),
            (b"f", "Zg"),
            (b"fo", "Zm8"),
            (b"foo", "Zm9v"),
            (b"foob", "Zm9vYg"),
            (b"\xfb\xff", "-_8"),
        ] {
            let mut out = Vec::new();
            base64url_nopad(input, &mut out);
            assert_eq!(out, want.as_bytes(), "{input:?}");
        }
    }

    #[test]
    fn flags_only_for_sk_signatures() {
        let mut w = Writer::new();
        w.write_string(SK_ED25519.as_bytes());
        w.write_string(&[0u8; 64]);
        w.write_u8(SK_USER_PRESENCE | SK_USER_VERIFICATION);
        w.write_u32(7);
        assert_eq!(sk_signature_flags(w.as_slice()), Some(0x05));
        let mut w = Writer::new();
        w.write_string(b"ssh-ed25519");
        w.write_string(&[0u8; 64]);
        assert_eq!(sk_signature_flags(w.as_slice()), None);
    }
}
