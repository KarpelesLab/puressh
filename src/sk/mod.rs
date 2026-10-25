//! FIDO security keys: the authenticator side of `sk-ecdsa-sha2-nistp256`
//! and `sk-ssh-ed25519` keys (OpenSSH `PROTOCOL.u2f`).
//!
//! An authenticator is reached through a *provider*, OpenSSH's
//! `SecurityKeyProvider`: either a shared library implementing OpenSSH's
//! middleware API (`sk-api.h`: `sk_enroll`, `sk_sign`,
//! `sk_load_resident_keys`), loaded at run time, or `internal`, which talks
//! to USB authenticators through libfido2 (also loaded at run time).
//!
//! On top of a [`Provider`], [`enroll`] makes a key, [`sign`] signs with
//! one, [`load_resident_keys`] downloads the discoverable ones, and
//! [`SkSigner`] is a [`HostKey`](crate::hostkey::HostKey) for user
//! authentication.

use alloc::string::String;
use alloc::vec::Vec;
use std::ffi::{CStr, CString, c_char, c_int};
use std::sync::Arc;

use purecrypto::zeroize::{Zeroize, Zeroizing};

use crate::error::{Error, Result};
use crate::format::{Writer, write_mpint};
use crate::hostkey::sk::{SK_ECDSA, SK_ED25519};
use crate::key::{PrivateKey, SkCredential};

mod external;
#[cfg(not(windows))]
mod fido2;

pub use external::ExternalProvider;

/// Enrolment / signature flag: require user presence (a touch).
pub const USER_PRESENCE_REQD: u8 = 0x01;
/// Require user verification (PIN, biometric).
pub const USER_VERIFICATION_REQD: u8 = 0x04;
/// Overwrite an existing resident credential at enrolment.
pub const FORCE_OPERATION: u8 = 0x10;
/// Make a resident (discoverable) credential.
pub const RESIDENT_KEY: u8 = 0x20;

/// The middleware API major version this build implements (OpenSSH 10).
pub const API_VERSION_MAJOR: u32 = 0x000a_0000;
const API_VERSION_MAJOR_MASK: u32 = 0xffff_0000;

/// A security-key algorithm.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Algorithm {
    /// ECDSA on NIST P-256 (`sk-ecdsa-sha2-nistp256@openssh.com`).
    EcdsaP256,
    /// Ed25519 (`sk-ssh-ed25519@openssh.com`).
    Ed25519,
}

impl Algorithm {
    /// The middleware API's number for it.
    pub fn id(self) -> u32 {
        match self {
            Algorithm::EcdsaP256 => 0,
            Algorithm::Ed25519 => 1,
        }
    }

    fn from_id(id: u32) -> Option<Self> {
        match id {
            0 => Some(Algorithm::EcdsaP256),
            1 => Some(Algorithm::Ed25519),
            _ => None,
        }
    }

    /// The key's SSH name.
    pub fn name(self) -> &'static str {
        match self {
            Algorithm::EcdsaP256 => SK_ECDSA,
            Algorithm::Ed25519 => SK_ED25519,
        }
    }

    /// The algorithm of an SSH key name (`ecdsa-sk` and `ed25519-sk` too,
    /// as `ssh-keygen -t` spells them).
    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            SK_ECDSA | "ecdsa-sk" => Some(Algorithm::EcdsaP256),
            SK_ED25519 | "ed25519-sk" => Some(Algorithm::Ed25519),
            _ => None,
        }
    }
}

/// A provider failure, as the middleware API reports them.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum SkError {
    /// Any other failure (`SSH_SK_ERR_GENERAL`).
    General,
    /// The operation or algorithm is not supported.
    Unsupported,
    /// The authenticator wants a PIN: retry with one.
    PinRequired,
    /// No authenticator present.
    DeviceNotFound,
    /// A resident credential exists already (retry with
    /// [`FORCE_OPERATION`] to overwrite it).
    CredentialExists,
    /// The provider could not be loaded or used.
    Provider(String),
}

impl SkError {
    fn from_code(code: c_int) -> Self {
        match code {
            -2 => SkError::Unsupported,
            -3 => SkError::PinRequired,
            -4 => SkError::DeviceNotFound,
            -5 => SkError::CredentialExists,
            _ => SkError::General,
        }
    }
}

impl core::fmt::Display for SkError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // OpenSSH's `ssh_err` texts for the errors it maps these to.
        match self {
            SkError::General => f.write_str("invalid format"),
            SkError::Unsupported => f.write_str("requested feature not supported"),
            SkError::PinRequired => {
                f.write_str("incorrect passphrase supplied to decrypt private key")
            }
            SkError::DeviceNotFound => f.write_str("device not found"),
            SkError::CredentialExists => f.write_str("bad permissions"),
            SkError::Provider(m) => f.write_str(m),
        }
    }
}

impl From<SkError> for Error {
    fn from(e: SkError) -> Self {
        Error::SecurityKey(e)
    }
}

/// An `sk_option`: a named, provider-specific setting (`device`, `user`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SkOption {
    /// The option's name.
    pub name: String,
    /// Its value.
    pub value: String,
    /// Whether the provider must refuse to proceed if it doesn't know it.
    pub required: bool,
}

/// What an authenticator returns from enrolment.
#[derive(Clone, Default)]
#[non_exhaustive]
pub struct EnrollResponse {
    /// The flags the credential was made with.
    pub flags: u8,
    /// The public key: an uncompressed P-256 point or 32 Ed25519 bytes.
    pub public_key: Vec<u8>,
    /// The credential's key handle.
    pub key_handle: Vec<u8>,
    /// The attestation signature.
    pub signature: Vec<u8>,
    /// The attestation certificate.
    pub attestation_cert: Vec<u8>,
    /// The authenticator data the attestation signs.
    pub authdata: Vec<u8>,
}

/// What an authenticator returns from signing.
#[derive(Clone, Default)]
#[non_exhaustive]
pub struct SignResponse {
    /// The flags the authenticator signed with (user presence, …).
    pub flags: u8,
    /// Its signature counter.
    pub counter: u32,
    /// ECDSA `r`, or the whole Ed25519 signature.
    pub sig_r: Vec<u8>,
    /// ECDSA `s` (empty for Ed25519).
    pub sig_s: Vec<u8>,
}

/// A resident (discoverable) credential found on an authenticator.
#[derive(Clone)]
#[non_exhaustive]
pub struct ResidentKey {
    /// Its algorithm.
    pub algorithm: Algorithm,
    /// The authenticator's slot number.
    pub slot: usize,
    /// The FIDO application, `ssh:…` for SSH keys.
    pub application: String,
    /// The public key and key handle.
    pub key: EnrollResponse,
    /// Its flags.
    pub flags: u8,
    /// The user ID it was enrolled with.
    pub user_id: Vec<u8>,
}

/// A security-key provider (OpenSSH's middleware API).
pub trait Provider: Send + Sync {
    /// Make a credential for `application`, attesting `challenge`.
    #[allow(clippy::too_many_arguments)]
    fn enroll(
        &self,
        alg: Algorithm,
        challenge: &[u8],
        application: &str,
        flags: u8,
        pin: Option<&str>,
        options: &[SkOption],
    ) -> core::result::Result<EnrollResponse, SkError>;

    /// Sign `data` (the provider hashes it) with the credential `key_handle`.
    #[allow(clippy::too_many_arguments)]
    fn sign(
        &self,
        alg: Algorithm,
        data: &[u8],
        application: &str,
        key_handle: &[u8],
        flags: u8,
        pin: Option<&str>,
        options: &[SkOption],
    ) -> core::result::Result<SignResponse, SkError>;

    /// List the authenticator's resident credentials.
    fn load_resident_keys(
        &self,
        pin: Option<&str>,
        options: &[SkOption],
    ) -> core::result::Result<Vec<ResidentKey>, SkError>;
}

/// Open the provider named by `SecurityKeyProvider`: `internal` (libfido2)
/// or the path to a middleware library.
pub fn open_provider(path: &str) -> core::result::Result<Arc<dyn Provider>, SkError> {
    if path.is_empty() {
        return Err(SkError::Provider(
            "No FIDO SecurityKeyProvider specified".into(),
        ));
    }
    if path.eq_ignore_ascii_case("internal") {
        #[cfg(not(windows))]
        return Ok(Arc::new(fido2::Fido2Provider::open()?));
        #[cfg(windows)]
        return Err(SkError::Provider(
            "internal security key support not enabled".into(),
        ));
    }
    Ok(Arc::new(ExternalProvider::open(path)?))
}

/// A provider opened on first use, so that a security key can be offered
/// (by its public half) before anything is loaded, and a provider that
/// fails to load fails the signature, as with OpenSSH.
pub fn lazy_provider(path: &str) -> Arc<dyn Provider> {
    Arc::new(LazyProvider {
        path: path.into(),
        inner: std::sync::OnceLock::new(),
    })
}

struct LazyProvider {
    path: String,
    inner: std::sync::OnceLock<core::result::Result<Arc<dyn Provider>, SkError>>,
}

impl LazyProvider {
    fn get(&self) -> core::result::Result<&Arc<dyn Provider>, SkError> {
        self.inner
            .get_or_init(|| open_provider(&self.path))
            .as_ref()
            .map_err(Clone::clone)
    }
}

impl Provider for LazyProvider {
    fn enroll(
        &self,
        alg: Algorithm,
        challenge: &[u8],
        application: &str,
        flags: u8,
        pin: Option<&str>,
        options: &[SkOption],
    ) -> core::result::Result<EnrollResponse, SkError> {
        self.get()?
            .enroll(alg, challenge, application, flags, pin, options)
    }

    fn sign(
        &self,
        alg: Algorithm,
        data: &[u8],
        application: &str,
        key_handle: &[u8],
        flags: u8,
        pin: Option<&str>,
        options: &[SkOption],
    ) -> core::result::Result<SignResponse, SkError> {
        self.get()?
            .sign(alg, data, application, key_handle, flags, pin, options)
    }

    fn load_resident_keys(
        &self,
        pin: Option<&str>,
        options: &[SkOption],
    ) -> core::result::Result<Vec<ResidentKey>, SkError> {
        self.get()?.load_resident_keys(pin, options)
    }
}

/// The provider to use: `configured` (`SecurityKeyProvider`), else
/// `$SSH_SK_PROVIDER`, else `internal`, as OpenSSH resolves it.
pub fn provider_path(configured: Option<&str>) -> String {
    configured
        .map(String::from)
        .or_else(|| {
            std::env::var("SSH_SK_PROVIDER")
                .ok()
                .filter(|p| !p.is_empty())
        })
        .unwrap_or_else(|| "internal".into())
}

/// The `device` / `user` options OpenSSH passes to a provider.
pub fn options(device: Option<&str>, user: Option<&str>) -> Vec<SkOption> {
    let mut out = Vec::new();
    for (name, value) in [("device", device), ("user", user)] {
        if let Some(v) = value {
            out.push(SkOption {
                name: name.into(),
                value: v.into(),
                required: false,
            });
        }
    }
    out
}

/// The SSH private key for an enrolment response, as `ssh-keygen` writes it.
fn key_from_response(
    alg: Algorithm,
    application: &str,
    flags: u8,
    resp: &EnrollResponse,
) -> Result<PrivateKey> {
    if resp.public_key.is_empty() || resp.key_handle.is_empty() {
        return Err(Error::Format("sk_enroll response invalid"));
    }
    let sk = SkCredential::new(application.into(), flags, resp.key_handle.clone());
    let mut blob = Writer::new();
    match alg {
        Algorithm::EcdsaP256 => {
            blob.write_string(SK_ECDSA.as_bytes());
            blob.write_string(b"nistp256");
            blob.write_string(&resp.public_key);
        }
        Algorithm::Ed25519 => {
            blob.write_string(SK_ED25519.as_bytes());
            blob.write_string(&resp.public_key);
        }
    }
    blob.write_string(application.as_bytes());
    // Validates the point / length, as OpenSSH's assembly does.
    let public = crate::key::PublicKey::parse_wire_blob(blob.as_slice())
        .map_err(|_| Error::Format("Authenticator returned invalid key"))?;
    PrivateKey::from_security_key(public, sk)
}

/// The result of [`enroll`].
pub struct Enrollment {
    /// The new key (comment empty).
    pub key: PrivateKey,
    /// The `ssh-sk-attest-v01` attestation blob (`ssh-keygen -O
    /// write-attestation=`).
    pub attestation: Vec<u8>,
}

/// Enrol a new key: `ssh-keygen -t ecdsa-sk|ed25519-sk`. `challenge`
/// defaults to 32 random bytes.
#[allow(clippy::too_many_arguments)]
pub fn enroll(
    provider: &dyn Provider,
    alg: Algorithm,
    application: &str,
    flags: u8,
    pin: Option<&str>,
    challenge: Option<&[u8]>,
    options: &[SkOption],
) -> Result<Enrollment> {
    if application.is_empty() {
        return Err(Error::Config("missing application"));
    }
    let mut random = Zeroizing::new([0u8; 32]);
    let challenge = match challenge {
        Some([]) => return Err(Error::Config("Missing enrollment challenge")),
        Some(c) => c,
        None => {
            use purecrypto::rng::RngCore;
            purecrypto::rng::OsRng.fill_bytes(&mut random[..]);
            &random[..]
        }
    };
    let resp = provider.enroll(alg, challenge, application, flags, pin, options)?;
    let key = key_from_response(alg, application, resp.flags, &resp)?;
    let mut w = Writer::new();
    w.write_string(b"ssh-sk-attest-v01");
    w.write_string(&resp.attestation_cert);
    w.write_string(&resp.signature);
    w.write_string(&resp.authdata);
    w.write_u32(0);
    w.write_string(&[]);
    Ok(Enrollment {
        key,
        attestation: w.into_vec(),
    })
}

/// The SSH signature blob for `key` over `data`, made by the authenticator.
pub fn sign(
    provider: &dyn Provider,
    key: &PrivateKey,
    data: &[u8],
    pin: Option<&str>,
) -> Result<Vec<u8>> {
    let (alg, sk) = match key {
        PrivateKey::SkEcdsaP256 { sk, .. } => (Algorithm::EcdsaP256, sk),
        PrivateKey::SkEd25519 { sk, .. } => (Algorithm::Ed25519, sk),
        _ => return Err(Error::Config("not a security key")),
    };
    if sk.application.is_empty() || sk.key_handle.is_empty() {
        return Err(Error::Config(
            "security key: missing application or key handle",
        ));
    }
    let resp = provider.sign(
        alg,
        data,
        &sk.application,
        &sk.key_handle,
        sk.flags,
        pin,
        &[],
    )?;
    let mut w = Writer::new();
    w.write_string(alg.name().as_bytes());
    match alg {
        Algorithm::EcdsaP256 => {
            if resp.sig_r.is_empty() || resp.sig_s.is_empty() {
                return Err(Error::Format("sk_sign response invalid"));
            }
            let mut inner = Writer::new();
            write_mpint(&mut inner, &resp.sig_r);
            write_mpint(&mut inner, &resp.sig_s);
            w.write_string(inner.as_slice());
        }
        Algorithm::Ed25519 => {
            if resp.sig_r.len() != 64 {
                return Err(Error::Format("sk_sign response invalid"));
            }
            w.write_string(&resp.sig_r);
        }
    }
    w.write_u8(resp.flags);
    w.write_u32(resp.counter);
    Ok(w.into_vec())
}

/// A resident key downloaded with [`load_resident_keys`].
pub struct LoadedResidentKey {
    /// The key, flagged resident (and user-verification-required if the
    /// credential is).
    pub key: PrivateKey,
    /// The user ID it was enrolled with.
    pub user_id: Vec<u8>,
}

/// The resident SSH keys (application `ssh:…`) on the authenticator:
/// `ssh-keygen -K`, `ssh-add -K`.
pub fn load_resident_keys(
    provider: &dyn Provider,
    pin: Option<&str>,
    options: &[SkOption],
) -> Result<Vec<LoadedResidentKey>> {
    let mut out = Vec::new();
    for rk in provider.load_resident_keys(pin, options)? {
        if !rk.application.starts_with("ssh:") {
            continue;
        }
        let mut flags = USER_PRESENCE_REQD | RESIDENT_KEY;
        flags |= rk.flags & USER_VERIFICATION_REQD;
        out.push(LoadedResidentKey {
            key: key_from_response(rk.algorithm, &rk.application, flags, &rk.key)?,
            user_id: rk.user_id,
        });
    }
    Ok(out)
}

/// How a [`SkSigner`] asks for what signing needs.
pub trait Prompt: Send + Sync {
    /// Ask the user to touch the authenticator (`Confirm user presence for
    /// key …`), before a signature that needs it.
    fn touch(&self, key: &PrivateKey);
    /// Ask for the authenticator's PIN, when it needs one.
    fn pin(&self, key: &PrivateKey) -> Option<Zeroizing<String>>;
    /// The signature is made (or failed): close what [`Self::touch`]
    /// opened, if anything.
    fn done(&self) {}
}

/// A [`HostKey`](crate::hostkey::HostKey) whose signatures the
/// authenticator makes: a security key for user authentication.
pub struct SkSigner {
    key: PrivateKey,
    provider: Arc<dyn Provider>,
    prompt: Option<Arc<dyn Prompt>>,
}

impl SkSigner {
    /// A signer for the security key `key` through `provider`, asking the
    /// user through `prompt` (none ⇒ never asks, and fails if a PIN is
    /// needed).
    pub fn new(
        key: PrivateKey,
        provider: Arc<dyn Provider>,
        prompt: Option<Arc<dyn Prompt>>,
    ) -> Result<Self> {
        if key.sk_credential().is_none() {
            return Err(Error::Config("not a security key"));
        }
        Ok(Self {
            key,
            provider,
            prompt,
        })
    }
}

impl crate::hostkey::HostKey for SkSigner {
    fn algorithm(&self) -> &'static str {
        self.key.algorithm()
    }

    fn public_blob(&self) -> Vec<u8> {
        self.key.public_key().wire_blob()
    }

    fn sign(&self, msg: &[u8]) -> Result<Vec<u8>> {
        let flags = self.key.sk_credential().map_or(0, |c| c.flags);
        // OpenSSH asks for the PIN up front when the key needs user
        // verification, and otherwise only if the authenticator wants one.
        let mut pin = if flags & USER_VERIFICATION_REQD != 0 {
            self.prompt.as_ref().and_then(|p| p.pin(&self.key))
        } else {
            None
        };
        loop {
            if flags & USER_PRESENCE_REQD != 0
                && let Some(p) = &self.prompt
            {
                p.touch(&self.key);
            }
            let res = sign(
                &*self.provider,
                &self.key,
                msg,
                pin.as_deref().map(|s| s.as_str()),
            );
            if let Some(p) = &self.prompt {
                p.done();
            }
            match res {
                Err(Error::SecurityKey(SkError::PinRequired)) if pin.is_none() => {
                    pin = self.prompt.as_ref().and_then(|p| p.pin(&self.key));
                    if pin.is_none() {
                        return Err(SkError::PinRequired.into());
                    }
                }
                other => return other,
            }
        }
    }
}

impl Drop for SkSigner {
    fn drop(&mut self) {
        self.key.wipe();
    }
}

/// A `NULL`-terminated `struct sk_option **` and the storage behind it,
/// alive for one provider call.
struct COptions {
    _strings: Vec<CString>,
    _structs: Vec<external::RawOption>,
    ptrs: Vec<*mut external::RawOption>,
}

impl COptions {
    fn new(options: &[SkOption]) -> core::result::Result<Self, SkError> {
        let mut strings = Vec::new();
        let mut structs = Vec::new();
        for o in options {
            let name = CString::new(o.name.as_str()).map_err(|_| SkError::General)?;
            let value = CString::new(o.value.as_str()).map_err(|_| SkError::General)?;
            structs.push(external::RawOption {
                name: name.as_ptr().cast_mut(),
                value: value.as_ptr().cast_mut(),
                required: u8::from(o.required),
            });
            strings.push(name);
            strings.push(value);
        }
        // `structs` is complete: its elements no longer move.
        let mut ptrs: Vec<*mut external::RawOption> =
            structs.iter_mut().map(|b| &raw mut *b).collect();
        ptrs.push(core::ptr::null_mut());
        Ok(Self {
            _strings: strings,
            _structs: structs,
            ptrs,
        })
    }

    fn as_ptr(&mut self) -> *mut *mut external::RawOption {
        if self.ptrs.len() == 1 {
            // OpenSSH passes NULL for no options.
            core::ptr::null_mut()
        } else {
            self.ptrs.as_mut_ptr()
        }
    }
}

/// A PIN as a C string, wiped on drop.
struct CPin(Option<CString>);

impl CPin {
    fn new(pin: Option<&str>) -> core::result::Result<Self, SkError> {
        Ok(CPin(match pin {
            Some(p) => Some(CString::new(p).map_err(|_| SkError::General)?),
            None => None,
        }))
    }

    fn as_ptr(&self) -> *const c_char {
        self.0.as_ref().map_or(core::ptr::null(), |c| c.as_ptr())
    }
}

impl Drop for CPin {
    fn drop(&mut self) {
        if let Some(c) = self.0.take() {
            c.into_bytes_with_nul().zeroize();
        }
    }
}

fn c_application(application: &str) -> core::result::Result<CString, SkError> {
    CString::new(application).map_err(|_| SkError::General)
}

/// The bytes of a provider-allocated buffer (`NULL` ⇒ empty).
///
/// # Safety
///
/// `ptr` is null or points to `len` readable bytes.
unsafe fn copy_bytes(ptr: *const u8, len: usize) -> Vec<u8> {
    if ptr.is_null() || len == 0 {
        return Vec::new();
    }
    // SAFETY: forwarded to the caller.
    unsafe { core::slice::from_raw_parts(ptr, len) }.to_vec()
}

/// A provider-allocated C string (`NULL` ⇒ empty).
///
/// # Safety
///
/// `ptr` is null or a NUL-terminated string.
unsafe fn copy_cstr(ptr: *const c_char) -> String {
    if ptr.is_null() {
        return String::new();
    }
    // SAFETY: forwarded to the caller.
    unsafe { CStr::from_ptr(ptr) }
        .to_string_lossy()
        .into_owned()
}

/// Wipe and `free` a provider-allocated buffer.
///
/// # Safety
///
/// `ptr` is null or a `malloc`ed buffer of at least `len` bytes, freed once.
unsafe fn free_bytes(ptr: *mut u8, len: usize) {
    if ptr.is_null() {
        return;
    }
    // SAFETY: forwarded to the caller.
    unsafe { core::slice::from_raw_parts_mut(ptr, len) }.zeroize();
    // SAFETY: forwarded to the caller.
    unsafe { libc::free(ptr.cast()) };
}

#[cfg(test)]
mod tests;
