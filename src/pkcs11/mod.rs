//! PKCS#11 tokens (smart cards, HSMs): keys whose private half stays on
//! the token, as OpenSSH's `PKCS11Provider`, `ssh -I`, `ssh-keygen -D` and
//! `ssh-add -s` use them (`ssh-pkcs11.c`).
//!
//! A module (`.so`) is loaded at run time with `dlsym` and initialised;
//! each initialised token gets a session, and its public keys (and the keys
//! of its X.509 certificates) become [`Pkcs11Key`]s: RSA, ECDSA on the NIST
//! curves and Ed25519. Signing finds the private key with the same
//! `CKA_ID`, logging in first when the token requires it (with the PIN
//! given at load, else asked for through a [`PinPrompt`]).

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use std::ffi::{c_uchar, c_ulong, c_void};
use std::sync::Mutex;

use purecrypto::hash::{Digest, Sha1, Sha256, Sha384, Sha512};
use purecrypto::zeroize::Zeroizing;

use crate::error::{Error, Result};
use crate::format::{Writer, write_mpint};
use crate::key::PublicKey;

mod x509;

type CkUlong = c_ulong;
type CkRv = CkUlong;

const CKR_OK: CkRv = 0;
const CKR_PIN_INCORRECT: CkRv = 0xa0;
const CKR_PIN_LEN_RANGE: CkRv = 0xa2;
const CKR_PIN_LOCKED: CkRv = 0xa4;
const CKR_USER_ALREADY_LOGGED_IN: CkRv = 0x100;

const CKF_LOGIN_REQUIRED: CkUlong = 1 << 2;
const CKF_PROTECTED_AUTHENTICATION_PATH: CkUlong = 1 << 8;
const CKF_TOKEN_INITIALIZED: CkUlong = 1 << 10;
const CKF_RW_SESSION: CkUlong = 1 << 1;
const CKF_SERIAL_SESSION: CkUlong = 1 << 2;

const CKU_USER: CkUlong = 1;
const CKU_CONTEXT_SPECIFIC: CkUlong = 2;

const CKA_CLASS: CkUlong = 0;
const CKA_LABEL: CkUlong = 3;
const CKA_VALUE: CkUlong = 0x11;
const CKA_CERTIFICATE_TYPE: CkUlong = 0x80;
const CKA_KEY_TYPE: CkUlong = 0x100;
const CKA_SUBJECT: CkUlong = 0x101;
const CKA_ID: CkUlong = 0x102;
const CKA_SIGN: CkUlong = 0x108;
const CKA_MODULUS: CkUlong = 0x120;
const CKA_PUBLIC_EXPONENT: CkUlong = 0x122;
const CKA_EC_PARAMS: CkUlong = 0x180;
const CKA_EC_POINT: CkUlong = 0x181;
const CKA_ALWAYS_AUTHENTICATE: CkUlong = 0x202;

const CKO_CERTIFICATE: CkUlong = 1;
const CKO_PUBLIC_KEY: CkUlong = 2;
const CKO_PRIVATE_KEY: CkUlong = 3;

const CKK_RSA: CkUlong = 0;
const CKK_EC: CkUlong = 3;
const CKK_EC_EDWARDS: CkUlong = 0x40;

const CKC_X_509: CkUlong = 0;

const CKM_RSA_PKCS: CkUlong = 1;
const CKM_ECDSA: CkUlong = 0x1041;
const CKM_EDDSA: CkUlong = 0x1057;

/// `CK_UNAVAILABLE_INFORMATION`: an attribute the token won't reveal.
const UNAVAILABLE: CkUlong = !0;

// Cryptoki packs its structures to one byte on Windows.
#[cfg_attr(not(windows), repr(C))]
#[cfg_attr(windows, repr(C, packed))]
#[derive(Clone, Copy, Default)]
struct CkVersion {
    major: u8,
    minor: u8,
}

#[cfg_attr(not(windows), repr(C))]
#[cfg_attr(windows, repr(C, packed))]
struct CkInfo {
    cryptoki_version: CkVersion,
    manufacturer_id: [u8; 32],
    flags: CkUlong,
    library_description: [u8; 32],
    library_version: CkVersion,
}

#[cfg_attr(not(windows), repr(C))]
#[cfg_attr(windows, repr(C, packed))]
struct CkTokenInfo {
    label: [u8; 32],
    manufacturer_id: [u8; 32],
    model: [u8; 16],
    serial_number: [u8; 16],
    flags: CkUlong,
    max_session_count: CkUlong,
    session_count: CkUlong,
    max_rw_session_count: CkUlong,
    rw_session_count: CkUlong,
    max_pin_len: CkUlong,
    min_pin_len: CkUlong,
    total_public_memory: CkUlong,
    free_public_memory: CkUlong,
    total_private_memory: CkUlong,
    free_private_memory: CkUlong,
    hardware_version: CkVersion,
    firmware_version: CkVersion,
    utc_time: [u8; 16],
}

#[cfg_attr(not(windows), repr(C))]
#[cfg_attr(windows, repr(C, packed))]
struct CkAttribute {
    kind: CkUlong,
    value: *mut c_void,
    len: CkUlong,
}

#[cfg_attr(not(windows), repr(C))]
#[cfg_attr(windows, repr(C, packed))]
struct CkMechanism {
    mechanism: CkUlong,
    parameter: *mut c_void,
    parameter_len: CkUlong,
}

/// A function this binding never calls (its slot in the table).
type Unused = Option<unsafe extern "C" fn()>;

/// `CK_FUNCTION_LIST` (Cryptoki 2.x, 68 entries): only the functions used
/// are typed.
#[cfg_attr(not(windows), repr(C))]
#[cfg_attr(windows, repr(C, packed))]
struct FunctionList {
    version: CkVersion,
    initialize: Option<unsafe extern "C" fn(*mut c_void) -> CkRv>,
    finalize: Option<unsafe extern "C" fn(*mut c_void) -> CkRv>,
    get_info: Option<unsafe extern "C" fn(*mut CkInfo) -> CkRv>,
    _get_function_list: Unused,
    get_slot_list: Option<unsafe extern "C" fn(c_uchar, *mut CkUlong, *mut CkUlong) -> CkRv>,
    _get_slot_info: Unused,
    get_token_info: Option<unsafe extern "C" fn(CkUlong, *mut CkTokenInfo) -> CkRv>,
    // GetMechanismList, GetMechanismInfo, InitToken, InitPIN, SetPIN.
    _unused_7_11: [Unused; 5],
    open_session:
        Option<unsafe extern "C" fn(CkUlong, CkUlong, *mut c_void, Unused, *mut CkUlong) -> CkRv>,
    close_session: Option<unsafe extern "C" fn(CkUlong) -> CkRv>,
    // CloseAllSessions, GetSessionInfo, GetOperationState,
    // SetOperationState.
    _unused_14_17: [Unused; 4],
    login: Option<unsafe extern "C" fn(CkUlong, CkUlong, *const u8, CkUlong) -> CkRv>,
    // Logout, CreateObject, CopyObject, DestroyObject, GetObjectSize.
    _unused_19_23: [Unused; 5],
    get_attribute_value:
        Option<unsafe extern "C" fn(CkUlong, CkUlong, *mut CkAttribute, CkUlong) -> CkRv>,
    _set_attribute_value: Unused,
    find_objects_init: Option<unsafe extern "C" fn(CkUlong, *mut CkAttribute, CkUlong) -> CkRv>,
    find_objects:
        Option<unsafe extern "C" fn(CkUlong, *mut CkUlong, CkUlong, *mut CkUlong) -> CkRv>,
    find_objects_final: Option<unsafe extern "C" fn(CkUlong) -> CkRv>,
    // EncryptInit … DigestFinal.
    _unused_29_41: [Unused; 13],
    sign_init: Option<unsafe extern "C" fn(CkUlong, *mut CkMechanism, CkUlong) -> CkRv>,
    sign: Option<unsafe extern "C" fn(CkUlong, *const u8, CkUlong, *mut u8, *mut CkUlong) -> CkRv>,
    // SignUpdate … WaitForSlotEvent.
    _unused_44_67: [Unused; 24],
}

type GetFunctionList = unsafe extern "C" fn(*mut *const FunctionList) -> CkRv;

/// A PKCS#11 failure.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Pkcs11Error {
    /// The module could not be loaded or initialised.
    Provider(String),
    /// The module has no slot with a token.
    NoSlots,
    /// The token needs a PIN and none can be asked for.
    PinRequired,
    /// The PIN was refused.
    PinIncorrect,
    /// The PIN is locked.
    PinLocked,
    /// Login failed otherwise.
    LoginFailed,
    /// The private key for a public key is not on the token.
    KeyNotFound,
    /// A Cryptoki call failed: the function, and its `CK_RV`.
    Call(&'static str, c_ulong),
}

impl core::fmt::Display for Pkcs11Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Pkcs11Error::Provider(m) => f.write_str(m),
            Pkcs11Error::NoSlots => f.write_str("provider returned no slots"),
            Pkcs11Error::PinRequired => f.write_str("pin required"),
            Pkcs11Error::PinIncorrect => f.write_str("PKCS#11 login failed: PIN incorrect"),
            Pkcs11Error::PinLocked => f.write_str("PKCS#11 login failed: PIN locked"),
            Pkcs11Error::LoginFailed => f.write_str("login failed"),
            Pkcs11Error::KeyNotFound => f.write_str("cannot find private key"),
            Pkcs11Error::Call(name, rv) => write!(f, "{name} failed: {rv}"),
        }
    }
}

impl From<Pkcs11Error> for Error {
    fn from(e: Pkcs11Error) -> Self {
        Error::Pkcs11(e)
    }
}

fn call(name: &'static str, rv: CkRv) -> core::result::Result<(), Pkcs11Error> {
    if rv == CKR_OK {
        Ok(())
    } else {
        Err(Pkcs11Error::Call(name, rv))
    }
}

/// Asks for a token's PIN when signing needs a login (`ssh`, interactive).
pub trait PinPrompt: Send + Sync {
    /// The PIN for the token labelled `label` (OpenSSH: `Enter PIN for
    /// '<label>': `), or `None` to give up.
    fn pin(&self, label: &str) -> Option<Zeroizing<String>>;
}

struct Slot {
    id: CkUlong,
    label: String,
    flags: CkUlong,
    session: CkUlong,
    logged_in: bool,
}

/// A loaded, initialised module and its sessions.
struct Module {
    f: *const FunctionList,
    /// `C_Initialize` succeeded: `C_Finalize` on drop.
    initialized: bool,
    slots: Mutex<Vec<Slot>>,
    prompt: Option<Arc<dyn PinPrompt>>,
    // Unloaded after `C_Finalize`, when the last key goes.
    _lib: dlsym::Library,
}

// SAFETY: every call into the module goes through `slots`' lock, so the
// (non-thread-safe, `C_Initialize(NULL)`) module is used by one thread at a
// time; the function table is immutable.
unsafe impl Send for Module {}
// SAFETY: as above.
unsafe impl Sync for Module {}

impl Module {
    fn f(&self) -> &FunctionList {
        // SAFETY: the table the module returned, valid until `C_Finalize`
        // in `Drop`.
        unsafe { &*self.f }
    }
}

impl Drop for Module {
    fn drop(&mut self) {
        if !self.initialized {
            return;
        }
        if let Some(finalize) = self.f().finalize {
            // SAFETY: the module is initialised and no other reference
            // to it remains.
            unsafe { finalize(core::ptr::null_mut()) };
        }
    }
}

/// Unwrap a function pointer the table must provide.
fn func<T>(f: Option<T>, name: &'static str) -> core::result::Result<T, Pkcs11Error> {
    f.ok_or_else(|| Pkcs11Error::Provider(alloc::format!("module lacks {name}")))
}

/// A token's space-padded fixed-width string, trailing spaces removed.
fn padded(s: &[u8]) -> String {
    String::from_utf8_lossy(s)
        .trim_end_matches([' ', '\0'])
        .into()
}

/// A key on a token.
pub struct Pkcs11Key {
    public: PublicKey,
    key_id: Vec<u8>,
    slot: usize,
    module: Arc<Module>,
}

impl core::fmt::Debug for Pkcs11Key {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Pkcs11Key")
            .field("public", &self.public)
            .field("slot", &self.slot)
            .finish_non_exhaustive()
    }
}

impl Pkcs11Key {
    /// The public key; its comment is the object's label (a certificate's
    /// subject, for a key from a certificate).
    pub fn public_key(&self) -> &PublicKey {
        &self.public
    }

    /// Sign `data` with the signature algorithm `alg` (`rsa-sha2-256`,
    /// `rsa-sha2-512` or `ssh-rsa` for an RSA key; the key's own name
    /// otherwise), returning the SSH signature blob.
    pub fn sign_with(&self, alg: &str, data: &[u8]) -> Result<Vec<u8>> {
        let mut w = Writer::new();
        match &self.public {
            PublicKey::Rsa { n, .. } => {
                let (name, prefix, digest): (&str, &[u8], Vec<u8>) = match alg {
                    "rsa-sha2-512" => (
                        "rsa-sha2-512",
                        DIGEST_INFO_SHA512,
                        Sha512::digest(data).as_ref().to_vec(),
                    ),
                    "rsa-sha2-256" => (
                        "rsa-sha2-256",
                        DIGEST_INFO_SHA256,
                        Sha256::digest(data).as_ref().to_vec(),
                    ),
                    "ssh-rsa" => (
                        "ssh-rsa",
                        DIGEST_INFO_SHA1,
                        Sha1::digest(data).as_ref().to_vec(),
                    ),
                    _ => return Err(Error::Unsupported("pkcs11: RSA signature algorithm")),
                };
                let mut input = Zeroizing::new(prefix.to_vec());
                input.extend_from_slice(&digest);
                let size = n.iter().skip_while(|&&b| b == 0).count();
                let mut sig = self.sign_raw(CKM_RSA_PKCS, &input, size)?;
                if sig.len() > size {
                    return Err(Error::Format("pkcs11: bad C_Sign length"));
                }
                // Left-pad a short signature to the modulus size.
                let mut padded_sig = alloc::vec![0u8; size - sig.len()];
                padded_sig.append(&mut sig);
                w.write_string(name.as_bytes());
                w.write_string(&padded_sig);
            }
            PublicKey::EcdsaP256 { .. }
            | PublicKey::EcdsaP384 { .. }
            | PublicKey::EcdsaP521 { .. } => {
                let digest = match &self.public {
                    PublicKey::EcdsaP256 { .. } => Sha256::digest(data).as_ref().to_vec(),
                    PublicKey::EcdsaP384 { .. } => Sha384::digest(data).as_ref().to_vec(),
                    _ => Sha512::digest(data).as_ref().to_vec(),
                };
                let sig = self.sign_raw(CKM_ECDSA, &digest, 132)?;
                if !(64..=132).contains(&sig.len()) || sig.len() % 2 != 0 {
                    return Err(Error::Format("pkcs11: bad ECDSA signature length"));
                }
                let (r, s) = sig.split_at(sig.len() / 2);
                let mut inner = Writer::new();
                write_mpint(&mut inner, trim_zeros(r));
                write_mpint(&mut inner, trim_zeros(s));
                w.write_string(self.public.algorithm().as_bytes());
                w.write_string(inner.as_slice());
            }
            PublicKey::Ed25519 { .. } => {
                let sig = self.sign_raw(CKM_EDDSA, data, 64)?;
                if sig.len() != 64 {
                    return Err(Error::Format("pkcs11: bad Ed25519 signature length"));
                }
                w.write_string(b"ssh-ed25519");
                w.write_string(&sig);
            }
            _ => return Err(Error::Unsupported("pkcs11: key type")),
        }
        Ok(w.into_vec())
    }

    /// `C_Sign` with `mechanism` over `input`, after finding the private
    /// key (logging in as needed), as OpenSSH's `pkcs11_get_key`.
    fn sign_raw(&self, mechanism: CkUlong, input: &[u8], max: usize) -> Result<Vec<u8>> {
        let m = &*self.module;
        let mut slots = m
            .slots
            .lock()
            .map_err(|_| Error::Config("pkcs11: lock poisoned"))?;
        let slot = &mut slots[self.slot];
        let mut did_login = false;
        if slot.flags & CKF_LOGIN_REQUIRED != 0 && !slot.logged_in {
            login(m, slot, CKU_USER, None)?;
            did_login = true;
        }
        let obj = self.find_private_key(slot.session)?;
        let mut mech = CkMechanism {
            mechanism,
            parameter: core::ptr::null_mut(),
            parameter_len: 0,
        };
        let sign_init = func(m.f().sign_init, "C_SignInit")?;
        // SAFETY: a live session and object; `mech` outlives the call.
        call("C_SignInit", unsafe {
            sign_init(slot.session, &mut mech, obj)
        })?;
        if !did_login && bool_attribute(m, slot.session, obj, CKA_ALWAYS_AUTHENTICATE) {
            login(m, slot, CKU_CONTEXT_SPECIFIC, None)?;
        }
        let sign = func(m.f().sign, "C_Sign")?;
        let mut out = alloc::vec![0u8; max];
        let mut len = max as CkUlong;
        // SAFETY: `input` and `out` are valid for their lengths.
        call("C_Sign", unsafe {
            sign(
                slot.session,
                input.as_ptr(),
                input.len() as CkUlong,
                out.as_mut_ptr(),
                &mut len,
            )
        })?;
        out.truncate(len as usize);
        Ok(out)
    }

    /// The private key object with our `CKA_ID`: with `CKA_SIGN` first,
    /// then without.
    fn find_private_key(&self, session: CkUlong) -> Result<CkUlong> {
        let m = &*self.module;
        let mut class: CkUlong = CKO_PRIVATE_KEY;
        let mut yes: c_uchar = 1;
        let mut id = self.key_id.clone();
        let mut filter = [
            attr(CKA_CLASS, &mut class),
            CkAttribute {
                kind: CKA_ID,
                value: id.as_mut_ptr().cast(),
                len: id.len() as CkUlong,
            },
            attr(CKA_SIGN, &mut yes),
        ];
        for n in [3, 2] {
            if let Some(obj) = find_one(m, session, &mut filter[..n])? {
                return Ok(obj);
            }
        }
        Err(Pkcs11Error::KeyNotFound.into())
    }
}

impl crate::hostkey::HostKey for Pkcs11Key {
    fn algorithm(&self) -> &'static str {
        match self.public {
            // As for an RSA key held in memory: SHA-512 unless the server
            // asks otherwise.
            PublicKey::Rsa { .. } => "rsa-sha2-512",
            _ => self.public.algorithm(),
        }
    }

    fn public_blob(&self) -> Vec<u8> {
        self.public.wire_blob()
    }

    fn sign(&self, msg: &[u8]) -> Result<Vec<u8>> {
        self.sign_with(crate::hostkey::HostKey::algorithm(self), msg)
    }
}

/// An RSA token key under one signature algorithm (the server's
/// `server-sig-algs`, or an agent request's flags).
pub struct Pkcs11RsaSigner {
    key: Arc<Pkcs11Key>,
    alg: &'static str,
}

impl Pkcs11RsaSigner {
    /// `key` signing with `alg` (`rsa-sha2-512`, `rsa-sha2-256`, `ssh-rsa`).
    pub fn new(key: Arc<Pkcs11Key>, alg: &'static str) -> Self {
        Self { key, alg }
    }
}

impl crate::hostkey::HostKey for Pkcs11RsaSigner {
    fn algorithm(&self) -> &'static str {
        self.alg
    }

    fn public_blob(&self) -> Vec<u8> {
        self.key.public.wire_blob()
    }

    fn sign(&self, msg: &[u8]) -> Result<Vec<u8>> {
        self.key.sign_with(self.alg, msg)
    }
}

const DIGEST_INFO_SHA1: &[u8] = &[
    0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14,
];
const DIGEST_INFO_SHA256: &[u8] = &[
    0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
    0x00, 0x04, 0x20,
];
const DIGEST_INFO_SHA512: &[u8] = &[
    0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05,
    0x00, 0x04, 0x40,
];

fn trim_zeros(b: &[u8]) -> &[u8] {
    let i = b.iter().position(|&x| x != 0).unwrap_or(b.len());
    &b[i..]
}

/// An attribute pointing at `v`.
fn attr<T>(kind: CkUlong, v: &mut T) -> CkAttribute {
    CkAttribute {
        kind,
        value: (v as *mut T).cast(),
        len: size_of::<T>() as CkUlong,
    }
}

/// The first object matching `filter`, as OpenSSH's `pkcs11_find`.
fn find_one(
    m: &Module,
    session: CkUlong,
    filter: &mut [CkAttribute],
) -> core::result::Result<Option<CkUlong>, Pkcs11Error> {
    let init = func(m.f().find_objects_init, "C_FindObjectsInit")?;
    let find = func(m.f().find_objects, "C_FindObjects")?;
    let fin = func(m.f().find_objects_final, "C_FindObjectsFinal")?;
    // SAFETY: the attributes point at live values.
    call("C_FindObjectsInit", unsafe {
        init(session, filter.as_mut_ptr(), filter.len() as CkUlong)
    })?;
    let mut obj: CkUlong = 0;
    let mut n: CkUlong = 0;
    // SAFETY: room for one handle.
    let rv = unsafe { find(session, &mut obj, 1, &mut n) };
    // SAFETY: ends the search begun above.
    unsafe { fin(session) };
    Ok((rv == CKR_OK && n == 1).then_some(obj))
}

/// Every object matching `filter`.
fn find_all(
    m: &Module,
    session: CkUlong,
    filter: &mut [CkAttribute],
) -> core::result::Result<Vec<CkUlong>, Pkcs11Error> {
    let init = func(m.f().find_objects_init, "C_FindObjectsInit")?;
    let find = func(m.f().find_objects, "C_FindObjects")?;
    let fin = func(m.f().find_objects_final, "C_FindObjectsFinal")?;
    // SAFETY: the attributes point at live values.
    call("C_FindObjectsInit", unsafe {
        init(session, filter.as_mut_ptr(), filter.len() as CkUlong)
    })?;
    let mut out = Vec::new();
    let res = loop {
        let mut obj: CkUlong = 0;
        let mut n: CkUlong = 0;
        // SAFETY: room for one handle.
        let rv = unsafe { find(session, &mut obj, 1, &mut n) };
        if rv != CKR_OK {
            break Err(Pkcs11Error::Call("C_FindObjects", rv));
        }
        if n == 0 || out.len() >= MAX_OBJECTS {
            break Ok(());
        }
        out.push(obj);
    };
    // SAFETY: ends the search begun above.
    unsafe { fin(session) };
    res.map(|()| out)
}

/// Most objects listed per token.
const MAX_OBJECTS: usize = 1024;
/// Largest attribute value read.
const MAX_ATTRIBUTE: usize = 64 * 1024;

/// The values of `kinds` on `obj` (two passes: lengths, then values).
/// `None` for one the token won't reveal.
fn attributes(
    m: &Module,
    session: CkUlong,
    obj: CkUlong,
    kinds: &[CkUlong],
) -> core::result::Result<Vec<Option<Vec<u8>>>, Pkcs11Error> {
    let get = func(m.f().get_attribute_value, "C_GetAttributeValue")?;
    let mut attrs: Vec<CkAttribute> = kinds
        .iter()
        .map(|&kind| CkAttribute {
            kind,
            value: core::ptr::null_mut(),
            len: 0,
        })
        .collect();
    // SAFETY: null values ask for the lengths only.
    call("C_GetAttributeValue", unsafe {
        get(session, obj, attrs.as_mut_ptr(), attrs.len() as CkUlong)
    })?;
    let mut bufs: Vec<Option<Vec<u8>>> = attrs
        .iter()
        .map(|a| {
            let len = a.len;
            (len != UNAVAILABLE && (len as usize) <= MAX_ATTRIBUTE)
                .then(|| alloc::vec![0u8; len as usize])
        })
        .collect();
    for (a, b) in attrs.iter_mut().zip(bufs.iter_mut()) {
        match b {
            Some(b) if !b.is_empty() => {
                a.value = b.as_mut_ptr().cast();
                a.len = b.len() as CkUlong;
            }
            _ => {
                a.value = core::ptr::null_mut();
                a.len = 0;
            }
        }
    }
    // SAFETY: each value points at a buffer of its length.
    call("C_GetAttributeValue", unsafe {
        get(session, obj, attrs.as_mut_ptr(), attrs.len() as CkUlong)
    })?;
    for (a, b) in attrs.iter().zip(bufs.iter_mut()) {
        let len = a.len;
        if let Some(buf) = b {
            if len == UNAVAILABLE || len as usize > buf.len() {
                *b = None;
            } else {
                buf.truncate(len as usize);
            }
        }
    }
    Ok(bufs)
}

/// A scalar attribute of `obj` (`CK_ULONG`).
fn ulong_attribute(m: &Module, session: CkUlong, obj: CkUlong, kind: CkUlong) -> Option<CkUlong> {
    let get = m.f().get_attribute_value?;
    let mut v: CkUlong = 0;
    let mut a = attr(kind, &mut v);
    // SAFETY: `a` points at `v`.
    (unsafe { get(session, obj, &mut a, 1) } == CKR_OK).then_some(v)
}

/// A boolean attribute of `obj`, false when unreadable.
fn bool_attribute(m: &Module, session: CkUlong, obj: CkUlong, kind: CkUlong) -> bool {
    let Some(get) = m.f().get_attribute_value else {
        return false;
    };
    let mut v: c_uchar = 0;
    let mut a = attr(kind, &mut v);
    // SAFETY: `a` points at `v`.
    unsafe { get(session, obj, &mut a, 1) == CKR_OK && v != 0 }
}

/// Log in to `slot` (`C_Login`), with `pin` or asking the prompt, as
/// OpenSSH's `pkcs11_login_slot`.
fn login(
    m: &Module,
    slot: &mut Slot,
    user: CkUlong,
    pin: Option<&str>,
) -> core::result::Result<(), Pkcs11Error> {
    let login = func(m.f().login, "C_Login")?;
    let asked;
    let pin: Option<&str> = if slot.flags & CKF_PROTECTED_AUTHENTICATION_PATH != 0 {
        // The reader's keypad.
        None
    } else if let Some(p) = pin {
        Some(p)
    } else {
        let prompt = m.prompt.as_ref().ok_or(Pkcs11Error::PinRequired)?;
        asked = prompt.pin(&slot.label).ok_or(Pkcs11Error::PinRequired)?;
        Some(asked.as_str())
    };
    let (ptr, len) = pin.map_or((core::ptr::null(), 0), |p| (p.as_ptr(), p.len()));
    // SAFETY: `ptr` is null or `len` readable bytes.
    match unsafe { login(slot.session, user, ptr, len as CkUlong) } {
        CKR_OK | CKR_USER_ALREADY_LOGGED_IN => {
            slot.logged_in = true;
            Ok(())
        }
        CKR_PIN_INCORRECT => Err(Pkcs11Error::PinIncorrect),
        CKR_PIN_LOCKED => Err(Pkcs11Error::PinLocked),
        CKR_PIN_LEN_RANGE => Err(Pkcs11Error::Provider(
            "PKCS#11 login failed: PIN length out of range".into(),
        )),
        rv => Err(Pkcs11Error::Provider(alloc::format!(
            "PKCS#11 login failed: error {rv}"
        ))),
    }
}

/// The curve name of DER `CKA_EC_PARAMS` (a named-curve OID).
fn ec_curve(params: &[u8]) -> Option<(&'static str, &'static str)> {
    const P256: &[u8] = &[0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
    const P384: &[u8] = &[0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22];
    const P521: &[u8] = &[0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x23];
    match params {
        P256 => Some(("ecdsa-sha2-nistp256", "nistp256")),
        P384 => Some(("ecdsa-sha2-nistp384", "nistp384")),
        P521 => Some(("ecdsa-sha2-nistp521", "nistp521")),
        _ => None,
    }
}

/// `CKA_EC_POINT`: a DER OCTET STRING holding the point (some tokens give
/// the bare point).
fn ec_point(v: &[u8]) -> &[u8] {
    let mut r = purecrypto::der::Reader::new(v);
    match r.read_octet_string() {
        Ok(p) if r.is_empty() => p,
        _ => v,
    }
}

/// The SSH public key of a `CKO_PUBLIC_KEY` object, and its `CKA_ID`.
fn public_key_object(
    m: &Module,
    session: CkUlong,
    obj: CkUlong,
) -> core::result::Result<Option<(PublicKey, Vec<u8>)>, Pkcs11Error> {
    let Some(key_type) = ulong_attribute(m, session, obj, CKA_KEY_TYPE) else {
        return Ok(None);
    };
    let mut w = Writer::new();
    let id = match key_type {
        CKK_RSA => {
            let v = attributes(m, session, obj, &[CKA_ID, CKA_MODULUS, CKA_PUBLIC_EXPONENT])?;
            let (Some(n), Some(e)) = (&v[1], &v[2]) else {
                return Ok(None);
            };
            if n.is_empty() || e.is_empty() {
                return Ok(None);
            }
            w.write_string(b"ssh-rsa");
            write_mpint(&mut w, e);
            write_mpint(&mut w, n);
            v[0].clone()
        }
        CKK_EC => {
            let v = attributes(m, session, obj, &[CKA_ID, CKA_EC_POINT, CKA_EC_PARAMS])?;
            let (Some(point), Some(params)) = (&v[1], &v[2]) else {
                return Ok(None);
            };
            let Some((name, curve)) = ec_curve(params) else {
                return Ok(None);
            };
            w.write_string(name.as_bytes());
            w.write_string(curve.as_bytes());
            w.write_string(ec_point(point));
            v[0].clone()
        }
        CKK_EC_EDWARDS => {
            let v = attributes(m, session, obj, &[CKA_ID, CKA_EC_POINT, CKA_EC_PARAMS])?;
            let (Some(point), Some(params)) = (&v[1], &v[2]) else {
                return Ok(None);
            };
            // PrintableString "edwards25519" or OID 1.3.101.112.
            const ID1: &[u8] = b"\x13\x0cedwards25519";
            const ID2: &[u8] = &[0x06, 0x03, 0x2b, 0x65, 0x70];
            if params != ID1 && params != ID2 {
                return Ok(None);
            }
            let raw = ec_point(point);
            if raw.len() != 32 {
                return Ok(None);
            }
            w.write_string(b"ssh-ed25519");
            w.write_string(raw);
            v[0].clone()
        }
        _ => return Ok(None),
    };
    Ok(PublicKey::parse_wire_blob(w.as_slice())
        .ok()
        .map(|k| (k, id.unwrap_or_default())))
}

/// Load `path` (`PKCS11Provider`, `ssh -I`, `ssh-add -s`) and list its
/// tokens' keys, as OpenSSH's `pkcs11_add_provider`. `pin` logs in up
/// front (the agent's way); otherwise login waits for the first signature
/// and asks `prompt` (`ssh`'s way), which also lets a token that shows no
/// key before login be logged in to at once.
pub fn load(
    path: &str,
    pin: Option<&str>,
    prompt: Option<Arc<dyn PinPrompt>>,
) -> Result<Vec<Arc<Pkcs11Key>>> {
    let module = open(path, prompt)?;
    let m = &*module;
    let nslots = m.slots.lock().map(|s| s.len()).unwrap_or(0);
    let mut keys: Vec<Arc<Pkcs11Key>> = Vec::new();
    for idx in 0..nslots {
        let mut slots = m
            .slots
            .lock()
            .map_err(|_| Error::Config("pkcs11: lock poisoned"))?;
        let slot = &mut slots[idx];
        let pin = pin.filter(|p| !p.is_empty());
        if slot.flags & CKF_LOGIN_REQUIRED != 0 && pin.is_none() && m.prompt.is_none() {
            // OpenSSH fails early without a way to log in.
            return Err(Pkcs11Error::PinRequired.into());
        }
        let open_session = func(m.f().open_session, "C_OpenSession")?;
        let mut session: CkUlong = 0;
        // SAFETY: a slot of this module; no callback.
        call("C_OpenSession", unsafe {
            open_session(
                slot.id,
                CKF_RW_SESSION | CKF_SERIAL_SESSION,
                core::ptr::null_mut(),
                None,
                &mut session,
            )
        })?;
        slot.session = session;
        if slot.flags & CKF_LOGIN_REQUIRED != 0
            && let Some(p) = pin
            && let Err(e) = login(m, slot, CKU_USER, Some(p))
        {
            if let Some(close) = m.f().close_session {
                // SAFETY: the session just opened.
                unsafe { close(session) };
            }
            return Err(match e {
                Pkcs11Error::PinLocked => e,
                _ => Pkcs11Error::LoginFailed,
            }
            .into());
        }
        let mut found = slot_keys(m, session)?;
        if found.is_empty() && !slot.logged_in && m.prompt.is_some() {
            // Some tokens show their keys only after login.
            login(m, slot, CKU_USER, None)?;
            found = slot_keys(m, session)?;
        }
        drop(slots);
        for (public, key_id) in found {
            // A key in more than one slot is listed once, as OpenSSH's.
            if keys
                .iter()
                .any(|k| k.public.wire_blob() == public.wire_blob())
            {
                continue;
            }
            keys.push(Arc::new(Pkcs11Key {
                public,
                key_id,
                slot: idx,
                module: module.clone(),
            }));
        }
    }
    Ok(keys)
}

/// The keys of one token: its public key objects, then its X.509
/// certificates' keys, each once, with its label (a certificate's
/// subject) as the comment.
fn slot_keys(
    m: &Module,
    session: CkUlong,
) -> core::result::Result<Vec<(PublicKey, Vec<u8>)>, Pkcs11Error> {
    let mut out: Vec<(PublicKey, Vec<u8>)> = Vec::new();
    let mut push = |mut k: PublicKey, id: Vec<u8>, label: String| {
        // The 2048-bit RSA floor applies to token keys too.
        if let PublicKey::Rsa { n, .. } = &k
            && crate::hostkey::rsa::check_rsa_modulus_mpint(n).is_err()
        {
            return;
        }
        if out.iter().any(|(o, _)| o.wire_blob() == k.wire_blob()) {
            return;
        }
        k.set_comment(label);
        out.push((k, id));
    };
    let mut class: CkUlong = CKO_PUBLIC_KEY;
    for obj in find_all(m, session, &mut [attr(CKA_CLASS, &mut class)])? {
        if let Some((k, id)) = public_key_object(m, session, obj)? {
            let label = attributes(m, session, obj, &[CKA_LABEL])?
                .remove(0)
                .map(|l| String::from_utf8_lossy(&l).into_owned())
                .unwrap_or_default();
            push(k, id, label);
        }
    }
    let mut class: CkUlong = CKO_CERTIFICATE;
    for obj in find_all(m, session, &mut [attr(CKA_CLASS, &mut class)])? {
        if ulong_attribute(m, session, obj, CKA_CERTIFICATE_TYPE) != Some(CKC_X_509) {
            continue;
        }
        let v = attributes(m, session, obj, &[CKA_ID, CKA_SUBJECT, CKA_VALUE])?;
        let (Some(subject), Some(der)) = (&v[1], &v[2]) else {
            continue;
        };
        let Some(spki) = x509::subject_public_key_info(der) else {
            continue;
        };
        let Ok(k) = PublicKey::from_spki_der(spki) else {
            continue;
        };
        let label = x509::name_oneline(subject).unwrap_or_else(|| "invalid subject".into());
        push(k, v[0].clone().unwrap_or_default(), label);
    }
    Ok(out)
}

/// `dlopen` the module, `C_GetFunctionList`, `C_Initialize`, and list the
/// slots with an initialised token.
fn open(path: &str, prompt: Option<Arc<dyn PinPrompt>>) -> Result<Arc<Module>> {
    // SAFETY: loading a module runs its initialisers; naming it is trusting
    // it, as with OpenSSH.
    let lib = unsafe { dlsym::Library::open(path) }
        .map_err(|e| Pkcs11Error::Provider(alloc::format!("dlopen {path} failed: {e}")))?;
    // SAFETY: `C_GetFunctionList` has this signature (PKCS#11 2.x).
    let get_list = unsafe { lib.get::<GetFunctionList>(c"C_GetFunctionList") }.map_err(|_| {
        Pkcs11Error::Provider(alloc::format!("provider {path} is not a PKCS11 library"))
    })?;
    let mut f: *const FunctionList = core::ptr::null();
    // SAFETY: `f` receives the module's static table.
    let rv = unsafe { get_list.call((&mut f,)) };
    if rv != CKR_OK || f.is_null() {
        return Err(Pkcs11Error::Provider(alloc::format!(
            "C_GetFunctionList for provider {path} failed: {rv}"
        ))
        .into());
    }
    // Finalized on drop from here on.
    let mut module = Module {
        f,
        initialized: false,
        slots: Mutex::new(Vec::new()),
        prompt,
        _lib: lib,
    };
    let initialize = func(module.f().initialize, "C_Initialize")?;
    // SAFETY: no arguments: the module's default locking.
    let rv = unsafe { initialize(core::ptr::null_mut()) };
    if rv != CKR_OK {
        return Err(Pkcs11Error::Provider(alloc::format!(
            "C_Initialize for provider {path} failed: {rv}"
        ))
        .into());
    }
    module.initialized = true;
    let get_slot_list = func(module.f().get_slot_list, "C_GetSlotList")?;
    let get_token_info = func(module.f().get_token_info, "C_GetTokenInfo")?;
    let mut n: CkUlong = 0;
    // SAFETY: a null list asks for the count of slots with a token.
    call("C_GetSlotList", unsafe {
        get_slot_list(1, core::ptr::null_mut(), &mut n)
    })?;
    if n == 0 {
        return Err(Pkcs11Error::NoSlots.into());
    }
    let mut ids = alloc::vec![0 as CkUlong; n as usize];
    // SAFETY: room for `n` slot IDs.
    call("C_GetSlotList", unsafe {
        get_slot_list(1, ids.as_mut_ptr(), &mut n)
    })?;
    ids.truncate(n as usize);
    let mut slots = Vec::new();
    for id in ids {
        // SAFETY: zeroed is a valid `CK_TOKEN_INFO`, filled by the call.
        let mut info: CkTokenInfo = unsafe { core::mem::zeroed() };
        // SAFETY: `info` is a `CK_TOKEN_INFO`.
        if unsafe { get_token_info(id, &mut info) } != CKR_OK {
            continue;
        }
        let flags = info.flags;
        if flags & CKF_TOKEN_INITIALIZED == 0 {
            continue;
        }
        slots.push(Slot {
            id,
            label: padded(&info.label),
            flags,
            session: 0,
            logged_in: false,
        });
    }
    module.slots = Mutex::new(slots);
    Ok(Arc::new(module))
}

#[cfg(test)]
mod tests;
