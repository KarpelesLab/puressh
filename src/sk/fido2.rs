//! `internal`: USB / NFC authenticators through libfido2, a port of
//! OpenSSH's `sk-usbhid.c`.
//!
//! libfido2 is loaded at run time, so there is no link-time dependency.
//! The functions only some of its versions export are `#[optional]`, with
//! the fallbacks OpenSSH compiles in when its configure checks miss them.

use alloc::vec::Vec;
use std::ffi::{CStr, CString, c_char, c_int};
use std::time::{Duration, Instant};

use dlsym::Bindings;
use purecrypto::ec::{BoxedEcdsaPublicKey, CurveId};
use purecrypto::hash::{Digest, Sha256};
use purecrypto::zeroize::Zeroizing;

use super::{
    Algorithm, CPin, EnrollResponse, FORCE_OPERATION, Provider, RESIDENT_KEY, ResidentKey,
    SignResponse, SkError, SkOption, USER_PRESENCE_REQD, USER_VERIFICATION_REQD, c_application,
    copy_bytes, copy_cstr,
};

/// Where libfido2 is looked for.
#[cfg(target_vendor = "apple")]
const LIBRARY_NAMES: &[&str] = &[
    "libfido2.1.dylib",
    "libfido2.dylib",
    "/opt/homebrew/lib/libfido2.1.dylib",
    "/opt/homebrew/lib/libfido2.dylib",
    "/usr/local/lib/libfido2.1.dylib",
    "/usr/local/lib/libfido2.dylib",
];
#[cfg(not(target_vendor = "apple"))]
const LIBRARY_NAMES: &[&str] = &["libfido2.so.1", "libfido2.so"];

// `fido/err.h`.
const FIDO_OK: c_int = 0x00;
const FIDO_ERR_INVALID_COMMAND: c_int = 0x01;
const FIDO_ERR_UNSUPPORTED_ALGORITHM: c_int = 0x26;
const FIDO_ERR_OPERATION_DENIED: c_int = 0x27;
const FIDO_ERR_UNSUPPORTED_OPTION: c_int = 0x2b;
const FIDO_ERR_NO_CREDENTIALS: c_int = 0x2e;
const FIDO_ERR_PIN_INVALID: c_int = 0x31;
const FIDO_ERR_PIN_REQUIRED: c_int = 0x36;
const FIDO_ERR_USER_PRESENCE_REQUIRED: c_int = -8;
const FIDO_ERR_INTERNAL: c_int = -9;

// `fido_opt_t` (`fido/types.h`).
const FIDO_OPT_OMIT: c_int = 0;
const FIDO_OPT_FALSE: c_int = 1;
const FIDO_OPT_TRUE: c_int = 2;

// `fido/param.h`.
const COSE_ES256: c_int = -7;
const COSE_EDDSA: c_int = -8;
const FIDO_CRED_PROT_UV_OPTIONAL_WITH_ID: c_int = 0x02;
const FIDO_CRED_PROT_UV_REQUIRED: c_int = 0x03;

/// `fido_init` flags: no `FIDO_DEBUG`.
const SSH_FIDO_INIT_ARG: c_int = 0;
const MAX_FIDO_DEVICES: usize = 8;
const FIDO_POLL_MS: c_int = 50;
const SELECT_MS: u128 = 15000;
const POLL_SLEEP: Duration = Duration::from_millis(200);

macro_rules! opaque {
    ($($(#[$m:meta])* $name:ident;)*) => {$(
        $(#[$m])*
        #[repr(C)]
        struct $name {
            _opaque: [u8; 0],
        }
    )*};
}

opaque! {
    /// `fido_dev_t`.
    FidoDev;
    /// `fido_dev_info_t`.
    FidoDevInfo;
    /// `fido_assert_t`.
    FidoAssert;
    /// `fido_cred_t`.
    FidoCred;
    /// `fido_cbor_info_t`.
    FidoCborInfo;
    /// `fido_credman_metadata_t`.
    FidoCredmanMetadata;
    /// `fido_credman_rp_t`.
    FidoCredmanRp;
    /// `fido_credman_rk_t`.
    FidoCredmanRk;
}

dlsym::library! {
    /// The part of libfido2 (`fido.h`, `fido/credman.h`) `sk-usbhid.c` uses.
    struct Fido2 {
        unsafe extern "C" {
            fn fido_init(flags: c_int);

            fn fido_dev_new() -> *mut FidoDev;
            fn fido_dev_open(dev: *mut FidoDev, path: *const c_char) -> c_int;
            fn fido_dev_cancel(dev: *mut FidoDev) -> c_int;
            fn fido_dev_close(dev: *mut FidoDev) -> c_int;
            fn fido_dev_free(dev: *mut *mut FidoDev);
            fn fido_dev_is_fido2(dev: *const FidoDev) -> bool;
            #[optional]
            fn fido_dev_is_winhello(dev: *const FidoDev) -> bool;
            #[optional]
            fn fido_dev_supports_cred_prot(dev: *const FidoDev) -> bool;
            #[optional]
            fn fido_dev_get_touch_begin(dev: *mut FidoDev) -> c_int;
            #[optional]
            fn fido_dev_get_touch_status(dev: *mut FidoDev, touched: *mut c_int, ms: c_int)
                -> c_int;
            fn fido_dev_get_cbor_info(dev: *mut FidoDev, info: *mut FidoCborInfo) -> c_int;
            fn fido_dev_get_assert(
                dev: *mut FidoDev,
                assert: *mut FidoAssert,
                pin: *const c_char,
            ) -> c_int;
            fn fido_dev_make_cred(dev: *mut FidoDev, cred: *mut FidoCred, pin: *const c_char)
                -> c_int;

            fn fido_dev_info_new(n: usize) -> *mut FidoDevInfo;
            fn fido_dev_info_free(devlist: *mut *mut FidoDevInfo, n: usize);
            fn fido_dev_info_manifest(devlist: *mut FidoDevInfo, ilen: usize, olen: *mut usize)
                -> c_int;
            fn fido_dev_info_ptr(devlist: *const FidoDevInfo, i: usize) -> *const FidoDevInfo;
            fn fido_dev_info_path(di: *const FidoDevInfo) -> *const c_char;

            fn fido_cbor_info_new() -> *mut FidoCborInfo;
            fn fido_cbor_info_free(info: *mut *mut FidoCborInfo);
            fn fido_cbor_info_options_name_ptr(info: *const FidoCborInfo) -> *mut *mut c_char;
            fn fido_cbor_info_options_value_ptr(info: *const FidoCborInfo) -> *const bool;
            fn fido_cbor_info_options_len(info: *const FidoCborInfo) -> usize;

            fn fido_assert_new() -> *mut FidoAssert;
            fn fido_assert_free(assert: *mut *mut FidoAssert);
            #[optional]
            fn fido_assert_set_clientdata(assert: *mut FidoAssert, ptr: *const u8, len: usize)
                -> c_int;
            fn fido_assert_set_clientdata_hash(
                assert: *mut FidoAssert,
                ptr: *const u8,
                len: usize,
            ) -> c_int;
            fn fido_assert_set_rp(assert: *mut FidoAssert, id: *const c_char) -> c_int;
            fn fido_assert_allow_cred(assert: *mut FidoAssert, ptr: *const u8, len: usize)
                -> c_int;
            fn fido_assert_set_up(assert: *mut FidoAssert, up: c_int) -> c_int;
            fn fido_assert_set_uv(assert: *mut FidoAssert, uv: c_int) -> c_int;
            fn fido_assert_count(assert: *const FidoAssert) -> usize;
            fn fido_assert_user_id_ptr(assert: *const FidoAssert, idx: usize) -> *const u8;
            fn fido_assert_user_id_len(assert: *const FidoAssert, idx: usize) -> usize;
            fn fido_assert_flags(assert: *const FidoAssert, idx: usize) -> u8;
            fn fido_assert_sigcount(assert: *const FidoAssert, idx: usize) -> u32;
            fn fido_assert_sig_ptr(assert: *const FidoAssert, idx: usize) -> *const u8;
            fn fido_assert_sig_len(assert: *const FidoAssert, idx: usize) -> usize;

            fn fido_cred_new() -> *mut FidoCred;
            fn fido_cred_free(cred: *mut *mut FidoCred);
            fn fido_cred_set_type(cred: *mut FidoCred, cose_alg: c_int) -> c_int;
            #[optional]
            fn fido_cred_set_clientdata(cred: *mut FidoCred, ptr: *const u8, len: usize) -> c_int;
            fn fido_cred_set_clientdata_hash(cred: *mut FidoCred, ptr: *const u8, len: usize)
                -> c_int;
            fn fido_cred_set_rk(cred: *mut FidoCred, rk: c_int) -> c_int;
            fn fido_cred_set_user(
                cred: *mut FidoCred,
                user_id: *const u8,
                user_id_len: usize,
                name: *const c_char,
                display_name: *const c_char,
                icon: *const c_char,
            ) -> c_int;
            fn fido_cred_set_rp(cred: *mut FidoCred, id: *const c_char, name: *const c_char)
                -> c_int;
            #[optional]
            fn fido_cred_set_prot(cred: *mut FidoCred, prot: c_int) -> c_int;
            fn fido_cred_verify(cred: *const FidoCred) -> c_int;
            fn fido_cred_verify_self(cred: *const FidoCred) -> c_int;
            fn fido_cred_fmt(cred: *const FidoCred) -> *const c_char;
            fn fido_cred_x5c_ptr(cred: *const FidoCred) -> *const u8;
            fn fido_cred_x5c_len(cred: *const FidoCred) -> usize;
            fn fido_cred_pubkey_ptr(cred: *const FidoCred) -> *const u8;
            fn fido_cred_pubkey_len(cred: *const FidoCred) -> usize;
            fn fido_cred_id_ptr(cred: *const FidoCred) -> *const u8;
            fn fido_cred_id_len(cred: *const FidoCred) -> usize;
            fn fido_cred_sig_ptr(cred: *const FidoCred) -> *const u8;
            fn fido_cred_sig_len(cred: *const FidoCred) -> usize;
            fn fido_cred_authdata_ptr(cred: *const FidoCred) -> *const u8;
            fn fido_cred_authdata_len(cred: *const FidoCred) -> usize;
            fn fido_cred_user_id_ptr(cred: *const FidoCred) -> *const u8;
            fn fido_cred_user_id_len(cred: *const FidoCred) -> usize;
            fn fido_cred_type(cred: *const FidoCred) -> c_int;
            #[optional]
            fn fido_cred_prot(cred: *const FidoCred) -> c_int;

            fn fido_credman_metadata_new() -> *mut FidoCredmanMetadata;
            fn fido_credman_metadata_free(metadata: *mut *mut FidoCredmanMetadata);
            fn fido_credman_get_dev_metadata(
                dev: *mut FidoDev,
                metadata: *mut FidoCredmanMetadata,
                pin: *const c_char,
            ) -> c_int;
            fn fido_credman_rp_new() -> *mut FidoCredmanRp;
            fn fido_credman_rp_free(rp: *mut *mut FidoCredmanRp);
            fn fido_credman_get_dev_rp(
                dev: *mut FidoDev,
                rp: *mut FidoCredmanRp,
                pin: *const c_char,
            ) -> c_int;
            fn fido_credman_rp_count(rp: *const FidoCredmanRp) -> usize;
            fn fido_credman_rp_id(rp: *const FidoCredmanRp, idx: usize) -> *const c_char;
            fn fido_credman_rk_new() -> *mut FidoCredmanRk;
            fn fido_credman_rk_free(rk: *mut *mut FidoCredmanRk);
            fn fido_credman_get_dev_rk(
                dev: *mut FidoDev,
                rp_id: *const c_char,
                rk: *mut FidoCredmanRk,
                pin: *const c_char,
            ) -> c_int;
            fn fido_credman_rk_count(rk: *const FidoCredmanRk) -> usize;
            fn fido_credman_rk(rk: *const FidoCredmanRk, idx: usize) -> *const FidoCred;
        }
    }
}

/// A libfido2 object, freed with its `fido_*_free` on drop.
macro_rules! owned {
    ($($(#[$m:meta])* $name:ident($raw:ty, $new:ident, $free:ident);)*) => {$(
        $(#[$m])*
        struct $name<'a> {
            lib: &'a Fido2,
            ptr: *mut $raw,
        }

        impl<'a> $name<'a> {
            fn new(lib: &'a Fido2) -> Option<Self> {
                // SAFETY: the constructor takes no arguments.
                let ptr = unsafe { lib.$new() };
                (!ptr.is_null()).then_some(Self { lib, ptr })
            }
        }

        impl Drop for $name<'_> {
            fn drop(&mut self) {
                // SAFETY: `ptr` came from the matching constructor and is
                // freed once, here.
                unsafe { self.lib.$free(&mut self.ptr) };
            }
        }
    )*};
}

owned! {
    /// `fido_assert_t`.
    Assert(FidoAssert, fido_assert_new, fido_assert_free);
    /// `fido_cred_t`.
    Cred(FidoCred, fido_cred_new, fido_cred_free);
    /// `fido_cbor_info_t`.
    CborInfo(FidoCborInfo, fido_cbor_info_new, fido_cbor_info_free);
    /// `fido_credman_metadata_t`.
    Metadata(FidoCredmanMetadata, fido_credman_metadata_new, fido_credman_metadata_free);
    /// `fido_credman_rp_t`.
    CredmanRp(FidoCredmanRp, fido_credman_rp_new, fido_credman_rp_free);
    /// `fido_credman_rk_t`.
    CredmanRk(FidoCredmanRk, fido_credman_rk_new, fido_credman_rk_free);
}

/// A device list of [`MAX_FIDO_DEVICES`] entries.
struct DevInfo<'a> {
    lib: &'a Fido2,
    ptr: *mut FidoDevInfo,
}

impl Drop for DevInfo<'_> {
    fn drop(&mut self) {
        // SAFETY: allocated by `fido_dev_info_new(MAX_FIDO_DEVICES)`, freed
        // once.
        unsafe { self.lib.fido_dev_info_free(&mut self.ptr, MAX_FIDO_DEVICES) };
    }
}

/// An open device (`struct sk_usbhid`); `sk_close` on drop.
struct Dev<'a> {
    lib: &'a Fido2,
    ptr: *mut FidoDev,
}

impl Drop for Dev<'_> {
    fn drop(&mut self) {
        // SAFETY: an opened device: cancel any pending operation, close it
        // and free it, once.
        unsafe {
            self.lib.fido_dev_cancel(self.ptr);
            self.lib.fido_dev_close(self.ptr);
            self.lib.fido_dev_free(&mut self.ptr);
        }
    }
}

/// `fidoerr_to_skerr`.
fn fidoerr_to_skerr(fidoerr: c_int) -> SkError {
    match fidoerr {
        FIDO_ERR_UNSUPPORTED_OPTION | FIDO_ERR_UNSUPPORTED_ALGORITHM => SkError::Unsupported,
        FIDO_ERR_PIN_REQUIRED | FIDO_ERR_PIN_INVALID | FIDO_ERR_OPERATION_DENIED => {
            SkError::PinRequired
        }
        _ => SkError::General,
    }
}

/// A libfido2 status as a `Result`, for `?`.
fn ok(r: c_int) -> Result<(), c_int> {
    if r == FIDO_OK { Ok(()) } else { Err(r) }
}

/// A libfido2 status, any failure being [`SkError::General`].
fn general(r: c_int) -> Result<(), SkError> {
    ok(r).map_err(|_| SkError::General)
}

/// The `device` option as a C string.
fn device_option(value: &str) -> Result<CString, SkError> {
    CString::new(value).map_err(|_| SkError::General)
}

/// `check_enroll_options`: the `device` and `user` options (`user` is
/// copied, NUL-terminated, into `user_id`, as `strlcpy` does).
fn check_enroll_options(
    options: &[SkOption],
    user_id: &mut [u8; 32],
) -> Result<Option<CString>, SkError> {
    let mut device = None;
    for o in options {
        match o.name.as_str() {
            "device" => device = Some(device_option(&o.value)?),
            "user" => {
                let v = o.value.as_bytes();
                if v.contains(&0) || v.len() >= user_id.len() {
                    // "user too long"
                    return Err(SkError::General);
                }
                user_id[..v.len()].copy_from_slice(v);
                user_id[v.len()] = 0;
            }
            _ if o.required => return Err(SkError::General),
            _ => {}
        }
    }
    Ok(device)
}

/// `check_sign_load_resident_options`: the `device` option.
fn check_sign_load_resident_options(options: &[SkOption]) -> Result<Option<CString>, SkError> {
    let mut device = None;
    for o in options {
        match o.name.as_str() {
            "device" => device = Some(device_option(&o.value)?),
            _ if o.required => return Err(SkError::General),
            _ => {}
        }
    }
    Ok(device)
}

/// `pack_public_key`: the SSH public key from the credential's (`None` if
/// libfido2 returned none): the SEC1 uncompressed point for ECDSA (libfido2
/// gives the affine `x || y`, checked to be on the curve), the 32 raw bytes
/// for Ed25519.
fn pack_public_key(alg: Algorithm, pubkey: Option<&[u8]>) -> Option<Vec<u8>> {
    let pubkey = pubkey?;
    match alg {
        Algorithm::EcdsaP256 => {
            if pubkey.len() != 64 {
                return None;
            }
            let mut sec1 = Vec::with_capacity(65);
            sec1.push(0x04);
            sec1.extend_from_slice(pubkey);
            let point = BoxedEcdsaPublicKey::from_sec1(CurveId::P256, &sec1).ok()?;
            Some(point.to_sec1())
        }
        Algorithm::Ed25519 => (pubkey.len() == 32).then(|| pubkey.to_vec()),
    }
}

/// A DER length at the start of `der`: (length, header bytes used).
fn der_length(der: &[u8]) -> Option<(usize, usize)> {
    match *der.first()? {
        n @ 0..=0x7f => Some((n.into(), 1)),
        0x81 => {
            let n = *der.get(1)?;
            (n >= 0x80).then_some((n.into(), 2))
        }
        0x82 => {
            let n = usize::from(*der.get(1)?) << 8 | usize::from(*der.get(2)?);
            (n >= 0x100).then_some((n, 3))
        }
        _ => None,
    }
}

/// A DER TLV with `tag` at the start of `der`: (contents, rest).
fn der_tlv(der: &[u8], tag: u8) -> Option<(&[u8], &[u8])> {
    if *der.first()? != tag {
        return None;
    }
    let (len, hdr) = der_length(&der[1..])?;
    let body = der.get(1 + hdr..1 + hdr + len)?;
    Some((body, &der[1 + hdr + len..]))
}

/// A non-negative, minimally encoded DER INTEGER at the start of `der`, as
/// big-endian bytes without leading zeros (`BN_bn2bin`): (value, rest).
fn der_uint(der: &[u8]) -> Option<(Vec<u8>, &[u8])> {
    let (body, rest) = der_tlv(der, 0x02)?;
    let (&first, tail) = body.split_first()?;
    if first & 0x80 != 0 {
        return None;
    }
    if first == 0 && tail.first().is_some_and(|b| b & 0x80 == 0) {
        return None;
    }
    let start = body.iter().position(|&b| b != 0).unwrap_or(body.len());
    Some((body[start..].to_vec(), rest))
}

/// `pack_sig_ecdsa`: `r` and `s` of a DER `ECDSA-Sig-Value`
/// (`d2i_ECDSA_SIG`, which ignores bytes after the SEQUENCE).
fn ecdsa_sig_from_der(der: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
    let (seq, _) = der_tlv(der, 0x30)?;
    let (r, seq) = der_uint(seq)?;
    let (s, seq) = der_uint(seq)?;
    seq.is_empty().then_some((r, s))
}

/// `pack_sig`.
fn pack_sig(alg: Algorithm, sig: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
    match alg {
        Algorithm::EcdsaP256 => ecdsa_sig_from_der(sig),
        Algorithm::Ed25519 => (sig.len() == 64).then(|| (sig.to_vec(), Vec::new())),
    }
}

/// libfido2, loaded.
pub(super) struct Fido2Provider {
    lib: Fido2,
    /// Whether it exports `fido_dev_get_touch_status` (libfido2 ≥ 1.5,
    /// needed to choose among several devices).
    has_touch_status: bool,
}

impl core::fmt::Debug for Fido2Provider {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Fido2Provider").finish_non_exhaustive()
    }
}

impl Fido2Provider {
    /// Load the system's libfido2.
    pub(super) fn open() -> Result<Fido2Provider, SkError> {
        Self::open_first(LIBRARY_NAMES)
    }

    fn open_first(names: &[&str]) -> Result<Fido2Provider, SkError> {
        // SAFETY: loading libfido2 runs its initialisers (and its
        // dependencies'); `internal` trusts the system's libfido2, as
        // OpenSSH linking it does.
        let lib = unsafe { Fido2::open_first(names) }.map_err(|e| {
            SkError::Provider(alloc::format!(
                "internal security key support unavailable: cannot load libfido2: {e}"
            ))
        })?;
        // SAFETY: only looked up, never called through this type.
        let has_touch_status = unsafe {
            lib.library()
                .get::<unsafe extern "C" fn(*mut FidoDev, *mut c_int, c_int) -> c_int>(
                    c"fido_dev_get_touch_status",
                )
        }
        .is_ok();
        Ok(Self {
            lib,
            has_touch_status,
        })
    }

    fn init(&self) {
        // SAFETY: `fido_init` takes flags and may be called repeatedly.
        unsafe { self.lib.fido_init(SSH_FIDO_INIT_ARG) };
    }

    /// `sk_open`.
    fn sk_open(&self, path: &CStr) -> Option<Dev<'_>> {
        let lib = &self.lib;
        // SAFETY: no arguments.
        let mut ptr = unsafe { lib.fido_dev_new() };
        if ptr.is_null() {
            return None;
        }
        // SAFETY: a new device and a C string.
        if unsafe { lib.fido_dev_open(ptr, path.as_ptr()) } != FIDO_OK {
            // SAFETY: never opened: freed once, here.
            unsafe { lib.fido_dev_free(&mut ptr) };
            return None;
        }
        Some(Dev { lib, ptr })
    }

    /// `sk_openv`: every device of `devlist` that opens.
    fn sk_openv(&self, devlist: &DevInfo<'_>, ndevs: usize) -> Vec<Dev<'_>> {
        let mut out = Vec::new();
        for i in 0..ndevs {
            // SAFETY: `i < ndevs`, the count the manifest filled in.
            let di = unsafe { self.lib.fido_dev_info_ptr(devlist.ptr, i) };
            if di.is_null() {
                continue;
            }
            // SAFETY: an entry of the list.
            let path = unsafe { self.lib.fido_dev_info_path(di) };
            if path.is_null() {
                continue;
            }
            // SAFETY: a NUL-terminated path owned by the list, which
            // outlives this call.
            if let Some(sk) = self.sk_open(unsafe { CStr::from_ptr(path) }) {
                out.push(sk);
            }
        }
        out
    }

    /// `sk_touch_begin`: whether any device started waiting for a touch.
    fn sk_touch_begin(&self, skv: &[Option<Dev<'_>>]) -> bool {
        let mut ok = 0;
        for sk in skv.iter().flatten() {
            // SAFETY: an open device.
            let r = unsafe { self.lib.fido_dev_get_touch_begin(sk.ptr) }
                .unwrap_or(FIDO_ERR_UNSUPPORTED_OPTION);
            if r == FIDO_OK {
                ok += 1;
            }
        }
        ok > 0
    }

    /// `sk_touch_poll`: the index of a touched device, `None` for none yet,
    /// `Err` when no device is left. A device that fails is discarded.
    fn sk_touch_poll(&self, skv: &mut [Option<Dev<'_>>]) -> Result<Option<usize>, ()> {
        std::thread::sleep(POLL_SLEEP);
        // As OpenSSH does, counted from all devices, discarded ones included.
        let mut npoll = skv.len();
        for (i, slot) in skv.iter_mut().enumerate() {
            let Some(sk) = slot else {
                continue; // device discarded
            };
            let mut touch: c_int = 0;
            // SAFETY: an open device and an `int` to write to.
            let r = unsafe {
                self.lib
                    .fido_dev_get_touch_status(sk.ptr, &mut touch, FIDO_POLL_MS)
            }
            .unwrap_or(FIDO_ERR_UNSUPPORTED_OPTION);
            if r != FIDO_OK {
                *slot = None; // discard device
                npoll -= 1;
                if npoll == 0 {
                    return Err(());
                }
            } else if touch != 0 {
                return Ok(Some(i));
            }
        }
        Ok(None)
    }

    /// `check_sk_options`: whether the device has option `opt` on (1), off
    /// (0) or doesn't say (-1); `Err` if its info can't be read.
    fn check_sk_options(&self, dev: &Dev<'_>, opt: &CStr) -> Result<i32, ()> {
        let lib = &self.lib;
        // SAFETY: an open device.
        if !unsafe { lib.fido_dev_is_fido2(dev.ptr) } {
            return Ok(-1);
        }
        let info = CborInfo::new(lib).ok_or(())?;
        // SAFETY: an open device and a new info object.
        if unsafe { lib.fido_dev_get_cbor_info(dev.ptr, info.ptr) } != FIDO_OK {
            return Err(());
        }
        // SAFETY: accessors of a filled-in info object; the two arrays
        // have `len` entries, alive as long as `info`.
        unsafe {
            let name = lib.fido_cbor_info_options_name_ptr(info.ptr);
            let value = lib.fido_cbor_info_options_value_ptr(info.ptr);
            let len = lib.fido_cbor_info_options_len(info.ptr);
            if name.is_null() || value.is_null() {
                return Ok(-1);
            }
            for i in 0..len {
                let n = *name.add(i);
                if !n.is_null() && CStr::from_ptr(n) == opt {
                    return Ok(i32::from(*value.add(i)));
                }
            }
        }
        Ok(-1)
    }

    /// `fido_assert_set_clientdata`, or OpenSSH's fallback for libfido2
    /// before 1.8: the SHA-256 of `data` as the client data hash.
    fn assert_set_clientdata(&self, assert: &Assert<'_>, data: &[u8]) -> c_int {
        // SAFETY: a live assertion and a buffer of `data.len()` bytes.
        let r = unsafe {
            self.lib
                .fido_assert_set_clientdata(assert.ptr, data.as_ptr(), data.len())
        };
        r.unwrap_or_else(|| {
            let d = Zeroizing::new(Sha256::digest(data));
            let d: &[u8] = d.as_ref();
            // SAFETY: as above.
            unsafe {
                self.lib
                    .fido_assert_set_clientdata_hash(assert.ptr, d.as_ptr(), d.len())
            }
        })
    }

    /// `fido_cred_set_clientdata`, or the same fallback.
    fn cred_set_clientdata(&self, cred: &Cred<'_>, data: &[u8]) -> c_int {
        // SAFETY: a live credential and a buffer of `data.len()` bytes.
        let r = unsafe {
            self.lib
                .fido_cred_set_clientdata(cred.ptr, data.as_ptr(), data.len())
        };
        r.unwrap_or_else(|| {
            let d = Zeroizing::new(Sha256::digest(data));
            let d: &[u8] = d.as_ref();
            // SAFETY: as above.
            unsafe {
                self.lib
                    .fido_cred_set_clientdata_hash(cred.ptr, d.as_ptr(), d.len())
            }
        })
    }

    /// `sk_try`: whether the key handle exists on the device.
    fn sk_try(&self, sk: &Dev<'_>, application: &CStr, key_handle: &[u8]) -> bool {
        let lib = &self.lib;
        let Some(assert) = Assert::new(lib) else {
            return false;
        };
        let message = [0u8; 32];
        let r = (|| {
            // Generate an invalid signature on FIDO2 tokens.
            ok(self.assert_set_clientdata(&assert, &message))?;
            // SAFETY (all below): a live assertion, an open device, C
            // strings and buffers of the stated lengths.
            ok(unsafe { lib.fido_assert_set_rp(assert.ptr, application.as_ptr()) })?;
            ok(unsafe {
                lib.fido_assert_allow_cred(assert.ptr, key_handle.as_ptr(), key_handle.len())
            })?;
            ok(unsafe { lib.fido_assert_set_up(assert.ptr, FIDO_OPT_FALSE) })?;
            match unsafe { lib.fido_dev_get_assert(sk.ptr, assert.ptr, core::ptr::null()) } {
                // U2F tokens may return this.
                FIDO_ERR_USER_PRESENCE_REQUIRED => Ok(()),
                r => ok(r),
            }
        })();
        r.is_ok()
    }

    /// `sk_select_by_cred`.
    fn sk_select_by_cred(
        &self,
        devlist: &DevInfo<'_>,
        ndevs: usize,
        application: &CStr,
        key_handle: &[u8],
    ) -> Option<Dev<'_>> {
        let mut skv = self.sk_openv(devlist, ndevs);
        if skv.len() == 1 && matches!(self.check_sk_options(&skv[0], c"uv"), Ok(uv) if uv != -1) {
            return skv.pop();
        }
        let i = skv
            .iter()
            .position(|sk| self.sk_try(sk, application, key_handle))?;
        Some(skv.swap_remove(i))
    }

    /// `sk_select_by_touch`.
    fn sk_select_by_touch(&self, devlist: &DevInfo<'_>, ndevs: usize) -> Option<Dev<'_>> {
        let mut skv: Vec<Option<Dev<'_>>> = self
            .sk_openv(devlist, ndevs)
            .into_iter()
            .map(Some)
            .collect();
        if skv.len() < 2 {
            // A single candidate, or none.
            return skv.pop().flatten();
        }
        if !self.has_touch_status {
            // libfido2 < 1.5 can't choose among several tokens.
            return None;
        }
        if !self.sk_touch_begin(&skv) {
            return None;
        }
        let start = Instant::now();
        loop {
            if let Some(idx) = self.sk_touch_poll(&mut skv).ok()? {
                return skv[idx].take();
            }
            let ms_remain = SELECT_MS.saturating_sub(start.elapsed().as_millis());
            if ms_remain < FIDO_POLL_MS as u128 {
                return None; // timeout
            }
        }
    }

    /// `sk_probe`: the device to use, by credential when `cred` is given
    /// (application and key handle), else by touch.
    fn sk_probe(&self, cred: Option<(&CStr, &[u8])>) -> Option<Dev<'_>> {
        let lib = &self.lib;
        // SAFETY: allocates a list of `MAX_FIDO_DEVICES` entries.
        let devlist = DevInfo {
            lib,
            ptr: unsafe { lib.fido_dev_info_new(MAX_FIDO_DEVICES) },
        };
        if devlist.ptr.is_null() {
            return None;
        }
        let mut ndevs = 0usize;
        // SAFETY: a list of `MAX_FIDO_DEVICES` entries and a count to
        // write to.
        let r = unsafe { lib.fido_dev_info_manifest(devlist.ptr, MAX_FIDO_DEVICES, &mut ndevs) };
        if r != FIDO_OK || ndevs == 0 {
            return None;
        }
        let ndevs = ndevs.min(MAX_FIDO_DEVICES);
        match cred {
            Some((application, key_handle)) => {
                self.sk_select_by_cred(&devlist, ndevs, application, key_handle)
            }
            None => self.sk_select_by_touch(&devlist, ndevs),
        }
    }

    /// The device named by the `device` option, else the one probed for.
    fn find_device(
        &self,
        device: Option<&CStr>,
        cred: Option<(&CStr, &[u8])>,
    ) -> Result<Dev<'_>, SkError> {
        match device {
            Some(d) => self.sk_open(d),
            None => self.sk_probe(cred),
        }
        .ok_or(SkError::DeviceNotFound)
    }

    /// `key_lookup`: `FIDO_OK` if a resident credential for `application`
    /// and `user_id` exists, `FIDO_ERR_NO_CREDENTIALS` if not, else the
    /// error.
    fn key_lookup(&self, dev: &Dev<'_>, application: &CStr, user_id: &[u8], pin: &CPin) -> c_int {
        let lib = &self.lib;
        let Some(assert) = Assert::new(lib) else {
            return FIDO_ERR_INTERNAL;
        };
        let message = [0u8; 32];
        let r = (|| {
            // Generate an invalid signature on FIDO2 tokens.
            ok(self.assert_set_clientdata(&assert, &message))?;
            // SAFETY (all below): a live assertion, an open device, C
            // strings and buffers of the stated lengths.
            ok(unsafe { lib.fido_assert_set_rp(assert.ptr, application.as_ptr()) })?;
            ok(unsafe { lib.fido_assert_set_up(assert.ptr, FIDO_OPT_FALSE) })?;
            let mut uv = FIDO_OPT_OMIT;
            if pin.0.is_none() && matches!(self.check_sk_options(dev, c"uv"), Ok(v) if v != -1) {
                uv = FIDO_OPT_TRUE;
            }
            ok(unsafe { lib.fido_assert_set_uv(assert.ptr, uv) })?;
            ok(unsafe { lib.fido_dev_get_assert(dev.ptr, assert.ptr, pin.as_ptr()) })?;
            for i in 0..unsafe { lib.fido_assert_count(assert.ptr) } {
                let len = unsafe { lib.fido_assert_user_id_len(assert.ptr, i) };
                let ptr = unsafe { lib.fido_assert_user_id_ptr(assert.ptr, i) };
                if len == user_id.len()
                    && !ptr.is_null()
                    // SAFETY: `len` bytes owned by the assertion.
                    && unsafe { core::slice::from_raw_parts(ptr, len) } == user_id
                {
                    // Credential exists.
                    return Ok(());
                }
            }
            Err(FIDO_ERR_NO_CREDENTIALS)
        })();
        match r {
            Ok(()) => FIDO_OK,
            Err(e) => e,
        }
    }

    /// `read_rks`.
    fn read_rks(&self, sk: &Dev<'_>, pin: &CPin) -> Result<Vec<ResidentKey>, SkError> {
        let lib = &self.lib;
        if pin.0.is_none() {
            return Err(SkError::PinRequired);
        }
        let metadata = Metadata::new(lib).ok_or(SkError::General)?;
        // SAFETY: an open device, a new metadata object and a C string.
        let r = unsafe { lib.fido_credman_get_dev_metadata(sk.ptr, metadata.ptr, pin.as_ptr()) };
        if r != FIDO_OK {
            if r == FIDO_ERR_INVALID_COMMAND {
                // The device does not support resident keys.
                return Ok(Vec::new());
            }
            return Err(fidoerr_to_skerr(r));
        }
        let rp = CredmanRp::new(lib).ok_or(SkError::General)?;
        // SAFETY: as above.
        general(unsafe { lib.fido_credman_get_dev_rp(sk.ptr, rp.ptr, pin.as_ptr()) })?;
        let mut out = Vec::new();
        // SAFETY: a filled-in RP list.
        let nrp = unsafe { lib.fido_credman_rp_count(rp.ptr) };
        // Iterate over RP IDs that have resident keys.
        for i in 0..nrp {
            // SAFETY: `i < nrp`; the string lives as long as `rp`.
            let rp_id = unsafe { lib.fido_credman_rp_id(rp.ptr, i) };
            if rp_id.is_null() {
                continue;
            }
            // SAFETY: a NUL-terminated string owned by `rp`.
            let rp_id = unsafe { CStr::from_ptr(rp_id) };
            // Skip non-SSH RP IDs.
            if !rp_id
                .to_bytes()
                .get(..4)
                .is_some_and(|p| p.eq_ignore_ascii_case(b"ssh:"))
            {
                continue;
            }
            let rk = CredmanRk::new(lib).ok_or(SkError::General)?;
            // SAFETY: an open device, a C string, a new RK list.
            general(unsafe {
                lib.fido_credman_get_dev_rk(sk.ptr, rp_id.as_ptr(), rk.ptr, pin.as_ptr())
            })?;
            // SAFETY: a filled-in RK list.
            let nrk = unsafe { lib.fido_credman_rk_count(rk.ptr) };
            // Iterate over resident keys for this RP ID.
            for j in 0..nrk {
                // SAFETY: `j < nrk`; the credential lives as long as `rk`.
                let cred = unsafe { lib.fido_credman_rk(rk.ptr, j) };
                if cred.is_null() {
                    continue; // no RK in slot j
                }
                // SAFETY (all below): accessors of a credential owned by
                // `rk`, their buffers of the stated lengths.
                let algorithm = match unsafe { lib.fido_cred_type(cred) } {
                    COSE_ES256 => Algorithm::EcdsaP256,
                    COSE_EDDSA => Algorithm::Ed25519,
                    _ => continue, // unsupported key type
                };
                let key_handle =
                    unsafe { copy_bytes(lib.fido_cred_id_ptr(cred), lib.fido_cred_id_len(cred)) };
                let user_id = unsafe {
                    copy_bytes(
                        lib.fido_cred_user_id_ptr(cred),
                        lib.fido_cred_user_id_len(cred),
                    )
                };
                let mut flags = 0;
                if unsafe { lib.fido_cred_prot(cred) } == Some(FIDO_CRED_PROT_UV_REQUIRED) {
                    flags |= USER_VERIFICATION_REQD;
                }
                let public_key = pack_public_key(algorithm, unsafe { cred_pubkey(lib, cred) })
                    .ok_or(SkError::General)?;
                out.push(ResidentKey {
                    algorithm,
                    // OpenSSH leaves it zero.
                    slot: 0,
                    // SAFETY: the NUL-terminated `rp_id`.
                    application: unsafe { copy_cstr(rp_id.as_ptr()) },
                    key: EnrollResponse {
                        public_key,
                        key_handle,
                        ..EnrollResponse::default()
                    },
                    flags,
                    user_id,
                });
            }
        }
        Ok(out)
    }
}

/// A credential's public key, `None` if it has none.
///
/// # Safety
///
/// `cred` is a live credential.
unsafe fn cred_pubkey<'a>(lib: &Fido2, cred: *const FidoCred) -> Option<&'a [u8]> {
    // SAFETY: forwarded to the caller; the buffer lives as long as `cred`.
    unsafe {
        let ptr = lib.fido_cred_pubkey_ptr(cred);
        (!ptr.is_null()).then(|| core::slice::from_raw_parts(ptr, lib.fido_cred_pubkey_len(cred)))
    }
}

impl Provider for Fido2Provider {
    fn enroll(
        &self,
        alg: Algorithm,
        challenge: &[u8],
        application: &str,
        flags: u8,
        pin: Option<&str>,
        options: &[SkOption],
    ) -> Result<EnrollResponse, SkError> {
        let lib = &self.lib;
        self.init();
        let mut user_id = [0u8; 32];
        let device = check_enroll_options(options, &mut user_id)?;
        let cose_alg = match alg {
            Algorithm::EcdsaP256 => COSE_ES256,
            Algorithm::Ed25519 => COSE_EDDSA,
        };
        let app = c_application(application)?;
        let pin = CPin::new(pin)?;
        let sk = self.find_device(device.as_deref(), None)?;
        if flags & RESIDENT_KEY != 0 && flags & FORCE_OPERATION == 0 {
            let r = self.key_lookup(&sk, &app, &user_id, &pin);
            if r != FIDO_ERR_NO_CREDENTIALS {
                return Err(if r != FIDO_OK {
                    fidoerr_to_skerr(r)
                } else {
                    SkError::CredentialExists
                });
            }
        }
        let cred = Cred::new(lib).ok_or(SkError::General)?;
        // SAFETY (all below): a live credential, an open device, C strings
        // and buffers of the stated lengths.
        general(unsafe { lib.fido_cred_set_type(cred.ptr, cose_alg) })?;
        general(self.cred_set_clientdata(&cred, challenge))?;
        let rk = if flags & RESIDENT_KEY != 0 {
            FIDO_OPT_TRUE
        } else {
            FIDO_OPT_OMIT
        };
        general(unsafe { lib.fido_cred_set_rk(cred.ptr, rk) })?;
        general(unsafe {
            lib.fido_cred_set_user(
                cred.ptr,
                user_id.as_ptr(),
                user_id.len(),
                c"openssh".as_ptr(),
                c"openssh".as_ptr(),
                core::ptr::null(),
            )
        })?;
        general(unsafe { lib.fido_cred_set_rp(cred.ptr, app.as_ptr(), core::ptr::null()) })?;
        if flags & (RESIDENT_KEY | USER_VERIFICATION_REQD) != 0 {
            // Missing in libfido2 < 1.4 (OpenSSH: "Please upgrade to
            // >=1.5.0"), or the device doesn't support credprot: refuse to
            // create an unprotected resident / verify-required key.
            if unsafe { lib.fido_dev_supports_cred_prot(sk.ptr) } != Some(true) {
                return Err(SkError::Unsupported);
            }
            let credprot = if flags & USER_VERIFICATION_REQD != 0 {
                FIDO_CRED_PROT_UV_REQUIRED
            } else {
                FIDO_CRED_PROT_UV_OPTIONAL_WITH_ID
            };
            let r = unsafe { lib.fido_cred_set_prot(cred.ptr, credprot) }
                .ok_or(SkError::Unsupported)?;
            ok(r).map_err(fidoerr_to_skerr)?;
        }
        ok(unsafe { lib.fido_dev_make_cred(sk.ptr, cred.ptr, pin.as_ptr()) })
            .map_err(fidoerr_to_skerr)?;
        if !unsafe { lib.fido_cred_x5c_ptr(cred.ptr) }.is_null() {
            general(unsafe { lib.fido_cred_verify(cred.ptr) })?;
        } else {
            let fmt = unsafe { lib.fido_cred_fmt(cred.ptr) };
            // SAFETY: a NUL-terminated string owned by the credential.
            if fmt.is_null() || unsafe { CStr::from_ptr(fmt) } != c"none" {
                // Self-attested credential.
                general(unsafe { lib.fido_cred_verify_self(cred.ptr) })?;
            }
            // Else no attestation data.
        }
        let public_key =
            pack_public_key(alg, unsafe { cred_pubkey(lib, cred.ptr) }).ok_or(SkError::General)?;
        // SAFETY (all below): the credential's buffers, of the stated
        // lengths (null ⇒ empty).
        unsafe {
            Ok(EnrollResponse {
                flags,
                public_key,
                key_handle: copy_bytes(
                    lib.fido_cred_id_ptr(cred.ptr),
                    lib.fido_cred_id_len(cred.ptr),
                ),
                signature: copy_bytes(
                    lib.fido_cred_sig_ptr(cred.ptr),
                    lib.fido_cred_sig_len(cred.ptr),
                ),
                attestation_cert: copy_bytes(
                    lib.fido_cred_x5c_ptr(cred.ptr),
                    lib.fido_cred_x5c_len(cred.ptr),
                ),
                authdata: copy_bytes(
                    lib.fido_cred_authdata_ptr(cred.ptr),
                    lib.fido_cred_authdata_len(cred.ptr),
                ),
            })
        }
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
    ) -> Result<SignResponse, SkError> {
        let lib = &self.lib;
        self.init();
        let device = check_sign_load_resident_options(options)?;
        let app = c_application(application)?;
        let pin = CPin::new(pin)?;
        let cred = if pin.0.is_some() || flags & USER_VERIFICATION_REQD != 0 {
            None
        } else {
            Some((app.as_c_str(), key_handle))
        };
        let sk = self.find_device(device.as_deref(), cred)?;
        let assert = Assert::new(lib).ok_or(SkError::General)?;
        general(self.assert_set_clientdata(&assert, data))?;
        // SAFETY (all below): a live assertion, an open device, C strings
        // and buffers of the stated lengths.
        general(unsafe { lib.fido_assert_set_rp(assert.ptr, app.as_ptr()) })?;
        general(unsafe {
            lib.fido_assert_allow_cred(assert.ptr, key_handle.as_ptr(), key_handle.len())
        })?;
        let up = if flags & USER_PRESENCE_REQD != 0 {
            FIDO_OPT_TRUE
        } else {
            FIDO_OPT_FALSE
        };
        general(unsafe { lib.fido_assert_set_up(assert.ptr, up) })?;
        // WinHello requests the PIN by default. Make "uv" request explicit
        // to allow keys with and without -O verify-required to make sense.
        // (A failure here is only logged by OpenSSH.)
        if pin.0.is_none() && unsafe { lib.fido_dev_is_winhello(sk.ptr) } == Some(true) {
            unsafe { lib.fido_assert_set_uv(assert.ptr, FIDO_OPT_FALSE) };
        }
        if pin.0.is_none() && flags & USER_VERIFICATION_REQD != 0 {
            if self.check_sk_options(&sk, c"uv") != Ok(1) {
                return Err(SkError::PinRequired);
            }
            ok(unsafe { lib.fido_assert_set_uv(assert.ptr, FIDO_OPT_TRUE) })
                .map_err(fidoerr_to_skerr)?;
        }
        ok(unsafe { lib.fido_dev_get_assert(sk.ptr, assert.ptr, pin.as_ptr()) })
            .map_err(fidoerr_to_skerr)?;
        let (flags, counter, sig) = unsafe {
            let ptr = lib.fido_assert_sig_ptr(assert.ptr, 0);
            let len = lib.fido_assert_sig_len(assert.ptr, 0);
            (
                lib.fido_assert_flags(assert.ptr, 0),
                lib.fido_assert_sigcount(assert.ptr, 0),
                copy_bytes(ptr, len),
            )
        };
        let (sig_r, sig_s) = pack_sig(alg, &sig).ok_or(SkError::General)?;
        Ok(SignResponse {
            flags,
            counter,
            sig_r,
            sig_s,
        })
    }

    fn load_resident_keys(
        &self,
        pin: Option<&str>,
        options: &[SkOption],
    ) -> Result<Vec<ResidentKey>, SkError> {
        self.init();
        let device = check_sign_load_resident_options(options)?;
        let pin = CPin::new(pin)?;
        let sk = self.find_device(device.as_deref(), None)?;
        self.read_rks(&sk, &pin)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::String;

    fn opt(name: &str, value: &str, required: bool) -> SkOption {
        SkOption {
            name: name.into(),
            value: value.into(),
            required,
        }
    }

    #[test]
    fn error_mapping() {
        assert_eq!(
            fidoerr_to_skerr(FIDO_ERR_UNSUPPORTED_OPTION),
            SkError::Unsupported
        );
        assert_eq!(
            fidoerr_to_skerr(FIDO_ERR_UNSUPPORTED_ALGORITHM),
            SkError::Unsupported
        );
        assert_eq!(
            fidoerr_to_skerr(FIDO_ERR_PIN_REQUIRED),
            SkError::PinRequired
        );
        assert_eq!(fidoerr_to_skerr(FIDO_ERR_PIN_INVALID), SkError::PinRequired);
        assert_eq!(
            fidoerr_to_skerr(FIDO_ERR_OPERATION_DENIED),
            SkError::PinRequired
        );
        for e in [
            FIDO_ERR_NO_CREDENTIALS,
            FIDO_ERR_INTERNAL,
            FIDO_ERR_INVALID_COMMAND,
            0x32, // PIN_BLOCKED
            0x33, // PIN_AUTH_INVALID
            -1,
        ] {
            assert_eq!(fidoerr_to_skerr(e), SkError::General, "{e}");
        }
    }

    #[test]
    fn enroll_options() {
        let mut uid = [0u8; 32];
        assert_eq!(check_enroll_options(&[], &mut uid), Ok(None));
        assert_eq!(uid, [0; 32]);

        let o = [
            opt("device", "/dev/hidraw3", true),
            opt("user", "alice", false),
            opt("other", "x", false),
        ];
        let dev = check_enroll_options(&o, &mut uid).unwrap();
        assert_eq!(dev.as_deref(), Some(c"/dev/hidraw3"));
        let mut want = [0u8; 32];
        want[..5].copy_from_slice(b"alice");
        assert_eq!(uid, want);

        // `strlcpy` over a longer value: its tail stays.
        check_enroll_options(&[opt("user", "bob", false)], &mut uid).unwrap();
        assert_eq!(&uid[..6], b"bob\0e\0");

        // 31 bytes fit (with the NUL), 32 don't.
        let mut uid = [0u8; 32];
        let v31 = String::from_utf8(alloc::vec![b'u'; 31]).unwrap();
        check_enroll_options(&[opt("user", &v31, false)], &mut uid).unwrap();
        assert_eq!(&uid[..31], v31.as_bytes());
        let v32 = String::from_utf8(alloc::vec![b'u'; 32]).unwrap();
        assert_eq!(
            check_enroll_options(&[opt("user", &v32, false)], &mut uid),
            Err(SkError::General)
        );

        // An unknown required option fails; the last `device` wins.
        assert_eq!(
            check_enroll_options(&[opt("other", "x", true)], &mut uid),
            Err(SkError::General)
        );
        let o = [opt("device", "a", false), opt("device", "b", false)];
        assert_eq!(
            check_enroll_options(&o, &mut uid).unwrap().as_deref(),
            Some(c"b")
        );
    }

    #[test]
    fn sign_options() {
        assert_eq!(check_sign_load_resident_options(&[]), Ok(None));
        let o = [
            opt("device", "/dev/hidraw0", false),
            opt("user", "x", false),
        ];
        assert_eq!(
            check_sign_load_resident_options(&o).unwrap().as_deref(),
            Some(c"/dev/hidraw0")
        );
        // `user` is an enrolment option only.
        assert_eq!(
            check_sign_load_resident_options(&[opt("user", "x", true)]),
            Err(SkError::General)
        );
        assert_eq!(
            check_sign_load_resident_options(&[opt("device", "a\0b", false)]),
            Err(SkError::General)
        );
    }

    #[test]
    fn public_key_packing() {
        use purecrypto::ec::BoxedEcdsaPrivateKey;

        let sk = BoxedEcdsaPrivateKey::from_bytes(CurveId::P256, &[7u8; 32]).unwrap();
        let sec1 = sk.public_key().to_sec1();
        assert_eq!(sec1.len(), 65);
        let xy = &sec1[1..];
        assert_eq!(
            pack_public_key(Algorithm::EcdsaP256, Some(xy)).as_deref(),
            Some(&sec1[..])
        );
        // Off the curve, wrong length, absent.
        let mut bad = xy.to_vec();
        bad[63] ^= 1;
        assert_eq!(pack_public_key(Algorithm::EcdsaP256, Some(&bad)), None);
        assert_eq!(pack_public_key(Algorithm::EcdsaP256, Some(&sec1)), None);
        assert_eq!(pack_public_key(Algorithm::EcdsaP256, None), None);

        let ed = [9u8; 32];
        assert_eq!(
            pack_public_key(Algorithm::Ed25519, Some(&ed)).as_deref(),
            Some(&ed[..])
        );
        assert_eq!(pack_public_key(Algorithm::Ed25519, Some(&ed[..31])), None);
        assert_eq!(pack_public_key(Algorithm::Ed25519, None), None);
    }

    #[test]
    fn signature_packing() {
        // r with its sign byte, s short.
        let mut der = alloc::vec![0x30, 0x27, 0x02, 0x21, 0x00];
        der.extend_from_slice(&[0xff; 32]);
        der.extend_from_slice(&[0x02, 0x02, 0x01, 0x02]);
        let (r, s) = pack_sig(Algorithm::EcdsaP256, &der).unwrap();
        assert_eq!(r, [0xff; 32]);
        assert_eq!(s, [0x01, 0x02]);
        // Bytes after the SEQUENCE are ignored, as `d2i_ECDSA_SIG` does.
        let mut trailing = der.clone();
        trailing.push(0);
        assert!(pack_sig(Algorithm::EcdsaP256, &trailing).is_some());
        // Bytes inside it after `s` aren't.
        let inner = [0x30, 0x07, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01, 0x00];
        assert_eq!(pack_sig(Algorithm::EcdsaP256, &inner), None);
        // Zero is no bytes (`BN_num_bytes`).
        let zero = [0x30, 0x06, 0x02, 0x01, 0x00, 0x02, 0x01, 0x05];
        assert_eq!(
            pack_sig(Algorithm::EcdsaP256, &zero),
            Some((Vec::new(), alloc::vec![5]))
        );
        // Negative, non-minimal, truncated, empty.
        for bad in [
            &[0x30, 0x06, 0x02, 0x01, 0x80, 0x02, 0x01, 0x05][..],
            &[0x30, 0x07, 0x02, 0x02, 0x00, 0x05, 0x02, 0x01, 0x05],
            &[0x30, 0x06, 0x02, 0x01, 0x05, 0x02, 0x01],
            &[0x30, 0x05, 0x02, 0x00, 0x02, 0x01, 0x05],
            &[],
        ] {
            assert_eq!(pack_sig(Algorithm::EcdsaP256, bad), None, "{bad:02x?}");
        }
        // A long-form length.
        let mut long = alloc::vec![0x30, 0x81, 0x84, 0x02, 0x40];
        long.extend_from_slice(&[0x11; 64]);
        long.extend_from_slice(&[0x02, 0x40]);
        long.extend_from_slice(&[0x22; 64]);
        let (r, s) = pack_sig(Algorithm::EcdsaP256, &long).unwrap();
        assert_eq!((r.len(), s.len()), (64, 64));
        // ... but not a needless one.
        let mut lax = alloc::vec![0x30, 0x81, 0x06];
        lax.extend_from_slice(&zero[2..]);
        assert_eq!(pack_sig(Algorithm::EcdsaP256, &lax), None);

        let ed = [3u8; 64];
        assert_eq!(
            pack_sig(Algorithm::Ed25519, &ed),
            Some((ed.to_vec(), Vec::new()))
        );
        assert_eq!(pack_sig(Algorithm::Ed25519, &ed[..63]), None);
    }

    /// With `LIBFIDO2_PATH` naming a libfido2 build: every symbol resolves,
    /// and with no authenticator attached each operation reports
    /// `DeviceNotFound`, as OpenSSH's does.
    #[test]
    fn libfido2_without_device() {
        let Ok(path) = std::env::var("LIBFIDO2_PATH") else {
            return;
        };
        let p = Fido2Provider::open_first(&[path.as_str()]).expect("load libfido2");
        assert!(p.has_touch_status);
        for name in [
            c"fido_dev_is_winhello",
            c"fido_dev_supports_cred_prot",
            c"fido_dev_get_touch_begin",
            c"fido_dev_get_touch_status",
            c"fido_assert_set_clientdata",
            c"fido_cred_set_clientdata",
            c"fido_cred_set_prot",
            c"fido_cred_prot",
        ] {
            // SAFETY: only looked up.
            let found = unsafe { p.lib.library().get::<unsafe extern "C" fn()>(name) }.is_ok();
            assert!(found, "{name:?} missing");
        }

        let none = [];
        let missing = [opt("device", "/nonexistent/hidraw", false)];
        for options in [&none[..], &missing[..]] {
            for alg in [Algorithm::EcdsaP256, Algorithm::Ed25519] {
                for flags in [USER_PRESENCE_REQD, USER_PRESENCE_REQD | RESIDENT_KEY] {
                    assert_eq!(
                        p.enroll(alg, &[1; 32], "ssh:", flags, None, options).err(),
                        Some(SkError::DeviceNotFound)
                    );
                }
                for (flags, pin) in [
                    (USER_PRESENCE_REQD, None),
                    (USER_VERIFICATION_REQD, None),
                    (USER_PRESENCE_REQD, Some("1234")),
                ] {
                    assert_eq!(
                        p.sign(alg, b"data", "ssh:", &[1; 16], flags, pin, options)
                            .err(),
                        Some(SkError::DeviceNotFound)
                    );
                }
            }
            assert_eq!(
                p.load_resident_keys(Some("1234"), options).err(),
                Some(SkError::DeviceNotFound)
            );
            assert_eq!(
                p.load_resident_keys(None, options).err(),
                Some(SkError::DeviceNotFound)
            );
        }
        // Option errors come first.
        assert_eq!(
            p.sign(
                Algorithm::Ed25519,
                b"",
                "ssh:",
                &[1],
                0,
                None,
                &[opt("x", "y", true)]
            )
            .err(),
            Some(SkError::General)
        );
    }
}
