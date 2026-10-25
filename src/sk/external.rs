//! A middleware library implementing OpenSSH's `sk-api.h`, loaded at run
//! time (`SecurityKeyProvider /path/to/lib.so`).

use alloc::string::String;
use alloc::vec::Vec;
use std::ffi::{c_char, c_int};

use dlsym::Bindings;

use super::{
    Algorithm, COptions, CPin, EnrollResponse, Provider, ResidentKey, SignResponse, SkError,
    SkOption, c_application, copy_bytes, copy_cstr, free_bytes,
};

/// `struct sk_option`.
#[repr(C)]
pub(super) struct RawOption {
    pub(super) name: *mut c_char,
    pub(super) value: *mut c_char,
    pub(super) required: u8,
}

/// `struct sk_enroll_response`.
#[repr(C)]
pub(super) struct RawEnrollResponse {
    flags: u8,
    public_key: *mut u8,
    public_key_len: usize,
    key_handle: *mut u8,
    key_handle_len: usize,
    signature: *mut u8,
    signature_len: usize,
    attestation_cert: *mut u8,
    attestation_cert_len: usize,
    authdata: *mut u8,
    authdata_len: usize,
}

/// `struct sk_sign_response`.
#[repr(C)]
pub(super) struct RawSignResponse {
    flags: u8,
    counter: u32,
    sig_r: *mut u8,
    sig_r_len: usize,
    sig_s: *mut u8,
    sig_s_len: usize,
}

/// `struct sk_resident_key`.
#[repr(C)]
pub(super) struct RawResidentKey {
    alg: u32,
    slot: usize,
    application: *mut c_char,
    key: RawEnrollResponse,
    flags: u8,
    user_id: *mut u8,
    user_id_len: usize,
}

dlsym::library! {
    struct SkApi {
        unsafe extern "C" {
            fn sk_api_version() -> u32;
            fn sk_enroll(
                alg: u32,
                challenge: *const u8,
                challenge_len: usize,
                application: *const c_char,
                flags: u8,
                pin: *const c_char,
                options: *mut *mut RawOption,
                enroll_response: *mut *mut RawEnrollResponse,
            ) -> c_int;
            fn sk_sign(
                alg: u32,
                data: *const u8,
                data_len: usize,
                application: *const c_char,
                key_handle: *const u8,
                key_handle_len: usize,
                flags: u8,
                pin: *const c_char,
                options: *mut *mut RawOption,
                sign_response: *mut *mut RawSignResponse,
            ) -> c_int;
            fn sk_load_resident_keys(
                pin: *const c_char,
                options: *mut *mut RawOption,
                rks: *mut *mut *mut RawResidentKey,
                nrks: *mut usize,
            ) -> c_int;
        }
    }
}

/// A provider library.
pub struct ExternalProvider {
    api: SkApi,
    path: String,
}

impl core::fmt::Debug for ExternalProvider {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ExternalProvider")
            .field("path", &self.path)
            .finish()
    }
}

impl ExternalProvider {
    /// Load the provider at `path`, checking it implements this API major
    /// version.
    pub fn open(path: &str) -> Result<Self, SkError> {
        // SAFETY: loading a provider runs its initialisers; naming it in
        // `SecurityKeyProvider` is trusting it, as with OpenSSH.
        let api = unsafe { SkApi::open(path) }.map_err(|e| {
            SkError::Provider(alloc::format!(
                "provider {path} is not an OpenSSH FIDO library: {e}"
            ))
        })?;
        // SAFETY: `sk_api_version` takes no arguments.
        let version = unsafe { api.sk_api_version() };
        if version & super::API_VERSION_MAJOR_MASK != super::API_VERSION_MAJOR {
            return Err(SkError::Provider(alloc::format!(
                "Provider \"{path}\" implements unsupported version 0x{version:08x} (supported: 0x{:08x})",
                super::API_VERSION_MAJOR
            )));
        }
        Ok(Self {
            api,
            path: path.into(),
        })
    }
}

/// Take ownership of an enrolment response the provider allocated.
///
/// # Safety
///
/// `r` is a live response from the provider, its buffers `malloc`ed; it
/// is freed here (its fields, not the struct itself).
unsafe fn take_enroll(r: &mut RawEnrollResponse) -> EnrollResponse {
    // SAFETY (all below): the provider's buffers, of the stated lengths.
    let out = unsafe {
        EnrollResponse {
            flags: r.flags,
            public_key: copy_bytes(r.public_key, r.public_key_len),
            key_handle: copy_bytes(r.key_handle, r.key_handle_len),
            signature: copy_bytes(r.signature, r.signature_len),
            attestation_cert: copy_bytes(r.attestation_cert, r.attestation_cert_len),
            authdata: copy_bytes(r.authdata, r.authdata_len),
        }
    };
    // SAFETY: each freed once; the pointers are cleared after.
    unsafe {
        free_bytes(r.public_key, r.public_key_len);
        free_bytes(r.key_handle, r.key_handle_len);
        free_bytes(r.signature, r.signature_len);
        free_bytes(r.attestation_cert, r.attestation_cert_len);
        free_bytes(r.authdata, r.authdata_len);
    }
    r.public_key = core::ptr::null_mut();
    r.key_handle = core::ptr::null_mut();
    r.signature = core::ptr::null_mut();
    r.attestation_cert = core::ptr::null_mut();
    r.authdata = core::ptr::null_mut();
    out
}

impl Provider for ExternalProvider {
    fn enroll(
        &self,
        alg: Algorithm,
        challenge: &[u8],
        application: &str,
        flags: u8,
        pin: Option<&str>,
        options: &[SkOption],
    ) -> Result<EnrollResponse, SkError> {
        let app = c_application(application)?;
        let pin = CPin::new(pin)?;
        let mut opts = COptions::new(options)?;
        let mut resp: *mut RawEnrollResponse = core::ptr::null_mut();
        // SAFETY: valid buffers and C strings for the call; `resp` receives
        // a provider-allocated response.
        let rc = unsafe {
            self.api.sk_enroll(
                alg.id(),
                challenge.as_ptr(),
                challenge.len(),
                app.as_ptr(),
                flags,
                pin.as_ptr(),
                opts.as_ptr(),
                &mut resp,
            )
        };
        if resp.is_null() {
            return Err(if rc == 0 {
                SkError::General
            } else {
                SkError::from_code(rc)
            });
        }
        // SAFETY: a provider response, taken then freed once.
        let out = unsafe { take_enroll(&mut *resp) };
        // SAFETY: the struct itself is `malloc`ed too.
        unsafe { libc::free(resp.cast()) };
        if rc != 0 {
            return Err(SkError::from_code(rc));
        }
        Ok(out)
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
        let app = c_application(application)?;
        let pin = CPin::new(pin)?;
        let mut opts = COptions::new(options)?;
        let mut resp: *mut RawSignResponse = core::ptr::null_mut();
        // SAFETY: as for `enroll`.
        let rc = unsafe {
            self.api.sk_sign(
                alg.id(),
                data.as_ptr(),
                data.len(),
                app.as_ptr(),
                key_handle.as_ptr(),
                key_handle.len(),
                flags,
                pin.as_ptr(),
                opts.as_ptr(),
                &mut resp,
            )
        };
        if resp.is_null() {
            return Err(if rc == 0 {
                SkError::General
            } else {
                SkError::from_code(rc)
            });
        }
        // SAFETY: a provider response; its buffers are freed once.
        let out = unsafe {
            let r = &mut *resp;
            let out = SignResponse {
                flags: r.flags,
                counter: r.counter,
                sig_r: copy_bytes(r.sig_r, r.sig_r_len),
                sig_s: copy_bytes(r.sig_s, r.sig_s_len),
            };
            free_bytes(r.sig_r, r.sig_r_len);
            free_bytes(r.sig_s, r.sig_s_len);
            libc::free(resp.cast());
            out
        };
        if rc != 0 {
            return Err(SkError::from_code(rc));
        }
        Ok(out)
    }

    fn load_resident_keys(
        &self,
        pin: Option<&str>,
        options: &[SkOption],
    ) -> Result<Vec<ResidentKey>, SkError> {
        let pin = CPin::new(pin)?;
        let mut opts = COptions::new(options)?;
        let mut rks: *mut *mut RawResidentKey = core::ptr::null_mut();
        let mut nrks = 0usize;
        // SAFETY: as for `enroll`; `rks` receives an array of `nrks`.
        let rc = unsafe {
            self.api
                .sk_load_resident_keys(pin.as_ptr(), opts.as_ptr(), &mut rks, &mut nrks)
        };
        let mut out = Vec::new();
        if !rks.is_null() {
            for i in 0..nrks {
                // SAFETY: `i < nrks` entries of the provider's array.
                let rk = unsafe { *rks.add(i) };
                if rk.is_null() {
                    continue;
                }
                // SAFETY: a provider-allocated resident key, freed once.
                unsafe {
                    let r = &mut *rk;
                    let key = take_enroll(&mut r.key);
                    let application = copy_cstr(r.application);
                    let user_id = copy_bytes(r.user_id, r.user_id_len);
                    if let Some(algorithm) = Algorithm::from_id(r.alg) {
                        out.push(ResidentKey {
                            algorithm,
                            slot: r.slot,
                            application,
                            key,
                            flags: r.flags,
                            user_id,
                        });
                    }
                    libc::free(r.application.cast());
                    free_bytes(r.user_id, r.user_id_len);
                    libc::free(rk.cast());
                }
            }
            // SAFETY: the array is `malloc`ed.
            unsafe { libc::free(rks.cast()) };
        }
        if rc != 0 {
            return Err(SkError::from_code(rc));
        }
        Ok(out)
    }
}
