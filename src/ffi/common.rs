//! Shared FFI helpers: error codes, panic-guard glue, string conversion,
//! and the `pcssh_error_message` / `pcssh_version` entry points.
//!
//! Lives in its own submodule so the per-surface modules
//! ([`super::client`], future SFTP/known_hosts/agent modules) don't
//! duplicate the boilerplate.

use core::ffi::{c_char, c_int};
use core::panic::AssertUnwindSafe;
use core::ptr;
use std::ffi::CStr;
use std::panic::catch_unwind;

use crate::error::Error;

/// Error code: success.
pub const PCSSH_OK: c_int = 0;
/// Error code: unspecified / generic failure.
pub const PCSSH_ERR_GENERIC: c_int = -1;
/// Error code: caller-supplied buffer too small. Output length variables
/// reflect the required capacity.
pub const PCSSH_ERR_BUFFER_TOO_SMALL: c_int = -2;
/// Error code: a pointer or string argument was invalid (NULL or non-UTF-8).
pub const PCSSH_ERR_INVALID_ARGUMENT: c_int = -3;
/// Error code: low-level I/O failure.
pub const PCSSH_ERR_IO: c_int = -4;
/// Error code: failed to establish TCP connection.
pub const PCSSH_ERR_CONNECT: c_int = -5;
/// Error code: key exchange failed.
pub const PCSSH_ERR_KEX: c_int = -6;
/// Error code: authentication exhausted or refused.
pub const PCSSH_ERR_AUTH_FAILED: c_int = -7;
/// Error code: server host key rejected by policy.
pub const PCSSH_ERR_HOSTKEY_REJECTED: c_int = -8;
/// Error code: protocol-level invariant violated by peer.
pub const PCSSH_ERR_PROTOCOL: c_int = -9;
/// Error code: parsing or wire-format failure.
pub const PCSSH_ERR_PARSE: c_int = -10;
/// Error code: a Rust panic was caught at the FFI boundary.
pub const PCSSH_ERR_PANIC: c_int = -99;
/// Error code: caller-supplied configuration is internally inconsistent
/// (e.g. a known-hosts policy without a target host).
pub const PCSSH_ERR_CONFIG: c_int = -11;
/// Error code: a child handle (e.g. SFTP file) was used after its parent
/// (e.g. SFTP session) was freed. Detected via generation counters.
pub const PCSSH_ERR_INVALID_HANDLE: c_int = -12;

/// Map a Rust [`Error`] to a C error code.
pub(crate) fn map_error(err: &Error) -> c_int {
    match err {
        Error::Io(_) => PCSSH_ERR_IO,
        Error::Format(_) => PCSSH_ERR_PARSE,
        Error::NoCommonAlgorithm(_) => PCSSH_ERR_KEX,
        Error::Protocol(_) => PCSSH_ERR_PROTOCOL,
        Error::BadMac
        | Error::BadTag
        | Error::BadPadding
        | Error::BadSignature
        | Error::Crypto(_) => PCSSH_ERR_KEX,
        Error::HostKeyRejected => PCSSH_ERR_HOSTKEY_REJECTED,
        Error::AuthFailed => PCSSH_ERR_AUTH_FAILED,
        Error::BadChannelState => PCSSH_ERR_PROTOCOL,
        Error::Unsupported(_) => PCSSH_ERR_GENERIC,
        Error::Config(_) => PCSSH_ERR_CONFIG,
    }
}

/// Convert an FFI C string pointer into a `&str`. NULL or non-UTF-8
/// yields `None`.
///
/// # Safety
///
/// `ptr` must either be NULL or point to a NUL-terminated C string valid
/// for the duration of the call.
pub(crate) unsafe fn cstr_to_str<'a>(ptr: *const c_char) -> Option<&'a str> {
    if ptr.is_null() {
        return None;
    }
    // SAFETY: caller guarantees NUL termination and lifetime.
    let cs = unsafe { CStr::from_ptr(ptr) };
    cs.to_str().ok()
}

/// Run an FFI body inside `catch_unwind`, returning [`PCSSH_ERR_PANIC`]
/// on unwind. Saves every `pcssh_*` entry point from typing the same
/// match arm by hand.
pub(crate) fn catch<F: FnOnce() -> c_int>(f: F) -> c_int {
    match catch_unwind(AssertUnwindSafe(f)) {
        Ok(code) => code,
        Err(_) => PCSSH_ERR_PANIC,
    }
}

/// Return a static, NUL-terminated description for a non-success error
/// code.
///
/// Returns NULL for codes the library does not recognise. The returned
/// pointer is owned by the library and must not be freed.
#[no_mangle]
pub extern "C" fn pcssh_error_message(code: c_int) -> *const c_char {
    let s: &'static [u8] = match code {
        PCSSH_OK => b"ok\0",
        PCSSH_ERR_GENERIC => b"generic error\0",
        PCSSH_ERR_BUFFER_TOO_SMALL => b"buffer too small\0",
        PCSSH_ERR_INVALID_ARGUMENT => b"invalid argument\0",
        PCSSH_ERR_IO => b"I/O error\0",
        PCSSH_ERR_CONNECT => b"connect failed\0",
        PCSSH_ERR_KEX => b"key exchange failed\0",
        PCSSH_ERR_AUTH_FAILED => b"authentication failed\0",
        PCSSH_ERR_HOSTKEY_REJECTED => b"host key rejected\0",
        PCSSH_ERR_PROTOCOL => b"protocol error\0",
        PCSSH_ERR_PARSE => b"parse error\0",
        PCSSH_ERR_CONFIG => b"configuration error\0",
        PCSSH_ERR_INVALID_HANDLE => b"invalid or stale handle\0",
        PCSSH_ERR_PANIC => b"caught panic at FFI boundary\0",
        _ => return ptr::null(),
    };
    s.as_ptr() as *const c_char
}

/// Build-time version string (matches `CARGO_PKG_VERSION`).
///
/// Returns a static, NUL-terminated UTF-8 pointer owned by the library.
#[no_mangle]
pub extern "C" fn pcssh_version() -> *const c_char {
    static VERSION: &[u8] = concat!(env!("CARGO_PKG_VERSION"), "\0").as_bytes();
    VERSION.as_ptr() as *const c_char
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_is_nul_terminated() {
        let p = pcssh_version();
        assert!(!p.is_null());
        // SAFETY: pointer is a 'static, NUL-terminated string.
        let s = unsafe { CStr::from_ptr(p) };
        let v = s.to_str().unwrap();
        assert_eq!(v, env!("CARGO_PKG_VERSION"));
    }

    #[test]
    fn error_message_known_codes() {
        for code in [
            PCSSH_OK,
            PCSSH_ERR_GENERIC,
            PCSSH_ERR_BUFFER_TOO_SMALL,
            PCSSH_ERR_INVALID_ARGUMENT,
            PCSSH_ERR_IO,
            PCSSH_ERR_CONNECT,
            PCSSH_ERR_KEX,
            PCSSH_ERR_AUTH_FAILED,
            PCSSH_ERR_HOSTKEY_REJECTED,
            PCSSH_ERR_PROTOCOL,
            PCSSH_ERR_PARSE,
            PCSSH_ERR_CONFIG,
            PCSSH_ERR_INVALID_HANDLE,
            PCSSH_ERR_PANIC,
        ] {
            let p = pcssh_error_message(code);
            assert!(!p.is_null(), "missing message for {code}");
            // SAFETY: returned pointer is a 'static, NUL-terminated string.
            let _ = unsafe { CStr::from_ptr(p) }.to_str().unwrap();
        }
    }

    #[test]
    fn error_message_unknown_returns_null() {
        assert!(pcssh_error_message(12345).is_null());
        assert!(pcssh_error_message(-12345).is_null());
    }

    #[test]
    fn catch_returns_panic_code_on_unwind() {
        let rc = catch(|| panic!("boom"));
        assert_eq!(rc, PCSSH_ERR_PANIC);
    }

    #[test]
    fn catch_passes_through_normal_return() {
        let rc = catch(|| PCSSH_OK);
        assert_eq!(rc, PCSSH_OK);
        let rc = catch(|| PCSSH_ERR_IO);
        assert_eq!(rc, PCSSH_ERR_IO);
    }
}
