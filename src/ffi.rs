//! C ABI / FFI surface for `puressh`.
//!
//! Exposes a minimal client-side API to C callers: connect + KEX, password or
//! publickey authentication, command execution into caller-supplied buffers,
//! and resource cleanup. Errors are returned as small negative integers; see
//! [`pcssh_error_message`] for human-readable descriptions.
//!
//! This module is gated behind the `ffi` feature and only built with `std`.
//! Compiled as `staticlib` / `cdylib`, it produces `libpuressh.a` and a
//! platform-appropriate shared library.

#![cfg(feature = "std")]
#![deny(unsafe_op_in_unsafe_fn)]
#![allow(clippy::missing_safety_doc)]

use core::ffi::{c_char, c_int};
use core::panic::AssertUnwindSafe;
use core::ptr;
use std::ffi::CStr;
use std::net::ToSocketAddrs;
use std::panic::catch_unwind;
use std::slice;
use std::time::Duration;

use crate::auth::ClientCredential;
use crate::client::{Client, Config, HostKeyPolicy};
use crate::error::Error;
use crate::key::PrivateKey;

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

/// Opaque handle to a connected SSH client.
///
/// Allocated by [`pcssh_client_connect`], freed by [`pcssh_client_free`].
/// Internally a `Box<Client>`; the C side treats it as an opaque pointer.
pub struct PcSshClient {
    inner: Client,
}

/// Map a Rust [`Error`] to a C error code.
fn map_error(err: &Error) -> c_int {
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
    }
}

/// Convert an FFI C string pointer into a `&str`. NULL or non-UTF-8 yields
/// `None`.
///
/// # Safety
///
/// `ptr` must either be NULL or point to a NUL-terminated C string valid for
/// the duration of the call.
unsafe fn cstr_to_str<'a>(ptr: *const c_char) -> Option<&'a str> {
    if ptr.is_null() {
        return None;
    }
    // SAFETY: caller guarantees NUL termination and lifetime.
    let cs = unsafe { CStr::from_ptr(ptr) };
    cs.to_str().ok()
}

/// Connect to `host:port`, run version-exchange and KEX, and return a client
/// handle ready for authentication.
///
/// Uses [`HostKeyPolicy::AcceptAny`] (insecure — TOFU is the caller's
/// responsibility). A future revision may expose a fingerprint-pinned variant.
///
/// On success returns [`PCSSH_OK`] and writes a non-NULL pointer into `*out`.
/// On error returns a negative code; `*out` is set to NULL.
///
/// # Safety
///
/// - `host` must be NUL-terminated, valid UTF-8.
/// - `out` must be non-NULL and point to writable storage for one
///   `*mut PcSshClient`.
#[no_mangle]
pub unsafe extern "C" fn pcssh_client_connect(
    host: *const c_char,
    port: u16,
    timeout_ms: i32,
    out: *mut *mut PcSshClient,
) -> c_int {
    let result = catch_unwind(AssertUnwindSafe(|| {
        if out.is_null() {
            return PCSSH_ERR_INVALID_ARGUMENT;
        }
        // SAFETY: caller guarantees `out` is writable.
        unsafe { *out = ptr::null_mut() };

        // SAFETY: caller upholds the contract on `host`.
        let host_str = match unsafe { cstr_to_str(host) } {
            Some(s) => s,
            None => return PCSSH_ERR_INVALID_ARGUMENT,
        };

        let addr = format!("{host_str}:{port}");
        let addrs = match addr.to_socket_addrs() {
            Ok(a) => a,
            Err(_) => return PCSSH_ERR_CONNECT,
        };

        let timeout = if timeout_ms > 0 {
            Some(Duration::from_millis(timeout_ms as u64))
        } else {
            None
        };

        let mut last_err: Option<Error> = None;
        for sa in addrs {
            let cfg = Config {
                host_key_policy: HostKeyPolicy::AcceptAny,
                timeout,
            };
            match Client::connect(sa, cfg) {
                Ok(c) => {
                    let boxed = Box::new(PcSshClient { inner: c });
                    // SAFETY: `out` is non-NULL and writable per caller contract.
                    unsafe { *out = Box::into_raw(boxed) };
                    return PCSSH_OK;
                }
                Err(e) => last_err = Some(e),
            }
        }

        match last_err {
            Some(Error::Io(_)) => PCSSH_ERR_CONNECT,
            Some(e) => map_error(&e),
            None => PCSSH_ERR_CONNECT,
        }
    }));
    match result {
        Ok(code) => code,
        Err(_) => PCSSH_ERR_PANIC,
    }
}

/// Authenticate using a password.
///
/// # Safety
///
/// `client`, `user`, `password` must all be non-NULL. `user` and `password`
/// must be NUL-terminated, valid UTF-8.
#[no_mangle]
pub unsafe extern "C" fn pcssh_client_auth_password(
    client: *mut PcSshClient,
    user: *const c_char,
    password: *const c_char,
) -> c_int {
    let result = catch_unwind(AssertUnwindSafe(|| {
        if client.is_null() {
            return PCSSH_ERR_INVALID_ARGUMENT;
        }
        // SAFETY: caller upholds NUL termination + UTF-8.
        let user_s = match unsafe { cstr_to_str(user) } {
            Some(s) => s,
            None => return PCSSH_ERR_INVALID_ARGUMENT,
        };
        // SAFETY: caller upholds NUL termination + UTF-8.
        let pass_s = match unsafe { cstr_to_str(password) } {
            Some(s) => s,
            None => return PCSSH_ERR_INVALID_ARGUMENT,
        };
        // SAFETY: `client` is a non-NULL pointer we returned from
        // `pcssh_client_connect`; the caller has not freed it.
        let c = unsafe { &mut *client };
        match c.inner.authenticate_password(user_s, pass_s) {
            Ok(()) => PCSSH_OK,
            Err(e) => map_error(&e),
        }
    }));
    match result {
        Ok(code) => code,
        Err(_) => PCSSH_ERR_PANIC,
    }
}

/// Authenticate using a private key (openssh-key-v1 PEM).
///
/// `private_key_pem` is treated as a byte slice of `private_key_pem_len`
/// bytes (NOT NUL-scanned, so embedded NULs and binary base64 are safe).
/// The bytes must be valid UTF-8 PEM text.
///
/// `passphrase` is optional; pass NULL for an unencrypted key. An empty
/// string is treated the same as NULL.
///
/// # Safety
///
/// - `client` must be a valid handle returned from `pcssh_client_connect`.
/// - `user` must be NUL-terminated valid UTF-8.
/// - `private_key_pem` must point to at least `private_key_pem_len` bytes.
/// - `passphrase`, if non-NULL, must be NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn pcssh_client_auth_publickey(
    client: *mut PcSshClient,
    user: *const c_char,
    private_key_pem: *const c_char,
    private_key_pem_len: usize,
    passphrase: *const c_char,
) -> c_int {
    let result = catch_unwind(AssertUnwindSafe(|| {
        if client.is_null() || private_key_pem.is_null() {
            return PCSSH_ERR_INVALID_ARGUMENT;
        }
        // SAFETY: caller contract.
        let user_s = match unsafe { cstr_to_str(user) } {
            Some(s) => s,
            None => return PCSSH_ERR_INVALID_ARGUMENT,
        };

        // SAFETY: caller guarantees at least `private_key_pem_len` readable bytes.
        let pem_bytes =
            unsafe { slice::from_raw_parts(private_key_pem as *const u8, private_key_pem_len) };
        let pem_str = match core::str::from_utf8(pem_bytes) {
            Ok(s) => s,
            Err(_) => return PCSSH_ERR_INVALID_ARGUMENT,
        };

        // Passphrase: NULL → None; empty C string → None; otherwise bytes
        // up to NUL.
        let passphrase_opt: Option<Vec<u8>> = if passphrase.is_null() {
            None
        } else {
            // SAFETY: caller contract: NUL-terminated.
            let cs = unsafe { CStr::from_ptr(passphrase) };
            let bytes = cs.to_bytes();
            if bytes.is_empty() {
                None
            } else {
                Some(bytes.to_vec())
            }
        };

        let priv_key = match PrivateKey::parse_openssh_pem(pem_str, passphrase_opt.as_deref()) {
            Ok(k) => k,
            Err(e) => return map_error(&e),
        };
        let hk = match priv_key.into_host_key() {
            Ok(h) => h,
            Err(e) => return map_error(&e),
        };

        // SAFETY: caller-supplied valid handle.
        let c = unsafe { &mut *client };
        match c
            .inner
            .authenticate(user_s, vec![ClientCredential::PublicKey(hk)])
        {
            Ok(()) => PCSSH_OK,
            Err(e) => map_error(&e),
        }
    }));
    match result {
        Ok(code) => code,
        Err(_) => PCSSH_ERR_PANIC,
    }
}

/// Execute a remote command, draining stdout/stderr into caller buffers.
///
/// On success returns [`PCSSH_OK`] and writes the actual lengths to
/// `*stdout_out_len` and `*stderr_out_len`, and the exit status (or `-1` if
/// the server did not report one) to `*exit_status_out`.
///
/// If either buffer is too small, returns [`PCSSH_ERR_BUFFER_TOO_SMALL`] and
/// writes the *required* sizes to the corresponding `*_out_len`. The caller
/// can then resize and retry — though note that the command has already
/// completed; the exec is not re-executed on retry.
///
/// # Safety
///
/// - `client` must be a valid handle.
/// - `command` must be NUL-terminated valid UTF-8.
/// - `stdout_buf` / `stderr_buf` may be NULL only if the matching capacity
///   is 0; otherwise they must point to at least `*_cap` writable bytes.
/// - All `_out` pointers must be non-NULL and writable.
#[allow(clippy::too_many_arguments)]
#[no_mangle]
pub unsafe extern "C" fn pcssh_client_exec(
    client: *mut PcSshClient,
    command: *const c_char,
    stdout_buf: *mut u8,
    stdout_cap: usize,
    stdout_out_len: *mut usize,
    stderr_buf: *mut u8,
    stderr_cap: usize,
    stderr_out_len: *mut usize,
    exit_status_out: *mut i32,
) -> c_int {
    let result = catch_unwind(AssertUnwindSafe(|| {
        if client.is_null()
            || stdout_out_len.is_null()
            || stderr_out_len.is_null()
            || exit_status_out.is_null()
        {
            return PCSSH_ERR_INVALID_ARGUMENT;
        }
        if (stdout_buf.is_null() && stdout_cap != 0) || (stderr_buf.is_null() && stderr_cap != 0) {
            return PCSSH_ERR_INVALID_ARGUMENT;
        }

        // SAFETY: caller contract.
        let cmd_s = match unsafe { cstr_to_str(command) } {
            Some(s) => s,
            None => return PCSSH_ERR_INVALID_ARGUMENT,
        };

        // SAFETY: valid handle, exclusive mutable use.
        let c = unsafe { &mut *client };
        let out = match c.inner.exec(cmd_s) {
            Ok(o) => o,
            Err(e) => return map_error(&e),
        };

        let need_out = out.stdout.len();
        let need_err = out.stderr.len();
        // SAFETY: out-pointers checked non-NULL above.
        unsafe {
            *stdout_out_len = need_out;
            *stderr_out_len = need_err;
            *exit_status_out = out.exit_status.map(|v| v as i32).unwrap_or(-1);
        }

        if need_out > stdout_cap || need_err > stderr_cap {
            return PCSSH_ERR_BUFFER_TOO_SMALL;
        }

        if need_out > 0 {
            // SAFETY: stdout_buf has at least `stdout_cap` >= need_out bytes.
            unsafe {
                ptr::copy_nonoverlapping(out.stdout.as_ptr(), stdout_buf, need_out);
            }
        }
        if need_err > 0 {
            // SAFETY: stderr_buf has at least `stderr_cap` >= need_err bytes.
            unsafe {
                ptr::copy_nonoverlapping(out.stderr.as_ptr(), stderr_buf, need_err);
            }
        }
        PCSSH_OK
    }));
    match result {
        Ok(code) => code,
        Err(_) => PCSSH_ERR_PANIC,
    }
}

/// Free a client handle. Safe to call with NULL.
///
/// After this call the pointer is invalid; the caller must not use it again.
///
/// # Safety
///
/// `client` must either be NULL, or a pointer previously returned by
/// `pcssh_client_connect` that has not already been freed.
#[no_mangle]
pub unsafe extern "C" fn pcssh_client_free(client: *mut PcSshClient) {
    if client.is_null() {
        return;
    }
    let _ = catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: pointer originally produced by `Box::into_raw` in
        // `pcssh_client_connect`. Caller guarantees no double-free.
        let boxed = unsafe { Box::from_raw(client) };
        drop(boxed);
    }));
}

/// Return a static, NUL-terminated description for a non-success error code.
///
/// Returns NULL for codes the library does not recognise. The returned pointer
/// is owned by the library and must not be freed.
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
    use std::ffi::CString;

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
    fn free_null_is_safe() {
        // SAFETY: NULL is the documented safe input.
        unsafe { pcssh_client_free(ptr::null_mut()) };
    }

    #[test]
    fn connect_rejects_null_out() {
        let host = CString::new("127.0.0.1").unwrap();
        // SAFETY: passing NULL for `out` is the contract being exercised.
        let rc = unsafe { pcssh_client_connect(host.as_ptr(), 22, 100, ptr::null_mut()) };
        assert_eq!(rc, PCSSH_ERR_INVALID_ARGUMENT);
    }

    #[test]
    fn connect_rejects_null_host() {
        let mut out: *mut PcSshClient = ptr::null_mut();
        // SAFETY: NULL host is the contract being exercised.
        let rc = unsafe { pcssh_client_connect(ptr::null(), 22, 100, &mut out) };
        assert_eq!(rc, PCSSH_ERR_INVALID_ARGUMENT);
        assert!(out.is_null());
    }

    #[test]
    fn connect_to_unbound_port_fails() {
        // Port 0 means "ephemeral" to the OS — connecting to it deterministically
        // refuses. Use a high port that's unlikely to be bound either way.
        let host = CString::new("127.0.0.1").unwrap();
        let mut out: *mut PcSshClient = ptr::null_mut();
        // SAFETY: well-formed inputs.
        let rc = unsafe { pcssh_client_connect(host.as_ptr(), 1, 500, &mut out) };
        assert!(rc < 0, "expected failure, got {rc}");
        assert!(out.is_null());
    }
}
