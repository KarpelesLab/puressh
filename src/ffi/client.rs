//! C ABI for the high-level SSH client: connect, authenticate, exec,
//! free.
//!
//! The Rust-side handle [`PcSshClient`] wraps a [`SharedClient`] rather
//! than the raw [`Client`] so subsequent FFI modules (SFTP, etc.) can
//! open multiple concurrent channels on the same connection. Cost: every
//! method-call entry point grabs the shared mutex via `with_client` for
//! the duration of one Rust call, which is the same exclusion the
//! borrow-checker enforced on `&mut Client`.
//!
//! No public ABI change vs. the pre-split `src/ffi.rs`. C consumers
//! continue to see the same function names, signatures, and error
//! semantics.

use core::ffi::{c_char, c_int};
use core::ptr;
use std::ffi::CStr;
use std::net::ToSocketAddrs;
use std::slice;
use std::time::Duration;

use super::common::{
    catch, cstr_to_str, map_error, PCSSH_ERR_BUFFER_TOO_SMALL, PCSSH_ERR_CONNECT,
    PCSSH_ERR_INVALID_ARGUMENT, PCSSH_OK,
};
use crate::auth::ClientCredential;
use crate::client::{Client, Config, HostKeyPolicy};
use crate::error::Error;
use crate::key::PrivateKey;
use crate::shared::SharedClient;

/// Opaque handle to a connected SSH client.
///
/// Allocated by [`pcssh_client_connect`], freed by [`pcssh_client_free`].
/// Internally a [`SharedClient`] (Arc-clonable, multi-channel ready);
/// the C side treats it as an opaque pointer.
pub struct PcSshClient {
    pub(crate) inner: SharedClient,
}

/// Connect to `host:port`, run version-exchange and KEX, and return a
/// client handle ready for authentication.
///
/// Uses [`HostKeyPolicy::AcceptAny`] (insecure — TOFU is the caller's
/// responsibility). A future revision may expose a fingerprint-pinned
/// variant.
///
/// On success returns [`PCSSH_OK`] and writes a non-NULL pointer into
/// `*out`. On error returns a negative code; `*out` is set to NULL.
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
    catch(|| {
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
                    let boxed = Box::new(PcSshClient {
                        inner: SharedClient::from(c),
                    });
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
    })
}

/// Authenticate using a password.
///
/// # Safety
///
/// `client`, `user`, `password` must all be non-NULL. `user` and
/// `password` must be NUL-terminated, valid UTF-8.
#[no_mangle]
pub unsafe extern "C" fn pcssh_client_auth_password(
    client: *mut PcSshClient,
    user: *const c_char,
    password: *const c_char,
) -> c_int {
    catch(|| {
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
        let c = unsafe { &*client };
        match c
            .inner
            .with_client(|cl| cl.authenticate_password(user_s, pass_s))
        {
            Ok(()) => PCSSH_OK,
            Err(e) => map_error(&e),
        }
    })
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
    catch(|| {
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
        let c = unsafe { &*client };
        match c
            .inner
            .with_client(|cl| cl.authenticate(user_s, vec![ClientCredential::PublicKey(hk)]))
        {
            Ok(()) => PCSSH_OK,
            Err(e) => map_error(&e),
        }
    })
}

/// Execute a remote command, draining stdout/stderr into caller buffers.
///
/// On success returns [`PCSSH_OK`] and writes the actual lengths to
/// `*stdout_out_len` and `*stderr_out_len`, and the exit status (or `-1`
/// if the server did not report one) to `*exit_status_out`.
///
/// If either buffer is too small, returns [`PCSSH_ERR_BUFFER_TOO_SMALL`]
/// and writes the *required* sizes to the corresponding `*_out_len`. The
/// caller can then resize and retry — though note that the command has
/// already completed; the exec is not re-executed on retry.
///
/// # Safety
///
/// - `client` must be a valid handle.
/// - `command` must be NUL-terminated valid UTF-8.
/// - `stdout_buf` / `stderr_buf` may be NULL only if the matching
///   capacity is 0; otherwise they must point to at least `*_cap`
///   writable bytes.
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
    catch(|| {
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

        // SAFETY: valid handle.
        let c = unsafe { &*client };
        let out = match c.inner.with_client(|cl| cl.exec(cmd_s)) {
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
    })
}

/// Free a client handle. Safe to call with NULL.
///
/// After this call the pointer is invalid; the caller must not use it
/// again.
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
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        // SAFETY: pointer originally produced by `Box::into_raw` in
        // `pcssh_client_connect`. Caller guarantees no double-free.
        let boxed = unsafe { Box::from_raw(client) };
        drop(boxed);
    }));
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;

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
        // Port 1 is unlikely to be bound; connect should fail without hanging.
        let host = CString::new("127.0.0.1").unwrap();
        let mut out: *mut PcSshClient = ptr::null_mut();
        // SAFETY: well-formed inputs.
        let rc = unsafe { pcssh_client_connect(host.as_ptr(), 1, 500, &mut out) };
        assert!(rc < 0, "expected failure, got {rc}");
        assert!(out.is_null());
    }
}
