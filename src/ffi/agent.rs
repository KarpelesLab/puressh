//! C ABI for the ssh-agent client. **Unix only** — mirrors the
//! `cfg(unix)` gate on [`crate::agent`].
//!
//! Surface: connect (path or `$SSH_AUTH_SOCK`), enumerate identities,
//! sign data with a chosen identity, free.
//!
//! Identity listing is cached inside the [`PcSshAgent`] handle: the
//! first `pcssh_agent_identity_count` call performs the wire round-trip
//! and caches the result; subsequent `pcssh_agent_identity(i)` calls
//! just index into the cached vector. Re-invoke
//! `pcssh_agent_refresh_identities` to drop the cache and re-query.

#![cfg(unix)]

use core::ffi::{c_char, c_int};
use core::ptr;
use std::slice;
use std::sync::Mutex;

use super::common::{
    catch, map_error, with_cstr, PCSSH_ERR_BUFFER_TOO_SMALL, PCSSH_ERR_GENERIC,
    PCSSH_ERR_INVALID_ARGUMENT, PCSSH_OK,
};
use crate::agent::{Agent, AgentIdentity};

/// Agent-sign flag: legacy SSH-RSA SHA1 (default).
pub const PCSSH_AGENT_SIGN_DEFAULT: u32 = 0;
/// Agent-sign flag: request `rsa-sha2-256` signature (RFC 8332).
pub const PCSSH_AGENT_RSA_SHA2_256: u32 = 2;
/// Agent-sign flag: request `rsa-sha2-512` signature (RFC 8332).
pub const PCSSH_AGENT_RSA_SHA2_512: u32 = 4;

/// Opaque handle to a connected ssh-agent.
///
/// Holds the underlying [`Agent`] plus a cached identity vector built
/// lazily on the first call to [`pcssh_agent_identity_count`].
///
/// Thread-safety: this handle is intended to be shareable between C
/// threads (it is `Send + Sync` because the interior `Agent` is owned
/// behind a `Mutex`). Concurrent calls from multiple threads serialize
/// at the `Mutex`; without it, two threads calling `pcssh_agent_sign`
/// on the same handle would race on the underlying Unix socket and
/// interleave request/reply frames. We surface a poisoned mutex as
/// `PCSSH_ERR_GENERIC` — the underlying socket is now in an unknown
/// state and the caller should free the handle and reconnect.
pub struct PcSshAgent {
    inner: Mutex<Agent>,
    /// Cached identities; `None` until populated. Behind the same mutex
    /// as `inner` so cache reads and refreshes can't interleave with an
    /// in-flight sign on another thread.
    identities: Mutex<Option<Vec<AgentIdentity>>>,
}

/// Connect to an ssh-agent at the Unix socket `path`.
///
/// # Safety
///
/// - `path` must be NUL-terminated, valid UTF-8.
/// - `out` must be non-NULL.
#[no_mangle]
pub unsafe extern "C" fn pcssh_agent_connect(
    path: *const c_char,
    out: *mut *mut PcSshAgent,
) -> c_int {
    catch(|| {
        if out.is_null() {
            return PCSSH_ERR_INVALID_ARGUMENT;
        }
        // SAFETY: caller contract.
        unsafe { *out = ptr::null_mut() };
        // SAFETY: caller contract.
        with_cstr(path, |path_s| match Agent::connect(path_s) {
            Ok(agent) => {
                let boxed = Box::new(PcSshAgent {
                    inner: Mutex::new(agent),
                    identities: Mutex::new(None),
                });
                // SAFETY: out non-NULL.
                unsafe { *out = Box::into_raw(boxed) };
                PCSSH_OK
            }
            Err(e) => map_error(&e),
        })
        .unwrap_or(PCSSH_ERR_INVALID_ARGUMENT)
    })
}

/// Connect using `$SSH_AUTH_SOCK`. If the env var is unset or empty,
/// returns [`PCSSH_OK`] with `*out` set to NULL (caller treats that as
/// "no agent available" rather than an error).
///
/// # Safety
///
/// `out` must be non-NULL.
#[no_mangle]
pub unsafe extern "C" fn pcssh_agent_connect_env(out: *mut *mut PcSshAgent) -> c_int {
    catch(|| {
        if out.is_null() {
            return PCSSH_ERR_INVALID_ARGUMENT;
        }
        // SAFETY: caller contract.
        unsafe { *out = ptr::null_mut() };
        match Agent::connect_env() {
            Ok(None) => PCSSH_OK, // *out stays NULL
            Ok(Some(agent)) => {
                let boxed = Box::new(PcSshAgent {
                    inner: Mutex::new(agent),
                    identities: Mutex::new(None),
                });
                // SAFETY: out non-NULL.
                unsafe { *out = Box::into_raw(boxed) };
                PCSSH_OK
            }
            Err(e) => map_error(&e),
        }
    })
}

/// Populate the identity cache from the agent and write the resulting
/// count to `*out_count`. Subsequent
/// [`pcssh_agent_identity`] calls index into the cached vector.
///
/// # Safety
///
/// - `agent` must be a valid handle.
/// - `out_count` must be non-NULL.
#[no_mangle]
pub unsafe extern "C" fn pcssh_agent_identity_count(
    agent: *mut PcSshAgent,
    out_count: *mut usize,
) -> c_int {
    catch(|| {
        if agent.is_null() || out_count.is_null() {
            return PCSSH_ERR_INVALID_ARGUMENT;
        }
        // SAFETY: agent non-NULL per check; handle is `Sync` and lives
        // for the call so a shared reference is sound.
        let a = unsafe { &*agent };
        let mut ids_guard = match a.identities.lock() {
            Ok(g) => g,
            Err(_) => return PCSSH_ERR_GENERIC,
        };
        if ids_guard.is_none() {
            // Hold the cache lock while we round-trip — otherwise two
            // threads could each push a list. The inner socket lock is
            // taken separately and dropped before we return so a parallel
            // `sign()` is only blocked for one wire RTT.
            let mut inner = match a.inner.lock() {
                Ok(g) => g,
                Err(_) => return PCSSH_ERR_GENERIC,
            };
            match inner.identities() {
                Ok(ids) => *ids_guard = Some(ids),
                Err(e) => return map_error(&e),
            }
        }
        // SAFETY: out_count non-NULL.
        unsafe { *out_count = ids_guard.as_ref().map(|v| v.len()).unwrap_or(0) };
        PCSSH_OK
    })
}

/// Drop the cached identity list. The next
/// [`pcssh_agent_identity_count`] call will re-query the agent. Useful
/// if a long-lived caller wants to see keys added with `ssh-add` after
/// the agent handle was first used.
///
/// # Safety
///
/// `agent` must be a valid handle.
#[no_mangle]
pub unsafe extern "C" fn pcssh_agent_refresh_identities(agent: *mut PcSshAgent) -> c_int {
    catch(|| {
        if agent.is_null() {
            return PCSSH_ERR_INVALID_ARGUMENT;
        }
        // SAFETY: agent non-NULL per check.
        let a = unsafe { &*agent };
        let mut g = match a.identities.lock() {
            Ok(g) => g,
            Err(_) => return PCSSH_ERR_GENERIC,
        };
        *g = None;
        PCSSH_OK
    })
}

/// Read identity at `index` from the cached identity list.
///
/// Two-pass buffer pattern: pass NULL buffers with capacity 0 to query
/// the required lengths. On `PCSSH_ERR_BUFFER_TOO_SMALL`, `*_len` are
/// the required sizes.
///
/// `pcssh_agent_identity_count` must be called first to populate the
/// cache (otherwise this returns `PCSSH_ERR_GENERIC`).
///
/// # Safety
///
/// - `agent` must be a valid handle.
/// - Each `_buf` may be NULL only if its `_cap` is 0.
/// - Each `_len` must be non-NULL.
#[allow(clippy::too_many_arguments)]
#[no_mangle]
pub unsafe extern "C" fn pcssh_agent_identity(
    agent: *mut PcSshAgent,
    index: usize,
    algorithm_buf: *mut u8,
    algorithm_cap: usize,
    algorithm_len: *mut usize,
    comment_buf: *mut u8,
    comment_cap: usize,
    comment_len: *mut usize,
    key_blob_buf: *mut u8,
    key_blob_cap: usize,
    key_blob_len: *mut usize,
) -> c_int {
    catch(|| {
        if agent.is_null()
            || algorithm_len.is_null()
            || comment_len.is_null()
            || key_blob_len.is_null()
        {
            return PCSSH_ERR_INVALID_ARGUMENT;
        }
        if (algorithm_buf.is_null() && algorithm_cap != 0)
            || (comment_buf.is_null() && comment_cap != 0)
            || (key_blob_buf.is_null() && key_blob_cap != 0)
        {
            return PCSSH_ERR_INVALID_ARGUMENT;
        }
        // SAFETY: agent non-NULL.
        let a = unsafe { &*agent };
        let ids_guard = match a.identities.lock() {
            Ok(g) => g,
            Err(_) => return PCSSH_ERR_GENERIC,
        };
        let ids = match ids_guard.as_ref() {
            Some(v) => v,
            None => return PCSSH_ERR_GENERIC,
        };
        let id = match ids.get(index) {
            Some(id) => id,
            None => return PCSSH_ERR_INVALID_ARGUMENT,
        };
        let alg = id.algorithm();
        let alg_bytes = alg.as_bytes();
        let comment = id.comment().as_bytes();
        let blob = id.key_blob();

        let need_alg = alg_bytes.len();
        let need_comment = comment.len();
        let need_blob = blob.len();
        // SAFETY: out-len pointers non-NULL per check.
        unsafe {
            *algorithm_len = need_alg;
            *comment_len = need_comment;
            *key_blob_len = need_blob;
        }
        if need_alg > algorithm_cap || need_comment > comment_cap || need_blob > key_blob_cap {
            return PCSSH_ERR_BUFFER_TOO_SMALL;
        }
        if need_alg > 0 {
            // SAFETY: cap >= need bytes writable.
            unsafe { ptr::copy_nonoverlapping(alg_bytes.as_ptr(), algorithm_buf, need_alg) };
        }
        if need_comment > 0 {
            // SAFETY: cap >= need bytes writable.
            unsafe { ptr::copy_nonoverlapping(comment.as_ptr(), comment_buf, need_comment) };
        }
        if need_blob > 0 {
            // SAFETY: cap >= need bytes writable.
            unsafe { ptr::copy_nonoverlapping(blob.as_ptr(), key_blob_buf, need_blob) };
        }
        PCSSH_OK
    })
}

/// Ask the agent to sign `data` under the identity whose public key
/// blob equals `key_blob`.
///
/// `flags` is one of `PCSSH_AGENT_SIGN_DEFAULT`,
/// `PCSSH_AGENT_RSA_SHA2_256`, `PCSSH_AGENT_RSA_SHA2_512`. The
/// returned signature is SSH wire-format `string algorithm || string
/// raw_sig`.
///
/// Two-pass buffer pattern: see [`pcssh_agent_identity`].
///
/// # Safety
///
/// - `agent` must be a valid handle.
/// - `key_blob`, `data` must point to at least `*_len` bytes (or be
///   NULL if the corresponding length is 0).
/// - `sig_buf` may be NULL only if `sig_cap` is 0.
/// - `sig_len` must be non-NULL.
#[allow(clippy::too_many_arguments)]
#[no_mangle]
pub unsafe extern "C" fn pcssh_agent_sign(
    agent: *mut PcSshAgent,
    key_blob: *const u8,
    key_blob_len: usize,
    data: *const u8,
    data_len: usize,
    flags: u32,
    sig_buf: *mut u8,
    sig_cap: usize,
    sig_len: *mut usize,
) -> c_int {
    catch(|| {
        if agent.is_null() || sig_len.is_null() {
            return PCSSH_ERR_INVALID_ARGUMENT;
        }
        if (key_blob.is_null() && key_blob_len != 0)
            || (data.is_null() && data_len != 0)
            || (sig_buf.is_null() && sig_cap != 0)
        {
            return PCSSH_ERR_INVALID_ARGUMENT;
        }
        // SAFETY: caller contract; len=0 → empty.
        let key_slice = if key_blob_len == 0 {
            &[][..]
        } else {
            unsafe { slice::from_raw_parts(key_blob, key_blob_len) }
        };
        // SAFETY: caller contract; len=0 → empty.
        let data_slice = if data_len == 0 {
            &[][..]
        } else {
            unsafe { slice::from_raw_parts(data, data_len) }
        };

        // SAFETY: agent non-NULL.
        let a = unsafe { &*agent };
        let mut inner = match a.inner.lock() {
            Ok(g) => g,
            Err(_) => return PCSSH_ERR_GENERIC,
        };
        let sig = match inner.sign(key_slice, data_slice, flags) {
            Ok(s) => s,
            Err(e) => return map_error(&e),
        };
        drop(inner);
        let need = sig.len();
        // SAFETY: sig_len non-NULL.
        unsafe { *sig_len = need };
        if need > sig_cap {
            return PCSSH_ERR_BUFFER_TOO_SMALL;
        }
        if need > 0 {
            // SAFETY: cap >= need writable.
            unsafe { ptr::copy_nonoverlapping(sig.as_ptr(), sig_buf, need) };
        }
        PCSSH_OK
    })
}

/// Free an agent handle. Safe to call with NULL.
///
/// # Safety
///
/// `agent` must either be NULL or a pointer previously returned by a
/// `pcssh_agent_*` constructor that has not been freed.
#[no_mangle]
pub unsafe extern "C" fn pcssh_agent_free(agent: *mut PcSshAgent) {
    if agent.is_null() {
        return;
    }
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        // SAFETY: pointer from Box::into_raw, no double-free per caller.
        let _ = unsafe { Box::from_raw(agent) };
    }));
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;

    #[test]
    fn free_null_is_safe() {
        // SAFETY: NULL is the documented safe input.
        unsafe { pcssh_agent_free(ptr::null_mut()) };
    }

    #[test]
    fn connect_rejects_null_out() {
        let p = CString::new("/nonexistent/socket").unwrap();
        // SAFETY: NULL out is the contract being exercised.
        let rc = unsafe { pcssh_agent_connect(p.as_ptr(), ptr::null_mut()) };
        assert_eq!(rc, PCSSH_ERR_INVALID_ARGUMENT);
    }

    #[test]
    fn connect_to_missing_socket_fails() {
        // Path that definitely won't exist.
        let p = CString::new("/nonexistent/puressh-agent-test-socket").unwrap();
        let mut out: *mut PcSshAgent = ptr::null_mut();
        // SAFETY: well-formed inputs.
        let rc = unsafe { pcssh_agent_connect(p.as_ptr(), &mut out) };
        assert!(rc < 0, "expected failure, got {rc}");
        assert!(out.is_null());
    }

    #[test]
    fn connect_env_unset_returns_ok_null() {
        // Stash and clear SSH_AUTH_SOCK so connect_env hits the "unset"
        // path deterministically.
        let prev = std::env::var_os("SSH_AUTH_SOCK");
        // SAFETY: single-threaded test; std::env::remove_var is the
        // documented way to clear.
        unsafe { std::env::remove_var("SSH_AUTH_SOCK") };
        let mut out: *mut PcSshAgent = ptr::null_mut();
        // SAFETY: well-formed inputs.
        let rc = unsafe { pcssh_agent_connect_env(&mut out) };
        assert_eq!(rc, PCSSH_OK);
        assert!(out.is_null());
        if let Some(v) = prev {
            // SAFETY: restoring the original env var.
            unsafe { std::env::set_var("SSH_AUTH_SOCK", v) };
        }
    }
}
