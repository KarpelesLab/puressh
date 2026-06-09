//! C ABI for the `KnownHosts` store: build, persist, lookup, mutate,
//! plus a `pcssh_client_connect_known_hosts` policy variant that
//! verifies the server host key against the store on connect.
//!
//! The Rust-side handle [`PcSshKnownHosts`] wraps the store in
//! `Arc<Mutex<KnownHosts>>` so a single FFI handle can both be operated
//! on through `pcssh_known_hosts_*` and be plugged into a connect-time
//! [`HostKeyPolicy::KnownHosts`] policy simultaneously (the lib's
//! [`KnownHostsPolicy::store`] field is also `Arc<Mutex<KnownHosts>>`).
//!
//! Every entry point grabs the mutex for the duration of one Rust call.
//! Concurrent use from multiple OS threads is safe; they serialise.

use core::ffi::{c_char, c_int};
use core::ptr;
use std::ffi::c_void;
use std::path::PathBuf;
use std::slice;
use std::sync::{Arc, Mutex};

use super::client::PcSshClient;
use super::common::{
    catch, map_error, with_cstr, with_two_cstr, PCSSH_ERR_BUFFER_TOO_SMALL, PCSSH_ERR_CONNECT,
    PCSSH_ERR_GENERIC, PCSSH_ERR_INVALID_ARGUMENT, PCSSH_ERR_IO, PCSSH_OK,
};
use crate::client::{Client, Config, HostKeyPolicy, KnownHostsPolicy, TofuAction};
use crate::error::Error;
use crate::known_hosts::{KnownHosts, LookupResult};
use crate::shared::SharedClient;

/// Lookup-result variant returned by [`pcssh_known_hosts_lookup`]: an
/// exact host+key match was found.
pub const PCSSH_KH_MATCH: c_int = 0;
/// Lookup-result variant: at least one entry matched the host, but no
/// entry's key matched. This is the security-relevant case — refuse the
/// connection.
pub const PCSSH_KH_MISMATCH: c_int = 1;
/// Lookup-result variant: no entry matched the host. The caller decides
/// whether to TOFU-add.
pub const PCSSH_KH_UNKNOWN: c_int = 2;

/// TOFU action: refuse the connection (equivalent to OpenSSH's
/// `StrictHostKeyChecking=yes`).
pub const PCSSH_TOFU_REJECT: c_int = 0;
/// TOFU action: accept silently and (optionally) save back.
pub const PCSSH_TOFU_ACCEPT: c_int = 1;
/// TOFU action: invoke the C callback to decide.
pub const PCSSH_TOFU_PROMPT: c_int = 2;

/// Opaque handle to an in-memory `known_hosts` store.
///
/// Internally backed by `Arc<Mutex<KnownHosts>>` so the same handle can
/// be plugged into [`pcssh_client_connect_known_hosts`] and continue to
/// receive `pcssh_known_hosts_*` mutations afterwards.
pub struct PcSshKnownHosts {
    pub(crate) inner: Arc<Mutex<KnownHosts>>,
}

/// TOFU prompt callback signature for
/// [`pcssh_client_connect_known_hosts`].
///
/// Invoked when the connecting host is unknown to the store and
/// `on_unknown == PCSSH_TOFU_PROMPT`. Return `1` to accept (and the
/// callback is expected to have shown the user the fingerprint), `0` to
/// reject.
///
/// Arguments mirror the underlying [`crate::client::TofuPromptFn`]:
/// host, port, algorithm name, key blob.
pub type PcSshTofuPromptCb = Option<
    unsafe extern "C" fn(
        ctx: *mut c_void,
        host: *const c_char,
        port: u16,
        algorithm: *const c_char,
        key_blob: *const u8,
        key_blob_len: usize,
    ) -> c_int,
>;

/// Allocate an empty `known_hosts` store.
///
/// # Safety
///
/// `out` must be non-NULL and point to writable storage for one
/// `*mut PcSshKnownHosts`.
#[no_mangle]
pub unsafe extern "C" fn pcssh_known_hosts_new(out: *mut *mut PcSshKnownHosts) -> c_int {
    catch(|| {
        if out.is_null() {
            return PCSSH_ERR_INVALID_ARGUMENT;
        }
        // SAFETY: `out` non-NULL per caller contract. Zero up-front so
        // the post-condition "on error, `*out` is NULL" holds for any
        // future error path added between here and the success write.
        unsafe { *out = ptr::null_mut() };
        let kh = PcSshKnownHosts {
            inner: Arc::new(Mutex::new(KnownHosts::new())),
        };
        // SAFETY: `out` non-NULL per caller contract.
        unsafe { *out = Box::into_raw(Box::new(kh)) };
        PCSSH_OK
    })
}

/// Load an OpenSSH-format `known_hosts` file. A missing file yields an
/// empty store (matches OpenSSH client behaviour).
///
/// # Safety
///
/// - `path` must be NUL-terminated, valid UTF-8.
/// - `out` must be non-NULL.
#[no_mangle]
pub unsafe extern "C" fn pcssh_known_hosts_load(
    path: *const c_char,
    out: *mut *mut PcSshKnownHosts,
) -> c_int {
    catch(|| {
        if out.is_null() {
            return PCSSH_ERR_INVALID_ARGUMENT;
        }
        // SAFETY: caller contract.
        unsafe { *out = ptr::null_mut() };
        // SAFETY: caller contract.
        with_cstr(path, |path_s| {
            let kh = match KnownHosts::load(path_s) {
                Ok(k) => k,
                Err(_) => return PCSSH_ERR_IO,
            };
            let boxed = PcSshKnownHosts {
                inner: Arc::new(Mutex::new(kh)),
            };
            // SAFETY: out non-NULL.
            unsafe { *out = Box::into_raw(Box::new(boxed)) };
            PCSSH_OK
        })
        .unwrap_or(PCSSH_ERR_INVALID_ARGUMENT)
    })
}

/// Atomically save the store to `path` (writes `path.tmp` then
/// renames).
///
/// # Safety
///
/// - `kh` must be a valid handle returned by `pcssh_known_hosts_*`.
/// - `path` must be NUL-terminated, valid UTF-8.
#[no_mangle]
pub unsafe extern "C" fn pcssh_known_hosts_save(
    kh: *const PcSshKnownHosts,
    path: *const c_char,
) -> c_int {
    catch(|| {
        if kh.is_null() {
            return PCSSH_ERR_INVALID_ARGUMENT;
        }
        // SAFETY: caller contract.
        with_cstr(path, |path_s| {
            // SAFETY: kh non-NULL per check.
            let h = unsafe { &*kh };
            let g = match h.inner.lock() {
                Ok(g) => g,
                Err(_) => return PCSSH_ERR_GENERIC,
            };
            match g.save(path_s) {
                Ok(()) => PCSSH_OK,
                Err(_) => PCSSH_ERR_IO,
            }
        })
        .unwrap_or(PCSSH_ERR_INVALID_ARGUMENT)
    })
}

/// Parse a `known_hosts` file from a byte buffer.
///
/// # Safety
///
/// - `buf` must point to at least `len` readable bytes.
/// - `out` must be non-NULL.
#[no_mangle]
pub unsafe extern "C" fn pcssh_known_hosts_from_bytes(
    buf: *const u8,
    len: usize,
    out: *mut *mut PcSshKnownHosts,
) -> c_int {
    catch(|| {
        if out.is_null() || (buf.is_null() && len != 0) {
            return PCSSH_ERR_INVALID_ARGUMENT;
        }
        // SAFETY: out non-NULL per check. Zero up-front so the
        // post-condition "on error, `*out` is NULL" stays correct as
        // future error paths are added between here and the success
        // write — matches the convention used by other constructors
        // (`pcssh_known_hosts_load`, `pcssh_agent_connect`, …).
        unsafe { *out = ptr::null_mut() };
        // SAFETY: caller contract; len=0 is empty slice.
        let bytes = if len == 0 {
            &[][..]
        } else {
            unsafe { slice::from_raw_parts(buf, len) }
        };
        let kh = KnownHosts::from_bytes(bytes);
        let boxed = PcSshKnownHosts {
            inner: Arc::new(Mutex::new(kh)),
        };
        // SAFETY: out non-NULL.
        unsafe { *out = Box::into_raw(Box::new(boxed)) };
        PCSSH_OK
    })
}

/// Serialise the store to a caller-supplied buffer. Writes the required
/// length to `*out_len`; if `cap < required`, returns
/// [`PCSSH_ERR_BUFFER_TOO_SMALL`] (the length still being written so the
/// caller can resize).
///
/// # Safety
///
/// - `kh` must be a valid handle.
/// - `buf` may be NULL only if `cap == 0`.
/// - `out_len` must be non-NULL.
#[no_mangle]
pub unsafe extern "C" fn pcssh_known_hosts_to_bytes(
    kh: *const PcSshKnownHosts,
    buf: *mut u8,
    cap: usize,
    out_len: *mut usize,
) -> c_int {
    catch(|| {
        if kh.is_null() || out_len.is_null() || (buf.is_null() && cap != 0) {
            return PCSSH_ERR_INVALID_ARGUMENT;
        }
        // SAFETY: kh non-NULL.
        let h = unsafe { &*kh };
        let g = match h.inner.lock() {
            Ok(g) => g,
            Err(_) => return PCSSH_ERR_GENERIC,
        };
        let data = g.to_bytes();
        let need = data.len();
        // SAFETY: out_len non-NULL.
        unsafe { *out_len = need };
        if need > cap {
            return PCSSH_ERR_BUFFER_TOO_SMALL;
        }
        if need > 0 {
            // SAFETY: cap >= need bytes writable at buf.
            unsafe { ptr::copy_nonoverlapping(data.as_ptr(), buf, need) };
        }
        PCSSH_OK
    })
}

/// Look up `(host, port, algorithm, key_blob)` in the store. The result
/// variant is written to `*out_result` (one of `PCSSH_KH_MATCH`,
/// `PCSSH_KH_MISMATCH`, `PCSSH_KH_UNKNOWN`).
///
/// `Mismatch` does not surface the list of expected keys through this
/// API; an enriched `pcssh_known_hosts_find` returning the expected
/// keys is deferred to a future revision.
///
/// # Safety
///
/// - `kh` must be a valid handle.
/// - `host`, `algorithm` must be NUL-terminated valid UTF-8.
/// - `key_blob` must point to at least `key_blob_len` readable bytes.
/// - `out_result` must be non-NULL.
#[allow(clippy::too_many_arguments)]
#[no_mangle]
pub unsafe extern "C" fn pcssh_known_hosts_lookup(
    kh: *const PcSshKnownHosts,
    host: *const c_char,
    port: u16,
    algorithm: *const c_char,
    key_blob: *const u8,
    key_blob_len: usize,
    out_result: *mut c_int,
) -> c_int {
    catch(|| {
        if kh.is_null() || out_result.is_null() {
            return PCSSH_ERR_INVALID_ARGUMENT;
        }
        if key_blob.is_null() && key_blob_len != 0 {
            return PCSSH_ERR_INVALID_ARGUMENT;
        }
        // SAFETY: caller contract for both strings.
        with_two_cstr(host, algorithm, |host_s, alg_s| {
            // SAFETY: caller contract; len=0 yields empty slice.
            let blob = if key_blob_len == 0 {
                &[][..]
            } else {
                unsafe { slice::from_raw_parts(key_blob, key_blob_len) }
            };
            // SAFETY: kh non-NULL.
            let h = unsafe { &*kh };
            let g = match h.inner.lock() {
                Ok(g) => g,
                Err(_) => return PCSSH_ERR_GENERIC,
            };
            let r = match g.lookup(host_s, port, alg_s, blob) {
                LookupResult::Match => PCSSH_KH_MATCH,
                LookupResult::Mismatch { .. } => PCSSH_KH_MISMATCH,
                LookupResult::Unknown => PCSSH_KH_UNKNOWN,
            };
            // SAFETY: out_result non-NULL.
            unsafe { *out_result = r };
            PCSSH_OK
        })
        .unwrap_or(PCSSH_ERR_INVALID_ARGUMENT)
    })
}

/// Append a new entry. If `hash_host != 0`, the host pattern is stored
/// as an HMAC-SHA1 hash (OpenSSH's `HashKnownHosts yes`).
///
/// # Safety
///
/// - `kh` must be a valid handle.
/// - `host`, `algorithm` must be NUL-terminated valid UTF-8.
/// - `key_blob` must point to at least `key_blob_len` readable bytes.
#[allow(clippy::too_many_arguments)]
#[no_mangle]
pub unsafe extern "C" fn pcssh_known_hosts_add(
    kh: *mut PcSshKnownHosts,
    host: *const c_char,
    port: u16,
    algorithm: *const c_char,
    key_blob: *const u8,
    key_blob_len: usize,
    hash_host: c_int,
) -> c_int {
    catch(|| {
        if kh.is_null() {
            return PCSSH_ERR_INVALID_ARGUMENT;
        }
        if key_blob.is_null() && key_blob_len != 0 {
            return PCSSH_ERR_INVALID_ARGUMENT;
        }
        // SAFETY: caller contract for both strings.
        with_two_cstr(host, algorithm, |host_s, alg_s| {
            // SAFETY: caller contract; len=0 → empty.
            let blob = if key_blob_len == 0 {
                &[][..]
            } else {
                unsafe { slice::from_raw_parts(key_blob, key_blob_len) }
            };
            // SAFETY: kh non-NULL.
            let h = unsafe { &*kh };
            let mut g = match h.inner.lock() {
                Ok(g) => g,
                Err(_) => return PCSSH_ERR_GENERIC,
            };
            g.add(host_s, port, alg_s, blob, hash_host != 0);
            PCSSH_OK
        })
        .unwrap_or(PCSSH_ERR_INVALID_ARGUMENT)
    })
}

/// Remove every entry matching `host[:port]`. Writes the count to
/// `*out_removed` if non-NULL.
///
/// # Safety
///
/// - `kh` must be a valid handle.
/// - `host` must be NUL-terminated valid UTF-8.
#[no_mangle]
pub unsafe extern "C" fn pcssh_known_hosts_remove(
    kh: *mut PcSshKnownHosts,
    host: *const c_char,
    port: u16,
    out_removed: *mut usize,
) -> c_int {
    catch(|| {
        if kh.is_null() {
            return PCSSH_ERR_INVALID_ARGUMENT;
        }
        // SAFETY: caller contract.
        with_cstr(host, |host_s| {
            // SAFETY: kh non-NULL.
            let h = unsafe { &*kh };
            let mut g = match h.inner.lock() {
                Ok(g) => g,
                Err(_) => return PCSSH_ERR_GENERIC,
            };
            let n = g.remove(host_s, port);
            if !out_removed.is_null() {
                // SAFETY: caller contract.
                unsafe { *out_removed = n };
            }
            PCSSH_OK
        })
        .unwrap_or(PCSSH_ERR_INVALID_ARGUMENT)
    })
}

/// Hash every plain entry in the store using a fresh salt — the
/// equivalent of `ssh-keygen -H`.
///
/// # Safety
///
/// `kh` must be a valid handle.
#[no_mangle]
pub unsafe extern "C" fn pcssh_known_hosts_hash_in_place(kh: *mut PcSshKnownHosts) -> c_int {
    catch(|| {
        if kh.is_null() {
            return PCSSH_ERR_INVALID_ARGUMENT;
        }
        // SAFETY: kh non-NULL.
        let h = unsafe { &*kh };
        let mut g = match h.inner.lock() {
            Ok(g) => g,
            Err(_) => return PCSSH_ERR_GENERIC,
        };
        g.hash_in_place();
        PCSSH_OK
    })
}

/// Free a `known_hosts` handle. Safe to call with NULL.
///
/// # Safety
///
/// `kh` must either be NULL, or a pointer previously returned by a
/// `pcssh_known_hosts_*` constructor that has not been freed.
#[no_mangle]
pub unsafe extern "C" fn pcssh_known_hosts_free(kh: *mut PcSshKnownHosts) {
    if kh.is_null() {
        return;
    }
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        // SAFETY: pointer originally from Box::into_raw, caller no double-free.
        let _ = unsafe { Box::from_raw(kh) };
    }));
}

/// Connect to `host:port`, run version-exchange + KEX with a
/// [`HostKeyPolicy::KnownHosts`] policy backed by `kh`.
///
/// `on_unknown` is one of `PCSSH_TOFU_REJECT`, `PCSSH_TOFU_ACCEPT`, or
/// `PCSSH_TOFU_PROMPT`. With `PROMPT`, `prompt_cb` is invoked; with
/// `ACCEPT` and a non-NULL `save_path`, the new entry is also persisted
/// back. `hash_new != 0` requests that newly added entries be hashed.
///
/// Mismatch is always a hard reject (host known, wrong key).
///
/// # Safety
///
/// - `host` (and `save_path` if non-NULL) must be NUL-terminated valid
///   UTF-8.
/// - `kh` must be a valid handle.
/// - `out_client` must be non-NULL.
#[allow(clippy::too_many_arguments)]
#[no_mangle]
pub unsafe extern "C" fn pcssh_client_connect_known_hosts(
    host: *const c_char,
    port: u16,
    timeout_ms: i32,
    kh: *mut PcSshKnownHosts,
    on_unknown: c_int,
    prompt_cb: PcSshTofuPromptCb,
    prompt_ctx: *mut c_void,
    save_path: *const c_char,
    hash_new: c_int,
    out_client: *mut *mut PcSshClient,
) -> c_int {
    catch(|| {
        if out_client.is_null() {
            return PCSSH_ERR_INVALID_ARGUMENT;
        }
        // SAFETY: caller contract.
        unsafe { *out_client = ptr::null_mut() };
        if kh.is_null() {
            return PCSSH_ERR_INVALID_ARGUMENT;
        }
        // Optional save_path: NULL keeps None; non-NULL must be valid UTF-8
        // (the previous code returned PCSSH_ERR_INVALID_ARGUMENT on
        // non-UTF-8, matching what `with_cstr` reports via `None`).
        let save_path_opt: Option<PathBuf> = if save_path.is_null() {
            None
        } else {
            // SAFETY: caller contract.
            match with_cstr(save_path, |s| PathBuf::from(s)) {
                Some(p) => Some(p),
                None => return PCSSH_ERR_INVALID_ARGUMENT,
            }
        };

        // SAFETY: caller contract on `host`.
        with_cstr(host, |host_s| {
            let timeout = if timeout_ms > 0 {
                Some(std::time::Duration::from_millis(timeout_ms as u64))
            } else {
                None
            };

            // Build TofuAction from the C side.
            let on_unknown = match on_unknown {
                PCSSH_TOFU_REJECT => TofuAction::Reject,
                PCSSH_TOFU_ACCEPT => TofuAction::Accept,
                PCSSH_TOFU_PROMPT => match prompt_cb {
                    Some(cb) => {
                        // Capture the raw pointer as an integer so the closure
                        // is Send + Sync. The caller promises the context is
                        // live for the duration of the connect.
                        let ctx_addr = prompt_ctx as usize;
                        TofuAction::Prompt(Arc::new(
                            move |host: &str, port: u16, alg: &str, blob: &[u8]| -> bool {
                                let h_cs = match std::ffi::CString::new(host) {
                                    Ok(c) => c,
                                    Err(_) => return false,
                                };
                                let a_cs = match std::ffi::CString::new(alg) {
                                    Ok(c) => c,
                                    Err(_) => return false,
                                };
                                // SAFETY: function pointer validity + lifetime
                                // upheld by the C caller per docs.
                                let rc = unsafe {
                                    cb(
                                        ctx_addr as *mut c_void,
                                        h_cs.as_ptr(),
                                        port,
                                        a_cs.as_ptr(),
                                        blob.as_ptr(),
                                        blob.len(),
                                    )
                                };
                                rc != 0
                            },
                        ))
                    }
                    None => return PCSSH_ERR_INVALID_ARGUMENT,
                },
                _ => return PCSSH_ERR_INVALID_ARGUMENT,
            };

            // SAFETY: kh non-NULL.
            let kh_handle = unsafe { &*kh };
            let store = Arc::clone(&kh_handle.inner);

            let policy = KnownHostsPolicy {
                store,
                save_path: save_path_opt,
                hash_new: hash_new != 0,
                on_unknown,
                // FFI callers that want loud-but-permissive mismatch can
                // upgrade to a future pcssh_client_connect_known_hosts_ex
                // taking an on_mismatch action; the default here matches
                // OpenSSH's `StrictHostKeyChecking=yes` for mismatches.
                on_mismatch: TofuAction::Reject,
            };

            let cfg = Config {
                host_key_policy: HostKeyPolicy::KnownHosts(policy),
                timeout,
            };

            match Client::connect_to_host(host_s, port, cfg) {
                Ok(c) => {
                    let boxed = Box::new(PcSshClient {
                        inner: SharedClient::from(c),
                    });
                    // SAFETY: out_client non-NULL.
                    unsafe { *out_client = Box::into_raw(boxed) };
                    PCSSH_OK
                }
                Err(Error::Io(_)) => PCSSH_ERR_CONNECT,
                Err(e) => map_error(&e),
            }
        })
        .unwrap_or(PCSSH_ERR_INVALID_ARGUMENT)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;

    #[test]
    fn free_null_is_safe() {
        // SAFETY: NULL is the documented safe input.
        unsafe { pcssh_known_hosts_free(ptr::null_mut()) };
    }

    #[test]
    fn new_then_free() {
        let mut h: *mut PcSshKnownHosts = ptr::null_mut();
        // SAFETY: well-formed inputs.
        let rc = unsafe { pcssh_known_hosts_new(&mut h) };
        assert_eq!(rc, PCSSH_OK);
        assert!(!h.is_null());
        // SAFETY: handle returned from pcssh_known_hosts_new.
        unsafe { pcssh_known_hosts_free(h) };
    }

    #[test]
    fn lookup_empty_is_unknown() {
        let mut h: *mut PcSshKnownHosts = ptr::null_mut();
        // SAFETY: well-formed inputs.
        unsafe { pcssh_known_hosts_new(&mut h) };
        let host = CString::new("example.com").unwrap();
        let alg = CString::new("ssh-ed25519").unwrap();
        let blob = [1u8, 2, 3];
        let mut r: c_int = -1;
        // SAFETY: well-formed inputs.
        let rc = unsafe {
            pcssh_known_hosts_lookup(
                h,
                host.as_ptr(),
                22,
                alg.as_ptr(),
                blob.as_ptr(),
                blob.len(),
                &mut r,
            )
        };
        assert_eq!(rc, PCSSH_OK);
        assert_eq!(r, PCSSH_KH_UNKNOWN);
        // SAFETY: handle from new.
        unsafe { pcssh_known_hosts_free(h) };
    }

    #[test]
    fn add_then_lookup_matches() {
        let mut h: *mut PcSshKnownHosts = ptr::null_mut();
        // SAFETY: well-formed inputs.
        unsafe { pcssh_known_hosts_new(&mut h) };
        let host = CString::new("example.com").unwrap();
        let alg = CString::new("ssh-ed25519").unwrap();
        let blob = [9u8, 8, 7, 6];
        // SAFETY: handle valid, strings NUL-terminated.
        let rc = unsafe {
            pcssh_known_hosts_add(
                h,
                host.as_ptr(),
                22,
                alg.as_ptr(),
                blob.as_ptr(),
                blob.len(),
                0,
            )
        };
        assert_eq!(rc, PCSSH_OK);
        let mut r: c_int = -1;
        // SAFETY: handle valid.
        let rc = unsafe {
            pcssh_known_hosts_lookup(
                h,
                host.as_ptr(),
                22,
                alg.as_ptr(),
                blob.as_ptr(),
                blob.len(),
                &mut r,
            )
        };
        assert_eq!(rc, PCSSH_OK);
        assert_eq!(r, PCSSH_KH_MATCH);
        // SAFETY: handle valid.
        unsafe { pcssh_known_hosts_free(h) };
    }

    #[test]
    fn add_wrong_key_is_mismatch() {
        let mut h: *mut PcSshKnownHosts = ptr::null_mut();
        // SAFETY: well-formed inputs.
        unsafe { pcssh_known_hosts_new(&mut h) };
        let host = CString::new("example.com").unwrap();
        let alg = CString::new("ssh-ed25519").unwrap();
        let blob_good = [1u8, 2, 3];
        let blob_bad = [4u8, 5, 6];
        // SAFETY: handle valid.
        unsafe {
            pcssh_known_hosts_add(
                h,
                host.as_ptr(),
                22,
                alg.as_ptr(),
                blob_good.as_ptr(),
                blob_good.len(),
                0,
            )
        };
        let mut r: c_int = -1;
        // SAFETY: handle valid.
        unsafe {
            pcssh_known_hosts_lookup(
                h,
                host.as_ptr(),
                22,
                alg.as_ptr(),
                blob_bad.as_ptr(),
                blob_bad.len(),
                &mut r,
            )
        };
        assert_eq!(r, PCSSH_KH_MISMATCH);
        // SAFETY: handle valid.
        unsafe { pcssh_known_hosts_free(h) };
    }

    #[test]
    fn to_bytes_then_from_bytes_roundtrip() {
        let mut h: *mut PcSshKnownHosts = ptr::null_mut();
        // SAFETY: well-formed.
        unsafe { pcssh_known_hosts_new(&mut h) };
        let host = CString::new("a.example").unwrap();
        let alg = CString::new("ssh-ed25519").unwrap();
        let blob = [1u8, 2, 3, 4];
        // SAFETY: handle valid.
        unsafe {
            pcssh_known_hosts_add(
                h,
                host.as_ptr(),
                22,
                alg.as_ptr(),
                blob.as_ptr(),
                blob.len(),
                0,
            )
        };
        // Two-pass: query size, then write.
        let mut need: usize = 0;
        // SAFETY: handle valid, cap=0 + buf=null is documented.
        let rc = unsafe { pcssh_known_hosts_to_bytes(h, ptr::null_mut(), 0, &mut need) };
        assert_eq!(rc, PCSSH_ERR_BUFFER_TOO_SMALL);
        assert!(need > 0);
        let mut buf = vec![0u8; need];
        let mut got: usize = 0;
        // SAFETY: handle valid, buf has need bytes.
        let rc = unsafe { pcssh_known_hosts_to_bytes(h, buf.as_mut_ptr(), buf.len(), &mut got) };
        assert_eq!(rc, PCSSH_OK);
        assert_eq!(got, need);

        // Parse back.
        let mut h2: *mut PcSshKnownHosts = ptr::null_mut();
        // SAFETY: buf has `got` readable bytes.
        let rc = unsafe { pcssh_known_hosts_from_bytes(buf.as_ptr(), got, &mut h2) };
        assert_eq!(rc, PCSSH_OK);
        let mut r: c_int = -1;
        // SAFETY: h2 valid.
        unsafe {
            pcssh_known_hosts_lookup(
                h2,
                host.as_ptr(),
                22,
                alg.as_ptr(),
                blob.as_ptr(),
                blob.len(),
                &mut r,
            )
        };
        assert_eq!(r, PCSSH_KH_MATCH);
        // SAFETY: handles valid.
        unsafe {
            pcssh_known_hosts_free(h);
            pcssh_known_hosts_free(h2);
        };
    }

    #[test]
    fn remove_then_lookup_unknown() {
        let mut h: *mut PcSshKnownHosts = ptr::null_mut();
        // SAFETY: well-formed.
        unsafe { pcssh_known_hosts_new(&mut h) };
        let host = CString::new("rm.example").unwrap();
        let alg = CString::new("ssh-ed25519").unwrap();
        let blob = [7u8; 8];
        // SAFETY: handle valid.
        unsafe {
            pcssh_known_hosts_add(
                h,
                host.as_ptr(),
                22,
                alg.as_ptr(),
                blob.as_ptr(),
                blob.len(),
                0,
            )
        };
        let mut n: usize = 0;
        // SAFETY: handle valid.
        let rc = unsafe { pcssh_known_hosts_remove(h, host.as_ptr(), 22, &mut n) };
        assert_eq!(rc, PCSSH_OK);
        assert_eq!(n, 1);
        let mut r: c_int = -1;
        // SAFETY: handle valid.
        unsafe {
            pcssh_known_hosts_lookup(
                h,
                host.as_ptr(),
                22,
                alg.as_ptr(),
                blob.as_ptr(),
                blob.len(),
                &mut r,
            )
        };
        assert_eq!(r, PCSSH_KH_UNKNOWN);
        // SAFETY: handle valid.
        unsafe { pcssh_known_hosts_free(h) };
    }
}
