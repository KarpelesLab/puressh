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
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::slice;
use std::time::Duration;
use zeroize::Zeroizing;

use super::common::{
    PCSSH_ERR_BUFFER_TOO_SMALL, PCSSH_ERR_CONNECT, PCSSH_ERR_INVALID_ARGUMENT, PCSSH_OK, catch,
    map_error, slice_len_ok, with_cstr,
};
use crate::auth::ClientCredential;
use crate::client::{Client, Config, HostKeyPolicy};
use crate::error::Error;
use crate::key::PrivateKey;
use crate::shared::SharedClient;

// ---------------------------------------------------------------------------
// Host-key policy enum (for `pcssh_client_connect_ex`)
// ---------------------------------------------------------------------------

/// `pcssh_client_connect_ex` policy: accept any host key the server
/// presents. **Insecure** — equivalent to `StrictHostKeyChecking=no`
/// with no known-hosts file. Use only when the caller will pin the
/// fingerprint themselves out-of-band, or in tests against ephemeral
/// loopback servers.
pub const PCSSH_HOSTKEY_POLICY_ACCEPT_ANY: c_int = 0;

/// `pcssh_client_connect_ex` policy: accept only host keys whose
/// SHA-256 fingerprint matches the base64 string (no `SHA256:` prefix,
/// no `=` padding — `ssh-keygen -lf` format) supplied via the
/// `fingerprint_b64` argument.
pub const PCSSH_HOSTKEY_POLICY_ACCEPT_FINGERPRINT: c_int = 1;

/// `pcssh_client_connect_ex` policy: defer to a `PcSshKnownHosts` store.
/// **Not implemented in `_ex`** — use [`super::known_hosts::
/// pcssh_client_connect_known_hosts`] instead, which accepts the store
/// handle and per-call TOFU thresholds.
pub const PCSSH_HOSTKEY_POLICY_KNOWN_HOSTS: c_int = 2;

/// Opaque handle to a connected SSH client.
///
/// Allocated by [`pcssh_client_connect`], freed by [`pcssh_client_free`].
/// Internally a [`SharedClient`] (Arc-clonable, multi-channel ready);
/// the C side treats it as an opaque pointer.
pub struct PcSshClient {
    pub(crate) inner: SharedClient,
}

/// Translate the C-side `timeout_ms` into the library's optional
/// [`Duration`]. `timeout_ms <= 0` means "no timeout" — documented in
/// `include/puressh.h` for every connect entry point.
pub(crate) fn timeout_from_ms(timeout_ms: i32) -> Option<Duration> {
    if timeout_ms > 0 {
        Some(Duration::from_millis(timeout_ms as u64))
    } else {
        None
    }
}

/// Open a TCP connection to `sa`, bounding the connect itself by
/// `timeout` when one is given, then apply the same read/write timeout
/// so every later socket operation (banner, KEX, auth, channel I/O) is
/// bounded too. Mirrors what [`Client::connect`] does after its own
/// unbounded `TcpStream::connect`.
fn tcp_connect(sa: SocketAddr, timeout: Option<Duration>) -> std::io::Result<TcpStream> {
    let stream = match timeout {
        Some(t) => TcpStream::connect_timeout(&sa, t)?,
        None => TcpStream::connect(sa)?,
    };
    if timeout.is_some() {
        stream.set_read_timeout(timeout)?;
        stream.set_write_timeout(timeout)?;
    }
    stream.set_nodelay(true)?;
    Ok(stream)
}

/// Accept `[::1]`-style bracketed IPv6 literals as well as bare ones so
/// every FFI connect entry point takes the same host spellings. The
/// stripped form is what `(host, port)` resolution and `known_hosts`
/// lookups expect.
fn strip_ipv6_brackets(host: &str) -> &str {
    host.strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host)
}

/// Shared connect path for every FFI `pcssh_client_connect*` entry
/// point: resolve `host:port`, try each address in turn, run the SSH
/// handshake over the first TCP connection that succeeds.
///
/// Two security properties live here:
///
/// - **`timeout` bounds the whole connect.** The TCP connect uses
///   [`TcpStream::connect_timeout`] and the socket's read/write timeouts
///   are set *before* the stream is handed to [`Client::connect_via`],
///   so the version exchange and KEX are bounded too. (Name resolution
///   goes through the system resolver and is not bounded — see the
///   header.)
/// - **A non-I/O failure ends the attempt.** Only a TCP connect failure
///   or an [`Error::Io`] during the handshake moves on to the next
///   resolved address. A host-key rejection, KEX/protocol error, etc. is
///   returned immediately so the client never talks to a second peer
///   after refusing the first one (and the caller sees the real reason
///   rather than a later address's `PCSSH_ERR_CONNECT`).
///
/// `make_cfg` is called once per address because [`Config`] is not
/// `Clone` (the `KnownHosts` policy variant holds `Arc`s the caller can
/// re-clone cheaply).
///
/// Returns the mapped C error code on failure.
pub(crate) fn connect_bounded(
    host: &str,
    port: u16,
    timeout: Option<Duration>,
    mut make_cfg: impl FnMut() -> Config,
) -> Result<Client, c_int> {
    let host = strip_ipv6_brackets(host);
    let addrs = match (host, port).to_socket_addrs() {
        Ok(a) => a,
        Err(_) => return Err(PCSSH_ERR_CONNECT),
    };
    for sa in addrs {
        let stream = match tcp_connect(sa, timeout) {
            Ok(s) => s,
            // TCP-level failure (refused, unreachable, connect timeout):
            // the next address is fair game.
            Err(_) => continue,
        };
        match Client::connect_via(Box::new(stream), host, port, make_cfg()) {
            Ok(c) => return Ok(c),
            // The peer closed / reset / timed out mid-handshake. Keep
            // the historical `PCSSH_ERR_CONNECT` mapping and try the
            // next address.
            Err(Error::Io(_)) => continue,
            // Anything else (host key rejected, no common algorithm,
            // protocol violation, ...) is final.
            Err(e) => return Err(map_error(&e)),
        }
    }
    Err(PCSSH_ERR_CONNECT)
}

/// Connect to `host:port` with an explicit host-key policy.
///
/// `timeout_ms > 0` bounds the TCP connect and every subsequent socket
/// read/write (so the handshake cannot hang on a silent peer);
/// `timeout_ms <= 0` means no timeout at all. Name resolution is not
/// bounded. `host` may be a hostname, an IPv4 literal, or an IPv6
/// literal with or without surrounding brackets (`::1` and `[::1]` are
/// equivalent).
///
/// Resolution may yield several addresses; they are tried in order,
/// moving on only after a TCP-level or I/O failure. A host-key
/// rejection (or any other non-I/O error) on one address ends the
/// attempt immediately and is reported as-is — see the private
/// `connect_bounded` helper for the exact rule.
///
/// `policy` is one of `PCSSH_HOSTKEY_POLICY_*`:
///
///  - `PCSSH_HOSTKEY_POLICY_ACCEPT_ANY`: accept whatever the server
///    presents. Insecure; `fingerprint_b64` is ignored.
///  - `PCSSH_HOSTKEY_POLICY_ACCEPT_FINGERPRINT`: `fingerprint_b64` must
///    be a NUL-terminated, base64 (no padding, no `SHA256:` prefix)
///    SHA-256 fingerprint of the server's host key in the same format
///    `ssh-keygen -lf` prints. Mismatch ⇒ `PCSSH_ERR_HOSTKEY_REJECTED`.
///  - `PCSSH_HOSTKEY_POLICY_KNOWN_HOSTS`: not supported from this
///    function — call [`super::known_hosts::pcssh_client_connect_known_hosts`]
///    instead. Returns `PCSSH_ERR_CONFIG` when supplied.
///
/// Finding #1 (Critical): the original `pcssh_client_connect` hardcoded
/// AcceptAny with no opt-out. New callers should use this function and
/// pass an explicit policy.
///
/// # Safety
///
/// - `host` must be NUL-terminated, valid UTF-8.
/// - `out` must be non-NULL and point to writable storage for one
///   `*mut PcSshClient`.
/// - `fingerprint_b64`, when policy is `ACCEPT_FINGERPRINT`, must be
///   NUL-terminated.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pcssh_client_connect_ex(
    host: *const c_char,
    port: u16,
    timeout_ms: i32,
    policy: c_int,
    fingerprint_b64: *const c_char,
    out: *mut *mut PcSshClient,
) -> c_int {
    catch(|| {
        if out.is_null() {
            return PCSSH_ERR_INVALID_ARGUMENT;
        }
        // SAFETY: caller guarantees `out` is writable.
        unsafe { *out = ptr::null_mut() };

        // SAFETY: caller upholds the contract on `host`.
        with_cstr(host, |host_str| {
            // Resolve the policy enum into a `HostKeyPolicy` before opening
            // a socket so a misconfigured caller fails fast.
            let host_key_policy = match policy {
                PCSSH_HOSTKEY_POLICY_ACCEPT_ANY => HostKeyPolicy::AcceptAny,
                PCSSH_HOSTKEY_POLICY_ACCEPT_FINGERPRINT => {
                    if fingerprint_b64.is_null() {
                        return super::common::PCSSH_ERR_CONFIG;
                    }
                    // SAFETY: caller contract: NUL-terminated.
                    let fp_outcome = with_cstr(fingerprint_b64, |fp_str| {
                        // Normalize: strip a "SHA256:" prefix if present, and trim any
                        // padding `=` so callers can pass either ssh-keygen's display
                        // form or raw base64.
                        let trimmed = fp_str
                            .strip_prefix("SHA256:")
                            .unwrap_or(fp_str)
                            .trim_end_matches('=');
                        let raw = match crate::key::base64::decode(trimmed.as_bytes()) {
                            Ok(v) => v,
                            Err(_) => return Err(super::common::PCSSH_ERR_CONFIG),
                        };
                        if raw.len() != 32 {
                            return Err(super::common::PCSSH_ERR_CONFIG);
                        }
                        let mut fp = [0u8; 32];
                        fp.copy_from_slice(&raw);
                        Ok(fp)
                    });
                    let fp = match fp_outcome {
                        Some(Ok(fp)) => fp,
                        Some(Err(code)) => return code,
                        None => return PCSSH_ERR_INVALID_ARGUMENT,
                    };
                    HostKeyPolicy::AcceptFingerprint(fp)
                }
                PCSSH_HOSTKEY_POLICY_KNOWN_HOSTS => {
                    // KnownHosts requires a store handle; that path lives in
                    // ffi::known_hosts::pcssh_client_connect_known_hosts.
                    return super::common::PCSSH_ERR_CONFIG;
                }
                _ => return PCSSH_ERR_INVALID_ARGUMENT,
            };

            let timeout = timeout_from_ms(timeout_ms);
            // `Config` / `HostKeyPolicy` are not `Clone`; the two
            // variants reachable here are trivially rebuilt per address.
            let make_cfg = || Config {
                host_key_policy: match &host_key_policy {
                    HostKeyPolicy::AcceptAny => HostKeyPolicy::AcceptAny,
                    HostKeyPolicy::AcceptFingerprint(fp) => HostKeyPolicy::AcceptFingerprint(*fp),
                    HostKeyPolicy::KnownHosts(_) => unreachable!("rejected above"),
                },
                timeout,
                algorithms: Default::default(),
            };
            match connect_bounded(host_str, port, timeout, make_cfg) {
                Ok(c) => {
                    let boxed = Box::new(PcSshClient {
                        inner: SharedClient::from(c),
                    });
                    // SAFETY: `out` is non-NULL and writable per caller contract.
                    unsafe { *out = Box::into_raw(boxed) };
                    PCSSH_OK
                }
                Err(code) => code,
            }
        })
        .unwrap_or(PCSSH_ERR_INVALID_ARGUMENT)
    })
}

/// Connect to `host:port` with [`HostKeyPolicy::AcceptAny`].
///
/// **Deprecated**: this is the insecure shortcut — it accepts whatever
/// host key the server presents, which is equivalent to OpenSSH's
/// `StrictHostKeyChecking=no` with no known-hosts file. Prefer
/// [`pcssh_client_connect_ex`] (explicit policy) or
/// [`super::known_hosts::pcssh_client_connect_known_hosts`] (real TOFU
/// verifier) instead. Kept as a thin shim so existing C callers don't
/// break, and so the insecure choice is searchable by string in code
/// review.
///
/// On success returns [`PCSSH_OK`] and writes a non-NULL pointer into
/// `*out`. On error returns a negative code; `*out` is set to NULL.
///
/// # Safety
///
/// - `host` must be NUL-terminated, valid UTF-8.
/// - `out` must be non-NULL and point to writable storage for one
///   `*mut PcSshClient`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pcssh_client_connect(
    host: *const c_char,
    port: u16,
    timeout_ms: i32,
    out: *mut *mut PcSshClient,
) -> c_int {
    // SAFETY: same contract as `pcssh_client_connect_ex`; we forward
    // unchanged arguments and an empty fingerprint pointer (unused for
    // ACCEPT_ANY).
    unsafe {
        pcssh_client_connect_ex(
            host,
            port,
            timeout_ms,
            PCSSH_HOSTKEY_POLICY_ACCEPT_ANY,
            ptr::null(),
            out,
        )
    }
}

/// Authenticate using a password.
///
/// **Memory note** (Finding #8): the FFI layer itself only borrows the
/// caller's bytes, but the library copies them into a zeroize-on-drop
/// `SecretString` (see [`ClientCredential::Password`]) for the duration
/// of the auth exchange; that copy is wiped when the call returns. The
/// caller remains responsible for wiping the C-side buffer (e.g. with
/// `explicit_bzero(3)`) once this call returns.
///
/// # Safety
///
/// `client`, `user`, `password` must all be non-NULL. `user` and
/// `password` must be NUL-terminated, valid UTF-8.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pcssh_client_auth_password(
    client: *mut PcSshClient,
    user: *const c_char,
    password: *const c_char,
) -> c_int {
    catch(|| {
        if client.is_null() {
            return PCSSH_ERR_INVALID_ARGUMENT;
        }
        // SAFETY: caller upholds NUL termination + UTF-8 for both strings.
        super::common::with_two_cstr(user, password, |user_s, pass_s| {
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
        .unwrap_or(PCSSH_ERR_INVALID_ARGUMENT)
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
/// **Memory note**: the caller owns both the PEM buffer and the
/// passphrase; neither is retained after this call returns. The library
/// keeps its own copies in zeroize-on-drop storage while the key is
/// being parsed and used, but the caller should wipe the C-side buffers
/// themselves (e.g. `explicit_bzero(3)`) once the call returns.
///
/// # Safety
///
/// - `client` must be a valid handle returned from `pcssh_client_connect`.
/// - `user` must be NUL-terminated valid UTF-8.
/// - `private_key_pem` must point to at least `private_key_pem_len` bytes.
/// - `passphrase`, if non-NULL, must be NUL-terminated.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pcssh_client_auth_publickey(
    client: *mut PcSshClient,
    user: *const c_char,
    private_key_pem: *const c_char,
    private_key_pem_len: usize,
    passphrase: *const c_char,
) -> c_int {
    catch(|| {
        if client.is_null() || private_key_pem.is_null() || !slice_len_ok(private_key_pem_len) {
            return PCSSH_ERR_INVALID_ARGUMENT;
        }
        // SAFETY: caller contract.
        with_cstr(user, |user_s| {
            // SAFETY: caller guarantees at least `private_key_pem_len` readable
            // bytes; the length was bounded to `isize::MAX` above.
            let pem_bytes =
                unsafe { slice::from_raw_parts(private_key_pem as *const u8, private_key_pem_len) };
            let pem_str = match core::str::from_utf8(pem_bytes) {
                Ok(s) => s,
                Err(_) => return PCSSH_ERR_INVALID_ARGUMENT,
            };

            // Passphrase: NULL → None; empty C string → None; otherwise bytes
            // up to NUL. Wrapped in `Zeroizing` so the heap copy is wiped on
            // drop even on the error paths below (Finding #8).
            let passphrase_opt: Option<Zeroizing<Vec<u8>>> = if passphrase.is_null() {
                None
            } else {
                // SAFETY: caller contract: NUL-terminated.
                let cs = unsafe { CStr::from_ptr(passphrase) };
                let bytes = cs.to_bytes();
                if bytes.is_empty() {
                    None
                } else {
                    Some(Zeroizing::new(bytes.to_vec()))
                }
            };

            let priv_key = match PrivateKey::parse_openssh_pem(
                pem_str,
                passphrase_opt.as_deref().map(|v| v.as_slice()),
            ) {
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
        .unwrap_or(PCSSH_ERR_INVALID_ARGUMENT)
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
/// On any other error (`PCSSH_ERR_INVALID_ARGUMENT` aside, where the
/// out-pointers may themselves be the invalid argument) the out-params
/// are reset to `0` / `0` / `-1` before the command is attempted, so a
/// caller that ignores the return code never reads stale values.
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
#[unsafe(no_mangle)]
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

        // Reset the out-params up front so an early error leaves them in
        // a defined state (empty output, "no exit status").
        // SAFETY: out-pointers checked non-NULL above.
        unsafe {
            *stdout_out_len = 0;
            *stderr_out_len = 0;
            *exit_status_out = -1;
        }

        // SAFETY: caller contract.
        with_cstr(command, |cmd_s| {
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
                // Saturate the server-reported status into the non-negative
                // i32 range. The header documents -1 as the sole "no status
                // reported" sentinel, but a raw `v as i32` would alias a
                // server status of 0xFFFF_FFFF onto -1 (and any value >=
                // 0x8000_0000 onto an unexpected negative). Clamping to
                // i32::MAX keeps -1 strictly meaning "no status", while
                // still distinguishing a reported status from the sentinel.
                // (A cleaner fix would widen the ABI to u32; we avoid that
                // to preserve the existing C signature.)
                *exit_status_out = out
                    .exit_status
                    .map(|v| v.min(0x7fff_ffff) as i32)
                    .unwrap_or(-1);
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
        .unwrap_or(PCSSH_ERR_INVALID_ARGUMENT)
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
#[unsafe(no_mangle)]
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
    fn timeout_from_ms_nonpositive_means_none() {
        assert_eq!(timeout_from_ms(0), None);
        assert_eq!(timeout_from_ms(-1), None);
        assert_eq!(timeout_from_ms(i32::MIN), None);
        assert_eq!(timeout_from_ms(250), Some(Duration::from_millis(250)));
    }

    #[test]
    fn strip_ipv6_brackets_accepts_both_spellings() {
        assert_eq!(strip_ipv6_brackets("[::1]"), "::1");
        assert_eq!(strip_ipv6_brackets("::1"), "::1");
        assert_eq!(strip_ipv6_brackets("example.com"), "example.com");
        // Unbalanced brackets are left alone for the resolver to reject.
        assert_eq!(strip_ipv6_brackets("[::1"), "[::1");
        assert_eq!(strip_ipv6_brackets("::1]"), "::1]");
    }

    #[test]
    fn connect_ex_bounds_tcp_connect_by_timeout() {
        // A non-routable address (RFC 5737 TEST-NET-1) black-holes the
        // SYN; without `connect_timeout` this would sit in the kernel's
        // retry schedule for a minute or more. Firewalls that answer
        // with RST make it fail even faster, which is fine too.
        let host = CString::new("192.0.2.1").unwrap();
        let mut out: *mut PcSshClient = ptr::null_mut();
        let started = std::time::Instant::now();
        // SAFETY: well-formed inputs.
        let rc = unsafe {
            pcssh_client_connect_ex(
                host.as_ptr(),
                22,
                300,
                PCSSH_HOSTKEY_POLICY_ACCEPT_ANY,
                ptr::null(),
                &mut out,
            )
        };
        assert_eq!(rc, PCSSH_ERR_CONNECT);
        assert!(out.is_null());
        assert!(
            started.elapsed() < Duration::from_secs(10),
            "connect was not bounded by timeout_ms: {:?}",
            started.elapsed()
        );
    }

    #[test]
    fn connect_ex_accepts_bracketed_ipv6_literal() {
        // Both spellings must reach the resolver as `::1`. Port 1 is
        // closed (or IPv6 loopback is absent); either way the outcome is
        // a plain PCSSH_ERR_CONNECT rather than a resolution failure —
        // which is the same code, so assert on the shared path instead:
        // neither spelling may be rejected as an invalid argument.
        for spelling in ["[::1]", "::1"] {
            let host = CString::new(spelling).unwrap();
            let mut out: *mut PcSshClient = ptr::null_mut();
            // SAFETY: well-formed inputs.
            let rc = unsafe {
                pcssh_client_connect_ex(
                    host.as_ptr(),
                    1,
                    300,
                    PCSSH_HOSTKEY_POLICY_ACCEPT_ANY,
                    ptr::null(),
                    &mut out,
                )
            };
            assert_eq!(rc, PCSSH_ERR_CONNECT, "spelling {spelling}");
            assert!(out.is_null());
        }
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
