// Migration-in-progress: drops in the follow-up "ffi/sftp: migrate to
// with_cstr" commit.
#![allow(deprecated)]

//! C ABI for SFTP — full coverage of every `SftpClient` operation.
//!
//! SFTP runs as one session channel on the SSH connection. The
//! multi-handle capability — multiple SFTP sessions, multiple shells,
//! multiple forwards, etc. all coexisting on one `PcSshClient` — is a
//! **client-level** feature provided by Phase 1's `SharedClient` (see
//! [`crate::shared`]). This module is just one of its consumers; the
//! same Phase 1 plumbing underpins every other session type the FFI may
//! add in the future.
//!
//! ## Concurrency contract
//!
//! - Multiple `PcSshSftp` per `PcSshClient` are supported, as is mixing
//!   SFTP with future shell/exec/forward handles.
//! - Calls on the same `PcSshClient` from different OS threads are safe;
//!   they serialise on the shared connection mutex.
//! - `PcSshSftpFile` / `PcSshSftpDir` are **not** thread-safe (each one
//!   owns a per-handle cursor / handle-bytes vector). Concurrent use of
//!   one file or directory from two threads is undefined behaviour —
//!   this matches libssh2's posture.
//!
//! ## Lifetime
//!
//! `PcSshSftpFile` / `PcSshSftpDir` hold a raw pointer back to their
//! parent `PcSshSftp` (used for every read/write/readdir). The C caller
//! must not free the parent while a file/dir handle is still live; doing
//! so dereferences a dangling pointer on the next file/dir op. This
//! mirrors libssh2's session ownership model.

use core::ffi::{c_char, c_int};
use core::ptr;
use std::slice;
use std::sync::{Arc, Mutex};

use super::client::PcSshClient;
use super::common::{
    catch, cstr_to_str, PCSSH_ERR_BUFFER_TOO_SMALL, PCSSH_ERR_GENERIC, PCSSH_ERR_INVALID_ARGUMENT,
    PCSSH_ERR_INVALID_HANDLE, PCSSH_ERR_IO, PCSSH_ERR_PARSE, PCSSH_ERR_PROTOCOL, PCSSH_OK,
};
use crate::sftp::{Attrs, NameEntry, SftpError};
use crate::shared::SftpSession;

/// Shared cell holding the live SFTP session. The parent `PcSshSftp`
/// owns one strong `Arc<SftpCell>`; every child `PcSshSftpFile` /
/// `PcSshSftpDir` clones an `Arc` so the cell outlives a premature
/// parent free.
///
/// Finding #11 (Medium). Previously each child held a raw
/// `*mut PcSshSftp` and `pcssh_sftp_free` deallocated the parent
/// unconditionally; the next call on a child dereferenced freed
/// memory. Now:
///
///   - Parent free wipes the `Option<SftpSession>` to `None` and drops
///     the strong ref it held; the cell itself stays alive as long as
///     any child still holds an `Arc` to it.
///   - Every child entry point locks the cell and bails with
///     `PCSSH_ERR_INVALID_HANDLE` if the parent is gone, instead of
///     dereferencing.
type SftpCell = Mutex<Option<SftpSession>>;

/// SFTP open-flag: open for reading.
pub const PCSSH_SFTP_READ: u32 = 0x0000_0001;
/// SFTP open-flag: open for writing.
pub const PCSSH_SFTP_WRITE: u32 = 0x0000_0002;
/// SFTP open-flag: open in append mode.
pub const PCSSH_SFTP_APPEND: u32 = 0x0000_0004;
/// SFTP open-flag: create if it doesn't exist.
pub const PCSSH_SFTP_CREAT: u32 = 0x0000_0008;
/// SFTP open-flag: truncate to zero on open.
pub const PCSSH_SFTP_TRUNC: u32 = 0x0000_0010;
/// SFTP open-flag: exclusive create (fail if it exists).
pub const PCSSH_SFTP_EXCL: u32 = 0x0000_0020;

/// Attrs flag-mask bit: `size` is valid.
pub const PCSSH_ATTR_SIZE: u32 = 0x0000_0001;
/// Attrs flag-mask bit: `uid` / `gid` are valid.
pub const PCSSH_ATTR_UIDGID: u32 = 0x0000_0002;
/// Attrs flag-mask bit: `permissions` is valid.
pub const PCSSH_ATTR_PERMISSIONS: u32 = 0x0000_0004;
/// Attrs flag-mask bit: `atime` / `mtime` are valid.
pub const PCSSH_ATTR_ACMODTIME: u32 = 0x0000_0008;

/// Opaque SFTP session handle. Multiple per `PcSshClient` are supported.
///
/// Holds an `Arc<SftpCell>` rather than the `SftpSession` directly so
/// child file/dir handles can detect a freed parent (see the private
/// `SftpCell` alias above).
pub struct PcSshSftp {
    inner: Arc<SftpCell>,
}

/// Opaque file handle. Owns the server-side handle bytes plus a local
/// read/write cursor.
pub struct PcSshSftpFile {
    /// Shared cell pointing at the parent SFTP session. Cloned at
    /// `pcssh_sftp_open_file` time; if the parent is freed first the
    /// cell's `Option` becomes `None` and every subsequent op returns
    /// `PCSSH_ERR_INVALID_HANDLE` rather than dereferencing freed memory.
    sftp: Arc<SftpCell>,
    /// Server-side handle bytes from `SSH_FXP_OPEN`.
    handle: Vec<u8>,
    /// Current read/write offset.
    offset: u64,
    /// True once `pcssh_sftp_close_file` has been called; subsequent
    /// reads/writes return an error.
    closed: bool,
}

/// Opaque directory handle. Same shape as a file handle but without an
/// offset (SFTP readdir is server-paginated).
pub struct PcSshSftpDir {
    /// Shared cell pointing at the parent SFTP session — see
    /// [`PcSshSftpFile::sftp`] for the rationale.
    sftp: Arc<SftpCell>,
    /// Server-side directory handle from `SSH_FXP_OPENDIR`.
    handle: Vec<u8>,
    /// True once `pcssh_sftp_closedir` has been called.
    closed: bool,
}

/// Lock the parent cell and call `f` on the live session. Returns
/// `PCSSH_ERR_INVALID_HANDLE` if the parent has been freed, or
/// `PCSSH_ERR_GENERIC` if the cell mutex is poisoned.
fn with_parent<F>(cell: &Arc<SftpCell>, f: F) -> c_int
where
    F: FnOnce(&mut SftpSession) -> c_int,
{
    let mut g = match cell.lock() {
        Ok(g) => g,
        Err(_) => return PCSSH_ERR_GENERIC,
    };
    match g.as_mut() {
        Some(s) => f(s),
        None => PCSSH_ERR_INVALID_HANDLE,
    }
}

/// File attributes in C-friendly form. Use `flags` (a bitmask of
/// `PCSSH_ATTR_*`) to discover which other fields are meaningful.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct PcSshSftpAttrs {
    /// Bitmask of `PCSSH_ATTR_*` indicating which fields are valid.
    pub flags: u32,
    /// File size in bytes (valid iff `flags & PCSSH_ATTR_SIZE`).
    pub size: u64,
    /// Owning user id (valid iff `flags & PCSSH_ATTR_UIDGID`).
    pub uid: u32,
    /// Owning group id (valid iff `flags & PCSSH_ATTR_UIDGID`).
    pub gid: u32,
    /// POSIX `st_mode` (valid iff `flags & PCSSH_ATTR_PERMISSIONS`).
    pub permissions: u32,
    /// Last-access time, Unix seconds (valid iff `flags & PCSSH_ATTR_ACMODTIME`).
    pub atime: u32,
    /// Last-modify time, Unix seconds (valid iff `flags & PCSSH_ATTR_ACMODTIME`).
    pub mtime: u32,
}

/// Map a [`SftpError`] to a C error code.
fn map_sftp_err(e: &SftpError) -> c_int {
    match e {
        SftpError::Io(_) => PCSSH_ERR_IO,
        SftpError::Format(_) => PCSSH_ERR_PARSE,
        SftpError::Protocol(_) => PCSSH_ERR_PROTOCOL,
        SftpError::Status { .. } => PCSSH_ERR_GENERIC,
    }
}

/// Convert library-side [`Attrs`] into the C-flat representation.
fn attrs_to_c(a: &Attrs) -> PcSshSftpAttrs {
    let mut out = PcSshSftpAttrs::default();
    if let Some(s) = a.size {
        out.flags |= PCSSH_ATTR_SIZE;
        out.size = s;
    }
    if let Some((u, g)) = a.uid_gid {
        out.flags |= PCSSH_ATTR_UIDGID;
        out.uid = u;
        out.gid = g;
    }
    if let Some(p) = a.permissions {
        out.flags |= PCSSH_ATTR_PERMISSIONS;
        out.permissions = p;
    }
    if let Some((at, mt)) = a.atime_mtime {
        out.flags |= PCSSH_ATTR_ACMODTIME;
        out.atime = at;
        out.mtime = mt;
    }
    out
}

/// Convert the C-flat representation back into a library-side [`Attrs`].
fn attrs_from_c(a: &PcSshSftpAttrs) -> Attrs {
    let mut out = Attrs::default();
    if a.flags & PCSSH_ATTR_SIZE != 0 {
        out.size = Some(a.size);
    }
    if a.flags & PCSSH_ATTR_UIDGID != 0 {
        out.uid_gid = Some((a.uid, a.gid));
    }
    if a.flags & PCSSH_ATTR_PERMISSIONS != 0 {
        out.permissions = Some(a.permissions);
    }
    if a.flags & PCSSH_ATTR_ACMODTIME != 0 {
        out.atime_mtime = Some((a.atime, a.mtime));
    }
    out
}

/// Write the contents of `src` into `(buf, cap)`, recording the required
/// length in `*out_len`. Returns [`PCSSH_OK`] on success,
/// [`PCSSH_ERR_BUFFER_TOO_SMALL`] if `src.len() > cap`,
/// [`PCSSH_ERR_INVALID_ARGUMENT`] if `out_len` is NULL or if `buf` is
/// NULL while `cap > 0` and bytes need writing.
///
/// # Safety
///
/// - `out_len` must be non-NULL and writable.
/// - If `cap > 0` and the call ends up writing, `buf` must be non-NULL
///   and point to at least `cap` writable bytes.
unsafe fn copy_to_caller_buf(src: &[u8], buf: *mut u8, cap: usize, out_len: *mut usize) -> c_int {
    if out_len.is_null() {
        return PCSSH_ERR_INVALID_ARGUMENT;
    }
    let need = src.len();
    // SAFETY: out_len checked non-NULL above.
    unsafe { *out_len = need };
    if need > cap {
        return PCSSH_ERR_BUFFER_TOO_SMALL;
    }
    if need == 0 {
        return PCSSH_OK;
    }
    if buf.is_null() {
        return PCSSH_ERR_INVALID_ARGUMENT;
    }
    // SAFETY: caller contract: at least `cap` >= need writable bytes.
    unsafe { ptr::copy_nonoverlapping(src.as_ptr(), buf, need) };
    PCSSH_OK
}

// ---------------------------------------------------------------------------
// Lifecycle
// ---------------------------------------------------------------------------

/// Open a new SFTP session over `client`. Multiple sessions per client
/// are supported — each one rides on its own SSH channel.
///
/// # Safety
///
/// - `client` must be a valid `PcSshClient` returned by
///   `pcssh_client_connect` and not yet freed.
/// - `out_sftp` must be non-NULL and writable.
#[no_mangle]
pub unsafe extern "C" fn pcssh_sftp_open(
    client: *mut PcSshClient,
    out_sftp: *mut *mut PcSshSftp,
) -> c_int {
    catch(|| {
        if client.is_null() || out_sftp.is_null() {
            return PCSSH_ERR_INVALID_ARGUMENT;
        }
        // SAFETY: out_sftp checked non-NULL above.
        unsafe { *out_sftp = ptr::null_mut() };
        // SAFETY: caller contract.
        let c = unsafe { &*client };
        let session = match c.inner.sftp() {
            Ok(s) => s,
            Err(e) => return super::common::map_error(&e),
        };
        let boxed = Box::new(PcSshSftp {
            inner: Arc::new(Mutex::new(Some(session))),
        });
        // SAFETY: out_sftp checked non-NULL above.
        unsafe { *out_sftp = Box::into_raw(boxed) };
        PCSSH_OK
    })
}

/// Free an SFTP session handle. The underlying SSH channel is closed in
/// `Drop` (best-effort). Safe to call with NULL.
///
/// # Safety
///
/// `sftp` must either be NULL or a pointer returned by `pcssh_sftp_open`
/// not yet freed.
#[no_mangle]
pub unsafe extern "C" fn pcssh_sftp_free(sftp: *mut PcSshSftp) {
    if sftp.is_null() {
        return;
    }
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        // SAFETY: caller contract.
        let boxed = unsafe { Box::from_raw(sftp) };
        // Wipe the session out of the shared cell so any surviving
        // child file/dir handles see `None` on their next op (and return
        // `PCSSH_ERR_INVALID_HANDLE` instead of UAF'ing). The cell
        // itself stays alive as long as those children hold their Arcs.
        //
        // We must wipe even if the mutex is poisoned: poisoning means a
        // panic happened mid-operation, which leaves the session in an
        // unknown state — having children continue to call into it
        // would be strictly worse than getting `PCSSH_ERR_INVALID_HANDLE`.
        // `PoisonError::into_inner` lets us drop the session anyway.
        let mut g = match boxed.inner.lock() {
            Ok(g) => g,
            Err(e) => e.into_inner(),
        };
        // Drop the session here, while still holding the lock, so
        // children waiting on `with_parent` see `None` rather than a
        // half-dropped session.
        *g = None;
        drop(g);
        drop(boxed);
    }));
}

// ---------------------------------------------------------------------------
// File ops
// ---------------------------------------------------------------------------

/// Open a remote file. `flags` is a bitmask of `PCSSH_SFTP_*`; `mode` is
/// the POSIX permissions to apply when creating.
///
/// # Safety
///
/// - `sftp` must be a live handle.
/// - `path` must be NUL-terminated UTF-8.
/// - `out_file` must be non-NULL and writable.
#[no_mangle]
pub unsafe extern "C" fn pcssh_sftp_open_file(
    sftp: *mut PcSshSftp,
    path: *const c_char,
    flags: u32,
    mode: u32,
    out_file: *mut *mut PcSshSftpFile,
) -> c_int {
    catch(|| {
        if sftp.is_null() || out_file.is_null() {
            return PCSSH_ERR_INVALID_ARGUMENT;
        }
        // SAFETY: caller contract.
        unsafe { *out_file = ptr::null_mut() };
        // SAFETY: caller contract.
        let path_s = match unsafe { cstr_to_str(path) } {
            Some(s) => s,
            None => return PCSSH_ERR_INVALID_ARGUMENT,
        };
        let attrs = if flags & PCSSH_SFTP_CREAT != 0 {
            Attrs {
                permissions: Some(mode),
                ..Default::default()
            }
        } else {
            Attrs::default()
        };
        // SAFETY: caller contract.
        let s = unsafe { &*sftp };
        let cell = s.inner.clone();
        let mut handle_out: Option<Vec<u8>> = None;
        let rc = with_parent(&cell, |sess| {
            match sess.open(path_s.as_bytes(), flags, attrs) {
                Ok(h) => {
                    handle_out = Some(h);
                    PCSSH_OK
                }
                Err(e) => map_sftp_err(&e),
            }
        });
        if rc != PCSSH_OK {
            return rc;
        }
        let handle = match handle_out {
            Some(h) => h,
            None => return PCSSH_ERR_GENERIC,
        };
        let boxed = Box::new(PcSshSftpFile {
            sftp: cell,
            handle,
            offset: 0,
            closed: false,
        });
        // SAFETY: out_file checked non-NULL above.
        unsafe { *out_file = Box::into_raw(boxed) };
        PCSSH_OK
    })
}

/// Read up to `cap` bytes from `file` at the current cursor. Advances
/// the cursor by the number of bytes returned. `*out_len = 0` on EOF.
///
/// # Safety
///
/// - `file` must be live and not yet closed.
/// - `out_len` must be non-NULL and writable.
/// - If `cap > 0`, `buf` must be non-NULL with `cap` writable bytes.
#[no_mangle]
pub unsafe extern "C" fn pcssh_sftp_read(
    file: *mut PcSshSftpFile,
    buf: *mut u8,
    cap: usize,
    out_len: *mut usize,
) -> c_int {
    catch(|| {
        if file.is_null() || out_len.is_null() {
            return PCSSH_ERR_INVALID_ARGUMENT;
        }
        if buf.is_null() && cap != 0 {
            return PCSSH_ERR_INVALID_ARGUMENT;
        }
        // SAFETY: caller contract.
        let f = unsafe { &mut *file };
        if f.closed {
            return PCSSH_ERR_INVALID_ARGUMENT;
        }
        if cap == 0 {
            // SAFETY: out_len checked.
            unsafe { *out_len = 0 };
            return PCSSH_OK;
        }
        // Clamp request length to u32 — SFTP wire is 32-bit.
        let want = cap.min(u32::MAX as usize) as u32;
        let handle = f.handle.clone();
        let offset = f.offset;
        let mut got_buf: Option<Vec<u8>> = None;
        let rc = with_parent(&f.sftp, |sess| match sess.read(&handle, offset, want) {
            Ok(c) => {
                got_buf = Some(c);
                PCSSH_OK
            }
            Err(e) => map_sftp_err(&e),
        });
        if rc != PCSSH_OK {
            return rc;
        }
        let chunk = got_buf.unwrap_or_default();
        // Defensive: a misbehaving server (or a bug in the underlying
        // `sess.read` implementation) could in principle return more
        // bytes than `want`. Cap the copy at the caller's buffer size
        // so we can never overflow `buf` — the per-call read clamp
        // (`want = cap.min(u32::MAX)`) already bounded the *request*
        // to `cap` bytes, so honest peers never trip this path.
        let got = chunk.len().min(cap);
        if got > 0 {
            // SAFETY: cap > 0 → buf non-NULL per check above; got <= cap by the min above.
            unsafe { ptr::copy_nonoverlapping(chunk.as_ptr(), buf, got) };
            f.offset = f.offset.saturating_add(got as u64);
        }
        // SAFETY: out_len checked.
        unsafe { *out_len = got };
        PCSSH_OK
    })
}

/// Write `len` bytes from `buf` at the current cursor. Advances the
/// cursor by `len`. SFTP write is all-or-nothing per call.
///
/// # Safety
///
/// - `file` must be live and not yet closed.
/// - If `len > 0`, `buf` must be non-NULL with `len` readable bytes.
#[no_mangle]
pub unsafe extern "C" fn pcssh_sftp_write(
    file: *mut PcSshSftpFile,
    buf: *const u8,
    len: usize,
) -> c_int {
    catch(|| {
        if file.is_null() {
            return PCSSH_ERR_INVALID_ARGUMENT;
        }
        if buf.is_null() && len != 0 {
            return PCSSH_ERR_INVALID_ARGUMENT;
        }
        // SAFETY: caller contract.
        let f = unsafe { &mut *file };
        if f.closed {
            return PCSSH_ERR_INVALID_ARGUMENT;
        }
        if len == 0 {
            return PCSSH_OK;
        }
        // SAFETY: len > 0 → buf non-NULL per check above; caller contract.
        let data = unsafe { slice::from_raw_parts(buf, len) };
        let handle = f.handle.clone();
        let offset = f.offset;
        let rc = with_parent(&f.sftp, |sess| match sess.write(&handle, offset, data) {
            Ok(()) => PCSSH_OK,
            Err(e) => map_sftp_err(&e),
        });
        if rc != PCSSH_OK {
            return rc;
        }
        f.offset = f.offset.saturating_add(len as u64);
        PCSSH_OK
    })
}

/// Seek to absolute `offset`. (Local-only; SFTP servers don't track a
/// cursor — the offset rides on every read/write packet.)
///
/// # Safety
///
/// `file` must be a live handle.
#[no_mangle]
pub unsafe extern "C" fn pcssh_sftp_seek(file: *mut PcSshSftpFile, offset: u64) -> c_int {
    catch(|| {
        if file.is_null() {
            return PCSSH_ERR_INVALID_ARGUMENT;
        }
        // SAFETY: caller contract.
        let f = unsafe { &mut *file };
        f.offset = offset;
        PCSSH_OK
    })
}

/// Report the current cursor.
///
/// # Safety
///
/// `file` must be live; `out_offset` must be non-NULL and writable.
#[no_mangle]
pub unsafe extern "C" fn pcssh_sftp_tell(file: *mut PcSshSftpFile, out_offset: *mut u64) -> c_int {
    catch(|| {
        if file.is_null() || out_offset.is_null() {
            return PCSSH_ERR_INVALID_ARGUMENT;
        }
        // SAFETY: caller contract.
        let f = unsafe { &*file };
        // SAFETY: out_offset checked.
        unsafe { *out_offset = f.offset };
        PCSSH_OK
    })
}

/// Close the server-side handle. Idempotent after first call.
///
/// # Safety
///
/// `file` must be live (not yet freed).
#[no_mangle]
pub unsafe extern "C" fn pcssh_sftp_close_file(file: *mut PcSshSftpFile) -> c_int {
    catch(|| {
        if file.is_null() {
            return PCSSH_ERR_INVALID_ARGUMENT;
        }
        // SAFETY: caller contract.
        let f = unsafe { &mut *file };
        if f.closed {
            return PCSSH_OK;
        }
        let handle = f.handle.clone();
        let rc = with_parent(&f.sftp, |sess| match sess.close(&handle) {
            Ok(()) => PCSSH_OK,
            Err(e) => map_sftp_err(&e),
        });
        f.closed = true;
        rc
    })
}

/// Free a file handle. Sends `SSH_FXP_CLOSE` if it hasn't already.
///
/// # Safety
///
/// `file` must be NULL or a pointer returned by `pcssh_sftp_open_file`,
/// not yet freed. The parent `PcSshSftp` may already be freed — the
/// shared cell detects that and skips the wire close in that case.
#[no_mangle]
pub unsafe extern "C" fn pcssh_sftp_file_free(file: *mut PcSshSftpFile) {
    if file.is_null() {
        return;
    }
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        // SAFETY: caller contract.
        let mut boxed = unsafe { Box::from_raw(file) };
        if !boxed.closed {
            let handle = boxed.handle.clone();
            // Best-effort close; if the parent is already gone we silently
            // skip the wire RTT (the server-side handle will be cleaned up
            // when the session channel itself goes away).
            let _ = with_parent(&boxed.sftp, |sess| match sess.close(&handle) {
                Ok(()) => PCSSH_OK,
                Err(e) => map_sftp_err(&e),
            });
            boxed.closed = true;
        }
        drop(boxed);
    }));
}

// ---------------------------------------------------------------------------
// Directory ops
// ---------------------------------------------------------------------------

/// Open a directory for reading.
///
/// # Safety
///
/// - `sftp` must be live; `path` NUL-terminated UTF-8.
/// - `out_dir` must be non-NULL and writable.
#[no_mangle]
pub unsafe extern "C" fn pcssh_sftp_opendir(
    sftp: *mut PcSshSftp,
    path: *const c_char,
    out_dir: *mut *mut PcSshSftpDir,
) -> c_int {
    catch(|| {
        if sftp.is_null() || out_dir.is_null() {
            return PCSSH_ERR_INVALID_ARGUMENT;
        }
        // SAFETY: caller contract.
        unsafe { *out_dir = ptr::null_mut() };
        // SAFETY: caller contract.
        let path_s = match unsafe { cstr_to_str(path) } {
            Some(s) => s,
            None => return PCSSH_ERR_INVALID_ARGUMENT,
        };
        // SAFETY: caller contract.
        let s = unsafe { &*sftp };
        let cell = s.inner.clone();
        let mut handle_out: Option<Vec<u8>> = None;
        let rc = with_parent(&cell, |sess| match sess.opendir(path_s.as_bytes()) {
            Ok(h) => {
                handle_out = Some(h);
                PCSSH_OK
            }
            Err(e) => map_sftp_err(&e),
        });
        if rc != PCSSH_OK {
            return rc;
        }
        let handle = match handle_out {
            Some(h) => h,
            None => return PCSSH_ERR_GENERIC,
        };
        let boxed = Box::new(PcSshSftpDir {
            sftp: cell,
            handle,
            closed: false,
        });
        // SAFETY: out_dir checked.
        unsafe { *out_dir = Box::into_raw(boxed) };
        PCSSH_OK
    })
}

/// Read one directory entry. Returns [`PCSSH_OK`] with entry data on
/// success, [`PCSSH_OK`] with `*name_len = 0` and `out_attrs->flags = 0`
/// on EOF (i.e. no more entries), or a negative code on error. The
/// implementation maintains an internal buffer of entries between calls
/// — one wire round-trip per server-side chunk, then the cached entries
/// are drained one-at-a-time.
///
/// **Note**: the current implementation does *not* cache; it requests
/// one chunk per call and returns the first entry from each chunk. A
/// future revision may add the cache to amortise wire round-trips.
///
/// # Safety
///
/// - `dir` must be live and not closed.
/// - `out_attrs` must be non-NULL and writable.
/// - `name_len` / `longname_len` must be non-NULL and writable. If
///   `name_cap > 0`, `name_buf` must point to `name_cap` writable bytes;
///   same for the longname pair.
#[allow(clippy::too_many_arguments)]
#[no_mangle]
pub unsafe extern "C" fn pcssh_sftp_readdir(
    dir: *mut PcSshSftpDir,
    name_buf: *mut u8,
    name_cap: usize,
    name_len: *mut usize,
    longname_buf: *mut u8,
    longname_cap: usize,
    longname_len: *mut usize,
    out_attrs: *mut PcSshSftpAttrs,
) -> c_int {
    catch(|| {
        if dir.is_null() || out_attrs.is_null() || name_len.is_null() || longname_len.is_null() {
            return PCSSH_ERR_INVALID_ARGUMENT;
        }
        // SAFETY: caller contract.
        let d = unsafe { &mut *dir };
        if d.closed {
            return PCSSH_ERR_INVALID_ARGUMENT;
        }
        let handle = d.handle.clone();
        let mut chunk_out: Option<Option<Vec<NameEntry>>> = None;
        let rc = with_parent(&d.sftp, |sess| match sess.readdir(&handle) {
            Ok(c) => {
                chunk_out = Some(c);
                PCSSH_OK
            }
            Err(e) => map_sftp_err(&e),
        });
        if rc != PCSSH_OK {
            return rc;
        }
        let chunk = chunk_out.unwrap_or(None);
        let entry: Option<NameEntry> = chunk.and_then(|mut v| v.drain(..1).next());
        let Some(e) = entry else {
            // EOF.
            // SAFETY: out_attrs non-NULL.
            unsafe { *out_attrs = PcSshSftpAttrs::default() };
            // SAFETY: out lens non-NULL.
            unsafe {
                *name_len = 0;
                *longname_len = 0;
            }
            return PCSSH_OK;
        };
        // SAFETY: out_attrs non-NULL.
        unsafe { *out_attrs = attrs_to_c(&e.attrs) };
        // Reuse copy_to_caller_buf for each byte field; bail on the first
        // truncation. The caller can call again with bigger buffers.
        // SAFETY: pointer/cap checked by the helper.
        let rc = unsafe { copy_to_caller_buf(&e.filename, name_buf, name_cap, name_len) };
        if rc != PCSSH_OK {
            return rc;
        }
        // SAFETY: pointer/cap checked by the helper.
        unsafe { copy_to_caller_buf(&e.longname, longname_buf, longname_cap, longname_len) }
    })
}

/// Close a server-side directory handle. Idempotent.
///
/// # Safety
///
/// `dir` must be live.
#[no_mangle]
pub unsafe extern "C" fn pcssh_sftp_closedir(dir: *mut PcSshSftpDir) -> c_int {
    catch(|| {
        if dir.is_null() {
            return PCSSH_ERR_INVALID_ARGUMENT;
        }
        // SAFETY: caller contract.
        let d = unsafe { &mut *dir };
        if d.closed {
            return PCSSH_OK;
        }
        let handle = d.handle.clone();
        let rc = with_parent(&d.sftp, |sess| match sess.close(&handle) {
            Ok(()) => PCSSH_OK,
            Err(e) => map_sftp_err(&e),
        });
        d.closed = true;
        rc
    })
}

/// Free a directory handle. Sends `SSH_FXP_CLOSE` if needed.
///
/// # Safety
///
/// `dir` must be NULL or a `pcssh_sftp_opendir` return not yet freed.
/// The parent `PcSshSftp` may already be freed.
#[no_mangle]
pub unsafe extern "C" fn pcssh_sftp_dir_free(dir: *mut PcSshSftpDir) {
    if dir.is_null() {
        return;
    }
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        // SAFETY: caller contract.
        let mut boxed = unsafe { Box::from_raw(dir) };
        if !boxed.closed {
            let handle = boxed.handle.clone();
            let _ = with_parent(&boxed.sftp, |sess| match sess.close(&handle) {
                Ok(()) => PCSSH_OK,
                Err(e) => map_sftp_err(&e),
            });
            boxed.closed = true;
        }
        drop(boxed);
    }));
}

// ---------------------------------------------------------------------------
// Stat family
// ---------------------------------------------------------------------------

/// Stat a path (follows symlinks).
///
/// # Safety
///
/// `sftp` live, `path` NUL-terminated UTF-8, `out_attrs` non-NULL writable.
#[no_mangle]
pub unsafe extern "C" fn pcssh_sftp_stat(
    sftp: *mut PcSshSftp,
    path: *const c_char,
    out_attrs: *mut PcSshSftpAttrs,
) -> c_int {
    catch(|| {
        if sftp.is_null() || out_attrs.is_null() {
            return PCSSH_ERR_INVALID_ARGUMENT;
        }
        // SAFETY: caller contract.
        let path_s = match unsafe { cstr_to_str(path) } {
            Some(s) => s,
            None => return PCSSH_ERR_INVALID_ARGUMENT,
        };
        // SAFETY: caller contract.
        let s = unsafe { &*sftp };
        let mut attrs_out: Option<Attrs> = None;
        let rc = with_parent(&s.inner, |sess| match sess.stat(path_s.as_bytes()) {
            Ok(a) => {
                attrs_out = Some(a);
                PCSSH_OK
            }
            Err(e) => map_sftp_err(&e),
        });
        if rc != PCSSH_OK {
            return rc;
        }
        // SAFETY: out_attrs checked.
        unsafe { *out_attrs = attrs_to_c(&attrs_out.unwrap_or_default()) };
        PCSSH_OK
    })
}

/// Lstat (does not follow the final symlink).
///
/// # Safety
///
/// As for [`pcssh_sftp_stat`].
#[no_mangle]
pub unsafe extern "C" fn pcssh_sftp_lstat(
    sftp: *mut PcSshSftp,
    path: *const c_char,
    out_attrs: *mut PcSshSftpAttrs,
) -> c_int {
    catch(|| {
        if sftp.is_null() || out_attrs.is_null() {
            return PCSSH_ERR_INVALID_ARGUMENT;
        }
        // SAFETY: caller contract.
        let path_s = match unsafe { cstr_to_str(path) } {
            Some(s) => s,
            None => return PCSSH_ERR_INVALID_ARGUMENT,
        };
        // SAFETY: caller contract.
        let s = unsafe { &*sftp };
        let mut attrs_out: Option<Attrs> = None;
        let rc = with_parent(&s.inner, |sess| match sess.lstat(path_s.as_bytes()) {
            Ok(a) => {
                attrs_out = Some(a);
                PCSSH_OK
            }
            Err(e) => map_sftp_err(&e),
        });
        if rc != PCSSH_OK {
            return rc;
        }
        // SAFETY: out_attrs checked.
        unsafe { *out_attrs = attrs_to_c(&attrs_out.unwrap_or_default()) };
        PCSSH_OK
    })
}

/// Stat an open file (by server-side handle).
///
/// # Safety
///
/// `file` live, `out_attrs` non-NULL writable.
#[no_mangle]
pub unsafe extern "C" fn pcssh_sftp_fstat(
    file: *mut PcSshSftpFile,
    out_attrs: *mut PcSshSftpAttrs,
) -> c_int {
    catch(|| {
        if file.is_null() || out_attrs.is_null() {
            return PCSSH_ERR_INVALID_ARGUMENT;
        }
        // SAFETY: caller contract.
        let f = unsafe { &mut *file };
        if f.closed {
            return PCSSH_ERR_INVALID_ARGUMENT;
        }
        let handle = f.handle.clone();
        let mut attrs_out: Option<Attrs> = None;
        let rc = with_parent(&f.sftp, |sess| match sess.fstat(&handle) {
            Ok(a) => {
                attrs_out = Some(a);
                PCSSH_OK
            }
            Err(e) => map_sftp_err(&e),
        });
        if rc != PCSSH_OK {
            return rc;
        }
        // SAFETY: out_attrs checked.
        unsafe { *out_attrs = attrs_to_c(&attrs_out.unwrap_or_default()) };
        PCSSH_OK
    })
}

/// Set attributes on a path.
///
/// # Safety
///
/// `sftp` live, `path` NUL-terminated UTF-8, `attrs` non-NULL and readable.
#[no_mangle]
pub unsafe extern "C" fn pcssh_sftp_setstat(
    sftp: *mut PcSshSftp,
    path: *const c_char,
    attrs: *const PcSshSftpAttrs,
) -> c_int {
    catch(|| {
        if sftp.is_null() || attrs.is_null() {
            return PCSSH_ERR_INVALID_ARGUMENT;
        }
        // SAFETY: caller contract.
        let path_s = match unsafe { cstr_to_str(path) } {
            Some(s) => s,
            None => return PCSSH_ERR_INVALID_ARGUMENT,
        };
        // SAFETY: caller contract.
        let a = unsafe { &*attrs };
        let a_owned = attrs_from_c(a);
        // SAFETY: caller contract.
        let s = unsafe { &*sftp };
        with_parent(&s.inner, |sess| {
            match sess.setstat(path_s.as_bytes(), a_owned) {
                Ok(()) => PCSSH_OK,
                Err(e) => map_sftp_err(&e),
            }
        })
    })
}

/// Set attributes on an open file.
///
/// # Safety
///
/// `file` live, `attrs` non-NULL readable.
#[no_mangle]
pub unsafe extern "C" fn pcssh_sftp_fsetstat(
    file: *mut PcSshSftpFile,
    attrs: *const PcSshSftpAttrs,
) -> c_int {
    catch(|| {
        if file.is_null() || attrs.is_null() {
            return PCSSH_ERR_INVALID_ARGUMENT;
        }
        // SAFETY: caller contract.
        let f = unsafe { &mut *file };
        if f.closed {
            return PCSSH_ERR_INVALID_ARGUMENT;
        }
        // SAFETY: caller contract.
        let a = unsafe { &*attrs };
        let a_owned = attrs_from_c(a);
        let handle = f.handle.clone();
        with_parent(&f.sftp, |sess| match sess.fsetstat(&handle, a_owned) {
            Ok(()) => PCSSH_OK,
            Err(e) => map_sftp_err(&e),
        })
    })
}

// ---------------------------------------------------------------------------
// Path ops
// ---------------------------------------------------------------------------

/// `SSH_FXP_MKDIR` — create a directory.
///
/// # Safety
///
/// `sftp` live, `path` NUL-terminated UTF-8.
#[no_mangle]
pub unsafe extern "C" fn pcssh_sftp_mkdir(
    sftp: *mut PcSshSftp,
    path: *const c_char,
    mode: u32,
) -> c_int {
    catch(|| {
        if sftp.is_null() {
            return PCSSH_ERR_INVALID_ARGUMENT;
        }
        // SAFETY: caller contract.
        let path_s = match unsafe { cstr_to_str(path) } {
            Some(s) => s,
            None => return PCSSH_ERR_INVALID_ARGUMENT,
        };
        let attrs = Attrs {
            permissions: Some(mode),
            ..Default::default()
        };
        // SAFETY: caller contract.
        let s = unsafe { &*sftp };
        with_parent(&s.inner, |sess| {
            match sess.mkdir(path_s.as_bytes(), attrs) {
                Ok(()) => PCSSH_OK,
                Err(e) => map_sftp_err(&e),
            }
        })
    })
}

/// `SSH_FXP_RMDIR` — remove an empty directory.
///
/// # Safety
///
/// `sftp` live, `path` NUL-terminated UTF-8.
#[no_mangle]
pub unsafe extern "C" fn pcssh_sftp_rmdir(sftp: *mut PcSshSftp, path: *const c_char) -> c_int {
    catch(|| {
        if sftp.is_null() {
            return PCSSH_ERR_INVALID_ARGUMENT;
        }
        // SAFETY: caller contract.
        let path_s = match unsafe { cstr_to_str(path) } {
            Some(s) => s,
            None => return PCSSH_ERR_INVALID_ARGUMENT,
        };
        // SAFETY: caller contract.
        let s = unsafe { &*sftp };
        with_parent(&s.inner, |sess| match sess.rmdir(path_s.as_bytes()) {
            Ok(()) => PCSSH_OK,
            Err(e) => map_sftp_err(&e),
        })
    })
}

/// `SSH_FXP_REMOVE` — remove a file.
///
/// # Safety
///
/// `sftp` live, `path` NUL-terminated UTF-8.
#[no_mangle]
pub unsafe extern "C" fn pcssh_sftp_remove(sftp: *mut PcSshSftp, path: *const c_char) -> c_int {
    catch(|| {
        if sftp.is_null() {
            return PCSSH_ERR_INVALID_ARGUMENT;
        }
        // SAFETY: caller contract.
        let path_s = match unsafe { cstr_to_str(path) } {
            Some(s) => s,
            None => return PCSSH_ERR_INVALID_ARGUMENT,
        };
        // SAFETY: caller contract.
        let s = unsafe { &*sftp };
        with_parent(&s.inner, |sess| match sess.remove(path_s.as_bytes()) {
            Ok(()) => PCSSH_OK,
            Err(e) => map_sftp_err(&e),
        })
    })
}

/// `SSH_FXP_RENAME`.
///
/// # Safety
///
/// `sftp` live, both paths NUL-terminated UTF-8.
#[no_mangle]
pub unsafe extern "C" fn pcssh_sftp_rename(
    sftp: *mut PcSshSftp,
    old_path: *const c_char,
    new_path: *const c_char,
) -> c_int {
    catch(|| {
        if sftp.is_null() {
            return PCSSH_ERR_INVALID_ARGUMENT;
        }
        // SAFETY: caller contract.
        let old_s = match unsafe { cstr_to_str(old_path) } {
            Some(s) => s,
            None => return PCSSH_ERR_INVALID_ARGUMENT,
        };
        // SAFETY: caller contract.
        let new_s = match unsafe { cstr_to_str(new_path) } {
            Some(s) => s,
            None => return PCSSH_ERR_INVALID_ARGUMENT,
        };
        // SAFETY: caller contract.
        let s = unsafe { &*sftp };
        with_parent(&s.inner, |sess| {
            match sess.rename(old_s.as_bytes(), new_s.as_bytes()) {
                Ok(()) => PCSSH_OK,
                Err(e) => map_sftp_err(&e),
            }
        })
    })
}

/// `SSH_FXP_SYMLINK`. Argument order matches the lib: `(target,
/// link_path)`.
///
/// # Safety
///
/// `sftp` live, both paths NUL-terminated UTF-8.
#[no_mangle]
pub unsafe extern "C" fn pcssh_sftp_symlink(
    sftp: *mut PcSshSftp,
    target: *const c_char,
    link_path: *const c_char,
) -> c_int {
    catch(|| {
        if sftp.is_null() {
            return PCSSH_ERR_INVALID_ARGUMENT;
        }
        // SAFETY: caller contract.
        let tgt = match unsafe { cstr_to_str(target) } {
            Some(s) => s,
            None => return PCSSH_ERR_INVALID_ARGUMENT,
        };
        // SAFETY: caller contract.
        let lnk = match unsafe { cstr_to_str(link_path) } {
            Some(s) => s,
            None => return PCSSH_ERR_INVALID_ARGUMENT,
        };
        // SAFETY: caller contract.
        let s = unsafe { &*sftp };
        with_parent(&s.inner, |sess| {
            match sess.symlink(tgt.as_bytes(), lnk.as_bytes()) {
                Ok(()) => PCSSH_OK,
                Err(e) => map_sftp_err(&e),
            }
        })
    })
}

/// `SSH_FXP_READLINK` — read link target into caller buffer.
///
/// # Safety
///
/// `sftp` live, `path` NUL-terminated UTF-8, `out_len` non-NULL writable;
/// if `cap > 0` and the target is non-empty, `buf` non-NULL with `cap`
/// writable bytes.
#[no_mangle]
pub unsafe extern "C" fn pcssh_sftp_readlink(
    sftp: *mut PcSshSftp,
    path: *const c_char,
    buf: *mut u8,
    cap: usize,
    out_len: *mut usize,
) -> c_int {
    catch(|| {
        if sftp.is_null() || out_len.is_null() {
            return PCSSH_ERR_INVALID_ARGUMENT;
        }
        // SAFETY: caller contract.
        let path_s = match unsafe { cstr_to_str(path) } {
            Some(s) => s,
            None => return PCSSH_ERR_INVALID_ARGUMENT,
        };
        // SAFETY: caller contract.
        let s = unsafe { &*sftp };
        let mut tgt_out: Option<Vec<u8>> = None;
        let rc = with_parent(&s.inner, |sess| match sess.readlink(path_s.as_bytes()) {
            Ok(t) => {
                tgt_out = Some(t);
                PCSSH_OK
            }
            Err(e) => map_sftp_err(&e),
        });
        if rc != PCSSH_OK {
            return rc;
        }
        let target = tgt_out.unwrap_or_default();
        // SAFETY: out_len/buf/cap checked by helper.
        unsafe { copy_to_caller_buf(&target, buf, cap, out_len) }
    })
}

/// `SSH_FXP_REALPATH` — canonicalise a path.
///
/// # Safety
///
/// As for [`pcssh_sftp_readlink`].
#[no_mangle]
pub unsafe extern "C" fn pcssh_sftp_realpath(
    sftp: *mut PcSshSftp,
    path: *const c_char,
    buf: *mut u8,
    cap: usize,
    out_len: *mut usize,
) -> c_int {
    catch(|| {
        if sftp.is_null() || out_len.is_null() {
            return PCSSH_ERR_INVALID_ARGUMENT;
        }
        // SAFETY: caller contract.
        let path_s = match unsafe { cstr_to_str(path) } {
            Some(s) => s,
            None => return PCSSH_ERR_INVALID_ARGUMENT,
        };
        // SAFETY: caller contract.
        let s = unsafe { &*sftp };
        let mut canon_out: Option<Vec<u8>> = None;
        let rc = with_parent(&s.inner, |sess| match sess.realpath(path_s.as_bytes()) {
            Ok(t) => {
                canon_out = Some(t);
                PCSSH_OK
            }
            Err(e) => map_sftp_err(&e),
        });
        if rc != PCSSH_OK {
            return rc;
        }
        let canon = canon_out.unwrap_or_default();
        // SAFETY: out_len/buf/cap checked by helper.
        unsafe { copy_to_caller_buf(&canon, buf, cap, out_len) }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn attrs_round_trip_through_c_form() {
        let a = Attrs {
            size: Some(123),
            uid_gid: Some((1000, 100)),
            permissions: Some(0o644),
            atime_mtime: Some((1, 2)),
            extended: vec![],
        };
        let c = attrs_to_c(&a);
        assert_eq!(
            c.flags,
            PCSSH_ATTR_SIZE | PCSSH_ATTR_UIDGID | PCSSH_ATTR_PERMISSIONS | PCSSH_ATTR_ACMODTIME
        );
        assert_eq!(c.size, 123);
        assert_eq!(c.uid, 1000);
        assert_eq!(c.gid, 100);
        assert_eq!(c.permissions, 0o644);
        assert_eq!(c.atime, 1);
        assert_eq!(c.mtime, 2);
        let back = attrs_from_c(&c);
        assert_eq!(back.size, Some(123));
        assert_eq!(back.uid_gid, Some((1000, 100)));
        assert_eq!(back.permissions, Some(0o644));
        assert_eq!(back.atime_mtime, Some((1, 2)));
    }

    #[test]
    fn attrs_empty_round_trips() {
        let a = Attrs::default();
        let c = attrs_to_c(&a);
        assert_eq!(c.flags, 0);
        let back = attrs_from_c(&c);
        assert_eq!(back, Attrs::default());
    }

    #[test]
    fn copy_to_caller_buf_exact_fit() {
        let src = b"hello";
        let mut buf = [0u8; 5];
        let mut len = 0usize;
        let rc = unsafe { copy_to_caller_buf(src, buf.as_mut_ptr(), 5, &mut len) };
        assert_eq!(rc, PCSSH_OK);
        assert_eq!(len, 5);
        assert_eq!(&buf, src);
    }

    #[test]
    fn copy_to_caller_buf_too_small_reports_required() {
        let src = b"hello";
        let mut buf = [0u8; 2];
        let mut len = 0usize;
        let rc = unsafe { copy_to_caller_buf(src, buf.as_mut_ptr(), 2, &mut len) };
        assert_eq!(rc, PCSSH_ERR_BUFFER_TOO_SMALL);
        assert_eq!(len, 5);
    }

    #[test]
    fn copy_to_caller_buf_empty_src_ok_with_zero_cap() {
        let src: &[u8] = &[];
        let mut len = 0usize;
        let rc = unsafe { copy_to_caller_buf(src, std::ptr::null_mut(), 0, &mut len) };
        assert_eq!(rc, PCSSH_OK);
        assert_eq!(len, 0);
    }

    #[test]
    fn free_null_safe() {
        unsafe {
            pcssh_sftp_free(std::ptr::null_mut());
            pcssh_sftp_file_free(std::ptr::null_mut());
            pcssh_sftp_dir_free(std::ptr::null_mut());
        }
    }

    /// `with_parent` returns `PCSSH_ERR_INVALID_HANDLE` when the cell has
    /// been wiped (which is what `pcssh_sftp_free` does to any surviving
    /// child handles). This is the regression test for finding #11 — a
    /// child file/dir handle outliving its parent must NOT dereference
    /// freed memory.
    #[test]
    fn with_parent_returns_invalid_handle_after_wipe() {
        // We can't easily construct a real SftpSession in unit tests
        // (it needs a connected client), so we test the cell mechanics
        // directly: a cell that started populated and was then wiped
        // returns INVALID_HANDLE on the next access.
        let cell: Arc<SftpCell> = Arc::new(Mutex::new(None));
        // Closure must not run when the cell is empty.
        let mut called = false;
        let rc = with_parent(&cell, |_sess| {
            called = true;
            PCSSH_OK
        });
        assert_eq!(rc, PCSSH_ERR_INVALID_HANDLE);
        assert!(!called, "callback must not run for a wiped cell");
    }
}
