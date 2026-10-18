//! The few POSIX calls the client binaries make that `std` lacks, over
//! `libc` (the `nix` wrappers come with the library's `server` and `agent`
//! features only); included by `ssh`, `ssh-add` and `ssh-keygen` via
//! `#[path]`.

#![allow(dead_code)]

use std::os::fd::AsRawFd;

/// The effective uid.
pub fn geteuid() -> u32 {
    // SAFETY: geteuid(2) has no preconditions and cannot fail.
    unsafe { libc::geteuid() }
}

/// The real uid.
pub fn getuid() -> u32 {
    // SAFETY: getuid(2) has no preconditions and cannot fail.
    unsafe { libc::getuid() }
}

/// The password database entry for `uid`: its login name and home directory.
pub fn passwd_entry(uid: u32) -> Option<(String, String)> {
    let mut buf = vec![0u8; 1024];
    loop {
        // SAFETY: `pw` and `buf` outlive the call and `buf.len()` is its
        // size; on success `result` points at `pw`, whose strings point
        // into `buf`, and both are read before either is dropped.
        let mut pw: libc::passwd = unsafe { core::mem::zeroed() };
        let mut result: *mut libc::passwd = core::ptr::null_mut();
        let rc = unsafe {
            libc::getpwuid_r(
                uid,
                &mut pw,
                buf.as_mut_ptr().cast(),
                buf.len(),
                &mut result,
            )
        };
        if rc == libc::ERANGE && buf.len() < 1 << 20 {
            buf.resize(buf.len() * 2, 0);
            continue;
        }
        if rc != 0 || result.is_null() {
            return None;
        }
        let field = |p: *const libc::c_char| {
            // SAFETY: getpwuid_r stored NUL-terminated strings in `buf`.
            (!p.is_null()).then(|| {
                unsafe { std::ffi::CStr::from_ptr(p) }
                    .to_string_lossy()
                    .into_owned()
            })
        };
        return Some((field(pw.pw_name)?, field(pw.pw_dir).unwrap_or_default()));
    }
}

/// Make `fd` (0, 1 or 2) a duplicate of `f`.
pub fn dup2(f: &impl AsRawFd, fd: i32) -> std::io::Result<()> {
    // SAFETY: plain dup2(2) on a descriptor `f` keeps open for the call.
    if unsafe { libc::dup2(f.as_raw_fd(), fd) } == -1 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}
