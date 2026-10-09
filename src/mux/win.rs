//! Windows named-pipe carrier for the mux control connection.
//!
//! The master binds a byte-mode, overlapped named pipe whose name is derived from
//! the expanded ControlPath, and clients connect to the same name. The first
//! instance is created with FILE_FLAG_FIRST_PIPE_INSTANCE, so only one master can
//! own a name at a time. The DACL grants access only to the creating account, and
//! a client checks that the pipe's owner is its own account before trusting it.
//! The design follows PuTTY's windows/utils/security.c and windows/named-pipe files.
//!
//! This is the only mux module that uses unsafe. The crate lint allows it only on
//! Windows with the win-ipc feature.

#![allow(unsafe_code)]

use std::ffi::c_void;
use std::io::{self, Read, Write};
use std::net::Shutdown;
use std::ptr::{null, null_mut};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use purecrypto::hash::{Digest, Sha256};

type Handle = *mut c_void;
type Bool = i32;
type Dword = u32;
type Wide = *const u16;

const FALSE: Bool = 0;
const TRUE: Bool = 1;
const INVALID_HANDLE: Handle = -1isize as Handle;
const INFINITE: Dword = 0xFFFF_FFFF;
const WAIT_OBJECT_0: Dword = 0;
const WAIT_TIMEOUT: Dword = 0x102;

const ERROR_FILE_NOT_FOUND: i32 = 2;
const ERROR_HANDLE_EOF: i32 = 38;
const ERROR_PIPE_BUSY: i32 = 231;
const ERROR_BROKEN_PIPE: i32 = 109;
const ERROR_OPERATION_ABORTED: i32 = 995;
const ERROR_PIPE_CONNECTED: i32 = 535;
const ERROR_PIPE_NOT_CONNECTED: i32 = 233;
const ERROR_IO_PENDING: i32 = 997;
const ERROR_NOT_FOUND: i32 = 1168;

const GENERIC_READ: Dword = 0x8000_0000;
const GENERIC_WRITE: Dword = 0x4000_0000;
const OPEN_EXISTING: Dword = 3;
const FILE_FLAG_OVERLAPPED: Dword = 0x4000_0000;
const FILE_FLAG_FIRST_PIPE_INSTANCE: Dword = 0x0008_0000;
const PIPE_ACCESS_DUPLEX: Dword = 0x0000_0003;
const PIPE_TYPE_BYTE: Dword = 0x0000_0000;
const PIPE_READMODE_BYTE: Dword = 0x0000_0000;
const PIPE_WAIT: Dword = 0x0000_0000;
const PIPE_REJECT_REMOTE_CLIENTS: Dword = 0x0000_0008;
const PIPE_UNLIMITED_INSTANCES: Dword = 255;
const NMPWAIT_USE_DEFAULT_WAIT: Dword = 0;

const SDDL_REVISION_1: Dword = 1;
const TOKEN_QUERY: Dword = 0x0008;
const TOKEN_USER_CLASS: u32 = 1;
const SE_KERNEL_OBJECT: u32 = 6;
const OWNER_SECURITY_INFORMATION: u32 = 0x0000_0001;

/// Prefix of every carrier pipe name. The account name and a digest follow it.
const PIPE_PREFIX: &str = r"\\.\pipe\puressh-mux";

#[repr(C)]
struct SecurityAttributes {
    n_length: Dword,
    lp_security_descriptor: *mut c_void,
    b_inherit_handle: Bool,
}

#[repr(C)]
struct Overlapped {
    internal: usize,
    internal_high: usize,
    offset: Dword,
    offset_high: Dword,
    h_event: Handle,
}

#[repr(C)]
struct TokenUser {
    sid: *mut c_void,
    attributes: Dword,
}

#[link(name = "kernel32")]
unsafe extern "system" {
    fn CreateNamedPipeW(
        name: Wide,
        open_mode: Dword,
        pipe_mode: Dword,
        max_instances: Dword,
        out_buffer: Dword,
        in_buffer: Dword,
        default_timeout: Dword,
        attributes: *const SecurityAttributes,
    ) -> Handle;
    fn ConnectNamedPipe(pipe: Handle, overlapped: *mut Overlapped) -> Bool;
    fn CreateFileW(
        name: Wide,
        access: Dword,
        share: Dword,
        attributes: *const SecurityAttributes,
        disposition: Dword,
        flags: Dword,
        template: Handle,
    ) -> Handle;
    fn WaitNamedPipeW(name: Wide, timeout: Dword) -> Bool;
    fn CreateEventW(
        attributes: *const SecurityAttributes,
        manual_reset: Bool,
        initial: Bool,
        name: Wide,
    ) -> Handle;
    fn WaitForSingleObject(handle: Handle, milliseconds: Dword) -> Dword;
    fn ReadFile(
        handle: Handle,
        buffer: *mut c_void,
        count: Dword,
        read: *mut Dword,
        overlapped: *mut Overlapped,
    ) -> Bool;
    fn WriteFile(
        handle: Handle,
        buffer: *const c_void,
        count: Dword,
        written: *mut Dword,
        overlapped: *mut Overlapped,
    ) -> Bool;
    fn GetOverlappedResult(
        handle: Handle,
        overlapped: *mut Overlapped,
        transferred: *mut Dword,
        wait: Bool,
    ) -> Bool;
    fn CancelIoEx(handle: Handle, overlapped: *mut Overlapped) -> Bool;
    fn CloseHandle(handle: Handle) -> Bool;
    fn GetLastError() -> Dword;
    fn GetCurrentProcess() -> Handle;
    fn LocalFree(memory: *mut c_void) -> *mut c_void;
}

#[link(name = "advapi32")]
unsafe extern "system" {
    fn OpenProcessToken(process: Handle, access: Dword, token: *mut Handle) -> Bool;
    fn GetTokenInformation(
        token: Handle,
        class: u32,
        information: *mut c_void,
        length: Dword,
        returned: *mut Dword,
    ) -> Bool;
    fn ConvertSidToStringSidW(sid: *mut c_void, out: *mut *mut u16) -> Bool;
    fn ConvertStringSecurityDescriptorToSecurityDescriptorW(
        sddl: Wide,
        revision: Dword,
        descriptor: *mut *mut c_void,
        size: *mut Dword,
    ) -> Bool;
    fn GetUserNameW(buffer: *mut u16, size: *mut Dword) -> Bool;
    fn GetSecurityInfo(
        handle: Handle,
        object_type: u32,
        information: u32,
        owner: *mut *mut c_void,
        group: *mut *mut c_void,
        dacl: *mut *mut c_void,
        sacl: *mut *mut c_void,
        descriptor: *mut *mut c_void,
    ) -> Dword;
    fn EqualSid(first: *mut c_void, second: *mut c_void) -> Bool;
}

/// Map a BOOL result to an io::Result, reading GetLastError on failure.
fn check(ok: Bool) -> io::Result<()> {
    if ok == FALSE {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// Lock a mutex, recovering from poisoning. The protected state is plain data.
fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

/// UTF-16, NUL terminated, for the W APIs.
fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(core::iter::once(0)).collect()
}

/// Read a NUL-terminated UTF-16 string.
///
/// # Safety
/// The caller guarantees that p points to a NUL-terminated UTF-16 string.
unsafe fn read_wide_z(p: *const u16) -> String {
    let mut len = 0;
    // SAFETY: the caller guarantees a terminating NUL, so we stop inside the string.
    unsafe {
        while *p.add(len) != 0 {
            len += 1;
        }
        String::from_utf16_lossy(core::slice::from_raw_parts(p, len))
    }
}

/// An owned Win32 handle, closed on drop.
struct OwnedHandle(Handle);

// SAFETY: kernel handles may be used from any thread. Each call on them here is
// independent: overlapped I/O with its own OVERLAPPED, and cancellation.
unsafe impl Send for OwnedHandle {}
// SAFETY: as above; shared references only issue thread-safe kernel calls.
unsafe impl Sync for OwnedHandle {}

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        if !self.0.is_null() && self.0 != INVALID_HANDLE {
            // SAFETY: we own this handle and close it exactly once.
            unsafe {
                CloseHandle(self.0);
            }
        }
    }
}

/// The current account name, as the Windows API reports it.
fn current_user_name() -> io::Result<String> {
    let mut size: Dword = 0;
    // SAFETY: a null buffer with a size pointer only asks for the required size.
    unsafe {
        GetUserNameW(null_mut(), &mut size);
    }
    let mut buf = vec![0u16; size as usize];
    // SAFETY: buf has size UTF-16 units, as the API requires.
    check(unsafe { GetUserNameW(buf.as_mut_ptr(), &mut size) })?;
    Ok(String::from_utf16_lossy(
        &buf[..size.saturating_sub(1) as usize],
    ))
}

/// The current process's user SID, kept alive with the buffer that backs it.
struct UserSid {
    raw: Vec<u64>,
}

impl UserSid {
    fn current() -> io::Result<Self> {
        let mut token: Handle = null_mut();
        // SAFETY: the pseudo-handle from GetCurrentProcess needs no closing.
        check(unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) })?;
        let token = OwnedHandle(token);
        let mut len: Dword = 0;
        // SAFETY: a null buffer with length 0 asks for the required size.
        unsafe {
            GetTokenInformation(token.0, TOKEN_USER_CLASS, null_mut(), 0, &mut len);
        }
        let mut raw = vec![0u64; (len as usize).div_ceil(8)];
        // SAFETY: raw is 8-byte aligned and holds len bytes.
        check(unsafe {
            GetTokenInformation(
                token.0,
                TOKEN_USER_CLASS,
                raw.as_mut_ptr().cast(),
                len,
                &mut len,
            )
        })?;
        Ok(UserSid { raw })
    }

    fn sid(&self) -> *mut c_void {
        // SAFETY: raw was filled with a TOKEN_USER by GetTokenInformation.
        unsafe { (*self.raw.as_ptr().cast::<TokenUser>()).sid }
    }

    fn as_string(&self) -> io::Result<String> {
        let mut out: *mut u16 = null_mut();
        // SAFETY: self.sid() stays valid while self lives.
        check(unsafe { ConvertSidToStringSidW(self.sid(), &mut out) })?;
        // SAFETY: on success out is a NUL-terminated string from LocalAlloc.
        let s = unsafe { read_wide_z(out) };
        // SAFETY: we own out and free it exactly once.
        unsafe {
            LocalFree(out.cast());
        }
        Ok(s)
    }
}

/// A security descriptor from SDDL, freed on drop.
struct SecurityDescriptor {
    raw: *mut c_void,
}

// SAFETY: the descriptor is immutable after creation and only read by the kernel.
unsafe impl Send for SecurityDescriptor {}

impl SecurityDescriptor {
    fn from_sddl(sddl: &str) -> io::Result<Self> {
        let w = wide(sddl);
        let mut raw: *mut c_void = null_mut();
        let mut size: Dword = 0;
        // SAFETY: w is NUL terminated, and the API allocates raw for us.
        check(unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                w.as_ptr(),
                SDDL_REVISION_1,
                &mut raw,
                &mut size,
            )
        })?;
        Ok(SecurityDescriptor { raw })
    }

    /// A descriptor that grants rights to the current account only: the owner is
    /// the account, and the single DACL entry is the account's SID.
    fn private(rights: &str) -> io::Result<Self> {
        let sid = UserSid::current()?.as_string()?;
        Self::from_sddl(&format!("O:{sid}G:{sid}D:(A;;{rights};;;{sid})"))
    }

    fn attributes(&self) -> SecurityAttributes {
        SecurityAttributes {
            n_length: core::mem::size_of::<SecurityAttributes>() as Dword,
            lp_security_descriptor: self.raw,
            b_inherit_handle: FALSE,
        }
    }
}

impl Drop for SecurityDescriptor {
    fn drop(&mut self) {
        if !self.raw.is_null() {
            // SAFETY: allocated by ConvertStringSecurityDescriptorToSecurityDescriptorW.
            unsafe {
                LocalFree(self.raw);
            }
        }
    }
}

/// Create an unnamed manual-reset event for one overlapped operation.
fn create_event() -> io::Result<OwnedHandle> {
    // SAFETY: an unnamed event with default security.
    let h = unsafe { CreateEventW(null(), TRUE, FALSE, null()) };
    if h.is_null() {
        Err(io::Error::last_os_error())
    } else {
        Ok(OwnedHandle(h))
    }
}

/// Run one overlapped read or write, waiting at most the given timeout.
///
/// On timeout the request is cancelled. If it completed just before the
/// cancellation, its bytes are returned rather than dropped.
fn overlapped_io(
    pipe: Handle,
    write: bool,
    buf: *mut u8,
    len: usize,
    timeout: Option<Duration>,
) -> io::Result<usize> {
    let event = create_event()?;
    let mut ov = Overlapped {
        internal: 0,
        internal_high: 0,
        offset: 0,
        offset_high: 0,
        h_event: event.0,
    };
    let len = len.min(Dword::MAX as usize) as Dword;
    let mut n: Dword = 0;
    // SAFETY: buf is valid for len bytes, and ov lives until the operation completes.
    let started = unsafe {
        if write {
            WriteFile(pipe, buf.cast_const().cast(), len, &mut n, &mut ov)
        } else {
            ReadFile(pipe, buf.cast(), len, &mut n, &mut ov)
        }
    };
    if started == FALSE {
        // SAFETY: reads the calling thread's last error.
        let code = unsafe { GetLastError() } as i32;
        if code != ERROR_IO_PENDING {
            return finish_error(code, write);
        }
        let ms = match timeout {
            None => INFINITE,
            Some(d) => d.as_millis().min(u128::from(INFINITE - 1)) as Dword,
        };
        // SAFETY: waits on this operation's own event.
        match unsafe { WaitForSingleObject(event.0, ms) } {
            WAIT_OBJECT_0 => {}
            WAIT_TIMEOUT => {
                // SAFETY: cancels only this request. The wait below lets it finish
                // before ov and buf are released.
                unsafe {
                    CancelIoEx(pipe, &mut ov);
                }
                let mut got: Dword = 0;
                // SAFETY: as above.
                if unsafe { GetOverlappedResult(pipe, &mut ov, &mut got, TRUE) } != FALSE {
                    return Ok(got as usize);
                }
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "control pipe operation timed out",
                ));
            }
            _ => return Err(io::Error::last_os_error()),
        }
        // SAFETY: the event is signalled, so the operation has completed.
        if unsafe { GetOverlappedResult(pipe, &mut ov, &mut n, FALSE) } == FALSE {
            // SAFETY: reads the calling thread's last error.
            let code = unsafe { GetLastError() } as i32;
            return finish_error(code, write);
        }
    }
    Ok(n as usize)
}

/// A read that hits a closed or cancelled pipe is end of stream (Ok(0)). A write
/// to a closed pipe is an error.
fn finish_error(code: i32, write: bool) -> io::Result<usize> {
    if write {
        return Err(io::Error::from_raw_os_error(code));
    }
    match code {
        ERROR_BROKEN_PIPE
        | ERROR_HANDLE_EOF
        | ERROR_PIPE_NOT_CONNECTED
        | ERROR_OPERATION_ABORTED => Ok(0),
        _ => Err(io::Error::from_raw_os_error(code)),
    }
}

/// Read and write timeouts, shared by a connection and all of its clones.
#[derive(Default)]
struct Timeouts {
    read: Option<Duration>,
    write: Option<Duration>,
}

/// Which directions have been shut down, shared by a connection and its clones.
#[derive(Default)]
struct Shut {
    read: AtomicBool,
    write: AtomicBool,
}

/// One end of a control connection: a byte-mode, overlapped named pipe.
///
/// Clones share the handle, the timeouts, and the shutdown state, as clones of a
/// UnixStream do. Reads and writes may run on different clones at the same time.
pub struct PipeConn {
    handle: Arc<OwnedHandle>,
    timeouts: Arc<Mutex<Timeouts>>,
    shut: Arc<Shut>,
}

impl PipeConn {
    fn new(handle: OwnedHandle) -> Self {
        PipeConn {
            handle: Arc::new(handle),
            timeouts: Arc::new(Mutex::new(Timeouts::default())),
            shut: Arc::new(Shut::default()),
        }
    }

    /// Another handle to the same connection.
    pub fn try_clone(&self) -> io::Result<PipeConn> {
        Ok(PipeConn {
            handle: self.handle.clone(),
            timeouts: self.timeouts.clone(),
            shut: self.shut.clone(),
        })
    }

    /// Set the read timeout. None waits forever. A timeout reports TimedOut.
    pub fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        lock(&self.timeouts).read = timeout;
        Ok(())
    }

    /// Set the write timeout. None waits forever.
    pub fn set_write_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        lock(&self.timeouts).write = timeout;
        Ok(())
    }

    /// Shut down one or both directions. Operations in flight on any clone are
    /// cancelled, so a reader blocked on this connection wakes up with end of stream.
    pub fn shutdown(&self, how: Shutdown) -> io::Result<()> {
        if matches!(how, Shutdown::Read | Shutdown::Both) {
            self.shut.read.store(true, Ordering::SeqCst);
        }
        if matches!(how, Shutdown::Write | Shutdown::Both) {
            self.shut.write.store(true, Ordering::SeqCst);
        }
        // SAFETY: the handle is valid while self lives. A null overlapped pointer
        // cancels every pending request on the handle.
        if unsafe { CancelIoEx(self.handle.0, null_mut()) } == FALSE {
            let err = io::Error::last_os_error();
            if err.raw_os_error() != Some(ERROR_NOT_FOUND) {
                return Err(err);
            }
        }
        Ok(())
    }
}

impl Read for PipeConn {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() || self.shut.read.load(Ordering::SeqCst) {
            return Ok(0);
        }
        let timeout = lock(&self.timeouts).read;
        overlapped_io(self.handle.0, false, buf.as_mut_ptr(), buf.len(), timeout)
    }
}

impl Write for PipeConn {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.shut.write.load(Ordering::SeqCst) {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "connection shut down for writing",
            ));
        }
        if buf.is_empty() {
            return Ok(0);
        }
        let timeout = lock(&self.timeouts).write;
        overlapped_io(
            self.handle.0,
            true,
            buf.as_ptr().cast_mut(),
            buf.len(),
            timeout,
        )
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Create one pipe instance with the given security.
fn create_instance(
    name: &[u16],
    descriptor: &SecurityDescriptor,
    first: bool,
) -> io::Result<OwnedHandle> {
    let attributes = descriptor.attributes();
    let open_mode = PIPE_ACCESS_DUPLEX
        | FILE_FLAG_OVERLAPPED
        | if first {
            FILE_FLAG_FIRST_PIPE_INSTANCE
        } else {
            0
        };
    let pipe_mode = PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS;
    // SAFETY: name is NUL terminated, and attributes points at a live descriptor.
    let h = unsafe {
        CreateNamedPipeW(
            name.as_ptr(),
            open_mode,
            pipe_mode,
            PIPE_UNLIMITED_INSTANCES,
            4096,
            4096,
            0,
            &attributes,
        )
    };
    if h == INVALID_HANDLE {
        Err(io::Error::last_os_error())
    } else {
        Ok(OwnedHandle(h))
    }
}

/// Server side: keeps one unconnected pipe instance ready for the next client.
pub struct PipeListener {
    name: Vec<u16>,
    descriptor: SecurityDescriptor,
    next: Mutex<OwnedHandle>,
}

impl PipeListener {
    /// Create the first instance. Fails if another listener already owns the name,
    /// which is how a second master is kept out.
    pub fn bind(name: &str) -> io::Result<Self> {
        let descriptor = SecurityDescriptor::private("GRGW")?;
        let w = wide(name);
        let next = create_instance(&w, &descriptor, true)?;
        Ok(PipeListener {
            name: w,
            descriptor,
            next: Mutex::new(next),
        })
    }

    /// Wait for the next client, then re-arm with a fresh instance so that more
    /// clients can connect.
    pub fn accept(&self) -> io::Result<PipeConn> {
        let mut next = lock(&self.next);
        let event = create_event()?;
        let mut ov = Overlapped {
            internal: 0,
            internal_high: 0,
            offset: 0,
            offset_high: 0,
            h_event: event.0,
        };
        // SAFETY: ov and its event stay alive until the wait below completes.
        if unsafe { ConnectNamedPipe(next.0, &mut ov) } == FALSE {
            // SAFETY: reads the calling thread's last error.
            let code = unsafe { GetLastError() } as i32;
            match code {
                ERROR_PIPE_CONNECTED => {}
                ERROR_IO_PENDING => {
                    let mut n: Dword = 0;
                    // SAFETY: waits on this operation's own overlapped structure.
                    check(unsafe { GetOverlappedResult(next.0, &mut ov, &mut n, TRUE) })?;
                }
                _ => return Err(io::Error::from_raw_os_error(code)),
            }
        }
        let fresh = create_instance(&self.name, &self.descriptor, false)?;
        let connected = std::mem::replace(&mut *next, fresh);
        Ok(PipeConn::new(connected))
    }
}

/// Check that the pipe's owner is the current account, as PuTTY does before it
/// trusts a connection.
fn verify_owner(pipe: Handle) -> io::Result<()> {
    let mut owner: *mut c_void = null_mut();
    let mut descriptor: *mut c_void = null_mut();
    // SAFETY: the out pointers are valid. The descriptor is freed below.
    let rc = unsafe {
        GetSecurityInfo(
            pipe,
            SE_KERNEL_OBJECT,
            OWNER_SECURITY_INFORMATION,
            &mut owner,
            null_mut(),
            null_mut(),
            null_mut(),
            &mut descriptor,
        )
    };
    if rc != 0 {
        return Err(io::Error::from_raw_os_error(rc as i32));
    }
    let me = UserSid::current()?;
    // SAFETY: both SIDs are valid for the duration of the call.
    let same = unsafe { EqualSid(owner, me.sid()) } != FALSE;
    // SAFETY: descriptor was allocated by GetSecurityInfo, and owner points into it.
    unsafe {
        LocalFree(descriptor);
    }
    if same {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "owner of the control pipe is not the current user",
        ))
    }
}

/// Client side: open a master's pipe, retrying while every instance is busy.
///
/// Fails with NotFound when no master listens, and with PermissionDenied when the
/// pipe is owned by another account.
pub fn connect(name: &str) -> io::Result<PipeConn> {
    let w = wide(name);
    for _ in 0..50 {
        // SAFETY: w is NUL terminated. Connecting needs no security attributes.
        let h = unsafe {
            CreateFileW(
                w.as_ptr(),
                GENERIC_READ | GENERIC_WRITE,
                0,
                null(),
                OPEN_EXISTING,
                FILE_FLAG_OVERLAPPED,
                null_mut(),
            )
        };
        if h != INVALID_HANDLE {
            let conn = PipeConn::new(OwnedHandle(h));
            verify_owner(conn.handle.0)?;
            return Ok(conn);
        }
        let err = io::Error::last_os_error();
        match err.raw_os_error() {
            Some(ERROR_PIPE_BUSY) => {
                // SAFETY: waits for the server to create its next instance.
                check(unsafe { WaitNamedPipeW(w.as_ptr(), NMPWAIT_USE_DEFAULT_WAIT) })?;
            }
            Some(ERROR_FILE_NOT_FOUND) => {
                return Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    "no master is listening",
                ));
            }
            _ => return Err(err),
        }
    }
    Err(io::Error::new(
        io::ErrorKind::TimedOut,
        "every pipe instance stayed busy",
    ))
}

/// The pipe name for a ControlPath key: unique per account and per path. The
/// name carries no secret. The DACL and the owner check keep other accounts out.
pub fn carrier_name(key: &str) -> io::Result<String> {
    let user = current_user_name()?;
    let digest = Sha256::digest(key.as_bytes());
    let hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
    Ok(format!("{PIPE_PREFIX}.{user}.{hex}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn unique_name(tag: &str) -> String {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        carrier_name(&format!("test-{tag}-{}-{nanos}", std::process::id())).unwrap()
    }

    #[test]
    fn carrier_names_are_per_key() {
        let a = carrier_name("/home/u/.ssh/cm-a").unwrap();
        assert_eq!(a, carrier_name("/home/u/.ssh/cm-a").unwrap());
        assert_ne!(a, carrier_name("/home/u/.ssh/cm-b").unwrap());
        assert!(a.starts_with(r"\\.\pipe\puressh-mux."), "{a}");
    }

    #[test]
    fn pipe_round_trips_bytes_both_ways() {
        use std::io::{Read, Write};
        let name = unique_name("echo");
        let listener = PipeListener::bind(&name).unwrap();
        let server = thread::spawn(move || {
            let mut conn = listener.accept().unwrap();
            let mut buf = [0u8; 5];
            conn.read_exact(&mut buf).unwrap();
            conn.write_all(&buf).unwrap();
            conn
        });
        let mut client = connect(&name).unwrap();
        client.write_all(b"hello").unwrap();
        let mut back = [0u8; 5];
        client.read_exact(&mut back).unwrap();
        assert_eq!(&back, b"hello");
        drop(server.join());
    }

    #[test]
    fn second_bind_on_the_same_name_is_refused() {
        let name = unique_name("twice");
        let _first = PipeListener::bind(&name).unwrap();
        assert!(PipeListener::bind(&name).is_err());
    }

    #[test]
    fn connect_without_a_master_is_not_found() {
        let err = connect(&unique_name("absent"))
            .err()
            .expect("no pipe should exist");
        assert_eq!(err.kind(), io::ErrorKind::NotFound);
    }

    #[test]
    fn read_timeout_reports_timed_out() {
        use std::io::Read;
        let name = unique_name("timeout");
        let listener = PipeListener::bind(&name).unwrap();
        let server = thread::spawn(move || listener.accept().unwrap());
        let mut client = connect(&name).unwrap();
        client
            .set_read_timeout(Some(Duration::from_millis(50)))
            .unwrap();
        let mut buf = [0u8; 1];
        let err = client.read(&mut buf).expect_err("nothing was written");
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
        drop(server.join());
    }

    #[test]
    fn shutdown_wakes_a_blocked_reader() {
        use std::io::Read;
        let name = unique_name("shutdown");
        let listener = PipeListener::bind(&name).unwrap();
        let server = thread::spawn(move || listener.accept().unwrap());
        let client = connect(&name).unwrap();
        let mut reader = client.try_clone().unwrap();
        let blocked = thread::spawn(move || {
            let mut buf = [0u8; 1];
            reader.read(&mut buf).unwrap()
        });
        thread::sleep(Duration::from_millis(100));
        client.shutdown(Shutdown::Both).unwrap();
        assert_eq!(blocked.join().unwrap(), 0);
        drop(server.join());
    }

    #[test]
    fn try_clone_shares_the_connection() {
        use std::io::{Read, Write};
        let name = unique_name("clone");
        let listener = PipeListener::bind(&name).unwrap();
        let server = thread::spawn(move || {
            let mut conn = listener.accept().unwrap();
            let mut buf = [0u8; 4];
            conn.read_exact(&mut buf).unwrap();
            conn.write_all(&buf).unwrap();
            conn
        });
        let mut client = connect(&name).unwrap();
        let mut writer = client.try_clone().unwrap();
        writer.write_all(b"ping").unwrap();
        let mut back = [0u8; 4];
        client.read_exact(&mut back).unwrap();
        assert_eq!(&back, b"ping");
        drop(server.join());
    }
}
