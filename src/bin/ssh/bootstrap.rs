//! Background ControlPersist master for Windows.
//!
//! ControlPersist needs a master that outlives the ssh invocation which started it,
//! and Windows has no fork. So the master is a detached copy of this program, started
//! with the DAEMON_ENV variable set. The copy connects and authenticates on its own.
//! When it needs a prompt answered (host key confirmation, a password), the prompt
//! travels over its stdout to the launching process, which asks the user at its own
//! terminal and sends the answer back on the copy's stdin. Once the control pipe is
//! bound, the copy sends Ready, and the launching process attaches to it as an
//! ordinary mux client.
//!
//! Stdin and stdout are the control channel in master mode, so nothing else may write
//! to stdout there. Diagnostics go to stderr, which the launcher points at a log file.

#![allow(dead_code)]

use std::io::{self, Read, Write};
#[cfg(all(windows, feature = "win-ipc"))]
use std::path::{Path, PathBuf};

use purecrypto::zeroize::Zeroizing;

/// Environment variable that marks a process as the background master.
pub const DAEMON_ENV: &str = "PURESSH_MUX_DAEMON";

/// Largest payload accepted in one frame. Prompts and answers are far smaller.
const MAX_PAYLOAD: usize = 64 * 1024;

/// One message on the control channel. Deliberately not Debug: an answer holds a
/// password.
pub enum Frame {
    /// Master to launcher: a prompt. The secret flag asks for no echo.
    Prompt { secret: bool, text: String },
    /// Launcher to master: the answer to the last prompt.
    Answer(Zeroizing<String>),
    /// Master to launcher: the control pipe is bound and the master is serving.
    Ready,
    /// Master to launcher: startup failed, and the message says why.
    Error(String),
}

/// Whether this process is the background master started by a launcher.
pub fn is_daemon() -> bool {
    std::env::var_os(DAEMON_ENV).is_some_and(|v| !v.is_empty())
}

fn invalid(msg: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg.into())
}

/// Write one frame: a kind byte, a 4-byte big-endian length, then the payload.
pub fn write_frame<W: Write + ?Sized>(w: &mut W, frame: &Frame) -> io::Result<()> {
    let (kind, payload): (u8, Zeroizing<Vec<u8>>) = match frame {
        Frame::Prompt { secret, text } => {
            let mut p = Vec::with_capacity(text.len() + 1);
            p.push(u8::from(*secret));
            p.extend_from_slice(text.as_bytes());
            (b'P', Zeroizing::new(p))
        }
        Frame::Answer(answer) => (b'A', Zeroizing::new(answer.as_bytes().to_vec())),
        Frame::Ready => (b'R', Zeroizing::new(Vec::new())),
        Frame::Error(message) => (b'E', Zeroizing::new(message.as_bytes().to_vec())),
    };
    if payload.len() > MAX_PAYLOAD {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "frame payload too large",
        ));
    }
    let mut header = [0u8; 5];
    header[0] = kind;
    header[1..].copy_from_slice(&(payload.len() as u32).to_be_bytes());
    w.write_all(&header)?;
    w.write_all(&payload)?;
    w.flush()
}

/// Read one frame. An unknown kind, an oversized payload, or malformed text is an
/// error, and so is a stream that ends early.
pub fn read_frame<R: Read + ?Sized>(r: &mut R) -> io::Result<Frame> {
    let mut header = [0u8; 5];
    r.read_exact(&mut header)?;
    let len = u32::from_be_bytes([header[1], header[2], header[3], header[4]]) as usize;
    if len > MAX_PAYLOAD {
        return Err(invalid("frame payload too large"));
    }
    let mut payload = Zeroizing::new(vec![0u8; len]);
    r.read_exact(&mut payload)?;
    match header[0] {
        b'P' => {
            let (flag, text) = payload
                .split_first()
                .ok_or_else(|| invalid("empty prompt frame"))?;
            Ok(Frame::Prompt {
                secret: *flag != 0,
                text: utf8(text)?,
            })
        }
        b'A' => {
            let text = std::str::from_utf8(&payload).map_err(|_| invalid("answer is not UTF-8"))?;
            Ok(Frame::Answer(Zeroizing::new(text.to_owned())))
        }
        b'R' if len == 0 => Ok(Frame::Ready),
        b'E' => Ok(Frame::Error(utf8(&payload)?)),
        other => Err(invalid(format!(
            "unknown frame kind 0x{other:02x} (or a Ready frame with a payload)"
        ))),
    }
}

fn utf8(bytes: &[u8]) -> io::Result<String> {
    std::str::from_utf8(bytes)
        .map(str::to_owned)
        .map_err(|_| invalid("frame text is not UTF-8"))
}

/// The master's prompt relay: a prompt goes to the launcher, and the answer comes back
/// on stdin.
pub struct FrameRelay;

impl crate::common::PromptRelay for FrameRelay {
    fn ask(&mut self, prompt: &str, secret: bool) -> io::Result<Zeroizing<String>> {
        {
            let mut out = io::stdout().lock();
            write_frame(
                &mut out,
                &Frame::Prompt {
                    secret,
                    text: prompt.to_string(),
                },
            )?;
        }
        let mut input = io::stdin().lock();
        match read_frame(&mut input)? {
            Frame::Answer(answer) => Ok(answer),
            _ => Err(invalid("the launcher sent something other than an answer")),
        }
    }
}

/// Route the master's prompts through the launcher.
pub fn install_relay() {
    crate::common::set_prompt_relay(Box::new(FrameRelay));
}

/// Tell the launcher why the master could not start. Called only in master mode.
pub fn report_failure(message: &str) {
    let mut out = io::stdout().lock();
    let _ = write_frame(&mut out, &Frame::Error(message.to_string()));
}

/// Serve the control pipe as the background master. Ready goes to the launcher as soon
/// as the pipe is bound, and before any client is served.
#[cfg(all(windows, feature = "win-ipc"))]
pub fn serve_background_master(
    dec: &super::MuxDecision,
    client: puressh::client::Client,
) -> Result<i32, String> {
    let cfg = puressh::mux::MasterConfig::new(dec.path.clone(), dec.persist);
    let shared: puressh::shared::SharedClient = client.into();
    puressh::mux::run_master_daemon_notify(cfg, shared, || {
        let mut out = io::stdout().lock();
        let _ = write_frame(&mut out, &Frame::Ready);
    })?;
    Ok(0)
}

/// Start the background master for control_path, and wait until it is ready. Prompts
/// the master raises are answered at this terminal. On failure the error is the
/// master's own message, or a description of what went wrong.
#[cfg(all(windows, feature = "win-ipc"))]
pub fn start_background_master(control_path: &Path) -> Result<(), String> {
    let exe = std::env::current_exe().map_err(|e| format!("mux: cannot locate ssh: {e}"))?;
    let args: Vec<std::ffi::OsString> = std::env::args_os().skip(1).collect();
    let log = log_path(control_path);
    let log_file =
        open_log(&log).map_err(|e| format!("mux: cannot open {}: {e}", log.display()))?;
    let (mut to_master, mut from_master) = spawn::spawn_master(&exe, &args, &log_file)
        .map_err(|e| format!("mux: cannot start the background master: {e}"))?;
    drop(log_file);
    crate::common::vlog(
        1,
        &format!("mux: background master started, log {}", log.display()),
    );
    loop {
        match read_frame(&mut from_master) {
            Ok(Frame::Prompt { secret, text }) => {
                let answer = crate::common::read_kbdint_response(&text, !secret).map_err(|e| {
                    format!("mux: cannot answer a prompt from the background master: {e}")
                })?;
                write_frame(&mut to_master, &Frame::Answer(answer))
                    .map_err(|e| format!("mux: cannot reach the background master: {e}"))?;
            }
            Ok(Frame::Ready) => return Ok(()),
            Ok(Frame::Error(message)) => return Err(message),
            Ok(Frame::Answer(_)) => {
                return Err("mux: unexpected answer from the background master".into());
            }
            Err(e) => {
                return Err(format!(
                    "mux: the background master exited before it was ready ({e}); see {}",
                    log.display()
                ));
            }
        }
    }
}

#[cfg(all(windows, feature = "win-ipc"))]
fn open_log(path: &Path) -> io::Result<std::fs::File> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
}

/// A log file per ControlPath, under the local application data directory.
#[cfg(all(windows, feature = "win-ipc"))]
fn log_path(control_path: &Path) -> PathBuf {
    let base = std::env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir);
    let name = control_path
        .file_name()
        .map(|n| {
            n.to_string_lossy()
                .chars()
                .map(|c| {
                    if c.is_ascii_alphanumeric() || c == '-' || c == '.' {
                        c
                    } else {
                        '_'
                    }
                })
                .collect::<String>()
        })
        .unwrap_or_else(|| "master".to_string());
    base.join("puressh")
        .join("logs")
        .join(format!("mux-{name}.log"))
}

/// Process creation for the background master.
///
/// std::process::Command passes bInheritHandles=TRUE, so the master would inherit every
/// inheritable handle of the launcher, including the launcher's stdout pipe. A master
/// that outlives the launcher would then keep that pipe open, and whoever waits for the
/// pipe to close would wait for the master to exit. This module starts the master with
/// a handle list instead: only the two control pipes and the log file are inherited.
#[cfg(all(windows, feature = "win-ipc"))]
mod spawn {
    use std::ffi::{OsStr, OsString, c_void};
    use std::fs::File;
    use std::io;
    use std::mem::size_of;
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::io::{AsRawHandle, FromRawHandle};
    use std::path::Path;
    use std::ptr::{null, null_mut};

    use super::DAEMON_ENV;

    type Handle = *mut c_void;

    const HANDLE_FLAG_INHERIT: u32 = 0x0000_0001;
    const STARTF_USESTDHANDLES: u32 = 0x0000_0100;
    const EXTENDED_STARTUPINFO_PRESENT: u32 = 0x0008_0000;
    const CREATE_UNICODE_ENVIRONMENT: u32 = 0x0000_0400;
    const DETACHED_PROCESS: u32 = 0x0000_0008;
    const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;
    const CREATE_BREAKAWAY_FROM_JOB: u32 = 0x0100_0000;
    const PROC_THREAD_ATTRIBUTE_HANDLE_LIST: usize = 0x0002_0002;
    const ERROR_ACCESS_DENIED: i32 = 5;

    #[repr(C)]
    struct SecurityAttributes {
        length: u32,
        security_descriptor: *mut c_void,
        inherit_handle: i32,
    }

    #[repr(C)]
    struct StartupInfoW {
        cb: u32,
        reserved: *mut u16,
        desktop: *mut u16,
        title: *mut u16,
        x: u32,
        y: u32,
        x_size: u32,
        y_size: u32,
        x_count_chars: u32,
        y_count_chars: u32,
        fill_attribute: u32,
        flags: u32,
        show_window: u16,
        cb_reserved2: u16,
        reserved2: *mut u8,
        std_input: Handle,
        std_output: Handle,
        std_error: Handle,
    }

    #[repr(C)]
    struct StartupInfoExW {
        startup_info: StartupInfoW,
        attribute_list: *mut c_void,
    }

    #[repr(C)]
    struct ProcessInformation {
        process: Handle,
        thread: Handle,
        process_id: u32,
        thread_id: u32,
    }

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn CreatePipe(
            read: *mut Handle,
            write: *mut Handle,
            attributes: *const SecurityAttributes,
            size: u32,
        ) -> i32;
        fn SetHandleInformation(object: Handle, mask: u32, flags: u32) -> i32;
        fn InitializeProcThreadAttributeList(
            list: *mut c_void,
            count: u32,
            flags: u32,
            size: *mut usize,
        ) -> i32;
        fn UpdateProcThreadAttribute(
            list: *mut c_void,
            flags: u32,
            attribute: usize,
            value: *const c_void,
            size: usize,
            previous: *mut c_void,
            return_size: *mut usize,
        ) -> i32;
        fn DeleteProcThreadAttributeList(list: *mut c_void);
        fn CreateProcessW(
            application: *const u16,
            command_line: *mut u16,
            process_attributes: *const c_void,
            thread_attributes: *const c_void,
            inherit_handles: i32,
            flags: u32,
            environment: *const c_void,
            directory: *const u16,
            startup: *mut StartupInfoExW,
            information: *mut ProcessInformation,
        ) -> i32;
        fn CloseHandle(object: Handle) -> i32;
    }

    /// A handle that is closed when dropped, unless it is given away with into_raw.
    struct Owned(Handle);

    impl Owned {
        fn raw(&self) -> Handle {
            self.0
        }

        fn into_raw(self) -> Handle {
            let handle = self.0;
            std::mem::forget(self);
            handle
        }
    }

    impl Drop for Owned {
        fn drop(&mut self) {
            // SAFETY: the handle is owned by this value and is closed exactly once.
            unsafe {
                CloseHandle(self.0);
            }
        }
    }

    /// A process attribute list, deleted when dropped. Its storage is aligned for
    /// pointers.
    struct AttributeList {
        storage: Vec<usize>,
        ptr: *mut c_void,
    }

    impl AttributeList {
        fn new() -> io::Result<Self> {
            let mut size = 0usize;
            // SAFETY: a null list with a size out-pointer is the documented size query.
            unsafe { InitializeProcThreadAttributeList(null_mut(), 1, 0, &mut size) };
            let words = size.div_ceil(size_of::<usize>()).max(1);
            let mut storage = vec![0usize; words];
            let ptr = storage.as_mut_ptr().cast::<c_void>();
            // SAFETY: storage holds at least size bytes and is pointer-aligned.
            if unsafe { InitializeProcThreadAttributeList(ptr, 1, 0, &mut size) } == 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(AttributeList { storage, ptr })
        }

        fn set_handle_list(&mut self, handles: &[Handle]) -> io::Result<()> {
            // SAFETY: the list was initialised above, and handles stays alive for the call.
            let ok = unsafe {
                UpdateProcThreadAttribute(
                    self.ptr,
                    0,
                    PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
                    handles.as_ptr().cast::<c_void>(),
                    size_of_val(handles),
                    null_mut(),
                    null_mut(),
                )
            };
            if ok == 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        }
    }

    impl Drop for AttributeList {
        fn drop(&mut self) {
            let _ = &self.storage;
            // SAFETY: the list was initialised by InitializeProcThreadAttributeList.
            unsafe { DeleteProcThreadAttributeList(self.ptr) };
        }
    }

    /// Start the background master with exe and args. Its stdin and stdout are the
    /// returned control pipes (to_master, from_master). Its stderr is log, and nothing
    /// else is inherited.
    pub fn spawn_master(exe: &Path, args: &[OsString], log: &File) -> io::Result<(File, File)> {
        let inheritable = SecurityAttributes {
            length: size_of::<SecurityAttributes>() as u32,
            security_descriptor: null_mut(),
            inherit_handle: 1,
        };

        // The master reads stdin from in_read, and the launcher writes to in_write.
        let mut in_read: Handle = null_mut();
        let mut in_write: Handle = null_mut();
        // SAFETY: the out-pointers are valid, and the attributes outlive the call.
        if unsafe { CreatePipe(&mut in_read, &mut in_write, &inheritable, 0) } == 0 {
            return Err(io::Error::last_os_error());
        }
        let in_read = Owned(in_read);
        let in_write = Owned(in_write);

        // The master writes stdout to out_write, and the launcher reads from out_read.
        let mut out_read: Handle = null_mut();
        let mut out_write: Handle = null_mut();
        // SAFETY: as above.
        if unsafe { CreatePipe(&mut out_read, &mut out_write, &inheritable, 0) } == 0 {
            return Err(io::Error::last_os_error());
        }
        let out_read = Owned(out_read);
        let out_write = Owned(out_write);

        // The launcher keeps only its own ends.
        for end in [in_write.raw(), out_read.raw()] {
            // SAFETY: end is a live handle owned by this function.
            if unsafe { SetHandleInformation(end, HANDLE_FLAG_INHERIT, 0) } == 0 {
                return Err(io::Error::last_os_error());
            }
        }
        let log_handle = log.as_raw_handle() as Handle;
        // SAFETY: log_handle is a live file handle owned by the caller.
        if unsafe { SetHandleInformation(log_handle, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT) }
            == 0
        {
            return Err(io::Error::last_os_error());
        }

        let handles = [in_read.raw(), out_write.raw(), log_handle];
        let mut attributes = AttributeList::new()?;
        attributes.set_handle_list(&handles)?;
        let mut startup = StartupInfoExW {
            startup_info: StartupInfoW {
                cb: size_of::<StartupInfoExW>() as u32,
                reserved: null_mut(),
                desktop: null_mut(),
                title: null_mut(),
                x: 0,
                y: 0,
                x_size: 0,
                y_size: 0,
                x_count_chars: 0,
                y_count_chars: 0,
                fill_attribute: 0,
                flags: STARTF_USESTDHANDLES,
                show_window: 0,
                cb_reserved2: 0,
                reserved2: null_mut(),
                std_input: in_read.raw(),
                std_output: out_write.raw(),
                std_error: log_handle,
            },
            attribute_list: attributes.ptr,
        };

        let application: Vec<u16> = exe.as_os_str().encode_wide().chain(Some(0)).collect();
        let mut command_line = command_line(exe.as_os_str(), args);
        let environment = environment_block();
        let base_flags = DETACHED_PROCESS
            | CREATE_NEW_PROCESS_GROUP
            | EXTENDED_STARTUPINFO_PRESENT
            | CREATE_UNICODE_ENVIRONMENT;
        let mut info = ProcessInformation {
            process: null_mut(),
            thread: null_mut(),
            process_id: 0,
            thread_id: 0,
        };
        let mut create = |flags: u32, info: &mut ProcessInformation| {
            // SAFETY: every pointer is valid for the call. The handle list names only
            // handles that are alive and inheritable.
            unsafe {
                CreateProcessW(
                    application.as_ptr(),
                    command_line.as_mut_ptr(),
                    null(),
                    null(),
                    1,
                    flags,
                    environment.as_ptr().cast::<c_void>(),
                    null(),
                    &mut startup,
                    info,
                )
            }
        };
        let mut created = create(base_flags | CREATE_BREAKAWAY_FROM_JOB, &mut info);
        if created == 0 && io::Error::last_os_error().raw_os_error() == Some(ERROR_ACCESS_DENIED) {
            // The launcher's job object may forbid breakaway. The master then stays in it.
            created = create(base_flags, &mut info);
        }
        if created == 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: the handles came from CreateProcessW. The master keeps running after
        // these are closed.
        unsafe {
            CloseHandle(info.thread);
            CloseHandle(info.process);
        }
        drop(in_read);
        drop(out_write);
        // SAFETY: each handle is a valid pipe end that nothing else owns.
        let to_master = unsafe { File::from_raw_handle(in_write.into_raw()) };
        let from_master = unsafe { File::from_raw_handle(out_read.into_raw()) };
        Ok((to_master, from_master))
    }

    /// Quote one argument the way the Microsoft C runtime parses it.
    fn append_arg(cmd: &mut Vec<u16>, arg: &OsStr) {
        const QUOTE: u16 = b'"' as u16;
        const BACKSLASH: u16 = b'\\' as u16;
        const SPACE: u16 = b' ' as u16;
        const TAB: u16 = b'\t' as u16;
        let wide: Vec<u16> = arg.encode_wide().collect();
        let needs_quotes =
            wide.is_empty() || wide.iter().any(|&c| c == SPACE || c == TAB || c == QUOTE);
        if !needs_quotes {
            cmd.extend_from_slice(&wide);
            return;
        }
        cmd.push(QUOTE);
        let mut backslashes = 0usize;
        for &c in &wide {
            if c == BACKSLASH {
                backslashes += 1;
            } else {
                if c == QUOTE {
                    // n backslashes before a quote become 2n+1.
                    cmd.extend(std::iter::repeat_n(BACKSLASH, backslashes + 1));
                }
                backslashes = 0;
            }
            cmd.push(c);
        }
        // Trailing backslashes double, so they do not escape the closing quote.
        cmd.extend(std::iter::repeat_n(BACKSLASH, backslashes));
        cmd.push(QUOTE);
    }

    /// The command line for exe and args, NUL terminated.
    fn command_line(exe: &OsStr, args: &[OsString]) -> Vec<u16> {
        let mut cmd = Vec::new();
        append_arg(&mut cmd, exe);
        for arg in args {
            cmd.push(u16::from(b' '));
            append_arg(&mut cmd, arg);
        }
        cmd.push(0);
        cmd
    }

    /// The current environment with DAEMON_ENV=1, as a double-NUL terminated block.
    fn environment_block() -> Vec<u16> {
        let mut block: Vec<u16> = Vec::new();
        for (name, value) in std::env::vars_os() {
            if name.to_string_lossy().eq_ignore_ascii_case(DAEMON_ENV) {
                continue;
            }
            block.extend(name.encode_wide());
            block.push(u16::from(b'='));
            block.extend(value.encode_wide());
            block.push(0);
        }
        block.extend(format!("{DAEMON_ENV}=1").encode_utf16());
        block.push(0);
        block.push(0);
        block
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn encode(frame: &Frame) -> Vec<u8> {
        let mut wire = Vec::new();
        write_frame(&mut wire, frame).expect("encode");
        wire
    }

    fn decode(wire: Vec<u8>) -> io::Result<Frame> {
        read_frame(&mut Cursor::new(wire))
    }

    #[test]
    fn prompt_keeps_text_and_secret_flag() {
        let frame = Frame::Prompt {
            secret: true,
            text: "password: ".to_string(),
        };
        match decode(encode(&frame)).expect("decode") {
            Frame::Prompt { secret, text } => {
                assert!(secret);
                assert_eq!(text, "password: ");
            }
            _ => panic!("expected a prompt frame"),
        }
    }

    #[test]
    fn answer_round_trips() {
        let frame = Frame::Answer(Zeroizing::new("yes".to_string()));
        match decode(encode(&frame)).expect("decode") {
            Frame::Answer(answer) => assert_eq!(answer.as_str(), "yes"),
            _ => panic!("expected an answer frame"),
        }
    }

    #[test]
    fn ready_and_error_round_trip() {
        assert!(matches!(
            decode(encode(&Frame::Ready)).expect("decode"),
            Frame::Ready
        ));
        match decode(encode(&Frame::Error("bind failed".to_string()))).expect("decode") {
            Frame::Error(message) => assert_eq!(message, "bind failed"),
            _ => panic!("expected an error frame"),
        }
    }

    #[test]
    fn unknown_kind_is_rejected() {
        assert!(decode(vec![b'Z', 0, 0, 0, 0]).is_err());
    }

    #[test]
    fn ready_with_payload_is_rejected() {
        assert!(decode(vec![b'R', 0, 0, 0, 1, b'x']).is_err());
    }

    #[test]
    fn oversized_payload_is_rejected_before_allocating() {
        let len = (MAX_PAYLOAD as u32 + 1).to_be_bytes();
        assert!(decode(vec![b'E', len[0], len[1], len[2], len[3]]).is_err());
    }

    #[test]
    fn non_utf8_answer_is_rejected() {
        assert!(decode(vec![b'A', 0, 0, 0, 1, 0xff]).is_err());
    }

    #[test]
    fn truncated_frame_is_an_error() {
        assert!(decode(vec![b'R', 0, 0]).is_err());
    }
}
