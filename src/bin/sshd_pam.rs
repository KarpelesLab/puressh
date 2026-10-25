//! A minimal Linux-PAM client: just what sshd needs (`pam_start`, items,
//! `authenticate`/`acct_mgmt`, a session with its credentials, the PAM
//! environment, `pam_end`).
//!
//! libpam is loaded at run time through `dlsym`, so building needs no
//! libpam headers and the binary has no link-time libpam dependency: a
//! system without it fails the first PAM call instead of refusing to start.
//! The constants and struct layouts are Linux-PAM's (OpenPAM numbers its
//! error codes differently), hence the Linux-only gate on the module.

use std::ffi::{CStr, CString, c_char, c_int, c_void};
use std::sync::OnceLock;

use dlsym::Bindings;
use purecrypto::zeroize::{Zeroize, Zeroizing};

const PAM_SUCCESS: c_int = 0;
const PAM_BUF_ERR: c_int = 5;
const PAM_CONV_ERR: c_int = 19;

const PAM_SILENT: c_int = 0x8000;
const PAM_ESTABLISH_CRED: c_int = 0x2;
const PAM_DELETE_CRED: c_int = 0x4;
const PAM_REINITIALIZE_CRED: c_int = 0x8;

const PAM_TTY: c_int = 3;
const PAM_RHOST: c_int = 4;

const PAM_PROMPT_ECHO_OFF: c_int = 1;
const PAM_PROMPT_ECHO_ON: c_int = 2;
const PAM_ERROR_MSG: c_int = 3;
const PAM_TEXT_INFO: c_int = 4;

const PAM_MAX_NUM_MSG: c_int = 32;

#[repr(C)]
struct PamMessage {
    msg_style: c_int,
    msg: *const c_char,
}

#[repr(C)]
struct PamResponse {
    resp: *mut c_char,
    resp_retcode: c_int,
}

type ConvFn = unsafe extern "C" fn(
    num_msg: c_int,
    msg: *mut *const PamMessage,
    resp: *mut *mut PamResponse,
    appdata_ptr: *mut c_void,
) -> c_int;

#[repr(C)]
struct PamConv {
    conv: ConvFn,
    appdata_ptr: *mut c_void,
}

dlsym::library! {
    struct LibPam {
        unsafe extern "C" {
            fn pam_start(
                service: *const c_char,
                user: *const c_char,
                conv: *const PamConv,
                pamh: *mut *mut c_void,
            ) -> c_int;
            fn pam_end(pamh: *mut c_void, status: c_int) -> c_int;
            fn pam_set_item(pamh: *mut c_void, item_type: c_int, item: *const c_void) -> c_int;
            fn pam_authenticate(pamh: *mut c_void, flags: c_int) -> c_int;
            fn pam_acct_mgmt(pamh: *mut c_void, flags: c_int) -> c_int;
            fn pam_setcred(pamh: *mut c_void, flags: c_int) -> c_int;
            fn pam_open_session(pamh: *mut c_void, flags: c_int) -> c_int;
            fn pam_close_session(pamh: *mut c_void, flags: c_int) -> c_int;
            fn pam_getenvlist(pamh: *mut c_void) -> *mut *mut c_char;
            fn pam_strerror(pamh: *mut c_void, errnum: c_int) -> *const c_char;
        }
    }
}

/// libpam, opened on first use and kept for the life of the process (PAM
/// modules are not safe to unload from under a live handle anyway).
fn libpam() -> Result<&'static LibPam, Error> {
    static LIB: OnceLock<Result<LibPam, String>> = OnceLock::new();
    LIB.get_or_init(|| {
        // SAFETY: libpam's initialisers are trusted, as they are for any
        // program linked against it.
        unsafe { LibPam::open_first(["libpam.so.0", "libpam.so"]) }.map_err(|e| e.to_string())
    })
    .as_ref()
    .map_err(|e| Error(format!("cannot load libpam: {e}")))
}

/// A failed PAM call, with libpam's description of the code.
#[derive(Debug)]
pub struct Error(String);

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Answers the messages of a PAM conversation.
pub trait ConversationHandler {
    /// A prompt; `echo` is true for a visible one. `None` fails the
    /// conversation (`PAM_CONV_ERR`), as does an answer containing a NUL.
    fn prompt(&mut self, prompt: &CStr, echo: bool) -> Option<Zeroizing<Vec<u8>>>;
    /// A `PAM_TEXT_INFO` (`error` false) or `PAM_ERROR_MSG` (`error` true)
    /// message.
    fn info(&mut self, msg: &CStr, error: bool);
}

/// Refuses every prompt and ignores messages: for transactions that only
/// manage the account and session, never authenticate.
pub struct NullConversation;

impl ConversationHandler for NullConversation {
    fn prompt(&mut self, _prompt: &CStr, _echo: bool) -> Option<Zeroizing<Vec<u8>>> {
        None
    }
    fn info(&mut self, _msg: &CStr, _error: bool) {}
}

/// Wipe and free the first `n` replies of `replies`, then the array.
///
/// # Safety
///
/// `replies` is a `calloc`ed array of `n` responses whose `resp` fields are
/// null or `malloc`ed NUL-terminated strings.
unsafe fn free_replies(replies: *mut PamResponse, n: usize) {
    for i in 0..n {
        // SAFETY: `i < n`, within the array.
        let resp = unsafe { (*replies.add(i)).resp };
        if !resp.is_null() {
            // SAFETY: `resp` is a live NUL-terminated `malloc`ed string.
            let len = unsafe { libc::strlen(resp) };
            // SAFETY: the `len` bytes before the NUL belong to `resp`.
            unsafe { std::slice::from_raw_parts_mut(resp.cast::<u8>(), len) }.zeroize();
            // SAFETY: `resp` came from `malloc` and is freed once.
            unsafe { libc::free(resp.cast()) };
        }
    }
    // SAFETY: the array came from `calloc` and is freed once.
    unsafe { libc::free(replies.cast()) };
}

/// The `pam_conv` callback: dispatches each message to the handler `C` at
/// `appdata_ptr` and hands PAM a `malloc`ed reply array, as it expects.
unsafe extern "C" fn converse<C: ConversationHandler>(
    num_msg: c_int,
    msg: *mut *const PamMessage,
    resp: *mut *mut PamResponse,
    appdata_ptr: *mut c_void,
) -> c_int {
    if !(1..=PAM_MAX_NUM_MSG).contains(&num_msg)
        || msg.is_null()
        || resp.is_null()
        || appdata_ptr.is_null()
    {
        return PAM_CONV_ERR;
    }
    let n = num_msg as usize;
    // SAFETY: `appdata_ptr` is the `Box<C>` that `Context::new` registered,
    // and libpam calls the conversation from one thread at a time.
    let handler = unsafe { &mut *appdata_ptr.cast::<C>() };
    // SAFETY: plain allocation; zeroed, so every `resp` starts null.
    let replies = unsafe { libc::calloc(n, size_of::<PamResponse>()) }.cast::<PamResponse>();
    if replies.is_null() {
        return PAM_BUF_ERR;
    }
    for i in 0..n {
        // Linux-PAM passes an array of `n` message pointers.
        // SAFETY: `i < n` and `msg` is non-null.
        let m = unsafe { *msg.add(i) };
        if m.is_null() {
            // SAFETY: `replies` holds `n` responses, null or ours.
            unsafe { free_replies(replies, n) };
            return PAM_CONV_ERR;
        }
        // SAFETY: a non-null message from libpam.
        let (style, text) = unsafe { ((*m).msg_style, (*m).msg) };
        let text = if text.is_null() {
            c""
        } else {
            // SAFETY: text messages are NUL-terminated strings.
            unsafe { CStr::from_ptr(text) }
        };
        let ok = match style {
            PAM_PROMPT_ECHO_OFF | PAM_PROMPT_ECHO_ON => {
                match handler.prompt(text, style == PAM_PROMPT_ECHO_ON) {
                    Some(answer) if !answer.contains(&0) => {
                        // SAFETY: plain allocation.
                        let p = unsafe { libc::malloc(answer.len() + 1) }.cast::<u8>();
                        if !p.is_null() {
                            // SAFETY: `p` has room for the answer and its NUL.
                            unsafe {
                                std::ptr::copy_nonoverlapping(answer.as_ptr(), p, answer.len());
                            }
                            // SAFETY: as above.
                            unsafe { *p.add(answer.len()) = 0 };
                            // SAFETY: `i < n`; PAM frees the string.
                            unsafe { (*replies.add(i)).resp = p.cast() };
                        }
                        !p.is_null()
                    }
                    _ => false,
                }
            }
            PAM_ERROR_MSG | PAM_TEXT_INFO => {
                handler.info(text, style == PAM_ERROR_MSG);
                true
            }
            // Linux-PAM's binary and radio prompts are never answered.
            _ => false,
        };
        if !ok {
            // SAFETY: `replies` holds `n` responses, null or ours.
            unsafe { free_replies(replies, n) };
            return PAM_CONV_ERR;
        }
    }
    // SAFETY: `resp` is non-null; PAM takes ownership of the array.
    unsafe { *resp = replies };
    PAM_SUCCESS
}

/// A PAM transaction (`pam_start` … `pam_end`) with conversation `C`.
///
/// An opened session is closed, and its credentials deleted, on drop.
pub struct Context<C: ConversationHandler> {
    lib: &'static LibPam,
    handle: *mut c_void,
    /// The status of the last PAM call, passed to `pam_end`.
    last: c_int,
    session: bool,
    // The callback's `appdata_ptr` is `handler`, from `Box::into_raw`:
    // both must outlive `handle`, which `Drop` ends first.
    _conv: Box<PamConv>,
    handler: *mut C,
}

// SAFETY: the handle is only used through `&mut self` (or in `Drop`), so
// moving the context moves sole access to it; the handler moves along.
unsafe impl<C: ConversationHandler + Send> Send for Context<C> {}

impl<C: ConversationHandler> Context<C> {
    /// `pam_start` for `user` of `service`.
    pub fn new(service: &str, user: &str, handler: C) -> Result<Self, Error> {
        let lib = libpam()?;
        let service = CString::new(service).map_err(|_| Error("NUL in service".into()))?;
        let user = CString::new(user).map_err(|_| Error("NUL in user".into()))?;
        let handler = Box::into_raw(Box::new(handler));
        let conv = Box::new(PamConv {
            conv: converse::<C>,
            appdata_ptr: handler.cast(),
        });
        let mut handle = std::ptr::null_mut();
        // SAFETY: valid C strings; `conv` and the handler it points to live
        // in boxes owned by the returned context, until after `pam_end`.
        let rc = unsafe { lib.pam_start(service.as_ptr(), user.as_ptr(), &*conv, &mut handle) };
        if rc != PAM_SUCCESS || handle.is_null() {
            // SAFETY: from `Box::into_raw` above, and PAM never got to use it.
            drop(unsafe { Box::from_raw(handler) });
            // SAFETY: `pam_strerror` accepts a null handle and returns a
            // static string.
            return Err(unsafe { describe(lib, std::ptr::null_mut(), rc) });
        }
        Ok(Self {
            lib,
            handle,
            last: PAM_SUCCESS,
            session: false,
            _conv: conv,
            handler,
        })
    }

    fn check(&mut self, rc: c_int) -> Result<(), Error> {
        self.last = rc;
        if rc == PAM_SUCCESS {
            Ok(())
        } else {
            // SAFETY: `self.handle` is live.
            Err(unsafe { describe(self.lib, self.handle, rc) })
        }
    }

    fn set_str_item(&mut self, item: c_int, value: &str) -> Result<(), Error> {
        let value = CString::new(value).map_err(|_| Error("NUL in PAM item".into()))?;
        // SAFETY: live handle; libpam copies the string.
        let rc = unsafe {
            self.lib
                .pam_set_item(self.handle, item, value.as_ptr().cast())
        };
        self.check(rc)
    }

    /// Set `PAM_RHOST`.
    pub fn set_rhost(&mut self, rhost: &str) -> Result<(), Error> {
        self.set_str_item(PAM_RHOST, rhost)
    }

    /// Set `PAM_TTY`.
    pub fn set_tty(&mut self, tty: &str) -> Result<(), Error> {
        self.set_str_item(PAM_TTY, tty)
    }

    /// `pam_authenticate`, which drives the conversation.
    pub fn authenticate(&mut self) -> Result<(), Error> {
        // SAFETY: live handle.
        let rc = unsafe { self.lib.pam_authenticate(self.handle, 0) };
        self.check(rc)
    }

    /// `pam_acct_mgmt`.
    pub fn acct_mgmt(&mut self) -> Result<(), Error> {
        // SAFETY: live handle.
        let rc = unsafe { self.lib.pam_acct_mgmt(self.handle, 0) };
        self.check(rc)
    }

    /// Establish credentials and open the session, then reinitialise the
    /// credentials (modules disagree on whether `setcred` comes before or
    /// after `open_session`; OpenSSH covers both the same way). Undone on
    /// failure.
    pub fn open_session(&mut self) -> Result<(), Error> {
        let (lib, h) = (self.lib, self.handle);
        // SAFETY (all calls below): live handle.
        let rc = unsafe { lib.pam_setcred(h, PAM_ESTABLISH_CRED) };
        self.check(rc)?;
        let rc = unsafe { lib.pam_open_session(h, 0) };
        if let Err(e) = self.check(rc) {
            unsafe { lib.pam_setcred(h, PAM_DELETE_CRED) };
            return Err(e);
        }
        let rc = unsafe { lib.pam_setcred(h, PAM_REINITIALIZE_CRED) };
        if let Err(e) = self.check(rc) {
            unsafe { lib.pam_close_session(h, 0) };
            unsafe { lib.pam_setcred(h, PAM_DELETE_CRED) };
            return Err(e);
        }
        self.session = true;
        Ok(())
    }

    /// The PAM environment (`pam_getenvlist`), as `(name, value)` pairs.
    pub fn envlist(&mut self) -> Vec<(CString, CString)> {
        let mut out = Vec::new();
        // SAFETY: live handle.
        let list = unsafe { self.lib.pam_getenvlist(self.handle) };
        if list.is_null() {
            return out;
        }
        let mut i = 0;
        loop {
            // SAFETY: a NULL-terminated array of `malloc`ed strings, which
            // the caller frees.
            let entry = unsafe { *list.add(i) };
            if entry.is_null() {
                break;
            }
            // SAFETY: each entry is a NUL-terminated `NAME=value`.
            let bytes = unsafe { CStr::from_ptr(entry) }.to_bytes();
            if let Some(eq) = bytes.iter().position(|&b| b == b'=')
                && let (Ok(k), Ok(v)) = (CString::new(&bytes[..eq]), CString::new(&bytes[eq + 1..]))
            {
                out.push((k, v));
            }
            // SAFETY: freed once, after its last use.
            unsafe { libc::free(entry.cast()) };
            i += 1;
        }
        // SAFETY: the array itself is `malloc`ed too.
        unsafe { libc::free(list.cast()) };
        out
    }
}

impl<C: ConversationHandler> Drop for Context<C> {
    fn drop(&mut self) {
        let (lib, h) = (self.lib, self.handle);
        if self.session {
            // SAFETY: live handle.
            self.last = unsafe { lib.pam_close_session(h, 0) };
            // SAFETY: live handle.
            self.last = unsafe { lib.pam_setcred(h, PAM_DELETE_CRED | PAM_SILENT) };
        }
        // SAFETY: live handle, ended once.
        unsafe { lib.pam_end(h, self.last) };
        // SAFETY: from `Box::into_raw` in `new`; PAM is done with it.
        drop(unsafe { Box::from_raw(self.handler) });
    }
}

/// libpam's text for `rc`.
///
/// # Safety
///
/// `handle` is null or a live PAM handle.
unsafe fn describe(lib: &LibPam, handle: *mut c_void, rc: c_int) -> Error {
    // SAFETY: forwarded to the caller; the result is a static string.
    let s = unsafe { lib.pam_strerror(handle, rc) };
    if s.is_null() {
        Error(format!("error {rc}"))
    } else {
        // SAFETY: a NUL-terminated string.
        Error(unsafe { CStr::from_ptr(s) }.to_string_lossy().into_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Records each prompt and answers it with a wrong password.
    struct Wrong(Vec<(String, bool)>);

    impl ConversationHandler for Wrong {
        fn prompt(&mut self, prompt: &CStr, echo: bool) -> Option<Zeroizing<Vec<u8>>> {
            self.0.push((prompt.to_string_lossy().into_owned(), echo));
            Some(Zeroizing::new(b"definitely-not-the-password".to_vec()))
        }
        fn info(&mut self, _msg: &CStr, _error: bool) {}
    }

    /// Against the host's real `sshd` PAM stack (so not hermetic, hence
    /// ignored): the password prompt must reach the handler, and the wrong
    /// answer must be refused with libpam's own error text.
    #[test]
    #[ignore = "uses the host's PAM configuration"]
    fn wrong_password_is_refused() {
        let user = std::env::var("USER").expect("USER");
        let mut ctx = Context::new("sshd", &user, Wrong(Vec::new())).expect("pam_start");
        ctx.set_rhost("127.0.0.1").expect("set_rhost");
        let err = ctx.authenticate().expect_err("wrong password accepted");
        // SAFETY: the handler is alive until `ctx` drops.
        let prompts = &unsafe { &*ctx.handler }.0;
        eprintln!("prompts={prompts:?} err={err}");
        assert!(prompts.iter().any(|(_, echo)| !echo), "no echo-off prompt");
        assert!(!err.to_string().is_empty());
    }
}
