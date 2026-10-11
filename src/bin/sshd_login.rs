//! Login records for pty sessions, written as OpenSSH writes them: utmp
//! (`who`, `w`), wtmp (`last`) and lastlog (`lastlog`, and the `Last
//! login: … from …` line PrintLastLog shows at the next login).
//!
//! glibc's utmpx API (the `libc` crate lacks `updwtmpx`, which glibc
//! exports). Records are only writable as root; failures are ignored, as
//! OpenSSH ignores them.

use std::ffi::c_char;
use std::io::{Read, Seek, SeekFrom, Write};
use std::net::IpAddr;

const LASTLOG: &str = "/var/log/lastlog";

unsafe extern "C" {
    fn updwtmpx(file: *const c_char, ut: *const libc::utmpx);
}

/// Copy `s` into a fixed-size record field, truncated, zero-padded.
fn put(dst: &mut [c_char], s: &str) {
    dst.fill(0);
    for (d, b) in dst.iter_mut().zip(s.bytes()) {
        *d = b as c_char;
    }
}

/// `pts/3` for `/dev/pts/3`.
fn line_of(tty: &str) -> &str {
    tty.strip_prefix("/dev/").unwrap_or(tty)
}

fn now() -> std::time::Duration {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
}

fn record(
    kind: libc::c_short,
    pid: i32,
    line: &str,
    user: &str,
    host: &str,
    addr: Option<IpAddr>,
) -> libc::utmpx {
    // SAFETY: utmpx is plain data; all-zero is its empty value.
    let mut ut: libc::utmpx = unsafe { std::mem::zeroed() };
    ut.ut_type = kind;
    ut.ut_pid = pid;
    put(&mut ut.ut_line, line);
    // The id is the line's last four characters (OpenSSH's
    // line_abbrevname): `ts/3`, `s/12`.
    let id = &line[line.len().saturating_sub(4)..];
    put(&mut ut.ut_id, id);
    put(&mut ut.ut_user, user);
    put(&mut ut.ut_host, host);
    let t = now();
    ut.ut_tv.tv_sec = t.as_secs() as _;
    ut.ut_tv.tv_usec = t.subsec_micros() as _;
    // The address in network byte order, as copied from a sockaddr.
    let words = |b: &[u8]| {
        let mut w = [0i32; 4];
        for (i, c) in b.chunks(4).enumerate() {
            w[i] = i32::from_ne_bytes([c[0], c[1], c[2], c[3]]);
        }
        w
    };
    ut.ut_addr_v6 = match addr {
        Some(IpAddr::V4(v4)) => words(&v4.octets()),
        Some(IpAddr::V6(v6)) => words(&v6.octets()),
        None => [0; 4],
    };
    ut
}

fn write_utmp(ut: &libc::utmpx) {
    // SAFETY: `ut` is a complete utmpx; the wtmp path is a C string.
    unsafe {
        libc::setutxent();
        libc::pututxline(ut);
        libc::endutxent();
        updwtmpx(c"/var/log/wtmp".as_ptr(), ut);
    }
}

/// The size of lastlog's `ll_time`: glibc keeps it as wide as utmpx's
/// `tv_sec` (32 bits on x86_64, 64 on aarch64).
fn time_size() -> usize {
    // SAFETY: plain data, as above.
    let ut: libc::utmpx = unsafe { std::mem::zeroed() };
    std::mem::size_of_val(&ut.ut_tv.tv_sec)
}

fn lastlog_size() -> u64 {
    (time_size() + 32 + 256) as u64
}

/// The previous login of `uid` from lastlog: `(time, host)`.
pub fn last_login(uid: u32) -> Option<(i64, String)> {
    let mut f = std::fs::File::open(LASTLOG).ok()?;
    f.seek(SeekFrom::Start(u64::from(uid) * lastlog_size()))
        .ok()?;
    let mut rec = vec![0u8; lastlog_size() as usize];
    f.read_exact(&mut rec).ok()?;
    let ts = time_size();
    let time = if ts == 4 {
        i64::from(i32::from_ne_bytes(rec[..4].try_into().ok()?))
    } else {
        i64::from_ne_bytes(rec[..8].try_into().ok()?)
    };
    if time == 0 {
        return None;
    }
    let host = &rec[ts + 32..];
    let host = &host[..host.iter().position(|b| *b == 0).unwrap_or(host.len())];
    Some((time, String::from_utf8_lossy(host).into_owned()))
}

/// `Last login: Sat Oct 11 03:00:00 2026 from 192.0.2.1\r\n`, as OpenSSH
/// prints it on the terminal of an interactive login.
pub fn last_login_message(uid: u32) -> Option<String> {
    let (time, host) = last_login(uid)?;
    let t = time as libc::time_t;
    let mut buf = [0 as c_char; 64];
    // SAFETY: ctime_r writes at most 26 bytes into the 64-byte buffer.
    let p = unsafe { libc::ctime_r(&t, buf.as_mut_ptr()) };
    if p.is_null() {
        return None;
    }
    // SAFETY: ctime_r NUL-terminated it.
    let when = unsafe { std::ffi::CStr::from_ptr(buf.as_ptr()) }
        .to_string_lossy()
        .trim_end()
        .to_string();
    Some(if host.is_empty() {
        format!("Last login: {when}\r\n")
    } else {
        format!("Last login: {when} from {host}\r\n")
    })
}

fn write_lastlog(uid: u32, line: &str, host: &str) {
    let Ok(mut f) = std::fs::OpenOptions::new().write(true).open(LASTLOG) else {
        return;
    };
    let ts = time_size();
    let mut rec = vec![0u8; lastlog_size() as usize];
    let secs = now().as_secs();
    if ts == 4 {
        rec[..4].copy_from_slice(&(secs as i32).to_ne_bytes());
    } else {
        rec[..8].copy_from_slice(&(secs as i64).to_ne_bytes());
    }
    for (d, b) in rec[ts..ts + 32].iter_mut().zip(line.bytes()) {
        *d = b;
    }
    for (d, b) in rec[ts + 32..].iter_mut().zip(host.bytes()) {
        *d = b;
    }
    if f.seek(SeekFrom::Start(u64::from(uid) * lastlog_size()))
        .is_ok()
    {
        let _ = f.write_all(&rec);
    }
}

/// A recorded pty login, to be closed by [`logout`].
pub struct Session {
    pid: i32,
    line: String,
}

impl Session {
    /// Whether this is the login of session process `pid` on `tty`.
    pub fn is(&self, pid: i32, tty: &str) -> bool {
        self.pid == pid && self.line == line_of(tty)
    }
}

/// Record the login of `user` (`uid`) on `tty` by session process `pid`,
/// from `host` / `addr`.
pub fn login(
    pid: i32,
    tty: &str,
    user: &str,
    uid: u32,
    host: &str,
    addr: Option<IpAddr>,
) -> Session {
    let line = line_of(tty).to_string();
    write_utmp(&record(libc::USER_PROCESS, pid, &line, user, host, addr));
    write_lastlog(uid, &line, host);
    Session { pid, line }
}

/// Record the end of a login.
pub fn logout(s: &Session) {
    write_utmp(&record(libc::DEAD_PROCESS, s.pid, &s.line, "", "", None));
}
