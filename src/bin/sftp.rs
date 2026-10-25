//! `sftp` — interactive and batch file transfer, a drop-in for OpenSSH's.
//!
//! ```text
//! sftp [-46AaCfNpqrv] [-B buffer_size] [-b batchfile] [-c cipher]
//!      [-D sftp_server_command] [-F ssh_config] [-i identity_file]
//!      [-J destination] [-l limit] [-o ssh_option] [-P port]
//!      [-R num_requests] [-S program] [-s subsystem | sftp_server]
//!      [-X sftp_option] destination
//! ```
//!
//! The session runs over `ssh -s host sftp` (`-S` picks the ssh), so every
//! ssh option and ssh_config setting applies. `destination` is
//! `[user@]host[:path]` or `sftp://[user@]host[:port][/path]`: a directory
//! path starts the session there, a file path (or glob) is fetched and sftp
//! exits. Commands, their flags, messages and listings follow OpenSSH's
//! sftp.c (`help` lists them); in batch mode (`-b`) each is echoed and the
//! first failure aborts with status 1 unless the command is prefixed with
//! `-` (`@` suppresses the echo).

use std::collections::BTreeMap;
use std::io::{self, BufRead, IsTerminal, Write};
use std::path::Path;
use std::process::ExitCode;

use puressh::sftp::{Attrs, FxpStatus, NameEntry, SftpClient, SftpError};

#[path = "transfer.rs"]
mod transfer;
use transfer::{SshOptions, SshPipe, XferOpts};

/// OpenSSH's `error()` / `logit()` / `fatal()`: a line on stderr made safe
/// with `strnvis(VIS_SAFE | VIS_OCTAL)` and ended with `\r\n`.
macro_rules! error {
    ($($t:tt)*) => {
        log_line(&format!($($t)*))
    };
}

fn log_line(msg: &str) {
    eprint!("{}\r\n", vis(msg));
}

/// `strnvis(VIS_SAFE | VIS_OCTAL)`: bytes other than printable ASCII,
/// space, tab, newline, backspace, bell and carriage return as `\ooo`, and
/// `\` doubled.
fn vis(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for &b in s.as_bytes() {
        match b {
            b'\\' => out.push_str("\\\\"),
            b' '..=b'~' | b'\t' | b'\n' | 0x08 | 0x07 | b'\r' => out.push(b as char),
            _ => out.push_str(&format!("\\{b:03o}")),
        }
    }
    out
}

const USAGE: &str = "usage: sftp [-46AaCfNpqrv] [-B buffer_size] [-b batchfile] [-c cipher]
          [-D sftp_server_command] [-F ssh_config] [-i identity_file]
          [-J destination] [-l limit] [-o ssh_option] [-P port]
          [-R num_requests] [-S program] [-s subsystem | sftp_server]
          [-X sftp_option] destination";

const HELP: &str = "Available commands:
bye                                Quit sftp
cd path                            Change remote directory to 'path'
chgrp [-h] grp path                Change group of file 'path' to 'grp'
chmod [-h] mode path               Change permissions of file 'path' to 'mode'
chown [-h] own path                Change owner of file 'path' to 'own'
copy oldpath newpath               Copy remote file
cp oldpath newpath                 Copy remote file
df [-hi] [path]                    Display statistics for current directory or
                                   filesystem containing 'path'
exit                               Quit sftp
get [-afpR] remote [local]         Download file
help                               Display this help text
lcd path                           Change local directory to 'path'
lls [ls-options [path]]            Display local directory listing
lmkdir [-p] path                   Create local directory
ln [-s] oldpath newpath            Link remote file (-s for symlink)
lpwd                               Print local working directory
ls [-1afhlnrSt] [path]             Display remote directory listing
lumask umask                       Set local umask to 'umask'
mkdir [-p] path                    Create remote directory
progress                           Toggle display of progress meter
put [-afpR] local [remote]         Upload file
pwd                                Display remote working directory
quit                               Quit sftp
reget [-fpR] remote [local]        Resume download file
rename oldpath newpath             Rename remote file
reput [-fpR] local [remote]        Resume upload file
rm path                            Delete remote file
rmdir path                         Remove remote directory
symlink oldpath newpath            Symlink remote file
version                            Show SFTP version
!command                           Execute 'command' in local shell
!                                  Escape to local shell
?                                  Synonym for help";

/// Directory recursion limit of `get -R` / `put -R` (OpenSSH's).
const MAX_DIR_DEPTH: usize = 64;

/// How the program ends before a session: OpenSSH's `usage()` (status 1,
/// after an optional getopt message) or `fatal()` (status 255).
enum Exit {
    Usage(Option<String>),
    Fatal(String),
}

/// `-b`: the batch file, opened while the options are parsed.
enum Batch {
    Stdin,
    File(std::fs::File),
}

struct Cli {
    ssh: SshOptions,
    port: Option<u16>,
    batch: Option<Batch>,
    quiet: bool,
    /// `-q`: OpenSSH's log level `ERROR`, which also hides the
    /// informational notes of recursive transfers.
    log_quiet: bool,
    progress: bool,
    xfer: XferOpts,
    global_a: bool,
    global_f: bool,
    global_p: bool,
    global_r: bool,
    subsystem: Option<String>,
    sftp_direct: Option<String>,
    destination: String,
    /// `sftp host:file localpath`: where the fetched file goes.
    local: Option<String>,
}

/// The program options, parsed as OpenSSH's (BSD) getopt does: the first
/// operand ends them.
fn parse_args(args: &[String]) -> Result<Cli, Exit> {
    const WITH_ARG: &str = "cDilosSbBFJPRX";
    let mut c = Cli {
        ssh: SshOptions::default(),
        port: None,
        batch: None,
        quiet: false,
        log_quiet: false,
        progress: true,
        xfer: XferOpts::default(),
        global_a: false,
        global_f: false,
        global_p: false,
        global_r: false,
        subsystem: None,
        sftp_direct: None,
        destination: String::new(),
        local: None,
    };
    let mut noisy = false;
    let mut debug_level = 0;
    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
        if a == "--" {
            i += 1;
            break;
        }
        if !a.starts_with('-') || a == "-" {
            break;
        }
        let flags: Vec<char> = a[1..].chars().collect();
        let mut j = 0;
        while j < flags.len() {
            let f = flags[j];
            if WITH_ARG.contains(f) {
                let rest: String = flags[j + 1..].iter().collect();
                let v = if !rest.is_empty() {
                    rest
                } else {
                    i += 1;
                    args.get(i).cloned().ok_or_else(|| {
                        Exit::Usage(Some(format!("option requires an argument -- {f}")))
                    })?
                };
                option_with_arg(&mut c, f, v)?;
                break;
            }
            match f {
                '4' | '6' | 'C' => c.ssh.push(&format!("-{f}"), None),
                'A' => c.ssh.forward_agent = true,
                'v' => {
                    if debug_level < 3 {
                        c.ssh.push("-v", None);
                    }
                    debug_level += 1;
                }
                '1' => {
                    return Err(Exit::Fatal(
                        "SSH protocol v.1 is no longer supported".into(),
                    ));
                }
                // Accepted silently, as by OpenSSH.
                '2' => {}
                'a' => c.global_a = true,
                'f' => c.global_f = true,
                'N' => noisy = true,
                'p' => c.global_p = true,
                'q' => {
                    c.quiet = true;
                    c.log_quiet = true;
                    c.progress = false;
                    c.ssh.push("-q", None);
                }
                'r' => c.global_r = true,
                'h' => return Err(Exit::Usage(None)),
                _ => return Err(Exit::Usage(Some(format!("unknown option -- {f}")))),
            }
            j += 1;
        }
        i += 1;
    }
    // `-N` undoes the quiet mode `-b` / `-q` imply.
    if noisy {
        c.quiet = false;
    }
    // With `-D` there is no host; operands are ignored, as by OpenSSH.
    if c.sftp_direct.is_none() {
        match &args[i..] {
            [d] => c.destination = d.clone(),
            [d, l] => {
                c.destination = d.clone();
                c.local = Some(l.clone());
            }
            _ => return Err(Exit::Usage(None)),
        }
    }
    Ok(c)
}

fn option_with_arg(c: &mut Cli, f: char, v: String) -> Result<(), Exit> {
    match f {
        'B' => {
            c.xfer.chunk = strtoll(&v, 10)
                .filter(|n| *n > 0)
                .and_then(|n| u32::try_from(n).ok())
                .ok_or_else(|| Exit::Fatal(format!("Invalid buffer size \"{v}\"")))?
        }
        'b' => {
            if c.batch.is_some() {
                return Err(Exit::Fatal("Batch file already specified.".into()));
            }
            c.batch = Some(if v == "-" {
                Batch::Stdin
            } else {
                Batch::File(
                    std::fs::File::open(&v)
                        .map_err(|e| Exit::Fatal(format!("{} ({v}).", strerror(&e))))?,
                )
            });
            c.progress = false;
            c.quiet = true;
            c.ssh.push("-oBatchMode=yes", None);
        }
        'c' | 'F' | 'i' | 'J' | 'o' => c.ssh.push(&format!("-{f}"), Some(&v)),
        'D' => c.sftp_direct = Some(v),
        'l' => {
            let kbps = strtonum(&v, 1, 100 * 1024 * 1024).map_err(|_| Exit::Usage(None))?;
            c.xfer.limit = Some(kbps as u64 * 1024 / 8);
        }
        'P' => {
            c.port = Some(
                v.parse::<u16>()
                    .ok()
                    .filter(|p| *p > 0)
                    .ok_or_else(|| Exit::Fatal(format!("Bad port \"{v}\"\n")))?,
            )
        }
        'R' => {
            c.xfer.depth = strtoll(&v, 10)
                .filter(|n| *n > 0)
                .map(|n| n as usize)
                .ok_or_else(|| Exit::Fatal(format!("Invalid number of requests \"{v}\"")))?
        }
        's' => c.subsystem = Some(v),
        'S' => c.ssh.program = Some(v),
        'X' => {
            if let Some(n) = v.strip_prefix("buffer=") {
                c.xfer.chunk = match scan_scaled(n) {
                    Ok(b) if b > 0 && b <= 256 * 1024 => b as u32,
                    Ok(_) => {
                        return Err(Exit::Fatal(format!(
                            "Invalid buffer size \"{n}\": Invalid argument"
                        )));
                    }
                    Err(e) => {
                        return Err(Exit::Fatal(format!("Invalid buffer size \"{n}\": {e}")));
                    }
                };
            } else if let Some(n) = v.strip_prefix("nrequests=") {
                c.xfer.depth = strtonum(n, 1, 256 * 1024)
                    .map_err(|e| Exit::Fatal(format!("Invalid number of requests \"{n}\": {e}")))?
                    as usize;
            } else {
                return Err(Exit::Fatal("Invalid -X option".into()));
            }
        }
        _ => unreachable!(),
    }
    Ok(())
}

/// C `strtoll`: optional leading space and sign, then digits in `base` (0:
/// by prefix, `0x` hex, `0` octal). `None` unless the whole string is one
/// in-range number.
fn strtoll(s: &str, base: u32) -> Option<i64> {
    let t = s.trim_start_matches([' ', '\t', '\n', '\r', '\x0b', '\x0c']);
    let (neg, t) = match t.as_bytes().first() {
        Some(b'-') => (true, &t[1..]),
        Some(b'+') => (false, &t[1..]),
        _ => (false, t),
    };
    let (base, digits) = match base {
        0 if (t.starts_with("0x") || t.starts_with("0X"))
            && t[2..].starts_with(|c: char| c.is_ascii_hexdigit()) =>
        {
            (16, &t[2..])
        }
        0 if t.starts_with('0') => (8, t),
        0 => (10, t),
        b => (b, t),
    };
    if digits.is_empty() {
        return None;
    }
    let mut v: i64 = 0;
    for c in digits.chars() {
        let d = i64::from(c.to_digit(base)?);
        v = v.checked_mul(i64::from(base))?.checked_add(d)?;
    }
    Some(if neg { -v } else { v })
}

/// OpenBSD `strtonum`, with its error strings.
fn strtonum(s: &str, min: i64, max: i64) -> Result<i64, &'static str> {
    match strtoll(s, 10) {
        None => Err("invalid"),
        Some(n) if n < min => Err("too small"),
        Some(n) if n > max => Err("too large"),
        Some(n) => Ok(n),
    }
}

/// OpenBSD `scan_scaled`: a number with an optional fraction and one unit
/// letter (`B`, `K`, `M`, `G`, `T`, `P`, `E`, powers of 1024).
fn scan_scaled(s: &str) -> Result<i64, &'static str> {
    const EINVAL: &str = "Invalid argument";
    const ERANGE: &str = "Numerical result out of range";
    let b = s
        .trim_start_matches(|c: char| c.is_ascii_whitespace())
        .as_bytes();
    let mut p = 0;
    let mut sign = 0i64;
    while p < b.len() && (b[p] == b'-' || b[p] == b'+') {
        if sign != 0 {
            return Err(EINVAL);
        }
        sign = if b[p] == b'-' { -1 } else { 1 };
        p += 1;
    }
    let (mut whole, mut fpart, mut fract_digits) = (0i64, 0i64, 0u32);
    while p < b.len() && (b[p].is_ascii_digit() || b[p] == b'.') {
        if b[p] == b'.' {
            if fract_digits > 0 {
                return Err(EINVAL);
            }
            fract_digits = 1;
        } else {
            let d = i64::from(b[p] - b'0');
            if fract_digits > 0 {
                if fract_digits < 20 {
                    fract_digits += 1;
                    fpart = fpart
                        .checked_mul(10)
                        .and_then(|f| f.checked_add(d))
                        .ok_or(ERANGE)?;
                }
            } else {
                whole = whole
                    .checked_mul(10)
                    .and_then(|w| w.checked_add(d))
                    .ok_or(ERANGE)?;
            }
        }
        p += 1;
    }
    if sign != 0 {
        whole *= sign;
    }
    if p == b.len() {
        return Ok(whole);
    }
    let unit = b"BKMGTPE"
        .iter()
        .position(|u| b[p].to_ascii_uppercase() == *u)
        .ok_or(EINVAL)?;
    if b.get(p + 1).is_some_and(|c| c.is_ascii_alphanumeric()) {
        return Err(EINVAL);
    }
    let scale = 1i64 << (10 * unit);
    whole = whole.checked_mul(scale).ok_or(ERANGE)?;
    let mut f = fpart as i128 * i128::from(scale);
    for _ in 1..fract_digits.max(1) {
        f /= 10;
    }
    let f = f as i64;
    Ok(if sign == -1 { whole - f } else { whole + f })
}

/// OpenSSH's `fmt_scaled` (as for `ls -h` and `df -h`): `512B`, `2.9K`,
/// `15.0M`, `120G`.
fn fmt_scaled(n: u64) -> String {
    const UNITS: &[u8; 7] = b"BKMGTPE";
    let mut i = 0usize;
    while i < 6 && n / 1024 >= 1u64 << (10 * i) {
        i += 1;
    }
    let (mut number, fract) = if i == 0 {
        (n, 0)
    } else {
        (
            n >> (10 * i),
            (n & ((1u64 << (10 * i)) - 1)) >> (10 * (i - 1)),
        )
    };
    let mut fract = (10 * fract + 512) / 1024;
    if fract >= 10 {
        number += 1;
        fract = 0;
    }
    let unit = UNITS[i] as char;
    if number == 0 {
        "0B".into()
    } else if i == 0 || number >= 100 {
        if fract >= 5 {
            number += 1;
        }
        format!("{number}{unit}")
    } else {
        format!("{number}.{fract}{unit}")
    }
}

/// OpenSSH's wording for a status (its `fx2txt`). Any other failure means
/// the connection is gone, which ends sftp as OpenSSH's `fatal()` does.
fn fx(e: &SftpError) -> &'static str {
    match e {
        SftpError::Status { code, .. } => match code {
            FxpStatus::Ok => "No error",
            FxpStatus::Eof => "End of file",
            FxpStatus::NoSuchFile => "No such file or directory",
            FxpStatus::PermissionDenied => "Permission denied",
            FxpStatus::Failure => "Failure",
            FxpStatus::BadMessage => "Bad message",
            FxpStatus::NoConnection => "No connection",
            FxpStatus::ConnectionLost => "Connection lost",
            FxpStatus::OpUnsupported => "Operation unsupported",
            #[allow(unreachable_patterns)]
            _ => "Unknown status",
        },
        other => connection_lost(other),
    }
}

/// Whether sftp is quiet (`-q`, `-b`): for the note on a lost connection.
static QUIET: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// A request failed without a status: the transport is gone.
fn connection_lost(e: &SftpError) -> ! {
    match e {
        SftpError::Io(_) => error!("Connection closed"),
        other => error!("{other}"),
    }
    transport_gone()
}

/// End sftp after the transport died, with OpenSSH's note (from its
/// SIGCHLD handler) unless quiet.
fn transport_gone() -> ! {
    let _ = io::stdout().flush();
    if !QUIET.load(std::sync::atomic::Ordering::Relaxed) {
        eprint!("\rConnection closed.  \n");
    }
    std::process::exit(255)
}

/// A failure that is not reported (OpenSSH's "quiet" requests); only a
/// dead connection matters.
fn check(e: &SftpError) {
    if !matches!(e, SftpError::Status { .. }) {
        connection_lost(e);
    }
}

/// C `strerror` text for an I/O error.
fn strerror(e: &io::Error) -> String {
    let s = e.to_string();
    match s.rfind(" (os error ") {
        Some(i) => s[..i].to_string(),
        None => s,
    }
}

fn lossy(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}

/// Scrub control bytes (terminal escapes) from server-supplied names before
/// they reach the terminal, as OpenSSH does.
fn safe_display(b: &[u8]) -> String {
    let scrubbed: Vec<u8> = b
        .iter()
        .map(|c| if *c < 0x20 || *c == 0x7f { b'?' } else { *c })
        .collect();
    lossy(&scrubbed)
}

/// Split a command line as OpenSSH's sftp (`makeargv`): whitespace
/// separates words, `'…'` and `"…"` quote, `\` escapes, `#` starts a
/// comment outside quotes. Glob characters stay escaped (`\*`) where they
/// were quoted or escaped, for the glob to take literally; paths that are
/// not globbed are unescaped by the command ([`undo_glob_escape`]).
fn split_line(line: &str) -> Result<Vec<String>, String> {
    #[derive(PartialEq, Clone, Copy)]
    enum St {
        Start,
        Squote,
        Dquote,
        Unquoted,
    }
    const MAXARGS: usize = 128;
    const MAXARGLEN: usize = 8192;
    if line.len() > MAXARGLEN - 1 {
        return Err("string too long".into());
    }
    let a: Vec<char> = line.chars().collect();
    let at = |i: usize| a.get(i).copied().unwrap_or('\0');
    let is_glob = |c: char| matches!(c, '?' | '[' | '*');
    let mut out: Vec<String> = Vec::new();
    let mut cur = String::new();
    let mut st = St::Start;
    let mut i = 0;
    loop {
        if out.len() > MAXARGS {
            return Err("Too many arguments.".into());
        }
        let c = at(i);
        if c != '\0' && c.is_ascii_whitespace() {
            if st == St::Unquoted {
                out.push(std::mem::take(&mut cur));
                st = St::Start;
            } else if st != St::Start {
                cur.push(c);
            }
        } else if c == '"' || c == '\'' {
            let q = if c == '"' { St::Dquote } else { St::Squote };
            match st {
                St::Start | St::Unquoted => st = q,
                s if s == q => st = St::Unquoted,
                _ => cur.push(c),
            }
        } else if c == '\\' {
            if st == St::Squote || st == St::Dquote {
                let quot = if st == St::Squote { '\'' } else { '"' };
                let n = at(i + 1);
                if n == quot {
                    i += 1;
                    cur.push(n);
                } else if is_glob(n) {
                    // Double-escaped: the glob undoes one level.
                    cur.push('\\');
                    cur.push('\\');
                    cur.push('\\');
                    cur.push(n);
                    i += 1;
                } else {
                    cur.push('\\');
                    if n == '\0' {
                        return Err("Unterminated quoted argument".into());
                    }
                    cur.push(n);
                    i += 1;
                }
            } else {
                st = St::Unquoted;
                let n = at(i + 1);
                if is_glob(n) || n == '\\' {
                    cur.push('\\');
                    cur.push(n);
                    i += 1;
                } else {
                    i += 1;
                    if n == '\0' {
                        return Err("Unterminated quoted argument".into());
                    }
                    cur.push(n);
                }
            }
        } else if c == '#' && !(st == St::Squote || st == St::Dquote) {
            break;
        } else if c == '\0' {
            if st == St::Squote || st == St::Dquote {
                return Err("Unterminated quoted argument".into());
            }
            break;
        } else {
            if st == St::Start {
                st = St::Unquoted;
            }
            if (st == St::Squote || st == St::Dquote) && is_glob(c) {
                cur.push('\\');
            }
            cur.push(c);
        }
        i += 1;
    }
    if st == St::Unquoted {
        out.push(cur);
    }
    Ok(out)
}

/// OpenSSH's `undo_glob_escape`, for paths a command does not glob:
/// `\?`, `\[`, `\*` and `\\` lose their backslash.
fn undo_glob_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut it = s.chars().peekable();
    while let Some(c) = it.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match it.peek() {
            Some(&n) if matches!(n, '?' | '[' | '*' | '\\') => {
                out.push(n);
                it.next();
            }
            _ => out.push('\\'),
        }
    }
    out
}

/// OpenSSH's `escape_glob`: the working directory, made literal for a glob.
fn escape_glob(s: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(s.len() * 2);
    for c in s {
        if b"[]?*\\".contains(c) {
            out.push(b'\\');
        }
        out.push(*c);
    }
    out
}

/// `sftp_path_append`: `p1/p2` (no doubled `/`).
fn path_append(p1: &[u8], p2: &[u8]) -> Vec<u8> {
    let mut out = p1.to_vec();
    if !p1.is_empty() && !p1.ends_with(b"/") {
        out.push(b'/');
    }
    out.extend_from_slice(p2);
    out
}

/// `sftp_make_absolute`: a relative path under `pwd`.
fn make_absolute(p: &[u8], pwd: &[u8]) -> Vec<u8> {
    if p.starts_with(b"/") {
        p.to_vec()
    } else {
        path_append(pwd, p)
    }
}

/// `path_strip`: `path` without the leading `strip` directory.
fn path_strip(path: &[u8], strip: Option<&[u8]>) -> Vec<u8> {
    let Some(s) = strip.filter(|s| !s.is_empty()) else {
        return path.to_vec();
    };
    if path.starts_with(s) {
        let mut len = s.len();
        if s[len - 1] != b'/' && path.get(len) == Some(&b'/') {
            len += 1;
        }
        return path[len..].to_vec();
    }
    path.to_vec()
}

/// POSIX `basename`: the last component, trailing slashes ignored.
fn basename(p: &[u8]) -> Vec<u8> {
    if p.is_empty() {
        return b".".to_vec();
    }
    let end = p.iter().rposition(|c| *c != b'/').map_or(0, |i| i + 1);
    if end == 0 {
        return b"/".to_vec();
    }
    let start = p[..end]
        .iter()
        .rposition(|c| *c == b'/')
        .map_or(0, |i| i + 1);
    p[start..end].to_vec()
}

/// Skip a `[...]` class starting at `p[i]`: the index of its `]`, if any.
fn class_end(p: &[u8], i: usize) -> Option<usize> {
    let mut j = i + 1;
    if p.get(j) == Some(&b'!') {
        j += 1;
    }
    if p.get(j) == Some(&b']') {
        j += 1;
    }
    p[j.min(p.len())..]
        .iter()
        .position(|c| *c == b']')
        .map(|k| j + k)
}

/// `glob(3)`'s `GLOB_BRACE`: `a{b,c{d,e}}f` as `abf`, `acdf`, `acef`
/// (unbalanced braces and `{}` stay literal).
fn brace_expand(p: &[u8]) -> Vec<Vec<u8>> {
    if p == b"{}" {
        return vec![p.to_vec()];
    }
    let mut i = 0;
    while i < p.len() && p[i] != b'{' {
        i += if p[i] == b'\\' { 2 } else { 1 };
    }
    if i >= p.len() {
        return vec![p.to_vec()];
    }
    // The matching `}` and the top-level commas between.
    let (open, mut depth, mut commas, mut close) = (i, 0, Vec::new(), None);
    let mut j = i;
    while j < p.len() {
        match p[j] {
            b'\\' => j += 1,
            b'[' => j = class_end(p, j).unwrap_or(j),
            b'{' => depth += 1,
            b',' if depth == 1 => commas.push(j),
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    close = Some(j);
                    break;
                }
            }
            _ => {}
        }
        j += 1;
    }
    let Some(close) = close else {
        return vec![p.to_vec()];
    };
    let mut out = Vec::new();
    let mut from = open + 1;
    for end in commas.into_iter().chain([close]) {
        let mut alt = p[..open].to_vec();
        alt.extend_from_slice(&p[from..end]);
        alt.extend_from_slice(&p[close + 1..]);
        out.extend(brace_expand(&alt));
        from = end + 1;
    }
    out
}

/// OpenSSH's `argv_split` for `-D`: words with `'`/`"` quoting and `\`
/// escapes; `#` ends the line.
fn argv_split(s: &str) -> Option<Vec<String>> {
    let b: Vec<char> = s.chars().collect();
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        if b[i] == ' ' || b[i] == '\t' {
            i += 1;
            continue;
        }
        if b[i] == '#' {
            break;
        }
        let mut arg = String::new();
        let mut quote = None;
        while i < b.len() {
            let c = b[i];
            if c == '\\' {
                match b.get(i + 1) {
                    Some(&n)
                        if n == '\'' || n == '"' || n == '\\' || (quote.is_none() && n == ' ') =>
                    {
                        i += 1;
                        arg.push(n);
                    }
                    _ => arg.push(c),
                }
            } else if quote.is_none() && (c == ' ' || c == '\t') {
                break;
            } else if quote.is_none() && (c == '"' || c == '\'') {
                quote = Some(c);
            } else if quote == Some(c) {
                quote = None;
            } else {
                arg.push(c);
            }
            i += 1;
        }
        if i >= b.len() && quote.is_some() {
            return None;
        }
        out.push(arg);
    }
    Some(out)
}

const S_IFMT: u32 = 0o170000;
const S_IFDIR: u32 = 0o040000;
const S_IFREG: u32 = 0o100000;
const S_IFLNK: u32 = 0o120000;

fn is_dir(a: &Attrs) -> bool {
    a.permissions.unwrap_or(0) & S_IFMT == S_IFDIR
}

fn is_reg(a: &Attrs) -> bool {
    a.permissions.unwrap_or(0) & S_IFMT == S_IFREG
}

fn is_link(a: &Attrs) -> bool {
    a.permissions.unwrap_or(0) & S_IFMT == S_IFLNK
}

/// BSD `strmode` (without its trailing space).
fn strmode(mode: u32) -> String {
    let kind = match mode & S_IFMT {
        S_IFDIR => 'd',
        0o020000 => 'c',
        0o060000 => 'b',
        S_IFREG => '-',
        S_IFLNK => 'l',
        0o140000 => 's',
        0o010000 => 'p',
        _ => '?',
    };
    let bit = |m: u32, c: char| if mode & m != 0 { c } else { '-' };
    let mut s = String::with_capacity(10);
    s.push(kind);
    for (r, w, x, special, sc) in [
        (0o400, 0o200, 0o100, 0o4000, 's'),
        (0o040, 0o020, 0o010, 0o2000, 's'),
        (0o004, 0o002, 0o001, 0o1000, 't'),
    ] {
        s.push(bit(r, 'r'));
        s.push(bit(w, 'w'));
        s.push(match (mode & x != 0, mode & special != 0) {
            (true, true) => sc,
            (false, true) => sc.to_ascii_uppercase(),
            (true, false) => 'x',
            (false, false) => '-',
        });
    }
    s
}

/// OpenSSH's `ls_file` for a remote file: an `ls -l` line from attributes,
/// with the owner names given (numbers otherwise).
fn ls_file(name: &str, a: &Attrs, si: bool, user: Option<&str>, group: Option<&str>) -> String {
    let (uid, gid) = a.uid_gid.unwrap_or((0, 0));
    let user = user.map_or_else(|| uid.to_string(), str::to_string);
    let group = group.map_or_else(|| gid.to_string(), str::to_string);
    let size = a.size.unwrap_or(0);
    let size = if si {
        fmt_scaled(size)
    } else {
        size.to_string()
    };
    let mtime = a.atime_mtime.map_or(0, |(_, m)| m);
    format!(
        "{} {:>3} {user:<8} {group:<8} {size:>8} {} {name}",
        strmode(a.permissions.unwrap_or(0)) + " ",
        "?",
        format_mtime(mtime)
    )
}

/// `ls -l`'s time column: the time within the last six months, else the
/// year (C locale `%b %e %H:%M` / `%b %e  %Y`).
fn format_mtime(t: u32) -> String {
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let t = i64::from(t);
    let local = t + transfer::local_offset(t);
    let days = local.div_euclid(86_400);
    let secs = local.rem_euclid(86_400);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let month = MONTHS[(m - 1) as usize];
    if now - (365 * 24 * 60 * 60) / 2 < t && now >= t {
        format!("{month} {d:>2} {:02}:{:02}", secs / 3600, secs / 60 % 60)
    } else {
        format!("{month} {d:>2}  {y}")
    }
}

// `ls` flags, as OpenSSH's.
const LS_LONG_VIEW: u32 = 0x0001;
const LS_SHORT_VIEW: u32 = 0x0002;
const LS_NUMERIC_VIEW: u32 = 0x0004;
const LS_NAME_SORT: u32 = 0x0008;
const LS_TIME_SORT: u32 = 0x0010;
const LS_SIZE_SORT: u32 = 0x0020;
const LS_REVERSE_SORT: u32 = 0x0040;
const LS_SHOW_ALL: u32 = 0x0080;
const LS_SI_UNITS: u32 = 0x0100;
const VIEW_FLAGS: u32 = LS_LONG_VIEW | LS_SHORT_VIEW | LS_NUMERIC_VIEW | LS_SI_UNITS;
const SORT_FLAGS: u32 = LS_NAME_SORT | LS_TIME_SORT | LS_SIZE_SORT;

/// `ls` flags in order: the later of `-1`/`-l` and of `-f`/`-S`/`-t` wins.
fn ls_flags(flags: &[char]) -> u32 {
    let mut l = LS_NAME_SORT;
    for f in flags {
        match f {
            '1' => l = (l & !VIEW_FLAGS) | LS_SHORT_VIEW,
            'S' => l = (l & !SORT_FLAGS) | LS_SIZE_SORT,
            'a' => l |= LS_SHOW_ALL,
            'f' => l &= !SORT_FLAGS,
            'h' => l |= LS_SI_UNITS,
            'l' => l = (l & !LS_SHORT_VIEW) | LS_LONG_VIEW,
            'n' => l = (l & !LS_SHORT_VIEW) | LS_NUMERIC_VIEW | LS_LONG_VIEW,
            'r' => l |= LS_REVERSE_SORT,
            't' => l = (l & !SORT_FLAGS) | LS_TIME_SORT,
            _ => {}
        }
    }
    l
}

/// `ls` ordering (OpenSSH's `sdirent_comp`): name, or newest / largest
/// first; `-r` inverts the comparison (ties keep their order).
fn ls_cmp(sort: u32, an: &[u8], a: &Attrs, bn: &[u8], b: &Attrs) -> std::cmp::Ordering {
    let o = if sort & LS_NAME_SORT != 0 {
        an.cmp(bn)
    } else if sort & LS_TIME_SORT != 0 {
        let mt = |a: &Attrs| a.atime_mtime.map_or(0, |t| t.1);
        mt(b).cmp(&mt(a))
    } else {
        b.size.unwrap_or(0).cmp(&a.size.unwrap_or(0))
    };
    if sort & LS_REVERSE_SORT != 0 {
        o.reverse()
    } else {
        o
    }
}

/// The terminal width `ls` lays its columns out for (of stdin, as
/// OpenSSH's): 80 when stdin is not a terminal.
fn stdin_width() -> usize {
    #[cfg(unix)]
    {
        // SAFETY: TIOCGWINSZ fills a plain struct.
        let mut ws: libc::winsize = unsafe { std::mem::zeroed() };
        if unsafe { libc::ioctl(0, libc::TIOCGWINSZ, &mut ws) } != -1 {
            return ws.ws_col as usize;
        }
    }
    80
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Cmd {
    Chdir,
    Chgrp,
    Chmod,
    Chown,
    Copy,
    Df,
    Get,
    Help,
    Lchdir,
    Link,
    Lls,
    Lmkdir,
    Lpwd,
    Ls,
    Lumask,
    Mkdir,
    Put,
    Pwd,
    Quit,
    Reget,
    Rename,
    Reput,
    Rm,
    Rmdir,
    Shell,
    Symlink,
    Version,
    Progress,
}

/// OpenSSH's command table (names match case-insensitively).
const CMDS: &[(&str, Cmd)] = &[
    ("bye", Cmd::Quit),
    ("cd", Cmd::Chdir),
    ("chdir", Cmd::Chdir),
    ("chgrp", Cmd::Chgrp),
    ("chmod", Cmd::Chmod),
    ("chown", Cmd::Chown),
    ("copy", Cmd::Copy),
    ("cp", Cmd::Copy),
    ("df", Cmd::Df),
    ("dir", Cmd::Ls),
    ("exit", Cmd::Quit),
    ("get", Cmd::Get),
    ("help", Cmd::Help),
    ("lcd", Cmd::Lchdir),
    ("lchdir", Cmd::Lchdir),
    ("lls", Cmd::Lls),
    ("lmkdir", Cmd::Lmkdir),
    ("ln", Cmd::Link),
    ("lpwd", Cmd::Lpwd),
    ("ls", Cmd::Ls),
    ("lumask", Cmd::Lumask),
    ("mkdir", Cmd::Mkdir),
    ("mget", Cmd::Get),
    ("mput", Cmd::Put),
    ("progress", Cmd::Progress),
    ("put", Cmd::Put),
    ("pwd", Cmd::Pwd),
    ("quit", Cmd::Quit),
    ("reget", Cmd::Reget),
    ("rename", Cmd::Rename),
    ("reput", Cmd::Reput),
    ("rm", Cmd::Rm),
    ("rmdir", Cmd::Rmdir),
    ("symlink", Cmd::Symlink),
    ("version", Cmd::Version),
    ("!", Cmd::Shell),
    ("?", Cmd::Help),
];

fn lookup_cmd(name: &str) -> Option<(&'static str, Cmd)> {
    // An explicit loop: rustc --release has hung on `CONST.iter().find()`.
    for (n, c) in CMDS {
        if n.eq_ignore_ascii_case(name) {
            return Some((n, *c));
        }
    }
    None
}

/// One parsed command line (OpenSSH's `parse_args` outputs).
#[derive(Debug, PartialEq)]
struct Parsed {
    cmd: Cmd,
    /// The command's name as in the table, for messages.
    name: &'static str,
    flags: Vec<char>,
    n_arg: u64,
    path1: Option<String>,
    path2: Option<String>,
    /// `lls` / `!`: the rest of the line, for the shell.
    rest: String,
}

impl Parsed {
    fn has(&self, f: char) -> bool {
        self.flags.contains(&f)
    }
}

/// The `-` (ignore errors) and `@` (no echo) prefixes of a command line,
/// in any order, and what follows them.
fn parse_prefix(line: &str) -> (bool, bool, &str) {
    const WS: [char; 4] = [' ', '\t', '\r', '\n'];
    let mut cp = line.trim_start_matches(WS);
    let (mut ignore, mut noecho) = (false, false);
    loop {
        if let Some(r) = cp.strip_prefix('-') {
            ignore = true;
            cp = r;
        } else if let Some(r) = cp.strip_prefix('@') {
            noecho = true;
            cp = r;
        } else {
            break;
        }
    }
    (ignore, noecho, cp.trim_start_matches(WS))
}

/// A command's leading flags, as OpenSSH's getopt loops: `(flags, index
/// of the first operand)`.
fn getopt(argv: &[String], allowed: &str, cmd: &str) -> Result<(Vec<char>, usize), String> {
    let mut flags = Vec::new();
    let mut i = 1;
    while i < argv.len() && argv[i].starts_with('-') && argv[i].len() > 1 {
        if argv[i] == "--" {
            i += 1;
            break;
        }
        for f in argv[i][1..].chars() {
            if !allowed.contains(f) {
                return Err(format!("{cmd}: Invalid flag -{f}"));
            }
            flags.push(f);
        }
        i += 1;
    }
    Ok((flags, i))
}

/// OpenSSH's `parse_args` for a command line (after its prefixes): `None`
/// for a blank or comment line.
fn parse_command(cp: &str) -> Result<Option<Parsed>, String> {
    if cp.is_empty() || cp.starts_with('#') {
        return Ok(None);
    }
    let argv = split_line(cp)?;
    let found = argv.first().and_then(|a| lookup_cmd(a));
    let (name, cmd) = if let Some(rest) = cp.strip_prefix('!') {
        return Ok(Some(Parsed {
            cmd: Cmd::Shell,
            name: "!",
            flags: Vec::new(),
            n_arg: 0,
            path1: None,
            path2: None,
            rest: rest.to_string(),
        }));
    } else {
        found.ok_or("Invalid command.")?
    };
    let mut p = Parsed {
        cmd,
        name,
        flags: Vec::new(),
        n_arg: 0,
        path1: None,
        path2: None,
        rest: String::new(),
    };
    let arg = |i: usize| argv.get(i).cloned();
    match cmd {
        Cmd::Get | Cmd::Reget | Cmd::Put | Cmd::Reput => {
            let (f, i) = getopt(&argv, "afPpRr", name)?;
            p.flags = f;
            p.path1 = Some(arg(i).ok_or(format!(
                "You must specify at least one path after a {name} command."
            ))?);
            // The destination is not globbed.
            p.path2 = arg(i + 1).map(|d| undo_glob_escape(&d));
        }
        Cmd::Link | Cmd::Copy | Cmd::Rename | Cmd::Symlink => {
            let allowed = match cmd {
                Cmd::Link => "s",
                Cmd::Rename => "l",
                _ => "",
            };
            let (f, i) = getopt(&argv, allowed, name)?;
            p.flags = f;
            let (Some(a), Some(b)) = (arg(i), arg(i + 1)) else {
                return Err(format!(
                    "You must specify two paths after a {name} command."
                ));
            };
            p.path1 = Some(undo_glob_escape(&a));
            p.path2 = Some(undo_glob_escape(&b));
        }
        Cmd::Mkdir | Cmd::Lmkdir | Cmd::Rm | Cmd::Rmdir | Cmd::Chdir | Cmd::Lchdir => {
            let allowed = if matches!(cmd, Cmd::Mkdir | Cmd::Lmkdir) {
                "p"
            } else {
                ""
            };
            let (f, i) = getopt(&argv, allowed, name)?;
            p.flags = f;
            match arg(i) {
                // Only `rm` globs.
                Some(a) if cmd == Cmd::Rm => p.path1 = Some(a),
                Some(a) => p.path1 = Some(undo_glob_escape(&a)),
                None if matches!(cmd, Cmd::Chdir | Cmd::Lchdir) => {}
                None => return Err(format!("You must specify a path after a {name} command.")),
            }
        }
        Cmd::Df => {
            let (f, i) = getopt(&argv, "hi", name)?;
            p.flags = f;
            p.path1 = arg(i).map(|a| undo_glob_escape(&a));
        }
        Cmd::Ls => {
            let (f, i) = getopt(&argv, "1Safhlnrt", "ls")?;
            p.flags = f;
            p.path1 = arg(i);
        }
        Cmd::Lls => {
            // The rest of the line, after the command name.
            p.rest = cp.get(3..).unwrap_or("").to_string();
        }
        Cmd::Shell => p.rest = String::new(),
        Cmd::Lumask | Cmd::Chmod | Cmd::Chown | Cmd::Chgrp => {
            let base = if matches!(cmd, Cmd::Lumask | Cmd::Chmod) {
                8
            } else {
                0
            };
            let (f, i) = getopt(&argv, "h", name)?;
            p.flags = f;
            let need = || format!("You must supply a numeric argument to the {name} command.");
            p.n_arg = arg(i)
                .and_then(|a| strtoll(&a, base))
                .filter(|n| (0..=i64::from(u32::MAX)).contains(n))
                .ok_or_else(need)? as u64;
            if cmd != Cmd::Lumask {
                p.path1 = Some(
                    arg(i + 1).ok_or(format!("You must specify a path after a {name} command."))?,
                );
            }
        }
        Cmd::Quit | Cmd::Pwd | Cmd::Lpwd | Cmd::Help | Cmd::Version | Cmd::Progress => {
            getopt(&argv, "", name)?;
        }
    }
    Ok(Some(p))
}

/// What OpenSSH's `glob(3)` over SFTP yields: the paths (directories
/// marked with `/` when asked), the `lstat` of each match, and how many
/// really matched (a no-match "nocheck" pattern comes back as itself).
#[derive(Default)]
struct Glob {
    paths: Vec<Vec<u8>>,
    stats: Vec<Option<Attrs>>,
    matched: usize,
}

struct Session {
    sftp: SftpClient<SshPipe>,
    pwd: Vec<u8>,
    startdir: Vec<u8>,
    /// `-B`, `-R`, `-l`.
    xfer: XferOpts,
    global_a: bool,
    global_f: bool,
    global_p: bool,
    global_r: bool,
    quiet: bool,
    log_quiet: bool,
    progress: bool,
    /// Remote user and group names seen so far (`ls -l`).
    users: BTreeMap<u32, String>,
    groups: BTreeMap<u32, String>,
}

/// A command's outcome: `Err` once its failure is reported (an empty
/// message: already printed).
type Res = Result<(), String>;

enum Flow {
    Continue,
    Quit,
}

impl Session {
    /// `make_absolute_pwd_glob`: a pattern under the (literal) working
    /// directory.
    fn abs_glob(&self, p: &str) -> Vec<u8> {
        make_absolute(p.as_bytes(), &escape_glob(&self.pwd))
    }

    fn abs(&self, p: &str) -> Vec<u8> {
        make_absolute(p.as_bytes(), &self.pwd)
    }

    fn stat_quiet(&mut self, p: &[u8], follow: bool) -> Option<Attrs> {
        let r = if follow {
            self.sftp.stat(p)
        } else {
            self.sftp.lstat(p)
        };
        r.map_err(|e| check(&e)).ok()
    }

    /// `sftp_remote_is_dir`.
    fn remote_is_dir(&mut self, p: &[u8]) -> bool {
        self.stat_quiet(p, true).is_some_and(|a| is_dir(&a))
    }

    /// Expand a remote pattern (`sftp_glob`): `mark` is `GLOB_MARK`,
    /// `nocheck` is `GLOB_NOCHECK`.
    fn glob(&mut self, pattern: &[u8], mark: bool, nocheck: bool) -> Glob {
        let candidates = if transfer::has_glob(pattern) {
            transfer::remote_glob(&mut self.sftp, b"", pattern).unwrap_or_default()
        } else {
            vec![transfer::unescape(pattern)]
        };
        let mut found: Vec<(Vec<u8>, Attrs)> = Vec::new();
        for mut p in candidates {
            let Some(mut st) = self.stat_quiet(&p, false) else {
                continue;
            };
            // As glob(3): marking looks through a symlink, and keeps the
            // target's attributes.
            if mark && !p.ends_with(b"/") && is_link(&st) {
                st = self.stat_quiet(&p, true).unwrap_or(st);
            }
            if mark && !p.ends_with(b"/") && is_dir(&st) {
                p.push(b'/');
            }
            found.push((p, st));
        }
        found.sort_by(|a, b| a.0.cmp(&b.0));
        let mut g = Glob {
            matched: found.len(),
            ..Glob::default()
        };
        for (p, st) in found {
            g.paths.push(p);
            g.stats.push(Some(st));
        }
        if g.matched == 0 && nocheck {
            let mut p = transfer::unescape(pattern);
            if mark && !p.ends_with(b"/") && self.remote_is_dir(&p) {
                p.push(b'/');
            }
            g.paths.push(p);
            g.stats.push(None);
        }
        g
    }

    /// `ls`'s glob, which also expands `{a,b}` (`GLOB_BRACE`): each
    /// alternative is a pattern of its own.
    fn glob_brace(&mut self, pattern: &[u8]) -> Glob {
        let mut g = Glob::default();
        for p in brace_expand(pattern) {
            let one = self.glob(&p, true, true);
            g.matched += one.matched;
            g.paths.extend(one.paths);
            g.stats.extend(one.stats);
        }
        g
    }

    /// Transfer options for one file.
    fn opts(&self, preserve: bool, resume: bool) -> XferOpts {
        let mut o = self.xfer.clone();
        o.preserve = preserve;
        o.resume = resume;
        o.recursive = false;
        o.progress = self.progress;
        o.announce_dirs = false;
        o
    }

    /// Run one command line (OpenSSH's `parse_dispatch_command`): 0 to go
    /// on, 1 to quit, -1 to abort the batch.
    fn dispatch(&mut self, line: &str, err_abort: bool, echo: bool) -> i32 {
        let (ignore, noecho, cp) = parse_prefix(line);
        let err_abort = err_abort && !ignore;
        let parsed = parse_command(cp);
        if let Err(msg) = &parsed {
            error!("{msg}");
        }
        if echo && !noecho {
            println!("sftp> {line}");
        }
        let res = match parsed {
            Ok(None) => Ok(Flow::Continue),
            Ok(Some(p)) => self.run(&p, err_abort),
            Err(_) => Err(String::new()),
        };
        match res {
            Ok(Flow::Quit) => 1,
            Ok(Flow::Continue) => 0,
            Err(msg) => {
                if !msg.is_empty() {
                    error!("{msg}");
                }
                if err_abort { -1 } else { 0 }
            }
        }
    }

    fn run(&mut self, p: &Parsed, err_abort: bool) -> Result<Flow, String> {
        let path1 = p.path1.as_deref().unwrap_or("");
        let path2 = p.path2.as_deref();
        match p.cmd {
            Cmd::Get | Cmd::Reget => self.process_get(
                path1,
                path2,
                p.has('p') || p.has('P'),
                p.has('r') || p.has('R'),
                p.has('a') || p.cmd == Cmd::Reget,
                p.has('f'),
            )?,
            Cmd::Put | Cmd::Reput => self.process_put(
                path1,
                path2,
                p.has('p') || p.has('P'),
                p.has('r') || p.has('R'),
                p.has('a') || p.cmd == Cmd::Reput,
                p.has('f'),
            )?,
            Cmd::Copy => {
                let (o, n) = (self.abs(path1), self.abs(path2.unwrap_or("")));
                self.copy(&o, &n)?;
            }
            Cmd::Rename => {
                let (o, n) = (self.abs(path1), self.abs(path2.unwrap_or("")));
                let res = if !p.has('l') && self.sftp.has_extension("posix-rename@openssh.com") {
                    self.sftp.posix_rename(&o, &n)
                } else {
                    self.sftp.rename(&o, &n)
                };
                res.map_err(|e| {
                    format!(
                        "remote rename \"{}\" to \"{}\": {}",
                        lossy(&o),
                        lossy(&n),
                        fx(&e)
                    )
                })?;
            }
            Cmd::Symlink | Cmd::Link => {
                let link = self.abs(path2.unwrap_or(""));
                if p.cmd == Cmd::Symlink || p.has('s') {
                    // The target is stored as given (relative stays relative).
                    self.sftp.symlink(path1.as_bytes(), &link).map_err(|e| {
                        format!(
                            "remote symlink file \"{path1}\" to \"{}\": {}",
                            lossy(&link),
                            fx(&e)
                        )
                    })?;
                } else {
                    if !self.sftp.has_extension("hardlink@openssh.com") {
                        return Err("Server does not support hardlink@openssh.com extension".into());
                    }
                    let target = self.abs(path1);
                    self.sftp.hardlink(&target, &link).map_err(|e| {
                        format!(
                            "remote link \"{}\" to \"{}\": {}",
                            lossy(&target),
                            lossy(&link),
                            fx(&e)
                        )
                    })?;
                }
            }
            Cmd::Rm => {
                let pat = self.abs_glob(path1);
                let g = self.glob(&pat, false, true);
                let mut err = false;
                for f in &g.paths {
                    if interrupted() {
                        break;
                    }
                    if !self.quiet {
                        println!("Removing {}", safe_display(f));
                    }
                    err = match self.sftp.remove(f) {
                        Ok(()) => false,
                        Err(e) => {
                            error!("remote delete {}: {}", lossy(f), fx(&e));
                            true
                        }
                    };
                    if err && err_abort {
                        break;
                    }
                }
                if err {
                    return Err(String::new());
                }
            }
            Cmd::Mkdir => {
                let abs = self.abs(path1);
                if p.has('p') {
                    self.mkpath(&abs)?;
                } else {
                    self.mkdir(&abs)?;
                }
            }
            Cmd::Rmdir => {
                let abs = self.abs(path1);
                self.sftp
                    .rmdir(&abs)
                    .map_err(|e| format!("remote rmdir \"{}\": {}", lossy(&abs), fx(&e)))?;
            }
            Cmd::Chdir => self.cd(p.path1.as_deref())?,
            Cmd::Ls => match &p.path1 {
                // Listing the working directory never fails the command.
                None => {
                    let pwd = self.pwd.clone();
                    let _ = self.do_ls_dir(&pwd, Some(&pwd), ls_flags(&p.flags));
                }
                Some(path) => {
                    // Relative paths are shown relative.
                    let strip = (!path.starts_with('/')).then(|| self.pwd.clone());
                    let pat = self.abs_glob(path);
                    self.do_globbed_ls(&pat, strip.as_deref(), ls_flags(&p.flags))?;
                }
            },
            Cmd::Df => {
                let path = make_absolute(p.path1.as_deref().unwrap_or("").as_bytes(), &self.pwd);
                self.df(&path, p.has('h'), p.has('i'))?;
            }
            Cmd::Lchdir => {
                let target =
                    tilde_expand(p.path1.as_deref().filter(|s| !s.is_empty()).unwrap_or("~"));
                std::env::set_current_dir(&target).map_err(|e| {
                    format!(
                        "Couldn't change local directory to \"{target}\": {}",
                        strerror(&e)
                    )
                })?;
            }
            Cmd::Lmkdir => {
                if p.has('p') {
                    local_mkdir_path(path1)?;
                } else {
                    local_mkdir(path1).map_err(|e| {
                        format!(
                            "Couldn't create local directory \"{path1}\": {}",
                            strerror(&e)
                        )
                    })?;
                }
            }
            Cmd::Lls => {
                if p.rest.is_empty() {
                    local_shell("ls");
                } else {
                    local_shell(&format!("ls {}", p.rest));
                }
            }
            Cmd::Shell => local_shell(&p.rest),
            Cmd::Lumask => {
                set_umask(p.n_arg as u32);
                println!("Local umask: {:03o}", p.n_arg);
            }
            Cmd::Chmod => {
                let pat = self.abs_glob(path1);
                let g = self.glob(&pat, false, true);
                let mut err = false;
                for f in &g.paths {
                    if interrupted() {
                        break;
                    }
                    if !self.quiet {
                        println!("Changing mode on {}", safe_display(f));
                    }
                    let mut a = Attrs::default();
                    a.permissions = Some(p.n_arg as u32);
                    err = !self.setstat(f, &a, p.has('h'));
                    if err && err_abort {
                        break;
                    }
                }
                if err {
                    return Err(String::new());
                }
            }
            Cmd::Chown | Cmd::Chgrp => {
                let pat = self.abs_glob(path1);
                let g = self.glob(&pat, false, true);
                let mut err = false;
                for f in &g.paths {
                    if interrupted() {
                        break;
                    }
                    let cur = if p.has('h') {
                        self.sftp.lstat(f)
                    } else {
                        self.sftp.stat(f)
                    };
                    let owners = match cur {
                        Ok(a) => a.uid_gid,
                        Err(e) => {
                            error!("stat remote: {}", fx(&e));
                            if err_abort {
                                err = true;
                                break;
                            }
                            continue;
                        }
                    };
                    let Some((uid, gid)) = owners else {
                        error!(
                            "Can't get current ownership of remote file \"{}\"",
                            lossy(f)
                        );
                        if err_abort {
                            err = true;
                            break;
                        }
                        continue;
                    };
                    let id = p.n_arg as u32;
                    let mut a = Attrs::default();
                    if p.cmd == Cmd::Chown {
                        if !self.quiet {
                            println!("Changing owner on {}", safe_display(f));
                        }
                        a.uid_gid = Some((id, gid));
                    } else {
                        if !self.quiet {
                            println!("Changing group on {}", safe_display(f));
                        }
                        a.uid_gid = Some((uid, id));
                    }
                    err = !self.setstat(f, &a, p.has('h'));
                    if err && err_abort {
                        break;
                    }
                }
                if err {
                    return Err(String::new());
                }
            }
            Cmd::Pwd => println!("Remote working directory: {}", safe_display(&self.pwd)),
            Cmd::Lpwd => {
                let d = std::env::current_dir()
                    .map_err(|e| format!("Couldn't get local cwd: {}", strerror(&e)))?;
                println!("Local working directory: {}", d.display());
            }
            Cmd::Quit => return Ok(Flow::Quit),
            Cmd::Help => println!("{HELP}"),
            Cmd::Version => println!("SFTP protocol version {}", self.sftp.server_version()),
            Cmd::Progress => {
                self.progress = !self.progress;
                println!(
                    "Progress meter {}",
                    if self.progress { "enabled" } else { "disabled" }
                );
            }
        }
        Ok(Flow::Continue)
    }

    /// `setstat`, or with `-h` `lsetstat@openssh.com` (the link itself).
    fn setstat(&mut self, path: &[u8], a: &Attrs, nofollow: bool) -> bool {
        if nofollow {
            if !self.sftp.has_extension("lsetstat@openssh.com") {
                error!("Server does not support lsetstat@openssh.com extension");
                return false;
            }
            if let Err(e) = self.sftp.lsetstat(path, a) {
                error!("remote lsetstat \"{}\": {}", lossy(path), fx(&e));
                return false;
            }
        } else if let Err(e) = self.sftp.setstat(path, a.clone()) {
            error!("remote setstat \"{}\": {}", lossy(path), fx(&e));
            return false;
        }
        true
    }

    fn mkdir(&mut self, path: &[u8]) -> Res {
        let mut a = Attrs::default();
        a.permissions = Some(0o777);
        self.sftp
            .mkdir(path, a)
            .map_err(|e| format!("remote mkdir \"{}\": {}", lossy(path), fx(&e)))
    }

    /// `mkdir -p`: each missing directory along the path.
    fn mkpath(&mut self, path: &[u8]) -> Res {
        let mut i = 0;
        loop {
            while i < path.len() && path[i] == b'/' {
                i += 1;
            }
            while i < path.len() && path[i] != b'/' {
                i += 1;
            }
            let prefix = &path[..i];
            if !self.remote_is_dir(prefix) {
                self.mkdir(prefix)?;
            }
            if i >= path.len() {
                return Ok(());
            }
        }
    }

    fn cd(&mut self, p: Option<&str>) -> Res {
        let target = match p.filter(|s| !s.is_empty()) {
            Some(p) => self.abs(p),
            None => self.startdir.clone(),
        };
        let real = self
            .sftp
            .realpath(&target)
            .map_err(|e| realpath_error(&target, &e))?;
        let a = self
            .sftp
            .stat(&real)
            .map_err(|e| format!("stat remote: {}", fx(&e)))?;
        if a.permissions.is_none() {
            return Err("Can't change directory: Can't check target".into());
        }
        if !is_dir(&a) {
            return Err(format!(
                "Can't change directory: \"{}\" is not a directory",
                lossy(&real)
            ));
        }
        self.pwd = real;
        Ok(())
    }

    /// `cp`: a copy made by the server (`copy-data`), as OpenSSH's
    /// sftp_copy: the new file gets the old one's permissions (without
    /// set-id bits).
    fn copy(&mut self, old: &[u8], new: &[u8]) -> Res {
        if !self.sftp.has_extension("copy-data") {
            return Err("Server does not support copy-data extension".into());
        }
        let a = self
            .sftp
            .stat(old)
            .map_err(|e| format!("stat remote: {}", fx(&e)))?;
        let mode = match a.permissions {
            Some(p) if p & S_IFMT != S_IFREG => {
                return Err(format!("Cannot copy non-regular file: {}", lossy(old)));
            }
            Some(p) => p & 0o777,
            None => 0o666,
        };
        let rh = self
            .sftp
            .open(old, puressh::sftp::FXF_READ, Attrs::default())
            .map_err(|e| format!("remote open(\"{}\"): {}", lossy(old), fx(&e)))?;
        let mut attrs = Attrs::default();
        attrs.permissions = Some(mode);
        let wh = match self.sftp.open(
            new,
            puressh::sftp::FXF_WRITE | puressh::sftp::FXF_CREAT | puressh::sftp::FXF_TRUNC,
            attrs,
        ) {
            Ok(h) => h,
            Err(e) => {
                let msg = format!("remote open(\"{}\"): {}", lossy(new), fx(&e));
                let _ = self.sftp.close(&rh);
                return Err(msg);
            }
        };
        let res = self.sftp.copy_data(&rh, 0, 0, &wh, 0);
        let _ = self.sftp.close(&rh);
        let _ = self.sftp.close(&wh);
        res.map_err(|e| {
            format!(
                "Couldn't copy file \"{}\" to \"{}\": {}",
                lossy(old),
                lossy(new),
                fx(&e)
            )
        })
    }

    /// A directory's entries (`sftp_readdir`), reporting failures.
    fn readdir(&mut self, path: &[u8]) -> Result<Vec<NameEntry>, ()> {
        let h = match self.sftp.opendir(path) {
            Ok(h) => h,
            Err(e) => {
                error!("remote readdir(\"{}\"): {}", lossy(path), fx(&e));
                return Err(());
            }
        };
        let mut out = Vec::new();
        let res = loop {
            if interrupted() {
                // No partial listings after an interrupt.
                out.clear();
                break Ok(out);
            }
            match self.sftp.readdir(&h) {
                Ok(Some(batch)) => {
                    for e in batch {
                        // Names with a `/` could steer recursive transfers.
                        if e.filename.is_empty() || e.filename.contains(&b'/') {
                            error!(
                                "Server sent suspect path \"{}\" during readdir of \"{}\"",
                                lossy(&e.filename),
                                lossy(path)
                            );
                        } else {
                            out.push(e);
                        }
                    }
                }
                Ok(None) => break Ok(out),
                Err(e) => {
                    error!("Couldn't read directory: {}", fx(&e));
                    break Err(());
                }
            }
        };
        if let Err(e) = self.sftp.close(&h) {
            error!("close remote: {}", fx(&e));
        }
        res
    }

    /// Learn the names of these owners (`users-groups-by-id@openssh.com`),
    /// for `ls -l`.
    fn lookup_owners(&mut self, ids: &[(u32, u32)]) {
        if !self.sftp.has_extension("users-groups-by-id@openssh.com") {
            return;
        }
        let mut uids: Vec<u32> = Vec::new();
        let mut gids: Vec<u32> = Vec::new();
        for (u, g) in ids {
            if !self.users.contains_key(u) && !uids.contains(u) {
                uids.push(*u);
            }
            if !self.groups.contains_key(g) && !gids.contains(g) {
                gids.push(*g);
            }
        }
        if uids.is_empty() && gids.is_empty() {
            return;
        }
        match self.sftp.users_groups_by_id(&uids, &gids) {
            Ok((un, gn)) => {
                for (id, n) in uids.iter().zip(un) {
                    if !n.is_empty() {
                        self.users.insert(*id, lossy(&n));
                    }
                }
                for (id, n) in gids.iter().zip(gn) {
                    if !n.is_empty() {
                        self.groups.insert(*id, lossy(&n));
                    }
                }
            }
            Err(e) => check(&e),
        }
    }

    /// `ls -l` line with the owners' names (unless `-n`).
    fn long_line(&self, name: &[u8], a: &Attrs, lflag: u32) -> String {
        let (uid, gid) = a.uid_gid.unwrap_or((0, 0));
        let (user, group) = if lflag & LS_NUMERIC_VIEW == 0 {
            (
                self.users.get(&uid).map(String::as_str),
                self.groups.get(&gid).map(String::as_str),
            )
        } else {
            (None, None)
        };
        ls_file(
            &safe_display(name),
            a,
            lflag & LS_SI_UNITS != 0,
            user,
            group,
        )
    }

    /// `ls` of a directory's contents (OpenSSH's `do_ls_dir`).
    fn do_ls_dir(&mut self, path: &[u8], strip: Option<&[u8]>, lflag: u32) -> Res {
        let mut d = self.readdir(path).map_err(|_| String::new())?;
        let all = lflag & LS_SHOW_ALL != 0;
        let shown = |e: &NameEntry| e.filename[0] != b'.' || all;
        let (mut columns, mut colspace) = (1usize, 0usize);
        if lflag & LS_SHORT_VIEW == 0 {
            let m = d
                .iter()
                .filter(|e| shown(e))
                .map(|e| e.filename.len())
                .max()
                .unwrap_or(0)
                + path_strip(path, strip).len();
            let width = stdin_width();
            columns = (width / (m + 2)).max(1);
            colspace = (width / columns).min(width);
        }
        if lflag & SORT_FLAGS != 0 {
            let sort = lflag & (SORT_FLAGS | LS_REVERSE_SORT);
            d.sort_by(|a, b| ls_cmp(sort, &a.filename, &a.attrs, &b.filename, &b.attrs));
        }
        let long = lflag & LS_LONG_VIEW != 0;
        let can_ids = self.sftp.has_extension("users-groups-by-id@openssh.com");
        if long && can_ids {
            let ids: Vec<(u32, u32)> = d
                .iter()
                .map(|e| e.attrs.uid_gid.unwrap_or((0, 0)))
                .collect();
            self.lookup_owners(&ids);
        }
        let out = io::stdout();
        let mut out = out.lock();
        let mut c = 1;
        for e in d.iter().filter(|e| shown(e)) {
            if interrupted() {
                break;
            }
            let fname = path_strip(&path_append(path, &e.filename), strip);
            if long {
                let line = if lflag & (LS_NUMERIC_VIEW | LS_SI_UNITS) != 0 || can_ids {
                    self.long_line(&fname, &e.attrs, lflag)
                } else {
                    safe_display(&e.longname)
                };
                let _ = writeln!(out, "{line}");
            } else {
                let _ = write!(out, "{:<colspace$}", safe_display(&fname));
                if c >= columns {
                    let _ = writeln!(out);
                    c = 1;
                } else {
                    c += 1;
                }
            }
        }
        if !long && c != 1 {
            let _ = writeln!(out);
        }
        Ok(())
    }

    /// `ls path` (OpenSSH's `do_globbed_ls`): the matches of a pattern, or
    /// a single directory's contents.
    fn do_globbed_ls(&mut self, path: &[u8], strip: Option<&[u8]>, lflag: u32) -> Res {
        let g = self.glob_brace(path);
        if g.matched == 0 {
            return Err(format!("Can't ls: \"{}\" not found", lossy(path)));
        }
        if g.matched == 1 && g.stats[0].as_ref().is_some_and(is_dir) {
            let dir = g.paths[0].clone();
            return self.do_ls_dir(&dir, strip, lflag);
        }
        let width = stdin_width();
        let (mut columns, mut colspace) = (1usize, 0usize);
        if lflag & LS_SHORT_VIEW == 0 {
            let m = g.paths.iter().map(Vec::len).max().unwrap_or(0);
            columns = (width / (m + 2)).max(1);
            colspace = width / columns;
        }
        let mut idx: Vec<usize> = (0..g.paths.len()).collect();
        if lflag & SORT_FLAGS != 0 {
            let sort = lflag & (SORT_FLAGS | LS_REVERSE_SORT);
            let rev = sort & LS_REVERSE_SORT != 0;
            idx.sort_by(|&a, &b| match (&g.stats[a], &g.stats[b]) {
                // Entries without stat information go last.
                (None, None) => std::cmp::Ordering::Equal,
                (None, Some(_)) if rev => std::cmp::Ordering::Less,
                (None, Some(_)) => std::cmp::Ordering::Greater,
                (Some(_), None) if rev => std::cmp::Ordering::Greater,
                (Some(_), None) => std::cmp::Ordering::Less,
                (Some(sa), Some(sb)) => ls_cmp(sort, &g.paths[a], sa, &g.paths[b], sb),
            });
        }
        let long = lflag & LS_LONG_VIEW != 0;
        if long {
            let ids: Vec<(u32, u32)> = g
                .stats
                .iter()
                .flatten()
                .map(|a| a.uid_gid.unwrap_or((0, 0)))
                .collect();
            self.lookup_owners(&ids);
        }
        let mut c = 1;
        for i in idx {
            if interrupted() {
                break;
            }
            let fname = path_strip(&g.paths[i], strip);
            if long {
                let Some(st) = &g.stats[i] else {
                    error!("no stat information for {}", lossy(&fname));
                    continue;
                };
                println!("{}", self.long_line(&fname, st, lflag));
            } else {
                print!("{:<colspace$}", safe_display(&fname));
                if c >= columns {
                    println!();
                    c = 1;
                } else {
                    c += 1;
                }
            }
        }
        if !long && c != 1 {
            println!();
        }
        Ok(())
    }

    fn df(&mut self, path: &[u8], hflag: bool, iflag: bool) -> Res {
        if !self.sftp.has_extension("statvfs@openssh.com") {
            return Err("Server does not support statvfs@openssh.com extension".into());
        }
        // Failures are not reported, as by OpenSSH.
        let v = self.sftp.statvfs(path).map_err(|e| {
            check(&e);
            String::new()
        })?;
        let (frsize, blocks, bfree, bavail, files, ffree, favail) =
            (v[1], v[2], v[3], v[4], v[5], v[6], v[7]);
        let cap = |used: u64, total: u64| match total {
            0 => "ERR".to_string(),
            t => format!("{:3}%", used.wrapping_mul(100) / t),
        };
        let used = blocks.wrapping_sub(bfree);
        if iflag {
            println!("     Inodes        Used       Avail      (root)    %Capacity");
            println!(
                "{files:>11} {:>11} {favail:>11} {ffree:>11}         {}",
                files.wrapping_sub(ffree),
                cap(files.wrapping_sub(ffree), files)
            );
        } else if hflag {
            let s = |b: u64| fmt_scaled(b.wrapping_mul(frsize));
            println!("    Size     Used    Avail   (root)    %Capacity");
            println!(
                "{:>7}B {:>7}B {:>7}B {:>7}B         {}",
                s(blocks),
                s(used),
                s(bavail),
                s(bfree),
                cap(used, blocks)
            );
        } else {
            let k = |b: u64| frsize.wrapping_mul(b) / 1024;
            println!("        Size         Used        Avail       (root)    %Capacity");
            println!(
                "{:>12} {:>12} {:>12} {:>12}         {}",
                k(blocks),
                k(used),
                k(bavail),
                k(bfree),
                cap(used, blocks)
            );
        }
        Ok(())
    }

    /// `get` / `reget` (OpenSSH's `process_get`).
    fn process_get(
        &mut self,
        src: &str,
        dst: Option<&str>,
        pflag: bool,
        rflag: bool,
        resume: bool,
        fflag: bool,
    ) -> Res {
        let abs_src = self.abs_glob(src);
        let g = self.glob(&abs_src, true, false);
        if g.matched == 0 {
            return Err(format!("File \"{}\" not found.", lossy(&abs_src)));
        }
        // Several matches need a directory to go to.
        if g.matched > 1 && dst.is_some_and(|d| !Path::new(d).is_dir()) {
            return Err(format!(
                "Multiple source paths, but destination \"{}\" is not a directory",
                dst.unwrap_or_default()
            ));
        }
        let resume = resume || self.global_a;
        let (preserve, recurse, fsync) = (
            pflag || self.global_p,
            rflag || self.global_r,
            fflag || self.global_f,
        );
        let mut failed = false;
        for path in &g.paths {
            if interrupted() {
                break;
            }
            // `..` and remote roots download into the destination itself.
            let mut filename = lossy(&basename(path));
            if filename == ".." || filename.bytes().all(|c| c == b'/') {
                filename = ".".into();
            }
            let abs_dst = match dst {
                Some(d) if g.matched == 1 && !Path::new(d).is_dir() => d.to_string(),
                Some(d) => lossy(&path_append(d.as_bytes(), filename.as_bytes())),
                None => filename,
            };
            if !self.quiet {
                println!(
                    "{} {} to {abs_dst}",
                    if resume { "Resuming" } else { "Fetching" },
                    safe_display(path)
                );
            }
            let ok = if path.ends_with(b"/") && recurse {
                self.download_dir(path, &abs_dst, preserve, resume, fsync)
            } else {
                self.download(path, &abs_dst, None, preserve, resume, fsync)
            };
            failed |= !ok;
        }
        if failed { Err(String::new()) } else { Ok(()) }
    }

    /// `put` / `reput` (OpenSSH's `process_put`).
    fn process_put(
        &mut self,
        src: &str,
        dst: Option<&str>,
        pflag: bool,
        rflag: bool,
        resume: bool,
        fflag: bool,
    ) -> Res {
        let tmp_dst = dst.map(|d| self.abs(d));
        let (paths, matched) = local_glob(src);
        let dst_is_dir = match &tmp_dst {
            Some(d) => self.remote_is_dir(d),
            None => true,
        };
        if matched > 1 && !dst_is_dir {
            return Err(format!(
                "Multiple paths match, but destination \"{}\" is not a directory",
                lossy(tmp_dst.as_deref().unwrap_or_default())
            ));
        }
        let resume = resume || self.global_a;
        let (preserve, recurse, fsync) = (
            pflag || self.global_p,
            rflag || self.global_r,
            fflag || self.global_f,
        );
        let mut failed = false;
        for path in &paths {
            if interrupted() {
                break;
            }
            if let Err(e) = std::fs::metadata(path) {
                error!("stat {path}: {}", strerror(&e));
                failed = true;
                continue;
            }
            let mut filename = lossy(&basename(path.as_bytes()));
            if filename == ".." {
                filename = ".".into();
            }
            let abs_dst = match &tmp_dst {
                Some(d) if matched == 1 && !dst_is_dir => d.clone(),
                Some(d) => path_append(d, filename.as_bytes()),
                None => self.abs(&filename),
            };
            if !self.quiet {
                if resume {
                    println!("Resuming upload of {path} to {}", safe_display(&abs_dst));
                } else {
                    println!("Uploading {path} to {}", safe_display(&abs_dst));
                }
            }
            let ok = if path.ends_with('/') && recurse {
                self.upload_dir(path, &abs_dst, preserve, resume, fsync)
            } else {
                self.upload(path, &abs_dst, preserve, resume, fsync)
            };
            failed |= !ok;
        }
        if failed { Err(String::new()) } else { Ok(()) }
    }

    /// One file down (OpenSSH's `sftp_download`); `attrs` when known.
    fn download(
        &mut self,
        remote: &[u8],
        local: &str,
        attrs: Option<Attrs>,
        preserve: bool,
        resume: bool,
        fsync: bool,
    ) -> bool {
        let a = match attrs {
            Some(a) => a,
            None => match self.sftp.stat(remote) {
                Ok(a) => a,
                Err(e) => {
                    error!("stat remote: {}", fx(&e));
                    return false;
                }
            },
        };
        if a.permissions.is_some() && !is_reg(&a) {
            error!("download {}: not a regular file", lossy(remote));
            return false;
        }
        let have = std::fs::metadata(local).map_or(0, |m| m.len());
        if resume && have > a.size.unwrap_or(0) {
            error!("Unable to resume download of \"{local}\": local file is larger than remote");
            return false;
        }
        let opts = self.opts(preserve, resume);
        if let Err(e) = transfer::download(&mut self.sftp, remote, Path::new(local), &opts) {
            if !interrupted() {
                error!("{e}");
            }
            return false;
        }
        if resume && have >= a.size.unwrap_or(0) {
            if !self.log_quiet {
                error!("File \"{local}\" was not modified");
            }
        } else if fsync && let Err(e) = std::fs::File::open(local).and_then(|f| f.sync_all()) {
            error!("local sync \"{local}\": {}", strerror(&e));
            return false;
        }
        true
    }

    /// `get -R` (OpenSSH's `sftp_download_dir`).
    fn download_dir(
        &mut self,
        src: &[u8],
        dst: &str,
        preserve: bool,
        resume: bool,
        fsync: bool,
    ) -> bool {
        let canon = match self.sftp.realpath(src) {
            Ok(p) => p,
            Err(e) => {
                error!("{}", realpath_error(src, &e));
                error!("download \"{}\": path canonicalization failed", lossy(src));
                return false;
            }
        };
        self.download_dir_at(&canon, dst, 0, None, preserve, resume, fsync)
    }

    #[allow(clippy::too_many_arguments)]
    fn download_dir_at(
        &mut self,
        src: &[u8],
        dst: &str,
        depth: usize,
        dirattrib: Option<Attrs>,
        preserve: bool,
        resume: bool,
        fsync: bool,
    ) -> bool {
        if depth >= MAX_DIR_DEPTH {
            error!("Maximum directory depth exceeded: {depth} levels");
            return false;
        }
        let da = match dirattrib.or_else(|| self.stat_quiet(src, true)) {
            Some(a) => a,
            None => {
                error!("stat remote \"{}\" directory failed", lossy(src));
                return false;
            }
        };
        if !is_dir(&da) {
            error!("\"{}\" is not a directory", lossy(src));
            return false;
        }
        println!("Retrieving {}", safe_display(src));
        let (mode, tmpmode) = match da.permissions {
            Some(p) => (p & 0o1777, (p & 0o1777) | 0o300),
            None => (0o777, 0o777),
        };
        if let Err(e) = local_mkdir_mode(dst, tmpmode)
            && e.kind() != io::ErrorKind::AlreadyExists
        {
            error!("mkdir {dst}: {}", strerror(&e));
            return false;
        }
        let Ok(entries) = self.readdir(src) else {
            error!("remote readdir \"{}\" failed", lossy(src));
            return false;
        };
        let mut ok = true;
        for e in entries {
            if interrupted() {
                break;
            }
            let new_dst = lossy(&path_append(dst.as_bytes(), &e.filename));
            let new_src = path_append(src, &e.filename);
            let a = e.attrs;
            if is_link(&a) {
                if !self.log_quiet {
                    error!("download \"{}\": not a regular file", lossy(&new_src));
                }
            } else if is_dir(&a) {
                if e.filename == b"." || e.filename == b".." {
                    continue;
                }
                ok &= self.download_dir_at(
                    &new_src,
                    &new_dst,
                    depth + 1,
                    Some(a),
                    preserve,
                    resume,
                    fsync,
                );
            } else if is_reg(&a) {
                if !self.download(&new_src, &new_dst, Some(a), preserve, resume, fsync) {
                    error!("Download of file {} to {new_dst} failed", lossy(&new_src));
                    ok = false;
                }
            } else if !self.log_quiet {
                error!("download \"{}\": not a regular file", lossy(&new_src));
            }
        }
        if preserve
            && let Some((at, mt)) = da.atime_mtime
            && let Err(e) = set_local_times(dst, at, mt)
        {
            error!("local set times on \"{dst}\": {}", strerror(&e));
        }
        if mode != tmpmode
            && let Err(e) = set_local_mode(dst, mode)
        {
            error!("local chmod directory \"{dst}\": {}", strerror(&e));
        }
        ok
    }

    /// One file up (OpenSSH's `sftp_upload`).
    fn upload(
        &mut self,
        local: &str,
        remote: &[u8],
        preserve: bool,
        resume: bool,
        fsync: bool,
    ) -> bool {
        let md = match std::fs::File::open(local) {
            Ok(f) => match f.metadata() {
                Ok(m) => m,
                Err(e) => {
                    error!("fstat local \"{local}\": {}", strerror(&e));
                    return false;
                }
            },
            Err(e) => {
                error!("open local \"{local}\": {}", strerror(&e));
                return false;
            }
        };
        if !md.is_file() {
            error!("local \"{local}\" is not a regular file");
            return false;
        }
        if resume {
            match self.sftp.stat(remote) {
                Err(e) => {
                    error!("stat remote: {}", fx(&e));
                    return false;
                }
                Ok(c) if c.size.unwrap_or(0) >= md.len() => {
                    error!("resume \"{local}\": destination file same size or larger");
                    return false;
                }
                Ok(_) => {}
            }
        }
        let opts = self.opts(preserve, resume);
        if let Err(e) = transfer::upload(&mut self.sftp, Path::new(local), remote, &opts) {
            if !interrupted() {
                error!("{e}");
            }
            return false;
        }
        if fsync
            && self.sftp.has_extension("fsync@openssh.com")
            && let Ok(h) = self
                .sftp
                .open(remote, puressh::sftp::FXF_WRITE, Attrs::default())
        {
            if let Err(e) = self.sftp.fsync(&h) {
                error!("remote fsync: {}", fx(&e));
            }
            let _ = self.sftp.close(&h);
        }
        true
    }

    /// `put -R` (OpenSSH's `sftp_upload_dir`).
    fn upload_dir(
        &mut self,
        src: &str,
        dst: &[u8],
        preserve: bool,
        resume: bool,
        fsync: bool,
    ) -> bool {
        let canon = match self.sftp.realpath(dst) {
            Ok(p) => p,
            Err(e) => {
                error!("{}", realpath_error(dst, &e));
                error!("upload \"{}\": path canonicalization failed", lossy(dst));
                return false;
            }
        };
        self.upload_dir_at(src, &canon, 0, preserve, resume, fsync)
    }

    fn upload_dir_at(
        &mut self,
        src: &str,
        dst: &[u8],
        depth: usize,
        preserve: bool,
        resume: bool,
        fsync: bool,
    ) -> bool {
        if depth >= MAX_DIR_DEPTH {
            error!("Maximum directory depth exceeded: {depth} levels");
            return false;
        }
        let md = match std::fs::metadata(src) {
            Ok(m) => m,
            Err(e) => {
                error!("stat local \"{src}\": {}", strerror(&e));
                return false;
            }
        };
        if !md.is_dir() {
            error!("\"{src}\" is not a directory");
            return false;
        }
        println!("Entering {src}");
        let mut a = Attrs::default();
        let perm = local_mode(&md) & 0o1777;
        a.permissions = Some(perm);
        if preserve {
            a.atime_mtime = local_times(&md);
        }
        // The directory must stay writable for us while we fill it.
        let mut wa = a.clone();
        wa.permissions = Some(perm | 0o300);
        let created = match self.sftp.mkdir(dst, wa) {
            Ok(()) => true,
            Err(e) => {
                check(&e);
                match self.sftp.stat(dst) {
                    Err(e) => {
                        error!("stat remote: {}", fx(&e));
                        return false;
                    }
                    Ok(d) if !is_dir(&d) => {
                        error!("\"{}\" exists but is not a directory", lossy(dst));
                        return false;
                    }
                    Ok(_) => false,
                }
            }
        };
        let rd = match std::fs::read_dir(src) {
            Ok(rd) => rd,
            Err(e) => {
                error!("local opendir \"{src}\": {}", strerror(&e));
                return false;
            }
        };
        let mut ok = true;
        for entry in rd.flatten() {
            if interrupted() {
                break;
            }
            let filename = entry.file_name().to_string_lossy().into_owned();
            let new_dst = path_append(dst, filename.as_bytes());
            let new_src = lossy(&path_append(src.as_bytes(), filename.as_bytes()));
            let lmd = match std::fs::symlink_metadata(&new_src) {
                Ok(m) => m,
                Err(e) => {
                    if !self.log_quiet {
                        error!("local lstat \"{filename}\": {}", strerror(&e));
                    }
                    ok = false;
                    continue;
                }
            };
            if lmd.file_type().is_symlink() {
                if !self.log_quiet {
                    error!("{filename}: not a regular file");
                }
            } else if lmd.is_dir() {
                ok &= self.upload_dir_at(&new_src, &new_dst, depth + 1, preserve, resume, fsync);
            } else if lmd.is_file() {
                if !self.upload(&new_src, &new_dst, preserve, resume, fsync) {
                    error!("upload \"{new_src}\" to \"{}\" failed", lossy(&new_dst));
                    ok = false;
                }
            } else if !self.log_quiet {
                error!("{filename}: not a regular file");
            }
        }
        if created || preserve {
            let _ = self.setstat(dst, &a, false);
        }
        ok
    }
}

fn interrupted() -> bool {
    transfer::INTERRUPTED.load(std::sync::atomic::Ordering::Relaxed)
}

fn set_interrupted(v: bool) {
    transfer::INTERRUPTED.store(v, std::sync::atomic::Ordering::Relaxed);
}

/// SIGINT as OpenSSH's sftp handles it: at the interactive prompt a new
/// prompt, during a command "Interrupt" (the command stops), otherwise
/// the end of sftp (status 1).
mod sigint {
    use std::sync::atomic::{AtomicU8, Ordering};

    pub const EXIT: u8 = 0;
    pub const PROMPT: u8 = 1;
    pub const COMMAND: u8 = 2;

    static MODE: AtomicU8 = AtomicU8::new(EXIT);

    pub fn set(mode: u8) {
        MODE.store(mode, Ordering::Relaxed);
    }

    #[cfg(unix)]
    extern "C" fn handler(_: libc::c_int) {
        // Only atomics, write(2) and _exit(2): async-signal-safe.
        let msg: &[u8] = match MODE.load(Ordering::Relaxed) {
            COMMAND => b"\rInterrupt  \n",
            PROMPT => b"\nsftp> ",
            // SAFETY: _exit is async-signal-safe.
            _ => unsafe { libc::_exit(1) },
        };
        super::transfer::INTERRUPTED.store(true, Ordering::Relaxed);
        let fd = if msg[0] == b'\r' { 2 } else { 1 };
        // SAFETY: a valid buffer; the result does not matter.
        unsafe {
            libc::write(fd, msg.as_ptr().cast(), msg.len());
        }
    }

    /// Ignore SIGINT (inherited by the transport we spawn next).
    pub fn ignore() {
        #[cfg(unix)]
        // SAFETY: setting a disposition.
        unsafe {
            libc::signal(libc::SIGINT, libc::SIG_IGN);
        }
    }

    pub fn install() {
        #[cfg(unix)]
        // SAFETY: a plain sigaction with an async-signal-safe handler.
        unsafe {
            let mut sa: libc::sigaction = std::mem::zeroed();
            sa.sa_sigaction = handler as *const () as libc::sighandler_t;
            sa.sa_flags = libc::SA_RESTART;
            libc::sigemptyset(&mut sa.sa_mask);
            libc::sigaction(libc::SIGINT, &sa, std::ptr::null_mut());
        }
    }
}

/// The message for a failed `realpath`: the server's own text when it
/// sent one, as OpenSSH prints.
fn realpath_error(path: &[u8], e: &SftpError) -> String {
    let text = match e {
        SftpError::Status { message, .. } if !message.is_empty() => message.clone(),
        other => fx(other).to_string(),
    };
    format!("realpath {}: {text}", lossy(path))
}

/// Expand a local pattern as `glob(3)` with `GLOB_NOCHECK | GLOB_MARK`:
/// `(paths, how many matched)`.
fn local_glob(pattern: &str) -> (Vec<String>, usize) {
    let candidates = if transfer::has_glob(pattern.as_bytes()) {
        transfer::local_glob(pattern).unwrap_or_default()
    } else {
        vec![lossy(&transfer::unescape(pattern.as_bytes())).into()]
    };
    let mut out = Vec::new();
    for p in candidates {
        let Ok(md) = std::fs::symlink_metadata(&p) else {
            continue;
        };
        let mut s = p.to_string_lossy().into_owned();
        let dir = md.is_dir() || (md.file_type().is_symlink() && p.is_dir());
        if dir && !s.ends_with('/') {
            s.push('/');
        }
        out.push(s);
    }
    out.sort();
    let matched = out.len();
    if matched == 0 {
        out.push(lossy(&transfer::unescape(pattern.as_bytes())));
    }
    (out, matched)
}

/// OpenSSH's `tilde_expand_filename` for `lcd`: `~`, `~/path`,
/// `~user/path` (an unknown user ends sftp).
fn tilde_expand(p: &str) -> String {
    let Some(rest) = p.strip_prefix('~') else {
        return p.to_string();
    };
    let (user, path) = match rest.split_once('/') {
        Some((u, path)) => (u, path.trim_start_matches('/')),
        None => (rest, ""),
    };
    let Some(mut home) = home_dir(user) else {
        if user.is_empty() {
            error!("tilde_expand: No such uid");
        } else {
            error!("tilde_expand: No such user {user}");
        }
        let _ = io::stdout().flush();
        std::process::exit(255);
    };
    if !home.ends_with('/') {
        home.push('/');
    }
    home + path
}

/// A user's home directory (`""`: ours), from the password database.
fn home_dir(user: &str) -> Option<String> {
    #[cfg(unix)]
    {
        // SAFETY: getpwnam/getpwuid return NULL or a pointer to a static
        // record, read at once.
        unsafe {
            let pw = if user.is_empty() {
                libc::getpwuid(libc::getuid())
            } else {
                let name = std::ffi::CString::new(user).ok()?;
                libc::getpwnam(name.as_ptr())
            };
            if pw.is_null() || (*pw).pw_dir.is_null() {
                return None;
            }
            Some(
                std::ffi::CStr::from_ptr((*pw).pw_dir)
                    .to_string_lossy()
                    .into_owned(),
            )
        }
    }
    #[cfg(not(unix))]
    {
        if !user.is_empty() {
            return None;
        }
        std::env::var("USERPROFILE")
            .or_else(|_| std::env::var("HOME"))
            .ok()
    }
}

fn local_mkdir(p: &str) -> io::Result<()> {
    local_mkdir_mode(p, 0o777)
}

fn local_mkdir_mode(p: &str, mode: u32) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new().mode(mode).create(p)
    }
    #[cfg(not(unix))]
    {
        let _ = mode;
        std::fs::create_dir(p)
    }
}

/// `lmkdir -p` (OpenSSH's `mkdir_path`).
fn local_mkdir_path(p: &str) -> Res {
    let mut end = 0;
    let b = p.as_bytes();
    while end < b.len() {
        while end < b.len() && b[end] == b'/' {
            end += 1;
        }
        while end < b.len() && b[end] != b'/' {
            end += 1;
        }
        let sub = &p[..end];
        if sub.trim_start_matches('/').is_empty() {
            continue;
        }
        match local_mkdir(sub) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                if !Path::new(sub).is_dir() {
                    return Err(format!("mkdir_path: open(\"{sub}\"): Not a directory"));
                }
            }
            Err(e) => return Err(format!("mkdir_path: mkdir(\"{sub}\"): {}", strerror(&e))),
        }
    }
    Ok(())
}

fn local_mode(md: &std::fs::Metadata) -> u32 {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        md.permissions().mode()
    }
    #[cfg(not(unix))]
    {
        let _ = md;
        0o777
    }
}

fn local_times(md: &std::fs::Metadata) -> Option<(u32, u32)> {
    let secs = |t: io::Result<std::time::SystemTime>| {
        t.ok()?
            .duration_since(std::time::UNIX_EPOCH)
            .ok()
            .and_then(|d| u32::try_from(d.as_secs()).ok())
    };
    Some((secs(md.accessed())?, secs(md.modified())?))
}

fn set_local_times(p: &str, atime: u32, mtime: u32) -> io::Result<()> {
    let t = |s: u32| std::time::UNIX_EPOCH + std::time::Duration::from_secs(s.into());
    std::fs::File::open(p)?.set_times(
        std::fs::FileTimes::new()
            .set_accessed(t(atime))
            .set_modified(t(mtime)),
    )
}

fn set_local_mode(p: &str, mode: u32) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(p, std::fs::Permissions::from_mode(mode))
    }
    #[cfg(not(unix))]
    {
        let _ = (p, mode);
        Ok(())
    }
}

fn set_umask(mask: u32) {
    #[cfg(unix)]
    // SAFETY: umask only swaps the process file-creation mask.
    unsafe {
        libc::umask(mask as libc::mode_t);
    }
    #[cfg(not(unix))]
    let _ = mask;
}

/// `!command` / `!` / `lls`: run it with the user's shell.
fn local_shell(cmd: &str) {
    let shell = std::env::var("SHELL")
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "/bin/sh".into());
    let mut c = std::process::Command::new(&shell);
    if !cmd.is_empty() {
        c.arg("-c").arg(cmd);
    }
    match c.status() {
        Ok(s) => match s.code() {
            Some(0) => {}
            Some(code) => error!("Shell exited with status {code}"),
            None => error!("Shell exited abnormally"),
        },
        Err(e) => eprintln!("Couldn't execute \"{shell}\": {}", strerror(&e)),
    }
}

/// Run commands from `input` until EOF or `quit` (OpenSSH's
/// `interactive_loop`). In batch mode the first failing command (unless
/// prefixed with `-`) aborts; the result is the exit status.
fn command_loop(sess: &mut Session, input: &mut dyn BufRead, batch: bool) -> u8 {
    let interactive = !batch && io::stdin().is_terminal();
    let mut buf = Vec::new();
    loop {
        set_interrupted(false);
        // Ctrl-C at the prompt starts a new one; otherwise it ends sftp.
        sigint::set(if interactive {
            sigint::PROMPT
        } else {
            sigint::EXIT
        });
        if interactive {
            print!("sftp> ");
            let _ = io::stdout().flush();
        }
        buf.clear();
        let read = input.read_until(b'\n', &mut buf);
        set_interrupted(false);
        sigint::set(sigint::COMMAND);
        match read {
            Ok(0) | Err(_) => {
                if interactive {
                    println!();
                }
                return 0;
            }
            Ok(_) => {}
        }
        let line = String::from_utf8_lossy(&buf);
        let line = line.split('\n').next().unwrap_or("");
        // Commands not typed at a terminal are echoed.
        match sess.dispatch(line, batch, !interactive) {
            0 => {}
            1 => return 0,
            _ => return 1,
        }
    }
}

fn run() -> u8 {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut cli = match parse_args(&args) {
        Ok(c) => c,
        Err(Exit::Usage(msg)) => {
            if let Some(m) = msg {
                error!("{m}");
            }
            eprintln!("{USAGE}");
            return 1;
        }
        Err(Exit::Fatal(msg)) => {
            error!("{msg}");
            return 255;
        }
    };
    if !io::stderr().is_terminal() {
        cli.progress = false;
    }
    QUIET.store(cli.quiet, std::sync::atomic::Ordering::Relaxed);
    let mut file1 = None;
    sigint::ignore();
    let (pipe, label) = match &cli.sftp_direct {
        Some(server) => {
            let Some(argv) = argv_split(server) else {
                error!("Parse -D arguments: invalid format");
                return 255;
            };
            let Some((prog, rest)) = argv.split_first() else {
                error!("No sftp server specified via -D");
                return 255;
            };
            (
                SshPipe::spawn_program(prog, rest),
                format!("Attached to {server}."),
            )
        }
        None => {
            let remote =
                transfer::parse_remote(&cli.destination, &["sftp"]).unwrap_or(transfer::Remote {
                    user: None,
                    host: cli.destination.clone(),
                    port: None,
                    path: String::new(),
                });
            // A `user@host` destination without a path.
            let (user, host) = match (&remote.user, remote.host.rsplit_once('@')) {
                (None, Some((u, h))) if remote.path.is_empty() => {
                    (Some(u.to_string()), h.to_string())
                }
                _ => (remote.user.clone(), remote.host.clone()),
            };
            if host.is_empty() {
                eprintln!("Missing hostname");
                eprintln!("{USAGE}");
                return 1;
            }
            if !remote.path.is_empty() {
                file1 = Some(remote.path.clone());
            }
            let port = remote.port.or(cli.port);
            let pipe = match &cli.subsystem {
                // `-s /path/sftp-server`: run it as a command, not a subsystem.
                Some(s) if s.contains('/') => SshPipe::spawn(
                    &cli.ssh,
                    user.as_deref(),
                    &host,
                    port,
                    false,
                    std::slice::from_ref(s),
                ),
                sub => SshPipe::spawn(
                    &cli.ssh,
                    user.as_deref(),
                    &host,
                    port,
                    true,
                    &[sub.clone().unwrap_or_else(|| "sftp".into())],
                ),
            };
            (pipe, format!("Connected to {host}."))
        }
    };
    // The transport is spawned with SIGINT ignored, so Ctrl-C reaches
    // only us (it interrupts a command, as OpenSSH's sftp).
    sigint::install();
    let pipe = match pipe {
        Ok(p) => p,
        Err(e) => {
            eprintln!("exec: {}", strerror(&e));
            error!("Connection closed");
            transport_gone();
        }
    };
    let mut sftp = match SftpClient::new(pipe) {
        Ok(s) => s,
        Err(SftpError::Io(_)) => {
            error!("Connection closed");
            transport_gone();
        }
        Err(_) => {
            error!("Couldn't initialise connection to server");
            return 255;
        }
    };
    if !cli.quiet {
        eprintln!("{label}");
    }
    let home = match sftp.realpath(b".") {
        Ok(h) => h,
        Err(e) => {
            error!("{}", realpath_error(b".", &e));
            error!("Need cwd");
            return 255;
        }
    };
    let mut sess = Session {
        sftp,
        pwd: home.clone(),
        startdir: home,
        xfer: cli.xfer.clone(),
        global_a: cli.global_a,
        global_f: cli.global_f,
        global_p: cli.global_p,
        global_r: cli.global_r,
        quiet: cli.quiet,
        log_quiet: cli.log_quiet,
        progress: cli.progress,
        users: BTreeMap::new(),
        groups: BTreeMap::new(),
    };

    // `host:path`: a directory to start in, or files to fetch.
    if let Some(file1) = file1 {
        let dir = sess.abs(&file1);
        if cli.local.is_none() && sess.remote_is_dir(&dir) {
            if !cli.quiet {
                println!("Changing to: {}", safe_display(&dir));
            }
            if let Err(e) = sess.cd(Some(&lossy(&dir))) {
                if !e.is_empty() {
                    error!("{e}");
                }
                return 1;
            }
        } else {
            let res = sess.process_get(
                &lossy(&dir),
                cli.local.as_deref(),
                false,
                false,
                false,
                false,
            );
            if let Err(e) = &res
                && !e.is_empty()
            {
                error!("{e}");
            }
            return u8::from(res.is_err());
        }
    }

    match cli.batch.take() {
        Some(Batch::File(f)) => command_loop(&mut sess, &mut io::BufReader::new(f), true),
        Some(Batch::Stdin) => command_loop(&mut sess, &mut io::stdin().lock(), true),
        None => command_loop(&mut sess, &mut io::stdin().lock(), false),
    }
}

fn main() -> ExitCode {
    ExitCode::from(run())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn argv(s: &[&str]) -> Vec<String> {
        s.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn splits_like_openssh() {
        assert_eq!(split_line("get a b").unwrap(), ["get", "a", "b"]);
        assert_eq!(
            split_line("put 'my file' \"other file\"").unwrap(),
            ["put", "my file", "other file"]
        );
        assert_eq!(split_line("rm a\\ b").unwrap(), ["rm", "a b"]);
        assert!(split_line("rm 'x").is_err());
    }

    #[test]
    fn flags() {
        let (f, i) = getopt(&argv(&["get", "-pR", "a", "b"]), "afPpRr", "get").unwrap();
        assert_eq!(f, ['p', 'R']);
        assert_eq!(i, 2);
        assert_eq!(
            getopt(&argv(&["get", "-x", "a"]), "afPpRr", "mget").unwrap_err(),
            "mget: Invalid flag -x"
        );
        // `--` ends the flags; a lone `-` is an operand.
        assert_eq!(getopt(&argv(&["rm", "--", "-f"]), "", "rm").unwrap().1, 2);
        assert_eq!(getopt(&argv(&["rm", "-"]), "", "rm").unwrap().1, 1);
    }

    #[test]
    fn prefixes() {
        assert_eq!(parse_prefix("  -@ rm x"), (true, true, "rm x"));
        assert_eq!(parse_prefix("@-rm x"), (true, true, "rm x"));
        assert_eq!(parse_prefix("--ls"), (true, false, "ls"));
        assert_eq!(parse_prefix("ls -l"), (false, false, "ls -l"));
    }

    #[test]
    fn commands() {
        let p = |s: &str| parse_command(s).unwrap().unwrap();
        // mget / mput are get / put, matched case-insensitively.
        let g = p("MGET -p *.txt dst\\*");
        assert_eq!((g.cmd, g.name), (Cmd::Get, "mget"));
        assert_eq!(g.path1.as_deref(), Some("*.txt"));
        assert_eq!(g.path2.as_deref(), Some("dst*"));
        assert_eq!(p("mput a").cmd, Cmd::Put);
        assert_eq!(p("chdir /x").cmd, Cmd::Chdir);
        assert_eq!(p("lchdir").cmd, Cmd::Lchdir);
        assert!(parse_command("# comment").unwrap().is_none());
        assert_eq!(parse_command("foo").unwrap_err(), "Invalid command.");
        assert_eq!(
            parse_command("reget").unwrap_err(),
            "You must specify at least one path after a reget command."
        );
        assert_eq!(
            parse_command("cp a").unwrap_err(),
            "You must specify two paths after a cp command."
        );
        assert_eq!(
            parse_command("rename -l a b").unwrap().unwrap().flags,
            ['l']
        );
        assert_eq!(parse_command("pwd -x").unwrap_err(), "pwd: Invalid flag -x");
        assert_eq!(parse_command("dir -x").unwrap_err(), "ls: Invalid flag -x");
        assert_eq!(p("mkdir -p a/b").flags, ['p']);
        assert_eq!(p("lls -l /tmp").rest, " -l /tmp");
        assert_eq!(p("!echo hi").rest, "echo hi");
        assert_eq!(p("!").rest, "");
    }

    #[test]
    fn numeric_arguments() {
        let p = |s: &str| parse_command(s);
        let c = p("chmod -h 0755 f").unwrap().unwrap();
        assert_eq!(
            (c.n_arg, c.has('h'), c.path1.as_deref()),
            (0o755, true, Some("f"))
        );
        // chown / chgrp take strtoll base 0: decimal, 0x hex, 0 octal.
        assert_eq!(p("chown 1000 f").unwrap().unwrap().n_arg, 1000);
        assert_eq!(p("chgrp 0x10 f").unwrap().unwrap().n_arg, 16);
        assert_eq!(p("chgrp 010 f").unwrap().unwrap().n_arg, 8);
        assert_eq!(
            p("chown abc f").unwrap_err(),
            "You must supply a numeric argument to the chown command."
        );
        assert_eq!(
            p("chmod 9 f").unwrap_err(),
            "You must supply a numeric argument to the chmod command."
        );
        assert_eq!(
            p("chown -- -1 f").unwrap_err(),
            "You must supply a numeric argument to the chown command."
        );
        assert_eq!(
            p("chown 1000").unwrap_err(),
            "You must specify a path after a chown command."
        );
        assert_eq!(p("lumask 022").unwrap().unwrap().n_arg, 0o22);
    }

    #[test]
    fn program_options() {
        let usage = |a: &[&str]| matches!(parse_args(&argv(a)), Err(Exit::Usage(_)));
        let fatal = |a: &[&str]| match parse_args(&argv(a)) {
            Err(Exit::Fatal(m)) => m,
            _ => String::new(),
        };
        assert!(usage(&["-h"]));
        assert!(usage(&["a", "b", "c"]));
        assert!(usage(&["-l", "0", "h"]));
        assert_eq!(
            fatal(&["-1", "h"]),
            "SSH protocol v.1 is no longer supported"
        );
        assert_eq!(fatal(&["-B", "12k", "h"]), "Invalid buffer size \"12k\"");
        assert_eq!(fatal(&["-R", "x", "h"]), "Invalid number of requests \"x\"");
        assert_eq!(
            fatal(&["-X", "nrequests=0", "h"]),
            "Invalid number of requests \"0\": too small"
        );
        assert_eq!(
            fatal(&["-X", "buffer=1M3", "h"]),
            "Invalid buffer size \"1M3\": Invalid argument"
        );
        let c = parse_args(&argv(&["-2", "-X", "buffer=16K", "h"]))
            .ok()
            .unwrap();
        assert_eq!(c.xfer.chunk, 16384);
        // `-N` undoes `-q`'s quiet mode; the first operand ends the options.
        let c = parse_args(&argv(&["-qN", "h", "-v"])).ok().unwrap();
        assert!(!c.quiet && c.log_quiet);
        assert_eq!(c.local.as_deref(), Some("-v"));
    }

    #[test]
    fn ls_flag_order() {
        assert_eq!(ls_flags(&['l', '1']) & VIEW_FLAGS, LS_SHORT_VIEW);
        assert_eq!(ls_flags(&['1', 'l']) & VIEW_FLAGS, LS_LONG_VIEW);
        assert_eq!(ls_flags(&['S', 't']) & SORT_FLAGS, LS_TIME_SORT);
        assert_eq!(ls_flags(&['t', 'f']) & SORT_FLAGS, 0);
        assert_ne!(ls_flags(&['n']) & LS_LONG_VIEW, 0);
    }

    #[test]
    fn scaled_sizes() {
        assert_eq!(fmt_scaled(0), "0B");
        assert_eq!(fmt_scaled(6), "6B");
        assert_eq!(fmt_scaled(1023), "1023B");
        assert_eq!(fmt_scaled(3000), "2.9K");
        assert_eq!(fmt_scaled(10 * 1024), "10.0K");
        assert_eq!(fmt_scaled(150 * 1024 * 1024), "150M");
        assert_eq!(scan_scaled("16K"), Ok(16384));
        assert_eq!(scan_scaled("1.5k"), Ok(1536));
        assert_eq!(scan_scaled("100"), Ok(100));
        assert!(scan_scaled("1M3").is_err());
    }

    #[test]
    fn paths() {
        assert_eq!(path_strip(b"/h/u/dir/s1", Some(b"/h/u")), b"dir/s1");
        assert_eq!(path_strip(b"/h/u/a", Some(b"/h/u/")), b"a");
        assert_eq!(path_strip(b"/etc/x", Some(b"/h/u")), b"/etc/x");
        assert_eq!(basename(b"/r/dir/"), b"dir");
        assert_eq!(basename(b"/"), b"/");
        assert_eq!(escape_glob(b"/a*b"), b"/a\\*b");
        assert_eq!(make_absolute(b"x", b"/h"), b"/h/x");
        assert_eq!(
            argv_split("srv -d '/a b' x\\ y #c"),
            Some(argv(&["srv", "-d", "/a b", "x y"]))
        );
        assert_eq!(argv_split("srv 'x"), None);
    }

    #[test]
    fn braces() {
        let e = |p: &str| -> Vec<String> {
            brace_expand(p.as_bytes())
                .iter()
                .map(|v| lossy(v))
                .collect()
        };
        assert_eq!(e("a{b,c{d,e}}f"), ["abf", "acdf", "acef"]);
        assert_eq!(e("{a.txt,nope}"), ["a.txt", "nope"]);
        assert_eq!(e("x{[,]}y"), ["x[,]y"]);
        assert_eq!(e("{}"), ["{}"]);
        assert_eq!(e("a{b"), ["a{b"]);
        assert_eq!(e("a\\{b,c}"), ["a\\{b,c}"]);
    }

    #[test]
    fn scrubs_control_bytes() {
        assert_eq!(safe_display(b"a\x1b[31mb\n"), "a?[31mb?");
    }

    #[test]
    fn long_listing() {
        let mut a = Attrs::default();
        a.permissions = Some(0o100644);
        a.size = Some(3000);
        a.uid_gid = Some((1000, 1000));
        a.atime_mtime = Some((0, 0));
        let l = ls_file("f", &a, false, None, None);
        assert!(
            l.starts_with("-rw-r--r--    ? 1000     1000         3000 Jan  1  1970 f")
                || l.starts_with("-rw-r--r--    ? 1000     1000         3000 Dec 31  1969 f"),
            "{l}"
        );
        let l = ls_file("f", &a, true, Some("someuser1"), Some("g"));
        assert!(l.contains(" someuser1 g            2.9K "), "{l}");
        assert!(ls_file("f", &Attrs::default(), false, None, None).starts_with("?---------"));
    }
}
