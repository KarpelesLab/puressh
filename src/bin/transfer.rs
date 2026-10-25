//! Shared by `scp` and `sftp`: the remote side runs through `ssh`, exactly
//! as with OpenSSH (`ssh … -s host sftp`), so every ssh option, ssh_config
//! setting, ProxyJump, agent and multiplexing applies unchanged; and the
//! SFTP file transfers themselves (single files and trees, `-p`, `-l`,
//! globbing, progress meter).

#![allow(dead_code)]

use std::io::{self, IsTerminal, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use puressh::sftp::{
    Attrs, FXF_APPEND, FXF_CREAT, FXF_READ, FXF_TRUNC, FXF_WRITE, SftpClient, SftpError,
};

/// `ssh` invocation shared by scp and sftp: the program (`-S`) and the
/// options passed through from their own command line.
#[derive(Default, Clone)]
pub struct SshOptions {
    /// `-S program`.
    pub program: Option<String>,
    /// Options for ssh (`-F f`, `-i f`, `-o opt`, `-J j`, `-c c`, `-C`, …).
    pub args: Vec<String>,
    /// `-A`: allow agent forwarding (otherwise `ForwardAgent=no`).
    pub forward_agent: bool,
}

impl SshOptions {
    /// Add one ssh option (`-x`, or `-o value` etc.).
    pub fn push(&mut self, flag: &str, value: Option<&str>) {
        self.args.push(flag.to_string());
        if let Some(v) = value {
            self.args.push(v.to_string());
        }
    }
}

/// The ssh to run: `-S`, else the `ssh` installed next to this binary, else
/// `ssh` from `$PATH`.
pub fn ssh_program(explicit: Option<&str>) -> String {
    if let Some(p) = explicit {
        return p.to_string();
    }
    if let Ok(exe) = std::env::current_exe()
        && let Some(dir) = exe.parent()
    {
        let sibling = dir.join(if cfg!(windows) { "ssh.exe" } else { "ssh" });
        if sibling.is_file() {
            return sibling.display().to_string();
        }
    }
    "ssh".into()
}

/// A child ssh (or local sftp-server) whose stdin/stdout carry the remote
/// protocol. Its stderr is ours, so ssh's diagnostics and prompts appear.
pub struct SshPipe {
    child: Option<Child>,
    stdin: Option<ChildStdin>,
    stdout: Option<ChildStdout>,
}

impl SshPipe {
    /// `ssh [opts] [-l user] [-p port] [-s] -- host remote…`, with the options
    /// OpenSSH's scp/sftp add: no X11, agent (unless `-A`), local command,
    /// forwardings, remote command, tty or control master.
    pub fn spawn(
        opts: &SshOptions,
        user: Option<&str>,
        host: &str,
        port: Option<u16>,
        subsystem: bool,
        remote: &[String],
    ) -> io::Result<Self> {
        let mut args: Vec<String> = vec![
            "-x".into(),
            "-oPermitLocalCommand=no".into(),
            "-oClearAllForwardings=yes".into(),
            "-oRemoteCommand=none".into(),
            "-oRequestTTY=no".into(),
            "-oControlMaster=no".into(),
        ];
        if !opts.forward_agent {
            args.push("-oForwardAgent=no".into());
        }
        args.extend(opts.args.iter().cloned());
        if let Some(u) = user {
            args.push("-l".into());
            args.push(u.into());
        }
        if let Some(p) = port {
            args.push("-p".into());
            args.push(p.to_string());
        }
        if subsystem {
            args.push("-s".into());
        }
        args.push("--".into());
        args.push(host.into());
        args.extend(remote.iter().cloned());
        Self::spawn_program(&ssh_program(opts.program.as_deref()), &args)
    }

    /// Run `program args…` with piped stdin/stdout (also `-D sftp_server`).
    pub fn spawn_program(program: &str, args: &[String]) -> io::Result<Self> {
        let mut child = Command::new(program)
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .map_err(|e| io::Error::new(e.kind(), format!("{program}: {e}")))?;
        let stdin = child.stdin.take();
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| io::Error::other("no stdout pipe"))?;
        Ok(Self {
            child: Some(child),
            stdin,
            stdout: Some(stdout),
        })
    }

    /// Close our end and wait for the child; its exit code (or 255).
    pub fn finish(mut self) -> i32 {
        self.stdin.take();
        self.child
            .take()
            .and_then(|mut c| c.wait().ok())
            .and_then(|s| s.code())
            .unwrap_or(255)
    }

    /// The two ends, for pumping between two pipes; the returned guard
    /// waits for the child when dropped.
    pub fn split(mut self) -> (ChildStdout, ChildStdin, ChildGuard) {
        let out = self.stdout.take().expect("stdout");
        let inp = self.stdin.take().expect("stdin");
        (out, inp, ChildGuard(self.child.take()))
    }
}

/// Waits for a child process when dropped.
pub struct ChildGuard(Option<Child>);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        if let Some(mut c) = self.0.take() {
            let _ = c.wait();
        }
    }
}

impl Read for SshPipe {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self.stdout.as_mut() {
            Some(s) => s.read(buf),
            None => Ok(0),
        }
    }
}

impl Write for SshPipe {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self.stdin.as_mut() {
            Some(s) => s.write(buf),
            None => Err(io::ErrorKind::BrokenPipe.into()),
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        match self.stdin.as_mut() {
            Some(s) => s.flush(),
            None => Ok(()),
        }
    }
}

impl Drop for SshPipe {
    fn drop(&mut self) {
        self.stdin.take();
        if let Some(mut c) = self.child.take() {
            let _ = c.wait();
        }
    }
}

/// A remote operand: `[user@]host:path`, `[user@][v6]:path`, or an
/// `scp://` / `sftp://` URI (`[user@]host[:port][/path]`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Remote {
    pub user: Option<String>,
    pub host: String,
    pub port: Option<u16>,
    pub path: String,
}

/// Parse an operand the way OpenSSH's scp does: remote iff it has a `:`
/// before any `/` (so `./a:b` and `dir/a:b` are local), or is a URI.
pub fn parse_remote(arg: &str, schemes: &[&str]) -> Option<Remote> {
    for scheme in schemes {
        if let Some(rest) = arg.strip_prefix(scheme).and_then(|r| r.strip_prefix("://")) {
            return parse_uri(rest);
        }
    }
    let (user, rest) = match arg.find('@') {
        // `@` belongs to the user part only if it comes before the host
        // separator and any `/`.
        Some(i) if !arg[..i].contains(['/', ':']) => (Some(arg[..i].to_string()), &arg[i + 1..]),
        _ => (None, arg),
    };
    let (host, path) = if let Some(v6) = rest.strip_prefix('[') {
        let close = v6.find(']')?;
        (&v6[..close], v6[close + 1..].strip_prefix(':')?)
    } else {
        let colon = rest.find(':')?;
        if rest[..colon].contains('/') {
            return None;
        }
        (&rest[..colon], &rest[colon + 1..])
    };
    if host.is_empty() {
        return None;
    }
    Some(Remote {
        user: user.filter(|u| !u.is_empty()),
        host: host.to_string(),
        port: None,
        path: path.to_string(),
    })
}

fn parse_uri(rest: &str) -> Option<Remote> {
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i + 1..]),
        None => (rest, ""),
    };
    let (user, hostport) = match authority.rfind('@') {
        Some(i) => (Some(percent_decode(&authority[..i])), &authority[i + 1..]),
        None => (None, authority),
    };
    let (host, port) = if let Some(v6) = hostport.strip_prefix('[') {
        let close = v6.find(']')?;
        let port = v6[close + 1..].strip_prefix(':');
        (&v6[..close], port)
    } else {
        match hostport.rsplit_once(':') {
            Some((h, p)) => (h, Some(p)),
            None => (hostport, None),
        }
    };
    if host.is_empty() {
        return None;
    }
    let port = match port {
        Some(p) => Some(p.parse::<u16>().ok()?),
        None => None,
    };
    Some(Remote {
        user: user.filter(|u| !u.is_empty()),
        host: host.to_string(),
        port,
        path: percent_decode(path),
    })
}

fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%'
            && i + 2 < b.len()
            && let Some(v) = std::str::from_utf8(&b[i + 1..i + 3])
                .ok()
                .and_then(|h| u8::from_str_radix(h, 16).ok())
        {
            out.push(v);
            i += 3;
            continue;
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// `fnmatch(3)`-style matching: `*`, `?`, `[set]` / `[!set]` with ranges,
/// `\` escapes; a leading `.` must be matched explicitly.
pub fn glob_match(pattern: &[u8], name: &[u8]) -> bool {
    if name.first() == Some(&b'.') && pattern.first() != Some(&b'.') {
        return false;
    }
    fn rec(p: &[u8], n: &[u8]) -> bool {
        let (mut pi, mut ni) = (0, 0);
        let mut star: Option<(usize, usize)> = None;
        while ni < n.len() {
            let step = if pi < p.len() {
                match p[pi] {
                    b'*' => {
                        star = Some((pi, ni));
                        pi += 1;
                        continue;
                    }
                    b'?' => Some(1),
                    b'[' => match_class(&p[pi..], n[ni]),
                    b'\\' if pi + 1 < p.len() => (p[pi + 1] == n[ni]).then_some(2),
                    c => (c == n[ni]).then_some(1),
                }
            } else {
                None
            };
            match step {
                Some(adv) => {
                    pi += adv;
                    ni += 1;
                }
                None => match star {
                    Some((sp, sn)) => {
                        pi = sp + 1;
                        ni = sn + 1;
                        star = Some((sp, sn + 1));
                    }
                    None => return false,
                },
            }
        }
        p[pi..].iter().all(|c| *c == b'*')
    }
    rec(pattern, name)
}

/// Match `c` against a `[...]` class at the start of `p`; on a match, the
/// class's length in the pattern.
fn match_class(p: &[u8], c: u8) -> Option<usize> {
    let mut i = 1;
    let negate = matches!(p.get(i), Some(b'!' | b'^'));
    if negate {
        i += 1;
    }
    let mut matched = false;
    let mut first = true;
    while i < p.len() && (p[i] != b']' || first) {
        first = false;
        let lo = p[i];
        if p.get(i + 1) == Some(&b'-') && p.get(i + 2).is_some_and(|h| *h != b']') {
            if lo <= c && c <= p[i + 2] {
                matched = true;
            }
            i += 3;
        } else {
            if lo == c {
                matched = true;
            }
            i += 1;
        }
    }
    if i >= p.len() {
        // Unterminated: `[` is literal.
        return (c == b'[').then_some(1);
    }
    (matched != negate).then_some(i + 1)
}

/// Whether `s` has an unescaped `*`, `?` or `[` (a `\` quotes the next
/// character, as for `glob(3)`).
pub fn has_glob(s: &[u8]) -> bool {
    let mut i = 0;
    while i < s.len() {
        match s[i] {
            b'\\' => i += 2,
            b'*' | b'?' | b'[' => return true,
            _ => i += 1,
        }
    }
    false
}

/// A glob pattern's literal text: each `\x` becomes `x` (a trailing `\`
/// stays), as `glob(3)` reads a pattern.
pub fn unescape(s: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(s.len());
    let mut i = 0;
    while i < s.len() {
        if s[i] == b'\\' && i + 1 < s.len() {
            out.push(s[i + 1]);
            i += 2;
        } else {
            out.push(s[i]);
            i += 1;
        }
    }
    out
}

/// Remote path join: absolute `rel` wins; empty `rel` is `cwd`.
pub fn remote_join(cwd: &[u8], rel: &[u8]) -> Vec<u8> {
    if rel.first() == Some(&b'/') || cwd.is_empty() {
        return rel.to_vec();
    }
    if rel.is_empty() {
        return cwd.to_vec();
    }
    let mut out = cwd.to_vec();
    if out.last() != Some(&b'/') {
        out.push(b'/');
    }
    out.extend_from_slice(rel);
    out
}

/// Last component of a remote path (`a/b/` → `b`).
pub fn remote_basename(p: &[u8]) -> &[u8] {
    let trimmed = {
        let mut t = p;
        while t.len() > 1 && t.last() == Some(&b'/') {
            t = &t[..t.len() - 1];
        }
        t
    };
    match trimmed.iter().rposition(|c| *c == b'/') {
        Some(i) => &trimmed[i + 1..],
        None => trimmed,
    }
}

/// A file name from the server is used as a local path component: refuse
/// anything that is not a plain name.
pub fn safe_name(name: &[u8]) -> bool {
    !name.is_empty() && name != b"." && name != b".." && !name.contains(&b'/') && !name.contains(&0)
}

/// Expand a remote glob (relative to `cwd`). A pattern without glob
/// characters is returned as is; one matching nothing is an error.
pub fn remote_glob<T: Read + Write>(
    sftp: &mut SftpClient<T>,
    cwd: &[u8],
    pattern: &[u8],
) -> Result<Vec<Vec<u8>>, String> {
    let full = remote_join(cwd, pattern);
    if !has_glob(&full) {
        return Ok(vec![unescape(&full)]);
    }
    let absolute = full.first() == Some(&b'/');
    let mut current: Vec<Vec<u8>> = vec![if absolute { b"/".to_vec() } else { Vec::new() }];
    for comp in full.split(|c| *c == b'/').filter(|c| !c.is_empty()) {
        let mut next = Vec::new();
        for base in &current {
            let join = |name: &[u8]| {
                let mut p = base.clone();
                if !p.is_empty() && p.last() != Some(&b'/') {
                    p.push(b'/');
                }
                p.extend_from_slice(name);
                p
            };
            if !has_glob(comp) {
                next.push(join(&unescape(comp)));
                continue;
            }
            let dir = if base.is_empty() {
                b".".to_vec()
            } else {
                base.clone()
            };
            let Ok(h) = sftp.opendir(&dir) else { continue };
            let mut names = Vec::new();
            while let Ok(Some(batch)) = sftp.readdir(&h) {
                for e in batch {
                    if safe_name(&e.filename) && glob_match(comp, &e.filename) {
                        names.push(e.filename);
                    }
                }
            }
            let _ = sftp.close(&h);
            names.sort();
            next.extend(names.iter().map(|n| join(n)));
        }
        current = next;
    }
    if current.is_empty() {
        return Err(format!(
            "{}: No such file or directory",
            String::from_utf8_lossy(pattern)
        ));
    }
    Ok(current)
}

/// Expand a local glob. A pattern without glob characters is returned as
/// is; one matching nothing is an error.
pub fn local_glob(pattern: &str) -> Result<Vec<PathBuf>, String> {
    if !has_glob(pattern.as_bytes()) {
        return Ok(vec![PathBuf::from(
            String::from_utf8_lossy(&unescape(pattern.as_bytes())).into_owned(),
        )]);
    }
    let absolute = pattern.starts_with('/');
    let mut current: Vec<PathBuf> = vec![if absolute {
        PathBuf::from("/")
    } else {
        PathBuf::new()
    }];
    for comp in pattern.split('/').filter(|c| !c.is_empty()) {
        let mut next = Vec::new();
        for base in &current {
            if !has_glob(comp.as_bytes()) {
                next.push(base.join(String::from_utf8_lossy(&unescape(comp.as_bytes())).as_ref()));
                continue;
            }
            let dir = if base.as_os_str().is_empty() {
                Path::new(".")
            } else {
                base.as_path()
            };
            let Ok(rd) = std::fs::read_dir(dir) else {
                continue;
            };
            let mut names: Vec<String> = rd
                .filter_map(|e| e.ok())
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .filter(|n| glob_match(comp.as_bytes(), n.as_bytes()))
                .collect();
            names.sort();
            next.extend(names.iter().map(|n| base.join(n)));
        }
        current = next;
    }
    if current.is_empty() {
        return Err(format!("{pattern}: No such file or directory"));
    }
    Ok(current)
}

/// Transfer options.
#[derive(Clone)]
pub struct XferOpts {
    /// `-p`: keep modes and times.
    pub preserve: bool,
    /// `-r` / `-R`: copy directories recursively.
    pub recursive: bool,
    /// Show the progress meter.
    pub progress: bool,
    /// `-l`: bandwidth limit in bytes per second.
    pub limit: Option<u64>,
    /// `-B`: request size.
    pub chunk: u32,
    /// `-R`: requests in flight.
    pub depth: usize,
    /// `reget` / `reput` / `-a`: continue a partial transfer.
    pub resume: bool,
    /// sftp: print `Entering dir` / `Retrieving dir` for each directory of
    /// a recursive transfer, as OpenSSH's sftp does.
    pub announce_dirs: bool,
    /// Write targets in place: not truncated when opened, cut to size
    /// after (scp does, so a file can be copied onto itself).
    pub inplace: bool,
}

impl Default for XferOpts {
    fn default() -> Self {
        Self {
            preserve: false,
            recursive: false,
            progress: false,
            limit: None,
            chunk: 32768,
            depth: 64,
            resume: false,
            announce_dirs: false,
            inplace: false,
        }
    }
}

/// `-l`: keeps the average rate under the limit by sleeping.
struct Limiter {
    rate: u64,
    start: Instant,
    bytes: u64,
}

impl Limiter {
    fn account(&mut self, n: usize) {
        self.bytes += n as u64;
        let due = Duration::from_secs_f64(self.bytes as f64 / self.rate as f64);
        let elapsed = self.start.elapsed();
        if due > elapsed {
            std::thread::sleep(due - elapsed);
        }
    }
}

struct Limited<S> {
    inner: S,
    limiter: Option<Limiter>,
    /// The local file's own I/O error, if any (as opposed to the remote
    /// side's), for the message.
    error: Option<String>,
}

impl<S> Limited<S> {
    fn new(inner: S, rate: Option<u64>) -> Self {
        Self {
            inner,
            limiter: rate.filter(|r| *r > 0).map(|rate| Limiter {
                rate,
                start: Instant::now(),
                bytes: 0,
            }),
            error: None,
        }
    }

    fn note<T>(&mut self, r: io::Result<T>) -> io::Result<T> {
        if let Err(e) = &r {
            self.error = Some(strerror(e));
        }
        r
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

/// OpenSSH's `fx2txt`: the text for a status.
fn fx2txt(e: &puressh::sftp::SftpError) -> String {
    use puressh::sftp::FxpStatus;
    match e {
        puressh::sftp::SftpError::Status { code, .. } => match code {
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
        }
        .into(),
        other => other.to_string(),
    }
}

/// Set (by sftp's SIGINT handler) to stop the transfer in progress.
pub static INTERRUPTED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

fn check_interrupted() -> io::Result<()> {
    if INTERRUPTED.load(std::sync::atomic::Ordering::Relaxed) {
        return Err(io::Error::other("interrupted"));
    }
    Ok(())
}

impl<R: Read> Read for Limited<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        check_interrupted()?;
        let r = self.inner.read(buf);
        let n = self.note(r)?;
        if let Some(l) = &mut self.limiter {
            l.account(n);
        }
        Ok(n)
    }
}

impl<W: Write> Write for Limited<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        check_interrupted()?;
        let r = self.inner.write(buf);
        let n = self.note(r)?;
        if let Some(l) = &mut self.limiter {
            l.account(n);
        }
        Ok(n)
    }
    fn flush(&mut self) -> io::Result<()> {
        let r = self.inner.flush();
        self.note(r)
    }
}

/// OpenSSH's progress meter (progressmeter.c), on stdout when it is a
/// terminal: drawn at the start, about once a second, and at the end.
pub struct Progress {
    name: String,
    start_pos: u64,
    end_pos: u64,
    cur_pos: u64,
    /// The position last reported to [`Progress::update`].
    counter: u64,
    start: Instant,
    last_update: Instant,
    bytes_per_second: i64,
    stalled: i64,
    enabled: bool,
}

/// The meter's width: stdout's columns (80 when unknown, at most 512).
fn terminal_width() -> usize {
    #[cfg(unix)]
    {
        // SAFETY: TIOCGWINSZ fills a plain struct; failure leaves it zeroed.
        let mut ws: libc::winsize = unsafe { std::mem::zeroed() };
        if unsafe { libc::ioctl(1, libc::TIOCGWINSZ, &mut ws) } == 0 && ws.ws_col > 0 {
            return (ws.ws_col as usize).min(512);
        }
    }
    80
}

const UNITS: &[u8; 5] = b" KMGT";

/// progressmeter.c's `format_size`: `1000 `, `3072KB`.
fn format_size(mut bytes: u64) -> String {
    let mut i = 0;
    while bytes >= 10000 && UNITS[i] != b'T' {
        bytes = (bytes + 512) / 1024;
        i += 1;
    }
    format!(
        "{bytes:4}{}{}",
        UNITS[i] as char,
        if i > 0 { "B" } else { " " }
    )
}

/// progressmeter.c's `format_rate`: at least KB, one decimal (`  7.7MB`).
fn format_rate(bytes: i64) -> String {
    let mut bytes = bytes.max(0) as u64 * 100;
    let mut i = 0;
    while bytes >= 100 * 1000 && UNITS[i] != b'T' {
        bytes = (bytes + 512) / 1024;
        i += 1;
    }
    if i == 0 {
        i = 1;
        bytes = (bytes + 512) / 1024;
    }
    format!(
        "{:3}.{}{}B",
        (bytes + 5) / 100,
        (bytes + 5) / 10 % 10,
        UNITS[i] as char
    )
}

impl Progress {
    /// A meter for `name`, `total` bytes long, the transfer starting at
    /// `start` (a resumed one past 0).
    pub fn new(name: &str, total: u64, start: u64, enabled: bool) -> Self {
        let now = Instant::now();
        let mut p = Self {
            name: name.to_string(),
            start_pos: start,
            end_pos: total,
            cur_pos: 0,
            counter: start,
            start: now,
            last_update: now,
            bytes_per_second: 0,
            stalled: 0,
            enabled: enabled && io::stdout().is_terminal(),
        };
        if p.enabled {
            p.refresh();
        }
        p
    }

    /// The transfer has reached `done`.
    pub fn update(&mut self, done: u64) {
        self.counter = done;
        if self.enabled && self.last_update.elapsed() >= Duration::from_secs(1) {
            self.refresh();
        }
    }

    /// The transfer stopped at `done`: complete the meter.
    pub fn finish(&mut self, done: u64) {
        self.counter = done;
        if self.enabled {
            if self.cur_pos != self.end_pos {
                self.refresh();
            }
            println!();
        }
    }

    fn refresh(&mut self) {
        let base = if self.cur_pos != 0 {
            self.cur_pos
        } else {
            self.start_pos
        };
        let mut transferred = self.counter as i64 - base as i64;
        self.cur_pos = self.counter;
        let now = Instant::now();
        let bytes_left = self.end_pos as i64 - self.cur_pos as i64;
        let elapsed = if bytes_left > 0 {
            now.duration_since(self.last_update).as_secs_f64()
        } else {
            // The true total speed when done.
            transferred = self.end_pos as i64 - self.start_pos as i64;
            self.bytes_per_second = 0;
            now.duration_since(self.start).as_secs_f64()
        };
        let cur_speed = if elapsed != 0.0 {
            (transferred as f64 / elapsed) as i64
        } else {
            transferred
        };
        self.bytes_per_second = if self.bytes_per_second != 0 {
            (self.bytes_per_second as f64 * 0.9 + cur_speed as f64 * 0.1) as i64
        } else {
            cur_speed
        };
        self.last_update = now;

        let win_size = terminal_width() + 1;
        let file_len = win_size as i64 - 36;
        let mut buf = String::new();
        if file_len > 0 {
            let file_len = file_len as usize;
            let mut name: String = self.name.chars().take(file_len).collect();
            while name.chars().count() < file_len {
                name.push(' ');
            }
            buf.push_str(&name);
        }
        let percent = if self.end_pos == 0 || self.cur_pos == self.end_pos {
            100
        } else {
            ((self.cur_pos as f32 / self.end_pos as f32) * 100.0) as i32
        };
        buf.push_str(&format!(
            " {percent:3}% {} {}/s ",
            format_size(self.cur_pos),
            format_rate(self.bytes_per_second)
        ));
        if transferred == 0 {
            self.stalled += elapsed as i64;
        } else {
            self.stalled = 0;
        }
        if self.stalled >= 5 {
            buf.push_str("- stalled -");
        } else if self.bytes_per_second == 0 && bytes_left != 0 {
            buf.push_str("  --:-- ETA");
        } else {
            let mut seconds = if bytes_left > 0 {
                bytes_left / self.bytes_per_second
            } else {
                elapsed as i64
            };
            let hours = seconds / 3600;
            seconds -= hours * 3600;
            let minutes = seconds / 60;
            seconds -= minutes * 60;
            if hours != 0 {
                buf.push_str(&format!("{hours}:{minutes:02}:{seconds:02}"));
            } else {
                buf.push_str(&format!("  {minutes:02}:{seconds:02}"));
            }
            buf.push_str(if bytes_left > 0 { " ETA" } else { "    " });
        }
        // `\r` and the line, cut at the window width.
        let line: String = buf.chars().take(win_size.saturating_sub(2)).collect();
        let mut out = io::stdout().lock();
        let _ = write!(out, "\r{line}");
        let _ = out.flush();
    }
}

/// Control bytes from a server-supplied name, made harmless for a terminal.
pub fn sanitize(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_control() { '?' } else { c })
        .collect()
}

/// The local time zone's offset east of UTC at Unix time `t`, in seconds.
pub fn local_offset(t: i64) -> i64 {
    #[cfg(unix)]
    {
        let tt = t as libc::time_t;
        // SAFETY: `tm` is plain data; localtime_r fills it or returns NULL.
        let mut tm: libc::tm = unsafe { std::mem::zeroed() };
        if !unsafe { libc::localtime_r(&tt, &mut tm) }.is_null() {
            return tm.tm_gmtoff as i64;
        }
    }
    let _ = t;
    0
}

fn sftp_err(e: puressh::sftp::SftpError) -> String {
    match e {
        puressh::sftp::SftpError::Status { code, message } if !message.is_empty() => {
            let _ = code;
            message
        }
        puressh::sftp::SftpError::Status { code, .. } => format!("{code:?}"),
        other => other.to_string(),
    }
}

/// Mode/times of a remote file applied to a local one (`-p`).
fn apply_local_attrs(path: &Path, attrs: &Attrs, preserve: bool) {
    if !preserve {
        return;
    }
    #[cfg(unix)]
    if let Some(perm) = attrs.permissions {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(perm & 0o7777));
    }
    if let Some((atime, mtime)) = attrs.atime_mtime {
        let at = UNIX_EPOCH + Duration::from_secs(atime.into());
        let mt = UNIX_EPOCH + Duration::from_secs(mtime.into());
        if let Ok(f) = std::fs::File::options()
            .write(true)
            .open(path)
            .or_else(|_| std::fs::File::open(path))
        {
            let _ = f.set_times(std::fs::FileTimes::new().set_accessed(at).set_modified(mt));
        }
    }
}

fn secs(t: std::io::Result<SystemTime>) -> Option<u32> {
    t.ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .and_then(|d| u32::try_from(d.as_secs()).ok())
}

/// Remote attributes for a local file (`-p` sends times too).
fn local_attrs(md: &std::fs::Metadata, preserve: bool) -> Attrs {
    let mut a = Attrs::default();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        a.permissions = Some(md.permissions().mode() & if preserve { 0o7777 } else { 0o777 });
    }
    if preserve && let (Some(at), Some(mt)) = (secs(md.accessed()), secs(md.modified())) {
        a.atime_mtime = Some((at, mt));
    }
    a
}

const S_IFMT: u32 = 0o170000;
const S_IFDIR: u32 = 0o040000;
const S_IFREG: u32 = 0o100000;
const S_IFLNK: u32 = 0o120000;

pub fn is_dir(a: &Attrs) -> bool {
    a.permissions.is_some_and(|p| p & S_IFMT == S_IFDIR)
}

fn is_reg(a: &Attrs) -> bool {
    a.permissions.is_none_or(|p| p & S_IFMT == S_IFREG)
}

/// Download `remote` (file, or directory with `recursive`) to `local`.
pub fn download<T: Read + Write>(
    sftp: &mut SftpClient<T>,
    remote: &[u8],
    local: &Path,
    opts: &XferOpts,
) -> Result<(), String> {
    download_at(sftp, remote, local, opts, 0)
}

fn download_at<T: Read + Write>(
    sftp: &mut SftpClient<T>,
    remote: &[u8],
    local: &Path,
    opts: &XferOpts,
    depth: usize,
) -> Result<(), String> {
    let shown = String::from_utf8_lossy(remote).into_owned();
    let attrs = sftp
        .stat(remote)
        .map_err(|e| format!("{shown}: {}", sftp_err(e)))?;
    if is_dir(&attrs) {
        if !opts.recursive {
            return Err(format!("{shown}: not a regular file"));
        }
        if depth > 64 {
            return Err(format!("{shown}: directory nesting too deep"));
        }
        if opts.announce_dirs {
            println!("Retrieving {}", sanitize(&shown));
        }
        match std::fs::create_dir(local) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists && local.is_dir() => {}
            Err(e) => return Err(format!("{}: {e}", local.display())),
        }
        let h = sftp
            .opendir(remote)
            .map_err(|e| format!("{shown}: {}", sftp_err(e)))?;
        let mut names = Vec::new();
        loop {
            match sftp.readdir(&h) {
                Ok(Some(batch)) => names.extend(batch.into_iter().map(|e| e.filename)),
                Ok(None) => break,
                Err(e) => {
                    let _ = sftp.close(&h);
                    return Err(format!("{shown}: {}", sftp_err(e)));
                }
            }
        }
        let _ = sftp.close(&h);
        let mut first_err = None;
        for name in names {
            if name == b"." || name == b".." {
                continue;
            }
            if !safe_name(&name) {
                eprintln!(
                    "{shown}: server sent an invalid file name {:?}; skipped",
                    String::from_utf8_lossy(&name)
                );
                continue;
            }
            let child_remote = remote_join(remote, &name);
            let child_local = local.join(String::from_utf8_lossy(&name).as_ref());
            if let Err(e) = download_at(sftp, &child_remote, &child_local, opts, depth + 1) {
                eprintln!("{e}");
                first_err.get_or_insert(e);
            }
        }
        apply_local_attrs(local, &attrs, opts.preserve);
        return match first_err {
            Some(_) => Err(format!("{shown}: some files could not be copied")),
            None => Ok(()),
        };
    }
    if !is_reg(&attrs) {
        return Err(format!("{shown}: not a regular file"));
    }
    let total = attrs.size.unwrap_or(0);
    let h = sftp
        .open(remote, FXF_READ, Attrs::default())
        .map_err(|e| format!("remote open \"{shown}\": {}", fx2txt(&e)))?;
    let mut options = std::fs::File::options();
    options.write(true).create(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(attrs.permissions.unwrap_or(0o644) & 0o777);
    }
    let start = if opts.resume {
        local.metadata().map(|m| m.len()).unwrap_or(0)
    } else {
        options.truncate(!opts.inplace);
        0
    };
    let file = match options.open(local) {
        Ok(f) => f,
        Err(e) => {
            let _ = sftp.close(&h);
            return Err(format!(
                "open local \"{}\": {}",
                local.display(),
                strerror(&e)
            ));
        }
    };
    if opts.resume && start > total {
        let _ = sftp.close(&h);
        return Err(format!(
            "Unable to resume download of \"{}\": local file is larger than remote",
            local.display()
        ));
    }
    let mut file = Limited::new(io::BufWriter::new(file), opts.limit);
    if opts.resume {
        use std::io::Seek;
        let _ = file.inner.seek(io::SeekFrom::Start(start));
    }
    let name = String::from_utf8_lossy(remote_basename(remote)).into_owned();
    let mut meter = Progress::new(&name, total, start, opts.progress);
    let res = sftp.read_to(&h, start, opts.chunk, opts.depth, &mut file, |n| {
        meter.update(start + n)
    });
    let _ = sftp.close(&h);
    let res = res.and_then(|n| file.flush().map(|()| n).map_err(SftpError::Io));
    let n = res.map_err(|e| match &file.error {
        Some(err) => format!("write local \"{}\": {err}", local.display()),
        None => format!("read remote \"{shown}\" : {}", fx2txt(&e)),
    })?;
    meter.finish(start + n);
    if opts.inplace {
        let _ = file.inner.get_ref().set_len(start + n);
    }
    drop(file);
    apply_local_attrs(local, &attrs, opts.preserve);
    Ok(())
}

/// Upload `local` (file, or directory with `recursive`) to `remote`.
pub fn upload<T: Read + Write>(
    sftp: &mut SftpClient<T>,
    local: &Path,
    remote: &[u8],
    opts: &XferOpts,
) -> Result<(), String> {
    upload_at(sftp, local, remote, opts, 0)
}

fn upload_at<T: Read + Write>(
    sftp: &mut SftpClient<T>,
    local: &Path,
    remote: &[u8],
    opts: &XferOpts,
    depth: usize,
) -> Result<(), String> {
    let shown = local.display().to_string();
    let md = std::fs::metadata(local).map_err(|e| format!("{shown}: {e}"))?;
    if md.is_dir() {
        if !opts.recursive {
            return Err(format!("{shown}: not a regular file"));
        }
        if depth > 64 {
            return Err(format!("{shown}: directory nesting too deep"));
        }
        if opts.announce_dirs {
            if depth == 0 && !shown.ends_with('/') {
                println!("Entering {shown}/");
            } else {
                println!("Entering {shown}");
            }
        }
        let mut dattrs = local_attrs(&md, false);
        // The directory must stay writable for us while we fill it.
        dattrs.permissions = dattrs.permissions.map(|p| p | 0o700);
        if let Err(e) = sftp.mkdir(remote, dattrs) {
            // An existing directory is fine.
            if !sftp.stat(remote).is_ok_and(|a| is_dir(&a)) {
                return Err(format!(
                    "{}: {}",
                    String::from_utf8_lossy(remote),
                    sftp_err(e)
                ));
            }
        }
        let mut entries: Vec<_> = std::fs::read_dir(local)
            .map_err(|e| format!("{shown}: {e}"))?
            .filter_map(|e| e.ok())
            .collect();
        entries.sort_by_key(|e| e.file_name());
        let mut first_err = None;
        for e in entries {
            let name = e.file_name();
            let child_remote = remote_join(remote, name.to_string_lossy().as_bytes());
            if let Err(err) = upload_at(sftp, &e.path(), &child_remote, opts, depth + 1) {
                eprintln!("{err}");
                first_err.get_or_insert(err);
            }
        }
        if opts.preserve {
            let _ = sftp.setstat(remote, local_attrs(&md, true));
        }
        return match first_err {
            Some(_) => Err(format!("{shown}: some files could not be copied")),
            None => Ok(()),
        };
    }
    if !md.is_file() {
        return Err(format!("{shown}: not a regular file"));
    }
    let remote_shown = String::from_utf8_lossy(remote).into_owned();
    let start = if opts.resume {
        sftp.stat(remote).ok().and_then(|a| a.size).unwrap_or(0)
    } else {
        0
    };
    if start > md.len() {
        return Err(format!(
            "{remote_shown}: remote file is larger than the local one"
        ));
    }
    let flags = if opts.resume || opts.inplace {
        FXF_WRITE | FXF_CREAT
    } else {
        FXF_WRITE | FXF_CREAT | FXF_TRUNC
    };
    let _ = FXF_APPEND;
    let mut file = std::fs::File::open(local)
        .map_err(|e| format!("open local \"{shown}\": {}", strerror(&e)))?;
    let h = sftp
        .open(remote, flags, local_attrs(&md, false))
        .map_err(|e| format!("dest open \"{remote_shown}\": {}", fx2txt(&e)))?;
    if start > 0 {
        use std::io::Seek;
        file.seek(io::SeekFrom::Start(start))
            .map_err(|e| format!("{shown}: {e}"))?;
    }
    let mut src = Limited::new(io::BufReader::new(file), opts.limit);
    let name = local
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| shown.clone());
    let mut meter = Progress::new(&name, md.len(), start, opts.progress);
    let res = sftp.write_from(&h, start, opts.chunk, opts.depth, &mut src, |n| {
        meter.update(start + n)
    });
    if opts.inplace
        && let Ok(n) = &res
    {
        let mut size = Attrs::default();
        size.size = Some(start + n);
        let _ = sftp.fsetstat(&h, size);
    }
    let close = sftp.close(&h);
    let n = res.map_err(|e| match &src.error {
        Some(err) => format!("read local \"{shown}\": {err}"),
        None => format!("write remote \"{remote_shown}\": {}", fx2txt(&e)),
    })?;
    close.map_err(|e| format!("close remote: {}", fx2txt(&e)))?;
    meter.finish(start + n);
    if opts.preserve {
        let _ = sftp.setstat(remote, local_attrs(&md, true));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn remotes() {
        let r = |s| parse_remote(s, &["scp"]);
        assert_eq!(
            r("u@h:p"),
            Some(Remote {
                user: Some("u".into()),
                host: "h".into(),
                port: None,
                path: "p".into()
            })
        );
        assert_eq!(r("h:").map(|x| x.path), Some(String::new()));
        assert_eq!(r("[::1]:/tmp").map(|x| x.host), Some("::1".into()));
        assert!(r("./a:b").is_none());
        assert!(r("dir/a:b").is_none());
        assert!(r("/abs:x").is_none());
        assert!(r("file").is_none());
        let u = r("scp://me@host:2222/some%20dir/f").unwrap();
        assert_eq!(
            (u.user.as_deref(), u.host.as_str(), u.port, u.path.as_str()),
            (Some("me"), "host", Some(2222), "some dir/f")
        );
        assert_eq!(r("scp://host").map(|x| x.path), Some(String::new()));
    }

    #[test]
    fn globs() {
        assert!(glob_match(b"*.txt", b"a.txt"));
        assert!(!glob_match(b"*.txt", b".hidden.txt"));
        assert!(glob_match(b".*", b".hidden"));
        assert!(glob_match(b"f?o", b"foo"));
        assert!(glob_match(b"[a-c]x", b"bx"));
        assert!(!glob_match(b"[!a-c]x", b"bx"));
        assert!(glob_match(b"a\\*", b"a*"));
        assert!(!glob_match(b"a\\*", b"ab"));
        assert!(glob_match(b"*", b""));
        assert!(!glob_match(b"abc", b"abcd"));
    }

    #[test]
    fn meter_units() {
        // As OpenSSH's progressmeter.c prints them.
        assert_eq!(format_size(1000), "1000  ");
        assert_eq!(format_size(3 * 1024 * 1024), "3072KB");
        assert_eq!(format_size(0), "   0  ");
        assert_eq!(format_rate(0), "  0.0KB");
        assert_eq!(format_rate(8_100_000), "  7.7MB");
        assert_eq!(format_rate(2_000_000_000), "  1.9GB");
    }

    #[test]
    fn names() {
        assert_eq!(remote_basename(b"/a/b/"), b"b");
        assert_eq!(remote_basename(b"f"), b"f");
        assert_eq!(remote_join(b"/home/u", b"x"), b"/home/u/x");
        assert_eq!(remote_join(b"/home/u", b"/etc"), b"/etc");
        assert!(!safe_name(b"../x"));
        assert!(!safe_name(b".."));
        assert!(safe_name(b"ok"));
    }
}
