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

use puressh::sftp::{Attrs, FXF_APPEND, FXF_CREAT, FXF_READ, FXF_TRUNC, FXF_WRITE, SftpClient};

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
        }
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
        let n = self.inner.read(buf)?;
        if let Some(l) = &mut self.limiter {
            l.account(n);
        }
        Ok(n)
    }
}

impl<W: Write> Write for Limited<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        check_interrupted()?;
        let n = self.inner.write(buf)?;
        if let Some(l) = &mut self.limiter {
            l.account(n);
        }
        Ok(n)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

/// OpenSSH's progress meter, on stdout when it is a terminal.
pub struct Progress {
    name: String,
    total: u64,
    start: Instant,
    last: Option<Instant>,
    enabled: bool,
}

fn terminal_width() -> usize {
    #[cfg(unix)]
    {
        // SAFETY: TIOCGWINSZ fills a plain struct; failure leaves it zeroed.
        let mut ws: libc::winsize = unsafe { std::mem::zeroed() };
        if unsafe { libc::ioctl(1, libc::TIOCGWINSZ, &mut ws) } == 0 && ws.ws_col > 0 {
            return ws.ws_col as usize;
        }
    }
    80
}

fn human(n: f64) -> String {
    const UNITS: [&str; 6] = ["B", "KB", "MB", "GB", "TB", "PB"];
    let mut v = n;
    let mut u = 0;
    while v >= 1024.0 * 10.0 && u + 1 < UNITS.len() {
        v /= 1024.0;
        u += 1;
    }
    format!("{:.0}{}", v, UNITS[u])
}

fn human_rate(n: f64) -> String {
    const UNITS: [&str; 6] = ["B", "KB", "MB", "GB", "TB", "PB"];
    let mut v = n;
    let mut u = 0;
    while v >= 1000.0 && u + 1 < UNITS.len() {
        v /= 1024.0;
        u += 1;
    }
    format!("{v:.1}{}", UNITS[u])
}

impl Progress {
    pub fn new(name: &str, total: u64, enabled: bool) -> Self {
        Self {
            name: name.to_string(),
            total,
            start: Instant::now(),
            last: None,
            enabled: enabled && io::stdout().is_terminal(),
        }
    }

    pub fn update(&mut self, done: u64) {
        if !self.enabled {
            return;
        }
        if self
            .last
            .is_some_and(|l| l.elapsed() < Duration::from_secs(1))
            && done < self.total
        {
            return;
        }
        self.last = Some(Instant::now());
        self.draw(done, false);
    }

    pub fn finish(&mut self, done: u64) {
        if self.enabled {
            self.draw(done, true);
            println!();
        }
    }

    fn draw(&self, done: u64, end: bool) {
        let elapsed = self.start.elapsed().as_secs_f64().max(0.001);
        let rate = done as f64 / elapsed;
        let pct = done
            .saturating_mul(100)
            .checked_div(self.total)
            .map_or(100, |p| p.min(100));
        let secs = if end || done >= self.total {
            elapsed as u64
        } else if rate > 0.0 {
            ((self.total - done) as f64 / rate) as u64
        } else {
            0
        };
        let time = if secs >= 3600 {
            format!("{}:{:02}:{:02}", secs / 3600, secs / 60 % 60, secs % 60)
        } else {
            format!("{:02}:{:02}", secs / 60, secs % 60)
        };
        let eta = if end || done >= self.total {
            "    "
        } else {
            " ETA"
        };
        let stats = format!(
            "{pct:3}% {:>6} {:>8}/s {:>8}{eta}",
            human(done as f64),
            human_rate(rate),
            time
        );
        let width = terminal_width().saturating_sub(stats.len() + 2).max(10);
        let mut name: String = self.name.chars().take(width).collect();
        while name.chars().count() < width {
            name.push(' ');
        }
        let mut out = io::stdout().lock();
        let _ = write!(out, "\r{name} {stats}");
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
        .map_err(|e| format!("{shown}: {}", sftp_err(e)))?;
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
            return Err(format!("{}: {e}", local.display()));
        }
    };
    if opts.resume && start > total {
        let _ = sftp.close(&h);
        return Err(format!(
            "{}: local file is larger than the remote one",
            local.display()
        ));
    }
    let mut file = Limited::new(io::BufWriter::new(file), opts.limit);
    if opts.resume {
        use std::io::Seek;
        let _ = file.inner.seek(io::SeekFrom::Start(start));
    }
    let name = String::from_utf8_lossy(remote_basename(remote)).into_owned();
    let mut meter = Progress::new(&name, total, opts.progress);
    let res = sftp.read_to(&h, start, opts.chunk, opts.depth, &mut file, |n| {
        meter.update(start + n)
    });
    let _ = sftp.close(&h);
    let n = res.map_err(|e| format!("{shown}: {}", sftp_err(e)))?;
    file.flush()
        .map_err(|e| format!("{}: {e}", local.display()))?;
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
    let h = sftp
        .open(remote, flags, local_attrs(&md, false))
        .map_err(|e| format!("{remote_shown}: {}", sftp_err(e)))?;
    let mut file = std::fs::File::open(local).map_err(|e| format!("{shown}: {e}"))?;
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
    let mut meter = Progress::new(&name, md.len(), opts.progress);
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
    let n = res.map_err(|e| format!("{remote_shown}: {}", sftp_err(e)))?;
    close.map_err(|e| format!("{remote_shown}: {}", sftp_err(e)))?;
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
