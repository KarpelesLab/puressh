//! `scp` — copy files between hosts, a drop-in for OpenSSH's.
//!
//! ```text
//! scp [-346ABCOpqRrsTv] [-c cipher] [-D sftp_server_path] [-F ssh_config]
//!     [-i identity_file] [-J destination] [-l limit] [-o ssh_option]
//!     [-P port] [-S program] [-X sftp_option] source ... target
//! ```
//!
//! As with OpenSSH's, the remote side is reached by running `ssh` (`-S`
//! overrides which), so every ssh option and ssh_config setting applies.
//! Transfers use the SFTP protocol by default; `-O` selects the legacy SCP
//! protocol (`scp -t` / `scp -f` on the remote host). Copies between two
//! remote hosts go through this host (`-3`, the default) or, with `-R`, are
//! run by scp on the source host. Local-to-local copies use `cp`.

use std::io::{self, IsTerminal};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use puressh::scp::{Receiver, ScpRecvOptions, ScpSendOptions, Sender};
use puressh::sftp::SftpClient;

#[path = "transfer.rs"]
mod transfer;
use transfer::{Remote, SshOptions, SshPipe, XferOpts};

const USAGE: &str = "usage: scp [-346ABCOpqRrsTv] [-c cipher] [-D sftp_server_path] [-F ssh_config]
           [-i identity_file] [-J destination] [-l limit] [-o ssh_option]
           [-P port] [-S program] [-X sftp_option] source ... target";

struct Cli {
    ssh: SshOptions,
    port: Option<u16>,
    through_local: bool,
    remote_to_remote_direct: bool,
    legacy: bool,
    sftp_direct: Option<String>,
    quiet: bool,
    verbose: bool,
    xfer: XferOpts,
    /// Flags to repeat for a remote scp (`-R`) or `scp -t/-f` (`-O`).
    passthrough: Vec<String>,
    /// `-t` / `-f`: the remote end of the legacy protocol (`-d`: the
    /// target must be a directory).
    sink: bool,
    source: bool,
    target_dir: bool,
    /// `-T`: no check that the files a server sends are those requested.
    no_name_check: bool,
    operands: Vec<String>,
}

fn parse_args(args: &[String]) -> Result<Cli, String> {
    const WITH_ARG: &str = "cDFiJloPSX";
    let mut c = Cli {
        ssh: SshOptions::default(),
        port: None,
        through_local: true,
        remote_to_remote_direct: false,
        legacy: false,
        sftp_direct: None,
        quiet: false,
        verbose: false,
        // scp writes in place, as OpenSSH's.
        xfer: XferOpts {
            inplace: true,
            ..XferOpts::default()
        },
        passthrough: Vec::new(),
        sink: false,
        source: false,
        target_dir: false,
        no_name_check: false,
        operands: Vec::new(),
    };
    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
        if a == "--" {
            c.operands.extend(args[i + 1..].iter().cloned());
            break;
        }
        if !a.starts_with('-') || a == "-" {
            c.operands.push(a.clone());
            i += 1;
            continue;
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
                    args.get(i)
                        .cloned()
                        .ok_or_else(|| format!("option requires an argument -- {f}"))?
                };
                match f {
                    'c' => c.ssh.push("-c", Some(&v)),
                    'D' => c.sftp_direct = Some(v),
                    'F' => {
                        c.ssh.push("-F", Some(&v));
                        c.passthrough.extend(["-F".into(), v]);
                    }
                    'i' => {
                        c.ssh.push("-i", Some(&v));
                        c.passthrough.extend(["-i".into(), v]);
                    }
                    'J' => c.ssh.push("-J", Some(&v)),
                    'l' => {
                        let kbit: u64 = v
                            .parse()
                            .ok()
                            .filter(|n| *n > 0)
                            .ok_or_else(|| format!("bad limit {v}"))?;
                        c.xfer.limit = Some(kbit * 1024 / 8);
                        c.passthrough.extend(["-l".into(), v]);
                    }
                    'o' => {
                        c.ssh.push("-o", Some(&v));
                        c.passthrough.extend(["-o".into(), v]);
                    }
                    'P' => {
                        c.port = Some(v.parse().map_err(|_| format!("bad port \"{v}\""))?);
                    }
                    'S' => c.ssh.program = Some(v),
                    'X' => match v.split_once('=') {
                        Some(("buffer", n)) => {
                            c.xfer.chunk = n
                                .parse()
                                .ok()
                                .filter(|n| (1..=256 * 1024).contains(n))
                                .ok_or_else(|| format!("Invalid buffer size \"{n}\""))?;
                        }
                        Some(("nrequests", n)) => {
                            c.xfer.depth = n
                                .parse()
                                .ok()
                                .filter(|n| *n >= 1)
                                .ok_or_else(|| format!("Invalid number of requests \"{n}\""))?;
                        }
                        _ => return Err(format!("Invalid -X option \"{v}\"")),
                    },
                    _ => unreachable!(),
                }
                break;
            }
            match f {
                '3' => c.through_local = true,
                'R' => {
                    c.through_local = false;
                    c.remote_to_remote_direct = true;
                }
                '4' | '6' | 'C' => {
                    c.ssh.push(&format!("-{f}"), None);
                    c.passthrough.push(format!("-{f}"));
                }
                'A' => c.ssh.forward_agent = true,
                'B' => {
                    c.ssh.push("-oBatchMode=yes", None);
                    c.passthrough.push("-B".into());
                }
                'O' => c.legacy = true,
                's' => c.legacy = false,
                'p' => {
                    c.xfer.preserve = true;
                    c.passthrough.push("-p".into());
                }
                'q' => {
                    c.quiet = true;
                    c.ssh.push("-q", None);
                    c.passthrough.push("-q".into());
                }
                'r' => {
                    c.xfer.recursive = true;
                    c.passthrough.push("-r".into());
                }
                'T' => c.no_name_check = true,
                'v' => {
                    c.verbose = true;
                    c.ssh.push("-v", None);
                    c.passthrough.push("-v".into());
                }
                't' => c.sink = true,
                'f' => c.source = true,
                'd' => c.target_dir = true,
                _ => return Err(format!("unknown option -- {f}")),
            }
            j += 1;
        }
        i += 1;
    }
    if c.sink || c.source {
        if c.operands.is_empty() {
            return Err(USAGE.into());
        }
        return Ok(c);
    }
    if c.operands.len() < 2 {
        return Err(USAGE.into());
    }
    c.xfer.progress = !c.quiet && io::stdout().is_terminal();
    Ok(c)
}

fn remote(arg: &str) -> Option<Remote> {
    transfer::parse_remote(arg, &["scp"])
}

/// A remote path for SFTP: `~` / `~/x` are relative to the login
/// directory; empty means the login directory.
fn sftp_path(path: &str) -> Vec<u8> {
    let p = path
        .strip_prefix("~/")
        .or_else(|| (path == "~").then_some(""))
        .unwrap_or(path);
    if p.is_empty() {
        b".".to_vec()
    } else {
        p.as_bytes().to_vec()
    }
}

struct Session {
    sftp: SftpClient<SshPipe>,
}

fn open_sftp(cli: &Cli, r: &Remote) -> Result<Session, String> {
    let pipe = match &cli.sftp_direct {
        Some(server) => SshPipe::spawn_program(server, &[]),
        None => SshPipe::spawn(
            &cli.ssh,
            r.user.as_deref(),
            &r.host,
            r.port.or(cli.port),
            true,
            &["sftp".to_string()],
        ),
    }
    .map_err(|e| e.to_string())?;
    let sftp = SftpClient::new(pipe).map_err(|e| format!("Connection closed ({e})"))?;
    Ok(Session { sftp })
}

/// Where `name` lands under a target that may be a directory.
fn remote_target(
    sess: &mut Session,
    target: &[u8],
    name: &[u8],
    many: bool,
) -> Result<Vec<u8>, String> {
    let is_dir = sess.sftp.stat(target).is_ok_and(|a| transfer::is_dir(&a));
    if is_dir {
        Ok(transfer::remote_join(target, name))
    } else if many {
        Err(format!(
            "{}: Not a directory",
            String::from_utf8_lossy(target)
        ))
    } else {
        Ok(target.to_vec())
    }
}

fn local_target(target: &Path, name: &str, many: bool) -> Result<PathBuf, String> {
    if target.is_dir() {
        Ok(target.join(name))
    } else if many {
        Err(format!("{}: Not a directory", target.display()))
    } else {
        Ok(target.to_path_buf())
    }
}

/// Report an error OpenSSH-style and remember that one happened.
fn fail(errs: &mut u32, msg: impl std::fmt::Display) {
    // Without Rust's ` (os error N)`: OpenSSH says `No such file or
    // directory`.
    let msg = msg.to_string();
    let msg = match msg.find(" (os error ") {
        Some(i) if msg.ends_with(')') => &msg[..i],
        _ => &msg,
    };
    eprintln!("scp: {msg}");
    *errs += 1;
}

fn upload_sftp(cli: &Cli, sources: &[String], to: &Remote, errs: &mut u32) {
    let mut sess = match open_sftp(cli, to) {
        Ok(s) => s,
        Err(e) => return fail(errs, e),
    };
    let target = sftp_path(&to.path);
    let many = sources.len() > 1;
    for src in sources {
        let path = Path::new(src);
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| src.clone());
        if path.is_dir() && !cli.xfer.recursive {
            fail(errs, format!("{src}: not a regular file"));
            continue;
        }
        let dest = match remote_target(&mut sess, &target, name.as_bytes(), many) {
            Ok(d) => d,
            Err(e) => {
                fail(errs, e);
                continue;
            }
        };
        if let Err(e) = transfer::upload(&mut sess.sftp, path, &dest, &cli.xfer) {
            fail(errs, e);
        }
    }
}

fn download_sftp(cli: &Cli, from: &Remote, target: &Path, many: bool, errs: &mut u32) {
    let mut sess = match open_sftp(cli, from) {
        Ok(s) => s,
        Err(e) => return fail(errs, e),
    };
    let pattern = sftp_path(&from.path);
    // GLOB_NOCHECK, as OpenSSH's scp: a pattern matching nothing is taken
    // as a name (a file may be called `a[1]`).
    let matches = match transfer::remote_glob(&mut sess.sftp, b"", &pattern) {
        Ok(m) if !m.is_empty() => m,
        _ => vec![pattern.clone()],
    };
    let many = many || matches.len() > 1;
    for m in matches {
        let mut name = String::from_utf8_lossy(transfer::remote_basename(&m)).into_owned();
        // `..` downloads into the target itself, as OpenSSH.
        if name == ".." {
            name = ".".into();
        }
        if !transfer::safe_name(name.as_bytes()) && name != "." {
            fail(errs, format!("{name}: invalid file name"));
            continue;
        }
        let dest = match local_target(target, &name, many) {
            Ok(d) => d,
            Err(e) => {
                fail(errs, e);
                continue;
            }
        };
        if let Err(e) = transfer::download(&mut sess.sftp, &m, &dest, &cli.xfer) {
            fail(errs, e);
        }
    }
}

/// Remote to remote through this host, SFTP: each file goes through a
/// local temporary copy.
fn crossload_sftp(cli: &Cli, from: &Remote, to: &Remote, errs: &mut u32) {
    let tmp = std::env::temp_dir().join(format!("puressh-scp-{}", std::process::id()));
    if let Err(e) = std::fs::create_dir(&tmp) {
        return fail(errs, format!("{}: {e}", tmp.display()));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o700));
    }
    let before = *errs;
    download_sftp(cli, from, &tmp, true, errs);
    // `dir/..` (or `.`) copies the directory's contents onto the target,
    // which is made if missing, as OpenSSH's crossload of a directory.
    let base = from
        .path
        .trim_end_matches('/')
        .rsplit('/')
        .next()
        .unwrap_or("");
    if *errs == before
        && cli.xfer.recursive
        && matches!(base, "." | "..")
        && let Ok(mut sess) = open_sftp(cli, to)
    {
        let dst = sftp_path(&to.path);
        if sess.sftp.stat(&dst).is_err() {
            let _ = sess.sftp.mkdir(&dst, puressh::sftp::Attrs::default());
        }
    }
    if *errs == before {
        let mut staged: Vec<String> = std::fs::read_dir(&tmp)
            .map(|rd| {
                rd.filter_map(|e| e.ok())
                    .map(|e| e.path().display().to_string())
                    .collect()
            })
            .unwrap_or_default();
        staged.sort();
        upload_sftp(cli, &staged, to, errs);
    }
    let _ = std::fs::remove_dir_all(&tmp);
}

/// The remote command for the legacy protocol, as OpenSSH sends it: one
/// argument (`scp [-v] [-r] [-p] -t [-- ]path`), the path left for the
/// remote shell to expand, `--` only before a path starting with `-`.
fn legacy_cmd(cli: &Cli, mode: &str, path: &str) -> Vec<String> {
    let mut cmd = String::from("scp");
    if cli.verbose {
        cmd.push_str(" -v");
    }
    if cli.xfer.recursive {
        cmd.push_str(" -r");
    }
    if cli.xfer.preserve {
        cmd.push_str(" -p");
    }
    let path = if path.is_empty() { "." } else { path };
    let dashes = if path.starts_with('-') { "-- " } else { "" };
    vec![format!("{cmd} {mode} {dashes}{path}")]
}

fn legacy_pipe(cli: &Cli, r: &Remote, mode: &str) -> Result<SshPipe, String> {
    SshPipe::spawn(
        &cli.ssh,
        r.user.as_deref(),
        &r.host,
        r.port.or(cli.port),
        false,
        &legacy_cmd(cli, mode, &r.path),
    )
    .map_err(|e| e.to_string())
}

fn upload_legacy(cli: &Cli, sources: &[String], to: &Remote, errs: &mut u32) {
    let mode = if sources.len() > 1 { "-dt" } else { "-t" };
    let pipe = match legacy_pipe(cli, to, mode) {
        Ok(p) => p,
        Err(e) => return fail(errs, e),
    };
    let mut sender = match Sender::new(pipe) {
        Ok(s) => s,
        Err(e) => return fail(errs, e),
    };
    let mut opts = ScpSendOptions::default();
    opts.recursive = cli.xfer.recursive;
    opts.preserve_times = cli.xfer.preserve;
    for src in sources {
        if let Err(e) = sender.send_path(Path::new(src), &opts) {
            fail(errs, format!("{src}: {e}"));
        }
    }
}

fn download_legacy(cli: &Cli, from: &Remote, target: &Path, errs: &mut u32) {
    let pipe = match legacy_pipe(cli, from, "-f") {
        Ok(p) => p,
        Err(e) => return fail(errs, e),
    };
    let mut opts = ScpRecvOptions::default();
    opts.recursive = cli.xfer.recursive;
    opts.preserve_times = cli.xfer.preserve;
    opts.target_is_file = !target.is_dir();
    // As OpenSSH's sink, unless -T a server may only send what was asked
    // for (CVE-2019-6111): exactly the named file for a plain non-recursive
    // request, otherwise top-level names matching the requested basename
    // pattern(s), braces expanded. Unlike OpenSSH this also holds with -r.
    let base = from.path.rsplit('/').next().unwrap_or(&from.path);
    let expected = (!cli.xfer.recursive
        && !cli.no_name_check
        && !base.is_empty()
        && !base.contains(['*', '?', '[', '{', '\\']))
    .then_some(base);
    let patterns = if cli.no_name_check || expected.is_some() {
        None
    } else {
        requested_patterns(&from.path)
    };
    let res = Receiver::new(pipe, target, opts)
        .map(|r| {
            let r = r.with_expected_name(expected);
            match patterns {
                Some(p) => r.with_top_level_filter(move |name| {
                    p.iter()
                        .any(|pat| transfer::glob_match(pat.as_bytes(), name.as_bytes()))
                }),
                None => r,
            }
        })
        .and_then(|mut r| r.run());
    if let Err(e) = res {
        fail(errs, e);
    }
}

/// Most alternatives one brace expression may expand to before the name
/// check gives up (the request is the user's own, so this only bounds work).
const MAX_BRACE_EXPANSIONS: usize = 1024;

/// The basename patterns a legacy `scp -f` request for `path` may answer
/// with, braces expanded, or `None` when they cannot be predicted: an
/// empty, `.` or `..` basename, or one the remote shell rewrites
/// (`~`, `$`, backquotes, quotes).
fn requested_patterns(path: &str) -> Option<Vec<String>> {
    if path.contains(['~', '$', '`', '\'', '"']) {
        return None;
    }
    let mut expanded = Vec::new();
    if !brace_expand(path, 0, &mut expanded) {
        return None;
    }
    expanded
        .into_iter()
        .map(|p| {
            let p = p.trim_end_matches('/');
            let base = p.rsplit('/').next().unwrap_or(p);
            (!matches!(base, "" | "." | "..")).then(|| base.to_string())
        })
        .collect()
}

/// Expand `{a,b}` alternatives in `s` (from byte `from` on) into `out`,
/// as the remote shell would; a brace without a top-level comma, or an
/// unmatched one, is literal. `false` past [`MAX_BRACE_EXPANSIONS`].
fn brace_expand(s: &str, from: usize, out: &mut Vec<String>) -> bool {
    let b = s.as_bytes();
    let mut i = from;
    while i < b.len() {
        match b[i] {
            b'\\' => i += 2,
            b'{' => {
                if let Some((close, commas)) = brace_group(b, i)
                    && !commas.is_empty()
                {
                    let mut start = i + 1;
                    for end in commas.into_iter().chain([close]) {
                        let alt = format!("{}{}{}", &s[..i], &s[start..end], &s[close + 1..]);
                        if !brace_expand(&alt, i, out) {
                            return false;
                        }
                        start = end + 1;
                    }
                    return true;
                }
                i += 1;
            }
            _ => i += 1,
        }
    }
    out.push(s.to_string());
    out.len() <= MAX_BRACE_EXPANSIONS
}

/// The `}` matching the `{` at `open`, and the positions of the commas
/// directly inside it.
fn brace_group(b: &[u8], open: usize) -> Option<(usize, Vec<usize>)> {
    let (mut depth, mut commas, mut i) = (0usize, Vec::new(), open);
    while i < b.len() {
        match b[i] {
            b'\\' => i += 1,
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    return Some((i, commas));
                }
            }
            b',' if depth == 1 => commas.push(i),
            _ => {}
        }
        i += 1;
    }
    None
}

/// Remote to remote through this host, legacy protocol: `scp -f` on the
/// source piped into `scp -t` on the target.
fn crossload_legacy(cli: &Cli, from: &Remote, to: &Remote, many: bool, errs: &mut u32) {
    // Several sources: the target sink must be a directory (`-d`).
    let sink = if many { "-dt" } else { "-t" };
    let (src, dst) = match (legacy_pipe(cli, from, "-f"), legacy_pipe(cli, to, sink)) {
        (Ok(s), Ok(d)) => (s, d),
        (Err(e), _) | (_, Err(e)) => return fail(errs, e),
    };
    let (mut src_r, mut src_w, src_child) = src.split();
    let (mut dst_r, mut dst_w, dst_child) = dst.split();
    // Each side's output is the other's input; a side closing ends the
    // copy into the other.
    let up = std::thread::spawn(move || io::copy(&mut src_r, &mut dst_w).map(|_| ()));
    let down = std::thread::spawn(move || io::copy(&mut dst_r, &mut src_w).map(|_| ()));
    let _ = up.join();
    let _ = down.join();
    drop((src_child, dst_child));
}

/// `-R`: run scp on the source host to copy straight to the target.
fn remote_to_remote_direct(cli: &Cli, from: &Remote, target: &str, errs: &mut u32) {
    let mut cmd = vec!["scp".to_string()];
    cmd.extend(cli.passthrough.iter().cloned());
    if let Some(p) = cli.port {
        cmd.extend(["-P".into(), p.to_string()]);
    }
    cmd.push("--".into());
    cmd.push(if from.path.is_empty() {
        ".".into()
    } else {
        from.path.clone()
    });
    cmd.push(target.to_string());
    match SshPipe::spawn(
        &cli.ssh,
        from.user.as_deref(),
        &from.host,
        from.port.or(cli.port),
        false,
        &cmd,
    ) {
        Ok(p) => {
            if p.finish() != 0 {
                *errs += 1;
            }
        }
        Err(e) => fail(errs, e),
    }
}

fn local_copy(cli: &Cli, sources: &[String], target: &str, errs: &mut u32) {
    let mut cmd = std::process::Command::new("cp");
    if cli.xfer.recursive {
        cmd.arg("-r");
    }
    if cli.xfer.preserve {
        cmd.arg("-p");
    }
    cmd.arg("--").args(sources).arg(target);
    match cmd.status() {
        Ok(s) if s.success() => {}
        Ok(_) => *errs += 1,
        Err(e) => fail(errs, format!("cp: {e}")),
    }
}

/// Our stdin/stdout as one stream (the remote end of the legacy protocol).
struct Stdio;

impl io::Read for Stdio {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        io::stdin().read(buf)
    }
}

impl io::Write for Stdio {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        io::stdout().write(buf)
    }
    fn flush(&mut self) -> io::Result<()> {
        io::stdout().flush()
    }
}

/// `scp -t target` / `scp -f source…`: run by the other side's scp in
/// legacy (`-O`) mode.
fn remote_end(cli: &Cli) -> u32 {
    if cli.sink {
        let target = Path::new(&cli.operands[0]);
        if cli.target_dir && !target.is_dir() {
            let _ = puressh::scp::protocol::write_fatal(
                &mut Stdio,
                &format!("scp: {}: Not a directory", target.display()),
            );
            return 1;
        }
        let mut opts = ScpRecvOptions::default();
        opts.recursive = cli.xfer.recursive;
        opts.preserve_times = cli.xfer.preserve;
        opts.target_is_file = !target.is_dir();
        match Receiver::new(Stdio, target, opts).and_then(|mut r| r.run()) {
            Ok(()) => 0,
            Err(_) => 1,
        }
    } else {
        let mut opts = ScpSendOptions::default();
        opts.recursive = cli.xfer.recursive;
        opts.preserve_times = cli.xfer.preserve;
        let mut sender = match Sender::new(Stdio) {
            Ok(s) => s,
            Err(_) => return 1,
        };
        let mut errs = 0;
        for src in &cli.operands {
            if sender.send_path(Path::new(src), &opts).is_err() {
                errs += 1;
            }
        }
        errs
    }
}

fn run() -> Result<u32, String> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let cli = parse_args(&args)?;
    if cli.sink || cli.source {
        return Ok(remote_end(&cli));
    }
    let (target_arg, sources) = cli.operands.split_last().expect("checked");
    let target_remote = remote(target_arg);
    let mut errs = 0u32;

    match &target_remote {
        Some(to) => {
            // Local sources go in one session; each remote source separately.
            let locals: Vec<String> = sources
                .iter()
                .filter(|s| remote(s).is_none())
                .cloned()
                .collect();
            if !locals.is_empty() {
                if cli.legacy {
                    upload_legacy(&cli, &locals, to, &mut errs);
                } else {
                    upload_sftp(&cli, &locals, to, &mut errs);
                }
            }
            let many = sources.len() > 1;
            // Several sources need a directory to go into.
            if many && !cli.legacy && !cli.remote_to_remote_direct {
                let is_dir = open_sftp(&cli, to).ok().is_some_and(|mut sess| {
                    sess.sftp
                        .stat(&sftp_path(&to.path))
                        .is_ok_and(|a| transfer::is_dir(&a))
                });
                if !is_dir {
                    return Err(format!("{}: Not a directory", to.path));
                }
            }
            for s in sources {
                let Some(from) = remote(s) else { continue };
                if cli.remote_to_remote_direct {
                    remote_to_remote_direct(&cli, &from, target_arg, &mut errs);
                } else if cli.legacy {
                    crossload_legacy(&cli, &from, to, many, &mut errs);
                } else {
                    crossload_sftp(&cli, &from, to, &mut errs);
                }
            }
        }
        None => {
            let target = Path::new(target_arg);
            let many = sources.len() > 1;
            if many && !target.is_dir() {
                return Err(format!("{target_arg}: Not a directory"));
            }
            let locals: Vec<String> = sources
                .iter()
                .filter(|s| remote(s).is_none())
                .cloned()
                .collect();
            if !locals.is_empty() {
                local_copy(&cli, &locals, target_arg, &mut errs);
            }
            for s in sources {
                let Some(from) = remote(s) else { continue };
                if cli.legacy {
                    download_legacy(&cli, &from, target, &mut errs);
                } else {
                    download_sftp(&cli, &from, target, many, &mut errs);
                }
            }
        }
    }
    let _ = cli.through_local;
    Ok(errs)
}

fn main() -> ExitCode {
    match run() {
        Ok(0) => ExitCode::SUCCESS,
        Ok(_) => ExitCode::from(1),
        Err(msg) => {
            eprintln!("{msg}");
            ExitCode::from(1)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::requested_patterns;

    fn pats(p: &str) -> Option<Vec<String>> {
        requested_patterns(p)
    }

    #[test]
    fn requested_patterns_expand_braces_to_basenames() {
        assert_eq!(pats("dir/*.txt").unwrap(), ["*.txt"]);
        assert_eq!(pats("d/{a,b{1,2}}.c").unwrap(), ["a.c", "b1.c", "b2.c"]);
        assert_eq!(pats("{x/one,y/two/}").unwrap(), ["one", "two"]);
        assert_eq!(pats("lit{eral}").unwrap(), ["lit{eral}"]);
        assert_eq!(pats("tree/").unwrap(), ["tree"]);
    }

    #[test]
    fn requested_patterns_unpredictable_requests_are_not_checked() {
        for p in ["", ".", "a/..", "~", "~/x", "$HOME", "`f`", "'q'", "{a,.}"] {
            assert!(pats(p).is_none(), "{p}");
        }
        assert!(pats(&"{a,b}".repeat(11)).is_none());
    }
}
