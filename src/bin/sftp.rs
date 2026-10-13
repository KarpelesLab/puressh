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
//! exits. Commands follow OpenSSH's (`help` lists them); in batch mode
//! (`-b`) each is echoed and the first failure aborts with status 1 unless
//! the command is prefixed with `-` (`@` suppresses the echo).

use std::io::{self, BufRead, IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use puressh::sftp::{Attrs, FxpStatus, SftpClient, SftpError};

#[path = "transfer.rs"]
mod transfer;
use transfer::{SshOptions, SshPipe, XferOpts, remote_basename};

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
df [-hi] [path]                    Display statistics for current directory or
                                   filesystem containing 'path'
exit                               Quit sftp
get [-afpR] remote [local]         Download file
help                               Display this help text
lcd path                           Change local directory to 'path'
lls [ls-options [path]]            Display local directory listing
lmkdir path                        Create local directory
ln [-s] oldpath newpath            Link remote file (-s for symlink)
lpwd                               Print local working directory
ls [-1afhlnrSt] [path]             Display remote directory listing
lumask umask                       Set local umask to 'umask'
mkdir path                         Create remote directory
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

struct Cli {
    ssh: SshOptions,
    port: Option<u16>,
    batch: Option<String>,
    quiet: bool,
    xfer: XferOpts,
    fsync: bool,
    subsystem: Option<String>,
    sftp_direct: Option<String>,
    destination: String,
    /// `sftp host:file localpath`: where the fetched file goes.
    local: Option<String>,
}

fn parse_args(args: &[String]) -> Result<Cli, String> {
    const WITH_ARG: &str = "BbcDFiJloPRSsX";
    let mut c = Cli {
        ssh: SshOptions::default(),
        port: None,
        batch: None,
        quiet: false,
        xfer: XferOpts::default(),
        fsync: false,
        subsystem: None,
        sftp_direct: None,
        destination: String::new(),
        local: None,
    };
    let mut operands = Vec::new();
    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
        if a == "--" {
            operands.extend(args[i + 1..].iter().cloned());
            break;
        }
        if !a.starts_with('-') || a == "-" {
            operands.push(a.clone());
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
                let num = |what: &str, v: &str| -> Result<u64, String> {
                    v.parse::<u64>()
                        .ok()
                        .filter(|n| *n > 0)
                        .ok_or_else(|| format!("Invalid {what}: {v}"))
                };
                match f {
                    'B' => {
                        c.xfer.chunk = u32::try_from(num("buffer size", &v)?)
                            .ok()
                            .filter(|n| *n <= 256 * 1024)
                            .ok_or_else(|| format!("Invalid buffer size \"{v}\""))?
                    }
                    'b' => {
                        c.batch = Some(v);
                        c.quiet = true;
                        c.ssh.push("-oBatchMode=yes", None);
                    }
                    'c' => c.ssh.push("-c", Some(&v)),
                    'D' => c.sftp_direct = Some(v),
                    'F' => c.ssh.push("-F", Some(&v)),
                    'i' => c.ssh.push("-i", Some(&v)),
                    'J' => c.ssh.push("-J", Some(&v)),
                    'l' => c.xfer.limit = Some(num("limit", &v)? * 1024 / 8),
                    'o' => c.ssh.push("-o", Some(&v)),
                    'P' => c.port = Some(v.parse().map_err(|_| format!("Bad port \"{v}\""))?),
                    'R' => c.xfer.depth = num("number of requests", &v)? as usize,
                    'S' => c.ssh.program = Some(v),
                    's' => c.subsystem = Some(v),
                    'X' => match v.split_once('=') {
                        Some(("buffer", n)) => {
                            c.xfer.chunk = n
                                .parse()
                                .ok()
                                .filter(|n| (1..=256 * 1024).contains(n))
                                .ok_or_else(|| format!("Invalid buffer size \"{n}\""))?
                        }
                        Some(("nrequests", n)) => {
                            c.xfer.depth = num("number of requests", n)? as usize
                        }
                        _ => return Err(format!("Invalid -X option \"{v}\"")),
                    },
                    _ => unreachable!(),
                }
                break;
            }
            match f {
                '4' | '6' | 'C' | 'v' => c.ssh.push(&format!("-{f}"), None),
                'A' => c.ssh.forward_agent = true,
                'a' => c.xfer.resume = true,
                'f' => c.fsync = true,
                'N' => {}
                'p' => c.xfer.preserve = true,
                'q' => {
                    c.quiet = true;
                    c.ssh.push("-q", None);
                }
                'r' => c.xfer.recursive = true,
                _ => return Err(format!("unknown option -- {f}\n{USAGE}")),
            }
            j += 1;
        }
        i += 1;
    }
    match operands.as_slice() {
        [d] => c.destination = d.clone(),
        [d, l] => {
            c.destination = d.clone();
            c.local = Some(l.clone());
        }
        // `-D server`: no host to connect to, as with OpenSSH.
        [] if c.sftp_direct.is_some() => {}
        _ => return Err(USAGE.into()),
    }
    Ok(c)
}

/// OpenSSH's wording for a failed request (its `fx2txt`).
fn fx(e: &SftpError) -> String {
    match e {
        SftpError::Status { code, .. } => match code {
            FxpStatus::Ok => "Success",
            FxpStatus::Eof => "End of file",
            FxpStatus::NoSuchFile => "No such file or directory",
            FxpStatus::PermissionDenied => "Permission denied",
            FxpStatus::Failure => "Failure",
            FxpStatus::BadMessage => "Bad message",
            FxpStatus::NoConnection => "No connection",
            FxpStatus::ConnectionLost => "Connection lost",
            FxpStatus::OpUnsupported => "Operation unsupported",
            _ => "Unknown status",
        }
        .into(),
        other => other.to_string(),
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

/// Split a command line like OpenSSH's sftp: whitespace separates words,
/// `'…'` and `"…"` quote, `\` escapes the next character.
fn split_line(line: &str) -> Result<Vec<String>, String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut in_word = false;
    let mut quote: Option<char> = None;
    let mut chars = line.chars();
    while let Some(c) = chars.next() {
        match (quote, c) {
            (Some(q), c) if c == q => quote = None,
            (Some('"'), '\\') | (None, '\\') => match chars.next() {
                Some(n) => {
                    cur.push(n);
                    in_word = true;
                }
                None => return Err("Invalid escape at end of line".into()),
            },
            (Some(_), c) => cur.push(c),
            (None, '\'' | '"') => {
                quote = Some(c);
                in_word = true;
            }
            (None, c) if c.is_whitespace() => {
                if in_word {
                    out.push(std::mem::take(&mut cur));
                    in_word = false;
                }
            }
            (None, c) => {
                cur.push(c);
                in_word = true;
            }
        }
    }
    if quote.is_some() {
        return Err("Unterminated quote".into());
    }
    if in_word {
        out.push(cur);
    }
    Ok(out)
}

/// Split leading `-xyz` flags off a command's arguments.
fn take_flags(args: &[String], allowed: &str, cmd: &str) -> Result<(String, Vec<String>), String> {
    let mut flags = String::new();
    let mut i = 0;
    while i < args.len() && args[i].starts_with('-') && args[i].len() > 1 {
        if args[i] == "--" {
            i += 1;
            break;
        }
        for f in args[i][1..].chars() {
            if !allowed.contains(f) {
                return Err(format!("{cmd}: Invalid flag -{f}"));
            }
            flags.push(f);
        }
        i += 1;
    }
    Ok((flags, args[i..].to_vec()))
}

fn human_size(n: u64) -> String {
    const UNITS: [&str; 7] = ["", "K", "M", "G", "T", "P", "E"];
    let mut v = n as f64;
    let mut u = 0;
    while v >= 1024.0 && u + 1 < UNITS.len() {
        v /= 1024.0;
        u += 1;
    }
    if u == 0 {
        format!("{n}B")
    } else if v < 10.0 {
        format!("{v:.1}{}", UNITS[u])
    } else {
        format!("{v:.0}{}", UNITS[u])
    }
}

/// `ls -l` line formatted from attributes (`-n`, `-h`, or a single file).
fn long_line(name: &str, a: &Attrs, human: bool, owners: Option<(&str, &str)>) -> String {
    let mode = a.permissions.unwrap_or(0);
    let kind = match mode & 0o170000 {
        0o040000 => 'd',
        0o120000 => 'l',
        0o020000 => 'c',
        0o060000 => 'b',
        0o010000 => 'p',
        0o140000 => 's',
        _ => '-',
    };
    let bit = |m: u32, c: char| if mode & m != 0 { c } else { '-' };
    let mut perms = String::with_capacity(10);
    perms.push(kind);
    for (r, w, x, special, sc) in [
        (0o400, 0o200, 0o100, 0o4000, 's'),
        (0o040, 0o020, 0o010, 0o2000, 's'),
        (0o004, 0o002, 0o001, 0o1000, 't'),
    ] {
        perms.push(bit(r, 'r'));
        perms.push(bit(w, 'w'));
        perms.push(match (mode & x != 0, mode & special != 0) {
            (true, true) => sc,
            (false, true) => sc.to_ascii_uppercase(),
            (true, false) => 'x',
            (false, false) => '-',
        });
    }
    let (uid, gid) = a.uid_gid.unwrap_or((0, 0));
    let (user, group) = match owners {
        Some((u, g)) if !u.is_empty() && !g.is_empty() => (u.to_string(), g.to_string()),
        _ => (uid.to_string(), gid.to_string()),
    };
    let size = a.size.unwrap_or(0);
    let size = if human {
        human_size(size)
    } else {
        size.to_string()
    };
    let mtime = a.atime_mtime.map(|(_, m)| m).unwrap_or(0);
    format!(
        "{perms}    ? {user:<8} {group:<8} {size:>8} {} {name}",
        format_mtime(mtime)
    )
}

fn format_mtime(t: u32) -> String {
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let local = i64::from(t) + transfer::local_offset(i64::from(t));
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
    // Like ls: the time for the last six months, else the year.
    if (now - i64::from(t)).abs() < 183 * 86_400 {
        format!(
            "{} {d:>2} {:02}:{:02}",
            MONTHS[(m - 1) as usize],
            secs / 3600,
            secs / 60 % 60
        )
    } else {
        format!("{} {d:>2}  {y}", MONTHS[(m - 1) as usize])
    }
}

struct Session {
    sftp: SftpClient<SshPipe>,
    pwd: Vec<u8>,
    home: Vec<u8>,
    xfer: XferOpts,
    quiet: bool,
    progress: bool,
    fsync: bool,
}

enum Flow {
    Continue,
    Quit,
}

impl Session {
    /// A remote path: `~` / `~/x` from the login directory, else relative
    /// to the working directory.
    fn resolve(&self, p: &str) -> Vec<u8> {
        if p == "~" {
            return self.home.clone();
        }
        if let Some(rest) = p.strip_prefix("~/") {
            return transfer::remote_join(&self.home, rest.as_bytes());
        }
        transfer::remote_join(&self.pwd, p.as_bytes())
    }

    fn glob(&mut self, p: &str) -> Result<Vec<Vec<u8>>, String> {
        let full = self.resolve(p);
        transfer::remote_glob(&mut self.sftp, b"", &full)
    }

    fn opts(&self, flags: &str, resume: bool) -> XferOpts {
        let mut o = self.xfer.clone();
        o.preserve |= flags.contains('p') || flags.contains('P');
        o.recursive |= flags.contains('r') || flags.contains('R');
        o.resume |= resume || flags.contains('a');
        o.progress = self.progress && !self.quiet;
        o.announce_dirs = true;
        o
    }

    fn run(&mut self, args: &[String]) -> Result<Flow, String> {
        let Some((cmd, rest)) = args.split_first() else {
            return Ok(Flow::Continue);
        };
        match cmd.as_str() {
            "bye" | "exit" | "quit" => return Ok(Flow::Quit),
            "help" | "?" => println!("{HELP}"),
            "version" => println!("SFTP protocol version {}", self.sftp.server_version()),
            "pwd" => println!("Remote working directory: {}", safe_display(&self.pwd)),
            "lpwd" => println!(
                "Local working directory: {}",
                std::env::current_dir()
                    .map(|d| d.display().to_string())
                    .unwrap_or_default()
            ),
            "progress" => {
                self.progress = !self.progress;
                println!(
                    "Progress meter {}",
                    if self.progress { "enabled" } else { "disabled" }
                );
            }
            "cd" => self.cd(rest.first().map(String::as_str))?,
            "lcd" => {
                let target = match rest.first() {
                    Some(p) => PathBuf::from(p),
                    None => std::env::var_os("HOME")
                        .map(PathBuf::from)
                        .unwrap_or_default(),
                };
                std::env::set_current_dir(&target).map_err(|e| {
                    format!(
                        "Couldn't change local directory to \"{}\": {}",
                        target.display(),
                        io_text(&e)
                    )
                })?;
            }
            "lmkdir" => {
                let p = rest
                    .first()
                    .ok_or("You must specify a path after a lmkdir command.")?;
                std::fs::create_dir(p).map_err(|e| {
                    format!("Couldn't create local directory \"{p}\": {}", io_text(&e))
                })?;
            }
            "lls" => {
                let st = std::process::Command::new("ls").args(rest).status();
                if !st.is_ok_and(|s| s.success()) {
                    return Err("Couldn't execute \"ls\"".into());
                }
            }
            "lumask" => {
                let v = rest
                    .first()
                    .ok_or("You must supply a numeric argument to the lumask command.")?;
                let mask = u32::from_str_radix(v, 8)
                    .ok()
                    .filter(|m| *m <= 0o777)
                    .ok_or("You must supply a numeric argument to the lumask command.")?;
                set_umask(mask);
                println!("Local umask: {mask:03o}");
            }
            "ls" | "dir" => self.ls(rest)?,
            "get" | "reget" => self.get(rest, cmd == "reget")?,
            "put" | "reput" => self.put(rest, cmd == "reput")?,
            "mkdir" => {
                let p = rest
                    .first()
                    .ok_or("You must specify a path after a mkdir command.")?;
                let abs = self.resolve(p);
                let mut a = Attrs::default();
                a.permissions = Some(0o777);
                self.sftp
                    .mkdir(&abs, a)
                    .map_err(|e| format!("remote mkdir \"{}\": {}", lossy(&abs), fx(&e)))?;
            }
            "rmdir" => {
                let p = rest
                    .first()
                    .ok_or("You must specify a path after a rmdir command.")?;
                let abs = self.resolve(p);
                self.sftp
                    .rmdir(&abs)
                    .map_err(|e| format!("remote rmdir \"{}\": {}", lossy(&abs), fx(&e)))?;
            }
            "rm" => {
                let p = rest
                    .first()
                    .ok_or("You must specify a path after a rm command.")?;
                let mut err = None;
                for f in self.glob(p)? {
                    if !self.quiet {
                        println!("Removing {}", safe_display(&f));
                    }
                    if let Err(e) = self.sftp.remove(&f) {
                        let msg = format!("remote delete {}: {}", lossy(&f), fx(&e));
                        eprintln!("{msg}");
                        err = Some(msg);
                    }
                }
                if err.is_some() {
                    return Err(String::new());
                }
            }
            "rename" => {
                let [old, new] = rest else {
                    return Err("You must specify two paths after a rename command.".into());
                };
                let (o, n) = (self.resolve(old), self.resolve(new));
                let res = if self.sftp.has_extension("posix-rename@openssh.com") {
                    self.sftp.posix_rename(&o, &n)
                } else {
                    self.sftp.rename(&o, &n)
                };
                res.map_err(|e| {
                    format!(
                        "Couldn't rename file \"{}\" to \"{}\": {}",
                        lossy(&o),
                        lossy(&n),
                        fx(&e)
                    )
                })?;
            }
            "ln" | "symlink" => {
                let (flags, paths) = take_flags(rest, "s", cmd)?;
                let [old, new] = paths.as_slice() else {
                    return Err(format!("You must specify two paths after a {cmd} command."));
                };
                let link = self.resolve(new);
                if cmd == "symlink" || flags.contains('s') {
                    // The target is stored as given (relative stays relative).
                    self.sftp.symlink(old.as_bytes(), &link).map_err(|e| {
                        format!(
                            "Couldn't symlink file \"{old}\" to \"{}\": {}",
                            lossy(&link),
                            fx(&e)
                        )
                    })?;
                } else {
                    if !self.sftp.has_extension("hardlink@openssh.com") {
                        return Err("Server does not support hardlink@openssh.com extension".into());
                    }
                    let target = self.resolve(old);
                    self.sftp.hardlink(&target, &link).map_err(|e| {
                        format!(
                            "Couldn't link file \"{}\" to \"{}\": {}",
                            lossy(&target),
                            lossy(&link),
                            fx(&e)
                        )
                    })?;
                }
            }
            "chmod" | "chown" | "chgrp" => self.chattr(cmd, rest)?,
            "df" => self.df(rest)?,
            "copy" | "cp" => {
                return Err("Server does not support copy-data extension".into());
            }
            other => return Err(format!("Invalid command \"{other}\".")),
        }
        Ok(Flow::Continue)
    }

    fn cd(&mut self, p: Option<&str>) -> Result<(), String> {
        let abs = match p {
            Some(p) => self.resolve(p),
            None => self.home.clone(),
        };
        let a = self
            .sftp
            .stat(&abs)
            .map_err(|e| format!("stat remote: {}", fx(&e)))?;
        if !transfer::is_dir(&a) {
            return Err(format!(
                "Can't change directory: \"{}\" is not a directory",
                lossy(&abs)
            ));
        }
        self.pwd = self.sftp.realpath(&abs).map_err(|e| fx(&e))?;
        Ok(())
    }

    fn ls(&mut self, args: &[String]) -> Result<(), String> {
        let (flags, paths) = take_flags(args, "1afhlnrSt", "ls")?;
        let long = flags.contains('l') || flags.contains('n');
        let all = flags.contains('a');
        let targets: Vec<String> = if paths.is_empty() {
            vec![lossy(&self.pwd)]
        } else {
            paths
        };
        for t in targets {
            let abs = self.resolve(&t);
            let matches = if transfer::has_glob(&abs) {
                self.glob(&t)
                    .map_err(|_| format!("Can't ls: \"{}\" not found", lossy(&abs)))?
            } else {
                vec![abs.clone()]
            };
            let mut entries: Vec<(Vec<u8>, Vec<u8>, Attrs)> = Vec::new();
            for m in matches {
                let a = self
                    .sftp
                    .stat(&m)
                    .map_err(|_| format!("Can't ls: \"{}\" not found", lossy(&m)))?;
                if transfer::is_dir(&a) && !transfer::has_glob(&abs) {
                    let h = self
                        .sftp
                        .opendir(&m)
                        .map_err(|e| format!("Couldn't read directory: {}", fx(&e)))?;
                    while let Some(batch) = self.sftp.readdir(&h).map_err(|e| fx(&e))? {
                        for e in batch {
                            if !all && e.filename.first() == Some(&b'.') {
                                continue;
                            }
                            entries.push((e.filename, e.longname, e.attrs));
                        }
                    }
                    let _ = self.sftp.close(&h);
                } else {
                    let name = if paths_given(&t) {
                        m.clone()
                    } else {
                        remote_basename(&m).to_vec()
                    };
                    entries.push((name, Vec::new(), a));
                }
            }
            if !flags.contains('f') {
                if flags.contains('S') {
                    entries.sort_by(|a, b| b.2.size.cmp(&a.2.size).then(a.0.cmp(&b.0)));
                } else if flags.contains('t') {
                    let mt = |a: &Attrs| a.atime_mtime.map(|t| t.1).unwrap_or(0);
                    entries.sort_by(|a, b| mt(&b.2).cmp(&mt(&a.2)).then(a.0.cmp(&b.0)));
                } else {
                    entries.sort_by(|a, b| a.0.cmp(&b.0));
                }
                if flags.contains('r') {
                    entries.reverse();
                }
            }
            let out = io::stdout();
            let mut out = out.lock();
            if long {
                let numeric = flags.contains('n');
                let human = flags.contains('h');
                // Names for the lines formatted here (the server's own
                // `longname` already has them), as OpenSSH asks the server.
                let ids: Vec<(u32, u32)> = entries
                    .iter()
                    .filter(|e| e.1.is_empty() || human)
                    .filter_map(|e| e.2.uid_gid)
                    .collect();
                let names = if !numeric
                    && !ids.is_empty()
                    && self.sftp.has_extension("users-groups-by-id@openssh.com")
                {
                    let uids: Vec<u32> = ids.iter().map(|i| i.0).collect();
                    let gids: Vec<u32> = ids.iter().map(|i| i.1).collect();
                    self.sftp
                        .users_groups_by_id(&uids, &gids)
                        .ok()
                        .map(|(u, g)| {
                            ids.iter()
                                .zip(u.iter().zip(g.iter()))
                                .map(|(id, (u, g))| (*id, (lossy(u), lossy(g))))
                                .collect::<std::collections::BTreeMap<_, _>>()
                        })
                } else {
                    None
                };
                for (name, longname, a) in &entries {
                    let line = if !longname.is_empty() && !numeric && !human {
                        safe_display(longname)
                    } else {
                        let owners = a
                            .uid_gid
                            .and_then(|id| names.as_ref()?.get(&id))
                            .map(|(u, g)| (u.as_str(), g.as_str()));
                        long_line(&safe_display(name), a, human, owners)
                    };
                    let _ = writeln!(out, "{line}");
                }
            } else if flags.contains('1') {
                for (name, _, _) in &entries {
                    let _ = writeln!(out, "{}", safe_display(name));
                }
            } else {
                let names: Vec<String> = entries.iter().map(|e| safe_display(&e.0)).collect();
                let width = names.iter().map(|n| n.chars().count()).max().unwrap_or(0) + 2;
                let cols = (terminal_width() / width.max(1)).max(1);
                for (i, n) in names.iter().enumerate() {
                    let _ = write!(out, "{n:<width$}");
                    if (i + 1) % cols == 0 || i + 1 == names.len() {
                        let _ = writeln!(out);
                    }
                }
            }
        }
        Ok(())
    }

    fn get(&mut self, args: &[String], resume: bool) -> Result<(), String> {
        let (flags, paths) = take_flags(args, "afpPrR", "get")?;
        let (src, dst) = match paths.as_slice() {
            [s] => (s, None),
            [s, d] => (s, Some(d.as_str())),
            _ => return Err("You must specify at least one path after a get command.".into()),
        };
        let abs = self.resolve(src);
        let matches = if transfer::has_glob(&abs) {
            self.glob(src)
                .map_err(|_| format!("File \"{}\" not found.", lossy(&abs)))?
        } else {
            vec![abs.clone()]
        };
        let local_dir = dst
            .map(Path::new)
            .filter(|d| d.is_dir())
            .map(Path::to_path_buf);
        if matches.len() > 1 && dst.is_some() && local_dir.is_none() {
            return Err(
                "Multiple source paths, but destination \"{}\" is not a directory"
                    .replace("{}", dst.unwrap_or_default()),
            );
        }
        let opts = self.opts(&flags, resume);
        let mut failed = false;
        for m in matches {
            let name = lossy(remote_basename(&m));
            if self.sftp.stat(&m).is_err() {
                eprintln!("File \"{}\" not found.", lossy(&m));
                failed = true;
                continue;
            }
            let local = match (&local_dir, dst) {
                (Some(d), _) => d.join(&name),
                (None, Some(d)) => PathBuf::from(d),
                (None, None) => PathBuf::from(&name),
            };
            if !self.quiet {
                let slash = if self.sftp.stat(&m).is_ok_and(|a| transfer::is_dir(&a))
                    && m.last() != Some(&b'/')
                {
                    "/"
                } else {
                    ""
                };
                println!(
                    "Fetching {}{slash} to {}",
                    safe_display(&m),
                    local.display()
                );
            }
            if let Err(e) = transfer::download(&mut self.sftp, &m, &local, &opts) {
                eprintln!("{e}");
                failed = true;
            } else if (self.fsync || flags.contains('f'))
                && let Ok(f) = std::fs::File::open(&local)
            {
                let _ = f.sync_all();
            }
        }
        if failed { Err(String::new()) } else { Ok(()) }
    }

    fn put(&mut self, args: &[String], resume: bool) -> Result<(), String> {
        let (flags, paths) = take_flags(args, "afpPrR", "put")?;
        let (src, dst) = match paths.as_slice() {
            [s] => (s, None),
            [s, d] => (s, Some(d.as_str())),
            _ => return Err("You must specify at least one path after a put command.".into()),
        };
        let locals = transfer::local_glob(src).map_err(|_| format!("File \"{src}\" not found."))?;
        let target = dst.map(|d| self.resolve(d));
        let target_is_dir = match &target {
            Some(t) => self.sftp.stat(t).is_ok_and(|a| transfer::is_dir(&a)),
            None => true,
        };
        if locals.len() > 1 && !target_is_dir {
            return Err(format!(
                "Multiple paths match, but destination \"{}\" is not a directory",
                lossy(target.as_deref().unwrap_or_default())
            ));
        }
        let opts = self.opts(&flags, resume);
        let mut failed = false;
        for l in locals {
            let name = l
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default();
            let remote = match &target {
                Some(t) if target_is_dir => transfer::remote_join(t, name.as_bytes()),
                Some(t) => t.clone(),
                None => transfer::remote_join(&self.pwd, name.as_bytes()),
            };
            if !l.exists() {
                eprintln!("File \"{}\" not found.", l.display());
                failed = true;
                continue;
            }
            if !self.quiet {
                let slash = if l.is_dir() && !l.to_string_lossy().ends_with('/') {
                    "/"
                } else {
                    ""
                };
                println!(
                    "Uploading {}{slash} to {}",
                    l.display(),
                    safe_display(&remote)
                );
            }
            if let Err(e) = transfer::upload(&mut self.sftp, &l, &remote, &opts) {
                eprintln!("{e}");
                failed = true;
            } else if (self.fsync || flags.contains('f'))
                && self.sftp.has_extension("fsync@openssh.com")
                && let Ok(h) = self
                    .sftp
                    .open(&remote, puressh::sftp::FXF_WRITE, Attrs::default())
            {
                let _ = self.sftp.fsync(&h);
                let _ = self.sftp.close(&h);
            }
        }
        if failed { Err(String::new()) } else { Ok(()) }
    }

    fn chattr(&mut self, cmd: &str, args: &[String]) -> Result<(), String> {
        let (_flags, rest) = take_flags(args, "h", cmd)?;
        let [value, path] = rest.as_slice() else {
            return Err(format!(
                "You must specify a value and a path after a {cmd} command."
            ));
        };
        let mut failed = false;
        for f in self.glob(path)? {
            let mut a = Attrs::default();
            match cmd {
                "chmod" => {
                    let mode = u32::from_str_radix(value, 8)
                        .ok()
                        .filter(|m| *m <= 0o7777)
                        .ok_or("You must supply a numeric argument to the chmod command.")?;
                    a.permissions = Some(mode);
                    if !self.quiet {
                        println!("Changing mode on {}", safe_display(&f));
                    }
                }
                _ => {
                    let id: u32 = value.parse().map_err(|_| {
                        format!("You must supply a numeric argument to the {cmd} command.")
                    })?;
                    let cur = match self.sftp.stat(&f) {
                        Ok(c) => c,
                        Err(e) => {
                            eprintln!(
                                "Can't get current ownership of remote file \"{}\": {}",
                                lossy(&f),
                                fx(&e)
                            );
                            failed = true;
                            continue;
                        }
                    };
                    let (uid, gid) = cur.uid_gid.unwrap_or((0, 0));
                    a.uid_gid = Some(if cmd == "chown" { (id, gid) } else { (uid, id) });
                    if !self.quiet {
                        println!(
                            "Changing {} on {}",
                            if cmd == "chown" { "owner" } else { "group" },
                            safe_display(&f)
                        );
                    }
                }
            }
            if let Err(e) = self.sftp.setstat(&f, a) {
                eprintln!("Couldn't setstat on \"{}\": {}", lossy(&f), fx(&e));
                failed = true;
            }
        }
        if failed { Err(String::new()) } else { Ok(()) }
    }

    fn df(&mut self, args: &[String]) -> Result<(), String> {
        let (flags, rest) = take_flags(args, "hi", "df")?;
        let path = match rest.first() {
            Some(p) => self.resolve(p),
            None => self.pwd.clone(),
        };
        if !self.sftp.has_extension("statvfs@openssh.com") {
            return Err("Server does not support statvfs@openssh.com extension".into());
        }
        let v = self
            .sftp
            .statvfs(&path)
            .map_err(|e| format!("Couldn't statvfs: {}", fx(&e)))?;
        let (frsize, blocks, bfree, bavail, files, ffree, favail) =
            (v[1], v[2], v[3], v[4], v[5], v[6], v[7]);
        let pct = |used: u64, total: u64| (used * 100).checked_div(total).unwrap_or(0);
        if flags.contains('i') {
            println!("      Inodes        Used       Avail      (root)    %Capacity");
            println!(
                "{:>12} {:>11} {:>11} {:>11}         {:>3}%",
                files,
                files - ffree,
                favail,
                ffree,
                pct(files - ffree, files)
            );
        } else if flags.contains('h') {
            let h = |b: u64| {
                let s = human_size(b * frsize);
                // OpenSSH prints these with a trailing "B".
                if s.ends_with('B') { s } else { format!("{s}B") }
            };
            println!("    Size     Used    Avail   (root)    %Capacity");
            println!(
                "{:>8} {:>8} {:>8} {:>8}         {:>3}%",
                h(blocks),
                h(blocks - bfree),
                h(bavail),
                h(bfree),
                pct(blocks - bfree, blocks)
            );
        } else {
            let k = |b: u64| b * frsize / 1024;
            println!("        Size         Used        Avail       (root)    %Capacity");
            println!(
                "{:>12} {:>12} {:>12} {:>12}         {:>3}%",
                k(blocks),
                k(blocks - bfree),
                k(bavail),
                k(bfree),
                pct(blocks - bfree, blocks)
            );
        }
        Ok(())
    }
}

fn paths_given(t: &str) -> bool {
    t.contains('/')
}

fn io_text(e: &io::Error) -> String {
    match e.kind() {
        io::ErrorKind::NotFound => "No such file or directory".into(),
        io::ErrorKind::PermissionDenied => "Permission denied".into(),
        io::ErrorKind::AlreadyExists => "File exists".into(),
        _ => e.to_string(),
    }
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

fn set_umask(mask: u32) {
    #[cfg(unix)]
    // SAFETY: umask only swaps the process file-creation mask.
    unsafe {
        libc::umask(mask as libc::mode_t);
    }
    #[cfg(not(unix))]
    let _ = mask;
}

/// `!command` / `!`: run it with the user's shell.
fn local_shell(cmd: &str) {
    let shell = std::env::var("SHELL").unwrap_or_else(|_| "/bin/sh".into());
    let mut c = std::process::Command::new(&shell);
    if !cmd.trim().is_empty() {
        c.arg("-c").arg(cmd);
    }
    match c.status() {
        Ok(s) if !s.success() => {
            if let Some(code) = s.code() {
                eprintln!("Shell exited with status {code}");
            }
        }
        Ok(_) => {}
        Err(e) => eprintln!("Couldn't execute \"{shell}\": {e}"),
    }
}

/// Run commands from `input` until EOF or `quit`. Batch mode aborts on the
/// first failing command (unless prefixed with `-`); the result is the exit
/// status.
fn command_loop(sess: &mut Session, input: &mut dyn BufRead, batch: bool) -> u8 {
    let tty = io::stdin().is_terminal() && !batch;
    let mut line = String::new();
    loop {
        if !batch {
            print!("sftp> ");
            let _ = io::stdout().flush();
        }
        line.clear();
        match input.read_line(&mut line) {
            Ok(0) | Err(_) => {
                if tty {
                    println!();
                }
                return 0;
            }
            Ok(_) => {}
        }
        let raw = line.trim_end_matches(['\n', '\r']);
        let mut cmd = raw.trim_start();
        // Interactive input from a pipe is echoed; batch input too unless
        // prefixed with `@`.
        let mut echo = !tty;
        if let Some(rest) = cmd.strip_prefix('@') {
            cmd = rest;
            echo = false;
        }
        if echo {
            if batch {
                println!("sftp> {raw}");
            } else {
                println!("{raw}");
            }
        }
        let ignore_err = cmd.starts_with('-');
        if ignore_err {
            cmd = &cmd[1..];
        }
        if cmd.trim().is_empty() || cmd.trim_start().starts_with('#') {
            continue;
        }
        if let Some(shell_cmd) = cmd.strip_prefix('!') {
            local_shell(shell_cmd);
            continue;
        }
        let result = split_line(cmd).and_then(|argv| sess.run(&argv));
        match result {
            Ok(Flow::Quit) => return 0,
            Ok(Flow::Continue) => {}
            Err(msg) => {
                if !msg.is_empty() {
                    eprintln!("{msg}");
                }
                if batch && !ignore_err {
                    return 1;
                }
            }
        }
    }
}

fn run() -> Result<u8, String> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let cli = parse_args(&args)?;
    let remote = transfer::parse_remote(&cli.destination, &["sftp"]).unwrap_or(transfer::Remote {
        user: None,
        host: cli.destination.clone(),
        port: None,
        path: String::new(),
    });
    // A `user@host` destination without a path.
    let (user, host) = match (&remote.user, remote.host.rsplit_once('@')) {
        (None, Some((u, h))) if remote.path.is_empty() => (Some(u.to_string()), h.to_string()),
        _ => (remote.user.clone(), remote.host.clone()),
    };
    let pipe = match (&cli.sftp_direct, &cli.subsystem) {
        (Some(server), _) => {
            let mut words = server.split_whitespace().map(str::to_string);
            let prog = words.next().ok_or("empty -D command")?;
            SshPipe::spawn_program(&prog, &words.collect::<Vec<_>>())
        }
        // `-s /path/sftp-server`: run it as a command instead of a subsystem.
        (None, Some(s)) if s.contains('/') => SshPipe::spawn(
            &cli.ssh,
            user.as_deref(),
            &host,
            remote.port.or(cli.port),
            false,
            std::slice::from_ref(s),
        ),
        (None, sub) => SshPipe::spawn(
            &cli.ssh,
            user.as_deref(),
            &host,
            remote.port.or(cli.port),
            true,
            &[sub.clone().unwrap_or_else(|| "sftp".into())],
        ),
    }
    .map_err(|e| e.to_string())?;
    let mut sftp = SftpClient::new(pipe).map_err(|_| "Connection closed".to_string())?;
    let home = sftp
        .realpath(b".")
        .map_err(|e| format!("Couldn't canonicalize: {}", fx(&e)))?;
    if !cli.quiet {
        eprintln!("Connected to {host}.");
    }
    let mut sess = Session {
        sftp,
        pwd: home.clone(),
        home,
        progress: io::stdout().is_terminal(),
        xfer: cli.xfer.clone(),
        quiet: cli.quiet,
        fsync: cli.fsync,
    };

    // `host:path`: a directory to start in, or files to fetch.
    if !remote.path.is_empty() {
        let abs = sess.resolve(&remote.path);
        let is_dir =
            !transfer::has_glob(&abs) && sess.sftp.stat(&abs).is_ok_and(|a| transfer::is_dir(&a));
        if is_dir {
            sess.cd(Some(&remote.path))?;
        } else {
            let mut args = vec![remote.path.clone()];
            args.extend(cli.local.iter().cloned());
            let res = sess.get(&args, cli.xfer.resume);
            if let Err(e) = &res
                && !e.is_empty()
            {
                eprintln!("{e}");
            }
            return Ok(if res.is_ok() { 0 } else { 1 });
        }
    }

    let code = match &cli.batch {
        Some(path) if path != "-" => {
            let f = std::fs::File::open(path).map_err(|e| format!("{path} ({e})"))?;
            command_loop(&mut sess, &mut io::BufReader::new(f), true)
        }
        Some(_) => command_loop(&mut sess, &mut io::stdin().lock(), true),
        None => command_loop(&mut sess, &mut io::stdin().lock(), false),
    };
    Ok(code)
}

fn main() -> ExitCode {
    match run() {
        Ok(code) => ExitCode::from(code),
        Err(msg) => {
            eprintln!("{msg}");
            ExitCode::from(255)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        let args: Vec<String> = ["-pR", "a", "b"].iter().map(|s| s.to_string()).collect();
        let (f, rest) = take_flags(&args, "afpPrR", "get").unwrap();
        assert_eq!(f, "pR");
        assert_eq!(rest, ["a", "b"]);
        assert!(take_flags(&args, "a", "get").is_err());
    }

    #[test]
    fn scrubs_control_bytes() {
        assert_eq!(safe_display(b"a\x1b[31mb\n"), "a?[31mb?");
    }

    #[test]
    fn long_listing() {
        let mut a = Attrs::default();
        a.permissions = Some(0o100644);
        a.size = Some(5);
        a.uid_gid = Some((1000, 1000));
        a.atime_mtime = Some((0, 0));
        let l = long_line("f", &a, false, None);
        assert!(
            l.starts_with("-rw-r--r--    ? 1000     1000            5 Jan  1  1970 f"),
            "{l}"
        );
    }
}
