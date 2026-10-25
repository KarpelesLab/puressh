//! The `ssh-agent` binary's command line: where it makes its socket
//! (`-A user:` / `shared:`), what it prints in the foreground, and its
//! stale-socket cleanup (`-u`), as OpenSSH 10.6's.

#![cfg(unix)]

use std::io::{BufRead, BufReader};
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};

const AGENT: &str = env!("CARGO_BIN_EXE_ssh-agent");

/// A short directory (socket paths are limited to ~100 bytes).
fn tempdir(name: &str) -> PathBuf {
    let d = PathBuf::from(format!("/tmp/puressh-agent-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// Start `ssh-agent -D args`, returning it and the lines it printed.
fn foreground(args: &[&str]) -> (Child, Vec<String>) {
    let mut child = Command::new(AGENT)
        .arg("-D")
        .args(args)
        .env_remove("SHELL")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap();
    let mut out = BufReader::new(child.stdout.take().unwrap());
    let mut lines = Vec::new();
    for _ in 0..2 {
        let mut l = String::new();
        out.read_line(&mut l).unwrap();
        lines.push(l.trim_end().to_string());
    }
    (child, lines)
}

/// The socket path out of `SSH_AUTH_SOCK=<path>; export SSH_AUTH_SOCK;`.
fn sock_of(line: &str) -> PathBuf {
    let rest = line.strip_prefix("SSH_AUTH_SOCK=").expect(line);
    PathBuf::from(rest.split(';').next().unwrap())
}

fn stop(mut child: Child) {
    let ok = Command::new("kill")
        .arg(child.id().to_string())
        .status()
        .unwrap();
    assert!(ok.success());
    child.wait().unwrap();
}

#[test]
fn shared_directory_socket() {
    let base = tempdir("shared");
    let spec = format!("shared:{}", base.display());
    let (child, lines) = foreground(&["-A", &spec]);
    let pid = child.id();
    // In the foreground only SSH_AUTH_SOCK is set.
    assert_eq!(lines[1], format!("echo Agent pid {pid};"));
    let sock = sock_of(&lines[0]);
    assert_eq!(sock.file_name().unwrap(), &*format!("agent.local.{pid}"));
    let dir = sock.parent().unwrap().to_path_buf();
    assert_eq!(dir.parent().unwrap(), base);
    let name = dir.file_name().unwrap().to_string_lossy().into_owned();
    assert!(name.starts_with("ssh-") && name.len() == 16, "{name}");
    let meta = std::fs::metadata(&sock).unwrap();
    assert!(meta.file_type().is_socket());
    assert_eq!(meta.permissions().mode() & 0o777, 0o600);
    assert_eq!(
        std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777,
        0o700
    );
    stop(child);
    // The socket and the directory made for it are gone.
    assert!(!dir.exists());
    let _ = std::fs::remove_dir_all(&base);
}

#[test]
fn user_directory_socket() {
    let base = tempdir("user");
    let dir = base.join("a/b");
    let spec = format!("user:{}", dir.display());
    let (child, lines) = foreground(&["-A", &spec]);
    let pid = child.id();
    let sock = sock_of(&lines[0]);
    assert_eq!(sock.parent().unwrap(), dir);
    let name = sock.file_name().unwrap().to_string_lossy().into_owned();
    // s.<host hash>.local.<pid>.<random>
    let parts: Vec<&str> = name.split('.').collect();
    assert_eq!(parts.len(), 5, "{name}");
    assert_eq!((parts[0], parts[2]), ("s", "local"));
    assert_eq!(parts[1].len(), 10);
    assert_eq!(parts[3], pid.to_string());
    assert_eq!(parts[4].len(), 10);
    assert_eq!(
        std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777,
        0o700
    );
    stop(child);
    // The socket goes; the directory stays.
    assert!(!sock.exists());
    assert!(dir.is_dir());
    let _ = std::fs::remove_dir_all(&base);
}

/// Backdate `path` by two hours (sockets cannot be opened to set it).
fn age(path: &Path) {
    let c = std::ffi::CString::new(path.as_os_str().as_encoded_bytes()).unwrap();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as libc::time_t;
    let tv = libc::timeval {
        tv_sec: now - 7200,
        tv_usec: 0,
    };
    // SAFETY: a valid C string and two timevals.
    assert_eq!(unsafe { libc::utimes(c.as_ptr(), [tv, tv].as_ptr()) }, 0);
}

#[test]
fn stale_sockets_are_cleaned() {
    let dir = tempdir("stale");
    let stale = dir.join("s.otherhost0.local.1.aaaaaaaaaa");
    drop(UnixListener::bind(&stale).unwrap());
    let live_path = dir.join("s.otherhost0.local.2.bbbbbbbbbb");
    let live = UnixListener::bind(&live_path).unwrap();
    let recent = dir.join("s.otherhost0.local.3.cccccccccc");
    drop(UnixListener::bind(&recent).unwrap());
    age(&stale);
    age(&live_path);
    let spec = format!("user:{}", dir.display());

    // One -u: only this host's sockets, and these are another host's.
    let out = Command::new(AGENT)
        .args(["-u", "-A", &spec])
        .output()
        .unwrap();
    assert!(out.status.success());
    assert_eq!(
        String::from_utf8_lossy(&out.stdout),
        "Deleted stale agent sockets in ~/user:.ssh/agent\n"
    );
    assert!(stale.exists());

    // Twice: whichever host. Only the old socket nothing listens on goes.
    let out = Command::new(AGENT)
        .args(["-uu", "-A", &spec])
        .output()
        .unwrap();
    assert!(out.status.success());
    assert!(!stale.exists());
    assert!(live_path.exists());
    assert!(recent.exists());
    drop(live);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn option_errors_match_openssh() {
    let run = |args: &[&str]| {
        let out = Command::new(AGENT).args(args).output().unwrap();
        (
            out.status.code(),
            String::from_utf8_lossy(&out.stderr).into_owned(),
        )
    };
    let (code, err) = run(&["-E", "sha1"]);
    assert_eq!(code, Some(255));
    assert_eq!(err, "Invalid hash algorithm \"sha1\"\n");
    let (code, err) = run(&["-T", "-a", "/x"]);
    assert_eq!(code, Some(1));
    assert!(err.starts_with("usage: ssh-agent"), "{err}");
    let (code, err) = run(&["-A", "nope", "-D"]);
    assert_eq!(code, Some(255));
    assert_eq!(
        err,
        "agent_listener: unsupported agent path specification nope\n\
         main: Couldn't prepare agent socket\n"
    );
    let (code, _) = run(&["-V"]);
    assert_eq!(code, Some(0));
}
