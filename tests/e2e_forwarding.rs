//! Port and Unix-socket forwarding through the real binaries, both ways:
//! our `ssh` against OpenSSH's `sshd`, OpenSSH's `ssh` against our `sshd`,
//! and ours against ours. Every forward kind (`-L` and `-R`, TCP ports and
//! Unix sockets at either end, `-R port` as a SOCKS proxy) must carry a
//! half-closed exchange — the client sends, shuts down its writing side,
//! then reads the reply — as OpenSSH's do. Also `ssh -f -M -N -L …`, which
//! returns only once the forward listens, and `-O exit` ending it.
//!
//! `#[ignore]` by default (needs OpenSSH's `ssh`, `sshd` and `ssh-keygen`).
//! Run with: `cargo test --test e2e_forwarding -- --ignored`.

#![cfg(unix)]

use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

struct Daemon(Child);
impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn find(name: &str, extra: &[&str]) -> Option<PathBuf> {
    std::env::var_os("PATH")
        .into_iter()
        .flat_map(|p| std::env::split_paths(&p).collect::<Vec<_>>())
        .chain(extra.iter().map(PathBuf::from))
        .map(|d| d.join(name))
        .find(|p| p.is_file())
}

fn keygen(path: &Path) {
    let st = Command::new("ssh-keygen")
        .args(["-q", "-t", "ed25519", "-N", "", "-f"])
        .arg(path)
        .status()
        .expect("ssh-keygen");
    assert!(st.success());
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn wait_port(port: u16) {
    let start = Instant::now();
    while TcpStream::connect(("127.0.0.1", port)).is_err() {
        assert!(
            start.elapsed() < Duration::from_secs(10),
            "no daemon on {port}"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// Answer each connection, once its sender has shut down writing, with
/// `echo:` and everything it sent.
fn echo<S: Read + Write>(mut c: S) {
    let mut got = Vec::new();
    let _ = c.read_to_end(&mut got);
    let _ = c.write_all(&[b"echo:".as_slice(), &got].concat());
}

fn spawn_tcp_echo() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for c in l.incoming().flatten() {
            std::thread::spawn(move || echo(c));
        }
    });
    port
}

fn spawn_unix_echo(path: &Path) {
    let l = UnixListener::bind(path).unwrap();
    std::thread::spawn(move || {
        for c in l.incoming().flatten() {
            std::thread::spawn(move || echo(c));
        }
    });
}

/// Where a test connects: a TCP port or a Unix socket.
#[derive(Clone, Debug)]
enum End {
    Port(u16),
    Path(PathBuf),
}

/// Connect (retrying while the forward comes up), send, half-close, read.
fn exchange(end: &End, socks: Option<u16>) -> Result<String, String> {
    let start = Instant::now();
    loop {
        let attempt = match end {
            End::Port(p) => TcpStream::connect(("127.0.0.1", *p)).and_then(|mut s| {
                s.set_read_timeout(Some(Duration::from_secs(10)))?;
                if let Some(target) = socks {
                    socks5_connect(&mut s, target)?;
                }
                talk(&mut s, |s| s.shutdown(Shutdown::Write))
            }),
            End::Path(p) => UnixStream::connect(p).and_then(|mut s| {
                s.set_read_timeout(Some(Duration::from_secs(10)))?;
                talk(&mut s, |s| s.shutdown(Shutdown::Write))
            }),
        };
        match attempt {
            Ok(reply) => return Ok(reply),
            Err(e) if start.elapsed() > Duration::from_secs(10) => {
                return Err(format!("{end:?}: {e}"));
            }
            Err(_) => std::thread::sleep(Duration::from_millis(100)),
        }
    }
}

fn talk<S: Read + Write>(
    s: &mut S,
    half_close: impl Fn(&S) -> std::io::Result<()>,
) -> std::io::Result<String> {
    s.write_all(b"hi")?;
    half_close(s)?;
    let mut got = Vec::new();
    s.read_to_end(&mut got)?;
    if got.is_empty() {
        return Err(std::io::Error::other("no reply"));
    }
    Ok(String::from_utf8_lossy(&got).into_owned())
}

/// A SOCKS5 CONNECT to `127.0.0.1:port`.
fn socks5_connect(s: &mut TcpStream, port: u16) -> std::io::Result<()> {
    s.write_all(&[5, 1, 0])?;
    let mut r = [0u8; 2];
    s.read_exact(&mut r)?;
    if r != [5, 0] {
        return Err(std::io::Error::other(format!("socks method {r:?}")));
    }
    let p = port.to_be_bytes();
    s.write_all(&[5, 1, 0, 1, 127, 0, 0, 1, p[0], p[1]])?;
    let mut reply = [0u8; 10];
    s.read_exact(&mut reply)?;
    if reply[1] != 0 {
        return Err(std::io::Error::other(format!("socks reply {}", reply[1])));
    }
    Ok(())
}

struct Setup {
    dir: PathBuf,
    user: String,
    openssh_port: u16,
    ours_port: u16,
    _daemons: Vec<Daemon>,
}

impl Setup {
    fn client(&self, ours: bool, port: u16) -> Command {
        let mut c = Command::new(if ours {
            PathBuf::from(env!("CARGO_BIN_EXE_ssh"))
        } else {
            PathBuf::from("ssh")
        });
        c.args(["-F", "/dev/null", "-p", &port.to_string(), "-i"])
            .arg(self.dir.join("user"))
            .args([
                "-q",
                "-o",
                "IdentitiesOnly=yes",
                "-o",
                "BatchMode=yes",
                "-o",
                "StrictHostKeyChecking=no",
                "-o",
                "UserKnownHostsFile=/dev/null",
                "-o",
                "IdentityAgent=none",
                "-o",
                "ExitOnForwardFailure=yes",
            ]);
        c
    }
}

fn setup(tag: &str) -> Option<Setup> {
    let sshd = find("sshd", &["/usr/sbin", "/usr/local/sbin"])?;
    find("ssh", &[])?;
    find("ssh-keygen", &[])?;
    // Short: Unix socket paths are limited to ~100 bytes.
    let dir = PathBuf::from(format!("/tmp/pfw-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let p = |n: &str| dir.join(n);
    keygen(&p("host"));
    keygen(&p("user"));
    std::fs::copy(p("user.pub"), p("ak")).unwrap();
    let user = String::from_utf8(Command::new("id").arg("-un").output().unwrap().stdout)
        .unwrap()
        .trim()
        .to_string();
    let base = |port: u16, pid: &str| {
        format!(
            "Port {port}\nListenAddress 127.0.0.1\nHostKey {}\nAuthorizedKeysFile {}\n\
             StrictModes no\nUsePAM no\nPidFile {}\nLogLevel INFO\n",
            p("host").display(),
            p("ak").display(),
            p(pid).display()
        )
    };
    let (openssh_port, ours_port) = (free_port(), free_port());
    std::fs::write(p("openssh.cfg"), base(openssh_port, "o.pid")).unwrap();
    std::fs::write(p("ours.cfg"), base(ours_port, "p.pid")).unwrap();
    let spawn = |bin: &Path, cfg: &str, log: &str| {
        Daemon(
            Command::new(bin)
                .args(["-D", "-f"])
                .arg(p(cfg))
                .arg("-E")
                .arg(p(log))
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .expect("spawn sshd"),
        )
    };
    let daemons = vec![
        spawn(&sshd, "openssh.cfg", "openssh.log"),
        spawn(
            Path::new(env!("CARGO_BIN_EXE_sshd")),
            "ours.cfg",
            "ours.log",
        ),
    ];
    wait_port(openssh_port);
    wait_port(ours_port);
    Some(Setup {
        dir,
        user,
        openssh_port,
        ours_port,
        _daemons: daemons,
    })
}

#[test]
#[ignore]
fn every_forward_kind_carries_a_half_closed_exchange() {
    let Some(s) = setup("hc") else {
        eprintln!("e2e_forwarding: skipping (OpenSSH ssh/sshd/ssh-keygen not found)");
        return;
    };
    let tcp_echo = spawn_tcp_echo();
    let unix_echo = s.dir.join("echo.sock");
    spawn_unix_echo(&unix_echo);
    let mut failures = Vec::new();
    for (n, (ours, port, what)) in [
        (true, s.openssh_port, "puressh ssh -> OpenSSH sshd"),
        (false, s.ours_port, "OpenSSH ssh -> puressh sshd"),
        (true, s.ours_port, "puressh ssh -> puressh sshd"),
    ]
    .into_iter()
    .enumerate()
    {
        let sock = |name: &str| s.dir.join(format!("{name}{n}.sock"));
        let (l_tcp, l_tcp_unix, r_tcp, r_socks) =
            (free_port(), free_port(), free_port(), free_port());
        let e = unix_echo.display();
        let specs = [
            ("-L", format!("{l_tcp}:127.0.0.1:{tcp_echo}")),
            ("-L", format!("{}:{e}", sock("lu").display())),
            ("-L", format!("{l_tcp_unix}:{e}")),
            ("-R", format!("{r_tcp}:127.0.0.1:{tcp_echo}")),
            ("-R", format!("{}:{e}", sock("ru").display())),
            ("-R", format!("{r_socks}")),
        ];
        let mut c = s.client(ours, port);
        c.arg("-N");
        for (flag, spec) in &specs {
            c.args([*flag, spec.as_str()]);
        }
        let child = Daemon(
            c.arg(format!("{}@127.0.0.1", s.user))
                .stdin(Stdio::null())
                .spawn()
                .expect("spawn ssh"),
        );
        for (end, socks, label) in [
            (End::Port(l_tcp), None, "-L port:host:port"),
            (End::Path(sock("lu")), None, "-L path:path"),
            (End::Port(l_tcp_unix), None, "-L port:path"),
            (End::Port(r_tcp), None, "-R port:host:port"),
            (End::Path(sock("ru")), None, "-R path:path"),
            (End::Port(r_socks), Some(tcp_echo), "-R port (SOCKS)"),
        ] {
            match exchange(&end, socks) {
                Ok(reply) if reply == "echo:hi" => {}
                Ok(reply) => failures.push(format!("{what}: {label}: got {reply:?}")),
                Err(e) => failures.push(format!("{what}: {label}: {e}")),
            }
        }
        drop(child);
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
#[ignore]
fn fork_returns_with_the_forward_up_and_exit_ends_it() {
    let Some(s) = setup("fk") else {
        eprintln!("e2e_forwarding: skipping (OpenSSH ssh/sshd/ssh-keygen not found)");
        return;
    };
    let tcp_echo = spawn_tcp_echo();
    let l = free_port();
    let ctl = s.dir.join("ctl");
    let st = s
        .client(true, s.openssh_port)
        .args(["-f", "-N", "-M", "-S"])
        .arg(&ctl)
        .args(["-L", &format!("{l}:127.0.0.1:{tcp_echo}")])
        .arg(format!("{}@127.0.0.1", s.user))
        .stdin(Stdio::null())
        .status()
        .expect("ssh -f");
    assert!(st.success(), "ssh -f failed: {st}");
    // No waiting: `-f` returned only once the forward listened.
    let mut c = TcpStream::connect(("127.0.0.1", l)).expect("forward not up when -f returned");
    c.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    assert_eq!(
        talk(&mut c, |c| c.shutdown(Shutdown::Write)).unwrap(),
        "echo:hi"
    );
    // `-O check` answers; `-O exit` ends the master and its forward.
    let check = s
        .client(true, s.openssh_port)
        .args(["-O", "check", "-S"])
        .arg(&ctl)
        .arg("x")
        .output()
        .unwrap();
    assert!(check.status.success(), "{check:?}");
    let exit = s
        .client(true, s.openssh_port)
        .args(["-O", "exit", "-S"])
        .arg(&ctl)
        .arg("x")
        .output()
        .unwrap();
    assert!(exit.status.success(), "{exit:?}");
    let start = Instant::now();
    while ctl.exists() || TcpStream::connect(("127.0.0.1", l)).is_ok() {
        assert!(
            start.elapsed() < Duration::from_secs(10),
            "the master outlived -O exit"
        );
        std::thread::sleep(Duration::from_millis(100));
    }
}

#[test]
#[ignore]
fn control_persist_master_serves_its_forwards() {
    let Some(s) = setup("cp") else {
        eprintln!("e2e_forwarding: skipping (OpenSSH ssh/sshd/ssh-keygen not found)");
        return;
    };
    let tcp_echo = spawn_tcp_echo();
    let l = free_port();
    let ctl = s.dir.join("ctl");
    // `-N` with ControlPersist: ssh returns at once, the daemonized master
    // keeps the connection and serves the forward.
    let st = s
        .client(true, s.openssh_port)
        .args(["-N", "-M", "-o", "ControlPersist=yes", "-S"])
        .arg(&ctl)
        .args(["-L", &format!("{l}:127.0.0.1:{tcp_echo}")])
        .arg(format!("{}@127.0.0.1", s.user))
        .stdin(Stdio::null())
        .status()
        .expect("ssh");
    assert!(st.success(), "ssh -N -M ControlPersist failed: {st}");
    let reply = exchange(&End::Port(l), None);
    let exit = s
        .client(true, s.openssh_port)
        .args(["-O", "exit", "-S"])
        .arg(&ctl)
        .arg("x")
        .output()
        .unwrap();
    assert_eq!(reply.as_deref(), Ok("echo:hi"));
    assert!(exit.status.success(), "{exit:?}");
}
