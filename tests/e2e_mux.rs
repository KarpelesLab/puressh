//! Connection sharing through our own binaries, the way Ansible and users'
//! configs drive it: `ControlMaster auto` + `ControlPersist` + a `%C`
//! ControlPath, then commands, `sftp` and `scp` (which reach the server as a
//! subsystem) and `-A` all go through, and only the first one authenticates.
//! Also checks that `%C` names the same socket as OpenSSH's.
//!
//! `#[ignore]` by default (needs `ssh-keygen` on PATH). Run with:
//! `cargo test --test e2e_mux -- --ignored`.

#![cfg(unix)]

use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};

const SSH: &str = env!("CARGO_BIN_EXE_ssh");
const SFTP: &str = env!("CARGO_BIN_EXE_sftp");
const SCP: &str = env!("CARGO_BIN_EXE_scp");

struct Sshd(Child);
impl Drop for Sshd {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn have(name: &str) -> bool {
    std::env::var_os("PATH")
        .is_some_and(|p| std::env::split_paths(&p).any(|d| d.join(name).is_file()))
}

fn keygen(path: &Path) {
    let st = Command::new("ssh-keygen")
        .args(["-q", "-t", "ed25519", "-N", "", "-f"])
        .arg(path)
        .status()
        .expect("ssh-keygen");
    assert!(st.success());
}

fn run(cmd: &mut Command) -> Output {
    cmd.stdin(Stdio::null()).output().expect("spawn")
}

#[test]
#[ignore]
fn control_master_shares_one_connection() {
    if !have("ssh-keygen") {
        eprintln!("e2e_mux: skipping (ssh-keygen not on PATH)");
        return;
    }
    // Short: the ControlPath must fit in a Unix socket address.
    let dir = PathBuf::from(format!("/tmp/pmx{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let p = |n: &str| dir.join(n);
    keygen(&p("host"));
    keygen(&p("user"));
    std::fs::copy(p("user.pub"), p("ak")).unwrap();
    let user = String::from_utf8(run(Command::new("id").arg("-un")).stdout)
        .unwrap()
        .trim()
        .to_string();

    let port = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let child = Command::new(env!("CARGO_BIN_EXE_sshd"))
        .arg("-D")
        .args([
            "-f",
            "/dev/null",
            "-o",
            "ListenAddress=127.0.0.1",
            "-p",
            &port.to_string(),
        ])
        .arg("-h")
        .arg(p("host"))
        .arg("-A")
        .arg(p("ak"))
        .args(["-u", &user, "--no-strict-modes", "-d"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(std::fs::File::create(p("sshd.log")).unwrap())
        .spawn()
        .unwrap();
    let _sshd = Sshd(child);
    let start = Instant::now();
    while TcpStream::connect(("127.0.0.1", port)).is_err() {
        assert!(
            start.elapsed() < Duration::from_secs(5),
            "sshd never listened"
        );
        std::thread::sleep(Duration::from_millis(50));
    }

    let control_path = format!("{}/%C", dir.display());
    let opts: Vec<String> = [
        "-F",
        "/dev/null",
        "-o",
        "IdentitiesOnly=yes",
        "-o",
        "StrictHostKeyChecking=no",
        "-o",
        "UserKnownHostsFile=/dev/null",
        "-o",
        "LogLevel=ERROR",
        "-o",
        "ControlMaster=auto",
        "-o",
        "ControlPersist=60",
        "-o",
        &format!("ControlPath={control_path}"),
        "-i",
    ]
    .iter()
    .map(|s| s.to_string())
    .chain([p("user").display().to_string()])
    .collect();
    let target = format!("{user}@127.0.0.1");
    let ssh = |extra: &[&str]| {
        let mut c = Command::new(SSH);
        c.args(&opts).args(["-p", &port.to_string()]).args(extra);
        c
    };
    let log = || std::fs::read_to_string(p("sshd.log")).unwrap_or_default();
    let ok = |what: &str, out: Output| {
        assert!(
            out.status.success(),
            "{what}: {}\n--- sshd log ---\n{}",
            String::from_utf8_lossy(&out.stderr),
            log()
        );
        String::from_utf8_lossy(&out.stdout).into_owned()
    };

    assert_eq!(
        ok("first", run(&mut ssh(&[&target, "echo", "one"]))),
        "one\n"
    );
    assert_eq!(
        ok("second", run(&mut ssh(&[&target, "echo", "two"]))),
        "two\n"
    );
    ok("-O check", run(&mut ssh(&["-O", "check", &target])));

    // sftp and scp reach the server as the `sftp` subsystem.
    let out = ok(
        "sftp",
        Command::new(SFTP)
            .args(&opts)
            .args(["-P", &port.to_string(), "-b", "-", &target])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .and_then(|mut c| {
                use std::io::Write;
                c.stdin.take().unwrap().write_all(b"pwd\n")?;
                c.wait_with_output()
            })
            .unwrap(),
    );
    assert!(out.contains("Remote working directory"), "{out}");
    std::fs::write(p("f"), "payload\n").unwrap();
    ok(
        "scp",
        run(Command::new(SCP)
            .args(&opts)
            .args(["-P", &port.to_string()])
            .arg(p("f"))
            .arg(format!("{target}:{}", p("g").display()))),
    );
    assert_eq!(std::fs::read_to_string(p("g")).unwrap(), "payload\n");

    let auths = log().matches("auth publickey: verified").count();
    assert_eq!(auths, 1, "every session should reuse the master\n{}", log());

    // -A needs a connection of its own; it must still work (no agent here).
    let out = run(ssh(&["-A", &target, "echo", "agent"]).env_remove("SSH_AUTH_SOCK"));
    assert_eq!(ok("-A", out), "agent\n");

    // Our %C is OpenSSH's, so either client finds the other's master.
    if have("ssh") {
        let ours = ok("-G", run(&mut ssh(&["-G", &target])));
        let theirs =
            run(Command::new("ssh")
                .args(&opts)
                .args(["-p", &port.to_string(), "-G", &target]));
        let pick = |s: &str| {
            s.lines()
                .find(|l| l.starts_with("controlpath "))
                .map(str::to_string)
        };
        assert_eq!(pick(&ours), pick(&String::from_utf8_lossy(&theirs.stdout)));
    }

    ok("-O exit", run(&mut ssh(&["-O", "exit", &target])));
    // The master must go even though its socket is removed at once (it used
    // to wait for a wake-up through that path forever): sshd then sees every
    // connection end.
    for entry in std::fs::read_dir(&dir).unwrap().flatten() {
        let name = entry.file_name();
        if name.to_string_lossy().len() == 40 {
            let _ = std::fs::remove_file(entry.path());
        }
    }
    let start = Instant::now();
    loop {
        let l = log();
        if l.matches("reaped connection").count() == l.matches("forked connection").count() {
            break;
        }
        assert!(
            start.elapsed() < Duration::from_secs(5),
            "the master did not exit after -O exit\n{l}"
        );
        std::thread::sleep(Duration::from_millis(100));
    }
    let _ = std::fs::remove_dir_all(&dir);
}
