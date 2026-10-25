//! `AuthorizedKeysCommand` / `AuthorizedPrincipalsCommand` and the
//! certificate principal rules of our `sshd`, driven by a stock OpenSSH `ssh`
//! client: keys that only the command lists log in, its `%` tokens are
//! expanded, a `TrustedUserCAKeys` certificate needs a principal the
//! principals command returns (the login name need not be one), and a
//! certificate without principals is refused.
//!
//! `#[ignore]` by default (needs `ssh` and `ssh-keygen` on PATH). Run with:
//! `cargo test --test e2e_auth_command -- --ignored`.

#![cfg(unix)]

use std::net::{TcpListener, TcpStream};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

fn pick_free_port() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").expect("bind");
    l.local_addr().unwrap().port()
}

fn run(cmd: &mut Command) -> String {
    let out = cmd.output().expect("spawn");
    assert!(
        out.status.success(),
        "{cmd:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn keygen(out: &Path) {
    run(Command::new("ssh-keygen")
        .args(["-q", "-t", "ed25519", "-N", "", "-C", "", "-f"])
        .arg(out));
}

/// Sign `key.pub` with `ca`: key id `id`, serial `serial`, `principals`
/// (none when empty).
fn certify(ca: &Path, key: &Path, id: &str, serial: &str, principals: &str) {
    let mut c = Command::new("ssh-keygen");
    c.arg("-q").arg("-s").arg(ca).args(["-I", id, "-z", serial]);
    if !principals.is_empty() {
        c.args(["-n", principals]);
    }
    run(c.arg(format!("{}.pub", key.display())));
}

fn fingerprint(key: &Path) -> String {
    let out = run(Command::new("ssh-keygen")
        .arg("-lf")
        .arg(format!("{}.pub", key.display())));
    out.split_whitespace()
        .nth(1)
        .expect("fingerprint")
        .to_string()
}

fn current_user() -> String {
    let out = run(Command::new("id").arg("-un"));
    out.trim().to_string()
}

fn have(name: &str) -> bool {
    std::env::var_os("PATH")
        .is_some_and(|p| std::env::split_paths(&p).any(|d| d.join(name).is_file()))
}

fn script(path: &Path, body: &str) {
    std::fs::write(path, format!("#!/bin/sh\n{body}")).expect("write script");
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).expect("chmod");
}

struct Sshd(Child);
impl Drop for Sshd {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn wait_for_tcp(port: u16) {
    let start = Instant::now();
    while TcpStream::connect(("127.0.0.1", port)).is_err() {
        assert!(
            start.elapsed() < Duration::from_secs(5),
            "sshd never listened"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// `ssh -i key user@127.0.0.1 echo ok`: whether it logged in.
fn login(key: &Path, port: u16, user: &str) -> bool {
    let out = Command::new("ssh")
        .args([
            "-F",
            "/dev/null",
            "-o",
            "BatchMode=yes",
            "-o",
            "IdentitiesOnly=yes",
        ])
        .args([
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "UserKnownHostsFile=/dev/null",
        ])
        .args(["-o", "LogLevel=ERROR", "-p", &port.to_string(), "-i"])
        .arg(key)
        .arg(format!("{user}@127.0.0.1"))
        .args(["echo", "ok"])
        .stdin(Stdio::null())
        .output()
        .expect("ssh");
    out.status.success() && String::from_utf8_lossy(&out.stdout).trim() == "ok"
}

#[test]
#[ignore]
fn authorized_keys_and_principals_commands() {
    if !have("ssh") || !have("ssh-keygen") {
        eprintln!("e2e_auth_command: skipping (ssh/ssh-keygen not on PATH)");
        return;
    }
    let tmp: PathBuf = std::env::temp_dir().join(format!("puressh-akc-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(&tmp).unwrap();
    let p = |n: &str| tmp.join(n);
    let user = current_user();

    for k in ["host", "listed", "unlisted", "ca", "admin", "other", "bare"] {
        keygen(&p(k));
    }
    certify(&p("ca"), &p("admin"), "admin-id", "7", "admin");
    certify(&p("ca"), &p("other"), "other-id", "8", "other");
    certify(&p("ca"), &p("bare"), "bare-id", "9", "");

    script(
        &p("keys.sh"),
        &format!(
            "echo \"keys $*\" >>{log}\ncat {key}\n",
            log = p("log").display(),
            key = p("listed.pub").display()
        ),
    );
    script(
        &p("principals.sh"),
        &format!(
            "echo \"principals $*\" >>{log}\necho '# comment'\necho admin\n",
            log = p("log").display()
        ),
    );
    std::fs::write(
        p("sshd_config"),
        format!(
            "AuthorizedKeysFile none\n\
             AuthorizedKeysCommand {keys} %u %f %t\n\
             AuthorizedKeysCommandUser {user}\n\
             TrustedUserCAKeys {ca}.pub\n\
             AuthorizedPrincipalsCommand {principals} %u %i %s %T\n\
             AuthorizedPrincipalsCommandUser {user}\n",
            keys = p("keys.sh").display(),
            principals = p("principals.sh").display(),
            ca = p("ca").display(),
        ),
    )
    .unwrap();

    let port = pick_free_port();
    let child = Command::new(env!("CARGO_BIN_EXE_sshd"))
        .arg("-D")
        .arg("-f")
        .arg(p("sshd_config"))
        .args([
            "-o",
            "ListenAddress=127.0.0.1",
            "-p",
            &port.to_string(),
            "-u",
            &user,
        ])
        .arg("-h")
        .arg(p("host"))
        .arg("--no-strict-modes")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(std::fs::File::create(p("sshd.log")).unwrap())
        .spawn()
        .expect("spawn sshd");
    let _sshd = Sshd(child);
    wait_for_tcp(port);

    let check = |what: &str, key: &str, expect: bool| {
        let ok = login(&p(key), port, &user);
        assert_eq!(
            ok,
            expect,
            "{what}\n--- command log ---\n{}\n--- sshd log ---\n{}",
            std::fs::read_to_string(p("log")).unwrap_or_default(),
            std::fs::read_to_string(p("sshd.log")).unwrap_or_default()
        );
    };
    check("a key the command lists logs in", "listed", true);
    check(
        "a key the command does not list is refused",
        "unlisted",
        false,
    );
    check(
        "a certificate for a listed principal logs in",
        "admin",
        true,
    );
    check(
        "a certificate for another principal is refused",
        "other",
        false,
    );
    check("a certificate without principals is refused", "bare", false);

    let log = std::fs::read_to_string(p("log")).unwrap();
    let keys_line = format!("keys {user} {} ssh-ed25519", fingerprint(&p("listed")));
    assert!(
        log.lines().any(|l| l == keys_line),
        "{keys_line:?} not in\n{log}"
    );
    let principals_line = format!("principals {user} admin-id 7 ssh-ed25519");
    assert!(
        log.lines().any(|l| l == principals_line),
        "{principals_line:?} not in\n{log}"
    );
    let _ = std::fs::remove_dir_all(&tmp);
}
