//! sshd logs what OpenSSH logs, worded as OpenSSH words it — fail2ban's sshd
//! filter, logwatch and admins' greps read these lines. Drives our `sshd -e`
//! (stderr instead of syslog) with a stock `ssh` client: an accepted key, an
//! invalid user, a user refused by DenyUsers, password failures up to
//! MaxAuthTries, and a scanner that connects and hangs up.
//!
//! `#[ignore]` by default (needs `ssh` and `ssh-keygen` on PATH). Run with:
//! `cargo test --test e2e_sshd_log -- --ignored`.

#![cfg(unix)]

use std::net::{TcpListener, TcpStream};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

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

#[test]
#[ignore]
fn auth_log_lines_match_openssh() {
    if !have("ssh") || !have("ssh-keygen") {
        eprintln!("e2e_sshd_log: skipping (ssh/ssh-keygen not on PATH)");
        return;
    }
    let dir = std::env::temp_dir().join(format!("puressh-log-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let p = |n: &str| dir.join(n);
    keygen(&p("host"));
    keygen(&p("user"));
    keygen(&p("other"));
    std::fs::copy(p("user.pub"), p("ak")).unwrap();
    let user = String::from_utf8(Command::new("id").arg("-un").output().unwrap().stdout)
        .unwrap()
        .trim()
        .to_string();
    let port = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    std::fs::write(
        p("sshd_config"),
        format!(
            "HostKey {}\nPort {port}\nListenAddress 127.0.0.1\nAuthorizedKeysFile {}\n\
             AllowUsers {user} nobody\nDenyUsers nobody\nMaxAuthTries 2\n",
            p("host").display(),
            p("ak").display()
        ),
    )
    .unwrap();
    let child = Command::new(env!("CARGO_BIN_EXE_sshd"))
        .arg("-e")
        .arg("-f")
        .arg(p("sshd_config"))
        .arg("--no-strict-modes")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(std::fs::File::create(p("log")).unwrap())
        .spawn()
        .unwrap();
    let sshd = Sshd(child);
    let start = Instant::now();
    while TcpStream::connect(("127.0.0.1", port)).is_err() {
        assert!(
            start.elapsed() < Duration::from_secs(5),
            "sshd never listened"
        );
        std::thread::sleep(Duration::from_millis(50));
    }

    std::fs::write(p("askpass"), "#!/bin/sh\necho wrong\n").unwrap();
    std::fs::set_permissions(p("askpass"), std::fs::Permissions::from_mode(0o755)).unwrap();
    let ssh_cmd = |key: &str, who: &str, extra: &[&str], cmd: &str| {
        Command::new("ssh")
            .args(["-F", "/dev/null", "-o", "StrictHostKeyChecking=no"])
            .args([
                "-o",
                "UserKnownHostsFile=/dev/null",
                "-o",
                "IdentitiesOnly=yes",
            ])
            .args(["-o", "LogLevel=ERROR", "-p", &port.to_string(), "-i"])
            .arg(p(key))
            .args(extra)
            .arg(format!("{who}@127.0.0.1"))
            .arg(cmd)
            .env("SSH_ASKPASS", p("askpass"))
            .env("SSH_ASKPASS_REQUIRE", "force")
            .stdin(Stdio::null())
            .output()
            .unwrap()
    };
    let ssh = |key: &str, who: &str, extra: &[&str]| ssh_cmd(key, who, extra, "true");
    // The session knows where it comes from, as under OpenSSH.
    let out = ssh_cmd(
        "user",
        &user,
        &["-o", "BatchMode=yes"],
        "printf '%s|%s' \"$SSH_CLIENT\" \"$SSH_CONNECTION\"",
    );
    assert!(out.status.success());
    let env = String::from_utf8_lossy(&out.stdout).into_owned();
    let (client, connection) = env.split_once('|').unwrap();
    let c: Vec<&str> = client.split(' ').collect();
    assert_eq!(
        (c[0], c[2]),
        ("127.0.0.1", port.to_string().as_str()),
        "{env}"
    );
    assert_eq!(
        connection,
        format!("127.0.0.1 {} 127.0.0.1 {port}", c[1]),
        "{env}"
    );
    ssh("user", "nosuchuser", &["-o", "BatchMode=yes"]);
    ssh("user", "nobody", &["-o", "BatchMode=yes"]);
    ssh(
        "other",
        &user,
        &[
            "-o",
            "PubkeyAuthentication=no",
            "-o",
            "PreferredAuthentications=password",
            "-o",
            "NumberOfPasswordPrompts=5",
        ],
    );
    drop(TcpStream::connect(("127.0.0.1", port)).unwrap());
    std::thread::sleep(Duration::from_millis(500));
    // SIGTERM, as systemd stops it.
    let mut sshd = sshd;
    let _ = Command::new("kill").arg(sshd.0.id().to_string()).status();
    let _ = sshd.0.wait();
    let log = std::fs::read_to_string(p("log")).unwrap();

    let fp = String::from_utf8(
        Command::new("ssh-keygen")
            .arg("-lf")
            .arg(p("user.pub"))
            .output()
            .unwrap()
            .stdout,
    )
    .unwrap();
    let fp = fp.split_whitespace().nth(1).unwrap().to_string();
    let has = |line: &str| {
        assert!(
            log.lines().any(|l| l.starts_with(line)),
            "missing {line:?} in\n{log}"
        );
    };
    has(&format!("Server listening on 127.0.0.1 port {port}."));
    has(&format!(
        "Accepted publickey for {user} from 127.0.0.1 port "
    ));
    assert!(log.contains(&format!(" ssh2: ED25519 {fp}")), "{log}");
    has(&format!("Disconnected from user {user} 127.0.0.1 port "));
    has("Invalid user nosuchuser from 127.0.0.1 port ");
    has("Failed publickey for invalid user nosuchuser from 127.0.0.1 port ");
    has("Connection closed by invalid user nosuchuser 127.0.0.1 port ");
    has("User nobody from 127.0.0.1 not allowed because listed in DenyUsers");
    has(&format!("Failed password for {user} from 127.0.0.1 port "));
    has(&format!(
        "maximum authentication attempts exceeded for {user} from 127.0.0.1 port "
    ));
    has(&format!(
        "Disconnecting authenticating user {user} 127.0.0.1 port "
    ));
    assert!(
        log.lines()
            .any(|l| l.starts_with("Connection closed by 127.0.0.1 port ")
                && l.ends_with(" [preauth]")),
        "{log}"
    );
    has("Received signal 15; terminating.");
    let _ = std::fs::remove_dir_all(&dir);
}
