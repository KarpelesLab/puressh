//! `UpdateHostKeys` through the real binaries, both ways: our `ssh`
//! learning an OpenSSH `sshd`'s other host keys, and OpenSSH's `ssh`
//! learning ours (`hostkeys-00@openssh.com`, proven with
//! `hostkeys-prove-00@openssh.com`). Also the `ssh-rsa` known_hosts entry
//! for an RSA host key negotiated as `rsa-sha2-512`.
//!
//! `#[ignore]` by default (needs OpenSSH's `ssh`, `sshd` and `ssh-keygen`).
//! Run with: `cargo test --test e2e_hostkeys -- --ignored`.

#![cfg(unix)]

use std::net::{TcpListener, TcpStream};
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

fn keygen(path: &Path, kind: &str) {
    let mut c = Command::new("ssh-keygen");
    c.args(["-q", "-t", kind, "-N", "", "-f"]).arg(path);
    if kind == "rsa" {
        c.args(["-b", "2048"]);
    }
    assert!(c.status().expect("ssh-keygen").success());
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

/// The key types recorded in a known_hosts file.
fn recorded_types(path: &Path) -> Vec<String> {
    let mut v: Vec<String> = std::fs::read_to_string(path)
        .unwrap_or_default()
        .lines()
        .filter_map(|l| l.split_whitespace().nth(1).map(str::to_string))
        .collect();
    v.sort();
    v
}

#[test]
#[ignore]
fn update_host_keys_both_ways() {
    let Some(sshd) = find("sshd", &["/usr/sbin", "/usr/local/sbin"]) else {
        eprintln!("e2e_hostkeys: skipping (no sshd)");
        return;
    };
    if find("ssh", &[]).is_none() || find("ssh-keygen", &[]).is_none() {
        eprintln!("e2e_hostkeys: skipping (no ssh / ssh-keygen)");
        return;
    }
    let dir = std::env::temp_dir().join(format!("puressh-hostkeys-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let p = |n: &str| dir.join(n);
    keygen(&p("hk_ed"), "ed25519");
    keygen(&p("hk_rsa"), "rsa");
    keygen(&p("user"), "ed25519");
    std::fs::copy(p("user.pub"), p("ak")).unwrap();
    let user = String::from_utf8(Command::new("id").arg("-un").output().unwrap().stdout)
        .unwrap()
        .trim()
        .to_string();
    let cfg = |port: u16, pid: &str| {
        format!(
            "Port {port}\nListenAddress 127.0.0.1\nHostKey {}\nHostKey {}\n\
             AuthorizedKeysFile {}\nStrictModes no\nUsePAM no\nPidFile {}\n",
            p("hk_ed").display(),
            p("hk_rsa").display(),
            p("ak").display(),
            p(pid).display()
        )
    };
    let (openssh_port, ours_port) = (free_port(), free_port());
    std::fs::write(p("openssh.cfg"), cfg(openssh_port, "o.pid")).unwrap();
    std::fs::write(p("ours.cfg"), cfg(ours_port, "p.pid")).unwrap();
    let spawn = |bin: &Path, cfg: &str| {
        Daemon(
            Command::new(bin)
                .args(["-D", "-f"])
                .arg(p(cfg))
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .expect("spawn sshd"),
        )
    };
    let _daemons = [
        spawn(&sshd, "openssh.cfg"),
        spawn(Path::new(env!("CARGO_BIN_EXE_sshd")), "ours.cfg"),
    ];
    wait_port(openssh_port);
    wait_port(ours_port);

    let ed_pub = std::fs::read_to_string(p("hk_ed.pub")).unwrap();
    let rsa_pub = std::fs::read_to_string(p("hk_rsa.pub")).unwrap();
    let mut failures = Vec::new();
    for (ours, port, what) in [
        (true, openssh_port, "puressh ssh -> OpenSSH sshd"),
        (false, ours_port, "OpenSSH ssh -> puressh sshd"),
    ] {
        // Known: only the ed25519 key; the RSA one is to be learned.
        let kh = p(&format!("kh-{port}"));
        std::fs::write(&kh, format!("[127.0.0.1]:{port} {ed_pub}")).unwrap();
        let bin = if ours {
            PathBuf::from(env!("CARGO_BIN_EXE_ssh"))
        } else {
            PathBuf::from("ssh")
        };
        let out = Command::new(&bin)
            .args(["-F", "/dev/null", "-p", &port.to_string(), "-i"])
            .arg(p("user"))
            .args([
                "-o",
                "BatchMode=yes",
                "-o",
                "IdentitiesOnly=yes",
                "-o",
                "IdentityAgent=none",
                "-o",
                "StrictHostKeyChecking=yes",
                "-o",
                "UpdateHostKeys=yes",
                "-o",
                "HostKeyAlgorithms=ssh-ed25519,rsa-sha2-512,rsa-sha2-256",
                "-o",
            ])
            .arg(format!("UserKnownHostsFile={}", kh.display()))
            .arg(format!("{user}@127.0.0.1"))
            .arg("true")
            .stdin(Stdio::null())
            .output()
            .expect("run ssh");
        if !out.status.success() {
            failures.push(format!(
                "{what}: ssh failed: {}",
                String::from_utf8_lossy(&out.stderr)
            ));
            continue;
        }
        let types = recorded_types(&kh);
        if types != ["ssh-ed25519", "ssh-rsa"] {
            failures.push(format!("{what}: known_hosts has {types:?}"));
        }
        // The learned entry is the RSA key, recorded as `ssh-rsa`, and it
        // verifies a connection that negotiates RSA.
        let rsa_b64 = rsa_pub.split_whitespace().nth(1).unwrap();
        if !std::fs::read_to_string(&kh).unwrap().contains(rsa_b64) {
            failures.push(format!("{what}: the RSA key was not recorded"));
        }
        let rsa_only = Command::new(&bin)
            .args(["-F", "/dev/null", "-p", &port.to_string(), "-i"])
            .arg(p("user"))
            .args([
                "-o",
                "BatchMode=yes",
                "-o",
                "IdentitiesOnly=yes",
                "-o",
                "IdentityAgent=none",
                "-o",
                "StrictHostKeyChecking=yes",
                "-o",
                "UpdateHostKeys=no",
                "-o",
                "HostKeyAlgorithms=rsa-sha2-512",
                "-o",
            ])
            .arg(format!("UserKnownHostsFile={}", kh.display()))
            .arg(format!("{user}@127.0.0.1"))
            .arg("true")
            .stdin(Stdio::null())
            .output()
            .expect("run ssh");
        if !rsa_only.status.success() {
            failures.push(format!(
                "{what}: RSA host key not accepted: {}",
                String::from_utf8_lossy(&rsa_only.stderr)
            ));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}
