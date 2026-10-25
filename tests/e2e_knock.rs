//! End-to-end knock test with the real binaries: our `sshd` with
//! `KnockListen`, and our `ssh` connecting to a port that has
//! no TCP listener, so the connection only works through the UDP knock
//! (`docs/knock.md`).
//!
//! `#[ignore]` by default (spawns processes, needs `ssh-keygen`); run with
//! `cargo test --test e2e_knock -- --ignored`.

#![cfg(unix)]

use std::net::{TcpListener, TcpStream, UdpSocket};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{Duration, Instant};

mod common;
use common::ChildGuard;

fn ssh_keygen(out: &Path, kind: &str) {
    let status = Command::new("ssh-keygen")
        .args(["-q", "-t", kind, "-N", "", "-f"])
        .arg(out)
        .status()
        .expect("ssh-keygen");
    assert!(status.success(), "ssh-keygen failed");
}

fn current_user() -> String {
    std::env::var("USER")
        .or_else(|_| std::env::var("LOGNAME"))
        .expect("$USER")
}

/// A port free for both TCP and UDP right now.
fn pick_free_port() -> u16 {
    loop {
        let u = UdpSocket::bind("127.0.0.1:0").expect("bind udp");
        let p = u.local_addr().unwrap().port();
        if TcpListener::bind(("127.0.0.1", p)).is_ok() {
            return p;
        }
    }
}

fn wait_for_tcp(port: u16, guard: &ChildGuard) {
    let start = Instant::now();
    while TcpStream::connect(("127.0.0.1", port)).is_err() {
        if start.elapsed() > Duration::from_secs(5) {
            panic!("sshd never opened port {port}:\n{}", guard.log());
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

struct Env {
    dir: PathBuf,
    user: String,
    knock_port: u16,
}

impl Env {
    fn ssh(&self, key: &str, user: &str, strict: &str, extra: &[&str], cmd: &str) -> Output {
        Command::new(env!("CARGO_BIN_EXE_ssh"))
            .env("HOME", self.dir.join("home"))
            .env_remove("SSH_AUTH_SOCK")
            .args(["-F", "/dev/null", "-v", "-p", &self.knock_port.to_string()])
            .arg("-i")
            .arg(self.dir.join(key))
            .arg("-o")
            .arg(format!("StrictHostKeyChecking={strict}"))
            .arg("-o")
            .arg(format!(
                "UserKnownHostsFile={}",
                self.dir.join("known_hosts").display()
            ))
            .args(extra)
            .arg(format!("{user}@127.0.0.1"))
            .arg(cmd)
            .output()
            .expect("run ssh")
    }
}

#[test]
#[ignore]
fn ssh_reaches_sshd_only_through_knock() {
    let dir = common::tempdir("puressh_e2e_knock");
    std::fs::create_dir_all(dir.join("home")).unwrap();
    ssh_keygen(&dir.join("host"), "ed25519");
    ssh_keygen(&dir.join("client"), "ed25519");
    ssh_keygen(&dir.join("stranger"), "ed25519");
    std::fs::copy(dir.join("client.pub"), dir.join("authorized")).unwrap();

    let user = current_user();
    let tcp_port = pick_free_port();
    let knock_port = pick_free_port();
    std::fs::write(
        dir.join("sshd_config"),
        format!("KnockListen 127.0.0.1:{knock_port}\n"),
    )
    .unwrap();

    let guard = ChildGuard::spawn(
        Command::new(env!("CARGO_BIN_EXE_sshd"))
            .arg("-D")
            .arg("-d")
            .args(["-o", "ListenAddress=127.0.0.1"])
            .args(["-p", &tcp_port.to_string()])
            .arg("-h")
            .arg(dir.join("host"))
            .arg("-A")
            .arg(dir.join("authorized"))
            .args(["-u", &user])
            .arg("-f")
            .arg(dir.join("sshd_config"))
            .arg("--no-strict-modes"),
    );
    wait_for_tcp(tcp_port, &guard);
    let env = Env {
        dir: dir.clone(),
        user: user.clone(),
        knock_port,
    };
    let show = |o: &Output| {
        format!(
            "status {:?}\nstdout: {}\nstderr: {}\nsshd:\n{}",
            o.status,
            String::from_utf8_lossy(&o.stdout),
            String::from_utf8_lossy(&o.stderr),
            guard.log()
        )
    };

    // Unknown host: the knock fetches the host key, TOFU accepts it.
    let o = env.ssh("client", &env.user, "accept-new", &[], "echo first");
    assert!(o.status.success(), "{}", show(&o));
    assert_eq!(String::from_utf8_lossy(&o.stdout).trim(), "first");
    assert!(
        String::from_utf8_lossy(&o.stderr).contains("knock: accepted"),
        "{}",
        show(&o)
    );
    let kh = std::fs::read_to_string(dir.join("known_hosts")).unwrap();
    assert!(kh.contains(&format!("[127.0.0.1]:{knock_port}")), "{kh}");
    let home_cache = dir.join("home/.ssh/puressh");
    assert!(home_cache.join("knock_ids").is_file());
    assert!(home_cache.join("knock_hosts").is_file());

    // Known host, strict checking, cached sig1 and knock host.
    let o = env.ssh("client", &env.user, "yes", &[], "echo second");
    assert!(o.status.success(), "{}", show(&o));
    assert_eq!(String::from_utf8_lossy(&o.stdout).trim(), "second");

    // An unauthorized key gets no answer: plain TCP's refusal surfaces.
    let o = env.ssh("stranger", &env.user, "yes", &[], "echo nope");
    assert!(!o.status.success(), "{}", show(&o));
    assert!(
        String::from_utf8_lossy(&o.stderr).contains("refused"),
        "{}",
        show(&o)
    );

    // Nor is a valid key knocking for a user it is not authorized for.
    let o = env.ssh("client", "root", "yes", &[], "echo nope");
    assert!(!o.status.success(), "{}", show(&o));

    // KnockMode no: plain TCP only, refused.
    let o = env.ssh(
        "client",
        &env.user,
        "yes",
        &["-o", "KnockMode=no"],
        "echo nope",
    );
    assert!(!o.status.success(), "{}", show(&o));
    assert!(
        !String::from_utf8_lossy(&o.stderr).contains("knock: accepted"),
        "{}",
        show(&o)
    );

    drop(guard);
    let _ = std::fs::remove_dir_all(&dir);
}
