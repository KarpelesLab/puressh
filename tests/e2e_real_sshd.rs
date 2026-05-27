//! End-to-end interop test against the system `sshd`.
//!
//! `#[ignore]` by default; run with `cargo test --test e2e_real_sshd -- --ignored`.
//! Requires `sshd` and `ssh-keygen` on PATH and an OpenSSH host that lets us
//! `setsid sshd -D -e` from a regular user. The test:
//!
//! 1. Generates a host key and a client identity in a tempdir.
//! 2. Writes a minimal sshd_config and an authorized_keys for the running user.
//! 3. Spawns `sshd -D -e -p <free-port>` and polls for it to accept TCP.
//! 4. Drives puressh::client::Client through KEX → publickey auth →
//!    `exec("echo hello-from-puressh")` and asserts the exit status and stdout.
//! 5. Kills sshd on the way out.
//!
//! The whole module is `cfg(unix)`-only — the test relies on `sshd`,
//! `ssh-keygen`, and `setsid`, none of which are available on Windows.

#![cfg(unix)]

use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use puressh::auth::ClientCredential;
use puressh::client::{Client, Config, HostKeyPolicy};
use puressh::key::PrivateKey;

/// Find an unused TCP port by binding ephemerally and immediately releasing.
fn pick_free_port() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").expect("bind");
    let p = l.local_addr().unwrap().port();
    drop(l);
    p
}

fn ssh_keygen(out: &PathBuf, kind: &str) {
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

fn wait_for_tcp(port: u16, deadline: Duration) {
    let start = Instant::now();
    loop {
        if TcpStream::connect_timeout(
            &format!("127.0.0.1:{port}").parse().unwrap(),
            Duration::from_millis(200),
        )
        .is_ok()
        {
            return;
        }
        if start.elapsed() > deadline {
            panic!("sshd never opened port {port}");
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

struct SshdGuard {
    child: Child,
}

impl Drop for SshdGuard {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[test]
#[ignore]
fn exec_against_real_sshd() {
    let tmp = tempdir();
    let host_key = tmp.join("host_ed25519");
    let client_key = tmp.join("client_ed25519");
    let authorized = tmp.join("authorized_keys");
    let config = tmp.join("sshd_config");

    ssh_keygen(&host_key, "ed25519");
    ssh_keygen(&client_key, "ed25519");

    let pubkey = std::fs::read(format!("{}.pub", client_key.display())).expect("client pub");
    std::fs::write(&authorized, &pubkey).expect("write authorized_keys");
    chmod_600(&authorized);

    let user = current_user();
    let port = pick_free_port();

    let cfg_body = format!(
        "Port {port}\n\
         ListenAddress 127.0.0.1\n\
         HostKey {host_key}\n\
         PidFile {pid}\n\
         AuthorizedKeysFile {authorized}\n\
         StrictModes no\n\
         UsePAM no\n\
         PasswordAuthentication no\n\
         KbdInteractiveAuthentication no\n\
         ChallengeResponseAuthentication no\n\
         PubkeyAuthentication yes\n\
         PermitRootLogin no\n\
         AllowUsers {user}\n\
         Subsystem sftp /usr/lib/openssh/sftp-server\n\
         LogLevel DEBUG1\n",
        host_key = host_key.display(),
        authorized = authorized.display(),
        pid = tmp.join("sshd.pid").display(),
        port = port,
        user = user,
    );
    std::fs::write(&config, cfg_body).expect("write sshd_config");

    let sshd = which("sshd").unwrap_or_else(|| PathBuf::from("/usr/sbin/sshd"));
    let child = Command::new(&sshd)
        .args(["-D", "-e", "-f"])
        .arg(&config)
        .stderr(Stdio::piped())
        .stdout(Stdio::null())
        .stdin(Stdio::null())
        .spawn()
        .expect("spawn sshd");
    let _guard = SshdGuard { child };

    wait_for_tcp(port, Duration::from_secs(5));

    let mut client = Client::connect(
        ("127.0.0.1", port),
        Config {
            host_key_policy: HostKeyPolicy::AcceptAny,
            timeout: Some(Duration::from_secs(10)),
        },
    )
    .expect("connect");

    let pem = std::fs::read_to_string(&client_key).expect("client key pem");
    let pk = PrivateKey::parse_openssh_pem(&pem, None).expect("parse client key");
    let hk = pk.into_host_key().expect("into_host_key");

    client
        .authenticate(&user, vec![ClientCredential::PublicKey(hk)])
        .expect("auth");

    let out = client.exec("echo hello-from-puressh").expect("exec");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(stdout.trim(), "hello-from-puressh", "stderr was: {stderr}");
    assert_eq!(out.exit_status, Some(0), "stderr was: {stderr}");
}

fn tempdir() -> PathBuf {
    let base = std::env::temp_dir().join(format!(
        "puressh_e2e_{}_{}",
        std::process::id(),
        Instant::now().elapsed().as_nanos()
    ));
    std::fs::create_dir_all(&base).expect("tempdir");
    base
}

fn chmod_600(path: &PathBuf) {
    use std::os::unix::fs::PermissionsExt;
    let mut perm = std::fs::metadata(path).expect("stat").permissions();
    perm.set_mode(0o600);
    std::fs::set_permissions(path, perm).expect("chmod");
}

fn which(name: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    for p in std::env::split_paths(&path) {
        let cand = p.join(name);
        if cand.is_file() {
            return Some(cand);
        }
    }
    // Common system path that's missing from non-root $PATH on some distros.
    let fallback = PathBuf::from("/usr/sbin").join(name);
    if fallback.is_file() {
        return Some(fallback);
    }
    None
}
