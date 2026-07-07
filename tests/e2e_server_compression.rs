//! Server-side compression interop: a **real OpenSSH `ssh` client** with
//! compression enabled (`-C`) against our own `sshd` binary configured with
//! `Compression yes`. This is the mirror of the client-side test in
//! `e2e_real_sshd.rs` — here puressh is the server that must advertise
//! `zlib@openssh.com`, activate it after auth, and compress a large stdout
//! stream that a stock `ssh` then inflates.
//!
//! `#[ignore]` by default (needs a real `ssh` + `ssh-keygen` on PATH and the
//! in-tree `sshd` binary). Run with:
//! `cargo test --test e2e_server_compression -- --ignored`.

#![cfg(unix)]

use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

fn pick_free_port() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").expect("bind");
    let p = l.local_addr().unwrap().port();
    drop(l);
    p
}

fn ssh_keygen(out: &Path) {
    let status = Command::new("ssh-keygen")
        .args(["-q", "-t", "ed25519", "-N", "", "-f"])
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

fn which(name: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|d| d.join(name))
        .find(|p| p.is_file())
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

fn tempdir() -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let p = std::env::temp_dir().join(format!("puressh-srvcomp-{}-{nanos}", std::process::id()));
    std::fs::create_dir_all(&p).expect("mkdir tempdir");
    p
}

/// Spawn our in-tree `sshd` with `Compression yes` and return a guard + port.
/// Returns `None` if the prerequisites (our `sshd` binary, `ssh`, `ssh-keygen`)
/// are missing so the test can skip cleanly.
fn spawn_our_sshd(tmp: &Path) -> Option<(u16, String, PathBuf, SshdGuard)> {
    if which("ssh").is_none() || which("ssh-keygen").is_none() {
        eprintln!("e2e_server_compression: skipping (ssh/ssh-keygen not on PATH)");
        return None;
    }
    let sshd_bin = PathBuf::from(env!("CARGO_BIN_EXE_sshd"));
    if !sshd_bin.is_file() {
        eprintln!("e2e_server_compression: skipping (sshd binary not built)");
        return None;
    }

    let host_key = tmp.join("host_ed25519");
    let client_key = tmp.join("client_ed25519");
    let authorized = tmp.join("authorized_keys");
    let config = tmp.join("sshd_config");
    ssh_keygen(&host_key);
    ssh_keygen(&client_key);
    let pubkey = std::fs::read(format!("{}.pub", client_key.display())).expect("client pub");
    std::fs::write(&authorized, &pubkey).expect("write authorized_keys");

    // `Compression yes` makes our server advertise zlib ahead of `none`.
    std::fs::write(&config, "Compression yes\n").expect("write sshd_config");

    let user = current_user();
    let port = pick_free_port();
    let child = Command::new(&sshd_bin)
        .args(["-f", &config.display().to_string()])
        .args(["-p", &port.to_string()])
        .args(["-h", &host_key.display().to_string()])
        .args(["-A", &authorized.display().to_string()])
        .args(["-u", &user])
        // Test keys live in a user-owned tempdir, not root-owned; relax the
        // ownership/permission checks that would otherwise refuse them.
        .arg("--no-strict-modes")
        .stderr(Stdio::null())
        .stdout(Stdio::null())
        .stdin(Stdio::null())
        .spawn()
        .expect("spawn sshd");
    let guard = SshdGuard { child };
    wait_for_tcp(port, Duration::from_secs(5));
    Some((port, user, client_key, guard))
}

/// Base args for the stock `ssh` client: our key, no host-key prompts, and
/// `-C` to request compression.
fn ssh_base(client_key: &Path, port: u16, user: &str) -> Command {
    let mut c = Command::new("ssh");
    c.arg("-C")
        .args(["-i", &client_key.display().to_string()])
        .args(["-o", "StrictHostKeyChecking=no"])
        .args(["-o", "UserKnownHostsFile=/dev/null"])
        .args(["-o", "IdentitiesOnly=yes"])
        .args(["-p", &port.to_string()])
        .arg(format!("{user}@127.0.0.1"));
    c
}

#[test]
#[ignore]
fn server_compresses_large_stdout_for_real_ssh_client() {
    let tmp = tempdir();
    let Some((port, user, client_key, _guard)) = spawn_our_sshd(&tmp) else {
        return;
    };

    // First: prove compression was actually negotiated as `zlib@openssh.com`
    // (a silent fallback to `none` would make the payload check below pass
    // without ever exercising the server's compressor). `ssh -vv` prints the
    // per-direction choice.
    let verbose = {
        let mut c = ssh_base(&client_key, port, &user);
        c.arg("-vv").arg("true");
        c.output().expect("ssh -vv")
    };
    let vstderr = String::from_utf8_lossy(&verbose.stderr);
    assert!(
        vstderr.contains("compression: zlib@openssh.com"),
        "expected zlib@openssh.com to be negotiated; ssh -vv said:\n{vstderr}"
    );

    // ~620 KB of deterministic, highly compressible stdout produced *on the
    // server* and streamed back to the stock client, which inflates it.
    const LINE: &str = "the-quick-brown-fox-0123456789";
    const LINES: usize = 20_000;
    let out = {
        let mut c = ssh_base(&client_key, port, &user);
        c.arg(format!("yes {LINE} | head -n {LINES}"));
        c.output().expect("ssh exec")
    };
    assert!(
        out.status.success(),
        "ssh exec failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let expected: String = std::iter::repeat_n(LINE, LINES)
        .flat_map(|l| [l, "\n"])
        .collect();
    assert_eq!(
        out.stdout.len(),
        expected.len(),
        "server-compressed stdout length mismatch"
    );
    assert!(
        out.stdout == expected.as_bytes(),
        "server-compressed stdout did not round-trip byte-exact"
    );

    let _ = std::fs::remove_dir_all(&tmp);
}
