//! End-to-end interop test for puressh's SCP: spins up our own `sshd`
//! binary (which carries the in-process [`puressh::server::ExecStreamHandler`]
//! / `ScpExecHandler` glue) and drives [`puressh::client::Client::scp_send_to`]
//! / [`scp_recv_from`] against it.
//!
//! `#[ignore]` by default — run with
//! `cargo test --test e2e_scp -- --ignored`.
//!
//! The test reuses the same approach as `e2e_real_sshd.rs`: tempdir for keys,
//! free TCP port, RAII guard kills the child on the way out. We deliberately
//! point at the in-tree `sshd` (`target/debug/sshd`) rather than the system
//! one so the puressh-specific SCP path is what we actually exercise.

#![cfg(unix)]

use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use puressh::auth::ClientCredential;
use puressh::client::{Client, Config, HostKeyPolicy};
use puressh::key::PrivateKey;
use puressh::scp::{ScpRecvOptions, ScpSendOptions};

fn pick_free_port() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").expect("bind");
    let p = l.local_addr().unwrap().port();
    drop(l);
    p
}

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
            panic!("sshd never opened port {port} (see the server log above)");
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

fn tempdir(label: &str) -> PathBuf {
    let base = std::env::temp_dir().join(format!(
        "puressh_e2e_scp_{}_{}_{}",
        label,
        std::process::id(),
        Instant::now().elapsed().as_nanos()
    ));
    std::fs::create_dir_all(&base).expect("tempdir");
    base
}

mod common;
use common::ChildGuard as SshdGuard;

/// Locate the in-tree `sshd` binary that Cargo has built. Tests run with
/// the same target directory as the binaries, so `target/debug/sshd` is
/// adjacent to the test binary; we walk up from `CARGO_MANIFEST_DIR` to
/// avoid relying on the build profile name.
fn locate_sshd_binary() -> PathBuf {
    // Prefer the explicit override (CI uses this).
    if let Ok(p) = std::env::var("PURESSH_SSHD") {
        return PathBuf::from(p);
    }
    // Cargo sets CARGO_BIN_EXE_<name> when the bin is declared as a
    // [[bin]] target in Cargo.toml — that's the right way to find it.
    // The constant gets compiled in by the test runner.
    PathBuf::from(env!("CARGO_BIN_EXE_sshd"))
}

/// Build a Client authenticated against our running `sshd`. Reused by every
/// test in this file.
fn open_client(port: u16, user: &str, client_key: &Path) -> Client {
    let mut client = Client::connect(
        ("127.0.0.1", port),
        Config {
            host_key_policy: HostKeyPolicy::AcceptAny,
            timeout: Some(Duration::from_secs(10)),
            algorithms: Default::default(),
        },
    )
    .expect("connect");

    let pem = std::fs::read_to_string(client_key).expect("client key pem");
    let pk = PrivateKey::parse_openssh_pem(&pem, None).expect("parse client key");
    let hk = pk.into_host_key().expect("into_host_key");
    client
        .authenticate(user, vec![ClientCredential::PublicKey(hk)])
        .expect("auth");
    client
}

/// Set up the shared fixtures (keys, authorized_keys, sshd child, port) and
/// hand back the pieces each test needs. Returns `None` if a system
/// prerequisite is missing so the test can skip cleanly.
fn fixture() -> Option<(PathBuf, PathBuf, u16, String, SshdGuard)> {
    // The test calls ssh-keygen for key material; if it isn't on PATH there's
    // nothing to test against.
    if which("ssh-keygen").is_none() {
        eprintln!("e2e_scp: skipping (ssh-keygen not on PATH)");
        return None;
    }
    let sshd_bin = locate_sshd_binary();
    if !sshd_bin.is_file() {
        eprintln!(
            "e2e_scp: skipping (sshd binary not found at {})",
            sshd_bin.display()
        );
        return None;
    }

    let tmp = tempdir("base");
    let host_key = tmp.join("host_ed25519");
    let client_key = tmp.join("client_ed25519");
    let authorized = tmp.join("authorized_keys");
    ssh_keygen(&host_key, "ed25519");
    ssh_keygen(&client_key, "ed25519");

    let pubkey = std::fs::read(format!("{}.pub", client_key.display())).expect("client pub");
    std::fs::write(&authorized, &pubkey).expect("write authorized_keys");

    let user = current_user();
    let port = pick_free_port();

    // Spawn our own sshd. `--no-default-features` defaults to PAM enabled,
    // but the in-tree binary's PAM gate is no-op-friendly: we run without
    // root, so PAM session-open is allowed to fail and the test still works
    // for non-PAM-required paths. The connection-level priv drop is a
    // no-op when we're already the right user, which is the case here.
    // `--no-strict-modes` is required: the host key lives in a tempdir owned
    // by the (non-root) user running the tests, and our sshd otherwise
    // refuses to start with "host key ...: must be owned by root (uid 0)".
    // The OpenSSH-based suites do the same thing with `StrictModes no`.
    let guard = SshdGuard::spawn(
        Command::new(&sshd_bin)
            .args(["-p", &port.to_string()])
            .args(["-h", &host_key.display().to_string()])
            .args(["-A", &authorized.display().to_string()])
            .args(["-u", &user])
            .arg("--no-strict-modes"),
        // Default subsystems on; we don't need --no-sftp here.
    );

    wait_for_tcp(port, Duration::from_secs(5));

    Some((tmp, client_key, port, user, guard))
}

#[test]
#[ignore]
fn scp_round_trip_single_file() {
    let Some((tmp, client_key, port, user, _guard)) = fixture() else {
        return;
    };

    // Source file we'll upload.
    let src = tmp.join("upload.txt");
    let payload = b"hello-from-puressh-scp\n";
    std::fs::write(&src, payload).expect("write src");

    // Destination directory inside the tempdir.
    let dst_dir = tmp.join("recv");
    std::fs::create_dir(&dst_dir).expect("mkdir recv");
    let dst_file = dst_dir.join("upload.txt");

    // Upload.
    {
        let mut client = open_client(port, &user, &client_key);
        let opts = ScpSendOptions::default();
        client
            .scp_send_to(&[&src], &dst_dir.display().to_string(), opts)
            .expect("scp_send_to");
    }
    let got = std::fs::read(&dst_file).expect("read uploaded");
    assert_eq!(got, payload, "uploaded contents mismatch");

    // Download — fetch the same file we just uploaded into a new local
    // path, exercising the receive path.
    let local_back = tmp.join("downloaded.txt");
    {
        let mut client = open_client(port, &user, &client_key);
        let opts = ScpRecvOptions::default();
        client
            .scp_recv_from(&dst_file.display().to_string(), &local_back, opts)
            .expect("scp_recv_from");
    }
    let got = std::fs::read(&local_back).expect("read downloaded");
    assert_eq!(got, payload, "downloaded contents mismatch");
}

#[test]
#[ignore]
fn scp_round_trip_directory_tree() {
    let Some((tmp, client_key, port, user, _guard)) = fixture() else {
        return;
    };

    let src_tree = tmp.join("tree");
    std::fs::create_dir_all(src_tree.join("a/b")).unwrap();
    std::fs::write(src_tree.join("top.txt"), b"top").unwrap();
    std::fs::write(src_tree.join("a/middle.txt"), b"middle").unwrap();
    std::fs::write(src_tree.join("a/b/deep.txt"), b"deep").unwrap();

    let dst_dir = tmp.join("recv-tree");
    std::fs::create_dir(&dst_dir).expect("mkdir recv-tree");

    let mut client = open_client(port, &user, &client_key);
    let opts = ScpSendOptions {
        recursive: true,
        preserve_times: false,
    };
    client
        .scp_send_to(&[&src_tree], &dst_dir.display().to_string(), opts)
        .expect("scp_send_to recursive");

    let read = |rel: &str| {
        std::fs::read(dst_dir.join("tree").join(rel))
            .unwrap_or_else(|e| panic!("missing {}: {e}", dst_dir.join("tree").join(rel).display()))
    };
    assert_eq!(read("top.txt"), b"top");
    assert_eq!(read("a/middle.txt"), b"middle");
    assert_eq!(read("a/b/deep.txt"), b"deep");
}

fn which(name: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    for p in std::env::split_paths(&path) {
        let cand = p.join(name);
        if cand.is_file() {
            return Some(cand);
        }
    }
    None
}
