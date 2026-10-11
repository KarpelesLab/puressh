//! The `scp` and `sftp` binaries end to end against the in-tree `sshd`,
//! through the in-tree `ssh` they run as transport (as OpenSSH's do).
//!
//! `#[ignore]` by default; run with
//! `cargo test --test e2e_transfer -- --ignored --test-threads=1`.
//! Needs `ssh-keygen` on PATH. `cfg(unix)`-only.

#![cfg(unix)]

use std::io::Write;
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

mod common;
use common::ChildGuard;

struct Fixture {
    dir: PathBuf,
    config: PathBuf,
    _sshd: ChildGuard,
}

fn keygen(out: &Path) {
    let ok = Command::new("ssh-keygen")
        .args(["-q", "-t", "ed25519", "-N", "", "-f"])
        .arg(out)
        .status()
        .expect("ssh-keygen")
        .success();
    assert!(ok, "ssh-keygen failed");
}

fn fixture(label: &str) -> Fixture {
    let dir = common::tempdir(&format!("puressh_e2e_transfer_{label}"));
    let host_key = dir.join("host_key");
    let user_key = dir.join("user_key");
    keygen(&host_key);
    keygen(&user_key);
    let authorized = dir.join("authorized_keys");
    std::fs::copy(dir.join("user_key.pub"), &authorized).unwrap();
    let port = {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().port()
    };
    let user = std::env::var("USER").expect("$USER");
    let sshd = ChildGuard::spawn(
        Command::new(env!("CARGO_BIN_EXE_sshd"))
            .args([
                "-f",
                "/dev/null",
                "-b",
                "127.0.0.1",
                "-p",
                &port.to_string(),
            ])
            .arg("-h")
            .arg(&host_key)
            .arg("-A")
            .arg(&authorized)
            .args(["-u", &user, "--no-strict-modes"]),
    );
    let start = Instant::now();
    while TcpStream::connect(("127.0.0.1", port)).is_err() {
        assert!(
            start.elapsed() < Duration::from_secs(5),
            "sshd did not start"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
    let config = dir.join("ssh_config");
    std::fs::write(
        &config,
        format!(
            "Host t\n  HostName 127.0.0.1\n  Port {port}\n  IdentityFile {}\n  \
             IdentitiesOnly yes\n  UserKnownHostsFile /dev/null\n  \
             StrictHostKeyChecking no\n  LogLevel ERROR\n",
            user_key.display()
        ),
    )
    .unwrap();
    Fixture {
        dir,
        config,
        _sshd: sshd,
    }
}

fn run(prog: &str, args: &[&str], stdin: &[u8]) -> Output {
    let mut child = Command::new(prog)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn");
    child.stdin.take().unwrap().write_all(stdin).unwrap();
    child.wait_with_output().unwrap()
}

fn assert_ok(out: &Output, what: &str) {
    assert!(
        out.status.success(),
        "{what} failed:\n{}\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}

fn make_tree(root: &Path) {
    std::fs::create_dir_all(root.join("sub")).unwrap();
    std::fs::write(root.join("a.txt"), b"alpha\n").unwrap();
    let big: Vec<u8> = (0..300_001u32).map(|i| (i * 31 + i / 7) as u8).collect();
    std::fs::write(root.join("big.bin"), big).unwrap();
    std::fs::write(root.join("sub/c.txt"), b"gamma\n").unwrap();
}

fn same_tree(a: &Path, b: &Path) {
    for rel in ["a.txt", "big.bin", "sub/c.txt"] {
        assert_eq!(
            std::fs::read(a.join(rel)).unwrap(),
            std::fs::read(b.join(rel)).unwrap(),
            "{rel}"
        );
    }
}

#[test]
#[ignore]
fn scp_sftp_and_legacy_modes() {
    let f = fixture("scp");
    let cfg = f.config.display().to_string();
    let src = f.dir.join("src");
    make_tree(&src);
    let remote = f.dir.join("remote");
    std::fs::create_dir(&remote).unwrap();
    let scp = env!("CARGO_BIN_EXE_scp");
    let r = |p: &str| format!("t:{}/{p}", remote.display());

    // Upload and download a tree, keeping times (-p).
    let out = run(
        scp,
        &["-F", &cfg, "-rp", &src.display().to_string(), &r("tree")],
        b"",
    );
    assert_ok(&out, "scp -rp upload");
    same_tree(&src, &remote.join("tree"));
    // SFTP carries whole seconds.
    let mt = |p: &Path| {
        std::fs::metadata(p)
            .unwrap()
            .modified()
            .unwrap()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    };
    assert_eq!(mt(&src.join("a.txt")), mt(&remote.join("tree/a.txt")));

    let back = f.dir.join("back");
    let out = run(
        scp,
        &["-F", &cfg, "-r", &r("tree"), &back.display().to_string()],
        b"",
    );
    assert_ok(&out, "scp -r download");
    same_tree(&src, &back);

    // A remote glob, into a directory.
    let globbed = f.dir.join("globbed");
    std::fs::create_dir(&globbed).unwrap();
    let out = run(
        scp,
        &["-F", &cfg, &r("tree/*.txt"), &globbed.display().to_string()],
        b"",
    );
    assert_ok(&out, "scp remote glob");
    assert!(globbed.join("a.txt").is_file());
    assert!(!globbed.join("big.bin").exists());

    // Legacy protocol both ways.
    let out = run(
        scp,
        &[
            "-O",
            "-F",
            &cfg,
            "-r",
            &src.display().to_string(),
            &r("legacy"),
        ],
        b"",
    );
    assert_ok(&out, "scp -O upload");
    same_tree(&src, &remote.join("legacy"));

    // Remote to remote, through this host.
    let out = run(scp, &["-F", &cfg, &r("tree/big.bin"), &r("copy.bin")], b"");
    assert_ok(&out, "scp remote to remote");
    assert_eq!(
        std::fs::read(src.join("big.bin")).unwrap(),
        std::fs::read(remote.join("copy.bin")).unwrap()
    );

    // Failures are reported with status 1.
    let out = run(
        scp,
        &["-F", &cfg, &r("missing"), &f.dir.display().to_string()],
        b"",
    );
    assert_eq!(out.status.code(), Some(1));
}

#[test]
#[ignore]
fn sftp_batch_mode() {
    let f = fixture("sftp");
    let cfg = f.config.display().to_string();
    let src = f.dir.join("src");
    make_tree(&src);
    let remote = f.dir.join("remote");
    std::fs::create_dir(&remote).unwrap();
    let local = f.dir.join("local");
    std::fs::create_dir(&local).unwrap();
    let sftp = env!("CARGO_BIN_EXE_sftp");
    let batch = format!(
        "cd {r}\nput -r {s} tree\nmkdir made\nrename tree/a.txt tree/renamed.txt\n\
         ls -1 tree\nlcd {l}\nget -r tree\n-rm nothing-here\nchmod 600 tree/renamed.txt\n\
         symlink renamed.txt tree/link\nbye\n",
        r = remote.display(),
        s = src.display(),
        l = local.display()
    );
    let out = run(sftp, &["-F", &cfg, "-b", "-", "t"], batch.as_bytes());
    assert_ok(&out, "sftp batch");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("sftp> put -r"), "{stdout}");
    assert!(stdout.contains("renamed.txt"), "{stdout}");
    assert!(remote.join("made").is_dir());
    assert_eq!(
        std::fs::read(local.join("tree/renamed.txt")).unwrap(),
        b"alpha\n"
    );
    assert_eq!(
        std::fs::read(local.join("tree/big.bin")).unwrap(),
        std::fs::read(src.join("big.bin")).unwrap()
    );
    assert_eq!(
        std::fs::read_link(remote.join("tree/link")).unwrap(),
        PathBuf::from("renamed.txt")
    );

    // The first failing command aborts a batch with status 1.
    let out = run(
        sftp,
        &["-F", &cfg, "-b", "-", "t"],
        format!("cd {}\nrm nothing-here\nmkdir never\n", remote.display()).as_bytes(),
    );
    assert_eq!(out.status.code(), Some(1));
    assert!(!remote.join("never").exists());

    // `host:file` fetches the file and exits.
    let fetched = f.dir.join("fetched");
    std::fs::create_dir(&fetched).unwrap();
    let out = Command::new(sftp)
        .args(["-q", "-F", &cfg])
        .arg(format!("t:{}/made/../tree/renamed.txt", remote.display()))
        .current_dir(&fetched)
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert_ok(&out, "sftp host:file");
    assert!(fetched.join("renamed.txt").is_file());
}
