//! End-to-end SFTP round-trip tests.
//!
//! These spawn an [`SftpServerSession`] in a thread, pair it with an
//! [`SftpClient`] over a `UnixStream::pair`, and exercise each operation.

#![cfg(unix)]

use std::fs;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::thread;

use super::client::SftpClient;
use super::server::{SftpServerOptions, SftpServerSession};
use super::types::{Attrs, FxpStatus, SftpError, FXF_CREAT, FXF_READ, FXF_TRUNC, FXF_WRITE};

struct TempDir(PathBuf);

impl TempDir {
    fn new(tag: &str) -> Self {
        // pid + thread-id gives a unique directory across parallel `cargo
        // test` workers without pulling in a tempfile dep.
        let dir = std::env::temp_dir().join(format!(
            "puressh-sftp-{}-{}-{}",
            tag,
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
        ));
        fs::create_dir_all(&dir).unwrap();
        Self(dir)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn pair() -> (UnixStream, UnixStream) {
    UnixStream::pair().unwrap()
}

fn spawn_server(opts: SftpServerOptions, server_end: UnixStream) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        let mut session = SftpServerSession::new(opts);
        // Closing the client side returns Ok(()); other errors get printed
        // through the panic so they surface in the test log.
        session.run(server_end).expect("sftp server session");
    })
}

#[test]
fn version_handshake() {
    let tmp = TempDir::new("handshake");
    let (a, b) = pair();
    let h = spawn_server(SftpServerOptions::new(tmp.path()), a);
    let client = SftpClient::new(b).unwrap();
    assert!(client.server_version() >= 3);
    drop(client);
    h.join().unwrap();
}

#[test]
fn open_write_read_close() {
    let tmp = TempDir::new("rw");
    let (a, b) = pair();
    let h = spawn_server(SftpServerOptions::new(tmp.path()), a);
    let mut client = SftpClient::new(b).unwrap();

    let handle = client
        .open(
            b"hello.txt",
            FXF_WRITE | FXF_CREAT | FXF_TRUNC,
            Attrs::default(),
        )
        .unwrap();
    client.write(&handle, 0, b"hello world").unwrap();
    client.close(&handle).unwrap();

    let handle = client
        .open(b"hello.txt", FXF_READ, Attrs::default())
        .unwrap();
    let data = client.read(&handle, 0, 1024).unwrap();
    assert_eq!(data, b"hello world");
    client.close(&handle).unwrap();

    let on_disk = fs::read(tmp.path().join("hello.txt")).unwrap();
    assert_eq!(on_disk, b"hello world");

    drop(client);
    h.join().unwrap();
}

#[test]
fn stat_returns_size_and_mode() {
    let tmp = TempDir::new("stat");
    fs::write(tmp.path().join("a.txt"), b"abc").unwrap();
    let (a, b) = pair();
    let h = spawn_server(SftpServerOptions::new(tmp.path()), a);
    let mut client = SftpClient::new(b).unwrap();
    let attrs = client.stat(b"a.txt").unwrap();
    assert_eq!(attrs.size, Some(3));
    assert!(attrs.permissions.unwrap_or(0) != 0);
    drop(client);
    h.join().unwrap();
}

#[test]
fn mkdir_readdir_rmdir() {
    let tmp = TempDir::new("dir");
    let (a, b) = pair();
    let h = spawn_server(SftpServerOptions::new(tmp.path()), a);
    let mut client = SftpClient::new(b).unwrap();

    client.mkdir(b"sub", Attrs::default()).unwrap();
    let handle = client.opendir(b".").unwrap();
    let entries = client.readdir(&handle).unwrap().unwrap();
    assert!(entries.iter().any(|e| e.filename == b"sub"));

    // After exhausting entries the next readdir returns None.
    let mut saw_none = false;
    for _ in 0..16 {
        match client.readdir(&handle).unwrap() {
            None => {
                saw_none = true;
                break;
            }
            Some(_) => continue,
        }
    }
    assert!(saw_none, "expected directory iteration to end");

    client.close(&handle).unwrap();
    client.rmdir(b"sub").unwrap();
    assert!(!tmp.path().join("sub").exists());

    drop(client);
    h.join().unwrap();
}

#[test]
fn rename_and_remove() {
    let tmp = TempDir::new("rename");
    fs::write(tmp.path().join("a"), b"x").unwrap();
    let (a, b) = pair();
    let h = spawn_server(SftpServerOptions::new(tmp.path()), a);
    let mut client = SftpClient::new(b).unwrap();
    client.rename(b"a", b"b").unwrap();
    assert!(tmp.path().join("b").exists());
    client.remove(b"b").unwrap();
    assert!(!tmp.path().join("b").exists());
    drop(client);
    h.join().unwrap();
}

#[test]
fn realpath_normalises() {
    let tmp = TempDir::new("realpath");
    let (a, b) = pair();
    let h = spawn_server(SftpServerOptions::new(tmp.path()), a);
    let mut client = SftpClient::new(b).unwrap();
    let p = client.realpath(b"./foo/../bar").unwrap();
    let expected = tmp.path().join("bar").to_string_lossy().into_owned();
    assert_eq!(String::from_utf8_lossy(&p), expected);
    drop(client);
    h.join().unwrap();
}

#[test]
fn symlink_and_readlink() {
    let tmp = TempDir::new("symlink");
    fs::write(tmp.path().join("target"), b"x").unwrap();
    let (a, b) = pair();
    let h = spawn_server(SftpServerOptions::new(tmp.path()), a);
    let mut client = SftpClient::new(b).unwrap();
    client.symlink(b"target", b"linkname").unwrap();
    let tgt = client.readlink(b"linkname").unwrap();
    assert_eq!(tgt, b"target");
    drop(client);
    h.join().unwrap();
}

#[test]
fn jail_blocks_traversal_escape() {
    let tmp = TempDir::new("jail");
    let jail = tmp.path().to_path_buf();
    let (a, b) = pair();
    let opts = SftpServerOptions::new(jail.clone()).with_root(jail);
    let h = spawn_server(opts, a);
    let mut client = SftpClient::new(b).unwrap();
    let err = client
        .open(b"../../etc/passwd", FXF_READ, Attrs::default())
        .unwrap_err();
    match err {
        SftpError::Status { code, .. } => assert_eq!(code, FxpStatus::PermissionDenied),
        other => panic!("expected PermissionDenied, got {other:?}"),
    }
    drop(client);
    h.join().unwrap();
}

#[test]
fn read_only_refuses_writes() {
    let tmp = TempDir::new("readonly");
    let opts = SftpServerOptions::new(tmp.path()).read_only();
    let (a, b) = pair();
    let h = spawn_server(opts, a);
    let mut client = SftpClient::new(b).unwrap();
    let err = client
        .open(b"new.txt", FXF_WRITE | FXF_CREAT, Attrs::default())
        .unwrap_err();
    match err {
        SftpError::Status { code, .. } => assert_eq!(code, FxpStatus::PermissionDenied),
        other => panic!("expected PermissionDenied, got {other:?}"),
    }
    drop(client);
    h.join().unwrap();
}

#[test]
fn fstat_after_open() {
    let tmp = TempDir::new("fstat");
    fs::write(tmp.path().join("x"), b"hello").unwrap();
    let (a, b) = pair();
    let h = spawn_server(SftpServerOptions::new(tmp.path()), a);
    let mut client = SftpClient::new(b).unwrap();
    let handle = client.open(b"x", FXF_READ, Attrs::default()).unwrap();
    let attrs = client.fstat(&handle).unwrap();
    assert_eq!(attrs.size, Some(5));
    client.close(&handle).unwrap();
    drop(client);
    h.join().unwrap();
}

// --- security: jail-aware symlink rejection (finding #1) ---

#[test]
fn jailed_open_through_planted_symlink_rejected() {
    let tmp = TempDir::new("symjail-open");
    let jail = tmp.path().to_path_buf();
    // Plant a symlink inside the jail pointing at /etc/passwd.
    std::os::unix::fs::symlink("/etc/passwd", jail.join("escape")).unwrap();

    let (a, b) = pair();
    let opts = SftpServerOptions::new(jail.clone()).with_root(jail);
    let h = spawn_server(opts, a);
    let mut client = SftpClient::new(b).unwrap();
    let err = client
        .open(b"escape", FXF_READ, Attrs::default())
        .unwrap_err();
    match err {
        SftpError::Status { code, .. } => assert_eq!(code, FxpStatus::NoSuchFile),
        other => panic!("expected NoSuchFile, got {other:?}"),
    }
    drop(client);
    h.join().unwrap();
}

#[test]
fn jailed_setstat_through_symlink_rejected() {
    let tmp = TempDir::new("symjail-setstat");
    let jail = tmp.path().to_path_buf();
    // Outside the jail, a victim file.
    let outside = std::env::temp_dir().join(format!(
        "puressh-sftp-victim-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos(),
    ));
    fs::write(&outside, b"victim").unwrap();
    let _g = OutsideGuard(outside.clone());
    // Plant a symlink inside the jail pointing at the victim.
    std::os::unix::fs::symlink(&outside, jail.join("link")).unwrap();

    let (a, b) = pair();
    let opts = SftpServerOptions::new(jail.clone()).with_root(jail);
    let h = spawn_server(opts, a);
    let mut client = SftpClient::new(b).unwrap();
    // Try to chmod through the planted symlink.
    let attrs = Attrs {
        permissions: Some(0o000),
        ..Default::default()
    };
    let err = client.setstat(b"link", attrs).unwrap_err();
    match err {
        SftpError::Status { code, .. } => assert_eq!(code, FxpStatus::NoSuchFile),
        other => panic!("expected NoSuchFile, got {other:?}"),
    }
    // The victim should be untouched (permissions still readable).
    let md = fs::metadata(&outside).unwrap();
    use std::os::unix::fs::PermissionsExt as _;
    assert_ne!(md.permissions().mode() & 0o777, 0o000);
    drop(client);
    h.join().unwrap();
}

#[test]
fn jailed_open_relative_symlink_to_outside_rejected() {
    let tmp = TempDir::new("symjail-rel");
    let jail = tmp.path().to_path_buf();
    // Even though the lexical jail check would clamp at `/`, the relative
    // target only resolves at use time — and use time is gated by
    // O_NOFOLLOW on the final component.
    std::os::unix::fs::symlink("../../etc/passwd", jail.join("trap")).unwrap();

    let (a, b) = pair();
    let opts = SftpServerOptions::new(jail.clone()).with_root(jail);
    let h = spawn_server(opts, a);
    let mut client = SftpClient::new(b).unwrap();
    let err = client
        .open(b"trap", FXF_READ, Attrs::default())
        .unwrap_err();
    match err {
        SftpError::Status { code, .. } => assert_eq!(code, FxpStatus::NoSuchFile),
        other => panic!("expected NoSuchFile, got {other:?}"),
    }
    drop(client);
    h.join().unwrap();
}

#[test]
fn jailed_symlink_with_absolute_target_rejected() {
    let tmp = TempDir::new("symjail-abs");
    let jail = tmp.path().to_path_buf();
    let (a, b) = pair();
    let opts = SftpServerOptions::new(jail.clone()).with_root(jail);
    let h = spawn_server(opts, a);
    let mut client = SftpClient::new(b).unwrap();
    let err = client.symlink(b"/etc/passwd", b"abs-link").unwrap_err();
    match err {
        SftpError::Status { code, .. } => assert_eq!(code, FxpStatus::PermissionDenied),
        other => panic!("expected PermissionDenied, got {other:?}"),
    }
    drop(client);
    h.join().unwrap();
}

#[test]
fn jailed_realpath_strips_jail_prefix() {
    let tmp = TempDir::new("realpath-jail");
    let jail = tmp.path().to_path_buf();
    let (a, b) = pair();
    let opts = SftpServerOptions::new(jail.clone()).with_root(jail.clone());
    let h = spawn_server(opts, a);
    let mut client = SftpClient::new(b).unwrap();
    // Asking the jailed server to realpath "." should give us "/" not the
    // jail's absolute path on disk.
    let p = client.realpath(b".").unwrap();
    let s = String::from_utf8_lossy(&p);
    assert!(
        !s.contains(jail.to_string_lossy().as_ref()),
        "jail leaked in realpath: {s}"
    );
    assert_eq!(s, "/", "expected '/' inside jail, got {s}");
    let p = client.realpath(b"sub/file").unwrap();
    assert_eq!(String::from_utf8_lossy(&p), "/sub/file");
    drop(client);
    h.join().unwrap();
}

// --- security: setstat size cap (finding #4) ---

#[test]
fn setstat_set_len_above_cap_rejected() {
    let tmp = TempDir::new("setlen");
    fs::write(tmp.path().join("f"), b"x").unwrap();
    let opts = SftpServerOptions::new(tmp.path()).with_max_set_len(1024);
    let (a, b) = pair();
    let h = spawn_server(opts, a);
    let mut client = SftpClient::new(b).unwrap();
    let attrs = Attrs {
        size: Some(8 * 1024), // above the 1 KiB cap
        ..Default::default()
    };
    let err = client.setstat(b"f", attrs).unwrap_err();
    match err {
        SftpError::Status { code, .. } => assert_eq!(code, FxpStatus::PermissionDenied),
        other => panic!("expected PermissionDenied, got {other:?}"),
    }
    // File is unchanged.
    assert_eq!(fs::read(tmp.path().join("f")).unwrap(), b"x");
    drop(client);
    h.join().unwrap();
}

// --- security: setuid/setgid/sticky stripping (finding #9) ---

#[test]
fn open_strips_setuid_bit_by_default() {
    use std::os::unix::fs::PermissionsExt as _;
    let tmp = TempDir::new("setuid");
    let (a, b) = pair();
    let h = spawn_server(SftpServerOptions::new(tmp.path()), a);
    let mut client = SftpClient::new(b).unwrap();
    let attrs = Attrs {
        // 04755: setuid + rwxr-xr-x
        permissions: Some(0o4755),
        ..Default::default()
    };
    let handle = client
        .open(b"suid.bin", FXF_WRITE | FXF_CREAT, attrs)
        .unwrap();
    client.close(&handle).unwrap();
    let md = fs::metadata(tmp.path().join("suid.bin")).unwrap();
    assert_eq!(
        md.permissions().mode() & 0o7777,
        0o0755,
        "setuid should be stripped by default"
    );
    drop(client);
    h.join().unwrap();
}

#[test]
fn setstat_strips_special_bits_by_default() {
    use std::os::unix::fs::PermissionsExt as _;
    let tmp = TempDir::new("setstat-special");
    fs::write(tmp.path().join("f"), b"x").unwrap();
    fs::set_permissions(tmp.path().join("f"), fs::Permissions::from_mode(0o644)).unwrap();
    let (a, b) = pair();
    let h = spawn_server(SftpServerOptions::new(tmp.path()), a);
    let mut client = SftpClient::new(b).unwrap();
    let attrs = Attrs {
        permissions: Some(0o6755), // setuid + setgid
        ..Default::default()
    };
    client.setstat(b"f", attrs).unwrap();
    let md = fs::metadata(tmp.path().join("f")).unwrap();
    assert_eq!(md.permissions().mode() & 0o7777, 0o0755);
    drop(client);
    h.join().unwrap();
}

struct OutsideGuard(PathBuf);
impl Drop for OutsideGuard {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

#[test]
fn large_file_round_trip() {
    let tmp = TempDir::new("large");
    let (a, b) = pair();
    let h = spawn_server(SftpServerOptions::new(tmp.path()), a);
    let mut client = SftpClient::new(b).unwrap();

    let handle = client
        .open(b"big", FXF_WRITE | FXF_CREAT | FXF_TRUNC, Attrs::default())
        .unwrap();
    let chunk = vec![0xab_u8; 32 * 1024];
    let total_chunks = 4_u64;
    for i in 0..total_chunks {
        client
            .write(&handle, i * chunk.len() as u64, &chunk)
            .unwrap();
    }
    client.close(&handle).unwrap();

    let handle = client.open(b"big", FXF_READ, Attrs::default()).unwrap();
    let mut got = Vec::new();
    let mut offset = 0u64;
    loop {
        let buf = client.read(&handle, offset, 32 * 1024).unwrap();
        if buf.is_empty() {
            break;
        }
        offset += buf.len() as u64;
        got.extend_from_slice(&buf);
    }
    client.close(&handle).unwrap();
    assert_eq!(got.len() as u64, total_chunks * chunk.len() as u64);
    assert!(got.iter().all(|&b| b == 0xab));

    drop(client);
    h.join().unwrap();
}
