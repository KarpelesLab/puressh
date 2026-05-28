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
