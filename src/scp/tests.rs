//! Sender↔Receiver round-trip tests over `UnixStream::pair()` — the
//! transport is full duplex and ordering-preserving, mirroring how an
//! SSH channel behaves once buffering is squared away. Each test
//! spawns the receiver on its own thread so the sender can drive
//! reads/writes from the test thread without deadlocking.

use std::io::Write as _;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::thread;

use super::{Receiver, ScpRecvOptions, ScpSendOptions, Sender};

/// Allocate a fresh temp directory rooted at $TMPDIR, with an unlikely
/// suffix so concurrent test runs don't collide. Cleaned by the test
/// `Drop` guard at the end of each test (or left in /tmp if a panic
/// short-circuits cleanup).
fn fresh_tmp(label: &str) -> PathBuf {
    use std::sync::atomic::{AtomicU32, Ordering};
    static COUNTER: AtomicU32 = AtomicU32::new(0);
    let n = COUNTER.fetch_add(1, Ordering::SeqCst);
    let pid = std::process::id();
    let dir = std::env::temp_dir().join(format!("puressh-scp-test-{}-{}-{}", label, pid, n));
    std::fs::create_dir_all(&dir).expect("tmp dir");
    dir
}

struct DirGuard(PathBuf);
impl Drop for DirGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn round_trip_single_file() {
    let src_dir = fresh_tmp("send");
    let _g1 = DirGuard(src_dir.clone());
    let dst_dir = fresh_tmp("recv");
    let _g2 = DirGuard(dst_dir.clone());

    let src_path = src_dir.join("hello.txt");
    let payload = b"hello, scp world!\n";
    std::fs::write(&src_path, payload).unwrap();

    let (a, b) = UnixStream::pair().expect("socketpair");

    // Receiver thread runs `Receiver::run` until EOF.
    let dst_dir_thread = dst_dir.clone();
    let recv = thread::spawn(move || {
        let mut r = Receiver::new(
            b,
            &dst_dir_thread,
            ScpRecvOptions {
                recursive: false,
                preserve_times: false,
                target_is_file: false,
            },
        )
        .expect("recv new");
        r.run().expect("recv run");
    });

    let mut sender = Sender::new(a).expect("send new");
    sender
        .send_path(&src_path, &ScpSendOptions::default())
        .expect("send file");
    drop(sender); // closes stream — receiver thread sees EOF
    recv.join().expect("recv join");

    let got = std::fs::read(dst_dir.join("hello.txt")).expect("read dst");
    assert_eq!(got, payload);
}

#[test]
fn round_trip_directory_tree() {
    let src_dir = fresh_tmp("send-tree");
    let _g1 = DirGuard(src_dir.clone());
    let dst_dir = fresh_tmp("recv-tree");
    let _g2 = DirGuard(dst_dir.clone());

    let tree = src_dir.join("tree");
    std::fs::create_dir_all(tree.join("a/b")).unwrap();
    std::fs::write(tree.join("top.txt"), b"top").unwrap();
    std::fs::write(tree.join("a/middle.txt"), b"middle").unwrap();
    std::fs::write(tree.join("a/b/deep.txt"), b"deep").unwrap();

    let (a, b) = UnixStream::pair().expect("socketpair");

    let dst_dir_thread = dst_dir.clone();
    let recv = thread::spawn(move || {
        let mut r = Receiver::new(
            b,
            &dst_dir_thread,
            ScpRecvOptions {
                recursive: true,
                preserve_times: false,
                target_is_file: false,
            },
        )
        .expect("recv new");
        r.run().expect("recv run");
    });

    let mut sender = Sender::new(a).expect("send new");
    let opts = ScpSendOptions {
        recursive: true,
        preserve_times: false,
    };
    sender.send_path(&tree, &opts).expect("send tree");
    drop(sender);
    recv.join().expect("recv join");

    assert_eq!(std::fs::read(dst_dir.join("tree/top.txt")).unwrap(), b"top");
    assert_eq!(
        std::fs::read(dst_dir.join("tree/a/middle.txt")).unwrap(),
        b"middle"
    );
    assert_eq!(
        std::fs::read(dst_dir.join("tree/a/b/deep.txt")).unwrap(),
        b"deep"
    );
}

#[test]
fn round_trip_preserve_times() {
    let src_dir = fresh_tmp("send-t");
    let _g1 = DirGuard(src_dir.clone());
    let dst_dir = fresh_tmp("recv-t");
    let _g2 = DirGuard(dst_dir.clone());

    let src_path = src_dir.join("t.txt");
    std::fs::write(&src_path, b"hello").unwrap();

    let (a, b) = UnixStream::pair().expect("socketpair");

    let dst_dir_thread = dst_dir.clone();
    let recv = thread::spawn(move || {
        let mut r = Receiver::new(
            b,
            &dst_dir_thread,
            ScpRecvOptions {
                recursive: false,
                preserve_times: true,
                target_is_file: false,
            },
        )
        .expect("recv new");
        r.run().expect("recv run");
    });

    let mut sender = Sender::new(a).expect("send new");
    let opts = ScpSendOptions {
        recursive: false,
        preserve_times: true,
    };
    sender.send_path(&src_path, &opts).expect("send");
    drop(sender);
    recv.join().expect("recv join");

    assert_eq!(std::fs::read(dst_dir.join("t.txt")).unwrap(), b"hello");
}

#[test]
fn receiver_refuses_directory_without_recursive() {
    let src_dir = fresh_tmp("send-nor");
    let _g1 = DirGuard(src_dir.clone());
    let dst_dir = fresh_tmp("recv-nor");
    let _g2 = DirGuard(dst_dir.clone());

    let tree = src_dir.join("noR");
    std::fs::create_dir(&tree).unwrap();
    std::fs::write(tree.join("f"), b"x").unwrap();

    let (a, b) = UnixStream::pair().expect("socketpair");

    let dst_dir_thread = dst_dir.clone();
    let recv = thread::spawn(move || {
        let mut r = Receiver::new(
            b,
            &dst_dir_thread,
            ScpRecvOptions::default(), // recursive: false
        )
        .expect("recv new");
        r.run() // expected to fail
    });

    let mut sender = Sender::new(a).expect("send new");
    let opts = ScpSendOptions {
        recursive: true,
        ..Default::default()
    };
    // Sender will receive a 0x02 frame from the receiver. The error
    // surfaces somewhere in the send path; we don't care exactly when.
    let _ = sender.send_path(&tree, &opts);
    drop(sender);
    let r = recv.join().expect("recv join");
    assert!(r.is_err());
}

#[test]
fn validate_rejects_leading_dash() {
    // Direct protocol-level check — Sender::send_file would refuse a
    // path whose basename starts with '-' via write_header → validate_name.
    use super::protocol::{ScpError, validate_name};
    assert!(matches!(validate_name("-rf"), Err(ScpError::BadName(_))));
}

#[test]
fn validate_rejects_dot_name() {
    use super::protocol::{ScpError, validate_name};
    assert!(matches!(validate_name("."), Err(ScpError::BadName(_))));
}

#[test]
fn validate_rejects_dotdot_name() {
    use super::protocol::{ScpError, validate_name};
    assert!(matches!(validate_name(".."), Err(ScpError::BadName(_))));
}

#[test]
fn receiver_new_rejects_missing_base() {
    // canonicalize() on a path that doesn't exist must surface as an
    // Io error from `Receiver::new`. Use a freshly-allocated tmp name
    // we explicitly never create.
    let bogus = std::env::temp_dir().join(format!(
        "puressh-scp-test-DOES-NOT-EXIST-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let (a, _b) = UnixStream::pair().expect("socketpair");
    let r = Receiver::new(a, &bogus, ScpRecvOptions::default());
    assert!(r.is_err(), "expected Receiver::new to reject missing base");
}

#[cfg(unix)]
#[test]
fn recv_file_refuses_to_overwrite_symlink() {
    // Plant a symlink in the destination directory at the basename
    // that the sender will use. recv_file must refuse to follow it
    // rather than truncating/overwriting the link target.
    let src_dir = fresh_tmp("send-sym-f");
    let _g1 = DirGuard(src_dir.clone());
    let dst_dir = fresh_tmp("recv-sym-f");
    let _g2 = DirGuard(dst_dir.clone());
    let outside_dir = fresh_tmp("recv-sym-outside");
    let _g3 = DirGuard(outside_dir.clone());

    let outside_file = outside_dir.join("target.txt");
    std::fs::write(&outside_file, b"PRECIOUS").unwrap();
    let dst_link = dst_dir.join("hello.txt");
    std::os::unix::fs::symlink(&outside_file, &dst_link).unwrap();

    let src_file = src_dir.join("hello.txt");
    std::fs::write(&src_file, b"OVERWRITE").unwrap();

    let (a, b) = UnixStream::pair().expect("socketpair");
    let dst_dir_thread = dst_dir.clone();
    let recv = thread::spawn(move || {
        let mut r = Receiver::new(b, &dst_dir_thread, ScpRecvOptions::default()).expect("recv new");
        r.run()
    });
    let mut sender = Sender::new(a).expect("send new");
    // The sender may see an error from the fatal frame; that's fine.
    let _ = sender.send_path(&src_file, &ScpSendOptions::default());
    drop(sender);
    let r = recv.join().expect("recv join");
    assert!(r.is_err(), "receiver should refuse symlink overwrite");

    // The outside file must be untouched.
    let still = std::fs::read(&outside_file).expect("read outside");
    assert_eq!(still, b"PRECIOUS");
}

#[cfg(unix)]
#[test]
fn recv_dir_refuses_to_descend_into_symlinked_directory() {
    // Plant a symlink under the destination at the directory name the
    // sender will announce. recv_dir must refuse rather than descend
    // through the symlink and write under its (potentially outside)
    // target.
    let src_dir = fresh_tmp("send-sym-d");
    let _g1 = DirGuard(src_dir.clone());
    let dst_dir = fresh_tmp("recv-sym-d");
    let _g2 = DirGuard(dst_dir.clone());
    let outside_dir = fresh_tmp("recv-sym-d-outside");
    let _g3 = DirGuard(outside_dir.clone());

    let tree_name = "tree";
    let tree = src_dir.join(tree_name);
    std::fs::create_dir(&tree).unwrap();
    std::fs::write(tree.join("f.txt"), b"x").unwrap();

    // Plant the symlink at dst_dir/tree -> outside_dir.
    std::os::unix::fs::symlink(&outside_dir, dst_dir.join(tree_name)).unwrap();

    let (a, b) = UnixStream::pair().expect("socketpair");
    let dst_dir_thread = dst_dir.clone();
    let recv = thread::spawn(move || {
        let mut r = Receiver::new(
            b,
            &dst_dir_thread,
            ScpRecvOptions {
                recursive: true,
                preserve_times: false,
                target_is_file: false,
            },
        )
        .expect("recv new");
        r.run()
    });
    let opts = ScpSendOptions {
        recursive: true,
        preserve_times: false,
    };
    let mut sender = Sender::new(a).expect("send new");
    let _ = sender.send_path(&tree, &opts);
    drop(sender);
    let r = recv.join().expect("recv join");
    assert!(r.is_err(), "receiver should refuse symlinked dir");

    // Nothing should have landed under outside_dir.
    assert!(!outside_dir.join("f.txt").exists());
}

#[test]
fn round_trip_empty_file() {
    let src_dir = fresh_tmp("send-empty");
    let _g1 = DirGuard(src_dir.clone());
    let dst_dir = fresh_tmp("recv-empty");
    let _g2 = DirGuard(dst_dir.clone());

    let src_path = src_dir.join("empty.txt");
    std::fs::File::create(&src_path).unwrap().flush().unwrap();

    let (a, b) = UnixStream::pair().expect("socketpair");

    let dst_dir_thread = dst_dir.clone();
    let recv = thread::spawn(move || {
        let mut r = Receiver::new(b, &dst_dir_thread, ScpRecvOptions::default()).expect("recv new");
        r.run().expect("recv run");
    });

    let mut sender = Sender::new(a).expect("send new");
    sender
        .send_path(&src_path, &ScpSendOptions::default())
        .expect("send empty");
    drop(sender);
    recv.join().expect("recv join");

    let got = std::fs::read(dst_dir.join("empty.txt")).expect("read dst");
    assert_eq!(got, Vec::<u8>::new());
}
