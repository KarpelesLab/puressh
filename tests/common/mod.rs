//! Shared helpers for the `#[ignore]`d end-to-end interop tests.
//!
//! Lives in a subdirectory so Cargo does not treat it as its own test binary;
//! each suite pulls it in with `mod common;`.

#![allow(dead_code)] // each test binary uses a different subset

use std::io::Read;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;

/// Owns a spawned child process and the threads draining its output.
///
/// Every suite here runs an `sshd` — the system one under `-e` with
/// `LogLevel DEBUG*`, or our own in-tree binary — and both log steadily to
/// stderr. That output must never be left on an un-drained pipe: the 64 KiB
/// kernel buffer fills partway through a busy test, the server blocks in
/// `write(2)`, stops servicing the connection, and the client sees the
/// session die. The failure looks exactly like a protocol bug, but it is the
/// harness starving the server, and how much a given test logs depends on the
/// server build — so the same code passes on one version and hangs on the
/// next.
///
/// The reader threads keep the pipes empty and accumulate the output, so a
/// failing test can print what the server actually said. Without this, a
/// server that refuses to start reports only "never opened port", with the
/// reason sitting unread in a pipe.
pub struct ChildGuard {
    child: Child,
    log: Arc<Mutex<Vec<u8>>>,
    drains: Vec<JoinHandle<()>>,
}

impl ChildGuard {
    /// Spawns `cmd` with stdout and stderr drained into one interleaved log.
    /// The caller sets the program and arguments; stdio is configured here.
    pub fn spawn(cmd: &mut Command) -> Self {
        let mut child = cmd
            .stderr(Stdio::piped())
            .stdout(Stdio::piped())
            .stdin(Stdio::null())
            .spawn()
            .expect("spawn child");

        let log = Arc::new(Mutex::new(Vec::new()));
        let mut drains = Vec::new();
        if let Some(out) = child.stdout.take() {
            drains.push(drain_into(out, Arc::clone(&log)));
        }
        if let Some(err) = child.stderr.take() {
            drains.push(drain_into(err, Arc::clone(&log)));
        }

        Self { child, log, drains }
    }

    /// Everything the child has written so far.
    pub fn log(&self) -> String {
        let log = self.log.lock().unwrap_or_else(|e| e.into_inner());
        String::from_utf8_lossy(&log).into_owned()
    }
}

fn drain_into<R: Read + Send + 'static>(mut src: R, sink: Arc<Mutex<Vec<u8>>>) -> JoinHandle<()> {
    std::thread::spawn(move || {
        let mut buf = [0u8; 8192];
        loop {
            match src.read(&mut buf) {
                Ok(0) | Err(_) => return,
                Ok(n) => sink
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .extend_from_slice(&buf[..n]),
            }
        }
    })
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        // Only worth printing when the test is already going down; on a green
        // run this is several hundred lines of noise per test.
        if std::thread::panicking() {
            eprintln!(
                "---- server log ----\n{}---- end server log ----",
                self.log()
            );
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
        // Killing the child closes the pipes, which ends the reader threads.
        for h in self.drains.drain(..) {
            let _ = h.join();
        }
    }
}
