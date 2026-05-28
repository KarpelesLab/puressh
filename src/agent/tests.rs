//! Integration tests for `Agent` against an in-process fake
//! `ssh-agent` that speaks the same wire protocol.

use std::io::{Read, Write};
use std::os::unix::net::UnixListener;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc, Mutex,
};
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

use super::client::Agent;
use super::host_key::AgentHostKey;
use super::protocol::{
    encode_message, IdentityEntry, SSH_AGENTC_REQUEST_IDENTITIES, SSH_AGENTC_SIGN_REQUEST,
    SSH_AGENT_FAILURE, SSH_AGENT_IDENTITIES_ANSWER, SSH_AGENT_SIGN_RESPONSE,
};
use crate::format::{Reader, Writer};
use crate::hostkey::HostKey;

struct TestTempDir {
    path: std::path::PathBuf,
}

impl TestTempDir {
    fn new(prefix: &str) -> Self {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let pid = std::process::id();
        // Use a per-counter suffix because some tests in this file
        // spin up the listener twice in quick succession.
        static N: AtomicUsize = AtomicUsize::new(0);
        let seq = N.fetch_add(1, Ordering::SeqCst);
        let path = std::env::temp_dir().join(format!("puressh-agent-{prefix}-{pid}-{nanos}-{seq}"));
        std::fs::create_dir_all(&path).expect("create tempdir");
        Self { path }
    }
    fn child(&self, name: &str) -> std::path::PathBuf {
        self.path.join(name)
    }
}

impl Drop for TestTempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

/// Spawn a fake agent on `path` that serves one connection then exits.
/// `identities` are returned for `REQUEST_IDENTITIES`; sign requests
/// produce a deterministic `b"FAKE-SIG/" || key_blob || b"/" || data`
/// blob wrapped in a fake `string algorithm || string raw_sig` shape.
fn spawn_fake_agent(
    path: &std::path::Path,
    identities: Vec<IdentityEntry>,
) -> thread::JoinHandle<()> {
    let listener = UnixListener::bind(path).expect("bind unix socket");
    let path = path.to_path_buf();
    let _ = &path; // path kept alive on this side via TestTempDir
    thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept");
        loop {
            let mut hdr = [0u8; 4];
            if stream.read_exact(&mut hdr).is_err() {
                return;
            }
            let len = u32::from_be_bytes(hdr) as usize;
            let mut frame = vec![0u8; len];
            if stream.read_exact(&mut frame).is_err() {
                return;
            }
            let (msg_type, body) = (frame[0], &frame[1..]);
            match msg_type {
                x if x == SSH_AGENTC_REQUEST_IDENTITIES => {
                    let mut w = Writer::new();
                    w.write_u32(identities.len() as u32);
                    for id in &identities {
                        w.write_string(&id.key_blob);
                        w.write_string(id.comment.as_bytes());
                    }
                    let frame = encode_message(SSH_AGENT_IDENTITIES_ANSWER, w.as_slice());
                    if stream.write_all(&frame).is_err() {
                        return;
                    }
                }
                x if x == SSH_AGENTC_SIGN_REQUEST => {
                    let mut r = Reader::new(body);
                    let key = r.read_string().unwrap().to_vec();
                    let data = r.read_string().unwrap().to_vec();
                    let _flags = r.read_u32().unwrap();
                    // Build a wire-shaped signature: `string algo ||
                    // string raw_sig`. We use whatever algo the
                    // identity's blob declares so AgentHostKey's
                    // post-sign sanity-check passes.
                    let algo = first_string_of(&key).unwrap_or_else(|| "ssh-ed25519".into());
                    let mut sigbody = Writer::new();
                    sigbody.write_string(algo.as_bytes());
                    let mut raw = Vec::new();
                    raw.extend_from_slice(b"FAKE-SIG/");
                    raw.extend_from_slice(&key);
                    raw.extend_from_slice(b"/");
                    raw.extend_from_slice(&data);
                    sigbody.write_string(&raw);

                    let mut outer = Writer::new();
                    outer.write_string(sigbody.as_slice());
                    let frame = encode_message(SSH_AGENT_SIGN_RESPONSE, outer.as_slice());
                    if stream.write_all(&frame).is_err() {
                        return;
                    }
                }
                _ => {
                    let frame = encode_message(SSH_AGENT_FAILURE, &[]);
                    if stream.write_all(&frame).is_err() {
                        return;
                    }
                }
            }
        }
    })
}

fn first_string_of(buf: &[u8]) -> Option<String> {
    if buf.len() < 4 {
        return None;
    }
    let len = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
    if buf.len() < 4 + len {
        return None;
    }
    Some(String::from_utf8_lossy(&buf[4..4 + len]).into_owned())
}

fn make_ed25519_blob(seed: &str) -> Vec<u8> {
    let mut w = Writer::new();
    w.write_string(b"ssh-ed25519");
    // 32-byte fake "pubkey" derived from seed so different identities
    // have distinct blobs.
    let mut pk = [0u8; 32];
    for (i, b) in seed.bytes().take(32).enumerate() {
        pk[i] = b;
    }
    w.write_string(&pk);
    w.into_vec()
}

#[test]
fn identities_round_trip() {
    let dir = TestTempDir::new("identities");
    let sock = dir.child("sock");
    let id1 = IdentityEntry {
        key_blob: make_ed25519_blob("alice"),
        comment: "alice@laptop".into(),
    };
    let id2 = IdentityEntry {
        key_blob: make_ed25519_blob("bob"),
        comment: "bob@desktop".into(),
    };
    let h = spawn_fake_agent(&sock, vec![id1.clone(), id2.clone()]);

    let mut agent = Agent::connect(&sock).expect("connect agent");
    let got = agent.identities().expect("identities");
    assert_eq!(got.len(), 2);
    assert_eq!(got[0].comment(), "alice@laptop");
    assert_eq!(got[0].key_blob(), id1.key_blob.as_slice());
    assert_eq!(got[0].algorithm(), "ssh-ed25519");
    assert_eq!(got[1].comment(), "bob@desktop");

    drop(agent);
    let _ = h.join();
}

#[test]
fn sign_round_trip_via_host_key() {
    let dir = TestTempDir::new("sign");
    let sock = dir.child("sock");
    let id = IdentityEntry {
        key_blob: make_ed25519_blob("alice"),
        comment: "alice@laptop".into(),
    };
    let h = spawn_fake_agent(&sock, vec![id.clone()]);

    let agent = Arc::new(Mutex::new(Agent::connect(&sock).expect("connect")));
    let key = AgentHostKey::from_identity(agent, id.key_blob.clone()).expect("AgentHostKey");
    assert_eq!(key.algorithm(), "ssh-ed25519");
    assert_eq!(key.public_blob(), id.key_blob);

    let sig = key.sign(b"hello").expect("sign");
    // The blob is `string algorithm || string raw_sig`. Decode and
    // assert the raw_sig contains our payload — that confirms the
    // request body was wired in correctly and the agent reply was
    // unwrapped from its outer `string` envelope.
    let mut r = Reader::new(&sig);
    let algo = std::str::from_utf8(r.read_string().expect("algo")).unwrap();
    let raw = r.read_string().expect("raw");
    assert_eq!(algo, "ssh-ed25519");
    let raw_s = String::from_utf8_lossy(raw);
    assert!(raw_s.contains("FAKE-SIG/"));
    assert!(raw_s.ends_with("/hello"));

    // Drop `key` so the inner Arc<Mutex<Agent>> goes to zero and the
    // UnixStream is closed; the fake agent's read_exact then returns
    // an error and the server thread exits.
    drop(key);
    let _ = h.join();
}

#[test]
fn connect_env_returns_none_when_unset() {
    // Make sure no SSH_AUTH_SOCK leaks in from the test environment.
    let saved = std::env::var_os("SSH_AUTH_SOCK");
    // SAFETY: tests in this binary do not race on env vars — we
    // mutate around our single call and restore at the end.
    std::env::remove_var("SSH_AUTH_SOCK");
    let r = Agent::connect_env().expect("connect_env");
    assert!(r.is_none());
    if let Some(v) = saved {
        std::env::set_var("SSH_AUTH_SOCK", v);
    }
}
