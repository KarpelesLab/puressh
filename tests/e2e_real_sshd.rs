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

use std::io::Read;
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
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

mod common;

/// Owns a spawned `sshd` plus the thread that drains its stderr.
///
/// `sshd` runs under `-e` with `LogLevel DEBUG*`, so it emits a steady stream
/// of diagnostics on stderr. That pipe must never be left un-drained: the
/// 64 KiB kernel buffer fills partway through a re-key-heavy test, `sshd`
/// blocks in `write(2)`, stops servicing the connection, and the client sees
/// the session die. The failure looks exactly like a protocol bug in our
/// re-key handling, but it is the harness starving the server. How much a
/// given test logs depends on the OpenSSH build, so the same code passes on
/// one sshd version and hangs on the next.
///
/// The reader thread keeps the pipe empty and accumulates the log, so a
/// failing test can print what the server actually said.
struct SshdGuard {
    child: Child,
    log: Arc<Mutex<Vec<u8>>>,
    drain: Option<JoinHandle<()>>,
}

impl SshdGuard {
    /// Spawns `sshd -D -e -f <config>` with its stderr drained into `log`.
    fn spawn(sshd: &Path, config: &Path) -> Self {
        let mut child = Command::new(sshd)
            .args(["-D", "-e", "-f"])
            .arg(config)
            .stderr(Stdio::piped())
            .stdout(Stdio::null())
            .stdin(Stdio::null())
            .spawn()
            .expect("spawn sshd");

        let mut stderr = child.stderr.take().expect("sshd stderr is piped");
        let log = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&log);
        let drain = std::thread::spawn(move || {
            let mut buf = [0u8; 8192];
            loop {
                match stderr.read(&mut buf) {
                    Ok(0) | Err(_) => return,
                    Ok(n) => sink
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .extend_from_slice(&buf[..n]),
                }
            }
        });

        Self {
            child,
            log,
            drain: Some(drain),
        }
    }
}

impl Drop for SshdGuard {
    fn drop(&mut self) {
        // Only worth printing when the test is already going down; on a green
        // run this is several hundred lines of noise per test.
        if std::thread::panicking() {
            let log = self.log.lock().unwrap_or_else(|e| e.into_inner());
            eprintln!(
                "---- sshd log ----\n{}---- end sshd log ----",
                String::from_utf8_lossy(&log)
            );
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
        // Killing the child closes the pipe, which ends the reader thread.
        if let Some(h) = self.drain.take() {
            let _ = h.join();
        }
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
    let _guard = SshdGuard::spawn(&sshd, &config);

    wait_for_tcp(port, Duration::from_secs(5));

    let mut client = Client::connect(
        ("127.0.0.1", port),
        Config {
            host_key_policy: HostKeyPolicy::AcceptAny,
            timeout: Some(Duration::from_secs(10)),
            algorithms: Default::default(),
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

/// Compression interop against a real sshd: request `zlib@openssh.com`
/// (`Config.algorithms.compression = Some(true)`) against an sshd configured
/// with `Compression yes`, confirm the negotiation actually lands on
/// `zlib@openssh.com` in both directions, then pump a large, highly
/// compressible payload through `exec` and assert it round-trips byte-exact.
///
/// This is the end-to-end guard for our client-side zlib **decompressor**:
/// the ~600 KB of server→client stdout is delivered compressed (delayed zlib
/// starts right after `USERAUTH_SUCCESS`), so a broken inflate would either
/// desync the transport or corrupt the bytes. `#[ignore]` — needs a real
/// sshd; run with `-- --ignored`.
#[test]
#[ignore]
fn compression_zlib_interop_against_real_sshd() {
    use puressh::client::AlgoOverrides;

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

    // `Compression yes` makes sshd offer `zlib@openssh.com` (the only zlib
    // variant modern OpenSSH supports) alongside `none`.
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
         Compression yes\n\
         LogLevel DEBUG1\n",
        host_key = host_key.display(),
        authorized = authorized.display(),
        pid = tmp.join("sshd.pid").display(),
        port = port,
        user = user,
    );
    std::fs::write(&config, cfg_body).expect("write sshd_config");

    let sshd = which("sshd").unwrap_or_else(|| PathBuf::from("/usr/sbin/sshd"));
    let _guard = SshdGuard::spawn(&sshd, &config);

    wait_for_tcp(port, Duration::from_secs(5));

    let mut client = Client::connect(
        ("127.0.0.1", port),
        Config {
            host_key_policy: HostKeyPolicy::AcceptAny,
            timeout: Some(Duration::from_secs(10)),
            algorithms: AlgoOverrides {
                compression: Some(true),
                ..Default::default()
            },
        },
    )
    .expect("connect");

    let pem = std::fs::read_to_string(&client_key).expect("client key pem");
    let pk = PrivateKey::parse_openssh_pem(&pem, None).expect("parse client key");
    let hk = pk.into_host_key().expect("into_host_key");
    client
        .authenticate(&user, vec![ClientCredential::PublicKey(hk)])
        .expect("auth");

    // The negotiation must have selected zlib in BOTH directions; a silent
    // fallback to `none` would make the payload assertion below pass without
    // ever exercising the codec, so pin it explicitly.
    let (c2s, s2c) = client
        .negotiated_compression()
        .expect("compression negotiated after handshake");
    assert_eq!(c2s, "zlib@openssh.com", "client->server compression");
    assert_eq!(s2c, "zlib@openssh.com", "server->client compression");

    // ~620 KB of highly compressible, deterministic output. `yes STRING`
    // repeats the line; `head -n N` bounds it (and SIGPIPEs `yes`, whose
    // status the pipeline discards — `head` exits 0).
    const LINE: &str = "the-quick-brown-fox-0123456789";
    const LINES: usize = 20_000;
    let out = client
        .exec(&format!("yes {LINE} | head -n {LINES}"))
        .expect("exec");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.exit_status, Some(0), "stderr was: {stderr}");

    let expected: String = std::iter::repeat_n(LINE, LINES)
        .flat_map(|l| [l, "\n"])
        .collect();
    assert_eq!(
        out.stdout.len(),
        expected.len(),
        "compressed stdout length mismatch (stderr: {stderr})"
    );
    assert!(
        out.stdout == expected.as_bytes(),
        "compressed stdout did not round-trip byte-exact"
    );
}

/// Interactive (pty) session against a real sshd while exercising the
/// `ping@openssh.com` chaff path that `ObscureKeystrokeTiming` relies on:
/// open a real shell channel, interleave transport PINGs (chaff) with
/// keystroke data, and confirm the shell still echoes our command. A real
/// OpenSSH server answers each PING with a PONG (dropped by our read loop);
/// if PING/PONG framing were wrong the session would desynchronise.
#[test]
#[ignore]
fn interactive_shell_with_keystroke_chaff_against_real_sshd() {
    use puressh::shared::SharedClient;

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
         PubkeyAuthentication yes\n\
         PermitRootLogin no\n\
         AllowUsers {user}\n\
         LogLevel DEBUG1\n",
        host_key = host_key.display(),
        authorized = authorized.display(),
        pid = tmp.join("sshd.pid").display(),
        port = port,
        user = user,
    );
    std::fs::write(&config, cfg_body).expect("write sshd_config");

    let sshd = which("sshd").unwrap_or_else(|| PathBuf::from("/usr/sbin/sshd"));
    let _guard = SshdGuard::spawn(&sshd, &config);

    wait_for_tcp(port, Duration::from_secs(5));

    let mut client = Client::connect(
        ("127.0.0.1", port),
        Config {
            host_key_policy: HostKeyPolicy::AcceptAny,
            timeout: Some(Duration::from_secs(10)),
            algorithms: Default::default(),
        },
    )
    .expect("connect");

    let pem = std::fs::read_to_string(&client_key).expect("client key pem");
    let pk = PrivateKey::parse_openssh_pem(&pem, None).expect("parse client key");
    let hk = pk.into_host_key().expect("into_host_key");
    client
        .authenticate(&user, vec![ClientCredential::PublicKey(hk)])
        .expect("auth");

    let shared: SharedClient = client.into();
    shared
        .set_read_timeout(Some(Duration::from_millis(50)))
        .expect("set timeout");

    // Open a pty shell.
    let mut stream = shared
        .shell_stream("xterm", 80, 24, 0, 0, Vec::new())
        .expect("shell_stream");
    let ch = stream.channel_id();

    // Simulate the obfuscator cadence: a few chaff PINGs, then real
    // keystrokes (a command + newline), then more chaff.
    for _ in 0..3 {
        shared.send_ping(b"").expect("chaff ping");
    }
    shared
        .channel_send_data(ch, b"echo chaff-ok\n")
        .expect("send keystrokes");
    for _ in 0..3 {
        shared.send_ping(b"timing").expect("chaff ping");
    }

    // Read the shell output until we see our marker (with a deadline).
    use std::io::Read as _;
    let mut acc = Vec::new();
    let mut buf = [0u8; 4096];
    let start = Instant::now();
    while start.elapsed() < Duration::from_secs(10) {
        match stream.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                acc.extend_from_slice(&buf[..n]);
                if String::from_utf8_lossy(&acc).contains("chaff-ok") {
                    break;
                }
            }
            Err(_) => {}
        }
    }
    let out = String::from_utf8_lossy(&acc);
    assert!(out.contains("chaff-ok"), "shell output was: {out:?}");
}

/// Server-initiated re-key interop against a real sshd. Configures the server
/// with a tiny `RekeyLimit` so OpenSSH sends `SSH_MSG_KEXINIT` repeatedly
/// mid-stream — mechanically identical to the default 1-hour time trigger,
/// just reached in bytes instead of wall-clock. If our client mishandles a
/// server-initiated re-key the exec desyncs and this fails. `#[ignore]` —
/// needs a real sshd; run with `-- --ignored`.
#[test]
#[ignore]
fn server_initiated_rekey_against_real_sshd() {
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

    // `RekeyLimit 32K` forces the server to start a fresh KEX every 32 KiB of
    // data. Pumping ~600 KB below drives ~18 server-initiated re-keys.
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
         RekeyLimit 32K\n\
         LogLevel DEBUG1\n",
        host_key = host_key.display(),
        authorized = authorized.display(),
        pid = tmp.join("sshd.pid").display(),
        port = port,
        user = user,
    );
    std::fs::write(&config, cfg_body).expect("write sshd_config");

    let sshd = which("sshd").unwrap_or_else(|| PathBuf::from("/usr/sbin/sshd"));
    let _guard = SshdGuard::spawn(&sshd, &config);

    wait_for_tcp(port, Duration::from_secs(5));

    let mut client = Client::connect(
        ("127.0.0.1", port),
        Config {
            host_key_policy: HostKeyPolicy::AcceptAny,
            timeout: Some(Duration::from_secs(30)),
            algorithms: Default::default(),
        },
    )
    .expect("connect");

    let pem = std::fs::read_to_string(&client_key).expect("client key pem");
    let pk = PrivateKey::parse_openssh_pem(&pem, None).expect("parse client key");
    let hk = pk.into_host_key().expect("into_host_key");
    client
        .authenticate(&user, vec![ClientCredential::PublicKey(hk)])
        .expect("auth");

    // ~620 KB of deterministic output spanning many 32 KiB rekey windows.
    const LINE: &str = "the-quick-brown-fox-0123456789";
    const LINES: usize = 20_000;
    let out = client
        .exec(&format!("yes {LINE} | head -n {LINES}"))
        .expect("exec across server re-keys");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.exit_status, Some(0), "stderr was: {stderr}");

    let expected: String = std::iter::repeat_n(LINE, LINES)
        .flat_map(|l| [l, "\n"])
        .collect();
    assert_eq!(
        out.stdout.len(),
        expected.len(),
        "stdout length mismatch after server re-keys (stderr: {stderr})"
    );
    assert!(
        out.stdout == expected.as_bytes(),
        "stdout corrupted across server-initiated re-key"
    );
}

/// Client-initiated re-key interop against a real sshd. The server keeps its
/// default limits (no `RekeyLimit`), but we shrink the *client's* `RekeyPolicy`
/// to 32 KiB so our side sends `SSH_MSG_KEXINIT` repeatedly during a bulk
/// download — the exact code path a mostly-idle interactive session hits at
/// the 1-hour time threshold, only reached in bytes here. `#[ignore]` — needs
/// a real sshd; run with `-- --ignored`.
#[test]
#[ignore]
fn client_initiated_rekey_against_real_sshd() {
    use puressh::transport::RekeyPolicy;

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
         LogLevel DEBUG1\n",
        host_key = host_key.display(),
        authorized = authorized.display(),
        pid = tmp.join("sshd.pid").display(),
        port = port,
        user = user,
    );
    std::fs::write(&config, cfg_body).expect("write sshd_config");

    let sshd = which("sshd").unwrap_or_else(|| PathBuf::from("/usr/sbin/sshd"));
    let _guard = SshdGuard::spawn(&sshd, &config);

    wait_for_tcp(port, Duration::from_secs(5));

    let mut client = Client::connect(
        ("127.0.0.1", port),
        Config {
            host_key_policy: HostKeyPolicy::AcceptAny,
            timeout: Some(Duration::from_secs(30)),
            algorithms: Default::default(),
        },
    )
    .expect("connect");

    // Force our side to re-key every 32 KiB of traffic.
    client.set_rekey_policy(RekeyPolicy {
        max_bytes: 32 * 1024,
        ..RekeyPolicy::default()
    });

    let pem = std::fs::read_to_string(&client_key).expect("client key pem");
    let pk = PrivateKey::parse_openssh_pem(&pem, None).expect("parse client key");
    let hk = pk.into_host_key().expect("into_host_key");
    client
        .authenticate(&user, vec![ClientCredential::PublicKey(hk)])
        .expect("auth");

    const LINE: &str = "the-quick-brown-fox-0123456789";
    const LINES: usize = 20_000;
    let out = client
        .exec(&format!("yes {LINE} | head -n {LINES}"))
        .expect("exec across client re-keys");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.exit_status, Some(0), "stderr was: {stderr}");

    let expected: String = std::iter::repeat_n(LINE, LINES)
        .flat_map(|l| [l, "\n"])
        .collect();
    assert_eq!(
        out.stdout.len(),
        expected.len(),
        "stdout length mismatch after client re-keys (stderr: {stderr})"
    );
    assert!(
        out.stdout == expected.as_bytes(),
        "stdout corrupted across client-initiated re-key"
    );
}

/// Time-based re-key interop against a real sshd — the exact trigger a real
/// 1-hour idle session hits, compressed to seconds. The client's
/// `max_duration` is set to 2s (bytes/seq caps left huge) so re-keys fire on
/// wall-clock alone while a slow-drip command runs. `#[ignore]`.
#[test]
#[ignore]
fn time_based_rekey_against_real_sshd() {
    use puressh::transport::RekeyPolicy;

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
         LogLevel DEBUG1\n",
        host_key = host_key.display(),
        authorized = authorized.display(),
        pid = tmp.join("sshd.pid").display(),
        port = port,
        user = user,
    );
    std::fs::write(&config, cfg_body).expect("write sshd_config");

    let sshd = which("sshd").unwrap_or_else(|| PathBuf::from("/usr/sbin/sshd"));
    let _guard = SshdGuard::spawn(&sshd, &config);

    wait_for_tcp(port, Duration::from_secs(5));

    let mut client = Client::connect(
        ("127.0.0.1", port),
        Config {
            host_key_policy: HostKeyPolicy::AcceptAny,
            timeout: Some(Duration::from_secs(30)),
            algorithms: Default::default(),
        },
    )
    .expect("connect");

    // Re-key on wall-clock alone: 2s, with bytes/seq caps left at defaults.
    client.set_rekey_policy(RekeyPolicy {
        max_duration: Duration::from_secs(2),
        ..RekeyPolicy::default()
    });

    let pem = std::fs::read_to_string(&client_key).expect("client key pem");
    let pk = PrivateKey::parse_openssh_pem(&pem, None).expect("parse client key");
    let hk = pk.into_host_key().expect("into_host_key");
    client
        .authenticate(&user, vec![ClientCredential::PublicKey(hk)])
        .expect("auth");

    // ~10s of slow-drip output: a line per second across ~5 re-key windows.
    let out = client
        .exec("for i in $(seq 1 10); do echo tick-$i; sleep 1; done")
        .expect("exec across time re-keys");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.exit_status, Some(0), "stderr was: {stderr}");
    let stdout = String::from_utf8_lossy(&out.stdout);
    for i in 1..=10 {
        assert!(
            stdout.contains(&format!("tick-{i}\n")),
            "missing tick-{i}; got: {stdout:?} (stderr: {stderr})"
        );
    }
}

/// Idle-connection server re-key: server set to `RekeyLimit default 3` (time,
/// every 3s) while the client sits reading with NO data flowing — the closest
/// analog to a real idle session at the 1-hour mark. `sleep 12` produces no
/// output for 12s, so the ONLY packets crossing the wire are the server's
/// periodic KEXINIT re-keys. `#[ignore]`.
#[test]
#[ignore]
fn idle_server_time_rekey_against_real_sshd() {
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
         RekeyLimit default 3\n\
         LogLevel DEBUG1\n",
        host_key = host_key.display(),
        authorized = authorized.display(),
        pid = tmp.join("sshd.pid").display(),
        port = port,
        user = user,
    );
    std::fs::write(&config, cfg_body).expect("write sshd_config");

    let sshd = which("sshd").unwrap_or_else(|| PathBuf::from("/usr/sbin/sshd"));
    let _guard = SshdGuard::spawn(&sshd, &config);

    wait_for_tcp(port, Duration::from_secs(5));

    let mut client = Client::connect(
        ("127.0.0.1", port),
        Config {
            host_key_policy: HostKeyPolicy::AcceptAny,
            timeout: Some(Duration::from_secs(30)),
            algorithms: Default::default(),
        },
    )
    .expect("connect");

    let pem = std::fs::read_to_string(&client_key).expect("client key pem");
    let pk = PrivateKey::parse_openssh_pem(&pem, None).expect("parse client key");
    let hk = pk.into_host_key().expect("into_host_key");
    client
        .authenticate(&user, vec![ClientCredential::PublicKey(hk)])
        .expect("auth");

    // 12s of dead air: the channel carries no data, so the server's only
    // reason to touch the wire is its 3s time-based re-key. If our idle
    // re-key handling is broken this exec never returns cleanly.
    let out = client
        .exec("sleep 12; echo survived-idle-rekey")
        .expect("exec across idle server re-keys");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.exit_status, Some(0), "stderr was: {stderr}");
    assert_eq!(
        String::from_utf8_lossy(&out.stdout).trim(),
        "survived-idle-rekey",
        "stderr was: {stderr}"
    );
}

/// **Simultaneous** re-key interop — the real 1-hour scenario. Both the
/// OpenSSH server (`RekeyLimit 32K`) and our client (`max_bytes = 32 KiB`)
/// cross their thresholds at nearly the same byte offset during a bulk
/// transfer, so both fire `SSH_MSG_KEXINIT` at once and each must fold the
/// peer's KEXINIT into the exchange it already started. At the default 1-hour
/// mark both ends hit their time limit together — this is that collision,
/// reached in bytes. `#[ignore]`.
#[test]
#[ignore]
fn simultaneous_rekey_against_real_sshd() {
    use puressh::transport::RekeyPolicy;

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
         RekeyLimit 32K\n\
         LogLevel DEBUG1\n",
        host_key = host_key.display(),
        authorized = authorized.display(),
        pid = tmp.join("sshd.pid").display(),
        port = port,
        user = user,
    );
    std::fs::write(&config, cfg_body).expect("write sshd_config");

    let sshd = which("sshd").unwrap_or_else(|| PathBuf::from("/usr/sbin/sshd"));
    let _guard = SshdGuard::spawn(&sshd, &config);

    wait_for_tcp(port, Duration::from_secs(5));

    let mut client = Client::connect(
        ("127.0.0.1", port),
        Config {
            host_key_policy: HostKeyPolicy::AcceptAny,
            timeout: Some(Duration::from_secs(30)),
            algorithms: Default::default(),
        },
    )
    .expect("connect");

    // Same 32 KiB limit as the server: both sides trip at ~the same offset.
    client.set_rekey_policy(RekeyPolicy {
        max_bytes: 32 * 1024,
        ..RekeyPolicy::default()
    });

    let pem = std::fs::read_to_string(&client_key).expect("client key pem");
    let pk = PrivateKey::parse_openssh_pem(&pem, None).expect("parse client key");
    let hk = pk.into_host_key().expect("into_host_key");
    client
        .authenticate(&user, vec![ClientCredential::PublicKey(hk)])
        .expect("auth");

    const LINE: &str = "the-quick-brown-fox-0123456789";
    const LINES: usize = 20_000;
    let out = client
        .exec(&format!("yes {LINE} | head -n {LINES}"))
        .expect("exec across simultaneous re-keys");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.exit_status, Some(0), "stderr was: {stderr}");

    let expected: String = std::iter::repeat_n(LINE, LINES)
        .flat_map(|l| [l, "\n"])
        .collect();
    assert_eq!(
        out.stdout.len(),
        expected.len(),
        "stdout length mismatch after simultaneous re-keys (stderr: {stderr})"
    );
    assert!(
        out.stdout == expected.as_bytes(),
        "stdout corrupted across simultaneous re-key"
    );
}

/// AES-GCM re-key interop. GCM derives a fresh nonce/IV from the KDF on every
/// re-key (RFC 5647); if the cipher's invocation counter isn't reset on
/// install, nonces repeat and OpenSSH drops the connection on the first bad
/// tag. Pins `aes256-gcm@openssh.com` and drives simultaneous 32K re-keys.
/// `#[ignore]`.
#[test]
#[ignore]
fn gcm_rekey_against_real_sshd() {
    use puressh::client::AlgoOverrides;
    use puressh::transport::RekeyPolicy;

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
         Ciphers aes256-gcm@openssh.com\n\
         RekeyLimit 32K\n\
         LogLevel DEBUG1\n",
        host_key = host_key.display(),
        authorized = authorized.display(),
        pid = tmp.join("sshd.pid").display(),
        port = port,
        user = user,
    );
    std::fs::write(&config, cfg_body).expect("write sshd_config");

    let sshd = which("sshd").unwrap_or_else(|| PathBuf::from("/usr/sbin/sshd"));
    let _guard = SshdGuard::spawn(&sshd, &config);

    wait_for_tcp(port, Duration::from_secs(5));

    let mut client = Client::connect(
        ("127.0.0.1", port),
        Config {
            host_key_policy: HostKeyPolicy::AcceptAny,
            timeout: Some(Duration::from_secs(30)),
            algorithms: AlgoOverrides {
                ciphers: Some(vec!["aes256-gcm@openssh.com".to_string()]),
                ..Default::default()
            },
        },
    )
    .expect("connect");

    client.set_rekey_policy(RekeyPolicy {
        max_bytes: 32 * 1024,
        ..RekeyPolicy::default()
    });

    let pem = std::fs::read_to_string(&client_key).expect("client key pem");
    let pk = PrivateKey::parse_openssh_pem(&pem, None).expect("parse client key");
    let hk = pk.into_host_key().expect("into_host_key");
    client
        .authenticate(&user, vec![ClientCredential::PublicKey(hk)])
        .expect("auth");

    const LINE: &str = "the-quick-brown-fox-0123456789";
    const LINES: usize = 20_000;
    let out = client
        .exec(&format!("yes {LINE} | head -n {LINES}"))
        .expect("exec across GCM re-keys");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.exit_status, Some(0), "stderr was: {stderr}");
    let expected: String = std::iter::repeat_n(LINE, LINES)
        .flat_map(|l| [l, "\n"])
        .collect();
    assert_eq!(out.stdout.len(), expected.len(), "stderr was: {stderr}");
    assert!(out.stdout == expected.as_bytes(), "GCM stdout corrupted");
}

/// Concurrent-write re-key against a real sshd — reproduces the cterm tunnel
/// failure. A `SharedClient` runs a reader thread (which drives the pump and
/// processes the server's re-keys) and a *separate* writer thread hammering the
/// same channel, exactly like a gRPC tunnel where forwarded data flows while
/// the connection is otherwise being re-keyed. The server re-keys every 32 KiB
/// (`RekeyLimit 32K`), so with continuous concurrent writes a CHANNEL_DATA
/// packet lands inside a KEX window. Under strict-kex (default in OpenSSH
/// 9.6+/10.0) the server fatals on that out-of-sequence packet and the
/// connection dies — the "fails after ~1 hour" symptom, reached in seconds.
/// `#[ignore]`.
#[test]
#[ignore]
fn concurrent_write_during_rekey_against_real_sshd() {
    use puressh::shared::SharedClient;
    use std::io::{Read, Write};
    use std::sync::Arc;

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
         RekeyLimit 32K\n\
         LogLevel DEBUG1\n",
        host_key = host_key.display(),
        authorized = authorized.display(),
        pid = tmp.join("sshd.pid").display(),
        port = port,
        user = user,
    );
    std::fs::write(&config, cfg_body).expect("write sshd_config");

    let sshd = which("sshd").unwrap_or_else(|| PathBuf::from("/usr/sbin/sshd"));
    let _guard = SshdGuard::spawn(&sshd, &config);

    wait_for_tcp(port, Duration::from_secs(5));

    let mut client = Client::connect(
        ("127.0.0.1", port),
        Config {
            host_key_policy: HostKeyPolicy::AcceptAny,
            timeout: Some(Duration::from_secs(30)),
            algorithms: Default::default(),
        },
    )
    .expect("connect");

    let pem = std::fs::read_to_string(&client_key).expect("client key pem");
    let pk = PrivateKey::parse_openssh_pem(&pem, None).expect("parse client key");
    let hk = pk.into_host_key().expect("into_host_key");
    client
        .authenticate(&user, vec![ClientCredential::PublicKey(hk)])
        .expect("auth");

    // Both ends re-key aggressively: the server via `RekeyLimit 32K` and the
    // client via a matching byte policy. Under the mux, client re-keys are
    // initiated from the pump (reader) thread while the writer thread is mid
    // flight — the real simultaneous-collision-under-load case.
    client.set_rekey_policy(puressh::transport::RekeyPolicy {
        max_bytes: 32 * 1024,
        ..puressh::transport::RekeyPolicy::default()
    });

    let shared = SharedClient::from(client);
    shared
        .set_read_timeout(Some(Duration::from_millis(200)))
        .expect("set read timeout");

    // `cat` echoes every byte we send straight back — so the s->c echo stream
    // trips the server's 32K RekeyLimit repeatedly while we keep writing.
    let mut stream = shared.exec_stream("cat").expect("exec cat");
    let chan = stream.channel_id();

    const CHUNK: usize = 1024;
    const TOTAL: usize = 512 * 1024; // 512 KiB each way => ~16 server re-keys

    // Writer thread: a SEPARATE thread pushing CHANNEL_DATA while the reader
    // (below) drives re-keys. This concurrency is the whole point — a single
    // thread would finish each re-key before writing.
    let writer_shared = shared.clone();
    let writer = std::thread::spawn(move || -> std::io::Result<usize> {
        let buf = Arc::new([b'x'; CHUNK]);
        let mut sent = 0usize;
        while sent < TOTAL {
            match writer_shared.channel_send_data(chan, buf.as_ref()) {
                Ok(0) => std::thread::yield_now(),
                Ok(n) => sent += n,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => std::thread::yield_now(),
                Err(e) => return Err(e),
            }
        }
        let _ = writer_shared.channel_send_eof(chan);
        Ok(sent)
    });

    // Reader: drain the echoed bytes. Reads drive the pump, so this is where
    // the server's KEXINITs get processed into full re-keys.
    let mut received = 0usize;
    let mut buf = [0u8; 4096];
    let deadline = Instant::now() + Duration::from_secs(60);
    let read_result = loop {
        if received >= TOTAL {
            break Ok(());
        }
        if Instant::now() > deadline {
            break Err("timed out before echo completed".to_string());
        }
        match stream.read(&mut buf) {
            Ok(0) => break Err(format!("channel EOF after {received}/{TOTAL} bytes")),
            Ok(n) => received += n,
            Err(ref e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                std::thread::yield_now()
            }
            Err(e) => break Err(format!("read failed after {received}/{TOTAL} bytes: {e}")),
        }
    };

    let write_result = writer.join().expect("writer thread panicked");
    let _ = stream.flush();

    assert!(
        read_result.is_ok(),
        "connection died during concurrent-write re-key: {}",
        read_result.unwrap_err()
    );
    let sent = write_result.expect("writer failed — connection died mid-re-key");
    assert_eq!(sent, TOTAL, "writer did not send everything");
    assert!(received >= TOTAL, "reader got {received}, expected {TOTAL}");
}

/// Idle `SharedClient` across a server re-key — the prime suspect for the
/// cterm tunnel dying at ~1h. `SharedClient`'s pump is pull-based: the wire is
/// only serviced while some thread sits in `read`/`write`. Here we open a
/// channel and then let the connection go **fully idle** (no reads, no writes)
/// while the server time-re-keys (`RekeyLimit default 3`). If nothing pumps the
/// server's KEXINIT, the re-key never completes and the server drops us — so the
/// delayed output never arrives. `#[ignore]`.
#[test]
#[ignore]
fn idle_sharedclient_across_server_rekey() {
    use puressh::shared::SharedClient;
    use std::io::Read;

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
         RekeyLimit default 3\n\
         LogLevel DEBUG1\n",
        host_key = host_key.display(),
        authorized = authorized.display(),
        pid = tmp.join("sshd.pid").display(),
        port = port,
        user = user,
    );
    std::fs::write(&config, cfg_body).expect("write sshd_config");

    let sshd = which("sshd").unwrap_or_else(|| PathBuf::from("/usr/sbin/sshd"));
    let _guard = SshdGuard::spawn(&sshd, &config);

    wait_for_tcp(port, Duration::from_secs(5));

    let mut client = Client::connect(
        ("127.0.0.1", port),
        Config {
            host_key_policy: HostKeyPolicy::AcceptAny,
            timeout: Some(Duration::from_secs(30)),
            algorithms: Default::default(),
        },
    )
    .expect("connect");

    let pem = std::fs::read_to_string(&client_key).expect("client key pem");
    let pk = PrivateKey::parse_openssh_pem(&pem, None).expect("parse client key");
    let hk = pk.into_host_key().expect("into_host_key");
    client
        .authenticate(&user, vec![ClientCredential::PublicKey(hk)])
        .expect("auth");

    let shared = SharedClient::from(client);
    // The command stays silent for 9s, then speaks. During the silence the
    // server crosses its 3s re-key threshold ~3 times. NOTHING reads the wire
    // meanwhile — we deliberately sleep instead of reading — mimicking an idle
    // gRPC tunnel with no in-flight RPC.
    let mut stream = shared
        .exec_stream("sleep 9; echo alive-after-idle")
        .expect("exec");

    // Fully idle: no read/write on the SharedClient at all for 9s.
    std::thread::sleep(Duration::from_secs(9));

    // Now read the delayed output. If the idle re-key was missed the server
    // has already dropped us and this yields EOF / an error instead.
    shared
        .set_read_timeout(Some(Duration::from_secs(10)))
        .expect("set read timeout");
    let mut got = Vec::new();
    let mut buf = [0u8; 256];
    let deadline = Instant::now() + Duration::from_secs(15);
    let outcome = loop {
        if Instant::now() > deadline {
            break Err("timed out reading delayed output".to_string());
        }
        match stream.read(&mut buf) {
            Ok(0) => {
                break Err(format!(
                    "channel EOF; got {:?}",
                    String::from_utf8_lossy(&got)
                ));
            }
            Ok(n) => {
                got.extend_from_slice(&buf[..n]);
                if String::from_utf8_lossy(&got).contains("alive-after-idle") {
                    break Ok(());
                }
            }
            Err(ref e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut => {}
            Err(e) => break Err(format!("read failed: {e}")),
        }
    };

    assert!(
        outcome.is_ok(),
        "idle SharedClient did not survive the server's time re-key: {}",
        outcome.unwrap_err()
    );
}

/// Re-key **with zlib compression** — cterm's actual config (`compress:
/// true`). `zlib@openssh.com` is a single continuous deflate/inflate stream
/// that must survive re-keys; if the codec is reset on the rekey's NEWKEYS the
/// stream desyncs from the server and inflate corrupts. Pins compression on,
/// forces server re-keys every 32 KiB, and asserts byte-exact output. `#[ignore]`.
#[test]
#[ignore]
fn compressed_rekey_against_real_sshd() {
    use puressh::client::AlgoOverrides;

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
         Compression yes\n\
         RekeyLimit 32K\n\
         LogLevel DEBUG1\n",
        host_key = host_key.display(),
        authorized = authorized.display(),
        pid = tmp.join("sshd.pid").display(),
        port = port,
        user = user,
    );
    std::fs::write(&config, cfg_body).expect("write sshd_config");

    let sshd = which("sshd").unwrap_or_else(|| PathBuf::from("/usr/sbin/sshd"));
    let _guard = SshdGuard::spawn(&sshd, &config);

    wait_for_tcp(port, Duration::from_secs(5));

    let mut client = Client::connect(
        ("127.0.0.1", port),
        Config {
            host_key_policy: HostKeyPolicy::AcceptAny,
            timeout: Some(Duration::from_secs(30)),
            algorithms: AlgoOverrides {
                compression: Some(true),
                ..Default::default()
            },
        },
    )
    .expect("connect");

    let pem = std::fs::read_to_string(&client_key).expect("client key pem");
    let pk = PrivateKey::parse_openssh_pem(&pem, None).expect("parse client key");
    let hk = pk.into_host_key().expect("into_host_key");
    client
        .authenticate(&user, vec![ClientCredential::PublicKey(hk)])
        .expect("auth");

    let (c2s, s2c) = client
        .negotiated_compression()
        .expect("compression negotiated");
    assert_eq!(c2s, "zlib@openssh.com", "c2s compression");
    assert_eq!(s2c, "zlib@openssh.com", "s2c compression");

    // Non-repeating-ish but compressible output that spans many 32K windows.
    const LINE: &str = "the-quick-brown-fox-0123456789";
    const LINES: usize = 40_000;
    let out = client
        .exec(&format!("yes {LINE} | head -n {LINES}"))
        .expect("exec across compressed re-keys");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.exit_status, Some(0), "stderr was: {stderr}");
    let expected: String = std::iter::repeat_n(LINE, LINES)
        .flat_map(|l| [l, "\n"])
        .collect();
    assert_eq!(
        out.stdout.len(),
        expected.len(),
        "compressed+re-key stdout length mismatch (stderr: {stderr})"
    );
    assert!(
        out.stdout == expected.as_bytes(),
        "compressed stream corrupted across re-key"
    );
}

fn tempdir() -> PathBuf {
    common::tempdir("puressh_e2e")
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
