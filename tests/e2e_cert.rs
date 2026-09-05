//! End-to-end certificate interop tests against the system OpenSSH `sshd`,
//! using `ssh-keygen -s` to mint certificates.
//!
//! `#[ignore]` by default; run with `cargo test --test e2e_cert -- --ignored`.
//! Requires `sshd` + `ssh-keygen` on PATH and the ability to `sshd -D -e` as a
//! regular user. `cfg(unix)`-only.
//!
//! Two directions, both exercising wire-compatibility with OpenSSH:
//!
//! - **User cert**: puressh's `Client` presents a CA-signed *user* certificate;
//!   real `sshd` (configured with `TrustedUserCAKeys`) authorizes it. Confirms
//!   our cert blob, the `*-cert-v01@openssh.com` userauth method, and the
//!   embedded-key signature are all byte-compatible with OpenSSH.
//! - **Host cert**: real `sshd` presents a CA-signed *host* certificate;
//!   puressh's `Client` verifies it via a known_hosts `@cert-authority` line.

#![cfg(unix)]

use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use puressh::auth::ClientCredential;
use puressh::cert::Certificate;
use puressh::client::{Client, Config, HostKeyPolicy, KnownHostsPolicy, TofuAction};
use puressh::hostkey::CertHostKey;
use puressh::key::PrivateKey;
use puressh::known_hosts::KnownHosts;

fn pick_free_port() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").expect("bind");
    let p = l.local_addr().unwrap().port();
    drop(l);
    p
}

fn run(cmd: &mut Command) {
    let status = cmd.status().expect("spawn");
    assert!(status.success(), "command failed: {cmd:?}");
}

fn ssh_keygen_key(out: &Path, kind: &str) {
    run(Command::new("ssh-keygen")
        .args(["-q", "-t", kind, "-N", ""])
        .arg("-f")
        .arg(out));
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
use common::ChildGuard as SshdGuard;

fn tempdir() -> PathBuf {
    let base = std::env::temp_dir().join(format!(
        "puressh_e2e_cert_{}_{}",
        std::process::id(),
        Instant::now().elapsed().as_nanos()
    ));
    std::fs::create_dir_all(&base).expect("tempdir");
    base
}

fn chmod_600(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let mut perm = std::fs::metadata(path).expect("stat").permissions();
    perm.set_mode(0o600);
    std::fs::set_permissions(path, perm).expect("chmod");
}

fn which(name: &str) -> PathBuf {
    if let Some(path) = std::env::var_os("PATH") {
        for p in std::env::split_paths(&path) {
            let c = p.join(name);
            if c.is_file() {
                return c;
            }
        }
    }
    let fallback = PathBuf::from("/usr/sbin").join(name);
    if fallback.is_file() {
        return fallback;
    }
    PathBuf::from(name)
}

fn spawn_sshd(config: &Path) -> SshdGuard {
    let sshd = which("sshd");
    SshdGuard::spawn(Command::new(&sshd).args(["-D", "-e", "-f"]).arg(config))
}

/// puressh client presents a CA-signed USER cert to real sshd.
#[test]
#[ignore]
fn user_cert_against_real_sshd() {
    let tmp = tempdir();
    let host_key = tmp.join("host_ed25519");
    let user_ca = tmp.join("user_ca");
    let client_key = tmp.join("client_ed25519");
    let trusted_cas = tmp.join("trusted_user_ca");
    let config = tmp.join("sshd_config");

    ssh_keygen_key(&host_key, "ed25519");
    ssh_keygen_key(&user_ca, "ed25519");
    ssh_keygen_key(&client_key, "ed25519");

    // Trust the user CA.
    let ca_pub = std::fs::read(format!("{}.pub", user_ca.display())).unwrap();
    std::fs::write(&trusted_cas, &ca_pub).unwrap();
    chmod_600(&trusted_cas);

    let user = current_user();
    // Mint a user cert for the login user as a principal.
    run(Command::new("ssh-keygen").args([
        "-s",
        &user_ca.display().to_string(),
        "-I",
        "e2e-user",
        "-n",
        &user,
        "-V",
        "+52w",
        &format!("{}.pub", client_key.display()),
    ]));

    let port = pick_free_port();
    let cfg_body = format!(
        "Port {port}\nListenAddress 127.0.0.1\nHostKey {host}\nPidFile {pid}\n\
         TrustedUserCAKeys {cas}\nStrictModes no\nUsePAM no\n\
         PasswordAuthentication no\nKbdInteractiveAuthentication no\n\
         PubkeyAuthentication yes\nPermitRootLogin no\nAllowUsers {user}\nLogLevel DEBUG1\n",
        host = host_key.display(),
        pid = tmp.join("sshd.pid").display(),
        cas = trusted_cas.display(),
    );
    std::fs::write(&config, cfg_body).unwrap();

    let _guard = spawn_sshd(&config);
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

    // Offer the user cert as a CertHostKey credential.
    let cert_text = std::fs::read_to_string(format!("{}-cert.pub", client_key.display())).unwrap();
    let cert = Certificate::parse_openssh_line(&cert_text).unwrap();
    let pem = std::fs::read_to_string(&client_key).unwrap();
    let signer = PrivateKey::parse_openssh_pem(&pem, None)
        .unwrap()
        .into_host_key_sync()
        .unwrap();
    let cred = CertHostKey::new(signer, &cert, "ssh-ed25519-cert-v01@openssh.com").unwrap();

    client
        .authenticate(&user, vec![ClientCredential::PublicKey(Box::new(cred))])
        .expect("user-cert auth against real sshd");

    let out = client.exec("echo cert-ok").expect("exec");
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "cert-ok");
    assert_eq!(out.exit_status, Some(0));
}

/// Real sshd presents a CA-signed HOST cert; puressh verifies it via
/// `@cert-authority`.
#[test]
#[ignore]
fn host_cert_against_real_sshd() {
    let tmp = tempdir();
    let host_key = tmp.join("host_ed25519");
    let host_ca = tmp.join("host_ca");
    let client_key = tmp.join("client_ed25519");
    let authorized = tmp.join("authorized_keys");
    let config = tmp.join("sshd_config");

    ssh_keygen_key(&host_key, "ed25519");
    ssh_keygen_key(&host_ca, "ed25519");
    ssh_keygen_key(&client_key, "ed25519");

    let pubkey = std::fs::read(format!("{}.pub", client_key.display())).unwrap();
    std::fs::write(&authorized, &pubkey).unwrap();
    chmod_600(&authorized);

    let user = current_user();
    // Mint a host cert valid for "localhost".
    run(Command::new("ssh-keygen").args([
        "-s",
        &host_ca.display().to_string(),
        "-h",
        "-I",
        "e2e-host",
        "-n",
        "localhost",
        "-V",
        "+52w",
        &format!("{}.pub", host_key.display()),
    ]));
    let host_cert = format!("{}-cert.pub", host_key.display());

    let port = pick_free_port();
    let cfg_body = format!(
        "Port {port}\nListenAddress 127.0.0.1\nHostKey {host}\nHostCertificate {cert}\n\
         PidFile {pid}\nAuthorizedKeysFile {ak}\nStrictModes no\nUsePAM no\n\
         PasswordAuthentication no\nKbdInteractiveAuthentication no\n\
         PubkeyAuthentication yes\nPermitRootLogin no\nAllowUsers {user}\nLogLevel DEBUG1\n",
        host = host_key.display(),
        cert = host_cert,
        pid = tmp.join("sshd.pid").display(),
        ak = authorized.display(),
    );
    std::fs::write(&config, cfg_body).unwrap();

    let _guard = spawn_sshd(&config);
    wait_for_tcp(port, Duration::from_secs(5));

    // known_hosts @cert-authority trusting the host CA for [localhost]:port.
    let ca_pub = std::fs::read_to_string(format!("{}.pub", host_ca.display())).unwrap();
    let mut it = ca_pub.split_whitespace();
    let (algo, b64) = (it.next().unwrap(), it.next().unwrap());
    let kh_line = format!("@cert-authority [localhost]:{port} {algo} {b64}\n");
    let store = Arc::new(Mutex::new(KnownHosts::from_bytes(kh_line.as_bytes())));
    let mut policy = KnownHostsPolicy::strict(store);
    policy.on_unknown = TofuAction::Reject;

    // connect_to_host resolves "localhost" → 127.0.0.1, and threads the name
    // for the cert principal check.
    let mut client = Client::connect_to_host(
        "localhost",
        port,
        Config {
            host_key_policy: HostKeyPolicy::KnownHosts(policy),
            timeout: Some(Duration::from_secs(10)),
            algorithms: Default::default(),
        },
    )
    .expect("connect + host-cert verify against real sshd");

    let pem = std::fs::read_to_string(&client_key).unwrap();
    let hk = PrivateKey::parse_openssh_pem(&pem, None)
        .unwrap()
        .into_host_key()
        .unwrap();
    client
        .authenticate(&user, vec![ClientCredential::PublicKey(hk)])
        .expect("auth");
    let out = client.exec("echo host-cert-ok").expect("exec");
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "host-cert-ok");
    assert_eq!(out.exit_status, Some(0));
}
