//! In-process certificate-authentication tests over loopback `Server`s,
//! driven by the `ssh-keygen -s` fixtures under `tests/fixtures/cert/`.
//!
//! Host certs: the server presents a `CertHostKey` (fixture host key wrapped in
//! its host certificate); the client trusts the CA via a known_hosts
//! `@cert-authority` line. Covers accept plus wrong-CA / expired / wrong-host
//! rejection.
//!
//! User certs: the client offers a user certificate; the server's authenticator
//! verifies the CA and principal binding. Covers accept plus wrong-CA /
//! expired / principal-not-allowed / unknown-critical-option rejection.

#![cfg(all(feature = "client", feature = "server"))]

use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use puressh::auth::{AuthAttempt, AuthDecision, Authenticator};
use puressh::cert::{CertType, Certificate};
use puressh::client::{
    Client, Config as ClientConfig, HostKeyPolicy, KnownHostsPolicy, TofuAction,
};
use puressh::hostkey::{CertHostKey, Ed25519HostKey, HostKey};
use puressh::key::PrivateKey;
use puressh::known_hosts::KnownHosts;
use puressh::server::{
    AuthenticatorFactory, CommandHandler, Config as ServerConfig, ExecResult, Server, SessionEnv,
};

fn fixture(name: &str) -> String {
    format!(
        "{}/tests/fixtures/cert/{}",
        env!("CARGO_MANIFEST_DIR"),
        name
    )
}

fn load_cert(name: &str) -> Certificate {
    let text = std::fs::read_to_string(fixture(name)).unwrap();
    Certificate::parse_openssh_line(&text).unwrap()
}

fn load_priv(name: &str) -> PrivateKey {
    let pem = std::fs::read_to_string(fixture(name)).unwrap();
    PrivateKey::parse_openssh_pem(&pem, None).unwrap()
}

/// The ed25519 seed inside an OpenSSH private-key fixture.
fn seed_of(name: &str) -> [u8; 32] {
    match load_priv(name) {
        PrivateKey::Ed25519 { seed, .. } => seed,
        _ => panic!("{name} is not ed25519"),
    }
}

/// The base64 of a `.pub` / `-cert.pub` fixture's second field.
fn pub_field(name: &str) -> (String, String) {
    let text = std::fs::read_to_string(fixture(name)).unwrap();
    let mut it = text.split_whitespace();
    (
        it.next().unwrap().to_string(),
        it.next().unwrap().to_string(),
    )
}

struct StaticHandler(Vec<u8>);
impl CommandHandler for StaticHandler {
    fn handle(&self, _user: &str, _env: &SessionEnv, _command: &str) -> ExecResult {
        ExecResult {
            stdout: self.0.clone(),
            stderr: Vec::new(),
            exit_status: 0,
        }
    }
}

/// Accept one public key for one user (plain-key auth, used by the host-cert
/// tests where only the *host* side uses a certificate).
struct OneKeyAuth {
    user: String,
    blob: Vec<u8>,
}
impl Authenticator for OneKeyAuth {
    fn evaluate(&mut self, attempt: AuthAttempt) -> AuthDecision {
        match attempt {
            AuthAttempt::PublicKey {
                user,
                public_blob,
                probe_only,
                verified,
                ..
            } => {
                if user != self.user || public_blob != self.blob {
                    return AuthDecision::Reject;
                }
                if probe_only || verified {
                    AuthDecision::Accept
                } else {
                    AuthDecision::Reject
                }
            }
            _ => AuthDecision::Reject,
        }
    }
}

/// Build a server whose host key is the fixture host cert, accepting `user`
/// with `client_seed`'s public key. Returns (addr, join handle).
fn spawn_host_cert_server(
    user: &str,
    client_seed: [u8; 32],
) -> (std::net::SocketAddr, thread::JoinHandle<()>) {
    let cert = load_cert("h_ed25519-cert.pub");
    let inner: Box<dyn HostKey + Send + Sync> =
        Box::new(Ed25519HostKey::from_seed(seed_of("h_ed25519")));
    let cert_key =
        CertHostKey::new(inner, &cert, "ssh-ed25519-cert-v01@openssh.com").expect("wrap cert");

    let allowed = Ed25519HostKey::from_seed(client_seed).public_blob();
    let user_s = user.to_string();
    let factory: Arc<dyn AuthenticatorFactory> = Arc::new(move || -> Box<dyn Authenticator> {
        Box::new(OneKeyAuth {
            user: user_s.clone(),
            blob: allowed.clone(),
        })
    });

    let cfg = ServerConfig::new(
        vec![Box::new(cert_key)],
        factory,
        vec!["publickey"],
        Arc::new(StaticHandler(b"host-cert-ok\n".to_vec())),
    );
    let mut server = Server::bind("127.0.0.1:0", cfg).expect("bind");
    let addr = server.local_addr().expect("addr");
    let handle = thread::spawn(move || {
        let _ = server.accept_one();
    });
    (addr, handle)
}

/// A known_hosts store with one `@cert-authority` line for `host` (on `port`)
/// trusting the given CA `.pub` fixture. A non-default port is encoded as the
/// OpenSSH `[host]:port` host pattern (a bare pattern only matches port 22).
fn ca_known_hosts(host: &str, port: u16, ca_pub_fixture: &str) -> Arc<Mutex<KnownHosts>> {
    let (algo, b64) = pub_field(ca_pub_fixture);
    let host_pattern = if port == 22 {
        host.to_string()
    } else {
        format!("[{host}]:{port}")
    };
    let line = format!("@cert-authority {host_pattern} {algo} {b64}\n");
    Arc::new(Mutex::new(KnownHosts::from_bytes(line.as_bytes())))
}

fn client_cfg(policy: HostKeyPolicy) -> ClientConfig {
    ClientConfig {
        host_key_policy: policy,
        timeout: Some(Duration::from_secs(15)),
        algorithms: Default::default(),
    }
}

fn ca_policy(store: Arc<Mutex<KnownHosts>>) -> HostKeyPolicy {
    let mut p = KnownHostsPolicy::strict(store);
    // No TOFU: a cert that isn't CA-trusted must be rejected outright.
    p.on_unknown = TofuAction::Reject;
    HostKeyPolicy::KnownHosts(p)
}

/// Connect to the loopback `addr` but present `principal` as the host name, so
/// the cert's principal check runs against a name we can control (the fixture
/// host cert names `host.example.com`, which does not resolve to 127.0.0.1).
fn connect_principal(
    principal: &str,
    addr: std::net::SocketAddr,
    cfg: ClientConfig,
) -> puressh::Result<Client> {
    let stream = std::net::TcpStream::connect(addr)?;
    stream.set_nodelay(true).ok();
    if let Some(t) = cfg.timeout {
        stream.set_read_timeout(Some(t)).ok();
        stream.set_write_timeout(Some(t)).ok();
    }
    Client::connect_via(Box::new(stream), principal, addr.port(), cfg)
}

#[test]
fn host_cert_accepted_via_cert_authority() {
    let client_seed = puressh_fresh_seed();
    let user = "alice";
    let (addr, handle) = spawn_host_cert_server(user, client_seed);

    let store = ca_known_hosts("host.example.com", addr.port(), "ca_ed25519.pub");
    let mut client = connect_principal("host.example.com", addr, client_cfg(ca_policy(store)))
        .expect("client connect");

    let hk: Box<dyn HostKey + Send> = Box::new(Ed25519HostKey::from_seed(client_seed));
    client.authenticate_publickey(user, hk).expect("auth");
    let out = client.exec("whatever").expect("exec");
    assert_eq!(out.stdout, b"host-cert-ok\n");
    drop(client);
    let _ = handle.join();
}

#[test]
fn host_cert_wrong_ca_rejected() {
    let client_seed = puressh_fresh_seed();
    let (addr, handle) = spawn_host_cert_server("alice", client_seed);

    // Trust the WRONG CA (ecdsa) — the host cert was signed by the ed25519 CA.
    let store = ca_known_hosts("host.example.com", addr.port(), "ca_ecdsa.pub");
    let res = connect_principal("host.example.com", addr, client_cfg(ca_policy(store)));
    assert!(res.is_err(), "wrong CA must reject the host cert");
    let _ = handle.join();
}

#[test]
fn host_cert_wrong_principal_rejected() {
    let client_seed = puressh_fresh_seed();
    let (addr, handle) = spawn_host_cert_server("alice", client_seed);

    // Right CA, but connect under a host name the cert does not list.
    let store = ca_known_hosts("other.example.com", addr.port(), "ca_ed25519.pub");
    let res = connect_principal("other.example.com", addr, client_cfg(ca_policy(store)));
    assert!(res.is_err(), "host not in cert principals must reject");
    let _ = handle.join();
}

#[test]
fn expired_host_cert_fails_validity() {
    // check_validity is what `verify_host_cert` calls; the fixture expired
    // cert (a user cert, but the gate is type-independent) must fail.
    let cert = load_cert("u_ed25519_expired-cert.pub");
    assert!(cert.check_validity(1_700_000_000).is_err());
    assert!(matches!(cert.cert_type, CertType::User));
}

// ---------------------------------------------------------------------------
// User certificates: client offers a CertHostKey credential; the server trusts
// the CA via a `CertInfo`-driven authenticator (mirroring sshd's
// LocalAuthenticator trust gate) and checks the principal binding.
// ---------------------------------------------------------------------------

/// An authenticator that accepts a user certificate iff its CA matches a
/// trusted blob and the login user is among the cert's principals.
struct CaUserAuth {
    trusted_ca: Vec<u8>,
}
impl Authenticator for CaUserAuth {
    fn evaluate(&mut self, attempt: AuthAttempt) -> AuthDecision {
        match attempt {
            AuthAttempt::PublicKey {
                user,
                probe_only,
                verified,
                cert: Some(ci),
                ..
            } => {
                let ca_ok = ci.ca_key_blob == self.trusted_ca;
                let principal_ok =
                    ci.valid_principals.is_empty() || ci.valid_principals.contains(&user);
                if probe_only {
                    // Let the client proceed to the signed step; final trust is
                    // re-checked on the verified attempt below.
                    return if ca_ok && principal_ok {
                        AuthDecision::Accept
                    } else {
                        AuthDecision::Reject
                    };
                }
                if verified && ca_ok && principal_ok {
                    AuthDecision::Accept
                } else {
                    AuthDecision::Reject
                }
            }
            // Reject plain keys and everything else.
            _ => AuthDecision::Reject,
        }
    }
}

/// CA-trust helper that builds a server which accepts certs from `trusted_ca`,
/// plus a client that offers the given (cert, identity-key) pair.
fn run_user_cert_auth(
    login_user: &str,
    cert_fixture: &str,
    identity_fixture: &str,
    trusted_ca_fixture: &str,
) -> Result<(), puressh::Error> {
    // Server.
    let host_seed = puressh_fresh_seed();
    let trusted_ca = {
        let (algo, b64) = pub_field(trusted_ca_fixture);
        let line = format!("{algo} {b64}");
        // Reuse the cert line parser? No — decode the plain pubkey blob.
        puressh::key::PublicKey::parse_authorized_keys_line(&line)
            .unwrap()
            .wire_blob()
    };
    let factory: Arc<dyn AuthenticatorFactory> = Arc::new(move || -> Box<dyn Authenticator> {
        Box::new(CaUserAuth {
            trusted_ca: trusted_ca.clone(),
        })
    });
    let host_key: Box<dyn HostKey + Send + Sync> = Box::new(Ed25519HostKey::from_seed(host_seed));
    let cfg = ServerConfig::new(
        vec![host_key],
        factory,
        vec!["publickey"],
        Arc::new(StaticHandler(b"user-cert-ok\n".to_vec())),
    );
    let mut server = Server::bind("127.0.0.1:0", cfg).expect("bind");
    let addr = server.local_addr().expect("addr");
    let handle = thread::spawn(move || {
        let _ = server.accept_one();
    });

    // Client.
    let cert = load_cert(cert_fixture);
    let signer = load_priv(identity_fixture).into_host_key_sync().unwrap();
    let cert_name = puressh::cert::CERT_KEY_NAMES
        .iter()
        .copied()
        .find(|n| puressh::cert::cert_name_to_plain(n) == Some(cert.embedded_algorithm()))
        .unwrap();
    let cert_cred = CertHostKey::new(signer, &cert, cert_name).expect("wrap user cert");

    let mut client = Client::connect(addr, client_cfg(HostKeyPolicy::AcceptAny))?;
    let res = client.authenticate(
        login_user,
        vec![puressh::auth::ClientCredential::PublicKey(Box::new(
            cert_cred,
        ))],
    );
    drop(client);
    let _ = handle.join();
    res
}

#[test]
fn user_cert_accepted() {
    // alice's ed25519 user cert, signed by the ed25519 CA, login as alice.
    run_user_cert_auth("alice", "u_ed25519-cert.pub", "u_ed25519", "ca_ed25519.pub")
        .expect("user cert auth should succeed");
}

#[test]
fn user_cert_wrong_ca_rejected() {
    // Server trusts the ecdsa CA, but the cert was signed by the ed25519 CA.
    let r = run_user_cert_auth("alice", "u_ed25519-cert.pub", "u_ed25519", "ca_ecdsa.pub");
    assert!(r.is_err(), "cert from an untrusted CA must be rejected");
}

#[test]
fn user_cert_principal_not_allowed_rejected() {
    // The ed25519 cert authorizes alice,bob — logging in as carol must fail.
    let r = run_user_cert_auth("carol", "u_ed25519-cert.pub", "u_ed25519", "ca_ed25519.pub");
    assert!(
        r.is_err(),
        "login user not in cert principals must be rejected"
    );
}

#[test]
fn user_cert_expired_rejected() {
    // The expired user cert must be rejected at the auth layer (validity gate)
    // before the authenticator even sees a verified attempt.
    let r = run_user_cert_auth(
        "alice",
        "u_ed25519_expired-cert.pub",
        "u_ed25519",
        "ca_ed25519.pub",
    );
    assert!(r.is_err(), "expired cert must be rejected");
}

#[test]
fn user_cert_unknown_critical_option_rejected() {
    // Build a cert blob with an injected unknown critical option and confirm
    // the parse-level gate the auth layer relies on rejects it.
    let mut cert = load_cert("u_ed25519-cert.pub");
    cert.critical_options
        .push(("bogus-must-understand".to_string(), Vec::new()));
    assert!(cert.require_known_critical_options().is_err());
}

fn puressh_fresh_seed() -> [u8; 32] {
    use purecrypto::rng::{OsRng, RngCore};
    let mut s = [0u8; 32];
    OsRng.fill_bytes(&mut s);
    s
}

// ---------------------------------------------------------------------------
// R1/R2: user-certificate extension default-deny + force-command end-to-end.
//
// These build a signed ed25519 user certificate *in process* (no ssh-keygen
// dependency) so we can vary the extension set / force-command per test, then
// drive a full loopback auth + shell and observe, through a recording
// `ShellHandler`, whether the server honoured the `pty-req` and which command
// the connection ran. The default-deny behaviour lives in the server's
// `EffectivePolicy`, fed from the authenticating cert's `AuthCertCaps`.
// ---------------------------------------------------------------------------

use puressh::format::Writer;
use puressh::server::{PtySpec, ShellExitStatus, ShellHandler, ShellSession};

/// Build a signed ed25519 user certificate blob in process.
///
/// `extensions` is the ordered (sorted) list of extension names to include
/// (empty data each, like OpenSSH's permit-* flags). `critical` is the ordered
/// list of `(name, ssh-string-payload)` critical options. The cert wraps
/// `user_pub` (a plain ssh-ed25519 32-byte key) and is signed by `ca` acting as
/// the CA. Returns `(cert_blob, ca_pubkey_blob)`.
fn build_user_cert(
    ca: &Ed25519HostKey,
    user_pub: &[u8; 32],
    principals: &[&str],
    extensions: &[&str],
    critical: &[(&str, Vec<u8>)],
) -> (Vec<u8>, Vec<u8>) {
    // The wire layout up to (and including) the signature key, per
    // PROTOCOL.certkeys; we then sign that region and append the signature.
    let mut w = Writer::new();
    w.write_string(b"ssh-ed25519-cert-v01@openssh.com");
    w.write_string(&puressh_fresh_seed()); // nonce
    w.write_string(user_pub); // ed25519 public key field
    w.write_u64(7); // serial
    w.write_u32(1); // type = user
    w.write_string(b"e2e"); // key id
    // principals: a list-of-strings, itself length-prefixed.
    let mut princ = Writer::new();
    for p in principals {
        princ.write_string(p.as_bytes());
    }
    w.write_string(&princ.into_vec());
    w.write_u64(0); // valid after
    w.write_u64(u64::MAX); // valid before (always valid)
    // critical options (must be name-sorted; caller supplies sorted).
    let mut crit = Writer::new();
    for (name, data) in critical {
        crit.write_string(name.as_bytes());
        crit.write_string(data);
    }
    w.write_string(&crit.into_vec());
    // extensions (must be name-sorted; caller supplies sorted).
    let mut ext = Writer::new();
    for name in extensions {
        ext.write_string(name.as_bytes());
        ext.write_string(b""); // empty data
    }
    w.write_string(&ext.into_vec());
    w.write_string(b""); // reserved
    let ca_blob = ca.public_blob();
    w.write_string(&ca_blob); // signature key
    let signed = w.into_vec();
    let signature = ca.sign(&signed).expect("CA sign");
    let mut full = signed;
    // Append the signature string.
    let mut sw = Writer::new();
    sw.write_string(&signature);
    full.extend_from_slice(&sw.into_vec());
    (full, ca_blob)
}

/// Encode `s` as an SSH `string` (4-byte length prefix + bytes), the inner
/// payload form a `force-command` critical option carries.
fn ssh_string(s: &str) -> Vec<u8> {
    let mut w = Writer::new();
    w.write_string(s.as_bytes());
    w.into_vec()
}

/// Recording shell handler: latches the `pty-req` spec (if any) and the user
/// seen at spawn, and replays a fixed stdout + clean exit.
#[derive(Clone)]
struct RecordingShell {
    inner: Arc<Mutex<RecordingShellState>>,
}
#[derive(Default)]
struct RecordingShellState {
    pty: Option<PtySpec>,
    spawned: bool,
    stdout: Vec<u8>,
}
impl RecordingShell {
    fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(RecordingShellState {
                pty: None,
                spawned: false,
                stdout: b"shell-ran\n".to_vec(),
            })),
        }
    }
}
impl ShellHandler for RecordingShell {
    fn spawn(
        &self,
        _user: &str,
        _env: &SessionEnv,
        pty: Option<PtySpec>,
    ) -> puressh::Result<Box<dyn ShellSession>> {
        let mut st = self.inner.lock().unwrap();
        st.pty = pty;
        st.spawned = true;
        Ok(Box::new(RecordingSession {
            inner: self.inner.clone(),
        }))
    }
}
struct RecordingSession {
    inner: Arc<Mutex<RecordingShellState>>,
}
impl ShellSession for RecordingSession {
    fn read(&mut self, buf: &mut [u8]) -> puressh::Result<usize> {
        let mut st = self.inner.lock().unwrap();
        if st.stdout.is_empty() {
            return Ok(0);
        }
        let n = std::cmp::min(buf.len(), st.stdout.len());
        buf[..n].copy_from_slice(&st.stdout[..n]);
        st.stdout.drain(..n);
        Ok(n)
    }
    fn write(&mut self, data: &[u8]) -> puressh::Result<usize> {
        Ok(data.len())
    }
    fn close_stdin(&mut self) -> puressh::Result<()> {
        Ok(())
    }
    fn resize(&mut self, _c: u32, _r: u32, _w: u32, _h: u32) -> puressh::Result<()> {
        Ok(())
    }
    fn try_exit(&mut self) -> Option<ShellExitStatus> {
        // Exit once stdout has drained so the client's shell call returns.
        if self.inner.lock().unwrap().stdout.is_empty() {
            Some(ShellExitStatus::Exited(0))
        } else {
            None
        }
    }
}

/// Records the command string the buffered command handler was asked to run,
/// so a force-command test can confirm what the connection executed and what
/// `SSH_ORIGINAL_COMMAND` carried.
#[derive(Clone)]
struct CmdRecorder {
    last: Arc<Mutex<Option<(String, String)>>>,
}
impl CommandHandler for CmdRecorder {
    fn handle(&self, _user: &str, env: &SessionEnv, command: &str) -> ExecResult {
        let orig = env.get("SSH_ORIGINAL_COMMAND").unwrap_or("").to_string();
        *self.last.lock().unwrap() = Some((command.to_string(), orig.clone()));
        ExecResult {
            stdout: format!("CMD={command}\nORIG={orig}\n").into_bytes(),
            stderr: Vec::new(),
            exit_status: 0,
        }
    }
}

/// Authenticator accepting any CA-trusted, in-principals user cert.
struct AnyCaUserAuth {
    trusted_ca: Vec<u8>,
}
impl Authenticator for AnyCaUserAuth {
    fn evaluate(&mut self, attempt: AuthAttempt) -> AuthDecision {
        match attempt {
            AuthAttempt::PublicKey {
                user,
                probe_only,
                verified,
                cert: Some(ci),
                ..
            } => {
                let ca_ok = ci.ca_key_blob == self.trusted_ca;
                let principal_ok =
                    ci.valid_principals.is_empty() || ci.valid_principals.contains(&user);
                if (probe_only || verified) && ca_ok && principal_ok {
                    AuthDecision::Accept
                } else {
                    AuthDecision::Reject
                }
            }
            _ => AuthDecision::Reject,
        }
    }
}

/// Spin up a loopback server with a `RecordingShell` + `CmdRecorder`, trusting
/// `ca`, and authenticate a client offering `(cert_blob, identity-seed)`.
/// Drives a `pty-req`+`shell`, returning the recorded shell + command state.
/// Result of driving an authenticated cert connection through `pty-req`+`shell`.
struct CertShellOutcome {
    /// The pty spec the shell handler saw (`None` if the server refused it).
    pty: Option<PtySpec>,
    /// Whether the shell handler's `spawn` ran at all.
    spawned: bool,
    /// `Ok` iff the client's `shell_with_stdin` completed (a refused `pty-req`
    /// makes it `Err`, since that call requests a pty with want_reply=true).
    shell_ok: bool,
    /// The (command, SSH_ORIGINAL_COMMAND) the buffered handler ran, if any.
    cmd: Option<(String, String)>,
}

#[allow(clippy::type_complexity)]
fn run_cert_shell(
    login_user: &str,
    cert_blob: Vec<u8>,
    identity_seed: [u8; 32],
    ca_blob: Vec<u8>,
) -> CertShellOutcome {
    let host_seed = puressh_fresh_seed();
    let trusted = ca_blob.clone();
    let factory: Arc<dyn AuthenticatorFactory> = Arc::new(move || -> Box<dyn Authenticator> {
        Box::new(AnyCaUserAuth {
            trusted_ca: trusted.clone(),
        })
    });
    let shell = RecordingShell::new();
    let cmd_last = Arc::new(Mutex::new(None));
    let host_key: Box<dyn HostKey + Send + Sync> = Box::new(Ed25519HostKey::from_seed(host_seed));
    let cfg = ServerConfig::new(
        vec![host_key],
        factory,
        vec!["publickey"],
        Arc::new(CmdRecorder {
            last: cmd_last.clone(),
        }),
    )
    .with_shell(Arc::new(shell.clone()));
    let mut server = Server::bind("127.0.0.1:0", cfg).expect("bind");
    let addr = server.local_addr().expect("addr");
    let handle = thread::spawn(move || {
        let _ = server.accept_one();
    });

    // Client: offer the user cert as a CertHostKey credential.
    let cert = Certificate::parse(&cert_blob).expect("parse built cert");
    let signer =
        Box::new(Ed25519HostKey::from_seed(identity_seed)) as Box<dyn HostKey + Send + Sync>;
    let cert_cred = CertHostKey::new(signer, &cert, "ssh-ed25519-cert-v01@openssh.com")
        .expect("wrap user cert");

    let mut client =
        Client::connect(addr, client_cfg(HostKeyPolicy::AcceptAny)).expect("client connect");
    client
        .authenticate(
            login_user,
            vec![puressh::auth::ClientCredential::PublicKey(Box::new(
                cert_cred,
            ))],
        )
        .expect("cert auth");
    // `shell_with_stdin` itself sends a `pty-req` (want_reply=true) then
    // `shell`; a server that refuses the pty makes this call return `Err`.
    let shell_ok = client.shell_with_stdin("xterm", 80, 24, b"").is_ok();
    drop(client);
    let _ = handle.join();

    let st = shell.inner.lock().unwrap();
    let cmd = cmd_last.lock().unwrap().clone();
    CertShellOutcome {
        pty: st.pty.clone(),
        spawned: st.spawned,
        shell_ok,
        cmd,
    }
}

#[test]
fn r1_cert_without_permit_pty_is_refused_a_pty() {
    let ca = Ed25519HostKey::from_seed(puressh_fresh_seed());
    let id_seed = puressh_fresh_seed();
    let user_pub = raw_ed25519_from_blob(&Ed25519HostKey::from_seed(id_seed).public_blob());

    // Cert WITHOUT permit-pty (only other permits present).
    let (cert, ca_blob) =
        build_user_cert(&ca, &user_pub, &["alice"], &["permit-port-forwarding"], &[]);
    let out = run_cert_shell("alice", cert, id_seed, ca_blob);
    // The `pty-req` is refused (want_reply=true), so the interactive-shell
    // request never reaches the handler and the client call errors. Auth itself
    // succeeded (we got far enough to issue the session request).
    assert!(
        !out.shell_ok,
        "a user cert without permit-pty must have its pty-req refused"
    );
    assert!(out.pty.is_none(), "no pty must have reached the handler");
}

#[test]
fn r1_cert_with_permit_pty_gets_a_pty() {
    let ca = Ed25519HostKey::from_seed(puressh_fresh_seed());
    let id_seed = puressh_fresh_seed();
    let user_pub = raw_ed25519_from_blob(&Ed25519HostKey::from_seed(id_seed).public_blob());
    let (cert, ca_blob) = build_user_cert(
        &ca,
        &user_pub,
        &["alice"],
        &["permit-port-forwarding", "permit-pty"],
        &[],
    );
    let out = run_cert_shell("alice", cert, id_seed, ca_blob);
    assert!(out.shell_ok, "shell with pty should succeed");
    assert!(out.spawned);
    assert!(
        out.pty.is_some(),
        "a user cert with permit-pty must be granted a pty"
    );
}

#[test]
fn r1_plain_key_auth_still_gets_a_pty() {
    // Plain-key (non-cert) auth is unaffected by cert gating: a pty is allowed.
    let host_seed = puressh_fresh_seed();
    let client_seed = puressh_fresh_seed();
    let allowed = Ed25519HostKey::from_seed(client_seed).public_blob();
    let user = "plain".to_string();
    let user_s = user.clone();
    let factory: Arc<dyn AuthenticatorFactory> = Arc::new(move || -> Box<dyn Authenticator> {
        Box::new(OneKeyAuth {
            user: user_s.clone(),
            blob: allowed.clone(),
        })
    });
    let shell = RecordingShell::new();
    let host_key: Box<dyn HostKey + Send + Sync> = Box::new(Ed25519HostKey::from_seed(host_seed));
    let cfg = ServerConfig::new(
        vec![host_key],
        factory,
        vec!["publickey"],
        Arc::new(StaticHandler(b"x\n".to_vec())),
    )
    .with_shell(Arc::new(shell.clone()));
    let mut server = Server::bind("127.0.0.1:0", cfg).expect("bind");
    let addr = server.local_addr().expect("addr");
    let handle = thread::spawn(move || {
        let _ = server.accept_one();
    });
    let mut client = Client::connect(addr, client_cfg(HostKeyPolicy::AcceptAny)).expect("connect");
    let hk: Box<dyn HostKey + Send> = Box::new(Ed25519HostKey::from_seed(client_seed));
    client.authenticate_publickey(&user, hk).expect("auth");
    client.set_request_pty(Some(("xterm".into(), 80, 24, 0, 0, Vec::new())));
    let _ = client.shell_with_stdin("xterm", 80, 24, b"");
    drop(client);
    let _ = handle.join();
    let st = shell.inner.lock().unwrap();
    assert!(st.spawned);
    assert!(st.pty.is_some(), "plain-key auth must still get a pty");
}

#[test]
fn r2_cert_force_command_overrides_interactive_shell() {
    let ca = Ed25519HostKey::from_seed(puressh_fresh_seed());
    let id_seed = puressh_fresh_seed();
    let user_pub = raw_ed25519_from_blob(&Ed25519HostKey::from_seed(id_seed).public_blob());
    // Cert carries permit-pty AND a force-command critical option.
    let (cert, ca_blob) = build_user_cert(
        &ca,
        &user_pub,
        &["alice"],
        &["permit-pty"],
        &[("force-command", ssh_string("/forced/by/cert"))],
    );
    let out = run_cert_shell("alice", cert, id_seed, ca_blob);
    // The shell handler is NOT used; the forced command runs via the buffered
    // command handler instead of a login shell.
    assert!(
        !out.spawned,
        "force-command must run instead of a login shell"
    );
    let (cmd, orig) = out.cmd.expect("forced command ran");
    assert_eq!(cmd, "/forced/by/cert");
    // An interactive shell has no client command ⇒ empty SSH_ORIGINAL_COMMAND.
    assert_eq!(orig, "");
}

/// Extract the raw 32-byte ed25519 public key from a wire `ssh-ed25519` blob
/// (`string "ssh-ed25519"`, `string <32 bytes>`).
fn raw_ed25519_from_blob(blob: &[u8]) -> [u8; 32] {
    use puressh::format::Reader;
    let mut r = Reader::new(blob);
    let _algo = r.read_string().expect("algo");
    let pk = r.read_string().expect("pk");
    pk.try_into().expect("32-byte ed25519 key")
}
