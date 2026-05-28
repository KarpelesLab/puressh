//! `ssh` — puressh's SSH client driver.
//!
//! ```text
//! ssh [-p port] [-i identity_file] [-l user]
//!     [-o StrictHostKeyChecking={yes,no,accept-new,ask}]
//!     [-o UserKnownHostsFile=PATH]
//!     [-o HashKnownHosts={yes,no}]
//!     [-o IdentitiesOnly={yes,no}]
//!     [-L LPORT:RHOST:RPORT] [-R RPORT:LHOST:LPORT]
//!     [-N]
//!     [user@]host [command...]
//! ```

use std::io::{ErrorKind, Read, Write};
use std::net::TcpStream;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::{Arc, Mutex};
use std::thread;

use puressh::agent::{Agent, AgentHostKey};
use puressh::auth::ClientCredential;
use puressh::client::{
    ChannelStream, Client, ClientHandlers, Config, ForwardedTcpipCallback, ForwardedTcpipOrigin,
    HostKeyPolicy, KnownHostsPolicy, TofuAction,
};
use puressh::key::PrivateKey;
use puressh::known_hosts::KnownHosts;

const VERSION: &str = env!("CARGO_PKG_VERSION");

const USAGE: &str = "usage: ssh [-p port] [-i identity_file] [-l user] \
                     [-o StrictHostKeyChecking={yes,no,accept-new,ask}] \
                     [-o UserKnownHostsFile=PATH] [-o HashKnownHosts={yes,no}] \
                     [-o IdentitiesOnly={yes,no}] \
                     [-L LPORT:RHOST:RPORT] [-R RPORT:LHOST:LPORT] \
                     [-N] \
                     [user@]host [command...]";

/// Maps `StrictHostKeyChecking` modes to TOFU behaviour.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum StrictMode {
    /// `yes`: refuse Unknown; reject Mismatch.
    Yes,
    /// `no`: accept Unknown silently AND tolerate Mismatch (insecure).
    No,
    /// `accept-new`: silently accept Unknown; still reject Mismatch.
    AcceptNew,
    /// `ask` (OpenSSH default): prompt on Unknown; reject Mismatch.
    Ask,
}

/// Parsed `-L LPORT:RHOST:RPORT` spec — client binds `LPORT` on loopback;
/// each accepted connection becomes a `direct-tcpip` channel to the server
/// targeting `RHOST:RPORT`.
///
/// Fields are currently unread because the ssh binary rejects `-L` at runtime
/// (see `run()`): the lib's [`puressh::client::Client::open_direct_tcpip`] is
/// single-channel-borrowing, so multi-channel `-L` from the binary needs an
/// outbound-request side channel inside [`puressh::client::Client::serve`]. The
/// parser is kept so command lines stay forward-compatible.
#[derive(Clone, Debug)]
#[allow(dead_code)]
struct LocalForward {
    /// Local port to bind on `127.0.0.1`.
    listen_port: u16,
    /// Destination hostname/IP the server is asked to dial.
    remote_host: String,
    /// Destination TCP port.
    remote_port: u16,
}

/// Parsed `-R RPORT:LHOST:LPORT` spec — client asks the server to bind
/// `RPORT`; each incoming connection arrives as a `forwarded-tcpip` open
/// which the client splices to a fresh TCP connection on `LHOST:LPORT`.
#[derive(Clone, Debug)]
struct RemoteForward {
    /// Remote port the server is asked to bind on `127.0.0.1`.
    remote_port: u16,
    /// Local destination the client dials per accepted forward.
    local_host: String,
    /// Local destination TCP port.
    local_port: u16,
}

struct Cli {
    port: u16,
    identities: Vec<String>,
    cli_user: Option<String>,
    strict: StrictMode,
    known_hosts_path: Option<PathBuf>,
    hash_known_hosts: bool,
    identities_only: bool,
    locals: Vec<LocalForward>,
    remotes: Vec<RemoteForward>,
    no_command: bool,
    host: String,
    user_in_host: Option<String>,
    command: Option<String>,
}

/// Parse one `-L` arg value: `LPORT:RHOST:RPORT`. `RHOST` may be a bare IPv4
/// or hostname; bracketed IPv6 (`[::1]:80`) is NOT yet supported.
fn parse_local_forward(s: &str) -> Result<LocalForward, String> {
    let parts: Vec<&str> = s.splitn(3, ':').collect();
    if parts.len() != 3 {
        return Err(format!("-L expects LPORT:RHOST:RPORT, got {s:?}"));
    }
    let listen_port: u16 = parts[0]
        .parse()
        .map_err(|_| format!("-L: invalid LPORT {:?}", parts[0]))?;
    let remote_host = parts[1].to_string();
    if remote_host.is_empty() {
        return Err("-L: RHOST cannot be empty".into());
    }
    let remote_port: u16 = parts[2]
        .parse()
        .map_err(|_| format!("-L: invalid RPORT {:?}", parts[2]))?;
    Ok(LocalForward {
        listen_port,
        remote_host,
        remote_port,
    })
}

/// Parse one `-R` arg value: `RPORT:LHOST:LPORT`.
fn parse_remote_forward(s: &str) -> Result<RemoteForward, String> {
    let parts: Vec<&str> = s.splitn(3, ':').collect();
    if parts.len() != 3 {
        return Err(format!("-R expects RPORT:LHOST:LPORT, got {s:?}"));
    }
    let remote_port: u16 = parts[0]
        .parse()
        .map_err(|_| format!("-R: invalid RPORT {:?}", parts[0]))?;
    let local_host = parts[1].to_string();
    if local_host.is_empty() {
        return Err("-R: LHOST cannot be empty".into());
    }
    let local_port: u16 = parts[2]
        .parse()
        .map_err(|_| format!("-R: invalid LPORT {:?}", parts[2]))?;
    Ok(RemoteForward {
        remote_port,
        local_host,
        local_port,
    })
}

fn parse_args(args: &[String]) -> Result<Cli, String> {
    let mut port = 22u16;
    let mut identities: Vec<String> = Vec::new();
    let mut cli_user: Option<String> = None;
    let mut strict = StrictMode::Ask;
    let mut known_hosts_path: Option<PathBuf> = None;
    let mut hash_known_hosts = false;
    let mut identities_only = false;
    let mut locals: Vec<LocalForward> = Vec::new();
    let mut remotes: Vec<RemoteForward> = Vec::new();
    let mut no_command = false;
    let mut positional: Vec<String> = Vec::new();

    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
        if a == "--" {
            positional.extend_from_slice(&args[i + 1..]);
            break;
        }
        match a.as_str() {
            "-p" => {
                i += 1;
                let v = args.get(i).ok_or("-p requires a value")?;
                port = v.parse::<u16>().map_err(|_| "invalid port".to_string())?;
            }
            "-i" => {
                i += 1;
                let v = args.get(i).ok_or("-i requires a value")?.clone();
                identities.push(v);
            }
            "-l" => {
                i += 1;
                let v = args.get(i).ok_or("-l requires a value")?.clone();
                cli_user = Some(v);
            }
            "-L" => {
                i += 1;
                let v = args.get(i).ok_or("-L requires a value")?;
                locals.push(parse_local_forward(v)?);
            }
            "-R" => {
                i += 1;
                let v = args.get(i).ok_or("-R requires a value")?;
                remotes.push(parse_remote_forward(v)?);
            }
            "-N" => {
                no_command = true;
            }
            "-o" => {
                i += 1;
                let v = args.get(i).ok_or("-o requires a value")?;
                let (k, val) = v
                    .split_once('=')
                    .ok_or_else(|| format!("-o expects KEY=VALUE, got {v:?}"))?;
                match k.to_ascii_lowercase().as_str() {
                    "stricthostkeychecking" => {
                        strict = match val.to_ascii_lowercase().as_str() {
                            "yes" => StrictMode::Yes,
                            "no" | "off" => StrictMode::No,
                            "accept-new" => StrictMode::AcceptNew,
                            "ask" => StrictMode::Ask,
                            other => return Err(format!("unknown StrictHostKeyChecking={other}")),
                        };
                    }
                    "userknownhostsfile" => {
                        known_hosts_path = Some(PathBuf::from(val));
                    }
                    "hashknownhosts" => {
                        hash_known_hosts =
                            matches!(val.to_ascii_lowercase().as_str(), "yes" | "on");
                    }
                    "identitiesonly" => {
                        identities_only = matches!(val.to_ascii_lowercase().as_str(), "yes" | "on");
                    }
                    other => {
                        return Err(format!("unsupported -o option: {other}={val}"));
                    }
                }
            }
            s if s.starts_with('-') => {
                return Err(format!("unknown flag: {s}"));
            }
            _ => positional.push(a.clone()),
        }
        i += 1;
    }

    if positional.is_empty() {
        return Err("missing host argument".into());
    }
    let target = positional.remove(0);
    let (user_in_host, host) = match target.split_once('@') {
        Some((u, h)) => (Some(u.to_string()), h.to_string()),
        None => (None, target),
    };
    if host.is_empty() {
        return Err("empty host".into());
    }
    let command = if positional.is_empty() {
        None
    } else {
        Some(positional.join(" "))
    };

    Ok(Cli {
        port,
        identities,
        cli_user,
        strict,
        known_hosts_path,
        hash_known_hosts,
        identities_only,
        locals,
        remotes,
        no_command,
        host,
        user_in_host,
        command,
    })
}

fn resolve_user(cli: &Cli) -> Result<String, String> {
    if let Some(u) = &cli.cli_user {
        return Ok(u.clone());
    }
    if let Some(u) = &cli.user_in_host {
        return Ok(u.clone());
    }
    std::env::var("USER").map_err(|_| "no user specified and $USER is unset".into())
}

fn read_password_from_stdin() -> std::io::Result<String> {
    eprint!("password: ");
    std::io::stderr().flush()?;
    let mut s = String::new();
    let mut byte = [0u8; 1];
    let mut stdin = std::io::stdin();
    loop {
        let n = stdin.read(&mut byte)?;
        if n == 0 {
            break;
        }
        if byte[0] == b'\n' {
            break;
        }
        if byte[0] == b'\r' {
            continue;
        }
        s.push(byte[0] as char);
        if s.len() > 4096 {
            break;
        }
    }
    Ok(s)
}

fn load_identity(path: &str) -> Result<PrivateKey, String> {
    let pem = std::fs::read_to_string(path).map_err(|e| format!("read {path}: {e}"))?;
    PrivateKey::parse_openssh_pem(&pem, None)
        .map_err(|e| format!("parse {path}: {e} (passphrase-protected keys not supported here)"))
}

/// Connect to `$SSH_AUTH_SOCK` (if set), list identities, and wrap each as a
/// publickey credential backed by [`AgentHostKey`]. Returns `Ok(empty)` when
/// no agent is reachable — that's an expected "no agent" state, not an
/// error.
fn connect_agent_credentials() -> Result<Vec<ClientCredential>, String> {
    let agent = match Agent::connect_env().map_err(|e| format!("connect: {e}"))? {
        Some(a) => a,
        None => return Ok(Vec::new()),
    };
    let agent = Arc::new(Mutex::new(agent));
    let identities = {
        let mut a = agent
            .lock()
            .map_err(|_| "agent mutex poisoned".to_string())?;
        a.identities().map_err(|e| format!("identities: {e}"))?
    };
    let mut creds: Vec<ClientCredential> = Vec::with_capacity(identities.len());
    for ident in identities {
        match AgentHostKey::from_identity(Arc::clone(&agent), ident.key_blob.clone()) {
            Ok(hk) => creds.push(ClientCredential::PublicKey(Box::new(hk))),
            Err(e) => eprintln!(
                "warning: agent identity {:?}: skipping: {e}",
                ident.comment()
            ),
        }
    }
    Ok(creds)
}

/// Compute the user's default known_hosts path: `$HOME/.ssh/known_hosts`.
fn default_known_hosts_path() -> Option<PathBuf> {
    let home = std::env::var_os("HOME")?;
    Some(PathBuf::from(home).join(".ssh").join("known_hosts"))
}

/// SHA-256 fingerprint, base64-encoded (no padding), formatted as
/// `SHA256:<base64>` — matches `ssh-keygen -lf`.
fn fingerprint_b64_sha256(blob: &[u8]) -> String {
    use purecrypto::hash::{Digest, Sha256};
    let digest = Sha256::digest(blob);
    // Standard base64, no padding, as OpenSSH renders.
    let s = base64_no_pad(digest.as_ref());
    format!("SHA256:{s}")
}

fn base64_no_pad(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    let mut i = 0;
    while i + 3 <= bytes.len() {
        let b = ((bytes[i] as u32) << 16) | ((bytes[i + 1] as u32) << 8) | (bytes[i + 2] as u32);
        out.push(ALPHABET[((b >> 18) & 0x3F) as usize] as char);
        out.push(ALPHABET[((b >> 12) & 0x3F) as usize] as char);
        out.push(ALPHABET[((b >> 6) & 0x3F) as usize] as char);
        out.push(ALPHABET[(b & 0x3F) as usize] as char);
        i += 3;
    }
    let rem = bytes.len() - i;
    if rem == 1 {
        let b = (bytes[i] as u32) << 16;
        out.push(ALPHABET[((b >> 18) & 0x3F) as usize] as char);
        out.push(ALPHABET[((b >> 12) & 0x3F) as usize] as char);
    } else if rem == 2 {
        let b = ((bytes[i] as u32) << 16) | ((bytes[i + 1] as u32) << 8);
        out.push(ALPHABET[((b >> 18) & 0x3F) as usize] as char);
        out.push(ALPHABET[((b >> 12) & 0x3F) as usize] as char);
        out.push(ALPHABET[((b >> 6) & 0x3F) as usize] as char);
    }
    out
}

/// Build the [`HostKeyPolicy`] for the requested strict mode + path.
fn build_host_key_policy(cli: &Cli) -> Result<HostKeyPolicy, String> {
    // `StrictHostKeyChecking=no` is the historical OpenSSH "trust on every
    // connect" mode. We approximate it as AcceptAny since the user has
    // explicitly opted out of the check.
    if cli.strict == StrictMode::No {
        return Ok(HostKeyPolicy::AcceptAny);
    }

    let path = match &cli.known_hosts_path {
        Some(p) => p.clone(),
        None => default_known_hosts_path()
            .ok_or_else(|| "no $HOME, cannot locate default known_hosts".to_string())?,
    };
    let store = KnownHosts::load(&path).map_err(|e| format!("load {}: {e}", path.display()))?;

    let on_unknown = match cli.strict {
        StrictMode::Yes => TofuAction::Reject,
        StrictMode::AcceptNew => TofuAction::Accept,
        StrictMode::Ask => TofuAction::Prompt(Arc::new(tofu_prompt)),
        StrictMode::No => unreachable!(),
    };

    Ok(HostKeyPolicy::KnownHosts(KnownHostsPolicy {
        store: Arc::new(Mutex::new(store)),
        save_path: Some(path),
        hash_new: cli.hash_known_hosts,
        on_unknown,
    }))
}

/// The TOFU prompt — mimics OpenSSH's wording so muscle-memory ports.
fn tofu_prompt(host: &str, port: u16, key_type: &str, key_blob: &[u8]) -> bool {
    let fp = fingerprint_b64_sha256(key_blob);
    let target = if port == 22 {
        host.to_string()
    } else {
        format!("[{host}]:{port}")
    };
    eprintln!("The authenticity of host '{target}' can't be established.");
    eprintln!("{key_type} key fingerprint is {fp}.");
    eprint!("Are you sure you want to continue connecting (yes/no)? ");
    let _ = std::io::stderr().flush();
    let mut line = String::new();
    let mut byte = [0u8; 1];
    let mut stdin = std::io::stdin();
    while let Ok(n) = stdin.read(&mut byte) {
        if n == 0 || byte[0] == b'\n' {
            break;
        }
        if byte[0] == b'\r' {
            continue;
        }
        line.push(byte[0] as char);
        if line.len() > 16 {
            break;
        }
    }
    matches!(line.trim().to_ascii_lowercase().as_str(), "yes" | "y")
}

fn run() -> Result<i32, String> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.iter().any(|a| a == "-h" || a == "--help") {
        println!("{USAGE}");
        println!();
        println!("A pure-Rust SSH client built on puressh {VERSION}.");
        return Ok(0);
    }
    if args.iter().any(|a| a == "-V" || a == "--version") {
        println!("puressh ssh {VERSION}");
        return Ok(0);
    }

    let cli = parse_args(&args).map_err(|e| format!("{e}\n{USAGE}"))?;
    let user = resolve_user(&cli)?;

    let policy = build_host_key_policy(&cli)?;
    let cfg = Config {
        host_key_policy: policy,
        timeout: None,
    };

    // Use connect_to_host so KnownHosts can look the host up by its
    // user-supplied name.
    let mut client = Client::connect_to_host(cli.host.as_str(), cli.port, cfg)
        .map_err(|e| format!("connect: {e}"))?;

    // Collect publickey credentials. Per OpenSSH default, agent identities
    // are tried first (when `$SSH_AUTH_SOCK` is set and `IdentitiesOnly=no`),
    // then `-i` identity files in command-line order.
    let mut credentials: Vec<ClientCredential> = Vec::new();
    if !cli.identities_only {
        match connect_agent_credentials() {
            Ok(mut from_agent) => credentials.append(&mut from_agent),
            Err(e) => eprintln!("warning: agent: {e}"),
        }
    }
    for id_path in &cli.identities {
        let pk = match load_identity(id_path) {
            Ok(p) => p,
            Err(e) => {
                eprintln!("warning: {e}");
                continue;
            }
        };
        match pk.into_host_key() {
            Ok(hk) => credentials.push(ClientCredential::PublicKey(hk)),
            Err(e) => eprintln!("warning: identity {id_path}: {e}"),
        }
    }

    let authed = if !credentials.is_empty() {
        match client.authenticate(&user, credentials) {
            Ok(()) => true,
            Err(e) => {
                eprintln!("publickey auth: {e}");
                false
            }
        }
    } else {
        false
    };

    if !authed {
        // v0 limitation: password input is echoed to the terminal — there is no
        // portable in-tree way to disable terminal echo without adding a dep.
        let password = read_password_from_stdin().map_err(|e| format!("read password: {e}"))?;
        client
            .authenticate_password(&user, &password)
            .map_err(|e| format!("Auth failed: {e}"))?;
    }

    // If any port-forwarding was requested, switch over to the multi-channel
    // serve loop instead of the single-shot exec/shell path. Mixing exec with
    // forwarding on the same client is a follow-up — it needs an outbound-
    // request side channel inside `Client::serve`.
    let want_forwarding = cli.no_command || !cli.remotes.is_empty() || !cli.locals.is_empty();
    if want_forwarding {
        if cli.command.is_some() {
            return Err(
                "running a command alongside -L/-R/-N is not yet supported; \
                        invoke ssh twice or wire the forward without a command"
                    .into(),
            );
        }
        if !cli.locals.is_empty() {
            return Err(
                "-L is parsed but not yet executed by the ssh binary; the lib API \
                        Client::open_direct_tcpip works for single-channel direct-tcpip \
                        from custom code"
                    .into(),
            );
        }
        if cli.remotes.is_empty() && cli.no_command {
            return Err("-N requires at least one -R (or -L when wired)".into());
        }
        return run_forwarding(client, &cli);
    }

    let command = cli
        .command
        .ok_or_else(|| "interactive shell not yet implemented".to_string())?;

    let out = client.exec(&command).map_err(|e| format!("exec: {e}"))?;
    let _ = std::io::stdout().write_all(&out.stdout);
    let _ = std::io::stderr().write_all(&out.stderr);
    Ok(out.exit_status.map(|s| s as i32).unwrap_or(255))
}

/// Splice a `forwarded-tcpip` channel against a fresh outbound `TcpStream`
/// (the local destination the user nominated with `-R RPORT:LHOST:LPORT`).
/// Each direction runs on its own thread; when one side finishes we emit
/// EOF/Close on the channel and `shutdown(Read)` on the TCP socket so the
/// other thread unblocks and exits. Mirrors `forwarding::reverse::spawn_splice`
/// but for the client side.
fn spawn_splice_to_tcp(stream: ChannelStream, tcp: TcpStream) {
    use puressh::client::ChannelEgress;
    let (chan_rx, chan_tx) = stream.into_raw();
    let tcp_in = match tcp.try_clone() {
        Ok(c) => c,
        Err(_) => {
            let _ = chan_tx.send(ChannelEgress::Eof);
            let _ = chan_tx.send(ChannelEgress::Close);
            return;
        }
    };
    let tcp_out = tcp;

    // TCP → channel.
    let chan_tx_a = chan_tx.clone();
    let mut tcp_in_a = tcp_in;
    let a = thread::spawn(move || {
        let mut buf = [0u8; 32 * 1024];
        loop {
            match tcp_in_a.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    if chan_tx_a
                        .send(ChannelEgress::Data(buf[..n].to_vec()))
                        .is_err()
                    {
                        break;
                    }
                }
                Err(e) if e.kind() == ErrorKind::Interrupted => continue,
                Err(_) => break,
            }
        }
        let _ = chan_tx_a.send(ChannelEgress::Eof);
    });

    // Channel → TCP.
    let mut tcp_out_b = tcp_out;
    let b = thread::spawn(move || {
        while let Ok(Some(chunk)) = chan_rx.recv() {
            if tcp_out_b.write_all(&chunk).is_err() {
                break;
            }
        }
        let _ = tcp_out_b.shutdown(std::net::Shutdown::Read);
    });

    // Reaper: emit Close once both halves are done.
    thread::spawn(move || {
        let _ = a.join();
        let _ = b.join();
        let _ = chan_tx.send(ChannelEgress::Close);
    });
}

/// Drive the multi-channel forwarding loop: register every `-R` binding on the
/// server, install an `on_forwarded_tcpip` callback that dials the user's
/// local destination per accepted connection, then enter
/// [`Client::serve`] until either the peer hangs up or the process is killed.
///
/// Returns an exit code matching OpenSSH's `-N -R` behaviour: 0 on a clean
/// peer disconnect, 255 on protocol error.
fn run_forwarding(mut client: Client, cli: &Cli) -> Result<i32, String> {
    // Map "(bound_address, bound_port) → (local_host, local_port)" so the
    // callback can look up the right local destination for each incoming
    // forward. The bound address echoed by the server is "127.0.0.1" since
    // that's what we ask for below.
    let mut routes: std::collections::BTreeMap<(String, u16), (String, u16)> =
        std::collections::BTreeMap::new();
    for r in &cli.remotes {
        let bound_port = client
            .request_tcpip_forward("127.0.0.1", r.remote_port)
            .map_err(|e| format!("tcpip-forward 127.0.0.1:{}: {e}", r.remote_port))?;
        eprintln!(
            "ssh: -R 127.0.0.1:{}:{}:{} active",
            bound_port, r.local_host, r.local_port,
        );
        routes.insert(
            ("127.0.0.1".to_string(), bound_port),
            (r.local_host.clone(), r.local_port),
        );
    }

    let routes = Arc::new(Mutex::new(routes));
    let routes_for_cb = Arc::clone(&routes);
    let cb: Arc<ForwardedTcpipCallback> =
        Arc::new(move |origin: ForwardedTcpipOrigin, stream: ChannelStream| {
            let target = {
                let map = match routes_for_cb.lock() {
                    Ok(g) => g,
                    Err(_) => return,
                };
                map.get(&(origin.bound_address.clone(), origin.bound_port))
                    .cloned()
            };
            let (local_host, local_port) = match target {
                Some(t) => t,
                None => {
                    eprintln!(
                        "ssh: forwarded-tcpip for unknown binding {}:{}; dropping",
                        origin.bound_address, origin.bound_port
                    );
                    return;
                }
            };
            match TcpStream::connect((local_host.as_str(), local_port)) {
                Ok(tcp) => spawn_splice_to_tcp(stream, tcp),
                Err(e) => eprintln!(
                    "ssh: dial {}:{} for forwarded-tcpip from {}:{}: {e}",
                    local_host, local_port, origin.orig_address, origin.orig_port
                ),
            }
        });

    let handlers = ClientHandlers::new().with_forwarded_tcpip(cb);
    match client.serve(handlers) {
        Ok(()) => Ok(0),
        Err(e) => Err(format!("serve: {e}")),
    }
}

fn main() -> ExitCode {
    match run() {
        Ok(code) => {
            let clamped = code.clamp(0, 255) as u8;
            ExitCode::from(clamped)
        }
        Err(msg) => {
            eprintln!("ssh: {msg}");
            ExitCode::from(255)
        }
    }
}
