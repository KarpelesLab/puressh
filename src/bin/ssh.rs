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
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::{Arc, Mutex};
use std::thread;

use puressh::auth::ClientCredential;
use puressh::client::{
    ChannelStream, Client, ClientHandlers, Config, ForwardedTcpipCallback, ForwardedTcpipOrigin,
    ServeContext,
};

#[path = "common.rs"]
mod common;
use common::{
    build_host_key_policy, connect_agent_credentials, default_identity_paths, load_identity,
    read_password_from_stdin, resolve_user, set_verbose, try_load_default_identity, vlog,
    StrictMode,
};

const VERSION: &str = env!("CARGO_PKG_VERSION");

const USAGE: &str = "usage: ssh [-v[v[v]]] [-p port] [-i identity_file] [-l user] \
                     [-o StrictHostKeyChecking={yes,no,accept-new,ask}] \
                     [-o UserKnownHostsFile=PATH] [-o HashKnownHosts={yes,no}] \
                     [-o IdentitiesOnly={yes,no}] \
                     [-L LPORT:RHOST:RPORT] [-R RPORT:LHOST:LPORT] \
                     [-N] [-A] [-X] [-Y] \
                     [user@]host [command...]";

/// Parsed `-L LPORT:RHOST:RPORT` spec — client binds `LPORT` on loopback;
/// each accepted connection becomes a `direct-tcpip` channel to the server
/// targeting `RHOST:RPORT`. Each forward gets a dedicated accept thread
/// that drives [`ServeContext::open_direct_tcpip`] per connection.
#[derive(Clone, Debug)]
struct LocalForward {
    /// Local port to bind on `127.0.0.1`.
    listen_port: u16,
    /// Destination hostname/IP the server is asked to dial.
    remote_host: String,
    /// Destination TCP port.
    remote_port: u16,
}

/// Parsed `-X` / `-Y` mode. `Untrusted` corresponds to `-X` (untrusted X11
/// forwarding); `Trusted` to `-Y`. In v0 both modes emit identical wire
/// arguments (`single_connection=false`, screen 0, generated cookie). The
/// distinction is retained so a follow-up can split them — minting a fresh
/// cookie via `xauth` for `-X` and forwarding the real `$XAUTHORITY` cookie
/// for `-Y`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum X11Forward {
    Untrusted,
    Trusted,
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
    /// OpenSSH-style verbose level: `-v` → 1, `-vv` → 2, `-vvv` → 3.
    /// Repeated single `-v`s also stack and saturate at 3. Drives
    /// `common::vlog` — see [`common::set_verbose`].
    verbose: u8,
    /// `-A`: ask the server to forward the local ssh-agent. The lib sends
    /// `auth-agent-req@openssh.com` on the session channel; incoming
    /// `auth-agent@openssh.com` channels get spliced against
    /// `$SSH_AUTH_SOCK` via `ClientHandlers::on_auth_agent`.
    agent_forward: bool,
    /// `-X` (untrusted) / `-Y` (trusted): ask the server to forward X11.
    /// The lib sends `x11-req` on the session channel; incoming `x11`
    /// channels get spliced against `$DISPLAY` via
    /// `ClientHandlers::on_x11`. `None` = no X11; in v0 `-X` and `-Y`
    /// both set the same wire arguments (no untrusted cookie minting).
    x11_forward: Option<X11Forward>,
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
    let mut agent_forward = false;
    let mut x11_forward: Option<X11Forward> = None;
    let mut verbose: u8 = 0;
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
            "-A" => {
                agent_forward = true;
            }
            "-X" => {
                x11_forward = Some(X11Forward::Untrusted);
            }
            "-Y" => {
                x11_forward = Some(X11Forward::Trusted);
            }
            // OpenSSH-style verbosity. Accept the stacked forms `-vv` /
            // `-vvv` as single tokens (the common way users type them),
            // plus repeated `-v` which also accumulates.
            "-v" => {
                verbose = verbose.saturating_add(1).min(3);
            }
            "-vv" => {
                verbose = verbose.max(2);
            }
            "-vvv" => {
                verbose = 3;
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
        agent_forward,
        x11_forward,
        verbose,
        host,
        user_in_host,
        command,
    })
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
    set_verbose(cli.verbose);
    let user = resolve_user(cli.cli_user.as_deref(), cli.user_in_host.as_deref())?;

    let policy = build_host_key_policy(
        cli.strict,
        cli.known_hosts_path.clone(),
        cli.hash_known_hosts,
    )?;
    let cfg = Config {
        host_key_policy: policy,
        timeout: None,
    };

    // Use connect_to_host so KnownHosts can look the host up by its
    // user-supplied name.
    vlog(1, &format!("connecting to {}:{}", cli.host, cli.port));
    let mut client = Client::connect_to_host(cli.host.as_str(), cli.port, cfg)
        .map_err(|e| format!("connect: {e}"))?;
    vlog(1, &format!("connected to {}:{}", cli.host, cli.port));

    // Collect publickey credentials. Per OpenSSH default, agent identities
    // come first (when `$SSH_AUTH_SOCK` is set and `IdentitiesOnly=no`),
    // then `-i` identity files in command-line order, then the OpenSSH
    // default identities under `~/.ssh/` (`id_ed25519`, `id_ecdsa`,
    // `id_rsa`). `IdentitiesOnly=yes` suppresses both the agent and the
    // defaults, mirroring OpenSSH.
    let mut credentials: Vec<ClientCredential> = Vec::new();
    if !cli.identities_only {
        match connect_agent_credentials() {
            Ok(mut from_agent) => {
                if !from_agent.is_empty() {
                    vlog(
                        1,
                        &format!("agent contributed {} identities", from_agent.len()),
                    );
                }
                credentials.append(&mut from_agent);
            }
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
            Ok(hk) => {
                vlog(1, &format!("identity {id_path}: loaded"));
                credentials.push(ClientCredential::PublicKey(hk));
            }
            Err(e) => eprintln!("warning: identity {id_path}: {e}"),
        }
    }
    if !cli.identities_only {
        for path in default_identity_paths() {
            match try_load_default_identity(&path) {
                Ok(Some(pk)) => match pk.into_host_key() {
                    Ok(hk) => {
                        vlog(1, &format!("default identity {}: loaded", path.display()));
                        credentials.push(ClientCredential::PublicKey(hk));
                    }
                    Err(e) => {
                        eprintln!("warning: default identity {}: {e}", path.display());
                    }
                },
                Ok(None) => {
                    vlog(2, &format!("default identity {}: skipped", path.display()));
                }
                Err(msg) => eprintln!("warning: {msg}"),
            }
        }
    }

    let authed = if !credentials.is_empty() {
        vlog(
            1,
            &format!(
                "attempting publickey auth with {} credentials",
                credentials.len()
            ),
        );
        match client.authenticate(&user, credentials) {
            Ok(()) => {
                vlog(1, &format!("authenticated as {user} via publickey"));
                true
            }
            Err(e) => {
                eprintln!("publickey auth: {e}");
                false
            }
        }
    } else {
        vlog(
            1,
            "no publickey credentials available; falling back to password",
        );
        false
    };

    if !authed {
        // Password reader honors $SSH_ASKPASS and suppresses terminal echo
        // on Unix via termios (see src/bin/common.rs). On Windows / when the
        // tty layer is unavailable, the user is warned and a plain read is
        // used as a last resort.
        let password = read_password_from_stdin().map_err(|e| format!("read password: {e}"))?;
        client
            .authenticate_password(&user, &password)
            .map_err(|e| format!("Auth failed: {e}"))?;
        vlog(1, &format!("authenticated as {user} via password"));
    }

    // If any port-forwarding was requested, switch over to the multi-channel
    // serve loop instead of the single-shot exec/shell path. Mixing exec with
    // forwarding on the same client is a follow-up — it needs the serve loop
    // to also drive a session channel concurrently.
    //
    // `-A` (agent forwarding) also routes through the serve loop: it needs a
    // session channel open (for the `auth-agent-req@openssh.com` request)
    // plus concurrent handling of incoming `auth-agent@openssh.com` channels,
    // which is exactly the multi-channel shape.
    let want_forwarding = cli.no_command
        || !cli.remotes.is_empty()
        || !cli.locals.is_empty()
        || cli.agent_forward
        || cli.x11_forward.is_some();
    if want_forwarding {
        if cli.command.is_some() {
            return Err(
                "running a command alongside -A/-L/-R/-N/-X/-Y is not yet supported; \
                        invoke ssh twice or wire the forward without a command"
                    .into(),
            );
        }
        if cli.no_command
            && cli.remotes.is_empty()
            && cli.locals.is_empty()
            && !cli.agent_forward
            && cli.x11_forward.is_none()
        {
            return Err("-N requires at least one of -A, -L, -R, -X, -Y".into());
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

    let mut handlers = ClientHandlers::new().with_forwarded_tcpip(cb);

    // -A: install an `on_auth_agent` that splices each incoming
    // `auth-agent@openssh.com` channel against the local `$SSH_AUTH_SOCK`.
    // Then open a session channel up front so `auth-agent-req@openssh.com`
    // can ride on it; the channel stays open for the lifetime of the serve
    // loop. We close it at the end so the server unlinks its
    // `SSH_AUTH_SOCK`.
    let agent_fwd_channel: Option<u32> = if cli.agent_forward {
        // Agent forwarding routes through `$SSH_AUTH_SOCK`, a Unix-domain
        // socket. The forwarding implementation lives behind `cfg(unix)`
        // in `puressh::forwarding::agent`, so on Windows we hard-fail
        // rather than silently ignoring `-A`.
        #[cfg(unix)]
        {
            use puressh::forwarding::agent::splice_to_local_agent_callback;
            let cb = splice_to_local_agent_callback().ok_or_else(|| {
                "-A: $SSH_AUTH_SOCK is unset or names a socket that doesn't exist".to_string()
            })?;
            handlers = handlers.with_auth_agent(cb);
            let id = client
                .open_session_for_agent_forward()
                .map_err(|e| format!("agent-forward session: {e}"))?;
            eprintln!("ssh: -A agent forwarding requested");
            Some(id)
        }
        #[cfg(not(unix))]
        {
            return Err("-A agent forwarding is not supported on this platform".to_string());
        }
    } else {
        None
    };

    // -X / -Y: install an `on_x11` callback that splices each incoming `x11`
    // channel against the local `$DISPLAY`, then open a session channel up
    // front so `x11-req` can ride on it. The channel stays open for the
    // lifetime of the serve loop. We close it at the end so the server
    // tears down its display listener.
    //
    // v0: `-X` and `-Y` are identical on the wire — both send
    // `single_connection=false`, screen 0, MIT-MAGIC-COOKIE-1, and a fresh
    // random cookie (we don't yet shell out to `xauth` for the real one).
    // The server passes the cookie through to the on-server display socket
    // verbatim; the local `on_x11` callback splices against `$DISPLAY`
    // without rewriting the X-protocol auth record. Cookie substitution
    // (untrusted-X11 isolation) is a follow-up.
    let x11_fwd_channel: Option<u32> = if let Some(mode) = cli.x11_forward {
        // X11 forwarding dials `$DISPLAY` — either a TCP `host:N` form or
        // a `/tmp/.X11-unix/X<N>` Unix-domain socket. The forwarding
        // implementation in `puressh::forwarding::x11` is `cfg(unix)` for
        // the UDS case, so we gate the consumer here too.
        #[cfg(not(unix))]
        {
            let _ = mode;
            return Err("-X/-Y X11 forwarding is not supported on this platform".to_string());
        }
        #[cfg(unix)]
        {
            use puressh::forwarding::x11::splice_to_local_display_callback;
            let cb = splice_to_local_display_callback().ok_or_else(|| {
                "-X/-Y: $DISPLAY is unset or names a display we don't know how to dial".to_string()
            })?;
            handlers = handlers.with_x11(cb);
            let cookie = mint_x11_cookie()?;
            let id = client
                .open_session_for_x11_forward(false, "MIT-MAGIC-COOKIE-1", &cookie, 0)
                .map_err(|e| format!("x11-forward session: {e}"))?;
            eprintln!(
                "ssh: -{} X11 forwarding requested (cookie={} chars)",
                if mode == X11Forward::Trusted {
                    "Y"
                } else {
                    "X"
                },
                cookie.len(),
            );
            Some(id)
        }
    } else {
        None
    };

    // -L: bind every configured local-forward listener and hand each one a
    // clone of the ServeContext so its accept thread can open `direct-tcpip`
    // through the running serve loop.
    let ctx_opt: Option<ServeContext> = if cli.locals.is_empty() {
        None
    } else {
        let (h, ctx) = handlers.with_serve_context();
        handlers = h;
        for l in &cli.locals {
            let listener = TcpListener::bind(("127.0.0.1", l.listen_port))
                .map_err(|e| format!("-L bind 127.0.0.1:{}: {e}", l.listen_port))?;
            eprintln!(
                "ssh: -L 127.0.0.1:{}:{}:{} active",
                l.listen_port, l.remote_host, l.remote_port,
            );
            spawn_local_forward_listener(listener, l.clone(), ctx.clone());
        }
        Some(ctx)
    };

    let result = match client.serve(handlers) {
        Ok(()) => Ok(0),
        Err(e) => Err(format!("serve: {e}")),
    };

    // Tear down the agent-forwarding session channel if we opened one.
    if let Some(id) = agent_fwd_channel {
        let _ = client.close_session(id);
    }
    // Same for the X11-forwarding session channel.
    if let Some(id) = x11_fwd_channel {
        let _ = client.close_session(id);
    }
    // Hold the original ctx until serve returns so cmd_tx isn't dropped
    // (the listener threads keep their clones, so this is belt-and-braces).
    drop(ctx_opt);
    result
}

/// Per-`-L` accept loop. Each accepted TCP connection becomes one
/// `direct-tcpip` channel via the serve loop; we then splice the channel
/// stream against the TCP socket in both directions until either side
/// closes.
///
/// Mirrors [`spawn_splice_to_tcp`] but for the outbound side: there's no
/// `forwarded-tcpip` channel; instead we wait for [`ServeContext::open_direct_tcpip`]
/// to return the freshly-opened [`ChannelStream`] before splicing.
fn spawn_local_forward_listener(listener: TcpListener, spec: LocalForward, ctx: ServeContext) {
    thread::spawn(move || {
        for accept in listener.incoming() {
            let tcp = match accept {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("ssh: -L accept on 127.0.0.1:{}: {e}", spec.listen_port);
                    continue;
                }
            };
            let orig = tcp
                .peer_addr()
                .map(|a| (a.ip().to_string(), a.port()))
                .unwrap_or_else(|_| ("127.0.0.1".to_string(), 0));
            let stream =
                match ctx.open_direct_tcpip(&spec.remote_host, spec.remote_port, &orig.0, orig.1) {
                    Ok(s) => s,
                    Err(e) => {
                        eprintln!(
                            "ssh: -L direct-tcpip {}:{}: {e}",
                            spec.remote_host, spec.remote_port
                        );
                        continue;
                    }
                };
            spawn_splice_to_tcp(stream, tcp);
        }
    });
}

/// Mint a fresh MIT-MAGIC-COOKIE-1 value (32 hex chars from 16 random bytes).
/// OpenSSH normally reads the real cookie out of `$XAUTHORITY` via `xauth
/// list`; we don't yet, so untrusted (`-X`) and trusted (`-Y`) currently
/// share the same generated cookie.
///
/// Security: this is a credential. We seed it strictly from purecrypto's
/// `OsRng` (the same CSPRNG the rest of the crate uses for session keys).
/// We deliberately do NOT mix in PID + wall-clock nanoseconds as a fallback
/// — those are low-entropy and would mask an underlying RNG fault. If the
/// OS RNG isn't available `OsRng::fill_bytes` panics, which is the only
/// safe behaviour: we cannot forward X11 with a guessable cookie.
///
/// X11 forwarding is Unix-only (the channel handlers depend on Unix-domain
/// sockets), so this helper is too — gating keeps Windows builds clean.
#[cfg(unix)]
fn mint_x11_cookie() -> Result<String, String> {
    use purecrypto::rng::{OsRng, RngCore};
    let mut bytes = [0u8; 16];
    OsRng.fill_bytes(&mut bytes);
    // Defence in depth: if for some reason `fill_bytes` returned a buffer
    // of all-zero bytes (i.e. the OS RNG produced nothing observable), bail
    // rather than emit a known-weak cookie. A 16-byte all-zero read from a
    // healthy CSPRNG has probability 2^-128, so this only catches "RNG is
    // returning a fixed value" type faults, not legitimate output.
    if bytes.iter().all(|&b| b == 0) {
        return Err("x11 cookie: OS RNG returned all-zero entropy; refusing to forward".into());
    }
    let mut s = String::with_capacity(32);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    Ok(s)
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
