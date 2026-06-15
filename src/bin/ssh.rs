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
    StrictMode, build_host_key_policy, connect_agent_credentials, default_identity_paths,
    expand_tilde, load_identity, parse_target, read_password_from_stdin, resolve_user, set_verbose,
    try_load_default_identity, vlog,
};

const VERSION: &str = env!("CARGO_PKG_VERSION");

const USAGE: &str = "usage: ssh [-v[v[v]]] [-F configfile] [-p port] [-i identity_file] [-l user] \
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
    /// `-F path`: load this `ssh_config` instead of the defaults.
    config_file: Option<PathBuf>,
    /// `None` when `-p` wasn't supplied; the ssh_config `Port` then wins.
    port: Option<u16>,
    identities: Vec<String>,
    cli_user: Option<String>,
    /// `None` when `-o StrictHostKeyChecking=…` wasn't supplied.
    strict: Option<StrictMode>,
    known_hosts_path: Option<PathBuf>,
    /// `None` when `-o HashKnownHosts=…` wasn't supplied.
    hash_known_hosts: Option<bool>,
    /// `None` when `-o IdentitiesOnly=…` wasn't supplied.
    identities_only: Option<bool>,
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

/// Parse one `-L` arg value: `LPORT:RHOST:RPORT`. `RHOST` may be a bare
/// IPv4 / hostname, a bare IPv6 literal, OR an RFC-3986 bracketed IPv6
/// literal (`[2001:db8::1]`) — the bracketed form is needed for v6
/// because the literal itself contains colons that the `:`-split below
/// would otherwise mangle.
fn parse_local_forward(s: &str) -> Result<LocalForward, String> {
    let (listen_port, remote_host, remote_port) = split_forward_triple(s, "-L")?;
    Ok(LocalForward {
        listen_port,
        remote_host,
        remote_port,
    })
}

/// Parse one `-R` arg value: `RPORT:LHOST:LPORT`. Same v6 rules as `-L`.
fn parse_remote_forward(s: &str) -> Result<RemoteForward, String> {
    let (remote_port, local_host, local_port) = split_forward_triple(s, "-R")?;
    Ok(RemoteForward {
        remote_port,
        local_host,
        local_port,
    })
}

/// Common splitter for `-L` / `-R` triples: `PORT:HOST:PORT`. Handles a
/// bracketed-IPv6 middle field by skipping past the `]` before looking
/// for the second `:` separator. The `flag` argument is the originating
/// CLI flag name (e.g. `"-L"`) for the error messages.
fn split_forward_triple(s: &str, flag: &str) -> Result<(u16, String, u16), String> {
    // First `:` ends the leading port. Always unambiguous — a port is
    // numeric, no colons.
    let (port1_str, after_p1) = s
        .split_once(':')
        .ok_or_else(|| format!("{flag} expects PORT:HOST:PORT, got {s:?}"))?;
    let port1: u16 = port1_str
        .parse()
        .map_err(|_| format!("{flag}: invalid leading port {port1_str:?}"))?;

    // Middle host field: bracketed v6 or plain.
    let (host, after_host) = if let Some(rest) = after_p1.strip_prefix('[') {
        // [v6]:port form — find the closing `]`. The host token is
        // taken verbatim; we don't validate v6 here because the kernel
        // will (TcpStream::connect) and a stricter check would just
        // duplicate that work without catching anything user-meaningful.
        let close = rest
            .find(']')
            .ok_or_else(|| format!("{flag}: missing `]` in {s:?}"))?;
        let host = rest[..close].to_string();
        let after = &rest[close + 1..];
        let after = after
            .strip_prefix(':')
            .ok_or_else(|| format!("{flag}: expected `:port` after `]` in {s:?}"))?;
        (host, after)
    } else {
        // Plain `host:port` — split on the FIRST `:`. A bare v6 with no
        // brackets is ambiguous in this position (the colons of the
        // address collide with the port separator); we require brackets
        // for v6, matching OpenSSH's `-L` behaviour.
        let (h, p) = after_p1
            .split_once(':')
            .ok_or_else(|| format!("{flag} expects PORT:HOST:PORT, got {s:?}"))?;
        if h.is_empty() {
            return Err(format!("{flag}: HOST cannot be empty"));
        }
        (h.to_string(), p)
    };
    if host.is_empty() {
        return Err(format!("{flag}: HOST cannot be empty"));
    }
    let port2: u16 = after_host
        .parse()
        .map_err(|_| format!("{flag}: invalid trailing port {after_host:?}"))?;
    Ok((port1, host, port2))
}

fn parse_args(args: &[String]) -> Result<Cli, String> {
    let mut config_file: Option<PathBuf> = None;
    let mut port: Option<u16> = None;
    let mut identities: Vec<String> = Vec::new();
    let mut cli_user: Option<String> = None;
    let mut strict: Option<StrictMode> = None;
    let mut known_hosts_path: Option<PathBuf> = None;
    let mut hash_known_hosts: Option<bool> = None;
    let mut identities_only: Option<bool> = None;
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
                port = Some(v.parse::<u16>().map_err(|_| "invalid port".to_string())?);
            }
            "-F" => {
                i += 1;
                let v = args.get(i).ok_or("-F requires a value")?.clone();
                config_file = Some(PathBuf::from(v));
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
                        strict = Some(match val.to_ascii_lowercase().as_str() {
                            "yes" => StrictMode::Yes,
                            "no" | "off" => StrictMode::No,
                            "accept-new" => StrictMode::AcceptNew,
                            "ask" => StrictMode::Ask,
                            other => return Err(format!("unknown StrictHostKeyChecking={other}")),
                        });
                    }
                    "userknownhostsfile" => {
                        known_hosts_path = Some(PathBuf::from(val));
                    }
                    "hashknownhosts" => {
                        hash_known_hosts =
                            Some(matches!(val.to_ascii_lowercase().as_str(), "yes" | "on"));
                    }
                    "identitiesonly" => {
                        identities_only =
                            Some(matches!(val.to_ascii_lowercase().as_str(), "yes" | "on"));
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
    // parse_target accepts `[user@]host[:port]` and handles bare /
    // bracketed IPv6 literals (`2001:db8::1`, `[2001:db8::1]:22`).
    // The returned port is `Some(p)` only when the target carried an
    // explicit one — `-p` keeps wining over a missing target port.
    let (user_in_host, host, target_port) = parse_target(&target)?;
    // `-p` wins over a target-embedded port; an embedded port only
    // takes effect if `-p` was not supplied.
    if port.is_none() {
        port = target_port;
    }
    let command = if positional.is_empty() {
        None
    } else {
        Some(positional.join(" "))
    };

    Ok(Cli {
        config_file,
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

    let mut cli = parse_args(&args).map_err(|e| format!("{e}\n{USAGE}"))?;
    set_verbose(cli.verbose);

    // Resolve the ssh_config block matching the user-typed host name. CLI
    // values then take precedence over the block; the block over built-in
    // defaults (OpenSSH's documented order).
    let ssh_cfg = common::load_client_config(cli.config_file.as_deref())?;
    let cfg_block = ssh_cfg.lookup(&cli.host);

    // Append ssh_config-supplied forwards alongside `-L` / `-R` from the CLI.
    // (Both lists are additive; OpenSSH treats `LocalForward` entries the
    // same as `-L` arguments.)
    for lf in &cfg_block.local_forwards {
        cli.locals.push(LocalForward {
            listen_port: lf.listen_port,
            remote_host: lf.remote_host.clone(),
            remote_port: lf.remote_port,
        });
    }
    for rf in &cfg_block.remote_forwards {
        cli.remotes.push(RemoteForward {
            remote_port: rf.remote_port,
            local_host: rf.local_host.clone(),
            local_port: rf.local_port,
        });
    }
    // `ForwardAgent yes` / `ForwardX11 yes` flip the CLI-side toggles if the
    // user didn't already set them. (The flag form has no "off" — once `-A`
    // is on, it's on; config-driven enable matches that.)
    if !cli.agent_forward && cfg_block.forward_agent == Some(true) {
        cli.agent_forward = true;
    }
    if cli.x11_forward.is_none() && cfg_block.forward_x11 == Some(true) {
        cli.x11_forward = Some(if cfg_block.forward_x11_trusted == Some(true) {
            X11Forward::Trusted
        } else {
            X11Forward::Untrusted
        });
    }
    if cli.verbose == 0
        && let Some(level) = cfg_block.log_level
    {
        set_verbose(level);
    }

    // CLI `-l user` > config `User` > `user@host` syntax > $USER.
    let cli_user = cli.cli_user.clone().or_else(|| cfg_block.user.clone());
    let user = resolve_user(cli_user.as_deref(), cli.user_in_host.as_deref())?;

    let strict = common::pick(cli.strict, cfg_block.strict_host_key, StrictMode::Ask);
    let known_hosts_path = cli
        .known_hosts_path
        .clone()
        .or_else(|| cfg_block.user_known_hosts.as_ref().map(PathBuf::from));
    let hash_known_hosts = common::pick(cli.hash_known_hosts, cfg_block.hash_known_hosts, false);
    let identities_only = common::pick(cli.identities_only, cfg_block.identities_only, false);
    let port = common::pick(cli.port, cfg_block.port, 22);
    // `HostName` rewrites the connect target; the original `cli.host` is
    // what we *displayed* and what the config block matched on.
    let connect_host = cfg_block
        .host_name
        .clone()
        .unwrap_or_else(|| cli.host.clone());

    let policy = build_host_key_policy(strict, known_hosts_path, hash_known_hosts)?;
    let cfg = Config {
        host_key_policy: policy,
        timeout: None,
    };

    // Use connect_to_host so KnownHosts can look the host up by its
    // user-supplied name.
    vlog(1, &format!("connecting to {connect_host}:{port}"));
    let mut client = Client::connect_to_host(connect_host.as_str(), port, cfg)
        .map_err(|e| format!("connect: {e}"))?;
    vlog(1, &format!("connected to {connect_host}:{port}"));

    // Collect publickey credentials. Per OpenSSH default, agent identities
    // come first (when `$SSH_AUTH_SOCK` is set and `IdentitiesOnly=no`),
    // then `-i` identity files in command-line order, then the OpenSSH
    // default identities under `~/.ssh/` (`id_ed25519`, `id_ecdsa`,
    // `id_rsa`). `IdentitiesOnly=yes` suppresses both the agent and the
    // defaults, mirroring OpenSSH.
    let mut credentials: Vec<ClientCredential> = Vec::new();
    if !identities_only {
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
    // Also load identities listed in the matching ssh_config block.
    for id_path_raw in &cfg_block.identity_files {
        let id_path = expand_tilde(id_path_raw);
        let pk = match load_identity(&id_path) {
            Ok(p) => p,
            Err(e) => {
                eprintln!("warning: {e}");
                continue;
            }
        };
        match pk.into_host_key() {
            Ok(hk) => {
                vlog(1, &format!("config identity {id_path}: loaded"));
                credentials.push(ClientCredential::PublicKey(hk));
            }
            Err(e) => eprintln!("warning: config identity {id_path}: {e}"),
        }
    }
    if !identities_only {
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

    if let Some(command) = cli.command {
        let out = client.exec(&command).map_err(|e| format!("exec: {e}"))?;
        let _ = std::io::stdout().write_all(&out.stdout);
        let _ = std::io::stderr().write_all(&out.stderr);
        return Ok(out.exit_status.map(|s| s as i32).unwrap_or(255));
    }

    // No command on the CLI → interactive shell. Hand the connection
    // off to the SharedClient-driven runner so the SIGWINCH thread can
    // call back into the same SSH connection without contending with
    // the I/O threads.
    let shared: puressh::shared::SharedClient = client.into();
    #[cfg(unix)]
    {
        if stdin_is_tty() {
            run_interactive_pty_shell(shared)
        } else {
            run_interactive_pipe_shell(shared)
        }
    }
    #[cfg(not(unix))]
    {
        // Windows: no PTY plumbing yet. The pipe path is portable —
        // splice stdin/stdout/stderr against a no-PTY shell. The
        // remote login shell will run line-buffered; not great for
        // interactive use but useful for scripts.
        let _ = shared;
        Err(
            "interactive shell on non-Unix needs the pipe fallback path, which has \
             not been wired up for Windows in this version"
                .into(),
        )
    }
}

/// `isatty(0)` — true if stdin is connected to a terminal. We only
/// allocate a PTY when this is the case (matching OpenSSH `ssh host`
/// behaviour when stdin is redirected from a file or a pipe).
#[cfg(unix)]
fn stdin_is_tty() -> bool {
    // nix's IsAtty helper is feature-gated and not in our nix flags;
    // call libc directly under the bin's own unsafe (binaries are
    // outside the lib's `forbid(unsafe_code)`).
    unsafe { nix::libc::isatty(0) == 1 }
}

/// Run an interactive shell with a real PTY:
///   1. capture local terminal size + termios
///   2. switch local TTY into raw mode (restored on Drop)
///   3. open the remote shell with our `term`/dimensions/modes
///   4. spawn three I/O threads (stdin→remote, remote-stdout→1,
///      remote-stderr→2) and a SIGWINCH watcher that sends
///      window-change requests on local resize
///   5. wait for the I/O threads to finish, then read exit-status
#[cfg(unix)]
fn run_interactive_pty_shell(shared: puressh::shared::SharedClient) -> Result<i32, String> {
    use std::sync::atomic::{AtomicBool, Ordering};

    // 1. Geometry.
    let (cols, rows, px_w, px_h) = query_window_size();
    let term = std::env::var("TERM").unwrap_or_else(|_| "xterm".to_string());

    // 2. Termios capture + raw mode.
    let mut original_termios: nix::libc::termios = unsafe { core::mem::zeroed() };
    let tcget_ok = unsafe { nix::libc::tcgetattr(0, &mut original_termios) } == 0;
    let modes = if tcget_ok {
        puressh::client::encode_termios_modes(&original_termios)
    } else {
        Vec::new()
    };
    let _raw_guard = if tcget_ok {
        Some(common::TermiosRawGuard::install(&original_termios))
    } else {
        None
    };

    // 3. Open the remote shell.
    let stream = shared
        .shell_stream(&term, cols, rows, px_w, px_h, modes)
        .map_err(|e| format!("shell: {e}"))?;
    let channel_id = stream.channel_id();

    // Short read timeout so the channel-reader pump releases the
    // SharedClient mutex periodically. The stdin → channel writer thread
    // and the SIGWINCH watcher both need to acquire that mutex, and
    // without the timeout the reader would park indefinitely in the
    // socket read while there's nothing to read — wedging the writer.
    let _ = shared.set_read_timeout(Some(std::time::Duration::from_millis(50)));

    // 4. Three I/O threads. We do NOT wrap the OwnedChannelStream in a
    //    mutex — that would serialise the read pump and the write path
    //    on the outer lock and deadlock interactive sessions. Instead
    //    the reader thread owns the stream; the writer thread issues
    //    sends via `SharedClient::channel_send_data` / `channel_send_eof`
    //    keyed by `channel_id`, which goes through the inner mutex
    //    independently and yields between pump iterations.
    let stdout_done = Arc::new(AtomicBool::new(false));

    // stdin → channel.
    let writer_shared = shared.clone();
    let t_in = thread::spawn(move || {
        let mut buf = [0u8; 8 * 1024];
        let mut stdin = std::io::stdin();
        loop {
            match stdin.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    let mut off = 0;
                    while off < n {
                        match writer_shared.channel_send_data(channel_id, &buf[off..n]) {
                            Ok(0) => return,
                            Err(_) => return,
                            Ok(taken) => off += taken,
                        }
                    }
                }
                Err(e) if e.kind() == ErrorKind::Interrupted => continue,
                Err(_) => break,
            }
        }
        // Half-close the write side so the remote shell sees EOF on
        // its stdin. We don't close the channel — the remote stdout
        // is probably still draining.
        let _ = writer_shared.channel_send_eof(channel_id);
    });

    // channel → stdout. Owns the stream — no outer mutex.
    let stdout_flag = stdout_done.clone();
    let (stream_tx, stream_rx) = std::sync::mpsc::channel::<puressh::shared::OwnedChannelStream>();
    let t_out = thread::spawn(move || {
        let mut stream = stream;
        let mut buf = [0u8; 32 * 1024];
        let mut stdout = std::io::stdout();
        loop {
            match stream.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    if stdout.write_all(&buf[..n]).is_err() {
                        break;
                    }
                    let _ = stdout.flush();
                }
                Err(_) => break,
            }
        }
        stdout_flag.store(true, Ordering::Relaxed);
        // Hand the stream out so the main thread can pull exit-status
        // and run Drop (which sends CHANNEL_CLOSE).
        let _ = stream_tx.send(stream);
    });

    // channel.stderr → stderr. Reads via the SharedClient directly so
    // it doesn't need to share the OwnedChannelStream with t_out.
    let err_shared = shared.clone();
    let t_err = thread::spawn(move || {
        let mut buf = [0u8; 32 * 1024];
        let mut stderr = std::io::stderr();
        loop {
            match err_shared.channel_recv_stderr(channel_id, &mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    if stderr.write_all(&buf[..n]).is_err() {
                        break;
                    }
                    let _ = stderr.flush();
                }
                Err(_) => break,
            }
        }
    });

    // 5. SIGWINCH watcher.
    static RESIZED: AtomicBool = AtomicBool::new(false);
    extern "C" fn on_winch(_sig: nix::libc::c_int) {
        RESIZED.store(true, Ordering::Relaxed);
    }
    // SAFETY: signal handler is async-signal-safe — it only stores
    // into an AtomicBool. Replacing SIGWINCH is the standard idiom
    // for terminal resize handling.
    unsafe {
        nix::libc::signal(
            nix::libc::SIGWINCH,
            on_winch as *const () as nix::libc::sighandler_t,
        );
    }
    let winch_shared = shared.clone();
    let winch_stop = stdout_done.clone();
    let t_winch = thread::spawn(move || {
        while !winch_stop.load(Ordering::Relaxed) {
            thread::sleep(std::time::Duration::from_millis(100));
            if RESIZED.swap(false, Ordering::Relaxed) {
                let (cols, rows, px_w, px_h) = query_window_size();
                let _ = winch_shared.send_window_change(channel_id, cols, rows, px_w, px_h);
            }
        }
    });

    // Wait for the channel reader to wind down — that's the canonical
    // "remote shell exited" signal. The stdin thread may still be
    // parked in read(0); we don't try to join it (read(0) is
    // uninterruptible without closing the fd, which would mangle the
    // user's terminal). The kernel cleans it up on process exit.
    let _ = t_out.join();
    let _ = t_err.join();
    drop(t_in);
    drop(t_winch);

    // Recover the stream so we can read exit-status and run Drop
    // (which sends CHANNEL_CLOSE).
    let stream = stream_rx
        .recv_timeout(std::time::Duration::from_secs(1))
        .ok();
    Ok(stream.and_then(|s| s.exit_status()).unwrap_or(0))
}

/// Non-PTY shell: stdin is a pipe / file, not a terminal. Same
/// three-way splice, no termios fiddling, no SIGWINCH. The remote
/// shell runs in non-canonical line-buffered mode but still works for
/// `echo cmd | ssh host`-style usage.
#[cfg(unix)]
fn run_interactive_pipe_shell(shared: puressh::shared::SharedClient) -> Result<i32, String> {
    let stream = shared
        .shell_stream_no_pty()
        .map_err(|e| format!("shell: {e}"))?;
    let channel_id = stream.channel_id();

    // See run_interactive_pty_shell: a short read timeout lets the
    // stdin → channel writer thread acquire the SharedClient mutex
    // while the channel → stdout reader thread is otherwise pumping.
    let _ = shared.set_read_timeout(Some(std::time::Duration::from_millis(50)));

    // stdin → channel.
    let writer_shared = shared.clone();
    let t_in = thread::spawn(move || {
        let mut buf = [0u8; 8 * 1024];
        let mut stdin = std::io::stdin();
        loop {
            match stdin.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    let mut off = 0;
                    while off < n {
                        match writer_shared.channel_send_data(channel_id, &buf[off..n]) {
                            Ok(0) | Err(_) => return,
                            Ok(taken) => off += taken,
                        }
                    }
                }
                Err(e) if e.kind() == ErrorKind::Interrupted => continue,
                Err(_) => break,
            }
        }
        let _ = writer_shared.channel_send_eof(channel_id);
    });

    // channel → stdout. Owns the stream — no outer mutex.
    let (stream_tx, stream_rx) = std::sync::mpsc::channel::<puressh::shared::OwnedChannelStream>();
    let t_out = thread::spawn(move || {
        let mut stream = stream;
        let mut buf = [0u8; 32 * 1024];
        let mut stdout = std::io::stdout();
        loop {
            match stream.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    if stdout.write_all(&buf[..n]).is_err() {
                        break;
                    }
                    let _ = stdout.flush();
                }
                Err(_) => break,
            }
        }
        let _ = stream_tx.send(stream);
    });

    // channel.stderr → stderr.
    let err_shared = shared.clone();
    let t_err = thread::spawn(move || {
        let mut buf = [0u8; 32 * 1024];
        let mut stderr = std::io::stderr();
        loop {
            match err_shared.channel_recv_stderr(channel_id, &mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    if stderr.write_all(&buf[..n]).is_err() {
                        break;
                    }
                    let _ = stderr.flush();
                }
                Err(_) => break,
            }
        }
    });

    let _ = t_out.join();
    let _ = t_err.join();
    drop(t_in);

    let stream = stream_rx
        .recv_timeout(std::time::Duration::from_secs(1))
        .ok();
    Ok(stream.and_then(|s| s.exit_status()).unwrap_or(0))
}

/// Query the local terminal's size via `TIOCGWINSZ` on fd 0. Returns
/// `(cols, rows, px_w, px_h)`. Falls back to `(80, 24, 0, 0)` if the
/// ioctl fails.
#[cfg(unix)]
fn query_window_size() -> (u32, u32, u32, u32) {
    let mut ws: nix::libc::winsize = unsafe { core::mem::zeroed() };
    let ok = unsafe { nix::libc::ioctl(0, nix::libc::TIOCGWINSZ, &mut ws) } == 0;
    if ok {
        (
            ws.ws_col as u32,
            ws.ws_row as u32,
            ws.ws_xpixel as u32,
            ws.ws_ypixel as u32,
        )
    } else {
        (80, 24, 0, 0)
    }
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
            // `-X` is documented as "untrusted X11 forwarding" but
            // puressh has no SECURITY-extension cookie isolation yet:
            // both `-X` and `-Y` mint and forward the same plain
            // MIT-MAGIC-COOKIE-1, which means the remote can read X11
            // input from the local display either way. Warn loudly
            // (once, on session start) when the user asked for the
            // safer `-X` mode so they aren't silently downgraded to
            // `-Y`-equivalent behaviour. Don't refuse — that would
            // break existing scripts that rely on `-X` working at all.
            if mode == X11Forward::Untrusted {
                eprintln!(
                    "warning: -X is currently equivalent to -Y in puressh \
                     (no SECURITY-extension cookie); the remote can read \
                     X11 input from your local display."
                );
            }
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

#[cfg(test)]
mod forward_tests {
    use super::*;

    #[test]
    fn local_forward_plain() {
        let f = parse_local_forward("8080:example.com:80").unwrap();
        assert_eq!(f.listen_port, 8080);
        assert_eq!(f.remote_host, "example.com");
        assert_eq!(f.remote_port, 80);
    }

    #[test]
    fn local_forward_v4() {
        let f = parse_local_forward("8080:192.0.2.1:80").unwrap();
        assert_eq!(f.remote_host, "192.0.2.1");
        assert_eq!(f.remote_port, 80);
    }

    #[test]
    fn local_forward_bracketed_v6() {
        let f = parse_local_forward("8080:[2001:db8::1]:80").unwrap();
        assert_eq!(f.listen_port, 8080);
        assert_eq!(f.remote_host, "2001:db8::1");
        assert_eq!(f.remote_port, 80);
    }

    #[test]
    fn local_forward_bracketed_v6_loopback() {
        let f = parse_local_forward("8080:[::1]:80").unwrap();
        assert_eq!(f.remote_host, "::1");
        assert_eq!(f.remote_port, 80);
    }

    #[test]
    fn local_forward_rejects_missing_close_bracket() {
        assert!(parse_local_forward("8080:[2001:db8::1:80").is_err());
    }

    #[test]
    fn local_forward_rejects_missing_trailing_port() {
        // `[v6]` with no `:port` afterwards.
        assert!(parse_local_forward("8080:[2001:db8::1]").is_err());
        assert!(parse_local_forward("8080:[2001:db8::1]junk").is_err());
    }

    #[test]
    fn local_forward_rejects_too_few_fields() {
        assert!(parse_local_forward("only-one-field").is_err());
        assert!(parse_local_forward("80:hostonly").is_err());
    }

    #[test]
    fn remote_forward_plain() {
        let f = parse_remote_forward("9090:127.0.0.1:22").unwrap();
        assert_eq!(f.remote_port, 9090);
        assert_eq!(f.local_host, "127.0.0.1");
        assert_eq!(f.local_port, 22);
    }

    #[test]
    fn remote_forward_bracketed_v6() {
        let f = parse_remote_forward("9090:[2001:db8::2]:22").unwrap();
        assert_eq!(f.remote_port, 9090);
        assert_eq!(f.local_host, "2001:db8::2");
        assert_eq!(f.local_port, 22);
    }
}
