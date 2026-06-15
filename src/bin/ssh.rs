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
    AlgoOverrides, ChannelStream, Client, ClientHandlers, Config, ForwardedTcpipCallback,
    ForwardedTcpipOrigin, ServeContext,
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
                     [-L LPORT:RHOST:RPORT] [-R RPORT:LHOST:LPORT] [-D [bind:]port] \
                     [-J [user@]host[:port][,...]] \
                     [-C] [-t] [-T] [-N] [-A] [-X] [-Y] \
                     [-o ssh_config_keyword=value] \
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

/// Parsed `-D [bind:]port` spec — client binds a SOCKS proxy listener;
/// each accepted SOCKS CONNECT becomes a `direct-tcpip` channel to the
/// SOCKS-requested target. Mirrors [`LocalForward`] but the destination is
/// chosen per-connection by the SOCKS client rather than fixed up front.
#[derive(Clone, Debug)]
struct DynamicForward {
    /// Local bind address (already resolved through GatewayPorts).
    bind_addr: String,
    /// Local port to bind the SOCKS listener on.
    listen_port: u16,
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
    /// `-D [bind:]port`: SOCKS dynamic-forward listeners (bind addr not yet
    /// resolved through GatewayPorts — that happens in `run`).
    dynamics_raw: Vec<puressh::config::DynamicForwardSpec>,
    /// `-o Compression={yes,no}`. `None` when not supplied on the CLI.
    compression: Option<bool>,
    /// `-t` (force PTY) / `-T` (disable PTY) / `-o RequestTTY=…`. `None`
    /// when neither was supplied; the config `RequestTTY` then wins.
    request_tty: Option<puressh::config::RequestTty>,
    /// Raw `KEY VALUE` lines for `-o` options not consumed into a dedicated
    /// Cli field; parsed in `run` as a highest-priority synthetic block.
    extra_o: Vec<String>,
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
    /// `-J [user@]host[:port][,…]`: ProxyJump chain. `None` when the flag
    /// wasn't supplied; the ssh_config `ProxyJump` then wins.
    proxy_jump: Option<String>,
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

/// Parse one `-D` arg value: `[bind_address:]port`. Reuses the config-layer
/// `[bind:]port` splitter so `-D 1080`, `-D 127.0.0.1:1080`, and
/// `-D [::1]:1080` all parse identically to a `DynamicForward` keyword.
fn parse_dynamic_forward(s: &str) -> Result<puressh::config::DynamicForwardSpec, String> {
    // `[bind]:port` (bracketed v6) or `[bind:]port`.
    if let Some(rest) = s.strip_prefix('[') {
        let (addr, port) = rest
            .split_once("]:")
            .ok_or_else(|| format!("-D: malformed bracketed bind:port {s:?}"))?;
        let listen_port = port
            .parse::<u16>()
            .map_err(|_| format!("-D: bad port in {s:?}"))?;
        return Ok(puressh::config::DynamicForwardSpec {
            bind_addr: Some(addr.to_string()),
            listen_port,
        });
    }
    match s.rsplit_once(':') {
        Some((addr, port)) => {
            let listen_port = port
                .parse::<u16>()
                .map_err(|_| format!("-D: bad port in {s:?}"))?;
            Ok(puressh::config::DynamicForwardSpec {
                bind_addr: Some(addr.to_string()),
                listen_port,
            })
        }
        None => {
            let listen_port = s
                .parse::<u16>()
                .map_err(|_| format!("-D expects [bind:]port, got {s:?}"))?;
            Ok(puressh::config::DynamicForwardSpec {
                bind_addr: None,
                listen_port,
            })
        }
    }
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
    let mut dynamics_raw: Vec<puressh::config::DynamicForwardSpec> = Vec::new();
    let mut compression: Option<bool> = None;
    let mut request_tty: Option<puressh::config::RequestTty> = None;
    let mut extra_o: Vec<String> = Vec::new();
    let mut no_command = false;
    let mut agent_forward = false;
    let mut x11_forward: Option<X11Forward> = None;
    let mut proxy_jump: Option<String> = None;
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
            "-D" => {
                i += 1;
                let v = args.get(i).ok_or("-D requires a value")?;
                dynamics_raw.push(parse_dynamic_forward(v)?);
            }
            // `-C` enables compression (OpenSSH's flag form of
            // `Compression yes`). There is no flag to turn it off.
            "-C" => {
                compression = Some(true);
            }
            // `-t` forces PTY allocation; `-T` disables it. These map onto
            // RequestTTY Force / No and win over the config keyword.
            "-t" => {
                request_tty = Some(puressh::config::RequestTty::Force);
            }
            "-T" => {
                request_tty = Some(puressh::config::RequestTty::No);
            }
            "-N" => {
                no_command = true;
            }
            "-J" => {
                i += 1;
                let v = args.get(i).ok_or("-J requires a value")?.clone();
                proxy_jump = Some(v);
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
                    "compression" => {
                        compression = Some(match val.to_ascii_lowercase().as_str() {
                            "yes" | "on" | "true" => true,
                            "no" | "off" | "false" => false,
                            other => return Err(format!("unknown Compression={other}")),
                        });
                    }
                    "requesttty" => {
                        request_tty = Some(match val.to_ascii_lowercase().as_str() {
                            "no" => puressh::config::RequestTty::No,
                            "yes" => puressh::config::RequestTty::Yes,
                            "force" => puressh::config::RequestTty::Force,
                            "auto" => puressh::config::RequestTty::Auto,
                            other => return Err(format!("unknown RequestTTY={other}")),
                        });
                    }
                    // Every other recognised ssh_config keyword is routed
                    // through the real config parser (as a highest-priority
                    // synthetic block) so `-o KEY=VAL` honours the same strict
                    // validation as the file. Collected here; applied in run().
                    _ => {
                        extra_o.push(format!("{k} {val}"));
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
        extra_o,
        locals,
        remotes,
        dynamics_raw,
        compression,
        request_tty,
        no_command,
        agent_forward,
        x11_forward,
        proxy_jump,
        verbose,
        host,
        user_in_host,
        command,
    })
}

/// Merge the `-o KEY=VALUE` options collected in [`Cli::extra_o`] into the
/// resolved config block. We parse them as a standalone synthetic config so
/// each honours the real strict parser (rejecting unknown keywords and bad
/// values exactly as the file would), then overlay every field the synthetic
/// block actually set on top of `cfg_block` — giving `-o` the highest
/// precedence, matching OpenSSH.
fn apply_extra_o(
    cfg_block: &mut puressh::config::ClientOptions,
    extra_o: &[String],
) -> Result<(), String> {
    if extra_o.is_empty() {
        return Ok(());
    }
    let src = extra_o.join("\n");
    let parsed = puressh::config::SshClientConfig::parse(&src).map_err(|e| format!("-o: {e}"))?;
    let o = parsed.lookup("*");
    // Scalars: a `Some` in the synthetic block wins.
    macro_rules! overlay {
        ($($f:ident),* $(,)?) => { $( if o.$f.is_some() { cfg_block.$f = o.$f.clone(); } )* };
    }
    overlay!(
        host_name,
        port,
        user,
        identities_only,
        strict_host_key,
        user_known_hosts,
        hash_known_hosts,
        forward_agent,
        forward_x11,
        forward_x11_trusted,
        request_tty,
        log_level,
        ciphers,
        macs,
        kex_algorithms,
        host_key_algorithms,
        pubkey_accepted_algorithms,
        proxy_command,
        proxy_jump,
        compression,
        connect_timeout,
        server_alive_interval,
        server_alive_count_max,
        tcp_keep_alive,
        add_keys_to_agent,
        preferred_authentications,
        pubkey_authentication,
        number_of_password_prompts,
        batch_mode,
        exit_on_forward_failure,
        clear_all_forwardings,
        gateway_ports,
        address_family,
        bind_address,
        identity_agent,
    );
    // Cumulative lists: append whatever the -o block contributed.
    cfg_block.identity_files.extend(o.identity_files);
    cfg_block.local_forwards.extend(o.local_forwards);
    cfg_block.remote_forwards.extend(o.remote_forwards);
    cfg_block.dynamic_forwards.extend(o.dynamic_forwards);
    cfg_block.set_env.extend(o.set_env);
    cfg_block.send_env.extend(o.send_env);
    Ok(())
}

/// One parsed `ProxyJump` hop: `[user@]host[:port]`.
#[derive(Clone, Debug, PartialEq, Eq)]
struct JumpHop {
    user: Option<String>,
    host: String,
    /// `None` ⇒ fall back to the hop's ssh_config `Port`, then 22.
    port: Option<u16>,
}

/// Parse a comma-separated `ProxyJump` value into hops. Each hop is
/// `[user@]host[:port]`. Rejects empty hops and an empty list.
fn parse_jump_hops(spec: &str) -> Result<Vec<JumpHop>, String> {
    let mut hops = Vec::new();
    for raw in spec.split(',') {
        let token = raw.trim();
        if token.is_empty() {
            return Err(format!("ProxyJump: empty hop in {spec:?}"));
        }
        let (user, host, port) = parse_target(token)?;
        hops.push(JumpHop { user, host, port });
    }
    if hops.is_empty() {
        return Err("ProxyJump: no hops".into());
    }
    Ok(hops)
}

/// Collect publickey credentials for a host: agent identities (unless
/// `IdentitiesOnly`), then the `-i` CLI identities, then the matching
/// ssh_config block's `IdentityFile`s, then the OpenSSH default identities
/// under `~/.ssh/`. Mirrors OpenSSH's ordering. `cli_identities` is empty
/// for ProxyJump hops (the `-i` flag targets the final host only).
fn collect_credentials(
    cfg_block: &puressh::config::ClientOptions,
    cli_identities: &[String],
    identities_only: bool,
) -> Vec<ClientCredential> {
    // `PubkeyAuthentication no` (or a PreferredAuthentications list that omits
    // publickey) disables publickey credentials entirely — return nothing so
    // the auth driver falls straight to password.
    if cfg_block.pubkey_authentication == Some(false) {
        vlog(1, "PubkeyAuthentication no: skipping publickey credentials");
        return Vec::new();
    }
    if let Some(prefs) = cfg_block.preferred_authentications.as_ref()
        && !prefs.iter().any(|m| m == "publickey")
    {
        vlog(
            1,
            "PreferredAuthentications excludes publickey: skipping publickey credentials",
        );
        return Vec::new();
    }
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
    for id_path in cli_identities {
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
    credentials
}

/// Authenticate `client` as `user` with `credentials`: try publickey, then
/// fall back to an interactive password prompt. Used for the final target
/// and for every ProxyJump hop.
fn authenticate_client(
    client: &mut Client,
    user: &str,
    credentials: Vec<ClientCredential>,
    cfg_block: &puressh::config::ClientOptions,
) -> Result<(), String> {
    let authed = if !credentials.is_empty() {
        vlog(
            1,
            &format!(
                "attempting publickey auth with {} credentials",
                credentials.len()
            ),
        );
        match client.authenticate(user, credentials) {
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
    if authed {
        return Ok(());
    }

    // Whether password auth is permitted: BatchMode disables it outright;
    // PreferredAuthentications must include "password"; NumberOfPasswordPrompts
    // 0 also disables it.
    let batch = cfg_block.batch_mode == Some(true);
    let password_allowed_by_prefs = cfg_block
        .preferred_authentications
        .as_ref()
        .map(|p| p.iter().any(|m| m == "password"))
        .unwrap_or(true);
    // OpenSSH default is 3 attempts.
    let max_prompts = cfg_block.number_of_password_prompts.unwrap_or(3);

    if batch {
        return Err(
            "Auth failed: BatchMode is on and publickey auth did not succeed (no password prompt)"
                .into(),
        );
    }
    if !password_allowed_by_prefs {
        return Err(
            "Auth failed: publickey auth did not succeed and PreferredAuthentications excludes password"
                .into(),
        );
    }
    if max_prompts == 0 {
        return Err(
            "Auth failed: publickey auth did not succeed and NumberOfPasswordPrompts is 0".into(),
        );
    }

    // Up to `max_prompts` interactive password attempts. The reader honors
    // $SSH_ASKPASS and suppresses terminal echo on Unix (see common.rs).
    let mut last_err = String::from("no attempt made");
    for attempt in 1..=max_prompts {
        let password = read_password_from_stdin().map_err(|e| format!("read password: {e}"))?;
        match client.authenticate_password(user, &password) {
            Ok(()) => {
                vlog(1, &format!("authenticated as {user} via password"));
                return Ok(());
            }
            Err(e) => {
                last_err = format!("{e}");
                if attempt < max_prompts {
                    eprintln!("Permission denied, please try again.");
                }
            }
        }
    }
    Err(format!("Auth failed: {last_err}"))
}

/// Build the [`Config`] for a host from its resolved ssh_config block:
/// host-key policy + crypto-algorithm overrides.
fn config_for_host(
    cfg_block: &puressh::config::ClientOptions,
    cli: &Cli,
) -> Result<Config, String> {
    let mut strict = common::pick(cli.strict, cfg_block.strict_host_key, StrictMode::Ask);
    // BatchMode never prompts. An interactive `ask` would block forever
    // under BatchMode, so OpenSSH promotes it to `yes` (refuse unknown).
    if cfg_block.batch_mode == Some(true) && strict == StrictMode::Ask {
        strict = StrictMode::Yes;
    }
    let known_hosts_path = cli
        .known_hosts_path
        .clone()
        .or_else(|| cfg_block.user_known_hosts.as_ref().map(PathBuf::from));
    let hash_known_hosts = common::pick(cli.hash_known_hosts, cfg_block.hash_known_hosts, false);
    let policy = build_host_key_policy(strict, known_hosts_path, hash_known_hosts)?;
    Ok(Config {
        host_key_policy: policy,
        timeout: None,
        algorithms: AlgoOverrides {
            ciphers: cfg_block.ciphers.clone(),
            macs: cfg_block.macs.clone(),
            kex_algorithms: cfg_block.kex_algorithms.clone(),
            host_key_algorithms: cfg_block.host_key_algorithms.clone(),
            pubkey_accepted_algorithms: cfg_block.pubkey_accepted_algorithms.clone(),
            // -o Compression / config Compression. The keyword is rejected
            // up front (in run()) when the `compress` feature is absent, so
            // by the time we get here Some(true) is honourable.
            compression: cli.compression.or(cfg_block.compression),
        },
    })
}

/// Walk the ProxyJump chain, returning the [`SharedClient`] for the *last*
/// jump host. The caller opens a `direct-tcpip` channel from it to the final
/// target and runs the real session over that. Each hop re-runs
/// `ssh_cfg.lookup(hop.host)` for its own identities / known_hosts / user;
/// host-key checking runs per hop (a rejection at any hop aborts).
fn connect_jump_chain(
    hops: &[JumpHop],
    ssh_cfg: &puressh::config::SshClientConfig,
    cli: &Cli,
) -> Result<puressh::shared::SharedClient, String> {
    let mut current: Option<puressh::shared::SharedClient> = None;
    for (idx, hop) in hops.iter().enumerate() {
        let block = ssh_cfg.lookup(&hop.host);
        let connect_host = block.host_name.clone().unwrap_or_else(|| hop.host.clone());
        let port = hop.port.or(block.port).unwrap_or(22);
        // Hop user: `user@` in the hop spec wins over the hop's config User,
        // then the local user. CLI `-l` targets the final host, not hops.
        let user = resolve_user(block.user.as_deref(), hop.user.as_deref())?;
        let cfg = config_for_host(&block, cli)?;

        vlog(
            1,
            &format!(
                "proxyjump hop {}: connecting to {connect_host}:{port}",
                idx + 1
            ),
        );
        let mut hop_client = match &current {
            // First hop: direct TCP.
            None => Client::connect_to_host(connect_host.as_str(), port, cfg)
                .map_err(|e| format!("proxyjump hop {}: connect: {e}", idx + 1))?,
            // Subsequent hop: tunnel a direct-tcpip channel through the
            // previous hop and run the client over it.
            Some(prev) => {
                let ch = prev
                    .open_direct_tcpip(connect_host.as_str(), port, "127.0.0.1", 0)
                    .map_err(|e| format!("proxyjump hop {}: open channel: {e}", idx + 1))?;
                Client::connect_via(Box::new(ch), connect_host.as_str(), port, cfg)
                    .map_err(|e| format!("proxyjump hop {}: handshake: {e}", idx + 1))?
            }
        };

        // ProxyJump hops authenticate with config/agent/default identities
        // only — the CLI `-i` list belongs to the final target.
        let credentials = collect_credentials(&block, &[], block.identities_only.unwrap_or(false));
        authenticate_client(&mut hop_client, &user, credentials, &block)
            .map_err(|e| format!("proxyjump hop {}: {e}", idx + 1))?;
        vlog(1, &format!("proxyjump hop {}: authenticated", idx + 1));

        current = Some(hop_client.into());
    }
    current.ok_or_else(|| "ProxyJump: no hops".into())
}

/// Build the environment to forward to the server: `SetEnv` literals
/// (first-wins on duplicate names) plus `SendEnv` patterns matched against
/// the local process environment.
fn build_session_env(cfg_block: &puressh::config::ClientOptions) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = Vec::new();
    let mut seen: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    // SetEnv: literal NAME=VALUE; first occurrence of a name wins.
    for (name, value) in &cfg_block.set_env {
        if seen.insert(name.clone()) {
            out.push((name.clone(), value.clone()));
        }
    }
    // SendEnv: forward matching local env vars. Patterns use glob-style `*`
    // / `?` (OpenSSH semantics). A name already set via SetEnv is not
    // overwritten.
    if !cfg_block.send_env.is_empty() {
        let env: Vec<(String, String)> = std::env::vars().collect();
        for pat in &cfg_block.send_env {
            for (name, value) in &env {
                if !seen.contains(name) && send_env_matches(pat, name) {
                    seen.insert(name.clone());
                    out.push((name.clone(), value.clone()));
                }
            }
        }
    }
    out
}

/// Match a `SendEnv` pattern against an environment-variable name. Supports
/// `*` (any run) and `?` (one char), matching OpenSSH's pattern syntax. The
/// match is anchored (the whole name must match).
fn send_env_matches(pattern: &str, name: &str) -> bool {
    fn rec(p: &[u8], n: &[u8]) -> bool {
        match p.first() {
            None => n.is_empty(),
            Some(b'*') => rec(&p[1..], n) || (!n.is_empty() && rec(p, &n[1..])),
            Some(b'?') => !n.is_empty() && rec(&p[1..], &n[1..]),
            Some(&c) => !n.is_empty() && n[0] == c && rec(&p[1..], &n[1..]),
        }
    }
    rec(pattern.as_bytes(), name.as_bytes())
}

/// Honour `AddKeysToAgent yes`: push each `-i` / config / default identity
/// the user supplied into the running ssh-agent so later sessions can reuse
/// it without re-reading the file. Best-effort and Unix-only (the agent
/// client is `cfg(unix)`); failures warn but never abort the session.
#[cfg(unix)]
fn maybe_add_keys_to_agent(cfg_block: &puressh::config::ClientOptions, cli: &Cli) {
    if cfg_block.add_keys_to_agent != Some(true) {
        return;
    }
    use puressh::agent::Agent;
    let mut agent = match Agent::connect_env() {
        Ok(Some(a)) => a,
        Ok(None) => {
            eprintln!("warning: AddKeysToAgent: no agent at $SSH_AUTH_SOCK; skipping");
            return;
        }
        Err(e) => {
            eprintln!("warning: AddKeysToAgent: agent connect: {e}");
            return;
        }
    };
    // Collect the identity file paths the same way collect_credentials does,
    // minus the agent's own identities (which are already loaded).
    let mut paths: Vec<String> = cli.identities.clone();
    for p in &cfg_block.identity_files {
        paths.push(expand_tilde(p));
    }
    for p in default_identity_paths() {
        paths.push(p.to_string_lossy().into_owned());
    }
    for path in paths {
        // Missing / unreadable files are normal for the default identity
        // list; load_identity already logs read errors, so skip silently.
        if let Ok(pk) = load_identity(&path) {
            match agent.add_identity(&pk) {
                Ok(()) => vlog(1, &format!("AddKeysToAgent: added {path}")),
                Err(e) => eprintln!("warning: AddKeysToAgent: add {path}: {e}"),
            }
        }
    }
}

#[cfg(not(unix))]
fn maybe_add_keys_to_agent(_cfg_block: &puressh::config::ClientOptions, _cli: &Cli) {}

/// Decide whether the one-shot `exec` path should allocate a PTY, honouring
/// `RequestTTY` (CLI `-t`/`-T`/`-o RequestTTY` over the config keyword):
///   - Force / Yes ⇒ always (even for a remote command);
///   - No ⇒ never;
///   - Auto / unset ⇒ only when local stdin is a tty.
#[cfg(unix)]
fn want_exec_pty(cli: &Cli, cfg_block: &puressh::config::ClientOptions) -> bool {
    use puressh::config::RequestTty::*;
    match cli.request_tty.or(cfg_block.request_tty) {
        Some(Force) | Some(Yes) => true,
        Some(No) => false,
        Some(Auto) | None => stdin_is_tty(),
    }
}

/// Honour `IdentityAgent`. `none` clears `$SSH_AUTH_SOCK` so no agent is
/// consulted; a path overrides it (expanding the `SSH_AUTH_SOCK` /
/// `$SSH_AUTH_SOCK` token to the inherited value and `~`). When unset, the
/// inherited `$SSH_AUTH_SOCK` stands. `identities_only` is informational
/// (the agent is skipped for credentials anyway) but we still set the env so
/// AddKeysToAgent targets the right socket.
fn apply_identity_agent(setting: Option<&puressh::config::IdentityAgent>, _identities_only: bool) {
    use puressh::config::IdentityAgent;
    match setting {
        None => {}
        Some(IdentityAgent::None) => {
            // SAFETY: single-threaded at this point (before any forwarding
            // threads spawn); removing an env var is sound here.
            unsafe {
                std::env::remove_var("SSH_AUTH_SOCK");
            }
        }
        Some(IdentityAgent::Path(p)) => {
            // Expand the SSH_AUTH_SOCK token (OpenSSH allows referencing the
            // inherited socket) and `~`.
            let inherited = std::env::var("SSH_AUTH_SOCK").unwrap_or_default();
            let expanded = p
                .replace("$SSH_AUTH_SOCK", &inherited)
                .replace("SSH_AUTH_SOCK", &inherited);
            let expanded = expand_tilde(&expanded);
            // SAFETY: see above — still single-threaded.
            unsafe {
                std::env::set_var("SSH_AUTH_SOCK", &expanded);
            }
        }
    }
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
    let mut cfg_block = ssh_cfg.lookup(&cli.host);
    // `-o KEY=VALUE` overlays the matched block at the highest precedence,
    // re-using the strict config parser for validation.
    apply_extra_o(&mut cfg_block, &cli.extra_o)?;

    // Compression requires the `compress` feature. Reject up front (rather
    // than silently advertising `none`) so the directive can never look like
    // it took effect when the build can't honour it.
    let want_compression = cli.compression.or(cfg_block.compression) == Some(true);
    if want_compression && !cfg!(feature = "compress") {
        return Err("Compression yes requested but this build lacks the `compress` feature".into());
    }

    // `ClearAllForwardings yes` discards every forward gathered so far —
    // CLI `-L/-R/-D` and the config's own forward lists — before we add the
    // config-derived ones below. Matches OpenSSH: the cleared state wins.
    if cfg_block.clear_all_forwardings == Some(true) {
        cli.locals.clear();
        cli.remotes.clear();
        cli.dynamics_raw.clear();
        cfg_block.local_forwards.clear();
        cfg_block.remote_forwards.clear();
        cfg_block.dynamic_forwards.clear();
    }

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
    // DynamicForward: gather `-D` and config entries, resolving each
    // listener's bind address through GatewayPorts.
    let gateway = cfg_block
        .gateway_ports
        .unwrap_or(puressh::config::GatewayPorts::No);
    let mut dynamics: Vec<DynamicForward> = Vec::new();
    for d in cli
        .dynamics_raw
        .iter()
        .chain(cfg_block.dynamic_forwards.iter())
    {
        dynamics.push(DynamicForward {
            bind_addr: resolve_bind_addr(gateway, d.bind_addr.as_deref()),
            listen_port: d.listen_port,
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

    let identities_only = common::pick(cli.identities_only, cfg_block.identities_only, false);
    let port = common::pick(cli.port, cfg_block.port, 22);
    // `HostName` rewrites the connect target; the original `cli.host` is
    // what we *displayed* and what the config block matched on.
    let connect_host = cfg_block
        .host_name
        .clone()
        .unwrap_or_else(|| cli.host.clone());

    let cfg = config_for_host(&cfg_block, &cli)?;

    // Decide the connection transport for the final target:
    //   ProxyJump (CLI -J > config ProxyJump) tunnels through jump hosts;
    //   ProxyCommand spawns a helper process; otherwise a direct TCP socket.
    // ProxyJump beats ProxyCommand when both are configured (warn).
    let proxy_jump = cli
        .proxy_jump
        .clone()
        .or_else(|| cfg_block.proxy_jump.clone());
    let proxy_command = cfg_block.proxy_command.clone();
    if proxy_jump.is_some() && proxy_command.is_some() {
        eprintln!("warning: both ProxyJump and ProxyCommand set; using ProxyJump");
    }

    let mut client = if let Some(spec) = proxy_jump {
        // ---- ProxyJump ----
        let hops = parse_jump_hops(&spec)?;
        vlog(1, &format!("proxyjump: {} hop(s)", hops.len()));
        let last = connect_jump_chain(&hops, &ssh_cfg, &cli)?;
        // Final hop: open a direct-tcpip channel from the last jump host to
        // the real target and run the client over it. Host/port flow through
        // so the target's host-key check runs against its own known_hosts.
        vlog(
            1,
            &format!("proxyjump: opening channel to target {connect_host}:{port}"),
        );
        let ch = last
            .open_direct_tcpip(connect_host.as_str(), port, "127.0.0.1", 0)
            .map_err(|e| format!("proxyjump: open channel to target: {e}"))?;
        let client = Client::connect_via(Box::new(ch), connect_host.as_str(), port, cfg)
            .map_err(|e| format!("proxyjump: target handshake: {e}"))?;
        // `ch` (now inside `client`) holds a clone of `last`'s SharedClient,
        // so the jump chain stays alive for the lifetime of the session even
        // after `last` drops here.
        drop(last);
        vlog(
            1,
            &format!("connected to {connect_host}:{port} via ProxyJump"),
        );
        client
    } else if let Some(cmd_raw) = proxy_command {
        // ---- ProxyCommand (Unix only) ----
        #[cfg(unix)]
        {
            // Phase-1 restriction: the pipe transport's read-timeout toggle
            // is a no-op, so the serve / forwarding poll loops can't run over
            // it. Reject -L/-R/-N (and config-derived forwards) up front.
            if cli.no_command
                || !cli.locals.is_empty()
                || !cli.remotes.is_empty()
                || !cfg_block.local_forwards.is_empty()
                || !cfg_block.remote_forwards.is_empty()
            {
                return Err(
                    "ProxyCommand does not support -L/-R/-N forwarding in this release; \
                     use a single exec or an interactive shell"
                        .into(),
                );
            }
            let cmd = puressh::proc_transport::expand_tokens(&cmd_raw, &connect_host, port, &user);
            vlog(1, &format!("proxycommand: spawning {cmd:?}"));
            let proc = puressh::proc_transport::ProcTransport::spawn(&cmd)
                .map_err(|e| format!("ProxyCommand: spawn failed: {e}"))?;
            let client = Client::connect_via(Box::new(proc), connect_host.as_str(), port, cfg)
                .map_err(|e| format!("ProxyCommand: handshake: {e}"))?;
            vlog(
                1,
                &format!("connected to {connect_host}:{port} via ProxyCommand"),
            );
            client
        }
        #[cfg(not(unix))]
        {
            let _ = cmd_raw;
            return Err("ProxyCommand is only supported on Unix".into());
        }
    } else {
        // ---- direct TCP ----
        // Dial through dial_tcp so ConnectTimeout / BindAddress /
        // AddressFamily / TCPKeepAlive take real effect, then run the client
        // over the configured socket via connect_via (which still threads
        // connect_host through so KnownHosts looks the host up by name).
        vlog(1, &format!("connecting to {connect_host}:{port}"));
        let sock = dial_tcp(&connect_host, port, &cfg_block)?;
        let client = Client::connect_via(Box::new(sock), connect_host.as_str(), port, cfg)
            .map_err(|e| format!("connect: {e}"))?;
        vlog(1, &format!("connected to {connect_host}:{port}"));
        client
    };

    // IdentityAgent overrides which agent socket we consult. `none` disables
    // the agent entirely; a path (with the `SSH_AUTH_SOCK` token expanded)
    // replaces $SSH_AUTH_SOCK for the agent-backed credential lookup and any
    // AddKeysToAgent push below. We do this by adjusting the process env so
    // the existing agent helpers (which read $SSH_AUTH_SOCK) pick it up.
    apply_identity_agent(cfg_block.identity_agent.as_ref(), identities_only);

    let credentials = collect_credentials(&cfg_block, &cli.identities, identities_only);
    authenticate_client(&mut client, &user, credentials, &cfg_block)?;

    // AddKeysToAgent yes: push the supplied identities into the local agent.
    maybe_add_keys_to_agent(&cfg_block, &cli);

    // SetEnv / SendEnv: arm the env requests the session-channel helpers send
    // after each channel open.
    let session_env = build_session_env(&cfg_block);
    if !session_env.is_empty() {
        vlog(
            1,
            &format!("forwarding {} environment variable(s)", session_env.len()),
        );
        client.set_session_env(session_env);
    }

    // ServerAliveInterval / ServerAliveCountMax drive the serve loop's
    // keepalive. No-op on the one-shot exec path (which doesn't serve).
    if let Some(interval) = cfg_block.server_alive_interval
        && interval > 0
    {
        let count_max = cfg_block.server_alive_count_max.unwrap_or(3);
        client.set_keepalive(interval, count_max);
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
        || !dynamics.is_empty()
        || cli.agent_forward
        || cli.x11_forward.is_some();
    if want_forwarding {
        if cli.command.is_some() {
            return Err(
                "running a command alongside -A/-D/-L/-R/-N/-X/-Y is not yet supported; \
                        invoke ssh twice or wire the forward without a command"
                    .into(),
            );
        }
        if cli.no_command
            && cli.remotes.is_empty()
            && cli.locals.is_empty()
            && dynamics.is_empty()
            && !cli.agent_forward
            && cli.x11_forward.is_none()
        {
            return Err("-N requires at least one of -A, -D, -L, -R, -X, -Y".into());
        }
        let exit_on_forward_failure = cfg_block.exit_on_forward_failure == Some(true);
        let gateway = cfg_block
            .gateway_ports
            .unwrap_or(puressh::config::GatewayPorts::No);
        return run_forwarding(client, &cli, &dynamics, exit_on_forward_failure, gateway);
    }

    if let Some(command) = cli.command.clone() {
        // RequestTTY Force/Yes allocates a PTY even for a remote command.
        #[cfg(unix)]
        {
            if want_exec_pty(&cli, &cfg_block) {
                let (cols, rows, px_w, px_h) = query_window_size();
                let term = std::env::var("TERM").unwrap_or_else(|_| "xterm".to_string());
                client.set_request_pty(Some((term, cols, rows, px_w, px_h, Vec::new())));
            }
        }
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
        // RequestTTY decides PTY allocation for the interactive shell:
        //   Force/Yes ⇒ PTY even when stdin isn't a tty;
        //   No        ⇒ no PTY (line-buffered pipe shell);
        //   Auto/unset⇒ PTY iff stdin is a tty (the historical default).
        use puressh::config::RequestTty::*;
        let use_pty = match cli.request_tty.or(cfg_block.request_tty) {
            Some(Force) | Some(Yes) => true,
            Some(No) => false,
            Some(Auto) | None => stdin_is_tty(),
        };
        if use_pty {
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

/// Resolve a client-side listener bind address per `GatewayPorts`:
///   - `No` (default): always loopback (`127.0.0.1`), ignoring any spec.
///   - `Yes`: all interfaces (`0.0.0.0`), ignoring any spec.
///   - `ClientSpecified`: honour the address spelled out in the forward
///     spec, falling back to loopback when none was given.
fn resolve_bind_addr(gateway: puressh::config::GatewayPorts, spec: Option<&str>) -> String {
    use puressh::config::GatewayPorts::*;
    match gateway {
        No => "127.0.0.1".to_string(),
        Yes => "0.0.0.0".to_string(),
        ClientSpecified => spec.unwrap_or("127.0.0.1").to_string(),
    }
}

/// Open a configured TCP connection to `host:port`, honouring
/// `ConnectTimeout`, `BindAddress`, `AddressFamily`, and `TCPKeepAlive`.
///
/// Returns a `TcpStream` ready to hand to [`Client::connect_via`]. Used for
/// the direct-TCP path so these socket-level keywords take real effect
/// (the library's `connect_to_host` uses a plain `TcpStream::connect`).
fn dial_tcp(
    host: &str,
    port: u16,
    cfg_block: &puressh::config::ClientOptions,
) -> Result<TcpStream, String> {
    use puressh::config::AddressFamily;
    use std::net::ToSocketAddrs;

    // Resolve and filter by AddressFamily.
    let family = cfg_block.address_family.unwrap_or(AddressFamily::Any);
    let mut addrs: Vec<std::net::SocketAddr> = (host, port)
        .to_socket_addrs()
        .map_err(|e| format!("resolve {host}:{port}: {e}"))?
        .filter(|a| match family {
            AddressFamily::Any => true,
            AddressFamily::Inet => a.is_ipv4(),
            AddressFamily::Inet6 => a.is_ipv6(),
        })
        .collect();
    if addrs.is_empty() {
        return Err(format!(
            "no addresses for {host}:{port} in the requested address family"
        ));
    }

    let timeout = cfg_block
        .connect_timeout
        .map(|s| std::time::Duration::from_secs(s as u64));

    // Try each candidate address until one connects.
    let mut last_err: Option<String> = None;
    for addr in addrs.drain(..) {
        let sock = match connect_one(addr, cfg_block.bind_address.as_deref(), timeout) {
            Ok(s) => s,
            Err(e) => {
                last_err = Some(e);
                continue;
            }
        };
        // TCPKeepAlive: default yes (OpenSSH default). Only set SO_KEEPALIVE
        // off when explicitly disabled.
        if cfg_block.tcp_keep_alive != Some(false) {
            set_so_keepalive(&sock, true)?;
        }
        let _ = sock.set_nodelay(true);
        return Ok(sock);
    }
    Err(last_err.unwrap_or_else(|| format!("could not connect to {host}:{port}")))
}

/// Connect to a single resolved address, optionally binding a local source
/// address (`BindAddress`) and applying a connect timeout (`ConnectTimeout`).
fn connect_one(
    addr: std::net::SocketAddr,
    bind_address: Option<&str>,
    timeout: Option<std::time::Duration>,
) -> Result<TcpStream, String> {
    if let Some(bind) = bind_address {
        // A local source bind requires the two-step socket2-style dance,
        // which std doesn't expose directly. Use a TcpSocket-free approach
        // via libc on Unix; on other platforms BindAddress is unsupported.
        return connect_bound(addr, bind, timeout);
    }
    match timeout {
        Some(t) => TcpStream::connect_timeout(&addr, t)
            .map_err(|e| format!("connect {addr} (timeout {}s): {e}", t.as_secs())),
        None => TcpStream::connect(addr).map_err(|e| format!("connect {addr}: {e}")),
    }
}

/// Bind a local source address before connecting (`BindAddress`). Unix-only:
/// uses libc `socket`/`bind`/`connect` since `std` has no source-address
/// API. On non-Unix this returns an error rather than silently ignoring the
/// directive.
#[cfg(unix)]
fn connect_bound(
    addr: std::net::SocketAddr,
    bind: &str,
    timeout: Option<std::time::Duration>,
) -> Result<TcpStream, String> {
    use std::net::ToSocketAddrs;
    use std::os::unix::io::FromRawFd;

    // Resolve the bind address (port 0 = ephemeral) in the same family as
    // the target.
    let bind_addr = (bind, 0u16)
        .to_socket_addrs()
        .map_err(|e| format!("resolve BindAddress {bind}: {e}"))?
        .find(|a| a.is_ipv4() == addr.is_ipv4())
        .ok_or_else(|| format!("BindAddress {bind} has no address matching the target family"))?;

    let domain = if addr.is_ipv4() {
        nix::libc::AF_INET
    } else {
        nix::libc::AF_INET6
    };
    // SAFETY: standard socket(2) call; fd ownership transferred to TcpStream
    // via from_raw_fd below (or closed on the error paths).
    let fd = unsafe { nix::libc::socket(domain, nix::libc::SOCK_STREAM, 0) };
    if fd < 0 {
        return Err(format!("socket(): {}", std::io::Error::last_os_error()));
    }
    // Wrap immediately so any early return closes the fd via Drop.
    let stream = unsafe { TcpStream::from_raw_fd(fd) };

    let (bind_storage, bind_len) = sockaddr_bytes(&bind_addr);
    // SAFETY: bind_storage/len describe a valid sockaddr for this fd's family.
    let rc = unsafe {
        nix::libc::bind(
            fd,
            bind_storage.as_ptr() as *const nix::libc::sockaddr,
            bind_len,
        )
    };
    if rc != 0 {
        return Err(format!(
            "bind {bind_addr}: {}",
            std::io::Error::last_os_error()
        ));
    }

    let (target_storage, target_len) = sockaddr_bytes(&addr);
    // SAFETY: same contract as bind; connect blocks (no timeout fd dance).
    let rc = unsafe {
        nix::libc::connect(
            fd,
            target_storage.as_ptr() as *const nix::libc::sockaddr,
            target_len,
        )
    };
    if rc != 0 {
        return Err(format!(
            "connect {addr}: {}",
            std::io::Error::last_os_error()
        ));
    }
    // ConnectTimeout with a bound source address would need non-blocking
    // connect + poll; we keep the simple blocking path and apply the timeout
    // as a read/write timeout instead so a wedged peer still unblocks.
    if let Some(t) = timeout {
        let _ = stream.set_read_timeout(Some(t));
        let _ = stream.set_write_timeout(Some(t));
    }
    Ok(stream)
}

#[cfg(not(unix))]
fn connect_bound(
    _addr: std::net::SocketAddr,
    _bind: &str,
    _timeout: Option<std::time::Duration>,
) -> Result<TcpStream, String> {
    Err("BindAddress is only supported on Unix".into())
}

/// Encode a `SocketAddr` into a `sockaddr_storage` byte buffer + length for
/// the raw libc `bind`/`connect` calls.
#[cfg(unix)]
fn sockaddr_bytes(addr: &std::net::SocketAddr) -> (Vec<u8>, nix::libc::socklen_t) {
    match addr {
        std::net::SocketAddr::V4(v4) => {
            let mut sa: nix::libc::sockaddr_in = unsafe { core::mem::zeroed() };
            sa.sin_family = nix::libc::AF_INET as nix::libc::sa_family_t;
            sa.sin_port = v4.port().to_be();
            sa.sin_addr.s_addr = u32::from_ne_bytes(v4.ip().octets());
            let len = core::mem::size_of::<nix::libc::sockaddr_in>() as nix::libc::socklen_t;
            let bytes = unsafe {
                core::slice::from_raw_parts(
                    &sa as *const _ as *const u8,
                    core::mem::size_of::<nix::libc::sockaddr_in>(),
                )
                .to_vec()
            };
            (bytes, len)
        }
        std::net::SocketAddr::V6(v6) => {
            let mut sa: nix::libc::sockaddr_in6 = unsafe { core::mem::zeroed() };
            sa.sin6_family = nix::libc::AF_INET6 as nix::libc::sa_family_t;
            sa.sin6_port = v6.port().to_be();
            sa.sin6_addr.s6_addr = v6.ip().octets();
            let len = core::mem::size_of::<nix::libc::sockaddr_in6>() as nix::libc::socklen_t;
            let bytes = unsafe {
                core::slice::from_raw_parts(
                    &sa as *const _ as *const u8,
                    core::mem::size_of::<nix::libc::sockaddr_in6>(),
                )
                .to_vec()
            };
            (bytes, len)
        }
    }
}

/// Set `SO_KEEPALIVE` on a connected socket (`TCPKeepAlive`). Unix uses libc
/// `setsockopt`; other platforms reject the directive rather than ignore it.
#[cfg(unix)]
fn set_so_keepalive(sock: &TcpStream, on: bool) -> Result<(), String> {
    use std::os::unix::io::AsRawFd;
    let val: nix::libc::c_int = if on { 1 } else { 0 };
    // SAFETY: standard setsockopt on a valid fd with a correctly-sized int.
    let rc = unsafe {
        nix::libc::setsockopt(
            sock.as_raw_fd(),
            nix::libc::SOL_SOCKET,
            nix::libc::SO_KEEPALIVE,
            &val as *const _ as *const nix::libc::c_void,
            core::mem::size_of::<nix::libc::c_int>() as nix::libc::socklen_t,
        )
    };
    if rc != 0 {
        return Err(format!(
            "setsockopt(SO_KEEPALIVE): {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(())
}

#[cfg(not(unix))]
fn set_so_keepalive(_sock: &TcpStream, _on: bool) -> Result<(), String> {
    Err("TCPKeepAlive is only supported on Unix".into())
}

/// Drive the multi-channel forwarding loop: register every `-R` binding on the
/// server, install an `on_forwarded_tcpip` callback that dials the user's
/// local destination per accepted connection, then enter
/// [`Client::serve`] until either the peer hangs up or the process is killed.
///
/// Returns an exit code matching OpenSSH's `-N -R` behaviour: 0 on a clean
/// peer disconnect, 255 on protocol error.
fn run_forwarding(
    mut client: Client,
    cli: &Cli,
    dynamics: &[DynamicForward],
    exit_on_forward_failure: bool,
    gateway: puressh::config::GatewayPorts,
) -> Result<i32, String> {
    // `ExitOnForwardFailure yes` turns a failed bind / grant into a hard
    // abort; otherwise we warn and carry on (OpenSSH's default).
    macro_rules! forward_fail {
        ($($arg:tt)*) => {{
            let msg = format!($($arg)*);
            if exit_on_forward_failure {
                return Err(msg);
            } else {
                eprintln!("ssh: {msg}");
            }
        }};
    }

    // Map "(bound_address, bound_port) → (local_host, local_port)" so the
    // callback can look up the right local destination for each incoming
    // forward. The bound address echoed by the server is "127.0.0.1" since
    // that's what we ask for below.
    let mut routes: std::collections::BTreeMap<(String, u16), (String, u16)> =
        std::collections::BTreeMap::new();
    for r in &cli.remotes {
        let bound_port = match client.request_tcpip_forward("127.0.0.1", r.remote_port) {
            Ok(p) => p,
            Err(e) => {
                forward_fail!("tcpip-forward 127.0.0.1:{}: {e}", r.remote_port);
                continue;
            }
        };
        eprintln!(
            "ssh: -R 127.0.0.1:{}:{}:{} active",
            bound_port, r.local_host, r.local_port,
        );
        routes.insert(
            ("127.0.0.1".to_string(), bound_port),
            (r.local_host.clone(), r.local_port),
        );
    }
    let _ = gateway; // -R always binds loopback server-side in this release.

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

    // -L / -D: bind every local-forward and SOCKS listener, handing each a
    // clone of the ServeContext so its accept thread can open `direct-tcpip`
    // through the running serve loop. Both forward kinds share one context.
    // The bind address comes from GatewayPorts (loopback by default).
    let bind_ip = resolve_bind_addr(gateway, None);
    let ctx_opt: Option<ServeContext> = if cli.locals.is_empty() && dynamics.is_empty() {
        None
    } else {
        let (h, ctx) = handlers.with_serve_context();
        handlers = h;
        for l in &cli.locals {
            match TcpListener::bind((bind_ip.as_str(), l.listen_port)) {
                Ok(listener) => {
                    eprintln!(
                        "ssh: -L {}:{}:{}:{} active",
                        bind_ip, l.listen_port, l.remote_host, l.remote_port,
                    );
                    spawn_local_forward_listener(listener, l.clone(), ctx.clone());
                }
                Err(e) => forward_fail!("-L bind {bind_ip}:{}: {e}", l.listen_port),
            }
        }
        for d in dynamics {
            match TcpListener::bind((d.bind_addr.as_str(), d.listen_port)) {
                Ok(listener) => {
                    eprintln!("ssh: -D {}:{} (SOCKS) active", d.bind_addr, d.listen_port);
                    spawn_dynamic_forward_listener(listener, d.listen_port, ctx.clone());
                }
                Err(e) => forward_fail!("-D bind {}:{}: {e}", d.bind_addr, d.listen_port),
            }
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

/// Per-`-D` SOCKS accept loop. Each accepted TCP connection runs the SOCKS
/// handshake ([`puressh::forwarding::socks::handshake`]) to learn the CONNECT
/// target, opens a `direct-tcpip` channel to it through the serve loop,
/// writes the SOCKS success/failure reply, then splices the channel against
/// the socket. BIND / UDP / bad-auth requests are rejected in-handshake and
/// the connection dropped.
fn spawn_dynamic_forward_listener(listener: TcpListener, listen_port: u16, ctx: ServeContext) {
    use puressh::forwarding::socks;
    thread::spawn(move || {
        for accept in listener.incoming() {
            let mut tcp = match accept {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("ssh: -D accept on :{listen_port}: {e}");
                    continue;
                }
            };
            let ctx = ctx.clone();
            // One thread per connection: the SOCKS handshake reads from the
            // socket and must not block the accept loop.
            thread::spawn(move || {
                let target = match socks::handshake(&mut tcp) {
                    Ok(t) => t,
                    Err(e) => {
                        // Unsupported/protocol errors already wrote any reply
                        // the protocol allows; just log and drop.
                        eprintln!("ssh: -D handshake: {e}");
                        return;
                    }
                };
                let orig = tcp
                    .peer_addr()
                    .map(|a| (a.ip().to_string(), a.port()))
                    .unwrap_or_else(|_| ("127.0.0.1".to_string(), 0));
                match ctx.open_direct_tcpip(&target.host, target.port, &orig.0, orig.1) {
                    Ok(stream) => {
                        if socks::write_reply(&mut tcp, target.version, true).is_err() {
                            return;
                        }
                        spawn_splice_to_tcp(stream, tcp);
                    }
                    Err(e) => {
                        eprintln!("ssh: -D direct-tcpip {}:{}: {e}", target.host, target.port);
                        let _ = socks::write_reply(&mut tcp, target.version, false);
                    }
                }
            });
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
