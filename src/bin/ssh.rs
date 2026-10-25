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
use std::sync::Arc;
use std::thread;

use puressh::auth::SecretString;
use puressh::auth::{ClientCredential, KeyboardInteractiveResponder};
use puressh::client::{
    AlgoOverrides, ChannelStream, Client, ClientHandlers, Config, ForwardedStreamlocalCallback,
    ForwardedStreamlocalOrigin, ForwardedTcpipCallback, ForwardedTcpipOrigin,
};

#[path = "common.rs"]
mod common;

#[path = "dns.rs"]
mod dns;
#[path = "fingerprint.rs"]
mod fingerprint;
#[path = "tundev.rs"]
mod tundev;

/// A warning: printed unless `-q`.
macro_rules! warn {
    ($($t:tt)*) => {
        if !common::is_quiet() {
            eprintln!($($t)*);
        }
    };
}
#[cfg(unix)]
use common::{KeystrokeObfuscator, TickAction};
use common::{
    StrictMode, build_host_key_policy, connect_agent_credentials, default_identity_paths,
    expand_tilde, parse_target, read_kbdint_response, read_password_from_stdin, resolve_user,
    sanitize_terminal_str, set_verbose, vlog,
};

const VERSION: &str = env!("CARGO_PKG_VERSION");

const USAGE: &str = "usage: ssh [-46AaCfGgKkMNnqsTtVvXxYyZ] [-B bind_interface] [-b bind_address]\n           \
                     [-c cipher_spec] [-D [bind_address:]port] [-E log_file]\n           \
                     [-e escape_char] [-F configfile] [-I pkcs11] [-i identity_file]\n           \
                     [-J destination] [-L address] [-l login_name] [-m mac_spec]\n           \
                     [-O ctl_cmd] [-o option] [-P tag] [-p port] [-Q query_option]\n           \
                     [-R address] [-S ctl_path] [-W host:port] [-w local_tun[:remote_tun]]\n           \
                     destination [command [argument ...]]";

/// A `-L` / `LocalForward`: listen on a local port or Unix socket; each
/// connection becomes a `direct-tcpip` (or `direct-streamlocal`) channel.
type LocalForward = puressh::config::LocalForwardSpec;

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

/// A `-R` / `RemoteForward`: the server listens (on a port or a Unix
/// socket) and each connection is spliced to a local port or socket, or is
/// a SOCKS request when there is no destination.
type RemoteForward = puressh::config::RemoteForwardSpec;

struct Cli {
    /// `-F path`: load this `ssh_config` instead of the defaults.
    config_file: Option<PathBuf>,
    /// `None` when `-p` wasn't supplied; the ssh_config `Port` then wins.
    port: Option<u16>,
    identities: Vec<String>,
    cli_user: Option<String>,
    /// `-P tag` (`Match tagged`).
    tag: Option<String>,
    /// `cli_user` came from `-o User=…`, which (unlike `-l` and `user@`)
    /// takes %tokens as the configuration's User does.
    user_from_o: bool,
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
    /// Only consumed by the (unix-only) interactive/pty session path.
    #[cfg_attr(not(unix), allow(dead_code))]
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
    /// `-O <cmd>`: a ControlMaster control command (`check` / `exit` / `stop`).
    /// `None` for a normal session. Honored only on Unix (the mux carrier is
    /// unix-gated); requires a resolved `ControlPath`.
    #[cfg_attr(not(unix), allow(dead_code))]
    control_cmd: Option<String>,
    /// `-O proxy`: run the session through the running master (never
    /// becoming one).
    #[cfg_attr(not(unix), allow(dead_code))]
    mux_proxy: bool,
    /// The `-L` / `-R` / `-D` specifications as given, with their option
    /// letter (for `-O forward` / `-O cancel`).
    #[cfg_attr(not(unix), allow(dead_code))]
    forward_specs: Vec<(u8, String)>,
    /// `-n`: stdin from /dev/null (also implied by `-f`).
    #[cfg_attr(not(unix), allow(dead_code))]
    stdin_null: bool,
    /// `-f`: go to the background after authentication.
    #[cfg_attr(not(unix), allow(dead_code))]
    fork_after_auth: bool,
    /// `-q`: quiet; no warnings or diagnostics.
    quiet: bool,
    /// `-W host:port`: forward stdin/stdout to `host:port` over the server.
    stdio_forward: Option<String>,
    /// `-s`: the command names a subsystem.
    subsystem: bool,
    /// `-G`: print the resolved configuration and exit.
    print_config: bool,
    /// `-Z`: list the public keys authentication would try and exit.
    dump_pubkeys: bool,
    /// `-e char`: escape character for the interactive session (`None` in the
    /// outer option = default `~`; `Some(None)` = `-e none`).
    escape_char: Option<Option<u8>>,
    /// `-E file`: append diagnostics to `file` instead of stderr.
    #[cfg_attr(not(unix), allow(dead_code))]
    log_file: Option<String>,
    /// `-y`: ssh's own messages go to syslog.
    #[cfg_attr(not(unix), allow(dead_code))]
    use_syslog: bool,
    /// `-Q query`: print the supported algorithms of a kind and exit.
    query: Option<String>,
    /// `-V`: print the version and exit.
    version: bool,
    host: String,
    user_in_host: Option<String>,
    command: Option<String>,
}

/// Parse one `-L` value as OpenSSH: `[bind_address:]port:host:hostport`,
/// with Unix socket paths allowed for either end.
fn parse_local_forward(s: &str) -> Result<LocalForward, String> {
    puressh::config::parse_forward(&expand_env(s), false)
        .and_then(puressh::config::ForwardSpec::into_local)
        .ok_or_else(|| format!("Bad local forwarding specification '{s}'"))
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
        return Ok(puressh::config::DynamicForwardSpec::new(
            Some(addr.to_string()),
            listen_port,
        ));
    }
    match s.rsplit_once(':') {
        Some((addr, port)) => {
            let listen_port = port
                .parse::<u16>()
                .map_err(|_| format!("-D: bad port in {s:?}"))?;
            Ok(puressh::config::DynamicForwardSpec::new(
                Some(addr.to_string()),
                listen_port,
            ))
        }
        None => {
            let listen_port = s
                .parse::<u16>()
                .map_err(|_| format!("-D expects [bind:]port, got {s:?}"))?;
            Ok(puressh::config::DynamicForwardSpec::new(None, listen_port))
        }
    }
}

/// Parse one `-R` value as OpenSSH: `[bind_address:]port:host:hostport`
/// (Unix socket paths allowed for either end), or `[bind_address:]port`
/// for a SOCKS proxy on the server whose connections the client dials.
fn parse_remote_forward(s: &str) -> Result<RemoteForward, String> {
    puressh::config::parse_forward(&expand_env(s), true)
        .map(puressh::config::ForwardSpec::into_remote)
        .ok_or_else(|| format!("Bad remote forwarding specification '{s}'"))
}

/// Options of OpenSSH's `ssh` that take a value (its getopt string is
/// `1246ab:c:e:fgi:kl:m:no:p:qstvxAB:CD:E:F:GI:J:KL:MNO:P:Q:R:S:TVw:W:XYy`).
const SSH_VALUE_OPTS: &str = "bceilmopBDEFIJLOPQRSwW";
/// Options of OpenSSH's `ssh` that are plain flags.
const SSH_FLAG_OPTS: &str = "1246afgknqstvxACGKMNTVXYyZ";

/// Parse `-e` values: a single character, `^X` for a control character, or
/// `none`.
fn parse_escape_char(v: &str) -> Result<Option<u8>, String> {
    let b = v.as_bytes();
    match b {
        _ if v.eq_ignore_ascii_case("none") => Ok(None),
        [c] => Ok(Some(*c)),
        [b'^', c]
            if c.is_ascii_alphabetic() || matches!(c, b'@' | b'[' | b'\\' | b']' | b'^' | b'_') =>
        {
            Ok(Some(c.to_ascii_uppercase() & 0x1f))
        }
        _ => Err(format!("-e: bad escape character {v:?}")),
    }
}

/// Parse the command line the way OpenSSH's `ssh` does: getopt-style short
/// options (bundled flags like `-tt` / `-NfL 8080:h:80`, values attached
/// like `-p22` or separate), options are also accepted after the
/// destination, and the first argument after the destination that is not an
/// option starts the remote command — everything from there on, options
/// included, belongs to the command (`ssh host ls -la`).
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
    let mut control_cmd: Option<String> = None;
    let mut mux_proxy = false;
    let mut forward_specs: Vec<(u8, String)> = Vec::new();
    let mut verbose: u8 = 0;
    let mut stdin_null = false;
    let mut fork_after_auth = false;
    let mut quiet = false;
    let mut stdio_forward: Option<String> = None;
    let mut subsystem = false;
    let mut print_config = false;
    let mut dump_pubkeys = false;
    let mut escape_char: Option<Option<u8>> = None;
    let mut log_file: Option<String> = None;
    let mut use_syslog = false;
    let mut query: Option<String> = None;
    let mut version = false;
    let mut tty_count = 0u8;
    let mut host_arg: Option<String> = None;
    let mut command_args: Vec<String> = Vec::new();
    let mut first_user: Option<String> = None;
    let mut user_from_o = false;
    let mut tag: Option<String> = None;

    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
        if a == "--" {
            // End of options: next is the destination (if not seen yet),
            // then the command.
            let mut rest = args[i + 1..].iter().cloned();
            if host_arg.is_none() {
                host_arg = rest.next();
                if let Some(Ok((Some(u), _, _))) = host_arg.as_deref().map(parse_target) {
                    first_user.get_or_insert(u);
                }
            }
            command_args.extend(rest);
            break;
        }
        if !a.starts_with('-') || a == "-" {
            if host_arg.is_none() {
                if let Ok((Some(u), _, _)) = parse_target(a) {
                    first_user.get_or_insert(u);
                }
                host_arg = Some(a.clone());
                i += 1;
                continue;
            }
            // First non-option after the destination: the command.
            command_args.extend_from_slice(&args[i..]);
            break;
        }
        let cluster: Vec<char> = a[1..].chars().collect();
        let mut j = 0;
        while j < cluster.len() {
            let c = cluster[j];
            if SSH_VALUE_OPTS.contains(c) {
                let attached: String = cluster[j + 1..].iter().collect();
                let v = if !attached.is_empty() {
                    attached
                } else {
                    i += 1;
                    args.get(i)
                        .ok_or_else(|| format!("option requires an argument -- {c}"))?
                        .clone()
                };
                match c {
                    'b' => extra_o.push(format!("BindAddress {v}")),
                    'c' => extra_o.push(format!("Ciphers {v}")),
                    'e' => escape_char = Some(parse_escape_char(&v)?),
                    'i' => identities.push(v),
                    // The first user named (-l, -o User, user@host) wins.
                    'l' => {
                        first_user.get_or_insert(v);
                    }
                    'm' => extra_o.push(format!("MACs {v}")),
                    'o' => apply_dash_o(
                        &{
                            let kv = v.trim_start();
                            if kv.len() > 5
                                && kv[..4].eq_ignore_ascii_case("user")
                                && matches!(kv.as_bytes()[4], b'=' | b' ' | b'\t')
                                // The configuration's own parsing (quotes:
                                // Ansible passes `-o User="name"`).
                                && let Some(u) = puressh::config::SshClientConfig::parse(&format!(
                                    "User {}",
                                    kv[5..].trim_start_matches(['=', ' ', '\t'])
                                ))
                                .ok()
                                .and_then(|c| c.lookup("*").user)
                            {
                                user_from_o |= first_user.is_none();
                                first_user.get_or_insert(u);
                            }
                            v.clone()
                        },
                        &mut strict,
                        &mut known_hosts_path,
                        &mut hash_known_hosts,
                        &mut identities_only,
                        &mut compression,
                        &mut request_tty,
                        &mut extra_o,
                    )?,
                    'p' => port = Some(v.parse::<u16>().map_err(|_| "invalid port".to_string())?),
                    'B' => extra_o.push(format!("BindInterface {v}")),
                    'D' => {
                        dynamics_raw.push(parse_dynamic_forward(&v)?);
                        forward_specs.push((b'D', v));
                    }
                    'E' => log_file = Some(v),
                    'F' => config_file = Some(PathBuf::from(v)),
                    'I' => extra_o.push(format!("PKCS11Provider {v}")),
                    // Also a first-obtained `ProxyJump` (so it excludes a
                    // configured ProxyCommand, as OpenSSH's).
                    'J' => {
                        extra_o.push(format!("ProxyJump {v}"));
                        proxy_jump = Some(v);
                    }
                    'L' => {
                        locals.push(parse_local_forward(&v)?);
                        forward_specs.push((b'L', v));
                    }
                    // `-O <cmd>`: control a running ControlMaster. We accept
                    // the multiplexing control commands puressh's mux master
                    // honors: `check` (is the master alive?), `exit`/`stop`.
                    'O' => match v.as_str() {
                        "check" | "exit" | "stop" | "forward" | "cancel" | "conninfo"
                        | "channels" => control_cmd = Some(v),
                        "proxy" => mux_proxy = true,
                        _ => return Err("Invalid multiplex command.".into()),
                    },
                    // `-P tag`: the `Tag` that `Match tagged` compares.
                    'P' => {
                        extra_o.push(format!("Tag {v}"));
                        tag.get_or_insert(v);
                    }
                    'Q' => query = Some(v),
                    'R' => {
                        remotes.push(parse_remote_forward(&v)?);
                        forward_specs.push((b'R', v));
                    }
                    'S' => extra_o.push(format!("ControlPath {v}")),
                    'w' => {
                        // As OpenSSH: enables tunnelling (point-to-point
                        // unless set already) with these devices.
                        if parse_tun_units(&v).is_none() {
                            eprintln!("Bad tun device '{v}'");
                            std::process::exit(255);
                        }
                        extra_o.push("Tunnel yes".to_string());
                        extra_o.push(format!("TunnelDevice {v}"));
                    }
                    'W' => stdio_forward = Some(v),
                    _ => unreachable!(),
                }
                // The value consumed the rest of the cluster.
                break;
            }
            if !SSH_FLAG_OPTS.contains(c) {
                return Err(format!("unknown option -- {c}"));
            }
            match c {
                '1' => return Err("SSH protocol v.1 is no longer supported".into()),
                '2' | 'k' => {}
                'y' => use_syslog = true,
                '4' => extra_o.push("AddressFamily inet".into()),
                '6' => extra_o.push("AddressFamily inet6".into()),
                'a' => {
                    agent_forward = false;
                    extra_o.push("ForwardAgent no".into());
                }
                'A' => agent_forward = true,
                'C' => compression = Some(true),
                'f' => {
                    fork_after_auth = true;
                    stdin_null = true;
                }
                'g' => extra_o.push("GatewayPorts yes".into()),
                'G' => print_config = true,
                'Z' => dump_pubkeys = true,
                // GSSAPI authentication / credential delegation: not
                // implemented, so (as with GSSAPIAuthentication) nothing to
                // turn on; OpenSSH without a Kerberos ticket behaves alike.
                'K' => {}
                'M' => extra_o.push("ControlMaster yes".into()),
                'n' => stdin_null = true,
                'N' => no_command = true,
                'q' => quiet = true,
                's' => subsystem = true,
                't' => tty_count = tty_count.saturating_add(1),
                'T' => request_tty = Some(puressh::config::RequestTty::No),
                // OpenSSH-style verbosity; `-vvv` stacks.
                'v' => verbose = verbose.saturating_add(1).min(3),
                'V' => version = true,
                'x' => {
                    x11_forward = None;
                    extra_o.push("ForwardX11 no".into());
                }
                'X' => x11_forward = Some(X11Forward::Untrusted),
                'Y' => x11_forward = Some(X11Forward::Trusted),
                _ => unreachable!(),
            }
            j += 1;
        }
        i += 1;
    }
    if first_user.is_some() {
        cli_user = first_user;
    }
    // `-t` asks for a terminal when stdin is one; `-tt` always.
    match tty_count {
        0 => {}
        1 => request_tty = Some(puressh::config::RequestTty::Yes),
        _ => request_tty = Some(puressh::config::RequestTty::Force),
    }

    // `-V` and `-Q` need no destination.
    if version || query.is_some() {
        return Ok(Cli {
            config_file,
            port,
            identities,
            cli_user,
            user_from_o,
            tag,
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
            control_cmd,
            mux_proxy,
            forward_specs: forward_specs.clone(),
            stdin_null,
            fork_after_auth,
            quiet,
            stdio_forward,
            subsystem,
            print_config,
            dump_pubkeys,
            escape_char,
            log_file,
            use_syslog,
            query,
            version,
            verbose,
            host: String::new(),
            user_in_host: None,
            command: None,
        });
    }

    let target = host_arg.ok_or("missing host argument")?;
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
    let command = if command_args.is_empty() {
        None
    } else {
        Some(command_args.join(" "))
    };

    Ok(Cli {
        config_file,
        port,
        identities,
        cli_user,
        user_from_o,
        tag,
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
        control_cmd,
        mux_proxy,
        forward_specs,
        stdin_null,
        fork_after_auth,
        quiet,
        stdio_forward,
        subsystem,
        print_config,
        dump_pubkeys,
        escape_char,
        log_file,
        use_syslog,
        query,
        version,
        verbose,
        host,
        user_in_host,
        command,
    })
}

/// One `-o KEY=VALUE` (or `-o "KEY VALUE"`): the handful of keywords with a
/// dedicated `Cli` field are set directly; every other keyword is queued in
/// `extra_o` for the real config parser.
#[allow(clippy::too_many_arguments)]
fn apply_dash_o(
    v: &str,
    strict: &mut Option<StrictMode>,
    known_hosts_path: &mut Option<PathBuf>,
    hash_known_hosts: &mut Option<bool>,
    identities_only: &mut Option<bool>,
    compression: &mut Option<bool>,
    request_tty: &mut Option<puressh::config::RequestTty>,
    extra_o: &mut Vec<String>,
) -> Result<(), String> {
    // The unrecognised-keyword path below joins every `-o` with `\n` into a
    // synthetic config that the real parser reads; a value carrying a line
    // break would smuggle in extra directives. Refuse up front.
    if v.contains(['\n', '\r']) {
        return Err(format!(
            "-o value must not contain a newline or carriage return: {v:?}"
        ));
    }
    // OpenSSH accepts both `Key=Value` and `Key Value`.
    let (k, val) = match v.split_once('=') {
        Some((k, val)) if !k.trim().contains(char::is_whitespace) => (k.trim(), val.trim()),
        _ => v
            .trim()
            .split_once(char::is_whitespace)
            .map(|(k, val)| (k, val.trim()))
            .ok_or_else(|| format!("-o expects KEY=VALUE, got {v:?}"))?,
    };
    // The first value given wins, as for every option (OpenSSH).
    let yes_no = |val: &str| match val.to_ascii_lowercase().as_str() {
        "yes" | "on" | "true" => Some(true),
        "no" | "off" | "false" => Some(false),
        _ => None,
    };
    match k.to_ascii_lowercase().as_str() {
        "stricthostkeychecking" => {
            let mode = match val.to_ascii_lowercase().as_str() {
                "yes" | "true" => StrictMode::Yes,
                "no" | "off" | "false" => StrictMode::No,
                "accept-new" => StrictMode::AcceptNew,
                "ask" => StrictMode::Ask,
                other => return Err(format!("unknown StrictHostKeyChecking={other}")),
            };
            strict.get_or_insert(mode);
        }
        "userknownhostsfile" => {
            known_hosts_path.get_or_insert_with(|| PathBuf::from(val));
        }
        "hashknownhosts" => {
            let v = yes_no(val).ok_or_else(|| format!("unknown HashKnownHosts={val}"))?;
            hash_known_hosts.get_or_insert(v);
        }
        "identitiesonly" => {
            let v = yes_no(val).ok_or_else(|| format!("unknown IdentitiesOnly={val}"))?;
            identities_only.get_or_insert(v);
        }
        "compression" => {
            let v = yes_no(val).ok_or_else(|| format!("unknown Compression={val}"))?;
            compression.get_or_insert(v);
        }
        "requesttty" => {
            let v = match val.to_ascii_lowercase().as_str() {
                "no" | "false" => puressh::config::RequestTty::No,
                "yes" | "true" => puressh::config::RequestTty::Yes,
                "force" => puressh::config::RequestTty::Force,
                "auto" => puressh::config::RequestTty::Auto,
                other => return Err(format!("unknown RequestTTY={other}")),
            };
            request_tty.get_or_insert(v);
        }
        _ => extra_o.push(format!("{k} {val}")),
    }
    Ok(())
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
    // `-o` options are obtained before the files: theirs win, and their
    // list entries (IdentityFile, forwards, …) come first.
    let mut o = parsed.lookup("*");
    o.merge_lower(cfg_block);
    *cfg_block = o;
    Ok(())
}

/// The agent's key for the identity `path` — the public key in `path`
/// itself or in `path.pub` — unless `have` already offers it.
#[cfg(unix)]
fn agent_identity_for(path: &str, have: &[ClientCredential]) -> Option<ClientCredential> {
    let blob_of = |p: &str| {
        let text = std::fs::read_to_string(p).ok()?;
        let b64 = text.split_whitespace().nth(1)?;
        purecrypto::der::base64_decode(b64).ok()
    };
    let blob = blob_of(path).or_else(|| blob_of(&format!("{path}.pub")))?;
    let offered = have.iter().any(|c| match c {
        ClientCredential::PublicKey(k) => k.public_blob() == blob,
        _ => false,
    });
    if offered {
        return None;
    }
    let signer = common::agent_signer_for(&blob)?;
    Some(ClientCredential::PublicKey(Box::new(signer)))
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
/// ssh_config block's `IdentityFile`s, then (only when neither names one)
/// the OpenSSH default identities under `~/.ssh/`. Mirrors OpenSSH. `cli_identities` is empty
/// for ProxyJump hops (the `-i` flag targets the final host only).
fn collect_credentials(
    cfg_block: &puressh::config::ClientOptions,
    cli_identities: &[String],
    identities_only: bool,
) -> Vec<ClientCredential> {
    #[cfg(feature = "security-key")]
    if let Some(p) = &cfg_block.security_key_provider {
        common::set_security_key_provider(p);
    }
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
            Err(e) => warn!("warning: agent: {e}"),
        }
    }
    // PKCS#11 token keys (`PKCS11Provider`, `-I`) come before the identity
    // files, as OpenSSH lists them, each with any `CertificateFile` that
    // certifies it.
    #[cfg(feature = "pkcs11")]
    if let Some(module) = cfg_block
        .pkcs11_provider
        .as_deref()
        .filter(|p| !p.eq_ignore_ascii_case("none"))
    {
        let batch = cfg_block.batch_mode == Some(true);
        for key in common::pkcs11_keys(module, batch) {
            let blob = key.public_key().wire_blob();
            for cert_path in &cfg_block.certificate_files {
                let cert_path = expand_tilde(cert_path);
                let Ok(cert) = std::fs::read_to_string(&cert_path)
                    .map_err(|_| ())
                    .and_then(|t| {
                        puressh::cert::Certificate::parse_openssh_line(&t).map_err(|_| ())
                    })
                else {
                    continue;
                };
                if cert.embedded_pubkey_blob() != blob {
                    continue;
                }
                let Some(name) = puressh::cert::cert_name_for_key_type(cert.embedded_algorithm())
                else {
                    continue;
                };
                if let Ok(ch) = puressh::hostkey::CertHostKey::new(
                    Box::new(common::Pkcs11Signer(key.clone())),
                    &cert,
                    name,
                ) {
                    vlog(
                        1,
                        &format!("certificate {cert_path}: offered (PKCS#11 key)"),
                    );
                    credentials.push(ClientCredential::PublicKey(Box::new(ch)));
                }
            }
            vlog(
                1,
                &format!(
                    "PKCS#11 key {} {}",
                    key.public_key().type_label(),
                    key.public_key().sha256_fingerprint()
                ),
            );
            credentials.push(ClientCredential::PublicKey(Box::new(common::Pkcs11Signer(
                key,
            ))));
        }
    }
    // User certificates (`CertificateFile`). Each cert is paired with the
    // IdentityFile / -i private key whose embedded key it certifies, then
    // offered as a `CertHostKey` credential *ahead of* the plain keys so the
    // server sees the certificate first. The signed userauth blob hashes the
    // cert key-type name + cert blob, which `CertHostKey` produces correctly.
    {
        use puressh::cert::Certificate;
        use puressh::hostkey::CertHostKey;

        // Candidate private keys: -i then config IdentityFile.
        let mut key_paths: Vec<String> = cli_identities.to_vec();
        key_paths.extend(cfg_block.identity_files.iter().map(|p| expand_tilde(p)));

        // Explicit CertificateFile entries pair with any of those keys; like
        // OpenSSH, `<identity>-cert.pub` next to an identity (including
        // the default ones) is also offered, paired with that identity.
        let mut candidates: Vec<(String, Option<String>)> = cfg_block
            .certificate_files
            .iter()
            .map(|c| (expand_tilde(c), None))
            .collect();
        let mut implicit_keys = key_paths.clone();
        if key_paths.is_empty() {
            implicit_keys.extend(
                default_identity_paths()
                    .into_iter()
                    .filter(|p| p.exists())
                    .map(|p| p.display().to_string()),
            );
        }
        for kp in implicit_keys {
            // The identity's own `.pub`, when that is a certificate (OpenSSH
            // takes the identity's public half from it), then its
            // `-cert.pub`.
            let pub_path = format!("{kp}.pub");
            let pub_is_cert = std::fs::read_to_string(&pub_path)
                .ok()
                .and_then(|t| t.split_whitespace().next().map(str::to_string))
                .is_some_and(|t| puressh::cert::is_cert_name(&t));
            let cert_path = format!("{kp}-cert.pub");
            for path in [pub_is_cert.then_some(pub_path), Some(cert_path)]
                .into_iter()
                .flatten()
            {
                if std::path::Path::new(&path).exists()
                    && !candidates.iter().any(|(c, _)| *c == path)
                {
                    candidates.push((path, Some(kp.clone())));
                }
            }
        }

        for (cert_path, own_key) in candidates {
            let text = match std::fs::read_to_string(&cert_path) {
                Ok(t) => t,
                Err(e) => {
                    warn!("warning: CertificateFile {cert_path}: {e}");
                    continue;
                }
            };
            let cert = match Certificate::parse_openssh_line(&text) {
                Ok(c) => c,
                Err(e) => {
                    warn!("warning: CertificateFile {cert_path}: {e}");
                    continue;
                }
            };
            // Find the matching private key by embedded-key equality.
            let mut paired = false;
            let pair_with = match &own_key {
                Some(k) => std::slice::from_ref(k),
                None => &key_paths[..],
            };
            let batch = cfg_block.batch_mode == Some(true);
            for kp in pair_with {
                let Ok(Some(signer)) = common::identity_signer(kp, own_key.is_some(), batch) else {
                    continue;
                };
                if signer.public_blob() != cert.embedded_pubkey_blob {
                    continue;
                }
                let Some(cert_name) = puressh::cert::cert_name_for_key_type(signer.algorithm())
                else {
                    continue;
                };
                match CertHostKey::new(signer, &cert, cert_name) {
                    Ok(ch) => {
                        vlog(1, &format!("certificate {cert_path}: offered"));
                        credentials.push(ClientCredential::PublicKey(Box::new(ch)));
                        paired = true;
                        break;
                    }
                    Err(e) => warn!("warning: CertificateFile {cert_path}: {e}"),
                }
            }
            // Else a key the agent holds.
            #[cfg(unix)]
            if !paired
                && let Some(signer) = common::agent_signer_for(&cert.embedded_pubkey_blob)
                && let Some(cert_name) = puressh::cert::cert_name_for_key_type(
                    puressh::hostkey::HostKey::algorithm(&signer),
                )
            {
                match CertHostKey::new(Box::new(signer), &cert, cert_name) {
                    Ok(ch) => {
                        vlog(1, &format!("certificate {cert_path}: offered (agent key)"));
                        credentials.push(ClientCredential::PublicKey(Box::new(ch)));
                        paired = true;
                    }
                    Err(e) => warn!("warning: CertificateFile {cert_path}: {e}"),
                }
            }
            // OpenSSH says nothing of a certificate it has no key for
            // (unless debugging).
            if !paired {
                vlog(
                    1,
                    &format!("CertificateFile {cert_path}: no matching private key"),
                );
            }
        }
    }
    let batch = cfg_block.batch_mode == Some(true);
    let explicit = cli_identities
        .iter()
        .cloned()
        .chain(cfg_block.identity_files.iter().map(|p| expand_tilde(p)));
    for id_path in explicit {
        let loaded = match common::identity_credential(&id_path, false, batch) {
            Ok(Some(c)) => {
                vlog(1, &format!("identity {id_path}: loaded"));
                credentials.push(c);
                true
            }
            Ok(None) => false,
            Err(e) => {
                // A public key (`-i key.pub`) whose private half the agent
                // holds is used through the agent, as OpenSSH does.
                #[cfg(unix)]
                if let Some(c) = agent_identity_for(&id_path, &credentials) {
                    vlog(1, &format!("identity {id_path}: agent key"));
                    credentials.push(c);
                    continue;
                }
                warn!("warning: {e}");
                continue;
            }
        };
        #[cfg(unix)]
        if !loaded && let Some(c) = agent_identity_for(&id_path, &credentials) {
            vlog(1, &format!("identity {id_path}: agent key"));
            credentials.push(c);
        }
        #[cfg(not(unix))]
        let _ = loaded;
    }
    // Like OpenSSH, the default identities are used only when no -i or
    // IdentityFile names one (IdentitiesOnly restricts agent keys, not these).
    if cli_identities.is_empty() && cfg_block.identity_files.is_empty() {
        for path in default_identity_paths() {
            let path = path.display().to_string();
            match common::identity_credential(&path, true, batch) {
                Ok(Some(c)) => {
                    vlog(1, &format!("default identity {path}: loaded"));
                    credentials.push(c);
                }
                Ok(None) => vlog(2, &format!("default identity {path}: skipped")),
                Err(e) => warn!("warning: {e}"),
            }
        }
    }
    // RequiredRSASize: smaller RSA keys are not offered (this library has a
    // 2048-bit floor of its own).
    let min_rsa = cfg_block.required_rsa_size.unwrap_or(1024);
    if min_rsa > 2048 {
        credentials.retain(|c| {
            let ClientCredential::PublicKey(k) = c else {
                return true;
            };
            let blob = k.public_blob();
            match puressh::key::PublicKey::parse_wire_blob(&blob) {
                Ok(pk @ puressh::key::PublicKey::Rsa { .. }) if pk.bit_length() < min_rsa => {
                    eprintln!(
                        "RSA key {} is shorter than RequiredRSASize: Invalid key length",
                        common::fingerprint_b64_sha256(&blob)
                    );
                    false
                }
                _ => true,
            }
        });
    }
    credentials
}

/// Whether a key exchange is post-quantum (OpenSSH's `KEX_IS_PQ` ones).
fn is_pq_kex(name: &str) -> bool {
    matches!(
        name,
        "mlkem768x25519-sha256"
            | "mlkem768nistp256-sha256"
            | "sntrup761x25519-sha512"
            | "sntrup761x25519-sha512@openssh.com"
    )
}

/// A keyboard-interactive responder (RFC 4256) backed by the terminal: prints
/// the server's title/instruction once, then reads one answer per prompt,
/// honoring each prompt's echo flag via [`read_kbdint_response`].
struct StdinKbdResponder {
    /// `KbdInteractiveDevices`.
    devices: String,
}
impl KeyboardInteractiveResponder for StdinKbdResponder {
    fn submethods(&self) -> String {
        self.devices.clone()
    }

    fn respond(
        &mut self,
        name: &str,
        instruction: &str,
        prompts: &[(String, bool)],
    ) -> Vec<String> {
        // `name`, `instruction`, and each prompt are server-supplied and
        // reach the TTY before any trust decision; scrub control bytes so a
        // hostile server can't inject terminal escapes (the per-prompt scrub
        // happens inside `read_kbdint_response`).
        if !name.is_empty() {
            eprintln!("{}", sanitize_terminal_str(name));
        }
        if !instruction.is_empty() {
            eprintln!("{}", sanitize_terminal_str(instruction));
        }
        // The trait returns plain `String`s (the driver zeroizes the
        // encoded packet, not these). Move each answer out of its
        // `Zeroizing` buffer rather than cloning it so there is exactly one
        // plaintext copy alive, owned by the auth driver.
        prompts
            .iter()
            .map(|(prompt, echo)| {
                read_kbdint_response(prompt, *echo)
                    .map(|mut z| core::mem::take(&mut *z))
                    // On read error, send an empty answer (the server will
                    // reject); never abort the whole exchange here.
                    .unwrap_or_default()
            })
            .collect()
    }
}

/// A completed key exchange, as OpenSSH's `-v` shows it.
fn log_kex(n: &puressh::hazmat::transport::Negotiated) {
    if common::verbose_level() == 0 {
        return;
    }
    let mac = |m: &str| {
        if m.is_empty() {
            "<implicit>".to_string()
        } else {
            m.to_string()
        }
    };
    vlog(1, &format!("kex: algorithm: {}", n.kex));
    vlog(1, &format!("kex: host key algorithm: {}", n.host_key));
    vlog(
        1,
        &format!(
            "kex: server->client cipher: {} MAC: {} compression: {}",
            n.cipher_s2c,
            mac(&n.mac_s2c),
            n.comp_s2c
        ),
    );
    vlog(
        1,
        &format!(
            "kex: client->server cipher: {} MAC: {} compression: {}",
            n.cipher_c2s,
            mac(&n.mac_c2s),
            n.comp_c2s
        ),
    );
    if let Some(g) = n.gex {
        vlog(
            1,
            &format!(
                "SSH2_MSG_KEX_DH_GEX_REQUEST({}<{}<{}) sent",
                g.min, g.n, g.max
            ),
        );
        vlog(1, "SSH2_MSG_KEX_DH_GEX_GROUP received");
        vlog(2, &format!("bits set: {}/{}", g.bits_set, g.group_bits));
    }
    vlog(1, "SSH2_MSG_NEWKEYS sent");
    vlog(1, "SSH2_MSG_NEWKEYS received");
}

/// Authenticate `client` as `user`. Builds a SINGLE `ClientAuth` driver for
/// this connection — publickey credentials first, then a re-promptable
/// password closure, then a keyboard-interactive responder — and runs it once.
/// Crucially this sends exactly one SERVICE_REQUEST: every method is attempted
/// inside the same userauth exchange, which is both RFC-conformant and required
/// for a multi-factor server. Used for the final target and every ProxyJump
/// hop.
fn authenticate_client(
    client: &mut Client,
    host: &str,
    user: &str,
    credentials: Vec<ClientCredential>,
    cfg_block: &puressh::config::ClientOptions,
) -> Result<(), String> {
    // Each key exchange in OpenSSH's debug words (the first has already run).
    if let Some(n) = client.negotiated() {
        log_kex(&n);
        // WarnWeakCrypto (default yes): a key exchange that is not
        // post-quantum, unless KexAlgorithms chose the list.
        if cfg_block.warn_weak_crypto != Some(false)
            && cfg_block.kex_algorithms.is_none()
            && !is_pq_kex(&n.kex)
            && !common::is_quiet()
        {
            eprintln!("** WARNING: connection is not using a post-quantum key exchange algorithm.");
            eprintln!("** This session may be vulnerable to \"store now, decrypt later\" attacks.");
            eprintln!("** The server may need to be upgraded. See https://openssh.com/pq.html");
        }
    }
    // Agent keys sign for this session only (destination constraints).
    #[cfg(unix)]
    if let Some(b) = client.session_binding() {
        common::bind_auth_agents(&b);
        let _ = SESSION_BINDING.set(b);
    }
    client.set_kex_observer(log_kex);

    // Whether password auth is permitted: BatchMode disables it outright;
    // PreferredAuthentications must include "password"; NumberOfPasswordPrompts
    // 0 also disables it.
    let batch = cfg_block.batch_mode == Some(true);
    let password_allowed_by_prefs = cfg_block
        .preferred_authentications
        .as_ref()
        .map(|p| p.iter().any(|m| m == "password"))
        .unwrap_or(true);
    let kbdint_allowed_by_prefs = cfg_block
        .preferred_authentications
        .as_ref()
        .map(|p| p.iter().any(|m| m == "keyboard-interactive"))
        .unwrap_or(true);
    // OpenSSH default is 3 attempts.
    let max_prompts = cfg_block.number_of_password_prompts.unwrap_or(3);
    // Without a controlling terminal or an askpass helper there is nowhere
    // safe to ask: OpenSSH fails closed rather than reading answers from a
    // redirected stdin (which a hostile server could otherwise harvest by
    // offering `password`). Treat that exactly like BatchMode.
    let can_prompt = batch || common::secret_prompt_available();
    if !batch && !can_prompt {
        vlog(
            1,
            "no controlling terminal and $SSH_ASKPASS unset: password and \
             keyboard-interactive auth disabled",
        );
    }
    let password_enabled = !batch
        && can_prompt
        && password_allowed_by_prefs
        && max_prompts > 0
        && cfg_block.password_authentication != Some(false);
    let kbdint_enabled = !batch
        && can_prompt
        && kbdint_allowed_by_prefs
        && cfg_block.kbd_interactive_authentication != Some(false);

    // The server's banner, on stderr as OpenSSH shows it (not with -q or a
    // LogLevel below INFO); control characters other than newlines and
    // tabs are shown as `\ooo`.
    client.set_banner_handler(|msg: &str| {
        if common::is_quiet() {
            return;
        }
        let mut out = String::with_capacity(msg.len());
        for c in msg.chars() {
            if (c.is_control() && !matches!(c, '\n' | '\r' | '\t')) || c == '\u{7f}' {
                for b in c.to_string().bytes() {
                    out.push_str(&format!("\\{b:03o}"));
                }
            } else {
                out.push(c);
            }
        }
        // The terminal's stderr even under -E, as OpenSSH writes it.
        let mut err = common::remote_stderr();
        let _ = err.write_all(out.as_bytes());
        let _ = err.flush();
    });
    let mut auth = client.new_auth_driver(user);
    // OpenSSH starts with "none": it learns which methods the server takes
    // (for `Permission denied (…)`) and logs in where none is enough.
    auth.add_credential(ClientCredential::None);
    if !credentials.is_empty() {
        vlog(
            1,
            &format!("offering {} publickey credential(s)", credentials.len()),
        );
        for c in credentials {
            auth.add_credential(c);
        }
    }

    // Re-promptable password: the closure owns the NumberOfPasswordPrompts cap
    // and BatchMode. It is invoked by the driver each time `password` is
    // attempted; `retry` is true after a wrong password where the server still
    // offers `password`. Returning None stops further attempts.
    if password_enabled {
        let mut attempts: u32 = 0;
        let closure = move |retry: bool| -> Option<SecretString> {
            if retry {
                eprintln!("Permission denied, please try again.");
            }
            if attempts >= max_prompts {
                return None;
            }
            attempts += 1;
            match read_password_from_stdin() {
                // `SecretString` wraps its own `Zeroizing`; moving the
                // `String` out of ours (leaving an empty, already-wiped
                // buffer behind) avoids a second plaintext copy.
                Ok(mut z) => Some(SecretString::from(core::mem::take(&mut *z))),
                Err(e) => {
                    eprintln!("read password: {e}");
                    None
                }
            }
        };
        auth.add_credential(ClientCredential::PasswordPrompt(Box::new(closure)));
    } else if batch {
        vlog(1, "BatchMode: no interactive password prompt");
    }

    // Keyboard-interactive: offered after password (OpenSSH's default order
    // for these two), gated on PreferredAuthentications and BatchMode.
    if kbdint_enabled {
        auth.add_credential(ClientCredential::KeyboardInteractive(Box::new(
            StdinKbdResponder {
                devices: cfg_block
                    .kbd_interactive_devices
                    .clone()
                    .unwrap_or_default(),
            },
        )));
    }

    match client.run_auth(auth) {
        Ok(()) => {
            vlog(1, &format!("authenticated as {user}"));
            Ok(())
        }
        // OpenSSH's wording, which sshpass, Ansible and scripts look for.
        Err(puressh::Error::AuthFailed) => {
            eprintln!(
                "{user}@{host}: Permission denied ({}).",
                // Server-supplied method names (USERAUTH_FAILURE).
                sanitize_terminal_str(&client.auth_methods_left().join(","))
            );
            Err(String::new())
        }
        Err(e) => match transport_fatal(
            &e.to_string(),
            &format!("{host} port {}", cfg_block.port.unwrap_or(22)),
        ) {
            Some(m) => {
                eprintln!("{m}");
                Err(String::new())
            }
            None => Err(format!("Auth failed: {e}")),
        },
    }
}

/// A corrupted connection, reported in OpenSSH's words (which tools and its
/// test suite look for): what the packet layer found, then
/// `ssh_dispatch_run_fatal: Connection to HOST port PORT: <reason>`.
fn transport_fatal(err: &str, peer: &str) -> Option<String> {
    let (first, reason) = if err.contains("bad MAC") {
        (
            "Corrupted MAC on input.",
            "message authentication code incorrect",
        )
    } else if err.contains("packet length exceeds limit")
        || err.contains("packet too short")
        || err.contains("not block-aligned")
    {
        ("Bad packet length.", "Connection corrupted")
    } else {
        return None;
    };
    Some(format!(
        "{first}\nssh_dispatch_run_fatal: Connection to {peer}: {reason}"
    ))
}

/// Build the [`Config`] for a host from its resolved ssh_config block:
/// host-key policy + crypto-algorithm overrides.
fn config_for_host(
    cfg_block: &puressh::config::ClientOptions,
    cli: &Cli,
    connect_host: &str,
) -> Result<Config, String> {
    let mut strict = common::pick(cli.strict, cfg_block.strict_host_key, StrictMode::Ask);
    // BatchMode never prompts. An interactive `ask` would block forever
    // under BatchMode, so OpenSSH promotes it to `yes` (refuse unknown).
    if cfg_block.batch_mode == Some(true) && strict == StrictMode::Ask {
        strict = StrictMode::Yes;
    }
    // UserKnownHostsFile: a list, as OpenSSH's (default known_hosts and
    // known_hosts2); new keys go to the first, all are read. `none`: none.
    let all_user_files = user_known_hosts_files(cli, cfg_block);
    let mut user_files = all_user_files.clone();
    let first = (!user_files.is_empty()).then(|| user_files.remove(0));
    let hash_known_hosts = common::pick(cli.hash_known_hosts, cfg_block.hash_known_hosts, false);
    let mut policy = build_host_key_policy(
        strict,
        Some(first.unwrap_or_else(|| PathBuf::from("/dev/null"))),
        hash_known_hosts,
        all_user_files,
    )?;
    common::apply_known_hosts_options(&mut policy, cfg_block)?;
    if let puressh::client::HostKeyPolicy::KnownHosts(kh) = &mut policy {
        for path in user_files {
            match puressh::known_hosts::KnownHosts::load(&path) {
                Ok(store) => kh.global.push(Arc::new(store)),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => vlog(1, &format!("known_hosts {}: {e}", path.display())),
            }
        }
        install_host_key_checks(
            kh,
            cfg_block,
            connect_host,
            strict,
            user_known_hosts_files(cli, cfg_block),
        );
    }

    // HostKeyAlgorithms +ssh-rsa opt-in: if the resolved host-key list names
    // legacy bare `ssh-rsa`, enable SHA-1 host-key verification. This is the
    // ONLY way the SHA-1 form is ever permitted — it stays off by default.
    //
    // SECURITY: ssh-rsa uses SHA-1, which is broken; the only legitimate use
    // is interop with ancient peers in known-controlled environments. The flag
    // is process-wide (a single atomic), so once any host's config opts in it
    // affects subsequent host-key verification in this process.
    if cfg_block.host_key_algorithms.as_ref().is_some_and(|list| {
        list.iter()
            .any(|n| n == "ssh-rsa" || n == "ssh-rsa-cert-v01@openssh.com")
    }) {
        vlog(
            1,
            "HostKeyAlgorithms names ssh-rsa: enabling legacy SHA-1 host-key verification \
             (insecure; interop opt-in)",
        );
        puressh::hostkey::set_allow_rsa_sha1(true);
    }
    // Likewise `PubkeyAcceptedAlgorithms +ssh-rsa`: sign with SHA-1 RSA for
    // servers that take nothing else (before OpenSSH 7.2).
    if cfg_block
        .pubkey_accepted_algorithms
        .as_ref()
        .is_some_and(|list| {
            list.iter()
                .any(|n| n == "ssh-rsa" || n == "ssh-rsa-cert-v01@openssh.com")
        })
    {
        vlog(
            1,
            "PubkeyAcceptedAlgorithms names ssh-rsa: enabling legacy SHA-1 RSA signatures \
             (insecure; interop opt-in)",
        );
        puressh::hostkey::set_allow_rsa_sha1(true);
    }

    let mut algorithms = AlgoOverrides::default();
    algorithms.ciphers = cfg_block.ciphers.clone();
    algorithms.macs = cfg_block.macs.clone();
    algorithms.kex_algorithms = cfg_block.kex_algorithms.clone();
    algorithms.host_key_algorithms = cfg_block.host_key_algorithms.clone();
    algorithms.pubkey_accepted_algorithms = cfg_block.pubkey_accepted_algorithms.clone();
    algorithms.ca_signature_algorithms = cfg_block.ca_signature_algorithms.clone();
    // -o Compression / config Compression. The keyword is rejected
    // up front (in run()) when the `compress` feature is absent, so
    // by the time we get here Some(true) is honourable.
    algorithms.compression = cli.compression.or(cfg_block.compression);
    algorithms.version_addendum = cfg_block.version_addendum.clone();
    Ok(Config::new(policy).with_algorithms(algorithms))
}

/// The host-key checks OpenSSH makes around known_hosts: `RequiredRSASize`,
/// `NoHostAuthenticationForLocalhost` and `VerifyHostKeyDNS` before it,
/// `VisualHostKey` and `CheckHostIP`'s address check after, with
/// fingerprints in `FingerprintHash`.
fn install_host_key_checks(
    kh: &mut puressh::client::KnownHostsPolicy,
    cfg_block: &puressh::config::ClientOptions,
    connect_host: &str,
    strict: StrictMode,
    files: Vec<PathBuf>,
) {
    use puressh::config::VerifyHostKeyDns;
    let hash = cfg_block
        .fingerprint_hash
        .clone()
        .unwrap_or_else(|| "SHA256".into());
    let visual = cfg_block.visual_host_key == Some(true);
    {
        let hash = hash.clone();
        common::set_host_key_show(Box::new(move |blob: &[u8]| {
            (
                fingerprint::fingerprint(blob, &hash),
                visual
                    .then(|| fingerprint::randomart_of_blob(blob, &hash))
                    .flatten(),
            )
        }));
    }
    kh.notice = Some(Arc::new(|msg: &str| {
        if !common::is_quiet() {
            eprintln!("{msg}");
        }
    }));
    if visual {
        let hash = hash.clone();
        kh.on_known = Some(Arc::new(move |_key_type: &str, blob: &[u8]| {
            if !common::is_quiet() {
                eprintln!(
                    "Host key fingerprint is: {}\n{}",
                    fingerprint::fingerprint(blob, &hash),
                    fingerprint::randomart_of_blob(blob, &hash).unwrap_or_default()
                );
            }
        }));
    }
    kh.on_address_change = common::openssh_address_change_action(strict, files);
    let min_rsa = cfg_block.required_rsa_size.unwrap_or(1024);
    let localhost = cfg_block.no_host_authentication_for_localhost == Some(true)
        && cfg_block.host_key_alias.is_none();
    let dns_mode = cfg_block
        .verify_host_key_dns
        .unwrap_or(VerifyHostKeyDns::No);
    let host = connect_host.to_string();
    kh.pre_check = Some(Arc::new(move |key_type: &str, blob: &[u8]| {
        // This library refuses RSA keys under 2048 bits whatever the floor.
        if key_type == "ssh-rsa"
            && min_rsa > 2048
            && let Ok(pk) = puressh::key::PublicKey::parse_wire_blob(blob)
            && pk.bit_length() < min_rsa
        {
            eprintln!("Bad server host key: Invalid key length");
            std::process::exit(255);
        }
        if localhost && common::peer_addr().is_some_and(|a| a.ip().to_canonical().is_loopback()) {
            vlog(1, "Forcing accepting of host key for loopback/localhost.");
            HOST_KEY_FORCED.store(true, std::sync::atomic::Ordering::Relaxed);
            return Some(true);
        }
        if dns_mode != VerifyHostKeyDns::No {
            let mut matched = false;
            match verify_host_key_dns(&host, key_type, blob) {
                Some(v)
                    if v.found && v.matched && v.secure && dns_mode == VerifyHostKeyDns::Yes =>
                {
                    return Some(true);
                }
                Some(v) if v.found && v.matched => matched = true,
                Some(v) if v.found => {
                    common::warn_changed_key(blob);
                    eprintln!(
                        "Update the SSHFP RR in DNS with the new host key to get rid of this \
                         message."
                    );
                }
                _ => {}
            }
            common::set_dns_match(Some(matched));
        }
        None
    }));
}

/// OpenSSH's `verify_host_key_dns`: what `host`'s SSHFP records say about
/// the key, `None` when they could not be looked up or compared.
fn verify_host_key_dns(host: &str, key_type: &str, blob: &[u8]) -> Option<dns::SshfpVerdict> {
    if host.parse::<std::net::IpAddr>().is_ok() {
        vlog(1, "skipped DNS lookup for numerical hostname");
        return None;
    }
    let set = match dns::lookup(host, dns::TYPE_SSHFP) {
        Ok(set) => set,
        Err(e) => {
            vlog(1, &format!("DNS lookup error: {}", e.text()));
            return None;
        }
    };
    vlog(
        1,
        &format!(
            "found {} {} fingerprints in DNS",
            set.rdatas.len(),
            if set.validated { "secure" } else { "insecure" }
        ),
    );
    let Some(v) = dns::check_sshfp(&set, key_type, blob) else {
        eprintln!("Error calculating key fingerprint.");
        return None;
    };
    vlog(
        1,
        match (v.found, v.matched) {
            (true, true) => "matching host key fingerprint found in DNS",
            (true, false) => "mismatching host key fingerprint found in DNS",
            _ => "no host key fingerprint found in DNS",
        },
    );
    Some(v)
}

/// The host key was accepted without known_hosts
/// (`NoHostAuthenticationForLocalhost`): UpdateHostKeys stays off.
static HOST_KEY_FORCED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Walk the ProxyJump chain, returning the `SharedClient` for the *last*
/// jump host. The caller opens a `direct-tcpip` channel from it to the final
/// target and runs the real session over that. Each hop re-runs
/// `ssh_cfg.lookup(hop.host)` for its own identities / known_hosts / user;
/// host-key checking runs per hop (a rejection at any hop aborts).
///
/// Also says whether the last hop is owed `no-more-sessions@openssh.com`
/// once the caller's channel is open: OpenSSH runs each hop as an `ssh -W`
/// of its own, which sends it then (see [`server_honours_no_more_sessions`]).
fn connect_jump_chain(
    hops: &[JumpHop],
    ssh_cfg: &puressh::config::SshClientConfig,
    cli: &Cli,
) -> Result<(puressh::shared::SharedClient, bool), String> {
    let mut current: Option<(puressh::shared::SharedClient, bool)> = None;
    for (idx, hop) in hops.iter().enumerate() {
        let block = ssh_cfg.lookup(&hop.host);
        let connect_host = block.host_name.clone().unwrap_or_else(|| hop.host.clone());
        let port = hop.port.or(block.port).unwrap_or(22);
        // Hop user: `user@` in the hop spec wins over the hop's config User,
        // then the local user. CLI `-l` targets the final host, not hops.
        let user = resolve_user(hop.user.as_deref(), block.user.as_deref())?;
        let cfg = config_for_host(&block, cli, &connect_host)?;

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
                .map_err(|e| hop_connect_error(idx, "connect", e))?,
            // Subsequent hop: tunnel a direct-tcpip channel through the
            // previous hop and run the client over it.
            Some((prev, prev_no_more_sessions)) => {
                let ch = prev
                    .open_direct_tcpip(connect_host.as_str(), port, "127.0.0.1", 0)
                    .map_err(|e| format!("proxyjump hop {}: open channel: {e}", idx + 1))?;
                if *prev_no_more_sessions {
                    send_no_more_sessions(prev);
                }
                Client::connect_via(Box::new(ch), connect_host.as_str(), port, cfg)
                    .map_err(|e| hop_connect_error(idx, "handshake", e))?
            }
        };

        // ProxyJump hops authenticate with config/agent/default identities
        // only — the CLI `-i` list belongs to the final target.
        let credentials = collect_credentials(&block, &[], block.identities_only.unwrap_or(false));
        authenticate_client(&mut hop_client, &connect_host, &user, credentials, &block).map_err(
            |e| {
                if e.is_empty() {
                    e
                } else {
                    format!("proxyjump hop {}: {e}", idx + 1)
                }
            },
        )?;
        vlog(1, &format!("proxyjump hop {}: authenticated", idx + 1));

        let no_more_sessions = matches!(
            block.control_master,
            None | Some(puressh::config::ControlMaster::No)
        ) && server_honours_no_more_sessions(hop_client.server_ident());
        current = Some((hop_client.into(), no_more_sessions));
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
            vlog(1, "AddKeysToAgent: no authentication agent, not adding key");
            return;
        }
        Err(e) => {
            vlog(1, &format!("AddKeysToAgent: agent: {e}"));
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
        if let Ok(pk) = common::load_identity(&path) {
            match agent.add_identity(&pk) {
                Ok(()) => vlog(1, &format!("AddKeysToAgent: added {path}")),
                Err(e) => warn!("warning: AddKeysToAgent: add {path}: {e}"),
            }
        }
    }
}

#[cfg(not(unix))]
fn maybe_add_keys_to_agent(_cfg_block: &puressh::config::ClientOptions, _cli: &Cli) {}

/// A ProxyJump hop's connection failure; a refused host key as OpenSSH
/// reports it.
fn hop_connect_error(idx: usize, stage: &str, e: puressh::Error) -> String {
    if matches!(e, puressh::Error::HostKeyRejected) {
        eprintln!("Host key verification failed.");
        return String::new();
    }
    format!("proxyjump hop {}: {stage}: {e}", idx + 1)
}

/// The `UserKnownHostsFile` list (`-o` / config, else OpenSSH's default
/// `~/.ssh/known_hosts ~/.ssh/known_hosts2`); empty for `none`.
fn user_known_hosts_files(cli: &Cli, cfg_block: &puressh::config::ClientOptions) -> Vec<PathBuf> {
    let spec = cli
        .known_hosts_path
        .as_ref()
        .map(|p| p.to_string_lossy().into_owned())
        .or_else(|| cfg_block.user_known_hosts.clone());
    match spec {
        Some(s) if s.trim().eq_ignore_ascii_case("none") => Vec::new(),
        Some(s) => s.split_whitespace().map(PathBuf::from).collect(),
        None => match common::default_known_hosts_path() {
            Some(p) => {
                let second = p.with_file_name("known_hosts2");
                vec![p, second]
            }
            None => Vec::new(),
        },
    }
}

/// `CanonicalizePermittedCNAMEs`: the name `name` is an alias to, when a
/// rule lets canonicalisation follow it there (OpenSSH's
/// `check_follow_cname`).
fn follow_cname(cfg_block: &puressh::config::ClientOptions, name: &str) -> Option<String> {
    let rules = cfg_block
        .canonicalize_permitted_cnames
        .as_deref()
        .filter(|r| !r.is_empty())?;
    let cname = dns::canonical_name(name)?.to_ascii_lowercase();
    if cname == name {
        return None;
    }
    let matches = |list: &str, n: &str| {
        let patterns: Vec<puressh::config::HostPattern> = list
            .split(',')
            .map(puressh::config::HostPattern::parse)
            .collect();
        puressh::config::host_matches(&patterns, n)
    };
    for (from, to) in rules {
        if matches(from, name) && matches(to, &cname) {
            vlog(
                1,
                &format!("Canonicalized DNS aliased hostname \"{name}\" => \"{cname}\""),
            );
            return Some(cname);
        }
    }
    None
}

/// `CanonicalizeHostname`, then the final pass over the configuration, as
/// OpenSSH: with canonicalisation on, or a `Match final`, the
/// configuration is read again for the final host name (`Host` patterns
/// match it, `Match canonical` / `final` fire), filling what the first pass
/// left unset.
fn final_config_pass(
    ssh_cfg: &puressh::config::SshClientConfig,
    cfg_block: &mut puressh::config::ClientOptions,
    cli: &Cli,
    local_user: &str,
) -> Result<(), String> {
    use puressh::config::CanonicalizeHostname as Canon;
    let expanded = cfg_block
        .host_name
        .as_deref()
        .map(|h| {
            h.replace("%%", "\0")
                .replace("%h", &cli.host)
                .replace('\0', "%")
        })
        .unwrap_or_else(|| cli.host.clone());
    let is_addr = expanded.parse::<std::net::IpAddr>().is_ok();
    let mut host = if is_addr {
        expanded
    } else {
        expanded.to_ascii_lowercase()
    };
    let direct = cfg_block
        .proxy_command
        .as_deref()
        .is_none_or(|p| p.eq_ignore_ascii_case("none"))
        && cfg_block
            .proxy_jump
            .as_deref()
            .is_none_or(|p| p.eq_ignore_ascii_case("none"))
        && cli.proxy_jump.is_none();
    let mode = cfg_block.canonicalize_hostname.unwrap_or(Canon::No);
    let mut canonical = false;
    if mode != Canon::No && (direct || mode == Canon::Always) && !is_addr {
        let resolves = |name: &str| {
            let port = cli.port.or(cfg_block.port).unwrap_or(22);
            // A trailing dot keeps the resolver's search list out of it.
            let q = if cfg!(unix) {
                format!("{name}.")
            } else {
                name.to_string()
            };
            std::net::ToSocketAddrs::to_socket_addrs(&(q.as_str(), port))
                .is_ok_and(|mut a| a.next().is_some())
        };
        if let Some(anchored) = host.strip_suffix('.') {
            // An anchored name is already fully qualified.
            host = anchored.to_string();
            canonical = true;
            if let Some(alias) = follow_cname(cfg_block, &host) {
                host = alias;
            }
        } else if host.matches('.').count() as u32 <= cfg_block.canonicalize_max_dots.unwrap_or(1) {
            let domains = cfg_block.canonical_domains.clone().unwrap_or_default();
            if let Some(full) = domains
                .iter()
                .map(|d| format!("{host}.{d}"))
                .find(|full| resolves(full))
            {
                match follow_cname(cfg_block, &full) {
                    Some(alias) => host = alias,
                    None => {
                        vlog(
                            1,
                            &format!("Canonicalized hostname \"{host}\" => \"{full}\""),
                        );
                        host = full;
                    }
                }
                canonical = true;
            } else if cfg_block.canonicalize_fallback_local == Some(false) {
                return Err(format!("Could not resolve host \"{host}\""));
            }
        }
    }
    // As OpenSSH: any CanonicalizeHostname other than `no` (whether or not
    // the name changed), or a `Match final`, means a final pass, in which
    // `Match canonical` and `Match final` both match.
    if mode == Canon::No && !ssh_cfg.wants_final_pass() {
        return Ok(());
    }
    if canonical {
        // The canonical name is the connection target from now on.
        cfg_block.host_name = Some(host.clone());
    }
    let user = cli
        .cli_user
        .clone()
        .or_else(|| cli.user_in_host.clone())
        .or_else(|| cfg_block.user.clone())
        .unwrap_or_else(|| local_user.to_string());
    let mut ctx = puressh::config::MatchContext::default();
    ctx.host = &host;
    ctx.original_host = Some(&cli.host);
    ctx.user = Some(&user);
    ctx.local_user = Some(local_user);
    ctx.canonical = true;
    ctx.final_pass = true;
    ctx.tag = cli.tag.as_deref();
    let earlier = cfg_block.clone();
    let fin = ssh_cfg.lookup_with_exec(ctx, &mut |cmd, so_far| {
        let mut opts = earlier.clone();
        opts.merge_lower(so_far);
        match_exec(cmd, &opts, cli, true)
    });
    cfg_block.merge_lower(&fin);
    // Blocks matched on both passes added their lists twice; OpenSSH skips
    // duplicate identities and forwards.
    fn dedup<T: PartialEq + Clone>(v: &mut Vec<T>) {
        let mut out: Vec<T> = Vec::with_capacity(v.len());
        for x in v.drain(..) {
            if !out.contains(&x) {
                out.push(x);
            }
        }
        *v = out;
    }
    dedup(&mut cfg_block.identity_files);
    dedup(&mut cfg_block.certificate_files);
    dedup(&mut cfg_block.local_forwards);
    dedup(&mut cfg_block.remote_forwards);
    dedup(&mut cfg_block.dynamic_forwards);
    Ok(())
}

/// Whether to request a PTY, with OpenSSH's rules (CLI `-t`/`-T`/`-o
/// RequestTTY` over the config keyword): always for `-tt` (`force`); when
/// stdin is a terminal for `-t` (`yes`); by default (`auto`) only for an
/// interactive shell on a terminal; never for `-T` (`no`) or a subsystem
/// unless forced.
fn want_pty(
    cli: &Cli,
    cfg_block: &puressh::config::ClientOptions,
    has_command: bool,
    subsystem: bool,
) -> bool {
    use puressh::config::RequestTty::*;
    let tty = stdin_is_tty();
    match cli.request_tty.or(cfg_block.request_tty) {
        Some(Force) => true,
        Some(No) => false,
        Some(Yes) if !subsystem => {
            if !tty {
                warn!("Pseudo-terminal will not be allocated because stdin is not a terminal.");
            }
            tty
        }
        _ => !has_command && !subsystem && tty,
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
        // A keyword value this binary predates: leave the inherited socket.
        Some(_) => {}
    }
}

/// `ssh -G`: the resolved configuration as `keyword value` lines (lower-case
/// keywords, OpenSSH's format and order), with OpenSSH's defaults for unset
/// values. Scripts typically read `hostname`, `user`, `port`,
/// `identityfile`, `proxyjump` / `proxycommand` and `controlpath` from it.
fn print_config(
    cli: &Cli,
    c: &puressh::config::ClientOptions,
    hostname: &str,
    user: &str,
    port: u16,
) {
    use puressh::config::{AddressFamily, ControlMaster, RequestTty, StrictMode, VerifyHostKeyDns};
    let yn = |b: Option<bool>, default: bool| if b.unwrap_or(default) { "yes" } else { "no" };
    let tf = |b: Option<bool>, default: bool| {
        if b.unwrap_or(default) {
            "true"
        } else {
            "false"
        }
    };
    let list = |l: &Option<Vec<String>>, cat| match l {
        Some(v) => v.join(","),
        None => puressh::config::default_algorithms(cat).join(","),
    };
    let oneline = |l: Option<&Vec<String>>| match l {
        Some(v) if !v.is_empty() => v.join(" "),
        _ => "none".to_string(),
    };
    // Keywords this build accepts without acting on them: as configured,
    // else OpenSSH's default.
    let unimplemented = |key: &str, default: &'static str| -> String {
        c.unimplemented
            .iter()
            .find(|(k, _)| k == key)
            .map_or(default.to_string(), |(_, v)| v.clone())
    };
    let mut out = vec![
        format!("host {}", cli.host),
        format!("user {user}"),
        format!("hostname {hostname}"),
        format!("port {port}"),
        format!(
            "addressfamily {}",
            match c.address_family {
                Some(AddressFamily::Inet) => "inet",
                Some(AddressFamily::Inet6) => "inet6",
                _ => "any",
            }
        ),
        format!("batchmode {}", yn(c.batch_mode, false)),
        format!(
            "canonicalizefallbacklocal {}",
            yn(c.canonicalize_fallback_local, true)
        ),
        format!(
            "canonicalizehostname {}",
            match c.canonicalize_hostname {
                Some(puressh::config::CanonicalizeHostname::Yes) => "true",
                Some(puressh::config::CanonicalizeHostname::Always) => "always",
                _ => "false",
            }
        ),
        format!("checkhostip {}", yn(c.check_host_ip, false)),
        format!(
            "compression {}",
            yn(cli.compression.or(c.compression), false)
        ),
        format!(
            "controlmaster {}",
            match c.control_master {
                Some(ControlMaster::Yes) => "true",
                Some(ControlMaster::Auto) => "auto",
                _ => "false",
            }
        ),
        format!(
            "enablesshkeysign {}",
            unimplemented("enablesshkeysign", "no")
        ),
        format!("clearallforwardings {}", yn(c.clear_all_forwardings, false)),
        format!(
            "exitonforwardfailure {}",
            yn(c.exit_on_forward_failure, false)
        ),
        format!(
            "fingerprinthash {}",
            c.fingerprint_hash.as_deref().unwrap_or("SHA256")
        ),
        format!("forwardx11 {}", yn(c.forward_x11, false)),
        format!("forwardx11trusted {}", yn(c.forward_x11_trusted, false)),
        format!(
            "gatewayports {}",
            match c.gateway_ports {
                Some(puressh::config::GatewayPorts::Yes) => "yes",
                _ => "no",
            }
        ),
        format!(
            "hashknownhosts {}",
            yn(cli.hash_known_hosts.or(c.hash_known_hosts), false)
        ),
        format!(
            "hostbasedauthentication {}",
            unimplemented("hostbasedauthentication", "no")
        ),
        format!(
            "identitiesonly {}",
            yn(cli.identities_only.or(c.identities_only), false)
        ),
        format!(
            "kbdinteractiveauthentication {}",
            yn(c.kbd_interactive_authentication, true)
        ),
        format!(
            "nohostauthenticationforlocalhost {}",
            yn(c.no_host_authentication_for_localhost, false)
        ),
        format!(
            "passwordauthentication {}",
            yn(c.password_authentication, true)
        ),
        format!("permitlocalcommand {}", yn(c.permit_local_command, false)),
        format!("proxyusefdpass {}", yn(c.proxy_use_fdpass, false)),
        format!("pubkeyauthentication {}", tf(c.pubkey_authentication, true)),
        format!(
            "requesttty {}",
            match cli.request_tty.or(c.request_tty) {
                Some(RequestTty::No) => "false",
                Some(RequestTty::Yes) => "true",
                Some(RequestTty::Force) => "force",
                _ => "auto",
            }
        ),
        format!(
            "sessiontype {}",
            match c.session_type {
                Some(puressh::config::SessionType::None) => "none",
                Some(puressh::config::SessionType::Subsystem) => "subsystem",
                _ => "default",
            }
        ),
        format!("stdinnull {}", yn(c.stdin_null, false)),
        format!(
            "forkafterauthentication {}",
            yn(c.fork_after_authentication, false)
        ),
        format!(
            "streamlocalbindunlink {}",
            yn(c.stream_local_bind_unlink, false)
        ),
        format!(
            "stricthostkeychecking {}",
            match cli.strict.or(c.strict_host_key) {
                Some(StrictMode::Yes) => "true",
                Some(StrictMode::No) => "false",
                Some(StrictMode::AcceptNew) => "accept-new",
                _ => "ask",
            }
        ),
        format!("tcpkeepalive {}", tf(c.tcp_keep_alive, true)),
        format!(
            "tunnel {}",
            tunnel_dump("tunnel", c.tunnel.as_deref().unwrap_or("no"))
        ),
        format!(
            "verifyhostkeydns {}",
            match c.verify_host_key_dns {
                Some(VerifyHostKeyDns::Yes) => "true",
                Some(VerifyHostKeyDns::Ask) => "ask",
                _ => "false",
            }
        ),
        format!("visualhostkey {}", yn(c.visual_host_key, false)),
        format!(
            "updatehostkeys {}",
            match c.update_host_keys.as_deref() {
                Some("no") => "false",
                Some("ask") => "ask",
                Some(_) => "true",
                None if update_host_keys_by_default(cli, c) => "true",
                None => "false",
            }
        ),
        format!(
            "enableescapecommandline {}",
            yn(c.enable_escape_commandline, false)
        ),
        format!("warnweakcrypto {}", yn(c.warn_weak_crypto, true)),
        format!(
            "canonicalizemaxdots {}",
            c.canonicalize_max_dots.unwrap_or(1)
        ),
        format!("connectionattempts {}", c.connection_attempts.unwrap_or(1)),
        format!(
            "forwardx11timeout {}",
            c.forward_x11_timeout.unwrap_or(1200)
        ),
        format!(
            "numberofpasswordprompts {}",
            c.number_of_password_prompts.unwrap_or(3)
        ),
        format!(
            "serveralivecountmax {}",
            c.server_alive_count_max.unwrap_or(3)
        ),
        format!(
            "serveraliveinterval {}",
            c.server_alive_interval.unwrap_or(0)
        ),
        format!("requiredrsasize {}", c.required_rsa_size.unwrap_or(1024)),
        format!(
            "obscurekeystroketiming {}",
            match c.obscure_keystroke_timing {
                Some(puressh::config::ObscureKeystrokeTiming::Off) => "no".to_string(),
                Some(puressh::config::ObscureKeystrokeTiming::On { interval_ms })
                    if interval_ms != 20 =>
                {
                    interval_ms.to_string()
                }
                _ => "yes".to_string(),
            }
        ),
    ];
    // String options, when set.
    let not_none = |p: &&String| !p.eq_ignore_ascii_case("none");
    if let Some(b) = &c.bind_address {
        out.push(format!("bindaddress {b}"));
    }
    if let Some(b) = &c.bind_interface {
        out.push(format!("bindinterface {b}"));
    }
    out.push(format!(
        "ciphers {}",
        list(&c.ciphers, puressh::config::AlgoCategory::Cipher)
    ));
    if let Some(p) = &c.control_path {
        out.push(format!("controlpath {p}"));
    }
    out.push(format!(
        "hostkeyalgorithms {}",
        list(
            &c.host_key_algorithms,
            puressh::config::AlgoCategory::HostKey
        )
    ));
    if let Some(a) = &c.host_key_alias {
        out.push(format!("hostkeyalias {a}"));
    }
    match &c.identity_agent {
        Some(puressh::config::IdentityAgent::Path(p)) => out.push(format!("identityagent {p}")),
        Some(puressh::config::IdentityAgent::None) => out.push("identityagent none".to_string()),
        _ => {}
    }
    if let Some(d) = &c.kbd_interactive_devices {
        out.push(format!("kbdinteractivedevices {d}"));
    }
    out.push(format!(
        "kexalgorithms {}",
        list(&c.kex_algorithms, puressh::config::AlgoCategory::Kex)
    ));
    out.push(format!(
        "casignaturealgorithms {}",
        list(
            &c.ca_signature_algorithms,
            puressh::config::AlgoCategory::CaSignature
        )
    ));
    if let Some(l) = c.local_command.as_ref().filter(not_none) {
        out.push(format!("localcommand {l}"));
    }
    if let Some(r) = c.remote_command.as_ref().filter(not_none) {
        out.push(format!("remotecommand {r}"));
    }
    out.push(format!(
        "loglevel {}",
        match (cli.quiet, cli.verbose) {
            (true, _) => "QUIET",
            (_, 1) => "DEBUG1",
            (_, 2) => "DEBUG2",
            (_, v) if v >= 3 => "DEBUG3",
            _ => puressh::config::server::LOG_LEVELS[usize::from(c.log_level.unwrap_or(3).min(7))],
        }
    ));
    out.push(format!(
        "macs {}",
        list(&c.macs, puressh::config::AlgoCategory::Mac)
    ));
    if let Some(p) = &c.pkcs11_provider {
        out.push(format!("pkcs11provider {p}"));
    }
    out.push(format!(
        "securitykeyprovider {}",
        c.security_key_provider
            .as_deref()
            .unwrap_or("$SSH_SK_PROVIDER")
    ));
    if let Some(p) = &c.preferred_authentications {
        out.push(format!("preferredauthentications {}", p.join(",")));
    }
    out.push(format!(
        "pubkeyacceptedalgorithms {}",
        list(
            &c.pubkey_accepted_algorithms,
            puressh::config::AlgoCategory::PubkeyAccepted
        )
    ));
    out.push(format!(
        "xauthlocation {}",
        c.xauth_location.as_deref().unwrap_or(DEFAULT_XAUTH)
    ));
    if let Some(k) = c.known_hosts_command.as_ref().filter(not_none) {
        out.push(format!("knownhostscommand {k}"));
    }
    if let Some(t) = &c.tag {
        out.push(format!("tag {t}"));
    }
    if let Some(v) = &c.version_addendum {
        out.push(format!("versionaddendum {v}"));
    }
    // As OpenSSH's dump_cfg_forwards: a listen port without an address is
    // bare, any address is bracketed.
    let listen = |a: &Option<String>, p: u16| match a {
        Some(a) => format!("[{a}]:{p}"),
        None => p.to_string(),
    };
    for f in cli.dynamics_raw.iter().chain(c.dynamic_forwards.iter()) {
        out.push(format!(
            "dynamicforward {}",
            listen(&f.bind_addr, f.listen_port)
        ));
    }
    // The command line's and the configuration's, as OpenSSH keeps them.
    for f in &cli.locals {
        let from = f
            .listen_path
            .clone()
            .unwrap_or_else(|| listen(&f.bind_addr, f.listen_port));
        let to = f
            .connect_path
            .clone()
            .unwrap_or_else(|| format!("[{}]:{}", f.remote_host, f.remote_port));
        out.push(format!("localforward {from} {to}"));
    }
    for f in &cli.remotes {
        let from = f
            .listen_path
            .clone()
            .unwrap_or_else(|| listen(&f.bind_addr, f.remote_port));
        match &f.connect_path {
            Some(to) => out.push(format!("remoteforward {from} {to}")),
            None if f.dynamic => out.push(format!("remoteforward {from}")),
            None => out.push(format!(
                "remoteforward {from} [{}]:{}",
                f.local_host, f.local_port
            )),
        }
    }
    // As written (OpenSSH expands them only when loading).
    if !cli.identities.is_empty() || !c.identity_files.is_empty() {
        out.extend(
            cli.identities
                .iter()
                .chain(c.identity_files.iter())
                .map(|p| format!("identityfile {p}")),
        );
    } else {
        out.extend(
            DEFAULT_IDENTITY_NAMES
                .iter()
                .map(|n| format!("identityfile ~/.ssh/{n}")),
        );
    }
    out.push(format!(
        "canonicaldomains {}",
        oneline(c.canonical_domains.as_ref())
    ));
    out.extend(
        c.certificate_files
            .iter()
            .map(|p| format!("certificatefile {p}")),
    );
    out.push(format!(
        "globalknownhostsfile {}",
        c.global_known_hosts_files
            .as_ref()
            .map(|f| f.join(" "))
            .unwrap_or_else(|| "/etc/ssh/ssh_known_hosts /etc/ssh/ssh_known_hosts2".into())
    ));
    let known_hosts = cli
        .known_hosts_path
        .as_ref()
        .map(|p| p.display().to_string())
        .or_else(|| c.user_known_hosts.clone())
        .unwrap_or_else(|| {
            format!(
                "{} {}",
                expand_tilde("~/.ssh/known_hosts"),
                expand_tilde("~/.ssh/known_hosts2")
            )
        });
    out.push(format!("userknownhostsfile {known_hosts}"));
    out.push(format!(
        "revokedhostkeys {}",
        c.revoked_host_keys.as_deref().unwrap_or("none")
    ));
    out.extend(c.send_env.iter().map(|e| format!("sendenv {e}")));
    out.extend(c.set_env.iter().map(|(k, v)| format!("setenv {k}={v}")));
    out.push(format!("logverbose {}", oneline(c.log_verbose.as_ref())));
    out.push(format!(
        "channeltimeout {}",
        oneline(c.channel_timeouts.as_ref())
    ));
    out.push(format!(
        "permitremoteopen {}",
        c.permit_remote_open
            .as_ref()
            .map_or("any".to_string(), |v| v.join(" "))
    ));
    out.push(format!("addkeystoagent {}", tf(c.add_keys_to_agent, false)));
    out.push(format!(
        "forwardagent {}",
        match &c.forward_agent_socket {
            Some(sock) if c.forward_agent == Some(true) => sock.clone(),
            _ => yn(c.forward_agent.or(Some(cli.agent_forward)), false).to_string(),
        }
    ));
    out.push(format!(
        "connecttimeout {}",
        c.connect_timeout
            .filter(|t| *t > 0)
            .map_or("none".into(), |t| t.to_string())
    ));
    out.push(format!(
        "tunneldevice {}",
        tunnel_dump(
            "tunneldevice",
            c.tunnel_device.as_deref().unwrap_or("any:any")
        )
    ));
    out.push(format!(
        "canonicalizepermittedcnames {}",
        match c.canonicalize_permitted_cnames.as_deref() {
            Some(rules) if !rules.is_empty() => rules
                .iter()
                .map(|(from, to)| format!("{from}:{to}"))
                .collect::<Vec<_>>()
                .join(" "),
            _ => "none".to_string(),
        }
    ));
    out.push(format!(
        "controlpersist {}",
        match c.control_persist {
            Some(puressh::config::ControlPersist::Yes) => "yes".to_string(),
            Some(puressh::config::ControlPersist::Seconds(n)) => n.to_string(),
            _ => "no".to_string(),
        }
    ));
    out.push(format!(
        "escapechar {}",
        match cli.escape_char.unwrap_or(Some(b'~')) {
            None => "none".to_string(),
            Some(b) if b < 0x20 => format!("^{}", (b + b'@') as char),
            Some(b) => (b as char).to_string(),
        }
    ));
    let (interactive, bulk) = c.ip_qos.unwrap_or(DEFAULT_IPQOS);
    out.push(format!(
        "ipqos {} {}",
        puressh::config::ipqos_name(interactive),
        puressh::config::ipqos_name(bulk)
    ));
    // In bytes and seconds, 0 for the defaults, as OpenSSH prints it.
    out.push(format!(
        "rekeylimit {} {}",
        c.rekey_limit.and_then(|r| r.max_bytes).unwrap_or(0),
        c.rekey_limit.and_then(|r| r.max_seconds).unwrap_or(0)
    ));
    out.push(format!(
        "streamlocalbindmask 0{:o}",
        c.stream_local_bind_mask.unwrap_or(0o177)
    ));
    out.push(format!(
        "syslogfacility {}",
        c.syslog_facility.as_deref().unwrap_or("USER")
    ));
    if let Some(p) = cli
        .proxy_jump
        .as_ref()
        .or(c.proxy_jump.as_ref())
        .filter(not_none)
    {
        // As OpenSSH keeps them: `[user@]host[:port]` (ssh:// URIs too),
        // a numeric last host in brackets.
        let hops: Vec<String> = match parse_jump_hops(p) {
            Ok(hops) => {
                let n = hops.len();
                hops.iter()
                    .enumerate()
                    .map(|(i, h)| {
                        let mut s = String::new();
                        if let Some(u) = &h.user {
                            s.push_str(u);
                            s.push('@');
                        }
                        let numeric = h.host.contains(':')
                            || h.host.bytes().all(|b| b.is_ascii_digit() || b == b'.');
                        if i + 1 == n && numeric {
                            s.push_str(&format!("[{}]", h.host));
                        } else {
                            s.push_str(&h.host);
                        }
                        if let Some(port) = h.port {
                            s.push_str(&format!(":{port}"));
                        }
                        s
                    })
                    .collect()
            }
            Err(_) => vec![p.clone()],
        };
        out.push(format!("proxyjump {}", hops.join(",")));
    } else if let Some(p) = c.proxy_command.as_ref().filter(not_none) {
        out.push(format!("proxycommand {p}"));
    }
    for line in out {
        println!("{line}");
    }
}

/// `XAuthLocation`'s default, as OpenSSH's build on Linux has it.
const DEFAULT_XAUTH: &str = "/usr/bin/xauth";

/// `IPQoS`'s default: `ef` for interactive sessions, `cs0` for the rest
/// (OpenSSH 10).
const DEFAULT_IPQOS: (u32, u32) = (0xb8, 0x00);

/// The default `IdentityFile`s, in OpenSSH's order (`~/.ssh/` names; the
/// FIDO `_sk` ones are tried only by a build with security keys).
const DEFAULT_IDENTITY_NAMES: [&str; 6] = [
    "id_rsa",
    "id_ecdsa",
    "id_ecdsa_sk",
    "id_ed25519",
    "id_ed25519_sk",
    "id_mldsa44_ed25519",
];

/// `ssh -Z`: the public keys authentication would try, in OpenSSH's order
/// and its `format_identity` words: user certificates, the agent's keys
/// (those an identity file names first, as that file), then the other
/// identity files (a missing default one with no key).
fn dump_pubkeys(cli: &Cli, cfg_block: &puressh::config::ClientOptions, identities_only: bool) {
    let hash = cfg_block.fingerprint_hash.as_deref().unwrap_or("SHA256");
    let describe = |blob: &[u8]| {
        format!(
            "{} {}",
            puressh::client::host_key_type_label(blob),
            fingerprint::fingerprint(blob, hash)
        )
    };
    // The public half of an identity file: its `.pub`, else the file.
    let public_of = |path: &str| -> Option<Vec<u8>> {
        let text = std::fs::read_to_string(format!("{path}.pub"))
            .or_else(|_| std::fs::read_to_string(path))
            .ok()?;
        if let Ok(pk) = puressh::key::PublicKey::parse_authorized_keys_line(text.trim()) {
            return Some(pk.wire_blob());
        }
        puressh::key::PrivateKey::parse_pem(&text, None)
            .ok()
            .map(|k| k.public_key().wire_blob())
    };
    let explicit = !cli.identities.is_empty() || !cfg_block.identity_files.is_empty();
    let mut files: Vec<(String, Option<Vec<u8>>, bool)> = Vec::new();
    if explicit {
        for p in cli
            .identities
            .iter()
            .cloned()
            .chain(cfg_block.identity_files.iter().map(|p| expand_tilde(p)))
        {
            if let Err(e) = std::fs::metadata(&p) {
                eprintln!(
                    "Warning: Identity file {p} not accessible: {}.",
                    common::io_reason(&e)
                );
                continue;
            }
            let key = public_of(&p);
            files.push((p, key, true));
        }
    } else {
        for n in DEFAULT_IDENTITY_NAMES {
            let p = expand_tilde(&format!("~/.ssh/{n}"));
            let key = public_of(&p);
            files.push((p, key, false));
        }
    }
    let mut out: Vec<String> = Vec::new();
    for c in &cfg_block.certificate_files {
        let p = expand_tilde(c);
        if let Ok(cert) = std::fs::read_to_string(&p)
            .map_err(|_| ())
            .and_then(|t| puressh::cert::Certificate::parse_openssh_line(&t).map_err(|_| ()))
        {
            out.push(format!("{p} {} explicit", describe(&cert.raw)));
        }
    }
    #[cfg(unix)]
    if let Ok(Some(mut agent)) = puressh::agent::Agent::connect_env()
        && let Ok(ids) = agent.identities()
    {
        let mut others = Vec::new();
        for id in ids {
            match files
                .iter()
                .position(|(_, k, _)| k.as_deref() == Some(&id.key_blob[..]))
            {
                Some(i) => {
                    let (p, _, user) = files.remove(i);
                    out.push(format!(
                        "{p} {}{} agent",
                        describe(&id.key_blob),
                        if user { " explicit" } else { "" }
                    ));
                }
                None if !identities_only => {
                    others.push(format!("{} {} agent", id.comment, describe(&id.key_blob)))
                }
                None => {}
            }
        }
        out.extend(others);
    }
    for (p, key, user) in files {
        match key {
            Some(blob) => out.push(format!(
                "{p} {}{}",
                describe(&blob),
                if user { " explicit" } else { "" }
            )),
            None => out.push(format!("{p} {}", if user { "explicit" } else { "" })),
        }
    }
    for line in out {
        println!("{line}");
    }
}

/// `ssh -Q KIND`: list the algorithms this build supports, one per line.
/// The key types this build implements, each with its certificate type, in
/// OpenSSH's `-Q key` order (which also lists the FIDO `sk-` types we lack).
const KEY_TYPES: &[(&str, &str)] = &[
    ("ssh-ed25519", "ssh-ed25519-cert-v01@openssh.com"),
    (
        "ssh-mldsa44-ed25519@openssh.com",
        "ssh-mldsa44-ed25519-cert-v01@openssh.com",
    ),
    (
        "ecdsa-sha2-nistp256",
        "ecdsa-sha2-nistp256-cert-v01@openssh.com",
    ),
    (
        "ecdsa-sha2-nistp384",
        "ecdsa-sha2-nistp384-cert-v01@openssh.com",
    ),
    (
        "ecdsa-sha2-nistp521",
        "ecdsa-sha2-nistp521-cert-v01@openssh.com",
    ),
    ("ssh-rsa", "ssh-rsa-cert-v01@openssh.com"),
];

fn run_query(kind: &str) -> Result<i32, String> {
    use puressh::config::{AlgoCategory, supported_algorithms};
    // The configuration keywords name their lists too (any case), as in
    // OpenSSH.
    let kind = match kind.to_ascii_lowercase().as_str() {
        "ciphers" => "cipher",
        "macs" => "mac",
        "kexalgorithms" => "kex",
        "casignaturealgorithms" => "key-ca-sign",
        "pubkeyacceptedalgorithms"
        | "pubkeyacceptedkeytypes"
        | "hostkeyalgorithms"
        | "hostbasedacceptedalgorithms"
        | "hostbasedacceptedkeytypes"
        | "hostbasedkeytypes" => "key-sig",
        _ => kind,
    };
    let list: Vec<&str> = match kind {
        "cipher" => supported_algorithms(AlgoCategory::Cipher),
        // The ciphers that authenticate (AEAD), as OpenSSH lists them.
        "cipher-auth" => vec![
            "aes128-gcm@openssh.com",
            "aes256-gcm@openssh.com",
            "chacha20-poly1305@openssh.com",
        ],
        "mac" => supported_algorithms(AlgoCategory::Mac),
        "kex" => supported_algorithms(AlgoCategory::Kex),
        // As OpenSSH's: key types (`ssh-rsa` for RSA keys), then with their
        // certificate types; signature algorithms; the default lists.
        "key-plain" => KEY_TYPES.iter().map(|(plain, _)| *plain).collect(),
        "key" => KEY_TYPES
            .iter()
            .flat_map(|(plain, cert)| [*plain, *cert])
            .collect(),
        "key-cert" => KEY_TYPES.iter().map(|(_, cert)| *cert).collect(),
        "key-sig" => supported_algorithms(AlgoCategory::HostKey),
        "sig" | "key-ca-sign" => vec![
            "ssh-ed25519",
            "ssh-mldsa44-ed25519@openssh.com",
            "ecdsa-sha2-nistp256",
            "ecdsa-sha2-nistp384",
            "ecdsa-sha2-nistp521",
            "ssh-rsa",
            "rsa-sha2-256",
            "rsa-sha2-512",
        ],
        "compression" => vec!["none", "zlib@openssh.com"],
        "protocol-version" => vec!["2"],
        "help" => vec![
            "cipher",
            "cipher-auth",
            "compression",
            "kex",
            "key",
            "key-ca-sign",
            "key-cert",
            "key-plain",
            "key-sig",
            "mac",
            "protocol-version",
            "sig",
        ],
        other => return Err(format!("Unsupported query \"{other}\"")),
    };
    for name in list {
        println!("{name}");
    }
    Ok(0)
}

fn run() -> Result<i32, String> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    // Only a leading `-h`/`--help` asks for help: anywhere else it may be
    // part of the remote command (`ssh host df -h`).
    if matches!(args.first().map(String::as_str), Some("-h" | "--help")) {
        println!("{USAGE}");
        println!();
        println!("A pure-Rust SSH client built on puressh {VERSION}.");
        return Ok(0);
    }

    let mut cli = parse_args(&args).map_err(|e| format!("{e}\n{USAGE}"))?;
    set_verbose(cli.verbose);
    common::set_quiet(cli.quiet);
    LOG_QUIET.store(cli.quiet, std::sync::atomic::Ordering::Relaxed);

    // `-V`: like OpenSSH, the version goes to stderr.
    if cli.version {
        eprintln!("puressh_{VERSION} (pure-Rust SSH, OpenSSH-compatible)");
        return Ok(0);
    }
    if let Some(q) = cli.query.as_deref() {
        return run_query(q);
    }
    // `-E file`: ssh's own messages go to `file` from here on; the remote
    // command's stderr does not (common::remote_stderr).
    #[cfg(unix)]
    if let Some(path) = cli.log_file.as_deref() {
        common::log_to_file(path)?;
    }
    // `-n` (and `-f`): stdin from /dev/null.
    #[cfg(unix)]
    if cli.stdin_null {
        let null = std::fs::File::open("/dev/null").map_err(|e| format!("/dev/null: {e}"))?;
        common::unix_sys::dup2(&null, 0).map_err(|e| format!("-n: {e}"))?;
    }

    // Resolve the ssh_config block matching the user-typed host name. CLI
    // values then take precedence over the block; the block over built-in
    // defaults (OpenSSH's documented order).
    // `Include` paths take the %tokens known before the configuration is
    // read: the destination as given, the command line's user and port.
    let include_tokens = {
        let user = cli
            .cli_user
            .clone()
            .or_else(|| cli.user_in_host.clone())
            .or_else(common::local_user_name)
            .unwrap_or_default();
        Tokens::new(
            &cli.host,
            &cli.host,
            cli.port.unwrap_or(22),
            &user,
            &puressh::config::ClientOptions::default(),
            &cli,
        )
    };
    let ssh_cfg = common::load_client_config(cli.config_file.as_deref(), &|p: &str| {
        include_tokens.expand(p)
    })?;
    // `Match user` / `localuser` see the user named on the command line
    // (else the local one), as OpenSSH's first pass does.
    // As OpenSSH, values from the command line that end up in %tokens are
    // checked before the configuration is read.
    if let Some(u) = cli
        .cli_user
        .as_deref()
        .filter(|_| !cli.user_from_o)
        .or(cli.user_in_host.as_deref())
        && !valid_ruser(u)
    {
        return Err("remote username contains invalid characters".into());
    }
    if !valid_hostname(&cli.host) {
        return Err("hostname contains invalid characters".into());
    }
    // Jump hosts from the command line (-J, -o ProxyJump) are checked too
    // (those from a file are not).
    let jump_ok = |spec: &str| {
        spec.eq_ignore_ascii_case("none")
            || parse_jump_hops(spec).is_ok_and(|hops| {
                hops.iter()
                    .all(|h| valid_hostname(&h.host) && h.user.as_deref().is_none_or(valid_ruser))
            })
    };
    if let Some(j) = &cli.proxy_jump
        && !jump_ok(j)
    {
        return Err("Invalid -J argument".into());
    }
    for o in &cli.extra_o {
        let o = o.trim_start();
        if o.len() > 9 && o[..9].eq_ignore_ascii_case("proxyjump") {
            let v = o[9..].trim_start_matches(['=', ' ', '\t']).trim();
            if !jump_ok(v) {
                return Err("Invalid ProxyJump argument".into());
            }
        }
    }
    let local_user = common::local_user_name().unwrap_or_default();
    let named_user = cli
        .cli_user
        .clone()
        .or_else(|| cli.user_in_host.clone())
        .unwrap_or_else(|| local_user.clone());
    let mut ctx = puressh::config::MatchContext::default();
    ctx.host = &cli.host;
    ctx.original_host = Some(&cli.host);
    ctx.user = Some(&named_user);
    ctx.local_user = Some(&local_user);
    ctx.tag = cli.tag.as_deref();
    let mut cfg_block =
        ssh_cfg.lookup_with_exec(ctx, &mut |cmd, so_far| match_exec(cmd, so_far, &cli, false));
    // `-o KEY=VALUE` overlays the matched block at the highest precedence,
    // re-using the strict config parser for validation.
    apply_extra_o(&mut cfg_block, &cli.extra_o)?;
    final_config_pass(&ssh_cfg, &mut cfg_block, &cli, &local_user)?;
    // RefuseConnection in a block that applies: OpenSSH stops there, before
    // even `-G` prints anything.
    if let Some(why) = &cfg_block.refuse_connection {
        eprintln!("{why}");
        return Err(String::new());
    }
    // -W implies ExitOnForwardFailure and ClearAllForwardings, unless the
    // configuration or -o says otherwise (OpenSSH).
    if cli.stdio_forward.is_some() {
        cfg_block.exit_on_forward_failure.get_or_insert(true);
        cfg_block.clear_all_forwardings.get_or_insert(true);
    }

    // ssh_config equivalents of command-line flags; a flag always wins.
    match cfg_block.session_type {
        Some(puressh::config::SessionType::None) if cli.command.is_none() => cli.no_command = true,
        Some(puressh::config::SessionType::Subsystem) => cli.subsystem = true,
        _ => {}
    }
    // RemoteCommand is taken once its tokens are expanded (below).
    let command_from_config = cli.command.is_none()
        && !cli.no_command
        && cfg_block
            .remote_command
            .as_deref()
            .is_some_and(|c| !c.eq_ignore_ascii_case("none"));
    if cli.escape_char.is_none() {
        cli.escape_char = cfg_block.escape_char;
    }
    if cfg_block.fork_after_authentication == Some(true) {
        cli.fork_after_auth = true;
    }
    if (cfg_block.stdin_null == Some(true) || cli.fork_after_auth) && !cli.stdin_null {
        cli.stdin_null = true;
        #[cfg(unix)]
        {
            let null = std::fs::File::open("/dev/null").map_err(|e| format!("/dev/null: {e}"))?;
            common::unix_sys::dup2(&null, 0).map_err(|e| format!("StdinNull: {e}"))?;
        }
    }

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
        cli.locals.push(lf.clone());
    }
    for rf in &cfg_block.remote_forwards {
        cli.remotes.push(rf.clone());
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
    // `-X` is trusted when ForwardX11Trusted says so (Ubuntu's ssh_config
    // does); `-Y` always is.
    if cli.x11_forward == Some(X11Forward::Untrusted) && cfg_block.forward_x11_trusted == Some(true)
    {
        cli.x11_forward = Some(X11Forward::Trusted);
    }
    if cli.x11_forward.is_none() && cfg_block.forward_x11 == Some(true) {
        cli.x11_forward = Some(if cfg_block.forward_x11_trusted == Some(true) {
            X11Forward::Trusted
        } else {
            X11Forward::Untrusted
        });
    }
    // LogLevel (OpenSSH's numbering): QUIET..ERROR hide the informational
    // messages (`Warning: Permanently added …`), as -q does; VERBOSE and
    // DEBUGn are -v levels.
    // `-y`: ssh's messages go to syslog, with the SyslogFacility.
    #[cfg(unix)]
    if cli.use_syslog {
        let facility = cfg_block
            .syslog_facility
            .as_deref()
            .and_then(common::syslog_facility)
            .unwrap_or(libc::LOG_USER);
        common::log_to_syslog(c"ssh", facility)?;
    }
    if let Some(v) = cfg_block.log_verbose.clone().filter(|v| !v.is_empty()) {
        common::set_log_verbose(v);
    }
    if cli.verbose == 0
        && !cli.quiet
        && let Some(level) = cfg_block.log_level
    {
        match level {
            0..=2 => {
                common::set_quiet(true);
                LOG_QUIET.store(level == 0, std::sync::atomic::Ordering::Relaxed);
            }
            3 => {}
            4 | 5 => set_verbose(1),
            6 => set_verbose(2),
            _ => set_verbose(3),
        }
    }

    // CLI `-l user` > `user@host` > config `User` > the local user, as
    // OpenSSH (the command line is read before the configuration).
    let cli_user = cli
        .cli_user
        .clone()
        .or_else(|| cli.user_in_host.clone())
        .or_else(|| cfg_block.user.clone());
    let mut user = resolve_user(cli_user.as_deref(), None)?;

    let identities_only = common::pick(cli.identities_only, cfg_block.identities_only, false);
    let port = common::pick(cli.port, cfg_block.port, 22);
    // `HostName` rewrites the connect target; the original `cli.host` is
    // what we *displayed* and what the config block matched on.
    // `HostName` takes `%h` (the name given) and `%%`.
    let connect_host = cfg_block
        .host_name
        .as_deref()
        .map(|h| {
            h.replace("%%", "\0")
                .replace("%h", &cli.host)
                .replace('\0', "%")
        })
        .unwrap_or_else(|| cli.host.clone());

    // ssh_config(5) TOKENS in the directives that take them (before -G
    // prints them, except IdentityFile / CertificateFile, which OpenSSH
    // prints as written).
    // A configured User takes the tokens (but not %r, itself, or %C, which
    // hashes it) and ${VAR}; a name that expansion changed is checked as a
    // command-line one is.
    let configured = if cli.user_from_o {
        cli.cli_user.clone()
    } else if cli.cli_user.is_none() && cli.user_in_host.is_none() {
        cfg_block.user.clone()
    } else {
        None
    };
    if let Some(configured) = configured {
        let t = Tokens::new(&cli.host, &connect_host, port, "%r", &cfg_block, &cli);
        let expanded = t.expand(&expand_env(&configured.replace("%C", "%%C")));
        if expanded != configured {
            if !valid_ruser(&expanded) {
                return Err("remote username contains invalid characters".into());
            }
            user = expanded.clone();
            if cli.user_from_o {
                cli.cli_user = Some(expanded.clone());
            }
            cfg_block.user = Some(expanded);
        }
    }
    let tokens = Tokens::new(&cli.host, &connect_host, port, &user, &cfg_block, &cli);
    tokens.expand_options(&mut cfg_block);
    // Unix socket paths in forwards take tokens and ${VAR}.
    let socket_path = |p: &mut Option<String>| {
        if let Some(p) = p {
            *p = tokens.expand(&expand_env(p));
        }
    };
    for f in cli.locals.iter_mut() {
        socket_path(&mut f.listen_path);
        socket_path(&mut f.connect_path);
    }
    for f in cli.remotes.iter_mut() {
        socket_path(&mut f.listen_path);
        socket_path(&mut f.connect_path);
    }
    if let Some(p) = &cli.known_hosts_path {
        cli.known_hosts_path = Some(PathBuf::from(tokens.expand_path(&p.to_string_lossy())));
    }
    if command_from_config {
        cli.command = cfg_block.remote_command.clone();
    }

    // `-G`: print the resolved configuration and stop.
    if cli.print_config {
        print_config(&cli, &cfg_block, &connect_host, &user, port);
        return Ok(0);
    }

    tokens.expand_paths(&mut cfg_block);
    cli.identities = cli
        .identities
        .iter()
        .map(|p| tokens.expand_path(p))
        .collect();
    // `-Z`: the keys authentication would offer, and stop.
    if cli.dump_pubkeys {
        apply_identity_agent(cfg_block.identity_agent.as_ref(), identities_only);
        dump_pubkeys(&cli, &cfg_block, identities_only);
        return Ok(0);
    }
    let mut cfg = config_for_host(&cfg_block, &cli, &connect_host)?;
    // KnownHostsCommand: its output joins the global known_hosts files.
    if let Some(template) = cfg_block
        .known_hosts_command
        .clone()
        .filter(|c| !c.is_empty() && !c.eq_ignore_ascii_case("none"))
        && let puressh::client::HostKeyPolicy::KnownHosts(kh) = &mut cfg.host_key_policy
    {
        let tokens = tokens.clone();
        let looked_up = match &cfg_block.host_key_alias {
            Some(a) => a.clone(),
            None if port == 22 => connect_host.clone(),
            None => format!("[{connect_host}]:{port}"),
        };
        kh.command = Some(Arc::new(move |key_type: &str, blob: &[u8]| {
            known_hosts_command(&template, &tokens, &looked_up, key_type, blob)
        }));
    }

    // ---- Connection multiplexing (ControlMaster/ControlPath/ControlPersist) ----
    // Resolve the control settings once. The honoring is Unix-only; the
    // resolved values just sit unused on other platforms.
    #[cfg(unix)]
    let mut mux_decision = resolve_mux(&cfg_block, &connect_host, port, &user)?;

    // `-O check|exit|stop`: a control command, not a session. Resolve the
    // ControlPath, talk to the master, and return — never connect/auth.
    #[cfg(unix)]
    if let Some(cmd) = cli.control_cmd.clone() {
        let dec = mux_decision.as_ref().ok_or_else(|| {
            "-O requires a ControlPath (set ControlPath in ssh_config or -o ControlPath=…)"
                .to_string()
        })?;
        return run_control_command(&cmd, &dec.path, &cli);
    }

    // `-O proxy`: the session goes through the running master, which must
    // be there.
    #[cfg(unix)]
    if cli.mux_proxy {
        let dec = mux_decision.as_ref().ok_or_else(|| {
            "-O requires a ControlPath (set ControlPath in ssh_config or -o ControlPath=…)"
                .to_string()
        })?;
        if puressh::mux::probe_master(&dec.path) != puressh::mux::ProbeOutcome::Live {
            eprintln!(
                "Control socket connect({}): No such file or directory",
                dec.path.display()
            );
            return Ok(255);
        }
        return run_mux_client(&cli, &cfg_block, &dec.path);
    }

    #[cfg(unix)]
    if let Some(ref dec) = mux_decision {
        use puressh::config::ControlMaster;
        // Client role: if master is auto/no and a live master answers, attach
        // to it and run the session as a new channel — no second TCP/KEX/auth.
        if matches!(dec.master, ControlMaster::Auto | ControlMaster::No) {
            // Trust check first: a symlink, a non-socket, or a socket owned
            // by / accessible to another user at the ControlPath is never
            // attached to (the mux client refuses internally too) and never
            // silently replaced — surface the reason and stop.
            match puressh::mux::validate_control_socket(&dec.path) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(format!("mux: refusing ControlPath: {e}")),
            }
            match puressh::mux::probe_master(&dec.path) {
                puressh::mux::ProbeOutcome::Live => {
                    // `-L` / `-D` ride the mux carrier: each accepted local
                    // connection opens its own OPEN_DIRECT_TCPIP control
                    // connection to the master, which dials the destination
                    // over its SSH connection. `-R`, `-A` and `-X`/`-Y` need
                    // the master's own session machinery, which this mux
                    // protocol does not carry: such a session gets its own
                    // connection instead (and leaves the master alone).
                    // `-R`: the master listens on the server for us, as
                    // OpenSSH's mux client asks it to.
                    if !cli.remotes.is_empty() && !cli.agent_forward && cli.x11_forward.is_none() {
                        for (kind, spec) in cli.forward_specs.iter().filter(|(k, _)| *k == b'R') {
                            match puressh::mux::request_forward(&dec.path, *kind, spec, false) {
                                Ok(port) if port != 0 => {
                                    warn!("Allocated port {port} for remote forward to {spec}")
                                }
                                Ok(_) => {}
                                Err(e) => {
                                    eprintln!("mux_client_forward: forwarding request failed: {e}");
                                    return Ok(255);
                                }
                            }
                        }
                        if cli.locals.is_empty() && dynamics.is_empty() {
                            if cli.no_command {
                                return Ok(0);
                            }
                            return run_mux_client(&cli, &cfg_block, &dec.path);
                        }
                    }
                    if cli.agent_forward || cli.x11_forward.is_some() {
                        vlog(
                            1,
                            "mux: -A/-X need their own connection; not using the master",
                        );
                        if let Some(d) = mux_decision.as_mut() {
                            d.become_master = false;
                        }
                    } else {
                        vlog(1, &format!("mux: reusing master at {}", dec.path.display()));
                        if !cli.locals.is_empty() || !dynamics.is_empty() {
                            // `-N` alongside `-L`/`-D` over mux is fine: we just
                            // serve the listeners and never open a session.
                            return run_mux_forwarding(&cli, &dynamics, &dec.path);
                        }
                        if cli.no_command {
                            return Err(
                                "-N over a multiplexed (ControlMaster) connection requires at \
                             least one of -L or -D (the only forwards a mux client can carry)"
                                    .into(),
                            );
                        }
                        return run_mux_client(&cli, &cfg_block, &dec.path);
                    }
                }
                puressh::mux::ProbeOutcome::Stale | puressh::mux::ProbeOutcome::Absent => {
                    // No live master: fall through to a normal connection.
                    // Under auto/yes we'll become the master after auth.
                    vlog(1, "mux: no live master, connecting normally");
                }
                _ => {
                    // A probe outcome this binary predates: treat it like
                    // "no usable master" rather than guessing.
                    vlog(1, "mux: unrecognised probe outcome, connecting normally");
                }
            }
        }
    }

    // Decide the connection transport for the final target:
    //   ProxyJump (CLI -J > config ProxyJump) tunnels through jump hosts;
    //   ProxyCommand spawns a helper process; otherwise a direct TCP socket.
    // ProxyJump beats ProxyCommand when both are configured (warn).
    let proxy_jump = cli
        .proxy_jump
        .clone()
        .or_else(|| cfg_block.proxy_jump.clone())
        .filter(|p| !p.eq_ignore_ascii_case("none"));
    let proxy_command = cfg_block
        .proxy_command
        .clone()
        .filter(|p| !p.eq_ignore_ascii_case("none"));
    if proxy_jump.is_some() && proxy_command.is_some() {
        warn!("warning: both ProxyJump and ProxyCommand set; using ProxyJump");
    }

    // Publickey credentials gathered before connecting (knock path only).
    let mut early_credentials: Option<Vec<ClientCredential>> = None;
    let mut client = if let Some(spec) = proxy_jump {
        // ---- ProxyJump ----
        let hops = parse_jump_hops(&spec)?;
        vlog(1, &format!("proxyjump: {} hop(s)", hops.len()));
        let (last, last_no_more_sessions) = connect_jump_chain(&hops, &ssh_cfg, &cli)?;
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
        if last_no_more_sessions {
            send_no_more_sessions(&last);
        }
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
            // `ProcTransport` now honours `set_read_timeout` (O_NONBLOCK fd +
            // poll-with-deadline read), so the serve / forwarding poll loops
            // tick correctly over the pipe carrier. `-L`/`-R`/`-D`/`-N` are
            // therefore supported here, same as a direct connection.
            let cmd = puressh::proc_transport::expand_tokens_checked(
                &cmd_raw,
                &connect_host,
                port,
                &user,
            )
            .map_err(|e| format!("ProxyCommand: {e}"))?;
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
        //
        // Unless `KnockMode no`, a refused or slow connect falls back to the
        // puressh UDP knock (docs/knock.md), which needs the publickey
        // identities up front to sign the knock.
        vlog(1, &format!("connecting to {connect_host}:{port}"));
        #[cfg_attr(not(feature = "knock"), allow(unused_mut))]
        let mut cfg = cfg;
        let knock_mode = cfg_block
            .knock_mode
            .unwrap_or(puressh::config::KnockSetting::Auto);
        // Without the `knock` feature the keywords parse but do nothing.
        let use_knock = cfg!(feature = "knock") && knock_mode != puressh::config::KnockSetting::No;
        let sock = if !use_knock {
            dial_tcp(&connect_host, port, &cfg_block)?
        } else {
            apply_identity_agent(cfg_block.identity_agent.as_ref(), identities_only);
            let creds = collect_credentials(&cfg_block, &cli.identities, identities_only);
            #[cfg(feature = "knock")]
            let sock =
                knock_support::dial(&connect_host, port, &user, &cfg_block, &mut cfg, &creds)?;
            #[cfg(not(feature = "knock"))]
            let sock = dial_tcp(&connect_host, port, &cfg_block)?;
            early_credentials = Some(creds);
            sock
        };
        common::set_peer_addr(sock.peer_addr().ok());
        if let (Ok(l), Ok(r)) = (sock.local_addr(), sock.peer_addr()) {
            let _ = CONN_ADDRS.set((l.to_string(), r.to_string()));
        }
        // CheckHostIP: the address too, unless it is loopback or the name
        // given was the address (OpenSSH; never through a proxy).
        if cfg_block.check_host_ip == Some(true)
            && let Ok(peer) = sock.peer_addr()
            && let puressh::client::HostKeyPolicy::KnownHosts(kh) = &mut cfg.host_key_policy
        {
            let ip = peer.ip().to_canonical();
            if !ip.is_loopback() && ip.to_string() != connect_host {
                kh.check_host_ip = Some(ip.to_string());
            }
        }
        let peer_ip = sock
            .peer_addr()
            .map(|a| a.ip().to_canonical().to_string())
            .unwrap_or_else(|_| connect_host.clone());
        let client = Client::connect_via(Box::new(sock), connect_host.as_str(), port, cfg)
            .map_err(|e| match e.openssh_negotiation_message(true) {
                // OpenSSH's wording, which admins and tools (Ansible's
                // error hints) recognise: the fix is in "Their offer".
                Some(m) => {
                    // `m` quotes the server's KEXINIT name lists.
                    eprintln!(
                        "Unable to negotiate with {peer_ip} port {port}: {}",
                        sanitize_terminal_str(&m)
                    );
                    String::new()
                }
                None if matches!(e, puressh::Error::HostKeyRejected) => {
                    eprintln!("Host key verification failed.");
                    String::new()
                }
                None => format!("connect: {e}"),
            })?;
        vlog(1, &format!("connected to {connect_host}:{port}"));
        client
    };

    // IdentityAgent overrides which agent socket we consult. `none` disables
    // the agent entirely; a path (with the `SSH_AUTH_SOCK` token expanded)
    // replaces $SSH_AUTH_SOCK for the agent-backed credential lookup and any
    // AddKeysToAgent push below. We do this by adjusting the process env so
    // the existing agent helpers (which read $SSH_AUTH_SOCK) pick it up.
    let credentials = match early_credentials {
        Some(c) => c,
        None => {
            apply_identity_agent(cfg_block.identity_agent.as_ref(), identities_only);
            collect_credentials(&cfg_block, &cli.identities, identities_only)
        }
    };
    // RekeyLimit: re-key after that much data / time (else the defaults).
    if let Some(rk) = cfg_block.rekey_limit {
        let mut policy = puressh::hazmat::transport::RekeyPolicy::default();
        if let Some(b) = rk.max_bytes {
            policy.max_bytes = b;
        }
        if let Some(secs) = rk.max_seconds {
            policy.max_duration = std::time::Duration::from_secs(secs as u64);
        }
        client.set_rekey_policy(policy);
    }
    // UpdateHostKeys: the server's `hostkeys-00@openssh.com` (sent after
    // authentication) is acted on once the connection is shared. Never over
    // a host key that failed known_hosts verification but was let through
    // (StrictHostKeyChecking=no): a MITM's key list must not rewrite the
    // recorded keys, as with OpenSSH.
    let hostkeys_updater = if client.host_key_mismatched() {
        vlog(
            1,
            "UpdateHostkeys is disabled because the host key is not trusted.",
        );
        None
    } else if HOST_KEY_FORCED.load(std::sync::atomic::Ordering::Relaxed) {
        None
    } else {
        HostKeysUpdater::for_connection(&cli, &cfg_block, &connect_host, port)
    };
    if let Some(u) = &hostkeys_updater {
        let u = u.clone();
        let negotiated = client.negotiated().map(|n| n.host_key);
        u.state.lock().map(|mut g| g.host_key_alg = negotiated).ok();
        client.set_global_request_hook(move |name, raw| {
            if name == "hostkeys-00@openssh.com" {
                u.received(raw.to_vec());
            }
        });
    }
    authenticate_client(&mut client, &connect_host, &user, credentials, &cfg_block)?;

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

    // ServerAliveInterval: started once the connection is shared (below).
    let server_alive = cfg_block.server_alive_interval.filter(|i| *i > 0);

    // As OpenSSH's ssh_session2: a connection that is not a ControlMaster
    // will open no other session than its own (if any), so once that is
    // open it asks the server to refuse any more — only an OpenSSH server
    // (by banner), or ours.
    let no_more_sessions = matches!(
        cfg_block.control_master,
        None | Some(puressh::config::ControlMaster::No)
    ) && server_honours_no_more_sessions(client.server_ident());

    // `-f`: authenticated; continue in the background.
    #[cfg(unix)]
    if cli.fork_after_auth {
        fork_to_background()?;
    }

    // `-W host:port`: stdin/stdout become a tunnel to host:port (the usual
    // `ProxyCommand ssh -W %h:%p jump` form); no session.
    if let Some(spec) = cli.stdio_forward.clone() {
        background_ready();
        set_session_qos(false);
        return run_stdio_forward(client, &spec, no_more_sessions);
    }

    // Forwarding, set up the way OpenSSH does it, alongside the session:
    //   -R  remote listeners, requested now (the replies are synchronous);
    //   -A  -X/-Y  requested on the session channel, the server's agent /
    //       X11 channels accepted by the handlers below;
    //   -L  -D  local listeners opening direct-tcpip channels.
    let exit_on_forward_failure = cfg_block.exit_on_forward_failure == Some(true);
    let gateway = cfg_block
        .gateway_ports
        .unwrap_or(puressh::config::GatewayPorts::No);
    let mut handlers = ClientHandlers::new();
    let remote_routes = request_remote_forwards(
        &mut client,
        &cli,
        exit_on_forward_failure,
        cfg_block.permit_remote_open.as_deref(),
    )?;
    let (tcp_cb, path_cb) = remote_routes.handlers();
    handlers = handlers
        .with_forwarded_tcpip(tcp_cb)
        .with_forwarded_streamlocal(path_cb);
    if cli.agent_forward {
        #[cfg(unix)]
        {
            // No usable agent: no forwarding, as with OpenSSH (which only
            // finds out when the server first asks for it).
            // `ForwardAgent <path>` / `$VARIABLE`: that socket, else
            // $SSH_AUTH_SOCK's.
            let named = cfg_block.forward_agent_socket.as_deref().map(|s| {
                let s = match s.strip_prefix('$') {
                    Some(var) => std::env::var(var).unwrap_or_default(),
                    None => s.to_string(),
                };
                PathBuf::from(expand_tilde(&s))
            });
            let path = named.or_else(|| {
                std::env::var_os("SSH_AUTH_SOCK")
                    .filter(|s| !s.is_empty())
                    .map(PathBuf::from)
                    .filter(|p| puressh::agent::validate_auth_sock(p).is_ok())
            });
            let cb = path.filter(|p| p.exists()).map(forwarded_agent_callback);
            match cb {
                Some(cb) => {
                    handlers = handlers.with_auth_agent(cb);
                    client.set_request_auth_agent_forwarding(true);
                }
                None => vlog(
                    1,
                    "-A: no usable agent ($SSH_AUTH_SOCK unset, or not a socket of \
                     yours); not forwarding it",
                ),
            }
        }
        #[cfg(not(unix))]
        warn!("Warning: agent forwarding is not supported on this platform; ignoring -A");
    }
    if let Some(mode) = cli.x11_forward {
        #[cfg(unix)]
        {
            // No display: no forwarding (OpenSSH: "DISPLAY not set").
            let cb = puressh::forwarding::x11::splice_to_local_display_callback();
            if cb.is_none() {
                vlog(
                    1,
                    "-X/-Y: $DISPLAY is unset or not a display we can reach; not forwarding X11",
                );
            }
            // puressh has no SECURITY-extension cookie isolation yet: -X
            // behaves like -Y. Say so rather than silently downgrading.
            if mode == X11Forward::Untrusted && cb.is_some() {
                warn!(
                    "Warning: -X is currently equivalent to -Y in puressh (no \
                     SECURITY-extension cookie); the remote can read X11 input from \
                     your local display."
                );
            }
            if let Some(cb) = cb {
                let cookie = mint_x11_cookie()?;
                handlers = handlers.with_x11(cb);
                client.set_request_x11_forwarding(Some((
                    false,
                    "MIT-MAGIC-COOKIE-1".to_string(),
                    cookie,
                    0,
                )));
            }
        }
        #[cfg(not(unix))]
        {
            let _ = mode;
            warn!("Warning: X11 forwarding is not supported on this platform; ignoring -X/-Y");
        }
    }

    // The session: a command (`-s`: a subsystem) or the login shell, all
    // streamed both ways like OpenSSH.
    if cli.subsystem && cli.command.is_none() {
        return Err("-s requires a subsystem name".into());
    }
    let has_command = cli.command.is_some();
    let use_pty = want_pty(&cli, &cfg_block, has_command, cli.subsystem);
    // IPQoS: interactive for a terminal session (or X11), else bulk.
    set_session_qos(use_pty || cli.x11_forward.is_some());
    // A terminal asked for explicitly (-t, RequestTTY yes / force) must be
    // granted, as OpenSSH; one it chose to ask for may be refused.
    let pty_required = matches!(
        cli.request_tty.or(cfg_block.request_tty),
        Some(puressh::config::RequestTty::Yes | puressh::config::RequestTty::Force)
    );
    // EscapeChar: `-e`, else `~`.
    let escape: Option<u8> = cli.escape_char.unwrap_or(Some(b'~'));
    // EnableEscapeCommandline (default no, as in OpenSSH 9.2+): `~C`.
    ESCAPE_CMDLINE.store(
        cfg_block.enable_escape_commandline == Some(true),
        std::sync::atomic::Ordering::Relaxed,
    );
    // ObscureKeystrokeTiming: unset ⇒ OpenSSH default (on@20ms); only used
    // for interactive terminal sessions.
    let okt = cfg_block
        .obscure_keystroke_timing
        .unwrap_or_else(puressh::config::ObscureKeystrokeTiming::default_on);
    let command = cli.command.clone();
    let subsystem = cli.subsystem;
    let no_command = cli.no_command;
    // Backstop: a re-key could have accepted a mismatched host key since the
    // updater was created; never let UpdateHostKeys run over it.
    if client.host_key_mismatched()
        && let Some(u) = &hostkeys_updater
    {
        u.distrust();
    }
    let shared: puressh::shared::SharedClient = client.into();
    shared.set_channel_handlers(handlers);
    let connected_at = std::time::Instant::now();
    {
        let s = shared.clone();
        let _ = CONNINFO.set(Box::new(move || connection_info(&s, connected_at)));
    }
    let listeners = bind_local_forwards(&cli, &dynamics, gateway, exit_on_forward_failure)?;
    // `-w` / `Tunnel`: the tunnel device forwarding.
    let (tunnel, tun_ifname) = match tunnel_request(&cfg_block)? {
        Some(req) => match open_tunnel(&shared, req, exit_on_forward_failure) {
            Some((link, ifname)) => (Some(link), Some(ifname)),
            None => (None, None),
        },
        None => (None, None),
    };
    // The threads serving the connection — forward listeners, keepalive —
    // start in the process that keeps it (a ControlPersist master forks).
    let alive_count = cfg_block.server_alive_count_max.unwrap_or(3);
    let alive_host = connect_host.clone();
    let channel_timeouts: Vec<(String, u32)> = cfg_block
        .channel_timeouts
        .iter()
        .flatten()
        .filter_map(|t| puressh::config::parse_channel_timeout(t))
        .collect();
    let start_serving = move |shared: &puressh::shared::SharedClient| {
        serve_local_listeners(listeners, shared);
        if let Some(link) = tunnel {
            serve_tunnel(shared, link);
        }
        if let Some(interval) = server_alive {
            spawn_keepalive(shared, interval, alive_count, alive_host);
        }
        if channel_timeouts.iter().any(|(_, secs)| *secs > 0) {
            spawn_channel_timeouts(shared, channel_timeouts);
        }
    };

    // A server's SSH_MSG_DISCONNECT is reported as OpenSSH does.
    let peer = format!("{connect_host} port {port}");
    let disconnect_peer = peer.clone();
    let disconnected = move |s: &puressh::shared::SharedClient| -> bool {
        let peer = &disconnect_peer;
        match s.disconnect_reason() {
            Some((reason, description)) => {
                warn!("Received disconnect from {peer}:{reason}: {description}");
                warn!("Disconnected from {peer}");
                true
            }
            None => false,
        }
    };
    // LocalCommand (PermitLocalCommand yes): run here once the connection
    // and its forwards are up, waiting for it, as OpenSSH's ssh_session2.
    if cfg_block.permit_local_command == Some(true)
        && let Some(cmd) = cfg_block
            .local_command
            .as_deref()
            .filter(|c| !c.is_empty() && !c.eq_ignore_ascii_case("none"))
    {
        run_local_command(
            &tokens.expand(&cmd.replace("%T", tun_ifname.as_deref().unwrap_or("NONE"))),
        );
    }

    // `-N`: no session; keep the connection (and its forwards) alive.
    let run = move |s: &puressh::shared::SharedClient| -> i32 {
        // Forwards up, control socket (if any) bound: `-f` may detach.
        background_ready();
        if no_command {
            if no_more_sessions {
                send_no_more_sessions(s);
            }
            return match s.pump_until_closed() {
                Ok(()) => 0,
                Err(e) => {
                    if let Some(m) = transport_fatal(&e.to_string(), &peer) {
                        eprintln!("{m}");
                    } else if !disconnected(s) {
                        warn!("Connection closed: {e}");
                    }
                    255
                }
            };
        }
        // With forwards or remote channels to serve, keep pumping the
        // connection when the session is not reading.
        let what = session_request(command.as_deref(), subsystem);
        let code = run_session(
            s,
            what,
            use_pty,
            pty_required,
            okt,
            escape,
            no_more_sessions,
        )
        .unwrap_or_else(|e| {
            // Empty: already reported in OpenSSH's words.
            if let Some(m) = transport_fatal(&e, &peer) {
                eprintln!("{m}");
            } else if !e.is_empty() && !disconnected(s) {
                eprintln!("ssh: {e}");
            }
            255
        });
        // A forwarded tunnel keeps the connection, as with OpenSSH.
        if TUNNEL_ALIVE.load(std::sync::atomic::Ordering::Relaxed) {
            let _ = s.pump_while(|| TUNNEL_ALIVE.load(std::sync::atomic::Ordering::Relaxed));
        }
        code
    };
    // `~C` adds and cancels forwards on this connection.
    #[cfg(unix)]
    let _ = ESCAPE_FORWARDS.set(MuxForwards {
        shared: shared.clone(),
        routes: remote_routes.clone(),
        gateway,
        listeners: Arc::default(),
    });
    // Master role: serve the control socket while running this session as
    // the foreground one.
    #[cfg(unix)]
    if let Some(dec) = mux_decision.as_ref().filter(|d| d.become_master) {
        if let Some(u) = &hostkeys_updater {
            u.attach(shared.clone());
        }
        let extras = MasterExtras {
            routes: remote_routes.clone(),
            gateway,
            started: connected_at,
        };
        return become_master(dec, &cli, &cfg_block, shared, start_serving, run, extras);
    }
    if let Some(u) = &hostkeys_updater {
        u.attach(shared.clone());
    }
    start_serving(&shared);
    let code = run(&shared);
    // Let an UpdateHostKeys exchange in flight finish.
    if let Some(u) = &hostkeys_updater {
        u.wait(std::time::Duration::from_secs(5));
    }
    Ok(code)
}

/// `UpdateHostKeys`, as OpenSSH's client: after authentication the server
/// lists all its host keys (`hostkeys-00@openssh.com`); keys the user's
/// known_hosts does not have for this host are proven by the server
/// (`hostkeys-prove-00@openssh.com`, signed over the session id) and
/// recorded, and recorded keys it no longer offers are removed.
struct HostKeysUpdater {
    /// The name the host is recorded under, and its port.
    host: String,
    port: u16,
    /// The known_hosts file updated (the first user one).
    file: PathBuf,
    hash: bool,
    /// `HostKeyAlgorithms`: offered keys of other types are not learned.
    algorithms: Vec<String>,
    state: std::sync::Mutex<HostKeysUpdateState>,
    done: std::sync::Condvar,
    /// Set once the session's host key is known not to match known_hosts;
    /// no update is then made (checked again right before writing).
    untrusted: std::sync::atomic::AtomicBool,
}

#[derive(Default)]
struct HostKeysUpdateState {
    offered: Option<Vec<u8>>,
    shared: Option<puressh::shared::SharedClient>,
    host_key_alg: Option<String>,
    started: bool,
    finished: bool,
}

/// OpenSSH's `UpdateHostKeys` default: on, unless `VerifyHostKeyDNS` is or
/// `UserKnownHostsFile` names files other than `~/.ssh/known_hosts`.
fn update_host_keys_by_default(cli: &Cli, cfg_block: &puressh::config::ClientOptions) -> bool {
    if matches!(
        cfg_block.verify_host_key_dns,
        Some(puressh::config::VerifyHostKeyDns::Yes | puressh::config::VerifyHostKeyDns::Ask)
    ) {
        return false;
    }
    let explicit = cli.known_hosts_path.is_some() || cfg_block.user_known_hosts.is_some();
    let files = user_known_hosts_files(cli, cfg_block);
    !explicit || (files.len() == 1 && common::default_known_hosts_path().as_ref() == files.first())
}

impl HostKeysUpdater {
    /// The updater for this connection, unless UpdateHostKeys is off (by
    /// default it is on when UserKnownHostsFile is not set, or is just
    /// `~/.ssh/known_hosts`).
    fn for_connection(
        cli: &Cli,
        cfg_block: &puressh::config::ClientOptions,
        host: &str,
        port: u16,
    ) -> Option<Arc<Self>> {
        let files = user_known_hosts_files(cli, cfg_block);
        let on = match cfg_block.update_host_keys.as_deref() {
            Some("yes") => true,
            Some(_) => false,
            None => update_host_keys_by_default(cli, cfg_block),
        };
        let file = files.into_iter().next()?;
        if !on || file == std::path::Path::new("/dev/null") {
            return None;
        }
        let (host, port) = match &cfg_block.host_key_alias {
            Some(a) => (a.clone(), 22),
            None => (host.to_string(), port),
        };
        Some(Arc::new(Self {
            host,
            port,
            file,
            hash: cli.hash_known_hosts.or(cfg_block.hash_known_hosts) == Some(true),
            algorithms: cfg_block.host_key_algorithms.clone().unwrap_or_else(|| {
                puressh::config::default_algorithms(puressh::config::AlgoCategory::HostKey)
                    .into_iter()
                    .map(String::from)
                    .collect()
            }),
            state: std::sync::Mutex::new(HostKeysUpdateState::default()),
            done: std::sync::Condvar::new(),
            untrusted: std::sync::atomic::AtomicBool::new(false),
        }))
    }

    /// The session's host key is not trusted: make no update.
    fn distrust(&self) {
        self.untrusted
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }

    fn trusted(&self) -> bool {
        !self.untrusted.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// The server's host key list arrived.
    fn received(self: &Arc<Self>, raw: Vec<u8>) {
        if let Ok(mut g) = self.state.lock()
            && g.offered.is_none()
        {
            g.offered = Some(raw);
            self.maybe_start(&mut g);
        }
    }

    /// The connection is shared from now on.
    fn attach(self: &Arc<Self>, shared: puressh::shared::SharedClient) {
        if let Ok(mut g) = self.state.lock() {
            g.shared = Some(shared);
            self.maybe_start(&mut g);
        }
    }

    fn maybe_start(self: &Arc<Self>, g: &mut HostKeysUpdateState) {
        let (Some(raw), Some(shared)) = (g.offered.clone(), g.shared.clone()) else {
            return;
        };
        if g.started || !self.trusted() {
            return;
        }
        g.started = true;
        let me = self.clone();
        let host_key_alg = g.host_key_alg.clone();
        thread::spawn(move || {
            me.update(&shared, &raw, host_key_alg.as_deref());
            if let Ok(mut g) = me.state.lock() {
                g.finished = true;
            }
            me.done.notify_all();
        });
    }

    /// Wait (up to `limit`) for an update that has started.
    fn wait(&self, limit: std::time::Duration) {
        let Ok(mut g) = self.state.lock() else {
            return;
        };
        let deadline = std::time::Instant::now() + limit;
        while g.started && !g.finished {
            let left = deadline.saturating_duration_since(std::time::Instant::now());
            if left.is_zero() {
                return;
            }
            match self.done.wait_timeout(g, left) {
                Ok((ng, _)) => g = ng,
                Err(_) => return,
            }
        }
    }

    /// Whether `HostKeyAlgorithms` allows a key of type `key_type`.
    fn permitted(&self, key_type: &str) -> bool {
        let rsa = ["rsa-sha2-512", "rsa-sha2-256", "ssh-rsa"];
        self.algorithms
            .iter()
            .any(|a| a == key_type || (key_type == "ssh-rsa" && rsa.contains(&a.as_str())))
    }

    fn update(
        &self,
        shared: &puressh::shared::SharedClient,
        raw: &[u8],
        host_key_alg: Option<&str>,
    ) {
        if !self.trusted() {
            vlog(
                1,
                "UpdateHostkeys is disabled because the host key is not trusted.",
            );
            return;
        }
        // The offered keys: plain ones HostKeyAlgorithms allows.
        let mut offered: Vec<Vec<u8>> = Vec::new();
        let mut rest = raw;
        while rest.len() >= 4 {
            let n = u32::from_be_bytes([rest[0], rest[1], rest[2], rest[3]]) as usize;
            if rest.len() < 4 + n {
                vlog(1, "UpdateHostKeys: malformed hostkeys message");
                return;
            }
            let blob = rest[4..4 + n].to_vec();
            rest = &rest[4 + n..];
            let Some(t) = key_blob_type(&blob) else {
                continue;
            };
            if puressh::cert::is_cert_name(&t) || !self.permitted(&t) {
                continue;
            }
            if offered.contains(&blob) {
                vlog(
                    1,
                    &format!("UpdateHostKeys: received duplicated {t} host key"),
                );
                return;
            }
            offered.push(blob);
        }
        if offered.is_empty() {
            return;
        }
        let mut kh = match std::fs::read(&self.file) {
            Ok(b) => puressh::known_hosts::KnownHosts::from_bytes(&b),
            Err(e) if e.kind() == ErrorKind::NotFound => puressh::known_hosts::KnownHosts::new(),
            Err(_) => return,
        };
        let plan = kh.host_keys_update(&self.host, self.port, &offered);
        if let Some(why) = plan.blocked {
            vlog(
                1,
                &format!("UpdateHostKeys: {why}; skipping known_hosts update"),
            );
            return;
        }
        if plan.new.is_empty() && plan.old.is_empty() {
            return;
        }
        let mut add: Vec<(String, Vec<u8>)> = Vec::new();
        if !plan.new.is_empty() {
            let mut req = Vec::new();
            for &i in &plan.new {
                req.extend_from_slice(&(offered[i].len() as u32).to_be_bytes());
                req.extend_from_slice(&offered[i]);
            }
            let reply = match shared.global_request("hostkeys-prove-00@openssh.com", &req) {
                Ok(r) => r,
                Err(_) => {
                    warn!("Server failed to confirm ownership of private host keys");
                    return;
                }
            };
            let Ok(session_id) = shared.session_id() else {
                return;
            };
            let mut sigs = &reply[..];
            for &i in &plan.new {
                let key = &offered[i];
                if sigs.len() < 4 {
                    return;
                }
                let n = u32::from_be_bytes([sigs[0], sigs[1], sigs[2], sigs[3]]) as usize;
                if sigs.len() < 4 + n {
                    return;
                }
                let sig = &sigs[4..4 + n];
                sigs = &sigs[4 + n..];
                let Some(key_type) = key_blob_type(key) else {
                    return;
                };
                let Some(alg) = key_blob_type(sig) else {
                    return;
                };
                // RSA proofs: the negotiated RSA algorithm, else SHA-2 only.
                let alg = if key_type == "ssh-rsa" {
                    match host_key_alg.filter(|a| a.starts_with("rsa-sha2-") || *a == "ssh-rsa") {
                        Some(a) => a.to_string(),
                        None if alg.starts_with("rsa-sha2-") => alg,
                        None => continue,
                    }
                } else {
                    alg
                };
                let mut signed = Vec::new();
                for part in [
                    b"hostkeys-prove-00@openssh.com".as_slice(),
                    &session_id,
                    key,
                ] {
                    signed.extend_from_slice(&(part.len() as u32).to_be_bytes());
                    signed.extend_from_slice(part);
                }
                if puressh::hostkey::verify_signature(&alg, key, &signed, sig).is_err() {
                    warn!("server gave bad signature for {key_type} key {i}");
                    return;
                }
                vlog(
                    1,
                    &format!(
                        "Learned new hostkey: {} {}",
                        puressh::client::host_key_type_label(key),
                        common::fingerprint_b64_sha256(key)
                    ),
                );
                add.push((key_type, key.clone()));
            }
        }
        for old in &plan.old {
            vlog(
                1,
                &format!(
                    "Deprecating obsolete hostkey: {}",
                    common::fingerprint_b64_sha256(old)
                ),
            );
        }
        // Last check before rewriting the recorded keys.
        if !self.trusted() {
            return;
        }
        kh.update_host_keys(&self.host, self.port, &plan.old, &add, self.hash);
        if let Err(e) = kh.save(&self.file) {
            warn!(
                "UpdateHostKeys: {}: {}",
                self.file.display(),
                common::io_reason(&e)
            );
        }
    }
}

/// The algorithm name a key or signature blob starts with.
fn key_blob_type(blob: &[u8]) -> Option<String> {
    let n = u32::from_be_bytes(blob.get(..4)?.try_into().ok()?) as usize;
    let name = blob.get(4..4 + n)?;
    core::str::from_utf8(name).ok().map(str::to_string)
}

/// Run a `LocalCommand` with the user's shell (`$SHELL`, else `/bin/sh`;
/// `cmd` on Windows) and wait for it; its output goes to ssh's own stdout and stderr.
/// OpenSSH's `a2tun`: `local[:remote]` tun units, each a number or `any`
/// (the remote one defaults to any).
fn parse_tun_units(s: &str) -> Option<(u32, u32)> {
    const ANY: u32 = 0x7fff_ffff;
    let unit = |u: &str| {
        if u.eq_ignore_ascii_case("any") {
            Some(ANY)
        } else {
            u.parse::<u32>().ok().filter(|n| *n < ANY)
        }
    };
    match s.split_once(':') {
        Some((l, r)) => Some((unit(l)?, unit(r)?)),
        None => Some((unit(s)?, ANY)),
    }
}

/// The tunnel `Tunnel` / `TunnelDevice` (or `-w`) ask for: `(mode, local
/// unit, remote unit)`, `None` when tunnelling is off.
fn tunnel_request(cfg: &puressh::config::ClientOptions) -> Result<Option<(u32, u32, u32)>, String> {
    let mode = match cfg.tunnel.as_deref() {
        Some("yes" | "true" | "point-to-point") => 1,
        Some("ethernet") => 2,
        _ => return Ok(None),
    };
    let device = cfg.tunnel_device.as_deref().unwrap_or("any:any");
    let (local, remote) =
        parse_tun_units(device).ok_or_else(|| format!("Bad tun device '{device}'"))?;
    Ok(Some((mode, local, remote)))
}

/// OpenSSH's `-G` spelling of `Tunnel` and `TunnelDevice`.
fn tunnel_dump(key: &str, value: &str) -> String {
    match key {
        "tunnel" => match value.to_ascii_lowercase().as_str() {
            "yes" | "true" | "point-to-point" => "point-to-point".into(),
            "ethernet" => "ethernet".into(),
            _ => "false".into(),
        },
        _ => match parse_tun_units(value) {
            Some((l, r)) => {
                let u = |n: u32| {
                    if n == 0x7fff_ffff {
                        "any".to_string()
                    } else {
                        n.to_string()
                    }
                };
                format!("{}:{}", u(l), u(r))
            }
            None => value.to_string(),
        },
    }
}

/// A forwarded tunnel: the local device, the channel and its mode.
type TunLink = (std::fs::File, puressh::shared::OwnedChannelStream, u32);

/// Open the local device and the `tun@openssh.com` channel, as OpenSSH's
/// `ssh_init_forwarding`: a failure is reported (and fatal with
/// `ExitOnForwardFailure`). Returns the link and the interface name.
fn open_tunnel(
    shared: &puressh::shared::SharedClient,
    (mode, local, remote): (u32, u32, u32),
    exit_on_forward_failure: bool,
) -> Option<(TunLink, String)> {
    let fail = |m: &str| {
        eprintln!("{m}");
        if exit_on_forward_failure {
            std::process::exit(255);
        }
    };
    let (dev, ifname) = match tundev::open(local, mode) {
        Ok(d) => d,
        Err(e) => {
            vlog(1, &format!("tun open: {e}"));
            eprintln!("Tunnel device open failed.");
            fail("Could not request tunnel forwarding.");
            return None;
        }
    };
    vlog(1, &format!("Tunnel forwarding using interface {ifname}"));
    match shared.open_tun(mode, remote) {
        Ok(ch) => Some(((dev, ch, mode), ifname)),
        Err(_) => {
            fail("Tunnel forwarding failed");
            None
        }
    }
}

/// Whether a forwarded tunnel is still up: like OpenSSH's, the client
/// stays connected after its session ends until the tunnel closes.
static TUNNEL_ALIVE: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Move packets between the local device and the channel until either
/// ends.
#[cfg(unix)]
fn serve_tunnel(shared: &puressh::shared::SharedClient, (dev, ch, mode): TunLink) {
    use std::sync::atomic::Ordering;
    let (rx, tx) = (shared.clone(), shared.clone());
    TUNNEL_ALIVE.store(true, Ordering::Relaxed);
    std::thread::spawn(move || {
        let id = ch.channel_id();
        let _ = puressh::forwarding::tun::splice(
            dev,
            mode,
            || rx.recv_datagram(id).ok().flatten(),
            move |m| tx.send_datagram(id, &m).is_ok(),
        );
        drop(ch);
        TUNNEL_ALIVE.store(false, Ordering::Relaxed);
    });
}

#[cfg(not(unix))]
fn serve_tunnel(_shared: &puressh::shared::SharedClient, _link: TunLink) {}

fn run_local_command(cmd: &str) {
    #[cfg(unix)]
    let (shell, flag) = (
        std::env::var("SHELL")
            .ok()
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "/bin/sh".to_string()),
        "-c",
    );
    #[cfg(not(unix))]
    let (shell, flag) = ("cmd".to_string(), "/C");
    vlog(3, &format!("Executing {shell} {flag} \"{cmd}\""));
    if let Err(e) = std::process::Command::new(&shell)
        .arg(flag)
        .arg(cmd)
        .status()
    {
        warn!(
            "Couldn't execute {shell} -c \"{cmd}\": {}",
            common::io_reason(&e)
        );
    }
}

/// The name `ChannelTimeout` (and the channel list) call a channel of wire
/// type `kind` by, as OpenSSH's client.
fn channel_type_name(kind: &str) -> &str {
    match kind {
        "auth-agent@openssh.com" => "agent-connection",
        "x11" => "x11-connection",
        "tun@openssh.com" => "tun-connection",
        other => other,
    }
}

/// The open channels, worded as OpenSSH's `channel_open_message` heads
/// them (`~#`, `ssh -O channels`).
fn channel_list(shared: &puressh::shared::SharedClient) -> String {
    let mut out = String::from("The following connections are open:\r\n");
    for (id, kind, _) in shared.open_channels().unwrap_or_default() {
        out.push_str(&format!("  #{id} {}\r\n", channel_type_name(&kind)));
    }
    out
}

/// The channel of this process's own session (`u32::MAX`: none yet).
static MAIN_SESSION: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(u32::MAX);

/// `ChannelTimeout`: close each channel idle (no data either way) for
/// longer than the first `type=interval` its type matches, and every
/// channel when all of them together have been idle past `global`, as
/// OpenSSH's client does.
fn spawn_channel_timeouts(shared: &puressh::shared::SharedClient, timeouts: Vec<(String, u32)>) {
    let s = shared.clone();
    thread::spawn(move || {
        let limit_for = |ty: &str| {
            for (pat, secs) in &timeouts {
                if pat != "global"
                    && puressh::config::host_matches(
                        &[puressh::config::HostPattern::parse(pat)],
                        ty,
                    )
                {
                    return *secs;
                }
            }
            0
        };
        let global = timeouts
            .iter()
            .find(|(pat, _)| pat == "global")
            .map_or(0, |(_, secs)| *secs);
        let mut idle: std::collections::BTreeMap<u32, (u64, std::time::Instant)> =
            std::collections::BTreeMap::new();
        let mut all_idle = (0u64, std::time::Instant::now());
        loop {
            thread::sleep(std::time::Duration::from_secs(1));
            let Ok(open) = s.open_channels() else {
                return;
            };
            let now = std::time::Instant::now();
            let mut expired = Vec::new();
            let mut total = 0u64;
            for (id, kind, activity) in &open {
                total = total.wrapping_add(*activity);
                let e = idle.entry(*id).or_insert((*activity, now));
                if e.0 != *activity {
                    *e = (*activity, now);
                }
                let limit = limit_for(channel_type_name(kind));
                if limit > 0 && now.duration_since(e.1).as_secs() >= u64::from(limit) {
                    vlog(1, &format!("channel {id}: timed out after {limit} seconds"));
                    expired.push(*id);
                }
            }
            idle.retain(|id, _| open.iter().any(|(o, _, _)| o == id));
            if all_idle.0 != total || open.is_empty() {
                all_idle = (total, now);
            } else if global > 0 && now.duration_since(all_idle.1).as_secs() >= u64::from(global) {
                vlog(
                    1,
                    &format!("inactive channels timed out after {global} seconds"),
                );
                expired = open.iter().map(|(id, _, _)| *id).collect();
                all_idle = (total, now);
            }
            for id in expired {
                idle.remove(&id);
                let _ = s.close_channel(id);
                // The session itself: ssh ends there (status 255), as
                // OpenSSH's client does without waiting for the server.
                if id == MAIN_SESSION.load(std::sync::atomic::Ordering::Relaxed) {
                    #[cfg(unix)]
                    if let Ok(g) = ORIGINAL_TERMIOS.lock()
                        && let Some(t) = g.as_ref()
                    {
                        // SAFETY: restoring a termios captured from fd 0.
                        unsafe { libc::tcsetattr(0, libc::TCSADRAIN, t) };
                    }
                    common::finish_log();
                    std::process::exit(255);
                }
            }
        }
    });
}

/// `ServerAliveInterval`: a keepalive on the connection every `interval`
/// seconds, so NAT and firewall state stays up during quiet periods, and
/// ssh exits (status 255) once the connection can no longer be written to.
/// `ServerAliveInterval` / `ServerAliveCountMax`, as OpenSSH: after
/// `interval` seconds without hearing from the server, send a keepalive
/// request; once `count_max` of them go unanswered (no traffic at all from
/// the server meanwhile), give up.
fn spawn_keepalive(
    shared: &puressh::shared::SharedClient,
    interval: u32,
    count_max: u32,
    host: String,
) {
    let s = shared.clone();
    let interval = std::time::Duration::from_secs(interval as u64);
    thread::spawn(move || {
        let mut unanswered = 0u32;
        loop {
            thread::sleep(interval);
            match s.idle_for() {
                Ok(idle) if idle < interval => {
                    unanswered = 0;
                    continue;
                }
                Ok(_) => {}
                Err(_) => return,
            }
            if unanswered >= count_max {
                eprintln!("Timeout, server {host} not responding.");
                std::process::exit(255);
            }
            if s.send_keepalive().is_err() {
                eprintln!("Timeout, server {host} not responding.");
                std::process::exit(255);
            }
            unanswered += 1;
        }
    });
}

/// Where a `-R` connection goes on this side.
#[derive(Clone, Debug)]
enum RemoteDest {
    Tcp(String, u16),
    Path(String),
    /// `-R [bind:]port`: the connection is a SOCKS request.
    Socks,
}

impl RemoteDest {
    fn of(r: &RemoteForward) -> Self {
        match &r.connect_path {
            Some(p) => RemoteDest::Path(p.clone()),
            None if r.dynamic => RemoteDest::Socks,
            None => RemoteDest::Tcp(r.local_host.clone(), r.local_port),
        }
    }
}

/// Where the server's forwarded connections go: per listener (as requested
/// from the server), the local destination. Shared with the handlers, so
/// remote forwards can be added later (`ssh -O forward -R`).
#[derive(Clone, Default)]
struct RemoteRoutes {
    tcp: Arc<std::sync::Mutex<std::collections::BTreeMap<(String, u16), RemoteDest>>>,
    paths: Arc<std::sync::Mutex<std::collections::BTreeMap<String, RemoteDest>>>,
    permit: Arc<Option<Vec<String>>>,
}

impl RemoteRoutes {
    /// The handlers for the server's `forwarded-tcpip` and
    /// `forwarded-streamlocal` channels.
    fn handlers(
        &self,
    ) -> (
        Arc<ForwardedTcpipCallback>,
        Arc<ForwardedStreamlocalCallback>,
    ) {
        let me = self.clone();
        let tcp: Arc<ForwardedTcpipCallback> =
            Arc::new(move |origin: ForwardedTcpipOrigin, stream: ChannelStream| {
                // The server names the listener as it was requested; a
                // server that normalises the address is matched on the port.
                let route = me.tcp.lock().ok().and_then(|routes| {
                    routes
                        .get(&(origin.bound_address.clone(), origin.bound_port))
                        .or_else(|| {
                            let mut by_port =
                                routes.iter().filter(|((_, p), _)| *p == origin.bound_port);
                            match (by_port.next(), by_port.next()) {
                                (Some((_, t)), None) => Some(t),
                                _ => None,
                            }
                        })
                        .cloned()
                });
                match route {
                    Some(dest) => serve_remote_dest(stream, dest, me.permit.clone()),
                    None => warn!(
                        "Warning: forwarded connection for unknown listener {}:{}; dropping",
                        origin.bound_address, origin.bound_port
                    ),
                }
            });
        let me = self.clone();
        let path: Arc<ForwardedStreamlocalCallback> = Arc::new(
            move |origin: ForwardedStreamlocalOrigin, stream: ChannelStream| {
                let route = me
                    .paths
                    .lock()
                    .ok()
                    .and_then(|p| p.get(&origin.socket_path).cloned());
                match route {
                    Some(dest) => serve_remote_dest(stream, dest, me.permit.clone()),
                    None => warn!(
                        "Warning: forwarded connection for unknown listener {}; dropping",
                        origin.socket_path
                    ),
                }
            },
        );
        (tcp, path)
    }
}

/// The address a remote forward asks the server to listen on, as OpenSSH's
/// channel_rfwd_bind_host: none is the server's loopback, `*` (or empty)
/// all of its interfaces.
fn rfwd_bind_host(r: &RemoteForward) -> &str {
    match r.bind_addr.as_deref() {
        None => "localhost",
        Some("" | "*") => "",
        Some(a) => a,
    }
}

/// `-R`: ask the server to listen for every remote forward (before the
/// connection is shared: the replies are awaited synchronously) and return
/// where each forwarded connection goes.
fn request_remote_forwards(
    client: &mut Client,
    cli: &Cli,
    exit_on_forward_failure: bool,
    permit_remote_open: Option<&[String]>,
) -> Result<RemoteRoutes, String> {
    let routes = RemoteRoutes {
        permit: Arc::new(permit_remote_open.map(<[String]>::to_vec)),
        ..Default::default()
    };
    for r in &cli.remotes {
        let dest = RemoteDest::of(r);
        let shown = match &dest {
            RemoteDest::Tcp(h, p) => format!("{h}:{p}"),
            RemoteDest::Path(p) => p.clone(),
            RemoteDest::Socks => "SOCKS".to_string(),
        };
        let fail = |what: String, e: puressh::Error| -> Result<(), String> {
            let msg = format!("remote port forwarding failed for listen {what}: {e}");
            if exit_on_forward_failure {
                return Err(msg);
            }
            warn!("Warning: {msg}");
            Ok(())
        };
        if let Some(path) = &r.listen_path {
            match client.request_streamlocal_forward(path) {
                Ok(()) => {
                    vlog(1, &format!("-R {path}:{shown} active"));
                    if let Ok(mut p) = routes.paths.lock() {
                        p.insert(path.clone(), dest);
                    }
                }
                Err(e) => fail(format!("path {path}"), e)?,
            }
            continue;
        }
        let bind = rfwd_bind_host(r);
        let bound_port = match client.request_tcpip_forward(bind, r.remote_port) {
            Ok(p) => p,
            Err(e) => {
                fail(format!("port {}", r.remote_port), e)?;
                continue;
            }
        };
        vlog(1, &format!("-R {bind}:{bound_port}:{shown} active"));
        // OpenSSH reports the port the server picked for `-R 0:…`.
        if r.remote_port == 0 {
            match &dest {
                RemoteDest::Socks => warn!("Allocated port {bound_port} for remote forward"),
                _ => warn!("Allocated port {bound_port} for remote forward to {shown}"),
            }
        }
        if let Ok(mut t) = routes.tcp.lock() {
            t.insert((bind.to_string(), bound_port), dest);
        }
    }
    Ok(routes)
}

/// Connect one forwarded connection to its local destination. Runs off the
/// connection's I/O thread: connecting, or reading a SOCKS request from the
/// channel, may block.
fn serve_remote_dest(stream: ChannelStream, dest: RemoteDest, permit: Arc<Option<Vec<String>>>) {
    thread::spawn(move || match dest {
        RemoteDest::Socks => socks_to_local(stream, permit.as_deref()),
        RemoteDest::Tcp(host, port) => match TcpStream::connect((host.as_str(), port)) {
            Ok(tcp) => spawn_splice_to_tcp(stream, tcp),
            Err(e) => warn!(
                "connect to {host} port {port} failed: {}",
                common::io_reason(&e)
            ),
        },
        RemoteDest::Path(path) => match LocalConn::connect_path(&path) {
            Ok(conn) => spawn_splice_to_tcp(stream, conn),
            Err(e) => warn!("connect to {path} failed: {}", common::io_reason(&e)),
        },
    });
}

/// The local end of a forwarded connection: a TCP or Unix-domain stream.
enum LocalConn {
    Tcp(TcpStream),
    #[cfg(unix)]
    Unix(std::os::unix::net::UnixStream),
}

impl LocalConn {
    /// Connect to a Unix socket (not available on Windows).
    fn connect_path(path: &str) -> std::io::Result<Self> {
        #[cfg(unix)]
        return std::os::unix::net::UnixStream::connect(path).map(LocalConn::Unix);
        #[cfg(not(unix))]
        {
            let _ = path;
            Err(std::io::Error::new(
                ErrorKind::Unsupported,
                "Unix domain sockets are not supported on this platform",
            ))
        }
    }

    fn try_clone(&self) -> std::io::Result<Self> {
        match self {
            LocalConn::Tcp(t) => t.try_clone().map(LocalConn::Tcp),
            #[cfg(unix)]
            LocalConn::Unix(u) => u.try_clone().map(LocalConn::Unix),
        }
    }

    fn shutdown(&self, how: std::net::Shutdown) -> std::io::Result<()> {
        match self {
            LocalConn::Tcp(t) => t.shutdown(how),
            #[cfg(unix)]
            LocalConn::Unix(u) => u.shutdown(how),
        }
    }
}

impl From<TcpStream> for LocalConn {
    fn from(t: TcpStream) -> Self {
        LocalConn::Tcp(t)
    }
}

impl Read for LocalConn {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            LocalConn::Tcp(t) => t.read(buf),
            #[cfg(unix)]
            LocalConn::Unix(u) => u.read(buf),
        }
    }
}

impl Write for LocalConn {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self {
            LocalConn::Tcp(t) => t.write(buf),
            #[cfg(unix)]
            LocalConn::Unix(u) => u.write(buf),
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            LocalConn::Tcp(t) => t.flush(),
            #[cfg(unix)]
            LocalConn::Unix(u) => u.flush(),
        }
    }
}

/// `PermitRemoteOpen`, as OpenSSH's open_match: unset or `any` allows all,
/// `none` nothing, else a `host:port` entry must match (`*` for either part;
/// IPv6 hosts may be bracketed).
fn remote_open_permitted(permit: Option<&[String]>, host: &str, port: u16) -> bool {
    let Some(list) = permit else {
        return true;
    };
    list.iter().any(|e| {
        if e.eq_ignore_ascii_case("any") {
            return true;
        }
        let Some((h, p)) = e.rsplit_once(':') else {
            return false;
        };
        let h = h
            .strip_prefix('[')
            .and_then(|h| h.strip_suffix(']'))
            .unwrap_or(h);
        (h == "*" || h == host) && (p == "*" || p.parse::<u16>() == Ok(port))
    })
}

/// Serve one `-R [bind:]port` connection: read its SOCKS request, connect to
/// the destination from here, reply, then splice the two.
fn socks_to_local(mut stream: ChannelStream, permit: Option<&[String]>) {
    use puressh::forwarding::socks;
    let target = match socks::handshake(&mut stream) {
        Ok(t) => t,
        Err(e) => {
            vlog(1, &format!("-R SOCKS handshake: {e}"));
            return;
        }
    };
    if !remote_open_permitted(permit, &target.host, target.port) {
        warn!(
            "Rejected connection to {} port {}: not permitted by PermitRemoteOpen",
            target.host, target.port
        );
        let _ = socks::write_reply(&mut stream, target.version, false);
        return;
    }
    match TcpStream::connect((target.host.as_str(), target.port)) {
        Ok(mut tcp) => {
            if socks::write_reply(&mut stream, target.version, true).is_err() {
                return;
            }
            // Anything the SOCKS client sent along with its request.
            let early = stream.take_buffered();
            if !early.is_empty() && tcp.write_all(&early).is_err() {
                return;
            }
            spawn_splice_to_tcp(stream, tcp);
        }
        Err(e) => {
            warn!(
                "connect to {} port {} failed: {e}",
                target.host, target.port
            );
            let _ = socks::write_reply(&mut stream, target.version, false);
        }
    }
}

/// A bound `-L` / `-D` listener, not yet accepting.
enum LocalListener {
    Tcp(TcpListener, LocalForward),
    #[cfg(unix)]
    Unix(std::os::unix::net::UnixListener, LocalForward),
    Socks(TcpListener, u16),
}

/// `-L` and `-D`: bind the local listeners (the bind address follows
/// `GatewayPorts`; loopback by default). They start accepting with
/// [`serve_local_listeners`], in the process that keeps the connection:
/// a ControlPersist master forks first, and its listening sockets go with
/// it while threads would not.
fn bind_local_forwards(
    cli: &Cli,
    dynamics: &[DynamicForward],
    gateway: puressh::config::GatewayPorts,
    exit_on_forward_failure: bool,
) -> Result<Vec<LocalListener>, String> {
    let mut out = Vec::new();
    for l in &cli.locals {
        let shown_to = match &l.connect_path {
            Some(p) => p.clone(),
            None => format!("{}:{}", l.remote_host, l.remote_port),
        };
        if let Some(path) = &l.listen_path {
            match bind_unix_listener(path) {
                Ok(listener) => {
                    vlog(1, &format!("-L {path}:{shown_to} active"));
                    #[cfg(unix)]
                    out.push(LocalListener::Unix(listener, l.clone()));
                    #[cfg(not(unix))]
                    let () = listener;
                }
                Err(e) => {
                    let msg = format!("unix_listener: cannot bind to path {path}: {e}");
                    if exit_on_forward_failure {
                        return Err(msg);
                    }
                    warn!("{msg}");
                }
            }
            continue;
        }
        // As OpenSSH's channel_fwd_bind_addr for the client: an address in
        // the spec is used as given (`*` or empty: all interfaces).
        let bind_ip = match l.bind_addr.as_deref() {
            None => resolve_bind_addr(gateway, None),
            Some("" | "*") => "0.0.0.0".to_string(),
            Some("localhost") => "127.0.0.1".to_string(),
            Some(a) => a.to_string(),
        };
        match TcpListener::bind((bind_ip.as_str(), l.listen_port)) {
            Ok(listener) => {
                vlog(
                    1,
                    &format!("-L {}:{}:{} active", bind_ip, l.listen_port, shown_to),
                );
                out.push(LocalListener::Tcp(listener, l.clone()));
            }
            Err(e) => {
                let msg = format!("bind [{bind_ip}]:{}: {e}", l.listen_port);
                if exit_on_forward_failure {
                    return Err(msg);
                }
                warn!("{msg}");
            }
        }
    }
    for d in dynamics {
        match TcpListener::bind((d.bind_addr.as_str(), d.listen_port)) {
            Ok(listener) => {
                vlog(
                    1,
                    &format!("-D {}:{} (SOCKS) active", d.bind_addr, d.listen_port),
                );
                out.push(LocalListener::Socks(listener, d.listen_port));
            }
            Err(e) => {
                let msg = format!("bind [{}]:{}: {e}", d.bind_addr, d.listen_port);
                if exit_on_forward_failure {
                    return Err(msg);
                }
                warn!("{msg}");
            }
        }
    }
    Ok(out)
}

/// Start accepting on the listeners [`bind_local_forwards`] bound.
fn serve_local_listeners(listeners: Vec<LocalListener>, shared: &puressh::shared::SharedClient) {
    for l in listeners {
        match l {
            LocalListener::Tcp(listener, spec) => {
                spawn_local_forward_listener(listener, spec, shared.clone(), None)
            }
            #[cfg(unix)]
            LocalListener::Unix(listener, spec) => {
                spawn_local_path_listener(listener, spec, shared.clone(), None)
            }
            LocalListener::Socks(listener, port) => {
                spawn_dynamic_forward_listener(listener, port, shared.clone(), None)
            }
        }
    }
}

/// Splice a `direct-tcpip` channel on the shared connection with a local TCP
/// connection, both ways, until either side closes.
fn splice_shared_with_tcp(
    shared: puressh::shared::SharedClient,
    mut stream: puressh::shared::OwnedChannelStream,
    tcp: impl Into<LocalConn>,
) {
    let tcp: LocalConn = tcp.into();
    let channel = stream.channel_id();
    let Ok(mut tcp_in) = tcp.try_clone() else {
        return;
    };
    let mut tcp_out = tcp;
    // TCP → channel.
    thread::spawn(move || {
        let mut buf = [0u8; 32 * 1024];
        loop {
            match tcp_in.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    if !send_all(&shared, channel, &buf[..n]) {
                        return;
                    }
                }
                Err(e) if e.kind() == ErrorKind::Interrupted => continue,
                Err(_) => break,
            }
        }
        let _ = shared.channel_send_eof(channel);
    });
    // Channel → TCP; dropping the stream closes the channel.
    thread::spawn(move || {
        let mut buf = [0u8; 32 * 1024];
        loop {
            match stream.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if tcp_out.write_all(&buf[..n]).is_err() {
                        break;
                    }
                }
            }
        }
        let _ = tcp_out.shutdown(std::net::Shutdown::Both);
    });
}

/// The session channel request for `ssh [-s] host [command]`.
fn session_request(command: Option<&str>, subsystem: bool) -> puressh::shared::SessionRequest<'_> {
    use puressh::shared::SessionRequest;
    match command {
        Some(c) if subsystem => SessionRequest::Subsystem(c),
        Some(c) => SessionRequest::Exec(c),
        None => SessionRequest::Shell,
    }
}

/// `ssh -f`: after authentication, keep going in a child process that
/// leaves the terminal's session. As OpenSSH's, the parent returns to the
/// shell only once the forwards and the control socket are set up
/// ([`background_ready`]): with status 0, or the child's own status if it
/// fails first (`ExitOnForwardFailure`) — so `ssh -fN -L …` returns with the
/// tunnel up.
#[cfg(unix)]
fn fork_to_background() -> Result<(), String> {
    use std::os::fd::{FromRawFd, OwnedFd};
    let mut fds = [0; 2];
    // SAFETY: pipe() fills the two-element array.
    if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0 {
        return Err(format!("pipe: {}", std::io::Error::last_os_error()));
    }
    // SAFETY: both descriptors were just created and are owned here.
    let (rd, wr) = unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) };
    // SAFETY: called while single-threaded (no session or forwarding threads
    // have been started); the child continues with ordinary Rust code.
    match unsafe { libc::fork() } {
        -1 => Err(format!("fork: {}", std::io::Error::last_os_error())),
        0 => {
            drop(rd);
            // SAFETY: setsid() in the child; failure is harmless.
            unsafe { libc::setsid() };
            if let Ok(mut g) = BACKGROUND_READY.lock() {
                *g = Some(std::fs::File::from(wr));
            }
            Ok(())
        }
        child => {
            drop(wr);
            let mut b = [0u8; 1];
            if matches!(std::fs::File::from(rd).read(&mut b), Ok(1)) {
                std::process::exit(0);
            }
            // The child ended before it was ready: its status is ours.
            let mut status = 0;
            // SAFETY: waiting for our own child.
            unsafe { libc::waitpid(child, &mut status, 0) };
            let code = if libc::WIFEXITED(status) {
                libc::WEXITSTATUS(status)
            } else {
                255
            };
            std::process::exit(code)
        }
    }
}

/// The `-f` child's end of the pipe its parent waits on.
#[cfg(unix)]
static BACKGROUND_READY: std::sync::Mutex<Option<std::fs::File>> = std::sync::Mutex::new(None);

/// Tell the parent of an `ssh -f` that the connection is set up, so it
/// returns to the shell (no-op otherwise, and after the first call).
fn background_ready() {
    #[cfg(unix)]
    if let Ok(mut g) = BACKGROUND_READY.lock()
        && let Some(mut f) = g.take()
    {
        let _ = f.write_all(b"1");
    }
}

/// `ssh -W host:port`: splice stdin/stdout with a `direct-tcpip` channel to
/// `host:port`. Exits 0 when the connection ends.
/// Whether OpenSSH's `ssh` would send `no-more-sessions@openssh.com` to a
/// server identifying itself as `ident`: its `SSH_NEW_OPENSSH` compat
/// flag (`compat.c`: any `OpenSSH*` software version but 2.x to 4.x,
/// since other implementations may abort on the request). puressh's sshd
/// honours it too.
fn server_honours_no_more_sessions(ident: &str) -> bool {
    // `SSH-protoversion-softwareversion SP comments`.
    let software = ident.splitn(3, '-').nth(2).unwrap_or("");
    if software.starts_with("puressh_") {
        return true;
    }
    for old in ["OpenSSH_2", "OpenSSH_3", "OpenSSH_4"] {
        if software.starts_with(old) {
            return false;
        }
    }
    software.starts_with("OpenSSH")
}

/// Send `no-more-sessions@openssh.com`, as OpenSSH does once its session
/// (if any) is open. A failure to send shows up on the next read.
fn send_no_more_sessions(shared: &puressh::shared::SharedClient) {
    vlog(1, "Requesting no-more-sessions@openssh.com");
    let _ = shared.no_more_sessions();
}

fn run_stdio_forward(client: Client, spec: &str, no_more_sessions: bool) -> Result<i32, String> {
    // host:port, [v6]:port, or host/port style is not accepted by OpenSSH.
    let (host, port) = if let Some(rest) = spec.strip_prefix('[') {
        let (h, p) = rest
            .split_once("]:")
            .ok_or_else(|| format!("-W: bad forwarding specification {spec:?}"))?;
        (h.to_string(), p)
    } else {
        let (h, p) = spec
            .rsplit_once(':')
            .ok_or_else(|| format!("-W: bad forwarding specification {spec:?}"))?;
        (h.to_string(), p)
    };
    let port: u16 = port
        .parse()
        .map_err(|_| format!("-W: bad port in {spec:?}"))?;
    let shared: puressh::shared::SharedClient = client.into();
    let mut stream = shared
        .open_stdio_forward(&host, port)
        .map_err(|e| format!("stdio forwarding failed: {e}"))?;
    if no_more_sessions {
        send_no_more_sessions(&shared);
    }
    let channel_id = stream.channel_id();
    let _ = shared.set_read_timeout(Some(std::time::Duration::from_millis(50)));
    let w = shared.clone();
    thread::spawn(move || {
        let mut buf = [0u8; 32 * 1024];
        let mut stdin = std::io::stdin();
        loop {
            match stdin.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    if !send_all(&w, channel_id, &buf[..n]) {
                        return;
                    }
                }
                Err(e) if e.kind() == ErrorKind::Interrupted => continue,
                Err(_) => break,
            }
        }
        let _ = w.channel_send_eof(channel_id);
    });
    let mut buf = [0u8; 32 * 1024];
    let mut stdout = std::io::stdout();
    loop {
        match stream.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                if stdout.write_all(&buf[..n]).is_err() {
                    break;
                }
                let _ = stdout.flush();
            }
        }
    }
    Ok(0)
}

// ---------------------------------------------------------------------------
// Connection multiplexing (ControlMaster / ControlPath / ControlPersist)
// ---------------------------------------------------------------------------

/// Resolved per-host mux settings (Unix-only honoring).
#[cfg(unix)]
struct MuxDecision {
    /// Concrete control-socket path (token/`~`-expanded, length-checked).
    path: PathBuf,
    /// The configured (or defaulted) ControlMaster role.
    master: puressh::config::ControlMaster,
    /// Whether this invocation should become the master after connecting
    /// (auto/yes, and no live master already present).
    become_master: bool,
    /// ControlPersist policy translated for the mux master.
    persist: puressh::mux::Persist,
}

/// The `%` tokens of ssh_config(5) for this connection.
#[derive(Clone)]
struct Tokens {
    /// `%n`: the host name as given.
    original: String,
    /// `%h`: the host connected to (after `HostName`).
    host: String,
    port: u16,
    /// `%r`: the remote user.
    remote_user: String,
    /// `%u`, `%i`, `%d`: the local user, uid and home directory.
    local_user: String,
    uid: String,
    home: String,
    /// `%l` / `%L`: the local host name, in full and up to the first dot.
    local_host: String,
    /// `%j`: the ProxyJump hops, or empty.
    jump: String,
    /// `%k`: HostKeyAlias, else the host name as given.
    key_alias: String,
}

impl Tokens {
    fn new(
        original: &str,
        host: &str,
        port: u16,
        remote_user: &str,
        cfg: &puressh::config::ClientOptions,
        cli: &Cli,
    ) -> Self {
        #[cfg(unix)]
        let (uid, pw_home) = {
            let uid = common::unix_sys::getuid();
            let home = common::unix_sys::passwd_entry(uid).map(|(_, dir)| dir);
            (uid.to_string(), home)
        };
        #[cfg(not(unix))]
        let (uid, pw_home) = (String::new(), None::<String>);
        let home = pw_home
            .or_else(|| std::env::var("HOME").ok())
            .or_else(|| std::env::var("USERPROFILE").ok())
            .unwrap_or_default();
        Tokens {
            original: original.to_string(),
            host: host.to_string(),
            port,
            remote_user: remote_user.to_string(),
            local_user: common::local_user_name().unwrap_or_default(),
            uid,
            home,
            #[cfg(unix)]
            local_host: puressh::mux::local_hostname(),
            #[cfg(not(unix))]
            local_host: std::env::var("COMPUTERNAME").unwrap_or_default(),
            jump: cli
                .proxy_jump
                .clone()
                .or_else(|| cfg.proxy_jump.clone())
                .filter(|j| !j.eq_ignore_ascii_case("none"))
                .unwrap_or_default(),
            key_alias: cfg
                .host_key_alias
                .clone()
                .unwrap_or_else(|| original.to_string()),
        }
    }

    /// `%C`: SHA-1 of `%l%h%p%r%j`, in hex (as `puressh::mux` computes it,
    /// which Windows builds lack).
    fn connection_hash(&self) -> String {
        use purecrypto::hash::{Digest, Sha1};
        let material = format!(
            "{}{}{}{}{}",
            self.local_host, self.host, self.port, self.remote_user, self.jump
        );
        Sha1::digest(material.as_bytes())
            .as_ref()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    }

    /// Expand `%C %d %h %i %j %k %L %l %n %p %r %u %%`; any other `%x` is
    /// left as written.
    fn expand(&self, s: &str) -> String {
        self.expand_with(s, &[])
    }

    /// [`Self::expand`], with `extra` tokens (`%t`, `%K`, …) as well.
    fn expand_with(&self, s: &str, extra: &[(char, &str)]) -> String {
        let mut out = String::with_capacity(s.len());
        let mut chars = s.chars();
        while let Some(c) = chars.next() {
            if c != '%' {
                out.push(c);
                continue;
            }
            let next = chars.next();
            if let Some((_, v)) = next.and_then(|c| extra.iter().find(|(k, _)| *k == c)) {
                out.push_str(v);
                continue;
            }
            match next {
                Some('%') => out.push('%'),
                Some('C') => out.push_str(&self.connection_hash()),
                Some('d') => out.push_str(&self.home),
                Some('h') => out.push_str(&self.host),
                Some('i') => out.push_str(&self.uid),
                Some('j') => out.push_str(&self.jump),
                Some('k') => out.push_str(&self.key_alias),
                Some('L') => out.push_str(self.local_host.split('.').next().unwrap_or("")),
                Some('l') => out.push_str(&self.local_host),
                Some('n') => out.push_str(&self.original),
                Some('p') => out.push_str(&self.port.to_string()),
                Some('r') => out.push_str(&self.remote_user),
                Some('u') => out.push_str(&self.local_user),
                Some(other) => {
                    out.push('%');
                    out.push(other);
                }
                None => out.push('%'),
            }
        }
        out
    }

    /// A file name as OpenSSH takes it: `~`, then `${VAR}`, then tokens.
    /// (`~` alone is the home directory with a `/`, as tilde_expand_filename.)
    fn expand_path(&self, s: &str) -> String {
        let s = if s == "~" {
            expand_tilde("~/")
        } else {
            expand_tilde(s)
        };
        self.expand(&expand_env(&s))
    }

    /// The directives `-G` prints expanded: UserKnownHostsFile, ControlPath,
    /// IdentityAgent, RevokedHostKeys, RemoteCommand.
    fn expand_options(&self, cfg: &mut puressh::config::ClientOptions) {
        if let Some(files) = &cfg.user_known_hosts {
            let expanded: Vec<String> = files
                .split_whitespace()
                .map(|f| self.expand_path(f))
                .collect();
            cfg.user_known_hosts = Some(expanded.join(" "));
        }
        for p in [&mut cfg.control_path, &mut cfg.revoked_host_keys]
            .into_iter()
            .flatten()
        {
            if !p.eq_ignore_ascii_case("none") {
                *p = self.expand_path(p);
            }
        }
        // An agent socket named by a variable (`SSH_AUTH_SOCK`, `$VAR`) is
        // read from the environment when used; `${VAR}` is expanded here.
        let names_variable =
            |p: &str| p == "SSH_AUTH_SOCK" || (p.starts_with('$') && !p.starts_with("${"));
        if let Some(puressh::config::IdentityAgent::Path(p)) = &mut cfg.identity_agent
            && !names_variable(p)
        {
            *p = self.expand_path(p);
        }
        if let Some(p) = &mut cfg.forward_agent_socket
            && !names_variable(p)
        {
            *p = self.expand_path(p);
        }
        if let Some(c) = &mut cfg.remote_command {
            *c = self.expand(c);
        }
        if let Some(v) = &mut cfg.version_addendum {
            *v = self.expand(&expand_env(v));
        }
        // SetEnv values (not the names).
        for (_, v) in cfg.set_env.iter_mut() {
            *v = self.expand(&expand_env(v));
        }
    }

    /// IdentityFile and CertificateFile, which `-G` prints as written.
    fn expand_paths(&self, cfg: &mut puressh::config::ClientOptions) {
        for p in cfg
            .identity_files
            .iter_mut()
            .chain(cfg.certificate_files.iter_mut())
        {
            *p = self.expand_path(p);
        }
    }
}

/// `Match exec`: run `cmd`, its tokens expanded from the options matched so
/// far, with the user's shell (stdin and stdout on /dev/null); exit status 0
/// is a match. As OpenSSH's expand_match_exec_or_include_path and
/// execute_in_shell.
fn match_exec(
    cmd: &str,
    opts: &puressh::config::ClientOptions,
    cli: &Cli,
    final_pass: bool,
) -> bool {
    let host = match &opts.host_name {
        Some(h) if final_pass => h.clone(),
        Some(h) => h
            .replace("%%", "\0")
            .replace("%h", &cli.host)
            .replace('\0', "%"),
        None => cli.host.clone(),
    };
    let port = cli.port.or(opts.port).unwrap_or(22);
    let ruser = cli
        .cli_user
        .clone()
        .or_else(|| cli.user_in_host.clone())
        .or_else(|| opts.user.clone())
        .or_else(common::local_user_name)
        .unwrap_or_default();
    let mut tokens = Tokens::new(&cli.host, &host, port, &ruser, opts, cli);
    tokens.key_alias = opts.host_key_alias.clone().unwrap_or_else(|| host.clone());
    let cmd = tokens.expand(cmd);
    #[cfg(unix)]
    let (shell, flag) = (
        std::env::var("SHELL")
            .ok()
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "/bin/sh".to_string()),
        "-c",
    );
    #[cfg(not(unix))]
    let (shell, flag) = ("cmd".to_string(), "/C");
    vlog(1, &format!("Executing command: '{cmd}'"));
    match std::process::Command::new(&shell)
        .arg(flag)
        .arg(&cmd)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .status()
    {
        Ok(st) => st.success(),
        Err(e) => {
            warn!("Unable to execute '{cmd}': {}", common::io_reason(&e));
            false
        }
    }
}

/// OpenSSH's ssh_valid_ruser: no control or shell-special characters, no
/// leading `-` (nor one after whitespace), no trailing `\\`.
fn valid_ruser(s: &str) -> bool {
    if s.starts_with('-') {
        return false;
    }
    let b = s.as_bytes();
    for (i, &c) in b.iter().enumerate() {
        if c.is_ascii_control() || b"'`\";&<>|(){}".contains(&c) {
            return false;
        }
        if c.is_ascii_whitespace() && b.get(i + 1) == Some(&b'-') {
            return false;
        }
        if c == b'\\' && i + 1 == b.len() {
            return false;
        }
    }
    true
}

/// OpenSSH's ssh_valid_hostname: no leading `-`, whitespace, control or
/// shell-special characters.
fn valid_hostname(s: &str) -> bool {
    !s.starts_with('-')
        && !s.bytes().any(|c| {
            c.is_ascii_whitespace() || c.is_ascii_control() || b"'`\"$\\;&<>|(){},".contains(&c)
        })
}

/// Run `KnownHostsCommand` for the server's key, as OpenSSH's
/// load_hostkeys_command: the template split into arguments (no shell),
/// each with the tokens expanded — `%H` the name looked up, `%I`
/// `HOSTNAME`, `%t` the key type, `%K` the key, `%f` its fingerprint —
/// and its output read as known_hosts lines. `None` if it fails.
fn known_hosts_command(
    template: &str,
    tokens: &Tokens,
    looked_up: &str,
    key_type: &str,
    blob: &[u8],
) -> Option<Vec<u8>> {
    let key = purecrypto::der::base64_encode(blob);
    let fp = common::fingerprint_b64_sha256(blob);
    let extra = [
        ('H', looked_up),
        ('I', "HOSTNAME"),
        ('t', key_type),
        ('K', key.as_str()),
        ('f', fp.as_str()),
    ];
    let argv: Vec<String> = split_command_args(template)
        .iter()
        .map(|a| tokens.expand_with(a, &extra))
        .collect();
    let (prog, args) = argv.split_first()?;
    vlog(
        1,
        &format!("Executing KnownHostsCommand: {}", argv.join(" ")),
    );
    match std::process::Command::new(prog)
        .args(args)
        .stdin(std::process::Stdio::null())
        .output()
    {
        Ok(out) if out.status.success() => Some(out.stdout),
        Ok(out) => {
            warn!("KnownHostsCommand {prog} failed, {}", out.status);
            None
        }
        Err(e) => {
            warn!("KnownHostsCommand {prog}: {}", common::io_reason(&e));
            None
        }
    }
}

/// Split a command line into arguments as OpenSSH's argv_split: on
/// whitespace, with `'…'` / `"…"` quoting and `\` escaping the next
/// character.
fn split_command_args(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut in_arg = false;
    let mut quote: Option<char> = None;
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        match (quote, c) {
            (_, '\\') => {
                if let Some(n) = chars.next() {
                    cur.push(n);
                }
                in_arg = true;
            }
            (Some(q), c) if c == q => quote = None,
            (Some(_), c) => cur.push(c),
            (None, '\'' | '"') => {
                quote = Some(c);
                in_arg = true;
            }
            (None, c) if c.is_whitespace() => {
                if in_arg {
                    out.push(core::mem::take(&mut cur));
                    in_arg = false;
                }
            }
            (None, c) => {
                cur.push(c);
                in_arg = true;
            }
        }
    }
    if in_arg {
        out.push(cur);
    }
    out
}

/// `${NAME}` environment references (OpenSSH expands them in file names);
/// an unset variable expands to nothing.
fn expand_env(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(i) = rest.find("${") {
        let Some(end) = rest[i + 2..].find('}') else {
            break;
        };
        out.push_str(&rest[..i]);
        out.push_str(&std::env::var(&rest[i + 2..i + 2 + end]).unwrap_or_default());
        rest = &rest[i + 3 + end..];
    }
    out.push_str(rest);
    out
}

/// Resolve ControlMaster/ControlPath/ControlPersist into a [`MuxDecision`].
/// Returns `Ok(None)` when multiplexing is disabled (no `ControlPath`, or
/// `ControlMaster no` with no path — i.e. nothing to do), and `Err` when the
/// expanded `ControlPath` is too long for a Unix socket address (OpenSSH:
/// `ControlPath too long`).
#[cfg(unix)]
fn resolve_mux(
    cfg_block: &puressh::config::ClientOptions,
    connect_host: &str,
    port: u16,
    user: &str,
) -> Result<Option<MuxDecision>, String> {
    use puressh::config::{ControlMaster, ControlPersist};
    let Some(template) = cfg_block.control_path.as_deref() else {
        return Ok(None);
    };
    let master = cfg_block.control_master.unwrap_or(ControlMaster::No);
    // ControlMaster no + a path still permits *attaching* as a client; only
    // skip entirely when there is no path. (Handled by the `?` above.)
    // Already expanded by `Tokens::expand_options`.
    let _ = (connect_host, port, user);
    let path = puressh::mux::socket_path_for(template).map_err(|e| format!("ControlPath: {e}"))?;
    let persist = match cfg_block.control_persist {
        Some(ControlPersist::No) | None => puressh::mux::Persist::No,
        Some(ControlPersist::Yes) => puressh::mux::Persist::Yes,
        Some(ControlPersist::Seconds(n)) => puressh::mux::Persist::Seconds(n),
        // A keyword value this binary predates: don't linger.
        Some(_) => puressh::mux::Persist::No,
    };
    // Become master only for auto/yes (the live-master check happens at the
    // call site; if a live master answered we'd have taken the client path).
    let become_master = matches!(master, ControlMaster::Auto | ControlMaster::Yes);
    Ok(Some(MuxDecision {
        path,
        master,
        become_master,
        persist,
    }))
}

/// Handle `ssh -O check|exit|stop`: talk to the master at `path` and report
/// on stderr, worded as OpenSSH's: `Master running (pid=N)`, `Exit request
/// sent.`, `Stop listening request sent.`; no master: `Control socket
/// connect(PATH): <reason>` and exit 255.
#[cfg(unix)]
fn run_control_command(cmd: &str, path: &std::path::Path, cli: &Cli) -> Result<i32, String> {
    use puressh::mux::ControlCommand;
    // Reach the master first: the error is OpenSSH's message when absent.
    let pid = match std::os::unix::net::UnixStream::connect(path) {
        Ok(s) => master_pid(&s),
        Err(e) => {
            let e = e.to_string();
            let e = e.split(" (os error").next().unwrap_or(&e).to_string();
            eprintln!("Control socket connect({}): {e}", path.display());
            return Ok(255);
        }
    };
    match cmd {
        "check" => {
            let alive = puressh::mux::send_control_command(path, ControlCommand::Check)
                .map_err(|e| format!("-O check: {e}"))?;
            if !alive {
                eprintln!(
                    "Control socket connect({}): Connection refused",
                    path.display()
                );
                return Ok(255);
            }
            match pid {
                Some(pid) => eprintln!("Master running (pid={pid})"),
                None => eprintln!("Master running"),
            }
            Ok(0)
        }
        "exit" | "stop" => {
            puressh::mux::send_control_command(path, ControlCommand::Exit)
                .map_err(|e| format!("-O {cmd}: {e}"))?;
            if !LOG_QUIET.load(std::sync::atomic::Ordering::Relaxed) {
                if cmd == "exit" {
                    eprintln!("Exit request sent.");
                } else {
                    eprintln!("Stop listening request sent.");
                }
            }
            Ok(0)
        }
        // As OpenSSH's mux client: the port the server chose for `-R 0:…` on
        // stdout; a refused forward ends `-O forward` with 255 (a refused
        // cancel is reported, then exits 0).
        "forward" | "cancel" => {
            let cancel = cmd == "cancel";
            for (kind, spec) in &cli.forward_specs {
                match puressh::mux::request_forward(path, *kind, spec, cancel) {
                    Ok(port) => {
                        if !cancel && port != 0 {
                            println!("{port}");
                        }
                    }
                    Err(e) => {
                        let reason = match e {
                            puressh::mux::MuxError::ForwardFailed(r) => r,
                            other => other.to_string(),
                        };
                        eprintln!("mux_client_forward: forwarding request failed: {reason}");
                        if cancel {
                            eprintln!("mux_client_request: master cancel forward request failed");
                            return Ok(0);
                        }
                        eprintln!("mux_client_request: master forward request failed");
                        return Ok(255);
                    }
                }
            }
            Ok(0)
        }
        "conninfo" => {
            let text = puressh::mux::conninfo(path).map_err(|e| format!("-O conninfo: {e}"))?;
            print!("{text}");
            Ok(0)
        }
        "channels" => {
            let text = puressh::mux::channels(path).map_err(|e| format!("-O channels: {e}"))?;
            print!("{text}");
            Ok(0)
        }
        other => Err(format!("-O: unsupported control command {other:?}")),
    }
}

/// Whether a client on the control socket may use the master: only our own
/// user or root, by peer credentials, as OpenSSH's master checks.
#[cfg(unix)]
fn mux_peer_allowed(sock: &std::os::unix::net::UnixStream) -> bool {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    let uid = {
        let mut cred: libc::ucred = unsafe { core::mem::zeroed() };
        peer_sockopt(sock, libc::SOL_SOCKET, libc::SO_PEERCRED, &mut cred).map(|()| cred.uid)
    };
    #[cfg(any(
        target_vendor = "apple",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "dragonfly"
    ))]
    let uid = {
        use std::os::fd::AsRawFd;
        let (mut uid, mut gid): (libc::uid_t, libc::gid_t) = (0, 0);
        // SAFETY: both out-pointers are valid for the call.
        (unsafe { libc::getpeereid(sock.as_raw_fd(), &mut uid, &mut gid) } == 0).then_some(uid)
    };
    #[cfg(not(any(
        target_os = "linux",
        target_os = "android",
        target_vendor = "apple",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "dragonfly"
    )))]
    let uid = {
        // No way to ask here: the owner-only socket is the access control.
        let _ = sock;
        return true;
    };
    // SAFETY: geteuid(2) cannot fail.
    uid.is_some_and(|u| u == 0 || u == unsafe { libc::geteuid() })
}

/// The master's process id, from the control socket's peer credentials.
#[cfg(unix)]
fn master_pid(sock: &std::os::unix::net::UnixStream) -> Option<i32> {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        let mut cred: libc::ucred = unsafe { core::mem::zeroed() };
        peer_sockopt(sock, libc::SOL_SOCKET, libc::SO_PEERCRED, &mut cred).map(|()| cred.pid)
    }
    #[cfg(target_vendor = "apple")]
    {
        let mut pid: libc::pid_t = 0;
        peer_sockopt(sock, libc::SOL_LOCAL, libc::LOCAL_PEERPID, &mut pid).map(|()| pid)
    }
    #[cfg(not(any(target_os = "linux", target_os = "android", target_vendor = "apple")))]
    {
        let _ = sock;
        None
    }
}

/// `getsockopt(level, name)` on `sock` into `out`, which must be the type
/// the option fills in, whole.
#[cfg(any(target_os = "linux", target_os = "android", target_vendor = "apple"))]
fn peer_sockopt<T>(
    sock: &std::os::unix::net::UnixStream,
    level: libc::c_int,
    name: libc::c_int,
    out: &mut T,
) -> Option<()> {
    use std::os::fd::AsRawFd;
    let mut len = core::mem::size_of::<T>() as libc::socklen_t;
    // SAFETY: `out` is a valid, writable `T` of `len` bytes for the call;
    // the caller passes the type the option is defined to fill in.
    let rc = unsafe {
        libc::getsockopt(
            sock.as_raw_fd(),
            level,
            name,
            (out as *mut T).cast(),
            &mut len,
        )
    };
    (rc == 0 && len as usize == core::mem::size_of::<T>()).then_some(())
}

/// Serve `-L` / `-D` listeners over a live ControlMaster: bind every local
/// and SOCKS listener, and for each accepted connection open an
/// `OPEN_DIRECT_TCPIP` control connection to the master, which dials the
/// destination over its SSH connection and splices the result back. Blocks
/// forever (Ctrl-C to quit), mirroring `ssh -N -L`/`-D`.
#[cfg(unix)]
fn run_mux_forwarding(
    cli: &Cli,
    dynamics: &[DynamicForward],
    path: &std::path::Path,
) -> Result<i32, String> {
    use puressh::forwarding::socks;

    let mut bound_any = false;

    // -L: each accepted TCP connection → one direct-tcpip forward to the
    // fixed remote_host:remote_port.
    for l in &cli.locals {
        if l.listen_path.is_some() || l.connect_path.is_some() {
            return Err(
                "Unix socket forwarding is not supported through a ControlMaster connection".into(),
            );
        }
        let bind_ip = "127.0.0.1";
        let listener = TcpListener::bind((bind_ip, l.listen_port))
            .map_err(|e| format!("-L bind {bind_ip}:{}: {e}", l.listen_port))?;
        vlog(
            1,
            &format!(
                "-L {}:{}:{} active (via ControlMaster)",
                l.listen_port, l.remote_host, l.remote_port
            ),
        );
        bound_any = true;
        let spec = l.clone();
        let mux_path = path.to_path_buf();
        thread::spawn(move || {
            for accept in listener.incoming() {
                let tcp = match accept {
                    Ok(s) => s,
                    Err(e) => {
                        eprintln!("ssh: -L accept on {bind_ip}:{}: {e}", spec.listen_port);
                        continue;
                    }
                };
                let orig = tcp
                    .peer_addr()
                    .map(|a| (a.ip().to_string(), a.port()))
                    .unwrap_or_else(|_| ("127.0.0.1".to_string(), 0));
                let mux_path = mux_path.clone();
                let spec = spec.clone();
                thread::spawn(move || {
                    match puressh::mux::open_forward(
                        &mux_path,
                        &spec.remote_host,
                        spec.remote_port,
                        &orig.0,
                        orig.1,
                    ) {
                        Ok(sock) => {
                            let _ = puressh::mux::splice_forward(sock, tcp);
                        }
                        Err(e) => eprintln!(
                            "ssh: -L direct-tcpip {}:{} over mux: {e}",
                            spec.remote_host, spec.remote_port
                        ),
                    }
                });
            }
        });
    }

    // -D: each accepted TCP connection runs the SOCKS handshake, then opens a
    // direct-tcpip forward to the SOCKS-requested target through the master.
    for d in dynamics {
        let listener = TcpListener::bind((d.bind_addr.as_str(), d.listen_port))
            .map_err(|e| format!("-D bind {}:{}: {e}", d.bind_addr, d.listen_port))?;
        eprintln!(
            "ssh: -D {}:{} (SOCKS) active (via ControlMaster)",
            d.bind_addr, d.listen_port
        );
        bound_any = true;
        let listen_port = d.listen_port;
        let mux_path = path.to_path_buf();
        thread::spawn(move || {
            for accept in listener.incoming() {
                let mut tcp = match accept {
                    Ok(s) => s,
                    Err(e) => {
                        eprintln!("ssh: -D accept on :{listen_port}: {e}");
                        continue;
                    }
                };
                let mux_path = mux_path.clone();
                thread::spawn(move || {
                    let target = match socks::handshake(&mut tcp) {
                        Ok(t) => t,
                        Err(e) => {
                            eprintln!("ssh: -D handshake: {e}");
                            return;
                        }
                    };
                    let orig = tcp
                        .peer_addr()
                        .map(|a| (a.ip().to_string(), a.port()))
                        .unwrap_or_else(|_| ("127.0.0.1".to_string(), 0));
                    match puressh::mux::open_forward(
                        &mux_path,
                        &target.host,
                        target.port,
                        &orig.0,
                        orig.1,
                    ) {
                        Ok(sock) => {
                            if socks::write_reply(&mut tcp, target.version, true).is_err() {
                                return;
                            }
                            let _ = puressh::mux::splice_forward(sock, tcp);
                        }
                        Err(e) => {
                            eprintln!(
                                "ssh: -D direct-tcpip {}:{} over mux: {e}",
                                target.host, target.port
                            );
                            let _ = socks::write_reply(&mut tcp, target.version, false);
                        }
                    }
                });
            }
        });
    }

    if !bound_any {
        return Err("mux forwarding: no -L or -D listeners to serve".into());
    }

    // Park forever: the listener threads do the work. OpenSSH's `-N` blocks
    // until interrupted; we mirror that.
    loop {
        thread::sleep(std::time::Duration::from_secs(3600));
    }
}

/// Attach to a live master at `path` and run the requested session over it.
#[cfg(unix)]
fn run_mux_client(
    cli: &Cli,
    cfg_block: &puressh::config::ClientOptions,
    path: &std::path::Path,
) -> Result<i32, String> {
    let env = build_session_env(cfg_block);
    // Same PTY rules as a direct connection.
    let (want_pty, term, cols, rows) = if want_pty(cli, cfg_block, cli.command.is_some(), false) {
        let (c, r, _, _) = query_window_size();
        (true, term_env(), c, r)
    } else {
        (false, String::new(), 0, 0)
    };
    let mut req = puressh::mux::SessionRequest::default();
    req.want_pty = want_pty;
    req.term = term;
    req.cols = cols;
    req.rows = rows;
    req.env = env;
    req.command = cli.command.clone();
    req.subsystem = cli.subsystem;

    // Put the local terminal in raw mode for an interactive PTY session so
    // keystrokes reach the remote unprocessed (mirrors the direct path).
    let _raw_guard = if want_pty {
        let mut t: libc::termios = unsafe { core::mem::zeroed() };
        if unsafe { libc::tcgetattr(0, &mut t) } == 0 {
            Some(common::TermiosRawGuard::install(&t))
        } else {
            None
        }
    } else {
        None
    };

    // Resize watcher only for PTY sessions.
    let resize: Option<Arc<dyn Fn() -> (u32, u32) + Send + Sync>> = if want_pty {
        Some(Arc::new(|| {
            let (c, r, _, _) = query_window_size();
            (c, r)
        }))
    } else {
        None
    };

    // The mux client writes the remote stderr to fd 2.
    common::restore_stderr();
    puressh::mux::run_client(path, &req, resize).map_err(|e| format!("mux client: {e}"))
}

/// `$TERM` with the usual `xterm` fallback.
#[cfg(unix)]
fn term_env() -> String {
    std::env::var("TERM").unwrap_or_else(|_| "xterm".to_string())
}

/// Become the ControlMaster and run this invocation's own session.
///
/// Under `ControlPersist no` the master is tied to the foreground session: we
/// stay in this process, bind the socket, serve clients, and run `foreground`
/// (the user's exec / shell) against the master's `SharedClient`. When it
/// returns, the master tears down and unlinks the socket.
///
/// Under `ControlPersist yes`/`<N>` we **daemonize**: `fork()`+`setsid()` move
/// the authenticated connection into an independent background process that
/// outlives this `ssh` invocation. The daemon child binds the socket and serves
/// clients ([`puressh::mux::run_master_daemon`]); the foreground (this process)
/// then runs its own session as an ordinary mux client over the control socket,
/// exactly like any later `ssh` to the same master. This is the OpenSSH model:
/// killing the launching `ssh` leaves the master (and any other attached
/// sessions) alive.
#[cfg(unix)]
fn become_master<F>(
    dec: &MuxDecision,
    cli: &Cli,
    cfg_block: &puressh::config::ClientOptions,
    shared: puressh::shared::SharedClient,
    start_serving: impl FnOnce(&puressh::shared::SharedClient),
    foreground: F,
    extras: MasterExtras,
) -> Result<i32, String>
where
    F: FnOnce(&puressh::shared::SharedClient) -> i32 + Send + 'static,
{
    // `-O exit` ends the master process, whatever its own session is doing
    // (status 255, as OpenSSH's client loop leaves it).
    let cfg = puressh::mux::MasterConfig::new(dec.path.clone(), dec.persist).with_on_exit(|| {
        if let Ok(g) = ORIGINAL_TERMIOS.lock()
            && let Some(t) = g.as_ref()
        {
            // SAFETY: restoring a termios captured from fd 0.
            unsafe { libc::tcsetattr(0, libc::TCSADRAIN, t) };
        }
        std::process::exit(255);
    });
    // `-O forward` / `-O cancel` / `-O conninfo`.
    let forwards = MuxForwards {
        shared: shared.clone(),
        routes: extras.routes,
        gateway: extras.gateway,
        listeners: Arc::default(),
    };
    let info_shared = shared.clone();
    let chan_shared = shared.clone();
    let started = extras.started;
    let cfg = cfg
        .with_on_forward(move |kind, spec, cancel| forwards.handle(kind, spec, cancel))
        .with_on_conninfo(move || connection_info(&info_shared, started))
        .with_on_channels(move || channel_list(&chan_shared))
        .with_peer_check(mux_peer_allowed);

    // ControlPersist no: master lives and dies with the foreground session in
    // this process. No daemonization.
    if matches!(dec.persist, puressh::mux::Persist::No) {
        vlog(
            1,
            &format!("mux: becoming master at {}", dec.path.display()),
        );
        start_serving(&shared);
        return puressh::mux::run_master(cfg, shared, foreground);
    }

    // ControlPersist yes/<N>: daemonize the master.
    vlog(
        1,
        &format!(
            "mux: becoming persistent master at {} (daemonizing)",
            dec.path.display()
        ),
    );
    daemonize_master(dec, cli, cfg_block, shared, cfg, start_serving)
}

/// What a ControlMaster needs besides the connection: where remote
/// forwards go, the GatewayPorts setting, and when it connected.
#[cfg(unix)]
struct MasterExtras {
    routes: RemoteRoutes,
    gateway: puressh::config::GatewayPorts,
    started: std::time::Instant,
}

/// The local and remote socket addresses of a direct TCP connection.
static CONN_ADDRS: std::sync::OnceLock<(String, String)> = std::sync::OnceLock::new();

/// The forwards a ControlMaster adds or removes for `ssh -O forward` /
/// `-O cancel`: remote ones on its connection, local listeners (stopped
/// through a flag, the listener woken by a connection to it).
#[cfg(unix)]
#[derive(Clone)]
struct MuxForwards {
    shared: puressh::shared::SharedClient,
    routes: RemoteRoutes,
    gateway: puressh::config::GatewayPorts,
    #[allow(clippy::type_complexity)]
    listeners: Arc<
        std::sync::Mutex<
            std::collections::BTreeMap<String, (Arc<std::sync::atomic::AtomicBool>, MuxWake)>,
        >,
    >,
}

/// How to wake a local listener's accept loop so it sees its stop flag.
#[cfg(unix)]
enum MuxWake {
    Tcp(std::net::SocketAddr),
    Path(PathBuf),
}

#[cfg(unix)]
impl MuxForwards {
    /// Cancel the `kind` forward listening as `listen` (`[bind:]port`, or the
    /// whole spec it was added with), as `~C -KL port` names it.
    fn cancel_listen(&self, kind: u8, listen: &str) -> Result<(), String> {
        if kind == b'R' {
            return self.handle(kind, listen, true).map(|_| ());
        }
        let prefix = format!("{}{listen}", kind as char);
        let key = self
            .listeners
            .lock()
            .ok()
            .and_then(|l| {
                l.keys()
                    .find(|k| **k == prefix || k.starts_with(&format!("{prefix}:")))
                    .cloned()
            })
            .ok_or("port not forwarded")?;
        self.handle(kind, &key[1..], true).map(|_| ())
    }

    fn handle(&self, kind: u8, spec: &str, cancel: bool) -> Result<u16, String> {
        let failed = |_: puressh::Error| "Port forwarding failed".to_string();
        let io_failed = |_: std::io::Error| "Port forwarding failed".to_string();
        match kind {
            b'R' => {
                let r = parse_remote_forward(spec)?;
                let dest = RemoteDest::of(&r);
                if let Some(path) = &r.listen_path {
                    if cancel {
                        self.shared
                            .cancel_streamlocal_forward(path)
                            .map_err(failed)?;
                        if let Ok(mut p) = self.routes.paths.lock() {
                            p.remove(path);
                        }
                    } else {
                        self.shared
                            .request_streamlocal_forward(path)
                            .map_err(failed)?;
                        if let Ok(mut p) = self.routes.paths.lock() {
                            p.insert(path.clone(), dest);
                        }
                    }
                    return Ok(0);
                }
                let bind = rfwd_bind_host(&r).to_string();
                if cancel {
                    self.shared
                        .cancel_tcpip_forward(&bind, r.remote_port)
                        .map_err(failed)?;
                    if let Ok(mut t) = self.routes.tcp.lock() {
                        t.remove(&(bind, r.remote_port));
                    }
                    return Ok(0);
                }
                let port = self
                    .shared
                    .request_tcpip_forward(&bind, r.remote_port)
                    .map_err(failed)?;
                if let Ok(mut t) = self.routes.tcp.lock() {
                    t.insert((bind, port), dest);
                }
                Ok(if r.remote_port == 0 { port } else { 0 })
            }
            b'L' | b'D' => {
                let key = format!("{}{spec}", kind as char);
                if cancel {
                    let (stop, wake) = self
                        .listeners
                        .lock()
                        .ok()
                        .and_then(|mut l| l.remove(&key))
                        .ok_or_else(|| "port not forwarded".to_string())?;
                    stop.store(true, std::sync::atomic::Ordering::SeqCst);
                    match wake {
                        MuxWake::Tcp(a) => {
                            let _ = TcpStream::connect(a);
                        }
                        MuxWake::Path(p) => {
                            let _ = std::os::unix::net::UnixStream::connect(&p);
                            let _ = std::fs::remove_file(&p);
                        }
                    }
                    return Ok(0);
                }
                let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
                let flag = Some(stop.clone());
                // A connection to a wildcard listener goes to loopback.
                let wake_addr = |l: &TcpListener| {
                    l.local_addr().ok().map(|mut a| {
                        if a.ip().is_unspecified() {
                            a.set_ip(std::net::Ipv4Addr::LOCALHOST.into());
                        }
                        MuxWake::Tcp(a)
                    })
                };
                let wake = if kind == b'L' {
                    let l = parse_local_forward(spec)?;
                    if let Some(path) = &l.listen_path {
                        let listener = bind_unix_listener(path).map_err(io_failed)?;
                        spawn_local_path_listener(listener, l.clone(), self.shared.clone(), flag);
                        MuxWake::Path(PathBuf::from(path))
                    } else {
                        let ip = match l.bind_addr.as_deref() {
                            None => resolve_bind_addr(self.gateway, None),
                            Some("" | "*") => "0.0.0.0".to_string(),
                            Some("localhost") => "127.0.0.1".to_string(),
                            Some(a) => a.to_string(),
                        };
                        let listener =
                            TcpListener::bind((ip.as_str(), l.listen_port)).map_err(io_failed)?;
                        let wake = wake_addr(&listener).ok_or("Port forwarding failed")?;
                        spawn_local_forward_listener(listener, l, self.shared.clone(), flag);
                        wake
                    }
                } else {
                    let d = parse_dynamic_forward(spec)?;
                    let ip = resolve_bind_addr(self.gateway, d.bind_addr.as_deref());
                    let listener =
                        TcpListener::bind((ip.as_str(), d.listen_port)).map_err(io_failed)?;
                    let wake = wake_addr(&listener).ok_or("Port forwarding failed")?;
                    spawn_dynamic_forward_listener(
                        listener,
                        d.listen_port,
                        self.shared.clone(),
                        flag,
                    );
                    wake
                };
                if let Ok(mut l) = self.listeners.lock() {
                    l.insert(key, (stop, wake));
                }
                Ok(0)
            }
            _ => Err("unknown forwarding type".into()),
        }
    }
}

/// `ssh -O conninfo` (and the `~I` escape): the connection, as OpenSSH's
/// connection_info_message describes it.
fn connection_info(shared: &puressh::shared::SharedClient, started: std::time::Instant) -> String {
    #[cfg(unix)]
    let host = puressh::mux::local_hostname();
    #[cfg(not(unix))]
    let host = std::env::var("COMPUTERNAME").unwrap_or_default();
    let mut out = format!(
        "Connection information for {host} pid {}\r\n",
        std::process::id()
    );
    if let Some((l, r)) = CONN_ADDRS.get() {
        out.push_str(&format!("  tcp {l} -> {r}\r\n"));
    }
    out.push_str(&format!(
        "  duration {}\r\n",
        fmt_timeframe(started.elapsed().as_secs())
    ));
    let dedupe = |a: &str, b: &str| {
        let a = if a.is_empty() { "<implicit>" } else { a };
        let b = if b.is_empty() { "<implicit>" } else { b };
        if a == b {
            a.to_string()
        } else {
            format!("{a} in, {b} out")
        }
    };
    if let Some(n) = shared.negotiated() {
        out.push_str(&format!("  kexalgorithm {}\r\n", n.kex));
        out.push_str(&format!("  hostkeyalgorithm {}\r\n", n.host_key));
        out.push_str(&format!(
            "  cipher {}\r\n",
            dedupe(&n.cipher_s2c, &n.cipher_c2s)
        ));
        out.push_str(&format!("  mac {}\r\n", dedupe(&n.mac_s2c, &n.mac_c2s)));
        out.push_str(&format!(
            "  compression {}\r\n",
            dedupe(&n.comp_s2c, &n.comp_c2s)
        ));
    }
    out.push_str("  rekey limit none interval none\r\n");
    if let Ok(t) = shared.traffic() {
        out.push_str(&format!(
            "  traffic {} pkts {} blks {}B in, {} pkts {} blks {}B out\r\n",
            t.packets_in,
            t.bytes_in / 16,
            fmt_scaled(t.bytes_in),
            t.packets_out,
            t.bytes_out / 16,
            fmt_scaled(t.bytes_out)
        ));
        if t.raw_in + t.raw_out > 0 {
            let ratio = |c: u64, r: u64| if r == 0 { 0.0 } else { c as f64 / r as f64 };
            out.push_str(&format!(
                "    compressed {}/{} (*{:.3}) in, {}/{} (*{:.3}) out\r\n",
                fmt_scaled(t.compressed_in),
                fmt_scaled(t.raw_in),
                ratio(t.compressed_in, t.raw_in),
                fmt_scaled(t.compressed_out),
                fmt_scaled(t.raw_out),
                ratio(t.compressed_out, t.raw_out)
            ));
        }
    }
    out
}

/// A duration as OpenSSH's fmt_timeframe: `HH:MM:SS`, `NdHHhMMm`, or
/// `NNwNdHHh`.
fn fmt_timeframe(secs: u64) -> String {
    let (sec, min, hrs) = (secs % 60, secs / 60 % 60, secs / 3600 % 24);
    let (day, week) = (secs / 86400 % 7, secs / 604800);
    if week > 0 {
        format!("{week:02}w{day}d{hrs:02}h")
    } else if day > 0 {
        format!("{day}d{hrs:02}h{min:02}m")
    } else {
        format!("{hrs:02}:{min:02}:{sec:02}")
    }
}

/// A byte count as OpenSSH's fmt_scaled: `512`, `1.5K`, `23M`, …
fn fmt_scaled(n: u64) -> String {
    if n < 1024 {
        return n.to_string();
    }
    let mut v = n as f64;
    for unit in ["K", "M", "G", "T", "P", "E"] {
        v /= 1024.0;
        if v < 1024.0 {
            return if v < 10.0 {
                format!("{v:.1}{unit}")
            } else {
                format!("{}{unit}", v.round() as u64)
            };
        }
    }
    format!("{}E", v.round() as u64)
}

/// Fork the authenticated connection into a detached daemon that owns the
/// ControlMaster, then run the foreground session in the parent as a mux
/// client over the freshly-bound control socket.
///
/// fd / Drop discipline: after `fork()` both processes share the SSH socket fd.
/// The **child** is the sole user of it (the master). The **parent** must never
/// touch the inherited `SharedClient` — dropping it would send channel/close
/// traffic on the shared socket and corrupt the daemon's connection — so we
/// `mem::forget` the parent's handle. The parent reaches the server only via
/// the control socket from here on.
#[cfg(unix)]
fn daemonize_master(
    dec: &MuxDecision,
    cli: &Cli,
    cfg_block: &puressh::config::ClientOptions,
    shared: puressh::shared::SharedClient,
    cfg: puressh::mux::MasterConfig,
    start_serving: impl FnOnce(&puressh::shared::SharedClient),
) -> Result<i32, String> {
    // SAFETY: the binary is outside the library's `forbid(unsafe_code)`. At
    // this point we are still single-threaded (no serve / I/O threads have
    // been spawned yet — `start_serving` and run_master_daemon start them in
    // the child), so fork() does not orphan any locks.
    match unsafe { libc::fork() } {
        -1 => Err(format!(
            "ControlPersist: fork failed: {}",
            std::io::Error::last_os_error()
        )),
        0 => {
            // --- Daemon master process ---
            // New session: detach from the controlling terminal so the master
            // is not killed when the launching shell / terminal goes away.
            // SAFETY: setsid(2) has no preconditions.
            let _ = unsafe { libc::setsid() };
            // An `ssh -f` parent waits on the launcher, not on this daemon.
            if let Ok(mut g) = BACKGROUND_READY.lock() {
                g.take();
            }
            // Detach stdio: the daemon must not hold the terminal's fds open
            // (that would wedge the parent's tty on exit) nor write to it.
            detach_stdio();
            start_serving(&shared);
            // Serve until the persist policy / `-O exit` tears us down. The
            // daemon never returns to `run()`; exit directly with its status.
            let code = match puressh::mux::run_master_daemon(cfg, shared) {
                Ok(()) => 0,
                Err(e) => {
                    // stderr is /dev/null now; nothing useful to print.
                    let _ = e;
                    1
                }
            };
            std::process::exit(code);
        }
        _ => {
            // --- Foreground (launcher) process ---
            // We must NOT run Drop on our copy of the connection: the daemon
            // owns the SSH socket now. Leak the handle deliberately. Our
            // copies of the forward listeners close: the daemon serves them.
            core::mem::forget(shared);
            drop(start_serving);

            // Wait for the daemon to bind + answer on the control socket.
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
            loop {
                if puressh::mux::probe_master(&dec.path) == puressh::mux::ProbeOutcome::Live {
                    break;
                }
                if std::time::Instant::now() >= deadline {
                    return Err(
                        "ControlPersist: daemon master did not come up on the control socket"
                            .into(),
                    );
                }
                std::thread::sleep(std::time::Duration::from_millis(20));
            }

            // `-N`: nothing more to do here; the daemon keeps the connection
            // and its forwards (OpenSSH backgrounds the master likewise).
            if cli.no_command {
                return Ok(0);
            }
            // Run our own session as a normal mux client over the daemon.
            run_mux_client(cli, cfg_block, &dec.path)
        }
    }
}

/// Redirect stdin/stdout/stderr to `/dev/null` for the daemon master, so it
/// neither reads from nor writes to the launcher's terminal.
#[cfg(unix)]
fn detach_stdio() {
    use std::os::fd::AsRawFd;
    if let Ok(devnull) = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/null")
    {
        let fd = devnull.as_raw_fd();
        // dup2 over 0/1/2. SAFETY: bin is outside the lib's forbid(unsafe);
        // these are plain POSIX dup2 calls on a valid fd.
        unsafe {
            libc::dup2(fd, 0);
            libc::dup2(fd, 1);
            libc::dup2(fd, 2);
        }
        // `devnull` (and its fd) drops here; the dup'd 0/1/2 stay open.
    }
}

/// True if stdin is a terminal. A PTY is only allocated automatically in
/// that case (matching OpenSSH when stdin is redirected from a file or a
/// pipe).
fn stdin_is_tty() -> bool {
    use std::io::IsTerminal;
    std::io::stdin().is_terminal()
}

/// `ObscureKeystrokeTiming` chaff tail: how long the cadence keeps emitting
/// chaff after the last keystroke before logging "chaff time expired". OpenSSH
/// uses a randomized duration; we use a modestly jittered ~1 s tail (the lib
/// stays deterministic — the jitter lives here in the binary, which may use
/// std). Spirit-equivalent: the cover outlasts a pause in typing.
#[cfg(unix)]
fn chaff_tail_ms() -> u32 {
    // Base 1000 ms ± up to ~256 ms of jitter, derived cheaply from the
    // process clock (no crypto-grade randomness needed for timing cover).
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    1000u32.saturating_add(now & 0xff)
}

/// Spawn the obfuscated stdin path: a blocking stdin reader that enqueues
/// keystrokes into a shared [`KeystrokeObfuscator`], plus a fixed-interval
/// cadence thread that releases queued data (or emits chaff `ping@openssh.com`
/// packets) so the on-wire rate is constant while typing. Returns the join
/// handles for both threads.
///
/// `stop` is the shared "remote shell exited" flag (set by the stdout reader);
/// once it trips and stdin has hit EOF, the cadence thread winds down.
#[cfg(unix)]
fn spawn_obfuscated_stdin(
    shared: &puressh::shared::SharedClient,
    channel_id: u32,
    okt: puressh::config::ObscureKeystrokeTiming,
    stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
) -> Vec<thread::JoinHandle<()>> {
    use std::sync::atomic::{AtomicBool, Ordering};

    let interval_ms = okt
        .interval_ms()
        .unwrap_or(puressh::config::ObscureKeystrokeTiming::DEFAULT_INTERVAL_MS)
        .max(1);
    let tail_ms = chaff_tail_ms();
    vlog(
        2,
        &format!("ObscureKeystrokeTiming enabled: interval ~{interval_ms}ms"),
    );

    let obf = std::sync::Arc::new(std::sync::Mutex::new(KeystrokeObfuscator::new(
        interval_ms,
        tail_ms,
    )));
    // Set once stdin reaches EOF so the cadence thread can flush remaining
    // queued bytes, send EOF to the remote, and exit.
    let stdin_eof = std::sync::Arc::new(AtomicBool::new(false));
    let start = std::time::Instant::now();

    // Reader thread: blocking stdin → obfuscator queue.
    let r_obf = obf.clone();
    let r_eof = stdin_eof.clone();
    let t_reader = thread::spawn(move || {
        let mut buf = [0u8; 8 * 1024];
        let mut stdin = std::io::stdin();
        loop {
            match stdin.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    let now = start.elapsed().as_millis() as u64;
                    if let Ok(mut g) = r_obf.lock() {
                        g.enqueue(&buf[..n], now);
                    }
                }
                Err(e) if e.kind() == ErrorKind::Interrupted => continue,
                Err(_) => break,
            }
        }
        r_eof.store(true, Ordering::Relaxed);
    });

    // Cadence thread: fixed-interval release of data / chaff.
    let c_shared = shared.clone();
    let c_obf = obf.clone();
    let c_stop = stop;
    let c_eof = stdin_eof;
    let t_cadence = thread::spawn(move || {
        let interval = std::time::Duration::from_millis(interval_ms as u64);
        loop {
            thread::sleep(interval);
            let now = start.elapsed().as_millis() as u64;
            let (action, started) = match c_obf.lock() {
                Ok(mut g) => {
                    let started = g.take_started_log();
                    (g.tick(now), started)
                }
                Err(_) => break,
            };
            if started {
                vlog(
                    2,
                    &format!("ObscureKeystrokeTiming starting: interval ~{interval_ms}ms"),
                );
            }
            match action {
                TickAction::SendData(chunk) => {
                    let mut off = 0;
                    while off < chunk.len() {
                        match c_shared.channel_send_data(channel_id, &chunk[off..]) {
                            Ok(0) | Err(_) => return,
                            Ok(taken) => off += taken,
                        }
                    }
                }
                TickAction::SendChaff => {
                    // Connection-level chaff: a PING the peer answers with a
                    // PONG (which our pump drops). Failure means the transport
                    // is gone — stop.
                    if c_shared.send_ping(b"").is_err() {
                        return;
                    }
                }
                TickAction::WindowExpired { chaff_sent } => {
                    vlog(
                        2,
                        &format!(
                            "ObscureKeystrokeTiming stopping: chaff time expired \
                             ({chaff_sent} chaff packets sent)"
                        ),
                    );
                }
                TickAction::Idle => {}
            }

            // Wind-down: once stdin hit EOF and the obfuscator has drained
            // (window closed, queue empty), half-close the write side and
            // exit. Also exit if the remote shell has gone away.
            if c_eof.load(Ordering::Relaxed) {
                let drained = c_obf.lock().map(|g| !g.window_open()).unwrap_or(true);
                if drained {
                    let _ = c_shared.channel_send_eof(channel_id);
                    return;
                }
            }
            if c_stop.load(Ordering::Relaxed) {
                return;
            }
        }
    });

    vec![t_reader, t_cadence]
}

/// OpenSSH escape sequences (`EscapeChar`, `~` by default) on the
/// interactive stdin stream: recognised only right after a newline.
struct EscapeFilter {
    ch: u8,
    at_line_start: bool,
    pending: bool,
}

/// What an escape sequence asks for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EscapeAction {
    /// `~.`: disconnect.
    Disconnect,
    /// `~?`: list the escapes.
    Help,
    /// `~^Z`: suspend ssh.
    Suspend,
    /// `~#`: list forwarded connections.
    ListForwards,
    /// `~V` / `~v`: more / less verbose.
    MoreVerbose,
    LessVerbose,
    /// `~I`: describe the connection.
    ConnInfo,
    /// `~B`: send a BREAK to the remote system.
    Break,
    /// `~R`: re-key the connection.
    Rekey,
    /// `~C`: the `ssh>` command line (`EnableEscapeCommandline yes`).
    CommandLine,
}

/// `EnableEscapeCommandline`: `~C` opens the command line.
static ESCAPE_CMDLINE: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// What `~C` adds forwards to and cancels them from (set once connected).
#[cfg(unix)]
static ESCAPE_FORWARDS: std::sync::OnceLock<MuxForwards> = std::sync::OnceLock::new();

/// What `~I` prints (set once the connection is up).
#[allow(clippy::type_complexity)]
static CONNINFO: std::sync::OnceLock<Box<dyn Fn() -> String + Send + Sync>> =
    std::sync::OnceLock::new();

impl EscapeFilter {
    fn new(ch: u8) -> Self {
        Self {
            ch,
            at_line_start: true,
            pending: false,
        }
    }

    /// Filter `input`: bytes to forward go to `out`; recognised escapes are
    /// returned in order (with the position in `out` where each occurred,
    /// so the caller can flush what precedes it first).
    fn feed(&mut self, input: &[u8], out: &mut Vec<u8>) -> Vec<(usize, EscapeAction)> {
        let mut actions = Vec::new();
        for &b in input {
            if self.pending {
                self.pending = false;
                let action = match b {
                    b'.' => Some(EscapeAction::Disconnect),
                    b'?' => Some(EscapeAction::Help),
                    0x1a => Some(EscapeAction::Suspend),
                    b'#' => Some(EscapeAction::ListForwards),
                    b'V' => Some(EscapeAction::MoreVerbose),
                    b'v' => Some(EscapeAction::LessVerbose),
                    b'I' => Some(EscapeAction::ConnInfo),
                    b'B' => Some(EscapeAction::Break),
                    b'R' => Some(EscapeAction::Rekey),
                    b'C' => Some(EscapeAction::CommandLine),
                    _ => None,
                };
                match action {
                    Some(a) => {
                        actions.push((out.len(), a));
                        // OpenSSH keeps treating the next byte as a line
                        // start after an escape.
                        self.at_line_start = true;
                        continue;
                    }
                    None if b == self.ch => {
                        // `~~` sends one escape character.
                        out.push(b);
                        self.at_line_start = false;
                        continue;
                    }
                    None => {
                        // Not an escape: send both bytes.
                        out.push(self.ch);
                    }
                }
            } else if self.at_line_start && b == self.ch {
                self.pending = true;
                continue;
            }
            out.push(b);
            self.at_line_start = b == b'\r' || b == b'\n';
        }
        actions
    }
}

/// The local terminal settings to restore when ssh exits or suspends from
/// an escape sequence (set while a raw-mode session runs).
#[cfg(unix)]
static ORIGINAL_TERMIOS: std::sync::Mutex<Option<libc::termios>> = std::sync::Mutex::new(None);

/// Carry out an escape action on behalf of the stdin thread, for the
/// session `channel` of `shared`.
fn run_escape(action: EscapeAction, ch: u8, shared: &puressh::shared::SharedClient, channel: u32) {
    let show = |c: u8| -> String {
        if c < 0x20 {
            format!("^{}", (c + b'@') as char)
        } else {
            (c as char).to_string()
        }
    };
    let e = show(ch);
    match action {
        EscapeAction::Disconnect => {
            #[cfg(unix)]
            if let Ok(g) = ORIGINAL_TERMIOS.lock()
                && let Some(t) = g.as_ref()
            {
                // SAFETY: restoring a termios captured from fd 0.
                unsafe { libc::tcsetattr(0, libc::TCSADRAIN, t) };
            }
            eprintln!("{e}.");
            std::process::exit(255);
        }
        EscapeAction::Help => {
            // OpenSSH's table (as a session that is not a mux client).
            let mut lines = vec![
                format!("{e}?"),
                "Supported escape sequences:".to_string(),
                format!(" {e}.   - terminate connection (and any multiplexed sessions)"),
                format!(" {e}B   - send a BREAK to the remote system"),
            ];
            if ESCAPE_CMDLINE.load(std::sync::atomic::Ordering::Relaxed) {
                lines.push(format!(" {e}C   - open a command line"));
            }
            lines.extend([
                format!(" {e}I   - show connection information"),
                format!(" {e}R   - request rekey"),
                format!(" {e}V/v - decrease/increase verbosity (LogLevel)"),
                format!(" {e}^Z  - suspend ssh"),
                format!(" {e}#   - list forwarded connections"),
                format!(" {e}&   - background ssh (when waiting for connections to terminate)"),
                format!(" {e}?   - this message"),
                format!(" {e}{e}   - send the escape character by typing it twice"),
                "(Note that escapes are only recognized immediately after newline.)".to_string(),
            ]);
            for l in lines {
                eprint!("{l}\r\n");
            }
        }
        EscapeAction::CommandLine => {
            if !ESCAPE_CMDLINE.load(std::sync::atomic::Ordering::Relaxed) {
                eprint!("commandline disabled\r\n");
            } else {
                #[cfg(unix)]
                escape_command_line();
            }
        }
        EscapeAction::Break => {
            eprint!("{e}B\r\n");
            let _ = shared.send_break(channel, 1000);
        }
        EscapeAction::Rekey => {
            eprint!("{e}R\r\n");
            let _ = shared.rekey();
        }
        EscapeAction::ListForwards => {
            eprint!("{}", channel_list(shared));
        }
        EscapeAction::ConnInfo => {
            eprint!("{e}I\r\n");
            if let Some(f) = CONNINFO.get() {
                eprint!("{}", f());
            }
        }
        EscapeAction::MoreVerbose => {
            set_verbose(common::verbose_level().saturating_add(1));
            eprint!("[verbosity {}]\r\n", common::verbose_level());
        }
        EscapeAction::LessVerbose => {
            set_verbose(common::verbose_level().saturating_sub(1));
            eprint!("[verbosity {}]\r\n", common::verbose_level());
        }
        EscapeAction::Suspend => {
            #[cfg(unix)]
            {
                let original = ORIGINAL_TERMIOS.lock().ok().and_then(|g| *g);
                // SAFETY: plain termios calls on fd 0 and a raise() of a
                // stop signal; the raw settings are read back first so they
                // can be re-applied on resume.
                unsafe {
                    let mut raw: libc::termios = core::mem::zeroed();
                    let have_raw = libc::tcgetattr(0, &mut raw) == 0;
                    if let Some(t) = original {
                        libc::tcsetattr(0, libc::TCSADRAIN, &t);
                    }
                    eprintln!("{e}^Z [suspend ssh]");
                    libc::raise(libc::SIGTSTP);
                    if have_raw {
                        libc::tcsetattr(0, libc::TCSADRAIN, &raw);
                    }
                }
            }
        }
    }
}

/// This connection's binding for agent connections (set once connected).
#[cfg(unix)]
static SESSION_BINDING: std::sync::OnceLock<puressh::client::SessionBinding> =
    std::sync::OnceLock::new();

/// Each `auth-agent@openssh.com` channel the server opens: a new connection
/// to the agent at `path`, bound to the session as a forwarding one (as
/// OpenSSH's), spliced to the channel.
#[cfg(unix)]
fn forwarded_agent_callback(
    path: PathBuf,
) -> Arc<dyn Fn(puressh::stream::ChannelStream) + Send + Sync + 'static> {
    Arc::new(move |stream| match puressh::agent::Agent::connect(&path) {
        Ok(mut agent) => {
            if let Some(b) = SESSION_BINDING.get() {
                let _ = agent.bind_session(&b.host_key, &b.session_id, &b.signature, true);
            }
            puressh::forwarding::agent::splice_unix_stream(agent.into_stream(), stream);
        }
        // The agent went away: dropping the channel closes it.
        Err(_) => drop(stream),
    })
}

/// `~C`: read an `ssh>` command line from the terminal (cooked mode, as
/// OpenSSH's) and add or cancel a forward on the connection.
#[cfg(unix)]
fn escape_command_line() {
    use std::io::BufRead;
    let original = ORIGINAL_TERMIOS.lock().ok().and_then(|g| *g);
    // SAFETY: plain termios calls on fd 0; the raw settings are read back
    // first so they can be re-applied afterwards.
    let mut raw: libc::termios = unsafe { core::mem::zeroed() };
    let have_raw = unsafe { libc::tcgetattr(0, &mut raw) } == 0;
    if let Some(t) = original {
        unsafe { libc::tcsetattr(0, libc::TCSADRAIN, &t) };
    }
    eprint!("\r\nssh> ");
    let mut line = String::new();
    let read = std::fs::File::open("/dev/tty")
        .map(|f| std::io::BufReader::new(f).read_line(&mut line))
        .is_ok();
    if have_raw {
        unsafe { libc::tcsetattr(0, libc::TCSADRAIN, &raw) };
    }
    if read {
        for msg in run_command_line(line.trim()) {
            eprint!("{msg}\r\n");
        }
    }
}

/// Carry out one `~C` command (OpenSSH's process_cmdline); what to print.
#[cfg(unix)]
fn run_command_line(line: &str) -> Vec<String> {
    let s = line.trim_start();
    let s = s.strip_prefix('-').unwrap_or(s);
    let Some(first) = s.chars().next() else {
        return Vec::new();
    };
    if matches!(first, 'h' | 'H' | '?') {
        return [
            "Commands:",
            "      -L[bind_address:]port:host:hostport    Request local forward",
            "      -R[bind_address:]port:host:hostport    Request remote forward",
            "      -D[bind_address:]port                  Request dynamic forward",
            "      -KL[bind_address:]port                 Cancel local forward",
            "      -KR[bind_address:]port                 Cancel remote forward",
            "      -KD[bind_address:]port                 Cancel dynamic forward",
        ]
        .map(String::from)
        .to_vec();
    }
    let (cancel, s) = match s.strip_prefix('K') {
        Some(rest) => (true, rest),
        None => (false, s),
    };
    let kind = match s.chars().next() {
        Some('L') => b'L',
        Some('R') => b'R',
        Some('D') => b'D',
        _ => return vec!["Invalid command.".into()],
    };
    let spec = s[1..].trim();
    let Some(forwards) = ESCAPE_FORWARDS.get() else {
        return vec!["Port forwarding failed.".into()];
    };
    if cancel {
        match forwards.cancel_listen(kind, spec) {
            Ok(()) => vec!["Canceled forwarding.".into()],
            Err(_) => vec!["Unknown port forwarding.".into()],
        }
    } else {
        let parses = match kind {
            b'L' => parse_local_forward(spec).is_ok(),
            b'D' => parse_dynamic_forward(spec).is_ok(),
            _ => parse_remote_forward(spec).is_ok(),
        };
        if !parses {
            let what = if kind == b'R' { "remote" } else { "local" };
            return vec![format!("Bad {what} forwarding specification.")];
        }
        match forwards.handle(kind, spec, false) {
            Ok(_) => vec!["Forwarding port.".into()],
            Err(_) => vec!["Port forwarding failed.".into()],
        }
    }
}

/// Send `data` on the session channel, retrying partial writes. `false` once
/// the channel is gone.
fn send_all(shared: &puressh::shared::SharedClient, channel: u32, data: &[u8]) -> bool {
    let mut off = 0;
    while off < data.len() {
        match shared.channel_send_data(channel, &data[off..]) {
            Ok(0) | Err(_) => return false,
            Ok(n) => off += n,
        }
    }
    true
}

/// Run one session channel the way OpenSSH's `ssh` does, streaming in both
/// directions: stdin → channel (EOF forwarded), channel stdout → stdout,
/// channel stderr → stderr, until the remote side closes. With `want_pty`
/// a pseudo-terminal is requested (with the local terminal's size and
/// modes); if stdin is a terminal it is put in raw mode, window resizes
/// are forwarded, and `escape` (normally `~`) sequences are honoured.
/// Returns the remote exit status (255 when there is none, e.g. the
/// command was killed by a signal).
fn run_session(
    shared: &puressh::shared::SharedClient,
    what: puressh::shared::SessionRequest<'_>,
    want_pty: bool,
    pty_required: bool,
    okt: puressh::config::ObscureKeystrokeTiming,
    escape: Option<u8>,
    no_more_sessions: bool,
) -> Result<i32, String> {
    use std::sync::atomic::{AtomicBool, Ordering};

    #[cfg(unix)]
    let stdin_tty = stdin_is_tty();
    #[cfg(unix)]
    let interactive = want_pty && stdin_tty;

    // Terminal: size, modes, raw mode (only when stdin is a terminal).
    #[cfg(unix)]
    let (pty, mut raw_guard) = {
        if want_pty {
            let (cols, rows, px_w, px_h) = query_window_size();
            let term = std::env::var("TERM").unwrap_or_else(|_| "xterm".to_string());
            // SAFETY: zero-initialised termios filled by tcgetattr on fd 0.
            let mut original: libc::termios = unsafe { core::mem::zeroed() };
            let have = stdin_tty && unsafe { libc::tcgetattr(0, &mut original) } == 0;
            let mut req = puressh::shared::PtyRequest::new(term, cols, rows);
            req.px_w = px_w;
            req.px_h = px_h;
            if have {
                req.modes = puressh::client::encode_termios_modes(&original);
                if let Ok(mut g) = ORIGINAL_TERMIOS.lock() {
                    *g = Some(original);
                }
            }
            let guard = have.then(|| common::TermiosRawGuard::install(&original));
            (Some(req), guard)
        } else {
            (None, None)
        }
    };
    #[cfg(not(unix))]
    let pty = want_pty.then(|| puressh::shared::PtyRequest::new("xterm", 80, 24));

    let stream = shared.session_stream(what, pty).map_err(|e| match e {
        // OpenSSH's report of a refused shell / exec / subsystem.
        puressh::Error::Protocol(m) if m.ends_with("request failed") => {
            eprintln!("{m} on channel 0");
            String::new()
        }
        e => e.to_string(),
    })?;
    // Our one session is open: no other may follow.
    if no_more_sessions {
        send_no_more_sessions(shared);
    }
    let channel_id = stream.channel_id();
    MAIN_SESSION.store(channel_id, std::sync::atomic::Ordering::Relaxed);
    if stream.pty_denied() {
        // As OpenSSH: say so and leave raw mode; a terminal asked for with
        // -t / RequestTTY yes|force is required, else carry on without.
        #[cfg(unix)]
        drop(raw_guard.take());
        eprintln!("PTY allocation request failed on channel {channel_id}");
        if pty_required {
            return Err(String::new());
        }
    }
    // A short read timeout makes the stdout pump release the SharedClient
    // lock regularly, so the stdin writer and resize threads get through.
    let _ = shared.set_read_timeout(Some(std::time::Duration::from_millis(50)));

    let done = Arc::new(AtomicBool::new(false));
    // As OpenSSH: escapes work whenever the session has a terminal (`-tt`
    // with a pipe on stdin included).
    let escape = if want_pty && !stream.pty_denied() {
        escape
    } else {
        None
    };

    // stdin → channel.
    #[cfg(unix)]
    let use_okt = interactive && okt.is_on() && escape.is_none();
    #[cfg(not(unix))]
    let use_okt = false;
    let _t_in: Vec<thread::JoinHandle<()>> = if use_okt {
        #[cfg(unix)]
        {
            spawn_obfuscated_stdin(shared, channel_id, okt, done.clone())
        }
        #[cfg(not(unix))]
        unreachable!()
    } else {
        let _ = okt;
        let w = shared.clone();
        vec![thread::spawn(move || {
            let mut filter = escape.map(EscapeFilter::new);
            let mut buf = [0u8; 16 * 1024];
            let mut out = Vec::with_capacity(16 * 1024);
            let mut stdin = std::io::stdin();
            loop {
                match stdin.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => match filter.as_mut() {
                        None => {
                            if !send_all(&w, channel_id, &buf[..n]) {
                                return;
                            }
                        }
                        Some(f) => {
                            out.clear();
                            let actions = f.feed(&buf[..n], &mut out);
                            let mut sent = 0;
                            for (at, action) in actions {
                                if !send_all(&w, channel_id, &out[sent..at]) {
                                    return;
                                }
                                sent = at;
                                run_escape(action, f.ch, &w, channel_id);
                            }
                            if !send_all(&w, channel_id, &out[sent..]) {
                                return;
                            }
                        }
                    },
                    Err(e) if e.kind() == ErrorKind::Interrupted => continue,
                    Err(_) => break,
                }
            }
            // Half-close: the remote command sees EOF on its stdin.
            let _ = w.channel_send_eof(channel_id);
        })]
    };

    // channel → stdout (owns the stream).
    let (stream_tx, stream_rx) = std::sync::mpsc::channel::<puressh::shared::OwnedChannelStream>();
    let out_done = done.clone();
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
        // EOF can come before the exit status (OpenSSH's server sends it
        // first for a command that printed nothing): wait for it, as ssh
        // waits for the channel to close.
        let _ = stream.wait_exit_status(None);
        out_done.store(true, Ordering::Relaxed);
        let _ = stream_tx.send(stream);
    });

    // channel stderr → stderr.
    let err_shared = shared.clone();
    let t_err = thread::spawn(move || {
        let mut buf = [0u8; 32 * 1024];
        let mut stderr = common::remote_stderr();
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

    // Window resizes.
    #[cfg(unix)]
    let _t_winch = interactive.then(|| {
        static RESIZED: AtomicBool = AtomicBool::new(false);
        extern "C" fn on_winch(_sig: libc::c_int) {
            RESIZED.store(true, Ordering::Relaxed);
        }
        // SAFETY: the handler only stores into an AtomicBool.
        unsafe {
            libc::signal(libc::SIGWINCH, on_winch as *const () as libc::sighandler_t);
        }
        let s = shared.clone();
        let stop = done.clone();
        thread::spawn(move || {
            while !stop.load(Ordering::Relaxed) {
                thread::sleep(std::time::Duration::from_millis(100));
                if RESIZED.swap(false, Ordering::Relaxed) {
                    let (cols, rows, px_w, px_h) = query_window_size();
                    let _ = s.send_window_change(channel_id, cols, rows, px_w, px_h);
                }
            }
        })
    });

    // The remote side closing stdout ends the session. The stdin thread
    // may still be blocked reading a terminal; it is not joined (the
    // process exits right after).
    let _ = t_out.join();
    let _ = t_err.join();
    let stream = stream_rx
        .recv_timeout(std::time::Duration::from_secs(1))
        .ok();
    Ok(stream.and_then(|s| s.exit_status()).unwrap_or(255))
}

/// Query the local terminal's size via `TIOCGWINSZ` on fd 0. Returns
/// `(cols, rows, px_w, px_h)`. Falls back to `(80, 24, 0, 0)` if the
/// ioctl fails.
#[cfg(unix)]
fn query_window_size() -> (u32, u32, u32, u32) {
    let mut ws: libc::winsize = unsafe { core::mem::zeroed() };
    let ok = unsafe { libc::ioctl(0, libc::TIOCGWINSZ, &mut ws) } == 0;
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
/// Each direction runs on its own thread: the local side's EOF is sent as
/// the channel's, the channel's EOF half-closes the socket, and Close
/// follows once both directions are done. Mirrors `forwarding::reverse::spawn_splice`
/// but for the client side.
fn spawn_splice_to_tcp(stream: ChannelStream, tcp: impl Into<LocalConn>) {
    use puressh::client::ChannelEgress;
    let tcp: LocalConn = tcp.into();
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
        // EOF from the channel half-closes the socket (the local side may
        // still answer, and closes it in the end); the channel going away,
        // or a failed write, ends both directions.
        let closed = loop {
            match chan_rx.recv() {
                Ok(Some(chunk)) => {
                    if tcp_out_b.write_all(&chunk).is_err() {
                        break true;
                    }
                }
                Ok(None) => break false,
                Err(_) => break true,
            }
        };
        let _ = tcp_out_b.shutdown(if closed {
            std::net::Shutdown::Both
        } else {
            std::net::Shutdown::Write
        });
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
        // A keyword value this binary predates: stay on loopback.
        _ => "127.0.0.1".to_string(),
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
    let timeout = connect_timeout(cfg_block);

    // Try each candidate address until one connects; `ConnectionAttempts`
    // rounds, a second apart, as in OpenSSH.
    let mut last_err: Option<std::io::Error> = None;
    let attempts = cfg_block.connection_attempts.unwrap_or(1).max(1);
    for attempt in 0..attempts {
        if attempt > 0 {
            std::thread::sleep(std::time::Duration::from_secs(1));
        }
        for addr in resolve_addrs(host, port, cfg_block)? {
            let bind = (
                cfg_block.bind_address.as_deref(),
                cfg_block.bind_interface.as_deref(),
            );
            let sock = match connect_from(addr, bind, timeout) {
                Ok(s) => s,
                Err(e) => {
                    last_err = Some(e);
                    continue;
                }
            };
            configure_socket(&sock, cfg_block)?;
            return Ok(sock);
        }
    }
    Err(match last_err {
        Some(e) => format!(
            "connect to host {host} port {port}: {}",
            common::io_reason(&e)
        ),
        None => format!("connect to host {host} port {port}: no address"),
    })
}

/// `ConnectTimeout` as a `Duration`.
fn connect_timeout(cfg_block: &puressh::config::ClientOptions) -> Option<std::time::Duration> {
    cfg_block
        .connect_timeout
        .filter(|s| *s > 0)
        .map(|s| std::time::Duration::from_secs(s as u64))
}

/// Resolve `host:port`, keeping only the `AddressFamily` the config allows.
fn resolve_addrs(
    host: &str,
    port: u16,
    cfg_block: &puressh::config::ClientOptions,
) -> Result<Vec<std::net::SocketAddr>, String> {
    use puressh::config::AddressFamily;
    use std::net::ToSocketAddrs;

    let family = cfg_block.address_family.unwrap_or(AddressFamily::Any);
    let addrs: Vec<std::net::SocketAddr> = (host, port)
        .to_socket_addrs()
        .map_err(|e| format!("resolve {host}:{port}: {e}"))?
        .filter(|a| match family {
            AddressFamily::Any => true,
            AddressFamily::Inet => a.is_ipv4(),
            AddressFamily::Inet6 => a.is_ipv6(),
            // A family this binary predates: don't filter.
            _ => true,
        })
        .collect();
    if addrs.is_empty() {
        return Err(format!(
            "no addresses for {host}:{port} in the requested address family"
        ));
    }
    Ok(addrs)
}

/// Socket options applied to every connected SSH socket.
fn configure_socket(
    sock: &TcpStream,
    cfg_block: &puressh::config::ClientOptions,
) -> Result<(), String> {
    // TCPKeepAlive: default yes (OpenSSH default). Only set SO_KEEPALIVE
    // off when explicitly disabled.
    if cfg_block.tcp_keep_alive != Some(false) {
        set_so_keepalive(sock, true)?;
    }
    let _ = sock.set_nodelay(true);
    // IPQoS: the interactive value until the session says otherwise
    // (`set_session_qos`).
    let (interactive, bulk) = cfg_block.ip_qos.unwrap_or(DEFAULT_IPQOS);
    set_sock_tos(sock, interactive);
    if let Ok(clone) = sock.try_clone()
        && let Ok(mut g) = QOS_SOCKET.lock()
    {
        *g = Some((clone, interactive, bulk));
    }
    Ok(())
}

/// The connection's socket and its `IPQoS` values (interactive, bulk), for
/// [`set_session_qos`].
static QOS_SOCKET: std::sync::Mutex<Option<(TcpStream, u32, u32)>> = std::sync::Mutex::new(None);

/// `IPQoS` once the session is known: the interactive value for a terminal
/// session, the bulk one otherwise (OpenSSH's `ssh_packet_set_interactive`).
fn set_session_qos(interactive: bool) {
    if let Ok(g) = QOS_SOCKET.lock()
        && let Some((sock, i, b)) = g.as_ref()
    {
        vlog(
            2,
            &format!(
                "session QoS is now {}",
                if interactive {
                    "interactive"
                } else {
                    "non-interactive"
                }
            ),
        );
        set_sock_tos(sock, if interactive { *i } else { *b });
    }
}

/// Set the socket's TOS (IPv4) or traffic class (IPv6); `IPQOS_NONE`
/// leaves the system default.
#[cfg(unix)]
fn set_sock_tos(sock: &TcpStream, tos: u32) {
    use std::os::unix::io::AsRawFd;
    if tos == puressh::config::IPQOS_NONE {
        return;
    }
    let (level, name) = match sock.local_addr() {
        Ok(a) if a.is_ipv4() => (libc::IPPROTO_IP, libc::IP_TOS),
        #[cfg(any(target_os = "linux", target_os = "android", target_vendor = "apple"))]
        Ok(_) => (libc::IPPROTO_IPV6, libc::IPV6_TCLASS),
        _ => return,
    };
    let val = tos as libc::c_int;
    // SAFETY: setsockopt on a valid fd with a correctly-sized int.
    let rc = unsafe {
        libc::setsockopt(
            sock.as_raw_fd(),
            level,
            name,
            &val as *const _ as *const libc::c_void,
            core::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if rc != 0 {
        vlog(
            1,
            &format!(
                "setsockopt IP_TOS {tos}: {}",
                std::io::Error::last_os_error()
            ),
        );
    }
}

#[cfg(not(unix))]
fn set_sock_tos(_sock: &TcpStream, _tos: u32) {}

/// `BindInterface`: an address of interface `ifname` in the family asked
/// for, preferring one that is neither loopback nor link-local (OpenSSH's
/// `check_ifaddrs`).
#[cfg(unix)]
fn interface_address(ifname: &str, v4: bool) -> Option<std::net::IpAddr> {
    let mut list: *mut libc::ifaddrs = core::ptr::null_mut();
    // SAFETY: getifaddrs fills `list`, released by freeifaddrs below.
    if unsafe { libc::getifaddrs(&mut list) } != 0 {
        return None;
    }
    let mut found: Vec<std::net::IpAddr> = Vec::new();
    let mut cur = list;
    while !cur.is_null() {
        // SAFETY: `cur` walks the list getifaddrs returned.
        let ifa = unsafe { &*cur };
        cur = ifa.ifa_next;
        if ifa.ifa_addr.is_null()
            || ifa.ifa_name.is_null()
            || ifa.ifa_flags & (libc::IFF_UP as libc::c_uint) == 0
        {
            continue;
        }
        // SAFETY: a NUL-terminated interface name.
        let name = unsafe { std::ffi::CStr::from_ptr(ifa.ifa_name) };
        if name.to_bytes() != ifname.as_bytes() {
            continue;
        }
        // SAFETY: the address is a sockaddr of the family it says.
        let family = i32::from(unsafe { (*ifa.ifa_addr).sa_family });
        if v4 && family == libc::AF_INET {
            let sa = unsafe { &*(ifa.ifa_addr as *const libc::sockaddr_in) };
            found.push(std::net::IpAddr::from(sa.sin_addr.s_addr.to_ne_bytes()));
        } else if !v4 && family == libc::AF_INET6 {
            let sa = unsafe { &*(ifa.ifa_addr as *const libc::sockaddr_in6) };
            found.push(std::net::IpAddr::from(sa.sin6_addr.s6_addr));
        }
    }
    // SAFETY: the list from getifaddrs above.
    unsafe { libc::freeifaddrs(list) };
    let local = |a: &std::net::IpAddr| match a {
        std::net::IpAddr::V4(a) => a.is_loopback(),
        std::net::IpAddr::V6(a) => a.is_loopback() || (a.segments()[0] & 0xffc0) == 0xfe80,
    };
    found
        .iter()
        .find(|a| !local(a))
        .or_else(|| found.first())
        .copied()
}

#[cfg(not(unix))]
fn interface_address(_ifname: &str, _v4: bool) -> Option<std::net::IpAddr> {
    eprintln!("BindInterface not supported on this platform.");
    None
}

/// [`connect_one`] from `BindAddress`, else from `BindInterface`'s address
/// of the target's family (`bind`: the two, as configured).
fn connect_from(
    addr: std::net::SocketAddr,
    bind: (Option<&str>, Option<&str>),
    timeout: Option<std::time::Duration>,
) -> std::io::Result<TcpStream> {
    match bind {
        (Some(a), _) => connect_one(addr, Some(a), timeout),
        (None, Some(ifname)) => match interface_address(ifname, addr.is_ipv4()) {
            Some(a) => connect_one(addr, Some(&a.to_string()), timeout),
            None => {
                eprintln!("getifaddrs: {ifname}: no suitable addresses");
                Err(std::io::Error::other("failure"))
            }
        },
        (None, None) => connect_one(addr, None, timeout),
    }
}

/// Connect to a single resolved address, optionally binding a local source
/// address (`BindAddress`) and applying a connect timeout (`ConnectTimeout`).
fn connect_one(
    addr: std::net::SocketAddr,
    bind_address: Option<&str>,
    timeout: Option<std::time::Duration>,
) -> std::io::Result<TcpStream> {
    if let Some(bind) = bind_address {
        // A local source bind requires the two-step socket2-style dance,
        // which std doesn't expose directly. Use a TcpSocket-free approach
        // via libc on Unix; on other platforms BindAddress is unsupported.
        return connect_bound(addr, bind, timeout);
    }
    match timeout {
        Some(t) => TcpStream::connect_timeout(&addr, t),
        None => TcpStream::connect(addr),
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
) -> std::io::Result<TcpStream> {
    use std::io::Error as IoError;
    use std::net::ToSocketAddrs;
    use std::os::unix::io::FromRawFd;

    // Resolve the bind address (port 0 = ephemeral) in the same family as
    // the target.
    let bind_addr = (bind, 0u16)
        .to_socket_addrs()
        .map_err(|e| IoError::other(format!("resolve BindAddress {bind}: {e}")))?
        .find(|a| a.is_ipv4() == addr.is_ipv4())
        .ok_or_else(|| {
            IoError::other(format!(
                "BindAddress {bind} has no address matching the target family"
            ))
        })?;

    let domain = if addr.is_ipv4() {
        libc::AF_INET
    } else {
        libc::AF_INET6
    };
    // SAFETY: standard socket(2) call; fd ownership transferred to TcpStream
    // via from_raw_fd below (or closed on the error paths).
    let fd = unsafe { libc::socket(domain, libc::SOCK_STREAM, 0) };
    if fd < 0 {
        return Err(IoError::last_os_error());
    }
    // Wrap immediately so any early return closes the fd via Drop.
    let stream = unsafe { TcpStream::from_raw_fd(fd) };

    let (bind_storage, bind_len) = sockaddr_bytes(&bind_addr);
    // SAFETY: bind_storage/len describe a valid sockaddr for this fd's family.
    let rc = unsafe { libc::bind(fd, bind_storage.as_ptr() as *const libc::sockaddr, bind_len) };
    if rc != 0 {
        let e = IoError::last_os_error();
        return Err(IoError::new(e.kind(), format!("bind {bind_addr}: {e}")));
    }

    let (target_storage, target_len) = sockaddr_bytes(&addr);
    // SAFETY: same contract as bind; connect blocks (no timeout fd dance).
    let rc = unsafe {
        libc::connect(
            fd,
            target_storage.as_ptr() as *const libc::sockaddr,
            target_len,
        )
    };
    if rc != 0 {
        return Err(IoError::last_os_error());
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
) -> std::io::Result<TcpStream> {
    Err(std::io::Error::other(
        "BindAddress is only supported on Unix",
    ))
}

/// Encode a `SocketAddr` into a `sockaddr_storage` byte buffer + length for
/// the raw libc `bind`/`connect` calls.
#[cfg(unix)]
fn sockaddr_bytes(addr: &std::net::SocketAddr) -> (Vec<u8>, libc::socklen_t) {
    match addr {
        std::net::SocketAddr::V4(v4) => {
            let mut sa: libc::sockaddr_in = unsafe { core::mem::zeroed() };
            sa.sin_family = libc::AF_INET as libc::sa_family_t;
            sa.sin_port = v4.port().to_be();
            sa.sin_addr.s_addr = u32::from_ne_bytes(v4.ip().octets());
            let len = core::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
            let bytes = unsafe {
                core::slice::from_raw_parts(
                    &sa as *const _ as *const u8,
                    core::mem::size_of::<libc::sockaddr_in>(),
                )
                .to_vec()
            };
            (bytes, len)
        }
        std::net::SocketAddr::V6(v6) => {
            let mut sa: libc::sockaddr_in6 = unsafe { core::mem::zeroed() };
            sa.sin6_family = libc::AF_INET6 as libc::sa_family_t;
            sa.sin6_port = v6.port().to_be();
            sa.sin6_addr.s6_addr = v6.ip().octets();
            let len = core::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t;
            let bytes = unsafe {
                core::slice::from_raw_parts(
                    &sa as *const _ as *const u8,
                    core::mem::size_of::<libc::sockaddr_in6>(),
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
    let val: libc::c_int = if on { 1 } else { 0 };
    // SAFETY: standard setsockopt on a valid fd with a correctly-sized int.
    let rc = unsafe {
        libc::setsockopt(
            sock.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_KEEPALIVE,
            &val as *const _ as *const libc::c_void,
            core::mem::size_of::<libc::c_int>() as libc::socklen_t,
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

/// Whether a listener's stop flag (`ssh -O cancel`) is set.
fn stopped(stop: &Option<Arc<std::sync::atomic::AtomicBool>>) -> bool {
    stop.as_ref()
        .is_some_and(|s| s.load(std::sync::atomic::Ordering::SeqCst))
}

/// Per-`-L` accept loop on a TCP port: each connection gets a channel to
/// the forward's destination on the shared connection.
fn spawn_local_forward_listener(
    listener: TcpListener,
    spec: LocalForward,
    ctx: puressh::shared::SharedClient,
    stop: Option<Arc<std::sync::atomic::AtomicBool>>,
) {
    thread::spawn(move || {
        for accept in listener.incoming() {
            if stopped(&stop) {
                break;
            }
            let tcp = match accept {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("ssh: -L accept on port {}: {e}", spec.listen_port);
                    continue;
                }
            };
            let orig = tcp
                .peer_addr()
                .map(|a| (a.ip().to_string(), a.port()))
                .unwrap_or_else(|_| ("127.0.0.1".to_string(), 0));
            if let Some(stream) = open_local_forward_channel(&ctx, &spec, &orig) {
                splice_shared_with_tcp(ctx.clone(), stream, tcp);
            }
        }
    });
}

/// Per-`-L` accept loop on a Unix socket.
#[cfg(unix)]
fn spawn_local_path_listener(
    listener: std::os::unix::net::UnixListener,
    spec: LocalForward,
    ctx: puressh::shared::SharedClient,
    stop: Option<Arc<std::sync::atomic::AtomicBool>>,
) {
    thread::spawn(move || {
        for accept in listener.incoming() {
            if stopped(&stop) {
                break;
            }
            let conn = match accept {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("ssh: -L accept: {e}");
                    continue;
                }
            };
            let orig = ("127.0.0.1".to_string(), 0);
            if let Some(stream) = open_local_forward_channel(&ctx, &spec, &orig) {
                splice_shared_with_tcp(ctx.clone(), stream, LocalConn::Unix(conn));
            }
        }
    });
}

/// The channel for one `-L` connection: `direct-streamlocal` to a socket
/// path, else `direct-tcpip`. `None` (reported) when the server refuses.
fn open_local_forward_channel(
    ctx: &puressh::shared::SharedClient,
    spec: &LocalForward,
    orig: &(String, u16),
) -> Option<puressh::shared::OwnedChannelStream> {
    let opened = match &spec.connect_path {
        Some(path) => ctx.open_direct_streamlocal(path),
        None => ctx.open_direct_tcpip(&spec.remote_host, spec.remote_port, &orig.0, orig.1),
    };
    match opened {
        Ok(s) => Some(s),
        Err(e) => {
            match &spec.connect_path {
                Some(path) => eprintln!("ssh: -L direct-streamlocal {path}: {e}"),
                None => eprintln!(
                    "ssh: -L direct-tcpip {}:{}: {e}",
                    spec.remote_host, spec.remote_port
                ),
            }
            None
        }
    }
}

/// Listen on a Unix socket for `-L /path:…`, owner-only as OpenSSH's
/// (StreamLocalBindMask 0177). An existing file is not replaced
/// (StreamLocalBindUnlink no).
#[cfg(unix)]
fn bind_unix_listener(path: &str) -> std::io::Result<std::os::unix::net::UnixListener> {
    use std::os::unix::fs::PermissionsExt;
    let l = std::os::unix::net::UnixListener::bind(path)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    Ok(l)
}

#[cfg(not(unix))]
fn bind_unix_listener(_path: &str) -> std::io::Result<()> {
    Err(std::io::Error::new(
        ErrorKind::Unsupported,
        "Unix domain sockets are not supported on this platform",
    ))
}

/// Per-`-D` SOCKS accept loop. Each accepted TCP connection runs the SOCKS
/// handshake ([`puressh::forwarding::socks::handshake`]) to learn the CONNECT
/// target, opens a `direct-tcpip` channel to it on the shared connection,
/// writes the SOCKS success/failure reply, then splices the channel against
/// the socket. BIND / UDP / bad-auth requests are rejected in-handshake and
/// the connection dropped.
fn spawn_dynamic_forward_listener(
    listener: TcpListener,
    listen_port: u16,
    ctx: puressh::shared::SharedClient,
    stop: Option<Arc<std::sync::atomic::AtomicBool>>,
) {
    use puressh::forwarding::socks;
    thread::spawn(move || {
        for accept in listener.incoming() {
            if stopped(&stop) {
                break;
            }
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
                        splice_shared_with_tcp(ctx, stream, tcp);
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

/// `LogLevel QUIET` (`-q`): not even the fatal error ending ssh is shown.
static LOG_QUIET: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

fn main() -> ExitCode {
    let code = match run() {
        Ok(code) => {
            let clamped = code.clamp(0, 255) as u8;
            ExitCode::from(clamped)
        }
        Err(msg) => {
            // Empty: the error was already reported in OpenSSH's words.
            if !msg.is_empty() && !LOG_QUIET.load(std::sync::atomic::Ordering::Relaxed) {
                eprintln!("ssh: {msg}");
            }
            ExitCode::from(255)
        }
    };
    common::finish_log();
    code
}

/// Client side of the puressh UDP knock (`docs/knock.md` §6) for the direct
/// TCP path: identity selection, the sig1 and knock-host caches under
/// `~/.ssh/puressh/`, and pinning the session to the ACCEPT's host key.
#[cfg(feature = "knock")]
mod knock_support {
    use super::*;
    use puressh::client::HostKeyPolicy;
    use puressh::config::KnockSetting;
    use puressh::hostkey::HostKey;
    use puressh::knock::{
        Connected, KnockConnectOptions, KnockIdentity, KnockMode, KnockRequest, TcpDialer,
        connect_or_knock_addrs, wire,
    };
    use std::collections::HashMap;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    /// Keys knocked with at once (`docs/knock.md` §6.2).
    const MAX_IDENTITIES: usize = 4;
    /// Knock-host cache entries unused for this long are forgotten.
    const HOST_CACHE_TTL_SECS: u64 = 30 * 24 * 3600;

    /// Connect to `host:port` like [`dial_tcp`], knocking when plain TCP is
    /// refused or slow. On a knock, `cfg` is pinned to the ACCEPT's host key.
    pub(super) fn dial(
        host: &str,
        port: u16,
        user: &str,
        cfg_block: &puressh::config::ClientOptions,
        cfg: &mut Config,
        creds: &[ClientCredential],
    ) -> Result<TcpStream, String> {
        let signers: Vec<&dyn HostKey> = creds
            .iter()
            .filter_map(|c| match c {
                ClientCredential::PublicKey(k) => Some(&**k as &dyn HostKey),
                _ => None,
            })
            .filter(|k| wire::max_sig_blob_len(&k.public_blob()).is_some())
            .take(MAX_IDENTITIES)
            .collect();
        if signers.is_empty() || user.is_empty() || user.len() > wire::MAX_USER_LEN {
            vlog(2, "knock: no usable identity or user name; plain TCP only");
            return dial_tcp(host, port, cfg_block);
        }

        let addrs = resolve_addrs(host, port, cfg_block)?;
        let timeout = connect_timeout(cfg_block);
        let bind = cfg_block.bind_address.clone();
        let bind_if = cfg_block.bind_interface.clone();
        let dialer: TcpDialer =
            Arc::new(move |a| connect_from(a, (bind.as_deref(), bind_if.as_deref()), timeout));

        let mut sig1_cache = Sig1Cache::load();
        let identities: Vec<KnockIdentity<'_>> = signers
            .iter()
            .map(|k| KnockIdentity {
                signer: *k,
                sig1: sig1_cache.get(user, &wire::key_fp(&k.public_blob())),
            })
            .collect();
        let mut host_cache = HostCache::load();
        let host_key = format!("{host}:{port}");

        let mut opts = KnockConnectOptions::default();
        opts.mode = match cfg_block.knock_mode {
            Some(KnockSetting::Always) => KnockMode::Always,
            _ => KnockMode::Auto,
        };
        opts.fallback_delay = if host_cache.contains(&host_key) {
            // Answered a knock before: knock right away, alongside TCP.
            Duration::ZERO
        } else {
            Duration::from_millis(cfg_block.knock_fallback_delay.unwrap_or(1500) as u64)
        };
        opts.connect_timeout = timeout;
        opts.knock_port = cfg_block.knock_port;

        let mut req = KnockRequest {
            user,
            identities,
            known_host_keys: known_host_keys(cfg, host, port),
        };
        let res = connect_or_knock_addrs(&addrs, &mut req, &opts, dialer);
        for (k, id) in signers.iter().zip(&req.identities) {
            if let Some(s1) = &id.sig1 {
                sig1_cache.put(user, wire::key_fp(&k.public_blob()), s1);
            }
        }
        sig1_cache.save();

        match res {
            Ok(Connected::Direct(s)) => {
                configure_socket(&s, cfg_block)?;
                Ok(s)
            }
            Ok(Connected::Knocked { stream, accepted }) => {
                vlog(
                    1,
                    &format!(
                        "knock: accepted, rendezvous at {} ({} host key)",
                        accepted.target,
                        if accepted.host_key_known {
                            "known"
                        } else {
                            "new"
                        }
                    ),
                );
                accepted.pin(cfg);
                host_cache.touch(&host_key);
                host_cache.save();
                configure_socket(&stream, cfg_block)?;
                Ok(stream)
            }
            Ok(_) => Err(format!("connect {host}:{port}: unsupported knock outcome")),
            Err(puressh::Error::Io(e)) => Err(format!(
                "connect to host {host} port {port}: {}",
                common::io_reason(&e)
            )),
            Err(e) => Err(format!("connect to host {host} port {port}: {e}")),
        }
    }

    /// Plain host keys `known_hosts` holds for `host:port`, if the policy
    /// reads `known_hosts` at all.
    fn known_host_keys(cfg: &Config, host: &str, port: u16) -> Vec<Vec<u8>> {
        let HostKeyPolicy::KnownHosts(kh) = &cfg.host_key_policy else {
            return Vec::new();
        };
        let Ok(store) = kh.store.lock() else {
            return Vec::new();
        };
        store
            .find(host, port)
            .into_iter()
            .filter(|e| e.marker.is_none())
            .map(|e| e.key_blob.clone())
            .collect()
    }

    fn cache_path(name: &str) -> Option<PathBuf> {
        let dir = expand_tilde("~/.ssh/puressh");
        if dir.starts_with('~') {
            return None;
        }
        Some(PathBuf::from(dir).join(name))
    }

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    fn unhex(s: &str) -> Option<Vec<u8>> {
        if !s.len().is_multiple_of(2) {
            return None;
        }
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok())
            .collect()
    }

    /// Write `content` to `path` (mode 0600, directory 0700) via a rename.
    fn write_private(path: &std::path::Path, content: &str) {
        let Some(dir) = path.parent() else { return };
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            let _ = std::fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(dir);
        }
        #[cfg(not(unix))]
        let _ = std::fs::create_dir_all(dir);
        let tmp = path.with_extension(format!("tmp{}", std::process::id()));
        let mut o = std::fs::OpenOptions::new();
        o.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            o.mode(0o600);
        }
        let ok = o
            .open(&tmp)
            .and_then(|mut f| f.write_all(content.as_bytes()))
            .is_ok();
        if !ok || std::fs::rename(&tmp, path).is_err() {
            let _ = std::fs::remove_file(&tmp);
            vlog(1, &format!("knock: could not write {}", path.display()));
        }
    }

    /// `knock_ids`: `user key_fp_hex sig1_hex` per line.
    struct Sig1Cache {
        entries: HashMap<(String, [u8; 32]), Vec<u8>>,
        dirty: bool,
    }

    impl Sig1Cache {
        fn load() -> Self {
            let mut entries = HashMap::new();
            let text = cache_path("knock_ids")
                .and_then(|p| std::fs::read_to_string(p).ok())
                .unwrap_or_default();
            for line in text.lines() {
                let mut it = line.split_whitespace();
                let (Some(u), Some(fp), Some(sig)) = (it.next(), it.next(), it.next()) else {
                    continue;
                };
                let (Some(fp), Some(sig)) = (unhex(fp), unhex(sig)) else {
                    continue;
                };
                let Ok(fp) = <[u8; 32]>::try_from(fp) else {
                    continue;
                };
                entries.insert((u.to_string(), fp), sig);
            }
            Self {
                entries,
                dirty: false,
            }
        }

        fn get(&self, user: &str, fp: &[u8; 32]) -> Option<Vec<u8>> {
            self.entries.get(&(user.to_string(), *fp)).cloned()
        }

        fn put(&mut self, user: &str, fp: [u8; 32], sig1: &[u8]) {
            let k = (user.to_string(), fp);
            if self.entries.get(&k).map(Vec::as_slice) != Some(sig1) {
                self.entries.insert(k, sig1.to_vec());
                self.dirty = true;
            }
        }

        fn save(&self) {
            if !self.dirty
                || self
                    .entries
                    .keys()
                    .any(|(u, _)| u.contains(char::is_whitespace))
            {
                return;
            }
            let Some(path) = cache_path("knock_ids") else {
                return;
            };
            let mut out = String::new();
            for ((u, fp), sig) in &self.entries {
                out.push_str(&format!("{u} {} {}\n", hex(fp), hex(sig)));
            }
            write_private(&path, &out);
        }
    }

    /// `knock_hosts`: `host:port last_use_unix_secs` per line.
    struct HostCache {
        entries: HashMap<String, u64>,
        now: u64,
    }

    impl HostCache {
        fn load() -> Self {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            let text = cache_path("knock_hosts")
                .and_then(|p| std::fs::read_to_string(p).ok())
                .unwrap_or_default();
            let entries = text
                .lines()
                .filter_map(|l| {
                    let (h, t) = l.split_once(' ')?;
                    let t: u64 = t.trim().parse().ok()?;
                    (now.saturating_sub(t) < HOST_CACHE_TTL_SECS).then(|| (h.to_string(), t))
                })
                .collect();
            Self { entries, now }
        }

        fn contains(&self, host: &str) -> bool {
            self.entries.contains_key(host)
        }

        fn touch(&mut self, host: &str) {
            self.entries.insert(host.to_string(), self.now);
        }

        fn save(&self) {
            let Some(path) = cache_path("knock_hosts") else {
                return;
            };
            let mut out = String::new();
            for (h, t) in &self.entries {
                if !h.contains(char::is_whitespace) {
                    out.push_str(&format!("{h} {t}\n"));
                }
            }
            write_private(&path, &out);
        }
    }
}

#[cfg(test)]
mod extra_o_tests {
    use super::*;

    fn args(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn options_stop_at_the_command() {
        // `ssh host ls -la`: `-la` belongs to the remote command.
        let c = parse_args(&args(&["host", "ls", "-la", "/tmp"])).unwrap();
        assert_eq!(c.host, "host");
        assert_eq!(c.command.as_deref(), Some("ls -la /tmp"));
        // Options are still parsed after the destination, before a command.
        let c = parse_args(&args(&["host", "-p", "2222", "-q", "uptime", "-p"])).unwrap();
        assert_eq!(c.port, Some(2222));
        assert!(c.quiet);
        assert_eq!(c.command.as_deref(), Some("uptime -p"));
        // `--` ends options.
        let c = parse_args(&args(&["--", "host", "-x"])).unwrap();
        assert_eq!(c.command.as_deref(), Some("-x"));
    }

    #[test]
    fn bundled_and_attached_options() {
        let c = parse_args(&args(&["-p22", "-NfL", "8080:example:80", "-vv", "host"])).unwrap();
        assert_eq!(c.port, Some(22));
        assert!(c.no_command && c.fork_after_auth && c.stdin_null);
        assert_eq!(c.locals.len(), 1);
        assert_eq!(c.verbose, 2);
        let c = parse_args(&args(&["-tt", "host"])).unwrap();
        assert_eq!(c.request_tty, Some(puressh::config::RequestTty::Force));
        let c = parse_args(&args(&["-t", "host"])).unwrap();
        assert_eq!(c.request_tty, Some(puressh::config::RequestTty::Yes));
        let c = parse_args(&args(&["-4", "-c", "aes128-ctr", "-S", "/tmp/s", "host"])).unwrap();
        assert!(c.extra_o.contains(&"AddressFamily inet".to_string()));
        assert!(c.extra_o.contains(&"Ciphers aes128-ctr".to_string()));
        assert!(c.extra_o.contains(&"ControlPath /tmp/s".to_string()));
        let c = parse_args(&args(&["-o", "Port 2200", "-oUser=bob", "host"])).unwrap();
        assert!(c.extra_o.contains(&"Port 2200".to_string()));
        assert!(c.extra_o.contains(&"User bob".to_string()));
        assert!(parse_args(&args(&["-Z", "host"])).unwrap().dump_pubkeys);
        assert!(parse_args(&args(&["-U", "host"])).is_err());
        assert_eq!(
            parse_args(&args(&["-B", "eth0", "-O", "channels", "host"]))
                .unwrap()
                .extra_o,
            ["BindInterface eth0"]
        );
        assert!(parse_args(&args(&["host", "-p"])).is_err());
    }

    #[test]
    fn version_query_and_escape_parse() {
        assert!(parse_args(&args(&["-V"])).unwrap().version);
        assert_eq!(
            parse_args(&args(&["-Q", "mac"])).unwrap().query.as_deref(),
            Some("mac")
        );
        assert_eq!(
            parse_args(&args(&["-e", "none", "h"])).unwrap().escape_char,
            Some(None)
        );
        assert_eq!(
            parse_args(&args(&["-e", "^]", "h"])).unwrap().escape_char,
            Some(Some(0x1d))
        );
        assert!(parse_args(&args(&["-e", "ab", "h"])).is_err());
    }

    #[test]
    fn escape_filter() {
        let mut f = EscapeFilter::new(b'~');
        let mut out = Vec::new();
        assert_eq!(f.feed(b"~.", &mut out), vec![(0, EscapeAction::Disconnect)]);
        assert!(out.is_empty());
        // Not at a line start: plain data.
        let mut f = EscapeFilter::new(b'~');
        let mut out = Vec::new();
        assert!(f.feed(b"a~.", &mut out).is_empty());
        assert_eq!(out, b"a~.");
        // After a newline it is an escape again; `~~` sends one `~`; an
        // unknown escape sends both bytes.
        let mut out = Vec::new();
        assert_eq!(
            f.feed(b"\r~?x\n~~\n~z", &mut out),
            vec![(1, EscapeAction::Help)]
        );
        assert_eq!(out, b"\rx\n~\n~z");
        // Split across reads.
        let mut f = EscapeFilter::new(b'~');
        let mut out = Vec::new();
        assert!(f.feed(b"~", &mut out).is_empty());
        assert_eq!(f.feed(b".", &mut out), vec![(0, EscapeAction::Disconnect)]);
    }

    #[test]
    fn dash_o_rejects_embedded_newline() {
        // A line break in a `-o` value would smuggle a second directive
        // into the synthetic config the real parser reads.
        let err = parse_args(&args(&["-o", "User=x\nProxyCommand=evil", "host"]))
            .err()
            .unwrap();
        assert!(err.contains("newline"), "{err}");
        let err = parse_args(&args(&["-o", "StrictHostKeyChecking=no\r", "host"]))
            .err()
            .unwrap();
        assert!(err.contains("newline"), "{err}");
        // Plain values still parse.
        assert!(parse_args(&args(&["-o", "User=x", "host"])).is_ok());
    }

    #[test]
    fn dash_o_control_path_overlays_block() {
        let mut block = puressh::config::ClientOptions::default();
        apply_extra_o(
            &mut block,
            &args(&["ControlPath /tmp/cm-%C", "ControlMaster auto"]),
        )
        .unwrap();
        assert_eq!(block.control_path.as_deref(), Some("/tmp/cm-%C"));
        assert_eq!(
            block.control_master,
            Some(puressh::config::ControlMaster::Auto)
        );
    }
}

#[cfg(test)]
mod no_more_sessions_tests {
    use super::server_honours_no_more_sessions as honours;

    #[test]
    fn sent_to_openssh_5_and_later_and_to_puressh() {
        assert!(honours("SSH-2.0-OpenSSH_10.6"));
        assert!(honours("SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5"));
        assert!(honours("SSH-2.0-OpenSSH_5.3"));
        assert!(honours("SSH-1.99-OpenSSH_7.4"));
        assert!(honours("SSH-2.0-puressh_0.2.5"));
        // OpenSSH 2.x-4.x lack SSH_NEW_OPENSSH; others may abort on it.
        assert!(!honours("SSH-2.0-OpenSSH_4.7"));
        assert!(!honours("SSH-2.0-OpenSSH_3.9p1"));
        assert!(!honours("SSH-2.0-dropbear_2024.86"));
        assert!(!honours("SSH-2.0-libssh_0.10.6"));
        assert!(!honours("SSH-2.0-Go"));
        assert!(!honours(""));
    }
}

#[cfg(test)]
mod forward_tests {
    use super::*;

    #[test]
    fn local_forward_forms() {
        let f = parse_local_forward("8080:example.com:80").unwrap();
        assert_eq!((f.bind_addr.as_deref(), f.listen_port), (None, 8080));
        assert_eq!((f.remote_host.as_str(), f.remote_port), ("example.com", 80));
        let f = parse_local_forward("8080:[2001:db8::1]:80").unwrap();
        assert_eq!(f.remote_host, "2001:db8::1");
        let f = parse_local_forward("127.0.0.2:8080:example.com:80").unwrap();
        assert_eq!(f.bind_addr.as_deref(), Some("127.0.0.2"));
        let f = parse_local_forward("[::1]:8080:[2001:db8::1]:80").unwrap();
        assert_eq!(f.bind_addr.as_deref(), Some("::1"));
        let f = parse_local_forward("*:8080:h:80").unwrap();
        assert_eq!(f.bind_addr.as_deref(), Some("*"));
        // Unix socket paths at either end.
        let f = parse_local_forward("/tmp/l.sock:/run/r.sock").unwrap();
        assert_eq!(f.listen_path.as_deref(), Some("/tmp/l.sock"));
        assert_eq!(f.connect_path.as_deref(), Some("/run/r.sock"));
        let f = parse_local_forward("8080:/run/r.sock").unwrap();
        assert_eq!(
            (f.listen_port, f.connect_path.as_deref()),
            (8080, Some("/run/r.sock"))
        );
        let f = parse_local_forward("/tmp/l.sock:h:22").unwrap();
        assert_eq!(f.listen_path.as_deref(), Some("/tmp/l.sock"));
        assert_eq!((f.remote_host.as_str(), f.remote_port), ("h", 22));
    }

    #[test]
    fn local_forward_rejects() {
        for bad in [
            "8080:[2001:db8::1:80",
            "8080:[2001:db8::1]",
            "8080:[2001:db8::1]junk",
            "only-one-field",
            "80:hostonly",
            "0:h:22",
            "a:b:c:d:e",
            "8080",
        ] {
            assert!(parse_local_forward(bad).is_err(), "{bad}");
        }
        assert_eq!(
            parse_local_forward("x").unwrap_err(),
            "Bad local forwarding specification 'x'"
        );
    }

    #[test]
    fn remote_forward_forms() {
        let f = parse_remote_forward("9090:127.0.0.1:22").unwrap();
        assert_eq!((f.bind_addr, f.remote_port), (None, 9090));
        assert_eq!(
            (f.local_host.as_str(), f.local_port, f.dynamic),
            ("127.0.0.1", 22, false)
        );
        let f = parse_remote_forward("9090:[2001:db8::2]:22").unwrap();
        assert_eq!(f.local_host, "2001:db8::2");
        let f = parse_remote_forward("4243").unwrap();
        assert!(f.dynamic && f.bind_addr.is_none() && f.remote_port == 4243);
        let f = parse_remote_forward("[::1]:4243").unwrap();
        assert!(f.dynamic && f.bind_addr.as_deref() == Some("::1"));
        let f = parse_remote_forward("0.0.0.0:9090:h:22").unwrap();
        assert_eq!(f.bind_addr.as_deref(), Some("0.0.0.0"));
        let f = parse_remote_forward("0:h:22").unwrap();
        assert_eq!(f.remote_port, 0);
        let f = parse_remote_forward("/tmp/r.sock:/tmp/l.sock").unwrap();
        assert_eq!(f.listen_path.as_deref(), Some("/tmp/r.sock"));
        assert_eq!(f.connect_path.as_deref(), Some("/tmp/l.sock"));
        assert!(parse_remote_forward("a:b:c:d:e").is_err());
        assert!(parse_remote_forward("nope").is_err());
    }
}
