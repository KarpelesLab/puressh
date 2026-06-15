//! `scp` — puressh's SCP client driver.
//!
//! ```text
//! scp [-r] [-p] [-P port] [-i identity_file] [-l user]
//!     [-o StrictHostKeyChecking={yes,no,accept-new,ask}]
//!     [-o UserKnownHostsFile=PATH]
//!     [-o HashKnownHosts={yes,no}]
//!     [-o IdentitiesOnly={yes,no}]
//!     SOURCE [SOURCE...] TARGET
//! ```
//!
//! Exactly one of `TARGET` or `SOURCE` may be of the form
//! `[user@]host:path`; the others must be plain local paths.
//! Three-corner copies (`scp host1:foo host2:bar`) are explicitly out of
//! scope — the client connects to a single peer.
//!
//! Authentication and host-key policy mirror the `ssh` binary: the agent
//! (`$SSH_AUTH_SOCK`) is tried first unless `IdentitiesOnly=yes`, then any
//! `-i` keys, then a stdin password prompt.
//!
//! Note: OpenSSH 9.0+ deprecated SCP in favour of SFTP. For new scripts
//! the puressh `sftp` binary (or the `puressh::client::Client::sftp`
//! library API) is a better choice.

use std::path::PathBuf;
use std::process::ExitCode;

use puressh::auth::ClientCredential;
use puressh::client::{AlgoOverrides, Client, Config};
use puressh::scp::{ScpRecvOptions, ScpSendOptions};

#[path = "common.rs"]
mod common;
use common::{
    StrictMode, build_host_key_policy, connect_agent_credentials, default_identity_paths,
    expand_tilde, load_identity, parse_userhost_path, read_password_from_stdin, resolve_user,
    set_verbose, try_load_default_identity, vlog,
};

const VERSION: &str = env!("CARGO_PKG_VERSION");

const USAGE: &str = "usage: scp [-v[v[v]]] [-r] [-p] [-F configfile] [-P port] [-i identity_file] [-l user] \
                     [-o StrictHostKeyChecking={yes,no,accept-new,ask}] \
                     [-o UserKnownHostsFile=PATH] [-o HashKnownHosts={yes,no}] \
                     [-o IdentitiesOnly={yes,no}] \
                     SOURCE [SOURCE...] TARGET";

struct Cli {
    /// Recursive (`-r`).
    recursive: bool,
    /// Preserve mtime/atime/mode (`-p`).
    preserve_times: bool,
    /// `-F path`: load this `ssh_config` instead of the defaults.
    config_file: Option<PathBuf>,
    port: Option<u16>,
    identities: Vec<String>,
    cli_user: Option<String>,
    strict: Option<StrictMode>,
    known_hosts_path: Option<PathBuf>,
    hash_known_hosts: Option<bool>,
    identities_only: Option<bool>,
    /// OpenSSH-style verbose level: `-v` → 1, `-vv` → 2, `-vvv` → 3.
    /// See [`common::set_verbose`].
    verbose: u8,
    /// All positional args, last is TARGET, the rest are SOURCEs.
    positional: Vec<String>,
}

fn parse_args(args: &[String]) -> Result<Cli, String> {
    let mut recursive = false;
    let mut preserve_times = false;
    let mut config_file: Option<PathBuf> = None;
    let mut port: Option<u16> = None;
    let mut identities: Vec<String> = Vec::new();
    let mut cli_user: Option<String> = None;
    let mut strict: Option<StrictMode> = None;
    let mut known_hosts_path: Option<PathBuf> = None;
    let mut hash_known_hosts: Option<bool> = None;
    let mut identities_only: Option<bool> = None;
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
            "-r" => recursive = true,
            "-p" => preserve_times = true,
            "-P" => {
                i += 1;
                let v = args.get(i).ok_or("-P requires a value")?;
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
            "-v" => {
                verbose = verbose.saturating_add(1).min(3);
            }
            "-vv" => {
                verbose = verbose.max(2);
            }
            "-vvv" => {
                verbose = 3;
            }
            // Ignore harmless flags scp(1) users sometimes set.
            "-q" | "-B" | "-C" | "-1" | "-2" | "-3" | "-4" | "-6" => {}
            s if s.starts_with('-') => {
                return Err(format!("unknown flag: {s}"));
            }
            _ => positional.push(a.clone()),
        }
        i += 1;
    }

    if positional.len() < 2 {
        return Err(format!(
            "expected at least one SOURCE and one TARGET, got {} args",
            positional.len()
        ));
    }
    // No bare `-` (stdin/stdout) anywhere — we don't speak that.
    if positional.iter().any(|p| p == "-") {
        return Err("`-` (stdin/stdout) not supported".into());
    }

    Ok(Cli {
        recursive,
        preserve_times,
        config_file,
        port,
        identities,
        cli_user,
        strict,
        known_hosts_path,
        hash_known_hosts,
        identities_only,
        verbose,
        positional,
    })
}

/// One side of a copy: local file path, or a `[user@]host:path` remote ref.
#[derive(Debug)]
enum Endpoint {
    Local(PathBuf),
    Remote {
        user: Option<String>,
        host: String,
        path: String,
    },
}

fn classify(arg: &str) -> Endpoint {
    match parse_userhost_path(arg) {
        Some((user, host, path)) => Endpoint::Remote { user, host, path },
        None => Endpoint::Local(PathBuf::from(arg)),
    }
}

/// Connect to a remote, authenticate (agent → identity files → password),
/// and return the resulting [`Client`] ready to drive SCP.
///
/// Factored out so it can be called once per `scp` invocation regardless of
/// whether the remote is the source or the target.
fn open_authenticated(
    host: &str,
    user_in_endpoint: Option<&str>,
    cli: &Cli,
    ssh_cfg: &puressh::config::SshClientConfig,
) -> Result<Client, String> {
    let cfg_block = ssh_cfg.lookup(host);

    let cli_user = cli.cli_user.clone().or_else(|| cfg_block.user.clone());
    let user = resolve_user(cli_user.as_deref(), user_in_endpoint)?;
    let strict = common::pick(cli.strict, cfg_block.strict_host_key, StrictMode::Ask);
    let known_hosts_path = cli
        .known_hosts_path
        .clone()
        .or_else(|| cfg_block.user_known_hosts.as_ref().map(PathBuf::from));
    let hash_known_hosts = common::pick(cli.hash_known_hosts, cfg_block.hash_known_hosts, false);
    let identities_only = common::pick(cli.identities_only, cfg_block.identities_only, false);
    let port = common::pick(cli.port, cfg_block.port, 22);
    let connect_host = cfg_block
        .host_name
        .clone()
        .unwrap_or_else(|| host.to_string());

    let policy = build_host_key_policy(strict, known_hosts_path, hash_known_hosts)?;
    let cfg = Config {
        host_key_policy: policy,
        timeout: None,
        algorithms: AlgoOverrides {
            ciphers: cfg_block.ciphers.clone(),
            macs: cfg_block.macs.clone(),
            kex_algorithms: cfg_block.kex_algorithms.clone(),
            host_key_algorithms: cfg_block.host_key_algorithms.clone(),
            pubkey_accepted_algorithms: cfg_block.pubkey_accepted_algorithms.clone(),
        },
    };
    vlog(1, &format!("connecting to {connect_host}:{port}"));
    let mut client = Client::connect_to_host(connect_host.as_str(), port, cfg)
        .map_err(|e| format!("connect: {e}"))?;
    vlog(1, &format!("connected to {connect_host}:{port}"));

    // Collect publickey credentials (agent first, unless IdentitiesOnly=yes).
    let mut credentials: Vec<ClientCredential> = Vec::new();
    if !identities_only {
        match connect_agent_credentials() {
            Ok(mut from_agent) => {
                vlog(
                    1,
                    &format!("agent: offered {} identities", from_agent.len()),
                );
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
    // Identities listed in the matching ssh_config block.
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
    // OpenSSH-style default identities: tried after agent + explicit -i,
    // suppressed entirely by IdentitiesOnly=yes (which also disables the
    // agent above).
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
                "trying publickey auth as {} ({} credentials)",
                user,
                credentials.len()
            ),
        );
        let ok = client.authenticate(&user, credentials).is_ok();
        if ok {
            vlog(1, &format!("authenticated as {user} via publickey"));
        }
        ok
    } else {
        false
    };
    if !authed {
        vlog(1, &format!("trying password auth as {user}"));
        let password = read_password_from_stdin().map_err(|e| format!("read password: {e}"))?;
        client
            .authenticate_password(&user, &password)
            .map_err(|e| format!("Auth failed: {e}"))?;
        vlog(1, &format!("authenticated as {user} via password"));
    }
    Ok(client)
}

fn run() -> Result<i32, String> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.iter().any(|a| a == "-h" || a == "--help") {
        println!("{USAGE}");
        println!();
        println!("A pure-Rust SCP client built on puressh {VERSION}.");
        println!("Note: for new scripts, prefer sftp (puressh's `sftp` binary, or");
        println!("`puressh::client::Client::sftp` from code). OpenSSH 9.0+ has");
        println!("deprecated the SCP protocol.");
        return Ok(0);
    }
    if args.iter().any(|a| a == "-V" || a == "--version") {
        println!("puressh scp {VERSION}");
        return Ok(0);
    }

    let cli = parse_args(&args).map_err(|e| format!("{e}\n{USAGE}"))?;
    set_verbose(cli.verbose);

    // Resolve config once; each remote host re-walks the same blocks via
    // `open_authenticated`.
    let ssh_cfg = common::load_client_config(cli.config_file.as_deref())?;

    // Split into sources (all but last) and target (last).
    let mut endpoints: Vec<Endpoint> = cli.positional.iter().map(|s| classify(s)).collect();
    let target = endpoints.pop().expect("at least 2 positionals");
    let sources = endpoints;

    let n_remote_sources = sources
        .iter()
        .filter(|e| matches!(e, Endpoint::Remote { .. }))
        .count();
    let target_is_remote = matches!(target, Endpoint::Remote { .. });

    if target_is_remote && n_remote_sources > 0 {
        return Err("at most one side may be remote; three-corner copy not supported".into());
    }
    if !target_is_remote && n_remote_sources == 0 {
        return Err("at least one of SOURCE/TARGET must be a remote (user@host:path)".into());
    }
    if !target_is_remote && n_remote_sources > 1 {
        return Err("multiple remote sources not supported".into());
    }

    if target_is_remote {
        // Local → Remote.
        let (user, host, remote_path) = match target {
            Endpoint::Remote { user, host, path } => (user, host, path),
            Endpoint::Local(_) => unreachable!(),
        };
        let local_paths: Vec<PathBuf> = sources
            .into_iter()
            .map(|e| match e {
                Endpoint::Local(p) => Ok(p),
                Endpoint::Remote { .. } => {
                    Err("mixing local and remote sources is not supported".to_string())
                }
            })
            .collect::<Result<_, _>>()?;
        let path_refs: Vec<&std::path::Path> = local_paths.iter().map(|p| p.as_path()).collect();

        let mut client = open_authenticated(&host, user.as_deref(), &cli, &ssh_cfg)?;
        let opts = ScpSendOptions {
            recursive: cli.recursive,
            preserve_times: cli.preserve_times,
        };
        client
            .scp_send_to(&path_refs, &remote_path, opts)
            .map_err(|e| format!("upload: {e}"))?;
    } else {
        // Remote → Local.
        let local_target = match target {
            Endpoint::Local(p) => p,
            Endpoint::Remote { .. } => unreachable!(),
        };
        // We've already established n_remote_sources == 1.
        let (user, host, remote_path) = sources
            .into_iter()
            .find_map(|e| match e {
                Endpoint::Remote { user, host, path } => Some((user, host, path)),
                Endpoint::Local(_) => None,
            })
            .expect("one remote source");

        let mut client = open_authenticated(&host, user.as_deref(), &cli, &ssh_cfg)?;
        let opts = ScpRecvOptions {
            recursive: cli.recursive,
            preserve_times: cli.preserve_times,
            // Let scp_recv_from auto-detect based on the local target.
            target_is_file: false,
        };
        client
            .scp_recv_from(&remote_path, &local_target, opts)
            .map_err(|e| format!("download: {e}"))?;
    }

    Ok(0)
}

fn main() -> ExitCode {
    match run() {
        Ok(code) => {
            let clamped = code.clamp(0, 255) as u8;
            ExitCode::from(clamped)
        }
        Err(msg) => {
            eprintln!("scp: {msg}");
            ExitCode::from(255)
        }
    }
}
