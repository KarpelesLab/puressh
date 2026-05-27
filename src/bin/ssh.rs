//! `ssh` — puressh's SSH client driver.
//!
//! ```text
//! ssh [-p port] [-i identity_file] [-l user] [-o StrictHostKeyChecking=no] [user@]host [command...]
//! ```

use std::io::{Read, Write};
use std::process::ExitCode;

use puressh::auth::ClientCredential;
use puressh::client::{Client, Config, HostKeyPolicy};
use puressh::key::PrivateKey;

const VERSION: &str = env!("CARGO_PKG_VERSION");

const USAGE: &str = "usage: ssh [-p port] [-i identity_file] [-l user] \
                     [-o StrictHostKeyChecking=no] [user@]host [command...]";

struct Cli {
    port: u16,
    identities: Vec<String>,
    cli_user: Option<String>,
    strict_host_key: bool,
    host: String,
    user_in_host: Option<String>,
    command: Option<String>,
}

fn parse_args(args: &[String]) -> Result<Cli, String> {
    let mut port = 22u16;
    let mut identities: Vec<String> = Vec::new();
    let mut cli_user: Option<String> = None;
    let mut strict_host_key = true;
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
            "-o" => {
                i += 1;
                let v = args.get(i).ok_or("-o requires a value")?;
                if v.eq_ignore_ascii_case("StrictHostKeyChecking=no") {
                    strict_host_key = false;
                } else if v.eq_ignore_ascii_case("StrictHostKeyChecking=yes") {
                    strict_host_key = true;
                } else {
                    return Err(format!("unsupported -o option: {v}"));
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
        strict_host_key,
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

    if cli.strict_host_key {
        eprintln!("warning: host key verification is disabled (no known-hosts support yet)");
    }
    let cfg = Config {
        host_key_policy: HostKeyPolicy::AcceptAny,
        timeout: None,
    };

    let addr = (cli.host.as_str(), cli.port);
    let mut client = Client::connect(addr, cfg).map_err(|e| format!("connect: {e}"))?;

    let mut authed = false;
    if !cli.identities.is_empty() {
        for id_path in &cli.identities {
            let pk = match load_identity(id_path) {
                Ok(p) => p,
                Err(e) => {
                    eprintln!("warning: {e}");
                    continue;
                }
            };
            let hk = match pk.into_host_key() {
                Ok(h) => h,
                Err(e) => {
                    eprintln!("warning: identity {id_path}: {e}");
                    continue;
                }
            };
            match client.authenticate(&user, vec![ClientCredential::PublicKey(hk)]) {
                Ok(()) => {
                    authed = true;
                    break;
                }
                Err(e) => {
                    eprintln!("publickey auth with {id_path}: {e}");
                }
            }
        }
    }

    if !authed {
        // v0 limitation: password input is echoed to the terminal — there is no
        // portable in-tree way to disable terminal echo without adding a dep.
        let password = read_password_from_stdin().map_err(|e| format!("read password: {e}"))?;
        client
            .authenticate_password(&user, &password)
            .map_err(|e| format!("Auth failed: {e}"))?;
    }

    let command = cli
        .command
        .ok_or_else(|| "interactive shell not yet implemented".to_string())?;

    let out = client.exec(&command).map_err(|e| format!("exec: {e}"))?;
    let _ = std::io::stdout().write_all(&out.stdout);
    let _ = std::io::stderr().write_all(&out.stderr);
    Ok(out.exit_status.map(|s| s as i32).unwrap_or(255))
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
