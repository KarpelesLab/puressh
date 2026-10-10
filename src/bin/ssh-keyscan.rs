//! `ssh-keyscan` — gather SSH host keys, in `known_hosts` format.
//!
//! ```text
//! ssh-keyscan [-46Hv] [-f file] [-p port] [-T timeout] [-t type] [host | addrlist namelist] ...
//! ```
//!
//! Like OpenSSH's: for every host and every requested key type
//! (`rsa,ecdsa,ed25519` by default) it opens a connection offering only that
//! type's host-key algorithms, completes the key exchange to learn the key,
//! and prints `host keytype base64` on stdout (`[host]:port` for a
//! non-default port; `-H` hashes the host names). Diagnostics go to stderr.
//! Hosts that cannot be reached or offer no key of a type are skipped.

use std::io::{BufRead, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::process::ExitCode;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use puressh::client::{
    AlgoOverrides, Client, Config, HostKeyPolicy, KnownHostsPolicy, TofuAction, TofuPromptFn,
};
use puressh::known_hosts::KnownHosts;

const USAGE: &str = "usage: ssh-keyscan [-46Hv] [-f file] [-p port] [-T timeout] [-t type]\n\
                     \t\t   [host | addrlist namelist] ...";

struct Opts {
    family: Option<bool>, // Some(true) = IPv4 only, Some(false) = IPv6 only
    hash: bool,
    verbose: bool,
    port: u16,
    timeout: Duration,
    types: Vec<&'static str>,
    hosts: Vec<String>,
}

/// Host-key algorithms offered when scanning for one key type.
fn algorithms_for(ty: &str) -> Option<(&'static str, &'static [&'static str])> {
    Some(match ty {
        "rsa" => ("rsa", &["rsa-sha2-512", "rsa-sha2-256"][..]),
        "ecdsa" => (
            "ecdsa",
            &[
                "ecdsa-sha2-nistp256",
                "ecdsa-sha2-nistp384",
                "ecdsa-sha2-nistp521",
            ][..],
        ),
        "ed25519" => ("ed25519", &["ssh-ed25519"][..]),
        _ => return None,
    })
}

fn parse_args(args: &[String]) -> Result<Opts, String> {
    let mut o = Opts {
        family: None,
        hash: false,
        verbose: false,
        port: 22,
        timeout: Duration::from_secs(5),
        types: vec!["rsa", "ecdsa", "ed25519"],
        hosts: Vec::new(),
    };
    let mut files: Vec<String> = Vec::new();
    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
        if a == "--" {
            o.hosts.extend(args[i + 1..].iter().cloned());
            break;
        }
        if !a.starts_with('-') || a == "-" {
            o.hosts.push(a.clone());
            i += 1;
            continue;
        }
        let chars: Vec<char> = a[1..].chars().collect();
        let mut j = 0;
        while j < chars.len() {
            let c = chars[j];
            if "fpTt".contains(c) {
                let attached: String = chars[j + 1..].iter().collect();
                let v = if !attached.is_empty() {
                    attached
                } else {
                    i += 1;
                    args.get(i)
                        .ok_or_else(|| format!("option requires an argument -- {c}"))?
                        .clone()
                };
                match c {
                    'f' => files.push(v),
                    'p' => o.port = v.parse().map_err(|_| format!("bad port '{v}'"))?,
                    'T' => {
                        let secs: u64 = v.parse().map_err(|_| format!("bad timeout '{v}'"))?;
                        o.timeout = Duration::from_secs(secs.max(1));
                    }
                    't' => {
                        o.types.clear();
                        for t in v.split(',') {
                            // Accept OpenSSH's names for the same families.
                            let t = match t {
                                "ssh-rsa" | "rsa" => "rsa",
                                "ecdsa-sha2-nistp256"
                                | "ecdsa-sha2-nistp384"
                                | "ecdsa-sha2-nistp521"
                                | "ecdsa" => "ecdsa",
                                "ssh-ed25519" | "ed25519" => "ed25519",
                                // Not supported by this build: skipped like
                                // a type the server does not offer.
                                "dsa" | "ssh-dss" | "ecdsa-sk" | "ed25519-sk" => continue,
                                other => return Err(format!("unknown key type {other}")),
                            };
                            if !o.types.contains(&t) {
                                o.types.push(t);
                            }
                        }
                    }
                    _ => unreachable!(),
                }
                break;
            }
            match c {
                '4' => o.family = Some(true),
                '6' => o.family = Some(false),
                'H' => o.hash = true,
                'v' => o.verbose = true,
                'c' => return Err("-c (certificates) is not supported".into()),
                'D' => return Err("-D (SSHFP records) is not supported".into()),
                _ => return Err(format!("unknown option -- {c}")),
            }
            j += 1;
        }
        i += 1;
    }
    for f in files {
        let reader: Box<dyn BufRead> = if f == "-" {
            Box::new(std::io::BufReader::new(std::io::stdin()))
        } else {
            Box::new(std::io::BufReader::new(
                std::fs::File::open(&f).map_err(|e| format!("{f}: {e}"))?,
            ))
        };
        for line in reader.lines() {
            let line = line.map_err(|e| format!("{f}: {e}"))?;
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            o.hosts.push(line.to_string());
        }
    }
    if o.hosts.is_empty() {
        return Err(USAGE.into());
    }
    Ok(o)
}

/// `(key type, public key blob)` presented by a server.
type KeyFound = (String, Vec<u8>);

/// Connect to `name:port` (one of `addrs`) offering only `algs`, and return
/// the host key the server presented, if any.
fn scan_one(
    name: &str,
    port: u16,
    addrs: &[SocketAddr],
    algs: &[&str],
    timeout: Duration,
) -> Option<(String, Vec<u8>)> {
    let found: Arc<Mutex<Option<KeyFound>>> = Arc::new(Mutex::new(None));
    for addr in addrs {
        let sink = found.clone();
        let capture: Arc<TofuPromptFn> = Arc::new(move |_h, _p, key_type, blob| {
            if let Ok(mut g) = sink.lock() {
                *g = Some((key_type.to_string(), blob.to_vec()));
            }
            // Refuse: we only wanted the key, not a session.
            false
        });
        let mut policy = KnownHostsPolicy::strict(Arc::new(Mutex::new(KnownHosts::new())));
        policy.on_unknown = TofuAction::Prompt(capture);
        let mut algorithms = AlgoOverrides::default();
        algorithms.host_key_algorithms = Some(algs.iter().map(|a| a.to_string()).collect());
        let mut cfg = Config::new(HostKeyPolicy::KnownHosts(policy)).with_algorithms(algorithms);
        cfg.timeout = Some(timeout);
        let Ok(stream) = TcpStream::connect_timeout(addr, timeout) else {
            continue;
        };
        let _ = stream.set_read_timeout(Some(timeout));
        let _ = stream.set_write_timeout(Some(timeout));
        // Like OpenSSH, note the server's banner as a comment (peeked, so
        // the handshake still reads it).
        if let Some(banner) = peek_banner(&stream) {
            println!("# {target_host}:{port} {banner}", target_host = addr.ip());
        }
        let _ = Client::connect_via(Box::new(stream), name, port, cfg);
        if let Some(k) = found.lock().ok().and_then(|mut g| g.take()) {
            // The algorithm name for RSA is the key type `ssh-rsa`.
            let key_type = if k.0.starts_with("rsa-sha2-") {
                "ssh-rsa".to_string()
            } else {
                k.0
            };
            return Some((key_type, k.1));
        }
    }
    None
}

/// The server's identification line, read without consuming it.
fn peek_banner(stream: &TcpStream) -> Option<String> {
    let mut buf = [0u8; 256];
    let start = std::time::Instant::now();
    while start.elapsed() < Duration::from_secs(5) {
        let n = stream.peek(&mut buf).ok()?;
        if n == 0 {
            return None;
        }
        if let Some(end) = buf[..n].iter().position(|b| *b == b'\n') {
            let line = String::from_utf8_lossy(&buf[..end]);
            return Some(line.trim_end_matches('\r').to_string());
        }
        if n == buf.len() {
            return None;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    None
}

fn run() -> Result<i32, String> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let o = parse_args(&args)?;
    let mut out = std::io::stdout();
    for spec in &o.hosts {
        // `addrlist namelist`: connect to the first list, print the second.
        let mut words = spec.split_whitespace();
        let addr_list = words.next().unwrap_or("");
        let names: Vec<&str> = words
            .next()
            .map(|n| n.split(',').collect())
            .unwrap_or_else(|| addr_list.split(',').collect());
        let target = addr_list.split(',').next().unwrap_or("");
        let addrs: Vec<SocketAddr> = match (target, o.port).to_socket_addrs() {
            Ok(a) => a
                .filter(|a| match o.family {
                    Some(true) => a.is_ipv4(),
                    Some(false) => a.is_ipv6(),
                    None => true,
                })
                .collect(),
            Err(e) => {
                eprintln!("{target}: {e}");
                continue;
            }
        };
        for ty in &o.types {
            let Some((_, algs)) = algorithms_for(ty) else {
                continue;
            };
            match scan_one(target, o.port, &addrs, algs, o.timeout) {
                Some((key_type, blob)) => {
                    let mut kh = KnownHosts::new();
                    for name in &names {
                        kh.add(name, o.port, &key_type, &blob, o.hash);
                    }
                    let _ = out.write_all(&kh.to_bytes());
                }
                None => {
                    if o.verbose {
                        eprintln!("# {target}:{} no {ty} host key", o.port);
                    }
                }
            }
        }
    }
    Ok(0)
}

fn main() -> ExitCode {
    match run() {
        Ok(code) => ExitCode::from(code as u8),
        Err(e) => {
            eprintln!("{e}");
            ExitCode::from(1)
        }
    }
}
