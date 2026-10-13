//! `ssh-keyscan` — gather SSH host keys, in `known_hosts` format.
//!
//! ```text
//! ssh-keyscan [-46cDHqv] [-f file] [-O option] [-p port] [-T timeout] [-t type]
//!             [host | addrlist namelist] ...
//! ```
//!
//! Like OpenSSH's: for every host and every requested key type
//! (`rsa,ecdsa,ed25519,mldsa44-ed25519` by default) it opens a connection
//! offering only that type's host-key algorithms, completes the key exchange
//! to learn the key, and prints `host keytype base64` on stdout
//! (`[host]:port` for a non-default port; `-H` hashes the host names), each
//! host preceded by a `# host:port banner` comment (not with `-q`). `-c`
//! asks for certificates instead, `-D` prints SSHFP records. Diagnostics go
//! to stderr. Hosts that cannot be reached or offer no key of a type are
//! skipped.

use std::io::{BufRead, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::process::ExitCode;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use puressh::client::{
    AlgoOverrides, Client, Config, HostKeyPolicy, KnownHostsPolicy, TofuAction, TofuPromptFn,
};
use puressh::known_hosts::KnownHosts;

const USAGE: &str = "usage: ssh-keyscan [-46cDHqv] [-f file] [-O option] [-p port] [-T timeout]\n\
                     \t\t   [-t type] [host | addrlist namelist]";

struct Opts {
    family: Option<bool>, // Some(true) = IPv4 only, Some(false) = IPv6 only
    hash: bool,
    verbose: bool,
    quiet: bool,
    /// `-c`: certificates.
    certs: bool,
    /// `-D`: SSHFP records, with `-O hashalg=` choosing one digest.
    sshfp: bool,
    sshfp_hash: Option<u8>,
    port: u16,
    timeout: Duration,
    types: Vec<&'static str>,
    hosts: Vec<String>,
}

/// Host-key algorithms offered when scanning for one key type (`cert`:
/// its certificates), as OpenSSH's.
fn algorithms_for(ty: &str, cert: bool) -> &'static [&'static str] {
    match (ty, cert) {
        ("rsa", false) => &["rsa-sha2-512", "rsa-sha2-256", "ssh-rsa"],
        ("rsa", true) => &[
            "rsa-sha2-512-cert-v01@openssh.com",
            "rsa-sha2-256-cert-v01@openssh.com",
            "ssh-rsa-cert-v01@openssh.com",
        ],
        ("ecdsa", false) => &[
            "ecdsa-sha2-nistp256",
            "ecdsa-sha2-nistp384",
            "ecdsa-sha2-nistp521",
        ],
        ("ecdsa", true) => &[
            "ecdsa-sha2-nistp256-cert-v01@openssh.com",
            "ecdsa-sha2-nistp384-cert-v01@openssh.com",
            "ecdsa-sha2-nistp521-cert-v01@openssh.com",
        ],
        ("ed25519", false) => &["ssh-ed25519"],
        ("ed25519", true) => &["ssh-ed25519-cert-v01@openssh.com"],
        ("mldsa44-ed25519", false) => &["ssh-mldsa44-ed25519@openssh.com"],
        ("mldsa44-ed25519", true) => &["ssh-mldsa44-ed25519-cert-v01@openssh.com"],
        _ => &[],
    }
}

fn parse_args(args: &[String]) -> Result<Opts, String> {
    let mut o = Opts {
        family: None,
        hash: false,
        verbose: false,
        quiet: false,
        certs: false,
        sshfp: false,
        sshfp_hash: None,
        port: 22,
        timeout: Duration::from_secs(5),
        types: vec!["rsa", "ecdsa", "ed25519", "mldsa44-ed25519"],
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
            if "fOpTt".contains(c) {
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
                    'O' => match v.strip_prefix("hashalg=") {
                        Some("sha1") => o.sshfp_hash = Some(1),
                        Some("sha256") => o.sshfp_hash = Some(2),
                        Some(other) => return Err(format!("Unsupported hash algorithm {other}")),
                        None => return Err("Unsupported -O option".into()),
                    },
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
                                "ssh-mldsa44-ed25519@openssh.com" | "mldsa44-ed25519" => {
                                    "mldsa44-ed25519"
                                }
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
                'q' => o.quiet = true,
                'c' => o.certs = true,
                'D' => o.sshfp = true,
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
    comment: Option<char>,
) -> Option<(String, Vec<u8>)> {
    let found: Arc<Mutex<Option<KeyFound>>> = Arc::new(Mutex::new(None));
    for addr in addrs {
        let sink = found.clone();
        let capture: Arc<TofuPromptFn> = Arc::new(move |_h, _p, key_type, blob| {
            if let Ok(mut g) = sink.lock()
                && g.is_none()
            {
                *g = Some((key_type.to_string(), blob.to_vec()));
            }
            // Refuse: we only wanted the key, not a session.
            false
        });
        let mut policy = KnownHostsPolicy::strict(Arc::new(Mutex::new(KnownHosts::new())));
        policy.on_unknown = TofuAction::Prompt(capture);
        // The key as presented (a certificate, for `-c`), before a
        // certificate is reduced to the key it certifies.
        let first = found.clone();
        policy.command = Some(Arc::new(move |key_type: &str, blob: &[u8]| {
            if let Ok(mut g) = first.lock()
                && g.is_none()
            {
                *g = Some((key_type.to_string(), blob.to_vec()));
            }
            None
        }));
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
        if let Some(c) = comment
            && let Some(banner) = peek_banner(&stream)
        {
            println!("{c} {name}:{port} {banner}");
        }
        let _ = Client::connect_via(Box::new(stream), name, port, cfg);
        if let Some(k) = found.lock().ok().and_then(|mut g| g.take()) {
            // The algorithm name for RSA is the key type `ssh-rsa`.
            let key_type = if k.0.starts_with("rsa-sha2-") && !k.0.contains("-cert-") {
                "ssh-rsa".to_string()
            } else if k.0.starts_with("rsa-sha2-") {
                "ssh-rsa-cert-v01@openssh.com".to_string()
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
    let mut found_one = false;
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
        let comment = (!o.quiet).then_some(if o.sshfp { ';' } else { '#' });
        for ty in &o.types {
            let algs = algorithms_for(ty, o.certs);
            match scan_one(target, o.port, &addrs, algs, o.timeout, comment) {
                Some((key_type, blob)) => {
                    found_one = true;
                    print_key(&o, &names, &key_type, &blob, &mut out)
                }
                None => {
                    if o.verbose {
                        eprintln!("# {target}:{} no {ty} host key", o.port);
                    }
                }
            }
        }
    }
    // As OpenSSH: failure when no key was found at all.
    Ok(if found_one { 0 } else { 1 })
}

/// Print a key found for `names`, as OpenSSH's `keyprint`: one line naming
/// every host (port 22, unhashed, or a certificate), else one per host.
fn print_key(o: &Opts, names: &[&str], key_type: &str, blob: &[u8], out: &mut impl Write) {
    let joined = names.join(",");
    let hosts: Vec<&str> = if o.certs || (!o.hash && o.port == 22) {
        vec![joined.as_str()]
    } else {
        names.to_vec()
    };
    let b64 = purecrypto::der::base64_encode(blob);
    for host in hosts {
        let line = if o.sshfp {
            sshfp_lines(host, blob, o.sshfp_hash)
        } else if o.certs {
            format!("{key_type} {b64}\n")
        } else if o.hash {
            let mut kh = KnownHosts::new();
            kh.add(host, o.port, key_type, blob, true);
            String::from_utf8_lossy(&kh.to_bytes()).into_owned()
        } else {
            let host = host.to_ascii_lowercase();
            if o.port == 22 {
                format!("{host} {key_type} {b64}\n")
            } else {
                format!("[{host}]:{} {key_type} {b64}\n", o.port)
            }
        };
        let _ = out.write_all(line.as_bytes());
    }
}

/// `host IN SSHFP alg fptype digest` lines (SHA-1 and SHA-256, or the one
/// `-O hashalg=` names); none for a key type without an SSHFP number.
fn sshfp_lines(host: &str, blob: &[u8], only: Option<u8>) -> String {
    use purecrypto::hash::{Digest, Sha1, Sha256};
    let Some(alg) = puressh::key::PublicKey::parse_wire_blob(blob)
        .ok()
        .and_then(|k| k.sshfp_algorithm())
    else {
        return String::new();
    };
    let mut out = String::new();
    for (fptype, digest) in [
        (1u8, Sha1::digest(blob).as_ref().to_vec()),
        (2, Sha256::digest(blob).as_ref().to_vec()),
    ] {
        if only.is_some_and(|o| o != fptype) {
            continue;
        }
        let hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
        out.push_str(&format!("{host} IN SSHFP {alg} {fptype} {hex}\n"));
    }
    out
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
