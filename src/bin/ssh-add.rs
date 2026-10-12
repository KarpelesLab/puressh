//! `ssh-add` — add private keys to, list and remove keys from the agent.
//!
//! ```text
//! ssh-add [-DdLlqXx] [-t life] [file ...]
//! ```
//!
//! Works with any agent speaking the standard protocol (puressh's
//! `ssh-agent` or OpenSSH's), found through `$SSH_AUTH_SOCK`. Without files
//! it adds the default identities (`~/.ssh/id_rsa`, `id_ecdsa`,
//! `id_ed25519`) that exist. Exit status: 0 on success, 1 on failure, 2 if
//! the agent cannot be reached.

#[cfg(not(unix))]
fn main() -> std::process::ExitCode {
    eprintln!("ssh-add: only supported on Unix-like systems");
    std::process::ExitCode::from(2)
}

#[cfg(unix)]
#[path = "common.rs"]
mod common;

#[cfg(unix)]
fn main() -> std::process::ExitCode {
    std::process::ExitCode::from(imp::run() as u8)
}

#[cfg(unix)]
mod imp {
    use super::common;
    use puressh::agent::Agent;
    use puressh::key::{PrivateKey, PublicKey};

    const USAGE: &str = "usage: ssh-add [-cDdKkLlqvXx] [-E fingerprint_hash] [-H hostkey_file]\n               [-h destination_constraint] [-S provider] [-t life]\n               [file ...]\n       ssh-add -s pkcs11 [-Cv] [certificate ...]\n       ssh-add -e pkcs11\n       ssh-add -T pubkey ...";

    #[derive(Default)]
    struct Opts {
        list: bool,
        list_full: bool,
        delete: bool,
        delete_all: bool,
        lock: bool,
        unlock: bool,
        quiet: bool,
        lifetime: Option<u32>,
        files: Vec<String>,
    }

    fn parse_lifetime(v: &str) -> Option<u32> {
        let mut total = 0u64;
        let mut num = String::new();
        for c in v.chars() {
            if c.is_ascii_digit() {
                num.push(c);
                continue;
            }
            let n: u64 = num.parse().ok()?;
            num.clear();
            total += n * match c.to_ascii_lowercase() {
                's' => 1,
                'm' => 60,
                'h' => 3600,
                'd' => 86400,
                'w' => 604800,
                _ => return None,
            };
        }
        if !num.is_empty() {
            total += num.parse::<u64>().ok()?;
        }
        u32::try_from(total).ok().filter(|t| *t > 0)
    }

    fn parse_args(args: &[String]) -> Result<Opts, String> {
        let mut o = Opts::default();
        let mut i = 0;
        while i < args.len() {
            let a = &args[i];
            if a == "--" {
                o.files.extend(args[i + 1..].iter().cloned());
                break;
            }
            if !a.starts_with('-') || a == "-" {
                o.files.push(a.clone());
                i += 1;
                continue;
            }
            let chars: Vec<char> = a[1..].chars().collect();
            let mut j = 0;
            while j < chars.len() {
                let c = chars[j];
                if "tEHhSse".contains(c) {
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
                        't' => {
                            o.lifetime = Some(
                                parse_lifetime(&v)
                                    .ok_or_else(|| format!("Invalid lifetime {v}"))?,
                            )
                        }
                        'E' => {}
                        'h' | 'H' => {
                            return Err("destination constraints (-h/-H) are not supported".into());
                        }
                        _ => return Err("PKCS#11 tokens (-s/-e/-S) are not supported".into()),
                    }
                    break;
                }
                match c {
                    'l' => o.list = true,
                    'L' => o.list_full = true,
                    'd' => o.delete = true,
                    'D' => o.delete_all = true,
                    'x' => o.lock = true,
                    'X' => o.unlock = true,
                    'q' => o.quiet = true,
                    'v' | 'k' | 'K' => {}
                    'c' => {
                        return Err("confirmation (-c) is not supported: keys would be usable \
                                    without the confirmation you asked for"
                            .into());
                    }
                    'C' | 'T' => return Err(format!("-{c} is not supported")),
                    _ => return Err(format!("unknown option -- {c}")),
                }
                j += 1;
            }
            i += 1;
        }
        Ok(o)
    }

    fn label(pk: &PublicKey) -> &'static str {
        match pk {
            PublicKey::Ed25519 { .. } => "ED25519",
            PublicKey::Rsa { .. } => "RSA",
            _ => "ECDSA",
        }
    }

    fn default_files() -> Vec<String> {
        let home = std::env::var("HOME").unwrap_or_default();
        ["id_rsa", "id_ecdsa", "id_ed25519"]
            .iter()
            .map(|n| format!("{home}/.ssh/{n}"))
            .filter(|p| std::path::Path::new(p).exists())
            .collect()
    }

    /// Read a private key, asking for its passphrase when it is encrypted.
    fn load_private(path: &str) -> Result<PrivateKey, String> {
        let pem = std::fs::read_to_string(path).map_err(|e| format!("{path}: {e}"))?;
        match PrivateKey::parse_pem(&pem, None) {
            Ok(k) => Ok(k),
            Err(puressh::Error::Crypto(_)) => {
                for _ in 0..3 {
                    let pass = common::read_secret(&format!("Enter passphrase for {path}: "))
                        .map_err(|e| format!("{path}: {e}"))?;
                    if pass.is_empty() {
                        break;
                    }
                    match PrivateKey::parse_pem(&pem, Some(pass.as_bytes())) {
                        Ok(k) => return Ok(k),
                        Err(_) => eprintln!("Bad passphrase, try again for {path}: "),
                    }
                }
                Err(format!("{path}: bad passphrase"))
            }
            Err(e) => Err(format!("{path}: {e}")),
        }
    }

    /// The public key of `path`: `path.pub` if present, else derived from
    /// the private key.
    fn load_public(path: &str) -> Result<PublicKey, String> {
        let pubfile = if path.ends_with(".pub") {
            path.to_string()
        } else {
            format!("{path}.pub")
        };
        if let Ok(line) = std::fs::read_to_string(&pubfile) {
            return PublicKey::parse_authorized_keys_line(line.trim())
                .map_err(|e| format!("{pubfile}: {e}"));
        }
        load_private(path).map(|k| k.public_key())
    }

    pub fn run() -> i32 {
        let args: Vec<String> = std::env::args().skip(1).collect();
        let o = match parse_args(&args) {
            Ok(o) => o,
            Err(e) => {
                eprintln!("{e}\n{USAGE}");
                return 1;
            }
        };
        let mut agent = match Agent::connect_env() {
            Ok(Some(a)) => a,
            Ok(None) => {
                eprintln!("Could not open a connection to your authentication agent.");
                return 2;
            }
            Err(puressh::Error::Io(e)) => {
                eprintln!("Error connecting to agent: {e}");
                return 2;
            }
            Err(e) => {
                eprintln!("Error connecting to agent: {e}");
                return 2;
            }
        };

        if o.list || o.list_full {
            let ids = match agent.identities() {
                Ok(ids) => ids,
                Err(e) => {
                    eprintln!("error fetching identities: {e}");
                    return 1;
                }
            };
            if ids.is_empty() {
                println!("The agent has no identities.");
                return 1;
            }
            for id in ids {
                let Ok(pk) = PublicKey::parse_wire_blob(id.key_blob()) else {
                    continue;
                };
                if o.list_full {
                    let mut line = pk.to_authorized_keys_line();
                    if !id.comment().is_empty() {
                        line = format!("{} {}", line.trim_end(), id.comment());
                    }
                    println!("{line}");
                } else {
                    println!(
                        "{} {} {} ({})",
                        pk.bit_length(),
                        pk.sha256_fingerprint(),
                        if id.comment().is_empty() {
                            "no comment"
                        } else {
                            id.comment()
                        },
                        label(&pk)
                    );
                }
            }
            return 0;
        }

        if o.lock || o.unlock {
            let pass = match common::read_secret("Enter lock password: ") {
                Ok(p) => p,
                Err(e) => {
                    eprintln!("{e}");
                    return 1;
                }
            };
            if o.lock {
                match common::read_secret("Again: ") {
                    Ok(again) if *again == *pass => {}
                    Ok(_) => {
                        eprintln!("Passwords do not match.");
                        return 1;
                    }
                    Err(e) => {
                        eprintln!("{e}");
                        return 1;
                    }
                }
                return match agent.lock(pass.as_bytes()) {
                    Ok(()) => {
                        eprintln!("Agent locked.");
                        0
                    }
                    Err(_) => {
                        eprintln!("Failed to lock agent.");
                        1
                    }
                };
            }
            return match agent.unlock(pass.as_bytes()) {
                Ok(()) => {
                    eprintln!("Agent unlocked.");
                    0
                }
                Err(_) => {
                    eprintln!("Failed to unlock agent.");
                    1
                }
            };
        }

        if o.delete_all {
            return match agent.remove_all_identities() {
                Ok(()) => {
                    if !o.quiet {
                        eprintln!("All identities removed.");
                    }
                    0
                }
                Err(_) => {
                    eprintln!("Failed to remove all identities.");
                    1
                }
            };
        }

        let files = if o.files.is_empty() {
            default_files()
        } else {
            o.files.clone()
        };
        let mut status = 0;
        for path in &files {
            if o.delete {
                let pk = match load_public(path) {
                    Ok(pk) => pk,
                    Err(e) => {
                        eprintln!("Bad key file {e}");
                        status = 1;
                        continue;
                    }
                };
                match agent.remove_identity(&pk.wire_blob()) {
                    Ok(()) => {
                        if !o.quiet {
                            eprintln!("Identity removed: {path} {} ({})", label(&pk), pk.comment());
                        }
                    }
                    Err(_) => {
                        eprintln!("Could not remove identity \"{path}\": agent refused operation");
                        status = 1;
                    }
                }
                continue;
            }
            let key = match load_private(path) {
                Ok(k) => k,
                Err(e) => {
                    eprintln!("{e}");
                    status = 1;
                    continue;
                }
            };
            let res = match o.lifetime {
                Some(t) => agent.add_identity_with_lifetime(&key, t),
                None => agent.add_identity(&key),
            };
            match res {
                Ok(()) => {
                    if !o.quiet {
                        eprintln!("Identity added: {path} ({})", key.comment());
                        if let Some(t) = o.lifetime {
                            eprintln!("Lifetime set to {t} seconds");
                        }
                    }
                }
                Err(_) => {
                    eprintln!("Could not add identity \"{path}\": agent refused operation");
                    status = 1;
                }
            }
        }
        status
    }
}
