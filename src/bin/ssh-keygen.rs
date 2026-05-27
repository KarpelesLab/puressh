//! `ssh-keygen` — puressh's key-generation and key-inspection tool.
//!
//! Subcommands (still scaffolding — the actual logic is not wired up yet):
//!
//! ```text
//! ssh-keygen -t ed25519 -N "" -f path        generate a keypair
//! ssh-keygen -l -f path[.pub]                print SHA-256 fingerprint
//! ssh-keygen -y -f path                      derive public key from a private key
//! ```

use std::process::ExitCode;

const VERSION: &str = env!("CARGO_PKG_VERSION");

const USAGE: &str = "usage: ssh-keygen -t TYPE [-N passphrase] -f path     (generate)\n       \
                     ssh-keygen -l -f path[.pub]                          (fingerprint)\n       \
                     ssh-keygen -y -f path                                (extract public)";

fn main() -> ExitCode {
    let mut args = std::env::args();
    let _prog = args.next().unwrap_or_else(|| "ssh-keygen".into());

    let rest: Vec<String> = args.collect();
    if rest.iter().any(|a| a == "-h" || a == "--help") {
        println!("{USAGE}");
        println!("\nA pure-Rust ssh-keygen built on puressh {VERSION}.");
        return ExitCode::SUCCESS;
    }
    if rest.iter().any(|a| a == "-V" || a == "--version") {
        println!("puressh ssh-keygen {VERSION}");
        return ExitCode::SUCCESS;
    }

    eprintln!("{USAGE}");
    eprintln!("\nssh-keygen: key operations not yet implemented");
    ExitCode::from(2)
}
