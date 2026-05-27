//! `ssh` — puressh's interactive SSH client.
//!
//! Usage (still scaffolding — the underlying [`puressh::client`] glue
//! is not wired up yet):
//!
//! ```text
//! ssh [-p port] [-i identity_file] user@host [command...]
//! ```

use std::process::ExitCode;

const VERSION: &str = env!("CARGO_PKG_VERSION");

fn usage(prog: &str) -> String {
    format!(
        "usage: {prog} [-p port] [-i identity_file] [user@]host [command...]\n\
         \n\
         A pure-Rust SSH client built on puressh {VERSION}."
    )
}

fn main() -> ExitCode {
    let mut args = std::env::args();
    let prog = args.next().unwrap_or_else(|| "ssh".into());

    let rest: Vec<String> = args.collect();
    if rest.iter().any(|a| a == "-h" || a == "--help") {
        println!("{}", usage(&prog));
        return ExitCode::SUCCESS;
    }
    if rest.iter().any(|a| a == "-V" || a == "--version") {
        println!("puressh ssh {VERSION}");
        return ExitCode::SUCCESS;
    }

    eprintln!("{}", usage(&prog));
    eprintln!("\nssh: client driver not yet implemented");
    ExitCode::from(2)
}
