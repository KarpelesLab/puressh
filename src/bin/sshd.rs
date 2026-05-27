//! `sshd` — puressh's SSH server daemon.
//!
//! Usage (still scaffolding — the underlying [`puressh::server`] glue
//! is not wired up yet):
//!
//! ```text
//! sshd [-d] [-p port] [-h host_key_file]...
//! ```

use std::process::ExitCode;

const VERSION: &str = env!("CARGO_PKG_VERSION");

fn usage(prog: &str) -> String {
    format!(
        "usage: {prog} [-d] [-p port] [-h host_key_file]...\n\
         \n\
         A pure-Rust SSH server daemon built on puressh {VERSION}."
    )
}

fn main() -> ExitCode {
    let mut args = std::env::args();
    let prog = args.next().unwrap_or_else(|| "sshd".into());

    let rest: Vec<String> = args.collect();
    if rest.iter().any(|a| a == "-?" || a == "--help") {
        println!("{}", usage(&prog));
        return ExitCode::SUCCESS;
    }
    if rest.iter().any(|a| a == "-V" || a == "--version") {
        println!("puressh sshd {VERSION}");
        return ExitCode::SUCCESS;
    }

    eprintln!("{}", usage(&prog));
    eprintln!("\nsshd: server driver not yet implemented");
    ExitCode::from(2)
}
