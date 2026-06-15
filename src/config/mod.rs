//! OpenSSH-compatible `ssh_config` / `sshd_config` parser.
//!
//! `puressh::config` parses the two configuration files OpenSSH ships
//! (`ssh_config(5)` and `sshd_config(5)`). The grammar is shared, so this
//! crate exposes a single low-level tokenizer in [`parser`] and two
//! semantic layers on top — [`SshClientConfig`] for the client side, and
//! [`SshServerConfig`] for the daemon side. Both round-trip through
//! [`str::parse`]-like entry points and return a typed [`ConfigError`] on
//! bad input.
//!
//! The module is `alloc`-only — it parses `&str`. Reading the file off disk
//! and choosing the search path is up to the caller (the bin/common helpers
//! do this for `~/.ssh/config` and `/etc/ssh/ssh_config`).
//!
//! ## Example
//!
//! ```
//! use puressh::config::SshClientConfig;
//!
//! let src = "\
//! Host gw
//!   HostName 198.51.100.7
//!   User admin
//!   Port 2222
//! ";
//! let cfg = SshClientConfig::parse(src).unwrap();
//! let eff = cfg.lookup("gw");
//! assert_eq!(eff.host_name.as_deref(), Some("198.51.100.7"));
//! assert_eq!(eff.port, Some(2222));
//! assert_eq!(eff.user.as_deref(), Some("admin"));
//! ```

#![cfg(feature = "alloc")]

use alloc::string::String;

pub mod algos;
pub mod client;
pub mod glob;
pub mod host_port;
#[cfg(feature = "std")]
pub mod include;
pub mod match_block;
pub mod parser;
pub mod server;

pub use client::{
    AddressFamily, ClientOptions, DynamicForwardSpec, GatewayPorts, IdentityAgent,
    LocalForwardSpec, RemoteForwardSpec, RequestTty, SshClientConfig, StrictMode,
};
pub use glob::HostPattern;
pub use host_port::{parse_host_port, parse_host_port_pattern};
pub use match_block::{MatchCondition, MatchContext};
pub use server::{PermitRootLogin, SshServerConfig};

/// Errors produced while parsing or evaluating an SSH config file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigError {
    /// Lexical/structural failure (unterminated quote, bad block header, …).
    Syntax {
        /// 1-based source line number.
        line: usize,
        /// Human-readable description.
        msg: String,
    },
    /// Keyword present in the file but not recognised by this parser.
    UnknownKeyword {
        /// 1-based source line number.
        line: usize,
        /// The offending keyword (lowercased).
        keyword: String,
    },
    /// Value for a recognised keyword failed to parse (bad integer, bad
    /// enum, bad forward-spec, …).
    BadValue {
        /// 1-based source line number.
        line: usize,
        /// The keyword whose value was malformed.
        keyword: String,
        /// Human-readable description of what went wrong.
        msg: String,
    },
    /// Construct understood by OpenSSH but not yet implemented here (e.g.
    /// `Match` blocks in `sshd_config`).
    Unsupported {
        /// 1-based source line number.
        line: usize,
        /// Human-readable description of the unsupported construct.
        msg: String,
    },
}

impl core::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ConfigError::Syntax { line, msg } => {
                write!(f, "config: line {line}: syntax: {msg}")
            }
            ConfigError::UnknownKeyword { line, keyword } => {
                write!(f, "config: line {line}: unknown keyword: {keyword}")
            }
            ConfigError::BadValue { line, keyword, msg } => {
                write!(f, "config: line {line}: bad value for {keyword}: {msg}")
            }
            ConfigError::Unsupported { line, msg } => {
                write!(f, "config: line {line}: unsupported: {msg}")
            }
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for ConfigError {}
