//! `ssh_config(5)` parsing — see [`SshClientConfig`].
//!
//! Only the keywords the puressh client binaries actually consume today are
//! recognised; any other keyword is rejected as
//! [`ConfigError::UnknownKeyword`]. This is deliberate: the scope is "config
//! values that change observable behaviour", and silently dropping an
//! unrecognised knob is worse than failing loudly.

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;

use super::glob::{host_matches, HostPattern};
use super::parser::{tokenize, ParsedLine};
use super::ConfigError;

/// `StrictHostKeyChecking` value — maps OpenSSH's keyword set to puressh's
/// TOFU policy. Re-exported as `puressh::config::StrictMode` and re-exported
/// once more from `src/bin/common.rs` so existing binaries keep compiling.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StrictMode {
    /// `yes`: refuse Unknown; reject Mismatch.
    Yes,
    /// `no`: accept Unknown silently AND tolerate Mismatch (insecure).
    No,
    /// `accept-new`: silently accept Unknown; still reject Mismatch.
    AcceptNew,
    /// `ask` (OpenSSH default): prompt on Unknown; reject Mismatch.
    Ask,
}

/// `RequestTTY` value. Distinct from a CLI bool: `Auto` means "PTY if local
/// stdin is a tty" — the binary needs the original token so it can decide
/// late.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RequestTty {
    /// `no`: never allocate.
    No,
    /// `yes`: allocate when there's an interactive session (default for
    /// interactive shells).
    Yes,
    /// `force`: always allocate.
    Force,
    /// `auto`: allocate iff local stdin is a tty.
    Auto,
}

/// One `LocalForward` entry. Wire form `[bind:]port host:hostport`, e.g.
/// `8080 example.com:80` or `127.0.0.1:8080 example.com:80`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LocalForwardSpec {
    /// Local bind address; `None` ⇒ loopback (`127.0.0.1`).
    pub bind_addr: Option<String>,
    /// Local port to listen on.
    pub listen_port: u16,
    /// Remote destination host (resolved server-side).
    pub remote_host: String,
    /// Remote destination port.
    pub remote_port: u16,
}

/// One `RemoteForward` entry. Wire form `[bind:]port host:hostport`, e.g.
/// `8080 127.0.0.1:8080`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RemoteForwardSpec {
    /// Remote bind address; `None` ⇒ loopback on the server side.
    pub bind_addr: Option<String>,
    /// Remote port the server should bind.
    pub remote_port: u16,
    /// Local destination host (resolved client-side).
    pub local_host: String,
    /// Local destination port.
    pub local_port: u16,
}

/// Per-host options. Every field is `Option`-typed so callers can distinguish
/// "not set" from "set to default" and apply OpenSSH precedence (CLI > file >
/// built-in default) via a `pick(cli, cfg, default)` helper.
#[derive(Default, Clone, Debug, PartialEq, Eq)]
pub struct ClientOptions {
    /// `HostName`: real hostname to connect to (the `Host` block name is just a label).
    pub host_name: Option<String>,
    /// `Port`: TCP port for the SSH session.
    pub port: Option<u16>,
    /// `User`: remote username.
    pub user: Option<String>,
    /// `IdentityFile` (cumulative across matching blocks).
    pub identity_files: Vec<String>,
    /// `IdentitiesOnly` (yes/no).
    pub identities_only: Option<bool>,
    /// `StrictHostKeyChecking`.
    pub strict_host_key: Option<StrictMode>,
    /// `UserKnownHostsFile`.
    pub user_known_hosts: Option<String>,
    /// `HashKnownHosts` (yes/no).
    pub hash_known_hosts: Option<bool>,
    /// `LocalForward` entries (cumulative).
    pub local_forwards: Vec<LocalForwardSpec>,
    /// `RemoteForward` entries (cumulative).
    pub remote_forwards: Vec<RemoteForwardSpec>,
    /// `ForwardAgent` (yes/no).
    pub forward_agent: Option<bool>,
    /// `ForwardX11` (yes/no).
    pub forward_x11: Option<bool>,
    /// `ForwardX11Trusted` (yes/no).
    pub forward_x11_trusted: Option<bool>,
    /// `RequestTTY` (yes/no/force/auto).
    pub request_tty: Option<RequestTty>,
    /// `LogLevel`: 0 = QUIET/INFO, 1 = VERBOSE/DEBUG1, 2 = DEBUG2, 3 = DEBUG3.
    pub log_level: Option<u8>,
}

/// One `Host` block in a parsed `ssh_config`.
#[derive(Clone, Debug)]
struct HostBlock {
    patterns: Vec<HostPattern>,
    opts: ClientOptions,
}

/// A parsed `ssh_config(5)` file.
///
/// Use [`SshClientConfig::parse`] to construct one from text, then
/// [`SshClientConfig::lookup`] to flatten the matching blocks for a target
/// host. Pre-`Host` lines form an implicit "global" block applied to every
/// host (OpenSSH's documented behaviour).
#[derive(Clone, Debug, Default)]
pub struct SshClientConfig {
    blocks: Vec<HostBlock>,
}

impl SshClientConfig {
    /// Parse `src` (the contents of a `ssh_config` file) into an
    /// [`SshClientConfig`].
    pub fn parse(src: &str) -> Result<Self, ConfigError> {
        let lines = tokenize(src)?;
        // Implicit global block at index 0; the OpenSSH default semantics
        // apply pre-`Host` lines to every host.
        let mut blocks: Vec<HostBlock> = vec![HostBlock {
            patterns: vec![HostPattern::Any],
            opts: ClientOptions::default(),
        }];
        for line in lines {
            if line.keyword == "host" {
                if line.args.is_empty() {
                    return Err(ConfigError::BadValue {
                        line: line.line_no,
                        keyword: "host".to_string(),
                        msg: "Host requires at least one pattern".into(),
                    });
                }
                blocks.push(HostBlock {
                    patterns: HostPattern::parse_all(&line.args),
                    opts: ClientOptions::default(),
                });
                continue;
            }
            if line.keyword == "match" {
                return Err(ConfigError::Unsupported {
                    line: line.line_no,
                    msg: "ssh_config Match blocks not yet supported".into(),
                });
            }
            let current = blocks.last_mut().expect("global block always present");
            apply_keyword(&mut current.opts, &line)?;
        }
        Ok(SshClientConfig { blocks })
    }

    /// Resolve the effective options for `host`, walking every matching
    /// block in source order with OpenSSH **first-match-wins** semantics for
    /// scalars and **concatenation** for cumulative list fields
    /// (`IdentityFile`, `LocalForward`, `RemoteForward`).
    pub fn lookup(&self, host: &str) -> ClientOptions {
        let mut out = ClientOptions::default();
        for block in &self.blocks {
            if host_matches(&block.patterns, host) {
                merge_into(&mut out, &block.opts);
            }
        }
        out
    }
}

/// Apply one parsed line to the in-progress [`ClientOptions`] of the current
/// block.
fn apply_keyword(opts: &mut ClientOptions, line: &ParsedLine) -> Result<(), ConfigError> {
    let kw = line.keyword.as_str();
    let args = &line.args;
    match kw {
        "hostname" => {
            opts.host_name = Some(one_arg(line)?);
        }
        "port" => {
            opts.port = Some(parse_u16(line)?);
        }
        "user" => {
            opts.user = Some(one_arg(line)?);
        }
        "identityfile" => {
            opts.identity_files.push(one_arg(line)?);
        }
        "identitiesonly" => {
            opts.identities_only = Some(parse_yes_no(line)?);
        }
        "stricthostkeychecking" => {
            opts.strict_host_key = Some(parse_strict(line)?);
        }
        "userknownhostsfile" => {
            opts.user_known_hosts = Some(one_arg(line)?);
        }
        "hashknownhosts" => {
            opts.hash_known_hosts = Some(parse_yes_no(line)?);
        }
        "localforward" => {
            opts.local_forwards.push(parse_local_forward(line)?);
        }
        "remoteforward" => {
            opts.remote_forwards.push(parse_remote_forward(line)?);
        }
        "forwardagent" => {
            opts.forward_agent = Some(parse_yes_no(line)?);
        }
        "forwardx11" => {
            opts.forward_x11 = Some(parse_yes_no(line)?);
        }
        "forwardx11trusted" => {
            opts.forward_x11_trusted = Some(parse_yes_no(line)?);
        }
        "requesttty" => {
            opts.request_tty = Some(parse_request_tty(line)?);
        }
        "loglevel" => {
            opts.log_level = Some(parse_log_level(line)?);
        }
        _ => {
            return Err(ConfigError::UnknownKeyword {
                line: line.line_no,
                keyword: kw.to_string(),
            });
        }
    }
    let _ = args;
    Ok(())
}

/// First-match-wins merge of `src` over `dst`. Scalars only overwrite if
/// `dst` had `None`; list fields concatenate.
fn merge_into(dst: &mut ClientOptions, src: &ClientOptions) {
    macro_rules! take_scalar {
        ($field:ident) => {
            if dst.$field.is_none() {
                dst.$field = src.$field.clone();
            }
        };
    }
    take_scalar!(host_name);
    take_scalar!(port);
    take_scalar!(user);
    take_scalar!(identities_only);
    take_scalar!(strict_host_key);
    take_scalar!(user_known_hosts);
    take_scalar!(hash_known_hosts);
    take_scalar!(forward_agent);
    take_scalar!(forward_x11);
    take_scalar!(forward_x11_trusted);
    take_scalar!(request_tty);
    take_scalar!(log_level);
    dst.identity_files
        .extend(src.identity_files.iter().cloned());
    dst.local_forwards
        .extend(src.local_forwards.iter().cloned());
    dst.remote_forwards
        .extend(src.remote_forwards.iter().cloned());
}

fn one_arg(line: &ParsedLine) -> Result<String, ConfigError> {
    if line.args.len() != 1 {
        return Err(ConfigError::BadValue {
            line: line.line_no,
            keyword: line.keyword.clone(),
            msg: format!("expected 1 value, got {}", line.args.len()),
        });
    }
    Ok(line.args[0].clone())
}

fn parse_u16(line: &ParsedLine) -> Result<u16, ConfigError> {
    let s = one_arg(line)?;
    s.parse::<u16>().map_err(|_| ConfigError::BadValue {
        line: line.line_no,
        keyword: line.keyword.clone(),
        msg: format!("expected a port number, got {s:?}"),
    })
}

fn parse_yes_no(line: &ParsedLine) -> Result<bool, ConfigError> {
    let s = one_arg(line)?.to_ascii_lowercase();
    match s.as_str() {
        "yes" | "true" | "on" => Ok(true),
        "no" | "false" | "off" => Ok(false),
        _ => Err(ConfigError::BadValue {
            line: line.line_no,
            keyword: line.keyword.clone(),
            msg: format!("expected yes/no, got {s:?}"),
        }),
    }
}

fn parse_strict(line: &ParsedLine) -> Result<StrictMode, ConfigError> {
    let s = one_arg(line)?.to_ascii_lowercase();
    match s.as_str() {
        "yes" => Ok(StrictMode::Yes),
        "no" | "off" => Ok(StrictMode::No),
        "accept-new" => Ok(StrictMode::AcceptNew),
        "ask" => Ok(StrictMode::Ask),
        _ => Err(ConfigError::BadValue {
            line: line.line_no,
            keyword: line.keyword.clone(),
            msg: format!("expected yes/no/accept-new/ask/off, got {s:?}"),
        }),
    }
}

fn parse_request_tty(line: &ParsedLine) -> Result<RequestTty, ConfigError> {
    let s = one_arg(line)?.to_ascii_lowercase();
    match s.as_str() {
        "no" => Ok(RequestTty::No),
        "yes" => Ok(RequestTty::Yes),
        "force" => Ok(RequestTty::Force),
        "auto" => Ok(RequestTty::Auto),
        _ => Err(ConfigError::BadValue {
            line: line.line_no,
            keyword: line.keyword.clone(),
            msg: format!("expected no/yes/force/auto, got {s:?}"),
        }),
    }
}

fn parse_log_level(line: &ParsedLine) -> Result<u8, ConfigError> {
    let s = one_arg(line)?.to_ascii_uppercase();
    match s.as_str() {
        "QUIET" | "FATAL" | "ERROR" | "INFO" => Ok(0),
        "VERBOSE" | "DEBUG" | "DEBUG1" => Ok(1),
        "DEBUG2" => Ok(2),
        "DEBUG3" => Ok(3),
        _ => Err(ConfigError::BadValue {
            line: line.line_no,
            keyword: line.keyword.clone(),
            msg: format!("expected QUIET..DEBUG3, got {s:?}"),
        }),
    }
}

/// Parse a `LocalForward` argument list. OpenSSH accepts two whitespace-
/// separated tokens: `[bind:]port host:hostport`.
fn parse_local_forward(line: &ParsedLine) -> Result<LocalForwardSpec, ConfigError> {
    if line.args.len() != 2 {
        return Err(ConfigError::BadValue {
            line: line.line_no,
            keyword: line.keyword.clone(),
            msg: format!("expected 2 tokens, got {}", line.args.len()),
        });
    }
    let (bind_addr, listen_port) = split_bind_port(&line.args[0], line)?;
    let (remote_host, remote_port) = split_host_port(&line.args[1], line)?;
    Ok(LocalForwardSpec {
        bind_addr,
        listen_port,
        remote_host,
        remote_port,
    })
}

/// Parse a `RemoteForward` argument list. Same shape as `LocalForward`.
fn parse_remote_forward(line: &ParsedLine) -> Result<RemoteForwardSpec, ConfigError> {
    if line.args.len() != 2 {
        return Err(ConfigError::BadValue {
            line: line.line_no,
            keyword: line.keyword.clone(),
            msg: format!("expected 2 tokens, got {}", line.args.len()),
        });
    }
    let (bind_addr, remote_port) = split_bind_port(&line.args[0], line)?;
    let (local_host, local_port) = split_host_port(&line.args[1], line)?;
    Ok(RemoteForwardSpec {
        bind_addr,
        remote_port,
        local_host,
        local_port,
    })
}

/// `[bind:]port` → `(Some("bind"), port)` or `(None, port)`. IPv6 literal
/// addresses must be bracketed (`[::1]:port`).
fn split_bind_port(s: &str, line: &ParsedLine) -> Result<(Option<String>, u16), ConfigError> {
    if let Some(rest) = s.strip_prefix('[') {
        // `[addr]:port`
        if let Some((addr, port)) = rest.split_once("]:") {
            let port = port.parse::<u16>().map_err(|_| ConfigError::BadValue {
                line: line.line_no,
                keyword: line.keyword.clone(),
                msg: format!("bad port in {s:?}"),
            })?;
            return Ok((Some(addr.to_string()), port));
        }
        return Err(ConfigError::BadValue {
            line: line.line_no,
            keyword: line.keyword.clone(),
            msg: format!("malformed bracketed bind:port {s:?}"),
        });
    }
    match s.rsplit_once(':') {
        Some((addr, port)) => {
            let port = port.parse::<u16>().map_err(|_| ConfigError::BadValue {
                line: line.line_no,
                keyword: line.keyword.clone(),
                msg: format!("bad port in {s:?}"),
            })?;
            Ok((Some(addr.to_string()), port))
        }
        None => {
            let port = s.parse::<u16>().map_err(|_| ConfigError::BadValue {
                line: line.line_no,
                keyword: line.keyword.clone(),
                msg: format!("expected port or addr:port, got {s:?}"),
            })?;
            Ok((None, port))
        }
    }
}

/// `host:port` or `[host]:port`.
fn split_host_port(s: &str, line: &ParsedLine) -> Result<(String, u16), ConfigError> {
    if let Some(rest) = s.strip_prefix('[') {
        if let Some((addr, port)) = rest.split_once("]:") {
            let port = port.parse::<u16>().map_err(|_| ConfigError::BadValue {
                line: line.line_no,
                keyword: line.keyword.clone(),
                msg: format!("bad port in {s:?}"),
            })?;
            return Ok((addr.to_string(), port));
        }
        return Err(ConfigError::BadValue {
            line: line.line_no,
            keyword: line.keyword.clone(),
            msg: format!("malformed bracketed host:port {s:?}"),
        });
    }
    match s.rsplit_once(':') {
        Some((host, port)) => {
            let port = port.parse::<u16>().map_err(|_| ConfigError::BadValue {
                line: line.line_no,
                keyword: line.keyword.clone(),
                msg: format!("bad port in {s:?}"),
            })?;
            Ok((host.to_string(), port))
        }
        None => Err(ConfigError::BadValue {
            line: line.line_no,
            keyword: line.keyword.clone(),
            msg: format!("expected host:port, got {s:?}"),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_minimal() {
        let src = "\
Host gw
  HostName 198.51.100.7
  User admin
  Port 2222
";
        let cfg = SshClientConfig::parse(src).unwrap();
        let eff = cfg.lookup("gw");
        assert_eq!(eff.host_name.as_deref(), Some("198.51.100.7"));
        assert_eq!(eff.port, Some(2222));
        assert_eq!(eff.user.as_deref(), Some("admin"));
    }

    #[test]
    fn global_block_applies() {
        let src = "\
User globaluser
IdentitiesOnly yes
Host gw
  Port 2222
";
        let cfg = SshClientConfig::parse(src).unwrap();
        let eff = cfg.lookup("gw");
        assert_eq!(eff.user.as_deref(), Some("globaluser"));
        assert_eq!(eff.port, Some(2222));
        assert_eq!(eff.identities_only, Some(true));
    }

    #[test]
    fn first_match_wins_for_scalars() {
        // Two matching blocks; the FIRST set wins.
        let src = "\
Host *.example.com
  User firstuser
Host *
  User otheruser
";
        let cfg = SshClientConfig::parse(src).unwrap();
        let eff = cfg.lookup("host.example.com");
        assert_eq!(eff.user.as_deref(), Some("firstuser"));
    }

    #[test]
    fn identity_files_cumulative() {
        let src = "\
Host *
  IdentityFile ~/.ssh/id_a
Host gw
  IdentityFile ~/.ssh/id_b
";
        let cfg = SshClientConfig::parse(src).unwrap();
        let eff = cfg.lookup("gw");
        assert_eq!(eff.identity_files, vec!["~/.ssh/id_a", "~/.ssh/id_b"]);
    }

    #[test]
    fn local_forward_parses() {
        let src = "\
Host gw
  LocalForward 8080 example.com:80
  LocalForward 127.0.0.1:9090 backend:443
";
        let cfg = SshClientConfig::parse(src).unwrap();
        let eff = cfg.lookup("gw");
        assert_eq!(eff.local_forwards.len(), 2);
        assert_eq!(eff.local_forwards[0].bind_addr, None);
        assert_eq!(eff.local_forwards[0].listen_port, 8080);
        assert_eq!(eff.local_forwards[0].remote_host, "example.com");
        assert_eq!(eff.local_forwards[0].remote_port, 80);
        assert_eq!(
            eff.local_forwards[1].bind_addr.as_deref(),
            Some("127.0.0.1")
        );
        assert_eq!(eff.local_forwards[1].listen_port, 9090);
    }

    #[test]
    fn ipv6_bracketed_bind() {
        let src = "\
Host gw
  LocalForward [::1]:8080 example.com:80
";
        let cfg = SshClientConfig::parse(src).unwrap();
        let eff = cfg.lookup("gw");
        assert_eq!(eff.local_forwards[0].bind_addr.as_deref(), Some("::1"));
        assert_eq!(eff.local_forwards[0].listen_port, 8080);
    }

    #[test]
    fn negated_host_excludes() {
        let src = "\
Host *.example.com !secret.example.com
  User foo
";
        let cfg = SshClientConfig::parse(src).unwrap();
        assert_eq!(cfg.lookup("ok.example.com").user.as_deref(), Some("foo"));
        assert_eq!(cfg.lookup("secret.example.com").user, None);
    }

    #[test]
    fn unknown_keyword_errors() {
        let src = "Host gw\n  CompressionLevel 9\n";
        let err = SshClientConfig::parse(src).unwrap_err();
        match err {
            ConfigError::UnknownKeyword { keyword, line } => {
                assert_eq!(keyword, "compressionlevel");
                assert_eq!(line, 2);
            }
            _ => panic!("wrong error: {err:?}"),
        }
    }

    #[test]
    fn match_block_unsupported() {
        let src = "Match Host *\n  User foo\n";
        let err = SshClientConfig::parse(src).unwrap_err();
        match err {
            ConfigError::Unsupported { line, .. } => assert_eq!(line, 1),
            _ => panic!("wrong error: {err:?}"),
        }
    }

    #[test]
    fn strict_host_key_values() {
        for (s, want) in [
            ("yes", StrictMode::Yes),
            ("no", StrictMode::No),
            ("off", StrictMode::No),
            ("accept-new", StrictMode::AcceptNew),
            ("ask", StrictMode::Ask),
        ] {
            let src = format!("StrictHostKeyChecking {s}\n");
            let cfg = SshClientConfig::parse(&src).unwrap();
            assert_eq!(cfg.lookup("anything").strict_host_key, Some(want));
        }
    }

    #[test]
    fn request_tty_values() {
        for (s, want) in [
            ("no", RequestTty::No),
            ("yes", RequestTty::Yes),
            ("force", RequestTty::Force),
            ("auto", RequestTty::Auto),
        ] {
            let src = format!("RequestTTY {s}\n");
            let cfg = SshClientConfig::parse(&src).unwrap();
            assert_eq!(cfg.lookup("anything").request_tty, Some(want));
        }
    }

    #[test]
    fn equals_separator_accepted() {
        let src = "Host gw\n  Port=2222\n";
        let cfg = SshClientConfig::parse(src).unwrap();
        assert_eq!(cfg.lookup("gw").port, Some(2222));
    }
}
