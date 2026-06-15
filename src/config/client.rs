//! `ssh_config(5)` parsing — see [`SshClientConfig`].
//!
//! Only the keywords the puressh client binaries actually consume today are
//! recognised; any other keyword is rejected as
//! [`ConfigError::UnknownKeyword`]. This is deliberate: the scope is "config
//! values that change observable behaviour", and silently dropping an
//! unrecognised knob is worse than failing loudly.
//!
//! The file is a sequence of blocks. `Host <pattern>` opens a host-pattern
//! block, `Match <criteria>` opens a Match block, and everything before the
//! first block belongs to an implicit "global" Host * block. Settings inside a
//! block apply when the block's selector matches the lookup target;
//! [`SshClientConfig::lookup`] walks the blocks in order with OpenSSH's
//! first-match-wins precedence (scalars) and cumulative-concatenation
//! semantics (`IdentityFile`, `LocalForward`, `RemoteForward`).

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;

use super::ConfigError;
use super::glob::{HostPattern, host_matches};
use super::match_block::{ExecPolicy, MatchCondition, MatchContext, all_match, parse_match_line};
use super::parser::{ParsedLine, tokenize};

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

/// One block in a parsed `ssh_config` — either a `Host` block or a `Match`
/// block. Pre-block lines go into an implicit `Host *` block at index 0.
#[derive(Clone, Debug)]
pub(crate) enum Block {
    Host {
        patterns: Vec<HostPattern>,
        opts: ClientOptions,
    },
    Match {
        conditions: Vec<MatchCondition>,
        opts: ClientOptions,
    },
}

impl Block {
    fn opts(&self) -> &ClientOptions {
        match self {
            Block::Host { opts, .. } | Block::Match { opts, .. } => opts,
        }
    }
    fn opts_mut(&mut self) -> &mut ClientOptions {
        match self {
            Block::Host { opts, .. } | Block::Match { opts, .. } => opts,
        }
    }
}

/// A parsed `ssh_config(5)` file.
///
/// Use [`SshClientConfig::parse`] to construct one from text, then
/// [`SshClientConfig::lookup`] (or [`SshClientConfig::lookup_with`] for full
/// `Match` evaluation) to flatten the matching blocks for a target host.
/// Pre-`Host` lines form an implicit "global" block applied to every host
/// (OpenSSH's documented behaviour).
#[derive(Clone, Debug, Default)]
pub struct SshClientConfig {
    pub(crate) blocks: Vec<Block>,
    /// Whether `Match exec` criteria are allowed to execute. Default `false`
    /// (deny). Toggle with [`Self::enable_match_exec`].
    enable_match_exec: bool,
}

impl SshClientConfig {
    /// Parse `src` (the contents of a `ssh_config` file) into an
    /// [`SshClientConfig`]. `Match exec` evaluation is **off** by default;
    /// see [`Self::enable_match_exec`].
    ///
    /// `Include` directives are not resolved by this entry point because
    /// inline parsing has no filesystem context to anchor relative paths to.
    /// Use [`Self::load`] (or [`Self::load_with_base`]) to parse a file with
    /// Include support.
    pub fn parse(src: &str) -> Result<Self, ConfigError> {
        let lines = tokenize(src)?;
        let blocks = parse_blocks(lines)?;
        Ok(SshClientConfig {
            blocks,
            enable_match_exec: false,
        })
    }

    /// Read `path` from disk and parse it, resolving `Include` directives
    /// recursively. Relative paths inside `Include` are anchored to the
    /// directory of the file containing the directive; `~` expands to
    /// `$HOME`; `*` / `?` globs are expanded against the filesystem.
    /// Recursion is capped at [`super::include::MAX_INCLUDE_DEPTH`] hops.
    #[cfg(feature = "std")]
    pub fn load<P: AsRef<std::path::Path>>(path: P) -> Result<Self, ConfigError> {
        let lines = super::include::tokenize_file_with_includes(path.as_ref(), 0)?;
        let blocks = parse_blocks(lines)?;
        Ok(SshClientConfig {
            blocks,
            enable_match_exec: false,
        })
    }

    /// Like [`Self::load`] but parses an in-memory `src` while still
    /// honouring `Include` directives relative to `base_dir`. Useful when
    /// the config has been pre-read (e.g. from a memfd) but you still want
    /// Include semantics anchored at a known directory.
    #[cfg(feature = "std")]
    pub fn load_with_base<P: AsRef<std::path::Path>>(
        src: &str,
        base_dir: P,
    ) -> Result<Self, ConfigError> {
        let lines = tokenize(src)?;
        let expanded = super::include::expand_includes(lines, base_dir.as_ref(), 0)?;
        let blocks = parse_blocks(expanded)?;
        Ok(SshClientConfig {
            blocks,
            enable_match_exec: false,
        })
    }

    /// Permit `Match exec <cmd>` criteria to run `/bin/sh -c <cmd>` during
    /// lookup. Off by default because evaluating arbitrary shell commands
    /// during config resolution is a confused-deputy hazard: a config loaded
    /// from an untrusted location could trigger arbitrary commands at the
    /// privilege level of whoever called `lookup`. Callers that fully trust
    /// the config source (e.g. a CLI tool loading the local user's
    /// `~/.ssh/config`) can opt in.
    pub fn enable_match_exec(mut self, allow: bool) -> Self {
        self.enable_match_exec = allow;
        self
    }

    /// `true` iff `Match exec` is currently permitted on this config.
    pub fn is_match_exec_enabled(&self) -> bool {
        self.enable_match_exec
    }

    /// Resolve the effective options for `host`, walking every matching
    /// block in source order with OpenSSH **first-match-wins** semantics for
    /// scalars and **concatenation** for cumulative list fields
    /// (`IdentityFile`, `LocalForward`, `RemoteForward`).
    ///
    /// `Match` blocks that need a username (`Match user …` / `Match localuser
    /// …`) will not match through this entry point — they require fields the
    /// bare `host`-only API doesn't carry. Use [`Self::lookup_with`] when you
    /// have that context.
    pub fn lookup(&self, host: &str) -> ClientOptions {
        self.lookup_with(MatchContext {
            host,
            original_host: None,
            user: None,
            local_user: None,
        })
    }

    /// Like [`Self::lookup`] but supplies a full [`MatchContext`] so `Match`
    /// blocks with `user` / `localuser` / `originalhost` criteria can match.
    pub fn lookup_with(&self, ctx: MatchContext<'_>) -> ClientOptions {
        let policy = if self.enable_match_exec {
            ExecPolicy::Allow
        } else {
            ExecPolicy::Deny
        };
        let mut out = ClientOptions::default();
        for block in &self.blocks {
            let matches = match block {
                Block::Host { patterns, .. } => host_matches(patterns, ctx.host),
                Block::Match { conditions, .. } => all_match(conditions, &ctx, policy),
            };
            if matches {
                merge_into(&mut out, block.opts());
            }
        }
        out
    }
}

/// Walk the tokenised stream and split it into [`Block`]s. Lines outside any
/// explicit `Host` / `Match` block accumulate into the implicit `Host *`
/// block at index 0.
pub(crate) fn parse_blocks(lines: Vec<ParsedLine>) -> Result<Vec<Block>, ConfigError> {
    let mut blocks: Vec<Block> = vec![Block::Host {
        patterns: vec![HostPattern::Any],
        opts: ClientOptions::default(),
    }];
    for line in lines {
        match line.keyword.as_str() {
            "host" => {
                if line.args.is_empty() {
                    return Err(ConfigError::BadValue {
                        line: line.line_no,
                        keyword: "host".to_string(),
                        msg: "Host requires at least one pattern".into(),
                    });
                }
                blocks.push(Block::Host {
                    patterns: HostPattern::parse_all(&line.args),
                    opts: ClientOptions::default(),
                });
            }
            "match" => {
                let conditions = parse_match_line(&line.args, line.line_no)?;
                blocks.push(Block::Match {
                    conditions,
                    opts: ClientOptions::default(),
                });
            }
            "include" => {
                // The Include-expansion pass runs before us when the caller
                // uses SshClientConfig::load* (the std-only entry points). If
                // we see an Include here, the user reached us via
                // SshClientConfig::parse(&str), which has no filesystem
                // context — refuse rather than silently drop.
                return Err(ConfigError::Unsupported {
                    line: line.line_no,
                    msg: "Include requires file-based loading; use SshClientConfig::load() instead"
                        .into(),
                });
            }
            _ => {
                let current = blocks.last_mut().expect("global block always present");
                apply_keyword(current.opts_mut(), &line)?;
            }
        }
    }
    Ok(blocks)
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

    // ----- Match-block tests --------------------------------------------

    #[test]
    fn match_host_glob() {
        let src = "\
Match host *.example.com
  User alice
";
        let cfg = SshClientConfig::parse(src).unwrap();
        assert_eq!(cfg.lookup("web.example.com").user.as_deref(), Some("alice"));
        assert_eq!(cfg.lookup("web.other.com").user, None);
    }

    #[test]
    fn match_negated_host() {
        let src = "\
Match host *.example.com,!internal.example.com
  User alice
";
        let cfg = SshClientConfig::parse(src).unwrap();
        assert_eq!(cfg.lookup("web.example.com").user.as_deref(), Some("alice"));
        assert_eq!(cfg.lookup("internal.example.com").user, None);
    }

    #[test]
    fn match_user_combined_with_host() {
        let src = "\
Match host *.example.com user alice
  Port 2222
";
        let cfg = SshClientConfig::parse(src).unwrap();
        // No user supplied → does not match.
        assert_eq!(cfg.lookup("web.example.com").port, None);
        // Wrong user → does not match.
        let ctx = MatchContext {
            host: "web.example.com",
            original_host: None,
            user: Some("bob"),
            local_user: None,
        };
        assert_eq!(cfg.lookup_with(ctx).port, None);
        // Right user → matches.
        let ctx = MatchContext {
            host: "web.example.com",
            original_host: None,
            user: Some("alice"),
            local_user: None,
        };
        assert_eq!(cfg.lookup_with(ctx).port, Some(2222));
    }

    #[test]
    fn match_all_matches_everything() {
        let src = "\
Match all
  Port 4242
";
        let cfg = SshClientConfig::parse(src).unwrap();
        assert_eq!(cfg.lookup("anything").port, Some(4242));
        assert_eq!(cfg.lookup("other").port, Some(4242));
    }

    #[test]
    fn match_canonical_never_matches_in_first_pass() {
        let src = "\
Match canonical
  Port 4242
";
        let cfg = SshClientConfig::parse(src).unwrap();
        assert_eq!(cfg.lookup("anything").port, None);
    }

    #[test]
    fn match_final_never_matches_in_first_pass() {
        let src = "\
Match final
  Port 4242
";
        let cfg = SshClientConfig::parse(src).unwrap();
        assert_eq!(cfg.lookup("anything").port, None);
    }

    #[test]
    fn match_exec_disabled_by_default() {
        // Even with a command that would succeed on every platform, the
        // block must be silently skipped while the default policy is in
        // effect.
        let src = "\
Match exec true
  Port 4242
";
        let cfg = SshClientConfig::parse(src).unwrap();
        assert!(!cfg.is_match_exec_enabled());
        assert_eq!(cfg.lookup("anything").port, None);
    }

    #[cfg(unix)]
    #[test]
    fn match_exec_enabled_runs_command() {
        // Use the shell builtins `true` / `false` (not the `/bin/true`
        // / `/bin/false` binaries) so the test is portable: macOS
        // runners ship coreutils-style helpers at `/usr/bin/true` and
        // recent macOS images don't carry `/bin/true` at all, so an
        // absolute path here breaks `macos-latest` in CI. The `sh -c`
        // wrapper this code routes through always resolves the
        // builtins.
        let src = "\
Match exec true
  Port 4242
";
        let cfg = SshClientConfig::parse(src).unwrap().enable_match_exec(true);
        assert!(cfg.is_match_exec_enabled());
        assert_eq!(cfg.lookup("anything").port, Some(4242));

        let src_false = "\
Match exec false
  Port 4242
";
        let cfg = SshClientConfig::parse(src_false)
            .unwrap()
            .enable_match_exec(true);
        assert_eq!(cfg.lookup("anything").port, None);
    }

    #[test]
    fn match_originalhost_uses_pre_substitution_name() {
        let src = "\
Match originalhost prod
  Port 2200
";
        let cfg = SshClientConfig::parse(src).unwrap();
        let ctx = MatchContext {
            host: "10.0.0.1",
            original_host: Some("prod"),
            user: None,
            local_user: None,
        };
        assert_eq!(cfg.lookup_with(ctx).port, Some(2200));
    }

    #[test]
    fn match_localuser() {
        let src = "\
Match localuser alice
  Port 2200
";
        let cfg = SshClientConfig::parse(src).unwrap();
        let ctx = MatchContext {
            host: "h",
            original_host: None,
            user: None,
            local_user: Some("alice"),
        };
        assert_eq!(cfg.lookup_with(ctx).port, Some(2200));
        let ctx = MatchContext {
            host: "h",
            original_host: None,
            user: None,
            local_user: Some("bob"),
        };
        assert_eq!(cfg.lookup_with(ctx).port, None);
    }

    #[test]
    fn match_block_with_settings_parses() {
        // Sanity: settings inside a Match block actually get applied when
        // the block matches.
        let src = "\
Match host gw
  HostName 10.0.0.1
  Port 2222
  User admin
";
        let cfg = SshClientConfig::parse(src).unwrap();
        let eff = cfg.lookup("gw");
        assert_eq!(eff.host_name.as_deref(), Some("10.0.0.1"));
        assert_eq!(eff.port, Some(2222));
        assert_eq!(eff.user.as_deref(), Some("admin"));
    }

    #[test]
    fn match_unknown_criterion_errors() {
        let src = "Match address 1.2.3.4\n  Port 22\n";
        let err = SshClientConfig::parse(src).unwrap_err();
        match err {
            ConfigError::BadValue { line, .. } => assert_eq!(line, 1),
            _ => panic!("wrong err: {err:?}"),
        }
    }

    #[test]
    fn match_empty_args_errors() {
        let src = "Match\n  Port 22\n";
        let err = SshClientConfig::parse(src).unwrap_err();
        match err {
            ConfigError::BadValue { line, .. } => assert_eq!(line, 1),
            _ => panic!("wrong err: {err:?}"),
        }
    }

    // ----- Include-directive tests -------------------------------------

    #[cfg(feature = "std")]
    #[test]
    fn include_unsupported_in_string_parse() {
        // parse(&str) cannot resolve Include — it should surface a friendly
        // diagnostic rather than UnknownKeyword.
        let src = "Include /etc/ssh/somefile\n";
        let err = SshClientConfig::parse(src).unwrap_err();
        match err {
            ConfigError::Unsupported { line, msg } => {
                assert_eq!(line, 1);
                assert!(msg.contains("Include"), "msg = {msg}");
            }
            _ => panic!("wrong err: {err:?}"),
        }
    }

    #[cfg(feature = "std")]
    mod include_io {
        use super::*;
        use std::io::Write;
        use std::path::PathBuf;

        struct TempDir {
            path: PathBuf,
        }
        impl TempDir {
            fn new(prefix: &str) -> Self {
                use std::time::{SystemTime, UNIX_EPOCH};
                let nanos = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map(|d| d.as_nanos())
                    .unwrap_or(0);
                let pid = std::process::id();
                let path =
                    std::env::temp_dir().join(format!("puressh-cfg-client-{prefix}-{pid}-{nanos}"));
                std::fs::create_dir_all(&path).expect("create tempdir");
                Self { path }
            }
            fn write(&self, name: &str, body: &str) -> PathBuf {
                let p = self.path.join(name);
                if let Some(parent) = p.parent() {
                    std::fs::create_dir_all(parent).expect("mkdir");
                }
                let mut f = std::fs::File::create(&p).expect("create file");
                f.write_all(body.as_bytes()).expect("write file");
                p
            }
        }
        impl Drop for TempDir {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.path);
            }
        }

        #[test]
        fn include_pulls_in_settings() {
            let dir = TempDir::new("pull");
            let leaf = dir.write("leaf.cfg", "Port 4242\n");
            let root = dir.write(
                "root.cfg",
                &format!("Host gw\n  HostName 10.0.0.1\nInclude {}\n", leaf.display()),
            );
            let cfg = SshClientConfig::load(&root).unwrap();
            // Include is inside the `Host gw` block — its Port applies to gw.
            assert_eq!(cfg.lookup("gw").port, Some(4242));
            assert_eq!(cfg.lookup("gw").host_name.as_deref(), Some("10.0.0.1"));
        }

        #[test]
        fn include_glob_pulls_all_matches() {
            let dir = TempDir::new("glob");
            dir.write("conf.d/01.cfg", "Host gw\n  Port 2001\n");
            dir.write("conf.d/02.cfg", "Host gw\n  User u2\n");
            dir.write("conf.d/03.cfg", "Host gw\n  IdentityFile /tmp/k3\n");
            dir.write("conf.d/skip.txt", "Host gw\n  Port 9999\n");
            let root = dir.write(
                "root.cfg",
                &format!("Include {}/conf.d/*.cfg\n", dir.path.display()),
            );
            let cfg = SshClientConfig::load(&root).unwrap();
            let eff = cfg.lookup("gw");
            // First-match-wins on Port → 2001 (alphabetical 01.cfg sorts
            // first under our deterministic sort).
            assert_eq!(eff.port, Some(2001));
            assert_eq!(eff.user.as_deref(), Some("u2"));
            assert_eq!(eff.identity_files, vec!["/tmp/k3"]);
        }

        #[test]
        fn include_relative_to_containing_file() {
            // root.cfg lives in dir/; Include uses a bare filename, which
            // must be resolved against dir/ (not the CWD).
            let dir = TempDir::new("relative");
            dir.write("sibling.cfg", "Host gw\n  Port 7777\n");
            let root = dir.write("root.cfg", "Include sibling.cfg\n");
            let cfg = SshClientConfig::load(&root).unwrap();
            assert_eq!(cfg.lookup("gw").port, Some(7777));
        }

        #[test]
        fn include_missing_file_warned_not_fatal() {
            let dir = TempDir::new("missing");
            let root = dir.write(
                "root.cfg",
                &format!(
                    "Host gw\n  Port 22\nInclude {}/nope.cfg\n",
                    dir.path.display()
                ),
            );
            let cfg = SshClientConfig::load(&root).expect("missing include is non-fatal");
            assert_eq!(cfg.lookup("gw").port, Some(22));
        }

        #[test]
        fn include_circular_capped_at_16_depth() {
            // file A includes file A → infinite loop guarded by depth cap.
            let dir = TempDir::new("circ");
            // Path-stable file under the temp dir.
            let p = dir.path.join("loop.cfg");
            let body = format!("Include {}\n", p.display());
            std::fs::write(&p, body).expect("write loop.cfg");
            let err = SshClientConfig::load(&p).unwrap_err();
            match err {
                ConfigError::Syntax { msg, .. } => {
                    assert!(msg.contains("max depth"), "msg = {msg}");
                }
                _ => panic!("wrong err: {err:?}"),
            }
        }

        #[test]
        fn include_load_with_base_resolves_relative() {
            let dir = TempDir::new("loadbase");
            dir.write("inner.cfg", "Host gw\n  Port 9999\n");
            let src = "Include inner.cfg\n";
            let cfg = SshClientConfig::load_with_base(src, &dir.path).unwrap();
            assert_eq!(cfg.lookup("gw").port, Some(9999));
        }

        #[test]
        fn include_inside_match_block_only_applies_there() {
            // The Include sits inside a Host block — its settings should be
            // tagged onto that block, not bleed into a sibling block.
            let dir = TempDir::new("inblock");
            dir.write("only_gw.cfg", "Port 3300\n");
            let root = dir.write(
                "root.cfg",
                "Host gw\n  Include only_gw.cfg\nHost other\n  Port 22\n",
            );
            let cfg = SshClientConfig::load(&root).unwrap();
            assert_eq!(cfg.lookup("gw").port, Some(3300));
            assert_eq!(cfg.lookup("other").port, Some(22));
        }
    }
}
