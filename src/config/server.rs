//! `sshd_config(5)` parsing — see [`SshServerConfig`].
//!
//! Only the keywords the puressh `sshd` binary actually consumes today are
//! recognised; any other keyword is rejected as
//! [`ConfigError::UnknownKeyword`]. `Match` blocks are parsed at the token
//! level but rejected with [`ConfigError::Unsupported`] for the moment —
//! they're a follow-up.

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use super::parser::{tokenize, ParsedLine};
use super::ConfigError;

/// A parsed `sshd_config(5)` file.
///
/// Every field is `Option`-typed (or an empty `Vec`) so the binary can apply
/// OpenSSH precedence — CLI flag > config file > built-in default — using a
/// `pick(cli, cfg, default)` helper.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SshServerConfig {
    /// `Port` — default 22 (OpenSSH default; puressh's CLI default differs).
    pub port: Option<u16>,
    /// `ListenAddress` entries — cumulative; one bind socket per entry. Each
    /// is a `host[:port]` literal; missing port inherits `port`. Stored as
    /// raw strings (parsed at bind time so a v6 literal `[::1]:22` stays
    /// readable).
    pub listen_addresses: Vec<String>,
    /// `HostKey` entries — cumulative.
    pub host_key_files: Vec<String>,
    /// `AuthorizedKeysFile`.
    pub authorized_keys_file: Option<String>,
    /// `AllowUsers` — cumulative; empty ⇒ "current user only" (matches the
    /// existing CLI default behaviour).
    pub allow_users: Vec<String>,
    /// `LoginGraceTime` in seconds; `0` disables.
    pub login_grace_time: Option<u32>,
    /// `MaxStartups` (first sub-field only — the OpenSSH `start:rate:full`
    /// triple is rejected as a bad value).
    pub max_startups: Option<u32>,
    /// `AllowAgentForwarding` (yes/no).
    pub allow_agent_forwarding: Option<bool>,
    /// `X11Forwarding` (yes/no).
    pub x11_forwarding: Option<bool>,
    /// `AcceptEnv` patterns — cumulative.
    pub accept_env: Vec<String>,
    /// `StrictModes` (yes/no).
    pub strict_modes: Option<bool>,
    /// `LogLevel`: 0 = QUIET/INFO, 1 = VERBOSE/DEBUG1, 2 = DEBUG2, 3 = DEBUG3.
    pub log_level: Option<u8>,
    /// puressh-specific: `SftpEnabled` (yes/no). `sshd_config(5)` expresses
    /// this via `Subsystem sftp ...`; we expose a direct toggle instead.
    pub sftp_enabled: Option<bool>,
    /// puressh-specific: `SftpReadOnly` (yes/no).
    pub sftp_read_only: Option<bool>,
    /// puressh-specific: `SftpRoot` — chroot-like root for the SFTP subsystem.
    pub sftp_root: Option<String>,
    /// puressh-specific: `ScpEnabled` (yes/no).
    pub scp_enabled: Option<bool>,
}

impl SshServerConfig {
    /// Parse `src` (the contents of an `sshd_config` file) into an
    /// [`SshServerConfig`].
    pub fn parse(src: &str) -> Result<Self, ConfigError> {
        let lines = tokenize(src)?;
        let mut out = SshServerConfig::default();
        for line in lines {
            if line.keyword == "match" {
                return Err(ConfigError::Unsupported {
                    line: line.line_no,
                    msg: "sshd_config Match blocks not yet supported".into(),
                });
            }
            apply_keyword(&mut out, &line)?;
        }
        Ok(out)
    }
}

fn apply_keyword(opts: &mut SshServerConfig, line: &ParsedLine) -> Result<(), ConfigError> {
    let kw = line.keyword.as_str();
    match kw {
        "port" => {
            opts.port = Some(parse_u16(line)?);
        }
        "listenaddress" => {
            opts.listen_addresses.push(one_arg(line)?);
        }
        "hostkey" => {
            opts.host_key_files.push(one_arg(line)?);
        }
        "authorizedkeysfile" => {
            opts.authorized_keys_file = Some(one_arg(line)?);
        }
        "allowusers" => {
            for u in &line.args {
                opts.allow_users.push(u.clone());
            }
            if line.args.is_empty() {
                return Err(ConfigError::BadValue {
                    line: line.line_no,
                    keyword: kw.to_string(),
                    msg: "expected at least one user name".into(),
                });
            }
        }
        "logingracetime" => {
            opts.login_grace_time = Some(parse_duration_seconds(line)?);
        }
        "maxstartups" => {
            let s = one_arg(line)?;
            if s.contains(':') {
                return Err(ConfigError::Unsupported {
                    line: line.line_no,
                    msg: "MaxStartups start:rate:full triple not yet supported".into(),
                });
            }
            opts.max_startups = Some(s.parse::<u32>().map_err(|_| ConfigError::BadValue {
                line: line.line_no,
                keyword: kw.to_string(),
                msg: format!("expected an integer, got {s:?}"),
            })?);
        }
        "allowagentforwarding" => {
            opts.allow_agent_forwarding = Some(parse_yes_no(line)?);
        }
        "x11forwarding" => {
            opts.x11_forwarding = Some(parse_yes_no(line)?);
        }
        "acceptenv" => {
            if line.args.is_empty() {
                return Err(ConfigError::BadValue {
                    line: line.line_no,
                    keyword: kw.to_string(),
                    msg: "expected at least one env pattern".into(),
                });
            }
            for p in &line.args {
                opts.accept_env.push(p.clone());
            }
        }
        "strictmodes" => {
            opts.strict_modes = Some(parse_yes_no(line)?);
        }
        "loglevel" => {
            opts.log_level = Some(parse_log_level(line)?);
        }
        "sftpenabled" => {
            opts.sftp_enabled = Some(parse_yes_no(line)?);
        }
        "sftpreadonly" => {
            opts.sftp_read_only = Some(parse_yes_no(line)?);
        }
        "sftproot" => {
            opts.sftp_root = Some(one_arg(line)?);
        }
        "scpenabled" => {
            opts.scp_enabled = Some(parse_yes_no(line)?);
        }
        _ => {
            return Err(ConfigError::UnknownKeyword {
                line: line.line_no,
                keyword: kw.to_string(),
            });
        }
    }
    Ok(())
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

/// Parse an OpenSSH time-format duration like `30s`, `5m`, `2h`, or a bare
/// integer (interpreted as seconds). Returns the total in seconds.
fn parse_duration_seconds(line: &ParsedLine) -> Result<u32, ConfigError> {
    let s = one_arg(line)?;
    let bytes = s.as_bytes();
    let mut total: u64 = 0;
    let mut acc: u64 = 0;
    let mut has_digit = false;
    for &b in bytes {
        if b.is_ascii_digit() {
            has_digit = true;
            acc = acc * 10 + (b - b'0') as u64;
        } else {
            let mult: u64 = match b.to_ascii_lowercase() {
                b's' => 1,
                b'm' => 60,
                b'h' => 3600,
                b'd' => 86400,
                b'w' => 604800,
                _ => {
                    return Err(ConfigError::BadValue {
                        line: line.line_no,
                        keyword: line.keyword.clone(),
                        msg: format!("bad duration unit in {s:?}"),
                    });
                }
            };
            if !has_digit {
                return Err(ConfigError::BadValue {
                    line: line.line_no,
                    keyword: line.keyword.clone(),
                    msg: format!("missing number before unit in {s:?}"),
                });
            }
            total = total.saturating_add(acc.saturating_mul(mult));
            acc = 0;
            has_digit = false;
        }
    }
    if has_digit {
        total = total.saturating_add(acc);
    }
    if total > u32::MAX as u64 {
        return Err(ConfigError::BadValue {
            line: line.line_no,
            keyword: line.keyword.clone(),
            msg: format!("duration overflows u32 seconds: {s:?}"),
        });
    }
    Ok(total as u32)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_minimal() {
        let src = "\
Port 2222
ListenAddress 127.0.0.1
HostKey /etc/ssh/ssh_host_ed25519_key
AuthorizedKeysFile /etc/authkeys
AllowUsers alice bob
StrictModes yes
";
        let cfg = SshServerConfig::parse(src).unwrap();
        assert_eq!(cfg.port, Some(2222));
        assert_eq!(cfg.listen_addresses, vec!["127.0.0.1".to_string()]);
        assert_eq!(
            cfg.host_key_files,
            vec!["/etc/ssh/ssh_host_ed25519_key".to_string()]
        );
        assert_eq!(cfg.authorized_keys_file.as_deref(), Some("/etc/authkeys"));
        assert_eq!(
            cfg.allow_users,
            vec!["alice".to_string(), "bob".to_string()]
        );
        assert_eq!(cfg.strict_modes, Some(true));
    }

    #[test]
    fn cumulative_fields() {
        let src = "\
HostKey /a
HostKey /b
ListenAddress 127.0.0.1
ListenAddress ::1
AllowUsers alice
AllowUsers bob carol
";
        let cfg = SshServerConfig::parse(src).unwrap();
        assert_eq!(cfg.host_key_files, vec!["/a".to_string(), "/b".to_string()]);
        assert_eq!(
            cfg.listen_addresses,
            vec!["127.0.0.1".to_string(), "::1".to_string()]
        );
        assert_eq!(
            cfg.allow_users,
            vec!["alice".to_string(), "bob".to_string(), "carol".to_string()]
        );
    }

    #[test]
    fn match_block_unsupported() {
        let src = "Port 22\nMatch User alice\n  AllowAgentForwarding no\n";
        let err = SshServerConfig::parse(src).unwrap_err();
        match err {
            ConfigError::Unsupported { line, .. } => assert_eq!(line, 2),
            _ => panic!("wrong error: {err:?}"),
        }
    }

    #[test]
    fn unknown_keyword_errors() {
        let src = "Port 22\nKexAlgorithms curve25519-sha256\n";
        let err = SshServerConfig::parse(src).unwrap_err();
        match err {
            ConfigError::UnknownKeyword { keyword, line } => {
                assert_eq!(keyword, "kexalgorithms");
                assert_eq!(line, 2);
            }
            _ => panic!("wrong error: {err:?}"),
        }
    }

    #[test]
    fn login_grace_time_units() {
        for (s, want) in [
            ("30", 30u32),
            ("30s", 30),
            ("2m", 120),
            ("1h", 3600),
            ("1m30s", 90),
        ] {
            let src = format!("LoginGraceTime {s}\n");
            let cfg = SshServerConfig::parse(&src).unwrap();
            assert_eq!(cfg.login_grace_time, Some(want), "case {s:?}");
        }
    }

    #[test]
    fn sftp_knobs() {
        let src = "\
SftpEnabled yes
SftpReadOnly no
SftpRoot /var/sftp
ScpEnabled yes
";
        let cfg = SshServerConfig::parse(src).unwrap();
        assert_eq!(cfg.sftp_enabled, Some(true));
        assert_eq!(cfg.sftp_read_only, Some(false));
        assert_eq!(cfg.sftp_root.as_deref(), Some("/var/sftp"));
        assert_eq!(cfg.scp_enabled, Some(true));
    }
}
