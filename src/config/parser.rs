//! Low-level tokenizer for OpenSSH-style config files.
//!
//! `ssh_config(5)` and `sshd_config(5)` share the same line-oriented syntax:
//! one keyword per line, optional `=` between keyword and value, values may be
//! quoted, `#` starts a comment, and the keyword is case-insensitive. `Host`
//! and `Match` open new blocks; everything before the first block belongs to
//! an implicit "global" block.
//!
//! This module produces a flat stream of [`ParsedLine`] events; turning those
//! into [`SshClientConfig`](super::SshClientConfig) or
//! [`SshServerConfig`](super::SshServerConfig) is the caller's job.

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use super::ConfigError;

/// One parsed non-empty, non-comment line.
#[derive(Debug, Clone)]
pub struct ParsedLine {
    /// 1-based source line number (for diagnostics).
    pub line_no: usize,
    /// Lowercased keyword (e.g. `"hostname"`, `"port"`).
    pub keyword: String,
    /// Whitespace-separated value tokens with quoting/escaping resolved.
    pub args: Vec<String>,
}

/// Tokenize `src` into a vector of [`ParsedLine`] events.
///
/// Skips blank lines and `#` comments. Quoted (`"..."`) substrings preserve
/// internal whitespace and honour backslash escapes (`\"`, `\\`). An optional
/// `=` between keyword and value is accepted (matching OpenSSH).
pub fn tokenize(src: &str) -> Result<Vec<ParsedLine>, ConfigError> {
    let mut out = Vec::new();
    for (idx, raw) in src.lines().enumerate() {
        let line_no = idx + 1;
        let stripped = strip_comment(raw);
        let trimmed = stripped.trim();
        if trimmed.is_empty() {
            continue;
        }
        let mut toks = tokenize_line(trimmed, line_no)?;
        if toks.is_empty() {
            continue;
        }
        let mut keyword = toks.remove(0);
        // OpenSSH accepts `Keyword=value`, `Keyword =value`, `Keyword= value`,
        // and `Keyword = value`. Resolve each into "keyword + clean args".
        if let Some((kw, rest)) = keyword.split_once('=') {
            // `Keyword=value` or `Keyword=` → the value (if any) becomes the
            // first arg.
            let rest_str = rest.to_string();
            keyword = kw.to_string();
            if !rest_str.is_empty() {
                toks.insert(0, rest_str);
            }
        }
        keyword.make_ascii_lowercase();
        // `Keyword =value` was tokenized as ["=value"]; `Keyword = value`
        // becomes ["=", "value"]; `Keyword= value` becomes ["", "value"]
        // (the split_once above already left an empty kw side discarded).
        if !toks.is_empty() {
            if toks[0] == "=" {
                toks.remove(0);
            } else if let Some(stripped_arg) = toks[0].strip_prefix('=') {
                let s = stripped_arg.to_string();
                if s.is_empty() {
                    toks.remove(0);
                } else {
                    toks[0] = s;
                }
            }
        }
        out.push(ParsedLine {
            line_no,
            keyword,
            args: toks,
        });
    }
    Ok(out)
}

/// Cut everything from the first unquoted `#` on. Quoted spans are skipped
/// over so `Host "weird#name"` parses correctly.
fn strip_comment(line: &str) -> &str {
    let bytes = line.as_bytes();
    let mut i = 0;
    let mut in_quotes = false;
    let mut escape = false;
    while i < bytes.len() {
        let c = bytes[i];
        if escape {
            escape = false;
        } else if c == b'\\' && in_quotes {
            escape = true;
        } else if c == b'"' {
            in_quotes = !in_quotes;
        } else if c == b'#' && !in_quotes {
            return &line[..i];
        }
        i += 1;
    }
    line
}

/// Split a trimmed, comment-free line into whitespace-separated tokens with
/// quoting and escape handling.
fn tokenize_line(line: &str, line_no: usize) -> Result<Vec<String>, ConfigError> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut in_token = false;
    let mut in_quotes = false;
    let mut escape = false;

    for ch in line.chars() {
        if escape {
            cur.push(ch);
            escape = false;
            in_token = true;
            continue;
        }
        if in_quotes {
            match ch {
                '\\' => escape = true,
                '"' => in_quotes = false,
                _ => cur.push(ch),
            }
            continue;
        }
        match ch {
            '"' => {
                in_quotes = true;
                in_token = true;
            }
            c if c.is_whitespace() => {
                if in_token {
                    out.push(core::mem::take(&mut cur));
                    in_token = false;
                }
            }
            c => {
                cur.push(c);
                in_token = true;
            }
        }
    }
    if in_quotes {
        return Err(ConfigError::Syntax {
            line: line_no,
            msg: "unterminated quoted string".into(),
        });
    }
    if in_token {
        out.push(cur);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn skips_blank_and_comment_lines() {
        let p = tokenize("# comment\n\n   \n# another\n").unwrap();
        assert!(p.is_empty());
    }

    #[test]
    fn lowercases_keyword() {
        let p = tokenize("HostName example.com").unwrap();
        assert_eq!(p.len(), 1);
        assert_eq!(p[0].keyword, "hostname");
        assert_eq!(p[0].args, vec!["example.com"]);
    }

    #[test]
    fn accepts_equals_separator() {
        let cases = ["Port=2222", "Port =2222", "Port= 2222", "Port = 2222"];
        for src in cases {
            let p = tokenize(src).unwrap();
            assert_eq!(p.len(), 1, "case {src:?}");
            assert_eq!(p[0].keyword, "port", "case {src:?}");
            assert_eq!(p[0].args, vec!["2222"], "case {src:?}");
        }
    }

    #[test]
    fn quoted_value_preserves_whitespace() {
        let p = tokenize(r#"User "alice bob""#).unwrap();
        assert_eq!(p[0].args, vec!["alice bob"]);
    }

    #[test]
    fn backslash_escape_in_quotes() {
        let p = tokenize(r#"User "a\"b\\c""#).unwrap();
        assert_eq!(p[0].args, vec!["a\"b\\c"]);
    }

    #[test]
    fn trailing_comment_after_value() {
        let p = tokenize("Port 22 # default").unwrap();
        assert_eq!(p[0].args, vec!["22"]);
    }

    #[test]
    fn quoted_hash_is_not_comment() {
        let p = tokenize(r#"Host "weird#name""#).unwrap();
        assert_eq!(p[0].args, vec!["weird#name"]);
    }

    #[test]
    fn multiple_args() {
        let p = tokenize("LocalForward 8080 example.com:80").unwrap();
        assert_eq!(p[0].args, vec!["8080", "example.com:80"]);
    }

    #[test]
    fn unterminated_quote_errors() {
        let err = tokenize(r#"Host "unterminated"#).unwrap_err();
        match err {
            ConfigError::Syntax { line, .. } => assert_eq!(line, 1),
            _ => panic!("wrong error: {err:?}"),
        }
    }
}
