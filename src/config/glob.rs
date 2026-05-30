//! Host/Match pattern matching, with `!negation` support.
//!
//! OpenSSH `Host` patterns are whitespace-separated tokens; a pattern can be
//! negated with a leading `!`. A block matches a host name iff:
//!
//! 1. at least one positive (non-`!`) pattern in the block matches the host
//!    (`Host *` matches everything), AND
//! 2. no negative (`!`) pattern matches.
//!
//! The underlying glob grammar is the same minimal `*` / `?` matcher already
//! used for `AcceptEnv` (`src/server.rs`).

use alloc::string::{String, ToString};
use alloc::vec::Vec;

/// One token from a `Host`/`Match Host` pattern list. `Any` is a small
/// optimisation for the global-block fallthrough where every host matches.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostPattern {
    /// `*` (literal): matches every host without scanning.
    Any,
    /// A positive pattern; matches when the glob matches.
    Positive(String),
    /// A negated pattern (leading `!`); a single match excludes the host.
    Negative(String),
}

impl HostPattern {
    /// Parse one whitespace-separated token from a `Host` line.
    pub fn parse(token: &str) -> Self {
        if let Some(rest) = token.strip_prefix('!') {
            HostPattern::Negative(rest.to_string())
        } else if token == "*" {
            HostPattern::Any
        } else {
            HostPattern::Positive(token.to_string())
        }
    }

    /// Parse a vector of tokens (the arguments after a `Host` keyword).
    pub fn parse_all(tokens: &[String]) -> Vec<HostPattern> {
        tokens
            .iter()
            .map(|s| HostPattern::parse(s.as_str()))
            .collect()
    }
}

/// True when `host` is matched by the pattern list using OpenSSH semantics:
/// at least one positive match AND no negative match. Empty pattern lists
/// never match.
pub fn host_matches(patterns: &[HostPattern], host: &str) -> bool {
    if patterns.is_empty() {
        return false;
    }
    let mut any_positive = false;
    let mut positive_hit = false;
    for p in patterns {
        match p {
            HostPattern::Any => {
                any_positive = true;
                positive_hit = true;
            }
            HostPattern::Positive(g) => {
                any_positive = true;
                if !positive_hit && glob_match(g, host) {
                    positive_hit = true;
                }
            }
            HostPattern::Negative(g) => {
                if glob_match(g, host) {
                    return false;
                }
            }
        }
    }
    any_positive && positive_hit
}

/// Minimal `*` / `?` matcher (mirrors the one in `src/server.rs`).
///
/// Uses the iterative two-pointer ("Knuth/Bell") algorithm: O(|pattern| +
/// |input|) worst case. The previous recursive implementation backtracked
/// exponentially on adversarial patterns like `*a*a*a*a*a*…`, which is a
/// ReDoS vector when patterns originate from `Host`/`Match` config lines
/// in an untrusted ssh_config.
fn glob_match(pattern: &str, name: &str) -> bool {
    let p = pattern.as_bytes();
    let n = name.as_bytes();
    let mut pi = 0usize;
    let mut ni = 0usize;
    let mut star_pi: Option<usize> = None;
    let mut star_ni = 0usize;
    while ni < n.len() {
        if pi < p.len() && (p[pi] == b'?' || p[pi] == n[ni]) {
            pi += 1;
            ni += 1;
        } else if pi < p.len() && p[pi] == b'*' {
            // Record the `*` position and the input cursor we'd resume
            // matching from if the suffix fails. Skip the `*` itself so
            // the next iteration tries the pattern after it first.
            star_pi = Some(pi);
            star_ni = ni;
            pi += 1;
        } else if let Some(sp) = star_pi {
            // No match at this position; back up to the most recent `*`
            // and let it swallow one more input byte.
            pi = sp + 1;
            star_ni += 1;
            ni = star_ni;
        } else {
            return false;
        }
    }
    // Tail: any leftover pattern must be all `*` for the match to hold.
    while pi < p.len() && p[pi] == b'*' {
        pi += 1;
    }
    pi == p.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pat(tokens: &[&str]) -> Vec<HostPattern> {
        let v: Vec<String> = tokens.iter().map(|s| s.to_string()).collect();
        HostPattern::parse_all(&v)
    }

    #[test]
    fn literal_match() {
        assert!(host_matches(&pat(&["example.com"]), "example.com"));
        assert!(!host_matches(&pat(&["example.com"]), "other.com"));
    }

    #[test]
    fn star_matches_any() {
        assert!(host_matches(&pat(&["*"]), "anything"));
        assert!(host_matches(&pat(&["*"]), ""));
    }

    #[test]
    fn star_partial() {
        assert!(host_matches(&pat(&["*.example.com"]), "host.example.com"));
        assert!(!host_matches(&pat(&["*.example.com"]), "example.com"));
    }

    #[test]
    fn question_mark() {
        assert!(host_matches(&pat(&["host?"]), "hosta"));
        assert!(!host_matches(&pat(&["host?"]), "host"));
        assert!(!host_matches(&pat(&["host?"]), "hostab"));
    }

    #[test]
    fn negation_excludes() {
        // `Host *.example.com !secret.example.com`
        assert!(host_matches(
            &pat(&["*.example.com", "!secret.example.com"]),
            "ok.example.com"
        ));
        assert!(!host_matches(
            &pat(&["*.example.com", "!secret.example.com"]),
            "secret.example.com"
        ));
    }

    #[test]
    fn negation_alone_never_matches() {
        // Pure-negative lists have no positive token, so nothing matches.
        assert!(!host_matches(&pat(&["!foo"]), "bar"));
        assert!(!host_matches(&pat(&["!foo"]), "foo"));
    }

    #[test]
    fn empty_never_matches() {
        assert!(!host_matches(&[], "anything"));
    }
}
