//! Line-level parsing/encoding of OpenSSH `known_hosts` entries.

use crate::key::base64;

/// A single non-blank, non-comment `known_hosts` entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// Marker line (`@cert-authority`, `@revoked`), or `None` for plain.
    pub marker: Option<Marker>,
    /// The host field, exactly as it appeared in the file.
    pub host_spec: HostSpec,
    /// Key algorithm name (`ssh-ed25519`, `ssh-rsa`, …).
    pub key_type: String,
    /// Raw key blob (decoded from base64).
    pub key_blob: Vec<u8>,
    /// Optional trailing comment (everything after the key blob).
    pub comment: String,
}

/// Marker prefix on a known_hosts entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Marker {
    /// `@cert-authority` — CA key for any host matching the host spec.
    CertAuthority,
    /// `@revoked` — refuse this key for matching hosts, regardless.
    Revoked,
}

impl Marker {
    /// Wire token used in the file.
    pub fn as_str(self) -> &'static str {
        match self {
            Marker::CertAuthority => "@cert-authority",
            Marker::Revoked => "@revoked",
        }
    }
}

/// The host field of a known_hosts entry — either plain
/// comma-separated patterns or a hashed `|1|salt|hmac` token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostSpec {
    /// Plain comma-separated host patterns
    /// (`host`, `host,host2`, `[host]:port`).
    Patterns(Vec<String>),
    /// Hashed entry: `|1|<base64-salt>|<base64-hmac>`. Stored verbatim
    /// so re-serialising preserves the exact token.
    Hashed(String),
}

impl HostSpec {
    /// Reconstruct the wire form.
    pub fn to_field(&self) -> String {
        match self {
            HostSpec::Patterns(v) => v.join(","),
            HostSpec::Hashed(s) => s.clone(),
        }
    }
}

/// Outcome of parsing one line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParsedLine {
    /// A real entry.
    Entry(Entry),
    /// Blank or comment — keep around verbatim when rewriting the file.
    Verbatim(String),
}

/// Parse one line. Always succeeds: malformed lines round-trip as
/// `Verbatim` so re-saving the file doesn't drop unknown content.
pub fn parse_line(raw: &str) -> ParsedLine {
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed.starts_with('#') {
        return ParsedLine::Verbatim(raw.to_string());
    }

    let mut tokens = trimmed.split_whitespace();
    let first = match tokens.next() {
        Some(t) => t,
        None => return ParsedLine::Verbatim(raw.to_string()),
    };

    let (marker, host_field) = match first {
        "@cert-authority" => match tokens.next() {
            Some(h) => (Some(Marker::CertAuthority), h),
            None => return ParsedLine::Verbatim(raw.to_string()),
        },
        "@revoked" => match tokens.next() {
            Some(h) => (Some(Marker::Revoked), h),
            None => return ParsedLine::Verbatim(raw.to_string()),
        },
        other => (None, other),
    };

    let key_type = match tokens.next() {
        Some(s) => s.to_string(),
        None => return ParsedLine::Verbatim(raw.to_string()),
    };
    let key_b64 = match tokens.next() {
        Some(s) => s,
        None => return ParsedLine::Verbatim(raw.to_string()),
    };
    let key_blob = match base64::decode(key_b64.as_bytes()) {
        Ok(b) => b,
        Err(_) => return ParsedLine::Verbatim(raw.to_string()),
    };
    let comment = tokens.collect::<Vec<&str>>().join(" ");

    let host_spec = if host_field.starts_with("|1|") {
        HostSpec::Hashed(host_field.to_string())
    } else {
        HostSpec::Patterns(host_field.split(',').map(|s| s.to_string()).collect())
    };

    ParsedLine::Entry(Entry {
        marker,
        host_spec,
        key_type,
        key_blob,
        comment,
    })
}

/// Render an entry back into a `known_hosts` line. No trailing newline.
pub fn format_entry(e: &Entry) -> String {
    let mut out = String::new();
    if let Some(m) = e.marker {
        out.push_str(m.as_str());
        out.push(' ');
    }
    out.push_str(&e.host_spec.to_field());
    out.push(' ');
    out.push_str(&e.key_type);
    out.push(' ');
    out.push_str(&base64::encode(&e.key_blob));
    if !e.comment.is_empty() {
        out.push(' ');
        out.push_str(&e.comment);
    }
    out
}

/// Format the host field the way OpenSSH prints it on save —
/// `host` for the default port (22) and `[host]:port` otherwise.
pub fn format_host_pattern(host: &str, port: u16) -> String {
    if port == 22 {
        host.to_string()
    } else {
        format!("[{host}]:{port}")
    }
}

/// True if `pattern` matches `host[:port]` per OpenSSH rules:
///   - Literal match against `host` or `[host]:port` (case-insensitive
///     for the host portion).
///   - Wildcards (`*`, `?`) are supported in the host portion.
///   - A leading `!` is a negation; we evaluate the rest and invert.
///
/// The standard OpenSSH semantics: a line matches if **any** non-negated
/// pattern matches and **no** negated pattern matches. Pattern-list
/// evaluation is in [`patterns_match`].
pub fn pattern_match(pattern: &str, host: &str, port: u16) -> bool {
    let (negated, pat) = if let Some(rest) = pattern.strip_prefix('!') {
        (true, rest)
    } else {
        (false, pattern)
    };

    // `[host]:port` style.
    let raw = if pat.starts_with('[') {
        if let Some(idx) = pat.rfind(']') {
            let host_part = &pat[1..idx];
            let port_part = pat[idx + 1..].strip_prefix(':');
            match port_part {
                Some(ps) => match ps.parse::<u16>() {
                    Ok(p) => glob_match_ascii_ci(host_part, host) && p == port,
                    Err(_) => false,
                },
                None => glob_match_ascii_ci(host_part, host) && port == 22,
            }
        } else {
            false
        }
    } else {
        // Plain host pattern. We compare against `host` and (for the
        // default port) accept; for non-default ports a plain pattern
        // can't match.
        port == 22 && glob_match_ascii_ci(pat, host)
    };
    negated ^ raw
}

/// OpenSSH pattern-list semantics: any non-negated match wins unless a
/// negated pattern in the same list also matches.
pub fn patterns_match(patterns: &[String], host: &str, port: u16) -> bool {
    let mut any_pos = false;
    for p in patterns {
        if let Some(rest) = p.strip_prefix('!') {
            // Negation matched ⇒ the whole list rejects this host.
            if pattern_match_inner(rest, host, port) {
                return false;
            }
        } else if pattern_match_inner(p, host, port) {
            any_pos = true;
        }
    }
    any_pos
}

fn pattern_match_inner(pattern: &str, host: &str, port: u16) -> bool {
    // `[host]:port` style.
    if pattern.starts_with('[') {
        if let Some(idx) = pattern.rfind(']') {
            let host_part = &pattern[1..idx];
            let port_part = pattern[idx + 1..].strip_prefix(':');
            return match port_part {
                Some(ps) => match ps.parse::<u16>() {
                    Ok(p) => glob_match_ascii_ci(host_part, host) && p == port,
                    Err(_) => false,
                },
                None => glob_match_ascii_ci(host_part, host) && port == 22,
            };
        }
        return false;
    }
    port == 22 && glob_match_ascii_ci(pattern, host)
}

/// Hard limit on a single pattern's length. A well-formed hostname is
/// 253 chars; OpenSSH allows globs but doesn't need megabyte-scale
/// patterns. 1024 is comfortably above any legitimate use.
const MAX_GLOB_PATTERN_LEN: usize = 1024;

/// Hard limit on `*` wildcards in a single pattern. The naive backtracking
/// `glob_inner` is O(2^k) over the number of `*`s when made to backtrack
/// against a long subject (`a*a*a*...` vs `aaaaa...`), so we cap k to
/// keep worst-case match time bounded regardless of the input.
const MAX_GLOB_STARS: usize = 32;

/// `*` / `?` glob with ASCII case-insensitive comparisons. No character
/// classes — OpenSSH supports them in some contexts but `known_hosts`
/// has historically been `*`/`?` only.
///
/// Returns `false` (no match) for patterns that exceed
/// [`MAX_GLOB_PATTERN_LEN`] or [`MAX_GLOB_STARS`]. We intentionally
/// don't return an error here — `pattern_match` is on the lookup hot
/// path and the caller treats any non-match identically. Refusing the
/// pattern means "this entry doesn't apply to this host" rather than
/// "the file is malformed"; the user's connection still proceeds via
/// the TOFU path for any other valid entries.
fn glob_match_ascii_ci(pat: &str, s: &str) -> bool {
    if pat.len() > MAX_GLOB_PATTERN_LEN {
        return false;
    }
    if pat.bytes().filter(|&b| b == b'*').count() > MAX_GLOB_STARS {
        return false;
    }
    let p: Vec<char> = pat.chars().collect();
    let t: Vec<char> = s.chars().collect();
    glob_inner(&p, &t)
}

fn glob_inner(p: &[char], t: &[char]) -> bool {
    if p.is_empty() {
        return t.is_empty();
    }
    match p[0] {
        '*' => {
            // try matching * against zero or more chars
            for i in 0..=t.len() {
                if glob_inner(&p[1..], &t[i..]) {
                    return true;
                }
            }
            false
        }
        '?' => {
            if t.is_empty() {
                false
            } else {
                glob_inner(&p[1..], &t[1..])
            }
        }
        c => {
            if t.is_empty() {
                false
            } else if c.eq_ignore_ascii_case(&t[0]) {
                glob_inner(&p[1..], &t[1..])
            } else {
                false
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_plain_line() {
        let line = "example.com ssh-ed25519 AAAA test-comment";
        match parse_line(line) {
            ParsedLine::Entry(e) => {
                assert!(e.marker.is_none());
                assert_eq!(e.key_type, "ssh-ed25519");
                assert_eq!(e.comment, "test-comment");
                match e.host_spec {
                    HostSpec::Patterns(v) => assert_eq!(v, vec!["example.com".to_string()]),
                    _ => panic!("expected Patterns"),
                }
            }
            _ => panic!("expected Entry"),
        }
    }

    #[test]
    fn parse_hashed_line() {
        let token = "|1|F1E2D3C4B5A6978685746352413021000F0E0D0C=|0102030405060708090a0b0c0d0e0f1011121314=";
        let line = format!("{token} ssh-ed25519 AAAA");
        match parse_line(&line) {
            ParsedLine::Entry(e) => match e.host_spec {
                HostSpec::Hashed(t) => assert_eq!(t, token),
                _ => panic!("expected Hashed"),
            },
            _ => panic!("expected Entry"),
        }
    }

    #[test]
    fn parse_marker_lines() {
        let line = "@cert-authority *.example.com ssh-ed25519 AAAA";
        match parse_line(line) {
            ParsedLine::Entry(e) => {
                assert_eq!(e.marker, Some(Marker::CertAuthority));
                match e.host_spec {
                    HostSpec::Patterns(v) => assert_eq!(v, vec!["*.example.com".to_string()]),
                    _ => panic!("expected Patterns"),
                }
            }
            _ => panic!("expected Entry"),
        }
        let line = "@revoked old.example.com ssh-ed25519 AAAA";
        match parse_line(line) {
            ParsedLine::Entry(e) => assert_eq!(e.marker, Some(Marker::Revoked)),
            _ => panic!("expected Entry"),
        }
    }

    #[test]
    fn parse_blank_and_comment_lines() {
        match parse_line("") {
            ParsedLine::Verbatim(_) => {}
            _ => panic!("expected Verbatim"),
        }
        match parse_line("# hello") {
            ParsedLine::Verbatim(s) => assert_eq!(s, "# hello"),
            _ => panic!("expected Verbatim"),
        }
    }

    #[test]
    fn pattern_match_plain_and_bracket() {
        assert!(pattern_match("example.com", "example.com", 22));
        assert!(!pattern_match("example.com", "example.com", 2222));
        assert!(pattern_match("[example.com]:2222", "example.com", 2222));
        assert!(!pattern_match("[example.com]:2222", "example.com", 22));
    }

    #[test]
    fn pattern_match_wildcards() {
        assert!(pattern_match("*.example.com", "host.example.com", 22));
        assert!(!pattern_match("*.example.com", "example.com", 22));
        assert!(pattern_match("host?.example.com", "host1.example.com", 22));
        assert!(!pattern_match(
            "host?.example.com",
            "host12.example.com",
            22
        ));
    }

    #[test]
    fn patterns_match_with_negation() {
        let pats = vec!["*.example.com".to_string(), "!evil.example.com".to_string()];
        assert!(patterns_match(&pats, "good.example.com", 22));
        assert!(!patterns_match(&pats, "evil.example.com", 22));
        assert!(!patterns_match(&pats, "other.invalid", 22));
    }

    #[test]
    fn glob_pathological_pattern_returns_quickly_without_match() {
        // Classic exponential-glob input: many `*a` segments followed by a
        // long run of `a`s in the subject. Without the wildcard cap this
        // would visit on the order of 2^k states.
        let mut pat = String::new();
        for _ in 0..40 {
            pat.push('*');
            pat.push('a');
        }
        let subject = "a".repeat(60);
        let start = std::time::Instant::now();
        let result = glob_match_ascii_ci(&pat, &subject);
        let elapsed = start.elapsed();
        // 40 stars > MAX_GLOB_STARS (32) ⇒ refuse immediately.
        assert!(!result, "pattern over cap should not match");
        assert!(
            elapsed < std::time::Duration::from_millis(50),
            "glob cap should bound runtime: took {elapsed:?}"
        );
    }

    #[test]
    fn glob_pattern_length_cap_rejects_huge_pattern() {
        let pat = "a".repeat(MAX_GLOB_PATTERN_LEN + 1);
        // Returns false (no match) regardless of subject.
        assert!(!glob_match_ascii_ci(&pat, &pat));
    }

    #[test]
    fn glob_within_cap_still_matches_correctly() {
        // Sanity: ordinary 3-star pattern within the cap matches as before.
        assert!(glob_match_ascii_ci("*.example.com", "host.example.com"));
        assert!(!glob_match_ascii_ci("*.example.com", "example.org"));
        assert!(glob_match_ascii_ci("a*b*c", "axxxbyyyc"));
    }

    #[test]
    fn format_roundtrip() {
        let e = Entry {
            marker: None,
            host_spec: HostSpec::Patterns(vec!["example.com".to_string()]),
            key_type: "ssh-ed25519".to_string(),
            key_blob: vec![0, 1, 2, 3],
            comment: "ed25519 from-test".to_string(),
        };
        let s = format_entry(&e);
        match parse_line(&s) {
            ParsedLine::Entry(e2) => assert_eq!(e2, e),
            _ => panic!("expected Entry"),
        }
    }
}
