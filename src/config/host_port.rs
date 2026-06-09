//! Bracketed-IPv6 aware `host[:port]` parsing.
//!
//! `host:port` is ambiguous for IPv6 literals because the address itself
//! contains colons (`2001:db8::1`). The standard fix (RFC 3986 §3.2.2)
//! is to wrap the literal in brackets when a port follows:
//! `[2001:db8::1]:22`.
//!
//! [`parse_host_port`] accepts all of:
//!
//! - `example.com:2222` → `("example.com", 2222)`
//! - `192.0.2.1:22` → `("192.0.2.1", 22)`
//! - `[2001:db8::1]:2222` → `("2001:db8::1", 2222)`
//! - `[2001:db8::1]` → `("2001:db8::1", default_port)`
//! - `2001:db8::1` (no brackets, no port) → `("2001:db8::1", default_port)`
//! - `example.com` (no port) → `("example.com", default_port)`
//!
//! and rejects:
//!
//! - `[2001:db8::1` (missing close bracket)
//! - `[192.0.2.1]:22` (brackets are v6-only)
//! - `[example.com]:22` (brackets are v6-only)
//! - `host:not-a-port`, `host:` (empty/bad port)
//!
//! The helper is `alloc`-only — it returns an owned `String` for the host
//! and operates on `&str`. It does NOT do DNS or connect; the caller hands
//! the result to whatever resolver / connect API it uses.

use alloc::string::{String, ToString};
use core::net::Ipv6Addr;
use core::str::FromStr;

use super::ConfigError;

/// Parse a `host[:port]` token with bracketed-IPv6 support.
///
/// See the module docs for the accepted forms. Errors are returned as
/// [`ConfigError::BadValue`] with `keyword="host_port"` and `line=0` so
/// callers that already have a `ParsedLine` context can wrap the message,
/// and callers that don't (CLI args) can format it directly.
///
/// Returns `(host, port)` where `host` is the string the caller should
/// hand to `TcpStream::connect((&host, port))` — no brackets, no port
/// suffix.
pub fn parse_host_port(s: &str, default_port: u16) -> Result<(String, u16), ConfigError> {
    // 1) Bracketed form: `[v6-literal]` or `[v6-literal]:port`. Strict —
    //    the host MUST parse as an Ipv6Addr. Brackets exist precisely to
    //    disambiguate v6 literals; allowing v4 / hostnames inside would
    //    silently accept malformed input like `[2001:db8::1` ... `]:22`
    //    where the missing bracket was the actual bug.
    if let Some(rest) = s.strip_prefix('[') {
        let close = rest.find(']').ok_or_else(|| ConfigError::BadValue {
            line: 0,
            keyword: "host_port".to_string(),
            msg: alloc::format!("missing `]` in bracketed host {s:?}"),
        })?;
        let host = &rest[..close];
        let after = &rest[close + 1..];
        if Ipv6Addr::from_str(host).is_err() {
            return Err(ConfigError::BadValue {
                line: 0,
                keyword: "host_port".to_string(),
                msg: alloc::format!(
                    "brackets are only valid around IPv6 literals; got {host:?} in {s:?}"
                ),
            });
        }
        let port = if after.is_empty() {
            default_port
        } else {
            let port_str = after
                .strip_prefix(':')
                .ok_or_else(|| ConfigError::BadValue {
                    line: 0,
                    keyword: "host_port".to_string(),
                    msg: alloc::format!("expected `:port` after `]` in {s:?}"),
                })?;
            port_str.parse::<u16>().map_err(|_| ConfigError::BadValue {
                line: 0,
                keyword: "host_port".to_string(),
                msg: alloc::format!("bad port {port_str:?} in {s:?}"),
            })?
        };
        return Ok((host.to_string(), port));
    }

    // 2) Bare IPv6 literal (no brackets, no port). Detect by trying
    //    Ipv6Addr::from_str on the whole string first — that's
    //    unambiguous and avoids the colon-count heuristic. Users
    //    naturally type `ssh 2001:db8::1`, so this MUST work.
    if Ipv6Addr::from_str(s).is_ok() {
        return Ok((s.to_string(), default_port));
    }

    // 3) Single-`:` form: hostname / IPv4 + port. We use `rsplit_once`
    //    so a port suffix on a stray `host:something:22` still parses
    //    as port=22 (but this is also a degenerate input — at worst
    //    the user gets a connect failure on the malformed host half).
    //    A v6 literal with 2+ colons would have matched step 2 already
    //    and never reach here.
    if let Some((host, port)) = s.rsplit_once(':') {
        // Reject `host:` with empty port and `host:not-a-number` so we
        // don't silently fall back to the default. `host:` should be a
        // clear error, not "connect to host:default_port".
        let port = port.parse::<u16>().map_err(|_| ConfigError::BadValue {
            line: 0,
            keyword: "host_port".to_string(),
            msg: alloc::format!("bad port {port:?} in {s:?}"),
        })?;
        if host.is_empty() {
            return Err(ConfigError::BadValue {
                line: 0,
                keyword: "host_port".to_string(),
                msg: alloc::format!("empty host in {s:?}"),
            });
        }
        return Ok((host.to_string(), port));
    }

    // 4) Plain hostname, no port.
    if s.is_empty() {
        return Err(ConfigError::BadValue {
            line: 0,
            keyword: "host_port".to_string(),
            msg: "empty host".to_string(),
        });
    }
    Ok((s.to_string(), default_port))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_v4_with_port() {
        let (h, p) = parse_host_port("192.0.2.1:22", 22).unwrap();
        assert_eq!(h, "192.0.2.1");
        assert_eq!(p, 22);
    }

    #[test]
    fn parse_hostname_with_port() {
        let (h, p) = parse_host_port("example.com:2222", 22).unwrap();
        assert_eq!(h, "example.com");
        assert_eq!(p, 2222);
    }

    #[test]
    fn parse_hostname_no_port_uses_default() {
        let (h, p) = parse_host_port("example.com", 22).unwrap();
        assert_eq!(h, "example.com");
        assert_eq!(p, 22);
        let (h, p) = parse_host_port("example.com", 2200).unwrap();
        assert_eq!(h, "example.com");
        assert_eq!(p, 2200);
    }

    #[test]
    fn parse_v4_no_port_uses_default() {
        let (h, p) = parse_host_port("192.0.2.1", 22).unwrap();
        assert_eq!(h, "192.0.2.1");
        assert_eq!(p, 22);
    }

    #[test]
    fn parse_v6_bracketed_with_port() {
        let (h, p) = parse_host_port("[2001:db8::1]:2222", 22).unwrap();
        assert_eq!(h, "2001:db8::1");
        assert_eq!(p, 2222);
    }

    #[test]
    fn parse_v6_bracketed_no_port() {
        let (h, p) = parse_host_port("[2001:db8::1]", 22).unwrap();
        assert_eq!(h, "2001:db8::1");
        assert_eq!(p, 22);
    }

    #[test]
    fn parse_v6_bare_uses_default() {
        // The common natural form on the CLI: `ssh 2001:db8::1`.
        let (h, p) = parse_host_port("2001:db8::1", 22).unwrap();
        assert_eq!(h, "2001:db8::1");
        assert_eq!(p, 22);
    }

    #[test]
    fn parse_v6_loopback_bare() {
        let (h, p) = parse_host_port("::1", 22).unwrap();
        assert_eq!(h, "::1");
        assert_eq!(p, 22);
    }

    #[test]
    fn parse_v6_full_form_bracketed() {
        let (h, p) = parse_host_port("[2001:0db8:0000:0000:0000:0000:0000:0001]:2222", 22).unwrap();
        assert_eq!(h, "2001:0db8:0000:0000:0000:0000:0000:0001");
        assert_eq!(p, 2222);
    }

    #[test]
    fn reject_missing_close_bracket() {
        assert!(parse_host_port("[2001:db8::1", 22).is_err());
        assert!(parse_host_port("[2001:db8::1:22", 22).is_err());
    }

    #[test]
    fn reject_bracketed_v4() {
        // Brackets are v6-only.
        assert!(parse_host_port("[192.0.2.1]:22", 22).is_err());
        assert!(parse_host_port("[192.0.2.1]", 22).is_err());
    }

    #[test]
    fn reject_bracketed_hostname() {
        assert!(parse_host_port("[example.com]:22", 22).is_err());
        assert!(parse_host_port("[example.com]", 22).is_err());
    }

    #[test]
    fn reject_bad_port() {
        assert!(parse_host_port("host:not-a-port", 22).is_err());
        assert!(parse_host_port("host:", 22).is_err());
        assert!(parse_host_port("[2001:db8::1]:not-a-port", 22).is_err());
        assert!(parse_host_port("[2001:db8::1]:", 22).is_err());
    }

    #[test]
    fn reject_empty() {
        assert!(parse_host_port("", 22).is_err());
    }

    #[test]
    fn reject_garbage_after_close_bracket() {
        // `[host]garbage` — `]` is followed by something other than `:port`.
        assert!(parse_host_port("[2001:db8::1]garbage", 22).is_err());
    }

    #[test]
    fn reject_empty_host_with_port() {
        // `:22` — port-only with no host.
        assert!(parse_host_port(":22", 22).is_err());
    }
}
