//! Platform-neutral OpenSSH percent-token expansion and the shell-safety checks behind it.
//!
//! These helpers do not depend on the process-spawning transport, so they build on
//! every platform. The mux control path uses them on Windows as well.

use alloc::string::String;

use crate::error::{Error, Result};

/// Is `host` safe to substitute into a shell command line?
///
/// Mirrors OpenSSH's `valid_hostname()` (the CVE-2023-51385 fix): only
/// ASCII alphanumerics, `.`, `-` and `_`, plus the IPv6-literal
/// characters `:`, `[`, `]` and `%` (zone id), are allowed; the name must
/// be non-empty and must not start with `-` (so it can never be parsed as
/// an option by the helper it is handed to).
pub fn valid_hostname(host: &str) -> bool {
    if host.is_empty() || host.starts_with('-') {
        return false;
    }
    host.bytes().all(|b| {
        b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_' | b':' | b'[' | b']' | b'%')
    })
}

/// Is `user` safe to substitute into a shell command line?
///
/// Mirrors OpenSSH's `valid_ruser()` (a strict superset of its deny-list):
/// rejects a leading `-`, any whitespace or control character, and the
/// shell metacharacters `` ' ` \ " ; & | ( ) { } < > $ ``. Any other
/// character is accepted, as OpenSSH allows locale-specific login names.
pub fn valid_ruser(user: &str) -> bool {
    if user.starts_with('-') {
        return false;
    }
    !user.chars().any(|c| {
        c.is_whitespace()
            || c.is_control()
            || matches!(
                c,
                '\'' | '`' | '\\' | '"' | ';' | '&' | '|' | '(' | ')' | '{' | '}' | '<' | '>' | '$'
            )
    })
}

/// [`expand_tokens`] for strings that will be handed to `/bin/sh -c`
/// (`ProxyCommand`): the `%h` host and `%r` user are validated with
/// [`valid_hostname`] / [`valid_ruser`] before being spliced in, so a
/// hostname such as `` `id` `` or `-oProxyCommand=...` coming from an
/// untrusted source (a `.git/config`, a URL, a `ProxyJump` chain) cannot
/// inject shell syntax or options into the helper command. Only tokens
/// that actually appear in `s` are checked. Returns [`Error::Config`]
/// on an invalid value.
pub fn expand_tokens_checked(s: &str, host: &str, port: u16, user: &str) -> Result<String> {
    if uses_token(s, 'h') && !valid_hostname(host) {
        return Err(Error::Config(
            "ProxyCommand: hostname contains characters that are not permitted \
             in a shell command",
        ));
    }
    if uses_token(s, 'r') && !valid_ruser(user) {
        return Err(Error::Config(
            "ProxyCommand: remote user name contains characters that are not \
             permitted in a shell command",
        ));
    }
    Ok(expand_tokens(s, host, port, user))
}

/// Does `s` contain the `%<tok>` sequence (with `%%` escaping honoured)?
fn uses_token(s: &str, tok: char) -> bool {
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c == '%' && chars.next() == Some(tok) {
            return true;
        }
    }
    false
}

/// Expand OpenSSH-style `%`-tokens in a `ProxyCommand` / `ProxyJump` host
/// string.
///
/// Supported tokens:
/// - `%h` → target host
/// - `%p` → target port
/// - `%r` → remote (login) user
/// - `%%` → a literal `%`
///
/// Any other `%x` sequence is passed through verbatim (the `%` and the
/// following char are both kept), matching OpenSSH's lenient handling of
/// unknown tokens in these particular directives.
///
/// This performs **no validation** of `host` / `user` and is suitable for
/// values that are not interpreted by a shell (e.g. `ControlPath`). For a
/// string destined for `/bin/sh -c` use [`expand_tokens_checked`].
pub fn expand_tokens(s: &str, host: &str, port: u16, user: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c != '%' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some('h') => out.push_str(host),
            Some('p') => {
                use core::fmt::Write as _;
                let _ = write!(out, "{port}");
            }
            Some('r') => out.push_str(user),
            Some('%') => out.push('%'),
            Some(other) => {
                out.push('%');
                out.push(other);
            }
            None => out.push('%'),
        }
    }
    out
}
