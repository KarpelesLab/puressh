//! `ControlPath` `%`-token expansion and `sun_path` length management.
//!
//! OpenSSH's `ControlPath` accepts the same `%`-token vocabulary as
//! `ProxyCommand` plus `%C` — a hash of the connection 4-tuple
//! (`localhost:host:port:user`). We reuse the shared
//! [`expand_tokens`](crate::proc_transport::expand_tokens) for `%h`/`%p`/`%r`
//! and add `%C` here, since `%C` needs SHA-256 (already in the dep tree) and
//! the local hostname.
//!
//! A Unix-domain socket address is bounded by `sun_path` (~108 bytes including
//! the NUL terminator on Linux). An expanded `ControlPath` longer than that
//! cannot be `bind()`ed, so [`socket_path_for`] falls back to a short,
//! collision-resistant `<dir>/<sha256-prefix>` name in the same directory.

use std::path::PathBuf;

use purecrypto::hash::sha256;

/// Conservative usable length for a `sockaddr_un.sun_path`. The real limit is
/// 108 on Linux / 104 on macOS *including* the trailing NUL; we keep a margin
/// and treat anything longer as "must hash".
const SUN_PATH_MAX: usize = 100;

/// Lowercase-hex encode a byte slice.
fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(char::from_digit((b >> 4) as u32, 16).unwrap());
        s.push(char::from_digit((b & 0xf) as u32, 16).unwrap());
    }
    s
}

/// The `%C` connection hash: lowercase hex SHA-256 of
/// `localhost:host:port:user`, truncated to 16 hex chars (8 bytes) to match
/// OpenSSH's compact form. `localhost` is the local hostname (best-effort;
/// empty string if unavailable, which still yields a stable per-target hash).
pub fn connection_hash(localhost: &str, host: &str, port: u16, user: &str) -> String {
    let material = format!("{localhost}:{host}:{port}:{user}");
    let digest = sha256(material.as_bytes());
    hex(&digest[..8])
}

/// Expand a `ControlPath` template's `%`-tokens — `%h`/`%p`/`%r`/`%%` via the
/// shared expander, plus `%C` (the [`connection_hash`]) and `%l` (the local
/// hostname). Tilde (`~` / `~/`) is **not** expanded here; do that first with
/// the binary's `expand_tilde` helper.
pub fn expand_tokens_with_hash(
    template: &str,
    localhost: &str,
    host: &str,
    port: u16,
    user: &str,
) -> String {
    // Substitute %C and %l first (they aren't known to the shared expander),
    // being careful to leave %% alone so the shared pass can collapse it.
    let mut pre = String::with_capacity(template.len());
    let mut chars = template.chars().peekable();
    while let Some(c) = chars.next() {
        if c != '%' {
            pre.push(c);
            continue;
        }
        match chars.peek() {
            Some('C') => {
                chars.next();
                pre.push_str(&connection_hash(localhost, host, port, user));
            }
            Some('l') => {
                chars.next();
                pre.push_str(localhost);
            }
            // %% and every other %x: hand the pair through untouched so the
            // shared expander sees it verbatim.
            Some(&other) => {
                chars.next();
                pre.push('%');
                pre.push(other);
            }
            None => pre.push('%'),
        }
    }
    crate::proc_transport::expand_tokens(&pre, host, port, user)
}

/// Best-effort local hostname for `%C` / `%l`. Tries `$HOSTNAME`, then the
/// kernel hostname file (`/proc/sys/kernel/hostname` on Linux). The `nix`
/// `gethostname` syscall isn't enabled in our feature set, and the library
/// stays `forbid(unsafe_code)` so it can't call `libc::gethostname` directly;
/// the binary passes a hostname in explicitly where one matters. An empty
/// string is acceptable — the `%C` hash only needs to be *stable* per target.
pub fn local_hostname() -> String {
    if let Ok(h) = std::env::var("HOSTNAME")
        && !h.is_empty()
    {
        return h;
    }
    if let Ok(h) = std::fs::read_to_string("/proc/sys/kernel/hostname") {
        let h = h.trim();
        if !h.is_empty() {
            return h.to_string();
        }
    }
    String::new()
}

/// Fully resolve a `ControlPath` template to a concrete filesystem path,
/// applying `~`/token expansion and the `sun_path` length fallback.
///
/// `tilde` expands a leading `~`/`~/` (pass the binary's `expand_tilde`). If
/// the expanded path's byte length exceeds the conservative `sun_path` limit,
/// it is replaced by `<parent>/ssh-mux-<sha256hex>` so the socket can actually
/// be bound; the hash is taken over the *full* expanded path so distinct long
/// paths stay distinct.
pub fn expand_control_path(
    template: &str,
    localhost: &str,
    host: &str,
    port: u16,
    user: &str,
    tilde: impl Fn(&str) -> String,
) -> PathBuf {
    let expanded = tilde(&expand_tokens_with_hash(
        template, localhost, host, port, user,
    ));
    socket_path_for(&expanded)
}

/// Apply the `sun_path` length fallback to an already-expanded path string.
/// Returns the path unchanged when it fits, otherwise a short hashed name in
/// the same parent directory.
pub fn socket_path_for(expanded: &str) -> PathBuf {
    if expanded.len() <= SUN_PATH_MAX {
        return PathBuf::from(expanded);
    }
    let digest = sha256(expanded.as_bytes());
    let short = format!("ssh-mux-{}", hex(&digest[..16]));
    let parent = PathBuf::from(expanded)
        .parent()
        .map(|p| p.to_path_buf())
        .filter(|p| !p.as_os_str().is_empty());
    match parent {
        Some(dir) if dir.as_os_str().len() + 1 + short.len() <= SUN_PATH_MAX => dir.join(short),
        // Even the parent dir is too long (or absent): fall back to a temp
        // directory, which is guaranteed short.
        _ => std::env::temp_dir().join(short),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connection_hash_is_stable_and_distinct() {
        let a = connection_hash("box", "example.com", 22, "alice");
        let b = connection_hash("box", "example.com", 22, "alice");
        assert_eq!(a, b, "same tuple ⇒ same hash");
        assert_eq!(a.len(), 16);
        assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
        let c = connection_hash("box", "example.com", 2222, "alice");
        assert_ne!(a, c, "different port ⇒ different hash");
        let d = connection_hash("box", "example.com", 22, "bob");
        assert_ne!(a, d, "different user ⇒ different hash");
    }

    #[test]
    fn expand_basic_tokens() {
        let out = expand_tokens_with_hash("/tmp/cm-%r@%h:%p", "lh", "example.com", 2222, "alice");
        assert_eq!(out, "/tmp/cm-alice@example.com:2222");
    }

    #[test]
    fn expand_percent_c_and_l() {
        let h = connection_hash("myhost", "srv", 22, "u");
        let out = expand_tokens_with_hash("/tmp/%l-%C", "myhost", "srv", 22, "u");
        assert_eq!(out, format!("/tmp/myhost-{h}"));
    }

    #[test]
    fn expand_literal_percent() {
        let out = expand_tokens_with_hash("100%%-%h", "lh", "h", 22, "u");
        assert_eq!(out, "100%-h");
    }

    #[test]
    fn unknown_token_passthrough() {
        let out = expand_tokens_with_hash("%z-%h", "lh", "h", 22, "u");
        assert_eq!(out, "%z-h");
    }

    #[test]
    fn short_path_unchanged() {
        let p = socket_path_for("/tmp/ssh-mux-abc");
        assert_eq!(p, PathBuf::from("/tmp/ssh-mux-abc"));
    }

    #[test]
    fn overlong_path_is_hashed_in_same_dir() {
        let long_name: String = "x".repeat(200);
        let full = format!("/tmp/{long_name}");
        let p = socket_path_for(&full);
        assert!(p.as_os_str().len() <= SUN_PATH_MAX, "result fits sun_path");
        assert_eq!(p.parent().unwrap(), std::path::Path::new("/tmp"));
        assert!(
            p.file_name()
                .unwrap()
                .to_str()
                .unwrap()
                .starts_with("ssh-mux-"),
            "hashed name uses ssh-mux- prefix"
        );
        // Distinct long paths ⇒ distinct hashed names.
        let other = format!("/tmp/{}", "y".repeat(200));
        assert_ne!(p, socket_path_for(&other));
    }

    #[test]
    fn overlong_parent_falls_back_to_tempdir() {
        let deep = format!("/{}/sock", "d".repeat(200));
        let p = socket_path_for(&deep);
        assert!(p.as_os_str().len() <= SUN_PATH_MAX + 64);
        assert!(
            p.file_name()
                .unwrap()
                .to_str()
                .unwrap()
                .starts_with("ssh-mux-")
        );
    }
}
