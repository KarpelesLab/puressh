//! In-memory `KnownHosts` model: load, save, lookup, mutate.

use std::fs;
use std::io;
use std::path::Path;

use purecrypto::rng::{OsRng, RngCore};

use super::format::{
    Entry, HostSpec, Marker, ParsedLine, format_entry, format_host_pattern, parse_line,
    patterns_match,
};
use super::hash::{check_hashed, hash_new, parse_hashed};

/// Outcome of looking up a host in a [`KnownHosts`] store.
#[derive(Debug)]
pub enum LookupResult {
    /// At least one entry's host and key match the candidate exactly.
    /// Connection is safe to proceed.
    Match,
    /// At least one entry's host matched, but no entry's key did. The
    /// expected keys (`(key_type, key_blob)`) are returned so the caller
    /// can render a helpful diagnostic.
    Mismatch {
        /// `(key_type, key_blob)` pairs the store has on file for the
        /// host — the keys we would have accepted, in load order.
        expected: Vec<(String, Vec<u8>)>,
    },
    /// No entry's host matched. The caller decides whether to TOFU-add.
    Unknown,
}

/// In-memory model of a `known_hosts` file. Preserves comments,
/// formatting, and unknown lines verbatim across load → save.
pub struct KnownHosts {
    /// Original file lines, kept in order so `save` produces a stable
    /// diff. Entries are mutable in-place; verbatim lines are passed
    /// through unchanged.
    lines: Vec<Slot>,
}

enum Slot {
    Verbatim(String),
    Entry(Entry),
    /// Tombstoned slot — skipped on save. Lets `remove` keep indices
    /// stable for callers that hold references during a mutation pass.
    Removed,
}

impl Default for KnownHosts {
    fn default() -> Self {
        Self::new()
    }
}

impl KnownHosts {
    /// Empty store.
    pub fn new() -> Self {
        Self { lines: Vec::new() }
    }

    /// Parse the bytes of a `known_hosts` file.
    ///
    /// Parsing is done line-by-line over the raw bytes (split on `\n`,
    /// with a trailing `\r` stripped) so a single non-UTF-8 byte anywhere
    /// in the file cannot empty the whole store. Applying `from_utf8` to
    /// the entire buffer and falling back to `""` on error would turn one
    /// bad byte into zero loaded entries → every lookup returns `Unknown`
    /// → host-key verification is silently disabled and a MITM key is
    /// accepted/pinned via TOFU. Instead, each line that is valid UTF-8 is
    /// parsed as usual; a line that is not valid UTF-8 is skipped (just
    /// that line), matching OpenSSH's tolerance of individual bad lines.
    pub fn from_bytes(data: &[u8]) -> Self {
        let mut out = Self::new();
        // `split(b'\n')` yields a trailing empty element for a buffer that
        // ends in `\n` (and for an empty buffer); `str::lines()` does not.
        // Drop that single trailing empty element so a normally-terminated
        // file doesn't gain a spurious blank line on save.
        let mut parts = data.split(|&b| b == b'\n').peekable();
        while let Some(line) = parts.next() {
            if parts.peek().is_none() && line.is_empty() {
                break;
            }
            // Strip a trailing `\r` so CRLF files parse the same as LF.
            let line = match line.split_last() {
                Some((b'\r', rest)) => rest,
                _ => line,
            };
            // Skip only this line if it isn't valid UTF-8; do not abort
            // parsing and do not empty the store.
            let raw = match std::str::from_utf8(line) {
                Ok(s) => s,
                Err(_) => continue,
            };
            match parse_line(raw) {
                ParsedLine::Entry(e) => out.lines.push(Slot::Entry(e)),
                ParsedLine::Verbatim(s) => out.lines.push(Slot::Verbatim(s)),
            }
        }
        out
    }

    /// Load from a path. If the file doesn't exist, returns an empty
    /// store (the OpenSSH client behaves the same).
    pub fn load(path: impl AsRef<Path>) -> io::Result<Self> {
        match fs::read(path) {
            Ok(bytes) => Ok(Self::from_bytes(&bytes)),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(Self::new()),
            Err(e) => Err(e),
        }
    }

    /// Serialise back to bytes. Each line is `\n`-terminated.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        for slot in &self.lines {
            match slot {
                Slot::Verbatim(s) => {
                    out.extend_from_slice(s.as_bytes());
                    out.push(b'\n');
                }
                Slot::Entry(e) => {
                    out.extend_from_slice(format_entry(e).as_bytes());
                    out.push(b'\n');
                }
                Slot::Removed => {}
            }
        }
        out
    }

    /// Atomically save to `path`. Writes to a per-call unique temporary
    /// file then renames into place.
    ///
    /// Hardening notes:
    /// - The tmp filename embeds `pid` plus a fresh `u64` from `OsRng`,
    ///   so two concurrent saves cannot collide on the same temp name.
    /// - On Unix the tmp file is opened with `O_EXCL` (`create_new`) and
    ///   mode `0o600`, so a pre-existing symlink in the directory cannot
    ///   be used to trick us into overwriting an attacker-chosen target.
    /// - After writing, the tmp file is `fsync`ed, then renamed into
    ///   place. On Unix the parent directory is `fsync`ed after the
    ///   rename so the new entry survives a crash. The host-key list is
    ///   thus never world- or group-readable, even during the brief
    ///   window before the rename — matching OpenSSH and avoiding
    ///   information leak via `umask 0` shells or shared filesystems.
    /// - On error the leftover tmp file is best-effort cleaned up; the
    ///   cleanup error is intentionally swallowed so we surface the
    ///   original failure.
    pub fn save(&self, path: impl AsRef<Path>) -> io::Result<()> {
        let path = path.as_ref();
        let tmp = unique_tmp_path(path);
        match write_private_file(&tmp, &self.to_bytes()) {
            Ok(()) => {}
            Err(e) => {
                let _ = fs::remove_file(&tmp);
                return Err(e);
            }
        }
        if let Err(e) = fs::rename(&tmp, path) {
            let _ = fs::remove_file(&tmp);
            return Err(e);
        }
        #[cfg(unix)]
        {
            // Best-effort directory fsync so the rename is durable.
            // Failing here is not fatal: the data has already been
            // written and renamed, and many filesystems (notably
            // virtualised ones) reject O_RDONLY+fsync on directories.
            if let Some(parent) = path.parent() {
                let parent = if parent.as_os_str().is_empty() {
                    Path::new(".")
                } else {
                    parent
                };
                if let Ok(dir) = fs::File::open(parent) {
                    let _ = dir.sync_all();
                }
            }
        }
        Ok(())
    }

    /// Look up a host+key. See [`LookupResult`].
    ///
    /// Per OpenSSH semantics, `@revoked` is evaluated **first** across
    /// every entry in the file — a revoke line elsewhere in the file
    /// outranks any non-revoked match. After that, the first matching
    /// (host, key) pair wins; if any entry's host matches but no
    /// matching key is found, the result is `Mismatch` with the list of
    /// expected keys.
    pub fn lookup(&self, host: &str, port: u16, key_type: &str, key_blob: &[u8]) -> LookupResult {
        // Pass 1: any `@revoked` line whose host AND key matches refuses
        // the candidate unconditionally.
        for slot in &self.lines {
            if let Slot::Entry(e) = slot
                && e.marker == Some(Marker::Revoked)
                && host_field_matches(&e.host_spec, host, port)
                && e.key_type == key_type
                && e.key_blob == key_blob
            {
                return LookupResult::Mismatch {
                    expected: vec![(e.key_type.clone(), e.key_blob.clone())],
                };
            }
        }

        // Pass 2: normal Match / Mismatch / Unknown evaluation.
        let mut host_matched = false;
        let mut expected: Vec<(String, Vec<u8>)> = Vec::new();
        for slot in &self.lines {
            let e = match slot {
                Slot::Entry(e) => e,
                _ => continue,
            };
            if !host_field_matches(&e.host_spec, host, port) {
                continue;
            }
            // Revoked lines are not evidence of "known"; if pass 1
            // didn't fire, they have nothing useful to contribute.
            if e.marker == Some(Marker::Revoked) {
                continue;
            }
            host_matched = true;
            // Cert-authority entries indicate the key signs certs for the
            // host; we don't speak ssh-{ed25519,rsa}-cert-v01 yet, so
            // record the CA key as "expected" but only count it as a
            // match if the candidate equals it exactly.
            if e.key_type == key_type && e.key_blob == key_blob {
                return LookupResult::Match;
            }
            expected.push((e.key_type.clone(), e.key_blob.clone()));
        }

        if host_matched {
            LookupResult::Mismatch { expected }
        } else {
            LookupResult::Unknown
        }
    }

    /// Append a new entry. The host is formatted as `host` for the
    /// default port and `[host]:port` otherwise.
    ///
    /// If `hashed` is true, the host field is HMAC-SHA1-hashed (with a
    /// freshly generated salt) before storage — matching OpenSSH's
    /// `HashKnownHosts yes` behaviour.
    pub fn add(&mut self, host: &str, port: u16, key_type: &str, key_blob: &[u8], hashed: bool) {
        let host_spec = if hashed {
            let mut rng = OsRng;
            let (_salt, token) = hash_new(&mut rng, host, port);
            HostSpec::Hashed(token)
        } else {
            HostSpec::Patterns(vec![format_host_pattern(host, port)])
        };
        self.lines.push(Slot::Entry(Entry {
            marker: None,
            host_spec,
            key_type: key_type.to_string(),
            key_blob: key_blob.to_vec(),
            comment: String::new(),
        }));
    }

    /// Remove every entry matching `host[:port]`. Returns the count
    /// removed.
    pub fn remove(&mut self, host: &str, port: u16) -> usize {
        let mut removed = 0usize;
        for slot in self.lines.iter_mut() {
            if let Slot::Entry(e) = slot
                && host_field_matches(&e.host_spec, host, port)
            {
                removed += 1;
                *slot = Slot::Removed;
            }
        }
        removed
    }

    /// Return all entries whose host field matches `host[:port]`.
    pub fn find(&self, host: &str, port: u16) -> Vec<&Entry> {
        self.lines
            .iter()
            .filter_map(|s| match s {
                Slot::Entry(e) if host_field_matches(&e.host_spec, host, port) => Some(e),
                _ => None,
            })
            .collect()
    }

    /// Hash every unhashed entry in place using fresh salts. Equivalent
    /// to `ssh-keygen -H`.
    ///
    /// Entries with multiple host patterns expand to one hashed entry
    /// per pattern, matching OpenSSH's behaviour.
    pub fn hash_in_place(&mut self) {
        let mut rng = OsRng;
        let mut new_lines: Vec<Slot> = Vec::with_capacity(self.lines.len());
        for slot in self.lines.drain(..) {
            match slot {
                Slot::Entry(e) => match e.host_spec {
                    HostSpec::Hashed(_) => new_lines.push(Slot::Entry(e)),
                    HostSpec::Patterns(pats) => {
                        // Buffer one entry per pattern. If any pattern
                        // is malformed (e.g. `[host]:NOT-A-PORT`), we
                        // refuse to silently downgrade — the whole
                        // entry is preserved verbatim instead, so a
                        // typo can't mask a hostkey-change.
                        let mut hashed: Vec<Entry> = Vec::with_capacity(pats.len());
                        let mut all_ok = true;
                        for pat in &pats {
                            let Some((host, port)) = split_host_port(pat) else {
                                all_ok = false;
                                break;
                            };
                            let mut salt = [0u8; super::hash::SALT_LEN];
                            rng.fill_bytes(&mut salt);
                            let token = super::hash::encode_hashed(
                                &salt,
                                &super::hash::format_host(&host, port),
                            );
                            hashed.push(Entry {
                                marker: e.marker,
                                host_spec: HostSpec::Hashed(token),
                                key_type: e.key_type.clone(),
                                key_blob: e.key_blob.clone(),
                                comment: e.comment.clone(),
                            });
                        }
                        if all_ok {
                            for entry in hashed {
                                new_lines.push(Slot::Entry(entry));
                            }
                        } else {
                            new_lines.push(Slot::Entry(Entry {
                                marker: e.marker,
                                host_spec: HostSpec::Patterns(pats),
                                key_type: e.key_type,
                                key_blob: e.key_blob,
                                comment: e.comment,
                            }));
                        }
                    }
                },
                other => new_lines.push(other),
            }
        }
        self.lines = new_lines;
    }
}

/// Write `data` to `path` with permissions `0o600` on Unix. The file is
/// opened with `O_EXCL` (`create_new`) so a pre-existing symlink in the
/// target directory cannot be used to redirect the write — the open
/// fails outright if the path already exists. On non-Unix targets the
/// `create_new(true)` open is still used (so we never follow a
/// pre-existing entry); the explicit mode bits are dropped because
/// Windows ACLs already grant owner-only access for files created under
/// the user's profile.
fn write_private_file(path: &Path, data: &[u8]) -> io::Result<()> {
    use std::io::Write as _;
    let mut opts = fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        opts.mode(0o600);
    }
    let mut f = opts.open(path)?;
    f.write_all(data)?;
    f.sync_all()?;
    Ok(())
}

/// Build a per-call unique temporary path next to `path`. The suffix
/// combines the process id and a fresh `u64` from `OsRng`, so two
/// concurrent saves in the same process cannot collide and an attacker
/// cannot predict the name to pre-create as a symlink.
fn unique_tmp_path(path: &Path) -> std::path::PathBuf {
    let mut rng = OsRng;
    let mut nonce = [0u8; 8];
    rng.fill_bytes(&mut nonce);
    let nonce = u64::from_le_bytes(nonce);
    let pid = std::process::id();
    let file_name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("known_hosts");
    let tmp_name = format!(".{file_name}.tmp.{pid}.{nonce:016x}");
    match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent.join(tmp_name),
        _ => std::path::PathBuf::from(tmp_name),
    }
}

/// Does the entry's host field match `host[:port]`?
///
/// For plain entries this runs the OpenSSH pattern-list match. For
/// hashed entries this re-computes HMAC-SHA1 under the stored salt.
fn host_field_matches(spec: &HostSpec, host: &str, port: u16) -> bool {
    match spec {
        HostSpec::Patterns(pats) => patterns_match(pats, host, port),
        HostSpec::Hashed(token) => match parse_hashed(token) {
            Some((salt, hash)) => check_hashed(&salt, &hash, host, port),
            None => false,
        },
    }
}

/// Split a plain host pattern (`host` or `[host]:port`) into
/// `(host, port)`. Default port is 22.
///
/// Returns `None` for malformed bracketed forms — specifically
/// `[host]:NOT-A-PORT`, `[host]:` (empty port) and `[host`-without-`]`.
/// Silently downgrading those to port 22 would mask a host-key change
/// (subsequent lookups would target a different host record than the
/// one the user wrote down).
///
/// Delegates to [`crate::config::parse_host_port_pattern`] (the
/// known_hosts grammar variant: brackets allowed around any host, no
/// colon-splitting of bare patterns). The `Err` cases (malformed
/// bracket forms) are mapped to `None` to preserve the original
/// `Option`-based contract.
fn split_host_port(pat: &str) -> Option<(String, u16)> {
    crate::config::parse_host_port_pattern(pat, 22).ok()
}

#[cfg(test)]
mod store_tests {
    use super::*;

    /// A file containing one valid line, one line with an invalid UTF-8
    /// byte, and another valid line must load BOTH valid entries — the bad
    /// line is skipped, not the whole file. Previously a single non-UTF-8
    /// byte emptied the entire store (every lookup → Unknown → silent TOFU
    /// fail-open, accepting a MITM key).
    #[test]
    fn invalid_utf8_line_is_skipped_not_whole_file() {
        // "AAAA" base64-decodes cleanly to a 3-byte blob, so these parse.
        let mut data: Vec<u8> = Vec::new();
        data.extend_from_slice(b"good1.example.com ssh-ed25519 AAAA\n");
        // A line carrying a lone 0xFF byte — invalid UTF-8 anywhere.
        data.extend_from_slice(b"bad.example.com ssh-ed25519 ");
        data.push(0xFF);
        data.push(b'\n');
        data.extend_from_slice(b"good2.example.com ssh-ed25519 AAAA\n");

        let kh = KnownHosts::from_bytes(&data);

        // Both valid hosts must be known.
        assert!(
            matches!(
                kh.lookup("good1.example.com", 22, "ssh-ed25519", &[0, 0, 0]),
                LookupResult::Match
            ),
            "first valid entry should have loaded"
        );
        assert!(
            matches!(
                kh.lookup("good2.example.com", 22, "ssh-ed25519", &[0, 0, 0]),
                LookupResult::Match
            ),
            "third valid entry should have loaded despite the bad middle line"
        );
        // The bad line contributed nothing.
        assert!(
            matches!(
                kh.lookup("bad.example.com", 22, "ssh-ed25519", &[0, 0, 0]),
                LookupResult::Unknown
            ),
            "the invalid-utf8 line must be skipped, not parsed"
        );
        // Exactly the two good entries were loaded.
        let entries = kh
            .lines
            .iter()
            .filter(|s| matches!(s, Slot::Entry(_)))
            .count();
        assert_eq!(entries, 2, "only the two valid lines should load");
    }

    /// A normally-terminated file (trailing `\n`) must not gain a spurious
    /// blank line when round-tripped, matching the old `str::lines()`
    /// behaviour.
    #[test]
    fn trailing_newline_does_not_add_blank_line() {
        let src = b"example.com ssh-ed25519 AAAA\n";
        let kh = KnownHosts::from_bytes(src);
        let out = kh.to_bytes();
        assert_eq!(out, src, "round-trip must not add a trailing blank line");
    }
}
