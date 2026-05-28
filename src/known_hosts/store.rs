//! In-memory `KnownHosts` model: load, save, lookup, mutate.

use std::fs;
use std::io;
use std::path::Path;

use purecrypto::rng::{OsRng, RngCore};

use super::format::{
    format_entry, format_host_pattern, parse_line, patterns_match, Entry, HostSpec, Marker,
    ParsedLine,
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
    pub fn from_bytes(data: &[u8]) -> Self {
        let mut out = Self::new();
        for raw in std::str::from_utf8(data).unwrap_or("").lines() {
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

    /// Atomically save to `path`. Writes to `path.tmp` then renames.
    pub fn save(&self, path: impl AsRef<Path>) -> io::Result<()> {
        let path = path.as_ref();
        let tmp = path.with_extension({
            let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
            if ext.is_empty() {
                "tmp".to_string()
            } else {
                format!("{ext}.tmp")
            }
        });
        fs::write(&tmp, self.to_bytes())?;
        fs::rename(&tmp, path)?;
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
            if let Slot::Entry(e) = slot {
                if e.marker == Some(Marker::Revoked)
                    && host_field_matches(&e.host_spec, host, port)
                    && e.key_type == key_type
                    && e.key_blob == key_blob
                {
                    return LookupResult::Mismatch {
                        expected: vec![(e.key_type.clone(), e.key_blob.clone())],
                    };
                }
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
            if let Slot::Entry(e) = slot {
                if host_field_matches(&e.host_spec, host, port) {
                    removed += 1;
                    *slot = Slot::Removed;
                }
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
                        for pat in pats {
                            let (host, port) = split_host_port(&pat);
                            let mut salt = [0u8; super::hash::SALT_LEN];
                            rng.fill_bytes(&mut salt);
                            let token = super::hash::encode_hashed(
                                &salt,
                                &super::hash::format_host(&host, port),
                            );
                            new_lines.push(Slot::Entry(Entry {
                                marker: e.marker,
                                host_spec: HostSpec::Hashed(token),
                                key_type: e.key_type.clone(),
                                key_blob: e.key_blob.clone(),
                                comment: e.comment.clone(),
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
fn split_host_port(pat: &str) -> (String, u16) {
    if let Some(stripped) = pat.strip_prefix('[') {
        if let Some(idx) = stripped.rfind(']') {
            let host = stripped[..idx].to_string();
            if let Some(rest) = stripped[idx + 1..].strip_prefix(':') {
                if let Ok(p) = rest.parse::<u16>() {
                    return (host, p);
                }
            }
            return (host, 22);
        }
    }
    (pat.to_string(), 22)
}
