//! `Include` directive for `ssh_config(5)`.
//!
//! `Include` pulls additional config files into the stream at the current
//! point. Multiple whitespace-separated paths are supported, `~` is expanded
//! to the user's home directory, and each path may contain `*` / `?` /
//! `[abc]` shell globs. Per the man page:
//!
//! > Files without absolute paths are assumed to be in ~/.ssh if included in
//! > a user configuration file or /etc/ssh if included from the system
//! > configuration file.
//!
//! For correctness across nested includes we follow a slightly stronger rule
//! than the manpage and resolve relative paths against the directory of the
//! file currently being parsed. That matches OpenSSH's actual behaviour for
//! anything other than the top-level user / system entry points (which the
//! caller chooses anyway, when they decide which file to feed to
//! [`SshClientConfig::load`](super::SshClientConfig::load)).
//!
//! Failure to **open** a referenced file is non-fatal (the directive is
//! ignored, mirroring OpenSSH which warns but continues). Failure to
//! **parse** an included file is a hard error.
//!
//! Recursion depth is capped at [`MAX_INCLUDE_DEPTH`] (16, matching OpenSSH).
//!
//! This module is `std`-only because it touches the filesystem.

#![cfg(feature = "std")]

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use std::fs;
use std::path::{Path, PathBuf};

use super::glob::HostPattern;
use super::parser::{tokenize, ParsedLine};
use super::ConfigError;

/// Maximum number of nested `Include` files. OpenSSH uses the same value.
pub const MAX_INCLUDE_DEPTH: usize = 16;

/// Read `path`, tokenise it, and inline any `Include` directives it
/// references. The returned `ParsedLine` stream is what the block-parser
/// consumes — by the time it sees the stream, Include lines have been
/// replaced by the tokens of their targets (in source order).
///
/// `depth` is the recursion depth of the current file (top-level is 0).
/// Exceeding [`MAX_INCLUDE_DEPTH`] returns a hard error.
///
/// Errors:
/// - `Err` for failure to **parse** this file or any included file (lexer
///   errors, malformed Include lines, bad Match criteria, …).
/// - `Err` if recursion depth exceeds [`MAX_INCLUDE_DEPTH`].
///
/// I/O failures opening the *top-level* `path` are returned as
/// [`ConfigError::Syntax`] with `line: 0` — the caller asked us to read this
/// specific file, so silent-skip would be the wrong default. I/O failures
/// opening *included* files are non-fatal (skipped, matching OpenSSH).
pub fn tokenize_file_with_includes(
    path: &Path,
    depth: usize,
) -> Result<Vec<ParsedLine>, ConfigError> {
    if depth > MAX_INCLUDE_DEPTH {
        return Err(ConfigError::Syntax {
            line: 0,
            msg: "Include: max depth exceeded".into(),
        });
    }
    let src = fs::read_to_string(path).map_err(|e| ConfigError::Syntax {
        line: 0,
        msg: alloc::format!("Include: cannot read {}: {e}", path.display()),
    })?;
    let base_dir = path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .to_path_buf();
    expand_includes(tokenize(&src)?, &base_dir, depth)
}

/// Same as [`tokenize_file_with_includes`] but treats "file not found" / any
/// I/O failure as a silent skip (returning `Ok(empty)`). Used for the
/// recursive Include path, where ssh_config(5) says to warn and continue.
fn tokenize_included_file(path: &Path, depth: usize) -> Result<Vec<ParsedLine>, ConfigError> {
    if depth > MAX_INCLUDE_DEPTH {
        return Err(ConfigError::Syntax {
            line: 0,
            msg: "Include: max depth exceeded".into(),
        });
    }
    let src = match fs::read_to_string(path) {
        Ok(s) => s,
        Err(_) => return Ok(Vec::new()), // warn-and-continue
    };
    let base_dir = path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .to_path_buf();
    expand_includes(tokenize(&src)?, &base_dir, depth)
}

/// Walk a token stream and replace every `include` line in-place with the
/// tokens of the file(s) it names.
///
/// Glob expansion happens here; one Include line can fan out to many files.
/// Missing files are silently skipped (per ssh_config(5)); unreadable files
/// produce a warning-equivalent (we just skip them); parse failures bubble
/// up.
pub fn expand_includes(
    lines: Vec<ParsedLine>,
    base_dir: &Path,
    depth: usize,
) -> Result<Vec<ParsedLine>, ConfigError> {
    let mut out = Vec::with_capacity(lines.len());
    for line in lines {
        if line.keyword != "include" {
            out.push(line);
            continue;
        }
        if line.args.is_empty() {
            return Err(ConfigError::BadValue {
                line: line.line_no,
                keyword: "include".to_string(),
                msg: "Include requires at least one path".into(),
            });
        }
        for raw_path in &line.args {
            let expanded = expand_tilde(raw_path);
            let resolved = resolve_relative(&expanded, base_dir);
            let matches = match expand_glob(&resolved) {
                Ok(v) => v,
                Err(_) => continue, // unreadable parent dir → warn-and-skip
            };
            for matched in matches {
                if depth + 1 > MAX_INCLUDE_DEPTH {
                    return Err(ConfigError::Syntax {
                        line: line.line_no,
                        msg: "Include: max depth exceeded".into(),
                    });
                }
                let child_lines = tokenize_included_file(&matched, depth + 1)?;
                out.extend(child_lines);
            }
        }
    }
    Ok(out)
}

/// `~` → `$HOME`; `~/foo` → `$HOME/foo`. Other forms (`~user/foo`) aren't
/// supported — they need user-database lookups we don't want to pull in here.
/// Unrecognised tildes are returned verbatim.
fn expand_tilde(path: &str) -> PathBuf {
    if path == "~" {
        if let Some(home) = home_dir() {
            return home;
        }
    } else if let Some(rest) = path.strip_prefix("~/") {
        if let Some(mut home) = home_dir() {
            home.push(rest);
            return home;
        }
    }
    PathBuf::from(path)
}

/// `$HOME` on Unix, `%USERPROFILE%` on Windows. Returns `None` if neither is
/// set.
fn home_dir() -> Option<PathBuf> {
    if let Some(h) = std::env::var_os("HOME") {
        if !h.is_empty() {
            return Some(PathBuf::from(h));
        }
    }
    #[cfg(windows)]
    {
        if let Some(h) = std::env::var_os("USERPROFILE") {
            if !h.is_empty() {
                return Some(PathBuf::from(h));
            }
        }
    }
    None
}

/// If `path` is relative, root it at `base_dir`. Absolute paths pass through.
fn resolve_relative(path: &Path, base_dir: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        base_dir.join(path)
    }
}

/// Expand a single path that may contain `*` / `?` / `[abc]` in the final
/// component(s). Returns a vector of concrete paths (possibly empty when
/// nothing matches).
///
/// The implementation walks one segment at a time: literal segments are
/// joined as-is, glob segments cause a `read_dir` on the accumulated path
/// and filter children with [`super::glob::glob_match_str`].
///
/// `Err` is returned only on read-failures that mean we couldn't even tell
/// whether anything could match; callers treat that as "ignore this glob,
/// continue". No-match (the directory exists but nothing inside it matches)
/// is returned as `Ok(vec![])`.
fn expand_glob(path: &Path) -> std::io::Result<Vec<PathBuf>> {
    let segments: Vec<String> = path
        .iter()
        .map(|s| s.to_string_lossy().into_owned())
        .collect();
    if segments.is_empty() {
        return Ok(Vec::new());
    }
    let mut frontier: Vec<PathBuf> = Vec::new();
    // Seed: handle absolute vs relative root.
    let mut start_idx = 0;
    if path.is_absolute() {
        // The first segment of an absolute path is the root component
        // (`/` on Unix, `C:\` on Windows). Use it verbatim.
        frontier.push(PathBuf::from(&segments[0]));
        start_idx = 1;
    } else {
        frontier.push(PathBuf::from("."));
    }
    for seg in &segments[start_idx..] {
        let mut next = Vec::new();
        if contains_glob_meta(seg) {
            for parent in &frontier {
                let read_target = if parent.as_os_str().is_empty() {
                    PathBuf::from(".")
                } else {
                    parent.clone()
                };
                let entries = match fs::read_dir(&read_target) {
                    Ok(it) => it,
                    Err(_) => continue, // skip unreadable parent (warn-and-continue)
                };
                for entry in entries.flatten() {
                    let name = entry.file_name();
                    let name_str = name.to_string_lossy();
                    if glob_segment_matches(seg, &name_str) {
                        next.push(parent.join(&*name_str));
                    }
                }
            }
        } else {
            for parent in &frontier {
                next.push(parent.join(seg));
            }
        }
        frontier = next;
        if frontier.is_empty() {
            break;
        }
    }
    // Strip the relative `.` seed so callers see the same shape as the input.
    if !path.is_absolute() {
        frontier = frontier
            .into_iter()
            .map(|p| match p.strip_prefix(".") {
                Ok(suffix) => suffix.to_path_buf(),
                Err(_) => p,
            })
            .collect();
    }
    // Sort for deterministic order across platforms (read_dir is unordered).
    frontier.sort();
    Ok(frontier)
}

fn contains_glob_meta(s: &str) -> bool {
    s.bytes().any(|b| matches!(b, b'*' | b'?' | b'['))
}

/// Match one path-segment glob. We honour `*` / `?` via the existing
/// `HostPattern` glob (it's the same Knuth/Bell matcher). `[...]` character
/// classes aren't part of `HostPattern` so we ignore that subset for now;
/// segments using only `*` and `?` cover the bulk of real-world `config.d/*`
/// patterns.
fn glob_segment_matches(pattern: &str, name: &str) -> bool {
    // Re-use HostPattern positive matching by constructing a one-token list.
    let pats = [HostPattern::parse(pattern)];
    super::glob::host_matches(&pats, name)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    /// Mini scratch directory; uses the same pattern as
    /// `known_hosts::tests::TestTempDir` so we don't depend on `tempfile`.
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
                std::env::temp_dir().join(alloc::format!("puressh-cfg-{prefix}-{pid}-{nanos}"));
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
    fn contains_glob_meta_works() {
        assert!(contains_glob_meta("foo*"));
        assert!(contains_glob_meta("foo?"));
        assert!(contains_glob_meta("foo[a-z]"));
        assert!(!contains_glob_meta("foo.bar"));
    }

    #[test]
    fn expand_glob_no_meta_passes_through() {
        let dir = TempDir::new("noglob");
        let f = dir.write("plain.cfg", "");
        let v = expand_glob(&f).unwrap();
        assert_eq!(v, vec![f]);
    }

    #[test]
    fn expand_glob_star_matches_directory_children() {
        let dir = TempDir::new("star");
        let f1 = dir.write("config.d/a.cfg", "");
        let f2 = dir.write("config.d/b.cfg", "");
        dir.write("config.d/other.txt", ""); // should not match *.cfg
        let pattern = dir.path.join("config.d/*.cfg");
        let mut v = expand_glob(&pattern).unwrap();
        v.sort();
        let mut want = vec![f1, f2];
        want.sort();
        assert_eq!(v, want);
    }

    #[test]
    fn expand_tilde_replaces_leading_tilde() {
        std::env::set_var("HOME", "/tmp/fake-home");
        let p = expand_tilde("~/foo");
        assert_eq!(p, PathBuf::from("/tmp/fake-home/foo"));
        let bare = expand_tilde("~");
        assert_eq!(bare, PathBuf::from("/tmp/fake-home"));
        let unchanged = expand_tilde("nottilde");
        assert_eq!(unchanged, PathBuf::from("nottilde"));
    }
}
