//! Path resolution for [`SftpServerSession`](super::server::SftpServerSession).
//!
//! SFTP paths arrive as opaque byte strings. The server keeps a per-session
//! "virtual cwd" so the daemon process never needs to call `chdir()` (which
//! would race with other concurrent SFTP channels). Relative paths join with
//! the virtual cwd; absolute paths replace it. The result is then lexically
//! normalised (`.` removed, `..` collapsed) without touching the filesystem.
//!
//! An optional jail root constrains every resolved path to a subtree —
//! requests escaping the jail are rejected with `FxpStatus::PermissionDenied`.
//!
//! **Caveat.** This path-level check is lexical only. It does *not* prevent
//! escape through a symlink whose target points outside the jail —
//! `[SftpServerSession]` mitigates that case at I/O time by opening with
//! `O_NOFOLLOW` on the final component, but full confinement requires
//! `openat2(RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS)` or a real `chroot(2)`.
//! Treat `with_root(...)` as defence-in-depth, not as a chroot replacement.
//!
//! [SftpServerSession]: super::server::SftpServerSession

use std::path::{Component, Path, PathBuf};

use super::types::{FxpStatus, SftpError};

/// Lexically normalise `p`: collapse `.` and `..` components, strip
/// duplicate separators. Does **not** touch the filesystem (no symlinks
/// followed). Result is always absolute.
pub fn lexically_clean(p: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    // Always start absolute. If `p` is relative this shouldn't happen at
    // this layer — callers join with cwd first — but defend anyway.
    out.push("/");
    for comp in p.components() {
        match comp {
            Component::Prefix(_) | Component::RootDir | Component::CurDir => {}
            Component::ParentDir => {
                // pop unless we're already at the root
                if out.parent().is_some() {
                    out.pop();
                }
            }
            Component::Normal(c) => out.push(c),
        }
    }
    out
}

/// [`resolve_in`] with absolute client paths taken as host paths (the
/// historical behaviour; the server uses `resolve_in` directly).
///
/// Resolve `raw` (which the SFTP peer sent as bytes) against `cwd`, returning
/// an absolute lexically-clean path. If `root` is set, the resolved path
/// must lie inside it; otherwise this returns [`FxpStatus::PermissionDenied`].
///
/// Bytes that aren't valid UTF-8 currently fail with [`FxpStatus::BadMessage`].
/// SFTP v3 itself is byte-oriented, but `std::path` on Unix is `OsStr`-based;
/// supporting non-UTF-8 bytes here would need `OsStrExt::from_bytes` and a
/// `cfg(unix)` gate. We'll add that when we need it.
#[cfg(test)]
fn resolve(cwd: &Path, raw: &[u8], root: Option<&Path>) -> Result<PathBuf, SftpError> {
    resolve_in(cwd, raw, root, false)
}

/// [`resolve`], and with `jail_relative` an absolute client path is taken
/// relative to `root`, as under a `chroot(2)`: `/a/b` is `root/a/b`, and
/// `/../x` is `root/x`. That is the view `op_realpath` presents under
/// `hide_jail_in_realpath`, so the paths a client builds from its answers
/// resolve again. Without it, an absolute client path is a host path.
pub fn resolve_in(
    cwd: &Path,
    raw: &[u8],
    root: Option<&Path>,
    jail_relative: bool,
) -> Result<PathBuf, SftpError> {
    let s = std::str::from_utf8(raw).map_err(|_| SftpError::status(FxpStatus::BadMessage))?;
    let p = Path::new(s);

    // `has_root`, not `is_absolute`: SFTP paths are POSIX paths, and on
    // Windows `/a/b` has a root but, lacking a drive, is not "absolute".
    let joined = if p.has_root() {
        match root {
            Some(jail) if jail_relative => {
                let clean = lexically_clean(p);
                match clean.strip_prefix("/") {
                    Ok(rel) => jail.join(rel),
                    Err(_) => jail.to_path_buf(),
                }
            }
            _ => p.to_path_buf(),
        }
    } else {
        cwd.join(p)
    };
    let clean = lexically_clean(&joined);

    if let Some(jail) = root {
        let jail_clean = lexically_clean(jail);
        if !is_inside(&clean, &jail_clean) {
            return Err(SftpError::status_msg(
                FxpStatus::PermissionDenied,
                "path escapes jail root",
            ));
        }
    }
    Ok(clean)
}

/// True if `child` equals `parent` or is a descendant of `parent`.
/// Both paths are expected to be lexically-clean absolute paths.
pub fn is_inside(child: &Path, parent: &Path) -> bool {
    let mut c = child.components();
    let mut p = parent.components();
    loop {
        match (c.next(), p.next()) {
            (Some(ca), Some(pa)) if ca == pa => continue,
            (_, None) => return true,
            _ => return false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lexically_clean_simple() {
        assert_eq!(lexically_clean(Path::new("/a/b/./c")), Path::new("/a/b/c"));
        assert_eq!(
            lexically_clean(Path::new("/a/b/../c/./d")),
            Path::new("/a/c/d")
        );
        assert_eq!(lexically_clean(Path::new("/../..")), Path::new("/"));
        assert_eq!(lexically_clean(Path::new("/a//b///c")), Path::new("/a/b/c"));
    }

    #[test]
    fn resolve_absolute_replaces_cwd() {
        let p = resolve(Path::new("/home/u"), b"/etc/passwd", None).unwrap();
        assert_eq!(p, Path::new("/etc/passwd"));
    }

    #[test]
    fn resolve_relative_joins_cwd() {
        let p = resolve(Path::new("/home/u"), b"foo/bar", None).unwrap();
        assert_eq!(p, Path::new("/home/u/foo/bar"));
    }

    #[test]
    fn resolve_dotdot_traversal() {
        // From /tmp/x/y, two `..`s walk up to /tmp, then etc/passwd.
        let p = resolve(Path::new("/tmp/x/y"), b"../../etc/passwd", None).unwrap();
        assert_eq!(p, Path::new("/tmp/etc/passwd"));
        // Three `..`s would over-pop and clamp at /.
        let p = resolve(Path::new("/tmp/x/y"), b"../../../etc/passwd", None).unwrap();
        assert_eq!(p, Path::new("/etc/passwd"));
    }

    #[test]
    fn resolve_jail_blocks_escape() {
        let err = resolve(
            Path::new("/srv/jail/u"),
            b"../../etc/passwd",
            Some(Path::new("/srv/jail")),
        )
        .unwrap_err();
        match err {
            SftpError::Status { code, .. } => assert_eq!(code, FxpStatus::PermissionDenied),
            _ => panic!("expected PermissionDenied"),
        }
    }

    #[test]
    fn resolve_jail_allows_inside() {
        let p = resolve(
            Path::new("/srv/jail/u"),
            b"file.txt",
            Some(Path::new("/srv/jail")),
        )
        .unwrap();
        assert_eq!(p, Path::new("/srv/jail/u/file.txt"));
    }

    #[test]
    fn resolve_in_jail_relative_maps_absolute_paths_into_the_jail() {
        let jail = Some(Path::new("/srv/jail"));
        let cwd = Path::new("/srv/jail/u");
        // What a client does with realpath's `/` answer under the jail.
        assert_eq!(
            resolve_in(cwd, b"/etc/passwd", jail, true).unwrap(),
            Path::new("/srv/jail/etc/passwd")
        );
        assert_eq!(
            resolve_in(cwd, b"/", jail, true).unwrap(),
            Path::new("/srv/jail")
        );
        // `..` from the jail's root stays at the jail's root, as in a chroot.
        assert_eq!(
            resolve_in(cwd, b"/../../etc/passwd", jail, true).unwrap(),
            Path::new("/srv/jail/etc/passwd")
        );
        // Relative paths are unchanged.
        assert_eq!(
            resolve_in(cwd, b"f", jail, true).unwrap(),
            Path::new("/srv/jail/u/f")
        );
        // Without the flag (host paths shown), an absolute path is a host
        // path and is still confined.
        assert_eq!(
            resolve_in(cwd, b"/srv/jail/f", jail, false).unwrap(),
            Path::new("/srv/jail/f")
        );
        assert!(resolve_in(cwd, b"/etc/passwd", jail, false).is_err());
        // No jail: the flag is meaningless.
        assert_eq!(
            resolve_in(cwd, b"/etc/passwd", None, true).unwrap(),
            Path::new("/etc/passwd")
        );
    }

    #[test]
    fn is_inside_basics() {
        assert!(is_inside(Path::new("/a/b/c"), Path::new("/a/b")));
        assert!(is_inside(Path::new("/a/b"), Path::new("/a/b")));
        assert!(is_inside(Path::new("/a/b/c"), Path::new("/")));
        assert!(!is_inside(Path::new("/a/bc"), Path::new("/a/b")));
        assert!(!is_inside(Path::new("/a"), Path::new("/a/b")));
    }
}
