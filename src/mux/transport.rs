//! Carrier for the mux control connection.
//!
//! The master listens and clients connect on a bidirectional byte stream whose
//! kind depends on the platform: a Unix-domain socket on Unix, and a byte-mode
//! named pipe on Windows. The mux protocol in codec runs unchanged on either.
//!
//! The ControlPath names the carrier. On Unix the path is the socket file itself.
//! On Windows the path is only a key: the pipe name is derived from it, so the
//! master and every client that use the same ControlPath meet at the same pipe.

#[cfg(unix)]
mod imp {
    use std::fs;
    use std::io;
    use std::os::unix::fs::{DirBuilderExt, FileTypeExt, MetadataExt, PermissionsExt};
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::path::Path;

    pub(crate) type Stream = UnixStream;
    pub(crate) type Listener = UnixListener;

    /// Trust check run before every client connect. The path must be a
    /// Unix-domain socket owned by our effective uid, with no group or world
    /// permission bits, and it must not be a symlink.
    pub(crate) fn validate(path: &Path) -> io::Result<()> {
        let md = fs::symlink_metadata(path)?;
        let reject = |why: String| {
            io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("control socket {}: {why}", path.display()),
            )
        };
        if md.file_type().is_symlink() {
            return Err(reject("is a symlink; refusing to follow it".into()));
        }
        if !md.file_type().is_socket() {
            return Err(reject("is not a Unix-domain socket".into()));
        }
        let euid = crate::sys::effective_uid()?;
        if md.uid() != euid {
            return Err(reject(format!(
                "is owned by uid {} but we are euid {euid}; refusing to trust another user's master",
                md.uid()
            )));
        }
        let mode = md.mode() & 0o777;
        if (mode & 0o077) != 0 {
            return Err(reject(format!(
                "is group/world-accessible (mode {mode:04o}); refusing to use it"
            )));
        }
        Ok(())
    }

    /// Validate, then connect to the master at the given path.
    pub(crate) fn connect(path: &Path) -> io::Result<Stream> {
        validate(path)?;
        UnixStream::connect(path)
    }

    /// Bind the master's carrier at the given path with owner-only
    /// permissions, without ever leaving a window in which another user could
    /// connect.
    ///
    /// A plain bind creates the socket `0777 & ~umask`, and the chmod after it
    /// leaves such a window. OpenSSH binds a temporary name under umask 0177
    /// and link(2)s it into place; the library cannot change the umask
    /// (`forbid(unsafe_code)`), so it binds inside a fresh 0700 directory next
    /// to `path` instead, makes the socket 0600 there and then links it to
    /// `path` — which, unlike a rename, fails rather than replace a master
    /// that bound `path` in the meantime.
    pub(crate) fn bind(path: &Path) -> io::Result<Listener> {
        match bind_private(path) {
            Ok(l) => return Ok(l),
            // The temporary name did not fit in a socket address (a very
            // short ControlPath file name): bind in place below.
            Err(e) if e.kind() == io::ErrorKind::InvalidInput => {}
            Err(e) => return Err(e),
        }
        let listener = UnixListener::bind(path)?;
        // 0600: only the owner may connect to the multiplexed connection.
        if let Err(e) = fs::set_permissions(path, fs::Permissions::from_mode(0o600)) {
            let _ = fs::remove_file(path);
            return Err(io::Error::new(
                e.kind(),
                format!("chmod 0600 {}: {e}", path.display()),
            ));
        }
        Ok(listener)
    }

    /// Bind a socket nobody else can reach at any point: a 0700 directory next
    /// to `path` holds the 0600 socket, which is then hard-linked into place.
    fn bind_private(path: &Path) -> io::Result<Listener> {
        let parent = match path.parent() {
            Some(p) if !p.as_os_str().is_empty() => p,
            _ => Path::new("."),
        };
        let seed = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.subsec_nanos())
            ^ std::process::id().rotate_left(16);
        let mut dir = None;
        for i in 0..16u32 {
            // Kept short: the socket inside must still fit in `sun_path`.
            let d = parent.join(format!(".m{:06x}", seed.wrapping_add(i) & 0xff_ffff));
            match fs::DirBuilder::new().mode(0o700).create(&d) {
                Ok(()) => {
                    dir = Some(d);
                    break;
                }
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(e) => return Err(e),
            }
        }
        let Some(dir) = dir else {
            return Err(io::Error::other("no free temporary directory name"));
        };
        let tmp = dir.join("s");
        let res = UnixListener::bind(&tmp).and_then(|l| {
            fs::set_permissions(&tmp, fs::Permissions::from_mode(0o600))?;
            fs::hard_link(&tmp, path)?;
            Ok(l)
        });
        let _ = fs::remove_file(&tmp);
        let _ = fs::remove_dir(&dir);
        res
    }

    pub(crate) fn accept(listener: &Listener) -> io::Result<Stream> {
        listener.accept().map(|(stream, _)| stream)
    }

    /// Remove the carrier's name so that new clients stop finding this master.
    pub(crate) fn unlink(path: &Path) {
        let _ = fs::remove_file(path);
    }

    /// Make one throwaway connection so that a blocked accept returns.
    pub(crate) fn wake(path: &Path) {
        let _ = UnixStream::connect(path);
    }
}

#[cfg(all(windows, feature = "win-ipc"))]
mod imp {
    use std::io;
    use std::path::Path;

    use super::super::win::{self, PipeConn, PipeListener};

    pub(crate) type Stream = PipeConn;
    pub(crate) type Listener = PipeListener;

    fn name_for(path: &Path) -> io::Result<String> {
        win::carrier_name(&path.to_string_lossy())
    }

    /// There is no file to inspect. Ownership is verified when the pipe is opened.
    pub(crate) fn validate(path: &Path) -> io::Result<()> {
        if path.as_os_str().is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "empty ControlPath",
            ));
        }
        Ok(())
    }

    pub(crate) fn connect(path: &Path) -> io::Result<Stream> {
        win::connect(&name_for(path)?)
    }

    pub(crate) fn bind(path: &Path) -> io::Result<Listener> {
        PipeListener::bind(&name_for(path)?)
    }

    pub(crate) fn accept(listener: &Listener) -> io::Result<Stream> {
        listener.accept()
    }

    /// Named pipes disappear with their last handle, so there is nothing to remove.
    pub(crate) fn unlink(_path: &Path) {}

    /// Make one throwaway connection so that a blocked accept returns.
    pub(crate) fn wake(path: &Path) {
        let _ = connect(path);
    }
}

pub(crate) use imp::{Listener, Stream, accept, bind, connect, unlink, validate, wake};
