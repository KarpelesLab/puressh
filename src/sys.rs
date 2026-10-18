//! The few process facts the library needs from the OS that `std` does not
//! expose, obtained without `unsafe` (the crate forbids it outside `ffi`)
//! or a syscall-wrapper dependency.

#![cfg(all(unix, any(feature = "multichannel", feature = "server")))]

use std::fs::File;
use std::os::fd::OwnedFd;
use std::os::unix::fs::MetadataExt;

/// The effective uid, which `geteuid(2)` would return: a pipe is owned by
/// the (effective) uid of the process that made it, on Linux, macOS and
/// the BSDs alike.
pub(crate) fn effective_uid() -> std::io::Result<u32> {
    let (r, _w) = std::io::pipe()?;
    Ok(File::from(OwnedFd::from(r)).metadata()?.uid())
}

#[cfg(test)]
mod tests {
    #[test]
    fn effective_uid_is_the_owner_of_new_files() {
        let dir = std::env::temp_dir().join(format!("puressh-euid-{}", std::process::id()));
        std::fs::write(&dir, b"").unwrap();
        let owner = std::os::unix::fs::MetadataExt::uid(&std::fs::metadata(&dir).unwrap());
        std::fs::remove_file(&dir).unwrap();
        assert_eq!(super::effective_uid().unwrap(), owner);
    }
}
