use std::fs::{File, OpenOptions};
use std::io;
use std::path::Path;

/// Returns `true` when an open failure should be mapped to an
/// `InvalidPath("... is a symlink")` style policy error.
#[cfg(unix)]
pub fn is_symlink_open_error(err: &io::Error) -> bool {
    err.raw_os_error() == Some(libc::ELOOP)
}

/// Returns `true` when an open failure should be mapped to an
/// `InvalidPath("... is a symlink")` style policy error.
#[cfg(windows)]
pub fn is_symlink_open_error(err: &io::Error) -> bool {
    use windows_sys::Win32::Foundation::{
        ERROR_CANT_RESOLVE_FILENAME, ERROR_REPARSE_POINT_ENCOUNTERED, ERROR_STOPPED_ON_SYMLINK,
    };

    match err.raw_os_error() {
        Some(code) => {
            // Keep a strict whitelist: direct "symlink encountered" plus
            // unresolved link traversal (loop/too many indirections).
            code == ERROR_STOPPED_ON_SYMLINK as i32
                || code == ERROR_REPARSE_POINT_ENCOUNTERED as i32
                || code == ERROR_CANT_RESOLVE_FILENAME as i32
        }
        None => false,
    }
}

/// Returns `true` when an open failure should be mapped to an
/// `InvalidPath("... is a symlink")` style policy error.
#[cfg(all(not(unix), not(windows)))]
pub fn is_symlink_open_error(_err: &io::Error) -> bool {
    false
}

/// Opens `path` for read-only access without following the final path component.
///
/// On Unix we also set `O_NONBLOCK` to avoid blocking when the target is a FIFO.
#[cfg(unix)]
pub fn open_readonly_nofollow(path: &Path) -> io::Result<File> {
    use std::os::unix::fs::OpenOptionsExt;

    let mut options = OpenOptions::new();
    options
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    options.open(path)
}

/// Opens `path` for read-only access without following the final path component.
#[cfg(windows)]
pub fn open_readonly_nofollow(path: &Path) -> io::Result<File> {
    use std::os::windows::fs::OpenOptionsExt;
    use windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT;

    let mut options = OpenOptions::new();
    options
        .read(true)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    options.open(path)
}

#[cfg(all(not(unix), not(windows)))]
pub fn open_readonly_nofollow(path: &Path) -> io::Result<File> {
    let _ = path;
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "platform does not support atomic no-follow reads",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn unix_symlink_open_is_classified_as_symlink_error() {
        use std::os::unix::fs::symlink;

        let dir = tempfile::tempdir().expect("create tempdir");
        let target = dir.path().join("target.txt");
        let link = dir.path().join("link.txt");

        std::fs::write(&target, b"x").expect("write target");
        symlink(&target, &link).expect("create symlink");

        let err = open_readonly_nofollow(&link).expect_err("symlink open should fail");
        assert!(is_symlink_open_error(&err));
    }

    #[cfg(windows)]
    #[test]
    fn windows_only_expected_reparse_errors_are_classified_as_symlink_errors() {
        use windows_sys::Win32::Foundation::{
            ERROR_CANT_ACCESS_FILE, ERROR_CANT_RESOLVE_FILENAME, ERROR_INVALID_REPARSE_DATA,
            ERROR_NOT_A_REPARSE_POINT, ERROR_REPARSE_POINT_ENCOUNTERED, ERROR_STOPPED_ON_SYMLINK,
        };

        for code in [
            ERROR_STOPPED_ON_SYMLINK,
            ERROR_CANT_RESOLVE_FILENAME,
            ERROR_REPARSE_POINT_ENCOUNTERED,
        ] {
            let err = io::Error::from_raw_os_error(code as i32);
            assert!(is_symlink_open_error(&err), "code {code} should be true");
        }

        for code in [
            ERROR_CANT_ACCESS_FILE,
            ERROR_NOT_A_REPARSE_POINT,
            ERROR_INVALID_REPARSE_DATA,
        ] {
            let err = io::Error::from_raw_os_error(code as i32);
            assert!(!is_symlink_open_error(&err), "code {code} should be false");
        }
    }

    #[cfg(all(not(unix), not(windows)))]
    #[test]
    fn unsupported_platform_open_returns_unsupported() {
        let path = Path::new("dummy");
        let err = open_readonly_nofollow(path).expect_err("open must fail");
        assert_eq!(err.kind(), io::ErrorKind::Unsupported);
        assert!(!is_symlink_open_error(&err));
    }
}
