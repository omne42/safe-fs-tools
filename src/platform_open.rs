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
    const ERROR_STOPPED_ON_SYMLINK: i32 = 681;
    const ERROR_CANT_ACCESS_FILE: i32 = 1920;
    const ERROR_CANT_RESOLVE_FILENAME: i32 = 1921;
    const ERROR_NOT_A_REPARSE_POINT: i32 = 4390;
    const ERROR_INVALID_REPARSE_DATA: i32 = 4392;
    const ERROR_REPARSE_TAG_INVALID: i32 = 4393;
    const ERROR_REPARSE_TAG_MISMATCH: i32 = 4394;
    const ERROR_REPARSE_POINT_ENCOUNTERED: i32 = 4395;

    matches!(
        err.raw_os_error(),
        Some(
            ERROR_STOPPED_ON_SYMLINK
                | ERROR_CANT_ACCESS_FILE
                | ERROR_CANT_RESOLVE_FILENAME
                | ERROR_NOT_A_REPARSE_POINT
                | ERROR_INVALID_REPARSE_DATA
                | ERROR_REPARSE_TAG_INVALID
                | ERROR_REPARSE_TAG_MISMATCH
                | ERROR_REPARSE_POINT_ENCOUNTERED
        )
    )
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
