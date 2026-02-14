use std::fs::{File, OpenOptions};
use std::io;
use std::path::Path;

#[cfg(unix)]
pub fn is_symlink_open_error(err: &io::Error) -> bool {
    err.raw_os_error() == Some(libc::ELOOP)
}

#[cfg(not(unix))]
pub fn is_symlink_open_error(_err: &io::Error) -> bool {
    false
}

#[cfg(unix)]
pub fn open_readonly_nofollow(path: &Path) -> io::Result<File> {
    use std::os::unix::fs::OpenOptionsExt;

    let mut options = OpenOptions::new();
    options
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    options.open(path)
}

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
