use std::fs::{File, OpenOptions};
use std::io::{self, Read};
use std::path::Path;

const HARD_MAX_TEXT_INPUT_BYTES: u64 = 64 * 1024 * 1024;

#[cfg(unix)]
fn is_symlink_open_error(err: &io::Error) -> bool {
    err.raw_os_error() == Some(libc::ELOOP)
}

#[cfg(windows)]
fn is_symlink_open_error(_err: &io::Error) -> bool {
    false
}

#[cfg(all(not(unix), not(windows)))]
fn is_symlink_open_error(_err: &io::Error) -> bool {
    false
}

#[cfg(unix)]
fn open_readonly_nofollow(path: &Path) -> io::Result<File> {
    use std::os::unix::fs::OpenOptionsExt;

    let mut options = OpenOptions::new();
    options
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    options.open(path)
}

#[cfg(windows)]
fn open_readonly_nofollow(path: &Path) -> io::Result<File> {
    use std::os::windows::fs::OpenOptionsExt;

    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;

    let mut options = OpenOptions::new();
    options
        .read(true)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    options.open(path)
}

#[cfg(all(not(unix), not(windows)))]
fn open_readonly_nofollow(path: &Path) -> io::Result<File> {
    let _ = path;
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "platform does not support atomic no-follow reads",
    ))
}

fn open_input_file(path: &Path) -> Result<std::fs::File, safe_fs_tools::Error> {
    let file = open_readonly_nofollow(path).map_err(|err| {
        if is_symlink_open_error(&err) {
            return safe_fs_tools::Error::InvalidPath(format!(
                "path resolution for {} encountered a symlink (or symlink loop); refusing to read text inputs from symlink paths",
                path.display()
            ));
        }
        if err.kind() == std::io::ErrorKind::Unsupported {
            return safe_fs_tools::Error::InvalidPath(
                "loading text inputs on this platform requires an atomic no-follow open primitive"
                    .to_string(),
            );
        }
        safe_fs_tools::Error::IoPath {
            op: "open",
            path: path.to_path_buf(),
            source: err,
        }
    })?;
    #[cfg(windows)]
    {
        let meta = file
            .metadata()
            .map_err(|err| safe_fs_tools::Error::IoPath {
                op: "metadata",
                path: path.to_path_buf(),
                source: err,
            })?;
        if meta.file_type().is_symlink() {
            return Err(safe_fs_tools::Error::InvalidPath(format!(
                "path {} is a symlink; refusing to read text inputs from symlink paths",
                path.display()
            )));
        }
    }
    Ok(file)
}

pub(crate) fn load_text_limited(
    path: &Path,
    max_bytes: u64,
) -> Result<String, safe_fs_tools::Error> {
    if max_bytes == 0 {
        return Err(safe_fs_tools::Error::InvalidPolicy(
            "max input bytes must be > 0".to_string(),
        ));
    }
    if max_bytes > HARD_MAX_TEXT_INPUT_BYTES {
        return Err(safe_fs_tools::Error::InvalidPolicy(format!(
            "max input bytes exceeds hard limit ({HARD_MAX_TEXT_INPUT_BYTES} bytes)"
        )));
    }
    if max_bytes >= usize::MAX as u64 {
        return Err(safe_fs_tools::Error::InvalidPolicy(
            "max input bytes exceeds platform limits".to_string(),
        ));
    }

    let limit = max_bytes.saturating_add(1);
    let mut bytes = Vec::<u8>::new();
    let mut known_size = None;

    if path.as_os_str() == "-" {
        std::io::stdin()
            .take(limit)
            .read_to_end(&mut bytes)
            .map_err(|err| safe_fs_tools::Error::IoPath {
                op: "read_stdin",
                path: path.to_path_buf(),
                source: err,
            })?;
    } else {
        let file = open_input_file(path)?;
        let meta = file
            .metadata()
            .map_err(|err| safe_fs_tools::Error::IoPath {
                op: "metadata",
                path: path.to_path_buf(),
                source: err,
            })?;
        if !meta.is_file() {
            return Err(safe_fs_tools::Error::InvalidPath(format!(
                "path {} is not a regular file",
                path.display()
            )));
        }
        let file_size = meta.len();
        if file_size > max_bytes {
            return Err(safe_fs_tools::Error::InputTooLarge {
                size_bytes: file_size,
                max_bytes,
            });
        }
        known_size = Some(file_size);

        file.take(limit)
            .read_to_end(&mut bytes)
            .map_err(|err| safe_fs_tools::Error::IoPath {
                op: "read",
                path: path.to_path_buf(),
                source: err,
            })?;
    }

    let read_size = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
    if read_size > max_bytes {
        let size_bytes = known_size.map_or(read_size, |size| size.max(read_size));
        return Err(safe_fs_tools::Error::InputTooLarge {
            size_bytes,
            max_bytes,
        });
    }

    String::from_utf8(bytes).map_err(|_| safe_fs_tools::Error::InvalidUtf8(path.to_path_buf()))
}
