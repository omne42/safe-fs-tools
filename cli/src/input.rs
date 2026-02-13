use std::io::Read;
use std::path::Path;

#[cfg(unix)]
fn is_symlink_open_error(err: &std::io::Error) -> bool {
    err.raw_os_error() == Some(libc::ELOOP)
}

#[cfg(not(unix))]
fn is_symlink_open_error(_err: &std::io::Error) -> bool {
    false
}

#[cfg(unix)]
fn open_input_file(path: &Path) -> Result<std::fs::File, safe_fs_tools::Error> {
    use std::os::unix::fs::OpenOptionsExt;

    let mut options = std::fs::OpenOptions::new();
    options
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    options.open(path).map_err(|err| {
        if is_symlink_open_error(&err) {
            return safe_fs_tools::Error::InvalidPath(format!(
                "path resolution for {} encountered a symlink (or symlink loop); refusing to read text inputs from symlink paths",
                path.display()
            ));
        }
        safe_fs_tools::Error::IoPath {
            op: "open",
            path: path.to_path_buf(),
            source: err,
        }
    })
}

#[cfg(windows)]
fn open_input_file(path: &Path) -> Result<std::fs::File, safe_fs_tools::Error> {
    use std::os::windows::fs::OpenOptionsExt;

    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;

    let mut options = std::fs::OpenOptions::new();
    options
        .read(true)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    let file = options
        .open(path)
        .map_err(|err| safe_fs_tools::Error::IoPath {
            op: "open",
            path: path.to_path_buf(),
            source: err,
        })?;
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
    Ok(file)
}

#[cfg(all(not(unix), not(windows)))]
fn open_input_file(path: &Path) -> Result<std::fs::File, safe_fs_tools::Error> {
    let _ = path;
    Err(safe_fs_tools::Error::InvalidPath(
        "loading text inputs on this platform requires an atomic no-follow open primitive"
            .to_string(),
    ))
}

pub(crate) fn load_text_limited(
    path: &Path,
    max_bytes: u64,
) -> Result<String, safe_fs_tools::Error> {
    let limit = max_bytes.saturating_add(1);
    let mut bytes = Vec::<u8>::new();

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
        return Err(safe_fs_tools::Error::InputTooLarge {
            size_bytes: read_size,
            max_bytes,
        });
    }

    String::from_utf8(bytes).map_err(|_| safe_fs_tools::Error::InvalidUtf8(path.to_path_buf()))
}
