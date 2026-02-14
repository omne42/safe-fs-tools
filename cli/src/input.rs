use std::io::Read;
use std::path::Path;

fn open_input_file(path: &Path) -> Result<std::fs::File, safe_fs_tools::Error> {
    let file = safe_fs_tools::platform_open::open_readonly_nofollow(path).map_err(|err| {
        if safe_fs_tools::platform_open::is_symlink_open_error(&err) {
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
        return Err(safe_fs_tools::Error::InvalidPath(
            "max input bytes must be > 0".to_string(),
        ));
    }
    if max_bytes >= usize::MAX as u64 {
        return Err(safe_fs_tools::Error::InvalidPath(
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
