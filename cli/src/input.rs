use std::fs::{File, Metadata};
use std::io::Read;
use std::path::Path;

const HARD_MAX_TEXT_INPUT_BYTES: u64 = 64 * 1024 * 1024;
const MAX_INITIAL_STDIN_CAPACITY: usize = 64 * 1024;
const DEFAULT_INITIAL_FILE_CAPACITY: usize = 8 * 1024;
const MAX_INITIAL_FILE_CAPACITY: usize = 256 * 1024;

fn symlink_rejected_error(path: &Path) -> safe_fs_tools::Error {
    safe_fs_tools::Error::InvalidPath(format!(
        "path resolution for {} detected a symlink; refusing to read text inputs from symlink paths",
        path.display()
    ))
}

fn open_input_file(path: &Path) -> Result<(File, Metadata), safe_fs_tools::Error> {
    match safe_fs_tools::open_regular_readonly_nofollow(path) {
        Ok((file, metadata)) => Ok((file, metadata)),
        Err(err) => {
            if safe_fs_tools::is_symlink_or_reparse_open_error(&err) {
                return Err(symlink_rejected_error(path));
            }
            if err.kind() == std::io::ErrorKind::InvalidInput {
                let is_symlink = std::fs::symlink_metadata(path)
                    .map(|metadata| metadata.file_type().is_symlink())
                    .unwrap_or(false);
                if is_symlink {
                    return Err(symlink_rejected_error(path));
                }
                return Err(safe_fs_tools::Error::InvalidPath(format!(
                    "path {} is not a regular file",
                    path.display()
                )));
            }
            if err.kind() == std::io::ErrorKind::Unsupported {
                return Err(safe_fs_tools::Error::InvalidPath(
                    "loading text inputs on this platform requires an atomic no-follow open primitive"
                        .to_string(),
                ));
            }
            Err(safe_fs_tools::Error::IoPath {
                op: "open",
                path: path.to_path_buf(),
                source: err,
            })
        }
    }
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

    let limit = max_bytes.saturating_add(1);
    let reads_stdin = path.as_os_str() == "-";
    let mut bytes = if reads_stdin {
        Vec::<u8>::with_capacity(initial_stdin_capacity(max_bytes))
    } else {
        Vec::<u8>::new()
    };
    let mut known_size = None;

    if reads_stdin {
        std::io::stdin()
            .take(limit)
            .read_to_end(&mut bytes)
            .map_err(|err| safe_fs_tools::Error::IoPath {
                op: "read_stdin",
                path: path.to_path_buf(),
                source: err,
            })?;
    } else {
        let (file, metadata) = open_input_file(path)?;
        let file_size = metadata.len();
        if file_size > max_bytes {
            return Err(safe_fs_tools::Error::InputTooLarge {
                size_bytes: file_size,
                max_bytes,
            });
        }
        known_size = Some(file_size);
        bytes = Vec::<u8>::with_capacity(initial_input_capacity(file_size, max_bytes));

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

    String::from_utf8(bytes).map_err(|err| safe_fs_tools::Error::InvalidUtf8 {
        path: path.to_path_buf(),
        source: err.into(),
    })
}

fn initial_input_capacity(file_size: u64, max_bytes: u64) -> usize {
    usize::try_from(file_size.min(max_bytes))
        .ok()
        .map_or(DEFAULT_INITIAL_FILE_CAPACITY, |capacity| {
            capacity.min(MAX_INITIAL_FILE_CAPACITY)
        })
}

fn initial_stdin_capacity(max_bytes: u64) -> usize {
    usize::try_from(max_bytes)
        .ok()
        .map_or(MAX_INITIAL_STDIN_CAPACITY, |max| {
            max.min(MAX_INITIAL_STDIN_CAPACITY)
        })
}

#[cfg(test)]
mod tests {
    use super::{initial_input_capacity, initial_stdin_capacity};

    #[test]
    fn initial_input_capacity_keeps_small_values() {
        assert_eq!(initial_input_capacity(2048, 4096), 2048);
        assert_eq!(initial_input_capacity(0, 4096), 0);
    }

    #[test]
    fn initial_input_capacity_caps_large_values() {
        assert_eq!(
            initial_input_capacity(64 * 1024 * 1024, 64 * 1024 * 1024),
            256 * 1024
        );
    }

    #[test]
    fn initial_stdin_capacity_is_bounded() {
        assert_eq!(initial_stdin_capacity(1024), 1024);
        assert_eq!(initial_stdin_capacity(64 * 1024 * 1024), 64 * 1024);
    }
}
