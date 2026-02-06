use std::io::Read;
use std::path::Path;

pub(crate) fn load_text_limited(
    path: &Path,
    max_bytes: u64,
) -> Result<String, safe_fs_tools::Error> {
    let limit = max_bytes.saturating_add(1);
    let mut bytes = Vec::<u8>::new();

    if path.as_os_str() == "-" {
        std::io::stdin().take(limit).read_to_end(&mut bytes)?;
    } else {
        let meta = std::fs::symlink_metadata(path).map_err(|err| safe_fs_tools::Error::IoPath {
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
        if !meta.is_file() {
            return Err(safe_fs_tools::Error::InvalidPath(format!(
                "path {} is not a regular file",
                path.display()
            )));
        }

        std::fs::File::open(path)
            .map_err(|err| safe_fs_tools::Error::IoPath {
                op: "open",
                path: path.to_path_buf(),
                source: err,
            })?
            .take(limit)
            .read_to_end(&mut bytes)
            .map_err(|err| safe_fs_tools::Error::IoPath {
                op: "read",
                path: path.to_path_buf(),
                source: err,
            })?;
    }

    if bytes.len() as u64 > max_bytes {
        return Err(safe_fs_tools::Error::InputTooLarge {
            size_bytes: bytes.len() as u64,
            max_bytes,
        });
    }

    let text = std::str::from_utf8(&bytes)
        .map_err(|_| safe_fs_tools::Error::InvalidUtf8(path.to_path_buf()))?;
    Ok(text.to_string())
}
