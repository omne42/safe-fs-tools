use std::fs;
use std::io::{Read, Write};
use std::path::Path;

use crate::error::{Error, Result};

#[cfg(all(test, unix))]
pub(super) fn open_private_temp_file(path: &Path) -> std::io::Result<fs::File> {
    let mut open_options = fs::OpenOptions::new();
    open_options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        open_options.mode(0o600);
    }
    open_options.open(path)
}

pub(super) fn read_bytes_limited(path: &Path, relative: &Path, max_bytes: u64) -> Result<Vec<u8>> {
    // NOTE: Always check metadata before opening the file to avoid blocking on special files
    // (e.g. FIFOs) in `File::open` on Unix.
    let meta = fs::metadata(path).map_err(|err| Error::io_path("metadata", relative, err))?;
    if !meta.is_file() {
        return Err(Error::InvalidPath(format!(
            "path {} is not a regular file",
            relative.display()
        )));
    }
    if meta.len() > max_bytes {
        return Err(Error::FileTooLarge {
            path: relative.to_path_buf(),
            size_bytes: meta.len(),
            max_bytes,
        });
    }

    let file = fs::File::open(path).map_err(|err| Error::io_path("open", relative, err))?;
    let limit = max_bytes.saturating_add(1);
    let mut bytes = Vec::<u8>::new();
    file.take(limit)
        .read_to_end(&mut bytes)
        .map_err(|err| Error::io_path("read", relative, err))?;
    if bytes.len() as u64 > max_bytes {
        return Err(Error::FileTooLarge {
            path: relative.to_path_buf(),
            size_bytes: bytes.len() as u64,
            max_bytes,
        });
    }
    Ok(bytes)
}

pub(super) fn read_string_limited(path: &Path, relative: &Path, max_bytes: u64) -> Result<String> {
    let bytes = read_bytes_limited(path, relative, max_bytes)?;
    std::str::from_utf8(&bytes)
        .map_err(|_| Error::InvalidUtf8(relative.to_path_buf()))
        .map(str::to_string)
}

pub(super) fn write_bytes_atomic(path: &Path, relative: &Path, bytes: &[u8]) -> Result<()> {
    let meta = fs::metadata(path).map_err(|err| Error::io_path("metadata", relative, err))?;
    if !meta.is_file() {
        return Err(Error::InvalidPath(format!(
            "path {} is not a regular file",
            relative.display()
        )));
    }

    // Preserve prior behavior: fail if the original file isn't writable.
    let _ = fs::OpenOptions::new()
        .write(true)
        .open(path)
        .map_err(|err| Error::io_path("open_for_write", relative, err))?;

    let perms = meta.permissions();

    let parent = path.parent().ok_or_else(|| {
        Error::InvalidPath(format!(
            "invalid path {}: missing parent directory",
            relative.display()
        ))
    })?;
    let _ = path.file_name().ok_or_else(|| {
        Error::InvalidPath(format!(
            "invalid path {}: missing file name",
            relative.display()
        ))
    })?;

    let mut tmp_file = tempfile::Builder::new()
        .prefix(".safe-fs-tools.")
        .suffix(".tmp")
        .tempfile_in(parent)
        .map_err(|err| Error::io_path("create_temp", relative, err))?;

    tmp_file
        .as_file_mut()
        .write_all(bytes)
        .map_err(|err| Error::io_path("write", relative, err))?;
    tmp_file
        .as_file_mut()
        .sync_all()
        .map_err(|err| Error::io_path("sync", relative, err))?;

    let tmp_path = tmp_file.into_temp_path();

    fs::set_permissions(&tmp_path, perms)
        .map_err(|err| Error::io_path("set_permissions", relative, err))?;

    rename_replace(tmp_path.as_ref(), path, true)
        .map_err(|err| Error::io_path("replace_file", relative, err))?;

    Ok(())
}

#[cfg(windows)]
pub(super) fn rename_replace(
    src_path: &Path,
    dest_path: &Path,
    replace_existing: bool,
) -> std::io::Result<()> {
    use std::os::windows::ffi::OsStrExt;

    use windows_sys::Win32::Storage::FileSystem::{MOVEFILE_REPLACE_EXISTING, MoveFileExW};

    fn to_wide_null(p: &Path) -> Vec<u16> {
        let mut wide: Vec<u16> = p.as_os_str().encode_wide().collect();
        wide.push(0);
        wide
    }

    let src_w = to_wide_null(src_path);
    let dest_w = to_wide_null(dest_path);

    let flags = if replace_existing {
        MOVEFILE_REPLACE_EXISTING
    } else {
        0
    };

    // Safety: `src_w` and `dest_w` are NUL-terminated UTF-16 paths kept alive for the duration of
    // the call; `MoveFileExW` reads them synchronously and does not store the pointers.
    let moved = unsafe { MoveFileExW(src_w.as_ptr(), dest_w.as_ptr(), flags) };
    if moved == 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(not(windows))]
pub(super) fn rename_replace(
    src_path: &Path,
    dest_path: &Path,
    _replace_existing: bool,
) -> std::io::Result<()> {
    fs::rename(src_path, dest_path)
}
