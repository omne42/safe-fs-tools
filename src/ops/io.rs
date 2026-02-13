use std::fs;
use std::io::{Read, Write};
use std::path::Path;

use crate::error::{Error, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct FileIdentity {
    #[cfg(unix)]
    dev: u64,
    #[cfg(unix)]
    ino: u64,
}

impl FileIdentity {
    fn from_metadata(meta: &fs::Metadata) -> Option<Self> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;

            Some(Self {
                dev: meta.dev(),
                ino: meta.ino(),
            })
        }
        #[cfg(not(unix))]
        {
            let _ = meta;
            None
        }
    }
}

#[cfg(unix)]
fn is_symlink_open_error(err: &std::io::Error) -> bool {
    err.raw_os_error() == Some(libc::ELOOP)
}

#[cfg(not(unix))]
fn is_symlink_open_error(_err: &std::io::Error) -> bool {
    false
}

#[cfg(unix)]
fn open_readonly_nofollow(path: &Path) -> std::io::Result<fs::File> {
    use std::os::unix::fs::OpenOptionsExt;

    let mut options = fs::OpenOptions::new();
    options
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    options.open(path)
}

#[cfg(windows)]
fn open_readonly_nofollow(path: &Path) -> std::io::Result<fs::File> {
    use std::os::windows::fs::OpenOptionsExt;
    use windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT;

    let mut options = fs::OpenOptions::new();
    options
        .read(true)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    options.open(path)
}

#[cfg(all(not(unix), not(windows)))]
fn open_readonly_nofollow(path: &Path) -> std::io::Result<fs::File> {
    let _ = path;
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "platform does not support atomic no-follow reads",
    ))
}

#[cfg(unix)]
fn open_writeonly_nofollow(path: &Path) -> std::io::Result<fs::File> {
    use std::os::unix::fs::OpenOptionsExt;

    let mut options = fs::OpenOptions::new();
    options
        .write(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    options.open(path)
}

#[cfg(windows)]
fn open_writeonly_nofollow(path: &Path) -> std::io::Result<fs::File> {
    use std::os::windows::fs::OpenOptionsExt;
    use windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT;

    let mut options = fs::OpenOptions::new();
    options
        .write(true)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    options.open(path)
}

#[cfg(all(not(unix), not(windows)))]
fn open_writeonly_nofollow(path: &Path) -> std::io::Result<fs::File> {
    let _ = path;
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "platform does not support atomic no-follow writes",
    ))
}

pub(super) fn open_regular_file_for_read(
    path: &Path,
    relative: &Path,
) -> Result<(fs::File, fs::Metadata)> {
    let file = open_readonly_nofollow(path).map_err(|err| {
        if is_symlink_open_error(&err) {
            return Error::InvalidPath(format!("path {} is a symlink", relative.display()));
        }
        Error::io_path("open", relative, err)
    })?;
    let meta = file
        .metadata()
        .map_err(|err| Error::io_path("metadata", relative, err))?;
    if !meta.is_file() {
        return Err(Error::InvalidPath(format!(
            "path {} is not a regular file",
            relative.display()
        )));
    }
    Ok((file, meta))
}

fn open_regular_file_for_write(path: &Path, relative: &Path) -> Result<(fs::File, fs::Metadata)> {
    let file = open_writeonly_nofollow(path).map_err(|err| {
        if is_symlink_open_error(&err) {
            return Error::InvalidPath(format!("path {} is a symlink", relative.display()));
        }
        Error::io_path("open_for_write", relative, err)
    })?;
    let meta = file
        .metadata()
        .map_err(|err| Error::io_path("metadata", relative, err))?;
    if !meta.is_file() {
        return Err(Error::InvalidPath(format!(
            "path {} is not a regular file",
            relative.display()
        )));
    }
    Ok((file, meta))
}

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
    let (file, meta) = open_regular_file_for_read(path, relative)?;
    read_open_file_limited(file, relative, max_bytes, meta.len())
}

pub(super) fn read_string_limited(path: &Path, relative: &Path, max_bytes: u64) -> Result<String> {
    let (text, _identity) = read_string_limited_with_identity(path, relative, max_bytes)?;
    Ok(text)
}

pub(super) fn read_string_limited_with_identity(
    path: &Path,
    relative: &Path,
    max_bytes: u64,
) -> Result<(String, Option<FileIdentity>)> {
    let (file, meta) = open_regular_file_for_read(path, relative)?;
    let identity = FileIdentity::from_metadata(&meta);
    let bytes = read_open_file_limited(file, relative, max_bytes, meta.len())?;
    std::str::from_utf8(&bytes)
        .map_err(|_| Error::InvalidUtf8(relative.to_path_buf()))
        .map(str::to_string)
        .map(|text| (text, identity))
}

fn file_too_large(relative: &Path, size_bytes: u64, max_bytes: u64) -> Error {
    Error::FileTooLarge {
        path: relative.to_path_buf(),
        size_bytes,
        max_bytes,
    }
}

fn read_open_file_limited(
    file: fs::File,
    relative: &Path,
    max_bytes: u64,
    known_size: u64,
) -> Result<Vec<u8>> {
    if known_size > max_bytes {
        return Err(file_too_large(relative, known_size, max_bytes));
    }

    let limit = max_bytes.saturating_add(1);
    let mut bytes = Vec::<u8>::new();
    file.take(limit)
        .read_to_end(&mut bytes)
        .map_err(|err| Error::io_path("read", relative, err))?;
    let read_size = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
    if read_size > max_bytes {
        return Err(file_too_large(relative, read_size, max_bytes));
    }
    Ok(bytes)
}

pub(super) fn write_bytes_atomic(path: &Path, relative: &Path, bytes: &[u8]) -> Result<()> {
    write_bytes_atomic_checked(path, relative, bytes, None)
}

pub(super) fn write_bytes_atomic_checked(
    path: &Path,
    relative: &Path,
    bytes: &[u8],
    expected_identity: Option<FileIdentity>,
) -> Result<()> {
    // Preserve prior behavior: fail if the original file isn't writable.
    let (_existing_file, meta) = open_regular_file_for_write(path, relative)?;
    match (expected_identity, FileIdentity::from_metadata(&meta)) {
        (Some(expected), Some(actual)) if expected != actual => {
            return Err(Error::InvalidPath(format!(
                "path {} changed during operation",
                relative.display()
            )));
        }
        (Some(_), None) => {
            return Err(Error::InvalidPath(format!(
                "cannot verify identity for path {} on this platform",
                relative.display()
            )));
        }
        _ => {}
    }

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

#[cfg(unix)]
fn sync_parent_directory(path: &Path) -> std::io::Result<()> {
    let Some(parent) = path.parent() else {
        return Ok(());
    };
    if parent.as_os_str().is_empty() {
        return Ok(());
    }
    let parent_dir = fs::File::open(parent)?;
    parent_dir.sync_all()
}

#[cfg(not(unix))]
fn sync_parent_directory(_path: &Path) -> std::io::Result<()> {
    Ok(())
}

#[cfg(unix)]
fn sync_rename_parents(src_path: &Path, dest_path: &Path) -> std::io::Result<()> {
    sync_parent_directory(dest_path)?;
    let src_parent = src_path.parent();
    let dest_parent = dest_path.parent();
    if src_parent != dest_parent {
        sync_parent_directory(src_path)?;
    }
    Ok(())
}

#[cfg(not(unix))]
fn sync_rename_parents(_src_path: &Path, _dest_path: &Path) -> std::io::Result<()> {
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

    // WHY THIS UNSAFE EXISTS (and why we intentionally keep it):
    //
    // `safe-fs-tools` treats in-place updates as atomic replacement (temp file -> replace target)
    // so readers never observe a "destination missing" gap during overwrite. A pure std fallback
    // (`remove_*` + `fs::rename`) is not equivalent on Windows: it introduces a non-atomic window
    // where destination can disappear, violating replacement semantics and weakening tool-level
    // safety guarantees for concurrent readers.
    //
    // `MoveFileExW(..., MOVEFILE_REPLACE_EXISTING)` provides the platform primitive for overwrite
    // rename semantics without that delete-then-rename gap, so this call is a deliberate tradeoff:
    // keep one narrow FFI boundary to preserve the atomicity contract.
    //
    // Safety conditions for this call:
    // - `src_w` / `dest_w` are owned, NUL-terminated UTF-16 buffers.
    // - Pointers passed to Win32 are valid for the full duration of the synchronous call.
    // - Win32 does not retain these pointers after return.
    // - All filesystem policy/root checks are performed by higher layers before reaching here.
    //
    // If someone wants to remove this `unsafe`, they must replace it with a Windows API path that
    // preserves overwrite atomicity. Replacing with delete+rename is explicitly not acceptable.
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
    replace_existing: bool,
) -> std::io::Result<()> {
    if replace_existing {
        fs::rename(src_path, dest_path)?;
    } else {
        rename_no_replace(src_path, dest_path)?;
    }
    sync_rename_parents(src_path, dest_path)
}

#[cfg(all(unix, not(windows), any(target_os = "linux", target_os = "android")))]
fn rename_no_replace(src_path: &Path, dest_path: &Path) -> std::io::Result<()> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    let src = CString::new(src_path.as_os_str().as_bytes()).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "source path contains interior NUL byte",
        )
    })?;
    let dest = CString::new(dest_path.as_os_str().as_bytes()).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "destination path contains interior NUL byte",
        )
    })?;

    // Safety: both C strings are NUL-terminated and valid for the duration of this call.
    let rc = unsafe {
        libc::renameat2(
            libc::AT_FDCWD,
            src.as_ptr(),
            libc::AT_FDCWD,
            dest.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    };
    if rc == 0 {
        return Ok(());
    }
    Err(std::io::Error::last_os_error())
}

#[cfg(all(
    unix,
    not(windows),
    not(any(target_os = "linux", target_os = "android"))
))]
fn rename_no_replace(src_path: &Path, dest_path: &Path) -> std::io::Result<()> {
    let _ = src_path;
    let _ = dest_path;
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "atomic no-replace rename is unsupported on this platform",
    ))
}
