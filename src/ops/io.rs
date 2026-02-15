use std::fs;
use std::io::{Read, Write};
use std::path::Path;

use crate::error::{Error, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum FileIdentity {
    #[cfg(unix)]
    Unix { dev: u64, ino: u64 },
    #[cfg(windows)]
    Windows { volume_serial: u64, file_index: u64 },
}

impl FileIdentity {
    fn from_metadata(meta: &fs::Metadata) -> Option<Self> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;

            Some(Self::Unix {
                dev: meta.dev(),
                ino: meta.ino(),
            })
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::MetadataExt;

            Some(Self::Windows {
                volume_serial: u64::from(meta.volume_serial_number()?),
                file_index: meta.file_index()?,
            })
        }
        #[cfg(all(not(unix), not(windows)))]
        {
            let _ = meta;
            None
        }
    }
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
    let file = crate::platform_open::open_readonly_nofollow(path).map_err(|err| {
        if crate::platform_open::is_symlink_open_error(&err) {
            return Error::InvalidPath(format!("path {} is a symlink", relative.display()));
        }
        Error::io_path("open", relative, err)
    })?;
    let meta = file
        .metadata()
        .map_err(|err| Error::io_path("metadata", relative, err))?;
    reject_symlink_metadata(&meta, relative)?;
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
        if crate::platform_open::is_symlink_open_error(&err) {
            return Error::InvalidPath(format!("path {} is a symlink", relative.display()));
        }
        Error::io_path("open_for_write", relative, err)
    })?;
    let meta = file
        .metadata()
        .map_err(|err| Error::io_path("metadata", relative, err))?;
    reject_symlink_metadata(&meta, relative)?;
    if !meta.is_file() {
        return Err(Error::InvalidPath(format!(
            "path {} is not a regular file",
            relative.display()
        )));
    }
    Ok((file, meta))
}

#[cfg(windows)]
fn reject_symlink_metadata(meta: &fs::Metadata, relative: &Path) -> Result<()> {
    if meta.file_type().is_symlink() {
        return Err(Error::InvalidPath(format!(
            "path {} is a symlink",
            relative.display()
        )));
    }
    Ok(())
}

#[cfg(not(windows))]
fn reject_symlink_metadata(_meta: &fs::Metadata, _relative: &Path) -> Result<()> {
    Ok(())
}

fn verify_expected_identity(
    relative: &Path,
    expected_identity: Option<FileIdentity>,
    actual_identity: Option<FileIdentity>,
) -> Result<()> {
    match (expected_identity, actual_identity) {
        (Some(expected), Some(actual)) if expected != actual => Err(Error::InvalidPath(format!(
            "path {} changed during operation",
            relative.display()
        ))),
        (Some(_), None) => Err(Error::InvalidPath(format!(
            "cannot verify identity for path {} on this platform",
            relative.display()
        ))),
        _ => Ok(()),
    }
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

pub(super) fn read_string_limited_with_identity(
    path: &Path,
    relative: &Path,
    max_bytes: u64,
) -> Result<(String, FileIdentity)> {
    let (file, meta) = open_regular_file_for_read(path, relative)?;
    let identity = FileIdentity::from_metadata(&meta).ok_or_else(|| {
        Error::InvalidPath(format!(
            "cannot verify identity for path {} on this platform",
            relative.display()
        ))
    })?;
    let bytes = read_open_file_limited(file, relative, max_bytes, meta.len())?;
    decode_utf8(relative, bytes).map(|text| (text, identity))
}

fn decode_utf8(relative: &Path, bytes: Vec<u8>) -> Result<String> {
    String::from_utf8(bytes).map_err(|err| Error::invalid_utf8(relative.to_path_buf(), err))
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

pub(super) fn write_bytes_atomic_checked(
    path: &Path,
    relative: &Path,
    bytes: &[u8],
    expected_identity: FileIdentity,
) -> Result<()> {
    write_bytes_atomic_impl(path, relative, bytes, Some(expected_identity), true)
}

fn write_bytes_atomic_impl(
    path: &Path,
    relative: &Path,
    bytes: &[u8],
    expected_identity: Option<FileIdentity>,
    recheck_before_commit: bool,
) -> Result<()> {
    // Preserve prior behavior: fail if the original file isn't writable.
    let (existing_file, meta) = open_regular_file_for_write(path, relative)?;
    verify_expected_identity(
        relative,
        expected_identity,
        FileIdentity::from_metadata(&meta),
    )?;

    // Keep existing mode/readonly permissions, then preserve Unix security metadata.
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

    tmp_file
        .as_file()
        .set_permissions(perms)
        .map_err(|err| Error::io_path("set_permissions", relative, err))?;
    #[cfg(unix)]
    crate::platform::unix_metadata::preserve_unix_security_metadata(
        &existing_file,
        &meta,
        tmp_file.as_file(),
    )
    .map_err(|err| Error::io_path("preserve_metadata", relative, err))?;
    tmp_file
        .as_file_mut()
        .sync_all()
        .map_err(|err| Error::io_path("sync", relative, err))?;

    let tmp_path = tmp_file.into_temp_path();

    if recheck_before_commit {
        // Best-effort conflict detection: re-open with no-follow and re-check identity
        // right before commit to narrow the TOCTOU window between read and replace.
        let (_recheck_file, recheck_meta) = open_regular_file_for_write(path, relative)?;
        verify_expected_identity(
            relative,
            expected_identity,
            FileIdentity::from_metadata(&recheck_meta),
        )?;
    }

    rename_replace(tmp_path.as_ref(), path, true)
        .map_err(|err| Error::io_path("replace_file", relative, err))?;

    Ok(())
}

pub(super) fn rename_replace(
    src_path: &Path,
    dest_path: &Path,
    replace_existing: bool,
) -> std::io::Result<()> {
    crate::platform::rename::rename_replace(src_path, dest_path, replace_existing)
}
