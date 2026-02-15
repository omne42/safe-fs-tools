use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

use super::Context;

#[cfg(any(unix, windows))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ParentIdentity {
    #[cfg(unix)]
    Unix { dev: u64, ino: u64 },
    #[cfg(windows)]
    Windows { volume_serial: u64, file_index: u64 },
}

#[cfg(not(any(unix, windows)))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ParentIdentity;

#[cfg(unix)]
fn parent_identity_from_metadata(
    meta: &fs::Metadata,
    _relative_parent: &Path,
) -> Result<ParentIdentity> {
    use std::os::unix::fs::MetadataExt;

    Ok(ParentIdentity::Unix {
        dev: meta.dev(),
        ino: meta.ino(),
    })
}

#[cfg(windows)]
fn parent_identity_from_metadata(
    meta: &fs::Metadata,
    relative_parent: &Path,
) -> Result<ParentIdentity> {
    use std::os::windows::fs::MetadataExt;

    let Some(volume_serial) = meta.volume_serial_number() else {
        return Err(Error::InvalidPath(format!(
            "cannot verify parent identity for path {}",
            relative_parent.display()
        )));
    };
    let Some(file_index) = meta.file_index() else {
        return Err(Error::InvalidPath(format!(
            "cannot verify parent identity for path {}",
            relative_parent.display()
        )));
    };
    Ok(ParentIdentity::Windows {
        volume_serial: u64::from(volume_serial),
        file_index,
    })
}

#[cfg(not(any(unix, windows)))]
fn parent_identity_from_metadata(
    _meta: &fs::Metadata,
    _relative_parent: &Path,
) -> Result<ParentIdentity> {
    Err(Error::InvalidPath(
        "write is unsupported on this platform: cannot verify destination parent identity"
            .to_string(),
    ))
}

fn capture_parent_identity(
    canonical_parent: &Path,
    relative_parent: &Path,
) -> Result<ParentIdentity> {
    let meta = fs::symlink_metadata(canonical_parent)
        .map_err(|err| Error::io_path("symlink_metadata", relative_parent, err))?;
    if meta.file_type().is_symlink() || !meta.is_dir() {
        return Err(Error::InvalidPath(format!(
            "parent path {} changed during operation",
            relative_parent.display()
        )));
    }
    parent_identity_from_metadata(&meta, relative_parent)
}

fn write_temp_file(
    canonical_parent: &Path,
    relative: &Path,
    bytes: &[u8],
    permissions: Option<fs::Permissions>,
) -> Result<tempfile::TempPath> {
    let mut tmp_file = tempfile::Builder::new()
        .prefix(".safe-fs-tools.")
        .suffix(".tmp")
        .tempfile_in(canonical_parent)
        .map_err(|err| Error::io_path("create_temp", relative, err))?;
    tmp_file
        .as_file_mut()
        .write_all(bytes)
        .map_err(|err| Error::io_path("write", relative, err))?;
    tmp_file
        .as_file_mut()
        .sync_all()
        .map_err(|err| Error::io_path("sync", relative, err))?;
    if let Some(perms) = permissions {
        tmp_file
            .as_file()
            .set_permissions(perms)
            .map_err(|err| Error::io_path("set_permissions", relative, err))?;
        tmp_file
            .as_file_mut()
            .sync_all()
            .map_err(|err| Error::io_path("sync", relative, err))?;
    }
    Ok(tmp_file.into_temp_path())
}

struct WriteCommitContext<'ctx> {
    canonical_parent: &'ctx Path,
    relative_parent: &'ctx Path,
    expected_parent_identity: &'ctx ParentIdentity,
    relative: &'ctx Path,
    target: &'ctx Path,
    bytes: &'ctx [u8],
    permissions: Option<fs::Permissions>,
}

fn commit_write<F>(
    context: WriteCommitContext<'_>,
    overwrite: bool,
    map_rename_error: F,
) -> Result<()>
where
    F: FnOnce(std::io::Error) -> Error,
{
    verify_parent_identity(
        context.canonical_parent,
        context.relative_parent,
        context.expected_parent_identity,
    )?;
    let tmp_path = write_temp_file(
        context.canonical_parent,
        context.relative,
        context.bytes,
        context.permissions,
    )?;
    verify_parent_identity(
        context.canonical_parent,
        context.relative_parent,
        context.expected_parent_identity,
    )?;
    super::io::rename_replace(tmp_path.as_ref(), context.target, overwrite)
        .map_err(map_rename_error)?;
    Ok(())
}

fn verify_parent_identity(
    canonical_parent: &Path,
    relative_parent: &Path,
    expected_parent_identity: &ParentIdentity,
) -> Result<()> {
    let current_parent_meta = fs::symlink_metadata(canonical_parent)
        .map_err(|err| Error::io_path("symlink_metadata", relative_parent, err))?;
    if current_parent_meta.file_type().is_symlink() || !current_parent_meta.is_dir() {
        return Err(Error::InvalidPath(format!(
            "parent path {} changed during operation",
            relative_parent.display()
        )));
    }
    let current_parent_identity =
        parent_identity_from_metadata(&current_parent_meta, relative_parent)?;
    if current_parent_identity != *expected_parent_identity {
        return Err(Error::InvalidPath(format!(
            "parent path {} changed during operation",
            relative_parent.display()
        )));
    }
    Ok(())
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

fn ensure_existing_target_writable(target: &Path, relative: &Path) -> Result<()> {
    let file = open_writeonly_nofollow(target).map_err(|err| {
        if crate::platform_open::is_symlink_open_error(&err) {
            return Error::InvalidPath(format!("path {} is a symlink", relative.display()));
        }
        Error::io_path("open_for_write", relative, err)
    })?;
    let meta = file
        .metadata()
        .map_err(|err| Error::io_path("metadata", relative, err))?;
    if meta.file_type().is_symlink() {
        return Err(Error::InvalidPath(format!(
            "path {} is a symlink",
            relative.display()
        )));
    }
    if !meta.is_file() {
        return Err(Error::InvalidPath(format!(
            "path {} is not a regular file",
            relative.display()
        )));
    }
    Ok(())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WriteFileRequest {
    pub root_id: String,
    pub path: PathBuf,
    pub content: String,
    #[serde(default)]
    pub overwrite: bool,
    #[serde(default)]
    pub create_parents: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WriteFileResponse {
    pub path: PathBuf,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requested_path: Option<PathBuf>,
    pub bytes_written: u64,
    /// Best-effort preflight observation. Concurrent writers may still turn an
    /// apparent create into a replace before commit.
    pub created: bool,
}

pub fn write_file(ctx: &Context, request: WriteFileRequest) -> Result<WriteFileResponse> {
    ctx.ensure_write_operation_allowed(&request.root_id, ctx.policy.permissions.write, "write")?;

    let resolved =
        super::resolve::resolve_path_in_root_lexically(ctx, &request.root_id, &request.path)?;
    let canonical_root = resolved.canonical_root;
    let requested_path = resolved.requested_path;

    let bytes_written = u64::try_from(request.content.len()).map_err(|_| Error::FileTooLarge {
        path: requested_path.clone(),
        size_bytes: u64::MAX,
        max_bytes: ctx.policy.limits.max_write_bytes,
    })?;
    if bytes_written > ctx.policy.limits.max_write_bytes {
        return Err(Error::FileTooLarge {
            path: requested_path.clone(),
            size_bytes: bytes_written,
            max_bytes: ctx.policy.limits.max_write_bytes,
        });
    }

    let file_name = super::path_validation::ensure_non_root_leaf(
        &requested_path,
        &request.path,
        super::path_validation::LeafOp::Write,
    )?;

    let requested_parent = requested_path.parent().unwrap_or_else(|| Path::new(""));
    let canonical_parent =
        ctx.ensure_dir_under_root(&request.root_id, requested_parent, request.create_parents)?;

    let relative_parent =
        crate::path_utils::strip_prefix_case_insensitive(&canonical_parent, &canonical_root)
            .ok_or_else(|| Error::OutsideRoot {
                root_id: request.root_id.clone(),
                path: requested_path.clone(),
            })?;
    let parent_identity = capture_parent_identity(&canonical_parent, &relative_parent)?;
    let relative = relative_parent.join(file_name);

    if ctx.redactor.is_path_denied(&relative) {
        return Err(Error::SecretPathDenied(relative));
    }

    let target = canonical_parent.join(file_name);
    if !crate::path_utils::starts_with_case_insensitive(&target, &canonical_root) {
        return Err(Error::OutsideRoot {
            root_id: request.root_id.clone(),
            path: requested_path,
        });
    }

    let existing = match fs::symlink_metadata(&target) {
        Ok(meta) => Some(meta),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => None,
        Err(err) => return Err(Error::io_path("metadata", &relative, err)),
    };

    if let Some(meta) = existing {
        let file_type = meta.file_type();
        if file_type.is_dir() {
            return Err(Error::InvalidPath(
                "destination exists and is a directory".to_string(),
            ));
        }
        if file_type.is_symlink() {
            return Err(Error::InvalidPath(format!(
                "path {} is a symlink",
                relative.display()
            )));
        }
        if !file_type.is_file() {
            return Err(Error::InvalidPath(
                "destination exists and is not a regular file".to_string(),
            ));
        }

        if !request.overwrite {
            return Err(Error::InvalidPath("file exists".to_string()));
        }
        ensure_existing_target_writable(&target, &relative)?;

        let commit_context = WriteCommitContext {
            canonical_parent: &canonical_parent,
            relative_parent: &relative_parent,
            expected_parent_identity: &parent_identity,
            relative: &relative,
            target: &target,
            bytes: request.content.as_bytes(),
            permissions: Some(meta.permissions()),
        };
        commit_write(commit_context, true, |err| {
            Error::io_path("rename", &relative, err)
        })?;
        return Ok(WriteFileResponse {
            path: relative,
            requested_path: Some(requested_path),
            bytes_written,
            created: false,
        });
    }

    let commit_context = WriteCommitContext {
        canonical_parent: &canonical_parent,
        relative_parent: &relative_parent,
        expected_parent_identity: &parent_identity,
        relative: &relative,
        target: &target,
        bytes: request.content.as_bytes(),
        permissions: None,
    };
    commit_write(commit_context, request.overwrite, |err| {
        if err.kind() == std::io::ErrorKind::AlreadyExists && !request.overwrite {
            return Error::InvalidPath("file exists".to_string());
        }
        if err.kind() == std::io::ErrorKind::Unsupported && !request.overwrite {
            return Error::InvalidPath(
                "create without overwrite is unsupported on this platform".to_string(),
            );
        }
        Error::io_path("rename", &relative, err)
    })?;

    Ok(WriteFileResponse {
        path: relative,
        requested_path: Some(requested_path),
        bytes_written,
        created: true,
    })
}
