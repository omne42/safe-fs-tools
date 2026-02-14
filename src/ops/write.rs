use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

use super::Context;

#[cfg(unix)]
fn metadata_same_file(a: &fs::Metadata, b: &fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    a.dev() == b.dev() && a.ino() == b.ino()
}

#[cfg(windows)]
fn metadata_same_file(a: &fs::Metadata, b: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    a.volume_serial_number() == b.volume_serial_number() && a.file_index() == b.file_index()
}

#[cfg(any(unix, windows))]
fn ensure_parent_identity_verification_supported() -> Result<()> {
    Ok(())
}

#[cfg(not(any(unix, windows)))]
fn ensure_parent_identity_verification_supported() -> Result<()> {
    Err(Error::InvalidPath(
        "write is unsupported on this platform: cannot verify destination parent identity"
            .to_string(),
    ))
}

fn capture_parent_identity(
    canonical_parent: &Path,
    relative_parent: &Path,
) -> Result<fs::Metadata> {
    let meta = fs::symlink_metadata(canonical_parent)
        .map_err(|err| Error::io_path("symlink_metadata", relative_parent, err))?;
    if meta.file_type().is_symlink() || !meta.is_dir() {
        return Err(Error::InvalidPath(format!(
            "parent path {} changed during operation",
            relative_parent.display()
        )));
    }
    Ok(meta)
}

#[cfg(any(unix, windows))]
fn verify_parent_identity(
    canonical_parent: &Path,
    relative_parent: &Path,
    expected_parent_meta: &fs::Metadata,
) -> Result<()> {
    let current_parent_meta = fs::symlink_metadata(canonical_parent)
        .map_err(|err| Error::io_path("symlink_metadata", relative_parent, err))?;
    if current_parent_meta.file_type().is_symlink()
        || !current_parent_meta.is_dir()
        || !metadata_same_file(expected_parent_meta, &current_parent_meta)
    {
        return Err(Error::InvalidPath(format!(
            "parent path {} changed during operation",
            relative_parent.display()
        )));
    }
    Ok(())
}

#[cfg(not(any(unix, windows)))]
fn verify_parent_identity(
    _canonical_parent: &Path,
    _relative_parent: &Path,
    _expected_parent_meta: &fs::Metadata,
) -> Result<()> {
    Err(Error::InvalidPath(
        "write is unsupported on this platform: cannot verify destination parent identity"
            .to_string(),
    ))
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
    pub created: bool,
}

pub fn write_file(ctx: &Context, request: WriteFileRequest) -> Result<WriteFileResponse> {
    if !ctx.policy.permissions.write {
        return Err(Error::NotPermitted(
            "write is disabled by policy".to_string(),
        ));
    }
    ctx.ensure_can_write(&request.root_id, "write")?;

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
    ensure_parent_identity_verification_supported()?;
    let canonical_parent_meta = capture_parent_identity(&canonical_parent, &relative_parent)?;
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

        verify_parent_identity(&canonical_parent, &relative_parent, &canonical_parent_meta)?;
        let tmp_path = write_temp_file(
            &canonical_parent,
            &relative,
            request.content.as_bytes(),
            Some(meta.permissions()),
        )?;
        verify_parent_identity(&canonical_parent, &relative_parent, &canonical_parent_meta)?;
        super::io::rename_replace(tmp_path.as_ref(), &target, true)
            .map_err(|err| Error::io_path("rename", &relative, err))?;
        return Ok(WriteFileResponse {
            path: relative,
            requested_path: Some(requested_path),
            bytes_written,
            created: false,
        });
    }

    verify_parent_identity(&canonical_parent, &relative_parent, &canonical_parent_meta)?;
    let tmp_path = write_temp_file(
        &canonical_parent,
        &relative,
        request.content.as_bytes(),
        None,
    )?;
    verify_parent_identity(&canonical_parent, &relative_parent, &canonical_parent_meta)?;

    super::io::rename_replace(tmp_path.as_ref(), &target, request.overwrite).map_err(|err| {
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
