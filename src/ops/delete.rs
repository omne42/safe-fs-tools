use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

use super::Context;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeleteRequest {
    pub root_id: String,
    pub path: PathBuf,
    #[serde(default)]
    pub recursive: bool,
    #[serde(default)]
    pub ignore_missing: bool,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DeleteKind {
    File,
    Dir,
    Symlink,
    Other,
    Missing,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeleteResponse {
    pub path: PathBuf,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requested_path: Option<PathBuf>,
    pub deleted: bool,
    #[serde(rename = "type")]
    pub kind: DeleteKind,
}

fn missing_response(requested_path: &Path) -> DeleteResponse {
    let requested_path = requested_path.to_path_buf();
    DeleteResponse {
        path: requested_path.clone(),
        requested_path: Some(requested_path),
        deleted: false,
        kind: DeleteKind::Missing,
    }
}

fn unlink_symlink(target: &Path) -> std::io::Result<()> {
    #[cfg(windows)]
    {
        match fs::remove_file(target) {
            Ok(()) => Ok(()),
            // On Windows, directory symlinks/junctions require remove_dir semantics.
            Err(remove_file_err) => match fs::remove_dir(target) {
                Ok(()) => Ok(()),
                Err(_) => Err(remove_file_err),
            },
        }
    }

    #[cfg(not(windows))]
    {
        fs::remove_file(target)
    }
}

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

#[cfg(not(any(unix, windows)))]
fn metadata_same_file(_a: &fs::Metadata, _b: &fs::Metadata) -> bool {
    false
}

#[cfg(any(unix, windows))]
fn ensure_delete_identity_verification_supported() -> Result<()> {
    Ok(())
}

#[cfg(not(any(unix, windows)))]
fn ensure_delete_identity_verification_supported() -> Result<()> {
    Err(Error::InvalidPath(
        "delete is unsupported on this platform: cannot verify file identity".to_string(),
    ))
}

fn revalidate_parent_before_delete(
    ctx: &Context,
    request: &DeleteRequest,
    requested_parent: &Path,
    canonical_parent: &Path,
    canonical_parent_meta: &fs::Metadata,
    requested_path: &Path,
) -> Result<Option<DeleteResponse>> {
    match ctx.ensure_dir_under_root(&request.root_id, requested_parent, false) {
        Ok(rechecked_parent) => {
            if rechecked_parent != canonical_parent {
                Err(Error::InvalidPath(format!(
                    "path {} changed during delete; refusing to continue",
                    requested_path.display()
                )))
            } else {
                let rechecked_parent_meta = match fs::symlink_metadata(&rechecked_parent) {
                    Ok(meta) => meta,
                    Err(err)
                        if request.ignore_missing && err.kind() == std::io::ErrorKind::NotFound =>
                    {
                        return Ok(Some(missing_response(requested_path)));
                    }
                    Err(err) => {
                        return Err(Error::io_path("symlink_metadata", requested_parent, err));
                    }
                };
                if !rechecked_parent_meta.is_dir()
                    || !metadata_same_file(canonical_parent_meta, &rechecked_parent_meta)
                {
                    return Err(Error::InvalidPath(
                        "parent identity changed during delete; refusing to continue".to_string(),
                    ));
                }
                Ok(None)
            }
        }
        Err(Error::IoPath { source, .. })
            if request.ignore_missing && source.kind() == std::io::ErrorKind::NotFound =>
        {
            Ok(Some(missing_response(requested_path)))
        }
        Err(err) => Err(err),
    }
}

pub fn delete(ctx: &Context, request: DeleteRequest) -> Result<DeleteResponse> {
    ctx.ensure_write_operation_allowed(&request.root_id, ctx.policy.permissions.delete, "delete")?;
    ensure_delete_identity_verification_supported()?;

    let resolved =
        super::resolve::resolve_path_in_root_lexically(ctx, &request.root_id, &request.path)?;
    let canonical_root = resolved.canonical_root;
    let requested_path = resolved.requested_path;

    let file_name = super::path_validation::ensure_non_root_leaf(
        &requested_path,
        &request.path,
        super::path_validation::LeafOp::Delete,
    )?;

    let requested_parent = requested_path.parent().unwrap_or_else(|| Path::new(""));
    let requested_relative = requested_parent.join(file_name);
    // First check blocks secret paths in the original user-supplied location.
    if ctx.redactor.is_path_denied(&requested_relative) {
        return Err(Error::SecretPathDenied(requested_relative));
    }

    let canonical_parent =
        match ctx.ensure_dir_under_root(&request.root_id, requested_parent, false) {
            Ok(path) => path,
            Err(Error::IoPath { source, .. })
                if request.ignore_missing && source.kind() == std::io::ErrorKind::NotFound =>
            {
                // If the parent directory doesn't exist, the target doesn't exist either.
                return Ok(missing_response(&requested_path));
            }
            Err(err) => return Err(err),
        };
    let canonical_parent_meta = match fs::symlink_metadata(&canonical_parent) {
        Ok(meta) => meta,
        Err(err) if request.ignore_missing && err.kind() == std::io::ErrorKind::NotFound => {
            return Ok(missing_response(&requested_path));
        }
        Err(err) => return Err(Error::io_path("symlink_metadata", requested_parent, err)),
    };
    if !canonical_parent_meta.is_dir() {
        return Err(Error::InvalidPath(format!(
            "parent path {} is not a directory",
            requested_parent.display()
        )));
    }

    let relative_parent =
        crate::path_utils::strip_prefix_case_insensitive(&canonical_parent, &canonical_root)
            .ok_or_else(|| Error::OutsideRoot {
                root_id: request.root_id.clone(),
                path: requested_path.clone(),
            })?;
    let relative = relative_parent.join(file_name);

    // Second check blocks secret paths after canonicalization resolves symlinks.
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

    if let Some(response) = revalidate_parent_before_delete(
        ctx,
        &request,
        requested_parent,
        &canonical_parent,
        &canonical_parent_meta,
        &requested_path,
    )? {
        return Ok(response);
    }

    let meta = match fs::symlink_metadata(&target) {
        Ok(meta) => meta,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound && request.ignore_missing => {
            return Ok(missing_response(&requested_path));
        }
        Err(err) => return Err(Error::io_path("symlink_metadata", &relative, err)),
    };

    let file_type = meta.file_type();
    let kind = if file_type.is_file() {
        DeleteKind::File
    } else if file_type.is_dir() {
        DeleteKind::Dir
    } else if file_type.is_symlink() {
        DeleteKind::Symlink
    } else {
        DeleteKind::Other
    };

    let ensure_parent_stable_or_missing = || {
        revalidate_parent_before_delete(
            ctx,
            &request,
            requested_parent,
            &canonical_parent,
            &canonical_parent_meta,
            &requested_path,
        )
    };
    let ensure_target_stable_or_missing = || -> Result<Option<DeleteResponse>> {
        let current_meta = match fs::symlink_metadata(&target) {
            Ok(meta) => meta,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound && request.ignore_missing => {
                return Ok(Some(missing_response(&requested_path)));
            }
            Err(err) => return Err(Error::io_path("symlink_metadata", &relative, err)),
        };
        if !metadata_same_file(&meta, &current_meta) {
            return Err(Error::InvalidPath(
                "target identity changed during delete; refusing to continue".to_string(),
            ));
        }
        Ok(None)
    };

    if file_type.is_dir() {
        if !request.recursive {
            return Err(Error::InvalidPath(
                "path is a directory; set recursive=true to delete directories".to_string(),
            ));
        }

        if let Some(response) = ensure_parent_stable_or_missing()? {
            return Ok(response);
        }
        if let Some(response) = ensure_target_stable_or_missing()? {
            return Ok(response);
        }

        if let Err(err) = fs::remove_dir_all(&target) {
            if err.kind() == std::io::ErrorKind::NotFound && request.ignore_missing {
                return Ok(missing_response(&requested_path));
            }
            return Err(Error::io_path("remove_dir_all", &relative, err));
        }
    } else {
        if let Some(response) = ensure_parent_stable_or_missing()? {
            return Ok(response);
        }
        if let Some(response) = ensure_target_stable_or_missing()? {
            return Ok(response);
        }

        let delete_non_dir_result = if file_type.is_symlink() {
            unlink_symlink(&target)
        } else {
            fs::remove_file(&target)
        };
        if let Err(err) = delete_non_dir_result {
            if err.kind() == std::io::ErrorKind::NotFound && request.ignore_missing {
                return Ok(missing_response(&requested_path));
            }
            let op = if file_type.is_symlink() {
                "unlink_symlink"
            } else {
                "remove_file"
            };
            return Err(Error::io_path(op, &relative, err));
        }
    }

    Ok(DeleteResponse {
        path: relative,
        requested_path: Some(requested_path),
        deleted: true,
        kind,
    })
}
