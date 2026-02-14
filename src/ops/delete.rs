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

impl DeleteKind {
    const fn as_str(self) -> &'static str {
        match self {
            Self::File => "file",
            Self::Dir => "dir",
            Self::Symlink => "symlink",
            Self::Other => "other",
            Self::Missing => "missing",
        }
    }
}

impl PartialEq<&str> for DeleteKind {
    fn eq(&self, other: &&str) -> bool {
        self.as_str() == *other
    }
}

impl PartialEq<DeleteKind> for &str {
    fn eq(&self, other: &DeleteKind) -> bool {
        *self == other.as_str()
    }
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
    DeleteResponse {
        path: requested_path.to_path_buf(),
        requested_path: Some(requested_path.to_path_buf()),
        deleted: false,
        kind: DeleteKind::Missing,
    }
}

fn revalidate_parent_before_delete(
    ctx: &Context,
    request: &DeleteRequest,
    requested_parent: &Path,
    canonical_parent: &Path,
    requested_path: &Path,
) -> Result<Option<DeleteResponse>> {
    match ctx.ensure_dir_under_root(&request.root_id, requested_parent, false) {
        Ok(rechecked_parent) => {
            if rechecked_parent == canonical_parent {
                Ok(None)
            } else {
                Err(Error::InvalidPath(format!(
                    "path {} changed during delete; refusing to continue",
                    requested_path.display()
                )))
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
    if !ctx.policy.permissions.delete {
        return Err(Error::NotPermitted(
            "delete is disabled by policy".to_string(),
        ));
    }
    ctx.ensure_can_write(&request.root_id, "delete")?;

    let resolved =
        super::resolve::resolve_path_in_root_lexically(ctx, &request.root_id, &request.path)?;
    let canonical_root = resolved.canonical_root;
    let requested_path = resolved.requested_path;

    let file_name = super::path_validation::ensure_non_root_leaf(
        &requested_path,
        &request.path,
        "delete",
        "path segment",
        "refusing to delete the root directory",
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
        &requested_path,
    )? {
        return Ok(response);
    }

    let meta = match fs::symlink_metadata(&target) {
        Ok(meta) => meta,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound && request.ignore_missing => {
            return Ok(missing_response(&requested_path));
        }
        Err(err) => return Err(Error::io_path("metadata", &relative, err)),
    };

    let kind = if meta.file_type().is_file() {
        DeleteKind::File
    } else if meta.file_type().is_dir() {
        DeleteKind::Dir
    } else if meta.file_type().is_symlink() {
        DeleteKind::Symlink
    } else {
        DeleteKind::Other
    };

    if meta.is_dir() {
        if !request.recursive {
            return Err(Error::InvalidPath(
                "path is a directory; set recursive=true to delete directories".to_string(),
            ));
        }

        if let Some(response) = revalidate_parent_before_delete(
            ctx,
            &request,
            requested_parent,
            &canonical_parent,
            &requested_path,
        )? {
            return Ok(response);
        }

        if let Err(err) = fs::remove_dir_all(&target) {
            if err.kind() == std::io::ErrorKind::NotFound && request.ignore_missing {
                return Ok(missing_response(&requested_path));
            }
            return Err(Error::io_path("remove_dir_all", &relative, err));
        }
    } else {
        if let Some(response) = revalidate_parent_before_delete(
            ctx,
            &request,
            requested_parent,
            &canonical_parent,
            &requested_path,
        )? {
            return Ok(response);
        }

        if let Err(err) = fs::remove_file(&target) {
            if err.kind() == std::io::ErrorKind::NotFound && request.ignore_missing {
                return Ok(missing_response(&requested_path));
            }
            return Err(Error::io_path("remove_file", &relative, err));
        }
    }

    Ok(DeleteResponse {
        path: relative,
        requested_path: Some(requested_path),
        deleted: true,
        kind,
    })
}
