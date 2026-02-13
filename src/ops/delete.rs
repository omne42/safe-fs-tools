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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeleteResponse {
    pub path: PathBuf,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requested_path: Option<PathBuf>,
    pub deleted: bool,
    #[serde(rename = "type")]
    pub kind: String,
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

    let requested_is_root = requested_path
        .components()
        .all(|component| matches!(component, std::path::Component::CurDir));
    if requested_is_root {
        return Err(Error::InvalidPath(
            "refusing to delete the root directory".to_string(),
        ));
    }

    let file_name = requested_path.file_name().ok_or_else(|| {
        Error::InvalidPath(format!(
            "invalid delete path {:?}: missing final path segment",
            request.path
        ))
    })?;
    if file_name == std::ffi::OsStr::new(".") || file_name == std::ffi::OsStr::new("..") {
        return Err(Error::InvalidPath(format!(
            "invalid delete path {:?}",
            request.path
        )));
    }

    let requested_parent = requested_path.parent().unwrap_or_else(|| Path::new(""));
    let canonical_parent =
        match ctx.ensure_dir_under_root(&request.root_id, requested_parent, false) {
            Ok(path) => path,
            Err(Error::IoPath { source, .. })
                if request.ignore_missing && source.kind() == std::io::ErrorKind::NotFound =>
            {
                // If the parent directory doesn't exist, the target doesn't exist either.
                return Ok(DeleteResponse {
                    path: requested_path.clone(),
                    requested_path: Some(requested_path),
                    deleted: false,
                    kind: "missing".to_string(),
                });
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

    let meta = match fs::symlink_metadata(&target) {
        Ok(meta) => meta,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound && request.ignore_missing => {
            return Ok(DeleteResponse {
                path: requested_path.clone(),
                requested_path: Some(requested_path),
                deleted: false,
                kind: "missing".to_string(),
            });
        }
        Err(err) => return Err(Error::io_path("metadata", &relative, err)),
    };

    let kind = if meta.file_type().is_file() {
        "file"
    } else if meta.file_type().is_dir() {
        "dir"
    } else if meta.file_type().is_symlink() {
        "symlink"
    } else {
        "other"
    };

    if meta.is_dir() {
        if !request.recursive {
            return Err(Error::InvalidPath(
                "path is a directory; set recursive=true to delete directories".to_string(),
            ));
        }

        if let Err(err) = fs::remove_dir_all(&target) {
            if err.kind() == std::io::ErrorKind::NotFound && request.ignore_missing {
                return Ok(DeleteResponse {
                    path: requested_path.clone(),
                    requested_path: Some(requested_path),
                    deleted: false,
                    kind: "missing".to_string(),
                });
            }
            return Err(Error::io_path("remove_dir_all", &relative, err));
        }
    } else if let Err(err) = fs::remove_file(&target) {
        if err.kind() == std::io::ErrorKind::NotFound && request.ignore_missing {
            return Ok(DeleteResponse {
                path: requested_path.clone(),
                requested_path: Some(requested_path),
                deleted: false,
                kind: "missing".to_string(),
            });
        }
        return Err(Error::io_path("remove_file", &relative, err));
    }

    Ok(DeleteResponse {
        path: relative,
        requested_path: Some(requested_path),
        deleted: true,
        kind: kind.to_string(),
    })
}
