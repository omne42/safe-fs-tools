use std::fs;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

use super::Context;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeleteRequest {
    pub root_id: String,
    pub path: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeleteResponse {
    pub path: PathBuf,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requested_path: Option<PathBuf>,
}

pub fn delete_file(ctx: &Context, request: DeleteRequest) -> Result<DeleteResponse> {
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
    let resolved = resolved.resolved;

    let file_name = resolved
        .file_name()
        .ok_or_else(|| Error::InvalidPath("delete requires a file path (got empty)".to_string()))?;
    if file_name == std::ffi::OsStr::new(".") || file_name == std::ffi::OsStr::new("..") {
        return Err(Error::InvalidPath(format!(
            "invalid delete path {:?}",
            request.path
        )));
    }

    let parent = resolved.parent().ok_or_else(|| {
        Error::InvalidPath(format!(
            "invalid delete path {:?}: missing parent directory",
            request.path
        ))
    })?;
    let canonical_parent = match parent.canonicalize() {
        Ok(canonical) => canonical,
        Err(err) => return Err(Error::io_path("canonicalize", requested_path, err)),
    };
    if !crate::path_utils::starts_with_case_insensitive(&canonical_parent, &canonical_root) {
        return Err(Error::OutsideRoot {
            root_id: request.root_id.clone(),
            path: requested_path,
        });
    }

    let relative_parent =
        crate::path_utils::strip_prefix_case_insensitive(&canonical_parent, &canonical_root)
            .unwrap_or(canonical_parent);
    let relative = relative_parent.join(file_name);
    if ctx.redactor.is_path_denied(&relative) {
        return Err(Error::SecretPathDenied(relative));
    }

    let meta = fs::symlink_metadata(&resolved)
        .map_err(|err| Error::io_path("metadata", &relative, err))?;
    if meta.is_dir() {
        return Err(Error::InvalidPath(
            "delete does not support directories".to_string(),
        ));
    }

    fs::remove_file(&resolved).map_err(|err| Error::io_path("remove_file", &relative, err))?;
    Ok(DeleteResponse {
        path: relative,
        requested_path: Some(requested_path),
    })
}
