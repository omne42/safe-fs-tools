use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

use super::Context;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CopyFileRequest {
    pub root_id: String,
    pub from: PathBuf,
    pub to: PathBuf,
    #[serde(default)]
    pub overwrite: bool,
    #[serde(default)]
    pub create_parents: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CopyFileResponse {
    pub from: PathBuf,
    pub to: PathBuf,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requested_from: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requested_to: Option<PathBuf>,
    pub copied: bool,
    pub bytes: u64,
}

pub fn copy_file(ctx: &Context, request: CopyFileRequest) -> Result<CopyFileResponse> {
    if !ctx.policy.permissions.copy_file {
        return Err(Error::NotPermitted(
            "copy_file is disabled by policy".to_string(),
        ));
    }
    ctx.ensure_can_write(&request.root_id, "copy_file")?;

    let from_resolved =
        super::resolve::resolve_path_in_root_lexically(ctx, &request.root_id, &request.from)?;
    let to_resolved =
        super::resolve::resolve_path_in_root_lexically(ctx, &request.root_id, &request.to)?;

    let canonical_root = from_resolved.canonical_root;

    if to_resolved.canonical_root != canonical_root {
        return Err(Error::InvalidPath(
            "from/to roots resolved inconsistently".to_string(),
        ));
    }

    let requested_from = from_resolved.requested_path;
    let requested_to = to_resolved.requested_path;

    let requested_from_is_root = requested_from
        .components()
        .all(|component| matches!(component, std::path::Component::CurDir));
    let requested_to_is_root = requested_to
        .components()
        .all(|component| matches!(component, std::path::Component::CurDir));
    if requested_from_is_root || requested_to_is_root {
        return Err(Error::InvalidPath(
            "refusing to copy the root directory".to_string(),
        ));
    }

    let from_name = requested_from.file_name().ok_or_else(|| {
        Error::InvalidPath(format!(
            "invalid from path {:?}: missing file name",
            request.from
        ))
    })?;
    let to_name = requested_to.file_name().ok_or_else(|| {
        Error::InvalidPath(format!(
            "invalid to path {:?}: missing file name",
            request.to
        ))
    })?;

    let from_parent_rel = requested_from.parent().unwrap_or_else(|| Path::new(""));
    let to_parent_rel = requested_to.parent().unwrap_or_else(|| Path::new(""));

    let from_parent = ctx.ensure_dir_under_root(&request.root_id, from_parent_rel, false)?;
    let to_parent =
        ctx.ensure_dir_under_root(&request.root_id, to_parent_rel, request.create_parents)?;

    let from_relative_parent =
        crate::path_utils::strip_prefix_case_insensitive(&from_parent, &canonical_root)
            .unwrap_or_else(|| from_parent.clone());
    let to_relative_parent =
        crate::path_utils::strip_prefix_case_insensitive(&to_parent, &canonical_root)
            .unwrap_or_else(|| to_parent.clone());

    let from_relative = from_relative_parent.join(from_name);
    let to_relative = to_relative_parent.join(to_name);

    if ctx.redactor.is_path_denied(&from_relative) {
        return Err(Error::SecretPathDenied(from_relative));
    }
    if ctx.redactor.is_path_denied(&to_relative) {
        return Err(Error::SecretPathDenied(to_relative));
    }

    let source = from_parent.join(from_name);
    let destination = to_parent.join(to_name);

    if !crate::path_utils::starts_with_case_insensitive(&source, &canonical_root) {
        return Err(Error::OutsideRoot {
            root_id: request.root_id.clone(),
            path: requested_from,
        });
    }
    if !crate::path_utils::starts_with_case_insensitive(&destination, &canonical_root) {
        return Err(Error::OutsideRoot {
            root_id: request.root_id.clone(),
            path: requested_to,
        });
    }

    if source == destination {
        return Ok(CopyFileResponse {
            from: from_relative,
            to: to_relative,
            requested_from: Some(requested_from),
            requested_to: Some(requested_to),
            copied: false,
            bytes: 0,
        });
    }

    let meta = fs::symlink_metadata(&source)
        .map_err(|err| Error::io_path("metadata", &from_relative, err))?;
    if meta.file_type().is_symlink() {
        return Err(Error::InvalidPath("refusing to copy symlinks".to_string()));
    }
    if meta.is_dir() {
        return Err(Error::InvalidPath("path is a directory".to_string()));
    }
    if !meta.is_file() {
        return Err(Error::InvalidPath("path is not a file".to_string()));
    }
    if meta.len() > ctx.policy.limits.max_write_bytes {
        return Err(Error::FileTooLarge {
            path: from_relative.clone(),
            size_bytes: meta.len(),
            max_bytes: ctx.policy.limits.max_write_bytes,
        });
    }

    match fs::symlink_metadata(&destination) {
        Ok(meta) => {
            if meta.is_dir() {
                return Err(Error::InvalidPath(
                    "destination exists and is a directory".to_string(),
                ));
            }
            if !request.overwrite {
                return Err(Error::InvalidPath("destination exists".to_string()));
            }
            fs::remove_file(&destination)
                .map_err(|err| Error::io_path("remove_file", &to_relative, err))?;
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(err) => return Err(Error::io_path("metadata", &to_relative, err)),
    }

    let bytes =
        fs::copy(&source, &destination).map_err(|err| Error::io_path("copy", &to_relative, err))?;

    Ok(CopyFileResponse {
        from: from_relative,
        to: to_relative,
        requested_from: Some(requested_from),
        requested_to: Some(requested_to),
        copied: true,
        bytes,
    })
}
