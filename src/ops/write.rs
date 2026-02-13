use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

use super::Context;

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

    let requested_is_root = requested_path
        .components()
        .all(|component| matches!(component, std::path::Component::CurDir));
    if requested_is_root {
        return Err(Error::InvalidPath(
            "refusing to write to the root directory".to_string(),
        ));
    }

    let file_name = requested_path.file_name().ok_or_else(|| {
        Error::InvalidPath(format!(
            "invalid write path {:?}: missing final file name",
            request.path
        ))
    })?;
    if file_name == std::ffi::OsStr::new(".") || file_name == std::ffi::OsStr::new("..") {
        return Err(Error::InvalidPath(format!(
            "invalid write path {:?}",
            request.path
        )));
    }

    let requested_parent = requested_path.parent().unwrap_or_else(|| Path::new(""));
    let canonical_parent =
        ctx.ensure_dir_under_root(&request.root_id, requested_parent, request.create_parents)?;

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

    let existing = match fs::symlink_metadata(&target) {
        Ok(meta) => Some(meta),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => None,
        Err(err) => return Err(Error::io_path("metadata", &relative, err)),
    };

    if existing.is_some() && !request.overwrite {
        return Err(Error::InvalidPath("file exists".to_string()));
    }

    if existing.is_some() {
        if ctx.redactor.is_path_denied(&relative) {
            return Err(Error::SecretPathDenied(relative.clone()));
        }
        super::io::write_bytes_atomic(&target, &relative, request.content.as_bytes())?;
        return Ok(WriteFileResponse {
            path: relative,
            requested_path: Some(requested_path),
            bytes_written,
            created: false,
        });
    }

    let parent = target.parent().ok_or_else(|| {
        Error::InvalidPath(format!(
            "invalid write path {}: missing parent directory",
            relative.display()
        ))
    })?;

    let mut tmp_file = tempfile::Builder::new()
        .prefix(".safe-fs-tools.")
        .suffix(".tmp")
        .tempfile_in(parent)
        .map_err(|err| Error::io_path("create_temp", &relative, err))?;
    tmp_file
        .as_file_mut()
        .write_all(request.content.as_bytes())
        .map_err(|err| Error::io_path("write", &relative, err))?;
    tmp_file
        .as_file_mut()
        .sync_all()
        .map_err(|err| Error::io_path("sync", &relative, err))?;
    let tmp_path = tmp_file.into_temp_path();

    super::io::rename_replace(tmp_path.as_ref(), &target, false).map_err(|err| {
        if err.kind() == std::io::ErrorKind::AlreadyExists {
            return Error::InvalidPath("file exists".to_string());
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
