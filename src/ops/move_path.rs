use std::fs;
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

#[cfg(not(any(unix, windows)))]
fn metadata_same_file(_a: &fs::Metadata, _b: &fs::Metadata) -> bool {
    false
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MovePathRequest {
    pub root_id: String,
    pub from: PathBuf,
    pub to: PathBuf,
    #[serde(default)]
    pub overwrite: bool,
    #[serde(default)]
    pub create_parents: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MovePathResponse {
    pub from: PathBuf,
    pub to: PathBuf,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requested_from: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requested_to: Option<PathBuf>,
    pub moved: bool,
    #[serde(rename = "type")]
    pub kind: String,
}

pub fn move_path(ctx: &Context, request: MovePathRequest) -> Result<MovePathResponse> {
    if !ctx.policy.permissions.move_path {
        return Err(Error::NotPermitted(
            "move is disabled by policy".to_string(),
        ));
    }
    ctx.ensure_can_write(&request.root_id, "move")?;

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
            "refusing to move the root directory".to_string(),
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
    let mut to_parent = match ctx.ensure_dir_under_root(&request.root_id, to_parent_rel, false) {
        Ok(path) => Some(path),
        Err(Error::IoPath { source, .. })
            if request.create_parents && source.kind() == std::io::ErrorKind::NotFound =>
        {
            None
        }
        Err(err) => return Err(err),
    };

    let from_relative_parent =
        crate::path_utils::strip_prefix_case_insensitive(&from_parent, &canonical_root)
            .ok_or_else(|| Error::OutsideRoot {
                root_id: request.root_id.clone(),
                path: requested_from.clone(),
            })?;

    let from_relative = from_relative_parent.join(from_name);
    let mut to_relative = requested_to.clone();

    if ctx.redactor.is_path_denied(&from_relative) {
        return Err(Error::SecretPathDenied(from_relative));
    }
    if ctx.redactor.is_path_denied(&to_relative) {
        return Err(Error::SecretPathDenied(to_relative));
    }

    let source = from_parent.join(from_name);

    let source_meta = fs::symlink_metadata(&source)
        .map_err(|err| Error::io_path("metadata", &from_relative, err))?;
    let kind = if source_meta.file_type().is_file() {
        "file"
    } else if source_meta.file_type().is_dir() {
        "dir"
    } else if source_meta.file_type().is_symlink() {
        "symlink"
    } else {
        "other"
    };

    if to_parent.is_none() {
        to_parent = Some(ctx.ensure_dir_under_root(&request.root_id, to_parent_rel, true)?);
    }
    let to_parent = to_parent.ok_or_else(|| {
        Error::InvalidPath("failed to prepare destination parent directory".to_string())
    })?;
    let to_relative_parent =
        crate::path_utils::strip_prefix_case_insensitive(&to_parent, &canonical_root).ok_or_else(
            || Error::OutsideRoot {
                root_id: request.root_id.clone(),
                path: requested_to.clone(),
            },
        )?;
    to_relative = to_relative_parent.join(to_name);
    if ctx.redactor.is_path_denied(&to_relative) {
        return Err(Error::SecretPathDenied(to_relative));
    }

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
        return Ok(MovePathResponse {
            from: from_relative,
            to: to_relative,
            requested_from: Some(requested_from),
            requested_to: Some(requested_to),
            moved: false,
            kind: kind.to_string(),
        });
    }

    if source_meta.is_dir() {
        let normalized_source = crate::path_utils::normalize_path_lexical(&source);
        let normalized_destination = crate::path_utils::normalize_path_lexical(&destination);
        if normalized_destination != normalized_source
            && crate::path_utils::starts_with_case_insensitive(
                &normalized_destination,
                &normalized_source,
            )
        {
            return Err(Error::InvalidPath(
                "refusing to move a directory into its own subdirectory".to_string(),
            ));
        }
    }

    let destination_meta = match fs::symlink_metadata(&destination) {
        Ok(meta) => Some(meta),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => None,
        Err(err) => return Err(Error::io_path("metadata", &to_relative, err)),
    };

    if let Some(dest_meta) = &destination_meta {
        let same_destination_entity = metadata_same_file(&source_meta, dest_meta);
        if same_destination_entity {
            return Ok(MovePathResponse {
                from: from_relative,
                to: to_relative,
                requested_from: Some(requested_from),
                requested_to: Some(requested_to),
                moved: false,
                kind: kind.to_string(),
            });
        }
        if dest_meta.is_dir() {
            return Err(Error::InvalidPath(
                "destination exists and is a directory".to_string(),
            ));
        }
        if !request.overwrite {
            return Err(Error::InvalidPath("destination exists".to_string()));
        }
        if source_meta.is_dir() {
            return Err(Error::InvalidPath(
                "refusing to overwrite an existing destination with a directory".to_string(),
            ));
        }
    }

    let replace_existing = request.overwrite;
    super::io::rename_replace(&source, &destination, replace_existing).map_err(|err| {
        if !replace_existing && err.kind() == std::io::ErrorKind::AlreadyExists {
            return Error::InvalidPath("destination exists".to_string());
        }
        Error::io_path("rename", &to_relative, err)
    })?;

    Ok(MovePathResponse {
        from: from_relative,
        to: to_relative,
        requested_from: Some(requested_from),
        requested_to: Some(requested_to),
        moved: true,
        kind: kind.to_string(),
    })
}
