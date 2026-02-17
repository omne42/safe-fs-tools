use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

use super::Context;

fn revalidate_parent_before_move(
    ctx: &Context,
    root_id: &str,
    requested_parent: &Path,
    expected_parent: &Path,
    expected_parent_meta: &fs::Metadata,
    requested_path: &Path,
    side: &str,
) -> Result<PathBuf> {
    let rechecked_parent = ctx.ensure_dir_under_root(root_id, requested_parent, false)?;
    if !crate::path_utils::paths_equal_case_insensitive(&rechecked_parent, expected_parent) {
        return Err(Error::InvalidPath(format!(
            "{side} path {} changed during move; refusing to continue",
            requested_path.display()
        )));
    }

    let rechecked_parent_meta = fs::symlink_metadata(&rechecked_parent)
        .map_err(|err| Error::io_path("symlink_metadata", requested_parent, err))?;
    if !rechecked_parent_meta.is_dir() {
        return Err(Error::InvalidPath(format!(
            "{side} parent identity changed during move; refusing to continue"
        )));
    }
    match metadata_same_file(expected_parent_meta, &rechecked_parent_meta) {
        Some(true) => {}
        Some(false) => {
            return Err(Error::InvalidPath(format!(
                "{side} parent identity changed during move; refusing to continue"
            )));
        }
        None => {
            // Best-effort fallback for filesystems that do not expose stable file IDs.
            // Path re-resolution above still guarantees we are operating on the same
            // canonical parent path inside the selected root.
        }
    }

    Ok(rechecked_parent)
}

#[cfg(unix)]
fn metadata_same_file(a: &fs::Metadata, b: &fs::Metadata) -> Option<bool> {
    use std::os::unix::fs::MetadataExt;
    Some(a.dev() == b.dev() && a.ino() == b.ino())
}

#[cfg(windows)]
fn metadata_same_file(a: &fs::Metadata, b: &fs::Metadata) -> Option<bool> {
    use std::os::windows::fs::MetadataExt;
    match (
        a.volume_serial_number(),
        a.file_index(),
        b.volume_serial_number(),
        b.file_index(),
    ) {
        (Some(a_serial), Some(a_index), Some(b_serial), Some(b_index)) => {
            Some(a_serial == b_serial && a_index == b_index)
        }
        _ => None,
    }
}

#[cfg(not(any(unix, windows)))]
fn metadata_same_file(_a: &fs::Metadata, _b: &fs::Metadata) -> Option<bool> {
    None
}

#[cfg(any(unix, windows))]
fn ensure_move_identity_verification_supported() -> Result<()> {
    Ok(())
}

#[cfg(not(any(unix, windows)))]
fn ensure_move_identity_verification_supported() -> Result<()> {
    Err(Error::InvalidPath(
        "move is unsupported on this platform: cannot verify file identity".to_string(),
    ))
}

fn capture_parent_identity(
    parent: &Path,
    parent_relative: &Path,
    side: &str,
) -> Result<fs::Metadata> {
    let parent_meta = fs::symlink_metadata(parent)
        .map_err(|err| Error::io_path("symlink_metadata", parent_relative, err))?;
    if !parent_meta.is_dir() {
        return Err(Error::InvalidPath(format!(
            "{side} parent path {} is not a directory",
            parent_relative.display()
        )));
    }
    Ok(parent_meta)
}

fn revalidate_source_before_move(
    source: &Path,
    source_relative: &Path,
    expected_source_meta: &fs::Metadata,
) -> Result<()> {
    let current_source_meta = fs::symlink_metadata(source)
        .map_err(|err| Error::io_path("symlink_metadata", source_relative, err))?;
    match metadata_same_file(expected_source_meta, &current_source_meta) {
        Some(true) => {}
        Some(false) => {
            return Err(Error::InvalidPath(
                "source identity changed during move; refusing to continue".to_string(),
            ));
        }
        None => {
            // Best-effort fallback for filesystems that do not expose stable file IDs.
            // The source path has already been lexically/canonically revalidated.
        }
    }
    Ok(())
}

fn validate_destination_before_move(
    source_meta: &fs::Metadata,
    destination: &Path,
    destination_relative: &Path,
    overwrite: bool,
) -> Result<bool> {
    let destination_meta = match fs::symlink_metadata(destination) {
        Ok(meta) => Some(meta),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => None,
        Err(err) => {
            return Err(Error::io_path(
                "symlink_metadata",
                destination_relative,
                err,
            ));
        }
    };

    if let Some(dest_meta) = &destination_meta {
        if matches!(metadata_same_file(source_meta, dest_meta), Some(true)) {
            return Ok(true);
        }
        if dest_meta.is_dir() {
            return Err(Error::InvalidPath(
                "destination exists and is a directory".to_string(),
            ));
        }
        if !overwrite {
            return Err(Error::InvalidPath("destination exists".to_string()));
        }
        if source_meta.is_dir() {
            return Err(Error::InvalidPath(
                "refusing to overwrite an existing destination with a directory".to_string(),
            ));
        }
    }

    Ok(false)
}

fn validate_directory_move_target(source: &Path, destination: &Path) -> Result<()> {
    let normalized_source = crate::path_utils::normalized_for_boundary(source);
    let normalized_destination = crate::path_utils::normalized_for_boundary(destination);
    if normalized_destination.as_ref() != normalized_source.as_ref()
        && crate::path_utils::starts_with_case_insensitive_normalized(
            normalized_destination.as_ref(),
            normalized_source.as_ref(),
        )
    {
        return Err(Error::InvalidPath(
            "refusing to move a directory into its own subdirectory".to_string(),
        ));
    }
    Ok(())
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
    ctx.ensure_write_operation_allowed(&request.root_id, ctx.policy.permissions.move_path, "move")?;
    ensure_move_identity_verification_supported()?;

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
    let from_parent_meta = capture_parent_identity(&from_parent, from_parent_rel, "source")?;
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
        crate::path_utils::strip_prefix_case_insensitive_normalized(&from_parent, canonical_root)
            .ok_or_else(|| Error::OutsideRoot {
            root_id: request.root_id.clone(),
            path: requested_from.clone(),
        })?;

    let mut from_relative = from_relative_parent.join(from_name);
    let mut to_relative = requested_to.clone();

    if ctx.redactor.is_path_denied(&from_relative) {
        return Err(Error::SecretPathDenied(from_relative));
    }
    if ctx.redactor.is_path_denied(&to_relative) {
        return Err(Error::SecretPathDenied(to_relative));
    }

    let source = from_parent.join(from_name);

    let source_meta = fs::symlink_metadata(&source)
        .map_err(|err| Error::io_path("symlink_metadata", &from_relative, err))?;
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
    let to_parent_meta = capture_parent_identity(&to_parent, to_parent_rel, "destination")?;
    let to_relative_parent =
        crate::path_utils::strip_prefix_case_insensitive_normalized(&to_parent, canonical_root)
            .ok_or_else(|| Error::OutsideRoot {
                root_id: request.root_id.clone(),
                path: requested_to.clone(),
            })?;
    to_relative = to_relative_parent.join(to_name);
    if ctx.redactor.is_path_denied(&to_relative) {
        return Err(Error::SecretPathDenied(to_relative));
    }

    let destination = to_parent.join(to_name);

    if !crate::path_utils::starts_with_case_insensitive_normalized(&source, canonical_root) {
        return Err(Error::OutsideRoot {
            root_id: request.root_id.clone(),
            path: requested_from,
        });
    }
    if !crate::path_utils::starts_with_case_insensitive_normalized(&destination, canonical_root) {
        return Err(Error::OutsideRoot {
            root_id: request.root_id.clone(),
            path: requested_to,
        });
    }

    if crate::path_utils::paths_equal_case_insensitive_normalized(&source, &destination) {
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
        validate_directory_move_target(&source, &destination)?;
    }

    if validate_destination_before_move(
        &source_meta,
        &destination,
        &to_relative,
        request.overwrite,
    )? {
        return Ok(MovePathResponse {
            from: from_relative,
            to: to_relative,
            requested_from: Some(requested_from),
            requested_to: Some(requested_to),
            moved: false,
            kind: kind.to_string(),
        });
    }

    let rechecked_from_parent = revalidate_parent_before_move(
        ctx,
        &request.root_id,
        from_parent_rel,
        &from_parent,
        &from_parent_meta,
        &requested_from,
        "source",
    )?;
    let rechecked_to_parent = revalidate_parent_before_move(
        ctx,
        &request.root_id,
        to_parent_rel,
        &to_parent,
        &to_parent_meta,
        &requested_to,
        "destination",
    )?;
    let rechecked_from_relative_parent =
        crate::path_utils::strip_prefix_case_insensitive_normalized(
            &rechecked_from_parent,
            canonical_root,
        )
        .ok_or_else(|| Error::OutsideRoot {
            root_id: request.root_id.clone(),
            path: requested_from.clone(),
        })?;
    from_relative = rechecked_from_relative_parent.join(from_name);
    let rechecked_to_relative_parent = crate::path_utils::strip_prefix_case_insensitive_normalized(
        &rechecked_to_parent,
        canonical_root,
    )
    .ok_or_else(|| Error::OutsideRoot {
        root_id: request.root_id.clone(),
        path: requested_to.clone(),
    })?;
    to_relative = rechecked_to_relative_parent.join(to_name);
    if ctx.redactor.is_path_denied(&from_relative) {
        return Err(Error::SecretPathDenied(from_relative));
    }
    if ctx.redactor.is_path_denied(&to_relative) {
        return Err(Error::SecretPathDenied(to_relative));
    }
    revalidate_source_before_move(&source, &from_relative, &source_meta)?;
    if validate_destination_before_move(
        &source_meta,
        &destination,
        &to_relative,
        request.overwrite,
    )? {
        return Ok(MovePathResponse {
            from: from_relative,
            to: to_relative,
            requested_from: Some(requested_from),
            requested_to: Some(requested_to),
            moved: false,
            kind: kind.to_string(),
        });
    }

    let replace_existing = request.overwrite;
    super::io::rename_replace(&source, &destination, replace_existing).map_err(
        |err| match err {
            super::io::RenameReplaceError::Io(err) => {
                if !replace_existing && super::io::is_destination_exists_rename_error(&err) {
                    return Error::InvalidPath("destination exists".to_string());
                }
                if !replace_existing && err.kind() == std::io::ErrorKind::Unsupported {
                    return Error::InvalidPath(
                        "overwrite=false move is unsupported on this platform".to_string(),
                    );
                }
                let source_missing = matches!(
                    fs::symlink_metadata(&source),
                    Err(source_err) if source_err.kind() == std::io::ErrorKind::NotFound
                );
                if source_missing {
                    return Error::io_path("rename", &from_relative, err);
                }
                let rename_context = PathBuf::from(format!(
                    "{} -> {}",
                    from_relative.display(),
                    to_relative.display()
                ));
                Error::io_path("rename", rename_context, err)
            }
            super::io::RenameReplaceError::CommittedButUnsynced(err) => {
                let rename_context = PathBuf::from(format!(
                    "{} -> {}",
                    from_relative.display(),
                    to_relative.display()
                ));
                Error::committed_but_unsynced("rename", rename_context, err)
            }
        },
    )?;

    Ok(MovePathResponse {
        from: from_relative,
        to: to_relative,
        requested_from: Some(requested_from),
        requested_to: Some(requested_to),
        moved: true,
        kind: kind.to_string(),
    })
}
