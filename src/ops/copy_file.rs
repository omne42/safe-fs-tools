use std::fs;
use std::io::Read;
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

struct ResolvedCopyPaths {
    canonical_root: PathBuf,
    requested_from: PathBuf,
    requested_to: PathBuf,
    from_relative: PathBuf,
    source: PathBuf,
    to_parent_rel: PathBuf,
    to_name: PathBuf,
    to_parent: Option<PathBuf>,
}

struct PreparedDestination {
    parent: PathBuf,
    to_effective_relative: PathBuf,
    path: PathBuf,
}

pub fn copy_file(ctx: &Context, request: CopyFileRequest) -> Result<CopyFileResponse> {
    ctx.ensure_write_operation_allowed(
        &request.root_id,
        ctx.policy.permissions.copy_file,
        "copy_file",
    )?;
    let mut paths = resolve_and_validate_paths(ctx, &request)?;

    let (mut input, source_meta) =
        super::io::open_regular_file_for_read(&paths.source, &paths.from_relative)?;

    if source_meta.len() > ctx.policy.limits.max_write_bytes {
        return Err(Error::FileTooLarge {
            path: paths.from_relative.clone(),
            size_bytes: source_meta.len(),
            max_bytes: ctx.policy.limits.max_write_bytes,
        });
    }

    ensure_destination_parent_identity_verification_supported()?;
    let destination = prepare_destination(ctx, &request, &mut paths)?;
    if paths.source == destination.path {
        return Ok(noop_response(
            paths.from_relative.clone(),
            destination.to_effective_relative.clone(),
            paths.requested_from.clone(),
            paths.requested_to.clone(),
        ));
    }

    let destination_meta = match fs::symlink_metadata(&destination.path) {
        Ok(meta) => Some(meta),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => None,
        Err(err) => {
            return Err(Error::io_path(
                "metadata",
                &destination.to_effective_relative,
                err,
            ));
        }
    };
    if let Some(meta) = &destination_meta {
        if metadata_same_file(&source_meta, meta) {
            return Ok(noop_response(
                paths.from_relative.clone(),
                destination.to_effective_relative.clone(),
                paths.requested_from.clone(),
                paths.requested_to.clone(),
            ));
        }
        if meta.is_dir() {
            return Err(Error::InvalidPath(
                "destination exists and is a directory".to_string(),
            ));
        }
        if !meta.is_file() {
            return Err(Error::InvalidPath(
                "destination exists and is not a regular file".to_string(),
            ));
        }
        if !request.overwrite {
            return Err(Error::InvalidPath("destination exists".to_string()));
        }
    }

    let destination_parent_meta = capture_destination_parent_identity(
        &destination.parent,
        &destination.to_effective_relative,
    )?;
    verify_destination_parent_identity(
        &destination.parent,
        &destination_parent_meta,
        &destination.to_effective_relative,
    )?;
    let (tmp_path, bytes) = copy_to_temp(
        &mut input,
        &destination.parent,
        &destination_parent_meta,
        &paths.from_relative,
        &destination.to_effective_relative,
        ctx.policy.limits.max_write_bytes,
    )?;
    commit_replace(
        &tmp_path,
        &destination.path,
        &destination.parent,
        &destination_parent_meta,
        &destination.to_effective_relative,
        request.overwrite,
        &source_meta,
    )?;

    Ok(CopyFileResponse {
        from: paths.from_relative,
        to: destination.to_effective_relative,
        requested_from: Some(paths.requested_from),
        requested_to: Some(paths.requested_to),
        copied: true,
        bytes,
    })
}

fn resolve_and_validate_paths(
    ctx: &Context,
    request: &CopyFileRequest,
) -> Result<ResolvedCopyPaths> {
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
    let to_name = PathBuf::from(to_name);

    let from_parent_rel = requested_from
        .parent()
        .unwrap_or_else(|| Path::new(""))
        .to_path_buf();
    let to_parent_rel = requested_to
        .parent()
        .unwrap_or_else(|| Path::new(""))
        .to_path_buf();

    let from_parent = ctx.ensure_dir_under_root(&request.root_id, &from_parent_rel, false)?;
    let to_parent = match ctx.ensure_dir_under_root(&request.root_id, &to_parent_rel, false) {
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
    let to_requested_relative = requested_to.clone();

    if ctx.redactor.is_path_denied(&from_relative) {
        return Err(Error::SecretPathDenied(from_relative));
    }
    if ctx.redactor.is_path_denied(&to_requested_relative) {
        return Err(Error::SecretPathDenied(to_requested_relative));
    }

    let source = from_parent.join(from_name);
    if !crate::path_utils::starts_with_case_insensitive(&source, &canonical_root) {
        return Err(Error::OutsideRoot {
            root_id: request.root_id.clone(),
            path: requested_from.clone(),
        });
    }

    Ok(ResolvedCopyPaths {
        canonical_root,
        requested_from,
        requested_to,
        from_relative,
        source,
        to_parent_rel,
        to_name,
        to_parent,
    })
}

fn prepare_destination(
    ctx: &Context,
    request: &CopyFileRequest,
    paths: &mut ResolvedCopyPaths,
) -> Result<PreparedDestination> {
    if paths.to_parent.is_none() {
        paths.to_parent =
            Some(ctx.ensure_dir_under_root(&request.root_id, &paths.to_parent_rel, true)?);
    }
    let to_parent = paths.to_parent.clone().ok_or_else(|| {
        Error::InvalidPath("failed to prepare destination parent directory".to_string())
    })?;

    let to_relative_parent =
        crate::path_utils::strip_prefix_case_insensitive(&to_parent, &paths.canonical_root)
            .ok_or_else(|| Error::OutsideRoot {
                root_id: request.root_id.clone(),
                path: paths.requested_to.clone(),
            })?;
    let to_effective_relative = to_relative_parent.join(&paths.to_name);
    if ctx.redactor.is_path_denied(&to_effective_relative) {
        return Err(Error::SecretPathDenied(to_effective_relative));
    }

    let destination = to_parent.join(&paths.to_name);
    if !crate::path_utils::starts_with_case_insensitive(&destination, &paths.canonical_root) {
        return Err(Error::OutsideRoot {
            root_id: request.root_id.clone(),
            path: paths.requested_to.clone(),
        });
    }

    Ok(PreparedDestination {
        parent: to_parent,
        to_effective_relative,
        path: destination,
    })
}

fn copy_to_temp(
    input: &mut fs::File,
    destination_parent: &Path,
    expected_parent_meta: &fs::Metadata,
    from_relative: &Path,
    to_effective_relative: &Path,
    max_write_bytes: u64,
) -> Result<(tempfile::TempPath, u64)> {
    let mut tmp_file = tempfile::Builder::new()
        .prefix(".safe-fs-tools.")
        .suffix(".tmp")
        .tempfile_in(destination_parent)
        .map_err(|err| Error::io_path("create_temp", to_effective_relative, err))?;
    verify_destination_parent_identity(
        destination_parent,
        expected_parent_meta,
        to_effective_relative,
    )?;

    let limit = max_write_bytes.saturating_add(1);
    let bytes = std::io::copy(&mut input.take(limit), tmp_file.as_file_mut())
        .map_err(|err| Error::io_path("copy", to_effective_relative, err))?;
    if bytes > max_write_bytes {
        return Err(Error::FileTooLarge {
            path: from_relative.to_path_buf(),
            size_bytes: bytes,
            max_bytes: max_write_bytes,
        });
    }

    tmp_file
        .as_file_mut()
        .sync_all()
        .map_err(|err| Error::io_path("sync", to_effective_relative, err))?;

    let tmp_path = tmp_file.into_temp_path();
    Ok((tmp_path, bytes))
}

fn commit_replace(
    tmp_path: &tempfile::TempPath,
    destination: &Path,
    destination_parent: &Path,
    expected_parent_meta: &fs::Metadata,
    to_effective_relative: &Path,
    overwrite: bool,
    source_meta: &fs::Metadata,
) -> Result<()> {
    let tmp_path_ref: &Path = tmp_path.as_ref();

    fs::set_permissions(tmp_path_ref, source_meta.permissions())
        .map_err(|err| Error::io_path("set_permissions", to_effective_relative, err))?;
    fs::OpenOptions::new()
        .read(true)
        .open(tmp_path_ref)
        .and_then(|file| file.sync_all())
        .map_err(|err| Error::io_path("sync", to_effective_relative, err))?;

    verify_destination_parent_identity(
        destination_parent,
        expected_parent_meta,
        to_effective_relative,
    )?;
    super::io::rename_replace(tmp_path_ref, destination, overwrite).map_err(|err| {
        if !overwrite && err.kind() == std::io::ErrorKind::AlreadyExists {
            return Error::InvalidPath("destination exists".to_string());
        }
        if !overwrite && err.kind() == std::io::ErrorKind::Unsupported {
            return Error::InvalidPath(
                "overwrite=false copy is unsupported on this platform".to_string(),
            );
        }
        Error::io_path("rename", to_effective_relative, err)
    })?;
    Ok(())
}

#[cfg(any(unix, windows))]
fn ensure_destination_parent_identity_verification_supported() -> Result<()> {
    Ok(())
}

#[cfg(not(any(unix, windows)))]
fn ensure_destination_parent_identity_verification_supported() -> Result<()> {
    Err(Error::InvalidPath(
        "copy_file is unsupported on this platform: cannot verify destination parent identity"
            .to_string(),
    ))
}

fn capture_destination_parent_identity(
    destination_parent: &Path,
    to_effective_relative: &Path,
) -> Result<fs::Metadata> {
    let meta = fs::symlink_metadata(destination_parent)
        .map_err(|err| Error::io_path("symlink_metadata", to_effective_relative, err))?;
    if !meta.is_dir() {
        return Err(Error::InvalidPath(
            "destination parent directory is not a directory".to_string(),
        ));
    }
    Ok(meta)
}

#[cfg(any(unix, windows))]
fn verify_destination_parent_identity(
    destination_parent: &Path,
    expected_parent_meta: &fs::Metadata,
    to_effective_relative: &Path,
) -> Result<()> {
    let actual_parent_meta = fs::symlink_metadata(destination_parent)
        .map_err(|err| Error::io_path("symlink_metadata", to_effective_relative, err))?;
    if !actual_parent_meta.is_dir()
        || !destination_parent_identity_matches(expected_parent_meta, &actual_parent_meta)
    {
        return Err(Error::InvalidPath(
            "destination parent directory changed during copy".to_string(),
        ));
    }
    Ok(())
}

#[cfg(any(unix, windows))]
fn destination_parent_identity_matches(
    expected_parent_meta: &fs::Metadata,
    actual_parent_meta: &fs::Metadata,
) -> bool {
    metadata_same_file(expected_parent_meta, actual_parent_meta)
}

#[cfg(not(any(unix, windows)))]
fn verify_destination_parent_identity(
    _destination_parent: &Path,
    _expected_parent_meta: &fs::Metadata,
    _to_effective_relative: &Path,
) -> Result<()> {
    Err(Error::InvalidPath(
        "copy_file is unsupported on this platform: cannot verify destination parent identity"
            .to_string(),
    ))
}

fn noop_response(
    from: PathBuf,
    to: PathBuf,
    requested_from: PathBuf,
    requested_to: PathBuf,
) -> CopyFileResponse {
    CopyFileResponse {
        from,
        to,
        requested_from: Some(requested_from),
        requested_to: Some(requested_to),
        copied: false,
        bytes: 0,
    }
}
