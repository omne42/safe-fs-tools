use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

use super::Context;

#[cfg(unix)]
fn metadata_same_file(a: &fs::Metadata, b: &fs::Metadata) -> Option<bool> {
    use std::os::unix::fs::MetadataExt;
    Some(a.dev() == b.dev() && a.ino() == b.ino())
}

#[cfg(windows)]
#[inline]
fn windows_identity_fields_match<T: Eq, U: Eq>(
    a_volume: Option<T>,
    a_index: Option<U>,
    b_volume: Option<T>,
    b_index: Option<U>,
) -> Option<bool> {
    match (a_volume, a_index, b_volume, b_index) {
        (Some(a_volume), Some(a_index), Some(b_volume), Some(b_index)) => {
            Some(a_volume == b_volume && a_index == b_index)
        }
        _ => None,
    }
}

#[cfg(windows)]
fn metadata_same_file(a: &fs::Metadata, b: &fs::Metadata) -> Option<bool> {
    use std::os::windows::fs::MetadataExt;
    windows_identity_fields_match(
        a.volume_serial_number(),
        a.file_index(),
        b.volume_serial_number(),
        b.file_index(),
    )
}

#[cfg(not(any(unix, windows)))]
fn metadata_same_file(_a: &fs::Metadata, _b: &fs::Metadata) -> Option<bool> {
    None
}

#[cfg(all(test, windows))]
mod tests {
    use super::windows_identity_fields_match;

    #[test]
    fn windows_identity_requires_all_fields_present() {
        assert_eq!(
            windows_identity_fields_match::<u32, u64>(None, Some(1), None, Some(1),),
            None
        );
        assert_eq!(
            windows_identity_fields_match::<u32, u64>(Some(1), None, Some(1), None,),
            None
        );
        assert_eq!(
            windows_identity_fields_match::<u32, u64>(None, None, None, None,),
            None
        );
    }

    #[test]
    fn windows_identity_compares_values_when_all_present() {
        assert_eq!(
            windows_identity_fields_match::<u32, u64>(Some(7), Some(11), Some(7), Some(11),),
            Some(true)
        );
        assert_eq!(
            windows_identity_fields_match::<u32, u64>(Some(7), Some(11), Some(8), Some(11),),
            Some(false)
        );
        assert_eq!(
            windows_identity_fields_match::<u32, u64>(Some(7), Some(11), Some(7), Some(12),),
            Some(false)
        );
    }
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

struct ResolvedCopyPaths<'ctx> {
    canonical_root: &'ctx Path,
    requested_from: PathBuf,
    requested_to: PathBuf,
    from_relative: PathBuf,
    source: PathBuf,
    to_name: PathBuf,
    to_parent: Option<PathBuf>,
}

struct PreparedDestination {
    parent: PathBuf,
    to_effective_relative: PathBuf,
    path: PathBuf,
}

struct TempCopy {
    file: fs::File,
    path: tempfile::TempPath,
    bytes: u64,
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
    if crate::path_utils::paths_equal_case_insensitive_normalized(&paths.source, &destination.path)
    {
        return Ok(noop_response(
            paths.from_relative,
            destination.to_effective_relative,
            paths.requested_from,
            paths.requested_to,
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
        if matches!(metadata_same_file(&source_meta, meta), Some(true)) {
            return Ok(noop_response(
                paths.from_relative,
                destination.to_effective_relative,
                paths.requested_from,
                paths.requested_to,
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
    let temp_copy = copy_to_temp(
        &mut input,
        &destination.parent,
        &destination_parent_meta,
        &paths.from_relative,
        &destination.to_effective_relative,
        ctx.policy.limits.max_write_bytes,
    )?;
    let bytes = temp_copy.bytes;
    commit_replace(
        temp_copy,
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

fn resolve_and_validate_paths<'ctx>(
    ctx: &'ctx Context,
    request: &CopyFileRequest,
) -> Result<ResolvedCopyPaths<'ctx>> {
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

    let from_parent_rel = requested_from.parent().unwrap_or_else(|| Path::new(""));
    let to_parent_rel = requested_to.parent().unwrap_or_else(|| Path::new(""));

    let from_parent = ctx.ensure_dir_under_root(&request.root_id, from_parent_rel, false)?;
    let to_parent = match ctx.ensure_dir_under_root(&request.root_id, to_parent_rel, false) {
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
    let from_relative = from_relative_parent.join(from_name);
    if ctx.redactor.is_path_denied(&from_relative) {
        return Err(Error::SecretPathDenied(from_relative));
    }
    if ctx.redactor.is_path_denied(&requested_to) {
        return Err(Error::SecretPathDenied(requested_to.clone()));
    }

    let source = from_parent.join(from_name);
    if !crate::path_utils::starts_with_case_insensitive_normalized(&source, canonical_root) {
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
        to_name,
        to_parent,
    })
}

fn prepare_destination(
    ctx: &Context,
    request: &CopyFileRequest,
    paths: &mut ResolvedCopyPaths<'_>,
) -> Result<PreparedDestination> {
    if paths.to_parent.is_none() {
        let to_parent_rel = paths.requested_to.parent().unwrap_or_else(|| Path::new(""));
        paths.to_parent = Some(ctx.ensure_dir_under_root(&request.root_id, to_parent_rel, true)?);
    }
    let to_parent = paths.to_parent.take().ok_or_else(|| {
        Error::InvalidPath("failed to prepare destination parent directory".to_string())
    })?;

    let to_relative_parent = crate::path_utils::strip_prefix_case_insensitive_normalized(
        &to_parent,
        paths.canonical_root,
    )
    .ok_or_else(|| Error::OutsideRoot {
        root_id: request.root_id.clone(),
        path: paths.requested_to.clone(),
    })?;
    let to_effective_relative = to_relative_parent.join(&paths.to_name);
    if ctx.redactor.is_path_denied(&to_effective_relative) {
        return Err(Error::SecretPathDenied(to_effective_relative));
    }

    let destination = to_parent.join(&paths.to_name);
    if !crate::path_utils::starts_with_case_insensitive_normalized(
        &destination,
        paths.canonical_root,
    ) {
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
) -> Result<TempCopy> {
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

    let (file, path) = tmp_file.into_parts();
    Ok(TempCopy { file, path, bytes })
}

fn commit_replace(
    temp_copy: TempCopy,
    destination: &Path,
    destination_parent: &Path,
    expected_parent_meta: &fs::Metadata,
    to_effective_relative: &Path,
    overwrite: bool,
    source_meta: &fs::Metadata,
) -> Result<()> {
    temp_copy
        .file
        .set_permissions(source_meta.permissions())
        .map_err(|err| Error::io_path("set_permissions", to_effective_relative, err))?;
    temp_copy
        .file
        .sync_all()
        .map_err(|err| Error::io_path("sync", to_effective_relative, err))?;

    verify_destination_parent_identity(
        destination_parent,
        expected_parent_meta,
        to_effective_relative,
    )?;
    verify_temp_path_identity(
        &temp_copy.file,
        temp_copy.path.as_ref(),
        to_effective_relative,
    )?;

    let tmp_path_ref: &Path = temp_copy.path.as_ref();
    super::io::rename_replace(tmp_path_ref, destination, overwrite).map_err(|err| match err {
        super::io::RenameReplaceError::Io(err) => {
            if !overwrite && super::io::is_destination_exists_rename_error(&err) {
                return Error::InvalidPath("destination exists".to_string());
            }
            if !overwrite && err.kind() == std::io::ErrorKind::Unsupported {
                return Error::InvalidPath(
                    "overwrite=false copy is unsupported on this platform".to_string(),
                );
            }
            Error::io_path("rename", to_effective_relative, err)
        }
        super::io::RenameReplaceError::CommittedButUnsynced(err) => {
            Error::committed_but_unsynced("rename", to_effective_relative, err)
        }
    })?;
    Ok(())
}

fn temp_path_changed_error(to_effective_relative: &Path) -> Error {
    Error::InvalidPath(format!(
        "temporary copy file changed during commit for path {}",
        to_effective_relative.display()
    ))
}

fn verify_temp_path_identity(
    temp_file: &fs::File,
    temp_path: &Path,
    to_effective_relative: &Path,
) -> Result<()> {
    let temp_file_meta = temp_file
        .metadata()
        .map_err(|err| Error::io_path("metadata", to_effective_relative, err))?;
    let temp_path_meta = fs::symlink_metadata(temp_path)
        .map_err(|err| Error::io_path("symlink_metadata", to_effective_relative, err))?;
    if !temp_path_meta.is_file() {
        return Err(temp_path_changed_error(to_effective_relative));
    }
    match metadata_same_file(&temp_file_meta, &temp_path_meta) {
        Some(true) => Ok(()),
        Some(false) => Err(temp_path_changed_error(to_effective_relative)),
        None => Err(Error::InvalidPath(format!(
            "cannot verify temporary copy file identity for path {}",
            to_effective_relative.display()
        ))),
    }
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
    if !actual_parent_meta.is_dir() {
        return Err(Error::InvalidPath(
            "destination parent directory changed during copy".to_string(),
        ));
    }
    match destination_parent_identity_matches(expected_parent_meta, &actual_parent_meta) {
        Some(true) => {}
        Some(false) => {
            return Err(Error::InvalidPath(
                "destination parent directory changed during copy".to_string(),
            ));
        }
        None => {
            // Best-effort fallback for filesystems that do not expose stable file IDs.
            // We still require the canonical parent path to remain unchanged.
        }
    }
    Ok(())
}

#[cfg(any(unix, windows))]
fn destination_parent_identity_matches(
    expected_parent_meta: &fs::Metadata,
    actual_parent_meta: &fs::Metadata,
) -> Option<bool> {
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

#[cfg(all(test, unix))]
mod tests {
    use std::path::Path;

    use super::verify_temp_path_identity;
    use crate::error::Error;

    #[test]
    fn temp_path_identity_check_detects_replaced_path() {
        let dir = tempfile::tempdir().expect("tempdir");
        let tmp = tempfile::Builder::new()
            .prefix(".safe-fs-tools.")
            .suffix(".tmp")
            .tempfile_in(dir.path())
            .expect("create temp file");
        let (file, path) = tmp.into_parts();
        let temp_path = path.to_path_buf();

        std::fs::remove_file(&temp_path).expect("unlink temp path");
        std::fs::write(&temp_path, b"replacement").expect("write replacement");

        let err = verify_temp_path_identity(&file, &temp_path, Path::new("dst.txt"))
            .expect_err("replaced temp path must be rejected");
        match err {
            Error::InvalidPath(msg) => assert!(msg.contains("temporary copy file changed")),
            other => panic!("unexpected error: {other:?}"),
        }
    }
}
