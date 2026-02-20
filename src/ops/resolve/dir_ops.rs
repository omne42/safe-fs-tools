use std::ffi::OsStr;
use std::fs;
use std::path::{Component, Path, PathBuf};

use crate::error::{Error, Result};

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

#[cfg(any(unix, windows))]
fn ensure_create_missing_identity_verification_supported() -> Result<()> {
    Ok(())
}

#[cfg(not(any(unix, windows)))]
fn ensure_create_missing_identity_verification_supported() -> Result<()> {
    Err(Error::InvalidPath(
        "create_parents is unsupported on this platform: cannot verify parent directory identity"
            .to_string(),
    ))
}

fn outside_root_error(root_id: &str, relative: &Path) -> Error {
    Error::OutsideRoot {
        root_id: root_id.to_string(),
        path: relative.to_path_buf(),
    }
}

fn ensure_canonical_under_root(
    canonical: &Path,
    canonical_root: &Path,
    root_id: &str,
    relative: &Path,
) -> Result<()> {
    if crate::path_utils::starts_with_case_insensitive_normalized(canonical, canonical_root) {
        return Ok(());
    }
    Err(outside_root_error(root_id, relative))
}

fn canonicalize_checked(
    path: &Path,
    relative: &Path,
    canonical_root: &Path,
    root_id: &str,
) -> Result<PathBuf> {
    let canonical = path
        .canonicalize()
        .map_err(|err| Error::io_path("canonicalize", relative, err))?;
    ensure_canonical_under_root(&canonical, canonical_root, root_id, relative)?;
    Ok(canonical)
}

fn canonical_relative_checked(
    canonical: &Path,
    canonical_root: &Path,
    root_id: &str,
    relative: &Path,
) -> Result<PathBuf> {
    ensure_canonical_under_root(canonical, canonical_root, root_id, relative)?;
    crate::path_utils::strip_prefix_case_insensitive_normalized(canonical, canonical_root)
        .ok_or_else(|| {
            Error::InvalidPath(format!(
                "failed to derive root-relative path from canonical path {}",
                canonical.display()
            ))
        })
}

fn reject_secret_canonical_path(
    ctx: &super::super::Context,
    canonical: &Path,
    canonical_root: &Path,
    root_id: &str,
    relative: &Path,
) -> Result<()> {
    let relative_path = canonical_relative_checked(canonical, canonical_root, root_id, relative)?;
    ctx.reject_secret_path(relative_path)?;
    Ok(())
}

fn cleanup_created_dir(
    parent: &Path,
    parent_relative: &Path,
    expected_parent_meta: &fs::Metadata,
    next: &Path,
    relative: &Path,
    created_meta: &fs::Metadata,
    validation_err: &Error,
) -> Result<()> {
    verify_parent_identity(parent, parent_relative, expected_parent_meta)?;
    let current_meta = fs::symlink_metadata(next)
        .map_err(|err| Error::io_path("symlink_metadata", relative, err))?;
    if current_meta.file_type().is_symlink() || !current_meta.is_dir() {
        return Err(Error::InvalidPath(format!(
            "path {} changed before cleanup after validation failure: {validation_err}",
            relative.display()
        )));
    }
    match metadata_same_file(created_meta, &current_meta) {
        Some(true) => {}
        Some(false) => {
            return Err(Error::InvalidPath(format!(
                "path {} changed before cleanup after validation failure: {validation_err}",
                relative.display()
            )));
        }
        None => {
            return Err(Error::InvalidPath(format!(
                "path {} identity could not be verified before cleanup after validation failure: {validation_err}",
                relative.display()
            )));
        }
    }
    fs::remove_dir(next).map_err(|cleanup_err| {
        let cleanup_context = std::io::Error::new(
            cleanup_err.kind(),
            format!(
                "directory post-create validation failed ({validation_err}); cleanup failed: {cleanup_err}"
            ),
        );
        Error::io_path("remove_dir", relative, cleanup_context)
    })
}

fn capture_parent_identity(parent: &Path, parent_relative: &Path) -> Result<fs::Metadata> {
    let meta = fs::symlink_metadata(parent)
        .map_err(|err| Error::io_path("symlink_metadata", parent_relative, err))?;
    if meta.file_type().is_symlink() || !meta.is_dir() {
        return Err(Error::InvalidPath(format!(
            "parent path {} changed during operation",
            parent_relative.display()
        )));
    }
    Ok(meta)
}

#[cfg(any(unix, windows))]
fn verify_parent_identity(
    parent: &Path,
    parent_relative: &Path,
    expected_parent_meta: &fs::Metadata,
) -> Result<()> {
    let current_parent_meta = fs::symlink_metadata(parent)
        .map_err(|err| Error::io_path("symlink_metadata", parent_relative, err))?;
    if current_parent_meta.file_type().is_symlink() || !current_parent_meta.is_dir() {
        return Err(Error::InvalidPath(format!(
            "parent path {} changed during operation",
            parent_relative.display()
        )));
    }
    match metadata_same_file(expected_parent_meta, &current_parent_meta) {
        Some(true) => {}
        Some(false) => {
            return Err(Error::InvalidPath(format!(
                "parent path {} changed during operation",
                parent_relative.display()
            )));
        }
        None => {
            return Err(Error::InvalidPath(format!(
                "parent path {} identity could not be verified during operation",
                parent_relative.display()
            )));
        }
    }
    Ok(())
}

#[cfg(not(any(unix, windows)))]
fn verify_parent_identity(
    _parent: &Path,
    _parent_relative: &Path,
    _expected_parent_meta: &fs::Metadata,
) -> Result<()> {
    Err(Error::InvalidPath(
        "create_parents is unsupported on this platform: cannot verify parent directory identity"
            .to_string(),
    ))
}

fn handle_existing_component(
    next: &Path,
    meta: &fs::Metadata,
    relative: &Path,
    canonical_root: &Path,
    root_id: &str,
    canonicalize_existing_dirs: bool,
) -> Result<PathBuf> {
    if meta.file_type().is_symlink() {
        let canonical = canonicalize_checked(next, relative, canonical_root, root_id)?;
        let canonical_meta =
            fs::metadata(&canonical).map_err(|err| Error::io_path("metadata", relative, err))?;
        if !canonical_meta.is_dir() {
            return Err(Error::InvalidPath(format!(
                "path component {} is not a directory",
                relative.display()
            )));
        }
        return Ok(canonical);
    }

    if meta.is_dir() {
        if canonicalize_existing_dirs {
            return canonicalize_checked(next, relative, canonical_root, root_id);
        }
        ensure_canonical_under_root(next, canonical_root, root_id, relative)?;
        return Ok(next.to_path_buf());
    }

    Err(Error::InvalidPath(format!(
        "path component {} is not a directory",
        relative.display()
    )))
}

fn validate_relative_component<'a>(
    relative: &Path,
    component: Component<'a>,
) -> Result<Option<&'a OsStr>> {
    match component {
        Component::CurDir => Ok(None),
        Component::ParentDir => Err(Error::InvalidPath(format!(
            "invalid path {}: '..' segments are not allowed",
            relative.display()
        ))),
        Component::Normal(segment) => Ok(Some(segment)),
        _ => Err(Error::InvalidPath(format!(
            "invalid path segment in {}",
            relative.display()
        ))),
    }
}

pub(super) fn ensure_dir_under_root(
    ctx: &super::super::Context,
    root_id: &str,
    relative: &Path,
    create_missing: bool,
) -> Result<PathBuf> {
    let canonical_root = ctx.canonical_root(root_id)?;
    if create_missing {
        ensure_create_missing_identity_verification_supported()?;
    }
    let mut current = canonical_root.to_path_buf();
    let mut current_relative = PathBuf::new();

    for component in relative.components() {
        let Some(segment) = validate_relative_component(relative, component)? else {
            continue;
        };
        let parent_meta_snapshot = if create_missing {
            Some(capture_parent_identity(
                &current,
                current_relative.as_path(),
            )?)
        } else {
            None
        };
        current_relative.push(segment);
        let next_relative = current_relative.as_path();
        let parent_relative = next_relative.parent().unwrap_or_else(|| Path::new(""));
        let next = current.join(segment);
        let mut created_meta: Option<fs::Metadata> = None;

        let resolved_current = match fs::symlink_metadata(&next) {
            Ok(meta) => handle_existing_component(
                &next,
                &meta,
                next_relative,
                canonical_root,
                root_id,
                !create_missing,
            )?,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                if !create_missing {
                    return Err(Error::io_path("symlink_metadata", next_relative, err));
                }
                let expected_parent_meta = match parent_meta_snapshot.as_ref() {
                    Some(meta) => meta,
                    None => {
                        return Err(Error::InvalidPath(
                            "internal error: missing parent identity snapshot".to_string(),
                        ));
                    }
                };
                verify_parent_identity(&current, parent_relative, expected_parent_meta)?;
                reject_secret_canonical_path(ctx, &next, canonical_root, root_id, next_relative)?;
                let created_now = match fs::create_dir(&next) {
                    Ok(()) => true,
                    Err(create_err) if create_err.kind() == std::io::ErrorKind::AlreadyExists => {
                        false
                    }
                    Err(create_err) => {
                        return Err(Error::io_path("create_dir", next_relative, create_err));
                    }
                };
                let mut post_create_meta =
                    Some(fs::symlink_metadata(&next).map_err(|meta_err| {
                        Error::io_path("symlink_metadata", next_relative, meta_err)
                    })?);
                if created_now {
                    created_meta = post_create_meta.take();
                }
                if let Err(err) =
                    verify_parent_identity(&current, parent_relative, expected_parent_meta)
                {
                    if let Some(created_meta) = created_meta.as_ref() {
                        cleanup_created_dir(
                            &current,
                            parent_relative,
                            expected_parent_meta,
                            &next,
                            next_relative,
                            created_meta,
                            &err,
                        )?;
                    }
                    return Err(err);
                }

                let post_create_meta = created_meta
                    .as_ref()
                    .or(post_create_meta.as_ref())
                    .ok_or_else(|| {
                        Error::InvalidPath(
                            "internal error: missing post-create metadata snapshot".to_string(),
                        )
                    })?;
                match handle_existing_component(
                    &next,
                    post_create_meta,
                    next_relative,
                    canonical_root,
                    root_id,
                    !create_missing,
                ) {
                    Ok(canonical) => canonical,
                    Err(err) => {
                        if let (Some(created_meta), Some(expected_parent_meta)) =
                            (created_meta.as_ref(), parent_meta_snapshot.as_ref())
                        {
                            cleanup_created_dir(
                                &current,
                                parent_relative,
                                expected_parent_meta,
                                &next,
                                next_relative,
                                created_meta,
                                &err,
                            )?;
                        }
                        return Err(err);
                    }
                }
            }
            Err(err) => return Err(Error::io_path("symlink_metadata", next_relative, err)),
        };
        if let Err(err) = reject_secret_canonical_path(
            ctx,
            &resolved_current,
            canonical_root,
            root_id,
            next_relative,
        ) {
            if let (Some(created_meta), Some(expected_parent_meta)) =
                (created_meta.as_ref(), parent_meta_snapshot.as_ref())
            {
                cleanup_created_dir(
                    &current,
                    parent_relative,
                    expected_parent_meta,
                    &next,
                    next_relative,
                    created_meta,
                    &err,
                )?;
            }
            return Err(err);
        }
        current = resolved_current;
    }

    Ok(current)
}

#[cfg(all(test, windows))]
mod tests {
    use super::windows_identity_fields_match;

    #[test]
    fn windows_identity_requires_all_fields_present() {
        assert_eq!(
            windows_identity_fields_match::<u32, u64>(None, Some(1), None, Some(1)),
            None
        );
        assert_eq!(
            windows_identity_fields_match::<u32, u64>(Some(1), None, Some(1), None),
            None
        );
        assert_eq!(
            windows_identity_fields_match::<u32, u64>(None, None, None, None),
            None
        );
    }

    #[test]
    fn windows_identity_compares_values_when_all_present() {
        assert_eq!(
            windows_identity_fields_match(Some(7_u32), Some(11_u64), Some(7_u32), Some(11_u64)),
            Some(true)
        );
        assert_eq!(
            windows_identity_fields_match(Some(7_u32), Some(11_u64), Some(9_u32), Some(11_u64)),
            Some(false)
        );
    }
}
