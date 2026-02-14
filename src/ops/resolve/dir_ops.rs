use std::fs;
use std::path::{Component, Path, PathBuf};

use crate::error::{Error, Result};

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
    if crate::path_utils::starts_with_case_insensitive(canonical, canonical_root) {
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
    crate::path_utils::strip_prefix_case_insensitive(canonical, canonical_root).ok_or_else(|| {
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
    next: &Path,
    relative: &Path,
    created_meta: &fs::Metadata,
    validation_err: &Error,
) -> Result<()> {
    let current_meta = fs::symlink_metadata(next)
        .map_err(|err| Error::io_path("symlink_metadata", relative, err))?;
    if current_meta.file_type().is_symlink()
        || !current_meta.is_dir()
        || !metadata_same_file(created_meta, &current_meta)
    {
        return Err(Error::InvalidPath(
            "path changed before cleanup".to_string(),
        ));
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

fn handle_existing_component(
    next: &Path,
    meta: &fs::Metadata,
    relative: &Path,
    canonical_root: &Path,
    root_id: &str,
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
        return canonicalize_checked(next, relative, canonical_root, root_id);
    }

    Err(Error::InvalidPath(format!(
        "path component {} is not a directory",
        relative.display()
    )))
}

fn validate_relative_component(
    relative: &Path,
    component: Component<'_>,
) -> Result<Option<PathBuf>> {
    match component {
        Component::CurDir => Ok(None),
        Component::ParentDir => Err(Error::InvalidPath(format!(
            "invalid path {}: '..' segments are not allowed",
            relative.display()
        ))),
        Component::Normal(segment) => Ok(Some(PathBuf::from(segment))),
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
    let canonical_root = ctx.canonical_root(root_id)?.to_path_buf();
    let mut current = canonical_root.clone();
    let mut current_relative = PathBuf::new();

    for component in relative.components() {
        let Some(segment) = validate_relative_component(relative, component)? else {
            continue;
        };
        current_relative.push(&segment);
        let next = current.join(&segment);

        let resolved_current = match fs::symlink_metadata(&next) {
            Ok(meta) => handle_existing_component(
                &next,
                &meta,
                &current_relative,
                &canonical_root,
                root_id,
            )?,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                if !create_missing {
                    return Err(Error::io_path("symlink_metadata", &current_relative, err));
                }
                reject_secret_canonical_path(
                    ctx,
                    &next,
                    &canonical_root,
                    root_id,
                    &current_relative,
                )?;
                let created_now = match fs::create_dir(&next) {
                    Ok(()) => true,
                    Err(create_err) if create_err.kind() == std::io::ErrorKind::AlreadyExists => {
                        false
                    }
                    Err(create_err) => {
                        return Err(Error::io_path("create_dir", &current_relative, create_err));
                    }
                };
                let created_meta = if created_now {
                    Some(fs::symlink_metadata(&next).map_err(|meta_err| {
                        Error::io_path("symlink_metadata", &current_relative, meta_err)
                    })?)
                } else {
                    None
                };

                match fs::symlink_metadata(&next)
                    .map_err(|meta_err| {
                        Error::io_path("symlink_metadata", &current_relative, meta_err)
                    })
                    .and_then(|meta| {
                        handle_existing_component(
                            &next,
                            &meta,
                            &current_relative,
                            &canonical_root,
                            root_id,
                        )
                    }) {
                    Ok(canonical) => canonical,
                    Err(err) => {
                        if let Some(created_meta) = created_meta.as_ref() {
                            cleanup_created_dir(&next, &current_relative, created_meta, &err)?;
                        }
                        return Err(err);
                    }
                }
            }
            Err(err) => return Err(Error::io_path("symlink_metadata", &current_relative, err)),
        };
        reject_secret_canonical_path(
            ctx,
            &resolved_current,
            &canonical_root,
            root_id,
            &current_relative,
        )?;
        current = resolved_current;
    }

    Ok(current)
}
