use std::fs;
use std::path::{Component, Path, PathBuf};

use crate::error::{Error, Result};

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

        current = match fs::symlink_metadata(&next) {
            Ok(meta) => handle_existing_component(
                &next,
                &meta,
                &current_relative,
                &canonical_root,
                root_id,
            )?,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                if !create_missing {
                    return Err(Error::io_path("metadata", &current_relative, err));
                }
                fs::create_dir(&next).map_err(|create_err| {
                    Error::io_path("create_dir", &current_relative, create_err)
                })?;
                canonicalize_checked(&next, &current_relative, &canonical_root, root_id)?
            }
            Err(err) => return Err(Error::io_path("metadata", &current_relative, err)),
        };
    }

    Ok(current)
}
