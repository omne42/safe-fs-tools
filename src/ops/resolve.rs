use std::fs;
use std::path::{Path, PathBuf};

use crate::error::{Error, Result};

pub(super) fn derive_requested_path(
    root_path: &Path,
    canonical_root: &Path,
    input: &Path,
    resolved: &Path,
) -> PathBuf {
    let relative_requested = if input.is_absolute() {
        let normalized_resolved = crate::path_utils::normalize_path_lexical(resolved);
        let normalized_root_path = crate::path_utils::normalize_path_lexical(root_path);
        let normalized_canonical_root = crate::path_utils::normalize_path_lexical(canonical_root);

        crate::path_utils::strip_prefix_case_insensitive(
            &normalized_resolved,
            &normalized_root_path,
        )
        .or_else(|| {
            crate::path_utils::strip_prefix_case_insensitive(
                &normalized_resolved,
                &normalized_canonical_root,
            )
        })
        .unwrap_or_else(|| resolved.to_path_buf())
    } else {
        input.to_path_buf()
    };

    let normalized = crate::path_utils::normalize_path_lexical(&relative_requested);
    if normalized.as_os_str().is_empty() {
        PathBuf::from(".")
    } else {
        normalized
    }
}

pub(super) struct ResolvedPath {
    pub(super) resolved: PathBuf,
    pub(super) requested_path: PathBuf,
    pub(super) canonical_root: PathBuf,
}

pub(super) fn resolve_path_in_root_lexically(
    ctx: &super::Context,
    root_id: &str,
    path: &Path,
) -> Result<ResolvedPath> {
    let resolved = ctx.policy.resolve_path(root_id, path)?;
    let root = ctx.policy.root(root_id)?;
    let canonical_root = ctx.canonical_root(root_id)?.clone();

    let normalized_resolved = crate::path_utils::normalize_path_lexical(&resolved);
    let normalized_root_path = crate::path_utils::normalize_path_lexical(&root.path);
    let normalized_canonical_root = crate::path_utils::normalize_path_lexical(&canonical_root);

    let lexically_in_root = crate::path_utils::starts_with_case_insensitive(
        &normalized_resolved,
        &normalized_root_path,
    ) || crate::path_utils::starts_with_case_insensitive(
        &normalized_resolved,
        &normalized_canonical_root,
    );

    if !lexically_in_root {
        let requested_path = if path.is_absolute() {
            normalized_resolved
        } else {
            derive_requested_path(&root.path, &canonical_root, path, &resolved)
        };
        let requested_path = ctx.reject_secret_path(requested_path)?;
        return Err(Error::OutsideRoot {
            root_id: root_id.to_string(),
            path: requested_path,
        });
    }

    let requested_path = ctx.reject_secret_path(derive_requested_path(
        &root.path,
        &canonical_root,
        path,
        &resolved,
    ))?;

    Ok(ResolvedPath {
        resolved,
        requested_path,
        canonical_root,
    })
}

impl super::Context {
    pub(super) fn canonical_path_in_root(
        &self,
        root_id: &str,
        path: &Path,
    ) -> Result<(PathBuf, PathBuf, PathBuf)> {
        let resolved = resolve_path_in_root_lexically(self, root_id, path)?;
        let requested_path = resolved.requested_path;
        let canonical_root = resolved.canonical_root;
        let resolved = resolved.resolved;

        let canonical = match resolved.canonicalize() {
            Ok(canonical) => canonical,
            Err(err) => {
                if err.kind() == std::io::ErrorKind::NotFound
                    && let Ok(meta) = fs::symlink_metadata(&resolved)
                    && meta.file_type().is_symlink()
                {
                    let symlink_target = fs::read_link(&resolved).ok();
                    let parent = resolved.parent();
                    let canonical_parent = parent.and_then(|path| path.canonicalize().ok());
                    if let (Some(symlink_target), Some(canonical_parent)) =
                        (symlink_target, canonical_parent)
                    {
                        let resolved_target = if symlink_target.is_absolute() {
                            symlink_target
                        } else {
                            canonical_parent.join(symlink_target)
                        };
                        let resolved_target =
                            crate::path_utils::normalize_path_lexical(&resolved_target);
                        if !crate::path_utils::starts_with_case_insensitive(
                            &resolved_target,
                            &canonical_root,
                        ) {
                            return Err(Error::OutsideRoot {
                                root_id: root_id.to_string(),
                                path: requested_path,
                            });
                        }
                    }
                }
                return Err(Error::io_path("canonicalize", requested_path, err));
            }
        };
        if !crate::path_utils::starts_with_case_insensitive(&canonical, &canonical_root) {
            return Err(Error::OutsideRoot {
                root_id: root_id.to_string(),
                path: requested_path,
            });
        }
        let relative =
            crate::path_utils::strip_prefix_case_insensitive(&canonical, &canonical_root)
                .unwrap_or(canonical.clone());
        let relative = if relative.as_os_str().is_empty() {
            PathBuf::from(".")
        } else {
            relative
        };
        let relative = self.reject_secret_path(relative)?;
        Ok((canonical, relative, requested_path))
    }
}
