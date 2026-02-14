use std::fs;
use std::path::{Path, PathBuf};

use crate::error::{Error, Result};

mod dir_ops;

pub(super) fn derive_requested_path(
    root_path: &Path,
    canonical_root: &Path,
    input: &Path,
    resolved: &Path,
) -> Result<PathBuf> {
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
        .ok_or_else(|| {
            Error::InvalidPath(format!(
                "failed to derive root-relative path from absolute input {}",
                input.display()
            ))
        })?
    } else {
        input.to_path_buf()
    };

    let normalized = crate::path_utils::normalize_path_lexical(&relative_requested);
    if normalized.as_os_str().is_empty() {
        Ok(PathBuf::from("."))
    } else {
        Ok(normalized)
    }
}

pub(super) struct ResolvedPath {
    pub(super) resolved: PathBuf,
    pub(super) requested_path: PathBuf,
    pub(super) canonical_root: PathBuf,
}

// IMPORTANT DESIGN NOTE:
//
// This module uses lexical + canonical-path checks over path strings and canonicalization, not a
// full directory-fd descriptor chain (`openat`/capability walk).
//
// We intentionally keep this local-first model because `safe-fs-tools` targets local usage and
// policy-layer enforcement with manageable cross-platform complexity. A full descriptor-chain
// confinement model is stronger against TOCTOU but is currently outside this crate's hard
// guarantees and maintenance envelope.
//
// Therefore:
// - treat these checks as best-effort root-bounded validation,
// - do not interpret them as OS-sandbox-equivalent confinement,
// - use OS sandboxing/containerization for adversarial local-process threat models.
pub(super) fn resolve_path_in_root_lexically(
    ctx: &super::Context,
    root_id: &str,
    path: &Path,
) -> Result<ResolvedPath> {
    let resolved = ctx.policy.resolve_path(root_id, path)?;
    let root = ctx.policy.root(root_id)?;
    let canonical_root = ctx.canonical_root(root_id)?.to_path_buf();

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
            derive_requested_path(&root.path, &canonical_root, path, &resolved)?
        };
        if requested_path.is_absolute() {
            return Err(Error::OutsideRoot {
                root_id: root_id.to_string(),
                path: requested_path,
            });
        }
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
    )?)?;

    Ok(ResolvedPath {
        resolved,
        requested_path,
        canonical_root,
    })
}

impl super::Context {
    // NOTE: Same design constraints as above apply. This function is intentionally path-based for
    // local-first ergonomics; it is not a full descriptor-chain confinement primitive.
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
                .ok_or_else(|| {
                    Error::InvalidPath(format!(
                        "failed to derive root-relative path from canonical target {}",
                        canonical.display()
                    ))
                })?;
        let relative = if relative.as_os_str().is_empty() {
            PathBuf::from(".")
        } else {
            relative
        };
        let relative = self.reject_secret_path(relative)?;
        Ok((canonical, relative, requested_path))
    }

    pub(super) fn ensure_dir_under_root(
        &self,
        root_id: &str,
        relative: &Path,
        create_missing: bool,
    ) -> Result<PathBuf> {
        dir_ops::ensure_dir_under_root(self, root_id, relative, create_missing)
    }
}
