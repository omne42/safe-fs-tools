use std::borrow::Cow;
use std::fs;
use std::path::{Component, Path, PathBuf};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

use super::Context;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeleteRequest {
    pub root_id: String,
    pub path: PathBuf,
    #[serde(default)]
    pub recursive: bool,
    #[serde(default)]
    pub ignore_missing: bool,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DeleteKind {
    File,
    Dir,
    Symlink,
    Other,
    Missing,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeleteResponse {
    pub path: PathBuf,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requested_path: Option<PathBuf>,
    pub deleted: bool,
    #[serde(rename = "type")]
    pub kind: DeleteKind,
}

fn missing_response(requested_path: &Path) -> DeleteResponse {
    let requested_path = requested_path.to_path_buf();
    DeleteResponse {
        path: requested_path.clone(),
        requested_path: Some(requested_path),
        deleted: false,
        kind: DeleteKind::Missing,
    }
}

fn pattern_has_glob_meta(pattern: &str) -> bool {
    pattern
        .bytes()
        .any(|byte| matches!(byte, b'*' | b'?' | b'[' | b']' | b'{' | b'}' | b'!'))
}

fn component_has_glob_meta(component: &std::ffi::OsStr) -> bool {
    component
        .as_encoded_bytes()
        .iter()
        .any(|byte| matches!(*byte, b'*' | b'?' | b'[' | b']' | b'{' | b'}' | b'!'))
}

fn leading_literal_glob_prefix(pattern: &str) -> Option<PathBuf> {
    let mut prefix = PathBuf::new();
    for component in Path::new(pattern).components() {
        match component {
            Component::CurDir => {}
            Component::Normal(segment) => {
                if component_has_glob_meta(segment) {
                    break;
                }
                prefix.push(segment);
            }
            _ => break,
        }
    }
    if prefix.as_os_str().is_empty() {
        None
    } else {
        Some(prefix)
    }
}

fn deny_globs_require_descendant_scan(deny_globs: &[String], target_relative: &Path) -> bool {
    for pattern in deny_globs {
        let normalized = crate::path_utils_internal::normalize_glob_pattern_for_matching(pattern);
        if !pattern_has_glob_meta(&normalized) {
            if Path::new(normalized.as_str()).starts_with(target_relative) {
                return true;
            }
            continue;
        }
        let Some(prefix) = leading_literal_glob_prefix(&normalized) else {
            return true;
        };
        if prefix.starts_with(target_relative) || target_relative.starts_with(&prefix) {
            return true;
        }
    }
    false
}

fn ensure_recursive_delete_allows_descendants(
    ctx: &Context,
    target_abs: &Path,
    target_relative: &Path,
) -> Result<()> {
    let deny_globs = &ctx.policy.secrets.deny_globs;
    if deny_globs.is_empty() {
        return Ok(());
    }
    if !deny_globs_require_descendant_scan(deny_globs, target_relative) {
        return Ok(());
    }

    let max_walk_entries = u64::try_from(ctx.policy.limits.max_walk_entries).unwrap_or(u64::MAX);
    let max_walk = ctx.policy.limits.max_walk_ms.map(Duration::from_millis);
    let started = Instant::now();
    let mut scanned_entries: u64 = 0;
    // Keep only target-relative suffixes in the traversal stack to avoid
    // repeating canonical absolute prefixes across every queued node.
    let mut stack = vec![PathBuf::new()];

    while let Some(dir_suffix) = stack.pop() {
        let dir_abs = target_abs.join(&dir_suffix);
        let dir_relative = target_relative_with_suffix(target_relative, &dir_suffix);
        ensure_recursive_delete_scan_within_budget(
            dir_relative.as_ref(),
            scanned_entries,
            max_walk_entries,
            &started,
            max_walk,
        )?;
        let entries = fs::read_dir(&dir_abs)
            .map_err(|err| Error::io_path("read_dir", dir_relative.as_ref(), err))?;

        for entry in entries {
            scanned_entries = scanned_entries.saturating_add(1);
            ensure_recursive_delete_scan_within_budget(
                dir_relative.as_ref(),
                scanned_entries,
                max_walk_entries,
                &started,
                max_walk,
            )?;
            let entry =
                entry.map_err(|err| Error::io_path("read_dir", dir_relative.as_ref(), err))?;
            let child_name = entry.file_name();
            let child_suffix = if dir_suffix.as_os_str().is_empty() {
                PathBuf::from(&child_name)
            } else {
                dir_suffix.join(&child_name)
            };
            let child_relative = target_relative_with_suffix(target_relative, &child_suffix);

            if ctx.redactor.is_path_denied(child_relative.as_ref()) {
                return Err(Error::SecretPathDenied(child_relative.into_owned()));
            }

            let child_type = entry
                .file_type()
                .map_err(|err| Error::io_path("file_type", child_relative.as_ref(), err))?;
            if child_type.is_dir() {
                stack.push(child_suffix);
            }
        }
    }

    Ok(())
}

#[inline]
fn target_relative_with_suffix<'a>(target_relative: &Path, suffix: &'a Path) -> Cow<'a, Path> {
    if suffix.as_os_str().is_empty() {
        return Cow::Owned(target_relative.to_path_buf());
    }
    if target_relative == Path::new(".") {
        return Cow::Borrowed(suffix);
    }
    Cow::Owned(target_relative.join(suffix))
}

fn ensure_recursive_delete_scan_within_budget(
    current_relative_dir: &Path,
    scanned_entries: u64,
    max_walk_entries: u64,
    started: &Instant,
    max_walk: Option<Duration>,
) -> Result<()> {
    if scanned_entries > max_walk_entries {
        return Err(Error::NotPermitted(format!(
            "recursive delete pre-scan exceeded limits.max_walk_entries while scanning {} ({scanned_entries} > {max_walk_entries})",
            current_relative_dir.display()
        )));
    }
    if let Some(limit) = max_walk
        && started.elapsed() >= limit
    {
        return Err(Error::NotPermitted(format!(
            "recursive delete pre-scan exceeded limits.max_walk_ms while scanning {} (>= {} ms)",
            current_relative_dir.display(),
            limit.as_millis()
        )));
    }
    Ok(())
}

fn unlink_symlink(target: &Path) -> std::io::Result<()> {
    #[cfg(windows)]
    {
        match fs::remove_file(target) {
            Ok(()) => Ok(()),
            // On Windows, directory symlinks/junctions require remove_dir semantics.
            Err(remove_file_err) => match fs::remove_dir(target) {
                Ok(()) => Ok(()),
                Err(_) => Err(remove_file_err),
            },
        }
    }

    #[cfg(not(windows))]
    {
        fs::remove_file(target)
    }
}

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

#[cfg(any(unix, windows))]
fn ensure_delete_identity_verification_supported() -> Result<()> {
    Ok(())
}

#[cfg(not(any(unix, windows)))]
fn ensure_delete_identity_verification_supported() -> Result<()> {
    Err(Error::InvalidPath(
        "delete is unsupported on this platform: cannot verify file identity".to_string(),
    ))
}

fn revalidate_parent_before_delete(
    ctx: &Context,
    request: &DeleteRequest,
    requested_parent: &Path,
    canonical_parent: &Path,
    canonical_parent_meta: &fs::Metadata,
    requested_path: &Path,
) -> Result<Option<DeleteResponse>> {
    match ctx.ensure_dir_under_root(&request.root_id, requested_parent, false) {
        Ok(rechecked_parent) => {
            if rechecked_parent != canonical_parent {
                Err(Error::InvalidPath(format!(
                    "path {} changed during delete; refusing to continue",
                    requested_path.display()
                )))
            } else {
                let rechecked_parent_meta = match fs::symlink_metadata(&rechecked_parent) {
                    Ok(meta) => meta,
                    Err(err)
                        if request.ignore_missing && err.kind() == std::io::ErrorKind::NotFound =>
                    {
                        return Ok(Some(missing_response(requested_path)));
                    }
                    Err(err) => {
                        return Err(Error::io_path("symlink_metadata", requested_parent, err));
                    }
                };
                if !rechecked_parent_meta.is_dir() {
                    return Err(Error::InvalidPath(
                        "parent identity changed during delete; refusing to continue".to_string(),
                    ));
                }
                match metadata_same_file(canonical_parent_meta, &rechecked_parent_meta) {
                    Some(true) => {}
                    Some(false) => {
                        return Err(Error::InvalidPath(
                            "parent identity changed during delete; refusing to continue"
                                .to_string(),
                        ));
                    }
                    None => {
                        // Best-effort fallback for filesystems that do not expose stable file IDs.
                        // Parent path has already been re-resolved and validated under root.
                    }
                }
                Ok(None)
            }
        }
        Err(Error::IoPath { source, .. })
            if request.ignore_missing && source.kind() == std::io::ErrorKind::NotFound =>
        {
            Ok(Some(missing_response(requested_path)))
        }
        Err(err) => Err(err),
    }
}

pub fn delete(ctx: &Context, request: DeleteRequest) -> Result<DeleteResponse> {
    ctx.ensure_write_operation_allowed(&request.root_id, ctx.policy.permissions.delete, "delete")?;
    ensure_delete_identity_verification_supported()?;

    let resolved =
        super::resolve::resolve_path_in_root_lexically(ctx, &request.root_id, &request.path)?;
    let canonical_root = resolved.canonical_root;
    let requested_path = resolved.requested_path;

    let file_name = super::path_validation::ensure_non_root_leaf(
        &requested_path,
        &request.path,
        super::path_validation::LeafOp::Delete,
    )?;

    let requested_parent = requested_path.parent().unwrap_or_else(|| Path::new(""));
    let requested_relative = requested_parent.join(file_name);
    // First check blocks secret paths in the original user-supplied location.
    if ctx.redactor.is_path_denied(&requested_relative) {
        return Err(Error::SecretPathDenied(requested_relative));
    }

    let canonical_parent =
        match ctx.ensure_dir_under_root(&request.root_id, requested_parent, false) {
            Ok(path) => path,
            Err(Error::IoPath { source, .. })
                if request.ignore_missing && source.kind() == std::io::ErrorKind::NotFound =>
            {
                // If the parent directory doesn't exist, the target doesn't exist either.
                return Ok(missing_response(&requested_path));
            }
            Err(err) => return Err(err),
        };
    let canonical_parent_meta = match fs::symlink_metadata(&canonical_parent) {
        Ok(meta) => meta,
        Err(err) if request.ignore_missing && err.kind() == std::io::ErrorKind::NotFound => {
            return Ok(missing_response(&requested_path));
        }
        Err(err) => return Err(Error::io_path("symlink_metadata", requested_parent, err)),
    };
    if !canonical_parent_meta.is_dir() {
        return Err(Error::InvalidPath(format!(
            "parent path {} is not a directory",
            requested_parent.display()
        )));
    }

    let relative_parent = crate::path_utils::strip_prefix_case_insensitive_normalized(
        &canonical_parent,
        canonical_root,
    )
    .ok_or_else(|| Error::OutsideRoot {
        root_id: request.root_id.clone(),
        path: requested_path.clone(),
    })?;
    let relative = relative_parent.join(file_name);

    // Second check blocks secret paths after canonicalization resolves symlinks.
    if ctx.redactor.is_path_denied(&relative) {
        return Err(Error::SecretPathDenied(relative));
    }

    let target = canonical_parent.join(file_name);
    if !crate::path_utils::starts_with_case_insensitive_normalized(&target, canonical_root) {
        return Err(Error::OutsideRoot {
            root_id: request.root_id.clone(),
            path: requested_path,
        });
    }

    if let Some(response) = revalidate_parent_before_delete(
        ctx,
        &request,
        requested_parent,
        &canonical_parent,
        &canonical_parent_meta,
        &requested_path,
    )? {
        return Ok(response);
    }

    let meta = match fs::symlink_metadata(&target) {
        Ok(meta) => meta,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound && request.ignore_missing => {
            return Ok(missing_response(&requested_path));
        }
        Err(err) => return Err(Error::io_path("symlink_metadata", &relative, err)),
    };

    let file_type = meta.file_type();
    let kind = if file_type.is_file() {
        DeleteKind::File
    } else if file_type.is_dir() {
        DeleteKind::Dir
    } else if file_type.is_symlink() {
        DeleteKind::Symlink
    } else {
        DeleteKind::Other
    };

    let ensure_parent_stable_or_missing = || {
        revalidate_parent_before_delete(
            ctx,
            &request,
            requested_parent,
            &canonical_parent,
            &canonical_parent_meta,
            &requested_path,
        )
    };
    let ensure_target_stable_or_missing = || -> Result<Option<DeleteResponse>> {
        let current_meta = match fs::symlink_metadata(&target) {
            Ok(meta) => meta,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound && request.ignore_missing => {
                return Ok(Some(missing_response(&requested_path)));
            }
            Err(err) => return Err(Error::io_path("symlink_metadata", &relative, err)),
        };
        match metadata_same_file(&meta, &current_meta) {
            Some(true) => {}
            Some(false) => {
                return Err(Error::InvalidPath(
                    "target identity changed during delete; refusing to continue".to_string(),
                ));
            }
            None => {
                // Best-effort fallback for filesystems that do not expose stable file IDs.
                // Target path was already validated under the selected root.
            }
        }
        Ok(None)
    };

    if file_type.is_dir() {
        if !request.recursive {
            return Err(Error::InvalidPath(
                "path is a directory; set recursive=true to delete directories".to_string(),
            ));
        }

        if let Some(response) = ensure_parent_stable_or_missing()? {
            return Ok(response);
        }
        if let Some(response) = ensure_target_stable_or_missing()? {
            return Ok(response);
        }
        ensure_recursive_delete_allows_descendants(ctx, &target, &relative)?;

        if let Err(err) = fs::remove_dir_all(&target) {
            if err.kind() == std::io::ErrorKind::NotFound && request.ignore_missing {
                return Ok(missing_response(&requested_path));
            }
            return Err(Error::io_path("remove_dir_all", &relative, err));
        }
    } else {
        if let Some(response) = ensure_parent_stable_or_missing()? {
            return Ok(response);
        }
        if let Some(response) = ensure_target_stable_or_missing()? {
            return Ok(response);
        }

        let delete_non_dir_result = if file_type.is_symlink() {
            unlink_symlink(&target)
        } else {
            fs::remove_file(&target)
        };
        if let Err(err) = delete_non_dir_result {
            if err.kind() == std::io::ErrorKind::NotFound && request.ignore_missing {
                return Ok(missing_response(&requested_path));
            }
            let op = if file_type.is_symlink() {
                "unlink_symlink"
            } else {
                "remove_file"
            };
            return Err(Error::io_path(op, &relative, err));
        }
    }

    Ok(DeleteResponse {
        path: relative,
        requested_path: Some(requested_path),
        deleted: true,
        kind,
    })
}

#[cfg(test)]
mod recursive_scan_tests {
    use std::path::Path;
    use std::time::{Duration, Instant};

    use super::{
        deny_globs_require_descendant_scan, ensure_recursive_delete_scan_within_budget,
        target_relative_with_suffix,
    };
    use crate::error::Error;

    #[test]
    fn scan_skipped_when_literal_patterns_cannot_match_descendants() {
        let deny_globs = vec![
            "private/token.txt".to_string(),
            "secrets/key.pem".to_string(),
        ];
        assert!(!deny_globs_require_descendant_scan(
            &deny_globs,
            Path::new("public")
        ));
    }

    #[test]
    fn scan_required_when_literal_pattern_is_under_target_subtree() {
        let deny_globs = vec!["public/blocked.txt".to_string()];
        assert!(deny_globs_require_descendant_scan(
            &deny_globs,
            Path::new("public")
        ));
    }

    #[test]
    fn scan_required_when_pattern_uses_glob_meta() {
        let deny_globs = vec!["public/*.txt".to_string()];
        assert!(deny_globs_require_descendant_scan(
            &deny_globs,
            Path::new("public")
        ));
    }

    #[test]
    fn scan_skipped_when_glob_prefix_is_disjoint() {
        let deny_globs = vec!["private/*.txt".to_string()];
        assert!(!deny_globs_require_descendant_scan(
            &deny_globs,
            Path::new("public")
        ));
    }

    #[test]
    fn scan_required_when_glob_prefix_overlaps_target() {
        let deny_globs = vec!["private/*.txt".to_string()];
        assert!(deny_globs_require_descendant_scan(
            &deny_globs,
            Path::new("private")
        ));
    }

    #[test]
    fn scan_required_when_glob_has_no_literal_prefix() {
        let deny_globs = vec!["**/.git/**".to_string()];
        assert!(deny_globs_require_descendant_scan(
            &deny_globs,
            Path::new("public")
        ));
    }

    #[test]
    fn recursive_scan_budget_rejects_entry_limit_overflow() {
        let err = ensure_recursive_delete_scan_within_budget(
            Path::new("public"),
            11,
            10,
            &Instant::now(),
            None,
        )
        .expect_err("must reject scans over max_walk_entries");
        match err {
            Error::NotPermitted(msg) => assert!(msg.contains("limits.max_walk_entries")),
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn recursive_scan_budget_rejects_elapsed_time_limit() {
        let started = Instant::now();
        let err = ensure_recursive_delete_scan_within_budget(
            Path::new("public"),
            0,
            10,
            &started,
            Some(Duration::from_millis(0)),
        )
        .expect_err("must reject scans over max_walk_ms");
        match err {
            Error::NotPermitted(msg) => assert!(msg.contains("limits.max_walk_ms")),
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn target_relative_suffix_joins_for_non_root_target() {
        let joined = target_relative_with_suffix(Path::new("root/subtree"), Path::new("a/b"));
        assert_eq!(joined, Path::new("root/subtree/a/b"));
    }

    #[test]
    fn target_relative_suffix_avoids_dot_prefix() {
        let joined = target_relative_with_suffix(Path::new("."), Path::new("a/b"));
        assert_eq!(joined, Path::new("a/b"));
    }
}
