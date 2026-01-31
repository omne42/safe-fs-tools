use std::path::{Path, PathBuf};

#[cfg(any(feature = "glob", feature = "grep"))]
use std::fs;
#[cfg(any(feature = "glob", feature = "grep"))]
use std::time::{Duration, Instant};

#[cfg(any(feature = "glob", feature = "grep"))]
use globset::{GlobSet, GlobSetBuilder};
#[cfg(any(feature = "glob", feature = "grep"))]
use walkdir::WalkDir;

#[cfg(any(feature = "glob", feature = "grep"))]
use crate::error::{Error, Result};

#[cfg(any(feature = "glob", feature = "grep"))]
use super::{Context, ScanLimitReason};

#[cfg(any(feature = "glob", feature = "grep"))]
// A synthetic file name used to apply deny/skip glob patterns to directories: for each directory
// entry `dir`, we also evaluate `dir/<probe>` against glob rules so patterns like `node_modules/*`
// or `**/.git/**` can exclude entire directories (and avoid descending into them).
pub(super) const TRAVERSAL_GLOB_PROBE_NAME: &str = ".safe-fs-tools-probe";

#[cfg(any(feature = "glob", feature = "grep"))]
pub(super) fn elapsed_ms(started: &Instant) -> u64 {
    let ms = started.elapsed().as_millis();
    if ms > u64::MAX as u128 {
        u64::MAX
    } else {
        ms as u64
    }
}

#[cfg(any(feature = "glob", feature = "grep"))]
pub(super) fn globset_is_match(glob: &GlobSet, path: &Path) -> bool {
    #[cfg(windows)]
    {
        let raw = path.to_string_lossy();
        if !raw.contains('\\') {
            return glob.is_match(path);
        }
        let normalized = raw.replace('\\', "/");
        return glob.is_match(Path::new(&normalized));
    }
    #[cfg(not(windows))]
    {
        glob.is_match(path)
    }
}

#[cfg(any(feature = "glob", feature = "grep"))]
fn walkdir_root_error(root_path: &Path, walk_root: &Path, err: walkdir::Error) -> Error {
    let relative = crate::path_utils::strip_prefix_case_insensitive(walk_root, root_path)
        .filter(|relative| !relative.as_os_str().is_empty())
        .unwrap_or_else(|| PathBuf::from("."));

    let source = match err.io_error().and_then(|io| io.raw_os_error()) {
        Some(raw_os_error) => std::io::Error::from_raw_os_error(raw_os_error),
        None => std::io::Error::new(
            err.io_error()
                .map(|io| io.kind())
                .unwrap_or(std::io::ErrorKind::Other),
            "walkdir error",
        ),
    };

    Error::WalkDirRoot {
        path: relative,
        source,
    }
}

#[cfg(any(feature = "glob", feature = "grep"))]
pub(super) fn compile_glob(pattern: &str) -> Result<GlobSet> {
    let normalized = crate::path_utils::normalize_glob_pattern_for_matching(pattern);
    crate::path_utils::validate_root_relative_glob_pattern(&normalized)
        .map_err(|msg| Error::InvalidPath(format!("invalid glob pattern {pattern:?}: {msg}")))?;
    let glob = crate::path_utils::build_glob_from_normalized(&normalized)
        .map_err(|err| Error::InvalidPath(format!("invalid glob pattern {pattern:?}: {err}")))?;
    let mut builder = GlobSetBuilder::new();
    builder.add(glob);
    builder
        .build()
        .map_err(|err| Error::InvalidPath(format!("invalid glob pattern {pattern:?}: {err}")))
}

#[cfg(any(feature = "glob", feature = "grep"))]
pub(super) fn compile_traversal_skip_globs(patterns: &[String]) -> Result<Option<GlobSet>> {
    if patterns.is_empty() {
        return Ok(None);
    }
    let mut builder = GlobSetBuilder::new();
    for pattern in patterns {
        let normalized = crate::path_utils::normalize_glob_pattern_for_matching(pattern);
        crate::path_utils::validate_root_relative_glob_pattern(&normalized).map_err(|msg| {
            Error::InvalidPolicy(format!(
                "invalid traversal.skip_globs glob {pattern:?}: {msg}"
            ))
        })?;
        let glob = crate::path_utils::build_glob_from_normalized(&normalized).map_err(|err| {
            Error::InvalidPolicy(format!(
                "invalid traversal.skip_globs glob {pattern:?}: {err}"
            ))
        })?;
        builder.add(glob);
    }
    let set = builder
        .build()
        .map_err(|err| Error::InvalidPolicy(format!("invalid traversal.skip_globs: {err}")))?;
    Ok(Some(set))
}

#[cfg(any(feature = "glob", feature = "grep"))]
pub(super) fn derive_safe_traversal_prefix(pattern: &str) -> Option<PathBuf> {
    let pattern = crate::path_utils::normalize_glob_pattern(pattern);
    let pattern = pattern.as_ref();
    if pattern.starts_with('/') {
        return None;
    }
    #[cfg(windows)]
    {
        let bytes = pattern.as_bytes();
        if bytes.len() >= 2 && bytes[1] == b':' && bytes[0].is_ascii_alphabetic() {
            // Drive-prefix paths (e.g. `C:...`, `C:/...`) would cause `PathBuf::join` to
            // discard the root prefix, allowing traversal outside the selected root.
            return None;
        }
    }

    let mut out = PathBuf::new();
    for segment in pattern.split('/') {
        if segment.is_empty() || segment == "." {
            continue;
        }
        #[cfg(windows)]
        {
            use std::path::Component;

            if matches!(
                Path::new(segment).components().next(),
                Some(Component::Prefix(_))
            ) {
                // Windows drive/prefix components in later segments can cause `PathBuf::push/join`
                // to discard prior components, allowing traversal outside the selected root.
                return None;
            }
        }
        if segment == ".." {
            return None;
        }
        if segment
            .chars()
            .any(|ch| matches!(ch, '*' | '?' | '[' | ']' | '{' | '}'))
        {
            break;
        }
        out.push(segment);
    }
    if out.as_os_str().is_empty() {
        None
    } else {
        Some(out)
    }
}

#[cfg(any(feature = "glob", feature = "grep"))]
#[derive(Debug, Default, Clone)]
pub(super) struct TraversalDiagnostics {
    pub(super) truncated: bool,
    pub(super) scanned_files: u64,
    pub(super) scanned_entries: u64,
    pub(super) scan_limit_reached: bool,
    pub(super) scan_limit_reason: Option<ScanLimitReason>,
    pub(super) skipped_walk_errors: u64,
    pub(super) skipped_io_errors: u64,
    pub(super) skipped_dangling_symlink_targets: u64,
}

#[cfg(any(feature = "glob", feature = "grep"))]
pub(super) struct TraversalFile {
    pub(super) path: PathBuf,
    pub(super) relative_path: PathBuf,
}

#[cfg(any(feature = "glob", feature = "grep"))]
pub(super) fn walkdir_traversal_iter<'a>(
    ctx: &'a Context,
    root_path: &'a Path,
    walk_root: &'a Path,
) -> impl Iterator<Item = walkdir::Result<walkdir::DirEntry>> + 'a {
    WalkDir::new(walk_root)
        .follow_root_links(false)
        .follow_links(false)
        .sort_by_file_name()
        .into_iter()
        .filter_entry(move |entry| {
            if entry.depth() == 0 {
                return true;
            }
            let is_dir = entry.file_type().is_dir();
            let relative = match entry.path().strip_prefix(root_path) {
                Ok(relative) => std::borrow::Cow::Borrowed(relative),
                Err(_) => {
                    #[cfg(windows)]
                    {
                        if let Some(relative) = crate::path_utils::strip_prefix_case_insensitive(
                            entry.path(),
                            root_path,
                        ) {
                            std::borrow::Cow::Owned(relative)
                        } else {
                            return false;
                        }
                    }
                    #[cfg(not(windows))]
                    {
                        return false;
                    }
                }
            };

            let probe = relative.as_ref().join(TRAVERSAL_GLOB_PROBE_NAME);
            if ctx.redactor.is_path_denied(relative.as_ref())
                || (is_dir && ctx.redactor.is_path_denied(&probe))
            {
                return false;
            }
            !(ctx.is_traversal_path_skipped(relative.as_ref())
                || (is_dir && ctx.is_traversal_path_skipped(&probe)))
        })
}

#[cfg(any(feature = "glob", feature = "grep"))]
pub(super) fn walk_traversal_files(
    ctx: &Context,
    root_id: &str,
    root_path: &Path,
    walk_root: &Path,
    started: &Instant,
    max_walk: Option<Duration>,
    mut on_file: impl FnMut(
        TraversalFile,
        &mut TraversalDiagnostics,
    ) -> Result<std::ops::ControlFlow<()>>,
) -> Result<TraversalDiagnostics> {
    if !walk_root.starts_with(root_path) {
        return Err(Error::InvalidPath(
            "derived traversal root escapes selected root".to_string(),
        ));
    }

    let mut diag = TraversalDiagnostics::default();

    for entry in walkdir_traversal_iter(ctx, root_path, walk_root) {
        if max_walk.is_some_and(|limit| started.elapsed() >= limit) {
            diag.truncated = true;
            diag.scan_limit_reached = true;
            if diag.scan_limit_reason.is_none() {
                diag.scan_limit_reason = Some(ScanLimitReason::Time);
            }
            break;
        }

        let entry = match entry {
            Ok(entry) => entry,
            Err(err) => {
                if err.depth() == 0 {
                    return Err(walkdir_root_error(root_path, walk_root, err));
                }
                if diag.scanned_entries as usize >= ctx.policy.limits.max_walk_entries {
                    diag.truncated = true;
                    diag.scan_limit_reached = true;
                    if diag.scan_limit_reason.is_none() {
                        diag.scan_limit_reason = Some(ScanLimitReason::Entries);
                    }
                    break;
                }
                diag.scanned_entries = diag.scanned_entries.saturating_add(1);
                diag.skipped_walk_errors = diag.skipped_walk_errors.saturating_add(1);
                continue;
            }
        };

        if entry.depth() > 0 {
            if diag.scanned_entries as usize >= ctx.policy.limits.max_walk_entries {
                diag.truncated = true;
                diag.scan_limit_reached = true;
                if diag.scan_limit_reason.is_none() {
                    diag.scan_limit_reason = Some(ScanLimitReason::Entries);
                }
                break;
            }
            diag.scanned_entries = diag.scanned_entries.saturating_add(1);
        }

        let file_type = entry.file_type();
        if !(file_type.is_file() || file_type.is_symlink()) {
            continue;
        }
        if diag.scanned_files as usize >= ctx.policy.limits.max_walk_files {
            diag.truncated = true;
            diag.scan_limit_reached = true;
            if diag.scan_limit_reason.is_none() {
                diag.scan_limit_reason = Some(ScanLimitReason::Files);
            }
            break;
        }
        diag.scanned_files = diag.scanned_files.saturating_add(1);

        let Some(relative) =
            crate::path_utils::strip_prefix_case_insensitive(entry.path(), root_path)
        else {
            diag.skipped_walk_errors = diag.skipped_walk_errors.saturating_add(1);
            continue;
        };
        if ctx.redactor.is_path_denied(&relative) {
            continue;
        }

        let file = if file_type.is_symlink() {
            let (canonical, _canonical_relative, _requested_path) =
                match ctx.canonical_path_in_root(root_id, &relative) {
                    Ok(ok) => ok,
                    Err(Error::OutsideRoot { .. }) | Err(Error::SecretPathDenied(_)) => continue,
                    Err(Error::IoPath {
                        op: "canonicalize",
                        source,
                        ..
                    }) if source.kind() == std::io::ErrorKind::NotFound => {
                        diag.skipped_dangling_symlink_targets =
                            diag.skipped_dangling_symlink_targets.saturating_add(1);
                        continue;
                    }
                    Err(Error::IoPath { .. }) | Err(Error::Io(_)) => {
                        diag.skipped_io_errors = diag.skipped_io_errors.saturating_add(1);
                        continue;
                    }
                    Err(err) => return Err(err),
                };
            let meta = match fs::metadata(&canonical) {
                Ok(meta) => meta,
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                    diag.skipped_dangling_symlink_targets =
                        diag.skipped_dangling_symlink_targets.saturating_add(1);
                    continue;
                }
                Err(_) => {
                    diag.skipped_io_errors = diag.skipped_io_errors.saturating_add(1);
                    continue;
                }
            };
            if !meta.is_file() {
                continue;
            }
            TraversalFile {
                path: canonical,
                relative_path: relative,
            }
        } else {
            TraversalFile {
                path: entry.path().to_path_buf(),
                relative_path: relative,
            }
        };

        match on_file(file, &mut diag)? {
            std::ops::ControlFlow::Continue(()) => {}
            std::ops::ControlFlow::Break(()) => break,
        }
    }

    Ok(diag)
}
