use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use walkdir::WalkDir;

use crate::error::{Error, Result};

use super::super::{Context, ScanLimitReason};
use super::{TRAVERSAL_GLOB_PROBE_NAME, TraversalDiagnostics, TraversalFile};

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

#[derive(Debug)]
enum WalkEntryAction {
    Continue,
    Break,
    Entry(walkdir::DirEntry),
}

fn consume_walk_entry(diag: &mut TraversalDiagnostics, max_walk_entries: u64) -> bool {
    if diag.scanned_entries >= max_walk_entries {
        diag.mark_limit_reached(ScanLimitReason::Entries);
        return false;
    }
    diag.scanned_entries = diag.scanned_entries.saturating_add(1);
    true
}

fn classify_walkdir_entry(
    entry: walkdir::Result<walkdir::DirEntry>,
    root_path: &Path,
    walk_root: &Path,
    diag: &mut TraversalDiagnostics,
    max_walk_entries: u64,
) -> Result<WalkEntryAction> {
    match entry {
        Ok(entry) => {
            if entry.depth() > 0 && !consume_walk_entry(diag, max_walk_entries) {
                return Ok(WalkEntryAction::Break);
            }
            Ok(WalkEntryAction::Entry(entry))
        }
        Err(err) => {
            if err.depth() == 0 {
                return Err(walkdir_root_error(root_path, walk_root, err));
            }
            if !consume_walk_entry(diag, max_walk_entries) {
                return Ok(WalkEntryAction::Break);
            }
            diag.skipped_walk_errors = diag.skipped_walk_errors.saturating_add(1);
            Ok(WalkEntryAction::Continue)
        }
    }
}

fn relative_from_walk_entry(
    entry: &walkdir::DirEntry,
    root_path: &Path,
    diag: &mut TraversalDiagnostics,
) -> Option<PathBuf> {
    let relative = crate::path_utils::strip_prefix_case_insensitive(entry.path(), root_path);
    if relative.is_none() {
        diag.skipped_walk_errors = diag.skipped_walk_errors.saturating_add(1);
    }
    relative
}

fn resolve_symlink_traversal_file(
    ctx: &Context,
    root_id: &str,
    relative: PathBuf,
    diag: &mut TraversalDiagnostics,
) -> Result<Option<TraversalFile>> {
    let (canonical, _canonical_relative, _requested_path) =
        match ctx.canonical_path_in_root(root_id, &relative) {
            Ok(ok) => ok,
            Err(Error::OutsideRoot { .. }) | Err(Error::SecretPathDenied(_)) => return Ok(None),
            Err(Error::IoPath {
                op: "canonicalize",
                source,
                ..
            }) if source.kind() == std::io::ErrorKind::NotFound => {
                diag.skipped_dangling_symlink_targets =
                    diag.skipped_dangling_symlink_targets.saturating_add(1);
                return Ok(None);
            }
            Err(Error::IoPath { .. }) | Err(Error::Io(_)) => {
                diag.skipped_io_errors = diag.skipped_io_errors.saturating_add(1);
                return Ok(None);
            }
            Err(err) => return Err(err),
        };

    let opened = super::super::io::open_regular_file_for_read(&canonical, &relative);
    match opened {
        Ok(ok) => {
            let _ = ok;
            Ok(Some(TraversalFile {
                path: canonical,
                relative_path: relative,
            }))
        }
        Err(Error::IoPath {
            source, op: "open", ..
        }) if source.kind() == std::io::ErrorKind::NotFound => {
            diag.skipped_dangling_symlink_targets =
                diag.skipped_dangling_symlink_targets.saturating_add(1);
            Ok(None)
        }
        Err(Error::InvalidPath(_)) => Ok(None),
        Err(Error::IoPath { .. }) | Err(Error::Io(_)) => {
            diag.skipped_io_errors = diag.skipped_io_errors.saturating_add(1);
            Ok(None)
        }
        Err(err) => Err(err),
    }
}

fn traversal_file_from_entry(
    ctx: &Context,
    root_id: &str,
    root_path: &Path,
    entry: &walkdir::DirEntry,
    diag: &mut TraversalDiagnostics,
) -> Result<Option<TraversalFile>> {
    let Some(relative) = relative_from_walk_entry(entry, root_path, diag) else {
        return Ok(None);
    };
    if ctx.redactor.is_path_denied(&relative) {
        return Ok(None);
    }

    if entry.file_type().is_symlink() {
        return resolve_symlink_traversal_file(ctx, root_id, relative, diag);
    }

    Ok(Some(TraversalFile {
        path: entry.path().to_path_buf(),
        relative_path: relative,
    }))
}

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
    if !crate::path_utils::starts_with_case_insensitive(walk_root, root_path) {
        return Err(Error::InvalidPath(
            "derived traversal root escapes selected root".to_string(),
        ));
    }

    let mut diag = TraversalDiagnostics::default();
    let max_walk_entries = u64::try_from(ctx.policy.limits.max_walk_entries).unwrap_or(u64::MAX);
    let max_walk_files = u64::try_from(ctx.policy.limits.max_walk_files).unwrap_or(u64::MAX);

    for entry in walkdir_traversal_iter(ctx, root_path, walk_root) {
        if max_walk.is_some_and(|limit| started.elapsed() >= limit) {
            diag.mark_limit_reached(ScanLimitReason::Time);
            break;
        }

        let entry =
            match classify_walkdir_entry(entry, root_path, walk_root, &mut diag, max_walk_entries)?
            {
                WalkEntryAction::Continue => continue,
                WalkEntryAction::Break => break,
                WalkEntryAction::Entry(entry) => entry,
            };

        let file_type = entry.file_type();
        if !(file_type.is_file() || file_type.is_symlink()) {
            continue;
        }
        if diag.scanned_files >= max_walk_files {
            diag.mark_limit_reached(ScanLimitReason::Files);
            break;
        }
        diag.scanned_files = diag.scanned_files.saturating_add(1);

        let Some(file) = traversal_file_from_entry(ctx, root_id, root_path, &entry, &mut diag)?
        else {
            continue;
        };

        match on_file(file, &mut diag)? {
            std::ops::ControlFlow::Continue(()) => {}
            std::ops::ControlFlow::Break(()) => break,
        }
    }

    Ok(diag)
}
