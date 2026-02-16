use std::path::{Path, PathBuf};
use std::time::Instant;

use walkdir::WalkDir;

use crate::error::{Error, Result};

use super::super::{Context, ScanLimitReason};
use super::{
    TRAVERSAL_GLOB_PROBE_NAME, TraversalDiagnostics, TraversalFile, TraversalOpenMode,
    TraversalWalkOptions,
};

fn resolve_walk_root_for_traversal(
    ctx: &Context,
    root_id: &str,
    root_path: &Path,
    walk_root: &Path,
) -> Result<PathBuf> {
    let canonical_root = ctx.canonical_root(root_id)?;
    let relative_walk_root = crate::path_utils::strip_prefix_case_insensitive(walk_root, root_path)
        .ok_or_else(|| {
            Error::InvalidPath("derived traversal root escapes selected root".to_string())
        })?;
    let relative_walk_root = if relative_walk_root.as_os_str().is_empty() {
        PathBuf::from(".")
    } else {
        relative_walk_root
    };
    let requested_walk_root = canonical_root.join(&relative_walk_root);

    match ctx.canonical_path_in_root(root_id, &relative_walk_root) {
        Ok((canonical, _, _)) => {
            // Preserve alias paths for file/symlink roots so pattern matching sees the
            // requested path (e.g. "link.txt"), not only the canonical target path.
            match std::fs::symlink_metadata(&requested_walk_root) {
                Ok(meta) if !meta.is_dir() => Ok(requested_walk_root),
                Ok(_) => Ok(canonical),
                Err(_) => Ok(canonical),
            }
        }
        Err(Error::IoPath {
            op: "canonicalize",
            source,
            ..
        }) if source.kind() == std::io::ErrorKind::NotFound => {
            Ok(canonical_root.join(relative_walk_root))
        }
        Err(Error::OutsideRoot { .. }) | Err(Error::SecretPathDenied(_)) => Err(
            Error::InvalidPath("derived traversal root escapes selected root".to_string()),
        ),
        Err(err) => Err(err),
    }
}

fn walkdir_root_error(root_path: &Path, walk_root: &Path, err: walkdir::Error) -> Error {
    let relative = crate::path_utils::strip_prefix_case_insensitive(walk_root, root_path)
        .filter(|relative| !relative.as_os_str().is_empty())
        .unwrap_or_else(|| PathBuf::from("."));

    let source = err
        .io_error()
        .and_then(|io| {
            io.raw_os_error()
                .map(std::io::Error::from_raw_os_error)
                .or_else(|| Some(std::io::Error::from(io.kind())))
        })
        .unwrap_or_else(|| {
            std::io::Error::other("walkdir root traversal failed without io error detail")
        });

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
    let has_path_filters = ctx.has_traversal_path_filters();
    WalkDir::new(walk_root)
        .follow_root_links(false)
        .follow_links(false)
        .sort_by_file_name()
        .into_iter()
        .filter_entry(move |entry| {
            if entry.depth() == 0 {
                return true;
            }
            if !has_path_filters {
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
                            debug_assert!(
                                crate::path_utils::strip_prefix_case_insensitive(
                                    entry.path(),
                                    root_path,
                                )
                                .is_some(),
                                "walkdir yielded a path outside the selected root"
                            );
                            return false;
                        }
                    }
                    #[cfg(not(windows))]
                    {
                        debug_assert!(
                            crate::path_utils::strip_prefix_case_insensitive(
                                entry.path(),
                                root_path,
                            )
                            .is_some(),
                            "walkdir yielded a path outside the selected root"
                        );
                        return false;
                    }
                }
            };

            if ctx.redactor.is_path_denied(relative.as_ref())
                || ctx.is_traversal_path_skipped(relative.as_ref())
            {
                return false;
            }
            if is_dir {
                let probe = relative.as_ref().join(TRAVERSAL_GLOB_PROBE_NAME);
                if ctx.redactor.is_path_denied(&probe) || ctx.is_traversal_path_skipped(&probe) {
                    return false;
                }
            }
            true
        })
}

#[derive(Debug)]
enum WalkEntryAction {
    Continue,
    Break,
    Entry(walkdir::DirEntry),
}

fn consume_walk_entry(diag: &mut TraversalDiagnostics, max_walk_entries: u64) -> bool {
    if diag.scanned_entries() >= max_walk_entries {
        diag.mark_limit_reached(ScanLimitReason::Entries);
        return false;
    }
    diag.inc_scanned_entries();
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
            diag.inc_skipped_walk_errors();
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
        diag.inc_skipped_walk_errors();
    }
    relative
}

fn resolve_entry_traversal_file(
    ctx: &Context,
    root_id: &str,
    relative: PathBuf,
    is_symlink: bool,
    open_mode: TraversalOpenMode,
    diag: &mut TraversalDiagnostics,
) -> Result<Option<TraversalFile>> {
    #[derive(Clone, Copy)]
    enum ResolvePhase {
        Canonicalize,
        Open,
    }

    fn classify_resolve_error(
        err: Error,
        phase: ResolvePhase,
        is_symlink: bool,
        diag: &mut TraversalDiagnostics,
    ) -> Result<()> {
        match err {
            Error::OutsideRoot { .. } | Error::SecretPathDenied(_) => {
                diag.inc_skipped_walk_errors();
                Ok(())
            }
            Error::IoPath {
                op: "canonicalize",
                source,
                ..
            } if matches!(phase, ResolvePhase::Canonicalize)
                && source.kind() == std::io::ErrorKind::NotFound =>
            {
                if is_symlink {
                    diag.inc_skipped_dangling_symlink_targets();
                } else {
                    diag.inc_skipped_io_errors();
                }
                Ok(())
            }
            Error::IoPath {
                source, op: "open", ..
            } if matches!(phase, ResolvePhase::Open)
                && source.kind() == std::io::ErrorKind::NotFound =>
            {
                if is_symlink {
                    diag.inc_skipped_dangling_symlink_targets();
                } else {
                    diag.inc_skipped_io_errors();
                }
                Ok(())
            }
            Error::InvalidPath(_) if matches!(phase, ResolvePhase::Open) => {
                diag.inc_skipped_io_errors();
                Ok(())
            }
            Error::IoPath { .. } | Error::Io(_) => {
                diag.inc_skipped_io_errors();
                Ok(())
            }
            err => Err(err),
        }
    }

    let (canonical, _canonical_relative, _requested_path) =
        match ctx.canonical_path_in_root(root_id, &relative) {
            Ok(ok) => ok,
            Err(err) => {
                classify_resolve_error(err, ResolvePhase::Canonicalize, is_symlink, diag)?;
                return Ok(None);
            }
        };

    let opened_file = if matches!(open_mode, TraversalOpenMode::ReadFile) {
        match super::super::io::open_regular_file_for_read(&canonical, &relative) {
            Ok(opened_file) => Some(opened_file),
            Err(err) => {
                classify_resolve_error(err, ResolvePhase::Open, is_symlink, diag)?;
                return Ok(None);
            }
        }
    } else {
        None
    };

    Ok(Some(TraversalFile {
        path: canonical,
        relative_path: relative,
        opened_file,
    }))
}

fn traversal_file_from_entry(
    ctx: &Context,
    root_id: &str,
    root_path: &Path,
    entry: &walkdir::DirEntry,
    open_mode: TraversalOpenMode,
    diag: &mut TraversalDiagnostics,
) -> Result<Option<TraversalFile>> {
    let Some(relative) = relative_from_walk_entry(entry, root_path, diag) else {
        return Ok(None);
    };
    if ctx.redactor.is_path_denied(&relative) {
        return Ok(None);
    }

    resolve_entry_traversal_file(
        ctx,
        root_id,
        relative,
        entry.file_type().is_symlink(),
        open_mode,
        diag,
    )
}

pub(super) fn walk_traversal_files(
    ctx: &Context,
    root_id: &str,
    root_path: &Path,
    walk_root: &Path,
    options: TraversalWalkOptions,
    started: &Instant,
    mut on_file: impl FnMut(
        TraversalFile,
        &mut TraversalDiagnostics,
    ) -> Result<std::ops::ControlFlow<()>>,
) -> Result<TraversalDiagnostics> {
    let walk_root = resolve_walk_root_for_traversal(ctx, root_id, root_path, walk_root)?;

    let mut diag = TraversalDiagnostics::default();
    let max_walk_entries = u64::try_from(ctx.policy.limits.max_walk_entries).unwrap_or(u64::MAX);
    let max_walk_files = u64::try_from(ctx.policy.limits.max_walk_files).unwrap_or(u64::MAX);

    for entry in walkdir_traversal_iter(ctx, root_path, &walk_root) {
        if options
            .max_walk
            .is_some_and(|limit| started.elapsed() >= limit)
        {
            diag.mark_limit_reached(ScanLimitReason::Time);
            break;
        }

        let entry = match classify_walkdir_entry(
            entry,
            root_path,
            &walk_root,
            &mut diag,
            max_walk_entries,
        )? {
            WalkEntryAction::Continue => continue,
            WalkEntryAction::Break => break,
            WalkEntryAction::Entry(entry) => entry,
        };

        let file_type = entry.file_type();
        if !(file_type.is_file() || file_type.is_symlink()) {
            continue;
        }
        if diag.scanned_files() >= max_walk_files {
            diag.mark_limit_reached(ScanLimitReason::Files);
            break;
        }
        diag.inc_scanned_files();

        let Some(file) = traversal_file_from_entry(
            ctx,
            root_id,
            root_path,
            &entry,
            options.open_mode,
            &mut diag,
        )?
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
