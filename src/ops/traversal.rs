use std::path::{Path, PathBuf};

#[cfg(any(feature = "glob", feature = "grep"))]
use std::time::Instant;

#[cfg(any(feature = "glob", feature = "grep"))]
use globset::GlobSet;

#[cfg(all(any(feature = "glob", feature = "grep"), test))]
use walkdir::DirEntry;

#[cfg(any(feature = "glob", feature = "grep"))]
use crate::error::Result;

#[cfg(any(feature = "glob", feature = "grep"))]
use super::super::Context;
#[cfg(any(feature = "glob", feature = "grep"))]
use super::ScanLimitReason;

#[cfg(any(feature = "glob", feature = "grep"))]
mod compile;
#[cfg(any(feature = "glob", feature = "grep"))]
mod walk;

#[cfg(any(feature = "glob", feature = "grep"))]
pub(super) fn compile_glob(pattern: &str) -> Result<GlobSet> {
    compile::compile_glob(pattern)
}

#[cfg(any(feature = "glob", feature = "grep"))]
pub(super) fn compile_traversal_skip_globs(patterns: &[String]) -> Result<Option<GlobSet>> {
    compile::compile_traversal_skip_globs(patterns)
}

#[cfg(any(feature = "glob", feature = "grep"))]
pub(super) fn derive_safe_traversal_prefix(pattern: &str) -> Option<PathBuf> {
    compile::derive_safe_traversal_prefix(pattern)
}

#[cfg(any(feature = "glob", feature = "grep"))]
#[cfg(test)]
pub(super) fn walkdir_traversal_iter<'a>(
    ctx: &'a Context,
    root_path: &'a Path,
    walk_root: &'a Path,
) -> impl Iterator<Item = walkdir::Result<DirEntry>> + 'a {
    walk::walkdir_traversal_iter(ctx, root_path, walk_root)
}

#[cfg(any(feature = "glob", feature = "grep"))]
pub(super) fn walk_traversal_files(
    ctx: &Context,
    root_id: &str,
    root_path: &Path,
    walk_root: &Path,
    started: &Instant,
    max_walk: Option<std::time::Duration>,
    on_file: impl FnMut(TraversalFile, &mut TraversalDiagnostics) -> Result<std::ops::ControlFlow<()>>,
) -> Result<TraversalDiagnostics> {
    let mut diag = walk::walk_traversal_files(
        ctx, root_id, root_path, walk_root, started, max_walk, on_file,
    )?;
    diag.normalize_limit_state();
    Ok(diag)
}

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
        use std::ffi::OsString;
        use std::os::windows::ffi::{OsStrExt, OsStringExt};

        const BACKSLASH: u16 = b'\\' as u16;
        const SLASH: u16 = b'/' as u16;

        let mut normalized_wide: Vec<u16> = path.as_os_str().encode_wide().collect();
        if !normalized_wide.contains(&BACKSLASH) {
            return glob.is_match(path);
        }
        for unit in &mut normalized_wide {
            if *unit == BACKSLASH {
                *unit = SLASH;
            }
        }
        let normalized = OsString::from_wide(&normalized_wide);
        return glob.is_match(Path::new(&normalized));
    }
    #[cfg(not(windows))]
    {
        glob.is_match(path)
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
impl TraversalDiagnostics {
    pub(super) fn mark_limit_reached(&mut self, reason: ScanLimitReason) {
        if self.scan_limit_reason.is_none() {
            self.scan_limit_reason = Some(reason);
        }
        self.normalize_limit_state();
    }

    pub(super) fn inc_scanned_files(&mut self) {
        self.scanned_files = self.scanned_files.saturating_add(1);
    }

    pub(super) fn inc_scanned_entries(&mut self) {
        self.scanned_entries = self.scanned_entries.saturating_add(1);
    }

    pub(super) fn inc_skipped_walk_errors(&mut self) {
        self.skipped_walk_errors = self.skipped_walk_errors.saturating_add(1);
    }

    pub(super) fn inc_skipped_io_errors(&mut self) {
        self.skipped_io_errors = self.skipped_io_errors.saturating_add(1);
    }

    pub(super) fn inc_skipped_dangling_symlink_targets(&mut self) {
        self.skipped_dangling_symlink_targets =
            self.skipped_dangling_symlink_targets.saturating_add(1);
    }

    pub(super) fn normalize_limit_state(&mut self) {
        self.scan_limit_reached = self.scan_limit_reason.is_some();
        if self.scan_limit_reached {
            self.truncated = true;
        }
    }
}

#[cfg(any(feature = "glob", feature = "grep"))]
pub(super) struct TraversalFile {
    pub(super) path: PathBuf,
    pub(super) relative_path: PathBuf,
}
