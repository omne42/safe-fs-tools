use std::path::{Path, PathBuf};

#[cfg(any(feature = "glob", feature = "grep"))]
use std::fs;
#[cfg(any(feature = "glob", feature = "grep"))]
use std::time::Instant;

#[cfg(any(feature = "glob", feature = "grep"))]
use globset::GlobSet;

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
pub(super) fn walk_traversal_files(
    ctx: &Context,
    root_id: &str,
    root_path: &Path,
    walk_root: &Path,
    options: TraversalWalkOptions,
    started: &Instant,
    on_file: impl FnMut(TraversalFile, &mut TraversalDiagnostics) -> Result<std::ops::ControlFlow<()>>,
) -> Result<TraversalDiagnostics> {
    walk::walk_traversal_files(
        ctx, root_id, root_path, walk_root, options, started, on_file,
    )
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

        if !path.as_os_str().encode_wide().any(|unit| unit == BACKSLASH) {
            return glob.is_match(path);
        }
        let normalized_wide: Vec<u16> = path
            .as_os_str()
            .encode_wide()
            .map(|unit| if unit == BACKSLASH { SLASH } else { unit })
            .collect();
        let normalized = OsString::from_wide(&normalized_wide);
        return glob.is_match(Path::new(&normalized));
    }
    #[cfg(not(windows))]
    {
        glob.is_match(path)
    }
}

#[cfg(any(feature = "glob", feature = "grep"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum TraversalOpenMode {
    None,
    ReadFile,
}

#[cfg(any(feature = "glob", feature = "grep"))]
#[derive(Debug, Clone, Copy)]
pub(super) struct TraversalWalkOptions {
    pub(super) open_mode: TraversalOpenMode,
    pub(super) max_walk: Option<std::time::Duration>,
}

#[cfg(any(feature = "glob", feature = "grep"))]
#[derive(Debug, Default, Clone)]
pub(super) struct TraversalDiagnostics {
    scanned_files: u64,
    scanned_entries: u64,
    scan_limit_reason: Option<ScanLimitReason>,
    skipped_walk_errors: u64,
    skipped_io_errors: u64,
    skipped_dangling_symlink_targets: u64,
}

#[cfg(any(feature = "glob", feature = "grep"))]
impl TraversalDiagnostics {
    // Legacy alias kept for response compatibility; use `scan_limit_reached` as the
    // canonical boolean source for limit truncation semantics.
    pub(super) fn truncated(&self) -> bool {
        self.scan_limit_reached()
    }

    pub(super) fn scanned_files(&self) -> u64 {
        self.scanned_files
    }

    pub(super) fn scanned_entries(&self) -> u64 {
        self.scanned_entries
    }

    pub(super) fn scan_limit_reached(&self) -> bool {
        self.scan_limit_reason.is_some()
    }

    pub(super) fn scan_limit_reason(&self) -> Option<ScanLimitReason> {
        self.scan_limit_reason
    }

    pub(super) fn skipped_walk_errors(&self) -> u64 {
        self.skipped_walk_errors
    }

    pub(super) fn skipped_io_errors(&self) -> u64 {
        self.skipped_io_errors
    }

    pub(super) fn skipped_dangling_symlink_targets(&self) -> u64 {
        self.skipped_dangling_symlink_targets
    }

    // Records the first observed limit-hit reason; subsequent limit reasons are ignored.
    pub(super) fn mark_limit_reached(&mut self, reason: ScanLimitReason) {
        if self.scan_limit_reason.is_none() {
            self.scan_limit_reason = Some(reason);
        }
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
}

#[cfg(any(feature = "glob", feature = "grep"))]
pub(super) struct TraversalFile {
    pub(super) path: PathBuf,
    pub(super) relative_path: PathBuf,
    pub(super) opened_file: Option<(fs::File, fs::Metadata)>,
}

#[cfg(all(any(feature = "glob", feature = "grep"), test))]
mod tests {
    use super::*;

    #[test]
    fn mark_limit_reached_keeps_first_reason() {
        let mut diag = TraversalDiagnostics::default();
        diag.mark_limit_reached(ScanLimitReason::Entries);
        diag.mark_limit_reached(ScanLimitReason::Time);

        assert!(diag.scan_limit_reached());
        assert!(diag.truncated());
        assert_eq!(diag.scan_limit_reason(), Some(ScanLimitReason::Entries));
    }
}
