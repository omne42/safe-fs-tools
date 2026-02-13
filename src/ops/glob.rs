use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

use super::{Context, ScanLimitReason};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GlobRequest {
    pub root_id: String,
    pub pattern: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GlobResponse {
    pub matches: Vec<PathBuf>,
    pub truncated: bool,
    #[serde(default)]
    pub scanned_files: u64,
    #[serde(default)]
    pub scan_limit_reached: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scan_limit_reason: Option<ScanLimitReason>,
    /// Elapsed wall-clock time spent in this call (milliseconds).
    #[serde(default)]
    pub elapsed_ms: u64,
    #[serde(default)]
    pub scanned_entries: u64,
    #[serde(default)]
    pub skipped_walk_errors: u64,
    #[serde(default)]
    pub skipped_io_errors: u64,
    #[serde(default)]
    pub skipped_dangling_symlink_targets: u64,
}

#[cfg(feature = "glob")]
use std::time::{Duration, Instant};

#[cfg(feature = "glob")]
use super::traversal::{
    TRAVERSAL_GLOB_PROBE_NAME, TraversalDiagnostics, compile_glob, derive_safe_traversal_prefix,
    elapsed_ms, globset_is_match, walk_traversal_files,
};

#[cfg(not(feature = "glob"))]
pub fn glob_paths(ctx: &Context, request: GlobRequest) -> Result<GlobResponse> {
    let _ = ctx;
    let _ = request;
    Err(Error::NotPermitted(
        "glob is not supported: crate feature 'glob' is disabled".to_string(),
    ))
}

#[cfg(feature = "glob")]
pub fn glob_paths(ctx: &Context, request: GlobRequest) -> Result<GlobResponse> {
    if !ctx.policy.permissions.glob {
        return Err(Error::NotPermitted(
            "glob is disabled by policy".to_string(),
        ));
    }
    let started = Instant::now();
    let max_walk = ctx.policy.limits.max_walk_ms.map(Duration::from_millis);
    let root_path = ctx.canonical_root(&request.root_id)?.clone();
    let matcher = compile_glob(&request.pattern)?;

    let mut matches = Vec::<PathBuf>::new();
    let mut diag = TraversalDiagnostics::default();
    let walk_root = match derive_safe_traversal_prefix(&request.pattern) {
        Some(prefix) => {
            let probe = prefix.join(TRAVERSAL_GLOB_PROBE_NAME);
            if ctx.redactor.is_path_denied(&prefix)
                || ctx.redactor.is_path_denied(&probe)
                || ctx.is_traversal_path_skipped(&prefix)
                || ctx.is_traversal_path_skipped(&probe)
            {
                return Ok(GlobResponse {
                    matches,
                    truncated: diag.truncated,
                    scanned_files: diag.scanned_files,
                    scan_limit_reached: diag.scan_limit_reached,
                    scan_limit_reason: diag.scan_limit_reason,
                    elapsed_ms: elapsed_ms(&started),
                    scanned_entries: diag.scanned_entries,
                    skipped_walk_errors: diag.skipped_walk_errors,
                    skipped_io_errors: diag.skipped_io_errors,
                    skipped_dangling_symlink_targets: diag.skipped_dangling_symlink_targets,
                });
            }
            root_path.join(prefix)
        }
        None => root_path.clone(),
    };
    diag = match walk_traversal_files(
        ctx,
        &request.root_id,
        &root_path,
        &walk_root,
        &started,
        max_walk,
        |file, diag| {
            if globset_is_match(&matcher, &file.relative_path) {
                if matches.len() >= ctx.policy.limits.max_results {
                    diag.truncated = true;
                    diag.scan_limit_reached = true;
                    diag.scan_limit_reason = Some(ScanLimitReason::Results);
                    return Ok(std::ops::ControlFlow::Break(()));
                }
                matches.push(file.relative_path);
            }
            Ok(std::ops::ControlFlow::Continue(()))
        },
    ) {
        Ok(diag) => diag,
        Err(Error::WalkDirRoot { source, .. }) if source.kind() == std::io::ErrorKind::NotFound => {
            return Ok(GlobResponse {
                matches,
                truncated: diag.truncated,
                scanned_files: diag.scanned_files,
                scan_limit_reached: diag.scan_limit_reached,
                scan_limit_reason: diag.scan_limit_reason,
                elapsed_ms: elapsed_ms(&started),
                scanned_entries: diag.scanned_entries,
                skipped_walk_errors: diag.skipped_walk_errors,
                skipped_io_errors: diag.skipped_io_errors,
                skipped_dangling_symlink_targets: diag.skipped_dangling_symlink_targets,
            });
        }
        Err(err) => return Err(err),
    };

    matches.sort();
    Ok(GlobResponse {
        matches,
        truncated: diag.truncated,
        scanned_files: diag.scanned_files,
        scan_limit_reached: diag.scan_limit_reached,
        scan_limit_reason: diag.scan_limit_reason,
        elapsed_ms: elapsed_ms(&started),
        scanned_entries: diag.scanned_entries,
        skipped_walk_errors: diag.skipped_walk_errors,
        skipped_io_errors: diag.skipped_io_errors,
        skipped_dangling_symlink_targets: diag.skipped_dangling_symlink_targets,
    })
}
