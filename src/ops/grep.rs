use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

use super::{Context, ScanLimitReason};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GrepRequest {
    pub root_id: String,
    pub query: String,
    #[serde(default)]
    pub regex: bool,
    #[serde(default)]
    pub glob: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GrepMatch {
    pub path: PathBuf,
    pub line: u64,
    pub text: String,
    #[serde(default)]
    pub line_truncated: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GrepResponse {
    pub matches: Vec<GrepMatch>,
    pub truncated: bool,
    #[serde(default)]
    pub skipped_too_large_files: u64,
    #[serde(default)]
    pub skipped_non_utf8_files: u64,
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

#[cfg(feature = "grep")]
use std::time::{Duration, Instant};

#[cfg(feature = "grep")]
use super::traversal::{
    TRAVERSAL_GLOB_PROBE_NAME, compile_glob, derive_safe_traversal_prefix, elapsed_ms,
    globset_is_match, walk_traversal_files,
};

#[cfg(not(feature = "grep"))]
pub fn grep(ctx: &Context, request: GrepRequest) -> Result<GrepResponse> {
    let _ = ctx;
    let _ = request;
    Err(Error::NotPermitted(
        "grep is not supported: crate feature 'grep' is disabled".to_string(),
    ))
}

#[cfg(feature = "grep")]
pub fn grep(ctx: &Context, request: GrepRequest) -> Result<GrepResponse> {
    if !ctx.policy.permissions.grep {
        return Err(Error::NotPermitted(
            "grep is disabled by policy".to_string(),
        ));
    }
    let started = Instant::now();
    let max_walk = ctx.policy.limits.max_walk_ms.map(Duration::from_millis);
    let root_path = ctx.canonical_root(&request.root_id)?.clone();
    let walk_root = match request
        .glob
        .as_deref()
        .and_then(derive_safe_traversal_prefix)
    {
        Some(prefix) => {
            let probe = prefix.join(TRAVERSAL_GLOB_PROBE_NAME);
            if ctx.redactor.is_path_denied(&prefix)
                || ctx.redactor.is_path_denied(&probe)
                || ctx.is_traversal_path_skipped(&prefix)
                || ctx.is_traversal_path_skipped(&probe)
            {
                return Ok(GrepResponse {
                    matches: Vec::new(),
                    truncated: false,
                    skipped_too_large_files: 0,
                    skipped_non_utf8_files: 0,
                    scanned_files: 0,
                    scan_limit_reached: false,
                    scan_limit_reason: None,
                    elapsed_ms: elapsed_ms(&started),
                    scanned_entries: 0,
                    skipped_walk_errors: 0,
                    skipped_io_errors: 0,
                    skipped_dangling_symlink_targets: 0,
                });
            }
            root_path.join(prefix)
        }
        None => root_path.clone(),
    };
    if !walk_root.exists() {
        return Ok(GrepResponse {
            matches: Vec::new(),
            truncated: false,
            skipped_too_large_files: 0,
            skipped_non_utf8_files: 0,
            scanned_files: 0,
            scan_limit_reached: false,
            scan_limit_reason: None,
            elapsed_ms: elapsed_ms(&started),
            scanned_entries: 0,
            skipped_walk_errors: 0,
            skipped_io_errors: 0,
            skipped_dangling_symlink_targets: 0,
        });
    }

    let file_glob = request.glob.as_deref().map(compile_glob).transpose()?;

    let regex = if request.regex {
        Some(regex::Regex::new(&request.query).map_err(|err| {
            Error::InvalidRegex(format!("invalid grep regex {:?}: {err}", request.query))
        })?)
    } else {
        None
    };

    let mut matches = Vec::<GrepMatch>::new();
    let mut skipped_too_large_files: u64 = 0;
    let mut skipped_non_utf8_files: u64 = 0;

    let diag = walk_traversal_files(
        ctx,
        &request.root_id,
        &root_path,
        &walk_root,
        &started,
        max_walk,
        |file, diag| {
            if let Some(glob) = &file_glob
                && !globset_is_match(glob, &file.relative_path)
            {
                return Ok(std::ops::ControlFlow::Continue(()));
            }

            let bytes = match super::io::read_bytes_limited(
                &file.path,
                &file.relative_path,
                ctx.policy.limits.max_read_bytes,
            ) {
                Ok(bytes) => bytes,
                Err(Error::FileTooLarge { .. }) => {
                    skipped_too_large_files = skipped_too_large_files.saturating_add(1);
                    return Ok(std::ops::ControlFlow::Continue(()));
                }
                Err(Error::IoPath { .. }) | Err(Error::Io(_)) => {
                    diag.skipped_io_errors = diag.skipped_io_errors.saturating_add(1);
                    return Ok(std::ops::ControlFlow::Continue(()));
                }
                Err(err) => return Err(err),
            };
            let content = match std::str::from_utf8(&bytes) {
                Ok(content) => content,
                Err(_) => {
                    skipped_non_utf8_files = skipped_non_utf8_files.saturating_add(1);
                    return Ok(std::ops::ControlFlow::Continue(()));
                }
            };

            for (idx, line) in content.lines().enumerate() {
                let ok = match &regex {
                    Some(regex) => regex.is_match(line),
                    None => line.contains(&request.query),
                };
                if !ok {
                    continue;
                }
                let line_truncated = line.len() > ctx.policy.limits.max_line_bytes;
                let mut end = line.len().min(ctx.policy.limits.max_line_bytes);
                while end > 0 && !line.is_char_boundary(end) {
                    end = end.saturating_sub(1);
                }
                let text = line[..end].to_string();
                let text = ctx.redactor.redact_text(&text);
                matches.push(GrepMatch {
                    path: file.relative_path.clone(),
                    line: idx.saturating_add(1) as u64,
                    text,
                    line_truncated,
                });
                if matches.len() >= ctx.policy.limits.max_results {
                    diag.truncated = true;
                    diag.scan_limit_reached = true;
                    diag.scan_limit_reason = Some(ScanLimitReason::Results);
                    return Ok(std::ops::ControlFlow::Break(()));
                }
            }

            Ok(std::ops::ControlFlow::Continue(()))
        },
    )?;

    matches.sort_by(|a, b| a.path.cmp(&b.path).then_with(|| a.line.cmp(&b.line)));
    Ok(GrepResponse {
        matches,
        truncated: diag.truncated,
        skipped_too_large_files,
        skipped_non_utf8_files,
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
