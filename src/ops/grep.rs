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
    TRAVERSAL_GLOB_PROBE_NAME, TraversalDiagnostics, compile_glob, derive_safe_traversal_prefix,
    elapsed_ms, globset_is_match, walk_traversal_files,
};

#[cfg(feature = "grep")]
#[derive(Debug, Default, Clone, Copy)]
struct GrepSkipCounters {
    skipped_too_large_files: u64,
    skipped_non_utf8_files: u64,
}

#[cfg(feature = "grep")]
fn build_grep_response(
    mut matches: Vec<GrepMatch>,
    diag: TraversalDiagnostics,
    counters: GrepSkipCounters,
    started: &Instant,
) -> GrepResponse {
    matches.sort_by(|a, b| a.path.cmp(&b.path).then_with(|| a.line.cmp(&b.line)));
    GrepResponse {
        matches,
        truncated: diag.truncated(),
        skipped_too_large_files: counters.skipped_too_large_files,
        skipped_non_utf8_files: counters.skipped_non_utf8_files,
        scanned_files: diag.scanned_files(),
        scan_limit_reached: diag.scan_limit_reached(),
        scan_limit_reason: diag.scan_limit_reason(),
        elapsed_ms: elapsed_ms(started),
        scanned_entries: diag.scanned_entries(),
        skipped_walk_errors: diag.skipped_walk_errors(),
        skipped_io_errors: diag.skipped_io_errors(),
        skipped_dangling_symlink_targets: diag.skipped_dangling_symlink_targets(),
    }
}

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
    ctx.ensure_policy_permission(ctx.policy.permissions.grep, "grep")?;
    if request.query.trim().is_empty() {
        return Err(Error::InvalidPath(
            "grep query must not be empty".to_string(),
        ));
    }
    let started = Instant::now();
    let max_walk = ctx.policy.limits.max_walk_ms.map(Duration::from_millis);
    let max_line_bytes = ctx.policy.limits.max_line_bytes;
    let root_path = ctx.canonical_root(&request.root_id)?.to_path_buf();
    let mut matches = Vec::<GrepMatch>::new();
    let mut counters = GrepSkipCounters::default();
    let mut diag = TraversalDiagnostics::default();
    let file_glob = request.glob.as_deref().map(compile_glob).transpose()?;
    let walk_root = match request
        .glob
        .as_deref()
        .and_then(derive_safe_traversal_prefix)
    {
        Some(prefix) => {
            let walk_root = root_path.join(&prefix);
            let prefix_denied_or_skipped =
                ctx.redactor.is_path_denied(&prefix) || ctx.is_traversal_path_skipped(&prefix);
            let probe = prefix.join(TRAVERSAL_GLOB_PROBE_NAME);
            let probe_denied_or_skipped =
                ctx.redactor.is_path_denied(&probe) || ctx.is_traversal_path_skipped(&probe);
            if prefix_denied_or_skipped || probe_denied_or_skipped {
                return Ok(build_grep_response(matches, diag, counters, &started));
            }
            walk_root
        }
        None => root_path.clone(),
    };

    let regex = if request.regex {
        Some(
            regex::Regex::new(&request.query)
                .map_err(|err| Error::invalid_regex(request.query.clone(), err))?,
        )
    } else {
        None
    };

    diag = match walk_traversal_files(
        ctx,
        &request.root_id,
        &root_path,
        &walk_root,
        &started,
        max_walk,
        |file, diag| {
            let super::traversal::TraversalFile {
                path,
                relative_path,
            } = file;

            if let Some(glob) = &file_glob
                && !globset_is_match(glob, &relative_path)
            {
                return Ok(std::ops::ControlFlow::Continue(()));
            }

            let bytes = match super::io::read_bytes_limited(
                &path,
                &relative_path,
                ctx.policy.limits.max_read_bytes,
            ) {
                Ok(bytes) => bytes,
                Err(Error::FileTooLarge { .. }) => {
                    counters.skipped_too_large_files =
                        counters.skipped_too_large_files.saturating_add(1);
                    return Ok(std::ops::ControlFlow::Continue(()));
                }
                Err(Error::IoPath { .. }) | Err(Error::Io(_)) => {
                    diag.inc_skipped_io_errors();
                    return Ok(std::ops::ControlFlow::Continue(()));
                }
                Err(err) => return Err(err),
            };
            let content = match std::str::from_utf8(&bytes) {
                Ok(content) => content,
                Err(_) => {
                    counters.skipped_non_utf8_files =
                        counters.skipped_non_utf8_files.saturating_add(1);
                    return Ok(std::ops::ControlFlow::Continue(()));
                }
            };

            let mut first_match_index_in_output = None::<usize>;
            let mut owned_relative_path = Some(relative_path);
            let mut stop_for_results_limit = false;
            for (idx, line) in content.lines().enumerate() {
                let ok = regex.as_ref().map_or_else(
                    || line.contains(&request.query),
                    |regex| regex.is_match(line),
                );
                if !ok {
                    continue;
                }
                if matches.len() >= ctx.policy.limits.max_results {
                    diag.mark_limit_reached(ScanLimitReason::Results);
                    stop_for_results_limit = true;
                    break;
                }
                let redacted = ctx.redactor.redact_text_cow(line);
                let line_truncated = redacted.len() > max_line_bytes;
                let mut end = redacted.len().min(max_line_bytes);
                while end > 0 && !redacted.is_char_boundary(end) {
                    end = end.saturating_sub(1);
                }
                let text = match redacted {
                    std::borrow::Cow::Borrowed(redacted) => redacted[..end].to_string(),
                    std::borrow::Cow::Owned(redacted) => {
                        if end == redacted.len() {
                            redacted
                        } else {
                            redacted[..end].to_string()
                        }
                    }
                };

                let path = match first_match_index_in_output {
                    Some(first_idx) => matches
                        .get(first_idx)
                        .expect("first match index must point into output")
                        .path
                        .clone(),
                    None => owned_relative_path.take().expect("relative path present"),
                };
                matches.push(GrepMatch {
                    path,
                    line: idx.saturating_add(1) as u64,
                    text,
                    line_truncated,
                });
                if first_match_index_in_output.is_none() {
                    first_match_index_in_output = Some(matches.len().saturating_sub(1));
                }
            }

            if stop_for_results_limit {
                return Ok(std::ops::ControlFlow::Break(()));
            }
            Ok(std::ops::ControlFlow::Continue(()))
        },
    ) {
        Ok(diag) => diag,
        Err(Error::WalkDirRoot { path, source })
            if source.kind() == std::io::ErrorKind::NotFound
                && path.as_path() != std::path::Path::new(".") =>
        {
            return Ok(build_grep_response(matches, diag, counters, &started));
        }
        Err(err) => return Err(err),
    };

    Ok(build_grep_response(matches, diag, counters, &started))
}
