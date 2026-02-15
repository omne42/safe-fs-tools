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
use std::io::{BufRead, Read};

#[cfg(feature = "grep")]
use std::time::{Duration, Instant};

#[cfg(feature = "grep")]
use super::traversal::{
    TRAVERSAL_GLOB_PROBE_NAME, TraversalDiagnostics, TraversalOpenMode, TraversalWalkOptions,
    compile_glob, derive_safe_traversal_prefix, elapsed_ms, globset_is_match, walk_traversal_files,
};

#[cfg(feature = "grep")]
#[derive(Debug, Default, Clone, Copy)]
struct GrepSkipCounters {
    skipped_too_large_files: u64,
    skipped_non_utf8_files: u64,
}

#[cfg(feature = "grep")]
fn initial_match_capacity(max_results: usize) -> usize {
    const MAX_INITIAL_MATCH_CAPACITY: usize = 1024;
    max_results.min(MAX_INITIAL_MATCH_CAPACITY)
}

#[cfg(feature = "grep")]
fn build_grep_response(
    mut matches: Vec<GrepMatch>,
    diag: TraversalDiagnostics,
    counters: GrepSkipCounters,
    started: &Instant,
) -> GrepResponse {
    if matches.len() > 1 {
        matches.sort_by(|a, b| a.path.cmp(&b.path).then_with(|| a.line.cmp(&b.line)));
    }
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

#[cfg(feature = "grep")]
fn maybe_shrink_line_buffer(line_buf: &mut Vec<u8>, max_line_bytes: usize) {
    const DEFAULT_RETAINED_CAPACITY: usize = 8 * 1024;
    const MAX_RETAINED_CAPACITY: usize = 64 * 1024;
    const SHRINK_FACTOR: usize = 4;

    let retained_capacity = max_line_bytes.clamp(DEFAULT_RETAINED_CAPACITY, MAX_RETAINED_CAPACITY);
    if line_buf.capacity() > retained_capacity.saturating_mul(SHRINK_FACTOR) {
        line_buf.clear();
        line_buf.shrink_to(retained_capacity);
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
    let mut matches =
        Vec::<GrepMatch>::with_capacity(initial_match_capacity(ctx.policy.limits.max_results));
    let mut counters = GrepSkipCounters::default();
    let mut diag = TraversalDiagnostics::default();
    let has_redact_regexes = ctx.redactor.has_redact_regexes();
    let file_glob = request.glob.as_deref().map(compile_glob).transpose()?;
    let traversal_open_mode = if file_glob.is_some() {
        TraversalOpenMode::None
    } else {
        TraversalOpenMode::ReadFile
    };
    let walk_root = match request
        .glob
        .as_deref()
        .and_then(derive_safe_traversal_prefix)
    {
        Some(prefix) => {
            let walk_root = root_path.join(&prefix);
            let prefix_is_dir = walk_root.is_dir();
            let prefix_denied_or_skipped =
                ctx.redactor.is_path_denied(&prefix) || ctx.is_traversal_path_skipped(&prefix);
            let probe_denied_or_skipped = if prefix_is_dir {
                let probe = prefix.join(TRAVERSAL_GLOB_PROBE_NAME);
                ctx.redactor.is_path_denied(&probe) || ctx.is_traversal_path_skipped(&probe)
            } else {
                false
            };
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
        TraversalWalkOptions {
            open_mode: traversal_open_mode,
            max_walk,
        },
        &started,
        |file, diag| {
            let super::traversal::TraversalFile {
                path,
                relative_path,
                opened_file,
            } = file;

            if let Some(glob) = &file_glob
                && !globset_is_match(glob, &relative_path)
            {
                return Ok(std::ops::ControlFlow::Continue(()));
            }

            let (file, meta) = match opened_file {
                Some(opened) => opened,
                None => match super::io::open_regular_file_for_read(&path, &relative_path) {
                    Ok(opened) => opened,
                    Err(Error::IoPath { .. }) | Err(Error::Io(_)) => {
                        diag.inc_skipped_io_errors();
                        return Ok(std::ops::ControlFlow::Continue(()));
                    }
                    Err(err) => return Err(err),
                },
            };
            if meta.len() > ctx.policy.limits.max_read_bytes {
                counters.skipped_too_large_files =
                    counters.skipped_too_large_files.saturating_add(1);
                return Ok(std::ops::ControlFlow::Continue(()));
            }

            let limit = ctx.policy.limits.max_read_bytes.saturating_add(1);
            let mut reader = std::io::BufReader::new(file.take(limit));
            let mut line_buf = Vec::<u8>::new();
            let mut scanned_bytes = 0_u64;
            let mut line_no = 0_u64;
            let file_match_start = matches.len();
            let mut owned_relative_path = relative_path;
            let mut repeated_match_path = None::<PathBuf>;
            loop {
                line_buf.clear();
                let n = match reader.read_until(b'\n', &mut line_buf) {
                    Ok(n) => n,
                    Err(_) => {
                        matches.truncate(file_match_start);
                        diag.inc_skipped_io_errors();
                        return Ok(std::ops::ControlFlow::Continue(()));
                    }
                };
                if n == 0 {
                    break;
                }

                scanned_bytes = scanned_bytes.saturating_add(n as u64);
                if scanned_bytes > ctx.policy.limits.max_read_bytes {
                    matches.truncate(file_match_start);
                    counters.skipped_too_large_files =
                        counters.skipped_too_large_files.saturating_add(1);
                    return Ok(std::ops::ControlFlow::Continue(()));
                }

                line_no = line_no.saturating_add(1);
                if line_buf.last() == Some(&b'\n') {
                    let _ = line_buf.pop();
                }
                if line_buf.last() == Some(&b'\r') {
                    let _ = line_buf.pop();
                }
                let line = match std::str::from_utf8(&line_buf) {
                    Ok(line) => line,
                    Err(_) => {
                        matches.truncate(file_match_start);
                        counters.skipped_non_utf8_files =
                            counters.skipped_non_utf8_files.saturating_add(1);
                        return Ok(std::ops::ControlFlow::Continue(()));
                    }
                };
                let ok = regex.as_ref().map_or_else(
                    || line.contains(&request.query),
                    |regex| regex.is_match(line),
                );
                if !ok {
                    maybe_shrink_line_buffer(&mut line_buf, max_line_bytes);
                    continue;
                }
                if matches.len() >= ctx.policy.limits.max_results {
                    diag.mark_limit_reached(ScanLimitReason::Results);
                    return Ok(std::ops::ControlFlow::Break(()));
                }
                let (text, line_truncated) = if has_redact_regexes {
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
                    (text, line_truncated)
                } else {
                    let line_truncated = line.len() > max_line_bytes;
                    let mut end = line.len().min(max_line_bytes);
                    while end > 0 && !line.is_char_boundary(end) {
                        end = end.saturating_sub(1);
                    }
                    (line[..end].to_string(), line_truncated)
                };

                let path = match &repeated_match_path {
                    Some(path) => path.clone(),
                    None => {
                        let path = std::mem::take(&mut owned_relative_path);
                        repeated_match_path = Some(path.clone());
                        path
                    }
                };
                matches.push(GrepMatch {
                    path,
                    line: line_no,
                    text,
                    line_truncated,
                });
                maybe_shrink_line_buffer(&mut line_buf, max_line_bytes);
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
