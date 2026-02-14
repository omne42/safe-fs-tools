use std::io::{BufRead, Read};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

use super::Context;

#[derive(Debug, Clone, Copy)]
enum ReadMode {
    Full,
    LineRange { start_line: u64, end_line: u64 },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReadRequest {
    pub root_id: String,
    pub path: PathBuf,
    #[serde(default)]
    pub start_line: Option<u64>,
    #[serde(default)]
    pub end_line: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReadResponse {
    pub path: PathBuf,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requested_path: Option<PathBuf>,
    /// Always `false`: `read` fails instead of truncating.
    pub truncated: bool,
    /// Number of bytes scanned from disk before returning.
    pub bytes_read: u64,
    pub content: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub start_line: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub end_line: Option<u64>,
}

pub fn read_file(ctx: &Context, request: ReadRequest) -> Result<ReadResponse> {
    if !ctx.policy.permissions.read {
        return Err(Error::NotPermitted(
            "read is disabled by policy".to_string(),
        ));
    }

    let mode = parse_read_mode(request.start_line, request.end_line)?;

    let (path, relative, requested_path) =
        ctx.canonical_path_in_root(&request.root_id, &request.path)?;

    let (bytes_read, content) = match mode {
        ReadMode::Full => read_full(&path, &relative, ctx)?,
        ReadMode::LineRange {
            start_line,
            end_line,
        } => read_line_range(&path, &relative, ctx, start_line, end_line)?,
    };

    let content = ctx.redactor.redact_text(&content);

    Ok(ReadResponse {
        path: relative,
        requested_path: Some(requested_path),
        truncated: false,
        bytes_read,
        content,
        start_line: request.start_line,
        end_line: request.end_line,
    })
}

fn parse_read_mode(start_line: Option<u64>, end_line: Option<u64>) -> Result<ReadMode> {
    match (start_line, end_line) {
        (None, None) => Ok(ReadMode::Full),
        (Some(start_line), Some(end_line)) => {
            if start_line == 0 || end_line == 0 || start_line > end_line {
                return Err(invalid_line_range(format!(
                    "invalid line range: {}..{}",
                    start_line, end_line
                )));
            }
            Ok(ReadMode::LineRange {
                start_line,
                end_line,
            })
        }
        _ => Err(invalid_line_range(
            "invalid line range: start_line and end_line must be provided together".to_string(),
        )),
    }
}

fn read_full(path: &std::path::Path, relative: &Path, ctx: &Context) -> Result<(u64, String)> {
    let bytes = super::io::read_bytes_limited(path, relative, ctx.policy.limits.max_read_bytes)?;
    let bytes_read = usize_to_u64(bytes.len(), relative, "file size")?;
    let content =
        String::from_utf8(bytes).map_err(|err| Error::invalid_utf8(relative.to_path_buf(), err))?;
    Ok((bytes_read, content))
}

fn read_line_range(
    path: &std::path::Path,
    relative: &Path,
    ctx: &Context,
    start_line: u64,
    end_line: u64,
) -> Result<(u64, String)> {
    let (file, meta) = super::io::open_regular_file_for_read(path, relative)?;
    let file_size_bytes = meta.len();
    let limit = ctx.policy.limits.max_read_bytes.saturating_add(1);
    let mut reader = std::io::BufReader::new(file.take(limit));
    let mut out = Vec::<u8>::new();

    let mut scanned_bytes: u64 = 0;
    let mut current_line: u64 = 0;

    loop {
        let line_start = out.len();
        let n = reader
            .read_until(b'\n', &mut out)
            .map_err(|err| Error::io_path("read", relative, err))?;
        if n == 0 {
            break;
        }

        scanned_bytes = scanned_bytes.saturating_add(n as u64);
        if scanned_bytes > ctx.policy.limits.max_read_bytes {
            let size_bytes = file_size_bytes.max(scanned_bytes);
            return Err(Error::FileTooLarge {
                path: relative.to_path_buf(),
                size_bytes,
                max_bytes: ctx.policy.limits.max_read_bytes,
            });
        }

        current_line += 1;

        if current_line < start_line {
            out.truncate(line_start);
            continue;
        }
        if current_line == end_line {
            break;
        }
    }

    if current_line < end_line {
        return Err(invalid_line_range(format!(
            "invalid line range: {}..{} out of bounds (file has {} lines)",
            start_line, end_line, current_line
        )));
    }

    let bytes_read = scanned_bytes;
    let content =
        String::from_utf8(out).map_err(|err| Error::invalid_utf8(relative.to_path_buf(), err))?;
    Ok((bytes_read, content))
}

fn invalid_line_range(message: String) -> Error {
    Error::InvalidPath(format!("invalid argument: {message}"))
}

fn usize_to_u64(value: usize, path: &Path, context: &str) -> Result<u64> {
    u64::try_from(value).map_err(|_| {
        Error::InvalidPath(format!(
            "{}: {context} exceeds supported size",
            path.display()
        ))
    })
}
