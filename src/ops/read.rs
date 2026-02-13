use std::io::{BufRead, Read};
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

use super::Context;

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

    let (path, relative, requested_path) =
        ctx.canonical_path_in_root(&request.root_id, &request.path)?;

    let (bytes_read, content) = match (request.start_line, request.end_line) {
        (None, None) => {
            let bytes =
                super::io::read_bytes_limited(&path, &relative, ctx.policy.limits.max_read_bytes)?;
            let bytes_read = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
            let content =
                String::from_utf8(bytes).map_err(|_| Error::InvalidUtf8(relative.clone()))?;
            (bytes_read, content)
        }
        (Some(start_line), Some(end_line)) => {
            if start_line == 0 || end_line == 0 || start_line > end_line {
                return Err(Error::InvalidPath(format!(
                    "invalid line range {}..{}",
                    start_line, end_line
                )));
            }

            let (file, meta) = super::io::open_regular_file_for_read(&path, &relative)?;
            let file_size_bytes = meta.len();
            let limit = ctx.policy.limits.max_read_bytes.saturating_add(1);
            let mut reader = std::io::BufReader::new(file.take(limit));
            let mut buf = Vec::<u8>::new();
            let mut out = Vec::<u8>::new();

            let mut scanned_bytes: u64 = 0;
            let mut current_line: u64 = 0;

            loop {
                buf.clear();
                let n = reader
                    .read_until(b'\n', &mut buf)
                    .map_err(|err| Error::io_path("read", &relative, err))?;
                if n == 0 {
                    break;
                }

                scanned_bytes = scanned_bytes.saturating_add(n as u64);
                if scanned_bytes > ctx.policy.limits.max_read_bytes {
                    let size_bytes = file_size_bytes.max(scanned_bytes);
                    return Err(Error::FileTooLarge {
                        path: relative.clone(),
                        size_bytes,
                        max_bytes: ctx.policy.limits.max_read_bytes,
                    });
                }

                current_line += 1;
                if current_line < start_line {
                    continue;
                }
                if current_line > end_line {
                    break;
                }

                out.extend_from_slice(&buf);
                if current_line == end_line {
                    break;
                }
            }

            if current_line < end_line {
                return Err(Error::InvalidPath(format!(
                    "line range {}..{} out of bounds (file has {} lines)",
                    start_line, end_line, current_line
                )));
            }

            let bytes_read = u64::try_from(out.len()).unwrap_or(u64::MAX);
            let content =
                String::from_utf8(out).map_err(|_| Error::InvalidUtf8(relative.clone()))?;
            (bytes_read, content)
        }
        _ => {
            return Err(Error::InvalidPath(
                "start_line and end_line must be provided together".to_string(),
            ));
        }
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
