use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

use super::Context;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EditRequest {
    pub root_id: String,
    pub path: PathBuf,
    pub start_line: u64,
    pub end_line: u64,
    pub replacement: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EditResponse {
    pub path: PathBuf,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requested_path: Option<PathBuf>,
    pub bytes_written: u64,
}

pub fn edit_range(ctx: &Context, request: EditRequest) -> Result<EditResponse> {
    ctx.ensure_write_operation_allowed(&request.root_id, ctx.policy.permissions.edit, "edit")?;
    let (path, relative, requested_path) =
        ctx.canonical_path_in_root(&request.root_id, &request.path)?;

    if request.start_line == 0 || request.end_line == 0 || request.start_line > request.end_line {
        return Err(invalid_edit_range(format!(
            "invalid line range: {}..{}",
            request.start_line, request.end_line
        )));
    }

    let start = usize::try_from(request.start_line - 1).map_err(|_| {
        invalid_edit_range(format!(
            "invalid line range: line number too large: {}",
            request.start_line
        ))
    })?;
    let end = usize::try_from(request.end_line - 1).map_err(|_| {
        invalid_edit_range(format!(
            "invalid line range: line number too large: {}",
            request.end_line
        ))
    })?;

    let (content, identity) = super::io::read_string_limited_with_identity(
        &path,
        &relative,
        ctx.policy.limits.max_read_bytes,
    )?;
    let lines = split_lines_preserving_endings(&content);

    if start >= lines.len() || end >= lines.len() {
        return Err(invalid_edit_range(format!(
            "invalid line range: {}..{} out of bounds (file has {} lines)",
            request.start_line,
            request.end_line,
            lines.len()
        )));
    }

    let removed_bytes = lines[start..=end].iter().try_fold(0_u64, |total, line| {
        let line_bytes = usize_to_u64(line.len(), &relative, "line length")?;
        total.checked_add(line_bytes).ok_or_else(|| {
            Error::InvalidPath(format!(
                "{}: removed byte count overflow",
                relative.display()
            ))
        })
    })?;

    let newline = line_ending(lines[end]);

    let mut replacement = normalize_replacement_line_endings(&request.replacement, newline);

    if !replacement.is_empty() && !newline.is_empty() && !replacement.ends_with(newline) {
        replacement.push_str(newline);
    }

    let content_bytes = usize_to_u64(content.len(), &relative, "file size")?;
    let replacement_bytes = usize_to_u64(replacement.len(), &relative, "replacement size")?;
    let output_bytes = content_bytes
        .checked_sub(removed_bytes)
        .and_then(|remaining| remaining.checked_add(replacement_bytes))
        .ok_or_else(|| {
            Error::InvalidPath(format!(
                "{}: output byte count overflow",
                relative.display()
            ))
        })?;
    if output_bytes > ctx.policy.limits.max_write_bytes {
        return Err(Error::FileTooLarge {
            path: relative.clone(),
            size_bytes: output_bytes,
            max_bytes: ctx.policy.limits.max_write_bytes,
        });
    }

    let mut out = String::with_capacity(content.len().saturating_add(replacement.len()));
    for (idx, line) in lines.iter().enumerate() {
        if idx == start {
            out.push_str(&replacement);
        }
        if idx < start || idx > end {
            out.push_str(line);
        }
    }

    let changed = out != content;
    if changed {
        super::io::write_bytes_atomic_checked(&path, &relative, out.as_bytes(), identity)?;
    }

    let output_len = if changed {
        usize_to_u64(out.len(), &relative, "output size")?
    } else {
        0
    };
    Ok(EditResponse {
        path: relative,
        requested_path: Some(requested_path),
        bytes_written: output_len,
    })
}

fn normalize_replacement_line_endings(replacement: &str, newline: &str) -> String {
    if newline.is_empty() {
        return replacement.to_string();
    }

    let mut out = String::with_capacity(replacement.len());
    let mut chars = replacement.chars().peekable();
    while let Some(ch) = chars.next() {
        match ch {
            '\r' => {
                if chars.peek() == Some(&'\n') {
                    let _ = chars.next();
                }
                out.push_str(newline);
            }
            '\n' => out.push_str(newline),
            _ => out.push(ch),
        }
    }

    out
}

fn split_lines_preserving_endings(content: &str) -> Vec<&str> {
    if content.is_empty() {
        return Vec::new();
    }

    let bytes = content.as_bytes();
    let mut lines = Vec::new();
    let mut start = 0_usize;
    let mut idx = 0_usize;

    while idx < bytes.len() {
        let end = match bytes[idx] {
            b'\n' => Some(idx + 1),
            b'\r' if idx + 1 < bytes.len() && bytes[idx + 1] == b'\n' => Some(idx + 2),
            b'\r' => Some(idx + 1),
            _ => None,
        };

        if let Some(line_end) = end {
            lines.push(&content[start..line_end]);
            start = line_end;
            idx = line_end;
        } else {
            idx += 1;
        }
    }

    if start < bytes.len() {
        lines.push(&content[start..]);
    }

    lines
}

fn line_ending(line: &str) -> &str {
    if line.ends_with("\r\n") {
        "\r\n"
    } else if line.ends_with('\n') {
        "\n"
    } else if line.ends_with('\r') {
        "\r"
    } else {
        ""
    }
}

fn invalid_edit_range(message: String) -> Error {
    Error::Patch(format!("invalid edit range: {message}"))
}

fn usize_to_u64(value: usize, path: &Path, context: &str) -> Result<u64> {
    u64::try_from(value).map_err(|_| {
        Error::InvalidPath(format!(
            "{}: {context} exceeds supported size",
            path.display()
        ))
    })
}

#[cfg(test)]
mod tests {
    use super::{line_ending, normalize_replacement_line_endings, split_lines_preserving_endings};

    #[test]
    fn normalize_replacement_converts_bare_cr() {
        assert_eq!(
            normalize_replacement_line_endings("one\rtwo\r", "\n"),
            "one\ntwo\n"
        );
    }

    #[test]
    fn normalize_replacement_converts_crlf() {
        assert_eq!(
            normalize_replacement_line_endings("one\r\ntwo\r\n", "\n"),
            "one\ntwo\n"
        );
    }

    #[test]
    fn normalize_replacement_converts_mixed_line_endings() {
        assert_eq!(
            normalize_replacement_line_endings("one\rtwo\r\nthree\nfour", "\r\n"),
            "one\r\ntwo\r\nthree\r\nfour"
        );
    }

    #[test]
    fn split_lines_supports_bare_cr() {
        assert_eq!(
            split_lines_preserving_endings("one\rtwo\rthree\r"),
            vec!["one\r", "two\r", "three\r"]
        );
    }

    #[test]
    fn line_ending_detects_bare_cr() {
        assert_eq!(line_ending("value\r"), "\r");
    }
}
