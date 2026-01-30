use std::path::PathBuf;

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
    if !ctx.policy.permissions.edit {
        return Err(Error::NotPermitted(
            "edit is disabled by policy".to_string(),
        ));
    }
    ctx.ensure_can_write(&request.root_id, "edit")?;
    let (path, relative, requested_path) =
        ctx.canonical_path_in_root(&request.root_id, &request.path)?;

    if request.start_line == 0 || request.end_line == 0 || request.start_line > request.end_line {
        return Err(Error::InvalidPath(format!(
            "invalid line range {}..{}",
            request.start_line, request.end_line
        )));
    }

    let content =
        super::io::read_string_limited(&path, &relative, ctx.policy.limits.max_read_bytes)?;
    let lines: Vec<&str> = if content.is_empty() {
        Vec::new()
    } else {
        content.split_inclusive('\n').collect()
    };
    let start = (request.start_line - 1) as usize;
    let end = (request.end_line - 1) as usize;
    if start >= lines.len() || end >= lines.len() {
        return Err(Error::InvalidPath(format!(
            "line range {}..{} out of bounds (file has {} lines)",
            request.start_line,
            request.end_line,
            lines.len()
        )));
    }

    let removed_bytes: u64 = lines[start..=end]
        .iter()
        .map(|line| line.len() as u64)
        .sum();

    let newline = if lines[end].ends_with("\r\n") {
        "\r\n"
    } else if lines[end].ends_with('\n') {
        "\n"
    } else {
        ""
    };

    let mut replacement = if newline == "\r\n" {
        let mut out = String::with_capacity(request.replacement.len());
        let mut prev_was_cr = false;
        for ch in request.replacement.chars() {
            if ch == '\n' {
                if prev_was_cr {
                    out.push('\n');
                } else {
                    out.push('\r');
                    out.push('\n');
                }
                prev_was_cr = false;
                continue;
            }
            out.push(ch);
            prev_was_cr = ch == '\r';
        }
        out
    } else {
        request.replacement.clone()
    };

    if !newline.is_empty() && !replacement.ends_with(newline) {
        replacement.push_str(newline);
    }

    let output_bytes = (content.len() as u64)
        .saturating_sub(removed_bytes)
        .saturating_add(replacement.len() as u64);
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

    super::io::write_bytes_atomic(&path, &relative, out.as_bytes())?;
    Ok(EditResponse {
        path: relative,
        requested_path: Some(requested_path),
        bytes_written: out.len() as u64,
    })
}
