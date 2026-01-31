use std::fs;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

use super::Context;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListDirRequest {
    pub root_id: String,
    pub path: PathBuf,
    #[serde(default)]
    pub max_entries: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListDirEntry {
    pub path: PathBuf,
    pub name: String,
    #[serde(rename = "type")]
    pub kind: String,
    pub size_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListDirResponse {
    pub path: PathBuf,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requested_path: Option<PathBuf>,
    pub entries: Vec<ListDirEntry>,
    pub truncated: bool,
    pub skipped_io_errors: u64,
}

pub fn list_dir(ctx: &Context, request: ListDirRequest) -> Result<ListDirResponse> {
    if !ctx.policy.permissions.list_dir {
        return Err(Error::NotPermitted(
            "list_dir is disabled by policy".to_string(),
        ));
    }

    let max_entries = request
        .max_entries
        .unwrap_or(ctx.policy.limits.max_results)
        .min(ctx.policy.limits.max_results)
        .max(1);

    let (dir, relative_dir, requested_path) =
        ctx.canonical_path_in_root(&request.root_id, &request.path)?;

    let meta = fs::metadata(&dir).map_err(|err| Error::io_path("metadata", &relative_dir, err))?;
    if !meta.is_dir() {
        return Err(Error::InvalidPath(format!(
            "path {} is not a directory",
            relative_dir.display()
        )));
    }

    let root_path = ctx.canonical_root(&request.root_id)?.clone();
    let mut entries = Vec::<ListDirEntry>::new();
    let mut truncated = false;
    let mut skipped_io_errors: u64 = 0;

    let mut rows = fs::read_dir(&dir)
        .map_err(|err| Error::io_path("read_dir", &relative_dir, err))?
        .collect::<std::io::Result<Vec<_>>>()
        .map_err(|err| Error::io_path("read_dir", &relative_dir, err))?;
    rows.sort_by_key(|entry| entry.file_name());

    for entry in rows {
        let path = entry.path();
        let relative = crate::path_utils::strip_prefix_case_insensitive(&path, &root_path)
            .unwrap_or(path.clone());

        if ctx.redactor.is_path_denied(&relative) {
            continue;
        }

        if entries.len() >= max_entries {
            truncated = true;
            break;
        }

        let file_type = match entry.file_type() {
            Ok(value) => value,
            Err(_) => {
                skipped_io_errors += 1;
                continue;
            }
        };

        let kind = if file_type.is_file() {
            "file"
        } else if file_type.is_dir() {
            "dir"
        } else if file_type.is_symlink() {
            "symlink"
        } else {
            "other"
        };

        let mut size_bytes: u64 = 0;
        if file_type.is_file() {
            match entry.metadata() {
                Ok(meta) => size_bytes = meta.len(),
                Err(_) => skipped_io_errors += 1,
            }
        }

        entries.push(ListDirEntry {
            path: relative,
            name: entry.file_name().to_string_lossy().into_owned(),
            kind: kind.to_string(),
            size_bytes,
        });
    }

    Ok(ListDirResponse {
        path: relative_dir,
        requested_path: Some(requested_path),
        entries,
        truncated,
        skipped_io_errors,
    })
}
