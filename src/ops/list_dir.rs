use std::collections::BinaryHeap;
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

#[derive(Debug)]
struct Candidate(ListDirEntry);

impl PartialEq for Candidate {
    fn eq(&self, other: &Self) -> bool {
        self.0.name == other.0.name && self.0.path == other.0.path
    }
}

impl Eq for Candidate {}

impl PartialOrd for Candidate {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Candidate {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.0
            .name
            .cmp(&other.0.name)
            .then_with(|| self.0.path.cmp(&other.0.path))
    }
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
        .min(ctx.policy.limits.max_results);

    let (dir, relative_dir, requested_path) =
        ctx.canonical_path_in_root(&request.root_id, &request.path)?;

    let meta = fs::metadata(&dir).map_err(|err| Error::io_path("metadata", &relative_dir, err))?;
    if !meta.is_dir() {
        return Err(Error::InvalidPath(format!(
            "path {} is not a directory",
            relative_dir.display()
        )));
    }

    let root_path = ctx.canonical_root(&request.root_id)?.to_path_buf();
    let mut heap = BinaryHeap::<Candidate>::new();
    let mut matched_entries: usize = 0;
    let mut skipped_io_errors: u64 = 0;

    for entry in fs::read_dir(&dir).map_err(|err| Error::io_path("read_dir", &relative_dir, err))? {
        let entry = match entry {
            Ok(entry) => entry,
            Err(_) => {
                skipped_io_errors = skipped_io_errors.saturating_add(1);
                continue;
            }
        };
        let path = entry.path();
        let relative = match crate::path_utils::strip_prefix_case_insensitive(&path, &root_path) {
            Some(relative) => relative,
            None => {
                skipped_io_errors = skipped_io_errors.saturating_add(1);
                continue;
            }
        };

        if ctx.redactor.is_path_denied(&relative) {
            continue;
        }

        let file_type = match entry.file_type() {
            Ok(value) => value,
            Err(_) => {
                skipped_io_errors = skipped_io_errors.saturating_add(1);
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
                Err(_) => skipped_io_errors = skipped_io_errors.saturating_add(1),
            }
        }

        let candidate = Candidate(ListDirEntry {
            path: relative,
            name: entry.file_name().to_string_lossy().into_owned(),
            kind: kind.to_string(),
            size_bytes,
        });

        matched_entries = matched_entries.saturating_add(1);
        if heap.len() < max_entries {
            heap.push(candidate);
            continue;
        }

        let should_replace = heap
            .peek()
            .is_some_and(|top| candidate.cmp(top) == std::cmp::Ordering::Less);
        if should_replace {
            let _ = heap.pop();
            heap.push(candidate);
        }
    }

    let truncated = matched_entries > max_entries;

    let mut entries = heap.into_vec().into_iter().map(|c| c.0).collect::<Vec<_>>();
    entries.sort_by(|a, b| a.name.cmp(&b.name).then_with(|| a.path.cmp(&b.path)));

    Ok(ListDirResponse {
        path: relative_dir,
        requested_path: Some(requested_path),
        entries,
        truncated,
        skipped_io_errors,
    })
}
