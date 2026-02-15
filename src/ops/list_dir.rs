use std::collections::BinaryHeap;
use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

use super::Context;

#[cfg(unix)]
fn metadata_same_file(a: &fs::Metadata, b: &fs::Metadata) -> Option<bool> {
    use std::os::unix::fs::MetadataExt;
    Some(a.dev() == b.dev() && a.ino() == b.ino())
}

#[cfg(windows)]
fn metadata_same_file(a: &fs::Metadata, b: &fs::Metadata) -> Option<bool> {
    use std::os::windows::fs::MetadataExt;
    match (
        a.volume_serial_number(),
        b.volume_serial_number(),
        a.file_index(),
        b.file_index(),
    ) {
        (Some(a_serial), Some(b_serial), Some(a_index), Some(b_index)) => {
            Some(a_serial == b_serial && a_index == b_index)
        }
        _ => None,
    }
}

#[cfg(not(any(unix, windows)))]
fn metadata_same_file(_a: &fs::Metadata, _b: &fs::Metadata) -> Option<bool> {
    None
}

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

enum EntryOutcome {
    Accepted(ListDirEntry),
    Denied,
    SkippedIoError,
}

fn directory_changed_during_list_error(relative_dir: &Path) -> Error {
    Error::InvalidPath(format!(
        "path {} changed during list_dir; refusing to continue",
        relative_dir.display()
    ))
}

fn ensure_directory_identity_unchanged(
    dir: &Path,
    relative_dir: &Path,
    expected_meta: &fs::Metadata,
) -> Result<()> {
    let current_meta = fs::symlink_metadata(dir)
        .map_err(|err| Error::io_path("symlink_metadata", relative_dir, err))?;
    if current_meta.file_type().is_symlink() || !current_meta.is_dir() {
        return Err(directory_changed_during_list_error(relative_dir));
    }
    match metadata_same_file(expected_meta, &current_meta) {
        Some(true) => Ok(()),
        Some(false) => Err(directory_changed_during_list_error(relative_dir)),
        None => {
            #[cfg(windows)]
            {
                // Some Windows filesystems do not provide stable file IDs.
                // Keep the directory/symlink re-check above and continue.
                Ok(())
            }
            #[cfg(not(windows))]
            {
                Err(Error::InvalidPath(format!(
                    "cannot verify directory identity for path {} on this platform",
                    relative_dir.display()
                )))
            }
        }
    }
}

fn process_dir_entry(
    ctx: &Context,
    entry: fs::DirEntry,
    root_path: &std::path::Path,
) -> Result<EntryOutcome> {
    let path = entry.path();
    let relative = match crate::path_utils::strip_prefix_case_insensitive(&path, root_path) {
        Some(relative) => relative,
        None => return Ok(EntryOutcome::SkippedIoError),
    };

    if ctx.redactor.is_path_denied(&relative) {
        return Ok(EntryOutcome::Denied);
    }

    let file_type = match entry.file_type() {
        Ok(value) => value,
        Err(_) => return Ok(EntryOutcome::SkippedIoError),
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

    let size_bytes = if file_type.is_file() {
        match entry.metadata() {
            Ok(meta) => meta.len(),
            Err(_) => return Ok(EntryOutcome::SkippedIoError),
        }
    } else {
        0
    };

    Ok(EntryOutcome::Accepted(ListDirEntry {
        path: relative,
        name: entry.file_name().to_string_lossy().into_owned(),
        kind: kind.to_string(),
        size_bytes,
    }))
}

pub fn list_dir(ctx: &Context, request: ListDirRequest) -> Result<ListDirResponse> {
    ctx.ensure_policy_permission(ctx.policy.permissions.list_dir, "list_dir")?;

    let max_entries = request
        .max_entries
        .unwrap_or(ctx.policy.limits.max_results)
        .min(ctx.policy.limits.max_results);

    let (dir, relative_dir, requested_path) =
        ctx.canonical_path_in_root(&request.root_id, &request.path)?;

    let meta = fs::symlink_metadata(&dir)
        .map_err(|err| Error::io_path("symlink_metadata", &relative_dir, err))?;
    if meta.file_type().is_symlink() || !meta.is_dir() {
        return Err(Error::InvalidPath(format!(
            "path {} is not a directory",
            relative_dir.display()
        )));
    }

    let root_path = ctx.canonical_root(&request.root_id)?.to_path_buf();
    let mut heap = BinaryHeap::<Candidate>::new();
    let mut matched_entries: usize = 0;
    let mut skipped_io_errors: u64 = 0;

    ensure_directory_identity_unchanged(&dir, &relative_dir, &meta)?;
    let read_dir =
        fs::read_dir(&dir).map_err(|err| Error::io_path("read_dir", &relative_dir, err))?;
    ensure_directory_identity_unchanged(&dir, &relative_dir, &meta)?;

    for entry in read_dir {
        let entry = match entry {
            Ok(entry) => entry,
            Err(_) => {
                skipped_io_errors = skipped_io_errors.saturating_add(1);
                continue;
            }
        };
        match process_dir_entry(ctx, entry, &root_path)? {
            EntryOutcome::Accepted(entry) => {
                matched_entries = matched_entries.saturating_add(1);
                if max_entries == 0 {
                    continue;
                }

                let candidate = Candidate(entry);
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
            EntryOutcome::Denied => {}
            EntryOutcome::SkippedIoError => {
                skipped_io_errors = skipped_io_errors.saturating_add(1);
            }
        }
    }
    ensure_directory_identity_unchanged(&dir, &relative_dir, &meta)?;

    let truncated = matched_entries > max_entries;

    let entries = if max_entries == 0 {
        Vec::new()
    } else {
        let mut entries = heap.into_vec().into_iter().map(|c| c.0).collect::<Vec<_>>();
        entries.sort_by(|a, b| a.name.cmp(&b.name).then_with(|| a.path.cmp(&b.path)));
        entries
    };

    Ok(ListDirResponse {
        path: relative_dir,
        requested_path: Some(requested_path),
        entries,
        truncated,
        skipped_io_errors,
    })
}
