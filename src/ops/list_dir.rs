use std::cell::OnceCell;
use std::collections::BinaryHeap;
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

use super::Context;

fn initial_heap_capacity(max_entries: usize) -> usize {
    const MAX_INITIAL_HEAP_CAPACITY: usize = 1024;
    max_entries.min(MAX_INITIAL_HEAP_CAPACITY)
}

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
    Accepted(EntryCandidate),
    Denied,
}

enum CountOnlyOutcome {
    Counted,
    Denied,
    SkippedIoError,
}

struct EntryCandidate {
    absolute_path: PathBuf,
    path: PathBuf,
    name: OsString,
    cached_lossy_name: OnceCell<String>,
}

impl EntryCandidate {
    #[inline]
    fn compare_name(&self, other: &str) -> std::cmp::Ordering {
        if let Some(valid_utf8) = self.name.to_str() {
            valid_utf8.cmp(other)
        } else {
            self.cached_lossy_name
                .get_or_init(|| self.name.to_string_lossy().into_owned())
                .as_str()
                .cmp(other)
        }
    }

    #[inline]
    fn sorts_before(&self, other: &ListDirEntry) -> bool {
        self.compare_name(other.name.as_str())
            .then_with(|| self.path.cmp(&other.path))
            == std::cmp::Ordering::Less
    }

    fn into_list_entry(self, kind: &'static str, size_bytes: u64) -> ListDirEntry {
        let name = match self.cached_lossy_name.into_inner() {
            Some(name) => name,
            None => self
                .name
                .into_string()
                .unwrap_or_else(|name| name.to_string_lossy().into_owned()),
        };
        ListDirEntry {
            path: self.path,
            name,
            kind: kind.to_string(),
            size_bytes,
        }
    }
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

fn entry_kind_and_size_no_follow(path: &Path) -> std::io::Result<(&'static str, u64)> {
    let meta = fs::symlink_metadata(path)?;
    let file_type = meta.file_type();
    if file_type.is_file() {
        Ok(("file", meta.len()))
    } else if file_type.is_dir() {
        Ok(("dir", 0))
    } else if file_type.is_symlink() {
        Ok(("symlink", 0))
    } else {
        Ok(("other", 0))
    }
}

fn process_dir_entry(
    ctx: &Context,
    entry: fs::DirEntry,
    relative_dir: &Path,
) -> Result<EntryOutcome> {
    let path = entry.path();
    let name = entry.file_name();
    let relative = relative_entry_path(relative_dir, &name);

    if ctx.redactor.is_path_denied(&relative) {
        return Ok(EntryOutcome::Denied);
    }

    Ok(EntryOutcome::Accepted(EntryCandidate {
        absolute_path: path,
        path: relative,
        name,
        cached_lossy_name: OnceCell::new(),
    }))
}

fn process_dir_entry_count_only(
    ctx: &Context,
    entry: fs::DirEntry,
    relative_dir: &Path,
) -> Result<CountOnlyOutcome> {
    let relative = relative_entry_path(relative_dir, &entry.file_name());

    if ctx.redactor.is_path_denied(&relative) {
        return Ok(CountOnlyOutcome::Denied);
    }

    // Keep parity with normal flow for best-effort IO error accounting.
    // For `max_entries=0`, callers only need truncation presence, but entries that
    // fail basic type probing should still count toward `skipped_io_errors`.
    if entry.file_type().is_err() {
        return Ok(CountOnlyOutcome::SkippedIoError);
    }

    Ok(CountOnlyOutcome::Counted)
}

#[inline]
fn relative_entry_path(relative_dir: &Path, name: &std::ffi::OsStr) -> PathBuf {
    if relative_dir == Path::new(".") {
        PathBuf::from(name)
    } else {
        relative_dir.join(name)
    }
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

    let mut heap = BinaryHeap::<Candidate>::with_capacity(initial_heap_capacity(max_entries));
    let mut matched_entries: usize = 0;
    let mut skipped_io_errors: u64 = 0;
    let mut zero_limit_truncated = false;

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
        if max_entries == 0 {
            match process_dir_entry_count_only(ctx, entry, &relative_dir)? {
                CountOnlyOutcome::Counted => {
                    // With `max_entries=0`, callers only need to know whether any entry exists.
                    // Stop after the first visible match to avoid scanning huge directories.
                    zero_limit_truncated = true;
                    break;
                }
                CountOnlyOutcome::Denied => {}
                CountOnlyOutcome::SkippedIoError => {
                    skipped_io_errors = skipped_io_errors.saturating_add(1);
                }
            }
            continue;
        }

        match process_dir_entry(ctx, entry, &relative_dir)? {
            EntryOutcome::Accepted(entry) => {
                matched_entries = matched_entries.saturating_add(1);

                let should_insert = if heap.len() < max_entries {
                    true
                } else {
                    heap.peek().is_some_and(|top| entry.sorts_before(&top.0))
                };
                if !should_insert {
                    continue;
                }

                // Re-read final type/size via `symlink_metadata` for the selected candidate.
                // This avoids following a raced symlink replacement when collecting file size.
                let (kind, size_bytes) = match entry_kind_and_size_no_follow(&entry.absolute_path) {
                    Ok(value) => value,
                    Err(_) => {
                        skipped_io_errors = skipped_io_errors.saturating_add(1);
                        matched_entries = matched_entries.saturating_sub(1);
                        continue;
                    }
                };

                let candidate = Candidate(entry.into_list_entry(kind, size_bytes));
                if heap.len() < max_entries {
                    heap.push(candidate);
                } else {
                    let _ = heap.pop();
                    heap.push(candidate);
                }
            }
            EntryOutcome::Denied => {}
        }
    }
    ensure_directory_identity_unchanged(&dir, &relative_dir, &meta)?;

    let truncated = if max_entries == 0 {
        zero_limit_truncated
    } else {
        matched_entries > max_entries
    };

    let entries = if max_entries == 0 {
        Vec::new()
    } else {
        heap.into_sorted_vec()
            .into_iter()
            .map(|candidate| candidate.0)
            .collect::<Vec<_>>()
    };

    Ok(ListDirResponse {
        path: relative_dir,
        requested_path: Some(requested_path),
        entries,
        truncated,
        skipped_io_errors,
    })
}

#[cfg(test)]
mod tests {
    use std::collections::BinaryHeap;
    use std::ffi::OsStr;
    use std::path::PathBuf;

    use super::{
        Candidate, ListDirEntry, entry_kind_and_size_no_follow, initial_heap_capacity,
        relative_entry_path,
    };

    #[test]
    fn initial_heap_capacity_is_capped() {
        assert_eq!(initial_heap_capacity(0), 0);
        assert_eq!(initial_heap_capacity(16), 16);
        assert_eq!(initial_heap_capacity(1024), 1024);
        assert_eq!(initial_heap_capacity(4096), 1024);
    }

    #[test]
    fn candidate_heap_into_sorted_vec_preserves_name_then_path_order() {
        let mut heap = BinaryHeap::new();
        heap.push(Candidate(ListDirEntry {
            path: PathBuf::from("b/alpha"),
            name: "alpha".to_string(),
            kind: "file".to_string(),
            size_bytes: 1,
        }));
        heap.push(Candidate(ListDirEntry {
            path: PathBuf::from("a/beta"),
            name: "beta".to_string(),
            kind: "file".to_string(),
            size_bytes: 1,
        }));
        heap.push(Candidate(ListDirEntry {
            path: PathBuf::from("a/alpha"),
            name: "alpha".to_string(),
            kind: "file".to_string(),
            size_bytes: 1,
        }));

        let ordered = heap
            .into_sorted_vec()
            .into_iter()
            .map(|candidate| (candidate.0.name, candidate.0.path))
            .collect::<Vec<_>>();

        assert_eq!(
            ordered,
            vec![
                ("alpha".to_string(), PathBuf::from("a/alpha")),
                ("alpha".to_string(), PathBuf::from("b/alpha")),
                ("beta".to_string(), PathBuf::from("a/beta")),
            ]
        );
    }

    #[test]
    fn relative_entry_path_uses_file_name_for_root_dot() {
        let path = relative_entry_path(std::path::Path::new("."), OsStr::new("a.txt"));
        assert_eq!(path, PathBuf::from("a.txt"));
    }

    #[test]
    fn relative_entry_path_joins_non_root_parent() {
        let path = relative_entry_path(std::path::Path::new("nested"), OsStr::new("a.txt"));
        assert_eq!(path, PathBuf::from("nested").join("a.txt"));
    }

    #[cfg(unix)]
    #[test]
    fn sorts_before_caches_lossy_name_for_non_utf8_entries() {
        use std::ffi::OsString;
        use std::os::unix::ffi::OsStringExt;

        let candidate = super::EntryCandidate {
            absolute_path: PathBuf::from("x"),
            path: PathBuf::from("x"),
            name: OsString::from_vec(vec![0xff]),
            cached_lossy_name: std::cell::OnceCell::new(),
        };
        let other = ListDirEntry {
            path: PathBuf::from("y"),
            name: "z".to_string(),
            kind: "file".to_string(),
            size_bytes: 0,
        };

        let _ = candidate.sorts_before(&other);
        assert!(candidate.cached_lossy_name.get().is_some());
        let first_cached = candidate.cached_lossy_name.get().cloned();
        let _ = candidate.sorts_before(&other);
        assert_eq!(candidate.cached_lossy_name.get().cloned(), first_cached);
    }

    #[cfg(unix)]
    #[test]
    fn entry_kind_no_follow_reports_symlink_after_replacement() {
        let dir = tempfile::tempdir().expect("tempdir");
        let outside = dir.path().join("outside.txt");
        std::fs::write(&outside, "outside target").expect("write outside");

        let victim = dir.path().join("victim.txt");
        std::fs::write(&victim, "x").expect("write victim");
        std::fs::remove_file(&victim).expect("remove victim");
        std::os::unix::fs::symlink(&outside, &victim).expect("create symlink");

        let (kind, size_bytes) = entry_kind_and_size_no_follow(&victim).expect("metadata");
        assert_eq!(kind, "symlink");
        assert_eq!(size_bytes, 0);
    }
}
