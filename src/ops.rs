use std::ffi::OsString;
use std::fs;
use std::io::{BufRead, Read, Write};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
#[cfg(any(feature = "glob", feature = "grep"))]
use std::time::{Duration, Instant};

#[cfg(feature = "patch")]
use diffy::{Patch, apply};
#[cfg(any(feature = "glob", feature = "grep"))]
use globset::{GlobBuilder, GlobSet, GlobSetBuilder};
use serde::{Deserialize, Serialize};
#[cfg(any(feature = "glob", feature = "grep"))]
use walkdir::WalkDir;

use crate::error::{Error, Result};
use crate::policy::{RootMode, SandboxPolicy};
use crate::redaction::SecretRedactor;

static ATOMIC_WRITE_COUNTER: AtomicU64 = AtomicU64::new(0);
#[cfg(any(feature = "glob", feature = "grep"))]
const TRAVERSAL_GLOB_PROBE_NAME: &str = ".safe-fs-tools-probe";

fn normalize_path_lexical(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    let mut seen_prefix = false;
    for comp in path.components() {
        match comp {
            Component::CurDir => {}
            Component::ParentDir => {
                if !out.pop() {
                    // If we're at the filesystem root, `..` is a no-op. For relative paths, keep it.
                    if out.as_os_str().is_empty() {
                        out.push("..");
                    }
                }
            }
            Component::Normal(part) => out.push(part),
            Component::RootDir => {
                if seen_prefix {
                    // On Windows, pushing `RootDir` after `Prefix` would reset the path (dropping
                    // the prefix). Append a separator instead.
                    #[cfg(windows)]
                    {
                        out.as_mut_os_string()
                            .push(std::path::MAIN_SEPARATOR.to_string());
                    }
                    #[cfg(not(windows))]
                    {
                        out.push(comp.as_os_str());
                    }
                } else {
                    out.push(comp.as_os_str());
                }
            }
            Component::Prefix(prefix) => {
                seen_prefix = true;
                out.push(prefix.as_os_str());
            }
        }
    }
    out
}

#[cfg(any(feature = "glob", feature = "grep"))]
fn elapsed_ms(started: &Instant) -> u64 {
    let ms = started.elapsed().as_millis();
    if ms > u64::MAX as u128 {
        u64::MAX
    } else {
        ms as u64
    }
}

fn open_private_temp_file(path: &Path) -> std::io::Result<fs::File> {
    let mut open_options = fs::OpenOptions::new();
    open_options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        open_options.mode(0o600);
    }
    open_options.open(path)
}

fn read_bytes_limited(path: &Path, relative: &Path, max_bytes: u64) -> Result<Vec<u8>> {
    if let Ok(meta) = fs::metadata(path)
        && meta.len() > max_bytes
    {
        return Err(Error::FileTooLarge {
            path: relative.to_path_buf(),
            size_bytes: meta.len(),
            max_bytes,
        });
    }

    let file = fs::File::open(path).map_err(|err| Error::io_path("open", relative, err))?;
    let limit = max_bytes.saturating_add(1);
    let mut bytes = Vec::<u8>::new();
    file.take(limit)
        .read_to_end(&mut bytes)
        .map_err(|err| Error::io_path("read", relative, err))?;
    if bytes.len() as u64 > max_bytes {
        return Err(Error::FileTooLarge {
            path: relative.to_path_buf(),
            size_bytes: bytes.len() as u64,
            max_bytes,
        });
    }
    Ok(bytes)
}

fn read_string_limited(path: &Path, relative: &Path, max_bytes: u64) -> Result<String> {
    let bytes = read_bytes_limited(path, relative, max_bytes)?;
    std::str::from_utf8(&bytes)
        .map_err(|_| Error::InvalidUtf8(relative.to_path_buf()))
        .map(str::to_string)
}

fn write_bytes_atomic(path: &Path, relative: &Path, bytes: &[u8]) -> Result<()> {
    // Preserve prior behavior: fail if the original file isn't writable.
    let _ = fs::OpenOptions::new()
        .write(true)
        .open(path)
        .map_err(|err| Error::io_path("open_for_write", relative, err))?;

    let perms = fs::metadata(path)
        .map_err(|err| Error::io_path("metadata", relative, err))?
        .permissions();

    let parent = path.parent().ok_or_else(|| {
        Error::InvalidPath(format!(
            "invalid path {}: missing parent directory",
            relative.display()
        ))
    })?;
    let file_name = path.file_name().ok_or_else(|| {
        Error::InvalidPath(format!(
            "invalid path {}: missing file name",
            relative.display()
        ))
    })?;

    let counter = ATOMIC_WRITE_COUNTER.fetch_add(1, Ordering::Relaxed);
    for attempt in 0..100u32 {
        let mut tmp_name = OsString::from(".");
        tmp_name.push(file_name);
        tmp_name.push(format!(
            ".safe-fs-tools.tmp.{}.{}.{}",
            std::process::id(),
            counter,
            attempt
        ));
        let tmp_path = parent.join(&tmp_name);

        let mut tmp_file = match open_private_temp_file(&tmp_path) {
            Ok(file) => file,
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(err) => return Err(Error::io_path("create_temp", relative, err)),
        };

        if let Err(err) = tmp_file.write_all(bytes) {
            let _ = fs::remove_file(&tmp_path);
            return Err(Error::io_path("write", relative, err));
        }
        if let Err(err) = tmp_file.sync_all() {
            let _ = fs::remove_file(&tmp_path);
            return Err(Error::io_path("sync", relative, err));
        }
        drop(tmp_file);

        if let Err(err) = fs::set_permissions(&tmp_path, perms.clone()) {
            let _ = fs::remove_file(&tmp_path);
            return Err(Error::io_path("set_permissions", relative, err));
        }

        if let Err(err) = replace_file(&tmp_path, path) {
            let _ = fs::remove_file(&tmp_path);
            return Err(Error::io_path("replace_file", relative, err));
        }

        return Ok(());
    }

    Err(Error::InvalidPath(format!(
        "failed to create unique temp file for {}",
        relative.display()
    )))
}

#[cfg(windows)]
fn replace_file(tmp_path: &Path, dest_path: &Path) -> std::io::Result<()> {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;

    use windows_sys::Win32::Storage::FileSystem::{REPLACEFILE_IGNORE_MERGE_ERRORS, ReplaceFileW};

    if !dest_path.exists() {
        return fs::rename(tmp_path, dest_path);
    }

    fn to_wide_null(s: &OsStr) -> Vec<u16> {
        let mut wide: Vec<u16> = s.encode_wide().collect();
        wide.push(0);
        wide
    }

    let replaced = unsafe {
        ReplaceFileW(
            to_wide_null(dest_path.as_os_str()).as_ptr(),
            to_wide_null(tmp_path.as_os_str()).as_ptr(),
            std::ptr::null(),
            REPLACEFILE_IGNORE_MERGE_ERRORS,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };

    if replaced == 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(not(windows))]
fn replace_file(tmp_path: &Path, dest_path: &Path) -> std::io::Result<()> {
    fs::rename(tmp_path, dest_path)
}

#[cfg(any(feature = "glob", feature = "grep"))]
fn globset_is_match(glob: &GlobSet, path: &Path) -> bool {
    #[cfg(windows)]
    {
        let raw = path.to_string_lossy();
        if !raw.contains('\\') {
            return glob.is_match(path);
        }
        let normalized = raw.replace('\\', "/");
        return glob.is_match(Path::new(&normalized));
    }
    #[cfg(not(windows))]
    {
        glob.is_match(path)
    }
}

#[cfg(any(feature = "glob", feature = "grep"))]
fn walkdir_root_error(root_path: &Path, walk_root: &Path, err: walkdir::Error) -> Error {
    let relative = match walk_root.strip_prefix(root_path) {
        Ok(relative) if !relative.as_os_str().is_empty() => relative.to_path_buf(),
        _ => PathBuf::from("."),
    };

    let source = match err.io_error().and_then(|io| io.raw_os_error()) {
        Some(raw_os_error) => std::io::Error::from_raw_os_error(raw_os_error),
        None => std::io::Error::new(
            err.io_error()
                .map(|io| io.kind())
                .unwrap_or(std::io::ErrorKind::Other),
            "walkdir error",
        ),
    };

    Error::WalkDirRoot {
        path: relative,
        source,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(unix)]
    fn open_private_temp_file_creates_files_without_group_or_other_access() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("tmp.txt");
        drop(open_private_temp_file(&path).expect("open"));
        let mode = fs::metadata(&path).expect("metadata").permissions().mode() & 0o777;
        assert_eq!(mode & 0o077, 0, "expected no group/other permission bits");
    }

    #[test]
    #[cfg(any(feature = "glob", feature = "grep"))]
    fn derive_safe_traversal_prefix_is_conservative() {
        assert_eq!(
            derive_safe_traversal_prefix("src/**/*.rs"),
            Some(PathBuf::from("src"))
        );
        assert_eq!(
            derive_safe_traversal_prefix("./src/**/*.rs"),
            Some(PathBuf::from("src"))
        );
        assert_eq!(
            derive_safe_traversal_prefix("src/*"),
            Some(PathBuf::from("src"))
        );
        assert_eq!(
            derive_safe_traversal_prefix("src/lib.rs"),
            Some(PathBuf::from("src/lib.rs"))
        );
        assert_eq!(derive_safe_traversal_prefix("**/*.rs"), None);
        assert_eq!(derive_safe_traversal_prefix("../**/*.rs"), None);
        assert_eq!(derive_safe_traversal_prefix("/etc/*"), None);
    }

    #[test]
    #[cfg(unix)]
    fn normalize_path_lexical_does_not_escape_filesystem_root() {
        assert_eq!(
            normalize_path_lexical(Path::new("/../etc")),
            PathBuf::from("/etc")
        );
        assert_eq!(
            normalize_path_lexical(Path::new("/a/../../b")),
            PathBuf::from("/b")
        );
    }

    #[test]
    #[cfg(windows)]
    fn normalize_path_lexical_preserves_prefix_root() {
        assert_eq!(
            normalize_path_lexical(Path::new(r"C:\..\foo")),
            PathBuf::from(r"C:\foo")
        );
    }
}

#[derive(Debug)]
pub struct Context {
    policy: SandboxPolicy,
    redactor: SecretRedactor,
    canonical_roots: Vec<(String, PathBuf)>,
    #[cfg(any(feature = "glob", feature = "grep"))]
    traversal_skip_globs: Option<GlobSet>,
}

impl Context {
    pub fn new(policy: SandboxPolicy) -> Result<Self> {
        policy.validate()?;
        let redactor = SecretRedactor::from_rules(&policy.secrets)?;

        let mut canonical_roots = Vec::<(String, PathBuf)>::new();
        for root in &policy.roots {
            let canonical = root.path.canonicalize().map_err(|err| {
                Error::InvalidPolicy(format!(
                    "failed to canonicalize root {} ({}): {err}",
                    root.id,
                    root.path.display()
                ))
            })?;
            let meta = fs::metadata(&canonical).map_err(|err| {
                Error::InvalidPolicy(format!(
                    "failed to stat root {} ({}): {err}",
                    root.id,
                    canonical.display()
                ))
            })?;
            if !meta.is_dir() {
                return Err(Error::InvalidPolicy(format!(
                    "root {} ({}) is not a directory",
                    root.id,
                    canonical.display()
                )));
            }
            canonical_roots.push((root.id.clone(), canonical));
        }

        #[cfg(any(feature = "glob", feature = "grep"))]
        let traversal_skip_globs = compile_traversal_skip_globs(&policy.traversal.skip_globs)?;

        Ok(Self {
            policy,
            redactor,
            canonical_roots,
            #[cfg(any(feature = "glob", feature = "grep"))]
            traversal_skip_globs,
        })
    }

    #[cfg(feature = "policy-io")]
    pub fn from_policy_path(path: impl AsRef<std::path::Path>) -> Result<Self> {
        let policy = crate::policy_io::load_policy(path)?;
        Self::new(policy)
    }

    pub fn policy(&self) -> &SandboxPolicy {
        &self.policy
    }

    pub fn read_file(&self, request: ReadRequest) -> Result<ReadResponse> {
        read_file(self, request)
    }

    pub fn glob_paths(&self, request: GlobRequest) -> Result<GlobResponse> {
        glob_paths(self, request)
    }

    pub fn grep(&self, request: GrepRequest) -> Result<GrepResponse> {
        grep(self, request)
    }

    pub fn edit_range(&self, request: EditRequest) -> Result<EditResponse> {
        edit_range(self, request)
    }

    pub fn apply_unified_patch(&self, request: PatchRequest) -> Result<PatchResponse> {
        apply_unified_patch(self, request)
    }

    pub fn delete_file(&self, request: DeleteRequest) -> Result<DeleteResponse> {
        delete_file(self, request)
    }

    fn canonical_root(&self, root_id: &str) -> Result<&PathBuf> {
        self.canonical_roots
            .iter()
            .find_map(|(id, path)| (id == root_id).then_some(path))
            .ok_or_else(|| Error::RootNotFound(root_id.to_string()))
    }

    #[cfg(any(feature = "glob", feature = "grep"))]
    fn is_traversal_path_skipped(&self, relative: &Path) -> bool {
        self.traversal_skip_globs
            .as_ref()
            .is_some_and(|skip| globset_is_match(skip, relative))
    }

    fn canonical_path_in_root(
        &self,
        root_id: &str,
        path: &Path,
    ) -> Result<(PathBuf, PathBuf, PathBuf)> {
        let resolved = self.policy.resolve_path(root_id, path)?;
        let root = self.policy.root(root_id)?;
        let canonical_root = self.canonical_root(root_id)?;

        let relative_requested = if path.is_absolute() {
            if let Ok(relative) = resolved.strip_prefix(&root.path) {
                relative.to_path_buf()
            } else if let Ok(relative) = resolved.strip_prefix(canonical_root) {
                relative.to_path_buf()
            } else if let (Some(parent), Some(file_name)) =
                (resolved.parent(), resolved.file_name())
            {
                match parent.canonicalize() {
                    Ok(canonical_parent) => {
                        let normalized = canonical_parent.join(file_name);
                        normalized
                            .strip_prefix(canonical_root)
                            .unwrap_or(&normalized)
                            .to_path_buf()
                    }
                    Err(_) => resolved.clone(),
                }
            } else {
                resolved.clone()
            }
        } else {
            path.to_path_buf()
        };
        let requested_path = normalize_path_lexical(&relative_requested);
        if self.redactor.is_path_denied(&requested_path) {
            return Err(Error::SecretPathDenied(requested_path));
        }

        let canonical = match resolved.canonicalize() {
            Ok(canonical) => canonical,
            Err(err) => {
                if err.kind() == std::io::ErrorKind::NotFound
                    && let Ok(meta) = fs::symlink_metadata(&resolved)
                    && meta.file_type().is_symlink()
                {
                    let symlink_target = fs::read_link(&resolved).ok();
                    let parent = resolved.parent();
                    let canonical_parent = parent.and_then(|path| path.canonicalize().ok());
                    if let (Some(symlink_target), Some(canonical_parent)) =
                        (symlink_target, canonical_parent)
                    {
                        let resolved_target = if symlink_target.is_absolute() {
                            symlink_target
                        } else {
                            canonical_parent.join(symlink_target)
                        };
                        let resolved_target = normalize_path_lexical(&resolved_target);
                        if !resolved_target.starts_with(canonical_root) {
                            return Err(Error::OutsideRoot {
                                root_id: root_id.to_string(),
                                path: requested_path,
                            });
                        }
                    }
                }
                return Err(Error::io_path("canonicalize", requested_path, err));
            }
        };
        if !canonical.starts_with(canonical_root) {
            return Err(Error::OutsideRoot {
                root_id: root_id.to_string(),
                path: requested_path,
            });
        }
        let relative = canonical
            .strip_prefix(canonical_root)
            .unwrap_or(&canonical)
            .to_path_buf();
        if self.redactor.is_path_denied(&relative) {
            return Err(Error::SecretPathDenied(relative));
        }
        Ok((canonical, relative, requested_path))
    }

    fn ensure_can_write(&self, root_id: &str, op: &str) -> Result<()> {
        let root = self.policy.root(root_id)?;
        if !matches!(root.mode, RootMode::ReadWrite) {
            return Err(Error::NotPermitted(format!(
                "{op} is not allowed: root {root_id} is read_only"
            )));
        }
        Ok(())
    }
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
            let bytes = read_bytes_limited(&path, &relative, ctx.policy.limits.max_read_bytes)?;
            let bytes_read = bytes.len() as u64;
            let content = std::str::from_utf8(&bytes)
                .map_err(|_| Error::InvalidUtf8(relative.clone()))?
                .to_string();
            (bytes_read, content)
        }
        (Some(start_line), Some(end_line)) => {
            if start_line == 0 || end_line == 0 || start_line > end_line {
                return Err(Error::InvalidPath(format!(
                    "invalid line range {}..{}",
                    start_line, end_line
                )));
            }

            let file =
                fs::File::open(&path).map_err(|err| Error::io_path("open", &relative, err))?;
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
                    return Err(Error::FileTooLarge {
                        path: relative.clone(),
                        size_bytes: scanned_bytes,
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

            if current_line < start_line || current_line < end_line {
                return Err(Error::InvalidPath(format!(
                    "line range {}..{} out of bounds (file has {} lines)",
                    start_line, end_line, current_line
                )));
            }

            let bytes_read = out.len() as u64;
            let content = std::str::from_utf8(&out)
                .map_err(|_| Error::InvalidUtf8(relative.clone()))?
                .to_string();
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GlobRequest {
    pub root_id: String,
    pub pattern: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScanLimitReason {
    Entries,
    Files,
    Time,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GlobResponse {
    pub matches: Vec<PathBuf>,
    pub truncated: bool,
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

#[cfg(any(feature = "glob", feature = "grep"))]
#[cfg(windows)]
fn normalize_glob_pattern(pattern: &str) -> std::borrow::Cow<'_, str> {
    if !pattern.contains('\\') {
        return std::borrow::Cow::Borrowed(pattern);
    }
    std::borrow::Cow::Owned(pattern.replace('\\', "/"))
}

#[cfg(any(feature = "glob", feature = "grep"))]
#[cfg(not(windows))]
fn normalize_glob_pattern(pattern: &str) -> std::borrow::Cow<'_, str> {
    std::borrow::Cow::Borrowed(pattern)
}

#[cfg(any(feature = "glob", feature = "grep"))]
fn compile_glob(pattern: &str) -> Result<GlobSet> {
    let glob = GlobBuilder::new(normalize_glob_pattern(pattern).as_ref())
        .literal_separator(true)
        .build()
        .map_err(|err| Error::InvalidPath(format!("invalid glob pattern {pattern:?}: {err}")))?;
    let mut builder = GlobSetBuilder::new();
    builder.add(glob);
    builder
        .build()
        .map_err(|err| Error::InvalidPath(format!("invalid glob pattern {pattern:?}: {err}")))
}

#[cfg(any(feature = "glob", feature = "grep"))]
fn compile_traversal_skip_globs(patterns: &[String]) -> Result<Option<GlobSet>> {
    if patterns.is_empty() {
        return Ok(None);
    }
    let mut builder = GlobSetBuilder::new();
    for pattern in patterns {
        let glob = GlobBuilder::new(normalize_glob_pattern(pattern).as_ref())
            .literal_separator(true)
            .build()
            .map_err(|err| {
                Error::InvalidPolicy(format!(
                    "invalid traversal.skip_globs glob {pattern:?}: {err}"
                ))
            })?;
        builder.add(glob);
    }
    let set = builder
        .build()
        .map_err(|err| Error::InvalidPolicy(format!("invalid traversal.skip_globs: {err}")))?;
    Ok(Some(set))
}

#[cfg(any(feature = "glob", feature = "grep"))]
fn derive_safe_traversal_prefix(pattern: &str) -> Option<PathBuf> {
    let pattern = normalize_glob_pattern(pattern);
    let pattern = pattern.as_ref();
    if pattern.starts_with('/') {
        return None;
    }

    let mut out = PathBuf::new();
    for segment in pattern.split('/') {
        if segment.is_empty() || segment == "." {
            continue;
        }
        if segment == ".." {
            return None;
        }
        if segment
            .chars()
            .any(|ch| matches!(ch, '*' | '?' | '[' | ']' | '{' | '}'))
        {
            break;
        }
        out.push(segment);
    }
    if out.as_os_str().is_empty() {
        None
    } else {
        Some(out)
    }
}

#[cfg(not(feature = "glob"))]
pub fn glob_paths(ctx: &Context, request: GlobRequest) -> Result<GlobResponse> {
    let _ = ctx;
    let _ = request;
    Err(Error::NotPermitted(
        "glob is not supported: crate feature 'glob' is disabled".to_string(),
    ))
}

#[cfg(feature = "glob")]
pub fn glob_paths(ctx: &Context, request: GlobRequest) -> Result<GlobResponse> {
    if !ctx.policy.permissions.glob {
        return Err(Error::NotPermitted(
            "glob is disabled by policy".to_string(),
        ));
    }
    let started = Instant::now();
    let max_walk = ctx.policy.limits.max_walk_ms.map(Duration::from_millis);
    let root_path = ctx.canonical_root(&request.root_id)?.clone();
    let matcher = compile_glob(&request.pattern)?;

    let mut matches = Vec::<PathBuf>::new();
    let mut truncated = false;
    let mut scanned_files: u64 = 0;
    let mut scanned_entries: u64 = 0;
    let mut scan_limit_reached = false;
    let mut scan_limit_reason: Option<ScanLimitReason> = None;
    let mut skipped_walk_errors: u64 = 0;
    let mut skipped_io_errors: u64 = 0;
    let mut skipped_dangling_symlink_targets: u64 = 0;
    let walk_root = match derive_safe_traversal_prefix(&request.pattern) {
        Some(prefix) => {
            let probe = prefix.join(TRAVERSAL_GLOB_PROBE_NAME);
            if ctx.redactor.is_path_denied(&prefix)
                || ctx.redactor.is_path_denied(&probe)
                || ctx.is_traversal_path_skipped(&prefix)
                || ctx.is_traversal_path_skipped(&probe)
            {
                return Ok(GlobResponse {
                    matches,
                    truncated,
                    scanned_files,
                    scan_limit_reached,
                    scan_limit_reason,
                    elapsed_ms: elapsed_ms(&started),
                    scanned_entries,
                    skipped_walk_errors,
                    skipped_io_errors,
                    skipped_dangling_symlink_targets,
                });
            }
            root_path.join(prefix)
        }
        None => root_path.clone(),
    };
    if !walk_root.exists() {
        return Ok(GlobResponse {
            matches,
            truncated,
            scanned_files,
            scan_limit_reached,
            scan_limit_reason,
            elapsed_ms: elapsed_ms(&started),
            scanned_entries,
            skipped_walk_errors,
            skipped_io_errors,
            skipped_dangling_symlink_targets,
        });
    }
    for entry in WalkDir::new(&walk_root)
        .follow_root_links(false)
        .follow_links(false)
        .sort_by_file_name()
        .into_iter()
        .filter_entry(|entry| {
            if entry.depth() == 0 {
                return true;
            }
            let is_dir = entry.file_type().is_dir();
            let relative = entry
                .path()
                .strip_prefix(&root_path)
                .unwrap_or(entry.path());
            let probe = relative.join(TRAVERSAL_GLOB_PROBE_NAME);
            if ctx.redactor.is_path_denied(relative)
                || (is_dir && ctx.redactor.is_path_denied(&probe))
            {
                return false;
            }
            !(ctx.is_traversal_path_skipped(relative)
                || (is_dir && ctx.is_traversal_path_skipped(&probe)))
        })
    {
        if max_walk.is_some_and(|limit| started.elapsed() >= limit) {
            truncated = true;
            scan_limit_reached = true;
            if scan_limit_reason.is_none() {
                scan_limit_reason = Some(ScanLimitReason::Time);
            }
            break;
        }
        let entry = match entry {
            Ok(entry) => entry,
            Err(err) => {
                if err.depth() == 0 {
                    return Err(walkdir_root_error(&root_path, &walk_root, err));
                }
                if scanned_entries as usize >= ctx.policy.limits.max_walk_entries {
                    truncated = true;
                    scan_limit_reached = true;
                    if scan_limit_reason.is_none() {
                        scan_limit_reason = Some(ScanLimitReason::Entries);
                    }
                    break;
                }
                scanned_entries = scanned_entries.saturating_add(1);
                skipped_walk_errors = skipped_walk_errors.saturating_add(1);
                continue;
            }
        };
        if entry.depth() > 0 {
            if scanned_entries as usize >= ctx.policy.limits.max_walk_entries {
                truncated = true;
                scan_limit_reached = true;
                if scan_limit_reason.is_none() {
                    scan_limit_reason = Some(ScanLimitReason::Entries);
                }
                break;
            }
            scanned_entries = scanned_entries.saturating_add(1);
        }
        let file_type = entry.file_type();
        if !(file_type.is_file() || file_type.is_symlink()) {
            continue;
        }
        if scanned_files as usize >= ctx.policy.limits.max_walk_files {
            truncated = true;
            scan_limit_reached = true;
            if scan_limit_reason.is_none() {
                scan_limit_reason = Some(ScanLimitReason::Files);
            }
            break;
        }
        scanned_files = scanned_files.saturating_add(1);
        let relative = entry
            .path()
            .strip_prefix(&root_path)
            .unwrap_or(entry.path());
        if ctx.redactor.is_path_denied(relative) {
            continue;
        }
        let relative = if file_type.is_symlink() {
            let (canonical, _canonical_relative, _requested_path) =
                match ctx.canonical_path_in_root(&request.root_id, entry.path()) {
                    Ok(ok) => ok,
                    Err(Error::OutsideRoot { .. }) | Err(Error::SecretPathDenied(_)) => continue,
                    Err(Error::IoPath {
                        op: "canonicalize",
                        source,
                        ..
                    }) if source.kind() == std::io::ErrorKind::NotFound => {
                        skipped_dangling_symlink_targets =
                            skipped_dangling_symlink_targets.saturating_add(1);
                        continue;
                    }
                    Err(Error::IoPath { .. }) | Err(Error::Io(_)) => {
                        skipped_io_errors = skipped_io_errors.saturating_add(1);
                        continue;
                    }
                    Err(err) => return Err(err),
                };
            let meta = match fs::metadata(&canonical) {
                Ok(meta) => meta,
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                    skipped_dangling_symlink_targets =
                        skipped_dangling_symlink_targets.saturating_add(1);
                    continue;
                }
                Err(_) => {
                    skipped_io_errors = skipped_io_errors.saturating_add(1);
                    continue;
                }
            };
            if !meta.is_file() {
                continue;
            }
            relative.to_path_buf()
        } else {
            relative.to_path_buf()
        };
        if globset_is_match(&matcher, &relative) {
            matches.push(relative);
            if matches.len() >= ctx.policy.limits.max_results {
                truncated = true;
                break;
            }
        }
    }

    matches.sort();
    Ok(GlobResponse {
        matches,
        truncated,
        scanned_files,
        scan_limit_reached,
        scan_limit_reason,
        elapsed_ms: elapsed_ms(&started),
        scanned_entries,
        skipped_walk_errors,
        skipped_io_errors,
        skipped_dangling_symlink_targets,
    })
}

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
    if !ctx.policy.permissions.grep {
        return Err(Error::NotPermitted(
            "grep is disabled by policy".to_string(),
        ));
    }
    let started = Instant::now();
    let max_walk = ctx.policy.limits.max_walk_ms.map(Duration::from_millis);
    let root_path = ctx.canonical_root(&request.root_id)?.clone();
    let walk_root = match request
        .glob
        .as_deref()
        .and_then(derive_safe_traversal_prefix)
    {
        Some(prefix) => {
            let probe = prefix.join(TRAVERSAL_GLOB_PROBE_NAME);
            if ctx.redactor.is_path_denied(&prefix)
                || ctx.redactor.is_path_denied(&probe)
                || ctx.is_traversal_path_skipped(&prefix)
                || ctx.is_traversal_path_skipped(&probe)
            {
                return Ok(GrepResponse {
                    matches: Vec::new(),
                    truncated: false,
                    skipped_too_large_files: 0,
                    skipped_non_utf8_files: 0,
                    scanned_files: 0,
                    scan_limit_reached: false,
                    scan_limit_reason: None,
                    elapsed_ms: elapsed_ms(&started),
                    scanned_entries: 0,
                    skipped_walk_errors: 0,
                    skipped_io_errors: 0,
                    skipped_dangling_symlink_targets: 0,
                });
            }
            root_path.join(prefix)
        }
        None => root_path.clone(),
    };
    if !walk_root.exists() {
        return Ok(GrepResponse {
            matches: Vec::new(),
            truncated: false,
            skipped_too_large_files: 0,
            skipped_non_utf8_files: 0,
            scanned_files: 0,
            scan_limit_reached: false,
            scan_limit_reason: None,
            elapsed_ms: elapsed_ms(&started),
            scanned_entries: 0,
            skipped_walk_errors: 0,
            skipped_io_errors: 0,
            skipped_dangling_symlink_targets: 0,
        });
    }

    let file_glob = request.glob.as_deref().map(compile_glob).transpose()?;

    let regex = if request.regex {
        Some(regex::Regex::new(&request.query).map_err(|err| {
            Error::InvalidRegex(format!("invalid grep regex {:?}: {err}", request.query))
        })?)
    } else {
        None
    };

    let mut matches = Vec::<GrepMatch>::new();
    let mut truncated = false;
    let mut skipped_too_large_files: u64 = 0;
    let mut skipped_non_utf8_files: u64 = 0;
    let mut scanned_files: u64 = 0;
    let mut scanned_entries: u64 = 0;
    let mut scan_limit_reached = false;
    let mut scan_limit_reason: Option<ScanLimitReason> = None;
    let mut skipped_walk_errors: u64 = 0;
    let mut skipped_io_errors: u64 = 0;
    let mut skipped_dangling_symlink_targets: u64 = 0;

    for entry in WalkDir::new(&walk_root)
        .follow_root_links(false)
        .follow_links(false)
        .sort_by_file_name()
        .into_iter()
        .filter_entry(|entry| {
            if entry.depth() == 0 {
                return true;
            }
            let is_dir = entry.file_type().is_dir();
            let relative = entry
                .path()
                .strip_prefix(&root_path)
                .unwrap_or(entry.path());
            let probe = relative.join(TRAVERSAL_GLOB_PROBE_NAME);
            if ctx.redactor.is_path_denied(relative)
                || (is_dir && ctx.redactor.is_path_denied(&probe))
            {
                return false;
            }
            !(ctx.is_traversal_path_skipped(relative)
                || (is_dir && ctx.is_traversal_path_skipped(&probe)))
        })
    {
        if max_walk.is_some_and(|limit| started.elapsed() >= limit) {
            truncated = true;
            scan_limit_reached = true;
            if scan_limit_reason.is_none() {
                scan_limit_reason = Some(ScanLimitReason::Time);
            }
            break;
        }
        let entry = match entry {
            Ok(entry) => entry,
            Err(err) => {
                if err.depth() == 0 {
                    return Err(walkdir_root_error(&root_path, &walk_root, err));
                }
                if scanned_entries as usize >= ctx.policy.limits.max_walk_entries {
                    truncated = true;
                    scan_limit_reached = true;
                    if scan_limit_reason.is_none() {
                        scan_limit_reason = Some(ScanLimitReason::Entries);
                    }
                    break;
                }
                scanned_entries = scanned_entries.saturating_add(1);
                skipped_walk_errors = skipped_walk_errors.saturating_add(1);
                continue;
            }
        };
        if entry.depth() > 0 {
            if scanned_entries as usize >= ctx.policy.limits.max_walk_entries {
                truncated = true;
                scan_limit_reached = true;
                if scan_limit_reason.is_none() {
                    scan_limit_reason = Some(ScanLimitReason::Entries);
                }
                break;
            }
            scanned_entries = scanned_entries.saturating_add(1);
        }
        let file_type = entry.file_type();
        if !(file_type.is_file() || file_type.is_symlink()) {
            continue;
        }
        if scanned_files as usize >= ctx.policy.limits.max_walk_files {
            truncated = true;
            scan_limit_reached = true;
            if scan_limit_reason.is_none() {
                scan_limit_reason = Some(ScanLimitReason::Files);
            }
            break;
        }
        scanned_files = scanned_files.saturating_add(1);
        let relative = entry
            .path()
            .strip_prefix(&root_path)
            .unwrap_or(entry.path());
        if ctx.redactor.is_path_denied(relative) {
            continue;
        }
        let (path, relative_path) = if file_type.is_symlink() {
            let (canonical, _canonical_relative, _requested_path) =
                match ctx.canonical_path_in_root(&request.root_id, entry.path()) {
                    Ok(ok) => ok,
                    Err(Error::OutsideRoot { .. }) | Err(Error::SecretPathDenied(_)) => continue,
                    Err(Error::IoPath {
                        op: "canonicalize",
                        source,
                        ..
                    }) if source.kind() == std::io::ErrorKind::NotFound => {
                        skipped_dangling_symlink_targets =
                            skipped_dangling_symlink_targets.saturating_add(1);
                        continue;
                    }
                    Err(Error::IoPath { .. }) | Err(Error::Io(_)) => {
                        skipped_io_errors = skipped_io_errors.saturating_add(1);
                        continue;
                    }
                    Err(err) => return Err(err),
                };
            let meta = match fs::metadata(&canonical) {
                Ok(meta) => meta,
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                    skipped_dangling_symlink_targets =
                        skipped_dangling_symlink_targets.saturating_add(1);
                    continue;
                }
                Err(_) => {
                    skipped_io_errors = skipped_io_errors.saturating_add(1);
                    continue;
                }
            };
            if !meta.is_file() {
                continue;
            }
            (canonical, relative.to_path_buf())
        } else {
            (entry.path().to_path_buf(), relative.to_path_buf())
        };
        if let Some(glob) = &file_glob
            && !globset_is_match(glob, &relative_path)
        {
            continue;
        }

        let bytes =
            match read_bytes_limited(&path, &relative_path, ctx.policy.limits.max_read_bytes) {
                Ok(bytes) => bytes,
                Err(Error::FileTooLarge { .. }) => {
                    skipped_too_large_files = skipped_too_large_files.saturating_add(1);
                    continue;
                }
                Err(Error::IoPath { .. }) | Err(Error::Io(_)) => {
                    skipped_io_errors = skipped_io_errors.saturating_add(1);
                    continue;
                }
                Err(err) => return Err(err),
            };
        let content = match std::str::from_utf8(&bytes) {
            Ok(content) => content,
            Err(_) => {
                skipped_non_utf8_files = skipped_non_utf8_files.saturating_add(1);
                continue;
            }
        };

        for (idx, line) in content.lines().enumerate() {
            let ok = match &regex {
                Some(regex) => regex.is_match(line),
                None => line.contains(&request.query),
            };
            if !ok {
                continue;
            }
            let line_bytes = line.as_bytes();
            let line_truncated = line_bytes.len() > ctx.policy.limits.max_line_bytes;
            let end = line_bytes.len().min(ctx.policy.limits.max_line_bytes);
            let text = String::from_utf8_lossy(&line_bytes[..end]).to_string();
            let text = ctx.redactor.redact_text(&text);
            matches.push(GrepMatch {
                path: relative_path.clone(),
                line: idx.saturating_add(1) as u64,
                text,
                line_truncated,
            });
            if matches.len() >= ctx.policy.limits.max_results {
                truncated = true;
                break;
            }
        }

        if truncated {
            break;
        }
    }

    matches.sort_by(|a, b| a.path.cmp(&b.path).then_with(|| a.line.cmp(&b.line)));
    Ok(GrepResponse {
        matches,
        truncated,
        skipped_too_large_files,
        skipped_non_utf8_files,
        scanned_files,
        scan_limit_reached,
        scan_limit_reason,
        elapsed_ms: elapsed_ms(&started),
        scanned_entries,
        skipped_walk_errors,
        skipped_io_errors,
        skipped_dangling_symlink_targets,
    })
}

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

    let content = read_string_limited(&path, &relative, ctx.policy.limits.max_read_bytes)?;
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

    write_bytes_atomic(&path, &relative, out.as_bytes())?;
    Ok(EditResponse {
        path: relative,
        requested_path: Some(requested_path),
        bytes_written: out.len() as u64,
    })
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatchRequest {
    pub root_id: String,
    pub path: PathBuf,
    pub patch: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatchResponse {
    pub path: PathBuf,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requested_path: Option<PathBuf>,
    pub bytes_written: u64,
}

#[cfg(not(feature = "patch"))]
pub fn apply_unified_patch(ctx: &Context, request: PatchRequest) -> Result<PatchResponse> {
    let _ = ctx;
    let _ = request;
    Err(Error::NotPermitted(
        "patch is not supported: crate feature 'patch' is disabled".to_string(),
    ))
}

#[cfg(feature = "patch")]
pub fn apply_unified_patch(ctx: &Context, request: PatchRequest) -> Result<PatchResponse> {
    if !ctx.policy.permissions.patch {
        return Err(Error::NotPermitted(
            "patch is disabled by policy".to_string(),
        ));
    }
    ctx.ensure_can_write(&request.root_id, "patch")?;
    let (path, relative, requested_path) =
        ctx.canonical_path_in_root(&request.root_id, &request.path)?;

    let max_patch_bytes = ctx
        .policy
        .limits
        .max_patch_bytes
        .unwrap_or(ctx.policy.limits.max_read_bytes);
    let patch_bytes = request.patch.len() as u64;
    if patch_bytes > max_patch_bytes {
        return Err(Error::InputTooLarge {
            size_bytes: patch_bytes,
            max_bytes: max_patch_bytes,
        });
    }

    let content = read_string_limited(&path, &relative, ctx.policy.limits.max_read_bytes)?;
    let parsed = Patch::from_str(&request.patch).map_err(|err| Error::Patch(err.to_string()))?;
    let updated = apply(&content, &parsed).map_err(|err| Error::Patch(err.to_string()))?;

    if updated.len() as u64 > ctx.policy.limits.max_write_bytes {
        return Err(Error::FileTooLarge {
            path: relative.clone(),
            size_bytes: updated.len() as u64,
            max_bytes: ctx.policy.limits.max_write_bytes,
        });
    }

    write_bytes_atomic(&path, &relative, updated.as_bytes())?;
    Ok(PatchResponse {
        path: relative,
        requested_path: Some(requested_path),
        bytes_written: updated.len() as u64,
    })
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeleteRequest {
    pub root_id: String,
    pub path: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeleteResponse {
    pub path: PathBuf,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requested_path: Option<PathBuf>,
}

pub fn delete_file(ctx: &Context, request: DeleteRequest) -> Result<DeleteResponse> {
    if !ctx.policy.permissions.delete {
        return Err(Error::NotPermitted(
            "delete is disabled by policy".to_string(),
        ));
    }
    ctx.ensure_can_write(&request.root_id, "delete")?;

    let resolved = ctx.policy.resolve_path(&request.root_id, &request.path)?;
    let root = ctx.policy.root(&request.root_id)?;
    let canonical_root = ctx.canonical_root(&request.root_id)?;
    let relative_requested = if request.path.is_absolute() {
        resolved
            .strip_prefix(&root.path)
            .or_else(|_| resolved.strip_prefix(canonical_root))
            .map(|path| path.to_path_buf())
            .unwrap_or_else(|_| resolved.clone())
    } else {
        request.path.clone()
    };
    let requested_path = normalize_path_lexical(&relative_requested);

    let file_name = resolved
        .file_name()
        .ok_or_else(|| Error::InvalidPath("delete requires a file path (got empty)".to_string()))?;
    if file_name == std::ffi::OsStr::new(".") || file_name == std::ffi::OsStr::new("..") {
        return Err(Error::InvalidPath(format!(
            "invalid delete path {:?}",
            request.path
        )));
    }

    let parent = resolved.parent().ok_or_else(|| {
        Error::InvalidPath(format!(
            "invalid delete path {:?}: missing parent directory",
            request.path
        ))
    })?;
    let canonical_parent = match parent.canonicalize() {
        Ok(canonical) => canonical,
        Err(err) => return Err(Error::io_path("canonicalize", requested_path, err)),
    };
    if !canonical_parent.starts_with(canonical_root) {
        return Err(Error::OutsideRoot {
            root_id: request.root_id.clone(),
            path: requested_path,
        });
    }

    let relative_parent = canonical_parent
        .strip_prefix(canonical_root)
        .unwrap_or(&canonical_parent);
    let relative = relative_parent.join(file_name);
    if ctx.redactor.is_path_denied(&relative) {
        return Err(Error::SecretPathDenied(relative));
    }

    let meta = fs::symlink_metadata(&resolved)
        .map_err(|err| Error::io_path("metadata", &relative, err))?;
    if meta.is_dir() {
        return Err(Error::InvalidPath("delete only supports files".to_string()));
    }

    fs::remove_file(&resolved).map_err(|err| Error::io_path("remove_file", &relative, err))?;
    Ok(DeleteResponse {
        path: relative,
        requested_path: Some(requested_path),
    })
}
