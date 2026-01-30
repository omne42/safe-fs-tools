use std::fs;
use std::io::{BufRead, Read, Write};
use std::path::{Path, PathBuf};
#[cfg(any(feature = "glob", feature = "grep"))]
use std::time::{Duration, Instant};

#[cfg(feature = "patch")]
use diffy::{Patch, apply};
#[cfg(any(feature = "glob", feature = "grep"))]
use globset::{GlobSet, GlobSetBuilder};
use serde::{Deserialize, Serialize};
#[cfg(any(feature = "glob", feature = "grep"))]
use walkdir::WalkDir;

use crate::error::{Error, Result};
use crate::policy::{RootMode, SandboxPolicy};
use crate::redaction::SecretRedactor;

#[cfg(any(feature = "glob", feature = "grep"))]
// A synthetic file name used to apply deny/skip glob patterns to directories: for each directory
// entry `dir`, we also evaluate `dir/<probe>` against glob rules so patterns like `node_modules/*`
// or `**/.git/**` can exclude entire directories (and avoid descending into them).
const TRAVERSAL_GLOB_PROBE_NAME: &str = ".safe-fs-tools-probe";

fn derive_requested_path(
    root_path: &Path,
    canonical_root: &Path,
    input: &Path,
    resolved: &Path,
) -> PathBuf {
    let relative_requested = if input.is_absolute() {
        let normalized_resolved = crate::path_utils::normalize_path_lexical(resolved);
        let normalized_root_path = crate::path_utils::normalize_path_lexical(root_path);
        let normalized_canonical_root = crate::path_utils::normalize_path_lexical(canonical_root);

        crate::path_utils::strip_prefix_case_insensitive(
            &normalized_resolved,
            &normalized_root_path,
        )
        .or_else(|| {
            crate::path_utils::strip_prefix_case_insensitive(
                &normalized_resolved,
                &normalized_canonical_root,
            )
        })
        .unwrap_or_else(|| resolved.to_path_buf())
    } else {
        input.to_path_buf()
    };

    let normalized = crate::path_utils::normalize_path_lexical(&relative_requested);
    if normalized.as_os_str().is_empty() {
        PathBuf::from(".")
    } else {
        normalized
    }
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

#[cfg(all(test, unix))]
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
    let _ = path.file_name().ok_or_else(|| {
        Error::InvalidPath(format!(
            "invalid path {}: missing file name",
            relative.display()
        ))
    })?;

    let mut tmp_file = tempfile::Builder::new()
        .prefix(".safe-fs-tools.")
        .suffix(".tmp")
        .tempfile_in(parent)
        .map_err(|err| Error::io_path("create_temp", relative, err))?;

    tmp_file
        .as_file_mut()
        .write_all(bytes)
        .map_err(|err| Error::io_path("write", relative, err))?;
    tmp_file
        .as_file_mut()
        .sync_all()
        .map_err(|err| Error::io_path("sync", relative, err))?;

    let tmp_path = tmp_file.into_temp_path();

    fs::set_permissions(&tmp_path, perms)
        .map_err(|err| Error::io_path("set_permissions", relative, err))?;

    replace_file(tmp_path.as_ref(), path)
        .map_err(|err| Error::io_path("replace_file", relative, err))?;

    Ok(())
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
    let relative = crate::path_utils::strip_prefix_case_insensitive(walk_root, root_path)
        .filter(|relative| !relative.as_os_str().is_empty())
        .unwrap_or_else(|| PathBuf::from("."));

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
        #[cfg(windows)]
        {
            assert_eq!(derive_safe_traversal_prefix("C:/foo/*"), None);
            assert_eq!(derive_safe_traversal_prefix("c:foo/*"), None);
            assert_eq!(derive_safe_traversal_prefix("C:"), None);
            assert_eq!(derive_safe_traversal_prefix("src/c:foo/*"), None);
            assert_eq!(derive_safe_traversal_prefix("a/b/c:tmp/**"), None);
        }
    }

    #[test]
    #[cfg(any(feature = "glob", feature = "grep"))]
    fn walk_traversal_files_rejects_walk_root_outside_root() {
        let dir = tempfile::tempdir().expect("tempdir");
        let policy = SandboxPolicy::single_root("root", dir.path(), RootMode::ReadOnly);
        let ctx = Context::new(policy).expect("ctx");

        let root_path = ctx.canonical_root("root").expect("root").clone();
        let walk_root = root_path.parent().expect("parent").to_path_buf();

        let err = walk_traversal_files(
            &ctx,
            "root",
            &root_path,
            &walk_root,
            &Instant::now(),
            None,
            |_file, _diag| Ok(std::ops::ControlFlow::Continue(())),
        )
        .unwrap_err();

        assert_eq!(err.code(), "invalid_path");
    }

    #[test]
    #[cfg(any(feature = "glob", feature = "grep"))]
    fn traversal_skip_globs_apply_to_directories_via_probe() {
        let dir = tempfile::tempdir().expect("tempdir");
        fs::create_dir_all(dir.path().join("node_modules").join("sub")).expect("mkdir");
        fs::write(dir.path().join("keep.txt"), "keep\n").expect("write");
        fs::write(dir.path().join("node_modules").join("skip.txt"), "skip\n").expect("write");
        fs::write(
            dir.path()
                .join("node_modules")
                .join("sub")
                .join("keep2.txt"),
            "keep\n",
        )
        .expect("write");

        let mut policy = SandboxPolicy::single_root("root", dir.path(), RootMode::ReadOnly);
        policy.traversal.skip_globs = vec!["node_modules/*".to_string()];
        let ctx = Context::new(policy).expect("ctx");

        assert!(
            !ctx.is_traversal_path_skipped(Path::new("node_modules")),
            "expected the skip glob not to match the directory itself"
        );
        let probe = Path::new("node_modules").join(TRAVERSAL_GLOB_PROBE_NAME);
        assert!(
            ctx.is_traversal_path_skipped(&probe),
            "expected the skip glob to match the probe path"
        );

        let root_path = ctx.canonical_root("root").expect("root").clone();
        let seen = walkdir_traversal_iter(&ctx, &root_path, &root_path)
            .filter_map(|entry| entry.ok())
            .filter(|entry| entry.depth() > 0)
            .map(|entry| {
                entry
                    .path()
                    .strip_prefix(&root_path)
                    .unwrap_or(entry.path())
                    .to_path_buf()
            })
            .collect::<Vec<_>>();

        assert!(
            seen.iter().any(|path| path == Path::new("keep.txt")),
            "expected keep.txt to be traversed, saw: {seen:?}"
        );
        assert!(
            !seen
                .iter()
                .any(|path| path.starts_with(Path::new("node_modules"))),
            "expected node_modules to be excluded via probe semantics, saw: {seen:?}"
        );
    }

    #[test]
    #[cfg(unix)]
    fn normalize_path_lexical_does_not_escape_filesystem_root() {
        assert_eq!(
            crate::path_utils::normalize_path_lexical(Path::new("/../etc")),
            PathBuf::from("/etc")
        );
        assert_eq!(
            crate::path_utils::normalize_path_lexical(Path::new("/a/../../b")),
            PathBuf::from("/b")
        );
    }

    #[test]
    fn normalize_path_lexical_preserves_leading_parent_dirs() {
        assert_eq!(
            crate::path_utils::normalize_path_lexical(Path::new("../..")),
            PathBuf::from("../..")
        );
        assert_eq!(
            crate::path_utils::normalize_path_lexical(Path::new("../../a/../b")),
            PathBuf::from("../../b")
        );
        assert_eq!(
            crate::path_utils::normalize_path_lexical(Path::new("a/../../b")),
            PathBuf::from("../b")
        );
    }

    #[test]
    fn requested_path_for_dot_is_not_empty() {
        let dir = tempfile::tempdir().expect("tempdir");
        let policy = SandboxPolicy::single_root("root", dir.path(), RootMode::ReadOnly);
        let ctx = Context::new(policy).expect("ctx");

        let (_canonical, relative, requested_path) = ctx
            .canonical_path_in_root("root", Path::new("."))
            .expect("canonicalize");
        assert_eq!(relative, PathBuf::from("."));
        assert_eq!(requested_path, PathBuf::from("."));
    }

    #[test]
    #[cfg(windows)]
    fn normalize_path_lexical_preserves_prefix_root() {
        assert_eq!(
            crate::path_utils::normalize_path_lexical(Path::new(r"C:\..\foo")),
            PathBuf::from(r"C:\foo")
        );
    }

    #[test]
    #[cfg(windows)]
    fn normalize_path_lexical_preserves_unc_prefix_root() {
        assert_eq!(
            crate::path_utils::normalize_path_lexical(Path::new(r"\\server\share\..\foo")),
            PathBuf::from(r"\\server\share\foo")
        );
    }

    #[test]
    #[cfg(windows)]
    fn normalize_path_lexical_preserves_verbatim_prefix_root() {
        assert_eq!(
            crate::path_utils::normalize_path_lexical(Path::new(r"\\?\C:\..\foo")),
            PathBuf::from(r"\\?\C:\foo")
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

    fn reject_secret_path(&self, path: PathBuf) -> Result<PathBuf> {
        if self.redactor.is_path_denied(&path) {
            return Err(Error::SecretPathDenied(path));
        }
        Ok(path)
    }

    fn canonical_path_in_root(
        &self,
        root_id: &str,
        path: &Path,
    ) -> Result<(PathBuf, PathBuf, PathBuf)> {
        let resolved = self.policy.resolve_path(root_id, path)?;
        let root = self.policy.root(root_id)?;
        let canonical_root = self.canonical_root(root_id)?;

        let normalized_resolved = crate::path_utils::normalize_path_lexical(&resolved);
        let normalized_root_path = crate::path_utils::normalize_path_lexical(&root.path);
        let normalized_canonical_root = crate::path_utils::normalize_path_lexical(canonical_root);

        let lexically_in_root = crate::path_utils::starts_with_case_insensitive(
            &normalized_resolved,
            &normalized_root_path,
        ) || crate::path_utils::starts_with_case_insensitive(
            &normalized_resolved,
            &normalized_canonical_root,
        );

        if !lexically_in_root {
            let requested_path = if path.is_absolute() {
                normalized_resolved
            } else {
                derive_requested_path(&root.path, canonical_root, path, &resolved)
            };
            let requested_path = self.reject_secret_path(requested_path)?;
            return Err(Error::OutsideRoot {
                root_id: root_id.to_string(),
                path: requested_path,
            });
        }

        let requested_path = self.reject_secret_path(derive_requested_path(
            &root.path,
            canonical_root,
            path,
            &resolved,
        ))?;

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
                        let resolved_target =
                            crate::path_utils::normalize_path_lexical(&resolved_target);
                        if !crate::path_utils::starts_with_case_insensitive(
                            &resolved_target,
                            canonical_root,
                        ) {
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
        if !crate::path_utils::starts_with_case_insensitive(&canonical, canonical_root) {
            return Err(Error::OutsideRoot {
                root_id: root_id.to_string(),
                path: requested_path,
            });
        }
        let relative = crate::path_utils::strip_prefix_case_insensitive(&canonical, canonical_root)
            .unwrap_or(canonical.clone());
        let relative = if relative.as_os_str().is_empty() {
            PathBuf::from(".")
        } else {
            relative
        };
        let relative = self.reject_secret_path(relative)?;
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

            let file_size_bytes = fs::metadata(&path).ok().map(|meta| meta.len());
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
                    let size_bytes = file_size_bytes.unwrap_or(scanned_bytes).max(scanned_bytes);
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
    Results,
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
fn compile_glob(pattern: &str) -> Result<GlobSet> {
    let normalized = crate::path_utils::normalize_glob_pattern_for_matching(pattern);
    crate::path_utils::validate_root_relative_glob_pattern(&normalized)
        .map_err(|msg| Error::InvalidPath(format!("invalid glob pattern {pattern:?}: {msg}")))?;
    let glob = crate::path_utils::build_glob_from_normalized(&normalized)
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
        let normalized = crate::path_utils::normalize_glob_pattern_for_matching(pattern);
        crate::path_utils::validate_root_relative_glob_pattern(&normalized).map_err(|msg| {
            Error::InvalidPolicy(format!(
                "invalid traversal.skip_globs glob {pattern:?}: {msg}"
            ))
        })?;
        let glob = crate::path_utils::build_glob_from_normalized(&normalized).map_err(|err| {
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
    let pattern = crate::path_utils::normalize_glob_pattern(pattern);
    let pattern = pattern.as_ref();
    if pattern.starts_with('/') {
        return None;
    }
    #[cfg(windows)]
    {
        let bytes = pattern.as_bytes();
        if bytes.len() >= 2 && bytes[1] == b':' && bytes[0].is_ascii_alphabetic() {
            // Drive-prefix paths (e.g. `C:...`, `C:/...`) would cause `PathBuf::join` to
            // discard the root prefix, allowing traversal outside the selected root.
            return None;
        }
    }

    let mut out = PathBuf::new();
    for segment in pattern.split('/') {
        if segment.is_empty() || segment == "." {
            continue;
        }
        #[cfg(windows)]
        {
            use std::path::Component;

            if matches!(
                Path::new(segment).components().next(),
                Some(Component::Prefix(_))
            ) {
                // Windows drive/prefix components in later segments can cause `PathBuf::push/join`
                // to discard prior components, allowing traversal outside the selected root.
                return None;
            }
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

#[cfg(any(feature = "glob", feature = "grep"))]
#[derive(Debug, Default, Clone)]
struct TraversalDiagnostics {
    truncated: bool,
    scanned_files: u64,
    scanned_entries: u64,
    scan_limit_reached: bool,
    scan_limit_reason: Option<ScanLimitReason>,
    skipped_walk_errors: u64,
    skipped_io_errors: u64,
    skipped_dangling_symlink_targets: u64,
}

#[cfg(any(feature = "glob", feature = "grep"))]
struct TraversalFile {
    path: PathBuf,
    relative_path: PathBuf,
}

#[cfg(any(feature = "glob", feature = "grep"))]
fn walkdir_traversal_iter<'a>(
    ctx: &'a Context,
    root_path: &'a Path,
    walk_root: &'a Path,
) -> impl Iterator<Item = walkdir::Result<walkdir::DirEntry>> + 'a {
    WalkDir::new(walk_root)
        .follow_root_links(false)
        .follow_links(false)
        .sort_by_file_name()
        .into_iter()
        .filter_entry(move |entry| {
            if entry.depth() == 0 {
                return true;
            }
            let is_dir = entry.file_type().is_dir();
            let relative = entry.path().strip_prefix(root_path).unwrap_or(entry.path());
            let probe = relative.join(TRAVERSAL_GLOB_PROBE_NAME);
            if ctx.redactor.is_path_denied(relative)
                || (is_dir && ctx.redactor.is_path_denied(&probe))
            {
                return false;
            }
            !(ctx.is_traversal_path_skipped(relative)
                || (is_dir && ctx.is_traversal_path_skipped(&probe)))
        })
}

#[cfg(any(feature = "glob", feature = "grep"))]
fn walk_traversal_files(
    ctx: &Context,
    root_id: &str,
    root_path: &Path,
    walk_root: &Path,
    started: &Instant,
    max_walk: Option<Duration>,
    mut on_file: impl FnMut(
        TraversalFile,
        &mut TraversalDiagnostics,
    ) -> Result<std::ops::ControlFlow<()>>,
) -> Result<TraversalDiagnostics> {
    if !walk_root.starts_with(root_path) {
        return Err(Error::InvalidPath(
            "derived traversal root escapes selected root".to_string(),
        ));
    }

    let mut diag = TraversalDiagnostics::default();

    for entry in walkdir_traversal_iter(ctx, root_path, walk_root) {
        if max_walk.is_some_and(|limit| started.elapsed() >= limit) {
            diag.truncated = true;
            diag.scan_limit_reached = true;
            if diag.scan_limit_reason.is_none() {
                diag.scan_limit_reason = Some(ScanLimitReason::Time);
            }
            break;
        }

        let entry = match entry {
            Ok(entry) => entry,
            Err(err) => {
                if err.depth() == 0 {
                    return Err(walkdir_root_error(root_path, walk_root, err));
                }
                if diag.scanned_entries as usize >= ctx.policy.limits.max_walk_entries {
                    diag.truncated = true;
                    diag.scan_limit_reached = true;
                    if diag.scan_limit_reason.is_none() {
                        diag.scan_limit_reason = Some(ScanLimitReason::Entries);
                    }
                    break;
                }
                diag.scanned_entries = diag.scanned_entries.saturating_add(1);
                diag.skipped_walk_errors = diag.skipped_walk_errors.saturating_add(1);
                continue;
            }
        };

        if entry.depth() > 0 {
            if diag.scanned_entries as usize >= ctx.policy.limits.max_walk_entries {
                diag.truncated = true;
                diag.scan_limit_reached = true;
                if diag.scan_limit_reason.is_none() {
                    diag.scan_limit_reason = Some(ScanLimitReason::Entries);
                }
                break;
            }
            diag.scanned_entries = diag.scanned_entries.saturating_add(1);
        }

        let file_type = entry.file_type();
        if !(file_type.is_file() || file_type.is_symlink()) {
            continue;
        }
        if diag.scanned_files as usize >= ctx.policy.limits.max_walk_files {
            diag.truncated = true;
            diag.scan_limit_reached = true;
            if diag.scan_limit_reason.is_none() {
                diag.scan_limit_reason = Some(ScanLimitReason::Files);
            }
            break;
        }
        diag.scanned_files = diag.scanned_files.saturating_add(1);

        let relative = crate::path_utils::strip_prefix_case_insensitive(entry.path(), root_path)
            .unwrap_or_else(|| entry.path().to_path_buf());
        if ctx.redactor.is_path_denied(&relative) {
            continue;
        }

        let file = if file_type.is_symlink() {
            let (canonical, _canonical_relative, _requested_path) =
                match ctx.canonical_path_in_root(root_id, &relative) {
                    Ok(ok) => ok,
                    Err(Error::OutsideRoot { .. }) | Err(Error::SecretPathDenied(_)) => continue,
                    Err(Error::IoPath {
                        op: "canonicalize",
                        source,
                        ..
                    }) if source.kind() == std::io::ErrorKind::NotFound => {
                        diag.skipped_dangling_symlink_targets =
                            diag.skipped_dangling_symlink_targets.saturating_add(1);
                        continue;
                    }
                    Err(Error::IoPath { .. }) | Err(Error::Io(_)) => {
                        diag.skipped_io_errors = diag.skipped_io_errors.saturating_add(1);
                        continue;
                    }
                    Err(err) => return Err(err),
                };
            let meta = match fs::metadata(&canonical) {
                Ok(meta) => meta,
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                    diag.skipped_dangling_symlink_targets =
                        diag.skipped_dangling_symlink_targets.saturating_add(1);
                    continue;
                }
                Err(_) => {
                    diag.skipped_io_errors = diag.skipped_io_errors.saturating_add(1);
                    continue;
                }
            };
            if !meta.is_file() {
                continue;
            }
            TraversalFile {
                path: canonical,
                relative_path: relative,
            }
        } else {
            TraversalFile {
                path: entry.path().to_path_buf(),
                relative_path: relative,
            }
        };

        match on_file(file, &mut diag)? {
            std::ops::ControlFlow::Continue(()) => {}
            std::ops::ControlFlow::Break(()) => break,
        }
    }

    Ok(diag)
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
    let mut diag = TraversalDiagnostics::default();
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
                    truncated: diag.truncated,
                    scanned_files: diag.scanned_files,
                    scan_limit_reached: diag.scan_limit_reached,
                    scan_limit_reason: diag.scan_limit_reason,
                    elapsed_ms: elapsed_ms(&started),
                    scanned_entries: diag.scanned_entries,
                    skipped_walk_errors: diag.skipped_walk_errors,
                    skipped_io_errors: diag.skipped_io_errors,
                    skipped_dangling_symlink_targets: diag.skipped_dangling_symlink_targets,
                });
            }
            root_path.join(prefix)
        }
        None => root_path.clone(),
    };
    if !walk_root.exists() {
        return Ok(GlobResponse {
            matches,
            truncated: diag.truncated,
            scanned_files: diag.scanned_files,
            scan_limit_reached: diag.scan_limit_reached,
            scan_limit_reason: diag.scan_limit_reason,
            elapsed_ms: elapsed_ms(&started),
            scanned_entries: diag.scanned_entries,
            skipped_walk_errors: diag.skipped_walk_errors,
            skipped_io_errors: diag.skipped_io_errors,
            skipped_dangling_symlink_targets: diag.skipped_dangling_symlink_targets,
        });
    }
    diag = walk_traversal_files(
        ctx,
        &request.root_id,
        &root_path,
        &walk_root,
        &started,
        max_walk,
        |file, diag| {
            if globset_is_match(&matcher, &file.relative_path) {
                matches.push(file.relative_path);
                if matches.len() >= ctx.policy.limits.max_results {
                    diag.truncated = true;
                    diag.scan_limit_reached = true;
                    diag.scan_limit_reason = Some(ScanLimitReason::Results);
                    return Ok(std::ops::ControlFlow::Break(()));
                }
            }
            Ok(std::ops::ControlFlow::Continue(()))
        },
    )?;

    matches.sort();
    Ok(GlobResponse {
        matches,
        truncated: diag.truncated,
        scanned_files: diag.scanned_files,
        scan_limit_reached: diag.scan_limit_reached,
        scan_limit_reason: diag.scan_limit_reason,
        elapsed_ms: elapsed_ms(&started),
        scanned_entries: diag.scanned_entries,
        skipped_walk_errors: diag.skipped_walk_errors,
        skipped_io_errors: diag.skipped_io_errors,
        skipped_dangling_symlink_targets: diag.skipped_dangling_symlink_targets,
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
    let mut skipped_too_large_files: u64 = 0;
    let mut skipped_non_utf8_files: u64 = 0;

    let diag = walk_traversal_files(
        ctx,
        &request.root_id,
        &root_path,
        &walk_root,
        &started,
        max_walk,
        |file, diag| {
            if let Some(glob) = &file_glob
                && !globset_is_match(glob, &file.relative_path)
            {
                return Ok(std::ops::ControlFlow::Continue(()));
            }

            let bytes = match read_bytes_limited(
                &file.path,
                &file.relative_path,
                ctx.policy.limits.max_read_bytes,
            ) {
                Ok(bytes) => bytes,
                Err(Error::FileTooLarge { .. }) => {
                    skipped_too_large_files = skipped_too_large_files.saturating_add(1);
                    return Ok(std::ops::ControlFlow::Continue(()));
                }
                Err(Error::IoPath { .. }) | Err(Error::Io(_)) => {
                    diag.skipped_io_errors = diag.skipped_io_errors.saturating_add(1);
                    return Ok(std::ops::ControlFlow::Continue(()));
                }
                Err(err) => return Err(err),
            };
            let content = match std::str::from_utf8(&bytes) {
                Ok(content) => content,
                Err(_) => {
                    skipped_non_utf8_files = skipped_non_utf8_files.saturating_add(1);
                    return Ok(std::ops::ControlFlow::Continue(()));
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
                let line_truncated = line.len() > ctx.policy.limits.max_line_bytes;
                let mut end = line.len().min(ctx.policy.limits.max_line_bytes);
                while end > 0 && !line.is_char_boundary(end) {
                    end = end.saturating_sub(1);
                }
                let text = line[..end].to_string();
                let text = ctx.redactor.redact_text(&text);
                matches.push(GrepMatch {
                    path: file.relative_path.clone(),
                    line: idx.saturating_add(1) as u64,
                    text,
                    line_truncated,
                });
                if matches.len() >= ctx.policy.limits.max_results {
                    diag.truncated = true;
                    diag.scan_limit_reached = true;
                    diag.scan_limit_reason = Some(ScanLimitReason::Results);
                    return Ok(std::ops::ControlFlow::Break(()));
                }
            }

            Ok(std::ops::ControlFlow::Continue(()))
        },
    )?;

    matches.sort_by(|a, b| a.path.cmp(&b.path).then_with(|| a.line.cmp(&b.line)));
    Ok(GrepResponse {
        matches,
        truncated: diag.truncated,
        skipped_too_large_files,
        skipped_non_utf8_files,
        scanned_files: diag.scanned_files,
        scan_limit_reached: diag.scan_limit_reached,
        scan_limit_reason: diag.scan_limit_reason,
        elapsed_ms: elapsed_ms(&started),
        scanned_entries: diag.scanned_entries,
        skipped_walk_errors: diag.skipped_walk_errors,
        skipped_io_errors: diag.skipped_io_errors,
        skipped_dangling_symlink_targets: diag.skipped_dangling_symlink_targets,
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
    let normalized_resolved = crate::path_utils::normalize_path_lexical(&resolved);
    let normalized_root_path = crate::path_utils::normalize_path_lexical(&root.path);
    let normalized_canonical_root = crate::path_utils::normalize_path_lexical(canonical_root);

    let is_lexically_within_root = crate::path_utils::starts_with_case_insensitive(
        &normalized_resolved,
        &normalized_root_path,
    ) || crate::path_utils::starts_with_case_insensitive(
        &normalized_resolved,
        &normalized_canonical_root,
    );

    let requested_path = if is_lexically_within_root || !request.path.is_absolute() {
        derive_requested_path(&root.path, canonical_root, &request.path, &resolved)
    } else {
        normalized_resolved.clone()
    };

    if ctx.redactor.is_path_denied(&requested_path) {
        return Err(Error::SecretPathDenied(requested_path));
    }

    if !is_lexically_within_root {
        return Err(Error::OutsideRoot {
            root_id: request.root_id.clone(),
            path: requested_path,
        });
    }

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
    if !crate::path_utils::starts_with_case_insensitive(&canonical_parent, canonical_root) {
        return Err(Error::OutsideRoot {
            root_id: request.root_id.clone(),
            path: requested_path,
        });
    }

    let relative_parent =
        crate::path_utils::strip_prefix_case_insensitive(&canonical_parent, canonical_root)
            .unwrap_or(canonical_parent);
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
