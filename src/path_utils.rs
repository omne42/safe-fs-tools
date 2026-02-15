//! Path utilities used across policy/path validation and traversal.
//!
//! This module is intentionally **lexical**: it does not touch the filesystem and therefore does
//! not resolve symlinks. Its job is to normalize and compare paths in a way that is predictable
//! across platforms.
//!
//! Invariants of `normalize_path_lexical`:
//! - Removes `.` segments.
//! - Resolves `..` against preceding *normal* segments when possible.
//! - Preserves leading `..` for relative paths (e.g. `../../a/../b` → `../../b`).
//! - For absolute paths, `..` cannot escape the filesystem root (e.g. `/../etc` → `/etc`).
//! - On Windows, preserves path prefixes (Disk/UNC/verbatim) and does not drop them when
//!   normalizing.
use std::borrow::Cow;
#[cfg(windows)]
use std::ffi::OsStr;
use std::ffi::OsString;
use std::path::{Component, Path, PathBuf};

use globset::GlobBuilder;

#[cfg(windows)]
#[inline]
pub(crate) fn normalize_glob_pattern(pattern: &str) -> Cow<'_, str> {
    if !pattern.contains('\\') {
        return Cow::Borrowed(pattern);
    }
    Cow::Owned(pattern.replace('\\', "/"))
}

#[cfg(not(windows))]
#[inline]
pub(crate) fn normalize_glob_pattern(pattern: &str) -> Cow<'_, str> {
    Cow::Borrowed(pattern)
}

pub(crate) fn normalize_glob_pattern_for_matching(pattern: &str) -> String {
    let normalized = normalize_glob_pattern(pattern);
    let mut trimmed = normalized.as_ref();
    while let Some(rest) = trimmed.strip_prefix("./") {
        trimmed = rest;
    }
    if trimmed.is_empty() {
        ".".to_string()
    } else {
        trimmed.to_string()
    }
}

pub(crate) fn validate_root_relative_glob_pattern(
    pattern: &str,
) -> std::result::Result<(), &'static str> {
    let normalized = normalize_glob_pattern(pattern);
    let pattern = normalized.as_ref();

    if pattern.starts_with('/') {
        return Err("glob patterns must be root-relative (must not start with '/')");
    }

    #[cfg(windows)]
    {
        let bytes = pattern.as_bytes();
        if bytes.len() >= 2 && bytes[1] == b':' && bytes[0].is_ascii_alphabetic() {
            return Err(
                "glob patterns must be root-relative (drive letter prefixes are not supported)",
            );
        }
    }

    if pattern.split('/').any(|segment| segment == "..") {
        return Err("glob patterns must not contain '..' segments");
    }

    Ok(())
}

pub(crate) fn build_glob_from_normalized(
    pattern: &str,
) -> std::result::Result<globset::Glob, globset::Error> {
    let mut builder = GlobBuilder::new(pattern);
    builder.literal_separator(true);
    #[cfg(windows)]
    builder.case_insensitive(true);
    builder.build()
}

pub(crate) fn normalize_path_lexical(path: &Path) -> PathBuf {
    #[derive(Debug)]
    enum Segment {
        ParentDir,
        Normal(OsString),
    }

    let mut path_prefix: Option<OsString> = None;
    let mut has_root = false;
    let mut segments: Vec<Segment> = Vec::new();

    for comp in path.components() {
        match comp {
            Component::CurDir => {}
            Component::ParentDir => {
                if matches!(segments.last(), Some(Segment::Normal(_))) {
                    segments.pop();
                } else if !has_root {
                    segments.push(Segment::ParentDir);
                }
            }
            Component::Normal(part) => segments.push(Segment::Normal(part.to_os_string())),
            Component::RootDir => {
                has_root = true;
            }
            Component::Prefix(prefix_comp) => {
                path_prefix = Some(prefix_comp.as_os_str().to_os_string());
            }
        }
    }

    let mut out = PathBuf::new();
    if let Some(prefix) = path_prefix {
        out.push(Path::new(&prefix));
    }
    if has_root {
        if out.as_os_str().is_empty() {
            #[cfg(windows)]
            out.push("\\");
            #[cfg(not(windows))]
            out.push("/");
        } else {
            // On Windows, pushing `RootDir` after `Prefix` would reset the path (dropping
            // the prefix). Append a separator instead.
            #[cfg(windows)]
            {
                out.as_mut_os_string()
                    .push(std::path::MAIN_SEPARATOR.to_string());
            }
            #[cfg(not(windows))]
            {
                out.push("/");
            }
        }
    }
    for segment in segments {
        match segment {
            Segment::ParentDir => out.push(".."),
            Segment::Normal(part) => out.push(part),
        }
    }

    if out.as_os_str().is_empty() && path.is_relative() {
        PathBuf::from(".")
    } else {
        out
    }
}

#[cfg(windows)]
#[inline]
fn os_str_eq_case_insensitive_windows(a: &OsStr, b: &OsStr) -> bool {
    crate::platform::windows_path_compare::os_str_eq_case_insensitive(a, b)
}

#[cfg(windows)]
#[inline]
fn prefixes_eq(a: std::path::Prefix<'_>, b: std::path::Prefix<'_>) -> bool {
    use std::path::Prefix::*;

    match (a, b) {
        (Disk(a), Disk(b))
        | (Disk(a), VerbatimDisk(b))
        | (VerbatimDisk(a), Disk(b))
        | (VerbatimDisk(a), VerbatimDisk(b)) => a.to_ascii_lowercase() == b.to_ascii_lowercase(),
        (UNC(a_server, a_share), UNC(b_server, b_share))
        | (UNC(a_server, a_share), VerbatimUNC(b_server, b_share))
        | (VerbatimUNC(a_server, a_share), UNC(b_server, b_share))
        | (VerbatimUNC(a_server, a_share), VerbatimUNC(b_server, b_share)) => {
            os_str_eq_case_insensitive_windows(a_server, b_server)
                && os_str_eq_case_insensitive_windows(a_share, b_share)
        }
        (Verbatim(a), Verbatim(b)) => os_str_eq_case_insensitive_windows(a, b),
        (DeviceNS(a), DeviceNS(b)) => os_str_eq_case_insensitive_windows(a, b),
        _ => false,
    }
}

#[cfg(windows)]
#[inline]
fn components_eq_case_insensitive(a: Component<'_>, b: Component<'_>) -> bool {
    match (a, b) {
        (Component::Prefix(a), Component::Prefix(b)) => prefixes_eq(a.kind(), b.kind()),
        (Component::RootDir, Component::RootDir) => true,
        (Component::Normal(a), Component::Normal(b)) => os_str_eq_case_insensitive_windows(a, b),
        (Component::CurDir, Component::CurDir) => true,
        (Component::ParentDir, Component::ParentDir) => true,
        _ => false,
    }
}

#[inline]
fn is_lexically_normalized_for_boundary(path: &Path) -> bool {
    path.as_os_str().is_empty() || normalize_path_lexical(path) == path
}

#[inline]
fn normalized_for_boundary(path: &Path) -> Cow<'_, Path> {
    if is_lexically_normalized_for_boundary(path) {
        Cow::Borrowed(path)
    } else {
        Cow::Owned(normalize_path_lexical(path))
    }
}

/// A case-insensitive `Path::starts_with` for Windows paths.
///
/// This function is purely lexical and does not resolve symlinks.
/// Inputs are normalized lexically before comparison.
///
/// On non-Windows platforms this is equivalent to `Path::starts_with`.
#[inline]
pub fn starts_with_case_insensitive(path: &Path, prefix: &Path) -> bool {
    let path = normalized_for_boundary(path);
    let prefix = normalized_for_boundary(prefix);
    let path = path.as_ref();
    let prefix = prefix.as_ref();

    debug_assert!(
        is_lexically_normalized_for_boundary(path),
        "starts_with_case_insensitive requires normalized `path` input, got: {path:?}"
    );
    debug_assert!(
        is_lexically_normalized_for_boundary(prefix),
        "starts_with_case_insensitive requires normalized `prefix` input, got: {prefix:?}"
    );

    #[cfg(windows)]
    {
        let mut path_components = path.components();
        for prefix_comp in prefix.components() {
            let Some(path_comp) = path_components.next() else {
                return false;
            };

            if !components_eq_case_insensitive(path_comp, prefix_comp) {
                return false;
            }
        }
        true
    }

    #[cfg(not(windows))]
    {
        path.starts_with(prefix)
    }
}

/// A case-insensitive `Path::strip_prefix` for Windows paths.
///
/// This function is purely lexical and does not resolve symlinks.
/// Inputs are normalized lexically before comparison.
///
/// On non-Windows platforms this is equivalent to `Path::strip_prefix`.
#[inline]
pub fn strip_prefix_case_insensitive(path: &Path, prefix: &Path) -> Option<PathBuf> {
    let path = normalized_for_boundary(path);
    let prefix = normalized_for_boundary(prefix);
    let path = path.as_ref();
    let prefix = prefix.as_ref();

    debug_assert!(
        is_lexically_normalized_for_boundary(path),
        "strip_prefix_case_insensitive requires normalized `path` input, got: {path:?}"
    );
    debug_assert!(
        is_lexically_normalized_for_boundary(prefix),
        "strip_prefix_case_insensitive requires normalized `prefix` input, got: {prefix:?}"
    );

    #[cfg(windows)]
    {
        let mut path_components = path.components();
        for prefix_comp in prefix.components() {
            let path_comp = path_components.next()?;

            if !components_eq_case_insensitive(path_comp, prefix_comp) {
                return None;
            }
        }

        Some(path_components.as_path().to_path_buf())
    }

    #[cfg(not(windows))]
    {
        path.strip_prefix(prefix).ok().map(PathBuf::from)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_path_lexical_dot_is_stable() {
        assert_eq!(normalize_path_lexical(Path::new(".")), PathBuf::from("."));
        assert_eq!(
            normalize_path_lexical(Path::new("././")),
            PathBuf::from(".")
        );
        assert_eq!(
            normalize_path_lexical(Path::new("a/..")),
            PathBuf::from(".")
        );
        assert_eq!(normalize_path_lexical(Path::new("")), PathBuf::from("."));
    }

    #[test]
    fn strip_prefix_case_insensitive_handles_relative_paths() {
        assert_eq!(
            strip_prefix_case_insensitive(Path::new("a/b/c"), Path::new("a/b")),
            Some(PathBuf::from("c"))
        );
        assert_eq!(
            strip_prefix_case_insensitive(Path::new("a/b"), Path::new("a/b")),
            Some(PathBuf::new())
        );
        assert_eq!(
            strip_prefix_case_insensitive(Path::new("a/b"), Path::new("a/b/c")),
            None
        );
    }

    #[test]
    fn starts_with_case_insensitive_handles_relative_paths() {
        assert!(starts_with_case_insensitive(
            Path::new("a/b/c"),
            Path::new("a/b")
        ));
        assert!(starts_with_case_insensitive(
            Path::new("a/b"),
            Path::new("a/b")
        ));
        assert!(!starts_with_case_insensitive(
            Path::new("a/b"),
            Path::new("a/b/c")
        ));
    }

    #[test]
    fn normalize_glob_pattern_for_matching_collapses_leading_dot_segments() {
        assert_eq!(normalize_glob_pattern_for_matching("././a/b"), "a/b");
        assert_eq!(normalize_glob_pattern_for_matching("././"), ".");
        let long = format!("{}file", "./".repeat(1024));
        assert_eq!(normalize_glob_pattern_for_matching(&long), "file");
    }

    #[test]
    fn starts_with_case_insensitive_normalizes_unnormalized_inputs() {
        assert!(starts_with_case_insensitive(
            Path::new("a/./b"),
            Path::new("./a")
        ));
    }

    #[test]
    fn strip_prefix_case_insensitive_normalizes_unnormalized_inputs() {
        assert_eq!(
            strip_prefix_case_insensitive(Path::new("a/./b/c"), Path::new("./a/b")),
            Some(PathBuf::from("c"))
        );
    }

    #[test]
    fn normalize_path_lexical_handles_deep_paths() {
        let mut input = PathBuf::new();
        for _ in 0..10_000 {
            input.push("a");
        }
        for _ in 0..9_999 {
            input.push("..");
        }
        input.push("tail");

        assert_eq!(
            normalize_path_lexical(&input),
            PathBuf::from("a").join("tail")
        );
    }

    #[test]
    #[cfg(not(windows))]
    fn normalize_path_lexical_handles_absolute_paths() {
        assert_eq!(
            normalize_path_lexical(Path::new("/../etc")),
            PathBuf::from("/etc")
        );
        assert_eq!(
            normalize_path_lexical(Path::new("/a/./b")),
            PathBuf::from("/a/b")
        );
    }

    #[test]
    #[cfg(windows)]
    fn normalize_path_lexical_handles_windows_prefix_paths() {
        assert_eq!(
            normalize_path_lexical(Path::new(r"C:\foo\..\bar")),
            PathBuf::from(r"C:\bar")
        );
        assert_eq!(
            normalize_path_lexical(Path::new(r"\\?\C:\foo\..")),
            PathBuf::from("\\\\?\\C:\\")
        );
        assert_eq!(
            normalize_path_lexical(Path::new(r"\\server\share\a\..")),
            PathBuf::from("\\\\server\\share\\")
        );
    }

    #[test]
    #[cfg(windows)]
    fn strip_prefix_case_insensitive_is_case_insensitive_for_drive_prefixes() {
        assert_eq!(
            strip_prefix_case_insensitive(Path::new(r"C:\Foo\Bar"), Path::new(r"c:\foo")),
            Some(PathBuf::from("Bar"))
        );
        assert!(starts_with_case_insensitive(
            Path::new(r"C:\Foo\Bar"),
            Path::new(r"c:\foo")
        ));
    }

    #[test]
    #[cfg(windows)]
    fn strip_prefix_case_insensitive_matches_verbatim_drive_prefixes() {
        assert_eq!(
            strip_prefix_case_insensitive(Path::new(r"\\?\C:\Foo\Bar"), Path::new(r"c:\foo")),
            Some(PathBuf::from("Bar"))
        );
        assert!(starts_with_case_insensitive(
            Path::new(r"\\?\C:\Foo\Bar"),
            Path::new(r"c:\foo")
        ));
    }

    #[test]
    #[cfg(windows)]
    fn strip_prefix_case_insensitive_is_some_when_starts_with_for_prefix_only_matches() {
        let cases = [
            (Path::new(r"C:\Foo\Bar"), Path::new(r"c:")),
            (
                Path::new(r"\\Server\Share\Dir"),
                Path::new(r"\\server\share"),
            ),
            (Path::new(r"\\?\C:\Foo\Bar"), Path::new(r"c:")),
        ];

        for (path, prefix) in cases {
            assert!(
                starts_with_case_insensitive(path, prefix),
                "expected starts_with for path={path:?}, prefix={prefix:?}"
            );
            assert!(
                strip_prefix_case_insensitive(path, prefix).is_some(),
                "expected strip_prefix to succeed for path={path:?}, prefix={prefix:?}"
            );
        }
    }

    #[test]
    #[cfg(windows)]
    fn strip_prefix_case_insensitive_empty_prefix_matches_std() {
        let path = Path::new(r"C:\Foo\Bar");
        assert_eq!(
            strip_prefix_case_insensitive(path, Path::new("")),
            path.strip_prefix(Path::new("")).ok().map(PathBuf::from)
        );
    }

    #[test]
    #[cfg(windows)]
    fn os_str_eq_case_insensitive_windows_handles_empty_and_unicode() {
        use std::ffi::OsStr;

        assert!(os_str_eq_case_insensitive_windows(
            OsStr::new(""),
            OsStr::new("")
        ));
        assert!(os_str_eq_case_insensitive_windows(
            OsStr::new("Straße"),
            OsStr::new("straße")
        ));
        assert!(!os_str_eq_case_insensitive_windows(
            OsStr::new("alpha"),
            OsStr::new("beta")
        ));
    }

    #[test]
    #[cfg(windows)]
    fn starts_with_case_insensitive_matches_device_namespace_prefixes() {
        assert!(starts_with_case_insensitive(
            Path::new(r"\\.\COM1\Logs\Today.txt"),
            Path::new(r"\\.\com1\logs")
        ));
        assert_eq!(
            strip_prefix_case_insensitive(
                Path::new(r"\\.\COM1\Logs\Today.txt"),
                Path::new(r"\\.\com1\logs")
            ),
            Some(PathBuf::from("Today.txt"))
        );
    }
}
