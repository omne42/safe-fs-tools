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
    let mut out = PathBuf::new();
    let mut seen_prefix = false;
    for comp in path.components() {
        match comp {
            Component::CurDir => {}
            Component::ParentDir => {
                if out.as_os_str().is_empty() {
                    out.push("..");
                    continue;
                }

                match out.components().next_back() {
                    Some(Component::Normal(_)) => {
                        out.pop();
                    }
                    Some(Component::ParentDir) => {
                        out.push("..");
                    }
                    Some(Component::Prefix(_)) => {
                        out.push("..");
                    }
                    // If we're at the filesystem root, `..` is a no-op.
                    Some(Component::RootDir) | None => {}
                    _ => {}
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
    if out.as_os_str().is_empty() && path.is_relative() {
        PathBuf::from(".")
    } else {
        out
    }
}

#[cfg(windows)]
#[inline]
fn os_str_eq_case_insensitive_windows(a: &OsStr, b: &OsStr) -> bool {
    use std::os::windows::ffi::OsStrExt;
    use std::ptr;

    // SAFETY: `CompareStringOrdinal` is called with valid pointers into stack-owned UTF-16
    // buffers, explicit lengths, and no pointers escape the call.
    #[link(name = "Kernel32")]
    unsafe extern "system" {
        #[link_name = "CompareStringOrdinal"]
        fn compare_string_ordinal(
            string1: *const u16,
            count1: i32,
            string2: *const u16,
            count2: i32,
            ignore_case: i32,
        ) -> i32;
    }

    const CSTR_EQUAL: i32 = 2;

    let a_wide: Vec<u16> = a.encode_wide().collect();
    let b_wide: Vec<u16> = b.encode_wide().collect();
    let Ok(a_len) = i32::try_from(a_wide.len()) else {
        return false;
    };
    let Ok(b_len) = i32::try_from(b_wide.len()) else {
        return false;
    };

    let a_ptr = if a_wide.is_empty() {
        ptr::null()
    } else {
        a_wide.as_ptr()
    };
    let b_ptr = if b_wide.is_empty() {
        ptr::null()
    } else {
        b_wide.as_ptr()
    };

    // SAFETY: pointers and lengths describe valid UTF-16 buffers for the duration of the call.
    unsafe { compare_string_ordinal(a_ptr, a_len, b_ptr, b_len, 1) == CSTR_EQUAL }
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

/// A case-insensitive `Path::starts_with` for Windows paths.
///
/// This function is purely lexical and does not resolve `.`/`..` or symlinks.
/// For boundary/security checks, callers must pass canonicalized or otherwise normalized paths.
///
/// On non-Windows platforms this is equivalent to `Path::starts_with`.
#[inline]
pub fn starts_with_case_insensitive(path: &Path, prefix: &Path) -> bool {
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
        use std::path::Component;

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
/// This function is purely lexical and does not resolve `.`/`..` or symlinks.
/// For boundary/security checks, callers must pass canonicalized or otherwise normalized paths.
///
/// On non-Windows platforms this is equivalent to `Path::strip_prefix`.
#[inline]
pub fn strip_prefix_case_insensitive(path: &Path, prefix: &Path) -> Option<PathBuf> {
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
    #[cfg(debug_assertions)]
    #[should_panic(expected = "requires normalized `path` input")]
    fn starts_with_case_insensitive_panics_on_unnormalized_path_in_debug() {
        let _ = starts_with_case_insensitive(Path::new("a/./b"), Path::new("a"));
    }

    #[test]
    #[cfg(debug_assertions)]
    #[should_panic(expected = "requires normalized `prefix` input")]
    fn strip_prefix_case_insensitive_panics_on_unnormalized_prefix_in_debug() {
        let _ = strip_prefix_case_insensitive(Path::new("a/b"), Path::new("a/./b"));
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
}
