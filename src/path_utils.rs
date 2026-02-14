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
    let mut normalized = normalize_glob_pattern(pattern).into_owned();
    while normalized.starts_with("./") {
        normalized.drain(..2);
    }
    if normalized.is_empty() {
        normalized.push('.');
    }
    normalized
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
    out
}

#[cfg(windows)]
#[inline]
fn lower(s: &OsStr) -> String {
    s.to_string_lossy().to_lowercase()
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
            lower(a_server) == lower(b_server) && lower(a_share) == lower(b_share)
        }
        (Verbatim(a), Verbatim(b)) => lower(a) == lower(b),
        (DeviceNS(a), DeviceNS(b)) => lower(a) == lower(b),
        _ => false,
    }
}

#[cfg(windows)]
#[inline]
fn components_eq_case_insensitive(a: Component<'_>, b: Component<'_>) -> bool {
    match (a, b) {
        (Component::Prefix(a), Component::Prefix(b)) => prefixes_eq(a.kind(), b.kind()),
        (Component::RootDir, Component::RootDir) => true,
        (Component::Normal(a), Component::Normal(b)) => lower(a) == lower(b),
        (Component::CurDir, Component::CurDir) => true,
        (Component::ParentDir, Component::ParentDir) => true,
        _ => false,
    }
}

/// A case-insensitive `Path::starts_with` for Windows paths.
///
/// On non-Windows platforms this is equivalent to `Path::starts_with`.
#[inline]
pub fn starts_with_case_insensitive(path: &Path, prefix: &Path) -> bool {
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
/// On non-Windows platforms this is equivalent to `Path::strip_prefix`.
#[inline]
pub fn strip_prefix_case_insensitive(path: &Path, prefix: &Path) -> Option<PathBuf> {
    #[cfg(windows)]
    {
        use std::path::Component;

        let mut path_components = path.components();
        for prefix_comp in prefix.components() {
            let path_comp = path_components.next()?;

            if !components_eq_case_insensitive(path_comp, prefix_comp) {
                return None;
            }
        }

        let mut out = PathBuf::new();
        for comp in path_components {
            match comp {
                Component::Normal(part) => out.push(part),
                Component::CurDir => {}
                Component::ParentDir => out.push(".."),
                Component::RootDir | Component::Prefix(_) => return None,
            }
        }
        Some(out)
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
}
