use std::path::PathBuf;

use globset::{GlobSet, GlobSetBuilder};

use crate::error::{Error, Result};

fn compile_validated_glob(
    pattern: &str,
    invalid_err: impl Fn(String) -> Error,
) -> Result<globset::Glob> {
    let normalized = normalize_and_validate_root_relative_glob_pattern(pattern)
        .map_err(|msg| invalid_err(msg))?;
    crate::path_utils_internal::build_glob_from_normalized(&normalized)
        .map_err(|err| invalid_err(err.to_string()))
}

pub(super) fn compile_glob(pattern: &str) -> Result<GlobSet> {
    let glob = compile_validated_glob(pattern, |msg| {
        Error::InvalidPath(format!("invalid glob pattern {pattern:?}: {msg}"))
    })?;
    let mut builder = GlobSetBuilder::new();
    builder.add(glob);
    builder
        .build()
        .map_err(|err| Error::InvalidPath(format!("invalid glob pattern {pattern:?}: {err}")))
}

pub(super) fn compile_traversal_skip_globs(patterns: &[String]) -> Result<Option<GlobSet>> {
    if patterns.is_empty() {
        return Ok(None);
    }

    let mut builder = GlobSetBuilder::new();
    for pattern in patterns {
        let glob = compile_validated_glob(pattern, |msg| {
            Error::InvalidPolicy(format!(
                "invalid traversal.skip_globs glob {pattern:?}: {msg}"
            ))
        })?;
        builder.add(glob);
    }

    let set = builder
        .build()
        .map_err(|err| Error::InvalidPolicy(format!("invalid traversal.skip_globs: {err}")))?;
    Ok(Some(set))
}

pub(super) fn derive_safe_traversal_prefix(pattern: &str) -> Option<PathBuf> {
    let normalized = normalize_and_validate_root_relative_glob_pattern(pattern).ok()?;
    collect_literal_traversal_prefix(&normalized)
}

fn normalize_and_validate_root_relative_glob_pattern(
    pattern: &str,
) -> std::result::Result<String, String> {
    if pattern.trim().is_empty() {
        return Err("glob pattern must not be empty".to_string());
    }

    let normalized = crate::path_utils_internal::normalize_glob_pattern_for_matching(pattern);
    crate::path_utils_internal::validate_root_relative_glob_pattern(&normalized)
        .map_err(|msg| msg.to_string())?;
    Ok(normalized)
}

fn collect_literal_traversal_prefix(pattern: &str) -> Option<PathBuf> {
    let mut out = PathBuf::new();
    for segment in pattern.split('/') {
        if segment.is_empty() || segment == "." {
            continue;
        }

        if reject_unsafe_segment(segment) {
            return None;
        }

        if !segment_is_strict_literal(segment) {
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

fn segment_is_strict_literal(segment: &str) -> bool {
    // Be intentionally conservative: only treat segments as literal when every byte
    // is known to be non-special in glob syntax. This avoids syntax drift turning a
    // meta segment into an accidentally narrowed traversal prefix.
    !segment.is_empty() && segment.bytes().all(is_always_literal_glob_byte)
}

#[inline]
const fn is_always_literal_glob_byte(byte: u8) -> bool {
    matches!(
        byte,
        b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'.' | b'_' | b'-'
    )
}

#[cfg(windows)]
fn reject_unsafe_segment(segment: &str) -> bool {
    use std::path::{Component, Path};

    matches!(
        Path::new(segment).components().next(),
        Some(Component::Prefix(_))
    )
}

#[cfg(not(windows))]
fn reject_unsafe_segment(_: &str) -> bool {
    false
}
