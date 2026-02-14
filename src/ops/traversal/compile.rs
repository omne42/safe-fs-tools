use std::path::PathBuf;

use globset::{GlobSet, GlobSetBuilder};

use crate::error::{Error, Result};

pub(super) fn compile_glob(pattern: &str) -> Result<GlobSet> {
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

pub(super) fn compile_traversal_skip_globs(patterns: &[String]) -> Result<Option<GlobSet>> {
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

pub(super) fn derive_safe_traversal_prefix(pattern: &str) -> Option<PathBuf> {
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
            use std::path::{Component, Path};

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
