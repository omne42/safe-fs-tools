#[cfg(feature = "patch")]
use std::path::Path;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

use super::Context;

#[cfg(feature = "patch")]
use diffy::{Patch, apply};

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
    /// Final on-disk file size when the patch changes content; `0` for a no-op patch.
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
    let patch_bytes = u64::try_from(request.patch.len()).unwrap_or(u64::MAX);
    if patch_bytes > max_patch_bytes {
        return Err(Error::InputTooLarge {
            size_bytes: patch_bytes,
            max_bytes: max_patch_bytes,
        });
    }

    let parsed = Patch::from_str(&request.patch)
        .map_err(|err| Error::Patch(format!("{}: {err}", relative.display())))?;
    ensure_patch_headers_match_target(&parsed, &requested_path, &relative)?;

    let (content, identity) = super::io::read_string_limited_with_identity(
        &path,
        &relative,
        ctx.policy.limits.max_read_bytes,
    )?;
    let updated = apply(&content, &parsed)
        .map_err(|err| Error::Patch(format!("{}: {err}", relative.display())))?;

    let updated_len = u64::try_from(updated.len()).unwrap_or(u64::MAX);
    if updated_len > ctx.policy.limits.max_write_bytes {
        return Err(Error::FileTooLarge {
            path: relative.clone(),
            size_bytes: updated_len,
            max_bytes: ctx.policy.limits.max_write_bytes,
        });
    }

    let changed = updated != content;
    if changed {
        super::io::write_bytes_atomic_checked(&path, &relative, updated.as_bytes(), identity)?;
    }
    Ok(PatchResponse {
        path: relative,
        requested_path: Some(requested_path),
        bytes_written: if changed { updated_len } else { 0 },
    })
}

#[cfg(feature = "patch")]
fn ensure_patch_headers_match_target(
    patch: &Patch<'_, str>,
    requested_path: &Path,
    relative: &Path,
) -> Result<()> {
    if patch_uses_diffy_default_filenames(patch) {
        return Ok(());
    }

    let original_header = required_patch_header("original", patch.original(), relative)?;
    let modified_header = required_patch_header("modified", patch.modified(), relative)?;

    for (label, header) in [("original", original_header), ("modified", modified_header)] {
        if !patch_header_matches_path(header, requested_path) {
            return Err(Error::Patch(format!(
                "{}: patch {label} header '{header}' does not match target '{}'",
                relative.display(),
                requested_path.display()
            )));
        }
    }

    Ok(())
}

#[cfg(feature = "patch")]
fn required_patch_header<'a>(
    label: &str,
    header: Option<&'a str>,
    relative: &Path,
) -> Result<&'a str> {
    header.ok_or_else(|| {
        Error::Patch(format!(
            "{}: patch {label} header is missing",
            relative.display()
        ))
    })
}

#[cfg(feature = "patch")]
fn patch_uses_diffy_default_filenames(patch: &Patch<'_, str>) -> bool {
    matches!(patch.original(), Some("original")) && matches!(patch.modified(), Some("modified"))
}

#[cfg(feature = "patch")]
fn patch_header_matches_path(header: &str, requested_path: &Path) -> bool {
    let normalized_header =
        crate::path_utils::normalize_path_lexical(Path::new(strip_common_patch_prefix(header)));
    let normalized_requested = crate::path_utils::normalize_path_lexical(requested_path);
    normalized_paths_match(&normalized_header, &normalized_requested)
}

#[cfg(feature = "patch")]
fn normalized_paths_match(a: &Path, b: &Path) -> bool {
    crate::path_utils::starts_with_case_insensitive(a, b)
        && crate::path_utils::starts_with_case_insensitive(b, a)
}

#[cfg(feature = "patch")]
fn strip_common_patch_prefix(header: &str) -> &str {
    let mut value = header;
    match value
        .strip_prefix("a/")
        .or_else(|| value.strip_prefix("b/"))
    {
        Some(stripped) if !stripped.is_empty() => value = stripped,
        _ => {}
    }
    while let Some(stripped) = value.strip_prefix("./") {
        value = stripped;
    }
    value
}

#[cfg(all(test, feature = "patch"))]
mod tests {
    use super::*;

    #[test]
    fn missing_patch_header_is_rejected() {
        let err = required_patch_header("original", None, Path::new("file.txt"))
            .expect_err("missing header should be rejected");
        match err {
            Error::Patch(msg) => assert!(
                msg.contains("patch original header is missing"),
                "unexpected message: {msg}"
            ),
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn patch_header_prefixes_are_normalized_before_compare() {
        assert!(patch_header_matches_path(
            "a/./nested/file.txt",
            Path::new("nested/file.txt")
        ));
    }

    #[cfg(windows)]
    #[test]
    fn patch_header_compare_is_case_insensitive_on_windows() {
        assert!(patch_header_matches_path(
            "a/file.txt",
            Path::new("File.txt")
        ));
    }

    #[cfg(not(windows))]
    #[test]
    fn patch_header_compare_remains_case_sensitive_on_non_windows() {
        assert!(!patch_header_matches_path(
            "a/file.txt",
            Path::new("File.txt")
        ));
    }
}
