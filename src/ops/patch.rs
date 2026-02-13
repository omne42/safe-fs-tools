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

    let (content, identity) = super::io::read_string_limited_with_identity(
        &path,
        &relative,
        ctx.policy.limits.max_read_bytes,
    )?;
    let parsed = Patch::from_str(&request.patch)
        .map_err(|err| Error::Patch(format!("{}: {err}", relative.display())))?;
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
