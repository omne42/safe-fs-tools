use std::fs;
use std::path::Path;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

use super::Context;

fn ensure_target_dir_within_root(
    root_id: &str,
    canonical_root: &Path,
    target: &Path,
    relative: &Path,
    requested_path: &Path,
) -> Result<()> {
    let canonical_target = target
        .canonicalize()
        .map_err(|err| Error::io_path("canonicalize", relative, err))?;
    if !crate::path_utils::starts_with_case_insensitive(&canonical_target, canonical_root) {
        return Err(Error::OutsideRoot {
            root_id: root_id.to_string(),
            path: requested_path.to_path_buf(),
        });
    }
    Ok(())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MkdirRequest {
    pub root_id: String,
    pub path: PathBuf,
    #[serde(default)]
    pub create_parents: bool,
    #[serde(default)]
    pub ignore_existing: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MkdirResponse {
    pub path: PathBuf,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requested_path: Option<PathBuf>,
    pub created: bool,
}

pub fn mkdir(ctx: &Context, request: MkdirRequest) -> Result<MkdirResponse> {
    if !ctx.policy.permissions.mkdir {
        return Err(Error::NotPermitted(
            "mkdir is disabled by policy".to_string(),
        ));
    }
    ctx.ensure_can_write(&request.root_id, "mkdir")?;

    let resolved =
        super::resolve::resolve_path_in_root_lexically(ctx, &request.root_id, &request.path)?;
    let canonical_root = resolved.canonical_root;
    let requested_path = resolved.requested_path;

    let requested_is_root = requested_path
        .components()
        .all(|component| matches!(component, std::path::Component::CurDir));
    if requested_is_root {
        return Err(Error::InvalidPath(
            "refusing to create the root directory".to_string(),
        ));
    }

    let dir_name = requested_path.file_name().ok_or_else(|| {
        Error::InvalidPath(format!(
            "invalid mkdir path {:?}: missing final directory name",
            request.path
        ))
    })?;
    if dir_name == std::ffi::OsStr::new(".") || dir_name == std::ffi::OsStr::new("..") {
        return Err(Error::InvalidPath(format!(
            "invalid mkdir path {:?}",
            request.path
        )));
    }

    let requested_parent = requested_path
        .parent()
        .unwrap_or_else(|| std::path::Path::new(""));

    let canonical_parent =
        ctx.ensure_dir_under_root(&request.root_id, requested_parent, request.create_parents)?;

    if !crate::path_utils::starts_with_case_insensitive(&canonical_parent, &canonical_root) {
        return Err(Error::OutsideRoot {
            root_id: request.root_id.clone(),
            path: requested_path,
        });
    }

    let relative_parent =
        crate::path_utils::strip_prefix_case_insensitive(&canonical_parent, &canonical_root)
            .ok_or_else(|| {
                Error::InvalidPath(format!(
                    "failed to derive root-relative parent for {}",
                    requested_path.display()
                ))
            })?;
    let relative = relative_parent.join(dir_name);

    if ctx.redactor.is_path_denied(&relative) {
        return Err(Error::SecretPathDenied(relative));
    }

    let target = canonical_parent.join(dir_name);
    if !crate::path_utils::starts_with_case_insensitive(&target, &canonical_root) {
        return Err(Error::OutsideRoot {
            root_id: request.root_id.clone(),
            path: requested_path,
        });
    }

    match fs::symlink_metadata(&target) {
        Ok(meta) => {
            if meta.file_type().is_symlink() {
                return Err(Error::InvalidPath(
                    "refusing to create directory through symlink".to_string(),
                ));
            }
            if meta.is_dir() {
                if request.ignore_existing {
                    ensure_target_dir_within_root(
                        &request.root_id,
                        &canonical_root,
                        &target,
                        &relative,
                        &requested_path,
                    )?;
                    return Ok(MkdirResponse {
                        path: relative,
                        requested_path: Some(requested_path),
                        created: false,
                    });
                }
                return Err(Error::InvalidPath("directory exists".to_string()));
            }
            Err(Error::InvalidPath(
                "path exists and is not a directory".to_string(),
            ))
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            if let Err(err) = fs::create_dir(&target) {
                if err.kind() == std::io::ErrorKind::AlreadyExists {
                    let existing = fs::symlink_metadata(&target)
                        .map_err(|meta_err| Error::io_path("metadata", &relative, meta_err))?;
                    if existing.file_type().is_symlink() {
                        return Err(Error::InvalidPath(
                            "refusing to create directory through symlink".to_string(),
                        ));
                    }
                    if existing.is_dir() && request.ignore_existing {
                        ensure_target_dir_within_root(
                            &request.root_id,
                            &canonical_root,
                            &target,
                            &relative,
                            &requested_path,
                        )?;
                        return Ok(MkdirResponse {
                            path: relative,
                            requested_path: Some(requested_path),
                            created: false,
                        });
                    }
                    if existing.is_dir() {
                        return Err(Error::InvalidPath("directory exists".to_string()));
                    }
                    return Err(Error::InvalidPath(
                        "path exists and is not a directory".to_string(),
                    ));
                }
                return Err(Error::io_path("create_dir", &relative, err));
            }
            ensure_target_dir_within_root(
                &request.root_id,
                &canonical_root,
                &target,
                &relative,
                &requested_path,
            )
            .inspect_err(|_err| {
                let _ = fs::remove_dir(&target);
            })?;
            Ok(MkdirResponse {
                path: relative,
                requested_path: Some(requested_path),
                created: true,
            })
        }
        Err(err) => Err(Error::io_path("metadata", &relative, err)),
    }
}
