use std::fs;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

use super::Context;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatRequest {
    pub root_id: String,
    pub path: PathBuf,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum StatKind {
    File,
    Dir,
    Other,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatResponse {
    pub path: PathBuf,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requested_path: Option<PathBuf>,
    #[serde(rename = "type")]
    pub kind: StatKind,
    pub size_bytes: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub modified_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub accessed_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_ms: Option<u64>,
    pub readonly: bool,
}

fn system_time_to_millis(value: std::time::SystemTime) -> Option<u64> {
    value
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .and_then(|duration| u64::try_from(duration.as_millis()).ok())
}

pub fn stat(ctx: &Context, request: StatRequest) -> Result<StatResponse> {
    if !ctx.policy.permissions.stat {
        return Err(Error::NotPermitted(
            "stat is disabled by policy".to_string(),
        ));
    }

    let (path, relative, requested_path) =
        ctx.canonical_path_in_root(&request.root_id, &request.path)?;

    let meta =
        fs::symlink_metadata(&path).map_err(|err| Error::io_path("metadata", &relative, err))?;
    if meta.file_type().is_symlink() {
        return Err(Error::InvalidPath(format!(
            "path {} changed during operation",
            relative.display()
        )));
    }
    let kind = if meta.is_file() {
        StatKind::File
    } else if meta.is_dir() {
        StatKind::Dir
    } else {
        StatKind::Other
    };

    let size_bytes = if meta.is_file() { meta.len() } else { 0 };

    let modified_ms = meta.modified().ok().and_then(system_time_to_millis);
    let accessed_ms = meta.accessed().ok().and_then(system_time_to_millis);
    let created_ms = meta.created().ok().and_then(system_time_to_millis);
    let readonly = meta.permissions().readonly();

    Ok(StatResponse {
        path: relative,
        requested_path: Some(requested_path),
        kind,
        size_bytes,
        modified_ms,
        accessed_ms,
        created_ms,
        readonly,
    })
}
