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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatResponse {
    pub path: PathBuf,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requested_path: Option<PathBuf>,
    #[serde(rename = "type")]
    pub kind: String,
    pub size_bytes: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub modified_ms: Option<u64>,
}

pub fn stat(ctx: &Context, request: StatRequest) -> Result<StatResponse> {
    if !ctx.policy.permissions.stat {
        return Err(Error::NotPermitted(
            "stat is disabled by policy".to_string(),
        ));
    }

    let (path, relative, requested_path) =
        ctx.canonical_path_in_root(&request.root_id, &request.path)?;

    let meta = fs::metadata(&path).map_err(|err| Error::io_path("metadata", &relative, err))?;
    let kind = if meta.is_file() {
        "file"
    } else if meta.is_dir() {
        "dir"
    } else {
        "other"
    };

    let size_bytes = if meta.is_file() { meta.len() } else { 0 };

    let modified_ms = meta
        .modified()
        .ok()
        .and_then(|value| value.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|value| value.as_millis().min(u128::from(u64::MAX)) as u64);

    Ok(StatResponse {
        path: relative,
        requested_path: Some(requested_path),
        kind: kind.to_string(),
        size_bytes,
        modified_ms,
    })
}
