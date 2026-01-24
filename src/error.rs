use std::path::PathBuf;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("walkdir error: {0}")]
    WalkDir(#[from] walkdir::Error),

    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("invalid policy: {0}")]
    InvalidPolicy(String),

    #[error("invalid path: {0}")]
    InvalidPath(String),

    #[error("root not found: {0}")]
    RootNotFound(String),

    #[error("path is outside root '{root_id}': {path}")]
    OutsideRoot { root_id: String, path: PathBuf },

    #[error("operation is not permitted: {0}")]
    NotPermitted(String),

    #[error("path is denied by secret rules: {0}")]
    SecretPathDenied(PathBuf),

    #[error("file is too large ({size_bytes} bytes; max {max_bytes} bytes): {path}")]
    FileTooLarge {
        path: PathBuf,
        size_bytes: u64,
        max_bytes: u64,
    },

    #[error("invalid utf-8 in file: {0}")]
    InvalidUtf8(PathBuf),

    #[error("failed to apply patch: {0}")]
    Patch(String),

    #[error("invalid regex: {0}")]
    InvalidRegex(String),
}

pub type Result<T> = std::result::Result<T, Error>;
