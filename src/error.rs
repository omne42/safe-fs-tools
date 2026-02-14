use std::path::PathBuf;

use thiserror::Error;

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Error {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("io error during {op} ({path}): {source}")]
    IoPath {
        op: &'static str,
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[cfg(any(feature = "glob", feature = "grep"))]
    #[error("walkdir error: {0}")]
    WalkDir(#[from] walkdir::Error),

    #[cfg(any(feature = "glob", feature = "grep"))]
    #[error("io error while preparing walk root ({path}): {source}")]
    WalkDirRoot {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("invalid policy: {0}")]
    InvalidPolicy(String),

    #[error("invalid path: {0}")]
    InvalidPath(String),

    #[error("root not found: {0}")]
    RootNotFound(String),

    #[error("path resolves outside root '{root_id}': {path}")]
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

    #[error("input is too large ({size_bytes} bytes; max {max_bytes} bytes)")]
    InputTooLarge { size_bytes: u64, max_bytes: u64 },
}

pub type Result<T> = std::result::Result<T, Error>;

impl Error {
    pub(crate) fn io_path(
        op: &'static str,
        path: impl Into<PathBuf>,
        source: std::io::Error,
    ) -> Self {
        Self::IoPath {
            op,
            path: path.into(),
            source,
        }
    }

    /// A stable, programmatic error code for callers that need to classify failures.
    pub fn code(&self) -> &'static str {
        match self {
            Error::Io(_) => "io",
            Error::IoPath { .. } => "io_path",
            #[cfg(any(feature = "glob", feature = "grep"))]
            Error::WalkDir(_) => "walkdir",
            #[cfg(any(feature = "glob", feature = "grep"))]
            Error::WalkDirRoot { .. } => "walkdir_root",
            Error::InvalidPolicy(_) => "invalid_policy",
            Error::InvalidPath(_) => "invalid_path",
            Error::RootNotFound(_) => "root_not_found",
            Error::OutsideRoot { .. } => "outside_root",
            Error::NotPermitted(_) => "not_permitted",
            Error::SecretPathDenied(_) => "secret_path_denied",
            Error::FileTooLarge { .. } => "file_too_large",
            Error::InvalidUtf8(_) => "invalid_utf8",
            Error::Patch(_) => "patch",
            Error::InvalidRegex(_) => "invalid_regex",
            Error::InputTooLarge { .. } => "input_too_large",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(any(feature = "glob", feature = "grep"))]
    fn sample_walkdir_error() -> walkdir::Error {
        let dir = tempfile::tempdir().expect("tempdir");
        let missing = dir.path().join("missing");
        walkdir::WalkDir::new(&missing)
            .into_iter()
            .find_map(|entry| entry.err())
            .expect("walk error")
    }

    #[test]
    fn code_covers_variants() {
        let cases = vec![
            (Error::Io(std::io::Error::from_raw_os_error(2)), "io"),
            (
                Error::IoPath {
                    op: "open",
                    path: PathBuf::from("file.txt"),
                    source: std::io::Error::from_raw_os_error(2),
                },
                "io_path",
            ),
            (Error::InvalidPolicy("x".to_string()), "invalid_policy"),
            (Error::InvalidPath("x".to_string()), "invalid_path"),
            (Error::RootNotFound("root".to_string()), "root_not_found"),
            (
                Error::OutsideRoot {
                    root_id: "root".to_string(),
                    path: PathBuf::from("x"),
                },
                "outside_root",
            ),
            (Error::NotPermitted("x".to_string()), "not_permitted"),
            (
                Error::SecretPathDenied(PathBuf::from("secret")),
                "secret_path_denied",
            ),
            (
                Error::FileTooLarge {
                    path: PathBuf::from("x"),
                    size_bytes: 2,
                    max_bytes: 1,
                },
                "file_too_large",
            ),
            (Error::InvalidUtf8(PathBuf::from("x")), "invalid_utf8"),
            (Error::Patch("x".to_string()), "patch"),
            (Error::InvalidRegex("x".to_string()), "invalid_regex"),
            (
                Error::InputTooLarge {
                    size_bytes: 2,
                    max_bytes: 1,
                },
                "input_too_large",
            ),
            #[cfg(any(feature = "glob", feature = "grep"))]
            (Error::WalkDir(sample_walkdir_error()), "walkdir"),
            #[cfg(any(feature = "glob", feature = "grep"))]
            (
                Error::WalkDirRoot {
                    path: PathBuf::from("x"),
                    source: std::io::Error::from_raw_os_error(2),
                },
                "walkdir_root",
            ),
        ];
        for (error, code) in cases {
            assert_eq!(error.code(), code);
        }
    }
}
