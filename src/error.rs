use std::path::PathBuf;

use thiserror::Error;

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Error {
    #[error("io error: {0}")]
    Io(std::io::Error),

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
    pub const CODE_IO: &'static str = "io";
    pub const CODE_IO_PATH: &'static str = "io_path";
    #[cfg(any(feature = "glob", feature = "grep"))]
    pub const CODE_WALKDIR: &'static str = "walkdir";
    #[cfg(any(feature = "glob", feature = "grep"))]
    pub const CODE_WALKDIR_ROOT: &'static str = "walkdir_root";
    pub const CODE_INVALID_POLICY: &'static str = "invalid_policy";
    pub const CODE_INVALID_PATH: &'static str = "invalid_path";
    pub const CODE_ROOT_NOT_FOUND: &'static str = "root_not_found";
    pub const CODE_OUTSIDE_ROOT: &'static str = "outside_root";
    pub const CODE_NOT_PERMITTED: &'static str = "not_permitted";
    pub const CODE_SECRET_PATH_DENIED: &'static str = "secret_path_denied";
    pub const CODE_FILE_TOO_LARGE: &'static str = "file_too_large";
    pub const CODE_INVALID_UTF8: &'static str = "invalid_utf8";
    pub const CODE_PATCH: &'static str = "patch";
    pub const CODE_INVALID_REGEX: &'static str = "invalid_regex";
    pub const CODE_INPUT_TOO_LARGE: &'static str = "input_too_large";

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
            Error::Io(_) => Self::CODE_IO,
            Error::IoPath { .. } => Self::CODE_IO_PATH,
            #[cfg(any(feature = "glob", feature = "grep"))]
            Error::WalkDir(_) => Self::CODE_WALKDIR,
            #[cfg(any(feature = "glob", feature = "grep"))]
            Error::WalkDirRoot { .. } => Self::CODE_WALKDIR_ROOT,
            Error::InvalidPolicy(_) => Self::CODE_INVALID_POLICY,
            Error::InvalidPath(_) => Self::CODE_INVALID_PATH,
            Error::RootNotFound(_) => Self::CODE_ROOT_NOT_FOUND,
            Error::OutsideRoot { .. } => Self::CODE_OUTSIDE_ROOT,
            Error::NotPermitted(_) => Self::CODE_NOT_PERMITTED,
            Error::SecretPathDenied(_) => Self::CODE_SECRET_PATH_DENIED,
            Error::FileTooLarge { .. } => Self::CODE_FILE_TOO_LARGE,
            Error::InvalidUtf8(_) => Self::CODE_INVALID_UTF8,
            Error::Patch(_) => Self::CODE_PATCH,
            Error::InvalidRegex(_) => Self::CODE_INVALID_REGEX,
            Error::InputTooLarge { .. } => Self::CODE_INPUT_TOO_LARGE,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn not_found_error() -> std::io::Error {
        std::io::Error::new(std::io::ErrorKind::NotFound, "not found")
    }

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
            (Error::Io(not_found_error()), "io"),
            (
                Error::IoPath {
                    op: "open",
                    path: PathBuf::from("file.txt"),
                    source: not_found_error(),
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
                    source: not_found_error(),
                },
                "walkdir_root",
            ),
        ];
        for (error, code) in cases {
            assert_eq!(error.code(), code);
        }
    }
}
