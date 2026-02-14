use std::ffi::OsStr;
use std::path::{Component, Path};

use crate::error::{Error, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct LeafValidationSpec {
    op_name: &'static str,
    missing_segment_label: &'static str,
    root_rejection_message: &'static str,
}

impl LeafValidationSpec {
    const WRITE: Self = Self {
        op_name: "write",
        missing_segment_label: "file name",
        root_rejection_message: "refusing to write to the root directory",
    };

    const DELETE: Self = Self {
        op_name: "delete",
        missing_segment_label: "path segment",
        root_rejection_message: "refusing to delete the root directory",
    };

    const MKDIR: Self = Self {
        op_name: "mkdir",
        missing_segment_label: "directory name",
        root_rejection_message: "refusing to create the root directory",
    };

    fn from_parts(
        op_name: &'static str,
        missing_segment_label: &'static str,
        root_rejection_message: &'static str,
    ) -> Result<Self> {
        match (op_name, missing_segment_label, root_rejection_message) {
            (op, missing, root)
                if op == Self::WRITE.op_name
                    && missing == Self::WRITE.missing_segment_label
                    && root == Self::WRITE.root_rejection_message =>
            {
                Ok(Self::WRITE)
            }
            (op, missing, root)
                if op == Self::DELETE.op_name
                    && missing == Self::DELETE.missing_segment_label
                    && root == Self::DELETE.root_rejection_message =>
            {
                Ok(Self::DELETE)
            }
            (op, missing, root)
                if op == Self::MKDIR.op_name
                    && missing == Self::MKDIR.missing_segment_label
                    && root == Self::MKDIR.root_rejection_message =>
            {
                Ok(Self::MKDIR)
            }
            _ => Err(Error::InvalidPath(format!(
                "invalid leaf validation contract: op={op_name}, missing_segment_label={missing_segment_label}, root_rejection_message={root_rejection_message}"
            ))),
        }
    }
}

fn validate_requested_path_contract(
    requested_path: &Path,
    raw_input_path: &Path,
    spec: LeafValidationSpec,
) -> Result<()> {
    let normalized = crate::path_utils::normalize_path_lexical(requested_path);
    if normalized != requested_path {
        return Err(Error::InvalidPath(format!(
            "invalid {} path {:?}: internal contract violation: requested path must be normalized root-relative",
            spec.op_name, raw_input_path
        )));
    }

    let has_non_relative_components = requested_path.components().any(|component| {
        matches!(
            component,
            Component::ParentDir | Component::RootDir | Component::Prefix(_)
        )
    });
    if has_non_relative_components {
        return Err(Error::InvalidPath(format!(
            "invalid {} path {:?}: internal contract violation: requested path must stay root-relative",
            spec.op_name, raw_input_path
        )));
    }

    Ok(())
}

/// Validates the leaf path segment for mutating operations.
///
/// Contract: `requested_path` must be a normalized root-relative path emitted by
/// path resolution (`.` means root). We keep missing-leaf and dot-segment checks
/// as defensive validation for callers violating that contract.
pub(super) fn ensure_non_root_leaf<'a>(
    requested_path: &'a Path,
    raw_input_path: &Path,
    op_name: &'static str,
    missing_segment_label: &'static str,
    root_rejection_message: &'static str,
) -> Result<&'a OsStr> {
    let spec =
        LeafValidationSpec::from_parts(op_name, missing_segment_label, root_rejection_message)?;

    if requested_path == Path::new(".") {
        return Err(Error::InvalidPath(spec.root_rejection_message.to_string()));
    }

    let file_name = requested_path.file_name().ok_or_else(|| {
        Error::InvalidPath(format!(
            "invalid {} path {:?}: missing final {}",
            spec.op_name, raw_input_path, spec.missing_segment_label
        ))
    })?;

    if file_name == OsStr::new(".") || file_name == OsStr::new("..") {
        return Err(Error::InvalidPath(format!(
            "invalid {} path {:?}",
            spec.op_name, raw_input_path
        )));
    }

    validate_requested_path_contract(requested_path, raw_input_path, spec)?;

    Ok(file_name)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn invalid_path_message(err: Error) -> String {
        match err {
            Error::InvalidPath(message) => message,
            other => panic!("expected invalid path error, got {other:?}"),
        }
    }

    #[test]
    fn rejects_root_dot_with_root_specific_message() {
        let err = ensure_non_root_leaf(
            Path::new("."),
            Path::new("."),
            "write",
            "file name",
            "refusing to write to the root directory",
        )
        .expect_err("root path should be rejected");

        assert_eq!(
            invalid_path_message(err),
            "refusing to write to the root directory"
        );
    }

    #[test]
    fn rejects_unknown_leaf_validation_contract() {
        let err = ensure_non_root_leaf(
            Path::new("file.txt"),
            Path::new("file.txt"),
            "write",
            "path segment",
            "refusing to write to the root directory",
        )
        .expect_err("mismatched contract should be rejected");

        let message = invalid_path_message(err);
        assert!(message.contains("invalid leaf validation contract"));
    }

    #[test]
    fn reports_missing_leaf_segment_for_defensive_input() {
        let err = ensure_non_root_leaf(
            Path::new(""),
            Path::new(""),
            "delete",
            "path segment",
            "refusing to delete the root directory",
        )
        .expect_err("empty path should be rejected");

        assert_eq!(
            invalid_path_message(err),
            "invalid delete path \"\": missing final path segment"
        );
    }

    #[test]
    fn rejects_non_normalized_requested_path() {
        let err = ensure_non_root_leaf(
            Path::new("./nested/file.txt"),
            Path::new("./nested/file.txt"),
            "write",
            "file name",
            "refusing to write to the root directory",
        )
        .expect_err("non-normalized requested path should be rejected");

        assert_eq!(
            invalid_path_message(err),
            "invalid write path \"./nested/file.txt\": internal contract violation: requested path must be normalized root-relative"
        );
    }

    #[test]
    fn rejects_requested_path_with_parent_dir_component() {
        let err = ensure_non_root_leaf(
            Path::new("../file.txt"),
            Path::new("../file.txt"),
            "delete",
            "path segment",
            "refusing to delete the root directory",
        )
        .expect_err("parent-dir segment should be rejected");

        assert_eq!(
            invalid_path_message(err),
            "invalid delete path \"../file.txt\": internal contract violation: requested path must stay root-relative"
        );
    }

    #[test]
    fn accepts_normalized_non_root_leaf() {
        let leaf = ensure_non_root_leaf(
            Path::new("nested/file.txt"),
            Path::new("nested/file.txt"),
            "delete",
            "path segment",
            "refusing to delete the root directory",
        )
        .expect("valid normalized path should pass");

        assert_eq!(leaf, OsStr::new("file.txt"));
    }
}
