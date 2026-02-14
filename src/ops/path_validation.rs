use std::ffi::OsStr;
use std::path::{Component, Path};

use crate::error::{Error, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum LeafOp {
    Write,
    Delete,
    Mkdir,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct LeafValidationSpec {
    op_name: &'static str,
    missing_segment_label: &'static str,
    root_rejection_message: &'static str,
}

impl LeafValidationSpec {
    const fn for_op(op: LeafOp) -> Self {
        match op {
            LeafOp::Write => Self {
                op_name: "write",
                missing_segment_label: "file name",
                root_rejection_message: "refusing to write to the root directory",
            },
            LeafOp::Delete => Self {
                op_name: "delete",
                missing_segment_label: "path segment",
                root_rejection_message: "refusing to delete the root directory",
            },
            LeafOp::Mkdir => Self {
                op_name: "mkdir",
                missing_segment_label: "directory name",
                root_rejection_message: "refusing to create the root directory",
            },
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
        debug_assert_eq!(
            normalized, requested_path,
            "invalid {} path contract: requested path must be normalized root-relative; raw={raw_input_path:?}, requested={requested_path:?}, normalized={normalized:?}",
            spec.op_name
        );
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
        debug_assert!(
            !has_non_relative_components,
            "invalid {} path contract: requested path must stay root-relative; raw={raw_input_path:?}, requested={requested_path:?}",
            spec.op_name
        );
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
    op: LeafOp,
) -> Result<&'a OsStr> {
    let spec = LeafValidationSpec::for_op(op);

    validate_requested_path_contract(requested_path, raw_input_path, spec)?;

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
        let err = ensure_non_root_leaf(Path::new("."), Path::new("."), LeafOp::Write)
            .expect_err("root path should be rejected");

        assert_eq!(
            invalid_path_message(err),
            "refusing to write to the root directory"
        );
    }

    #[test]
    fn rejects_non_normalized_requested_path() {
        let err = ensure_non_root_leaf(
            Path::new("./nested/file.txt"),
            Path::new("./nested/file.txt"),
            LeafOp::Write,
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
            LeafOp::Delete,
        )
        .expect_err("parent-dir segment should be rejected");

        assert_eq!(
            invalid_path_message(err),
            "invalid delete path \"../file.txt\": internal contract violation: requested path must stay root-relative"
        );
    }

    #[test]
    fn rejects_requested_path_with_root_component() {
        let err = ensure_non_root_leaf(
            Path::new("/tmp/file.txt"),
            Path::new("/tmp/file.txt"),
            LeafOp::Delete,
        )
        .expect_err("absolute requested path should be rejected");

        assert_eq!(
            invalid_path_message(err),
            "invalid delete path \"/tmp/file.txt\": internal contract violation: requested path must stay root-relative"
        );
    }

    #[test]
    #[cfg(windows)]
    fn rejects_requested_path_with_windows_prefix_component() {
        let err = ensure_non_root_leaf(
            Path::new(r"C:\tmp\file.txt"),
            Path::new(r"C:\tmp\file.txt"),
            LeafOp::Delete,
        )
        .expect_err("prefixed requested path should be rejected");

        assert_eq!(
            invalid_path_message(err),
            "invalid delete path \"C:\\tmp\\file.txt\": internal contract violation: requested path must stay root-relative"
        );
    }

    #[test]
    fn reports_contract_violation_before_leaf_extraction() {
        let err = ensure_non_root_leaf(Path::new(""), Path::new(""), LeafOp::Delete)
            .expect_err("empty path should be rejected as contract violation");

        assert_eq!(
            invalid_path_message(err),
            "invalid delete path \"\": internal contract violation: requested path must be normalized root-relative"
        );
    }

    #[test]
    fn accepts_normalized_non_root_leaf() {
        let leaf = ensure_non_root_leaf(
            Path::new("nested/file.txt"),
            Path::new("nested/file.txt"),
            LeafOp::Delete,
        )
        .expect("valid normalized path should pass");

        assert_eq!(leaf, OsStr::new("file.txt"));
    }
}
