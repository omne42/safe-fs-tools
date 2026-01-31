mod common;

use std::path::PathBuf;

use common::test_policy;
use safe_fs_tools::ops::{Context, DeleteRequest, delete};
use safe_fs_tools::policy::RootMode;

#[test]
fn delete_absolute_paths_report_relative_requested_path_on_errors() {
    let dir = tempfile::tempdir().expect("tempdir");
    let ctx = Context::new(test_policy(dir.path(), RootMode::ReadWrite)).expect("ctx");

    let abs = dir.path().join("missing").join("file.txt");
    let err = delete(
        &ctx,
        DeleteRequest {
            root_id: "root".to_string(),
            path: abs,
            recursive: false,
            ignore_missing: false,
        },
    )
    .expect_err("should reject");

    match err {
        safe_fs_tools::Error::IoPath { op, path, .. } => {
            assert_eq!(op, "metadata");
            assert_eq!(path, PathBuf::from("missing"));
        }
        other => panic!("unexpected error: {other:?}"),
    }
}

#[test]
#[cfg(unix)]
fn delete_unlinks_symlink_without_deleting_target() {
    use std::os::unix::fs::symlink;

    let dir = tempfile::tempdir().expect("tempdir");
    let target = dir.path().join("target.txt");
    let link = dir.path().join("link.txt");
    std::fs::write(&target, "hello\n").expect("write");
    symlink(&target, &link).expect("symlink");

    let ctx = Context::new(test_policy(dir.path(), RootMode::ReadWrite)).expect("ctx");
    let resp = delete(
        &ctx,
        DeleteRequest {
            root_id: "root".to_string(),
            path: PathBuf::from("link.txt"),
            recursive: false,
            ignore_missing: false,
        },
    )
    .expect("delete");
    assert_eq!(resp.requested_path, Some(PathBuf::from("link.txt")));
    assert!(resp.deleted);
    assert_eq!(resp.kind, "symlink");

    assert!(!link.exists());
    assert!(target.exists());
}

#[test]
#[cfg(unix)]
fn delete_unlinks_symlink_even_if_target_is_outside_root() {
    use std::os::unix::fs::symlink;

    let dir = tempfile::tempdir().expect("tempdir");
    let outside = tempfile::NamedTempFile::new().expect("tmp");
    std::fs::write(outside.path(), "hello\n").expect("write");
    let link = dir.path().join("outside-link.txt");
    symlink(outside.path(), &link).expect("symlink");

    let ctx = Context::new(test_policy(dir.path(), RootMode::ReadWrite)).expect("ctx");
    let resp = delete(
        &ctx,
        DeleteRequest {
            root_id: "root".to_string(),
            path: PathBuf::from("outside-link.txt"),
            recursive: false,
            ignore_missing: false,
        },
    )
    .expect("delete");
    assert_eq!(resp.requested_path, Some(PathBuf::from("outside-link.txt")));
    assert!(resp.deleted);
    assert_eq!(resp.kind, "symlink");

    assert!(!link.exists());
    assert!(outside.path().exists());
}

#[test]
#[cfg(unix)]
fn delete_denies_requested_path_before_resolving_symlink_dirs() {
    use std::os::unix::fs::symlink;

    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::create_dir_all(dir.path().join("allowed")).expect("mkdir");
    std::fs::write(dir.path().join("allowed").join("file.txt"), "hello\n").expect("write");
    symlink(dir.path().join("allowed"), dir.path().join("deny")).expect("symlink dir");

    let mut policy = test_policy(dir.path(), RootMode::ReadWrite);
    policy.secrets.deny_globs = vec!["deny/**".to_string()];
    let ctx = Context::new(policy).expect("ctx");

    let err = delete(
        &ctx,
        DeleteRequest {
            root_id: "root".to_string(),
            path: PathBuf::from("deny/file.txt"),
            recursive: false,
            ignore_missing: false,
        },
    )
    .expect_err("should reject");

    match err {
        safe_fs_tools::Error::SecretPathDenied(path) => {
            assert_eq!(path, PathBuf::from("deny/file.txt"));
        }
        other => panic!("unexpected error: {other:?}"),
    }

    assert!(
        dir.path().join("allowed").join("file.txt").exists(),
        "expected file to remain after denied delete"
    );
}

#[test]
fn delete_is_not_allowed_on_readonly_root() {
    let dir = tempfile::tempdir().expect("tempdir");
    let ctx = Context::new(test_policy(dir.path(), RootMode::ReadOnly)).expect("ctx");

    let err = delete(
        &ctx,
        DeleteRequest {
            root_id: "root".to_string(),
            path: PathBuf::from("file.txt"),
            recursive: false,
            ignore_missing: false,
        },
    )
    .expect_err("should reject");

    match err {
        safe_fs_tools::Error::NotPermitted(_) => {}
        other => panic!("unexpected error: {other:?}"),
    }
}

#[test]
fn delete_rejects_dot_and_empty_paths() {
    let dir = tempfile::tempdir().expect("tempdir");
    let ctx = Context::new(test_policy(dir.path(), RootMode::ReadWrite)).expect("ctx");

    let err = delete(
        &ctx,
        DeleteRequest {
            root_id: "root".to_string(),
            path: PathBuf::from("."),
            recursive: false,
            ignore_missing: false,
        },
    )
    .expect_err("should reject");

    match err {
        safe_fs_tools::Error::InvalidPath(message) => {
            assert!(message.contains("refusing to delete the root directory"));
        }
        other => panic!("unexpected error: {other:?}"),
    }

    let err = delete(
        &ctx,
        DeleteRequest {
            root_id: "root".to_string(),
            path: PathBuf::from(""),
            recursive: false,
            ignore_missing: false,
        },
    )
    .expect_err("should reject");

    match err {
        safe_fs_tools::Error::InvalidPath(message) => {
            assert!(message.contains("path is empty"));
        }
        other => panic!("unexpected error: {other:?}"),
    }
}

#[test]
fn delete_rejects_directories_without_recursive() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::create_dir_all(dir.path().join("subdir")).expect("mkdir");

    let ctx = Context::new(test_policy(dir.path(), RootMode::ReadWrite)).expect("ctx");

    let err = delete(
        &ctx,
        DeleteRequest {
            root_id: "root".to_string(),
            path: PathBuf::from("subdir"),
            recursive: false,
            ignore_missing: false,
        },
    )
    .expect_err("should reject");

    match err {
        safe_fs_tools::Error::InvalidPath(message) => {
            assert!(message.contains("recursive=true"));
        }
        other => panic!("unexpected error: {other:?}"),
    }
}
