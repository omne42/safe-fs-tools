mod common;

use std::path::PathBuf;

use common::permissive_test_policy as test_policy;
use safe_fs_tools::ops::{
    Context, CopyFileRequest, DeleteKind, DeleteRequest, ListDirRequest, MkdirRequest,
    MovePathRequest, StatRequest, WriteFileRequest, copy_file, delete, list_dir, mkdir, move_path,
    stat, write_file,
};
use safe_fs_tools::policy::RootMode;

#[cfg(any(unix, windows))]
fn create_file_symlink(target: &std::path::Path, link: &std::path::Path) {
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(target, link).expect("symlink");
    }

    #[cfg(windows)]
    {
        std::os::windows::fs::symlink_file(target, link).expect("symlink_file");
    }
}

fn assert_not_permitted(err: safe_fs_tools::Error, expected_op: &str) {
    assert_eq!(err.code(), safe_fs_tools::Error::CODE_NOT_PERMITTED);
    match err {
        safe_fs_tools::Error::NotPermitted(message) => {
            assert!(
                message.contains(expected_op),
                "expected not_permitted message to contain '{expected_op}', got '{message}'"
            );
        }
        other => panic!("unexpected error: {other:?}"),
    }
}

#[test]
fn list_dir_lists_entries_in_sorted_order_and_truncates() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(dir.path().join("b.txt"), "b").expect("write");
    std::fs::write(dir.path().join("a.txt"), "a").expect("write");
    std::fs::create_dir_all(dir.path().join("sub")).expect("mkdir");

    let ctx = Context::new(test_policy(dir.path(), RootMode::ReadOnly)).expect("ctx");
    let resp = list_dir(
        &ctx,
        ListDirRequest {
            root_id: "root".to_string(),
            path: PathBuf::from("."),
            max_entries: Some(2),
        },
    )
    .expect("list");

    assert_eq!(resp.path, PathBuf::from("."));
    assert_eq!(resp.requested_path, Some(PathBuf::from(".")));
    assert_eq!(resp.skipped_io_errors, 0);
    assert!(resp.truncated);
    assert_eq!(resp.entries.len(), 2);
    assert_eq!(resp.entries[0].name, "a.txt");
    assert_eq!(resp.entries[1].name, "b.txt");
}

#[test]
fn list_dir_allows_zero_max_entries() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(dir.path().join("a.txt"), "a").expect("write");

    let ctx = Context::new(test_policy(dir.path(), RootMode::ReadOnly)).expect("ctx");
    let resp = list_dir(
        &ctx,
        ListDirRequest {
            root_id: "root".to_string(),
            path: PathBuf::from("."),
            max_entries: Some(0),
        },
    )
    .expect("list");

    assert_eq!(resp.path, PathBuf::from("."));
    assert_eq!(resp.requested_path, Some(PathBuf::from(".")));
    assert_eq!(resp.skipped_io_errors, 0);
    assert!(resp.entries.is_empty());
    assert!(resp.truncated);
}

#[test]
fn stat_reports_file_metadata() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(dir.path().join("a.txt"), "hi").expect("write");

    let ctx = Context::new(test_policy(dir.path(), RootMode::ReadOnly)).expect("ctx");
    let resp = stat(
        &ctx,
        StatRequest {
            root_id: "root".to_string(),
            path: PathBuf::from("a.txt"),
        },
    )
    .expect("stat");

    assert!(matches!(resp.kind, safe_fs_tools::ops::StatKind::File));
    assert_eq!(resp.size_bytes, 2);
    assert!(!resp.readonly);
    assert!(resp.modified_ms.is_some());
}

#[test]
#[cfg(any(unix, windows))]
#[cfg_attr(windows, ignore = "requires symlink privilege")]
fn stat_rejects_symlink_targets() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(dir.path().join("real.txt"), "hi").expect("write");
    create_file_symlink(&dir.path().join("real.txt"), &dir.path().join("link.txt"));

    let mut policy = test_policy(dir.path(), RootMode::ReadOnly);
    policy.permissions.stat = true;
    let ctx = Context::new(policy).expect("ctx");

    let err = stat(
        &ctx,
        StatRequest {
            root_id: "root".to_string(),
            path: PathBuf::from("link.txt"),
        },
    )
    .expect_err("stat should reject symlink");

    assert_eq!(err.code(), safe_fs_tools::Error::CODE_INVALID_PATH);
    assert!(matches!(err, safe_fs_tools::Error::InvalidPath(_)));
}

#[test]
fn mkdir_creates_directories_and_can_ignore_existing() {
    let dir = tempfile::tempdir().expect("tempdir");

    let ctx = Context::new(test_policy(dir.path(), RootMode::ReadWrite)).expect("ctx");
    let resp = mkdir(
        &ctx,
        MkdirRequest {
            root_id: "root".to_string(),
            path: PathBuf::from("sub"),
            create_parents: false,
            ignore_existing: true,
        },
    )
    .expect("mkdir");
    assert_eq!(resp.path, PathBuf::from("sub"));
    assert_eq!(resp.requested_path, Some(PathBuf::from("sub")));
    assert!(resp.created);
    assert!(dir.path().join("sub").is_dir());

    let resp = mkdir(
        &ctx,
        MkdirRequest {
            root_id: "root".to_string(),
            path: PathBuf::from("sub"),
            create_parents: false,
            ignore_existing: true,
        },
    )
    .expect("mkdir");
    assert_eq!(resp.path, PathBuf::from("sub"));
    assert_eq!(resp.requested_path, Some(PathBuf::from("sub")));
    assert!(!resp.created);
}

#[test]
fn mkdir_rejects_existing_paths_when_creation_is_not_allowed() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::create_dir_all(dir.path().join("sub")).expect("mkdir");
    std::fs::write(dir.path().join("file.txt"), "hi").expect("write");

    let mut policy = test_policy(dir.path(), RootMode::ReadWrite);
    policy.permissions.mkdir = true;
    let ctx = Context::new(policy).expect("ctx");

    let existing_dir_err = mkdir(
        &ctx,
        MkdirRequest {
            root_id: "root".to_string(),
            path: PathBuf::from("sub"),
            create_parents: false,
            ignore_existing: false,
        },
    )
    .expect_err("mkdir should reject existing dir when ignore_existing=false");
    assert_eq!(
        existing_dir_err.code(),
        safe_fs_tools::Error::CODE_INVALID_PATH
    );
    assert!(matches!(
        existing_dir_err,
        safe_fs_tools::Error::InvalidPath(_)
    ));

    let existing_file_err = mkdir(
        &ctx,
        MkdirRequest {
            root_id: "root".to_string(),
            path: PathBuf::from("file.txt"),
            create_parents: false,
            ignore_existing: false,
        },
    )
    .expect_err("mkdir should reject existing file target");
    assert_eq!(
        existing_file_err.code(),
        safe_fs_tools::Error::CODE_INVALID_PATH
    );
    assert!(matches!(
        existing_file_err,
        safe_fs_tools::Error::InvalidPath(_)
    ));
}

#[test]
#[cfg(any(unix, windows))]
#[cfg_attr(windows, ignore = "requires symlink privilege")]
fn mkdir_rejects_symlink_targets() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::create_dir_all(dir.path().join("real_dir")).expect("mkdir");
    create_file_symlink(
        &dir.path().join("real_dir"),
        &dir.path().join("link_to_dir"),
    );

    let mut policy = test_policy(dir.path(), RootMode::ReadWrite);
    policy.permissions.mkdir = true;
    let ctx = Context::new(policy).expect("ctx");

    let err = mkdir(
        &ctx,
        MkdirRequest {
            root_id: "root".to_string(),
            path: PathBuf::from("link_to_dir"),
            create_parents: false,
            ignore_existing: true,
        },
    )
    .expect_err("mkdir should reject symlink targets");

    assert_eq!(err.code(), safe_fs_tools::Error::CODE_INVALID_PATH);
    assert!(matches!(err, safe_fs_tools::Error::InvalidPath(_)));
}

#[test]
fn mkdir_rejects_readonly_root() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut policy = test_policy(dir.path(), RootMode::ReadOnly);
    policy.permissions.mkdir = true;
    let ctx = Context::new(policy).expect("ctx");

    let err = mkdir(
        &ctx,
        MkdirRequest {
            root_id: "root".to_string(),
            path: PathBuf::from("sub"),
            create_parents: false,
            ignore_existing: false,
        },
    )
    .expect_err("mkdir should reject readonly root");
    assert_not_permitted(err, "mkdir");
}

#[test]
fn write_file_creates_new_files_and_respects_overwrite() {
    let dir = tempfile::tempdir().expect("tempdir");

    let ctx = Context::new(test_policy(dir.path(), RootMode::ReadWrite)).expect("ctx");
    let resp = write_file(
        &ctx,
        WriteFileRequest {
            root_id: "root".to_string(),
            path: PathBuf::from("sub/file.txt"),
            content: "hi".to_string(),
            overwrite: false,
            create_parents: true,
        },
    )
    .expect("write");
    assert_eq!(resp.path, PathBuf::from("sub/file.txt"));
    assert_eq!(resp.requested_path, Some(PathBuf::from("sub/file.txt")));
    assert_eq!(resp.bytes_written, 2);
    assert!(resp.created);
    assert_eq!(
        std::fs::read_to_string(dir.path().join("sub").join("file.txt"))
            .expect("read created file"),
        "hi"
    );

    let err = write_file(
        &ctx,
        WriteFileRequest {
            root_id: "root".to_string(),
            path: PathBuf::from("sub/file.txt"),
            content: "bye".to_string(),
            overwrite: false,
            create_parents: false,
        },
    )
    .expect_err("should reject");
    assert_eq!(err.code(), safe_fs_tools::Error::CODE_INVALID_PATH);
    assert!(matches!(err, safe_fs_tools::Error::InvalidPath(_)));
    assert_eq!(
        std::fs::read_to_string(dir.path().join("sub").join("file.txt"))
            .expect("read unchanged file"),
        "hi"
    );

    let resp = write_file(
        &ctx,
        WriteFileRequest {
            root_id: "root".to_string(),
            path: PathBuf::from("sub/file.txt"),
            content: "bye".to_string(),
            overwrite: true,
            create_parents: false,
        },
    )
    .expect("write");
    assert_eq!(resp.path, PathBuf::from("sub/file.txt"));
    assert_eq!(resp.requested_path, Some(PathBuf::from("sub/file.txt")));
    assert_eq!(resp.bytes_written, 3);
    assert!(!resp.created);
    assert_eq!(
        std::fs::read_to_string(dir.path().join("sub").join("file.txt"))
            .expect("read overwritten file"),
        "bye"
    );
}

#[test]
fn write_file_rejects_directory_targets() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::create_dir_all(dir.path().join("sub")).expect("mkdir");

    let mut policy = test_policy(dir.path(), RootMode::ReadWrite);
    policy.permissions.write = true;
    let ctx = Context::new(policy).expect("ctx");
    let err = write_file(
        &ctx,
        WriteFileRequest {
            root_id: "root".to_string(),
            path: PathBuf::from("sub"),
            content: "x".to_string(),
            overwrite: true,
            create_parents: false,
        },
    )
    .expect_err("write should reject directory target");

    assert_eq!(err.code(), safe_fs_tools::Error::CODE_INVALID_PATH);
    assert!(matches!(err, safe_fs_tools::Error::InvalidPath(_)));
}

#[test]
#[cfg(any(unix, windows))]
#[cfg_attr(windows, ignore = "requires symlink privilege")]
fn write_file_rejects_symlink_targets() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(dir.path().join("real.txt"), "real").expect("write");
    create_file_symlink(&dir.path().join("real.txt"), &dir.path().join("link.txt"));

    let mut policy = test_policy(dir.path(), RootMode::ReadWrite);
    policy.permissions.write = true;
    let ctx = Context::new(policy).expect("ctx");
    let err = write_file(
        &ctx,
        WriteFileRequest {
            root_id: "root".to_string(),
            path: PathBuf::from("link.txt"),
            content: "new".to_string(),
            overwrite: true,
            create_parents: false,
        },
    )
    .expect_err("write should reject symlink target");

    assert_eq!(err.code(), safe_fs_tools::Error::CODE_INVALID_PATH);
    assert!(matches!(err, safe_fs_tools::Error::InvalidPath(_)));
    assert_eq!(
        std::fs::read_to_string(dir.path().join("real.txt")).expect("read target"),
        "real"
    );
}

#[test]
fn write_file_rejects_content_larger_than_max_write_bytes() {
    let dir = tempfile::tempdir().expect("tempdir");

    let mut policy = test_policy(dir.path(), RootMode::ReadWrite);
    policy.permissions.write = true;
    policy.limits.max_write_bytes = 1;
    let ctx = Context::new(policy).expect("ctx");
    let err = write_file(
        &ctx,
        WriteFileRequest {
            root_id: "root".to_string(),
            path: PathBuf::from("too_large.txt"),
            content: "hi".to_string(),
            overwrite: false,
            create_parents: false,
        },
    )
    .expect_err("write should enforce max_write_bytes");

    assert_eq!(err.code(), safe_fs_tools::Error::CODE_FILE_TOO_LARGE);
    match err {
        safe_fs_tools::Error::FileTooLarge {
            path,
            size_bytes,
            max_bytes,
        } => {
            assert_eq!(path, PathBuf::from("too_large.txt"));
            assert_eq!(size_bytes, 2);
            assert_eq!(max_bytes, 1);
        }
        other => panic!("unexpected error: {other:?}"),
    }
}

#[test]
fn write_file_rejects_readonly_root() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut policy = test_policy(dir.path(), RootMode::ReadOnly);
    policy.permissions.write = true;
    let ctx = Context::new(policy).expect("ctx");

    let err = write_file(
        &ctx,
        WriteFileRequest {
            root_id: "root".to_string(),
            path: PathBuf::from("file.txt"),
            content: "hello".to_string(),
            overwrite: false,
            create_parents: false,
        },
    )
    .expect_err("write should reject readonly root");
    assert_not_permitted(err, "write");
}

#[test]
fn move_path_renames_entries() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(dir.path().join("a.txt"), "hi").expect("write");

    let ctx = Context::new(test_policy(dir.path(), RootMode::ReadWrite)).expect("ctx");
    let resp = move_path(
        &ctx,
        MovePathRequest {
            root_id: "root".to_string(),
            from: PathBuf::from("a.txt"),
            to: PathBuf::from("b.txt"),
            overwrite: false,
            create_parents: false,
        },
    )
    .expect("move");

    assert_eq!(resp.from, PathBuf::from("a.txt"));
    assert_eq!(resp.to, PathBuf::from("b.txt"));
    assert_eq!(resp.requested_from, Some(PathBuf::from("a.txt")));
    assert_eq!(resp.requested_to, Some(PathBuf::from("b.txt")));
    assert!(resp.moved);
    assert_eq!(resp.kind, "file");
    assert!(!dir.path().join("a.txt").exists());
    assert_eq!(
        std::fs::read_to_string(dir.path().join("b.txt")).expect("read moved file"),
        "hi"
    );
}

#[test]
fn move_path_rejects_moving_directory_into_descendant() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::create_dir_all(dir.path().join("a").join("sub")).expect("mkdir");

    let ctx = Context::new(test_policy(dir.path(), RootMode::ReadWrite)).expect("ctx");
    let err = move_path(
        &ctx,
        MovePathRequest {
            root_id: "root".to_string(),
            from: PathBuf::from("a"),
            to: PathBuf::from("a/sub/new"),
            overwrite: false,
            create_parents: false,
        },
    )
    .expect_err("should reject");

    assert_eq!(err.code(), safe_fs_tools::Error::CODE_INVALID_PATH);
    assert!(matches!(err, safe_fs_tools::Error::InvalidPath(_)));
    assert!(dir.path().join("a").is_dir());
    assert!(dir.path().join("a").join("sub").is_dir());
}

#[test]
fn move_path_rejects_readonly_root() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(dir.path().join("a.txt"), "hi").expect("write");

    let mut policy = test_policy(dir.path(), RootMode::ReadOnly);
    policy.permissions.move_path = true;
    let ctx = Context::new(policy).expect("ctx");
    let err = move_path(
        &ctx,
        MovePathRequest {
            root_id: "root".to_string(),
            from: PathBuf::from("a.txt"),
            to: PathBuf::from("b.txt"),
            overwrite: false,
            create_parents: false,
        },
    )
    .expect_err("move should reject readonly root");

    assert_not_permitted(err, "move");
    assert!(dir.path().join("a.txt").exists());
    assert!(!dir.path().join("b.txt").exists());
}

#[test]
fn copy_file_copies_regular_files() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(dir.path().join("a.txt"), "hi").expect("write");

    let ctx = Context::new(test_policy(dir.path(), RootMode::ReadWrite)).expect("ctx");
    let resp = copy_file(
        &ctx,
        CopyFileRequest {
            root_id: "root".to_string(),
            from: PathBuf::from("a.txt"),
            to: PathBuf::from("b.txt"),
            overwrite: false,
            create_parents: false,
        },
    )
    .expect("copy");

    assert_eq!(resp.from, PathBuf::from("a.txt"));
    assert_eq!(resp.to, PathBuf::from("b.txt"));
    assert_eq!(resp.requested_from, Some(PathBuf::from("a.txt")));
    assert_eq!(resp.requested_to, Some(PathBuf::from("b.txt")));
    assert!(resp.copied);
    assert_eq!(resp.bytes, 2);
    assert_eq!(
        std::fs::read_to_string(dir.path().join("b.txt")).expect("read copied file"),
        "hi"
    );
}

#[test]
fn copy_file_same_path_still_validates_source_exists() {
    let dir = tempfile::tempdir().expect("tempdir");
    let ctx = Context::new(test_policy(dir.path(), RootMode::ReadWrite)).expect("ctx");

    let err = copy_file(
        &ctx,
        CopyFileRequest {
            root_id: "root".to_string(),
            from: PathBuf::from("missing.txt"),
            to: PathBuf::from("missing.txt"),
            overwrite: false,
            create_parents: false,
        },
    )
    .expect_err("same-path copy should still validate source");

    match err {
        safe_fs_tools::Error::IoPath { source, .. } => {
            assert_eq!(source.kind(), std::io::ErrorKind::NotFound);
        }
        other => panic!("unexpected error: {other:?}"),
    }
}

#[test]
fn copy_file_same_path_is_a_noop_when_source_exists() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(dir.path().join("same.txt"), "hi").expect("write");

    let ctx = Context::new(test_policy(dir.path(), RootMode::ReadWrite)).expect("ctx");
    let resp = copy_file(
        &ctx,
        CopyFileRequest {
            root_id: "root".to_string(),
            from: PathBuf::from("same.txt"),
            to: PathBuf::from("same.txt"),
            overwrite: false,
            create_parents: false,
        },
    )
    .expect("same-path copy should be a no-op");

    assert_eq!(resp.from, PathBuf::from("same.txt"));
    assert_eq!(resp.to, PathBuf::from("same.txt"));
    assert_eq!(resp.requested_from, Some(PathBuf::from("same.txt")));
    assert_eq!(resp.requested_to, Some(PathBuf::from("same.txt")));
    assert!(!resp.copied);
    assert_eq!(resp.bytes, 0);
    assert_eq!(
        std::fs::read_to_string(dir.path().join("same.txt")).expect("read original file"),
        "hi"
    );
}

#[test]
#[cfg(any(unix, windows))]
#[cfg_attr(windows, ignore = "requires symlink privilege")]
fn copy_file_rejects_symlink_sources() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(dir.path().join("real.txt"), "hi").expect("write");
    create_file_symlink(&dir.path().join("real.txt"), &dir.path().join("link.txt"));

    let ctx = Context::new(test_policy(dir.path(), RootMode::ReadWrite)).expect("ctx");
    let err = copy_file(
        &ctx,
        CopyFileRequest {
            root_id: "root".to_string(),
            from: PathBuf::from("link.txt"),
            to: PathBuf::from("out.txt"),
            overwrite: false,
            create_parents: false,
        },
    )
    .expect_err("copy should reject symlink source");

    assert_eq!(err.code(), safe_fs_tools::Error::CODE_INVALID_PATH);
    assert!(matches!(err, safe_fs_tools::Error::InvalidPath(_)));
    assert!(!dir.path().join("out.txt").exists());
}

#[test]
fn copy_file_rejects_readonly_root() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(dir.path().join("a.txt"), "hi").expect("write");

    let mut policy = test_policy(dir.path(), RootMode::ReadOnly);
    policy.permissions.copy_file = true;
    let ctx = Context::new(policy).expect("ctx");
    let err = copy_file(
        &ctx,
        CopyFileRequest {
            root_id: "root".to_string(),
            from: PathBuf::from("a.txt"),
            to: PathBuf::from("b.txt"),
            overwrite: false,
            create_parents: false,
        },
    )
    .expect_err("copy should reject readonly root");

    assert_not_permitted(err, "copy_file");
    assert!(dir.path().join("a.txt").exists());
    assert!(!dir.path().join("b.txt").exists());
}

#[test]
fn delete_deletes_dirs_recursively_and_ignores_missing() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::create_dir_all(dir.path().join("sub")).expect("mkdir");
    std::fs::write(dir.path().join("sub").join("a.txt"), "hi").expect("write");

    let ctx = Context::new(test_policy(dir.path(), RootMode::ReadWrite)).expect("ctx");
    let resp = delete(
        &ctx,
        DeleteRequest {
            root_id: "root".to_string(),
            path: PathBuf::from("sub"),
            recursive: true,
            ignore_missing: false,
        },
    )
    .expect("delete");

    assert_eq!(resp.path, PathBuf::from("sub"));
    assert_eq!(resp.requested_path, Some(PathBuf::from("sub")));
    assert!(resp.deleted);
    assert_eq!(resp.kind, DeleteKind::Dir);
    assert!(!dir.path().join("sub").exists());

    let resp = delete(
        &ctx,
        DeleteRequest {
            root_id: "root".to_string(),
            path: PathBuf::from("missing"),
            recursive: false,
            ignore_missing: true,
        },
    )
    .expect("delete");
    assert_eq!(resp.path, PathBuf::from("missing"));
    assert_eq!(resp.requested_path, Some(PathBuf::from("missing")));
    assert!(!resp.deleted);
    assert_eq!(resp.kind, DeleteKind::Missing);
}

#[test]
fn delete_rejects_directory_without_recursive() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::create_dir_all(dir.path().join("sub")).expect("mkdir");

    let mut policy = test_policy(dir.path(), RootMode::ReadWrite);
    policy.permissions.delete = true;
    let ctx = Context::new(policy).expect("ctx");
    let err = delete(
        &ctx,
        DeleteRequest {
            root_id: "root".to_string(),
            path: PathBuf::from("sub"),
            recursive: false,
            ignore_missing: false,
        },
    )
    .expect_err("delete should reject non-recursive directory delete");

    assert_eq!(err.code(), safe_fs_tools::Error::CODE_INVALID_PATH);
    assert!(matches!(err, safe_fs_tools::Error::InvalidPath(_)));
    assert!(dir.path().join("sub").is_dir());
}

#[test]
fn delete_rejects_readonly_root() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(dir.path().join("file.txt"), "keep").expect("write");

    let mut policy = test_policy(dir.path(), RootMode::ReadOnly);
    policy.permissions.delete = true;
    let ctx = Context::new(policy).expect("ctx");
    let err = delete(
        &ctx,
        DeleteRequest {
            root_id: "root".to_string(),
            path: PathBuf::from("file.txt"),
            recursive: false,
            ignore_missing: false,
        },
    )
    .expect_err("delete should reject readonly root");

    assert_not_permitted(err, "delete");
    assert!(dir.path().join("file.txt").exists());
}
