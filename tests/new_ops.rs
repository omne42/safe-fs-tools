mod common;

use std::path::PathBuf;

use common::test_policy;
use safe_fs_tools::ops::{
    Context, CopyFileRequest, DeleteRequest, ListDirRequest, MkdirRequest, MovePathRequest,
    StatRequest, WriteFileRequest, copy_file, delete, list_dir, mkdir, move_path, stat, write_file,
};
use safe_fs_tools::policy::RootMode;

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

    assert!(resp.truncated);
    assert_eq!(resp.entries.len(), 2);
    assert_eq!(resp.entries[0].name, "a.txt");
    assert_eq!(resp.entries[1].name, "b.txt");
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

    assert_eq!(resp.kind, "file");
    assert_eq!(resp.size_bytes, 2);
    assert!(resp.modified_ms.is_some());
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
    assert!(!resp.created);
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
    assert!(resp.created);
    assert_eq!(
        std::fs::read_to_string(dir.path().join("sub").join("file.txt")).unwrap(),
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
    assert_eq!(err.code(), "invalid_path");

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
    assert!(!resp.created);
    assert_eq!(
        std::fs::read_to_string(dir.path().join("sub").join("file.txt")).unwrap(),
        "bye"
    );
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

    assert!(resp.moved);
    assert!(!dir.path().join("a.txt").exists());
    assert_eq!(
        std::fs::read_to_string(dir.path().join("b.txt")).unwrap(),
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

    assert_eq!(err.code(), "invalid_path");
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

    assert!(resp.copied);
    assert_eq!(resp.bytes, 2);
    assert_eq!(
        std::fs::read_to_string(dir.path().join("b.txt")).unwrap(),
        "hi"
    );
}

#[test]
#[cfg(unix)]
fn copy_file_rejects_symlink_sources() {
    use std::os::unix::fs::symlink;

    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(dir.path().join("real.txt"), "hi").expect("write");
    symlink(dir.path().join("real.txt"), dir.path().join("link.txt")).expect("symlink");

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

    assert_eq!(err.code(), "invalid_path");
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

    assert!(resp.deleted);
    assert_eq!(resp.kind, "dir");
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
    assert!(!resp.deleted);
    assert_eq!(resp.kind, "missing");
}
