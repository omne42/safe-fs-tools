mod common;

use std::path::PathBuf;

use common::test_policy;
use safe_fs_tools::ops::{
    Context, CopyFileRequest, DeleteRequest, EditRequest, GlobRequest, GrepRequest, ListDirRequest,
    MkdirRequest, MovePathRequest, ReadRequest, StatRequest, WriteFileRequest, copy_file, delete,
    edit_range, glob_paths, grep, list_dir, mkdir, move_path, read_file, stat, write_file,
};
use safe_fs_tools::policy::RootMode;

#[cfg(feature = "patch")]
use safe_fs_tools::ops::{PatchRequest, apply_unified_patch};

fn assert_not_permitted(err: safe_fs_tools::Error) {
    assert!(matches!(err, safe_fs_tools::Error::NotPermitted(_)));
}

#[test]
fn read_is_disabled_by_policy() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(dir.path().join("file.txt"), "hello\n").expect("write");

    let mut policy = test_policy(dir.path(), RootMode::ReadOnly);
    policy.permissions.read = false;
    let ctx = Context::new(policy).expect("ctx");

    let err = read_file(
        &ctx,
        ReadRequest {
            root_id: "root".to_string(),
            path: PathBuf::from("file.txt"),
            start_line: None,
            end_line: None,
        },
    )
    .expect_err("should reject");
    assert_not_permitted(err);
}

#[test]
fn glob_is_disabled_by_policy() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(dir.path().join("file.txt"), "hello\n").expect("write");

    let mut policy = test_policy(dir.path(), RootMode::ReadOnly);
    policy.permissions.glob = false;
    let ctx = Context::new(policy).expect("ctx");

    let err = glob_paths(
        &ctx,
        GlobRequest {
            root_id: "root".to_string(),
            pattern: "**/*.txt".to_string(),
        },
    )
    .expect_err("should reject");

    assert_not_permitted(err);
}

#[test]
fn grep_is_disabled_by_policy() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(dir.path().join("file.txt"), "hello\n").expect("write");

    let mut policy = test_policy(dir.path(), RootMode::ReadOnly);
    policy.permissions.grep = false;
    let ctx = Context::new(policy).expect("ctx");

    let err = grep(
        &ctx,
        GrepRequest {
            root_id: "root".to_string(),
            query: "hello".to_string(),
            regex: false,
            glob: None,
        },
    )
    .expect_err("should reject");

    assert_not_permitted(err);
}

#[test]
fn list_dir_is_disabled_by_policy() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(dir.path().join("file.txt"), "hello\n").expect("write");

    let mut policy = test_policy(dir.path(), RootMode::ReadOnly);
    policy.permissions.list_dir = false;
    let ctx = Context::new(policy).expect("ctx");

    let err = list_dir(
        &ctx,
        ListDirRequest {
            root_id: "root".to_string(),
            path: PathBuf::from("."),
            max_entries: None,
        },
    )
    .expect_err("should reject");

    assert_not_permitted(err);
}

#[test]
fn stat_is_disabled_by_policy() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(dir.path().join("file.txt"), "hello\n").expect("write");

    let mut policy = test_policy(dir.path(), RootMode::ReadOnly);
    policy.permissions.stat = false;
    let ctx = Context::new(policy).expect("ctx");

    let err = stat(
        &ctx,
        StatRequest {
            root_id: "root".to_string(),
            path: PathBuf::from("file.txt"),
        },
    )
    .expect_err("should reject");

    assert_not_permitted(err);
}

#[test]
fn edit_is_disabled_by_policy() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(dir.path().join("file.txt"), "hello\n").expect("write");

    let mut policy = test_policy(dir.path(), RootMode::ReadWrite);
    policy.permissions.edit = false;
    let ctx = Context::new(policy).expect("ctx");

    let err = edit_range(
        &ctx,
        EditRequest {
            root_id: "root".to_string(),
            path: PathBuf::from("file.txt"),
            start_line: 1,
            end_line: 1,
            replacement: "HELLO".to_string(),
        },
    )
    .expect_err("should reject");

    assert_not_permitted(err);
}

#[test]
#[cfg(feature = "patch")]
fn patch_is_disabled_by_policy() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(dir.path().join("file.txt"), "hello\n").expect("write");

    let mut policy = test_policy(dir.path(), RootMode::ReadWrite);
    policy.permissions.patch = false;
    let ctx = Context::new(policy).expect("ctx");

    let err = apply_unified_patch(
        &ctx,
        PatchRequest {
            root_id: "root".to_string(),
            path: PathBuf::from("file.txt"),
            patch: "x".to_string(),
        },
    )
    .expect_err("should reject");

    assert_not_permitted(err);
}

#[test]
fn mkdir_is_disabled_by_policy() {
    let dir = tempfile::tempdir().expect("tempdir");

    let mut policy = test_policy(dir.path(), RootMode::ReadWrite);
    policy.permissions.mkdir = false;
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
    .expect_err("should reject");

    assert_not_permitted(err);
}

#[test]
fn write_is_disabled_by_policy() {
    let dir = tempfile::tempdir().expect("tempdir");

    let mut policy = test_policy(dir.path(), RootMode::ReadWrite);
    policy.permissions.write = false;
    let ctx = Context::new(policy).expect("ctx");

    let err = write_file(
        &ctx,
        WriteFileRequest {
            root_id: "root".to_string(),
            path: PathBuf::from("file.txt"),
            content: "hello\n".to_string(),
            overwrite: false,
            create_parents: false,
        },
    )
    .expect_err("should reject");

    assert_not_permitted(err);
}

#[test]
fn delete_is_disabled_by_policy() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(dir.path().join("file.txt"), "hello\n").expect("write");

    let mut policy = test_policy(dir.path(), RootMode::ReadWrite);
    policy.permissions.delete = false;
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
    .expect_err("should reject");

    assert_not_permitted(err);
}

#[test]
fn move_is_disabled_by_policy() {
    let dir = tempfile::tempdir().expect("tempdir");

    let mut policy = test_policy(dir.path(), RootMode::ReadWrite);
    policy.permissions.move_path = false;
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
    .expect_err("should reject");

    assert_not_permitted(err);
}

#[test]
fn copy_is_disabled_by_policy() {
    let dir = tempfile::tempdir().expect("tempdir");

    let mut policy = test_policy(dir.path(), RootMode::ReadWrite);
    policy.permissions.copy_file = false;
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
    .expect_err("should reject");

    assert_not_permitted(err);
}

#[test]
fn write_ops_are_disallowed_on_readonly_root() {
    let dir = tempfile::tempdir().expect("tempdir");
    let ctx = Context::new(test_policy(dir.path(), RootMode::ReadOnly)).expect("ctx");

    let err = edit_range(
        &ctx,
        EditRequest {
            root_id: "root".to_string(),
            path: PathBuf::from("file.txt"),
            start_line: 1,
            end_line: 1,
            replacement: "HELLO".to_string(),
        },
    )
    .expect_err("should reject");
    assert_not_permitted(err);

    #[cfg(feature = "patch")]
    {
        let err = apply_unified_patch(
            &ctx,
            PatchRequest {
                root_id: "root".to_string(),
                path: PathBuf::from("file.txt"),
                patch: "x".to_string(),
            },
        )
        .expect_err("should reject");
        assert_not_permitted(err);
    }

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
    assert_not_permitted(err);

    let err = delete(
        &ctx,
        DeleteRequest {
            root_id: "root".to_string(),
            path: PathBuf::from("sub"),
            recursive: true,
            ignore_missing: true,
        },
    )
    .expect_err("should reject");
    assert_not_permitted(err);

    let err = mkdir(
        &ctx,
        MkdirRequest {
            root_id: "root".to_string(),
            path: PathBuf::from("sub"),
            create_parents: true,
            ignore_existing: true,
        },
    )
    .expect_err("should reject");
    assert_not_permitted(err);

    let err = write_file(
        &ctx,
        WriteFileRequest {
            root_id: "root".to_string(),
            path: PathBuf::from("file.txt"),
            content: "hello\n".to_string(),
            overwrite: true,
            create_parents: true,
        },
    )
    .expect_err("should reject");
    assert_not_permitted(err);

    let err = move_path(
        &ctx,
        MovePathRequest {
            root_id: "root".to_string(),
            from: PathBuf::from("a.txt"),
            to: PathBuf::from("b.txt"),
            overwrite: true,
            create_parents: true,
        },
    )
    .expect_err("should reject");
    assert_not_permitted(err);

    let err = copy_file(
        &ctx,
        CopyFileRequest {
            root_id: "root".to_string(),
            from: PathBuf::from("a.txt"),
            to: PathBuf::from("b.txt"),
            overwrite: true,
            create_parents: true,
        },
    )
    .expect_err("should reject");
    assert_not_permitted(err);
}

#[test]
fn root_not_found_is_reported() {
    let dir = tempfile::tempdir().expect("tempdir");
    let ctx = Context::new(test_policy(dir.path(), RootMode::ReadOnly)).expect("ctx");

    let err = read_file(
        &ctx,
        ReadRequest {
            root_id: "missing".to_string(),
            path: PathBuf::from("file.txt"),
            start_line: None,
            end_line: None,
        },
    )
    .expect_err("should reject");

    match err {
        safe_fs_tools::Error::RootNotFound(root_id) => assert_eq!(root_id, "missing"),
        other => panic!("unexpected error: {other:?}"),
    }
}
