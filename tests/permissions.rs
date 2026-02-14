mod common;

use std::path::PathBuf;

use common::{permissive_test_policy, test_policy};
use safe_fs_tools::ops::{
    Context, CopyFileRequest, DeleteRequest, EditRequest, GlobRequest, GrepRequest, ListDirRequest,
    MkdirRequest, MovePathRequest, ReadRequest, StatRequest, WriteFileRequest, copy_file, delete,
    edit_range, glob_paths, grep, list_dir, mkdir, move_path, read_file, stat, write_file,
};
use safe_fs_tools::policy::RootMode;

#[cfg(feature = "patch")]
use safe_fs_tools::ops::{PatchRequest, apply_unified_patch};

#[derive(Clone, Copy, Debug)]
enum NotPermittedReason {
    DisabledByPolicy,
    ReadOnlyRoot,
}

impl NotPermittedReason {
    fn stable_tokens(self) -> &'static [&'static str] {
        match self {
            Self::DisabledByPolicy => &["disabled by policy"],
            Self::ReadOnlyRoot => &["is not allowed", "read_only"],
        }
    }
}

fn assert_not_permitted(err: safe_fs_tools::Error, op: &str, reason: NotPermittedReason) {
    match err {
        safe_fs_tools::Error::NotPermitted(message) => {
            let expected_prefix = format!("{op} ");
            assert!(
                message.starts_with(&expected_prefix),
                "expected not_permitted reason to start with '{expected_prefix}', got '{message}'"
            );
            let stable_tokens = reason.stable_tokens();
            assert!(
                stable_tokens.iter().all(|token| message.contains(token)),
                "expected not_permitted reason to contain all of {stable_tokens:?} for {reason:?}, got '{message}'"
            );
        }
        other => panic!("unexpected error: {other:?}"),
    }
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
    assert_not_permitted(err, "read", NotPermittedReason::DisabledByPolicy);
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

    assert_not_permitted(err, "glob", NotPermittedReason::DisabledByPolicy);
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

    assert_not_permitted(err, "grep", NotPermittedReason::DisabledByPolicy);
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

    assert_not_permitted(err, "list_dir", NotPermittedReason::DisabledByPolicy);
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

    assert_not_permitted(err, "stat", NotPermittedReason::DisabledByPolicy);
}

#[test]
fn edit_is_disabled_by_policy() {
    let dir = tempfile::tempdir().expect("tempdir");
    let file_path = dir.path().join("file.txt");
    std::fs::write(&file_path, "hello\n").expect("write");
    let before = std::fs::read_to_string(&file_path).expect("read baseline");
    let before_meta = std::fs::metadata(&file_path).expect("metadata baseline");

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

    assert_not_permitted(err, "edit", NotPermittedReason::DisabledByPolicy);
    let after = std::fs::read_to_string(&file_path).expect("read after deny");
    let after_meta = std::fs::metadata(&file_path).expect("metadata after deny");
    assert_eq!(after, before, "edit deny must not change file content");
    assert_eq!(
        after_meta.len(),
        before_meta.len(),
        "edit deny must not change file metadata length"
    );
}

#[test]
#[cfg(feature = "patch")]
fn patch_is_disabled_by_policy() {
    let dir = tempfile::tempdir().expect("tempdir");
    let file_path = dir.path().join("file.txt");
    std::fs::write(&file_path, "hello\n").expect("write");
    let before = std::fs::read_to_string(&file_path).expect("read baseline");
    let before_meta = std::fs::metadata(&file_path).expect("metadata baseline");

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

    assert_not_permitted(err, "patch", NotPermittedReason::DisabledByPolicy);
    let after = std::fs::read_to_string(&file_path).expect("read after deny");
    let after_meta = std::fs::metadata(&file_path).expect("metadata after deny");
    assert_eq!(after, before, "patch deny must not change file content");
    assert_eq!(
        after_meta.len(),
        before_meta.len(),
        "patch deny must not change file metadata length"
    );
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

    assert_not_permitted(err, "mkdir", NotPermittedReason::DisabledByPolicy);
    assert!(
        !dir.path().join("sub").exists(),
        "mkdir deny must not create target directory"
    );
}

#[test]
fn write_is_disabled_by_policy() {
    let dir = tempfile::tempdir().expect("tempdir");
    let file_path = dir.path().join("file.txt");
    std::fs::write(&file_path, "baseline\n").expect("write baseline");
    let before = std::fs::read_to_string(&file_path).expect("read baseline");
    let before_meta = std::fs::metadata(&file_path).expect("metadata baseline");

    let mut policy = test_policy(dir.path(), RootMode::ReadWrite);
    policy.permissions.write = false;
    let ctx = Context::new(policy).expect("ctx");

    let err = write_file(
        &ctx,
        WriteFileRequest {
            root_id: "root".to_string(),
            path: PathBuf::from("file.txt"),
            content: "hello\n".to_string(),
            overwrite: true,
            create_parents: false,
        },
    )
    .expect_err("should reject");

    assert_not_permitted(err, "write", NotPermittedReason::DisabledByPolicy);
    let after = std::fs::read_to_string(&file_path).expect("read after deny");
    let after_meta = std::fs::metadata(&file_path).expect("metadata after deny");
    assert_eq!(after, before, "write deny must not change file content");
    assert_eq!(
        after_meta.len(),
        before_meta.len(),
        "write deny must not change file metadata length"
    );
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

    assert_not_permitted(err, "delete", NotPermittedReason::DisabledByPolicy);
    let file_path = dir.path().join("file.txt");
    assert!(file_path.exists(), "delete deny must keep source file");
    assert_eq!(
        std::fs::read_to_string(&file_path).expect("read after deny"),
        "hello\n",
        "delete deny must not change file content"
    );
}

#[test]
fn move_is_disabled_by_policy() {
    let dir = tempfile::tempdir().expect("tempdir");
    let from = dir.path().join("a.txt");
    let to = dir.path().join("b.txt");
    std::fs::write(&from, "from\n").expect("write from");
    std::fs::write(&to, "to\n").expect("write to");

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

    assert_not_permitted(err, "move", NotPermittedReason::DisabledByPolicy);
    assert_eq!(
        std::fs::read_to_string(&from).expect("read from after deny"),
        "from\n",
        "move deny must keep source content"
    );
    assert_eq!(
        std::fs::read_to_string(&to).expect("read to after deny"),
        "to\n",
        "move deny must not overwrite destination"
    );
}

#[test]
fn copy_is_disabled_by_policy() {
    let dir = tempfile::tempdir().expect("tempdir");
    let from = dir.path().join("a.txt");
    let to = dir.path().join("b.txt");
    std::fs::write(&from, "from\n").expect("write from");
    std::fs::write(&to, "to\n").expect("write to");

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

    assert_not_permitted(err, "copy_file", NotPermittedReason::DisabledByPolicy);
    assert_eq!(
        std::fs::read_to_string(&from).expect("read from after deny"),
        "from\n",
        "copy deny must keep source content"
    );
    assert_eq!(
        std::fs::read_to_string(&to).expect("read to after deny"),
        "to\n",
        "copy deny must not overwrite destination"
    );
}

#[test]
fn edit_is_disallowed_on_readonly_root() {
    let dir = tempfile::tempdir().expect("tempdir");
    let file_path = dir.path().join("file.txt");
    std::fs::write(&file_path, "hello\n").expect("write baseline");
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
    assert_not_permitted(err, "edit", NotPermittedReason::ReadOnlyRoot);
    assert_eq!(
        std::fs::read_to_string(&file_path).expect("read after deny"),
        "hello\n",
        "readonly edit deny must not change file content"
    );
}

#[test]
#[cfg(feature = "patch")]
fn patch_is_disallowed_on_readonly_root() {
    let dir = tempfile::tempdir().expect("tempdir");
    let file_path = dir.path().join("file.txt");
    std::fs::write(&file_path, "hello\n").expect("write baseline");
    let ctx = Context::new(test_policy(dir.path(), RootMode::ReadOnly)).expect("ctx");

    let err = apply_unified_patch(
        &ctx,
        PatchRequest {
            root_id: "root".to_string(),
            path: PathBuf::from("file.txt"),
            patch: "x".to_string(),
        },
    )
    .expect_err("should reject");
    assert_not_permitted(err, "patch", NotPermittedReason::ReadOnlyRoot);
    assert_eq!(
        std::fs::read_to_string(&file_path).expect("read after deny"),
        "hello\n",
        "readonly patch deny must not change file content"
    );
}

#[test]
fn delete_is_disallowed_on_readonly_root() {
    let dir = tempfile::tempdir().expect("tempdir");
    let file_path = dir.path().join("file.txt");
    std::fs::write(&file_path, "hello\n").expect("write baseline");
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
    assert_not_permitted(err, "delete", NotPermittedReason::ReadOnlyRoot);
    assert!(
        file_path.exists(),
        "readonly delete deny must keep source file"
    );
}

#[test]
fn delete_recursive_is_disallowed_on_readonly_root() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sub_dir = dir.path().join("sub");
    std::fs::create_dir_all(&sub_dir).expect("create sub");
    std::fs::write(sub_dir.join("child.txt"), "hello\n").expect("write child");
    let ctx = Context::new(test_policy(dir.path(), RootMode::ReadOnly)).expect("ctx");

    let err = delete(
        &ctx,
        DeleteRequest {
            root_id: "root".to_string(),
            path: PathBuf::from("sub"),
            recursive: true,
            ignore_missing: false,
        },
    )
    .expect_err("should reject");
    assert_not_permitted(err, "delete", NotPermittedReason::ReadOnlyRoot);
    assert!(
        sub_dir.exists(),
        "readonly recursive delete deny must keep dir"
    );
}

#[test]
fn mkdir_is_disallowed_on_readonly_root() {
    let dir = tempfile::tempdir().expect("tempdir");
    let ctx = Context::new(test_policy(dir.path(), RootMode::ReadOnly)).expect("ctx");

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
    assert_not_permitted(err, "mkdir", NotPermittedReason::ReadOnlyRoot);
    assert!(
        !dir.path().join("sub").exists(),
        "readonly mkdir deny must not create sub/"
    );
}

#[test]
fn write_is_disallowed_on_readonly_root() {
    let dir = tempfile::tempdir().expect("tempdir");
    let file_path = dir.path().join("file.txt");
    std::fs::write(&file_path, "baseline\n").expect("write baseline");
    let ctx = Context::new(test_policy(dir.path(), RootMode::ReadOnly)).expect("ctx");

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
    assert_not_permitted(err, "write", NotPermittedReason::ReadOnlyRoot);
    assert_eq!(
        std::fs::read_to_string(&file_path).expect("read after deny"),
        "baseline\n",
        "readonly write deny must not change file content"
    );
}

#[test]
fn move_is_disallowed_on_readonly_root() {
    let dir = tempfile::tempdir().expect("tempdir");
    let from = dir.path().join("a.txt");
    let to = dir.path().join("b.txt");
    std::fs::write(&from, "from\n").expect("write from");
    std::fs::write(&to, "to\n").expect("write to");
    let ctx = Context::new(test_policy(dir.path(), RootMode::ReadOnly)).expect("ctx");

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
    assert_not_permitted(err, "move", NotPermittedReason::ReadOnlyRoot);
    assert_eq!(
        std::fs::read_to_string(&from).expect("read from after deny"),
        "from\n",
        "readonly move deny must keep source content"
    );
    assert_eq!(
        std::fs::read_to_string(&to).expect("read to after deny"),
        "to\n",
        "readonly move deny must keep destination content"
    );
}

#[test]
fn copy_is_disallowed_on_readonly_root() {
    let dir = tempfile::tempdir().expect("tempdir");
    let from = dir.path().join("a.txt");
    let to = dir.path().join("b.txt");
    std::fs::write(&from, "from\n").expect("write from");
    std::fs::write(&to, "to\n").expect("write to");
    let ctx = Context::new(test_policy(dir.path(), RootMode::ReadOnly)).expect("ctx");

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
    assert_not_permitted(err, "copy_file", NotPermittedReason::ReadOnlyRoot);
    assert_eq!(
        std::fs::read_to_string(&from).expect("read from after deny"),
        "from\n",
        "readonly copy deny must keep source content"
    );
    assert_eq!(
        std::fs::read_to_string(&to).expect("read to after deny"),
        "to\n",
        "readonly copy deny must keep destination content"
    );
}

fn assert_root_not_found(err: safe_fs_tools::Error, expected_root_id: &str) {
    match err {
        safe_fs_tools::Error::RootNotFound(root_id) => assert_eq!(root_id, expected_root_id),
        other => panic!("unexpected error: {other:?}"),
    }
}

fn assert_missing_root<T: std::fmt::Debug>(result: Result<T, safe_fs_tools::Error>, op: &str) {
    let err = result.expect_err(&format!("{op} should reject missing root"));
    assert_root_not_found(err, "missing");
}

const MISSING_ROOT_ID: &str = "missing";

struct MissingRootFixture {
    _dir: tempfile::TempDir,
    ctx: Context,
    file_path: PathBuf,
    from: PathBuf,
    to: PathBuf,
}

fn setup_missing_root_fixture() -> MissingRootFixture {
    let dir = tempfile::tempdir().expect("tempdir");
    let file_path = dir.path().join("file.txt");
    let from = dir.path().join("from.txt");
    let to = dir.path().join("to.txt");
    std::fs::write(&file_path, "hello\n").expect("write file");
    std::fs::write(&from, "from\n").expect("write from");
    std::fs::write(&to, "to\n").expect("write to");
    let ctx = Context::new(permissive_test_policy(dir.path(), RootMode::ReadWrite)).expect("ctx");

    MissingRootFixture {
        _dir: dir,
        ctx,
        file_path,
        from,
        to,
    }
}

fn assert_missing_root_side_effects(fixture: &MissingRootFixture) {
    assert_eq!(
        std::fs::read_to_string(&fixture.file_path).expect("read file after missing root rejects"),
        "hello\n"
    );
    assert_eq!(
        std::fs::read_to_string(&fixture.from).expect("read from after missing root rejects"),
        "from\n"
    );
    assert_eq!(
        std::fs::read_to_string(&fixture.to).expect("read to after missing root rejects"),
        "to\n"
    );
    let sub_dir = fixture
        .file_path
        .parent()
        .expect("fixture root dir")
        .join("sub");
    assert!(
        !sub_dir.exists(),
        "missing root mkdir must not create target directory"
    );
}

#[test]
fn missing_root_with_disabled_write_permission_reports_not_permitted() {
    let dir = tempfile::tempdir().expect("tempdir");
    let file_path = dir.path().join("file.txt");
    std::fs::write(&file_path, "hello\n").expect("write baseline");

    let mut policy = permissive_test_policy(dir.path(), RootMode::ReadWrite);
    policy.permissions.write = false;
    let ctx = Context::new(policy).expect("ctx");

    let err = write_file(
        &ctx,
        WriteFileRequest {
            root_id: MISSING_ROOT_ID.to_string(),
            path: PathBuf::from("file.txt"),
            content: "updated\n".to_string(),
            overwrite: true,
            create_parents: false,
        },
    )
    .expect_err("should reject");

    assert_not_permitted(err, "write", NotPermittedReason::DisabledByPolicy);
    assert_eq!(
        std::fs::read_to_string(&file_path).expect("read after deny"),
        "hello\n",
        "disabled write permission must reject before missing-root handling"
    );
}

#[test]
fn missing_root_with_readonly_root_reports_root_not_found() {
    let dir = tempfile::tempdir().expect("tempdir");
    let file_path = dir.path().join("file.txt");
    std::fs::write(&file_path, "hello\n").expect("write baseline");

    let policy = permissive_test_policy(dir.path(), RootMode::ReadOnly);
    let ctx = Context::new(policy).expect("ctx");

    assert_missing_root(
        write_file(
            &ctx,
            WriteFileRequest {
                root_id: MISSING_ROOT_ID.to_string(),
                path: PathBuf::from("file.txt"),
                content: "updated\n".to_string(),
                overwrite: true,
                create_parents: false,
            },
        ),
        "write",
    );
    assert_eq!(
        std::fs::read_to_string(&file_path).expect("read after deny"),
        "hello\n",
        "missing root must be reported before readonly root rejection"
    );
}

#[test]
fn root_not_found_is_reported_for_read() {
    let fixture = setup_missing_root_fixture();
    assert_missing_root(
        read_file(
            &fixture.ctx,
            ReadRequest {
                root_id: MISSING_ROOT_ID.to_string(),
                path: PathBuf::from("file.txt"),
                start_line: None,
                end_line: None,
            },
        ),
        "read",
    );
    assert_missing_root_side_effects(&fixture);
}

#[test]
fn root_not_found_is_reported_for_write() {
    let fixture = setup_missing_root_fixture();
    assert_missing_root(
        write_file(
            &fixture.ctx,
            WriteFileRequest {
                root_id: MISSING_ROOT_ID.to_string(),
                path: PathBuf::from("file.txt"),
                content: "updated\n".to_string(),
                overwrite: true,
                create_parents: false,
            },
        ),
        "write",
    );
    assert_missing_root_side_effects(&fixture);
}

#[test]
fn root_not_found_is_reported_for_glob() {
    let fixture = setup_missing_root_fixture();
    assert_missing_root(
        glob_paths(
            &fixture.ctx,
            GlobRequest {
                root_id: MISSING_ROOT_ID.to_string(),
                pattern: "**/*.txt".to_string(),
            },
        ),
        "glob",
    );
    assert_missing_root_side_effects(&fixture);
}

#[test]
fn root_not_found_is_reported_for_grep() {
    let fixture = setup_missing_root_fixture();
    assert_missing_root(
        grep(
            &fixture.ctx,
            GrepRequest {
                root_id: MISSING_ROOT_ID.to_string(),
                query: "hello".to_string(),
                regex: false,
                glob: None,
            },
        ),
        "grep",
    );
    assert_missing_root_side_effects(&fixture);
}

#[test]
fn root_not_found_is_reported_for_list_dir() {
    let fixture = setup_missing_root_fixture();
    assert_missing_root(
        list_dir(
            &fixture.ctx,
            ListDirRequest {
                root_id: MISSING_ROOT_ID.to_string(),
                path: PathBuf::from("."),
                max_entries: None,
            },
        ),
        "list_dir",
    );
    assert_missing_root_side_effects(&fixture);
}

#[test]
fn root_not_found_is_reported_for_stat() {
    let fixture = setup_missing_root_fixture();
    assert_missing_root(
        stat(
            &fixture.ctx,
            StatRequest {
                root_id: MISSING_ROOT_ID.to_string(),
                path: PathBuf::from("file.txt"),
            },
        ),
        "stat",
    );
    assert_missing_root_side_effects(&fixture);
}

#[test]
fn root_not_found_is_reported_for_edit() {
    let fixture = setup_missing_root_fixture();
    assert_missing_root(
        edit_range(
            &fixture.ctx,
            EditRequest {
                root_id: MISSING_ROOT_ID.to_string(),
                path: PathBuf::from("file.txt"),
                start_line: 1,
                end_line: 1,
                replacement: "HELLO".to_string(),
            },
        ),
        "edit",
    );
    assert_missing_root_side_effects(&fixture);
}

#[test]
#[cfg(feature = "patch")]
fn root_not_found_is_reported_for_patch() {
    let fixture = setup_missing_root_fixture();
    assert_missing_root(
        apply_unified_patch(
            &fixture.ctx,
            PatchRequest {
                root_id: MISSING_ROOT_ID.to_string(),
                path: PathBuf::from("file.txt"),
                patch: "x".to_string(),
            },
        ),
        "patch",
    );
    assert_missing_root_side_effects(&fixture);
}

#[test]
fn root_not_found_is_reported_for_mkdir() {
    let fixture = setup_missing_root_fixture();
    assert_missing_root(
        mkdir(
            &fixture.ctx,
            MkdirRequest {
                root_id: MISSING_ROOT_ID.to_string(),
                path: PathBuf::from("sub"),
                create_parents: true,
                ignore_existing: false,
            },
        ),
        "mkdir",
    );
    assert_missing_root_side_effects(&fixture);
}

#[test]
fn root_not_found_is_reported_for_delete() {
    let fixture = setup_missing_root_fixture();
    assert_missing_root(
        delete(
            &fixture.ctx,
            DeleteRequest {
                root_id: MISSING_ROOT_ID.to_string(),
                path: PathBuf::from("file.txt"),
                recursive: false,
                ignore_missing: false,
            },
        ),
        "delete",
    );
    assert_missing_root_side_effects(&fixture);
}

#[test]
fn root_not_found_is_reported_for_move() {
    let fixture = setup_missing_root_fixture();
    assert_missing_root(
        move_path(
            &fixture.ctx,
            MovePathRequest {
                root_id: MISSING_ROOT_ID.to_string(),
                from: PathBuf::from("from.txt"),
                to: PathBuf::from("to.txt"),
                overwrite: true,
                create_parents: false,
            },
        ),
        "move",
    );
    assert_missing_root_side_effects(&fixture);
}

#[test]
fn root_not_found_is_reported_for_copy() {
    let fixture = setup_missing_root_fixture();
    assert_missing_root(
        copy_file(
            &fixture.ctx,
            CopyFileRequest {
                root_id: MISSING_ROOT_ID.to_string(),
                from: PathBuf::from("from.txt"),
                to: PathBuf::from("to.txt"),
                overwrite: true,
                create_parents: false,
            },
        ),
        "copy_file",
    );
    assert_missing_root_side_effects(&fixture);
}
