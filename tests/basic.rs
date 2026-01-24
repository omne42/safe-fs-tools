use std::path::PathBuf;

use safe_fs_tools::ops::{
    Context, DeleteRequest, EditRequest, PatchRequest, ReadRequest, apply_unified_patch,
    delete_file, edit_range, read_file,
};
use safe_fs_tools::policy::{Limits, Permissions, Root, RootMode, SandboxPolicy, SecretRules};

fn test_policy(root: &std::path::Path, mode: RootMode) -> SandboxPolicy {
    SandboxPolicy {
        roots: vec![Root {
            id: "root".to_string(),
            path: root.to_path_buf(),
            mode,
        }],
        permissions: Permissions {
            read: true,
            glob: true,
            grep: true,
            edit: true,
            patch: true,
            delete: true,
        },
        limits: Limits::default(),
        secrets: SecretRules {
            deny_globs: Vec::new(),
            redact_regexes: vec!["API_KEY=[A-Za-z0-9_]+".to_string()],
            replacement: "***REDACTED***".to_string(),
        },
    }
}

#[test]
fn read_redacts_matches() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("hello.txt");
    std::fs::write(&path, "API_KEY=abc123\nhello\n").expect("write");

    let ctx = Context::new(test_policy(dir.path(), RootMode::ReadOnly)).expect("ctx");
    let response = read_file(
        &ctx,
        ReadRequest {
            root_id: "root".to_string(),
            path: PathBuf::from("hello.txt"),
        },
    )
    .expect("read");

    assert_eq!(response.path, PathBuf::from("hello.txt"));
    assert!(response.content.contains("***REDACTED***"));
    assert!(!response.content.contains("abc123"));
}

#[test]
fn read_rejects_outside_root() {
    let dir = tempfile::tempdir().expect("tempdir");
    let outside = tempfile::NamedTempFile::new().expect("tmp");
    std::fs::write(outside.path(), "hello").expect("write");

    let ctx = Context::new(test_policy(dir.path(), RootMode::ReadOnly)).expect("ctx");
    let err = read_file(
        &ctx,
        ReadRequest {
            root_id: "root".to_string(),
            path: outside.path().to_path_buf(),
        },
    )
    .expect_err("should reject");

    match err {
        safe_fs_tools::Error::OutsideRoot { .. } => {}
        other => panic!("unexpected error: {other:?}"),
    }
}

#[test]
fn edit_patch_delete_roundtrip() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("file.txt");
    std::fs::write(&path, "one\ntwo\nthree\n").expect("write");

    let ctx = Context::new(test_policy(dir.path(), RootMode::ReadWrite)).expect("ctx");

    edit_range(
        &ctx,
        EditRequest {
            root_id: "root".to_string(),
            path: PathBuf::from("file.txt"),
            start_line: 2,
            end_line: 2,
            replacement: "TWO".to_string(),
        },
    )
    .expect("edit");

    let after_edit = std::fs::read_to_string(&path).expect("read");
    assert!(after_edit.contains("TWO"));

    let updated = "one\nTWO\nTHREE\n";
    let patch = diffy::create_patch(&after_edit, updated);

    apply_unified_patch(
        &ctx,
        PatchRequest {
            root_id: "root".to_string(),
            path: PathBuf::from("file.txt"),
            patch: patch.to_string(),
        },
    )
    .expect("patch");

    let after_patch = std::fs::read_to_string(&path).expect("read");
    assert_eq!(after_patch, updated);

    delete_file(
        &ctx,
        DeleteRequest {
            root_id: "root".to_string(),
            path: PathBuf::from("file.txt"),
        },
    )
    .expect("delete");

    assert!(!path.exists());
}
