mod common;

use std::path::PathBuf;

use common::test_policy;
use safe_fs_tools::ops::Context;
use safe_fs_tools::policy::{
    Limits, PathRules, Permissions, Root, RootMode, SandboxPolicy, SecretRules, TraversalRules,
};

fn assert_invalid_policy_contains(err: safe_fs_tools::Error, expected: &str) {
    match err {
        safe_fs_tools::Error::InvalidPolicy(msg) => assert!(
            msg.contains(expected),
            "expected invalid policy message containing {expected:?}, got: {msg}"
        ),
        other => panic!("unexpected error: {other:?}"),
    }
}

#[test]
fn policy_rejects_duplicate_root_ids() {
    let dir = tempfile::tempdir().expect("tempdir");
    let policy = SandboxPolicy {
        roots: vec![
            Root {
                id: "dup".to_string(),
                path: dir.path().to_path_buf(),
                mode: RootMode::ReadOnly,
            },
            Root {
                id: "dup".to_string(),
                path: dir.path().to_path_buf(),
                mode: RootMode::ReadOnly,
            },
        ],
        permissions: Permissions::default(),
        limits: Limits::default(),
        secrets: SecretRules::default(),
        traversal: TraversalRules::default(),
        paths: PathRules::default(),
    };

    let err = Context::new(policy).expect_err("should reject");
    assert_invalid_policy_contains(err, "duplicate root.id");
}

#[test]
fn policy_rejects_relative_root_paths() {
    let policy = SandboxPolicy {
        roots: vec![Root {
            id: "root".to_string(),
            path: PathBuf::from("relative-root"),
            mode: RootMode::ReadOnly,
        }],
        permissions: Permissions::default(),
        limits: Limits::default(),
        secrets: SecretRules::default(),
        traversal: TraversalRules::default(),
        paths: PathRules::default(),
    };

    let err = Context::new(policy).expect_err("should reject");
    assert_invalid_policy_contains(err, "root.path must be absolute");
}

#[test]
fn policy_rejects_invalid_redact_regexes() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut policy = test_policy(dir.path(), RootMode::ReadOnly);
    policy.secrets.redact_regexes = vec!["[".to_string()];

    let err = Context::new(policy).expect_err("should reject");
    assert_invalid_policy_contains(err, "secrets.redact_regexes");
}

#[test]
fn policy_rejects_zero_max_patch_bytes() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut policy = test_policy(dir.path(), RootMode::ReadOnly);
    policy.limits.max_patch_bytes = Some(0);

    let err = Context::new(policy).expect_err("should reject");
    assert_invalid_policy_contains(err, "limits.max_patch_bytes must be > 0");
}

#[test]
fn context_rejects_file_roots() {
    let dir = tempfile::tempdir().expect("tempdir");
    let root_file = dir.path().join("root.txt");
    std::fs::write(&root_file, "not a directory").expect("write");

    let policy = SandboxPolicy {
        roots: vec![Root {
            id: "root".to_string(),
            path: root_file,
            mode: RootMode::ReadOnly,
        }],
        permissions: Permissions::default(),
        limits: Limits::default(),
        secrets: SecretRules::default(),
        traversal: TraversalRules::default(),
        paths: PathRules::default(),
    };

    let err = Context::new(policy).expect_err("should reject");
    assert_invalid_policy_contains(err, "is not a directory");
}

#[test]
fn policy_deserialization_rejects_unknown_fields() {
    let raw = r#"
{
  "roots": [
    {
      "id": "root",
      "path": "/",
      "mode": "read_only",
      "unknown_field": true
    }
  ],
  "permissions": { "read": true }
}
"#;

    let err = serde_json::from_str::<SandboxPolicy>(raw).expect_err("should reject");
    assert!(
        err.to_string().contains("unknown field"),
        "unexpected error: {err}"
    );
}
