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

fn assert_invalid_policy_eq(err: safe_fs_tools::Error, expected: &str) {
    match err {
        safe_fs_tools::Error::InvalidPolicy(msg) => assert_eq!(msg, expected),
        other => panic!("unexpected error: {other:?}"),
    }
}

#[test]
fn policy_accepts_valid_configuration() {
    let dir = tempfile::tempdir().expect("tempdir");
    let policy = test_policy(dir.path(), RootMode::ReadOnly);
    let ctx = Context::new(policy).expect("valid policy should be accepted");
    assert_eq!(ctx.policy().roots.len(), 1);
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

    let err = policy.validate().expect_err("should reject");
    assert_invalid_policy_eq(err, "duplicate root.id: \"dup\"");
}

#[test]
fn policy_rejects_root_id_with_trailing_whitespace() {
    let dir = tempfile::tempdir().expect("tempdir");
    let policy = SandboxPolicy {
        roots: vec![Root {
            id: "root ".to_string(),
            path: dir.path().to_path_buf(),
            mode: RootMode::ReadOnly,
        }],
        permissions: Permissions::default(),
        limits: Limits::default(),
        secrets: SecretRules::default(),
        traversal: TraversalRules::default(),
        paths: PathRules::default(),
    };

    let err = policy.validate().expect_err("should reject");
    assert_invalid_policy_eq(
        err,
        "root.id must not contain leading/trailing whitespace: \"root \"",
    );
}

#[test]
fn policy_rejects_root_id_with_leading_whitespace() {
    let dir = tempfile::tempdir().expect("tempdir");
    let policy = SandboxPolicy {
        roots: vec![Root {
            id: " root".to_string(),
            path: dir.path().to_path_buf(),
            mode: RootMode::ReadOnly,
        }],
        permissions: Permissions::default(),
        limits: Limits::default(),
        secrets: SecretRules::default(),
        traversal: TraversalRules::default(),
        paths: PathRules::default(),
    };

    let err = policy.validate().expect_err("should reject");
    assert_invalid_policy_eq(
        err,
        "root.id must not contain leading/trailing whitespace: \" root\"",
    );
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

    let err = policy.validate().expect_err("should reject");
    assert_invalid_policy_eq(
        err,
        "root.path must be absolute (root.id=root, path=relative-root)",
    );
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

    let err = policy.validate().expect_err("should reject");
    assert_invalid_policy_eq(err, "limits.max_patch_bytes must be > 0");
}

#[test]
fn policy_rejects_max_walk_files_greater_than_entries() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut policy = test_policy(dir.path(), RootMode::ReadOnly);
    policy.limits.max_walk_entries = 10;
    policy.limits.max_walk_files = 11;

    let err = policy.validate().expect_err("should reject");
    assert_invalid_policy_eq(
        err,
        "limits.max_walk_files must be <= limits.max_walk_entries",
    );
}

#[test]
fn policy_rejects_empty_roots() {
    let policy = SandboxPolicy {
        roots: Vec::new(),
        permissions: Permissions::default(),
        limits: Limits::default(),
        secrets: SecretRules::default(),
        traversal: TraversalRules::default(),
        paths: PathRules::default(),
    };

    let err = policy.validate().expect_err("should reject");
    assert_invalid_policy_eq(err, "roots is empty");
}

#[test]
fn policy_rejects_empty_root_id() {
    let dir = tempfile::tempdir().expect("tempdir");
    let policy = SandboxPolicy {
        roots: vec![Root {
            id: String::new(),
            path: dir.path().to_path_buf(),
            mode: RootMode::ReadOnly,
        }],
        permissions: Permissions::default(),
        limits: Limits::default(),
        secrets: SecretRules::default(),
        traversal: TraversalRules::default(),
        paths: PathRules::default(),
    };

    let err = policy.validate().expect_err("should reject");
    assert_invalid_policy_eq(err, "root.id is empty");
}

#[test]
fn policy_rejects_empty_root_path() {
    let policy = SandboxPolicy {
        roots: vec![Root {
            id: "root".to_string(),
            path: PathBuf::new(),
            mode: RootMode::ReadOnly,
        }],
        permissions: Permissions::default(),
        limits: Limits::default(),
        secrets: SecretRules::default(),
        traversal: TraversalRules::default(),
        paths: PathRules::default(),
    };

    let err = policy.validate().expect_err("should reject");
    assert_invalid_policy_eq(err, "root.path is empty (root.id=root)");
}

#[test]
fn policy_rejects_zero_required_limits() {
    let dir = tempfile::tempdir().expect("tempdir");
    let cases: [(&str, fn(&mut Limits), &str); 6] = [
        (
            "max_read_bytes",
            |limits| limits.max_read_bytes = 0,
            "limits.max_read_bytes must be > 0",
        ),
        (
            "max_write_bytes",
            |limits| limits.max_write_bytes = 0,
            "limits.max_write_bytes must be > 0",
        ),
        (
            "max_results",
            |limits| limits.max_results = 0,
            "limits.max_results must be > 0",
        ),
        (
            "max_walk_files",
            |limits| limits.max_walk_files = 0,
            "limits.max_walk_files must be > 0",
        ),
        (
            "max_walk_entries",
            |limits| limits.max_walk_entries = 0,
            "limits.max_walk_entries must be > 0",
        ),
        (
            "max_line_bytes",
            |limits| limits.max_line_bytes = 0,
            "limits.max_line_bytes must be > 0",
        ),
    ];

    for (case_name, mutate, expected) in cases {
        let mut policy = test_policy(dir.path(), RootMode::ReadOnly);
        mutate(&mut policy.limits);

        match policy.validate().expect_err("should reject") {
            safe_fs_tools::Error::InvalidPolicy(msg) => {
                assert_eq!(msg, expected, "case: {case_name}");
            }
            other => panic!("case {case_name}: unexpected error: {other:?}"),
        }
    }
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
    assert!(
        err.to_string().contains("unknown_field"),
        "unexpected error: {err}"
    );
}
