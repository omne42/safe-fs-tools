mod common;

use std::path::PathBuf;

use common::test_policy;
use safe_fs_tools::ops::Context;
use safe_fs_tools::policy::{
    Limits, PathRules, Permissions, Root, RootMode, SandboxPolicy, SecretRules, TraversalRules,
};

fn assert_invalid_policy_contains_all(err: safe_fs_tools::Error, expected_parts: &[&str]) {
    match err {
        safe_fs_tools::Error::InvalidPolicy(msg) => {
            for expected in expected_parts {
                assert!(
                    msg.contains(expected),
                    "expected invalid policy message containing {expected:?}, got: {msg}"
                );
            }
        }
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
    assert_invalid_policy_contains_all(err, &["duplicate root.id", "dup"]);
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
    assert_invalid_policy_contains_all(
        err,
        &[
            "root.id must not contain leading/trailing whitespace",
            "root ",
        ],
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
    assert_invalid_policy_contains_all(
        err,
        &[
            "root.id must not contain leading/trailing whitespace",
            " root",
        ],
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
    assert_invalid_policy_contains_all(err, &["root.path must be absolute", "root.id=root"]);
}

#[test]
fn policy_rejects_invalid_redact_regexes() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut policy = test_policy(dir.path(), RootMode::ReadOnly);
    policy.secrets.redact_regexes = vec!["[".to_string()];

    let err = Context::new(policy).expect_err("should reject");
    assert_invalid_policy_contains_all(err, &["secrets.redact_regexes", "regex"]);
}

#[test]
fn policy_rejects_zero_max_patch_bytes() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut policy = test_policy(dir.path(), RootMode::ReadOnly);
    policy.limits.max_patch_bytes = Some(0);

    let err = policy.validate().expect_err("should reject");
    assert_invalid_policy_contains_all(err, &["limits.max_patch_bytes", "> 0"]);
}

#[test]
fn policy_rejects_max_walk_files_greater_than_entries() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut policy = test_policy(dir.path(), RootMode::ReadOnly);
    policy.limits.max_walk_entries = 10;
    policy.limits.max_walk_files = 11;

    let err = policy.validate().expect_err("should reject");
    assert_invalid_policy_contains_all(err, &["limits.max_walk_files", "limits.max_walk_entries"]);
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
    assert_invalid_policy_contains_all(err, &["roots", "empty"]);
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
    assert_invalid_policy_contains_all(err, &["root.id", "empty"]);
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
    assert_invalid_policy_contains_all(err, &["root.path is empty", "root.id=root"]);
}

#[test]
fn policy_rejects_zero_required_limits() {
    let dir = tempfile::tempdir().expect("tempdir");
    let cases: [(&str, fn(&mut Limits), &str); 6] = [
        (
            "max_read_bytes",
            |limits| limits.max_read_bytes = 0,
            "limits.max_read_bytes",
        ),
        (
            "max_write_bytes",
            |limits| limits.max_write_bytes = 0,
            "limits.max_write_bytes",
        ),
        (
            "max_results",
            |limits| limits.max_results = 0,
            "limits.max_results",
        ),
        (
            "max_walk_files",
            |limits| limits.max_walk_files = 0,
            "limits.max_walk_files",
        ),
        (
            "max_walk_entries",
            |limits| limits.max_walk_entries = 0,
            "limits.max_walk_entries",
        ),
        (
            "max_line_bytes",
            |limits| limits.max_line_bytes = 0,
            "limits.max_line_bytes",
        ),
    ];

    for (case_name, mutate, expected) in cases {
        let mut policy = test_policy(dir.path(), RootMode::ReadOnly);
        mutate(&mut policy.limits);

        match policy.validate().expect_err("should reject") {
            safe_fs_tools::Error::InvalidPolicy(msg) => {
                assert!(msg.contains(expected), "case: {case_name}, msg: {msg}");
                assert!(msg.contains("> 0"), "case: {case_name}, msg: {msg}");
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
    assert_invalid_policy_contains_all(err, &["root", "is not a directory"]);
}

#[test]
fn validate_only_checks_policy_shape_not_filesystem_state() {
    let dir = tempfile::tempdir().expect("tempdir");
    let missing_root = dir.path().join("missing-root");

    let policy = SandboxPolicy {
        roots: vec![Root {
            id: "root".to_string(),
            path: missing_root,
            mode: RootMode::ReadOnly,
        }],
        permissions: Permissions::default(),
        limits: Limits::default(),
        secrets: SecretRules::default(),
        traversal: TraversalRules::default(),
        paths: PathRules::default(),
    };

    policy
        .validate()
        .expect("validate should stay structural and avoid filesystem IO");
    let err = Context::new(policy).expect_err("context should reject missing roots");
    assert_invalid_policy_contains_all(err, &["failed to canonicalize root", "root"]);
}

#[test]
fn policy_deserialization_rejects_unknown_fields() {
    let cases = [
        (
            "unknown root field",
            r#"{
  "roots": [{"id": "root", "path": "/", "mode": "read_only", "unknown_root": true}],
  "permissions": { "read": true }
}"#,
            "unknown_root",
        ),
        (
            "unknown top-level field",
            r#"{
  "roots": [{"id": "root", "path": "/", "mode": "read_only"}],
  "unknown_top": true
}"#,
            "unknown_top",
        ),
        (
            "unknown permissions field",
            r#"{
  "roots": [{"id": "root", "path": "/", "mode": "read_only"}],
  "permissions": { "read": true, "unknown_permissions": true }
}"#,
            "unknown_permissions",
        ),
        (
            "unknown limits field",
            r#"{
  "roots": [{"id": "root", "path": "/", "mode": "read_only"}],
  "limits": { "unknown_limits": 1 }
}"#,
            "unknown_limits",
        ),
        (
            "unknown secrets field",
            r#"{
  "roots": [{"id": "root", "path": "/", "mode": "read_only"}],
  "secrets": { "unknown_secrets": true }
}"#,
            "unknown_secrets",
        ),
        (
            "unknown traversal field",
            r#"{
  "roots": [{"id": "root", "path": "/", "mode": "read_only"}],
  "traversal": { "unknown_traversal": true }
}"#,
            "unknown_traversal",
        ),
        (
            "unknown paths field",
            r#"{
  "roots": [{"id": "root", "path": "/", "mode": "read_only"}],
  "paths": { "unknown_paths": true }
}"#,
            "unknown_paths",
        ),
    ];

    for (case_name, raw, unknown_field) in cases {
        let err = serde_json::from_str::<SandboxPolicy>(raw).expect_err("should reject");
        let msg = err.to_string();
        assert!(
            msg.contains("unknown field"),
            "case: {case_name}, msg: {msg}"
        );
        assert!(msg.contains(unknown_field), "case: {case_name}, msg: {msg}");
    }
}
