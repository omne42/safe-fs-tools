mod common;

use std::path::PathBuf;

use common::test_policy;
use safe_fs_tools::ops::{Context, ReadRequest, read_file};
use safe_fs_tools::policy::RootMode;

#[test]
fn deny_globs_support_leading_dot_slash() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::create_dir_all(dir.path().join(".git")).expect("mkdir");
    std::fs::write(dir.path().join(".git").join("config"), "secret").expect("write");

    let mut policy = test_policy(dir.path(), RootMode::ReadOnly);
    policy.secrets.deny_globs = vec!["./.git/**".to_string()];
    let ctx = Context::new(policy).expect("ctx");

    let err = read_file(
        &ctx,
        ReadRequest {
            root_id: "root".to_string(),
            path: PathBuf::from(".git").join("config"),
            start_line: None,
            end_line: None,
        },
    )
    .expect_err("should reject");

    match err {
        safe_fs_tools::Error::SecretPathDenied(_) => {}
        other => panic!("unexpected error: {other:?}"),
    }
}

#[test]
fn deny_globs_reject_absolute_and_parent_segments() {
    let dir = tempfile::tempdir().expect("tempdir");

    for pattern in ["/.git/**", "../**/*.txt", "src/../*.txt"] {
        let mut policy = test_policy(dir.path(), RootMode::ReadOnly);
        policy.secrets.deny_globs = vec![pattern.to_string()];
        let err = Context::new(policy).expect_err("should reject");
        assert!(
            matches!(err, safe_fs_tools::Error::InvalidPolicy(_)),
            "pattern {pattern:?} should fail with InvalidPolicy, got: {err:?}"
        );
    }
}

#[test]
#[cfg(unix)]
fn deny_globs_cannot_be_bypassed_via_symlink_paths() {
    use std::os::unix::fs::symlink;

    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(dir.path().join("target.txt"), "hello\n").expect("write");
    std::fs::create_dir_all(dir.path().join(".git")).expect("mkdir");
    symlink(
        dir.path().join("target.txt"),
        dir.path().join(".git").join("link.txt"),
    )
    .expect("symlink");

    let mut policy = test_policy(dir.path(), RootMode::ReadOnly);
    policy.secrets.deny_globs = vec![".git/**".to_string(), "**/.git/**".to_string()];
    let ctx = Context::new(policy).expect("ctx");

    let err = read_file(
        &ctx,
        ReadRequest {
            root_id: "root".to_string(),
            path: PathBuf::from(".git/link.txt"),
            start_line: None,
            end_line: None,
        },
    )
    .expect_err("should reject");

    match err {
        safe_fs_tools::Error::SecretPathDenied(_) => {}
        other => panic!("unexpected error: {other:?}"),
    }
}

#[test]
#[cfg(unix)]
fn deny_globs_match_after_lexical_normalization() {
    use std::os::unix::fs::symlink;

    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(dir.path().join("target.txt"), "hello\n").expect("write");
    std::fs::create_dir_all(dir.path().join(".git")).expect("mkdir");
    std::fs::create_dir_all(dir.path().join("sub")).expect("mkdir");
    symlink(
        dir.path().join("target.txt"),
        dir.path().join(".git").join("link.txt"),
    )
    .expect("symlink");

    let mut policy = test_policy(dir.path(), RootMode::ReadOnly);
    policy.secrets.deny_globs = vec![".git/**".to_string()];
    let ctx = Context::new(policy).expect("ctx");

    let err = read_file(
        &ctx,
        ReadRequest {
            root_id: "root".to_string(),
            path: PathBuf::from("sub/../.git/link.txt"),
            start_line: None,
            end_line: None,
        },
    )
    .expect_err("should reject");

    match err {
        safe_fs_tools::Error::SecretPathDenied(_) => {}
        other => panic!("unexpected error: {other:?}"),
    }
}
