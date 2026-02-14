mod common;

use std::path::{Path, PathBuf};

use common::test_policy;
use safe_fs_tools::ops::{Context, ReadRequest, read_file};
use safe_fs_tools::policy::RootMode;

fn assert_secret_path_denied(
    ctx: &Context,
    request_path: impl Into<PathBuf>,
    expected_denied_path: impl Into<PathBuf>,
) {
    let expected_denied_path = expected_denied_path.into();
    let err = read_file(
        ctx,
        ReadRequest {
            root_id: "root".to_string(),
            path: request_path.into(),
            start_line: None,
            end_line: None,
        },
    )
    .expect_err("should reject");

    match err {
        safe_fs_tools::Error::SecretPathDenied(path) => {
            assert_eq!(path, expected_denied_path);
        }
        other => panic!("unexpected error: {other:?}"),
    }
}

#[cfg(any(unix, windows))]
fn create_file_symlink_or_skip(target: &Path, link: &Path) -> bool {
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(target, link).expect("symlink");
        true
    }

    #[cfg(windows)]
    {
        match std::os::windows::fs::symlink_file(target, link) {
            Ok(()) => true,
            Err(err) if err.kind() == std::io::ErrorKind::PermissionDenied => {
                eprintln!("skipping symlink test (permission denied): {err}");
                false
            }
            Err(err) => panic!("symlink_file failed: {err}"),
        }
    }
}

#[test]
fn deny_globs_support_leading_dot_slash() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::create_dir_all(dir.path().join(".git")).expect("mkdir");
    std::fs::write(dir.path().join(".git").join("config"), "secret").expect("write");

    let mut policy = test_policy(dir.path(), RootMode::ReadOnly);
    policy.secrets.deny_globs = vec!["./.git/**".to_string()];
    let ctx = Context::new(policy).expect("ctx");

    assert_secret_path_denied(&ctx, ".git/config", ".git/config");
}

#[test]
fn deny_globs_reject_absolute_patterns_with_specific_reason() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut policy = test_policy(dir.path(), RootMode::ReadOnly);
    policy.secrets.deny_globs = vec!["/.git/**".to_string()];

    let err = Context::new(policy).expect_err("should reject");
    match err {
        safe_fs_tools::Error::InvalidPolicy(msg) => {
            assert!(msg.contains("root-relative"), "unexpected msg: {msg}");
            assert!(
                msg.contains("must not start with '/'"),
                "unexpected msg: {msg}"
            );
        }
        other => panic!("unexpected error: {other:?}"),
    }
}

#[test]
fn deny_globs_reject_parent_segments_with_specific_reason() {
    let dir = tempfile::tempdir().expect("tempdir");

    for pattern in ["../**/*.txt", "src/../*.txt"] {
        let mut policy = test_policy(dir.path(), RootMode::ReadOnly);
        policy.secrets.deny_globs = vec![pattern.to_string()];
        let err = Context::new(policy).expect_err("should reject");
        match err {
            safe_fs_tools::Error::InvalidPolicy(msg) => {
                assert!(
                    msg.contains("must not contain '..' segments"),
                    "pattern {pattern:?} should mention parent-segment prohibition, got: {msg}"
                );
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }
}

#[test]
#[cfg(any(unix, windows))]
fn deny_glob_dot_git_cannot_be_bypassed_via_symlink_paths() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(dir.path().join("target.txt"), "hello\n").expect("write");
    std::fs::create_dir_all(dir.path().join(".git")).expect("mkdir");
    let target = dir.path().join("target.txt");
    let link = dir.path().join(".git").join("link.txt");
    if !create_file_symlink_or_skip(&target, &link) {
        return;
    }

    let mut policy = test_policy(dir.path(), RootMode::ReadOnly);
    policy.secrets.deny_globs = vec![".git/**".to_string()];
    let ctx = Context::new(policy).expect("ctx");

    assert_secret_path_denied(&ctx, ".git/link.txt", ".git/link.txt");
}

#[test]
#[cfg(any(unix, windows))]
fn deny_glob_double_star_dot_git_cannot_be_bypassed_via_symlink_paths() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(dir.path().join("target.txt"), "hello\n").expect("write");
    std::fs::create_dir_all(dir.path().join(".git")).expect("mkdir");
    let target = dir.path().join("target.txt");
    let link = dir.path().join(".git").join("link.txt");
    if !create_file_symlink_or_skip(&target, &link) {
        return;
    }

    let mut policy = test_policy(dir.path(), RootMode::ReadOnly);
    policy.secrets.deny_globs = vec!["**/.git/**".to_string()];
    let ctx = Context::new(policy).expect("ctx");

    assert_secret_path_denied(&ctx, ".git/link.txt", ".git/link.txt");
}

#[test]
#[cfg(any(unix, windows))]
fn deny_glob_blocks_regular_path_that_symlinks_into_git() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::create_dir_all(dir.path().join(".git")).expect("mkdir");
    std::fs::write(dir.path().join(".git").join("config"), "secret\n").expect("write");
    let target = dir.path().join(".git").join("config");
    let link = dir.path().join("public-link.txt");
    if !create_file_symlink_or_skip(&target, &link) {
        return;
    }

    let mut policy = test_policy(dir.path(), RootMode::ReadOnly);
    policy.secrets.deny_globs = vec![".git/**".to_string()];
    let ctx = Context::new(policy).expect("ctx");

    assert_secret_path_denied(&ctx, "public-link.txt", ".git/config");
}

#[test]
fn deny_globs_match_after_lexical_normalization() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::create_dir_all(dir.path().join(".git")).expect("mkdir");
    std::fs::create_dir_all(dir.path().join("sub")).expect("mkdir");
    std::fs::write(dir.path().join(".git").join("config"), "secret\n").expect("write");

    let mut policy = test_policy(dir.path(), RootMode::ReadOnly);
    policy.secrets.deny_globs = vec![".git/**".to_string()];
    let ctx = Context::new(policy).expect("ctx");

    assert_secret_path_denied(&ctx, "sub/../.git/config", ".git/config");
}
