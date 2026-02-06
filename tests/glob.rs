#![cfg(feature = "glob")]

mod common;

use std::path::PathBuf;

use common::test_policy;
use safe_fs_tools::ops::{Context, GlobRequest, glob_paths};
use safe_fs_tools::policy::RootMode;

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

#[cfg(unix)]
fn is_root_user() -> bool {
    // Safety: libc call with no preconditions.
    unsafe { libc::geteuid() == 0 }
}

#[test]
fn glob_patterns_support_leading_dot_slash() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::create_dir_all(dir.path().join("src")).expect("mkdir");
    std::fs::write(dir.path().join("src").join("a.txt"), "a\n").expect("write");

    let ctx = Context::new(test_policy(dir.path(), RootMode::ReadOnly)).expect("ctx");
    let resp = glob_paths(
        &ctx,
        GlobRequest {
            root_id: "root".to_string(),
            pattern: "./src/*.txt".to_string(),
        },
    )
    .expect("glob");

    assert_eq!(resp.matches, vec![PathBuf::from("src/a.txt")]);
}

#[test]
fn glob_patterns_reject_absolute_and_parent_segments() {
    let dir = tempfile::tempdir().expect("tempdir");
    let ctx = Context::new(test_policy(dir.path(), RootMode::ReadOnly)).expect("ctx");

    for pattern in ["/src/*.txt", "../**/*.txt", "src/../*.txt"] {
        let err = glob_paths(
            &ctx,
            GlobRequest {
                root_id: "root".to_string(),
                pattern: pattern.to_string(),
            },
        )
        .expect_err("should reject");

        match err {
            safe_fs_tools::Error::InvalidPath(_) => {}
            other => panic!("unexpected error: {other:?}"),
        }
    }
}

#[test]
#[cfg(unix)]
fn glob_skips_dangling_symlink_targets() {
    use std::os::unix::fs::symlink;

    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(dir.path().join("a.txt"), "a\n").expect("write");

    let missing = dir.path().join("missing.txt");
    symlink(&missing, dir.path().join("b.txt")).expect("symlink");

    let ctx = Context::new(test_policy(dir.path(), RootMode::ReadOnly)).expect("ctx");
    let resp = glob_paths(
        &ctx,
        GlobRequest {
            root_id: "root".to_string(),
            pattern: "*.txt".to_string(),
        },
    )
    .expect("glob");

    assert_eq!(resp.matches, vec![PathBuf::from("a.txt")]);
}

#[test]
#[cfg(unix)]
fn glob_does_not_follow_symlink_root_prefix() {
    use std::os::unix::fs::symlink;

    let dir = tempfile::tempdir().expect("tempdir");
    let outside = tempfile::tempdir().expect("outside");
    std::fs::write(outside.path().join("a.txt"), "a\n").expect("write");
    symlink(outside.path(), dir.path().join("sub")).expect("symlink dir");

    let ctx = Context::new(test_policy(dir.path(), RootMode::ReadOnly)).expect("ctx");
    let resp = glob_paths(
        &ctx,
        GlobRequest {
            root_id: "root".to_string(),
            pattern: "sub/**/*.txt".to_string(),
        },
    )
    .expect("glob");

    assert!(resp.matches.is_empty());
    assert_eq!(resp.scanned_entries, 0);
    assert_eq!(resp.scanned_files, 1);
}

#[test]
#[cfg(unix)]
fn glob_skips_walkdir_errors() {
    if is_root_user() {
        eprintln!("skipping: permission-based walkdir error tests do not work as root");
        return;
    }

    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(dir.path().join("a.txt"), "a\n").expect("write");

    let blocked = dir.path().join("blocked");
    std::fs::create_dir(&blocked).expect("mkdir");
    std::fs::write(blocked.join("b.txt"), "b\n").expect("write");
    std::fs::set_permissions(&blocked, std::fs::Permissions::from_mode(0o000)).expect("chmod");

    let ctx = Context::new(test_policy(dir.path(), RootMode::ReadOnly)).expect("ctx");
    let resp = glob_paths(
        &ctx,
        GlobRequest {
            root_id: "root".to_string(),
            pattern: "*.txt".to_string(),
        },
    )
    .expect("glob");

    assert_eq!(resp.matches, vec![PathBuf::from("a.txt")]);
    assert!(
        resp.skipped_walk_errors > 0,
        "expected at least one walk error"
    );

    std::fs::set_permissions(&blocked, std::fs::Permissions::from_mode(0o700)).expect("chmod back");
}

#[test]
#[cfg(unix)]
fn glob_root_walkdir_error_does_not_leak_absolute_paths() {
    if is_root_user() {
        eprintln!("skipping: permission-based walkdir error tests do not work as root");
        return;
    }

    let dir = tempfile::tempdir().expect("tempdir");

    let blocked = dir.path().join("blocked");
    std::fs::create_dir(&blocked).expect("mkdir");
    std::fs::write(blocked.join("b.txt"), "b\n").expect("write");
    std::fs::set_permissions(&blocked, std::fs::Permissions::from_mode(0o000)).expect("chmod");

    let ctx = Context::new(test_policy(dir.path(), RootMode::ReadOnly)).expect("ctx");
    let err = glob_paths(
        &ctx,
        GlobRequest {
            root_id: "root".to_string(),
            pattern: "blocked/*.txt".to_string(),
        },
    )
    .expect_err("should fail");

    match &err {
        safe_fs_tools::Error::WalkDirRoot { path, .. } => {
            assert!(!path.is_absolute());
            assert_eq!(path, &PathBuf::from("blocked"));
        }
        other => panic!("unexpected error: {other:?}"),
    }

    let rendered = err.to_string();
    assert!(
        !rendered.contains(&dir.path().display().to_string()),
        "expected error to not contain absolute root path: {rendered}"
    );

    std::fs::set_permissions(&blocked, std::fs::Permissions::from_mode(0o700)).expect("chmod back");
}

#[test]
fn glob_respects_max_walk_ms_time_budget() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(dir.path().join("a.txt"), "a\n").expect("write");

    let mut policy = test_policy(dir.path(), RootMode::ReadOnly);
    policy.limits.max_walk_ms = Some(0);

    let ctx = Context::new(policy).expect("ctx");
    let resp = glob_paths(
        &ctx,
        GlobRequest {
            root_id: "root".to_string(),
            pattern: "**/*.txt".to_string(),
        },
    )
    .expect("glob");

    assert!(resp.truncated);
    assert!(resp.scan_limit_reached);
    assert_eq!(
        resp.scan_limit_reason,
        Some(safe_fs_tools::ops::ScanLimitReason::Time)
    );
    assert!(resp.matches.is_empty());
}

#[test]
fn glob_truncation_is_deterministic_under_max_results() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(dir.path().join("b.txt"), "b\n").expect("write");
    std::fs::write(dir.path().join("a.txt"), "a\n").expect("write");

    let mut policy = test_policy(dir.path(), RootMode::ReadOnly);
    policy.limits.max_results = 1;
    let ctx = Context::new(policy).expect("ctx");

    let resp = glob_paths(
        &ctx,
        GlobRequest {
            root_id: "root".to_string(),
            pattern: "*.txt".to_string(),
        },
    )
    .expect("glob");

    assert_eq!(resp.matches, vec![PathBuf::from("a.txt")]);
    assert!(resp.truncated);
    assert!(resp.scan_limit_reached);
    assert_eq!(
        resp.scan_limit_reason,
        Some(safe_fs_tools::ops::ScanLimitReason::Results)
    );
}
