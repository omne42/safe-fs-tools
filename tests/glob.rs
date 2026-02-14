#![cfg(feature = "glob")]

mod common;

use std::path::{Path, PathBuf};

use common::all_permissions_test_policy;
use safe_fs_tools::ops::{Context, GlobRequest, glob_paths};
use safe_fs_tools::policy::RootMode;

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

#[cfg(unix)]
fn is_running_as_root() -> bool {
    // SAFETY: `geteuid` has no preconditions and does not dereference pointers.
    unsafe { libc::geteuid() == 0 }
}

#[cfg(unix)]
fn skip_when_root(test_name: &str) -> bool {
    if is_running_as_root() {
        eprintln!("{test_name} skipped: requires non-root to validate permission-denied behavior");
        return true;
    }
    false
}

#[cfg(unix)]
struct PermissionRestoreGuard {
    path: PathBuf,
    mode: u32,
}

#[cfg(unix)]
impl PermissionRestoreGuard {
    fn set(path: &std::path::Path, mode: u32) -> Self {
        let prev = std::fs::symlink_metadata(path)
            .expect("stat before chmod")
            .permissions()
            .mode()
            & 0o777;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).expect("chmod");
        Self {
            path: path.to_path_buf(),
            mode: prev,
        }
    }
}

#[cfg(unix)]
impl Drop for PermissionRestoreGuard {
    fn drop(&mut self) {
        if let Err(err) =
            std::fs::set_permissions(&self.path, std::fs::Permissions::from_mode(self.mode))
        {
            eprintln!(
                "failed to restore permissions for {}: {err}",
                self.path.display()
            );
        }
    }
}

#[test]
fn glob_patterns_support_leading_dot_slash() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::create_dir_all(dir.path().join("src")).expect("mkdir");
    std::fs::write(dir.path().join("src").join("a.txt"), "a\n").expect("write");

    let ctx =
        Context::new(all_permissions_test_policy(dir.path(), RootMode::ReadOnly)).expect("ctx");
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
    let ctx =
        Context::new(all_permissions_test_policy(dir.path(), RootMode::ReadOnly)).expect("ctx");

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
            safe_fs_tools::Error::InvalidPath(message) => {
                assert!(
                    message.contains(pattern),
                    "expected invalid pattern message to contain input pattern {pattern:?}, got {message:?}"
                );
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }
}

#[test]
fn glob_patterns_reject_empty_and_whitespace() {
    let dir = tempfile::tempdir().expect("tempdir");
    let ctx =
        Context::new(all_permissions_test_policy(dir.path(), RootMode::ReadOnly)).expect("ctx");

    for pattern in ["", "   "] {
        let err = glob_paths(
            &ctx,
            GlobRequest {
                root_id: "root".to_string(),
                pattern: pattern.to_string(),
            },
        )
        .expect_err("should reject");

        match err {
            safe_fs_tools::Error::InvalidPath(message) => {
                assert!(
                    message.contains("empty"),
                    "expected empty-pattern error, got {message:?}"
                );
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }
}

#[test]
fn glob_missing_prefix_returns_empty_without_error() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(dir.path().join("a.txt"), "a\n").expect("write");

    let ctx =
        Context::new(all_permissions_test_policy(dir.path(), RootMode::ReadOnly)).expect("ctx");
    let resp = glob_paths(
        &ctx,
        GlobRequest {
            root_id: "root".to_string(),
            pattern: "missing/**/*.txt".to_string(),
        },
    )
    .expect("glob");

    assert!(resp.matches.is_empty());
    assert_eq!(resp.scanned_entries, 0);
    assert_eq!(resp.scanned_files, 0);
    assert_eq!(resp.skipped_walk_errors, 0);
}

#[test]
fn glob_dot_pattern_is_stable() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(dir.path().join("a.txt"), "a\n").expect("write");

    let ctx =
        Context::new(all_permissions_test_policy(dir.path(), RootMode::ReadOnly)).expect("ctx");
    let resp = glob_paths(
        &ctx,
        GlobRequest {
            root_id: "root".to_string(),
            pattern: ".".to_string(),
        },
    )
    .expect("glob");

    assert!(resp.matches.is_empty());
    assert!(!resp.truncated);
    assert!(!resp.scan_limit_reached);
}

#[test]
#[cfg(unix)]
fn glob_skips_dangling_symlink_targets() {
    use std::os::unix::fs::symlink;

    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(dir.path().join("a.txt"), "a\n").expect("write");

    let missing = dir.path().join("missing.txt");
    symlink(&missing, dir.path().join("b.txt")).expect("symlink");

    let ctx =
        Context::new(all_permissions_test_policy(dir.path(), RootMode::ReadOnly)).expect("ctx");
    let resp = glob_paths(
        &ctx,
        GlobRequest {
            root_id: "root".to_string(),
            pattern: "*.txt".to_string(),
        },
    )
    .expect("glob");

    assert_eq!(resp.matches, vec![PathBuf::from("a.txt")]);
    assert_eq!(resp.skipped_dangling_symlink_targets, 1);
}

#[test]
#[cfg(unix)]
fn glob_does_not_follow_symlink_root_prefix() {
    use std::os::unix::fs::symlink;

    let dir = tempfile::tempdir().expect("tempdir");
    let outside = tempfile::tempdir().expect("outside");
    std::fs::write(outside.path().join("a.txt"), "a\n").expect("write");
    symlink(outside.path(), dir.path().join("sub")).expect("symlink dir");

    let ctx =
        Context::new(all_permissions_test_policy(dir.path(), RootMode::ReadOnly)).expect("ctx");
    let err = glob_paths(
        &ctx,
        GlobRequest {
            root_id: "root".to_string(),
            pattern: "sub/**/*.txt".to_string(),
        },
    )
    .expect_err("should reject root-prefix symlink escaping outside root");

    match &err {
        safe_fs_tools::Error::OutsideRoot { root_id, path } => {
            assert_eq!(root_id, "root");
            assert!(!path.is_absolute());
            assert_eq!(path.as_path(), Path::new("sub"));
        }
        safe_fs_tools::Error::InvalidPath(message) => {
            assert!(
                message.contains("escapes selected root"),
                "unexpected: {message}"
            );
        }
        other => panic!("unexpected error: {other:?}"),
    }

    let rendered = err.to_string();
    assert!(
        !rendered.contains(&dir.path().display().to_string()),
        "expected error to not contain absolute root path: {rendered}"
    );
    assert!(
        !rendered.contains(&outside.path().display().to_string()),
        "expected error to not contain absolute outside path: {rendered}"
    );
}

#[test]
#[cfg(unix)]
fn glob_skips_walkdir_errors() {
    if skip_when_root("glob_skips_walkdir_errors") {
        return;
    }

    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(dir.path().join("a.txt"), "a\n").expect("write");

    let blocked = dir.path().join("blocked");
    std::fs::create_dir(&blocked).expect("mkdir");
    std::fs::write(blocked.join("b.txt"), "b\n").expect("write");
    let _chmod_guard = PermissionRestoreGuard::set(&blocked, 0o000);

    let ctx =
        Context::new(all_permissions_test_policy(dir.path(), RootMode::ReadOnly)).expect("ctx");
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
        resp.skipped_walk_errors >= 1,
        "expected at least one walk error"
    );
}

#[test]
#[cfg(unix)]
fn glob_root_walkdir_error_does_not_leak_absolute_paths() {
    if skip_when_root("glob_root_walkdir_error_does_not_leak_absolute_paths") {
        return;
    }

    let dir = tempfile::tempdir().expect("tempdir");

    let blocked = dir.path().join("blocked");
    std::fs::create_dir(&blocked).expect("mkdir");
    std::fs::write(blocked.join("b.txt"), "b\n").expect("write");
    let _chmod_guard = PermissionRestoreGuard::set(&blocked, 0o000);

    let ctx =
        Context::new(all_permissions_test_policy(dir.path(), RootMode::ReadOnly)).expect("ctx");
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
            assert_eq!(path.as_path(), Path::new("blocked"));
        }
        other => panic!("unexpected error: {other:?}"),
    }

    let rendered = err.to_string();
    assert!(
        !rendered.contains(&dir.path().display().to_string()),
        "expected error to not contain absolute root path: {rendered}"
    );
}

#[test]
fn glob_respects_max_walk_ms_time_budget() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(dir.path().join("a.txt"), "a\n").expect("write");

    let mut policy = all_permissions_test_policy(dir.path(), RootMode::ReadOnly);
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
    assert!(resp.matches.len() <= ctx.policy().limits.max_results);
}

#[test]
fn glob_truncation_is_deterministic_under_max_results() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(dir.path().join("b.txt"), "b\n").expect("write");
    std::fs::write(dir.path().join("a.txt"), "a\n").expect("write");

    let mut policy = all_permissions_test_policy(dir.path(), RootMode::ReadOnly);
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
