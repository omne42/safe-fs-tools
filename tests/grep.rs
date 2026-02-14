#![cfg(feature = "grep")]

mod common;

use std::path::PathBuf;

use common::test_policy;
use safe_fs_tools::ops::{Context, GrepRequest, grep};
use safe_fs_tools::policy::RootMode;

#[cfg(feature = "glob")]
use safe_fs_tools::ops::{GlobRequest, glob_paths};

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

#[cfg(unix)]
fn is_running_as_root() -> bool {
    // SAFETY: `geteuid` has no preconditions and does not dereference pointers.
    unsafe { libc::geteuid() == 0 }
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
fn grep_globs_support_leading_dot_slash() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::create_dir_all(dir.path().join("src")).expect("mkdir");
    std::fs::write(dir.path().join("src").join("a.txt"), "needle\n").expect("write");

    let ctx = Context::new(test_policy(dir.path(), RootMode::ReadOnly)).expect("ctx");
    let resp = grep(
        &ctx,
        GrepRequest {
            root_id: "root".to_string(),
            query: "needle".to_string(),
            regex: false,
            glob: Some("./src/*.txt".to_string()),
        },
    )
    .expect("grep");

    assert_eq!(resp.matches.len(), 1);
    assert_eq!(resp.matches[0].path, PathBuf::from("src/a.txt"));
}

#[test]
fn grep_globs_reject_absolute_and_parent_segments() {
    let dir = tempfile::tempdir().expect("tempdir");
    let ctx = Context::new(test_policy(dir.path(), RootMode::ReadOnly)).expect("ctx");

    for pattern in ["/src/*.txt", "../**/*.txt", "src/../*.txt"] {
        let err = grep(
            &ctx,
            GrepRequest {
                root_id: "root".to_string(),
                query: "needle".to_string(),
                regex: false,
                glob: Some(pattern.to_string()),
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
fn grep_rejects_empty_query() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(dir.path().join("a.txt"), "needle\n").expect("write");

    let ctx = Context::new(test_policy(dir.path(), RootMode::ReadOnly)).expect("ctx");
    for query in ["", "   \t"] {
        let err = grep(
            &ctx,
            GrepRequest {
                root_id: "root".to_string(),
                query: query.to_string(),
                regex: false,
                glob: None,
            },
        )
        .expect_err("empty query should be rejected");

        match err {
            safe_fs_tools::Error::InvalidPath(msg) => {
                assert!(msg.contains("must not be empty"));
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }
}

#[test]
#[cfg(unix)]
fn grep_skips_dangling_symlink_targets() {
    use std::os::unix::fs::symlink;

    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(dir.path().join("a.txt"), "needle\n").expect("write");

    let missing = dir.path().join("missing.txt");
    symlink(&missing, dir.path().join("b.txt")).expect("symlink");

    let ctx = Context::new(test_policy(dir.path(), RootMode::ReadOnly)).expect("ctx");
    let resp = grep(
        &ctx,
        GrepRequest {
            root_id: "root".to_string(),
            query: "needle".to_string(),
            regex: false,
            glob: None,
        },
    )
    .expect("grep");

    assert_eq!(resp.matches.len(), 1);
    assert_eq!(resp.matches[0].path, PathBuf::from("a.txt"));
    assert_eq!(resp.skipped_dangling_symlink_targets, 1);
}

#[test]
#[cfg(unix)]
fn grep_does_not_follow_symlink_root_prefix() {
    use std::os::unix::fs::symlink;

    let dir = tempfile::tempdir().expect("tempdir");
    let outside = tempfile::tempdir().expect("outside");
    std::fs::write(outside.path().join("a.txt"), "needle\n").expect("write");
    symlink(outside.path(), dir.path().join("sub")).expect("symlink dir");

    let ctx = Context::new(test_policy(dir.path(), RootMode::ReadOnly)).expect("ctx");
    let resp = grep(
        &ctx,
        GrepRequest {
            root_id: "root".to_string(),
            query: "needle".to_string(),
            regex: false,
            glob: Some("sub/**/*.txt".to_string()),
        },
    )
    .expect("grep");

    assert!(resp.matches.is_empty());
    assert!(!resp.scan_limit_reached);
    assert!(!resp.truncated);
    assert_eq!(resp.scan_limit_reason, None);
}

#[test]
#[cfg(unix)]
fn grep_skips_walkdir_errors() {
    if is_running_as_root() {
        return;
    }

    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(dir.path().join("a.txt"), "needle\n").expect("write");

    let blocked = dir.path().join("blocked");
    std::fs::create_dir(&blocked).expect("mkdir");
    std::fs::write(blocked.join("b.txt"), "needle\n").expect("write");
    let _chmod_guard = PermissionRestoreGuard::set(&blocked, 0o000);

    let ctx = Context::new(test_policy(dir.path(), RootMode::ReadOnly)).expect("ctx");
    let resp = grep(
        &ctx,
        GrepRequest {
            root_id: "root".to_string(),
            query: "needle".to_string(),
            regex: false,
            glob: None,
        },
    )
    .expect("grep");

    assert_eq!(resp.matches.len(), 1);
    assert_eq!(resp.matches[0].path, PathBuf::from("a.txt"));
    assert!(
        resp.skipped_walk_errors > 0,
        "expected at least one walk error"
    );
}

#[test]
#[cfg(unix)]
fn grep_root_walkdir_error_does_not_leak_absolute_paths() {
    if is_running_as_root() {
        return;
    }

    let dir = tempfile::tempdir().expect("tempdir");

    let blocked = dir.path().join("blocked");
    std::fs::create_dir(&blocked).expect("mkdir");
    std::fs::write(blocked.join("b.txt"), "needle\n").expect("write");
    let _chmod_guard = PermissionRestoreGuard::set(&blocked, 0o000);

    let ctx = Context::new(test_policy(dir.path(), RootMode::ReadOnly)).expect("ctx");
    let err = grep(
        &ctx,
        GrepRequest {
            root_id: "root".to_string(),
            query: "needle".to_string(),
            regex: false,
            glob: Some("blocked/**/*.txt".to_string()),
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
}

#[test]
#[cfg(unix)]
fn grep_skips_unreadable_files() {
    if is_running_as_root() {
        return;
    }

    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(dir.path().join("a.txt"), "needle\n").expect("write");
    let unreadable = dir.path().join("b.txt");
    std::fs::write(&unreadable, "needle\n").expect("write");
    let _chmod_guard = PermissionRestoreGuard::set(&unreadable, 0o000);

    let ctx = Context::new(test_policy(dir.path(), RootMode::ReadOnly)).expect("ctx");
    let resp = grep(
        &ctx,
        GrepRequest {
            root_id: "root".to_string(),
            query: "needle".to_string(),
            regex: false,
            glob: None,
        },
    )
    .expect("grep");

    assert_eq!(resp.matches.len(), 1);
    assert_eq!(resp.matches[0].path, PathBuf::from("a.txt"));
    assert_eq!(resp.skipped_io_errors, 1);
}

#[test]
fn grep_respects_max_walk_ms_time_budget() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(dir.path().join("a.txt"), "needle\n").expect("write");

    let mut policy = test_policy(dir.path(), RootMode::ReadOnly);
    policy.limits.max_walk_ms = Some(0);

    let ctx = Context::new(policy).expect("ctx");
    let resp = grep(
        &ctx,
        GrepRequest {
            root_id: "root".to_string(),
            query: "needle".to_string(),
            regex: false,
            glob: None,
        },
    )
    .expect("grep");

    assert!(resp.truncated);
    assert!(resp.scan_limit_reached);
    assert_eq!(
        resp.scan_limit_reason,
        Some(safe_fs_tools::ops::ScanLimitReason::Time)
    );
}

#[test]
fn grep_redacts_sensitive_match_text() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(dir.path().join("a.txt"), "API_KEY=abc123 hello\n").expect("write");

    let mut policy = test_policy(dir.path(), RootMode::ReadOnly);
    policy.limits.max_read_bytes = 64;
    let ctx = Context::new(policy).expect("ctx");

    let resp = grep(
        &ctx,
        GrepRequest {
            root_id: "root".to_string(),
            query: "API_KEY=".to_string(),
            regex: false,
            glob: None,
        },
    )
    .expect("grep");

    assert_eq!(resp.matches.len(), 1);
    assert!(resp.matches[0].text.contains("***REDACTED***"));
    assert!(!resp.matches[0].text.contains("abc123"));
}

#[test]
fn grep_skips_non_utf8_files() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(dir.path().join("a.txt"), "API_KEY=abc123 hello\n").expect("write");
    std::fs::write(dir.path().join("bin.dat"), [0xff, 0xfe, 0xfd]).expect("write");

    let mut policy = test_policy(dir.path(), RootMode::ReadOnly);
    policy.limits.max_read_bytes = 64;
    let ctx = Context::new(policy).expect("ctx");

    let resp = grep(
        &ctx,
        GrepRequest {
            root_id: "root".to_string(),
            query: "API_KEY=".to_string(),
            regex: false,
            glob: None,
        },
    )
    .expect("grep");

    assert_eq!(resp.matches.len(), 1);
    assert_eq!(resp.skipped_non_utf8_files, 1);
    assert_eq!(resp.skipped_too_large_files, 0);
}

#[test]
fn grep_skips_too_large_files() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(dir.path().join("a.txt"), "API_KEY=abc123 hello\n").expect("write");
    std::fs::write(dir.path().join("large.txt"), "x".repeat(200)).expect("write");

    let mut policy = test_policy(dir.path(), RootMode::ReadOnly);
    policy.limits.max_read_bytes = 64;
    let ctx = Context::new(policy).expect("ctx");

    let resp = grep(
        &ctx,
        GrepRequest {
            root_id: "root".to_string(),
            query: "API_KEY=".to_string(),
            regex: false,
            glob: None,
        },
    )
    .expect("grep");

    assert_eq!(resp.matches.len(), 1);
    assert_eq!(resp.skipped_non_utf8_files, 0);
    assert_eq!(resp.skipped_too_large_files, 1);
}

#[test]
fn grep_skips_non_utf8_and_too_large_files() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(dir.path().join("a.txt"), "API_KEY=abc123 hello\n").expect("write");
    std::fs::write(dir.path().join("large.txt"), "x".repeat(200)).expect("write");
    std::fs::write(dir.path().join("bin.dat"), [0xff, 0xfe, 0xfd]).expect("write");

    let mut policy = test_policy(dir.path(), RootMode::ReadOnly);
    policy.limits.max_read_bytes = 64;
    let ctx = Context::new(policy).expect("ctx");

    let resp = grep(
        &ctx,
        GrepRequest {
            root_id: "root".to_string(),
            query: "API_KEY=".to_string(),
            regex: false,
            glob: None,
        },
    )
    .expect("grep");

    assert_eq!(resp.matches.len(), 1);
    assert!(resp.matches[0].text.contains("***REDACTED***"));
    assert!(!resp.matches[0].text.contains("abc123"));
    assert_eq!(resp.skipped_non_utf8_files, 1);
    assert_eq!(resp.skipped_too_large_files, 1);
}

#[test]
fn grep_honors_max_walk_files() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(dir.path().join("a.txt"), "hello\n").expect("write");
    std::fs::write(dir.path().join("b.txt"), "world\n").expect("write");

    let mut policy = test_policy(dir.path(), RootMode::ReadOnly);
    policy.limits.max_walk_files = 1;
    let ctx = Context::new(policy).expect("ctx");

    let resp = grep(
        &ctx,
        GrepRequest {
            root_id: "root".to_string(),
            query: "needle".to_string(),
            regex: false,
            glob: None,
        },
    )
    .expect("grep");

    assert!(resp.matches.is_empty());
    assert_eq!(resp.scanned_files, 1);
    assert!(resp.scan_limit_reached);
    assert!(resp.truncated);
}

#[test]
fn grep_honors_max_walk_entries() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(dir.path().join("a.txt"), "hello\n").expect("write");
    std::fs::write(dir.path().join("b.txt"), "world\n").expect("write");

    let mut policy = test_policy(dir.path(), RootMode::ReadOnly);
    policy.limits.max_walk_entries = 1;
    policy.limits.max_walk_files = 1;
    let ctx = Context::new(policy).expect("ctx");

    let resp = grep(
        &ctx,
        GrepRequest {
            root_id: "root".to_string(),
            query: "needle".to_string(),
            regex: false,
            glob: None,
        },
    )
    .expect("grep");

    assert!(resp.matches.is_empty());
    assert_eq!(resp.scanned_files, 1);
    assert!(resp.scan_limit_reached);
    assert!(resp.truncated);
    assert_eq!(
        resp.scan_limit_reason,
        Some(safe_fs_tools::ops::ScanLimitReason::Entries)
    );
}

#[test]
fn grep_reports_line_truncation() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(dir.path().join("long.txt"), "0123456789\n").expect("write");

    let mut policy = test_policy(dir.path(), RootMode::ReadOnly);
    policy.limits.max_line_bytes = 5;
    let ctx = Context::new(policy).expect("ctx");

    let resp = grep(
        &ctx,
        GrepRequest {
            root_id: "root".to_string(),
            query: "0".to_string(),
            regex: false,
            glob: Some("long.txt".to_string()),
        },
    )
    .expect("grep");

    assert_eq!(resp.matches.len(), 1);
    assert_eq!(resp.matches[0].path, PathBuf::from("long.txt"));
    assert_eq!(resp.matches[0].text, "01234");
    assert!(resp.matches[0].line_truncated);
}

#[test]
#[cfg(all(unix, feature = "glob"))]
fn glob_and_grep_include_symlink_files() {
    use std::os::unix::fs::symlink;

    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(dir.path().join("target.txt"), "hello\n").expect("write");
    symlink(dir.path().join("target.txt"), dir.path().join("link.txt")).expect("symlink");

    let ctx = Context::new(test_policy(dir.path(), RootMode::ReadOnly)).expect("ctx");

    let glob = glob_paths(
        &ctx,
        GlobRequest {
            root_id: "root".to_string(),
            pattern: "link.txt".to_string(),
        },
    )
    .expect("glob");
    assert_eq!(glob.matches, vec![PathBuf::from("link.txt")]);

    let resp = grep(
        &ctx,
        GrepRequest {
            root_id: "root".to_string(),
            query: "hello".to_string(),
            regex: false,
            glob: Some("link.txt".to_string()),
        },
    )
    .expect("grep");
    assert_eq!(resp.matches.len(), 1);
    assert_eq!(resp.matches[0].path, PathBuf::from("link.txt"));
}

#[test]
#[cfg(all(unix, feature = "glob"))]
fn glob_and_grep_include_symlink_files_when_absolute_paths_are_disallowed() {
    use std::os::unix::fs::symlink;

    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(dir.path().join("target.txt"), "hello\n").expect("write");
    symlink(dir.path().join("target.txt"), dir.path().join("link.txt")).expect("symlink");

    let mut policy = test_policy(dir.path(), RootMode::ReadOnly);
    policy.paths.allow_absolute = false;
    let ctx = Context::new(policy).expect("ctx");

    let glob = glob_paths(
        &ctx,
        GlobRequest {
            root_id: "root".to_string(),
            pattern: "link.txt".to_string(),
        },
    )
    .expect("glob");
    assert_eq!(glob.matches, vec![PathBuf::from("link.txt")]);

    let resp = grep(
        &ctx,
        GrepRequest {
            root_id: "root".to_string(),
            query: "hello".to_string(),
            regex: false,
            glob: Some("link.txt".to_string()),
        },
    )
    .expect("grep");
    assert_eq!(resp.matches.len(), 1);
    assert_eq!(resp.matches[0].path, PathBuf::from("link.txt"));
}

#[test]
fn grep_truncation_is_deterministic_under_max_results() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(dir.path().join("b.txt"), "needle\n").expect("write");
    std::fs::write(dir.path().join("a.txt"), "needle\n").expect("write");

    let mut policy = test_policy(dir.path(), RootMode::ReadOnly);
    policy.limits.max_results = 1;
    let ctx = Context::new(policy).expect("ctx");

    let resp = grep(
        &ctx,
        GrepRequest {
            root_id: "root".to_string(),
            query: "needle".to_string(),
            regex: false,
            glob: None,
        },
    )
    .expect("grep");

    assert_eq!(resp.matches.len(), 1);
    assert_eq!(resp.matches[0].path, PathBuf::from("a.txt"));
    assert!(resp.truncated);
    assert!(resp.scan_limit_reached);
    assert_eq!(
        resp.scan_limit_reason,
        Some(safe_fs_tools::ops::ScanLimitReason::Results)
    );
}

#[test]
fn grep_truncates_on_utf8_boundary() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(dir.path().join("utf8.txt"), "€€€\n").expect("write");

    let mut policy = test_policy(dir.path(), RootMode::ReadOnly);
    policy.limits.max_line_bytes = 4;
    let ctx = Context::new(policy).expect("ctx");

    let resp = grep(
        &ctx,
        GrepRequest {
            root_id: "root".to_string(),
            query: "€".to_string(),
            regex: false,
            glob: Some("utf8.txt".to_string()),
        },
    )
    .expect("grep");

    assert_eq!(resp.matches.len(), 1);
    assert_eq!(resp.matches[0].path, PathBuf::from("utf8.txt"));
    assert_eq!(resp.matches[0].text, "€");
    assert!(resp.matches[0].line_truncated);
}
