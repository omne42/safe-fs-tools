use std::path::PathBuf;

use safe_fs_tools::ops::{
    Context, DeleteRequest, EditRequest, ReadRequest, delete_file, edit_range, read_file,
};
#[cfg(feature = "glob")]
use safe_fs_tools::ops::{GlobRequest, glob_paths};
#[cfg(feature = "grep")]
use safe_fs_tools::ops::{GrepRequest, grep};
#[cfg(feature = "patch")]
use safe_fs_tools::ops::{PatchRequest, apply_unified_patch};
use safe_fs_tools::policy::{
    Limits, Permissions, Root, RootMode, SandboxPolicy, SecretRules, TraversalRules,
};
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

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
        traversal: TraversalRules::default(),
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
            start_line: None,
            end_line: None,
        },
    )
    .expect("read");

    assert_eq!(response.path, PathBuf::from("hello.txt"));
    assert_eq!(response.requested_path, Some(PathBuf::from("hello.txt")));
    assert!(response.content.contains("***REDACTED***"));
    assert!(!response.content.contains("abc123"));
}

#[test]
fn read_redacts_literal_replacement_without_expanding_capture_groups() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("hello.txt");
    std::fs::write(&path, "API_KEY=abc123\nhello\n").expect("write");

    let mut policy = test_policy(dir.path(), RootMode::ReadOnly);
    policy.secrets.redact_regexes = vec!["API_KEY=([A-Za-z0-9_]+)".to_string()];
    policy.secrets.replacement = "***$1***".to_string();

    let ctx = Context::new(policy).expect("ctx");
    let response = read_file(
        &ctx,
        ReadRequest {
            root_id: "root".to_string(),
            path: PathBuf::from("hello.txt"),
            start_line: None,
            end_line: None,
        },
    )
    .expect("read");

    assert!(response.content.contains("***$1***"));
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
            start_line: None,
            end_line: None,
        },
    )
    .expect_err("should reject");

    match err {
        safe_fs_tools::Error::OutsideRoot { .. } => {}
        other => panic!("unexpected error: {other:?}"),
    }
}

#[test]
#[cfg(unix)]
fn read_rejects_dangling_symlink_escape() {
    use std::os::unix::fs::symlink;

    let dir = tempfile::tempdir().expect("tempdir");
    let outside = tempfile::tempdir().expect("outside");
    let link_target = outside.path().join("missing.txt");
    symlink(&link_target, dir.path().join("link.txt")).expect("symlink");

    let ctx = Context::new(test_policy(dir.path(), RootMode::ReadOnly)).expect("ctx");
    let err = read_file(
        &ctx,
        ReadRequest {
            root_id: "root".to_string(),
            path: PathBuf::from("link.txt"),
            start_line: None,
            end_line: None,
        },
    )
    .expect_err("should reject");

    match err {
        safe_fs_tools::Error::OutsideRoot { .. } => {}
        other => panic!("unexpected error: {other:?}"),
    }
}

#[test]
#[cfg(unix)]
fn edit_rejects_symlink_escape() {
    use std::os::unix::fs::symlink;

    let dir = tempfile::tempdir().expect("tempdir");
    let outside = tempfile::NamedTempFile::new().expect("tmp");
    std::fs::write(outside.path(), "one\n").expect("write");

    symlink(outside.path(), dir.path().join("link.txt")).expect("symlink");

    let ctx = Context::new(test_policy(dir.path(), RootMode::ReadWrite)).expect("ctx");
    let err = edit_range(
        &ctx,
        EditRequest {
            root_id: "root".to_string(),
            path: PathBuf::from("link.txt"),
            start_line: 1,
            end_line: 1,
            replacement: "ONE".to_string(),
        },
    )
    .expect_err("should reject");

    match err {
        safe_fs_tools::Error::OutsideRoot { .. } => {}
        other => panic!("unexpected error: {other:?}"),
    }
}

#[test]
#[cfg(all(unix, feature = "patch"))]
fn patch_rejects_symlink_escape() {
    use std::os::unix::fs::symlink;

    let dir = tempfile::tempdir().expect("tempdir");
    let outside = tempfile::NamedTempFile::new().expect("tmp");
    std::fs::write(outside.path(), "one\n").expect("write");

    symlink(outside.path(), dir.path().join("link.txt")).expect("symlink");

    let ctx = Context::new(test_policy(dir.path(), RootMode::ReadWrite)).expect("ctx");
    let err = apply_unified_patch(
        &ctx,
        PatchRequest {
            root_id: "root".to_string(),
            path: PathBuf::from("link.txt"),
            patch: diffy::create_patch("one\n", "ONE\n").to_string(),
        },
    )
    .expect_err("should reject");

    match err {
        safe_fs_tools::Error::OutsideRoot { .. } => {}
        other => panic!("unexpected error: {other:?}"),
    }
}

#[test]
#[cfg(unix)]
fn edit_rejects_symlink_escape_via_ancestor_dir() {
    use std::os::unix::fs::symlink;

    let dir = tempfile::tempdir().expect("tempdir");
    let outside = tempfile::tempdir().expect("outside");
    std::fs::write(outside.path().join("file.txt"), "one\n").expect("write");

    symlink(outside.path(), dir.path().join("sub")).expect("symlink dir");

    let ctx = Context::new(test_policy(dir.path(), RootMode::ReadWrite)).expect("ctx");
    let err = edit_range(
        &ctx,
        EditRequest {
            root_id: "root".to_string(),
            path: PathBuf::from("sub/file.txt"),
            start_line: 1,
            end_line: 1,
            replacement: "ONE".to_string(),
        },
    )
    .expect_err("should reject");

    match err {
        safe_fs_tools::Error::OutsideRoot { .. } => {}
        other => panic!("unexpected error: {other:?}"),
    }
}

#[test]
#[cfg(all(unix, feature = "glob"))]
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
#[cfg(all(unix, feature = "grep"))]
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
}

#[test]
#[cfg(feature = "grep")]
fn traversal_skip_globs_skip_in_traversal_but_allow_direct_read() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::create_dir_all(dir.path().join("node_modules")).expect("mkdir");
    std::fs::write(dir.path().join("keep.txt"), "needle\n").expect("write");
    std::fs::write(dir.path().join("node_modules").join("skip.txt"), "needle\n").expect("write");

    let mut policy = test_policy(dir.path(), RootMode::ReadOnly);
    policy.traversal.skip_globs = vec!["node_modules/**".to_string()];
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

    assert_eq!(resp.scanned_files, 1);
    assert_eq!(resp.matches.len(), 1);
    assert_eq!(resp.matches[0].path, PathBuf::from("keep.txt"));

    let read = read_file(
        &ctx,
        ReadRequest {
            root_id: "root".to_string(),
            path: PathBuf::from("node_modules").join("skip.txt"),
            start_line: None,
            end_line: None,
        },
    )
    .expect("read");
    assert!(read.content.contains("needle"));
}

#[test]
#[cfg(all(unix, feature = "glob"))]
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
#[cfg(all(unix, feature = "grep"))]
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
    assert_eq!(resp.scanned_entries, 0);
    assert_eq!(resp.scanned_files, 1);
}

#[test]
#[cfg(all(unix, feature = "glob"))]
fn glob_skips_walkdir_errors() {
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
#[cfg(all(unix, feature = "grep"))]
fn grep_skips_walkdir_errors() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(dir.path().join("a.txt"), "needle\n").expect("write");

    let blocked = dir.path().join("blocked");
    std::fs::create_dir(&blocked).expect("mkdir");
    std::fs::write(blocked.join("b.txt"), "needle\n").expect("write");
    std::fs::set_permissions(&blocked, std::fs::Permissions::from_mode(0o000)).expect("chmod");

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

    std::fs::set_permissions(&blocked, std::fs::Permissions::from_mode(0o700)).expect("chmod back");
}

#[test]
#[cfg(all(unix, feature = "grep"))]
fn grep_skips_unreadable_files() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(dir.path().join("a.txt"), "needle\n").expect("write");
    let unreadable = dir.path().join("b.txt");
    std::fs::write(&unreadable, "needle\n").expect("write");
    std::fs::set_permissions(&unreadable, std::fs::Permissions::from_mode(0o000)).expect("chmod");

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
#[cfg(feature = "glob")]
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
#[cfg(feature = "grep")]
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
    assert!(resp.matches.is_empty());
}

#[test]
#[cfg(feature = "patch")]
fn edit_patch_delete_roundtrip() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("file.txt");
    std::fs::write(&path, "one\ntwo\nthree\n").expect("write");

    let ctx = Context::new(test_policy(dir.path(), RootMode::ReadWrite)).expect("ctx");

    let edit = edit_range(
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
    assert_eq!(edit.requested_path, Some(PathBuf::from("file.txt")));

    let after_edit = std::fs::read_to_string(&path).expect("read");
    assert!(after_edit.contains("TWO"));

    let updated = "one\nTWO\nTHREE\n";
    let patch = diffy::create_patch(&after_edit, updated);

    let patch_resp = apply_unified_patch(
        &ctx,
        PatchRequest {
            root_id: "root".to_string(),
            path: PathBuf::from("file.txt"),
            patch: patch.to_string(),
        },
    )
    .expect("patch");
    assert_eq!(patch_resp.requested_path, Some(PathBuf::from("file.txt")));

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

#[test]
fn read_supports_line_ranges() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("lines.txt");
    std::fs::write(&path, "one\ntwo\nthree\nfour\n").expect("write");

    let ctx = Context::new(test_policy(dir.path(), RootMode::ReadOnly)).expect("ctx");
    let response = read_file(
        &ctx,
        ReadRequest {
            root_id: "root".to_string(),
            path: PathBuf::from("lines.txt"),
            start_line: Some(2),
            end_line: Some(3),
        },
    )
    .expect("read");

    assert_eq!(response.content, "two\nthree\n");
    assert_eq!(response.start_line, Some(2));
    assert_eq!(response.end_line, Some(3));
}

#[test]
fn read_line_ranges_respects_max_read_bytes() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("bigline.txt");
    std::fs::write(&path, "x".repeat(200)).expect("write");

    let mut policy = test_policy(dir.path(), RootMode::ReadOnly);
    policy.limits.max_read_bytes = 64;
    let ctx = Context::new(policy).expect("ctx");

    let err = read_file(
        &ctx,
        ReadRequest {
            root_id: "root".to_string(),
            path: PathBuf::from("bigline.txt"),
            start_line: Some(1),
            end_line: Some(1),
        },
    )
    .expect_err("should reject");

    match err {
        safe_fs_tools::Error::FileTooLarge { .. } => {}
        other => panic!("unexpected error: {other:?}"),
    }
}

#[test]
fn edit_preserves_crlf() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("crlf.txt");
    std::fs::write(&path, "one\r\ntwo\r\nthree\r\n").expect("write");

    let ctx = Context::new(test_policy(dir.path(), RootMode::ReadWrite)).expect("ctx");
    edit_range(
        &ctx,
        EditRequest {
            root_id: "root".to_string(),
            path: PathBuf::from("crlf.txt"),
            start_line: 2,
            end_line: 2,
            replacement: "TWO".to_string(),
        },
    )
    .expect("edit");

    let out = std::fs::read_to_string(&path).expect("read");
    assert_eq!(out, "one\r\nTWO\r\nthree\r\n");
}

#[test]
fn edit_respects_max_write_bytes() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("small.txt");
    std::fs::write(&path, "one\n").expect("write");

    let mut policy = test_policy(dir.path(), RootMode::ReadWrite);
    policy.limits.max_write_bytes = 1;
    let ctx = Context::new(policy).expect("ctx");

    let err = edit_range(
        &ctx,
        EditRequest {
            root_id: "root".to_string(),
            path: PathBuf::from("small.txt"),
            start_line: 1,
            end_line: 1,
            replacement: "X".to_string(),
        },
    )
    .expect_err("should reject");

    match err {
        safe_fs_tools::Error::FileTooLarge {
            path,
            size_bytes,
            max_bytes,
        } => {
            assert_eq!(path, PathBuf::from("small.txt"));
            assert_eq!(size_bytes, 2, "expected newline-preserving output size");
            assert_eq!(max_bytes, 1);
        }
        other => panic!("unexpected error: {other:?}"),
    }
}

#[test]
#[cfg(unix)]
fn edit_preserves_unix_permissions() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("mode.txt");
    std::fs::write(&path, "one\ntwo\nthree\n").expect("write");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).expect("chmod");

    let ctx = Context::new(test_policy(dir.path(), RootMode::ReadWrite)).expect("ctx");
    edit_range(
        &ctx,
        EditRequest {
            root_id: "root".to_string(),
            path: PathBuf::from("mode.txt"),
            start_line: 2,
            end_line: 2,
            replacement: "TWO".to_string(),
        },
    )
    .expect("edit");

    let mode = std::fs::metadata(&path).expect("stat").permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);
}

#[test]
#[cfg(feature = "grep")]
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
    };

    let err = Context::new(policy).expect_err("should reject");
    match err {
        safe_fs_tools::Error::InvalidPolicy(msg) => assert!(msg.contains("duplicate root.id")),
        other => panic!("unexpected error: {other:?}"),
    }
}

#[test]
#[cfg(feature = "grep")]
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
#[cfg(feature = "grep")]
fn grep_honors_max_walk_entries() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(dir.path().join("a.txt"), "hello\n").expect("write");
    std::fs::write(dir.path().join("b.txt"), "world\n").expect("write");

    let mut policy = test_policy(dir.path(), RootMode::ReadOnly);
    policy.limits.max_walk_entries = 1;
    policy.limits.max_walk_files = 10;
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
fn edit_respects_max_read_bytes() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("big.txt");
    std::fs::write(&path, "line\n".repeat(50)).expect("write");

    let mut policy = test_policy(dir.path(), RootMode::ReadWrite);
    policy.limits.max_read_bytes = 8;
    let ctx = Context::new(policy).expect("ctx");

    let err = edit_range(
        &ctx,
        EditRequest {
            root_id: "root".to_string(),
            path: PathBuf::from("big.txt"),
            start_line: 1,
            end_line: 1,
            replacement: "LINE".to_string(),
        },
    )
    .expect_err("should reject");

    match err {
        safe_fs_tools::Error::FileTooLarge { .. } => {}
        other => panic!("unexpected error: {other:?}"),
    }
}

#[test]
#[cfg(feature = "patch")]
fn patch_respects_max_read_bytes() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("big.txt");
    std::fs::write(&path, "line\n".repeat(50)).expect("write");

    let mut policy = test_policy(dir.path(), RootMode::ReadWrite);
    policy.limits.max_read_bytes = 8;
    policy.limits.max_patch_bytes = Some(1024);
    let ctx = Context::new(policy).expect("ctx");

    let err = apply_unified_patch(
        &ctx,
        PatchRequest {
            root_id: "root".to_string(),
            path: PathBuf::from("big.txt"),
            patch: diffy::create_patch("", "").to_string(),
        },
    )
    .expect_err("should reject");

    match err {
        safe_fs_tools::Error::FileTooLarge { .. } => {}
        other => panic!("unexpected error: {other:?}"),
    }
}

#[test]
#[cfg(feature = "patch")]
fn patch_rejects_too_large_patch_input() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("file.txt");
    std::fs::write(&path, "one\n").expect("write");

    let mut policy = test_policy(dir.path(), RootMode::ReadWrite);
    policy.limits.max_patch_bytes = Some(10);
    let ctx = Context::new(policy).expect("ctx");

    let err = apply_unified_patch(
        &ctx,
        PatchRequest {
            root_id: "root".to_string(),
            path: PathBuf::from("file.txt"),
            patch: "x".repeat(11),
        },
    )
    .expect_err("should reject");

    match err {
        safe_fs_tools::Error::InputTooLarge { .. } => {}
        other => panic!("unexpected error: {other:?}"),
    }
}

#[test]
#[cfg(unix)]
fn delete_unlinks_symlink_without_deleting_target() {
    use std::os::unix::fs::symlink;

    let dir = tempfile::tempdir().expect("tempdir");
    let target = dir.path().join("target.txt");
    let link = dir.path().join("link.txt");
    std::fs::write(&target, "hello\n").expect("write");
    symlink(&target, &link).expect("symlink");

    let ctx = Context::new(test_policy(dir.path(), RootMode::ReadWrite)).expect("ctx");
    delete_file(
        &ctx,
        DeleteRequest {
            root_id: "root".to_string(),
            path: PathBuf::from("link.txt"),
        },
    )
    .expect("delete");

    assert!(!link.exists());
    assert!(target.exists());
}

#[test]
#[cfg(unix)]
fn delete_unlinks_symlink_even_if_target_is_outside_root() {
    use std::os::unix::fs::symlink;

    let dir = tempfile::tempdir().expect("tempdir");
    let outside = tempfile::NamedTempFile::new().expect("tmp");
    std::fs::write(outside.path(), "hello\n").expect("write");
    let link = dir.path().join("outside-link.txt");
    symlink(outside.path(), &link).expect("symlink");

    let ctx = Context::new(test_policy(dir.path(), RootMode::ReadWrite)).expect("ctx");
    delete_file(
        &ctx,
        DeleteRequest {
            root_id: "root".to_string(),
            path: PathBuf::from("outside-link.txt"),
        },
    )
    .expect("delete");

    assert!(!link.exists());
    assert!(outside.path().exists());
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
    };

    let err = Context::new(policy).expect_err("should reject");
    match err {
        safe_fs_tools::Error::InvalidPolicy(msg) => {
            assert!(msg.contains("root.path must be absolute"))
        }
        other => panic!("unexpected error: {other:?}"),
    }
}

#[test]
fn policy_rejects_invalid_redact_regexes() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut policy = test_policy(dir.path(), RootMode::ReadOnly);
    policy.secrets.redact_regexes = vec!["[".to_string()];

    let err = Context::new(policy).expect_err("should reject");
    match err {
        safe_fs_tools::Error::InvalidPolicy(msg) => assert!(msg.contains("secrets.redact_regexes")),
        other => panic!("unexpected error: {other:?}"),
    }
}

#[test]
fn policy_rejects_zero_max_patch_bytes() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut policy = test_policy(dir.path(), RootMode::ReadOnly);
    policy.limits.max_patch_bytes = Some(0);

    let err = Context::new(policy).expect_err("should reject");
    match err {
        safe_fs_tools::Error::InvalidPolicy(msg) => {
            assert!(msg.contains("limits.max_patch_bytes must be > 0"))
        }
        other => panic!("unexpected error: {other:?}"),
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
    };

    let err = Context::new(policy).expect_err("should reject");
    match err {
        safe_fs_tools::Error::InvalidPolicy(msg) => assert!(msg.contains("is not a directory")),
        other => panic!("unexpected error: {other:?}"),
    }
}

#[test]
#[cfg(feature = "grep")]
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

#[test]
#[cfg(all(unix, feature = "glob", feature = "grep"))]
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
#[cfg(feature = "glob")]
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
}

#[test]
#[cfg(feature = "grep")]
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
}

#[test]
#[cfg(windows)]
fn deny_globs_match_backslash_separators() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::create_dir_all(dir.path().join(".git")).expect("mkdir");
    std::fs::write(dir.path().join(".git").join("config"), "secret").expect("write");

    let ctx = Context::new(test_policy(dir.path(), RootMode::ReadOnly)).expect("ctx");
    let err = read_file(
        &ctx,
        ReadRequest {
            root_id: "root".to_string(),
            path: PathBuf::from(r".git\config"),
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
