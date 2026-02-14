mod common;
#[cfg(unix)]
#[path = "common/unix_helpers.rs"]
mod unix_helpers;

use std::path::PathBuf;

use common::test_policy;
use safe_fs_tools::ops::{Context, ReadRequest, read_file};
use safe_fs_tools::policy::RootMode;

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
    assert!(response.content.contains("hello"));
}

#[test]
fn read_absolute_paths_return_root_relative_requested_path() {
    let dir = tempfile::tempdir().expect("tempdir");
    let abs_path = dir.path().join("hello.txt");
    std::fs::write(&abs_path, "hello\n").expect("write");

    let ctx = Context::new(test_policy(dir.path(), RootMode::ReadOnly)).expect("ctx");
    let response = read_file(
        &ctx,
        ReadRequest {
            root_id: "root".to_string(),
            path: abs_path,
            start_line: None,
            end_line: None,
        },
    )
    .expect("read");

    assert_eq!(response.path, PathBuf::from("hello.txt"));
    assert_eq!(response.requested_path, Some(PathBuf::from("hello.txt")));
}

#[test]
fn absolute_paths_can_be_disabled_by_policy() {
    let dir = tempfile::tempdir().expect("tempdir");
    let abs_path = dir.path().join("hello.txt");
    std::fs::write(&abs_path, "hello\n").expect("write");

    let mut policy = test_policy(dir.path(), RootMode::ReadOnly);
    policy.paths.allow_absolute = false;
    let ctx = Context::new(policy).expect("ctx");
    let err = read_file(
        &ctx,
        ReadRequest {
            root_id: "root".to_string(),
            path: abs_path,
            start_line: None,
            end_line: None,
        },
    )
    .expect_err("should reject");

    match err {
        safe_fs_tools::Error::InvalidPath(message) => {
            assert!(message.contains("absolute request paths"));
        }
        other => panic!("unexpected error: {other:?}"),
    }
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
    assert!(response.content.contains("hello"));
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
        safe_fs_tools::Error::OutsideRoot { path, .. } => {
            assert!(path.is_absolute());
            assert_eq!(path, outside.path());
        }
        other => panic!("unexpected error: {other:?}"),
    }
}

#[test]
fn read_rejects_missing_absolute_paths_outside_root_as_outside_root() {
    let dir = tempfile::tempdir().expect("tempdir");
    let outside = tempfile::tempdir().expect("outside");
    let missing = outside.path().join("missing.txt");

    let ctx = Context::new(test_policy(dir.path(), RootMode::ReadOnly)).expect("ctx");
    let err = read_file(
        &ctx,
        ReadRequest {
            root_id: "root".to_string(),
            path: missing,
            start_line: None,
            end_line: None,
        },
    )
    .expect_err("should reject");

    match err {
        safe_fs_tools::Error::OutsideRoot { path, .. } => {
            assert!(path.is_absolute());
            assert_eq!(path, outside.path().join("missing.txt"));
        }
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
        safe_fs_tools::Error::OutsideRoot { path, .. } => {
            assert_eq!(path, PathBuf::from("link.txt"));
        }
        other => panic!("unexpected error: {other:?}"),
    }
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
fn read_supports_line_ranges_without_trailing_newline() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("lines.txt");
    std::fs::write(&path, "one\ntwo\nthree").expect("write");

    let ctx = Context::new(test_policy(dir.path(), RootMode::ReadOnly)).expect("ctx");
    let response = read_file(
        &ctx,
        ReadRequest {
            root_id: "root".to_string(),
            path: PathBuf::from("lines.txt"),
            start_line: Some(3),
            end_line: Some(3),
        },
    )
    .expect("read");

    assert_eq!(response.content, "three");
    assert_eq!(response.start_line, Some(3));
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
#[cfg(unix)]
fn read_rejects_fifo_special_files() {
    let dir = tempfile::tempdir().expect("tempdir");
    let fifo = dir.path().join("pipe");
    unix_helpers::create_fifo(&fifo);

    let mut policy = test_policy(dir.path(), RootMode::ReadOnly);
    policy.limits.max_read_bytes = 8;
    let ctx = Context::new(policy).expect("ctx");

    let err = read_file(
        &ctx,
        ReadRequest {
            root_id: "root".to_string(),
            path: PathBuf::from("pipe"),
            start_line: None,
            end_line: None,
        },
    )
    .expect_err("should reject");

    match err {
        safe_fs_tools::Error::InvalidPath(_) => {}
        other => panic!("unexpected error: {other:?}"),
    }
}

#[test]
#[cfg(unix)]
fn read_line_ranges_reject_fifo_special_files() {
    let dir = tempfile::tempdir().expect("tempdir");
    let fifo = dir.path().join("pipe");
    unix_helpers::create_fifo(&fifo);

    let ctx = Context::new(test_policy(dir.path(), RootMode::ReadOnly)).expect("ctx");

    let err = read_file(
        &ctx,
        ReadRequest {
            root_id: "root".to_string(),
            path: PathBuf::from("pipe"),
            start_line: Some(1),
            end_line: Some(1),
        },
    )
    .expect_err("should reject");

    match err {
        safe_fs_tools::Error::InvalidPath(_) => {}
        other => panic!("unexpected error: {other:?}"),
    }
}

#[test]
fn read_rejects_incomplete_line_ranges() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(dir.path().join("file.txt"), "one\ntwo\n").expect("write");

    let ctx = Context::new(test_policy(dir.path(), RootMode::ReadOnly)).expect("ctx");

    let err = read_file(
        &ctx,
        ReadRequest {
            root_id: "root".to_string(),
            path: PathBuf::from("file.txt"),
            start_line: Some(1),
            end_line: None,
        },
    )
    .expect_err("should reject");
    match err {
        safe_fs_tools::Error::InvalidPath(message) => {
            assert!(message.contains("must be provided together"));
        }
        other => panic!("unexpected error: {other:?}"),
    }

    let err = read_file(
        &ctx,
        ReadRequest {
            root_id: "root".to_string(),
            path: PathBuf::from("file.txt"),
            start_line: None,
            end_line: Some(1),
        },
    )
    .expect_err("should reject");
    match err {
        safe_fs_tools::Error::InvalidPath(message) => {
            assert!(message.contains("must be provided together"));
        }
        other => panic!("unexpected error: {other:?}"),
    }
}

#[test]
fn read_rejects_invalid_line_ranges() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(dir.path().join("file.txt"), "one\ntwo\n").expect("write");

    let ctx = Context::new(test_policy(dir.path(), RootMode::ReadOnly)).expect("ctx");

    let err = read_file(
        &ctx,
        ReadRequest {
            root_id: "root".to_string(),
            path: PathBuf::from("file.txt"),
            start_line: Some(0),
            end_line: Some(1),
        },
    )
    .expect_err("should reject");
    match err {
        safe_fs_tools::Error::InvalidPath(message) => {
            assert!(message.contains("invalid line range"));
        }
        other => panic!("unexpected error: {other:?}"),
    }

    let err = read_file(
        &ctx,
        ReadRequest {
            root_id: "root".to_string(),
            path: PathBuf::from("file.txt"),
            start_line: Some(2),
            end_line: Some(1),
        },
    )
    .expect_err("should reject");
    match err {
        safe_fs_tools::Error::InvalidPath(message) => {
            assert!(message.contains("invalid line range"));
        }
        other => panic!("unexpected error: {other:?}"),
    }
}

#[test]
fn read_line_ranges_reject_out_of_bounds_requests() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(dir.path().join("file.txt"), "one\ntwo\n").expect("write");

    let ctx = Context::new(test_policy(dir.path(), RootMode::ReadOnly)).expect("ctx");

    let err = read_file(
        &ctx,
        ReadRequest {
            root_id: "root".to_string(),
            path: PathBuf::from("file.txt"),
            start_line: Some(1),
            end_line: Some(3),
        },
    )
    .expect_err("should reject");
    match err {
        safe_fs_tools::Error::InvalidPath(message) => {
            assert!(message.contains("line range"));
            assert!(message.contains("out of bounds"));
        }
        other => panic!("unexpected error: {other:?}"),
    }
}
