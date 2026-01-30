#![cfg(any(feature = "glob", feature = "grep"))]

mod common;

use common::test_policy;
use safe_fs_tools::ops::Context;
use safe_fs_tools::policy::RootMode;

#[test]
#[cfg(feature = "grep")]
fn traversal_skip_globs_support_leading_dot_slash() {
    use std::path::PathBuf;

    use safe_fs_tools::ops::{GrepRequest, ReadRequest, grep, read_file};

    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::create_dir_all(dir.path().join("node_modules")).expect("mkdir");
    std::fs::write(dir.path().join("keep.txt"), "needle\n").expect("write");
    std::fs::write(dir.path().join("node_modules").join("skip.txt"), "needle\n").expect("write");

    let mut policy = test_policy(dir.path(), RootMode::ReadOnly);
    policy.traversal.skip_globs = vec!["./node_modules/**".to_string()];
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
#[cfg(any(feature = "glob", feature = "grep"))]
fn traversal_skip_globs_reject_absolute_and_parent_segments() {
    let dir = tempfile::tempdir().expect("tempdir");

    for pattern in ["/node_modules/**", "../**/*.txt", "src/../*.txt"] {
        let mut policy = test_policy(dir.path(), RootMode::ReadOnly);
        policy.traversal.skip_globs = vec![pattern.to_string()];
        let err = Context::new(policy).expect_err("should reject");

        match err {
            safe_fs_tools::Error::InvalidPolicy(_) => {}
            other => panic!("unexpected error: {other:?}"),
        }
    }
}

#[test]
#[cfg(feature = "grep")]
fn traversal_skip_globs_skip_in_traversal_but_allow_direct_read() {
    use std::path::PathBuf;

    use safe_fs_tools::ops::{GrepRequest, ReadRequest, grep, read_file};

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
