#![cfg(any(feature = "glob", feature = "grep"))]

mod common;

use std::path::PathBuf;

use common::test_policy;
use safe_fs_tools::ops::Context;
use safe_fs_tools::policy::RootMode;

fn setup_skip_glob_fixture() -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::create_dir_all(dir.path().join("node_modules")).expect("mkdir");
    std::fs::write(dir.path().join("keep.txt"), "needle\n").expect("write");
    std::fs::write(dir.path().join("node_modules").join("skip.txt"), "needle\n").expect("write");
    dir
}

#[cfg(feature = "grep")]
fn assert_skip_glob_applies_to_grep_but_not_direct_read(skip_pattern: &str) {
    use safe_fs_tools::ops::{GrepRequest, ReadRequest, grep, read_file};

    let dir = setup_skip_glob_fixture();

    let mut policy = test_policy(dir.path(), RootMode::ReadOnly);
    policy.traversal.skip_globs = vec![skip_pattern.to_string()];
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

#[cfg(feature = "glob")]
fn assert_skip_glob_applies_to_glob_paths(skip_pattern: &str) {
    use safe_fs_tools::ops::{GlobRequest, glob_paths};

    let dir = setup_skip_glob_fixture();

    let mut policy = test_policy(dir.path(), RootMode::ReadOnly);
    policy.traversal.skip_globs = vec![skip_pattern.to_string()];
    let ctx = Context::new(policy).expect("ctx");

    let resp = glob_paths(
        &ctx,
        GlobRequest {
            root_id: "root".to_string(),
            pattern: "**/*".to_string(),
        },
    )
    .expect("glob");

    let blocked = PathBuf::from("node_modules").join("skip.txt");
    assert!(
        !resp.matches.iter().any(|path| path == &blocked),
        "expected traversal.skip_globs to exclude node_modules/skip.txt: {:?}",
        resp.matches
    );
    assert!(
        resp.matches
            .iter()
            .any(|path| path == &PathBuf::from("keep.txt")),
        "expected keep.txt to remain visible in traversal result: {:?}",
        resp.matches
    );
}

#[test]
#[cfg(feature = "grep")]
fn traversal_skip_globs_support_leading_dot_slash() {
    assert_skip_glob_applies_to_grep_but_not_direct_read("./node_modules/**");
}

#[test]
fn traversal_skip_globs_reject_absolute_and_parent_segments() {
    let dir = tempfile::tempdir().expect("tempdir");

    for pattern in ["/node_modules/**", "../**/*.txt", "src/../*.txt"] {
        let mut policy = test_policy(dir.path(), RootMode::ReadOnly);
        policy.traversal.skip_globs = vec![pattern.to_string()];
        let err = Context::new(policy).expect_err("should reject");

        match err {
            safe_fs_tools::Error::InvalidPolicy(message) => {
                assert!(
                    message.contains("invalid traversal.skip_globs glob"),
                    "unexpected invalid policy message for pattern {pattern:?}: {message}"
                );
                assert!(
                    message.contains(pattern),
                    "expected invalid policy message to include pattern {pattern:?}: {message}"
                );
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }
}

#[test]
#[cfg(feature = "grep")]
fn traversal_skip_globs_skip_in_traversal_but_allow_direct_read() {
    assert_skip_glob_applies_to_grep_but_not_direct_read("node_modules/**");
}

#[test]
#[cfg(feature = "glob")]
fn traversal_skip_globs_apply_to_glob_paths_with_and_without_leading_dot_slash() {
    for skip_pattern in ["./node_modules/**", "node_modules/**"] {
        assert_skip_glob_applies_to_glob_paths(skip_pattern);
    }
}
