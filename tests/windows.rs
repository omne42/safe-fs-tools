#![cfg(windows)]

mod common;

use std::path::PathBuf;

use common::test_policy;
use safe_fs_tools::ops::{Context, ReadRequest, read_file};
use safe_fs_tools::policy::{RootMode, SandboxPolicy};

#[cfg(feature = "glob")]
use safe_fs_tools::ops::{GlobRequest, glob_paths};

#[test]
fn deny_globs_apply_to_absolute_paths_even_when_parent_is_missing() {
    let dir = tempfile::tempdir().expect("tempdir");

    let mut policy = test_policy(dir.path(), RootMode::ReadOnly);
    policy.secrets.deny_globs = vec!["missing/**".to_string()];
    let ctx = Context::new(policy).expect("ctx");

    let mut root = dir.path().to_string_lossy().into_owned();
    let original_root = root.clone();
    let mut did_toggle = false;
    let drive_letter_index = if root.starts_with(r"\\?\") && root.len() >= 5 {
        Some(4)
    } else if root.len() >= 2 && root.as_bytes()[1] == b':' {
        Some(0)
    } else if root.starts_with(r"\\") && root.len() >= 3 {
        Some(2)
    } else {
        None
    };

    if let Some(idx) = drive_letter_index {
        if let Some(ch) = root.as_bytes().get(idx).copied().map(|b| b as char)
            && ch.is_ascii_alphabetic()
        {
            let new_ch = if ch.is_ascii_lowercase() {
                ch.to_ascii_uppercase()
            } else {
                ch.to_ascii_lowercase()
            };
            root.replace_range(idx..idx + 1, &new_ch.to_string());
            did_toggle = true;
        }
    }

    if !did_toggle {
        if let Some((idx, ch)) = root
            .char_indices()
            .find(|(_idx, ch)| ch.is_ascii_alphabetic())
        {
            let new_ch = if ch.is_ascii_lowercase() {
                ch.to_ascii_uppercase()
            } else {
                ch.to_ascii_lowercase()
            };
            root.replace_range(idx..idx + 1, &new_ch.to_string());
            did_toggle = true;
        }
    }

    assert_ne!(root, original_root, "expected to toggle root path casing");

    let abs = PathBuf::from(root).join("missing").join("file.txt");
    let err = read_file(
        &ctx,
        ReadRequest {
            root_id: "root".to_string(),
            path: abs,
            start_line: None,
            end_line: None,
        },
    )
    .expect_err("should reject");

    match err {
        safe_fs_tools::Error::SecretPathDenied(path) => {
            assert_eq!(path, PathBuf::from("missing").join("file.txt"));
        }
        other => panic!("unexpected error: {other:?}"),
    }
}

#[test]
fn resolve_path_rejects_drive_relative_paths() {
    use std::path::Path;

    let dir = tempfile::tempdir().expect("tempdir");
    let policy = SandboxPolicy::single_root("root", dir.path(), RootMode::ReadOnly);
    let err = policy
        .resolve_path("root", Path::new("C:foo"))
        .expect_err("should reject");

    match err {
        safe_fs_tools::Error::InvalidPath(_) => {}
        other => panic!("unexpected error: {other:?}"),
    }
}

#[test]
fn resolve_path_rejects_colon_paths_on_windows() {
    use std::path::Path;

    let dir = tempfile::tempdir().expect("tempdir");
    let policy = SandboxPolicy::single_root("root", dir.path(), RootMode::ReadOnly);
    let err = policy
        .resolve_path("root", Path::new("file.txt::$DATA"))
        .expect_err("should reject");

    match err {
        safe_fs_tools::Error::InvalidPath(_) => {}
        other => panic!("unexpected error: {other:?}"),
    }
}

#[test]
fn deny_globs_match_backslash_separators() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::create_dir_all(dir.path().join(".git")).expect("mkdir");
    std::fs::write(dir.path().join(".git").join("config"), "secret").expect("write");

    let mut policy = test_policy(dir.path(), RootMode::ReadOnly);
    policy.secrets.deny_globs = vec![".git/**".to_string()];
    let ctx = Context::new(policy).expect("ctx");
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

#[test]
fn deny_globs_are_case_insensitive_on_windows() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::create_dir_all(dir.path().join(".git")).expect("mkdir");
    std::fs::write(dir.path().join(".git").join("config"), "secret").expect("write");

    let mut policy = test_policy(dir.path(), RootMode::ReadOnly);
    policy.secrets.deny_globs = vec![".GIT/**".to_string()];
    let ctx = Context::new(policy).expect("ctx");
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

#[test]
#[cfg(feature = "glob")]
fn glob_patterns_are_case_insensitive_on_windows() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(dir.path().join("a.txt"), "a\n").expect("write");

    let ctx = Context::new(test_policy(dir.path(), RootMode::ReadOnly)).expect("ctx");
    let resp = glob_paths(
        &ctx,
        GlobRequest {
            root_id: "root".to_string(),
            pattern: "A.TXT".to_string(),
        },
    )
    .expect("glob");

    assert_eq!(resp.matches, vec![PathBuf::from("a.txt")]);
}

#[test]
#[cfg(feature = "glob")]
fn traversal_skip_globs_are_case_insensitive_on_windows() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::create_dir_all(dir.path().join(".git")).expect("mkdir");
    std::fs::write(dir.path().join(".git").join("config"), "secret").expect("write");

    let mut policy = test_policy(dir.path(), RootMode::ReadOnly);
    policy.traversal.skip_globs = vec![".GIT/**".to_string()];
    let ctx = Context::new(policy).expect("ctx");

    let resp = glob_paths(
        &ctx,
        GlobRequest {
            root_id: "root".to_string(),
            pattern: "**/*".to_string(),
        },
    )
    .expect("glob");

    assert!(
        !resp
            .matches
            .iter()
            .any(|path| path == PathBuf::from(".git/config")),
        "expected traversal.skip_globs to exclude .git/config: {:?}",
        resp.matches
    );
}
