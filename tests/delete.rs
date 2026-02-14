mod common;

use std::path::PathBuf;

use common::test_policy;
use safe_fs_tools::ops::{Context, DeleteRequest, delete};
use safe_fs_tools::policy::RootMode;

#[test]
fn delete_absolute_paths_report_relative_requested_path_when_parent_is_missing() {
    let dir = tempfile::tempdir().expect("tempdir");
    let ctx = Context::new(test_policy(dir.path(), RootMode::ReadWrite)).expect("ctx");

    let abs = dir.path().join("missing").join("file.txt");
    let err = delete(
        &ctx,
        DeleteRequest {
            root_id: "root".to_string(),
            path: abs,
            recursive: false,
            ignore_missing: false,
        },
    )
    .expect_err("should reject");

    match err {
        safe_fs_tools::Error::IoPath { op, path, .. } => {
            assert_eq!(op, "metadata");
            assert_eq!(path, PathBuf::from("missing"));
        }
        other => panic!("unexpected error: {other:?}"),
    }
}

#[test]
fn delete_absolute_paths_report_relative_requested_path_when_leaf_is_missing() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::create_dir_all(dir.path().join("parent")).expect("mkdir");
    let ctx = Context::new(test_policy(dir.path(), RootMode::ReadWrite)).expect("ctx");

    let abs = dir.path().join("parent").join("missing.txt");
    let err = delete(
        &ctx,
        DeleteRequest {
            root_id: "root".to_string(),
            path: abs,
            recursive: false,
            ignore_missing: false,
        },
    )
    .expect_err("should reject");

    match err {
        safe_fs_tools::Error::IoPath { op, path, .. } => {
            assert_eq!(op, "metadata");
            assert_eq!(path, PathBuf::from("parent").join("missing.txt"));
        }
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
    let resp = delete(
        &ctx,
        DeleteRequest {
            root_id: "root".to_string(),
            path: PathBuf::from("link.txt"),
            recursive: false,
            ignore_missing: false,
        },
    )
    .expect("delete");
    assert_eq!(resp.path, PathBuf::from("link.txt"));
    assert_eq!(resp.requested_path, Some(PathBuf::from("link.txt")));
    assert!(resp.deleted);
    assert_eq!(resp.kind, "symlink");

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
    let resp = delete(
        &ctx,
        DeleteRequest {
            root_id: "root".to_string(),
            path: PathBuf::from("outside-link.txt"),
            recursive: false,
            ignore_missing: false,
        },
    )
    .expect("delete");
    assert_eq!(resp.path, PathBuf::from("outside-link.txt"));
    assert_eq!(resp.requested_path, Some(PathBuf::from("outside-link.txt")));
    assert!(resp.deleted);
    assert_eq!(resp.kind, "symlink");

    assert!(!link.exists());
    assert!(outside.path().exists());
}

#[test]
#[cfg(unix)]
fn delete_denies_requested_path_before_resolving_symlink_dirs() {
    use std::os::unix::fs::symlink;

    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::create_dir_all(dir.path().join("allowed")).expect("mkdir");
    std::fs::write(dir.path().join("allowed").join("file.txt"), "hello\n").expect("write");
    symlink(dir.path().join("allowed"), dir.path().join("deny")).expect("symlink dir");

    let mut policy = test_policy(dir.path(), RootMode::ReadWrite);
    policy.secrets.deny_globs = vec!["deny/**".to_string()];
    let ctx = Context::new(policy).expect("ctx");

    let err = delete(
        &ctx,
        DeleteRequest {
            root_id: "root".to_string(),
            path: PathBuf::from("deny/file.txt"),
            recursive: false,
            ignore_missing: false,
        },
    )
    .expect_err("should reject");

    match err {
        safe_fs_tools::Error::SecretPathDenied(path) => {
            assert_eq!(path, PathBuf::from("deny/file.txt"));
        }
        other => panic!("unexpected error: {other:?}"),
    }

    assert!(
        dir.path().join("allowed").join("file.txt").exists(),
        "expected file to remain after denied delete"
    );
}

#[test]
#[cfg(unix)]
fn delete_denies_after_canonicalization_when_symlink_parent_points_to_denied_path() {
    use std::os::unix::fs::symlink;

    let dir = tempfile::tempdir().expect("tempdir");
    let denied_dir = dir.path().join("denied_dir");
    std::fs::create_dir_all(&denied_dir).expect("mkdir denied dir");
    std::fs::write(denied_dir.join("file.txt"), "secret\n").expect("write");
    symlink(&denied_dir, dir.path().join("allowed_link")).expect("symlink dir");

    let mut policy = test_policy(dir.path(), RootMode::ReadWrite);
    policy.secrets.deny_globs = vec!["denied_dir/**".to_string()];
    let ctx = Context::new(policy).expect("ctx");

    let err = delete(
        &ctx,
        DeleteRequest {
            root_id: "root".to_string(),
            path: PathBuf::from("allowed_link/file.txt"),
            recursive: false,
            ignore_missing: false,
        },
    )
    .expect_err("should reject");

    match err {
        safe_fs_tools::Error::SecretPathDenied(path) => {
            assert_eq!(path, PathBuf::from("denied_dir/file.txt"));
        }
        other => panic!("unexpected error: {other:?}"),
    }

    assert!(
        denied_dir.join("file.txt").exists(),
        "expected denied canonical target to remain after rejected delete"
    );
}

#[test]
fn delete_is_not_allowed_on_readonly_root() {
    let dir = tempfile::tempdir().expect("tempdir");
    let file = dir.path().join("file.txt");
    std::fs::write(&file, "keep\n").expect("write");
    let ctx = Context::new(test_policy(dir.path(), RootMode::ReadOnly)).expect("ctx");

    let err = delete(
        &ctx,
        DeleteRequest {
            root_id: "root".to_string(),
            path: PathBuf::from("file.txt"),
            recursive: false,
            ignore_missing: false,
        },
    )
    .expect_err("should reject");

    match err {
        safe_fs_tools::Error::NotPermitted(_) => {}
        other => panic!("unexpected error: {other:?}"),
    }

    assert!(
        file.exists(),
        "readonly-root delete rejection must not remove files"
    );
}

#[test]
fn delete_rejects_dot_and_empty_paths() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sentinel = dir.path().join("sentinel.txt");
    std::fs::write(&sentinel, "keep\n").expect("write sentinel");
    let ctx = Context::new(test_policy(dir.path(), RootMode::ReadWrite)).expect("ctx");

    let err = delete(
        &ctx,
        DeleteRequest {
            root_id: "root".to_string(),
            path: PathBuf::from("."),
            recursive: false,
            ignore_missing: false,
        },
    )
    .expect_err("should reject");

    match err {
        safe_fs_tools::Error::InvalidPath(message) => {
            assert!(message.contains("refusing to delete the root directory"));
        }
        other => panic!("unexpected error: {other:?}"),
    }

    let err = delete(
        &ctx,
        DeleteRequest {
            root_id: "root".to_string(),
            path: PathBuf::from(""),
            recursive: false,
            ignore_missing: false,
        },
    )
    .expect_err("should reject");

    match err {
        safe_fs_tools::Error::InvalidPath(message) => {
            assert!(message.contains("path is empty"));
        }
        other => panic!("unexpected error: {other:?}"),
    }

    assert!(
        sentinel.exists(),
        "rejecting dot/empty path must not delete files"
    );
    assert_eq!(
        std::fs::read_to_string(&sentinel).expect("read sentinel"),
        "keep\n",
        "rejecting dot/empty path must not mutate unrelated files"
    );
}

#[test]
fn delete_rejects_directories_without_recursive() {
    let dir = tempfile::tempdir().expect("tempdir");
    let subdir = dir.path().join("subdir");
    std::fs::create_dir_all(&subdir).expect("mkdir");

    let ctx = Context::new(test_policy(dir.path(), RootMode::ReadWrite)).expect("ctx");

    let err = delete(
        &ctx,
        DeleteRequest {
            root_id: "root".to_string(),
            path: PathBuf::from("subdir"),
            recursive: false,
            ignore_missing: false,
        },
    )
    .expect_err("should reject");

    match err {
        safe_fs_tools::Error::InvalidPath(message) => {
            assert!(message.contains("recursive=true"));
        }
        other => panic!("unexpected error: {other:?}"),
    }

    assert!(
        subdir.exists(),
        "rejecting non-recursive delete must keep directory"
    );
}

#[test]
#[cfg(unix)]
fn delete_revalidate_parent_detects_path_change() {
    use std::os::unix::fs::symlink;
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };

    let dir = tempfile::tempdir().expect("tempdir");
    let dir_a = dir.path().join("dir_a");
    let dir_b = dir.path().join("dir_b");
    std::fs::create_dir_all(dir_a.join("subdir")).expect("mkdir dir_a/subdir");
    std::fs::create_dir_all(dir_b.join("subdir")).expect("mkdir dir_b/subdir");

    let pivot = dir.path().join("pivot");
    symlink(&dir_a, &pivot).expect("symlink pivot");

    let ctx = Context::new(test_policy(dir.path(), RootMode::ReadWrite)).expect("ctx");

    let keep_flapping = Arc::new(AtomicBool::new(true));
    let keep_flapping_bg = Arc::clone(&keep_flapping);
    let pivot_bg = pivot.clone();
    let dir_a_bg = dir_a.clone();
    let dir_b_bg = dir_b.clone();
    let toggler = std::thread::spawn(move || {
        while keep_flapping_bg.load(Ordering::Relaxed) {
            let _ = std::fs::remove_file(&pivot_bg);
            let _ = symlink(&dir_b_bg, &pivot_bg);
            std::thread::yield_now();
            let _ = std::fs::remove_file(&pivot_bg);
            let _ = symlink(&dir_a_bg, &pivot_bg);
            std::thread::yield_now();
        }
    });

    let mut observed_changed = false;
    for _ in 0..4_000 {
        let err = delete(
            &ctx,
            DeleteRequest {
                root_id: "root".to_string(),
                path: PathBuf::from("pivot/subdir"),
                recursive: false,
                ignore_missing: false,
            },
        )
        .expect_err("should reject");

        match err {
            safe_fs_tools::Error::InvalidPath(message)
                if message.contains("changed during delete") =>
            {
                observed_changed = true;
                break;
            }
            safe_fs_tools::Error::InvalidPath(message) if message.contains("recursive=true") => {}
            safe_fs_tools::Error::IoPath { op, .. } if op == "metadata" => {}
            other => panic!("unexpected error: {other:?}"),
        }
    }

    keep_flapping.store(false, Ordering::Relaxed);
    toggler.join().expect("join toggler");

    assert!(
        observed_changed,
        "expected to observe revalidation failure for path change"
    );
}

#[test]
#[cfg(unix)]
fn delete_revalidate_parent_returns_missing_when_ignore_missing_is_true() {
    use std::os::unix::fs::symlink;
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };

    let dir = tempfile::tempdir().expect("tempdir");
    let actual_parent = dir.path().join("actual_parent");
    std::fs::create_dir_all(actual_parent.join("subdir")).expect("mkdir actual_parent/subdir");

    let pivot = dir.path().join("pivot");
    symlink(&actual_parent, &pivot).expect("symlink pivot");

    let ctx = Context::new(test_policy(dir.path(), RootMode::ReadWrite)).expect("ctx");

    let keep_flapping = Arc::new(AtomicBool::new(true));
    let keep_flapping_bg = Arc::clone(&keep_flapping);
    let pivot_bg = pivot.clone();
    let actual_parent_bg = actual_parent.clone();
    let toggler = std::thread::spawn(move || {
        while keep_flapping_bg.load(Ordering::Relaxed) {
            let _ = std::fs::remove_file(&pivot_bg);
            std::thread::sleep(std::time::Duration::from_millis(1));
            let _ = symlink(&actual_parent_bg, &pivot_bg);
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
    });

    let mut observed_missing = None;
    for _ in 0..2_000 {
        match delete(
            &ctx,
            DeleteRequest {
                root_id: "root".to_string(),
                path: PathBuf::from("pivot/subdir"),
                recursive: false,
                ignore_missing: true,
            },
        ) {
            Ok(resp) if resp.kind == "missing" => {
                observed_missing = Some(resp);
                break;
            }
            Err(safe_fs_tools::Error::InvalidPath(message))
                if message.contains("recursive=true") => {}
            Err(safe_fs_tools::Error::IoPath { op, .. }) if op == "metadata" => {}
            other => panic!("unexpected result: {other:?}"),
        }
    }

    keep_flapping.store(false, Ordering::Relaxed);
    toggler.join().expect("join toggler");

    let resp = observed_missing.expect("expected ignore_missing response when parent disappears");
    assert_eq!(resp.path, PathBuf::from("pivot/subdir"));
    assert_eq!(resp.requested_path, Some(PathBuf::from("pivot/subdir")));
    assert!(!resp.deleted);
    assert_eq!(resp.kind, "missing");
    assert!(
        actual_parent.join("subdir").is_dir(),
        "missing response must not remove existing directories"
    );
}

#[test]
fn delete_ignore_missing_returns_missing_when_parent_directory_is_absent() {
    let dir = tempfile::tempdir().expect("tempdir");
    let ctx = Context::new(test_policy(dir.path(), RootMode::ReadWrite)).expect("ctx");

    let resp = delete(
        &ctx,
        DeleteRequest {
            root_id: "root".to_string(),
            path: PathBuf::from("missing").join("file.txt"),
            recursive: false,
            ignore_missing: true,
        },
    )
    .expect("ignore_missing should return missing response");

    assert_eq!(resp.path, PathBuf::from("missing").join("file.txt"));
    assert_eq!(
        resp.requested_path,
        Some(PathBuf::from("missing").join("file.txt"))
    );
    assert!(!resp.deleted);
    assert_eq!(resp.kind, "missing");
}
