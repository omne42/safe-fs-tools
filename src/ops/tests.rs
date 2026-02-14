use std::fs;
use std::path::{Path, PathBuf};

use crate::policy::RootMode;

use super::*;

#[test]
#[cfg(unix)]
fn open_private_temp_file_creates_files_without_group_or_other_access() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("tmp.txt");
    drop(io::open_private_temp_file(&path).expect("open"));
    let mode = fs::metadata(&path).expect("metadata").permissions().mode() & 0o777;
    assert_eq!(mode & 0o077, 0, "expected no group/other permission bits");

    let err = io::open_private_temp_file(&path).expect_err("create_new must fail on existing path");
    assert_eq!(
        err.kind(),
        std::io::ErrorKind::AlreadyExists,
        "unexpected error for second create: {err:?}"
    );
}

#[test]
#[cfg(any(feature = "glob", feature = "grep"))]
fn derive_safe_traversal_prefix_is_conservative() {
    struct Case {
        name: &'static str,
        pattern: &'static str,
        expected: Option<&'static str>,
    }

    let base_cases = [
        Case {
            name: "relative_glob",
            pattern: "src/**/*.rs",
            expected: Some("src"),
        },
        Case {
            name: "relative_dot_prefix",
            pattern: "./src/**/*.rs",
            expected: Some("src"),
        },
        Case {
            name: "single_segment_wildcard",
            pattern: "src/*",
            expected: Some("src"),
        },
        Case {
            name: "concrete_file_path",
            pattern: "src/lib.rs",
            expected: Some("src/lib.rs"),
        },
        Case {
            name: "globstar_without_prefix",
            pattern: "**/*.rs",
            expected: None,
        },
        Case {
            name: "parent_escape",
            pattern: "../**/*.rs",
            expected: None,
        },
        Case {
            name: "absolute_path",
            pattern: "/etc/*",
            expected: None,
        },
    ];
    for case in base_cases {
        assert_eq!(
            traversal::derive_safe_traversal_prefix(case.pattern),
            case.expected.map(PathBuf::from),
            "case {} failed for pattern {:?}",
            case.name,
            case.pattern
        );
    }
    #[cfg(windows)]
    {
        let windows_cases = [
            Case {
                name: "drive_absolute_path",
                pattern: "C:/foo/*",
                expected: None,
            },
            Case {
                name: "drive_relative_path",
                pattern: "c:foo/*",
                expected: None,
            },
            Case {
                name: "drive_only",
                pattern: "C:",
                expected: None,
            },
            Case {
                name: "backslash_glob",
                pattern: r"src\**\*.rs",
                expected: Some("src"),
            },
            Case {
                name: "backslash_glob_with_dot_prefix",
                pattern: r".\src\**\*.rs",
                expected: Some("src"),
            },
            Case {
                name: "backslash_parent_escape",
                pattern: r"src\..\*",
                expected: None,
            },
            Case {
                name: "backslash_nested_parent_escape",
                pattern: r"src\foo\..\*.rs",
                expected: None,
            },
            Case {
                name: "embedded_drive_segment",
                pattern: "src/c:foo/*",
                expected: None,
            },
            Case {
                name: "embedded_drive_segment_nested",
                pattern: "a/b/c:tmp/**",
                expected: None,
            },
        ];
        for case in windows_cases {
            assert_eq!(
                traversal::derive_safe_traversal_prefix(case.pattern),
                case.expected.map(PathBuf::from),
                "case {} failed for pattern {:?}",
                case.name,
                case.pattern
            );
        }
    }
}

#[test]
#[cfg(any(feature = "glob", feature = "grep"))]
fn walk_traversal_files_rejects_walk_root_outside_root() {
    use std::cell::Cell;
    use std::time::Instant;

    let dir = tempfile::tempdir().expect("tempdir");
    let policy = SandboxPolicy::single_root("root", dir.path(), RootMode::ReadOnly);
    let ctx = Context::new(policy).expect("ctx");

    let root_path = ctx.canonical_root("root").expect("root").to_path_buf();
    let walk_root = root_path.parent().expect("parent").to_path_buf();
    let callback_count = Cell::new(0_u32);

    let err = traversal::walk_traversal_files(
        &ctx,
        "root",
        &root_path,
        &walk_root,
        &Instant::now(),
        None,
        |_file, _diag| {
            callback_count.set(callback_count.get().saturating_add(1));
            Ok(std::ops::ControlFlow::Continue(()))
        },
    )
    .unwrap_err();

    assert_eq!(err.code(), "invalid_path");
    assert_eq!(
        callback_count.get(),
        0,
        "walk callback must not run for invalid traversal roots"
    );
}

#[test]
#[cfg(any(feature = "glob", feature = "grep"))]
fn traversal_skip_globs_apply_to_directories_via_probe() {
    use std::time::Instant;

    let dir = tempfile::tempdir().expect("tempdir");
    fs::create_dir_all(dir.path().join("node_modules").join("sub")).expect("mkdir");
    fs::write(dir.path().join("keep.txt"), "keep\n").expect("write");
    fs::write(dir.path().join("node_modules").join("skip.txt"), "skip\n").expect("write");
    fs::write(
        dir.path()
            .join("node_modules")
            .join("sub")
            .join("keep2.txt"),
        "keep\n",
    )
    .expect("write");

    let mut policy = SandboxPolicy::single_root("root", dir.path(), RootMode::ReadOnly);
    policy.traversal.skip_globs = vec!["node_modules/*".to_string()];
    let ctx = Context::new(policy).expect("ctx");

    assert!(
        !ctx.is_traversal_path_skipped(Path::new("node_modules")),
        "expected the skip glob not to match the directory itself"
    );
    let probe = Path::new("node_modules").join(traversal::TRAVERSAL_GLOB_PROBE_NAME);
    assert!(
        ctx.is_traversal_path_skipped(&probe),
        "expected the skip glob to match the probe path"
    );

    let root_path = ctx.canonical_root("root").expect("root").to_path_buf();
    let mut seen = Vec::new();
    let diag = traversal::walk_traversal_files(
        &ctx,
        "root",
        &root_path,
        &root_path,
        &Instant::now(),
        None,
        |file, _diag| {
            seen.push(file.relative_path);
            Ok(std::ops::ControlFlow::Continue(()))
        },
    )
    .expect("walk");

    assert!(
        seen.iter().any(|path| path == Path::new("keep.txt")),
        "expected keep.txt to be traversed, saw: {seen:?}"
    );
    assert!(
        !seen
            .iter()
            .any(|path| path.starts_with(Path::new("node_modules"))),
        "expected node_modules to be excluded via probe semantics, saw: {seen:?}"
    );
    assert_eq!(
        seen.len(),
        1,
        "expected exactly one visited file, saw: {seen:?}"
    );
    assert_eq!(
        diag.scanned_files(),
        1,
        "unexpected scanned files: {diag:?}"
    );
    // Directory iteration order can vary across filesystems, so allow one or two entries
    // as long as the observed files and scanned_files invariants stay strict.
    assert!(
        (1..=2).contains(&diag.scanned_entries()),
        "unexpected scanned entries: {diag:?}"
    );
}

#[test]
#[cfg(unix)]
fn normalize_path_lexical_does_not_escape_filesystem_root() {
    assert_eq!(
        crate::path_utils_internal::normalize_path_lexical(Path::new("/../etc")),
        PathBuf::from("/etc")
    );
    assert_eq!(
        crate::path_utils_internal::normalize_path_lexical(Path::new("/a/../../b")),
        PathBuf::from("/b")
    );
}

#[test]
fn normalize_path_lexical_preserves_leading_parent_dirs() {
    assert_eq!(
        crate::path_utils_internal::normalize_path_lexical(Path::new("../..")),
        PathBuf::from("../..")
    );
    assert_eq!(
        crate::path_utils_internal::normalize_path_lexical(Path::new("../../a/../b")),
        PathBuf::from("../../b")
    );
    assert_eq!(
        crate::path_utils_internal::normalize_path_lexical(Path::new("a/../../b")),
        PathBuf::from("../b")
    );
}

#[test]
fn requested_path_for_dot_is_not_empty() {
    let dir = tempfile::tempdir().expect("tempdir");
    let policy = SandboxPolicy::single_root("root", dir.path(), RootMode::ReadOnly);
    let ctx = Context::new(policy).expect("ctx");

    let (_canonical, relative, requested_path) = ctx
        .canonical_path_in_root("root", Path::new("."))
        .expect("canonicalize");
    assert_eq!(relative, PathBuf::from("."));
    assert_eq!(requested_path, PathBuf::from("."));
}

#[test]
#[cfg(windows)]
fn normalize_path_lexical_preserves_prefix_root() {
    assert_eq!(
        crate::path_utils_internal::normalize_path_lexical(Path::new(r"C:\..\foo")),
        PathBuf::from(r"C:\foo")
    );
}

#[test]
#[cfg(windows)]
fn normalize_path_lexical_preserves_unc_prefix_root() {
    assert_eq!(
        crate::path_utils_internal::normalize_path_lexical(Path::new(r"\\server\share\..\foo")),
        PathBuf::from(r"\\server\share\foo")
    );
}

#[test]
#[cfg(windows)]
fn normalize_path_lexical_preserves_verbatim_prefix_root() {
    assert_eq!(
        crate::path_utils_internal::normalize_path_lexical(Path::new(r"\\?\C:\..\foo")),
        PathBuf::from(r"\\?\C:\foo")
    );
}

#[test]
#[cfg(windows)]
fn rename_replace_honors_replace_existing_flag_windows() {
    rename_replace_honors_replace_existing_flag_with_assertion(|err| {
        if err.kind() != std::io::ErrorKind::AlreadyExists {
            assert!(
                matches!(err.raw_os_error(), Some(80 | 183)),
                "unexpected error: {err:?}"
            );
        }
    });
}

#[test]
#[cfg(not(windows))]
fn rename_replace_honors_replace_existing_flag_non_windows() {
    rename_replace_honors_replace_existing_flag_with_assertion(|err| {
        assert_eq!(
            err.kind(),
            std::io::ErrorKind::AlreadyExists,
            "unexpected error: {err:?}"
        );
    });
}

fn rename_replace_honors_replace_existing_flag_with_assertion(
    assert_error: impl FnOnce(&std::io::Error),
) {
    let dir = tempfile::tempdir().expect("tempdir");
    let src = dir.path().join("src.txt");
    let dest = dir.path().join("dest.txt");

    fs::write(&src, "new").expect("write src");
    fs::write(&dest, "old").expect("write dest");

    let err = io::rename_replace(&src, &dest, false).expect_err("should not overwrite");
    assert_error(&err);
    assert!(
        src.exists(),
        "source should remain when overwrite is disabled"
    );
    let out = fs::read_to_string(&dest).expect("read dest after failed overwrite");
    assert_eq!(out, "old", "destination should not be replaced");

    io::rename_replace(&src, &dest, true).expect("overwrite");
    let out = fs::read_to_string(&dest).expect("read dest");
    assert_eq!(out, "new");
    assert!(!src.exists());
}
