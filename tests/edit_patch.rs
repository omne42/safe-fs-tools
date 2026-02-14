mod common;
#[cfg(unix)]
#[path = "common/unix_helpers.rs"]
mod unix_helpers;

use std::path::PathBuf;

use common::test_policy;
use safe_fs_tools::ops::{Context, EditRequest, edit_range};
use safe_fs_tools::policy::RootMode;

#[cfg(feature = "patch")]
use safe_fs_tools::ops::{DeleteRequest, PatchRequest, apply_unified_patch, delete};

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

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
    assert_eq!(after_edit, "one\nTWO\nthree\n");

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

    let delete = delete(
        &ctx,
        DeleteRequest {
            root_id: "root".to_string(),
            path: PathBuf::from("file.txt"),
            recursive: false,
            ignore_missing: false,
        },
    )
    .expect("delete");
    assert_eq!(delete.requested_path, Some(PathBuf::from("file.txt")));

    assert!(!path.exists());
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
    assert_eq!(
        std::fs::read_to_string(&path).expect("read after reject"),
        "one\n"
    );
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
    assert_eq!(
        std::fs::read_to_string(&path).expect("read after reject"),
        "line\n".repeat(50)
    );
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
    assert_eq!(
        std::fs::read_to_string(&path).expect("read after reject"),
        "line\n".repeat(50)
    );
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
fn edit_rejects_fifo_special_files() {
    let dir = tempfile::tempdir().expect("tempdir");
    let fifo = dir.path().join("pipe");
    unix_helpers::create_fifo(&fifo);

    let mut policy = test_policy(dir.path(), RootMode::ReadWrite);
    policy.limits.max_read_bytes = 8;
    let ctx = Context::new(policy).expect("ctx");

    let err = edit_range(
        &ctx,
        EditRequest {
            root_id: "root".to_string(),
            path: PathBuf::from("pipe"),
            start_line: 1,
            end_line: 1,
            replacement: "ONE".to_string(),
        },
    )
    .expect_err("should reject");

    match err {
        safe_fs_tools::Error::InvalidPath(_) => {}
        other => panic!("unexpected error: {other:?}"),
    }
}

#[test]
#[cfg(all(unix, feature = "patch"))]
fn patch_rejects_fifo_special_files() {
    let dir = tempfile::tempdir().expect("tempdir");
    let fifo = dir.path().join("pipe");
    unix_helpers::create_fifo(&fifo);

    let mut policy = test_policy(dir.path(), RootMode::ReadWrite);
    policy.limits.max_read_bytes = 8;
    policy.limits.max_patch_bytes = Some(1024);
    let ctx = Context::new(policy).expect("ctx");

    let err = apply_unified_patch(
        &ctx,
        PatchRequest {
            root_id: "root".to_string(),
            path: PathBuf::from("pipe"),
            patch: diffy::create_patch("one\n", "two\n").to_string(),
        },
    )
    .expect_err("should reject");

    match err {
        safe_fs_tools::Error::InvalidPath(_) => {}
        other => panic!("unexpected error: {other:?}"),
    }
}

#[test]
fn edit_rejects_invalid_line_ranges() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("file.txt");
    std::fs::write(&path, "one\ntwo\n").expect("write");

    let ctx = Context::new(test_policy(dir.path(), RootMode::ReadWrite)).expect("ctx");

    let err = edit_range(
        &ctx,
        EditRequest {
            root_id: "root".to_string(),
            path: PathBuf::from("file.txt"),
            start_line: 0,
            end_line: 1,
            replacement: "ONE".to_string(),
        },
    )
    .expect_err("should reject");
    match err {
        safe_fs_tools::Error::InvalidPath(_) => {}
        other => panic!("unexpected error: {other:?}"),
    }

    let err = edit_range(
        &ctx,
        EditRequest {
            root_id: "root".to_string(),
            path: PathBuf::from("file.txt"),
            start_line: 2,
            end_line: 1,
            replacement: "ONE".to_string(),
        },
    )
    .expect_err("should reject");
    match err {
        safe_fs_tools::Error::InvalidPath(_) => {}
        other => panic!("unexpected error: {other:?}"),
    }
}

#[test]
fn edit_rejects_out_of_bounds_line_ranges() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("file.txt");
    std::fs::write(&path, "one\n").expect("write");

    let ctx = Context::new(test_policy(dir.path(), RootMode::ReadWrite)).expect("ctx");

    let err = edit_range(
        &ctx,
        EditRequest {
            root_id: "root".to_string(),
            path: PathBuf::from("file.txt"),
            start_line: 2,
            end_line: 2,
            replacement: "TWO".to_string(),
        },
    )
    .expect_err("should reject");

    match err {
        safe_fs_tools::Error::InvalidPath(message) => assert!(message.contains("out of bounds")),
        other => panic!("unexpected error: {other:?}"),
    }

    let empty_path = dir.path().join("empty.txt");
    std::fs::write(&empty_path, "").expect("write");

    let err = edit_range(
        &ctx,
        EditRequest {
            root_id: "root".to_string(),
            path: PathBuf::from("empty.txt"),
            start_line: 1,
            end_line: 1,
            replacement: "ONE".to_string(),
        },
    )
    .expect_err("should reject");

    match err {
        safe_fs_tools::Error::InvalidPath(message) => assert!(message.contains("out of bounds")),
        other => panic!("unexpected error: {other:?}"),
    }
}

#[test]
fn edit_preserves_crlf_when_replacement_contains_crlf() {
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
            replacement: "TWO\r\n".to_string(),
        },
    )
    .expect("edit");

    let out = std::fs::read_to_string(&path).expect("read");
    assert_eq!(out, "one\r\nTWO\r\nthree\r\n");
}

#[test]
fn edit_normalizes_crlf_replacement_for_lf_files() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("lf.txt");
    std::fs::write(&path, "one\ntwo\nthree\n").expect("write");

    let ctx = Context::new(test_policy(dir.path(), RootMode::ReadWrite)).expect("ctx");
    edit_range(
        &ctx,
        EditRequest {
            root_id: "root".to_string(),
            path: PathBuf::from("lf.txt"),
            start_line: 2,
            end_line: 2,
            replacement: "TWO\r\n".to_string(),
        },
    )
    .expect("edit");

    let out = std::fs::read_to_string(&path).expect("read");
    assert_eq!(out, "one\nTWO\nthree\n");
}

#[test]
#[cfg(feature = "patch")]
fn patch_rejects_invalid_patch_text() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("file.txt");
    std::fs::write(&path, "one\n").expect("write");

    let ctx = Context::new(test_policy(dir.path(), RootMode::ReadWrite)).expect("ctx");
    let err = apply_unified_patch(
        &ctx,
        PatchRequest {
            root_id: "root".to_string(),
            path: PathBuf::from("file.txt"),
            patch: "@@ -1,1 +1,1 @@\n".to_string(),
        },
    )
    .expect_err("should reject");

    match err {
        safe_fs_tools::Error::Patch(message) => assert!(message.contains("file.txt")),
        other => panic!("unexpected error: {other:?}"),
    }
    assert_eq!(
        std::fs::read_to_string(&path).expect("read after reject"),
        "one\n"
    );
}

#[test]
#[cfg(feature = "patch")]
fn patch_rejects_patches_that_do_not_apply() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("file.txt");
    std::fs::write(&path, "one\n").expect("write");

    let ctx = Context::new(test_policy(dir.path(), RootMode::ReadWrite)).expect("ctx");
    let patch = diffy::create_patch("two\n", "TWO\n").to_string();

    let err = apply_unified_patch(
        &ctx,
        PatchRequest {
            root_id: "root".to_string(),
            path: PathBuf::from("file.txt"),
            patch,
        },
    )
    .expect_err("should reject");

    match err {
        safe_fs_tools::Error::Patch(message) => assert!(message.contains("file.txt")),
        other => panic!("unexpected error: {other:?}"),
    }
    assert_eq!(
        std::fs::read_to_string(&path).expect("read after reject"),
        "one\n"
    );
}

#[test]
#[cfg(feature = "patch")]
fn patch_respects_max_write_bytes() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("file.txt");
    std::fs::write(&path, "one\n").expect("write");

    let mut policy = test_policy(dir.path(), RootMode::ReadWrite);
    policy.limits.max_write_bytes = 4;
    let ctx = Context::new(policy).expect("ctx");

    let patch = diffy::create_patch("one\n", "one\nTWO\n").to_string();
    let err = apply_unified_patch(
        &ctx,
        PatchRequest {
            root_id: "root".to_string(),
            path: PathBuf::from("file.txt"),
            patch,
        },
    )
    .expect_err("should reject");

    match err {
        safe_fs_tools::Error::FileTooLarge {
            path,
            size_bytes,
            max_bytes,
        } => {
            assert_eq!(path, PathBuf::from("file.txt"));
            assert!(size_bytes > max_bytes);
            assert_eq!(max_bytes, 4);
        }
        other => panic!("unexpected error: {other:?}"),
    }
    assert_eq!(
        std::fs::read_to_string(&path).expect("read after reject"),
        "one\n"
    );
}
