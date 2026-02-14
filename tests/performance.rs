mod common;

use std::path::PathBuf;

use common::test_policy;
use safe_fs_tools::ops::{Context, ListDirRequest, ReadRequest, list_dir, read_file};
use safe_fs_tools::policy::RootMode;

// Large enough to reliably exercise list truncation on a non-trivial directory.
const DIR_ENTRIES: usize = 1_500;
const LIST_LIMIT: usize = 10;

// Roughly 884 KiB payload to exercise large-read paths near max_read_bytes.
const READ_LINE: &str = "0123456789abcdef\n";
const READ_LINE_REPEAT: usize = 52_000;

#[test]
fn list_dir_handles_large_directory_with_small_limit() {
    let dir = tempfile::tempdir().expect("tempdir");
    for idx in 0..DIR_ENTRIES {
        let name = format!("file-{idx:04}.txt");
        std::fs::write(dir.path().join(name), "x").expect("write");
    }

    let ctx = Context::new(test_policy(dir.path(), RootMode::ReadOnly)).expect("ctx");
    let resp = list_dir(
        &ctx,
        ListDirRequest {
            root_id: "root".to_string(),
            path: PathBuf::from("."),
            max_entries: Some(LIST_LIMIT),
        },
    )
    .expect("list");

    assert!(resp.truncated);
    assert_eq!(resp.entries.len(), LIST_LIMIT);
    assert_eq!(resp.skipped_io_errors, 0);
    for (idx, entry) in resp.entries.iter().enumerate() {
        assert_eq!(entry.name, format!("file-{idx:04}.txt"));
    }
    assert_eq!(resp.entries.first().expect("entry").name, "file-0000.txt");
    assert_eq!(
        resp.entries.last().expect("entry").name,
        format!("file-{:04}.txt", LIST_LIMIT - 1)
    );
}

#[test]
fn read_handles_large_file_within_limit() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("large.txt");
    let content = READ_LINE.repeat(READ_LINE_REPEAT);
    std::fs::write(&path, &content).expect("write");

    let mut policy = test_policy(dir.path(), RootMode::ReadOnly);
    policy.limits.max_read_bytes = u64::try_from(content.len()).expect("content len fits u64");
    let ctx = Context::new(policy).expect("ctx");
    let resp = read_file(
        &ctx,
        ReadRequest {
            root_id: "root".to_string(),
            path: PathBuf::from("large.txt"),
            start_line: None,
            end_line: None,
        },
    )
    .expect("read");

    assert_eq!(
        resp.bytes_read,
        u64::try_from(content.len()).expect("content len fits u64")
    );
    assert_eq!(resp.content.len(), content.len());
    assert!(resp.content.starts_with(READ_LINE));
    assert!(resp.content.ends_with(READ_LINE));
    assert_eq!(resp.content.lines().count(), READ_LINE_REPEAT);
    assert!(!resp.truncated);
}

#[test]
fn read_rejects_file_exceeding_max_read_bytes() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("large.txt");
    let content = READ_LINE.repeat(READ_LINE_REPEAT);
    std::fs::write(&path, &content).expect("write");

    let content_len = u64::try_from(content.len()).expect("content len fits u64");
    let mut policy = test_policy(dir.path(), RootMode::ReadOnly);
    policy.limits.max_read_bytes = content_len.saturating_sub(1);
    let ctx = Context::new(policy).expect("ctx");

    let err = read_file(
        &ctx,
        ReadRequest {
            root_id: "root".to_string(),
            path: PathBuf::from("large.txt"),
            start_line: None,
            end_line: None,
        },
    )
    .expect_err("should reject");

    match err {
        safe_fs_tools::Error::FileTooLarge {
            path,
            size_bytes,
            max_bytes,
        } => {
            assert_eq!(path, PathBuf::from("large.txt"));
            assert_eq!(size_bytes, content_len);
            assert_eq!(max_bytes, content_len.saturating_sub(1));
        }
        other => panic!("unexpected error: {other:?}"),
    }
}
