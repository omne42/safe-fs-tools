mod common;

use std::path::PathBuf;

use common::test_policy;
use safe_fs_tools::ops::{Context, ListDirRequest, ReadRequest, list_dir, read_file};
use safe_fs_tools::policy::RootMode;

#[test]
fn list_dir_handles_large_directory_with_small_limit() {
    let dir = tempfile::tempdir().expect("tempdir");
    for idx in 0..1500 {
        let name = format!("file-{idx:04}.txt");
        std::fs::write(dir.path().join(name), "x").expect("write");
    }

    let ctx = Context::new(test_policy(dir.path(), RootMode::ReadOnly)).expect("ctx");
    let resp = list_dir(
        &ctx,
        ListDirRequest {
            root_id: "root".to_string(),
            path: PathBuf::from("."),
            max_entries: Some(10),
        },
    )
    .expect("list");

    assert!(resp.truncated);
    assert_eq!(resp.entries.len(), 10);
    assert_eq!(resp.skipped_io_errors, 0);
}

#[test]
fn read_handles_large_file_within_limit() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("large.txt");
    let content = "0123456789abcdef\n".repeat(52_000);
    std::fs::write(&path, &content).expect("write");

    let ctx = Context::new(test_policy(dir.path(), RootMode::ReadOnly)).expect("ctx");
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

    assert_eq!(resp.bytes_read as usize, content.len());
    assert_eq!(resp.content.len(), content.len());
}
