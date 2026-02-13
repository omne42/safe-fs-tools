use super::*;

#[cfg(unix)]
fn create_fifo(path: &std::path::Path) {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    let c_path = CString::new(path.as_os_str().as_bytes()).expect("c path");
    // Safety: `CString::new` guarantees a NUL-terminated C string with no interior NUL bytes, and
    // the pointer remains valid for the duration of the call.
    let rc = unsafe { libc::mkfifo(c_path.as_ptr(), 0o600) };
    if rc != 0 {
        panic!("mkfifo failed: {}", std::io::Error::last_os_error());
    }
}

fn json_contains_string(value: &serde_json::Value, needle: &str) -> bool {
    match value {
        serde_json::Value::String(text) => text.contains(needle),
        serde_json::Value::Array(values) => values.iter().any(|v| json_contains_string(v, needle)),
        serde_json::Value::Object(map) => map.values().any(|v| json_contains_string(v, needle)),
        _ => false,
    }
}

#[test]
fn cli_rejects_zero_max_patch_bytes() {
    let err = Cli::try_parse_from([
        "safe-fs-tools",
        "--policy",
        "policy.toml",
        "--max-patch-bytes",
        "0",
        "read",
        "--root",
        "root",
        "README.md",
    ])
    .expect_err("expected clap to reject --max-patch-bytes=0");
    let message = err.to_string();
    assert!(
        message.contains("max-patch-bytes"),
        "unexpected clap error: {message}"
    );
}

#[test]
fn load_text_limited_rejects_large_file() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("big.diff");
    std::fs::write(&path, "x".repeat(100)).expect("write");

    let err = super::input::load_text_limited(&path, 10).expect_err("should reject");
    match err {
        safe_fs_tools::Error::InputTooLarge { .. } => {}
        other => panic!("unexpected error: {other:?}"),
    }
}

#[test]
#[cfg(unix)]
fn load_text_limited_rejects_symlink_paths() {
    use std::os::unix::fs::symlink;

    let dir = tempfile::tempdir().expect("tempdir");
    let real = dir.path().join("real.diff");
    let link = dir.path().join("link.diff");
    std::fs::write(&real, "ok\n").expect("write");
    symlink(&real, &link).expect("symlink");

    let err = super::input::load_text_limited(&link, 16).expect_err("should reject");
    match err {
        safe_fs_tools::Error::InvalidPath(message) => {
            assert!(message.contains("symlink"), "unexpected message: {message}");
        }
        other => panic!("unexpected error: {other:?}"),
    }
}

#[test]
#[cfg(unix)]
fn load_text_limited_rejects_fifo_special_files() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("pipe.diff");
    create_fifo(&path);

    let err = super::input::load_text_limited(&path, 8).expect_err("should reject");
    match err {
        safe_fs_tools::Error::InvalidPath(_) => {}
        other => panic!("unexpected error: {other:?}"),
    }
}

#[test]
fn tool_error_details_covers_invalid_path() {
    let err = safe_fs_tools::Error::InvalidPath("bad path".to_string());
    let details = tool_error_details(&err);
    assert_eq!(
        details.get("kind").and_then(|v| v.as_str()),
        Some("invalid_path")
    );
    assert_eq!(
        details.get("message").and_then(|v| v.as_str()),
        Some("bad path")
    );
}

#[test]
fn tool_error_details_includes_safe_invalid_path_message_when_redacting() {
    let err = safe_fs_tools::Error::InvalidPath("bad path".to_string());
    let details = tool_error_details_with(&err, None, true, false);
    assert_eq!(
        details.get("kind").and_then(|v| v.as_str()),
        Some("invalid_path")
    );
    assert_eq!(
        details.get("message").and_then(|v| v.as_str()),
        Some("invalid path")
    );
}

#[test]
fn tool_error_details_covers_root_not_found() {
    let err = safe_fs_tools::Error::RootNotFound("missing".to_string());
    let details = tool_error_details(&err);
    assert_eq!(
        details.get("kind").and_then(|v| v.as_str()),
        Some("root_not_found")
    );
    assert_eq!(
        details.get("root_id").and_then(|v| v.as_str()),
        Some("missing")
    );
}

#[test]
fn tool_error_details_includes_safe_invalid_policy_message_when_redacting() {
    let err = safe_fs_tools::Error::InvalidPolicy("bad policy".to_string());
    let details = tool_error_details_with(&err, None, true, false);
    assert_eq!(
        details.get("kind").and_then(|v| v.as_str()),
        Some("invalid_policy")
    );
    assert_eq!(
        details.get("message").and_then(|v| v.as_str()),
        Some("invalid policy")
    );
}

#[test]
fn format_path_for_error_strips_root_prefix_when_redacting() {
    let dir = tempfile::tempdir().expect("tempdir");
    let policy = safe_fs_tools::policy::SandboxPolicy::single_root(
        "root",
        dir.path(),
        safe_fs_tools::policy::RootMode::ReadOnly,
    );
    let redaction = PathRedaction::from_policy(&policy);
    let path = dir.path().join("sub").join("file.txt");

    let formatted = super::format_path_for_error(&path, Some(&redaction), true, false);
    assert_eq!(
        PathBuf::from(formatted),
        PathBuf::from("sub").join("file.txt")
    );
}

#[test]
fn format_path_for_error_strict_redaction_hides_file_names_outside_roots() {
    let dir = tempfile::tempdir().expect("tempdir");
    let other = tempfile::tempdir().expect("tempdir");
    let policy = safe_fs_tools::policy::SandboxPolicy::single_root(
        "root",
        dir.path(),
        safe_fs_tools::policy::RootMode::ReadOnly,
    );
    let redaction = PathRedaction::from_policy(&policy);
    let path = other.path().join(".env");

    let formatted = super::format_path_for_error(&path, Some(&redaction), true, true);
    assert_eq!(formatted, "<redacted>");
}

#[test]
fn format_path_for_error_redacts_relative_paths_to_file_name() {
    let path = PathBuf::from("nested/secret/file.txt");
    let formatted = super::format_path_for_error(&path, None, true, false);
    assert_eq!(formatted, "file.txt");
}

#[test]
fn tool_error_details_redacts_walkdir_message() {
    let dir = tempfile::tempdir().expect("tempdir");
    let policy = safe_fs_tools::policy::SandboxPolicy::single_root(
        "root",
        dir.path(),
        safe_fs_tools::policy::RootMode::ReadOnly,
    );
    let redaction = PathRedaction::from_policy(&policy);

    let missing = dir.path().join("missing");
    let walk_err = walkdir::WalkDir::new(&missing)
        .into_iter()
        .filter_map(|entry| entry.err())
        .next()
        .expect("walkdir error");
    let err = safe_fs_tools::Error::WalkDir(walk_err);

    let details = tool_error_details_with(&err, Some(&redaction), true, false);
    assert_eq!(
        details.get("kind").and_then(|v| v.as_str()),
        Some("walkdir")
    );
    assert!(
        details.get("message").is_none(),
        "expected walkdir message omitted in redacted mode"
    );
    assert_eq!(
        details.get("path").and_then(|v| v.as_str()),
        Some("missing")
    );

    assert!(
        !json_contains_string(&details, &dir.path().display().to_string()),
        "expected redacted details to not contain absolute root path: {details}"
    );
}

#[test]
fn tool_error_details_redacts_walkdir_root_message() {
    let dir = tempfile::tempdir().expect("tempdir");
    let policy = safe_fs_tools::policy::SandboxPolicy::single_root(
        "root",
        dir.path(),
        safe_fs_tools::policy::RootMode::ReadOnly,
    );
    let redaction = PathRedaction::from_policy(&policy);

    let err = safe_fs_tools::Error::WalkDirRoot {
        path: dir.path().join("missing"),
        source: std::io::Error::from_raw_os_error(2),
    };

    let details = tool_error_details_with(&err, Some(&redaction), true, false);
    assert_eq!(
        details.get("kind").and_then(|v| v.as_str()),
        Some("walkdir")
    );
    assert!(
        details.get("message").is_none(),
        "expected walkdir message omitted in redacted mode"
    );
    assert_eq!(
        details.get("path").and_then(|v| v.as_str()),
        Some("missing")
    );
    assert!(
        details.get("io_kind").and_then(|v| v.as_str()).is_some(),
        "expected io_kind"
    );
    assert_eq!(
        details.get("raw_os_error").and_then(|v| v.as_i64()),
        Some(2)
    );

    assert!(
        !json_contains_string(&details, &dir.path().display().to_string()),
        "expected redacted details to not contain absolute root path: {details}"
    );
}

#[test]
fn tool_error_details_includes_walkdir_root_message_when_not_redacting() {
    let dir = tempfile::tempdir().expect("tempdir");
    let missing = dir.path().join("missing");

    let err = safe_fs_tools::Error::WalkDirRoot {
        path: missing.clone(),
        source: std::io::Error::from_raw_os_error(2),
    };

    let details = tool_error_details_with(&err, None, false, false);
    assert_eq!(
        details.get("kind").and_then(|v| v.as_str()),
        Some("walkdir")
    );
    assert_eq!(
        details.get("path").and_then(|v| v.as_str()),
        Some(missing.to_string_lossy().as_ref())
    );
    assert!(
        details.get("message").and_then(|v| v.as_str()).is_some(),
        "expected message in non-redacted mode"
    );
    assert!(
        details.get("io_kind").and_then(|v| v.as_str()).is_some(),
        "expected io_kind"
    );
    assert_eq!(
        details.get("raw_os_error").and_then(|v| v.as_i64()),
        Some(2)
    );

    assert!(
        json_contains_string(&details, &dir.path().display().to_string()),
        "expected details to include absolute path in non-redacted mode: {details}"
    );
}

#[test]
fn tool_error_details_redacts_io_message() {
    let err = safe_fs_tools::Error::Io(std::io::Error::from_raw_os_error(2));
    let details = tool_error_details_with(&err, None, true, false);
    assert_eq!(details.get("kind").and_then(|v| v.as_str()), Some("io"));
    assert!(
        details.get("message").is_none(),
        "expected io message omitted in redacted mode"
    );
    assert!(
        details.get("io_kind").and_then(|v| v.as_str()).is_some(),
        "expected io_kind"
    );
    assert_eq!(
        details.get("raw_os_error").and_then(|v| v.as_i64()),
        Some(2)
    );
}

#[test]
fn tool_error_details_includes_io_details_when_not_redacting() {
    let err = safe_fs_tools::Error::Io(std::io::Error::from_raw_os_error(2));
    let details = tool_error_details_with(&err, None, false, false);
    assert_eq!(details.get("kind").and_then(|v| v.as_str()), Some("io"));
    assert!(
        details.get("message").and_then(|v| v.as_str()).is_some(),
        "expected io message in non-redacted mode"
    );
    assert!(
        details.get("io_kind").and_then(|v| v.as_str()).is_some(),
        "expected io_kind"
    );
    assert_eq!(
        details.get("raw_os_error").and_then(|v| v.as_i64()),
        Some(2)
    );
}

#[test]
fn tool_error_details_redacts_io_path_details() {
    let dir = tempfile::tempdir().expect("tempdir");
    let policy = safe_fs_tools::policy::SandboxPolicy::single_root(
        "root",
        dir.path(),
        safe_fs_tools::policy::RootMode::ReadOnly,
    );
    let redaction = PathRedaction::from_policy(&policy);

    let err = safe_fs_tools::Error::IoPath {
        op: "open",
        path: dir.path().join("file.txt"),
        source: std::io::Error::from_raw_os_error(2),
    };
    let details = tool_error_details_with(&err, Some(&redaction), true, false);
    assert_eq!(
        details.get("kind").and_then(|v| v.as_str()),
        Some("io_path")
    );
    assert_eq!(details.get("op").and_then(|v| v.as_str()), Some("open"));
    assert_eq!(
        details.get("path").and_then(|v| v.as_str()),
        Some("file.txt")
    );
    assert!(
        details.get("io_kind").and_then(|v| v.as_str()).is_some(),
        "expected io_kind"
    );
    assert_eq!(
        details.get("raw_os_error").and_then(|v| v.as_i64()),
        Some(2)
    );

    assert!(
        !json_contains_string(&details, &dir.path().display().to_string()),
        "expected redacted details to not contain absolute root path: {details}"
    );
}

#[test]
fn tool_error_details_includes_io_path_details_when_not_redacting() {
    let err = safe_fs_tools::Error::IoPath {
        op: "open",
        path: PathBuf::from("file.txt"),
        source: std::io::Error::from_raw_os_error(2),
    };
    let details = tool_error_details_with(&err, None, false, false);
    assert_eq!(
        details.get("kind").and_then(|v| v.as_str()),
        Some("io_path")
    );
    assert_eq!(details.get("op").and_then(|v| v.as_str()), Some("open"));
    assert_eq!(
        details.get("path").and_then(|v| v.as_str()),
        Some("file.txt")
    );
    assert!(
        details.get("message").and_then(|v| v.as_str()).is_some(),
        "expected message in non-redacted mode"
    );
    assert!(
        details.get("io_kind").and_then(|v| v.as_str()).is_some(),
        "expected io_kind"
    );
    assert_eq!(
        details.get("raw_os_error").and_then(|v| v.as_i64()),
        Some(2)
    );
}

#[test]
fn tool_error_details_redacts_patch_message() {
    let raw = "/abs/path/file.txt: bad patch";
    let err = safe_fs_tools::Error::Patch(raw.to_string());
    let details = tool_error_details_with(&err, None, true, false);
    assert_eq!(details.get("kind").and_then(|v| v.as_str()), Some("patch"));
    assert!(
        details.get("message").is_none(),
        "expected patch message omitted in redacted mode"
    );
    assert!(
        !json_contains_string(&details, raw),
        "expected redacted patch details to not contain raw path: {details}"
    );
}

#[test]
fn tool_error_details_keeps_patch_message_when_not_redacting() {
    let err = safe_fs_tools::Error::Patch("file.txt: bad patch".to_string());
    let details = tool_error_details_with(&err, None, false, false);
    assert_eq!(details.get("kind").and_then(|v| v.as_str()), Some("patch"));
    assert_eq!(
        details.get("message").and_then(|v| v.as_str()),
        Some("file.txt: bad patch")
    );
}

#[test]
fn tool_error_details_redacts_not_permitted_message() {
    let err = safe_fs_tools::Error::NotPermitted("/abs/path is blocked".to_string());
    let details = tool_error_details_with(&err, None, true, false);
    assert_eq!(
        details.get("kind").and_then(|v| v.as_str()),
        Some("not_permitted")
    );
    assert_eq!(
        details.get("message").and_then(|v| v.as_str()),
        Some("not permitted")
    );
}

#[test]
fn tool_public_message_redacts_patch_message() {
    let err = safe_fs_tools::Error::Patch("/abs/path/file.txt: bad patch".to_string());
    let message = tool_public_message(&err, None, true, false);
    assert_eq!(message, "failed to apply patch");
}

#[test]
fn tool_public_message_redacts_io_message() {
    let err = safe_fs_tools::Error::Io(std::io::Error::new(
        std::io::ErrorKind::PermissionDenied,
        "/abs/path denied",
    ));
    let message = tool_public_message(&err, None, true, false);
    assert_eq!(message, "io error");
}

#[test]
fn tool_public_message_redacts_not_permitted_message() {
    let err = safe_fs_tools::Error::NotPermitted("/abs/path denied".to_string());
    let message = tool_public_message(&err, None, true, false);
    assert_eq!(message, "not permitted");
}
