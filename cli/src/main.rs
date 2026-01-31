use std::io::Read;
use std::path::PathBuf;

use clap::{Parser, Subcommand, ValueEnum};

use safe_fs_tools::ops::{
    Context, CopyFileRequest, DeletePathRequest, EditRequest, GlobRequest, GrepRequest,
    ListDirRequest, MkdirRequest, MovePathRequest, PatchRequest, ReadRequest, StatRequest,
    WriteFileRequest,
};

mod error;

use error::{
    CliError, PathRedaction, tool_error_details, tool_error_details_with, tool_public_message,
};

#[cfg(test)]
use error::format_path_for_error;

#[derive(Debug, Clone, Copy, ValueEnum)]
enum ErrorFormat {
    Text,
    Json,
}

#[derive(Debug, Parser)]
#[command(name = "safe-fs-tools")]
#[command(
    about = "Safe filesystem tools (read/glob/grep/edit/patch/delete) with explicit sandbox policy."
)]
struct Cli {
    #[arg(long)]
    policy: PathBuf,

    /// Pretty-print JSON responses to stdout.
    #[arg(long)]
    pretty: bool,

    #[arg(long, value_enum, default_value_t = ErrorFormat::Text)]
    error_format: ErrorFormat,

    /// Redact file paths in JSON errors (best-effort).
    ///
    /// Useful when stderr is exposed to untrusted users; avoids leaking absolute paths.
    #[arg(long)]
    redact_paths: bool,

    /// Strict path redaction in JSON errors.
    ///
    /// Hides file names for absolute paths that are outside configured roots. This implies
    /// `--redact-paths` and is intended for scenarios where even file names are sensitive.
    #[arg(long)]
    redact_paths_strict: bool,

    /// Max bytes for patch input (stdin or file).
    ///
    /// Defaults to `policy.limits.max_patch_bytes` if set, otherwise `policy.limits.max_read_bytes`.
    #[arg(long)]
    #[arg(value_parser = clap::value_parser!(u64).range(1..))]
    max_patch_bytes: Option<u64>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    Read {
        #[arg(long)]
        root: String,
        path: PathBuf,
        #[arg(long)]
        start_line: Option<u64>,
        #[arg(long)]
        end_line: Option<u64>,
    },
    ListDir {
        #[arg(long)]
        root: String,
        #[arg(long)]
        max_entries: Option<usize>,
        #[arg(default_value = ".")]
        path: PathBuf,
    },
    Glob {
        #[arg(long)]
        root: String,
        pattern: String,
    },
    Grep {
        #[arg(long)]
        root: String,
        query: String,
        #[arg(long, default_value_t = false)]
        regex: bool,
        #[arg(long)]
        glob: Option<String>,
    },
    Stat {
        #[arg(long)]
        root: String,
        path: PathBuf,
    },
    Edit {
        #[arg(long)]
        root: String,
        path: PathBuf,
        #[arg(long)]
        start_line: u64,
        #[arg(long)]
        end_line: u64,
        replacement: String,
    },
    Patch {
        #[arg(long)]
        root: String,
        path: PathBuf,
        patch_file: PathBuf,
    },
    Mkdir {
        #[arg(long)]
        root: String,
        path: PathBuf,
        #[arg(long, default_value_t = false)]
        create_parents: bool,
        #[arg(long, default_value_t = false)]
        ignore_existing: bool,
    },
    Write {
        #[arg(long)]
        root: String,
        path: PathBuf,
        content_file: PathBuf,
        #[arg(long, default_value_t = false)]
        overwrite: bool,
        #[arg(long, default_value_t = false)]
        create_parents: bool,
    },
    Delete {
        #[arg(long)]
        root: String,
        path: PathBuf,
        #[arg(long, default_value_t = false)]
        recursive: bool,
        #[arg(long, default_value_t = false)]
        ignore_missing: bool,
    },
    Move {
        #[arg(long)]
        root: String,
        from: PathBuf,
        to: PathBuf,
        #[arg(long, default_value_t = false)]
        overwrite: bool,
        #[arg(long, default_value_t = false)]
        create_parents: bool,
    },
    CopyFile {
        #[arg(long)]
        root: String,
        from: PathBuf,
        to: PathBuf,
        #[arg(long, default_value_t = false)]
        overwrite: bool,
        #[arg(long, default_value_t = false)]
        create_parents: bool,
    },
}

fn main() {
    let cli = Cli::parse();
    let error_format = cli.error_format;
    let redact_paths = cli.redact_paths || cli.redact_paths_strict;
    let strict_redact_paths = cli.redact_paths_strict;
    let mut redaction = None::<PathRedaction>;

    let result = match safe_fs_tools::policy_io::load_policy(&cli.policy) {
        Ok(policy) => {
            if matches!(error_format, ErrorFormat::Json) && redact_paths {
                redaction = Some(PathRedaction::from_policy(&policy));
            }
            run_with_policy(&cli, policy)
        }
        Err(err) => Err(CliError::Tool(err)),
    };

    if let Err(err) = result {
        match error_format {
            ErrorFormat::Text => eprintln!("{err}"),
            ErrorFormat::Json => {
                let mut error = serde_json::Map::new();
                error.insert(
                    "code".to_string(),
                    serde_json::Value::String(err.code().to_string()),
                );
                error.insert(
                    "message".to_string(),
                    serde_json::Value::String(match &err {
                        CliError::Tool(tool) => tool_public_message(
                            tool,
                            redaction.as_ref(),
                            redact_paths,
                            strict_redact_paths,
                        ),
                        CliError::Json(_) => err.to_string(),
                    }),
                );

                if let CliError::Tool(tool) = &err {
                    let details = if redact_paths {
                        tool_error_details_with(tool, redaction.as_ref(), true, strict_redact_paths)
                    } else {
                        tool_error_details(tool)
                    };
                    if let Some(details) = details {
                        error.insert("details".to_string(), details);
                    }
                }

                let out = serde_json::json!({ "error": error });
                match serde_json::to_string(&out) {
                    Ok(text) => eprintln!("{text}"),
                    Err(_) => eprintln!("{err}"),
                }
            }
        }
        std::process::exit(1);
    }
}

fn run_with_policy(cli: &Cli, policy: safe_fs_tools::SandboxPolicy) -> Result<(), CliError> {
    let policy_patch_limit = policy
        .limits
        .max_patch_bytes
        .unwrap_or(policy.limits.max_read_bytes);
    let max_patch_bytes = cli
        .max_patch_bytes
        .map(|bytes| bytes.min(policy_patch_limit))
        .unwrap_or(policy_patch_limit);
    let max_write_bytes = policy.limits.max_write_bytes;
    let ctx = Context::new(policy)?;

    let value = match &cli.command {
        Command::Read {
            root,
            path,
            start_line,
            end_line,
        } => serde_json::to_value(safe_fs_tools::ops::read_file(
            &ctx,
            ReadRequest {
                root_id: root.clone(),
                path: path.clone(),
                start_line: *start_line,
                end_line: *end_line,
            },
        )?)?,
        Command::ListDir {
            root,
            max_entries,
            path,
        } => serde_json::to_value(safe_fs_tools::ops::list_dir(
            &ctx,
            ListDirRequest {
                root_id: root.clone(),
                path: path.clone(),
                max_entries: *max_entries,
            },
        )?)?,
        Command::Glob { root, pattern } => serde_json::to_value(safe_fs_tools::ops::glob_paths(
            &ctx,
            GlobRequest {
                root_id: root.clone(),
                pattern: pattern.clone(),
            },
        )?)?,
        Command::Grep {
            root,
            query,
            regex,
            glob,
        } => serde_json::to_value(safe_fs_tools::ops::grep(
            &ctx,
            GrepRequest {
                root_id: root.clone(),
                query: query.clone(),
                regex: *regex,
                glob: glob.clone(),
            },
        )?)?,
        Command::Stat { root, path } => serde_json::to_value(safe_fs_tools::ops::stat(
            &ctx,
            StatRequest {
                root_id: root.clone(),
                path: path.clone(),
            },
        )?)?,
        Command::Edit {
            root,
            path,
            start_line,
            end_line,
            replacement,
        } => serde_json::to_value(safe_fs_tools::ops::edit_range(
            &ctx,
            EditRequest {
                root_id: root.clone(),
                path: path.clone(),
                start_line: *start_line,
                end_line: *end_line,
                replacement: replacement.clone(),
            },
        )?)?,
        Command::Patch {
            root,
            path,
            patch_file,
        } => serde_json::to_value(safe_fs_tools::ops::apply_unified_patch(
            &ctx,
            PatchRequest {
                root_id: root.clone(),
                path: path.clone(),
                patch: load_text_limited(patch_file, max_patch_bytes)?,
            },
        )?)?,
        Command::Mkdir {
            root,
            path,
            create_parents,
            ignore_existing,
        } => serde_json::to_value(safe_fs_tools::ops::mkdir(
            &ctx,
            MkdirRequest {
                root_id: root.clone(),
                path: path.clone(),
                create_parents: *create_parents,
                ignore_existing: *ignore_existing,
            },
        )?)?,
        Command::Write {
            root,
            path,
            content_file,
            overwrite,
            create_parents,
        } => serde_json::to_value(safe_fs_tools::ops::write_file(
            &ctx,
            WriteFileRequest {
                root_id: root.clone(),
                path: path.clone(),
                content: load_text_limited(content_file, max_write_bytes)?,
                overwrite: *overwrite,
                create_parents: *create_parents,
            },
        )?)?,
        Command::Delete {
            root,
            path,
            recursive,
            ignore_missing,
        } => serde_json::to_value(safe_fs_tools::ops::delete_path(
            &ctx,
            DeletePathRequest {
                root_id: root.clone(),
                path: path.clone(),
                recursive: *recursive,
                ignore_missing: *ignore_missing,
            },
        )?)?,
        Command::Move {
            root,
            from,
            to,
            overwrite,
            create_parents,
        } => serde_json::to_value(safe_fs_tools::ops::move_path(
            &ctx,
            MovePathRequest {
                root_id: root.clone(),
                from: from.clone(),
                to: to.clone(),
                overwrite: *overwrite,
                create_parents: *create_parents,
            },
        )?)?,
        Command::CopyFile {
            root,
            from,
            to,
            overwrite,
            create_parents,
        } => serde_json::to_value(safe_fs_tools::ops::copy_file(
            &ctx,
            CopyFileRequest {
                root_id: root.clone(),
                from: from.clone(),
                to: to.clone(),
                overwrite: *overwrite,
                create_parents: *create_parents,
            },
        )?)?,
    };

    let out = if cli.pretty {
        serde_json::to_string_pretty(&value)?
    } else {
        serde_json::to_string(&value)?
    };
    println!("{out}");
    Ok(())
}

fn load_text_limited(path: &PathBuf, max_bytes: u64) -> Result<String, safe_fs_tools::Error> {
    let limit = max_bytes.saturating_add(1);
    let mut bytes = Vec::<u8>::new();

    if path.as_os_str() == "-" {
        std::io::stdin().take(limit).read_to_end(&mut bytes)?;
    } else {
        let meta = std::fs::metadata(path).map_err(|err| safe_fs_tools::Error::IoPath {
            op: "metadata",
            path: path.clone(),
            source: err,
        })?;
        if !meta.is_file() {
            return Err(safe_fs_tools::Error::InvalidPath(format!(
                "path {} is not a regular file",
                path.display()
            )));
        }

        std::fs::File::open(path)
            .map_err(|err| safe_fs_tools::Error::IoPath {
                op: "open",
                path: path.clone(),
                source: err,
            })?
            .take(limit)
            .read_to_end(&mut bytes)
            .map_err(|err| safe_fs_tools::Error::IoPath {
                op: "read",
                path: path.clone(),
                source: err,
            })?;
    }

    if bytes.len() as u64 > max_bytes {
        return Err(safe_fs_tools::Error::InputTooLarge {
            size_bytes: bytes.len() as u64,
            max_bytes,
        });
    }

    let text =
        std::str::from_utf8(&bytes).map_err(|_| safe_fs_tools::Error::InvalidUtf8(path.clone()))?;
    Ok(text.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    fn create_fifo(path: &std::path::Path) {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;

        let c_path = CString::new(path.as_os_str().as_bytes()).expect("c path");
        let rc = unsafe { libc::mkfifo(c_path.as_ptr(), 0o600) };
        if rc != 0 {
            panic!("mkfifo failed: {}", std::io::Error::last_os_error());
        }
    }

    #[test]
    fn cli_rejects_zero_max_patch_bytes() {
        let parsed = Cli::try_parse_from([
            "safe-fs-tools",
            "--policy",
            "policy.toml",
            "--max-patch-bytes",
            "0",
            "read",
            "--root",
            "root",
            "README.md",
        ]);
        assert!(parsed.is_err());
    }

    #[test]
    fn load_text_limited_rejects_large_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("big.diff");
        std::fs::write(&path, "x".repeat(100)).expect("write");

        let err = load_text_limited(&path, 10).expect_err("should reject");
        match err {
            safe_fs_tools::Error::InputTooLarge { .. } => {}
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    #[cfg(unix)]
    fn load_text_limited_rejects_fifo_special_files() {
        use std::io::Write;

        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("pipe.diff");
        create_fifo(&path);

        let mut fifo_writer = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .expect("open fifo");
        fifo_writer.write_all(b"123456789").expect("write");

        let err = load_text_limited(&path, 8).expect_err("should reject");
        match err {
            safe_fs_tools::Error::InvalidPath(_) => {}
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn tool_error_details_covers_invalid_path() {
        let err = safe_fs_tools::Error::InvalidPath("bad path".to_string());
        let details = tool_error_details(&err).expect("details");
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
        let details = tool_error_details_with(&err, None, true, false).expect("details");
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
        let details = tool_error_details(&err).expect("details");
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
        let details = tool_error_details_with(&err, None, true, false).expect("details");
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

        let formatted = format_path_for_error(&path, Some(&redaction), true, false);
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

        let formatted = format_path_for_error(&path, Some(&redaction), true, true);
        assert_eq!(formatted, "<redacted>");
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

        let details =
            tool_error_details_with(&err, Some(&redaction), true, false).expect("details");
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

        let rendered = details.to_string();
        assert!(
            !rendered.contains(&dir.path().display().to_string()),
            "expected redacted details to not contain absolute root path: {rendered}"
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

        let details =
            tool_error_details_with(&err, Some(&redaction), true, false).expect("details");
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

        let rendered = details.to_string();
        assert!(
            !rendered.contains(&dir.path().display().to_string()),
            "expected redacted details to not contain absolute root path: {rendered}"
        );
    }

    #[test]
    fn tool_error_details_includes_walkdir_root_message_when_not_redacting() {
        let dir = tempfile::tempdir().expect("tempdir");

        let err = safe_fs_tools::Error::WalkDirRoot {
            path: PathBuf::from("missing"),
            source: std::io::Error::from_raw_os_error(2),
        };

        let details = tool_error_details_with(&err, None, false, false).expect("details");
        assert_eq!(
            details.get("kind").and_then(|v| v.as_str()),
            Some("walkdir")
        );
        assert_eq!(
            details.get("path").and_then(|v| v.as_str()),
            Some("missing")
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

        let rendered = details.to_string();
        assert!(
            !rendered.contains(&dir.path().display().to_string()),
            "expected details to not contain absolute root path: {rendered}"
        );
    }

    #[test]
    fn tool_error_details_redacts_io_message() {
        let err = safe_fs_tools::Error::Io(std::io::Error::from_raw_os_error(2));
        let details = tool_error_details_with(&err, None, true, false).expect("details");
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
        let details = tool_error_details_with(&err, None, false, false).expect("details");
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
        let details =
            tool_error_details_with(&err, Some(&redaction), true, false).expect("details");
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

        let rendered = details.to_string();
        assert!(
            !rendered.contains(&dir.path().display().to_string()),
            "expected redacted details to not contain absolute root path: {rendered}"
        );
    }

    #[test]
    fn tool_error_details_includes_io_path_details_when_not_redacting() {
        let err = safe_fs_tools::Error::IoPath {
            op: "open",
            path: PathBuf::from("file.txt"),
            source: std::io::Error::from_raw_os_error(2),
        };
        let details = tool_error_details_with(&err, None, false, false).expect("details");
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
}
