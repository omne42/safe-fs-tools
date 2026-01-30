use std::io::Read;
use std::path::Path;
use std::path::PathBuf;

use clap::{Parser, Subcommand, ValueEnum};

use safe_fs_tools::ops::{
    Context, DeleteRequest, EditRequest, GlobRequest, GrepRequest, PatchRequest, ReadRequest,
};

#[derive(Debug)]
enum CliError {
    Tool(safe_fs_tools::Error),
    Json(serde_json::Error),
}

impl std::fmt::Display for CliError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CliError::Tool(err) => write!(f, "{err}"),
            CliError::Json(err) => write!(f, "json error: {err}"),
        }
    }
}

impl std::error::Error for CliError {}

impl From<safe_fs_tools::Error> for CliError {
    fn from(err: safe_fs_tools::Error) -> Self {
        Self::Tool(err)
    }
}

impl From<serde_json::Error> for CliError {
    fn from(err: serde_json::Error) -> Self {
        Self::Json(err)
    }
}

impl CliError {
    fn code(&self) -> &'static str {
        match self {
            CliError::Tool(err) => err.code(),
            CliError::Json(_) => "json",
        }
    }
}

#[derive(Debug, Clone)]
struct PathRedaction {
    roots: Vec<PathBuf>,
    canonical_roots: Vec<PathBuf>,
}

impl PathRedaction {
    fn from_policy(policy: &safe_fs_tools::SandboxPolicy) -> Self {
        let mut roots = Vec::<PathBuf>::new();
        let mut canonical_roots = Vec::<PathBuf>::new();

        for root in &policy.roots {
            roots.push(root.path.clone());
            if let Ok(canonical) = root.path.canonicalize() {
                canonical_roots.push(canonical);
            }
        }

        Self {
            roots,
            canonical_roots,
        }
    }
}

fn format_path_for_error(
    path: &Path,
    redaction: Option<&PathRedaction>,
    redact_paths: bool,
) -> String {
    if !redact_paths {
        return path.display().to_string();
    }

    if !path.is_absolute() {
        return path.display().to_string();
    }

    if let Some(redaction) = redaction {
        for root in redaction
            .roots
            .iter()
            .chain(redaction.canonical_roots.iter())
        {
            if let Ok(relative) = path.strip_prefix(root) {
                return relative.display().to_string();
            }
        }
    }

    path.file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| "<redacted>".to_string())
}

fn tool_error_details(tool: &safe_fs_tools::Error) -> Option<serde_json::Value> {
    tool_error_details_with(tool, None, false)
}

fn tool_error_details_with(
    tool: &safe_fs_tools::Error,
    redaction: Option<&PathRedaction>,
    redact_paths: bool,
) -> Option<serde_json::Value> {
    match tool {
        safe_fs_tools::Error::Io(err) => {
            if redact_paths {
                let mut out = serde_json::Map::new();
                out.insert(
                    "kind".to_string(),
                    serde_json::Value::String("io".to_string()),
                );
                out.insert(
                    "io_kind".to_string(),
                    serde_json::Value::String(format!("{:?}", err.kind())),
                );
                if let Some(raw_os_error) = err.raw_os_error() {
                    out.insert("raw_os_error".to_string(), serde_json::json!(raw_os_error));
                }
                Some(serde_json::Value::Object(out))
            } else {
                Some(serde_json::json!({
                    "kind": "io",
                    "message": err.to_string(),
                }))
            }
        }
        safe_fs_tools::Error::IoPath { op, path, source } => {
            let mut out = serde_json::Map::new();
            out.insert(
                "kind".to_string(),
                serde_json::Value::String("io_path".to_string()),
            );
            out.insert("op".to_string(), serde_json::Value::String(op.to_string()));
            out.insert(
                "path".to_string(),
                serde_json::Value::String(format_path_for_error(path, redaction, redact_paths)),
            );
            if redact_paths {
                out.insert(
                    "io_kind".to_string(),
                    serde_json::Value::String(format!("{:?}", source.kind())),
                );
                if let Some(raw_os_error) = source.raw_os_error() {
                    out.insert("raw_os_error".to_string(), serde_json::json!(raw_os_error));
                }
            }
            Some(serde_json::Value::Object(out))
        }
        safe_fs_tools::Error::InvalidPolicy(message) => {
            let mut out = serde_json::Map::new();
            out.insert(
                "kind".to_string(),
                serde_json::Value::String("invalid_policy".to_string()),
            );
            if !redact_paths {
                out.insert(
                    "message".to_string(),
                    serde_json::Value::String(message.clone()),
                );
            }
            Some(serde_json::Value::Object(out))
        }
        safe_fs_tools::Error::InvalidPath(message) => {
            let mut out = serde_json::Map::new();
            out.insert(
                "kind".to_string(),
                serde_json::Value::String("invalid_path".to_string()),
            );
            if !redact_paths {
                out.insert(
                    "message".to_string(),
                    serde_json::Value::String(message.clone()),
                );
            }
            Some(serde_json::Value::Object(out))
        }
        safe_fs_tools::Error::RootNotFound(root_id) => Some(serde_json::json!({
            "kind": "root_not_found",
            "root_id": root_id,
        })),
        safe_fs_tools::Error::OutsideRoot { root_id, path } => Some(serde_json::json!({
            "kind": "outside_root",
            "root_id": root_id,
            "path": format_path_for_error(path, redaction, redact_paths),
        })),
        safe_fs_tools::Error::NotPermitted(message) => Some(serde_json::json!({
            "kind": "not_permitted",
            "message": message,
        })),
        safe_fs_tools::Error::SecretPathDenied(path) => Some(serde_json::json!({
            "kind": "secret_path_denied",
            "path": format_path_for_error(path, redaction, redact_paths),
        })),
        safe_fs_tools::Error::FileTooLarge {
            path,
            size_bytes,
            max_bytes,
        } => Some(serde_json::json!({
            "kind": "file_too_large",
            "path": format_path_for_error(path, redaction, redact_paths),
            "size_bytes": size_bytes,
            "max_bytes": max_bytes,
        })),
        safe_fs_tools::Error::InvalidUtf8(path) => Some(serde_json::json!({
            "kind": "invalid_utf8",
            "path": format_path_for_error(path, redaction, redact_paths),
        })),
        safe_fs_tools::Error::Patch(message) => Some(serde_json::json!({
            "kind": "patch",
            "message": message,
        })),
        safe_fs_tools::Error::InvalidRegex(message) => Some(serde_json::json!({
            "kind": "invalid_regex",
            "message": message,
        })),
        safe_fs_tools::Error::InputTooLarge {
            size_bytes,
            max_bytes,
        } => Some(serde_json::json!({
            "kind": "input_too_large",
            "size_bytes": size_bytes,
            "max_bytes": max_bytes,
        })),
        safe_fs_tools::Error::WalkDirRoot { path, source } => {
            let mut out = serde_json::Map::new();
            out.insert(
                "kind".to_string(),
                serde_json::Value::String("walkdir".to_string()),
            );
            out.insert(
                "path".to_string(),
                serde_json::Value::String(format_path_for_error(path, redaction, redact_paths)),
            );
            out.insert(
                "io_kind".to_string(),
                serde_json::Value::String(format!("{:?}", source.kind())),
            );
            if let Some(raw_os_error) = source.raw_os_error() {
                out.insert("raw_os_error".to_string(), serde_json::json!(raw_os_error));
            }
            if !redact_paths {
                out.insert(
                    "message".to_string(),
                    serde_json::Value::String(source.to_string()),
                );
            }
            Some(serde_json::Value::Object(out))
        }
        safe_fs_tools::Error::WalkDir(err) => {
            if redact_paths {
                let mut out = serde_json::Map::new();
                out.insert(
                    "kind".to_string(),
                    serde_json::Value::String("walkdir".to_string()),
                );
                if let Some(path) = err.path() {
                    out.insert(
                        "path".to_string(),
                        serde_json::Value::String(format_path_for_error(
                            path,
                            redaction,
                            redact_paths,
                        )),
                    );
                }
                if let Some(io_error) = err.io_error() {
                    out.insert(
                        "io_kind".to_string(),
                        serde_json::Value::String(format!("{:?}", io_error.kind())),
                    );
                    if let Some(raw_os_error) = io_error.raw_os_error() {
                        out.insert("raw_os_error".to_string(), serde_json::json!(raw_os_error));
                    }
                }
                Some(serde_json::Value::Object(out))
            } else {
                Some(serde_json::json!({
                    "kind": "walkdir",
                    "message": err.to_string(),
                }))
            }
        }
        _ => {
            if redact_paths {
                Some(serde_json::json!({
                    "kind": tool.code(),
                }))
            } else {
                Some(serde_json::json!({
                    "kind": tool.code(),
                    "message": tool.to_string(),
                }))
            }
        }
    }
}

fn tool_public_message(
    tool: &safe_fs_tools::Error,
    redaction: Option<&PathRedaction>,
    redact_paths: bool,
) -> String {
    if !redact_paths {
        return tool.to_string();
    }

    match tool {
        safe_fs_tools::Error::Io(_) => tool.to_string(),
        safe_fs_tools::Error::IoPath { op, path, .. } => {
            let path = format_path_for_error(path, redaction, redact_paths);
            format!("io error during {op} ({path})")
        }
        safe_fs_tools::Error::InvalidPolicy(_) => "invalid policy".to_string(),
        safe_fs_tools::Error::InvalidPath(_) => "invalid path".to_string(),
        safe_fs_tools::Error::RootNotFound(root_id) => format!("root not found: {root_id}"),
        safe_fs_tools::Error::OutsideRoot { root_id, .. } => {
            format!("path resolves outside root '{root_id}'")
        }
        safe_fs_tools::Error::NotPermitted(_) => tool.to_string(),
        safe_fs_tools::Error::SecretPathDenied(path) => {
            let path = format_path_for_error(path, redaction, redact_paths);
            format!("path is denied by secret rules: {path}")
        }
        safe_fs_tools::Error::FileTooLarge {
            path,
            size_bytes,
            max_bytes,
        } => {
            let path = format_path_for_error(path, redaction, redact_paths);
            format!("file is too large ({size_bytes} bytes; max {max_bytes} bytes): {path}")
        }
        safe_fs_tools::Error::InvalidUtf8(path) => {
            let path = format_path_for_error(path, redaction, redact_paths);
            format!("invalid utf-8 in file: {path}")
        }
        safe_fs_tools::Error::Patch(_) => tool.to_string(),
        safe_fs_tools::Error::InvalidRegex(_) => tool.to_string(),
        safe_fs_tools::Error::InputTooLarge { .. } => tool.to_string(),
        safe_fs_tools::Error::WalkDirRoot { .. } | safe_fs_tools::Error::WalkDir(_) => {
            "walkdir error".to_string()
        }
        _ => {
            if redact_paths {
                tool.code().to_string()
            } else {
                tool.to_string()
            }
        }
    }
}

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

    #[arg(long, value_enum, default_value_t = ErrorFormat::Text)]
    error_format: ErrorFormat,

    /// Redact file paths in JSON errors (best-effort).
    ///
    /// Useful when stderr is exposed to untrusted users; avoids leaking absolute paths.
    #[arg(long)]
    redact_paths: bool,

    /// Max bytes for patch input (stdin or file).
    ///
    /// Defaults to `policy.limits.max_patch_bytes` if set, otherwise `policy.limits.max_read_bytes`.
    #[arg(long)]
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
    Delete {
        #[arg(long)]
        root: String,
        path: PathBuf,
    },
}

fn main() {
    let cli = Cli::parse();
    let error_format = cli.error_format;
    if let Err(err) = run(&cli) {
        match error_format {
            ErrorFormat::Text => eprintln!("{err}"),
            ErrorFormat::Json => {
                let redaction = if cli.redact_paths {
                    safe_fs_tools::policy_io::load_policy(&cli.policy)
                        .ok()
                        .map(|policy| PathRedaction::from_policy(&policy))
                } else {
                    None
                };

                let mut error = serde_json::Map::new();
                error.insert(
                    "code".to_string(),
                    serde_json::Value::String(err.code().to_string()),
                );
                error.insert(
                    "message".to_string(),
                    serde_json::Value::String(match &err {
                        CliError::Tool(tool) => {
                            tool_public_message(tool, redaction.as_ref(), cli.redact_paths)
                        }
                        CliError::Json(_) => err.to_string(),
                    }),
                );

                if let CliError::Tool(tool) = &err {
                    let details = if cli.redact_paths {
                        tool_error_details_with(tool, redaction.as_ref(), true)
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

fn run(cli: &Cli) -> Result<(), CliError> {
    let policy = safe_fs_tools::policy_io::load_policy(&cli.policy)?;
    let policy_patch_limit = policy
        .limits
        .max_patch_bytes
        .unwrap_or(policy.limits.max_read_bytes);
    let max_patch_bytes = cli
        .max_patch_bytes
        .map(|bytes| bytes.min(policy_patch_limit))
        .unwrap_or(policy_patch_limit);
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
        Command::Delete { root, path } => serde_json::to_value(safe_fs_tools::ops::delete_file(
            &ctx,
            DeleteRequest {
                root_id: root.clone(),
                path: path.clone(),
            },
        )?)?,
    };

    println!("{}", serde_json::to_string_pretty(&value)?);
    Ok(())
}

fn load_text_limited(path: &PathBuf, max_bytes: u64) -> Result<String, safe_fs_tools::Error> {
    let limit = max_bytes.saturating_add(1);
    let mut bytes = Vec::<u8>::new();

    if path.as_os_str() == "-" {
        std::io::stdin().take(limit).read_to_end(&mut bytes)?;
    } else {
        std::fs::File::open(path)?
            .take(limit)
            .read_to_end(&mut bytes)?;
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
    fn format_path_for_error_strips_root_prefix_when_redacting() {
        let dir = tempfile::tempdir().expect("tempdir");
        let policy = safe_fs_tools::policy::SandboxPolicy::single_root(
            "root",
            dir.path(),
            safe_fs_tools::policy::RootMode::ReadOnly,
        );
        let redaction = PathRedaction::from_policy(&policy);
        let path = dir.path().join("sub").join("file.txt");

        let formatted = format_path_for_error(&path, Some(&redaction), true);
        assert_eq!(
            PathBuf::from(formatted),
            PathBuf::from("sub").join("file.txt")
        );
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

        let details = tool_error_details_with(&err, Some(&redaction), true).expect("details");
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

        let details = tool_error_details_with(&err, Some(&redaction), true).expect("details");
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

        let details = tool_error_details_with(&err, None, false).expect("details");
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
        let details = tool_error_details_with(&err, None, true).expect("details");
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
        let details = tool_error_details_with(&err, Some(&redaction), true).expect("details");
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
}
