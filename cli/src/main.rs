use std::io::Read;
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

fn tool_error_details(tool: &safe_fs_tools::Error) -> Option<serde_json::Value> {
    match tool {
        safe_fs_tools::Error::Io(err) => Some(serde_json::json!({
            "kind": "io",
            "message": err.to_string(),
        })),
        safe_fs_tools::Error::IoPath { op, path, .. } => Some(serde_json::json!({
            "kind": "io_path",
            "op": op,
            "path": path.display().to_string(),
        })),
        safe_fs_tools::Error::InvalidPolicy(message) => Some(serde_json::json!({
            "kind": "invalid_policy",
            "message": message,
        })),
        safe_fs_tools::Error::InvalidPath(message) => Some(serde_json::json!({
            "kind": "invalid_path",
            "message": message,
        })),
        safe_fs_tools::Error::RootNotFound(root_id) => Some(serde_json::json!({
            "kind": "root_not_found",
            "root_id": root_id,
        })),
        safe_fs_tools::Error::OutsideRoot { root_id, path } => Some(serde_json::json!({
            "kind": "outside_root",
            "root_id": root_id,
            "path": path.display().to_string(),
        })),
        safe_fs_tools::Error::NotPermitted(message) => Some(serde_json::json!({
            "kind": "not_permitted",
            "message": message,
        })),
        safe_fs_tools::Error::SecretPathDenied(path) => Some(serde_json::json!({
            "kind": "secret_path_denied",
            "path": path.display().to_string(),
        })),
        safe_fs_tools::Error::FileTooLarge {
            path,
            size_bytes,
            max_bytes,
        } => Some(serde_json::json!({
            "kind": "file_too_large",
            "path": path.display().to_string(),
            "size_bytes": size_bytes,
            "max_bytes": max_bytes,
        })),
        safe_fs_tools::Error::InvalidUtf8(path) => Some(serde_json::json!({
            "kind": "invalid_utf8",
            "path": path.display().to_string(),
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
        safe_fs_tools::Error::WalkDir(err) => Some(serde_json::json!({
            "kind": "walkdir",
            "message": err.to_string(),
        })),
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
                let mut error = serde_json::Map::new();
                error.insert(
                    "code".to_string(),
                    serde_json::Value::String(err.code().to_string()),
                );
                error.insert(
                    "message".to_string(),
                    serde_json::Value::String(err.to_string()),
                );

                if let CliError::Tool(tool) = &err {
                    if let Some(details) = tool_error_details(tool) {
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
}
