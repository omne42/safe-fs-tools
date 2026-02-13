use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand, ValueEnum};

use safe_fs_tools::ops::{
    Context, CopyFileRequest, DeleteRequest, EditRequest, GlobRequest, GrepRequest, ListDirRequest,
    MkdirRequest, MovePathRequest, PatchRequest, ReadRequest, StatRequest, WriteFileRequest,
};

mod error;
mod input;

use error::{
    CliError, PathRedaction, tool_error_details, tool_error_details_with, tool_public_message,
};
use input::load_text_limited;

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
        #[arg(long, value_parser = clap::value_parser!(u64).range(1..))]
        start_line: Option<u64>,
        #[arg(long, value_parser = clap::value_parser!(u64).range(1..))]
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
        #[arg(long, value_parser = clap::value_parser!(u64).range(1..))]
        start_line: u64,
        #[arg(long, value_parser = clap::value_parser!(u64).range(1..))]
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
    std::process::exit(match run() {
        ExitCode::SUCCESS => 0,
        ExitCode::FAILURE => 1,
        _ => 1,
    });
}

fn run() -> ExitCode {
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
                    error.insert("details".to_string(), details);
                }

                let out = serde_json::json!({ "error": error });
                match serialize_json(&out, cli.pretty) {
                    Ok(text) => eprintln!("{text}"),
                    Err(_) => {
                        const FALLBACK: &str = r#"{"error":{"code":"json","message":"failed to serialize json error output"}}"#;
                        let fallback = serde_json::json!({
                            "error": {
                                "code": "json",
                                "message": "failed to serialize json error output",
                            }
                        });
                        match serde_json::to_string(&fallback) {
                            Ok(text) => eprintln!("{text}"),
                            Err(_) => eprintln!("{FALLBACK}"),
                        }
                    }
                }
            }
        }
        return ExitCode::FAILURE;
    }

    ExitCode::SUCCESS
}

fn run_with_policy(cli: &Cli, policy: safe_fs_tools::SandboxPolicy) -> Result<(), CliError> {
    match &cli.command {
        Command::Read {
            start_line,
            end_line,
            ..
        } => validate_optional_line_range(*start_line, *end_line)?,
        Command::Edit {
            start_line,
            end_line,
            ..
        } => validate_required_line_range(*start_line, *end_line)?,
        _ => {}
    }

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
        } => serde_json::to_value(safe_fs_tools::ops::delete(
            &ctx,
            DeleteRequest {
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

    let out = serialize_json(&value, cli.pretty)?;
    write_stdout_line(&out)?;
    Ok(())
}

fn serialize_json(value: &serde_json::Value, pretty: bool) -> Result<String, CliError> {
    if pretty {
        Ok(serde_json::to_string_pretty(value)?)
    } else {
        Ok(serde_json::to_string(value)?)
    }
}

fn map_broken_pipe(result: std::io::Result<()>) -> Result<(), CliError> {
    match result {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::BrokenPipe => Ok(()),
        Err(err) => Err(CliError::Tool(safe_fs_tools::Error::Io(err))),
    }
}

fn write_stdout_line(line: &str) -> Result<(), CliError> {
    use std::io::Write;

    let mut stdout = std::io::stdout().lock();
    map_broken_pipe(stdout.write_all(line.as_bytes()))?;
    map_broken_pipe(stdout.write_all(b"\n"))?;
    map_broken_pipe(stdout.flush())
}

fn validate_optional_line_range(
    start_line: Option<u64>,
    end_line: Option<u64>,
) -> Result<(), CliError> {
    match (start_line, end_line) {
        (Some(start), Some(end)) if start > end => Err(CliError::Tool(
            safe_fs_tools::Error::InvalidPath("start_line must be <= end_line".to_string()),
        )),
        (Some(_), None) | (None, Some(_)) => {
            Err(CliError::Tool(safe_fs_tools::Error::InvalidPath(
                "start_line and end_line must be provided together".to_string(),
            )))
        }
        _ => Ok(()),
    }
}

fn validate_required_line_range(start_line: u64, end_line: u64) -> Result<(), CliError> {
    if start_line > end_line {
        return Err(CliError::Tool(safe_fs_tools::Error::InvalidPath(
            "start_line must be <= end_line".to_string(),
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests;
