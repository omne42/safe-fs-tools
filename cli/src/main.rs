use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand, ValueEnum};

mod command_exec;
mod error;
mod input;

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

    /// Pretty-print JSON responses (stdout and stderr).
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

fn main() -> ExitCode {
    run()
}

fn run() -> ExitCode {
    let cli = Cli::parse();
    let error_format = cli.error_format;
    let redact_paths = cli.redact_paths || cli.redact_paths_strict;
    let strict_redact_paths = cli.redact_paths_strict;
    let mut redaction = None::<PathRedaction>;

    let result = match safe_fs_tools::policy_io::load_policy(&cli.policy) {
        Ok(policy) => {
            redaction = build_redaction(&policy, error_format, redact_paths);
            command_exec::run_with_policy(&cli, policy)
        }
        Err(err) => Err(CliError::Tool(err)),
    };

    if let Err(err) = result {
        let rendered = render_error(
            &err,
            ErrorRenderCfg {
                format: error_format,
                pretty: cli.pretty,
                redact_paths,
                strict_redact_paths,
                redaction: redaction.as_ref(),
            },
        );
        if write_stderr_line(&rendered).is_err() {
            write_stderr_fallback();
        }
        return ExitCode::FAILURE;
    }

    ExitCode::SUCCESS
}

fn build_redaction(
    policy: &safe_fs_tools::policy::SandboxPolicy,
    error_format: ErrorFormat,
    redact_paths: bool,
) -> Option<PathRedaction> {
    if matches!(error_format, ErrorFormat::Json) && redact_paths {
        Some(PathRedaction::from_policy(policy))
    } else {
        None
    }
}

struct ErrorRenderCfg<'a> {
    format: ErrorFormat,
    pretty: bool,
    redact_paths: bool,
    strict_redact_paths: bool,
    redaction: Option<&'a PathRedaction>,
}

fn render_error(err: &CliError, cfg: ErrorRenderCfg<'_>) -> String {
    match cfg.format {
        ErrorFormat::Text => err.to_string(),
        ErrorFormat::Json => render_json_error(err, cfg),
    }
}

fn render_json_error(err: &CliError, cfg: ErrorRenderCfg<'_>) -> String {
    let mut error = serde_json::Map::new();
    error.insert(
        "code".to_string(),
        serde_json::Value::String(err.code().to_string()),
    );
    error.insert(
        "message".to_string(),
        serde_json::Value::String(match err {
            CliError::Tool(tool) => tool_public_message(
                tool,
                cfg.redaction,
                cfg.redact_paths,
                cfg.strict_redact_paths,
            ),
            CliError::Json(_) => err.to_string(),
        }),
    );

    if let CliError::Tool(tool) = err {
        let details = if cfg.redact_paths {
            tool_error_details_with(tool, cfg.redaction, true, cfg.strict_redact_paths)
        } else {
            tool_error_details(tool)
        };
        error.insert("details".to_string(), details);
    }

    let out = serde_json::json!({ "error": error });
    match serialize_json(&out, cfg.pretty) {
        Ok(text) => text,
        Err(_) => fallback_json_error(),
    }
}

fn fallback_json_error() -> String {
    const FALLBACK: &str =
        r#"{"error":{"code":"json","message":"failed to serialize json error output"}}"#;
    let fallback = serde_json::json!({
        "error": {
            "code": "json",
            "message": "failed to serialize json error output",
        }
    });
    match serde_json::to_string(&fallback) {
        Ok(text) => text,
        Err(_) => FALLBACK.to_string(),
    }
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

fn write_stderr_line(line: &str) -> Result<(), CliError> {
    use std::io::Write;

    let mut stderr = std::io::stderr().lock();
    map_broken_pipe(stderr.write_all(line.as_bytes()))?;
    map_broken_pipe(stderr.write_all(b"\n"))?;
    map_broken_pipe(stderr.flush())
}

fn write_stderr_fallback() {
    use std::io::Write;

    let mut stderr = std::io::stderr().lock();
    let _ = stderr.write_all(b"safe-fs-tools: failed to write error output to stderr\n");
    let _ = stderr.flush();
}

#[cfg(test)]
mod tests;
