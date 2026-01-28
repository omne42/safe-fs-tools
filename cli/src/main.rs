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
                let out = serde_json::json!({
                    "error": {
                        "code": err.code(),
                        "message": err.to_string(),
                    }
                });
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
    let ctx = Context::from_policy_path(&cli.policy)?;

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
                patch: load_text(patch_file)?,
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

fn load_text(path: &PathBuf) -> Result<String, safe_fs_tools::Error> {
    if path.as_os_str() == "-" {
        let mut out = String::new();
        std::io::stdin().read_to_string(&mut out)?;
        return Ok(out);
    }
    Ok(std::fs::read_to_string(path)?)
}
