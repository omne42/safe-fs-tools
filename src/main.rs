use std::io::Read;
use std::path::PathBuf;

use clap::{Parser, Subcommand};

use safe_fs_tools::ops::{
    Context, DeleteRequest, EditRequest, GlobRequest, GrepRequest, PatchRequest, ReadRequest,
};
use safe_fs_tools::policy::SandboxPolicy;
use safe_fs_tools::{Error, Result};

#[derive(Debug, Parser)]
#[command(name = "safe-fs-tools")]
#[command(
    about = "Safe filesystem tools (read/glob/grep/edit/patch/delete) with explicit sandbox policy."
)]
struct Cli {
    #[arg(long)]
    policy: PathBuf,

    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    Read {
        #[arg(long)]
        root: String,
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
    if let Err(err) = run() {
        eprintln!("{err}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let cli = Cli::parse();
    let policy = load_policy(&cli.policy)?;
    let ctx = Context::new(policy)?;

    let value = match cli.command {
        Command::Read { root, path } => serde_json::to_value(safe_fs_tools::ops::read_file(
            &ctx,
            ReadRequest {
                root_id: root,
                path,
            },
        )?)?,
        Command::Glob { root, pattern } => serde_json::to_value(safe_fs_tools::ops::glob_paths(
            &ctx,
            GlobRequest {
                root_id: root,
                pattern,
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
                root_id: root,
                query,
                regex,
                glob,
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
                root_id: root,
                path,
                start_line,
                end_line,
                replacement,
            },
        )?)?,
        Command::Patch {
            root,
            path,
            patch_file,
        } => serde_json::to_value(safe_fs_tools::ops::apply_unified_patch(
            &ctx,
            PatchRequest {
                root_id: root,
                path,
                patch: load_text(&patch_file)?,
            },
        )?)?,
        Command::Delete { root, path } => serde_json::to_value(safe_fs_tools::ops::delete_file(
            &ctx,
            DeleteRequest {
                root_id: root,
                path,
            },
        )?)?,
    };

    println!("{}", serde_json::to_string_pretty(&value)?);
    Ok(())
}

fn load_policy(path: &PathBuf) -> Result<SandboxPolicy> {
    let raw = std::fs::read_to_string(path)?;
    match path.extension().and_then(|ext| ext.to_str()) {
        Some("json") => serde_json::from_str(&raw)
            .map_err(|err| Error::InvalidPolicy(format!("invalid json policy: {err}"))),
        Some("toml") | None => toml::from_str(&raw)
            .map_err(|err| Error::InvalidPolicy(format!("invalid toml policy: {err}"))),
        Some(other) => Err(Error::InvalidPolicy(format!(
            "unsupported policy format {other:?}; expected .toml or .json"
        ))),
    }
}

fn load_text(path: &PathBuf) -> Result<String> {
    if path.as_os_str() == "-" {
        let mut out = String::new();
        std::io::stdin().read_to_string(&mut out)?;
        return Ok(out);
    }
    Ok(std::fs::read_to_string(path)?)
}
