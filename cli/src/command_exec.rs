use safe_fs_tools::ops::{
    Context, CopyFileRequest, DeleteRequest, EditRequest, GlobRequest, GrepRequest, ListDirRequest,
    MkdirRequest, MovePathRequest, PatchRequest, ReadRequest, StatRequest, WriteFileRequest,
};

use crate::error::CliError;
use crate::input::load_text_limited;
use crate::{Cli, Command};

pub(crate) fn run_with_policy(
    cli: &Cli,
    policy: safe_fs_tools::SandboxPolicy,
) -> Result<(), CliError> {
    validate_command_inputs(&cli.command)?;

    let max_patch_bytes = effective_max_patch_bytes(cli, &policy);
    let max_write_bytes = policy.limits.max_write_bytes;
    let ctx = Context::new(policy)?;

    let value = execute_command(&ctx, &cli.command, max_patch_bytes, max_write_bytes)?;
    let out = crate::serialize_json(&value, cli.pretty)?;
    crate::write_stdout_line(&out)?;
    Ok(())
}

fn effective_max_patch_bytes(cli: &Cli, policy: &safe_fs_tools::SandboxPolicy) -> u64 {
    let policy_patch_limit = policy
        .limits
        .max_patch_bytes
        .unwrap_or(policy.limits.max_read_bytes);
    cli.max_patch_bytes
        .map(|bytes| bytes.min(policy_patch_limit))
        .unwrap_or(policy_patch_limit)
}

fn validate_command_inputs(command: &Command) -> Result<(), CliError> {
    match command {
        Command::Read {
            start_line,
            end_line,
            ..
        } => validate_optional_line_range(*start_line, *end_line),
        Command::Edit {
            start_line,
            end_line,
            ..
        } => validate_required_line_range(*start_line, *end_line),
        _ => Ok(()),
    }
}

fn execute_command(
    ctx: &Context,
    command: &Command,
    max_patch_bytes: u64,
    max_write_bytes: u64,
) -> Result<serde_json::Value, CliError> {
    match command {
        Command::Read {
            root,
            path,
            start_line,
            end_line,
        } => serde_json::to_value(safe_fs_tools::ops::read_file(
            ctx,
            ReadRequest {
                root_id: root.clone(),
                path: path.clone(),
                start_line: *start_line,
                end_line: *end_line,
            },
        )?)
        .map_err(CliError::from),
        Command::ListDir {
            root,
            max_entries,
            path,
        } => serde_json::to_value(safe_fs_tools::ops::list_dir(
            ctx,
            ListDirRequest {
                root_id: root.clone(),
                path: path.clone(),
                max_entries: *max_entries,
            },
        )?)
        .map_err(CliError::from),
        Command::Glob { root, pattern } => serde_json::to_value(safe_fs_tools::ops::glob_paths(
            ctx,
            GlobRequest {
                root_id: root.clone(),
                pattern: pattern.clone(),
            },
        )?)
        .map_err(CliError::from),
        Command::Grep {
            root,
            query,
            regex,
            glob,
        } => serde_json::to_value(safe_fs_tools::ops::grep(
            ctx,
            GrepRequest {
                root_id: root.clone(),
                query: query.clone(),
                regex: *regex,
                glob: glob.clone(),
            },
        )?)
        .map_err(CliError::from),
        Command::Stat { root, path } => serde_json::to_value(safe_fs_tools::ops::stat(
            ctx,
            StatRequest {
                root_id: root.clone(),
                path: path.clone(),
            },
        )?)
        .map_err(CliError::from),
        Command::Edit {
            root,
            path,
            start_line,
            end_line,
            replacement,
        } => serde_json::to_value(safe_fs_tools::ops::edit_range(
            ctx,
            EditRequest {
                root_id: root.clone(),
                path: path.clone(),
                start_line: *start_line,
                end_line: *end_line,
                replacement: replacement.clone(),
            },
        )?)
        .map_err(CliError::from),
        Command::Patch {
            root,
            path,
            patch_file,
        } => serde_json::to_value(safe_fs_tools::ops::apply_unified_patch(
            ctx,
            PatchRequest {
                root_id: root.clone(),
                path: path.clone(),
                patch: load_text_limited(patch_file, max_patch_bytes)?,
            },
        )?)
        .map_err(CliError::from),
        Command::Mkdir {
            root,
            path,
            create_parents,
            ignore_existing,
        } => serde_json::to_value(safe_fs_tools::ops::mkdir(
            ctx,
            MkdirRequest {
                root_id: root.clone(),
                path: path.clone(),
                create_parents: *create_parents,
                ignore_existing: *ignore_existing,
            },
        )?)
        .map_err(CliError::from),
        Command::Write {
            root,
            path,
            content_file,
            overwrite,
            create_parents,
        } => serde_json::to_value(safe_fs_tools::ops::write_file(
            ctx,
            WriteFileRequest {
                root_id: root.clone(),
                path: path.clone(),
                content: load_text_limited(content_file, max_write_bytes)?,
                overwrite: *overwrite,
                create_parents: *create_parents,
            },
        )?)
        .map_err(CliError::from),
        Command::Delete {
            root,
            path,
            recursive,
            ignore_missing,
        } => serde_json::to_value(safe_fs_tools::ops::delete(
            ctx,
            DeleteRequest {
                root_id: root.clone(),
                path: path.clone(),
                recursive: *recursive,
                ignore_missing: *ignore_missing,
            },
        )?)
        .map_err(CliError::from),
        Command::Move {
            root,
            from,
            to,
            overwrite,
            create_parents,
        } => serde_json::to_value(safe_fs_tools::ops::move_path(
            ctx,
            MovePathRequest {
                root_id: root.clone(),
                from: from.clone(),
                to: to.clone(),
                overwrite: *overwrite,
                create_parents: *create_parents,
            },
        )?)
        .map_err(CliError::from),
        Command::CopyFile {
            root,
            from,
            to,
            overwrite,
            create_parents,
        } => serde_json::to_value(safe_fs_tools::ops::copy_file(
            ctx,
            CopyFileRequest {
                root_id: root.clone(),
                from: from.clone(),
                to: to.clone(),
                overwrite: *overwrite,
                create_parents: *create_parents,
            },
        )?)
        .map_err(CliError::from),
    }
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
