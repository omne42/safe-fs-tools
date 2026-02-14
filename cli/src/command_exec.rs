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
        } => {
            preflight_mutating_target(
                ctx,
                root,
                ctx.policy().permissions.patch,
                "patch is disabled by policy",
                "patch",
            )?;
            serde_json::to_value(safe_fs_tools::ops::apply_unified_patch(
                ctx,
                PatchRequest {
                    root_id: root.clone(),
                    path: path.clone(),
                    patch: load_text_limited(patch_file, max_patch_bytes)?,
                },
            )?)
        }
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
        } => {
            preflight_mutating_target(
                ctx,
                root,
                ctx.policy().permissions.write,
                "write is disabled by policy",
                "write",
            )?;
            serde_json::to_value(safe_fs_tools::ops::write_file(
                ctx,
                WriteFileRequest {
                    root_id: root.clone(),
                    path: path.clone(),
                    content: load_text_limited(content_file, max_write_bytes)?,
                    overwrite: *overwrite,
                    create_parents: *create_parents,
                },
            )?)
        }
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

fn preflight_mutating_target(
    ctx: &Context,
    root_id: &str,
    operation_enabled: bool,
    disabled_message: &'static str,
    operation_name: &'static str,
) -> Result<(), CliError> {
    if !operation_enabled {
        return Err(safe_fs_tools::Error::NotPermitted(disabled_message.to_string()).into());
    }

    let root = ctx.policy().root(root_id)?;
    if !matches!(root.mode, safe_fs_tools::RootMode::ReadWrite) {
        return Err(safe_fs_tools::Error::NotPermitted(format!(
            "{operation_name} is not allowed: root {root_id} is read_only"
        ))
        .into());
    }

    Ok(())
}
