use std::path::Path;

use safe_fs_tools::ops::{
    Context, CopyFileRequest, DeleteRequest, EditRequest, GlobRequest, GlobResponse, GrepRequest,
    GrepResponse, ListDirEntryKind, ListDirRequest, ListDirResponse, MkdirRequest, MovePathRequest,
    PatchRequest, ReadRequest, ScanLimitReason, StatRequest, WriteFileRequest,
};

use crate::error::CliError;
use crate::input::load_text_limited;
use crate::{Cli, Command};

pub(crate) fn run_with_policy(
    cli: Cli,
    policy: safe_fs_tools::SandboxPolicy,
) -> Result<(), CliError> {
    let max_patch_bytes = effective_max_patch_bytes(&cli, &policy);
    let max_write_bytes = policy.limits.max_write_bytes;
    let ctx = Context::new(policy)?;
    let Cli {
        command, pretty, ..
    } = cli;

    let value = execute_command(&ctx, command, max_patch_bytes, max_write_bytes)?;
    let out = crate::serialize_json(&value, pretty)?;
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

fn path_to_lossy_string(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

fn list_dir_entry_kind_json_value(kind: ListDirEntryKind) -> serde_json::Value {
    let value = match kind {
        ListDirEntryKind::File => "file",
        ListDirEntryKind::Dir => "dir",
        ListDirEntryKind::Symlink => "symlink",
        ListDirEntryKind::Other => "other",
    };
    serde_json::Value::String(value.to_string())
}

fn list_dir_response_to_json_value(
    response: ListDirResponse,
) -> Result<serde_json::Value, CliError> {
    let mut map = serde_json::Map::with_capacity(5);
    map.insert(
        "path".to_string(),
        serde_json::Value::String(path_to_lossy_string(response.path.as_path())),
    );
    if let Some(requested_path) = response.requested_path {
        map.insert(
            "requested_path".to_string(),
            serde_json::Value::String(path_to_lossy_string(requested_path.as_path())),
        );
    }
    let mut entries = Vec::with_capacity(response.entries.len());
    for entry in response.entries {
        let mut item = serde_json::Map::with_capacity(4);
        item.insert(
            "path".to_string(),
            serde_json::Value::String(path_to_lossy_string(entry.path.as_path())),
        );
        item.insert("name".to_string(), serde_json::Value::String(entry.name));
        item.insert(
            "type".to_string(),
            list_dir_entry_kind_json_value(entry.kind),
        );
        item.insert(
            "size_bytes".to_string(),
            serde_json::Value::from(entry.size_bytes),
        );
        entries.push(serde_json::Value::Object(item));
    }
    map.insert("entries".to_string(), serde_json::Value::Array(entries));
    map.insert(
        "truncated".to_string(),
        serde_json::Value::Bool(response.truncated),
    );
    map.insert(
        "skipped_io_errors".to_string(),
        serde_json::Value::from(response.skipped_io_errors),
    );
    Ok(serde_json::Value::Object(map))
}

fn glob_response_to_json_value(response: GlobResponse) -> Result<serde_json::Value, CliError> {
    let mut map = serde_json::Map::with_capacity(10);
    let matches = response
        .matches
        .into_iter()
        .map(|path| serde_json::Value::String(path_to_lossy_string(path.as_path())))
        .collect();
    map.insert("matches".to_string(), serde_json::Value::Array(matches));
    map.insert(
        "truncated".to_string(),
        serde_json::Value::Bool(response.truncated),
    );
    map.insert(
        "scanned_files".to_string(),
        serde_json::Value::from(response.scanned_files),
    );
    map.insert(
        "scan_limit_reached".to_string(),
        serde_json::Value::Bool(response.scan_limit_reached),
    );
    insert_scan_limit_reason(&mut map, response.scan_limit_reason)?;
    map.insert(
        "elapsed_ms".to_string(),
        serde_json::Value::from(response.elapsed_ms),
    );
    map.insert(
        "scanned_entries".to_string(),
        serde_json::Value::from(response.scanned_entries),
    );
    map.insert(
        "skipped_walk_errors".to_string(),
        serde_json::Value::from(response.skipped_walk_errors),
    );
    map.insert(
        "skipped_io_errors".to_string(),
        serde_json::Value::from(response.skipped_io_errors),
    );
    map.insert(
        "skipped_dangling_symlink_targets".to_string(),
        serde_json::Value::from(response.skipped_dangling_symlink_targets),
    );
    Ok(serde_json::Value::Object(map))
}

fn insert_scan_limit_reason(
    map: &mut serde_json::Map<String, serde_json::Value>,
    scan_limit_reason: Option<ScanLimitReason>,
) -> Result<(), CliError> {
    if let Some(reason) = scan_limit_reason {
        map.insert(
            "scan_limit_reason".to_string(),
            serde_json::to_value(reason).map_err(CliError::from)?,
        );
    }
    Ok(())
}

fn grep_response_to_json_value(response: GrepResponse) -> Result<serde_json::Value, CliError> {
    let mut map = serde_json::Map::with_capacity(12);
    let mut matches = Vec::with_capacity(response.matches.len());
    for item in response.matches {
        let mut match_item = serde_json::Map::with_capacity(4);
        match_item.insert(
            "path".to_string(),
            serde_json::Value::String(path_to_lossy_string(item.path.as_path())),
        );
        match_item.insert("line".to_string(), serde_json::Value::from(item.line));
        match_item.insert("text".to_string(), serde_json::Value::String(item.text));
        match_item.insert(
            "line_truncated".to_string(),
            serde_json::Value::Bool(item.line_truncated),
        );
        matches.push(serde_json::Value::Object(match_item));
    }
    map.insert("matches".to_string(), serde_json::Value::Array(matches));
    map.insert(
        "truncated".to_string(),
        serde_json::Value::Bool(response.truncated),
    );
    map.insert(
        "skipped_too_large_files".to_string(),
        serde_json::Value::from(response.skipped_too_large_files),
    );
    map.insert(
        "skipped_non_utf8_files".to_string(),
        serde_json::Value::from(response.skipped_non_utf8_files),
    );
    map.insert(
        "scanned_files".to_string(),
        serde_json::Value::from(response.scanned_files),
    );
    map.insert(
        "scan_limit_reached".to_string(),
        serde_json::Value::Bool(response.scan_limit_reached),
    );
    insert_scan_limit_reason(&mut map, response.scan_limit_reason)?;
    map.insert(
        "elapsed_ms".to_string(),
        serde_json::Value::from(response.elapsed_ms),
    );
    map.insert(
        "scanned_entries".to_string(),
        serde_json::Value::from(response.scanned_entries),
    );
    map.insert(
        "skipped_walk_errors".to_string(),
        serde_json::Value::from(response.skipped_walk_errors),
    );
    map.insert(
        "skipped_io_errors".to_string(),
        serde_json::Value::from(response.skipped_io_errors),
    );
    map.insert(
        "skipped_dangling_symlink_targets".to_string(),
        serde_json::Value::from(response.skipped_dangling_symlink_targets),
    );
    Ok(serde_json::Value::Object(map))
}

fn execute_command(
    ctx: &Context,
    command: Command,
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
                root_id: root,
                path,
                start_line,
                end_line,
            },
        )?)
        .map_err(CliError::from),
        Command::ListDir {
            root,
            max_entries,
            path,
        } => list_dir_response_to_json_value(safe_fs_tools::ops::list_dir(
            ctx,
            ListDirRequest {
                root_id: root,
                path,
                max_entries,
            },
        )?),
        Command::Glob { root, pattern } => {
            glob_response_to_json_value(safe_fs_tools::ops::glob_paths(
                ctx,
                GlobRequest {
                    root_id: root,
                    pattern,
                },
            )?)
        }
        Command::Grep {
            root,
            query,
            regex,
            glob,
        } => grep_response_to_json_value(safe_fs_tools::ops::grep(
            ctx,
            GrepRequest {
                root_id: root,
                query,
                regex,
                glob,
            },
        )?),
        Command::Stat { root, path } => serde_json::to_value(safe_fs_tools::ops::stat(
            ctx,
            StatRequest {
                root_id: root,
                path,
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
                root_id: root,
                path,
                start_line,
                end_line,
                replacement,
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
                root.as_str(),
                ctx.policy().permissions.patch,
                "patch is disabled by policy",
                "patch",
            )?;
            serde_json::to_value(safe_fs_tools::ops::apply_unified_patch(
                ctx,
                PatchRequest {
                    root_id: root,
                    path,
                    patch: load_text_limited(&patch_file, max_patch_bytes)?,
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
                root_id: root,
                path,
                create_parents,
                ignore_existing,
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
                root.as_str(),
                ctx.policy().permissions.write,
                "write is disabled by policy",
                "write",
            )?;
            serde_json::to_value(safe_fs_tools::ops::write_file(
                ctx,
                WriteFileRequest {
                    root_id: root,
                    path,
                    content: load_text_limited(&content_file, max_write_bytes)?,
                    overwrite,
                    create_parents,
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
                root_id: root,
                path,
                recursive,
                ignore_missing,
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
                root_id: root,
                from,
                to,
                overwrite,
                create_parents,
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
                root_id: root,
                from,
                to,
                overwrite,
                create_parents,
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

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    #[cfg(unix)]
    use std::os::unix::ffi::OsStringExt;

    use super::{
        glob_response_to_json_value, grep_response_to_json_value, list_dir_response_to_json_value,
    };

    #[cfg(unix)]
    fn non_utf8_path() -> PathBuf {
        PathBuf::from(std::ffi::OsString::from_vec(vec![b'f', b'o', 0x80]))
    }

    #[cfg(unix)]
    #[test]
    fn list_dir_json_uses_lossy_paths_for_non_utf8_entries() {
        let path = non_utf8_path();
        let value = list_dir_response_to_json_value(safe_fs_tools::ops::ListDirResponse {
            path: PathBuf::from("."),
            requested_path: Some(PathBuf::from(".")),
            entries: vec![safe_fs_tools::ops::ListDirEntry {
                path: path.clone(),
                name: "x".to_string(),
                kind: safe_fs_tools::ops::ListDirEntryKind::File,
                size_bytes: 1,
            }],
            truncated: false,
            skipped_io_errors: 0,
        })
        .expect("list_dir response should serialize");

        assert_eq!(
            value["entries"][0]["path"].as_str(),
            Some(path.to_string_lossy().as_ref())
        );
    }

    #[cfg(unix)]
    #[test]
    fn glob_json_uses_lossy_paths_for_non_utf8_matches() {
        let path = non_utf8_path();
        let value = glob_response_to_json_value(safe_fs_tools::ops::GlobResponse {
            matches: vec![path.clone()],
            truncated: false,
            scanned_files: 1,
            scan_limit_reached: false,
            scan_limit_reason: None,
            elapsed_ms: 0,
            scanned_entries: 1,
            skipped_walk_errors: 0,
            skipped_io_errors: 0,
            skipped_dangling_symlink_targets: 0,
        })
        .expect("glob response should serialize");

        assert_eq!(
            value["matches"][0].as_str(),
            Some(path.to_string_lossy().as_ref())
        );
    }

    #[cfg(unix)]
    #[test]
    fn grep_json_uses_lossy_paths_for_non_utf8_matches() {
        let path = non_utf8_path();
        let value = grep_response_to_json_value(safe_fs_tools::ops::GrepResponse {
            matches: vec![safe_fs_tools::ops::GrepMatch {
                path: path.clone(),
                line: 1,
                text: "hit".to_string(),
                line_truncated: false,
            }],
            truncated: false,
            skipped_too_large_files: 0,
            skipped_non_utf8_files: 0,
            scanned_files: 1,
            scan_limit_reached: false,
            scan_limit_reason: None,
            elapsed_ms: 0,
            scanned_entries: 1,
            skipped_walk_errors: 0,
            skipped_io_errors: 0,
            skipped_dangling_symlink_targets: 0,
        })
        .expect("grep response should serialize");

        assert_eq!(
            value["matches"][0]["path"].as_str(),
            Some(path.to_string_lossy().as_ref())
        );
    }
}
