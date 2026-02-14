use std::path::{Path, PathBuf};

#[derive(Debug)]
pub(crate) enum CliError {
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

impl std::error::Error for CliError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            CliError::Tool(err) => Some(err),
            CliError::Json(err) => Some(err),
        }
    }
}

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
    pub(crate) fn code(&self) -> &'static str {
        match self {
            CliError::Tool(err) => err.code(),
            CliError::Json(_) => "json",
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct PathRedaction {
    roots: Vec<PathBuf>,
    canonical_roots: Vec<PathBuf>,
}

impl PathRedaction {
    pub(crate) fn from_policy(policy: &safe_fs_tools::SandboxPolicy) -> Self {
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RedactionMode {
    Off,
    BestEffort,
    Strict,
}

impl RedactionMode {
    fn from_flags(redact_paths: bool, strict_redact_paths: bool) -> Self {
        if strict_redact_paths {
            Self::Strict
        } else if redact_paths {
            Self::BestEffort
        } else {
            Self::Off
        }
    }

    fn redact_paths(self) -> bool {
        !matches!(self, Self::Off)
    }
}

pub(crate) fn format_path_for_error(
    path: &Path,
    redaction: Option<&PathRedaction>,
    redact_paths: bool,
    strict_redact_paths: bool,
) -> String {
    let mode = RedactionMode::from_flags(redact_paths, strict_redact_paths);
    format_path_for_error_with_mode(path, redaction, mode)
}

fn format_path_for_error_with_mode(
    path: &Path,
    redaction: Option<&PathRedaction>,
    mode: RedactionMode,
) -> String {
    if !mode.redact_paths() {
        return path.display().to_string();
    }

    if matches!(mode, RedactionMode::Strict) {
        return "<redacted>".to_string();
    }

    if !path.is_absolute() {
        return path
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_else(|| "<redacted>".to_string());
    }

    if let Some(redaction) = redaction {
        let mut best_match: Option<(usize, PathBuf)> = None;
        for root in redaction
            .roots
            .iter()
            .chain(redaction.canonical_roots.iter())
        {
            if let Some(relative) =
                safe_fs_tools::path_utils::strip_prefix_case_insensitive(path, root)
            {
                let prefix_len = root.components().count();
                let should_replace = best_match
                    .as_ref()
                    .map(|(best_len, _)| prefix_len > *best_len)
                    .unwrap_or(true);
                if should_replace {
                    best_match = Some((prefix_len, relative));
                }
            }
        }

        if let Some((_, relative)) = best_match {
            if relative.as_os_str().is_empty() {
                return ".".to_string();
            }
            return relative.display().to_string();
        }
    }

    path.file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| "<redacted>".to_string())
}

pub(crate) fn tool_error_details(tool: &safe_fs_tools::Error) -> serde_json::Value {
    tool_error_details_with(tool, None, false, false)
}

fn details_map(kind: &str) -> serde_json::Map<String, serde_json::Value> {
    let mut out = serde_json::Map::new();
    out.insert(
        "kind".to_string(),
        serde_json::Value::String(kind.to_string()),
    );
    out
}

pub(crate) fn tool_error_details_with(
    tool: &safe_fs_tools::Error,
    redaction: Option<&PathRedaction>,
    redact_paths: bool,
    strict_redact_paths: bool,
) -> serde_json::Value {
    let mode = RedactionMode::from_flags(redact_paths, strict_redact_paths);
    tool_error_details_with_mode(tool, redaction, mode)
}

fn tool_error_details_with_mode(
    tool: &safe_fs_tools::Error,
    redaction: Option<&PathRedaction>,
    mode: RedactionMode,
) -> serde_json::Value {
    let redact_paths = mode.redact_paths();

    match tool {
        safe_fs_tools::Error::Io(err) => {
            let mut out = details_map("io");
            out.insert(
                "io_kind".to_string(),
                serde_json::Value::String(format!("{:?}", err.kind())),
            );
            if let Some(raw_os_error) = err.raw_os_error() {
                out.insert("raw_os_error".to_string(), serde_json::json!(raw_os_error));
            }
            if !redact_paths {
                out.insert(
                    "message".to_string(),
                    serde_json::Value::String(err.to_string()),
                );
            }
            serde_json::Value::Object(out)
        }
        safe_fs_tools::Error::IoPath { op, path, source } => {
            let mut out = details_map("io_path");
            out.insert("op".to_string(), serde_json::Value::String(op.to_string()));
            out.insert(
                "path".to_string(),
                serde_json::Value::String(format_path_for_error_with_mode(path, redaction, mode)),
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
            serde_json::Value::Object(out)
        }
        safe_fs_tools::Error::InvalidPolicy(message) => {
            let mut out = details_map("invalid_policy");
            out.insert(
                "message".to_string(),
                serde_json::Value::String(if redact_paths {
                    "invalid policy".to_string()
                } else {
                    message.clone()
                }),
            );
            serde_json::Value::Object(out)
        }
        safe_fs_tools::Error::InvalidPath(message) => {
            let mut out = details_map("invalid_path");
            out.insert(
                "message".to_string(),
                serde_json::Value::String(if redact_paths {
                    "invalid path".to_string()
                } else {
                    message.clone()
                }),
            );
            serde_json::Value::Object(out)
        }
        safe_fs_tools::Error::RootNotFound(root_id) => serde_json::json!({
            "kind": "root_not_found",
            "root_id": root_id,
        }),
        safe_fs_tools::Error::OutsideRoot { root_id, path } => serde_json::json!({
            "kind": "outside_root",
            "root_id": root_id,
            "path": format_path_for_error_with_mode(path, redaction, mode),
        }),
        safe_fs_tools::Error::NotPermitted(message) => serde_json::json!({
            "kind": "not_permitted",
            "message": if redact_paths {
                "not permitted".to_string()
            } else {
                message.clone()
            },
        }),
        safe_fs_tools::Error::SecretPathDenied(path) => serde_json::json!({
            "kind": "secret_path_denied",
            "path": format_path_for_error_with_mode(path, redaction, mode),
        }),
        safe_fs_tools::Error::FileTooLarge {
            path,
            size_bytes,
            max_bytes,
        } => serde_json::json!({
            "kind": "file_too_large",
            "path": format_path_for_error_with_mode(path, redaction, mode),
            "size_bytes": size_bytes,
            "max_bytes": max_bytes,
        }),
        safe_fs_tools::Error::InvalidUtf8 { path, .. } => serde_json::json!({
            "kind": "invalid_utf8",
            "path": format_path_for_error_with_mode(path, redaction, mode),
        }),
        safe_fs_tools::Error::Patch(message) => {
            if redact_paths {
                serde_json::json!({
                    "kind": "patch",
                })
            } else {
                serde_json::json!({
                    "kind": "patch",
                    "message": message,
                })
            }
        }
        safe_fs_tools::Error::InvalidRegex { pattern, source } => {
            let mut out = details_map("invalid_regex");
            out.insert(
                "message".to_string(),
                serde_json::Value::String(if redact_paths {
                    "invalid regex".to_string()
                } else {
                    format!("invalid regex pattern {pattern:?}: {source}")
                }),
            );
            serde_json::Value::Object(out)
        }
        safe_fs_tools::Error::InputTooLarge {
            size_bytes,
            max_bytes,
        } => serde_json::json!({
            "kind": "input_too_large",
            "size_bytes": size_bytes,
            "max_bytes": max_bytes,
        }),
        safe_fs_tools::Error::WalkDirRoot { path, source } => {
            let mut out = details_map("walkdir_root");
            out.insert(
                "path".to_string(),
                serde_json::Value::String(format_path_for_error_with_mode(path, redaction, mode)),
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
            serde_json::Value::Object(out)
        }
        safe_fs_tools::Error::WalkDir(err) => {
            if redact_paths {
                let mut out = details_map("walkdir");
                if let Some(path) = err.path() {
                    out.insert(
                        "path".to_string(),
                        serde_json::Value::String(format_path_for_error_with_mode(
                            path, redaction, mode,
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
                serde_json::Value::Object(out)
            } else {
                serde_json::json!({
                    "kind": "walkdir",
                    "message": err.to_string(),
                })
            }
        }
        _ => {
            if redact_paths {
                serde_json::json!({
                    "kind": tool.code(),
                })
            } else {
                serde_json::json!({
                    "kind": tool.code(),
                    "message": tool.to_string(),
                })
            }
        }
    }
}

pub(crate) fn tool_public_message(
    tool: &safe_fs_tools::Error,
    redaction: Option<&PathRedaction>,
    redact_paths: bool,
    strict_redact_paths: bool,
) -> String {
    let mode = RedactionMode::from_flags(redact_paths, strict_redact_paths);
    tool_public_message_with_mode(tool, redaction, mode)
}

fn tool_public_message_with_mode(
    tool: &safe_fs_tools::Error,
    redaction: Option<&PathRedaction>,
    mode: RedactionMode,
) -> String {
    if !mode.redact_paths() {
        return tool.to_string();
    }

    match tool {
        safe_fs_tools::Error::Io(_) => "io error".to_string(),
        safe_fs_tools::Error::IoPath { op, path, .. } => {
            let path = format_path_for_error_with_mode(path, redaction, mode);
            format!("io error during {op} ({path})")
        }
        safe_fs_tools::Error::InvalidPolicy(_) => "invalid policy".to_string(),
        safe_fs_tools::Error::InvalidPath(_) => "invalid path".to_string(),
        safe_fs_tools::Error::RootNotFound(root_id) => format!("root not found: {root_id}"),
        safe_fs_tools::Error::OutsideRoot { root_id, .. } => {
            format!("path resolves outside root '{root_id}'")
        }
        safe_fs_tools::Error::NotPermitted(_) => "not permitted".to_string(),
        safe_fs_tools::Error::SecretPathDenied(path) => {
            let path = format_path_for_error_with_mode(path, redaction, mode);
            format!("path is denied by secret rules: {path}")
        }
        safe_fs_tools::Error::FileTooLarge {
            path,
            size_bytes,
            max_bytes,
        } => {
            let path = format_path_for_error_with_mode(path, redaction, mode);
            format!("file is too large ({size_bytes} bytes; max {max_bytes} bytes): {path}")
        }
        safe_fs_tools::Error::InvalidUtf8 { path, .. } => {
            let path = format_path_for_error_with_mode(path, redaction, mode);
            format!("invalid utf-8 in file: {path}")
        }
        safe_fs_tools::Error::Patch(_) => "failed to apply patch".to_string(),
        safe_fs_tools::Error::InvalidRegex { .. } => "invalid regex".to_string(),
        safe_fs_tools::Error::InputTooLarge { .. } => tool.to_string(),
        safe_fs_tools::Error::WalkDirRoot { .. } | safe_fs_tools::Error::WalkDir(_) => {
            "walkdir error".to_string()
        }
        _ => tool.code().to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::{PathRedaction, RedactionMode, format_path_for_error_with_mode};
    use std::path::{Path, PathBuf};

    #[test]
    fn strict_flag_without_redact_paths_still_uses_strict_mode() {
        let mode = RedactionMode::from_flags(false, true);
        assert_eq!(mode, RedactionMode::Strict);
        assert!(mode.redact_paths());
    }

    #[test]
    fn strict_mode_never_returns_raw_path() {
        let path = Path::new("/tmp/secret.txt");
        let redaction = PathRedaction {
            roots: vec![PathBuf::from("/tmp")],
            canonical_roots: Vec::new(),
        };
        let formatted =
            format_path_for_error_with_mode(path, Some(&redaction), RedactionMode::Strict);
        assert_eq!(formatted, "<redacted>");
    }
}
