use std::path::{Path, PathBuf};

const CLI_ERROR_CODE_JSON: &str = "json";

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
            CliError::Json(_) => CLI_ERROR_CODE_JSON,
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
        let mut roots = Vec::<PathBuf>::with_capacity(policy.roots.len());
        let mut canonical_roots = Vec::<PathBuf>::with_capacity(policy.roots.len());

        for root in &policy.roots {
            roots.push(root.path.clone());
            if let Ok(canonical) = root.path.canonicalize()
                && canonical != root.path
            {
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

#[cfg(test)]
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
        return best_effort_leaf(path);
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

    best_effort_leaf(path)
}

fn best_effort_leaf(path: &Path) -> String {
    path.file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| "<redacted>".to_string())
}

pub(crate) fn tool_error_details(tool: &safe_fs_tools::Error) -> serde_json::Value {
    tool_error_details_with(tool, None, false, false)
}

fn details_map(kind: &'static str) -> serde_json::Map<String, serde_json::Value> {
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
    render_tool_error(tool, redaction, redact_paths, strict_redact_paths).details
}

pub(crate) fn tool_public_message(
    tool: &safe_fs_tools::Error,
    redaction: Option<&PathRedaction>,
    redact_paths: bool,
    strict_redact_paths: bool,
) -> String {
    render_tool_error(tool, redaction, redact_paths, strict_redact_paths).public_message
}

pub(crate) fn render_tool_error(
    tool: &safe_fs_tools::Error,
    redaction: Option<&PathRedaction>,
    redact_paths: bool,
    strict_redact_paths: bool,
) -> ToolErrorRender {
    let mode = RedactionMode::from_flags(redact_paths, strict_redact_paths);
    render_tool_error_with_mode(tool, redaction, mode)
}

#[derive(Debug)]
pub(crate) struct ToolErrorRender {
    pub(crate) details: serde_json::Value,
    pub(crate) public_message: String,
}

fn render_tool_error_with_mode(
    tool: &safe_fs_tools::Error,
    redaction: Option<&PathRedaction>,
    mode: RedactionMode,
) -> ToolErrorRender {
    let redact_paths = mode.redact_paths();

    match tool {
        safe_fs_tools::Error::Io(err) => {
            let mut out = details_map(safe_fs_tools::Error::CODE_IO);
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

            ToolErrorRender {
                details: serde_json::Value::Object(out),
                public_message: if redact_paths {
                    "io error".to_string()
                } else {
                    tool.to_string()
                },
            }
        }
        safe_fs_tools::Error::IoPath { op, path, source } => {
            let rendered_path = format_path_for_error_with_mode(path, redaction, mode);
            let mut out = details_map(safe_fs_tools::Error::CODE_IO_PATH);
            out.insert("op".to_string(), serde_json::Value::String(op.to_string()));
            out.insert(
                "path".to_string(),
                serde_json::Value::String(rendered_path.clone()),
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

            ToolErrorRender {
                details: serde_json::Value::Object(out),
                public_message: if redact_paths {
                    format!("io error during {op} ({rendered_path})")
                } else {
                    tool.to_string()
                },
            }
        }
        safe_fs_tools::Error::CommittedButUnsynced { op, path, source } => {
            let rendered_path = format_path_for_error_with_mode(path, redaction, mode);
            let mut out = details_map(safe_fs_tools::Error::CODE_COMMITTED_UNSYNCED);
            out.insert("op".to_string(), serde_json::Value::String(op.to_string()));
            out.insert(
                "path".to_string(),
                serde_json::Value::String(rendered_path.clone()),
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

            ToolErrorRender {
                details: serde_json::Value::Object(out),
                public_message: if redact_paths {
                    format!(
                        "filesystem update committed but parent sync failed during {op} ({rendered_path})"
                    )
                } else {
                    tool.to_string()
                },
            }
        }
        safe_fs_tools::Error::InvalidPolicy(message) => {
            let mut out = details_map(safe_fs_tools::Error::CODE_INVALID_POLICY);
            out.insert(
                "message".to_string(),
                serde_json::Value::String(if redact_paths {
                    "invalid policy".to_string()
                } else {
                    message.clone()
                }),
            );
            ToolErrorRender {
                details: serde_json::Value::Object(out),
                public_message: if redact_paths {
                    "invalid policy".to_string()
                } else {
                    tool.to_string()
                },
            }
        }
        safe_fs_tools::Error::InvalidPath(message) => {
            let mut out = details_map(safe_fs_tools::Error::CODE_INVALID_PATH);
            out.insert(
                "message".to_string(),
                serde_json::Value::String(if redact_paths {
                    "invalid path".to_string()
                } else {
                    message.clone()
                }),
            );
            ToolErrorRender {
                details: serde_json::Value::Object(out),
                public_message: if redact_paths {
                    "invalid path".to_string()
                } else {
                    tool.to_string()
                },
            }
        }
        safe_fs_tools::Error::RootNotFound(root_id) => {
            let rendered_root_id = format_root_id_for_error(root_id, mode);
            let mut out = details_map(safe_fs_tools::Error::CODE_ROOT_NOT_FOUND);
            out.insert(
                "root_id".to_string(),
                serde_json::Value::String(rendered_root_id.clone()),
            );
            ToolErrorRender {
                details: serde_json::Value::Object(out),
                public_message: if redact_paths {
                    format!("root not found: {rendered_root_id}")
                } else {
                    tool.to_string()
                },
            }
        }
        safe_fs_tools::Error::OutsideRoot { root_id, path } => {
            let rendered_root_id = format_root_id_for_error(root_id, mode);
            let mut out = details_map(safe_fs_tools::Error::CODE_OUTSIDE_ROOT);
            out.insert(
                "root_id".to_string(),
                serde_json::Value::String(rendered_root_id.clone()),
            );
            out.insert(
                "path".to_string(),
                serde_json::Value::String(format_path_for_error_with_mode(path, redaction, mode)),
            );
            ToolErrorRender {
                details: serde_json::Value::Object(out),
                public_message: if redact_paths {
                    format!("path resolves outside root '{rendered_root_id}'")
                } else {
                    tool.to_string()
                },
            }
        }
        safe_fs_tools::Error::NotPermitted(message) => {
            let mut out = details_map(safe_fs_tools::Error::CODE_NOT_PERMITTED);
            out.insert(
                "message".to_string(),
                serde_json::Value::String(if redact_paths {
                    "not permitted".to_string()
                } else {
                    message.clone()
                }),
            );
            ToolErrorRender {
                details: serde_json::Value::Object(out),
                public_message: if redact_paths {
                    "not permitted".to_string()
                } else {
                    tool.to_string()
                },
            }
        }
        safe_fs_tools::Error::SecretPathDenied(path) => {
            let rendered_path = format_path_for_error_with_mode(path, redaction, mode);
            let mut out = details_map(safe_fs_tools::Error::CODE_SECRET_PATH_DENIED);
            out.insert(
                "path".to_string(),
                serde_json::Value::String(rendered_path.clone()),
            );
            ToolErrorRender {
                details: serde_json::Value::Object(out),
                public_message: if redact_paths {
                    format!("path is denied by secret rules: {rendered_path}")
                } else {
                    tool.to_string()
                },
            }
        }
        safe_fs_tools::Error::FileTooLarge {
            path,
            size_bytes,
            max_bytes,
        } => {
            let rendered_path = format_path_for_error_with_mode(path, redaction, mode);
            let mut out = details_map(safe_fs_tools::Error::CODE_FILE_TOO_LARGE);
            out.insert(
                "path".to_string(),
                serde_json::Value::String(rendered_path.clone()),
            );
            out.insert("size_bytes".to_string(), serde_json::json!(size_bytes));
            out.insert("max_bytes".to_string(), serde_json::json!(max_bytes));
            ToolErrorRender {
                details: serde_json::Value::Object(out),
                public_message: if redact_paths {
                    format!(
                        "file is too large ({size_bytes} bytes; max {max_bytes} bytes): {rendered_path}"
                    )
                } else {
                    tool.to_string()
                },
            }
        }
        safe_fs_tools::Error::InvalidUtf8 { path, .. } => {
            let rendered_path = format_path_for_error_with_mode(path, redaction, mode);
            let mut out = details_map(safe_fs_tools::Error::CODE_INVALID_UTF8);
            out.insert(
                "path".to_string(),
                serde_json::Value::String(rendered_path.clone()),
            );
            ToolErrorRender {
                details: serde_json::Value::Object(out),
                public_message: if redact_paths {
                    format!("invalid utf-8 in file: {rendered_path}")
                } else {
                    tool.to_string()
                },
            }
        }
        safe_fs_tools::Error::Patch(message) => {
            let mut out = details_map(safe_fs_tools::Error::CODE_PATCH);
            if !redact_paths {
                out.insert(
                    "message".to_string(),
                    serde_json::Value::String(message.clone()),
                );
            }
            ToolErrorRender {
                details: serde_json::Value::Object(out),
                public_message: if redact_paths {
                    "failed to apply patch".to_string()
                } else {
                    tool.to_string()
                },
            }
        }
        safe_fs_tools::Error::InvalidRegex { pattern, source } => {
            let mut out = details_map(safe_fs_tools::Error::CODE_INVALID_REGEX);
            out.insert(
                "message".to_string(),
                serde_json::Value::String(if redact_paths {
                    "invalid regex".to_string()
                } else {
                    format!("invalid regex pattern {pattern:?}: {source}")
                }),
            );
            ToolErrorRender {
                details: serde_json::Value::Object(out),
                public_message: if redact_paths {
                    "invalid regex".to_string()
                } else {
                    tool.to_string()
                },
            }
        }
        safe_fs_tools::Error::InputTooLarge {
            size_bytes,
            max_bytes,
        } => {
            let mut out = details_map(safe_fs_tools::Error::CODE_INPUT_TOO_LARGE);
            out.insert("size_bytes".to_string(), serde_json::json!(size_bytes));
            out.insert("max_bytes".to_string(), serde_json::json!(max_bytes));
            ToolErrorRender {
                details: serde_json::Value::Object(out),
                public_message: tool.to_string(),
            }
        }
        safe_fs_tools::Error::WalkDirRoot { path, source } => {
            let mut out = details_map(safe_fs_tools::Error::CODE_WALKDIR_ROOT);
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
            ToolErrorRender {
                details: serde_json::Value::Object(out),
                public_message: if redact_paths {
                    "walkdir error".to_string()
                } else {
                    tool.to_string()
                },
            }
        }
        safe_fs_tools::Error::WalkDir(err) => {
            let details = if redact_paths {
                let mut out = details_map(safe_fs_tools::Error::CODE_WALKDIR);
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
                let mut out = details_map(safe_fs_tools::Error::CODE_WALKDIR);
                out.insert(
                    "message".to_string(),
                    serde_json::Value::String(err.to_string()),
                );
                serde_json::Value::Object(out)
            };

            ToolErrorRender {
                details,
                public_message: if redact_paths {
                    "walkdir error".to_string()
                } else {
                    tool.to_string()
                },
            }
        }
        _ => {
            let mut out = details_map(tool.code());
            if !redact_paths {
                out.insert(
                    "message".to_string(),
                    serde_json::Value::String(tool.to_string()),
                );
            }

            ToolErrorRender {
                details: serde_json::Value::Object(out),
                public_message: if redact_paths {
                    tool.code().to_string()
                } else {
                    tool.to_string()
                },
            }
        }
    }
}

fn format_root_id_for_error(root_id: &str, mode: RedactionMode) -> String {
    if matches!(mode, RedactionMode::Strict) {
        "<redacted>".to_string()
    } else {
        root_id.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::{
        PathRedaction, RedactionMode, format_path_for_error_with_mode, render_tool_error,
        tool_error_details_with, tool_public_message,
    };
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

    #[test]
    fn details_kind_matches_code_for_explicit_mappings() {
        let cases = vec![
            safe_fs_tools::Error::Io(std::io::Error::other("io")),
            safe_fs_tools::Error::IoPath {
                op: "open",
                path: PathBuf::from("/tmp/file.txt"),
                source: std::io::Error::other("io path"),
            },
            safe_fs_tools::Error::CommittedButUnsynced {
                op: "rename",
                path: PathBuf::from("/tmp/file.txt"),
                source: std::io::Error::other("sync"),
            },
            safe_fs_tools::Error::InvalidPolicy("bad policy".to_string()),
            safe_fs_tools::Error::InvalidPath("bad path".to_string()),
            safe_fs_tools::Error::RootNotFound("root".to_string()),
            safe_fs_tools::Error::OutsideRoot {
                root_id: "root".to_string(),
                path: PathBuf::from("/tmp/outside.txt"),
            },
            safe_fs_tools::Error::NotPermitted("nope".to_string()),
            safe_fs_tools::Error::SecretPathDenied(PathBuf::from("/tmp/secret.txt")),
            safe_fs_tools::Error::FileTooLarge {
                path: PathBuf::from("/tmp/large.txt"),
                size_bytes: 2,
                max_bytes: 1,
            },
            safe_fs_tools::Error::Patch("bad patch".to_string()),
            safe_fs_tools::Error::InputTooLarge {
                size_bytes: 2,
                max_bytes: 1,
            },
        ];

        for error in cases {
            let details = tool_error_details_with(&error, None, true, false);
            let kind = details.get("kind").and_then(serde_json::Value::as_str);
            assert_eq!(kind, Some(error.code()));
        }
    }

    #[test]
    fn missing_canonical_root_keeps_best_effort_fallback() {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock before epoch")
            .as_nanos();
        let missing_root = std::env::temp_dir().join(format!(
            "safe-fs-tools-missing-root-{}-{unique}",
            std::process::id(),
        ));
        assert!(!missing_root.exists());

        let policy = safe_fs_tools::SandboxPolicy::single_root(
            "root",
            &missing_root,
            safe_fs_tools::RootMode::ReadOnly,
        );
        let redaction = PathRedaction::from_policy(&policy);

        let absolute_under_root = missing_root.join("secret.txt");
        let formatted = format_path_for_error_with_mode(
            &absolute_under_root,
            Some(&redaction),
            RedactionMode::BestEffort,
        );
        assert_eq!(formatted, "secret.txt");
    }

    #[test]
    fn canonical_root_duplicate_is_skipped_when_equal_to_declared_root() {
        let dir = tempfile::tempdir().expect("tempdir");
        let policy = safe_fs_tools::SandboxPolicy::single_root(
            "root",
            dir.path(),
            safe_fs_tools::RootMode::ReadOnly,
        );

        let redaction = PathRedaction::from_policy(&policy);
        assert_eq!(redaction.roots.len(), 1);
        assert!(redaction.canonical_roots.is_empty());
    }

    #[test]
    fn strict_mode_redacts_root_id_in_details_and_message() {
        let error = safe_fs_tools::Error::OutsideRoot {
            root_id: "tenant-a".to_string(),
            path: PathBuf::from("/tmp/outside.txt"),
        };
        let details = tool_error_details_with(&error, None, false, true);
        let root_id = details.get("root_id").and_then(serde_json::Value::as_str);
        assert_eq!(root_id, Some("<redacted>"));

        let message = tool_public_message(&error, None, false, true);
        assert_eq!(message, "path resolves outside root '<redacted>'");
    }

    #[test]
    fn single_render_entry_matches_wrapper_outputs() {
        let error = safe_fs_tools::Error::InvalidPath("bad path".to_string());
        let rendered = render_tool_error(&error, None, true, false);
        let details = tool_error_details_with(&error, None, true, false);
        let message = tool_public_message(&error, None, true, false);
        assert_eq!(rendered.details, details);
        assert_eq!(rendered.public_message, message);
    }
}
