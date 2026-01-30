#[cfg(windows)]
use std::path::Component;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum RootMode {
    #[default]
    ReadOnly,
    ReadWrite,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Root {
    pub id: String,
    pub path: PathBuf,
    #[serde(default)]
    pub mode: RootMode,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Permissions {
    #[serde(default)]
    pub read: bool,
    #[serde(default)]
    pub glob: bool,
    #[serde(default)]
    pub grep: bool,
    #[serde(default)]
    pub edit: bool,
    #[serde(default)]
    pub patch: bool,
    #[serde(default)]
    pub delete: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Limits {
    #[serde(default = "default_max_read_bytes")]
    pub max_read_bytes: u64,
    /// Optional cap for unified-diff patch *input* size (bytes).
    ///
    /// - `None` => defaults to `max_read_bytes`.
    /// - `Some(0)` is invalid and rejected by policy validation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_patch_bytes: Option<u64>,
    #[serde(default = "default_max_write_bytes")]
    pub max_write_bytes: u64,
    #[serde(default = "default_max_results")]
    pub max_results: usize,
    #[serde(default = "default_max_walk_entries")]
    pub max_walk_entries: usize,
    #[serde(default = "default_max_walk_files")]
    pub max_walk_files: usize,
    /// Optional wall-clock traversal budget for `glob`/`grep` (milliseconds).
    ///
    /// - `None` => no time budget enforcement.
    /// - `Some(0)` => immediately stop traversal (useful for tests / hard disable).
    #[serde(default)]
    pub max_walk_ms: Option<u64>,
    #[serde(default = "default_max_line_bytes")]
    pub max_line_bytes: usize,
}

const fn default_max_read_bytes() -> u64 {
    1024 * 1024
}

const fn default_max_write_bytes() -> u64 {
    1024 * 1024
}

const fn default_max_results() -> usize {
    2000
}

const fn default_max_walk_entries() -> usize {
    500_000
}

const fn default_max_walk_files() -> usize {
    200_000
}

const fn default_max_line_bytes() -> usize {
    4096
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_read_bytes: default_max_read_bytes(),
            max_patch_bytes: None,
            max_write_bytes: default_max_write_bytes(),
            max_results: default_max_results(),
            max_walk_entries: default_max_walk_entries(),
            max_walk_files: default_max_walk_files(),
            max_walk_ms: None,
            max_line_bytes: default_max_line_bytes(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretRules {
    #[serde(default = "default_secret_deny_globs")]
    pub deny_globs: Vec<String>,
    #[serde(default)]
    pub redact_regexes: Vec<String>,
    #[serde(default = "default_redaction_replacement")]
    pub replacement: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TraversalRules {
    /// Glob patterns that should be skipped during traversal (`glob`/`grep`) for performance.
    ///
    /// Unlike `secrets.deny_globs`, this does **not** deny direct access to the path.
    #[serde(default)]
    pub skip_globs: Vec<String>,
}

fn default_secret_deny_globs() -> Vec<String> {
    vec![
        ".git/**".to_string(),
        "**/.git/**".to_string(),
        ".env".to_string(),
        ".env.*".to_string(),
        "**/.env".to_string(),
        "**/.env.*".to_string(),
    ]
}

fn default_redaction_replacement() -> String {
    "***REDACTED***".to_string()
}

impl Default for SecretRules {
    fn default() -> Self {
        Self {
            deny_globs: default_secret_deny_globs(),
            redact_regexes: Vec::new(),
            replacement: default_redaction_replacement(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxPolicy {
    pub roots: Vec<Root>,
    #[serde(default)]
    pub permissions: Permissions,
    #[serde(default)]
    pub limits: Limits,
    #[serde(default)]
    pub secrets: SecretRules,
    #[serde(default)]
    pub traversal: TraversalRules,
}

impl SandboxPolicy {
    pub fn single_root(id: impl Into<String>, path: impl Into<PathBuf>, mode: RootMode) -> Self {
        Self {
            roots: vec![Root {
                id: id.into(),
                path: path.into(),
                mode,
            }],
            permissions: Permissions::default(),
            limits: Limits::default(),
            secrets: SecretRules::default(),
            traversal: TraversalRules::default(),
        }
    }

    /// Validate policy structure and limit values.
    ///
    /// This is a purely *structural* validation: it does **not** perform any filesystem IO
    /// (e.g. it does not check whether roots exist or are directories).
    ///
    /// Root existence and directory checks happen in `ops::Context::new`, which also canonicalizes
    /// the configured root paths.
    pub fn validate(&self) -> Result<()> {
        if self.roots.is_empty() {
            return Err(Error::InvalidPolicy("roots is empty".to_string()));
        }
        if self.limits.max_read_bytes == 0 {
            return Err(Error::InvalidPolicy(
                "limits.max_read_bytes must be > 0".to_string(),
            ));
        }
        if let Some(max_patch_bytes) = self.limits.max_patch_bytes
            && max_patch_bytes == 0
        {
            return Err(Error::InvalidPolicy(
                "limits.max_patch_bytes must be > 0".to_string(),
            ));
        }
        if self.limits.max_write_bytes == 0 {
            return Err(Error::InvalidPolicy(
                "limits.max_write_bytes must be > 0".to_string(),
            ));
        }
        if self.limits.max_results == 0 {
            return Err(Error::InvalidPolicy(
                "limits.max_results must be > 0".to_string(),
            ));
        }
        if self.limits.max_walk_files == 0 {
            return Err(Error::InvalidPolicy(
                "limits.max_walk_files must be > 0".to_string(),
            ));
        }
        if self.limits.max_walk_entries == 0 {
            return Err(Error::InvalidPolicy(
                "limits.max_walk_entries must be > 0".to_string(),
            ));
        }
        if self.limits.max_line_bytes == 0 {
            return Err(Error::InvalidPolicy(
                "limits.max_line_bytes must be > 0".to_string(),
            ));
        }
        let mut seen_ids = std::collections::HashSet::<&str>::new();
        for root in &self.roots {
            if root.id.trim().is_empty() {
                return Err(Error::InvalidPolicy("root.id is empty".to_string()));
            }
            if !seen_ids.insert(root.id.as_str()) {
                return Err(Error::InvalidPolicy(format!(
                    "duplicate root.id: {:?}",
                    root.id
                )));
            }
            if root.path.as_os_str().is_empty() {
                return Err(Error::InvalidPolicy(format!(
                    "root.path is empty (root.id={})",
                    root.id
                )));
            }
            if !root.path.is_absolute() {
                return Err(Error::InvalidPolicy(format!(
                    "root.path must be absolute (root.id={}, path={})",
                    root.id,
                    root.path.display()
                )));
            }
        }
        Ok(())
    }

    pub fn root(&self, id: &str) -> Result<&Root> {
        self.roots
            .iter()
            .find(|root| root.id == id)
            .ok_or_else(|| Error::RootNotFound(id.to_string()))
    }

    /// Resolve a path against the selected root.
    ///
    /// This does **not** enforce any root boundary checks; it only joins paths.
    /// Use `ops::Context` (or equivalent checks) to ensure the resolved path
    /// stays within the root.
    pub fn resolve_path(&self, root_id: &str, path: &Path) -> Result<PathBuf> {
        let root = self.root(root_id)?;
        if path.as_os_str().is_empty() {
            return Err(Error::InvalidPath("path is empty".to_string()));
        }
        #[cfg(windows)]
        {
            if !path.is_absolute() && matches!(path.components().next(), Some(Component::Prefix(_)))
            {
                return Err(Error::InvalidPath(format!(
                    "invalid path {}: drive-relative paths are not supported",
                    path.display()
                )));
            }
        }
        if path.is_absolute() {
            return Ok(path.to_path_buf());
        }
        Ok(root.path.join(path))
    }
}
