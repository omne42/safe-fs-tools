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
    #[serde(default = "default_max_write_bytes")]
    pub max_write_bytes: u64,
    #[serde(default = "default_max_results")]
    pub max_results: usize,
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

const fn default_max_line_bytes() -> usize {
    4096
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_read_bytes: default_max_read_bytes(),
            max_write_bytes: default_max_write_bytes(),
            max_results: default_max_results(),
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
}

impl SandboxPolicy {
    pub fn validate(&self) -> Result<()> {
        if self.roots.is_empty() {
            return Err(Error::InvalidPolicy("roots is empty".to_string()));
        }
        for root in &self.roots {
            if root.id.trim().is_empty() {
                return Err(Error::InvalidPolicy("root.id is empty".to_string()));
            }
            if root.path.as_os_str().is_empty() {
                return Err(Error::InvalidPolicy(format!(
                    "root.path is empty (root.id={})",
                    root.id
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

    pub fn resolve_path(&self, root_id: &str, path: &Path) -> Result<PathBuf> {
        let root = self.root(root_id)?;
        if path.as_os_str().is_empty() {
            return Err(Error::InvalidPath("path is empty".to_string()));
        }
        if path.is_absolute() {
            return Ok(path.to_path_buf());
        }
        Ok(root.path.join(path))
    }
}
