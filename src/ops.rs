use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use diffy::{Patch, apply};
use globset::{GlobBuilder, GlobSet, GlobSetBuilder};
use serde::{Deserialize, Serialize};
use walkdir::WalkDir;

use crate::error::{Error, Result};
use crate::policy::{RootMode, SandboxPolicy};
use crate::redaction::SecretRedactor;

#[derive(Debug)]
pub struct Context {
    policy: SandboxPolicy,
    redactor: SecretRedactor,
    canonical_roots: Vec<(String, PathBuf)>,
}

impl Context {
    pub fn new(policy: SandboxPolicy) -> Result<Self> {
        policy.validate()?;
        let redactor = SecretRedactor::from_rules(&policy.secrets)?;

        let mut canonical_roots = Vec::<(String, PathBuf)>::new();
        for root in &policy.roots {
            let canonical = root.path.canonicalize().map_err(|err| {
                Error::InvalidPolicy(format!(
                    "failed to canonicalize root {} ({}): {err}",
                    root.id,
                    root.path.display()
                ))
            })?;
            canonical_roots.push((root.id.clone(), canonical));
        }

        Ok(Self {
            policy,
            redactor,
            canonical_roots,
        })
    }

    pub fn policy(&self) -> &SandboxPolicy {
        &self.policy
    }

    fn canonical_root(&self, root_id: &str) -> Result<&PathBuf> {
        self.canonical_roots
            .iter()
            .find_map(|(id, path)| (id == root_id).then_some(path))
            .ok_or_else(|| Error::RootNotFound(root_id.to_string()))
    }

    fn canonical_path_in_root(&self, root_id: &str, path: &Path) -> Result<(PathBuf, PathBuf)> {
        let resolved = self.policy.resolve_path(root_id, path)?;
        let canonical_root = self.canonical_root(root_id)?;
        let canonical = resolved.canonicalize()?;
        if !canonical.starts_with(canonical_root) {
            return Err(Error::OutsideRoot {
                root_id: root_id.to_string(),
                path: canonical,
            });
        }
        let relative = canonical
            .strip_prefix(canonical_root)
            .unwrap_or(&canonical)
            .to_path_buf();
        if self.redactor.is_path_denied(&relative) {
            return Err(Error::SecretPathDenied(relative));
        }
        Ok((canonical, relative))
    }

    fn ensure_can_write(&self, root_id: &str, op: &str) -> Result<()> {
        let root = self.policy.root(root_id)?;
        if !matches!(root.mode, RootMode::ReadWrite) {
            return Err(Error::NotPermitted(format!(
                "{op} is not allowed: root {root_id} is read_only"
            )));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReadRequest {
    pub root_id: String,
    pub path: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReadResponse {
    pub path: PathBuf,
    pub truncated: bool,
    pub bytes_read: u64,
    pub content: String,
}

pub fn read_file(ctx: &Context, request: ReadRequest) -> Result<ReadResponse> {
    if !ctx.policy.permissions.read {
        return Err(Error::NotPermitted(
            "read is disabled by policy".to_string(),
        ));
    }

    let (path, relative) = ctx.canonical_path_in_root(&request.root_id, &request.path)?;
    let meta = fs::metadata(&path)?;
    if meta.len() > ctx.policy.limits.max_read_bytes {
        return Err(Error::FileTooLarge {
            path: relative,
            size_bytes: meta.len(),
            max_bytes: ctx.policy.limits.max_read_bytes,
        });
    }

    let mut file = fs::File::open(&path)?;
    let mut bytes = Vec::<u8>::new();
    file.read_to_end(&mut bytes)?;
    let bytes_read = bytes.len() as u64;

    let content = std::str::from_utf8(&bytes)
        .map_err(|_| Error::InvalidUtf8(relative.clone()))?
        .to_string();
    let content = ctx.redactor.redact_text(&content);

    Ok(ReadResponse {
        path: relative,
        truncated: false,
        bytes_read,
        content,
    })
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GlobRequest {
    pub root_id: String,
    pub pattern: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GlobResponse {
    pub matches: Vec<PathBuf>,
    pub truncated: bool,
}

fn compile_glob(pattern: &str) -> Result<GlobSet> {
    let glob = GlobBuilder::new(pattern)
        .literal_separator(true)
        .build()
        .map_err(|err| Error::InvalidPath(format!("invalid glob pattern {pattern:?}: {err}")))?;
    let mut builder = GlobSetBuilder::new();
    builder.add(glob);
    builder
        .build()
        .map_err(|err| Error::InvalidPath(format!("invalid glob pattern {pattern:?}: {err}")))
}

pub fn glob_paths(ctx: &Context, request: GlobRequest) -> Result<GlobResponse> {
    if !ctx.policy.permissions.glob {
        return Err(Error::NotPermitted(
            "glob is disabled by policy".to_string(),
        ));
    }
    let root_path = ctx.canonical_root(&request.root_id)?.clone();
    let matcher = compile_glob(&request.pattern)?;

    let mut matches = Vec::<PathBuf>::new();
    let mut truncated = false;
    for entry in WalkDir::new(&root_path)
        .follow_links(false)
        .into_iter()
        .filter_entry(|entry| {
            if entry.depth() == 0 {
                return true;
            }
            let relative = entry
                .path()
                .strip_prefix(&root_path)
                .unwrap_or(entry.path());
            !ctx.redactor.is_path_denied(relative)
        })
    {
        let entry = entry?;
        if !entry.file_type().is_file() {
            continue;
        }
        let relative = entry
            .path()
            .strip_prefix(&root_path)
            .unwrap_or(entry.path());
        if ctx.redactor.is_path_denied(relative) {
            continue;
        }
        if matcher.is_match(relative) {
            matches.push(relative.to_path_buf());
            if matches.len() >= ctx.policy.limits.max_results {
                truncated = true;
                break;
            }
        }
    }

    Ok(GlobResponse { matches, truncated })
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GrepRequest {
    pub root_id: String,
    pub query: String,
    #[serde(default)]
    pub regex: bool,
    #[serde(default)]
    pub glob: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GrepMatch {
    pub path: PathBuf,
    pub line: u64,
    pub text: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GrepResponse {
    pub matches: Vec<GrepMatch>,
    pub truncated: bool,
}

pub fn grep(ctx: &Context, request: GrepRequest) -> Result<GrepResponse> {
    if !ctx.policy.permissions.grep {
        return Err(Error::NotPermitted(
            "grep is disabled by policy".to_string(),
        ));
    }
    let root_path = ctx.canonical_root(&request.root_id)?.clone();

    let file_glob = request.glob.as_deref().map(compile_glob).transpose()?;

    let regex = if request.regex {
        Some(regex::Regex::new(&request.query).map_err(|err| {
            Error::InvalidRegex(format!("invalid grep regex {:?}: {err}", request.query))
        })?)
    } else {
        None
    };

    let mut matches = Vec::<GrepMatch>::new();
    let mut truncated = false;

    for entry in WalkDir::new(&root_path)
        .follow_links(false)
        .into_iter()
        .filter_entry(|entry| {
            if entry.depth() == 0 {
                return true;
            }
            let relative = entry
                .path()
                .strip_prefix(&root_path)
                .unwrap_or(entry.path());
            !ctx.redactor.is_path_denied(relative)
        })
    {
        let entry = entry?;
        if !entry.file_type().is_file() {
            continue;
        }
        let relative = entry
            .path()
            .strip_prefix(&root_path)
            .unwrap_or(entry.path());
        if ctx.redactor.is_path_denied(relative) {
            continue;
        }
        if let Some(glob) = &file_glob {
            if !glob.is_match(relative) {
                continue;
            }
        }

        let meta = fs::metadata(entry.path())?;
        if meta.len() > ctx.policy.limits.max_read_bytes {
            continue;
        }

        let content = fs::read_to_string(entry.path()).map_err(|err| {
            if err.kind() == std::io::ErrorKind::InvalidData {
                Error::InvalidUtf8(relative.to_path_buf())
            } else {
                Error::Io(err)
            }
        })?;

        for (idx, line) in content.lines().enumerate() {
            let ok = match &regex {
                Some(regex) => regex.is_match(line),
                None => line.contains(&request.query),
            };
            if !ok {
                continue;
            }
            let text = line
                .as_bytes()
                .get(..ctx.policy.limits.max_line_bytes)
                .map(|slice| String::from_utf8_lossy(slice).to_string())
                .unwrap_or_default();
            let text = ctx.redactor.redact_text(&text);
            matches.push(GrepMatch {
                path: relative.to_path_buf(),
                line: idx.saturating_add(1) as u64,
                text,
            });
            if matches.len() >= ctx.policy.limits.max_results {
                truncated = true;
                break;
            }
        }

        if truncated {
            break;
        }
    }

    Ok(GrepResponse { matches, truncated })
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EditRequest {
    pub root_id: String,
    pub path: PathBuf,
    pub start_line: u64,
    pub end_line: u64,
    pub replacement: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EditResponse {
    pub path: PathBuf,
    pub bytes_written: u64,
}

pub fn edit_range(ctx: &Context, request: EditRequest) -> Result<EditResponse> {
    if !ctx.policy.permissions.edit {
        return Err(Error::NotPermitted(
            "edit is disabled by policy".to_string(),
        ));
    }
    ctx.ensure_can_write(&request.root_id, "edit")?;
    let (path, relative) = ctx.canonical_path_in_root(&request.root_id, &request.path)?;

    if request.start_line == 0 || request.end_line == 0 || request.start_line > request.end_line {
        return Err(Error::InvalidPath(format!(
            "invalid line range {}..{}",
            request.start_line, request.end_line
        )));
    }

    let content = fs::read_to_string(&path)?;
    let lines: Vec<&str> = content.lines().collect();
    let start = (request.start_line - 1) as usize;
    let end = (request.end_line - 1) as usize;
    if start >= lines.len() || end >= lines.len() {
        return Err(Error::InvalidPath(format!(
            "line range {}..{} out of bounds (file has {} lines)",
            request.start_line,
            request.end_line,
            lines.len()
        )));
    }

    let mut out = String::new();
    for (idx, line) in lines.iter().enumerate() {
        if idx == start {
            out.push_str(&request.replacement);
            if !request.replacement.ends_with('\n') {
                out.push('\n');
            }
        }
        if idx < start || idx > end {
            out.push_str(line);
            out.push('\n');
        }
    }

    if out.len() as u64 > ctx.policy.limits.max_write_bytes {
        return Err(Error::FileTooLarge {
            path: relative.clone(),
            size_bytes: out.len() as u64,
            max_bytes: ctx.policy.limits.max_write_bytes,
        });
    }

    let mut file = fs::File::create(&path)?;
    file.write_all(out.as_bytes())?;
    Ok(EditResponse {
        path: relative,
        bytes_written: out.len() as u64,
    })
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatchRequest {
    pub root_id: String,
    pub path: PathBuf,
    pub patch: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatchResponse {
    pub path: PathBuf,
    pub bytes_written: u64,
}

pub fn apply_unified_patch(ctx: &Context, request: PatchRequest) -> Result<PatchResponse> {
    if !ctx.policy.permissions.patch {
        return Err(Error::NotPermitted(
            "patch is disabled by policy".to_string(),
        ));
    }
    ctx.ensure_can_write(&request.root_id, "patch")?;
    let (path, relative) = ctx.canonical_path_in_root(&request.root_id, &request.path)?;

    let content = fs::read_to_string(&path)?;
    let parsed = Patch::from_str(&request.patch).map_err(|err| Error::Patch(err.to_string()))?;
    let updated = apply(&content, &parsed).map_err(|err| Error::Patch(err.to_string()))?;

    if updated.len() as u64 > ctx.policy.limits.max_write_bytes {
        return Err(Error::FileTooLarge {
            path: relative.clone(),
            size_bytes: updated.len() as u64,
            max_bytes: ctx.policy.limits.max_write_bytes,
        });
    }

    let mut file = fs::File::create(&path)?;
    file.write_all(updated.as_bytes())?;
    Ok(PatchResponse {
        path: relative,
        bytes_written: updated.len() as u64,
    })
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeleteRequest {
    pub root_id: String,
    pub path: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeleteResponse {
    pub path: PathBuf,
}

pub fn delete_file(ctx: &Context, request: DeleteRequest) -> Result<DeleteResponse> {
    if !ctx.policy.permissions.delete {
        return Err(Error::NotPermitted(
            "delete is disabled by policy".to_string(),
        ));
    }
    ctx.ensure_can_write(&request.root_id, "delete")?;
    let (path, relative) = ctx.canonical_path_in_root(&request.root_id, &request.path)?;
    fs::remove_file(path)?;
    Ok(DeleteResponse { path: relative })
}
