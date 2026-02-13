use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;

#[cfg(any(feature = "glob", feature = "grep"))]
use std::path::Path;

use crate::error::{Error, Result};
use crate::policy::{RootMode, SandboxPolicy};
use crate::redaction::SecretRedactor;

use super::{
    Context, CopyFileRequest, CopyFileResponse, DeleteRequest, DeleteResponse, EditRequest,
    EditResponse, GlobRequest, GlobResponse, GrepRequest, GrepResponse, ListDirRequest,
    ListDirResponse, MkdirRequest, MkdirResponse, MovePathRequest, MovePathResponse, PatchRequest,
    PatchResponse, ReadRequest, ReadResponse, StatRequest, StatResponse, WriteFileRequest,
    WriteFileResponse,
};

impl Context {
    pub fn new(policy: SandboxPolicy) -> Result<Self> {
        policy.validate()?;
        let redactor = SecretRedactor::from_rules(&policy.secrets)?;

        let mut canonical_roots = HashMap::<String, PathBuf>::new();
        for root in &policy.roots {
            let canonical = root.path.canonicalize().map_err(|err| {
                Error::InvalidPolicy(format!(
                    "failed to canonicalize root {} ({}): {err}",
                    root.id,
                    root.path.display()
                ))
            })?;
            let meta = fs::metadata(&canonical).map_err(|err| {
                Error::InvalidPolicy(format!(
                    "failed to stat root {} ({}): {err}",
                    root.id,
                    canonical.display()
                ))
            })?;
            if !meta.is_dir() {
                return Err(Error::InvalidPolicy(format!(
                    "root {} ({}) is not a directory",
                    root.id,
                    canonical.display()
                )));
            }
            if canonical_roots.insert(root.id.clone(), canonical).is_some() {
                return Err(Error::InvalidPolicy(format!(
                    "duplicate root id: {}",
                    root.id
                )));
            }
        }

        #[cfg(any(feature = "glob", feature = "grep"))]
        let traversal_skip_globs =
            super::traversal::compile_traversal_skip_globs(&policy.traversal.skip_globs)?;

        Ok(Self {
            policy,
            redactor,
            canonical_roots,
            #[cfg(any(feature = "glob", feature = "grep"))]
            traversal_skip_globs,
        })
    }

    #[cfg(feature = "policy-io")]
    pub fn from_policy_path(path: impl AsRef<std::path::Path>) -> Result<Self> {
        let policy = crate::policy_io::load_policy(path)?;
        Self::new(policy)
    }

    pub fn policy(&self) -> &SandboxPolicy {
        &self.policy
    }

    pub fn read_file(&self, request: ReadRequest) -> Result<ReadResponse> {
        super::read_file(self, request)
    }

    pub fn list_dir(&self, request: ListDirRequest) -> Result<ListDirResponse> {
        super::list_dir(self, request)
    }

    pub fn glob_paths(&self, request: GlobRequest) -> Result<GlobResponse> {
        super::glob_paths(self, request)
    }

    pub fn grep(&self, request: GrepRequest) -> Result<GrepResponse> {
        super::grep(self, request)
    }

    pub fn stat(&self, request: StatRequest) -> Result<StatResponse> {
        super::stat(self, request)
    }

    pub fn edit_range(&self, request: EditRequest) -> Result<EditResponse> {
        super::edit_range(self, request)
    }

    pub fn apply_unified_patch(&self, request: PatchRequest) -> Result<PatchResponse> {
        super::apply_unified_patch(self, request)
    }

    pub fn delete(&self, request: DeleteRequest) -> Result<DeleteResponse> {
        super::delete(self, request)
    }

    pub fn mkdir(&self, request: MkdirRequest) -> Result<MkdirResponse> {
        super::mkdir(self, request)
    }

    pub fn write_file(&self, request: WriteFileRequest) -> Result<WriteFileResponse> {
        super::write_file(self, request)
    }

    pub fn move_path(&self, request: MovePathRequest) -> Result<MovePathResponse> {
        super::move_path(self, request)
    }

    pub fn copy_file(&self, request: CopyFileRequest) -> Result<CopyFileResponse> {
        super::copy_file(self, request)
    }

    pub(super) fn canonical_root(&self, root_id: &str) -> Result<&PathBuf> {
        self.canonical_roots
            .get(root_id)
            .ok_or_else(|| Error::RootNotFound(root_id.to_string()))
    }

    #[cfg(any(feature = "glob", feature = "grep"))]
    pub(super) fn is_traversal_path_skipped(&self, relative: &Path) -> bool {
        self.traversal_skip_globs
            .as_ref()
            .is_some_and(|skip| super::traversal::globset_is_match(skip, relative))
    }

    pub(super) fn reject_secret_path(&self, path: PathBuf) -> Result<PathBuf> {
        if self.redactor.is_path_denied(&path) {
            return Err(Error::SecretPathDenied(path));
        }
        Ok(path)
    }

    pub(super) fn ensure_can_write(&self, root_id: &str, op: &str) -> Result<()> {
        let root = self.policy.root(root_id)?;
        if !matches!(root.mode, RootMode::ReadWrite) {
            return Err(Error::NotPermitted(format!(
                "{op} is not allowed: root {root_id} is read_only"
            )));
        }
        Ok(())
    }
}
