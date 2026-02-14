use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::fs;
use std::path::{Path, PathBuf};

use crate::error::{Error, Result};
use crate::policy::{RootMode, SandboxPolicy};
use crate::redaction::SecretRedactor;

use super::{
    Context, CopyFileRequest, CopyFileResponse, DeleteRequest, DeleteResponse, EditRequest,
    EditResponse, ListDirRequest, ListDirResponse, MkdirRequest, MkdirResponse, MovePathRequest,
    MovePathResponse, PatchRequest, PatchResponse, ReadRequest, ReadResponse, RootRuntime,
    StatRequest, StatResponse, WriteFileRequest, WriteFileResponse,
};
#[cfg(feature = "glob")]
use super::{GlobRequest, GlobResponse};
#[cfg(feature = "grep")]
use super::{GrepRequest, GrepResponse};

impl Context {
    pub fn new(policy: SandboxPolicy) -> Result<Self> {
        policy.validate()?;
        let redactor = SecretRedactor::from_rules(&policy.secrets)?;

        let mut roots = HashMap::<String, RootRuntime>::new();
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

            for (existing_id, existing_root) in &roots {
                let existing_canonical = &existing_root.canonical_path;
                if canonical_paths_equal(&canonical, existing_canonical) {
                    return Err(Error::InvalidPolicy(format!(
                        "root {} ({}) resolves to the same canonical directory as root {} ({})",
                        root.id,
                        canonical.display(),
                        existing_id,
                        existing_canonical.display()
                    )));
                }

                if canonical_paths_overlap(&canonical, existing_canonical) {
                    return Err(Error::InvalidPolicy(format!(
                        "root {} ({}) overlaps with root {} ({})",
                        root.id,
                        canonical.display(),
                        existing_id,
                        existing_canonical.display()
                    )));
                }
            }

            match roots.entry(root.id.clone()) {
                Entry::Vacant(slot) => {
                    slot.insert(RootRuntime {
                        canonical_path: canonical,
                        mode: root.mode,
                    });
                }
                Entry::Occupied(_) => {
                    return Err(Error::InvalidPolicy(format!(
                        "duplicate root.id: {:?}",
                        root.id
                    )));
                }
            }
        }

        #[cfg(any(feature = "glob", feature = "grep"))]
        let traversal_skip_globs =
            super::traversal::compile_traversal_skip_globs(&policy.traversal.skip_globs)?;

        Ok(Self {
            policy,
            redactor,
            roots,
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

    #[cfg(feature = "glob")]
    pub fn glob_paths(&self, request: GlobRequest) -> Result<GlobResponse> {
        super::glob_paths(self, request)
    }

    #[cfg(feature = "grep")]
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

    fn root_runtime(&self, root_id: &str) -> Result<&RootRuntime> {
        self.roots
            .get(root_id)
            .ok_or_else(|| Error::RootNotFound(root_id.to_string()))
    }

    pub(super) fn canonical_root(&self, root_id: &str) -> Result<&Path> {
        self.root_runtime(root_id)
            .map(|root| root.canonical_path.as_path())
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
        let root = self.root_runtime(root_id)?;
        if !matches!(root.mode, RootMode::ReadWrite) {
            return Err(Error::NotPermitted(format!(
                "{op} is not allowed: root {root_id} is read_only"
            )));
        }
        Ok(())
    }
}

fn canonical_paths_equal(a: &Path, b: &Path) -> bool {
    crate::path_utils::starts_with_case_insensitive(a, b)
        && crate::path_utils::starts_with_case_insensitive(b, a)
}

fn canonical_paths_overlap(a: &Path, b: &Path) -> bool {
    crate::path_utils::starts_with_case_insensitive(a, b)
        || crate::path_utils::starts_with_case_insensitive(b, a)
}
