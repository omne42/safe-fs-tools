use std::borrow::Cow;
use std::path::{Component, Path};

use globset::{GlobSet, GlobSetBuilder};
use regex::{NoExpand, Regex};

use crate::error::{Error, Result};
use crate::policy::SecretRules;

#[derive(Debug)]
pub struct SecretRedactor {
    deny: GlobSet,
    redact: Vec<Regex>,
    replacement: String,
}

impl SecretRedactor {
    pub fn from_rules(rules: &SecretRules) -> Result<Self> {
        let mut deny_builder = GlobSetBuilder::new();
        for pattern in &rules.deny_globs {
            let normalized = crate::path_utils::normalize_glob_pattern_for_matching(pattern);
            crate::path_utils::validate_root_relative_glob_pattern(&normalized).map_err(|msg| {
                Error::InvalidPolicy(format!("invalid deny glob {pattern:?}: {msg}"))
            })?;
            let glob =
                crate::path_utils::build_glob_from_normalized(&normalized).map_err(|err| {
                    Error::InvalidPolicy(format!("invalid deny glob {pattern:?}: {err}"))
                })?;
            deny_builder.add(glob);
        }
        let deny = deny_builder
            .build()
            .map_err(|err| Error::InvalidPolicy(format!("invalid deny globs: {err}")))?;

        let mut redact = Vec::<Regex>::new();
        for pattern in &rules.redact_regexes {
            let regex = Regex::new(pattern).map_err(|err| {
                Error::InvalidPolicy(format!(
                    "invalid secrets.redact_regexes regex {pattern:?}: {err}"
                ))
            })?;
            redact.push(regex);
        }

        Ok(Self {
            deny,
            redact,
            replacement: rules.replacement.clone(),
        })
    }

    /// Returns `true` if a **root-relative** path is denied by `secrets.deny_globs`.
    ///
    /// The deny glob patterns are defined relative to the selected root (e.g. `.git/**`), so
    /// callers should pass paths relative to the root. Absolute paths will typically not match.
    pub fn is_path_denied(&self, relative: &Path) -> bool {
        self.deny.is_match(normalize_path_for_glob(relative))
    }

    pub fn redact_text(&self, input: &str) -> String {
        let mut current: Cow<'_, str> = Cow::Borrowed(input);
        for regex in &self.redact {
            let replaced = regex.replace_all(current.as_ref(), NoExpand(&self.replacement));
            if matches!(replaced, Cow::Borrowed(_)) {
                continue;
            }
            current = Cow::Owned(replaced.into_owned());
        }
        current.into_owned()
    }
}

fn normalize_relative_path(path: &Path) -> Cow<'_, Path> {
    if path.is_absolute() {
        return Cow::Borrowed(path);
    }

    let mut needs_normalization = false;
    for comp in path.components() {
        if matches!(comp, Component::CurDir | Component::ParentDir) {
            needs_normalization = true;
            break;
        }
    }

    if !needs_normalization {
        return Cow::Borrowed(path);
    }
    Cow::Owned(crate::path_utils::normalize_path_lexical(path))
}

#[cfg(windows)]
fn normalize_path_for_glob(path: &Path) -> Cow<'_, Path> {
    let path = normalize_relative_path(path);
    let raw = path.to_string_lossy();
    if !raw.contains('\\') {
        return path;
    }
    Cow::Owned(std::path::PathBuf::from(raw.replace('\\', "/")))
}

#[cfg(not(windows))]
fn normalize_path_for_glob(path: &Path) -> Cow<'_, Path> {
    normalize_relative_path(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_relative_path_preserves_leading_parent_dirs() {
        assert_eq!(
            normalize_relative_path(Path::new("../..")).as_ref(),
            Path::new("../..")
        );
        assert_eq!(
            normalize_relative_path(Path::new("../../a/../b")).as_ref(),
            Path::new("../../b")
        );
        assert_eq!(
            normalize_relative_path(Path::new("a/../../b")).as_ref(),
            Path::new("../b")
        );
    }
}
