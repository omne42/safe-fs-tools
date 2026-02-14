use std::borrow::Cow;
use std::path::{Component, Path};

use globset::{GlobSet, GlobSetBuilder};
use regex::{NoExpand, Regex};

use crate::error::{Error, Result};
use crate::policy::SecretRules;

const MAX_REDACT_REGEXES: usize = 128;
const MAX_REPLACEMENT_BYTES: usize = 1024;
const MAX_REDACTED_OUTPUT_BYTES: usize = 8 * 1024 * 1024;
const REDACTION_OUTPUT_LIMIT_MARKER: &str = "[REDACTION_OUTPUT_LIMIT_EXCEEDED]";

#[derive(Debug)]
pub struct SecretRedactor {
    deny: GlobSet,
    redact: Vec<Regex>,
    replacement: String,
}

impl SecretRedactor {
    pub fn from_rules(rules: &SecretRules) -> Result<Self> {
        if rules.redact_regexes.len() > MAX_REDACT_REGEXES {
            return Err(Error::InvalidPolicy(format!(
                "invalid secrets.redact_regexes: too many patterns ({} > {MAX_REDACT_REGEXES})",
                rules.redact_regexes.len()
            )));
        }
        if rules.replacement.len() > MAX_REPLACEMENT_BYTES {
            return Err(Error::InvalidPolicy(format!(
                "invalid secrets.replacement: too long ({} bytes > {MAX_REPLACEMENT_BYTES} bytes)",
                rules.replacement.len()
            )));
        }

        let mut deny_builder = GlobSetBuilder::new();
        for pattern in &rules.deny_globs {
            if pattern.trim().is_empty() {
                return Err(Error::InvalidPolicy(format!(
                    "invalid secrets.deny_globs glob {pattern:?}: glob pattern must not be empty"
                )));
            }
            let normalized =
                crate::path_utils_internal::normalize_glob_pattern_for_matching(pattern);
            crate::path_utils_internal::validate_root_relative_glob_pattern(&normalized).map_err(
                |msg| Error::InvalidPolicy(format!("invalid deny glob {pattern:?}: {msg}")),
            )?;
            let glob = crate::path_utils_internal::build_glob_from_normalized(&normalized)
                .map_err(|err| {
                    Error::InvalidPolicy(format!("invalid deny glob {pattern:?}: {err}"))
                })?;
            deny_builder.add(glob);
        }
        let deny = deny_builder
            .build()
            .map_err(|err| Error::InvalidPolicy(format!("invalid deny globs: {err}")))?;

        let mut redact = Vec::<Regex>::new();
        for pattern in &rules.redact_regexes {
            if pattern.is_empty() {
                return Err(Error::InvalidPolicy(
                    "invalid secrets.redact_regexes regex \"\": empty patterns are not allowed"
                        .to_string(),
                ));
            }
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
    /// Non-root-relative paths are denied defensively to avoid silent allow-on-mismatch behavior.
    pub fn is_path_denied(&self, relative: &Path) -> bool {
        if !is_root_relative(relative) {
            return true;
        }
        match normalize_path_for_glob(relative) {
            Some(path) => self.deny.is_match(path.as_ref()),
            None => true,
        }
    }

    pub fn redact_text(&self, input: &str) -> String {
        self.redact_text_cow(input).into_owned()
    }

    pub fn redact_text_cow<'a>(&self, input: &'a str) -> Cow<'a, str> {
        let mut current: Cow<'_, str> = Cow::Borrowed(input);
        for regex in &self.redact {
            let (matched, projected_len) =
                match projected_redacted_len(current.as_ref(), regex, self.replacement.len()) {
                    Some(value) => value,
                    None => return Cow::Owned(REDACTION_OUTPUT_LIMIT_MARKER.to_string()),
                };
            if !matched {
                continue;
            }
            if projected_len > MAX_REDACTED_OUTPUT_BYTES {
                return Cow::Owned(REDACTION_OUTPUT_LIMIT_MARKER.to_string());
            }
            let replaced = regex.replace_all(current.as_ref(), NoExpand(&self.replacement));
            if matches!(replaced, Cow::Borrowed(_)) {
                continue;
            }
            let owned = replaced.into_owned();
            if owned.len() > MAX_REDACTED_OUTPUT_BYTES {
                return Cow::Owned(REDACTION_OUTPUT_LIMIT_MARKER.to_string());
            }
            current = Cow::Owned(owned);
        }
        current
    }
}

fn projected_redacted_len(
    input: &str,
    regex: &Regex,
    replacement_len: usize,
) -> Option<(bool, usize)> {
    let mut matched = false;
    let mut match_count = 0usize;
    let mut matched_bytes = 0usize;
    for found in regex.find_iter(input) {
        matched = true;
        match_count = match_count.checked_add(1)?;
        matched_bytes = matched_bytes.checked_add(found.len())?;
    }
    if !matched {
        return Some((false, input.len()));
    }

    let unmatched = input.len().checked_sub(matched_bytes)?;
    let replacement_bytes = replacement_len.checked_mul(match_count)?;
    let projected = unmatched.checked_add(replacement_bytes)?;
    Some((true, projected))
}

fn is_root_relative(path: &Path) -> bool {
    for component in path.components() {
        if matches!(component, Component::RootDir | Component::ParentDir) {
            return false;
        }
        #[cfg(windows)]
        if matches!(component, Component::Prefix(_)) {
            return false;
        }
    }
    true
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
    Cow::Owned(crate::path_utils_internal::normalize_path_lexical(path))
}

#[cfg(windows)]
fn normalize_path_for_glob(path: &Path) -> Option<Cow<'_, Path>> {
    debug_assert!(is_root_relative(path));
    let path = normalize_relative_path(path);
    // Fail closed on non-Unicode Windows paths: lossy conversion would change bytes and
    // could cause silent allow-on-mismatch behavior for glob checks.
    let raw = path.to_string_lossy();
    if matches!(raw, Cow::Owned(_)) {
        return None;
    }
    if !raw.contains('\\') {
        return Some(path);
    }
    Some(Cow::Owned(std::path::PathBuf::from(raw.replace('\\', "/"))))
}

#[cfg(not(windows))]
fn normalize_path_for_glob(path: &Path) -> Option<Cow<'_, Path>> {
    debug_assert!(is_root_relative(path));
    Some(normalize_relative_path(path))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::SecretRules;

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

    #[test]
    fn absolute_paths_are_denied_defensively() {
        let redactor = SecretRedactor::from_rules(&SecretRules {
            deny_globs: vec![".git/**".to_string()],
            redact_regexes: Vec::new(),
            replacement: "***".to_string(),
        })
        .expect("redactor");

        #[cfg(unix)]
        let absolute = Path::new("/tmp/.git/config");
        #[cfg(windows)]
        let absolute = Path::new(r"C:\tmp\.git\config");

        assert!(redactor.is_path_denied(absolute));
    }

    #[test]
    fn parent_relative_paths_are_denied_defensively() {
        let redactor = SecretRedactor::from_rules(&SecretRules {
            deny_globs: vec![".git/**".to_string()],
            redact_regexes: Vec::new(),
            replacement: "***".to_string(),
        })
        .expect("redactor");

        assert!(redactor.is_path_denied(Path::new("../.git/config")));
    }

    #[test]
    fn empty_redaction_regex_is_rejected() {
        let err = SecretRedactor::from_rules(&SecretRules {
            deny_globs: vec![".git/**".to_string()],
            redact_regexes: vec!["".to_string()],
            replacement: "***".to_string(),
        })
        .expect_err("empty redact regex should be rejected");

        match err {
            Error::InvalidPolicy(msg) => assert!(msg.contains("empty patterns are not allowed")),
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn empty_deny_glob_is_rejected() {
        for pattern in ["", "   "] {
            let err = SecretRedactor::from_rules(&SecretRules {
                deny_globs: vec![pattern.to_string()],
                redact_regexes: Vec::new(),
                replacement: "***".to_string(),
            })
            .expect_err("empty deny glob should be rejected");

            match err {
                Error::InvalidPolicy(msg) => {
                    assert!(
                        msg.contains("secrets.deny_globs"),
                        "unexpected message: {msg}"
                    );
                }
                other => panic!("unexpected error: {other:?}"),
            }
        }
    }

    #[test]
    fn redact_text_cow_returns_borrowed_when_no_regex_configured() {
        let redactor = SecretRedactor::from_rules(&SecretRules {
            deny_globs: vec![".git/**".to_string()],
            redact_regexes: Vec::new(),
            replacement: "***".to_string(),
        })
        .expect("redactor");

        let input = "no secrets here";
        let redacted = redactor.redact_text_cow(input);
        assert!(matches!(&redacted, Cow::Borrowed(_)));
        assert_eq!(redacted.as_ref(), input);
    }

    #[test]
    fn redact_text_cow_returns_borrowed_when_regex_configured_but_no_match() {
        let redactor = SecretRedactor::from_rules(&SecretRules {
            deny_globs: vec![".git/**".to_string()],
            redact_regexes: vec!["token".to_string()],
            replacement: "***".to_string(),
        })
        .expect("redactor");

        let input = "no secrets here";
        let redacted = redactor.redact_text_cow(input);
        assert!(matches!(&redacted, Cow::Borrowed(_)));
        assert_eq!(redacted.as_ref(), input);
    }

    #[test]
    fn redact_text_cow_applies_regexes_in_order() {
        let redactor = SecretRedactor::from_rules(&SecretRules {
            deny_globs: vec![".git/**".to_string()],
            redact_regexes: vec!["ab".to_string(), "b.".to_string()],
            replacement: "X".to_string(),
        })
        .expect("redactor");

        let redacted = redactor.redact_text_cow("abc");
        assert_eq!(redacted.as_ref(), "Xc");
    }

    #[test]
    fn too_many_redact_regexes_are_rejected() {
        let err = SecretRedactor::from_rules(&SecretRules {
            deny_globs: vec![".git/**".to_string()],
            redact_regexes: (0..=MAX_REDACT_REGEXES)
                .map(|idx| format!("token{idx}"))
                .collect(),
            replacement: "***".to_string(),
        })
        .expect_err("too many redact regexes should be rejected");

        match err {
            Error::InvalidPolicy(msg) => assert!(msg.contains("too many patterns")),
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn oversized_replacement_is_rejected() {
        let err = SecretRedactor::from_rules(&SecretRules {
            deny_globs: vec![".git/**".to_string()],
            redact_regexes: vec![".".to_string()],
            replacement: "X".repeat(MAX_REPLACEMENT_BYTES + 1),
        })
        .expect_err("oversized replacement should be rejected");

        match err {
            Error::InvalidPolicy(msg) => assert!(msg.contains("secrets.replacement")),
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn redaction_output_is_capped() {
        let redactor = SecretRedactor::from_rules(&SecretRules {
            deny_globs: vec![".git/**".to_string()],
            redact_regexes: vec![".".to_string()],
            replacement: "X".repeat(MAX_REPLACEMENT_BYTES),
        })
        .expect("redactor");

        let input = "a".repeat((MAX_REDACTED_OUTPUT_BYTES / MAX_REPLACEMENT_BYTES) + 1);
        let redacted = redactor.redact_text_cow(&input);
        assert_eq!(redacted.as_ref(), REDACTION_OUTPUT_LIMIT_MARKER);
    }

    #[cfg(windows)]
    #[test]
    fn non_unicode_windows_path_is_denied_fail_closed() {
        use std::ffi::OsString;
        use std::os::windows::ffi::OsStringExt;
        use std::path::PathBuf;

        let redactor = SecretRedactor::from_rules(&SecretRules {
            deny_globs: vec![".git/**".to_string()],
            redact_regexes: Vec::new(),
            replacement: "***".to_string(),
        })
        .expect("redactor");

        let path = PathBuf::from(OsString::from_wide(&[0xD800, b'a' as u16]));
        assert!(is_root_relative(&path));
        assert!(normalize_path_for_glob(&path).is_none());
        assert!(redactor.is_path_denied(&path));
    }
}
