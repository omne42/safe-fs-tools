use std::path::Path;

use globset::{GlobBuilder, GlobSet, GlobSetBuilder};
use regex::Regex;

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
            let glob = GlobBuilder::new(pattern)
                .literal_separator(true)
                .build()
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
            let regex = Regex::new(pattern).map_err(|err| {
                Error::InvalidRegex(format!("invalid redact regex {pattern:?}: {err}"))
            })?;
            redact.push(regex);
        }

        Ok(Self {
            deny,
            redact,
            replacement: rules.replacement.clone(),
        })
    }

    pub fn is_path_denied(&self, relative: &Path) -> bool {
        self.deny.is_match(relative)
    }

    pub fn redact_text(&self, input: &str) -> String {
        let mut out = input.to_string();
        for regex in &self.redact {
            out = regex.replace_all(&out, &self.replacement).to_string();
        }
        out
    }
}
