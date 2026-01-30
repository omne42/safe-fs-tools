use std::borrow::Cow;
use std::path::{Component, Path, PathBuf};

#[cfg(windows)]
pub(crate) fn normalize_glob_pattern(pattern: &str) -> Cow<'_, str> {
    if !pattern.contains('\\') {
        return Cow::Borrowed(pattern);
    }
    Cow::Owned(pattern.replace('\\', "/"))
}

#[cfg(not(windows))]
pub(crate) fn normalize_glob_pattern(pattern: &str) -> Cow<'_, str> {
    Cow::Borrowed(pattern)
}

pub(crate) fn normalize_path_lexical(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    let mut seen_prefix = false;
    for comp in path.components() {
        match comp {
            Component::CurDir => {}
            Component::ParentDir => {
                if out.as_os_str().is_empty() {
                    out.push("..");
                    continue;
                }

                match out.components().next_back() {
                    Some(Component::Normal(_)) => {
                        out.pop();
                    }
                    Some(Component::ParentDir) => {
                        out.push("..");
                    }
                    Some(Component::Prefix(_)) => {
                        out.push("..");
                    }
                    // If we're at the filesystem root, `..` is a no-op.
                    Some(Component::RootDir) | None => {}
                    _ => {}
                }
            }
            Component::Normal(part) => out.push(part),
            Component::RootDir => {
                if seen_prefix {
                    // On Windows, pushing `RootDir` after `Prefix` would reset the path (dropping
                    // the prefix). Append a separator instead.
                    #[cfg(windows)]
                    {
                        out.as_mut_os_string()
                            .push(std::path::MAIN_SEPARATOR.to_string());
                    }
                    #[cfg(not(windows))]
                    {
                        out.push(comp.as_os_str());
                    }
                } else {
                    out.push(comp.as_os_str());
                }
            }
            Component::Prefix(prefix) => {
                seen_prefix = true;
                out.push(prefix.as_os_str());
            }
        }
    }
    out
}
