use safe_fs_tools::policy::{
    Limits, PathRules, Permissions, Root, RootMode, SandboxPolicy, SecretRules, TraversalRules,
};

pub fn test_policy(root: &std::path::Path, mode: RootMode) -> SandboxPolicy {
    SandboxPolicy {
        roots: vec![Root {
            id: "root".to_string(),
            path: root.to_path_buf(),
            mode,
        }],
        permissions: Permissions {
            read: true,
            glob: true,
            grep: true,
            list_dir: true,
            stat: true,
            edit: true,
            patch: true,
            delete: true,
            mkdir: true,
            write: true,
            move_path: true,
            copy_file: true,
        },
        limits: Limits::default(),
        secrets: SecretRules {
            deny_globs: Vec::new(),
            redact_regexes: vec!["API_KEY=[A-Za-z0-9_]+".to_string()],
            replacement: "***REDACTED***".to_string(),
        },
        traversal: TraversalRules::default(),
        paths: PathRules::default(),
    }
}
