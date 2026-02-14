use safe_fs_tools::policy::{
    Limits, PathRules, Permissions, Root, RootMode, SandboxPolicy, SecretRules, TraversalRules,
};

fn base_permissions(_mode: RootMode) -> Permissions {
    Permissions {
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
    }
}

fn all_permissions() -> Permissions {
    Permissions {
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
    }
}

fn base_secret_rules() -> SecretRules {
    SecretRules {
        deny_globs: Vec::new(),
        redact_regexes: vec!["API_KEY=[A-Za-z0-9_]+".to_string()],
        replacement: "***REDACTED***".to_string(),
    }
}

pub fn test_policy(root: &std::path::Path, mode: RootMode) -> SandboxPolicy {
    SandboxPolicy {
        roots: vec![Root {
            id: "root".to_string(),
            path: root.to_path_buf(),
            mode,
        }],
        permissions: base_permissions(mode),
        limits: Limits::default(),
        secrets: base_secret_rules(),
        traversal: TraversalRules::default(),
        paths: PathRules::default(),
    }
}

pub fn test_policy_all_permissions(root: &std::path::Path, mode: RootMode) -> SandboxPolicy {
    let mut policy = test_policy(root, mode);
    policy.permissions = all_permissions();
    policy
}
