use safe_fs_tools::policy::{
    Limits, PathRules, Permissions, Root, RootMode, SandboxPolicy, SecretRules, TraversalRules,
};

fn base_permissions(mode: RootMode) -> Permissions {
    let mut permissions = Permissions {
        read: true,
        glob: true,
        grep: true,
        list_dir: true,
        stat: true,
        ..Permissions::default()
    };

    if matches!(mode, RootMode::ReadWrite) {
        permissions.edit = true;
        permissions.patch = true;
        permissions.delete = true;
        permissions.mkdir = true;
        permissions.write = true;
        permissions.move_path = true;
        permissions.copy_file = true;
    }

    permissions
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
        redact_regexes: Vec::new(),
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
