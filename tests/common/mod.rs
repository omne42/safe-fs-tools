use safe_fs_tools::policy::{
    Limits, PathRules, Permissions, Root, RootMode, SandboxPolicy, SecretRules, TraversalRules,
};

fn permissive_permissions() -> Permissions {
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

pub fn test_policy(root: &std::path::Path, mode: RootMode) -> SandboxPolicy {
    SandboxPolicy {
        roots: vec![Root {
            id: "root".to_string(),
            path: root.to_path_buf(),
            mode,
        }],
        permissions: Permissions::default(),
        limits: Limits::default(),
        secrets: SecretRules::default(),
        traversal: TraversalRules::default(),
        paths: PathRules::default(),
    }
}

pub fn permissive_test_policy(root: &std::path::Path, mode: RootMode) -> SandboxPolicy {
    SandboxPolicy {
        roots: vec![Root {
            id: "root".to_string(),
            path: root.to_path_buf(),
            mode,
        }],
        permissions: permissive_permissions(),
        limits: Limits::default(),
        secrets: SecretRules::default(),
        traversal: TraversalRules::default(),
        paths: PathRules::default(),
    }
}

pub fn readonly_policy_minimal(root: &std::path::Path) -> SandboxPolicy {
    test_policy(root, RootMode::ReadOnly)
}

pub fn readwrite_policy_minimal(root: &std::path::Path) -> SandboxPolicy {
    test_policy(root, RootMode::ReadWrite)
}
