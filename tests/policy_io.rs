#[cfg(feature = "policy-io")]
mod policy_io {
    use safe_fs_tools::ops::Context;
    use safe_fs_tools::policy::{Permissions, Root, RootMode, SandboxPolicy};

    #[test]
    fn load_policy_toml_and_json() {
        let dir = tempfile::tempdir().expect("tempdir");
        let root_path = dir.path().join("root");
        std::fs::create_dir_all(&root_path).expect("mkdir");

        let toml_path = dir.path().join("policy.toml");
        let json_path = dir.path().join("policy.json");

        std::fs::write(
            &toml_path,
            format!(
                r#"
[[roots]]
id = "workspace"
path = "{}"
mode = "read_only"

[permissions]
read = true
"#,
                root_path.display()
            ),
        )
        .expect("write toml");

        std::fs::write(
            &json_path,
            serde_json::to_string(&SandboxPolicy {
                roots: vec![Root {
                    id: "workspace".to_string(),
                    path: root_path.clone(),
                    mode: RootMode::ReadOnly,
                }],
                permissions: Permissions {
                    read: true,
                    ..Default::default()
                },
                limits: Default::default(),
                secrets: Default::default(),
                traversal: Default::default(),
                paths: Default::default(),
            })
            .expect("serialize json"),
        )
        .expect("write json");

        let toml_policy = safe_fs_tools::policy_io::load_policy(&toml_path).expect("load toml");
        assert_eq!(toml_policy.roots.len(), 1);
        assert!(toml_policy.permissions.read);
        assert!(toml_policy.paths.allow_absolute);

        let json_policy = safe_fs_tools::policy_io::load_policy(&json_path).expect("load json");
        assert_eq!(json_policy.roots.len(), 1);
        assert!(json_policy.permissions.read);
        assert!(json_policy.paths.allow_absolute);

        let ctx = Context::from_policy_path(&toml_path).expect("ctx");
        assert!(ctx.policy().permissions.read);
    }

    #[test]
    fn load_policy_rejects_large_files() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("policy.toml");
        std::fs::write(&path, "x".repeat(100)).expect("write");

        let err = safe_fs_tools::policy_io::load_policy_limited(&path, 10).expect_err("reject");
        match err {
            safe_fs_tools::Error::InputTooLarge { .. } => {}
            other => panic!("unexpected error: {other:?}"),
        }
    }
}
