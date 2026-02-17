use std::fs;
use std::path::Path;

use criterion::{Criterion, criterion_group, criterion_main};
use safe_fs_tools::ops::{Context, ListDirRequest, ReadRequest, list_dir, read_file};
#[cfg(feature = "glob")]
use safe_fs_tools::ops::{GlobRequest, glob_paths};
#[cfg(feature = "grep")]
use safe_fs_tools::ops::{GrepRequest, grep};
use safe_fs_tools::policy::{Permissions, RootMode, SandboxPolicy};

fn permissive_policy(root: &Path) -> SandboxPolicy {
    let mut policy = SandboxPolicy::single_root("root", root.to_path_buf(), RootMode::ReadWrite);
    policy.permissions = Permissions {
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
    };
    policy.secrets.deny_globs = Vec::new();
    policy.secrets.redact_regexes = Vec::new();
    policy
}

struct BenchFixture {
    _tempdir: tempfile::TempDir,
    ctx: Context,
    read_req: ReadRequest,
    list_req: ListDirRequest,
    #[cfg(feature = "glob")]
    glob_req: GlobRequest,
    #[cfg(feature = "grep")]
    grep_req: GrepRequest,
}

fn setup_fixture() -> BenchFixture {
    let tempdir = tempfile::tempdir().expect("tempdir");

    let large_path = tempdir.path().join("large.txt");
    let mut large = String::with_capacity(256 * 1024);
    for i in 0..8_000 {
        let line = format!("line-{i} normal text and maybe needle-{i}\n");
        large.push_str(&line);
    }
    fs::write(&large_path, large).expect("write large file");

    let docs_dir = tempdir.path().join("docs");
    fs::create_dir_all(&docs_dir).expect("mkdir docs");
    for i in 0..600 {
        let text = if i % 8 == 0 {
            "needle appears on some files\n"
        } else {
            "plain content\n"
        };
        fs::write(docs_dir.join(format!("file-{i}.txt")), text).expect("write txt");
    }
    for i in 0..200 {
        fs::write(docs_dir.join(format!("file-{i}.log")), "log content\n").expect("write log");
    }

    let ctx = Context::new(permissive_policy(tempdir.path())).expect("ctx");

    BenchFixture {
        _tempdir: tempdir,
        ctx,
        read_req: ReadRequest {
            root_id: "root".to_string(),
            path: "large.txt".into(),
            start_line: None,
            end_line: None,
        },
        list_req: ListDirRequest {
            root_id: "root".to_string(),
            path: "docs".into(),
            max_entries: Some(128),
        },
        #[cfg(feature = "glob")]
        glob_req: GlobRequest {
            root_id: "root".to_string(),
            pattern: "docs/**/*.txt".to_string(),
        },
        #[cfg(feature = "grep")]
        grep_req: GrepRequest {
            root_id: "root".to_string(),
            query: "needle".to_string(),
            regex: false,
            glob: Some("docs/**/*.txt".to_string()),
        },
    }
}

fn bench_ops(c: &mut Criterion) {
    let fixture = setup_fixture();

    c.bench_function("read/full_large_file", |b| {
        b.iter(|| {
            let req = fixture.read_req.clone();
            read_file(&fixture.ctx, req).expect("read");
        });
    });

    c.bench_function("list_dir/top_k_entries", |b| {
        b.iter(|| {
            let req = fixture.list_req.clone();
            list_dir(&fixture.ctx, req).expect("list_dir");
        });
    });

    #[cfg(feature = "glob")]
    c.bench_function("glob/txt_files", |b| {
        b.iter(|| {
            let req = fixture.glob_req.clone();
            glob_paths(&fixture.ctx, req).expect("glob");
        });
    });

    #[cfg(feature = "grep")]
    c.bench_function("grep/plain_query", |b| {
        b.iter(|| {
            let req = fixture.grep_req.clone();
            grep(&fixture.ctx, req).expect("grep");
        });
    });
}

criterion_group!(benches, bench_ops);
criterion_main!(benches);
