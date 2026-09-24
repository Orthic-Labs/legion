//! Tests for wf_port packet r04 (`skills/designer/engine/scripts/context.mjs`
//! CLI + skill-update-check layer, completing the deterministic core already
//! ported at `w2_010::context`).
//!
//! This file depends on `legion_runtime::wf_port::r04`, which is not yet
//! wired into `legion-runtime`'s public module tree (the integrator adds
//! `pub mod r04;` in `src/wf_port/mod.rs` per this packet's own note in
//! `src/wf_port/r04/mod.rs`). Until that wiring lands, this file will not
//! compile as part of the crate's test target.
//!
//! Most behavioral assertions live as unit tests inside each ported module
//! (`src/wf_port/r04/{cli,update_check}.rs`), matching this repo's existing
//! wf_port convention. This file adds end-to-end cases that exercise
//! `run_cli` together with a real (fixture-backed) monorepo layout and the
//! update-check machinery together, the way `context.mjs`'s own `cli()`
//! composes them.

use std::cell::RefCell;
use std::fs;
use std::path::{Path, PathBuf};

use legion_runtime::wf_port::r04::cli::run_cli;
use legion_runtime::wf_port::r04::update_check::{
    compute_update_directive, CacheStore, ConfigReader, UpdateCache, UpdateCheckContext,
    VersionFetcher,
};

fn tmp_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("legion_wf_r04_it_{name}_{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

struct FakeCache(RefCell<UpdateCache>);
impl CacheStore for FakeCache {
    fn read(&self) -> UpdateCache {
        self.0.borrow().clone()
    }
    fn write(&self, cache: &UpdateCache) {
        *self.0.borrow_mut() = cache.clone();
    }
}

struct FakeFetcher(Option<String>);
impl VersionFetcher for FakeFetcher {
    fn fetch_latest(&self, _host: &str) -> Option<String> {
        self.0.clone()
    }
}

struct NoConfigOverride;
impl ConfigReader for NoConfigOverride {
    fn update_check_flag(&self, _cwd: &Path) -> Option<bool> {
        None
    }
}

/// A monorepo root with a child app carrying its own PRODUCT.md, exercising
/// the full `cli()` path: target resolution -> load_context -> the
/// RESOLVED_CONTEXT / NEXT STEP text -> an appended UPDATE_AVAILABLE block.
#[test]
fn cli_end_to_end_with_target_and_update_directive() {
    let root = tmp_dir("e2e_target");
    fs::write(root.join("pnpm-workspace.yaml"), "packages:\n  - apps/*\n").unwrap();
    let app = root.join("apps/web");
    fs::create_dir_all(&app).unwrap();
    fs::write(
        app.join("PRODUCT.md"),
        "# Web App\n\n## Register\n\nproduct\n",
    )
    .unwrap();

    let cache = FakeCache(RefCell::new(UpdateCache::default()));
    let fetcher = FakeFetcher(Some("9.0.0".to_string()));
    let config = NoConfigOverride;
    let scripts_dir = root.join("scripts-not-present");
    let update_ctx = UpdateCheckContext {
        now_ms: 1,
        cwd: &root,
        scripts_dir: &scripts_dir,
        host: "https://example.invalid".to_string(),
        no_update_check_env: false,
        cache: &cache,
        fetcher: &fetcher,
        config: &config,
    };
    // No SKILL.md present at the fixture root -> no local version -> no
    // directive, matching the JS `readLocalSkillVersion()` returning null.
    let directive = compute_update_directive(&update_ctx);
    assert_eq!(directive, None);

    let args = vec!["--target".to_string(), "apps/web".to_string()];
    let out = run_cli(&args, &root, "context.mjs", directive);
    assert_eq!(out.exit_code, 0);
    assert!(out.stdout.starts_with("# PRODUCT.md"));
    assert!(out.stdout.contains("Web App"));
    assert!(out.stdout.contains("\"targetPath\": \"apps/web\""));
    assert!(out.stdout.contains("\"targetExists\": true"));
    assert!(out
        .stdout
        .contains("NEXT STEP: This project's register is `product`."));
}

/// Monorepo root with multiple candidate apps and no --target: the CLI must
/// emit TARGET_SELECTION_REQUIRED instead of resolving context.
#[test]
fn cli_monorepo_without_target_requires_selection() {
    let root = tmp_dir("e2e_selection");
    fs::write(root.join("pnpm-workspace.yaml"), "packages:\n  - apps/*\n").unwrap();
    for name in ["web", "mobile"] {
        let app = root.join("apps").join(name);
        fs::create_dir_all(&app).unwrap();
        fs::write(app.join("PRODUCT.md"), format!("# {name}\n")).unwrap();
    }
    let out = run_cli(&[], &root, "context.mjs", None);
    assert_eq!(out.exit_code, 0);
    assert!(out.stdout.starts_with("TARGET_SELECTION_REQUIRED:"));
    assert!(out.stdout.contains("\"name\": \"mobile\""));
    assert!(out.stdout.contains("\"name\": \"web\""));
}

/// The update check itself, end to end: a stale cache triggers a fetch, the
/// newer version is surfaced once, then suppressed by the anti-nag window.
#[test]
fn update_check_full_cycle() {
    let dir = tmp_dir("update_cycle");
    fs::create_dir_all(dir.join("scripts")).unwrap();
    fs::write(
        dir.join("SKILL.md"),
        "---\nname: designer\nversion: \"1.0.0\"\n---\n",
    )
    .unwrap();

    let cache = FakeCache(RefCell::new(UpdateCache::default()));
    let fetcher = FakeFetcher(Some("1.5.0".to_string()));
    let config = NoConfigOverride;

    let ctx1 = UpdateCheckContext {
        now_ms: 100,
        cwd: &dir,
        scripts_dir: &dir.join("scripts"),
        host: "https://example.invalid".to_string(),
        no_update_check_env: false,
        cache: &cache,
        fetcher: &fetcher,
        config: &config,
    };
    let first = compute_update_directive(&ctx1);
    assert!(first.as_deref().unwrap().contains("v1.5.0"));

    let ctx2 = UpdateCheckContext {
        now_ms: 200,
        cwd: &dir,
        scripts_dir: &dir.join("scripts"),
        host: "https://example.invalid".to_string(),
        no_update_check_env: false,
        cache: &cache,
        fetcher: &fetcher,
        config: &config,
    };
    assert_eq!(compute_update_directive(&ctx2), None);
}
