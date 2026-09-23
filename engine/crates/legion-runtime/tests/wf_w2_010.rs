//! Tests for wf_port chunk w2_010 (`skills/designer/engine/scripts`:
//! context-signals.mjs, context.mjs, critique-storage.mjs, detect-csp.mjs).
//!
//! This file depends on `legion_runtime::wf_port::w2_010`, which is not yet
//! wired into `legion-runtime`'s public module tree (the integrator adds
//! `pub mod wf_port;` in `src/lib.rs` and `pub mod w2_010;` in
//! `src/wf_port/mod.rs` per the wf_port chunk assignment). Until that wiring
//! lands, this file will not compile as part of the crate's test target.
//!
//! Most behavioral assertions live as unit tests inside each ported module
//! (`src/wf_port/w2_010/*.rs`), matching this repo's existing wf_port
//! convention (see e.g. `wf034`, `w2_004`). This file adds a handful of
//! cross-module / fixture-backed integration cases that don't fit neatly as
//! a single module's unit test, plus tests derived from the source repo's
//! own test fixtures where a reachable one exists for this chunk's files.

use std::fs;
use std::path::{Path, PathBuf};

use legion_runtime::wf_port::w2_010::context::{
    extract_register, load_context, resolve_target_selection, TargetOptions,
};
use legion_runtime::wf_port::w2_010::context_signals::{gather_signals, git_signals, scan_targets, GitSignals};
use legion_runtime::wf_port::w2_010::critique_storage::{
    read_latest_snapshot, read_trend, slug_from_target, write_snapshot,
};
use legion_runtime::wf_port::w2_010::detect_csp::{detect_csp, CspShape};

fn fixture_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/wf_w2_010")
}

fn tmp_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("legion_wf_w2_010_it_{name}_{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

// ─── context.mjs: monorepo + register resolution end to end ────────────

#[test]
fn monorepo_target_selection_then_child_context_resolution() {
    let root = tmp_dir("monorepo_e2e");
    fs::write(
        root.join("pnpm-workspace.yaml"),
        "packages:\n  - 'apps/*'\n",
    )
    .unwrap();
    fs::create_dir_all(root.join("apps/marketing-site")).unwrap();
    fs::write(
        root.join("apps/marketing-site/PRODUCT.md"),
        "# Marketing site\n\n## Register\nbrand\n",
    )
    .unwrap();
    fs::create_dir_all(root.join("apps/dashboard")).unwrap();

    // From the repo root, with no --target, we get a selection prompt
    // listing both apps.
    let selection = resolve_target_selection(&root, &TargetOptions::none()).expect("selection");
    assert_eq!(selection.target_candidates.len(), 2);
    let marketing = selection
        .target_candidates
        .iter()
        .find(|c| c.name == "marketing-site")
        .unwrap();
    assert_eq!(marketing.product_status, "child");
    assert_eq!(marketing.product_path.as_deref(), Some("apps/marketing-site/PRODUCT.md"));

    // Once cwd is inside the chosen app, context resolves directly and the
    // register drives the downstream reference file choice.
    let child = root.join("apps/marketing-site");
    let ctx = load_context(&child, &TargetOptions::none());
    assert!(ctx.is_monorepo);
    assert!(ctx.has_product);
    assert_eq!(extract_register(ctx.product.as_deref()), Some("brand".to_string()));

    // The sibling app with no PRODUCT.md has none, and is not a monorepo
    // root candidate list dead-end itself.
    let dashboard_ctx = load_context(&root.join("apps/dashboard"), &TargetOptions::none());
    assert!(!dashboard_ctx.has_product);
}

// ─── critique-storage.mjs: full write -> latest -> trend lifecycle ─────

#[test]
fn critique_snapshot_lifecycle_matches_slug_derived_from_target() {
    let root = tmp_dir("critique_lifecycle");
    fs::write(root.join("package.json"), "{}").unwrap();
    fs::create_dir_all(root.join("src")).unwrap();
    fs::write(root.join("src/App.tsx"), "export default function App() {}\n").unwrap();

    let slug = slug_from_target("src/App.tsx", &root).expect("slug");
    assert_eq!(slug, "src-app-tsx");

    let options = TargetOptions::none();
    write_snapshot(
        &root,
        &options,
        &slug,
        vec![("score".into(), "70".into()), ("p0".into(), "2".into())],
        "# Critique 1",
        1_700_000_000_000,
    )
    .unwrap();
    write_snapshot(
        &root,
        &options,
        &slug,
        vec![("score".into(), "88".into()), ("p0".into(), "0".into())],
        "# Critique 2 — fixed the P0s",
        1_700_100_000_000,
    )
    .unwrap();

    let latest = read_latest_snapshot(&slug, &root, &options).expect("latest snapshot");
    assert_eq!(latest.meta.get("score").map(String::as_str), Some("88"));
    assert!(latest.body.contains("fixed the P0s"));

    let trend = read_trend(&slug, 5, &root, &options);
    assert_eq!(trend.len(), 2);
    assert_eq!(trend[0].get("score").map(String::as_str), Some("70"));
    assert_eq!(trend[1].get("score").map(String::as_str), Some("88"));
}

// ─── context-signals.mjs: scan_targets sourced from real git_signals ────

#[test]
fn scan_targets_uses_live_git_signals_in_a_real_repo() {
    let root = tmp_dir("git_scan");
    let run = |args: &[&str]| {
        let status = std::process::Command::new("git")
            .args(args)
            .current_dir(&root)
            .status()
            .expect("git available");
        assert!(status.success(), "git {args:?} failed");
    };
    run(&["init", "-q"]);
    run(&["config", "user.email", "test@example.com"]);
    run(&["config", "user.name", "Test"]);
    fs::write(root.join("README.md"), "hello").unwrap();
    run(&["add", "."]);
    run(&["commit", "-q", "-m", "init"]);
    // dirty the tree with a scannable + a non-scannable change
    fs::write(root.join("App.tsx"), "// changed").unwrap();
    fs::write(root.join("README.md"), "hello again").unwrap();

    let git = git_signals(&root);
    assert!(git.is_repo);
    assert!(git.changed_files.iter().any(|f| f == "App.tsx"));

    let scan = scan_targets(&root, &git);
    assert_eq!(scan.via, Some("git-changes"));
    assert_eq!(scan.targets, vec!["App.tsx".to_string()]);
}

#[test]
fn gather_signals_smoke_in_a_real_git_repo_with_product_md() {
    let root = tmp_dir("gather_git_smoke");
    std::process::Command::new("git")
        .args(["init", "-q"])
        .current_dir(&root)
        .status()
        .unwrap();
    fs::write(root.join("PRODUCT.md"), "# Demo\n\n## Register\nproduct\n").unwrap();
    fs::create_dir_all(root.join("src")).unwrap();

    let signals = gather_signals(&root);
    assert!(signals.setup.has_product);
    assert_eq!(signals.setup.register.as_deref(), Some("product".to_string()));
    assert!(signals.git.is_repo);
}

// ─── detect-csp.mjs: fixture-backed shape classification ───────────────

#[test]
fn detect_csp_against_fixture_next_config_append_string() {
    let root = fixture_root().join("next-inline-headers");
    let result = detect_csp(&root);
    assert_eq!(result.shape, Some(CspShape::AppendString));
    assert!(result.signals.iter().any(|s| s == "next.config.js"));
}

#[test]
fn detect_csp_against_fixture_sveltekit_append_arrays() {
    let root = fixture_root().join("sveltekit-directives");
    let result = detect_csp(&root);
    assert_eq!(result.shape, Some(CspShape::AppendArrays));
    assert!(result.signals.iter().any(|s| s == "svelte.config.js"));
}

// ─── trivial GitSignals default sanity (documents the non-repo contract) ─

#[test]
fn default_git_signals_is_not_a_repo() {
    let g = GitSignals::default();
    assert!(!g.is_repo);
    assert!(g.branch.is_none());
    assert!(g.changed_files.is_empty());
}
