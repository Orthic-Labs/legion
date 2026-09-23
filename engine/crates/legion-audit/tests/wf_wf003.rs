// wf003 — integration tests for the Phase 6.7 evidence gauntlet port
// (engine/crates/legion-audit/src/wf_port/wf003/**).
//
// Ports the assertions from src/lib/gauntlet/tests/gauntlet.test.mjs onto
// the Rust `run_gauntlet` orchestrator. Fixtures are materialised into a
// throwaway git repo per test, mirroring the JS harness's `materialise()`.
//
// NOTE: this file assumes the integrator has wired `pub mod wf_port;` into
// `legion-audit`'s `src/lib.rs` and `pub mod wf003;` into
// `src/wf_port/mod.rs`, and that `legion_audit::wf_port::wf003` re-exports
// (or is otherwise reachable as) below. If the integrator instead nests
// this differently, only the `use` line needs updating.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use legion_audit::wf_port::wf003::{disabled_order_layer, run_gauntlet, RunGauntletOptions};

fn fixtures_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/wf_wf003")
}

fn run_git(dir: &Path, args: &[&str]) {
    let status = Command::new("git")
        .args(args)
        .current_dir(dir)
        .status()
        .expect("spawn git");
    assert!(status.success(), "git {args:?} failed in {}", dir.display());
}

/// Materialises `fixtures/wf_wf003/<name>/base` as a committed git repo,
/// then layers `fixtures/wf_wf003/<name>/changed` on top uncommitted —
/// mirroring `materialise()` in gauntlet.test.mjs.
fn materialise(name: &str) -> PathBuf {
    // Matches JS `materialise()` (`src/lib/gauntlet/tests/gauntlet.test.mjs`),
    // which uses `mkdtempSync` for a unique directory per call. A
    // `process::id()`-only path collided across tests that cargo runs in
    // parallel threads within one process and that share a fixture `name`
    // (e.g. two tests both materialising "sample-diff"): one thread's
    // `remove_dir_all` could wipe another thread's already-committed repo,
    // surfacing as "nothing to commit" from `git commit`.
    static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let unique = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let src = fixtures_root().join(name);
    let dir = std::env::temp_dir().join(format!(
        "wf003-gauntlet-{name}-{}-{unique}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    copy_dir(&src.join("base"), &dir);
    run_git(&dir, &["init", "-q", "--initial-branch=main"]);
    run_git(&dir, &["config", "user.email", "t@t"]);
    run_git(&dir, &["config", "user.name", "t"]);
    run_git(&dir, &["add", "-A"]);
    run_git(&dir, &["commit", "-qm", "init"]);
    let changed = src.join("changed");
    if changed.exists() {
        copy_dir(&changed, &dir);
    }
    dir
}

fn copy_dir(src: &Path, dst: &Path) {
    for entry in fs::read_dir(src).unwrap() {
        let entry = entry.unwrap();
        let from = entry.path();
        let to = dst.join(entry.file_name());
        if from.is_dir() {
            fs::create_dir_all(&to).unwrap();
            copy_dir(&from, &to);
        } else {
            fs::copy(&from, &to).unwrap();
        }
    }
}

/// Mirrors: "emits a Arcane-shaped check object with host executor and
/// receipt" + "catches a surviving mutant in the weak fixture".
#[test]
fn weak_test_surfaces_a_surviving_mutant_and_host_shaped_check() {
    let dir = materialise("sample-diff");
    let run = run_gauntlet(RunGauntletOptions {
        cwd: Some(dir.as_path()),
        base: None,
        diff_file: None,
        test_command: "node --test test/sum.test.mjs",
        run_mutation: true,
        run_coverage: false,
        order_layer: disabled_order_layer(),
    })
    .expect("gauntlet run");

    assert_eq!(run.exit_code, 1, "gauntlet must exit 1 when a mutant survives");
    assert_eq!(run.check.executor, "host");
    assert_eq!(run.check.authority, "host");
    assert_eq!(run.check.kind, "gauntlet");
    assert_eq!(run.check.status, "failed");
    assert_eq!(run.check.exit_code, 1);
    assert!(!run.check.receipt.is_empty(), "receipt field required");

    let receipt: serde_json::Value = serde_json::from_str(&run.check.receipt).unwrap();
    assert_eq!(receipt["schema"], "orthic.tool-receipt.v1");
    assert_eq!(receipt["exit_status"], 1);
    assert!(receipt["summary"]["mutation"].is_object(), "receipt must include mutation summary");

    let output: serde_json::Value = serde_json::from_str(&run.check.output).unwrap();
    let mutation_results = output["layers"]["mutation"]["results"].as_array().expect("mutation results array");
    let survived: Vec<_> = mutation_results
        .iter()
        .filter(|r| r["status"] == "survived")
        .collect();
    assert!(!survived.is_empty(), "fixture must contain at least one killable-but-survived mutant; got: {mutation_results:?}");
    let neq_survivor = survived.iter().find(|r| r["mutator"] == "neq-flip");
    assert!(neq_survivor.is_some(), "expected a === -> !== survivor; got: {survived:?}");

    let _ = fs::remove_dir_all(&dir);
}

/// Mirrors: "reports clean change-line mutation when test is strong enough".
#[test]
fn strong_test_kills_every_mutator() {
    let dir = materialise("sample-diff");
    let test_path = dir.join("test/sum.test.mjs");
    let strong = "import { sum, mean } from \"../src/sum.js\";\n\
import assert from \"node:assert/strict\";\n\
if (sum([1, 2, 3]) !== 6) throw new Error(\"sum([1,2,3]) failed\");\n\
if (sum([10, 20]) !== 30) throw new Error(\"sum([10,20]) failed\");\n\
if (sum([0, 5, 7]) !== 12) throw new Error(\"sum([0,5,7]) failed\");\n\
if (mean([]) !== 0) throw new Error(\"mean([]) failed\");\n\
if (mean([2, 4, 6]) !== 4) throw new Error(\"mean([2,4,6]) failed\");\n\
console.log(\"strong-test-ok\");\n";
    fs::write(&test_path, strong).unwrap();

    let run = run_gauntlet(RunGauntletOptions {
        cwd: Some(dir.as_path()),
        base: None,
        diff_file: None,
        test_command: "node test/sum.test.mjs",
        run_mutation: true,
        run_coverage: false,
        order_layer: disabled_order_layer(),
    })
    .expect("gauntlet run");

    let output: serde_json::Value = serde_json::from_str(&run.check.output).unwrap();
    let mutation_results = output["layers"]["mutation"]["results"].as_array().expect("mutation results array");
    let survivors: Vec<_> = mutation_results.iter().filter(|r| r["status"] == "survived").collect();
    assert!(survivors.is_empty(), "strong test should kill every mutator; survivors: {survivors:?}");
    assert_eq!(run.check.status, "passed");

    let _ = fs::remove_dir_all(&dir);
}

/// Mirrors: "returns 'no_diff' failure when the diff is empty".
#[test]
fn empty_diff_reports_no_diff_failure() {
    let dir = materialise("empty-repo");
    let run = run_gauntlet(RunGauntletOptions {
        cwd: Some(dir.as_path()),
        base: None,
        diff_file: None,
        test_command: "true",
        run_mutation: false,
        run_coverage: false,
        order_layer: disabled_order_layer(),
    })
    .expect("gauntlet run");

    assert_eq!(run.exit_code, 1, "gauntlet must exit 1 when diff is empty");
    assert_eq!(run.check.status, "failed");
    assert!(!run.check.receipt.is_empty(), "receipt always emitted");
    let receipt: serde_json::Value = serde_json::from_str(&run.check.receipt).unwrap();
    assert_eq!(receipt["exit_status"], 1);

    let _ = fs::remove_dir_all(&dir);
}
