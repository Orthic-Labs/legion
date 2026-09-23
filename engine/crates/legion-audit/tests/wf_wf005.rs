//! Port of `src/lib/gauntlet/tests/gauntlet.test.mjs` ("phase 6.7 evidence
//! gauntlet" self-tests) against the Rust gauntlet orchestrator in
//! `legion_audit::wf_port::wf005::gauntlet`.
//!
//! These tests are the gauntlet's own proof: when fed a code+test fixture
//! where the test is too weak to detect a token-flip mutant, the gauntlet
//! must report that mutant as `"survived"`. Never weaken a test to make
//! the gauntlet pass — fix the gauntlet or the fixture.
//!
//! Fixtures are copied as plain tracked files (not embedded git
//! repositories) under `tests/fixtures/wf_wf005/`, mirroring the JS
//! source's `tests/fixtures/{sample-diff,empty-repo}` — each fixture is
//! materialised into a throwaway repo here: `base/` is committed,
//! `changed/` is layered on top uncommitted to form the diff the gauntlet
//! scans.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use legion_audit::wf_port::wf005::gauntlet::{run_gauntlet, GauntletOptions};

const FIXTURES_ROOT: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/wf_wf005");

static NEXT_ID: AtomicU64 = AtomicU64::new(0);

fn unique_dir(label: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let counter = NEXT_ID.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!(
        "wf005-gauntlet-{label}-{}-{nanos}-{counter}",
        std::process::id()
    ));
    fs::create_dir_all(&dir).expect("create materialised fixture dir");
    dir
}

fn copy_dir_recursive(src: &Path, dst: &Path) {
    fs::create_dir_all(dst).unwrap();
    for entry in fs::read_dir(src).unwrap() {
        let entry = entry.unwrap();
        let from = entry.path();
        let to = dst.join(entry.file_name());
        if from.is_dir() {
            copy_dir_recursive(&from, &to);
        } else {
            fs::copy(&from, &to).unwrap();
        }
    }
}

fn git(dir: &Path, args: &[&str]) {
    let out = Command::new("git").args(args).current_dir(dir).output().expect("spawn git");
    assert!(
        out.status.success(),
        "git {:?} failed in {}: {}",
        args,
        dir.display(),
        String::from_utf8_lossy(&out.stderr)
    );
}

/// Mirrors JS `materialise(name)`.
fn materialise(name: &str) -> PathBuf {
    let src = Path::new(FIXTURES_ROOT).join(name);
    let dir = unique_dir(name);
    let base = src.join("base");
    copy_dir_recursive(&base, &dir);
    git(&dir, &["init", "-q", "--initial-branch=main"]);
    git(&dir, &["config", "user.email", "t@t"]);
    git(&dir, &["config", "user.name", "t"]);
    git(&dir, &["add", "-A"]);
    git(&dir, &["commit", "-qm", "init"]);
    let changed = src.join("changed");
    if changed.exists() {
        copy_dir_recursive(&changed, &dir);
    }
    dir
}

fn cleanup(dir: &Path) {
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn emits_an_arcane_shaped_check_object_with_host_executor_and_receipt() {
    let fixture = materialise("sample-diff");
    let run = run_gauntlet(GauntletOptions {
        cwd: &fixture,
        test_command: Some("node --test test/sum.test.mjs"),
        no_mutation: false,
        no_coverage: true,
        no_order: true,
        ..GauntletOptions::default()
    });
    assert_eq!(
        run.exit_code, 1,
        "gauntlet must exit 1 when a mutant survives; check={}",
        run.check
    );
    let out = &run.check;
    assert_eq!(out["executor"], "host");
    assert_eq!(out["authority"], "host");
    assert_eq!(out["kind"], "gauntlet");
    assert_eq!(out["status"], "failed");
    assert_eq!(out["exit_code"], 1);
    assert!(out["receipt"].is_string(), "receipt field required");
    let receipt: serde_json::Value = serde_json::from_str(out["receipt"].as_str().unwrap()).unwrap();
    assert_eq!(receipt["schema"], "orthic.tool-receipt.v1");
    assert_eq!(receipt["exit_status"], 1);
    assert!(
        receipt["summary"]["mutation"].is_object(),
        "receipt must include mutation summary"
    );
    cleanup(&fixture);
}

#[test]
fn catches_a_surviving_mutant_in_the_weak_fixture() {
    let fixture = materialise("sample-diff");
    let run = run_gauntlet(GauntletOptions {
        cwd: &fixture,
        test_command: Some("node --test test/sum.test.mjs"),
        no_mutation: false,
        no_coverage: true,
        no_order: true,
        ..GauntletOptions::default()
    });
    let output_str = run.check["output"].as_str().expect("output is a JSON string");
    let layers: serde_json::Value = serde_json::from_str(output_str).unwrap();
    let results = layers["layers"]["mutation"]["results"].as_array().expect("results array");
    let survived: Vec<&serde_json::Value> = results
        .iter()
        .filter(|r| r["status"].as_str() == Some("survived"))
        .collect();
    assert!(
        !survived.is_empty(),
        "fixture must contain at least one killable-but-survived mutant; got: {results:?}"
    );
    let neq_survivor = survived.iter().find(|r| r["mutator"] == "neq-flip");
    assert!(
        neq_survivor.is_some(),
        "expected a `===` -> `!==` survivor; got: {survived:?}"
    );
    cleanup(&fixture);
}

#[test]
fn reports_clean_change_line_mutation_when_test_is_strong_enough() {
    let fixture = materialise("sample-diff");
    // Strengthen the test the same way the JS suite does: exercise both
    // the `=== 0` branch (so a `===` -> `!==` mutation on that line breaks
    // the test) AND the negative-result path of `mean` (so a `neg-flip`
    // on `sum/len` breaks the test). Fix the test to actually cover the
    // change — never weaken the gauntlet to make it pass. Bypass `node
    // --test`'s recursive detection by using a plain script.
    let test_path = fixture.join("test/sum.test.mjs");
    let strong = r#"import { sum, mean } from "../src/sum.js";
if (sum([1, 2, 3]) !== 6) throw new Error("sum([1,2,3]) failed");
if (sum([10, 20]) !== 30) throw new Error("sum([10,20]) failed");
if (sum([0, 5, 7]) !== 12) throw new Error("sum([0,5,7]) failed");
if (mean([]) !== 0) throw new Error("mean([]) failed");
if (mean([2, 4, 6]) !== 4) throw new Error("mean([2,4,6]) failed");
console.log("strong-test-ok");
"#;
    fs::write(&test_path, strong).unwrap();

    let run = run_gauntlet(GauntletOptions {
        cwd: &fixture,
        test_command: Some("node test/sum.test.mjs"),
        no_mutation: false,
        no_coverage: true,
        no_order: true,
        ..GauntletOptions::default()
    });
    let output_str = run.check["output"].as_str().expect("output is a JSON string");
    let layers: serde_json::Value = serde_json::from_str(output_str).unwrap();
    let results = layers["layers"]["mutation"]["results"].as_array().expect("results array");
    let survivors: Vec<&serde_json::Value> = results
        .iter()
        .filter(|r| r["status"].as_str() == Some("survived"))
        .collect();
    assert!(
        survivors.is_empty(),
        "strong test should kill every mutator; survivors: {survivors:?}"
    );
    assert_eq!(run.check["status"], "passed");
    cleanup(&fixture);
}

#[test]
fn returns_no_diff_failure_when_the_diff_is_empty() {
    // Use a from-scratch git repo so the diff is genuinely empty (no
    // uncommitted `changed/` overlay is applied for this fixture).
    let empty_repo = materialise("empty-repo");
    let run = run_gauntlet(GauntletOptions {
        cwd: &empty_repo,
        no_mutation: true,
        no_coverage: true,
        no_order: true,
        ..GauntletOptions::default()
    });
    assert_eq!(run.exit_code, 1, "gauntlet must exit 1 when diff is empty");
    assert_eq!(run.check["status"], "failed");
    assert!(run.check["receipt"].is_string(), "receipt always emitted");
    let receipt: serde_json::Value = serde_json::from_str(run.check["receipt"].as_str().unwrap()).unwrap();
    assert_eq!(receipt["exit_status"], 1);
    cleanup(&empty_repo);
}
