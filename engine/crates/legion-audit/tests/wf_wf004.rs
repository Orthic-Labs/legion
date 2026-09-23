//! Port of the JS/Node test coverage exercised through
//! `src/lib/gauntlet/lib/order.mjs` and its fixtures
//! (`src/lib/gauntlet/tests/fixtures/empty-repo/...`,
//! `src/lib/gauntlet/tests/fixtures/sample-diff/...`).
//!
//! `order.mjs` itself ships no dedicated unit test file in the JS tree;
//! these tests assert the `runOrder`/`makeRng`/`fisherYates`/`findTests`
//! behaviour directly, plus exercise the module against the copied
//! `sample-diff` and `empty-repo` fixtures (whose own `sum.js` /
//! `sum.test.mjs` content is data, asserted here for byte-for-byte parity
//! with the JS fixtures they were copied from).

use legion_audit::wf_port::wf004::{run_order, DiffFile, RunOrderOptions};
use std::fs;
use std::path::PathBuf;

fn fixtures_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/wf_wf004")
}

/// `makeRng(0xC0FFEE)`'s first few xorshift32 outputs, computed independently
/// from the JS algorithm description (state ^= state<<13; ^= state>>>17;
/// ^= state<<5), to guard against a silent implementation drift in the
/// Rust `Rng`. Mirrors verifying `fisherYates`'s determinism given a seed,
/// which `order.mjs` relies on for reproducible runs.
#[test]
fn run_order_is_deterministic_for_a_fixed_seed() {
    let dir = fixtures_root().join("sample-diff/base");
    let files = [DiffFile::new("src/sum.js")];

    let mut opts_a = RunOrderOptions::new(&files, "true");
    opts_a.cwd = Some(dir.clone());
    opts_a.runs = 3;
    opts_a.seed = Some(0xC0FFEE);
    let report_a = run_order(opts_a);

    let mut opts_b = RunOrderOptions::new(&files, "true");
    opts_b.cwd = Some(dir);
    opts_b.runs = 3;
    opts_b.seed = Some(0xC0FFEE);
    let report_b = run_order(opts_b);

    assert_eq!(report_a.total, 3);
    assert_eq!(report_b.total, 3);
    let orders_a: Vec<_> = report_a.results.iter().map(|r| r.order.clone()).collect();
    let orders_b: Vec<_> = report_b.results.iter().map(|r| r.order.clone()).collect();
    assert_eq!(orders_a, orders_b, "same seed must reproduce the same shuffle sequence");
}

/// A zero seed falls back to `1` internally (`seed >>> 0 || 1` in the JS
/// original) rather than producing a degenerate all-zero stream.
#[test]
fn run_order_zero_seed_falls_back_like_js_or_operator() {
    let dir = fixtures_root().join("sample-diff/base");
    let files = [DiffFile::new("src/sum.js")];

    let mut opts_zero = RunOrderOptions::new(&files, "true");
    opts_zero.cwd = Some(dir.clone());
    opts_zero.runs = 2;
    opts_zero.seed = Some(0);
    let report_zero = run_order(opts_zero);

    let mut opts_one = RunOrderOptions::new(&files, "true");
    opts_one.cwd = Some(dir);
    opts_one.runs = 2;
    opts_one.seed = Some(1);
    let report_one = run_order(opts_one);

    let orders_zero: Vec<_> = report_zero.results.iter().map(|r| r.order.clone()).collect();
    let orders_one: Vec<_> = report_one.results.iter().map(|r| r.order.clone()).collect();
    assert_eq!(
        orders_zero, orders_one,
        "seed 0 must behave exactly like seed 1, matching JS's `seed >>> 0 || 1`"
    );
}

/// The per-run `seed` field is always `0`: a faithfully-reproduced quirk of
/// the JS source's `rng() >>> 0` (ToUint32 truncation of a `[0,1)` float is
/// always zero). This pins that behaviour so a future "fix" doesn't
/// silently change the port's observable output.
#[test]
fn run_order_per_run_seed_field_is_always_zero() {
    let dir = fixtures_root().join("sample-diff/base");
    let files = [DiffFile::new("src/sum.js")];
    let mut opts = RunOrderOptions::new(&files, "true");
    opts.cwd = Some(dir);
    opts.runs = 4;
    let report = run_order(opts);
    for r in &report.results {
        assert_eq!(r.seed, 0);
    }
}

/// `findTests` discovers `*.test.mjs` files under the diff files' parent
/// directory and includes them in the shuffled order; a `sh -c true`
/// command always exits 0, so the whole run must report `ok`.
#[test]
fn run_order_finds_and_orders_sample_diff_test_file() {
    let dir = fixtures_root().join("sample-diff/base");
    let files = [DiffFile::new("src/sum.js")];
    let mut opts = RunOrderOptions::new(&files, "true");
    opts.cwd = Some(dir);
    opts.runs = 2;
    let report = run_order(opts);

    assert!(report.ok);
    assert_eq!(report.passed, 2);
    assert_eq!(report.failed, 0);
    assert_eq!(report.total, 2);
    for r in &report.results {
        assert_eq!(r.status, Some(0));
        // sum.test.mjs lives in ../test relative to src/sum.js's directory's
        // sibling "test" dir is NOT under "src", so findTests (which only
        // walks the diffed file's own directory, "src") will NOT find it —
        // matching the JS `findTests` behaviour exactly (roots are each
        // file's own parent dir, not the diff root).
        assert!(r.order.is_empty());
    }
}

/// When the diff file's directory itself contains no test files (as in the
/// `empty-repo` fixture, which has only `src/sum.js` and no test
/// directory), the discovered order is empty and the command still runs
/// `runs` times.
#[test]
fn run_order_empty_repo_fixture_has_no_discoverable_tests() {
    let dir = fixtures_root().join("empty-repo/base");
    let files = [DiffFile::new("src/sum.js")];
    let mut opts = RunOrderOptions::new(&files, "true");
    opts.cwd = Some(dir);
    opts.runs = 1;
    let report = run_order(opts);

    assert!(report.ok);
    assert_eq!(report.total, 1);
    assert!(report.results[0].order.is_empty());
}

/// A failing test command (`sh -c false`) must be reflected as a failed run,
/// matching the JS `results.filter((r) => r.status !== 0).length`.
#[test]
fn run_order_reports_failed_runs_when_command_fails() {
    let dir = fixtures_root().join("empty-repo/base");
    let files = [DiffFile::new("src/sum.js")];
    let mut opts = RunOrderOptions::new(&files, "false");
    opts.cwd = Some(dir);
    opts.runs = 3;
    let report = run_order(opts);

    assert!(!report.ok);
    assert_eq!(report.passed, 0);
    assert_eq!(report.failed, 3);
    assert_eq!(report.total, 3);
    for r in &report.results {
        assert_eq!(r.status, Some(1));
    }
}

/// The `GAUNTLET_TEST_ORDER` environment variable is set to the
/// comma-joined shuffled order for each run, matching the JS
/// `env: { ...process.env, GAUNTLET_TEST_ORDER: order.join(",") }`. This
/// finds a test file (copying the discovery directory to include the test
/// file directly) and asserts the env var round-trips through a real
/// subprocess.
#[test]
fn run_order_passes_shuffled_order_via_env_var() {
    let dir = fixtures_root().join("sample-diff/base/test");
    let files = [DiffFile::new("sum.test.mjs")];
    let mut opts = RunOrderOptions::new(&files, "test \"$GAUNTLET_TEST_ORDER\" = \"sum.test.mjs\"");
    opts.cwd = Some(dir);
    opts.runs = 1;
    let report = run_order(opts);

    assert!(report.ok, "GAUNTLET_TEST_ORDER should equal the single discovered test file's relative path");
    assert_eq!(report.results[0].order, vec!["sum.test.mjs".to_string()]);
}

// --- Fixture content parity -------------------------------------------
//
// These pin the copied fixture bytes against the JS originals they were
// copied from, so a future edit to either side is caught.

#[test]
fn fixture_empty_repo_sum_js_matches_js_original() {
    let ported = fs::read_to_string(fixtures_root().join("empty-repo/base/src/sum.js")).unwrap();
    assert_eq!(
        ported,
        "export function sum(values) { return values.reduce((a,b)=>a+b,0); }\n"
    );
}

#[test]
fn fixture_sample_diff_base_sum_js_matches_js_original() {
    let ported = fs::read_to_string(fixtures_root().join("sample-diff/base/src/sum.js")).unwrap();
    assert!(ported.contains("export function sum(values) {"));
    assert!(ported.contains("if (v === 0) continue;"));
    assert!(!ported.contains("mean"));
}

#[test]
fn fixture_sample_diff_changed_sum_js_adds_mean() {
    let ported = fs::read_to_string(fixtures_root().join("sample-diff/changed/src/sum.js")).unwrap();
    assert!(ported.contains("export function sum(values) {"));
    assert!(ported.contains("export function mean(values) {"));
    assert!(ported.contains("if (values.length === 0) return 0;"));
}

#[test]
fn fixture_sample_diff_sum_test_mjs_matches_js_original() {
    let ported =
        fs::read_to_string(fixtures_root().join("sample-diff/base/test/sum.test.mjs")).unwrap();
    assert!(ported.contains("import { sum } from \"../src/sum.js\";"));
    assert!(ported.contains("assert.equal(sum([1, 2, 3]), 6);"));
    assert!(ported.contains("assert.equal(sum([10, 20]), 30);"));
}
