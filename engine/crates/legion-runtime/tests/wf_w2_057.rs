//! Integration tests for chunk w2_057
//! (`src/lib/tasklist-validator/validate-tasklist.py`).
//!
//! `src/lib/tasklist-validator/` carries no `test_validate_tasklist.py` of
//! its own to port (unlike the similarly-named script in
//! `dispatch-validator/`), so these tests are written directly against the
//! ported `validate()`/`template_check()`/`receipt_errors()` surface,
//! exercising a full passing tasklist+GoalRoute fixture and a set of
//! individually-broken variants, mirroring the Python script's own
//! documented contract.

use legion_runtime::wf_port::w2_057::{receipt_errors, template_check, validate, Context};
use std::path::PathBuf;

fn fixture_dir() -> PathBuf {
    // `validate-tasklist.py`'s `permanent_path()` rejects any path whose
    // lowercased form contains `/temp/`, `/tmp/`, `/scratch/`, `/.cache/`,
    // or `/review-run/` — and on macOS `std::env::temp_dir()` canonicalizes
    // through `/private/tmp/...`, which trips that check. Use a scratch
    // directory under the crate's own `target/` instead, which is both
    // absolute and free of every forbidden path segment.
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("target")
        .join("wf_w2_057_fixtures")
        .join(format!(
            "{}_{}",
            std::process::id(),
            ((std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()).wrapping_shl(20) | ({ static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0); u128::from(SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed)) }))
        ));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::canonicalize(&dir).unwrap_or(dir)
}

const ROUTE_JSON: &str = r#"{
  "schema": "goal-route.v2",
  "route_id": "route-1",
  "selected_route_id": "cand-a",
  "state_a": {"description": "before state"},
  "state_b": {
    "description": "after state",
    "proof": [{"command": "cargo test", "expected": "ok", "evidence_path": "/permanent/evidence.txt"}]
  },
  "selected_critical_path": ["s1", "s2"],
  "parallel_lanes": [],
  "deleted_work": [],
  "deferred_work": [],
  "invalidation": {"revision": 1},
  "candidates": [
    {
      "id": "cand-a",
      "expected_time_to_verified_b_ms": 12345,
      "steps": [
        {"id": "s1", "operation": "build", "depends_on": [], "b_state_delta": "compiled"},
        {"id": "s2", "operation": "test", "depends_on": ["s1"], "b_state_delta": "verified"}
      ]
    }
  ]
}"#;

fn write_route(dir: &std::path::Path) -> (PathBuf, PathBuf) {
    let route_path = dir.join("route.json");
    std::fs::write(&route_path, ROUTE_JSON).unwrap();
    let receipt_path = dir.join("route.receipt.json");
    std::fs::write(&receipt_path, b"{}").unwrap();
    (route_path, receipt_path)
}

fn tasklist_text(dir: &std::path::Path, canonical: &std::path::Path) -> String {
    format!(
        r#"# Tasklist

## 0. Control
- **Canonical path:** {canonical}
- **Purpose:** EXECUTE_HERE
- **Status:** PLANNED
- **Tasklist revision:** TASKLIST_REVISION:1
- **Tasklist ID:** demo-tasklist-1
- **Owner:** demo-owner
- **Scope boundary:** demo scope boundary text
- **Authority:** demo authority text
- **Non-goals:** demo non-goals text
- **Hard constraints:** demo hard constraints text

## 1. Goal Contract
- **State A:** STATE_A:before state
- **State B:** STATE_B:after state

## 2. GoalRoute Binding
- **Goal route artifact:** {route}
- **Goal route receipt:** {receipt}
- **Goal route schema:** goal-route.v2
- **Selected route:** SELECTED_ROUTE:cand-a
- **Expected time to verified B:** EXPECTED_TIME_TO_VERIFIED_B_MS:12345
- **Route revision:** ROUTE_REVISION:1
- **Critical path:** CRITICAL_PATH:s1>s2
- **Parallel lanes:** PARALLEL_LANES_JSON:[]
- **Deleted work:** DELETED_WORK_JSON:[]
- **Deferred work:** DEFERRED_WORK_JSON:[]

## 3. Execution Tasks
### Task 1 — Build it
- **Task status:** TODO
- **Route step:** ROUTE_STEP:s1
- **Action:** ACTION:build
- **Depends on:** START
- **Advances target:** ADVANCES_STATE_B:compiled
- **Done check:** CHECK:binary exists on disk
- **Expected result:** EXPECTED:binary runs and exits zero
- **Evidence path:** /permanent/evidence/task1.txt
- **On failure:** TRY: rebuild FALLBACK: use cached artifact RECOMPILE_IF: toolchain changed
- **Time span:** minute 0-5
- **Basis:** compile=5
- **Parallelizable:** no

### Task 2 — Test it
- **Task status:** TODO
- **Route step:** ROUTE_STEP:s2
- **Action:** ACTION:test
- **Depends on:** AFTER:s1
- **Advances target:** ADVANCES_STATE_B:verified
- **Done check:** CHECK:test suite exits zero
- **Expected result:** EXPECTED:all tests pass
- **Evidence path:** /permanent/evidence/task2.txt
- **On failure:** TRY: rerun FALLBACK: bisect failing test RECOMPILE_IF: never
- **Time span:** minute 5-10
- **Basis:** test=5
- **Parallelizable:** no

## 4. Recovery & TRUE_BLOCKER
- **TRUE_BLOCKER allowed only if:** RECOVERY_EXHAUSTED; INDEPENDENT_WORK_COMPLETE; NO_FEASIBLE_ROUTE; ONE_MISSING_EXTERNAL_INPUT

## 5. Progress & Change Control
- **Terminal record:** STATUS=PLANNED; DONE=0/2; NEXT=s1
- **Files touched:** FILES_TOUCHED:1
- **Lines changed:** LINES_CHANGED:100
- **Rate:** LINES_PER_MINUTE:20
- **Total minutes:** TOTAL_MINUTES:10

## 6. Completion Contract
- **Success proof:** PROOF_COMMAND:cargo test; EXPECTED:ok; EVIDENCE:/permanent/evidence.txt
- **Final evidence path:** /permanent/evidence/final.txt
- **Final verification:** run the full suite once more
- **Final expected result:** every test passes deterministically
"#,
        canonical = canonical.display(),
        route = dir.join("route.json").display(),
        receipt = dir.join("route.receipt.json").display(),
    )
}

fn write_minimize_sidecars(tasklist_path: &std::path::Path) {
    let stem = tasklist_path.with_extension("");
    let minimize_path = {
        let mut s = stem.clone().into_os_string();
        s.push(".minimize.json");
        PathBuf::from(s)
    };
    let receipt_path = {
        let mut s = stem.into_os_string();
        s.push(".minimize.receipt.json");
        PathBuf::from(s)
    };
    std::fs::write(&minimize_path, b"{}").unwrap();
    std::fs::write(&receipt_path, b"{}").unwrap();
}

#[test]
fn valid_tasklist_and_route_produce_no_errors() {
    let dir = fixture_dir();
    write_route(&dir);
    let tasklist_path = dir.join("plan.tasklist.md");
    let canonical = std::fs::canonicalize(&dir).unwrap_or(dir.clone()).join("plan.tasklist.md");
    let text = tasklist_text(&dir, &canonical);
    std::fs::write(&tasklist_path, &text).unwrap();
    write_minimize_sidecars(&tasklist_path);

    let resolved = std::fs::canonicalize(&tasklist_path).unwrap();
    let (errors, context) = validate(&resolved, &text);
    assert!(errors.is_empty(), "unexpected errors: {errors:?}");
    assert_eq!(context.task_count, 2);
    assert_eq!(context.total_minutes, Some(10));
    assert_eq!(context.parallelizable_task_count, 0);
    assert!(context.have_route);
}

#[test]
fn missing_headings_are_reported() {
    let dir = fixture_dir();
    let path = dir.join("broken.md");
    let (errors, context) = validate(&path, "not a tasklist at all");
    assert!(errors.iter().any(|e| e.contains("missing heading: ## 0. Control")));
    assert!(!context.have_route);
}

#[test]
fn placeholder_tokens_are_rejected() {
    let dir = fixture_dir();
    let path = dir.join("placeholder.md");
    let text = "## 0. Control\n{{STILL_A_TEMPLATE}}\n## 1. Goal Contract\n## 2. GoalRoute Binding\n## 3. Execution Tasks\n## 4. Recovery & TRUE_BLOCKER\n## 5. Progress & Change Control\n## 6. Completion Contract\n";
    let (errors, _context) = validate(&path, text);
    assert!(errors
        .iter()
        .any(|e| e.contains("unresolved template placeholders")));
}

#[test]
fn mismatched_time_span_basis_is_rejected() {
    let dir = fixture_dir();
    write_route(&dir);
    let tasklist_path = dir.join("plan.tasklist.md");
    let canonical = std::fs::canonicalize(&dir).unwrap_or(dir.clone()).join("plan.tasklist.md");
    let mut text = tasklist_text(&dir, &canonical);
    // Basis (5) no longer matches the (now 0-9) span length (9).
    text = text.replace("**Time span:** minute 0-5", "**Time span:** minute 0-9");
    std::fs::write(&tasklist_path, &text).unwrap();
    write_minimize_sidecars(&tasklist_path);

    let resolved = std::fs::canonicalize(&tasklist_path).unwrap();
    let (errors, _context) = validate(&resolved, &text);
    assert!(errors
        .iter()
        .any(|e| e.contains("named minutes sum to") && e.contains("Task 1")));
}

#[test]
fn banned_basis_label_is_rejected() {
    let dir = fixture_dir();
    write_route(&dir);
    let tasklist_path = dir.join("plan.tasklist.md");
    let canonical = std::fs::canonicalize(&dir).unwrap_or(dir.clone()).join("plan.tasklist.md");
    let mut text = tasklist_text(&dir, &canonical);
    text = text.replace("**Basis:** compile=5", "**Basis:** overhead=5");
    std::fs::write(&tasklist_path, &text).unwrap();
    write_minimize_sidecars(&tasklist_path);

    let resolved = std::fs::canonicalize(&tasklist_path).unwrap();
    let (errors, _context) = validate(&resolved, &text);
    assert!(errors
        .iter()
        .any(|e| e.contains("generic bucket") && e.contains("overhead")));
}

#[test]
fn implausibly_slow_rate_is_rejected() {
    let dir = fixture_dir();
    write_route(&dir);
    let tasklist_path = dir.join("plan.tasklist.md");
    let canonical = std::fs::canonicalize(&dir).unwrap_or(dir.clone()).join("plan.tasklist.md");
    let mut text = tasklist_text(&dir, &canonical);
    text = text.replace("LINES_PER_MINUTE:20", "LINES_PER_MINUTE:2");
    std::fs::write(&tasklist_path, &text).unwrap();
    write_minimize_sidecars(&tasklist_path);

    let resolved = std::fs::canonicalize(&tasklist_path).unwrap();
    let (errors, _context) = validate(&resolved, &text);
    assert!(errors.iter().any(|e| e.contains("implausibly slow")));
}

#[test]
fn template_check_flags_a_bare_document() {
    let errors = template_check("nothing here");
    assert!(!errors.is_empty());
    assert!(errors.iter().any(|e| e.contains("## 0. Control")));
}

#[test]
fn receipt_errors_reports_mismatch_on_wrong_schema() {
    let dir = fixture_dir();
    let (route_path, receipt_path) = write_route(&dir);
    let tasklist_path = dir.join("plan.tasklist.md");
    std::fs::write(&tasklist_path, b"raw bytes").unwrap();
    let wrong_receipt_path = dir.join("plan.tasklist.receipt.json");
    std::fs::write(&wrong_receipt_path, br#"{"schema": "wrong.schema.v9"}"#).unwrap();

    let context = Context {
        route_path,
        route_raw: ROUTE_JSON.as_bytes().to_vec(),
        route_receipt_path: receipt_path,
        ..Context::default()
    };
    let errors = receipt_errors(
        &tasklist_path,
        b"raw bytes",
        b"validator source bytes",
        &wrong_receipt_path,
        &context,
    );
    assert!(errors.contains(&"receipt schema mismatch".to_string()));
}
