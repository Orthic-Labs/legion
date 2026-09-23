//! Parity coverage for `legacy.architecture.decomposition` against the JS
//! reference in `tools/audit/collect-facts.mjs` (`decompositionReviewLoc()`
//! and the `decomposition` check): configurable review threshold (workspace
//! default 400 LOC, not an always-finding at 800), runtime/test/tooling
//! classification, and mechanical-split reconstruction.
//!
//! These tests exercise the exact registry route through the filesystem-owned
//! native implementation. They do not invoke Node, a shell, or a project tool.

use std::{
    collections::BTreeMap,
    fs,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

use legion_audit::{
    native_providers::legacy_checks::spec, AuditProvider, InventoryEntry, InventoryEnvelope,
    NativeProviderRegistry, ProviderExecutor,
};
use serde_json::{json, Value};
use std::sync::Mutex;

/// `decomposition_review_loc()` in the native provider reads the
/// `CORTEX_DECOMPOSITION_REVIEW_LOC` process env var, which is global state.
/// `cargo test` runs tests in this file concurrently on separate threads of
/// the same process, so any test that depends on that env var being absent
/// (or on a particular `.agent/config.json` threshold) races against
/// `env_var_overrides_workspace_default_threshold`, which sets and clears it.
/// Serialize every threshold-sensitive test on this lock so the env var
/// mutation in one test can never leak into another's assertions.
static THRESHOLD_ENV_LOCK: Mutex<()> = Mutex::new(());

fn provider(id: &str, selector: Value) -> AuditProvider {
    let contract = spec(id).expect("frozen provider");
    AuditProvider {
        id: id.into(),
        version: "2.0.0".into(),
        role: contract.role.into(),
        phase: contract.phase.into(),
        lens_ids: Vec::new(),
        dependencies: Vec::new(),
        kind: legion_audit::ProviderKind::TypedExternalProjectTool,
        configuration: BTreeMap::from([
            ("selector".into(), selector),
            (
                "runner".into(),
                json!({"kind":"legacy-check","check":contract.check}),
            ),
        ]),
        bounds: BTreeMap::new(),
        clean_claim: "evidence-only".into(),
        benchmark_status: "unproven".into(),
        benchmark_required_for_clean_claim: false,
        qualification_digest: None,
        required: false,
    }
}

fn root() -> PathBuf {
    let suffix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock")
        .as_nanos();
    let root = std::env::temp_dir().join(format!("legion-decomposition-parity-{suffix}"));
    fs::create_dir_all(&root).expect("temporary repository");
    root
}

fn inventory(paths: &[&str]) -> InventoryEnvelope {
    InventoryEnvelope::new(
        "decomposition-parity-fixture",
        "decomposition-parity-generation",
        paths
            .iter()
            .map(|path| InventoryEntry {
                path: (*path).into(),
                symbols: Vec::new(),
                dependencies: Vec::new(),
                package_scripts: Vec::new(),
                source_file: true,
                digest: None,
            })
            .collect(),
    )
    .expect("fixture inventory")
}

fn lines_of(count: usize) -> String {
    (0..count)
        .map(|n| format!("const line_{n} = {n};"))
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn default_threshold_is_400_loc_not_800() {
    let _guard = THRESHOLD_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let root = root();
    // 450 LOC: above the JS workspace default (400) but below the old
    // hardcoded native threshold (800) — must now trigger a review candidate.
    fs::write(root.join("big.ts"), lines_of(450)).unwrap();
    let inv = inventory(&["big.ts"]);
    let selector = json!({"op":"always"});
    let result = NativeProviderRegistry::new(&root)
        .execute(&provider("legacy.architecture.decomposition", selector), &inv)
        .unwrap();
    let candidates = result.details.get("candidates").unwrap().as_array().unwrap();
    assert!(
        !candidates.is_empty(),
        "450 LOC file must trigger a review candidate at the 400 LOC default threshold"
    );
    assert_eq!(result.details.get("threshold").unwrap().as_u64(), Some(400));
    assert_eq!(
        result.details.get("thresholdSource").unwrap().as_str(),
        Some("workspace-default")
    );
    let _ = fs::remove_dir_all(root);
}

#[test]
fn file_below_threshold_is_not_flagged() {
    let root = root();
    fs::write(root.join("small.ts"), lines_of(50)).unwrap();
    let inv = inventory(&["small.ts"]);
    let result = NativeProviderRegistry::new(&root)
        .execute(
            &provider("legacy.architecture.decomposition", json!({"op":"always"})),
            &inv,
        )
        .unwrap();
    let candidates = result.details.get("candidates").unwrap().as_array().unwrap();
    assert!(candidates.is_empty());
    let _ = fs::remove_dir_all(root);
}

#[test]
fn env_var_overrides_workspace_default_threshold() {
    let _guard = THRESHOLD_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let root = root();
    fs::write(root.join("mid.ts"), lines_of(500)).unwrap();
    let inv = inventory(&["mid.ts"]);
    std::env::set_var("CORTEX_DECOMPOSITION_REVIEW_LOC", "600");
    let result = NativeProviderRegistry::new(&root)
        .execute(
            &provider("legacy.architecture.decomposition", json!({"op":"always"})),
            &inv,
        )
        .unwrap();
    std::env::remove_var("CORTEX_DECOMPOSITION_REVIEW_LOC");
    let candidates = result.details.get("candidates").unwrap().as_array().unwrap();
    assert!(
        candidates.is_empty(),
        "500 LOC file must not trigger when the env threshold is raised to 600"
    );
    assert_eq!(result.details.get("threshold").unwrap().as_u64(), Some(600));
    assert_eq!(
        result.details.get("thresholdSource").unwrap().as_str(),
        Some("blueprint-config")
    );
    let _ = fs::remove_dir_all(root);
}

#[test]
fn config_file_threshold_is_read_when_env_is_absent() {
    let _guard = THRESHOLD_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let root = root();
    fs::write(root.join("mid.ts"), lines_of(500)).unwrap();
    fs::create_dir_all(root.join(".agent")).unwrap();
    fs::write(
        root.join(".agent/config.json"),
        r#"{"hygiene":{"decompositionReviewLoc":700}}"#,
    )
    .unwrap();
    let inv = inventory(&["mid.ts"]);
    let result = NativeProviderRegistry::new(&root)
        .execute(
            &provider("legacy.architecture.decomposition", json!({"op":"always"})),
            &inv,
        )
        .unwrap();
    let candidates = result.details.get("candidates").unwrap().as_array().unwrap();
    assert!(candidates.is_empty());
    assert_eq!(result.details.get("threshold").unwrap().as_u64(), Some(700));
    assert_eq!(
        result.details.get("thresholdSource").unwrap().as_str(),
        Some(".agent/config.json")
    );
    let _ = fs::remove_dir_all(root);
}

#[test]
fn test_classified_oversized_file_is_low_severity_not_runtime() {
    let root = root();
    fs::write(root.join("big.test.ts"), lines_of(450)).unwrap();
    let inv = inventory(&["big.test.ts"]);
    let result = NativeProviderRegistry::new(&root)
        .execute(
            &provider("legacy.architecture.decomposition", json!({"op":"always"})),
            &inv,
        )
        .unwrap();
    let candidates = result.details.get("candidates").unwrap().as_array().unwrap();
    assert_eq!(candidates.len(), 1);
    assert_eq!(candidates[0]["severityHint"].as_str(), Some("low"));
    let by_class = result.details.get("byClass").unwrap();
    assert_eq!(by_class["test"].as_u64(), Some(1));
    assert_eq!(by_class["runtime"].as_u64(), Some(0));
    let _ = fs::remove_dir_all(root);
}

#[test]
fn mechanical_split_across_parts_dir_reconstructs_logical_loc() {
    let root = root();
    fs::create_dir_all(root.join("engine/big_parts")).unwrap();
    // Each part is small on its own but the reconstructed logical unit
    // exceeds the 400 LOC review trigger.
    fs::write(root.join("engine/big_parts/part1.rs"), lines_of(250)).unwrap();
    fs::write(root.join("engine/big_parts/part2.rs"), lines_of(250)).unwrap();
    let inv = inventory(&[
        "engine/big_parts/part1.rs",
        "engine/big_parts/part2.rs",
    ]);
    let result = NativeProviderRegistry::new(&root)
        .execute(
            &provider("legacy.architecture.decomposition", json!({"op":"always"})),
            &inv,
        )
        .unwrap();
    let candidates = result.details.get("candidates").unwrap().as_array().unwrap();
    assert!(
        candidates
            .iter()
            .any(|c| c["ruleId"] == "architecture.decomposition-mechanical-split"),
        "two 250-LOC parts under a *_parts/ dir must reconstruct to a 500 LOC mechanical split candidate"
    );
    let _ = fs::remove_dir_all(root);
}

#[test]
fn generated_and_vendored_paths_are_excluded() {
    let root = root();
    fs::create_dir_all(root.join("dist")).unwrap();
    fs::write(root.join("dist/bundle.js"), lines_of(500)).unwrap();
    let inv = inventory(&["dist/bundle.js"]);
    let result = NativeProviderRegistry::new(&root)
        .execute(
            &provider("legacy.architecture.decomposition", json!({"op":"always"})),
            &inv,
        )
        .unwrap();
    let candidates = result.details.get("candidates").unwrap().as_array().unwrap();
    assert!(candidates.is_empty(), "dist/ is generated/vendored and must not be flagged");
    let _ = fs::remove_dir_all(root);
}
