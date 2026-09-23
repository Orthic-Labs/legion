//! Packet F — known-answer bench / recall gate.
//!
//! Runs the REAL native Audit providers (production dispatch through
//! `NativeProviderRegistry`, wired to the real `EffectExecutor` subprocess
//! route exactly as `legion` bin's `native_audit_external_tool` wires it) over
//! the AU20 planted-defect bench fixtures ported from `bench/manifest.json`.
//! For every bench class this asserts: the positive fixture is detected, and
//! the negative-control fixture produces zero findings. A class with no
//! native provider mapping fails loudly as "uncovered class" rather than
//! being silently skipped — coverage is never faked.

use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use legion_audit::{
    native_providers::legacy_checks::spec, AuditProvider, InventoryEntry, InventoryEnvelope,
    NativeProviderRegistry, ProviderExecutor, ProviderKind,
};
use serde_json::{json, Value};

const MANIFEST: &str = include_str!("fixtures/bench/manifest.json");

/// class -> legacy-check provider id that is supposed to catch it in the
/// native Rust port. `None` means: no native provider exists for this class
/// yet (must fail as an explicit uncovered-class case, never silently pass).
fn provider_for_class(class: &str) -> Option<&'static str> {
    match class {
        "secret" => Some("legacy.security.secrets"),
        "dependency_cve" => Some("legacy.security.node-dependencies"),
        "dead_code" => Some("legacy.quality.dead-code"),
        "duplication" => Some("legacy.quality.duplication"),
        "type_error" => Some("legacy.quality.types"),
        // "drift" (doc-drift) has no deterministic legacy-check contract;
        // the only registry entry for it is `reasoning.doc-drift`, an
        // LLM-adjudicated provider, not a recall-bench-eligible detector.
        "drift" => None,
        _ => None,
    }
}

fn registry_lens_ids(id: &str) -> Vec<String> {
    let raw = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../src/registry/providers.json"
    ))
    .expect("packaged provider registry");
    let registry: Value = serde_json::from_str(&raw).expect("registry JSON");
    registry["providers"]
        .as_array()
        .and_then(|items| {
            items
                .iter()
                .find(|item| item["id"].as_str() == Some(id))
                .map(|item| {
                    item["lensIds"]
                        .as_array()
                        .map(|lenses| {
                            lenses
                                .iter()
                                .filter_map(|lens| lens.as_str().map(ToOwned::to_owned))
                                .collect()
                        })
                        .unwrap_or_default()
                })
        })
        .unwrap_or_default()
}

fn provider(id: &str, selector: Value) -> AuditProvider {
    let contract = spec(id).unwrap_or_else(|| panic!("legacy provider {id} must be frozen"));
    AuditProvider {
        id: id.into(),
        version: "2.0.0".into(),
        role: contract.role.into(),
        phase: contract.phase.into(),
        lens_ids: registry_lens_ids(id),
        dependencies: Vec::new(),
        kind: ProviderKind::TypedExternalProjectTool,
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

fn temp_root(tag: &str) -> PathBuf {
    let suffix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock")
        .as_nanos();
    let root = std::env::temp_dir().join(format!("legion-bench-recall-{tag}-{suffix}"));
    fs::create_dir_all(&root).expect("temporary bench root");
    root
}

/// Copies a bench fixture directory (from the ported `tests/fixtures/bench/`
/// data) into a fresh temp repo root so the real provider scans real files.
fn stage_fixture(root: &Path, fixture_dir: &str) -> Vec<String> {
    let src = Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/bench"))
        .join(fixture_dir);
    let mut relative_paths = Vec::new();
    copy_tree(&src, root, &src, &mut relative_paths);
    relative_paths
}

fn copy_tree(dir: &Path, dest_root: &Path, src_root: &Path, out: &mut Vec<String>) {
    for entry in fs::read_dir(dir).unwrap_or_else(|e| panic!("read fixture dir {dir:?}: {e}")) {
        let entry = entry.expect("dir entry");
        let path = entry.path();
        if path.is_dir() {
            copy_tree(&path, dest_root, src_root, out);
            continue;
        }
        let relative = path.strip_prefix(src_root).expect("fixture-relative path");
        let dest = dest_root.join(relative);
        if let Some(parent) = dest.parent() {
            fs::create_dir_all(parent).expect("fixture parent dir");
        }
        fs::copy(&path, &dest).unwrap_or_else(|e| panic!("copy fixture file {path:?}: {e}"));
        out.push(relative.to_string_lossy().replace('\\', "/"));
    }
}

fn inventory(paths: &[String]) -> InventoryEnvelope {
    InventoryEnvelope::new(
        "bench-recall-fixture",
        "bench-recall-generation",
        paths
            .iter()
            .map(|path| InventoryEntry {
                path: path.clone(),
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

/// The real production external-tool route: `EffectExecutor` over the real
/// platform process backend, exactly as `legion` bin's
/// `native_audit_external_tool` wires it for `/audit`. No reimplemented
/// detector logic — findings come only from the real subprocess + parser.
fn real_external_tool(
    root: &Path,
) -> std::sync::Arc<dyn legion_provider_sdk::ExternalProjectTool> {
    let policy = legion_effects::StaticPolicy {
        decision: legion_effects::PolicyDecision {
            allowed: true,
            policy_id: "bench-recall-external-tools-v1".into(),
            policy_version: 1,
            policy_digest: "sha256:bench-recall-external-tools-v1".into(),
            reason: None,
        },
    };
    #[cfg(windows)]
    let process = legion_effects::platform::windows::WindowsProcess;
    #[cfg(unix)]
    let process = legion_effects::platform::unix::UnixProcess::new();
    let effects = legion_effects::EffectExecutor::new(
        process,
        legion_effects::ArtifactWriter::new(root),
        policy,
    );
    std::sync::Arc::new(
        legion_audit::native_providers::legacy_checks::AuditExternalProjectTool::new(effects),
    )
}

fn selector_for(provider_id: &str) -> Value {
    match provider_id {
        "legacy.security.secrets" => json!({"op": "always"}),
        "legacy.security.node-dependencies" => {
            json!({"op": "anyPath", "patterns": ["**/package.json"]})
        }
        "legacy.quality.dead-code" => json!({"op": "anyPath", "patterns": ["**/package.json"]}),
        "legacy.quality.duplication" => json!({"op": "sourceFilesAtLeast", "count": 1}),
        "legacy.quality.types" => json!({"op": "anyExtension", "extensions": ["ts", "tsx", "py"]}),
        other => panic!("no selector mapping for provider {other}"),
    }
}

struct BenchEntry {
    id: String,
    class: String,
    planted: bool,
    file: String,
}

fn manifest_entries() -> Vec<BenchEntry> {
    let parsed: Value = serde_json::from_str(MANIFEST).expect("bench manifest JSON");
    parsed["entries"]
        .as_array()
        .expect("entries array")
        .iter()
        .map(|entry| BenchEntry {
            id: entry["id"].as_str().unwrap().to_string(),
            class: entry["class"].as_str().unwrap().to_string(),
            planted: entry["planted"].as_bool().unwrap(),
            file: entry["file"].as_str().unwrap().to_string(),
        })
        .collect()
}

/// `bench/manifest.json` stores fixture paths as `fixtures/NNN-name/...`;
/// the ported copy under `tests/fixtures/bench/` drops the `fixtures/`
/// prefix, so the fixture directory is the first path segment after it.
fn fixture_dir_of(entry_file: &str) -> String {
    let trimmed = entry_file.strip_prefix("fixtures/").unwrap_or(entry_file);
    trimmed.split('/').next().unwrap().to_string()
}

enum ClassOutcome {
    Uncovered,
    ToolMissing(String),
    Recall { positive_hit: bool, negative_clean: bool },
}

fn run_class(class: &str) -> ClassOutcome {
    let Some(provider_id) = provider_for_class(class) else {
        return ClassOutcome::Uncovered;
    };
    let entries = manifest_entries();
    let positive = entries
        .iter()
        .find(|e| e.class == class && e.planted)
        .unwrap_or_else(|| panic!("bench manifest missing positive entry for class {class}"));
    let negative = entries
        .iter()
        .find(|e| e.class == class && !e.planted)
        .unwrap_or_else(|| panic!("bench manifest missing negative entry for class {class}"));

    let selector = selector_for(provider_id);
    let mut tool_missing_reason = None;
    let mut positive_hit = false;
    let mut negative_clean = false;

    for (entry, want_hit) in [(positive, true), (negative, false)] {
        let root = temp_root(&entry.id);
        let paths = stage_fixture(&root, &fixture_dir_of(&entry.file));
        let inv = inventory(&paths);
        let registry = NativeProviderRegistry::new(&root)
            .with_external_project_tool(real_external_tool(&root));
        let result = registry
            .execute(&provider(provider_id, selector.clone()), &inv)
            .expect("typed provider result (never a raw panic)");

        let missing = result
            .coverage_gaps
            .iter()
            .any(|gap| gap.contains("external-project-tool-capability-unavailable"))
            || result
                .details
                .get("executionReceipt")
                .and_then(|r| r.get("executable"))
                .and_then(|e| e.get("version"))
                .and_then(|v| v.get("qualified"))
                .and_then(Value::as_bool)
                == Some(false);

        if missing {
            tool_missing_reason = Some(format!(
                "provider {provider_id} could not run: {:?}",
                result.coverage_gaps
            ));
            let _ = fs::remove_dir_all(&root);
            continue;
        }

        let hit = !result.findings.is_empty();
        if want_hit {
            positive_hit = hit;
        } else {
            negative_clean = !hit;
        }
        let _ = fs::remove_dir_all(&root);
    }

    if let Some(reason) = tool_missing_reason {
        return ClassOutcome::ToolMissing(reason);
    }
    ClassOutcome::Recall {
        positive_hit,
        negative_clean,
    }
}

macro_rules! bench_class_test {
    ($name:ident, $class:literal) => {
        #[test]
        fn $name() {
            match run_class($class) {
                ClassOutcome::Uncovered => {
                    panic!(
                        "UNCOVERED CLASS: '{}' has no native Rust provider yet; \
                         the bench recall gate cannot claim coverage for it.",
                        $class
                    );
                }
                ClassOutcome::ToolMissing(reason) => {
                    panic!(
                        "class '{}' provider is wired but its external tool is unavailable \
                         in this environment: {reason}. This is a missing-provider gap, not a \
                         recall failure; the fix is providing/vendoring the tool, not the test.",
                        $class
                    );
                }
                ClassOutcome::Recall {
                    positive_hit,
                    negative_clean,
                } => {
                    assert!(
                        positive_hit,
                        "class '{}': planted positive fixture was NOT detected (recall failure)",
                        $class
                    );
                    assert!(
                        negative_clean,
                        "class '{}': negative-control fixture produced a finding (false positive)",
                        $class
                    );
                }
            }
        }
    };
}

bench_class_test!(bench_recall_secret, "secret");
bench_class_test!(bench_recall_dependency_cve, "dependency_cve");
bench_class_test!(bench_recall_dead_code, "dead_code");
bench_class_test!(bench_recall_duplication, "duplication");
bench_class_test!(bench_recall_type_error, "type_error");
bench_class_test!(bench_recall_drift, "drift");

/// Emits a qualification receipt shaped like the bench's
/// `references/audit-provider-benchmarks.schema.json` so the recall gate's
/// result is machine-readable evidence, not just terminal text.
#[test]
fn bench_recall_qualification_receipt() {
    let classes = ["secret", "dependency_cve", "dead_code", "duplication", "type_error", "drift"];
    let mut results = Vec::new();
    for class in classes {
        let outcome = run_class(class);
        let (status, detail) = match outcome {
            ClassOutcome::Uncovered => ("uncovered", "no native provider mapped".to_string()),
            ClassOutcome::ToolMissing(reason) => ("tool-missing", reason),
            ClassOutcome::Recall {
                positive_hit,
                negative_clean,
            } => (
                if positive_hit && negative_clean {
                    "pass"
                } else {
                    "recall-failure"
                },
                format!("positive_hit={positive_hit} negative_clean={negative_clean}"),
            ),
        };
        results.push(json!({"class": class, "status": status, "detail": detail}));
    }
    let receipt = json!({
        "schemaVersion": 1,
        "bench": "AU20-planted-findings",
        "gate": "legion-audit::bench_recall",
        "results": results,
    });
    let out_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("target").join("bench-receipts");
    let _ = fs::create_dir_all(&out_dir);
    let _ = fs::write(
        out_dir.join("bench_recall_receipt.json"),
        serde_json::to_string_pretty(&receipt).unwrap(),
    );
}
