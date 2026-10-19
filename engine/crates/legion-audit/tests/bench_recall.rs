//! Packet F — known-answer bench / recall gate.
//!
//! Runs the REAL native Audit providers (production dispatch through
//! `NativeProviderRegistry`, wired to the real `EffectExecutor` subprocess
//! route with an explicit in-process fixture authorizer) over
//! the AU20 planted-defect bench fixtures ported from `bench/manifest.json`.
//! For every bench class this asserts: the positive fixture is detected, and
//! the negative-control fixture produces zero findings. A class with no
//! benchmark detector mapping, or whose external tool is missing, FAILS the
//! test. Coverage is never faked and a skip is never silent.

use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use legion_audit::{
    native_providers::legacy_checks::spec, AuditPlan, AuditProvider, FrozenPlan, InventoryEntry,
    InventoryEnvelope, NativeProviderRegistry, ProviderExecutor, ProviderKind,
};
use serde_json::{json, Value};
use tokio_util::sync::CancellationToken;

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
        // Drift has no deterministic production provider. Its benchmark-only
        // comparator is handled directly from manifest doc_file/file pairs.
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

/// A frozen plan for one legacy-check provider. The external-tool route is
/// only taken by the plan-bound async executor (`execute_async`); the plain
/// synchronous `execute` path never launches a process, so a bench built on
/// it can only ever report tool-missing.
fn bench_plan(inventory: &InventoryEnvelope, provider_id: &str) -> FrozenPlan {
    let contract =
        spec(provider_id).unwrap_or_else(|| panic!("legacy provider {provider_id} must be frozen"));
    let definition = json!({
        "schemaVersion": 2,
        "id": provider_id,
        "providerVersion": "2.0.0",
        "family": "legacy",
        "role": contract.role,
        "phase": contract.phase,
        "lensIds": ["security"],
        "dependsOn": [],
        "consumes": ["repository-inventory"],
        "produces": ["provider-result"],
        "selector": {"op": "always"},
        "denominatorKind": "repository-inventory",
        "runner": {"kind": "legacy-check", "check": contract.check},
        "hostCapabilities": [],
        "execution": {},
        "reasoning": {},
        "benchmark": {"status": "unproven", "requiredForCleanClaim": false},
        "cleanClaim": "evidence-only",
        "controlIds": [],
        "scopes": [],
        "selectable": true
    });
    AuditPlan::compile(
        inventory,
        &[serde_json::from_value(definition).expect("bench provider definition")],
    )
    .expect("bench plan compiles")
    .freeze(Some(b"bench-recall-key"))
    .expect("bench plan freezes")
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
    let suffix = ((SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock")
        .as_nanos())
    .wrapping_shl(20)
        | ({
            static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
            u128::from(SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed))
        }));
    let root = std::env::temp_dir().join(format!("legion-bench-recall-{tag}-{suffix}"));
    fs::create_dir_all(&root).expect("temporary bench root");
    root
}

/// Copies a bench fixture directory (from the ported `tests/fixtures/bench/`
/// data) into a fresh temp repo root so the real provider scans real files.
fn stage_fixture(root: &Path, fixture_dir: &str) -> Vec<String> {
    let src =
        Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/bench")).join(fixture_dir);
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

/// Real `EffectExecutor` over the platform backend with SDK fixture admission.
/// Production CLI denies external tools until native owner admission exists.
/// This harness proves provider behavior, not deployment admission. No reimplemented
/// detector logic — findings come only from the real subprocess + parser.
fn real_external_tool(root: &Path) -> std::sync::Arc<dyn legion_provider_sdk::ExternalProjectTool> {
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
    doc_file: Option<String>,
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
            doc_file: entry["doc_file"].as_str().map(ToOwned::to_owned),
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
    Recall {
        positive_hit: bool,
        negative_clean: bool,
    },
}

fn run_class(class: &str) -> ClassOutcome {
    if class == "drift" {
        return run_drift_class();
    }
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
        let plan = bench_plan(&inv, provider_id);
        let result = tokio::runtime::Runtime::new()
            .expect("tokio runtime")
            .block_on(registry.execute_async(
                &plan,
                &provider(provider_id, selector.clone()),
                &inv,
                CancellationToken::new(),
            ))
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

        // Candidate-generator providers (e.g. secrets) report detections as
        // `candidates` pending adjudication, not as findings. A detection is
        // either; a negative control must produce neither.
        let candidates_hit = result
            .details
            .get("candidates")
            .and_then(Value::as_array)
            .is_some_and(|candidates| !candidates.is_empty());
        let hit = !result.findings.is_empty() || candidates_hit;
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

/// The historical AU20 comparator is deliberately limited to one claim
/// shape. It is benchmark evidence only; production doc-drift remains the
/// reasoning provider `reasoning.doc-drift`.
fn run_drift_class() -> ClassOutcome {
    let entries = manifest_entries();
    let positive = entries
        .iter()
        .find(|e| e.class == "drift" && e.planted)
        .unwrap_or_else(|| panic!("bench manifest missing positive drift entry"));
    let negative = entries
        .iter()
        .find(|e| e.class == "drift" && !e.planted)
        .unwrap_or_else(|| panic!("bench manifest missing negative drift entry"));

    let mut positive_hit = false;
    let mut negative_clean = false;
    for (entry, want_hit) in [(positive, true), (negative, false)] {
        let doc_file = entry
            .doc_file
            .as_deref()
            .unwrap_or_else(|| panic!("{} drift entry missing doc_file", entry.id));
        let fixture_dir = fixture_dir_of(&entry.file);
        let code_relative = fixture_relative_path(&entry.file, &fixture_dir);
        let doc_relative = fixture_relative_path(doc_file, &fixture_dir);
        let root = temp_root(&entry.id);
        stage_fixture(&root, &fixture_dir);
        let doc_path = root.join(doc_relative);
        let code_path = root.join(code_relative);
        let doc = fs::read_to_string(&doc_path)
            .unwrap_or_else(|e| panic!("read drift doc fixture {doc_path:?}: {e}"));
        let code = fs::read_to_string(&code_path)
            .unwrap_or_else(|e| panic!("read drift code fixture {code_path:?}: {e}"));
        let hit = scan_retry_claim_drift(&doc, &code).is_some();
        if want_hit {
            positive_hit = hit;
        } else {
            negative_clean = !hit;
        }
        let _ = fs::remove_dir_all(&root);
    }
    ClassOutcome::Recall {
        positive_hit,
        negative_clean,
    }
}

fn fixture_relative_path<'a>(path: &'a str, fixture_dir: &str) -> &'a str {
    let prefix = format!("fixtures/{fixture_dir}/");
    path.strip_prefix(&prefix).unwrap_or_else(|| {
        panic!("bench path {path:?} is outside declared fixture {fixture_dir:?}")
    })
}

/// Extracts the first supported `up to N times` claim and first
/// `MAX_RETRIES = N` assignment, matching the retired deterministic bench
/// comparator's intentionally narrow contract.
fn scan_retry_claim_drift(doc: &str, code: &str) -> Option<(f64, f64)> {
    let doc_claim = first_retry_claim(doc)?;
    let code_value = first_max_retries(code)?;
    (doc_claim != code_value).then_some((doc_claim, code_value))
}

fn first_retry_claim(source: &str) -> Option<f64> {
    let lower = source.to_ascii_lowercase();
    let mut search_from = 0;
    while let Some(offset) = lower[search_from..].find("up to ") {
        let start = search_from + offset + "up to ".len();
        let mut cursor = start;
        for _ in 0..2 {
            if source.as_bytes().get(cursor) == Some(&b'*') {
                cursor += 1;
            } else {
                break;
            }
        }
        let digits_start = cursor;
        while source
            .as_bytes()
            .get(cursor)
            .is_some_and(u8::is_ascii_digit)
        {
            cursor += 1;
        }
        if digits_start != cursor {
            let digits_end = cursor;
            for _ in 0..2 {
                if source.as_bytes().get(cursor) == Some(&b'*') {
                    cursor += 1;
                } else {
                    break;
                }
            }
            if lower[cursor..].starts_with(" times") {
                if let Ok(value) = source[digits_start..digits_end].parse() {
                    return Some(value);
                }
            }
        }
        search_from = start;
    }
    None
}

fn first_max_retries(source: &str) -> Option<f64> {
    let mut search_from = 0;
    while let Some(offset) = source[search_from..].find("MAX_RETRIES") {
        let start = search_from + offset;
        let mut cursor = start + "MAX_RETRIES".len();
        cursor = skip_js_whitespace(source, cursor);
        if source.as_bytes().get(cursor) == Some(&b'=') {
            cursor += 1;
            cursor = skip_js_whitespace(source, cursor);
            let digits_start = cursor;
            while source
                .as_bytes()
                .get(cursor)
                .is_some_and(u8::is_ascii_digit)
            {
                cursor += 1;
            }
            if digits_start != cursor {
                if let Ok(value) = source[digits_start..cursor].parse() {
                    return Some(value);
                }
            }
        }
        search_from = start + "MAX_RETRIES".len();
    }
    None
}

fn skip_js_whitespace(source: &str, mut cursor: usize) -> usize {
    while let Some(ch) = source[cursor..].chars().next() {
        if matches!(
            ch,
            '\u{0009}'..='\u{000d}'
                | '\u{0020}'
                | '\u{00a0}'
                | '\u{1680}'
                | '\u{2000}'..='\u{200a}'
                | '\u{2028}'..='\u{2029}'
                | '\u{202f}'
                | '\u{205f}'
                | '\u{3000}'
                | '\u{feff}'
        ) {
            cursor += ch.len_utf8();
        } else {
            break;
        }
    }
    cursor
}

#[cfg(test)]
mod drift_comparator_tests {
    use super::{fixture_relative_path, scan_retry_claim_drift};

    #[test]
    fn takes_first_supported_claim() {
        assert_eq!(
            scan_retry_claim_drift(
                "up to 3 times; later up to 9 times",
                "const MAX_RETRIES = 9;"
            ),
            Some((3.0, 9.0))
        );
    }

    #[test]
    fn accepts_zero_one_or_two_markdown_emphasis_stars() {
        for stars in ["", "*", "**"] {
            let doc = format!("up to {stars}3{stars} times");
            assert_eq!(
                scan_retry_claim_drift(&doc, "MAX_RETRIES = 4"),
                Some((3.0, 4.0)),
                "star count {stars:?}"
            );
        }
    }

    #[test]
    fn absent_claim_or_code_value_has_no_comparison() {
        assert_eq!(
            scan_retry_claim_drift("no retry count", "MAX_RETRIES = 4"),
            None
        );
        assert_eq!(
            scan_retry_claim_drift("up to 3 times", "no retry constant"),
            None
        );
    }

    #[test]
    fn equal_values_are_clean() {
        assert_eq!(
            scan_retry_claim_drift("up to **4** times", "MAX_RETRIES = 4"),
            None
        );
    }

    #[test]
    fn code_assignment_allows_whitespace_around_equals() {
        assert_eq!(
            scan_retry_claim_drift("up to 3 times", "MAX_RETRIES \n =\t 4"),
            Some((3.0, 4.0))
        );
    }

    #[test]
    fn code_assignment_matches_javascript_unicode_whitespace() {
        assert_eq!(
            scan_retry_claim_drift("up to 3 times", "MAX_RETRIES\u{00a0}=\u{feff}4"),
            Some((3.0, 4.0))
        );
    }

    #[test]
    fn code_assignment_rejects_nel_as_javascript_whitespace() {
        assert_eq!(
            scan_retry_claim_drift("up to 3 times", "MAX_RETRIES\u{0085}=4"),
            None
        );
    }

    #[test]
    fn oversized_first_number_still_wins_over_later_match() {
        let oversized = "9".repeat(400);
        let doc = format!("up to {oversized} times; later up to 3 times");
        assert!(scan_retry_claim_drift(&doc, "MAX_RETRIES = 3").is_some());
    }

    #[test]
    fn fixture_paths_strip_only_declared_directory_and_keep_nested_path() {
        assert_eq!(
            fixture_relative_path("fixtures/011-doc-drift/nested/README.md", "011-doc-drift"),
            "nested/README.md"
        );
    }

    #[test]
    #[should_panic(expected = "outside declared fixture")]
    fn fixture_paths_reject_a_different_directory() {
        fixture_relative_path("fixtures/012-other/README.md", "011-doc-drift");
    }
}

macro_rules! bench_class_test {
    ($name:ident, $class:literal) => {
        #[test]
        #[ignore = "needs gitleaks, node/npm, knip, jscpd, tsc; runs in the macOS CI bench job with --ignored"]
        fn $name() {
            match run_class($class) {
                ClassOutcome::Uncovered => panic!(
                    "class '{}' has no benchmark detector; the recall gate cannot claim coverage",
                    $class
                ),
                ClassOutcome::ToolMissing(reason) => panic!(
                    "class '{}' provider could not run because its external tool is \
                     unavailable: {reason}. Provision the tool in the environment running this gate.",
                    $class
                ),
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

#[test]
fn bench_recall_drift() {
    match run_class("drift") {
        ClassOutcome::Recall {
            positive_hit,
            negative_clean,
        } => {
            assert!(positive_hit, "AU20-011 doc/code mismatch was not detected");
            assert!(
                negative_clean,
                "AU20-012 matching doc/code pair was flagged"
            );
        }
        ClassOutcome::Uncovered => panic!("drift comparator was not bound"),
        ClassOutcome::ToolMissing(reason) => panic!("local drift comparator unavailable: {reason}"),
    }
}

/// Emits a qualification receipt shaped like the bench's
/// `references/audit-provider-benchmarks.schema.json` so the recall gate's
/// result is machine-readable evidence, not just terminal text.
#[test]
#[ignore = "needs gitleaks, node/npm, knip, jscpd, tsc; runs in the macOS CI bench job with --ignored"]
fn bench_recall_qualification_receipt() {
    let classes = [
        "secret",
        "dependency_cve",
        "dead_code",
        "duplication",
        "type_error",
        "drift",
    ];
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
                if class == "drift" {
                    format!(
                        "qualification=bench-local-comparator positive_hit={positive_hit} negative_clean={negative_clean}"
                    )
                } else {
                    format!("positive_hit={positive_hit} negative_clean={negative_clean}")
                },
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
    let out_dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("target")
        .join("bench-receipts");
    let _ = fs::create_dir_all(&out_dir);
    let _ = fs::write(
        out_dir.join("bench_recall_receipt.json"),
        serde_json::to_string_pretty(&receipt).unwrap(),
    );
    // The receipt is a gate, not a log: every class must pass.
    let failing = results
        .iter()
        .filter(|row| row["status"] != "pass")
        .map(|row| format!("{} ({})", row["class"], row["status"]))
        .collect::<Vec<_>>();
    assert!(
        failing.is_empty(),
        "bench classes without a passing result: {failing:?}"
    );
}
