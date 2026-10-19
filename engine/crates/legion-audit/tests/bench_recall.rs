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
    fs,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use legion_audit::{
    AuditPlan, AuditProvider, FrozenPlan, InventoryEntry, InventoryEnvelope,
    NativeProviderRegistry, ProviderExecutor,
};
use legion_contracts::{ProviderResult, ProviderSpec, ProviderStatus};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
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

/// Read the shipped definition verbatim, including its selector, execution
/// bounds, role and denominator. Qualification metadata is retained as input,
/// never treated as evidence that this run passed.
fn shipped_spec(id: &str) -> ProviderSpec {
    let registry: Value =
        serde_json::from_str(include_str!("../../../../src/registry/providers.json"))
            .expect("packaged provider registry");
    let definition = registry["providers"]
        .as_array()
        .expect("packaged providers")
        .iter()
        .find(|item| item["id"].as_str() == Some(id))
        .unwrap_or_else(|| panic!("missing shipped provider {id}"));
    serde_json::from_value(definition.clone()).expect("shipped ProviderSpec")
}

fn bench_plan(inventory: &InventoryEnvelope, spec: &ProviderSpec) -> FrozenPlan {
    AuditPlan::compile(inventory, std::slice::from_ref(spec))
        .expect("shipped provider plan compiles")
        .freeze(Some(b"bench-recall-key"))
        .expect("bench plan freezes")
}

fn digest(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

/// Exclude benchmark metadata from the implementation binding: changing a
/// prior qualification cannot manufacture a new measurement or form a cycle.
fn implementation_binding(spec: &ProviderSpec) -> Value {
    let mut definition = serde_json::to_value(spec).expect("serialize shipped spec");
    definition.as_object_mut().unwrap().remove("benchmark");
    json!({
        "providerDefinition": definition,
        "providerDefinitionDigest": legion_contracts::canonical_digest(&definition).unwrap(),
        "sourceBindings": source_bindings(),
        "sourceBindingsDigest": legion_contracts::canonical_digest(source_bindings()).unwrap()
    })
}

/// Bind the entire in-workspace production crate closure, registry resources,
/// dependency lock and this harness. Benchmark metadata is sanitized wherever
/// provider definitions are bound, preventing qualification circularity.
fn source_bindings() -> &'static Value {
    static BINDINGS: std::sync::OnceLock<Value> = std::sync::OnceLock::new();
    BINDINGS.get_or_init(|| {
        fn collect(root: &Path, path: &Path, bindings: &mut std::collections::BTreeMap<String, String>) {
            if path.is_dir() {
                for entry in fs::read_dir(path).expect("implementation source directory") {
                    collect(root, &entry.expect("implementation source entry").path(), bindings);
                }
            } else if path.is_file() {
                let relative = path.strip_prefix(root).expect("workspace-relative source")
                    .to_string_lossy().replace('\\', "/");
                let bytes = fs::read(path).expect("implementation source bytes");
                let bound_digest = if relative == "src/registry/providers.json" {
                    let mut registry: Value = serde_json::from_slice(&bytes).expect("provider registry");
                    for provider in registry["providers"].as_array_mut().expect("provider list") {
                        provider.as_object_mut().expect("provider definition").remove("benchmark");
                    }
                    legion_contracts::canonical_digest(&registry).expect("sanitized provider registry digest")
                } else { digest(&bytes) };
                bindings.insert(relative, bound_digest);
            }
        }
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..");
        let mut bindings = std::collections::BTreeMap::new();
        for entry in fs::read_dir(root.join("engine/crates")).expect("workspace production crates") {
            let crate_root = entry.expect("workspace crate").path();
            if crate_root.is_dir() {
                collect(&root, &crate_root.join("src"), &mut bindings);
                collect(&root, &crate_root.join("Cargo.toml"), &mut bindings);
            }
        }
        for path in ["engine/Cargo.toml", "engine/Cargo.lock", "src/registry",
            "engine/crates/legion-audit/tests/bench_recall.rs"] {
            collect(&root, &root.join(path), &mut bindings);
        }
        json!({"kind":"workspace-production-source-closure", "files":bindings,
            "sanitized": {"src/registry/providers.json":"remove providers[*].benchmark before canonical digest"}})
    })
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
/// Pass-through observer: retain the exact file-backed report before the
/// production provider removes its report directory. Execution and parsing
/// still belong to the real adapter and EffectExecutor.
struct RecordingTool {
    inner: std::sync::Arc<dyn legion_provider_sdk::ExternalProjectTool>,
    report: std::sync::Arc<std::sync::Mutex<Option<Vec<u8>>>>,
}

#[async_trait::async_trait]
impl legion_provider_sdk::ExternalProjectTool for RecordingTool {
    async fn execute(
        &self,
        request: legion_provider_sdk::ExternalToolRequest,
        cancellation: CancellationToken,
    ) -> legion_provider_sdk::ExecutionReceipt {
        let report_dir = request
            .args
            .windows(2)
            .find(|args| args[0] == "--output")
            .map(|args| PathBuf::from(&args[1]));
        let receipt = self.inner.execute(request, cancellation).await;
        if let Some(dir) = report_dir {
            let report = ["jscpd-report.json", "_jscpd/jscpd-report.json"]
                .iter()
                .find_map(|name| fs::read(dir.join(name)).ok())
                .filter(|bytes| bytes.len() <= 8 * 1024 * 1024);
            *self.report.lock().expect("bench report recorder") = report;
        }
        receipt
    }
}

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
    NotQualified(String),
    Recall {
        positive_hit: bool,
        negative_clean: bool,
    },
}

struct ClassRun {
    outcome: ClassOutcome,
    cases: Vec<Value>,
}

/// A positive must identify the planted subject, not merely emit something.
/// These are source-bound expectations, not the stale manifest line hints.
/// Aggregate count findings with fallback anchors cannot satisfy this contract.
fn expected_detection(class: &str) -> Value {
    match class {
        "secret" => json!({"rule": "aws-access-token", "path": "app.js", "lines": [7, 8]}),
        "dependency_cve" => {
            json!({"rule": "legacy.deps_cve.audit", "path": "package.json", "lines": [6, 7]})
        }
        "dead_code" => {
            json!({"rule": "legacy.dead_code.knip", "path": "legacy-discount.js", "lines": [1, 7]})
        }
        "duplication" => {
            json!({"rule": "legacy.duplication.jscpd", "path": "app.js", "lines": [3, 58]})
        }
        "type_error" => json!({"rule": "legacy.types.tsc", "path": "app.ts", "lines": [4, 4]}),
        _ => panic!("no expected detection for {class}"),
    }
}

fn matches_detection(row: &Value, expected: &Value, root: &Path) -> bool {
    let rule = row
        .get("ruleId")
        .or_else(|| row.get("rule"))
        .and_then(Value::as_str);
    let file = row
        .get("path")
        .or_else(|| row.get("file"))
        .and_then(Value::as_str);
    let line = row.get("line").and_then(Value::as_u64);
    let (Some(file), Some(line)) = (file, line) else {
        return false;
    };
    let path = Path::new(file);
    let relative = if path.is_absolute() {
        path.strip_prefix(root).ok().and_then(Path::to_str)
    } else {
        Some(file.strip_prefix("./").unwrap_or(file))
    };
    // Production summary findings explicitly say only that a tool reported N
    // findings. Their path/line is a fallback, not a reported defect location.
    let aggregate = row
        .get("message")
        .and_then(Value::as_str)
        .is_some_and(|message| message.contains(" reported ") && message.ends_with(" finding(s)"));
    !aggregate
        && rule == expected["rule"].as_str()
        && relative == expected["path"].as_str()
        && line >= expected["lines"][0].as_u64().unwrap()
        && line <= expected["lines"][1].as_u64().unwrap()
}

/// Classifier controls below exercise this function with synthetic inputs;
/// only run_class can produce execution evidence or a measured case record.
fn classify_case(
    result: &ProviderResult,
    provider: &AuditProvider,
    expected: &Value,
    planted: bool,
    root: &Path,
    artifacts: &Value,
) -> Result<bool, String> {
    if result.provider.as_str() != provider.id
        || !result.applicable
        || !matches!(result.status, ProviderStatus::Ok | ProviderStatus::Complete)
        || !result.complete
        || !result.coverage_gaps.is_empty()
        || !result.degradation.is_empty()
    {
        return Err(
            "provider result is not applicable, successful, complete and undegraded".into(),
        );
    }
    let coverage = result
        .coverage
        .as_ref()
        .ok_or("missing explicit coverage")?;
    if coverage.expected == 0
        || coverage.examined != coverage.expected
        || !coverage.gaps.is_empty()
        || provider
            .configuration
            .get("denominatorCount")
            .and_then(Value::as_u64)
            != Some(coverage.expected)
        || provider
            .configuration
            .get("denominatorDigest")
            .and_then(Value::as_str)
            != Some(coverage.denominator_digest.as_str())
    {
        return Err("coverage does not exactly reconcile to the frozen denominator".into());
    }
    let receipt = result
        .details
        .get("executionReceipt")
        .ok_or("missing execution receipt")?;
    if receipt["complete"] != true
        || receipt["state"] != "completed"
        || receipt
            .pointer("/executable/version/qualified")
            .and_then(Value::as_bool)
            != Some(true)
        || receipt
            .pointer("/processTree/started")
            .and_then(Value::as_bool)
            != Some(true)
        || receipt
            .pointer("/processTree/reaped")
            .and_then(Value::as_bool)
            != Some(true)
        || !receipt
            .get("gaps")
            .and_then(Value::as_array)
            .is_some_and(Vec::is_empty)
    {
        return Err("tool execution receipt is not qualified and complete".into());
    }
    let candidates = result
        .details
        .get("candidates")
        .and_then(Value::as_array)
        .ok_or("missing explicit candidate list")?;
    let emitted = result.findings.len() + candidates.len();
    if !planted {
        let reported_count = result
            .details
            .get("findingsCount")
            .and_then(Value::as_u64)
            .unwrap_or(0);
        return Ok(emitted == 0 && reported_count == 0);
    }
    let candidate_match = candidates
        .iter()
        .any(|row| matches_detection(row, expected, root));
    let finding_match = result.findings.iter().any(|finding| {
        result
            .details
            .get("findingEvidence")
            .and_then(|rows| rows.get(finding.id.as_str()))
            .is_some_and(|row| matches_detection(row, expected, root))
    });
    // Summary rules prove the provider parsed a detection, while the retained
    // tool report identifies the planted subject at case precision. Never use
    // the summary's fallback path/line as a reported defect locus.
    let expected_rule = expected["rule"].as_str();
    let rule_match = candidates
        .iter()
        .any(|row| row.get("ruleId").and_then(Value::as_str) == expected_rule)
        || result.findings.iter().any(|finding| {
            result
                .details
                .get("findingEvidence")
                .and_then(|rows| rows.get(finding.id.as_str()))
                .and_then(|row| row.get("ruleId"))
                .and_then(Value::as_str)
                == expected_rule
        });
    Ok(candidate_match
        || finding_match
        || (rule_match && raw_case_match(expected, artifacts, root)))
}

fn artifact_bytes(artifacts: &Value, name: &str) -> Option<Vec<u8>> {
    let artifact = &artifacts[name];
    if artifact["state"] != "retained" {
        return None;
    }
    hex::decode(artifact["bytesHex"].as_str()?).ok()
}

fn fixture_path_matches(path: &str, expected: &str, root: &Path) -> bool {
    let path = Path::new(path);
    let relative = if path.is_absolute() {
        path.strip_prefix(root).ok()
    } else {
        Some(path.strip_prefix(".").unwrap_or(path))
    };
    relative == Some(Path::new(expected))
}

/// Known-answer matching, not a second detector: only inspect the real tool's
/// reported advisory/unused-file/clone/diagnostic for the isolated fixture.
fn raw_case_match(expected: &Value, artifacts: &Value, root: &Path) -> bool {
    let rule = expected["rule"].as_str().unwrap();
    if rule == "legacy.types.tsc" {
        return ["stdout", "stderr"]
            .iter()
            .filter_map(|name| artifact_bytes(artifacts, name))
            .any(|bytes| {
                String::from_utf8_lossy(&bytes).lines().any(|line| {
                    line.split_once("(4,").is_some_and(|(path, diagnostic)| {
                        fixture_path_matches(path.trim(), "app.ts", root)
                            && diagnostic.contains("error TS2322:")
                    })
                })
            });
    }
    let stream = if rule == "legacy.duplication.jscpd" {
        "report"
    } else {
        "stdout"
    };
    let Some(bytes) = artifact_bytes(artifacts, stream) else {
        return false;
    };
    let Ok(report) = serde_json::from_slice::<Value>(&bytes) else {
        return false;
    };
    match rule {
        "legacy.deps_cve.audit" => ["lodash", "minimist"].iter().any(|name| {
            report
                .get("vulnerabilities")
                .and_then(|rows| rows.get(*name))
                .is_some_and(|row| {
                    row["name"].as_str() == Some(*name)
                        && row
                            .get("via")
                            .and_then(Value::as_array)
                            .is_some_and(|via| !via.is_empty())
                })
        }),
        "legacy.dead_code.knip" => {
            report
                .get("files")
                .and_then(Value::as_array)
                .is_some_and(|files| {
                    files
                        .iter()
                        .filter_map(Value::as_str)
                        .any(|file| fixture_path_matches(file, "legacy-discount.js", root))
                })
        }
        "legacy.duplication.jscpd" => report
            .get("duplicates")
            .and_then(Value::as_array)
            .is_some_and(|rows| {
                rows.iter().any(|row| {
                    ["firstFile", "secondFile"].iter().all(|side| {
                        row[*side]["name"]
                            .as_str()
                            .is_some_and(|file| fixture_path_matches(file, "app.js", root))
                            && row[*side]["start"].as_u64().is_some_and(|line| line > 0)
                            && row[*side]["end"].as_u64().is_some_and(|line| line > 0)
                    })
                })
            }),
        _ => false,
    }
}

/// Retain exact artifact bytes while the fixture-owned sink still exists.
/// A missing/deleted report remains an explicit evidence deficit, never
/// reconstructed from parser counts or a fabricated locator.
fn retained_artifacts(root: &Path, result: &ProviderResult, report: Option<&[u8]>) -> Value {
    let mut artifacts = serde_json::Map::new();
    for name in ["stdout", "stderr", "report"] {
        let reference = result
            .details
            .get("executionReceipt")
            .and_then(|r| r.get(name));
        let retained = reference.and_then(|r| {
            let path = r.get("path")?.as_str()?;
            let bytes = if name == "report" {
                report?.to_vec()
            } else {
                fs::read(root.join(path)).ok()?
            };
            if r["digest"].as_str() != Some(digest(&bytes).as_str())
                || r["bytes"].as_u64() != Some(bytes.len() as u64)
            {
                return None;
            }
            Some(json!({"reference": r, "state": "retained", "bytesHex": hex::encode(bytes)}))
        });
        artifacts.insert(
            name.into(),
            retained.unwrap_or_else(|| {
                json!({
                    "reference": reference, "state": "not-retained"
                })
            }),
        );
    }
    Value::Object(artifacts)
}

fn run_class(class: &str) -> ClassRun {
    if class == "drift" {
        return run_drift_class();
    }
    let Some(provider_id) = provider_for_class(class) else {
        return ClassRun {
            outcome: ClassOutcome::Uncovered,
            cases: Vec::new(),
        };
    };
    let spec = shipped_spec(provider_id);
    let expected = expected_detection(class);
    let mut cases = Vec::new();
    let mut reasons = Vec::new();
    let mut positive_hit = true;
    let mut negative_clean = true;
    let mut positive_count = 0;
    let mut negative_count = 0;
    // Include every manifest control, notably AU20-010, not just the first.
    for entry in manifest_entries()
        .iter()
        .filter(|entry| entry.class == class)
    {
        let root = temp_root(&entry.id);
        let mut paths = stage_fixture(&root, &fixture_dir_of(&entry.file));
        paths.sort();
        let fixtures: Vec<_> = paths.iter().map(|path| json!({
            "path": path, "digest": digest(&fs::read(root.join(path)).expect("fixture bytes"))
        })).collect();
        let inv = inventory(&paths);
        let report = std::sync::Arc::new(std::sync::Mutex::new(None));
        let tool = RecordingTool {
            inner: real_external_tool(&root),
            report: report.clone(),
        };
        let registry = NativeProviderRegistry::new(&root)
            .with_external_project_tool(std::sync::Arc::new(tool));
        let plan = bench_plan(&inv, &spec);
        let provider = &plan.plan().providers[0];
        let execution = tokio::runtime::Runtime::new()
            .expect("tokio runtime")
            .block_on(registry.execute_async(&plan, provider, &inv, CancellationToken::new()));
        let (result_value, artifacts, classification) = match execution {
            Ok(result) => {
                let report = report.lock().expect("bench report recorder");
                let artifacts = retained_artifacts(&root, &result, report.as_deref());
                let classification = classify_case(
                    &result,
                    provider,
                    &expected,
                    entry.planted,
                    &root,
                    &artifacts,
                );
                (
                    serde_json::to_value(&result).expect("result JSON"),
                    artifacts,
                    classification,
                )
            }
            Err(error) => (
                Value::Null,
                Value::Null,
                Err(format!("provider execution error: {error}")),
            ),
        };
        if let Err(reason) = &classification {
            reasons.push(format!("{}: {reason}", entry.id));
        }
        if entry.planted {
            positive_count += 1;
            positive_hit &= classification == Ok(true);
        } else {
            negative_count += 1;
            negative_clean &= classification == Ok(true);
        }
        cases.push(json!({
            "caseId": entry.id, "planted": entry.planted, "fixture": entry.file,
            "manifestDigest": digest(MANIFEST.as_bytes()), "fixtureFiles": fixtures,
            "fixtureFilesDigest": legion_contracts::canonical_digest(&fixtures).unwrap(),
            "implementationBinding": implementation_binding(&spec),
            "shippedProviderSpec": spec, "frozenPlan": plan.plan(),
            "expectedDetection": expected, "providerResult": result_value,
            "locatorPrecision": if class == "secret" { "reported-locus" } else { "isolated-fixture-case" },
            "retainedArtifacts": artifacts,
            "classification": match classification {
                Ok(passed) => json!({"eligible":true,"passed":passed}),
                Err(reason) => json!({"eligible":false,"passed":false,"reason":reason})
            }
        }));
        fs::remove_dir_all(&root).expect("remove staged fixture");
    }
    if positive_count == 0 || negative_count == 0 {
        reasons.push("class requires both planted and negative-control fixtures".into());
    }
    ClassRun {
        outcome: if reasons.is_empty() {
            ClassOutcome::Recall {
                positive_hit,
                negative_clean,
            }
        } else {
            ClassOutcome::NotQualified(reasons.join("; "))
        },
        cases,
    }
}

/// The historical AU20 comparator is deliberately limited to one claim
/// shape. It is benchmark evidence only; production doc-drift remains the
/// reasoning provider `reasoning.doc-drift`.
fn run_drift_class() -> ClassRun {
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
    let mut cases = Vec::new();
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
        let doc_claim =
            first_retry_claim(&doc).expect("drift fixture must contain supported claim");
        let code_value =
            first_max_retries(&code).expect("drift fixture must contain supported assignment");
        let hit = scan_retry_claim_drift(&doc, &code).is_some();
        cases.push(json!({"caseId":entry.id,"planted":entry.planted,
            "kind":"bench-local-retry-comparator-case", "productionQualification":false,
            "codePath":entry.file,"codeDigest":digest(code.as_bytes()),
            "docPath":doc_file,"docDigest":digest(doc.as_bytes()),
            "manifestDigest":digest(MANIFEST.as_bytes()),
            "comparatorSourceDigest":digest(include_bytes!("bench_recall.rs")),
            "docClaim":doc_claim,"codeValue":code_value,"mismatch":hit}));
        if want_hit {
            positive_hit = hit;
        } else {
            negative_clean = !hit;
        }
        let _ = fs::remove_dir_all(&root);
    }
    ClassRun {
        outcome: ClassOutcome::Recall {
            positive_hit,
            negative_clean,
        },
        cases,
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
mod classifier_controls {
    use super::*;

    // Deliberately synthetic: these controls test rejection logic and never
    // enter a measured record or assert a provider/tool executed.
    fn synthetic_control() -> (AuditProvider, ProviderResult) {
        let inv = inventory(&["app.js".into()]);
        let plan = bench_plan(&inv, &shipped_spec("legacy.security.secrets"));
        let provider = plan.plan().providers[0].clone();
        let result = serde_json::from_value(json!({
            "schema_version":1,"provider":provider.id,"applicable":true,"required":false,
            "status":"complete","complete":true,
            "coverage":{
                "denominator_digest":provider.configuration["denominatorDigest"],
                "expected":provider.configuration["denominatorCount"],
                "examined":provider.configuration["denominatorCount"],"gaps":[]
            },
            "findings":[],"coverage_gaps":[],"degradation":[],
            "details":{
                "candidates":[{"rule":"aws-access-token","file":"app.js","line":7}],
                "executionReceipt":{"complete":true,"state":"completed","gaps":[],
                    "executable":{"version":{"qualified":true}},
                    "processTree":{"started":true,"reaped":true}}
            }
        }))
        .expect("synthetic classifier control");
        (provider, result)
    }

    fn classify(
        result: &ProviderResult,
        provider: &AuditProvider,
        planted: bool,
    ) -> Result<bool, String> {
        classify_case(
            result,
            provider,
            &expected_detection("secret"),
            planted,
            Path::new("/fixture"),
            &Value::Null,
        )
    }

    #[test]
    fn rejects_failed_partial_cancelled_inapplicable_and_incomplete_results() {
        let (provider, control) = synthetic_control();
        for status in [
            ProviderStatus::Failed,
            ProviderStatus::Partial,
            ProviderStatus::Cancelled,
        ] {
            let mut result = control.clone();
            result.status = status;
            assert!(classify(&result, &provider, true).is_err());
            assert!(classify(&result, &provider, false).is_err());
        }
        for field in ["applicable", "complete"] {
            let mut value = serde_json::to_value(&control).unwrap();
            value[field] = json!(false);
            let result = serde_json::from_value(value).unwrap();
            assert!(classify(&result, &provider, false).is_err());
        }
    }

    #[test]
    fn rejects_missing_empty_mismatched_and_gapped_coverage() {
        let (provider, control) = synthetic_control();
        for coverage in [
            Value::Null,
            json!({"denominator_digest":"wrong","expected":1,"examined":1,"gaps":[]}),
            json!({"denominator_digest":provider.configuration["denominatorDigest"],"expected":0,"examined":0,"gaps":[]}),
            json!({"denominator_digest":provider.configuration["denominatorDigest"],"expected":1,"examined":0,"gaps":[]}),
            json!({"denominator_digest":provider.configuration["denominatorDigest"],"expected":1,"examined":2,"gaps":[]}),
            json!({"denominator_digest":provider.configuration["denominatorDigest"],"expected":1,"examined":1,"gaps":["partial"]}),
        ] {
            let mut value = serde_json::to_value(&control).unwrap();
            value["coverage"] = coverage;
            let result = serde_json::from_value(value).unwrap();
            assert!(classify(&result, &provider, false).is_err());
        }
        for field in ["coverage_gaps", "degradation"] {
            let mut value = serde_json::to_value(&control).unwrap();
            value[field] = json!(["unproven"]);
            assert!(classify(&serde_json::from_value(value).unwrap(), &provider, false).is_err());
        }
    }

    #[test]
    fn empty_emissions_only_pass_a_complete_negative_control() {
        let (provider, mut result) = synthetic_control();
        result.details.insert("candidates".into(), json!([]));
        assert_eq!(classify(&result, &provider, true), Ok(false));
        assert_eq!(classify(&result, &provider, false), Ok(true));
        result.details.insert("findingsCount".into(), json!(1));
        assert_eq!(classify(&result, &provider, false), Ok(false));
        result.status = ProviderStatus::Failed;
        assert!(classify(&result, &provider, false).is_err());
    }

    #[test]
    fn unrelated_or_aggregate_emissions_never_satisfy_planted_expectation() {
        let (provider, mut result) = synthetic_control();
        for row in [
            json!({"rule":"other-rule","file":"app.js","line":7}),
            json!({"rule":"aws-access-token","file":"other.js","line":7}),
            json!({"rule":"aws-access-token","file":"app.js","line":1}),
            json!({"rule":"aws-access-token","file":"app.js","line":7,"message":"secrets reported 1 finding(s)"}),
            json!({"rule":"aws-access-token","file":"../app.js","line":7}),
        ] {
            result.details.insert("candidates".into(), json!([row]));
            assert_eq!(classify(&result, &provider, true), Ok(false));
            assert_eq!(classify(&result, &provider, false), Ok(false));
        }
    }

    #[test]
    fn rejects_missing_unqualified_or_incomplete_execution_receipts() {
        let (provider, control) = synthetic_control();
        for pointer in [
            "/complete",
            "/executable/version/qualified",
            "/processTree/started",
            "/processTree/reaped",
        ] {
            let mut result = control.clone();
            *result
                .details
                .get_mut("executionReceipt")
                .unwrap()
                .pointer_mut(pointer)
                .unwrap() = json!(false);
            assert!(classify(&result, &provider, false).is_err());
        }
        let mut result = control;
        result.details.remove("executionReceipt");
        assert!(classify(&result, &provider, false).is_err());
    }

    #[test]
    fn raw_case_controls_require_expected_reported_subject() {
        fn artifacts(name: &str, bytes: &[u8]) -> Value {
            json!({(name):{"state":"retained","bytesHex":hex::encode(bytes)}})
        }
        let root = Path::new("/fixture");
        for (class, name, matching, unrelated) in [
            (
                "dependency_cve",
                "stdout",
                json!({"vulnerabilities":{"lodash":{"name":"lodash","via":[{"title":"advisory"}]}}}),
                json!({"vulnerabilities":{"other":{"name":"other","via":[{"title":"advisory"}]}}}),
            ),
            (
                "dead_code",
                "stdout",
                json!({"files":["legacy-discount.js"]}),
                json!({"files":["other.js"]}),
            ),
            (
                "duplication",
                "report",
                json!({"duplicates":[{"firstFile":{"name":"app.js","start":3,"end":29},"secondFile":{"name":"app.js","start":32,"end":58}}]}),
                json!({"duplicates":[{"firstFile":{"name":"other.js","start":3,"end":29},"secondFile":{"name":"other.js","start":32,"end":58}}]}),
            ),
        ] {
            let expected = expected_detection(class);
            assert!(raw_case_match(
                &expected,
                &artifacts(name, &serde_json::to_vec(&matching).unwrap()),
                root
            ));
            assert!(!raw_case_match(
                &expected,
                &artifacts(name, &serde_json::to_vec(&unrelated).unwrap()),
                root
            ));
            assert!(!raw_case_match(&expected, &Value::Null, root));
        }
        let expected = expected_detection("type_error");
        assert!(raw_case_match(
            &expected,
            &artifacts("stdout", b"app.ts(4,9): error TS2322: string to number"),
            root
        ));
        assert!(!raw_case_match(
            &expected,
            &artifacts("stdout", b"other.ts(4,9): error TS2322: string to number"),
            root
        ));
        assert!(!raw_case_match(
            &expected,
            &artifacts("stdout", b"app.ts(4,9): error TS9999: unrelated"),
            root
        ));
    }

    #[test]
    fn shipped_spec_binding_ignores_only_prior_benchmark_metadata() {
        let spec = shipped_spec("legacy.security.secrets");
        let binding = implementation_binding(&spec);
        let mut changed = spec.clone();
        changed.benchmark = json!({"status":"different-prior-qualification"});
        assert_eq!(binding, implementation_binding(&changed));
        changed.selector = json!({"op":"anyExtension","extensions":["ts"]});
        assert_ne!(binding, implementation_binding(&changed));
        assert!(binding["providerDefinition"].get("benchmark").is_none());
    }
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
            match run_class($class).outcome {
                ClassOutcome::Uncovered => panic!(
                    "class '{}' has no benchmark detector; the recall gate cannot claim coverage",
                    $class
                ),
                ClassOutcome::NotQualified(reason) => panic!(
                    "class '{}' provider result is not eligible for qualification: {reason}.",
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
    match run_class("drift").outcome {
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
        ClassOutcome::NotQualified(reason) => {
            panic!("local drift comparator unavailable: {reason}")
        }
    }
}

/// Emit a narrow known-answer execution record, not the broader precision/
/// recall qualification schema. No whole-provider or rule-pack qualification
/// is inferred from these fixture cases or the bench-local drift comparator.
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
        let run = run_class(class);
        let (status, detail) = match run.outcome {
            ClassOutcome::Uncovered => ("uncovered", "no native provider mapped".to_string()),
            ClassOutcome::NotQualified(reason) => ("not-qualified", reason),
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
        let mut projection = json!({"benchClass": class, "status": status, "detail": detail,
            "claimScope": if class == "drift" { "bench-local-comparator" } else { "known-answer-fixture-cases" },
            "productionQualification": false, "cases": run.cases});
        if class != "drift" {
            projection["projectionDigest"] =
                json!(legion_contracts::canonical_digest(&projection).unwrap());
        }
        results.push(projection);
    }
    let mut receipt = json!({
        "schemaVersion": 1,
        "kind": "audit-known-answer-execution-record",
        "family": "bench-known-answer",
        "claimScope": "known-answer-fixture-cases",
        "productionQualification": false,
        "bench": "AU20-planted-findings",
        "gate": "legion-audit::bench_recall",
        "measuredAtUnixMs": SystemTime::now().duration_since(UNIX_EPOCH).expect("system clock").as_millis(),
        "results": results,
    });
    receipt["qualificationDigest"] = json!(legion_contracts::canonical_digest(&receipt).unwrap());
    // One original JSON envelope in harness stdout, before any all-class
    // assertion. Consumers still require this entire test's terminal success.
    println!(
        "\nLEGION_BENCH_KNOWN_ANSWER_RECORD {}",
        serde_json::to_string(&receipt).unwrap()
    );
    let out_dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("target")
        .join("bench-receipts");
    fs::create_dir_all(&out_dir).expect("bench receipt directory");
    fs::write(
        out_dir.join("bench_recall_receipt.json"),
        serde_json::to_string_pretty(&receipt).unwrap(),
    )
    .expect("write complete bench execution record");
    // The receipt is a gate, not a log: every class must pass.
    let failing = results
        .iter()
        .filter(|row| row["status"] != "pass")
        .map(|row| format!("{} ({})", row["benchClass"], row["status"]))
        .collect::<Vec<_>>();
    assert!(
        failing.is_empty(),
        "bench classes without a passing result: {failing:?}"
    );
}
