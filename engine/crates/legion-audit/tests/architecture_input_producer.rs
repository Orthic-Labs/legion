//! The architecture-family providers self-source their input from the frozen
//! denominator when the host injects none, and keep host input authoritative.

use legion_audit::{
    execute, native_providers::availability::unavailable_reason, AuditPlan, AuditProvider,
    FilesystemInventorySource, FrozenPlan, InventoryEnvelope, InventorySource,
    NativeProviderRegistry, ProviderExecutor, ProviderKind,
};
use legion_contracts::{ProviderResult, ProviderSpec, ProviderStatus};
use serde_json::{json, Value};
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

#[path = "support/accuracy_receipt.rs"]
mod accuracy_receipt;

static SEQ: AtomicU64 = AtomicU64::new(0);

fn fixture_root(name: &str) -> PathBuf {
    let root = std::env::temp_dir().join(format!(
        "legion-arch-producer-{name}-{}-{}",
        std::process::id(),
        SEQ.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).unwrap();
    root
}

fn write(root: &Path, path: &str, body: &str) {
    let full = root.join(path);
    fs::create_dir_all(full.parent().unwrap()).unwrap();
    fs::write(full, body).unwrap();
}

fn provider(id: &str) -> AuditProvider {
    AuditProvider {
        id: id.into(),
        version: "2.0.0".into(),
        role: "diagnose".into(),
        phase: "static".into(),
        lens_ids: Vec::new(),
        dependencies: Vec::new(),
        kind: ProviderKind::RustAlgorithm,
        configuration: BTreeMap::from([("selector".into(), json!({"op":"always"}))]),
        bounds: BTreeMap::new(),
        clean_claim: "evidence-only".into(),
        benchmark_status: "unproven".into(),
        benchmark_required_for_clean_claim: false,
        qualification_digest: None,
        required: false,
    }
}

fn inventory(root: &Path) -> InventoryEnvelope {
    FilesystemInventorySource::new(root)
        .unwrap()
        .inventory("architecture-producer-fixture")
        .unwrap()
}

fn run(root: &Path, id: &str) -> ProviderResult {
    NativeProviderRegistry::new(root)
        .execute(&provider(id), &inventory(root))
        .unwrap()
}

/// (finding id, first located path) for every finding.
fn located(result: &ProviderResult) -> Vec<(String, String)> {
    let locations = result
        .details
        .get("findingLocations")
        .cloned()
        .unwrap_or(Value::Null);
    result
        .findings
        .iter()
        .map(|finding| {
            let id = finding.id.as_str().to_owned();
            let path = locations
                .get(&id)
                .and_then(|paths| paths.get(0))
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_owned();
            (id, path)
        })
        .collect()
}

/// Accuracy qualification uses shipped specifications, never `provider()`'s
/// synthetic configuration or injected analyzer observations.
fn architecture_accuracy_case(
    provider_id: &str,
    case_id: &str,
    files: &[(&str, &str)],
    expected: &[&str],
) -> accuracy_receipt::CaseObservation {
    let root = fixture_root(case_id);
    for (path, body) in files {
        write(&root, path, body);
    }
    let raw = fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../src/registry/providers.json"
    ))
    .unwrap();
    let registry: Value = serde_json::from_str(&raw).unwrap();
    let spec: ProviderSpec = serde_json::from_value(
        registry["providers"]
            .as_array()
            .unwrap()
            .iter()
            .find(|entry| entry["id"] == provider_id)
            .unwrap_or_else(|| panic!("missing shipped specification: {provider_id}"))
            .clone(),
    )
    .unwrap();
    let inventory = inventory(&root);
    let mut expected_paths: Vec<&str> = files.iter().map(|(path, _)| *path).collect();
    expected_paths.sort_unstable();
    let mut inventoried_paths: Vec<&str> = inventory
        .entries
        .iter()
        .map(|entry| entry.path.as_str())
        .collect();
    inventoried_paths.sort_unstable();
    assert_eq!(inventoried_paths, expected_paths, "{case_id}");
    let denominator = inventory.denominator_entries(&spec.selector).unwrap();
    assert_eq!(denominator.entries.len(), files.len(), "{case_id}");
    let plan = AuditPlan::compile_with_root(Some(&root), &inventory, &[spec])
        .unwrap()
        .freeze(Some(b"architecture-accuracy-fixture-key"))
        .unwrap();
    assert_eq!(plan.providers().len(), 1, "{case_id}");
    let planned = plan.provider(provider_id).unwrap();
    assert_eq!(planned.kind, ProviderKind::RustAlgorithm, "{case_id}");
    assert!(!planned.configuration.contains_key("input"), "{case_id}");
    assert_eq!(
        planned.configuration["denominatorCount"],
        json!(files.len()),
        "{case_id}"
    );
    assert_eq!(
        planned.configuration["denominatorDigest"],
        json!(denominator.digest),
        "{case_id}"
    );
    let execution = execute(&plan, &inventory, &NativeProviderRegistry::new(&root)).unwrap();
    assert_eq!(execution.plan_digest, plan.digest(), "{case_id}");
    assert_eq!(execution.inventory_digest, inventory.digest, "{case_id}");
    assert_eq!(execution.results.len(), 1, "{case_id}");
    assert!(execution.pending_host.is_empty(), "{case_id}");
    let entry = &execution.results[0];
    assert_eq!(entry.provider, provider_id, "{case_id}");
    assert!(!entry.skipped, "{case_id}");
    let result = &entry.result;
    result.validate().unwrap();
    assert!(result.applicable, "{case_id}");
    assert!(unavailable_reason(result).is_none(), "{case_id}");
    assert!(result.coverage_gaps.is_empty(), "{case_id}: {result:?}");
    assert!(result.degradation.is_empty(), "{case_id}: {result:?}");
    let coverage = result.coverage.as_ref().unwrap();
    assert_eq!(coverage.denominator_digest, denominator.digest, "{case_id}");
    assert_eq!(coverage.expected, files.len() as u64, "{case_id}");
    assert_eq!(coverage.examined, coverage.expected, "{case_id}");
    assert!(coverage.gaps.is_empty(), "{case_id}");
    assert!(coverage.complete(), "{case_id}");
    let input = &result.details["nativeInput"];
    assert_eq!(input["producer"]["kind"], "self-sourced", "{case_id}");
    assert_eq!(
        input["producer"]["filesRead"],
        json!(files.len()),
        "{case_id}"
    );
    assert_eq!(
        result.details["nativeAnalysis"]["denominator"]["examined"],
        json!(files.len()),
        "{case_id}"
    );
    let mut actual = Vec::new();
    for finding in &result.findings {
        let id = finding.id.as_str();
        let locations = result.details["findingLocations"][id].as_array().unwrap();
        assert!(!locations.is_empty(), "{case_id}: unlocated finding {id}");
        for location in locations {
            actual.push(format!("{id}|{}", location.as_str().unwrap()));
        }
    }
    actual.sort();
    let mut expected: Vec<String> = expected.iter().map(|label| (*label).to_owned()).collect();
    expected.sort();
    assert_eq!(actual, expected, "{provider_id}: {case_id}");
    if expected.is_empty() {
        assert!(result.complete, "{case_id}");
        assert_eq!(result.status, ProviderStatus::Complete, "{case_id}");
    } else {
        assert_eq!(result.status, ProviderStatus::Partial, "{case_id}");
    }
    fs::remove_dir_all(root).unwrap();
    accuracy_receipt::CaseObservation {
        id: case_id.to_owned(),
        expected,
        actual,
    }
}

#[test]
fn file_only_provider_accuracy_architecture() {
    let tested = module("", "", true);
    let untested = module("", "", false);
    // Expected identifiers below are fixed fixture labels, not snapshots of
    // provider output. Every clean case has a nonempty applicable denominator.
    let cases = [
        (
            "architecture.core",
            architecture_accuracy_case(
                "architecture.core",
                "architecture-import-cycle",
                &[
                    ("package.json", "{\"name\":\"cycle\"}\n"),
                    (
                        "src/a.js",
                        "import { b } from './b.js';\nexport const a = b;\n",
                    ),
                    (
                        "src/b.js",
                        "import { a } from './a.js';\nexport const b = a;\n",
                    ),
                ],
                &["architecture.core:cycle:7a343a747091|src/a.js"],
            ),
            architecture_accuracy_case(
                "architecture.core",
                "architecture-acyclic-imports",
                &[
                    ("package.json", "{\"name\":\"acyclic\"}\n"),
                    (
                        "src/a.js",
                        "import { b } from './b.js';\nexport const a = b;\n",
                    ),
                    ("src/b.js", "export const b = 3;\n"),
                ],
                &[],
            ),
        ),
        (
            "docs.contract",
            architecture_accuracy_case(
                "docs.contract",
                "docs-missing-citation",
                &[
                    (
                        "README.md",
                        "# Usage\n\nSee `src/existing.rs` & `src/missing.rs`.\n",
                    ),
                    ("src/existing.rs", "pub const VALUE: u32 = 3;\n"),
                ],
                &["docs.contract:e73da6403495|README.md"],
            ),
            architecture_accuracy_case(
                "docs.contract",
                "docs-existing-citation",
                &[
                    ("README.md", "# Usage\n\nSee `src/current.rs`.\n"),
                    ("src/current.rs", "pub const VALUE: u32 = 3;\n"),
                ],
                &[],
            ),
        ),
        (
            "requirements.traceability",
            architecture_accuracy_case(
                "requirements.traceability",
                "requirements-missing-implementation",
                &[
                    (
                        "README.md",
                        "# Requirements\n\n- REQ-101 persist values\n- REQ-102 add values\n",
                    ),
                    ("src/value.rs", "// REQ-102\npub const VALUE: u32 = 3;\n"),
                    (
                        "tests/value_test.rs",
                        "// REQ-102\n#[test]\nfn value() { assert_eq!(1 + 2, 3); }\n",
                    ),
                ],
                &["requirements.traceability:REQ-101|README.md"],
            ),
            architecture_accuracy_case(
                "requirements.traceability",
                "requirements-source-test-trace",
                &[
                    ("README.md", "# Requirements\n\n- REQ-201 add values\n"),
                    ("src/value.rs", "// REQ-201\npub const VALUE: u32 = 3;\n"),
                    (
                        "tests/value_test.rs",
                        "// REQ-201\n#[test]\nfn value() { assert_eq!(1 + 2, 3); }\n",
                    ),
                ],
                &[],
            ),
        ),
        (
            "test-quality.core",
            architecture_accuracy_case(
                "test-quality.core",
                "test-quality-missing-test",
                &[
                    (
                        "Cargo.toml",
                        "[package]\nname = \"missing-test\"\nversion = \"0.1.0\"\n",
                    ),
                    ("src/tested.rs", &tested),
                    ("src/untested.rs", &untested),
                ],
                &["test-quality.core:missing:ad59ec1ddbcd|src/untested.rs"],
            ),
            architecture_accuracy_case(
                "test-quality.core",
                "test-quality-inline-test",
                &[
                    (
                        "Cargo.toml",
                        "[package]\nname = \"tested\"\nversion = \"0.1.0\"\n",
                    ),
                    ("src/good.rs", &tested),
                ],
                &[],
            ),
        ),
    ];
    for (provider_id, planted, clean) in cases {
        accuracy_receipt::emit(
            provider_id,
            "finding",
            &[planted, clean],
            &["engine/crates/legion-audit/tests/architecture_input_producer.rs"],
        );
    }
    // Compatibility & backend retain their evidence gaps. Frontend/data native
    // source verifiers below qualify outcomes separately from finding accuracy.
}

#[test]
fn file_only_provider_accuracy_framework_backend_keeps_unknown_auth() {
    let root = fixture_root("backend-observed-route-unknown-auth");
    write(
        &root,
        "package.json",
        "{\"name\":\"backend\",\"dependencies\":{\"express\":\"4.21.0\"}}\n",
    );
    write(
        &root,
        "src/server.js",
        "const express = require('express');\nconst app = express();\napp.get('/health', (req, res) => res.send('ok'));\n",
    );
    let registry: Value = serde_json::from_str(
        &fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../../src/registry/providers.json"
        ))
        .unwrap(),
    )
    .unwrap();
    let spec: ProviderSpec = serde_json::from_value(
        registry["providers"]
            .as_array()
            .unwrap()
            .iter()
            .find(|entry| entry["id"] == "framework.backend")
            .unwrap()
            .clone(),
    )
    .unwrap();
    let inventory = inventory(&root);
    let denominator = inventory.denominator_entries(&spec.selector).unwrap();
    let plan = AuditPlan::compile_with_root(Some(&root), &inventory, &[spec])
        .unwrap()
        .freeze(Some(b"architecture-accuracy-fixture-key"))
        .unwrap();
    let execution = execute(&plan, &inventory, &NativeProviderRegistry::new(&root)).unwrap();
    assert_eq!(execution.results.len(), 1);
    assert!(!execution.results[0].skipped);
    let result = &execution.results[0].result;
    assert!(result.applicable);
    assert!(!result.complete);
    assert!(unavailable_reason(result).is_none());
    assert!(result.findings.is_empty());
    assert_eq!(result.status, ProviderStatus::Partial);
    let route = &result.details["nativeInput"]["artifacts"]["backendFrameworks"][0]["routes"][0];
    assert_eq!(route["path"], "/health");
    assert_eq!(route["file"], "src/server.js");
    assert_eq!(route["auth"], "unknown");
    assert_eq!(
        result.coverage_gaps,
        [
            "route-evidence-gap",
            "route-auth-unknown",
            "runtime-evidence-trust-unavailable"
        ]
    );
    let coverage = result.coverage.as_ref().unwrap();
    assert_eq!(coverage.denominator_digest, denominator.digest);
    assert_eq!((coverage.expected, coverage.examined), (2, 2));
    assert_eq!(coverage.gaps, result.coverage_gaps);
    assert_eq!(
        result.details["nativeAnalysis"]["certificationClaim"],
        false
    );
    // This rejection is raw verifier evidence, never a finding-accuracy record.
    println!(
        "FRAMEWORK_VERIFIER_OBSERVATION {}",
        json!({
            "provider": "framework.backend",
            "caseId": "backend-observed-route-unknown-auth",
            "complete": result.complete,
            "gaps": result.coverage_gaps,
            "auth": route["auth"],
        })
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn caller_receipt_booleans_cannot_certify_backend_or_compatibility() {
    use legion_audit::native_providers::architecture::{compatibility, evidence, framework};
    use sha2::{Digest, Sha256};

    let root = fixture_root("caller-runtime-receipt-is-not-authority");
    write(
        &root,
        "package.json",
        "{\"dependencies\":{\"express\":\"4.21.0\"}}\n",
    );
    write(&root, "src/server.js", "app.get('/health', handler);\n");
    let bytes = "caller supplied observation\n";
    write(&root, "observation.json", bytes);
    let binding = json!({"repositoryRevision":"caller-revision","digest":format!("sha256:{}", "1".repeat(64))});
    let artifacts = json!({"evidenceIndex":{"reported-runtime":{
        "path":"observation.json",
        "digest":format!("sha256:{}", hex::encode(Sha256::digest(bytes.as_bytes()))),
        "binding":binding,
        "storageReceipt":{"immutable":true},
        "toolReceipt":{"complete":true,"tool":{"executableDigest":format!("sha256:{}", "2".repeat(64))}}
    }}});
    let authority = evidence::authority(
        Some(&json!({"binding":binding})),
        Some(&artifacts),
        Some(&json!(root.to_string_lossy())),
        None,
    );
    // These plausible forged claims satisfy protocol checks, not authentication.
    assert!(evidence::validate_refs(Some(&json!(["reported-runtime"])), &authority).is_empty());
    let route = json!({"path":"/health","auth":"required","evidenceRefs":["reported-runtime"]});
    let direct_backend =
        framework::analyze_backend_framework("express", &json!({"routes":[route]}), &authority)
            .unwrap();
    assert!(!direct_backend.complete);
    assert_eq!(direct_backend.output()["certificationClaim"], false);
    let inventory = inventory(&root);
    for (id, observed) in [
        ("framework.backend", "ok"),
        ("compatibility.core", "ok"),
        ("compatibility.core", "different"),
    ] {
        let mut input_artifacts = artifacts.clone();
        if id == "framework.backend" {
            input_artifacts["backendFrameworks"] = json!([{"name":"express","routes":[route]}]);
        } else {
            input_artifacts["compatibility"] = json!([{"producerVersion":"1","consumerVersion":"1",
                "platform":"fixture","contract":"response","expected":"ok","observed":observed,
                "evidenceRefs":["reported-runtime"]}]);
            let comparison =
                compatibility::compatibility_finding(&input_artifacts["compatibility"][0]).unwrap();
            assert_eq!(comparison["certificationClaim"], false);
            assert_eq!(
                comparison["status"],
                if observed == "ok" {
                    "compatible"
                } else {
                    "incompatible"
                }
            );
        }
        let input = json!({"plan":{"binding":binding},"artifacts":input_artifacts});
        let plan = framework_plan(&root, id, &inventory);
        for configuration_input in [false, true] {
            let mut provider = plan.provider(id).unwrap().clone();
            let mut registry = NativeProviderRegistry::new(&root);
            if configuration_input {
                provider.configuration.insert("input".into(), input.clone());
            } else {
                registry.architecture = registry.architecture.with_input(id, input.clone());
            }
            let result = registry.execute(&provider, &inventory).unwrap();
            assert!(result.applicable && !result.complete);
            assert_eq!(result.status, ProviderStatus::Partial);
            assert!(
                result.findings.is_empty(),
                "caller observations cannot mint authenticated findings"
            );
            assert!(result
                .coverage_gaps
                .iter()
                .any(|gap| gap == "runtime-evidence-trust-unavailable"));
            let analysis = &result.details["nativeAnalysis"];
            assert_eq!(analysis["certificationClaim"], false);
            assert_eq!(analysis["denominator"]["examined"], 0);
            assert_eq!(analysis["protocolValidation"]["examined"], 1);
            if id == "compatibility.core" {
                assert_eq!(
                    analysis["comparisons"][0]["status"],
                    if observed == "ok" {
                        "compatible"
                    } else {
                        "incompatible"
                    }
                );
                assert_eq!(analysis["comparisons"][0]["certificationClaim"], false);
            }
        }
    }
    fs::remove_dir_all(root).unwrap();
}

fn framework_plan(root: &Path, id: &str, inventory: &InventoryEnvelope) -> FrozenPlan {
    let registry: Value = serde_json::from_str(
        &fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../../src/registry/providers.json"
        ))
        .unwrap(),
    )
    .unwrap();
    let spec: ProviderSpec = serde_json::from_value(
        registry["providers"]
            .as_array()
            .unwrap()
            .iter()
            .find(|entry| entry["id"] == id)
            .unwrap()
            .clone(),
    )
    .unwrap();
    AuditPlan::compile_with_root(Some(root), inventory, &[spec])
        .unwrap()
        .freeze(Some(b"architecture-framework-source-fixture-key"))
        .unwrap()
}

#[test]
fn file_only_provider_accuracy_framework_source_verifiers() {
    for (id, path, body, manifest) in [
        (
            "framework.frontend",
            "src/App.tsx",
            "export function App() { return <main>Hello</main>; }\n",
            Some("{\"name\":\"web\",\"dependencies\":{\"react\":\"18.3.1\"}}\n"),
        ),
        (
            "framework.data",
            "schema.prisma",
            "model User {\n  id Int @id\n}\n",
            None,
        ),
    ] {
        let mut outcomes = Vec::new();
        for change in [
            "valid",
            "drift",
            "missing-digest",
            "forged-native-json",
            "wrong-binding",
            "item-cap",
        ] {
            let root = fixture_root(&format!("{id}-{change}"));
            if let Some(manifest) = manifest {
                write(&root, "package.json", manifest);
            }
            write(&root, path, body);
            if change == "item-cap" {
                // Match 2,001 source observations: cap must expose an omitted
                // tail, even when that tail lacks a frozen content digest.
                for index in 0..2_000 {
                    let extra = if id == "framework.frontend" {
                        format!("src/extra-{index:04}.tsx")
                    } else {
                        format!("schema-extra-{index:04}.prisma")
                    };
                    write(&root, &extra, body);
                }
            }
            let mut inv = inventory(&root);
            if matches!(change, "missing-digest" | "item-cap") {
                let mut entries = inv.entries.clone();
                let missing_path = if change == "item-cap" && id == "framework.frontend" {
                    "src/extra-1999.tsx"
                } else {
                    path
                };
                entries
                    .iter_mut()
                    .find(|entry| entry.path == missing_path)
                    .unwrap()
                    .digest = None;
                inv = InventoryEnvelope::new(&inv.repository_id, &inv.generation, entries).unwrap();
            }
            let plan = framework_plan(&root, id, &inv);
            let mut registry = NativeProviderRegistry::new(&root);
            if change == "drift" {
                write(&root, path, &format!("{body}// changed after freeze\n"));
            }
            if change == "forged-native-json" {
                let observed = execute(&plan, &inv, &registry).unwrap();
                let original = &observed.results[0].result;
                assert!(original.complete, "{id}: {original:?}");
                let mut copied_input = original.details["nativeInput"].clone();
                copied_input["nativeSourceEvidence"] =
                    original.details["nativeSourceEvidence"].clone();
                copied_input["producer"]["kind"] = json!("native-frozen-source");
                // Public analyzers & with_input stay on tool-artifact evidence.
                let public = if id == "framework.data" {
                    legion_audit::native_providers::architecture::data::analyze(&copied_input)
                        .unwrap()
                } else {
                    legion_audit::native_providers::architecture::framework::analyze_frontend(
                        &copied_input,
                    )
                    .unwrap()
                };
                assert!(!public.complete, "native JSON must not be a capability");
                registry.architecture = registry.architecture.with_input(id, copied_input);
            }
            let result = if change == "wrong-binding" {
                // Adversarial dispatch starts from the real frozen provider;
                // changed scope identity must not admit native source evidence.
                let mut changed = plan.provider(id).unwrap().clone();
                changed.configuration.insert(
                    "denominatorDigest".into(),
                    json!(format!("sha256:{}", "0".repeat(64))),
                );
                registry.execute(&changed, &inv).unwrap()
            } else {
                execute(&plan, &inv, &registry)
                    .unwrap()
                    .results
                    .remove(0)
                    .result
            };
            assert!(result.applicable, "{id}/{change}");
            assert!(result.findings.is_empty(), "{id}/{change}");
            assert!(unavailable_reason(&result).is_none(), "{id}/{change}");
            let accepted = result.complete && result.coverage_gaps.is_empty();
            assert_eq!(accepted, change == "valid", "{id}/{change}: {result:?}");
            if accepted {
                assert_eq!(result.status, ProviderStatus::Complete);
                let coverage = result.coverage.as_ref().unwrap();
                assert_eq!(coverage.expected, inv.entries.len() as u64);
                assert_eq!(coverage.examined, coverage.expected);
                assert!(coverage.complete());
                let source = &result.details["nativeSourceEvidence"];
                assert_eq!(source["kind"], "native-frozen-source");
                assert_eq!(source["claim"], "source-bytes-observed");
                assert_eq!(source["repositoryRevision"], inv.generation);
                assert_eq!(source["inventoryDigest"], inv.digest);
                assert_eq!(
                    source["denominatorDigest"],
                    plan.provider(id).unwrap().configuration["denominatorDigest"]
                );
                assert!(source.get("storageReceipt").is_none());
                assert!(source.get("toolReceipt").is_none());
            } else {
                assert!(!result.coverage_gaps.is_empty());
            }
            let expected_gap = if id == "framework.frontend" {
                "framework-evidence-gap"
            } else {
                "model-evidence-gap"
            };
            let mut expected_gaps: Vec<String> = match change {
                "valid" => Vec::new(),
                "drift" => vec![
                    if id == "framework.frontend" {
                        "denominator-gap"
                    } else {
                        "model-evidence-gap"
                    }
                    .to_owned(),
                    format!("producer-skipped:{path}:drift"),
                ],
                "item-cap" => vec![if id == "framework.frontend" {
                    "producer-frontend-component-cap:react:2000"
                } else {
                    "producer-data-model-cap:2000"
                }
                .to_owned()],
                _ => vec![expected_gap.to_owned()],
            };
            let mut actual_gaps = result.coverage_gaps.clone();
            expected_gaps.sort();
            actual_gaps.sort();
            outcomes.push(accuracy_receipt::OutcomeObservation {
                id: format!("{id}-{change}"),
                expected: if change == "valid" {
                    "accepted"
                } else {
                    "unproven"
                }
                .into(),
                actual: if accepted {
                    "accepted"
                } else if matches!(
                    result.status,
                    ProviderStatus::Failed | ProviderStatus::Cancelled
                ) {
                    "rejected"
                } else {
                    "unproven"
                }
                .into(),
                expected_gaps,
                actual_gaps,
            });
            println!(
                "FRAMEWORK_VERIFIER_OBSERVATION {}",
                json!({
                    "provider": id, "caseId": format!("{id}-{change}"),
                    "expectedAccepted": change == "valid", "actualAccepted": accepted,
                    "complete": result.complete, "gaps": result.coverage_gaps,
                })
            );
            fs::remove_dir_all(root).unwrap();
        }
        accuracy_receipt::emit_outcomes(
            id,
            &outcomes,
            &["engine/crates/legion-audit/tests/architecture_input_producer.rs"],
        );
    }
}

const RUST_BODY: &str = "pub fn value() -> u32 {\n    let a = 1;\n    let b = 2;\n    a + b\n}\n";

fn module(uses: &str, extra: &str, tested: bool) -> String {
    let tests = if tested {
        "#[cfg(test)]\nmod tests {\n    #[test]\n    fn value_is_three() {\n        assert_eq!(super::value(), 3);\n    }\n}\n"
    } else {
        ""
    };
    format!("{uses}\n{RUST_BODY}{extra}\n{tests}")
}

fn dirty_fixture() -> PathBuf {
    let root = fixture_root("dirty");
    write(
        &root,
        "Cargo.toml",
        "[package]\nname = \"fixture\"\nversion = \"0.1.0\"\n",
    );
    write(
        &root,
        "src/lib.rs",
        "pub mod alpha;\npub mod beta;\npub mod untested;\n",
    );
    write(
        &root,
        "src/alpha.rs",
        &module(
            "use crate::beta::value as other;",
            "// REQ-1 implemented here",
            true,
        ),
    );
    write(
        &root,
        "src/beta.rs",
        &module("use crate::alpha::value as other;", "", true),
    );
    write(&root, "src/untested.rs", &module("", "", false));
    write(
        &root,
        "web/package.json",
        "{\"name\":\"web\",\"dependencies\":{}}\n",
    );
    write(
        &root,
        "web/src/a.ts",
        "import { b } from './b';\nexport function a(): number {\n  const x = 1;\n  const y = 2;\n  return b() + x + y;\n}\n",
    );
    write(
        &root,
        "web/src/b.ts",
        "import { a } from './a';\nexport function b(): number {\n  const x = 1;\n  const y = 2;\n  return a() + x + y;\n}\n",
    );
    write(
        &root,
        "web/src/a.test.ts",
        "import { a } from './a';\ntest('a', () => {\n  expect(a()).toBe(1);\n});\n",
    );
    write(
        &root,
        "web/src/b.test.ts",
        "import { b } from './b';\ntest('b', () => {\n  expect(b()).toBe(1);\n});\n",
    );
    write(
        &root,
        "README.md",
        "# Fixture\n\nSee `src/alpha.rs` and `src/ghost/missing.rs`.\n\n- REQ-1 values add up\n- REQ-2 values are persisted\n",
    );
    root
}

fn clean_fixture() -> PathBuf {
    let root = fixture_root("clean");
    write(
        &root,
        "Cargo.toml",
        "[package]\nname = \"clean\"\nversion = \"0.1.0\"\n",
    );
    write(&root, "src/lib.rs", "pub mod good;\n");
    write(&root, "src/good.rs", &module("", "", true));
    write(
        &root,
        "README.md",
        "# Clean\n\nSee `src/good.rs` for the code.\n",
    );
    root
}

#[test]
fn cyclic_imports_become_findings_with_member_paths() {
    let root = dirty_fixture();
    let result = run(&root, "architecture.core");
    assert!(unavailable_reason(&result).is_none());
    // Findings do not make a provider `failed`: the analyzer ran.
    assert_eq!(result.status, ProviderStatus::Partial);
    let findings = located(&result);
    let paths: Vec<&str> = findings.iter().map(|(_, path)| path.as_str()).collect();
    assert!(paths.contains(&"src/alpha.rs"), "{paths:?}");
    assert!(paths.contains(&"web/src/a.ts"), "{paths:?}");
    assert_eq!(findings.len(), 2, "{findings:?}");
    let input = result.details.get("nativeInput").unwrap();
    assert_eq!(input["producer"]["kind"], "self-sourced");
    assert!(!input["projection"]["auditFacts"]["dependencyEdges"]
        .as_array()
        .unwrap()
        .is_empty());
}

#[test]
fn doc_citing_a_missing_path_is_located_at_the_doc() {
    let root = dirty_fixture();
    let result = run(&root, "docs.contract");
    let findings = located(&result);
    assert_eq!(findings.len(), 1, "{findings:?}");
    assert_eq!(findings[0].1, "README.md");
    let evidence = &result.details["findingEvidence"][&findings[0].0];
    assert_eq!(evidence["cited"], "src/ghost/missing.rs");
}

#[test]
fn source_without_a_test_is_reported_and_tested_sources_are_not() {
    let root = dirty_fixture();
    let result = run(&root, "test-quality.core");
    let findings = located(&result);
    assert_eq!(findings.len(), 1, "{findings:?}");
    assert_eq!(findings[0].1, "src/untested.rs");
}

#[test]
fn undelivered_requirement_is_reported() {
    let root = dirty_fixture();
    let result = run(&root, "requirements.traceability");
    let ids: Vec<String> = located(&result).into_iter().map(|(id, _)| id).collect();
    assert!(
        ids.contains(&"requirements.traceability:REQ-2".to_owned()),
        "{ids:?}"
    );
}

#[test]
fn providers_without_derivable_input_stay_unavailable_with_a_specific_reason() {
    let root = dirty_fixture();
    // framework.frontend and framework.data have no frontend or data files in
    // this fixture, so they are not applicable (see the test below).
    for (id, prefix) in [
        (
            "compatibility.core",
            "compatibility-observations-not-derivable",
        ),
        ("framework.backend", "no-backend-framework-detected"),
    ] {
        let result = run(&root, id);
        let reason = unavailable_reason(&result).unwrap_or_else(|| panic!("{id} not unavailable"));
        assert!(reason.starts_with(prefix), "{id}: {reason}");
        assert!(!result.complete);
    }
}

/// Without frontend or data files, those frameworks have nothing to analyse:
/// not-applicable with no gap. Rust sources could host an undetected backend
/// framework, so backend keeps its unavailable gap.
#[test]
fn framework_providers_without_their_files_are_not_applicable() {
    let root = fixture_root("not-applicable");
    write(
        &root,
        "Cargo.toml",
        "[package]\nname = \"fixture\"\nversion = \"0.1.0\"\n",
    );
    write(&root, "src/lib.rs", "pub fn value() -> u32 {\n    1\n}\n");
    for (id, reason, subject) in [
        (
            "framework.frontend",
            "no-frontend-files-in-inventory",
            "frontend",
        ),
        ("framework.data", "no-data-files-in-inventory", "data"),
    ] {
        let result = run(&root, id);
        assert!(!result.applicable, "{id}");
        assert_eq!(result.status, ProviderStatus::Ok, "{id}");
        assert!(!result.complete, "{id}");
        assert!(result.coverage.is_none(), "{id}");
        assert!(
            result.coverage_gaps.is_empty(),
            "{id}: {:?}",
            result.coverage_gaps
        );
        assert!(unavailable_reason(&result).is_none(), "{id}");
        assert_eq!(result.details["applicability"], json!("not-applicable"));
        assert_eq!(result.details["notApplicableReason"], json!(reason));
        assert_eq!(
            result.details["summary"],
            json!(format!("not applicable: no {subject} files"))
        );
        result.validate().unwrap();
    }
    let backend = run(&root, "framework.backend");
    assert!(backend.applicable);
    assert_eq!(
        unavailable_reason(&backend),
        Some("no-backend-framework-detected")
    );
    fs::remove_dir_all(root).unwrap();
}

/// JavaScript backends can use packages that the producer does not recognize;
/// their backend gap must remain visible until detection can distinguish them.
#[test]
fn unlisted_javascript_backend_keeps_backend_gap() {
    let root = fixture_root("javascript-unlisted-backend");
    write(
        &root,
        "package.json",
        "{\"name\":\"server\",\"dependencies\":{\"koa\":\"2.15.0\"}}\n",
    );
    write(&root, "src/server.js", "const Koa = require('koa');\n");
    let result = run(&root, "framework.backend");
    assert!(result.applicable);
    assert_eq!(
        unavailable_reason(&result),
        Some("no-backend-framework-detected")
    );
    assert!(!result.complete);
    assert!(result
        .coverage_gaps
        .iter()
        .any(|gap| gap == "backend-framework-denominator-zero"));
    fs::remove_dir_all(root).unwrap();
}

/// A declared frontend framework with no components is a framework that
/// exists but cannot be analysed: it keeps its gap, it is not not-applicable.
#[test]
fn a_declared_frontend_framework_keeps_its_gap() {
    let root = fixture_root("frontend-declared");
    write(
        &root,
        "package.json",
        "{\"name\":\"web\",\"dependencies\":{\"react\":\"18.3.1\"}}\n",
    );
    write(&root, "src/index.js", "export const x = 1;\n");
    let result = run(&root, "framework.frontend");
    assert!(result.applicable);
    assert!(!result.details.contains_key("applicability"));
    assert!(!result.complete);
    assert!(!result.coverage_gaps.is_empty());
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn clean_fixture_produces_no_findings() {
    let root = clean_fixture();
    for id in ["architecture.core", "docs.contract", "test-quality.core"] {
        let result = run(&root, id);
        assert!(unavailable_reason(&result).is_none(), "{id}");
        assert!(result.findings.is_empty(), "{id}: {:?}", located(&result));
        assert!(result.complete, "{id}: {:?}", result.coverage_gaps);
        let coverage = result.coverage.as_ref().unwrap();
        assert_eq!(coverage.examined, coverage.expected, "{id}");
    }
    let requirements = run(&root, "requirements.traceability");
    assert_eq!(
        unavailable_reason(&requirements),
        Some("no-requirement-ids-declared-in-docs")
    );
}

#[test]
fn unreadable_denominator_files_become_coverage_gaps() {
    let root = clean_fixture();
    let inv = inventory(&root);
    // Content drift after the inventory was frozen is a gap, never a silent read.
    write(&root, "src/good.rs", "pub fn changed() {}\n");
    let result = NativeProviderRegistry::new(&root)
        .execute(&provider("docs.contract"), &inv)
        .unwrap();
    assert!(!result.complete);
    assert!(
        result
            .coverage_gaps
            .iter()
            .any(|gap| gap == "producer-skipped:src/good.rs:drift"),
        "{:?}",
        result.coverage_gaps
    );
    let coverage = result.coverage.as_ref().unwrap();
    assert!(coverage.examined < coverage.expected);
}

#[test]
fn host_injected_input_keeps_precedence() {
    let root = dirty_fixture();
    let mut injected = provider("architecture.core");
    let input = json!({"projection":{"auditFacts":{"dependencyEdges":[{"from":"x","to":"y"}]}}});
    injected.configuration.insert("input".into(), input.clone());
    let result = NativeProviderRegistry::new(&root)
        .execute(&injected, &inventory(&root))
        .unwrap();
    assert!(unavailable_reason(&result).is_none());
    assert!(result.findings.is_empty());
    assert_eq!(result.details.get("nativeInput"), Some(&input));
}

#[test]
fn coverage_is_bound_to_the_plans_frozen_denominator() {
    let root = dirty_fixture();
    let inv = inventory(&root);
    for id in [
        "architecture.core",
        "docs.contract",
        "test-quality.core",
        "requirements.traceability",
    ] {
        let mut planned = provider(id);
        planned
            .configuration
            .insert("denominatorCount".into(), json!(inv.entries.len()));
        planned
            .configuration
            .insert("denominatorDigest".into(), json!(inv.digest.clone()));
        let result = NativeProviderRegistry::new(&root)
            .execute(&planned, &inv)
            .unwrap();
        let coverage = result.coverage.as_ref().unwrap();
        assert_eq!(coverage.expected, inv.entries.len() as u64, "{id}");
        assert_eq!(coverage.denominator_digest, inv.digest, "{id}");
        assert!(coverage.examined <= coverage.expected, "{id}");
    }
}

#[test]
fn docs_under_frozen_history_trees_are_ignored() {
    let root = clean_fixture();
    for dir in [
        "docs/provenance",
        "docs/audits",
        "archive",
        "node_modules/x",
    ] {
        write(
            &root,
            &format!("{dir}/old.md"),
            "See `src/ghost/gone.rs` and [x](src/ghost/also_gone.rs).\n",
        );
    }
    write(&root, "CHANGELOG.md", "Removed `src/ghost/changelog.rs`.\n");
    let result = run(&root, "docs.contract");
    assert!(result.findings.is_empty(), "{:?}", located(&result));
}

#[test]
fn existing_cited_paths_are_not_findings_and_missing_ones_dedupe() {
    let root = clean_fixture();
    write(
        &root,
        "docs/guide.md",
        "`src/good.rs` `src/ghost/gone.rs` `src/ghost/gone.rs`\n",
    );
    let result = run(&root, "docs.contract");
    let findings = located(&result);
    assert_eq!(findings.len(), 1, "{findings:?}");
    assert_eq!(findings[0].1, "docs/guide.md");
}

#[test]
fn noisy_providers_cap_findings_with_an_overflow_gap() {
    let root = clean_fixture();
    let spans: String = (0..250).map(|i| format!("`src/ghost/m{i}.rs`\n")).collect();
    write(&root, "docs/many.md", &spans);
    let result = run(&root, "docs.contract");
    assert_eq!(result.findings.len(), 200);
    assert!(!result.complete);
    assert!(
        result
            .coverage_gaps
            .contains(&"docs.contract:findings-overflow:50".to_owned()),
        "{:?}",
        result.coverage_gaps
    );
    result.validate().unwrap();
}

#[test]
fn small_reexport_shells_and_test_trees_are_not_missing_tests() {
    let root = clean_fixture();
    write(
        &root,
        "src/shell/mod.rs",
        "pub mod a;\npub mod b;\npub mod c;\n",
    );
    write(&root, "benches/bench_it.rs", &module("", "", false));
    write(
        &root,
        "src/api.generated.ts",
        "export const a = 1;\nexport const b = 2;\nexport const c = 3;\nexport const d = 4;\nexport const e = 5;\nexport const f = 6;\n",
    );
    let result = run(&root, "test-quality.core");
    assert!(result.findings.is_empty(), "{:?}", located(&result));
}
