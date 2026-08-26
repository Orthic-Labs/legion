//! LEG-I01 frozen-plan, provider-gap, and finding-identity acceptance corpus.

use legion_audit::{execute, topological, AuditProvider, ProviderExecutor, ProviderKind};
use legion_contracts::{Coverage, ProviderId, ProviderResult, ProviderStatus};
use serde_json::Value;
use std::collections::BTreeMap;

fn fixtures() -> Value {
    serde_json::from_str(include_str!(
        "../../migration/native-rust/fixtures/audit-cases.v1.json"
    ))
    .expect("LEG-001 audit fixtures remain valid JSON")
}

fn provider(id: &str, dependencies: &[&str]) -> AuditProvider {
    AuditProvider {
        id: id.into(),
        version: "fixture".into(),
        role: "deterministic".into(),
        phase: "source".into(),
        lens_ids: Vec::new(),
        dependencies: dependencies.iter().map(|value| (*value).into()).collect(),
        kind: ProviderKind::BuiltIn,
        configuration: BTreeMap::new(),
        bounds: BTreeMap::new(),
        clean_claim: "finding-producing".into(),
        benchmark_status: "qualified".into(),
        benchmark_required_for_clean_claim: true,
        qualification_digest: Some("sha256:fixture".into()),
        required: true,
    }
}

fn spec(id: &str, role: &str, runner: &str, selector: Value) -> legion_contracts::ProviderSpec {
    legion_contracts::ProviderSpec {
        schema_version: 2,
        id: ProviderId::new(id).unwrap(),
        provider_version: "1".into(),
        family: "fixture".into(),
        lens_ids: if role == "deterministic" {
            Vec::new()
        } else {
            vec!["fixture-lens".into()]
        },
        role: role.into(),
        phase: "source".into(),
        depends_on: Vec::new(),
        consumes: Vec::new(),
        produces: vec!["provider-result".into()],
        selector,
        denominator_kind: "selected-scope".into(),
        runner: serde_json::json!({"kind": runner}),
        host_capabilities: Vec::new(),
        execution: serde_json::json!({}),
        reasoning: serde_json::json!({}),
        benchmark: serde_json::json!({
            "status": "qualified",
            "requiredForCleanClaim": true,
            "qualificationDigest": "sha256:fixture"
        }),
        clean_claim: "finding-producing".into(),
        control_ids: Vec::new(),
        scopes: Vec::new(),
        selectable: true,
    }
}

#[test]
fn audit_fixture_plan_only_is_incomplete_and_honest() {
    let fixture = fixtures();
    let case = &fixture["cases"][0];
    assert_eq!(case["expected"]["audit_status"], "incomplete");
    assert_eq!(case["expected"]["quality_gate"], "unproven");
    assert_eq!(case["expected"]["findings"].as_array().unwrap().len(), 0);
}

#[test]
fn provider_order_is_deterministic_and_cycles_fail() {
    let ordered = topological(&[provider("b", &["a"]), provider("a", &[])]).unwrap();
    assert_eq!(ordered, vec!["a", "b"]);
    assert!(topological(&[provider("a", &["b"]), provider("b", &["a"])]).is_err());
    let _ = ProviderId::new("fixture-provider").unwrap();
}

#[test]
fn audit_required_fields_are_explicit_in_fixture() {
    let fixture = fixtures();
    let required = fixture["cases"][1]["expected"]["required_fields"]
        .as_array()
        .unwrap()
        .iter()
        .map(|value| value.as_str().unwrap())
        .collect::<Vec<_>>();
    for field in [
        "schemaVersion",
        "targets",
        "findings",
        "gaps",
        "claims",
        "auditStatus",
    ] {
        assert!(required.contains(&field));
    }
}

#[test]
fn native_class_a_pack_manifest_compiles_exactly() {
    let manifest = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../../packs/native/manifest.v1.json"),
    )
    .unwrap();
    let compiled = legion_rules::RuleCompiler::compile_manifest_json(&manifest).unwrap();
    assert_eq!(compiled.len(), 11);
    assert_eq!(
        compiled
            .values()
            .filter_map(|pack| pack.lexical.as_ref())
            .count(),
        11
    );
}

#[test]
fn plan_requires_provider_and_signature() {
    let inventory = legion_audit::InventoryEnvelope::new("fixture", "generation", Vec::new())
        .expect("fixture inventory");
    assert!(legion_audit::AuditPlan::compile(&inventory, &[]).is_err());

    let spec = legion_contracts::ProviderSpec {
        schema_version: 2,
        id: ProviderId::new("fixture-provider").unwrap(),
        provider_version: "1".into(),
        family: "fixture".into(),
        role: "candidate-generator".into(),
        phase: "static".into(),
        lens_ids: vec!["security".into()],
        depends_on: Vec::new(),
        consumes: Vec::new(),
        produces: Vec::new(),
        selector: serde_json::json!({"op": "always"}),
        denominator_kind: "selected-scope".into(),
        runner: serde_json::json!({"kind": "reasoning-contract"}),
        host_capabilities: Vec::new(),
        execution: serde_json::json!({}),
        reasoning: serde_json::json!({}),
        benchmark: serde_json::json!({
            "status": "qualified",
            "requiredForCleanClaim": true,
            "qualificationDigest": "sha256:fixture"
        }),
        clean_claim: "evidence-only".into(),
        control_ids: Vec::new(),
        scopes: Vec::new(),
        selectable: true,
    };
    let plan = legion_audit::AuditPlan::compile(&inventory, &[spec]).expect("fixture plan");
    assert!(plan.clone().freeze(None).is_err());
    assert!(plan.freeze(Some(b"fixture-signing-key")).is_ok());
}

struct FixtureExecutor {
    complete: bool,
}

impl ProviderExecutor for FixtureExecutor {
    fn execute(
        &self,
        provider: &AuditProvider,
        _: &legion_audit::InventoryEnvelope,
    ) -> Result<ProviderResult, legion_audit::AuditError> {
        Ok(ProviderResult {
            schema_version: 1,
            provider: ProviderId::new(&provider.id).unwrap(),
            applicable: true,
            required: provider.required,
            status: if self.complete {
                ProviderStatus::Complete
            } else {
                ProviderStatus::Failed
            },
            complete: self.complete,
            coverage: self.complete.then_some(Coverage {
                denominator_digest: "fixture".into(),
                expected: 1,
                examined: 1,
                gaps: Vec::new(),
            }),
            findings: Vec::new(),
            coverage_gaps: if self.complete {
                Vec::new()
            } else {
                vec!["fixture-provider-failed".into()]
            },
            degradation: Vec::new(),
            details: BTreeMap::new(),
        })
    }
}

#[test]
fn selected_lenses_must_reconcile_with_completed_providers() {
    let inventory = legion_audit::InventoryEnvelope::new("fixture", "generation", Vec::new())
        .expect("fixture inventory");
    let spec = legion_contracts::ProviderSpec {
        schema_version: 2,
        id: ProviderId::new("fixture-provider").unwrap(),
        provider_version: "1".into(),
        family: "fixture".into(),
        role: "candidate-generator".into(),
        phase: "judgment".into(),
        lens_ids: vec!["correctness".into(), "architecture".into()],
        depends_on: Vec::new(),
        consumes: Vec::new(),
        produces: Vec::new(),
        selector: serde_json::json!({"op": "always"}),
        denominator_kind: "selected-scope".into(),
        runner: serde_json::json!({"kind": "reasoning-contract"}),
        host_capabilities: Vec::new(),
        execution: serde_json::json!({}),
        reasoning: serde_json::json!({}),
        benchmark: serde_json::json!({
            "status": "qualified",
            "requiredForCleanClaim": true,
            "qualificationDigest": "sha256:fixture"
        }),
        clean_claim: "evidence-only".into(),
        control_ids: Vec::new(),
        scopes: Vec::new(),
        selectable: true,
    };
    let plan = legion_audit::AuditPlan::compile(&inventory, &[spec])
        .unwrap()
        .freeze(Some(b"fixture-signing-key"))
        .unwrap();

    let incomplete = execute(&plan, &inventory, &FixtureExecutor { complete: false }).unwrap();
    assert_eq!(
        incomplete.selected_lenses,
        vec!["architecture", "correctness"]
    );
    assert!(incomplete.lenses_ran.is_empty());
    assert!(incomplete
        .gaps
        .contains(&"selected reasoning lenses did not complete".into()));

    // A fixture denominator is deliberately rejected: only the frozen inventory
    // digest and exact inventory count can support a complete provider claim.
    let complete = execute(&plan, &inventory, &FixtureExecutor { complete: true }).unwrap();
    assert_eq!(
        complete.selected_lenses,
        vec!["architecture", "correctness"]
    );
    assert!(complete.lenses_ran.is_empty());
    assert!(complete.gaps.iter().any(|gap| gap.contains("denominator")));
}

#[test]
fn selector_denominator_is_frozen_and_not_an_arbitrary_fixture() {
    let inventory = legion_audit::InventoryEnvelope::new(
        "fixture",
        "generation",
        vec![
            legion_audit::InventoryEntry {
                path: "src/a.rs".into(),
                symbols: Vec::new(),
                dependencies: Vec::new(),
                package_scripts: Vec::new(),
                source_file: true,
                digest: None,
            },
            legion_audit::InventoryEntry {
                path: "src/b.rs".into(),
                symbols: Vec::new(),
                dependencies: Vec::new(),
                package_scripts: Vec::new(),
                source_file: true,
                digest: None,
            },
        ],
    )
    .unwrap();
    let (all_count, all_digest) = inventory
        .denominator(&serde_json::json!({"op": "always"}))
        .unwrap();
    let (subset_count, subset_digest) = inventory
        .denominator(&serde_json::json!({"op": "paths", "paths": ["src/a.rs"]}))
        .unwrap();
    assert_eq!(all_count, 2);
    assert_eq!(all_digest, inventory.digest);
    assert_eq!(subset_count, 1);
    assert_ne!(subset_digest, inventory.digest);
    let plan = legion_audit::AuditPlan::compile(
        &inventory,
        &[spec(
            "subset-provider",
            "deterministic",
            "runtime-script",
            serde_json::json!({"op": "paths", "paths": ["src/a.rs"]}),
        )],
    )
    .unwrap();
    let provider = &plan.providers[0];
    assert_eq!(provider.bounds["blueprintDependent"], false);
    assert_eq!(provider.configuration["denominatorDigest"], subset_digest);
    assert_eq!(provider.configuration["denominatorCount"], 1);
}

#[test]
fn legacy_selector_language_preserves_evidence_denominators() {
    let inventory = legion_audit::InventoryEnvelope::new(
        "fixture",
        "generation",
        vec![
            legion_audit::InventoryEntry {
                path: "src/a.rs".into(),
                symbols: Vec::new(),
                dependencies: vec!["react".into()],
                package_scripts: Vec::new(),
                source_file: true,
                digest: None,
            },
            legion_audit::InventoryEntry {
                path: "src/b.ts".into(),
                symbols: Vec::new(),
                dependencies: Vec::new(),
                package_scripts: Vec::new(),
                source_file: true,
                digest: None,
            },
            legion_audit::InventoryEntry {
                path: "package.json".into(),
                symbols: Vec::new(),
                dependencies: Vec::new(),
                package_scripts: vec!["build".into()],
                source_file: false,
                digest: None,
            },
            legion_audit::InventoryEntry {
                path: "README.md".into(),
                symbols: Vec::new(),
                dependencies: Vec::new(),
                package_scripts: Vec::new(),
                source_file: false,
                digest: None,
            },
        ],
    )
    .unwrap();
    let selector = |value| {
        inventory
            .denominator_entries(&serde_json::json!(value))
            .unwrap()
    };
    assert_eq!(
        selector(serde_json::json!({"op": "always"})).entries.len(),
        4
    );
    assert_eq!(selector(serde_json::json!("always")).entries.len(), 4);
    assert_eq!(
        selector(serde_json::json!({"paths": ["src/*.rs"]}))
            .entries
            .len(),
        1
    );
    assert_eq!(
        selector(serde_json::json!({"op": "anyPath", "patterns": ["src-tauri/**", "src/*.rs"]}))
            .entries
            .iter()
            .map(|entry| entry.path.as_str())
            .collect::<Vec<_>>(),
        vec!["src/a.rs"]
    );
    assert_eq!(
        selector(serde_json::json!({"op": "anyExtension", "extensions": [".TS"]}))
            .entries
            .iter()
            .map(|entry| entry.path.as_str())
            .collect::<Vec<_>>(),
        vec!["src/b.ts"]
    );
    assert_eq!(
        selector(serde_json::json!({"op": "anyDependency", "names": ["react"]}))
            .entries
            .iter()
            .map(|entry| entry.path.as_str())
            .collect::<Vec<_>>(),
        vec!["src/a.rs", "src/b.ts"]
    );
    assert_eq!(
        selector(serde_json::json!({"op": "anyPackageScript", "names": ["build"]}))
            .entries
            .iter()
            .map(|entry| entry.path.as_str())
            .collect::<Vec<_>>(),
        vec!["src/a.rs", "src/b.ts"]
    );
    assert_eq!(
        selector(serde_json::json!({"op": "sourceFilesAtLeast", "count": 2}))
            .entries
            .len(),
        2
    );
    assert_eq!(
        selector(serde_json::json!({"op": "sourceFilesAtLeast", "count": 3}))
            .entries
            .len(),
        0
    );
    assert_eq!(selector(serde_json::json!({"op": "any", "selectors": [{"op": "anyExtension", "extensions": ["md"]}, {"op": "anyPath", "patterns": ["src/a.rs"]}]})).entries.iter().map(|entry| entry.path.as_str()).collect::<Vec<_>>(), vec!["README.md", "src/a.rs"]);
    assert_eq!(selector(serde_json::json!({"op": "all", "selectors": [{"op": "anyExtension", "extensions": ["rs", "ts"]}, {"op": "anyPath", "patterns": ["src/**"]}]})).entries.iter().map(|entry| entry.path.as_str()).collect::<Vec<_>>(), vec!["src/a.rs", "src/b.ts"]);
    let candidate = selector(serde_json::json!({"op": "anyPath", "patterns": ["src/a.rs"]}));
    let security = inventory
        .denominator_entries_with_candidates(
            &serde_json::json!({"op": "securityCandidatesSelected"}),
            &[candidate],
        )
        .unwrap();
    assert_eq!(
        security
            .entries
            .iter()
            .map(|entry| entry.path.as_str())
            .collect::<Vec<_>>(),
        vec!["src/a.rs"]
    );
    assert!(inventory
        .denominator_entries(&serde_json::json!({"op": "confirmedSecurityFinding"}))
        .unwrap()
        .entries
        .is_empty());
}

fn projected_receipt(provider: &str, state: &str, complete: bool, gaps: &[&str]) -> Value {
    serde_json::json!({
        "schemaVersion": 1,
        "receiptId": "receipt:fixture",
        "requestId": "request:fixture",
        "providerId": provider,
        "planId": "plan:fixture",
        "policyId": "policy:fixture",
        "policy": null,
        "taskId": null,
        "state": state,
        "complete": complete,
        "executable": null,
        "command": null,
        "cwd": null,
        "environmentNames": [],
        "sandbox": {"required": false, "receiptId": null, "networkEnabled": false},
        "processTree": {"started": complete, "terminated": complete, "hardKilled": false, "reaped": true, "detail": null},
        "timing": {"startedAtMs": 0, "completedAtMs": 0, "durationMs": 0},
        "exitCode": null,
        "signal": null,
        "stdout": null,
        "stderr": null,
        "parser": {"attempted": false, "succeeded": false, "error": null},
        "gaps": gaps,
    })
}

struct ReceiptExecutor(Value);

impl ProviderExecutor for ReceiptExecutor {
    fn execute(
        &self,
        provider: &AuditProvider,
        inventory: &legion_audit::InventoryEnvelope,
    ) -> Result<ProviderResult, legion_audit::AuditError> {
        let complete = self.0["complete"].as_bool() == Some(true);
        Ok(ProviderResult {
            schema_version: 1,
            provider: ProviderId::new(&provider.id).unwrap(),
            applicable: true,
            required: true,
            status: if complete {
                ProviderStatus::Complete
            } else {
                ProviderStatus::Failed
            },
            complete,
            coverage: complete.then_some(Coverage {
                denominator_digest: inventory.digest.clone(),
                expected: 1,
                examined: 1,
                gaps: Vec::new(),
            }),
            findings: Vec::new(),
            coverage_gaps: if complete {
                Vec::new()
            } else {
                vec!["fixture-failed".into()]
            },
            degradation: Vec::new(),
            details: BTreeMap::from([("executionReceipt".into(), self.0.clone())]),
        })
    }
}

#[test]
fn external_receipt_projection_rejects_missing_identity_and_state() {
    let inventory = legion_audit::InventoryEnvelope::new(
        "fixture",
        "generation",
        vec![legion_audit::InventoryEntry {
            path: "src/a.rs".into(),
            symbols: Vec::new(),
            dependencies: Vec::new(),
            package_scripts: Vec::new(),
            source_file: true,
            digest: None,
        }],
    )
    .unwrap();
    let mut malformed_nested = projected_receipt("external-provider", "failed", false, &["failed"]);
    malformed_nested["timing"]["durationMs"] = serde_json::json!(9);
    for receipt in [
        Value::Null,
        projected_receipt("wrong-provider", "failed", false, &["failed"]),
        projected_receipt("external-provider", "unknown", false, &["failed"]),
        malformed_nested,
    ] {
        let plan = legion_audit::AuditPlan::compile(
            &inventory,
            &[spec(
                "external-provider",
                "deterministic",
                "legacy-check",
                serde_json::json!({"op": "always"}),
            )],
        )
        .unwrap()
        .freeze(Some(b"key"))
        .unwrap();
        let report = execute(&plan, &inventory, &ReceiptExecutor(receipt)).unwrap();
        assert!(report
            .gaps
            .iter()
            .any(|gap| gap.contains("invalid-provider-result")));
    }
    let plan = legion_audit::AuditPlan::compile(
        &inventory,
        &[spec(
            "external-provider",
            "deterministic",
            "legacy-check",
            serde_json::json!({"op": "always"}),
        )],
    )
    .unwrap()
    .freeze(Some(b"key"))
    .unwrap();
    let completed = execute(
        &plan,
        &inventory,
        &ReceiptExecutor(projected_receipt(
            "external-provider",
            "completed",
            true,
            &[],
        )),
    )
    .unwrap();
    assert!(completed.gaps.is_empty());

    for state in [
        "unauthorized_effect",
        "cancelled",
        "timeout",
        "missing_executable",
    ] {
        let plan = legion_audit::AuditPlan::compile(
            &inventory,
            &[spec(
                "external-provider",
                "deterministic",
                "legacy-check",
                serde_json::json!({"op": "always"}),
            )],
        )
        .unwrap()
        .freeze(Some(b"key"))
        .unwrap();
        let report = execute(
            &plan,
            &inventory,
            &ReceiptExecutor(projected_receipt(
                "external-provider",
                state,
                false,
                &[state],
            )),
        )
        .unwrap();
        assert!(report
            .gaps
            .iter()
            .any(|gap| gap.contains("provider-incomplete")));
    }
}

#[test]
fn candidate_generator_may_complete_generation_but_not_emit_findings() {
    let inventory = legion_audit::InventoryEnvelope::new(
        "fixture",
        "generation",
        vec![legion_audit::InventoryEntry {
            path: "src/a.rs".into(),
            symbols: Vec::new(),
            dependencies: Vec::new(),
            package_scripts: Vec::new(),
            source_file: true,
            digest: None,
        }],
    )
    .unwrap();
    let plan = legion_audit::AuditPlan::compile(
        &inventory,
        &[spec(
            "candidate-provider",
            "candidate-generator",
            "runtime-script",
            serde_json::json!({"op": "always"}),
        )],
    )
    .unwrap()
    .freeze(Some(b"key"))
    .unwrap();
    struct CandidateExecutor;
    impl ProviderExecutor for CandidateExecutor {
        fn execute(
            &self,
            provider: &AuditProvider,
            inventory: &legion_audit::InventoryEnvelope,
        ) -> Result<ProviderResult, legion_audit::AuditError> {
            Ok(ProviderResult {
                schema_version: 1,
                provider: ProviderId::new(&provider.id).unwrap(),
                applicable: true,
                required: true,
                status: ProviderStatus::Complete,
                complete: true,
                coverage: Some(Coverage {
                    denominator_digest: inventory.digest.clone(),
                    expected: 1,
                    examined: 1,
                    gaps: Vec::new(),
                }),
                findings: Vec::new(),
                coverage_gaps: Vec::new(),
                degradation: Vec::new(),
                details: BTreeMap::new(),
            })
        }
    }
    let report = execute(&plan, &inventory, &CandidateExecutor).unwrap();
    assert!(report.gaps.is_empty());
    assert!(report.results[0].result.complete);
}
