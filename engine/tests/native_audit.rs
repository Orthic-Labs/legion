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

    let complete = execute(&plan, &inventory, &FixtureExecutor { complete: true }).unwrap();
    assert_eq!(complete.selected_lenses, complete.lenses_ran);
    assert!(complete.gaps.is_empty());
}
