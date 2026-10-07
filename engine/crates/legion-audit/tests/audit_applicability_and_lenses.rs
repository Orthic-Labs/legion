//! Unsigned plans still execute, inapplicable providers are not-applicable
//! rather than failed, a clean verdict is reachable, and reasoning lenses are
//! counted separately from deterministic lens tags (`pending-host` work).

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicUsize, Ordering};

use legion_audit::native_providers::reasoning::{pending_lens_work, ReasoningProviderExecutor};
use legion_audit::{
    canonical_report, execute, verify_execution, verify_source_diagnostic, AuditError, AuditPlan,
    AuditProvider, FrozenPlan, InventoryEntry, InventoryEnvelope, ProviderExecutor, ProviderKind,
};
use legion_contracts::{
    Coverage, ProviderId, ProviderResult, ProviderSpec, ProviderStatus, ReportStatus,
};
use serde_json::{json, Value};

const KEY: &[u8] = b"applicability-fixture-signing-key";

fn inventory() -> InventoryEnvelope {
    InventoryEnvelope::new(
        "fixture-repository",
        "fixture-generation",
        vec![InventoryEntry {
            path: "src/lib.rs".into(),
            symbols: Vec::new(),
            dependencies: Vec::new(),
            package_scripts: Vec::new(),
            source_file: true,
            digest: None,
        }],
    )
    .unwrap()
}

fn spec(id: &str, selector: Value, runner: Value, role: &str, lenses: &[&str]) -> ProviderSpec {
    ProviderSpec {
        schema_version: 2,
        id: ProviderId::new(id).unwrap(),
        provider_version: "1.0.0".into(),
        family: "fixture".into(),
        lens_ids: lenses.iter().map(|lens| (*lens).to_owned()).collect(),
        role: role.into(),
        phase: "source".into(),
        depends_on: Vec::new(),
        consumes: vec!["repository-inventory".into()],
        produces: vec!["provider-result".into()],
        selector,
        denominator_kind: "first-party-source-files".into(),
        runner,
        host_capabilities: Vec::new(),
        execution: json!({}),
        reasoning: json!({}),
        benchmark: json!({"status":"qualified","requiredForCleanClaim":false}),
        clean_claim: "evidence-only".into(),
        control_ids: Vec::new(),
        scopes: Vec::new(),
        selectable: true,
    }
}

fn deterministic(id: &str, selector: Value, lenses: &[&str]) -> ProviderSpec {
    spec(
        id,
        selector,
        json!({"kind":"built-in"}),
        "deterministic",
        lenses,
    )
}

fn reasoning(id: &str, lens: &str) -> ProviderSpec {
    spec(
        id,
        json!({"op":"always"}),
        json!({"kind":"reasoning-contract","contract":"fixture-reasoning-v1"}),
        "adjudicator",
        &[lens],
    )
}

/// Completes every deterministic provider with exact frozen coverage, and
/// leaves reasoning providers to an unavailable host.
struct Fixture {
    calls: AtomicUsize,
    reasoning: ReasoningProviderExecutor,
}

impl Fixture {
    fn new() -> Self {
        Self {
            calls: AtomicUsize::new(0),
            reasoning: ReasoningProviderExecutor::unavailable(env!("CARGO_MANIFEST_DIR")),
        }
    }
}

impl ProviderExecutor for Fixture {
    fn execute(
        &self,
        provider: &AuditProvider,
        _: &InventoryEnvelope,
    ) -> Result<ProviderResult, AuditError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let digest = provider.configuration["denominatorDigest"]
            .as_str()
            .unwrap()
            .to_owned();
        let count = provider.configuration["denominatorCount"].as_u64().unwrap();
        Ok(ProviderResult {
            schema_version: 1,
            provider: ProviderId::new(&provider.id).unwrap(),
            applicable: true,
            required: provider.required,
            status: ProviderStatus::Complete,
            complete: true,
            coverage: Some(Coverage {
                denominator_digest: digest,
                expected: count,
                examined: count,
                gaps: Vec::new(),
            }),
            findings: Vec::new(),
            coverage_gaps: Vec::new(),
            degradation: Vec::new(),
            details: BTreeMap::new(),
        })
    }

    fn execute_bound(
        &self,
        plan: &FrozenPlan,
        provider: &AuditProvider,
        inventory: &InventoryEnvelope,
    ) -> Result<ProviderResult, AuditError> {
        if provider.kind == ProviderKind::HostService {
            return self.reasoning.execute_bound(plan, provider, inventory);
        }
        self.execute(provider, inventory)
    }
}

#[test]
fn unsigned_plan_runs_every_provider_but_never_reports_clean() {
    let inventory = inventory();
    let specs = [
        deterministic("fixture.a", json!({"op":"always"}), &[]),
        deterministic("fixture.b", json!({"op":"always"}), &[]),
    ];
    let plan = AuditPlan::compile(&inventory, &specs)
        .unwrap()
        .freeze_source_diagnostic()
        .unwrap();
    let executor = Fixture::new();
    let report = execute(&plan, &inventory, &executor).unwrap();
    assert_eq!(executor.calls.load(Ordering::SeqCst), 2);
    assert!(report.gaps.iter().any(|gap| gap == "unsigned-plan"));
    assert!(!report
        .gaps
        .iter()
        .any(|gap| gap.starts_with("unsigned-plan-provider-not-executed")));
    assert!(report
        .results
        .iter()
        .all(|entry| !entry.skipped && entry.result.complete));
    assert!(verify_source_diagnostic(&report, &plan).is_ok());
    assert!(verify_execution(&report).is_err());
    let rendered = canonical_report("fixture", &report).unwrap();
    assert_eq!(rendered.status, ReportStatus::Incomplete);
}

#[test]
fn inapplicable_provider_is_not_applicable_and_clean_is_reachable() {
    let inventory = inventory();
    let specs = [
        deterministic("fixture.applies", json!({"op":"always"}), &[]),
        deterministic(
            "fixture.elsewhere",
            json!({"op":"anyPath","patterns":["elsewhere/**"]}),
            &[],
        ),
    ];
    let plan = AuditPlan::compile(&inventory, &specs)
        .unwrap()
        .freeze(Some(KEY))
        .unwrap();
    assert!(plan.provider("fixture.applies").unwrap().required);
    assert!(!plan.provider("fixture.elsewhere").unwrap().required);
    let executor = Fixture::new();
    let report = execute(&plan, &inventory, &executor).unwrap();
    assert_eq!(executor.calls.load(Ordering::SeqCst), 1);
    let elsewhere = report
        .results
        .iter()
        .find(|entry| entry.provider == "fixture.elsewhere")
        .unwrap();
    assert!(!elsewhere.result.applicable);
    assert!(!elsewhere.skipped);
    assert!(report.gaps.is_empty(), "{:?}", report.gaps);
    assert!(verify_execution(&report).is_ok());
    let rendered = canonical_report("fixture", &report).unwrap();
    assert_eq!(rendered.status, ReportStatus::Clean);
}

#[test]
fn deterministic_lens_tags_are_not_reasoning_lenses_and_pending_host_is_reported() {
    let inventory = inventory();
    let specs = [
        deterministic("fixture.tagged", json!({"op":"always"}), &["security"]),
        reasoning("reasoning.architecture", "architecture"),
    ];
    let plan = AuditPlan::compile(&inventory, &specs)
        .unwrap()
        .freeze_source_diagnostic()
        .unwrap();
    let report = execute(&plan, &inventory, &Fixture::new()).unwrap();
    assert!(report.lenses_ran.is_empty(), "{:?}", report.lenses_ran);
    assert_eq!(report.selected_reasoning_lenses, vec!["architecture"]);
    assert_eq!(report.deterministic_lens_tags.get("security"), Some(&1));
    assert_eq!(report.pending_host, vec!["reasoning.architecture"]);
    assert!(report
        .gaps
        .iter()
        .any(|gap| gap == "reasoning-lens-pending-host:reasoning.architecture"));
    assert!(report
        .gaps
        .iter()
        .any(|gap| gap == "selected reasoning lenses did not complete"));
    let pending = report
        .results
        .iter()
        .find(|entry| entry.provider == "reasoning.architecture")
        .unwrap();
    assert_eq!(pending.result.status, ProviderStatus::Partial);
    assert!(!pending.result.complete);
    assert_eq!(
        pending.result.details["reasoningHostState"],
        json!("pending-host")
    );
    let rendered = canonical_report("fixture", &report).unwrap();
    assert_eq!(rendered.claims["lensesRan"], json!([]));
    assert_eq!(rendered.claims["reasoningLensesRan"], json!([]));
    assert_eq!(
        rendered.claims["deterministicLensTagCounts"]["security"],
        json!(1)
    );
    assert_eq!(rendered.status, ReportStatus::Incomplete);
}

#[test]
fn pending_lens_work_builds_a_packet_for_an_unsigned_plan() {
    let inventory = inventory();
    let specs = [reasoning("reasoning.architecture", "architecture")];
    let plan = AuditPlan::compile(&inventory, &specs)
        .unwrap()
        .freeze_source_diagnostic()
        .unwrap();
    let work = pending_lens_work(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")),
        &plan,
        &inventory,
    )
    .unwrap();
    assert_eq!(work.len(), 1);
    assert_eq!(work[0].provider_id, "reasoning.architecture");
    assert_eq!(work[0].status, "pending-host");
    assert!(work[0].request.plan_signature.is_empty());
    assert_eq!(work[0].request.plan_digest, plan.digest());
}
