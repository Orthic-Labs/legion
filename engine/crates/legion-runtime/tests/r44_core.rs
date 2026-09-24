//! Integration tests for packet r44: the gap-closing extensions to chunk
//! w2_039 (`src/lib/core/{adjudicate-run,execute-plan,build-plan,index}.mjs`)
//! — see `legion_runtime::wf_port::w2_039` doc comment for full disposition.

use std::collections::BTreeMap;

use legion_runtime::wf_port::w2_039::build_plan::{
    build_sealed_plan, PlanOptions, PlanStage, StageResult,
};
use legion_runtime::wf_port::w2_039::core_index::{build_run_manifest, ArtifactRecord};
use legion_runtime::wf_port::w2_039::execute_plan::{
    execute_plan, skipped_receipt, ExecutionPlan, HostClock, PlannedProvider, ProviderExecutor,
    ProviderOutcome,
};
use legion_runtime::wf_port::w2_039::judgment::{
    adjudicate_subjects_with_reviewer, build_judgment_packet, prepare_adjudication,
    reviewer_policy, AdjudicationPolicy, JudgmentPacket, ReviewValue, Reviewer, ReviewerPolicy,
    Subject,
};
use legion_runtime::p5_core::core_scheduler::ScheduleMode;
use legion_runtime::wf_port::w2_039::run_ledger::RunLimits;
use serde_json::json;

// ---- adjudicate-run.mjs: prepareAdjudication / reviewer-enabled branch ----

#[test]
fn reviewer_policy_end_to_end() {
    let producer = json!("legion");
    let reviewer = json!("sage");
    let policy = reviewer_policy(&producer, &reviewer, "review-0", &[]).unwrap();
    assert_eq!(policy.context_id, "review-0");
    assert!(reviewer_policy(&producer, &producer, "review-0", &[]).is_err());
}

#[test]
fn build_judgment_packet_end_to_end() {
    let packet = build_judgment_packet(Some(&json!({"id": 7})), vec![json!("ev")], vec![], json!("sage"), json!(50), None);
    assert_eq!(packet.subject, json!({"id": 7}));
    assert_eq!(packet.budget, json!(50));
}

struct FakeReviewer;
impl Reviewer for FakeReviewer {
    fn review(&self, _packet: &JudgmentPacket, _policy: &ReviewerPolicy) -> ReviewValue {
        ReviewValue {
            status: Some("pass".to_string()),
            complete: true,
            verdict: Some(json!("confirmed")),
            gaps: vec![],
        }
    }
}

#[test]
fn adjudicate_subjects_with_reviewer_end_to_end() {
    let subjects = vec![Subject { id: json!(1), evidence: vec![json!("e1")] }];
    let policy = AdjudicationPolicy {
        mode: "auto".to_string(),
        producer: json!("legion"),
        reviewer: json!("sage"),
        context_prefix: None,
        budget: json!(10),
        used_contexts: vec![],
    };
    let (result, packets) =
        adjudicate_subjects_with_reviewer(&subjects, &policy, &json!("sage"), None, &FakeReviewer)
            .unwrap();
    assert!(result.complete);
    assert_eq!(packets.len(), 1);
    let prepared = prepare_adjudication(&subjects, &policy).unwrap();
    assert_eq!(prepared.len(), 1);
}

// ---- execute-plan.mjs: executePlan orchestration ----

struct Pass;
impl ProviderExecutor for Pass {
    fn execute(&self, provider: &PlannedProvider, _plan: &ExecutionPlan) -> Result<ProviderOutcome, String> {
        Ok(ProviderOutcome::ProviderResult {
            family: provider.family.clone(),
            value: json!({"status": "pass", "complete": true}),
        })
    }
}

struct FixedClock;
impl HostClock for FixedClock {
    fn now_ms(&self) -> i64 {
        1_700_000_000_000
    }
}

fn planned_provider(id: &str) -> PlannedProvider {
    PlannedProvider {
        id: id.to_string(),
        dependencies: vec![],
        resources: BTreeMap::new(),
        concurrency_key: None,
        denominator_digest: None,
        reserved_spend_micros: 0.0,
        family: "seo".to_string(),
        runner_module: None,
        runner_kind: None,
        provider_version: "1".to_string(),
        runner_module_digest: None,
    }
}

#[test]
fn execute_plan_end_to_end_produces_one_receipt_per_provider() {
    let plan = ExecutionPlan {
        root: Some("/repo".to_string()),
        binding: Some(json!({"rev": "abc"})),
        providers: vec![planned_provider("p1"), planned_provider("p2")],
        schedule_mode: ScheduleMode::Auto,
        max_concurrency: 4,
        resource_ceilings: None,
        limits: RunLimits::default(),
        plan_denominator_digest: None,
    };
    let result = execute_plan(&plan, &Pass, &FixedClock, None);
    assert_eq!(result.receipts.len(), 2);
    assert_eq!(result.runtime_state, "RUNNING");
}

#[test]
fn skipped_receipt_end_to_end() {
    let receipt = skipped_receipt(&planned_provider("p1"), "manual");
    assert_eq!(receipt["spawnStatus"], json!("blocked"));
}

// ---- build-plan.mjs: buildSealedPlan ----

struct OkStage(&'static str, &'static str);
impl PlanStage for OkStage {
    fn id(&self) -> &str {
        self.0
    }
    fn required_for(&self) -> &str {
        self.1
    }
    fn run(&self, _options: &PlanOptions, _artifacts: &BTreeMap<String, serde_json::Value>) -> StageResult {
        StageResult { complete: true, status: "pass".to_string(), artifact: Some(json!({"ok": true})), detail: None }
    }
}

#[test]
fn build_sealed_plan_end_to_end() {
    let stage = OkStage("repository-binding", "inventory");
    let stages: Vec<&dyn PlanStage> = vec![&stage];
    let options = PlanOptions { root: Some("/repo".to_string()), ..Default::default() };
    let plan = build_sealed_plan(&options, &stages, "2024-01-01T00:00:00.000Z").unwrap();
    assert_eq!(plan.kind, "legion-sealed-plan");
    assert!(plan.complete_for_requested_claim);
    assert!(!plan.plan_digest.is_empty());
}

// ---- index.mjs: writeRunManifest ----

#[test]
fn build_run_manifest_end_to_end() {
    let binding = json!({"sourceRevision": "rev1"});
    let records = vec![ArtifactRecord {
        kind: "audit-report".to_string(),
        path: "report.json".to_string(),
        digest: "sha256:aa".to_string(),
        bytes: 4,
        producer: "legion.core".to_string(),
        schema_version: 1,
        media_type: "application/json".to_string(),
        binding: None,
        status: None,
    }];
    let manifest = build_run_manifest(&records, Some(&binding));
    assert_eq!(manifest.kind, "legion-run-manifest");
    assert_eq!(manifest.source_revision, Some(json!("rev1")));
    assert!(manifest.terminal_absences.is_empty());
    assert!(!manifest.digest.is_empty());
}
