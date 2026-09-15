//! Bounded fake-host coverage for the native reasoning cutover.
//!
//! These tests never invoke a model or network.  The fixture host signs the
//! same receipt fields as the trusted host adapter, so tampering and replay
//! exercise the real audit verification boundary.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use hmac::{Hmac, KeyInit, Mac};
use legion_audit::native_providers::reasoning::{
    ReasoningHost, ReasoningHostError, ReasoningHostResponse, ReasoningInvocation,
    ReasoningProviderExecutor, ReasoningReceipt, REASONING_MAC_DOMAIN, REASONING_PROVIDER_IDS,
    REASONING_RECEIPT_BOUND_FIELDS,
};
use legion_audit::{AuditPlan, InventoryEntry, InventoryEnvelope, ProviderExecutor};
use legion_contracts::{
    canonical_digest, canonical_json_bytes, Coverage, ProviderId, ProviderResult, ProviderSpec,
    ProviderStatus,
};
use serde_json::{json, Value};
use sha2::Sha256;

const KEY: &[u8] = b"native-reasoning-fixture-trusted-key";

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

fn spec(id: &str) -> ProviderSpec {
    ProviderSpec {
        schema_version: 2,
        id: ProviderId::new(id).unwrap(),
        provider_version: "1.0.0".into(),
        family: "fixture".into(),
        lens_ids: vec!["fixture-lens".into()],
        role: "adjudicator".into(),
        phase: "judgment".into(),
        depends_on: Vec::new(),
        consumes: vec!["blueprint-packet".into()],
        produces: vec!["provider-result".into()],
        selector: json!({"op":"always"}),
        denominator_kind: "first-party-source-files".into(),
        runner: json!({"kind":"reasoning-contract","contract":"fixture-reasoning-v1"}),
        host_capabilities: Vec::new(),
        execution: json!({"required":true}),
        reasoning: json!({"requirement":"review","freshContext":true,"producerSeparation":true}),
        benchmark: json!({"status":"qualified","requiredForCleanClaim":false}),
        clean_claim: "evidence-only".into(),
        control_ids: Vec::new(),
        scopes: Vec::new(),
        selectable: true,
    }
}

fn plan(id: &str) -> (legion_audit::FrozenPlan, InventoryEnvelope) {
    let inventory = inventory();
    let plan = AuditPlan::compile(&inventory, &[spec(id)])
        .unwrap()
        .freeze(Some(KEY))
        .unwrap();
    (plan, inventory)
}

fn result(request: &ReasoningInvocation) -> ProviderResult {
    ProviderResult {
        schema_version: 1,
        provider: ProviderId::new(&request.provider_id).unwrap(),
        applicable: true,
        required: true,
        status: ProviderStatus::Complete,
        complete: true,
        coverage: Some(Coverage {
            denominator_digest: request.denominator_digest.clone(),
            expected: request.denominator_count,
            examined: request.denominator_count,
            gaps: Vec::new(),
        }),
        findings: Vec::new(),
        coverage_gaps: Vec::new(),
        degradation: Vec::new(),
        details: BTreeMap::new(),
    }
}

fn signed_receipt(request: &ReasoningInvocation, result: &ProviderResult) -> ReasoningReceipt {
    let mut receipt = ReasoningReceipt {
        schema_version: 1,
        kind: "legion-reasoning-receipt".into(),
        receipt_id: "receipt:fixture-reasoning".into(),
        request_id: request.request_id.clone(),
        provider_id: request.provider_id.clone(),
        contract: request.contract.clone(),
        plan_digest: request.plan_digest.clone(),
        plan_signature: request.plan_signature.clone(),
        repository_id: request.repository_id.clone(),
        inventory_generation: request.inventory_generation.clone(),
        inventory_digest: request.inventory_digest.clone(),
        denominator_digest: request.denominator_digest.clone(),
        denominator_count: request.denominator_count,
        result_digest: canonical_digest(result).unwrap(),
        status: result.status,
        complete: result.complete,
        gaps: result.coverage_gaps.clone(),
        authentication: Value::Null,
    };
    let value = serde_json::to_value(&receipt).unwrap();
    let object = value.as_object().unwrap();
    let mut subject = serde_json::Map::new();
    for field in REASONING_RECEIPT_BOUND_FIELDS {
        subject.insert(field.into(), object[field].clone());
    }
    let message = json!({
        "alg":"HMAC-SHA256",
        "boundFields":REASONING_RECEIPT_BOUND_FIELDS,
        "macDomain":REASONING_MAC_DOMAIN,
        "subject":subject,
    });
    let mut mac = Hmac::<Sha256>::new_from_slice(KEY).unwrap();
    mac.update(&canonical_json_bytes(&message).unwrap());
    receipt.authentication = json!({
        "alg":"HMAC-SHA256",
        "keyId":"fixture-key",
        "mac":hex::encode(mac.finalize().into_bytes()),
        "macDomain":REASONING_MAC_DOMAIN,
        "boundFieldsDigest":canonical_digest(&REASONING_RECEIPT_BOUND_FIELDS.to_vec()).unwrap(),
    });
    receipt
}

struct FixtureHost {
    calls: AtomicUsize,
    tamper: bool,
}

impl ReasoningHost for FixtureHost {
    fn invoke(
        &self,
        request: &ReasoningInvocation,
    ) -> Result<ReasoningHostResponse, ReasoningHostError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let result = result(request);
        let mut receipt = signed_receipt(request, &result);
        if self.tamper {
            receipt.result_digest = "sha256:tampered".into();
        }
        Ok(ReasoningHostResponse { result, receipt })
    }
}

#[test]
fn every_frozen_reasoning_provider_is_present() {
    assert_eq!(REASONING_PROVIDER_IDS.len(), 17);
    let unique = REASONING_PROVIDER_IDS
        .iter()
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(unique.len(), 17);
}

#[test]
fn signed_host_result_is_bound_and_reaches_report_execution() {
    let (plan, inventory) = plan("reasoning.architecture");
    let host = Arc::new(FixtureHost {
        calls: AtomicUsize::new(0),
        tamper: false,
    });
    let executor = ReasoningProviderExecutor::new(".", host.clone(), KEY.to_vec());
    let report = legion_audit::execute(&plan, &inventory, &executor).unwrap();
    assert_eq!(host.calls.load(Ordering::SeqCst), 1);
    assert!(report.gaps.is_empty(), "{:?}", report.gaps);
    assert!(report.results[0].result.complete);
    assert!(report.results[0]
        .result
        .details
        .contains_key("executionReceipt"));
    let rendered = legion_audit::canonical_report("fixture-repository", &report).unwrap();
    assert_eq!(rendered.status, legion_contracts::ReportStatus::Clean);
    assert_eq!(report.lenses_ran, vec!["fixture-lens"]);
}

#[test]
fn receipt_tampering_is_rejected_and_cannot_complete_provider() {
    let (plan, inventory) = plan("reasoning.architecture");
    let host = Arc::new(FixtureHost {
        calls: AtomicUsize::new(0),
        tamper: true,
    });
    let executor = ReasoningProviderExecutor::new(".", host, KEY.to_vec());
    let report = legion_audit::execute(&plan, &inventory, &executor).unwrap();
    assert!(!report.results[0].result.complete);
    assert!(report
        .gaps
        .iter()
        .any(|gap| gap.contains("reasoning receipt rejected")));
}

#[test]
fn replay_and_missing_host_are_typed_incomplete_results() {
    let (plan, inventory) = plan("reasoning.architecture");
    let host = Arc::new(FixtureHost {
        calls: AtomicUsize::new(0),
        tamper: false,
    });
    let executor = ReasoningProviderExecutor::new(".", host.clone(), KEY.to_vec());
    let first = executor
        .execute_bound(&plan, &plan.providers()[0], &inventory)
        .unwrap();
    assert!(first.complete);
    let replay = executor
        .execute_bound(&plan, &plan.providers()[0], &inventory)
        .unwrap();
    assert!(!replay.complete);
    assert!(replay
        .coverage_gaps
        .iter()
        .any(|gap| gap == "reasoning-replay-detected"));
    assert_eq!(host.calls.load(Ordering::SeqCst), 1);

    let missing = ReasoningProviderExecutor::unavailable(".");
    let result = missing
        .execute_bound(&plan, &plan.providers()[0], &inventory)
        .unwrap();
    assert!(!result.complete);
    assert!(result
        .coverage_gaps
        .iter()
        .any(|gap| gap == "reasoning-host-unavailable"));
}

#[test]
fn every_reasoning_id_executes_through_the_shared_native_registry() {
    let inventory = inventory();
    let specs = REASONING_PROVIDER_IDS.iter().map(|id| spec(id)).collect::<Vec<_>>();
    let plan = AuditPlan::compile(&inventory, &specs).unwrap().freeze(Some(KEY)).unwrap();
    let host = Arc::new(FixtureHost { calls: AtomicUsize::new(0), tamper: false });
    let executor = legion_audit::NativeProviderRegistry::new(".")
        .with_reasoning(ReasoningProviderExecutor::new(".", host.clone(), KEY.to_vec()));
    let report = legion_audit::execute(&plan, &inventory, &executor).unwrap();
    assert_eq!(host.calls.load(Ordering::SeqCst), 17);
    assert_eq!(report.results.len(), 17);
    assert!(report.gaps.is_empty(), "{:?}", report.gaps);
    assert!(report.results.iter().all(|entry| entry.result.complete));
}

#[test]
fn missing_trust_key_prevents_the_host_call() {
    let (plan, inventory) = plan("reasoning.architecture");
    let host = Arc::new(FixtureHost { calls: AtomicUsize::new(0), tamper: false });
    let executor = ReasoningProviderExecutor::new(".", host.clone(), Vec::new());
    let report = legion_audit::execute(&plan, &inventory, &executor).unwrap();
    assert_eq!(host.calls.load(Ordering::SeqCst), 0);
    assert!(!report.results[0].result.complete);
    assert!(report.gaps.iter().any(|gap| gap.contains("verification key is unavailable")));
}

struct CachedHost(std::sync::Mutex<Option<ReasoningHostResponse>>);

impl ReasoningHost for CachedHost {
    fn invoke(&self, request: &ReasoningInvocation) -> Result<ReasoningHostResponse, ReasoningHostError> {
        let mut cached = self.0.lock().unwrap();
        if let Some(response) = cached.as_ref() { return Ok(response.clone()); }
        let result = result(request);
        let response = ReasoningHostResponse { receipt: signed_receipt(request, &result), result };
        *cached = Some(response.clone());
        Ok(response)
    }
}

#[test]
fn a_new_executor_rejects_a_previously_signed_review_receipt() {
    let (plan, inventory) = plan("reasoning.architecture");
    let host = Arc::new(CachedHost(std::sync::Mutex::new(None)));
    let first = ReasoningProviderExecutor::new(".", host.clone(), KEY.to_vec());
    let first_report = legion_audit::execute(&plan, &inventory, &first).unwrap();
    assert!(first_report.results[0].result.complete);
    let second = ReasoningProviderExecutor::new(".", host, KEY.to_vec());
    let second_report = legion_audit::execute(&plan, &inventory, &second).unwrap();
    assert!(!second_report.results[0].result.complete);
    assert!(second_report.gaps.iter().any(|gap| gap.contains("reasoning receipt rejected")));
}

struct UnauthenticatedExecutor(AtomicUsize);

impl ProviderExecutor for UnauthenticatedExecutor {
    fn execute(&self, _: &legion_audit::AuditProvider, _: &InventoryEnvelope) -> Result<ProviderResult, legion_audit::AuditError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        panic!("unbound host-service path must not be invoked");
    }
}

#[test]
fn generic_executors_cannot_bypass_reasoning_authentication() {
    let (plan, inventory) = plan("reasoning.architecture");
    let executor = UnauthenticatedExecutor(AtomicUsize::new(0));
    let report = legion_audit::execute(&plan, &inventory, &executor).unwrap();
    assert_eq!(executor.0.load(Ordering::SeqCst), 0);
    assert!(!report.results[0].result.complete);
    assert!(report.gaps.iter().any(|gap| gap.contains("authenticated plan-bound executor")));
}
