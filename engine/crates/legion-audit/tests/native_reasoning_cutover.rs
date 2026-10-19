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
    delivery_chunk_manifest, required_packet_gaps, ReasoningHost, ReasoningHostError,
    ReasoningHostResponse, ReasoningInvocation, ReasoningProviderExecutor, ReasoningReceipt,
    REASONING_MAC_DOMAIN, REASONING_PROVIDER_IDS, REASONING_RECEIPT_BOUND_FIELDS,
};
use legion_audit::{AuditPlan, InventoryEntry, InventoryEnvelope, ProviderExecutor};
use legion_contracts::{
    canonical_digest, canonical_json_bytes, Coverage, ProviderId, ProviderResult, ProviderSpec,
    ProviderStatus,
};
use serde_json::{json, Value};
use sha2::Sha256;

mod common;

fn fixture_root() -> &'static std::path::Path {
    static ROOT: std::sync::OnceLock<std::path::PathBuf> = std::sync::OnceLock::new();
    ROOT.get_or_init(|| {
        let root =
            std::env::temp_dir().join(format!("legion-reasoning-cutover-{}", std::process::id()));
        std::fs::create_dir_all(root.join("src")).unwrap();
        std::fs::write(
            root.join("src/lib.rs"),
            "fixture source\n// cfg(target_os and Command::new( trigger fixtures\n",
        )
        .unwrap();
        std::fs::create_dir_all(root.join("migrations")).unwrap();
        std::fs::create_dir_all(root.join(".github/workflows")).unwrap();
        std::fs::write(root.join("src/ui.tsx"), "<button>fixture</button>\n").unwrap();
        std::fs::write(
            root.join("migrations/001.sql"),
            "CREATE TABLE fixture(id INTEGER);\n",
        )
        .unwrap();
        std::fs::write(
            root.join(".github/workflows/release.yml"),
            "publish: false\n",
        )
        .unwrap();
        root
    })
    .as_path()
}

const KEY: &[u8] = b"native-reasoning-fixture-trusted-key";

fn inventory() -> InventoryEnvelope {
    InventoryEnvelope::new(
        "fixture-repository",
        "fixture-generation",
        [
            "src/lib.rs",
            "src/ui.tsx",
            "migrations/001.sql",
            ".github/workflows/release.yml",
        ]
        .into_iter()
        .map(|path| InventoryEntry {
            path: path.into(),
            symbols: Vec::new(),
            dependencies: Vec::new(),
            package_scripts: Vec::new(),
            source_file: true,
            digest: None,
        })
        .collect(),
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
        consumes: vec!["repository-inventory".into()],
        produces: vec!["provider-result".into()],
        selector: json!({"op":"always"}),
        denominator_kind: "first-party-source-files".into(),
        runner: json!({"kind":"reasoning-contract","contract":"fixture-reasoning-v1"}),
        host_capabilities: Vec::new(),
        execution: json!({"required":true}),
        reasoning: json!({
            "requirement":"review","freshContext":true,"producerSeparation":true,
            "reviewContext": review_context()
        }),
        benchmark: json!({"status":"qualified","requiredForCleanClaim":false}),
        clean_claim: "evidence-only".into(),
        control_ids: Vec::new(),
        scopes: Vec::new(),
        selectable: true,
    }
}

fn review_context() -> Value {
    json!({
        "mode": "diff", "type": "all",
        "rawRefs": {"base": "main", "baseCommit": null, "dir": null},
        "changedPaths": ["src/lib.rs"],
        "baseline": {"kind": "merge-base", "status": "resolved", "head": "abc123", "commit": "def456", "mergeBase": "def456"}
    })
}

fn plan(id: &str) -> (legion_audit::FrozenPlan, InventoryEnvelope) {
    let inventory = inventory();
    let plan = AuditPlan::compile_with_root(Some(fixture_root()), &inventory, &[spec(id)])
        .unwrap()
        .freeze(Some(KEY))
        .unwrap();
    (plan, inventory)
}

fn result(request: &ReasoningInvocation) -> ProviderResult {
    let mut details = BTreeMap::new();
    details.insert("deliveryEvidence".into(), json!({
        "schemaVersion": 1, "kind": "legion-evidence-delivery", "source": "host-transport",
        "receiptId": format!("fixture-delivery:{}", request.request_id),
        "requestId": request.request_id, "packetDigest": canonical_digest(&request.packet).unwrap(),
        "deliveredPacketBytes": canonical_json_bytes(&request.packet).unwrap().len(),
        "complete": true, "truncated": false, "chunks": delivery_chunk_manifest(request).unwrap()
    }));
    let author_result = json!({"schemaVersion":1,"kind":"legion-lens-result","provider":request.provider_id,
        "packetDigest":canonical_digest(&request.packet).unwrap(),"planDigest":request.plan_digest,
        "complete":true,"findings":[],"withdrawn":[],"details":{"fixtureSimulation":true}});
    let negative_review = common::negative_review(request, &author_result, fixture_root());
    let verification_gap = (negative_review["verdict"] == "unresolved").then(|| {
        format!(
            "verification-negative-unresolved:{}:{}",
            request.provider_id,
            negative_review["reason"].as_str().unwrap(),
        )
    });
    details.insert("verificationEvidence".into(), json!({
        "schemaVersion": 1, "kind": "legion-runtime-verification", "requestId": request.request_id,
        "packetDigest": canonical_digest(&request.packet).unwrap(), "findings": [],
        "negativeReview":negative_review
    }));
    match request.provider_id.as_str() {
        "reasoning.architecture" => {
            details.insert(
                "changeRisk".into(),
                json!({
                    "reversibility": "unknown",
                    "blastRadius": "whole repository",
                    "reason": "fixture has no diff context",
                    "beforeEvidence": [],
                    "afterEvidence": []
                }),
            );
        }
        "reasoning.correctness" => {
            details.insert(
                "semanticReview".into(),
                json!({
                    "axis": "spec", "status": "pass", "reason": "fixture source reviewed",
                    "sources": [{"location": "src/lib.rs:1", "quote": "fixture source"}]
                }),
            );
        }
        "reasoning.ai-slop" => {
            details.insert(
                "semanticReview".into(),
                json!({
                    "axis": "standards", "status": "pass", "reason": "fixture source reviewed",
                    "sources": [{"location": "src/lib.rs:1", "quote": "fixture source"}]
                }),
            );
        }
        _ => {}
    }
    let mut gaps = required_packet_gaps(request);
    // Empty packet scopes cannot support even a simulated scoped-clean review.
    // Preserve the helper's real unresolved disposition in the signed result.
    gaps.extend(verification_gap);
    let complete = gaps.is_empty();
    ProviderResult {
        schema_version: 1,
        provider: ProviderId::new(&request.provider_id).unwrap(),
        applicable: true,
        required: true,
        status: if complete {
            ProviderStatus::Complete
        } else {
            ProviderStatus::Partial
        },
        complete,
        coverage: Some(Coverage {
            denominator_digest: request.denominator_digest.clone(),
            expected: request.denominator_count,
            examined: request.denominator_count,
            gaps: gaps.clone(),
        }),
        findings: Vec::new(),
        coverage_gaps: gaps,
        degradation: Vec::new(),
        details,
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

struct OrphanDetailFindingHost;

impl ReasoningHost for OrphanDetailFindingHost {
    fn invoke(
        &self,
        request: &ReasoningInvocation,
    ) -> Result<ReasoningHostResponse, ReasoningHostError> {
        let mut result = result(request);
        result.details.insert(
            "lensFindings".into(),
            json!([{
                "id": "orphan",
                "lens": "architecture",
                "severity": "medium",
                "confidence": "likely",
                "evidence": ["src/lib.rs:1"],
                "failureScenario": "architecture finding",
                "action": "review boundary",
                "verifyStatus": "unverified"
            }]),
        );
        let receipt = signed_receipt(request, &result);
        Ok(ReasoningHostResponse { result, receipt })
    }
}

impl ReasoningHost for FixtureHost {
    fn invoke(
        &self,
        request: &ReasoningInvocation,
    ) -> Result<ReasoningHostResponse, ReasoningHostError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        assert_eq!(request.packet.get("reviewContext"), Some(&review_context()));
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
    let executor = ReasoningProviderExecutor::new(fixture_root(), host.clone(), KEY.to_vec());
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
fn diff_review_cannot_claim_whole_repo_non_applicability() {
    struct NonApplicableHost;
    impl ReasoningHost for NonApplicableHost {
        fn invoke(
            &self,
            request: &ReasoningInvocation,
        ) -> Result<ReasoningHostResponse, ReasoningHostError> {
            let mut result = result(request);
            result.details.insert(
                "semanticReview".into(),
                json!({
                    "axis":"spec", "status":"not-applicable",
                    "reason":"No supplied specification", "sources":[]
                }),
            );
            Ok(ReasoningHostResponse {
                receipt: signed_receipt(request, &result),
                result,
            })
        }
    }
    let inventory = inventory();
    let mut provider = spec("reasoning.correctness");
    provider.reasoning["reviewContext"]["mode"] = json!("diff");
    let plan = AuditPlan::compile_with_root(Some(fixture_root()), &inventory, &[provider])
        .unwrap()
        .freeze(Some(KEY))
        .unwrap();
    let executor =
        ReasoningProviderExecutor::new(fixture_root(), Arc::new(NonApplicableHost), KEY.to_vec());
    let report = legion_audit::execute(&plan, &inventory, &executor).unwrap();
    assert!(!report.results[0].result.complete);
    assert!(report
        .gaps
        .iter()
        .any(|gap| gap.contains("frozen whole-repo context")));
}

#[test]
fn receipt_tampering_is_rejected_and_cannot_complete_provider() {
    let (plan, inventory) = plan("reasoning.architecture");
    let host = Arc::new(FixtureHost {
        calls: AtomicUsize::new(0),
        tamper: true,
    });
    let executor = ReasoningProviderExecutor::new(fixture_root(), host, KEY.to_vec());
    let report = legion_audit::execute(&plan, &inventory, &executor).unwrap();
    assert!(!report.results[0].result.complete);
    assert!(report
        .gaps
        .iter()
        .any(|gap| gap.contains("reasoning receipt rejected")));
}

#[test]
fn detail_finding_without_top_level_projection_is_rejected() {
    let (plan, inventory) = plan("reasoning.architecture");
    let executor = ReasoningProviderExecutor::new(
        fixture_root(),
        Arc::new(OrphanDetailFindingHost),
        KEY.to_vec(),
    );
    let report = legion_audit::execute(&plan, &inventory, &executor).unwrap();
    assert!(!report.results[0].result.complete);
    assert!(report
        .gaps
        .iter()
        .any(|gap| gap.contains("absent from top-level findings")));
}

#[test]
fn replay_and_missing_host_are_typed_incomplete_results() {
    let (plan, inventory) = plan("reasoning.architecture");
    let host = Arc::new(FixtureHost {
        calls: AtomicUsize::new(0),
        tamper: false,
    });
    let executor = ReasoningProviderExecutor::new(fixture_root(), host.clone(), KEY.to_vec());
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

    let missing = ReasoningProviderExecutor::unavailable(fixture_root());
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
    let specs = REASONING_PROVIDER_IDS
        .iter()
        .map(|id| spec(id))
        .collect::<Vec<_>>();
    let plan = AuditPlan::compile_with_root(Some(fixture_root()), &inventory, &specs)
        .unwrap()
        .freeze(Some(KEY))
        .unwrap();
    let host = Arc::new(FixtureHost {
        calls: AtomicUsize::new(0),
        tamper: false,
    });
    let executor = legion_audit::NativeProviderRegistry::new(fixture_root()).with_reasoning(
        ReasoningProviderExecutor::new(fixture_root(), host.clone(), KEY.to_vec()),
    );
    let report = legion_audit::execute(&plan, &inventory, &executor).unwrap();
    assert_eq!(host.calls.load(Ordering::SeqCst), 17);
    assert_eq!(report.results.len(), 17);
    assert!(
        report
            .gaps
            .iter()
            .any(|gap| gap.contains("scanner-candidates-unavailable")),
        "{:?}",
        report.gaps
    );
    assert!(
        report
            .gaps
            .iter()
            .all(|gap| !gap.contains("reasoning receipt rejected")),
        "{:?}",
        report.gaps
    );
    for entry in &report.results {
        let review = &entry.result.details["verificationEvidence"]["negativeReview"];
        assert!(
            matches!(
                review["verdict"].as_str(),
                Some("scoped_clean" | "unresolved")
            ),
            "{}: {review}",
            entry.provider
        );
        assert_eq!(
            entry.result.complete,
            entry.provider.as_str() != "legacy.security.adjudication"
                && review["verdict"] == "scoped_clean",
            "{}: {:?}",
            entry.provider,
            entry.result.coverage_gaps
        );
        if review["verdict"] == "unresolved" {
            assert!(
                entry.result.coverage_gaps.iter().any(|gap| gap
                    == &format!(
                        "verification-negative-unresolved:{}:{}",
                        entry.provider,
                        review["reason"].as_str().unwrap(),
                    )),
                "{}: {:?}",
                entry.provider,
                entry.result.coverage_gaps
            );
        }
    }
}

#[test]
fn missing_trust_key_prevents_the_host_call() {
    let (plan, inventory) = plan("reasoning.architecture");
    let host = Arc::new(FixtureHost {
        calls: AtomicUsize::new(0),
        tamper: false,
    });
    let executor = ReasoningProviderExecutor::new(fixture_root(), host.clone(), Vec::new());
    let report = legion_audit::execute(&plan, &inventory, &executor).unwrap();
    assert_eq!(host.calls.load(Ordering::SeqCst), 0);
    assert!(!report.results[0].result.complete);
    assert!(report
        .gaps
        .iter()
        .any(|gap| gap.contains("verification key is unavailable")));
}

struct CachedHost(std::sync::Mutex<Option<ReasoningHostResponse>>);

impl ReasoningHost for CachedHost {
    fn invoke(
        &self,
        request: &ReasoningInvocation,
    ) -> Result<ReasoningHostResponse, ReasoningHostError> {
        let mut cached = self.0.lock().unwrap();
        if let Some(response) = cached.as_ref() {
            return Ok(response.clone());
        }
        let result = result(request);
        let response = ReasoningHostResponse {
            receipt: signed_receipt(request, &result),
            result,
        };
        *cached = Some(response.clone());
        Ok(response)
    }
}

#[test]
fn a_new_executor_rejects_a_previously_signed_review_receipt() {
    let (plan, inventory) = plan("reasoning.architecture");
    let host = Arc::new(CachedHost(std::sync::Mutex::new(None)));
    let first = ReasoningProviderExecutor::new(fixture_root(), host.clone(), KEY.to_vec());
    let first_report = legion_audit::execute(&plan, &inventory, &first).unwrap();
    assert!(first_report.results[0].result.complete);
    let second = ReasoningProviderExecutor::new(fixture_root(), host, KEY.to_vec());
    let second_report = legion_audit::execute(&plan, &inventory, &second).unwrap();
    assert!(!second_report.results[0].result.complete);
    assert!(second_report
        .gaps
        .iter()
        .any(|gap| gap.contains("reasoning receipt rejected")));
}

struct UnauthenticatedExecutor(AtomicUsize);

impl ProviderExecutor for UnauthenticatedExecutor {
    fn execute(
        &self,
        _: &legion_audit::AuditProvider,
        _: &InventoryEnvelope,
    ) -> Result<ProviderResult, legion_audit::AuditError> {
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
    assert!(report
        .gaps
        .iter()
        .any(|gap| gap.contains("authenticated plan-bound executor")));
}

#[test]
fn signed_author_result_cannot_complete_without_independent_verification() {
    struct AuthorOnlyHost;
    impl ReasoningHost for AuthorOnlyHost {
        fn invoke(
            &self,
            request: &ReasoningInvocation,
        ) -> Result<ReasoningHostResponse, ReasoningHostError> {
            let mut result = result(request);
            result.details.remove("verificationEvidence");
            let receipt = signed_receipt(request, &result);
            Ok(ReasoningHostResponse { result, receipt })
        }
    }
    let (plan, inventory) = plan("reasoning.architecture");
    let executor =
        ReasoningProviderExecutor::new(fixture_root(), Arc::new(AuthorOnlyHost), KEY.to_vec());
    let report = legion_audit::execute(&plan, &inventory, &executor).unwrap();
    assert!(!report.results[0].result.complete);
    assert!(
        report
            .gaps
            .iter()
            .any(|gap| gap.contains("independent verification")),
        "{:?}",
        report.gaps
    );
}
