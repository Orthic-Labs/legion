//! Full Rust port of
//! `src/lib/verification/arcane/s11-bindings/evidence-closure.mjs`.
//!
//! The JS module's `SUPPORTED` table (6 ids) each drives a real production
//! verifier: `architecture-state.mjs`, `evidence-registry.mjs`,
//! `provider-capability.mjs`, `seal-reachability.mjs`, and
//! `gate-validity.mjs`. Every one of those now has a faithful Rust port
//! elsewhere in this crate (wf070's `state`/`canon`, wf072's
//! `evidence_registry`/`gate_validity`, wf075's `seal_reachability`, which
//! itself carries a faithful port of `provider-capability.mjs`'s
//! `verifyExternalProviderCapability`), so the 6 `SUPPORTED` cases are
//! wired to those real verifiers here rather than left blocked.
//!
//! The `UNSUPPORTED` table (12 ids) calls no dependency at all in the JS
//! source — it is a fixed id -> missing-capability-string map returned
//! verbatim as PENDING — and is ported here unchanged.

use crate::wf_port::wf070::canon::{digest_value as architecture_digest_value, CanonVal};
use crate::wf_port::wf070::state::{apply_architecture_event, create_architecture_state, validate_architecture_state};
use crate::wf_port::wf072::evidence_registry::{
    AcceptanceEntry, AcceptanceEvidenceRegistry, Artifact, FreshnessContext, Lifecycle,
};
use crate::wf_port::wf072::gate_validity::{
    execute_validated_gate, validate_gate, ExecResult, ExecResultStatus, Fixture, GateContract,
};
use crate::wf_port::wf072::support::{ArcCode, Json as SupportJson};
use crate::wf_port::wf075::seal_reachability::{
    compile_seal_reachability, verify_external_provider_capability, ProviderCapability, RecoveryPath,
    SealRequirement,
};

/// `NOW = new Date('2026-08-14T00:00:00.000Z')` in the JS source.
const NOW_ISO: &str = "2026-08-14T00:00:00.000Z";
/// Epoch millis for the same fixed instants the JS module's
/// `AE-EVIDENCE-FRESHNESS-001` case hardcodes.
const OBSERVED_AT_2026_08_13_MILLIS: i64 = 1_786_579_200_000;
const NOW_2026_08_14_MILLIS: i64 = 1_786_665_600_000;
const VALID_UNTIL_2026_08_15_MILLIS: i64 = 1_786_752_000_000;

pub const SUPPORTED_IDS: &[&str] = &[
    "AE-EVIDENCE-ARTIFACTS-001",
    "AE-EVIDENCE-ARTIFACTS-002",
    "AE-EVIDENCE-FRESHNESS-001",
    "AE-GATE-VALIDITY-001",
    "AE-GATE-VALIDITY-002",
    "AE-SEAL-REACHABILITY-001",
];

fn unsupported_capability(id: &str) -> Option<&'static str> {
    match id {
        "AE-EVIDENCE-001" => Some("authority-backed candidate constraint/admission evaluator"),
        "AE-EVIDENCE-002" => Some("authority-backed preference-versus-constraint classifier"),
        "AE-EVIDENCE-003" => {
            Some("candidate comparison engine with pre-score hard-gate elimination")
        }
        "AE-EVIDENCE-ARTIFACTS-003" => {
            Some("catalog capability registry with adapter-backed gateability state")
        }
        "AE-EVIDENCE-FRESHNESS-002" => {
            Some("waiver lifecycle store that exposes REFRESH_REQUIRED while retaining visible waiver state")
        }
        "AE-FINDING-LIFECYCLE-001" => {
            Some("finding store keyed by stable fingerprint with review-round identity")
        }
        "AE-FINDING-LIFECYCLE-002" => {
            Some("independent finding-closure verifier that rejects fix-author certification")
        }
        "AE-FINDING-LIFECYCLE-003" => {
            Some("scoped recheck consumer that closes blockers & defers unrelated findings")
        }
        "AE-DEFICIT-PROPAGATION-001" => {
            Some("acceptance deficit classifier & completion claim-ceiling consumer")
        }
        "AE-DEFICIT-PROPAGATION-002" => Some("required correctness/safety debt-conversion guard"),
        "AE-DEFICIT-PROPAGATION-003" => {
            Some("dispatch admission consumer for canonical downstream deficit acknowledgement")
        }
        "AE-OUTCOME-CLOSURE-001" => {
            Some("outcome state machine with acceptance-surface observation status")
        }
        _ => None,
    }
}

/// Sorted union of `SUPPORTED` + `UNSUPPORTED` ids, mirroring
/// `evidenceClosureRuntimePolicyIds`.
pub fn evidence_closure_runtime_policy_ids() -> Vec<&'static str> {
    let mut ids: Vec<&'static str> = SUPPORTED_IDS.to_vec();
    ids.extend([
        "AE-EVIDENCE-001",
        "AE-EVIDENCE-002",
        "AE-EVIDENCE-003",
        "AE-EVIDENCE-ARTIFACTS-003",
        "AE-EVIDENCE-FRESHNESS-002",
        "AE-FINDING-LIFECYCLE-001",
        "AE-FINDING-LIFECYCLE-002",
        "AE-FINDING-LIFECYCLE-003",
        "AE-DEFICIT-PROPAGATION-001",
        "AE-DEFICIT-PROPAGATION-002",
        "AE-DEFICIT-PROPAGATION-003",
        "AE-OUTCOME-CLOSURE-001",
    ]);
    ids.sort_unstable();
    ids
}

#[derive(Debug, Clone, PartialEq)]
pub enum EvidenceClosureResult {
    /// Mirrors a `SUPPORTED[row.id]()` call that returned successfully:
    /// `{ id, family: None, status: 'PASS', accepted: true,
    /// integratedStateIdentity }`.
    Accepted {
        id: &'static str,
        integrated_state_identity: String,
    },
    /// Mirrors the `catch` branch: `{ id, status: 'FAIL', reason:
    /// "production binding failed: ${error.message}" }`.
    Failed { id: &'static str, reason: String },
    Pending {
        id: &'static str,
        reason: String,
        missing_capability: &'static str,
    },
    /// Mirrors the JS fallback: an id with no `SUPPORTED`/`UNSUPPORTED`
    /// entry still gets a PENDING result (`'no evidence-closure binding is
    /// registered'`), not an execution error.
    NoBindingRegistered { id: String },
}

pub fn execute_evidence_closure_runtime_case(id: &str) -> EvidenceClosureResult {
    if let Some(&sid) = SUPPORTED_IDS.iter().find(|&&i| i == id) {
        return match run_supported_case(sid) {
            Ok(integrated_state_identity) => EvidenceClosureResult::Accepted { id: sid, integrated_state_identity },
            Err(reason) => EvidenceClosureResult::Failed {
                id: sid,
                reason: format!("production binding failed: {reason}"),
            },
        };
    }
    if let Some(capability) = unsupported_capability(id) {
        let sid = evidence_closure_runtime_policy_ids()
            .into_iter()
            .find(|&i| i == id)
            .unwrap();
        return EvidenceClosureResult::Pending {
            id: sid,
            reason: format!("missing production capability: {}", capability),
            missing_capability: capability,
        };
    }
    EvidenceClosureResult::NoBindingRegistered { id: id.to_string() }
}

/// Mirrors `observedState(caseId, eventType, payload)`: builds a fresh
/// architecture state, applies the one event the binding describes, and
/// returns the resulting `state_fingerprint` — or the error message if the
/// production observation is rejected. Mirrors `accepted()`'s
/// `integratedStateIdentity` value.
fn observed_state(case_id: &str, event_type: &str, payload: CanonVal) -> Result<String, String> {
    let acceptance_ledger = CanonVal::obj()
        .set("schema", CanonVal::Str("acceptance-ledger.v1".to_string()))
        .set("ledger_version", CanonVal::Int(1))
        .set("intent_epoch", CanonVal::Int(1))
        .set(
            "acceptance_fingerprint",
            CanonVal::Str(architecture_digest_value(&CanonVal::Str(case_id.to_string()))),
        )
        .set("frozen_at", CanonVal::Str(NOW_ISO.to_string()))
        .set("items", CanonVal::Arr(vec![]));

    let state = create_architecture_state(
        &format!("s11:{case_id}"),
        acceptance_ledger,
        "s11-production-binding",
    )
    .map_err(|e| e.0)?;

    let observed = apply_architecture_event(&state, event_type, &payload).map_err(|e| e.0)?;
    let (valid, _issues) = validate_architecture_state(&observed);
    if !valid {
        return Err("architecture-state rejected production observation".to_string());
    }
    observed
        .get("state_fingerprint")
        .and_then(CanonVal::as_str)
        .map(str::to_string)
        .ok_or_else(|| "architecture-state rejected production observation".to_string())
}

fn run_supported_case(id: &str) -> Result<String, String> {
    match id {
        "AE-EVIDENCE-ARTIFACTS-001" => case_evidence_artifacts_001(),
        "AE-EVIDENCE-ARTIFACTS-002" => case_evidence_artifacts_002(),
        "AE-EVIDENCE-FRESHNESS-001" => case_evidence_freshness_001(),
        "AE-GATE-VALIDITY-001" => case_gate_validity_001(),
        "AE-GATE-VALIDITY-002" => case_gate_validity_002(),
        "AE-SEAL-REACHABILITY-001" => case_seal_reachability_001(),
        other => unreachable!("run_supported_case called for unsupported id {other}"),
    }
}

fn case_evidence_artifacts_001() -> Result<String, String> {
    let capability = ProviderCapability {
        provider_id: Some("dashboard".to_string()),
        machine_readable: false,
        ..Default::default()
    };
    let result = verify_external_provider_capability(Some(&capability), "dashboard");
    if result.code != Some("ARC_UNSOUND_SEAL") {
        return Err("dashboard-only provider was admitted as closure evidence".to_string());
    }
    let payload = CanonVal::obj()
        .set("id", CanonVal::Str("dashboard".to_string()))
        .set("admission", CanonVal::Str("INFORMATIONAL_ONLY".to_string()))
        .set("verifierCode", CanonVal::Str(result.code.unwrap_or_default().to_string()));
    observed_state("AE-EVIDENCE-ARTIFACTS-001", "ARTIFACT_ENVELOPE_RECORDED", payload)
}

fn case_evidence_artifacts_002() -> Result<String, String> {
    let capability = ProviderCapability {
        provider_id: Some("sensitive-trace".to_string()),
        machine_readable: true,
        gateable: true,
        downloadable: true,
        trusted_retrieval: true,
        trajectory_bindable: true,
        sensitivity: Some("sensitive".to_string()),
        retention: None,
        deletion_owner: None,
    };
    let result = verify_external_provider_capability(Some(&capability), "sensitive-trace");
    // Mirrors `missingFields(capability, REQUIRED)` over the trailing
    // `retention`/`deletionOwner` fields of the JS `REQUIRED` list, in that
    // order — both are null here, so both are "missing".
    let mut missing: Vec<CanonVal> = Vec::new();
    if capability.retention.is_none() {
        missing.push(CanonVal::Str("retention".to_string()));
    }
    if capability.deletion_owner.is_none() {
        missing.push(CanonVal::Str("deletionOwner".to_string()));
    }
    let has_deletion_owner_missing = missing
        .iter()
        .any(|v| v.as_str() == Some("deletionOwner"));
    if result.code != Some("ARC_UNSOUND_SEAL") || !has_deletion_owner_missing {
        return Err("trace without deletion owner was admitted".to_string());
    }
    let payload = CanonVal::obj()
        .set("id", CanonVal::Str("sensitive-trace".to_string()))
        .set("admission", CanonVal::Str("DENIED".to_string()))
        .set("verifierCode", CanonVal::Str(result.code.unwrap_or_default().to_string()))
        .set("missing", CanonVal::Arr(missing));
    observed_state("AE-EVIDENCE-ARTIFACTS-002", "ARTIFACT_ENVELOPE_RECORDED", payload)
}

fn case_evidence_freshness_001() -> Result<String, String> {
    let mut registry = AcceptanceEvidenceRegistry::new();
    let entry = AcceptanceEntry {
        acceptance_id: "AC-freshness".to_string(),
        claim_type: "acceptance-surface".to_string(),
        producer: "oracle".to_string(),
        durable_store: "receipt-store".to_string(),
        verifier: "arcane".to_string(),
        completion_consumer: "legion".to_string(),
        integrated_state_binding: "exact".to_string(),
        validity_policy: "latest-material-change".to_string(),
        lifecycle: Lifecycle::Current,
    };
    let registered = registry.register(entry);
    if !registered.allowed {
        return Err(registered.message);
    }

    let integrated_state = Some("before-change".to_string());
    let artifact = Artifact {
        authenticated: true,
        integrated_state: integrated_state.clone(),
        observed_at_millis: Some(OBSERVED_AT_2026_08_13_MILLIS),
        valid_until_millis: Some(VALID_UNTIL_2026_08_15_MILLIS),
        acceptance_id: "AC-freshness".to_string(),
        producer: "oracle".to_string(),
        verifier: "arcane".to_string(),
        completion_consumer: "legion".to_string(),
    };
    let ctx = FreshnessContext {
        integrated_state,
        latest_material_change_millis: Some(NOW_2026_08_14_MILLIS),
        now_millis: NOW_2026_08_14_MILLIS,
    };
    let check = registry.verify("AC-freshness", &artifact, &ctx);
    let status_is_stale = check.detail.get("status").map(String::as_str) == Some("STALE");
    if check.code != Some(ArcCode::ArcEvidenceStale) || !status_is_stale {
        return Err("materially stale proof was accepted".to_string());
    }
    let payload = CanonVal::obj()
        .set("id", CanonVal::Str("AC-freshness".to_string()))
        .set("lifecycle", CanonVal::Str("STALE".to_string()))
        .set("completion", CanonVal::Str("CANDIDATE".to_string()))
        .set(
            "verifierCode",
            CanonVal::Str(check.code.map(|c| c.as_str().to_string()).unwrap_or_default()),
        );
    observed_state("AE-EVIDENCE-FRESHNESS-001", "EVIDENCE_LIFECYCLE_RECORDED", payload)
}

fn s11_gate_contract() -> GateContract {
    GateContract {
        id: "s11-evidence-closure-gate".to_string(),
        inspected_scope: "src/**".to_string(),
        discovery_breadth: "bounded".to_string(),
        blocking_filter: "known".to_string(),
        threshold: "1".to_string(),
        gates: true,
        authority: "oracle".to_string(),
        failure_semantics: "deny".to_string(),
        payload: SupportJson::Obj(vec![("id".to_string(), SupportJson::str("s11-evidence-closure-gate"))]),
    }
}

fn gate_fixture(id: &str) -> Fixture {
    Fixture { id: id.to_string(), payload: SupportJson::str(id) }
}

fn case_gate_validity_001() -> Result<String, String> {
    let contract = s11_gate_contract();
    let fixtures: Vec<(&'static str, Option<(Fixture, ExecResult)>)> = vec![
        ("knownGood", Some((gate_fixture("good"), ExecResult { status: ExecResultStatus::Pass }))),
        ("knownBad", Some((gate_fixture("bad"), ExecResult { status: ExecResultStatus::Fail }))),
        ("empty", Some((gate_fixture("empty"), ExecResult { status: ExecResultStatus::Fail }))),
        ("malformed", Some((gate_fixture("malformed"), ExecResult { status: ExecResultStatus::Fail }))),
    ];
    let validity = validate_gate(&contract, &fixtures).map_err(|e| e.message)?;
    let result = execute_validated_gate(&contract, Some(&validity), &[], &[]);
    let is_inconclusive = result.detail.get("gateStatus").map(String::as_str) == Some("INCONCLUSIVE");
    if result.code != Some(ArcCode::ArcEvidenceInsufficient) || !is_inconclusive {
        return Err("zero-item blocking gate passed".to_string());
    }
    let status = result.detail.get("gateStatus").cloned().unwrap_or_default();
    let verifier_code = result.code.map(|c| c.as_str().to_string()).unwrap_or_default();
    let payload = CanonVal::obj()
        .set("id", CanonVal::Str(contract.id.clone()))
        .set("status", CanonVal::Str(status))
        .set("verifierCode", CanonVal::Str(verifier_code));
    observed_state("AE-GATE-VALIDITY-001", "TERMINAL_STATE_RECORDED", payload)
}

fn case_gate_validity_002() -> Result<String, String> {
    let contract = s11_gate_contract();
    let fixtures: Vec<(&'static str, Option<(Fixture, ExecResult)>)> = vec![
        ("knownGood", Some((gate_fixture("good"), ExecResult { status: ExecResultStatus::Pass }))),
        ("knownBad", None),
        ("empty", None),
        ("malformed", None),
    ];
    let err = match validate_gate(&contract, &fixtures) {
        Ok(_) => return Err("incomplete gate self-test remained enabled".to_string()),
        Err(e) => e,
    };
    let machinery_defect = err.detail.get("machineryDefect").cloned().unwrap_or_default();
    if err.code != Some(ArcCode::ArcGateInvalid) || machinery_defect != "OUT_OF_SCOPE_MACHINERY_DEFECT" {
        return Err("incomplete gate self-test remained enabled".to_string());
    }
    let payload = CanonVal::obj()
        .set("id", CanonVal::Str("s11-evidence-closure-gate".to_string()))
        .set("status", CanonVal::Str("BLOCKING_DISABLED".to_string()))
        .set("machineryDefect", CanonVal::Str(machinery_defect))
        .set(
            "verifierCode",
            CanonVal::Str(err.code.map(|c| c.as_str().to_string()).unwrap_or_default()),
        );
    observed_state("AE-GATE-VALIDITY-002", "TERMINAL_STATE_RECORDED", payload)
}

fn case_seal_reachability_001() -> Result<String, String> {
    let requirement = SealRequirement {
        id: Some("required-schema".to_string()),
        producer: Some("oracle".to_string()),
        durable_store: true,
        authenticated_persistence: true,
        verifier: Some("arcane".to_string()),
        completion_consumer: Some("legion".to_string()),
        close_path: true,
        fixture_only: true,
        ..Default::default()
    };
    let recovery_path = RecoveryPath {
        requirement_id: "required-schema".to_string(),
        authenticated: true,
        close_path: true,
    };
    let result = compile_seal_reachability(&[requirement], &[], &[recovery_path]);
    if result.code != Some("ARC_UNSOUND_SEAL") {
        return Err("fixture-only evidence reached a seal".to_string());
    }
    let payload = CanonVal::obj()
        .set("id", CanonVal::Str("required-schema".to_string()))
        .set("status", CanonVal::Str("UNSOUND_SEAL".to_string()))
        .set("verifierCode", CanonVal::Str(result.code.unwrap_or_default().to_string()));
    observed_state("AE-SEAL-REACHABILITY-001", "EVIDENCE_LIFECYCLE_RECORDED", payload)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    #[test]
    fn every_supported_id_is_accepted_with_a_real_state_fingerprint() {
        for id in SUPPORTED_IDS {
            match execute_evidence_closure_runtime_case(id) {
                EvidenceClosureResult::Accepted { integrated_state_identity, .. } => {
                    assert!(!integrated_state_identity.is_empty());
                }
                other => panic!("{id}: expected Accepted, got {other:?}"),
            }
        }
    }

    #[test]
    fn every_unsupported_id_is_pending_with_its_capability_string() {
        let unsupported = [
            "AE-EVIDENCE-001",
            "AE-EVIDENCE-002",
            "AE-EVIDENCE-003",
            "AE-EVIDENCE-ARTIFACTS-003",
            "AE-EVIDENCE-FRESHNESS-002",
            "AE-FINDING-LIFECYCLE-001",
            "AE-FINDING-LIFECYCLE-002",
            "AE-FINDING-LIFECYCLE-003",
            "AE-DEFICIT-PROPAGATION-001",
            "AE-DEFICIT-PROPAGATION-002",
            "AE-DEFICIT-PROPAGATION-003",
            "AE-OUTCOME-CLOSURE-001",
        ];
        assert_eq!(unsupported.len(), 12);
        for id in unsupported {
            match execute_evidence_closure_runtime_case(id) {
                EvidenceClosureResult::Pending { reason, missing_capability, .. } => {
                    assert!(reason.starts_with("missing production capability: "));
                    assert!(reason.ends_with(missing_capability));
                }
                other => panic!("{id}: unexpected {other:?}"),
            }
        }
    }

    #[test]
    fn deficit_propagation_002_names_debt_conversion_guard() {
        match execute_evidence_closure_runtime_case("AE-DEFICIT-PROPAGATION-002") {
            EvidenceClosureResult::Pending { missing_capability, .. } => {
                assert_eq!(
                    missing_capability,
                    "required correctness/safety debt-conversion guard"
                );
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn unrecognized_id_has_no_binding_registered() {
        assert!(matches!(
            execute_evidence_closure_runtime_case("AE-NOT-A-REAL-CASE"),
            EvidenceClosureResult::NoBindingRegistered { .. }
        ));
    }

    #[test]
    fn runtime_policy_ids_has_eighteen_sorted_entries() {
        let ids = evidence_closure_runtime_policy_ids();
        assert_eq!(ids.len(), 18);
        let mut sorted = ids.clone();
        sorted.sort_unstable();
        assert_eq!(ids, sorted);
    }

    #[test]
    fn evidence_artifacts_001_is_informational_only_dashboard_admission() {
        let identity = case_evidence_artifacts_001().expect("case should be accepted");
        assert!(!identity.is_empty());
    }

    #[test]
    fn evidence_artifacts_002_reports_missing_deletion_owner() {
        let identity = case_evidence_artifacts_002().expect("case should be accepted");
        assert!(!identity.is_empty());
    }

    #[test]
    fn evidence_freshness_001_flags_stale_before_change_proof() {
        let identity = case_evidence_freshness_001().expect("case should be accepted");
        assert!(!identity.is_empty());
    }

    #[test]
    fn gate_validity_001_is_inconclusive_on_zero_inspected_items() {
        let identity = case_gate_validity_001().expect("case should be accepted");
        assert!(!identity.is_empty());
    }

    #[test]
    fn gate_validity_002_disables_blocking_on_incomplete_self_test() {
        let identity = case_gate_validity_002().expect("case should be accepted");
        assert!(!identity.is_empty());
    }

    #[test]
    fn seal_reachability_001_rejects_fixture_only_evidence() {
        let identity = case_seal_reachability_001().expect("case should be accepted");
        assert!(!identity.is_empty());
    }

    #[test]
    fn accepted_cases_produce_distinct_state_fingerprints() {
        let mut seen: BTreeMap<&str, String> = BTreeMap::new();
        for id in SUPPORTED_IDS {
            if let EvidenceClosureResult::Accepted { integrated_state_identity, .. } =
                execute_evidence_closure_runtime_case(id)
            {
                for (other_id, other_fp) in &seen {
                    assert_ne!(
                        &integrated_state_identity, other_fp,
                        "{id} and {other_id} produced the same state fingerprint"
                    );
                }
                seen.insert(id, integrated_state_identity);
            }
        }
    }
}
