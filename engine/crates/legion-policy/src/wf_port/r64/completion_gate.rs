//! Port of `src/lib/verification/arcane/completion-gate.mjs`
//! (`evaluateCompletion`) — CONTRACT B item 4, the completion gate.
//!
//! A completing agent (Alchemist, Legion) may claim a level of done-ness
//! (signoff / highRisk / release). This module is the seam that prevents
//! that claim from being self-certifying: it resolves which claim levels a
//! set of touched paths force (via `PolicyEngine::locked_domains_for`),
//! unions those with the level actually claimed, and evaluates every
//! resulting level's prerequisites through
//! `PolicyEngine::evaluate_claim_prerequisites` — reused directly from
//! `crate::wf_port::wf007::policy`, which is Arcane's single ported
//! claim-release authority.
//!
//! `evidenceClasses`, `staleEvidenceCount`, and `enforcementHealth` are
//! derived from `receipt_store.list({runId})` exactly as in the JS source
//! (never from caller-asserted fields) via [`derive_from_receipts`], which
//! reproduces `deriveFromReceipts`/`healthOfRecord` byte-for-byte,
//! including the weakest-link enforcement-health rule.
//!
//! GAP: the JS imports `findCurrentAdvisoryCertification` from
//! `advisory-certification.mjs` (158 lines, not one of this packet's seven
//! files, no Rust port anywhere in `engine/`). It is taken as an injected
//! `AdvisoryCertifier` trait, same pattern as packet Q4's
//! `completion_evidence` treating its own unported collaborators as
//! traits. `loadCompletionEvidence` and `consumeCurrentUserRiskAcceptance`/
//! `verifyCurrentUserRiskAcceptance` are reused directly from
//! `crate::wf_port::q_q4::completion_evidence` and
//! `crate::wf_port::r64::current_user_risk_acceptance` respectively — both
//! now real ports, not stubs.

use serde_json::{json, Value};

use crate::wf_port::q_q4::completion_evidence::{
    load_completion_evidence, AuthorityProofIssuer, Execution as EvidenceExecution, ReceiptStore as EvidenceReceiptStore,
    RecordVerifier,
};
use crate::wf_port::wf007::policy::{ClaimContext, PolicyEngine};

use super::current_user_risk_acceptance::{
    consume_current_user_risk_acceptance, ExpectedAcceptance, LedgerStore as RiskLedgerStore,
    RecordAuthenticator as RiskAuthenticator, ReceiptStore as RiskReceiptStore,
};
use super::decision::{decision, Decision};

/// Mirrors JS `healthOfRecord(record)`.
fn health_of_record(record: &Value) -> &'static str {
    let auth = record.get("authentication");
    let auth = match auth {
        Some(a) if !a.is_null() => a,
        _ => return "unsupported",
    };
    match auth.get("verificationMethod").and_then(Value::as_str) {
        Some("capability-signature") => {
            if auth.get("perMessage") == Some(&Value::Bool(true)) {
                "strong"
            } else {
                "observed"
            }
        }
        Some("host-connection-trust") => "read_only",
        _ => "unsupported",
    }
}

fn rank(level: &str) -> u8 {
    crate::wf_port::wf007::policy::ENFORCEMENT_RANK
        .iter()
        .find(|(name, _)| *name == level)
        .map(|(_, r)| *r)
        .unwrap_or(0)
}

pub struct DerivedEvidence {
    pub evidence_classes: Vec<String>,
    pub stale_evidence_count: i64,
    pub enforcement_health: &'static str,
}

/// Mirrors JS `deriveFromReceipts(records)`.
pub fn derive_from_receipts(records: &[Value]) -> DerivedEvidence {
    let mut evidence_classes: Vec<String> = Vec::new();
    let mut stale_evidence_count = 0i64;
    let mut weakest: Option<&'static str> = None;

    for record in records {
        if let Some(class) = record.get("evidenceClass").and_then(Value::as_str) {
            if !evidence_classes.iter().any(|c| c == class) {
                evidence_classes.push(class.to_string());
            }
            if record.get("stale") == Some(&Value::Bool(true)) {
                stale_evidence_count += 1;
            }
        }
        let health = health_of_record(record);
        weakest = match weakest {
            None => Some(health),
            Some(w) if rank(health) < rank(w) => Some(health),
            other => other,
        };
    }

    DerivedEvidence {
        evidence_classes,
        stale_evidence_count,
        enforcement_health: weakest.unwrap_or("unsupported"),
    }
}

/// Injected in place of `findCurrentAdvisoryCertification`
/// (`src/lib/verification/arcane/advisory-certification.mjs`).
pub trait AdvisoryCertifier {
    fn find_current(&self, run_id: &str, task_id: Option<&str>, expected: &Value, freshness_ms: f64) -> Decision;
}

/// Injected in place of `budgetStore.inspect({...})`.
pub trait BudgetStore {
    fn inspect(&self, contract_id: &str, version: i64, task_id: &str, run_id: &str) -> BudgetInspection;
}

#[derive(Debug, Clone)]
pub struct BudgetInspection {
    pub allowed: bool,
    pub stopped: bool,
    pub code: Option<&'static str>,
}

pub struct CompletionRequest<'a> {
    pub run_id: &'a str,
    pub task_id: Option<&'a str>,
    pub claimed_level: Option<&'a str>,
    pub touched_paths: &'a [&'a str],
    pub contract_id: Option<&'a str>,
    pub contract_version: Option<i64>,
    pub contract_digest: Option<&'a str>,
    pub source_revision: Option<&'a str>,
    pub completion_claim: Option<&'a Value>,
}

#[derive(Default)]
pub struct CompletionDeps<'a> {
    pub budget_store: Option<&'a dyn BudgetStore>,
    pub key_ring_present: bool,
    pub current_proof_present: bool,
    pub execution: Option<&'a EvidenceExecution>,
    pub authority_proof_issuer: Option<&'a dyn AuthorityProofIssuer>,
    pub record_verifier: Option<&'a dyn RecordVerifier>,
    pub integrated_state: Option<&'a Value>,
    pub latest_material_change: Option<&'a Value>,
    pub require_acceptance_evidence: bool,
    pub now_ms: i64,
    pub now_iso: &'a str,
    pub advisory_certifier: Option<&'a dyn AdvisoryCertifier>,
    pub risk_ledger: Option<&'a dyn RiskLedgerStore>,
    pub risk_receipts: Option<&'a dyn RiskReceiptStore>,
    pub risk_authenticator: Option<&'a dyn RiskAuthenticator>,
}

fn evidence_receipt_store<'a>(records: &'a [Value]) -> impl EvidenceReceiptStore + 'a {
    struct Store<'a>(&'a [Value]);
    impl<'a> EvidenceReceiptStore for Store<'a> {
        fn list(&self, _run_id: &Value) -> Vec<Value> {
            self.0.to_vec()
        }
    }
    Store(records)
}

/// Mirrors JS `evaluateCompletion({...}, {...})`.
pub fn evaluate_completion(req: &CompletionRequest, deps: &CompletionDeps, policy: &PolicyEngine, all_receipts: &[Value]) -> Decision {
    // Budget state comes only from Arcane's persisted projection.
    if let (Some(store), Some(contract_id), Some(version), Some(task_id)) =
        (deps.budget_store, req.contract_id, req.contract_version, req.task_id)
    {
        let budget = store.inspect(contract_id, version, task_id, req.run_id);
        if !budget.allowed || budget.stopped {
            return decision(
                false,
                Some(budget.code.unwrap_or("BUDGET_STOP")),
                "completion requires a non-stopped budget projection",
                json!({"runId": req.run_id, "taskId": task_id}),
            );
        }
    }

    let locked_matches = policy.locked_domains_for(req.touched_paths);
    let mut levels: Vec<String> = Vec::new();
    if let Some(claimed) = req.claimed_level {
        levels.push(claimed.to_string());
    }
    for (_, _, claim_level, _) in &locked_matches {
        if !levels.contains(claim_level) {
            levels.push(claim_level.clone());
        }
    }

    let derived = derive_from_receipts(all_receipts);

    if deps.require_acceptance_evidence {
        let trusted_execution = deps.execution.filter(|e| {
            e.run_id == json!(req.run_id)
                && req.task_id.map(|t| e.task_id == json!(t)).unwrap_or(e.task_id.is_null())
                && req.contract_id.map(|c| e.contract_id == json!(c)).unwrap_or(e.contract_id.is_null())
                && req.contract_version.map(|v| e.contract_version == json!(v)).unwrap_or(e.contract_version.is_null())
                && req.contract_digest.map(|d| e.contract_digest == json!(d)).unwrap_or(e.contract_digest.is_null())
                && req.source_revision.map(|s| e.source_revision == json!(s)).unwrap_or(e.source_revision.is_null())
        });
        let acceptance = match (trusted_execution, deps.key_ring_present, deps.authority_proof_issuer, deps.record_verifier) {
            (Some(execution), true, Some(issuer), Some(verifier)) => {
                let store = evidence_receipt_store(all_receipts);
                let integrated_state = deps.integrated_state.cloned().unwrap_or(Value::Null);
                let latest_material_change = deps.latest_material_change.cloned().unwrap_or(Value::Null);
                let evidence = load_completion_evidence(
                    &store,
                    true,
                    Some(issuer),
                    verifier,
                    execution,
                    &integrated_state,
                    &latest_material_change,
                );
                verify_required_acceptance_evidence(&evidence.evidence_registry, &evidence.acceptance_proofs)
            }
            _ => decision(
                false,
                Some("ARC_EVIDENCE_INSUFFICIENT"),
                "completion requires authenticated execution-bound Oracle evidence",
                json!({"missingEvidence": ["trusted-completion-evidence"]}),
            ),
        };
        if !acceptance.allowed {
            return acceptance;
        }
    }

    let material_risk_expected = req.completion_claim.and_then(|c| c.get("riskDigest")).map(|_| {
        let c = req.completion_claim.unwrap();
        ExpectedAcceptance {
            risk_id: c.get("riskId").and_then(Value::as_str).unwrap_or("").to_string(),
            risk_digest: c.get("riskDigest").and_then(Value::as_str).unwrap_or("").to_string(),
            acceptance_ledger_fingerprint: c.get("acceptanceLedgerFingerprint").and_then(Value::as_str).unwrap_or("").to_string(),
            integrated_state_identity: c.get("integratedStateIdentity").and_then(Value::as_str).unwrap_or("").to_string(),
            source_set_digest: c.get("sourceSetDigest").and_then(Value::as_str).unwrap_or("").to_string(),
            user_prompt_event_digest: c.get("userPromptEventDigest").and_then(Value::as_str).unwrap_or("").to_string(),
            challenge_token: c.get("challengeToken").and_then(Value::as_str).unwrap_or("").to_string(),
        }
    });

    if let Some(expected) = &material_risk_expected {
        if let (Some(ledger), Some(receipts), Some(authenticator)) = (deps.risk_ledger, deps.risk_receipts, deps.risk_authenticator) {
            let acceptance = super::current_user_risk_acceptance::verify_current_user_risk_acceptance(
                expected, ledger, receipts, authenticator, deps.now_ms,
            );
            if !acceptance.allowed {
                return acceptance;
            }
        }
    }

    let mut advisory_certification_detail: Option<Value> = None;
    if let Some(claim) = req.completion_claim {
        if claim.get("advisoryClaim").and_then(|a| a.get("required")) == Some(&Value::Bool(true)) {
            let advisory_claim = claim.get("advisoryClaim").unwrap();
            let expected = json!({
                "artifactDigest": advisory_claim.get("artifactDigest"),
                "briefDigest": advisory_claim.get("briefDigest"),
                "bundleId": advisory_claim.get("bundleId"),
                "bundleVersion": advisory_claim.get("bundleVersion"),
                "profileId": advisory_claim.get("profileId"),
                "manifestDigest": advisory_claim.get("manifestDigest"),
                "profileDigest": advisory_claim.get("profileDigest"),
                "runId": req.run_id,
                "taskId": req.task_id,
                "contractId": req.contract_id,
                "contractVersion": req.contract_version,
                "contractDigest": req.contract_digest,
                "sourceRevision": req.source_revision,
            });
            let freshness_ms = policy
                .evidence_policy()
                .get("freshnessSeconds")
                .and_then(|s| s.parse::<f64>().ok())
                .unwrap_or(0.0)
                * 1000.0;
            let cert = match deps.advisory_certifier {
                Some(certifier) => certifier.find_current(req.run_id, req.task_id, &expected, freshness_ms),
                None => decision(false, Some("ARC_EVIDENCE_INSUFFICIENT"), "advisory certifier is unavailable", json!({})),
            };
            if !cert.allowed {
                let mut detail = cert.detail.clone();
                if let Some(obj) = detail.as_object_mut() {
                    obj.insert("missingEvidence".into(), json!(["independent-advisory-certification"]));
                }
                return decision(false, cert.code, cert.message, detail);
            }
            advisory_certification_detail = Some(cert.detail);
        }
    }

    let mut levels_checked: Vec<String> = Vec::new();
    let evidence_classes_refs: Vec<&str> = derived.evidence_classes.iter().map(String::as_str).collect();
    let fields: Vec<&str> = req
        .completion_claim
        .and_then(|c| c.get("highRiskContext"))
        .and_then(Value::as_object)
        .map(|m| m.keys().map(String::as_str).collect())
        .unwrap_or_default();
    for level_name in &levels {
        let ctx = ClaimContext {
            evidence_classes: &evidence_classes_refs,
            stale_evidence_count: derived.stale_evidence_count,
            enforcement_health: derived.enforcement_health,
            fields: &fields,
            waived_by: None,
        };
        let result = policy.evaluate_claim_prerequisites(level_name, &ctx);
        levels_checked.push(level_name.clone());
        if !result.allowed {
            return decision(
                false,
                result.code,
                result.message,
                json!({
                    "level": level_name,
                    "runId": req.run_id,
                    "taskId": req.task_id,
                }),
            );
        }
    }

    if let Some(expected) = &material_risk_expected {
        if let (Some(ledger), Some(receipts), Some(authenticator)) = (deps.risk_ledger, deps.risk_receipts, deps.risk_authenticator) {
            let consumed = consume_current_user_risk_acceptance(expected, ledger, receipts, authenticator, deps.now_ms, deps.now_iso);
            if !consumed.allowed {
                return consumed;
            }
        }
    }

    decision(
        true,
        None,
        "completion claim satisfies every prerequisite the touched paths and claimed level require",
        json!({
            "runId": req.run_id,
            "taskId": req.task_id,
            "claimedLevel": req.claimed_level,
            "levelsChecked": levels_checked,
            "evidenceClasses": derived.evidence_classes,
            "staleEvidenceCount": derived.stale_evidence_count,
            "advisoryCertification": advisory_certification_detail,
        }),
    )
}

/// Mirrors JS `verifyRequiredAcceptanceEvidence({...})`, applied to the
/// value structs `load_completion_evidence` returns (this port's stand-in
/// for `AcceptanceEvidenceRegistry`, per packet Q4's own documented gap).
fn verify_required_acceptance_evidence(
    entries: &[crate::wf_port::q_q4::completion_evidence::RegisteredEvidence],
    proofs: &[crate::wf_port::q_q4::completion_evidence::AcceptanceProof],
) -> Decision {
    if entries.is_empty() {
        return decision(
            false,
            Some("ARC_EVIDENCE_INSUFFICIENT"),
            "completion requires registered acceptance evidence",
            json!({"missingEvidence": ["acceptance-proof"]}),
        );
    }
    if proofs.is_empty() {
        let missing: Vec<Value> = entries.iter().map(|e| e.acceptance_id.clone()).collect();
        return decision(false, Some("ARC_EVIDENCE_INSUFFICIENT"), "completion requires fresh acceptance proofs", json!({"missingEvidence": missing}));
    }
    let required: Vec<Value> = entries.iter().map(|e| e.acceptance_id.clone()).collect();
    let mut seen: Vec<Value> = Vec::new();
    for p in proofs {
        if seen.contains(&p.acceptance_id) {
            return decision(
                false,
                Some("ARC_BINDING_MISMATCH"),
                "completion acceptance proofs must contain one proof per acceptance id",
                json!({"acceptanceId": p.acceptance_id}),
            );
        }
        seen.push(p.acceptance_id.clone());
    }
    let missing: Vec<&Value> = required.iter().filter(|id| !seen.contains(id)).collect();
    let unexpected: Vec<&Value> = seen.iter().filter(|id| !required.contains(id)).collect();
    if !missing.is_empty() || !unexpected.is_empty() {
        return decision(
            false,
            Some("ARC_EVIDENCE_INSUFFICIENT"),
            "completion proofs must exactly cover registered acceptance evidence",
            json!({"missing": missing, "unexpected": unexpected}),
        );
    }
    decision(true, None, "registered acceptance evidence is fresh for exact integrated state", json!({"acceptanceIds": required}))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wf_port::wf007::policy::{ClaimLevel, PolicyBundle};
    use std::collections::BTreeMap;

    fn empty_bundle() -> PolicyBundle {
        let mut claim_levels = BTreeMap::new();
        claim_levels.insert(
            "signoff".to_string(),
            ClaimLevel {
                required_evidence_classes: vec![],
                required_enforcement: "advisory".to_string(),
                required_fields: vec![],
                allow_stale_evidence: true,
            },
        );
        PolicyBundle {
            policy_id: "p".into(),
            version: 1,
            digest: "sha256:0".into(),
            claim_levels,
            ..Default::default()
        }
    }

    #[test]
    fn no_claimed_level_and_no_locked_domains_passes_trivially() {
        let bundle = empty_bundle();
        let policy = PolicyEngine::new(bundle);
        let req = CompletionRequest {
            run_id: "run-1",
            task_id: None,
            claimed_level: None,
            touched_paths: &[],
            contract_id: None,
            contract_version: None,
            contract_digest: None,
            source_revision: None,
            completion_claim: None,
        };
        let deps = CompletionDeps::default();
        let result = evaluate_completion(&req, &deps, &policy, &[]);
        assert!(result.allowed);
    }

    #[test]
    fn claimed_level_with_satisfied_prerequisites_passes() {
        let bundle = empty_bundle();
        let policy = PolicyEngine::new(bundle);
        let req = CompletionRequest {
            run_id: "run-1",
            task_id: Some("task-1"),
            claimed_level: Some("signoff"),
            touched_paths: &[],
            contract_id: None,
            contract_version: None,
            contract_digest: None,
            source_revision: None,
            completion_claim: None,
        };
        let deps = CompletionDeps::default();
        let result = evaluate_completion(&req, &deps, &policy, &[]);
        assert!(result.allowed);
    }

    #[test]
    fn unknown_claimed_level_fails() {
        let bundle = empty_bundle();
        let policy = PolicyEngine::new(bundle);
        let req = CompletionRequest {
            run_id: "run-1",
            task_id: None,
            claimed_level: Some("nonexistent"),
            touched_paths: &[],
            contract_id: None,
            contract_version: None,
            contract_digest: None,
            source_revision: None,
            completion_claim: None,
        };
        let deps = CompletionDeps::default();
        let result = evaluate_completion(&req, &deps, &policy, &[]);
        assert!(!result.allowed);
        assert_eq!(result.code, Some("ARC_CLAIM_PREREQUISITE_UNMET"));
    }

    #[test]
    fn derive_from_receipts_takes_weakest_health() {
        let records = vec![
            json!({"evidenceClass": "a", "authentication": {"verificationMethod": "capability-signature", "perMessage": true}}),
            json!({"evidenceClass": "b", "authentication": {"verificationMethod": "host-connection-trust"}}),
        ];
        let derived = derive_from_receipts(&records);
        assert_eq!(derived.enforcement_health, "read_only");
        assert_eq!(derived.evidence_classes.len(), 2);
    }

    #[test]
    fn no_records_is_unsupported() {
        let derived = derive_from_receipts(&[]);
        assert_eq!(derived.enforcement_health, "unsupported");
    }
}
