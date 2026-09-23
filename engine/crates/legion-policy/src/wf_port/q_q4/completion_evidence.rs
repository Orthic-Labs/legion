//! Port of `src/lib/verification/arcane/completion-evidence.mjs`
//! (`loadCompletionEvidence`).
//!
//! Completion evidence is read, never caller-supplied: only authenticated
//! Oracle evidence receipts already persisted by Arcane can satisfy a
//! sealed contract's acceptance criteria.
//!
//! GAP: the original imports `AcceptanceEvidenceRegistry` from
//! `./evidence-registry.mjs` and `EVIDENCE_RECEIPT_BOUND_FIELDS`/
//! `verifyRecord` from `../../guard/compat/audit/receipt-auth.mjs`; neither
//! has a Rust port in this workspace yet. This port keeps the exact
//! decision logic (field-by-field criterion matching, exact-JSON
//! `integratedState` comparison, authority-proof + receipt-authentication
//! double check) but takes the collaborators as injected trait objects
//! (`ReceiptStore`, `AuthorityProofIssuer`, `RecordVerifier`) instead of
//! hard-wiring to those unported modules, and returns
//! [`AcceptanceProof`]/[`RegisteredEvidence`] value structs in place of
//! `AcceptanceEvidenceRegistry`'s mutable-registration API (whose own
//! shape is unported). A caller wiring this to the real registry once it
//! lands should fold `RegisteredEvidence` into
//! `AcceptanceEvidenceRegistry::register` calls one-for-one — the field
//! names below match the JS call site exactly.

use serde_json::Value;

/// Mirrors the `criterion` shape read from `execution.acceptanceCriteria`:
/// only `.id` is read by `loadCompletionEvidence`.
#[derive(Clone, Debug)]
pub struct AcceptanceCriterion {
    pub id: Value,
}

/// Mirrors the `execution` argument's fields actually read.
#[derive(Clone, Debug)]
pub struct Execution {
    pub run_id: Value,
    pub task_id: Value,
    pub contract_id: Value,
    pub contract_version: Value,
    pub contract_digest: Value,
    pub source_revision: Value,
    pub acceptance_criteria: Vec<AcceptanceCriterion>,
}

/// A persisted evidence-capability receipt, as read from `receiptStore.list`.
/// Kept as a raw JSON object (mirroring the JS's untyped `record`) since the
/// receipt schema itself lives outside this port's scope.
pub type Receipt = Value;

/// Injected in place of `receiptStore.list({ runId })`.
pub trait ReceiptStore {
    fn list(&self, run_id: &Value) -> Vec<Receipt>;
}

/// Result of `authorityProofIssuer.verify(authority, { expected })`.
pub struct AuthorityVerifyResult {
    pub allowed: bool,
}

/// Injected in place of `authorityProofIssuer.findByDigest` /
/// `authorityProofIssuer.verify`.
pub trait AuthorityProofIssuer {
    fn find_by_digest(&self, digest: &Value) -> Option<Value>;
    fn verify(&self, authority: &Value, expected: &Value) -> AuthorityVerifyResult;
}

/// Result of `verifyRecord(record, record.authentication, { keyRing,
/// boundFields, expectedBinding })`.
pub struct RecordVerifyResult {
    pub allowed: bool,
}

/// Injected in place of the imported `verifyRecord` (bound to a `keyRing`
/// and `EVIDENCE_RECEIPT_BOUND_FIELDS`, both opaque here).
pub trait RecordVerifier {
    fn verify_record(&self, record: &Value, expected_binding: &Value) -> RecordVerifyResult;
}

/// Mirrors one `registry.register({...})` call's arguments — a stand-in for
/// `AcceptanceEvidenceRegistry`'s (unported) mutation API.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RegisteredEvidence {
    pub acceptance_id: Value,
    pub claim_type: &'static str,
    pub producer: &'static str,
    pub durable_store: &'static str,
    pub verifier: &'static str,
    pub completion_consumer: &'static str,
    pub integrated_state_binding: &'static str,
    pub validity_policy: &'static str,
}

/// Mirrors one element pushed to `proofs`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AcceptanceProof {
    pub acceptance_id: Value,
    pub producer: &'static str,
    pub verifier: &'static str,
    pub completion_consumer: &'static str,
    pub authenticated: bool,
    pub integrated_state: Value,
    pub observed_at: Value,
    pub valid_until: Value,
}

/// Result of [`load_completion_evidence`], mirroring the JS return object.
pub struct CompletionEvidence {
    pub evidence_registry: Vec<RegisteredEvidence>,
    pub acceptance_proofs: Vec<AcceptanceProof>,
}

fn get(v: &Value, key: &str) -> Value {
    v.get(key).cloned().unwrap_or(Value::Null)
}

fn as_str_nonempty(v: &Value) -> Option<&str> {
    v.as_str().filter(|s| !s.is_empty())
}

/// Port of `loadCompletionEvidence`.
///
/// `key_ring_present` mirrors the JS's `if (... || !keyRing || ...)`
/// short-circuit: JS treats a falsy `keyRing` as "authentication is not
/// configured" and returns the empty/pass-through shape immediately. The
/// actual key material never needs to reach this function — only whether
/// it is present — because verification is delegated to `record_verifier`.
#[allow(clippy::too_many_arguments)]
pub fn load_completion_evidence(
    receipt_store: &dyn ReceiptStore,
    key_ring_present: bool,
    authority_proof_issuer: Option<&dyn AuthorityProofIssuer>,
    record_verifier: &dyn RecordVerifier,
    execution: &Execution,
    integrated_state: &Value,
    latest_material_change: &Value,
) -> CompletionEvidence {
    let mut registry = Vec::new();
    let mut proofs = Vec::new();

    let criteria = &execution.acceptance_criteria;
    let issuer = match (criteria.is_empty(), key_ring_present, authority_proof_issuer) {
        (false, true, Some(issuer)) => issuer,
        _ => {
            return CompletionEvidence {
                evidence_registry: registry,
                acceptance_proofs: proofs,
            }
        }
    };

    let expected_base = serde_json::json!({
        "runId": execution.run_id,
        "taskId": execution.task_id,
        "contractId": execution.contract_id,
    });

    let records = receipt_store.list(&execution.run_id);

    for criterion in criteria {
        let receipt = records.iter().find(|record| {
            if get(record, "kind") != Value::String("legion-evidence-capability-receipt".into())
                || get(record, "stale") == Value::Bool(true)
                || get(record, "producerAuthority") != Value::String("oracle".into())
            {
                return false;
            }
            let observation = get(record, "observation");
            if observation.is_null() {
                return false;
            }
            let ok = get(&observation, "acceptanceId") == criterion.id
                && as_str_nonempty(&get(&observation, "requirementId")).is_some()
                && as_str_nonempty(&get(&observation, "productionSymbol")).is_some()
                && as_str_nonempty(&get(&observation, "liveConsumer")).is_some()
                && as_str_nonempty(&get(&observation, "acceptanceSurface")).is_some()
                && get(&observation, "integratedState") == *integrated_state
                && get(&observation, "latestMaterialChange") == *latest_material_change
                && get(&observation, "contractVersion") == execution.contract_version
                && get(&observation, "contractDigest") == execution.contract_digest
                && get(&observation, "sourceRevision") == execution.source_revision;
            if !ok {
                return false;
            }
            let digest = get(&observation, "authorityProofDigest");
            let authority = match issuer.find_by_digest(&digest) {
                Some(a) => a,
                None => return false,
            };
            let mut expected = expected_base.clone();
            expected["contractVersion"] = execution.contract_version.clone();
            expected["contractDigest"] = execution.contract_digest.clone();
            expected["sourceRevision"] = execution.source_revision.clone();
            if !issuer.verify(&authority, &expected).allowed {
                return false;
            }
            record_verifier
                .verify_record(record, &expected_base)
                .allowed
        });

        let receipt = match receipt {
            Some(r) => r,
            None => continue,
        };
        let observation = get(receipt, "observation");

        registry.push(RegisteredEvidence {
            acceptance_id: criterion.id.clone(),
            claim_type: "acceptance-surface",
            producer: "oracle",
            durable_store: "receipt-store",
            verifier: "arcane",
            completion_consumer: "legion",
            integrated_state_binding: "exact-git-state",
            validity_policy: "latest-material-change",
        });
        proofs.push(AcceptanceProof {
            acceptance_id: criterion.id.clone(),
            producer: "oracle",
            verifier: "arcane",
            completion_consumer: "legion",
            authenticated: true,
            integrated_state: get(&observation, "integratedState"),
            observed_at: get(receipt, "observedAt"),
            valid_until: get(&observation, "validUntil"),
        });
    }

    CompletionEvidence {
        evidence_registry: registry,
        acceptance_proofs: proofs,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    struct FakeStore(Vec<Receipt>);
    impl ReceiptStore for FakeStore {
        fn list(&self, _run_id: &Value) -> Vec<Receipt> {
            self.0.clone()
        }
    }

    struct FakeIssuer;
    impl AuthorityProofIssuer for FakeIssuer {
        fn find_by_digest(&self, digest: &Value) -> Option<Value> {
            if digest == &json!("digest-1") {
                Some(json!({"id": "authority-1"}))
            } else {
                None
            }
        }
        fn verify(&self, _authority: &Value, _expected: &Value) -> AuthorityVerifyResult {
            AuthorityVerifyResult { allowed: true }
        }
    }

    struct FakeVerifier;
    impl RecordVerifier for FakeVerifier {
        fn verify_record(&self, _record: &Value, _expected_binding: &Value) -> RecordVerifyResult {
            RecordVerifyResult { allowed: true }
        }
    }

    fn base_execution() -> Execution {
        Execution {
            run_id: json!("run-1"),
            task_id: json!("task-1"),
            contract_id: json!("contract-1"),
            contract_version: json!(1),
            contract_digest: json!("digest-c"),
            source_revision: json!("rev-1"),
            acceptance_criteria: vec![AcceptanceCriterion { id: json!("crit-1") }],
        }
    }

    fn matching_receipt() -> Receipt {
        json!({
            "kind": "legion-evidence-capability-receipt",
            "producerAuthority": "oracle",
            "observedAt": "2026-01-01T00:00:00Z",
            "observation": {
                "acceptanceId": "crit-1",
                "requirementId": "req-1",
                "productionSymbol": "sym",
                "liveConsumer": "consumer",
                "acceptanceSurface": "surface",
                "integratedState": {"git": "abc"},
                "latestMaterialChange": "2026-01-01",
                "contractVersion": 1,
                "contractDigest": "digest-c",
                "sourceRevision": "rev-1",
                "authorityProofDigest": "digest-1",
                "validUntil": "2026-02-01",
            }
        })
    }

    #[test]
    fn no_criteria_returns_empty_without_touching_dependencies() {
        let mut execution = base_execution();
        execution.acceptance_criteria.clear();
        let result = load_completion_evidence(
            &FakeStore(vec![]),
            true,
            Some(&FakeIssuer),
            &FakeVerifier,
            &execution,
            &json!({}),
            &json!(null),
        );
        assert!(result.evidence_registry.is_empty());
        assert!(result.acceptance_proofs.is_empty());
    }

    #[test]
    fn missing_key_ring_short_circuits() {
        let execution = base_execution();
        let result = load_completion_evidence(
            &FakeStore(vec![matching_receipt()]),
            false,
            Some(&FakeIssuer),
            &FakeVerifier,
            &execution,
            &json!({"git": "abc"}),
            &json!("2026-01-01"),
        );
        assert!(result.acceptance_proofs.is_empty());
    }

    #[test]
    fn matching_authenticated_receipt_registers_and_proves() {
        let execution = base_execution();
        let result = load_completion_evidence(
            &FakeStore(vec![matching_receipt()]),
            true,
            Some(&FakeIssuer),
            &FakeVerifier,
            &execution,
            &json!({"git": "abc"}),
            &json!("2026-01-01"),
        );
        assert_eq!(result.evidence_registry.len(), 1);
        assert_eq!(result.acceptance_proofs.len(), 1);
        assert_eq!(result.acceptance_proofs[0].acceptance_id, json!("crit-1"));
        assert_eq!(
            result.acceptance_proofs[0].integrated_state,
            json!({"git": "abc"})
        );
    }

    #[test]
    fn mismatched_integrated_state_skips_criterion() {
        let execution = base_execution();
        let result = load_completion_evidence(
            &FakeStore(vec![matching_receipt()]),
            true,
            Some(&FakeIssuer),
            &FakeVerifier,
            &execution,
            &json!({"git": "different"}),
            &json!("2026-01-01"),
        );
        assert!(result.acceptance_proofs.is_empty());
    }

    #[test]
    fn stale_receipt_is_ignored() {
        let mut receipt = matching_receipt();
        receipt["stale"] = json!(true);
        let execution = base_execution();
        let result = load_completion_evidence(
            &FakeStore(vec![receipt]),
            true,
            Some(&FakeIssuer),
            &FakeVerifier,
            &execution,
            &json!({"git": "abc"}),
            &json!("2026-01-01"),
        );
        assert!(result.acceptance_proofs.is_empty());
    }
}
