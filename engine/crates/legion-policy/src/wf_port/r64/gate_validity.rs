//! Port of `src/lib/verification/arcane/gate-validity.mjs` (`validateGate`,
//! `executeValidatedGate`).
//!
//! Not one of this packet's seven owned files, but ported here to close
//! `src/lib/verification/arcane/s11-bindings/eval-review-security.mjs`'s
//! `AE-REVIEW-ADMISSION-001`/`AE-REVIEW-VERDICT-SECURITY-006` gap in
//! `crate::wf_port::wf074::eval_review_security`, which was previously
//! `BlockedOnDependency` on this exact module. Gate validity is pure
//! decision logic over caller-supplied fixtures/results (no I/O), so faking
//! it was never necessary — the only blocker was that no Rust port existed.
//!
//! JS ties a `validity` receipt to its gate contract via a `WeakSet`
//! (`VALIDITY_RECEIPTS`) plus content checks in `executeValidatedGate`, so
//! that a receipt from a different gate contract (even with an identical
//! shape) cannot be replayed as this gate's validity. Rust has no
//! equivalent ambient identity primitive, so `GateValidity` carries an
//! explicit opaque `token: u64` (assigned by `validate_gate`, checked by
//! `execute_validated_gate`) that plays the same "only a receipt this
//! function itself minted can pass" role as the WeakSet membership check.
//! The content checks (`gateId`/`gateContractDigest`/`fixtureBindings`
//! length) are ported unchanged alongside it.

use std::sync::atomic::{AtomicU64, Ordering};

use legion_contracts::canonical::canonical_digest;
use serde_json::{json, Value};

use super::decision::{decision, Decision};

const CASES: [&str; 4] = ["knownGood", "knownBad", "empty", "malformed"];

static NEXT_TOKEN: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, Clone)]
pub struct GateContract {
    pub id: String,
    pub inspected_scope: Vec<String>,
    pub discovery_breadth: String,
    pub blocking_filter: String,
    pub threshold: i64,
    pub gates: bool,
    pub authority: String,
    pub failure_semantics: String,
}

impl GateContract {
    fn to_digest_value(&self) -> Value {
        json!({
            "id": self.id,
            "inspectedScope": self.inspected_scope,
            "discoveryBreadth": self.discovery_breadth,
            "blockingFilter": self.blocking_filter,
            "threshold": self.threshold,
            "gates": self.gates,
            "authority": self.authority,
            "failureSemantics": self.failure_semantics,
        })
    }
}

fn digest_value(v: &Value) -> String {
    canonical_digest(v).expect("gate contract/fixture must be canonicalizable")
}

/// A case fixture: `{ id, status }` (only these two fields are read).
#[derive(Debug, Clone)]
pub struct Fixture {
    pub id: String,
    pub status: String,
}

/// Result of `execute(fixture)`: only `.status` is read by `validateGate`.
#[derive(Debug, Clone)]
pub struct CaseResult {
    pub status: String,
}

#[derive(Debug, Clone)]
pub struct GateValidity {
    pub decision: Decision,
    /// `None` unless `decision.allowed` — mirrors the JS receipt only being
    /// added to `VALIDITY_RECEIPTS` when it passed. Present so
    /// `execute_validated_gate` can check "was this the exact receipt this
    /// function minted" (see module doc).
    token: Option<u64>,
    gate_id: Option<String>,
    gate_contract_digest: Option<String>,
    fixture_bindings_len: Option<usize>,
}

/// Mirrors JS `validateGate({ contract, fixtures, execute })`.
pub fn validate_gate(
    contract: &GateContract,
    fixtures: &std::collections::BTreeMap<&'static str, Fixture>,
    execute: impl Fn(&Fixture) -> CaseResult,
) -> GateValidity {
    let results: Vec<(&'static str, Option<&Fixture>, Option<CaseResult>)> = CASES
        .iter()
        .map(|&name| {
            let fixture = fixtures.get(name);
            let result = fixture.map(&execute);
            (name, fixture, result)
        })
        .collect();

    let invalid: Vec<&(&'static str, Option<&Fixture>, Option<CaseResult>)> = results
        .iter()
        .filter(|(name, _, result)| match result {
            None => true,
            Some(r) => {
                if *name == "knownGood" {
                    r.status != "PASS"
                } else {
                    r.status != "FAIL"
                }
            }
        })
        .collect();

    if !invalid.is_empty() {
        let invalid_json: Vec<Value> = invalid
            .iter()
            .map(|(name, _, result)| json!({"name": name, "status": result.as_ref().map(|r| r.status.clone())}))
            .collect();
        let d = decision(
            false,
            Some("ARC_GATE_INVALID"),
            "blocking gate self-test failed",
            json!({"machineryDefect": "OUT_OF_SCOPE_MACHINERY_DEFECT", "invalid": invalid_json}),
        );
        return GateValidity { decision: d, token: None, gate_id: None, gate_contract_digest: None, fixture_bindings_len: None };
    }

    let gate_contract_digest = digest_value(&contract.to_digest_value());
    let fixture_bindings: Vec<Value> = results
        .iter()
        .map(|(name, fixture, _)| {
            let f = fixture.unwrap();
            json!({"name": name, "id": f.id, "digest": digest_value(&json!({"id": f.id, "status": f.status}))})
        })
        .collect();
    let d = decision(
        true,
        None,
        "blocking gate self-test passed",
        json!({
            "gateId": contract.id,
            "gateContractDigest": gate_contract_digest,
            "fixtureBindings": fixture_bindings,
            "gateStatus": "VALID",
        }),
    );
    let token = NEXT_TOKEN.fetch_add(1, Ordering::Relaxed);
    GateValidity {
        decision: d,
        token: Some(token),
        gate_id: Some(contract.id.clone()),
        gate_contract_digest: Some(gate_contract_digest),
        fixture_bindings_len: Some(CASES.len()),
    }
}

#[derive(Debug, Clone, Default)]
pub struct GateMatch {
    pub rule_id: Option<String>,
    pub reason: Option<String>,
}

/// Mirrors JS `executeValidatedGate({ contract, validity, inspected, matches })`.
pub fn execute_validated_gate(
    contract: &GateContract,
    validity: Option<&GateValidity>,
    inspected: &[Value],
    matches: &[GateMatch],
) -> Decision {
    if !contract.gates {
        return decision(true, None, "informational check cannot block", json!({"gateStatus": "INFORMATIONAL"}));
    }
    let validity = match validity {
        Some(v) if v.decision.allowed => v,
        Some(v) => {
            let defect = v.decision.detail.get("machineryDefect").cloned().unwrap_or(json!("OUT_OF_SCOPE_MACHINERY_DEFECT"));
            return decision(false, Some("ARC_GATE_INVALID"), "unvalidated blocking gate cannot block delivery", json!({"machineryDefect": defect}));
        }
        None => {
            return decision(
                false,
                Some("ARC_GATE_INVALID"),
                "unvalidated blocking gate cannot block delivery",
                json!({"machineryDefect": "OUT_OF_SCOPE_MACHINERY_DEFECT"}),
            );
        }
    };

    let binds = validity.token.is_some()
        && validity.gate_id.as_deref() == Some(contract.id.as_str())
        && validity.gate_contract_digest.as_deref() == Some(digest_value(&contract.to_digest_value()).as_str())
        && validity.fixture_bindings_len == Some(CASES.len());
    if !binds {
        return decision(
            false,
            Some("ARC_GATE_INVALID"),
            "gate validity receipt does not bind this gate contract and fixtures",
            json!({"machineryDefect": "OUT_OF_SCOPE_MACHINERY_DEFECT"}),
        );
    }

    if inspected.is_empty() {
        return decision(
            false,
            Some("ARC_EVIDENCE_INSUFFICIENT"),
            "zero eligible inspected items cannot produce CLEAN",
            json!({"gateStatus": "INCONCLUSIVE", "inspectionCount": 0}),
        );
    }
    if !matches.is_empty() {
        let m = &matches[0];
        return decision(
            false,
            Some("ARC_CLAIM_PREREQUISITE_UNMET"),
            "validated gate rejected matching observations",
            json!({
                "gateStatus": "FAIL",
                "inspectionCount": inspected.len(),
                "matchedRule": m.rule_id,
                "rejectionReason": m.reason,
            }),
        );
    }
    decision(
        true,
        None,
        "validated gate passed inspected scope",
        json!({"gateStatus": "PASS", "inspectionCount": inspected.len(), "matchedRule": Value::Null, "rejectionReason": Value::Null}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn contract() -> GateContract {
        GateContract {
            id: "review-admission-s11".into(),
            inspected_scope: vec!["packages/arcane/**".into()],
            discovery_breadth: "configured".into(),
            blocking_filter: "security".into(),
            threshold: 3,
            gates: true,
            authority: "oracle".into(),
            failure_semantics: "fail-closed".into(),
        }
    }

    fn fixtures() -> BTreeMap<&'static str, Fixture> {
        let mut m = BTreeMap::new();
        m.insert("knownGood", Fixture { id: "known-good".into(), status: "PASS".into() });
        m.insert("knownBad", Fixture { id: "known-bad".into(), status: "FAIL".into() });
        m.insert("empty", Fixture { id: "empty".into(), status: "FAIL".into() });
        m.insert("malformed", Fixture { id: "malformed".into(), status: "FAIL".into() });
        m
    }

    #[test]
    fn zero_inspected_is_inconclusive() {
        let contract = contract();
        let validity = validate_gate(&contract, &fixtures(), |f| CaseResult { status: f.status.clone() });
        assert!(validity.decision.allowed);
        let result = execute_validated_gate(&contract, Some(&validity), &[], &[]);
        assert!(!result.allowed);
        assert_eq!(result.code, Some("ARC_EVIDENCE_INSUFFICIENT"));
        assert_eq!(result.detail.get("inspectionCount"), Some(&json!(0)));
    }

    #[test]
    fn out_of_scope_match_rejects_admission() {
        let contract = contract();
        let validity = validate_gate(&contract, &fixtures(), |f| CaseResult { status: f.status.clone() });
        let matches = vec![GateMatch { rule_id: Some("UNINSPECTED_SCOPE".into()), reason: Some("outside configured scope".into()) }];
        let inspected = vec![json!({"subjectId": "src/lib/verification/arcane/gate-validity.mjs"})];
        let result = execute_validated_gate(&contract, Some(&validity), &inspected, &matches);
        assert!(!result.allowed);
        assert_eq!(result.code, Some("ARC_CLAIM_PREREQUISITE_UNMET"));
    }

    #[test]
    fn validity_from_a_different_contract_does_not_bind() {
        let contract_a = contract();
        let mut contract_b = contract();
        contract_b.id = "other-gate".into();
        let validity = validate_gate(&contract_a, &fixtures(), |f| CaseResult { status: f.status.clone() });
        let inspected = vec![json!({"subjectId": "x"})];
        let result = execute_validated_gate(&contract_b, Some(&validity), &inspected, &[]);
        assert!(!result.allowed);
        assert_eq!(result.code, Some("ARC_GATE_INVALID"));
    }

    #[test]
    fn invalid_self_test_fails_validation() {
        let contract = contract();
        let mut bad_fixtures = fixtures();
        bad_fixtures.insert("knownGood", Fixture { id: "known-good".into(), status: "FAIL".into() });
        let validity = validate_gate(&contract, &bad_fixtures, |f| CaseResult { status: f.status.clone() });
        assert!(!validity.decision.allowed);
        assert_eq!(validity.decision.code, Some("ARC_GATE_INVALID"));
    }
}
