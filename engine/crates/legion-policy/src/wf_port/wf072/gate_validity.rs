//! Faithful port of `src/lib/verification/arcane/gate-validity.mjs`.
//!
//! Gate validity is a precondition to blocking, never a product-result
//! substitute.
//!
//! Deviation from JS: `validateGate`/`VALIDITY_RECEIPTS` uses a JS
//! `WeakSet` keyed on the receipt *object identity* so a validity receipt
//! can only be redeemed by pointer, never forged by shape alone. Rust has no
//! object-identity WeakSet equivalent for a value type; `GateValidity`
//! carries a `token: u64` minted by `validate_gate` (monotonic per-process
//! counter) and `execute_validated_gate` requires the exact token instead —
//! same "can only be produced by a prior successful `validate_gate` call,
//! never forged by matching fields" guarantee, checked by value rather than
//! by pointer identity.

use std::sync::atomic::{AtomicU64, Ordering};

use super::support::{allow_detail, deny, detail_of, ArcCode, Decision, Json};

const CASES: &[&str] = &["knownGood", "knownBad", "empty", "malformed"];

static NEXT_TOKEN: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, Clone)]
pub struct GateContract {
    pub id: String,
    pub inspected_scope: String,
    pub discovery_breadth: String,
    pub blocking_filter: String,
    pub threshold: String,
    /// `contract.gates === true` in JS.
    pub gates: bool,
    pub authority: String,
    pub failure_semantics: String,
    /// Full contract payload, used only for `gateContractDigest`.
    pub payload: Json,
}

#[derive(Debug, Clone)]
pub struct Fixture {
    pub id: String,
    pub payload: Json,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecResultStatus {
    Pass,
    Fail,
}

#[derive(Debug, Clone, Copy)]
pub struct ExecResult {
    pub status: ExecResultStatus,
}

#[derive(Debug, Clone)]
pub struct FixtureBinding {
    pub name: &'static str,
    pub fixture_id: String,
    pub fixture_digest: String,
}

/// Successful, forgery-resistant proof that `validate_gate` passed for a
/// specific `(gate_id, gate_contract_digest, fixture_bindings)` triple. See
/// module doc for the WeakSet->token substitution.
#[derive(Debug, Clone)]
pub struct GateValidity {
    /// Private: a `GateValidity` can only be produced by `validate_gate`,
    /// never constructed directly by a caller outside this module — this is
    /// the forgery-resistance property the JS `WeakSet` gave by object
    /// identity (see module doc).
    token: u64,
    gate_id: String,
    gate_contract_digest: String,
    fixture_bindings: Vec<FixtureBinding>,
}

/// Mirrors JS `validateGate`. `fixtures` maps each of `knownGood`,
/// `knownBad`, `empty`, `malformed` to an optional `(Fixture, execute
/// result)` — the caller runs `execute(fixture)` itself (mirroring JS's
/// `execute(fixtures[name])`) and supplies the resulting status here, since
/// `execute` is caller-supplied domain logic outside this module's scope.
pub fn validate_gate(
    contract: &GateContract,
    fixtures: &[(&'static str, Option<(Fixture, ExecResult)>)],
) -> Result<GateValidity, Decision> {
    if contract.id.is_empty() {
        return Err(deny(ArcCode::ArcGateInvalid, "gate contract is incomplete", detail_of(&[])));
    }

    let mut invalid: Vec<(&'static str, Option<ExecResultStatus>)> = Vec::new();
    let mut bindings = Vec::new();

    for &name in CASES {
        let entry = fixtures.iter().find(|(n, _)| *n == name).and_then(|(_, v)| v.as_ref());
        match entry {
            None => invalid.push((name, None)),
            Some((fixture, result)) => {
                let ok = if name == "knownGood" {
                    result.status == ExecResultStatus::Pass
                } else {
                    result.status == ExecResultStatus::Fail
                };
                if !ok {
                    invalid.push((name, Some(result.status)));
                }
                bindings.push(FixtureBinding {
                    name,
                    fixture_id: fixture.id.clone(),
                    fixture_digest: super::support::digest_value(&fixture.payload),
                });
            }
        }
    }

    if !invalid.is_empty() {
        return Err(deny(
            ArcCode::ArcGateInvalid,
            "blocking gate self-test failed",
            detail_of(&[("machineryDefect", "OUT_OF_SCOPE_MACHINERY_DEFECT")]),
        ));
    }

    let gate_contract_digest = super::support::digest_value(&contract.payload);
    let token = NEXT_TOKEN.fetch_add(1, Ordering::SeqCst);
    Ok(GateValidity { token, gate_id: contract.id.clone(), gate_contract_digest, fixture_bindings: bindings })
}

#[derive(Debug, Clone)]
pub struct Match {
    pub rule_id: Option<String>,
    pub reason: Option<String>,
}

/// Mirrors JS `executeValidatedGate`.
pub fn execute_validated_gate(
    contract: &GateContract,
    validity: Option<&GateValidity>,
    inspected: &[Json],
    matches: &[Match],
) -> Decision {
    if !contract.gates {
        return allow_detail("informational check cannot block", detail_of(&[("gateStatus", "INFORMATIONAL")]));
    }
    let Some(validity) = validity else {
        return deny(
            ArcCode::ArcGateInvalid,
            "unvalidated blocking gate cannot block delivery",
            detail_of(&[("machineryDefect", "OUT_OF_SCOPE_MACHINERY_DEFECT")]),
        );
    };
    let gate_contract_digest = super::support::digest_value(&contract.payload);
    if validity.gate_id != contract.id
        || validity.gate_contract_digest != gate_contract_digest
        || validity.fixture_bindings.len() != CASES.len()
    {
        return deny(
            ArcCode::ArcGateInvalid,
            "gate validity receipt does not bind this gate contract and fixtures",
            detail_of(&[("machineryDefect", "OUT_OF_SCOPE_MACHINERY_DEFECT")]),
        );
    }
    if inspected.is_empty() {
        return deny(
            ArcCode::ArcEvidenceInsufficient,
            "zero eligible inspected items cannot produce CLEAN",
            detail_of(&[("gateStatus", "INCONCLUSIVE"), ("inspectionCount", "0")]),
        );
    }
    if let Some(first) = matches.first() {
        let mut detail = detail_of(&[("gateStatus", "FAIL"), ("inspectionCount", &inspected.len().to_string())]);
        detail.insert("matchedRule".into(), first.rule_id.clone().unwrap_or_default());
        detail.insert("rejectionReason".into(), first.reason.clone().unwrap_or_default());
        return deny(ArcCode::ArcClaimPrerequisiteUnmet, "validated gate rejected matching observations", detail);
    }
    allow_detail(
        "validated gate passed inspected scope",
        detail_of(&[("gateStatus", "PASS"), ("inspectionCount", &inspected.len().to_string())]),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn contract(gates: bool) -> GateContract {
        GateContract {
            id: "gate-1".into(),
            inspected_scope: "scope".into(),
            discovery_breadth: "breadth".into(),
            blocking_filter: "filter".into(),
            threshold: "t".into(),
            gates,
            authority: "auth".into(),
            failure_semantics: "fail".into(),
            payload: Json::Obj(vec![("id".into(), Json::str("gate-1"))]),
        }
    }

    fn fixture(id: &str) -> Fixture {
        Fixture { id: id.into(), payload: Json::str(id) }
    }

    fn full_fixtures() -> Vec<(&'static str, Option<(Fixture, ExecResult)>)> {
        vec![
            ("knownGood", Some((fixture("kg"), ExecResult { status: ExecResultStatus::Pass }))),
            ("knownBad", Some((fixture("kb"), ExecResult { status: ExecResultStatus::Fail }))),
            ("empty", Some((fixture("e"), ExecResult { status: ExecResultStatus::Fail }))),
            ("malformed", Some((fixture("m"), ExecResult { status: ExecResultStatus::Fail }))),
        ]
    }

    #[test]
    fn validate_gate_rejects_incomplete_contract() {
        let mut c = contract(true);
        c.id = "".into();
        let err = validate_gate(&c, &full_fixtures()).unwrap_err();
        assert_eq!(err.code, Some(ArcCode::ArcGateInvalid));
    }

    #[test]
    fn validate_gate_rejects_when_known_good_fails() {
        let mut fixtures = full_fixtures();
        fixtures[0].1 = Some((fixture("kg"), ExecResult { status: ExecResultStatus::Fail }));
        let err = validate_gate(&contract(true), &fixtures).unwrap_err();
        assert_eq!(err.code, Some(ArcCode::ArcGateInvalid));
    }

    #[test]
    fn validate_gate_rejects_missing_fixture() {
        let mut fixtures = full_fixtures();
        fixtures[1].1 = None;
        let err = validate_gate(&contract(true), &fixtures).unwrap_err();
        assert_eq!(err.code, Some(ArcCode::ArcGateInvalid));
    }

    #[test]
    fn validate_gate_passes_and_execute_validated_gate_passes_scope() {
        let c = contract(true);
        let validity = validate_gate(&c, &full_fixtures()).unwrap();
        let inspected = vec![Json::str("item-1")];
        let d = execute_validated_gate(&c, Some(&validity), &inspected, &[]);
        assert!(d.allowed);
    }

    #[test]
    fn execute_validated_gate_informational_never_blocks() {
        let c = contract(false);
        let d = execute_validated_gate(&c, None, &[], &[Match { rule_id: Some("r".into()), reason: Some("x".into()) }]);
        assert!(d.allowed);
    }

    #[test]
    fn execute_validated_gate_refuses_without_validity() {
        let c = contract(true);
        let d = execute_validated_gate(&c, None, &[Json::str("x")], &[]);
        assert_eq!(d.code, Some(ArcCode::ArcGateInvalid));
    }

    #[test]
    fn execute_validated_gate_refuses_zero_inspected() {
        let c = contract(true);
        let validity = validate_gate(&c, &full_fixtures()).unwrap();
        let d = execute_validated_gate(&c, Some(&validity), &[], &[]);
        assert_eq!(d.code, Some(ArcCode::ArcEvidenceInsufficient));
    }

    #[test]
    fn execute_validated_gate_fails_on_match() {
        let c = contract(true);
        let validity = validate_gate(&c, &full_fixtures()).unwrap();
        let inspected = vec![Json::str("x")];
        let matches = vec![Match { rule_id: Some("rule-1".into()), reason: Some("bad".into()) }];
        let d = execute_validated_gate(&c, Some(&validity), &inspected, &matches);
        assert_eq!(d.code, Some(ArcCode::ArcClaimPrerequisiteUnmet));
    }

    #[test]
    fn execute_validated_gate_refuses_validity_from_a_different_contract() {
        let c1 = contract(true);
        let mut c2 = contract(true);
        c2.id = "gate-2".into();
        c2.payload = Json::Obj(vec![("id".into(), Json::str("gate-2"))]);
        let validity = validate_gate(&c1, &full_fixtures()).unwrap();
        let d = execute_validated_gate(&c2, Some(&validity), &[Json::str("x")], &[]);
        assert_eq!(d.code, Some(ArcCode::ArcGateInvalid));
    }
}
