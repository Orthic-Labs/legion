//! Integration tests for the port of `src/providers/copy/claims.mjs` and
//! `src/lib/content/claim-proof-ledger.mjs`.
//!
//! No dedicated JS test file exists for `claims.mjs` upstream; these
//! integration tests exercise the same scenarios as the unit tests inside
//! `wf_port::w2_059`, from outside the crate, to prove the public API.
//!
//! Requires the integrator to wire `pub mod wf_port;` (with `pub mod
//! w2_059;` inside it) into `legion_audit`'s crate root.

use legion_audit::wf_port::w2_059::{assess_claims, Claim, Evidence, LedgerInput};

fn evidence(id: &str) -> Evidence {
    Evidence {
        id: id.to_string(),
        extra: serde_json::Map::new(),
    }
}

fn claim(refs: Option<Vec<&str>>) -> Claim {
    Claim {
        evidence_refs: refs.map(|r| r.into_iter().map(String::from).collect()),
        extra: serde_json::Map::new(),
    }
}

#[test]
fn assess_claims_pass_when_every_claim_bound() {
    let input = LedgerInput {
        claims: vec![claim(Some(vec!["e1"])), claim(Some(vec![]))],
        evidence: vec![evidence("e1")],
    };
    let result = assess_claims(input);
    assert_eq!(result.provider, "copy.claims");
    assert_eq!(result.status, "pass");
    assert_eq!(result.schema_version, 1);
    assert_eq!(result.kind, "legion-claim-proof-ledger");
    assert_eq!(result.claims.len(), 2);
}

#[test]
fn assess_claims_unproven_when_a_ref_is_missing() {
    let input = LedgerInput {
        claims: vec![claim(Some(vec!["e1", "ghost"]))],
        evidence: vec![evidence("e1")],
    };
    let result = assess_claims(input);
    assert_eq!(result.status, "unproven");
    assert_eq!(result.claims[0].proof.len(), 1);
}

#[test]
fn assess_claims_unproven_when_evidence_refs_absent() {
    let input = LedgerInput {
        claims: vec![claim(None)],
        evidence: vec![evidence("e1")],
    };
    let result = assess_claims(input);
    assert_eq!(result.status, "unproven");
    assert!(result.claims[0].proof.is_empty());
}

#[test]
fn assess_claims_pass_on_empty_input() {
    let result = assess_claims(LedgerInput::default());
    assert_eq!(result.status, "pass");
    assert!(result.claims.is_empty());
    assert!(result.evidence.is_empty());
}

#[test]
fn assess_claims_serializes_shape_via_json_roundtrip() {
    let input = LedgerInput {
        claims: vec![claim(Some(vec!["e1"]))],
        evidence: vec![evidence("e1")],
    };
    let result = assess_claims(input);
    let value = serde_json::to_value(&result).expect("serialize");
    assert_eq!(value["provider"], "copy.claims");
    assert_eq!(value["status"], "pass");
    assert_eq!(value["schemaVersion"], 1);
    assert_eq!(value["kind"], "legion-claim-proof-ledger");
    assert_eq!(value["claims"][0]["disposition"], "bound");
    assert_eq!(value["claims"][0]["proof"][0]["id"], "e1");
}
