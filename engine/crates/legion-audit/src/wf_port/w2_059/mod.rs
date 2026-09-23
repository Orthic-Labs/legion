//! Port of `src/providers/copy/claims.mjs`, which itself wraps
//! `src/lib/content/claim-proof-ledger.mjs`'s `buildClaimProofLedger`.
//!
//! JS source (verbatim, both files):
//!
//! ```js
//! // src/lib/content/claim-proof-ledger.mjs
//! export function buildClaimProofLedger({ claims = [], evidence = [] } = {}) {
//!   const source = new Map(evidence.map((item) => [item.id, item]));
//!   return {
//!     schemaVersion: 1,
//!     kind: 'legion-claim-proof-ledger',
//!     claims: claims.map((claim) => ({
//!       ...claim,
//!       proof: claim.evidenceRefs?.map((id) => source.get(id)).filter(Boolean) ?? [],
//!       disposition: claim.evidenceRefs?.every((id) => source.has(id)) ? 'bound' : 'unproven',
//!     })),
//!     evidence,
//!   };
//! }
//!
//! // src/providers/copy/claims.mjs
//! import { buildClaimProofLedger } from '../../lib/content/claim-proof-ledger.mjs';
//! export function assessClaims(input) {
//!   const ledger = buildClaimProofLedger(input);
//!   return {
//!     provider: 'copy.claims',
//!     status: ledger.claims.some((claim) => claim.disposition === 'unproven') ? 'unproven' : 'pass',
//!     ...ledger,
//!   };
//! }
//! ```
//!
//! Behavioural notes carried over faithfully:
//! - `evidence` is keyed by `id` into a `Map`; a later item with a
//!   duplicate `id` silently overwrites an earlier one when looked up
//!   (JS `Map` semantics) — we mirror this with a `HashMap` built by
//!   iterating `evidence` in order, later entries winning.
//! - A claim with no `evidenceRefs` (`undefined`/absent) gets
//!   `proof: []` and `disposition: "unproven"` — JS's `undefined?.every(...)`
//!   evaluates to `undefined`, which is falsy, not an empty-array vacuous
//!   truth. An explicit empty `evidenceRefs: []` *is* vacuously `every`
//!   true in JS, so it resolves to `"bound"` with `proof: []`. This
//!   distinction (absent vs. empty) is why `evidence_refs` is
//!   `Option<Vec<String>>`, not a bare `Vec<String>`.
//! - `proof` collects only the evidence items that were actually found
//!   (`.filter(Boolean)` drops `undefined` lookups for unknown refs), so
//!   `proof.len()` can be less than `evidence_refs.len()` even when
//!   `disposition` is `"unproven"`.
//! - Unknown/extra fields on each claim and each evidence item are
//!   preserved on the output (JS object spread `...claim`); we mirror
//!   this with `#[serde(flatten)]` into a `serde_json::Map`.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

/// One evidence record. Only `id` is meaningful to the ledger; every other
/// field is opaque payload that passes through unchanged.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Evidence {
    pub id: String,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// One input claim, matching the JS destructured claim shape. `id`/`text`/etc.
/// are not modeled explicitly since JS treats them as opaque spread fields;
/// only `evidence_refs` (`evidenceRefs`) drives ledger logic.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Claim {
    /// `None` mirrors JS `claim.evidenceRefs` being absent/`undefined`.
    #[serde(rename = "evidenceRefs", default, skip_serializing_if = "Option::is_none")]
    pub evidence_refs: Option<Vec<String>>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// Disposition of a claim against the evidence set.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Disposition {
    Bound,
    Unproven,
}

/// A resolved claim: the original claim's fields plus `proof` and `disposition`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResolvedClaim {
    #[serde(flatten)]
    pub extra: Map<String, Value>,
    #[serde(rename = "evidenceRefs", default, skip_serializing_if = "Option::is_none")]
    pub evidence_refs: Option<Vec<String>>,
    pub proof: Vec<Evidence>,
    pub disposition: Disposition,
}

/// Input to `buildClaimProofLedger` / `assessClaims`. JS defaults a missing
/// argument object, and defaults `claims`/`evidence` to `[]` within it; a
/// `Default` impl mirrors both defaults for an absent/empty caller input.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LedgerInput {
    #[serde(default)]
    pub claims: Vec<Claim>,
    #[serde(default)]
    pub evidence: Vec<Evidence>,
}

/// Output of `buildClaimProofLedger`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClaimProofLedger {
    #[serde(rename = "schemaVersion")]
    pub schema_version: u32,
    pub kind: String,
    pub claims: Vec<ResolvedClaim>,
    pub evidence: Vec<Evidence>,
}

/// Port of `buildClaimProofLedger`.
pub fn build_claim_proof_ledger(input: LedgerInput) -> ClaimProofLedger {
    let LedgerInput { claims, evidence } = input;

    // JS: `new Map(evidence.map((item) => [item.id, item]))` — later
    // duplicate ids overwrite earlier ones.
    let mut source: HashMap<String, Evidence> = HashMap::with_capacity(evidence.len());
    for item in &evidence {
        source.insert(item.id.clone(), item.clone());
    }

    let resolved_claims = claims
        .into_iter()
        .map(|claim| {
            let proof: Vec<Evidence> = match &claim.evidence_refs {
                Some(refs) => refs
                    .iter()
                    .filter_map(|id| source.get(id).cloned())
                    .collect(),
                None => Vec::new(),
            };
            let disposition = match &claim.evidence_refs {
                Some(refs) => {
                    if refs.iter().all(|id| source.contains_key(id)) {
                        Disposition::Bound
                    } else {
                        Disposition::Unproven
                    }
                }
                None => Disposition::Unproven,
            };
            ResolvedClaim {
                extra: claim.extra,
                evidence_refs: claim.evidence_refs,
                proof,
                disposition,
            }
        })
        .collect();

    ClaimProofLedger {
        schema_version: 1,
        kind: "legion-claim-proof-ledger".to_string(),
        claims: resolved_claims,
        evidence,
    }
}

/// Output of `assessClaims` (the `copy.claims` provider).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClaimsAssessment {
    pub provider: String,
    pub status: String,
    #[serde(rename = "schemaVersion")]
    pub schema_version: u32,
    pub kind: String,
    pub claims: Vec<ResolvedClaim>,
    pub evidence: Vec<Evidence>,
}

/// Port of `assessClaims` from `src/providers/copy/claims.mjs`.
pub fn assess_claims(input: LedgerInput) -> ClaimsAssessment {
    let ledger = build_claim_proof_ledger(input);
    let status = if ledger
        .claims
        .iter()
        .any(|claim| claim.disposition == Disposition::Unproven)
    {
        "unproven"
    } else {
        "pass"
    };
    ClaimsAssessment {
        provider: "copy.claims".to_string(),
        status: status.to_string(),
        schema_version: ledger.schema_version,
        kind: ledger.kind,
        claims: ledger.claims,
        evidence: ledger.evidence,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn evidence(id: &str) -> Evidence {
        Evidence {
            id: id.to_string(),
            extra: Map::new(),
        }
    }

    fn claim(refs: Option<Vec<&str>>) -> Claim {
        Claim {
            evidence_refs: refs.map(|r| r.into_iter().map(String::from).collect()),
            extra: Map::new(),
        }
    }

    #[test]
    fn empty_input_yields_empty_ledger() {
        let ledger = build_claim_proof_ledger(LedgerInput::default());
        assert_eq!(ledger.schema_version, 1);
        assert_eq!(ledger.kind, "legion-claim-proof-ledger");
        assert!(ledger.claims.is_empty());
        assert!(ledger.evidence.is_empty());
    }

    #[test]
    fn claim_with_all_refs_bound_is_bound_with_full_proof() {
        let input = LedgerInput {
            claims: vec![claim(Some(vec!["e1", "e2"]))],
            evidence: vec![evidence("e1"), evidence("e2")],
        };
        let ledger = build_claim_proof_ledger(input);
        assert_eq!(ledger.claims.len(), 1);
        assert_eq!(ledger.claims[0].disposition, Disposition::Bound);
        assert_eq!(ledger.claims[0].proof.len(), 2);
    }

    #[test]
    fn claim_with_missing_ref_is_unproven_with_partial_proof() {
        let input = LedgerInput {
            claims: vec![claim(Some(vec!["e1", "missing"]))],
            evidence: vec![evidence("e1")],
        };
        let ledger = build_claim_proof_ledger(input);
        assert_eq!(ledger.claims[0].disposition, Disposition::Unproven);
        // `.filter(Boolean)` drops the missing lookup: only e1 is proof.
        assert_eq!(ledger.claims[0].proof.len(), 1);
        assert_eq!(ledger.claims[0].proof[0].id, "e1");
    }

    #[test]
    fn claim_with_absent_evidence_refs_is_unproven_with_no_proof() {
        // JS: `undefined?.every(...)` is `undefined` (falsy) -> "unproven",
        // NOT vacuously true like an explicit empty array would be.
        let input = LedgerInput {
            claims: vec![claim(None)],
            evidence: vec![evidence("e1")],
        };
        let ledger = build_claim_proof_ledger(input);
        assert_eq!(ledger.claims[0].disposition, Disposition::Unproven);
        assert!(ledger.claims[0].proof.is_empty());
    }

    #[test]
    fn claim_with_explicit_empty_evidence_refs_is_vacuously_bound() {
        // JS: `[].every(...)` is `true` -> "bound", with empty proof.
        let input = LedgerInput {
            claims: vec![claim(Some(vec![]))],
            evidence: vec![],
        };
        let ledger = build_claim_proof_ledger(input);
        assert_eq!(ledger.claims[0].disposition, Disposition::Bound);
        assert!(ledger.claims[0].proof.is_empty());
    }

    #[test]
    fn duplicate_evidence_ids_last_write_wins() {
        let mut first = evidence("dup");
        first.extra.insert("label".into(), json!("first"));
        let mut second = evidence("dup");
        second.extra.insert("label".into(), json!("second"));

        let input = LedgerInput {
            claims: vec![claim(Some(vec!["dup"]))],
            evidence: vec![first, second],
        };
        let ledger = build_claim_proof_ledger(input);
        assert_eq!(ledger.claims[0].proof.len(), 1);
        assert_eq!(
            ledger.claims[0].proof[0].extra.get("label"),
            Some(&json!("second"))
        );
    }

    #[test]
    fn extra_claim_and_evidence_fields_pass_through() {
        let mut c = claim(Some(vec!["e1"]));
        c.extra.insert("id".into(), json!("claim-1"));
        c.extra.insert("text".into(), json!("the sky is blue"));
        let mut e = evidence("e1");
        e.extra.insert("source".into(), json!("survey.pdf"));

        let input = LedgerInput {
            claims: vec![c],
            evidence: vec![e],
        };
        let ledger = build_claim_proof_ledger(input);
        assert_eq!(ledger.claims[0].extra.get("id"), Some(&json!("claim-1")));
        assert_eq!(
            ledger.claims[0].extra.get("text"),
            Some(&json!("the sky is blue"))
        );
        assert_eq!(
            ledger.claims[0].proof[0].extra.get("source"),
            Some(&json!("survey.pdf"))
        );
    }

    #[test]
    fn assess_claims_status_pass_when_all_bound() {
        let input = LedgerInput {
            claims: vec![claim(Some(vec!["e1"])), claim(Some(vec![]))],
            evidence: vec![evidence("e1")],
        };
        let result = assess_claims(input);
        assert_eq!(result.provider, "copy.claims");
        assert_eq!(result.status, "pass");
        assert_eq!(result.schema_version, 1);
        assert_eq!(result.kind, "legion-claim-proof-ledger");
    }

    #[test]
    fn assess_claims_status_unproven_when_any_claim_unproven() {
        let input = LedgerInput {
            claims: vec![claim(Some(vec!["e1"])), claim(None)],
            evidence: vec![evidence("e1")],
        };
        let result = assess_claims(input);
        assert_eq!(result.status, "unproven");
    }

    #[test]
    fn assess_claims_with_no_claims_is_pass() {
        // `[].some(...)` is `false` -> status stays "pass".
        let result = assess_claims(LedgerInput::default());
        assert_eq!(result.status, "pass");
    }
}
