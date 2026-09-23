//! Partial port of `src/lib/core/adjudicate-run.mjs`.
//!
//! Ported in full: `validateJudgmentReceipt`, the `MODES` set, and the
//! `adjudicateSubjects` code path taken when reasoning is `'disabled'` or no
//! reviewer is available (the branch that never calls `prepareAdjudication`).
//!
//! NOT ported: `prepareAdjudication` and the reviewer-available branch of
//! `adjudicateSubjects`, because both call `buildJudgmentPacket` (from
//! `./judgment-packets.mjs`) and `reviewerPolicy` (from
//! `./reviewer-policy.mjs`) — neither file is in this chunk (w2_039 owns
//! only `adjudicate-run.mjs`, `audit.mjs`, `binding.mjs`, `build-plan.mjs`,
//! `execute-plan.mjs`). A faithful port of the reviewer-enabled path needs
//! those two modules ported first (see the w2_039 report for the exact
//! remaining shape).

use serde_json::{json, Value};

use super::binding::same_binding;

/// Mirrors `const MODES=new Set(['auto','disabled','required'])`.
pub const MODES: [&str; 3] = ["auto", "disabled", "required"];

pub fn is_known_mode(mode: &str) -> bool {
    MODES.contains(&mode)
}

/// One subject to adjudicate, mirroring the minimal shape `adjudicateSubjects`
/// reads in the disabled/unavailable branch: `{ id, evidence }`.
#[derive(Clone, Debug, Default)]
pub struct Subject {
    pub id: Value,
    pub evidence: Vec<Value>,
}

/// Mirrors one element of `receipts` built in the disabled/unavailable branch.
#[derive(Clone, Debug)]
pub struct JudgmentReceipt {
    pub schema_version: u32,
    pub kind: String,
    pub subject_id: Value,
    pub status: String,
    pub complete: bool,
    pub binding: Option<Value>,
    pub context_id: String,
    pub reviewer: Option<Value>,
    pub verdict: Option<Value>,
    pub evidence_refs: Vec<Value>,
    pub gaps: Vec<Value>,
}

impl JudgmentReceipt {
    /// Renders the JSON shape produced by the JS object literal, for callers
    /// that serialize the receipt (e.g. into a run artifact store).
    pub fn to_json(&self) -> Value {
        json!({
            "schemaVersion": self.schema_version,
            "kind": self.kind,
            "subjectId": self.subject_id,
            "status": self.status,
            "complete": self.complete,
            "binding": self.binding.clone().unwrap_or(Value::Null),
            "contextId": self.context_id,
            "reviewer": self.reviewer.clone().unwrap_or(Value::Null),
            "verdict": self.verdict.clone().unwrap_or(Value::Null),
            "evidenceRefs": self.evidence_refs,
            "gaps": self.gaps,
        })
    }
}

/// Mirrors the object `adjudicateSubjects` returns.
#[derive(Clone, Debug)]
pub struct AdjudicationResult {
    pub complete: bool,
    pub receipts: Vec<JudgmentReceipt>,
    // `packets` is always `[]` on this branch in JS.
    pub packets: Vec<Value>,
}

/// Error mirroring `throw new TypeError(...)`.
#[derive(Debug, thiserror::Error)]
pub enum AdjudicateError {
    #[error("unknown reasoning mode: {0}")]
    UnknownMode(String),
}

/// Mirrors the `mode==='disabled'||!reviewerAvailable` branch of
/// `adjudicateSubjects(subjects, policy, host)`.
///
/// `context_prefix` mirrors `policy.contextPrefix ?? 'review'`.
/// `binding` mirrors `host.binding ?? policy.binding ?? null`.
/// `reviewer_available` mirrors
/// `host.reviewer?.state!=='unavailable' && typeof review==='function'`,
/// which the caller must compute (it depends on host wiring outside this
/// chunk) and pass in.
pub fn adjudicate_subjects_without_reviewer(
    subjects: &[Subject],
    mode: &str,
    binding: Option<&Value>,
    context_prefix: Option<&str>,
    reviewer_available: bool,
) -> Result<AdjudicationResult, AdjudicateError> {
    if !is_known_mode(mode) {
        return Err(AdjudicateError::UnknownMode(mode.to_string()));
    }
    debug_assert!(
        mode == "disabled" || !reviewer_available,
        "this entry point only covers the mode==='disabled' || !reviewerAvailable branch"
    );
    let required = mode == "required";
    let prefix = context_prefix.unwrap_or("review");
    let receipts: Vec<JudgmentReceipt> = subjects
        .iter()
        .enumerate()
        .map(|(index, subject)| JudgmentReceipt {
            schema_version: 1,
            kind: "legion-judgment-receipt".to_string(),
            subject_id: subject.id.clone(),
            status: if required { "unproven" } else { "skipped" }.to_string(),
            complete: false,
            binding: binding.cloned(),
            context_id: format!("{prefix}-{index}"),
            reviewer: None,
            verdict: None,
            evidence_refs: subject.evidence.clone(),
            gaps: vec![json!({
                "kind": if required { "required-reviewer-unavailable" } else { "reasoning-disabled" }
            })],
        })
        .collect();
    // Mirrors: subjects.length===0 || (!required && mode==='disabled')
    let complete = subjects.is_empty() || (!required && mode == "disabled");
    Ok(AdjudicationResult {
        complete,
        receipts,
        packets: Vec::new(),
    })
}

/// Mirrors `validateJudgmentReceipt(receipt, expectedBinding)`.
pub fn validate_judgment_receipt(
    receipt: &JudgmentReceipt,
    expected_binding: Option<&Value>,
) -> Result<(), &'static str> {
    if receipt.schema_version != 1 || receipt.kind != "legion-judgment-receipt" {
        return Err("invalid judgment receipt");
    }
    if !same_binding(receipt.binding.as_ref(), expected_binding) {
        return Err("judgment receipt binding mismatch");
    }
    if receipt.complete {
        let ok = matches!(
            receipt.verdict.as_ref().and_then(Value::as_str),
            Some("confirmed") | Some("rejected") | Some("unproven") | Some("needs-human")
        );
        if !ok {
            return Err("complete judgment receipt requires verdict");
        }
    }
    // evidenceRefs/gaps are already `Vec<Value>` here, so the JS
    // `Array.isArray` checks are guaranteed by the type system.
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn subject(id: i64, evidence: Vec<Value>) -> Subject {
        Subject {
            id: json!(id),
            evidence,
        }
    }

    #[test]
    fn unknown_mode_is_rejected() {
        let err = adjudicate_subjects_without_reviewer(&[], "bogus", None, None, false)
            .unwrap_err();
        assert_eq!(err.to_string(), "unknown reasoning mode: bogus");
    }

    #[test]
    fn disabled_mode_produces_skipped_receipts_and_is_complete() {
        let subjects = vec![subject(1, vec![json!("ev-1")])];
        let result =
            adjudicate_subjects_without_reviewer(&subjects, "disabled", None, None, false)
                .unwrap();
        assert!(result.complete);
        assert_eq!(result.receipts.len(), 1);
        let receipt = &result.receipts[0];
        assert_eq!(receipt.status, "skipped");
        assert!(!receipt.complete);
        assert_eq!(receipt.context_id, "review-0");
        assert_eq!(receipt.gaps, vec![json!({"kind": "reasoning-disabled"})]);
        assert_eq!(receipt.evidence_refs, vec![json!("ev-1")]);
    }

    #[test]
    fn required_mode_with_no_reviewer_is_unproven_and_not_complete() {
        let subjects = vec![subject(1, vec![])];
        let result =
            adjudicate_subjects_without_reviewer(&subjects, "required", None, None, false)
                .unwrap();
        assert!(!result.complete);
        let receipt = &result.receipts[0];
        assert_eq!(receipt.status, "unproven");
        assert_eq!(
            receipt.gaps,
            vec![json!({"kind": "required-reviewer-unavailable"})]
        );
    }

    #[test]
    fn empty_subjects_is_always_complete() {
        let result =
            adjudicate_subjects_without_reviewer(&[], "required", None, None, false).unwrap();
        assert!(result.complete);
        assert!(result.receipts.is_empty());
    }

    #[test]
    fn context_prefix_defaults_to_review() {
        let subjects = vec![subject(1, vec![]), subject(2, vec![])];
        let result =
            adjudicate_subjects_without_reviewer(&subjects, "disabled", None, None, false)
                .unwrap();
        assert_eq!(result.receipts[0].context_id, "review-0");
        assert_eq!(result.receipts[1].context_id, "review-1");
    }

    #[test]
    fn context_prefix_is_honored_when_supplied() {
        let subjects = vec![subject(1, vec![])];
        let result = adjudicate_subjects_without_reviewer(
            &subjects,
            "disabled",
            None,
            Some("audit"),
            false,
        )
        .unwrap();
        assert_eq!(result.receipts[0].context_id, "audit-0");
    }

    #[test]
    fn binding_is_carried_onto_every_receipt() {
        let binding = json!({"rev": "abc"});
        let subjects = vec![subject(1, vec![])];
        let result = adjudicate_subjects_without_reviewer(
            &subjects,
            "disabled",
            Some(&binding),
            None,
            false,
        )
        .unwrap();
        assert_eq!(result.receipts[0].binding, Some(binding));
    }

    fn base_receipt() -> JudgmentReceipt {
        JudgmentReceipt {
            schema_version: 1,
            kind: "legion-judgment-receipt".to_string(),
            subject_id: json!(1),
            status: "confirmed".to_string(),
            complete: true,
            binding: Some(json!({"rev": "abc"})),
            context_id: "review-0".to_string(),
            reviewer: None,
            verdict: Some(json!("confirmed")),
            evidence_refs: vec![],
            gaps: vec![],
        }
    }

    #[test]
    fn validate_accepts_a_well_formed_complete_receipt() {
        let receipt = base_receipt();
        let expected = json!({"rev": "abc"});
        assert!(validate_judgment_receipt(&receipt, Some(&expected)).is_ok());
    }

    #[test]
    fn validate_rejects_wrong_schema_version() {
        let mut receipt = base_receipt();
        receipt.schema_version = 2;
        let expected = json!({"rev": "abc"});
        assert_eq!(
            validate_judgment_receipt(&receipt, Some(&expected)),
            Err("invalid judgment receipt")
        );
    }

    #[test]
    fn validate_rejects_wrong_kind() {
        let mut receipt = base_receipt();
        receipt.kind = "something-else".to_string();
        let expected = json!({"rev": "abc"});
        assert_eq!(
            validate_judgment_receipt(&receipt, Some(&expected)),
            Err("invalid judgment receipt")
        );
    }

    #[test]
    fn validate_rejects_binding_mismatch() {
        let receipt = base_receipt();
        let expected = json!({"rev": "different"});
        assert_eq!(
            validate_judgment_receipt(&receipt, Some(&expected)),
            Err("judgment receipt binding mismatch")
        );
    }

    #[test]
    fn validate_requires_verdict_when_complete() {
        let mut receipt = base_receipt();
        receipt.verdict = None;
        let expected = json!({"rev": "abc"});
        assert_eq!(
            validate_judgment_receipt(&receipt, Some(&expected)),
            Err("complete judgment receipt requires verdict")
        );
    }

    #[test]
    fn validate_rejects_unknown_verdict_when_complete() {
        let mut receipt = base_receipt();
        receipt.verdict = Some(json!("maybe"));
        let expected = json!({"rev": "abc"});
        assert_eq!(
            validate_judgment_receipt(&receipt, Some(&expected)),
            Err("complete judgment receipt requires verdict")
        );
    }

    #[test]
    fn validate_allows_missing_verdict_when_not_complete() {
        let mut receipt = base_receipt();
        receipt.complete = false;
        receipt.verdict = None;
        let expected = json!({"rev": "abc"});
        assert!(validate_judgment_receipt(&receipt, Some(&expected)).is_ok());
    }

    #[test]
    fn validate_accepts_every_known_verdict() {
        for verdict in ["confirmed", "rejected", "unproven", "needs-human"] {
            let mut receipt = base_receipt();
            receipt.verdict = Some(json!(verdict));
            let expected = json!({"rev": "abc"});
            assert!(validate_judgment_receipt(&receipt, Some(&expected)).is_ok());
        }
    }
}
