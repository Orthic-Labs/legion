//! Port of `src/lib/core/adjudicate-run.mjs`, extended under packet r44 to
//! close the gap w2_039 left open.
//!
//! Ported in full (w2_039): `validateJudgmentReceipt`, the `MODES` set, and
//! the `adjudicateSubjects` code path taken when reasoning is `'disabled'`
//! or no reviewer is available (the branch that never calls
//! `prepareAdjudication`).
//!
//! Ported in full (packet r44): `prepareAdjudication` and the
//! reviewer-available branch of `adjudicateSubjects`. Both call
//! `buildJudgmentPacket` (`src/lib/core/judgment-packets.mjs`, one function,
//! see [`build_judgment_packet`]) and `reviewerPolicy`
//! (`src/lib/core/reviewer-policy.mjs`, one function, see
//! [`reviewer_policy`]) — neither file has any further dependency, so both
//! are ported alongside `adjudicate-run.mjs` itself rather than left as a
//! separate chunk. The JS `review.call(host.reviewer, packet, reviewPolicy)`
//! host call is modeled as the [`Reviewer`] trait so it can be exercised
//! with a fake in tests, matching the async host call the JS makes.

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

/// Mirrors `buildJudgmentPacket({subject, evidence, omitted, reviewerRole,
/// budget, lens})` from `src/lib/core/judgment-packets.mjs`.
#[derive(Clone, Debug)]
pub struct JudgmentPacket {
    pub schema_version: u32,
    pub subject: Value,
    pub evidence: Vec<Value>,
    pub omitted: Vec<Value>,
    pub reviewer_role: Value,
    pub lens: Option<Value>,
    pub verdicts: [&'static str; 4],
    pub budget: Value,
}

impl JudgmentPacket {
    pub fn to_json(&self) -> Value {
        let mut obj = serde_json::Map::new();
        obj.insert("schemaVersion".into(), json!(self.schema_version));
        obj.insert("subject".into(), self.subject.clone());
        obj.insert("evidence".into(), json!(self.evidence));
        obj.insert("omitted".into(), json!(self.omitted));
        obj.insert("reviewerRole".into(), self.reviewer_role.clone());
        if let Some(lens) = &self.lens {
            obj.insert("lens".into(), lens.clone());
        }
        obj.insert("verdicts".into(), json!(self.verdicts));
        obj.insert("budget".into(), self.budget.clone());
        Value::Object(obj)
    }
}

/// Mirrors `buildJudgmentPacket`. `subject` is deep-cloned via JSON
/// round-trip in JS (`JSON.parse(JSON.stringify(subject ?? null))`); `Value`
/// clone in Rust is already an equivalent deep copy.
pub fn build_judgment_packet(
    subject: Option<&Value>,
    evidence: Vec<Value>,
    omitted: Vec<Value>,
    reviewer_role: Value,
    budget: Value,
    lens: Option<Value>,
) -> JudgmentPacket {
    JudgmentPacket {
        schema_version: 1,
        subject: subject.cloned().unwrap_or(Value::Null),
        evidence,
        omitted,
        reviewer_role,
        lens,
        verdicts: ["confirmed", "rejected", "unproven", "needs-human"],
        budget,
    }
}

/// Mirrors the object `reviewerPolicy(...)` returns from
/// `src/lib/core/reviewer-policy.mjs`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReviewerPolicy {
    pub producer: Value,
    pub reviewer: Value,
    pub context_id: String,
    pub fresh: bool,
}

/// Error mirroring the two `throw new TypeError(...)` in `reviewerPolicy`.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ReviewerPolicyError {
    #[error("reviewer self-adjudication forbidden")]
    SelfAdjudication,
    #[error("reviewer context reuse forbidden")]
    ContextReuse,
}

/// Mirrors `reviewerPolicy({producer, reviewer, contextId, usedContexts})`.
pub fn reviewer_policy(
    producer: &Value,
    reviewer: &Value,
    context_id: &str,
    used_contexts: &[String],
) -> Result<ReviewerPolicy, ReviewerPolicyError> {
    if producer == reviewer {
        return Err(ReviewerPolicyError::SelfAdjudication);
    }
    if used_contexts.iter().any(|c| c == context_id) {
        return Err(ReviewerPolicyError::ContextReuse);
    }
    Ok(ReviewerPolicy {
        producer: producer.clone(),
        reviewer: reviewer.clone(),
        context_id: context_id.to_string(),
        fresh: true,
    })
}

/// One subject as `prepareAdjudication`/the reviewer-enabled
/// `adjudicateSubjects` branch reads it: `{ id, evidence }` (same shape as
/// [`Subject`]) plus the packet-building extras the JS reads straight off
/// `subject`.
pub type AdjudicationSubject = Subject;

/// Policy fields `prepareAdjudication`/`adjudicateSubjects` read: mirrors
/// the `policy` object spread through both functions.
#[derive(Clone, Debug)]
pub struct AdjudicationPolicy {
    pub mode: String,
    pub producer: Value,
    pub reviewer: Value,
    pub context_prefix: Option<String>,
    pub budget: Value,
    pub used_contexts: Vec<String>,
}

/// Mirrors one element of the array `prepareAdjudication` returns.
pub struct Prepared {
    pub policy: ReviewerPolicy,
    pub packet: JudgmentPacket,
}

/// Mirrors `prepareAdjudication(subjects, policy)`.
pub fn prepare_adjudication(
    subjects: &[AdjudicationSubject],
    policy: &AdjudicationPolicy,
) -> Result<Vec<Prepared>, ReviewerPolicyError> {
    subjects
        .iter()
        .enumerate()
        .map(|(index, subject)| {
            let prefix = policy.context_prefix.as_deref().unwrap_or("review");
            let context_id = format!("{prefix}-{index}");
            let review_policy = reviewer_policy(
                &policy.producer,
                &policy.reviewer,
                &context_id,
                &policy.used_contexts,
            )?;
            let packet = build_judgment_packet(
                Some(&subject_to_value(subject)),
                subject.evidence.clone(),
                Vec::new(),
                policy.reviewer.clone(),
                policy.budget.clone(),
                None,
            );
            Ok(Prepared {
                policy: review_policy,
                packet,
            })
        })
        .collect()
}

fn subject_to_value(subject: &Subject) -> Value {
    json!({ "id": subject.id, "evidence": subject.evidence })
}

/// The value a reviewer call returns, mirroring the shape `value` reads in
/// `adjudicateSubjects`: `{status, complete, verdict, gaps}`.
#[derive(Clone, Debug, Default)]
pub struct ReviewValue {
    pub status: Option<String>,
    pub complete: bool,
    pub verdict: Option<Value>,
    pub gaps: Vec<Value>,
}

/// Mirrors `review.call(host.reviewer, packet, reviewPolicy)`. Modeled as a
/// trait (rather than a bare closure) so a fake implementation can be
/// supplied in tests without any network or process I/O, matching the rule
/// that host calls are ported behind a trait.
pub trait Reviewer {
    fn review(&self, packet: &JudgmentPacket, policy: &ReviewerPolicy) -> ReviewValue;
}

/// Error mirroring both `throw` sites the reviewer-enabled branch of
/// `adjudicateSubjects` can hit: `reviewerPolicy`'s two TypeErrors
/// (propagated via [`ReviewerPolicyError`]) plus
/// `validateJudgmentReceipt`'s TypeError on a malformed reviewer response.
#[derive(Debug, thiserror::Error)]
pub enum AdjudicateWithReviewerError {
    #[error(transparent)]
    ReviewerPolicy(#[from] ReviewerPolicyError),
    #[error("invalid judgment receipt from reviewer: {0}")]
    InvalidReceipt(&'static str),
}

/// Mirrors the reviewer-enabled branch of `adjudicateSubjects` (the tail
/// end, once `prepareAdjudication` has run and `review` is callable).
pub fn adjudicate_subjects_with_reviewer(
    subjects: &[AdjudicationSubject],
    policy: &AdjudicationPolicy,
    reviewer_id: &Value,
    binding: Option<&Value>,
    reviewer: &dyn Reviewer,
) -> Result<(AdjudicationResult, Vec<JudgmentPacket>), AdjudicateWithReviewerError> {
    // Mirrors: prepareAdjudication(subjects, {...policy, reviewer: policy.reviewer ?? host.reviewer.id})
    let mut effective_policy = policy.clone();
    if effective_policy.reviewer.is_null() {
        effective_policy.reviewer = reviewer_id.clone();
    }
    let prepared = prepare_adjudication(subjects, &effective_policy)?;
    let mut receipts = Vec::with_capacity(prepared.len());
    let mut packets = Vec::with_capacity(prepared.len());
    for Prepared {
        policy: review_policy,
        packet,
    } in prepared
    {
        let value = reviewer.review(&packet, &review_policy);
        let receipt = JudgmentReceipt {
            schema_version: 1,
            kind: "legion-judgment-receipt".to_string(),
            subject_id: packet
                .subject
                .get("id")
                .cloned()
                .unwrap_or(Value::Null),
            status: value.status.clone().unwrap_or_else(|| "unproven".to_string()),
            complete: value.complete,
            binding: binding.cloned(),
            context_id: review_policy.context_id.clone(),
            reviewer: Some(review_policy.reviewer.clone()),
            verdict: value.verdict.clone(),
            evidence_refs: packet.evidence.clone(),
            gaps: value.gaps.clone(),
        };
        validate_judgment_receipt(&receipt, binding)
            .map_err(AdjudicateWithReviewerError::InvalidReceipt)?;
        packets.push(packet);
        receipts.push(receipt);
    }
    let complete = receipts.iter().all(|r| r.complete);
    Ok((
        AdjudicationResult {
            complete,
            receipts,
            packets: Vec::new(),
        },
        packets,
    ))
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

    // -- packet r44: build_judgment_packet / reviewer_policy / prepare_adjudication / adjudicate_subjects_with_reviewer --

    #[test]
    fn build_judgment_packet_defaults_and_shape() {
        let packet = build_judgment_packet(
            Some(&json!({"id": 1})),
            vec![json!("ev-1")],
            vec![],
            json!("sage"),
            json!(100),
            None,
        );
        assert_eq!(packet.schema_version, 1);
        assert_eq!(packet.subject, json!({"id": 1}));
        assert_eq!(packet.evidence, vec![json!("ev-1")]);
        assert!(packet.omitted.is_empty());
        assert_eq!(packet.reviewer_role, json!("sage"));
        assert!(packet.lens.is_none());
        assert_eq!(packet.verdicts, ["confirmed", "rejected", "unproven", "needs-human"]);
        assert_eq!(packet.budget, json!(100));
        assert!(packet.to_json().get("lens").is_none());
    }

    #[test]
    fn build_judgment_packet_includes_lens_when_present() {
        let packet = build_judgment_packet(
            None,
            vec![],
            vec![],
            json!("sage"),
            json!(null),
            Some(json!({"scope": "x"})),
        );
        assert_eq!(packet.subject, Value::Null);
        assert_eq!(packet.to_json().get("lens"), Some(&json!({"scope": "x"})));
    }

    #[test]
    fn reviewer_policy_rejects_self_adjudication() {
        let producer = json!("legion");
        let err = reviewer_policy(&producer, &producer, "review-0", &[]).unwrap_err();
        assert_eq!(err, ReviewerPolicyError::SelfAdjudication);
    }

    #[test]
    fn reviewer_policy_rejects_context_reuse() {
        let producer = json!("legion");
        let reviewer = json!("sage");
        let used = vec!["review-0".to_string()];
        let err = reviewer_policy(&producer, &reviewer, "review-0", &used).unwrap_err();
        assert_eq!(err, ReviewerPolicyError::ContextReuse);
    }

    #[test]
    fn reviewer_policy_succeeds_with_fresh_context() {
        let producer = json!("legion");
        let reviewer = json!("sage");
        let policy = reviewer_policy(&producer, &reviewer, "review-0", &[]).unwrap();
        assert_eq!(policy.producer, producer);
        assert_eq!(policy.reviewer, reviewer);
        assert_eq!(policy.context_id, "review-0");
        assert!(policy.fresh);
    }

    fn adjudication_subject(id: i64, evidence: Vec<Value>) -> AdjudicationSubject {
        Subject { id: json!(id), evidence }
    }

    fn base_policy() -> AdjudicationPolicy {
        AdjudicationPolicy {
            mode: "auto".to_string(),
            producer: json!("legion"),
            reviewer: json!("sage"),
            context_prefix: None,
            budget: json!(100),
            used_contexts: vec![],
        }
    }

    #[test]
    fn prepare_adjudication_builds_one_prepared_entry_per_subject() {
        let subjects = vec![
            adjudication_subject(1, vec![json!("ev-1")]),
            adjudication_subject(2, vec![]),
        ];
        let policy = base_policy();
        let prepared = prepare_adjudication(&subjects, &policy).unwrap();
        assert_eq!(prepared.len(), 2);
        assert_eq!(prepared[0].policy.context_id, "review-0");
        assert_eq!(prepared[1].policy.context_id, "review-1");
        assert_eq!(prepared[0].packet.evidence, vec![json!("ev-1")]);
        assert_eq!(prepared[0].packet.reviewer_role, json!("sage"));
    }

    #[test]
    fn prepare_adjudication_honors_context_prefix() {
        let subjects = vec![adjudication_subject(1, vec![])];
        let mut policy = base_policy();
        policy.context_prefix = Some("audit".to_string());
        let prepared = prepare_adjudication(&subjects, &policy).unwrap();
        assert_eq!(prepared[0].policy.context_id, "audit-0");
    }

    #[test]
    fn prepare_adjudication_propagates_self_adjudication_error() {
        let subjects = vec![adjudication_subject(1, vec![])];
        let mut policy = base_policy();
        policy.reviewer = policy.producer.clone();
        let err = prepare_adjudication(&subjects, &policy).unwrap_err();
        assert_eq!(err, ReviewerPolicyError::SelfAdjudication);
    }

    struct FakeReviewer(ReviewValue);
    impl Reviewer for FakeReviewer {
        fn review(&self, _packet: &JudgmentPacket, _policy: &ReviewerPolicy) -> ReviewValue {
            self.0.clone()
        }
    }

    #[test]
    fn adjudicate_with_reviewer_produces_complete_receipt_on_confirmed_verdict() {
        let subjects = vec![adjudication_subject(1, vec![json!("ev-1")])];
        let policy = base_policy();
        let reviewer_id = json!("sage");
        let binding = json!({"rev": "abc"});
        let fake = FakeReviewer(ReviewValue {
            status: Some("pass".to_string()),
            complete: true,
            verdict: Some(json!("confirmed")),
            gaps: vec![],
        });
        let (result, packets) = adjudicate_subjects_with_reviewer(
            &subjects,
            &policy,
            &reviewer_id,
            Some(&binding),
            &fake,
        )
        .unwrap();
        assert!(result.complete);
        assert_eq!(result.receipts.len(), 1);
        let receipt = &result.receipts[0];
        assert_eq!(receipt.status, "pass");
        assert!(receipt.complete);
        assert_eq!(receipt.verdict, Some(json!("confirmed")));
        assert_eq!(receipt.binding, Some(binding));
        assert_eq!(receipt.reviewer, Some(json!("sage")));
        assert_eq!(packets.len(), 1);
    }

    #[test]
    fn adjudicate_with_reviewer_defaults_missing_reviewer_to_host_id() {
        let subjects = vec![adjudication_subject(1, vec![])];
        let mut policy = base_policy();
        policy.reviewer = Value::Null;
        let reviewer_id = json!("host-sage");
        let fake = FakeReviewer(ReviewValue {
            status: Some("skipped".to_string()),
            complete: false,
            verdict: None,
            gaps: vec![],
        });
        let (result, _) =
            adjudicate_subjects_with_reviewer(&subjects, &policy, &reviewer_id, None, &fake)
                .unwrap();
        assert_eq!(result.receipts[0].reviewer, Some(json!("host-sage")));
        assert!(!result.complete);
    }

    #[test]
    fn adjudicate_with_reviewer_completeness_requires_every_receipt_complete() {
        let subjects = vec![
            adjudication_subject(1, vec![]),
            adjudication_subject(2, vec![]),
        ];
        let policy = base_policy();
        let reviewer_id = json!("sage");
        let fake = FakeReviewer(ReviewValue {
            status: Some("pass".to_string()),
            complete: true,
            verdict: Some(json!("confirmed")),
            gaps: vec![],
        });
        let (result, _) =
            adjudicate_subjects_with_reviewer(&subjects, &policy, &reviewer_id, None, &fake)
                .unwrap();
        assert!(result.complete);
        assert_eq!(result.receipts.len(), 2);
    }

    #[test]
    fn adjudicate_with_reviewer_rejects_complete_receipt_without_verdict() {
        let subjects = vec![adjudication_subject(1, vec![])];
        let policy = base_policy();
        let reviewer_id = json!("sage");
        let fake = FakeReviewer(ReviewValue {
            status: Some("pass".to_string()),
            complete: true,
            verdict: None,
            gaps: vec![],
        });
        let err =
            adjudicate_subjects_with_reviewer(&subjects, &policy, &reviewer_id, None, &fake)
                .unwrap_err();
        assert!(matches!(
            err,
            AdjudicateWithReviewerError::InvalidReceipt("complete judgment receipt requires verdict")
        ));
    }
}
