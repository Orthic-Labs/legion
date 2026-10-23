//! Verified crash-safe resume of the deterministic provider pass (CP section 12).
//!
//! Resume is a proof operation, not "continue from whatever files exist". The
//! journal, the persisted provider receipts and the frozen plan must agree.
//! Any disagreement refuses the resume with reasons; nothing runs and nothing
//! is appended. Receipts are supplied already loaded (and signature-checked by
//! the caller); this module only reconciles them against the journal.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use serde::Serialize;

use crate::error::AuditError;
use crate::journal::{
    gap_payload_digest, verify_dir, AuditEvent, EventKind, Expectation, Journal, SealedHead,
};

/// A persisted provider receipt as the caller read it from the run directory.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReceiptRecord {
    pub provider: String,
    /// Plan digest the receipt was produced under.
    pub plan_digest: String,
    /// Canonical digest of the receipt; must equal the `provider_finished`
    /// payload digest.
    pub receipt_digest: String,
    /// False when the caller could not verify the receipt's own integrity.
    pub verified: bool,
}

#[derive(Clone, Debug, Default)]
pub struct ResumeInput {
    /// Frozen (original) plan digest.
    pub plan_digest: String,
    /// Final plan digest after amendments, when the run applied any.
    pub effective_plan_digest: Option<String>,
    /// Providers of the frozen plan, in plan order.
    pub planned_providers: Vec<String>,
    pub receipts: Vec<ReceiptRecord>,
    /// Providers safe to run twice. Anything else interrupted becomes a gap.
    pub idempotent: BTreeSet<String>,
    /// Failed providers the frozen retry policy still permits retrying.
    pub retry_allowed: BTreeSet<String>,
    /// Head recorded outside the journal directory (for example in a report).
    pub expected_head: Option<SealedHead>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "decision", rename_all = "snake_case")]
pub enum ResumeDecision {
    /// Completed with a matching verified receipt: do not rerun.
    Reuse { receipt_digest: String },
    /// Never started: run normally.
    Run,
    /// Started, never finished, idempotent: run again.
    Rerun { reason: String },
    /// Started, never finished, not idempotent: explicit gap, never rerun.
    Gap { reason: String },
    /// Terminal failure the frozen policy does not allow retrying.
    KeepFailed,
    /// Skipped by the original run.
    KeepSkipped,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ResumePlan {
    pub decisions: BTreeMap<String, ResumeDecision>,
    /// Receipts present on disk with no matching finish event. Ignored for
    /// proof and reported.
    pub orphan_receipts: Vec<String>,
    pub prior_head: SealedHead,
    pub prior_event_count: u64,
}

impl ResumePlan {
    pub fn reused(&self) -> BTreeSet<String> {
        self.decisions
            .iter()
            .filter(|(_, d)| matches!(d, ResumeDecision::Reuse { .. }))
            .map(|(p, _)| p.clone())
            .collect()
    }

    pub fn gaps(&self) -> Vec<String> {
        self.decisions
            .iter()
            .filter(|(_, d)| matches!(d, ResumeDecision::Gap { .. }))
            .map(|(p, _)| p.clone())
            .collect()
    }

    pub fn digest(&self) -> Result<String, AuditError> {
        legion_contracts::canonical_digest(self).map_err(|e| AuditError::Invalid(e.to_string()))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResumeRefusal {
    pub reasons: Vec<String>,
}

impl std::fmt::Display for ResumeRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "resume refused: {}", self.reasons.join("; "))
    }
}

impl std::error::Error for ResumeRefusal {}

#[derive(Debug)]
enum ProviderState {
    Started,
    Finished(String),
    Failed,
    Skipped,
}

fn provider_states(events: &[AuditEvent]) -> BTreeMap<String, ProviderState> {
    let mut states = BTreeMap::new();
    for event in events {
        let state = match event.kind {
            EventKind::ProviderStarted => ProviderState::Started,
            EventKind::ProviderFinished => ProviderState::Finished(event.payload_digest.clone()),
            EventKind::ProviderFailed => ProviderState::Failed,
            EventKind::ProviderSkipped => ProviderState::Skipped,
            _ => continue,
        };
        states.insert(event.subject.clone(), state);
    }
    states
}

/// Reconcile journal, receipts and plan without writing anything.
pub fn plan_resume(dir: &Path, input: &ResumeInput) -> Result<ResumePlan, ResumeRefusal> {
    let mut reasons = Vec::new();
    let expect = Expectation {
        require_finalized: false,
        expected_head: input.expected_head.clone(),
        final_plan_digest: input.effective_plan_digest.clone(),
    };
    let verification = verify_dir(dir, &input.plan_digest, &expect);
    for defect in &verification.defects {
        reasons.push(format!("journal: {defect}"));
    }
    if verification.events.is_empty() && verification.defects.is_empty() {
        reasons.push("journal is empty".to_owned());
    }
    if verification.finalized {
        reasons.push("run is already finalized; nothing to resume".to_owned());
    }
    let effective = verification
        .effective_plan_digest
        .clone()
        .unwrap_or_else(|| input.plan_digest.clone());

    let planned: BTreeSet<&str> = input.planned_providers.iter().map(String::as_str).collect();
    if planned.len() != input.planned_providers.len() {
        reasons.push("planned provider list contains duplicates".to_owned());
    }
    let states = provider_states(&verification.events);
    for provider in states.keys() {
        if !planned.contains(provider.as_str()) {
            reasons.push(format!(
                "journal names provider {provider} outside the frozen plan"
            ));
        }
    }

    let mut receipts: BTreeMap<&str, &ReceiptRecord> = BTreeMap::new();
    for receipt in &input.receipts {
        if receipts
            .insert(receipt.provider.as_str(), receipt)
            .is_some()
        {
            reasons.push(format!(
                "duplicate receipts for provider {}",
                receipt.provider
            ));
        }
        if !planned.contains(receipt.provider.as_str()) {
            reasons.push(format!(
                "receipt for provider {} is outside the frozen plan",
                receipt.provider
            ));
        }
    }

    let mut decisions = BTreeMap::new();
    let mut orphans = Vec::new();
    for provider in &input.planned_providers {
        let receipt = receipts.get(provider.as_str()).copied();
        let decision = match states.get(provider) {
            None => {
                if receipt.is_some() {
                    orphans.push(provider.clone());
                }
                ResumeDecision::Run
            }
            Some(ProviderState::Finished(payload)) => match receipt {
                None => {
                    reasons.push(format!(
                        "provider {provider} finished in the journal but its receipt is missing"
                    ));
                    continue;
                }
                Some(receipt) => {
                    if !receipt.verified {
                        reasons.push(format!("receipt for {provider} failed verification"));
                    }
                    if receipt.receipt_digest != *payload {
                        reasons.push(format!(
                            "receipt for {provider} does not match the journaled digest"
                        ));
                    }
                    if receipt.plan_digest != input.plan_digest && receipt.plan_digest != effective
                    {
                        reasons.push(format!(
                            "receipt for {provider} belongs to a different plan"
                        ));
                    }
                    ResumeDecision::Reuse {
                        receipt_digest: payload.clone(),
                    }
                }
            },
            Some(ProviderState::Started) => {
                if receipt.is_some() {
                    orphans.push(provider.clone());
                }
                if input.idempotent.contains(provider) {
                    ResumeDecision::Rerun {
                        reason: "started without finish; provider is idempotent".to_owned(),
                    }
                } else {
                    ResumeDecision::Gap {
                        reason: "started without finish; provider is not idempotent".to_owned(),
                    }
                }
            }
            Some(ProviderState::Failed) => {
                if input.retry_allowed.contains(provider) {
                    ResumeDecision::Rerun {
                        reason: "failed; frozen retry policy permits another attempt".to_owned(),
                    }
                } else {
                    ResumeDecision::KeepFailed
                }
            }
            Some(ProviderState::Skipped) => ResumeDecision::KeepSkipped,
        };
        decisions.insert(provider.clone(), decision);
    }

    if !reasons.is_empty() {
        return Err(ResumeRefusal { reasons });
    }
    let prior_head = verification.head.clone().unwrap_or(SealedHead {
        plan_digest: input.plan_digest.clone(),
        sequence: 0,
        digest: None,
        finalized: false,
    });
    Ok(ResumePlan {
        decisions,
        orphan_receipts: orphans,
        prior_head,
        prior_event_count: verification.events.len() as u64,
    })
}

/// Verify, lock and append the `run_resumed` event plus an explicit failure
/// event closing every gap. Returns the open journal and the plan. The
/// journal's effective plan must equal `effective_plan_digest` when given.
pub fn resume(
    dir: &Path,
    input: &ResumeInput,
    at: u64,
) -> Result<(Journal, ResumePlan), ResumeRefusal> {
    let plan = plan_resume(dir, input)?;
    let refuse = |error: AuditError| ResumeRefusal {
        reasons: vec![error.to_string()],
    };
    let mut journal = Journal::open(dir, &input.plan_digest).map_err(refuse)?;
    // Re-check under the lock: the head must still be what was just reconciled.
    if journal.events().len() as u64 != plan.prior_event_count {
        return Err(ResumeRefusal {
            reasons: vec!["journal changed between reconciliation and lock".to_owned()],
        });
    }
    let payload = plan.digest().map_err(refuse)?;
    journal
        .append(EventKind::RunResumed, "run", &payload, at)
        .map_err(refuse)?;
    for provider in plan.gaps() {
        journal
            .append(
                EventKind::ProviderFailed,
                &provider,
                &gap_payload_digest(&provider),
                at,
            )
            .map_err(refuse)?;
    }
    Ok((journal, plan))
}
