//! Verified crash-safe resume of the deterministic provider pass (CP section 12).
//!
//! Resume is a proof operation, not "continue from whatever files exist". The
//! journal, the persisted provider receipts and the frozen plan must agree.
//! Any disagreement refuses the resume with reasons; nothing runs and nothing
//! is appended. Receipts are supplied already loaded (and signature-checked by
//! the caller); this module only reconciles them against the journal.

use std::collections::{BTreeMap, BTreeSet};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard};

use serde::{Deserialize, Serialize};

use crate::error::AuditError;
use crate::execution::ProviderExecution;
use crate::journal::{
    domain_mac, domain_mac_verify, gap_payload_digest, interrupted_payload_digest, now_ms,
    verify_dir, AuditEvent, EventKind, Expectation, Journal, JournalAnchor, SealedHead,
};
use crate::scheduler::SchedulerConfig;

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
    let states = provider_states(journal.events());
    journal
        .append(EventKind::RunResumed, "run", &payload, at)
        .map_err(refuse)?;
    // A provider that was started and never finished is closed explicitly
    // before it can be started again: the journal never shows two open starts.
    for (provider, decision) in &plan.decisions {
        if matches!(decision, ResumeDecision::Rerun { .. })
            && matches!(states.get(provider), Some(ProviderState::Started))
        {
            journal
                .append(
                    EventKind::ProviderFailed,
                    provider,
                    &interrupted_payload_digest(provider),
                    at,
                )
                .map_err(refuse)?;
        }
    }
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

// ---------------------------------------------------------------------------
// Signed provider receipts and the run recorder (execution wiring)
// ---------------------------------------------------------------------------

pub const RECEIPT_DIR: &str = "provider-receipts";
pub const RECEIPT_FORMAT: &str = "audit-provider-receipt/v1";
const RECEIPT_DOMAIN: &[u8] = b"legion-audit-provider-receipt-v1\0";

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReceiptBody {
    pub format: String,
    pub provider: String,
    pub plan_digest: String,
    /// `finished`, `failed`, `skipped` or `not-applicable`.
    pub outcome: String,
    pub attempts: u32,
    pub execution: ProviderExecution,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StoredReceipt {
    pub body: ReceiptBody,
    /// Canonical digest of `body`; the journal event's payload digest.
    pub digest: String,
    /// HMAC under the run's plan key over provider, plan and digest.
    pub signature: String,
}

fn plain_provider(provider: &str) -> bool {
    !provider.is_empty()
        && provider.len() <= 128
        && provider
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.')
        && !provider.starts_with('.')
}

pub fn receipt_path(dir: &Path, provider: &str) -> Result<PathBuf, AuditError> {
    if !plain_provider(provider) {
        return Err(AuditError::Invalid(format!(
            "provider id {provider:?} cannot name a receipt file"
        )));
    }
    Ok(dir.join(RECEIPT_DIR).join(format!("{provider}.json")))
}

fn receipt_signed_bytes(body: &ReceiptBody, digest: &str) -> Result<Vec<u8>, AuditError> {
    legion_contracts::canonical_json_bytes(&serde_json::json!({
        "provider": body.provider,
        "planDigest": body.plan_digest,
        "digest": digest,
    }))
    .map_err(|e| AuditError::Invalid(e.to_string()))
}

/// Write a signed receipt atomically (tmp + fsync + rename) and return its digest.
pub fn write_receipt(dir: &Path, key: &[u8], body: ReceiptBody) -> Result<String, AuditError> {
    let path = receipt_path(dir, &body.provider)?;
    let parent = path
        .parent()
        .ok_or_else(|| AuditError::Invalid("receipt path has no parent".into()))?;
    std::fs::create_dir_all(parent)
        .map_err(|e| AuditError::Invalid(format!("receipt dir: {e}")))?;
    let digest = legion_contracts::canonical_digest(&body)
        .map_err(|e| AuditError::Invalid(e.to_string()))?;
    let signature = domain_mac(key, RECEIPT_DOMAIN, &receipt_signed_bytes(&body, &digest)?)?;
    let stored = StoredReceipt {
        body,
        digest: digest.clone(),
        signature,
    };
    let bytes = serde_json::to_vec(&stored).map_err(|e| AuditError::Invalid(e.to_string()))?;
    let tmp = parent.join(format!(".{}.tmp", stored.body.provider));
    let mut file = std::fs::File::create(&tmp)
        .map_err(|e| AuditError::Invalid(format!("receipt create: {e}")))?;
    file.write_all(&bytes)
        .and_then(|_| file.sync_all())
        .map_err(|e| AuditError::Invalid(format!("receipt write: {e}")))?;
    std::fs::rename(&tmp, &path)
        .map_err(|e| AuditError::Invalid(format!("receipt rename: {e}")))?;
    Ok(digest)
}

/// Read a receipt and check name, content digest and signature. Any problem is
/// an `Err` naming the reason; a receipt that does not verify is never used.
pub fn read_verified_receipt(
    dir: &Path,
    provider: &str,
    key: &[u8],
) -> Result<StoredReceipt, String> {
    let path = receipt_path(dir, provider).map_err(|e| e.to_string())?;
    let bytes = std::fs::read(&path).map_err(|e| format!("{}: {e}", path.display()))?;
    let stored: StoredReceipt =
        serde_json::from_slice(&bytes).map_err(|e| format!("receipt is malformed: {e}"))?;
    if stored.body.format != RECEIPT_FORMAT {
        return Err("receipt format is unsupported".into());
    }
    if stored.body.provider != provider {
        return Err("receipt names a different provider".into());
    }
    let digest = legion_contracts::canonical_digest(&stored.body)
        .map_err(|e| format!("receipt digest: {e}"))?;
    if digest != stored.digest {
        return Err("receipt content does not match its digest".into());
    }
    let signed = receipt_signed_bytes(&stored.body, &stored.digest).map_err(|e| e.to_string())?;
    if !domain_mac_verify(key, RECEIPT_DOMAIN, &signed, &stored.signature) {
        return Err("receipt signature does not verify under the run plan key".into());
    }
    Ok(stored)
}

/// Load every receipt file in the run as a [`ReceiptRecord`]. A receipt that
/// fails verification is still reported (with `verified: false`) so the
/// reconciliation refuses rather than silently ignoring it.
pub fn load_receipts(dir: &Path, key: &[u8]) -> Result<Vec<ReceiptRecord>, AuditError> {
    let receipts = dir.join(RECEIPT_DIR);
    let entries = match std::fs::read_dir(&receipts) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(AuditError::Invalid(format!("receipt dir: {error}"))),
    };
    let mut records = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|e| AuditError::Invalid(format!("receipt dir: {e}")))?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if name.starts_with('.') {
            // An abandoned temporary from an interrupted write is never evidence.
            continue;
        }
        let Some(provider) = name.strip_suffix(".json") else {
            return Err(AuditError::Invalid(format!(
                "unexpected file {name:?} in {RECEIPT_DIR}"
            )));
        };
        records.push(match read_verified_receipt(dir, provider, key) {
            Ok(stored) => ReceiptRecord {
                provider: provider.to_owned(),
                plan_digest: stored.body.plan_digest.clone(),
                receipt_digest: stored.digest,
                verified: true,
            },
            Err(_) => ReceiptRecord {
                provider: provider.to_owned(),
                plan_digest: String::new(),
                receipt_digest: String::new(),
                verified: false,
            },
        });
    }
    records.sort_by(|a, b| a.provider.cmp(&b.provider));
    Ok(records)
}

/// Verify every retained provider receipt of a run against its journal: each
/// receipt file must verify (name, content digest, signature under the run plan
/// key), be bound to a plan digest the journal records, and equal the payload
/// digest of its provider's last terminal event; each provider whose last
/// terminal event is not an explicit resume gap must have such a receipt, and a
/// receipt for a provider the journal never saw is refused. Returns one
/// message per defect (empty when everything agrees).
pub fn verify_retained_receipts(dir: &Path, key: &[u8], events: &[AuditEvent]) -> Vec<String> {
    let mut defects = Vec::new();
    let plan_digests: BTreeSet<&str> = events.iter().map(|e| e.plan_digest.as_str()).collect();
    let mut terminal: BTreeMap<&str, &AuditEvent> = BTreeMap::new();
    for event in events {
        if matches!(
            event.kind,
            EventKind::ProviderFinished | EventKind::ProviderFailed | EventKind::ProviderSkipped
        ) {
            terminal.insert(event.subject.as_str(), event);
        }
    }
    let mut seen: BTreeSet<String> = BTreeSet::new();
    let receipts = dir.join(RECEIPT_DIR);
    match std::fs::read_dir(&receipts) {
        Ok(entries) => {
            for entry in entries {
                let Ok(entry) = entry else {
                    defects.push(format!("{RECEIPT_DIR} cannot be listed"));
                    continue;
                };
                let name = entry.file_name().to_string_lossy().into_owned();
                if name.starts_with('.') {
                    continue;
                }
                let Some(provider) = name.strip_suffix(".json") else {
                    defects.push(format!("unexpected file {name:?} in {RECEIPT_DIR}"));
                    continue;
                };
                seen.insert(provider.to_owned());
                match read_verified_receipt(dir, provider, key) {
                    Err(reason) => defects.push(format!(
                        "receipt for {provider} failed verification: {reason}"
                    )),
                    Ok(stored) => {
                        if !plan_digests.contains(stored.body.plan_digest.as_str()) {
                            defects.push(format!(
                                "receipt for {provider} is bound to a plan the journal does not record"
                            ));
                        }
                        match terminal.get(provider) {
                            None => defects.push(format!(
                                "receipt for {provider} has no terminal journal event"
                            )),
                            Some(event) => {
                                let explicit_gap = event.kind == EventKind::ProviderFailed
                                    && (event.payload_digest == gap_payload_digest(provider)
                                        || event.payload_digest
                                            == interrupted_payload_digest(provider));
                                if !explicit_gap && event.payload_digest != stored.digest {
                                    defects.push(format!(
                                        "receipt for {provider} does not match the journaled digest"
                                    ));
                                }
                            }
                        }
                    }
                }
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => defects.push(format!("{RECEIPT_DIR} cannot be read: {error}")),
    }
    for (provider, event) in &terminal {
        let explicit_gap = event.kind == EventKind::ProviderFailed
            && (event.payload_digest == gap_payload_digest(provider)
                || event.payload_digest == interrupted_payload_digest(provider));
        if !explicit_gap && !seen.contains(*provider) {
            defects.push(format!(
                "provider {provider} has a terminal journal event but its receipt is missing"
            ));
        }
    }
    defects
}

/// What a resumed run feeds back into the engine instead of executing.
#[derive(Clone, Debug)]
pub enum ProviderSeed {
    /// Verified completed result from a signed receipt.
    Reuse {
        execution: ProviderExecution,
        attempts: u32,
    },
    /// Explicit failure (gap, kept failure, kept skip). Never reads as clean.
    Failed { reason: String },
}

/// Journal sink for one run: appends lifecycle events and writes the signed
/// receipt *before* the matching finish event. The first journal or receipt
/// failure is remembered and fails the run closed.
pub struct RunRecorder {
    journal: Mutex<Journal>,
    dir: PathBuf,
    key: Vec<u8>,
    plan_digest: String,
    failure: Mutex<Option<String>>,
}

impl RunRecorder {
    /// Create the journal (`plan_frozen`) in `dir`.
    pub fn create(dir: &Path, plan_digest: &str, key: Vec<u8>) -> Result<Self, AuditError> {
        let journal = Journal::create(dir, plan_digest, now_ms())?;
        Ok(Self::from_journal(journal, dir, plan_digest, key))
    }

    pub fn from_journal(journal: Journal, dir: &Path, plan_digest: &str, key: Vec<u8>) -> Self {
        Self {
            journal: Mutex::new(journal),
            dir: dir.to_path_buf(),
            key,
            plan_digest: plan_digest.to_owned(),
            failure: Mutex::new(None),
        }
    }

    pub fn plan_digest(&self) -> &str {
        &self.plan_digest
    }

    fn journal(&self) -> Result<MutexGuard<'_, Journal>, AuditError> {
        self.journal
            .lock()
            .map_err(|_| AuditError::Invalid("journal lock poisoned".into()))
    }

    fn remember<T>(&self, result: Result<T, AuditError>) -> Result<T, AuditError> {
        if let Err(error) = &result {
            if let Ok(mut failure) = self.failure.lock() {
                failure.get_or_insert_with(|| error.to_string());
            }
        }
        result
    }

    /// Fails when any earlier journal or receipt write failed.
    pub fn check(&self) -> Result<(), AuditError> {
        match self.failure.lock() {
            Ok(failure) => match failure.as_ref() {
                Some(reason) => Err(AuditError::Invalid(format!("run journal failed: {reason}"))),
                None => Ok(()),
            },
            Err(_) => Err(AuditError::Invalid("journal failure lock poisoned".into())),
        }
    }

    fn append(&self, kind: EventKind, subject: &str, payload: &str) -> Result<(), AuditError> {
        self.check()?;
        let result = self
            .journal()
            .and_then(|mut journal| journal.append(kind, subject, payload, now_ms()).map(|_| ()));
        self.remember(result)
    }

    fn payload(value: serde_json::Value) -> Result<String, AuditError> {
        legion_contracts::canonical_digest(&value).map_err(|e| AuditError::Invalid(e.to_string()))
    }

    pub fn started(&self, provider: &str) -> Result<(), AuditError> {
        let payload = Self::payload(serde_json::json!({"started": provider}))?;
        self.append(EventKind::ProviderStarted, provider, &payload)
    }

    /// Retries run on worker threads; a failure is remembered and surfaces at
    /// the next `settled`/`check`.
    pub fn retry_scheduled(&self, provider: &str, attempt: u32) {
        let result = Self::payload(serde_json::json!({"retry": provider, "attempt": attempt}))
            .and_then(|payload| self.append(EventKind::RetryScheduled, provider, &payload));
        let _ = self.remember(result);
    }

    pub fn breaker_tripped(&self, provider: &str, group: &str) -> Result<(), AuditError> {
        let payload = Self::payload(serde_json::json!({"breaker": group}))?;
        self.append(EventKind::BreakerTripped, provider, &payload)
    }

    pub fn fallback_used(
        &self,
        provider: &str,
        fallback: &str,
        outcome: &str,
    ) -> Result<(), AuditError> {
        let payload = Self::payload(
            serde_json::json!({"primary": provider, "fallback": fallback, "outcome": outcome}),
        )?;
        self.append(EventKind::FallbackUsed, provider, &payload)
    }

    fn receipt(
        &self,
        provider: &str,
        outcome: &str,
        attempts: u32,
        execution: &ProviderExecution,
    ) -> Result<String, AuditError> {
        let plan_digest = self.journal()?.effective_plan_digest().to_owned();
        let result = write_receipt(
            &self.dir,
            &self.key,
            ReceiptBody {
                format: RECEIPT_FORMAT.to_owned(),
                provider: provider.to_owned(),
                plan_digest,
                outcome: outcome.to_owned(),
                attempts,
                execution: execution.clone(),
            },
        );
        self.remember(result)
    }

    /// Receipt first, then `provider_finished` or `provider_failed`.
    pub fn settled(
        &self,
        provider: &str,
        completed: bool,
        attempts: u32,
        execution: &ProviderExecution,
    ) -> Result<(), AuditError> {
        self.check()?;
        let outcome = if completed { "finished" } else { "failed" };
        let digest = self.receipt(provider, outcome, attempts, execution)?;
        let kind = if completed {
            EventKind::ProviderFinished
        } else {
            EventKind::ProviderFailed
        };
        self.append(kind, provider, &digest)
    }

    /// A provider that needs no execution still gets a start, a receipt and a finish.
    pub fn not_applicable(
        &self,
        provider: &str,
        execution: &ProviderExecution,
    ) -> Result<(), AuditError> {
        self.started(provider)?;
        let digest = self.receipt(provider, "not-applicable", 0, execution)?;
        self.append(EventKind::ProviderFinished, provider, &digest)
    }

    /// Never invoked (dependency failure, open breaker, invalid policy, ...).
    pub fn skipped(&self, provider: &str, execution: &ProviderExecution) -> Result<(), AuditError> {
        self.check()?;
        let digest = self.receipt(provider, "skipped", 0, execution)?;
        self.append(EventKind::ProviderSkipped, provider, &digest)
    }

    pub fn head(&self) -> Result<SealedHead, AuditError> {
        Ok(self.journal()?.head())
    }

    pub fn events(&self) -> Result<Vec<AuditEvent>, AuditError> {
        Ok(self.journal()?.events().to_vec())
    }

    pub fn effective_plan_digest(&self) -> Result<String, AuditError> {
        Ok(self.journal()?.effective_plan_digest().to_owned())
    }

    /// Append `report_finalized` (payload: the report digest) and write the
    /// signed anchor over the final head. Refuses after any earlier failure.
    pub fn finalize(&self, report_digest: &str) -> Result<SealedHead, AuditError> {
        self.check()?;
        let (head, effective) = {
            let mut journal = self.journal()?;
            let result = journal
                .append(EventKind::ReportFinalized, "run", report_digest, now_ms())
                .map(|_| ());
            self.remember(result)?;
            (journal.head(), journal.effective_plan_digest().to_owned())
        };
        let digest = head
            .digest
            .clone()
            .ok_or_else(|| AuditError::Invalid("finalized journal has no head digest".into()))?;
        let anchor = JournalAnchor::sign(
            &self.plan_digest,
            &effective,
            head.sequence,
            &digest,
            &self.key,
        )?;
        self.remember(anchor.write(&self.dir))?;
        Ok(head)
    }
}

/// Process-wide execution wiring for callers that reach the engine through a
/// host application (which owns the executor) rather than through a function
/// they can pass a recorder to. It applies only to the default entry points
/// (`execute`, `execute_with_cancellation`), only to a run whose frozen plan
/// digest matches the recorder, and is cleared when the guard drops. Library
/// callers that never install it are unaffected.
#[derive(Clone)]
pub struct AmbientRun {
    pub config: SchedulerConfig,
    pub recorder: Option<Arc<RunRecorder>>,
    pub seeds: BTreeMap<String, ProviderSeed>,
}

static AMBIENT: Mutex<Option<AmbientRun>> = Mutex::new(None);

pub struct AmbientGuard(());

impl Drop for AmbientGuard {
    fn drop(&mut self) {
        if let Ok(mut slot) = AMBIENT.lock() {
            *slot = None;
        }
    }
}

pub fn install_ambient(run: AmbientRun) -> AmbientGuard {
    if let Ok(mut slot) = AMBIENT.lock() {
        *slot = Some(run);
    }
    AmbientGuard(())
}

pub(crate) fn ambient_for(plan_digest: &str) -> Option<AmbientRun> {
    let slot = AMBIENT.lock().ok()?;
    let run = slot.as_ref()?;
    match &run.recorder {
        Some(recorder) if recorder.plan_digest() != plan_digest => None,
        _ => Some(run.clone()),
    }
}
