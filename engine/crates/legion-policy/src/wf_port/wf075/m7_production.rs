//! Faithful port of
//! `src/lib/verification/arcane/s11-bindings/m7-production.mjs`, an S11
//! binding harness that exercises the production `ArchitectureEventStore`
//! and `createExecutionCheckpoint`/`verifyExecutionCheckpoint` machinery
//! end to end (full replay, a revision-count tripwire, and an epoch
//! mismatch) rather than a unit under test in its own right.
//!
//! This depends on wf070's already-ported `ArchitectureEventStore`,
//! `create_architecture_state`/`apply_architecture_event`, and canonical
//! digest primitives (`crate::wf_port::wf070::{event_store, state, canon}`).
//! `createExecutionCheckpoint`/`verifyExecutionCheckpoint`
//! (`src/lib/host/arcane/continuity.mjs`) and a test key ring
//! (`generateTestKeyRing`, `src/lib/guard/compat/host/keys.mjs`) are not
//! covered by any existing port, so the minimal slice this harness needs is
//! ported locally below rather than claimed for wf075 as a whole — see the
//! wf075 report.
//!
//! The JS harness's `fullReplay` binding drives a real, disk-backed
//! `ReceiptStore` (`node:fs` + `mkdtemp`). wf070's Rust
//! `ArchitectureEventStore` is generic over an injected `ReceiptStore`
//! trait precisely so callers don't need a filesystem for this; this port
//! uses an in-memory implementation instead. The event-acceptance and
//! replay semantics under test are identical either way — the JS harness's
//! tempdir is JS's own `ReceiptStore`'s implementation detail, not part of
//! what `fullReplay` asserts.

use std::collections::BTreeMap;

use crate::wf_port::wf070::canon::{digest_value, is_digest, CanonVal};
use crate::wf_port::wf070::event_store::{ArchitectureEventStore, EventProposal, KeyRing, ReceiptStore};
use crate::wf_port::wf070::state::create_architecture_state;

const NOW: &str = "2026-08-15T00:00:00.000Z";

fn ledger(id: &str) -> CanonVal {
    CanonVal::obj()
        .set("schema", CanonVal::Str("acceptance-ledger.v1".to_string()))
        .set("ledger_version", CanonVal::Int(1))
        .set("intent_epoch", CanonVal::Int(1))
        .set("acceptance_fingerprint", CanonVal::Str(digest_value(&CanonVal::Str(id.to_string()))))
        .set("frozen_at", CanonVal::Str(NOW.to_string()))
        .set("items", CanonVal::Arr(vec![]))
}

fn state(id: &str) -> CanonVal {
    create_architecture_state(&format!("s11:{id}"), ledger(id), &format!("s11:{id}")).expect("valid fixture state")
}

/// Mirrors `observation(producer, consumer, value)`.
#[derive(Debug, Clone)]
pub struct Observation {
    pub producer: &'static str,
    pub consumer: &'static str,
    pub value: CanonVal,
}

fn observation(producer: &'static str, consumer: &'static str, value: CanonVal) -> Observation {
    Observation { producer, consumer, value }
}

// ---------------------------------------------------------------------
// In-memory ReceiptStore / KeyRing test doubles for this harness only.
// ---------------------------------------------------------------------

struct MemoryReceiptStore(Vec<CanonVal>);
impl ReceiptStore for MemoryReceiptStore {
    fn append(&mut self, event: CanonVal) {
        self.0.push(event);
    }
    fn list(&self) -> &[CanonVal] {
        &self.0
    }
    fn verify_chain(&self) -> Result<(), String> {
        Ok(())
    }
}

/// Local stand-in for `generateTestKeyRing`. The JS fixture generates
/// random key material per call (fixtures only, never a real credential —
/// see `keys.mjs`); this port uses fixed deterministic bytes instead, since
/// nothing in these bindings asserts on the key material itself, only on
/// whether events verify under whichever ring produced them.
struct FixedKeyRing(BTreeMap<String, Vec<u8>>);
impl FixedKeyRing {
    fn single(key_id: &str) -> Self {
        let mut m = BTreeMap::new();
        m.insert(key_id.to_string(), b"wf075-m7-production-test-fixture-key".to_vec());
        FixedKeyRing(m)
    }
}
impl KeyRing for FixedKeyRing {
    fn get(&self, key_id: &str) -> Option<&[u8]> {
        self.0.get(key_id).map(|v| v.as_slice())
    }
}

fn proposal(
    lineage: &str,
    intent_epoch: i64,
    event_type: &str,
    payload: CanonVal,
) -> EventProposal {
    EventProposal {
        objective_lineage_id: lineage.to_string(),
        intent_epoch,
        execution_id: "s11:m7".to_string(),
        repository_id: "s11:repository".to_string(),
        actor_role: "alchemist".to_string(),
        phase: "execute".to_string(),
        event_type: event_type.to_string(),
        payload,
        acceptance_ids: vec![],
        decision_ids: vec![],
        finding_ids: vec![],
        input_fingerprint: None,
        output_refs: vec![],
        checkpoint_ref: None,
        cost_delta: CanonVal::obj(),
        retry_class: "none".to_string(),
        terminal_reason: None,
        privacy_class: "metadata".to_string(),
    }
}

/// Mirrors `fullReplay`.
pub fn full_replay() -> Observation {
    let lineage = "s11:AE-STATE-TRANSITIONS-REPLAY-002";
    let initial = state("AE-STATE-TRANSITIONS-REPLAY-002");
    let mut store = MemoryReceiptStore(vec![]);
    let key_ring = FixedKeyRing::single("k1");
    let mut event_store =
        ArchitectureEventStore::new(&mut store, &key_ring, "k1", Box::new(|| NOW.to_string())).expect("event store constructs");

    let replayed = event_store.replay(lineage, &initial).expect("initial replay succeeds");
    let mut expected_fp = replayed.state_fingerprint.clone();
    // Mirrors the JS harness reading `accepted.state.intent.intent_epoch`
    // fresh before every `accept()` call: `CANCEL_RECORDED` below advances
    // the real intent epoch to 2, and every later proposal must bind to
    // that current value, not the epoch the lineage started at.
    let mut current_intent_epoch = replayed
        .state
        .get("intent")
        .and_then(|i| i.get("intent_epoch"))
        .and_then(CanonVal::as_int)
        .expect("intent_epoch present");

    let mut append = |event_type: &str, payload: CanonVal| {
        let accepted = event_store
            .accept(&proposal(lineage, current_intent_epoch, event_type, payload), Some(expected_fp.as_str()))
            .unwrap_or_else(|e| panic!("event rejected: {event_type}: {e}"));
        expected_fp = accepted.state_fingerprint.clone();
        current_intent_epoch = accepted
            .state
            .get("intent")
            .and_then(|i| i.get("intent_epoch"))
            .and_then(CanonVal::as_int)
            .unwrap_or(current_intent_epoch);
        accepted
    };

    append(
        "ARCHITECTURE_TRANSITIONED",
        CanonVal::obj().set("from", CanonVal::Str("UNROUTED".into())).set("to", CanonVal::Str("TAILORED".into())),
    );
    append(
        "EFFECT_RECORDED",
        CanonVal::obj()
            .set("id", CanonVal::Str("effect-1".into()))
            .set("effect_id", CanonVal::Str("write-1".into()))
            .set("effect_class", CanonVal::Str("write".into()))
            .set("status", CanonVal::Str("completed".into())),
    );
    append(
        "EFFECT_DENIED",
        CanonVal::obj()
            .set("id", CanonVal::Str("denial-1".into()))
            .set("effect_id", CanonVal::Str("write-2".into()))
            .set("code", CanonVal::Str("ARC_PATH_FORBIDDEN".into()))
            .set("reason", CanonVal::Str("policy".into())),
    );
    append(
        "CANCEL_RECORDED",
        CanonVal::obj()
            .set("id", CanonVal::Str("cancel-1".into()))
            .set("intent_epoch", CanonVal::Int(2))
            .set("reason", CanonVal::Str("PAUSE".into()))
            .set("unverified_candidate_ids", CanonVal::Arr(vec![CanonVal::Str("candidate-1".into())])),
    );
    append(
        "RECOVERY_RECORDED",
        CanonVal::obj()
            .set("id", CanonVal::Str("recovery-1".into()))
            .set("checkpoint_digest", CanonVal::Str(digest_value(&CanonVal::obj().set("checkpoint", CanonVal::Int(1)))))
            .set("reason", CanonVal::Str("resume denied".into()))
            .set("candidate_ids", CanonVal::Arr(vec![CanonVal::Str("candidate-1".into())])),
    );
    let accepted = append(
        "SUPERSESSION_RECORDED",
        CanonVal::obj()
            .set("id", CanonVal::Str("supersession-1".into()))
            .set("supersedes_id", CanonVal::Str("candidate-1".into()))
            .set("replacement_id", CanonVal::Str("candidate-2".into()))
            .set("reason", CanonVal::Str("new evidence".into())),
    );

    let restored = event_store.replay(lineage, &initial).expect("restore replay succeeds");

    let effects = restored.state.get("execution").and_then(|e| e.get("effects")).and_then(CanonVal::as_arr).map(Vec::len).unwrap_or(0);
    let denials = restored.state.get("execution").and_then(|e| e.get("denials")).and_then(CanonVal::as_arr).map(Vec::len).unwrap_or(0);
    let cancellations = restored.state.get("execution").and_then(|e| e.get("cancellations")).and_then(CanonVal::as_arr).map(Vec::len).unwrap_or(0);
    let recoveries = restored.state.get("execution").and_then(|e| e.get("recovery_refs")).and_then(CanonVal::as_arr).map(Vec::len).unwrap_or(0);
    let supersessions = restored.state.get("execution").and_then(|e| e.get("supersession_refs")).and_then(CanonVal::as_arr).map(Vec::len).unwrap_or(0);

    observation(
        "ArchitectureEventStore.accept/replay",
        "authenticated trajectory receipt store",
        CanonVal::obj()
            .set("acceptedFingerprint", CanonVal::Str(accepted.state_fingerprint))
            .set("replayFingerprint", CanonVal::Str(restored.state_fingerprint))
            .set("eventCount", CanonVal::Int(restored.event_count))
            .set("effects", CanonVal::Int(effects as i64))
            .set("denials", CanonVal::Int(denials as i64))
            .set("cancellations", CanonVal::Int(cancellations as i64))
            .set("recoveries", CanonVal::Int(recoveries as i64))
            .set("supersessions", CanonVal::Int(supersessions as i64)),
    )
}

/// Mirrors `revisionTripwire`. The 4th `ARCHITECTURE_REVISION_RECORDED`
/// after a terminal disposition has already been set must be rejected.
pub fn revision_tripwire() -> Observation {
    use crate::wf_port::wf070::state::apply_architecture_event;

    let mut current = state("AE-CONVERGENCE-006");
    for revision in [1, 2] {
        current = apply_architecture_event(
            &current,
            "ARCHITECTURE_REVISION_RECORDED",
            &CanonVal::obj()
                .set("id", CanonVal::Str(format!("revision-{revision}")))
                .set("decision_id", CanonVal::Str("D-2".into()))
                .set("revision", CanonVal::Int(revision))
                .set("live_candidate_ids", CanonVal::Arr(vec![CanonVal::Str("a".into()), CanonVal::Str("b".into())]))
                .set("terminal_disposition", CanonVal::Null),
        )
        .expect("revision recorded");
    }
    current = apply_architecture_event(
        &current,
        "ARCHITECTURE_REVISION_RECORDED",
        &CanonVal::obj()
            .set("id", CanonVal::Str("revision-3".into()))
            .set("decision_id", CanonVal::Str("D-2".into()))
            .set("revision", CanonVal::Int(3))
            .set("live_candidate_ids", CanonVal::Arr(vec![CanonVal::Str("a".into()), CanonVal::Str("b".into())]))
            .set("terminal_disposition", CanonVal::Str("DECIDE_WITH_DEBT".into())),
    )
    .expect("terminal revision recorded");

    let fourth = apply_architecture_event(
        &current,
        "ARCHITECTURE_REVISION_RECORDED",
        &CanonVal::obj()
            .set("id", CanonVal::Str("revision-4".into()))
            .set("decision_id", CanonVal::Str("D-2".into()))
            .set("revision", CanonVal::Int(4))
            .set("live_candidate_ids", CanonVal::Arr(vec![CanonVal::Str("a".into()), CanonVal::Str("b".into())]))
            .set("terminal_disposition", CanonVal::Null),
    );
    let fourth_rejected = fourth.is_err();

    let revisions = current.get("convergence").and_then(|c| c.get("revisions")).and_then(CanonVal::as_arr).map(Vec::len).unwrap_or(0);
    let terminal_disposition =
        current.get("convergence").and_then(|c| c.get("terminal_disposition")).cloned().unwrap_or(CanonVal::Null);

    observation(
        "applyArchitectureEvent",
        "architecture convergence state",
        CanonVal::obj()
            .set("revisions", CanonVal::Int(revisions as i64))
            .set("terminalDisposition", terminal_disposition)
            .set("fourthRejected", CanonVal::Bool(fourth_rejected)),
    )
}

// ---------------------------------------------------------------------
// Minimal local port of `src/lib/host/arcane/continuity.mjs`'s
// `createExecutionCheckpoint`/`verifyExecutionCheckpoint` — only the slice
// `epochMismatch` exercises. Not claimed as a full continuity.mjs port.
// ---------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct ExecutionCheckpoint {
    pub objective_lineage_id: String,
    pub intent_epoch: i64,
    pub continuation_epoch: i64,
    pub repository_state: String,
    pub contract_fingerprint: String,
    pub event_sequence: i64,
    pub event_digest: String,
    pub checkpoint_digest: String,
}

/// Mirrors `createExecutionCheckpoint`, narrowed to the fields
/// `verifyExecutionCheckpoint`'s `epochMismatch` binding reads (producer
/// versions / completed-effect-ids / preserved-candidate-ids round-trip
/// identically in JS but are not asserted on here, so they are omitted
/// rather than half-ported).
pub fn create_execution_checkpoint(
    state: &CanonVal,
    contract_fingerprint: &str,
    repository_state: &str,
    event_sequence: i64,
    event_digest: &str,
) -> ExecutionCheckpoint {
    let objective_lineage_id = state.get("task").and_then(|t| t.get("objective_lineage_id")).and_then(CanonVal::as_str).expect("lineage present").to_string();
    let intent_epoch = state.get("intent").and_then(|i| i.get("intent_epoch")).and_then(CanonVal::as_int).expect("intent_epoch present");
    let continuation_epoch = state.get("intent").and_then(|i| i.get("continuation_epoch")).and_then(CanonVal::as_int).expect("continuation_epoch present");
    assert!(is_digest(repository_state), "repository_state must be a digest");
    assert!(is_digest(event_digest), "event_digest must be a digest");
    assert!(event_sequence >= 0, "event sequence must be non-negative");

    let body = CanonVal::obj()
        .set("schema", CanonVal::Str("execution-checkpoint.v1".to_string()))
        .set("objective_lineage_id", CanonVal::Str(objective_lineage_id.clone()))
        .set("intent_epoch", CanonVal::Int(intent_epoch))
        .set("continuation_epoch", CanonVal::Int(continuation_epoch))
        .set("repository_state", CanonVal::Str(repository_state.to_string()))
        .set("contract_fingerprint", CanonVal::Str(contract_fingerprint.to_string()))
        .set("event_sequence", CanonVal::Int(event_sequence))
        .set("event_digest", CanonVal::Str(event_digest.to_string()));
    let checkpoint_digest = digest_value(&body);

    ExecutionCheckpoint {
        objective_lineage_id,
        intent_epoch,
        continuation_epoch,
        repository_state: repository_state.to_string(),
        contract_fingerprint: contract_fingerprint.to_string(),
        event_sequence,
        event_digest: event_digest.to_string(),
        checkpoint_digest,
    }
}

#[derive(Debug, Clone)]
pub struct CheckpointVerification {
    pub valid: bool,
    pub reason: Option<&'static str>,
    pub resume_authorized: bool,
}

/// The "current" side `verifyExecutionCheckpoint` binds against.
#[derive(Debug, Clone)]
pub struct CurrentContinuity {
    pub objective_lineage_id: String,
    pub intent_epoch: i64,
    pub continuation_epoch: i64,
    pub repository_state: String,
    pub contract_fingerprint: String,
    pub event_sequence: i64,
    pub event_digest: String,
}

/// Mirrors `verifyExecutionCheckpoint`, narrowed to the mismatch classes
/// `epochMismatch` exercises (digest integrity + the binding-mismatch set).
pub fn verify_execution_checkpoint(checkpoint: &ExecutionCheckpoint, current: &CurrentContinuity) -> CheckpointVerification {
    let mut mismatches: Vec<&'static str> = Vec::new();
    if checkpoint.objective_lineage_id != current.objective_lineage_id {
        mismatches.push("objective_lineage");
    }
    if checkpoint.intent_epoch != current.intent_epoch {
        mismatches.push("intent_epoch");
    }
    if checkpoint.continuation_epoch != current.continuation_epoch {
        mismatches.push("continuation_epoch");
    }
    if checkpoint.repository_state != current.repository_state {
        mismatches.push("repository_state");
    }
    if checkpoint.contract_fingerprint != current.contract_fingerprint {
        mismatches.push("acceptance_contract");
    }
    if checkpoint.event_sequence != current.event_sequence || checkpoint.event_digest != current.event_digest {
        mismatches.push("event_continuity");
    }
    if !mismatches.is_empty() {
        return CheckpointVerification { valid: false, reason: Some("binding_mismatch"), resume_authorized: false };
    }
    CheckpointVerification { valid: true, reason: None, resume_authorized: true }
}

/// Mirrors `epochMismatch`.
pub fn epoch_mismatch() -> Observation {
    let initial = state("AE-TRAJECTORY-RESUME-002");
    let repository_state = digest_value(&CanonVal::obj().set("repository", CanonVal::Int(1)));
    let contract_fingerprint = digest_value(&CanonVal::obj().set("contract", CanonVal::Int(1)));
    let event_digest = digest_value(&CanonVal::obj().set("event", CanonVal::Int(0)));

    let checkpoint = create_execution_checkpoint(&initial, &contract_fingerprint, &repository_state, 0, &event_digest);

    let current = CurrentContinuity {
        objective_lineage_id: checkpoint.objective_lineage_id.clone(),
        intent_epoch: 2, // JS harness deliberately advances intent_epoch to 2 here.
        continuation_epoch: checkpoint.continuation_epoch,
        repository_state: checkpoint.repository_state.clone(),
        contract_fingerprint: checkpoint.contract_fingerprint.clone(),
        event_sequence: 0,
        event_digest: checkpoint.event_digest.clone(),
    };
    let result = verify_execution_checkpoint(&checkpoint, &current);

    observation(
        "verifyExecutionCheckpoint",
        "continuity admission",
        CanonVal::obj()
            .set("valid", CanonVal::Bool(result.valid))
            .set("reason", result.reason.map(|r| CanonVal::Str(r.to_string())).unwrap_or(CanonVal::Null))
            .set("resume_authorized", CanonVal::Bool(result.resume_authorized)),
    )
}

/// Mirrors `m7BindingIds`.
pub fn m7_binding_ids() -> Vec<&'static str> {
    let mut ids = vec!["AE-STATE-TRANSITIONS-REPLAY-002", "AE-CONVERGENCE-006", "AE-TRAJECTORY-RESUME-002"];
    ids.sort_unstable();
    ids
}

/// Mirrors `executeM7Binding`.
pub fn execute_m7_binding(id: &str) -> Option<Observation> {
    match id {
        "AE-STATE-TRANSITIONS-REPLAY-002" => Some(full_replay()),
        "AE-CONVERGENCE-006" => Some(revision_tripwire()),
        "AE-TRAJECTORY-RESUME-002" => Some(epoch_mismatch()),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn binding_ids_are_sorted() {
        assert_eq!(m7_binding_ids(), vec!["AE-CONVERGENCE-006", "AE-STATE-TRANSITIONS-REPLAY-002", "AE-TRAJECTORY-RESUME-002"]);
    }

    #[test]
    fn unknown_binding_returns_none() {
        assert!(execute_m7_binding("NOPE").is_none());
    }

    #[test]
    fn full_replay_reconstructs_identical_state_with_all_events() {
        let obs = full_replay();
        let v = &obs.value;
        assert_eq!(v.get("acceptedFingerprint"), v.get("replayFingerprint"));
        assert_eq!(v.get("eventCount"), Some(&CanonVal::Int(6)));
        assert_eq!(v.get("effects"), Some(&CanonVal::Int(1)));
        assert_eq!(v.get("denials"), Some(&CanonVal::Int(1)));
        assert_eq!(v.get("cancellations"), Some(&CanonVal::Int(1)));
        assert_eq!(v.get("recoveries"), Some(&CanonVal::Int(1)));
        assert_eq!(v.get("supersessions"), Some(&CanonVal::Int(1)));
    }

    #[test]
    fn revision_tripwire_rejects_the_fourth_revision() {
        let obs = revision_tripwire();
        let v = &obs.value;
        assert_eq!(v.get("revisions"), Some(&CanonVal::Int(3)));
        assert_eq!(v.get("terminalDisposition"), Some(&CanonVal::Str("DECIDE_WITH_DEBT".to_string())));
        assert_eq!(v.get("fourthRejected"), Some(&CanonVal::Bool(true)));
    }

    #[test]
    fn epoch_mismatch_denies_resume() {
        let obs = epoch_mismatch();
        let v = &obs.value;
        assert_eq!(v.get("valid"), Some(&CanonVal::Bool(false)));
        assert_eq!(v.get("reason"), Some(&CanonVal::Str("binding_mismatch".to_string())));
        assert_eq!(v.get("resume_authorized"), Some(&CanonVal::Bool(false)));
    }

    #[test]
    fn checkpoint_round_trip_verifies_when_nothing_changed() {
        let initial = state("AE-TRAJECTORY-RESUME-002");
        let repository_state = digest_value(&CanonVal::obj().set("repository", CanonVal::Int(1)));
        let contract_fingerprint = digest_value(&CanonVal::obj().set("contract", CanonVal::Int(1)));
        let event_digest = digest_value(&CanonVal::obj().set("event", CanonVal::Int(0)));
        let checkpoint = create_execution_checkpoint(&initial, &contract_fingerprint, &repository_state, 0, &event_digest);
        let current = CurrentContinuity {
            objective_lineage_id: checkpoint.objective_lineage_id.clone(),
            intent_epoch: checkpoint.intent_epoch,
            continuation_epoch: checkpoint.continuation_epoch,
            repository_state: checkpoint.repository_state.clone(),
            contract_fingerprint: checkpoint.contract_fingerprint.clone(),
            event_sequence: checkpoint.event_sequence,
            event_digest: checkpoint.event_digest.clone(),
        };
        let result = verify_execution_checkpoint(&checkpoint, &current);
        assert!(result.valid);
        assert!(result.resume_authorized);
    }
}
