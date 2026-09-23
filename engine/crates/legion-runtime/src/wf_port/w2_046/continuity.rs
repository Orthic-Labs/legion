//! Partial port of `src/lib/host/arcane/continuity.mjs`.
//!
//! ## What is ported here (full fidelity)
//! - `createExecutionCheckpoint` / `verifyExecutionCheckpoint` (and the
//!   `acceptanceBinding` helper they share) — pure, digest-bound checkpoint
//!   construction and verification.
//! - `rehydrateUntrustedData` — the typed `UNTRUSTED_DATA` envelope guard.
//! - `ContinuityController` — the in-memory epoch/effect-claim state
//!   machine (`bind`/`cancel`/`resume`/`assertCurrent`/`claimEffect`/
//!   `completedEffectIds`).
//! - `cancelProcessGroup` — generalized over `terminate`/`alive` closures
//!   exactly as the JS takes functions.
//!
//! ## What is NOT ported (left `NOT-STARTED`, out of this chunk)
//! - `WorkflowContinuityStore`: durable `node:fs` JSON-file state
//!   (`checkpoint`/`resume`/`pause`/`applyDirection`/`replan`). Needs a
//!   filesystem/JSON persistence layer this chunk does not own.
//! - `createHostArchitectureState` / `consumeHostArchitectureLifecycle` /
//!   `executionTrajectoryPayload` / the internal `proposal` builder: these
//!   depend on `src/lib/verification/arcane/architecture-state.mjs` and
//!   `architecture-router.mjs` plus an authenticated `ArchitectureEventStore`,
//!   none of which are part of this chunk's five files or reachable from
//!   `legion-runtime` today. Porting them needs those modules ported first
//!   (see chunk report for the suggested follow-up split).

use super::canonical::digest_value;
use serde_json::{Map, Value};
use std::sync::LazyLock;

use regex::Regex;

static DIGEST: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^sha256:[0-9a-f]{64}$").unwrap());

fn is_digest(value: &str) -> bool {
    DIGEST.is_match(value)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContinuityError(pub String);

impl std::fmt::Display for ContinuityError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}
impl std::error::Error for ContinuityError {}

fn fail<T>(message: &str) -> Result<T, ContinuityError> {
    Err(ContinuityError(message.to_string()))
}

/// The two acceptance-ledger schemas `acceptanceBinding` understands.
#[derive(Debug, Clone)]
pub enum AcceptanceLedger {
    V2 { acceptance_manifest_fingerprint: Value, schedule_fingerprint: Value },
    V1 { acceptance_fingerprint: Value },
    Unsupported,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcceptanceBinding {
    pub contract_fingerprint: String,
    pub acceptance_manifest_fingerprint: Value,
    pub schedule_fingerprint: Value,
}

/// Port of `acceptanceBinding`.
pub fn acceptance_binding(
    ledger: &AcceptanceLedger,
    contract_fingerprint: Option<&str>,
) -> Result<AcceptanceBinding, ContinuityError> {
    let cf = contract_fingerprint.unwrap_or("");
    if !is_digest(cf) {
        return fail("current item or stage contract fingerprint is required");
    }
    match ledger {
        AcceptanceLedger::V2 { acceptance_manifest_fingerprint, schedule_fingerprint } => {
            Ok(AcceptanceBinding {
                contract_fingerprint: cf.to_string(),
                acceptance_manifest_fingerprint: acceptance_manifest_fingerprint.clone(),
                schedule_fingerprint: schedule_fingerprint.clone(),
            })
        }
        AcceptanceLedger::V1 { acceptance_fingerprint } => Ok(AcceptanceBinding {
            contract_fingerprint: cf.to_string(),
            acceptance_manifest_fingerprint: acceptance_fingerprint.clone(),
            schedule_fingerprint: Value::Null,
        }),
        AcceptanceLedger::Unsupported => fail("unsupported acceptance ledger"),
    }
}

#[derive(Debug, Clone)]
pub struct CreateCheckpointInput<'a> {
    pub objective_lineage_id: &'a str,
    pub intent_epoch: Value,
    pub continuation_epoch: Value,
    pub repository_state: &'a str,
    pub acceptance_ledger: &'a AcceptanceLedger,
    pub contract_fingerprint: Option<&'a str>,
    pub producer_versions: Map<String, Value>,
    pub event_sequence: i64,
    pub event_digest: &'a str,
    pub completed_effect_ids: Vec<String>,
    pub preserved_candidate_ids: Vec<String>,
    pub created_at: Option<&'a str>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ExecutionCheckpoint {
    pub body: Value,
    pub checkpoint_digest: String,
}

fn sorted_unique_strings(values: Vec<String>) -> Vec<String> {
    let mut set: std::collections::BTreeSet<String> = values.into_iter().collect();
    set.into_iter().collect::<Vec<_>>().into_iter().collect::<std::collections::BTreeSet<_>>().into_iter().collect()
}

/// Port of `createExecutionCheckpoint`. The caller supplies
/// `objective_lineage_id`/`intent_epoch`/`continuation_epoch` directly
/// (in place of a full `state` object) since the architecture-state module
/// that produces them is out of this chunk.
pub fn create_execution_checkpoint(
    input: CreateCheckpointInput<'_>,
) -> Result<ExecutionCheckpoint, ContinuityError> {
    if input.objective_lineage_id.is_empty() {
        return fail("canonical architecture state is required");
    }
    if !is_digest(input.repository_state) || !is_digest(input.event_digest) {
        return fail("repository and event digests are required");
    }
    if input.event_sequence < 0 {
        return fail("event sequence must be non-negative");
    }
    let created_at = input.created_at.filter(|s| !s.is_empty());
    if created_at.is_none() {
        return fail("checkpoint timestamp is required");
    }
    let acceptance = acceptance_binding(input.acceptance_ledger, input.contract_fingerprint)?;

    let mut producer_versions_sorted = Map::new();
    let mut keys: Vec<&String> = input.producer_versions.keys().collect();
    keys.sort();
    for k in keys {
        producer_versions_sorted.insert(k.clone(), input.producer_versions[k].clone());
    }

    let completed: Vec<String> = sorted_unique_strings(input.completed_effect_ids);
    let preserved: Vec<String> = sorted_unique_strings(input.preserved_candidate_ids);

    let body = serde_json::json!({
        "schema": "execution-checkpoint.v1",
        "objective_lineage_id": input.objective_lineage_id,
        "intent_epoch": input.intent_epoch,
        "continuation_epoch": input.continuation_epoch,
        "repository_state": input.repository_state,
        "acceptance": {
            "contract_fingerprint": acceptance.contract_fingerprint,
            "acceptance_manifest_fingerprint": acceptance.acceptance_manifest_fingerprint,
            "schedule_fingerprint": acceptance.schedule_fingerprint,
        },
        "producer_versions": producer_versions_sorted,
        "event_sequence": input.event_sequence,
        "event_digest": input.event_digest,
        "completed_effect_ids": completed,
        "preserved_candidate_ids": preserved,
        "created_at": created_at,
    });
    let checkpoint_digest = digest_value(&body);
    Ok(ExecutionCheckpoint { body, checkpoint_digest })
}

#[derive(Debug, Clone)]
pub struct CurrentBindingState {
    pub objective_lineage_id: String,
    pub intent_epoch: Value,
    pub continuation_epoch: Value,
    pub repository_state: String,
    pub contract_fingerprint: String,
    pub event_sequence: i64,
    pub event_digest: String,
    pub producer_versions: Map<String, Value>,
    pub schedule_fingerprint: Value,
    pub invalidated_acceptance_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum CheckpointVerification {
    DigestMismatch { preserved_artifacts: bool, unverified_candidates: Vec<String> },
    BindingMismatch {
        mismatches: Vec<&'static str>,
        invalidated_acceptance_ids: Vec<String>,
        preserved_artifacts: bool,
        unverified_candidates: Vec<String>,
    },
    Valid {
        schedule_changed: bool,
        completed_effect_ids: Vec<String>,
        preserved_candidate_ids: Vec<String>,
    },
}

/// Port of `verifyExecutionCheckpoint`.
pub fn verify_execution_checkpoint(
    checkpoint: &ExecutionCheckpoint,
    current: &CurrentBindingState,
) -> CheckpointVerification {
    let preserved_candidates: Vec<String> = checkpoint
        .body
        .get("preserved_candidate_ids")
        .and_then(Value::as_array)
        .map(|a| {
            let mut v: Vec<String> =
                a.iter().filter_map(|x| x.as_str().map(str::to_string)).collect();
            v.sort();
            v
        })
        .unwrap_or_default();

    let recomputed = digest_value(&checkpoint.body);
    if !is_digest(&checkpoint.checkpoint_digest) || recomputed != checkpoint.checkpoint_digest {
        return CheckpointVerification::DigestMismatch {
            preserved_artifacts: true,
            unverified_candidates: preserved_candidates,
        };
    }

    let mut mismatches = Vec::new();
    let b = &checkpoint.body;
    if b.get("objective_lineage_id").and_then(Value::as_str) != Some(current.objective_lineage_id.as_str())
    {
        mismatches.push("objective_lineage");
    }
    if b.get("intent_epoch") != Some(&current.intent_epoch) {
        mismatches.push("intent_epoch");
    }
    if b.get("continuation_epoch") != Some(&current.continuation_epoch) {
        mismatches.push("continuation_epoch");
    }
    if b.get("repository_state").and_then(Value::as_str) != Some(current.repository_state.as_str()) {
        mismatches.push("repository_state");
    }
    let acceptance_contract_fp = b
        .get("acceptance")
        .and_then(|a| a.get("contract_fingerprint"))
        .and_then(Value::as_str);
    if acceptance_contract_fp != Some(current.contract_fingerprint.as_str()) {
        mismatches.push("acceptance_contract");
    }
    let event_sequence_matches = b.get("event_sequence").and_then(Value::as_i64) == Some(current.event_sequence);
    let event_digest_matches =
        b.get("event_digest").and_then(Value::as_str) == Some(current.event_digest.as_str());
    if !event_sequence_matches || !event_digest_matches {
        mismatches.push("event_continuity");
    }
    let mut current_producer_sorted = Map::new();
    let mut keys: Vec<&String> = current.producer_versions.keys().collect();
    keys.sort();
    for k in keys {
        current_producer_sorted.insert(k.clone(), current.producer_versions[k].clone());
    }
    if b.get("producer_versions") != Some(&Value::Object(current_producer_sorted)) {
        mismatches.push("producer_versions");
    }

    let checkpoint_schedule_fp = b
        .get("acceptance")
        .and_then(|a| a.get("schedule_fingerprint"))
        .cloned()
        .unwrap_or(Value::Null);
    let schedule_changed = checkpoint_schedule_fp != current.schedule_fingerprint;

    if !mismatches.is_empty() {
        return CheckpointVerification::BindingMismatch {
            mismatches,
            invalidated_acceptance_ids: current.invalidated_acceptance_ids.clone(),
            preserved_artifacts: true,
            unverified_candidates: preserved_candidates,
        };
    }

    let completed_effect_ids: Vec<String> = b
        .get("completed_effect_ids")
        .and_then(Value::as_array)
        .map(|a| a.iter().filter_map(|x| x.as_str().map(str::to_string)).collect())
        .unwrap_or_default();

    CheckpointVerification::Valid {
        schedule_changed,
        completed_effect_ids,
        preserved_candidate_ids: preserved_candidates,
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct RehydratedData {
    pub data: Value,
    pub authority_granted: bool,
    pub instruction_status: &'static str,
    pub preference_write_allowed: bool,
    pub effect_downgrade_allowed: bool,
}

/// Port of `rehydrateUntrustedData`.
pub fn rehydrate_untrusted_data(envelope: &Value) -> Result<RehydratedData, ContinuityError> {
    let schema_ok = envelope.get("schema").and_then(Value::as_str) == Some("rehydration-envelope.v1");
    let trust_ok = envelope.get("trust").and_then(Value::as_str) == Some("UNTRUSTED_DATA");
    if !schema_ok || !trust_ok {
        return fail("rehydration envelope must be typed UNTRUSTED_DATA");
    }
    let content_digest = envelope.get("content_digest").and_then(Value::as_str).unwrap_or("");
    let payload = envelope.get("payload").cloned().unwrap_or(Value::Null);
    if !is_digest(content_digest) || digest_value(&payload) != content_digest {
        return fail("rehydration content digest mismatch");
    }
    Ok(RehydratedData {
        data: payload,
        authority_granted: false,
        instruction_status: "DATA_ONLY",
        preference_write_allowed: false,
        effect_downgrade_allowed: false,
    })
}

/// Port of `ContinuityController`.
#[derive(Debug, Clone)]
pub struct ContinuityController {
    intent_epoch: i64,
    continuation_epoch: i64,
    cancelled: bool,
    completed_effects: std::collections::BTreeSet<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContinuationToken {
    pub work_id: String,
    pub intent_epoch: i64,
    pub continuation_epoch: i64,
}

impl ContinuityController {
    pub fn new(intent_epoch: i64, continuation_epoch: i64, completed_effect_ids: Vec<String>) -> Self {
        Self {
            intent_epoch,
            continuation_epoch,
            cancelled: false,
            completed_effects: completed_effect_ids.into_iter().collect(),
        }
    }

    pub fn bind(&self, work_id: &str) -> Result<ContinuationToken, ContinuityError> {
        if work_id.is_empty() {
            return fail("work id is required");
        }
        Ok(ContinuationToken {
            work_id: work_id.to_string(),
            intent_epoch: self.intent_epoch,
            continuation_epoch: self.continuation_epoch,
        })
    }

    pub fn cancel(&mut self, next_intent_epoch: i64) -> Result<(bool, i64), ContinuityError> {
        if next_intent_epoch <= self.intent_epoch {
            return fail("cancellation must advance intent epoch");
        }
        self.intent_epoch = next_intent_epoch;
        self.cancelled = true;
        Ok((true, self.intent_epoch))
    }

    pub fn resume(&mut self, intent_epoch: i64, continuation_epoch: i64) -> Result<(), ContinuityError> {
        if intent_epoch < self.intent_epoch || continuation_epoch <= self.continuation_epoch {
            return fail("resume requires current intent and newer continuation epoch");
        }
        self.intent_epoch = intent_epoch;
        self.continuation_epoch = continuation_epoch;
        self.cancelled = false;
        Ok(())
    }

    pub fn assert_current(&self, token: &ContinuationToken) -> Result<bool, ContinuityError> {
        if self.cancelled
            || token.intent_epoch != self.intent_epoch
            || token.continuation_epoch != self.continuation_epoch
        {
            return fail("stale or cancelled continuation");
        }
        Ok(true)
    }

    pub fn claim_effect(
        &mut self,
        token: &ContinuationToken,
        effect_id: &str,
    ) -> Result<(String, bool), ContinuityError> {
        self.assert_current(token)?;
        if effect_id.is_empty() {
            return fail("effect id is required");
        }
        if self.completed_effects.contains(effect_id) {
            return fail("duplicate effect denied");
        }
        self.completed_effects.insert(effect_id.to_string());
        Ok((effect_id.to_string(), true))
    }

    pub fn completed_effect_ids(&self) -> Vec<String> {
        self.completed_effects.iter().cloned().collect()
    }
}

/// Port of `cancelProcessGroup`, generalized over synchronous `terminate`/
/// `alive` closures (the JS versions are async; callers of this pure port
/// run any I/O before/around it, e.g. via `tokio::task::block_in_place` or
/// by making the closures do blocking I/O directly).
pub fn cancel_process_group<T, A>(
    group_id: &str,
    max_passes: u32,
    mut terminate: T,
    mut alive: A,
) -> Result<(String, bool, u32), ContinuityError>
where
    T: FnMut(&str),
    A: FnMut(&str) -> Vec<String>,
{
    if group_id.is_empty() {
        return fail("process-group controller is required");
    }
    let max_passes = if max_passes == 0 { 2 } else { max_passes };
    for pass in 1..=max_passes {
        terminate(group_id);
        let survivors = alive(group_id);
        if survivors.is_empty() {
            return Ok((group_id.to_string(), true, pass));
        }
    }
    fail("process group failed to quiesce")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn valid_digest_of(value: &Value) -> String {
        digest_value(value)
    }

    #[test]
    fn acceptance_binding_v1() {
        let ledger = AcceptanceLedger::V1 { acceptance_fingerprint: json!("fp") };
        let cf = "sha256:".to_string() + &"a".repeat(64);
        let out = acceptance_binding(&ledger, Some(&cf)).unwrap();
        assert_eq!(out.contract_fingerprint, cf);
        assert_eq!(out.acceptance_manifest_fingerprint, json!("fp"));
        assert_eq!(out.schedule_fingerprint, Value::Null);
    }

    #[test]
    fn acceptance_binding_rejects_bad_fingerprint() {
        let ledger = AcceptanceLedger::V1 { acceptance_fingerprint: json!("fp") };
        assert!(acceptance_binding(&ledger, Some("not-a-digest")).is_err());
        assert!(acceptance_binding(&ledger, None).is_err());
    }

    #[test]
    fn acceptance_binding_unsupported_ledger() {
        let cf = "sha256:".to_string() + &"a".repeat(64);
        assert!(acceptance_binding(&AcceptanceLedger::Unsupported, Some(&cf)).is_err());
    }

    fn repo_digest() -> String {
        "sha256:".to_string() + &"b".repeat(64)
    }
    fn event_digest() -> String {
        "sha256:".to_string() + &"c".repeat(64)
    }

    #[test]
    fn checkpoint_round_trips_through_verify() {
        let cf = "sha256:".to_string() + &"a".repeat(64);
        let ledger = AcceptanceLedger::V1 { acceptance_fingerprint: json!("m") };
        let checkpoint = create_execution_checkpoint(CreateCheckpointInput {
            objective_lineage_id: "obj-1",
            intent_epoch: json!(1),
            continuation_epoch: json!(1),
            repository_state: &repo_digest(),
            acceptance_ledger: &ledger,
            contract_fingerprint: Some(&cf),
            producer_versions: Map::new(),
            event_sequence: 5,
            event_digest: &event_digest(),
            completed_effect_ids: vec!["e2".into(), "e1".into(), "e1".into()],
            preserved_candidate_ids: vec![],
            created_at: Some("2026-01-01T00:00:00.000Z"),
        })
        .unwrap();
        assert!(checkpoint.checkpoint_digest.starts_with("sha256:"));
        assert_eq!(
            checkpoint.body["completed_effect_ids"],
            json!(["e1", "e2"])
        );

        let current = CurrentBindingState {
            objective_lineage_id: "obj-1".to_string(),
            intent_epoch: json!(1),
            continuation_epoch: json!(1),
            repository_state: repo_digest(),
            contract_fingerprint: cf.clone(),
            event_sequence: 5,
            event_digest: event_digest(),
            producer_versions: Map::new(),
            schedule_fingerprint: Value::Null,
            invalidated_acceptance_ids: vec![],
        };
        match verify_execution_checkpoint(&checkpoint, &current) {
            CheckpointVerification::Valid { schedule_changed, completed_effect_ids, .. } => {
                assert!(!schedule_changed);
                assert_eq!(completed_effect_ids, vec!["e1", "e2"]);
            }
            other => panic!("expected Valid, got {other:?}"),
        }
    }

    #[test]
    fn checkpoint_digest_tamper_is_detected() {
        let cf = "sha256:".to_string() + &"a".repeat(64);
        let ledger = AcceptanceLedger::V1 { acceptance_fingerprint: json!("m") };
        let mut checkpoint = create_execution_checkpoint(CreateCheckpointInput {
            objective_lineage_id: "obj-1",
            intent_epoch: json!(1),
            continuation_epoch: json!(1),
            repository_state: &repo_digest(),
            acceptance_ledger: &ledger,
            contract_fingerprint: Some(&cf),
            producer_versions: Map::new(),
            event_sequence: 1,
            event_digest: &event_digest(),
            completed_effect_ids: vec![],
            preserved_candidate_ids: vec![],
            created_at: Some("2026-01-01T00:00:00.000Z"),
        })
        .unwrap();
        checkpoint.body["event_sequence"] = json!(999);
        let current = CurrentBindingState {
            objective_lineage_id: "obj-1".to_string(),
            intent_epoch: json!(1),
            continuation_epoch: json!(1),
            repository_state: repo_digest(),
            contract_fingerprint: cf,
            event_sequence: 1,
            event_digest: event_digest(),
            producer_versions: Map::new(),
            schedule_fingerprint: Value::Null,
            invalidated_acceptance_ids: vec![],
        };
        match verify_execution_checkpoint(&checkpoint, &current) {
            CheckpointVerification::DigestMismatch { preserved_artifacts, .. } => {
                assert!(preserved_artifacts);
            }
            other => panic!("expected DigestMismatch, got {other:?}"),
        }
    }

    #[test]
    fn checkpoint_binding_mismatch_lists_fields() {
        let cf = "sha256:".to_string() + &"a".repeat(64);
        let ledger = AcceptanceLedger::V1 { acceptance_fingerprint: json!("m") };
        let checkpoint = create_execution_checkpoint(CreateCheckpointInput {
            objective_lineage_id: "obj-1",
            intent_epoch: json!(1),
            continuation_epoch: json!(1),
            repository_state: &repo_digest(),
            acceptance_ledger: &ledger,
            contract_fingerprint: Some(&cf),
            producer_versions: Map::new(),
            event_sequence: 1,
            event_digest: &event_digest(),
            completed_effect_ids: vec![],
            preserved_candidate_ids: vec![],
            created_at: Some("2026-01-01T00:00:00.000Z"),
        })
        .unwrap();
        let current = CurrentBindingState {
            objective_lineage_id: "obj-DIFFERENT".to_string(),
            intent_epoch: json!(1),
            continuation_epoch: json!(1),
            repository_state: repo_digest(),
            contract_fingerprint: cf,
            event_sequence: 1,
            event_digest: event_digest(),
            producer_versions: Map::new(),
            schedule_fingerprint: Value::Null,
            invalidated_acceptance_ids: vec!["a1".into()],
        };
        match verify_execution_checkpoint(&checkpoint, &current) {
            CheckpointVerification::BindingMismatch { mismatches, invalidated_acceptance_ids, .. } => {
                assert!(mismatches.contains(&"objective_lineage"));
                assert_eq!(invalidated_acceptance_ids, vec!["a1"]);
            }
            other => panic!("expected BindingMismatch, got {other:?}"),
        }
    }

    #[test]
    fn rehydrate_untrusted_data_round_trip() {
        let payload = json!({"foo": "bar"});
        let digest = valid_digest_of(&payload);
        let envelope = json!({
            "schema": "rehydration-envelope.v1",
            "trust": "UNTRUSTED_DATA",
            "content_digest": digest,
            "payload": payload,
        });
        let out = rehydrate_untrusted_data(&envelope).unwrap();
        assert!(!out.authority_granted);
        assert_eq!(out.instruction_status, "DATA_ONLY");
        assert_eq!(out.data, json!({"foo": "bar"}));
    }

    #[test]
    fn rehydrate_untrusted_data_rejects_wrong_schema() {
        let envelope = json!({"schema": "other", "trust": "UNTRUSTED_DATA"});
        assert!(rehydrate_untrusted_data(&envelope).is_err());
    }

    #[test]
    fn rehydrate_untrusted_data_rejects_digest_mismatch() {
        let envelope = json!({
            "schema": "rehydration-envelope.v1",
            "trust": "UNTRUSTED_DATA",
            "content_digest": "sha256:".to_string() + &"0".repeat(64),
            "payload": {"foo": "bar"},
        });
        assert!(rehydrate_untrusted_data(&envelope).is_err());
    }

    #[test]
    fn continuity_controller_bind_and_claim() {
        let mut controller = ContinuityController::new(1, 1, vec![]);
        let token = controller.bind("work-1").unwrap();
        assert!(controller.assert_current(&token).unwrap());
        let (id, accepted) = controller.claim_effect(&token, "eff-1").unwrap();
        assert_eq!(id, "eff-1");
        assert!(accepted);
        assert!(controller.claim_effect(&token, "eff-1").is_err());
        assert_eq!(controller.completed_effect_ids(), vec!["eff-1"]);
    }

    #[test]
    fn continuity_controller_cancel_and_resume() {
        let mut controller = ContinuityController::new(1, 1, vec![]);
        let token = controller.bind("w").unwrap();
        controller.cancel(2).unwrap();
        assert!(controller.assert_current(&token).is_err());
        assert!(controller.cancel(1).is_err());
        controller.resume(2, 2).unwrap();
        let fresh = controller.bind("w").unwrap();
        assert!(controller.assert_current(&fresh).unwrap());
    }

    #[test]
    fn continuity_controller_resume_requires_advance() {
        let mut controller = ContinuityController::new(2, 3, vec![]);
        assert!(controller.resume(1, 4).is_err()); // intent_epoch regressed
        assert!(controller.resume(2, 3).is_err()); // continuation_epoch not newer
        assert!(controller.resume(2, 4).is_ok());
    }

    #[test]
    fn cancel_process_group_quiesces() {
        let mut calls = 0;
        let result = cancel_process_group(
            "grp",
            2,
            |_| calls += 1,
            |_| if calls >= 1 { vec![] } else { vec!["p1".into()] },
        )
        .unwrap();
        assert_eq!(result, ("grp".to_string(), true, 1));
    }

    #[test]
    fn cancel_process_group_fails_after_max_passes() {
        let result = cancel_process_group("grp", 2, |_| {}, |_| vec!["p1".into()]);
        assert!(result.is_err());
    }

    #[test]
    fn cancel_process_group_requires_group_id() {
        let result = cancel_process_group("", 2, |_| {}, |_| vec![]);
        assert!(result.is_err());
    }
}
