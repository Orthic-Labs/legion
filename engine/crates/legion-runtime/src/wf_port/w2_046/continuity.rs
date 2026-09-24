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
//! ## Packet r50: `WorkflowContinuityStore` and the host architecture lifecycle
//! - [`WorkflowContinuityStore`]: durable `node:fs` JSON-file state
//!   (`checkpoint`/`resume`/`pause`/`applyDirection`/`replan`), ported onto
//!   `std::fs` with the same atomic tmp-file-then-rename write and the same
//!   `stateDigest` computed over the state minus that field.
//! - [`create_host_architecture_state`] / [`consume_host_architecture_lifecycle`]
//!   / [`execution_trajectory_payload`]: these depend on
//!   `src/lib/verification/arcane/architecture-state.mjs` and
//!   `architecture-router.mjs` plus an authenticated `ArchitectureEventStore`,
//!   which are now reachable via `legion_policy::wf_port::wf070` (`state`,
//!   `router`, `event_store`) — `legion-runtime` already depends on
//!   `legion-policy`. `hostEvent`/`binding` are Rust structs ([`HostEvent`],
//!   [`ExecutionBinding`]) rather than dynamic objects, since every field
//!   this lifecycle reads is statically known.

use super::canonical::digest_value;
use legion_policy::wf_port::wf070::canon::{digest_value as canon_digest_value, CanonVal};
use legion_policy::wf_port::wf070::event_store::{ArchitectureEventStore, EventProposal};
use legion_policy::wf_port::wf070::router::{route_architecture, route_to_canon, ArchitectureRouterInput};
use legion_policy::wf_port::wf070::state::create_architecture_state;
use serde_json::{json, Map, Value};
use std::collections::BTreeMap;
use std::io::Write as _;
use std::path::PathBuf;
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

fn now_millis() -> u128 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis()).unwrap_or(0)
}

/// `encodeURIComponent`, byte-wise (matches JS's per-UTF-8-byte percent
/// encoding of non-ASCII characters).
fn encode_uri_component(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'!' | b'~' | b'*' | b'\'' | b'(' | b')' => {
                out.push(byte as char);
            }
            _ => {
                out.push('%');
                out.push_str(&format!("{byte:02X}"));
            }
        }
    }
    out
}

#[derive(Debug, Clone, Default)]
pub struct CheckpointNode {
    pub id: String,
    pub dependencies: Vec<String>,
    pub state: String,
}

#[derive(Debug, Clone, Default)]
pub struct WorkflowCheckpointInput {
    pub run_id: String,
    pub fingerprint: String,
    pub nodes: Vec<CheckpointNode>,
    pub completed_effects: Vec<String>,
    pub completed_outputs: Map<String, Value>,
}

/// Port of `WorkflowContinuityStore`. `clock` mirrors the JS constructor's
/// `clock = () => new Date().toISOString()` default; callers inject it for
/// deterministic tests.
pub struct WorkflowContinuityStore<'a> {
    root: PathBuf,
    clock: Box<dyn FnMut() -> String + 'a>,
}

impl<'a> WorkflowContinuityStore<'a> {
    pub fn new(root: PathBuf, clock: Box<dyn FnMut() -> String + 'a>) -> Self {
        Self { root, clock }
    }

    fn path_for(&self, run_id: &str) -> PathBuf {
        self.root.join(format!("{}.json", encode_uri_component(run_id)))
    }

    fn read(&self, run_id: &str) -> Option<Value> {
        let path = self.path_for(run_id);
        if !path.exists() {
            return None;
        }
        let text = std::fs::read_to_string(path).ok()?;
        serde_json::from_str(&text).ok()
    }

    /// Writes `state` (which must have a `runId` string field), stamping a
    /// fresh `stateDigest` over every other field. Mirrors `_write`'s
    /// `wx`-flagged temp file plus rename.
    fn write(&mut self, mut state: Value) -> Result<Value, ContinuityError> {
        let run_id = state
            .get("runId")
            .and_then(Value::as_str)
            .ok_or_else(|| ContinuityError("workflow continuity state requires runId".to_string()))?
            .to_string();
        std::fs::create_dir_all(&self.root).map_err(|e| ContinuityError(e.to_string()))?;
        let mut without_digest = state.clone();
        if let Value::Object(map) = &mut without_digest {
            map.remove("stateDigest");
        }
        let digest = digest_value(&without_digest);
        if let Value::Object(map) = &mut state {
            map.insert("stateDigest".to_string(), Value::String(digest));
        }
        let path = self.path_for(&run_id);
        let tmp = self.root.join(format!(".state-{}-{}.tmp", std::process::id(), now_millis()));
        let body = serde_json::to_string(&state).map_err(|e| ContinuityError(e.to_string()))?;
        {
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&tmp)
                .map_err(|e| ContinuityError(e.to_string()))?;
            file.write_all(body.as_bytes()).map_err(|e| ContinuityError(e.to_string()))?;
        }
        std::fs::rename(&tmp, &path).map_err(|e| ContinuityError(e.to_string()))?;
        Ok(state)
    }

    /// Port of `checkpoint`. Node identity/order mirrors the JS `Map`
    /// semantics: prior nodes keep their position, updated in place when a
    /// new node shares their id; genuinely new node ids are appended.
    pub fn checkpoint(&mut self, input: WorkflowCheckpointInput) -> Result<Value, ContinuityError> {
        if input.run_id.is_empty() || !is_digest(&input.fingerprint) {
            return fail("run id & fingerprint are required");
        }
        let prior = self.read(&input.run_id);
        let prior_nodes: Vec<(String, Value)> = prior
            .as_ref()
            .and_then(|p| p.get("nodes"))
            .and_then(Value::as_array)
            .map(|arr| {
                arr.iter()
                    .filter_map(|n| n.get("id").and_then(Value::as_str).map(|id| (id.to_string(), n.clone())))
                    .collect()
            })
            .unwrap_or_default();
        let mut order: Vec<String> = prior_nodes.iter().map(|(id, _)| id.clone()).collect();
        let mut by_id: BTreeMap<String, Value> = prior_nodes.into_iter().collect();
        for node in &input.nodes {
            if !by_id.contains_key(&node.id) {
                order.push(node.id.clone());
            }
            by_id.insert(
                node.id.clone(),
                json!({ "id": node.id, "dependencies": node.dependencies, "state": if node.state.is_empty() { "PENDING".to_string() } else { node.state.clone() } }),
            );
        }
        let nodes: Vec<Value> = order.iter().filter_map(|id| by_id.get(id).cloned()).collect();

        let prior_completed: Vec<String> = prior
            .as_ref()
            .and_then(|p| p.get("completedEffects"))
            .and_then(Value::as_array)
            .map(|a| a.iter().filter_map(|v| v.as_str().map(str::to_string)).collect())
            .unwrap_or_default();
        let completed_effects = sorted_unique_strings(prior_completed.into_iter().chain(input.completed_effects).collect());

        let mut completed_outputs = prior
            .as_ref()
            .and_then(|p| p.get("completedOutputs"))
            .and_then(Value::as_object)
            .cloned()
            .unwrap_or_default();
        for (k, v) in input.completed_outputs {
            completed_outputs.insert(k, v);
        }
        let pause = prior.as_ref().and_then(|p| p.get("pause")).cloned().unwrap_or(Value::Null);
        let continuation_epoch = prior.as_ref().and_then(|p| p.get("continuationEpoch")).and_then(Value::as_i64).unwrap_or(1);

        let state = json!({
            "schemaVersion": 1,
            "kind": "legion-workflow-continuity",
            "runId": input.run_id,
            "fingerprint": input.fingerprint,
            "continuationEpoch": continuation_epoch,
            "nodes": nodes,
            "completedEffects": completed_effects,
            "completedOutputs": completed_outputs,
            "pause": pause,
            "updatedAt": (self.clock)(),
        });
        self.write(state)
    }

    /// Port of `resume`.
    pub fn resume(&self, run_id: &str, fingerprint: &str) -> Result<Value, ContinuityError> {
        let state = self.read(run_id);
        let matches = state.as_ref().and_then(|s| s.get("fingerprint")).and_then(Value::as_str) == Some(fingerprint);
        let state = match state {
            Some(s) if matches => s,
            _ => return fail("workflow continuity fingerprint mismatch"),
        };
        let unfinished: Vec<Value> = state
            .get("nodes")
            .and_then(Value::as_array)
            .map(|arr| {
                arr.iter()
                    .filter(|n| {
                        let s = n.get("state").and_then(Value::as_str).unwrap_or("");
                        !matches!(s, "SUCCEEDED" | "SKIPPED")
                    })
                    .cloned()
                    .collect()
            })
            .unwrap_or_default();
        Ok(json!({
            "runId": run_id,
            "continuationEpoch": state.get("continuationEpoch").cloned().unwrap_or(json!(1)),
            "unfinished": unfinished,
            "completedEffects": state.get("completedEffects").cloned().unwrap_or(json!([])),
            "completedOutputs": state.get("completedOutputs").cloned().unwrap_or(json!({})),
        }))
    }

    /// Port of `pause`.
    pub fn pause(
        &mut self,
        run_id: &str,
        decision_id: &str,
        phase: &str,
        choices: Vec<String>,
        context_fingerprint: &str,
        continuation_token: Value,
    ) -> Result<Value, ContinuityError> {
        let state = self.read(run_id);
        if state.is_none() || decision_id.is_empty() || choices.is_empty() || !is_digest(context_fingerprint) {
            return fail("named pause decision is invalid");
        }
        let mut state = state.unwrap();
        let pause = json!({
            "decisionId": decision_id,
            "phase": phase,
            "choices": choices,
            "contextFingerprint": context_fingerprint,
            "continuationToken": continuation_token,
            "chosen": null,
            "responseDigest": null,
            "pausedAt": (self.clock)(),
        });
        if let Value::Object(map) = &mut state {
            map.insert("pause".to_string(), pause);
            map.insert("updatedAt".to_string(), json!((self.clock)()));
        }
        self.write(state)
    }

    /// Port of `applyDirection`.
    pub fn apply_direction(&mut self, run_id: &str, decision_id: &str, choice: &str, response: &Value) -> Result<Value, ContinuityError> {
        let mut state = self.read(run_id).ok_or_else(|| ContinuityError("operator direction does not bind current pause".to_string()))?;
        let pause = state.get("pause").cloned().unwrap_or(Value::Null);
        let pause_decision_id = pause.get("decisionId").and_then(Value::as_str);
        let choices_include = pause.get("choices").and_then(Value::as_array).map(|a| a.iter().any(|c| c.as_str() == Some(choice))).unwrap_or(false);
        if pause.is_null() || pause_decision_id != Some(decision_id) || !choices_include {
            return fail("operator direction does not bind current pause");
        }
        let continuation_epoch = state.get("continuationEpoch").and_then(Value::as_i64).unwrap_or(1);
        let mut new_pause = pause;
        if let Value::Object(map) = &mut new_pause {
            map.insert("chosen".to_string(), json!(choice));
            map.insert("responseDigest".to_string(), json!(digest_value(response)));
            map.insert("resumedAt".to_string(), json!((self.clock)()));
        }
        if let Value::Object(map) = &mut state {
            map.insert("continuationEpoch".to_string(), json!(continuation_epoch + 1));
            map.insert("pause".to_string(), new_pause);
            map.insert("updatedAt".to_string(), json!((self.clock)()));
        }
        self.write(state)
    }

    /// Port of `replan`.
    pub fn replan(&mut self, run_id: &str, failure: &Value, replacement_nodes: Vec<Value>) -> Result<Value, ContinuityError> {
        if failure.is_null() {
            return fail("failure & replacement nodes are required");
        }
        let mut state = self.read(run_id).ok_or_else(|| ContinuityError("failure & replacement nodes are required".to_string()))?;
        let empty = vec![];
        let prior_nodes = state.get("nodes").and_then(Value::as_array).unwrap_or(&empty).clone();
        let completed: Vec<Value> = prior_nodes.into_iter().filter(|n| n.get("state").and_then(Value::as_str) == Some("SUCCEEDED")).collect();
        let completed_ids: std::collections::HashSet<String> =
            completed.iter().filter_map(|n| n.get("id").and_then(Value::as_str).map(str::to_string)).collect();
        if replacement_nodes.iter().any(|n| n.get("id").and_then(Value::as_str).map(|id| completed_ids.contains(id)).unwrap_or(false)) {
            return fail("replan may not replace completed nodes");
        }
        let mut nodes = completed;
        for node in replacement_nodes {
            let id = node.get("id").cloned().unwrap_or(Value::Null);
            let dependencies = node.get("dependencies").cloned().unwrap_or(json!([]));
            let node_state = node.get("state").and_then(Value::as_str).unwrap_or("PENDING").to_string();
            nodes.push(json!({ "id": id, "dependencies": dependencies, "state": node_state }));
        }
        let continuation_epoch = state.get("continuationEpoch").and_then(Value::as_i64).unwrap_or(1);
        let completed_outputs = state.get("completedOutputs").cloned().unwrap_or(json!({}));
        let replan = json!({
            "failureDigest": digest_value(failure),
            "preservedOutputDigest": digest_value(&completed_outputs),
            "at": (self.clock)(),
        });
        if let Value::Object(map) = &mut state {
            map.insert("continuationEpoch".to_string(), json!(continuation_epoch + 1));
            map.insert("nodes".to_string(), json!(nodes));
            map.insert("replan".to_string(), replan);
            map.insert("updatedAt".to_string(), json!((self.clock)()));
        }
        self.write(state)
    }
}

/// Host hooks are the only production producer for this minimal lifecycle:
/// they carry no model-authored architecture state. Mirrors `hostLineage`.
fn host_lineage(workspace: &str, session_id: Option<&str>) -> String {
    let value = CanonVal::obj()
        .set("workspace", CanonVal::Str(workspace.to_string()))
        .set("sessionId", session_id.map(|s| CanonVal::Str(s.to_string())).unwrap_or(CanonVal::Null));
    format!("host:{}", canon_digest_value(&value))
}

/// Mirrors `hostAcceptance`.
fn host_acceptance(workspace: &str, session_id: Option<&str>) -> CanonVal {
    let fingerprint_input = CanonVal::obj()
        .set("workspace", CanonVal::Str(workspace.to_string()))
        .set("sessionId", session_id.map(|s| CanonVal::Str(s.to_string())).unwrap_or(CanonVal::Null))
        .set("producer", CanonVal::Str("arcane-host-ingress-v1".to_string()));
    CanonVal::obj()
        .set("schema", CanonVal::Str("acceptance-ledger.v1".to_string()))
        .set("ledger_version", CanonVal::Int(1))
        .set("intent_epoch", CanonVal::Int(1))
        .set("acceptance_fingerprint", CanonVal::Str(canon_digest_value(&fingerprint_input)))
        .set("frozen_at", CanonVal::Str("1970-01-01T00:00:00.000Z".to_string()))
        .set("items", CanonVal::Arr(vec![]))
}

/// Port of `createHostArchitectureState`.
pub fn create_host_architecture_state(workspace: &str, session_id: Option<&str>) -> Result<CanonVal, ContinuityError> {
    if workspace.is_empty() {
        return fail("host workspace is required");
    }
    let budget_ref_input = CanonVal::obj()
        .set("workspace", CanonVal::Str(workspace.to_string()))
        .set("sessionId", session_id.map(|s| CanonVal::Str(s.to_string())).unwrap_or(CanonVal::Null));
    let budget_ref = format!("host:{}", canon_digest_value(&budget_ref_input));
    create_architecture_state(&host_lineage(workspace, session_id), host_acceptance(workspace, session_id), &budget_ref)
        .map_err(|e| ContinuityError(e.to_string()))
}

#[derive(Debug, Clone, Default)]
pub struct HostEventExtensions {
    pub parent_execution_id: Option<String>,
    pub work_node_id: Option<String>,
    pub dependency_ids: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct HostEffect {
    pub effect_class: String,
}

/// The subset of a host hook event `consumeHostArchitectureLifecycle` and
/// `executionTrajectoryPayload` read. `workspace` is a [`CanonVal`] (rather
/// than the plain `&str` the `workspace` *parameter* to
/// `consume_host_architecture_lifecycle` is) because the JS source digests
/// `hostEvent.workspace` as an arbitrary host-supplied value distinct from
/// the caller's own `workspace` argument.
#[derive(Debug, Clone)]
pub struct HostEvent {
    pub event_type: Option<String>,
    pub event_id: Option<String>,
    pub session_id: Option<String>,
    pub time: Option<String>,
    pub workspace: CanonVal,
    pub effect: Option<HostEffect>,
    pub extensions: HostEventExtensions,
}

impl Default for HostEvent {
    fn default() -> Self {
        Self {
            event_type: None,
            event_id: None,
            session_id: None,
            time: None,
            workspace: CanonVal::Null,
            effect: None,
            extensions: HostEventExtensions::default(),
        }
    }
}

/// Port of `executionTrajectoryPayload`.
pub fn execution_trajectory_payload(host_event: &HostEvent, payload: CanonVal) -> CanonVal {
    let is_stop = host_event.event_type.as_deref() == Some("stop");
    let mut map = match payload {
        CanonVal::Obj(m) => m,
        other => {
            let mut m = std::collections::BTreeMap::new();
            m.insert("value".to_string(), other);
            m
        }
    };
    let terminal_to = map.get("to").and_then(CanonVal::as_str).map(str::to_string);
    map.insert(
        "parent_execution_id".to_string(),
        host_event.extensions.parent_execution_id.clone().map(CanonVal::Str).unwrap_or(CanonVal::Null),
    );
    let work_node_id = host_event.extensions.work_node_id.clone().or_else(|| host_event.event_id.clone());
    map.insert("work_node_id".to_string(), work_node_id.map(CanonVal::Str).unwrap_or(CanonVal::Null));
    map.insert(
        "dependency_ids".to_string(),
        CanonVal::Arr(host_event.extensions.dependency_ids.iter().cloned().map(CanonVal::Str).collect()),
    );
    map.insert("submission_state".to_string(), CanonVal::Str(if is_stop { "TERMINAL" } else { "ACCEPTED" }.to_string()));
    map.insert("submitted_at".to_string(), host_event.time.clone().map(CanonVal::Str).unwrap_or(CanonVal::Null));
    map.insert(
        "terminal_state".to_string(),
        if is_stop { CanonVal::Str(terminal_to.unwrap_or_else(|| "STOPPED".to_string())) } else { CanonVal::Null },
    );
    CanonVal::Obj(map)
}

#[derive(Debug, Clone)]
pub struct ExecutionBinding {
    pub run_id: String,
}

/// Port of `consumeHostArchitectureLifecycle`. Returns `(state,
/// state_fingerprint)` on success, mirroring the JS `{ state,
/// state_fingerprint }` return.
pub fn consume_host_architecture_lifecycle<'a>(
    event_store: &mut ArchitectureEventStore<'a>,
    host_event: &HostEvent,
    binding: Option<&ExecutionBinding>,
    workspace: &str,
    stop_intent: &str,
) -> Result<(CanonVal, String), ContinuityError> {
    let initial_state = create_host_architecture_state(workspace, host_event.session_id.as_deref())?;
    let objective_lineage_id = initial_state
        .get("task")
        .and_then(|t| t.get("objective_lineage_id"))
        .and_then(CanonVal::as_str)
        .ok_or_else(|| ContinuityError("host architecture state missing objective_lineage_id".to_string()))?
        .to_string();

    let events_result =
        event_store.replay(&objective_lineage_id, &initial_state).map_err(|e| ContinuityError(e.to_string()))?;
    let mut state = events_result.state;
    let mut state_fingerprint = events_result.state_fingerprint;

    let execution_id = binding
        .map(|b| b.run_id.clone())
        .unwrap_or_else(|| format!("host:{}", host_event.session_id.clone().unwrap_or_else(|| "unbound".to_string())));
    let repository_id = format!("workspace:{}", canon_digest_value(&host_event.workspace));
    let effect_canon = host_event
        .effect
        .as_ref()
        .map(|e| CanonVal::obj().set("effectClass", CanonVal::Str(e.effect_class.clone())))
        .unwrap_or(CanonVal::Null);
    let input_fingerprint_input = CanonVal::obj()
        .set("eventType", host_event.event_type.clone().map(CanonVal::Str).unwrap_or(CanonVal::Null))
        .set("eventId", host_event.event_id.clone().map(CanonVal::Str).unwrap_or(CanonVal::Null))
        .set("effect", effect_canon);
    let input_fingerprint = canon_digest_value(&input_fingerprint_input);

    let mut accept = |state: &mut CanonVal,
                       state_fingerprint: &mut String,
                       event_type: &str,
                       payload: CanonVal,
                       phase: &str|
     -> Result<(), ContinuityError> {
        let intent_epoch = state.get("intent").and_then(|i| i.get("intent_epoch")).and_then(CanonVal::as_int).unwrap_or(1);
        let final_payload =
            if event_type == "ROUTE_CLASSIFIED" { execution_trajectory_payload(host_event, payload) } else { payload };
        let proposal = EventProposal {
            objective_lineage_id: objective_lineage_id.clone(),
            intent_epoch,
            execution_id: execution_id.clone(),
            repository_id: repository_id.clone(),
            actor_role: "host".to_string(),
            phase: phase.to_string(),
            event_type: event_type.to_string(),
            payload: final_payload,
            acceptance_ids: vec![],
            decision_ids: vec![],
            finding_ids: vec![],
            input_fingerprint: Some(input_fingerprint.clone()),
            output_refs: vec![],
            checkpoint_ref: None,
            cost_delta: CanonVal::obj(),
            retry_class: "none".to_string(),
            terminal_reason: None,
            privacy_class: "metadata".to_string(),
        };
        let accepted = event_store
            .accept(&proposal, Some(state_fingerprint.as_str()))
            .map_err(|e| ContinuityError(format!("host architecture lifecycle rejected: {}", e.code)))?;
        *state = accepted.state;
        *state_fingerprint = accepted.state_fingerprint;
        Ok(())
    };

    let architecture_status = state.get("task").and_then(|t| t.get("architecture_status")).and_then(CanonVal::as_str);
    if architecture_status == Some("UNROUTED") {
        let router_input = ArchitectureRouterInput {
            objective: Some("sufficient".to_string()),
            significance: std::collections::BTreeSet::new(),
            category: host_event.effect.as_ref().map(|e| e.effect_class.clone()),
            semantic_risk: if host_event.effect.is_none() { Some("ambiguous".to_string()) } else { None },
            ..Default::default()
        };
        let route = route_architecture(&router_input).map_err(|e| ContinuityError(e.0))?;
        accept(&mut state, &mut state_fingerprint, "ROUTE_CLASSIFIED", route_to_canon(&route), "route")?;
        let transition = CanonVal::obj().set("from", CanonVal::Str("UNROUTED".to_string())).set("to", CanonVal::Str("TAILORED".to_string()));
        accept(&mut state, &mut state_fingerprint, "ARCHITECTURE_TRANSITIONED", transition, "route")?;
    }

    if host_event.event_type.as_deref() == Some("pre-effect") {
        let episode_state = state.get("execution").and_then(|e| e.get("episode_state")).and_then(CanonVal::as_str).map(str::to_string);
        if episode_state.as_deref() == Some("PENDING") {
            let payload = CanonVal::obj().set("from", CanonVal::Str("PENDING".to_string())).set("to", CanonVal::Str("QUEUED".to_string()));
            accept(&mut state, &mut state_fingerprint, "EXECUTION_EPISODE_TRANSITIONED", payload, "execute")?;
        }
        let episode_state = state.get("execution").and_then(|e| e.get("episode_state")).and_then(CanonVal::as_str).map(str::to_string);
        if episode_state.as_deref() == Some("QUEUED") {
            let payload = CanonVal::obj().set("from", CanonVal::Str("QUEUED".to_string())).set("to", CanonVal::Str("RUNNING".to_string()));
            accept(&mut state, &mut state_fingerprint, "EXECUTION_EPISODE_TRANSITIONED", payload, "execute")?;
        }
    }

    if host_event.event_type.as_deref() == Some("stop") {
        if matches!(stop_intent, "PAUSE" | "REVOKE" | "SCOPE_NARROW") {
            let intent_epoch = state.get("intent").and_then(|i| i.get("intent_epoch")).and_then(CanonVal::as_int).unwrap_or(1);
            let payload = CanonVal::obj().set("intent_epoch", CanonVal::Int(intent_epoch + 1));
            accept(&mut state, &mut state_fingerprint, "INTENT_EPOCH_ADVANCED", payload, "close")?;
        } else {
            let episode_state = state.get("execution").and_then(|e| e.get("episode_state")).and_then(CanonVal::as_str).map(str::to_string);
            if episode_state.as_deref() == Some("RUNNING") {
                let payload = CanonVal::obj().set("from", CanonVal::Str("RUNNING".to_string())).set("to", CanonVal::Str("SUCCEEDED".to_string()));
                accept(&mut state, &mut state_fingerprint, "EXECUTION_EPISODE_TRANSITIONED", payload, "close")?;
            }
        }
    }

    Ok((state, state_fingerprint))
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
        let calls = std::cell::Cell::new(0);
        let result = cancel_process_group(
            "grp",
            2,
            |_| calls.set(calls.get() + 1),
            |_| if calls.get() >= 1 { vec![] } else { vec!["p1".into()] },
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
