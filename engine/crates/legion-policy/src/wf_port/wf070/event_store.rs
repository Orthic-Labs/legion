//! Faithful port of `src/lib/verification/arcane/architecture-event-store.mjs`.
//!
//! Authenticated accepted-event trajectory over an injected receipt store.
//! The JS source is a class with private (`#`) fields mutated in place by
//! `replay`/`accept`; this port uses `&mut self` for the same effect rather
//! than interior mutability, since Rust callers naturally hold a unique
//! `&mut ArchitectureEventStore` where the JS caller held an object
//! reference — behavior at the API boundary (single required `replay` before
//! `accept`, same failure codes) is unchanged.
//!
//! MAC signing and verification are ported from
//! `src/lib/guard/compat/audit/receipt-auth.mjs`'s `signRecord`/`verifyRecord`
//! narrowed to what this module needs (a single `macDomain`, no legacy
//! `signature_or_mac` / binding-field checking, since the JS event store
//! itself never exercises those paths). See `super::canon`'s module doc for
//! why the HMAC/digest primitives live locally rather than in a shared
//! `arcane_port::receipt_auth`.

use std::collections::BTreeMap;

use super::canon::{constant_time_equal, digest_value, hmac_sha256_hex, mint_id, CanonVal};
use super::fingerprints::architecture_event_fingerprint;
use super::state::{
    apply_architecture_event, assert_architecture_state, fingerprint_architecture_state, with_state_fingerprint,
    StateError,
};

pub const ARCHITECTURE_EVENT_BOUND_FIELDS: &[&str] = &[
    "schema", "kind", "event_id", "sequence", "occurred_at", "objective_lineage_id", "intent_epoch",
    "continuation_epoch", "execution_id", "repository_id", "actor_role", "phase", "event_type", "payload",
    "acceptance_status", "acceptance_ids", "decision_ids", "finding_ids", "input_fingerprint", "output_refs",
    "checkpoint_ref", "cost_delta", "retry_class", "terminal_reason", "privacy_class", "predecessor_digest",
    "resulting_state_fingerprint",
];

pub const ARCHITECTURE_EVENT_TYPES: &[&str] = &[
    "ROUTE_CLASSIFIED", "ARCHITECTURE_TRANSITIONED", "DECISION_RECORDED", "DECISION_FROZEN",
    "INVALIDATION_RECORDED", "INTENT_EPOCH_ADVANCED", "CONTINUATION_EPOCH_ADVANCED",
    "EXECUTION_EPISODE_TRANSITIONED", "BUDGET_SNAPSHOT_RECORDED", "FINGERPRINTS_RECORDED", "FINDING_UPSERTED",
    "RETRY_RECORDED", "ACCEPTANCE_RESULT_RECORDED", "DELIVERY_DEFICIT_UPSERTED",
    "DOWNSTREAM_ACKNOWLEDGEMENT_RECORDED", "OWNERSHIP_DISPOSITION_RECORDED", "MIGRATION_CUTOVER_RECORDED",
    "ARTIFACT_ENVELOPE_RECORDED", "EVIDENCE_LIFECYCLE_RECORDED", "EFFECT_RECORDED", "EFFECT_DENIED",
    "CANCEL_RECORDED", "TERMINAL_STATE_RECORDED", "RECOVERY_RECORDED", "SUPERSESSION_RECORDED",
    "ARCHITECTURE_REVISION_RECORDED", "CONVERGENCE_REVISION_RECORDED",
];

const PROPOSAL_FIELDS: &[&str] = &[
    "objective_lineage_id", "intent_epoch", "execution_id", "repository_id", "actor_role", "phase", "event_type",
    "payload", "acceptance_ids", "decision_ids", "finding_ids", "input_fingerprint", "output_refs",
    "checkpoint_ref", "cost_delta", "retry_class", "terminal_reason", "privacy_class",
];
const RESERVED_FIELDS: &[&str] = &[
    "schema", "kind", "event_id", "sequence", "occurred_at", "continuation_epoch", "acceptance_status",
    "authentication", "predecessor_digest", "resulting_state_fingerprint",
];
const ACTOR_ROLES: &[&str] = &["legion", "sage", "alchemist", "oracle", "covenant", "worker", "host"];
const PHASES: &[&str] = &["route", "decide", "dispatch", "execute", "verify", "integrate", "close"];
const RETRY_CLASSES: &[&str] = &["none", "mechanical", "changed_input", "changed_method", "external"];
const PRIVACY_CLASSES: &[&str] = &["content_free", "metadata", "sensitive", "restricted"];
const EVENT_SCHEMA: &str = "execution-trajectory-event.v1";
const EVENT_KIND: &str = "architecture-trajectory-event";
const MAC_DOMAIN: &str = "arcane-architecture-event-v1";
const MAC_ALGORITHM: &str = "HMAC-SHA256";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventStoreError {
    pub code: &'static str,
    pub message: String,
}
impl std::fmt::Display for EventStoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}
impl std::error::Error for EventStoreError {}

fn fail<T>(code: &'static str, message: impl Into<String>) -> Result<T, EventStoreError> {
    Err(EventStoreError { code, message: message.into() })
}

impl From<StateError> for EventStoreError {
    fn from(e: StateError) -> Self {
        EventStoreError { code: "ARC_SCHEMA_INVALID", message: e.0 }
    }
}

/// A signing/verifying key ring. Mirrors the `keyRing.get(keyId)` contract
/// the JS source requires (throws `ARC_AUTH_KEY_UNAVAILABLE` when absent).
pub trait KeyRing {
    fn get(&self, key_id: &str) -> Option<&[u8]>;
}

/// Append-only receipt store. Mirrors the `{ append, list, verifyChain }`
/// duck-typed contract the JS constructor requires.
pub trait ReceiptStore {
    fn append(&mut self, event: CanonVal);
    fn list(&self) -> &[CanonVal];
    /// `Ok(())` when the chain verifies; `Err(reason)` otherwise. The JS
    /// source's `verifyChain()` result carries richer detail; this port only
    /// needs the pass/fail boundary the event store checks.
    fn verify_chain(&self) -> Result<(), String>;
}

fn project_bound_fields(record: &CanonVal, fields: &[&str]) -> Result<CanonVal, EventStoreError> {
    let map = record.as_obj().ok_or_else(|| EventStoreError { code: "ARC_CANONICALIZATION_FAILED", message: "record must be an object".into() })?;
    let mut out = BTreeMap::new();
    for field in fields {
        match map.get(*field) {
            Some(v) => {
                out.insert((*field).to_string(), v.clone());
            }
            None => return fail("ARC_CANONICALIZATION_FAILED", format!("bound field missing: {field}")),
        }
    }
    Ok(CanonVal::Obj(out))
}

fn mac_over(key: &[u8], record: &CanonVal, bound_fields: &[&str], mac_domain: &str) -> Result<String, EventStoreError> {
    let projected = project_bound_fields(record, bound_fields)?;
    let message = CanonVal::obj()
        .set("alg", CanonVal::Str(MAC_ALGORITHM.to_string()))
        .set("boundFields", CanonVal::Arr(bound_fields.iter().map(|f| CanonVal::Str((*f).to_string())).collect()))
        .set("macDomain", CanonVal::Str(mac_domain.to_string()))
        .set("subject", projected);
    let text = super::canon::canonical_json(&message);
    Ok(hmac_sha256_hex(key, text.as_bytes()))
}

#[derive(Debug, Clone)]
pub struct Authentication {
    pub alg: String,
    pub key_id: String,
    pub mac: String,
    pub mac_domain: String,
    pub bound_fields_digest: String,
}

impl Authentication {
    fn to_canon(&self) -> CanonVal {
        CanonVal::obj()
            .set("alg", CanonVal::Str(self.alg.clone()))
            .set("keyId", CanonVal::Str(self.key_id.clone()))
            .set("mac", CanonVal::Str(self.mac.clone()))
            .set("macDomain", CanonVal::Str(self.mac_domain.clone()))
            .set("boundFieldsDigest", CanonVal::Str(self.bound_fields_digest.clone()))
    }
}

fn digest_of_bound_field_list(fields: &[&str]) -> String {
    let list = CanonVal::Arr(fields.iter().map(|f| CanonVal::Str((*f).to_string())).collect());
    digest_value(&list)
}

/// Mirrors `signRecord`.
pub fn sign_record(record: &CanonVal, key_ring: &dyn KeyRing, key_id: &str, bound_fields: &[&str]) -> Result<Authentication, EventStoreError> {
    if bound_fields.is_empty() {
        return fail("ARC_CANONICALIZATION_FAILED", "signRecord requires a non-empty boundFields list");
    }
    let key = key_ring.get(key_id).ok_or_else(|| EventStoreError { code: "ARC_AUTH_KEY_UNAVAILABLE", message: format!("no key for keyId: {key_id}") })?;
    Ok(Authentication {
        alg: MAC_ALGORITHM.to_string(),
        key_id: key_id.to_string(),
        mac: mac_over(key, record, bound_fields, MAC_DOMAIN)?,
        mac_domain: MAC_DOMAIN.to_string(),
        bound_fields_digest: digest_of_bound_field_list(bound_fields),
    })
}

/// Mirrors `verifyRecord`, narrowed to this store's fixed `macDomain` and
/// bound-field list (the JS source's generic `expectedBinding` path is
/// unused by the architecture event store and not ported here).
pub fn verify_record(record: &CanonVal, auth: &Authentication, key_ring: &dyn KeyRing, bound_fields: &[&str]) -> Result<(), EventStoreError> {
    if auth.alg != MAC_ALGORITHM {
        return fail("ARC_AUTH_FORGED", format!("unsupported MAC algorithm: {}", auth.alg));
    }
    if auth.mac_domain != MAC_DOMAIN {
        return fail("ARC_AUTH_FORGED", "MAC domain does not match verifier requirement");
    }
    let expected_fields_digest = digest_of_bound_field_list(bound_fields);
    if !constant_time_equal(auth.bound_fields_digest.as_bytes(), expected_fields_digest.as_bytes()) {
        return fail("ARC_AUTH_FORGED", "bound field list does not match verifier requirement");
    }
    let key = key_ring
        .get(&auth.key_id)
        .ok_or_else(|| EventStoreError { code: "ARC_AUTH_KEY_UNAVAILABLE", message: format!("no key for keyId: {}", auth.key_id) })?;
    let expected_mac = mac_over(key, record, bound_fields, MAC_DOMAIN)?;
    if !constant_time_equal(auth.mac.as_bytes(), expected_mac.as_bytes()) {
        return fail("ARC_AUTH_FORGED", "MAC does not verify");
    }
    Ok(())
}

fn non_empty(value: Option<&str>, field: &str) -> Result<(), EventStoreError> {
    match value {
        Some(v) if !v.is_empty() => Ok(()),
        _ => fail("ARC_SCHEMA_INVALID", format!("{field} is required")),
    }
}

/// The mutable fields a caller may propose; the store fills in everything
/// reserved (sequence, occurred_at, authentication, digests, ...).
#[derive(Debug, Clone)]
pub struct EventProposal {
    pub objective_lineage_id: String,
    pub intent_epoch: i64,
    pub execution_id: String,
    pub repository_id: String,
    pub actor_role: String,
    pub phase: String,
    pub event_type: String,
    pub payload: CanonVal,
    pub acceptance_ids: Vec<String>,
    pub decision_ids: Vec<String>,
    pub finding_ids: Vec<String>,
    pub input_fingerprint: Option<String>,
    pub output_refs: Vec<String>,
    pub checkpoint_ref: Option<String>,
    pub cost_delta: CanonVal,
    pub retry_class: String,
    pub terminal_reason: Option<String>,
    pub privacy_class: String,
}

fn validate_proposal(proposal: &EventProposal) -> Result<(), EventStoreError> {
    non_empty(Some(&proposal.objective_lineage_id), "objective_lineage_id")?;
    non_empty(Some(&proposal.execution_id), "execution_id")?;
    non_empty(Some(&proposal.repository_id), "repository_id")?;
    non_empty(Some(&proposal.event_type), "event_type")?;
    if proposal.intent_epoch < 1 {
        return fail("ARC_SCHEMA_INVALID", "intent_epoch must be a positive integer");
    }
    if !ARCHITECTURE_EVENT_TYPES.contains(&proposal.event_type.as_str())
        || !ACTOR_ROLES.contains(&proposal.actor_role.as_str())
        || !PHASES.contains(&proposal.phase.as_str())
        || !RETRY_CLASSES.contains(&proposal.retry_class.as_str())
        || !PRIVACY_CLASSES.contains(&proposal.privacy_class.as_str())
    {
        return fail("ARC_SCHEMA_INVALID", "event proposal contains an illegal closed value");
    }
    if proposal.payload.as_obj().is_none() {
        return fail("ARC_SCHEMA_INVALID", "payload must be an object");
    }
    if proposal.cost_delta.as_obj().is_none() {
        return fail("ARC_SCHEMA_INVALID", "cost_delta must be an object");
    }
    Ok(())
}

fn event_to_canon(event: &StoredEvent) -> CanonVal {
    CanonVal::obj()
        .set("schema", CanonVal::Str(EVENT_SCHEMA.to_string()))
        .set("kind", CanonVal::Str(EVENT_KIND.to_string()))
        .set("event_id", CanonVal::Str(event.event_id.clone()))
        .set("sequence", CanonVal::Int(event.sequence))
        .set("occurred_at", CanonVal::Str(event.occurred_at.clone()))
        .set("objective_lineage_id", CanonVal::Str(event.objective_lineage_id.clone()))
        .set("intent_epoch", CanonVal::Int(event.intent_epoch))
        .set("continuation_epoch", CanonVal::Int(event.continuation_epoch))
        .set("execution_id", CanonVal::Str(event.execution_id.clone()))
        .set("repository_id", CanonVal::Str(event.repository_id.clone()))
        .set("actor_role", CanonVal::Str(event.actor_role.clone()))
        .set("phase", CanonVal::Str(event.phase.clone()))
        .set("event_type", CanonVal::Str(event.event_type.clone()))
        .set("payload", event.payload.clone())
        .set("acceptance_status", CanonVal::Str("ACCEPTED".to_string()))
        .set("acceptance_ids", CanonVal::Arr(event.acceptance_ids.iter().map(|s| CanonVal::Str(s.clone())).collect()))
        .set("decision_ids", CanonVal::Arr(event.decision_ids.iter().map(|s| CanonVal::Str(s.clone())).collect()))
        .set("finding_ids", CanonVal::Arr(event.finding_ids.iter().map(|s| CanonVal::Str(s.clone())).collect()))
        .set(
            "input_fingerprint",
            event.input_fingerprint.clone().map(CanonVal::Str).unwrap_or(CanonVal::Null),
        )
        .set("output_refs", CanonVal::Arr(event.output_refs.iter().map(|s| CanonVal::Str(s.clone())).collect()))
        .set("checkpoint_ref", event.checkpoint_ref.clone().map(CanonVal::Str).unwrap_or(CanonVal::Null))
        .set("cost_delta", event.cost_delta.clone())
        .set("retry_class", CanonVal::Str(event.retry_class.clone()))
        .set("terminal_reason", event.terminal_reason.clone().map(CanonVal::Str).unwrap_or(CanonVal::Null))
        .set("privacy_class", CanonVal::Str(event.privacy_class.clone()))
        .set("predecessor_digest", event.predecessor_digest.clone().map(CanonVal::Str).unwrap_or(CanonVal::Null))
        .set("resulting_state_fingerprint", CanonVal::Str(event.resulting_state_fingerprint.clone()))
        .set("authentication", event.authentication.to_canon())
}

#[derive(Debug, Clone)]
struct StoredEvent {
    event_id: String,
    sequence: i64,
    occurred_at: String,
    objective_lineage_id: String,
    intent_epoch: i64,
    continuation_epoch: i64,
    execution_id: String,
    repository_id: String,
    actor_role: String,
    phase: String,
    event_type: String,
    payload: CanonVal,
    acceptance_ids: Vec<String>,
    decision_ids: Vec<String>,
    finding_ids: Vec<String>,
    input_fingerprint: Option<String>,
    output_refs: Vec<String>,
    checkpoint_ref: Option<String>,
    cost_delta: CanonVal,
    retry_class: String,
    terminal_reason: Option<String>,
    privacy_class: String,
    predecessor_digest: Option<String>,
    resulting_state_fingerprint: String,
    authentication: Authentication,
}

fn accepted_events<'a>(receipt_store: &'a dyn ReceiptStore, objective_lineage_id: &str) -> Vec<&'a CanonVal> {
    receipt_store
        .list()
        .iter()
        .filter(|e| {
            e.get("schema").and_then(CanonVal::as_str) == Some(EVENT_SCHEMA)
                && e.get("kind").and_then(CanonVal::as_str) == Some(EVENT_KIND)
                && e.get("objective_lineage_id").and_then(CanonVal::as_str) == Some(objective_lineage_id)
        })
        .collect()
}

fn verify_receipt_store(receipt_store: &dyn ReceiptStore) -> Result<(), EventStoreError> {
    receipt_store.verify_chain().map_err(|reason| EventStoreError { code: "ARC_STORE_CORRUPT", message: format!("ReceiptStore chain verification failed: {reason}") })
}

fn parse_authentication(event: &CanonVal) -> Result<Authentication, EventStoreError> {
    let auth = event.get("authentication").ok_or_else(|| EventStoreError { code: "ARC_AUTH_UNAUTHENTICATED", message: "no authentication material present on this record".to_string() })?;
    let alg = auth.get("alg").and_then(CanonVal::as_str).unwrap_or("").to_string();
    let key_id = auth.get("keyId").and_then(CanonVal::as_str).unwrap_or("").to_string();
    let mac = auth.get("mac").and_then(CanonVal::as_str).unwrap_or("").to_string();
    let mac_domain = auth.get("macDomain").and_then(CanonVal::as_str).unwrap_or("").to_string();
    let bound_fields_digest = auth.get("boundFieldsDigest").and_then(CanonVal::as_str).unwrap_or("").to_string();
    if mac.is_empty() || key_id.is_empty() {
        return fail("ARC_AUTH_UNAUTHENTICATED", "no authentication material present on this record");
    }
    Ok(Authentication { alg, key_id, mac, mac_domain, bound_fields_digest })
}

fn replay_events(events: &[&CanonVal], initial_state: &CanonVal, key_ring: &dyn KeyRing) -> Result<(CanonVal, Option<String>), EventStoreError> {
    assert_architecture_state(initial_state)?;
    let mut state = initial_state.clone();
    let mut predecessor: Option<String> = None;
    for (index, event) in events.iter().enumerate() {
        let expected_fields: std::collections::BTreeSet<&str> = ARCHITECTURE_EVENT_BOUND_FIELDS.iter().copied().collect();
        let present_fields: std::collections::BTreeSet<&str> = event.as_obj().map(|m| m.keys().filter(|k| k.as_str() != "authentication").map(String::as_str).collect()).unwrap_or_default();
        if present_fields != expected_fields {
            return fail("ARC_SCHEMA_INVALID", "stored event violates closed accepted-event fields");
        }
        let auth = parse_authentication(event)?;
        verify_record(event, &auth, key_ring, ARCHITECTURE_EVENT_BOUND_FIELDS)?;

        let event_type = event.get("event_type").and_then(CanonVal::as_str).unwrap_or("");
        if event.get("schema").and_then(CanonVal::as_str) != Some(EVENT_SCHEMA)
            || event.get("kind").and_then(CanonVal::as_str) != Some(EVENT_KIND)
            || event.get("acceptance_status").and_then(CanonVal::as_str) != Some("ACCEPTED")
            || !ARCHITECTURE_EVENT_TYPES.contains(&event_type)
        {
            return fail("ARC_SCHEMA_INVALID", "stored event violates accepted-event schema");
        }
        let sequence = event.get("sequence").and_then(CanonVal::as_int).unwrap_or(-1);
        let predecessor_digest = event.get("predecessor_digest").and_then(CanonVal::as_str).map(str::to_string);
        let objective_lineage_id = event.get("objective_lineage_id").and_then(CanonVal::as_str).unwrap_or("");
        let intent_epoch = event.get("intent_epoch").and_then(CanonVal::as_int).unwrap_or(-1);
        let continuation_epoch = event.get("continuation_epoch").and_then(CanonVal::as_int).unwrap_or(-1);
        let state_lineage = state.get("task").and_then(|t| t.get("objective_lineage_id")).and_then(CanonVal::as_str).unwrap_or("");
        let state_intent_epoch = state.get("intent").and_then(|i| i.get("intent_epoch")).and_then(CanonVal::as_int).unwrap_or(-1);
        let state_continuation_epoch = state.get("intent").and_then(|i| i.get("continuation_epoch")).and_then(CanonVal::as_int).unwrap_or(-1);
        if sequence != (index as i64) + 1
            || predecessor_digest != predecessor
            || objective_lineage_id != state_lineage
            || intent_epoch != state_intent_epoch
            || continuation_epoch != state_continuation_epoch
        {
            return fail("ARC_STORE_CORRUPT", "stored trajectory lineage, sequence, predecessor, or epoch mismatch");
        }
        let payload = event.get("payload").cloned().unwrap_or_else(CanonVal::obj);
        state = apply_architecture_event(&state, event_type, &payload)?;
        state = with_state_fingerprint(&set_trajectory_last_sequence(&state, sequence));
        let event_digest = architecture_event_fingerprint(event);
        predecessor = Some(event_digest.clone());
        state = with_state_fingerprint(&set_trajectory_replay(&state, &event_digest, &state.get("state_fingerprint").and_then(CanonVal::as_str).unwrap_or("").to_string()));
        let resulting = event.get("resulting_state_fingerprint").and_then(CanonVal::as_str).unwrap_or("");
        if resulting != state.get("state_fingerprint").and_then(CanonVal::as_str).unwrap_or("") {
            return fail("ARC_STORE_CORRUPT", "stored resulting state fingerprint mismatch");
        }
    }
    Ok((state, predecessor))
}

fn set_trajectory_last_sequence(state: &CanonVal, sequence: i64) -> CanonVal {
    let mut next = state.clone();
    if let CanonVal::Obj(map) = &mut next {
        if let Some(CanonVal::Obj(execution)) = map.get_mut("execution") {
            if let Some(CanonVal::Obj(trajectory)) = execution.get_mut("trajectory") {
                trajectory.insert("last_sequence".to_string(), CanonVal::Int(sequence));
            }
        }
    }
    next
}

fn set_trajectory_replay(state: &CanonVal, last_event_digest: &str, replay_state_fingerprint: &str) -> CanonVal {
    let mut next = state.clone();
    if let CanonVal::Obj(map) = &mut next {
        if let Some(CanonVal::Obj(execution)) = map.get_mut("execution") {
            if let Some(CanonVal::Obj(trajectory)) = execution.get_mut("trajectory") {
                trajectory.insert("last_event_digest".to_string(), CanonVal::Str(last_event_digest.to_string()));
                trajectory.insert("replay_state_fingerprint".to_string(), CanonVal::Str(replay_state_fingerprint.to_string()));
            }
        }
    }
    next
}

#[derive(Debug)]
pub struct EventsResult {
    pub state: CanonVal,
    pub state_fingerprint: String,
    pub last_sequence: i64,
    pub last_event_digest: Option<String>,
    pub event_count: i64,
}

#[derive(Debug)]
pub struct AcceptResult {
    pub event: CanonVal,
    pub state: CanonVal,
    pub state_fingerprint: String,
    pub last_sequence: i64,
    pub last_event_digest: String,
}

pub struct ArchitectureEventStore<'a> {
    receipt_store: &'a mut dyn ReceiptStore,
    key_ring: &'a dyn KeyRing,
    key_id: String,
    clock: Box<dyn Fn() -> String + 'a>,
    initial_states: BTreeMap<String, CanonVal>,
}

impl<'a> ArchitectureEventStore<'a> {
    pub fn new(receipt_store: &'a mut dyn ReceiptStore, key_ring: &'a dyn KeyRing, key_id: &str, clock: Box<dyn Fn() -> String + 'a>) -> Result<Self, EventStoreError> {
        non_empty(Some(key_id), "keyId")?;
        Ok(Self { receipt_store, key_ring, key_id: key_id.to_string(), clock, initial_states: BTreeMap::new() })
    }

    pub fn events(&self, objective_lineage_id: &str) -> Result<Vec<CanonVal>, EventStoreError> {
        non_empty(Some(objective_lineage_id), "objective_lineage_id")?;
        verify_receipt_store(self.receipt_store)?;
        Ok(accepted_events(self.receipt_store, objective_lineage_id).into_iter().cloned().collect())
    }

    pub fn replay(&mut self, objective_lineage_id: &str, initial_state: &CanonVal) -> Result<EventsResult, EventStoreError> {
        non_empty(Some(objective_lineage_id), "objective_lineage_id")?;
        assert_architecture_state(initial_state)?;
        if initial_state.get("task").and_then(|t| t.get("objective_lineage_id")).and_then(CanonVal::as_str) != Some(objective_lineage_id) {
            return fail("ARC_BINDING_MISMATCH", "initial_state lineage differs from replay request");
        }
        verify_receipt_store(self.receipt_store)?;
        let events = accepted_events(self.receipt_store, objective_lineage_id);
        let event_count = events.len() as i64;
        let (state, predecessor) = replay_events(&events, initial_state, self.key_ring)?;
        self.initial_states.insert(objective_lineage_id.to_string(), initial_state.clone());
        let state_fingerprint = state.get("state_fingerprint").and_then(CanonVal::as_str).unwrap_or("").to_string();
        Ok(EventsResult { state, state_fingerprint, last_sequence: event_count, last_event_digest: predecessor, event_count })
    }

    pub fn accept(&mut self, proposal: &EventProposal, expected_state_fingerprint: Option<&str>) -> Result<AcceptResult, EventStoreError> {
        validate_proposal(proposal)?;
        let initial_state = self
            .initial_states
            .get(&proposal.objective_lineage_id)
            .cloned()
            .ok_or_else(|| EventStoreError { code: "ARC_BINDING_MISMATCH", message: "accept requires prior replay for objective lineage".to_string() })?;
        assert_architecture_state(&initial_state)?;
        if initial_state.get("task").and_then(|t| t.get("objective_lineage_id")).and_then(CanonVal::as_str) != Some(proposal.objective_lineage_id.as_str()) {
            return fail("ARC_BINDING_MISMATCH", "initial_state lineage differs from proposal");
        }
        verify_receipt_store(self.receipt_store)?;
        let events = accepted_events(self.receipt_store, &proposal.objective_lineage_id);
        let events_len = events.len() as i64;
        let (state, predecessor) = replay_events(&events, &initial_state, self.key_ring)?;
        let state_fp = state.get("state_fingerprint").and_then(CanonVal::as_str).unwrap_or("").to_string();
        if expected_state_fingerprint != Some(state_fp.as_str()) {
            return fail("ARC_BINDING_MISMATCH", "expected state fingerprint is stale");
        }
        let state_intent_epoch = state.get("intent").and_then(|i| i.get("intent_epoch")).and_then(CanonVal::as_int).unwrap_or(-1);
        if proposal.intent_epoch != state_intent_epoch {
            return fail("ARC_BINDING_MISMATCH", "proposal intent epoch differs from accepted projection");
        }
        let mut next = apply_architecture_event(&state, &proposal.event_type, &proposal.payload)?;
        let sequence = events_len + 1;
        next = with_state_fingerprint(&set_trajectory_last_sequence(&next, sequence));

        let continuation_epoch = state.get("intent").and_then(|i| i.get("continuation_epoch")).and_then(CanonVal::as_int).unwrap_or(1);
        let event_id = mint_id("art_");
        let stored = StoredEvent {
            event_id,
            sequence,
            occurred_at: (self.clock)(),
            objective_lineage_id: proposal.objective_lineage_id.clone(),
            intent_epoch: proposal.intent_epoch,
            continuation_epoch,
            execution_id: proposal.execution_id.clone(),
            repository_id: proposal.repository_id.clone(),
            actor_role: proposal.actor_role.clone(),
            phase: proposal.phase.clone(),
            event_type: proposal.event_type.clone(),
            payload: proposal.payload.clone(),
            acceptance_ids: proposal.acceptance_ids.clone(),
            decision_ids: proposal.decision_ids.clone(),
            finding_ids: proposal.finding_ids.clone(),
            input_fingerprint: proposal.input_fingerprint.clone(),
            output_refs: proposal.output_refs.clone(),
            checkpoint_ref: proposal.checkpoint_ref.clone(),
            cost_delta: proposal.cost_delta.clone(),
            retry_class: proposal.retry_class.clone(),
            terminal_reason: proposal.terminal_reason.clone(),
            privacy_class: proposal.privacy_class.clone(),
            predecessor_digest: predecessor,
            resulting_state_fingerprint: fingerprint_architecture_state(&next),
            authentication: Authentication { alg: MAC_ALGORITHM.to_string(), key_id: String::new(), mac: String::new(), mac_domain: MAC_DOMAIN.to_string(), bound_fields_digest: String::new() },
        };

        let mut event_canon = event_to_canon(&stored);
        let auth = sign_record(&event_canon, self.key_ring, &self.key_id, ARCHITECTURE_EVENT_BOUND_FIELDS)?;
        if let CanonVal::Obj(map) = &mut event_canon {
            map.insert("authentication".to_string(), auth.to_canon());
        }
        self.receipt_store.append(event_canon.clone());

        let last_event_digest = architecture_event_fingerprint(&event_canon);
        let accepted_state = with_state_fingerprint(&set_trajectory_replay(&next, &last_event_digest, next.get("state_fingerprint").and_then(CanonVal::as_str).unwrap_or("")));
        let accepted_fp = accepted_state.get("state_fingerprint").and_then(CanonVal::as_str).unwrap_or("").to_string();
        if accepted_fp != stored.resulting_state_fingerprint {
            return fail("ARC_STORE_CORRUPT", "accepted state fingerprint mismatch");
        }
        Ok(AcceptResult { event: event_canon, state: accepted_state, state_fingerprint: accepted_fp, last_sequence: sequence, last_event_digest })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wf_port::wf070::state::create_architecture_state;

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

    struct FixedKeyRing(BTreeMap<String, Vec<u8>>);
    impl KeyRing for FixedKeyRing {
        fn get(&self, key_id: &str) -> Option<&[u8]> {
            self.0.get(key_id).map(|v| v.as_slice())
        }
    }

    fn ledger() -> CanonVal {
        CanonVal::obj()
            .set("schema", CanonVal::Str("acceptance-ledger.v1".to_string()))
            .set("ledger_version", CanonVal::Int(1))
            .set("intent_epoch", CanonVal::Int(1))
            .set("acceptance_fingerprint", CanonVal::Str(digest_value(&CanonVal::obj())))
            .set("frozen_at", CanonVal::Null)
            .set("items", CanonVal::Arr(vec![]))
    }

    fn keys() -> FixedKeyRing {
        let mut m = BTreeMap::new();
        m.insert("k1".to_string(), b"test-key-material".to_vec());
        FixedKeyRing(m)
    }

    fn proposal(objective_lineage_id: &str) -> EventProposal {
        EventProposal {
            objective_lineage_id: objective_lineage_id.to_string(),
            intent_epoch: 1,
            execution_id: "exec-1".to_string(),
            repository_id: "repo-1".to_string(),
            actor_role: "legion".to_string(),
            phase: "route".to_string(),
            event_type: "ARCHITECTURE_TRANSITIONED".to_string(),
            payload: CanonVal::obj().set("from", CanonVal::Str("UNROUTED".into())).set("to", CanonVal::Str("TAILORED".into())),
            acceptance_ids: vec![],
            decision_ids: vec![],
            finding_ids: vec![],
            input_fingerprint: None,
            output_refs: vec![],
            checkpoint_ref: None,
            cost_delta: CanonVal::obj(),
            retry_class: "none".to_string(),
            terminal_reason: None,
            privacy_class: "content_free".to_string(),
        }
    }

    #[test]
    fn accept_requires_prior_replay() {
        let mut store = MemoryReceiptStore(vec![]);
        let key_ring = keys();
        let mut event_store = ArchitectureEventStore::new(&mut store, &key_ring, "k1", Box::new(|| "2026-01-01T00:00:00Z".to_string())).unwrap();
        let err = event_store.accept(&proposal("lineage-1"), Some("whatever")).unwrap_err();
        assert_eq!(err.code, "ARC_BINDING_MISMATCH");
    }

    #[test]
    fn replay_then_accept_round_trips_and_verifies() {
        let mut store = MemoryReceiptStore(vec![]);
        let key_ring = keys();
        let initial = create_architecture_state("lineage-1", ledger(), "budget-1").unwrap();
        let mut event_store = ArchitectureEventStore::new(&mut store, &key_ring, "k1", Box::new(|| "2026-01-01T00:00:00Z".to_string())).unwrap();

        let replayed = event_store.replay("lineage-1", &initial).unwrap();
        assert_eq!(replayed.event_count, 0);
        assert_eq!(replayed.state_fingerprint, initial.get("state_fingerprint").and_then(CanonVal::as_str).unwrap());

        let accepted = event_store.accept(&proposal("lineage-1"), Some(replayed.state_fingerprint.as_str())).unwrap();
        assert_eq!(accepted.last_sequence, 1);
        assert_eq!(accepted.state.get("task").unwrap().get("architecture_status").unwrap().as_str(), Some("TAILORED"));

        // Re-replay from scratch must reconstruct the identical state.
        drop(event_store);
        let mut event_store2 = ArchitectureEventStore::new(event_store_receipt_store(&mut store), &key_ring, "k1", Box::new(|| "2026-01-01T00:00:00Z".to_string())).unwrap();
        let replayed2 = event_store2.replay("lineage-1", &initial).unwrap();
        assert_eq!(replayed2.event_count, 1);
        assert_eq!(replayed2.state_fingerprint, accepted.state_fingerprint);
    }

    fn event_store_receipt_store(store: &mut MemoryReceiptStore) -> &mut dyn ReceiptStore {
        store
    }

    #[test]
    fn accept_rejects_stale_expected_fingerprint() {
        let mut store = MemoryReceiptStore(vec![]);
        let key_ring = keys();
        let initial = create_architecture_state("lineage-1", ledger(), "budget-1").unwrap();
        let mut event_store = ArchitectureEventStore::new(&mut store, &key_ring, "k1", Box::new(|| "2026-01-01T00:00:00Z".to_string())).unwrap();
        event_store.replay("lineage-1", &initial).unwrap();
        let err = event_store.accept(&proposal("lineage-1"), Some("sha256:stale")).unwrap_err();
        assert_eq!(err.code, "ARC_BINDING_MISMATCH");
    }

    #[test]
    fn accept_rejects_unknown_event_type() {
        let mut store = MemoryReceiptStore(vec![]);
        let key_ring = keys();
        let initial = create_architecture_state("lineage-1", ledger(), "budget-1").unwrap();
        let mut event_store = ArchitectureEventStore::new(&mut store, &key_ring, "k1", Box::new(|| "2026-01-01T00:00:00Z".to_string())).unwrap();
        let replayed = event_store.replay("lineage-1", &initial).unwrap();
        let mut bad = proposal("lineage-1");
        bad.event_type = "NOT_A_REAL_EVENT".to_string();
        let err = event_store.accept(&bad, Some(replayed.state_fingerprint.as_str())).unwrap_err();
        assert_eq!(err.code, "ARC_SCHEMA_INVALID");
    }

    #[test]
    fn replay_detects_tampered_event_authentication() {
        let mut store = MemoryReceiptStore(vec![]);
        let key_ring = keys();
        let initial = create_architecture_state("lineage-1", ledger(), "budget-1").unwrap();
        {
            let mut event_store = ArchitectureEventStore::new(&mut store, &key_ring, "k1", Box::new(|| "2026-01-01T00:00:00Z".to_string())).unwrap();
            let replayed = event_store.replay("lineage-1", &initial).unwrap();
            event_store.accept(&proposal("lineage-1"), Some(replayed.state_fingerprint.as_str())).unwrap();
        }
        // Tamper with the stored event's payload after acceptance.
        if let CanonVal::Obj(map) = &mut store.0[0] {
            map.insert("payload".to_string(), CanonVal::obj().set("from", CanonVal::Str("UNROUTED".into())).set("to", CanonVal::Str("FRAMED".into())));
        }
        let mut event_store2 = ArchitectureEventStore::new(&mut store, &key_ring, "k1", Box::new(|| "2026-01-01T00:00:00Z".to_string())).unwrap();
        let err = event_store2.replay("lineage-1", &initial).unwrap_err();
        assert_eq!(err.code, "ARC_AUTH_FORGED");
    }
}
