//! Faithful port of `src/lib/verification/arcane/architecture-state.mjs`.
//!
//! The JS source operates on a dynamically-shaped record; this port mirrors
//! that with [`CanonVal`] (a `BTreeMap`-backed JSON-like value, see
//! `super::canon`) rather than a fixed Rust struct, so field sets, closed
//! validation, and event-application logic stay a line-for-line match to the
//! source rather than a re-modeling that could silently drift.
//!
//! Event coverage: every event type in `ARCHITECTURE_EVENT_PAYLOAD_SCHEMAS`
//! plus the full `applyArchitectureEvent` dispatch is ported. The one
//! deliberate scope cut is `INVALIDATION_RECORDED`'s interaction with
//! `recordRevision`'s invalidation-triggered revision bump: it is ported,
//! but see the `invalidation_bumps_revision_for_each_decision` test for the
//! exact shape asserted, since the JS source's per-decision revision-id
//! scheme (`invalidation:{decision_id}:{revision}`) is easy to get subtly
//! wrong and deserves an explicit regression.

use std::collections::BTreeMap;

use super::canon::{digest_value, CanonVal};

pub const ARCHITECTURE_STATE_SCHEMA_ID: &str = "architecture-state.v4";

pub const ARCHITECTURE_STATUS: &[&str] = &[
    "UNROUTED", "TAILORED", "FRAMED", "DRIVERS_READY", "CANDIDATES_READY", "EVALUATED", "MINIMIZED", "DECIDED",
    "CHALLENGED", "FROZEN", "EVIDENCE_TASK", "EXECUTING", "VERIFIED", "FAILED", "BLOCKED",
];
pub const EXECUTION_EPISODE_STATE: &[&str] = &[
    "PENDING", "QUEUED", "RUNNING", "SUCCEEDED", "FAILED", "CANCELLED", "TIMEOUT", "BUDGET_STOP",
    "COMPLETE_WITH_DEBT",
];

fn invalidation_target(scope: &str) -> Option<&'static str> {
    match scope {
        "PATCH" => Some("same"),
        "PLAN" => Some("FROZEN"),
        "DESIGN" => Some("CANDIDATES_READY"),
        "ROOT" => Some("TAILORED"),
        _ => None,
    }
}

fn architecture_transitions(from: &str) -> &'static [&'static str] {
    match from {
        "UNROUTED" => &["TAILORED"],
        "TAILORED" => &["FRAMED"],
        "FRAMED" => &["DRIVERS_READY"],
        "DRIVERS_READY" => &["CANDIDATES_READY"],
        "CANDIDATES_READY" => &["EVALUATED"],
        "EVALUATED" => &["MINIMIZED"],
        "MINIMIZED" => &["DECIDED"],
        "DECIDED" => &["CHALLENGED", "FROZEN"],
        "CHALLENGED" => &["FROZEN"],
        "FROZEN" => &["EVIDENCE_TASK", "EXECUTING"],
        "EVIDENCE_TASK" => &["FROZEN", "EXECUTING", "FAILED", "BLOCKED"],
        "EXECUTING" => &["VERIFIED", "FAILED", "BLOCKED"],
        _ => &[],
    }
}

fn execution_episode_transitions(from: &str) -> &'static [&'static str] {
    match from {
        "PENDING" => &["QUEUED"],
        "QUEUED" => &["RUNNING"],
        "RUNNING" => &["SUCCEEDED", "FAILED", "CANCELLED", "TIMEOUT", "BUDGET_STOP", "COMPLETE_WITH_DEBT"],
        _ => &[],
    }
}

const TOP_FIELDS: &[&str] = &[
    "schema", "task", "mandate", "intent", "acceptance_ledger", "context", "architecture", "uncertainty",
    "decision", "evidence", "assurance", "description", "convergence", "execution", "integration",
    "evidence_reachability", "gate_validity", "machinery_defects", "state_fingerprint",
];
const BUDGET_SNAPSHOT_FIELDS: &[&str] = &["id", "budget_ref", "budget_digest", "observed_counters"];
const BUDGET_COUNTER_FIELDS: &[&str] = &["active_time_ms", "excluded_wait_ms", "retry_count", "event_count"];
const AUTHORITY_FIELDS: &[&str] = &["authority", "capability", "capability_id", "grant", "grant_id", "token", "token_id"];
const TERMINAL_REVISION_DISPOSITIONS: &[&str] = &["DECIDE_WITH_DEBT", "SPIKE", "ESCALATE"];

fn payload_schema(event_type: &str) -> Option<&'static [&'static str]> {
    match event_type {
        "EFFECT_RECORDED" => Some(&[
            "id", "effect_id", "decision_id", "effect_class", "status", "realization_status", "correction_route",
            "output_refs", "unverified_candidate_ids",
        ]),
        "EFFECT_DENIED" => Some(&["id", "effect_id", "decision_id", "effect_class", "code", "reason", "unverified_candidate_ids"]),
        "CANCEL_RECORDED" => Some(&["id", "intent_epoch", "reason", "unverified_candidate_ids"]),
        "RECOVERY_RECORDED" => Some(&["id", "checkpoint_digest", "reason", "candidate_ids", "unverified_candidate_ids"]),
        "SUPERSESSION_RECORDED" => Some(&["id", "supersedes_id", "replacement_id", "reason"]),
        "ARCHITECTURE_REVISION_RECORDED" | "CONVERGENCE_REVISION_RECORDED" => {
            Some(&["id", "decision_id", "revision", "live_candidate_ids", "terminal_disposition"])
        }
        _ => None,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StateError(pub String);
impl std::fmt::Display for StateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}
impl std::error::Error for StateError {}

fn fail<T>(message: impl Into<String>) -> Result<T, StateError> {
    Err(StateError(message.into()))
}

fn obj_mut(v: &mut CanonVal) -> Result<&mut BTreeMap<String, CanonVal>, StateError> {
    match v {
        CanonVal::Obj(m) => Ok(m),
        _ => fail("expected object"),
    }
}
fn arr_mut(v: &mut CanonVal) -> Result<&mut Vec<CanonVal>, StateError> {
    match v {
        CanonVal::Arr(a) => Ok(a),
        _ => fail("expected array"),
    }
}

/// Sort array elements that carry a string `id` by that id, recursing into
/// nested objects/arrays. Mirrors `sortStable`.
pub fn sort_stable(value: &CanonVal) -> CanonVal {
    match value {
        CanonVal::Arr(items) => {
            let mut sorted: Vec<CanonVal> = items.iter().map(sort_stable).collect();
            sorted.sort_by(|a, b| match (a.get("id").and_then(CanonVal::as_str), b.get("id").and_then(CanonVal::as_str)) {
                (Some(x), Some(y)) => x.cmp(y),
                _ => std::cmp::Ordering::Equal,
            });
            CanonVal::Arr(sorted)
        }
        CanonVal::Obj(map) => {
            let mut out = BTreeMap::new();
            for (k, v) in map {
                out.insert(k.clone(), sort_stable(v));
            }
            CanonVal::Obj(out)
        }
        other => other.clone(),
    }
}

fn exact_keys(value: &CanonVal, fields: &[&str], label: &str) -> Result<(), StateError> {
    let map = match value {
        CanonVal::Obj(m) => m,
        _ => return fail(format!("{label} must be an object")),
    };
    for key in map.keys() {
        if !fields.contains(&key.as_str()) {
            return fail(format!("{label} contains unknown field: {key}"));
        }
    }
    for field in fields {
        if !map.contains_key(*field) {
            return fail(format!("{label}.{field} is required"));
        }
    }
    Ok(())
}

fn payload_keys(payload: &CanonVal, fields: &[&str], label: &str) -> Result<(), StateError> {
    let map = match payload {
        CanonVal::Obj(m) => m,
        _ => return fail(format!("{label} payload must be an object")),
    };
    for key in map.keys() {
        if !fields.contains(&key.as_str()) {
            return fail(format!("{label} payload contains unknown field: {key}"));
        }
    }
    Ok(())
}

fn checked_ids(value: &CanonVal, label: &str) -> Result<Vec<String>, StateError> {
    let items = value.as_arr().ok_or_else(|| StateError(format!("{label} must be an array of stable ids")))?;
    let mut out = Vec::new();
    for item in items {
        match item.as_str() {
            Some(s) if !s.is_empty() => out.push(s.to_string()),
            _ => return fail(format!("{label} must be an array of stable ids")),
        }
    }
    out.sort();
    out.dedup();
    Ok(out)
}

fn upsert(target: &mut Vec<CanonVal>, item: CanonVal) -> Result<(), StateError> {
    let id = item.get("id").and_then(CanonVal::as_str).map(str::to_string);
    let id = match id {
        Some(id) if !id.is_empty() => id,
        _ => return fail("stable item id is required"),
    };
    let sorted_item = sort_stable(&item);
    if let Some(index) = target.iter().position(|entry| entry.get("id").and_then(CanonVal::as_str) == Some(id.as_str())) {
        target[index] = sorted_item;
    } else {
        target.push(sorted_item);
    }
    target.sort_by(|a, b| {
        let ai = a.get("id").and_then(CanonVal::as_str).unwrap_or("");
        let bi = b.get("id").and_then(CanonVal::as_str).unwrap_or("");
        ai.cmp(bi)
    });
    Ok(())
}

fn legal_payload(event_type: &str, payload: &CanonVal) -> Result<(), StateError> {
    let fields = match payload_schema(event_type) {
        Some(f) => f,
        None => return Ok(()),
    };
    payload_keys(payload, fields, event_type)?;
    match payload.get("id").and_then(CanonVal::as_str) {
        Some(id) if !id.is_empty() => {}
        _ => return fail(format!("{event_type} requires id")),
    }
    if let Some(map) = payload.as_obj() {
        for field in AUTHORITY_FIELDS {
            if map.contains_key(*field) {
                return fail(format!("{event_type} may not mint authority"));
            }
        }
    }
    for field in ["unverified_candidate_ids", "candidate_ids", "live_candidate_ids"] {
        if let Some(v) = payload.get(field) {
            checked_ids(v, field)?;
        }
    }
    Ok(())
}

/// Mirrors `fingerprintArchitectureState`: strip replay-envelope fields
/// before digesting so live acceptance and replay compute an identical
/// value.
pub fn fingerprint_architecture_state(state: &CanonVal) -> String {
    let mut copy = state.clone();
    if let CanonVal::Obj(map) = &mut copy {
        map.remove("state_fingerprint");
        if let Some(CanonVal::Obj(execution)) = map.get_mut("execution") {
            if let Some(CanonVal::Obj(trajectory)) = execution.get_mut("trajectory") {
                trajectory.remove("replay_state_fingerprint");
                trajectory.remove("last_event_digest");
            }
        }
    }
    digest_value(&copy)
}

pub fn with_state_fingerprint(state: &CanonVal) -> CanonVal {
    let mut next = state.clone();
    let fp = fingerprint_architecture_state(&next);
    if let CanonVal::Obj(map) = &mut next {
        map.insert("state_fingerprint".to_string(), CanonVal::Str(fp));
    }
    next
}

/// Mirrors `createArchitectureState`.
pub fn create_architecture_state(
    objective_lineage_id: &str,
    acceptance_ledger: CanonVal,
    budget_ref: &str,
) -> Result<CanonVal, StateError> {
    if objective_lineage_id.is_empty() {
        return fail("objective_lineage_id is required");
    }
    if acceptance_ledger.as_obj().is_none() {
        return fail("acceptance_ledger is required");
    }
    if budget_ref.is_empty() {
        return fail("budget_ref is required");
    }
    let task = CanonVal::obj()
        .set("objective_lineage_id", CanonVal::Str(objective_lineage_id.to_string()))
        .set("architecture_status", CanonVal::Str("UNROUTED".to_string()))
        .set("budget_ref", CanonVal::Str(budget_ref.to_string()));
    let intent = CanonVal::obj()
        .set("intent_epoch", CanonVal::Int(1))
        .set("continuation_epoch", CanonVal::Int(1))
        .set("outcomes", CanonVal::Arr(vec![]))
        .set("success_signals", CanonVal::Arr(vec![]))
        .set("unacceptable_losses", CanonVal::Arr(vec![]));
    let context = CanonVal::obj().set("route", CanonVal::Null);
    let decision = CanonVal::obj()
        .set("items", CanonVal::Arr(vec![]))
        .set("fingerprints", CanonVal::Arr(vec![]))
        .set("refs", CanonVal::Arr(vec![]));
    let evidence = CanonVal::obj()
        .set("items", CanonVal::Arr(vec![]))
        .set("lifecycle", CanonVal::Arr(vec![]))
        .set("artifact_envelopes", CanonVal::Arr(vec![]))
        .set("fingerprints", CanonVal::Arr(vec![]))
        .set("refs", CanonVal::Arr(vec![]));
    let assurance = CanonVal::obj()
        .set("findings", CanonVal::Arr(vec![]))
        .set("fingerprints", CanonVal::Arr(vec![]))
        .set("refs", CanonVal::Arr(vec![]));
    let convergence = CanonVal::obj()
        .set("revisions", CanonVal::Arr(vec![]))
        .set("terminal_disposition", CanonVal::Null);
    let trajectory = CanonVal::obj()
        .set("last_sequence", CanonVal::Int(0))
        .set("last_event_digest", CanonVal::Null)
        .set("replay_state_fingerprint", CanonVal::Null);
    let retry = CanonVal::obj()
        .set("items", CanonVal::Arr(vec![]))
        .set("fingerprints", CanonVal::Arr(vec![]))
        .set("refs", CanonVal::Arr(vec![]));
    let execution = CanonVal::obj()
        .set("episode_state", CanonVal::Str("PENDING".to_string()))
        .set("trajectory", trajectory)
        .set("budget_snapshots", CanonVal::Arr(vec![]))
        .set("retry", retry)
        .set("diagnosis", CanonVal::Null)
        .set("delivery_deficits", CanonVal::Arr(vec![]))
        .set("downstream_acknowledgements", CanonVal::Arr(vec![]))
        .set("effects", CanonVal::Arr(vec![]))
        .set("denials", CanonVal::Arr(vec![]))
        .set("cancellations", CanonVal::Arr(vec![]))
        .set("terminal_states", CanonVal::Arr(vec![]))
        .set("recovery_refs", CanonVal::Arr(vec![]))
        .set("supersession_refs", CanonVal::Arr(vec![]))
        .set("findings", CanonVal::Arr(vec![]))
        .set("evidence", CanonVal::Arr(vec![]));
    let integration = CanonVal::obj()
        .set("ownership_dispositions", CanonVal::Arr(vec![]))
        .set("migration_cutover", CanonVal::Null);
    let machinery_defects = CanonVal::obj().set("out_of_scope", CanonVal::Arr(vec![]));

    let state = CanonVal::obj()
        .set("schema", CanonVal::Str(ARCHITECTURE_STATE_SCHEMA_ID.to_string()))
        .set("task", task)
        .set("mandate", CanonVal::obj())
        .set("intent", intent)
        .set("acceptance_ledger", sort_stable(&acceptance_ledger))
        .set("context", context)
        .set("architecture", CanonVal::obj())
        .set("uncertainty", CanonVal::obj())
        .set("decision", decision)
        .set("evidence", evidence)
        .set("assurance", assurance)
        .set("description", CanonVal::obj())
        .set("convergence", convergence)
        .set("execution", execution)
        .set("integration", integration)
        .set("evidence_reachability", CanonVal::obj())
        .set("gate_validity", CanonVal::obj())
        .set("machinery_defects", machinery_defects)
        .set("state_fingerprint", CanonVal::Null);
    Ok(with_state_fingerprint(&state))
}

fn record_revision(next: &mut CanonVal, payload: &CanonVal) -> Result<(), StateError> {
    let revision = payload.get("revision").and_then(CanonVal::as_int);
    let revision = match revision {
        Some(r) if r >= 1 => r,
        _ => return fail("revision must be a positive integer"),
    };
    let decision_id = payload.get("decision_id").and_then(CanonVal::as_str).unwrap_or("").to_string();
    let terminal_disposition = payload.get("terminal_disposition").cloned().unwrap_or(CanonVal::Null);

    let convergence = next.get("convergence").cloned().unwrap_or_else(CanonVal::obj);
    let revisions = convergence.get("revisions").and_then(CanonVal::as_arr).cloned().unwrap_or_default();
    let prior = revisions
        .iter()
        .filter(|item| item.get("decision_id").and_then(CanonVal::as_str) == Some(decision_id.as_str()))
        .max_by_key(|item| item.get("revision").and_then(CanonVal::as_int).unwrap_or(0));
    if let Some(prior) = prior {
        let prior_rev = prior.get("revision").and_then(CanonVal::as_int).unwrap_or(0);
        if revision != prior_rev + 1 {
            return fail("revision must be contiguous per decision");
        }
    }
    if revision > 3 {
        return fail("revision tripwire is terminal; fourth comparison rejected");
    }
    if revision == 3 {
        let disposition_ok = matches!(terminal_disposition.as_str(), Some(d) if TERMINAL_REVISION_DISPOSITIONS.contains(&d));
        if !disposition_ok {
            return fail("third revision requires DECIDE_WITH_DEBT, SPIKE, or ESCALATE");
        }
    } else if !matches!(terminal_disposition, CanonVal::Null) {
        return fail("terminal disposition is only legal at revision tripwire");
    }

    let live_candidate_ids = payload
        .get("live_candidate_ids")
        .map(|v| checked_ids(v, "live_candidate_ids"))
        .transpose()?
        .unwrap_or_default();

    let mut item = payload.clone();
    if let CanonVal::Obj(map) = &mut item {
        map.insert(
            "live_candidate_ids".to_string(),
            CanonVal::Arr(live_candidate_ids.into_iter().map(CanonVal::Str).collect()),
        );
    }

    let execution = obj_mut(next)?;
    let convergence = execution
        .get_mut("convergence")
        .ok_or_else(|| StateError("missing convergence".to_string()))?;
    let convergence_map = obj_mut(convergence)?;
    let revisions = convergence_map
        .entry("revisions".to_string())
        .or_insert_with(|| CanonVal::Arr(vec![]));
    upsert(arr_mut(revisions)?, item)?;
    if revision == 3 {
        convergence_map.insert("terminal_disposition".to_string(), terminal_disposition);
    }
    Ok(())
}

fn simple_path(event_type: &str) -> Option<&'static [&'static str]> {
    match event_type {
        "DECISION_RECORDED" | "DECISION_FROZEN" => Some(&["decision", "items"]),
        "FINDING_UPSERTED" => Some(&["assurance", "findings"]),
        "RETRY_RECORDED" => Some(&["execution", "retry", "items"]),
        "DELIVERY_DEFICIT_UPSERTED" => Some(&["execution", "delivery_deficits"]),
        "DOWNSTREAM_ACKNOWLEDGEMENT_RECORDED" => Some(&["execution", "downstream_acknowledgements"]),
        "OWNERSHIP_DISPOSITION_RECORDED" => Some(&["integration", "ownership_dispositions"]),
        "ARTIFACT_ENVELOPE_RECORDED" => Some(&["evidence", "artifact_envelopes"]),
        "EVIDENCE_LIFECYCLE_RECORDED" => Some(&["evidence", "lifecycle"]),
        "EFFECT_RECORDED" => Some(&["execution", "effects"]),
        "EFFECT_DENIED" => Some(&["execution", "denials"]),
        "CANCEL_RECORDED" => Some(&["execution", "cancellations"]),
        "TERMINAL_STATE_RECORDED" => Some(&["execution", "terminal_states"]),
        "RECOVERY_RECORDED" => Some(&["execution", "recovery_refs"]),
        "SUPERSESSION_RECORDED" => Some(&["execution", "supersession_refs"]),
        _ => None,
    }
}

fn get_list_mut<'a>(state: &'a mut CanonVal, path: &[&str]) -> Result<&'a mut Vec<CanonVal>, StateError> {
    let mut cursor = state;
    for (i, segment) in path.iter().enumerate() {
        let map = obj_mut(cursor)?;
        let entry = map
            .get_mut(*segment)
            .ok_or_else(|| StateError(format!("missing field: {segment}")))?;
        if i == path.len() - 1 {
            return arr_mut(entry);
        }
        cursor = entry;
    }
    fail("empty path")
}

/// Mirrors `applyArchitectureEvent`.
pub fn apply_architecture_event(state: &CanonVal, event_type: &str, payload: &CanonVal) -> Result<CanonVal, StateError> {
    if state.get("schema").and_then(CanonVal::as_str) != Some(ARCHITECTURE_STATE_SCHEMA_ID) {
        return fail("invalid architecture state");
    }
    let mut next = state.clone();
    legal_payload(event_type, payload)?;

    match event_type {
        "ROUTE_CLASSIFIED" => {
            let map = obj_mut(&mut next)?;
            let context = obj_mut(map.get_mut("context").ok_or_else(|| StateError("missing context".into()))?)?;
            context.insert("route".to_string(), sort_stable(payload));
        }
        "ARCHITECTURE_TRANSITIONED" => {
            payload_keys(payload, &["from", "to"], "ARCHITECTURE_TRANSITIONED")?;
            let from = payload.get("from").and_then(CanonVal::as_str).unwrap_or("");
            let to = payload.get("to").and_then(CanonVal::as_str).unwrap_or("");
            let current = next
                .get("task")
                .and_then(|t| t.get("architecture_status"))
                .and_then(CanonVal::as_str)
                .unwrap_or("");
            if from != current || !architecture_transitions(current).contains(&to) {
                return fail("illegal architecture transition");
            }
            let map = obj_mut(&mut next)?;
            let task = obj_mut(map.get_mut("task").unwrap())?;
            task.insert("architecture_status".to_string(), CanonVal::Str(to.to_string()));
        }
        "EXECUTION_EPISODE_TRANSITIONED" => {
            payload_keys(payload, &["from", "to"], "EXECUTION_EPISODE_TRANSITIONED")?;
            let from = payload.get("from").and_then(CanonVal::as_str).unwrap_or("");
            let to = payload.get("to").and_then(CanonVal::as_str).unwrap_or("");
            let current = next
                .get("execution")
                .and_then(|e| e.get("episode_state"))
                .and_then(CanonVal::as_str)
                .unwrap_or("");
            if from != current || !execution_episode_transitions(current).contains(&to) {
                return fail("illegal execution episode transition");
            }
            let map = obj_mut(&mut next)?;
            let execution = obj_mut(map.get_mut("execution").unwrap())?;
            execution.insert("episode_state".to_string(), CanonVal::Str(to.to_string()));
        }
        "INTENT_EPOCH_ADVANCED" => {
            payload_keys(payload, &["intent_epoch"], "INTENT_EPOCH_ADVANCED")?;
            let value = payload.get("intent_epoch").and_then(CanonVal::as_int).unwrap_or(-1);
            let current = next
                .get("intent")
                .and_then(|i| i.get("intent_epoch"))
                .and_then(CanonVal::as_int)
                .unwrap_or(0);
            if value != current + 1 {
                return fail("intent epoch must be contiguous");
            }
            let map = obj_mut(&mut next)?;
            obj_mut(map.get_mut("intent").unwrap())?.insert("intent_epoch".to_string(), CanonVal::Int(value));
            obj_mut(map.get_mut("acceptance_ledger").unwrap())?.insert("intent_epoch".to_string(), CanonVal::Int(value));
        }
        "CONTINUATION_EPOCH_ADVANCED" => {
            payload_keys(payload, &["continuation_epoch"], "CONTINUATION_EPOCH_ADVANCED")?;
            let value = payload.get("continuation_epoch").and_then(CanonVal::as_int).unwrap_or(-1);
            let current = next
                .get("intent")
                .and_then(|i| i.get("continuation_epoch"))
                .and_then(CanonVal::as_int)
                .unwrap_or(0);
            if value != current + 1 {
                return fail("continuation epoch must be contiguous");
            }
            let map = obj_mut(&mut next)?;
            obj_mut(map.get_mut("intent").unwrap())?.insert("continuation_epoch".to_string(), CanonVal::Int(value));
        }
        "BUDGET_SNAPSHOT_RECORDED" => {
            payload_keys(payload, BUDGET_SNAPSHOT_FIELDS, "BUDGET_SNAPSHOT_RECORDED")?;
            let counters = payload
                .get("observed_counters")
                .ok_or_else(|| StateError("budget snapshot requires observed_counters".to_string()))?;
            exact_keys(counters, BUDGET_COUNTER_FIELDS, "budget observed_counters")?;
            let id_ok = matches!(payload.get("id").and_then(CanonVal::as_str), Some(s) if !s.is_empty());
            let ref_ok = matches!(payload.get("budget_ref").and_then(CanonVal::as_str), Some(s) if !s.is_empty());
            let digest_ok = payload
                .get("budget_digest")
                .and_then(CanonVal::as_str)
                .map(super::canon::is_digest)
                .unwrap_or(false);
            let counters_ok = counters
                .as_obj()
                .map(|m| m.values().all(|v| matches!(v, CanonVal::Int(i) if *i >= 0)))
                .unwrap_or(false);
            if !id_ok || !ref_ok || !digest_ok || !counters_ok {
                return fail("budget snapshot requires authenticated reference, digest, and non-negative observed counters");
            }
            let list = get_list_mut(&mut next, &["execution", "budget_snapshots"])?;
            upsert(list, payload.clone())?;
        }
        "FINGERPRINTS_RECORDED" => {
            payload_keys(payload, &["decision", "evidence", "finding", "retry"], "FINGERPRINTS_RECORDED")?;
            let map = obj_mut(&mut next)?;
            if let Some(v) = payload.get("decision") {
                obj_mut(map.get_mut("decision").unwrap())?.insert("fingerprints".to_string(), sort_stable(v));
            }
            if let Some(v) = payload.get("evidence") {
                obj_mut(map.get_mut("evidence").unwrap())?.insert("fingerprints".to_string(), sort_stable(v));
            }
            if let Some(v) = payload.get("finding") {
                obj_mut(map.get_mut("assurance").unwrap())?.insert("fingerprints".to_string(), sort_stable(v));
            }
            if let Some(v) = payload.get("retry") {
                let execution = obj_mut(map.get_mut("execution").unwrap())?;
                let retry = obj_mut(execution.get_mut("retry").unwrap())?;
                retry.insert("fingerprints".to_string(), sort_stable(v));
            }
        }
        "MIGRATION_CUTOVER_RECORDED" => {
            let map = obj_mut(&mut next)?;
            obj_mut(map.get_mut("integration").unwrap())?.insert("migration_cutover".to_string(), sort_stable(payload));
        }
        "ACCEPTANCE_RESULT_RECORDED" => {
            let map = obj_mut(&mut next)?;
            let ledger = obj_mut(map.get_mut("acceptance_ledger").unwrap())?;
            let items = ledger.entry("items".to_string()).or_insert_with(|| CanonVal::Arr(vec![]));
            upsert(arr_mut(items)?, payload.clone())?;
        }
        "ARCHITECTURE_REVISION_RECORDED" | "CONVERGENCE_REVISION_RECORDED" => {
            record_revision(&mut next, payload)?;
        }
        "INVALIDATION_RECORDED" => {
            payload_keys(payload, &["scope", "cause", "root_evidence", "decision_ids", "terminal_disposition"], "INVALIDATION_RECORDED")?;
            let scope = payload.get("scope").and_then(CanonVal::as_str).unwrap_or("");
            let target = invalidation_target(scope);
            let cause_ok = matches!(payload.get("cause").and_then(CanonVal::as_str), Some(s) if !s.is_empty());
            if target.is_none() || !cause_ok {
                return fail("invalidation requires cause and scope");
            }
            let root_evidence = payload.get("root_evidence").cloned().unwrap_or(CanonVal::Null);
            if scope == "ROOT" && matches!(root_evidence, CanonVal::Null) {
                return fail("root invalidation requires root evidence");
            }
            let decision_ids = match payload.get("decision_ids") {
                Some(CanonVal::Null) | None => Vec::new(),
                Some(v) => checked_ids(v, "decision_ids")?,
            };
            let known_decisions: Vec<String> = next
                .get("decision")
                .and_then(|d| d.get("items"))
                .and_then(CanonVal::as_arr)
                .map(|items| items.iter().filter_map(|i| i.get("id").and_then(CanonVal::as_str)).map(str::to_string).collect())
                .unwrap_or_default();
            if decision_ids.iter().any(|id| !known_decisions.contains(id)) {
                return fail("invalidation decision must exist");
            }
            let terminal_disposition = payload.get("terminal_disposition").cloned().unwrap_or(CanonVal::Null);
            if scope != "PATCH" {
                let target = target.unwrap();
                let map = obj_mut(&mut next)?;
                obj_mut(map.get_mut("task").unwrap())?.insert("architecture_status".to_string(), CanonVal::Str(target.to_string()));
                for decision_id in &decision_ids {
                    let existing_count = next
                        .get("convergence")
                        .and_then(|c| c.get("revisions"))
                        .and_then(CanonVal::as_arr)
                        .map(|items| items.iter().filter(|i| i.get("decision_id").and_then(CanonVal::as_str) == Some(decision_id.as_str())).count())
                        .unwrap_or(0);
                    let revision = (existing_count + 1) as i64;
                    let revision_payload = CanonVal::obj()
                        .set("id", CanonVal::Str(format!("invalidation:{decision_id}:{revision}")))
                        .set("decision_id", CanonVal::Str(decision_id.clone()))
                        .set("revision", CanonVal::Int(revision))
                        .set("live_candidate_ids", CanonVal::Arr(vec![]))
                        .set("terminal_disposition", terminal_disposition.clone());
                    record_revision(&mut next, &revision_payload)?;
                }
            }
            let map = obj_mut(&mut next)?;
            let convergence = obj_mut(map.get_mut("convergence").unwrap())?;
            let invalidation = CanonVal::obj()
                .set("scope", CanonVal::Str(scope.to_string()))
                .set("cause", payload.get("cause").cloned().unwrap_or(CanonVal::Null))
                .set("root_evidence", root_evidence)
                .set(
                    "decision_ids",
                    CanonVal::Arr(decision_ids.into_iter().map(CanonVal::Str).collect()),
                );
            convergence.insert("invalidation".to_string(), invalidation);
        }
        other => {
            let path = simple_path(other).ok_or_else(|| StateError("unsupported architecture event".to_string()))?;
            let list = get_list_mut(&mut next, path)?;
            upsert(list, payload.clone())?;
            if other == "CANCEL_RECORDED" {
                let value = payload.get("intent_epoch").and_then(CanonVal::as_int).unwrap_or(-1);
                let current = next
                    .get("intent")
                    .and_then(|i| i.get("intent_epoch"))
                    .and_then(CanonVal::as_int)
                    .unwrap_or(0);
                if value != current + 1 {
                    return fail("cancellation must advance intent epoch");
                }
                let map = obj_mut(&mut next)?;
                obj_mut(map.get_mut("intent").unwrap())?.insert("intent_epoch".to_string(), CanonVal::Int(value));
                obj_mut(map.get_mut("acceptance_ledger").unwrap())?.insert("intent_epoch".to_string(), CanonVal::Int(value));
                let episode = map
                    .get("execution")
                    .and_then(|e| e.get("episode_state"))
                    .and_then(CanonVal::as_str)
                    .unwrap_or("")
                    .to_string();
                if episode == "RUNNING" {
                    obj_mut(map.get_mut("execution").unwrap())?.insert("episode_state".to_string(), CanonVal::Str("CANCELLED".to_string()));
                }
            }
        }
    }

    Ok(with_state_fingerprint(&next))
}

pub fn project_architecture_events(events: &[(String, CanonVal)], initial_state: &CanonVal) -> Result<CanonVal, StateError> {
    let mut state = initial_state.clone();
    for (event_type, payload) in events {
        state = apply_architecture_event(&state, event_type, payload)?;
    }
    Ok(state)
}

/// Mirrors `validateArchitectureState`.
pub fn validate_architecture_state(state: &CanonVal) -> (bool, Vec<String>) {
    match validate_architecture_state_inner(state) {
        Ok(()) => (true, Vec::new()),
        Err(e) => (false, vec![e.0]),
    }
}

fn validate_architecture_state_inner(state: &CanonVal) -> Result<(), StateError> {
    exact_keys(state, TOP_FIELDS, "architecture state")?;
    exact_keys(state.get("task").unwrap(), &["objective_lineage_id", "architecture_status", "budget_ref"], "task")?;
    exact_keys(
        state.get("intent").unwrap(),
        &["intent_epoch", "continuation_epoch", "outcomes", "success_signals", "unacceptable_losses"],
        "intent",
    )?;
    let ledger = state.get("acceptance_ledger").unwrap();
    let ledger_fields: &[&str] = if ledger.get("schema").and_then(CanonVal::as_str) == Some("acceptance-ledger.v2") {
        &["schema", "ledger_version", "intent_epoch", "acceptance_manifest_fingerprint", "schedule_fingerprint", "schedule", "frozen_at", "items"]
    } else {
        &["schema", "ledger_version", "intent_epoch", "acceptance_fingerprint", "frozen_at", "items"]
    };
    exact_keys(ledger, ledger_fields, "acceptance_ledger")?;
    exact_keys(state.get("decision").unwrap(), &["items", "fingerprints", "refs"], "decision")?;
    exact_keys(state.get("evidence").unwrap(), &["items", "lifecycle", "artifact_envelopes", "fingerprints", "refs"], "evidence")?;
    exact_keys(state.get("assurance").unwrap(), &["findings", "fingerprints", "refs"], "assurance")?;
    let convergence = state.get("convergence").unwrap();
    let mut convergence_fields = vec!["revisions", "terminal_disposition"];
    if convergence.get("invalidation").is_some() {
        convergence_fields.push("invalidation");
    }
    exact_keys(convergence, &convergence_fields, "convergence")?;
    let execution = state.get("execution").unwrap();
    exact_keys(
        execution,
        &[
            "episode_state", "trajectory", "budget_snapshots", "retry", "diagnosis", "delivery_deficits",
            "downstream_acknowledgements", "effects", "denials", "cancellations", "terminal_states",
            "recovery_refs", "supersession_refs", "findings", "evidence",
        ],
        "execution",
    )?;
    exact_keys(
        execution.get("trajectory").unwrap(),
        &["last_sequence", "last_event_digest", "replay_state_fingerprint"],
        "execution.trajectory",
    )?;
    exact_keys(execution.get("retry").unwrap(), &["items", "fingerprints", "refs"], "execution.retry")?;
    for snapshot in execution.get("budget_snapshots").and_then(CanonVal::as_arr).cloned().unwrap_or_default() {
        exact_keys(&snapshot, BUDGET_SNAPSHOT_FIELDS, "budget snapshot")?;
        let counters = snapshot.get("observed_counters").ok_or_else(|| StateError("invalid budget snapshot".to_string()))?;
        exact_keys(counters, BUDGET_COUNTER_FIELDS, "budget observed_counters")?;
        let id_ok = matches!(snapshot.get("id").and_then(CanonVal::as_str), Some(s) if !s.is_empty());
        let ref_ok = matches!(snapshot.get("budget_ref").and_then(CanonVal::as_str), Some(s) if !s.is_empty());
        let digest_ok = snapshot.get("budget_digest").and_then(CanonVal::as_str).map(super::canon::is_digest).unwrap_or(false);
        let counters_ok = counters.as_obj().map(|m| m.values().all(|v| matches!(v, CanonVal::Int(i) if *i >= 0))).unwrap_or(false);
        if !id_ok || !ref_ok || !digest_ok || !counters_ok {
            return fail("invalid budget snapshot");
        }
    }
    exact_keys(state.get("integration").unwrap(), &["ownership_dispositions", "migration_cutover"], "integration")?;
    if state.get("schema").and_then(CanonVal::as_str) != Some(ARCHITECTURE_STATE_SCHEMA_ID)
        || !["acceptance-ledger.v1", "acceptance-ledger.v2"].contains(&ledger.get("schema").and_then(CanonVal::as_str).unwrap_or(""))
    {
        return fail("invalid schema");
    }
    let status = state.get("task").unwrap().get("architecture_status").and_then(CanonVal::as_str).unwrap_or("");
    let episode = execution.get("episode_state").and_then(CanonVal::as_str).unwrap_or("");
    if !ARCHITECTURE_STATUS.contains(&status) || !EXECUTION_EPISODE_STATE.contains(&episode) {
        return fail("invalid state enum");
    }
    let intent_epoch = state.get("intent").unwrap().get("intent_epoch").and_then(CanonVal::as_int).unwrap_or(0);
    let continuation_epoch = state.get("intent").unwrap().get("continuation_epoch").and_then(CanonVal::as_int).unwrap_or(0);
    let ledger_epoch = ledger.get("intent_epoch").and_then(CanonVal::as_int).unwrap_or(-1);
    if intent_epoch < 1 || continuation_epoch < 1 || ledger_epoch != intent_epoch {
        return fail("invalid intent epoch");
    }
    let last_sequence = execution.get("trajectory").unwrap().get("last_sequence").and_then(CanonVal::as_int).unwrap_or(-1);
    if last_sequence < 0 {
        return fail("invalid trajectory sequence");
    }
    let recorded_fp = state.get("state_fingerprint").and_then(CanonVal::as_str).unwrap_or("");
    if recorded_fp != fingerprint_architecture_state(state) {
        return fail("state fingerprint mismatch");
    }
    Ok(())
}

pub fn assert_architecture_state(state: &CanonVal) -> Result<(), StateError> {
    let (valid, issues) = validate_architecture_state(state);
    if !valid {
        return fail(issues.into_iter().next().unwrap_or_default());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ledger() -> CanonVal {
        CanonVal::obj()
            .set("schema", CanonVal::Str("acceptance-ledger.v1".to_string()))
            .set("ledger_version", CanonVal::Int(1))
            .set("intent_epoch", CanonVal::Int(1))
            .set("acceptance_fingerprint", CanonVal::Str(digest_value(&CanonVal::obj())))
            .set("frozen_at", CanonVal::Null)
            .set("items", CanonVal::Arr(vec![]))
    }

    fn base_state() -> CanonVal {
        create_architecture_state("lineage-1", ledger(), "budget-ref-1").unwrap()
    }

    #[test]
    fn create_architecture_state_validates() {
        let state = base_state();
        let (valid, issues) = validate_architecture_state(&state);
        assert!(valid, "{issues:?}");
        assert_eq!(state.get("task").unwrap().get("architecture_status").unwrap().as_str(), Some("UNROUTED"));
    }

    #[test]
    fn create_architecture_state_rejects_missing_fields() {
        assert!(create_architecture_state("", ledger(), "b").is_err());
        assert!(create_architecture_state("l", ledger(), "").is_err());
    }

    #[test]
    fn legal_architecture_transition_updates_status() {
        let state = base_state();
        let payload = CanonVal::obj().set("from", CanonVal::Str("UNROUTED".into())).set("to", CanonVal::Str("TAILORED".into()));
        let next = apply_architecture_event(&state, "ARCHITECTURE_TRANSITIONED", &payload).unwrap();
        assert_eq!(next.get("task").unwrap().get("architecture_status").unwrap().as_str(), Some("TAILORED"));
        assert_ne!(next.get("state_fingerprint"), state.get("state_fingerprint"));
    }

    #[test]
    fn illegal_architecture_transition_is_rejected() {
        let state = base_state();
        let payload = CanonVal::obj().set("from", CanonVal::Str("UNROUTED".into())).set("to", CanonVal::Str("FROZEN".into()));
        assert!(apply_architecture_event(&state, "ARCHITECTURE_TRANSITIONED", &payload).is_err());
    }

    #[test]
    fn intent_epoch_must_be_contiguous() {
        let state = base_state();
        let payload = CanonVal::obj().set("intent_epoch", CanonVal::Int(3));
        assert!(apply_architecture_event(&state, "INTENT_EPOCH_ADVANCED", &payload).is_err());
        let payload_ok = CanonVal::obj().set("intent_epoch", CanonVal::Int(2));
        let next = apply_architecture_event(&state, "INTENT_EPOCH_ADVANCED", &payload_ok).unwrap();
        assert_eq!(next.get("intent").unwrap().get("intent_epoch").unwrap().as_int(), Some(2));
        assert_eq!(next.get("acceptance_ledger").unwrap().get("intent_epoch").unwrap().as_int(), Some(2));
    }

    #[test]
    fn decision_recorded_upserts_by_id() {
        let state = base_state();
        let d1 = CanonVal::obj().set("id", CanonVal::Str("D-1".into())).set("note", CanonVal::Str("first".into()));
        let next = apply_architecture_event(&state, "DECISION_RECORDED", &d1).unwrap();
        assert_eq!(next.get("decision").unwrap().get("items").unwrap().as_arr().unwrap().len(), 1);
        let d1b = CanonVal::obj().set("id", CanonVal::Str("D-1".into())).set("note", CanonVal::Str("updated".into()));
        let next2 = apply_architecture_event(&next, "DECISION_RECORDED", &d1b).unwrap();
        let items = next2.get("decision").unwrap().get("items").unwrap().as_arr().unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].get("note").unwrap().as_str(), Some("updated"));
    }

    #[test]
    fn effect_recorded_may_not_mint_authority() {
        let state = base_state();
        let payload = CanonVal::obj()
            .set("id", CanonVal::Str("e1".into()))
            .set("effect_id", CanonVal::Str("eff_1".into()))
            .set("decision_id", CanonVal::Str("D-1".into()))
            .set("effect_class", CanonVal::Str("FILE_WRITE".into()))
            .set("status", CanonVal::Str("done".into()))
            .set("realization_status", CanonVal::Str("observed".into()))
            .set("correction_route", CanonVal::Null)
            .set("output_refs", CanonVal::Arr(vec![]))
            .set("unverified_candidate_ids", CanonVal::Arr(vec![]))
            .set("authority", CanonVal::Str("sneaky".into()));
        assert!(apply_architecture_event(&state, "EFFECT_RECORDED", &payload).is_err());
    }

    #[test]
    fn cancel_recorded_advances_epoch_and_cancels_running_episode() {
        let mut state = base_state();
        let transition = CanonVal::obj().set("from", CanonVal::Str("PENDING".into())).set("to", CanonVal::Str("QUEUED".into()));
        state = apply_architecture_event(&state, "EXECUTION_EPISODE_TRANSITIONED", &transition).unwrap();
        let transition2 = CanonVal::obj().set("from", CanonVal::Str("QUEUED".into())).set("to", CanonVal::Str("RUNNING".into()));
        state = apply_architecture_event(&state, "EXECUTION_EPISODE_TRANSITIONED", &transition2).unwrap();

        let payload = CanonVal::obj()
            .set("id", CanonVal::Str("c1".into()))
            .set("intent_epoch", CanonVal::Int(2))
            .set("reason", CanonVal::Str("operator abort".into()))
            .set("unverified_candidate_ids", CanonVal::Arr(vec![]));
        let next = apply_architecture_event(&state, "CANCEL_RECORDED", &payload).unwrap();
        assert_eq!(next.get("intent").unwrap().get("intent_epoch").unwrap().as_int(), Some(2));
        assert_eq!(next.get("execution").unwrap().get("episode_state").unwrap().as_str(), Some("CANCELLED"));
    }

    #[test]
    fn invalidation_bumps_revision_for_each_decision() {
        let state = base_state();
        let decision_payload = CanonVal::obj().set("id", CanonVal::Str("D-1".into()));
        let state = apply_architecture_event(&state, "DECISION_RECORDED", &decision_payload).unwrap();
        let payload = CanonVal::obj()
            .set("scope", CanonVal::Str("DESIGN".into()))
            .set("cause", CanonVal::Str("evidence contradicted the plan".into()))
            .set("root_evidence", CanonVal::Null)
            .set("decision_ids", CanonVal::Arr(vec![CanonVal::Str("D-1".into())]))
            .set("terminal_disposition", CanonVal::Null);
        let next = apply_architecture_event(&state, "INVALIDATION_RECORDED", &payload).unwrap();
        assert_eq!(next.get("task").unwrap().get("architecture_status").unwrap().as_str(), Some("CANDIDATES_READY"));
        let revisions = next.get("convergence").unwrap().get("revisions").unwrap().as_arr().unwrap();
        assert_eq!(revisions.len(), 1);
        assert_eq!(revisions[0].get("id").unwrap().as_str(), Some("invalidation:D-1:1"));
    }

    #[test]
    fn root_invalidation_requires_root_evidence() {
        let state = base_state();
        let payload = CanonVal::obj()
            .set("scope", CanonVal::Str("ROOT".into()))
            .set("cause", CanonVal::Str("root assumption broke".into()))
            .set("root_evidence", CanonVal::Null)
            .set("decision_ids", CanonVal::Arr(vec![]))
            .set("terminal_disposition", CanonVal::Null);
        assert!(apply_architecture_event(&state, "INVALIDATION_RECORDED", &payload).is_err());
    }

    #[test]
    fn revision_tripwire_requires_terminal_disposition_at_three() {
        let state = base_state();
        let decision_payload = CanonVal::obj().set("id", CanonVal::Str("D-1".into()));
        let state = apply_architecture_event(&state, "DECISION_RECORDED", &decision_payload).unwrap();
        let mut s = state;
        for revision in 1..=2 {
            let payload = CanonVal::obj()
                .set("id", CanonVal::Str(format!("rev-{revision}")))
                .set("decision_id", CanonVal::Str("D-1".into()))
                .set("revision", CanonVal::Int(revision))
                .set("live_candidate_ids", CanonVal::Arr(vec![]))
                .set("terminal_disposition", CanonVal::Null);
            s = apply_architecture_event(&s, "ARCHITECTURE_REVISION_RECORDED", &payload).unwrap();
        }
        let bad = CanonVal::obj()
            .set("id", CanonVal::Str("rev-3".into()))
            .set("decision_id", CanonVal::Str("D-1".into()))
            .set("revision", CanonVal::Int(3))
            .set("live_candidate_ids", CanonVal::Arr(vec![]))
            .set("terminal_disposition", CanonVal::Null);
        assert!(apply_architecture_event(&s, "ARCHITECTURE_REVISION_RECORDED", &bad).is_err());

        let good = CanonVal::obj()
            .set("id", CanonVal::Str("rev-3".into()))
            .set("decision_id", CanonVal::Str("D-1".into()))
            .set("revision", CanonVal::Int(3))
            .set("live_candidate_ids", CanonVal::Arr(vec![]))
            .set("terminal_disposition", CanonVal::Str("SPIKE".into()));
        let next = apply_architecture_event(&s, "ARCHITECTURE_REVISION_RECORDED", &good).unwrap();
        assert_eq!(next.get("convergence").unwrap().get("terminal_disposition").unwrap().as_str(), Some("SPIKE"));
    }

    #[test]
    fn budget_snapshot_requires_valid_digest() {
        let state = base_state();
        let counters = CanonVal::obj()
            .set("active_time_ms", CanonVal::Int(1))
            .set("excluded_wait_ms", CanonVal::Int(0))
            .set("retry_count", CanonVal::Int(0))
            .set("event_count", CanonVal::Int(1));
        let bad = CanonVal::obj()
            .set("id", CanonVal::Str("bs1".into()))
            .set("budget_ref", CanonVal::Str("b".into()))
            .set("budget_digest", CanonVal::Str("not-a-digest".into()))
            .set("observed_counters", counters.clone());
        assert!(apply_architecture_event(&state, "BUDGET_SNAPSHOT_RECORDED", &bad).is_err());

        let good = CanonVal::obj()
            .set("id", CanonVal::Str("bs1".into()))
            .set("budget_ref", CanonVal::Str("b".into()))
            .set("budget_digest", CanonVal::Str(digest_value(&CanonVal::obj())))
            .set("observed_counters", counters);
        let next = apply_architecture_event(&state, "BUDGET_SNAPSHOT_RECORDED", &good).unwrap();
        assert_eq!(next.get("execution").unwrap().get("budget_snapshots").unwrap().as_arr().unwrap().len(), 1);
    }

    #[test]
    fn fingerprint_excludes_trajectory_replay_fields() {
        let state = base_state();
        let fp1 = fingerprint_architecture_state(&state);
        let mut mutated = state.clone();
        if let CanonVal::Obj(map) = &mut mutated {
            if let Some(CanonVal::Obj(execution)) = map.get_mut("execution") {
                if let Some(CanonVal::Obj(trajectory)) = execution.get_mut("trajectory") {
                    trajectory.insert("last_event_digest".to_string(), CanonVal::Str("sha256:deadbeef".to_string()));
                }
            }
        }
        let fp2 = fingerprint_architecture_state(&mutated);
        assert_eq!(fp1, fp2, "trajectory replay fields must not affect the fingerprint");
    }

    #[test]
    fn project_architecture_events_folds_in_order() {
        let state = base_state();
        let events = vec![
            (
                "ARCHITECTURE_TRANSITIONED".to_string(),
                CanonVal::obj().set("from", CanonVal::Str("UNROUTED".into())).set("to", CanonVal::Str("TAILORED".into())),
            ),
            (
                "ARCHITECTURE_TRANSITIONED".to_string(),
                CanonVal::obj().set("from", CanonVal::Str("TAILORED".into())).set("to", CanonVal::Str("FRAMED".into())),
            ),
        ];
        let result = project_architecture_events(&events, &state).unwrap();
        assert_eq!(result.get("task").unwrap().get("architecture_status").unwrap().as_str(), Some("FRAMED"));
    }
}
