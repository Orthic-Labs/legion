use serde_json::{json, Value};
use std::collections::HashSet;

fn readonly(value: Value) -> Value {
    value
}

fn list(value: Option<&Value>) -> Vec<Value> {
    value
        .and_then(Value::as_array)
        .map(|items| items.clone())
        .unwrap_or_default()
}

fn unique_strings(values: Vec<String>) -> Vec<String> {
    let mut set = HashSet::new();
    let mut out = Vec::new();
    for value in values {
        if set.insert(value.clone()) {
            out.push(value);
        }
    }
    out
}

fn constraints_of(constraints: &Value) -> Vec<(String, i64)> {
    let entries = if let Some(array) = constraints.as_array() {
        array.clone()
    } else if let Some(object) = constraints.as_object() {
        object
            .iter()
            .map(|(name, capacity)| {
                json!({
                    "name": name,
                    "capacity": capacity,
                })
            })
            .collect()
    } else {
        Vec::new()
    };
    entries
        .into_iter()
        .filter(|constraint| constraint.get("active").and_then(Value::as_bool) != Some(false))
        .filter_map(|constraint| {
            let name = constraint
                .get("name")
                .and_then(Value::as_str)
                .map(str::to_owned)?;
            let capacity = constraint.get("capacity").and_then(Value::as_i64)?;
            if capacity >= 0 {
                Some((name, capacity))
            } else {
                None
            }
        })
        .collect()
}

pub fn admit_capacity(input: &Value) -> Value {
    let ready_tasks = list(input.get("readyTasks"));
    let active_constraints = constraints_of(input.get("constraints").unwrap_or(&Value::Null));
    let limit = if active_constraints.is_empty() {
        ready_tasks.len()
    } else {
        active_constraints
            .iter()
            .map(|(_, capacity)| *capacity as usize)
            .min()
            .unwrap_or(0)
    };
    let narrowest = active_constraints
        .iter()
        .filter(|(_, capacity)| *capacity as usize == limit)
        .map(|(name, _)| name.clone())
        .collect::<Vec<_>>();
    let admitted = ready_tasks.iter().take(limit).cloned().collect::<Vec<_>>();
    let deferred = ready_tasks.iter().skip(limit).cloned().collect::<Vec<_>>();
    readonly(json!({
        "outcome": "CAPACITY_ADMITTED",
        "limit": limit,
        "narrowestActiveConstraints": narrowest,
        "admitted": admitted,
        "deferred": deferred,
    }))
}

fn proof_key(proof: &Value) -> Option<String> {
    if let Some(text) = proof.as_str() {
        return Some(text.to_owned());
    }
    proof
        .get("producerId")
        .or_else(|| proof.get("producer_id"))
        .or_else(|| proof.get("id"))
        .and_then(Value::as_str)
        .map(str::to_owned)
}

pub fn admit_task_phase(input: &Value) -> Value {
    let required = unique_strings(
        list(input.get("requiredProducerProofs"))
            .into_iter()
            .filter_map(|value| {
                value
                    .as_str()
                    .map(str::to_owned)
                    .or_else(|| proof_key(&value))
            })
            .collect(),
    );
    let present = list(input.get("producerProofs"))
        .into_iter()
        .filter_map(|value| proof_key(&value))
        .collect::<HashSet<_>>();
    let missing = required
        .iter()
        .filter(|id| !present.contains(id.as_str()))
        .cloned()
        .collect::<Vec<_>>();
    let phase = input
        .get("phase")
        .and_then(Value::as_str)
        .unwrap_or("preparation");
    if phase == "activation" || phase == "integration" {
        if !missing.is_empty() {
            return readonly(json!({
                "outcome": "ACTIVATION_DENIED",
                "code": "ARC_PRODUCER_PROOF_MISSING",
                "phase": phase,
                "missingProducerProofs": missing,
            }));
        }
        return readonly(json!({
            "outcome": "ACTIVATION_ADMITTED",
            "phase": phase,
            "requiredProducerProofs": required,
        }));
    }
    readonly(json!({
        "outcome": "PREPARATION_ADMITTED",
        "phase": phase,
        "requiredProducerProofs": required,
    }))
}

pub fn classify_handoff(input: &Value) -> Value {
    let declared = unique_strings(
        list(input.get("assumptions"))
            .into_iter()
            .filter_map(|value| value.as_str().map(str::to_owned))
            .collect(),
    );
    let safe = input.get("safe").and_then(Value::as_bool).unwrap_or(true);
    if !safe {
        return readonly(json!({
            "status": "BLOCKED",
            "code": "ARC_HANDOFF_UNSAFE",
            "assumptions": declared,
            "activationOwner": Value::Null,
        }));
    }
    if !declared.is_empty() {
        return readonly(json!({
            "status": "READY_WITH_ASSUMPTIONS",
            "assumptions": declared,
            "activationOwner": "alchemist",
            "requiredAction": "test_assumptions",
        }));
    }
    readonly(json!({
        "status": "READY",
        "assumptions": [],
        "activationOwner": "alchemist",
        "requiredAction": Value::Null,
    }))
}

pub fn assess_realization(input: &Value) -> Value {
    let decision_status = input.get("decisionStatus").cloned().unwrap_or(Value::Null);
    let intended = input.get("intendedDigest");
    let realized = input.get("realizedDigest");
    let diverged = decision_status == json!("frozen")
        && intended.is_some()
        && realized.is_some()
        && intended != realized;
    readonly(json!({
        "decisionStatus": decision_status,
        "realizationStatus": if diverged { "diverged" } else { "aligned" },
        "correctionRoute": if diverged {
            input
                .get("correctionRoute")
                .and_then(Value::as_str)
                .map(|value| json!(value))
                .unwrap_or(json!("alchemist"))
        } else {
            Value::Null
        },
        "decisionMutation": "none",
    }))
}
