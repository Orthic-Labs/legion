use crate::decision::{decision, deny};
use serde_json::{json, Value};
use std::collections::HashSet;

const PASS: &str = "PASS";

fn non_empty(value: &Value) -> bool {
    value.as_str().is_some_and(|text| !text.is_empty())
}

fn normalize_acceptance(item: &Value) -> Option<Value> {
    let id = item
        .get("acceptanceId")
        .or_else(|| item.get("acceptance_id"))
        .or_else(|| item.get("id"))
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty());
    let obligation_class = item
        .get("obligationClass")
        .or_else(|| item.get("obligation_class"))
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty());
    let result = item
        .get("result")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty());
    if id.is_none() || obligation_class.is_none() || result.is_none() {
        return None;
    }
    Some(json!({
        "id": id,
        "obligationClass": obligation_class,
        "result": result,
        "canonicalDeficitId": format!("deficit:{}", id.unwrap()),
    }))
}

pub fn classify_acceptance_deficits(input: &Value) -> Value {
    let acceptance_items = input.get("acceptanceItems").and_then(Value::as_array);
    if acceptance_items.is_none() {
        return deny(
            "ARC_SCHEMA_INVALID",
            "acceptanceItems must be an array",
            json!({}),
        );
    }
    let normalized = acceptance_items
        .unwrap()
        .iter()
        .map(normalize_acceptance)
        .collect::<Vec<_>>();
    if normalized.iter().any(|item| item.is_none()) {
        return deny(
            "ARC_SCHEMA_INVALID",
            "every acceptance item requires id, obligationClass, and result",
            json!({}),
        );
    }
    let deficits = normalized
        .into_iter()
        .flatten()
        .filter(|item| item.get("result").and_then(Value::as_str) != Some(PASS))
        .map(|item| {
            let obligation = item["obligationClass"].as_str().unwrap_or_default();
            let debt_eligible = matches!(obligation, "OPTIONAL" | "QUALITY" | "PERFORMANCE" | "USABILITY");
            let protected = matches!(obligation, "CORRECTNESS" | "SAFETY");
            let disposition = if debt_eligible { "DEBT" } else { "BLOCKING" };
            json!({
                "id": item["id"],
                "obligationClass": item["obligationClass"],
                "result": item["result"],
                "canonicalDeficitId": item["canonicalDeficitId"],
                "debtEligible": debt_eligible,
                "protected": protected,
                "disposition": disposition,
            })
        })
        .collect::<Vec<_>>();
    let blocking = deficits
        .iter()
        .filter(|item| item.get("disposition") == Some(&json!("BLOCKING")))
        .cloned()
        .collect::<Vec<_>>();
    let debt = deficits
        .iter()
        .filter(|item| item.get("disposition") == Some(&json!("DEBT")))
        .cloned()
        .collect::<Vec<_>>();
    let claim_ceiling = if !blocking.is_empty() {
        "CANDIDATE"
    } else if !debt.is_empty() {
        "COMPLETE_WITH_DEBT"
    } else {
        "COMPLETE"
    };
    let outcome_state = claim_ceiling;
    decision(
        true,
        None,
        Some("acceptance deficits classified"),
        json!({
            "deficits": deficits,
            "claimCeiling": claim_ceiling,
            "outcomeState": outcome_state,
        }),
    )
}

pub fn convert_deficits_to_debt(input: &Value) -> Value {
    let classified = classify_acceptance_deficits(input);
    if classified.get("allowed").and_then(Value::as_bool) != Some(true) {
        return classified;
    }
    let detail = classified.get("detail").cloned().unwrap_or(Value::Null);
    let deficits = detail.get("deficits").and_then(Value::as_array).cloned().unwrap_or_default();
    let protected = deficits
        .iter()
        .filter(|deficit| deficit.get("protected") == Some(&json!(true)))
        .collect::<Vec<_>>();
    if !protected.is_empty() {
        return deny(
            "ARC_CLAIM_PREREQUISITE_UNMET",
            "correctness or safety deficit cannot convert to debt",
            json!({
                "outcomeState": "CANDIDATE",
                "claimCeiling": "CANDIDATE",
                "protectedDeficitIds": protected
                    .iter()
                    .filter_map(|deficit| deficit.get("canonicalDeficitId").cloned())
                    .collect::<Vec<_>>(),
            }),
        );
    }
    let blocking = deficits
        .iter()
        .filter(|deficit| deficit.get("disposition") == Some(&json!("BLOCKING")))
        .collect::<Vec<_>>();
    if !blocking.is_empty() {
        return deny(
            "ARC_CLAIM_PREREQUISITE_UNMET",
            "required acceptance deficit cannot convert to debt",
            json!({
                "outcomeState": "CANDIDATE",
                "claimCeiling": "CANDIDATE",
                "blockingDeficitIds": blocking
                    .iter()
                    .filter_map(|deficit| deficit.get("canonicalDeficitId").cloned())
                    .collect::<Vec<_>>(),
            }),
        );
    }
    decision(
        true,
        None,
        Some("eligible acceptance deficits converted to canonical debt"),
        json!({
            "outcomeState": detail.get("outcomeState").cloned().unwrap_or(Value::Null),
            "claimCeiling": detail.get("claimCeiling").cloned().unwrap_or(Value::Null),
            "debts": deficits,
        }),
    )
}

pub fn acknowledge_downstream_deficits(input: &Value) -> Value {
    let canonical_deficits = input.get("canonicalDeficits").and_then(Value::as_array);
    let acknowledgements = input.get("acknowledgements").and_then(Value::as_array);
    if canonical_deficits.is_none() || acknowledgements.is_none() {
        return deny(
            "ARC_SCHEMA_INVALID",
            "canonicalDeficits and acknowledgements must be arrays",
            json!({}),
        );
    }
    let canonical_ids = canonical_deficits
        .unwrap()
        .iter()
        .filter_map(|deficit| deficit.get("canonicalDeficitId").and_then(Value::as_str))
        .filter(|value| !value.is_empty())
        .collect::<Vec<_>>();
    if canonical_ids.len() != canonical_deficits.unwrap().len() {
        return deny(
            "ARC_SCHEMA_INVALID",
            "each canonical deficit requires canonicalDeficitId",
            json!({}),
        );
    }
    let canonical_set = canonical_ids.iter().collect::<HashSet<_>>();
    let mut acknowledged = HashSet::<String>::new();
    for acknowledgement in acknowledgements.unwrap() {
        if !non_empty(&acknowledgement["canonicalDeficitId"])
            || acknowledgement.get("canonical") != Some(&json!(true))
            || !non_empty(&acknowledgement["consumerId"])
        {
            return deny(
                "ARC_SCHEMA_INVALID",
                "acknowledgement requires canonical identity, canonical marker, and consumerId",
                json!({}),
            );
        }
        let id = acknowledgement["canonicalDeficitId"]
            .as_str()
            .unwrap_or_default()
            .to_owned();
        if !canonical_set.contains(&id.as_str()) {
            return deny(
                "ARC_BINDING_MISMATCH",
                "downstream acknowledgement does not reference canonical debt",
                json!({ "canonicalDeficitId": id }),
            );
        }
        acknowledged.insert(id);
    }
    let missing = canonical_set
        .iter()
        .filter(|id| !acknowledged.contains(&id.to_string()))
        .cloned()
        .collect::<Vec<_>>();
    if !missing.is_empty() {
        return deny(
            "ARC_CLAIM_PREREQUISITE_UNMET",
            "dispatch rejected until canonical debt is acknowledged",
            json!({
                "dispatch": "REJECTED",
                "missingCanonicalDeficitIds": missing,
            }),
        );
    }
    let mut ids = acknowledged.into_iter().collect::<Vec<_>>();
    ids.sort();
    decision(
        true,
        None,
        Some("downstream acknowledged canonical deficits"),
        json!({
            "dispatch": "ALLOWED",
            "acknowledgedCanonicalDeficitIds": ids,
        }),
    )
}

pub fn evaluate_outcome_closure(input: &Value) -> Value {
    let acceptance_surface = input.get("acceptanceSurface").unwrap_or(&Value::Null);
    let observed = acceptance_surface.get("observed") == Some(&json!(true));
    let authenticated = acceptance_surface.get("authenticated") == Some(&json!(true));
    let state_identity = acceptance_surface.get("integratedState");
    if !observed
        || !authenticated
        || state_identity.is_none()
        || state_identity == Some(&Value::Null)
    {
        return deny(
            "ARC_EVIDENCE_INSUFFICIENT",
            "outcome remains CANDIDATE until acceptance surface is observed",
            json!({
                "outcomeState": "CANDIDATE",
                "claimCeiling": "CANDIDATE",
                "acceptanceSurface": if observed { "UNAUTHENTICATED" } else { "UNOBSERVED" },
            }),
        );
    }
    decision(
        true,
        None,
        Some("outcome acceptance surface observed"),
        json!({
            "outcomeState": "COMPLETE",
            "claimCeiling": "COMPLETE",
            "integratedState": state_identity,
        }),
    )
}
