use crate::decision::{decision, deny};
use serde_json::{json, Value};

const LATENCY_RECORD_FIELDS: [&str; 3] = ["authorityId", "scopeId", "targetMs"];
const TECHNOLOGY_RECORD_FIELDS: [&str; 4] = ["authorityId", "scopeId", "technology", "consequence"];
const LATENCY_INPUT_FIELDS: [&str; 4] = ["scopeId", "targetMs", "assumption", "authorityRequest"];
const TECHNOLOGY_INPUT_FIELDS: [&str; 3] = ["scopeId", "technology", "consequence"];
const ASSUMPTION_FIELDS: [&str; 2] = ["id", "rationaleDigest"];
const AUTHORITY_REQUEST_FIELDS: [&str; 2] = ["id", "question"];

fn exact(value: &Value, fields: &[&str]) -> bool {
    let object = value.as_object();
    object.is_some_and(|object| {
        object.len() == fields.len()
            && fields.iter().all(|field| object.contains_key(*field))
    })
}

fn text(value: &Value) -> bool {
    value.as_str().is_some_and(|text| !text.is_empty())
}

fn scope(value: &Value) -> bool {
    value.is_null() || text(value)
}

fn milliseconds(value: &Value) -> bool {
    value.as_f64().is_some_and(|ms| ms.is_finite() && ms > 0.0)
}

fn same_scope(record_scope: &Value, requested_scope: &Value) -> bool {
    record_scope == requested_scope
}

fn valid_latency_record(record: &Value) -> bool {
    exact(record, &LATENCY_RECORD_FIELDS)
        && text(&record["authorityId"])
        && scope(&record["scopeId"])
        && milliseconds(&record["targetMs"])
}

fn valid_technology_record(record: &Value) -> bool {
    exact(record, &TECHNOLOGY_RECORD_FIELDS)
        && text(&record["authorityId"])
        && scope(&record["scopeId"])
        && text(&record["technology"])
        && text(&record["consequence"])
}

fn valid_assumption(value: &Value) -> bool {
    exact(value, &ASSUMPTION_FIELDS) && text(&value["id"]) && text(&value["rationaleDigest"])
}

fn valid_authority_request(value: &Value) -> bool {
    exact(value, &AUTHORITY_REQUEST_FIELDS) && text(&value["id"]) && text(&value["question"])
}

#[derive(Clone, Debug)]
pub struct EvidenceAuthorityRegistry {
    latency: Vec<Value>,
    technology: Vec<Value>,
}

impl EvidenceAuthorityRegistry {
    pub fn new(latency_targets: Vec<Value>, technology_constraints: Vec<Value>) -> Result<Self, String> {
        if !latency_targets.iter().all(valid_latency_record)
            || !technology_constraints.iter().all(valid_technology_record)
        {
            return Err("invalid host evidence-authority records".into());
        }
        Ok(Self {
            latency: latency_targets,
            technology: technology_constraints,
        })
    }

    pub fn latency_target(&self, scope_id: &Value) -> Option<&Value> {
        self.latency
            .iter()
            .find(|record| same_scope(&record["scopeId"], scope_id))
    }

    pub fn technology_constraint(
        &self,
        scope_id: &Value,
        technology: &str,
        consequence: &str,
    ) -> Option<&Value> {
        self.technology.iter().find(|record| {
            same_scope(&record["scopeId"], scope_id)
                && record["technology"].as_str() == Some(technology)
                && record["consequence"].as_str() == Some(consequence)
        })
    }
}

pub fn resolve_latency_target(input: &Value, registry: &EvidenceAuthorityRegistry) -> Value {
    let target_ms = &input["targetMs"];
    let assumption = &input["assumption"];
    let authority_request = &input["authorityRequest"];
    if !exact(input, &LATENCY_INPUT_FIELDS)
        || !scope(&input["scopeId"])
        || !target_ms.is_null() && !milliseconds(target_ms)
        || !assumption.is_null() && !valid_assumption(assumption)
        || !authority_request.is_null() && !valid_authority_request(authority_request)
        || !assumption.is_null() && !authority_request.is_null()
        || !target_ms.is_null() && (!assumption.is_null() || !authority_request.is_null())
    {
        return deny(
            "ARC_SCHEMA_INVALID",
            "latency evidence input is invalid",
            json!({ "disposition": "AUTHORITY_REQUEST" }),
        );
    }
    let authorized = registry.latency_target(&input["scopeId"]);
    if !target_ms.is_null() {
        if authorized.is_none() {
            return deny(
                "ARC_EVIDENCE_INSUFFICIENT",
                "numeric latency target has no authorized source",
                json!({
                    "disposition": "AUTHORITY_REQUEST",
                    "reason": "UNAUTHORIZED_NUMERIC_TARGET",
                    "requestedTargetMs": target_ms,
                }),
            );
        }
        let authorized = authorized.unwrap();
        if authorized["targetMs"] != *target_ms {
            return deny(
                "ARC_BINDING_MISMATCH",
                "numeric latency target differs from authorized source",
                json!({
                    "disposition": "AUTHORITY_REQUEST",
                    "authorityId": authorized["authorityId"],
                    "authorizedTargetMs": authorized["targetMs"],
                    "requestedTargetMs": target_ms,
                }),
            );
        }
        return decision(
            true,
            None,
            None,
            json!({
                "disposition": "CONSTRAINT",
                "authorityId": authorized["authorityId"],
                "targetMs": authorized["targetMs"],
            }),
        );
    }
    if !assumption.is_null() {
        return decision(
            true,
            None,
            None,
            json!({
                "disposition": "ASSUMPTION",
                "assumptionId": assumption["id"],
                "rationaleDigest": assumption["rationaleDigest"],
            }),
        );
    }
    if !authority_request.is_null() {
        return decision(
            true,
            None,
            None,
            json!({
                "disposition": "AUTHORITY_REQUEST",
                "requestId": authority_request["id"],
                "question": authority_request["question"],
            }),
        );
    }
    decision(
        true,
        None,
        None,
        json!({
            "disposition": "AUTHORITY_REQUEST",
            "reason": "NO_AUTHORIZED_LATENCY_TARGET",
        }),
    )
}

pub fn classify_technology_requirement(
    input: &Value,
    registry: &EvidenceAuthorityRegistry,
) -> Value {
    let consequence = &input["consequence"];
    if !exact(input, &TECHNOLOGY_INPUT_FIELDS)
        || !scope(&input["scopeId"])
        || !text(&input["technology"])
        || !consequence.is_null() && !text(consequence)
    {
        return deny(
            "ARC_SCHEMA_INVALID",
            "technology evidence input is invalid",
            json!({ "disposition": "PREFERENCE" }),
        );
    }
    let authority = if consequence.is_null() {
        None
    } else {
        registry.technology_constraint(
            &input["scopeId"],
            input["technology"].as_str().unwrap_or_default(),
            consequence.as_str().unwrap_or_default(),
        )
    };
    if authority.is_none() {
        return decision(
            true,
            None,
            None,
            json!({
                "classification": "PREFERENCE",
                "technology": input["technology"],
                "consequence": consequence,
            }),
        );
    }
    let authority = authority.unwrap();
    decision(
        true,
        None,
        None,
        json!({
            "classification": "CONSTRAINT",
            "technology": authority["technology"],
            "consequence": authority["consequence"],
            "authorityId": authority["authorityId"],
        }),
    )
}
