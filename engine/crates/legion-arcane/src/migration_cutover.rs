use crate::error::ArcaneError;
use serde_json::{json, Value};

const SCHEMA: &str = "arcane.migration-cutover-assessment.v1";
const ABSENCE_SURFACES: [&str; 8] = [
    "imports",
    "routes",
    "runtime_registrations",
    "configuration_keys",
    "dependencies",
    "tests",
    "documentation",
    "emitted_protocol_variants",
];
const COEXISTENCE_FIELDS: [&str; 6] = [
    "owner",
    "reconciliation",
    "telemetry",
    "expiry",
    "rollback",
    "trigger",
];

fn object<'a>(value: &'a Value, name: &str) -> Result<&'a serde_json::Map<String, Value>, ArcaneError> {
    value.as_object().ok_or_else(|| {
        ArcaneError::typed("ARC_SCHEMA_INVALID", format!("{name} must be an object"))
    })
}

fn non_empty(value: &Value) -> bool {
    if let Some(text) = value.as_str() {
        !text.is_empty()
    } else if let Some(array) = value.as_array() {
        !array.is_empty()
    } else if let Some(object) = value.as_object() {
        !object.is_empty()
    } else {
        false
    }
}

pub fn assess_migration_cutover(input: &Value) -> Result<Value, ArcaneError> {
    let plan = object(input.get("plan").unwrap_or(&Value::Null), "plan")?;
    let observations =
        object(input.get("observations").unwrap_or(&Value::Null), "observations")?;
    let mode = plan
        .get("mode")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            ArcaneError::typed(
                "ARC_SCHEMA_INVALID",
                "plan.mode must be HARD_CUT or BOUNDED_COEXISTENCE",
            )
        })?;
    if mode == "HARD_CUT" {
        let configured = object(
            plan.get("hard_cut")
                .and_then(|value| value.get("absence_checks"))
                .unwrap_or(&Value::Null),
            "plan.hard_cut.absence_checks",
        )?;
        let mut failures = Vec::new();
        for surface in ABSENCE_SURFACES {
            if !configured.get(surface).and_then(Value::as_array).is_some() {
                failures.push(json!({
                    "surface": surface,
                    "code": "ARC_ABSENCE_PROOF_UNDECLARED",
                }));
                continue;
            }
            let matches = observations
                .get("absence")
                .and_then(|value| value.get(surface))
                .and_then(Value::as_array);
            if matches.is_none() {
                failures.push(json!({
                    "surface": surface,
                    "code": "ARC_ABSENCE_PROOF_MISSING",
                }));
                continue;
            }
            if let Some(matches) = matches {
                if !matches.is_empty() {
                    failures.push(json!({
                        "surface": surface,
                        "code": "ARC_ABSENCE_PROOF_FAILED",
                        "matches": matches,
                    }));
                }
            }
        }
        let ready = failures.is_empty();
        return Ok(json!({
            "schema": SCHEMA,
            "mode": mode,
            "ready": ready,
            "code": if ready { "ARC_MIGRATION_CUTOVER_READY" } else { "ARC_MIGRATION_ABSENCE_PROOF_FAILED" },
            "failures": failures,
        }));
    }
    if mode != "BOUNDED_COEXISTENCE" {
        return Err(ArcaneError::typed(
            "ARC_SCHEMA_INVALID",
            "plan.mode must be HARD_CUT or BOUNDED_COEXISTENCE",
        ));
    }
    let coexistence = object(
        plan.get("bounded_coexistence").unwrap_or(&Value::Null),
        "plan.bounded_coexistence",
    )?;
    let mut missing = Vec::new();
    for field in COEXISTENCE_FIELDS {
        if !non_empty(coexistence.get(field).unwrap_or(&Value::Null)) {
            missing.push(json!({ "field": field, "code": "ARC_COEXISTENCE_CONTRACT_MISSING" }));
        }
    }
    let observation_failures = if observations
        .get("coexistence")
        .and_then(|value| value.get("reconciled"))
        .and_then(Value::as_bool)
        == Some(true)
        && observations
            .get("coexistence")
            .and_then(|value| value.get("telemetryActive"))
            .and_then(Value::as_bool)
            == Some(true)
    {
        Vec::new()
    } else {
        vec![json!({ "code": "ARC_COEXISTENCE_OBSERVATION_FAILED" })]
    };
    let failures = missing
        .into_iter()
        .chain(observation_failures)
        .collect::<Vec<_>>();
    let ready = failures.is_empty();
    Ok(json!({
        "schema": SCHEMA,
        "mode": mode,
        "ready": ready,
        "code": if ready { "ARC_MIGRATION_CUTOVER_READY" } else { "ARC_MIGRATION_READINESS_FAILED" },
        "failures": failures,
    }))
}
