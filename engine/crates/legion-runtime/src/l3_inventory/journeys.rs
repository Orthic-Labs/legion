//! Port of `src/lib/inventory/journeys/build.mjs`.

use serde_json::{json, Value};

use super::binding::digest;

/// Port of `buildJourneys`.
pub fn build_journeys(portfolio: &Value, contract: &Value, projection: &Value, binding: &Value) -> Value {
    let declared_names = contract
        .get("declared")
        .and_then(|d| d.get("criticalJourneys"))
        .and_then(Value::as_array)
        .cloned();
    let names: Vec<Value> = declared_names
        .clone()
        .unwrap_or_else(|| {
            projection
                .get("journeys")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default()
        });
    let origin = if declared_names.is_some() { "declared" } else { "observed" };

    let targets = portfolio
        .get("targets")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();

    let mut journeys = Vec::new();
    for target in &targets {
        let target_id = target.get("id").cloned().unwrap_or(Value::Null);
        for name in &names {
            let name_str = name.as_str().unwrap_or_default();
            let details = projection
                .get("journeyDetails")
                .and_then(|d| d.get(name_str))
                .cloned()
                .unwrap_or_else(|| json!({}));
            journeys.push(json!({
                "id": format!("{}:{}", target_id.as_str().unwrap_or_default(), name_str),
                "targetId": target_id,
                "name": name,
                "origin": origin,
                "criticality": details.get("criticality").cloned().unwrap_or(Value::Null),
                "actors": details.get("actors").cloned().unwrap_or_else(|| json!([])),
                "steps": details.get("steps").cloned().unwrap_or_else(|| json!([])),
                "invariants": details.get("invariants").cloned().unwrap_or_else(|| json!([])),
                "dataEffects": details.get("dataEffects").cloned().unwrap_or_else(|| json!([])),
                "externalDependencies": details.get("externalDependencies").cloned().unwrap_or_else(|| json!([])),
                "failure": details.get("failure").cloned().unwrap_or_else(|| json!([])),
                "recovery": details.get("recovery").cloned().unwrap_or_else(|| json!([])),
            }));
        }
    }

    let gaps: Vec<Value> = if names.is_empty() {
        vec![json!({
            "kind": "journey-denominator-missing",
            "targetIds": targets.iter().filter_map(|t| t.get("id").cloned()).collect::<Vec<_>>(),
        })]
    } else {
        vec![]
    };

    let value = json!({
        "schemaVersion": 1,
        "kind": "legion-journey-inventory",
        "journeys": journeys,
        "gaps": gaps.clone(),
        "complete": gaps.is_empty(),
        "binding": binding,
    });
    let mut map = value.as_object().cloned().unwrap_or_default();
    map.insert("digest".into(), Value::String(digest(&value)));
    Value::Object(map)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_journeys_declared_yields_denominator_gap() {
        let portfolio = json!({"targets": [{"id": "target:web"}]});
        let result = build_journeys(&portfolio, &json!({}), &json!({}), &Value::Null);
        assert_eq!(result["complete"], false);
        assert_eq!(result["gaps"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn declared_journeys_expand_per_target() {
        let portfolio = json!({"targets": [{"id": "target:web"}, {"id": "target:api"}]});
        let contract = json!({"declared": {"criticalJourneys": ["checkout"]}});
        let result = build_journeys(&portfolio, &contract, &json!({}), &Value::Null);
        assert_eq!(result["journeys"].as_array().unwrap().len(), 2);
        assert!(result["complete"].as_bool().unwrap());
    }
}
