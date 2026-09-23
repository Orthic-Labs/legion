//! Ported from src/lib/controls/scenarios/compile.mjs (chunk w2_038).

use super::util::{arr, as_str, get};
use crate::p5_core::controls_scenarios::{pairwise, Constraint, Row};
use crate::p5_core::controls_support::{digest, Value};
use std::collections::{BTreeMap, BTreeSet};

/// Port of `compileScenarios({ baseline, journeys, capabilities, binding,
/// dimensions, constraints, mandatory })`. `journeys`/`capabilities` default
/// to `&[]`, `dimensions` to an empty map, `constraints`/`mandatory` to
/// `&[]` at the call site, matching the JS destructuring defaults.
pub fn compile_scenarios(
    baseline: &Value,
    journeys: &[Value],
    capabilities: &[Value],
    binding: Option<&Value>,
    dimensions: &BTreeMap<String, Vec<Value>>,
    constraints: &[Constraint],
    mandatory: &[Row],
) -> Result<Value, String> {
    let available: BTreeSet<String> = capabilities
        .iter()
        .filter(|c| matches!(get(c, "available"), Some(Value::Bool(true))))
        .filter_map(|c| get(c, "id").and_then(as_str))
        .map(str::to_string)
        .collect();

    let mut scenarios: Vec<Value> = Vec::new();
    let mut omitted: Vec<Value> = Vec::new();

    // `Object.fromEntries(Object.entries(dimensions).filter(([,v]) =>
    // Array.isArray(v) && v.length))`.
    let axes: BTreeMap<String, Vec<Value>> = dimensions
        .iter()
        .filter(|(_, values)| !values.is_empty())
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();

    let matrix: Vec<Row> = if axes.is_empty() {
        omitted.push(Value::object([
            ("id", Value::str("scenario-matrix:dimensions")),
            ("mandatory", Value::Bool(true)),
            ("reason", Value::str("scenario-dimensions-missing")),
            ("coverageEffect", Value::str("unproven")),
        ]));
        Vec::new()
    } else {
        let compiled = pairwise(&axes, constraints, mandatory)?;
        for item in &compiled.omitted {
            omitted.push(Value::object([
                ("row", Value::Object(item.row.clone())),
                ("reason", Value::str(item.reason.clone())),
                ("mandatory", Value::Bool(item.mandatory)),
                ("coverageEffect", Value::str("unproven")),
            ]));
        }
        compiled.rows
    };

    for control in get(baseline, "controls").map(arr).unwrap_or(&[]) {
        let control_id = get(control, "id").and_then(as_str).unwrap_or("").to_string();

        let templates: Vec<String> = match get(control, "scenarios") {
            Some(Value::Array(items)) if !items.is_empty() => {
                items.iter().filter_map(as_str).map(str::to_string).collect()
            }
            _ => vec![format!("{control_id}.default")],
        };
        let linked: Vec<Option<&Value>> = if journeys.is_empty() {
            vec![None]
        } else {
            journeys.iter().map(Some).collect()
        };
        let required: Vec<String> = get(control, "evidence")
            .map(arr)
            .unwrap_or(&[])
            .iter()
            .filter_map(as_str)
            .map(str::to_string)
            .collect();
        let providers = get(control, "providers").cloned().unwrap_or_else(|| Value::Array(vec![]));
        let claim_levels = get(control, "claimLevels").cloned().unwrap_or_else(|| Value::Array(vec![]));
        let missing_evidence_effect = get(control, "missingEvidenceEffect")
            .and_then(as_str)
            .unwrap_or("unproven")
            .to_string();

        for template in &templates {
            for journey in &linked {
                for combination in &matrix {
                    let missing: Vec<String> = required
                        .iter()
                        .filter(|id| !id.starts_with("provider:") && !available.contains(id.as_str()))
                        .cloned()
                        .collect();

                    let suffix = if combination.is_empty() {
                        String::new()
                    } else {
                        let d = digest(&Value::Object(combination.clone()));
                        format!(":{}", &d[d.len() - 12..])
                    };
                    let journey_id = journey.and_then(|j| get(j, "id")).and_then(as_str);
                    let id = format!(
                        "{template}{}{suffix}",
                        journey_id.map(|jid| format!(":{jid}")).unwrap_or_default()
                    );
                    let invariants = journey
                        .and_then(|j| get(j, "invariants"))
                        .cloned()
                        .unwrap_or_else(|| Value::Array(vec![Value::str("no-unaccounted-side-effects")]));

                    let mut row: BTreeMap<String, Value> = BTreeMap::new();
                    row.insert("id".to_string(), Value::str(id));
                    row.insert("templateId".to_string(), Value::str(template.clone()));
                    row.insert("controlId".to_string(), Value::str(control_id.clone()));
                    row.insert(
                        "journeyId".to_string(),
                        journey_id.map(Value::str).unwrap_or(Value::Null),
                    );
                    row.insert("combination".to_string(), Value::Object(combination.clone()));
                    row.insert("providers".to_string(), providers.clone());
                    row.insert(
                        "requiredCapabilities".to_string(),
                        Value::Array(required.iter().cloned().map(Value::str).collect()),
                    );
                    row.insert("mandatory".to_string(), Value::Bool(true));
                    row.insert("destructive".to_string(), Value::Bool(false));
                    row.insert("isolation".to_string(), Value::str("fresh"));
                    row.insert("timeoutMs".to_string(), Value::Number(30000.0));
                    row.insert("invariants".to_string(), invariants);
                    row.insert("claimLevels".to_string(), claim_levels.clone());

                    if missing.is_empty() {
                        scenarios.push(Value::Object(row));
                    } else {
                        row.insert("reason".to_string(), Value::str("missing-capability"));
                        row.insert(
                            "missingCapabilities".to_string(),
                            Value::Array(missing.into_iter().map(Value::str).collect()),
                        );
                        row.insert("coverageEffect".to_string(), Value::str(missing_evidence_effect.clone()));
                        omitted.push(Value::Object(row));
                    }
                }
            }
        }
    }

    let complete = !omitted
        .iter()
        .any(|o| matches!(get(o, "mandatory"), Some(Value::Bool(true))));

    let mut value_map: BTreeMap<String, Value> = BTreeMap::new();
    value_map.insert("schemaVersion".to_string(), Value::Number(1.0));
    value_map.insert("kind".to_string(), Value::str("legion-scenario-matrix"));
    value_map.insert(
        "axes".to_string(),
        Value::Object(axes.into_iter().map(|(k, v)| (k, Value::Array(v))).collect()),
    );
    value_map.insert("scenarios".to_string(), Value::Array(scenarios));
    value_map.insert("omitted".to_string(), Value::Array(omitted));
    value_map.insert("binding".to_string(), binding.cloned().unwrap_or(Value::Null));
    value_map.insert("complete".to_string(), Value::Bool(complete));
    let value = Value::Object(value_map);
    let d = digest(&value);
    let mut final_map = match value {
        Value::Object(m) => m,
        _ => unreachable!(),
    };
    final_map.insert("digest".to_string(), Value::str(d));
    Ok(Value::Object(final_map))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn control(id: &str, evidence: Vec<&str>) -> Value {
        Value::object([
            ("id", Value::str(id)),
            ("evidence", Value::array(evidence.into_iter().map(Value::str))),
            ("providers", Value::array([])),
            ("claimLevels", Value::array([Value::str("inventory")])),
        ])
    }

    fn baseline_with(controls: Vec<Value>) -> Value {
        Value::object([("controls", Value::array(controls))])
    }

    #[test]
    fn empty_dimensions_produce_mandatory_omission_and_incomplete_result() {
        let baseline = baseline_with(vec![control("c1", vec![])]);
        let result = compile_scenarios(&baseline, &[], &[], None, &BTreeMap::new(), &[], &[]).unwrap();
        assert_eq!(get(&result, "scenarios"), Some(&Value::array([])));
        assert_eq!(get(&result, "complete"), Some(&Value::Bool(false)));
        if let Value::Array(omitted) = get(&result, "omitted").unwrap() {
            assert_eq!(omitted.len(), 1);
            assert_eq!(get(&omitted[0], "id"), Some(&Value::str("scenario-matrix:dimensions")));
        } else {
            panic!("expected omitted array");
        }
    }

    #[test]
    fn available_evidence_produces_a_scenario_per_dimension_value() {
        let baseline = baseline_with(vec![control("c1", vec!["ev.a"])]);
        let capabilities = vec![Value::object([("id", Value::str("ev.a")), ("available", Value::Bool(true))])];
        let mut dims = BTreeMap::new();
        dims.insert("os".to_string(), vec![Value::str("mac"), Value::str("win")]);
        let result = compile_scenarios(&baseline, &[], &capabilities, None, &dims, &[], &[]).unwrap();
        if let Value::Array(scenarios) = get(&result, "scenarios").unwrap() {
            assert_eq!(scenarios.len(), 2);
            for s in scenarios {
                assert_eq!(get(s, "controlId"), Some(&Value::str("c1")));
                assert_eq!(get(s, "templateId"), Some(&Value::str("c1.default")));
            }
        } else {
            panic!("expected scenarios array");
        }
    }

    #[test]
    fn missing_evidence_omits_scenario_with_reason() {
        let baseline = baseline_with(vec![control("c1", vec!["ev.missing"])]);
        let mut dims = BTreeMap::new();
        dims.insert("os".to_string(), vec![Value::str("mac")]);
        let result = compile_scenarios(&baseline, &[], &[], None, &dims, &[], &[]).unwrap();
        assert_eq!(get(&result, "scenarios"), Some(&Value::array([])));
        if let Value::Array(omitted) = get(&result, "omitted").unwrap() {
            assert_eq!(omitted.len(), 1);
            assert_eq!(get(&omitted[0], "reason"), Some(&Value::str("missing-capability")));
            assert_eq!(
                get(&omitted[0], "missingCapabilities"),
                Some(&Value::array([Value::str("ev.missing")]))
            );
        } else {
            panic!("expected omitted array");
        }
    }

    #[test]
    fn provider_prefixed_evidence_never_counts_as_missing() {
        let baseline = baseline_with(vec![control("c1", vec!["provider:x"])]);
        let mut dims = BTreeMap::new();
        dims.insert("os".to_string(), vec![Value::str("mac")]);
        let result = compile_scenarios(&baseline, &[], &[], None, &dims, &[], &[]).unwrap();
        if let Value::Array(scenarios) = get(&result, "scenarios").unwrap() {
            assert_eq!(scenarios.len(), 1);
        } else {
            panic!("expected scenarios array");
        }
        assert_eq!(get(&result, "complete"), Some(&Value::Bool(true)));
    }
}
