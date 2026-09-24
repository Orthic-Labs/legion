//! Port of `src/lib/verification/arcane/architecture-router.mjs`.
//!
//! Not one of this packet's seven owned files, but ported here to close
//! `src/lib/verification/arcane/s11-bindings/eval-adversarial.mjs`'s
//! `AE-ADVERSARIAL-003` gap in `crate::wf_port::wf074::eval_adversarial`,
//! which was previously `BlockedOnDependency` on this exact module (see
//! that file's prior doc comment). `routeArchitecture` is pure logic with
//! no I/O, so faking it was never necessary — the only blocker was that no
//! Rust port of it existed yet.

use serde_json::{Map, Value};

pub const SIGNIFICANCE_RULES: &[&str] = &[
    "quality_or_mission",
    "responsibility_boundary",
    "data_authority_boundary",
    "trust_or_risk_boundary",
    "failure_or_deployment_boundary",
    "durable_contract",
    "broad_impact",
    "hard_to_reverse",
    "durable_governance",
    "material_loss",
];

pub const OBJECTIVE: &[&str] = &["sufficient", "optimize", "best_shape"];
pub const ARCHITECTURE_DEPTH: &[&str] = &["D0", "D1", "D2"];
pub const ASSURANCE_RIGOR: &[&str] = &["lite", "standard", "critical"];
pub const DOOR: &[&str] = &["reversible", "one_way", "authority_sensitive"];

const CRITICAL: &[&str] = &[
    "safety",
    "severe_security_privacy",
    "regulated",
    "irreversible_data",
    "mission_critical",
    "hard_real_time",
    "destructive_migration",
];

const DEPTH_FLAGS: &[&str] = &[
    "system_level",
    "cross_boundary",
    "migration",
    "platform",
    "broad_review",
];

pub const ARCHITECTURE_ROUTE_SCHEMA_ID: &str = "architecture-route.v1";

#[derive(Debug, Clone, PartialEq)]
pub struct RouterError {
    pub message: String,
    pub detail: Value,
}

fn fail<T>(message: impl Into<String>) -> Result<T, RouterError> {
    Err(RouterError { message: message.into(), detail: Value::Object(Map::new()) })
}

fn router_fields() -> Vec<&'static str> {
    let mut v = vec!["objective", "optimize_axis", "significance", "effect", "flags", "prior_route"];
    v.extend_from_slice(CRITICAL);
    v.extend_from_slice(DEPTH_FLAGS);
    v
}

/// Mirrors JS `normalizeArchitectureAlias`.
pub fn normalize_architecture_alias(value: &str) -> String {
    value.trim().to_lowercase().replace([' ', '-'], "_")
}

fn get<'a>(input: &'a Value, key: &str) -> Option<&'a Value> {
    input.get(key).filter(|v| !v.is_null())
}

fn is_true(input: &Value, key: &str) -> bool {
    input.get(key).map(|v| v == &Value::Bool(true)).unwrap_or(false)
}

#[derive(Debug, Clone)]
pub struct NormalizedRoute {
    pub objective: String,
    pub optimize_axis: Option<String>,
}

/// Mirrors JS `normalizeArchitectureRoute(input)`.
pub fn normalize_architecture_route(input: &Value) -> NormalizedRoute {
    let raw_objective = get(input, "objective").and_then(Value::as_str).unwrap_or("");
    let normalized_objective_str = raw_objective.trim().to_lowercase().replace([' ', '-'], "_");
    let optimize_axis = get(input, "optimize_axis").and_then(Value::as_str);
    let optimize_axis_present = optimize_axis.map(|s| !s.trim().is_empty()).unwrap_or(false);
    let objective = if normalized_objective_str == "best_shape" {
        "best_shape".to_string()
    } else if optimize_axis_present {
        "optimize".to_string()
    } else {
        "sufficient".to_string()
    };
    NormalizedRoute {
        objective,
        optimize_axis: if optimize_axis_present { Some(optimize_axis.unwrap().trim().to_string()) } else { None },
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Significance {
    pub significant: bool,
    pub matched_significance_facts: Vec<String>,
}

/// Mirrors JS `classifySignificance(facts)`.
pub fn classify_significance(facts: &Value) -> Result<Significance, RouterError> {
    let object = match facts {
        Value::Object(map) => map,
        Value::Null => return fail("significance facts must be an object"),
        _ => return fail("significance facts must be an object"),
    };
    for key in object.keys() {
        if !SIGNIFICANCE_RULES.contains(&key.as_str()) {
            return fail(format!("unknown significance fact: {key}"));
        }
    }
    let matched: Vec<String> = SIGNIFICANCE_RULES
        .iter()
        .filter(|k| object.get(**k) == Some(&Value::Bool(true)))
        .map(|k| k.to_string())
        .collect();
    Ok(Significance { significant: !matched.is_empty(), matched_significance_facts: matched })
}

#[derive(Debug, Clone, PartialEq)]
pub struct EffectClassification {
    pub declared_type: Option<String>,
    pub matched_rule: &'static str,
    pub basis: String,
    pub door: &'static str,
}

fn effect_category_door(category: &str) -> Option<&'static str> {
    match category {
        "FILE_WRITE" | "FILE_MOVE" => Some("reversible"),
        "FILE_DELETE" | "VCS_PUSH" | "PUBLISH" | "EXTERNAL_SIDE_EFFECT" => Some("one_way"),
        "CREDENTIAL_ACCESS" | "DEPENDENCY_INSTALL" | "VCS_COMMIT" => Some("authority_sensitive"),
        _ => None,
    }
}

/// Mirrors JS `classifyEffect(input)`.
pub fn classify_effect(input: &Value) -> Result<EffectClassification, RouterError> {
    let object = match input {
        Value::Object(map) => map,
        _ => return fail("effect classification must be an object"),
    };
    for key in object.keys() {
        if !["declared_type", "category", "semantic_risk"].contains(&key.as_str()) {
            return fail(format!("unknown effect classification field: {key}"));
        }
    }
    let explicit = object.get("declared_type").and_then(Value::as_str);
    let category = object.get("category").and_then(Value::as_str);
    let semantic = object.get("semantic_risk").and_then(Value::as_str);

    if let Some(e) = explicit {
        if DOOR.contains(&e) {
            let door = DOOR.iter().find(|d| **d == e).copied().unwrap();
            return Ok(EffectClassification {
                declared_type: Some(e.to_string()),
                matched_rule: "declared_type",
                basis: e.to_string(),
                door,
            });
        }
    }
    if let Some(c) = category {
        if let Some(door) = effect_category_door(c) {
            return Ok(EffectClassification {
                declared_type: explicit.map(str::to_string),
                matched_rule: "capability_category",
                basis: c.to_string(),
                door,
            });
        }
    }
    if let Some(s) = semantic {
        if ["destructive", "irreversible", "data_loss", "external_commitment"].contains(&s) {
            return Ok(EffectClassification {
                declared_type: explicit.map(str::to_string),
                matched_rule: "semantic_risk",
                basis: s.to_string(),
                door: "one_way",
            });
        }
        if ["authority", "credential", "trust_boundary", "production", "spend", "send", "publish"].contains(&s) {
            return Ok(EffectClassification {
                declared_type: explicit.map(str::to_string),
                matched_rule: "semantic_risk",
                basis: s.to_string(),
                door: "authority_sensitive",
            });
        }
    }
    Ok(EffectClassification {
        declared_type: explicit.map(str::to_string),
        matched_rule: "safe_default",
        basis: semantic.map(str::to_string).unwrap_or_else(|| "ambiguous".to_string()),
        door: "authority_sensitive",
    })
}

#[derive(Debug, Clone, PartialEq)]
pub struct ArchitectureRoute {
    pub schema: &'static str,
    pub significant: bool,
    pub matched_significance_facts: Vec<String>,
    pub objective: String,
    pub optimize_axis: Option<String>,
    pub depth: &'static str,
    pub rigor: &'static str,
    pub effect_classification: EffectClassification,
}

/// Mirrors JS `routeArchitecture(input)`.
pub fn route_architecture(input: &Value) -> Result<ArchitectureRoute, RouterError> {
    let object = match input {
        Value::Object(map) => map,
        _ => return fail("architecture router input must be an object"),
    };
    let fields = router_fields();
    for key in object.keys() {
        if !fields.contains(&key.as_str()) {
            return fail(format!("unknown architecture router field: {key}"));
        }
    }
    if let Some(objective) = object.get("objective").and_then(Value::as_str) {
        if !OBJECTIVE.contains(&normalize_architecture_alias(objective).as_str()) {
            return fail("objective is invalid");
        }
    }
    if let Some(prior) = object.get("prior_route") {
        if !prior.is_null() {
            let valid = prior
                .get("objective")
                .and_then(Value::as_str)
                .map(|o| OBJECTIVE.contains(&o))
                .unwrap_or(false);
            if !prior.is_object() || !valid {
                return fail("prior_route is invalid");
            }
        }
    }
    if let Some(flags) = object.get("flags") {
        if !flags.is_null() {
            let all_known = [CRITICAL, DEPTH_FLAGS].concat();
            let ok = flags
                .as_array()
                .map(|arr| arr.iter().all(|f| f.as_str().map(|s| all_known.contains(&s)).unwrap_or(false)))
                .unwrap_or(false);
            if !ok {
                return fail("flags contain an unknown routing fact");
            }
        }
    }

    let normalized = normalize_architecture_route(input);
    let significance_input = get(input, "significance")
        .or_else(|| get(input, "facts"))
        .cloned()
        .unwrap_or_else(|| Value::Object(Map::new()));
    let significance = classify_significance(&significance_input)?;

    if let Some(prior_objective) = object
        .get("prior_route")
        .and_then(|p| p.get("objective"))
        .and_then(Value::as_str)
    {
        if prior_objective != normalized.objective {
            return fail("objective self-upgrade requires explicit authority");
        }
    }

    let flags: Vec<String> = object
        .get("flags")
        .and_then(Value::as_array)
        .map(|arr| arr.iter().filter_map(|v| v.as_str().map(str::to_string)).collect())
        .unwrap_or_default();
    let critical = CRITICAL.iter().any(|fact| is_true(input, fact) || flags.iter().any(|f| f == fact));
    let depth: &'static str = if !significance.significant {
        "D0"
    } else if normalized.objective == "best_shape"
        || DEPTH_FLAGS.iter().any(|fact| is_true(input, fact) || flags.iter().any(|f| f == fact))
    {
        "D2"
    } else {
        "D1"
    };
    let rigor: &'static str = if critical {
        "critical"
    } else if significance.significant {
        "standard"
    } else {
        "lite"
    };

    let effect_input = get(input, "effect").cloned().unwrap_or_else(|| input.clone());
    let effect_classification = classify_effect(&effect_input)?;

    Ok(ArchitectureRoute {
        schema: ARCHITECTURE_ROUTE_SCHEMA_ID,
        significant: significance.significant,
        matched_significance_facts: significance.matched_significance_facts,
        objective: normalized.objective,
        optimize_axis: normalized.optimize_axis,
        depth,
        rigor,
        effect_classification,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn adversarial_003_input_is_critical_d1() {
        let input = json!({
            "flags": ["safety", "hard_real_time"],
            "significance": {"quality_or_mission": true},
            "effect": {},
        });
        let route = route_architecture(&input).expect("valid input");
        assert_eq!(route.rigor, "critical");
        assert_eq!(route.depth, "D1");
    }

    #[test]
    fn unknown_significance_fact_fails() {
        let input = json!({"significance": {"nope": true}});
        assert!(route_architecture(&input).is_err());
    }

    #[test]
    fn insignificant_input_is_d0_lite() {
        let input = json!({});
        let route = route_architecture(&input).unwrap();
        assert_eq!(route.depth, "D0");
        assert_eq!(route.rigor, "lite");
        assert!(!route.significant);
    }

    #[test]
    fn best_shape_objective_forces_d2() {
        let input = json!({"objective": "best_shape", "significance": {"broad_impact": true}});
        let route = route_architecture(&input).unwrap();
        assert_eq!(route.depth, "D2");
        assert_eq!(route.objective, "best_shape");
    }

    #[test]
    fn effect_classification_defaults_to_safe_default() {
        let input = json!({});
        let route = route_architecture(&input).unwrap();
        assert_eq!(route.effect_classification.matched_rule, "safe_default");
        assert_eq!(route.effect_classification.door, "authority_sensitive");
    }

    #[test]
    fn effect_category_maps_to_door() {
        let input = json!({"effect": {"category": "FILE_DELETE"}});
        let route = route_architecture(&input).unwrap();
        assert_eq!(route.effect_classification.door, "one_way");
        assert_eq!(route.effect_classification.matched_rule, "capability_category");
    }
}
