//! Faithful port of `src/lib/verification/arcane/architecture-router.mjs`.

use std::collections::BTreeSet;

use super::canon::CanonVal;

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

pub const ARCHITECTURE_ROUTER_INPUT_SCHEMA_ID: &str = "architecture-router-input.v1";
pub const ARCHITECTURE_ROUTE_SCHEMA_ID: &str = "architecture-route.v1";

const CRITICAL: &[&str] = &[
    "safety",
    "severe_security_privacy",
    "regulated",
    "irreversible_data",
    "mission_critical",
    "hard_real_time",
    "destructive_migration",
];
const DEPTH_FLAGS: &[&str] = &["system_level", "cross_boundary", "migration", "platform", "broad_review"];

fn effect_category_door(category: &str) -> Option<&'static str> {
    match category {
        "FILE_WRITE" | "FILE_MOVE" => Some("reversible"),
        "FILE_DELETE" | "VCS_PUSH" | "PUBLISH" | "EXTERNAL_SIDE_EFFECT" => Some("one_way"),
        "CREDENTIAL_ACCESS" | "DEPENDENCY_INSTALL" | "VCS_COMMIT" => Some("authority_sensitive"),
        _ => None,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouterError(pub String);

impl std::fmt::Display for RouterError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}
impl std::error::Error for RouterError {}

fn fail<T>(message: impl Into<String>) -> Result<T, RouterError> {
    Err(RouterError(message.into()))
}

fn normalize_alias(value: &str) -> String {
    value.trim().to_lowercase().replace([' ', '-'], "_")
}

#[derive(Debug, Clone, Default)]
pub struct NormalizedRoute {
    pub objective: String,
    pub optimize_axis: Option<String>,
}

/// Mirrors `normalizeArchitectureRoute`: `objective` is `best_shape` only
/// when explicitly requested, `optimize` when a non-blank `optimize_axis` is
/// present, and `sufficient` otherwise.
pub fn normalize_architecture_route(objective_raw: Option<&str>, optimize_axis_raw: Option<&str>) -> NormalizedRoute {
    let objective = normalize_alias(objective_raw.unwrap_or(""));
    let optimize_axis = optimize_axis_raw.map(str::trim).filter(|s| !s.is_empty());
    let normalized_objective = if objective == "best_shape" {
        "best_shape".to_string()
    } else if optimize_axis.is_some() {
        "optimize".to_string()
    } else {
        "sufficient".to_string()
    };
    NormalizedRoute {
        objective: normalized_objective,
        optimize_axis: optimize_axis.map(str::to_string),
    }
}

pub fn normalize_architecture_alias(value: &str) -> String {
    normalize_alias(value)
}

#[derive(Debug, Clone, Default)]
pub struct Significance {
    pub significant: bool,
    pub matched_significance_facts: Vec<String>,
}

/// Mirrors `classifySignificance`: every key in `facts` must be a known
/// significance rule.
pub fn classify_significance(facts: &BTreeSet<String>) -> Result<Significance, RouterError> {
    for key in facts {
        if !SIGNIFICANCE_RULES.contains(&key.as_str()) {
            return fail(format!("unknown significance fact: {key}"));
        }
    }
    let matched: Vec<String> = SIGNIFICANCE_RULES
        .iter()
        .filter(|rule| facts.contains(**rule))
        .map(|s| s.to_string())
        .collect();
    Ok(Significance {
        significant: !matched.is_empty(),
        matched_significance_facts: matched,
    })
}

#[derive(Debug, Clone)]
pub struct EffectClassification {
    pub declared_type: Option<String>,
    pub matched_rule: &'static str,
    pub basis: String,
    pub door: &'static str,
}

/// Mirrors `classifyEffect`.
pub fn classify_effect(
    declared_type: Option<&str>,
    category: Option<&str>,
    semantic_risk: Option<&str>,
) -> EffectClassification {
    if let Some(explicit) = declared_type {
        if DOOR.contains(&explicit) {
            return EffectClassification {
                declared_type: Some(explicit.to_string()),
                matched_rule: "declared_type",
                basis: explicit.to_string(),
                door: DOOR.iter().find(|d| **d == explicit).copied().unwrap(),
            };
        }
    }
    if let Some(category) = category {
        if let Some(door) = effect_category_door(category) {
            return EffectClassification {
                declared_type: declared_type.map(str::to_string),
                matched_rule: "capability_category",
                basis: category.to_string(),
                door,
            };
        }
    }
    if let Some(semantic) = semantic_risk {
        if ["destructive", "irreversible", "data_loss", "external_commitment"].contains(&semantic) {
            return EffectClassification {
                declared_type: declared_type.map(str::to_string),
                matched_rule: "semantic_risk",
                basis: semantic.to_string(),
                door: "one_way",
            };
        }
        if ["authority", "credential", "trust_boundary", "production", "spend", "send", "publish"].contains(&semantic)
        {
            return EffectClassification {
                declared_type: declared_type.map(str::to_string),
                matched_rule: "semantic_risk",
                basis: semantic.to_string(),
                door: "authority_sensitive",
            };
        }
    }
    EffectClassification {
        declared_type: declared_type.map(str::to_string),
        matched_rule: "safe_default",
        basis: semantic_risk.unwrap_or("ambiguous").to_string(),
        door: "authority_sensitive",
    }
}

#[derive(Debug, Clone)]
pub struct ArchitectureRouterInput {
    pub objective: Option<String>,
    pub optimize_axis: Option<String>,
    pub significance: BTreeSet<String>,
    pub declared_type: Option<String>,
    pub category: Option<String>,
    pub semantic_risk: Option<String>,
    pub flags: BTreeSet<String>,
    pub prior_route_objective: Option<String>,
}

impl Default for ArchitectureRouterInput {
    fn default() -> Self {
        Self {
            objective: None,
            optimize_axis: None,
            significance: BTreeSet::new(),
            declared_type: None,
            category: None,
            semantic_risk: None,
            flags: BTreeSet::new(),
            prior_route_objective: None,
        }
    }
}

#[derive(Debug, Clone)]
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

/// Mirrors `routeArchitecture`.
pub fn route_architecture(input: &ArchitectureRouterInput) -> Result<ArchitectureRoute, RouterError> {
    if let Some(objective) = &input.objective {
        if !OBJECTIVE.contains(&normalize_architecture_alias(objective).as_str()) {
            return fail("objective is invalid");
        }
    }
    if let Some(prior) = &input.prior_route_objective {
        if !OBJECTIVE.contains(&prior.as_str()) {
            return fail("prior_route is invalid");
        }
    }
    for flag in &input.flags {
        if !CRITICAL.contains(&flag.as_str()) && !DEPTH_FLAGS.contains(&flag.as_str()) {
            return fail("flags contain an unknown routing fact");
        }
    }
    let normalized = normalize_architecture_route(input.objective.as_deref(), input.optimize_axis.as_deref());
    let significance = classify_significance(&input.significance)?;
    if let Some(prior) = &input.prior_route_objective {
        if prior != &normalized.objective {
            return fail("objective self-upgrade requires explicit authority");
        }
    }
    let critical = CRITICAL.iter().any(|fact| input.flags.contains(*fact));
    let depth = if !significance.significant {
        "D0"
    } else if normalized.objective == "best_shape" || DEPTH_FLAGS.iter().any(|fact| input.flags.contains(*fact)) {
        "D2"
    } else {
        "D1"
    };
    let rigor = if critical {
        "critical"
    } else if significance.significant {
        "standard"
    } else {
        "lite"
    };
    let effect_classification = classify_effect(
        input.declared_type.as_deref(),
        input.category.as_deref(),
        input.semantic_risk.as_deref(),
    );
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

pub fn validate_architecture_router_input(input: &ArchitectureRouterInput) -> (bool, Vec<String>) {
    match route_architecture(input) {
        Ok(_) => (true, Vec::new()),
        Err(e) => (false, vec![e.0]),
    }
}

pub fn assert_architecture_router_input(input: &ArchitectureRouterInput) -> Result<(), RouterError> {
    let (valid, issues) = validate_architecture_router_input(input);
    if !valid {
        return fail(issues.into_iter().next().unwrap_or_default());
    }
    Ok(())
}

/// Route as a [`CanonVal`] record, mirroring the JS return shape closely
/// enough for callers that want to feed it into event payloads/state.
pub fn route_to_canon(route: &ArchitectureRoute) -> CanonVal {
    let mut v = CanonVal::obj()
        .set("schema", CanonVal::Str(route.schema.to_string()))
        .set("significant", CanonVal::Bool(route.significant))
        .set(
            "matched_significance_facts",
            CanonVal::Arr(route.matched_significance_facts.iter().map(|s| CanonVal::Str(s.clone())).collect()),
        )
        .set("objective", CanonVal::Str(route.objective.clone()))
        .set("depth", CanonVal::Str(route.depth.to_string()))
        .set("rigor", CanonVal::Str(route.rigor.to_string()));
    v = v.set(
        "optimize_axis",
        match &route.optimize_axis {
            Some(a) => CanonVal::Str(a.clone()),
            None => CanonVal::Null,
        },
    );
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set(items: &[&str]) -> BTreeSet<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn no_significance_facts_yields_d0_lite() {
        let route = route_architecture(&ArchitectureRouterInput::default()).unwrap();
        assert!(!route.significant);
        assert_eq!(route.depth, "D0");
        assert_eq!(route.rigor, "lite");
        assert_eq!(route.objective, "sufficient");
    }

    #[test]
    fn optimize_axis_forces_optimize_objective() {
        let input = ArchitectureRouterInput {
            optimize_axis: Some("latency".to_string()),
            ..Default::default()
        };
        let route = route_architecture(&input).unwrap();
        assert_eq!(route.objective, "optimize");
        assert_eq!(route.optimize_axis.as_deref(), Some("latency"));
    }

    #[test]
    fn significance_fact_without_critical_or_depth_flag_is_standard_d1() {
        let input = ArchitectureRouterInput {
            significance: set(&["broad_impact"]),
            ..Default::default()
        };
        let route = route_architecture(&input).unwrap();
        assert!(route.significant);
        assert_eq!(route.depth, "D1");
        assert_eq!(route.rigor, "standard");
    }

    #[test]
    fn critical_flag_forces_critical_rigor() {
        let input = ArchitectureRouterInput {
            significance: set(&["broad_impact"]),
            flags: set(&["safety"]),
            ..Default::default()
        };
        let route = route_architecture(&input).unwrap();
        assert_eq!(route.rigor, "critical");
    }

    #[test]
    fn depth_flag_forces_d2() {
        let input = ArchitectureRouterInput {
            significance: set(&["broad_impact"]),
            flags: set(&["migration"]),
            ..Default::default()
        };
        let route = route_architecture(&input).unwrap();
        assert_eq!(route.depth, "D2");
    }

    #[test]
    fn best_shape_objective_forces_d2_when_significant() {
        let input = ArchitectureRouterInput {
            objective: Some("best_shape".to_string()),
            significance: set(&["broad_impact"]),
            ..Default::default()
        };
        let route = route_architecture(&input).unwrap();
        assert_eq!(route.objective, "best_shape");
        assert_eq!(route.depth, "D2");
    }

    #[test]
    fn unknown_significance_fact_is_rejected() {
        let input = ArchitectureRouterInput {
            significance: set(&["not_a_real_fact"]),
            ..Default::default()
        };
        assert!(route_architecture(&input).is_err());
    }

    #[test]
    fn unknown_flag_is_rejected() {
        let input = ArchitectureRouterInput {
            flags: set(&["not_a_real_flag"]),
            ..Default::default()
        };
        assert!(route_architecture(&input).is_err());
    }

    #[test]
    fn objective_self_upgrade_without_authority_is_rejected() {
        let input = ArchitectureRouterInput {
            prior_route_objective: Some("sufficient".to_string()),
            optimize_axis: Some("latency".to_string()),
            ..Default::default()
        };
        assert!(route_architecture(&input).is_err());
    }

    #[test]
    fn effect_classification_declared_type_wins_first() {
        let c = classify_effect(Some("one_way"), Some("FILE_WRITE"), None);
        assert_eq!(c.door, "one_way");
        assert_eq!(c.matched_rule, "declared_type");
    }

    #[test]
    fn effect_classification_falls_back_to_category() {
        let c = classify_effect(None, Some("VCS_PUSH"), None);
        assert_eq!(c.door, "one_way");
        assert_eq!(c.matched_rule, "capability_category");
    }

    #[test]
    fn effect_classification_falls_back_to_semantic_risk_destructive() {
        let c = classify_effect(None, None, Some("data_loss"));
        assert_eq!(c.door, "one_way");
        assert_eq!(c.matched_rule, "semantic_risk");
    }

    #[test]
    fn effect_classification_falls_back_to_semantic_risk_authority() {
        let c = classify_effect(None, None, Some("credential"));
        assert_eq!(c.door, "authority_sensitive");
    }

    #[test]
    fn effect_classification_safe_default_is_authority_sensitive() {
        let c = classify_effect(None, None, None);
        assert_eq!(c.door, "authority_sensitive");
        assert_eq!(c.matched_rule, "safe_default");
        assert_eq!(c.basis, "ambiguous");
    }

    #[test]
    fn validate_architecture_router_input_reports_issue() {
        let input = ArchitectureRouterInput {
            significance: set(&["nope"]),
            ..Default::default()
        };
        let (valid, issues) = validate_architecture_router_input(&input);
        assert!(!valid);
        assert_eq!(issues.len(), 1);
    }
}
