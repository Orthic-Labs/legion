//! Faithful port of `src/lib/verification/arcane/adversarial-proportionality.mjs`.
//!
//! Deterministic architecture evaluators for proportionality and
//! non-negotiable obligations. Inputs are explicit structured facts; neither
//! evaluator reads architecture-eval corpus expectations.

use super::errors::{ArcCode, ArcaneError};

pub const ADVERSARIAL_PROPORTIONALITY_IDS: [&str; 2] = ["AE-ADVERSARIAL-001", "AE-ADVERSARIAL-002"];

const COMPLEXITY: [&str; 3] = ["minimal", "modular", "distributed"];
const SCALE: [&str; 3] = ["low", "moderate", "high"];
const OBLIGATION_DOMAINS: [&str; 6] =
    ["privacy", "compliance", "security", "safety", "retention", "availability"];

fn rank(complexity: &str) -> i32 {
    COMPLEXITY.iter().position(|c| *c == complexity).map(|i| i as i32).unwrap_or(-1)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ObligationStatus {
    Implemented,
    Missing,
    NotApplicable,
}

#[derive(Debug)]
pub struct Obligation {
    pub id: String,
    pub domain: String,
    pub mandatory: bool,
    pub status: ObligationStatus,
}

fn normalize_obligations(values: &[Obligation]) -> Result<Vec<Obligation>, ArcaneError> {
    let mut ids = std::collections::HashSet::new();
    for entry in values {
        if entry.id.trim().is_empty() {
            return Err(ArcaneError::new(ArcCode::ArcSchemaInvalid, "obligation id is required"));
        }
        if !ids.insert(entry.id.clone()) {
            return Err(ArcaneError::new(ArcCode::ArcSchemaInvalid, "duplicate obligation id")
                .with_detail("id", entry.id.clone()));
        }
        if !OBLIGATION_DOMAINS.contains(&entry.domain.as_str()) {
            return Err(ArcaneError::new(ArcCode::ArcSchemaInvalid, "obligation domain is invalid")
                .with_detail("id", entry.id.clone()));
        }
    }
    Ok(values.to_vec())
}

impl Clone for Obligation {
    fn clone(&self) -> Self {
        Self {
            id: self.id.clone(),
            domain: self.domain.clone(),
            mandatory: self.mandatory,
            status: self.status.clone(),
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct Drivers {
    pub independent_scaling: bool,
    pub isolation_boundary: bool,
    pub multi_region_consistency: bool,
}

#[derive(Debug, Clone)]
pub struct ProportionalityInput {
    pub deployment: String,
    pub scale: String,
    pub proposed_complexity: String,
    pub drivers: Drivers,
    pub obligations: Vec<Obligation>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProportionalityResult {
    pub decision: &'static str,
    pub code: Option<&'static str>,
    pub proposed_complexity: String,
    pub minimum_complexity: &'static str,
    pub distributed: bool,
    pub modular: bool,
    pub mandatory_obligation_ids: Vec<String>,
    pub reason: &'static str,
}

/// Decides whether proposed architecture complexity has evidence-backed
/// drivers. It does not select a design: it only rejects complexity above
/// demonstrated need.
pub fn assess_architecture_proportionality(
    input: &ProportionalityInput,
) -> Result<ProportionalityResult, ArcaneError> {
    if !["greenfield", "existing"].contains(&input.deployment.as_str()) {
        return Err(ArcaneError::new(ArcCode::ArcSchemaInvalid, "deployment is invalid"));
    }
    if !SCALE.contains(&input.scale.as_str()) {
        return Err(ArcaneError::new(ArcCode::ArcSchemaInvalid, "scale is invalid"));
    }
    if !COMPLEXITY.contains(&input.proposed_complexity.as_str()) {
        return Err(ArcaneError::new(ArcCode::ArcSchemaInvalid, "proposedComplexity is invalid"));
    }
    let obligations = normalize_obligations(&input.obligations)?;
    let mandatory: Vec<&Obligation> = obligations
        .iter()
        .filter(|o| o.mandatory && o.status != ObligationStatus::NotApplicable)
        .collect();
    let distributed_driver =
        input.scale == "high" || input.drivers.independent_scaling || input.drivers.multi_region_consistency;
    let modular_driver = !mandatory.is_empty() || input.drivers.isolation_boundary || input.scale == "moderate";
    let minimum_complexity = if distributed_driver {
        "distributed"
    } else if modular_driver {
        "modular"
    } else {
        "minimal"
    };
    let excessive = rank(&input.proposed_complexity) > rank(minimum_complexity);
    Ok(ProportionalityResult {
        decision: if excessive { "REJECT" } else { "ALLOW" },
        code: if excessive { Some("ARC_PROPORTIONALITY_EXCESS") } else { None },
        proposed_complexity: input.proposed_complexity.clone(),
        minimum_complexity,
        distributed: distributed_driver,
        modular: modular_driver,
        mandatory_obligation_ids: mandatory.iter().map(|o| o.id.clone()).collect(),
        reason: if excessive {
            "proposed complexity exceeds demonstrated drivers"
        } else {
            "proposed complexity is justified by structured drivers"
        },
    })
}

#[derive(Debug, Clone)]
pub struct ObligationReadinessInput {
    pub objective: String,
    pub proposed_complexity: String,
    pub obligations: Vec<Obligation>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObligationReadinessResult {
    pub decision: &'static str,
    pub code: Option<&'static str>,
    pub objective: String,
    pub proposed_complexity: String,
    pub required_obligation_ids: Vec<String>,
    pub missing_obligation_ids: Vec<String>,
    pub missing_domains: Vec<String>,
    pub reason: &'static str,
}

/// Blocks minimization when required privacy, compliance, or equivalent work
/// is absent.
pub fn assess_mandatory_obligation_readiness(
    input: &ObligationReadinessInput,
) -> Result<ObligationReadinessResult, ArcaneError> {
    if !["minimize", "standard"].contains(&input.objective.as_str()) {
        return Err(ArcaneError::new(ArcCode::ArcSchemaInvalid, "objective is invalid"));
    }
    if !COMPLEXITY.contains(&input.proposed_complexity.as_str()) {
        return Err(ArcaneError::new(ArcCode::ArcSchemaInvalid, "proposedComplexity is invalid"));
    }
    let obligations = normalize_obligations(&input.obligations)?;
    let missing: Vec<&Obligation> =
        obligations.iter().filter(|o| o.mandatory && o.status == ObligationStatus::Missing).collect();
    let required: Vec<&Obligation> =
        obligations.iter().filter(|o| o.mandatory && o.status != ObligationStatus::NotApplicable).collect();
    let mut missing_domains: Vec<String> = missing.iter().map(|o| o.domain.clone()).collect();
    missing_domains.sort();
    missing_domains.dedup();
    Ok(ObligationReadinessResult {
        decision: if missing.is_empty() { "READY" } else { "BLOCK" },
        code: if missing.is_empty() { None } else { Some("ARC_MANDATORY_OBLIGATION_MISSING") },
        objective: input.objective.clone(),
        proposed_complexity: input.proposed_complexity.clone(),
        required_obligation_ids: required.iter().map(|o| o.id.clone()).collect(),
        missing_obligation_ids: missing.iter().map(|o| o.id.clone()).collect(),
        missing_domains,
        reason: if missing.is_empty() {
            "all required obligations are implemented or not applicable"
        } else {
            "required obligations are not implemented"
        },
    })
}

pub fn adversarial_proportionality_binding_ids() -> [&'static str; 2] {
    ADVERSARIAL_PROPORTIONALITY_IDS
}

#[cfg(test)]
mod tests {
    use super::*;

    fn default_proportionality_input() -> ProportionalityInput {
        ProportionalityInput {
            deployment: "greenfield".into(),
            scale: "low".into(),
            proposed_complexity: "distributed".into(),
            drivers: Drivers::default(),
            obligations: vec![],
        }
    }

    #[test]
    fn rejects_excess_complexity_without_drivers() {
        let result = assess_architecture_proportionality(&default_proportionality_input()).unwrap();
        assert_eq!(result.decision, "REJECT");
        assert_eq!(result.code, Some("ARC_PROPORTIONALITY_EXCESS"));
        assert_eq!(result.minimum_complexity, "minimal");
    }

    #[test]
    fn allows_distributed_when_scale_high() {
        let mut input = default_proportionality_input();
        input.scale = "high".into();
        let result = assess_architecture_proportionality(&input).unwrap();
        assert_eq!(result.decision, "ALLOW");
        assert_eq!(result.minimum_complexity, "distributed");
    }

    #[test]
    fn obligation_readiness_blocks_missing_mandatory_domains() {
        let input = ObligationReadinessInput {
            objective: "minimize".into(),
            proposed_complexity: "minimal".into(),
            obligations: vec![
                Obligation {
                    id: "privacy-retention".into(),
                    domain: "privacy".into(),
                    mandatory: true,
                    status: ObligationStatus::Missing,
                },
                Obligation {
                    id: "regulated-audit".into(),
                    domain: "compliance".into(),
                    mandatory: true,
                    status: ObligationStatus::Missing,
                },
            ],
        };
        let result = assess_mandatory_obligation_readiness(&input).unwrap();
        assert_eq!(result.decision, "BLOCK");
        assert_eq!(result.code, Some("ARC_MANDATORY_OBLIGATION_MISSING"));
        assert!(result.missing_domains.contains(&"privacy".to_string()));
        assert!(result.missing_domains.contains(&"compliance".to_string()));
    }

    #[test]
    fn obligation_readiness_ready_when_implemented() {
        let input = ObligationReadinessInput {
            objective: "standard".into(),
            proposed_complexity: "modular".into(),
            obligations: vec![Obligation {
                id: "privacy-retention".into(),
                domain: "privacy".into(),
                mandatory: true,
                status: ObligationStatus::Implemented,
            }],
        };
        let result = assess_mandatory_obligation_readiness(&input).unwrap();
        assert_eq!(result.decision, "READY");
        assert!(result.code.is_none());
    }

    #[test]
    fn rejects_duplicate_obligation_ids() {
        let mut input = default_proportionality_input();
        input.obligations = vec![
            Obligation { id: "a".into(), domain: "privacy".into(), mandatory: true, status: ObligationStatus::Missing },
            Obligation { id: "a".into(), domain: "privacy".into(), mandatory: true, status: ObligationStatus::Missing },
        ];
        let err = assess_architecture_proportionality(&input).unwrap_err();
        assert_eq!(err.code, ArcCode::ArcSchemaInvalid);
    }

    #[test]
    fn binding_ids_match_js_constant() {
        assert_eq!(adversarial_proportionality_binding_ids(), ["AE-ADVERSARIAL-001", "AE-ADVERSARIAL-002"]);
    }
}
