use crate::{
    error::{Result, RuleError},
    schema::{BlueprintMatch, BlueprintResult, BlueprintSelector, EvidenceTier},
};
use serde::{Deserialize, Serialize};

pub trait BlueprintSource: Send + Sync {
    fn query(&self, selector: &BlueprintSelector) -> Result<BlueprintResult>;
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StructuralEvidence {
    pub selector_id: String,
    pub generation: String,
    pub evidence_tier: EvidenceTier,
    pub matches: Vec<BlueprintMatch>,
    pub complete: bool,
    pub gaps: Vec<String>,
}

pub fn execute_selector<S: BlueprintSource>(
    selector: &BlueprintSelector,
    source: &S,
) -> Result<StructuralEvidence> {
    if selector.schema_version != 1 {
        return Err(RuleError::InvalidPack(
            "unsupported Blueprint selector version".into(),
        ));
    }
    let mut result = source.query(selector)?;
    if let Some(expected) = &selector.expected_generation {
        if &result.generation != expected {
            return Err(RuleError::GenerationMismatch {
                expected: expected.clone(),
                actual: result.generation,
            });
        }
    }
    if result.evidence_tier != selector.expected_evidence_tier {
        result.complete = false;
        result.gaps.push("blueprint-evidence-tier-mismatch".into());
    }
    result.matches.sort_by(|left, right| {
        left.id
            .cmp(&right.id)
            .then(left.path.cmp(&right.path))
            .then(left.symbol.cmp(&right.symbol))
    });
    result.gaps.sort();
    result.gaps.dedup();
    if result.gaps.is_empty() && result.complete {
        result.complete = true;
    }
    Ok(StructuralEvidence {
        selector_id: selector.selector_id.clone(),
        generation: result.generation,
        evidence_tier: result.evidence_tier,
        matches: result.matches,
        complete: result.complete,
        gaps: result.gaps,
    })
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StructuralEvaluation {
    pub evidence: Vec<StructuralEvidence>,
    pub complete: bool,
    pub gaps: Vec<String>,
}

pub fn evaluate<S: BlueprintSource>(
    selectors: &[BlueprintSelector],
    source: &S,
) -> StructuralEvaluation {
    let mut evidence = Vec::new();
    let mut gaps = Vec::new();
    for selector in selectors {
        match execute_selector(selector, source) {
            Ok(value) => {
                if !value.complete {
                    gaps.extend(value.gaps.iter().cloned());
                }
                evidence.push(value);
            }
            Err(error) => gaps.push(error.to_string()),
        }
    }
    evidence.sort_by(|left, right| left.selector_id.cmp(&right.selector_id));
    gaps.sort();
    gaps.dedup();
    StructuralEvaluation {
        complete: gaps.is_empty() && evidence.len() == selectors.len(),
        evidence,
        gaps,
    }
}
