use crate::{
    error::{Result, RuleError},
    schema::{BlueprintMatch, BlueprintResult, BlueprintSelector, EvidenceTier},
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

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
    selector.validate()?;
    let mut result = source.query(selector)?;
    result
        .validate()
        .map_err(|error| RuleError::InvalidSource(error.to_string()))?;
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
            .then(left.evidence.cmp(&right.evidence))
    });
    result.gaps.sort();
    result.gaps.dedup();
    result.complete = result.complete && result.gaps.is_empty();
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
    let mut ordered = selectors.iter().collect::<Vec<_>>();
    ordered.sort_by(|left, right| left.selector_id.cmp(&right.selector_id));
    let mut selector_ids = BTreeSet::new();
    for selector in ordered {
        if !selector_ids.insert(selector.selector_id.as_str()) {
            gaps.push(format!("duplicate-selector-id:{}", selector.selector_id));
            continue;
        }
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

/// Evaluate a Blueprint-dependent rule set while preserving typed degradation
/// when host-published Blueprint context is absent. The Rules crate does not
/// discover, open, or synthesize a Blueprint store.
pub fn evaluate_optional<S: BlueprintSource>(
    selectors: &[BlueprintSelector],
    source: Option<&S>,
) -> StructuralEvaluation {
    source.map_or_else(
        || StructuralEvaluation::unavailable(selectors, "blueprint-unavailable"),
        |source| evaluate(selectors, source),
    )
}

impl StructuralEvaluation {
    pub fn unavailable(selectors: &[BlueprintSelector], reason: impl Into<String>) -> Self {
        let reason = reason.into();
        let mut ordered = selectors.to_vec();
        ordered.sort_by(|left, right| left.selector_id.cmp(&right.selector_id));
        let evidence = ordered
            .iter()
            .map(|selector| StructuralEvidence {
                selector_id: selector.selector_id.clone(),
                generation: String::new(),
                evidence_tier: selector.expected_evidence_tier,
                matches: Vec::new(),
                complete: false,
                gaps: vec![reason.clone()],
            })
            .collect();
        Self {
            evidence,
            complete: false,
            gaps: vec![reason],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::{BlueprintOperation, EvidenceTier};
    use std::sync::Mutex;

    fn selector(id: &str) -> BlueprintSelector {
        BlueprintSelector {
            schema_version: 1,
            selector_id: id.into(),
            operation: BlueprintOperation::Files,
            repository_id: None,
            path_prefix: None,
            symbol: None,
            from: None,
            to: None,
            expected_evidence_tier: EvidenceTier::Inventory,
            expected_generation: Some("generation-1".into()),
        }
    }

    struct FixtureSource {
        calls: Mutex<Vec<String>>,
        tier: EvidenceTier,
    }

    impl BlueprintSource for FixtureSource {
        fn query(&self, selector: &BlueprintSelector) -> Result<BlueprintResult> {
            self.calls
                .lock()
                .unwrap()
                .push(selector.selector_id.clone());
            Ok(BlueprintResult {
                generation: "generation-1".into(),
                evidence_tier: self.tier,
                matches: vec![BlueprintMatch {
                    id: "file:src/lib.rs".into(),
                    path: Some("src/lib.rs".into()),
                    symbol: None,
                    evidence: "fixture".into(),
                }],
                complete: true,
                gaps: Vec::new(),
            })
        }
    }

    #[test]
    fn structural_queries_are_sorted_and_tier_mismatch_is_incomplete() {
        let source = FixtureSource {
            calls: Mutex::new(Vec::new()),
            tier: EvidenceTier::Structural,
        };
        let result = evaluate(&[selector("b"), selector("a")], &source);
        assert!(!result.complete);
        assert_eq!(
            source.calls.lock().unwrap().as_slice(),
            vec!["a".to_owned(), "b".to_owned()].as_slice()
        );
        assert!(result
            .gaps
            .contains(&"blueprint-evidence-tier-mismatch".into()));
    }

    #[test]
    fn absent_blueprint_is_typed_degradation() {
        let result = evaluate_optional::<FixtureSource>(&[selector("a")], None);
        assert!(!result.complete);
        assert_eq!(result.gaps, vec!["blueprint-unavailable".to_owned()]);
        assert_eq!(
            result.evidence[0].gaps,
            vec!["blueprint-unavailable".to_owned()]
        );
    }
}
