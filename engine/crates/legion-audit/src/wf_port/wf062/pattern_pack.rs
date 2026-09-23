//! Port of `src/providers/security/packs/pattern-pack.mjs`: the generic
//! `createPatternPack({ id, family, description, rules })` factory used by
//! several other security packs (none owned by this chunk — e.g.
//! `insecure-defaults.mjs`, ported independently under wf060) to build a
//! lexical detector from a compact rule table.
//!
//! `createPatternPack` throws a `TypeError` when `id` does not start with
//! `'security.'`, or `family`/`rules` is falsy/empty; [`build`] mirrors that
//! validation with a `Result`.
//!
//! `resetAndMatch(pattern, text)` (`pattern.lastIndex = 0; return
//! pattern.test(text)`) exists in the JS source purely to make a **global**
//! regex's `test()` stateless across calls; the Rust `regex::Regex::is_match`
//! is already stateless, so no equivalent reset is needed here.

use super::{Context, Fact, Observation};
use regex::Regex;
use serde_json::json;

/// One entry of a pattern pack's `rules` array. Optional fields mirror the
/// JS `rule.<field> ?? <default>` fallbacks read by `analyze`.
#[derive(Debug, Clone)]
pub struct PatternRule {
    pub id: String,
    pub pattern: Regex,
    pub claim: String,
    /// Defaults to `"medium"` in JS.
    pub severity_hint: Option<String>,
    /// Defaults to `["control-request-input"]` in JS.
    pub attacker_capabilities: Option<Vec<String>>,
    /// Defaults to a single `attacker-position` fact in JS.
    pub preconditions: Option<Vec<Fact>>,
    /// Defaults to `"control-bypass"` in JS.
    pub effect_kind: Option<String>,
    /// Defaults to `"bypass"` in JS.
    pub effect_action: Option<String>,
    /// Defaults to `family` in JS.
    pub effect_scope: Option<String>,
    /// Defaults to `"application"` in JS.
    pub environment: Option<String>,
    /// Defaults to `["starter", "impact"]` in JS.
    pub chain_roles: Option<Vec<String>>,
    /// Defaults to a single fixed sentence in JS.
    pub uncertainty: Option<Vec<String>>,
}

impl PatternRule {
    /// Convenience constructor for a rule that relies on every JS default.
    pub fn simple(id: &str, pattern: Regex, claim: &str) -> Self {
        Self {
            id: id.to_string(),
            pattern,
            claim: claim.to_string(),
            severity_hint: None,
            attacker_capabilities: None,
            preconditions: None,
            effect_kind: None,
            effect_action: None,
            effect_scope: None,
            environment: None,
            chain_roles: None,
            uncertainty: None,
        }
    }
}

/// Mirrors `createPatternPack({ id, family, description, rules })`'s
/// return value (the parts every consumer of this chunk needs: `id`,
/// `candidateClass`, `rules`, and `analyze`; `variantStrategies` is always
/// `{}` in the JS source and is not modeled).
pub struct PatternPack {
    pub id: String,
    pub candidate_class: String,
    pub description: String,
    pub rules: Vec<PatternRule>,
}

/// Mirrors `createPatternPack`'s constructor-time `TypeError` checks:
/// `id` must start with `'security.'`; `family` must be non-empty;
/// `rules` must be a non-empty array.
pub fn build(id: &str, family: &str, description: &str, rules: Vec<PatternRule>) -> Result<PatternPack, String> {
    if !id.starts_with("security.") || family.is_empty() || rules.is_empty() {
        return Err("pattern pack requires security id, family, and rules".to_string());
    }
    Ok(PatternPack {
        id: id.to_string(),
        candidate_class: family.to_string(),
        description: description.to_string(),
        rules,
    })
}

impl PatternPack {
    /// Mirrors `analyze(context)`: for every scanned file with non-empty
    /// source text, find the bound `repository-artifact` (if any), and for
    /// every rule whose pattern matches, emit one [`Observation`].
    pub fn analyze(&self, context: &Context) -> Vec<Observation> {
        let mut observations = Vec::new();
        for file in &context.files {
            let text = context.read_file(file);
            if text.is_empty() {
                continue;
            }
            let artifact = context.find_artifact(file);
            let artifact_ids: Vec<String> = artifact.map(|a| vec![a.id.clone()]).unwrap_or_default();
            for rule in &self.rules {
                if !rule.pattern.is_match(text) {
                    continue;
                }
                let preconditions = rule.preconditions.clone().unwrap_or_else(|| {
                    vec![Fact {
                        kind: "attacker-position".to_string(),
                        subject: "actor:external".to_string(),
                        action: "supply-input".to_string(),
                        object: None,
                        scope: None,
                        environment: "application".to_string(),
                        tenant: None,
                    }]
                });
                observations.push(Observation {
                    rule_id: rule.id.clone(),
                    candidate_class: self.candidate_class.clone(),
                    claim: rule.claim.clone(),
                    severity_hint: rule.severity_hint.clone().unwrap_or_else(|| "medium".to_string()),
                    sources: artifact_ids.clone(),
                    sinks: artifact_ids.clone(),
                    attacker_capabilities: rule
                        .attacker_capabilities
                        .clone()
                        .unwrap_or_else(|| vec!["control-request-input".to_string()]),
                    preconditions,
                    effects: vec![Fact {
                        kind: rule.effect_kind.clone().unwrap_or_else(|| "control-bypass".to_string()),
                        subject: "actor:external".to_string(),
                        action: rule.effect_action.clone().unwrap_or_else(|| "bypass".to_string()),
                        object: artifact.map(|a| a.id.clone()),
                        scope: Some(rule.effect_scope.clone().unwrap_or_else(|| self.candidate_class.clone())),
                        environment: rule.environment.clone().unwrap_or_else(|| "application".to_string()),
                        tenant: None,
                    }],
                    assets: Vec::new(),
                    trust_boundary_crossings: Vec::new(),
                    required_controls: Vec::new(),
                    observed_controls: Vec::new(),
                    chain_roles: rule
                        .chain_roles
                        .clone()
                        .unwrap_or_else(|| vec!["starter".to_string(), "impact".to_string()]),
                    evidence_refs: artifact.map(|a| a.evidence_refs.clone()).unwrap_or_default(),
                    detector_metadata: json!({ "file": file, "patternFamily": self.candidate_class }),
                    uncertainty: rule.uncertainty.clone().unwrap_or_else(|| {
                        vec!["Reachability and compensating controls require independent adjudication.".to_string()]
                    }),
                });
            }
        }
        observations
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_rejects_a_non_security_prefixed_id() {
        let rules = vec![PatternRule::simple("x", Regex::new("x").unwrap(), "claim")];
        assert!(build("not-security.x", "family", "desc", rules).is_err());
    }

    #[test]
    fn build_rejects_empty_family_or_empty_rules() {
        assert!(build("security.x", "", "desc", vec![PatternRule::simple("x", Regex::new("x").unwrap(), "c")]).is_err());
        assert!(build("security.x", "family", "desc", Vec::new()).is_err());
    }

    #[test]
    fn analyze_emits_one_observation_per_matching_rule_with_bound_artifact_evidence() {
        let pack = build(
            "security.demo",
            "demo-family",
            "desc",
            vec![PatternRule::simple("demo.hit", Regex::new(r"danger\(").unwrap(), "Danger call present.")],
        )
        .unwrap();
        let context = Context::new().with_file("app.mjs", "danger(1);");
        let observations = pack.analyze(&context);
        assert_eq!(observations.len(), 1);
        let obs = &observations[0];
        assert_eq!(obs.rule_id, "demo.hit");
        assert_eq!(obs.candidate_class, "demo-family");
        assert_eq!(obs.severity_hint, "medium");
        assert_eq!(obs.sources, vec!["artifact:app.mjs".to_string()]);
        assert_eq!(obs.evidence_refs, vec!["ev:app.mjs".to_string()]);
        assert_eq!(obs.effects[0].scope.as_deref(), Some("demo-family"));
    }

    #[test]
    fn analyze_skips_files_with_empty_source_text_and_non_matching_rules() {
        let pack = build(
            "security.demo",
            "demo-family",
            "desc",
            vec![PatternRule::simple("demo.hit", Regex::new(r"danger\(").unwrap(), "Danger call present.")],
        )
        .unwrap();
        let context = Context::new().with_file("empty.mjs", "").with_file("neutral.mjs", "export const value = 1;");
        assert!(pack.analyze(&context).is_empty());
    }
}
