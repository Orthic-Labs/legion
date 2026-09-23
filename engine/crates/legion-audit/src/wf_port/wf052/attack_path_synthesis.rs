//! Port of `src/providers/security/attack-path-synthesis.mjs`.
//!
//! Bounded attack-path synthesis per Security Appendix Phase 4. Exact fact
//! matching, explicit bridge/objective registries, deterministic bounded
//! BFS. A path is a hypothesis until independent chain adjudication; no
//! numeric score is ever computed.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use serde_json::{json, Map, Value};

use super::contracts::{
    assert_artifact_binding, binding_from_plan, canonicalize, digest, evidence_rank, stable_id, Result,
};

const FACT_FIELDS: &[&str] = &["kind", "subject", "action", "object", "scope", "environment", "tenant"];

pub const PATH_PRIORITY: &[&str] = &[
    "DIRECT_CROWN_JEWEL",
    "PRIVILEGE_ESCALATION",
    "CROSS_TENANT",
    "CREDENTIAL_PIVOT",
    "LATERAL_PIVOT",
    "CONTROL_BYPASS",
    "PERSISTENT_COMPROMISE",
    "DATA_EXFILTRATION",
    "INTEGRITY_DESTRUCTION",
    "AVAILABILITY_FAILURE",
    "PARTIAL_PATH",
];

fn priority_index(priority: &str) -> i64 {
    PATH_PRIORITY
        .iter()
        .position(|p| *p == priority)
        .map(|i| i as i64)
        .unwrap_or(-1)
}

/// Limits, matching `DEFAULT_LIMITS`.
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    pub max_hops: usize,
    pub max_branching: usize,
    pub max_hypotheses: usize,
    pub max_paths_per_objective: usize,
    pub max_bridge_depth: u32,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_hops: 6,
            max_branching: 12,
            max_hypotheses: 100,
            max_paths_per_objective: 20,
            max_bridge_depth: 3,
        }
    }
}

impl Limits {
    fn to_json(self) -> Value {
        json!({
            "maxHops": self.max_hops,
            "maxBranching": self.max_branching,
            "maxHypotheses": self.max_hypotheses,
            "maxPathsPerObjective": self.max_paths_per_objective,
            "maxBridgeDepth": self.max_bridge_depth,
        })
    }
}

/// Faithful port of `factMatches`.
pub fn fact_matches(pattern: &Value, fact: &Value) -> bool {
    for key in FACT_FIELDS {
        let expected = pattern.get(*key);
        if matches!(expected, None | Some(Value::Null)) {
            continue;
        }
        let expected = expected.unwrap();
        let observed = fact.get(*key).cloned().unwrap_or(Value::Null);
        if expected.as_str() == Some("*") {
            if observed.is_null() {
                return false;
            }
            continue;
        }
        if expected != &observed {
            return false;
        }
    }
    if let Some(Value::Object(attrs)) = pattern.get("attributes") {
        for (key, expected) in attrs {
            let observed = fact.pointer(&format!("/attributes/{key}"));
            if expected.as_str() == Some("*") {
                if observed.is_none() || observed == Some(&Value::Null) {
                    return false;
                }
            } else if observed != Some(expected) {
                return false;
            }
        }
    }
    true
}

/// Faithful port of `canonicalFactKey`.
pub fn canonical_fact_key(fact: &Value) -> String {
    let mut normalized = Map::new();
    for key in FACT_FIELDS {
        normalized.insert((*key).to_string(), fact.get(*key).cloned().unwrap_or(Value::Null));
    }
    normalized.insert(
        "attributes".to_string(),
        fact.get("attributes").cloned().unwrap_or_else(|| json!({})),
    );
    serde_json::to_string(&canonicalize(&Value::Object(normalized))).expect("canonical JSON never fails")
}

fn bridge_pattern_matches(pattern: &Value, fact: &Value) -> bool {
    fact_matches(pattern, fact)
}

struct MappedFact {
    fact: Value,
    support: Value,
}

fn map_bridge_fact(bridge: &Value, source_fact: &Value, model: &Value) -> Vec<MappedFact> {
    let to = bridge.get("to").cloned().unwrap_or_else(|| json!({}));
    let mut target = Map::new();
    target.insert("kind".to_string(), to.get("kind").cloned().unwrap_or(Value::Null));
    target.insert("subject".to_string(), to.get("subject").cloned().unwrap_or(Value::Null));
    target.insert("action".to_string(), to.get("action").cloned().unwrap_or(Value::Null));
    target.insert("object".to_string(), to.get("object").cloned().unwrap_or(Value::Null));
    target.insert("scope".to_string(), to.get("scope").cloned().unwrap_or(Value::Null));
    target.insert("environment".to_string(), to.get("environment").cloned().unwrap_or(Value::Null));
    target.insert("tenant".to_string(), to.get("tenant").cloned().unwrap_or(Value::Null));
    target.insert("attributes".to_string(), to.get("attributes").cloned().unwrap_or_else(|| json!({})));

    if let Some(field_map) = bridge.get("fieldMap").and_then(Value::as_object) {
        for (target_field, source_field) in field_map {
            let source_field = source_field.as_str().unwrap_or("");
            target.insert(
                target_field.clone(),
                source_fact.get(source_field).cloned().unwrap_or(Value::Null),
            );
        }
    }

    let bridge_id = bridge.get("id").cloned().unwrap_or(Value::Null);
    let evidence_strength = bridge.get("evidenceStrength").cloned().unwrap_or(Value::Null);
    let source_fact_id = source_fact.get("id").cloned().unwrap_or(Value::Null);
    let source_evidence_refs: BTreeSet<String> = source_fact
        .get("evidenceRefs")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|v| v.as_str().map(str::to_string))
        .collect();

    if let Some(requires_relation) = bridge.get("requiresModelRelation").and_then(Value::as_str) {
        let source_object = source_fact.get("object").cloned().unwrap_or(Value::Null);
        let source_subject = source_fact.get("subject").cloned().unwrap_or(Value::Null);
        let compatible: Vec<&Value> = model
            .get("relations")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter(|relation| {
                relation.get("kind").and_then(Value::as_str) == Some(requires_relation)
                    && (relation.get("from") == Some(&source_object) || relation.get("from") == Some(&source_subject))
            })
            .collect();
        if compatible.is_empty() {
            return Vec::new();
        }
        return compatible
            .into_iter()
            .map(|relation| {
                let mut t = target.clone();
                let relation_to = relation.get("to").cloned().unwrap_or(Value::Null);
                let object_value = if target.get("object").map(Value::is_null).unwrap_or(true) {
                    relation_to.clone()
                } else {
                    target["object"].clone()
                };
                t.insert("object".to_string(), object_value.clone());
                let relation_id = relation.get("id").cloned().unwrap_or(Value::Null);
                let id_content = json!({
                    "bridge": bridge_id,
                    "sourceFact": source_fact_id,
                    "relation": relation_id,
                    "target": Value::Object(t.clone()),
                });
                let id = stable_id("bridged-security-fact", &id_content);
                let mut evidence_refs: BTreeSet<String> = source_evidence_refs.clone();
                for r in relation.get("evidenceRefs").and_then(Value::as_array).into_iter().flatten() {
                    if let Some(s) = r.as_str() {
                        evidence_refs.insert(s.to_string());
                    }
                }
                t.insert("id".to_string(), json!(id));
                t.insert("evidenceRefs".to_string(), json!(evidence_refs.into_iter().collect::<Vec<_>>()));
                MappedFact {
                    fact: Value::Object(t),
                    support: json!({
                        "bridgeId": bridge_id,
                        "relationId": relation_id,
                        "evidenceStrength": evidence_strength,
                        "evidenceRefs": relation.get("evidenceRefs").cloned().unwrap_or(json!([])),
                    }),
                }
            })
            .collect();
    }

    let id_content = json!({
        "bridge": bridge_id,
        "sourceFact": source_fact_id,
        "target": Value::Object(target.clone()),
    });
    let id = stable_id("bridged-security-fact", &id_content);
    let mut t = target;
    t.insert("id".to_string(), json!(id));
    t.insert(
        "evidenceRefs".to_string(),
        json!(source_evidence_refs.into_iter().collect::<Vec<_>>()),
    );
    vec![MappedFact {
        fact: Value::Object(t),
        support: json!({
            "bridgeId": bridge_id,
            "relationId": Value::Null,
            "evidenceStrength": evidence_strength,
            "evidenceRefs": [],
        }),
    }]
}

/// Faithful port of `expandBridges`.
pub fn expand_bridges(facts: &[Value], bridges: &[Value], model: &Value) -> Vec<MappedFactExport> {
    let mut generated = Vec::new();
    for fact in facts {
        for bridge in bridges {
            if !bridge_pattern_matches(&bridge["from"], fact) {
                continue;
            }
            for mapped in map_bridge_fact(bridge, fact, model) {
                generated.push(MappedFactExport(mapped.fact, mapped.support));
            }
        }
    }
    generated
}

/// Public wrapper so callers outside this module can read `expandBridges`
/// output without depending on the private `MappedFact` type.
pub struct MappedFactExport(pub Value, pub Value);

#[derive(Clone)]
struct State {
    facts: BTreeMap<String, Value>, // canonicalFactKey -> fact
    used_candidates: BTreeSet<String>,
    steps: Vec<Value>,
    joins: Vec<Value>,
    unsupported_assertions: Vec<Value>,
}

fn state_key(state: &State) -> String {
    let mut fact_keys: Vec<String> = state.facts.values().map(canonical_fact_key).collect();
    fact_keys.sort();
    let mut used: Vec<String> = state.used_candidates.iter().cloned().collect();
    used.sort();
    stable_id(
        "attack-path-state",
        &json!({"facts": fact_keys, "usedCandidates": used}),
    )
}

fn add_fact(map: &mut BTreeMap<String, Value>, fact: &Value) {
    let key = canonical_fact_key(fact);
    map.entry(key).or_insert_with(|| fact.clone());
}

fn add_fact_with_change(map: &mut BTreeMap<String, Value>, fact: &Value) -> bool {
    let key = canonical_fact_key(fact);
    if map.contains_key(&key) {
        return false;
    }
    map.insert(key, fact.clone());
    true
}

fn base_state(model: &Value) -> State {
    let mut facts = BTreeMap::new();
    for fact in model.get("initialFacts").and_then(Value::as_array).into_iter().flatten() {
        add_fact(&mut facts, fact);
    }
    State {
        facts,
        used_candidates: BTreeSet::new(),
        steps: Vec::new(),
        joins: Vec::new(),
        unsupported_assertions: Vec::new(),
    }
}

fn augment_state_with_bridges(state: &State, bridges: &[Value], model: &Value, max_bridge_depth: u32) -> State {
    let mut facts = state.facts.clone();
    let mut frontier: Vec<(Value, u32)> = facts.values().map(|f| (f.clone(), 0)).collect();
    let mut expanded: BTreeSet<String> = BTreeSet::new();

    while !frontier.is_empty() {
        let mut next_frontier = Vec::new();
        for (fact, depth) in &frontier {
            if *depth >= max_bridge_depth {
                continue;
            }
            for bridge in bridges {
                let bridge_id = bridge.get("id").and_then(Value::as_str).unwrap_or("");
                let fact_id = fact.get("id").and_then(Value::as_str).unwrap_or("");
                let expansion_key = format!("{bridge_id}\0{fact_id}");
                if expanded.contains(&expansion_key) {
                    continue;
                }
                expanded.insert(expansion_key);
                if !bridge_pattern_matches(&bridge["from"], fact) {
                    continue;
                }
                for generated in map_bridge_fact(bridge, fact, model) {
                    let produced_by_step = fact.get("producedByStep").cloned().unwrap_or(Value::Null);
                    let source_fact_id = fact.get("id").cloned().unwrap_or(Value::Null);
                    let bridge_support = json!({
                        "bridgeId": generated.support.get("bridgeId").cloned().unwrap_or(Value::Null),
                        "relationId": generated.support.get("relationId").cloned().unwrap_or(Value::Null),
                    });
                    let evidence_strength = generated.support.get("evidenceStrength").cloned().unwrap_or(Value::Null);
                    let mut refs: BTreeSet<String> = fact
                        .get("evidenceRefs")
                        .and_then(Value::as_array)
                        .into_iter()
                        .flatten()
                        .filter_map(|v| v.as_str().map(str::to_string))
                        .collect();
                    for r in generated
                        .support
                        .get("evidenceRefs")
                        .and_then(Value::as_array)
                        .into_iter()
                        .flatten()
                    {
                        if let Some(s) = r.as_str() {
                            refs.insert(s.to_string());
                        }
                    }
                    let mut bridged = generated.fact.as_object().cloned().unwrap();
                    bridged.insert("producedByStep".to_string(), produced_by_step);
                    bridged.insert("sourceFactId".to_string(), source_fact_id);
                    bridged.insert("bridgeSupport".to_string(), bridge_support);
                    bridged.insert("evidenceStrength".to_string(), evidence_strength);
                    bridged.insert("evidenceRefs".to_string(), json!(refs.into_iter().collect::<Vec<_>>()));
                    let bridged_fact = Value::Object(bridged);
                    if add_fact_with_change(&mut facts, &bridged_fact) {
                        next_frontier.push((bridged_fact, depth + 1));
                    }
                }
            }
        }
        frontier = next_frontier;
    }

    State {
        facts,
        used_candidates: state.used_candidates.clone(),
        steps: state.steps.clone(),
        joins: state.joins.clone(),
        unsupported_assertions: state.unsupported_assertions.clone(),
    }
}

struct PreconditionMatch {
    precondition_index: usize,
    fact: Value,
}

fn find_satisfied_preconditions(preconditions: &[Value], facts: &[Value]) -> Option<Vec<PreconditionMatch>> {
    let mut matches = Vec::with_capacity(preconditions.len());
    for (index, pattern) in preconditions.iter().enumerate() {
        let fact = facts.iter().find(|candidate| fact_matches(pattern, candidate))?;
        matches.push(PreconditionMatch {
            precondition_index: index,
            fact: fact.clone(),
        });
    }
    Some(matches)
}

fn candidate_applicability(candidate: &Value, state: &State) -> Option<Vec<PreconditionMatch>> {
    let preconditions = candidate.get("preconditions").and_then(Value::as_array).cloned().unwrap_or_default();
    let facts: Vec<Value> = state.facts.values().cloned().collect();
    find_satisfied_preconditions(&preconditions, &facts)
}

fn apply_candidate(candidate: &Value, state: &State, matches: &[PreconditionMatch]) -> State {
    let mut next_facts = state.facts.clone();
    let step_index = state.steps.len();
    let candidate_id = candidate.get("id").cloned().unwrap_or(Value::Null);

    let joins: Vec<Value> = matches
        .iter()
        .map(|m| {
            let from_step = m.fact.get("producedByStep").cloned().unwrap_or(Value::Null);
            let from_fact_id = m.fact.get("id").cloned().unwrap_or(Value::Null);
            let bridge_support = m.fact.get("bridgeSupport").cloned();
            let relation = if bridge_support.is_some() { "bridged-satisfaction" } else { "satisfies" };
            let support = bridge_support.unwrap_or_else(|| json!({"kind": "direct-fact-match"}));
            let evidence_strength = m.fact.get("evidenceStrength").cloned().unwrap_or_else(|| json!("possible"));
            let evidence_refs = m.fact.get("evidenceRefs").cloned().unwrap_or_else(|| json!([]));
            let id_content = json!({
                "candidateId": candidate_id,
                "preconditionIndex": m.precondition_index,
                "factId": from_fact_id,
                "stepIndex": step_index,
            });
            json!({
                "id": stable_id("attack-path-join", &id_content),
                "fromStep": from_step,
                "fromFactId": from_fact_id,
                "toStep": step_index,
                "toPreconditionIndex": m.precondition_index,
                "relation": relation,
                "support": support,
                "evidenceStrength": evidence_strength,
                "evidenceRefs": evidence_refs,
                "status": "UNADJUDICATED",
            })
        })
        .collect();

    let candidate_evidence_refs: BTreeSet<String> = candidate
        .get("evidenceRefs")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|v| v.as_str().map(str::to_string))
        .collect();

    let effects: Vec<Value> = candidate
        .get("effects")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .map(|effect| {
            let mut refs: BTreeSet<String> = effect
                .get("evidenceRefs")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(|v| v.as_str().map(str::to_string))
                .collect();
            refs.extend(candidate_evidence_refs.iter().cloned());
            let mut out = effect.as_object().cloned().unwrap();
            out.insert("producedByStep".to_string(), json!(step_index));
            out.insert("evidenceStrength".to_string(), json!("possible"));
            out.insert("evidenceRefs".to_string(), json!(refs.into_iter().collect::<Vec<_>>()));
            Value::Object(out)
        })
        .collect();

    for effect in &effects {
        add_fact(&mut next_facts, effect);
    }

    let mut used_candidates = state.used_candidates.clone();
    if let Some(id) = candidate_id.as_str() {
        used_candidates.insert(id.to_string());
    }

    let requires: Vec<Value> = matches.iter().map(|m| m.fact.get("id").cloned().unwrap_or(Value::Null)).collect();
    let produces: Vec<Value> = effects.iter().map(|e| e.get("id").cloned().unwrap_or(Value::Null)).collect();

    let mut steps = state.steps.clone();
    steps.push(json!({
        "order": step_index,
        "candidateId": candidate_id,
        "requires": requires,
        "produces": produces,
        "status": "UNADJUDICATED",
    }));

    let mut all_joins = state.joins.clone();
    all_joins.extend(joins);

    State {
        facts: next_facts,
        used_candidates,
        steps,
        joins: all_joins,
        unsupported_assertions: state.unsupported_assertions.clone(),
    }
}

fn glob_token(pattern: &str, value: &str) -> bool {
    let mut escaped = String::new();
    for ch in pattern.chars() {
        if ".+?^${}()|[]\\".contains(ch) {
            escaped.push('\\');
            escaped.push(ch);
        } else if ch == '*' {
            escaped.push_str(".*");
        } else {
            escaped.push(ch);
        }
    }
    let re = regex::RegexBuilder::new(&format!("^{escaped}$"))
        .case_insensitive(true)
        .build();
    match re {
        Ok(re) => re.is_match(value),
        Err(_) => false,
    }
}

fn objective_matches_fact(objective: &Value, fact: &Value, entity_by_id: &BTreeMap<String, Value>) -> bool {
    let rule = objective.get("matches").cloned().unwrap_or_else(|| json!({}));
    if let Some(fact_kind) = rule.get("factKind").and_then(Value::as_str) {
        if fact.get("kind").and_then(Value::as_str) != Some(fact_kind) {
            return false;
        }
    }
    if let Some(fact_kinds) = rule.get("factKinds").and_then(Value::as_array) {
        let kind = fact.get("kind").and_then(Value::as_str).unwrap_or("");
        if !fact_kinds.iter().any(|k| k.as_str() == Some(kind)) {
            return false;
        }
    }
    if let Some(scope_patterns) = rule.get("scopePatterns").and_then(Value::as_array) {
        if !scope_patterns.is_empty() {
            let scope = fact.get("scope").and_then(Value::as_str).unwrap_or("");
            let matched = scope_patterns
                .iter()
                .any(|p| p.as_str().map(|p| glob_token(p, scope)).unwrap_or(false));
            if !matched {
                return false;
            }
        }
    }
    if let Some(asset_kinds) = rule.get("assetKinds").and_then(Value::as_array) {
        if !asset_kinds.is_empty() {
            let object_id = fact.get("object").and_then(Value::as_str);
            let asset = object_id.and_then(|id| entity_by_id.get(id));
            match asset {
                None => return false,
                Some(asset) => {
                    let kind = asset.get("kind").and_then(Value::as_str).unwrap_or("");
                    if !asset_kinds.iter().any(|k| k.as_str() == Some(kind)) {
                        return false;
                    }
                }
            }
        }
    }
    true
}

fn match_objectives(facts: &[Value], model: &Value, objectives: &[Value]) -> Vec<Value> {
    let entity_by_id: BTreeMap<String, Value> = model
        .get("entities")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|e| e.get("id").and_then(Value::as_str).map(|id| (id.to_string(), e.clone())))
        .collect();

    let mut matches: Vec<Value> = Vec::new();
    for objective in objectives {
        let matched_facts: Vec<&Value> = facts
            .iter()
            .filter(|fact| objective_matches_fact(objective, fact, &entity_by_id))
            .collect();
        if matched_facts.is_empty() {
            continue;
        }
        let mut matched_fact_ids: Vec<String> = matched_facts
            .iter()
            .filter_map(|f| f.get("id").and_then(Value::as_str).map(str::to_string))
            .collect();
        matched_fact_ids.sort();
        let matched_asset_ids: BTreeSet<String> = matched_facts
            .iter()
            .filter_map(|f| f.get("object").and_then(Value::as_str))
            .filter(|id| entity_by_id.contains_key(*id))
            .map(str::to_string)
            .collect();
        let matched_asset_ids: Vec<String> = matched_asset_ids.into_iter().collect();

        matches.push(json!({
            "id": objective.get("id").cloned().unwrap_or(Value::Null),
            "priority": objective.get("priority").cloned().unwrap_or(Value::Null),
            "description": objective.get("description").cloned().unwrap_or_else(|| objective.get("id").cloned().unwrap_or(Value::Null)),
            "matchedFactIds": matched_fact_ids,
            "matchedAssetIds": matched_asset_ids,
        }));
    }
    matches.sort_by(|left, right| {
        let lp = priority_index(left.get("priority").and_then(Value::as_str).unwrap_or(""));
        let rp = priority_index(right.get("priority").and_then(Value::as_str).unwrap_or(""));
        lp.cmp(&rp).then_with(|| {
            let li = left.get("id").and_then(Value::as_str).unwrap_or("");
            let ri = right.get("id").and_then(Value::as_str).unwrap_or("");
            li.cmp(ri)
        })
    });
    matches
}

fn derive_start(state: &State) -> Value {
    let initial_joins: Vec<&Value> = state
        .joins
        .iter()
        .filter(|join| join.get("fromStep").map(Value::is_null).unwrap_or(true))
        .collect();
    let fact_ids: BTreeSet<String> = initial_joins
        .iter()
        .filter_map(|j| j.get("fromFactId").and_then(Value::as_str))
        .map(str::to_string)
        .collect();
    let fact_ids: Vec<String> = fact_ids.into_iter().collect();
    let first_candidate_id = state
        .steps
        .first()
        .and_then(|s| s.get("candidateId").cloned())
        .unwrap_or(Value::Null);
    json!({"factIds": fact_ids, "firstCandidateId": first_candidate_id})
}

fn derive_controls(state: &State, candidate_by_id: &BTreeMap<String, Value>) -> Value {
    let mut required: BTreeSet<String> = BTreeSet::new();
    let mut observed: BTreeSet<String> = BTreeSet::new();
    for step in &state.steps {
        let candidate_id = step.get("candidateId").and_then(Value::as_str).unwrap_or("");
        if let Some(candidate) = candidate_by_id.get(candidate_id) {
            for id in candidate.get("requiredControls").and_then(Value::as_array).into_iter().flatten() {
                if let Some(s) = id.as_str() {
                    required.insert(s.to_string());
                }
            }
            for id in candidate.get("observedControls").and_then(Value::as_array).into_iter().flatten() {
                if let Some(s) = id.as_str() {
                    observed.insert(s.to_string());
                }
            }
        }
    }
    json!({
        "required": required.into_iter().collect::<Vec<_>>(),
        "observed": observed.into_iter().collect::<Vec<_>>(),
        "status": "UNADJUDICATED",
    })
}

#[allow(clippy::too_many_arguments)]
fn build_hypothesis(
    state: &State,
    objective: &Value,
    binding: &Value,
    denominator_digest: &str,
    limits: Limits,
    candidate_by_id: &BTreeMap<String, Value>,
) -> Value {
    let start = derive_start(state);
    let terminal_facts = objective.get("matchedFactIds").cloned().unwrap_or_else(|| json!([]));
    let content = json!({
        "start": start,
        "objective": objective,
        "steps": state.steps,
        "joins": state.joins,
        "terminalFacts": terminal_facts,
    });
    let id = stable_id("attack-path-hypothesis", &content);
    json!({
        "schemaVersion": 1,
        "kind": "attack-path-hypothesis",
        "id": id,
        "provider": "security.attack-path-synthesis",
        "providerVersion": "1",
        "binding": binding,
        "denominatorDigest": denominator_digest,
        "status": "PROPOSED",
        "priority": objective.get("priority").cloned().unwrap_or(Value::Null),
        "start": start,
        "objective": objective,
        "steps": state.steps,
        "joins": state.joins,
        "terminalFacts": terminal_facts,
        "controls": derive_controls(state, candidate_by_id),
        "unsupportedAssertions": state.unsupported_assertions,
        "alternateExplanations": [],
        "synthesis": {
            "maxHops": limits.max_hops,
            "maxBranching": limits.max_branching,
            "maxHypotheses": limits.max_hypotheses,
            "maxBridgeDepth": limits.max_bridge_depth,
            "truncated": false,
            "truncationReasons": [],
        },
    })
}

fn hypothesis_signature(path: &Value) -> String {
    let content = json!({
        "objectiveId": path.pointer("/objective/id").cloned().unwrap_or(Value::Null),
        "startFactIds": path.pointer("/start/factIds").cloned().unwrap_or(json!([])),
        "candidateIds": path
            .get("steps")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .map(|s| s.get("candidateId").cloned().unwrap_or(Value::Null))
            .collect::<Vec<_>>(),
        "terminalFacts": path.get("terminalFacts").cloned().unwrap_or(json!([])),
    });
    serde_json::to_string(&canonicalize(&content)).expect("canonical JSON never fails")
}

fn weakest_join_rank(path: &Value) -> i64 {
    let joins = path.get("joins").and_then(Value::as_array).cloned().unwrap_or_default();
    if joins.is_empty() {
        return evidence_rank("possible");
    }
    joins
        .iter()
        .map(|j| evidence_rank(j.get("evidenceStrength").and_then(Value::as_str).unwrap_or("possible")))
        .min()
        .unwrap_or_else(|| evidence_rank("possible"))
}

fn better_hypothesis(left: &Value, right: &Value) -> bool {
    let left_unsupported = left.get("unsupportedAssertions").and_then(Value::as_array).map(Vec::len).unwrap_or(0);
    let right_unsupported = right.get("unsupportedAssertions").and_then(Value::as_array).map(Vec::len).unwrap_or(0);
    if left_unsupported != right_unsupported {
        return left_unsupported < right_unsupported;
    }
    let left_rank = weakest_join_rank(left);
    let right_rank = weakest_join_rank(right);
    if left_rank != right_rank {
        return left_rank > right_rank;
    }
    let left_steps = left.get("steps").and_then(Value::as_array).map(Vec::len).unwrap_or(0);
    let right_steps = right.get("steps").and_then(Value::as_array).map(Vec::len).unwrap_or(0);
    if left_steps != right_steps {
        return left_steps < right_steps;
    }
    left.get("id").and_then(Value::as_str).unwrap_or("") < right.get("id").and_then(Value::as_str).unwrap_or("")
}

#[allow(clippy::too_many_arguments)]
fn finalize_hypotheses(
    binding: &Value,
    denominator_digest: &str,
    hypotheses: Vec<Value>,
    limits: Limits,
    truncation_reasons: Vec<String>,
    model: &Value,
    candidates_artifact: &Value,
    states_examined: usize,
) -> Value {
    let mut by_signature: BTreeMap<String, Value> = BTreeMap::new();
    for path in hypotheses {
        let signature = hypothesis_signature(&path);
        let should_insert = match by_signature.get(&signature) {
            Some(current) => better_hypothesis(&path, current),
            None => true,
        };
        if should_insert {
            by_signature.insert(signature, path);
        }
    }
    let mut retained: Vec<Value> = by_signature.into_values().collect();
    retained.sort_by(|left, right| {
        let lp = priority_index(left.get("priority").and_then(Value::as_str).unwrap_or(""));
        let rp = priority_index(right.get("priority").and_then(Value::as_str).unwrap_or(""));
        if lp != rp {
            return lp.cmp(&rp);
        }
        let ls = left.get("steps").and_then(Value::as_array).map(Vec::len).unwrap_or(0);
        let rs = right.get("steps").and_then(Value::as_array).map(Vec::len).unwrap_or(0);
        if ls != rs {
            return ls.cmp(&rs);
        }
        left.get("id")
            .and_then(Value::as_str)
            .unwrap_or("")
            .cmp(right.get("id").and_then(Value::as_str).unwrap_or(""))
    });

    let truncated = !truncation_reasons.is_empty();
    for path in retained.iter_mut() {
        path["synthesis"]["truncated"] = json!(truncated);
        path["synthesis"]["truncationReasons"] = json!(truncation_reasons);
    }

    let model_complete = model.get("complete").and_then(Value::as_bool).unwrap_or(false);
    let candidates_complete = candidates_artifact.get("complete").and_then(Value::as_bool).unwrap_or(false);

    let mut coverage_gaps: Vec<Value> = Vec::new();
    if !model_complete {
        coverage_gaps.push(json!({"kind": "security-model-incomplete"}));
    }
    if !candidates_complete {
        coverage_gaps.push(json!({"kind": "security-candidates-incomplete"}));
    }
    for reason in &truncation_reasons {
        coverage_gaps.push(json!({"kind": "attack-path-search-truncated", "reason": reason}));
    }

    let candidate_count = candidates_artifact
        .get("candidates")
        .and_then(Value::as_array)
        .map(Vec::len)
        .unwrap_or(0);
    let initial_fact_count = model.get("initialFacts").and_then(Value::as_array).map(Vec::len).unwrap_or(0);

    json!({
        "schemaVersion": 1,
        "kind": "attack-path-hypotheses",
        "provider": "security.attack-path-synthesis",
        "providerVersion": "1",
        "binding": binding,
        "denominatorDigest": denominator_digest,
        "complete": !truncated && model_complete && candidates_complete,
        "hypotheses": retained.clone(),
        "coverage": {
            "candidateCount": candidate_count,
            "initialFactCount": initial_fact_count,
            "statesExamined": states_examined,
            "hypothesesProduced": retained.len(),
            "limits": limits.to_json(),
        },
        "coverageGaps": coverage_gaps,
    })
}

/// Faithful port of `synthesizeAttackPaths`.
pub fn synthesize_attack_paths(
    plan: &Value,
    model: &Value,
    candidates_artifact: &Value,
    bridges: &[Value],
    objectives: &[Value],
    limits: Limits,
) -> Result<Value> {
    let binding = binding_from_plan(plan)?;
    assert_artifact_binding(model, &binding, "security model")?;
    assert_artifact_binding(candidates_artifact, &binding, "security candidates")?;

    let denominator_digest = digest(&json!({
        "model": model.get("denominatorDigest").cloned().unwrap_or(Value::Null),
        "candidates": candidates_artifact.get("denominatorDigest").cloned().unwrap_or(Value::Null),
        "bridges": digest(&json!(bridges)),
        "objectives": digest(&json!(objectives)),
        "limits": limits.to_json(),
    }));

    let candidates: Vec<Value> = candidates_artifact
        .get("candidates")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let candidate_by_id: BTreeMap<String, Value> = candidates
        .iter()
        .filter_map(|c| c.get("id").and_then(Value::as_str).map(|id| (id.to_string(), c.clone())))
        .collect();

    let mut queue: VecDeque<State> = VecDeque::new();
    queue.push_back(base_state(model));
    let mut seen: BTreeSet<String> = BTreeSet::new();
    let mut hypotheses: Vec<Value> = Vec::new();
    let mut truncation_reasons: BTreeSet<String> = BTreeSet::new();

    while let Some(queued_state) = queue.pop_front() {
        if hypotheses.len() >= limits.max_hypotheses {
            break;
        }
        let state = augment_state_with_bridges(&queued_state, bridges, model, limits.max_bridge_depth);
        let key = state_key(&state);
        if seen.contains(&key) {
            continue;
        }
        seen.insert(key);

        let facts: Vec<Value> = state.facts.values().cloned().collect();
        let terminal = match_objectives(&facts, model, objectives);
        for objective in &terminal {
            if state.steps.is_empty() {
                continue;
            }
            hypotheses.push(build_hypothesis(&state, objective, &binding, &denominator_digest, limits, &candidate_by_id));
            if hypotheses.len() >= limits.max_hypotheses {
                break;
            }
        }
        if state.steps.len() >= limits.max_hops {
            truncation_reasons.insert("max-hops".to_string());
            continue;
        }

        let mut expansions: Vec<(&Value, Vec<PreconditionMatch>)> = Vec::new();
        for candidate in &candidates {
            let candidate_id = candidate.get("id").and_then(Value::as_str).unwrap_or("");
            if state.used_candidates.contains(candidate_id) {
                continue;
            }
            if let Some(applicable) = candidate_applicability(candidate, &state) {
                expansions.push((candidate, applicable));
            }
        }
        expansions.sort_by(|a, b| {
            a.0.get("id")
                .and_then(Value::as_str)
                .unwrap_or("")
                .cmp(b.0.get("id").and_then(Value::as_str).unwrap_or(""))
        });
        if expansions.len() > limits.max_branching {
            truncation_reasons.insert("max-branching".to_string());
        }
        for (candidate, matches) in expansions.into_iter().take(limits.max_branching) {
            queue.push_back(apply_candidate(candidate, &state, &matches));
        }
    }

    if !queue.is_empty() {
        truncation_reasons.insert("max-hypotheses".to_string());
    }

    Ok(finalize_hypotheses(
        &binding,
        &denominator_digest,
        hypotheses,
        limits,
        truncation_reasons.into_iter().collect(),
        model,
        candidates_artifact,
        seen.len(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plan_with() -> Value {
        json!({
            "seal": {"digest": "sha256:plan"},
            "binding": {
                "repositoryRevision": "rev1",
                "dirtyPatchDigest": null,
                "blueprint": {"generationId": "gen1", "manifestDigest": "sha256:manifest"},
                "registryDigest": "sha256:registry",
            },
        })
    }

    fn model_with(initial_facts: Value, entities: Value) -> Value {
        let binding = binding_from_plan(&plan_with()).unwrap();
        json!({
            "schemaVersion": 1, "kind": "security-surface-model", "binding": binding,
            "denominatorDigest": "sha256:denom", "complete": true,
            "entities": entities, "relations": [], "initialFacts": initial_facts, "evidence": [],
            "coverage": {}, "coverageGaps": [],
        })
    }

    fn candidates_artifact(candidates: Value) -> Value {
        let binding = binding_from_plan(&plan_with()).unwrap();
        json!({
            "schemaVersion": 1, "kind": "security-candidates", "binding": binding,
            "denominatorDigest": "sha256:denom", "complete": true, "candidates": candidates,
        })
    }

    fn candidate(id: &str, preconditions: Value, effects: Value) -> Value {
        let binding = binding_from_plan(&plan_with()).unwrap();
        json!({
            "schemaVersion": 2, "kind": "security-candidate", "id": id,
            "provider": "security.test", "providerVersion": "1", "ruleId": "r", "candidateClass": "test",
            "claim": "test", "severityHint": "high", "sources": [], "sinks": [], "assets": [],
            "trustBoundaryCrossings": [], "preconditions": preconditions, "effects": effects, "chainRoles": [],
            "requiredControls": [], "observedControls": [], "evidenceRefs": ["ev1"],
            "binding": binding, "denominatorDigest": "sha256:denom",
            "verdict": "UNADJUDICATED", "adjudicationRequired": true,
        })
    }

    fn fact(kind: &str, extra: Value, evidence_refs: Value) -> Value {
        let mut base = json!({"kind": kind});
        for (k, v) in extra.as_object().unwrap() {
            base[k] = v.clone();
        }
        base["id"] = json!(format!("fact:{kind}:{}", digest(&base)));
        base["evidenceRefs"] = evidence_refs;
        base
    }

    fn objectives() -> Vec<Value> {
        vec![
            json!({"id": "objective.crown-jewel-access", "priority": "DIRECT_CROWN_JEWEL", "description": "crown jewel", "matches": {"assetKinds": ["crown-jewel"], "factKinds": ["data-access", "object-access", "code-execution", "principal-access"]}}),
            json!({"id": "objective.privilege-escalation", "priority": "PRIVILEGE_ESCALATION", "description": "priv", "matches": {"factKind": "principal-access", "scopePatterns": ["admin", "owner"]}}),
        ]
    }

    #[test]
    fn no_candidates_produces_zero_hypotheses_and_complete_true() {
        let plan = plan_with();
        let model = model_with(json!([]), json!([]));
        let result = synthesize_attack_paths(&plan, &model, &candidates_artifact(json!([])), &[], &objectives(), Limits::default()).unwrap();
        assert_eq!(result["hypotheses"].as_array().unwrap().len(), 0);
        assert_eq!(result["complete"], true);
    }

    #[test]
    fn direct_primitive_reaches_a_crown_jewel() {
        let plan = plan_with();
        let start = fact("object-access", json!({"subject": "actor:external", "action": "read", "object": "jewel-id", "scope": "cross-tenant"}), json!(["ev1"]));
        let model = model_with(json!([start]), json!([{"id": "jewel-id", "kind": "crown-jewel"}]));
        let attack = candidate(
            "c1",
            json!([{"kind": "object-access", "subject": "actor:external", "action": "read", "object": "jewel-id"}]),
            json!([{"kind": "data-access", "subject": "actor:external", "action": "read", "object": "jewel-id"}]),
        );
        let result = synthesize_attack_paths(&plan, &model, &candidates_artifact(json!([attack])), &[], &objectives(), Limits::default()).unwrap();
        let hyps = result["hypotheses"].as_array().unwrap();
        assert!(!hyps.is_empty());
        assert_eq!(hyps[0]["status"], "PROPOSED");
    }

    #[test]
    fn tenant_mismatch_never_satisfies_a_precondition() {
        let plan = plan_with();
        let start = fact("principal-access", json!({"subject": "actor:external", "action": "authenticate", "scope": "low", "tenant": "tenant-a"}), json!(["ev1"]));
        let model = model_with(json!([start]), json!([]));
        let attack = candidate(
            "c1",
            json!([{"kind": "principal-access", "subject": "actor:external", "action": "authenticate", "tenant": "tenant-b"}]),
            json!([{"kind": "principal-access", "subject": "actor:external", "action": "authenticate", "scope": "admin", "tenant": "tenant-b"}]),
        );
        let result = synthesize_attack_paths(&plan, &model, &candidates_artifact(json!([attack])), &[], &objectives(), Limits::default()).unwrap();
        assert_eq!(result["hypotheses"].as_array().unwrap().len(), 0);
    }

    #[test]
    fn environment_mismatch_never_satisfies_without_a_bridge() {
        let plan = plan_with();
        let start = fact("code-execution", json!({"subject": "actor:external", "action": "execute", "environment": "local-development"}), json!(["ev1"]));
        let model = model_with(json!([start]), json!([]));
        let attack = candidate(
            "c1",
            json!([{"kind": "code-execution", "subject": "actor:external", "action": "execute", "environment": "production"}]),
            json!([{"kind": "principal-access", "subject": "actor:external", "action": "act-as", "scope": "admin"}]),
        );
        let result = synthesize_attack_paths(&plan, &model, &candidates_artifact(json!([attack])), &[], &objectives(), Limits::default()).unwrap();
        assert_eq!(result["hypotheses"].as_array().unwrap().len(), 0);
    }

    #[test]
    fn no_hidden_transformation_without_a_bridge() {
        let plan = plan_with();
        let start = fact("knowledge", json!({"subject": "actor:external", "action": "possess", "object": "secret-material"}), json!(["ev1"]));
        let model = model_with(json!([start]), json!([]));
        let attack = candidate(
            "c1",
            json!([{"kind": "credential-possession", "subject": "actor:external", "action": "possess"}]),
            json!([{"kind": "principal-access", "subject": "actor:external", "action": "authenticate", "scope": "admin"}]),
        );
        let result = synthesize_attack_paths(&plan, &model, &candidates_artifact(json!([attack])), &[], &objectives(), Limits::default()).unwrap();
        assert_eq!(result["hypotheses"].as_array().unwrap().len(), 0);
    }

    #[test]
    fn cycle_prevention_mutually_producing_candidates_terminate() {
        let plan = plan_with();
        let start = fact("capability", json!({"subject": "actor:external", "action": "a"}), json!(["ev1"]));
        let model = model_with(json!([start]), json!([]));
        let a = candidate("a", json!([{"kind": "capability", "subject": "actor:external", "action": "a"}]), json!([{"kind": "capability", "subject": "actor:external", "action": "b"}]));
        let b = candidate("b", json!([{"kind": "capability", "subject": "actor:external", "action": "b"}]), json!([{"kind": "capability", "subject": "actor:external", "action": "a"}]));
        let result = synthesize_attack_paths(&plan, &model, &candidates_artifact(json!([a, b])), &[], &objectives(), Limits::default()).unwrap();
        assert!(result["hypotheses"].as_array().unwrap().len() < 1000);
    }

    #[test]
    fn hop_bound_truncates_and_reports_max_hops() {
        let plan = plan_with();
        let start = fact("capability", json!({"subject": "a", "action": "s0"}), json!(["ev1"]));
        let model = model_with(json!([start]), json!([]));
        let mut chain = Vec::new();
        for index in 0..5 {
            chain.push(candidate(
                &format!("c{index}"),
                json!([{"kind": "capability", "subject": "a", "action": format!("s{index}")}]),
                json!([{"kind": "capability", "subject": "a", "action": format!("s{}", index + 1)}]),
            ));
        }
        let limits = Limits { max_hops: 2, ..Limits::default() };
        let result = synthesize_attack_paths(&plan, &model, &candidates_artifact(json!(chain)), &[], &objectives(), limits).unwrap();
        let has_gap = result["coverageGaps"]
            .as_array()
            .unwrap()
            .iter()
            .any(|g| g["kind"] == "attack-path-search-truncated" && g["reason"] == "max-hops");
        assert!(has_gap);
        assert_eq!(result["complete"], false);
    }

    #[test]
    fn no_numeric_score_exists_in_the_artifact() {
        let plan = plan_with();
        let start = fact("object-access", json!({"subject": "a", "action": "read", "object": "jewel-id", "scope": "cross-tenant"}), json!(["ev1"]));
        let model = model_with(json!([start]), json!([{"id": "jewel-id", "kind": "crown-jewel"}]));
        let attack = candidate("c1", json!([{"kind": "object-access", "subject": "a", "action": "read", "object": "jewel-id"}]), json!([{"kind": "data-access", "subject": "a", "action": "read", "object": "jewel-id"}]));
        let result = synthesize_attack_paths(&plan, &model, &candidates_artifact(json!([attack])), &[], &objectives(), Limits::default()).unwrap();
        let text = serde_json::to_string(&result).unwrap();
        assert!(!text.contains("riskScore"));
        assert!(!text.contains("criticalPathScore"));
    }

    #[test]
    fn binding_mismatch_is_rejected() {
        let plan = plan_with();
        let model = model_with(json!([]), json!([]));
        let mut wrong = candidates_artifact(json!([]));
        wrong["binding"]["repositoryRevision"] = json!("other");
        let err = synthesize_attack_paths(&plan, &model, &wrong, &[], &objectives(), Limits::default()).unwrap_err();
        assert!(err.0.contains("does not match"));
    }

    #[test]
    fn fact_matches_is_exact_and_wildcard_aware() {
        assert!(fact_matches(&json!({"kind": "capability", "subject": "*"}), &json!({"kind": "capability", "subject": "x"})));
        assert!(!fact_matches(&json!({"kind": "capability", "subject": "*"}), &json!({"kind": "capability", "subject": null})));
        assert!(!fact_matches(&json!({"kind": "capability", "tenant": "a"}), &json!({"kind": "capability", "tenant": "b"})));
        assert!(fact_matches(&json!({"kind": "capability"}), &json!({"kind": "capability", "subject": "x"})));
    }

    #[test]
    fn canonical_fact_key_is_deterministic() {
        let a = fact("capability", json!({"subject": "x", "action": "y"}), json!([]));
        let b = json!({"kind": "capability", "action": "y", "subject": "x"});
        assert_eq!(canonical_fact_key(&a), canonical_fact_key(&b));
    }
}
