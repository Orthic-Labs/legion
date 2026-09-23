//! Port of `src/providers/security/candidate-engine.mjs`.
//!
//! Security candidate v2 engine per Security Appendix Phase 3. A candidate
//! is an allegation about a security primitive — never a vulnerability,
//! never carrying a final severity or evidence verdict.
//!
//! `runSecurityPack` takes a `pack` object with an `analyze(context)`
//! function and a `readFile` closure the pack context exposes; JS packs are
//! arbitrary plugin code loaded elsewhere in the tree, outside this chunk's
//! owned files. This port models `pack.analyze` as a Rust closure
//! (`Fn(&PackContext<'_>) -> Vec<Value>`) rather than porting any actual pack,
//! preserving the same context-building/candidate-materialization
//! behaviour around it.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::{json, Value};

use super::contracts::{
    assert_artifact_binding, binding_from_plan, require_array, require_object, require_string,
    stable_id, Result, SecurityContractError as Error,
};

const SEVERITY_HINTS: &[&str] = &["critical", "high", "medium", "low", "info"];
const CHAIN_ROLES: &[&str] = &[
    "starter",
    "enabler",
    "pivot",
    "privilege-escalation",
    "control-bypass",
    "impact",
];
const FACT_KINDS: &[&str] = &[
    "attacker-position",
    "knowledge",
    "capability",
    "credential-possession",
    "principal-access",
    "network-reachability",
    "data-access",
    "object-access",
    "code-execution",
    "workflow-state",
    "control-bypass",
    "persistence",
    "availability-impact",
    "integrity-impact",
    "confidentiality-impact",
];

fn unique_sorted_strings(value: Option<&Value>) -> Vec<String> {
    let mut set: BTreeSet<String> = BTreeSet::new();
    if let Some(Value::Array(items)) = value {
        for item in items {
            if let Some(s) = item.as_str() {
                set.insert(s.to_string());
            }
        }
    }
    set.into_iter().collect()
}

fn validate_fact_pattern(pattern: &Value, label: &str) -> Result<Value> {
    let object = require_object(pattern, label)?;
    let kind = object
        .get("kind")
        .and_then(Value::as_str)
        .ok_or_else(|| Error::new(format!("{label}.kind is unsupported: null")))?;
    if !FACT_KINDS.contains(&kind) {
        return Err(Error::new(format!("{label}.kind is unsupported: {kind}")));
    }
    Ok(json!({
        "kind": kind,
        "subject": object.get("subject").cloned().unwrap_or(Value::Null),
        "action": object.get("action").cloned().unwrap_or(Value::Null),
        "object": object.get("object").cloned().unwrap_or(Value::Null),
        "scope": object.get("scope").cloned().unwrap_or(Value::Null),
        "environment": object.get("environment").cloned().unwrap_or(Value::Null),
        "tenant": object.get("tenant").cloned().unwrap_or(Value::Null),
        "attributes": object.get("attributes").cloned().unwrap_or_else(|| json!({})),
    }))
}

/// Whether any of `kind/subject/action/object/scope/environment/tenant`
/// equals the literal string `"*"` — JS `Object.values(base).includes('*')`.
/// `attributes` (an object) is excluded, matching JS `Object.values` on the
/// 7 scalar-only fields the JS spread produces for `base`.
fn has_wildcard_scalar(fact: &Value) -> bool {
    ["kind", "subject", "action", "object", "scope", "environment", "tenant"]
        .iter()
        .any(|key| fact.get(*key).and_then(Value::as_str) == Some("*"))
}

fn concrete_fact(raw: &Value, candidate_namespace: &str) -> Result<Value> {
    let base = validate_fact_pattern(raw, "effect")?;
    if has_wildcard_scalar(&base) {
        return Err(Error::new(
            "candidate effects must be concrete; wildcard is only valid in preconditions",
        ));
    }
    let id = raw
        .get("id")
        .and_then(Value::as_str)
        .map(str::to_string)
        .unwrap_or_else(|| stable_id(&format!("{candidate_namespace}:effect"), &base));
    let mut out = base.as_object().cloned().unwrap();
    out.insert("id".to_string(), json!(id));
    out.insert(
        "evidenceRefs".to_string(),
        json!(unique_sorted_strings(raw.get("evidenceRefs"))),
    );
    Ok(Value::Object(out))
}

fn assert_model_references(model: &Value, ids: &[String], label: &str) -> Result<()> {
    let known: BTreeSet<&str> = model
        .get("entities")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|item| item.get("id").and_then(Value::as_str))
        .collect();
    for id in ids {
        if !known.contains(id.as_str()) {
            return Err(Error::new(format!(
                "{label} references unknown security-model entity {id}"
            )));
        }
    }
    Ok(())
}

/// Faithful port of `createSecurityCandidateV2`.
pub fn create_security_candidate_v2(
    plan: &Value,
    model: &Value,
    provider: &str,
    provider_version: &str,
    denominator_digest: &str,
    observation: &Value,
) -> Result<Value> {
    let binding = binding_from_plan(plan)?;
    assert_artifact_binding(model, &binding, "security model")?;
    require_object(observation, "observation")?;
    require_string(&json!(provider), "provider")?;
    require_string(&json!(provider_version), "providerVersion")?;
    require_string(&json!(denominator_digest), "denominatorDigest")?;
    require_string(&observation["ruleId"], "observation.ruleId")?;
    require_string(&observation["candidateClass"], "observation.candidateClass")?;
    require_string(&observation["claim"], "observation.claim")?;
    let severity_hint = observation
        .get("severityHint")
        .and_then(Value::as_str)
        .unwrap_or("");
    if !SEVERITY_HINTS.contains(&severity_hint) {
        return Err(Error::new(format!("invalid severity hint {severity_hint}")));
    }

    let sources = unique_sorted_strings(observation.get("sources"));
    let sinks = unique_sorted_strings(observation.get("sinks"));
    let assets = unique_sorted_strings(observation.get("assets"));
    let boundaries = unique_sorted_strings(observation.get("trustBoundaryCrossings"));
    let controls = unique_sorted_strings(observation.get("requiredControls"));
    let observed_controls = unique_sorted_strings(observation.get("observedControls"));
    assert_model_references(model, &sources, "sources")?;
    assert_model_references(model, &sinks, "sinks")?;
    assert_model_references(model, &assets, "assets")?;
    assert_model_references(model, &boundaries, "trustBoundaryCrossings")?;
    assert_model_references(model, &controls, "requiredControls")?;
    assert_model_references(model, &observed_controls, "observedControls")?;

    let preconditions_raw = observation.get("preconditions").cloned().unwrap_or(json!([]));
    let preconditions_arr = require_array(&preconditions_raw, "preconditions")?;
    let mut preconditions = Vec::with_capacity(preconditions_arr.len());
    for (index, item) in preconditions_arr.iter().enumerate() {
        preconditions.push(validate_fact_pattern(item, &format!("preconditions[{index}]"))?);
    }

    let rule_id = observation["ruleId"].as_str().unwrap();
    let namespace = format!("{provider}:{rule_id}");
    let effects_raw = observation.get("effects").cloned().unwrap_or(json!([]));
    let effects_arr = require_array(&effects_raw, "effects")?;
    let mut effects = Vec::with_capacity(effects_arr.len());
    for item in effects_arr {
        effects.push(concrete_fact(item, &namespace)?);
    }
    if effects.is_empty() {
        return Err(Error::new("security candidate must declare at least one effect"));
    }

    let chain_roles = unique_sorted_strings(observation.get("chainRoles"));
    for role in &chain_roles {
        if !CHAIN_ROLES.contains(&role.as_str()) {
            return Err(Error::new(format!("unsupported chain role {role}")));
        }
    }

    let evidence_refs = unique_sorted_strings(observation.get("evidenceRefs"));
    let effect_ids: Vec<String> = effects
        .iter()
        .map(|e| e["id"].as_str().unwrap().to_string())
        .collect();

    let identity = json!({
        "provider": provider,
        "providerVersion": provider_version,
        "ruleId": rule_id,
        "sources": sources,
        "sinks": sinks,
        "evidenceRefs": evidence_refs,
        "effects": effect_ids,
    });

    Ok(json!({
        "schemaVersion": 2,
        "kind": "security-candidate",
        "id": stable_id("security-candidate-v2", &identity),
        "provider": provider,
        "providerVersion": provider_version,
        "ruleId": rule_id,
        "candidateClass": observation["candidateClass"],
        "claim": observation["claim"],
        "severityHint": severity_hint,
        "sources": sources,
        "sinks": sinks,
        "attackerCapabilities": unique_sorted_strings(observation.get("attackerCapabilities")),
        "preconditions": preconditions,
        "effects": effects,
        "assets": assets,
        "trustBoundaryCrossings": boundaries,
        "requiredControls": controls,
        "observedControls": observed_controls,
        "chainRoles": chain_roles,
        "evidenceRefs": evidence_refs,
        "detectorMetadata": observation.get("detectorMetadata").cloned().unwrap_or_else(|| json!({})),
        "uncertainty": unique_sorted_strings(observation.get("uncertainty")),
        "binding": binding,
        "denominatorDigest": denominator_digest,
        "verdict": "UNADJUDICATED",
        "adjudicationRequired": true,
    }))
}

/// Faithful port of `validateSecurityCandidateV2`.
pub fn validate_security_candidate_v2(
    candidate: &Value,
    plan_and_model: Option<(&Value, &Value)>,
) -> Result<bool> {
    require_object(candidate, "candidate")?;
    let schema_version = candidate.get("schemaVersion").and_then(Value::as_i64);
    if schema_version != Some(2) {
        let got = candidate
            .get("schemaVersion")
            .map(|v| v.to_string())
            .unwrap_or_else(|| "undefined".to_string());
        return Err(Error::new(format!("candidate schemaVersion must be 2; got {got}")));
    }
    let verdict = candidate.get("verdict").and_then(Value::as_str).unwrap_or("");
    if verdict != "UNADJUDICATED" {
        return Err(Error::new(format!(
            "candidate verdict must be UNADJUDICATED; got {verdict}"
        )));
    }
    if candidate.get("adjudicationRequired").and_then(Value::as_bool) != Some(true) {
        return Err(Error::new("candidate must require adjudication"));
    }
    if candidate.get("severity").is_some() {
        return Err(Error::new("candidate must not carry a final severity"));
    }
    if candidate.get("evidenceStrength").is_some() {
        return Err(Error::new("candidate must not carry a final evidence verdict"));
    }
    let effects = candidate.get("effects").and_then(Value::as_array).cloned().unwrap_or_default();
    if effects.is_empty() {
        return Err(Error::new("candidate must declare at least one effect"));
    }
    let evidence_refs = candidate
        .get("evidenceRefs")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    if evidence_refs.is_empty() {
        return Err(Error::new("candidate must declare evidence refs"));
    }
    for effect in &effects {
        if has_wildcard_scalar(effect) {
            return Err(Error::new("candidate effects must be concrete"));
        }
    }
    if let Some((plan, model)) = plan_and_model {
        let binding = binding_from_plan(plan)?;
        let _ = model;
        assert_artifact_binding(candidate, &binding, "security candidate")?;
    }
    Ok(true)
}

/// A security pack's `analyze` behaviour, standing in for the arbitrary JS
/// `pack.analyze(context)` plugin function. Returns raw observations, as
/// the JS pack does.
pub trait SecurityPack {
    fn id(&self) -> &str;
    fn version(&self) -> &str;
    fn rule_ids(&self) -> Vec<String> {
        Vec::new()
    }
    fn analyze(&self, context: &PackContext<'_>) -> Vec<Value>;
}

/// Faithful port of the `context` object built and passed to `pack.analyze`.
pub struct PackContext<'a> {
    pub root: &'a Value,
    pub plan: &'a Value,
    pub projection: &'a Value,
    pub model: &'a Value,
    pub files: Vec<String>,
    pub denominator_digest: &'a str,
    pub provider_id: &'a str,
    pub provider_version: &'a str,
    allowed: BTreeSet<String>,
    evidence_by_id: BTreeMap<String, Value>,
    entity_by_id: BTreeMap<String, Value>,
    relations_from: BTreeMap<String, Vec<Value>>,
    relations_to: BTreeMap<String, Vec<Value>>,
}

impl<'a> PackContext<'a> {
    pub fn evidence_by_id(&self, id: &str) -> Option<&Value> {
        self.evidence_by_id.get(id)
    }
    pub fn entity_by_id(&self, id: &str) -> Option<&Value> {
        self.entity_by_id.get(id)
    }
    pub fn relations_from(&self, id: &str) -> &[Value] {
        self.relations_from.get(id).map(Vec::as_slice).unwrap_or(&[])
    }
    pub fn relations_to(&self, id: &str) -> &[Value] {
        self.relations_to.get(id).map(Vec::as_slice).unwrap_or(&[])
    }
    /// Faithful port of `readFile`: throws (returns `Err`) on an
    /// out-of-denominator path.
    pub fn read_file(&self, path: &str) -> Result<Option<String>> {
        if !self.allowed.contains(path) {
            return Err(Error::new(format!("pack attempted to read out-of-denominator path {path}")));
        }
        Ok(self
            .projection
            .get("sourceText")
            .and_then(|source_text| source_text.get(path))
            .and_then(Value::as_str)
            .map(str::to_string))
    }
}

/// Faithful port of `runSecurityPack`.
pub fn run_security_pack(
    pack: &dyn SecurityPack,
    root: &Value,
    plan: &Value,
    projection: &Value,
    model: &Value,
    provider_plan: &Value,
) -> Result<Value> {
    let path_digest = provider_plan
        .pointer("/denominator/pathDigest")
        .and_then(Value::as_str)
        .ok_or_else(|| Error::new(format!("provider {} has no frozen denominator", pack.id())))?;

    let denominator_paths: Vec<String> = provider_plan
        .pointer("/denominator/paths")
        .and_then(Value::as_array)
        .map(|items| items.iter().filter_map(|v| v.as_str().map(str::to_string)).collect())
        .unwrap_or_else(|| {
            projection
                .get("files")
                .and_then(Value::as_array)
                .map(|items| items.iter().filter_map(|v| v.as_str().map(str::to_string)).collect())
                .unwrap_or_default()
        });
    let allowed: BTreeSet<String> = denominator_paths.into_iter().collect();

    let evidence_by_id: BTreeMap<String, Value> = model
        .get("evidence")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|item| item.get("id").and_then(Value::as_str).map(|id| (id.to_string(), item.clone())))
        .collect();
    let entity_by_id: BTreeMap<String, Value> = model
        .get("entities")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|item| item.get("id").and_then(Value::as_str).map(|id| (id.to_string(), item.clone())))
        .collect();

    let mut relations_from: BTreeMap<String, Vec<Value>> = BTreeMap::new();
    let mut relations_to: BTreeMap<String, Vec<Value>> = BTreeMap::new();
    for relation in model.get("relations").and_then(Value::as_array).into_iter().flatten() {
        if let Some(from) = relation.get("from").and_then(Value::as_str) {
            relations_from.entry(from.to_string()).or_default().push(relation.clone());
        }
        if let Some(to) = relation.get("to").and_then(Value::as_str) {
            relations_to.entry(to.to_string()).or_default().push(relation.clone());
        }
    }

    let mut files: Vec<String> = allowed.iter().cloned().collect();
    files.sort();

    let context = PackContext {
        root,
        plan,
        projection,
        model,
        files: files.clone(),
        denominator_digest: path_digest,
        provider_id: pack.id(),
        provider_version: pack.version(),
        allowed,
        evidence_by_id,
        entity_by_id,
        relations_from,
        relations_to,
    };

    let observations = pack.analyze(&context);
    let mut candidates = Vec::with_capacity(observations.len());
    for observation in &observations {
        candidates.push(create_security_candidate_v2(
            plan,
            model,
            pack.id(),
            pack.version(),
            path_digest,
            observation,
        )?);
    }

    let examined = context.files.len() as i64;
    Ok(json!({
        "schemaVersion": 1,
        "provider": pack.id(),
        "applicable": true,
        "required": provider_plan.pointer("/benchmark/requiredForCleanClaim").cloned().unwrap_or(json!(true)),
        "status": if candidates.is_empty() { "pass" } else { "candidates" },
        "complete": true,
        "coverage": {
            "denominatorDigest": path_digest,
            "expected": provider_plan.pointer("/denominator/pathCount").cloned().unwrap_or(Value::Null),
            "examined": examined,
            "unexamined": [],
            "rules": pack.rule_ids(),
        },
        "candidates": candidates,
        "findings": [],
        "coverageGaps": [],
        "degradation": [],
        "artifacts": [],
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    const BINDING_JSON: &str = r#"{
        "planDigest": "sha256:plan", "repositoryRevision": "rev1", "dirtyPatchDigest": null,
        "blueprintGenerationId": "gen1", "blueprintManifestDigest": "sha256:manifest", "registryDigest": "sha256:registry"
    }"#;

    fn binding() -> Value {
        serde_json::from_str(BINDING_JSON).unwrap()
    }

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

    fn model_with(entities: Value) -> Value {
        json!({
            "schemaVersion": 1, "kind": "security-surface-model", "binding": binding(),
            "denominatorDigest": "sha256:denom", "complete": true,
            "entities": entities, "relations": [], "initialFacts": [], "evidence": [],
            "coverage": {}, "coverageGaps": [],
        })
    }

    fn observation() -> Value {
        json!({
            "ruleId": "r1",
            "candidateClass": "test",
            "claim": "a claim",
            "severityHint": "high",
            "preconditions": [{"kind": "capability", "subject": "actor:x"}],
            "effects": [{"kind": "capability", "subject": "actor:x", "action": "b"}],
            "evidenceRefs": ["ev1"],
        })
    }

    #[test]
    fn creates_candidate_with_stable_id() {
        let plan = plan_with();
        let model = model_with(json!([]));
        let out = create_security_candidate_v2(&plan, &model, "prov", "1", "sha256:denom", &observation()).unwrap();
        assert_eq!(out["schemaVersion"], 2);
        assert_eq!(out["verdict"], "UNADJUDICATED");
        assert_eq!(out["adjudicationRequired"], true);
        assert!(out["id"].as_str().unwrap().starts_with("sha256:"));

        let again = create_security_candidate_v2(&plan, &model, "prov", "1", "sha256:denom", &observation()).unwrap();
        assert_eq!(out["id"], again["id"]);
    }

    #[test]
    fn invalid_severity_hint_is_rejected() {
        let plan = plan_with();
        let model = model_with(json!([]));
        let mut obs = observation();
        obs["severityHint"] = json!("not-a-severity");
        let err = create_security_candidate_v2(&plan, &model, "prov", "1", "sha256:denom", &obs).unwrap_err();
        assert!(err.0.contains("invalid severity hint"));
    }

    #[test]
    fn no_effects_is_rejected() {
        let plan = plan_with();
        let model = model_with(json!([]));
        let mut obs = observation();
        obs["effects"] = json!([]);
        let err = create_security_candidate_v2(&plan, &model, "prov", "1", "sha256:denom", &obs).unwrap_err();
        assert!(err.0.contains("at least one effect"));
    }

    #[test]
    fn unknown_entity_reference_is_rejected() {
        let plan = plan_with();
        let model = model_with(json!([]));
        let mut obs = observation();
        obs["sources"] = json!(["unknown-entity"]);
        let err = create_security_candidate_v2(&plan, &model, "prov", "1", "sha256:denom", &obs).unwrap_err();
        assert!(err.0.contains("references unknown security-model entity"));
    }

    #[test]
    fn known_entity_reference_passes() {
        let plan = plan_with();
        let model = model_with(json!([{"id": "asset-1", "kind": "asset"}]));
        let mut obs = observation();
        obs["sources"] = json!(["asset-1"]);
        assert!(create_security_candidate_v2(&plan, &model, "prov", "1", "sha256:denom", &obs).is_ok());
    }

    #[test]
    fn unsupported_chain_role_is_rejected() {
        let plan = plan_with();
        let model = model_with(json!([]));
        let mut obs = observation();
        obs["chainRoles"] = json!(["not-a-role"]);
        let err = create_security_candidate_v2(&plan, &model, "prov", "1", "sha256:denom", &obs).unwrap_err();
        assert!(err.0.contains("unsupported chain role"));
    }

    #[test]
    fn validate_accepts_well_formed_candidate() {
        let plan = plan_with();
        let model = model_with(json!([]));
        let candidate = create_security_candidate_v2(&plan, &model, "prov", "1", "sha256:denom", &observation()).unwrap();
        assert!(validate_security_candidate_v2(&candidate, Some((&plan, &model))).unwrap());
    }

    #[test]
    fn validate_rejects_final_severity() {
        let plan = plan_with();
        let model = model_with(json!([]));
        let mut candidate = create_security_candidate_v2(&plan, &model, "prov", "1", "sha256:denom", &observation()).unwrap();
        candidate["severity"] = json!("high");
        let err = validate_security_candidate_v2(&candidate, None).unwrap_err();
        assert!(err.0.contains("must not carry a final severity"));
    }

    #[test]
    fn validate_rejects_no_evidence_refs() {
        let plan = plan_with();
        let model = model_with(json!([]));
        let mut candidate = create_security_candidate_v2(&plan, &model, "prov", "1", "sha256:denom", &observation()).unwrap();
        candidate["evidenceRefs"] = json!([]);
        let err = validate_security_candidate_v2(&candidate, None).unwrap_err();
        assert!(err.0.contains("must declare evidence refs"));
    }

    struct NoopPack;
    impl SecurityPack for NoopPack {
        fn id(&self) -> &str {
            "test.pack"
        }
        fn version(&self) -> &str {
            "1"
        }
        fn analyze(&self, _context: &PackContext<'_>) -> Vec<Value> {
            Vec::new()
        }
    }

    struct FindingPack;
    impl SecurityPack for FindingPack {
        fn id(&self) -> &str {
            "test.pack"
        }
        fn version(&self) -> &str {
            "1"
        }
        fn analyze(&self, _context: &PackContext<'_>) -> Vec<Value> {
            vec![observation()]
        }
    }

    #[test]
    fn run_security_pack_requires_frozen_denominator() {
        let plan = plan_with();
        let model = model_with(json!([]));
        let err = run_security_pack(&NoopPack, &json!({}), &plan, &json!({}), &model, &json!({})).unwrap_err();
        assert!(err.0.contains("has no frozen denominator"));
    }

    #[test]
    fn run_security_pack_pass_with_no_candidates() {
        let plan = plan_with();
        let model = model_with(json!([]));
        let provider_plan = json!({"denominator": {"pathDigest": "sha256:denom", "paths": ["a.js"]}});
        let out = run_security_pack(&NoopPack, &json!({}), &plan, &json!({"files": []}), &model, &provider_plan).unwrap();
        assert_eq!(out["status"], "pass");
        assert_eq!(out["candidates"].as_array().unwrap().len(), 0);
    }

    #[test]
    fn run_security_pack_produces_candidates() {
        let plan = plan_with();
        let model = model_with(json!([]));
        let provider_plan = json!({"denominator": {"pathDigest": "sha256:denom", "paths": ["a.js"]}});
        let out = run_security_pack(&FindingPack, &json!({}), &plan, &json!({"files": []}), &model, &provider_plan).unwrap();
        assert_eq!(out["status"], "candidates");
        assert_eq!(out["candidates"].as_array().unwrap().len(), 1);
    }
}
