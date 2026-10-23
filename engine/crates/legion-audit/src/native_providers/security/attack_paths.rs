//! `security.attack-path-synthesis`: deterministic, bounded composition of
//! security-candidate effects into precondition chains.
//!
//! Design rule: a detector proposes, this provider proposes *compositions*,
//! only independent adjudication establishes, only evidence synthesis
//! publishes. Nothing here produces a finding, a verdict, or a "proven"
//! state. Every hypothesis is `status: "hypothesis"`, and any bound that cut the
//! search is reported as a coverage gap. A missing model, an invalid bound,
//! or zero usable candidates is an explicit `UNPROVEN` document, never "no
//! paths".
//!
//! # Final JSON contract (surface model -> candidates -> synthesis -> adjudication)
//!
//! * Model (`security.surface-model`, `legion-security-model`): `entities[]`
//!   (`id`, `kind` = entrypoint | asset | crown-jewel | ..., `name`,
//!   `evidenceRefs`), `relations[]` (`id`, `kind`, `from`/`to` = entity ids),
//!   `evidence[]` (`id`, `path`), `gaps[]` (`blocking`), `coverage.complete`.
//!   The hand-written `entrypoints`/`assets`/`relations` shape is still read.
//!   Every entity is indexed under three aliases (entity id, entity name,
//!   cited evidence paths); a candidate `sources`/`sinks`/`assets`/entrypoint
//!   string matching any alias of an entity (or of a relation endpoint) binds
//!   to it. A model with blocking gaps or `coverage.complete != true` adds the
//!   `security-model-incomplete` gap (coverage becomes TRUNCATED).
//! * Candidates (v2): `effects`/`preconditions` are `{kind, action, scope}`
//!   objects or `kind:action[:scope]` strings (the shape
//!   `SecurityCandidateV2` serializes). A candidate without effects can never
//!   compose. When no candidate carries effects the document reports the
//!   distinct gap `no-composable-candidates` (UNPROVEN); effects without any
//!   starter report `no-starter-candidates`; effects and starters without a
//!   composable pair still report any untyped candidates as `untyped-candidates-excluded`.
//! * Hypotheses (`attack-path-hypotheses`): each carries `id`,
//!   `memberCandidateIds`, `steps[].candidateId`, `joins[{id,from,to,bridge}]`
//!   (one per edge), `controls[]`, and, once `bind_hypotheses` ran, `binding`
//!   (`{repositoryRevision, digest}` of the frozen inventory), `provider` and
//!   `synthesisContextId`: exactly the fields `chain_adjudication` reads.
//!
//! Inputs are plain JSON values:
//! - security model (`security-model.json`): `entrypoints`, `assets`
//!   (`kind` may be `crown-jewel`), `relations` (`kind`, `from`, `to`).
//! - security candidates v2: a list (or `{ "candidates": [...] }`) whose items
//!   carry `id`, `effects`, `preconditions`, `chainRoles`, `sources`, `sinks`,
//!   `assets`. A fact is either `{kind, action, scope?, subject?, object?,
//!   environment?, tenant?}` or the string form `kind:action[:scope]`.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::{json, Map, Value};

use super::common::digest_json;

pub const PROVIDER_ID: &str = "security.attack-path-synthesis";
pub const ARTIFACT_KIND: &str = "attack-path-hypotheses";

/// Registry entry root should add to `src/registry/providers.json`.
pub const REGISTRY_ENTRY_NOTE: &str =
    "security.attack-path-synthesis: role deterministic, phase runtime, runtime-script, consumes security-model + security-candidates, produces attack-path-hypotheses (registered in src/registry/providers.json)";

const OBJECTIVES_JSON: &str = include_str!("../../../../../../src/registry/attack-objectives.json");
const BRIDGES_JSON: &str = include_str!("../../../../../../src/registry/attack-path-bridges.json");

const HARD_MAX_HOPS: usize = 16;
const FIELD_KEYS: [&str; 4] = ["subject", "object", "environment", "tenant"];

/// Frozen synthesis limits (SEC 10.2). All inputs; none adaptive.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bounds {
    pub max_hops: usize,
    pub max_branching: usize,
    pub max_per_objective: usize,
    pub max_hypotheses: usize,
    pub max_visited_paths: usize,
}

impl Default for Bounds {
    fn default() -> Self {
        Self {
            max_hops: 6,
            max_branching: 12,
            max_per_objective: 20,
            max_hypotheses: 100,
            max_visited_paths: 200_000,
        }
    }
}

impl Bounds {
    fn valid(&self) -> bool {
        (1..=HARD_MAX_HOPS).contains(&self.max_hops)
            && self.max_branching > 0
            && self.max_per_objective > 0
            && self.max_hypotheses > 0
            && self.max_visited_paths > 0
    }

    fn to_json(&self) -> Value {
        json!({
            "maxHops": self.max_hops,
            "maxBranching": self.max_branching,
            "maxPerObjective": self.max_per_objective,
            "maxHypotheses": self.max_hypotheses,
            "maxVisitedPaths": self.max_visited_paths,
        })
    }
}

#[derive(Debug, Clone)]
struct Objective {
    id: String,
    priority: String,
    matches: Value,
}

#[derive(Debug, Clone)]
struct Bridge {
    id: String,
    from: Value,
    to: Value,
    requires_relation: Option<String>,
    strength: Strength,
    relation: String,
}

#[derive(Debug, Clone)]
struct Template {
    id: String,
    step_kinds: Vec<String>,
}

/// Canonical objectives, priority order, bridges and templates (registry data).
#[derive(Debug, Clone)]
pub struct Registry {
    priority_order: Vec<String>,
    objectives: Vec<Objective>,
    bridges: Vec<Bridge>,
    templates: Vec<Template>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Strength {
    Possible,
    StrongInference,
    Verified,
}

impl Strength {
    fn parse(value: &str) -> Option<Self> {
        match value {
            "possible" => Some(Self::Possible),
            "strong-inference" => Some(Self::StrongInference),
            "verified" => Some(Self::Verified),
            _ => None,
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Possible => "possible",
            Self::StrongInference => "strong-inference",
            Self::Verified => "verified",
        }
    }
}

impl Registry {
    /// Registry compiled from the packaged `src/registry` data.
    pub fn embedded() -> Result<Self, String> {
        let objectives: Value = serde_json::from_str(OBJECTIVES_JSON).map_err(|e| e.to_string())?;
        let bridges: Value = serde_json::from_str(BRIDGES_JSON).map_err(|e| e.to_string())?;
        Self::from_values(&objectives, &bridges)
    }

    pub fn from_values(objectives: &Value, bridges: &Value) -> Result<Self, String> {
        let priority_order: Vec<String> = objectives["priorityOrder"]
            .as_array()
            .ok_or("objective registry lacks priorityOrder")?
            .iter()
            .filter_map(|v| v.as_str().map(ToOwned::to_owned))
            .collect();
        let mut objs = Vec::new();
        for item in objectives["objectives"]
            .as_array()
            .ok_or("objectives missing")?
        {
            let id = text(item, "id").ok_or("objective without id")?;
            let priority = text(item, "priority").ok_or("objective without priority")?;
            if !priority_order.contains(&priority) {
                return Err(format!("objective {id} has unknown priority {priority}"));
            }
            objs.push(Objective {
                id,
                priority,
                matches: item.get("matches").cloned().unwrap_or(Value::Null),
            });
        }
        let mut brs = Vec::new();
        for item in bridges["bridges"].as_array().ok_or("bridges missing")? {
            let id = text(item, "id").ok_or("bridge without id")?;
            let strength = text(item, "evidenceStrength")
                .and_then(|s| Strength::parse(&s))
                .ok_or_else(|| format!("bridge {id} has invalid evidenceStrength"))?;
            brs.push(Bridge {
                id,
                from: item.get("from").cloned().unwrap_or(Value::Null),
                to: item.get("to").cloned().unwrap_or(Value::Null),
                requires_relation: text(item, "requiresModelRelation"),
                strength,
                relation: text(item, "relation").unwrap_or_default(),
            });
        }
        let templates = bridges["templates"]
            .as_array()
            .map(|list| {
                list.iter()
                    .filter_map(|item| {
                        Some(Template {
                            id: text(item, "id")?,
                            step_kinds: ordered_strings(item.get("stepKinds")),
                        })
                    })
                    .collect()
            })
            .unwrap_or_default();
        Ok(Self {
            priority_order,
            objectives: objs,
            bridges: brs,
            templates,
        })
    }

    fn rank(&self, priority: &str) -> usize {
        self.priority_order
            .iter()
            .position(|p| p == priority)
            .unwrap_or(usize::MAX)
    }
}

fn text(value: &Value, key: &str) -> Option<String> {
    value
        .get(key)
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
}

fn strings(value: Option<&Value>) -> Vec<String> {
    let mut out: Vec<String> = value
        .and_then(Value::as_array)
        .map(|list| {
            list.iter()
                .filter_map(|v| v.as_str().map(ToOwned::to_owned))
                .collect()
        })
        .unwrap_or_default();
    out.sort();
    out.dedup();
    out
}

/// Order-preserving list read. Template `stepKinds` are ordered chains, so they
/// must not be sorted or deduplicated the way set-valued fields are.
fn ordered_strings(value: Option<&Value>) -> Vec<String> {
    value
        .and_then(Value::as_array)
        .map(|list| {
            list.iter()
                .filter_map(|v| v.as_str().map(ToOwned::to_owned))
                .collect()
        })
        .unwrap_or_default()
}

#[derive(Debug, Clone)]
struct Fact {
    kind: String,
    action: String,
    scope: Option<String>,
    fields: BTreeMap<String, String>,
    raw: Value,
}

fn parse_fact(value: &Value) -> Option<Fact> {
    if let Some(s) = value.as_str() {
        let mut parts = s.splitn(3, ':');
        let kind = parts.next().filter(|k| !k.is_empty())?.to_owned();
        let action = parts.next().unwrap_or_default().to_owned();
        let scope = parts.next().map(ToOwned::to_owned);
        return Some(Fact {
            kind,
            action,
            scope,
            fields: BTreeMap::new(),
            raw: value.clone(),
        });
    }
    let kind = text(value, "kind")?;
    let mut fields = BTreeMap::new();
    for key in FIELD_KEYS {
        if let Some(v) = text(value, key) {
            fields.insert(key.to_owned(), v);
        }
    }
    Some(Fact {
        kind,
        action: text(value, "action").unwrap_or_default(),
        scope: text(value, "scope"),
        fields,
        raw: value.clone(),
    })
}

fn parse_facts(value: Option<&Value>) -> Vec<Fact> {
    value
        .and_then(Value::as_array)
        .map(|list| list.iter().filter_map(parse_fact).collect())
        .unwrap_or_default()
}

#[derive(Debug, Clone)]
struct Candidate {
    id: String,
    rule_id: String,
    effects: Vec<Fact>,
    preconditions: Vec<Fact>,
    roles: BTreeSet<String>,
    sources: Vec<String>,
    sinks: Vec<String>,
    assets: Vec<String>,
    capabilities: Vec<String>,
    required_controls: Vec<String>,
    observed_controls: Vec<String>,
    uncertainty: Vec<String>,
    evidence_refs: Vec<String>,
}

impl Candidate {
    fn parse(value: &Value) -> Option<Self> {
        let id = text(value, "id")?;
        if id.is_empty() {
            return None;
        }
        Some(Self {
            id,
            rule_id: text(value, "ruleId").unwrap_or_default(),
            effects: parse_facts(value.get("effects")),
            preconditions: parse_facts(value.get("preconditions")),
            roles: strings(value.get("chainRoles")).into_iter().collect(),
            sources: strings(value.get("sources")),
            sinks: strings(value.get("sinks")),
            assets: strings(value.get("assets")),
            capabilities: strings(value.get("attackerCapabilities")),
            required_controls: strings(value.get("requiredControls")),
            observed_controls: strings(value.get("observedControls")),
            uncertainty: strings(value.get("uncertainty")),
            evidence_refs: strings(value.get("evidenceRefs")),
        })
    }

    fn touches(&self) -> BTreeSet<&str> {
        self.sources
            .iter()
            .chain(&self.sinks)
            .chain(&self.assets)
            .map(String::as_str)
            .collect()
    }

    fn user_interactions(&self) -> usize {
        self.capabilities
            .iter()
            .filter(|c| c.contains("user-interaction"))
            .count()
    }
}

#[derive(Debug, Clone)]
struct Model {
    entrypoints: BTreeSet<String>,
    crown_assets: BTreeMap<String, String>, // id -> kind
    asset_kinds: BTreeMap<String, String>,
    /// id, kind, from aliases, to aliases
    relations: Vec<(String, String, BTreeSet<String>, BTreeSet<String>)>,
    /// Model reports blocking gaps or incomplete coverage.
    incomplete: bool,
}

fn parse_model(value: &Value) -> Option<Model> {
    let obj = value.as_object()?;
    if obj.contains_key("entrypoints") {
        return parse_legacy_model(obj);
    }
    parse_surface_model(obj)
}

/// Legacy/hand-authored shape: `entrypoints`, `assets`, `relations` with plain ids.
fn parse_legacy_model(obj: &Map<String, Value>) -> Option<Model> {
    let ids =
        |key: &str| -> Option<Vec<&Value>> { obj.get(key)?.as_array().map(|a| a.iter().collect()) };
    let entrypoints = ids("entrypoints")?
        .into_iter()
        .filter_map(|e| text(e, "id").or_else(|| e.as_str().map(ToOwned::to_owned)))
        .collect();
    let mut asset_kinds = BTreeMap::new();
    let mut crown_assets = BTreeMap::new();
    for asset in ids("assets").unwrap_or_default() {
        if let Some(id) = text(asset, "id") {
            let kind = text(asset, "kind").unwrap_or_default();
            if kind == "crown-jewel" {
                crown_assets.insert(id.clone(), kind.clone());
            }
            asset_kinds.insert(id, kind);
        }
    }
    let relations = ids("relations")
        .unwrap_or_default()
        .into_iter()
        .filter_map(|r| {
            Some((
                text(r, "id").unwrap_or_default(),
                text(r, "kind")?,
                text(r, "from").into_iter().collect(),
                text(r, "to").into_iter().collect(),
            ))
        })
        .collect();
    Some(Model {
        entrypoints,
        crown_assets,
        asset_kinds,
        relations,
        incomplete: false,
    })
}

/// `legion-security-model` shape (`security.surface-model`): typed `entities`
/// (`kind` entrypoint | asset | crown-jewel), `relations` whose `from`/`to` are
/// entity ids, and `evidence` rows carrying paths. Candidates name sources,
/// sinks and assets as entity ids, entity names or repository paths, so every
/// entity is indexed under all three aliases (id, name, cited evidence paths).
/// A relation endpoint matches a candidate when any alias of that endpoint
/// matches. An entity without `kind` or a model without `entities` is rejected.
fn parse_surface_model(obj: &Map<String, Value>) -> Option<Model> {
    let entities = obj.get("entities")?.as_array()?;
    let evidence_paths: BTreeMap<String, String> = obj
        .get("evidence")
        .and_then(Value::as_array)
        .map(|rows| {
            rows.iter()
                .filter_map(|row| Some((text(row, "id")?, text(row, "path")?)))
                .collect()
        })
        .unwrap_or_default();
    let mut aliases: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut entrypoints = BTreeSet::new();
    let mut asset_kinds = BTreeMap::new();
    let mut crown_assets = BTreeMap::new();
    for entity in entities {
        let id = text(entity, "id")?;
        let kind = text(entity, "kind")?;
        let mut set = BTreeSet::new();
        set.insert(id.clone());
        if let Some(name) = text(entity, "name") {
            set.insert(name);
        }
        for reference in strings(entity.get("evidenceRefs")) {
            if let Some(path) = evidence_paths.get(&reference) {
                set.insert(path.clone());
            }
        }
        match kind.as_str() {
            "entrypoint" => entrypoints.extend(set.iter().cloned()),
            "crown-jewel" | "asset" => {
                for alias in &set {
                    if kind == "crown-jewel" {
                        crown_assets.insert(alias.clone(), kind.clone());
                    }
                    asset_kinds.insert(alias.clone(), kind.clone());
                }
            }
            _ => {}
        }
        aliases.insert(id, set);
    }
    let endpoint = |id: Option<String>| -> BTreeSet<String> {
        let id = id.unwrap_or_default();
        aliases
            .get(&id)
            .cloned()
            .unwrap_or_else(|| BTreeSet::from([id]))
    };
    let relations = obj
        .get("relations")
        .and_then(Value::as_array)
        .map(|rows| {
            rows.iter()
                .filter_map(|r| {
                    Some((
                        text(r, "id").unwrap_or_default(),
                        text(r, "kind")?,
                        endpoint(text(r, "from")),
                        endpoint(text(r, "to")),
                    ))
                })
                .collect()
        })
        .unwrap_or_default();
    let blocking_gap = obj
        .get("gaps")
        .and_then(Value::as_array)
        .is_some_and(|gaps| {
            gaps.iter()
                .any(|g| g.get("blocking").and_then(Value::as_bool) == Some(true))
        });
    let incomplete = blocking_gap
        || obj
            .get("coverage")
            .and_then(|c| c.get("complete"))
            .and_then(Value::as_bool)
            != Some(true);
    Some(Model {
        entrypoints,
        crown_assets,
        asset_kinds,
        relations,
        incomplete,
    })
}

#[derive(Debug, Clone)]
struct Edge {
    to: usize,
    bridge: String,
    relation: String,
    strength: Strength,
    supported: bool,
    from_effect: Value,
    to_precondition: Value,
    model_relation_ids: Vec<String>,
}

fn scope_ok(pattern: Option<&Value>, scope: &Option<String>) -> bool {
    match pattern.and_then(Value::as_str) {
        None => true,
        Some(p) => scope.as_deref().is_some_and(|s| s == p || s.contains(p)),
    }
}

fn fields_compatible(a: &Fact, b: &Fact) -> bool {
    FIELD_KEYS
        .iter()
        .all(|k| match (a.fields.get(*k), b.fields.get(*k)) {
            (Some(x), Some(y)) => x == y,
            _ => true,
        })
}

fn kind_action(pattern: &Value, fact: &Fact) -> bool {
    pattern["kind"].as_str() == Some(fact.kind.as_str())
        && pattern["action"]
            .as_str()
            .map_or(true, |a| a == fact.action)
}

/// Best composition of `a` into `b`, if any. Deterministic: bridge registry
/// order, then direct typed match; stronger and supported edges win.
fn compose(
    registry: &Registry,
    model: &Model,
    a: &Candidate,
    b: &Candidate,
    b_idx: usize,
) -> Option<Edge> {
    let touched: BTreeSet<&str> = a.touches().into_iter().chain(b.touches()).collect();
    let mut best: Option<Edge> = None;
    let mut consider = |edge: Edge| {
        let better = match &best {
            None => true,
            Some(cur) => (edge.supported, edge.strength) > (cur.supported, cur.strength),
        };
        if better {
            best = Some(edge);
        }
    };
    for effect in &a.effects {
        for pre in &b.preconditions {
            if !fields_compatible(effect, pre) {
                continue;
            }
            for bridge in &registry.bridges {
                if !kind_action(&bridge.from, effect)
                    || !scope_ok(bridge.from.get("scope"), &effect.scope)
                    || !kind_action(&bridge.to, pre)
                {
                    continue;
                }
                let (supported, strength, rels) = match &bridge.requires_relation {
                    None => (true, bridge.strength, Vec::new()),
                    Some(kind) => {
                        let rels: Vec<String> = model
                            .relations
                            .iter()
                            .filter(|(_, k, f, t)| {
                                k == kind
                                    && (f.iter().any(|a| touched.contains(a.as_str()))
                                        || t.iter().any(|a| touched.contains(a.as_str())))
                            })
                            .map(|(id, ..)| id.clone())
                            .collect();
                        if rels.is_empty() {
                            (false, Strength::Possible, rels)
                        } else {
                            (true, bridge.strength, rels)
                        }
                    }
                };
                consider(Edge {
                    to: b_idx,
                    bridge: bridge.id.clone(),
                    relation: bridge.relation.clone(),
                    strength,
                    supported,
                    from_effect: effect.raw.clone(),
                    to_precondition: pre.raw.clone(),
                    model_relation_ids: rels,
                });
            }
            let scopes_ok = match (&effect.scope, &pre.scope) {
                (Some(x), Some(y)) => x == y,
                _ => true,
            };
            if effect.kind == pre.kind && effect.action == pre.action && scopes_ok {
                consider(Edge {
                    to: b_idx,
                    bridge: "direct".to_owned(),
                    relation: "satisfies".to_owned(),
                    strength: Strength::StrongInference,
                    supported: true,
                    from_effect: effect.raw.clone(),
                    to_precondition: pre.raw.clone(),
                    model_relation_ids: Vec::new(),
                });
            }
        }
    }
    best
}

fn objective_hit<'a>(
    registry: &'a Registry,
    model: &Model,
    cand: &Candidate,
) -> Option<(&'a Objective, Value)> {
    let mut best: Option<(&Objective, Value)> = None;
    for effect in &cand.effects {
        for obj in &registry.objectives {
            let m = &obj.matches;
            let kind_ok = match (
                m.get("factKind").and_then(Value::as_str),
                m.get("factKinds"),
            ) {
                (Some(k), _) => k == effect.kind,
                (None, Some(list)) => strings(Some(list)).contains(&effect.kind),
                _ => false,
            };
            if !kind_ok {
                continue;
            }
            if let Some(kinds) = m.get("assetKinds") {
                let wanted = strings(Some(kinds));
                let hit = cand
                    .assets
                    .iter()
                    .any(|a| model.asset_kinds.get(a).is_some_and(|k| wanted.contains(k)));
                if !hit {
                    continue;
                }
            }
            if let Some(patterns) = m.get("scopePatterns") {
                let pats = strings(Some(patterns));
                let hit = effect
                    .scope
                    .as_deref()
                    .is_some_and(|s| pats.iter().any(|p| s.contains(p.as_str())));
                if !hit {
                    continue;
                }
            }
            if best.as_ref().map_or(true, |(cur, _)| {
                (registry.rank(&obj.priority), &obj.id) < (registry.rank(&cur.priority), &cur.id)
            }) {
                best = Some((obj, effect.raw.clone()));
            }
        }
    }
    best
}

/// Stamp the identity the chain adjudicator checks onto every hypothesis of a
/// synthesis `document`: the frozen plan `binding`, the synthesizing
/// `provider` and its `synthesisContextId`. Hypothesis ids are unaffected.
pub fn bind_hypotheses(document: &mut Value, binding: &Value, synthesis_context_id: &str) {
    if let Some(list) = document.get_mut("hypotheses").and_then(Value::as_array_mut) {
        for hypothesis in list {
            if let Some(obj) = hypothesis.as_object_mut() {
                obj.insert("binding".into(), binding.clone());
                obj.insert("provider".into(), json!(PROVIDER_ID));
                obj.insert("synthesisContextId".into(), json!(synthesis_context_id));
            }
        }
    }
}

/// `UNPROVEN` document for a packaged registry that failed to load.
pub fn registry_unavailable(bounds: &Bounds, error: &str) -> Value {
    unproven(
        bounds,
        json!({ "modelPresent": false, "candidateCount": 0 }),
        vec![gap(
            "attack-registry-invalid",
            format!("objective/bridge registry unavailable: {error}"),
        )],
    )
}

fn gap(code: &str, detail: String) -> Value {
    json!({ "code": code, "detail": detail })
}

fn unproven(bounds: &Bounds, inputs: Value, gaps: Vec<Value>) -> Value {
    document(bounds, inputs, "UNPROVEN", Vec::new(), gaps, 0)
}

fn document(
    bounds: &Bounds,
    inputs: Value,
    coverage: &str,
    hypotheses: Vec<Value>,
    gaps: Vec<Value>,
    visited: usize,
) -> Value {
    json!({
        "schemaVersion": 1,
        "kind": ARTIFACT_KIND,
        "provider": PROVIDER_ID,
        "authority": {
            "publishesFindings": false,
            "emitsVerdicts": false,
            "establishesPaths": false,
        },
        "claims": { "exhaustive": false, "pathsProven": 0 },
        "coverage": coverage,
        "bounds": bounds.to_json(),
        "inputs": inputs,
        "counts": { "hypotheses": hypotheses.len(), "visitedPaths": visited, "coverageGaps": gaps.len() },
        "hypotheses": hypotheses,
        "coverageGaps": gaps,
    })
}

struct Raw {
    members: Vec<usize>,
    edges: Vec<Edge>,
    objective: (String, String),
    target_effect: Value,
}

/// Synthesize attack-path hypotheses. Pure and deterministic.
pub fn synthesize(
    model: Option<&Value>,
    candidates: Option<&Value>,
    bounds: &Bounds,
    registry: &Registry,
) -> Value {
    let list: Vec<&Value> = candidates
        .and_then(|c| {
            c.as_array()
                .or_else(|| c.get("candidates").and_then(Value::as_array))
        })
        .map(|a| a.iter().collect())
        .unwrap_or_default();
    let mut inputs = Map::new();
    inputs.insert("modelPresent".into(), json!(model.is_some()));
    inputs.insert(
        "modelDigest".into(),
        model.map_or(Value::Null, |m| json!(digest_json(m))),
    );
    inputs.insert(
        "candidatesDigest".into(),
        candidates.map_or(Value::Null, |c| json!(digest_json(c))),
    );
    inputs.insert("candidateCount".into(), json!(list.len()));
    let inputs = Value::Object(inputs);

    let mut gaps = Vec::new();
    if !bounds.valid() {
        gaps.push(gap(
            "bounds-invalid",
            format!(
                "bounds must be positive and maxHops <= {HARD_MAX_HOPS}: {}",
                bounds.to_json()
            ),
        ));
        return unproven(bounds, inputs, gaps);
    }
    let parsed_model = model.and_then(parse_model);
    match (model, &parsed_model) {
        (None, _) => gaps.push(gap(
            "security-model-missing",
            "no security model supplied; entrypoints, crown jewels and relations are unknown"
                .into(),
        )),
        (Some(_), None) => gaps.push(gap(
            "security-model-invalid",
            "security model lacks an entrypoints array or a typed entities array".into(),
        )),
        _ => {}
    }
    let mut by_id: BTreeMap<String, Candidate> = BTreeMap::new();
    let mut malformed = 0usize;
    for item in &list {
        match Candidate::parse(item) {
            Some(c) => {
                by_id.entry(c.id.clone()).or_insert(c);
            }
            None => malformed += 1,
        }
    }
    if malformed > 0 {
        gaps.push(gap(
            "candidate-malformed",
            format!("{malformed} candidate(s) without an id were excluded"),
        ));
    }
    if by_id.is_empty() {
        gaps.push(gap(
            "no-candidates",
            "zero usable security candidates; absence of paths is unproven, not established".into(),
        ));
        gaps.push(gap(
            "no-composable-candidates",
            "no candidate carries typed effects, so nothing can compose; absence of paths is unproven".into(),
        ));
    }
    let Some(model) = parsed_model else {
        return unproven(bounds, inputs, gaps);
    };
    if model.incomplete {
        gaps.push(gap(
            "security-model-incomplete",
            "security model reports blocking gaps or incomplete coverage; entrypoints, assets and relations may be missing".into(),
        ));
    }
    if by_id.is_empty() {
        return unproven(bounds, inputs, gaps);
    }
    let cands: Vec<Candidate> = by_id.into_values().collect();
    if cands.iter().all(|c| c.effects.is_empty()) {
        gaps.push(gap(
            "no-composable-candidates",
            format!(
                "none of {} candidate(s) carries typed effects, so nothing can compose; absence of paths is unproven",
                cands.len()
            ),
        ));
        return unproven(bounds, inputs, gaps);
    }

    // Adjacency, bounded per node.
    let mut adjacency: Vec<Vec<Edge>> = Vec::with_capacity(cands.len());
    let mut branch_truncated: Vec<String> = Vec::new();
    for (i, a) in cands.iter().enumerate() {
        let mut edges: Vec<Edge> = (0..cands.len())
            .filter(|j| *j != i)
            .filter_map(|j| compose(registry, &model, a, &cands[j], j))
            .collect();
        edges.sort_by(|x, y| {
            (!x.supported, std::cmp::Reverse(x.strength), &cands[x.to].id).cmp(&(
                !y.supported,
                std::cmp::Reverse(y.strength),
                &cands[y.to].id,
            ))
        });
        if edges.len() > bounds.max_branching {
            branch_truncated.push(format!(
                "{} ({} -> {})",
                a.id,
                edges.len(),
                bounds.max_branching
            ));
            edges.truncate(bounds.max_branching);
        }
        adjacency.push(edges);
    }
    if !branch_truncated.is_empty() {
        gaps.push(gap(
            "max-branching-reached",
            format!(
                "expansion capped at {} for: {}",
                bounds.max_branching,
                branch_truncated.join(", ")
            ),
        ));
    }

    // Candidates without effects cannot compose; that exclusion is the real
    // coverage gap. When every candidate is typed and none composes, the
    // bounded search is complete (still never claimed exhaustive).
    let untyped = cands.iter().filter(|c| c.effects.is_empty()).count();
    if untyped > 0 {
        gaps.push(gap(
            "untyped-candidates-excluded",
            format!(
                "{untyped} candidate(s) carry no typed effects and were excluded from composition"
            ),
        ));
    }

    let starters: Vec<usize> = cands
        .iter()
        .enumerate()
        .filter(|(_, c)| {
            c.roles.contains("starter") || c.sources.iter().any(|s| model.entrypoints.contains(s))
        })
        .map(|(i, _)| i)
        .collect();
    if starters.is_empty() {
        gaps.push(gap("no-starter-candidates", "no candidate is a chain starter or reaches a modeled entrypoint; no composition attempted".into()));
        return unproven(bounds, inputs, gaps);
    }

    // Bounded DFS; no repeated candidate in one path.
    let mut raws: Vec<Raw> = Vec::new();
    let mut visited = 0usize;
    let mut budget_hit = false;
    let mut hop_capped = BTreeSet::new();
    for &s in &starters {
        if budget_hit {
            break;
        }
        let mut members = vec![s];
        let mut edges = Vec::new();
        dfs(
            &cands,
            &adjacency,
            registry,
            &model,
            bounds,
            &mut members,
            &mut edges,
            &mut raws,
            &mut visited,
            &mut budget_hit,
            &mut hop_capped,
        );
    }
    if budget_hit {
        gaps.push(gap(
            "visit-budget-exhausted",
            format!(
                "search stopped after {} visited paths; remaining paths not explored",
                bounds.max_visited_paths
            ),
        ));
    }
    if !hop_capped.is_empty() {
        let ids: Vec<&String> = hop_capped.iter().collect();
        gaps.push(gap(
            "max-hops-reached",
            format!(
                "paths at {} hops had further composable candidates: {}",
                bounds.max_hops,
                ids.iter()
                    .map(|s| s.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        ));
    }

    // Drop strict-prefix hypotheses dominated by a longer path of equal or higher priority.
    let mut prefix_rank: BTreeMap<Vec<usize>, usize> = BTreeMap::new();
    for raw in &raws {
        let rank = registry.rank(&raw.objective.1);
        for len in 1..raw.members.len() {
            let e = prefix_rank
                .entry(raw.members[..len].to_vec())
                .or_insert(rank);
            *e = (*e).min(rank);
        }
    }
    raws.retain(|raw| {
        prefix_rank
            .get(&raw.members)
            .map_or(true, |r| *r > registry.rank(&raw.objective.1))
    });

    let mut built: Vec<(Vec<String>, Value)> = Vec::new();
    for raw in &raws {
        built.push(build_hypothesis(registry, &model, &cands, raw));
    }
    // Deterministic order: category, then SEC 10.3 tie-breakers.
    built.sort_by(|a, b| a.0.cmp(&b.0));
    let mut per_objective: BTreeMap<String, usize> = BTreeMap::new();
    let mut kept: Vec<Value> = Vec::new();
    let mut dropped_objective = 0usize;
    for (_, h) in built {
        let obj = h["objective"]["id"].as_str().unwrap_or_default().to_owned();
        let n = per_objective.entry(obj).or_insert(0);
        if *n >= bounds.max_per_objective {
            dropped_objective += 1;
            continue;
        }
        *n += 1;
        kept.push(h);
    }
    if dropped_objective > 0 {
        gaps.push(gap(
            "max-per-objective-reached",
            format!(
                "{dropped_objective} lower-priority hypotheses dropped at {} per objective",
                bounds.max_per_objective
            ),
        ));
    }
    if kept.len() > bounds.max_hypotheses {
        gaps.push(gap(
            "max-hypotheses-reached",
            format!(
                "{} lower-priority hypotheses dropped at {} total",
                kept.len() - bounds.max_hypotheses,
                bounds.max_hypotheses
            ),
        ));
        kept.truncate(bounds.max_hypotheses);
    }
    let coverage = if gaps.is_empty() {
        "BOUNDED_COMPLETE"
    } else {
        "TRUNCATED"
    };
    document(bounds, inputs, coverage, kept, gaps, visited)
}

#[allow(clippy::too_many_arguments)]
fn dfs(
    cands: &[Candidate],
    adjacency: &[Vec<Edge>],
    registry: &Registry,
    model: &Model,
    bounds: &Bounds,
    members: &mut Vec<usize>,
    edges: &mut Vec<Edge>,
    out: &mut Vec<Raw>,
    visited: &mut usize,
    budget_hit: &mut bool,
    hop_capped: &mut BTreeSet<String>,
) {
    let last = *members.last().expect("non-empty path");
    if members.len() >= 2 {
        if let Some((obj, effect)) = objective_hit(registry, model, &cands[last]) {
            out.push(Raw {
                members: members.clone(),
                edges: edges.clone(),
                objective: (obj.id.clone(), obj.priority.clone()),
                target_effect: effect,
            });
        }
    }
    for edge in &adjacency[last] {
        if members.contains(&edge.to) {
            continue;
        }
        if edges.len() >= bounds.max_hops {
            hop_capped.insert(cands[last].id.clone());
            break;
        }
        if *visited >= bounds.max_visited_paths {
            *budget_hit = true;
            return;
        }
        *visited += 1;
        members.push(edge.to);
        edges.push(edge.clone());
        dfs(
            cands, adjacency, registry, model, bounds, members, edges, out, visited, budget_hit,
            hop_capped,
        );
        members.pop();
        edges.pop();
        if *budget_hit {
            return;
        }
    }
}

fn is_subsequence(needle: &[String], haystack: &[String]) -> bool {
    let mut it = haystack.iter();
    needle.iter().all(|n| it.any(|h| h == n))
}

/// Returns (sort key, hypothesis JSON).
fn build_hypothesis(
    registry: &Registry,
    model: &Model,
    cands: &[Candidate],
    raw: &Raw,
) -> (Vec<String>, Value) {
    let members: Vec<&Candidate> = raw.members.iter().map(|i| &cands[*i]).collect();
    let first = members[0];
    let entrypoint = first
        .sources
        .iter()
        .find(|s| model.entrypoints.contains(*s))
        .cloned();
    let unsupported_edges = raw.edges.iter().filter(|e| !e.supported).count();
    let weakest = raw
        .edges
        .iter()
        .map(|e| e.strength)
        .min()
        .unwrap_or(Strength::Possible);
    let last = members[members.len() - 1];
    let crown: Vec<String> = last
        .assets
        .iter()
        .filter(|a| model.crown_assets.contains_key(*a))
        .cloned()
        .collect();
    let user_interactions: usize = members.iter().map(|m| m.user_interactions()).sum();

    let mut unsupported = Vec::new();
    if entrypoint.is_none() {
        unsupported.push("start entrypoint is not bound to a modeled entrypoint".to_owned());
    }
    for (i, e) in raw.edges.iter().enumerate() {
        if !e.supported {
            unsupported.push(format!(
                "edge {} -> {} via {} lacks its required model relation",
                members[i].id,
                members[i + 1].id,
                e.bridge
            ));
        } else if e.strength == Strength::Possible {
            unsupported.push(format!(
                "edge {} -> {} via {} is only possible",
                members[i].id,
                members[i + 1].id,
                e.bridge
            ));
        }
    }
    let category = if entrypoint.is_none() {
        "PARTIAL_PATH".to_owned()
    } else {
        raw.objective.1.clone()
    };

    let mut kinds: Vec<String> = Vec::new();
    for (i, m) in members.iter().enumerate() {
        if i > 0 {
            if let Some(k) = raw.edges[i - 1].to_precondition["kind"].as_str() {
                kinds.push(k.to_owned());
            } else if let Some(k) = raw.edges[i - 1].to_precondition.as_str() {
                kinds.push(k.split(':').next().unwrap_or_default().to_owned());
            }
        }
        kinds.extend(m.effects.iter().map(|f| f.kind.clone()));
    }
    let template_ids: Vec<String> = registry
        .templates
        .iter()
        .filter(|t| is_subsequence(&t.step_kinds, &kinds))
        .map(|t| t.id.clone())
        .collect();

    let controls: BTreeSet<String> = members
        .iter()
        .flat_map(|m| m.observed_controls.iter().cloned())
        .collect();
    let missing: BTreeSet<String> = members
        .iter()
        .flat_map(|m| m.required_controls.iter())
        .filter(|c| !members.iter().any(|m| m.observed_controls.contains(*c)))
        .cloned()
        .collect();
    let alternates: BTreeSet<String> = members
        .iter()
        .flat_map(|m| m.uncertainty.iter().cloned())
        .collect();

    let edge_json: Vec<Value> = raw
        .edges
        .iter()
        .enumerate()
        .map(|(i, e)| {
            let state = if !e.supported {
                "unsupported"
            } else if e.bridge == "direct" {
                "typed-match"
            } else if e.strength == Strength::Possible {
                "possible"
            } else {
                "bridge-inferred"
            };
            json!({
                "from": members[i].id,
                "to": members[i + 1].id,
                "bridge": e.bridge,
                "relation": e.relation,
                "effect": e.from_effect,
                "precondition": e.to_precondition,
                "evidenceStrength": e.strength.as_str(),
                "evidenceState": state,
                "modelRelationIds": e.model_relation_ids,
            })
        })
        .collect();
    let member_ids: Vec<&str> = members.iter().map(|m| m.id.as_str()).collect();
    let id = digest_json(&json!({
        "start": entrypoint,
        "objective": raw.objective.0,
        "members": member_ids,
        "bridges": raw.edges.iter().map(|e| e.bridge.as_str()).collect::<Vec<_>>(),
    }));
    // Joins are the composition edges the chain adjudicator must verify one by
    // one (`joins[{id}]`); ids are stable digests of the edge, unique per path.
    let joins: Vec<Value> = raw
        .edges
        .iter()
        .enumerate()
        .map(|(i, e)| {
            json!({
                "id": digest_json(&json!({
                    "from": members[i].id,
                    "to": members[i + 1].id,
                    "bridge": e.bridge,
                })),
                "from": members[i].id,
                "to": members[i + 1].id,
                "bridge": e.bridge,
                "state": if !e.supported { "unsupported" } else { "unverified" },
            })
        })
        .collect();
    let steps: Vec<Value> = members
        .iter()
        .map(|m| {
            json!({
                "candidateId": m.id,
                "ruleId": m.rule_id,
                "preconditions": m.preconditions.iter().map(|f| f.raw.clone()).collect::<Vec<_>>(),
                "effects": m.effects.iter().map(|f| f.raw.clone()).collect::<Vec<_>>(),
                "evidenceRefs": m.evidence_refs,
            })
        })
        .collect();

    // Sort key: category rank, unsupported edges, weakest edge (stronger first),
    // direct crown-jewel, user interaction, hops, stable id. Zero-padded for lexical order.
    let direct_crown = u8::from(!(raw.objective.1 == "DIRECT_CROWN_JEWEL" && !crown.is_empty()));
    let key = vec![
        format!("{:04}", registry.rank(&category)),
        format!("{:04}", unsupported_edges),
        format!("{}", 2 - weakest as u8),
        format!("{direct_crown}"),
        format!("{:04}", user_interactions),
        format!("{:04}", raw.edges.len()),
        id.clone(),
    ];
    let hypothesis = json!({
        "id": id,
        "status": "hypothesis",
        "adjudicationState": "PROPOSED",
        "priority": category,
        "objective": { "id": raw.objective.0, "priority": raw.objective.1 },
        "start": { "entrypoint": entrypoint, "attackerCapabilities": first.capabilities },
        "target": { "crownJewelAssets": crown, "assets": last.assets, "effect": raw.target_effect },
        "memberCandidateIds": member_ids,
        "steps": steps,
        "edges": edge_json,
        "hops": raw.edges.len(),
        "unsupportedEdgeCount": unsupported_edges,
        "weakestEdgeStrength": weakest.as_str(),
        "userInteractionAssumptions": user_interactions,
        "joins": joins,
        "controls": controls.iter().cloned().collect::<Vec<_>>(),
        "controlsThatMayBlock": controls,
        "missingRequiredControls": missing,
        "unsupportedAssertions": unsupported,
        "alternateExplanations": alternates,
        "templateIds": template_ids,
    });
    (key, hypothesis)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_registry_loads() {
        let r = Registry::embedded().expect("registry");
        assert!(r.templates.len() >= 16);
        assert!(r.bridges.len() >= 9);
        assert!(r
            .objectives
            .iter()
            .all(|o| r.rank(&o.priority) != usize::MAX));
    }

    #[test]
    fn fact_string_form_parses() {
        let f = parse_fact(&json!("data-access:read:credential-material")).unwrap();
        assert_eq!(
            (f.kind.as_str(), f.action.as_str()),
            ("data-access", "read")
        );
        assert_eq!(f.scope.as_deref(), Some("credential-material"));
    }
}
