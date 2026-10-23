use std::collections::{BTreeMap, BTreeSet};

use serde_json::Value;

use crate::{error::AuditError, plan::AuditProvider};

/// Optional ordering-only prerequisite declared by the frozen visual runner.
/// It deliberately does not enter `dependencies`, whose execution semantics
/// require successful completion.
pub(crate) fn capture_source_provider(
    provider: &AuditProvider,
) -> Result<Option<&str>, AuditError> {
    let visual = provider
        .configuration
        .get("runner")
        .and_then(|runner| runner.get("visual"));
    let Some(source) = visual.and_then(|visual| visual.get("captureSource")) else {
        return Ok(None);
    };
    if provider.id != "legacy.visual.core"
        || source.get("kind").and_then(serde_json::Value::as_str) != Some("runtime-provider")
    {
        return Err(AuditError::Invalid(format!(
            "provider {} has an invalid visual capture source",
            provider.id
        )));
    }
    let provider_id = source
        .get("providerId")
        .and_then(serde_json::Value::as_str)
        .filter(|id| *id == "legacy.runtime.app")
        .ok_or_else(|| {
            AuditError::Invalid("visual capture source must name legacy.runtime.app".into())
        })?;
    Ok(Some(provider_id))
}

pub fn topological(providers: &[AuditProvider]) -> Result<Vec<String>, AuditError> {
    let by_id: BTreeMap<_, _> = providers
        .iter()
        .map(|provider| (provider.id.as_str(), provider))
        .collect();
    if by_id.len() != providers.len() {
        return Err(AuditError::Invalid("duplicate provider id".into()));
    }
    let capture_sources = providers
        .iter()
        .map(|provider| {
            Ok::<_, AuditError>((provider.id.as_str(), capture_source_provider(provider)?))
        })
        .collect::<Result<BTreeMap<_, _>, _>>()?;
    for source in capture_sources.values().flatten() {
        if !by_id.contains_key(source) {
            return Err(AuditError::Invalid(format!(
                "visual capture source provider {source} is missing"
            )));
        }
    }
    let mut remaining: BTreeSet<&str> = by_id.keys().copied().collect();
    let mut done = BTreeSet::new();
    let mut order = Vec::with_capacity(providers.len());
    while !remaining.is_empty() {
        let next = remaining
            .iter()
            .find(|id| {
                by_id[*id]
                    .dependencies
                    .iter()
                    .all(|dep| by_id.contains_key(dep.as_str()) && done.contains(dep.as_str()))
                    && capture_sources[*id].map_or(true, |source| done.contains(source))
            })
            .copied();
        let Some(id) = next else {
            return Err(AuditError::Invalid(
                "provider dependency cycle or missing dependency".into(),
            ));
        };
        remaining.remove(id);
        done.insert(id);
        order.push(id.to_owned());
    }
    Ok(order)
}

// ---------------------------------------------------------------------------
// First-class objective DAG (CP section 10).
//
// One objective per selected provider. Objective identity is content-derived
// from proof-relevant inputs only (never timestamps, paths or completion
// order), so it is stable across plan generations whose definition of that
// objective is unchanged. Edges come from `dependsOn` plus the frozen
// `consumes`/`produces` artifact declarations. Mutable execution state is not
// part of the objective record; it is derived from observations and kept
// separate from proof state.
// ---------------------------------------------------------------------------

/// Artifact kinds supplied by the frozen fact set rather than by a provider.
/// A consumed artifact outside this set must have a producer in the plan.
pub const FROZEN_FACT_SOURCES: &[&str] = &["blueprint-packet", "repository-inventory"];

pub const OBJECTIVE_FORMAT: &str = "audit-objective/v1";

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum EdgeKind {
    /// Declared `dependsOn`.
    Declared,
    /// Compiled from a consumed artifact kind with a producer in the plan.
    Artifact(String),
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ObjectiveEdge {
    pub from_objective: String,
    pub to_objective: String,
    pub kind: EdgeKind,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Objective {
    pub format: String,
    pub objective_id: String,
    pub provider_id: String,
    pub stage: String,
    /// Objective ids this objective depends on (sorted).
    pub dependencies: Vec<String>,
    pub consumes: Vec<String>,
    pub produces: Vec<String>,
    pub proof_obligations: Value,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ObjectiveGraph {
    /// Topologically ordered.
    pub objectives: Vec<Objective>,
    pub edges: Vec<ObjectiveEdge>,
}

fn artifact_list(provider: &AuditProvider, key: &str) -> Result<Vec<String>, AuditError> {
    match provider.configuration.get(key) {
        None | Some(Value::Null) => Ok(Vec::new()),
        Some(Value::Array(items)) => {
            let mut out = items
                .iter()
                .map(|item| {
                    item.as_str()
                        .filter(|name| !name.trim().is_empty())
                        .map(str::to_owned)
                        .ok_or_else(|| {
                            AuditError::Invalid(format!(
                                "provider {} {key} entry is not a non-empty string",
                                provider.id
                            ))
                        })
                })
                .collect::<Result<Vec<_>, _>>()?;
            out.sort();
            out.dedup();
            Ok(out)
        }
        Some(_) => Err(AuditError::Invalid(format!(
            "provider {} {key} is not an array",
            provider.id
        ))),
    }
}

/// Provider-level dependency sets: declared plus artifact-derived.
fn provider_edges(
    providers: &[AuditProvider],
) -> Result<BTreeMap<String, BTreeMap<String, EdgeKind>>, AuditError> {
    let ids: BTreeSet<&str> = providers.iter().map(|p| p.id.as_str()).collect();
    if ids.len() != providers.len() {
        return Err(AuditError::Invalid("duplicate provider id".into()));
    }
    let mut producers: BTreeMap<String, BTreeSet<&str>> = BTreeMap::new();
    for provider in providers {
        for kind in artifact_list(provider, "produces")? {
            producers
                .entry(kind)
                .or_default()
                .insert(provider.id.as_str());
        }
    }
    let mut edges = BTreeMap::new();
    for provider in providers {
        let mut deps: BTreeMap<String, EdgeKind> = BTreeMap::new();
        for dep in &provider.dependencies {
            if !ids.contains(dep.as_str()) {
                return Err(AuditError::Invalid(format!(
                    "provider {} depends on missing provider {dep}",
                    provider.id
                )));
            }
            deps.insert(dep.clone(), EdgeKind::Declared);
        }
        for kind in artifact_list(provider, "consumes")? {
            let sources: Vec<&str> = producers
                .get(&kind)
                .map(|set| {
                    set.iter()
                        .copied()
                        .filter(|id| *id != provider.id)
                        .collect()
                })
                .unwrap_or_default();
            if sources.is_empty() {
                if FROZEN_FACT_SOURCES.contains(&kind.as_str()) {
                    continue;
                }
                return Err(AuditError::Invalid(format!(
                    "provider {} consumes artifact {kind} which has no producer or frozen fact source",
                    provider.id
                )));
            }
            for source in sources {
                deps.entry(source.to_owned())
                    .or_insert_with(|| EdgeKind::Artifact(kind.clone()));
            }
        }
        edges.insert(provider.id.clone(), deps);
    }
    Ok(edges)
}

/// Deterministic order (alphabetical tie-break) over the given dependency map;
/// errors on a cycle.
fn order_edges(
    edges: &BTreeMap<String, BTreeMap<String, EdgeKind>>,
) -> Result<Vec<String>, AuditError> {
    let mut remaining: BTreeSet<&str> = edges.keys().map(String::as_str).collect();
    let mut done: BTreeSet<&str> = BTreeSet::new();
    let mut order = Vec::with_capacity(edges.len());
    while !remaining.is_empty() {
        let next = remaining
            .iter()
            .find(|id| edges[**id].keys().all(|dep| done.contains(dep.as_str())))
            .copied()
            .ok_or_else(|| AuditError::Invalid("objective dependency cycle".into()))?;
        remaining.remove(next);
        done.insert(next);
        order.push(next.to_owned());
    }
    Ok(order)
}

/// Like `topological`, but also honours producer/consumer artifact edges.
/// Used for schema 2 plans; `topological` keeps legacy `dependsOn` semantics.
pub fn topological_with_artifacts(providers: &[AuditProvider]) -> Result<Vec<String>, AuditError> {
    // Preserve visual capture-source ordering by delegating validation first.
    topological(providers)?;
    let mut edges = provider_edges(providers)?;
    for provider in providers {
        if let Some(source) = capture_source_provider(provider)? {
            edges
                .get_mut(&provider.id)
                .expect("known provider")
                .entry(source.to_owned())
                .or_insert(EdgeKind::Declared);
        }
    }
    order_edges(&edges)
}

impl ObjectiveGraph {
    /// Compile the objective graph of a plan. Fails closed on duplicate
    /// providers, missing dependencies, consumed artifacts without producer or
    /// frozen fact source, and cycles.
    pub fn compile(plan: &crate::plan::AuditPlan) -> Result<Self, AuditError> {
        let providers = &plan.providers;
        let edges = provider_edges(providers)?;
        let order = order_edges(&edges)?;
        let by_id: BTreeMap<&str, &AuditProvider> =
            providers.iter().map(|p| (p.id.as_str(), p)).collect();
        // Pass 1: identity from provider-level proof-relevant inputs.
        let mut ids: BTreeMap<String, String> = BTreeMap::new();
        for id in &order {
            let provider = by_id[id.as_str()];
            let proof = proof_obligations(provider);
            let seed = serde_json::json!({
                "repositoryId": plan.repository_id,
                "inventoryDigest": plan.inventory_digest,
                "providerId": provider.id,
                "stage": provider.phase,
                "dependencies": edges[id].keys().collect::<Vec<_>>(),
                "proofObligations": proof,
            });
            let digest = crate::integrity::digest(&seed)?;
            let hex = digest.strip_prefix("sha256:").unwrap_or(&digest);
            ids.insert(id.clone(), format!("obj_{}", &hex[..16]));
        }
        let mut objectives = Vec::with_capacity(order.len());
        let mut edge_list = Vec::new();
        for id in &order {
            let provider = by_id[id.as_str()];
            let mut dependencies: Vec<String> =
                edges[id].keys().map(|dep| ids[dep].clone()).collect();
            dependencies.sort();
            for (dep, kind) in &edges[id] {
                edge_list.push(ObjectiveEdge {
                    from_objective: ids[dep].clone(),
                    to_objective: ids[id].clone(),
                    kind: kind.clone(),
                });
            }
            objectives.push(Objective {
                format: OBJECTIVE_FORMAT.into(),
                objective_id: ids[id].clone(),
                provider_id: provider.id.clone(),
                stage: provider.phase.clone(),
                dependencies,
                consumes: artifact_list(provider, "consumes")?,
                produces: artifact_list(provider, "produces")?,
                proof_obligations: proof_obligations(provider),
            });
        }
        edge_list.sort_by(|a, b| {
            (&a.from_objective, &a.to_objective).cmp(&(&b.from_objective, &b.to_objective))
        });
        let unique: BTreeSet<&str> = objectives.iter().map(|o| o.objective_id.as_str()).collect();
        if unique.len() != objectives.len() {
            return Err(AuditError::Invalid("objective id collision".into()));
        }
        Ok(Self {
            objectives,
            edges: edge_list,
        })
    }

    pub fn digest(&self) -> Result<String, AuditError> {
        crate::integrity::digest(self)
    }

    pub fn objective_for_provider(&self, provider_id: &str) -> Option<&Objective> {
        self.objectives
            .iter()
            .find(|objective| objective.provider_id == provider_id)
    }

    pub fn objective(&self, objective_id: &str) -> Option<&Objective> {
        self.objectives
            .iter()
            .find(|objective| objective.objective_id == objective_id)
    }

    /// Derive lifecycle state from observations. A failed or blocked
    /// dependency blocks its dependents (never silently skipped); `Done`
    /// observed before every dependency is `Done` is inconsistent and fails
    /// closed to `Blocked`. Only a `Done` objective may carry any proof state
    /// other than `Unproven`.
    pub fn derive_status(
        &self,
        observed: &BTreeMap<String, Observation>,
    ) -> Result<BTreeMap<String, ObjectiveStatus>, AuditError> {
        for id in observed.keys() {
            if self.objective(id).is_none() {
                return Err(AuditError::Invalid(format!(
                    "observation for unknown objective {id}"
                )));
            }
        }
        let mut status: BTreeMap<String, ObjectiveStatus> = BTreeMap::new();
        for objective in &self.objectives {
            let dep_states: Vec<ExecutionState> = objective
                .dependencies
                .iter()
                .map(|dep| status[dep].execution)
                .collect();
            let broken = dep_states
                .iter()
                .any(|s| matches!(s, ExecutionState::Failed | ExecutionState::Blocked));
            let all_done = dep_states.iter().all(|s| *s == ExecutionState::Done);
            let state = if broken {
                ObjectiveStatus::unproven(ExecutionState::Blocked)
            } else {
                match observed.get(&objective.objective_id) {
                    None => ObjectiveStatus::unproven(ExecutionState::Pending),
                    Some(Observation::Running) if all_done => {
                        ObjectiveStatus::unproven(ExecutionState::Running)
                    }
                    Some(Observation::Done { proof }) if all_done => ObjectiveStatus {
                        execution: ExecutionState::Done,
                        proof: *proof,
                    },
                    Some(Observation::Failed) if all_done => {
                        ObjectiveStatus::unproven(ExecutionState::Failed)
                    }
                    Some(_) => ObjectiveStatus::unproven(ExecutionState::Blocked),
                }
            };
            status.insert(objective.objective_id.clone(), state);
        }
        Ok(status)
    }

    /// Pending objectives whose dependencies are all `Done`.
    pub fn ready(&self, status: &BTreeMap<String, ObjectiveStatus>) -> Vec<&Objective> {
        self.objectives
            .iter()
            .filter(|objective| {
                status
                    .get(&objective.objective_id)
                    .is_none_or(|s| s.execution == ExecutionState::Pending)
                    && objective.dependencies.iter().all(|dep| {
                        status
                            .get(dep)
                            .is_some_and(|s| s.execution == ExecutionState::Done)
                    })
            })
            .collect()
    }
}

fn proof_obligations(provider: &AuditProvider) -> Value {
    serde_json::json!({
        "providerVersion": provider.version,
        "denominatorDigest": provider.configuration.get("denominatorDigest").cloned().unwrap_or(Value::Null),
        "denominatorCount": provider.configuration.get("denominatorCount").cloned().unwrap_or(Value::Null),
        "cleanClaim": provider.clean_claim,
        "required": provider.required,
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionState {
    Pending,
    Running,
    Done,
    Blocked,
    Failed,
}

impl ExecutionState {
    pub fn can_transition_to(self, next: Self) -> bool {
        matches!(
            (self, next),
            (Self::Pending, Self::Running)
                | (Self::Pending, Self::Blocked)
                | (Self::Running, Self::Done)
                | (Self::Running, Self::Failed)
                | (Self::Running, Self::Blocked)
        )
    }
}

/// Proof state is independent of execution state: a `Done` objective can still
/// be `Unproven` (degraded) or `NotApplicable`.
#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProofState {
    Validated,
    Unproven,
    NotApplicable,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ObjectiveStatus {
    pub execution: ExecutionState,
    pub proof: ProofState,
}

impl ObjectiveStatus {
    fn unproven(execution: ExecutionState) -> Self {
        Self {
            execution,
            proof: ProofState::Unproven,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Observation {
    Running,
    Done { proof: ProofState },
    Failed,
}
