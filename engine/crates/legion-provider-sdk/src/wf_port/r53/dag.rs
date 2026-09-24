//! Port of `src/lib/providers/sdk/dag.mjs`: provider artifact dependency DAG
//! validation (topological ordering, unknown/self dependencies, cycles,
//! unproduced consumed artifacts, duplicate singleton producers, role/output
//! authority).

use std::collections::{BTreeMap, BTreeSet};

/// Minimal provider shape the DAG functions need. Mirrors the duck-typed
/// fields JS reads off each `provider` object (`id`, `dependsOn`, `role`,
/// `produces`, `consumes`, `nonSingletonArtifacts`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderNode {
    pub id: String,
    pub depends_on: Vec<String>,
    pub role: String,
    pub produces: Vec<String>,
    pub consumes: Vec<String>,
    pub non_singleton_artifacts: Vec<String>,
}

impl ProviderNode {
    pub fn new(id: impl Into<String>, role: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            depends_on: Vec::new(),
            role: role.into(),
            produces: Vec::new(),
            consumes: Vec::new(),
            non_singleton_artifacts: Vec::new(),
        }
    }
}

/// Port of `topologicalProviders(providers)`. Errors carry the same message
/// text as the JS `Error` it mirrors (including the `JSON.stringify`-shaped
/// cycle report), since these are diagnostics, not typed refusals.
pub fn topological_providers(providers: &[ProviderNode]) -> Result<Vec<ProviderNode>, String> {
    let by_id: BTreeMap<&str, &ProviderNode> = providers.iter().map(|p| (p.id.as_str(), p)).collect();
    let mut incoming: BTreeMap<String, BTreeSet<String>> = providers
        .iter()
        .map(|p| (p.id.clone(), p.depends_on.iter().cloned().collect()))
        .collect();

    for (id, deps) in &incoming {
        for dependency in deps {
            if !by_id.contains_key(dependency.as_str()) {
                return Err(format!("provider {id} depends on unknown {dependency}"));
            }
            if dependency == id {
                return Err(format!("provider {id} depends on itself"));
            }
        }
    }

    // JS uses an array `ready` with `.shift()` (FIFO) and keeps it sorted
    // after every push, so the next popped id is always the lexicographically
    // smallest currently-ready one.
    let mut ready: Vec<String> = incoming
        .iter()
        .filter(|(_, deps)| deps.is_empty())
        .map(|(id, _)| id.clone())
        .collect();
    ready.sort();

    let mut ordered: Vec<ProviderNode> = Vec::new();
    let mut ordered_ids: BTreeSet<String> = BTreeSet::new();

    while !ready.is_empty() {
        let id = ready.remove(0);
        ordered.push((*by_id.get(id.as_str()).expect("id came from incoming map")).clone());
        ordered_ids.insert(id.clone());
        for (other_id, deps) in incoming.iter_mut() {
            let removed = deps.remove(&id);
            if !removed || !deps.is_empty() {
                continue;
            }
            if !ordered_ids.contains(other_id) && !ready.contains(other_id) {
                ready.push(other_id.clone());
                ready.sort();
            }
        }
    }

    if ordered.len() != providers.len() {
        let mut cyclic: Vec<(String, Vec<String>)> = incoming
            .into_iter()
            .filter(|(id, deps)| !deps.is_empty() && !ordered_ids.contains(id))
            .map(|(id, deps)| {
                let mut d: Vec<String> = deps.into_iter().collect();
                d.sort();
                (id, d)
            })
            .collect();
        cyclic.sort_by(|a, b| a.0.cmp(&b.0));
        let json = serde_json::to_string(
            &cyclic
                .into_iter()
                .map(|(id, deps)| serde_json::json!({"id": id, "dependsOn": deps}))
                .collect::<Vec<_>>(),
        )
        .expect("cycle report always serializes");
        return Err(format!("provider dependency cycle: {json}"));
    }
    Ok(ordered)
}

/// One entry of the Security Appendix Phase 7 role/output authority table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RoleAuthority {
    pub candidates: bool,
    pub hypotheses: bool,
    pub verdicts: bool,
    pub findings: bool,
}

/// Mirrors `ROLE_OUTPUT_AUTHORITY`. Order/membership match JS exactly.
pub fn role_output_authority(role: &str) -> Option<RoleAuthority> {
    Some(match role {
        "model-builder" => RoleAuthority { candidates: false, hypotheses: false, verdicts: false, findings: false },
        "candidate-generator" => RoleAuthority { candidates: true, hypotheses: false, verdicts: false, findings: false },
        "hypothesis-generator" => RoleAuthority { candidates: false, hypotheses: true, verdicts: false, findings: false },
        "adjudicator" => RoleAuthority { candidates: false, hypotheses: false, verdicts: true, findings: false },
        "variant-analyzer" => RoleAuthority { candidates: false, hypotheses: false, verdicts: false, findings: false },
        "evidence-synthesizer" => RoleAuthority { candidates: false, hypotheses: false, verdicts: false, findings: true },
        "deterministic" => RoleAuthority { candidates: true, hypotheses: false, verdicts: false, findings: true },
        _ => return None,
    })
}

const ARTIFACT_KEYS: &[(&str, fn(&RoleAuthority) -> bool)] = &[
    ("security-candidates", |a| a.candidates),
    ("attack-path-hypotheses", |a| a.hypotheses),
    ("security-verdicts", |a| a.verdicts),
    ("findings", |a| a.findings),
];

/// Port of `validateRoleOutput(provider)`.
pub fn validate_role_output(provider: &ProviderNode) -> Result<bool, String> {
    let authority = role_output_authority(&provider.role)
        .ok_or_else(|| format!("provider {} has unknown role {}", provider.id, provider.role))?;
    for (artifact, allowed) in ARTIFACT_KEYS {
        if provider.produces.iter().any(|p| p == artifact) && !allowed(&authority) {
            return Err(format!(
                "provider {} role {} may not produce {artifact}",
                provider.id, provider.role
            ));
        }
    }
    Ok(true)
}

struct ProducerEntry {
    id: String,
    non_singleton: bool,
}

/// Port of `validateProviderDag(providers)`.
pub fn validate_provider_dag(providers: &[ProviderNode]) -> Result<bool, String> {
    let mut producers: BTreeMap<String, ProducerEntry> = BTreeMap::new();
    for provider in providers {
        validate_role_output(provider)?;
        for artifact in &provider.produces {
            if let Some(existing) = producers.get(artifact) {
                if !existing.non_singleton {
                    return Err(format!(
                        "artifact {artifact} is produced by both {} and {}",
                        existing.id, provider.id
                    ));
                }
            } else {
                producers.insert(
                    artifact.clone(),
                    ProducerEntry {
                        id: provider.id.clone(),
                        non_singleton: provider.non_singleton_artifacts.iter().any(|a| a == artifact),
                    },
                );
            }
        }
    }
    let produced: BTreeSet<&String> = producers.keys().collect();
    for provider in providers {
        for artifact in &provider.consumes {
            if !produced.contains(artifact) {
                return Err(format!(
                    "provider {} consumes unproduced artifact {artifact}",
                    provider.id
                ));
            }
        }
    }
    topological_providers(providers)?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node(id: &str, role: &str, deps: &[&str]) -> ProviderNode {
        let mut n = ProviderNode::new(id, role);
        n.depends_on = deps.iter().map(|s| s.to_string()).collect();
        n
    }

    #[test]
    fn topological_order_is_deterministic_and_lexicographic_among_ready_nodes() {
        let providers = vec![
            node("c", "deterministic", &["a", "b"]),
            node("b", "deterministic", &["a"]),
            node("a", "deterministic", &[]),
        ];
        let ordered = topological_providers(&providers).unwrap();
        let ids: Vec<&str> = ordered.iter().map(|p| p.id.as_str()).collect();
        assert_eq!(ids, vec!["a", "b", "c"]);
    }

    #[test]
    fn unknown_dependency_errors() {
        let providers = vec![node("a", "deterministic", &["ghost"])];
        let err = topological_providers(&providers).unwrap_err();
        assert_eq!(err, "provider a depends on unknown ghost");
    }

    #[test]
    fn self_dependency_errors() {
        let providers = vec![node("a", "deterministic", &["a"])];
        let err = topological_providers(&providers).unwrap_err();
        assert_eq!(err, "provider a depends on itself");
    }

    #[test]
    fn cycle_errors_with_json_report() {
        let providers = vec![node("a", "deterministic", &["b"]), node("b", "deterministic", &["a"])];
        let err = topological_providers(&providers).unwrap_err();
        assert!(err.starts_with("provider dependency cycle: "));
        assert!(err.contains(r#""id":"a""#));
        assert!(err.contains(r#""id":"b""#));
    }

    #[test]
    fn validate_role_output_rejects_unauthorized_production() {
        let mut p = ProviderNode::new("p1", "model-builder");
        p.produces = vec!["security-candidates".to_string()];
        let err = validate_role_output(&p).unwrap_err();
        assert_eq!(err, "provider p1 role model-builder may not produce security-candidates");
    }

    #[test]
    fn validate_role_output_rejects_unknown_role() {
        let p = ProviderNode::new("p1", "not-a-role");
        let err = validate_role_output(&p).unwrap_err();
        assert_eq!(err, "provider p1 has unknown role not-a-role");
    }

    #[test]
    fn validate_provider_dag_rejects_duplicate_singleton_producer() {
        let mut a = ProviderNode::new("a", "deterministic");
        a.produces = vec!["x".to_string()];
        let mut b = ProviderNode::new("b", "deterministic");
        b.produces = vec!["x".to_string()];
        let err = validate_provider_dag(&[a, b]).unwrap_err();
        assert_eq!(err, "artifact x is produced by both a and b");
    }

    #[test]
    fn validate_provider_dag_allows_non_singleton_duplicate_producer() {
        let mut a = ProviderNode::new("a", "deterministic");
        a.produces = vec!["x".to_string()];
        a.non_singleton_artifacts = vec!["x".to_string()];
        let mut b = ProviderNode::new("b", "deterministic");
        b.produces = vec!["x".to_string()];
        assert!(validate_provider_dag(&[a, b]).is_ok());
    }

    #[test]
    fn validate_provider_dag_rejects_unproduced_consumed_artifact() {
        let mut a = ProviderNode::new("a", "deterministic");
        a.consumes = vec!["missing".to_string()];
        let err = validate_provider_dag(&[a]).unwrap_err();
        assert_eq!(err, "provider a consumes unproduced artifact missing");
    }

    #[test]
    fn validate_provider_dag_happy_path() {
        let mut a = ProviderNode::new("a", "deterministic");
        a.produces = vec!["x".to_string()];
        let mut b = ProviderNode::new("b", "deterministic");
        b.depends_on = vec!["a".to_string()];
        b.consumes = vec!["x".to_string()];
        assert!(validate_provider_dag(&[a, b]).is_ok());
    }
}
