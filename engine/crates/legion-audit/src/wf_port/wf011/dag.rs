//! Port of `src/lib/providers/sdk/dag.mjs`.
//!
//! Provider artifact dependency DAG. Validates topological ordering, unknown
//! dependencies, self-dependencies, cycles, unproduced consumed artifacts,
//! duplicate singleton producers, and role/output authority.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::{json, Value};

use super::SdkError;

fn provider_id(provider: &Value) -> String {
    provider
        .get("id")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_owned()
}

fn string_array(value: &Value, key: &str) -> Vec<String> {
    value
        .get(key)
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(|item| item.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default()
}

/// Faithful port of `topologicalProviders`. Returns the providers (cloned)
/// in dependency order.
pub fn topological_providers(providers: &[Value]) -> Result<Vec<Value>, SdkError> {
    let by_id: BTreeMap<String, &Value> = providers
        .iter()
        .map(|provider| (provider_id(provider), provider))
        .collect();

    let mut incoming: BTreeMap<String, BTreeSet<String>> = providers
        .iter()
        .map(|provider| (provider_id(provider), string_array(provider, "dependsOn").into_iter().collect()))
        .collect();

    for (id, deps) in &incoming {
        for dependency in deps {
            if !by_id.contains_key(dependency) {
                return Err(SdkError::new(format!("provider {id} depends on unknown {dependency}")));
            }
            if dependency == id {
                return Err(SdkError::new(format!("provider {id} depends on itself")));
            }
        }
    }

    let mut ready: Vec<String> = incoming
        .iter()
        .filter(|(_, deps)| deps.is_empty())
        .map(|(id, _)| id.clone())
        .collect();
    ready.sort();

    let mut ordered: Vec<Value> = Vec::new();
    let mut ordered_ids: BTreeSet<String> = BTreeSet::new();

    while !ready.is_empty() {
        let id = ready.remove(0);
        ordered.push((*by_id.get(&id).expect("id came from by_id keys")).clone());
        ordered_ids.insert(id.clone());

        // Mirror the JS `for (const [otherId, deps] of incoming)` mutation
        // pass: for every other provider's dependency set, remove `id` and,
        // if that just emptied the set (and it wasn't already ordered or
        // queued), enqueue it.
        let other_ids: Vec<String> = incoming.keys().cloned().collect();
        for other_id in other_ids {
            let deps = incoming.get_mut(&other_id).expect("key from incoming.keys()");
            let removed = deps.remove(&id);
            if !removed || !deps.is_empty() {
                continue;
            }
            if !ordered_ids.contains(&other_id) && !ready.contains(&other_id) {
                ready.push(other_id);
                ready.sort();
            }
        }
    }

    if ordered.len() != providers.len() {
        let mut cyclic: Vec<Value> = incoming
            .iter()
            .filter(|(id, deps)| !deps.is_empty() && !ordered_ids.contains(*id))
            .map(|(id, deps)| {
                let mut sorted_deps: Vec<&String> = deps.iter().collect();
                sorted_deps.sort();
                json!({"id": id, "dependsOn": sorted_deps})
            })
            .collect();
        cyclic.sort_by(|a, b| a["id"].as_str().cmp(&b["id"].as_str()));
        let cyclic_json = Value::Array(cyclic).to_string();
        return Err(SdkError::new(format!("provider dependency cycle: {cyclic_json}")));
    }

    Ok(ordered)
}

/// Role/output authority table from the Security Appendix Phase 7.
pub fn role_output_authority(role: &str) -> Option<[(&'static str, bool); 4]> {
    match role {
        "model-builder" => Some([("candidates", false), ("hypotheses", false), ("verdicts", false), ("findings", false)]),
        "candidate-generator" => Some([("candidates", true), ("hypotheses", false), ("verdicts", false), ("findings", false)]),
        "hypothesis-generator" => Some([("candidates", false), ("hypotheses", true), ("verdicts", false), ("findings", false)]),
        "adjudicator" => Some([("candidates", false), ("hypotheses", false), ("verdicts", true), ("findings", false)]),
        "variant-analyzer" => Some([("candidates", false), ("hypotheses", false), ("verdicts", false), ("findings", false)]),
        "evidence-synthesizer" => Some([("candidates", false), ("hypotheses", false), ("verdicts", false), ("findings", true)]),
        "deterministic" => Some([("candidates", true), ("hypotheses", false), ("verdicts", false), ("findings", true)]),
        _ => None,
    }
}

/// The table itself, for callers that want to inspect it directly (mirrors
/// the exported `ROLE_OUTPUT_AUTHORITY` object).
pub const ROLE_OUTPUT_AUTHORITY: &[&str] = &[
    "model-builder",
    "candidate-generator",
    "hypothesis-generator",
    "adjudicator",
    "variant-analyzer",
    "evidence-synthesizer",
    "deterministic",
];

fn authority_flag(authority: [(&str, bool); 4], key: &str) -> bool {
    authority.iter().find(|(name, _)| *name == key).map(|(_, flag)| *flag).unwrap_or(false)
}

/// Faithful port of `validateRoleOutput`.
pub fn validate_role_output(provider: &Value) -> Result<bool, SdkError> {
    let id = provider_id(provider);
    let role = provider.get("role").and_then(Value::as_str).unwrap_or("");
    let Some(authority) = role_output_authority(role) else {
        return Err(SdkError::new(format!("provider {id} has unknown role {role}")));
    };
    let produced = string_array(provider, "produces");
    if produced.iter().any(|a| a == "security-candidates") && !authority_flag(authority, "candidates") {
        return Err(SdkError::new(format!("provider {id} role {role} may not produce security-candidates")));
    }
    if produced.iter().any(|a| a == "attack-path-hypotheses") && !authority_flag(authority, "hypotheses") {
        return Err(SdkError::new(format!("provider {id} role {role} may not produce attack-path-hypotheses")));
    }
    if produced.iter().any(|a| a == "security-verdicts") && !authority_flag(authority, "verdicts") {
        return Err(SdkError::new(format!("provider {id} role {role} may not produce security-verdicts")));
    }
    if produced.iter().any(|a| a == "findings") && !authority_flag(authority, "findings") {
        return Err(SdkError::new(format!("provider {id} role {role} may not produce findings")));
    }
    Ok(true)
}

/// Faithful port of `validateProviderDag`.
pub fn validate_provider_dag(providers: &[Value]) -> Result<bool, SdkError> {
    // Singleton artifact producers: an artifact kind may be produced by at
    // most one provider unless the artifact is explicitly non-singleton.
    struct ProducerEntry {
        id: String,
        non_singleton: bool,
    }
    let mut producers: BTreeMap<String, ProducerEntry> = BTreeMap::new();
    for provider in providers {
        validate_role_output(provider)?;
        let id = provider_id(provider);
        let non_singleton_artifacts = string_array(provider, "nonSingletonArtifacts");
        for artifact in string_array(provider, "produces") {
            if let Some(existing) = producers.get(&artifact) {
                if !existing.non_singleton {
                    return Err(SdkError::new(format!(
                        "artifact {artifact} is produced by both {} and {id}",
                        existing.id
                    )));
                }
            } else {
                producers.insert(
                    artifact.clone(),
                    ProducerEntry {
                        id: id.clone(),
                        non_singleton: non_singleton_artifacts.contains(&artifact),
                    },
                );
            }
        }
    }

    // Consumed artifacts must be produced by some provider.
    let produced: BTreeSet<&String> = producers.keys().collect();
    for provider in providers {
        let id = provider_id(provider);
        for artifact in string_array(provider, "consumes") {
            if !produced.contains(&artifact) {
                return Err(SdkError::new(format!("provider {id} consumes unproduced artifact {artifact}")));
            }
        }
    }

    topological_providers(providers)?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn p(id: &str, deps: Vec<&str>, produces: Vec<&str>, consumes: Vec<&str>, role: &str) -> Value {
        json!({
            "id": id, "providerVersion": "1.0.0", "role": role, "phase": "runtime",
            "dependsOn": deps, "produces": produces, "consumes": consumes,
            "activation": {"kind": "always"}, "runner": {"kind": "runtime-script"},
            "benchmark": {"status": "unproven", "requiredForCleanClaim": true},
        })
    }

    #[test]
    fn topological_order_respects_dependencies() {
        let ordered = topological_providers(&[
            p("c", vec!["a", "b"], vec![], vec![], "deterministic"),
            p("a", vec![], vec![], vec![], "deterministic"),
            p("b", vec!["a"], vec![], vec![], "deterministic"),
        ])
        .unwrap();
        let ids: Vec<&str> = ordered.iter().map(|p| p["id"].as_str().unwrap()).collect();
        assert_eq!(ids, vec!["a", "b", "c"]);
    }

    #[test]
    fn unknown_dependency_is_rejected() {
        let err = topological_providers(&[p("a", vec!["ghost"], vec![], vec![], "deterministic")]).unwrap_err();
        assert!(err.0.contains("depends on unknown"), "{}", err.0);
    }

    #[test]
    fn self_dependency_is_rejected() {
        let err = topological_providers(&[p("a", vec!["a"], vec![], vec![], "deterministic")]).unwrap_err();
        assert!(err.0.contains("depends on itself"), "{}", err.0);
    }

    #[test]
    fn dependency_cycle_is_rejected() {
        let err = topological_providers(&[
            p("a", vec!["b"], vec![], vec![], "deterministic"),
            p("b", vec!["a"], vec![], vec![], "deterministic"),
        ])
        .unwrap_err();
        assert!(err.0.contains("cycle"), "{}", err.0);
    }

    #[test]
    fn unproduced_consumed_artifact_is_rejected() {
        let err = validate_provider_dag(&[p(
            "a",
            vec![],
            vec![],
            vec!["security-surface-model"],
            "deterministic",
        )])
        .unwrap_err();
        assert!(err.0.contains("consumes unproduced"), "{}", err.0);
    }

    #[test]
    fn duplicate_singleton_producer_is_rejected() {
        let err = validate_provider_dag(&[
            p("a", vec![], vec!["security-candidates"], vec![], "deterministic"),
            p("b", vec![], vec!["security-candidates"], vec![], "deterministic"),
        ])
        .unwrap_err();
        assert!(err.0.contains("produced by both"), "{}", err.0);
    }

    #[test]
    fn role_output_authority_violations_are_rejected() {
        assert!(validate_role_output(&p("a", vec![], vec!["security-candidates"], vec![], "model-builder"))
            .unwrap_err()
            .0
            .contains("may not produce"));
        assert!(validate_role_output(&p("a", vec![], vec!["findings"], vec![], "adjudicator"))
            .unwrap_err()
            .0
            .contains("may not produce"));
        assert!(validate_role_output(&p(
            "a",
            vec![],
            vec!["attack-path-hypotheses"],
            vec![],
            "candidate-generator"
        ))
        .unwrap_err()
        .0
        .contains("may not produce"));
        assert!(validate_role_output(&p("a", vec![], vec!["findings"], vec![], "evidence-synthesizer")).is_ok());
    }

    #[test]
    fn unknown_role_is_rejected() {
        let err = validate_role_output(&json!({"id": "x", "role": "not-a-role", "produces": []})).unwrap_err();
        assert!(err.0.contains("unknown role"), "{}", err.0);
    }

    #[test]
    fn valid_dag_validates_cleanly() {
        let ok = validate_provider_dag(&[
            p("surface", vec![], vec!["security-surface-model"], vec![], "model-builder"),
            p(
                "packs",
                vec!["surface"],
                vec!["security-candidates"],
                vec!["security-surface-model"],
                "candidate-generator",
            ),
        ])
        .unwrap();
        assert!(ok);
    }
}
