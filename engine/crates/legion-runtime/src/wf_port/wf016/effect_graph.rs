//! Port of `src/lib/remediation/effect-graph.mjs`.
//!
//! Patch effect graphs (B7-033). A proposal is only as trustworthy as the
//! blast radius you can name. The effect graph maps a proposal to every
//! file, symbol, configuration key, public surface, content item, design
//! state, flow, runtime surface and security path it can move — then closes
//! over the plan graph to say which providers and families must be re-run
//! before anyone may apply it.

use serde_json::{json, Value};

use super::util::{digest_of, matches_glob, sorted_strings, sorted_unique_strings};

pub const EFFECT_GRAPH_SCHEMA_VERSION: i64 = 1;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub struct EffectGraphError(pub String);

impl std::fmt::Display for EffectGraphError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

fn str_vec(value: &Value, key: &str) -> Vec<String> {
    value
        .get(key)
        .and_then(Value::as_array)
        .map(|arr| arr.iter().filter_map(|v| v.as_str().map(str::to_owned)).collect())
        .unwrap_or_default()
}

/// Faithful port of `matchesPath` (delegates to the shared glob translator).
pub fn matches_path(pattern: &str, path: &str) -> bool {
    matches_glob(pattern, path)
}

/// Transitive closure over the plan's provider dependency graph: a provider
/// that consumes an affected provider is itself affected.
///
/// `plan_graph` is expected to carry a `providers` array of
/// `{ id, dependsOn: [...] }` objects, exactly like the JS `planGraph`.
pub fn compute_closure(plan_graph: &Value, seeds: &[String]) -> Vec<String> {
    let providers = plan_graph.get("providers").and_then(Value::as_array).cloned().unwrap_or_default();
    let mut closure: std::collections::BTreeSet<String> = seeds.iter().cloned().collect();
    let mut grew = true;
    while grew {
        grew = false;
        for provider in &providers {
            let Some(id) = provider.get("id").and_then(Value::as_str) else { continue };
            if closure.contains(id) {
                continue;
            }
            let depends_on = str_vec(provider, "dependsOn");
            if depends_on.iter().any(|dep| closure.contains(dep)) {
                closure.insert(id.to_owned());
                grew = true;
            }
        }
    }
    closure.into_iter().collect()
}

fn seed_providers(plan_graph: &Value, changed_files: &[String]) -> Vec<String> {
    let providers = plan_graph.get("providers").and_then(Value::as_array).cloned().unwrap_or_default();
    providers
        .iter()
        .filter(|provider| {
            let paths = str_vec(provider, "paths");
            paths.iter().any(|pattern| changed_files.iter().any(|file| matches_path(pattern, file)))
        })
        .filter_map(|provider| provider.get("id").and_then(Value::as_str).map(str::to_owned))
        .collect()
}

/// Input to [`build_effect_graph`], mirroring the JS destructured parameter
/// object. List fields default to empty like JS's default `= []`.
#[derive(Debug, Clone, Default)]
pub struct BuildEffectGraphInput {
    pub proposal: Value,
    pub plan_graph: Value,
    pub binding: Value,
    pub observed_public_surface_changes: Vec<String>,
    pub content_items: Vec<String>,
    pub design_states: Vec<String>,
    pub flows: Vec<String>,
    pub runtime_surfaces: Vec<String>,
    pub security_paths: Vec<String>,
    pub residual_risks: Vec<String>,
}

/// Faithful port of `buildEffectGraph`.
pub fn build_effect_graph(input: BuildEffectGraphInput) -> Result<Value, EffectGraphError> {
    let patch_digest = input.proposal.get("patch").and_then(|p| p.get("digest"));
    let patch_digest = match patch_digest {
        Some(Value::String(s)) => s.clone(),
        _ => return Err(EffectGraphError("an effect graph requires the proposal patch digest".to_string())),
    };

    let changed_files = sorted_unique_strings(str_vec(&input.proposal, "targetPaths"));
    if changed_files.is_empty() {
        return Err(EffectGraphError("an effect graph requires at least one target path".to_string()));
    }

    let changes: Vec<Value> = input.proposal.get("changes").and_then(Value::as_array).cloned().unwrap_or_default();
    let declared_public_surface_changes = sorted_unique_strings(str_vec(&input.proposal, "publicSurfaceChanges"));
    let observed = sorted_unique_strings(input.observed_public_surface_changes.clone());

    let seeds = seed_providers(&input.plan_graph, &changed_files);
    let affected_providers = compute_closure(&input.plan_graph, &seeds);
    let providers = input.plan_graph.get("providers").and_then(Value::as_array).cloned().unwrap_or_default();
    let provider_by_id: std::collections::HashMap<String, Value> = providers
        .into_iter()
        .filter_map(|p| p.get("id").and_then(Value::as_str).map(|id| (id.to_owned(), p.clone())))
        .collect();

    let changed_symbols = sorted_unique_strings(changes.iter().flat_map(|c| str_vec(c, "symbols")));
    let changed_config = sorted_unique_strings(changes.iter().filter(|c| c.get("kind").and_then(Value::as_str) == Some("config")).filter_map(|c| {
        c.get("keyPath").and_then(Value::as_array).map(|parts| {
            parts.iter().filter_map(|v| v.as_str()).collect::<Vec<_>>().join(".")
        })
    }));

    let mut public_surface_changes: Vec<String> = declared_public_surface_changes.clone();
    public_surface_changes.extend(observed.clone());
    let public_surface_changes = sorted_unique_strings(public_surface_changes);

    let unplanned_public_surface_changes: Vec<String> =
        sorted_strings(observed.iter().filter(|item| !declared_public_surface_changes.contains(item)).cloned().collect());

    let mut content_items = input.content_items.clone();
    content_items.extend(changes.iter().filter_map(|c| c.get("contentItemId").and_then(Value::as_str).map(str::to_owned)));
    let content_items = sorted_unique_strings(content_items);

    let affected_families = sorted_unique_strings(
        affected_providers
            .iter()
            .filter_map(|id| provider_by_id.get(id).and_then(|p| p.get("family")).and_then(Value::as_str).map(str::to_owned)),
    );
    let required_providers: Vec<String> = affected_providers
        .iter()
        .filter(|id| provider_by_id.get(*id).and_then(|p| p.get("requiredForCleanClaim")).and_then(Value::as_bool) == Some(true))
        .cloned()
        .collect();
    let required_gates = sorted_unique_strings(
        input
            .plan_graph
            .get("baselineGates")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default()
            .iter()
            .filter(|gate| gate.get("requiredForApply").and_then(Value::as_bool) == Some(true))
            .filter_map(|gate| gate.get("id").and_then(Value::as_str).map(str::to_owned)),
    );

    let mut body = json!({
        "schemaVersion": EFFECT_GRAPH_SCHEMA_VERSION,
        "kind": "legion-patch-effect-graph",
        "proposalId": input.proposal.get("id").cloned().unwrap_or(Value::Null),
        "findingIds": sorted_unique_strings(str_vec(&input.proposal, "findingIds")),
        "patchDigest": patch_digest,
        "changedFiles": changed_files,
        "changedSymbols": changed_symbols,
        "changedConfig": changed_config,
        "publicSurfaceChanges": public_surface_changes,
        "unplannedPublicSurfaceChanges": unplanned_public_surface_changes,
        "contentItems": content_items,
        "designStates": sorted_unique_strings(input.design_states.clone()),
        "flows": sorted_unique_strings(input.flows.clone()),
        "affectedProviders": affected_providers,
        "affectedFamilies": affected_families,
        "requiredProviders": required_providers,
        "requiredGates": required_gates,
        "runtimeSurfaces": sorted_unique_strings(input.runtime_surfaces.clone()),
        "securityPaths": sorted_unique_strings(input.security_paths.clone()),
        "residualRisks": sorted_unique_strings(input.residual_risks.clone()),
        "complete": true,
        "binding": input.binding,
    });
    let digest = digest_of("effect-graph", &body);
    body.as_object_mut().expect("body is an object").insert("digest".to_string(), Value::String(digest));
    Ok(body)
}

/// Application is blocked by a public-surface change nobody planned for.
/// Accepts both the current effect graph and the legacy `patchEffectGraph`
/// shape.
pub fn blocks_auto_apply(effect_graph: &Value) -> bool {
    if let Some(arr) = effect_graph.get("unplannedPublicSurfaceChanges").and_then(Value::as_array) {
        return !arr.is_empty();
    }
    !effect_graph.get("publicSurfaceChanges").and_then(Value::as_array).map(|a| a.is_empty()).unwrap_or(true)
}

/// Faithful port of `buildEffectGraphSchema` (a static JSON Schema document).
pub fn build_effect_graph_schema() -> Value {
    let strings = json!({ "type": "array", "items": { "type": "string" } });
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://orthic.dev/schemas/remediation/effect-graph-v1.json",
        "title": "RemediationEffectGraphV1",
        "type": "object",
        "required": [
            "schemaVersion", "kind", "proposalId", "findingIds", "patchDigest", "changedFiles",
            "changedSymbols", "changedConfig", "publicSurfaceChanges", "unplannedPublicSurfaceChanges",
            "contentItems", "designStates", "flows", "affectedProviders", "affectedFamilies",
            "requiredProviders", "requiredGates", "runtimeSurfaces", "securityPaths", "residualRisks",
            "complete", "binding", "digest",
        ],
        "properties": {
            "schemaVersion": { "const": EFFECT_GRAPH_SCHEMA_VERSION },
            "kind": { "const": "legion-patch-effect-graph" },
            "proposalId": { "type": "string" },
            "findingIds": strings,
            "patchDigest": { "type": "string", "pattern": "^sha256:" },
            "changedFiles": { "type": "array", "items": { "type": "string" }, "minItems": 1 },
            "changedSymbols": strings,
            "changedConfig": strings,
            "publicSurfaceChanges": strings,
            "unplannedPublicSurfaceChanges": strings,
            "contentItems": strings,
            "designStates": strings,
            "flows": strings,
            "affectedProviders": strings,
            "affectedFamilies": strings,
            "requiredProviders": strings,
            "requiredGates": strings,
            "runtimeSurfaces": strings,
            "securityPaths": strings,
            "residualRisks": strings,
            "complete": { "type": "boolean" },
            "binding": { "type": "object" },
            "digest": { "type": "string", "pattern": "^sha256:" },
        },
        "additionalProperties": false,
    })
}

// ---------------------------------------------------------------------------
// Pre-existing helper retained for its existing callers.
// ---------------------------------------------------------------------------

/// Input to [`patch_effect_graph`] (the legacy pre-`buildEffectGraph` shape).
#[derive(Debug, Clone, Default)]
pub struct PatchEffectGraphInput {
    pub patch_digest: Value,
    pub finding_ids: Vec<String>,
    pub changed_files: Vec<String>,
    pub changed_symbols: Vec<String>,
    pub public_surface_changes: Vec<String>,
    pub affected_providers: Vec<String>,
    pub required_tests: Vec<String>,
    pub runtime_surfaces: Vec<String>,
    pub security_paths: Vec<String>,
    pub residual_risks: Vec<String>,
}

pub fn patch_effect_graph(input: PatchEffectGraphInput) -> Value {
    json!({
        "schemaVersion": 1,
        "kind": "legion-patch-effect-graph",
        "patchDigest": input.patch_digest,
        "findingIds": sorted_unique_strings(input.finding_ids),
        "changedFiles": sorted_unique_strings(input.changed_files),
        "changedSymbols": sorted_unique_strings(input.changed_symbols),
        "publicSurfaceChanges": sorted_unique_strings(input.public_surface_changes),
        "affectedProviders": sorted_unique_strings(input.affected_providers),
        "requiredTests": sorted_unique_strings(input.required_tests),
        "runtimeSurfaces": sorted_unique_strings(input.runtime_surfaces),
        "securityPaths": sorted_unique_strings(input.security_paths),
        "residualRisks": sorted_unique_strings(input.residual_risks),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plan_graph() -> Value {
        json!({
            "providers": [
                { "id": "p1", "paths": ["src/a/**"], "family": "security", "dependsOn": [], "requiredForCleanClaim": true },
                { "id": "p2", "paths": ["src/b/**"], "family": "ux", "dependsOn": ["p1"], "requiredForCleanClaim": false },
                { "id": "p3", "paths": [], "family": "other", "dependsOn": ["p2"], "requiredForCleanClaim": false },
            ],
            "baselineGates": [
                { "id": "g1", "requiredForApply": true },
                { "id": "g2", "requiredForApply": false },
            ],
        })
    }

    #[test]
    fn compute_closure_transitively_includes_dependents() {
        let closure = compute_closure(&plan_graph(), &["p1".to_string()]);
        assert_eq!(closure, vec!["p1".to_string(), "p2".to_string(), "p3".to_string()]);
    }

    #[test]
    fn matches_path_supports_globstar() {
        assert!(matches_path("src/a/**", "src/a/b/c.js"));
        assert!(!matches_path("src/a/**", "src/b/c.js"));
        assert!(matches_path("src/*.js", "src/a.js"));
        assert!(!matches_path("src/*.js", "src/a/b.js"));
    }

    #[test]
    fn build_effect_graph_computes_closure_and_flags_unplanned_surface() {
        let proposal = json!({
            "id": "prop-1",
            "findingIds": ["f1"],
            "patch": { "digest": "sha256:deadbeef" },
            "targetPaths": ["src/a/x.js"],
            "publicSurfaceChanges": ["api:/v1/foo"],
            "changes": [{ "symbols": ["Foo"], "kind": "config", "keyPath": ["cookie", "sameSite"] }],
        });
        let result = build_effect_graph(BuildEffectGraphInput {
            proposal,
            plan_graph: plan_graph(),
            binding: json!({ "runId": "r1" }),
            observed_public_surface_changes: vec!["api:/v1/foo".to_string(), "api:/v1/bar".to_string()],
            ..Default::default()
        })
        .expect("builds");
        assert_eq!(result["affectedProviders"], json!(["p1", "p2", "p3"]));
        assert_eq!(result["affectedFamilies"], json!(["other", "security", "ux"]));
        assert_eq!(result["requiredProviders"], json!(["p1"]));
        assert_eq!(result["requiredGates"], json!(["g1"]));
        assert_eq!(result["changedConfig"], json!(["cookie.sameSite"]));
        assert_eq!(result["unplannedPublicSurfaceChanges"], json!(["api:/v1/bar"]));
        assert!(blocks_auto_apply(&result));
        assert!(result["digest"].as_str().unwrap().starts_with("sha256:"));
    }

    #[test]
    fn build_effect_graph_requires_patch_digest() {
        let err = build_effect_graph(BuildEffectGraphInput {
            proposal: json!({ "targetPaths": ["a.js"] }),
            plan_graph: plan_graph(),
            binding: json!({}),
            ..Default::default()
        })
        .unwrap_err();
        assert_eq!(err.0, "an effect graph requires the proposal patch digest");
    }

    #[test]
    fn build_effect_graph_requires_target_path() {
        let err = build_effect_graph(BuildEffectGraphInput {
            proposal: json!({ "patch": { "digest": "sha256:x" }, "targetPaths": [] }),
            plan_graph: plan_graph(),
            binding: json!({}),
            ..Default::default()
        })
        .unwrap_err();
        assert_eq!(err.0, "an effect graph requires at least one target path");
    }

    #[test]
    fn blocks_auto_apply_accepts_legacy_shape() {
        assert!(blocks_auto_apply(&json!({ "publicSurfaceChanges": ["x"] })));
        assert!(!blocks_auto_apply(&json!({ "publicSurfaceChanges": [] })));
    }

    #[test]
    fn schema_lists_required_fields() {
        let schema = build_effect_graph_schema();
        let required = schema["required"].as_array().unwrap();
        assert!(required.iter().any(|v| v == "digest"));
        assert_eq!(schema["properties"]["schemaVersion"]["const"], json!(1));
    }
}
