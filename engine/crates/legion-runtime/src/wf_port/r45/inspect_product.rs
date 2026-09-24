//! Port of `src/lib/core/inspect-product.mjs`'s own composition logic (see
//! `super::mod` doc comment for what is taken as caller-supplied input
//! rather than computed here, and why).
//!
//! JS source recap (the parts ported below):
//! ```js
//! const targets = portfolio.targets.map((target) => {
//!   const value = {
//!     ...target,
//!     componentIds: components.components
//!       .filter(({ targetIds = [] }) => targetIds.includes(target.id))
//!       .map(({ id }) => id).sort(),
//!     stackIds: stacks.stacks
//!       .filter(({ targetIds = [] }) => targetIds.includes(target.id))
//!       .map(({ id }) => id).sort(),
//!   };
//!   delete value.digest;
//!   return { ...value, digest: digest(value) };
//! });
//! const portfolioValue = { ...portfolio, targets };
//! delete portfolioValue.digest;
//! portfolio = { ...portfolioValue, digest: digest(portfolioValue) };
//! ...
//! const gaps = [
//!   ...(releaseContract.missingDeclarations ?? []).map((field) => ({ kind: 'release-contract-missing', field })),
//!   ...(productContext.gaps ?? []),
//!   ...(journeys.gaps ?? []),
//!   ...(stacks.coverage.unknownStacks ?? []).map((id) => ({ kind: 'unknown-stack', id })),
//! ];
//! const reportSkeleton = {
//!   targetIds: portfolio.targets.map(({ id }) => id),
//!   componentIds: components.components.map(({ id }) => id),
//!   stackIds: stacks.stacks.map(({ id }) => id),
//!   externalSystemIds: externalSystems.systems.map(({ id }) => id),
//!   controlIds: baseline.controls.map(({ id }) => id),
//!   scenarioIds: scenarios.scenarios.map(({ id }) => id),
//!   gaps,
//! };
//! return { schemaVersion: 1, kind: 'legion-product-inspection', portfolio, components, stacks,
//!   externalSystems, releaseContract, productContext, journeys, baseline, capabilities,
//!   claimImpact, scenarios, reportSkeleton };
//! ```

use crate::l3_inventory::{
    components::extract_components, external_systems::discover_external_systems, journeys::build_journeys,
    product_context::build_product_context, product_targets::{build_portfolio, discover_targets},
    release_contract::merge_release_contract, stacks::build_stack_graph,
};
use crate::p5_core::controls_support;
use crate::wf_port::w2_038::registry::load_control_packs;
use crate::wf_port::w2_038::scenarios::compile_scenarios;
use crate::wf_port::w2_039::binding::digest;
use crate::wf_port::w2_041::control_baseline::{compile_baseline_and_impacts_json, cv_to_json, json_to_cv};
use serde_json::{json, Map, Value};
use std::path::Path;

fn as_str(value: &Value) -> Option<&str> {
    value.as_str()
}

fn arr<'a>(value: &'a Value, key: &str) -> &'a [Value] {
    value
        .get(key)
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or(&[])
}

fn ids_with_target(items: &[Value], target_id: &str) -> Vec<String> {
    let mut out: Vec<String> = items
        .iter()
        .filter(|item| {
            item.get("targetIds")
                .and_then(Value::as_array)
                .map(|ids| ids.iter().any(|v| as_str(v) == Some(target_id)))
                .unwrap_or(false)
        })
        .filter_map(|item| item.get("id").and_then(as_str).map(str::to_string))
        .collect();
    out.sort();
    out
}

/// Port of the `portfolio.targets.map(...)` / `portfolio = {...}` block:
/// recomputes each target's `componentIds`/`stackIds` fan-in and re-digests
/// each target and the portfolio as a whole.
///
/// `portfolio` must be a JSON object with a `targets` array; `components`
/// must have a `components` array; `stacks` must have a `stacks` array
/// (matching `components.components` / `stacks.stacks` in the JS source).
pub fn recompute_portfolio_digests(portfolio: &Value, components: &Value, stacks: &Value) -> Value {
    let component_items = arr(components, "components");
    let stack_items = arr(stacks, "stacks");

    let targets: Vec<Value> = arr(portfolio, "targets")
        .iter()
        .map(|target| {
            let target_id = target.get("id").and_then(as_str).unwrap_or("").to_string();
            let mut map: Map<String, Value> = match target {
                Value::Object(m) => m.clone(),
                _ => Map::new(),
            };
            map.remove("digest");
            map.insert(
                "componentIds".to_string(),
                json!(ids_with_target(component_items, &target_id)),
            );
            map.insert(
                "stackIds".to_string(),
                json!(ids_with_target(stack_items, &target_id)),
            );
            let value = Value::Object(map);
            let d = digest(&value);
            let mut with_digest = match value {
                Value::Object(m) => m,
                _ => Map::new(),
            };
            with_digest.insert("digest".to_string(), Value::String(d));
            Value::Object(with_digest)
        })
        .collect();

    let mut portfolio_map: Map<String, Value> = match portfolio {
        Value::Object(m) => m.clone(),
        _ => Map::new(),
    };
    portfolio_map.remove("digest");
    portfolio_map.insert("targets".to_string(), Value::Array(targets));
    let portfolio_value = Value::Object(portfolio_map);
    let d = digest(&portfolio_value);
    let mut final_map = match portfolio_value {
        Value::Object(m) => m,
        _ => Map::new(),
    };
    final_map.insert("digest".to_string(), Value::String(d));
    Value::Object(final_map)
}

/// Port of the `gaps` array assembly.
pub fn build_gaps(release_contract: &Value, product_context: &Value, journeys: &Value, stacks: &Value) -> Vec<Value> {
    let mut gaps = Vec::new();
    for field in arr(release_contract, "missingDeclarations") {
        gaps.push(json!({"kind": "release-contract-missing", "field": field}));
    }
    for gap in arr(product_context, "gaps") {
        gaps.push(gap.clone());
    }
    for gap in arr(journeys, "gaps") {
        gaps.push(gap.clone());
    }
    let coverage = stacks.get("coverage").cloned().unwrap_or(Value::Null);
    for id in arr(&coverage, "unknownStacks") {
        gaps.push(json!({"kind": "unknown-stack", "id": id}));
    }
    gaps
}

fn ids_of(items: &[Value]) -> Vec<Value> {
    items.iter().filter_map(|v| v.get("id").cloned()).collect()
}

/// Every input `inspect_product` needs, mirroring `inspectProduct(options,
/// host)`'s locals after the (unported, caller-supplied) discovery/build
/// steps have already run. `portfolio`/`components`/`stacks` are the
/// pre-digest-recompute shapes (i.e. `buildPortfolio`/`extractComponents`/
/// `buildStackGraph`'s direct output); this function performs the
/// digest-recompute step itself via [`recompute_portfolio_digests`].
pub struct InspectProductInputs<'a> {
    pub portfolio: &'a Value,
    pub components: &'a Value,
    pub stacks: &'a Value,
    pub external_systems: &'a Value,
    pub release_contract: &'a Value,
    pub product_context: &'a Value,
    pub journeys: &'a Value,
    pub baseline: &'a Value,
    pub capabilities: &'a Value,
    pub claim_impact: &'a Value,
    pub scenarios: &'a Value,
}

/// Port of `inspectProduct`'s final assembly: recomputes portfolio/target
/// digests, builds the `gaps` list, the `reportSkeleton`, and the
/// `legion-product-inspection` envelope.
pub fn inspect_product(inputs: InspectProductInputs<'_>) -> Value {
    let InspectProductInputs {
        portfolio,
        components,
        stacks,
        external_systems,
        release_contract,
        product_context,
        journeys,
        baseline,
        capabilities,
        claim_impact,
        scenarios,
    } = inputs;

    let portfolio = recompute_portfolio_digests(portfolio, components, stacks);
    let gaps = build_gaps(release_contract, product_context, journeys, stacks);

    let report_skeleton = json!({
        "targetIds": ids_of(arr(&portfolio, "targets")),
        "componentIds": ids_of(arr(components, "components")),
        "stackIds": ids_of(arr(stacks, "stacks")),
        "externalSystemIds": ids_of(arr(external_systems, "systems")),
        "controlIds": ids_of(arr(baseline, "controls")),
        "scenarioIds": ids_of(arr(scenarios, "scenarios")),
        "gaps": gaps,
    });

    json!({
        "schemaVersion": 1,
        "kind": "legion-product-inspection",
        "portfolio": portfolio,
        "components": components,
        "stacks": stacks,
        "externalSystems": external_systems,
        "releaseContract": release_contract,
        "productContext": product_context,
        "journeys": journeys,
        "baseline": baseline,
        "capabilities": capabilities,
        "claimImpact": claim_impact,
        "scenarios": scenarios,
        "reportSkeleton": report_skeleton,
    })
}

/// Raw inputs to [`inspect_product_from_projection`], mirroring
/// `inspectProduct(options, host)`'s `options` fields.
pub struct InspectProductOptions<'a> {
    pub projection: &'a Value,
    pub declarations: Vec<Value>,
    pub target_relations: Vec<Value>,
    pub target_conflicts: Vec<Value>,
    pub material_deliverables: Vec<Value>,
    pub binding: &'a Value,
    /// `options.releaseContract`: either an already-merged
    /// `{kind: "legion-release-contract", ...}` object (used as-is, matching
    /// `releaseContract.kind === 'legion-release-contract'` in JS) or the
    /// raw `{observed, declared, policy, externalEvidence}` shape to merge.
    pub release_contract: &'a Value,
    /// `options.packs`. `None` mirrors the JS default `options.packs ??
    /// await loadControlPacks(ROOT)`: packs are loaded from `repo_root`
    /// (the directory containing `registry/controls/packs/index.json`,
    /// i.e. the JS `ROOT` = `fileURLToPath(new URL('../..',
    /// import.meta.url))` two levels up from `src/lib/core`) via
    /// `w2_038::registry::load_control_packs`.
    pub packs: Option<Vec<Value>>,
    pub repo_root: &'a Path,
    pub host: &'a Value,
    pub now_ms: Option<i64>,
}

/// Port of `inspectProduct(options, host)`, wired to the real ported
/// dependencies: `l3_inventory::product_targets::{discover_targets,
/// build_portfolio}`, `l3_inventory::components::extract_components`,
/// `l3_inventory::stacks::build_stack_graph`,
/// `l3_inventory::external_systems::discover_external_systems`,
/// `l3_inventory::release_contract::merge_release_contract`,
/// `l3_inventory::product_context::build_product_context`,
/// `l3_inventory::journeys::build_journeys`, and
/// `w2_041::control_baseline::compile_baseline_and_impacts_json` (itself
/// `w2_038::baseline::compile_baseline` +
/// `p5_core::controls_evidence::{evidence_capabilities,
/// capability_impacts}`), `w2_038::registry::load_control_packs`, and
/// `w2_038::scenarios::compile_scenarios`.
pub fn inspect_product_from_projection(options: InspectProductOptions<'_>) -> Result<Value, String> {
    let candidates = discover_targets(options.projection, options.binding);
    let portfolio_raw = build_portfolio(
        candidates,
        options.declarations,
        options.target_relations,
        options.target_conflicts,
        options.material_deliverables,
        options.binding.clone(),
    )
    .map_err(|e| e.to_string())?;
    let components = extract_components(&portfolio_raw, options.projection, options.binding).map_err(|e| e.to_string())?;
    let stacks = build_stack_graph(&portfolio_raw, &components, options.projection, options.binding);
    let portfolio = recompute_portfolio_digests(&portfolio_raw, &components, &stacks);

    let external_systems = discover_external_systems(options.projection, &components, options.binding);

    let release_contract = if options.release_contract.get("kind").and_then(as_str) == Some("legion-release-contract") {
        options.release_contract.clone()
    } else {
        let observed = options.release_contract.get("observed").cloned().unwrap_or(json!({}));
        let declared = options.release_contract.get("declared").cloned().unwrap_or(json!({}));
        let policy = options.release_contract.get("policy").cloned().unwrap_or(json!({}));
        let external_evidence = options
            .release_contract
            .get("externalEvidence")
            .cloned()
            .unwrap_or(json!({}));
        merge_release_contract(observed, declared, policy, external_evidence, options.binding.clone())
            .map_err(|e| e.to_string())?
    };

    let product_context = build_product_context(options.projection, &release_contract);
    let journeys = build_journeys(&portfolio, &release_contract, options.projection, options.binding);

    let packs: Vec<Value> = match options.packs {
        Some(packs) => packs,
        None => load_control_packs(options.repo_root)?.iter().map(cv_to_json).collect(),
    };

    let stacks_list: Vec<Value> = arr(&stacks, "stacks").to_vec();
    let (baseline, capabilities, claim_impact) = compile_baseline_and_impacts_json(
        &packs,
        &portfolio,
        &components,
        &stacks_list,
        &release_contract,
        Some(options.binding),
        options.host,
        options.now_ms,
    )?;

    // Port of:
    // ```js
    // const scenarios = compileScenarios({
    //   baseline, journeys: journeys.journeys, capabilities, binding,
    //   dimensions: { environment: releaseContract.environments,
    //                 role: releaseContract.roles,
    //                 platform: releaseContract.supportedPlatforms },
    // });
    // ```
    let baseline_cv = json_to_cv(&baseline);
    let journeys_cv: Vec<controls_support::Value> = arr(&journeys, "journeys").iter().map(json_to_cv).collect();
    let capabilities_cv: Vec<controls_support::Value> = capabilities
        .as_array()
        .into_iter()
        .flatten()
        .map(json_to_cv)
        .collect();
    let binding_cv = json_to_cv(options.binding);
    let binding_cv_opt = if matches!(binding_cv, controls_support::Value::Null) {
        None
    } else {
        Some(binding_cv)
    };
    let mut dimensions: std::collections::BTreeMap<String, Vec<controls_support::Value>> = std::collections::BTreeMap::new();
    dimensions.insert(
        "environment".to_string(),
        arr(&release_contract, "environments").iter().map(json_to_cv).collect(),
    );
    dimensions.insert(
        "role".to_string(),
        arr(&release_contract, "roles").iter().map(json_to_cv).collect(),
    );
    dimensions.insert(
        "platform".to_string(),
        arr(&release_contract, "supportedPlatforms").iter().map(json_to_cv).collect(),
    );
    let scenarios_cv = compile_scenarios(
        &baseline_cv,
        &journeys_cv,
        &capabilities_cv,
        binding_cv_opt.as_ref(),
        &dimensions,
        &[],
        &[],
    )?;
    let scenarios = cv_to_json(&scenarios_cv);

    Ok(inspect_product(InspectProductInputs {
        portfolio: &portfolio,
        components: &components,
        stacks: &stacks,
        external_systems: &external_systems,
        release_contract: &release_contract,
        product_context: &product_context,
        journeys: &journeys,
        baseline: &baseline,
        capabilities: &capabilities,
        claim_impact: &claim_impact,
        scenarios: &scenarios,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recompute_portfolio_digests_fans_in_component_and_stack_ids_sorted() {
        let portfolio = json!({"targets": [{"id": "t1"}]});
        let components = json!({"components": [
            {"id": "c2", "targetIds": ["t1"]},
            {"id": "c1", "targetIds": ["t1"]},
            {"id": "c3", "targetIds": ["other"]},
        ]});
        let stacks = json!({"stacks": [{"id": "s1", "targetIds": ["t1"]}]});
        let result = recompute_portfolio_digests(&portfolio, &components, &stacks);
        let target = &result["targets"][0];
        assert_eq!(target["componentIds"], json!(["c1", "c2"]));
        assert_eq!(target["stackIds"], json!(["s1"]));
        assert!(target["digest"].as_str().unwrap().starts_with("sha256:"));
        assert!(result["digest"].as_str().unwrap().starts_with("sha256:"));
    }

    #[test]
    fn recompute_portfolio_digests_is_stable_regardless_of_prior_digest_field() {
        let portfolio_a = json!({"targets": [{"id": "t1"}]});
        let portfolio_b = json!({"targets": [{"id": "t1", "digest": "sha256:stale"}], "digest": "sha256:stale-root"});
        let components = json!({"components": []});
        let stacks = json!({"stacks": []});
        let a = recompute_portfolio_digests(&portfolio_a, &components, &stacks);
        let b = recompute_portfolio_digests(&portfolio_b, &components, &stacks);
        assert_eq!(a, b);
    }

    #[test]
    fn build_gaps_unions_all_four_sources_in_order() {
        let release_contract = json!({"missingDeclarations": ["roles"]});
        let product_context = json!({"gaps": [{"kind": "context-gap"}]});
        let journeys = json!({"gaps": [{"kind": "journey-gap"}]});
        let stacks = json!({"coverage": {"unknownStacks": ["s9"]}});
        let gaps = build_gaps(&release_contract, &product_context, &journeys, &stacks);
        assert_eq!(
            gaps,
            vec![
                json!({"kind": "release-contract-missing", "field": "roles"}),
                json!({"kind": "context-gap"}),
                json!({"kind": "journey-gap"}),
                json!({"kind": "unknown-stack", "id": "s9"}),
            ]
        );
    }

    #[test]
    fn build_gaps_defaults_missing_fields_to_empty() {
        let gaps = build_gaps(&json!({}), &json!({}), &json!({}), &json!({}));
        assert!(gaps.is_empty());
    }

    #[test]
    fn inspect_product_assembles_envelope_and_report_skeleton() {
        let portfolio = json!({"targets": [{"id": "t1"}]});
        let components = json!({"components": [{"id": "c1", "targetIds": ["t1"]}]});
        let stacks = json!({"stacks": [{"id": "s1", "targetIds": ["t1"]}], "coverage": {"unknownStacks": []}});
        let external_systems = json!({"systems": [{"id": "e1"}]});
        let release_contract = json!({"missingDeclarations": []});
        let product_context = json!({"gaps": []});
        let journeys = json!({"gaps": []});
        let baseline = json!({"controls": [{"id": "ctl1"}]});
        let capabilities = json!([{"id": "repository"}]);
        let claim_impact = json!([]);
        let scenarios = json!({"scenarios": [{"id": "sc1"}]});

        let result = inspect_product(InspectProductInputs {
            portfolio: &portfolio,
            components: &components,
            stacks: &stacks,
            external_systems: &external_systems,
            release_contract: &release_contract,
            product_context: &product_context,
            journeys: &journeys,
            baseline: &baseline,
            capabilities: &capabilities,
            claim_impact: &claim_impact,
            scenarios: &scenarios,
        });

        assert_eq!(result["schemaVersion"], json!(1));
        assert_eq!(result["kind"], json!("legion-product-inspection"));
        assert_eq!(
            result["reportSkeleton"],
            json!({
                "targetIds": ["t1"],
                "componentIds": ["c1"],
                "stackIds": ["s1"],
                "externalSystemIds": ["e1"],
                "controlIds": ["ctl1"],
                "scenarioIds": ["sc1"],
                "gaps": [],
            })
        );
        assert_eq!(result["portfolio"]["targets"][0]["componentIds"], json!(["c1"]));
        assert!(result["portfolio"]["digest"].as_str().unwrap().starts_with("sha256:"));
    }
}
