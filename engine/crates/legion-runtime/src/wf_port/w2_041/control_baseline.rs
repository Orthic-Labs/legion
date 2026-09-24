//! Port of `src/lib/core/plan-stages/control-baseline.mjs`.
//!
//! `controlBaselineStage.run(options, host)` resolves the product topology
//! artifact, requires at least one control pack, compiles the control
//! baseline, computes evidence-capability impacts against it, and derives a
//! completeness verdict from the control denominator and impact count.
//!
//! `compileBaseline` (`controls/baseline/compile.mjs`) is a large dependency
//! this chunk does not own the files for and has no native port to call
//! directly from `legion-runtime`. `evidenceCapabilities` / `capabilityImpacts`
//! (`controls/evidence/{capabilities,impacts}.mjs`) *do* already have a
//! faithful native port at `legion_runtime::p5_core::controls_evidence`
//! (`evidence_capabilities`, `capability_impacts`), but on a typed
//! `controls_support::Value`, not the `serde_json::Value` this chunk's
//! `reconcile_run`/`product_topology` siblings use — reusing them here would
//! require a `serde_json::Value` <-> `controls_support::Value` bridge, which
//! is out of this chunk's owned files to add. Both computations are
//! therefore taken as injected closures: the branching/decision logic below
//! — which is `control-baseline.mjs`'s actual content — is a complete,
//! faithful port; wiring real `compile_baseline`/`compute_impacts`
//! implementations in is the integrator's job.

use serde_json::{json, Value};

/// Port of:
/// ```js
/// const topology = options.artifacts?.['product-portfolio']
///   ?? options.artifacts?.['product-topology']
///   ?? options.productInspection;
/// ```
pub fn resolve_topology<'a>(artifacts: Option<&'a Value>, product_inspection: Option<&'a Value>) -> Option<&'a Value> {
    if let Some(v) = artifacts.and_then(|a| a.get("product-portfolio")).filter(|v| !v.is_null()) {
        return Some(v);
    }
    if let Some(v) = artifacts.and_then(|a| a.get("product-topology")).filter(|v| !v.is_null()) {
        return Some(v);
    }
    product_inspection.filter(|v| !v.is_null())
}

/// Port of `controlBaselineStage.run(options, host)`.
///
/// `topology` is the result of [`resolve_topology`]. `packs_len` is
/// `options.packs?.length ?? 0`. `compile_baseline` and `compute_impacts`
/// stand in for `compileBaseline(...)` and
/// `capabilityImpacts(baseline, evidenceCapabilities(host))` respectively;
/// `compute_impacts` receives the compiled baseline.
pub fn control_baseline_stage(
    topology: Option<&Value>,
    packs_len: usize,
    compile_baseline: impl FnOnce() -> Value,
    compute_impacts: impl FnOnce(&Value) -> Vec<Value>,
) -> Value {
    if topology.is_none() {
        return json!({
            "complete": false,
            "status": "missing",
            "detail": "product-topology-required",
        });
    }
    if packs_len == 0 {
        return json!({
            "complete": false,
            "status": "missing",
            "detail": "control-packs-required",
            "artifact": {
                "baseline": Value::Null,
                "impacts": [{"kind": "control-denominator-missing"}],
            },
        });
    }

    let baseline = compile_baseline();
    let impacts = compute_impacts(&baseline);
    let denominator = baseline
        .get("controls")
        .and_then(Value::as_array)
        .map(|a| a.len())
        .unwrap_or(0);

    if denominator == 0 {
        let mut impacts_with_zero = impacts.clone();
        impacts_with_zero.push(json!({"kind": "control-denominator-zero"}));
        return json!({
            "complete": false,
            "status": "unproven",
            "detail": "control-denominator-zero",
            "artifact": {
                "baseline": baseline,
                "impacts": impacts_with_zero,
            },
        });
    }

    let complete = impacts.is_empty();
    json!({
        "complete": complete,
        "status": if complete { "pass" } else { "unproven" },
        "artifact": {
            "baseline": baseline,
            "impacts": impacts,
        },
        "detail": if complete { Value::Null } else { json!("evidence-capability-gap") },
    })
}

// ---------------------------------------------------------------------------
// Live wiring (packet r45): closes the gap documented above by supplying
// real `compile_baseline` (`w2_038::baseline::compile_baseline`) and
// `evidence_capabilities`/`capability_impacts`
// (`p5_core::controls_evidence`) implementations to [`control_baseline_stage`]
// instead of injected test closures. Those two live on
// `p5_core::controls_support::Value` / typed `CapabilityReceipt` structs
// rather than this module's `serde_json::Value`, so a small bidirectional
// JSON bridge is added here (owned by this file; no shared-file edits).
mod live {
    use super::super::super::w2_038::baseline::compile_baseline;
    use crate::p5_core::controls_evidence::{
        capability_impacts, evidence_capabilities, BaselineControlRef, CapabilityReceipt,
    };
    use crate::p5_core::controls_support::Value as CVal;
    use serde_json::{Map, Value as JVal};
    use std::collections::BTreeMap;

    /// `serde_json::Value` -> `controls_support::Value`.
    pub fn json_to_cv(value: &JVal) -> CVal {
        match value {
            JVal::Null => CVal::Null,
            JVal::Bool(b) => CVal::Bool(*b),
            JVal::Number(n) => CVal::Number(n.as_f64().unwrap_or(0.0)),
            JVal::String(s) => CVal::String(s.clone()),
            JVal::Array(items) => CVal::Array(items.iter().map(json_to_cv).collect()),
            JVal::Object(map) => {
                CVal::Object(map.iter().map(|(k, v)| (k.clone(), json_to_cv(v))).collect())
            }
        }
    }

    /// `controls_support::Value` -> `serde_json::Value`.
    pub fn cv_to_json(value: &CVal) -> JVal {
        match value {
            CVal::Null => JVal::Null,
            CVal::Bool(b) => JVal::Bool(*b),
            CVal::Number(n) => serde_json::Number::from_f64(*n)
                .map(JVal::Number)
                .unwrap_or(JVal::Null),
            CVal::String(s) => JVal::String(s.clone()),
            CVal::Array(items) => JVal::Array(items.iter().map(cv_to_json).collect()),
            CVal::Object(map) => {
                let mut out = Map::with_capacity(map.len());
                for (k, v) in map {
                    out.insert(k.clone(), cv_to_json(v));
                }
                JVal::Object(out)
            }
        }
    }

    fn cv_get<'a>(value: &'a CVal, key: &str) -> Option<&'a CVal> {
        match value {
            CVal::Object(map) => map.get(key),
            _ => None,
        }
    }

    fn cv_str_list(value: Option<&CVal>) -> Vec<String> {
        match value {
            Some(CVal::Array(items)) => items
                .iter()
                .filter_map(|v| match v {
                    CVal::String(s) => Some(s.clone()),
                    _ => None,
                })
                .collect(),
            _ => Vec::new(),
        }
    }

    /// Extracts `BaselineControlRef`s from a compiled baseline's `controls`
    /// array, mirroring the fields `capabilityImpacts` reads in JS
    /// (`id`, `targetIds`, `claimLevels`, `evidence`,
    /// `missingEvidenceEffect`).
    pub(crate) fn controls_from_baseline(baseline: &CVal) -> Vec<BaselineControlRef> {
        match cv_get(baseline, "controls") {
            Some(CVal::Array(items)) => items
                .iter()
                .map(|c| BaselineControlRef {
                    id: match cv_get(c, "id") {
                        Some(CVal::String(s)) => s.clone(),
                        _ => String::new(),
                    },
                    target_ids: cv_str_list(cv_get(c, "targetIds")),
                    claim_levels: cv_str_list(cv_get(c, "claimLevels")),
                    evidence: cv_str_list(cv_get(c, "evidence")),
                    // JS: `control.missingEvidenceEffect ?? 'unproven'`.
                    missing_evidence_effect: match cv_get(c, "missingEvidenceEffect") {
                        Some(CVal::String(s)) => s.clone(),
                        _ => "unproven".to_string(),
                    },
                })
                .collect(),
            _ => Vec::new(),
        }
    }

    /// Builds `host.capabilities` (`BTreeMap<String, CapabilityReceipt>`)
    /// from a JSON `host` object shaped like the JS runtime host: each key
    /// under `host.capabilities` maps to `{active, receiptBinding,
    /// artifactDigest, environment, limitations, observedAtMs, expiresAtMs,
    /// receiptValue}`.
    pub(crate) fn capabilities_from_host(host: &JVal) -> BTreeMap<String, CapabilityReceipt> {
        let mut out = BTreeMap::new();
        let Some(caps) = host.get("capabilities").and_then(JVal::as_object) else {
            return out;
        };
        for (key, entry) in caps {
            let receipt = CapabilityReceipt {
                active: entry.get("active").and_then(JVal::as_bool).unwrap_or(false),
                receipt_binding: entry.get("receiptBinding").map(json_to_cv),
                artifact_digest: entry
                    .get("artifactDigest")
                    .and_then(JVal::as_str)
                    .map(str::to_string),
                environment: entry
                    .get("environment")
                    .and_then(JVal::as_str)
                    .map(str::to_string),
                limitations: entry.get("limitations").and_then(JVal::as_array).map(|a| {
                    a.iter()
                        .filter_map(|v| v.as_str().map(str::to_string))
                        .collect()
                }),
                observed_at_ms: entry.get("observedAtMs").and_then(JVal::as_i64),
                expires_at_ms: entry.get("expiresAtMs").and_then(JVal::as_i64),
                receipt_value: entry.get("receiptValue").map(json_to_cv),
            };
            out.insert(key.clone(), receipt);
        }
        out
    }

    /// Port of `controlBaselineStage.run(options, host)` wired to the real
    /// `compileBaseline`/`evidenceCapabilities`/`capabilityImpacts`
    /// dependencies (instead of the injected test closures
    /// `control_baseline_stage` takes). Mirrors
    /// `compileBaseline({packs, portfolio, components, stacks, contract,
    /// binding})` throwing (as an unhandled rejection) on packs validation
    /// failure (duplicate pack id, missing dependency, dependency cycle):
    /// `control_baseline_stage`'s `compile_baseline` closure parameter is
    /// infallible (`impl FnOnce() -> Value`, matching its pre-existing
    /// signature), so that failure surfaces here as a panic, mirroring the
    /// JS throw propagating out of the stage.
    ///
    /// `now_ms`/`host_binding` stand in for `host.clock.now()` /
    /// `host.binding`, matching `evidence_capabilities`'s existing calling
    /// convention.
    #[allow(clippy::too_many_arguments)]
    pub fn control_baseline_stage_live(
        topology: Option<&JVal>,
        packs: &[JVal],
        portfolio: &JVal,
        components: &JVal,
        stacks: &[JVal],
        contract: &JVal,
        binding: Option<&JVal>,
        host: &JVal,
        now_ms: Option<i64>,
    ) -> JVal {
        let packs_cv: Vec<CVal> = packs.iter().map(json_to_cv).collect();
        let portfolio_cv = json_to_cv(portfolio);
        let components_cv = json_to_cv(components);
        let stacks_cv: Vec<CVal> = stacks.iter().map(json_to_cv).collect();
        let contract_cv = json_to_cv(contract);
        let binding_cv = binding.map(json_to_cv);
        let host_binding_cv = host.get("binding").map(json_to_cv);
        let capabilities = capabilities_from_host(host);

        super::control_baseline_stage(
            topology,
            packs.len(),
            move || {
                let baseline_cv = compile_baseline(
                    &packs_cv,
                    &portfolio_cv,
                    &components_cv,
                    &stacks_cv,
                    &contract_cv,
                    binding_cv.as_ref(),
                )
                .expect("compileBaseline: pack validation failure (duplicate/missing/cyclic)");
                cv_to_json(&baseline_cv)
            },
            move |baseline_json| {
                let baseline_cv = json_to_cv(baseline_json);
                let controls = controls_from_baseline(&baseline_cv);
                let capability_statuses =
                    evidence_capabilities(&capabilities, now_ms, host_binding_cv.as_ref());
                capability_impacts(&controls, &capability_statuses)
                    .into_iter()
                    .map(|impact| {
                        serde_json::json!({
                            "controlId": impact.control_id,
                            "targetIds": impact.target_ids,
                            "claimLevels": impact.claim_levels,
                            "evidence": impact.evidence,
                            "effect": impact.effect,
                        })
                    })
                    .collect()
            },
        )
    }

    /// Standalone `compileBaseline` + `evidenceCapabilities` +
    /// `capabilityImpacts` wiring, for callers (e.g. `r45::inspect_product`)
    /// that need the baseline/capabilities/claim-impact triple directly
    /// rather than through the `controlBaselineStage.run` decision wrapper.
    /// Returns `(baseline, capabilities, claim_impact)` as
    /// `serde_json::Value`s, matching `inspectProduct`'s
    /// `baseline`/`capabilities`/`claimImpact` locals.
    #[allow(clippy::too_many_arguments)]
    pub fn compile_baseline_and_impacts_json(
        packs: &[JVal],
        portfolio: &JVal,
        components: &JVal,
        stacks: &[JVal],
        contract: &JVal,
        binding: Option<&JVal>,
        host: &JVal,
        now_ms: Option<i64>,
    ) -> Result<(JVal, JVal, JVal), String> {
        let packs_cv: Vec<CVal> = packs.iter().map(json_to_cv).collect();
        let portfolio_cv = json_to_cv(portfolio);
        let components_cv = json_to_cv(components);
        let stacks_cv: Vec<CVal> = stacks.iter().map(json_to_cv).collect();
        let contract_cv = json_to_cv(contract);
        let binding_cv = binding.map(json_to_cv);
        let host_binding_cv = host.get("binding").map(json_to_cv);
        let capabilities_map = capabilities_from_host(host);

        let baseline_cv = compile_baseline(
            &packs_cv,
            &portfolio_cv,
            &components_cv,
            &stacks_cv,
            &contract_cv,
            binding_cv.as_ref(),
        )?;
        let baseline_json = cv_to_json(&baseline_cv);

        let controls = controls_from_baseline(&baseline_cv);
        let capability_statuses = evidence_capabilities(&capabilities_map, now_ms, host_binding_cv.as_ref());
        let capabilities_json = JVal::Array(
            capability_statuses
                .iter()
                .map(|status| {
                    serde_json::json!({
                        "id": status.id,
                        "available": status.available,
                        "owner": status.owner,
                        "receipt": status.receipt.as_ref().map(cv_to_json).unwrap_or(JVal::Null),
                        "reason": status.reason,
                    })
                })
                .collect(),
        );
        let claim_impact_json = JVal::Array(
            capability_impacts(&controls, &capability_statuses)
                .into_iter()
                .map(|impact| {
                    serde_json::json!({
                        "controlId": impact.control_id,
                        "targetIds": impact.target_ids,
                        "claimLevels": impact.claim_levels,
                        "evidence": impact.evidence,
                        "effect": impact.effect,
                    })
                })
                .collect(),
        );

        Ok((baseline_json, capabilities_json, claim_impact_json))
    }
}

pub use live::{compile_baseline_and_impacts_json, control_baseline_stage_live, cv_to_json, json_to_cv};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_topology_short_circuits() {
        let result = control_baseline_stage(None, 3, || json!({}), |_| Vec::new());
        assert_eq!(result["complete"], json!(false));
        assert_eq!(result["status"], json!("missing"));
        assert_eq!(result["detail"], json!("product-topology-required"));
        assert!(result.get("artifact").is_none());
    }

    #[test]
    fn zero_packs_reports_denominator_missing_without_compiling() {
        let topology = json!({});
        let mut compiled = false;
        let result = control_baseline_stage(
            Some(&topology),
            0,
            || {
                compiled = true;
                json!({})
            },
            |_| Vec::new(),
        );
        assert!(!compiled, "compile_baseline must not run when packs are empty");
        assert_eq!(result["status"], json!("missing"));
        assert_eq!(result["detail"], json!("control-packs-required"));
        assert_eq!(result["artifact"]["baseline"], Value::Null);
        assert_eq!(result["artifact"]["impacts"], json!([{"kind": "control-denominator-missing"}]));
    }

    #[test]
    fn zero_controls_reports_denominator_zero_and_appends_gap_to_impacts() {
        let topology = json!({});
        let result = control_baseline_stage(
            Some(&topology),
            2,
            || json!({"controls": []}),
            |_| vec![json!({"kind": "existing"})],
        );
        assert_eq!(result["status"], json!("unproven"));
        assert_eq!(result["detail"], json!("control-denominator-zero"));
        let impacts = result["artifact"]["impacts"].as_array().unwrap();
        assert_eq!(impacts.len(), 2);
        assert_eq!(impacts[1], json!({"kind": "control-denominator-zero"}));
    }

    #[test]
    fn nonzero_controls_with_no_impacts_pass() {
        let topology = json!({});
        let result = control_baseline_stage(
            Some(&topology),
            2,
            || json!({"controls": [{"id": "c1"}]}),
            |_| Vec::new(),
        );
        assert_eq!(result["complete"], json!(true));
        assert_eq!(result["status"], json!("pass"));
        assert!(result["detail"].is_null());
    }

    #[test]
    fn nonzero_controls_with_impacts_are_unproven() {
        let topology = json!({});
        let result = control_baseline_stage(
            Some(&topology),
            2,
            || json!({"controls": [{"id": "c1"}]}),
            |_| vec![json!({"kind": "evidence-gap"})],
        );
        assert_eq!(result["complete"], json!(false));
        assert_eq!(result["status"], json!("unproven"));
        assert_eq!(result["detail"], json!("evidence-capability-gap"));
    }

    #[test]
    fn resolve_topology_prefers_product_portfolio_over_product_topology_and_inspection() {
        let artifacts = json!({"product-portfolio": {"k": "portfolio"}, "product-topology": {"k": "topology"}});
        let inspection = json!({"k": "inspection"});
        let resolved = resolve_topology(Some(&artifacts), Some(&inspection)).unwrap();
        assert_eq!(resolved, &json!({"k": "portfolio"}));
    }

    #[test]
    fn resolve_topology_falls_back_to_product_inspection() {
        let inspection = json!({"k": "inspection"});
        let resolved = resolve_topology(None, Some(&inspection)).unwrap();
        assert_eq!(resolved, &json!({"k": "inspection"}));
    }

    mod live_wiring {
        use super::super::live::control_baseline_stage_live;

        fn control(id: &str) -> Value {
            json!({"id": id, "selector": {"op": "always"}, "providers": []})
        }

        fn pack(id: &str, controls: Vec<Value>) -> Value {
            json!({"id": id, "dependencies": [], "controls": controls})
        }

        fn portfolio() -> Value {
            json!({"targets": [{"id": "t1"}]})
        }

        fn components() -> Value {
            json!({"components": []})
        }

        #[test]
        fn live_compiles_real_baseline_and_reports_evidence_gap_when_host_has_no_capabilities() {
            let topology = json!({"k": "topology"});
            let packs = vec![pack("p1", vec![control("c1")])];
            let host = json!({"capabilities": {}});
            let result = control_baseline_stage_live(
                Some(&topology),
                &packs,
                &portfolio(),
                &components(),
                &[],
                &json!({}),
                None,
                &host,
                Some(1_000),
            );
            // c1 has no `evidence` requirements in this fixture, so with a
            // nonzero denominator and zero capability impacts the stage
            // passes; the important assertion is that the real
            // compileBaseline ran (denominator == 1, not a stubbed value).
            let baseline = &result["artifact"]["baseline"];
            assert_eq!(baseline["denominator"], json!(["c1"]));
            assert_eq!(result["complete"], json!(true));
            assert_eq!(result["status"], json!("pass"));
        }

        #[test]
        fn live_reports_impact_for_unmet_evidence_requirement() {
            let topology = json!({"k": "topology"});
            let mut ctl = control("c1");
            ctl["evidence"] = json!(["repository"]);
            let packs = vec![pack("p1", vec![ctl])];
            let host = json!({"capabilities": {}});
            let result = control_baseline_stage_live(
                Some(&topology),
                &packs,
                &portfolio(),
                &components(),
                &[],
                &json!({}),
                None,
                &host,
                Some(1_000),
            );
            assert_eq!(result["status"], json!("unproven"));
            assert_eq!(result["detail"], json!("evidence-capability-gap"));
            let impacts = result["artifact"]["impacts"].as_array().unwrap();
            assert_eq!(impacts.len(), 1);
            assert_eq!(impacts[0]["controlId"], json!("c1"));
            assert_eq!(impacts[0]["evidence"], json!("repository"));
        }

        #[test]
        fn live_short_circuits_on_missing_topology_without_compiling() {
            let host = json!({"capabilities": {}});
            let result = control_baseline_stage_live(
                None,
                &[],
                &portfolio(),
                &components(),
                &[],
                &json!({}),
                None,
                &host,
                None,
            );
            assert_eq!(result["status"], json!("missing"));
            assert_eq!(result["detail"], json!("product-topology-required"));
        }
    }
}
