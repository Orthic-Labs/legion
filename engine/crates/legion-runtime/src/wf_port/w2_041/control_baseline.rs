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
}
