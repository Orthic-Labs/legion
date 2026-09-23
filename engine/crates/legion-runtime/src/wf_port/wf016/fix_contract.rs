//! Port of `src/lib/remediation/fix-contract.mjs`.
//!
//! Fix proposal contract per SNIP-FIX-01. A proposal binds finding/root
//! cause, target files/ranges, preconditions, patch digest, expected
//! behavior, risks, and validation commands. Tier: MECHANICAL | AGENT_GUIDED
//! | MANUAL.

use serde_json::{json, Value};

use super::util::{digest_uncanonicalized, sorted_strings};

/// Input to [`fix_proposal`], mirroring the JS destructured parameter object.
/// Every list field defaults to empty the way JS's `?? []` does when the
/// caller omits it.
#[derive(Debug, Clone, Default)]
pub struct FixProposalInput {
    pub finding_id: Value,
    pub root_cause_digest: Value,
    pub producer: Value,
    pub target_paths: Vec<String>,
    pub preconditions: Vec<String>,
    pub patch: Value,
    pub expected_behavior: Vec<String>,
    pub risks: Vec<String>,
    pub validation_commands: Vec<String>,
    pub tier: Value,
}

/// Faithful port of:
/// ```js
/// export function fixProposal({ findingId, rootCauseDigest, producer, targetPaths, preconditions, patch, expectedBehavior, risks, validationCommands, tier }) {
///   const body = { schemaVersion: 1, kind: 'legion-fix-proposal', findingId, rootCauseDigest,
///     producer: producer ?? {}, targetPaths: [...(targetPaths ?? [])].sort(),
///     preconditions: [...(preconditions ?? [])].sort(), patch,
///     expectedBehavior: [...(expectedBehavior ?? [])].sort(), risks: [...(risks ?? [])].sort(),
///     validationCommands: [...(validationCommands ?? [])].sort(), tier };
///   body.id = `sha256:${createHash('sha256').update(JSON.stringify(body)).digest('hex')}`;
///   return body;
/// }
/// ```
/// The `id` digest is computed over `body` *before* `id` is inserted (the JS
/// right-hand side `JSON.stringify(body)` evaluates before the assignment
/// completes), then `id` is appended as the body's last key.
pub fn fix_proposal(input: FixProposalInput) -> Value {
    let producer = if input.producer.is_null() { json!({}) } else { input.producer };
    let mut body = json!({
        "schemaVersion": 1,
        "kind": "legion-fix-proposal",
        "findingId": input.finding_id,
        "rootCauseDigest": input.root_cause_digest,
        "producer": producer,
        "targetPaths": sorted_strings(input.target_paths),
        "preconditions": sorted_strings(input.preconditions),
        "patch": input.patch,
        "expectedBehavior": sorted_strings(input.expected_behavior),
        "risks": sorted_strings(input.risks),
        "validationCommands": sorted_strings(input.validation_commands),
        "tier": input.tier,
    });
    let id = digest_uncanonicalized(&body);
    body.as_object_mut().expect("body is an object").insert("id".to_string(), Value::String(id));
    body
}

/// `export const FIX_STOPS = Object.freeze([...]);`
pub const FIX_STOPS: &[&str] = &[
    "max-batches",
    "no-progress",
    "regression",
    "plan-drift",
    "new-high-critical",
    "manual-finding-required",
    "missing-variant-or-proof",
    "scope-expansion",
];

/// Input to [`evaluate_fix_loop`], mirroring the JS destructured parameter
/// object. `max_batches` defaults to `4` as in JS (`maxBatches = 4`); the
/// rest default to `false`/`None` as an absent (`undefined`) JS argument
/// would.
#[derive(Debug, Clone, Default)]
pub struct EvaluateFixLoopInput {
    pub batch_index: i64,
    pub max_batches: Option<i64>,
    pub progress: Option<bool>,
    pub regression: bool,
    pub drift: bool,
    pub new_high_critical: bool,
    pub manual_required: bool,
    pub missing_variant_proof: bool,
    pub scope_expansion: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FixLoopDecision {
    pub stop: bool,
    pub reason: Option<&'static str>,
}

/// Faithful port of `evaluateFixLoop`. Checks run in the exact JS order, and
/// the first matching stop condition wins.
pub fn evaluate_fix_loop(input: EvaluateFixLoopInput) -> FixLoopDecision {
    let max_batches = input.max_batches.unwrap_or(4);
    if input.batch_index >= max_batches {
        return FixLoopDecision { stop: true, reason: Some("max-batches") };
    }
    if input.progress == Some(false) {
        return FixLoopDecision { stop: true, reason: Some("no-progress") };
    }
    if input.regression {
        return FixLoopDecision { stop: true, reason: Some("regression") };
    }
    if input.drift {
        return FixLoopDecision { stop: true, reason: Some("plan-drift") };
    }
    if input.new_high_critical {
        return FixLoopDecision { stop: true, reason: Some("new-high-critical") };
    }
    if input.manual_required {
        return FixLoopDecision { stop: true, reason: Some("manual-finding-required") };
    }
    if input.missing_variant_proof {
        return FixLoopDecision { stop: true, reason: Some("missing-variant-or-proof") };
    }
    if input.scope_expansion {
        return FixLoopDecision { stop: true, reason: Some("scope-expansion") };
    }
    FixLoopDecision { stop: false, reason: None }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fix_proposal_sorts_lists_and_appends_id_last() {
        let body = fix_proposal(FixProposalInput {
            finding_id: json!("f1"),
            root_cause_digest: json!("sha256:abc"),
            producer: Value::Null,
            target_paths: vec!["b.js".into(), "a.js".into()],
            preconditions: vec!["z".into(), "a".into()],
            patch: json!({ "path": "patches/fix.patch", "digest": null }),
            expected_behavior: vec!["y".into(), "x".into()],
            risks: vec!["r2".into(), "r1".into()],
            validation_commands: vec!["v2".into(), "v1".into()],
            tier: json!("MECHANICAL"),
        });
        assert_eq!(body["producer"], json!({}));
        assert_eq!(body["targetPaths"], json!(["a.js", "b.js"]));
        assert_eq!(body["preconditions"], json!(["a", "z"]));
        assert_eq!(body["expectedBehavior"], json!(["x", "y"]));
        assert_eq!(body["risks"], json!(["r1", "r2"]));
        assert_eq!(body["validationCommands"], json!(["v1", "v2"]));
        let id = body["id"].as_str().unwrap();
        assert!(id.starts_with("sha256:"));
        assert_eq!(id.len(), 71);
        // The digest is stable given identical inputs.
        let body2 = fix_proposal(FixProposalInput {
            finding_id: json!("f1"),
            root_cause_digest: json!("sha256:abc"),
            producer: Value::Null,
            target_paths: vec!["b.js".into(), "a.js".into()],
            preconditions: vec!["z".into(), "a".into()],
            patch: json!({ "path": "patches/fix.patch", "digest": null }),
            expected_behavior: vec!["y".into(), "x".into()],
            risks: vec!["r2".into(), "r1".into()],
            validation_commands: vec!["v2".into(), "v1".into()],
            tier: json!("MECHANICAL"),
        });
        assert_eq!(body["id"], body2["id"]);
        // Field order in the serialized object mirrors the JS literal, with
        // `id` last.
        let keys: Vec<&String> = body.as_object().unwrap().keys().collect();
        assert_eq!(keys.last().unwrap().as_str(), "id");
    }

    #[test]
    fn fix_stops_order_is_stable() {
        assert_eq!(FIX_STOPS.len(), 8);
        assert_eq!(FIX_STOPS[0], "max-batches");
        assert_eq!(FIX_STOPS[7], "scope-expansion");
    }

    #[test]
    fn evaluate_fix_loop_max_batches() {
        let decision = evaluate_fix_loop(EvaluateFixLoopInput { batch_index: 4, ..Default::default() });
        assert_eq!(decision, FixLoopDecision { stop: true, reason: Some("max-batches") });
    }

    #[test]
    fn evaluate_fix_loop_custom_max_batches() {
        let decision = evaluate_fix_loop(EvaluateFixLoopInput { batch_index: 2, max_batches: Some(2), ..Default::default() });
        assert_eq!(decision, FixLoopDecision { stop: true, reason: Some("max-batches") });
    }

    #[test]
    fn evaluate_fix_loop_no_progress() {
        let decision = evaluate_fix_loop(EvaluateFixLoopInput { batch_index: 0, progress: Some(false), ..Default::default() });
        assert_eq!(decision, FixLoopDecision { stop: true, reason: Some("no-progress") });
    }

    #[test]
    fn evaluate_fix_loop_regression_before_drift() {
        let decision = evaluate_fix_loop(EvaluateFixLoopInput {
            batch_index: 0,
            regression: true,
            drift: true,
            ..Default::default()
        });
        assert_eq!(decision.reason, Some("regression"));
    }

    #[test]
    fn evaluate_fix_loop_continues() {
        let decision = evaluate_fix_loop(EvaluateFixLoopInput { batch_index: 0, progress: Some(true), ..Default::default() });
        assert_eq!(decision, FixLoopDecision { stop: false, reason: None });
    }
}
