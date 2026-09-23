//! Port of `src/providers/security/variant-analysis.mjs`: the semantic
//! variant analysis engine per Security Appendix §34 — repository-wide
//! enumeration under a frozen denominator with complete dispositions.
//! Exact/same-rule search alone can never complete a receipt.
//!
//! The JS module looks up each pack's `variantStrategies[ruleId]` (an
//! object exposing `rootCause(candidate, verdict)` and
//! `enumerate(context, rootCauseSignature)`) through a `packByProvider` map
//! passed in by the caller. Those pack-level `variantStrategies` are
//! coverage-report bookkeeping owned by the individual packs, not this
//! engine, and (mirroring the precedent set by the sibling `wf060` chunk)
//! are not ported for `supply-chain.mjs` / `uploads.mjs` in this chunk. This
//! module ports the engine itself faithfully, behind a [`VariantStrategy`]
//! trait a caller implements per rule and passes in through
//! [`PackByProvider`] — the same shape as the JS `packByProvider` map, just
//! statically typed.

use serde_json::{json, Value};

use crate::wf_port::wf052::contracts::{
    assert_artifact_binding, binding_from_plan, digest, stable_id, SecurityContractError,
};

pub type Result<T> = std::result::Result<T, SecurityContractError>;

/// Mirrors one pack's `variantStrategies[ruleId]` entry: `rootCause` and
/// `enumerate`.
pub trait VariantStrategy {
    /// Mirrors `strategy.rootCause(candidate, verdict)`.
    fn root_cause(&self, candidate: &Value, verdict: &Value) -> Value;
    /// Mirrors `strategy.enumerate({ plan, model, candidate, verdict, binding }, rootCauseSignature)`.
    /// Returns `{ denominator, strategies, matches, coverageGaps }` (`matches`
    /// entries omit `id`, which this function assigns, mirroring the JS
    /// `match.id ?? stableId(...)`).
    fn enumerate(
        &self,
        plan: &Value,
        model: &Value,
        candidate: &Value,
        verdict: &Value,
        binding: &Value,
        root_cause_signature: &Value,
    ) -> Value;
}

/// A resolver mirroring `packByProvider.get(candidate.provider)?.variantStrategies?.[candidate.ruleId]`.
pub trait PackByProvider {
    fn strategy_for(&self, provider: &str, rule_id: &str) -> Option<&dyn VariantStrategy>;
}

/// Faithful port of `summarize(matches)`.
fn summarize(matches: &[Value]) -> Value {
    let count = |value: &str| matches.iter().filter(|m| m.get("disposition").and_then(Value::as_str) == Some(value)).count();
    let examined = matches
        .iter()
        .filter(|m| m.get("disposition").and_then(Value::as_str) != Some("UNRESOLVED"))
        .count();
    json!({
        "enumerated": matches.len(),
        "examined": examined,
        "confirmed": count("CONFIRMED"),
        "rejected": count("REJECTED"),
        "duplicates": count("DUPLICATE"),
        "outOfScope": count("OUT_OF_SCOPE"),
        "unresolved": count("UNRESOLVED"),
    })
}

/// Faithful port of `missingStrategyReceipt({ candidate, verdict, binding })`.
fn missing_strategy_receipt(candidate: &Value, binding: &Value) -> Value {
    json!({
        "schemaVersion": 2,
        "kind": "security-variant-receipt",
        "findingId": candidate.get("id").cloned().unwrap_or(Value::Null),
        "ruleId": candidate.get("ruleId").cloned().unwrap_or(Value::Null),
        "rootCauseSignature": Value::Null,
        "provider": "security.variant-analysis",
        "providerVersion": "2",
        "binding": binding.clone(),
        "denominator": Value::Null,
        "strategies": [],
        "matches": [],
        "summary": {
            "enumerated": 0, "examined": 0, "confirmed": 0, "rejected": 0,
            "duplicates": 0, "outOfScope": 0, "unresolved": 0,
        },
        "complete": false,
        "coverageGaps": ["missing-variant-strategy"],
    })
}

/// Faithful port of `analyzeVariants({ plan, model, candidates, adjudication, packByProvider })`.
pub fn analyze_variants(
    plan: &Value,
    model: &Value,
    candidates: &Value,
    adjudication: &Value,
    pack_by_provider: &dyn PackByProvider,
) -> Result<Value> {
    let binding = binding_from_plan(plan)?;
    for (label, artifact) in [("model", model), ("candidates", candidates), ("adjudication", adjudication)] {
        assert_artifact_binding(artifact, &binding, label)?;
    }

    let candidate_by_id: std::collections::HashMap<&str, &Value> = candidates
        .get("candidates")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|c| c.get("id").and_then(Value::as_str).map(|id| (id, c)))
        .collect();

    let mut receipts: Vec<Value> = Vec::new();

    let verdicts = adjudication.get("verdicts").and_then(Value::as_array).cloned().unwrap_or_default();
    for verdict in &verdicts {
        let verdict_kind = verdict.get("verdict").and_then(Value::as_str).unwrap_or("");
        if !matches!(verdict_kind, "TRUE_POSITIVE" | "LIKELY_TRUE_POSITIVE") {
            continue;
        }
        let candidate_id = verdict.get("candidateId").and_then(Value::as_str).unwrap_or("");
        let candidate = *candidate_by_id
            .get(candidate_id)
            .ok_or_else(|| SecurityContractError::new(format!("missing candidate {candidate_id}")))?;

        let provider = candidate.get("provider").and_then(Value::as_str).unwrap_or("");
        let rule_id = candidate.get("ruleId").and_then(Value::as_str).unwrap_or("");
        let strategy = pack_by_provider.strategy_for(provider, rule_id);

        let Some(strategy) = strategy else {
            receipts.push(missing_strategy_receipt(candidate, &binding));
            continue;
        };

        let root_cause_signature = verdict
            .get("rootCauseSignature")
            .filter(|v| !v.is_null())
            .cloned()
            .unwrap_or_else(|| strategy.root_cause(candidate, verdict));

        let result = strategy.enumerate(plan, model, candidate, verdict, &binding, &root_cause_signature);

        let raw_matches = result.get("matches").and_then(Value::as_array).cloned().unwrap_or_default();
        let matches: Vec<Value> = raw_matches
            .into_iter()
            .map(|mut m| {
                if m.get("id").is_none() || m.get("id") == Some(&Value::Null) {
                    let finding_id = candidate.get("id").cloned().unwrap_or(Value::Null);
                    let id = stable_id(
                        "security-variant-match",
                        &json!({
                            "findingId": finding_id,
                            "semanticFingerprint": m.get("semanticFingerprint").cloned().unwrap_or(Value::Null),
                            "file": m.get("file").cloned().unwrap_or(Value::Null),
                            "line": m.get("line").cloned().unwrap_or(Value::Null),
                        }),
                    );
                    if let Value::Object(map) = &mut m {
                        map.insert("id".to_string(), Value::String(id));
                    }
                }
                m
            })
            .collect();

        let summary = summarize(&matches);
        let denominator = result.get("denominator").cloned().unwrap_or(Value::Null);
        let strategies = result.get("strategies").and_then(Value::as_array).cloned().unwrap_or_default();
        let coverage_gaps = result.get("coverageGaps").and_then(Value::as_array).cloned().unwrap_or_default();

        let denominator_expected_eq_examined = denominator
            .get("expected")
            .zip(denominator.get("examined"))
            .is_some_and(|(e, x)| e == x);
        let denominator_unexamined_empty = denominator
            .get("unexamined")
            .and_then(Value::as_array)
            .map(|a| a.is_empty())
            .unwrap_or(false);
        let summary_enumerated_eq_matches = summary.get("enumerated").and_then(Value::as_u64) == Some(matches.len() as u64);
        let summary_examined_eq_matches = summary.get("examined").and_then(Value::as_u64) == Some(matches.len() as u64);
        let summary_unresolved_zero = summary.get("unresolved").and_then(Value::as_u64) == Some(0);
        let strategies_all_complete = strategies
            .iter()
            .all(|s| s.get("complete").and_then(Value::as_bool) == Some(true));

        let complete = !denominator.is_null()
            && denominator_expected_eq_examined
            && denominator_unexamined_empty
            && summary_enumerated_eq_matches
            && summary_examined_eq_matches
            && summary_unresolved_zero
            && strategies_all_complete
            && coverage_gaps.is_empty();

        let receipt_digest = digest(&json!({
            "findingId": candidate.get("id").cloned().unwrap_or(Value::Null),
            "rootCauseSignature": root_cause_signature.clone(),
            "denominator": denominator.clone(),
            "strategies": strategies.clone(),
            "matches": matches.clone(),
        }));

        receipts.push(json!({
            "schemaVersion": 2,
            "kind": "security-variant-receipt",
            "findingId": candidate.get("id").cloned().unwrap_or(Value::Null),
            "ruleId": candidate.get("ruleId").cloned().unwrap_or(Value::Null),
            "rootCauseSignature": root_cause_signature,
            "provider": "security.variant-analysis",
            "providerVersion": "2",
            "binding": binding.clone(),
            "denominator": denominator,
            "strategies": strategies,
            "matches": matches,
            "summary": summary,
            "complete": complete,
            "coverageGaps": coverage_gaps,
            "receiptDigest": receipt_digest,
        }));
    }

    let complete = receipts.iter().all(|r| r.get("complete").and_then(Value::as_bool) == Some(true));
    let coverage_gaps: Vec<Value> = receipts
        .iter()
        .filter(|r| r.get("complete").and_then(Value::as_bool) != Some(true))
        .map(|r| json!({ "kind": "variant-incomplete", "findingId": r.get("findingId").cloned().unwrap_or(Value::Null) }))
        .collect();

    Ok(json!({
        "schemaVersion": 2,
        "kind": "security-variant-results",
        "provider": "security.variant-analysis",
        "providerVersion": "2",
        "binding": binding,
        "complete": complete,
        "receipts": receipts,
        "coverageGaps": coverage_gaps,
    }))
}
