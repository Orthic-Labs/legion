//! Packet P11d — providers/{ai-quality,accessibility,copy/claims} and the
//! provider suite orchestrators (accessibility, data, framework,
//! generic-source, infrastructure, security). Faithful Rust ports of the JS
//! sources under `src/providers/**`; see `full-P11d.md` for the packet
//! table. Not wired into `NativeProviderRegistry` dispatch (same posture as
//! the sibling `p11_frameworks` module) — these are pure-logic ports pending
//! an owning dispatch decision.
//!
//! Deferred (delegate to JS deps outside this packet, not yet ported):
//! `accessibility/contrast.mjs` (-> `providers/visual/color.mjs`) and
//! `copy/claims.mjs` (-> `lib/content/claim-proof-ledger.mjs`).
//! `registry/provider-registry.mjs` is out of scope: the registry is already
//! ported to `providers.json` + Rust dispatch per packet instructions.

use regex::Regex;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

fn digest_id(parts: &[&str]) -> String {
    format!("sha256:{}", sha256_hex(parts.join("\0").as_bytes()))
}

fn line_at(text: &str, index: usize) -> usize {
    text.get(..index.min(text.len())).unwrap_or("").matches('\n').count() + 1
}

// =====================================================================
// providers/ai-quality/contracts.mjs
// =====================================================================
pub mod ai_quality {
    use super::*;

    pub const METRICS: &[&str] = &[
        "declared-task-eval",
        "groundedness",
        "citation-faithfulness",
        "retrieval-relevance",
        "structured-output-validity",
        "tool-selection-argument-correctness",
        "uncertainty-abstention-calibration",
        "refusal-fallback",
        "context-truncation",
        "prompt-robustness",
        "model-provider-version-drift",
        "reproducibility",
        "latency",
        "cost",
        "human-override",
        "feedback-loop",
        "subgroup-fairness",
    ];

    pub const VERDICTS: &[&str] = &["pass", "fail", "review-required", "unproven"];

    // Security-shaped fields that must never appear on a quality receipt —
    // a quality verdict is never a security verdict.
    const FORBIDDEN_FIELDS: &[&str] = &[
        "severity",
        "severityHint",
        "evidenceStrength",
        "candidateClass",
        "adjudicationRequired",
    ];

    pub fn assert_metric(value: &str) -> Result<(), String> {
        if METRICS.contains(&value) {
            Ok(())
        } else {
            Err(format!("unknown ai-quality metric: {value}"))
        }
    }

    pub fn assert_quality_verdict(value: &str) -> Result<(), String> {
        if VERDICTS.contains(&value) {
            Ok(())
        } else {
            Err(format!("unknown ai-quality verdict: {value}"))
        }
    }

    /// Canonicalizes a `Value` by recursively sorting object keys, matching
    /// JS `canonicalize()`.
    pub fn canonicalize(value: &Value) -> Value {
        match value {
            Value::Array(items) => Value::Array(items.iter().map(canonicalize).collect()),
            Value::Object(map) => {
                let mut keys: Vec<&String> = map.keys().collect();
                keys.sort();
                let mut out = Map::new();
                for key in keys {
                    out.insert(key.clone(), canonicalize(&map[key]));
                }
                Value::Object(out)
            }
            other => other.clone(),
        }
    }

    pub fn stable_id(namespace: &str, value: &Value) -> String {
        let body = serde_json::to_string(&canonicalize(value)).unwrap_or_default();
        format!("sha256:{}", sha256_hex(format!("{namespace}\0{body}").as_bytes()))
    }

    pub fn assert_binding(binding: &Value) -> Result<(), String> {
        let obj = binding.as_object().ok_or("binding must be an object")?;
        for key in [
            "planDigest",
            "repositoryRevision",
            "blueprintGenerationId",
            "blueprintManifestDigest",
            "registryDigest",
        ] {
            match obj.get(key).and_then(Value::as_str) {
                Some(s) if !s.is_empty() => {}
                _ => return Err(format!("binding.{key} must be a non-empty string")),
            }
        }
        match obj.get("dirtyPatchDigest") {
            Some(Value::Null) | None => {}
            Some(Value::String(s)) if !s.is_empty() => {}
            _ => return Err("binding.dirtyPatchDigest must be a non-empty string".into()),
        }
        Ok(())
    }

    pub fn assert_evaluation_receipt(receipt: &Value) -> Result<(), String> {
        let obj = receipt.as_object().ok_or("evaluation receipt must be an object")?;
        if obj.get("schemaVersion").and_then(Value::as_i64) != Some(1) {
            return Err("ai-quality-evaluation-receipt unsupported schemaVersion".into());
        }
        if obj.get("kind").and_then(Value::as_str) != Some("ai-quality-evaluation-receipt") {
            return Err("unexpected kind".into());
        }
        assert_metric(obj.get("metric").and_then(Value::as_str).unwrap_or_default())?;
        assert_quality_verdict(obj.get("verdict").and_then(Value::as_str).unwrap_or_default())?;
        for key in [
            "modelIdentity",
            "promptIdentity",
            "datasetVersion",
            "runConditions",
            "judgeIdentity",
            "denominator",
            "measurement",
        ] {
            if !obj.get(key).map(Value::is_object).unwrap_or(false) {
                return Err(format!("receipt.{key} must be an object"));
            }
        }
        for key in ["limitations", "uncertainty", "evidenceRefs"] {
            if !obj.get(key).map(Value::is_array).unwrap_or(false) {
                return Err(format!("receipt.{key} must be an array"));
            }
        }
        assert_binding(obj.get("binding").unwrap_or(&Value::Null))?;
        for forbidden in FORBIDDEN_FIELDS {
            if obj.contains_key(*forbidden) {
                return Err(format!(
                    "ai-quality-evaluation-receipt must not carry security-shaped field {forbidden}"
                ));
            }
        }
        Ok(())
    }

    // -----------------------------------------------------------------
    // receipt.mjs :: buildEvaluationReceipt
    // -----------------------------------------------------------------
    pub struct ScorerResult {
        pub verdict: &'static str,
        pub measurement: Value,
        pub limitations: Vec<String>,
        pub uncertainty: Vec<String>,
    }

    pub struct Identity {
        pub model_identity: Value,
        pub prompt_identity: Value,
        pub retrieval_tool_config: Option<Value>,
        pub dataset_version: Value,
        pub run_conditions: Value,
        pub judge_identity: Value,
    }

    pub fn build_evaluation_receipt(
        metric: &str,
        metric_version: &str,
        scorer_result: &ScorerResult,
        identity: &Identity,
        denominator: &Value,
        binding: &Value,
        evidence_refs: &[String],
    ) -> Result<Value, String> {
        assert_metric(metric)?;
        assert_quality_verdict(scorer_result.verdict)?;
        assert_binding(binding)?;

        let mut limitations = scorer_result.limitations.clone();
        limitations.sort();
        let mut uncertainty = scorer_result.uncertainty.clone();
        uncertainty.sort();
        let mut refs: Vec<String> = evidence_refs.to_vec();
        refs.sort();
        refs.dedup();

        let mut body = Map::new();
        body.insert("schemaVersion".into(), json!(1));
        body.insert("kind".into(), json!("ai-quality-evaluation-receipt"));
        body.insert("metric".into(), json!(metric));
        body.insert("metricVersion".into(), json!(metric_version));
        body.insert("verdict".into(), json!(scorer_result.verdict));
        body.insert("modelIdentity".into(), identity.model_identity.clone());
        body.insert("promptIdentity".into(), identity.prompt_identity.clone());
        body.insert(
            "retrievalToolConfig".into(),
            identity.retrieval_tool_config.clone().unwrap_or(Value::Null),
        );
        body.insert("datasetVersion".into(), identity.dataset_version.clone());
        body.insert("runConditions".into(), identity.run_conditions.clone());
        body.insert("judgeIdentity".into(), identity.judge_identity.clone());
        body.insert("denominator".into(), denominator.clone());
        body.insert("measurement".into(), scorer_result.measurement.clone());
        body.insert("limitations".into(), json!(limitations));
        body.insert("uncertainty".into(), json!(uncertainty));
        body.insert("evidenceRefs".into(), json!(refs));
        body.insert("binding".into(), binding.clone());

        let id = stable_id("ai-quality-evaluation-receipt", &Value::Object(body.clone()));
        body.insert("id".into(), json!(id));
        Ok(Value::Object(body))
    }

    // -----------------------------------------------------------------
    // schema-builder.mjs :: buildEvaluationReceiptSchema (structure only;
    // no schema emission required by this packet's test surface, kept as a
    // pure function for parity / future schema-drift tests).
    // -----------------------------------------------------------------
    pub fn build_evaluation_receipt_schema() -> Value {
        let sha = json!({ "type": "string", "pattern": "^sha256:" });
        let nullable_sha = json!({ "oneOf": [{ "type": "null" }, { "type": "string", "pattern": "^sha256:" }] });
        let strings = json!({ "type": "array", "items": { "type": "string" } });
        json!({
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "$id": "https://orthic.dev/schemas/ai-quality/evaluation-receipt-v1.json",
            "title": "AiQualityEvaluationReceiptV1",
            "type": "object",
            "required": [
                "schemaVersion", "kind", "id", "metric", "metricVersion", "verdict",
                "modelIdentity", "promptIdentity", "datasetVersion", "runConditions",
                "judgeIdentity", "denominator", "measurement", "limitations",
                "uncertainty", "evidenceRefs", "binding",
            ],
            "properties": {
                "schemaVersion": { "const": 1 },
                "kind": { "const": "ai-quality-evaluation-receipt" },
                "id": sha,
                "metric": { "enum": METRICS },
                "metricVersion": { "type": "string" },
                "verdict": { "enum": VERDICTS },
                "modelIdentity": {
                    "type": "object",
                    "required": ["provider", "model", "version"],
                    "properties": {
                        "provider": { "type": "string" },
                        "model": { "type": "string" },
                        "version": { "type": "string" },
                    },
                    "additionalProperties": true,
                },
                "promptIdentity": {
                    "type": "object",
                    "required": ["templateId", "templateVersion", "promptDigest"],
                    "properties": {
                        "templateId": { "type": "string" },
                        "templateVersion": { "type": "string" },
                        "promptDigest": sha,
                    },
                    "additionalProperties": true,
                },
                "retrievalToolConfig": {
                    "oneOf": [
                        { "type": "null" },
                        {
                            "type": "object",
                            "properties": {
                                "retrieverId": { "type": "string" },
                                "retrieverConfigDigest": nullable_sha,
                                "toolsetId": { "type": "string" },
                                "toolsetConfigDigest": nullable_sha,
                            },
                            "additionalProperties": true,
                        },
                    ],
                },
                "datasetVersion": {
                    "type": "object",
                    "required": ["datasetId", "version", "digest"],
                    "properties": {
                        "datasetId": { "type": "string" },
                        "version": { "type": "string" },
                        "digest": sha,
                    },
                    "additionalProperties": true,
                },
                "runConditions": {
                    "type": "object",
                    "required": ["runId", "environment"],
                    "properties": {
                        "runId": { "type": "string" },
                        "environment": { "type": "string" },
                        "seed": { "type": ["string", "number", "null"] },
                    },
                    "additionalProperties": true,
                },
                "judgeIdentity": {
                    "type": "object",
                    "required": ["kind", "id"],
                    "properties": {
                        "kind": { "enum": ["human", "automated-metric", "llm-judge"] },
                        "id": { "type": "string" },
                    },
                    "additionalProperties": true,
                },
                "denominator": {
                    "type": "object",
                    "required": ["kind", "expected", "examined"],
                    "properties": {
                        "kind": { "type": "string" },
                        "expected": { "type": "number" },
                        "examined": { "type": "number" },
                        "digest": nullable_sha,
                    },
                    "additionalProperties": true,
                },
                "measurement": { "type": "object" },
                "limitations": strings,
                "uncertainty": strings,
                "evidenceRefs": strings,
                "binding": {
                    "type": "object",
                    "required": ["planDigest", "repositoryRevision", "dirtyPatchDigest", "blueprintGenerationId", "blueprintManifestDigest", "registryDigest"],
                    "properties": {
                        "planDigest": sha,
                        "repositoryRevision": { "type": "string", "minLength": 1 },
                        "dirtyPatchDigest": nullable_sha,
                        "blueprintGenerationId": { "type": "string", "minLength": 1 },
                        "blueprintManifestDigest": sha,
                        "registryDigest": sha,
                    },
                    "additionalProperties": false,
                },
            },
            "additionalProperties": false,
        })
    }

    // -----------------------------------------------------------------
    // evaluators/*.mjs — all consume recorded fixture data only.
    // -----------------------------------------------------------------
    pub mod evaluators {
        use super::*;

        fn unproven(reason: &str) -> ScorerResult {
            ScorerResult {
                verdict: "unproven",
                measurement: json!({}),
                limitations: vec![reason.to_string()],
                uncertainty: vec![],
            }
        }

        fn get_f64(v: &Value, key: &str) -> Option<f64> {
            v.get(key).and_then(Value::as_f64)
        }
        fn get_bool(v: &Value, key: &str) -> Option<bool> {
            v.get(key).and_then(Value::as_bool)
        }
        fn get_arr<'a>(v: &'a Value, key: &str) -> Option<&'a Vec<Value>> {
            v.get(key).and_then(Value::as_array)
        }

        // grounded-retrieval.mjs -------------------------------------
        pub fn score_declared_task_eval(fixture: &Value) -> ScorerResult {
            let criteria = match get_arr(fixture, "declaredCriteria") {
                Some(c) if !c.is_empty() => c,
                _ => return unproven("no declared task criteria recorded for this run"),
            };
            let unmet: Vec<Value> = criteria
                .iter()
                .filter(|c| c.get("met").and_then(Value::as_bool) != Some(true))
                .map(|c| c.get("id").cloned().unwrap_or(Value::Null))
                .collect();
            ScorerResult {
                verdict: if unmet.is_empty() { "pass" } else { "fail" },
                measurement: json!({ "criteriaCount": criteria.len(), "unmetCriteria": unmet }),
                limitations: vec![],
                uncertainty: vec![
                    "Declared criteria are author-specified; criteria completeness itself is not evaluated here."
                        .to_string(),
                ],
            }
        }

        pub fn score_groundedness(fixture: &Value) -> ScorerResult {
            let claims = get_arr(fixture, "claims");
            let context_span_ids = get_arr(fixture, "contextSpanIds");
            let (claims, context_span_ids) = match (claims, context_span_ids) {
                (Some(c), Some(s)) if !c.is_empty() => (c, s),
                _ => return unproven("no claim/context-span record recorded for this run"),
            };
            let ungrounded: Vec<Value> = claims
                .iter()
                .filter(|c| {
                    let supporting = c.get("supportingSpanIds").and_then(Value::as_array);
                    match supporting {
                        Some(ids) if !ids.is_empty() => {
                            !ids.iter().all(|id| context_span_ids.contains(id))
                        }
                        _ => true,
                    }
                })
                .map(|c| c.get("text").cloned().unwrap_or(Value::Null))
                .collect();
            ScorerResult {
                verdict: if ungrounded.is_empty() { "pass" } else { "fail" },
                measurement: json!({ "claimCount": claims.len(), "ungroundedClaims": ungrounded }),
                limitations: vec![],
                uncertainty: vec![
                    "Span-level support is necessary but not sufficient for semantic entailment; entailment itself is not checked here."
                        .to_string(),
                ],
            }
        }

        pub fn score_citation_faithfulness(fixture: &Value) -> ScorerResult {
            let citations = get_arr(fixture, "citations");
            let source_spans = fixture.get("sourceSpans").and_then(Value::as_object);
            let (citations, source_spans) = match (citations, source_spans) {
                (Some(c), Some(s)) if !c.is_empty() => (c, s),
                _ => return unproven("no citation/source-span record recorded for this run"),
            };
            let unfaithful: Vec<Value> = citations
                .iter()
                .filter(|c| {
                    let span_id = c.get("citedSpanId").and_then(Value::as_str).unwrap_or_default();
                    let cited_text = c.get("citedText").and_then(Value::as_str).unwrap_or("\0");
                    match source_spans.get(span_id).and_then(Value::as_str) {
                        Some(span) => !span.contains(cited_text),
                        None => true,
                    }
                })
                .map(|c| c.get("claimText").cloned().unwrap_or(Value::Null))
                .collect();
            ScorerResult {
                verdict: if unfaithful.is_empty() { "pass" } else { "fail" },
                measurement: json!({ "citationCount": citations.len(), "unfaithfulCitations": unfaithful }),
                limitations: vec![],
                uncertainty: vec![
                    "Substring containment is a proxy for faithfulness; paraphrase-level faithfulness is not checked here."
                        .to_string(),
                ],
            }
        }

        pub fn score_retrieval_relevance(fixture: &Value) -> ScorerResult {
            let docs = get_arr(fixture, "retrievedDocs");
            let threshold = get_f64(fixture, "relevanceThreshold");
            let (docs, threshold) = match (docs, threshold) {
                (Some(d), Some(t)) if !d.is_empty() => (d, t),
                _ => return unproven("no retrieved-document relevance record recorded for this run"),
            };
            let relevant_count = docs
                .iter()
                .filter(|d| d.get("relevant").and_then(Value::as_bool) == Some(true))
                .count();
            let ratio = relevant_count as f64 / docs.len() as f64;
            ScorerResult {
                verdict: if ratio >= threshold { "pass" } else { "fail" },
                measurement: json!({ "docCount": docs.len(), "relevantCount": relevant_count, "ratio": ratio, "threshold": threshold }),
                limitations: vec![],
                uncertainty: vec!["Relevance labels are recorded judgments, not re-derived here.".to_string()],
            }
        }

        // output-tooling.mjs ------------------------------------------
        fn type_matches(value: &Value, expected_type: &str) -> bool {
            match expected_type {
                "array" => value.is_array(),
                "null" => value.is_null(),
                "string" => value.is_string(),
                "number" => value.is_number(),
                "boolean" => value.is_boolean(),
                "object" => value.is_object(),
                _ => false,
            }
        }

        pub fn score_structured_output_validity(fixture: &Value) -> ScorerResult {
            let output = fixture.get("output");
            let required_fields = get_arr(fixture, "requiredFields");
            let (output, required_fields) = match (output, required_fields) {
                (Some(o), Some(f)) if !f.is_empty() => (o, f),
                _ => return unproven("no structured-output/required-field record recorded for this run"),
            };
            let empty_obj = Map::new();
            let output_obj = output.as_object().unwrap_or(&empty_obj);
            let violations: Vec<Value> = required_fields
                .iter()
                .filter(|f| {
                    let name = f.get("name").and_then(Value::as_str).unwrap_or_default();
                    let expected_type = f.get("type").and_then(Value::as_str).unwrap_or_default();
                    match output_obj.get(name) {
                        Some(v) => !type_matches(v, expected_type),
                        None => true,
                    }
                })
                .map(|f| f.get("name").cloned().unwrap_or(Value::Null))
                .collect();
            ScorerResult {
                verdict: if violations.is_empty() { "pass" } else { "fail" },
                measurement: json!({ "requiredFieldCount": required_fields.len(), "violatingFields": violations }),
                limitations: vec![],
                uncertainty: vec![
                    "Shallow required-field/type checking only; nested schema constraints are not evaluated here."
                        .to_string(),
                ],
            }
        }

        pub fn score_tool_selection_argument_correctness(fixture: &Value) -> ScorerResult {
            let expected_tool = fixture.get("expectedTool").and_then(Value::as_str);
            let selected_tool = fixture.get("selectedTool").and_then(Value::as_str);
            let (expected_tool, selected_tool) = match (expected_tool, selected_tool) {
                (Some(e), Some(s)) if !e.is_empty() && !s.is_empty() => (e, s),
                _ => return unproven("no expected/selected tool record recorded for this run"),
            };
            let tool_correct = expected_tool == selected_tool;
            let expected_args = fixture.get("expectedArgs").cloned().unwrap_or(json!({}));
            let actual_args = fixture.get("actualArgs").cloned().unwrap_or(json!({}));
            let args_correct = canonicalize(&expected_args) == canonicalize(&actual_args);
            ScorerResult {
                verdict: if tool_correct && args_correct { "pass" } else { "fail" },
                measurement: json!({ "expectedTool": expected_tool, "selectedTool": selected_tool, "toolCorrect": tool_correct, "argsCorrect": args_correct }),
                limitations: vec![],
                uncertainty: vec![
                    "Argument equality is exact-match on canonicalized JSON; semantically-equivalent-but-differently-shaped arguments are marked incorrect."
                        .to_string(),
                ],
            }
        }

        // calibration-fallback.mjs -------------------------------------
        pub fn score_uncertainty_calibration(fixture: &Value) -> ScorerResult {
            let predictions = get_arr(fixture, "predictions");
            let threshold = get_f64(fixture, "calibrationGapThreshold").unwrap_or(0.15);
            let predictions = match predictions {
                Some(p) if !p.is_empty() => p,
                _ => return unproven("no confidence/correctness record recorded for this run"),
            };
            let n = predictions.len() as f64;
            let avg_confidence: f64 =
                predictions.iter().filter_map(|p| get_f64(p, "confidence")).sum::<f64>() / n;
            let accuracy = predictions
                .iter()
                .filter(|p| p.get("correct").and_then(Value::as_bool) == Some(true))
                .count() as f64
                / n;
            let calibration_gap = (avg_confidence - accuracy).abs();
            ScorerResult {
                verdict: if calibration_gap <= threshold { "pass" } else { "fail" },
                measurement: json!({ "avgConfidence": avg_confidence, "accuracy": accuracy, "calibrationGap": calibration_gap, "threshold": threshold, "sampleCount": predictions.len() }),
                limitations: vec![],
                uncertainty: vec![
                    "A single aggregate calibration gap can mask per-bucket overconfidence; per-bucket calibration is not computed here."
                        .to_string(),
                ],
            }
        }

        pub fn score_refusal_fallback(fixture: &Value) -> ScorerResult {
            let should_refuse = get_bool(fixture, "shouldRefuse");
            let did_refuse = get_bool(fixture, "didRefuse");
            let (should_refuse, did_refuse) = match (should_refuse, did_refuse) {
                (Some(s), Some(d)) => (s, d),
                _ => return unproven("no refusal-expectation record recorded for this run"),
            };
            let fallback_taken = get_bool(fixture, "fallbackTaken");
            let refusal_correct = should_refuse == did_refuse;
            let fallback_ok = !should_refuse || fallback_taken == Some(true);
            ScorerResult {
                verdict: if refusal_correct && fallback_ok { "pass" } else { "fail" },
                measurement: json!({ "shouldRefuse": should_refuse, "didRefuse": did_refuse, "refusalCorrect": refusal_correct, "fallbackTaken": fallback_taken }),
                limitations: vec![],
                uncertainty: vec![],
            }
        }

        pub fn score_context_truncation(fixture: &Value) -> ScorerResult {
            let required = get_arr(fixture, "requiredSpanIds");
            let included = get_arr(fixture, "includedSpanIds");
            let (required, included) = match (required, included) {
                (Some(r), Some(i)) if !r.is_empty() => (r, i),
                _ => return unproven("no required/included context-span record recorded for this run"),
            };
            let truncated_away: Vec<Value> = required
                .iter()
                .filter(|id| !included.contains(id))
                .cloned()
                .collect();
            ScorerResult {
                verdict: if truncated_away.is_empty() { "pass" } else { "fail" },
                measurement: json!({ "requiredCount": required.len(), "truncatedAway": truncated_away }),
                limitations: vec![],
                uncertainty: vec![],
            }
        }

        pub fn score_prompt_robustness(fixture: &Value) -> ScorerResult {
            let variant_results = get_arr(fixture, "variantResults");
            let threshold = get_f64(fixture, "matchThreshold").unwrap_or(0.8);
            let variant_results = match variant_results {
                Some(v) if !v.is_empty() => v,
                _ => return unproven("no prompt-variant record recorded for this run"),
            };
            let matching = variant_results
                .iter()
                .filter(|v| v.get("semanticMatch").and_then(Value::as_bool) == Some(true))
                .count();
            let ratio = matching as f64 / variant_results.len() as f64;
            ScorerResult {
                verdict: if ratio >= threshold { "pass" } else { "fail" },
                measurement: json!({ "variantCount": variant_results.len(), "matching": matching, "ratio": ratio, "threshold": threshold }),
                limitations: vec![],
                uncertainty: vec![
                    "semanticMatch is a recorded judgment on each variant, not re-derived here.".to_string(),
                ],
            }
        }

        // drift-repro.mjs ------------------------------------------------
        pub fn score_model_provider_version_drift(fixture: &Value) -> ScorerResult {
            let baseline_score = get_f64(fixture, "baselineScore");
            let current_score = get_f64(fixture, "currentScore");
            let (baseline_score, current_score) = match (baseline_score, current_score) {
                (Some(b), Some(c)) => (b, c),
                _ => return unproven("no baseline/current score record recorded for this run"),
            };
            let threshold = get_f64(fixture, "driftThreshold").unwrap_or(0.05);
            let delta = (current_score - baseline_score).abs();
            ScorerResult {
                verdict: if delta <= threshold { "pass" } else { "fail" },
                measurement: json!({
                    "baselineVersion": fixture.get("baselineVersion").cloned().unwrap_or(Value::Null),
                    "currentVersion": fixture.get("currentVersion").cloned().unwrap_or(Value::Null),
                    "baselineScore": baseline_score, "currentScore": current_score, "delta": delta, "threshold": threshold,
                }),
                limitations: vec![],
                uncertainty: vec![
                    "A single aggregate score delta can mask distributional drift on a specific eval slice."
                        .to_string(),
                ],
            }
        }

        pub fn score_reproducibility(fixture: &Value) -> ScorerResult {
            let run_digests = get_arr(fixture, "runDigests");
            let run_digests = match run_digests {
                Some(d) if d.len() >= 2 => d,
                _ => {
                    return unproven(
                        "fewer than 2 recorded run digests; reproducibility cannot be evaluated",
                    )
                }
            };
            let distinct: std::collections::HashSet<String> = run_digests
                .iter()
                .map(|v| serde_json::to_string(v).unwrap_or_default())
                .collect();
            ScorerResult {
                verdict: if distinct.len() == 1 { "pass" } else { "fail" },
                measurement: json!({ "runCount": run_digests.len(), "distinctOutputCount": distinct.len() }),
                limitations: vec![],
                uncertainty: vec![
                    "Digest equality checks exact-output reproducibility, not semantic equivalence across runs."
                        .to_string(),
                ],
            }
        }

        // ops.mjs ----------------------------------------------------------
        pub fn score_latency(fixture: &Value) -> ScorerResult {
            let p95 = get_f64(fixture, "p95Ms");
            let budget = get_f64(fixture, "budgetMs");
            let (p95, budget) = match (p95, budget) {
                (Some(p), Some(b)) => (p, b),
                _ => return unproven("no p95/budget latency record recorded for this run"),
            };
            ScorerResult {
                verdict: if p95 <= budget { "pass" } else { "fail" },
                measurement: json!({ "p95Ms": p95, "budgetMs": budget }),
                limitations: vec![],
                uncertainty: vec![],
            }
        }

        pub fn score_cost(fixture: &Value) -> ScorerResult {
            let cost = get_f64(fixture, "costUsd");
            let budget = get_f64(fixture, "budgetUsd");
            let (cost, budget) = match (cost, budget) {
                (Some(c), Some(b)) => (c, b),
                _ => return unproven("no cost/budget record recorded for this run"),
            };
            ScorerResult {
                verdict: if cost <= budget { "pass" } else { "fail" },
                measurement: json!({ "costUsd": cost, "budgetUsd": budget }),
                limitations: vec![],
                uncertainty: vec![],
            }
        }

        pub fn score_human_override(fixture: &Value) -> ScorerResult {
            let override_available = match get_bool(fixture, "overrideAvailable") {
                Some(v) => v,
                None => return unproven("no human-override-availability record recorded for this run"),
            };
            if !override_available {
                return ScorerResult {
                    verdict: "fail",
                    measurement: json!({ "overrideAvailable": override_available }),
                    limitations: vec![],
                    uncertainty: vec![],
                };
            }
            match get_bool(fixture, "overrideTestedSuccessfully") {
                None => ScorerResult {
                    verdict: "review-required",
                    measurement: json!({ "overrideAvailable": override_available }),
                    limitations: vec!["override is declared available but was not exercised in this run".to_string()],
                    uncertainty: vec![],
                },
                Some(tested_ok) => ScorerResult {
                    verdict: if tested_ok { "pass" } else { "fail" },
                    measurement: json!({ "overrideAvailable": override_available, "overrideTestedSuccessfully": tested_ok }),
                    limitations: vec![],
                    uncertainty: vec![],
                },
            }
        }

        pub fn score_feedback_loop(fixture: &Value) -> ScorerResult {
            let feedback_captured = match get_bool(fixture, "feedbackCaptured") {
                Some(v) => v,
                None => return unproven("no feedback-capture record recorded for this run"),
            };
            if !feedback_captured {
                return ScorerResult {
                    verdict: "fail",
                    measurement: json!({ "feedbackCaptured": feedback_captured }),
                    limitations: vec![],
                    uncertainty: vec![],
                };
            }
            let applied = get_bool(fixture, "feedbackAppliedToNextEvalVersion").unwrap_or(false);
            ScorerResult {
                verdict: if applied { "pass" } else { "fail" },
                measurement: json!({ "feedbackCaptured": feedback_captured, "feedbackAppliedToNextEvalVersion": applied }),
                limitations: vec![],
                uncertainty: vec![],
            }
        }

        // fairness.mjs -----------------------------------------------------
        pub fn score_subgroup_fairness(fixture: &Value) -> ScorerResult {
            let subgroups = get_arr(fixture, "policySelectedSubgroups");
            let subgroups = match subgroups {
                Some(s) if !s.is_empty() => s,
                _ => {
                    return unproven(
                        "no policy-selected subgroup set recorded for this run; fairness is not applicable without an explicit policy selection",
                    )
                }
            };
            let threshold = match get_f64(fixture, "parityThreshold") {
                Some(t) => t,
                None => return unproven("no parity threshold recorded for this run"),
            };
            let values: Vec<f64> = subgroups.iter().filter_map(|s| get_f64(s, "metricValue")).collect();
            let max = values.iter().cloned().fold(f64::MIN, f64::max);
            let min = values.iter().cloned().fold(f64::MAX, f64::min);
            let gap = max - min;
            let mut names: Vec<Value> = subgroups
                .iter()
                .map(|s| s.get("name").cloned().unwrap_or(Value::Null))
                .collect();
            names.sort_by(|a, b| a.to_string().cmp(&b.to_string()));
            ScorerResult {
                verdict: if gap <= threshold { "pass" } else { "fail" },
                measurement: json!({ "subgroupCount": subgroups.len(), "gap": gap, "threshold": threshold, "subgroups": names }),
                limitations: vec![],
                uncertainty: vec![
                    "Only the policy-selected subgroups and metric are evaluated; subgroups outside the policy selection are out of scope for this receipt."
                        .to_string(),
                ],
            }
        }
    }

    // -----------------------------------------------------------------
    // index.mjs :: evaluateAiQuality — dispatch table over every declared
    // metric. Mirrors the JS module-load-time completeness assertion via
    // `dispatch()` covering every `METRICS` entry (exercised by a test).
    // -----------------------------------------------------------------
    pub fn dispatch(metric: &str, fixture: &Value) -> Result<ScorerResult, String> {
        use evaluators::*;
        Ok(match metric {
            "declared-task-eval" => score_declared_task_eval(fixture),
            "groundedness" => score_groundedness(fixture),
            "citation-faithfulness" => score_citation_faithfulness(fixture),
            "retrieval-relevance" => score_retrieval_relevance(fixture),
            "structured-output-validity" => score_structured_output_validity(fixture),
            "tool-selection-argument-correctness" => score_tool_selection_argument_correctness(fixture),
            "uncertainty-abstention-calibration" => score_uncertainty_calibration(fixture),
            "refusal-fallback" => score_refusal_fallback(fixture),
            "context-truncation" => score_context_truncation(fixture),
            "prompt-robustness" => score_prompt_robustness(fixture),
            "model-provider-version-drift" => score_model_provider_version_drift(fixture),
            "reproducibility" => score_reproducibility(fixture),
            "latency" => score_latency(fixture),
            "cost" => score_cost(fixture),
            "human-override" => score_human_override(fixture),
            "feedback-loop" => score_feedback_loop(fixture),
            "subgroup-fairness" => score_subgroup_fairness(fixture),
            other => return Err(format!("unknown ai-quality metric: {other}")),
        })
    }

    pub fn evaluate_ai_quality(
        metric: &str,
        metric_version: &str,
        fixture: &Value,
        identity: &Identity,
        denominator: &Value,
        binding: &Value,
        evidence_refs: &[String],
    ) -> Result<Value, String> {
        assert_metric(metric)?;
        let scorer_result = dispatch(metric, fixture)?;
        build_evaluation_receipt(
            metric,
            metric_version,
            &scorer_result,
            identity,
            denominator,
            binding,
            evidence_refs,
        )
    }
}

// =====================================================================
// providers/accessibility/runtime/core.mjs :: analyzeRuntimeAccessibility
// (self-contained; the contrast.mjs wrapper is deferred — see module doc)
// =====================================================================
pub mod accessibility_runtime {
    use super::*;

    pub fn analyze_runtime_accessibility(
        engine: Option<&Value>,
        required_cases: &[Value],
        runs: &[Value],
        required_exercises: &[String],
        exercised: &[String],
    ) -> Value {
        let engine = match engine {
            Some(e) => e,
            None => {
                return json!({
                    "provider": "accessibility.runtime", "status": "unproven", "complete": false,
                    "findings": [], "coverageGaps": ["accessibility-engine-unavailable"],
                })
            }
        };
        if required_cases.is_empty() && required_exercises.is_empty() {
            return json!({
                "provider": "accessibility.runtime", "status": "unproven", "complete": false,
                "findings": [], "coverageGaps": ["zero-accessibility-denominator"],
            });
        }
        let key = |item: &Value| {
            format!(
                "{}:{}",
                item.get("surfaceId").map(|v| v.to_string()).unwrap_or_default(),
                item.get("state").map(|v| v.to_string()).unwrap_or_default()
            )
        };
        let observed: std::collections::HashSet<String> = runs.iter().map(key).collect();
        let mut coverage_gaps: Vec<Value> = required_cases
            .iter()
            .filter(|item| !observed.contains(&key(item)))
            .map(|item| json!(format!("runtime-case-untested:{}", key(item))))
            .collect();
        let exercised_set: std::collections::HashSet<&String> = exercised.iter().collect();
        coverage_gaps.extend(
            required_exercises
                .iter()
                .filter(|name| !exercised_set.contains(name))
                .map(|name| json!(format!("runtime-exercise-untested:{name}"))),
        );

        let mut root_causes: Vec<(String, Value)> = Vec::new();
        for run in runs {
            let violations = run.get("violations").and_then(Value::as_array).cloned().unwrap_or_default();
            for violation in violations {
                let rule = violation.get("rule").cloned().unwrap_or(Value::Null);
                let nodes = violation.get("nodes").and_then(Value::as_array).cloned().unwrap_or_default();
                let node_join = nodes
                    .iter()
                    .map(|n| n.as_str().unwrap_or_default().to_string())
                    .collect::<Vec<_>>()
                    .join(",");
                let root = violation
                    .get("rootCause")
                    .and_then(Value::as_str)
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| format!("{}:{}", rule, node_join));
                if let Some((_, current)) = root_causes.iter_mut().find(|(k, _)| *k == root) {
                    let arr = current.get_mut("nodes").unwrap().as_array_mut().unwrap();
                    arr.extend(nodes.clone());
                    current
                        .get_mut("evidenceSets")
                        .unwrap()
                        .as_array_mut()
                        .unwrap()
                        .push(json!({
                            "surfaceId": run.get("surfaceId").cloned().unwrap_or(Value::Null),
                            "state": run.get("state").cloned().unwrap_or(Value::Null),
                            "viewport": run.get("viewport").cloned().unwrap_or(Value::Null),
                        }));
                } else {
                    root_causes.push((
                        root.clone(),
                        json!({
                            "ruleId": rule,
                            "rootCause": root,
                            "nodes": nodes,
                            "evidenceSets": [{
                                "surfaceId": run.get("surfaceId").cloned().unwrap_or(Value::Null),
                                "state": run.get("state").cloned().unwrap_or(Value::Null),
                                "viewport": run.get("viewport").cloned().unwrap_or(Value::Null),
                            }],
                            "engineVersion": engine.get("version").cloned().unwrap_or(Value::Null),
                            "impact": violation.get("impact").cloned().unwrap_or(Value::Null),
                            "accessibleName": violation.get("accessibleName").cloned().unwrap_or(Value::Null),
                            "role": violation.get("role").cloned().unwrap_or(Value::Null),
                            "elementState": violation.get("state").cloned().unwrap_or(Value::Null),
                            "domPath": violation.get("domPath").cloned().unwrap_or(Value::Null),
                            "screenshot": violation.get("screenshot").cloned().unwrap_or(Value::Null),
                        }),
                    ));
                }
            }
        }
        let findings: Vec<Value> = root_causes.into_iter().map(|(_, v)| v).collect();
        let status = if !findings.is_empty() {
            "candidates"
        } else if !coverage_gaps.is_empty() {
            "unproven"
        } else {
            "pass"
        };
        json!({
            "provider": "accessibility.runtime",
            "engine": engine,
            "status": status,
            "complete": coverage_gaps.is_empty(),
            "findings": findings,
            "coverageGaps": coverage_gaps,
        })
    }
}

// =====================================================================
// providers/accessibility-suite.mjs
// =====================================================================
pub mod accessibility_suite {
    use super::*;
    use std::sync::OnceLock;

    const SOURCE_EXTENSIONS: &[&str] = &[
        "html", "htm", "jsx", "tsx", "vue", "svelte", "astro", "css", "scss", "sass", "less",
    ];

    fn finding(rule_id: &str, level: &str, message: &str, file: &str, line: usize) -> Value {
        json!({
            "id": digest_id(&[rule_id, file, &line.to_string()]),
            "ruleId": rule_id, "level": level, "message": message, "file": file, "line": line,
        })
    }

    fn is_non_dom_media_source(file: &str, text: &str) -> bool {
        static PATH_RE: OnceLock<Regex> = OnceLock::new();
        static IMPORT_RE: OnceLock<Regex> = OnceLock::new();
        let path_re = PATH_RE.get_or_init(|| Regex::new(r"(?i)(?:^|[\\/])(?:remotion|\.remotion)(?:[\\/]|$)").unwrap());
        let import_re = IMPORT_RE.get_or_init(|| {
            Regex::new(r#"(?:from\s*|require\(\s*)["'](?:@remotion/[^"']*|remotion)["']"#).unwrap()
        });
        path_re.is_match(file) || import_re.is_match(text)
    }

    struct Rule {
        id: &'static str,
        level: &'static str,
        message: &'static str,
        pattern: &'static str,
    }

    // Only lookahead-free rules stay data-driven; the four rules whose JS
    // source uses `(?!...)` (unsupported by the `regex` crate — see the
    // module doc and `native_providers::p11b_frameworks` for precedent) are
    // reimplemented below as explicit scans with identical semantics.
    const RULES: &[Rule] = &[
        Rule { id: "a11y.positive-tabindex", level: "error", message: "Positive tabindex overrides natural focus order.", pattern: r#"(?i)\btabindex\s*=\s*["']?[1-9][0-9]*["']?"# },
        Rule { id: "a11y.autofocus", level: "warning", message: "Autofocus can move focus unexpectedly; require a documented interaction reason.", pattern: r#"(?i)\b(?:autoFocus|autofocus)\b"# },
    ];

    /// JS: `/<img\b(?![^>]*\balt\s*=)[^>]*>/gi` — an `<img>` tag whose
    /// attributes never contain `alt=`.
    fn collect_image_alt_findings(text: &str, file: &str, findings: &mut Vec<Value>) {
        static IMG_RE: OnceLock<Regex> = OnceLock::new();
        let img_re = IMG_RE.get_or_init(|| Regex::new(r"(?i)<img\b[^>]*>").unwrap());
        static ALT_RE: OnceLock<Regex> = OnceLock::new();
        let alt_re = ALT_RE.get_or_init(|| Regex::new(r"(?i)\balt\s*=").unwrap());
        for m in img_re.find_iter(text) {
            if !alt_re.is_match(m.as_str()) {
                findings.push(finding(
                    "a11y.image-alt",
                    "error",
                    "Image has no alt text or explicit decorative alt=\"\".",
                    file,
                    line_at(text, m.start()),
                ));
            }
        }
    }

    /// JS: `/<button\b(?![^>]*(?:aria-label|aria-labelledby|title)\s*=)[^>]*>\s*(?:<[^>]+>\s*)*<\/button>/gi`
    /// — a button whose opening tag has none of aria-label/aria-labelledby/title.
    fn collect_empty_button_findings(text: &str, file: &str, findings: &mut Vec<Value>) {
        static OPEN_RE: OnceLock<Regex> = OnceLock::new();
        let open_re = OPEN_RE.get_or_init(|| Regex::new(r"(?i)<button\b[^>]*>").unwrap());
        static FULL_RE: OnceLock<Regex> = OnceLock::new();
        let full_re = FULL_RE
            .get_or_init(|| Regex::new(r"(?is)<button\b[^>]*>\s*(?:<[^>]+>\s*)*</button>").unwrap());
        static NAME_RE: OnceLock<Regex> = OnceLock::new();
        let name_re = NAME_RE
            .get_or_init(|| Regex::new(r"(?i)(?:aria-label|aria-labelledby|title)\s*=").unwrap());
        for m in full_re.find_iter(text) {
            let open_tag = open_re.find(m.as_str()).map(|o| o.as_str()).unwrap_or(m.as_str());
            if !name_re.is_match(open_tag) {
                findings.push(finding(
                    "a11y.empty-button-name",
                    "error",
                    "Button appears to have no visible or accessible name.",
                    file,
                    line_at(text, m.start()),
                ));
            }
        }
    }

    /// JS: `/<(?:div|span)\b(?=[^>]*(?:onClick|@click|v-on:click)=)(?![^>]*(?:onKeyDown|onKeyUp|@keydown|@keyup|role=|tabIndex=))[^>]*>/gi`
    /// — a div/span with a click handler and no keyboard/role/tabIndex escape hatch.
    fn collect_pointer_only_findings(text: &str, file: &str, findings: &mut Vec<Value>) {
        static TAG_RE: OnceLock<Regex> = OnceLock::new();
        let tag_re = TAG_RE.get_or_init(|| Regex::new(r"(?i)<(?:div|span)\b[^>]*>").unwrap());
        static CLICK_RE: OnceLock<Regex> = OnceLock::new();
        let click_re = CLICK_RE.get_or_init(|| Regex::new(r"(?i)(?:onClick|@click|v-on:click)=").unwrap());
        static ESCAPE_RE: OnceLock<Regex> = OnceLock::new();
        let escape_re = ESCAPE_RE.get_or_init(|| {
            Regex::new(r"(?i)(?:onKeyDown|onKeyUp|@keydown|@keyup|role=|tabIndex=)").unwrap()
        });
        for m in tag_re.find_iter(text) {
            let tag = m.as_str();
            if click_re.is_match(tag) && !escape_re.is_match(tag) {
                findings.push(finding(
                    "a11y.pointer-only-handler",
                    "warning",
                    "Pointer handler has no matching keyboard/focus handler.",
                    file,
                    line_at(text, m.start()),
                ));
            }
        }
    }

    /// JS: `/<[^>]+\b(?:onMouseOver|onMouseEnter|@mouseover|@mouseenter)=(?![^>]*(?:onFocus|@focus))[^>]*>/gi`
    /// — a tag with a hover handler and no matching focus handler.
    fn collect_hover_without_focus_findings(text: &str, file: &str, findings: &mut Vec<Value>) {
        static TAG_RE: OnceLock<Regex> = OnceLock::new();
        let tag_re = TAG_RE.get_or_init(|| Regex::new(r"(?i)<[^>]+>").unwrap());
        static HOVER_RE: OnceLock<Regex> = OnceLock::new();
        let hover_re =
            HOVER_RE.get_or_init(|| Regex::new(r"(?i)(?:onMouseOver|onMouseEnter|@mouseover|@mouseenter)=").unwrap());
        static FOCUS_RE: OnceLock<Regex> = OnceLock::new();
        let focus_re = FOCUS_RE.get_or_init(|| Regex::new(r"(?i)(?:onFocus|@focus)").unwrap());
        for m in tag_re.find_iter(text) {
            let tag = m.as_str();
            if hover_re.is_match(tag) && !focus_re.is_match(tag) {
                findings.push(finding(
                    "a11y.hover-without-focus",
                    "warning",
                    "Hover behavior has no corresponding focus behavior.",
                    file,
                    line_at(text, m.start()),
                ));
            }
        }
    }

    fn outline_regexes() -> (&'static Regex, &'static Regex, &'static Regex) {
        static OUTLINE_REMOVAL: OnceLock<Regex> = OnceLock::new();
        static BLOCK: OnceLock<Regex> = OnceLock::new();
        static FOCUS_SELECTOR: OnceLock<Regex> = OnceLock::new();
        (
            OUTLINE_REMOVAL.get_or_init(|| Regex::new(r#"(?i)(?:\boutline\s*:\s*(?:none|0)\b|(?:^|[^\w-])outline-none\b)"#).unwrap()),
            BLOCK.get_or_init(|| Regex::new(r"(?s)([^{}]+)\{([^{}]*)\}").unwrap()),
            FOCUS_SELECTOR.get_or_init(|| Regex::new(r"(?i):(?:focus-visible|focus)\b").unwrap()),
        )
    }

    /// JS: `/(?:outline(?:-color|-width|-style)?\s*:\s*(?!\s*(?:none|0)\b)|box-shadow\s*:\s*(?!\s*none\b)|border(?:-color|-width)?\s*:[^;}]*(?:solid|dashed|dotted))/i`
    /// — some focus style is declared with a non-`none`/`0` value.
    fn has_visible_focus_style(block: &str) -> bool {
        static OUTLINE_VAL: OnceLock<Regex> = OnceLock::new();
        let outline_val = OUTLINE_VAL
            .get_or_init(|| Regex::new(r"(?i)outline(?:-color|-width|-style)?\s*:\s*([^;}]+)").unwrap());
        for cap in outline_val.captures_iter(block) {
            let value = cap[1].trim().to_lowercase();
            if !(value.starts_with("none") || value.starts_with('0')) {
                return true;
            }
        }
        static SHADOW_VAL: OnceLock<Regex> = OnceLock::new();
        let shadow_val = SHADOW_VAL.get_or_init(|| Regex::new(r"(?i)box-shadow\s*:\s*([^;}]+)").unwrap());
        for cap in shadow_val.captures_iter(block) {
            let value = cap[1].trim().to_lowercase();
            if !value.starts_with("none") {
                return true;
            }
        }
        static BORDER_STYLE: OnceLock<Regex> = OnceLock::new();
        let border_style = BORDER_STYLE.get_or_init(|| {
            Regex::new(r"(?i)border(?:-color|-width)?\s*:[^;}]*(?:solid|dashed|dotted)").unwrap()
        });
        border_style.is_match(block)
    }

    fn has_visible_focus_rule(text: &str) -> bool {
        let (_, block_re, focus_re) = outline_regexes();
        block_re
            .captures_iter(text)
            .any(|m| focus_re.is_match(&m[1]) && has_visible_focus_style(&m[2]))
    }

    /// JS matches a Tailwind `focus:`/`focus-visible:` utility whose suffix is
    /// NOT specifically `none`/`hidden`/`transparent`/`0` for the outline/
    /// border families (a bare `ring`/`shadow`/`underline` suffix always counts).
    fn tailwind_focus_replacement(window_text: &str) -> bool {
        static UTIL_RE: OnceLock<Regex> = OnceLock::new();
        let util_re = UTIL_RE.get_or_init(|| Regex::new(r"(?i)\bfocus(?:-visible)?[:-]([\w\[\].:-]+)").unwrap());
        static OUTLINE_NEUTRAL: OnceLock<Regex> = OnceLock::new();
        let outline_neutral =
            OUTLINE_NEUTRAL.get_or_init(|| Regex::new(r"(?i)^outline[-:]?(?:none|hidden|transparent)").unwrap());
        static BORDER_NEUTRAL: OnceLock<Regex> = OnceLock::new();
        let border_neutral =
            BORDER_NEUTRAL.get_or_init(|| Regex::new(r"(?i)^border[-:]?(?:0|none|transparent)").unwrap());
        for cap in util_re.captures_iter(window_text) {
            let util = &cap[1];
            let lower = util.to_lowercase();
            if lower.starts_with("ring") || lower.starts_with("shadow") || lower.starts_with("underline") {
                return true;
            }
            if lower.starts_with("outline") && !outline_neutral.is_match(util) {
                return true;
            }
            if lower.starts_with("border") && !border_neutral.is_match(util) {
                return true;
            }
        }
        false
    }

    fn has_local_focus_replacement(text: &str, index: usize) -> bool {
        let mut start = index.saturating_sub(400);
        while start > 0 && !text.is_char_boundary(start) {
            start -= 1;
        }
        let mut end = (index + 400).min(text.len());
        while end < text.len() && !text.is_char_boundary(end) {
            end += 1;
        }
        let window_text = &text[start..end.max(start)];
        if tailwind_focus_replacement(window_text) {
            return true;
        }
        let (_, block_re, focus_re) = outline_regexes();
        block_re
            .captures_iter(window_text)
            .any(|m| focus_re.is_match(&m[1]) && has_visible_focus_style(&m[2]))
    }

    fn collect_outline_findings(text: &str, file: &str, findings: &mut Vec<Value>) {
        let global_restore = has_visible_focus_rule(text);
        let (outline_removal, ..) = outline_regexes();
        for m in outline_removal.find_iter(text) {
            if !global_restore && !has_local_focus_replacement(text, m.start()) {
                findings.push(finding(
                    "a11y.focus-outline-removed",
                    "error",
                    "Focus outline is removed without a visible replacement proven here.",
                    file,
                    line_at(text, m.start()),
                ));
            }
        }
    }

    pub fn run_accessibility_suite(root: &std::path::Path, files: &[String]) -> Value {
        let mut findings = Vec::new();
        let mut scanned = Vec::new();
        let mut sorted: Vec<String> = files.to_vec();
        sorted.sort();
        sorted.dedup();
        for file in &sorted {
            let ext = std::path::Path::new(file)
                .extension()
                .and_then(|e| e.to_str())
                .map(|s| s.to_lowercase())
                .unwrap_or_default();
            if !SOURCE_EXTENSIONS.contains(&ext.as_str()) {
                continue;
            }
            let text = match std::fs::read_to_string(root.join(file)) {
                Ok(t) => t,
                Err(_) => continue,
            };
            if is_non_dom_media_source(file, &text) {
                continue;
            }
            scanned.push(file.clone());
            for rule in RULES {
                let re = Regex::new(rule.pattern).unwrap();
                for m in re.find_iter(&text) {
                    findings.push(finding(rule.id, rule.level, rule.message, file, line_at(&text, m.start())));
                }
            }
            collect_image_alt_findings(&text, file, &mut findings);
            collect_empty_button_findings(&text, file, &mut findings);
            collect_pointer_only_findings(&text, file, &mut findings);
            collect_hover_without_focus_findings(&text, file, &mut findings);
            collect_outline_findings(&text, file, &mut findings);
            if ["css", "scss", "sass", "less"].contains(&ext.as_str()) {
                static ANIM: OnceLock<Regex> = OnceLock::new();
                static PRM: OnceLock<Regex> = OnceLock::new();
                let anim_re = ANIM.get_or_init(|| Regex::new(r"(?i)(?:animation\s*:|@keyframes\b)").unwrap());
                let prm_re = PRM.get_or_init(|| Regex::new(r"(?i)prefers-reduced-motion").unwrap());
                if anim_re.is_match(&text) && !prm_re.is_match(&text) {
                    findings.push(finding(
                        "a11y.reduced-motion",
                        "warning",
                        "Animation exists without a visible prefers-reduced-motion alternative in this stylesheet.",
                        file,
                        1,
                    ));
                }
            }
        }
        // 2 data-driven rules + 4 custom-scan rules (image-alt, empty-button,
        // pointer-only, hover-without-focus) + outline + reduced-motion = 8,
        // matching the original JS `RULES.length + 2` (6 data rules + 2 extra).
        json!({
            "provider": "accessibility.internal-suite", "phase": "runtime",
            "applicable": !scanned.is_empty(), "required": !scanned.is_empty(),
            "status": if findings.is_empty() { "pass" } else { "fail" },
            "complete": true,
            "coverage": { "expectedFiles": files.len(), "scannedFiles": scanned.len(), "rules": RULES.len() + 6, "scanned": scanned },
            "findings": findings, "receipts": [], "coverageGaps": [], "degradation": [],
        })
    }

    /// `analyze({ root, projection })` — the plan-facing wrapper.
    pub fn analyze(root: &std::path::Path, files: &[String]) -> Value {
        let result = run_accessibility_suite(root, files);
        let expected = result["coverage"]["expectedFiles"].as_u64().unwrap_or(0);
        let zero = expected == 0;
        json!({
            "status": if zero { Value::String("unproven".to_string()) } else { result["status"].clone() },
            "complete": !zero && result["complete"].as_bool().unwrap_or(false),
            "denominator": {
                "kind": "accessibility-source-files",
                "expected": expected,
                "examined": result["coverage"]["scannedFiles"].clone(),
            },
            "findings": result["findings"].clone(),
            "coverageGaps": if zero { json!([{ "kind": "accessibility-denominator-zero" }]) } else { result["coverageGaps"].clone() },
        })
    }
}

// =====================================================================
// providers/generic-source-suite.mjs :: runGenericSourceAccounting
// =====================================================================
pub mod generic_source_suite {
    use super::*;

    const COVERED: &[&str] = &[
        "js", "jsx", "mjs", "cjs", "ts", "tsx", "cts", "mts", "astro", "vue", "py", "rs", "swift", "m", "mm",
        "c", "cc", "cpp", "cxx", "h", "hpp", "java", "kt", "kts", "scala", "cs", "fs", "vb", "php", "go", "rb", "dart",
        "ex", "exs", "erl", "hrl", "sh", "bash", "zsh", "ps1", "psm1", "bat", "vbs", "nsh", "nsi", "sql", "html", "css",
        "graphql", "gql", "svelte",
    ];

    fn extension(path: &str) -> Option<String> {
        std::path::Path::new(path)
            .file_name()
            .and_then(|n| n.to_str())
            .and_then(|name| name.rfind('.').map(|dot| name[dot + 1..].to_lowercase()))
    }

    pub fn run_generic_source_accounting(files: &[String], parsed_extensions: &[String]) -> Value {
        let parsed: std::collections::HashSet<String> =
            parsed_extensions.iter().map(|v| v.to_lowercase()).collect();
        let mut unknown: std::collections::BTreeMap<String, Vec<String>> = std::collections::BTreeMap::new();
        for file in files {
            let ext = match extension(file) {
                Some(e) => e,
                None => continue,
            };
            if !parsed.contains(&ext) || COVERED.contains(&ext.as_str()) {
                continue;
            }
            unknown.entry(ext).or_default().push(file.clone());
        }
        let coverage_gaps: Vec<Value> = unknown
            .into_iter()
            .map(|(ext, paths)| {
                json!({
                    "kind": "missing-language-provider", "extension": ext,
                    "pathCount": paths.len(), "samplePaths": paths.iter().take(20).collect::<Vec<_>>(),
                })
            })
            .collect();
        let mut parsed_sorted: Vec<&String> = parsed.iter().collect();
        parsed_sorted.sort();
        let mut covered_sorted: Vec<&str> = COVERED.to_vec();
        covered_sorted.sort();
        json!({
            "provider": "generic.source-accounting", "phase": "runtime", "applicable": true, "required": true,
            "status": if coverage_gaps.is_empty() { "pass" } else { "unproven" },
            "complete": coverage_gaps.is_empty(),
            "coverage": { "parsedExtensions": parsed_sorted, "explicitlyCoveredExtensions": covered_sorted, "fileCount": files.len() },
            "findings": [], "receipts": [], "coverageGaps": coverage_gaps, "degradation": [],
        })
    }
}

// =====================================================================
// providers/data-suite.mjs :: runDataSuite
// =====================================================================
pub mod data_suite {
    use super::*;

    const DATA_EXTENSIONS: &[&str] = &["sql", "ts", "tsx", "js", "mjs", "cjs", "py", "php", "rb", "go", "rs", "java", "kt", "cs"];

    fn severity_hint(level: &str) -> &'static str {
        match level {
            "error" => "high",
            "warning" => "medium",
            _ => "low",
        }
    }

    fn candidate(rule_id: &str, level: &str, message: &str, file: &str, line: usize) -> Value {
        json!({
            "id": digest_id(&[rule_id, file, &line.to_string()]),
            "ruleId": rule_id, "severityHint": severity_hint(level), "claim": message, "file": file, "line": line,
        })
    }

    struct Rule {
        id: &'static str,
        level: &'static str,
        message: &'static str,
        patterns: &'static [&'static str],
    }

    // Lookahead-free rules stay data-driven. Three JS rules use `(?!...)`
    // (unsupported by the `regex` crate) and are reimplemented below as
    // explicit scans with identical semantics.
    const RULES: &[Rule] = &[
        Rule { id: "data.sql-interpolation", level: "error", message: "SQL text appears to interpolate or concatenate variable input.", patterns: &[r#"(?is)(?:SELECT|INSERT|UPDATE|DELETE|ALTER|DROP)[^\n;]*(?:\$\{|\+\s*(?:req|request|input|user|params|query)|format\s*\(|f['"])"#] },
        Rule { id: "data.destructive-migration", level: "warning", message: "Migration contains a destructive DROP operation; require backup, rollback, and compatibility evidence.", patterns: &[r#"(?i)\bDROP\s+(?:TABLE|COLUMN|DATABASE|INDEX)\b"#] },
        Rule { id: "data.sqlite-foreign-keys-off", level: "error", message: "SQLite foreign-key enforcement is disabled.", patterns: &[r#"(?i)PRAGMA\s+foreign_keys\s*=\s*(?:OFF|0)"#] },
        Rule { id: "data.redis-keys", level: "warning", message: "Redis KEYS can block the server; use bounded SCAN for production paths.", patterns: &[r#"\.(?:keys|KEYS)\s*\(\s*['"][^'"]*['"]\s*\)"#] },
        Rule { id: "data.mongo-javascript", level: "error", message: "MongoDB server-side JavaScript evaluation is used.", patterns: &[r#"(?i)\$(?:where|function)\b|mapReduce\s*\("#] },
    ];

    /// JS: `/\bADD\s+(?:COLUMN\s+)?[A-Za-z0-9_"\`]+[^;\n]*\bNOT\s+NULL\b(?![^;\n]*\bDEFAULT\b)/i`
    /// — `NOT NULL` not followed by `DEFAULT` before the next `;`/newline.
    fn collect_not_null_migration(text: &str, file: &str, candidates: &mut Vec<Value>) {
        static RE: std::sync::OnceLock<Regex> = std::sync::OnceLock::new();
        let re = RE.get_or_init(|| {
            Regex::new(r#"(?i)\bADD\s+(?:COLUMN\s+)?[A-Za-z0-9_"`]+[^;\n]*\bNOT\s+NULL\b"#).unwrap()
        });
        for m in re.find_iter(text) {
            let rest_end = text[m.end()..].find(|c| c == ';' || c == '\n').map(|i| m.end() + i).unwrap_or(text.len());
            let rest = &text[m.end()..rest_end];
            if !rest.to_lowercase().contains("default") {
                candidates.push(candidate("data.not-null-migration", "warning", "Migration adds NOT NULL without a visible default/backfill sequence.", file, line_at(text, m.start())));
            }
        }
    }

    /// JS: `/sqlite(?:3)?[\s\S]{0,200}(?:connect|open)\s*\((?![\s\S]{0,300}(?:busy_timeout|timeout))/is`
    /// — an sqlite connect/open call not followed within 300 chars by a busy-timeout mention.
    fn collect_sqlite_no_busy_timeout(text: &str, file: &str, candidates: &mut Vec<Value>) {
        static RE: std::sync::OnceLock<Regex> = std::sync::OnceLock::new();
        let re = RE.get_or_init(|| {
            Regex::new(r"(?is)sqlite(?:3)?[\s\S]{0,200}(?:connect|open)\s*\(").unwrap()
        });
        for m in re.find_iter(text) {
            let end = (m.end() + 300).min(text.len());
            let window = &text[m.end()..end];
            if !Regex::new(r"(?i)busy_timeout|timeout").unwrap().is_match(window) {
                candidates.push(candidate("data.sqlite-no-busy-timeout", "note", "SQLite connection is configured without a visible busy timeout; assess lock contention.", file, line_at(text, m.start())));
            }
        }
    }

    /// JS: `/\.(?:set|hset)\s*\([^\n;]+\)(?![^\n;]*(?:expire|ttl|ex\s*:|px\s*:))/i`
    /// — a redis set/hset call with no expiration keyword before the next `;`/newline.
    fn collect_redis_unbounded_value(text: &str, file: &str, candidates: &mut Vec<Value>) {
        static RE: std::sync::OnceLock<Regex> = std::sync::OnceLock::new();
        let re = RE.get_or_init(|| Regex::new(r"(?i)\.(?:set|hset)\s*\([^\n;]+\)").unwrap());
        for m in re.find_iter(text) {
            let rest_end = text[m.end()..].find(|c| c == ';' || c == '\n').map(|i| m.end() + i).unwrap_or(text.len());
            let rest = &text[m.end()..rest_end];
            if !Regex::new(r"(?i)expire|ttl|ex\s*:|px\s*:").unwrap().is_match(rest) {
                candidates.push(candidate("data.redis-unbounded-value", "note", "Redis write has no visible expiration; verify retention and invalidation.", file, line_at(text, m.start())));
            }
        }
    }

    /// JS: `/(?:insert|update|delete|save)\s*\([\s\S]{0,500}(?:insert|update|delete|save)\s*\((?![\s\S]{0,700}(?:transaction|beginTransaction|BEGIN\b))/is`
    /// — two adjacent write calls within 500 chars, with no transaction keyword within 700 chars after the second.
    fn collect_transaction_missing(text: &str, file: &str, candidates: &mut Vec<Value>) {
        static FIRST: std::sync::OnceLock<Regex> = std::sync::OnceLock::new();
        let first_re = FIRST.get_or_init(|| Regex::new(r"(?i)(?:insert|update|delete|save)\s*\(").unwrap());
        static TXN: std::sync::OnceLock<Regex> = std::sync::OnceLock::new();
        let txn_re = TXN.get_or_init(|| Regex::new(r"(?i)transaction|beginTransaction|BEGIN\b").unwrap());
        for m in first_re.find_iter(text) {
            let window_end = (m.end() + 500).min(text.len());
            let window = &text[m.end()..window_end];
            let second = match first_re.find(window) {
                Some(s) => s,
                None => continue,
            };
            let second_abs_end = m.end() + second.end();
            let tail_end = (second_abs_end + 700).min(text.len());
            let tail = &text[second_abs_end..tail_end];
            if !txn_re.is_match(tail) {
                candidates.push(candidate("data.transaction-missing", "note", "Multiple adjacent write operations have no visible transaction boundary.", file, line_at(text, m.start())));
                break; // one candidate per file is sufficient to mirror the JS regex's single global scan cursor behavior closely enough
            }
        }
    }

    pub fn run_data_suite(root: &std::path::Path, files: &[String]) -> Value {
        let mut candidates = Vec::new();
        for file in files {
            let ext = std::path::Path::new(file)
                .extension()
                .and_then(|e| e.to_str())
                .map(|s| s.to_lowercase())
                .unwrap_or_default();
            if !DATA_EXTENSIONS.contains(&ext.as_str()) {
                continue;
            }
            let text = std::fs::read_to_string(root.join(file)).unwrap_or_default();
            for rule in RULES {
                for pattern in rule.patterns {
                    let re = Regex::new(pattern).unwrap();
                    for m in re.find_iter(&text) {
                        candidates.push(candidate(rule.id, rule.level, rule.message, file, line_at(&text, m.start())));
                    }
                }
            }
            collect_not_null_migration(&text, file, &mut candidates);
            collect_sqlite_no_busy_timeout(&text, file, &mut candidates);
            collect_redis_unbounded_value(&text, file, &mut candidates);
            collect_transaction_missing(&text, file, &mut candidates);
        }
        json!({
            "schemaVersion": 1, "provider": "data.internal-suite", "providerVersion": "1.0.0",
            "ownerProvider": "data.internal-suite", "phase": "runtime", "role": "candidate-generator",
            "status": if candidates.is_empty() { "pass" } else { "candidates" },
            "complete": true, "applicable": true, "required": true,
            "coverage": { "pathCount": files.len(), "rules": RULES.len() + 4 },
            "candidates": candidates, "findings": [], "receipts": [], "coverageGaps": [], "degradation": [],
        })
    }
}

// =====================================================================
// providers/infrastructure-suite.mjs :: runInfrastructureSuite
// =====================================================================
pub mod infrastructure_suite {
    use super::*;

    fn severity_hint(level: &str) -> &'static str {
        match level {
            "critical" | "error" => "high",
            "warning" => "medium",
            _ => "low",
        }
    }

    fn candidate(rule_id: &str, level: &str, message: &str, file: &str, line: usize) -> Value {
        json!({
            "id": digest_id(&[rule_id, file, &line.to_string()]),
            "ruleId": rule_id, "severityHint": severity_hint(level), "claim": message, "file": file, "line": line,
        })
    }

    type Applies = fn(&str, &str) -> bool;

    struct Rule {
        id: &'static str,
        level: &'static str,
        message: &'static str,
        pattern: &'static str,
        applies: Applies,
    }

    fn is_dockerfile(file: &str, _text: &str) -> bool {
        Regex::new(r"(?i)^Dockerfile").unwrap().is_match(
            std::path::Path::new(file).file_name().and_then(|n| n.to_str()).unwrap_or(""),
        )
    }
    fn is_dockerfile_no_user(file: &str, text: &str) -> bool {
        is_dockerfile(file, text) && !Regex::new(r"(?im)^\s*USER\s+").unwrap().is_match(text)
    }
    fn is_yaml(file: &str, _text: &str) -> bool {
        Regex::new(r"(?i)\.ya?ml$").unwrap().is_match(file)
    }
    fn is_workflow(file: &str, _text: &str) -> bool {
        file.starts_with(".github/workflows/")
    }
    fn is_workflow_pr_target(file: &str, text: &str) -> bool {
        is_workflow(file, text) && text.contains("pull_request_target")
    }
    fn is_tf(file: &str, _text: &str) -> bool {
        file.ends_with(".tf")
    }
    fn is_release_script(file: &str, _text: &str) -> bool {
        Regex::new(r"(?i)\.(?:sh|ps1|mjs|cjs|js|py|rb|yml|yaml|toml|json)$").unwrap().is_match(file)
    }
    fn is_release_script_narrow(file: &str, _text: &str) -> bool {
        Regex::new(r"(?i)\.(?:sh|ps1|mjs|cjs|js|py|rb)$").unwrap().is_match(file)
    }
    fn is_tauri_conf(file: &str, _text: &str) -> bool {
        Regex::new(r"(?:tauri\.conf\.(?:json|json5)|Tauri\.toml)$").unwrap().is_match(file)
    }
    fn always(_file: &str, _text: &str) -> bool {
        true
    }

    const RULES: &[Rule] = &[
        Rule { id: "container.latest-tag", level: "warning", message: "Container base image is unpinned or uses latest.", pattern: r"(?im)^\s*FROM\s+[^\s:@]+(?::latest)?\s*$", applies: is_dockerfile },
        Rule { id: "container.remote-add", level: "warning", message: "Docker ADD fetches a mutable remote resource without explicit integrity verification.", pattern: r"(?im)^\s*ADD\s+https?://", applies: is_dockerfile },
        Rule { id: "container.curl-pipe-shell", level: "error", message: "Container build pipes remote content directly to a shell.", pattern: r"(?i)(?:curl|wget)[^\n|]*\|\s*(?:sh|bash|zsh)", applies: is_dockerfile },
        Rule { id: "container-root-user", level: "warning", message: "Container has no explicit non-root USER.", pattern: r"(?im)^\s*FROM\s+", applies: is_dockerfile_no_user },
        Rule { id: "k8s-privileged", level: "error", message: "Kubernetes workload enables privileged mode.", pattern: r"(?i)privileged:\s*true", applies: is_yaml },
        Rule { id: "k8s-host-namespace", level: "error", message: "Kubernetes workload joins a host namespace.", pattern: r"(?i)(?:hostNetwork|hostPID|hostIPC):\s*true", applies: is_yaml },
        Rule { id: "k8s-unpinned-image", level: "warning", message: "Kubernetes image is not digest-pinned.", pattern: r"(?im)image:\s*[^\s@]+(?::latest)?\s*$", applies: is_yaml },
        Rule { id: "k8s-secret-literal", level: "error", message: "Secret-like value appears inline in deployment YAML.", pattern: r#"(?i)(?:password|secret|token|api[_-]?key):\s*['"]?[^\s${][^\n]{5,}"#, applies: is_yaml },
        Rule { id: "actions-write-all", level: "error", message: "GitHub Actions grants write-all permissions.", pattern: r"(?i)permissions:\s*write-all", applies: is_workflow },
        Rule { id: "actions-unpinned", level: "warning", message: "GitHub Action is not pinned to an immutable commit.", pattern: r"(?im)uses:\s*[^\s@]+@(?:main|master|latest|v?\d+(?:\.\d+)?)\s*$", applies: is_workflow },
        Rule { id: "actions-expression-in-shell", level: "error", message: "Attacker-controlled event data is interpolated directly into a shell command.", pattern: r"(?i)run:\s*[^\n]*\$\{\{\s*github\.event\.", applies: is_workflow },
        Rule { id: "actions-pr-target-checkout", level: "critical", message: "Privileged pull_request_target workflow checks out attacker-controlled head code.", pattern: r"(?i)ref:\s*\$\{\{\s*github\.event\.pull_request\.head\.(?:sha|ref)\s*\}\}", applies: is_workflow_pr_target },
        Rule { id: "terraform-open-ingress", level: "error", message: "Terraform security rule allows global IPv4 access.", pattern: r#"(?i)cidr_blocks\s*=\s*\[[^\]]*['"]0\.0\.0\.0/0['"][^\]]*\]"#, applies: is_tf },
        Rule { id: "terraform-public-storage", level: "error", message: "Infrastructure configuration enables public storage access.", pattern: r"(?i)(?:acl\s*=\s*['\x22]public|public_access\s*=\s*true|block_public_acls\s*=\s*false)", applies: is_tf },
        Rule { id: "release-mutable-download", level: "warning", message: "Release tooling downloads from a mutable latest URL.", pattern: r#"(?i)https?://[^\s'"]+/(?:latest|releases/latest|download/latest)[^\s'"]*"#, applies: is_release_script },
        Rule { id: "tauri-updater-insecure", level: "error", message: "Tauri updater permits insecure transport.", pattern: r"(?i)dangerousInsecureTransportProtocol\s*[:=]\s*true", applies: is_tauri_conf },
    ];
    #[allow(dead_code)]
    fn _unused() -> Applies { always }

    /// JS: `/(?:curl|wget|Invoke-WebRequest|fetch\s*\()[\s\S]{0,300}https?:\/\/(?![\s\S]{0,500}(?:sha256|checksum|digest|integrity))/is`
    /// (unsupported lookahead) — a download call whose URL has no integrity
    /// keyword within 500 chars after it.
    fn collect_release_download_no_hash(file: &str, text: &str, candidates: &mut Vec<Value>) {
        if !is_release_script_narrow(file, text) {
            return;
        }
        static PREFIX: std::sync::OnceLock<Regex> = std::sync::OnceLock::new();
        let prefix_re = PREFIX.get_or_init(|| {
            Regex::new(r"(?is)(?:curl|wget|Invoke-WebRequest|fetch\s*\()[\s\S]{0,300}https?://").unwrap()
        });
        static INTEGRITY: std::sync::OnceLock<Regex> = std::sync::OnceLock::new();
        let integrity_re =
            INTEGRITY.get_or_init(|| Regex::new(r"(?i)sha256|checksum|digest|integrity").unwrap());
        for m in prefix_re.find_iter(text) {
            let end = (m.end() + 500).min(text.len());
            if !integrity_re.is_match(&text[m.end()..end]) {
                candidates.push(candidate(
                    "release-download-no-hash", "warning",
                    "Downloaded release artifact has no nearby integrity verification.",
                    file, line_at(text, m.start()),
                ));
            }
        }
    }

    pub fn run_infrastructure_suite(root: &std::path::Path, files: &[String]) -> Value {
        let mut candidates = Vec::new();
        for file in files {
            let text = std::fs::read_to_string(root.join(file)).unwrap_or_default();
            for rule in RULES {
                if !(rule.applies)(file, &text) {
                    continue;
                }
                let re = Regex::new(rule.pattern).unwrap();
                for m in re.find_iter(&text) {
                    candidates.push(candidate(rule.id, rule.level, rule.message, file, line_at(&text, m.start())));
                }
            }
            collect_release_download_no_hash(file, &text, &mut candidates);
        }
        json!({
            "schemaVersion": 1, "provider": "infrastructure.internal-suite", "providerVersion": "1.0.0",
            "ownerProvider": "infrastructure.internal-suite", "phase": "runtime", "role": "candidate-generator",
            "status": if candidates.is_empty() { "pass" } else { "candidates" },
            "complete": true, "applicable": true, "required": true,
            "coverage": { "pathCount": files.len(), "rules": RULES.len() + 1 },
            "candidates": candidates, "findings": [], "receipts": [], "coverageGaps": [], "degradation": [],
        })
    }
}

// =====================================================================
// providers/framework-suite.mjs :: runFrameworkSuite
// =====================================================================
pub mod framework_suite {
    use super::*;

    fn severity_hint(level: &str) -> &'static str {
        match level {
            "critical" | "error" | "high" => "high",
            "warning" => "medium",
            _ => "low",
        }
    }

    fn candidate(rule_id: &str, level: &str, message: &str, file: &str, line: usize) -> Value {
        json!({
            "id": digest_id(&[rule_id, file, &line.to_string()]),
            "ruleId": rule_id, "severityHint": severity_hint(level), "claim": message, "file": file, "line": line,
        })
    }

    struct Rule {
        id: &'static str,
        level: &'static str,
        pattern: &'static str,
        message: &'static str,
    }

    fn specs() -> Vec<(&'static str, Vec<Rule>)> {
        vec![
            ("framework.next", vec![
                Rule { id: "next-public-secret", level: "error", pattern: r"NEXT_PUBLIC_[A-Z0-9_]*(?:SECRET|TOKEN|KEY|PASSWORD)", message: "Secret-like configuration uses the browser-exposed NEXT_PUBLIC_ prefix." },
                Rule { id: "next-unsafe-html", level: "warning", pattern: r"dangerouslySetInnerHTML\s*=", message: "Raw HTML rendering requires a proven sanitization boundary." },
                Rule { id: "next-unvalidated-redirect", level: "warning", pattern: r"(?:redirect|NextResponse\.redirect)\s*\([^\n]*(?:searchParams|query|request\.url)", message: "Request-controlled data may reach a redirect target." },
            ]),
            ("framework.vue", vec![
                Rule { id: "vue-v-html", level: "warning", pattern: r"\bv-html\s*=", message: "v-html renders raw HTML and requires sanitization." },
            ]),
            ("framework.nuxt", vec![
                Rule { id: "nuxt-public-secret", level: "error", pattern: r"(?is)public\s*:\s*\{[\s\S]{0,400}(?:secret|token|password|privateKey)\s*:", message: "Secret-like runtime configuration is placed in Nuxt public config." },
                Rule { id: "nuxt-ssr-disabled", level: "note", pattern: r"\bssr\s*:\s*false", message: "SSR is disabled; confirm this matches product and security assumptions." },
            ]),
            ("framework.angular", vec![
                Rule { id: "angular-trust-bypass", level: "error", pattern: r"bypassSecurityTrust(?:Html|Script|Style|Url|ResourceUrl)\s*\(", message: "Angular sanitization is explicitly bypassed." },
                Rule { id: "angular-inner-html", level: "warning", pattern: r"\[innerHTML\]\s*=", message: "Dynamic HTML binding requires trust and sanitization review." },
            ]),
            ("framework.svelte", vec![
                Rule { id: "svelte-raw-html", level: "warning", pattern: r"\{@html\s+", message: "Svelte raw HTML rendering requires sanitization." },
            ]),
            ("framework.sveltekit", vec![
                Rule { id: "sveltekit-public-env-secret", level: "error", pattern: r"(?is)\$env/(?:static|dynamic)/public[\s\S]{0,160}(?:SECRET|TOKEN|PASSWORD|PRIVATE_KEY)", message: "Secret-like value is imported through SvelteKit public environment APIs." },
                Rule { id: "sveltekit-unvalidated-redirect", level: "warning", pattern: r"redirect\s*\([^,]+,\s*(?:url|event\.url|searchParams)", message: "Request-controlled data may reach a redirect target." },
            ]),
            ("framework.express", vec![
                Rule { id: "express-trust-proxy-all", level: "warning", pattern: r#"set\s*\(\s*['"]trust proxy['"]\s*,\s*true\s*\)"#, message: "Express trusts every proxy; verify deployment boundaries." },
                Rule { id: "express-open-cors", level: "warning", pattern: r#"(?is)cors\s*\(\s*(?:\{|\))[\s\S]{0,200}(?:origin\s*:\s*['"]\*['"]|$)"#, message: "Express CORS appears broadly permissive." },
                Rule { id: "express-error-leak", level: "warning", pattern: r"res\.(?:send|json)\s*\([^\n]*(?:err\.stack|error\.stack)", message: "Server error stack may be returned to clients." },
            ]),
            ("framework.fastify", vec![
                Rule { id: "fastify-open-cors", level: "warning", pattern: r#"(?is)register\s*\([^\n]*cors[\s\S]{0,250}origin\s*:\s*(?:true|['"]\*['"])"#, message: "Fastify CORS accepts arbitrary origins." },
                Rule { id: "fastify-schema-missing", level: "note", pattern: r#"\.(?:get|post|put|patch|delete)\s*\(\s*['"][^'"]+['"]\s*,\s*(?:async\s*)?\("#, message: "Route declaration has no visible validation schema." },
            ]),
            ("framework.nest", vec![
                Rule { id: "nest-open-cors", level: "warning", pattern: r#"(?is)enableCors\s*\(\s*(?:\{|\))[\s\S]{0,200}(?:origin\s*:\s*(?:true|['"]\*['"])|$)"#, message: "Nest CORS appears broadly permissive." },
                // "nest-validation-missing-transform" uses a JS negative lookahead
                // (unsupported by the `regex` crate); see collect_nest_validation_missing_transform below.
            ]),
            ("framework.electron", vec![
                Rule { id: "electron-node-integration", level: "error", pattern: r"nodeIntegration\s*:\s*true", message: "Electron renderer has Node integration enabled." },
                Rule { id: "electron-context-isolation", level: "error", pattern: r"contextIsolation\s*:\s*false", message: "Electron context isolation is disabled." },
                Rule { id: "electron-web-security", level: "error", pattern: r"webSecurity\s*:\s*false", message: "Electron web security is disabled." },
                Rule { id: "electron-shell-open-external", level: "warning", pattern: r"shell\.openExternal\s*\([^\n]*(?:url|href|input|request)", message: "Potentially untrusted URL reaches shell.openExternal." },
            ]),
            ("framework.django", vec![
                Rule { id: "django-debug", level: "error", pattern: r"(?m)^\s*DEBUG\s*=\s*True\b", message: "Django DEBUG is enabled in tracked configuration." },
                Rule { id: "django-hosts-all", level: "warning", pattern: r#"(?m)^\s*ALLOWED_HOSTS\s*=\s*\[[^\]]*['"]\*['"]"#, message: "Django accepts every Host header." },
                Rule { id: "django-csrf-exempt", level: "warning", pattern: r"@csrf_exempt\b", message: "Django CSRF protection is bypassed for this view." },
                Rule { id: "django-mark-safe", level: "warning", pattern: r"\bmark_safe\s*\(", message: "Django output is explicitly marked safe." },
            ]),
            ("framework.fastapi", vec![
                Rule { id: "fastapi-open-cors", level: "warning", pattern: r#"allow_origins\s*=\s*\[[^\]]*['"]\*['"]"#, message: "FastAPI CORS accepts every origin." },
                Rule { id: "fastapi-no-response-model", level: "note", pattern: r"@(?:app|router)\.(?:get|post|put|patch|delete)\s*\([^\n]*\)\s*\n(?:async\s+)?def\s+", message: "FastAPI route has no visible response_model contract." },
            ]),
            ("framework.flask", vec![
                Rule { id: "flask-debug", level: "error", pattern: r"app\.run\s*\([^)]*debug\s*=\s*True", message: "Flask debug mode is enabled." },
                Rule { id: "flask-secret-fallback", level: "high", pattern: r#"SECRET_KEY['"]?\s*\]\s*=\s*(?:os\.environ\.get\([^)]*\)\s+or\s+)?['"][^'"]+['"]"#, message: "Flask secret key has a tracked fallback value." },
                Rule { id: "flask-render-template-string", level: "warning", pattern: r"render_template_string\s*\([^\n]*(?:request|input|user)", message: "Request-controlled data may reach a Jinja template source." },
            ]),
            ("framework.spring", vec![
                Rule { id: "spring-csrf-disabled", level: "warning", pattern: r"(?s)csrf\s*\([^)]*\)\s*\.disable\s*\(|csrf\s*\{[^}]*disable\s*\(", message: "Spring Security CSRF protection is disabled; prove the application is stateless." },
                Rule { id: "spring-sensitive-permit-all", level: "error", pattern: r"(?is)requestMatchers\s*\([^)]*(?:admin|internal|actuator)[^)]*\)\s*\.permitAll\s*\(", message: "Sensitive-looking Spring route is configured permitAll." },
                Rule { id: "spring-spel-input", level: "error", pattern: r"SpelExpressionParser[\s\S]{0,500}parseExpression\s*\(\s*(?:request|input|value|expression)", message: "Potentially variable input reaches a SpEL parser." },
            ]),
            ("framework.ktor", vec![
                Rule { id: "ktor-any-host", level: "warning", pattern: r"anyHost\s*\(\s*\)", message: "Ktor CORS permits any host." },
                Rule { id: "ktor-forwarded-headers", level: "note", pattern: r"XForwardedHeaders", message: "Forwarded headers are trusted; verify proxy boundaries." },
            ]),
            ("framework.rails", vec![
                Rule { id: "rails-forgery-skip", level: "warning", pattern: r"skip_(?:before_action|before_filter)\s+:verify_authenticity_token|skip_forgery_protection", message: "Rails request forgery protection is bypassed." },
                Rule { id: "rails-html-safe", level: "warning", pattern: r"\.html_safe\b|raw\s*\(", message: "Rails output is explicitly marked HTML-safe." },
                Rule { id: "rails-constantize-input", level: "error", pattern: r"(?:params|request)[^\n]*\.constantize\b", message: "Request-controlled value may select a Ruby constant." },
            ]),
            ("framework.phoenix", vec![
                Rule { id: "phoenix-check-origin-disabled", level: "warning", pattern: r"check_origin:\s*false", message: "Phoenix origin checks are disabled." },
                Rule { id: "phoenix-raw-html", level: "warning", pattern: r"raw\s*\(", message: "Phoenix template emits raw HTML." },
            ]),
            ("framework.flutter", vec![
                Rule { id: "flutter-bad-cert-callback", level: "error", pattern: r"badCertificateCallback\s*=\s*[^;]*=>\s*true", message: "Flutter/Dart accepts every TLS certificate." },
                Rule { id: "flutter-webview-js-unrestricted", level: "warning", pattern: r"JavaScriptMode\.unrestricted", message: "Flutter WebView enables unrestricted JavaScript." },
            ]),
            ("framework.go-web", vec![
                // "go-http-no-timeouts" uses a JS negative lookahead (unsupported by
                // the `regex` crate); see collect_go_http_no_timeouts below.
                Rule { id: "go-template-html", level: "warning", pattern: r"template\.HTML\s*\([^\n]*(?:request|input|user)", message: "Potentially untrusted content is cast to trusted template HTML." },
            ]),
            ("framework.rust-web", vec![
                Rule { id: "rust-web-unbounded-body", level: "note", pattern: r"(?s)(?:axum|actix_web|warp|rocket)[\s\S]{0,800}(?:Bytes|String|Json)<|web::Payload", message: "Request body handling should have an explicit size bound." },
                Rule { id: "rust-web-command-input", level: "error", pattern: r"(?s)Command::new\s*\([^)]*\)[\s\S]{0,200}arg\s*\([^\n]*(?:query|path|body|input)", message: "Request-derived data may reach a process argument." },
            ]),
        ]
    }

    /// JS: `/useGlobalPipes\s*\(\s*new\s+ValidationPipe\s*\(\s*\{(?![\s\S]{0,200}transform\s*:\s*true)/is`
    fn collect_nest_validation_missing_transform(text: &str) -> Option<usize> {
        static PREFIX: std::sync::OnceLock<Regex> = std::sync::OnceLock::new();
        let prefix_re = PREFIX
            .get_or_init(|| Regex::new(r"(?is)useGlobalPipes\s*\(\s*new\s+ValidationPipe\s*\(\s*\{").unwrap());
        for m in prefix_re.find_iter(text) {
            let end = (m.end() + 200).min(text.len());
            if !Regex::new(r"(?i)transform\s*:\s*true").unwrap().is_match(&text[m.end()..end]) {
                return Some(m.start());
            }
        }
        None
    }

    /// JS: `/http\.Server\s*\{(?![\s\S]{0,500}(?:ReadHeaderTimeout|ReadTimeout|WriteTimeout|IdleTimeout))/s`
    fn collect_go_http_no_timeouts(text: &str) -> Option<usize> {
        static PREFIX: std::sync::OnceLock<Regex> = std::sync::OnceLock::new();
        let prefix_re = PREFIX.get_or_init(|| Regex::new(r"http\.Server\s*\{").unwrap());
        for m in prefix_re.find_iter(text) {
            let end = (m.end() + 500).min(text.len());
            if !Regex::new(r"ReadHeaderTimeout|ReadTimeout|WriteTimeout|IdleTimeout").unwrap().is_match(&text[m.end()..end]) {
                return Some(m.start());
            }
        }
        None
    }

    fn family_files<'a>(plan: &'a Value, id: &str) -> Vec<String> {
        plan.get("coverageFamilies")
            .and_then(Value::as_array)
            .and_then(|families| families.iter().find(|f| f.get("id").and_then(Value::as_str) == Some(id)))
            .and_then(|f| f.get("denominator"))
            .and_then(|d| d.get("paths"))
            .and_then(Value::as_array)
            .map(|paths| paths.iter().filter_map(|p| p.as_str().map(String::from)).collect())
            .unwrap_or_default()
    }

    pub fn run_framework_suite(root: &std::path::Path, plan: &Value) -> Vec<Value> {
        let mut results = Vec::new();
        for (family, rules) in specs() {
            let files = family_files(plan, family);
            if files.is_empty() {
                continue;
            }
            let mut candidates = Vec::new();
            let mut unreadable = Vec::new();
            for file in &files {
                let text = match std::fs::read_to_string(root.join(file)) {
                    Ok(t) => t,
                    Err(_) if !root.join(file).exists() => {
                        unreadable.push(file.clone());
                        continue;
                    }
                    Err(_) => String::new(),
                };
                for rule in &rules {
                    // rule.pattern already declares inline (?s)/(?i)/(?m) matching the JS
                    // flags used at each call site.
                    let re = Regex::new(rule.pattern).unwrap();
                    if let Some(m) = re.find(&text) {
                        candidates.push(candidate(rule.id, rule.level, rule.message, file, line_at(&text, m.start())));
                    }
                }
                if family == "framework.nest" {
                    if let Some(idx) = collect_nest_validation_missing_transform(&text) {
                        candidates.push(candidate("nest-validation-missing-transform", "note", "Nest ValidationPipe does not visibly enable transformation.", file, line_at(&text, idx)));
                    }
                }
                if family == "framework.go-web" {
                    if let Some(idx) = collect_go_http_no_timeouts(&text) {
                        candidates.push(candidate("go-http-no-timeouts", "warning", "Go HTTP server has no visible timeout configuration.", file, line_at(&text, idx)));
                    }
                }
            }
            let coverage_gaps: Vec<Value> = if !unreadable.is_empty() {
                vec![json!({
                    "kind": "denominator-file-unreadable",
                    "detail": format!("{} of {} frozen paths could not be read", unreadable.len(), files.len()),
                    "paths": unreadable,
                })]
            } else {
                vec![]
            };
            results.push(json!({
                "schemaVersion": 1, "provider": format!("framework.{family}"), "providerVersion": "1.0.0",
                "ownerProvider": "framework.major-suite", "family": family, "applicable": true, "required": true,
                "role": "candidate-generator",
                "status": if !candidates.is_empty() { "candidates" } else if !coverage_gaps.is_empty() { "unproven" } else { "pass" },
                "complete": coverage_gaps.is_empty(),
                "coverage": { "pathCount": files.len(), "readablePathCount": files.len() - unreadable.len(), "paths": files, "rules": rules.len() },
                "receipts": [], "candidates": candidates, "findings": [], "coverageGaps": coverage_gaps.clone(), "degradation": coverage_gaps,
            }));
        }
        results
    }

    pub fn analyze(root: &std::path::Path, plan: &Value) -> Value {
        let results = run_framework_suite(root, plan);
        let mut gaps: Vec<Value> = results
            .iter()
            .flat_map(|r| r.get("coverageGaps").and_then(Value::as_array).cloned().unwrap_or_default())
            .collect();
        if results.is_empty() {
            gaps.push(json!({ "kind": "framework-denominator-zero" }));
        }
        let candidates_status = results.iter().any(|r| r.get("status").and_then(Value::as_str) == Some("candidates"));
        let examined = results.iter().filter(|r| r.get("complete").and_then(Value::as_bool) == Some(true)).count();
        let candidates: Vec<Value> = results
            .iter()
            .flat_map(|r| r.get("candidates").and_then(Value::as_array).cloned().unwrap_or_default())
            .collect();
        json!({
            "status": if !gaps.is_empty() { "unproven" } else if candidates_status { "candidates" } else { "pass" },
            "complete": gaps.is_empty(),
            "denominator": { "kind": "framework-provider-results", "expected": results.len(), "examined": examined },
            "findings": [], "candidates": candidates, "coverageGaps": gaps,
        })
    }
}

// =====================================================================
// providers/security-suite.mjs
// =====================================================================
pub mod security_suite {
    use super::*;

    pub const PACK_PROVIDERS: &[(&str, &str)] = &[
        ("credentials", "security.credentials"),
        ("insecure-defaults", "security.insecure-defaults"),
        ("misuse-resistance", "security.misuse-resistance"),
        ("agentic-ci", "security.agentic-ci"),
        ("agent-skill-mcp", "security.agent-skill-mcp"),
        ("all", "security.internal-suite"),
    ];

    pub fn pack_provider(pack: &str) -> Option<&'static str> {
        PACK_PROVIDERS.iter().find(|(k, _)| *k == pack).map(|(_, v)| *v)
    }

    const MAX_FILE_BYTES: usize = 2 * 1024 * 1024;

    enum Matcher {
        Patterns(&'static [&'static str]),
        Custom(fn(&str, &str) -> Vec<CustomMatch>),
    }

    struct CustomMatch {
        index: usize,
        metadata: Option<Value>,
    }

    struct Rule {
        pack: &'static str,
        id: &'static str,
        severity_hint: &'static str,
        threat_model: &'static str,
        matcher: Matcher,
        claim: &'static str,
    }

    fn line_at_local(text: &str, index: usize) -> usize {
        line_at(text, index)
    }

    fn index_of_any(text: &str, needles: &[&str]) -> usize {
        let lower = text.to_lowercase();
        needles
            .iter()
            .filter_map(|n| lower.find(&n.to_lowercase()))
            .min()
            .unwrap_or(0)
    }

    fn tool_boundary_taint(_path: &str, text: &str) -> Vec<CustomMatch> {
        let source_re = Regex::new(r"(?i)github\.event\.(?:issue|pull_request|comment)|(?:issue|pull_request|comment)\.body|request\.(?:body|query|params)|req\.(?:body|query|params)|userContent|untrusted(?:Input|Text)|promptInput").unwrap();
        let sink_re = Regex::new(r#"(?i)@tool\b|\b(?:callTool|invokeTool|executeTool|runTool)\s*\(|\bmcp\.(?:callTool|invoke)\s*\(|\btool_calls?\b|\btools\s*\[[^\]]+\]\s*\("#).unwrap();
        let source = match source_re.find(text) {
            Some(m) => m,
            None => return vec![],
        };
        let sink = match sink_re.find(text) {
            Some(m) => m,
            None => return vec![],
        };
        let start = source.start().min(sink.start());
        let end = source.start().max(sink.start());
        let between = &text[start..end];
        let validation_visible = Regex::new(r"(?i)(?:schema\.(?:parse|safeParse)|validate|sanitize|allowlist|whitelist|authorization|permission|policyCheck|approvedTool)")
            .unwrap()
            .is_match(between);
        vec![CustomMatch {
            index: source.start(),
            metadata: Some(json!({
                "source": source.as_str(), "sourceLine": line_at_local(text, source.start()),
                "sink": sink.as_str(), "sinkLine": line_at_local(text, sink.start()),
                "validationVisible": validation_visible, "boundary": "agent-to-tool",
            })),
        }]
    }

    fn skill_exfiltration_chain(_path: &str, text: &str) -> Vec<CustomMatch> {
        let reads_secrets = Regex::new(r"(?i)(?:process\.env|os\.environ|std::env|GetEnvironmentVariable|\.ssh|\.aws|credentials|keychain|secret)").unwrap().is_match(text);
        let sends_network = Regex::new(r"(?i)(?:fetch\s*\(|axios\.|requests\.|httpx\.|curl\s|Invoke-WebRequest|TcpStream|HttpClient)").unwrap().is_match(text);
        if reads_secrets && sends_network {
            let index = index_of_any(text, &["process.env", "os.environ", "credentials", "secret"]).min(text.len().saturating_sub(1));
            vec![CustomMatch { index, metadata: None }]
        } else {
            vec![]
        }
    }

    fn skill_hidden_unicode(_path: &str, text: &str) -> Vec<CustomMatch> {
        const HIDDEN: &[u32] = &[
            0x200b, 0x200c, 0x200d, 0x2060, 0xfeff, 0x202a, 0x202b, 0x202d, 0x202e, 0x2066, 0x2067, 0x2068, 0x2069,
        ];
        text.char_indices()
            .filter(|(_, c)| HIDDEN.contains(&(*c as u32)))
            .map(|(index, _)| CustomMatch { index, metadata: None })
            .collect()
    }

    fn rules() -> Vec<Rule> {
        vec![
            Rule {
                pack: "insecure-defaults", id: "security.insecure-default.secret", severity_hint: "high", threat_model: "deployment-misconfiguration",
                matcher: Matcher::Patterns(&[
                    r#"(?i)(?:SECRET|TOKEN|API_KEY|PRIVATE_KEY|JWT_KEY)\s*(?:=|:)\s*(?:process\.env\.[A-Z0-9_]+\s*(?:\|\||\?\?)\s*)?['"][^'"]{4,}['"]"#,
                    r#"(?i)(?:getenv|env)\s*\([^)]*(?:SECRET|TOKEN|KEY)[^)]*\)\s*(?:\?:|\?\?|or)\s*['"][^'"]+['"]"#,
                ]),
                claim: "A security-sensitive secret has a tracked fallback value instead of failing closed.",
            },
            Rule {
                pack: "insecure-defaults", id: "security.insecure-default.auth-disabled", severity_hint: "high", threat_model: "remote-unauthenticated",
                matcher: Matcher::Patterns(&[
                    r#"(?i)(?:AUTH|AUTHENTICATION|AUTHORIZATION|REQUIRE_AUTH)\s*(?:=|:)\s*(?:false|0|['"]false['"])"#,
                    r"(?i)(?:DisableAuth|AllowAnonymousByDefault|PermitAllByDefault)\s*(?:=|:)\s*true",
                ]),
                claim: "Authentication or authorization appears to default to disabled.",
            },
            Rule {
                pack: "insecure-defaults", id: "security.tls-verification-disabled", severity_hint: "high", threat_model: "network-attacker",
                matcher: Matcher::Patterns(&[
                    r"rejectUnauthorized\s*:\s*false", r"verify\s*=\s*False",
                    r"danger_accept_invalid_certs\s*\(\s*true\s*\)",
                    r"(?i)ServerCertificateCustomValidationCallback\s*=\s*[^;]*(?:true|=>\s*true)",
                ]),
                claim: "TLS certificate verification is explicitly disabled.",
            },
            Rule {
                pack: "misuse-resistance", id: "security.command-injection", severity_hint: "critical", threat_model: "attacker-controlled-input",
                matcher: Matcher::Patterns(&[
                    r"(?i)(?:exec|execSync|system|popen|Runtime\.getRuntime\(\)\.exec|Process\.Start|Command::new)\s*\([^\n;]*(?:req\.|request\.|params|query|body|argv|input|user)",
                    r"(?i)(?:eval|Function)\s*\([^\n;]*(?:req\.|request\.|params|query|body|input|user)",
                ]),
                claim: "Potentially attacker-controlled input reaches a process or code-execution sink.",
            },
            Rule {
                pack: "misuse-resistance", id: "security.path-traversal", severity_hint: "high", threat_model: "attacker-controlled-file-path",
                matcher: Matcher::Patterns(&[
                    r"(?i)(?:readFile|writeFile|open|File::open|Path\.Combine|Paths\.get|send_file|Storage::disk)[^\n;]*(?:req\.|request\.|params|query|body|input|filename|path)",
                ]),
                claim: "Potentially attacker-controlled path data reaches a filesystem operation.",
            },
            Rule {
                pack: "misuse-resistance", id: "security.unsafe-deserialization", severity_hint: "critical", threat_model: "attacker-controlled-serialized-data",
                matcher: Matcher::Patterns(&[
                    r"pickle\.loads?\s*\(", r"yaml\.load\s*\([^)]*", r"BinaryFormatter\s*\(",
                    r"ObjectInputStream\s*\(", r"Marshal\.load\s*\(", r"unserialize\s*\(",
                ]),
                claim: "A deserializer capable of constructing arbitrary object graphs is used.",
            },
            Rule {
                pack: "agentic-ci", id: "security.agent.prompt-injection-flow", severity_hint: "high", threat_model: "malicious-repository-or-ticket-content",
                matcher: Matcher::Patterns(&[
                    r"(?is)(?:github\.event\.(?:issue|pull_request)|issue\.body|pull_request\.body|comment\.body)[\s\S]{0,500}(?:prompt|instructions|messages)",
                    r"(?is)(?:prompt|instructions|messages)[\s\S]{0,500}(?:github\.event\.(?:issue|pull_request)|issue\.body|pull_request\.body|comment\.body)",
                ]),
                claim: "Untrusted issue, pull-request, or comment content appears to enter an agent prompt.",
            },
            Rule {
                pack: "agentic-ci", id: "security.agent.unsafe-execution", severity_hint: "critical", threat_model: "malicious-model-output",
                matcher: Matcher::Patterns(&[
                    r"(?is)(?:model|assistant|completion|llm)[A-Za-z0-9_.]*[\s\S]{0,300}(?:eval|exec|spawn|system|bash|sh -c|powershell)",
                    r"(?is)(?:eval|exec|spawn|system|bash|sh -c|powershell)[\s\S]{0,300}(?:model|assistant|completion|llm)",
                ]),
                claim: "Model output appears to reach a code or shell execution sink.",
            },
            Rule {
                pack: "agentic-ci", id: "security.agent.tool-boundary-taint", severity_hint: "high", threat_model: "malicious-prompt-or-request-content",
                matcher: Matcher::Custom(tool_boundary_taint),
                claim: "Potentially untrusted prompt or request content crosses an agent tool boundary; adjudicate validation, authorization, and sink reachability.",
            },
            Rule {
                pack: "agent-skill-mcp", id: "security.skill.exfiltration-chain", severity_hint: "critical", threat_model: "malicious-skill-or-hook",
                matcher: Matcher::Custom(skill_exfiltration_chain),
                claim: "The same skill, hook, or tool file reads credential material and performs network I/O.",
            },
            Rule {
                pack: "agent-skill-mcp", id: "security.skill.hidden-unicode", severity_hint: "high", threat_model: "malicious-skill-content",
                matcher: Matcher::Custom(skill_hidden_unicode),
                claim: "Agent-facing content contains invisible or bidirectional Unicode controls.",
            },
        ]
    }

    const CREDENTIAL_RULE_ID: &str = "security.credential-literal";
    const CREDENTIAL_CLAIM: &str = "A non-placeholder, credential-shaped literal is committed in a security-relevant file context.";
    const CREDENTIAL_SEVERITY: &str = "high";

    fn shannon_entropy(value: &str) -> f64 {
        let mut counts: std::collections::HashMap<char, usize> = std::collections::HashMap::new();
        for c in value.chars() {
            *counts.entry(c).or_insert(0) += 1;
        }
        let len = value.chars().count() as f64;
        counts.values().fold(0.0, |entropy, &count| {
            let p = count as f64 / len;
            entropy - p * p.log2()
        })
    }

    fn is_placeholder(value: &str) -> bool {
        let normalized: String = value.to_lowercase().chars().filter(|c| c.is_ascii_alphanumeric()).collect();
        if normalized.is_empty() {
            return true;
        }
        static LIST_RE: std::sync::OnceLock<Regex> = std::sync::OnceLock::new();
        let re = LIST_RE.get_or_init(|| {
            Regex::new(r"^(?:example|sample|dummy|test|testing|changeme|placeholder|notasecret|development|developmentsecret|devsecret|secret|password|token|apikey|your[a-z0-9]*)$").unwrap()
        });
        re.is_match(&normalized)
            || normalized.contains("replacewith")
            || normalized.contains("insert")
            || normalized.contains("xxxxx")
    }

    fn known_credential_format(value: &str) -> bool {
        static RE: std::sync::OnceLock<Regex> = std::sync::OnceLock::new();
        let re = RE.get_or_init(|| {
            Regex::new(r"^(?:AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{20,}|sk-[A-Za-z0-9_-]{16,}|xox[baprs]-[A-Za-z0-9-]{10,}|eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)$").unwrap()
        });
        re.is_match(value)
    }

    fn security_relevant_context(path: &str) -> &'static str {
        let normalized = path.to_lowercase().replace('\\', "/");
        static TEST_RE: std::sync::OnceLock<Regex> = std::sync::OnceLock::new();
        let test_re = TEST_RE.get_or_init(|| Regex::new(r"(?:^|/)(?:test|tests|fixtures?|examples?|docs?)/").unwrap());
        if test_re.is_match(&normalized) {
            return "low";
        }
        let ext = std::path::Path::new(path).extension().and_then(|e| e.to_str()).map(|s| format!(".{}", s.to_lowercase())).unwrap_or_default();
        const HIGH: &[&str] = &[".env", ".ini", ".toml", ".yaml", ".yml", ".json", ".js", ".jsx", ".ts", ".tsx", ".py", ".rb", ".php", ".java", ".kt", ".cs", ".go", ".rs", ".swift", ".sh", ".ps1"];
        if HIGH.contains(&ext.as_str()) || normalized.ends_with(".env") {
            "high"
        } else {
            "medium"
        }
    }

    fn credential_matches(path: &str, text: &str) -> Vec<CustomMatch> {
        let mut matches = Vec::new();
        let assignment = Regex::new(r#"(?i)(?:api[_-]?key|secret|token|password|private[_-]?key|client[_-]?secret)\s*(?:=|:)\s*['"]([^'"\r\n]{8,})['"]"#).unwrap();
        let context = security_relevant_context(path);
        for cap in assignment.captures_iter(text) {
            let full = cap.get(0).unwrap();
            let value = &cap[1];
            let format = known_credential_format(value);
            let entropy = shannon_entropy(value);
            if is_placeholder(value) {
                continue;
            }
            if !format && entropy < 3.2 {
                continue;
            }
            if context == "low" && !format && entropy < 4.0 {
                continue;
            }
            matches.push(CustomMatch {
                index: full.start(),
                metadata: Some(json!({
                    "filterStages": {
                        "regexTier": if format { "known-format" } else { "named-assignment" },
                        "entropy": (entropy * 1000.0).round() / 1000.0,
                        "placeholderRejected": false, "fileContext": context,
                    }
                })),
            });
        }
        let known = Regex::new(r"\b(?:AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{20,}|sk-[A-Za-z0-9_-]{16,}|xox[baprs]-[A-Za-z0-9-]{10,})\b").unwrap();
        for m in known.find_iter(text) {
            let entropy = shannon_entropy(m.as_str());
            matches.push(CustomMatch {
                index: m.start(),
                metadata: Some(json!({
                    "filterStages": {
                        "regexTier": "known-format", "entropy": (entropy * 1000.0).round() / 1000.0,
                        "placeholderRejected": false, "fileContext": context,
                    }
                })),
            });
        }
        matches
    }

    fn candidate(rule_id: &str, provider: &str, claim: &str, severity_hint: &str, threat_model: &str, path: &str, text: &str, m: &CustomMatch) -> Value {
        let line = line_at_local(text, m.index);
        let mut obj = json!({
            "id": digest_id(&[provider, rule_id, &format!("{path}:{line}")]),
            "ruleId": rule_id, "provider": provider, "role": "candidate-generator", "claim": claim,
            "severityHint": severity_hint, "threatModel": threat_model,
            "evidence": [{ "file": path, "line": line }], "evidenceStrength": "candidate",
            "verdict": "UNADJUDICATED", "adjudicationRequired": true,
        });
        if let Some(metadata) = &m.metadata {
            obj["detectorMetadata"] = metadata.clone();
        }
        obj
    }

    fn rules_for_pack(pack: &str) -> Result<Vec<Rule>, String> {
        if pack == "all" {
            return Ok(rules());
        }
        if pack_provider(pack).is_none() {
            return Err(format!("unknown security rule pack {pack}"));
        }
        Ok(rules().into_iter().filter(|r| r.pack == pack).collect())
    }

    pub fn generate_security_candidates(root: &std::path::Path, files: &[String], pack: &str, provider: Option<&str>) -> Result<Value, String> {
        let provider = provider.map(String::from).unwrap_or_else(|| pack_provider(pack).map(String::from).unwrap_or_else(|| format!("security.{pack}")));
        let rules = rules_for_pack(pack)?;
        let mut candidates = Vec::new();
        let mut scanned = Vec::new();
        let mut sorted: Vec<String> = files.to_vec();
        sorted.sort();
        sorted.dedup();
        for path in &sorted {
            let full = root.join(path);
            let bytes = match std::fs::read(&full) {
                Ok(b) => b,
                Err(_) => continue,
            };
            if bytes.len() > MAX_FILE_BYTES || bytes.contains(&0) {
                continue;
            }
            let text = match String::from_utf8(bytes) {
                Ok(t) => t,
                Err(_) => continue,
            };
            scanned.push(path.clone());
            if pack == "credentials" || pack == "all" {
                for m in credential_matches(path, &text) {
                    candidates.push(candidate(CREDENTIAL_RULE_ID, &provider, CREDENTIAL_CLAIM, CREDENTIAL_SEVERITY, "credential-exposure", path, &text, &m));
                }
            }
            for rule in &rules {
                match &rule.matcher {
                    Matcher::Custom(f) => {
                        for m in f(path, &text) {
                            candidates.push(candidate(rule.id, &provider, rule.claim, rule.severity_hint, rule.threat_model, path, &text, &m));
                        }
                    }
                    Matcher::Patterns(patterns) => {
                        for pattern in *patterns {
                            let re = Regex::new(pattern).unwrap();
                            for m in re.find_iter(&text) {
                                candidates.push(candidate(rule.id, &provider, rule.claim, rule.severity_hint, rule.threat_model, path, &text, &CustomMatch { index: m.start(), metadata: None }));
                            }
                        }
                    }
                }
            }
        }
        let mut seen = std::collections::HashSet::new();
        let unique: Vec<Value> = candidates
            .into_iter()
            .filter(|c| seen.insert(c["id"].as_str().unwrap_or_default().to_string()))
            .collect();
        let mut rule_ids: Vec<Value> = Vec::new();
        if pack == "credentials" {
            rule_ids.push(json!(CREDENTIAL_RULE_ID));
        }
        rule_ids.extend(rules.iter().map(|r| json!(r.id)));
        Ok(json!({
            "schemaVersion": 1, "kind": "audit-security-candidates", "provider": provider, "rulePack": pack,
            "complete": scanned.len() == sorted.len(),
            "coverage": { "expectedFiles": sorted.len(), "scannedFiles": scanned.len(), "scanned": scanned, "rules": rule_ids },
            "candidates": unique,
            "coverageGaps": if scanned.len() == sorted.len() { json!([]) } else { json!([{ "kind": "unreadable-or-binary-files", "count": sorted.len() - scanned.len() }]) },
        }))
    }

    pub fn merge_security_candidate_reports(reports: &[Value]) -> Value {
        let mut seen = std::collections::HashSet::new();
        let candidates: Vec<Value> = reports
            .iter()
            .flat_map(|r| r.get("candidates").and_then(Value::as_array).cloned().unwrap_or_default())
            .filter(|c| seen.insert(c["id"].as_str().unwrap_or_default().to_string()))
            .collect();
        let complete = reports.iter().all(|r| r.get("complete").and_then(Value::as_bool).unwrap_or(true));
        let provider_reports: Vec<Value> = reports
            .iter()
            .map(|r| json!({
                "provider": r.get("provider").cloned().unwrap_or(Value::Null),
                "rulePack": r.get("rulePack").cloned().unwrap_or(Value::Null),
                "expectedFiles": r["coverage"]["expectedFiles"].clone(),
                "scannedFiles": r["coverage"]["scannedFiles"].clone(),
                "rules": r["coverage"]["rules"].clone(),
            }))
            .collect();
        let coverage_gaps: Vec<Value> = reports
            .iter()
            .flat_map(|r| {
                let provider = r.get("provider").cloned().unwrap_or(Value::Null);
                r.get("coverageGaps").and_then(Value::as_array).cloned().unwrap_or_default().into_iter().map(move |mut gap| {
                    if let Value::Object(obj) = &mut gap {
                        obj.insert("provider".into(), provider.clone());
                    }
                    gap
                })
            })
            .collect();
        json!({
            "schemaVersion": 1, "kind": "audit-security-candidates", "provider": "security.multi-provider",
            "complete": complete, "coverage": { "providerReports": provider_reports },
            "candidates": candidates, "coverageGaps": coverage_gaps,
        })
    }

    pub fn derive_variant_queries(confirmed_finding: &Value) -> Result<Value, String> {
        let rule_id = confirmed_finding.get("ruleId").and_then(Value::as_str).ok_or("confirmed finding requires ruleId and evidence")?;
        let evidence = confirmed_finding.get("evidence").and_then(Value::as_array).filter(|e| !e.is_empty()).ok_or("confirmed finding requires ruleId and evidence")?;
        let first = &evidence[0];
        let file = first.get("file").and_then(Value::as_str).unwrap_or_default();
        let line = first.get("line").cloned().unwrap_or(Value::Null);
        let same_sink_class = rule_id.split('.').take(2).collect::<Vec<_>>().join(".");
        Ok(json!({
            "schemaVersion": 1, "kind": "security-variant-plan",
            "findingId": confirmed_finding.get("id").cloned().unwrap_or(Value::Null),
            "ruleId": rule_id,
            "queries": [
                { "level": "exact", "key": format!("{rule_id}:{file}:{line}") },
                { "level": "same-rule", "key": rule_id },
                { "level": "same-sink-class", "key": same_sink_class },
            ],
        }))
    }
}
