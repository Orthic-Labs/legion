//! Port of `skills/seo/scripts/contracts.py`.
//!
//! Structural validator for SEO evidence/finding/recommendation/action/
//! outcome objects, against the same rules read from `config()` in the
//! Python source (mirrored here as a static [`ContractsConfig`] equal to
//! the checked-in `skills/seo/config/contracts.json`, since this crate
//! keeps file I/O at the edges). Passing this validator never grants
//! permission to mutate; authorization stays owned by the host effect
//! boundary, exactly as the Python docstring says.

use serde_json::Value;

/// Mirrors the shape of `skills/seo/config/contracts.json`.
#[derive(Debug, Clone)]
pub struct ContractsConfig {
    pub statuses: &'static [&'static str],
    pub claim_states: &'static [&'static str],
    pub evidence_tiers: &'static [&'static str],
    pub evidence_required: &'static [&'static str],
    pub finding_required: &'static [&'static str],
    pub recommendation_required: &'static [&'static str],
    pub action_required: &'static [&'static str],
    pub outcome_required: &'static [&'static str],
}

/// Mirrors Python `config()`: the values read from
/// `skills/seo/config/contracts.json`.
pub fn config() -> ContractsConfig {
    ContractsConfig {
        statuses: &["pass", "partial", "fail", "na", "not_testable"],
        claim_states: &[
            "observed",
            "estimated",
            "hypothesis",
            "recommendation",
            "verified_technical",
            "outcome_observed",
            "causal_supported",
        ],
        evidence_tiers: &[
            "static",
            "rendered",
            "first_party",
            "paid_provider",
            "manual_first_party_export",
            "experimental",
        ],
        evidence_required: &[
            "id",
            "source_identity",
            "collected_at",
            "market",
            "tier",
            "subject",
            "raw_locator",
            "coverage_state",
        ],
        finding_required: &[
            "id",
            "subject",
            "evidence_ids",
            "market",
            "confidence",
            "coverage_state",
            "claim_state",
            "observed_condition",
        ],
        recommendation_required: &[
            "id",
            "finding_ids",
            "target",
            "proposed_action",
            "expected_mechanism",
            "confidence",
            "business_value",
            "effort",
            "downside",
        ],
        action_required: &[
            "id",
            "recommendation_id",
            "authorized_capability",
            "target",
            "exact_change",
            "baseline_ref",
            "idempotency_key",
            "rollback",
            "status",
        ],
        outcome_required: &[
            "id",
            "action_id",
            "recorded_at",
            "metric",
            "baseline_ref",
            "observation",
            "verdict",
            "causal_strength",
            "confounders",
        ],
    }
}

fn required_fields<'a>(cfg: &'a ContractsConfig, kind: &str) -> Option<&'a [&'static str]> {
    match kind {
        "evidence" => Some(cfg.evidence_required),
        "finding" => Some(cfg.finding_required),
        "recommendation" => Some(cfg.recommendation_required),
        "action" => Some(cfg.action_required),
        "outcome" => Some(cfg.outcome_required),
        _ => None,
    }
}

/// Mirrors Python `obj.get(key) in (None, '')`: missing key, JSON null, or
/// an empty string all count as "not present".
fn is_missing(obj: &Value, key: &str) -> bool {
    match obj.get(key) {
        None => true,
        Some(Value::Null) => true,
        Some(Value::String(s)) => s.is_empty(),
        Some(_) => false,
    }
}

fn as_str<'a>(obj: &'a Value, key: &str) -> Option<&'a str> {
    obj.get(key).and_then(Value::as_str)
}

fn truthy(v: Option<&Value>) -> bool {
    match v {
        None | Some(Value::Null) => false,
        Some(Value::Bool(b)) => *b,
        Some(Value::String(s)) => !s.is_empty(),
        Some(Value::Array(a)) => !a.is_empty(),
        Some(Value::Object(o)) => !o.is_empty(),
        Some(Value::Number(n)) => n.as_f64() != Some(0.0),
    }
}

/// Mirrors Python `validate(kind, obj)`.
pub fn validate(kind: &str, obj: &Value) -> Vec<String> {
    let cfg = config();
    let Some(required) = required_fields(&cfg, kind) else {
        return vec![format!("unknown contract kind: {kind}")];
    };
    let mut errors = Vec::new();
    for key in required {
        if is_missing(obj, key) {
            errors.push(format!("{kind}.{key} is required"));
        }
    }
    if kind == "evidence" || kind == "finding" {
        let state = as_str(obj, "coverage_state");
        if !state.is_some_and(|s| cfg.statuses.contains(&s)) {
            errors.push(format!(
                "{kind}.coverage_state must be one of {:?}",
                cfg.statuses
            ));
        }
    }
    if kind == "evidence" {
        let tier = as_str(obj, "tier");
        if !tier.is_some_and(|t| cfg.evidence_tiers.contains(&t)) {
            errors.push(format!(
                "evidence.tier must be one of {:?}",
                cfg.evidence_tiers
            ));
        }
    }
    if kind == "finding" {
        let claim_state = as_str(obj, "claim_state");
        if !claim_state.is_some_and(|c| cfg.claim_states.contains(&c)) {
            errors.push(format!(
                "finding.claim_state must be one of {:?}",
                cfg.claim_states
            ));
        }
        let evidence_ids_ok = matches!(obj.get("evidence_ids"), Some(Value::Array(a)) if !a.is_empty());
        if !evidence_ids_ok {
            errors.push("finding.evidence_ids must be a non-empty list".to_string());
        }
        if as_str(obj, "coverage_state") == Some("partial")
            && !(truthy(obj.get("tested_scope")) && truthy(obj.get("untested_scope")))
        {
            errors.push("partial finding requires tested_scope and untested_scope".to_string());
        }
        if as_str(obj, "coverage_state") == Some("not_testable") && !truthy(obj.get("reason")) {
            errors.push("not_testable finding requires reason".to_string());
        }
    }
    if kind == "action" {
        const VALID_STATUSES: &[&str] = &[
            "proposed",
            "authorized",
            "executed",
            "verified",
            "rolled_back",
            "failed",
        ];
        let status = as_str(obj, "status");
        if !status.is_some_and(|s| VALID_STATUSES.contains(&s)) {
            errors.push("action.status invalid".to_string());
        }
        if matches!(status, Some("executed") | Some("verified"))
            && !truthy(obj.get("effect_receipt"))
        {
            errors.push(
                "executed/verified action requires host-observed effect_receipt".to_string(),
            );
        }
    }
    if kind == "outcome" {
        const VALID_VERDICTS: &[&str] = &[
            "improved",
            "declined",
            "mixed",
            "inconclusive",
            "not_measurable",
        ];
        const VALID_CAUSAL_STRENGTHS: &[&str] =
            &["observational", "quasi_experimental", "controlled"];
        let verdict = as_str(obj, "verdict");
        if !verdict.is_some_and(|v| VALID_VERDICTS.contains(&v)) {
            errors.push("outcome.verdict invalid".to_string());
        }
        let causal_strength = as_str(obj, "causal_strength");
        if !causal_strength.is_some_and(|c| VALID_CAUSAL_STRENGTHS.contains(&c)) {
            errors.push("outcome.causal_strength invalid".to_string());
        }
    }
    errors
}

fn id_set(payload: &Value, key: &str) -> Vec<String> {
    payload
        .get(key)
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(|x| x.get("id").and_then(Value::as_str).map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

fn array_of<'a>(payload: &'a Value, key: &str) -> &'a [Value] {
    static EMPTY: [Value; 0] = [];
    payload
        .get(key)
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or(&EMPTY)
}

/// Mirrors Python `validate_bundle(payload)`. Returns
/// `{"status": "pass" | "fail", "errors": [...]}`.
pub fn validate_bundle(payload: &Value) -> Value {
    let mut errors: Vec<String> = Vec::new();
    for kind in ["evidence", "finding", "recommendation", "action", "outcome"] {
        let plural = format!("{kind}s");
        for (i, obj) in array_of(payload, &plural).iter().enumerate() {
            for error in validate(kind, obj) {
                errors.push(format!("{plural}[{i}]: {error}"));
            }
        }
    }

    let evidence_ids = id_set(payload, "evidences");
    let finding_ids = id_set(payload, "findings");
    let recommendation_ids = id_set(payload, "recommendations");
    let action_ids = id_set(payload, "actions");

    for (i, f) in array_of(payload, "findings").iter().enumerate() {
        let missing: Vec<String> = f
            .get("evidence_ids")
            .and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(Value::as_str)
                    .filter(|eid| !evidence_ids.iter().any(|e| e == eid))
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default();
        if !missing.is_empty() {
            errors.push(format!(
                "findings[{i}] references missing evidence IDs: [{}]",
                missing
                    .iter()
                    .map(|m| format!("'{m}'"))
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }
    }
    for (i, r) in array_of(payload, "recommendations").iter().enumerate() {
        let missing: Vec<String> = r
            .get("finding_ids")
            .and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(Value::as_str)
                    .filter(|fid| !finding_ids.iter().any(|f| f == fid))
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default();
        if !missing.is_empty() {
            errors.push(format!(
                "recommendations[{i}] references missing finding IDs: [{}]",
                missing
                    .iter()
                    .map(|m| format!("'{m}'"))
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }
    }
    for (i, a) in array_of(payload, "actions").iter().enumerate() {
        let rid = a.get("recommendation_id").and_then(Value::as_str);
        let ok = rid.is_some_and(|rid| recommendation_ids.iter().any(|r| r == rid));
        if !ok {
            errors.push(format!(
                "actions[{i}] references missing recommendation: {}",
                rid.map(|s| format!("{s}")).unwrap_or_else(|| "None".to_string())
            ));
        }
    }
    for (i, o) in array_of(payload, "outcomes").iter().enumerate() {
        let aid = o.get("action_id").and_then(Value::as_str);
        let ok = aid.is_some_and(|aid| action_ids.iter().any(|a| a == aid));
        if !ok {
            errors.push(format!(
                "outcomes[{i}] references missing action: {}",
                aid.map(|s| format!("{s}")).unwrap_or_else(|| "None".to_string())
            ));
        }
    }

    serde_json::json!({
        "status": if errors.is_empty() { "pass" } else { "fail" },
        "errors": errors,
    })
}
