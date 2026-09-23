//! Port of `skills/seo/scripts/page_engine.py`.
//!
//! Legion-native Page Engine contract helper. Validates page-family,
//! page-type, query-ownership, information-gain and claim-control inputs.
//! It identifies structural blockers before prose changes. It does not
//! invent a page verdict when evidence is insufficient and does not grant
//! mutation authority.
//!
//! Faithful to `page_engine.py`'s `assess`/`validate_page_contract`/
//! `validate_claims`/`detect_blockers`/`information_gain` behaviour. The
//! CLI's file I/O (`main`, reading `--input`/`--out` and
//! `config/page-engine.json` from disk) is intentionally not ported here;
//! callers supply the config (loaded once, e.g. from
//! `skills/seo/config/page-engine.json`) and the input bundle as
//! `serde_json::Value`, matching Python's untyped-JSON approach.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

/// Mirrors the `config/page-engine.json` schema read by `cfg()` in Python.
#[derive(Debug, Clone, Deserialize)]
pub struct PageEngineConfig {
    pub verdicts: Vec<String>,
    pub page_types: std::collections::BTreeMap<String, Vec<String>>,
    #[serde(default)]
    pub family_edges: Vec<String>,
    #[serde(default)]
    pub structural_blockers: Vec<String>,
    pub information_gain_types: Vec<String>,
    pub claim_states: Vec<String>,
    #[serde(default)]
    pub claim_rule: String,
}

/// `validate_page_contract(contract)` in Python.
pub fn validate_page_contract(cfg: &PageEngineConfig, contract: &Value) -> Vec<String> {
    let mut errors = Vec::new();
    let page_type = contract.get("page_type").and_then(Value::as_str);
    let Some(page_type) = page_type else {
        errors.push(format!("unknown page_type: {}", display_none(contract.get("page_type"))));
        return errors;
    };
    let Some(required_keys) = cfg.page_types.get(page_type) else {
        errors.push(format!("unknown page_type: {page_type}"));
        return errors;
    };
    for key in required_keys {
        let is_empty = match contract.get(key) {
            None => true,
            Some(Value::Null) => true,
            Some(Value::String(s)) => s.is_empty(),
            Some(Value::Array(a)) => a.is_empty(),
            _ => false,
        };
        if is_empty {
            errors.push(format!("{page_type}.{key} is required"));
        }
    }
    errors
}

fn display_none(v: Option<&Value>) -> String {
    match v {
        None | Some(Value::Null) => "None".to_string(),
        Some(other) => other.to_string(),
    }
}

/// `validate_claims(claims)` in Python.
pub fn validate_claims(cfg: &PageEngineConfig, claims: &[Value]) -> Vec<String> {
    let allowed: BTreeSet<&str> = cfg.claim_states.iter().map(String::as_str).collect();
    let mut errors = Vec::new();
    for (i, claim) in claims.iter().enumerate() {
        let claim_text = claim.get("claim").and_then(Value::as_str).unwrap_or("");
        if claim_text.is_empty() {
            errors.push(format!("claims[{i}].claim required"));
        }
        let state = claim.get("state").and_then(Value::as_str);
        if !state.is_some_and(|s| allowed.contains(s)) {
            errors.push(format!("claims[{i}].state invalid"));
        }
        let use_in_output = claim.get("use_in_output").and_then(Value::as_bool).unwrap_or(false);
        if state == Some("approved") {
            let has_source = claim
                .get("source")
                .map(|s| !matches!(s, Value::Null))
                .unwrap_or(false)
                && claim.get("source").and_then(Value::as_str) != Some("");
            if !has_source {
                errors.push(format!("claims[{i}] approved claim requires source"));
            }
        }
        if state == Some("requires_verification") && use_in_output {
            errors.push(format!("claims[{i}] unverified claim cannot be used in output"));
        }
        if state == Some("banned") && use_in_output {
            errors.push(format!("claims[{i}] banned claim cannot be used in output"));
        }
    }
    errors
}

/// `detect_blockers(bundle)` in Python.
pub fn detect_blockers(bundle: &Value) -> Vec<Value> {
    let mut blockers = Vec::new();

    if let Some(ownership) = bundle.get("query_ownership").and_then(Value::as_array) {
        for row in ownership {
            let kind = row.get("classification").and_then(Value::as_str);
            if matches!(kind, Some("ownership switching") | Some("probable duplicate target")) {
                blockers.push(json!({
                    "type": "multiple_owners_one_intent",
                    "subject": row.get("query").cloned().unwrap_or(Value::Null),
                    "evidence": row,
                }));
            }
        }
    }

    let empty = json!({});
    let page = bundle.get("page").unwrap_or(&empty);

    let canonical_expected = page.get("canonical_expected");
    let canonical_observed = page.get("canonical_observed");
    if truthy(canonical_expected) && truthy(canonical_observed) && canonical_expected != canonical_observed {
        blockers.push(json!({
            "type": "canonical_mismatch",
            "subject": page.get("url").cloned().unwrap_or(Value::Null),
            "evidence": {
                "expected": canonical_expected.cloned().unwrap_or(Value::Null),
                "observed": canonical_observed.cloned().unwrap_or(Value::Null),
            },
        }));
    }

    if page.get("intended_indexable").and_then(Value::as_bool) == Some(true)
        && page.get("observed_indexable").and_then(Value::as_bool) == Some(false)
    {
        blockers.push(json!({
            "type": "wrong_indexability",
            "subject": page.get("url").cloned().unwrap_or(Value::Null),
            "evidence": {"intended_indexable": true, "observed_indexable": false},
        }));
    }

    let serp_expected_type = page.get("serp_expected_type");
    let page_type = page.get("page_type");
    if truthy(serp_expected_type) && truthy(page_type) && serp_expected_type != page_type {
        blockers.push(json!({
            "type": "wrong_serp_page_type",
            "subject": page.get("url").cloned().unwrap_or(Value::Null),
            "evidence": {
                "page_type": page_type.cloned().unwrap_or(Value::Null),
                "serp_expected_type": serp_expected_type.cloned().unwrap_or(Value::Null),
            },
        }));
    }

    if page.get("orphan").and_then(Value::as_bool) == Some(true) {
        blockers.push(json!({
            "type": "orphan",
            "subject": page.get("url").cloned().unwrap_or(Value::Null),
            "evidence": {"orphan": true},
        }));
    }

    if let Some(intents) = page.get("intents").and_then(Value::as_array) {
        let unique: BTreeSet<String> = intents
            .iter()
            .filter_map(|v| v.as_str().map(str::to_string))
            .collect();
        let justified = page
            .get("mixed_intent_justified")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        if unique.len() > 1 && !justified {
            blockers.push(json!({
                "type": "two_intents_one_url",
                "subject": page.get("url").cloned().unwrap_or(Value::Null),
                "evidence": {"intents": intents},
            }));
        }
    }

    blockers
}

/// `contract.get(key) in (None, '', [])` truthiness used by `detect_blockers`
/// for the plain presence checks (`if page.get('canonical_expected') and ...`).
fn truthy(v: Option<&Value>) -> bool {
    match v {
        None | Some(Value::Null) => false,
        Some(Value::Bool(b)) => *b,
        Some(Value::String(s)) => !s.is_empty(),
        Some(Value::Array(a)) => !a.is_empty(),
        Some(Value::Number(n)) => n.as_f64() != Some(0.0),
        Some(Value::Object(o)) => !o.is_empty(),
    }
}

/// `information_gain(bundle)` in Python.
#[derive(Debug, Clone, Serialize)]
pub struct InformationGain {
    pub status: &'static str,
    pub valid: Vec<Value>,
    pub invalid_or_unsubstantiated: Vec<Value>,
}

pub fn information_gain(cfg: &PageEngineConfig, bundle: &Value) -> InformationGain {
    let allowed: BTreeSet<&str> = cfg.information_gain_types.iter().map(String::as_str).collect();
    let gains = bundle
        .get("information_gain")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let mut valid = Vec::new();
    let mut invalid = Vec::new();
    for item in gains {
        let type_ok = item.get("type").and_then(Value::as_str).is_some_and(|t| allowed.contains(t));
        let has_evidence = truthy(item.get("evidence"));
        if type_ok && has_evidence {
            valid.push(item);
        } else {
            invalid.push(item);
        }
    }
    let status = if !valid.is_empty() { "demonstrated" } else { "not_demonstrated" };
    InformationGain { status, valid, invalid_or_unsubstantiated: invalid }
}

/// `assess(bundle)` in Python. Returns the full result object as JSON,
/// matching the Python dict shape exactly (field names and order of
/// construction, though JSON object key order is not semantically
/// significant).
pub fn assess(cfg: &PageEngineConfig, bundle: &Value) -> Value {
    let mut errors: Vec<String> = Vec::new();

    let empty_contract = json!({});
    let contract = bundle.get("page_contract").unwrap_or(&empty_contract);
    let contract_present = truthy(Some(contract));
    if contract_present {
        errors.extend(validate_page_contract(cfg, contract));
    }

    let claims: Vec<Value> = bundle
        .get("claims")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    errors.extend(validate_claims(cfg, &claims));

    let blockers = detect_blockers(bundle);
    let gain = information_gain(cfg, bundle);

    let requested_verdict = bundle.get("verdict").and_then(Value::as_str);
    if let Some(v) = requested_verdict {
        if !cfg.verdicts.iter().any(|x| x == v) {
            errors.push(format!("unknown verdict: {v}"));
        }
    }

    if matches!(requested_verdict, Some("EXPAND") | Some("SPLIT") | Some("REPOSITION"))
        && gain.status != "demonstrated"
    {
        errors.push(format!(
            "{} requires demonstrated information gain",
            requested_verdict.unwrap()
        ));
    }

    if matches!(
        requested_verdict,
        Some("DELETE") | Some("REDIRECT") | Some("NOINDEX") | Some("CONSOLIDATE")
    ) && !truthy(bundle.get("destructive_justification"))
    {
        errors.push(format!(
            "{} requires destructive_justification",
            requested_verdict.unwrap()
        ));
    }

    let recommended: String = match requested_verdict {
        None => {
            let mut r = if !blockers.is_empty() { "INVESTIGATE" } else { "KEEP" };
            if !contract_present || !errors.is_empty() {
                r = "INVESTIGATE";
            }
            r.to_string()
        }
        Some(v) => v.to_string(),
    };

    let status = if errors.is_empty() { "pass" } else { "fail" };
    let page_url = bundle
        .get("page")
        .and_then(|p| p.get("url"))
        .cloned()
        .unwrap_or(Value::Null);

    json!({
        "status": status,
        "page": page_url,
        "blockers": blockers,
        "information_gain": {
            "status": gain.status,
            "valid": gain.valid,
            "invalid_or_unsubstantiated": gain.invalid_or_unsubstantiated,
        },
        "verdict": recommended,
        "errors": errors,
        "rule": "Structural blockers precede copy changes. This helper validates evidence/contracts; it does not authorize effects.",
    })
}
