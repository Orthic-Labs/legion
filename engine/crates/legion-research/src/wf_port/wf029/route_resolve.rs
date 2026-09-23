//! Port of `src/lib/research-core/router/route_resolve.py`: resolve and
//! grant a two-stage, least-privilege `ResearchRoute`.
//!
//! This is a from-scratch model of the route/subject/gate machinery as the
//! Python script defines it (a loose JSON `dict`), distinct from
//! `crate::ResearchRoute` in `workflow.rs`: that type already exists for a
//! different, stricter contract (fixed `allowed_effects`/`human_gates`
//! enums validated by `validate_unique_values` against `ROUTE_EFFECTS`/
//! `ROUTE_GATES`) and is read-only for this chunk. Everything here mirrors
//! `route_resolve.py`'s own field names and control flow one-for-one,
//! including gates and effects the existing `ResearchRoute` does not know
//! about (e.g. `approve-notebooklm-upload`, `spawn-worker`).
//!
//! The CLI entry point (`main`, argument parsing, file I/O) is not ported:
//! it is a thin `argparse`/stdin-stdout shim over `resolve`/`grant_effects`/
//! `gate_verdicts`/`validate_route`, all of which are ported below in full.

use std::collections::BTreeMap;

use serde_json::{json, Map, Value};

use super::route_detect::{
    detect_assurance, detect_domain, detect_methods, detect_operation, detect_provider,
    detect_scale, detect_sensitivity, is_other_patient, is_personal_first_person, unique,
};
use super::route_detect::{country as detect_country, issue as detect_issue, legal_area as detect_legal_area};
use super::route_detect::{ASSURANCE, DOMAIN_VALUES, METHODS, OPERATIONS, PROVIDERS, SCALE, SENSITIVITY};

/// Context supplied by the caller in place of `context: dict[str, Any] |
/// None` — every key the Python reads from `context` via `.get`, kept as
/// loose JSON `Value`s so an absent key and an explicit `null` both fall
/// through to detection exactly as `context.get(key)` does (`None` is
/// falsy in the `or` chains the Python uses).
pub type Context = Map<String, Value>;

fn get_str<'a>(context: &'a Context, key: &str) -> Option<&'a str> {
    context.get(key).and_then(Value::as_str).filter(|s| !s.is_empty())
}

fn get_nonempty<'a>(context: &'a Context, key: &str) -> Option<&'a Value> {
    match context.get(key) {
        None | Some(Value::Null) => None,
        Some(Value::String(s)) if s.is_empty() => None,
        Some(v) => Some(v),
    }
}

/// `route_resolve.build_subject`.
pub fn build_subject(intent: &str, domain: &str, context: &Context) -> Value {
    if domain == "medical" {
        let explicit = get_str(context, "patient_kind");
        let kind = match explicit {
            Some(k @ ("anonymous" | "self" | "other-identified")) => k.to_string(),
            _ if is_other_patient(intent) => "other-identified".to_string(),
            _ if is_personal_first_person(intent) => "self".to_string(),
            _ => "anonymous".to_string(),
        };
        // Personal routes never infer a patient-history path: the caller
        // must supply `history_source` explicitly via context. No filename
        // or path is hardcoded here.
        let history_source = get_str(context, "history_source").map(str::to_string);
        let history_available = history_source
            .as_deref()
            .map(|p| std::path::Path::new(p).is_file())
            .unwrap_or(false);
        let issue_text = get_str(context, "issue").map(str::to_string).unwrap_or_else(|| detect_issue(intent));
        let urgency = get_str(context, "urgency").unwrap_or("routine").to_string();
        return json!({
            "patient": {
                "kind": kind,
                "history_available": history_available,
                "history_source": history_source,
            },
            "issue": issue_text,
            "urgency": urgency,
        });
    }
    if domain == "legal" {
        let country_val = get_str(context, "country").map(str::to_string).or_else(|| detect_country(intent).map(str::to_string));
        let area_val = get_str(context, "area").map(str::to_string).or_else(|| detect_legal_area(intent).map(str::to_string));
        let issue_text = get_str(context, "issue").map(str::to_string).unwrap_or_else(|| detect_issue(intent));
        let mut subject = Map::new();
        subject.insert("country".into(), country_val.map(Value::String).unwrap_or(Value::Null));
        subject.insert("area".into(), area_val.map(Value::String).unwrap_or(Value::Null));
        subject.insert("issue".into(), Value::String(issue_text));
        for key in [
            "state_or_region", "forum_or_regulator", "posture", "role_or_side",
            "pecuniary_value", "cause_of_action_date", "notice_status", "desired_outcome",
            "intended_external_action",
        ] {
            if let Some(v) = get_nonempty(context, key) {
                subject.insert(key.to_string(), v.clone());
            }
        }
        return Value::Object(subject);
    }
    // `dict(context.get('subject') or {})`: an empty dict is falsy in
    // Python too, so both a missing/null subject and an explicit `{}`
    // fall back to a fresh empty object.
    match context.get("subject") {
        Some(Value::Object(m)) if !m.is_empty() => Value::Object(m.clone()),
        _ => Value::Object(Map::new()),
    }
}

fn default_output(domain: &str, operation: &str) -> &'static str {
    if domain == "medical" {
        return "medical-evidence-pack";
    }
    if domain == "legal" && operation == "procedure" {
        return "filing-guidance-or-pack";
    }
    if domain == "legal" {
        return "legal-research-memo";
    }
    if operation == "generate-artifact" {
        return "requested-artifact";
    }
    "evidence-brief"
}

/// `route_resolve.resolve`.
pub fn resolve(intent: &str, context: &Context) -> Result<Value, String> {
    let domain = get_str(context, "domain").unwrap_or_else(|| detect_domain(intent)).to_string();
    let operation = get_str(context, "operation").unwrap_or_else(|| detect_operation(intent)).to_string();
    let methods: Vec<String> = match context.get("methods") {
        Some(Value::Array(arr)) if !arr.is_empty() => {
            arr.iter().filter_map(|v| v.as_str().map(str::to_string)).collect()
        }
        _ => detect_methods(intent),
    };
    let provider = get_str(context, "provider")
        .map(str::to_string)
        .unwrap_or_else(|| detect_provider(intent, &domain, &methods).to_string());
    let assurance = get_str(context, "assurance")
        .map(str::to_string)
        .unwrap_or_else(|| detect_assurance(intent, &domain, &operation).to_string());
    let scale = get_str(context, "scale").map(str::to_string).unwrap_or_else(|| detect_scale(intent).to_string());
    let subject = build_subject(intent, &domain, context);
    let patient_kind = if domain == "medical" {
        subject.get("patient").and_then(|p| p.get("kind")).and_then(Value::as_str).map(str::to_string)
    } else {
        None
    };
    let sensitivity = get_str(context, "sensitivity")
        .map(str::to_string)
        .unwrap_or_else(|| detect_sensitivity(intent, &domain, patient_kind.as_deref()).to_string());
    let decision = get_str(context, "decision").unwrap_or(intent).trim().to_string();
    let output = get_str(context, "output")
        .map(str::to_string)
        .unwrap_or_else(|| default_output(&domain, &operation).to_string());

    let mut route = Map::new();
    route.insert("route_version".into(), json!(2));
    route.insert("domain".into(), json!(domain));
    route.insert("operation".into(), json!(operation));
    route.insert("methods".into(), json!(unique(&methods)));
    route.insert("provider".into(), json!(provider));
    route.insert("assurance".into(), json!(assurance));
    route.insert("scale".into(), json!(scale));
    route.insert("subject".into(), subject);
    route.insert("sensitivity".into(), json!(sensitivity));
    route.insert("decision".into(), json!(decision));
    route.insert("output".into(), json!(output));
    route.insert("allowed_effects".into(), json!(Vec::<String>::new()));
    route.insert("human_gates".into(), json!(Vec::<String>::new()));
    route.insert("forbidden_resources".into(), json!(Vec::<String>::new()));

    let mut route_val = Value::Object(route);
    let (gates, forbidden) = pending_gates(&route_val);
    route_val["human_gates"] = json!(gates);
    route_val["forbidden_resources"] = json!(forbidden);
    validate_route(&route_val, Stage::Route)?;
    Ok(route_val)
}

fn field_str<'a>(route: &'a Value, key: &str) -> &'a str {
    route.get(key).and_then(Value::as_str).unwrap_or("")
}

fn subject_str<'a>(subject: &'a Value, key: &str) -> Option<&'a str> {
    subject.get(key).and_then(Value::as_str).filter(|s| !s.is_empty())
}

/// Mirrors Python's `subject.get(key) in (None, '')`: any present,
/// non-null, non-empty-string value counts (numbers, bools, etc. included),
/// unlike `subject_str` which is specifically for string-typed fields.
fn subject_missing(subject: &Value, key: &str) -> bool {
    match subject.get(key) {
        None | Some(Value::Null) => true,
        Some(Value::String(s)) => s.is_empty(),
        Some(_) => false,
    }
}

/// `route_resolve.pending_gates`.
pub fn pending_gates(route: &Value) -> (Vec<String>, Vec<String>) {
    let mut gates: Vec<String> = Vec::new();
    let mut forbidden: Vec<String> = Vec::new();
    let domain = field_str(route, "domain");
    let subject = route.get("subject").cloned().unwrap_or(Value::Null);
    if domain == "medical" {
        let kind = subject.get("patient").and_then(|p| p.get("kind")).and_then(Value::as_str);
        if matches!(kind, Some("self") | Some("other-identified")) {
            gates.push("confirm-personal-medical-route".to_string());
        }
    }
    if domain == "legal" {
        if subject_str(&subject, "country").is_none() {
            gates.push("confirm-jurisdiction".to_string());
        }
        if subject_str(&subject, "area").is_none() {
            gates.push("confirm-legal-area".to_string());
        }
        if subject_str(&subject, "issue").is_none() {
            gates.push("confirm-legal-issue".to_string());
        }
        let country = subject_str(&subject, "country");
        let area = subject_str(&subject, "area");
        if country == Some("IN") && area == Some("criminal") {
            forbidden.push("skills/research/references/domains/legal/india/consumer/**".to_string());
            forbidden.push("src/lib/research-core/workflows/legal/india/consumer/**".to_string());
        }
        let operation = field_str(route, "operation");
        if country == Some("IN") && area == Some("consumer") && matches!(operation, "draft" | "procedure") {
            let required = ["pecuniary_value", "cause_of_action_date", "notice_status"];
            if required.iter().any(|key| subject_missing(&subject, key)) {
                gates.push("confirm-consumer-filing-facts".to_string());
            }
        }
    }
    let provider = field_str(route, "provider");
    let sensitivity = field_str(route, "sensitivity");
    if provider == "notebooklm" && matches!(sensitivity, "private" | "highly-sensitive") {
        gates.push("approve-notebooklm-upload".to_string());
    }
    if domain == "medical" && provider == "notebooklm" {
        gates.push("approve-notebooklm-upload".to_string());
    }
    if domain == "legal" {
        let action = subject_str(&subject, "intended_external_action").unwrap_or("").to_lowercase();
        if ["send", "sign", "file", "notarise", "notarize", "accept", "rely"].contains(&action.as_str()) {
            gates.push("approve-send-sign-file".to_string());
        }
    }
    (unique(&gates), unique(&forbidden))
}

/// `route_resolve.gate_verdicts`. `approvals` mirrors `dict[str, {'text':
/// str}] | None`: a gate counts as approved when present with a non-blank
/// `text` field.
pub fn gate_verdicts(route: &Value, approvals: Option<&Map<String, Value>>) -> Vec<Value> {
    let empty = Map::new();
    let approvals = approvals.unwrap_or(&empty);
    let mut verdicts: Vec<Value> = Vec::new();
    if let Some(Value::Array(human_gates)) = route.get("human_gates") {
        for gate in human_gates {
            let gate_str = gate.as_str().unwrap_or("");
            let approved = approvals
                .get(gate_str)
                .and_then(|entry| entry.get("text"))
                .and_then(Value::as_str)
                .map(|text| !text.trim().is_empty())
                .unwrap_or(false);
            verdicts.push(json!({"gate": gate_str, "verdict": if approved { "ok" } else { "ask" }}));
        }
    }
    let domain = field_str(route, "domain");
    let subject = route.get("subject").cloned().unwrap_or(Value::Null);
    if domain == "medical" {
        let kind = subject.get("patient").and_then(|p| p.get("kind")).and_then(Value::as_str).unwrap_or("");
        if kind == "anonymous" {
            verdicts.push(json!({"gate": "medical.anonymous-no-history", "verdict": "ok"}));
        } else if !subject
            .get("patient")
            .and_then(|p| p.get("history_available"))
            .and_then(Value::as_bool)
            .unwrap_or(false)
        {
            verdicts.push(json!({
                "gate": "medical.history-available",
                "verdict": "block",
                "reason": "personal medical route has no readable history source",
            }));
        } else {
            verdicts.push(json!({"gate": "medical.history-available", "verdict": "ok"}));
        }
    }
    if domain == "legal" {
        let missing: Vec<&str> = ["country", "area", "issue"]
            .into_iter()
            .filter(|key| subject_str(&subject, key).is_none())
            .collect();
        verdicts.push(json!({
            "gate": "legal.context-complete",
            "verdict": if missing.is_empty() { "ok" } else { "ask" },
            "missing": missing,
        }));
        if subject_str(&subject, "country") == Some("IN") && subject_str(&subject, "area") == Some("criminal") {
            let forbidden = route.get("forbidden_resources").cloned().unwrap_or_else(|| json!([]));
            verdicts.push(json!({
                "gate": "legal.criminal-consumer-isolation",
                "verdict": "ok",
                "forbidden_resources": forbidden,
            }));
        }
    }
    verdicts.push(json!({"gate": "notebooklm.answer-not-ledger", "verdict": "ok"}));
    verdicts.push(json!({"gate": "discovery.provenance", "verdict": "ok"}));
    verdicts
}

/// `route_resolve.grant_effects`. Returns `(granted_route, verdicts)`.
pub fn grant_effects(
    route: &Value,
    approvals: Option<&Map<String, Value>>,
) -> Result<(Value, Vec<Value>), String> {
    validate_route(route, Stage::Route)?;
    let verdicts = gate_verdicts(route, approvals);
    let mut granted = route.clone();
    if verdicts.iter().any(|v| v.get("verdict").and_then(Value::as_str) != Some("ok")) {
        granted["allowed_effects"] = json!(Vec::<String>::new());
        return Ok((granted, verdicts));
    }
    let mut effects: Vec<String> =
        vec!["read-local", "search", "extract", "synthesize", "write-output"].into_iter().map(String::from).collect();
    let provider = field_str(route, "provider");
    let assurance = field_str(route, "assurance");
    let domain = field_str(route, "domain");
    let scale = field_str(route, "scale");
    if matches!(provider, "browser" | "domain-default") {
        effects.push("fetch".to_string());
    }
    if matches!(assurance, "standard" | "verified") {
        effects.push("citecheck".to_string());
    }
    if assurance == "verified" {
        effects.push("retraction-check".to_string());
        effects.push("patch-sourced-draft".to_string());
    }
    let subject = route.get("subject").cloned().unwrap_or(Value::Null);
    let patient_kind = subject.get("patient").and_then(|p| p.get("kind")).and_then(Value::as_str).unwrap_or("");
    if domain == "medical" && patient_kind != "anonymous" {
        effects.push("read-sensitive".to_string());
        effects.push("load-medical-history".to_string());
    }
    if provider == "notebooklm" {
        effects.push("upload-notebooklm".to_string());
        effects.push("create-artifact".to_string());
    }
    if matches!(scale, "broad" | "dossier") {
        effects.push("spawn-worker".to_string());
    }
    granted["allowed_effects"] = json!(unique(&effects));
    Ok((granted, verdicts))
}

/// `route_resolve.validate_route`'s `stage` parameter (`'route'` or
/// `'grant'`).
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Stage {
    Route,
    Grant,
}

/// `route_resolve.validate_route`.
pub fn validate_route(route: &Value, stage: Stage) -> Result<(), String> {
    let obj = route.as_object().ok_or_else(|| "route must be an object".to_string())?;
    let required = [
        "route_version", "domain", "operation", "methods", "provider", "assurance", "scale",
        "subject", "sensitivity", "decision", "output", "allowed_effects", "human_gates",
        "forbidden_resources",
    ];
    let missing: Vec<&str> = required.into_iter().filter(|key| !obj.contains_key(*key)).collect();
    if !missing.is_empty() {
        return Err(format!("route missing keys: {missing:?}"));
    }
    if route.get("route_version").and_then(Value::as_i64) != Some(2) {
        return Err("route_version must be 2".to_string());
    }
    let domain = field_str(route, "domain");
    let operation = field_str(route, "operation");
    if !DOMAIN_VALUES.contains(&domain) || !OPERATIONS.contains(&operation) {
        return Err("invalid domain or operation".to_string());
    }
    let methods: Vec<&str> = route
        .get("methods")
        .and_then(Value::as_array)
        .map(|arr| arr.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();
    if methods.is_empty() || methods.iter().any(|m| !METHODS.contains(m)) {
        return Err(format!("invalid methods: {methods:?}"));
    }
    let provider = field_str(route, "provider");
    let assurance = field_str(route, "assurance");
    let scale = field_str(route, "scale");
    if !PROVIDERS.contains(&provider) || !ASSURANCE.contains(&assurance) || !SCALE.contains(&scale) {
        return Err("invalid provider/assurance/scale".to_string());
    }
    let sensitivity = field_str(route, "sensitivity");
    if !SENSITIVITY.contains(&sensitivity) {
        return Err("invalid sensitivity".to_string());
    }
    let decision = field_str(route, "decision");
    let output = field_str(route, "output");
    if decision.trim().is_empty() || output.trim().is_empty() {
        return Err("decision and output must be non-empty".to_string());
    }
    if domain == "medical" {
        let subject = route.get("subject").cloned().unwrap_or(Value::Null);
        let kind = subject.get("patient").and_then(|p| p.get("kind")).and_then(Value::as_str).unwrap_or("");
        if !matches!(kind, "anonymous" | "self" | "other-identified") {
            return Err("medical route requires subject.patient.kind".to_string());
        }
        if subject_str(&subject, "issue").is_none() {
            return Err("medical route requires subject.issue".to_string());
        }
    }
    if domain == "legal" && stage == Stage::Grant {
        let subject = route.get("subject").cloned().unwrap_or(Value::Null);
        let missing_legal: Vec<&str> = ["country", "area", "issue"]
            .into_iter()
            .filter(|key| subject_str(&subject, key).is_none())
            .collect();
        if !missing_legal.is_empty() {
            return Err(format!("legal route incomplete: {missing_legal:?}"));
        }
    }
    Ok(())
}

/// Convenience: build a `Context` from `(key, Value)` pairs, for callers
/// and tests that would otherwise hand-build a `serde_json::Map`.
pub fn context_from(pairs: impl IntoIterator<Item = (&'static str, Value)>) -> Context {
    let mut map: BTreeMap<&'static str, Value> = BTreeMap::new();
    for (k, v) in pairs {
        map.insert(k, v);
    }
    let mut out = Map::new();
    for (k, v) in map {
        out.insert(k.to_string(), v);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_general_route_has_no_gates_and_grants_baseline_effects() {
        let ctx = Context::new();
        let route = resolve("benchmark api latency for this service", &ctx).unwrap();
        assert_eq!(route["domain"], "technical");
        assert_eq!(route["human_gates"], json!([]));
        let (granted, verdicts) = grant_effects(&route, None).unwrap();
        assert!(verdicts.iter().all(|v| v["verdict"] == "ok"));
        let effects: Vec<String> =
            granted["allowed_effects"].as_array().unwrap().iter().map(|v| v.as_str().unwrap().to_string()).collect();
        assert!(effects.contains(&"search".to_string()));
        assert!(effects.contains(&"fetch".to_string()));
        validate_route(&granted, Stage::Grant).unwrap();
    }

    #[test]
    fn legal_route_without_context_asks_for_jurisdiction_and_area() {
        let ctx = Context::new();
        let route = resolve("please review this document about a contract dispute", &ctx).unwrap();
        assert_eq!(route["domain"], "legal");
        let gates: Vec<String> =
            route["human_gates"].as_array().unwrap().iter().map(|v| v.as_str().unwrap().to_string()).collect();
        assert!(gates.contains(&"confirm-jurisdiction".to_string()));
        let (granted, verdicts) = grant_effects(&route, None).unwrap();
        assert!(granted["allowed_effects"].as_array().unwrap().is_empty());
        assert!(verdicts.iter().any(|v| v["verdict"] != "ok"));
    }

    #[test]
    fn legal_india_criminal_forbids_consumer_workflow_paths() {
        let ctx = context_from([
            ("domain", json!("legal")),
            ("country", json!("IN")),
            ("area", json!("criminal")),
            ("issue", json!("bail application")),
        ]);
        let route = resolve("help with a criminal matter", &ctx).unwrap();
        let forbidden: Vec<String> =
            route["forbidden_resources"].as_array().unwrap().iter().map(|v| v.as_str().unwrap().to_string()).collect();
        assert!(forbidden.iter().any(|f| f.contains("consumer")));
    }

    #[test]
    fn legal_india_consumer_draft_requires_filing_facts_gate() {
        let ctx = context_from([
            ("domain", json!("legal")),
            ("operation", json!("draft")),
            ("country", json!("IN")),
            ("area", json!("consumer")),
            ("issue", json!("refund dispute")),
        ]);
        let route = resolve("draft a consumer complaint notice", &ctx).unwrap();
        let gates: Vec<String> =
            route["human_gates"].as_array().unwrap().iter().map(|v| v.as_str().unwrap().to_string()).collect();
        assert!(gates.contains(&"confirm-consumer-filing-facts".to_string()));
    }

    #[test]
    fn medical_self_route_requires_history_confirmation_and_blocks_without_source() {
        let ctx = Context::new();
        let route = resolve("what dose of a drug should i take", &ctx).unwrap();
        assert_eq!(route["domain"], "medical");
        assert_eq!(route["subject"]["patient"]["kind"], "self");
        let gates: Vec<String> =
            route["human_gates"].as_array().unwrap().iter().map(|v| v.as_str().unwrap().to_string()).collect();
        assert!(gates.contains(&"confirm-personal-medical-route".to_string()));
        let mut approvals = Map::new();
        approvals.insert(
            "confirm-personal-medical-route".to_string(),
            json!({"text": "approved by operator"}),
        );
        let verdicts = gate_verdicts(&route, Some(&approvals));
        let blocked = verdicts.iter().find(|v| v["gate"] == "medical.history-available").unwrap();
        assert_eq!(blocked["verdict"], "block");
    }

    #[test]
    fn medical_anonymous_route_grants_without_history() {
        let ctx = context_from([("patient_kind", json!("anonymous"))]);
        let route = resolve("what is a typical dose of a common drug", &ctx).unwrap();
        assert_eq!(route["subject"]["patient"]["kind"], "anonymous");
        let (granted, verdicts) = grant_effects(&route, None).unwrap();
        assert!(verdicts.iter().all(|v| v["verdict"] == "ok"));
        let effects: Vec<String> =
            granted["allowed_effects"].as_array().unwrap().iter().map(|v| v.as_str().unwrap().to_string()).collect();
        assert!(!effects.contains(&"read-sensitive".to_string()));
    }

    #[test]
    fn notebooklm_private_route_requires_upload_approval() {
        let ctx = context_from([
            ("provider", json!("notebooklm")),
            ("sensitivity", json!("private")),
        ]);
        let route = resolve("summarize my private notebooklm sources", &ctx).unwrap();
        let gates: Vec<String> =
            route["human_gates"].as_array().unwrap().iter().map(|v| v.as_str().unwrap().to_string()).collect();
        assert!(gates.contains(&"approve-notebooklm-upload".to_string()));
    }

    #[test]
    fn dossier_scale_grants_spawn_worker_effect() {
        let ctx = context_from([("scale", json!("dossier"))]);
        let route = resolve("broad landscape scan", &ctx).unwrap();
        let (granted, _verdicts) = grant_effects(&route, None).unwrap();
        let effects: Vec<String> =
            granted["allowed_effects"].as_array().unwrap().iter().map(|v| v.as_str().unwrap().to_string()).collect();
        assert!(effects.contains(&"spawn-worker".to_string()));
    }

    #[test]
    fn validate_route_rejects_missing_keys_and_bad_enum() {
        let bad = json!({"route_version": 2});
        assert!(validate_route(&bad, Stage::Route).is_err());
        let mut route = resolve("hello", &Context::new()).unwrap();
        route["domain"] = json!("not-a-domain");
        assert!(validate_route(&route, Stage::Route).is_err());
    }
}
