//! Port of `src/lib/report/sarif/index.mjs` / `scripts/report-to-sarif.mjs`
//! (chunk wf022, area `src/lib/report`, target crate `legion-audit`).
//!
//! The JS source is an *untyped* projection: it walks a plain JSON report
//! object (`report.findings`, `report.security.attackPaths.proven`, ...)
//! and emits a SARIF 2.1.0 document. There is already a native SARIF
//! renderer in `legion-report::sarif` (`ReportV1` / `Finding`), but it
//! operates on a different, typed data model and does not cover:
//!   - the `security.attackPaths.proven` -> extra SARIF results projection
//!   - the `report.plan.seal.{digest,signature}` run properties
//!   - the `report.audit_status` / `report.quality_gate` / `incomplete` /
//!     `generated_at` run properties
//!   - the full `TOOL` identity block (fullName/organization/semanticVersion)
//!
//! This module ports the JS behaviour byte-for-byte against the same loose
//! JSON shape (`serde_json::Value`) so callers that still hold report JSON
//! (rather than a typed `ReportV1`) get an equivalent SARIF document.
//!
//! DROP: the JS source also emits `blueprintGeneration:
//! report?.blueprint?.generationId ?? null` in the run `properties`.
//! Blueprint is moving to another product per project policy, so that
//! field is intentionally omitted here.

use serde_json::{json, Map, Value};

/// Canonical product identity for every machine output emitted by this
/// projection. Mirrors the frozen `TOOL` constant in the JS source.
struct ToolIdentity {
    name: &'static str,
    full_name: &'static str,
    organization: &'static str,
    information_uri: &'static str,
}

const TOOL: ToolIdentity = ToolIdentity {
    name: "Legion",
    full_name: "Orthic Labs Legion",
    organization: "Orthic Labs",
    information_uri: "https://github.com/Orthic-Labs/legion",
};

fn level_for_severity(severity: Option<&str>) -> &'static str {
    match severity {
        Some("critical") | Some("high") => "error",
        Some("medium") => "warning",
        Some("low") | Some("info") => "note",
        _ => "warning",
    }
}

/// Same replacement JS performs with `replaceAll(/[^A-Za-z0-9]+/g, '_')`.
fn sanitize_rule_name(rule_id: &str) -> String {
    let mut out = String::with_capacity(rule_id.len());
    let mut last_was_sub = false;
    for ch in rule_id.chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch);
            last_was_sub = false;
        } else if !last_was_sub {
            out.push('_');
            last_was_sub = true;
        }
    }
    out
}

fn as_str<'a>(value: &'a Value, key: &str) -> Option<&'a str> {
    value.get(key).and_then(Value::as_str)
}

fn as_line(value: &Value, key: &str) -> Option<i64> {
    match value.get(key) {
        Some(Value::Number(n)) => n.as_i64(),
        Some(Value::String(s)) => s.parse::<i64>().ok(),
        _ => None,
    }
}

/// Mirrors `locationFor(finding)` in the JS source: builds the
/// `locations` array for a finding-shaped object carrying `file`/`line`.
fn location_for(value: &Value) -> Vec<Value> {
    let file = match as_str(value, "file") {
        Some(f) if !f.is_empty() => f,
        _ => return Vec::new(),
    };
    let uri = file.replace('\\', "/");
    let line = as_line(value, "line").filter(|l| *l > 0).unwrap_or(1);
    vec![json!({
        "physicalLocation": {
            "artifactLocation": {"uri": uri},
            "region": {"startLine": line},
        }
    })]
}

fn first_of<'a>(value: &'a Value, keys: &[&str]) -> Option<&'a Value> {
    for key in keys {
        if let Some(v) = value.get(*key) {
            if !v.is_null() {
                return Some(v);
            }
        }
    }
    None
}

/// Port of `reportToSarif(report)`.
pub fn render_sarif_report(report: &Value) -> Value {
    let empty_vec: Vec<Value> = Vec::new();
    let findings = report
        .get("findings")
        .and_then(Value::as_array)
        .unwrap_or(&empty_vec);
    let security = report.get("security").cloned().unwrap_or(Value::Null);
    let attack_paths = security
        .get("attackPaths")
        .and_then(|ap| ap.get("proven"))
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();

    // Preserve insertion order of first appearance, like the JS `Map`.
    let mut rule_order: Vec<String> = Vec::new();
    let mut rules: Map<String, Value> = Map::new();
    let mut results: Vec<Value> = Vec::new();

    for finding in findings {
        let rule_id = first_of(finding, &["ruleId", "category", "subtype"])
            .and_then(Value::as_str)
            .map(str::to_string)
            .unwrap_or_else(|| "audit-finding".to_string());

        let severity = as_str(finding, "severity");
        let level = level_for_severity(severity);

        if !rules.contains_key(&rule_id) {
            let category = as_str(finding, "category");
            let short_description = category
                .map(|c| format!("Audit {c} finding"))
                .unwrap_or_else(|| "Audit finding".to_string());
            rules.insert(
                rule_id.clone(),
                json!({
                    "id": rule_id,
                    "name": sanitize_rule_name(&rule_id),
                    "shortDescription": {"text": short_description},
                    "defaultConfiguration": {"level": level},
                    "properties": {"category": category},
                }),
            );
            rule_order.push(rule_id.clone());
        }

        let mut properties = Map::new();
        properties.insert("severity".into(), finding.get("severity").cloned().unwrap_or(Value::Null));
        properties.insert(
            "evidenceStrength".into(),
            first_of(finding, &["evidence_strength", "evidenceStrength"]).cloned().unwrap_or(Value::Null),
        );
        properties.insert("judgment".into(), finding.get("judgment").cloned().unwrap_or(Value::Null));
        properties.insert("status".into(), finding.get("status").cloned().unwrap_or(Value::Null));
        properties.insert("tier".into(), finding.get("tier").cloned().unwrap_or(Value::Null));
        properties.insert("evidence".into(), finding.get("evidence").cloned().unwrap_or(Value::Null));
        properties.insert("action".into(), finding.get("action").cloned().unwrap_or(Value::Null));
        properties.insert(
            "sources".into(),
            finding.get("sources").cloned().unwrap_or_else(|| json!([])),
        );
        if let Some(candidate_id) = finding.get("candidateId") {
            if !candidate_id.is_null() {
                properties.insert("candidateId".into(), candidate_id.clone());
            }
        }
        if let Some(rcd) = first_of(finding, &["rootCauseDigest", "rootCauseSignature"]) {
            properties.insert("rootCauseDigest".into(), rcd.clone());
        }
        if let Some(vrid) = finding.get("variantReceiptId") {
            if !vrid.is_null() {
                properties.insert("variantReceiptId".into(), vrid.clone());
            }
        }
        if let Some(related) = finding.get("relatedAttackPathIds").and_then(Value::as_array) {
            if !related.is_empty() {
                properties.insert("relatedAttackPathIds".into(), Value::Array(related.clone()));
            }
        }

        let title = as_str(finding, "title");
        let detail = as_str(finding, "detail");
        let message = match (title, detail) {
            (Some(t), Some(d)) if !d.is_empty() => format!("{t} — {d}"),
            (Some(t), _) => t.to_string(),
            (None, _) => detail.unwrap_or("Audit finding").to_string(),
        };

        let id_fp = first_of(finding, &["id", "candidateId", "ruleId"])
            .map(value_to_string)
            .unwrap_or_default();
        let mut fingerprints = Map::new();
        fingerprints.insert("legionFinding/v1".into(), json!(id_fp));
        if let Some(rcd) = first_of(finding, &["rootCauseDigest", "rootCauseSignature"]) {
            fingerprints.insert("legionRootCause/v1".into(), json!(value_to_string(rcd)));
        }

        results.push(json!({
            "ruleId": rule_id,
            "level": level,
            "message": {"text": message},
            "locations": location_for(finding),
            "partialFingerprints": Value::Object(fingerprints),
            "properties": Value::Object(properties),
        }));
    }

    for path in &attack_paths {
        let objective_id = path
            .get("objective")
            .and_then(|o| o.get("id"))
            .and_then(Value::as_str)
            .unwrap_or("proven-path");
        let rule_id = format!("security.attack-path.{objective_id}");
        let severity = as_str(path, "severity");
        let level = if severity.is_some() {
            level_for_severity(severity)
        } else {
            "error"
        };

        if !rules.contains_key(&rule_id) {
            rules.insert(
                rule_id.clone(),
                json!({
                    "id": rule_id,
                    "name": sanitize_rule_name(&rule_id),
                    "shortDescription": {"text": "Proven attack path"},
                    "defaultConfiguration": {"level": level},
                    "properties": {"category": "security-attack-path"},
                }),
            );
            rule_order.push(rule_id.clone());
        }

        let empty_steps: Vec<Value> = Vec::new();
        let steps = path
            .get("stepAssessments")
            .and_then(Value::as_array)
            .unwrap_or(&empty_steps);
        let thread_flow: Vec<Value> = steps
            .iter()
            .enumerate()
            .filter_map(|(index, step)| {
                let file = as_str(step, "file")?;
                let loc = location_for(&json!({"file": file, "line": step.get("line")}));
                let location = loc.into_iter().next()?;
                Some(json!({"order": index, "location": location}))
            })
            .collect();

        let path_id = first_of(path, &["id", "pathId"])
            .map(value_to_string)
            .unwrap_or_default();

        let mut result = Map::new();
        result.insert("ruleId".into(), json!(rule_id));
        result.insert("level".into(), json!(level));
        result.insert(
            "message".into(),
            json!({"text": format!(
                "Proven attack path: {} ({})",
                objective_id,
                severity.unwrap_or("unknown")
            )}),
        );
        let locations = if let Some(first) = thread_flow.first() {
            vec![first.get("location").cloned().unwrap_or(Value::Null)]
        } else {
            Vec::new()
        };
        result.insert("locations".into(), Value::Array(locations));
        result.insert(
            "partialFingerprints".into(),
            json!({"legionPath/v1": path_id}),
        );
        if !thread_flow.is_empty() {
            result.insert(
                "codeFlows".into(),
                json!([{"threadFlows": [{"id": format!("path-{path_id}"), "locations": thread_flow}]}]),
            );
        }
        result.insert(
            "properties".into(),
            json!({
                "pathId": first_of(path, &["id", "pathId"]).cloned().unwrap_or(Value::Null),
                "constituentFindingIds": path.get("constituentFindingIds").cloned().unwrap_or_else(|| json!([])),
                "start": path.get("start").cloned().unwrap_or(Value::Null),
                "objective": path.get("objective").cloned().unwrap_or(Value::Null),
                "proofDigest": path.get("proof").and_then(|p| p.get("digest")).cloned().unwrap_or(Value::Null),
            }),
        );
        results.push(Value::Object(result));
    }

    let ordered_rules: Vec<Value> = {
        // JS sorts rules by id before emitting (`[...rules.values()].sort(...)`).
        let mut ids: Vec<&String> = rule_order.iter().collect();
        ids.sort();
        ids.into_iter()
            .map(|id| rules.get(id).cloned().unwrap_or(Value::Null))
            .collect()
    };

    let semantic_version = first_of(report, &["tool", "legionVersion"])
        .and_then(|t| {
            if let Some(obj) = t.as_object() {
                obj.get("version").and_then(Value::as_str)
            } else {
                t.as_str()
            }
        })
        .map(str::to_string)
        .or_else(|| {
            report
                .get("legionVersion")
                .and_then(Value::as_str)
                .map(str::to_string)
        })
        .unwrap_or_else(|| "0.0.0-dev".to_string());

    let automation_details = report.get("commit").and_then(Value::as_str).map(|c| {
        json!({"id": c.to_string()})
    });

    let mut run = Map::new();
    run.insert(
        "tool".into(),
        json!({
            "driver": {
                "name": TOOL.name,
                "fullName": TOOL.full_name,
                "organization": TOOL.organization,
                "informationUri": TOOL.information_uri,
                "semanticVersion": semantic_version,
                "rules": ordered_rules,
            }
        }),
    );
    if let Some(automation) = automation_details {
        run.insert("automationDetails".into(), automation);
    }
    run.insert("results".into(), Value::Array(results));
    run.insert(
        "properties".into(),
        json!({
            "auditStatus": first_of(report, &["audit_status", "auditStatus"]).cloned().unwrap_or(Value::Null),
            "qualityGate": first_of(report, &["quality_gate", "qualityGate"]).cloned().unwrap_or(Value::Null),
            "incomplete": report.get("incomplete").and_then(Value::as_bool).unwrap_or(false),
            "generatedAt": first_of(report, &["generated_at", "generatedAt"]).cloned().unwrap_or(Value::Null),
            "planSeal": report.get("plan").and_then(|p| p.get("seal")).and_then(|s| s.get("digest")).cloned().unwrap_or(Value::Null),
            "planSignature": report.get("plan").and_then(|p| p.get("seal")).and_then(|s| s.get("signature")).cloned().unwrap_or(Value::Null),
            // Blueprint is moving to another product; dropped by project policy.
        }),
    );

    json!({
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [Value::Object(run)],
    })
}

fn value_to_string(value: &Value) -> String {
    match value {
        Value::String(s) => s.clone(),
        Value::Number(n) => n.to_string(),
        Value::Null => String::new(),
        other => other.to_string(),
    }
}
