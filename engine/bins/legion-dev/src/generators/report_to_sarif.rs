//! Port of `scripts/report-to-sarif.mjs`.

use serde_json::{json, Map, Value};
use std::fs;
use std::path::Path;

fn level_for(severity: Option<&str>) -> &'static str {
    match severity {
        Some("critical") | Some("high") => "error",
        Some("medium") => "warning",
        Some("low") | Some("info") => "note",
        _ => "warning",
    }
}

fn location_for(file: Option<&str>, line: Option<i64>) -> Vec<Value> {
    let file = match file {
        Some(f) if !f.is_empty() => f,
        _ => return vec![],
    };
    let line = line.filter(|l| *l > 0).unwrap_or(1);
    vec![json!({
        "physicalLocation": {
            "artifactLocation": { "uri": file.replace('\\', "/") },
            "region": { "startLine": line },
        }
    })]
}

fn sanitize_rule_name(rule_id: &str) -> String {
    rule_id
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect::<String>()
        // collapse consecutive replacement runs the way `[^A-Za-z0-9]+` does
        .split('_')
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>()
        .join("_")
}

/// Faithful port of `reportToSarif(report)`.
pub fn report_to_sarif(report: &Value) -> Value {
    let findings: Vec<Value> = report.get("findings").and_then(Value::as_array).cloned().unwrap_or_default();
    let attack_paths: Vec<Value> = report
        .get("security")
        .and_then(|s| s.get("attackPaths"))
        .and_then(|a| a.get("proven"))
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();

    let mut rules: std::collections::BTreeMap<String, Value> = std::collections::BTreeMap::new();
    let mut results = Vec::new();

    for finding in &findings {
        let rule_id = finding
            .get("ruleId")
            .or_else(|| finding.get("category"))
            .or_else(|| finding.get("subtype"))
            .and_then(Value::as_str)
            .unwrap_or("audit-finding")
            .to_string();
        let severity = finding.get("severity").and_then(Value::as_str);
        rules.entry(rule_id.clone()).or_insert_with(|| {
            let category = finding.get("category").and_then(Value::as_str);
            json!({
                "id": rule_id,
                "name": sanitize_rule_name(&rule_id),
                "shortDescription": { "text": category.map(|c| format!("Audit {c} finding")).unwrap_or_else(|| "Audit finding".to_string()) },
                "defaultConfiguration": { "level": level_for(severity) },
                "properties": { "category": category },
            })
        });

        let mut properties = Map::new();
        properties.insert("severity".into(), finding.get("severity").cloned().unwrap_or(Value::Null));
        properties.insert(
            "evidenceStrength".into(),
            finding
                .get("evidence_strength")
                .or_else(|| finding.get("evidenceStrength"))
                .cloned()
                .unwrap_or(Value::Null),
        );
        properties.insert("judgment".into(), finding.get("judgment").cloned().unwrap_or(Value::Null));
        properties.insert("status".into(), finding.get("status").cloned().unwrap_or(Value::Null));
        properties.insert("tier".into(), finding.get("tier").cloned().unwrap_or(Value::Null));
        properties.insert("evidence".into(), finding.get("evidence").cloned().unwrap_or(Value::Null));
        properties.insert("action".into(), finding.get("action").cloned().unwrap_or(Value::Null));
        properties.insert("sources".into(), finding.get("sources").cloned().unwrap_or(Value::Array(vec![])));
        if let Some(cid) = finding.get("candidateId").filter(|v| !v.is_null()) {
            properties.insert("candidateId".into(), cid.clone());
        }
        let root_cause = finding.get("rootCauseDigest").filter(|v| !v.is_null()).or_else(|| finding.get("rootCauseSignature").filter(|v| !v.is_null()));
        if let Some(rc) = root_cause {
            properties.insert("rootCauseDigest".into(), rc.clone());
        }
        if let Some(v) = finding.get("variantReceiptId").filter(|v| !v.is_null()) {
            properties.insert("variantReceiptId".into(), v.clone());
        }
        let related = finding.get("relatedAttackPathIds").and_then(Value::as_array).filter(|a| !a.is_empty());
        if let Some(r) = related {
            properties.insert("relatedAttackPathIds".into(), Value::Array(r.clone()));
        }

        let title = finding.get("title").and_then(Value::as_str);
        let detail = finding.get("detail").and_then(Value::as_str);
        let message_text = match title {
            Some(t) => match detail {
                Some(d) => format!("{t} — {d}"),
                None => t.to_string(),
            },
            None => detail.unwrap_or("Audit finding").to_string(),
        };

        let file = finding.get("file").and_then(Value::as_str);
        let line = finding.get("line").and_then(|v| v.as_i64().or_else(|| v.as_f64().map(|f| f as i64)));

        let mut fingerprints = Map::new();
        let fp_id = finding
            .get("id")
            .or_else(|| finding.get("candidateId"))
            .cloned()
            .unwrap_or_else(|| Value::from(rule_id.clone()));
        fingerprints.insert("legionFinding/v1".into(), Value::from(value_to_string(&fp_id)));
        if let Some(rc) = finding.get("rootCauseDigest").filter(|v| !v.is_null()).or_else(|| finding.get("rootCauseSignature").filter(|v| !v.is_null())) {
            fingerprints.insert("legionRootCause/v1".into(), Value::from(value_to_string(rc)));
        }

        results.push(json!({
            "ruleId": rule_id,
            "level": level_for(severity),
            "message": { "text": message_text },
            "locations": location_for(file, line),
            "partialFingerprints": Value::Object(fingerprints),
            "properties": Value::Object(properties),
        }));
    }

    for path in &attack_paths {
        let objective_id = path.get("objective").and_then(|o| o.get("id")).and_then(Value::as_str).unwrap_or("proven-path");
        let rule_id = format!("security.attack-path.{objective_id}");
        let severity = path.get("severity").and_then(Value::as_str);
        rules.entry(rule_id.clone()).or_insert_with(|| {
            json!({
                "id": rule_id,
                "name": sanitize_rule_name(&rule_id),
                "shortDescription": { "text": "Proven attack path" },
                "defaultConfiguration": { "level": if severity.is_some() { level_for(severity) } else { "error" } },
                "properties": { "category": "security-attack-path" },
            })
        });

        let step_assessments = path.get("stepAssessments").and_then(Value::as_array).cloned().unwrap_or_default();
        let thread_flow: Vec<Value> = step_assessments
            .iter()
            .enumerate()
            .filter_map(|(index, step)| {
                let file = step.get("file").and_then(Value::as_str);
                let line = step.get("line").and_then(|v| v.as_i64());
                let loc = location_for(file, line);
                loc.into_iter().next().map(|location| json!({ "order": index, "location": location }))
            })
            .collect();

        let path_id = path.get("id").or_else(|| path.get("pathId")).cloned().unwrap_or(Value::Null);
        let mut result = Map::new();
        result.insert("ruleId".into(), Value::from(rule_id));
        result.insert("level".into(), Value::from(if severity.is_some() { level_for(severity) } else { "error" }));
        let severity_label = severity.unwrap_or("unknown");
        result.insert(
            "message".into(),
            json!({ "text": format!("Proven attack path: {} ({})", objective_id_or_empty(path), severity_label) }),
        );
        let locations = thread_flow.first().map(|t| vec![t["location"].clone()]).unwrap_or_default();
        result.insert("locations".into(), Value::Array(locations));
        let mut fp = Map::new();
        fp.insert("legionPath/v1".into(), Value::from(value_to_string(&path_id)));
        result.insert("partialFingerprints".into(), Value::Object(fp));
        if !thread_flow.is_empty() {
            result.insert(
                "codeFlows".into(),
                json!([{ "threadFlows": [{ "id": format!("path-{}", value_to_string(&path_id)), "locations": thread_flow }] }]),
            );
        }
        result.insert(
            "properties".into(),
            json!({
                "pathId": path_id,
                "constituentFindingIds": path.get("constituentFindingIds").cloned().unwrap_or(Value::Array(vec![])),
                "start": path.get("start").cloned().unwrap_or(Value::Null),
                "objective": path.get("objective").cloned().unwrap_or(Value::Null),
                "proofDigest": path.get("proof").and_then(|p| p.get("digest")).cloned().unwrap_or(Value::Null),
            }),
        );
        results.push(Value::Object(result));
    }

    let mut sorted_rules: Vec<Value> = rules.into_values().collect();
    sorted_rules.sort_by(|a, b| a["id"].as_str().unwrap_or_default().cmp(b["id"].as_str().unwrap_or_default()));

    let semantic_version = report
        .get("tool")
        .and_then(|t| t.get("version"))
        .or_else(|| report.get("legionVersion"))
        .cloned()
        .unwrap_or_else(|| Value::from("0.0.0-dev"));

    let mut driver = Map::new();
    driver.insert("name".into(), Value::from("Legion"));
    driver.insert("fullName".into(), Value::from("Orthic Labs Legion"));
    driver.insert("organization".into(), Value::from("Orthic Labs"));
    driver.insert("informationUri".into(), Value::from("https://github.com/Orthic-Labs/legion"));
    driver.insert("semanticVersion".into(), semantic_version);
    driver.insert("rules".into(), Value::Array(sorted_rules));

    let mut run = Map::new();
    run.insert("tool".into(), json!({ "driver": Value::Object(driver) }));
    if let Some(commit) = report.get("commit").filter(|v| !v.is_null()) {
        run.insert("automationDetails".into(), json!({ "id": value_to_string(commit) }));
    }
    run.insert("results".into(), Value::Array(results));
    run.insert(
        "properties".into(),
        json!({
            "auditStatus": report.get("audit_status").or_else(|| report.get("auditStatus")).cloned().unwrap_or(Value::Null),
            "qualityGate": report.get("quality_gate").or_else(|| report.get("qualityGate")).cloned().unwrap_or(Value::Null),
            "incomplete": report.get("incomplete").and_then(Value::as_bool).unwrap_or(false),
            "generatedAt": report.get("generated_at").or_else(|| report.get("generatedAt")).cloned().unwrap_or(Value::Null),
            "planSeal": report.get("plan").and_then(|p| p.get("seal")).and_then(|s| s.get("digest")).cloned().unwrap_or(Value::Null),
            "planSignature": report.get("plan").and_then(|p| p.get("seal")).and_then(|s| s.get("signature")).cloned().unwrap_or(Value::Null),
            "blueprintGeneration": report.get("blueprint").and_then(|b| b.get("generationId")).cloned().unwrap_or(Value::Null),
        }),
    );

    json!({
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [Value::Object(run)],
    })
}

fn objective_id_or_empty(path: &Value) -> String {
    path.get("objective").and_then(|o| o.get("id")).and_then(Value::as_str).unwrap_or("").to_string()
}

fn value_to_string(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Null => "null".to_string(),
        other => other.to_string(),
    }
}

/// `legion-dev report-to-sarif --report PATH [--out PATH]`
pub fn run(report_path: &Path, out_path: Option<&Path>) -> bool {
    let out_path = match out_path {
        Some(p) => p,
        None => {
            eprintln!("usage: report-to-sarif.mjs --report report.json --out report.sarif");
            return false;
        }
    };
    let text = match fs::read_to_string(report_path) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("report-to-sarif: {}: {e}", report_path.display());
            return false;
        }
    };
    let report: Value = match serde_json::from_str(&text) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("report-to-sarif: {}: {e}", report_path.display());
            return false;
        }
    };
    let sarif = report_to_sarif(&report);
    let rendered = format!("{}\n", serde_json::to_string_pretty(&sarif).unwrap());
    if let Err(e) = fs::write(out_path, rendered) {
        eprintln!("report-to-sarif: {e}");
        return false;
    }
    println!("{}", out_path.display());
    true
}
