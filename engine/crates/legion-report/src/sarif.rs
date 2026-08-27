use legion_contracts::{Finding, ReportV1};
use serde_json::{json, Map, Value};

use crate::{
    error::{validate, ReportError},
    ordered_findings,
};

fn severity_level(severity: &str) -> &'static str {
    match severity.to_ascii_lowercase().as_str() {
        "critical" | "high" | "error" | "fatal" => "error",
        "medium" | "warning" | "warn" => "warning",
        _ => "note",
    }
}

fn location(value: &str) -> Value {
    let normalized = value.replace('\\', "/");
    let parsed = normalized.rsplit_once(':').and_then(|(path, suffix)| {
        let (start, end) = suffix.split_once('-').unwrap_or((suffix, suffix));
        let start = start.parse::<u64>().ok()?;
        let end = end.parse::<u64>().ok()?;
        (start > 0 && end >= start).then_some((path, start, end))
    });
    let (path, region) = parsed.map_or((normalized.as_str(), None), |(path, start, end)| {
        let mut region = Map::new();
        region.insert("startLine".into(), json!(start));
        if end != start {
            region.insert("endLine".into(), json!(end));
        }
        (path, Some(Value::Object(region)))
    });
    let mut physical = Map::new();
    physical.insert("artifactLocation".into(), json!({"uri": path}));
    if let Some(region) = region {
        physical.insert("region".into(), region);
    }
    json!({"physicalLocation": Value::Object(physical)})
}

fn property(finding: &Finding, key: &str) -> Option<Value> {
    finding.evidence.get(key).cloned()
}

fn result(finding: &Finding) -> Value {
    let rule_id = finding.id.to_string();
    let mut properties = Map::new();
    properties.insert("severity".into(), json!(finding.severity));
    if let Some(confidence) =
        property(finding, "confidence").or_else(|| property(finding, "evidenceStrength"))
    {
        properties.insert("confidence".into(), confidence);
    }
    if let Some(hash) = property(finding, "artifactHash")
        .or_else(|| property(finding, "artifact_hash"))
        .or_else(|| property(finding, "artifactHashes"))
        .or_else(|| property(finding, "artifact_hashes"))
        .or_else(|| property(finding, "hash"))
    {
        properties.insert("artifactHash".into(), hash);
    }
    if let Some(provider) = &finding.provider {
        properties.insert("provider".into(), json!(provider));
    }
    properties.insert("evidence".into(), json!(finding.evidence));
    json!({
        "ruleId": rule_id,
        "level": severity_level(&finding.severity),
        "message": {"text": format!("{}: {}", finding.title, finding.message)},
        "locations": finding.locations.iter().map(|value| location(value)).collect::<Vec<_>>(),
        "partialFingerprints": {"legionFinding/v1": finding.id.to_string()},
        "properties": Value::Object(properties)
    })
}

pub fn render(report: &ReportV1) -> Result<String, ReportError> {
    validate(report)?;
    let ordered = ordered_findings(report)
        .into_iter()
        .map(result)
        .collect::<Vec<_>>();
    let rules = ordered_findings(report)
        .into_iter()
        .map(|finding| {
            json!({
                "id": finding.id.to_string(),
                "name": finding.title,
                "shortDescription": {"text": finding.message},
                "defaultConfiguration": {"level": severity_level(&finding.severity)}
            })
        })
        .collect::<Vec<_>>();
    let value = json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "Legion", "informationUri": "https://github.com/Orthic-Labs/legion", "rules": rules}},
            "results": ordered,
            "properties": {"schemaVersion": report.schema_version, "reportId": report.report_id, "status": report.status, "gaps": report.gaps, "targets": report.targets, "claims": report.claims}
        }]
    });
    Ok(format!("{}\n", serde_json::to_string_pretty(&value)?))
}

pub fn to_sarif(report: &ReportV1) -> Result<String, ReportError> {
    render(report)
}
