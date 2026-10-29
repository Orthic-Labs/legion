use super::{
    common::{gap, object_input, Analysis},
    evidence::{limit_runtime_evidence, validate_refs},
};
use crate::artifact_evidence::{ObservationKind, ObservationVerdict};
use serde_json::Value;

const BACKEND: &[&str] = &[
    "express",
    "fastify",
    "nest",
    "django",
    "fastapi",
    "flask",
    "spring",
    "ktor",
    "aspnet",
    "rails",
    "laravel",
    "go-router",
    "rust-web",
];
const FRONTEND: &[&str] = &[
    "react", "next", "vue", "nuxt", "angular", "svelte", "astro", "remix",
];

pub fn analyze_backend_framework(
    name: &str,
    input: &Value,
    authority: &Value,
) -> Result<Analysis, String> {
    let object = object_input(input)?;
    if !BACKEND.contains(&name) {
        let mut result = Analysis::new("unproven", false, Value::Null);
        result.include_findings = false;
        result
            .extras
            .insert("routes".into(), Value::Array(Vec::new()));
        result.coverage_gaps.push(gap("unsupported-framework"));
        limit_runtime_evidence(&mut result);
        return Ok(result);
    }
    let routes = object
        .get("routes")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let mut normalized = Vec::new();
    let mut qualified = 0;
    let mut gaps = Vec::new();
    if routes.is_empty() {
        gaps.push(gap("route-denominator-gap"));
    }
    for route in routes.iter() {
        let mut row = object_input(route)?.clone();
        if !row.contains_key("auth") || row["auth"].is_null() {
            row.insert("auth".into(), Value::String("unknown".into()));
        }
        if row
            .get("path")
            .is_some_and(|value| super::common::truthy(Some(value)))
            && validate_refs(row.get("evidenceRefs"), authority).is_empty()
        {
            qualified += 1;
        }
        normalized.push(Value::Object(row));
    }
    if qualified != routes.len() {
        gaps.push(gap("route-evidence-gap"));
    }
    if normalized.iter().any(|row| row["auth"] == "unknown") {
        gaps.push(gap("route-auth-unknown"));
    }
    let mut result = Analysis::new(
        if gaps.is_empty() {
            "measured"
        } else {
            "unproven"
        },
        gaps.is_empty(),
        serde_json::json!({"kind":format!("{name}-routes"),"expected":routes.len(),"examined":0}),
    );
    result
        .extras
        .insert("routes".into(), Value::Array(normalized));
    result.coverage_gaps = gaps;
    result.extras.insert("protocolValidation".into(), serde_json::json!({
        "scope":"caller-supplied-values-and-reference-metadata", "expected":routes.len(), "examined":qualified
    }));
    limit_runtime_evidence(&mut result);
    Ok(result)
}

pub fn analyze_frontend_framework(
    name: &str,
    input: &Value,
    authority: &Value,
) -> Result<Analysis, String> {
    analyze_frontend_framework_with_source(name, input, authority, None)
}

fn analyze_frontend_framework_with_source(
    name: &str,
    input: &Value,
    authority: &Value,
    source: Option<&super::evidence::NativeSourceEvidence<'_>>,
) -> Result<Analysis, String> {
    let object = object_input(input)?;
    if !FRONTEND.contains(&name) {
        let mut result = Analysis::new(
            "unproven",
            false,
            serde_json::json!({"kind":format!("{name}-unsupported"),"expected":0}),
        );
        result.include_findings = false;
        result.coverage_gaps.push(gap("unsupported-framework"));
        return Ok(result);
    }
    let subjects = object
        .get("components")
        .or_else(|| object.get("routes"))
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let mut qualified = Vec::new();
    let mut gaps = Vec::new();
    if subjects.is_empty() {
        gaps.push(gap("denominator-gap"));
    }
    for item in &subjects {
        if let Ok(row) = object_input(item) {
            if row
                .get("path")
                .is_some_and(|value| super::common::truthy(Some(value)))
                && match source {
                    Some(source) => source.validate_observation(row).is_empty(),
                    None => validate_refs(row.get("evidenceRefs"), authority).is_empty(),
                }
            {
                qualified.push(item.clone());
            }
        }
    }
    if qualified.len() != subjects.len() {
        gaps.push(gap("framework-evidence-gap"));
    }
    let mut result = Analysis::new(
        if gaps.is_empty() {
            "measured"
        } else {
            "unproven"
        },
        gaps.is_empty(),
        serde_json::json!({"kind":format!("{name}-components"),"expected":subjects.len(),"examined":qualified.len()}),
    );
    result
        .extras
        .insert("subjects".into(), Value::Array(qualified));
    result.coverage_gaps = gaps;
    Ok(result)
}

pub fn analyze_backend(input: &Value) -> Result<Analysis, String> {
    let object = object_input(input)?;
    let records = object
        .get("artifacts")
        .and_then(|v| v.get("backendFrameworks"))
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let authority = super::evidence::authority(
        object.get("plan"),
        object.get("artifacts"),
        object.get("root"),
        object.get("now").and_then(Value::as_str),
    );
    let mut gaps = Vec::new();
    let mut expected = 0;
    let mut examined = 0;
    let mut protocol_examined = 0;
    for record in &records {
        let name = record.get("name").and_then(Value::as_str).unwrap_or("");
        let result = analyze_backend_framework(name, record, &authority)?;
        expected += result
            .denominator
            .get("expected")
            .and_then(Value::as_u64)
            .unwrap_or(0) as usize;
        examined += result
            .denominator
            .get("examined")
            .and_then(Value::as_u64)
            .unwrap_or(0) as usize;
        protocol_examined += result
            .extras
            .get("protocolValidation")
            .and_then(|value| value.get("examined"))
            .and_then(Value::as_u64)
            .unwrap_or(0) as usize;
        gaps.extend(result.coverage_gaps);
    }
    if records.is_empty() {
        gaps.push(gap("backend-framework-denominator-zero"));
    }
    let mut output = Analysis::new(
        if gaps.is_empty() { "pass" } else { "unproven" },
        gaps.is_empty(),
        serde_json::json!({"kind":"backend-framework-routes","expected":expected,"examined":examined}),
    );
    output.coverage_gaps = gaps;
    output.extras.insert("protocolValidation".into(), serde_json::json!({
        "scope":"caller-supplied-values-and-reference-metadata", "expected":expected, "examined":protocol_examined
    }));
    limit_runtime_evidence(&mut output);
    Ok(output)
}
pub fn analyze_frontend(input: &Value) -> Result<Analysis, String> {
    analyze_frontend_with_source(input, None)
}

pub(super) fn analyze_frontend_with_source(
    input: &Value,
    source: Option<&super::evidence::NativeSourceEvidence<'_>>,
) -> Result<Analysis, String> {
    let object = object_input(input)?;
    let records = object
        .get("artifacts")
        .and_then(|v| v.get("frontendFrameworks"))
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let authority = super::evidence::authority(
        object.get("plan"),
        object.get("artifacts"),
        object.get("root"),
        object.get("now").and_then(Value::as_str),
    );
    let mut gaps = Vec::new();
    let mut complete = 0;
    for record in &records {
        let name = record.get("name").and_then(Value::as_str).unwrap_or("");
        let result = analyze_frontend_framework_with_source(name, record, &authority, source)?;
        if result.complete {
            complete += 1;
        }
        gaps.extend(result.coverage_gaps);
    }
    if records.is_empty() {
        gaps.push(gap("frontend-framework-denominator-zero"));
    }
    let mut output = Analysis::new(
        if gaps.is_empty() { "pass" } else { "unproven" },
        gaps.is_empty(),
        serde_json::json!({"kind":"frontend-frameworks","expected":records.len(),"examined":complete}),
    );
    output.coverage_gaps = gaps;
    Ok(output)
}

/// Fold verified backend authentication probe observations into the
/// source-fact analysis. Satisfies exactly the plan-named probes against the
/// bound deployed artifact and configuration; the analysis stays unproven
/// (`certificationClaim:false`), because source facts plus named probes are
/// never general authentication correctness. A rejected observation or an
/// unsatisfied probe adds a named gap/finding. No verdict: unchanged.
pub fn apply_backend_observations(analysis: &mut Analysis, verdicts: &[ObservationVerdict]) {
    let summary = super::compatibility::summarize_observations(
        ObservationKind::BackendAuthProbe,
        "backend-auth-probe-failed",
        verdicts,
    );
    if !summary.any {
        return;
    }
    analysis.findings.extend(summary.findings);
    for gap in summary.gaps {
        if !analysis.coverage_gaps.contains(&gap) {
            analysis.coverage_gaps.push(gap);
        }
    }
    analysis.extras.insert(
        "authProbeObservations".into(),
        Value::Array(summary.verified),
    );
    analysis.extras.insert(
        "runtimeObservationScope".into(),
        Value::String("named-probes-only".into()),
    );
    analysis
        .extras
        .insert("certificationClaim".into(), Value::Bool(false));
    analysis.status = "unproven".into();
    analysis.complete = false;
}
