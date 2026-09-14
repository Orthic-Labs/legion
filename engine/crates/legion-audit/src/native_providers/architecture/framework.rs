use super::{
    common::{gap, object_input, Analysis},
    evidence::validate_refs,
};
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
        serde_json::json!({"kind":format!("{name}-routes"),"expected":routes.len(),"examined":qualified}),
    );
    result
        .extras
        .insert("routes".into(), Value::Array(normalized));
    result.coverage_gaps = gaps;
    Ok(result)
}

pub fn analyze_frontend_framework(
    name: &str,
    input: &Value,
    authority: &Value,
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
                && validate_refs(row.get("evidenceRefs"), authority).is_empty()
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
    Ok(output)
}
pub fn analyze_frontend(input: &Value) -> Result<Analysis, String> {
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
        let result = analyze_frontend_framework(name, record, &authority)?;
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
