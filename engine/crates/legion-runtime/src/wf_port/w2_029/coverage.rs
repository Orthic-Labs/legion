//! Port of `skills/seo/scripts/coverage.py`.
//!
//! Calculates SEO audit evidence coverage without hiding unknowns in a
//! weighted score. N/A is excluded only with an explicit rationale.
//! Not-testable remains in the applicable denominator and therefore
//! reduces evidence coverage. Critical gates are reported separately and
//! may not be averaged away — same rules as the Python source.

use std::collections::BTreeMap;

use serde::Serialize;
use serde_json::Value;

const STATUSES: &[&str] = &["pass", "partial", "fail", "na", "not_testable"];

/// Mirrors Python `rows(payload)`: accepts a JSON array, or an object with
/// a `controls` array. Anything else is an error.
pub fn rows(payload: &Value) -> Result<Vec<Value>, String> {
    if let Value::Array(a) = payload {
        return Ok(a.clone());
    }
    if let Value::Object(o) = payload {
        if let Some(Value::Array(a)) = o.get("controls") {
            return Ok(a.clone());
        }
    }
    Err("input must be list or object with controls[]".to_string())
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct CoverageResult {
    pub status: String,
    pub counts: BTreeMap<String, i64>,
    pub total_controls: usize,
    pub applicable_controls: i64,
    pub tested_controls: i64,
    pub evidence_coverage: f64,
    pub critical_gate: String,
    pub critical_failures: Vec<String>,
    pub critical_unknown: Vec<String>,
    pub partial_controls: Vec<String>,
    pub validation_errors: Vec<String>,
    pub scoring_note: String,
}

fn str_field(control: &Value, key: &str) -> String {
    match control.get(key) {
        Some(Value::String(s)) => s.clone(),
        Some(Value::Null) | None => String::new(),
        Some(other) => other.to_string(),
    }
}

fn truthy_field(control: &Value, key: &str) -> bool {
    match control.get(key) {
        None | Some(Value::Null) => false,
        Some(Value::Bool(b)) => *b,
        Some(Value::String(s)) => !s.is_empty(),
        Some(Value::Array(a)) => !a.is_empty(),
        Some(Value::Object(o)) => !o.is_empty(),
        Some(Value::Number(n)) => n.as_f64() != Some(0.0),
    }
}

/// Mirrors Python `calculate(controls)`.
pub fn calculate(controls: &[Value]) -> CoverageResult {
    let mut errors: Vec<String> = Vec::new();
    let mut counts: BTreeMap<String, i64> = BTreeMap::new();
    let mut applicable: i64 = 0;
    let mut tested: i64 = 0;
    let mut critical_failures: Vec<String> = Vec::new();
    let mut critical_unknown: Vec<String> = Vec::new();
    let mut partials: Vec<String> = Vec::new();

    for (i, control) in controls.iter().enumerate() {
        let cid = {
            let raw = str_field(control, "id");
            if raw.is_empty() {
                format!("row-{i}")
            } else {
                raw
            }
        };
        let status = str_field(control, "status").to_lowercase();
        if !STATUSES.contains(&status.as_str()) {
            errors.push(format!("{cid}: invalid status '{status}'"));
            continue;
        }
        *counts.entry(status.clone()).or_insert(0) += 1;
        if status == "na" {
            if str_field(control, "rationale").trim().is_empty() {
                errors.push(format!("{cid}: N/A requires rationale"));
            }
            continue;
        }
        applicable += 1;
        if matches!(status.as_str(), "pass" | "partial" | "fail") {
            tested += 1;
        }
        if status == "partial" {
            if !truthy_field(control, "tested_scope") || !truthy_field(control, "untested_scope")
            {
                errors.push(format!(
                    "{cid}: Partial requires tested_scope and untested_scope"
                ));
            }
            partials.push(cid.clone());
        }
        if status == "not_testable" && str_field(control, "reason").trim().is_empty() {
            errors.push(format!("{cid}: not_testable requires reason"));
        }
        if truthy_field(control, "critical") {
            if status == "fail" {
                critical_failures.push(cid.clone());
            } else if matches!(status.as_str(), "partial" | "not_testable") {
                critical_unknown.push(cid.clone());
            }
        }
    }

    let coverage = if applicable != 0 {
        tested as f64 / applicable as f64
    } else {
        1.0
    };
    let gate = if !critical_failures.is_empty() {
        "fail"
    } else if !critical_unknown.is_empty() || !errors.is_empty() {
        "partial"
    } else {
        "pass"
    };

    CoverageResult {
        status: if !errors.is_empty() {
            "fail".to_string()
        } else {
            gate.to_string()
        },
        counts,
        total_controls: controls.len(),
        applicable_controls: applicable,
        tested_controls: tested,
        evidence_coverage: (coverage * 10_000.0).round() / 10_000.0,
        critical_gate: gate.to_string(),
        critical_failures,
        critical_unknown,
        partial_controls: partials,
        validation_errors: errors,
        scoring_note: "N/A excluded with rationale; not_testable remains in denominator; \
critical gates are separate from any optional score."
            .to_string(),
    }
}
