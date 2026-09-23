//! Port of `src/providers/runtime/web/performance/index.mjs`
//! (`verifyWebPerformance`) — chunk wf050.
//!
//! The JS module imports `captureWebEvidence` from
//! `../capture/index.mjs`, a file outside this chunk's owned paths
//! (`src/providers/runtime/web/capture/index.mjs`) and not yet visible in
//! `engine/` under any ported name. To stay faithful without reaching
//! outside `wf_port::wf050`, `verify_web_performance` takes the capture
//! evidence envelope as a parameter (`capture`) instead of computing it
//! in-process, exactly as `verifyWebPerformance(input)` uses whatever
//! `captureWebEvidence(input)` returns. The caller is expected to have run
//! (or ported) `captureWebEvidence` first and pass its `{ digest, captures,
//! coverageGaps }` triple here. See the wf050 report for this dependency.

use serde_json::{json, Value};

use super::shared::finalize;

/// The subset of `captureWebEvidence`'s return envelope that
/// `verifyWebPerformance` actually consumes (`coverageGaps`, `digest`,
/// `captures`).
pub struct CaptureEvidence {
    pub coverage_gaps: Vec<String>,
    pub digest: Value,
    pub captures: Value,
}

fn percentile75(values: &[f64]) -> Option<f64> {
    if values.is_empty() {
        return None;
    }
    let mut sorted = values.to_vec();
    sorted.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let idx = ((sorted.len() as f64) * 0.75).ceil() as usize;
    sorted.get(idx.saturating_sub(1)).copied()
}

fn is_numeric_array(value: Option<&Value>) -> bool {
    match value.and_then(Value::as_array) {
        Some(items) if !items.is_empty() => items.iter().all(|item| matches!(item, Value::Number(n) if n.as_f64().map(|f| f.is_finite() && f >= 0.0).unwrap_or(false))),
        _ => false,
    }
}

fn finite_nonneg(value: Option<&Value>) -> bool {
    value.and_then(Value::as_f64).map(|f| f.is_finite() && f >= 0.0).unwrap_or(false)
}

/// Port of `verifyWebPerformance(input)`. `capture` stands in for the
/// `captureWebEvidence(input)` call (see module docs).
pub fn verify_web_performance(input: &Value, capture: &CaptureEvidence) -> Value {
    let binding = input.get("binding").cloned().unwrap_or(json!({}));
    let budgets = input.get("budgets").cloned().unwrap_or(json!({}));

    let captures_val = input.get("captures");
    let captures_invalid = match captures_val.and_then(Value::as_array) {
        None => true,
        Some(items) => items.iter().any(|item| !item.is_object()),
    };
    if captures_invalid {
        return finalize(
            "legion-web-performance-evidence",
            json!({
                "provider": "runtime.web.performance",
                "status": "error",
                "terminal": true,
                "claimLevel": "runtime",
                "evidenceClass": "measured",
                "binding": binding,
                "metrics": { "lcp": Value::Null, "longTasks": Value::Null, "layoutShifts": Value::Null },
                "budgets": budgets,
                "captureDigest": Value::Null,
                "artifacts": [],
                "coverageGaps": ["performance-captures-invalid"],
            }),
        );
    }

    let samples = captures_val.and_then(Value::as_array).cloned().unwrap_or_default();
    let mut gaps = capture.coverage_gaps.clone();

    for sample in &samples {
        let id = sample
            .get("repeat")
            .filter(|v| !v.is_null())
            .or_else(|| sample.get("sampleId").filter(|v| !v.is_null()))
            .cloned()
            .unwrap_or(Value::String("missing".to_string()));
        let id_str = match &id {
            Value::String(s) => s.clone(),
            other => other.to_string(),
        };
        let perf = sample.get("performance");
        match perf {
            None | Some(Value::Null) => gaps.push(format!("performance-sample-invalid:{id_str}")),
            Some(Value::Array(_)) => gaps.push(format!("performance-sample-invalid:{id_str}")),
            Some(Value::Object(_)) => {
                let perf = perf.unwrap();
                if !finite_nonneg(perf.get("lcp")) {
                    gaps.push(format!("performance-lcp-invalid:{id_str}"));
                }
                for metric in ["longTasks", "layoutShifts", "paints", "userTimings"] {
                    if !is_numeric_array(perf.get(metric)) {
                        gaps.push(format!("performance-{metric}-invalid:{id_str}"));
                    }
                }
                if !finite_nonneg(perf.get("memory")) {
                    gaps.push(format!("performance-memory-invalid:{id_str}"));
                }
            }
            _ => gaps.push(format!("performance-sample-invalid:{id_str}")),
        }
    }

    let lcp_values: Vec<f64> = samples
        .iter()
        .filter_map(|item| item.get("performance").and_then(|p| p.get("lcp")).and_then(Value::as_f64))
        .filter(|v| v.is_finite() && *v >= 0.0)
        .collect();
    let long_tasks_values: Vec<f64> = samples
        .iter()
        .filter_map(|item| {
            let perf = item.get("performance");
            let lt = perf.and_then(|p| p.get("longTasks"));
            if is_numeric_array(lt) {
                Some(lt.and_then(Value::as_array).unwrap().len() as f64)
            } else {
                None
            }
        })
        .collect();
    let layout_shift_values: Vec<f64> = samples
        .iter()
        .filter_map(|item| {
            let perf = item.get("performance");
            let ls = perf.and_then(|p| p.get("layoutShifts"));
            if is_numeric_array(ls) {
                let sum: f64 = ls.and_then(Value::as_array).unwrap().iter().filter_map(Value::as_f64).sum();
                Some(sum)
            } else {
                None
            }
        })
        .collect();

    let metrics_lcp = percentile75(&lcp_values);
    let metrics_long_tasks = percentile75(&long_tasks_values);
    let metrics_layout_shifts = percentile75(&layout_shift_values);
    let metrics = json!({
        "lcp": metrics_lcp,
        "longTasks": metrics_long_tasks,
        "layoutShifts": metrics_layout_shifts,
    });

    let budgets_obj = budgets.as_object().cloned().unwrap_or_default();
    if budgets_obj.is_empty() {
        gaps.push("performance-budget-missing".to_string());
    }
    for (metric, limit) in &budgets_obj {
        match limit.as_f64().filter(|f| f.is_finite() && *f >= 0.0) {
            None => gaps.push(format!("budget-invalid:{metric}")),
            Some(limit_val) => {
                let metric_val = metrics.get(metric.as_str()).and_then(Value::as_f64);
                match metric_val {
                    None => gaps.push(format!("metric-missing:{metric}")),
                    Some(mv) => {
                        if mv > limit_val {
                            gaps.push(format!("budget-exceeded:{metric}"));
                        }
                    }
                }
            }
        }
    }

    let gaps = super::shared::unique_sorted(gaps);
    let status = if gaps.iter().any(|g| g.starts_with("budget-exceeded:")) {
        "fail"
    } else if !gaps.is_empty() {
        "unproven"
    } else {
        "pass"
    };

    finalize(
        "legion-web-performance-evidence",
        json!({
            "provider": "runtime.web.performance",
            "status": status,
            "terminal": true,
            "claimLevel": "runtime",
            "evidenceClass": "measured",
            "binding": binding,
            "metrics": metrics,
            "budgets": budgets,
            "captureDigest": capture.digest,
            "artifacts": capture.captures,
            "coverageGaps": gaps,
        }),
    )
}
