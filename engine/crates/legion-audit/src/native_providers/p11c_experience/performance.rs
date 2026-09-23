//! Port of `src/providers/performance/{bundle,cache,frontend,network}/core.mjs`.

use serde_json::Value;

fn arr<'a>(value: &'a Value, key: &str) -> Vec<&'a Value> {
    value.get(key).and_then(Value::as_array).map(|items| items.iter().collect()).unwrap_or_default()
}

fn truthy(value: Option<&Value>) -> bool {
    match value {
        None | Some(Value::Null) | Some(Value::Bool(false)) => false,
        Some(Value::Bool(true)) => true,
        Some(Value::String(s)) => !s.is_empty(),
        Some(Value::Number(n)) => n.as_f64().is_some_and(|n| n != 0.0),
        Some(Value::Array(a)) => !a.is_empty(),
        Some(Value::Object(_)) => true,
    }
}

// ---------------------------------------------------------------------
// performance/bundle/core.mjs :: analyzeBundleEvidence
// ---------------------------------------------------------------------

pub fn analyze_bundle_evidence(input: &Value) -> Value {
    let artifact = input.get("artifact").cloned().unwrap_or(Value::Null);
    if !truthy(artifact.get("id")) || !truthy(artifact.get("digest")) {
        return serde_json::json!({ "provider": "performance.bundle", "status": "unproven", "artifact": artifact, "candidates": [], "coverageGaps": ["build-artifact-identity-missing"] });
    }
    let modules: Vec<Value> = arr(input, "modules").into_iter().cloned().collect();
    let mut candidates: Vec<Value> = Vec::new();
    let flags = [
        ("duplicate", "performance.bundle-duplicate-module"),
        ("dead", "performance.bundle-dead-dependency"),
        ("renderBlocking", "performance.bundle-render-blocking"),
        ("heavyLibrary", "performance.bundle-heavy-library"),
        ("codeSplitMissing", "performance.bundle-code-split"),
    ];
    for module in &modules {
        for (flag, rule_id) in flags {
            if truthy(module.get(flag)) {
                candidates.push(serde_json::json!({
                    "ruleId": rule_id, "module": module.get("name").cloned().unwrap_or(Value::Null),
                    "bytes": module.get("bytes").cloned().unwrap_or(Value::Null),
                    "artifactId": artifact.get("id").cloned().unwrap_or(Value::Null),
                }));
            }
        }
    }
    serde_json::json!({ "provider": "performance.bundle", "status": if candidates.is_empty() { "pass" } else { "candidates" }, "artifact": artifact, "candidates": candidates, "coverageGaps": [] })
}

// ---------------------------------------------------------------------
// performance/cache/core.mjs :: analyzeCacheEvidence
// ---------------------------------------------------------------------

pub fn analyze_cache_evidence(input: &Value) -> Value {
    let entries: Vec<Value> = arr(input, "entries").into_iter().cloned().collect();
    let mut candidates: Vec<Value> = Vec::new();
    let mut recommendations: Vec<Value> = Vec::new();
    for entry in &entries {
        let id = entry.get("id").cloned().unwrap_or(Value::Null);
        let ttl = entry.get("ttl").and_then(Value::as_f64).unwrap_or(0.0);
        let invalidation_evidence = entry.get("invalidationEvidence").cloned().unwrap_or(Value::Null);
        if (truthy(entry.get("sensitive")) || truthy(entry.get("mutable"))) && ttl > 0.0 && !truthy(entry.get("invalidationEvidence")) {
            candidates.push(serde_json::json!({
                "ruleId": "performance.cache-correctness-risk", "entryId": id, "kind": "correctness-risk",
                "sensitive": truthy(entry.get("sensitive")), "mutable": truthy(entry.get("mutable")), "invalidationEvidence": Value::Null,
            }));
        }
        if truthy(entry.get("opportunity")) && truthy(entry.get("invalidationEvidence")) && truthy(entry.get("correctnessAnalysis")) {
            recommendations.push(serde_json::json!({
                "ruleId": "performance.cache-opportunity", "entryId": id, "invalidationEvidence": invalidation_evidence,
                "correctnessAnalysis": entry.get("correctnessAnalysis").cloned().unwrap_or(Value::Null),
            }));
        }
    }
    let status = if !candidates.is_empty() { "candidates" } else if !entries.is_empty() { "pass" } else { "unproven" };
    serde_json::json!({
        "provider": "performance.cache", "status": status, "candidates": candidates, "recommendations": recommendations,
        "coverageGaps": if entries.is_empty() { vec![Value::String("cache-evidence-missing".into())] } else { vec![] },
    })
}

// ---------------------------------------------------------------------
// performance/frontend/core.mjs :: assessFrontendPerformance
// ---------------------------------------------------------------------

pub fn assess_frontend_performance(measurements: &[Value], budgets: &Value) -> Value {
    let budget_map = budgets.as_object().cloned().unwrap_or_default();
    let mut findings: Vec<Value> = Vec::new();
    for item in measurements {
        for (metric, limit) in &budget_map {
            let Some(limit) = limit.as_f64() else { continue };
            let Some(actual) = item.get(metric).and_then(Value::as_f64).filter(|v| v.is_finite()) else { continue };
            if actual > limit {
                findings.push(serde_json::json!({ "surfaceId": item.get("surfaceId").cloned().unwrap_or(Value::Null), "metric": metric, "actual": actual, "limit": limit }));
            }
        }
    }
    let gaps: Vec<Value> = measurements
        .iter()
        .filter(|item| !truthy(item.get("environment")) || !truthy(item.get("repeatCount")))
        .map(|item| Value::String(format!("measurement-environment-missing:{}", item.get("surfaceId").and_then(Value::as_str).unwrap_or("unknown"))))
        .collect();
    let status = if !gaps.is_empty() { "partial" } else if !findings.is_empty() { "candidates" } else { "pass" };
    serde_json::json!({
        "schemaVersion": 1, "provider": "performance.frontend", "status": status, "findings": findings,
        "coverageGaps": gaps, "measurements": measurements,
    })
}

// ---------------------------------------------------------------------
// performance/network/core.mjs :: analyzeNetworkEvidence
// ---------------------------------------------------------------------

pub fn analyze_network_evidence(input: &Value) -> Value {
    let requests: Vec<Value> = arr(input, "requests").into_iter().cloned().collect();
    let mut candidates: Vec<Value> = Vec::new();
    for request in &requests {
        let id = request.get("id").cloned().unwrap_or(Value::Null);
        let url = request.get("url").cloned().unwrap_or(Value::Null);
        let evidence_class = if truthy(request.get("traceRef")) { "runtime-trace" } else { "runtime-observation" };
        let base = |rule_id: &str| serde_json::json!({ "requestId": id, "url": url, "evidenceClass": evidence_class, "ruleId": rule_id });
        if truthy(request.get("serializedBehind")) {
            let mut item = base("performance.network-independent-serialization");
            item.as_object_mut().unwrap().insert("serializedBehind".into(), request.get("serializedBehind").cloned().unwrap_or(Value::Null));
            candidates.push(item);
        }
        if truthy(request.get("duplicateConcurrent")) {
            candidates.push(base("performance.network-duplicate-concurrent"));
        }
        if truthy(request.get("unboundedRetry")) || truthy(request.get("retryWithoutBackoff")) {
            candidates.push(base("performance.network-retry-policy"));
        }
        if request.get("compressed") == Some(&Value::Bool(false)) {
            candidates.push(base("performance.network-compression"));
        }
        if truthy(request.get("timeoutMissing")) {
            candidates.push(base("performance.network-timeout-missing"));
        }
        if truthy(request.get("payloadOversized")) {
            let mut item = base("performance.network-payload-size");
            item.as_object_mut().unwrap().insert("bytes".into(), request.get("bytes").cloned().unwrap_or(Value::Null));
            candidates.push(item);
        }
        if truthy(request.get("paginationMissing")) {
            candidates.push(base("performance.network-pagination-missing"));
        }
    }
    let status = if !candidates.is_empty() { "candidates" } else if !requests.is_empty() { "pass" } else { "unproven" };
    serde_json::json!({
        "provider": "performance.network", "status": status, "candidates": candidates,
        "coverageGaps": if requests.is_empty() { vec![Value::String("request-evidence-missing".into())] } else { vec![] },
    })
}
