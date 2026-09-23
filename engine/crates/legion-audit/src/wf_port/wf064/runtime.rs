//! Partial port of `tools/audit/audit-runtime.mjs`.
//!
//! Scope note: the bulk of this file is a headless-Chrome CDP driver (raw
//! WebSocket framing, browser process spawn, in-page instrumentation
//! scripts, screenshot capture) — a live browser automation harness, not
//! unit-testable analysis logic, and is not ported. The three pure,
//! self-contained helpers around typed degradation are ported faithfully
//! below: `parseSurfacesInput`, `classifyRuntimeFailure`, and
//! `buildDegradedReport`.

use serde_json::{json, Value};

#[derive(Debug, Clone, PartialEq)]
pub struct ParsedSurfaces {
    pub targets: Vec<Value>,
}

/// Faithful port of `parseSurfacesInput`: the input must parse as JSON and
/// be a top-level array; non-object entries are dropped (JS
/// `.filter(t => t && typeof t === 'object')`).
pub fn parse_surfaces_input(text: &str) -> Result<ParsedSurfaces, String> {
    let parsed: Value = serde_json::from_str(text)
        .map_err(|e| format!("--surfaces parse failed: {e}"))?;
    let array = parsed
        .as_array()
        .ok_or_else(|| "--surfaces must contain a JSON array of {label, text|selector} targets".to_string())?;
    let targets = array
        .iter()
        .filter(|t| t.is_object())
        .cloned()
        .collect();
    Ok(ParsedSurfaces { targets })
}

/// Faithful port of `classifyRuntimeFailure`: maps a launch/connect/load
/// error message to one of four typed degradation kinds, in the same
/// precedence order as the JS regex chain.
pub fn classify_runtime_failure(message: &str) -> &'static str {
    if message.contains("No Chrome/Edge found") {
        "browser-unavailable"
    } else if message.contains("timed out waiting for app load") {
        "app-load-timeout"
    } else if contains_ci(message, "timed out waiting")
        || contains_ci(message, "cdp")
        || contains_ci(message, "page target")
        || contains_ci(message, "handshake")
    {
        "cdp-unavailable"
    } else {
        "runtime-execution"
    }
}

fn contains_ci(haystack: &str, needle: &str) -> bool {
    haystack.to_ascii_lowercase().contains(&needle.to_ascii_lowercase())
}

/// Faithful port of `buildDegradedReport`. `url` mirrors JS `URL_ ?? null`;
/// `keys` mirrors the `KEYS` CLI flag folded into every report.
pub fn build_degraded_report(gaps: &[Value], denominator: &Value, url: Option<&str>, keys: i64) -> Value {
    json!({
        "kind": "audit-runtime",
        "url": url,
        "status": "unproven",
        "complete": false,
        "incomplete": true,
        "shallow": false,
        "denominator": denominator,
        "surfaces_found": denominator.get("expected").cloned().unwrap_or(Value::Null),
        "surfaces_tested": denominator.get("examined").cloned().unwrap_or(Value::Null),
        "keystrokes": keys,
        "findings": [],
        "degradation": gaps,
        "coverageGaps": gaps,
        "console_total": 0,
        "a11y_axe": "not-run",
        "a11y_violations_total": 0,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_surfaces_rejects_non_array() {
        let err = parse_surfaces_input(r#"{"label":"x"}"#).unwrap_err();
        assert!(err.contains("must contain a JSON array"));
    }

    #[test]
    fn parse_surfaces_rejects_invalid_json() {
        let err = parse_surfaces_input("not json").unwrap_err();
        assert!(err.contains("--surfaces parse failed"));
    }

    #[test]
    fn parse_surfaces_drops_non_object_entries() {
        let parsed = parse_surfaces_input(r#"[{"label":"a"}, "skip-me", 42, {"label":"b"}]"#).unwrap();
        assert_eq!(parsed.targets.len(), 2);
    }

    #[test]
    fn classify_runtime_failure_precedence() {
        assert_eq!(classify_runtime_failure("No Chrome/Edge found for the runtime pass."), "browser-unavailable");
        assert_eq!(classify_runtime_failure("timed out waiting for app load"), "app-load-timeout");
        assert_eq!(classify_runtime_failure("CDP handshake failed"), "cdp-unavailable");
        assert_eq!(classify_runtime_failure("something else entirely"), "runtime-execution");
    }

    #[test]
    fn build_degraded_report_shape() {
        let gaps = vec![json!({"kind": "browser-unavailable"})];
        let denominator = json!({"kind": "runtime-surfaces", "expected": 1, "examined": 0});
        let report = build_degraded_report(&gaps, &denominator, Some("http://localhost:1422"), 12);
        assert_eq!(report["status"], json!("unproven"));
        assert_eq!(report["incomplete"], json!(true));
        assert_eq!(report["complete"], json!(false));
        assert_eq!(report["surfaces_found"], json!(1));
        assert_eq!(report["url"], json!("http://localhost:1422"));
    }
}
