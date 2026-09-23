//! Faithful port of the pure, deterministic parts of `skills/seo/scripts/gsc_inspect.py`:
//! the `inspectionResult` JSON -> normalized-result mapping done inline in `inspect_url()`, its
//! HTTP-error-string classification, and `batch_inspect()`'s summary tallying. The actual GSC
//! URL Inspection API call is provider I/O and is NOT ported (see the module gap note).

use serde_json::{json, Value};

pub const DAILY_LIMIT: usize = 2000;
pub const QPM_LIMIT: usize = 600;

/// Port of the `except Exception as e:` branch in `inspect_url()`: classifies a raised error's
/// string representation into the same human-readable messages, by substring match on
/// `"403"`/`"429"`/`"400"`, same as the python (first match wins, in the same order).
pub fn classify_inspection_error(error_str: &str, inspection_url: &str, site_url: &str) -> String {
    if error_str.contains("403") {
        format!("Permission denied. Add the service account as an Owner in GSC property '{site_url}'.")
    } else if error_str.contains("429") {
        format!("Rate limit exceeded. URL Inspection: {QPM_LIMIT} QPM / {DAILY_LIMIT} QPD per site.")
    } else if error_str.contains("400") {
        format!("Invalid request. Ensure the URL '{inspection_url}' belongs to property '{site_url}'.")
    } else {
        format!("URL Inspection API error: {error_str}")
    }
}

/// Port of the `inspectionResult` -> result-dict mapping in `inspect_url()` (the part after a
/// successful API call). `raw_inspection_result` is the API response's `"inspectionResult"`
/// object (or `Value::Null`/an empty object if absent).
pub fn parse_inspection_result(
    inspection_url: &str,
    site_url: &str,
    raw_inspection_result: &Value,
) -> Value {
    let ir = raw_inspection_result;
    let idx = ir.get("indexStatusResult").cloned().unwrap_or(json!({}));

    let google_canonical = idx.get("googleCanonical").cloned().unwrap_or(Value::Null);
    let user_canonical = idx.get("userCanonical").cloned().unwrap_or(Value::Null);
    let both_present = !google_canonical.is_null() && !user_canonical.is_null();
    let canonical_match = if both_present {
        json!(google_canonical == user_canonical)
    } else {
        Value::Null
    };

    let verdict = idx
        .get("verdict")
        .and_then(|v| v.as_str())
        .unwrap_or("VERDICT_UNSPECIFIED")
        .to_string();

    let mut out = json!({
        "url": inspection_url,
        "property": site_url,
        "verdict": verdict,
        "index_status": {
            "verdict": idx.get("verdict").cloned().unwrap_or(Value::Null),
            "coverage_state": idx.get("coverageState").cloned().unwrap_or(Value::Null),
            "robots_txt_state": idx.get("robotsTxtState").cloned().unwrap_or(Value::Null),
            "indexing_state": idx.get("indexingState").cloned().unwrap_or(Value::Null),
            "page_fetch_state": idx.get("pageFetchState").cloned().unwrap_or(Value::Null),
            "last_crawl_time": idx.get("lastCrawlTime").cloned().unwrap_or(Value::Null),
            "crawled_as": idx.get("crawledAs").cloned().unwrap_or(Value::Null),
            "referring_urls": idx.get("referringUrls").cloned().unwrap_or(json!([])),
        },
        "canonical": {
            "google_canonical": google_canonical,
            "user_canonical": user_canonical,
            "match": canonical_match,
        },
        "mobile_usability": Value::Null,
        "rich_results": Value::Null,
        "error": Value::Null,
    });

    if let Some(mu) = ir.get("mobileUsabilityResult") {
        if !mu.is_null() && mu != &json!({}) {
            let issues: Vec<Value> = mu
                .get("issues")
                .and_then(|v| v.as_array())
                .cloned()
                .unwrap_or_default()
                .iter()
                .map(|issue| {
                    json!({
                        "type": issue.get("issueType").cloned().unwrap_or(Value::Null),
                        "message": issue.get("message").cloned().unwrap_or(Value::Null),
                    })
                })
                .collect();
            out["mobile_usability"] = json!({
                "verdict": mu.get("verdict").cloned().unwrap_or(Value::Null),
                "issues": issues,
            });
        }
    }

    if let Some(rr) = ir.get("richResultsResult") {
        if !rr.is_null() && rr != &json!({}) {
            let detected_items: Vec<Value> = rr
                .get("detectedItems")
                .and_then(|v| v.as_array())
                .cloned()
                .unwrap_or_default()
                .iter()
                .map(|item| {
                    let items: Vec<Value> = item
                        .get("items")
                        .and_then(|v| v.as_array())
                        .cloned()
                        .unwrap_or_default()
                        .iter()
                        .map(|i| {
                            json!({
                                "name": i.get("name").cloned().unwrap_or(Value::Null),
                                "issues": i.get("issues").cloned().unwrap_or(json!([])),
                            })
                        })
                        .collect();
                    json!({
                        "type": item.get("richResultType").cloned().unwrap_or(Value::Null),
                        "items": items,
                    })
                })
                .collect();
            out["rich_results"] = json!({
                "verdict": rr.get("verdict").cloned().unwrap_or(Value::Null),
                "detected_items": detected_items,
            });
        }
    }

    out
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BatchSummary {
    pub pass_count: usize,
    pub fail_count: usize,
    pub neutral_count: usize,
    pub error_count: usize,
}

/// Port of `batch_inspect()`'s summary tally: for each already-produced per-URL inspection
/// result (as returned by [`parse_inspection_result`], or one carrying an `"error"`), bump the
/// matching counter. Order of checks matches python: error first, then verdict PASS/FAIL/other.
pub fn tally_batch_summary(inspections: &[Value]) -> BatchSummary {
    let mut summary = BatchSummary::default();
    for inspection in inspections {
        let has_error = inspection
            .get("error")
            .map(|e| !e.is_null())
            .unwrap_or(false);
        let verdict = inspection.get("verdict").and_then(|v| v.as_str()).unwrap_or("");
        if has_error {
            summary.error_count += 1;
        } else if verdict == "PASS" {
            summary.pass_count += 1;
        } else if verdict == "FAIL" {
            summary.fail_count += 1;
        } else {
            summary.neutral_count += 1;
        }
    }
    summary
}

/// Port of the `if len(urls) > DAILY_LIMIT:` truncation in `batch_inspect()`. Returns the
/// (possibly truncated) URL list plus the warning error string, if any.
pub fn apply_daily_limit(urls: Vec<String>) -> (Vec<String>, Option<String>) {
    if urls.len() > DAILY_LIMIT {
        let error = format!(
            "Batch size ({}) exceeds daily limit ({DAILY_LIMIT}). Only the first {DAILY_LIMIT} URLs will be processed.",
            urls.len()
        );
        let mut truncated = urls;
        truncated.truncate(DAILY_LIMIT);
        (truncated, Some(error))
    } else {
        (urls, None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_error_checks_403_then_429_then_400() {
        assert!(classify_inspection_error("HttpError 403 Forbidden", "u", "s").contains("Permission denied"));
        assert!(classify_inspection_error("429 too many requests", "u", "s").contains("Rate limit"));
        assert!(classify_inspection_error("400 bad request", "u", "s").contains("Invalid request"));
        assert!(classify_inspection_error("boom", "u", "s").contains("URL Inspection API error: boom"));
    }

    #[test]
    fn parse_inspection_result_maps_index_status() {
        let raw = json!({
            "indexStatusResult": {
                "verdict": "PASS",
                "coverageState": "Submitted and indexed",
                "googleCanonical": "https://example.com/",
                "userCanonical": "https://example.com/",
            }
        });
        let out = parse_inspection_result("https://example.com/", "sc-domain:example.com", &raw);
        assert_eq!(out["verdict"], "PASS");
        assert_eq!(out["index_status"]["coverage_state"], "Submitted and indexed");
        assert_eq!(out["canonical"]["match"], true);
        assert_eq!(out["mobile_usability"], Value::Null);
    }

    #[test]
    fn parse_inspection_result_defaults_verdict_unspecified() {
        let out = parse_inspection_result("u", "s", &json!({}));
        assert_eq!(out["verdict"], "VERDICT_UNSPECIFIED");
        assert_eq!(out["canonical"]["match"], Value::Null);
    }

    #[test]
    fn parse_inspection_result_maps_rich_results() {
        let raw = json!({
            "indexStatusResult": {"verdict": "PASS"},
            "richResultsResult": {
                "verdict": "PASS",
                "detectedItems": [
                    {"richResultType": "FAQ", "items": [{"name": "Q1", "issues": []}]}
                ]
            }
        });
        let out = parse_inspection_result("u", "s", &raw);
        assert_eq!(out["rich_results"]["verdict"], "PASS");
        assert_eq!(out["rich_results"]["detected_items"][0]["type"], "FAQ");
        assert_eq!(out["rich_results"]["detected_items"][0]["items"][0]["name"], "Q1");
    }

    #[test]
    fn tally_batch_summary_counts_each_bucket() {
        let inspections = vec![
            json!({"verdict": "PASS", "error": Value::Null}),
            json!({"verdict": "FAIL", "error": Value::Null}),
            json!({"verdict": "NEUTRAL", "error": Value::Null}),
            json!({"verdict": Value::Null, "error": "boom"}),
        ];
        let summary = tally_batch_summary(&inspections);
        assert_eq!(
            summary,
            BatchSummary { pass_count: 1, fail_count: 1, neutral_count: 1, error_count: 1 }
        );
    }

    #[test]
    fn apply_daily_limit_truncates_and_warns() {
        let urls: Vec<String> = (0..DAILY_LIMIT + 5).map(|i| format!("https://example.com/{i}")).collect();
        let (truncated, error) = apply_daily_limit(urls);
        assert_eq!(truncated.len(), DAILY_LIMIT);
        assert!(error.unwrap().contains("exceeds daily limit"));
    }

    #[test]
    fn apply_daily_limit_no_warning_under_limit() {
        let urls = vec!["https://example.com/1".to_string()];
        let (truncated, error) = apply_daily_limit(urls);
        assert_eq!(truncated.len(), 1);
        assert!(error.is_none());
    }
}
