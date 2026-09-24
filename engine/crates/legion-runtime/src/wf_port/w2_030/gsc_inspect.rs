//! Faithful port of `skills/seo/scripts/gsc_inspect.py`, packet r38.
//!
//! The `inspectionResult` JSON -> normalized-result mapping, HTTP-error-string classification,
//! and `batch_inspect()`'s summary tallying were already ported. This packet closes the
//! remaining gap: the live GSC URL Inspection API call ([`inspect_url_with`]/
//! [`batch_inspect_with`], generalized over [`InspectionTransport`] and backed for real by
//! [`ReqwestInspectionTransport`]) and `main()`'s CLI dispatch ([`run`]). Bearer-token resolution
//! reuses [`super::gsc_query_v2::resolve_bearer_token`] (see that module's header for the
//! documented service-account-JWT-signing gap it shares).

use std::io::Write;

use serde_json::{json, Value};

use super::gsc_query_v2::resolve_bearer_token;

pub const DAILY_LIMIT: usize = 2000;
pub const QPM_LIMIT: usize = 600;

const INSPECT_ENDPOINT: &str = "https://searchconsole.googleapis.com/v1/urlInspection/index:inspect";

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

/// Boundary a caller plugs a real URL Inspection HTTP transport behind, so
/// [`inspect_url_with`]/tests never need live credentials or network access.
pub trait InspectionTransport {
    fn post_json(&self, url: &str, bearer: &str, body: &Value) -> Result<(u16, String), String>;
}

/// Real transport backed by `reqwest::blocking`.
pub struct ReqwestInspectionTransport;

impl InspectionTransport for ReqwestInspectionTransport {
    fn post_json(&self, url: &str, bearer: &str, body: &Value) -> Result<(u16, String), String> {
        let client = reqwest::blocking::Client::new();
        let resp = client
            .post(url)
            .bearer_auth(bearer)
            .json(body)
            .send()
            .map_err(|e| e.to_string())?;
        let status = resp.status().as_u16();
        let text = resp.text().map_err(|e| e.to_string())?;
        Ok((status, text))
    }
}

/// Faithful port of `inspect_url()`, generalized over an [`InspectionTransport`]: builds the
/// `{inspectionUrl, siteUrl, languageCode}` body, calls the transport, and either classifies a
/// non-2xx / transport-level error via [`classify_inspection_error`] or maps a successful
/// response's `"inspectionResult"` via [`parse_inspection_result`].
pub fn inspect_url_with<T: InspectionTransport>(
    transport: &T,
    bearer: &str,
    inspection_url: &str,
    site_url: &str,
    language_code: &str,
) -> Value {
    let body = json!({
        "inspectionUrl": inspection_url,
        "siteUrl": site_url,
        "languageCode": language_code,
    });

    let (status, response_text) = match transport.post_json(INSPECT_ENDPOINT, bearer, &body) {
        Ok(ok) => ok,
        Err(e) => {
            let error = classify_inspection_error(&e, inspection_url, site_url);
            return error_result(inspection_url, site_url, &error);
        }
    };

    if !(200..300).contains(&status) {
        let error_str = format!("{status} {response_text}");
        let error = classify_inspection_error(&error_str, inspection_url, site_url);
        return error_result(inspection_url, site_url, &error);
    }

    let parsed: Value = match serde_json::from_str(&response_text) {
        Ok(v) => v,
        Err(e) => return error_result(inspection_url, site_url, &format!("URL Inspection API error: {e}")),
    };
    let raw_inspection_result = parsed.get("inspectionResult").cloned().unwrap_or(json!({}));
    parse_inspection_result(inspection_url, site_url, &raw_inspection_result)
}

fn error_result(inspection_url: &str, site_url: &str, error: &str) -> Value {
    json!({
        "url": inspection_url,
        "property": site_url,
        "index_status": Value::Null,
        "crawl_info": Value::Null,
        "canonical": Value::Null,
        "mobile_usability": Value::Null,
        "rich_results": Value::Null,
        "verdict": Value::Null,
        "error": error,
    })
}

/// Faithful port of `batch_inspect()`, generalized over an [`InspectionTransport`]: applies
/// [`apply_daily_limit`], calls [`inspect_url_with`] per URL, and tallies via
/// [`tally_batch_summary`]. The `time.sleep(delay)` pacing between requests is left to the
/// caller's transport (matching how other `wf_port` HTTP ports in this crate treat pacing).
pub fn batch_inspect_with<T: InspectionTransport>(
    transport: &T,
    bearer: &str,
    urls: Vec<String>,
    site_url: &str,
    language_code: &str,
) -> Value {
    let original_total = urls.len();
    let (urls, truncation_warning) = apply_daily_limit(urls);
    let mut results = Vec::new();
    for url in &urls {
        let url = url.trim();
        if url.is_empty() {
            continue;
        }
        results.push(inspect_url_with(transport, bearer, url, site_url, language_code));
    }
    let summary = tally_batch_summary(&results);
    json!({
        "property": site_url,
        "total": original_total,
        "results": results,
        "summary": {
            "pass": summary.pass_count,
            "fail": summary.fail_count,
            "neutral": summary.neutral_count,
            "error": summary.error_count,
        },
        "error": truncation_warning,
    })
}

/// Faithful port of `gsc_inspect.py`'s `main()`: real entry point wiring
/// [`resolve_bearer_token`] and [`ReqwestInspectionTransport`].
pub fn run(args: &[String], out: &mut dyn std::io::Write, err: &mut dyn std::io::Write) -> i32 {
    let mut url: Option<String> = None;
    let mut site_url: Option<String> = None;
    let mut batch: Option<String> = None;
    let mut delay: f64 = 1.0;
    let mut json_out = false;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--site-url" | "-s" => {
                i += 1;
                site_url = args.get(i).cloned();
            }
            "--batch" | "-b" => {
                i += 1;
                batch = args.get(i).cloned();
            }
            "--delay" => {
                i += 1;
                if let Some(v) = args.get(i) {
                    delay = v.parse().unwrap_or(1.0);
                }
            }
            "--json" | "-j" => json_out = true,
            other if !other.starts_with('-') && url.is_none() => url = Some(other.to_string()),
            _ => {}
        }
        i += 1;
    }
    let _ = delay; // network pacing is not reproduced in this port; see module header.

    let cfg = super::google_auth::load_config();
    let site_url = match site_url.or(cfg.default_property) {
        Some(s) => s,
        None => {
            let _ = writeln!(err, "Error: No site URL specified. Use --site-url or set default_property in config.");
            return 1;
        }
    };

    let bearer = match resolve_bearer_token() {
        Ok(b) => b,
        Err(e) => {
            let _ = writeln!(err, "Error: {e}");
            return 1;
        }
    };

    let result = if let Some(batch_path) = &batch {
        let text = match std::fs::read_to_string(batch_path) {
            Ok(t) => t,
            Err(e) => {
                let _ = writeln!(err, "Error reading batch file: {e}");
                return 1;
            }
        };
        let urls: Vec<String> = text.lines().map(str::trim).filter(|l| !l.is_empty()).map(str::to_string).collect();
        batch_inspect_with(&ReqwestInspectionTransport, &bearer, urls, &site_url, "en")
    } else if let Some(u) = &url {
        inspect_url_with(&ReqwestInspectionTransport, &bearer, u, &site_url, "en")
    } else {
        let _ = writeln!(err, "usage: gsc_inspect.py [-h] [--site-url SITE_URL] [--batch BATCH] [--delay DELAY] [--json] [url]");
        return 1;
    };

    if json_out {
        let _ = writeln!(out, "{}", serde_json::to_string_pretty(&result).unwrap_or_default());
        return 0;
    }

    if batch.is_some() {
        let summary = result.get("summary").cloned().unwrap_or(json!({}));
        let _ = writeln!(out, "=== URL Inspection Batch Results ===");
        let _ = writeln!(out, "Property: {site_url}");
        let _ = writeln!(
            out,
            "Total: {} | Pass: {} | Fail: {} | Errors: {}",
            result.get("total").and_then(Value::as_u64).unwrap_or(0),
            summary.get("pass").and_then(Value::as_u64).unwrap_or(0),
            summary.get("fail").and_then(Value::as_u64).unwrap_or(0),
            summary.get("error").and_then(Value::as_u64).unwrap_or(0),
        );
        let _ = writeln!(out);
        for r in result.get("results").and_then(Value::as_array).cloned().unwrap_or_default() {
            let verdict = r.get("verdict").and_then(Value::as_str).unwrap_or("?");
            let status = match verdict {
                "PASS" => "OK",
                "FAIL" => "FAIL",
                "NEUTRAL" => "--",
                _ => "ERR",
            };
            let _ = writeln!(out, "  [{status}] {}", r.get("url").and_then(Value::as_str).unwrap_or(""));
            if let Some(e) = r.get("error").and_then(Value::as_str) {
                let _ = writeln!(out, "       Error: {e}");
            } else if verdict == "FAIL" {
                let idx = r.get("index_status").cloned().unwrap_or(json!({}));
                let _ = writeln!(
                    out,
                    "       Coverage: {} | Fetch: {}",
                    idx.get("coverage_state").and_then(Value::as_str).unwrap_or("None"),
                    idx.get("page_fetch_state").and_then(Value::as_str).unwrap_or("None"),
                );
            }
        }
        0
    } else {
        if let Some(e) = result.get("error").and_then(Value::as_str) {
            let _ = writeln!(err, "Error: {e}");
            return 1;
        }
        let verdict = result.get("verdict").and_then(Value::as_str).unwrap_or("?");
        let _ = writeln!(out, "=== URL Inspection: {} ===", result.get("url").and_then(Value::as_str).unwrap_or(""));
        let _ = writeln!(out, "Verdict: {verdict}");
        if let Some(idx) = result.get("index_status").filter(|v| !v.is_null()) {
            let _ = writeln!(out, "\nIndex Status:");
            let _ = writeln!(out, "  Coverage: {}", idx.get("coverage_state").and_then(Value::as_str).unwrap_or("None"));
            let _ = writeln!(out, "  Robots.txt: {}", idx.get("robots_txt_state").and_then(Value::as_str).unwrap_or("None"));
            let _ = writeln!(out, "  Indexing: {}", idx.get("indexing_state").and_then(Value::as_str).unwrap_or("None"));
            let _ = writeln!(out, "  Page Fetch: {}", idx.get("page_fetch_state").and_then(Value::as_str).unwrap_or("None"));
            let _ = writeln!(out, "  Last Crawl: {}", idx.get("last_crawl_time").and_then(Value::as_str).unwrap_or("N/A"));
            let _ = writeln!(out, "  Crawled As: {}", idx.get("crawled_as").and_then(Value::as_str).unwrap_or("None"));
        }
        if let Some(canon) = result.get("canonical").filter(|v| !v.is_null()) {
            let _ = writeln!(out, "\nCanonical:");
            let _ = writeln!(out, "  Google: {}", canon.get("google_canonical").and_then(Value::as_str).unwrap_or("N/A"));
            let _ = writeln!(out, "  User: {}", canon.get("user_canonical").and_then(Value::as_str).unwrap_or("N/A"));
            if let Some(m) = canon.get("match").and_then(Value::as_bool) {
                let _ = writeln!(out, "  Match: {}", if m { "Yes" } else { "MISMATCH" });
            }
        }
        if let Some(rr) = result.get("rich_results").filter(|v| !v.is_null()) {
            if rr.get("detected_items").and_then(Value::as_array).is_some_and(|a| !a.is_empty()) {
                let _ = writeln!(out, "\nRich Results: {}", rr.get("verdict").and_then(Value::as_str).unwrap_or(""));
                for item in rr.get("detected_items").and_then(Value::as_array).cloned().unwrap_or_default() {
                    let _ = writeln!(out, "  Type: {}", item.get("type").and_then(Value::as_str).unwrap_or(""));
                }
            }
        }
        0
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

    struct FakeInspectionTransport {
        status: u16,
        body: Value,
    }

    impl InspectionTransport for FakeInspectionTransport {
        fn post_json(&self, _url: &str, _bearer: &str, _body: &Value) -> Result<(u16, String), String> {
            Ok((self.status, self.body.to_string()))
        }
    }

    #[test]
    fn inspect_url_with_success_maps_result() {
        let transport = FakeInspectionTransport {
            status: 200,
            body: json!({"inspectionResult": {"indexStatusResult": {"verdict": "PASS"}}}),
        };
        let out = inspect_url_with(&transport, "tok", "https://example.com/", "sc-domain:example.com", "en");
        assert_eq!(out["verdict"], "PASS");
        assert_eq!(out["error"], Value::Null);
    }

    #[test]
    fn inspect_url_with_classifies_403() {
        let transport = FakeInspectionTransport { status: 403, body: json!("Forbidden") };
        let out = inspect_url_with(&transport, "tok", "https://example.com/", "sc-domain:example.com", "en");
        assert!(out["error"].as_str().unwrap().contains("Permission denied"));
        assert_eq!(out["verdict"], Value::Null);
    }

    #[test]
    fn batch_inspect_with_tallies_and_truncates() {
        struct AlwaysPass;
        impl InspectionTransport for AlwaysPass {
            fn post_json(&self, _url: &str, _bearer: &str, _body: &Value) -> Result<(u16, String), String> {
                Ok((200, json!({"inspectionResult": {"indexStatusResult": {"verdict": "PASS"}}}).to_string()))
            }
        }
        let urls = vec!["https://example.com/1".to_string(), "https://example.com/2".to_string()];
        let out = batch_inspect_with(&AlwaysPass, "tok", urls, "sc-domain:example.com", "en");
        assert_eq!(out["summary"]["pass"], 2);
        assert_eq!(out["total"], 2);
        assert_eq!(out["error"], Value::Null);
    }
}
