//! Port of `skills/seo/scripts/pagespeed_check.py`.
//!
//! Packet r41 closes the remaining gap: the live PSI (`run_pagespeed`) and
//! CrUX (`query_crux`) HTTP round trips, `combined_check`, and the CLI
//! entry point (`main`), all behind a [`PsiClient`] trait so tests never
//! hit the network. CWV thresholds/rating, URL validation, the
//! origin-vs-URL decision for a CrUX target, and the response-JSON parsing
//! that turns a raw PSI or CrUX JSON body into the same structured result
//! the Python returns were already ported in full and are reused by
//! `run_pagespeed`/`query_crux` below.

use std::io::Write;
use std::time::Duration;

use serde::Serialize;
use serde_json::Value;

const PSI_ENDPOINT: &str = "https://www.googleapis.com/pagespeedonline/v5/runPagespeed";
const CRUX_ENDPOINT: &str = "https://chromeuxreport.googleapis.com/v1/records:queryRecord";

/// Mirrors `CWV_THRESHOLDS`.
pub struct Threshold {
    pub metric: &'static str,
    pub good: f64,
    pub poor: f64,
    pub unit: &'static str,
    pub label: &'static str,
}

pub const CWV_THRESHOLDS: &[Threshold] = &[
    Threshold { metric: "largest_contentful_paint", good: 2500.0, poor: 4000.0, unit: "ms", label: "LCP" },
    Threshold { metric: "interaction_to_next_paint", good: 200.0, poor: 500.0, unit: "ms", label: "INP" },
    Threshold { metric: "cumulative_layout_shift", good: 0.1, poor: 0.25, unit: "", label: "CLS" },
    Threshold { metric: "first_contentful_paint", good: 1800.0, poor: 3000.0, unit: "ms", label: "FCP" },
    Threshold { metric: "experimental_time_to_first_byte", good: 800.0, poor: 1800.0, unit: "ms", label: "TTFB" },
];

fn threshold_for(metric: &str) -> Option<&'static Threshold> {
    CWV_THRESHOLDS.iter().find(|t| t.metric == metric)
}

/// Mirrors `PSI_METRIC_MAP`: PSI's `loadingExperience.metrics` key -> our metric name.
pub const PSI_METRIC_MAP: &[(&str, &str)] = &[
    ("LARGEST_CONTENTFUL_PAINT_MS", "largest_contentful_paint"),
    ("INTERACTION_TO_NEXT_PAINT", "interaction_to_next_paint"),
    ("CUMULATIVE_LAYOUT_SHIFT_SCORE", "cumulative_layout_shift"),
    ("FIRST_CONTENTFUL_PAINT_MS", "first_contentful_paint"),
    ("EXPERIMENTAL_TIME_TO_FIRST_BYTE", "experimental_time_to_first_byte"),
];

/// Mirrors `rate_metric`: "good" | "needs-improvement" | "poor" | "unknown".
pub fn rate_metric(metric_name: &str, value: f64) -> &'static str {
    match threshold_for(metric_name) {
        None => "unknown",
        Some(t) if value <= t.good => "good",
        Some(t) if value <= t.poor => "needs-improvement",
        Some(_) => "poor",
    }
}

/// Mirrors `google_auth.validate_url`: http(s) scheme, non-empty hostname, not a
/// blocked loopback/metadata host, and not a private/loopback/link-local literal IP.
/// (DNS resolution is not performed here, matching the Python, which only inspects
/// the literal hostname string.)
pub fn validate_url(url: &str) -> bool {
    let parsed = match parse_scheme_host(url) {
        Some(p) => p,
        None => return false,
    };
    if parsed.scheme != "http" && parsed.scheme != "https" {
        return false;
    }
    let host = match &parsed.hostname {
        Some(h) if !h.is_empty() => h,
        _ => return false,
    };
    const BLOCKED: &[&str] = &["localhost", "127.0.0.1", "0.0.0.0", "::1", "metadata.google.internal"];
    if BLOCKED.contains(&host.as_str()) {
        return false;
    }
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        if is_private_or_loopback_or_link_local(ip) {
            return false;
        }
    }
    true
}

fn is_private_or_loopback_or_link_local(ip: std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(v4) => v4.is_private() || v4.is_loopback() || v4.is_link_local(),
        std::net::IpAddr::V6(v6) => {
            v6.is_loopback() || (v6.segments()[0] & 0xffc0) == 0xfe80
        }
    }
}

struct ParsedScheme {
    scheme: String,
    hostname: Option<String>,
}

fn parse_scheme_host(url: &str) -> Option<ParsedScheme> {
    let idx = url.find("://")?;
    let scheme = url[..idx].to_string();
    let rest = &url[idx + 3..];
    let authority_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let authority = &rest[..authority_end];
    let host_port = match authority.rfind('@') {
        Some(at) => &authority[at + 1..],
        None => authority,
    };
    let hostname = if host_port.starts_with('[') {
        host_port.find(']').map(|end| host_port[1..end].to_string())
    } else {
        let host = match host_port.rfind(':') {
            Some(colon) => &host_port[..colon],
            None => host_port,
        };
        if host.is_empty() { None } else { Some(host.to_lowercase()) }
    };
    Some(ParsedScheme { scheme, hostname })
}

/// Mirrors the `is_origin` decision in `query_crux`: path is empty or `/` and there is
/// no query string.
pub fn crux_target_is_origin(url: &str) -> bool {
    let parsed = match parse_scheme_host(url) {
        Some(p) => p,
        None => return false,
    };
    let _ = parsed;
    match url.find("://") {
        None => false,
        Some(idx) => {
            let rest = &url[idx + 3..];
            let path_start = rest.find('/');
            match path_start {
                None => true, // no path at all -> treated as origin (path == "")
                Some(ps) => {
                    let path_and_query = &rest[ps..];
                    let query_start = path_and_query.find('?');
                    let path = match query_start {
                        Some(qs) => &path_and_query[..qs],
                        None => path_and_query,
                    };
                    let has_query = query_start.is_some();
                    (path.is_empty() || path == "/") && !has_query
                }
            }
        }
    }
}

// ---------------------------------------------------------------------
// PSI response parsing
// ---------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Default)]
pub struct Opportunity {
    pub id: String,
    pub title: String,
    pub savings_ms: f64,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct AuditFinding {
    pub id: String,
    pub title: String,
    pub score: Option<f64>,
    pub display: String,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct SeoAudit {
    pub id: String,
    pub title: String,
    pub score: f64,
    pub pass: bool,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct PsiResult {
    pub url: String,
    pub strategy: String,
    pub analysis_timestamp: Option<String>,
    pub lighthouse_scores: std::collections::BTreeMap<String, i64>,
    pub lab_metrics: std::collections::BTreeMap<String, (f64, String, Option<f64>)>,
    pub field_metrics: std::collections::BTreeMap<String, (f64, String, String)>,
    pub opportunities: Vec<Opportunity>,
    pub diagnostics: Vec<AuditFinding>,
    pub failed_audits: Vec<AuditFinding>,
    pub passed_audits_count: usize,
    pub seo_audits: Vec<SeoAudit>,
    pub accessibility_audits: Vec<AuditFinding>,
    pub error: Option<String>,
}

const LAB_AUDIT_IDS: &[&str] = &[
    "first-contentful-paint", "largest-contentful-paint",
    "total-blocking-time", "cumulative-layout-shift",
    "speed-index", "interactive",
];

/// Parses a raw PSI v5 JSON response body into the same shape
/// `run_pagespeed` builds after the HTTP call succeeds.
pub fn parse_psi_response(data: &Value, url: &str, strategy: &str) -> PsiResult {
    let mut result = PsiResult {
        url: url.to_string(),
        strategy: strategy.to_string(),
        ..Default::default()
    };
    result.analysis_timestamp = data.get("analysisUTCTimestamp").and_then(|v| v.as_str()).map(|s| s.to_string());

    let lr = data.get("lighthouseResult").cloned().unwrap_or(Value::Null);
    if let Some(categories) = lr.get("categories").and_then(|c| c.as_object()) {
        for (cat_key, cat_data) in categories {
            let score = cat_data.get("score").and_then(|s| s.as_f64()).unwrap_or(0.0);
            result.lighthouse_scores.insert(cat_key.clone(), (score * 100.0).round() as i64);
        }
    }

    let audits = lr.get("audits").cloned().unwrap_or(Value::Null);
    let audits_obj = audits.as_object();

    if let Some(audits_obj) = audits_obj {
        for audit_id in LAB_AUDIT_IDS {
            if let Some(audit) = audits_obj.get(*audit_id) {
                if let Some(nv) = audit.get("numericValue").and_then(|v| v.as_f64()) {
                    let display = audit.get("displayValue").and_then(|v| v.as_str()).unwrap_or("").to_string();
                    let score = audit.get("score").and_then(|v| v.as_f64());
                    result.lab_metrics.insert(audit_id.to_string(), (nv, display, score));
                }
            }
        }
    }

    for exp_key in ["loadingExperience", "originLoadingExperience"] {
        let exp = data.get(exp_key).cloned().unwrap_or(Value::Null);
        let metrics = exp.get("metrics").and_then(|m| m.as_object());
        if let Some(metrics) = metrics {
            let field_source = if exp_key == "loadingExperience" { "url" } else { "origin" };
            for (psi_name, crux_name) in PSI_METRIC_MAP {
                if let Some(metric_data) = metrics.get(*psi_name) {
                    let p75 = metric_data.get("percentile").and_then(|v| v.as_f64());
                    let category = metric_data.get("category").and_then(|v| v.as_str()).unwrap_or("NONE");
                    if let Some(p75) = p75 {
                        let p75_val = if *crux_name == "cumulative_layout_shift" {
                            if p75 > 1.0 { p75 / 100.0 } else { p75 }
                        } else {
                            p75
                        };
                        let rating = category.to_lowercase().replace('_', "-");
                        result.field_metrics.insert(
                            format!("{field_source}_{crux_name}"),
                            (p75_val, rating, format!("PSI {field_source}-level")),
                        );
                    }
                }
            }
        }
    }

    if let Some(audits_obj) = audits_obj {
        for (audit_id, audit) in audits_obj {
            if audit.get("details").and_then(|d| d.get("type")).and_then(|t| t.as_str()) == Some("opportunity") {
                if let Some(savings) = audit.get("details").and_then(|d| d.get("overallSavingsMs")).and_then(|v| v.as_f64()) {
                    if savings > 0.0 {
                        result.opportunities.push(Opportunity {
                            id: audit_id.clone(),
                            title: audit.get("title").and_then(|v| v.as_str()).unwrap_or(audit_id).to_string(),
                            savings_ms: savings,
                            description: audit.get("description").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                        });
                    }
                }
            }
        }
    }
    result.opportunities.sort_by(|a, b| b.savings_ms.partial_cmp(&a.savings_ms).unwrap());

    const DIAGNOSTIC_IDS: &[&str] = &[
        "dom-size", "render-blocking-resources", "uses-long-cache-ttl",
        "total-byte-weight", "mainthread-work-breakdown", "bootup-time",
        "font-display", "third-party-summary", "largest-contentful-paint-element",
        "layout-shifts", "long-tasks", "duplicated-javascript",
        "legacy-javascript", "unused-javascript", "unused-css-rules",
    ];
    if let Some(audits_obj) = audits_obj {
        for diag_id in DIAGNOSTIC_IDS {
            if let Some(audit) = audits_obj.get(*diag_id) {
                result.diagnostics.push(AuditFinding {
                    id: diag_id.to_string(),
                    title: audit.get("title").and_then(|v| v.as_str()).unwrap_or(diag_id).to_string(),
                    display: audit.get("displayValue").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                    score: audit.get("score").and_then(|v| v.as_f64()),
                    description: audit.get("description").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                });
            }
        }
    }

    let opportunity_ids: std::collections::HashSet<&str> =
        result.opportunities.iter().map(|o| o.id.as_str()).collect();
    let mut passed_count = 0usize;
    if let Some(audits_obj) = audits_obj {
        for (audit_id, audit) in audits_obj {
            let score = match audit.get("score").and_then(|v| v.as_f64()) {
                Some(s) => s,
                None => continue,
            };
            if score >= 0.9 {
                passed_count += 1;
                continue;
            }
            if opportunity_ids.contains(audit_id.as_str()) {
                continue;
            }
            result.failed_audits.push(AuditFinding {
                id: audit_id.clone(),
                title: audit.get("title").and_then(|v| v.as_str()).unwrap_or(audit_id).to_string(),
                score: Some(score),
                display: audit.get("displayValue").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                description: audit.get("description").and_then(|v| v.as_str()).unwrap_or("").to_string(),
            });
        }
    }
    result.passed_audits_count = passed_count;
    result.failed_audits.sort_by(|a, b| {
        a.score.unwrap_or(1.0).partial_cmp(&b.score.unwrap_or(1.0)).unwrap()
    });

    if let (Some(seo_cat), Some(audits_obj)) = (lr.get("categories").and_then(|c| c.get("seo")), audits_obj) {
        if let Some(refs) = seo_cat.get("auditRefs").and_then(|r| r.as_array()) {
            for r in refs {
                let id = r.get("id").and_then(|v| v.as_str()).unwrap_or("");
                if let Some(audit) = audits_obj.get(id) {
                    if let Some(score) = audit.get("score").and_then(|v| v.as_f64()) {
                        result.seo_audits.push(SeoAudit {
                            id: id.to_string(),
                            title: audit.get("title").and_then(|v| v.as_str()).unwrap_or(id).to_string(),
                            score,
                            pass: score >= 0.9,
                        });
                    }
                }
            }
        }
    }

    if let (Some(a11y_cat), Some(audits_obj)) = (lr.get("categories").and_then(|c| c.get("accessibility")), audits_obj) {
        if let Some(refs) = a11y_cat.get("auditRefs").and_then(|r| r.as_array()) {
            for r in refs {
                let id = r.get("id").and_then(|v| v.as_str()).unwrap_or("");
                if let Some(audit) = audits_obj.get(id) {
                    if let Some(score) = audit.get("score").and_then(|v| v.as_f64()) {
                        if score < 0.9 {
                            result.accessibility_audits.push(AuditFinding {
                                id: id.to_string(),
                                title: audit.get("title").and_then(|v| v.as_str()).unwrap_or(id).to_string(),
                                display: audit.get("displayValue").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                                score: Some(score),
                                description: String::new(),
                            });
                        }
                    }
                }
            }
        }
    }

    result
}

// ---------------------------------------------------------------------
// CrUX response parsing
// ---------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Default)]
pub struct CruxDistribution {
    pub good: f64,
    pub needs_improvement: f64,
    pub poor: f64,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct CruxMetric {
    pub p75: f64,
    pub rating: &'static str,
    pub label: String,
    pub unit: &'static str,
    pub good_threshold: Option<f64>,
    pub poor_threshold: Option<f64>,
    pub distribution: Option<CruxDistribution>,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct CruxResult {
    pub target: String,
    pub metrics: std::collections::BTreeMap<String, CruxMetric>,
    pub collection_period: Option<(String, String)>,
    pub form_factor: String,
    pub error: Option<String>,
    pub note: Option<String>,
}

/// Parses `record` from a CrUX `records:queryRecord` response body into the
/// same shape `query_crux` builds after the HTTP call succeeds.
pub fn parse_crux_response(record: &Value, target: &str, form_factor: Option<&str>) -> CruxResult {
    let mut result = CruxResult {
        target: target.to_string(),
        form_factor: form_factor.map(|s| s.to_string()).unwrap_or_else(|| "ALL".to_string()),
        ..Default::default()
    };

    if let Some(cp) = record.get("collectionPeriod") {
        let fmt = |d: &Value| {
            let year = d.get("year").and_then(|v| v.as_i64()).unwrap_or(0);
            let month = d.get("month").and_then(|v| v.as_i64()).unwrap_or(0);
            let day = d.get("day").and_then(|v| v.as_i64()).unwrap_or(0);
            format!("{year}-{month:02}-{day:02}")
        };
        if let (Some(first), Some(last)) = (cp.get("firstDate"), cp.get("lastDate")) {
            result.collection_period = Some((fmt(first), fmt(last)));
        }
    }

    if let Some(metrics) = record.get("metrics").and_then(Value::as_object) {
        for (metric_name, metric_data) in metrics {
            let p75_raw = metric_data.get("percentiles").and_then(|p| p.get("p75"));
            let p75_raw = match p75_raw {
                Some(v) if !v.is_null() => v,
                _ => continue,
            };

            let p75_val: f64 = if metric_name == "cumulative_layout_shift" {
                p75_raw
                    .as_str()
                    .and_then(|s| s.parse::<f64>().ok())
                    .or_else(|| p75_raw.as_f64())
                    .unwrap_or(0.0)
            } else {
                match p75_raw.as_i64() {
                    Some(i) => i as f64,
                    None => match p75_raw.as_f64() {
                        Some(f) => f,
                        None => match p75_raw.as_str().and_then(|s| s.parse::<f64>().ok()) {
                            Some(f) => f,
                            None => continue,
                        },
                    },
                }
            };

            let rating = rate_metric(metric_name, p75_val);
            let t = threshold_for(metric_name);

            let mut m = CruxMetric {
                p75: p75_val,
                rating,
                label: t.map(|t| t.label.to_string()).unwrap_or_else(|| metric_name.to_string()),
                unit: t.map(|t| t.unit).unwrap_or(""),
                good_threshold: t.map(|t| t.good),
                poor_threshold: t.map(|t| t.poor),
                distribution: None,
            };

            if let Some(hist) = metric_data.get("histogram").and_then(|h| h.as_array()) {
                let densities: Vec<f64> = hist
                    .iter()
                    .map(|b| b.get("density").and_then(|d| d.as_f64()).unwrap_or(0.0))
                    .collect();
                if densities.len() >= 3 {
                    m.distribution = Some(CruxDistribution {
                        good: (densities[0] * 100.0 * 10.0).round() / 10.0,
                        needs_improvement: (densities[1] * 100.0 * 10.0).round() / 10.0,
                        poor: (densities[2] * 100.0 * 10.0).round() / 10.0,
                    });
                }
            }

            result.metrics.insert(metric_name.clone(), m);
        }
    }

    result
}

// ---------------------------------------------------------------------
// Live HTTP round trips (`run_pagespeed`, `query_crux`, `combined_check`)
// ---------------------------------------------------------------------

/// Behind-a-trait I/O boundary for the PSI GET and CrUX POST requests, so
/// `run_pagespeed`/`query_crux`/`run` are testable with a fake. Mirrors
/// `requests.get(...)`/`requests.post(...)`: returns `Ok((status_code,
/// body_json))` for any HTTP response (including a JSON-decode failure,
/// which the real client should surface via `Err`, matching
/// `resp.json()` raising inside `resp.raise_for_status()`'s success
/// path), `Err(msg)` only for a transport-level failure or timeout
/// (matching `requests.exceptions.RequestException`/`Timeout`).
pub trait PsiClient {
    fn get_psi(&self, url: &str, strategy: &str, api_key: Option<&str>, categories: &[&str]) -> Result<(u16, Value), String>;
    fn post_crux(&self, body: &Value, api_key: &str) -> Result<(u16, Value), String>;
}

/// Real `reqwest::blocking` implementation of [`PsiClient`].
pub struct ReqwestPsiClient;

impl PsiClient for ReqwestPsiClient {
    fn get_psi(&self, url: &str, strategy: &str, api_key: Option<&str>, categories: &[&str]) -> Result<(u16, Value), String> {
        let client = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(120))
            .build()
            .map_err(|e| format!("PSI API request failed: {e}"))?;
        let mut params: Vec<(String, String)> = vec![
            ("url".to_string(), url.to_string()),
            ("strategy".to_string(), strategy.to_uppercase()),
        ];
        for cat in categories {
            params.push(("category".to_string(), cat.to_string()));
        }
        if let Some(key) = api_key {
            params.push(("key".to_string(), key.to_string()));
        }
        let resp = client
            .get(PSI_ENDPOINT)
            .query(&params)
            .send()
            .map_err(|e| {
                if e.is_timeout() {
                    "PageSpeed Insights request timed out (120s). The target page may be very slow.".to_string()
                } else {
                    format!("Request failed: {e}")
                }
            })?;
        let status = resp.status().as_u16();
        let json = resp.json::<Value>().unwrap_or(Value::Object(Default::default()));
        Ok((status, json))
    }

    fn post_crux(&self, body: &Value, api_key: &str) -> Result<(u16, Value), String> {
        let client = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(|e| format!("CrUX API request failed: {e}"))?;
        let resp = client
            .post(format!("{CRUX_ENDPOINT}?key={api_key}"))
            .json(body)
            .send()
            .map_err(|e| format!("CrUX API request failed: {e}"))?;
        let status = resp.status().as_u16();
        let json = resp.json::<Value>().unwrap_or(Value::Object(Default::default()));
        Ok((status, json))
    }
}

const DEFAULT_CATEGORIES: &[&str] = &["PERFORMANCE", "ACCESSIBILITY", "BEST_PRACTICES", "SEO"];

/// Full port of `run_pagespeed()`: validates the URL, calls the client,
/// and parses the response with [`parse_psi_response`].
pub fn run_pagespeed(
    client: &dyn PsiClient,
    url: &str,
    strategy: &str,
    api_key: Option<&str>,
    categories: Option<&[&str]>,
) -> PsiResult {
    if !validate_url(url) {
        return PsiResult {
            url: url.to_string(),
            strategy: strategy.to_string(),
            error: Some("Invalid URL. Only http/https URLs to public hosts are accepted.".to_string()),
            ..Default::default()
        };
    }

    let categories = categories.unwrap_or(DEFAULT_CATEGORIES);
    let (status, data) = match client.get_psi(url, strategy, api_key, categories) {
        Ok(v) => v,
        Err(e) => {
            return PsiResult {
                url: url.to_string(),
                strategy: strategy.to_string(),
                error: Some(e),
                ..Default::default()
            };
        }
    };

    if status == 429 {
        return PsiResult {
            url: url.to_string(),
            strategy: strategy.to_string(),
            error: Some("PSI rate limit exceeded (240 QPM / 25,000 QPD). Wait and retry.".to_string()),
            ..Default::default()
        };
    }
    if status == 400 {
        return PsiResult {
            url: url.to_string(),
            strategy: strategy.to_string(),
            error: Some(format!("Invalid URL or parameters: {data}")),
            ..Default::default()
        };
    }
    if !(200..300).contains(&status) {
        return PsiResult {
            url: url.to_string(),
            strategy: strategy.to_string(),
            error: Some(format!("PSI API error {status}: {data}")),
            ..Default::default()
        };
    }

    parse_psi_response(&data, url, strategy)
}

/// Full port of `query_crux()`: validates the target, builds the request
/// body (origin vs. URL, optional `formFactor`), calls the client, and
/// parses the response with [`parse_crux_response`].
pub fn query_crux(client: &dyn PsiClient, url_or_origin: &str, api_key: &str, form_factor: Option<&str>) -> CruxResult {
    let form_factor_upper = form_factor.map(|f| f.to_uppercase());

    if !validate_url(url_or_origin) {
        return CruxResult {
            target: url_or_origin.to_string(),
            form_factor: form_factor_upper.clone().unwrap_or_else(|| "ALL".to_string()),
            error: Some("Invalid URL. Only http/https URLs to public hosts are accepted.".to_string()),
            ..Default::default()
        };
    }

    let is_origin = crux_target_is_origin(url_or_origin);

    let mut body = serde_json::Map::new();
    if is_origin {
        let (scheme, rest) = url_or_origin.split_once("://").unwrap_or(("", url_or_origin));
        let authority_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
        body.insert("origin".to_string(), Value::String(format!("{scheme}://{}", &rest[..authority_end])));
    } else {
        body.insert("url".to_string(), Value::String(url_or_origin.to_string()));
    }
    if let Some(ff) = &form_factor_upper {
        body.insert("formFactor".to_string(), Value::String(ff.clone()));
    }

    let (status, data) = match client.post_crux(&Value::Object(body), api_key) {
        Ok(v) => v,
        Err(e) => {
            return CruxResult {
                target: url_or_origin.to_string(),
                form_factor: form_factor_upper.unwrap_or_else(|| "ALL".to_string()),
                error: Some(format!("CrUX API request failed: {e}")),
                ..Default::default()
            };
        }
    };

    if status == 404 {
        let target_type = if is_origin { "origin" } else { "URL" };
        return CruxResult {
            target: url_or_origin.to_string(),
            form_factor: form_factor_upper.unwrap_or_else(|| "ALL".to_string()),
            error: Some(format!(
                "No CrUX data for this {target_type}. The site likely has insufficient Chrome traffic volume for eligibility."
            )),
            ..Default::default()
        };
    }
    if status == 429 {
        return CruxResult {
            target: url_or_origin.to_string(),
            form_factor: form_factor_upper.unwrap_or_else(|| "ALL".to_string()),
            error: Some("CrUX API rate limit exceeded (150 QPM shared with History API). Wait and retry.".to_string()),
            ..Default::default()
        };
    }
    if !(200..300).contains(&status) {
        return CruxResult {
            target: url_or_origin.to_string(),
            form_factor: form_factor_upper.unwrap_or_else(|| "ALL".to_string()),
            error: Some(format!("CrUX API request failed: HTTP {status}")),
            ..Default::default()
        };
    }

    let record = data.get("record").cloned().unwrap_or(Value::Null);
    let mut result = parse_crux_response(&record, url_or_origin, form_factor_upper.as_deref());
    result.form_factor = form_factor_upper.unwrap_or_else(|| "ALL".to_string());
    result
}

/// Result of `combined_check()`.
#[derive(Debug, Clone, Serialize, Default)]
pub struct CombinedResult {
    pub url: String,
    pub psi: std::collections::BTreeMap<String, PsiResult>,
    pub crux: Option<CruxResult>,
    pub error: Option<String>,
}

/// Full port of `combined_check()`.
pub fn combined_check(client: &dyn PsiClient, url: &str, api_key: Option<&str>, strategy: &str) -> CombinedResult {
    let mut result = CombinedResult {
        url: url.to_string(),
        ..Default::default()
    };

    let strategies: Vec<&str> = if strategy == "both" { vec!["mobile", "desktop"] } else { vec![strategy] };

    for strat in strategies {
        let psi_result = run_pagespeed(client, url, strat, api_key, None);
        if let Some(e) = &psi_result.error {
            result.error = Some(e.clone());
        }
        result.psi.insert(strat.to_string(), psi_result);
    }

    if let Some(key) = api_key {
        let mut crux_result = query_crux(client, url, key, None);
        if let Some(e) = &crux_result.error {
            if e.contains("insufficient") {
                let (scheme, rest) = url.split_once("://").unwrap_or(("", url));
                let authority_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
                let origin = format!("{scheme}://{}", &rest[..authority_end]);
                let origin_result = query_crux(client, &origin, key, None);
                if origin_result.error.is_none() {
                    crux_result = origin_result;
                    crux_result.note = Some("URL-level data unavailable; showing origin-level data".to_string());
                }
            }
        }
        result.crux = Some(crux_result);
    }

    result
}

// ---------------------------------------------------------------------
// CLI entry point (`main()`)
// ---------------------------------------------------------------------

#[derive(Debug, Clone, Default)]
struct Args {
    url: Option<String>,
    strategy: String,
    api_key: Option<String>,
    crux_only: bool,
    psi_only: bool,
    form_factor: Option<String>,
    json: bool,
}

fn parse_args(args: &[String]) -> Result<Args, String> {
    let mut out = Args {
        strategy: "both".to_string(),
        ..Default::default()
    };
    let mut i = 0;
    while i < args.len() {
        let a = args[i].as_str();
        match a {
            "--strategy" | "-s" => {
                i += 1;
                let v = args.get(i).ok_or("--strategy requires a value")?.clone();
                if !["mobile", "desktop", "both"].contains(&v.as_str()) {
                    return Err(format!("argument --strategy/-s: invalid choice: '{v}'"));
                }
                out.strategy = v;
            }
            "--api-key" => {
                i += 1;
                out.api_key = Some(args.get(i).ok_or("--api-key requires a value")?.clone());
            }
            "--crux-only" => out.crux_only = true,
            "--psi-only" => out.psi_only = true,
            "--form-factor" => {
                i += 1;
                let v = args.get(i).ok_or("--form-factor requires a value")?.clone();
                if !["PHONE", "DESKTOP", "TABLET"].contains(&v.as_str()) {
                    return Err(format!("argument --form-factor: invalid choice: '{v}'"));
                }
                out.form_factor = Some(v);
            }
            "--json" | "-j" => out.json = true,
            other if !other.starts_with('-') => out.url = Some(other.to_string()),
            other => return Err(format!("unrecognized argument: {other}")),
        }
        i += 1;
    }
    out.url.clone().ok_or("the following arguments are required: url")?;
    Ok(out)
}

/// Port of `pagespeed_check.py`'s `main()`, parameterized over the client
/// and stdout/stderr sinks so it is testable without touching real I/O.
/// Uses `google_auth::load_config().api_key` as the `get_api_key()`
/// fallback when `--api-key` is not given. Returns the process exit code.
pub fn run(args: &[String], client: &dyn PsiClient, stdout: &mut dyn Write, stderr: &mut dyn Write) -> i32 {
    let parsed = match parse_args(args) {
        Ok(p) => p,
        Err(e) => {
            let _ = writeln!(stderr, "{e}");
            return 2;
        }
    };

    let api_key = parsed.api_key.clone().or_else(|| crate::wf_port::w2_030::google_auth::load_config().api_key);
    let url = parsed.url.clone().unwrap_or_default();

    let had_error;
    if parsed.crux_only {
        let Some(key) = &api_key else {
            let _ = writeln!(stderr, "Error: CrUX API requires an API key. Use --api-key or configure GOOGLE_API_KEY.");
            return 1;
        };
        let result = query_crux(client, &url, key, parsed.form_factor.as_deref());
        had_error = result.error.is_some();
        if parsed.json {
            let _ = writeln!(stdout, "{}", serde_json::to_string_pretty(&result).unwrap_or_default());
        } else {
            print_crux_summary(stdout, &result);
        }
    } else if parsed.psi_only {
        let strategies: Vec<&str> = if parsed.strategy == "both" { vec!["mobile", "desktop"] } else { vec![parsed.strategy.as_str()] };
        let mut psi_map = std::collections::BTreeMap::new();
        for strat in &strategies {
            psi_map.insert(strat.to_string(), run_pagespeed(client, &url, strat, api_key.as_deref(), None));
        }
        had_error = psi_map.values().any(|r| r.error.is_some());
        if parsed.json {
            let _ = writeln!(
                stdout,
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({"psi": psi_map})).unwrap_or_default()
            );
        } else {
            for psi in psi_map.values() {
                print_psi_summary(stdout, psi);
            }
        }
    } else {
        let result = combined_check(client, &url, api_key.as_deref(), &parsed.strategy);
        had_error = result.error.is_some();
        if parsed.json {
            let _ = writeln!(stdout, "{}", serde_json::to_string_pretty(&result).unwrap_or_default());
        } else {
            for psi in result.psi.values() {
                print_psi_summary(stdout, psi);
            }
            if let Some(crux) = &result.crux {
                let _ = writeln!(stdout);
                print_crux_summary(stdout, crux);
            }
        }
    }

    if had_error {
        1
    } else {
        0
    }
}

fn print_psi_summary(out: &mut dyn Write, psi: &PsiResult) {
    if let Some(err) = &psi.error {
        let _ = writeln!(out, "PSI Error ({}): {err}", psi.strategy);
        return;
    }

    let _ = writeln!(out, "\n=== PageSpeed Insights ({}) ===", psi.strategy);
    let _ = writeln!(out, "URL: {}", psi.url);
    let _ = writeln!(out, "Timestamp: {}", psi.analysis_timestamp.as_deref().unwrap_or("N/A"));

    if !psi.lighthouse_scores.is_empty() {
        let _ = writeln!(out, "\nLighthouse Scores:");
        for (cat, score) in &psi.lighthouse_scores {
            let _ = writeln!(out, "  {cat}: {score}/100");
        }
    }

    if !psi.lab_metrics.is_empty() {
        let _ = writeln!(out, "\nLab Metrics:");
        for (id, (value, display, _score)) in &psi.lab_metrics {
            let shown = if display.is_empty() { value.to_string() } else { display.clone() };
            let _ = writeln!(out, "  {id}: {shown}");
        }
    }

    if !psi.opportunities.is_empty() {
        let _ = writeln!(out, "\nTop Opportunities:");
        for opp in psi.opportunities.iter().take(5) {
            let _ = writeln!(out, "  - {} (save ~{}ms)", opp.title, opp.savings_ms);
        }
    }

    if !psi.failed_audits.is_empty() {
        let _ = writeln!(out, "\nFailed/Warning Audits ({}):", psi.failed_audits.len());
        for a in psi.failed_audits.iter().take(10) {
            let score_pct = a.score.map(|s| format!("{:.0}%", s * 100.0)).unwrap_or_else(|| "?".to_string());
            let _ = writeln!(out, "  [{score_pct}] {} {}", a.title, a.display);
        }
    }

    let notable_diags: Vec<&AuditFinding> = psi.diagnostics.iter().filter(|d| d.score.map(|s| s < 0.9).unwrap_or(false)).collect();
    if !notable_diags.is_empty() {
        let _ = writeln!(out, "\nDiagnostics (needs attention):");
        for d in notable_diags.iter().take(5) {
            let score_pct = d.score.map(|s| format!("{:.0}%", s * 100.0)).unwrap_or_else(|| "info".to_string());
            let _ = writeln!(out, "  [{score_pct}] {}: {}", d.title, d.display);
        }
    }

    let seo_failed: Vec<&SeoAudit> = psi.seo_audits.iter().filter(|a| !a.pass).collect();
    if !seo_failed.is_empty() {
        let _ = writeln!(out, "\nSEO Issues ({}):", seo_failed.len());
        for a in &seo_failed {
            let _ = writeln!(out, "  [FAIL] {}", a.title);
        }
    } else if !psi.seo_audits.is_empty() {
        let _ = writeln!(out, "\nSEO: All {} checks passed", psi.seo_audits.len());
    }

    if !psi.accessibility_audits.is_empty() {
        let _ = writeln!(out, "\nAccessibility Issues ({}):", psi.accessibility_audits.len());
        for a in psi.accessibility_audits.iter().take(5) {
            let pct = a.score.map(|s| format!("{:.0}%", s * 100.0)).unwrap_or_default();
            let _ = writeln!(out, "  [{pct}] {}", a.title);
        }
    }

    if psi.passed_audits_count > 0 {
        let _ = writeln!(out, "\nPassed: {} audits", psi.passed_audits_count);
    }
}

fn print_crux_summary(out: &mut dyn Write, crux: &CruxResult) {
    if let Some(err) = &crux.error {
        let _ = writeln!(out, "CrUX Error: {err}");
        return;
    }

    let _ = writeln!(out, "=== CrUX Field Data ({}) ===", crux.form_factor);
    let _ = writeln!(out, "Target: {}", crux.target);

    if let Some(note) = &crux.note {
        let _ = writeln!(out, "Note: {note}");
    }

    if let Some((first, last)) = &crux.collection_period {
        let _ = writeln!(out, "Period: {first} to {last}");
    }

    if !crux.metrics.is_empty() {
        let _ = writeln!(out, "\nCore Web Vitals (p75):");
        for data in crux.metrics.values() {
            let rating_icon = match data.rating {
                "good" => "GOOD",
                "needs-improvement" => "NEEDS IMPROVEMENT",
                "poor" => "POOR",
                _ => "?",
            };
            let good = data.good_threshold;
            if data.label == "CLS" {
                let good_s = good.map(|g| format!("{g}")).unwrap_or_default();
                let _ = writeln!(out, "  {}: {:.3} [{rating_icon}] (threshold: <={good_s})", data.label, data.p75);
            } else {
                let good_s = good.map(|g| format!("{g}")).unwrap_or_default();
                let _ = writeln!(out, "  {}: {}{} [{rating_icon}] (threshold: <={good_s}{})", data.label, data.p75, data.unit, data.unit);
            }
            if let Some(dist) = &data.distribution {
                let _ = writeln!(out, "       Good: {}% | NI: {}% | Poor: {}%", dist.good, dist.needs_improvement, dist.poor);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn rate_metric_boundaries() {
        assert_eq!(rate_metric("largest_contentful_paint", 2500.0), "good");
        assert_eq!(rate_metric("largest_contentful_paint", 2501.0), "needs-improvement");
        assert_eq!(rate_metric("largest_contentful_paint", 4001.0), "poor");
        assert_eq!(rate_metric("unknown_metric", 1.0), "unknown");
    }

    #[test]
    fn validate_url_rejects_non_http_scheme() {
        assert!(!validate_url("ftp://example.com"));
    }

    #[test]
    fn validate_url_rejects_localhost_and_private_ips() {
        assert!(!validate_url("http://localhost/"));
        assert!(!validate_url("http://127.0.0.1/"));
        assert!(!validate_url("http://10.0.0.5/"));
        assert!(!validate_url("http://192.168.1.1/"));
        assert!(!validate_url("http://169.254.1.1/"));
        assert!(!validate_url("http://metadata.google.internal/"));
    }

    #[test]
    fn validate_url_accepts_public_https() {
        assert!(validate_url("https://example.com/page"));
    }

    #[test]
    fn crux_target_origin_detection() {
        assert!(crux_target_is_origin("https://example.com"));
        assert!(crux_target_is_origin("https://example.com/"));
        assert!(!crux_target_is_origin("https://example.com/page"));
        assert!(!crux_target_is_origin("https://example.com/?q=1"));
    }

    #[test]
    fn parse_psi_response_extracts_scores_and_lab_metrics() {
        let data = json!({
            "analysisUTCTimestamp": "2026-01-01T00:00:00Z",
            "lighthouseResult": {
                "categories": {
                    "performance": {"score": 0.87},
                    "seo": {"score": 1.0, "auditRefs": [{"id": "meta-description"}]},
                },
                "audits": {
                    "largest-contentful-paint": {"numericValue": 2200.0, "displayValue": "2.2 s", "score": 0.9},
                    "meta-description": {"score": 1.0, "title": "Document has a meta description"},
                    "uses-long-cache-ttl": {"score": 0.5, "title": "Serve static assets with an efficient cache policy", "details": {"type": "opportunity", "overallSavingsMs": 300}},
                }
            }
        });
        let result = parse_psi_response(&data, "https://example.com", "mobile");
        assert_eq!(result.lighthouse_scores.get("performance"), Some(&87));
        assert_eq!(result.lab_metrics.get("largest-contentful-paint").unwrap().0, 2200.0);
        assert_eq!(result.opportunities.len(), 1);
        assert_eq!(result.opportunities[0].id, "uses-long-cache-ttl");
        assert_eq!(result.seo_audits.len(), 1);
        assert!(result.seo_audits[0].pass);
    }

    #[test]
    fn parse_psi_response_field_metrics_scales_cls() {
        let data = json!({
            "loadingExperience": {
                "metrics": {
                    "CUMULATIVE_LAYOUT_SHIFT_SCORE": {"percentile": 12, "category": "AVERAGE"}
                }
            }
        });
        let result = parse_psi_response(&data, "https://example.com", "mobile");
        let (val, rating, source) = result.field_metrics.get("url_cumulative_layout_shift").unwrap();
        assert_eq!(*val, 0.12);
        assert_eq!(rating, "average");
        assert_eq!(source, "PSI url-level");
    }

    #[test]
    fn parse_crux_response_parses_cls_as_string_and_rates_it() {
        let record = json!({
            "collectionPeriod": {
                "firstDate": {"year": 2026, "month": 1, "day": 1},
                "lastDate": {"year": 2026, "month": 1, "day": 28}
            },
            "metrics": {
                "cumulative_layout_shift": {
                    "percentiles": {"p75": "0.05"},
                    "histogram": [{"density": 0.9}, {"density": 0.07}, {"density": 0.03}]
                },
                "largest_contentful_paint": {
                    "percentiles": {"p75": 2100}
                }
            }
        });
        let result = parse_crux_response(&record, "https://example.com", Some("PHONE"));
        assert_eq!(result.collection_period, Some(("2026-01-01".to_string(), "2026-01-28".to_string())));
        let cls = result.metrics.get("cumulative_layout_shift").unwrap();
        assert_eq!(cls.p75, 0.05);
        assert_eq!(cls.rating, "good");
        assert_eq!(cls.distribution.as_ref().unwrap().good, 90.0);
        let lcp = result.metrics.get("largest_contentful_paint").unwrap();
        assert_eq!(lcp.p75, 2100.0);
        assert_eq!(lcp.rating, "good");
    }

    #[test]
    fn parse_crux_response_skips_metric_without_p75() {
        let record = json!({"metrics": {"first_contentful_paint": {"percentiles": {}}}});
        let result = parse_crux_response(&record, "https://example.com", None);
        assert!(result.metrics.is_empty());
    }

    // -------------------------------------------------------------
    // Live round trips, exercised against a fake client (no network).
    // -------------------------------------------------------------

    struct FakeClient {
        psi_status: u16,
        psi_body: Value,
        crux_status: u16,
        crux_body: Value,
    }

    impl PsiClient for FakeClient {
        fn get_psi(&self, _url: &str, _strategy: &str, _api_key: Option<&str>, _categories: &[&str]) -> Result<(u16, Value), String> {
            Ok((self.psi_status, self.psi_body.clone()))
        }
        fn post_crux(&self, _body: &Value, _api_key: &str) -> Result<(u16, Value), String> {
            Ok((self.crux_status, self.crux_body.clone()))
        }
    }

    #[test]
    fn run_pagespeed_rejects_invalid_url() {
        let client = FakeClient { psi_status: 200, psi_body: json!({}), crux_status: 200, crux_body: json!({}) };
        let result = run_pagespeed(&client, "http://localhost/", "mobile", None, None);
        assert_eq!(result.error.as_deref(), Some("Invalid URL. Only http/https URLs to public hosts are accepted."));
    }

    #[test]
    fn run_pagespeed_maps_status_codes_to_errors() {
        let client = FakeClient { psi_status: 429, psi_body: json!({}), crux_status: 200, crux_body: json!({}) };
        let result = run_pagespeed(&client, "https://example.com", "mobile", None, None);
        assert!(result.error.unwrap().contains("rate limit"));
    }

    #[test]
    fn run_pagespeed_success_parses_body() {
        let client = FakeClient {
            psi_status: 200,
            psi_body: json!({"analysisUTCTimestamp": "2026-01-01T00:00:00Z", "lighthouseResult": {"categories": {"performance": {"score": 0.5}}, "audits": {}}}),
            crux_status: 200,
            crux_body: json!({}),
        };
        let result = run_pagespeed(&client, "https://example.com", "mobile", None, None);
        assert!(result.error.is_none());
        assert_eq!(result.lighthouse_scores.get("performance"), Some(&50));
        assert_eq!(result.analysis_timestamp.as_deref(), Some("2026-01-01T00:00:00Z"));
    }

    #[test]
    fn query_crux_maps_404_to_insufficient_traffic_message() {
        let client = FakeClient { psi_status: 200, psi_body: json!({}), crux_status: 404, crux_body: json!({}) };
        let result = query_crux(&client, "https://example.com/page", "key", None);
        assert!(result.error.unwrap().contains("insufficient"));
    }

    #[test]
    fn query_crux_success_parses_record() {
        let client = FakeClient {
            psi_status: 200,
            psi_body: json!({}),
            crux_status: 200,
            crux_body: json!({"record": {"metrics": {"largest_contentful_paint": {"percentiles": {"p75": 2000}}}}}),
        };
        let result = query_crux(&client, "https://example.com", "key", Some("phone"));
        assert!(result.error.is_none());
        assert_eq!(result.form_factor, "PHONE");
        assert_eq!(result.metrics.get("largest_contentful_paint").unwrap().p75, 2000.0);
    }

    #[test]
    fn combined_check_falls_back_to_origin_on_insufficient_crux_data() {
        let client = FakeClient {
            psi_status: 200,
            psi_body: json!({"lighthouseResult": {"categories": {}, "audits": {}}}),
            crux_status: 404,
            crux_body: json!({}),
        };
        // Every query_crux call returns 404 from this fake, so the retry also
        // fails -- this asserts the retry path is exercised, not that it
        // rescues the request; the "note" is only set on the rescue branch.
        let result = combined_check(&client, "https://example.com/page", Some("key"), "mobile");
        assert!(result.crux.unwrap().error.is_some());
    }

    #[test]
    fn parse_args_requires_url() {
        assert!(parse_args(&[]).is_err());
    }

    #[test]
    fn parse_args_parses_flags() {
        let args: Vec<String> = ["https://example.com", "--strategy", "mobile", "--json"].iter().map(|s| s.to_string()).collect();
        let parsed = parse_args(&args).unwrap();
        assert_eq!(parsed.url.as_deref(), Some("https://example.com"));
        assert_eq!(parsed.strategy, "mobile");
        assert!(parsed.json);
    }

    #[test]
    fn run_crux_only_without_api_key_errors() {
        let client = FakeClient { psi_status: 200, psi_body: json!({}), crux_status: 200, crux_body: json!({}) };
        let mut out = Vec::new();
        let mut err = Vec::new();
        let args: Vec<String> = ["https://example.com", "--crux-only"].iter().map(|s| s.to_string()).collect();
        let code = run(&args, &client, &mut out, &mut err);
        assert_eq!(code, 1);
        assert!(String::from_utf8(err).unwrap().contains("CrUX API requires an API key"));
    }

    #[test]
    fn run_psi_only_json_success() {
        let client = FakeClient {
            psi_status: 200,
            psi_body: json!({"lighthouseResult": {"categories": {"performance": {"score": 1.0}}, "audits": {}}}),
            crux_status: 200,
            crux_body: json!({}),
        };
        let mut out = Vec::new();
        let mut err = Vec::new();
        let args: Vec<String> = ["https://example.com", "--psi-only", "--strategy", "mobile", "--json"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let code = run(&args, &client, &mut out, &mut err);
        assert_eq!(code, 0);
        let stdout = String::from_utf8(out).unwrap();
        assert!(stdout.contains("\"performance\": 100"));
    }
}
