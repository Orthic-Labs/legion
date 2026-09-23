//! Port of `skills/seo/scripts/pagespeed_check.py`.
//!
//! This crate has no HTTP client dependency (see the module doc in
//! `super`), so the live PSI/CrUX round trips (`requests.get`/`requests.post`
//! in `run_pagespeed`/`query_crux`) are not ported. Everything that is pure
//! — CWV thresholds and rating, URL validation, the origin-vs-URL decision
//! for a CrUX target, and the response-JSON parsing that turns a raw PSI or
//! CrUX JSON body into the same structured result the Python returns — is
//! ported in full. Callers that fetch the JSON themselves (their own HTTP
//! client) can feed it straight into `parse_psi_response`/
//! `parse_crux_response`.

use serde::Serialize;
use serde_json::Value;

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
    pub lighthouse_scores: std::collections::BTreeMap<String, i64>,
    pub lab_metrics: std::collections::BTreeMap<String, (f64, String, Option<f64>)>,
    pub field_metrics: std::collections::BTreeMap<String, (f64, String, String)>,
    pub opportunities: Vec<Opportunity>,
    pub diagnostics: Vec<AuditFinding>,
    pub failed_audits: Vec<AuditFinding>,
    pub passed_audits_count: usize,
    pub seo_audits: Vec<SeoAudit>,
    pub accessibility_audits: Vec<AuditFinding>,
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
    pub label: &'static str,
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

    if let Some(metrics) = record.get("metrics").and_then(|m| m.as_object()) {
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
                label: t.map(|t| t.label).unwrap_or(metric_name),
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
}
