//! Port of `skills/seo/scripts/crux_history.py`, plus `validate_url` from
//! `skills/seo/scripts/google_auth.py` (which `crux_history.py` imports).
//!
//! The HTTP call to the Chrome UX Report History API is not ported (no
//! network I/O in this chunk); [`parse_history_record`] ports the pure
//! JSON-in/JSON-out transform that `query_history()` applies to the
//! response body after `resp.json()`, and [`detect_trends`] ports the
//! standalone `detect_trends()` function verbatim.

use std::collections::BTreeMap;
use std::net::IpAddr;

use serde::Serialize;
use serde_json::Value;

/// A `(good, poor, label, unit)` threshold row, mirroring
/// Python's `CWV_THRESHOLDS`.
struct Threshold {
    good: f64,
    poor: f64,
    label: &'static str,
    unit: &'static str,
}

fn thresholds() -> &'static BTreeMap<&'static str, Threshold> {
    use std::sync::OnceLock;
    static MAP: OnceLock<BTreeMap<&'static str, Threshold>> = OnceLock::new();
    MAP.get_or_init(|| {
        let mut m = BTreeMap::new();
        m.insert(
            "largest_contentful_paint",
            Threshold {
                good: 2500.0,
                poor: 4000.0,
                label: "LCP",
                unit: "ms",
            },
        );
        m.insert(
            "interaction_to_next_paint",
            Threshold {
                good: 200.0,
                poor: 500.0,
                label: "INP",
                unit: "ms",
            },
        );
        m.insert(
            "cumulative_layout_shift",
            Threshold {
                good: 0.1,
                poor: 0.25,
                label: "CLS",
                unit: "",
            },
        );
        m.insert(
            "first_contentful_paint",
            Threshold {
                good: 1800.0,
                poor: 3000.0,
                label: "FCP",
                unit: "ms",
            },
        );
        m.insert(
            "experimental_time_to_first_byte",
            Threshold {
                good: 800.0,
                poor: 1800.0,
                label: "TTFB",
                unit: "ms",
            },
        );
        m
    })
}

/// Mirrors Python `validate_url` from `google_auth.py`: only public
/// http/https URLs are accepted. Like the Python function, this checks
/// the hostname against a blocklist and, when the hostname is itself an
/// IP literal, against `is_private`/`is_loopback`/`is_link_local`; it does
/// not perform DNS resolution, so a hostname that merely *resolves* to a
/// private address (the separate SSRF check `fetch_page.py` does after a
/// `socket.gethostbyname` call) is not caught here — matching the Python
/// source, where `validate_url` and the DNS-based SSRF check are two
/// different functions in two different scripts.
pub fn validate_url(url: &str) -> bool {
    validate_parsed_url(url).unwrap_or(false)
}

/// Standalone helper doing the actual field-by-field check against a raw
/// URL string, without requiring a URL-parsing crate dependency this crate
/// does not carry. Mirrors `urlparse` + the blocklist/IP checks exactly.
fn validate_parsed_url(url: &str) -> Option<bool> {
    let (scheme, rest) = url.split_once("://")?;
    if scheme != "http" && scheme != "https" {
        return Some(false);
    }
    // hostname is the authority up to the first '/', '?', or '#', minus
    // userinfo and port.
    let authority_end = rest
        .find(&['/', '?', '#'][..])
        .unwrap_or(rest.len());
    let authority = &rest[..authority_end];
    let host_port = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
    let hostname = if let Some(stripped) = host_port.strip_prefix('[') {
        // IPv6 literal: "[::1]:port"
        stripped.split(']').next().unwrap_or("")
    } else {
        host_port.split(':').next().unwrap_or("")
    };
    if hostname.is_empty() {
        return Some(false);
    }
    let hostname_lower = hostname.to_lowercase();
    const BLOCKED: &[&str] = &[
        "localhost",
        "127.0.0.1",
        "0.0.0.0",
        "::1",
        "metadata.google.internal",
    ];
    if BLOCKED.contains(&hostname_lower.as_str()) {
        return Some(false);
    }
    if let Ok(ip) = hostname.parse::<IpAddr>() {
        if is_private_loopback_or_link_local(ip) {
            return Some(false);
        }
    }
    Some(true)
}

/// Mirrors `ip.is_private or ip.is_loopback or ip.is_link_local` from
/// Python's `ipaddress` module.
fn is_private_loopback_or_link_local(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_private() || v4.is_loopback() || v4.is_link_local(),
        IpAddr::V6(v6) => {
            v6.is_loopback()
                || (v6.segments()[0] & 0xffc0) == 0xfe80 // link-local fe80::/10
                || (v6.segments()[0] & 0xfe00) == 0xfc00 // unique local fc00::/7 (Python is_private)
        }
    }
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct CollectionPeriod {
    pub first: String,
    pub last: String,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct MetricSeries {
    pub label: String,
    pub unit: String,
    pub p75_values: Vec<Option<f64>>,
    pub good_percentages: Vec<Option<f64>>,
    pub needs_improvement_percentages: Vec<Option<f64>>,
    pub poor_percentages: Vec<Option<f64>>,
    pub latest_p75: Option<f64>,
    pub good_threshold: f64,
    pub poor_threshold: f64,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct Trend {
    pub direction: String,
    pub change_pct: Option<f64>,
    pub earliest_avg: Option<f64>,
    pub latest_avg: Option<f64>,
    pub label: String,
    pub data_points: Option<usize>,
}

fn round_to(v: f64, places: i32) -> f64 {
    let f = 10f64.powi(places);
    (v * f).round() / f
}

fn ymd(date: &Value) -> String {
    let year = date.get("year").and_then(Value::as_i64).unwrap_or(0);
    let month = date.get("month").and_then(Value::as_i64).unwrap_or(0);
    let day = date.get("day").and_then(Value::as_i64).unwrap_or(0);
    format!("{year}-{month:02}-{day:02}")
}

/// Mirrors the `p75s` parsing loop in `query_history()`: for
/// `cumulative_layout_shift`, parse as float; otherwise try int, then
/// float; `None`/unparsable becomes `None`.
fn parse_p75(metric_name: &str, val: &Value) -> Option<f64> {
    if val.is_null() {
        return None;
    }
    if metric_name == "cumulative_layout_shift" {
        return value_as_number_str(val).and_then(|s| s.parse::<f64>().ok());
    }
    if let Some(n) = val.as_i64() {
        return Some(n as f64);
    }
    if let Some(s) = val.as_str() {
        if let Ok(n) = s.parse::<i64>() {
            return Some(n as f64);
        }
    }
    value_as_number_str(val).and_then(|s| s.parse::<f64>().ok())
}

fn value_as_number_str(val: &Value) -> Option<String> {
    match val {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        _ => None,
    }
}

fn parse_density_pct(val: &Value) -> Option<f64> {
    match val {
        Value::Null => None,
        Value::String(s) if s == "NaN" => None,
        Value::String(s) => s.parse::<f64>().ok().map(|f| round_to(f * 100.0, 1)),
        Value::Number(n) => n.as_f64().map(|f| round_to(f * 100.0, 1)),
        _ => None,
    }
}

/// Mirrors the body of `query_history()` from parsing the `record`
/// response onward (i.e. everything after the HTTP call succeeds):
/// collection periods, metrics timeseries, and trend analysis. `record`
/// is the `data["record"]` object from the CrUX History API response.
pub fn parse_history_record(record: &Value) -> (Vec<CollectionPeriod>, BTreeMap<String, MetricSeries>) {
    let mut periods = Vec::new();
    if let Some(arr) = record.get("collectionPeriods").and_then(Value::as_array) {
        for period in arr {
            periods.push(CollectionPeriod {
                first: ymd(period.get("firstDate").unwrap_or(&Value::Null)),
                last: ymd(period.get("lastDate").unwrap_or(&Value::Null)),
            });
        }
    }

    let mut metrics: BTreeMap<String, MetricSeries> = BTreeMap::new();
    let known = thresholds();
    if let Some(obj) = record.get("metrics").and_then(Value::as_object) {
        for (metric_name, metric_data) in obj {
            let Some(th) = known.get(metric_name.as_str()) else {
                continue;
            };
            let p75s_raw = metric_data
                .get("percentilesTimeseries")
                .and_then(|p| p.get("p75s"))
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default();
            let p75s: Vec<Option<f64>> = p75s_raw
                .iter()
                .map(|v| parse_p75(metric_name, v))
                .collect();

            let histogram_ts = metric_data
                .get("histogramTimeseries")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default();
            let densities_at = |idx: usize| -> Vec<Option<f64>> {
                if histogram_ts.len() < 3 {
                    return Vec::new();
                }
                histogram_ts[idx]
                    .get("densities")
                    .and_then(Value::as_array)
                    .map(|a| a.iter().map(parse_density_pct).collect())
                    .unwrap_or_default()
            };
            let good_pcts = densities_at(0);
            let ni_pcts = densities_at(1);
            let poor_pcts = densities_at(2);

            let latest_p75 = p75s.last().copied().flatten();

            metrics.insert(
                metric_name.clone(),
                MetricSeries {
                    label: th.label.to_string(),
                    unit: th.unit.to_string(),
                    p75_values: p75s,
                    good_percentages: good_pcts,
                    needs_improvement_percentages: ni_pcts,
                    poor_percentages: poor_pcts,
                    latest_p75,
                    good_threshold: th.good,
                    poor_threshold: th.poor,
                },
            );
        }
    }

    (periods, metrics)
}

/// Mirrors Python `detect_trends(metrics)`: compares the average of the
/// last 4 valid p75 readings to the average of the first 4.
pub fn detect_trends(metrics: &BTreeMap<String, MetricSeries>) -> BTreeMap<String, Trend> {
    let mut trends = BTreeMap::new();
    for (metric_name, data) in metrics {
        let valid: Vec<f64> = data.p75_values.iter().filter_map(|v| *v).collect();
        if valid.len() < 8 {
            trends.insert(
                metric_name.clone(),
                Trend {
                    direction: "insufficient_data".to_string(),
                    change_pct: None,
                    earliest_avg: None,
                    latest_avg: None,
                    label: data.label.clone(),
                    data_points: None,
                },
            );
            continue;
        }
        let first_4 = &valid[..4];
        let last_4 = &valid[valid.len() - 4..];
        let avg_first = first_4.iter().sum::<f64>() / first_4.len() as f64;
        let avg_last = last_4.iter().sum::<f64>() / last_4.len() as f64;
        let change_pct = if avg_first == 0.0 {
            0.0
        } else {
            ((avg_last - avg_first) / avg_first) * 100.0
        };
        let direction = if change_pct.abs() < 5.0 {
            "stable"
        } else if change_pct < 0.0 {
            "improving"
        } else {
            "degrading"
        };
        let places = if data.unit.is_empty() { 3 } else { 0 };
        trends.insert(
            metric_name.clone(),
            Trend {
                direction: direction.to_string(),
                change_pct: Some(round_to(change_pct, 1)),
                earliest_avg: Some(round_to(avg_first, places)),
                latest_avg: Some(round_to(avg_last, places)),
                label: data.label.clone(),
                data_points: Some(valid.len()),
            },
        );
    }
    trends
}
