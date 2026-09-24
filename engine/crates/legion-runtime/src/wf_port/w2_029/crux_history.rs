//! Port of `skills/seo/scripts/crux_history.py`, plus `validate_url` from
//! `skills/seo/scripts/google_auth.py` (which `crux_history.py` imports).
//! Packet r34 closes the remaining gap: the CrUX History HTTP call and the
//! CLI entry point, both behind a [`CruxClient`] trait so tests never hit
//! the network. [`parse_history_record`] ports the pure JSON-in/JSON-out
//! transform that `query_history()` applies to the response body after
//! `resp.json()`, and [`detect_trends`] ports the standalone
//! `detect_trends()` function verbatim.

use std::collections::BTreeMap;
use std::io::Write;
use std::net::IpAddr;
use std::time::Duration;

use serde::Serialize;
use serde_json::Value;

use crate::wf_port::w2_030::google_auth;

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

const CRUX_HISTORY_ENDPOINT: &str =
    "https://chromeuxreport.googleapis.com/v1/records:queryHistoryRecord";

/// Outcome of one query, mirroring the shape `query_history()` returns
/// before/after the HTTP call.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct HistoryResult {
    pub target: String,
    pub form_factor: String,
    pub metrics: BTreeMap<String, MetricSeries>,
    pub collection_periods: Vec<CollectionPeriod>,
    pub trends: BTreeMap<String, Trend>,
    pub error: Option<String>,
}

/// Behind-a-trait I/O boundary for the CrUX History POST request, so
/// `run()`/`query_history()` are testable with a fake. Mirrors
/// `requests.post(f"{ENDPOINT}?key={api_key}", json=body, timeout=30)`:
/// returns `Ok((status_code, body_json))` on any HTTP response, `Err(msg)`
/// only for a transport-level failure (matching
/// `requests.exceptions.RequestException`).
pub trait CruxClient {
    fn post(&self, endpoint: &str, api_key: &str, body: &Value) -> Result<(u16, Value), String>;
}

/// Real `reqwest::blocking` implementation of [`CruxClient`].
pub struct ReqwestCruxClient;

impl CruxClient for ReqwestCruxClient {
    fn post(&self, endpoint: &str, api_key: &str, body: &Value) -> Result<(u16, Value), String> {
        let client = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(|e| format!("CrUX History API request failed: {e}"))?;
        let resp = client
            .post(format!("{endpoint}?key={api_key}"))
            .json(body)
            .send()
            .map_err(|e| format!("CrUX History API request failed: {e}"))?;
        let status = resp.status().as_u16();
        let json = resp
            .json::<Value>()
            .unwrap_or(Value::Object(Default::default()));
        Ok((status, json))
    }
}

/// End-to-end port of `query_history()`: validates the URL, builds the
/// request body (origin vs. URL query, optional `formFactor`), calls the
/// client, and parses the response into the same shape Python returns.
pub fn query_history(
    client: &dyn CruxClient,
    url_or_origin: &str,
    api_key: &str,
    form_factor: Option<&str>,
) -> HistoryResult {
    let mut result = HistoryResult {
        target: url_or_origin.to_string(),
        form_factor: form_factor.unwrap_or("ALL").to_string(),
        metrics: BTreeMap::new(),
        collection_periods: Vec::new(),
        trends: BTreeMap::new(),
        error: None,
    };

    if !validate_url(url_or_origin) {
        result.error = Some("Invalid URL. Only http/https URLs to public hosts are accepted.".to_string());
        return result;
    }

    let (scheme, rest) = url_or_origin.split_once("://").unwrap_or(("", url_or_origin));
    let authority_end = rest.find(&['/', '?', '#'][..]).unwrap_or(rest.len());
    let (authority, path_and_query) = rest.split_at(authority_end);
    let is_origin = (path_and_query.is_empty() || path_and_query == "/") && !rest.contains('?');

    let mut body = serde_json::Map::new();
    if is_origin {
        body.insert(
            "origin".to_string(),
            Value::String(format!("{scheme}://{authority}")),
        );
    } else {
        body.insert("url".to_string(), Value::String(url_or_origin.to_string()));
    }
    if let Some(ff) = form_factor {
        body.insert("formFactor".to_string(), Value::String(ff.to_uppercase()));
    }

    let (status, data) = match client.post(CRUX_HISTORY_ENDPOINT, api_key, &Value::Object(body)) {
        Ok(v) => v,
        Err(e) => {
            result.error = Some(e);
            return result;
        }
    };

    if status == 404 {
        let target_type = if is_origin { "origin" } else { "URL" };
        result.error = Some(format!(
            "No CrUX history data for this {target_type}. Insufficient Chrome traffic volume for eligibility."
        ));
        return result;
    }
    if status == 429 {
        result.error = Some("CrUX API rate limit exceeded (150 QPM shared). Wait and retry.".to_string());
        return result;
    }
    if !(200..300).contains(&status) {
        result.error = Some(format!("CrUX History API request failed: HTTP {status}"));
        return result;
    }

    let record = data.get("record").cloned().unwrap_or(Value::Null);
    let (periods, metrics) = parse_history_record(&record);
    result.collection_periods = periods;
    result.trends = detect_trends(&metrics);
    result.metrics = metrics;

    result
}

/// CLI arg bundle mirroring `argparse` in `crux_history.py`'s `main()`.
#[derive(Debug, Clone, Default)]
struct Args {
    url: Option<String>,
    form_factor: Option<String>,
    api_key: Option<String>,
    origin: bool,
    json: bool,
}

fn parse_args(args: &[String]) -> Result<Args, String> {
    let mut out = Args::default();
    let mut i = 0;
    while i < args.len() {
        let a = args[i].as_str();
        match a {
            "--form-factor" => {
                i += 1;
                let v = args.get(i).ok_or("--form-factor requires a value")?.clone();
                if !["PHONE", "DESKTOP", "TABLET"].contains(&v.as_str()) {
                    return Err(format!("argument --form-factor: invalid choice: '{v}'"));
                }
                out.form_factor = Some(v);
            }
            "--api-key" => {
                i += 1;
                out.api_key = Some(args.get(i).ok_or("--api-key requires a value")?.clone());
            }
            "--origin" => out.origin = true,
            "--json" | "-j" => out.json = true,
            other if !other.starts_with('-') => out.url = Some(other.to_string()),
            other => return Err(format!("unrecognized argument: {other}")),
        }
        i += 1;
    }
    out.url.clone().ok_or("the following arguments are required: url")?;
    Ok(out)
}

/// Port of `crux_history.py`'s `main()`, parameterized over the client
/// and stdout/stderr sinks so it is testable without touching real I/O.
/// Uses `google_auth::load_config().api_key` as the `get_api_key()`
/// fallback when `--api-key` is not given. Returns the process exit code.
pub fn run(
    args: &[String],
    client: &dyn CruxClient,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> i32 {
    let parsed = match parse_args(args) {
        Ok(p) => p,
        Err(e) => {
            let _ = writeln!(stderr, "{e}");
            return 2;
        }
    };

    let api_key = parsed
        .api_key
        .clone()
        .or_else(|| google_auth::load_config().api_key);
    let Some(api_key) = api_key else {
        let _ = writeln!(
            stderr,
            "Error: API key required. Use --api-key or configure GOOGLE_API_KEY."
        );
        return 1;
    };

    let mut target = parsed.url.clone().unwrap_or_default();
    if parsed.origin {
        if let Some((scheme, rest)) = target.split_once("://") {
            let authority_end = rest.find(&['/', '?', '#'][..]).unwrap_or(rest.len());
            target = format!("{scheme}://{}", &rest[..authority_end]);
        }
    }

    let result = query_history(client, &target, &api_key, parsed.form_factor.as_deref());

    if parsed.json {
        let _ = writeln!(
            stdout,
            "{}",
            serde_json::to_string_pretty(&result).unwrap_or_default()
        );
        return 0;
    }

    if let Some(err) = &result.error {
        let _ = writeln!(stderr, "Error: {err}");
        return 1;
    }

    let _ = writeln!(stdout, "=== CrUX History ({}) ===", result.form_factor);
    let _ = writeln!(stdout, "Target: {}", result.target);

    if let (Some(first), Some(last)) = (result.collection_periods.first(), result.collection_periods.last()) {
        let _ = writeln!(
            stdout,
            "Range: {} to {} ({} weeks)",
            first.first,
            last.last,
            result.collection_periods.len()
        );
    }

    let _ = writeln!(stdout, "\nTrend Analysis:");
    for (name, trend) in &result.trends {
        let label = &trend.label;
        if trend.direction == "insufficient_data" {
            let _ = writeln!(stdout, "  {label}: Insufficient data");
            let _ = name; // name unused otherwise, mirrors Python's dict-iteration label lookup.
            continue;
        }
        let arrow = match trend.direction.as_str() {
            "improving" => "IMPROVING",
            "stable" => "STABLE",
            "degrading" => "DEGRADING",
            _ => "?",
        };
        let change = trend.change_pct.unwrap_or(0.0);
        let earliest = trend.earliest_avg;
        let latest = trend.latest_avg;
        let earliest_s = earliest.map(|v| v.to_string()).unwrap_or_default();
        let latest_s = latest.map(|v| v.to_string()).unwrap_or_default();
        let _ = writeln!(
            stdout,
            "  {label}: {arrow} ({change:+.1}%) | {earliest_s} -> {latest_s}"
        );
    }

    0
}
