//! Port of `skills/seo/scripts/ga4_report.py` (packet r35).
//!
//! `_resolve_property`, the `datetime.now() - timedelta(days=...)`
//! date-range computation (pure civil-calendar arithmetic, since this
//! crate carries no date/time crate), the totals/slimming logic, and now
//! the GA4 Data API v1beta `runReport` calls themselves
//! (`organic_traffic_report`, `top_pages_report`, `device_breakdown`,
//! `country_breakdown`) plus the CLI (`run`) are ported. The HTTP call is
//! behind the [`Ga4Http`] trait: [`ReqwestGa4Http`] is the real
//! `reqwest::blocking` implementation, and tests use a fake. Minting the
//! OAuth/service-account bearer token itself is `google_auth.py`'s job
//! (ported separately in `wf_port::w2_030::google_auth`); this module
//! takes an already-resolved bearer token as input, matching how
//! `_build_ga4_client()` hands a ready `BetaAnalyticsDataClient` to each
//! report function.

use std::time::{SystemTime, UNIX_EPOCH};

use serde::Serialize;
use serde_json::Value;

/// Mirrors Python `_resolve_property(property_id)`.
pub fn resolve_property(property_id: &str) -> String {
    if property_id.is_empty() {
        return String::new();
    }
    if property_id.starts_with("properties/") {
        property_id.to_string()
    } else {
        format!("properties/{property_id}")
    }
}

/// A civil (proleptic Gregorian) calendar date, used only for the pure
/// `days` arithmetic `ga4_report.py` does via `datetime`/`timedelta`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct CivilDate {
    pub year: i64,
    pub month: u32,
    pub day: u32,
}

impl CivilDate {
    pub fn new(year: i64, month: u32, day: u32) -> Self {
        Self { year, month, day }
    }

    /// Days since the civil epoch (0000-03-01), per Howard Hinnant's
    /// `days_from_civil` algorithm — used only to implement `- N days`.
    fn to_days(self) -> i64 {
        let y = if self.month <= 2 {
            self.year - 1
        } else {
            self.year
        };
        let era = if y >= 0 { y } else { y - 399 } / 400;
        let yoe = (y - era * 400) as i64; // [0, 399]
        let mp = (self.month as i64 + 9) % 12; // [0, 11]
        let doy = (153 * mp + 2) / 5 + self.day as i64 - 1; // [0, 365]
        let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy; // [0, 146096]
        era * 146097 + doe - 719468
    }

    fn from_days(z: i64) -> Self {
        let z = z + 719468;
        let era = if z >= 0 { z } else { z - 146096 } / 146097;
        let doe = z - era * 146097; // [0, 146096]
        let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365; // [0, 399]
        let y = yoe + era * 400;
        let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
        let mp = (5 * doy + 2) / 153; // [0, 11]
        let day = (doy - (153 * mp + 2) / 5 + 1) as u32; // [1, 31]
        let month = (if mp < 10 { mp + 3 } else { mp - 9 }) as u32; // [1, 12]
        let year = if month <= 2 { y + 1 } else { y };
        CivilDate { year, month, day }
    }

    /// Mirrors `date - timedelta(days=n)`.
    pub fn minus_days(self, n: i64) -> Self {
        Self::from_days(self.to_days() - n)
    }

    /// Mirrors `date.strftime("%Y-%m-%d")`.
    pub fn to_iso(self) -> String {
        format!("{:04}-{:02}-{:02}", self.year, self.month, self.day)
    }
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct DateRange {
    pub start: String,
    pub end: String,
}

/// Mirrors the date-range computation shared by `organic_traffic_report`,
/// `device_breakdown`, and `country_breakdown`:
/// `start = today - timedelta(days=days)`, `end = today - timedelta(days=1)`,
/// both formatted `%Y-%m-%d`. `today` is caller-supplied (this crate does
/// not read the system clock).
pub fn date_range(today: CivilDate, days: i64) -> DateRange {
    DateRange {
        start: today.minus_days(days).to_iso(),
        end: today.minus_days(1).to_iso(),
    }
}

#[derive(Debug, Clone, Serialize, PartialEq, Default)]
pub struct Totals {
    pub sessions: i64,
    pub users: i64,
    pub pageviews: i64,
    pub avg_daily_sessions: f64,
}

fn round1(v: f64) -> f64 {
    (v * 10.0).round() / 10.0
}

/// Mirrors the totals block at the end of `organic_traffic_report`:
/// summed from each daily row's `sessions`/`users`/`pageviews`, with
/// `avg_daily_sessions = round(total_sessions / len(daily_data), 1)`.
/// Returns `None` when `daily_data` is empty, matching Python's
/// `if result["daily_data"]:` guard (an empty `{}` totals object).
pub fn compute_totals(daily_sessions: &[i64], daily_users: &[i64], daily_pageviews: &[i64]) -> Option<Totals> {
    if daily_sessions.is_empty() {
        return None;
    }
    let total_sessions: i64 = daily_sessions.iter().sum();
    let total_users: i64 = daily_users.iter().sum();
    let total_pageviews: i64 = daily_pageviews.iter().sum();
    Some(Totals {
        sessions: total_sessions,
        users: total_users,
        pageviews: total_pageviews,
        avg_daily_sessions: round1(total_sessions as f64 / daily_sessions.len() as f64),
    })
}

/// Mirrors `top_pages_report()`'s slimming of an already-built
/// `organic_traffic_report()` result down to just the pages view. `report`
/// is the JSON object `organic_traffic_report` would have returned;
/// `property_id` is passed through as-is (Python re-uses its own
/// argument, not the report's `property` field).
pub fn slim_to_top_pages(property_id: &str, report: &Value) -> Value {
    let total_organic_sessions = report
        .get("totals")
        .and_then(|t| t.get("sessions"))
        .cloned()
        .unwrap_or(Value::from(0));
    serde_json::json!({
        "property": property_id,
        "report": "top_organic_pages",
        "date_range": report.get("date_range").cloned().unwrap_or(Value::Null),
        "pages": report.get("top_pages").cloned().unwrap_or_else(|| Value::Array(vec![])),
        "total_organic_sessions": total_organic_sessions,
        "quota_tokens_used": report.get("quota_tokens_used").cloned().unwrap_or(Value::Null),
        "error": report.get("error").cloned().unwrap_or(Value::Null),
    })
}

// ---------------------------------------------------------------------
// GA4 Data API v1beta HTTP surface
// ---------------------------------------------------------------------

/// Abstracts the single GA4 REST call every report function makes:
/// `POST https://analyticsdata.googleapis.com/v1beta/{property}:runReport`.
/// Mirrors `client.run_report(request)` in the Python SDK. Returns the
/// parsed JSON response body on success, or an error string built the
/// same way `organic_traffic_report`'s `except Exception as e` branch
/// classifies GA4 errors (see [`classify_error`]).
pub trait Ga4Http {
    fn run_report(&self, property: &str, body: &Value) -> Result<Value, Ga4HttpError>;
}

/// An HTTP-layer failure: status code (0 if the request never completed,
/// e.g. a transport error) plus whatever body/message text is available
/// for [`classify_error`] to inspect (Python matches on `"403"` /
/// `"PERMISSION_DENIED"` / `"404"` / `"NOT_FOUND"` substrings in `str(e)`).
#[derive(Debug, Clone)]
pub struct Ga4HttpError {
    pub status: u16,
    pub message: String,
}

/// Mirrors the `except Exception as e:` classification in
/// `organic_traffic_report`'s daily-request block.
pub fn classify_error(property_id: &str, err: &Ga4HttpError) -> String {
    let s = &err.message;
    if err.status == 403 || s.contains("403") || s.contains("PERMISSION_DENIED") {
        format!(
            "Permission denied for property '{property_id}'. Add the service account email as Viewer in GA4 Admin > Property Access Management."
        )
    } else if err.status == 404 || s.contains("404") || s.contains("NOT_FOUND") {
        format!(
            "Property '{property_id}' not found. Verify the numeric property ID in GA4 Admin > Property Details."
        )
    } else {
        format!("GA4 API error: {s}")
    }
}

/// Real implementation: a blocking `reqwest` client carrying an
/// already-minted OAuth bearer token (see module docs — token minting is
/// `google_auth.py`'s job, not this one's).
pub struct ReqwestGa4Http {
    pub bearer_token: String,
    pub http: reqwest::blocking::Client,
}

impl ReqwestGa4Http {
    pub fn new(bearer_token: String) -> Self {
        Self {
            bearer_token,
            http: reqwest::blocking::Client::new(),
        }
    }
}

impl Ga4Http for ReqwestGa4Http {
    fn run_report(&self, property: &str, body: &Value) -> Result<Value, Ga4HttpError> {
        let url = format!("https://analyticsdata.googleapis.com/v1beta/{property}:runReport");
        let resp = self
            .http
            .post(&url)
            .bearer_auth(&self.bearer_token)
            .json(body)
            .send()
            .map_err(|e| Ga4HttpError {
                status: 0,
                message: e.to_string(),
            })?;
        let status = resp.status().as_u16();
        let text = resp.text().unwrap_or_default();
        if status >= 400 {
            return Err(Ga4HttpError {
                status,
                message: text,
            });
        }
        serde_json::from_str::<Value>(&text).map_err(|e| Ga4HttpError {
            status,
            message: format!("invalid GA4 JSON response: {e}"),
        })
    }
}

fn dim(name: &str) -> Value {
    serde_json::json!({"name": name})
}
fn met(name: &str) -> Value {
    serde_json::json!({"name": name})
}
fn organic_filter() -> Value {
    serde_json::json!({
        "filter": {
            "fieldName": "sessionDefaultChannelGroup",
            "stringFilter": {"matchType": "EXACT", "value": "Organic Search"}
        }
    })
}

/// Mirrors the `daily_request` `RunReportRequest` built in
/// `organic_traffic_report`.
fn daily_request_body(start: &str, end: &str, days: i64) -> Value {
    serde_json::json!({
        "dimensions": [dim("date")],
        "metrics": [met("sessions"), met("totalUsers"), met("screenPageViews"), met("bounceRate"), met("averageSessionDuration"), met("engagementRate")],
        "dateRanges": [{"startDate": start, "endDate": end}],
        "dimensionFilter": organic_filter(),
        "orderBys": [{"dimension": {"dimensionName": "date"}}],
        "limit": days + 5,
        "returnPropertyQuota": true,
    })
}

/// Mirrors `pages_request`.
fn pages_request_body(start: &str, end: &str, limit: i64) -> Value {
    serde_json::json!({
        "dimensions": [dim("landingPage")],
        "metrics": [met("sessions"), met("totalUsers"), met("screenPageViews"), met("bounceRate"), met("engagementRate")],
        "dateRanges": [{"startDate": start, "endDate": end}],
        "dimensionFilter": organic_filter(),
        "orderBys": [{"metric": {"metricName": "sessions"}, "desc": true}],
        "limit": limit,
    })
}

/// Mirrors the `device_breakdown` request.
fn device_request_body(start: &str, end: &str) -> Value {
    serde_json::json!({
        "dimensions": [dim("deviceCategory")],
        "metrics": [met("sessions"), met("totalUsers"), met("bounceRate"), met("engagementRate")],
        "dateRanges": [{"startDate": start, "endDate": end}],
        "dimensionFilter": organic_filter(),
        "orderBys": [{"metric": {"metricName": "sessions"}, "desc": true}],
    })
}

/// Mirrors the `country_breakdown` request.
fn country_request_body(start: &str, end: &str, limit: i64) -> Value {
    serde_json::json!({
        "dimensions": [dim("country")],
        "metrics": [met("sessions"), met("totalUsers")],
        "dateRanges": [{"startDate": start, "endDate": end}],
        "dimensionFilter": organic_filter(),
        "orderBys": [{"metric": {"metricName": "sessions"}, "desc": true}],
        "limit": limit,
    })
}

fn row_dim(row: &Value, i: usize) -> String {
    row.get("dimensionValues")
        .and_then(|v| v.get(i))
        .and_then(|v| v.get("value"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string()
}
fn row_metric_i64(row: &Value, i: usize) -> i64 {
    row.get("metricValues")
        .and_then(|v| v.get(i))
        .and_then(|v| v.get("value"))
        .and_then(|v| v.as_str())
        .and_then(|s| s.parse::<f64>().ok())
        .unwrap_or(0.0) as i64
}
fn row_metric_f64(row: &Value, i: usize) -> f64 {
    row.get("metricValues")
        .and_then(|v| v.get(i))
        .and_then(|v| v.get("value"))
        .and_then(|v| v.as_str())
        .and_then(|s| s.parse::<f64>().ok())
        .unwrap_or(0.0)
}

fn quota_from_response(resp: &Value) -> Value {
    match resp.get("propertyQuota") {
        Some(pq) if pq.is_object() => {
            let tpd = pq.get("tokensPerDay");
            let tph = pq.get("tokensPerHour");
            serde_json::json!({
                "daily_consumed": tpd.and_then(|v| v.get("consumed")).cloned().unwrap_or(Value::Null),
                "daily_remaining": tpd.and_then(|v| v.get("remaining")).cloned().unwrap_or(Value::Null),
                "hourly_consumed": tph.and_then(|v| v.get("consumed")).cloned().unwrap_or(Value::Null),
                "hourly_remaining": tph.and_then(|v| v.get("remaining")).cloned().unwrap_or(Value::Null),
            })
        }
        _ => Value::Null,
    }
}

/// Mirrors `organic_traffic_report(property_id, days, limit)`.
pub fn organic_traffic_report(
    client: &dyn Ga4Http,
    property_id: &str,
    days: i64,
    limit: i64,
    today: CivilDate,
) -> Value {
    let range = date_range(today, days);
    let prop = resolve_property(property_id);

    let daily_body = daily_request_body(&range.start, &range.end, days);
    let daily_resp = match client.run_report(&prop, &daily_body) {
        Ok(v) => v,
        Err(e) => {
            return serde_json::json!({
                "property": property_id,
                "report": "organic_traffic",
                "date_range": range,
                "totals": {},
                "daily_data": [],
                "top_pages": [],
                "quota_tokens_used": null,
                "error": classify_error(property_id, &e),
            });
        }
    };

    let rows = daily_resp.get("rows").and_then(|v| v.as_array()).cloned().unwrap_or_default();
    let mut daily_data = Vec::new();
    let mut sessions_col = Vec::new();
    let mut users_col = Vec::new();
    let mut pageviews_col = Vec::new();
    for row in &rows {
        let sessions = row_metric_i64(row, 0);
        let users = row_metric_i64(row, 1);
        let pageviews = row_metric_i64(row, 2);
        sessions_col.push(sessions);
        users_col.push(users);
        pageviews_col.push(pageviews);
        daily_data.push(serde_json::json!({
            "date": row_dim(row, 0),
            "sessions": sessions,
            "users": users,
            "pageviews": pageviews,
            "bounce_rate": round1(row_metric_f64(row, 3) * 100.0),
            "avg_session_duration": round1(row_metric_f64(row, 4)),
            "engagement_rate": round1(row_metric_f64(row, 5) * 100.0),
        }));
    }
    let quota = quota_from_response(&daily_resp);

    let pages_body = pages_request_body(&range.start, &range.end, limit);
    let mut pages_error: Option<String> = None;
    let mut top_pages = Vec::new();
    match client.run_report(&prop, &pages_body) {
        Ok(pages_resp) => {
            for row in pages_resp.get("rows").and_then(|v| v.as_array()).unwrap_or(&vec![]) {
                top_pages.push(serde_json::json!({
                    "landing_page": row_dim(row, 0),
                    "sessions": row_metric_i64(row, 0),
                    "users": row_metric_i64(row, 1),
                    "pageviews": row_metric_i64(row, 2),
                    "bounce_rate": round1(row_metric_f64(row, 3) * 100.0),
                    "engagement_rate": round1(row_metric_f64(row, 4) * 100.0),
                }));
            }
        }
        Err(e) => {
            pages_error = Some(format!("Error fetching top pages: {}", e.message));
        }
    }

    let totals = compute_totals(&sessions_col, &users_col, &pageviews_col);

    let mut out = serde_json::json!({
        "property": property_id,
        "report": "organic_traffic",
        "date_range": range,
        "totals": totals.map(|t| serde_json::to_value(t).unwrap()).unwrap_or_else(|| serde_json::json!({})),
        "daily_data": daily_data,
        "top_pages": top_pages,
        "quota_tokens_used": quota,
        "error": Value::Null,
    });
    if let Some(pe) = pages_error {
        out["pages_error"] = Value::String(pe);
    }
    out
}

/// Mirrors `top_pages_report(property_id, days, limit)`.
pub fn top_pages_report(client: &dyn Ga4Http, property_id: &str, days: i64, limit: i64, today: CivilDate) -> Value {
    let report = organic_traffic_report(client, property_id, days, limit, today);
    slim_to_top_pages(property_id, &report)
}

/// Mirrors `device_breakdown(property_id, days)`.
pub fn device_breakdown(client: &dyn Ga4Http, property_id: &str, days: i64, today: CivilDate) -> Value {
    let range = date_range(today, days);
    let prop = resolve_property(property_id);
    let body = device_request_body(&range.start, &range.end);
    match client.run_report(&prop, &body) {
        Ok(resp) => {
            let mut devices = Vec::new();
            for row in resp.get("rows").and_then(|v| v.as_array()).unwrap_or(&vec![]) {
                devices.push(serde_json::json!({
                    "category": row_dim(row, 0),
                    "sessions": row_metric_i64(row, 0),
                    "users": row_metric_i64(row, 1),
                    "bounce_rate": round1(row_metric_f64(row, 2) * 100.0),
                    "engagement_rate": round1(row_metric_f64(row, 3) * 100.0),
                }));
            }
            serde_json::json!({
                "property": property_id, "report": "device_breakdown",
                "devices": devices, "error": null, "date_range": range,
            })
        }
        Err(e) => serde_json::json!({
            "property": property_id, "report": "device_breakdown",
            "devices": [], "error": format!("GA4 device breakdown error: {}", e.message),
            "date_range": range,
        }),
    }
}

/// Mirrors `country_breakdown(property_id, days, limit)`.
pub fn country_breakdown(client: &dyn Ga4Http, property_id: &str, days: i64, limit: i64, today: CivilDate) -> Value {
    let range = date_range(today, days);
    let prop = resolve_property(property_id);
    let body = country_request_body(&range.start, &range.end, limit);
    match client.run_report(&prop, &body) {
        Ok(resp) => {
            let mut countries = Vec::new();
            for row in resp.get("rows").and_then(|v| v.as_array()).unwrap_or(&vec![]) {
                countries.push(serde_json::json!({
                    "country": row_dim(row, 0),
                    "sessions": row_metric_i64(row, 0),
                    "users": row_metric_i64(row, 1),
                }));
            }
            serde_json::json!({
                "property": property_id, "report": "country_breakdown",
                "countries": countries, "error": null, "date_range": range,
            })
        }
        Err(e) => serde_json::json!({
            "property": property_id, "report": "country_breakdown",
            "countries": [], "error": format!("GA4 country breakdown error: {}", e.message),
            "date_range": range,
        }),
    }
}

/// System-clock `today()`, used by the real CLI entry point (tests pass an
/// explicit [`CivilDate`] instead, matching how `date_range` above takes
/// `today` as a parameter rather than reading the clock itself).
pub fn today_from_system_clock() -> CivilDate {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0) as i64;
    CivilDate::from_days(secs.div_euclid(86_400))
}

// ---------------------------------------------------------------------
// CLI (`main()` in ga4_report.py)
// ---------------------------------------------------------------------

/// Parsed CLI args, mirroring `argparse` in `main()`.
#[derive(Debug, Clone, PartialEq)]
pub struct CliArgs {
    pub property: Option<String>,
    pub days: i64,
    pub report: String,
    pub limit: i64,
    pub json: bool,
}

impl Default for CliArgs {
    fn default() -> Self {
        Self {
            property: None,
            days: 28,
            report: "organic".to_string(),
            limit: 50,
            json: false,
        }
    }
}

/// Mirrors argparse's flag handling for `--property/-p`, `--days/-d`,
/// `--report/-r` (choices: organic/top-pages/device/country),
/// `--limit`, `--json/-j`. Returns `Err(message)` for a bad `--report`
/// choice or a missing value, matching argparse's exit-2-with-stderr
/// behaviour closely enough for this CLI's purposes.
pub fn parse_args(args: &[String]) -> Result<CliArgs, String> {
    let mut out = CliArgs::default();
    let mut i = 0;
    while i < args.len() {
        let a = args[i].as_str();
        match a {
            "--property" | "-p" => {
                i += 1;
                out.property = Some(args.get(i).ok_or("argument --property/-p: expected one argument")?.clone());
            }
            "--days" | "-d" => {
                i += 1;
                let v = args.get(i).ok_or("argument --days/-d: expected one argument")?;
                out.days = v.parse::<i64>().map_err(|_| format!("argument --days/-d: invalid int value: '{v}'"))?;
            }
            "--report" | "-r" => {
                i += 1;
                let v = args.get(i).ok_or("argument --report/-r: expected one argument")?.clone();
                if !["organic", "top-pages", "device", "country"].contains(&v.as_str()) {
                    return Err(format!(
                        "argument --report/-r: invalid choice: '{v}' (choose from 'organic', 'top-pages', 'device', 'country')"
                    ));
                }
                out.report = v;
            }
            "--limit" => {
                i += 1;
                let v = args.get(i).ok_or("argument --limit: expected one argument")?;
                out.limit = v.parse::<i64>().map_err(|_| format!("argument --limit: invalid int value: '{v}'"))?;
            }
            "--json" | "-j" => {
                out.json = true;
            }
            other => return Err(format!("unrecognized arguments: {other}")),
        }
        i += 1;
    }
    Ok(out)
}

/// Result of a CLI run: exit code plus stdout/stderr text, so tests can
/// assert on all three the way a subprocess test would. Mirrors `main()`.
pub struct CliOutcome {
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
}

/// Mirrors `main()`: resolves the property (from `--property` or
/// `config.ga4_property_id`, stripping a `properties/` prefix), dispatches
/// to the right report function, and formats text or JSON output.
/// `config_ga4_property_id` stands in for `load_config().get("ga4_property_id")`
/// (config loading is `google_auth.py`'s job).
pub fn run(
    args: &[String],
    client: &dyn Ga4Http,
    today: CivilDate,
    config_ga4_property_id: Option<&str>,
) -> CliOutcome {
    let parsed = match parse_args(args) {
        Ok(p) => p,
        Err(e) => {
            return CliOutcome {
                exit_code: 2,
                stdout: String::new(),
                stderr: e,
            }
        }
    };

    let mut prop = parsed.property.clone();
    if prop.is_none() {
        if let Some(p) = config_ga4_property_id {
            let stripped = p.strip_prefix("properties/").unwrap_or(p);
            if !stripped.is_empty() {
                prop = Some(stripped.to_string());
            }
        }
    }
    let prop = match prop {
        Some(p) if !p.is_empty() => p,
        _ => {
            return CliOutcome {
                exit_code: 1,
                stdout: String::new(),
                stderr: "Error: No GA4 property specified. Use --property or set ga4_property_id in config.".to_string(),
            }
        }
    };

    let result = match parsed.report.as_str() {
        "top-pages" => top_pages_report(client, &prop, parsed.days, parsed.limit, today),
        "device" => device_breakdown(client, &prop, parsed.days, today),
        "country" => country_breakdown(client, &prop, parsed.days, parsed.limit, today),
        _ => organic_traffic_report(client, &prop, parsed.days, parsed.limit, today),
    };

    let mut stderr = String::new();
    let mut exit_code = 0;
    let err = result.get("error").and_then(|v| v.as_str());
    if let Some(e) = err {
        stderr.push_str(&format!("Error: {e}\n"));
        if !parsed.json {
            exit_code = 1;
        }
    }

    let mut stdout = String::new();
    if parsed.json {
        stdout.push_str(&serde_json::to_string_pretty(&result).unwrap_or_default());
        stdout.push('\n');
    } else if exit_code == 0 || err.is_none() {
        stdout.push_str(&format_text(&parsed, &prop, &result));
    }

    CliOutcome {
        exit_code,
        stdout,
        stderr,
    }
}

fn format_text(parsed: &CliArgs, prop: &str, result: &Value) -> String {
    let mut out = String::new();
    let dr = result.get("date_range");
    let start = dr.and_then(|d| d.get("start")).and_then(|v| v.as_str()).unwrap_or("None");
    let end = dr.and_then(|d| d.get("end")).and_then(|v| v.as_str()).unwrap_or("None");

    if parsed.report == "top-pages" {
        out.push_str("=== Top Organic Landing Pages ===\n");
        out.push_str(&format!("Property: {prop} | Period: {start} to {end}\n"));
        let total = result.get("total_organic_sessions").and_then(|v| v.as_i64()).unwrap_or(0);
        out.push_str(&format!("Total organic sessions: {total}\n\n"));
        if let Some(pages) = result.get("pages").and_then(|v| v.as_array()) {
            for (i, page) in pages.iter().take(20).enumerate() {
                let landing = page.get("landing_page").and_then(|v| v.as_str()).unwrap_or("");
                out.push_str(&format!("  {:2}. {}\n", i + 1, landing));
                let sessions = page.get("sessions").and_then(|v| v.as_i64()).unwrap_or(0);
                let users = page.get("users").and_then(|v| v.as_i64()).unwrap_or(0);
                let bounce = page.get("bounce_rate").and_then(|v| v.as_f64()).unwrap_or(0.0);
                out.push_str(&format!(
                    "      Sessions: {sessions} | Users: {users} | Bounce: {bounce}%\n"
                ));
            }
        }
    } else {
        let totals = result.get("totals").cloned().unwrap_or(serde_json::json!({}));
        out.push_str("=== GA4 Organic Traffic Report ===\n");
        out.push_str(&format!("Property: {prop}\n"));
        out.push_str(&format!("Period: {start} to {end}\n"));
        let sessions = totals.get("sessions").and_then(|v| v.as_i64()).unwrap_or(0);
        let users = totals.get("users").and_then(|v| v.as_i64()).unwrap_or(0);
        let pageviews = totals.get("pageviews").and_then(|v| v.as_i64()).unwrap_or(0);
        out.push_str(&format!(
            "\nSessions: {sessions} | Users: {users} | Pageviews: {pageviews}\n"
        ));
        let avg = totals.get("avg_daily_sessions").and_then(|v| v.as_f64()).unwrap_or(0.0);
        out.push_str(&format!("Avg Daily Sessions: {avg:.0}\n"));

        if let Some(quota) = result.get("quota_tokens_used") {
            if let Some(remaining) = quota.get("daily_remaining") {
                if !remaining.is_null() {
                    let consumed = quota.get("daily_consumed").cloned().unwrap_or(Value::Null);
                    out.push_str(&format!(
                        "\nQuota: {} tokens used / {} remaining (daily)\n",
                        consumed, remaining
                    ));
                }
            }
        }

        if let Some(pages) = result.get("top_pages").and_then(|v| v.as_array()) {
            if !pages.is_empty() {
                out.push_str(&format!("\nTop {} Organic Landing Pages:\n", pages.len().min(10)));
                for (i, page) in pages.iter().take(10).enumerate() {
                    let landing = page.get("landing_page").and_then(|v| v.as_str()).unwrap_or("");
                    let sessions = page.get("sessions").and_then(|v| v.as_i64()).unwrap_or(0);
                    out.push_str(&format!("  {:2}. {} ({} sessions)\n", i + 1, landing, sessions));
                }
            }
        }
    }
    out
}
