//! Faithful port of `skills/seo/scripts/gsc_query_v2.py`, packet r38.
//!
//! `normalize_result()` (the deterministic core the docstring calls out as "replayable so
//! recorded provider fixtures can verify semantics without credentials") and `--device`/
//! `--country` filter-building were already ported. This packet closes the remaining gap: the
//! live `query()`/`service()` Search Analytics API call ([`query_with`], generalized over
//! [`SearchAnalyticsTransport`] and backed for real by [`ReqwestSearchAnalyticsTransport`]) and
//! `main()`'s CLI dispatch ([`run`]).
//!
//! Bearer-token resolution ([`resolve_bearer_token`]) reuses `google_auth`'s already-ported OAuth
//! token-file/refresh machinery (`TOKEN_PATH_SUFFIX`, `OauthClient`, `TokenHttpClient`,
//! `refresh_oauth_token`). When no usable OAuth token exists and a service-account file is
//! configured, it falls back to the service account: `google_auth` signs the RS256 JWT-bearer
//! assertion and exchanges it for a token scoped to the one API the route calls
//! ([`bearer_with_service_account_fallback`]). No token is cached; each call that needs the
//! fallback performs one exchange.

use std::io::Write;
use std::path::PathBuf;

use serde_json::{json, Value};

use super::google_auth;

const SEARCH_ANALYTICS_ENDPOINT: &str = "https://www.googleapis.com/webmasters/v3/sites";

/// Percent-encodes a single URL path segment with an empty "safe" set (every non-unreserved byte
/// is escaped, including `/` and `:`), matching how `googleapiclient`'s REST path-parameter
/// substitution encodes a GSC `siteUrl` (e.g. `sc-domain:example.com` or
/// `https://example.com/`) when it is spliced into a request path.
pub fn encode_path_segment(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

fn oauth_token_path() -> Option<PathBuf> {
    std::env::var("HOME")
        .ok()
        .map(|home| std::path::Path::new(&home).join(google_auth::TOKEN_PATH_SUFFIX))
}

fn oauth_client_path_from_config() -> Option<String> {
    let home = std::env::var("HOME").ok()?;
    let config_path = std::path::Path::new(&home).join(google_auth::CONFIG_PATH_SUFFIX);
    let text = std::fs::read_to_string(config_path).ok()?;
    let cfg: Value = serde_json::from_str(&text).ok()?;
    cfg.get("oauth_client_path")
        .and_then(Value::as_str)
        .map(str::to_string)
}

/// Resolves the saved OAuth access token (the OAuth half of [`resolve_bearer_token`]), reusing
/// `google_auth`'s OAuth token-file/refresh machinery. Mirrors the OAuth-token branch of
/// `get_oauth_credentials()`: loads the saved token, and if it is within 60s of `expires_at`,
/// refreshes it via a real HTTP POST (persisting the refreshed token back to disk, same as
/// `_refresh_oauth_token()`'s `_save_oauth_token()` call).
pub fn resolve_oauth_bearer() -> Result<String, String> {
    let path = oauth_token_path().ok_or_else(|| "HOME not set".to_string())?;
    let token = google_auth::load_oauth_token_file(&path).ok_or_else(|| {
        "No OAuth token found. Run `google_auth --auth --creds /path/to/client_secret.json` first."
            .to_string()
    })?;

    let access_token = token
        .get("access_token")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| "OAuth token file is missing access_token".to_string())?
        .to_string();
    let expires_at = token
        .get("expires_at")
        .and_then(Value::as_f64)
        .unwrap_or(0.0);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0);
    if now <= expires_at - 60.0 {
        return Ok(access_token);
    }

    let client_path = oauth_client_path_from_config().ok_or_else(|| {
        "OAuth token expired and no oauth_client_path configured to refresh it. Re-run --auth."
            .to_string()
    })?;
    let client = google_auth::load_oauth_client_file(std::path::Path::new(&client_path))?;
    let refreshed =
        google_auth::refresh_oauth_token(&google_auth::ReqwestTokenClient, &client, token)?
            .ok_or_else(|| "OAuth token refresh failed. Re-run --auth.".to_string())?;
    if let Some(p) = oauth_token_path() {
        let _ = google_auth::save_oauth_token_file(&p, &refreshed);
    }
    refreshed
        .get("access_token")
        .and_then(Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| "token refresh response missing access_token".to_string())
}

/// Why a route has no bearer token. Display is the text the route prints: a missing credential
/// keeps the route's existing OAuth-only message, and a configured service account that fails is
/// typed `unavailable:` with its reason.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BearerError {
    /// No usable OAuth token and no service account configured.
    NoCredential(String),
    /// A service account is configured but produced no token. `google_auth` redacts its exchange
    /// errors (the key and the assertion never appear), and its load errors name only the file.
    ServiceAccount(String),
}

impl std::fmt::Display for BearerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BearerError::NoCredential(message) => f.write_str(message),
            BearerError::ServiceAccount(reason) => write!(f, "unavailable: {reason}"),
        }
    }
}

/// Resolves the bearer token for `service` (`gsc`, `indexing` or `ga4`): the saved OAuth token when
/// it is usable, otherwise a service-account token minted for that API's scope.
pub fn resolve_bearer_token(service: &str) -> Result<String, BearerError> {
    let oauth = resolve_oauth_bearer();
    let cfg = google_auth::load_config();
    bearer_with_service_account_fallback(
        service,
        oauth,
        cfg.service_account_path.as_deref(),
        &google_auth::ReqwestTokenClient,
        &|path: &str| google_auth::load_service_account_key(path),
        google_auth::now_unix_whole_secs(),
    )
}

/// The fallback decision, with its dependencies injected so tests need no files, network or clock.
/// A usable OAuth token wins and no service-account call is made. Without a configured service
/// account the OAuth failure is returned unchanged. With one configured, its key is loaded and
/// exchanged for an access token scoped to `service` alone.
pub fn bearer_with_service_account_fallback(
    service: &str,
    oauth: Result<String, String>,
    service_account_path: Option<&str>,
    http: &dyn google_auth::TokenHttpClient,
    load_key: &dyn Fn(&str) -> Result<google_auth::ServiceAccountKey, String>,
    now_unix: u64,
) -> Result<String, BearerError> {
    let oauth_reason = match oauth {
        Ok(token) => return Ok(token),
        Err(reason) => reason,
    };
    let path = match service_account_path {
        Some(path) if !path.is_empty() => path,
        _ => return Err(BearerError::NoCredential(oauth_reason)),
    };
    let api = google_auth::service_name(service);
    let Some(scopes) = google_auth::service_account_scopes(service) else {
        return Err(BearerError::ServiceAccount(format!(
            "no service-account scope is defined for {api}"
        )));
    };
    let key = match load_key(path) {
        Ok(key) => key,
        Err(reason) => {
            return Err(BearerError::ServiceAccount(format!(
                "service account for {api} is not usable: {reason}"
            )))
        }
    };
    match google_auth::exchange_assertion(http, &key, scopes, now_unix) {
        Ok(token) => Ok(token.access_token),
        Err(reason) => Err(BearerError::ServiceAccount(format!(
            "service account token exchange failed for {api}: {reason}"
        ))),
    }
}

/// Boundary a caller plugs a real Search Analytics HTTP transport behind, so
/// [`query_with`]/tests never need live credentials or network access.
pub trait SearchAnalyticsTransport {
    fn post_json(&self, url: &str, bearer: &str, body: &Value) -> Result<(u16, String), String>;
}

/// Real transport backed by `reqwest::blocking`, posting to
/// `.../sites/{siteUrl}/searchAnalytics/query`.
pub struct ReqwestSearchAnalyticsTransport;

impl SearchAnalyticsTransport for ReqwestSearchAnalyticsTransport {
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

#[derive(Debug, Clone)]
pub struct NormalizeParams<'a> {
    pub site_url: &'a str,
    pub start_date: &'a str,
    pub end_date: &'a str,
    pub dimensions: &'a [String],
    pub search_type: &'a str,
    /// The single dimensionless aggregate row (or an empty object if the API returned none).
    pub aggregate_row: &'a Value,
    pub rows: &'a [Value],
    pub max_rows: i64,
    pub hit_cap: bool,
    pub data_state: &'a str,
}

fn num(v: &Value, key: &str) -> f64 {
    v.get(key).and_then(|x| x.as_f64()).unwrap_or(0.0)
}

fn round4(x: f64) -> f64 {
    (x * 10_000.0).round() / 10_000.0
}

fn round3(x: f64) -> f64 {
    (x * 1_000.0).round() / 1_000.0
}

/// Port of `normalize_result()`. Faithful to field names, rounding (`round(x, 4)` / `round(x,
/// 3)`), and the `query_click_coverage` / `query_impression_coverage` divide-by-zero -> `null`
/// behavior.
pub fn normalize_result(p: &NormalizeParams) -> Value {
    let mut processed: Vec<Value> = Vec::with_capacity(p.rows.len());
    for row in p.rows {
        let mut item = serde_json::Map::new();
        item.insert(
            "clicks".to_string(),
            row.get("clicks").cloned().unwrap_or(json!(0)),
        );
        item.insert(
            "impressions".to_string(),
            row.get("impressions").cloned().unwrap_or(json!(0)),
        );
        item.insert("ctr".to_string(), json!(round4(num(row, "ctr") * 100.0)));
        item.insert("position".to_string(), json!(round3(num(row, "position"))));
        let keys = row
            .get("keys")
            .and_then(|k| k.as_array())
            .cloned()
            .unwrap_or_default();
        for (i, dim) in p.dimensions.iter().enumerate() {
            item.insert(dim.clone(), keys.get(i).cloned().unwrap_or(Value::Null));
        }
        processed.push(Value::Object(item));
    }

    let dim_clicks: f64 = p.rows.iter().map(|r| num(r, "clicks")).sum();
    let dim_impressions: f64 = p.rows.iter().map(|r| num(r, "impressions")).sum();
    let agg_clicks = num(p.aggregate_row, "clicks");
    let agg_impressions = num(p.aggregate_row, "impressions");

    let query_click_coverage = if agg_clicks != 0.0 {
        json!(round4(dim_clicks / agg_clicks))
    } else {
        Value::Null
    };
    let query_impression_coverage = if agg_impressions != 0.0 {
        json!(round4(dim_impressions / agg_impressions))
    } else {
        Value::Null
    };

    json!({
        "property": p.site_url,
        "date_range": {"start": p.start_date, "end": p.end_date},
        "search_type": p.search_type,
        "data_state": p.data_state,
        "dimensions": p.dimensions,
        "rows": processed,
        "aggregate": {
            "clicks": agg_clicks,
            "impressions": agg_impressions,
            "ctr": round4(num(p.aggregate_row, "ctr") * 100.0),
            "position": round3(num(p.aggregate_row, "position")),
            "provenance": "dimensionless Search Analytics query",
        },
        "dimension_sum": {
            "clicks": dim_clicks,
            "impressions": dim_impressions,
            "provenance": "sum of returned dimension rows; not authoritative property total",
        },
        "coverage": {
            "returned_rows": processed.len(),
            "max_rows": p.max_rows,
            "hit_client_cap": p.hit_cap,
            "query_click_coverage": query_click_coverage,
            "query_impression_coverage": query_impression_coverage,
            "complete": if p.hit_cap { json!(false) } else { Value::Null },
            "note": "Dimensioned Search Console data can omit anonymized/low-volume rows. Aggregate totals are intentionally separate; absence of a cap does not prove dimension-row completeness.",
        },
        "error": Value::Null,
    })
}

/// Port of `main()`'s pure filter-building: `--device`/`--country` become GSC
/// `dimensionFilterGroups` filters, uppercased, same as the python CLI.
pub fn build_filters(device: Option<&str>, country: Option<&str>) -> Vec<Value> {
    let mut filters = Vec::new();
    if let Some(d) = device {
        filters.push(
            json!({"dimension": "device", "operator": "equals", "expression": d.to_uppercase()}),
        );
    }
    if let Some(c) = country {
        filters.push(
            json!({"dimension": "country", "operator": "equals", "expression": c.to_uppercase()}),
        );
    }
    filters
}

/// Faithful port of `query()`: a dimensionless aggregate call (`rowLimit: 1`), then a paginated
/// dimensioned-rows loop (`startRow` advancing by each response's row count, stopping when a
/// page returns fewer rows than requested or `max_rows` is reached), fed into
/// [`normalize_result`]. Matches python's `min(max(1, page_size), 25000)` page-size clamp and its
/// `hit_cap` bookkeeping.
#[allow(clippy::too_many_arguments)]
pub fn query_with<T: SearchAnalyticsTransport>(
    transport: &T,
    bearer: &str,
    site_url: &str,
    start_date: &str,
    end_date: &str,
    dimensions: &[String],
    search_type: &str,
    page_size: i64,
    max_rows: i64,
    filters: Option<&[Value]>,
    data_state: &str,
) -> Value {
    let url = format!(
        "{SEARCH_ANALYTICS_ENDPOINT}/{}/searchAnalytics/query",
        encode_path_segment(site_url)
    );

    let mut common = serde_json::Map::new();
    common.insert("startDate".to_string(), json!(start_date));
    common.insert("endDate".to_string(), json!(end_date));
    common.insert("type".to_string(), json!(search_type));
    common.insert("dataState".to_string(), json!(data_state));
    if let Some(filters) = filters {
        if !filters.is_empty() {
            common.insert(
                "dimensionFilterGroups".to_string(),
                json!([{"filters": filters}]),
            );
        }
    }

    let mut aggregate_body = common.clone();
    aggregate_body.insert("dimensions".to_string(), json!([]));
    aggregate_body.insert("rowLimit".to_string(), json!(1));

    let aggregate_row = match transport.post_json(&url, bearer, &Value::Object(aggregate_body)) {
        Ok((status, body)) if (200..300).contains(&status) => {
            let parsed: Value = match serde_json::from_str(&body) {
                Ok(v) => v,
                Err(e) => return json!({"error": e.to_string(), "property": site_url}),
            };
            parsed
                .get("rows")
                .and_then(Value::as_array)
                .and_then(|rows| rows.first())
                .cloned()
                .unwrap_or(json!({}))
        }
        Ok((status, body)) => {
            return json!({"error": format!("{status} {body}"), "property": site_url})
        }
        Err(e) => return json!({"error": e, "property": site_url}),
    };

    let page_size = page_size.max(1).min(25_000);
    let mut rows: Vec<Value> = Vec::new();
    let mut start_row: i64 = 0;
    let mut hit_cap = false;

    while start_row < max_rows {
        let size = page_size.min(max_rows - start_row);
        let mut body = common.clone();
        body.insert("dimensions".to_string(), json!(dimensions));
        body.insert("rowLimit".to_string(), json!(size));
        body.insert("startRow".to_string(), json!(start_row));

        let response = match transport.post_json(&url, bearer, &Value::Object(body)) {
            Ok((status, body)) if (200..300).contains(&status) => {
                match serde_json::from_str::<Value>(&body) {
                    Ok(v) => v,
                    Err(e) => return json!({"error": e.to_string(), "property": site_url}),
                }
            }
            Ok((status, body)) => {
                return json!({"error": format!("{status} {body}"), "property": site_url})
            }
            Err(e) => return json!({"error": e, "property": site_url}),
        };

        let batch = response
            .get("rows")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        let batch_len = batch.len() as i64;
        rows.extend(batch);
        if batch_len < size {
            break;
        }
        start_row += batch_len;
        if start_row >= max_rows {
            hit_cap = true;
            break;
        }
    }

    let params = NormalizeParams {
        site_url,
        start_date,
        end_date,
        dimensions,
        search_type,
        aggregate_row: &aggregate_row,
        rows: &rows,
        max_rows,
        hit_cap,
        data_state,
    };
    normalize_result(&params)
}

/// Faithful port of `gsc_query_v2.py`'s `main()`: real entry point wiring [`resolve_bearer_token`]
/// and [`ReqwestSearchAnalyticsTransport`]. Writes the same `json.dumps(result, indent=2)` to
/// `out`, plus to `--out <path>` if given, and returns 1 if `result["error"]` is set (else 0),
/// matching `return 1 if result.get('error') else 0`.
pub fn run(args: &[String], out: &mut dyn std::io::Write, err: &mut dyn std::io::Write) -> i32 {
    let mut property: Option<String> = None;
    let mut start_date: Option<String> = None;
    let mut end_date: Option<String> = None;
    let mut days: i64 = 28;
    let mut dimensions = "query,page".to_string();
    let mut search_type = "web".to_string();
    let mut page_size: i64 = 25_000;
    let mut max_rows: i64 = 100_000;
    let mut device: Option<String> = None;
    let mut country: Option<String> = None;
    let mut data_state = "final".to_string();
    let mut out_path: Option<String> = None;

    let mut i = 0;
    while i < args.len() {
        macro_rules! next {
            () => {{
                i += 1;
                args.get(i).cloned()
            }};
        }
        match args[i].as_str() {
            "--property" | "-p" => property = next!(),
            "--start-date" => start_date = next!(),
            "--end-date" => end_date = next!(),
            "--days" => {
                if let Some(v) = next!() {
                    days = v.parse().unwrap_or(28);
                }
            }
            "--dimensions" => dimensions = next!().unwrap_or(dimensions),
            "--type" => search_type = next!().unwrap_or(search_type),
            "--page-size" => {
                if let Some(v) = next!() {
                    page_size = v.parse().unwrap_or(25_000);
                }
            }
            "--max-rows" => {
                if let Some(v) = next!() {
                    max_rows = v.parse().unwrap_or(100_000);
                }
            }
            "--device" => device = next!(),
            "--country" => country = next!(),
            "--data-state" => data_state = next!().unwrap_or(data_state),
            "--out" => out_path = next!(),
            _ => {}
        }
        i += 1;
    }

    let cfg = google_auth::load_config();
    let prop = property
        .or(cfg.default_property)
        .or_else(|| std::env::var("GSC_PROPERTY").ok());
    let Some(prop) = prop else {
        let _ = writeln!(err, "--property required unless configured");
        return 2;
    };

    let now = super::date_util::civil_now();
    let (start, end) =
        super::date_util::default_date_range(now, days, start_date.as_deref(), end_date.as_deref());
    let filters = build_filters(device.as_deref(), country.as_deref());
    let dims: Vec<String> = dimensions
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect();

    let bearer = match resolve_bearer_token("gsc") {
        Ok(b) => b,
        Err(e) => {
            let result = json!({"error": e.to_string()});
            let text = serde_json::to_string_pretty(&result).unwrap_or_default();
            let _ = writeln!(out, "{text}");
            return 1;
        }
    };

    let result = query_with(
        &ReqwestSearchAnalyticsTransport,
        &bearer,
        &prop,
        &start,
        &end,
        &dims,
        &search_type,
        page_size,
        max_rows,
        if filters.is_empty() {
            None
        } else {
            Some(filters.as_slice())
        },
        &data_state,
    );

    let text = serde_json::to_string_pretty(&result).unwrap_or_default();
    if let Some(path) = &out_path {
        let _ = std::fs::write(path, format!("{text}\n"));
    }
    let _ = writeln!(out, "{text}");
    if result.get("error").map(|e| !e.is_null()).unwrap_or(false) {
        1
    } else {
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Fake [`SearchAnalyticsTransport`] driven by a queue of canned `(status, body)` responses,
    /// one per call, in order (aggregate call first, then each page).
    struct FakeTransport {
        responses: std::cell::RefCell<std::collections::VecDeque<(u16, String)>>,
    }

    impl SearchAnalyticsTransport for FakeTransport {
        fn post_json(
            &self,
            _url: &str,
            _bearer: &str,
            _body: &Value,
        ) -> Result<(u16, String), String> {
            self.responses
                .borrow_mut()
                .pop_front()
                .ok_or_else(|| "no more fake responses".to_string())
        }
    }

    fn fake(responses: Vec<Value>) -> FakeTransport {
        FakeTransport {
            responses: std::cell::RefCell::new(
                responses
                    .into_iter()
                    .map(|v| (200, v.to_string()))
                    .collect(),
            ),
        }
    }

    #[test]
    fn query_with_paginates_and_normalizes() {
        let transport = fake(vec![
            json!({"rows": [{"clicks": 20, "impressions": 500, "ctr": 0.04, "position": 3.9}]}),
            json!({"rows": [{"clicks": 10, "impressions": 200, "ctr": 0.05, "position": 3.4, "keys": ["seo"]}]}),
        ]);
        let dims = vec!["query".to_string()];
        let result = query_with(
            &transport,
            "tok",
            "sc-domain:example.com",
            "2026-08-01",
            "2026-08-28",
            &dims,
            "web",
            25_000,
            100_000,
            None,
            "final",
        );
        assert_eq!(result["aggregate"]["clicks"], 20.0);
        assert_eq!(result["rows"][0]["query"], "seo");
        assert_eq!(result["error"], Value::Null);
    }

    #[test]
    fn query_with_reports_transport_error() {
        struct ErrTransport;
        impl SearchAnalyticsTransport for ErrTransport {
            fn post_json(
                &self,
                _u: &str,
                _b: &str,
                _body: &Value,
            ) -> Result<(u16, String), String> {
                Err("connection refused".to_string())
            }
        }
        let dims = vec!["query".to_string()];
        let result = query_with(
            &ErrTransport,
            "tok",
            "sc-domain:example.com",
            "2026-08-01",
            "2026-08-28",
            &dims,
            "web",
            25_000,
            100_000,
            None,
            "final",
        );
        assert_eq!(result["error"], "connection refused");
        assert_eq!(result["property"], "sc-domain:example.com");
    }

    #[test]
    fn query_with_reports_http_error_status() {
        struct StatusTransport;
        impl SearchAnalyticsTransport for StatusTransport {
            fn post_json(
                &self,
                _u: &str,
                _b: &str,
                _body: &Value,
            ) -> Result<(u16, String), String> {
                Ok((403, "Forbidden".to_string()))
            }
        }
        let dims = vec!["query".to_string()];
        let result = query_with(
            &StatusTransport,
            "tok",
            "sc-domain:example.com",
            "2026-08-01",
            "2026-08-28",
            &dims,
            "web",
            25_000,
            100_000,
            None,
            "final",
        );
        assert!(result["error"].as_str().unwrap().contains("403"));
    }

    #[test]
    fn encode_path_segment_escapes_colon_and_slash() {
        assert_eq!(
            encode_path_segment("sc-domain:example.com"),
            "sc-domain%3Aexample.com"
        );
        assert_eq!(
            encode_path_segment("https://example.com/"),
            "https%3A%2F%2Fexample.com%2F"
        );
    }

    #[test]
    fn normalize_result_matches_python_shape() {
        let dims = vec!["query".to_string(), "page".to_string()];
        let rows = vec![
            json!({"clicks": 10, "impressions": 200, "ctr": 0.05, "position": 3.456, "keys": ["seo tips", "/blog"]}),
            json!({"clicks": 5, "impressions": 100, "ctr": 0.05, "position": 4.2, "keys": ["seo", "/"]}),
        ];
        let aggregate_row = json!({"clicks": 20, "impressions": 500, "ctr": 0.04, "position": 3.9});
        let params = NormalizeParams {
            site_url: "sc-domain:example.com",
            start_date: "2026-08-01",
            end_date: "2026-08-28",
            dimensions: &dims,
            search_type: "web",
            aggregate_row: &aggregate_row,
            rows: &rows,
            max_rows: 100000,
            hit_cap: false,
            data_state: "final",
        };
        let out = normalize_result(&params);
        assert_eq!(out["property"], "sc-domain:example.com");
        assert_eq!(out["rows"][0]["query"], "seo tips");
        assert_eq!(out["rows"][0]["page"], "/blog");
        assert_eq!(out["rows"][0]["ctr"], 5.0);
        assert_eq!(out["aggregate"]["clicks"], 20.0);
        assert_eq!(out["dimension_sum"]["clicks"], 15.0);
        // 15/20 = 0.75
        assert_eq!(out["coverage"]["query_click_coverage"], 0.75);
        assert_eq!(out["coverage"]["complete"], Value::Null);
        assert_eq!(out["error"], Value::Null);
    }

    #[test]
    fn normalize_result_zero_aggregate_coverage_is_null() {
        let dims = vec!["query".to_string()];
        let rows: Vec<Value> = vec![];
        let aggregate_row = json!({});
        let params = NormalizeParams {
            site_url: "sc-domain:example.com",
            start_date: "2026-08-01",
            end_date: "2026-08-28",
            dimensions: &dims,
            search_type: "web",
            aggregate_row: &aggregate_row,
            rows: &rows,
            max_rows: 100,
            hit_cap: true,
            data_state: "final",
        };
        let out = normalize_result(&params);
        assert_eq!(out["coverage"]["query_click_coverage"], Value::Null);
        assert_eq!(out["coverage"]["hit_client_cap"], true);
        assert_eq!(out["coverage"]["complete"], false);
    }

    #[test]
    fn build_filters_uppercases_device_and_country() {
        let filters = build_filters(Some("mobile"), Some("us"));
        assert_eq!(filters.len(), 2);
        assert_eq!(filters[0]["expression"], "MOBILE");
        assert_eq!(filters[1]["expression"], "US");
    }

    #[test]
    fn build_filters_empty_when_none() {
        assert!(build_filters(None, None).is_empty());
    }

    #[test]
    fn oauth_token_is_used_without_any_service_account_call() {
        let http =
            test_support::FakeTokenEndpoint::new(200, json!({"access_token": "ya29.unused"}));
        let result = bearer_with_service_account_fallback(
            "gsc",
            Ok("oauth-token".to_string()),
            Some("/sa.json"),
            &http,
            &|path: &str| test_support::load_fixture_key(path),
            1_700_000_000,
        );
        assert_eq!(result, Ok("oauth-token".to_string()));
        assert!(http.assertions.borrow().is_empty());
    }

    #[test]
    fn without_oauth_each_api_mints_a_token_for_its_own_scope() {
        let cases = [
            ("gsc", "https://www.googleapis.com/auth/webmasters.readonly"),
            ("indexing", "https://www.googleapis.com/auth/indexing"),
            ("ga4", "https://www.googleapis.com/auth/analytics.readonly"),
        ];
        for (service, scope) in cases {
            let http = test_support::FakeTokenEndpoint::new(
                200,
                json!({"access_token": "ya29.minted", "expires_in": 3599}),
            );
            let result = bearer_with_service_account_fallback(
                service,
                Err("No OAuth token found.".to_string()),
                Some("/sa.json"),
                &http,
                &|path: &str| test_support::load_fixture_key(path),
                1_700_000_000,
            );
            assert_eq!(result, Ok("ya29.minted".to_string()), "{service}");
            let assertions = http.assertions.borrow();
            assert_eq!(assertions.len(), 1, "{service}");
            assert_eq!(
                test_support::assertion_scope(&assertions[0]),
                scope,
                "{service}"
            );
        }
    }

    #[test]
    fn rejected_service_account_is_typed_unavailable_and_redacted() {
        let http = test_support::FakeTokenEndpoint::new(
            401,
            json!({"error": "invalid_client", "error_description": "Unauthorized"}),
        );
        let result = bearer_with_service_account_fallback(
            "gsc",
            Err("No OAuth token found.".to_string()),
            Some("/sa.json"),
            &http,
            &|path: &str| test_support::load_fixture_key(path),
            1_700_000_000,
        );
        let err = match result {
            Err(err) => err,
            Ok(token) => panic!("a rejected key must not yield a token: {token}"),
        };
        let text = err.to_string();
        assert!(
            text.starts_with(
                "unavailable: service account token exchange failed for Google Search Console API: "
            ),
            "{text}"
        );
        assert!(text.contains("invalid_client"), "{text}");
        let assertion = http.assertions.borrow()[0].clone();
        assert!(!text.contains(&assertion), "assertion leaked: {text}");
        assert!(!text.contains("BEGIN PRIVATE KEY"), "key leaked: {text}");
    }

    #[test]
    fn no_service_account_keeps_the_oauth_message_unchanged() {
        let http = test_support::FakeTokenEndpoint::new(200, json!({"access_token": "unused"}));
        let message = "No OAuth token found. Run `google_auth --auth`.".to_string();
        let result = bearer_with_service_account_fallback(
            "gsc",
            Err(message.clone()),
            None,
            &http,
            &|path: &str| test_support::load_fixture_key(path),
            1,
        );
        assert_eq!(result, Err(BearerError::NoCredential(message.clone())));
        let empty = bearer_with_service_account_fallback(
            "gsc",
            Err(message.clone()),
            Some(""),
            &http,
            &|path: &str| test_support::load_fixture_key(path),
            1,
        );
        assert_eq!(empty, Err(BearerError::NoCredential(message)));
        assert!(http.assertions.borrow().is_empty());
    }

    #[test]
    fn unreadable_service_account_file_is_unavailable_without_any_exchange() {
        let http = test_support::FakeTokenEndpoint::new(200, json!({"access_token": "unused"}));
        let result = bearer_with_service_account_fallback(
            "ga4",
            Err("No OAuth token found.".to_string()),
            Some("/sa.json"),
            &http,
            &|_path: &str| -> Result<google_auth::ServiceAccountKey, String> {
                Err("service account file unreadable: /sa.json".to_string())
            },
            1,
        );
        assert_eq!(
            result.unwrap_err().to_string(),
            "unavailable: service account for GA4 Data API v1beta is not usable: service account file unreadable: /sa.json"
        );
        assert!(http.assertions.borrow().is_empty());
    }

    struct BearerRecordingSearchAnalytics {
        bearers: std::cell::RefCell<Vec<String>>,
    }

    impl SearchAnalyticsTransport for BearerRecordingSearchAnalytics {
        fn post_json(
            &self,
            _url: &str,
            bearer: &str,
            _body: &Value,
        ) -> Result<(u16, String), String> {
            self.bearers.borrow_mut().push(bearer.to_string());
            Ok((200, json!({"rows": []}).to_string()))
        }
    }

    #[test]
    fn minted_service_account_token_is_the_bearer_sent_to_search_analytics() {
        let http =
            test_support::FakeTokenEndpoint::new(200, json!({"access_token": "ya29.minted"}));
        let bearer = bearer_with_service_account_fallback(
            "gsc",
            Err("No OAuth token found.".to_string()),
            Some("/sa.json"),
            &http,
            &|path: &str| test_support::load_fixture_key(path),
            1_700_000_000,
        )
        .expect("service account mints a token");
        let transport = BearerRecordingSearchAnalytics {
            bearers: std::cell::RefCell::new(Vec::new()),
        };
        let dims = vec!["query".to_string()];
        let result = query_with(
            &transport,
            &bearer,
            "sc-domain:example.com",
            "2026-08-01",
            "2026-08-28",
            &dims,
            "web",
            25_000,
            100_000,
            None,
            "final",
        );
        assert_eq!(result["error"], Value::Null);
        assert_eq!(
            *transport.bearers.borrow(),
            vec!["ya29.minted".to_string(), "ya29.minted".to_string()]
        );
    }
}

/// Test seams shared by the three GSC routes' fallback tests: a fake token endpoint, a fixed
/// service-account key, and a verifier that reads the `scope` claim of a signed assertion.
#[cfg(test)]
pub(crate) mod test_support {
    use std::cell::RefCell;

    use serde_json::Value;

    use super::google_auth;

    // TEST FIXTURE ONLY: a 2048-bit RSA key pair generated for these unit tests with
    // `openssl genrsa` / `openssl rsa -pubout`. It is not a credential and guards nothing.
    pub const FIXTURE_PRIVATE_KEY_PEM: &str = r#"-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCo9DnVFU/vo5Io
J6UrsGmP2w3Jxll29O+nUIFa9pN5quPHdjr/AaSamKCsBpy7YfVYnjuWtTf0ln8j
j3fufY+Iw/s/6hSwDddcXKPFdCHi+J7r0QcCsAI4VyxbvHCYXwTIPg0Iuvg+usPy
gCu5VWf7wD/UTjF2WHjFmeIOwz1iML6Knw4sqGP7/pU3f8AkbtMbpxCEVAgtw0o/
M2JND+g7naLrOhHEh43chXVMzKja/HG/h5DMg8TNSSWUPBENu8px2YjvQP2tw320
SsEdi2BBjtCLMLXiF3wRf4Lv75PimVilWysZ28CmXtmrU7iTzakR4aRDMoM069+K
OR2SasqtAgMBAAECggEAUSHOb7unQi1rLysyjtNNLc6ERYOhTJV8S/1F0NedpAxj
C1KELBau46otZc5bD0SQG7kIZmupbiOi9AGeFwFmnsd17JBM1Oogo/K8lkIZT7QS
JK2gzzKULlf2LitEancehcX+XlXihcUL+XSBCqOvpl4AiMPvzqPXgxRNUMeCv5Ze
l6ULLNjhPywYWuMIVJWR/YMPP5kiaSWsYy0zXcoFTPKmQJ/ltkwjSIhPLJsKCJ0H
Z5M7d4clB/BMbjGTeC/eF11GCTukjInPDFaftjnjpQIoFpf+492ERYnSJZl9IX4z
fgaN9ak5jdbWtncVxwEe6iAfPu01MxLXhVV497GuRQKBgQDdbWsSAbXLAO7iYgbu
E4RzupCR6xDU3Z6qr7/qDUqDlIl57w6BbQYMQ4rv1u9vG+VOzWonJhoFmWL22D+y
CDYmXBPLlvW0jUagEl1pmYK8qU0/g7mYK5kkKEbCm7Ym8bByvKTJj3vLzRzPqcuC
K83OVvjY2Nulto8/5UjcZ+QeKwKBgQDDVWpM5Slbq7cDIzXABM/uTSAem0bYOI9/
bi81fVRhVYPJr/1XTSK6DbIBQGLrJ2wwvrt9VEx5eS2CwFRfZc6a29HIlSaTmLZd
Evl8eM2kCOuRbgYoJojRyhUJDk+9mDFHW7FctwxAPx9uOGBX75HDW5bcdOsn1yQf
9tQKsC2mhwKBgQC+CUhZPep9/aEH3cXA0jNc94NYGHxrlIC2UPvOrfWDlBmg8pBq
d9027Ujyqm731uMojJdMXiD7KTeMTu/rpayDo4bBth/OA2nXu6s8FCnmLQ9FMZI5
jUFzjLWeE/Fy3v7mmgx7iI9gy/qsJzen0lxheLc9tHBeep3a4rdzoh5f3QKBgQC6
mQgZOPlPVzRXTPV136L61LaQRmlg+HcsloeGo5lN+jERJIvxMACyl46qX2WfmmNi
FXJqAXOkvzvYof53u3uot8EpykG10ba0JwIqBAT+ZH8UyHQdOuKM9m0t33wRdCfv
MQq3tS2A2kweMMDogDVQ2Fe/dfmGb6FU36gkJbUWVQKBgHu+lAyBLFMVmas1L24N
QsGx3zekVyIBwBfpFNN9n7mrClGSSuogM5NZv162EecdssgnRNlv8Mrg0g4Hblhl
/1frgfdruHFKi9u9xYf0qCDZHuZv1PNckOOEbSni7J/5MW02LVHwHotyXjk2vVCj
5fkAD6MjtsxMbA+bGWXjpOYC
-----END PRIVATE KEY-----
"#;

    // TEST FIXTURE ONLY: public half of FIXTURE_PRIVATE_KEY_PEM.
    pub const FIXTURE_PUBLIC_KEY_PEM: &str = r#"-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqPQ51RVP76OSKCelK7Bp
j9sNycZZdvTvp1CBWvaTearjx3Y6/wGkmpigrAacu2H1WJ47lrU39JZ/I4937n2P
iMP7P+oUsA3XXFyjxXQh4vie69EHArACOFcsW7xwmF8EyD4NCLr4PrrD8oAruVVn
+8A/1E4xdlh4xZniDsM9YjC+ip8OLKhj+/6VN3/AJG7TG6cQhFQILcNKPzNiTQ/o
O52i6zoRxIeN3IV1TMyo2vxxv4eQzIPEzUkllDwRDbvKcdmI70D9rcN9tErBHYtg
QY7QizC14hd8EX+C7++T4plYpVsrGdvApl7Zq1O4k82pEeGkQzKDNOvfijkdkmrK
rQIDAQAB
-----END PUBLIC KEY-----
"#;

    /// Records each assertion posted to the token endpoint and answers with a canned status/body.
    pub struct FakeTokenEndpoint {
        pub status: u16,
        pub body: Value,
        pub assertions: RefCell<Vec<String>>,
    }

    impl FakeTokenEndpoint {
        pub fn new(status: u16, body: Value) -> Self {
            Self {
                status,
                body,
                assertions: RefCell::new(Vec::new()),
            }
        }
    }

    impl google_auth::TokenHttpClient for FakeTokenEndpoint {
        fn post_form(&self, url: &str, params: &[(&str, &str)]) -> Result<Value, String> {
            self.post_form_status(url, params).map(|(_, body)| body)
        }

        fn post_form_status(
            &self,
            _url: &str,
            params: &[(&str, &str)],
        ) -> Result<(u16, Value), String> {
            let assertion = params
                .iter()
                .find(|(k, _)| *k == "assertion")
                .map(|(_, v)| v.to_string())
                .unwrap_or_default();
            self.assertions.borrow_mut().push(assertion);
            Ok((self.status, self.body.clone()))
        }
    }

    pub fn fixture_key() -> google_auth::ServiceAccountKey {
        google_auth::ServiceAccountKey {
            client_email: "svc@project.iam.gserviceaccount.com".to_string(),
            private_key: FIXTURE_PRIVATE_KEY_PEM.to_string(),
            private_key_id: Some("test-kid".to_string()),
            token_uri: google_auth::SERVICE_ACCOUNT_TOKEN_URI.to_string(),
        }
    }

    pub fn load_fixture_key(_path: &str) -> Result<google_auth::ServiceAccountKey, String> {
        Ok(fixture_key())
    }

    /// Verifies a signed assertion with the fixture public key and returns its `scope` claim.
    pub fn assertion_scope(jwt: &str) -> String {
        let key = jsonwebtoken::DecodingKey::from_rsa_pem(FIXTURE_PUBLIC_KEY_PEM.as_bytes())
            .expect("fixture public key parses");
        let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::RS256);
        // The test clock is fixed in the past, so only the signature and audience are checked.
        validation.validate_exp = false;
        validation.set_audience(&[google_auth::SERVICE_ACCOUNT_TOKEN_URI]);
        let claims = jsonwebtoken::decode::<Value>(jwt, &key, &validation)
            .expect("assertion verifies with the fixture public key")
            .claims;
        claims["scope"].as_str().unwrap_or_default().to_string()
    }
}
