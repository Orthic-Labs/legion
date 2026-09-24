//! Port of `skills/seo/scripts/keyword_planner.py`.
//!
//! Google Ads API — Keyword Planner for SEO keyword research (search
//! volume, CPC, and competition data). Requires a Google Ads Manager
//! account with a developer token.
//!
//! This module ports the pure, unit-testable core: customer-id
//! normalization, seed-keyword splitting, micros→currency conversion,
//! keyword-idea sorting, CLI bid-string formatting, and Google Ads
//! exception-message joining. Packet r40 closes the remaining gap:
//! [`ReqwestAdsClient`] is a real implementation of [`AdsClient`] against
//! the Google Ads API's REST (JSON/HTTP) surface — the same API surface
//! the Python `google-ads` library calls over gRPC — authenticated with
//! an OAuth2 access token obtained via [`refresh_access_token`] (a plain
//! `reqwest` POST to Google's token endpoint, standing in for what the
//! `google-auth` Python library does internally when `GoogleAdsClient`
//! is given a `refresh_token`). [`run`] ports `main()`'s argv handling
//! end to end.

use std::io::Write;
use std::time::Duration;

use serde::Serialize;
use serde_json::{json, Value};

use crate::wf_port::w2_030::google_auth;

pub const DEFAULT_LANGUAGE_ID: &str = "1000"; // English
pub const DEFAULT_LOCATION_ID: &str = "2840"; // United States
pub const DEFAULT_LIMIT: usize = 50;

/// `customer_id.replace("-", "")` in `_build_ads_client`.
pub fn normalize_customer_id(customer_id: &str) -> String {
    customer_id.replace('-', "")
}

/// `[k.strip() for k in args.keywords.split(",")]` — shared by both the
/// `ideas` and `volume` CLI commands.
pub fn split_keywords(raw: &str) -> Vec<String> {
    raw.split(',').map(str::trim).map(str::to_string).collect()
}

/// `metrics.low_top_of_page_bid_micros / 1_000_000 if ... else None`.
pub fn micros_to_currency(micros: Option<i64>) -> Option<f64> {
    match micros {
        Some(0) | None => None,
        Some(m) => Some(m as f64 / 1_000_000.0),
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct MonthlyVolume {
    pub year: i32,
    pub month: i32,
    pub volume: i64,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct KeywordIdea {
    pub keyword: String,
    pub avg_monthly_searches: Option<i64>,
    pub competition: String,
    pub competition_index: Option<i64>,
    pub low_top_of_page_bid: Option<f64>,
    pub high_top_of_page_bid: Option<f64>,
    pub monthly_volumes: Vec<MonthlyVolume>,
}

/// `monthly_volumes[-12:] if monthly_volumes else []` — keep only the last
/// 12 entries (or fewer, or none).
pub fn last_12_months(mut volumes: Vec<MonthlyVolume>) -> Vec<MonthlyVolume> {
    if volumes.len() > 12 {
        volumes.drain(0..volumes.len() - 12);
    }
    volumes
}

/// `result["ideas"].sort(key=lambda k: k.get("avg_monthly_searches", 0) or 0, reverse=True)`.
///
/// Python's `or 0` also treats `avg_monthly_searches == 0` (falsy) as `0`
/// for the sort key, same as `None`; that is already the effective value
/// here since both `None` and `Some(0)` sort as `0`. Rust's stable sort
/// preserves relative order of equal keys, matching Python's stable
/// `list.sort`.
pub fn sort_ideas_desc(ideas: &mut [KeywordIdea]) {
    ideas.sort_by(|a, b| {
        let ka = a.avg_monthly_searches.unwrap_or(0);
        let kb = b.avg_monthly_searches.unwrap_or(0);
        kb.cmp(&ka)
    });
}

/// `GoogleAdsException` handling: `'; '.join(err.message for err in e.failure.errors)`.
pub fn join_ads_error_messages(messages: &[String]) -> String {
    format!("Google Ads API error: {}", messages.join("; "))
}

/// Non-`GoogleAdsException` catch-all: `f"Keyword Planner error: {e}"` /
/// `f"Keyword volume error: {e}"`.
pub fn generic_ideas_error(e: &str) -> String {
    format!("Keyword Planner error: {e}")
}

pub fn generic_volume_error(e: &str) -> String {
    format!("Keyword volume error: {e}")
}

/// Text-mode bid string, from `main()`'s pretty-printer:
/// `f"${bid_low:.2f}-${bid_high:.2f}" if bid_low and bid_high else "N/A"`.
/// Python's `if bid_low and bid_high` is falsy for `None` *and* `0.0`.
pub fn format_bid_str(low: Option<f64>, high: Option<f64>) -> String {
    let low_truthy = low.is_some_and(|v| v != 0.0);
    let high_truthy = high.is_some_and(|v| v != 0.0);
    if low_truthy && high_truthy {
        format!("${:.2}-${:.2}", low.unwrap(), high.unwrap())
    } else {
        "N/A".to_string()
    }
}

/// Client boundary a caller plugs a real Google Ads client behind for
/// `generate_keyword_ideas`/`get_keyword_volumes`.
pub trait AdsClient {
    fn generate_keyword_ideas(
        &self,
        customer_id: &str,
        seed_keywords: &[String],
        language_id: &str,
        location_id: &str,
    ) -> Result<Vec<KeywordIdea>, AdsError>;

    fn generate_keyword_volumes(
        &self,
        customer_id: &str,
        keywords: &[String],
        language_id: &str,
        location_id: &str,
    ) -> Result<Vec<KeywordIdea>, AdsError>;
}

#[derive(Debug, Clone)]
pub enum AdsError {
    /// `GoogleAdsException` with per-error messages.
    GoogleAds(Vec<String>),
    /// Any other exception, carrying its `str(e)`.
    Other(String),
}

impl AdsError {
    /// The exact error string Python assigns to `result["error"]`.
    pub fn ideas_message(&self) -> String {
        match self {
            AdsError::GoogleAds(msgs) => join_ads_error_messages(msgs),
            AdsError::Other(e) => generic_ideas_error(e),
        }
    }

    pub fn volume_message(&self) -> String {
        match self {
            AdsError::GoogleAds(msgs) => join_ads_error_messages(msgs),
            AdsError::Other(e) => generic_volume_error(e),
        }
    }
}

/// `generate_keyword_ideas(seed_keywords, ...)`, generalized over
/// [`AdsClient`]. Applies the `limit` truncation and descending sort exactly
/// as Python does (sort happens once, over the already-limited list, since
/// the Python loop breaks at `limit` before sorting).
pub fn generate_keyword_ideas_with<C: AdsClient>(
    client: &C,
    customer_id: &str,
    seed_keywords: &[String],
    language_id: &str,
    location_id: &str,
    limit: usize,
) -> (Vec<KeywordIdea>, Option<String>) {
    match client.generate_keyword_ideas(customer_id, seed_keywords, language_id, location_id) {
        Ok(mut ideas) => {
            ideas.truncate(limit);
            sort_ideas_desc(&mut ideas);
            (ideas, None)
        }
        Err(e) => (Vec::new(), Some(e.ideas_message())),
    }
}

pub fn get_keyword_volumes_with<C: AdsClient>(
    client: &C,
    customer_id: &str,
    keywords: &[String],
    language_id: &str,
    location_id: &str,
) -> (Vec<KeywordIdea>, Option<String>) {
    match client.generate_keyword_volumes(customer_id, keywords, language_id, location_id) {
        Ok(kws) => (kws, None),
        Err(e) => (Vec::new(), Some(e.volume_message())),
    }
}

// ---------------------------------------------------------------------
// Real network client (packet r40)
// ---------------------------------------------------------------------

const ADS_API_BASE: &str = "https://googleads.googleapis.com/v17";

/// The `ads_*` fields `_build_ads_client()` reads from
/// `~/.config/claude-seo/google-api.json`, which are not part of
/// [`google_auth::GoogleApiConfig`] (that struct only models the
/// four fields the other four scripts in this chunk use).
#[derive(Debug, Clone, Default)]
pub struct AdsConfig {
    pub developer_token: Option<String>,
    pub customer_id: Option<String>,
    pub login_customer_id: Option<String>,
    pub oauth_client_path: Option<String>,
}

/// Real entry point mirroring `_build_ads_client()`'s config read: parses
/// the same `google-api.json` file `google_auth::load_config` reads, but
/// pulls the Ads-specific keys it does not model.
pub fn load_ads_config() -> AdsConfig {
    let path = std::env::var("HOME")
        .ok()
        .map(|home| std::path::Path::new(&home).join(google_auth::CONFIG_PATH_SUFFIX));
    let file: Option<Value> = path
        .and_then(|p| std::fs::read_to_string(p).ok())
        .and_then(|s| serde_json::from_str(&s).ok());

    let get = |key: &str| -> Option<String> {
        file.as_ref()
            .and_then(|v| v.get(key))
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
    };

    AdsConfig {
        developer_token: get("ads_developer_token"),
        customer_id: get("ads_customer_id"),
        login_customer_id: get("ads_login_customer_id"),
        oauth_client_path: get("oauth_client_path"),
    }
}

/// Loads the stored OAuth token JSON (`~/.config/claude-seo/oauth-token.json`)
/// and the client-secret document at `oauth_client_path`, mirroring the
/// `token_path`/`oauth_client_path` reads in `_build_ads_client()`.
/// Returns `(token_json, oauth_client)`, ready for
/// [`google_auth::refresh_oauth_token`].
pub fn load_oauth_state(oauth_client_path: Option<&str>) -> Option<(Value, google_auth::OauthClient)> {
    let home = std::env::var("HOME").ok()?;
    let token_path = std::path::Path::new(&home).join(google_auth::TOKEN_PATH_SUFFIX);
    let token_json: Value = serde_json::from_str(&std::fs::read_to_string(token_path).ok()?).ok()?;
    if !token_json
        .get("refresh_token")
        .and_then(Value::as_str)
        .is_some_and(|s| !s.is_empty())
    {
        return None;
    }

    let client_path = oauth_client_path?;
    let expanded = if let Some(rest) = client_path.strip_prefix("~/") {
        std::path::Path::new(&home).join(rest)
    } else {
        std::path::PathBuf::from(client_path)
    };
    let client_doc: Value = serde_json::from_str(&std::fs::read_to_string(expanded).ok()?).ok()?;
    let oauth_client = google_auth::parse_oauth_client(&client_doc)?;

    Some((token_json, oauth_client))
}

/// Turns stored OAuth credentials into a short-lived access token by
/// calling [`google_auth::refresh_oauth_token`] — the same
/// `reqwest`-backed token-endpoint POST the other Google-API scripts in
/// this crate use — standing in for what the `google-auth` Python
/// library does internally when `GoogleAdsClient` is given a
/// `refresh_token`.
pub fn refresh_access_token(
    http: &dyn google_auth::TokenHttpClient,
    token_json: Value,
    oauth_client: &google_auth::OauthClient,
) -> Result<String, String> {
    let refreshed = google_auth::refresh_oauth_token(http, oauth_client, token_json)?
        .ok_or_else(|| "OAuth token refresh failed: no refresh_token on stored token".to_string())?;
    refreshed
        .get("access_token")
        .and_then(Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| "OAuth token refresh failed: no access_token in response".to_string())
}

/// Real `reqwest::blocking` implementation of [`AdsClient`] against the
/// Google Ads API's REST/JSON surface
/// (`POST {ADS_API_BASE}/customers/{id}:generateKeywordIdeas` /
/// `:generateKeywordHistoricalMetrics`), authenticated with a
/// caller-supplied bearer token (see [`refresh_access_token`]) and
/// developer token.
pub struct ReqwestAdsClient {
    pub access_token: String,
    pub developer_token: String,
    pub login_customer_id: Option<String>,
}

impl ReqwestAdsClient {
    fn client(&self) -> Result<reqwest::blocking::Client, AdsError> {
        reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(|e| AdsError::Other(e.to_string()))
    }

    fn post(&self, url: &str, body: &Value) -> Result<Value, AdsError> {
        let client = self.client()?;
        let mut req = client
            .post(url)
            .bearer_auth(&self.access_token)
            .header("developer-token", &self.developer_token)
            .json(body);
        if let Some(login) = &self.login_customer_id {
            if !login.is_empty() {
                req = req.header("login-customer-id", login.as_str());
            }
        }
        let resp = req.send().map_err(|e| AdsError::Other(e.to_string()))?;
        let status = resp.status();
        let data: Value = resp.json().unwrap_or(json!({}));
        if !status.is_success() {
            if let Some(errors) = data.get("error").and_then(|e| e.get("details")).and_then(Value::as_array) {
                let messages: Vec<String> = errors
                    .iter()
                    .filter_map(|d| d.get("errors").and_then(Value::as_array))
                    .flatten()
                    .filter_map(|e| e.get("message").and_then(Value::as_str))
                    .map(str::to_string)
                    .collect();
                if !messages.is_empty() {
                    return Err(AdsError::GoogleAds(messages));
                }
            }
            let msg = data
                .get("error")
                .and_then(|e| e.get("message"))
                .and_then(Value::as_str)
                .map(str::to_string)
                .unwrap_or_else(|| format!("HTTP {status}"));
            return Err(AdsError::Other(msg));
        }
        Ok(data)
    }
}

impl AdsClient for ReqwestAdsClient {
    fn generate_keyword_ideas(
        &self,
        customer_id: &str,
        seed_keywords: &[String],
        language_id: &str,
        location_id: &str,
    ) -> Result<Vec<KeywordIdea>, AdsError> {
        let url = format!("{ADS_API_BASE}/customers/{customer_id}:generateKeywordIdeas");
        let body = json!({
            "language": format!("languageConstants/{language_id}"),
            "geoTargetConstants": [format!("geoTargetConstants/{location_id}")],
            "keywordPlanNetwork": "GOOGLE_SEARCH",
            "keywordSeed": {"keywords": seed_keywords},
        });
        let data = self.post(&url, &body)?;
        let results = data.get("results").and_then(Value::as_array).cloned().unwrap_or_default();
        Ok(results.iter().map(parse_keyword_idea).collect())
    }

    fn generate_keyword_volumes(
        &self,
        customer_id: &str,
        keywords: &[String],
        language_id: &str,
        location_id: &str,
    ) -> Result<Vec<KeywordIdea>, AdsError> {
        let url = format!("{ADS_API_BASE}/customers/{customer_id}:generateKeywordHistoricalMetrics");
        let body = json!({
            "keywords": keywords,
            "language": format!("languageConstants/{language_id}"),
            "geoTargetConstants": [format!("geoTargetConstants/{location_id}")],
            "keywordPlanNetwork": "GOOGLE_SEARCH",
        });
        let data = self.post(&url, &body)?;
        let results = data.get("results").and_then(Value::as_array).cloned().unwrap_or_default();
        Ok(results.iter().map(parse_keyword_volume).collect())
    }
}

fn parse_metrics(metrics: &Value) -> (Option<i64>, String, Option<i64>, Option<f64>, Option<f64>) {
    let avg = metrics.get("avgMonthlySearches").and_then(Value::as_i64);
    let competition = metrics.get("competition").and_then(Value::as_str).unwrap_or("UNSPECIFIED").to_string();
    let competition_index = metrics.get("competitionIndex").and_then(Value::as_i64);
    let low = metrics
        .get("lowTopOfPageBidMicros")
        .and_then(Value::as_i64)
        .and_then(|m| micros_to_currency(Some(m)));
    let high = metrics
        .get("highTopOfPageBidMicros")
        .and_then(Value::as_i64)
        .and_then(|m| micros_to_currency(Some(m)));
    (avg, competition, competition_index, low, high)
}

/// One `results[]` entry of `GenerateKeywordIdeasResponse`, transcoded to
/// JSON, into a [`KeywordIdea`] — matching the `for idea in
/// response.results` loop body in `generate_keyword_ideas`.
fn parse_keyword_idea(idea: &Value) -> KeywordIdea {
    let keyword = idea.get("text").and_then(Value::as_str).unwrap_or("").to_string();
    let metrics = idea.get("keywordIdeaMetrics").cloned().unwrap_or(json!({}));
    let (avg, competition, competition_index, low, high) = parse_metrics(&metrics);
    let monthly_volumes: Vec<MonthlyVolume> = metrics
        .get("monthlySearchVolumes")
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .map(|mv| MonthlyVolume {
                    year: mv.get("year").and_then(Value::as_i64).unwrap_or(0) as i32,
                    month: mv.get("month").and_then(Value::as_i64).unwrap_or(0) as i32,
                    volume: mv.get("monthlySearches").and_then(Value::as_i64).unwrap_or(0),
                })
                .collect()
        })
        .unwrap_or_default();

    KeywordIdea {
        keyword,
        avg_monthly_searches: avg,
        competition,
        competition_index,
        low_top_of_page_bid: low,
        high_top_of_page_bid: high,
        monthly_volumes: last_12_months(monthly_volumes),
    }
}

/// One `results[]` entry of `GenerateKeywordHistoricalMetricsResponse`,
/// into a [`KeywordIdea`] — matching `get_keyword_volumes`'s loop body
/// (no `monthly_volumes` field there, matching Python's `result["keywords"]`
/// shape, which omits it).
fn parse_keyword_volume(kw: &Value) -> KeywordIdea {
    let keyword = kw.get("text").and_then(Value::as_str).unwrap_or("").to_string();
    let metrics = kw.get("keywordMetrics").cloned().unwrap_or(json!({}));
    let (avg, competition, competition_index, low, high) = parse_metrics(&metrics);
    KeywordIdea {
        keyword,
        avg_monthly_searches: avg,
        competition,
        competition_index,
        low_top_of_page_bid: low,
        high_top_of_page_bid: high,
        monthly_volumes: Vec::new(),
    }
}

/// Resolves an [`AdsError`] into the `Err(GoogleAdsException)` vs.
/// `Err(Exception)` branch it should classify as, when the transport
/// layer above hasn't already done so (used by callers building an
/// [`AdsClient`] on top of a raw transport, e.g. tests).
pub fn ads_error_from_status(status: u16, body: &Value) -> AdsError {
    if let Some(errors) = body.get("error").and_then(|e| e.get("details")).and_then(Value::as_array) {
        let messages: Vec<String> = errors
            .iter()
            .filter_map(|d| d.get("errors").and_then(Value::as_array))
            .flatten()
            .filter_map(|e| e.get("message").and_then(Value::as_str))
            .map(str::to_string)
            .collect();
        if !messages.is_empty() {
            return AdsError::GoogleAds(messages);
        }
    }
    AdsError::Other(format!("HTTP {status}"))
}

/// Resolves the OAuth access token + developer/login/customer identifiers
/// needed to build a [`ReqwestAdsClient`], mirroring `_build_ads_client()`
/// end to end (config + oauth-token.json + client-secret file + live
/// token refresh). Returns `Err(message)` matching one of Python's
/// `result["error"]` strings when a prerequisite is missing.
pub fn build_ads_client() -> Result<(ReqwestAdsClient, String), String> {
    let ads_cfg = load_ads_config();
    let dev_token = ads_cfg.developer_token.ok_or_else(|| {
        "Error: No Google Ads developer token configured. Add 'ads_developer_token' to \
~/.config/claude-seo/google-api.json. Get a token at: https://ads.google.com/aw/apicenter"
            .to_string()
    })?;
    let customer_id = ads_cfg
        .customer_id
        .map(|c| normalize_customer_id(&c))
        .filter(|c| !c.is_empty())
        .ok_or_else(|| {
            "Error: No Google Ads customer ID configured. Add 'ads_customer_id' \
(format: 123-456-7890) to config."
                .to_string()
        })?;
    let login_customer_id = ads_cfg.login_customer_id.map(|c| normalize_customer_id(&c));

    let (token_json, oauth_client) = load_oauth_state(ads_cfg.oauth_client_path.as_deref())
        .ok_or_else(|| "Error building Google Ads client: no OAuth token configured.".to_string())?;
    let http = google_auth::ReqwestTokenClient;
    let access_token = refresh_access_token(&http, token_json, &oauth_client)
        .map_err(|e| format!("Error building Google Ads client: {e}"))?;

    Ok((ReqwestAdsClient { access_token, developer_token: dev_token, login_customer_id }, customer_id))
}

/// CLI arg bundle mirroring `argparse` in `keyword_planner.py`'s `main()`.
#[derive(Debug, Clone)]
struct Args {
    command: String,
    keywords: String,
    limit: usize,
    language: String,
    location: String,
    json: bool,
}

fn parse_args(args: &[String]) -> Result<Args, String> {
    let mut positionals: Vec<String> = Vec::new();
    let mut limit = DEFAULT_LIMIT;
    let mut language = DEFAULT_LANGUAGE_ID.to_string();
    let mut location = DEFAULT_LOCATION_ID.to_string();
    let mut json_out = false;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--limit" => {
                i += 1;
                let v = args.get(i).ok_or("--limit requires a value")?;
                limit = v.parse().map_err(|_| format!("argument --limit: invalid int value: '{v}'"))?;
            }
            "--language" => {
                i += 1;
                language = args.get(i).ok_or("--language requires a value")?.clone();
            }
            "--location" => {
                i += 1;
                location = args.get(i).ok_or("--location requires a value")?.clone();
            }
            "--json" | "-j" => json_out = true,
            other if !other.starts_with("--") => positionals.push(other.to_string()),
            other => return Err(format!("unrecognized argument: {other}")),
        }
        i += 1;
    }

    if positionals.len() < 2 {
        return Err("the following arguments are required: command, keywords".to_string());
    }
    let command = positionals[0].clone();
    if command != "ideas" && command != "volume" {
        return Err(format!("argument command: invalid choice: '{command}' (choose from 'ideas', 'volume')"));
    }
    Ok(Args { command, keywords: positionals[1].clone(), limit, language, location, json: json_out })
}

/// Port of `keyword_planner.py`'s `main()`, parameterized over an
/// [`AdsClient`] and stdout/stderr sinks. `client` and `customer_id` are
/// the result of [`build_ads_client`] in a real run (kept separate here
/// so tests can pass a fake client with a fixed customer id, matching
/// how `_build_ads_client()` is a distinct step before either command
/// runs in Python). Returns the process exit code.
pub fn run<C: AdsClient>(
    args: &[String],
    client: &C,
    customer_id: &str,
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

    let (ideas, volumes, error): (Vec<KeywordIdea>, Vec<KeywordIdea>, Option<String>) = if parsed.command == "ideas" {
        let seeds = split_keywords(&parsed.keywords);
        let (ideas, error) =
            generate_keyword_ideas_with(client, customer_id, &seeds, &parsed.language, &parsed.location, parsed.limit);
        (ideas, Vec::new(), error)
    } else {
        let kws = split_keywords(&parsed.keywords);
        let (volumes, error) = get_keyword_volumes_with(client, customer_id, &kws, &parsed.language, &parsed.location);
        (Vec::new(), volumes, error)
    };

    if let Some(err) = &error {
        let _ = writeln!(stderr, "Error: {err}");
        if !parsed.json {
            return 1;
        }
    }

    if parsed.json {
        let value = if parsed.command == "ideas" {
            json!({"seed_keywords": split_keywords(&parsed.keywords), "ideas": ideas, "error": error})
        } else {
            json!({"keywords": volumes, "error": error})
        };
        let _ = writeln!(stdout, "{}", serde_json::to_string_pretty(&value).unwrap_or_default());
        return 0;
    }

    if parsed.command == "ideas" {
        let _ = writeln!(stdout, "=== Keyword Ideas ===");
        for (i, idea) in ideas.iter().take(20).enumerate() {
            let vol = idea.avg_monthly_searches.map(|v| v.to_string()).unwrap_or_else(|| "?".to_string());
            let bid_str = format_bid_str(idea.low_top_of_page_bid, idea.high_top_of_page_bid);
            let _ = writeln!(
                stdout,
                "  {:2}. {:40} | Vol: {:>8} | Comp: {:8} | CPC: {}",
                i + 1,
                idea.keyword,
                vol,
                idea.competition,
                bid_str
            );
        }
    } else {
        let _ = writeln!(stdout, "=== Keyword Volumes ===");
        for kw in &volumes {
            let vol = kw.avg_monthly_searches.map(|v| v.to_string()).unwrap_or_else(|| "?".to_string());
            let _ = writeln!(stdout, "  {:40} | Vol: {:>8} | Comp: {}", kw.keyword, vol, kw.competition);
        }
    }

    0
}
