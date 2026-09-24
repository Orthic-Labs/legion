//! Faithful port of the deterministic, provider-I/O-free logic in
//! `skills/seo/scripts/google_auth.py`.
//!
//! Ported: the `SCOPES` / `SERVICE_AUTH` / `SERVICE_NAMES` tables, `OAUTH_SCOPES` /
//! `OAUTH_REDIRECT_URI`, `load_config`'s file+env merge (`merge_config` is the pure core,
//! `load_config` is the real-filesystem/env entry point), `validate_url`, and the branching
//! logic of `detect_tier` / `check_credentials` (abstracted over an already-resolved
//! [`CredentialState`] instead of re-implementing Google OAuth/service-account I/O — see the
//! module-level gap note in `wf_port::w2_030::mod`).

use std::collections::BTreeMap;
use std::net::IpAddr;

use serde_json::Value;

/// `SERVICE_AUTH` from `google_auth.py`: which auth type each service needs.
pub fn service_auth(service: &str) -> Option<&'static str> {
    match service {
        "psi" => Some("api_key"),
        "crux" => Some("api_key"),
        "crux_history" => Some("api_key"),
        "gsc" => Some("oauth_or_sa"),
        "indexing" => Some("oauth_or_sa"),
        "ga4" => Some("oauth_or_sa"),
        _ => None,
    }
}

/// `SERVICE_NAMES` from `google_auth.py`: human-readable service names.
pub fn service_name(service: &str) -> &str {
    match service {
        "psi" => "PageSpeed Insights v5",
        "crux" => "Chrome UX Report (CrUX) API",
        "crux_history" => "CrUX History API",
        "gsc" => "Google Search Console API",
        "indexing" => "Google Indexing API v3",
        "ga4" => "GA4 Data API v1beta",
        other => other,
    }
}

pub const OAUTH_SCOPES: &str = "https://www.googleapis.com/auth/indexing \
https://www.googleapis.com/auth/webmasters \
https://www.googleapis.com/auth/analytics.readonly";
pub const OAUTH_REDIRECT_URI: &str = "http://localhost:8085";

pub const CONFIG_PATH_SUFFIX: &str = ".config/claude-seo/google-api.json";
pub const TOKEN_PATH_SUFFIX: &str = ".config/claude-seo/oauth-token.json";

/// Mirrors the four keys `load_config()` in `google_auth.py` populates.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GoogleApiConfig {
    pub service_account_path: Option<String>,
    pub api_key: Option<String>,
    pub default_property: Option<String>,
    pub ga4_property_id: Option<String>,
}

/// Pure core of `load_config()`: merges a parsed config-file JSON object (if any) with an env
/// map, exactly matching the python precedence (file value wins if truthy/non-empty string,
/// otherwise fall back to the matching environment variable).
pub fn merge_config(file_config: Option<&Value>, env: &BTreeMap<String, String>) -> GoogleApiConfig {
    let mut cfg = GoogleApiConfig::default();

    if let Some(Value::Object(map)) = file_config {
        cfg.service_account_path = str_field(map, "service_account_path");
        cfg.api_key = str_field(map, "api_key");
        cfg.default_property = str_field(map, "default_property");
        cfg.ga4_property_id = str_field(map, "ga4_property_id");
    }

    if cfg.service_account_path.is_none() {
        cfg.service_account_path = env.get("GOOGLE_APPLICATION_CREDENTIALS").cloned();
    }
    if cfg.api_key.is_none() {
        cfg.api_key = env.get("GOOGLE_API_KEY").cloned();
    }
    if cfg.ga4_property_id.is_none() {
        cfg.ga4_property_id = env.get("GA4_PROPERTY_ID").cloned();
    }
    if cfg.default_property.is_none() {
        cfg.default_property = env.get("GSC_PROPERTY").cloned();
    }

    cfg
}

fn str_field(map: &serde_json::Map<String, Value>, key: &str) -> Option<String> {
    match map.get(key) {
        Some(Value::String(s)) if !s.is_empty() => Some(s.clone()),
        _ => None,
    }
}

/// Real entry point: reads `~/.config/claude-seo/google-api.json` and the four matching
/// environment variables, same as `google_auth.load_config()`.
pub fn load_config() -> GoogleApiConfig {
    let file_config = config_path()
        .and_then(|p| std::fs::read_to_string(p).ok())
        .and_then(|s| serde_json::from_str::<Value>(&s).ok());

    let mut env = BTreeMap::new();
    for key in [
        "GOOGLE_APPLICATION_CREDENTIALS",
        "GOOGLE_API_KEY",
        "GA4_PROPERTY_ID",
        "GSC_PROPERTY",
    ] {
        if let Ok(v) = std::env::var(key) {
            env.insert(key.to_string(), v);
        }
    }

    merge_config(file_config.as_ref(), &env)
}

fn config_path() -> Option<std::path::PathBuf> {
    std::env::var("HOME").ok().map(|home| std::path::Path::new(&home).join(CONFIG_PATH_SUFFIX))
}

/// Faithful port of `validate_url()`: accepts only public `http(s)` URLs, rejecting
/// loopback/private/link-local/metadata hosts. Implemented with hand-rolled URL parsing since
/// no URL-parsing crate is a dependency of this crate (see the report's dependency-patch note).
pub fn validate_url(url: &str) -> bool {
    let scheme_end = match url.find("://") {
        Some(i) => i,
        None => return false,
    };
    let scheme = &url[..scheme_end];
    if scheme != "http" && scheme != "https" {
        return false;
    }
    let rest = &url[scheme_end + 3..];
    let host_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let mut host_port = &rest[..host_end];
    if let Some(at) = host_port.rfind('@') {
        host_port = &host_port[at + 1..];
    }
    let host = if let Some(stripped) = host_port.strip_prefix('[') {
        match stripped.find(']') {
            Some(i) => &stripped[..i],
            None => return false,
        }
    } else {
        match host_port.find(':') {
            Some(i) => &host_port[..i],
            None => host_port,
        }
    };
    if host.is_empty() {
        return false;
    }
    let host_lower = host.to_ascii_lowercase();
    const BLOCKED: [&str; 5] = ["localhost", "127.0.0.1", "0.0.0.0", "::1", "metadata.google.internal"];
    if BLOCKED.contains(&host_lower.as_str()) {
        return false;
    }
    if let Ok(ip) = host.parse::<IpAddr>() {
        if is_blocked_ip(ip) {
            return false;
        }
    }
    true
}

fn is_blocked_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_private() || v4.is_loopback() || v4.is_link_local(),
        IpAddr::V6(v6) => v6.is_loopback(),
    }
}

/// Result of an already-resolved credential lookup (the abstraction point over the Python
/// script's live OAuth-token / service-account file I/O; see the module gap note).
#[derive(Debug, Clone, Default)]
pub struct CredentialState {
    pub api_key: Option<String>,
    /// `None` = no OAuth token on disk. `Some(true)` = token present and either valid or
    /// expired-with-refresh-token (python's "will auto-refresh" branch). `Some(false)` = token
    /// present, expired, and no refresh token (python: available=False, "Re-run --auth.").
    pub oauth_token_usable: Option<bool>,
    pub oauth_token_expired_refreshable: bool,
    pub service_account: Option<ServiceAccountState>,
    pub ga4_property_id: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ServiceAccountState {
    pub exists: bool,
    pub has_required_fields: bool,
    pub client_email: Option<String>,
    pub path: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct CredentialCheck {
    pub available: bool,
    pub method: String,
    pub service: String,
    pub error: Option<String>,
    pub note: Option<String>,
    pub client_email: Option<String>,
}

/// Faithful port of `check_credentials()`'s branching, taking an already-resolved
/// [`CredentialState`] in place of the python function's own file/OAuth I/O.
pub fn check_credentials(service: &str, cfg: &GoogleApiConfig, state: &CredentialState) -> CredentialCheck {
    let mut result = CredentialCheck {
        available: false,
        method: service_auth(service).unwrap_or("unknown").to_string(),
        service: service_name(service).to_string(),
        error: None,
        note: None,
        client_email: None,
    };

    match service_auth(service) {
        Some("api_key") => {
            if let Some(key) = &cfg.api_key {
                if !key.is_empty() {
                    result.available = true;
                } else {
                    result.error = Some(no_api_key_error());
                }
            } else {
                result.error = Some(no_api_key_error());
            }
        }
        Some("oauth_or_sa") => {
            if let Some(usable) = state.oauth_token_usable {
                result.available = usable;
                result.method = "oauth_token".to_string();
                if state.oauth_token_expired_refreshable {
                    result.note = Some(
                        "Token expired but refresh_token available (will auto-refresh)".to_string(),
                    );
                } else if !usable {
                    result.error = Some("OAuth token expired and no refresh_token. Re-run --auth.".to_string());
                }
            } else {
                match &state.service_account {
                    None => {
                        result.error = Some(no_credentials_error());
                    }
                    Some(sa) => {
                        if !sa.exists {
                            result.error = Some(format!("Service account file not found: {}", sa.path));
                        } else if !sa.has_required_fields {
                            result.error = Some(
                                "Service account JSON missing required fields (client_email, private_key)"
                                    .to_string(),
                            );
                        } else {
                            result.available = true;
                            result.method = "service_account".to_string();
                            result.client_email = sa.client_email.clone();
                        }
                    }
                }
            }

            if service == "ga4" && result.available {
                match &cfg.ga4_property_id {
                    Some(id) if !id.is_empty() => {}
                    _ => {
                        result.available = false;
                        result.error = Some(
                            "Credentials found but no GA4 property ID configured. Set GA4_PROPERTY_ID or add 'ga4_property_id' to config."
                                .to_string(),
                        );
                    }
                }
            }
        }
        _ => {
            result.error = Some(format!("Unknown service: {service}"));
        }
    }

    result
}

fn no_api_key_error() -> String {
    "No API key found. Set GOOGLE_API_KEY environment variable or add 'api_key' to config".to_string()
}

fn no_credentials_error() -> String {
    "No OAuth token or service account found. Either:\n         1. Run: python scripts/google_auth.py --auth --creds /path/to/client_secret.json\n         2. Or add 'service_account_path' to config".to_string()
}

#[derive(Debug, Clone, PartialEq)]
pub struct TierInfo {
    pub tier: i32,
    pub description: String,
    pub capabilities: Vec<&'static str>,
    pub missing: Option<String>,
}

/// Faithful port of `detect_tier()`'s branching, over an already-resolved [`CredentialState`].
pub fn detect_tier(cfg: &GoogleApiConfig, state: &CredentialState) -> TierInfo {
    let has_api_key = cfg.api_key.as_deref().is_some_and(|s| !s.is_empty());

    let mut has_authenticated = false;
    if state.oauth_token_usable.is_some() {
        has_authenticated = true;
    }
    if !has_authenticated {
        if let Some(sa) = &state.service_account {
            if sa.exists && sa.has_required_fields {
                has_authenticated = true;
            }
        }
    }

    let has_ga4 = has_authenticated && cfg.ga4_property_id.as_deref().is_some_and(|s| !s.is_empty());

    if has_ga4 {
        TierInfo {
            tier: 2,
            description: "Full (API key + Service Account + GA4)".to_string(),
            capabilities: vec![
                "PageSpeed Insights",
                "CrUX",
                "CrUX History",
                "Search Console",
                "URL Inspection",
                "Sitemaps",
                "Indexing API",
                "GA4 Organic Traffic",
            ],
            missing: None,
        }
    } else if has_authenticated {
        TierInfo {
            tier: 1,
            description: "Authenticated (API key + OAuth/Service Account)".to_string(),
            capabilities: vec![
                "PageSpeed Insights",
                "CrUX",
                "CrUX History",
                "Search Console",
                "URL Inspection",
                "Sitemaps",
                "Indexing API",
            ],
            missing: Some("Add 'ga4_property_id' to unlock GA4 organic traffic reports".to_string()),
        }
    } else if has_api_key {
        TierInfo {
            tier: 0,
            description: "API Key Only".to_string(),
            capabilities: vec!["PageSpeed Insights", "CrUX", "CrUX History"],
            missing: Some(
                "Add a service account to unlock Search Console, URL Inspection, and Indexing API"
                    .to_string(),
            ),
        }
    } else {
        TierInfo {
            tier: -1,
            description: "No credentials configured".to_string(),
            capabilities: vec![],
            missing: Some(
                "Create config at ~/.config/claude-seo/google-api.json with at minimum an 'api_key' field. Run with --setup for full instructions."
                    .to_string(),
            ),
        }
    }
}

fn token_path() -> Option<PathBuf> {
    std::env::var("HOME").ok().map(|home| Path::new(&home).join(TOKEN_PATH_SUFFIX))
}

fn now_unix_secs() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

/// Faithful port of `os.path.expanduser()` for the `~/` prefix used by `sa_path`.
pub fn expand_home(path: &str) -> String {
    if let Some(rest) = path.strip_prefix("~/") {
        if let Ok(home) = std::env::var("HOME") {
            return format!("{home}/{rest}");
        }
    }
    path.to_string()
}

/// Real-filesystem resolver for the service-account half of [`CredentialState`]: mirrors the
/// inline file-existence and `client_email`/`private_key` field checks `check_credentials()` /
/// `detect_tier()` perform in python. Does not sign a JWT or build a live credentials object --
/// see the module gap note.
pub fn resolve_service_account(path: &str) -> ServiceAccountState {
    let expanded = expand_home(path);
    if !std::path::Path::new(&expanded).exists() {
        return ServiceAccountState { exists: false, has_required_fields: false, client_email: None, path: expanded };
    }
    let parsed = std::fs::read_to_string(&expanded).ok().and_then(|s| serde_json::from_str::<Value>(&s).ok());
    match parsed {
        Some(Value::Object(map)) => {
            let has_fields = map.contains_key("client_email") && map.contains_key("private_key");
            let client_email = map.get("client_email").and_then(Value::as_str).map(str::to_string);
            ServiceAccountState { exists: true, has_required_fields: has_fields, client_email, path: expanded }
        }
        _ => ServiceAccountState { exists: true, has_required_fields: false, client_email: None, path: expanded },
    }
}

/// Faithful port of `_load_oauth_token()`.
pub fn load_oauth_token_file(path: &Path) -> Option<Value> {
    let text = std::fs::read_to_string(path).ok()?;
    serde_json::from_str(&text).ok()
}

/// Faithful port of `_save_oauth_token()`.
pub fn save_oauth_token_file(path: &Path, token: &Value) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let text = serde_json::to_string_pretty(token).unwrap_or_default();
    std::fs::write(path, text)
}

/// Real-filesystem resolver for the OAuth-token half of [`CredentialState`]: replays the
/// `token_data and token_data.get("access_token")` / expiry-with-or-without-refresh-token
/// branching that `check_credentials()` does inline in python. Returns
/// `(oauth_token_usable, oauth_token_expired_refreshable)`.
pub fn resolve_oauth_token_state(token_path: &Path) -> (Option<bool>, bool) {
    let token = match load_oauth_token_file(token_path) {
        Some(t) => t,
        None => return (None, false),
    };
    let has_access_token = token.get("access_token").and_then(Value::as_str).is_some_and(|s| !s.is_empty());
    if !has_access_token {
        return (None, false);
    }
    let expires_at = token.get("expires_at").and_then(Value::as_f64).unwrap_or(0.0);
    let expired = now_unix_secs() > expires_at - 60.0;
    if !expired {
        return (Some(true), false);
    }
    let has_refresh = token.get("refresh_token").and_then(Value::as_str).is_some_and(|s| !s.is_empty());
    if has_refresh {
        (Some(true), true)
    } else {
        (Some(false), false)
    }
}

/// Real-filesystem/env resolver that builds a [`CredentialState`] the way `check_credentials()`
/// derives its inputs inline in python, wired to the real `~/.config/claude-seo/oauth-token.json`
/// and the configured `service_account_path`. Mirrors the python `if token_data ... else fall
/// back to service account` precedence: the service-account file is only probed when there is no
/// usable OAuth token on disk.
pub fn resolve_credential_state(cfg: &GoogleApiConfig) -> CredentialState {
    let (oauth_token_usable, oauth_token_expired_refreshable) =
        token_path().map(|p| resolve_oauth_token_state(&p)).unwrap_or((None, false));

    let service_account = if oauth_token_usable.is_none() {
        cfg.service_account_path.as_deref().map(resolve_service_account)
    } else {
        None
    };

    CredentialState {
        api_key: cfg.api_key.clone(),
        oauth_token_usable,
        oauth_token_expired_refreshable,
        service_account,
        ga4_property_id: cfg.ga4_property_id.clone(),
    }
}

/// An OAuth client, loaded from a `client_secret.json` file (`web` or `installed` section).
#[derive(Debug, Clone, PartialEq)]
pub struct OauthClient {
    pub client_id: String,
    pub client_secret: String,
    pub auth_uri: String,
    pub token_uri: String,
}

/// Faithful port of `_load_oauth_client()`'s JSON shape: pulls the `web` or `installed` object
/// out of a parsed client_secret document.
pub fn parse_oauth_client(doc: &Value) -> Option<OauthClient> {
    let obj = doc.get("web").or_else(|| doc.get("installed"))?.as_object()?;
    let client_id = obj.get("client_id")?.as_str()?.to_string();
    let client_secret = obj.get("client_secret")?.as_str()?.to_string();
    let auth_uri = obj
        .get("auth_uri")
        .and_then(Value::as_str)
        .unwrap_or("https://accounts.google.com/o/oauth2/auth")
        .to_string();
    let token_uri = obj
        .get("token_uri")
        .and_then(Value::as_str)
        .unwrap_or("https://oauth2.googleapis.com/token")
        .to_string();
    Some(OauthClient { client_id, client_secret, auth_uri, token_uri })
}

/// Faithful port of `_load_oauth_client()`'s file I/O.
pub fn load_oauth_client_file(path: &Path) -> Result<OauthClient, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("Error reading OAuth client file: {e}"))?;
    let doc: Value = serde_json::from_str(&text).map_err(|e| format!("Error reading OAuth client file: {e}"))?;
    parse_oauth_client(&doc)
        .ok_or_else(|| "Error reading OAuth client file: missing client_id/client_secret".to_string())
}

/// Minimal percent-encoder matching python's `urllib.parse.quote()` default safe set (letters,
/// digits, `-_.~` and `/` pass through unescaped; everything else becomes `%XX`).
pub fn quote(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' | b'/' => out.push(b as char),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(byte) = u8::from_str_radix(std::str::from_utf8(&bytes[i + 1..i + 3]).unwrap_or(""), 16) {
                out.push(byte);
                i += 3;
                continue;
            }
        }
        out.push(if bytes[i] == b'+' { b' ' } else { bytes[i] });
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Faithful port of the `auth_url` construction in `run_oauth_flow()`.
pub fn build_auth_url(client: &OauthClient) -> String {
    format!(
        "{}?client_id={}&redirect_uri={}&response_type=code&scope={}&access_type=offline&prompt=consent",
        client.auth_uri,
        client.client_id,
        quote(OAUTH_REDIRECT_URI),
        quote(OAUTH_SCOPES)
    )
}

/// Faithful port of the redirect-callback query-string parsing done inline by `run_oauth_flow()`'s
/// local `http.server.BaseHTTPRequestHandler.do_GET`: pulls `code` out of a `GET <path>?code=...`
/// request line's path.
pub fn extract_auth_code(request_path: &str) -> Option<String> {
    let query = request_path.split_once('?')?.1;
    for pair in query.split('&') {
        let (k, v) = pair.split_once('=')?;
        if k == "code" {
            return Some(percent_decode(v));
        }
    }
    None
}

/// Abstraction over the HTTPS POST calls `_refresh_oauth_token()` / `_exchange_code()` make to
/// the Google token endpoint, so tests never touch the network.
pub trait TokenHttpClient {
    fn post_form(&self, url: &str, params: &[(&str, &str)]) -> Result<Value, String>;
}

/// Real `reqwest`-backed [`TokenHttpClient`].
pub struct ReqwestTokenClient;

impl TokenHttpClient for ReqwestTokenClient {
    fn post_form(&self, url: &str, params: &[(&str, &str)]) -> Result<Value, String> {
        let client = reqwest::blocking::Client::new();
        let resp = client.post(url).form(params).send().map_err(|e| e.to_string())?;
        resp.json::<Value>().map_err(|e| e.to_string())
    }
}

/// Pure core of `_refresh_oauth_token()`: given the current token JSON and the parsed response
/// from the token endpoint, produce the updated token JSON. `None` mirrors python's early
/// `return None` when there is no `refresh_token`.
pub fn apply_refresh_response(mut token: Value, response: &Value) -> Option<Value> {
    {
        let obj = token.as_object()?;
        if !obj.get("refresh_token").and_then(Value::as_str).is_some_and(|s| !s.is_empty()) {
            return None;
        }
    }
    let access_token = response.get("access_token")?.as_str()?.to_string();
    let expires_in = response.get("expires_in").and_then(Value::as_f64).unwrap_or(3600.0);
    let obj = token.as_object_mut()?;
    obj.insert("access_token".to_string(), Value::String(access_token));
    obj.insert("expires_at".to_string(), serde_json::json!(now_unix_secs() + expires_in));
    Some(token)
}

/// Faithful port of `_refresh_oauth_token()`, over the [`TokenHttpClient`] abstraction.
pub fn refresh_oauth_token(
    http: &dyn TokenHttpClient,
    client: &OauthClient,
    token: Value,
) -> Result<Option<Value>, String> {
    let has_refresh = token.get("refresh_token").and_then(Value::as_str).is_some_and(|s| !s.is_empty());
    if !has_refresh {
        return Ok(None);
    }
    let refresh_token = token.get("refresh_token").and_then(Value::as_str).unwrap_or("").to_string();
    let response = http.post_form(
        &client.token_uri,
        &[
            ("client_id", client.client_id.as_str()),
            ("client_secret", client.client_secret.as_str()),
            ("refresh_token", refresh_token.as_str()),
            ("grant_type", "refresh_token"),
        ],
    )?;
    Ok(apply_refresh_response(token, &response))
}

/// Faithful port of `_exchange_code()`'s token-shaping (`expires_at`/`client_id` injection,
/// `client_secret` scrub before persisting), over the [`TokenHttpClient`] abstraction.
pub fn exchange_code(http: &dyn TokenHttpClient, client: &OauthClient, code: &str) -> Result<Value, String> {
    let mut response = http.post_form(
        &client.token_uri,
        &[
            ("code", code),
            ("client_id", client.client_id.as_str()),
            ("client_secret", client.client_secret.as_str()),
            ("redirect_uri", OAUTH_REDIRECT_URI),
            ("grant_type", "authorization_code"),
        ],
    )?;
    let expires_in = response.get("expires_in").and_then(Value::as_f64).unwrap_or(3600.0);
    if let Some(obj) = response.as_object_mut() {
        obj.insert("expires_at".to_string(), serde_json::json!(now_unix_secs() + expires_in));
        obj.insert("client_id".to_string(), Value::String(client.client_id.clone()));
        // SECURITY: never persist client_secret in the token file (matches the python comment).
        obj.remove("client_secret");
    }
    Ok(response)
}

/// Abstraction over `webbrowser.open()` in `run_oauth_flow()`.
pub trait BrowserOpener {
    fn open(&self, url: &str);
}

/// Real OS-backed [`BrowserOpener`].
pub struct SystemBrowserOpener;

impl BrowserOpener for SystemBrowserOpener {
    fn open(&self, url: &str) {
        #[cfg(target_os = "macos")]
        {
            let _ = std::process::Command::new("open").arg(url).status();
        }
        #[cfg(target_os = "linux")]
        {
            let _ = std::process::Command::new("xdg-open").arg(url).status();
        }
        #[cfg(target_os = "windows")]
        {
            let _ = std::process::Command::new("cmd").args(["/C", "start", url]).status();
        }
    }
}

/// Faithful port of `run_oauth_flow()`: builds the auth URL, opens it via [`BrowserOpener`], and
/// blocks (up to `timeout`, matching python's `server.timeout = 300`) on a local TCP listener
/// bound to [`OAUTH_REDIRECT_URI`]'s port for the OAuth redirect carrying `?code=...`, then
/// exchanges it for a token. Returns the raw token JSON on success (callers persist it with
/// [`save_oauth_token_file`], as `main()` does).
pub fn run_oauth_flow(
    creds_path: &Path,
    http: &dyn TokenHttpClient,
    browser: &dyn BrowserOpener,
    timeout: std::time::Duration,
    out: &mut dyn Write,
) -> Result<Value, String> {
    let client = load_oauth_client_file(creds_path)?;
    let auth_url = build_auth_url(&client);

    let _ = writeln!(out, "\nOpen this URL in your browser:\n\n{auth_url}\n");
    let _ = writeln!(out, "Waiting up to 5 minutes for authentication...");
    browser.open(&auth_url);

    let code = wait_for_redirect_code(timeout)?;
    exchange_code(http, &client, &code)
}

fn wait_for_redirect_code(timeout: std::time::Duration) -> Result<String, String> {
    let listener = std::net::TcpListener::bind(("127.0.0.1", 8085)).map_err(|e| e.to_string())?;
    listener.set_nonblocking(true).ok();
    let deadline = std::time::Instant::now() + timeout;
    loop {
        match listener.accept() {
            Ok((mut stream, _)) => {
                let mut buf = [0u8; 4096];
                let n = stream.read(&mut buf).unwrap_or(0);
                let request = String::from_utf8_lossy(&buf[..n]);
                let request_line = request.lines().next().unwrap_or("");
                let path = request_line.split_whitespace().nth(1).unwrap_or("");
                if let Some(code) = extract_auth_code(path) {
                    let body = "<h1>Authentication successful!</h1><p>Close this tab.</p>";
                    let response =
                        format!("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\n\r\n{}", body.len(), body);
                    let _ = stream.write_all(response.as_bytes());
                    return Ok(code);
                }
                let _ = stream.write_all(b"HTTP/1.1 400 Bad Request\r\n\r\n");
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                if std::time::Instant::now() >= deadline {
                    return Err(
                        "\nAuthentication failed or timed out.\nIf the browser showed 'localhost refused to connect', copy the full URL\nfrom the browser address bar and run:\n  python scripts/google_auth.py --exchange --creds <creds> --code 'THE_CODE'".to_string(),
                    );
                }
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
            Err(e) => return Err(e.to_string()),
        }
    }
}

fn tier_to_json(info: &TierInfo) -> Value {
    serde_json::json!({
        "tier": info.tier,
        "description": info.description,
        "capabilities": info.capabilities,
        "missing": info.missing,
    })
}

fn check_to_json(result: &CredentialCheck) -> Value {
    let mut obj = serde_json::Map::new();
    obj.insert("available".to_string(), Value::Bool(result.available));
    obj.insert("method".to_string(), Value::String(result.method.clone()));
    obj.insert("service".to_string(), Value::String(result.service.clone()));
    obj.insert(
        "error".to_string(),
        result.error.clone().map(Value::String).unwrap_or(Value::Null),
    );
    if let Some(note) = &result.note {
        obj.insert("note".to_string(), Value::String(note.clone()));
    }
    if let Some(email) = &result.client_email {
        obj.insert("client_email".to_string(), Value::String(email.clone()));
    }
    Value::Object(obj)
}

fn print_tier_text(info: &TierInfo, out: &mut dyn Write) {
    let _ = writeln!(out, "Credential Tier: {} -- {}", info.tier, info.description);
    if !info.capabilities.is_empty() {
        let _ = writeln!(out, "Available APIs: {}", info.capabilities.join(", "));
    }
    if let Some(missing) = &info.missing {
        let _ = writeln!(out, "Next tier: {missing}");
    }
}

fn print_check_text(tier_info: &TierInfo, results: &[(String, CredentialCheck)], out: &mut dyn Write) {
    let _ = writeln!(out, "Credential Tier: {} -- {}", tier_info.tier, tier_info.description);
    let _ = writeln!(out);
    for (_svc, result) in results {
        let status = if result.available { "OK" } else { "MISSING" };
        let _ = writeln!(out, "  [{status}] {}", result.service);
        if let Some(err) = &result.error {
            let _ = writeln!(out, "         {err}");
        }
        if let Some(email) = &result.client_email {
            let _ = writeln!(out, "         Service account: {email}");
        }
    }
    let _ = writeln!(out);
    if let Some(missing) = &tier_info.missing {
        let _ = writeln!(out, "Tip: {missing}");
    }
}

/// Faithful port of `print_setup_instructions()`.
pub const SETUP_INSTRUCTIONS: &str = r#"
Google SEO API Setup Instructions
=================================

1. CREATE A GOOGLE CLOUD PROJECT
   - Go to https://console.cloud.google.com
   - Create a new project (or select existing)
   - Note the project ID

2. ENABLE APIs
   In API Library (APIs & Services > Library), enable:
   - Google Search Console API
   - PageSpeed Insights API
   - Chrome UX Report API
   - Web Search Indexing API (for Indexing API)
   - Google Analytics Data API (for GA4)

3. CREATE AN API KEY (for PSI, CrUX -- free, no service account needed)
   - APIs & Services > Credentials > Create Credentials > API key
   - Restrict to: PageSpeed Insights API, Chrome UX Report API

4. CREATE A SERVICE ACCOUNT (for GSC, Indexing API, GA4)
   - IAM & Admin > Service Accounts > Create Service Account
   - Download JSON key file, store securely

5. GRANT ACCESS
   - Search Console: Settings > Users and permissions > Add user
     Paste the service account client_email, set as Owner (for Indexing API) or Full (read-only)
   - GA4: Admin > Property Access Management > Add
     Paste email, set Viewer role

6. CREATE CONFIG FILE
   mkdir -p ~/.config/claude-seo
   Save to ~/.config/claude-seo/google-api.json:

   {
     "service_account_path": "/path/to/service_account.json",
     "api_key": "AIzaSy...",
     "default_property": "sc-domain:example.com",
     "ga4_property_id": "properties/123456789"
   }

7. VERIFY
   python scripts/google_auth.py --check

ENVIRONMENT VARIABLE ALTERNATIVES:
   GOOGLE_API_KEY              - API key
   GOOGLE_APPLICATION_CREDENTIALS - Path to service account JSON
   GA4_PROPERTY_ID             - GA4 property ID (e.g., properties/123456789)
   GSC_PROPERTY                - Default Search Console property
"#;

/// Faithful port of `main()`'s argument dispatch (minus `--auth`/`--exchange`'s real network
/// calls, which the caller wires via [`run_with_io`]; this convenience wrapper uses the real
/// `reqwest`/OS-process backends). Returns the process exit code, matching python's
/// `sys.exit(1)` calls (0 otherwise, matching a bare `return`).
pub fn run(args: &[String], out: &mut dyn Write, err: &mut dyn Write) -> i32 {
    run_with_io(args, &ReqwestTokenClient, &SystemBrowserOpener, out, err)
}

/// Same CLI dispatch as [`run`], with the network/browser backends injected -- this is what
/// tests call with fakes.
pub fn run_with_io(
    args: &[String],
    http: &dyn TokenHttpClient,
    browser: &dyn BrowserOpener,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> i32 {
    let mut check: Option<String> = None;
    let mut setup = false;
    let mut tier = false;
    let mut json = false;
    let mut auth = false;
    let mut exchange = false;
    let mut creds: Option<String> = None;
    let mut code: Option<String> = None;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--check" => {
                if i + 1 < args.len() && !args[i + 1].starts_with("--") {
                    i += 1;
                    check = Some(args[i].clone());
                } else {
                    check = Some("all".to_string());
                }
            }
            "--setup" => setup = true,
            "--tier" => tier = true,
            "--json" => json = true,
            "--auth" => auth = true,
            "--exchange" => exchange = true,
            "--creds" => {
                i += 1;
                creds = args.get(i).cloned();
            }
            "--code" => {
                i += 1;
                code = args.get(i).cloned();
            }
            _ => {}
        }
        i += 1;
    }

    if auth {
        let Some(creds_path) = creds else {
            let _ = writeln!(err, "Error: --creds is required with --auth");
            return 1;
        };
        return match run_oauth_flow(Path::new(&creds_path), http, browser, std::time::Duration::from_secs(300), out) {
            Ok(token) => {
                if let Some(p) = token_path() {
                    let _ = save_oauth_token_file(&p, &token);
                    let _ = writeln!(out, "OAuth token saved successfully!");
                    let _ = writeln!(out, "\nToken saved to: {}", p.display());
                }
                0
            }
            Err(e) => {
                let _ = writeln!(err, "{e}");
                1
            }
        };
    }

    if exchange {
        let (Some(creds_path), Some(code)) = (creds, code) else {
            let _ = writeln!(err, "Error: --creds and --code are required with --exchange");
            return 1;
        };
        let client = match load_oauth_client_file(Path::new(&creds_path)) {
            Ok(c) => c,
            Err(e) => {
                let _ = writeln!(err, "{e}");
                return 0;
            }
        };
        return match exchange_code(http, &client, &code) {
            Ok(token) => {
                if let Some(p) = token_path() {
                    let _ = save_oauth_token_file(&p, &token);
                    let _ = writeln!(out, "OAuth token saved successfully!");
                    let _ = writeln!(out, "\nToken saved to: {}", p.display());
                }
                0
            }
            Err(e) => {
                let _ = writeln!(err, "Error exchanging authorization code: {e}");
                1
            }
        };
    }

    if setup {
        let _ = writeln!(out, "{SETUP_INSTRUCTIONS}");
        return 0;
    }

    if tier {
        let cfg = load_config();
        let state = resolve_credential_state(&cfg);
        let info = detect_tier(&cfg, &state);
        if json {
            let _ = writeln!(out, "{}", serde_json::to_string_pretty(&tier_to_json(&info)).unwrap_or_default());
        } else {
            print_tier_text(&info, out);
        }
        return 0;
    }

    if let Some(svc) = check {
        let cfg = load_config();
        let state = resolve_credential_state(&cfg);
        let services: Vec<String> = if svc == "all" {
            ["psi", "crux", "crux_history", "gsc", "indexing", "ga4"].iter().map(|s| s.to_string()).collect()
        } else {
            vec![svc]
        };
        let results: Vec<(String, CredentialCheck)> =
            services.iter().map(|s| (s.clone(), check_credentials(s, &cfg, &state))).collect();
        let tier_info = detect_tier(&cfg, &state);
        if json {
            let services_obj: serde_json::Map<String, Value> =
                results.iter().map(|(s, r)| (s.clone(), check_to_json(r))).collect();
            let out_json = serde_json::json!({"tier": tier_to_json(&tier_info), "services": services_obj});
            let _ = writeln!(out, "{}", serde_json::to_string_pretty(&out_json).unwrap_or_default());
        } else {
            print_check_text(&tier_info, &results, out);
        }
        return 0;
    }

    // Default: show tier (no --check/--setup/--tier/--auth/--exchange given).
    let cfg = load_config();
    let state = resolve_credential_state(&cfg);
    let info = detect_tier(&cfg, &state);
    if json {
        let _ = writeln!(out, "{}", serde_json::to_string_pretty(&tier_to_json(&info)).unwrap_or_default());
    } else {
        let _ = writeln!(out, "Credential Tier: {} -- {}", info.tier, info.description);
        if info.missing.is_some() {
            let _ = writeln!(out, "Run --setup for configuration instructions.");
        }
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn service_auth_matches_python_table() {
        assert_eq!(service_auth("psi"), Some("api_key"));
        assert_eq!(service_auth("gsc"), Some("oauth_or_sa"));
        assert_eq!(service_auth("nope"), None);
    }

    #[test]
    fn merge_config_prefers_file_over_env_when_truthy() {
        let file = serde_json::json!({"api_key": "from-file", "default_property": ""});
        let mut env = BTreeMap::new();
        env.insert("GOOGLE_API_KEY".to_string(), "from-env".to_string());
        env.insert("GSC_PROPERTY".to_string(), "sc-domain:example.com".to_string());
        let cfg = merge_config(Some(&file), &env);
        assert_eq!(cfg.api_key.as_deref(), Some("from-file"));
        // empty string in file is falsy in python -> falls back to env
        assert_eq!(cfg.default_property.as_deref(), Some("sc-domain:example.com"));
    }

    #[test]
    fn merge_config_no_file_uses_env_only() {
        let mut env = BTreeMap::new();
        env.insert("GOOGLE_APPLICATION_CREDENTIALS".to_string(), "/path/sa.json".to_string());
        let cfg = merge_config(None, &env);
        assert_eq!(cfg.service_account_path.as_deref(), Some("/path/sa.json"));
        assert_eq!(cfg.api_key, None);
    }

    #[test]
    fn validate_url_rejects_loopback_and_private() {
        assert!(!validate_url("http://localhost"));
        assert!(!validate_url("https://127.0.0.1/x"));
        assert!(!validate_url("https://0.0.0.0"));
        assert!(!validate_url("https://[::1]/x"));
        assert!(!validate_url("https://metadata.google.internal/"));
        assert!(!validate_url("https://10.0.0.5/x"));
        assert!(!validate_url("https://192.168.1.5"));
        assert!(!validate_url("https://172.16.0.1"));
        assert!(!validate_url("ftp://example.com"));
        assert!(!validate_url("not a url"));
    }

    #[test]
    fn validate_url_accepts_public_http_https() {
        assert!(validate_url("https://example.com/page?q=1"));
        assert!(validate_url("http://example.com"));
        assert!(validate_url("https://8.8.8.8"));
    }

    #[test]
    fn detect_tier_no_credentials() {
        let cfg = GoogleApiConfig::default();
        let state = CredentialState::default();
        let tier = detect_tier(&cfg, &state);
        assert_eq!(tier.tier, -1);
        assert!(tier.capabilities.is_empty());
    }

    #[test]
    fn detect_tier_api_key_only() {
        let cfg = GoogleApiConfig { api_key: Some("k".into()), ..Default::default() };
        let state = CredentialState::default();
        let tier = detect_tier(&cfg, &state);
        assert_eq!(tier.tier, 0);
    }

    #[test]
    fn detect_tier_authenticated_without_ga4() {
        let cfg = GoogleApiConfig { api_key: Some("k".into()), ..Default::default() };
        let state = CredentialState { oauth_token_usable: Some(true), ..Default::default() };
        let tier = detect_tier(&cfg, &state);
        assert_eq!(tier.tier, 1);
        assert!(tier.missing.unwrap().contains("ga4_property_id"));
    }

    #[test]
    fn detect_tier_full_with_ga4() {
        let cfg = GoogleApiConfig {
            api_key: Some("k".into()),
            ga4_property_id: Some("properties/1".into()),
            ..Default::default()
        };
        let state = CredentialState { oauth_token_usable: Some(true), ..Default::default() };
        let tier = detect_tier(&cfg, &state);
        assert_eq!(tier.tier, 2);
        assert!(tier.missing.is_none());
    }

    #[test]
    fn check_credentials_api_key_missing() {
        let cfg = GoogleApiConfig::default();
        let state = CredentialState::default();
        let result = check_credentials("psi", &cfg, &state);
        assert!(!result.available);
        assert!(result.error.unwrap().contains("GOOGLE_API_KEY"));
    }

    #[test]
    fn check_credentials_oauth_expired_no_refresh() {
        let cfg = GoogleApiConfig::default();
        let state = CredentialState {
            oauth_token_usable: Some(false),
            oauth_token_expired_refreshable: false,
            ..Default::default()
        };
        let result = check_credentials("gsc", &cfg, &state);
        assert!(!result.available);
        assert_eq!(result.method, "oauth_token");
        assert!(result.error.unwrap().contains("Re-run --auth"));
    }

    #[test]
    fn check_credentials_service_account_missing_fields() {
        let cfg = GoogleApiConfig::default();
        let state = CredentialState {
            service_account: Some(ServiceAccountState {
                exists: true,
                has_required_fields: false,
                client_email: None,
                path: "/tmp/sa.json".into(),
            }),
            ..Default::default()
        };
        let result = check_credentials("gsc", &cfg, &state);
        assert!(!result.available);
        assert!(result.error.unwrap().contains("missing required fields"));
    }

    #[test]
    fn check_credentials_ga4_needs_property_id() {
        let cfg = GoogleApiConfig::default();
        let state = CredentialState { oauth_token_usable: Some(true), ..Default::default() };
        let result = check_credentials("ga4", &cfg, &state);
        assert!(!result.available);
        assert!(result.error.unwrap().contains("GA4 property ID"));
    }

    #[test]
    fn check_credentials_unknown_service() {
        let cfg = GoogleApiConfig::default();
        let state = CredentialState::default();
        let result = check_credentials("bogus", &cfg, &state);
        assert_eq!(result.error.as_deref(), Some("Unknown service: bogus"));
    }
}
