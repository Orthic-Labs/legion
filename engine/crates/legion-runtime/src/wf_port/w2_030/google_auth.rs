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
