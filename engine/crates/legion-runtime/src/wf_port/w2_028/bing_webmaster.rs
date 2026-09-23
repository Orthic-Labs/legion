//! Port of `skills/seo/scripts/bing_webmaster.py`.
//!
//! `bing_webmaster.py` is primarily an HTTPS client for the Bing Webmaster
//! Tools JSON API (`urllib.request` GET/POST calls to `ssl.bing.com`). This
//! crate has no HTTP client dependency, so the live `call()` request/response
//! round trip is not ported here — it is the entire remaining gap for this
//! file. What is ported, with the same behavior, is everything pure around
//! that call: the API-key-missing error path, subcommand-to-method mapping,
//! request URL/query construction, and the `{"d": ...}` response-envelope
//! unwrap.

use std::collections::BTreeMap;

use serde_json::Value;

pub const BASE: &str = "https://ssl.bing.com/webmaster/api.svc/json";

/// Mirrors the `SUBCOMMANDS` dict.
pub fn subcommand_method(command: &str) -> Option<&'static str> {
    match command {
        "traffic" => Some("GetRankAndTrafficStats"),
        "queries" => Some("GetQueryStats"),
        "pages" => Some("GetPageStats"),
        "links" => Some("GetUrlLinks"),
        "crawl" => Some("GetCrawlIssues"),
        _ => None,
    }
}

/// Mirrors `_key()`'s missing-key path: `Err` carries the same message
/// printed to stderr before `sys.exit(2)`; the exit code the CLI used is
/// documented on the caller, not modeled as a return value here.
pub const MISSING_KEY_MESSAGE: &str = "Error: BING_API_KEY not set. Get a free key at Bing Webmaster Tools \u{2192} Settings \u{2192} API access, then set BING_API_KEY. See references/free-data-sources.md.";
pub const MISSING_KEY_EXIT_CODE: i32 = 2;

pub fn require_key(env_value: Option<&str>) -> Result<String, String> {
    match env_value {
        Some(k) if !k.is_empty() => Ok(k.to_string()),
        _ => Err(MISSING_KEY_MESSAGE.to_string()),
    }
}

/// Minimal `application/x-www-form-urlencoded`-style percent-encoding
/// matching `urllib.parse.urlencode`'s default (space -> `+`, unreserved
/// characters `A-Za-z0-9_.-~` left alone, everything else `%XX`).
pub fn url_encode_query_component(s: &str) -> String {
    let mut out = String::new();
    for b in s.as_bytes() {
        match *b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'_' | b'.' | b'-' | b'~' => {
                out.push(*b as char)
            }
            b' ' => out.push('+'),
            _ => out.push_str(&format!("%{:02X}", b)),
        }
    }
    out
}

/// Mirrors `call()`'s URL construction: `{BASE}/{method}?apikey=KEY[&params...]`,
/// with `None`-valued params dropped (matching the Python
/// `{k: v for k, v in params.items() if v is not None}` filter). Params are
/// encoded in insertion order.
pub fn build_request_url(method: &str, api_key: &str, params: &[(&str, Option<&str>)]) -> String {
    let mut query: Vec<(String, String)> = vec![("apikey".to_string(), api_key.to_string())];
    for (k, v) in params {
        if let Some(v) = v {
            query.push((k.to_string(), v.to_string()));
        }
    }
    let qs = query
        .into_iter()
        .map(|(k, v)| format!("{}={}", url_encode_query_component(&k), url_encode_query_component(&v)))
        .collect::<Vec<_>>()
        .join("&");
    format!("{BASE}/{method}?{qs}")
}

/// One BWT API result envelope, matching what `call()` returns to its
/// caller: either `{"error": ..., "method": ...}` (optionally with
/// `detail`/`raw`) on failure, or `{"method": ..., "d": ...}` on success
/// with the `{"d": ...}` wrapper unwrapped (or the whole body, if it had no
/// `"d"` key — matching `parsed.get("d", parsed)`).
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct CallResult {
    pub method: String,
    pub error: Option<String>,
    pub detail: Option<String>,
    pub d: Option<Value>,
}

impl CallResult {
    pub fn is_error(&self) -> bool {
        self.error.is_some()
    }
}

/// Mirrors `call()`'s success-path body handling: parse `raw` as JSON and
/// unwrap `{"d": ...}` (`parsed.get("d", parsed)`); a non-JSON body becomes
/// the `"non-JSON response"` error shape with `raw` truncated to 500 chars.
pub fn parse_response_body(method: &str, raw: &str) -> CallResult {
    match serde_json::from_str::<Value>(raw) {
        Ok(parsed) => {
            let d = match &parsed {
                Value::Object(map) => map.get("d").cloned().unwrap_or(parsed.clone()),
                other => other.clone(),
            };
            CallResult {
                method: method.to_string(),
                error: None,
                detail: None,
                d: Some(d),
            }
        }
        Err(_) => CallResult {
            method: method.to_string(),
            error: Some("non-JSON response".to_string()),
            detail: None,
            d: Some(Value::String(raw.chars().take(500).collect())),
        },
    }
}

/// Mirrors the `HTTPError` branch: `{"error": f"HTTP {code}", "method":
/// method, "detail": body[:500]}`.
pub fn http_error_result(method: &str, code: u16, body: &str) -> CallResult {
    CallResult {
        method: method.to_string(),
        error: Some(format!("HTTP {code}")),
        detail: Some(body.chars().take(500).collect()),
        d: None,
    }
}

/// Mirrors main()'s dispatch validation (not the network call itself):
/// resolves `(command, method_arg, site, url)` into the `(method,
/// params/body)` `call()` would be invoked with, or an argparse-style usage
/// error. `params` are query params (GET); `body` fields are the POST body
/// for `submit`.
#[derive(Debug, Clone, PartialEq)]
pub enum Dispatch {
    Get {
        method: String,
        params: BTreeMap<String, String>,
    },
    Post {
        method: String,
        body: BTreeMap<String, String>,
    },
}

pub fn resolve_dispatch(
    command: &str,
    raw_method: Option<&str>,
    site: Option<&str>,
    url: Option<&str>,
) -> Result<Dispatch, String> {
    match command {
        "submit" => match (site, url) {
            (Some(s), Some(u)) => {
                let mut body = BTreeMap::new();
                body.insert("siteUrl".to_string(), s.to_string());
                body.insert("url".to_string(), u.to_string());
                Ok(Dispatch::Post {
                    method: "SubmitUrl".to_string(),
                    body,
                })
            }
            _ => Err("submit needs --site and --url".to_string()),
        },
        "raw" => match raw_method {
            Some(m) => {
                let mut params = BTreeMap::new();
                if let Some(s) = site {
                    params.insert("siteUrl".to_string(), s.to_string());
                }
                Ok(Dispatch::Get {
                    method: m.to_string(),
                    params,
                })
            }
            None => Err("raw needs a method name".to_string()),
        },
        other => match subcommand_method(other) {
            Some(method) => match site {
                Some(s) => {
                    let mut params = BTreeMap::new();
                    params.insert("siteUrl".to_string(), s.to_string());
                    Ok(Dispatch::Get {
                        method: method.to_string(),
                        params,
                    })
                }
                None => Err(format!("{other} needs --site")),
            },
            None => Err(format!("unknown command '{other}'")),
        },
    }
}
