//! Port of `skills/seo/scripts/bing_webmaster.py` (packet r33 closes the
//! previously-open HTTP gap).
//!
//! `bing_webmaster.py` is primarily an HTTPS client for the Bing Webmaster
//! Tools JSON API (`urllib.request` GET/POST calls to `ssl.bing.com`). The
//! live `call()` request/response round trip now runs behind the
//! [`Transport`] trait ([`ReqwestTransport`] is the production impl, using
//! this crate's existing `reqwest::blocking` dependency); [`run`]
//! reproduces `main()`'s full CLI dispatch. What was already ported stays
//! exactly as it was: the API-key-missing error path, subcommand-to-method
//! mapping, request URL/query construction, and the `{"d": ...}`
//! response-envelope unwrap.

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

/// HTTP boundary for `call()`'s GET/POST round trip. Mirrors
/// `urllib.request.urlopen`/`HTTPError`: `Ok((status, body))` for any
/// response that reached the server (2xx or an error status), `Err` for a
/// transport-level failure (Python's generic `except Exception` branch,
/// which `call()` turns into `{"error": str(e), "method": method}`).
pub trait Transport {
    fn get(&self, url: &str) -> Result<(u16, String), String>;
    fn post_json(&self, url: &str, body: &BTreeMap<String, String>) -> Result<(u16, String), String>;
}

/// `call(method, params, body)`, generalized over any [`Transport`]:
/// builds the URL, does a GET (no body) or POST (JSON body), and maps the
/// response the same way the Python does (HTTPError -> `HTTP {code}` with
/// truncated detail; other exception -> `{error, method}`; success ->
/// parse + unwrap `{"d": ...}`; non-JSON body -> the `"non-JSON response"`
/// shape).
pub fn call(
    transport: &dyn Transport,
    method: &str,
    api_key: &str,
    params: &BTreeMap<String, String>,
    body: Option<&BTreeMap<String, String>>,
) -> CallResult {
    let param_pairs: Vec<(&str, Option<&str>)> =
        params.iter().map(|(k, v)| (k.as_str(), Some(v.as_str()))).collect();
    let url = build_request_url(method, api_key, &param_pairs);

    let outcome = match body {
        Some(b) => transport.post_json(&url, b),
        None => transport.get(&url),
    };

    match outcome {
        Ok((status, resp_body)) if status < 400 => parse_response_body(method, &resp_body),
        Ok((status, resp_body)) => http_error_result(method, status, &resp_body),
        Err(message) => CallResult {
            method: method.to_string(),
            error: Some(message),
            detail: None,
            d: None,
        },
    }
}

/// Outcome of [`run`]: the JSON printed to stdout (truncated to 4000
/// chars, matching `print(json.dumps(res, indent=1)[:4000])`) and the
/// process exit code (`1 if res.get("error") else 0`, matching Python's
/// `sys.exit`). Argparse-style usage errors (`ap.error(...)`) are reported
/// via `usage_error` instead, since Python's `ap.error` prints to stderr
/// and exits 2 before ever building a `res` dict.
#[derive(Debug, Clone, PartialEq)]
pub struct RunOutcome {
    pub printed: Option<String>,
    pub usage_error: Option<String>,
    pub written_json: Option<String>,
    pub exit_code: i32,
}

/// CLI-shaped arguments, matching `argparse`'s positional/optional flags.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct BwtArgs {
    pub command: String,
    pub method: Option<String>,
    pub site: Option<String>,
    pub url: Option<String>,
    pub out: Option<String>,
}

/// `main()`: resolve the API key, dispatch the subcommand, call the API,
/// optionally write the full JSON to `--json`, and print/exit. `env_key`
/// mirrors `os.environ.get("BING_API_KEY")`.
pub fn run(args: &BwtArgs, env_key: Option<&str>, transport: &dyn Transport) -> RunOutcome {
    let dispatch = resolve_dispatch(
        &args.command,
        args.method.as_deref(),
        args.site.as_deref(),
        args.url.as_deref(),
    );
    let dispatch = match dispatch {
        Ok(d) => d,
        Err(usage) => {
            return RunOutcome {
                printed: None,
                usage_error: Some(usage),
                written_json: None,
                exit_code: 2,
            }
        }
    };

    let api_key = match require_key(env_key) {
        Ok(k) => k,
        Err(_message) => {
            return RunOutcome {
                printed: None,
                usage_error: None,
                written_json: None,
                exit_code: MISSING_KEY_EXIT_CODE,
            }
        }
    };

    let res = match dispatch {
        Dispatch::Get { method, params } => call(transport, &method, &api_key, &params, None),
        Dispatch::Post { method, body } => call(transport, &method, &api_key, &BTreeMap::new(), Some(&body)),
    };

    let full_json = serde_json::to_string_pretty(&res).unwrap_or_default();
    let printed: String = full_json.chars().take(4000).collect();
    let exit_code = if res.is_error() { 1 } else { 0 };

    RunOutcome {
        printed: Some(printed),
        usage_error: None,
        written_json: args.out.as_ref().map(|_| full_json),
        exit_code,
    }
}

/// Production [`Transport`]: a blocking `reqwest::blocking::Client`,
/// matching `urllib.request.urlopen(req, timeout=30)` with the same
/// `User-Agent: seo-audit/1.0` header.
pub struct ReqwestTransport {
    client: reqwest::blocking::Client,
}

impl ReqwestTransport {
    pub fn new() -> Self {
        Self {
            client: reqwest::blocking::Client::builder()
                .timeout(std::time::Duration::from_secs(30))
                .build()
                .expect("reqwest client"),
        }
    }
}

impl Default for ReqwestTransport {
    fn default() -> Self {
        Self::new()
    }
}

impl Transport for ReqwestTransport {
    fn get(&self, url: &str) -> Result<(u16, String), String> {
        let resp = self
            .client
            .get(url)
            .header("User-Agent", "seo-audit/1.0")
            .send()
            .map_err(|e| e.to_string())?;
        let status = resp.status().as_u16();
        let text = resp.text().map_err(|e| e.to_string())?;
        Ok((status, text))
    }

    fn post_json(&self, url: &str, body: &BTreeMap<String, String>) -> Result<(u16, String), String> {
        let resp = self
            .client
            .post(url)
            .header("User-Agent", "seo-audit/1.0")
            .header("Content-Type", "application/json; charset=utf-8")
            .json(body)
            .send()
            .map_err(|e| e.to_string())?;
        let status = resp.status().as_u16();
        let text = resp.text().map_err(|e| e.to_string())?;
        Ok((status, text))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    struct FakeTransport {
        get_response: RefCell<Option<Result<(u16, String), String>>>,
        post_response: RefCell<Option<Result<(u16, String), String>>>,
    }

    impl FakeTransport {
        fn get(resp: Result<(u16, String), String>) -> Self {
            Self {
                get_response: RefCell::new(Some(resp)),
                post_response: RefCell::new(None),
            }
        }
        fn post(resp: Result<(u16, String), String>) -> Self {
            Self {
                get_response: RefCell::new(None),
                post_response: RefCell::new(Some(resp)),
            }
        }
    }

    impl Transport for FakeTransport {
        fn get(&self, _url: &str) -> Result<(u16, String), String> {
            self.get_response.borrow_mut().take().expect("unexpected get")
        }
        fn post_json(&self, _url: &str, _body: &BTreeMap<String, String>) -> Result<(u16, String), String> {
            self.post_response.borrow_mut().take().expect("unexpected post")
        }
    }

    #[test]
    fn call_success_unwraps_d_envelope() {
        let transport = FakeTransport::get(Ok((200, r#"{"d": {"Rank": 1}}"#.to_string())));
        let mut params = BTreeMap::new();
        params.insert("siteUrl".to_string(), "https://example.com/".to_string());
        let res = call(&transport, "GetRankAndTrafficStats", "KEY", &params, None);
        assert!(!res.is_error());
        assert_eq!(res.d, Some(serde_json::json!({"Rank": 1})));
    }

    #[test]
    fn call_http_error_reports_status_and_detail() {
        let transport = FakeTransport::get(Ok((403, "forbidden body".to_string())));
        let res = call(&transport, "GetQueryStats", "KEY", &BTreeMap::new(), None);
        assert!(res.is_error());
        assert_eq!(res.error, Some("HTTP 403".to_string()));
        assert_eq!(res.detail, Some("forbidden body".to_string()));
    }

    #[test]
    fn call_transport_failure_reports_message() {
        let transport = FakeTransport::get(Err("dns failure".to_string()));
        let res = call(&transport, "GetPageStats", "KEY", &BTreeMap::new(), None);
        assert_eq!(res.error, Some("dns failure".to_string()));
        assert_eq!(res.d, None);
    }

    #[test]
    fn call_posts_body_for_submit() {
        let transport = FakeTransport::post(Ok((200, r#"{"d": null}"#.to_string())));
        let mut body = BTreeMap::new();
        body.insert("siteUrl".to_string(), "https://example.com/".to_string());
        body.insert("url".to_string(), "https://example.com/new/".to_string());
        let res = call(&transport, "SubmitUrl", "KEY", &BTreeMap::new(), Some(&body));
        assert!(!res.is_error());
    }

    #[test]
    fn run_missing_key_exits_2() {
        let transport = FakeTransport::get(Ok((200, "{}".to_string())));
        let args = BwtArgs {
            command: "traffic".to_string(),
            site: Some("https://example.com/".to_string()),
            ..Default::default()
        };
        let outcome = run(&args, None, &transport);
        assert_eq!(outcome.exit_code, MISSING_KEY_EXIT_CODE);
        assert!(outcome.printed.is_none());
    }

    #[test]
    fn run_usage_error_missing_site_exits_2_without_calling_transport() {
        struct PanicTransport;
        impl Transport for PanicTransport {
            fn get(&self, _url: &str) -> Result<(u16, String), String> {
                panic!("must not be called");
            }
            fn post_json(&self, _url: &str, _body: &BTreeMap<String, String>) -> Result<(u16, String), String> {
                panic!("must not be called");
            }
        }
        let args = BwtArgs {
            command: "traffic".to_string(),
            ..Default::default()
        };
        let outcome = run(&args, Some("KEY"), &PanicTransport);
        assert_eq!(outcome.exit_code, 2);
        assert_eq!(outcome.usage_error, Some("traffic needs --site".to_string()));
    }

    #[test]
    fn run_success_exits_0_and_prints_result() {
        let transport = FakeTransport::get(Ok((200, r#"{"d": {"ok": true}}"#.to_string())));
        let args = BwtArgs {
            command: "traffic".to_string(),
            site: Some("https://example.com/".to_string()),
            ..Default::default()
        };
        let outcome = run(&args, Some("KEY"), &transport);
        assert_eq!(outcome.exit_code, 0);
        assert!(outcome.printed.unwrap().contains("GetRankAndTrafficStats"));
    }

    #[test]
    fn run_error_result_exits_1_and_records_json_for_out_flag() {
        let transport = FakeTransport::get(Ok((500, "boom".to_string())));
        let args = BwtArgs {
            command: "crawl".to_string(),
            site: Some("https://example.com/".to_string()),
            out: Some("out.json".to_string()),
            ..Default::default()
        };
        let outcome = run(&args, Some("KEY"), &transport);
        assert_eq!(outcome.exit_code, 1);
        assert!(outcome.written_json.unwrap().contains("HTTP 500"));
    }

    #[test]
    fn run_submit_dispatches_post() {
        let transport = FakeTransport::post(Ok((200, r#"{"d": null}"#.to_string())));
        let args = BwtArgs {
            command: "submit".to_string(),
            site: Some("https://example.com/".to_string()),
            url: Some("https://example.com/new/".to_string()),
            ..Default::default()
        };
        let outcome = run(&args, Some("KEY"), &transport);
        assert_eq!(outcome.exit_code, 0);
    }
}
