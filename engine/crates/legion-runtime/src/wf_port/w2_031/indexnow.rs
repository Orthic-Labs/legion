//! Port of `skills/seo/scripts/indexnow.py`.
//!
//! IndexNow lets you ping search engines the moment a URL changes; Bing,
//! Yandex, Seznam, Naver (and others) honor it. Google does NOT — it
//! ignores IndexNow — so this COMPLEMENTS Google Search Console, it does
//! not replace it. Submitting a URL to one participating engine shares it
//! with all of them.
//!
//! This module ports the full script: key generation, submit-body
//! construction, status-code-to-result mapping, and now (packet r39) the
//! real HTTPS POST plus the `main()` CLI. The HTTP call is behind the
//! [`Transport`] trait — [`ReqwestTransport`] is the real
//! `reqwest::blocking` implementation (30s timeout, matching
//! `urllib.request.urlopen(req, timeout=30)`), tests use a fake — so
//! `submit_with` reproduces `submit()`'s exact success/error result shape
//! from whatever status/body the transport returns, matching Python's
//! 200/202 = success, else error branches. [`run`] ports `main()`:
//! `genkey`/`submit` subcommand dispatch, `--host`/`--url`/`--urls`/
//! `--key-location`/`--json` argument parsing, the `INDEXNOW_KEY`
//! environment check (exit 2 if missing, matching `sys.exit(2)`), and the
//! exit-code convention (`0` if `res["status"] in (200, 202)` else `1`).
//! File I/O (`--urls FILE` reads, `--json OUT` writes) is injected via
//! [`UrlsFileReader`] and [`CliOutcome::write_file`] respectively, keeping
//! `run` a pure function of its inputs for testing.

use std::collections::hash_map::RandomState;
use std::hash::{BuildHasher, Hasher};
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::{json, Value};
use sha2::{Digest, Sha256};

pub const ENDPOINT: &str = "https://api.indexnow.org/indexnow";

/// `genkey()` in Python: 32 hex chars derived from OS entropy (sha256 of 32
/// random bytes, truncated to the first 32 hex chars). IndexNow accepts
/// `[a-zA-Z0-9-]` of length 8..128.
///
/// `legion-runtime` has no `rand` dependency (see the w2_031 report), so
/// this draws its entropy the way `std` itself does for `HashMap`'s
/// per-process keys: `std::collections::hash_map::RandomState`, which is
/// seeded from the OS's CSPRNG on every supported platform. It is mixed
/// with the wall clock across several draws and hashed through SHA-256,
/// matching Python's `hashlib.sha256(os.urandom(32)).hexdigest()[:32]`
/// shape (32 bytes of entropy in, 32 lowercase hex chars out).
pub fn genkey() -> String {
    let mut bytes = [0u8; 32];
    for chunk in bytes.chunks_mut(8) {
        let mut hasher = RandomState::new().build_hasher();
        hasher.write_u128(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or_default(),
        );
        let word = hasher.finish().to_le_bytes();
        chunk.copy_from_slice(&word[..chunk.len()]);
    }
    let digest = Sha256::digest(bytes);
    let hex = hex::encode(digest);
    hex[..32].to_string()
}

/// A minimal HTTP transport the caller plugs in to actually submit. Mirrors
/// what `urllib.request.urlopen`/`HTTPError` give `submit()`: either a
/// status code (2xx or an HTTP error status) plus response body, or a
/// transport-level failure (DNS, connect, timeout — `status == 0` in
/// Python's generic `except Exception` branch).
pub trait Transport {
    /// Returns `Ok((status_code, response_body))` for any HTTP response
    /// (including 4xx/5xx — those are not `Err` here, matching Python's
    /// `HTTPError` branch), or `Err(message)` for a transport-level failure
    /// that never got a response, matching Python's `except Exception`.
    fn post_json(&self, url: &str, body: &Value) -> Result<(u16, String), String>;
}

/// `submit(host, urls, key, key_location)` in Python's request-body shape.
pub fn build_submit_body(host: &str, urls: &[String], key: &str, key_location: Option<&str>) -> Value {
    let mut body = json!({
        "host": host,
        "key": key,
        "urlList": urls,
    });
    if let Some(loc) = key_location {
        body["keyLocation"] = json!(loc);
    }
    body
}

/// `submit()`'s result dict, ported field-for-field.
#[derive(Debug, Clone, PartialEq)]
pub struct SubmitResult {
    pub status: u16,
    pub submitted: usize,
    pub host: String,
    pub error: Option<String>,
    pub detail: Option<String>,
}

/// Default key-location URL when `--key-location` is not given:
/// `f"https://{host}/{key}.txt"`.
pub fn default_key_location(host: &str, key: &str) -> String {
    format!("https://{host}/{key}.txt")
}

/// `submit(...)` in Python, generalized over any [`Transport`]. On success
/// (any HTTP status 200/202 is what `main()` treats as accepted — this
/// function reports whatever status was returned; the accept check lives in
/// [`is_accepted`], mirroring `res.get("status") in (200, 202)`).
pub fn submit_with<T: Transport>(
    transport: &T,
    host: &str,
    urls: &[String],
    key: &str,
    key_location: Option<&str>,
) -> SubmitResult {
    let body = build_submit_body(host, urls, key, key_location);
    match transport.post_json(ENDPOINT, &body) {
        Ok((status, _resp_body)) if status < 400 => SubmitResult {
            status,
            submitted: urls.len(),
            host: host.to_string(),
            error: None,
            detail: None,
        },
        Ok((status, resp_body)) => SubmitResult {
            status,
            submitted: 0,
            host: host.to_string(),
            error: Some(http_reason(status)),
            detail: Some(resp_body.chars().take(300).collect()),
        },
        Err(message) => SubmitResult {
            status: 0,
            submitted: 0,
            host: host.to_string(),
            error: Some(message),
            detail: None,
        },
    }
}

/// `res.get("status") in (200, 202)` — the CLI's exit-code check.
pub fn is_accepted(result: &SubmitResult) -> bool {
    matches!(result.status, 200 | 202)
}

/// Standard reason phrases for the statuses IndexNow documents:
/// 403 = key not found/valid at keyLocation; 422 = URLs don't match host;
/// 429 = rate limited. Falls back to a generic label for anything else,
/// since Python relies on `HTTPError.reason` from the HTTP client rather
/// than a fixed table.
fn http_reason(status: u16) -> String {
    match status {
        400 => "Bad Request".to_string(),
        403 => "Forbidden".to_string(),
        422 => "Unprocessable Entity".to_string(),
        429 => "Too Many Requests".to_string(),
        other => format!("HTTP {other}"),
    }
}

/// `--urls` file parsing: one URL per line, blank lines skipped.
pub fn parse_urls_file(contents: &str) -> Vec<String> {
    contents
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .map(str::to_string)
        .collect()
}

// ---------------------------------------------------------------------
// Real transport (r39): `urllib.request.urlopen(req, timeout=30)` in
// Python, backed by `reqwest::blocking`.
// ---------------------------------------------------------------------

/// Real implementation of [`Transport`]: a blocking `reqwest` POST with a
/// 30s timeout, matching `urllib.request.urlopen(req, timeout=30)`. HTTP
/// error statuses (4xx/5xx) are surfaced as `Ok((status, body))`, matching
/// Python's `HTTPError` branch (which still has a status code and a
/// readable body); only a request that never got a response (DNS,
/// connect, timeout) is `Err`, matching the generic `except Exception`
/// branch.
pub struct ReqwestTransport {
    pub http: reqwest::blocking::Client,
}

impl ReqwestTransport {
    pub fn new() -> Self {
        Self {
            http: reqwest::blocking::Client::builder()
                .timeout(std::time::Duration::from_secs(30))
                .build()
                .unwrap_or_else(|_| reqwest::blocking::Client::new()),
        }
    }
}

impl Default for ReqwestTransport {
    fn default() -> Self {
        Self::new()
    }
}

impl Transport for ReqwestTransport {
    fn post_json(&self, url: &str, body: &Value) -> Result<(u16, String), String> {
        let resp = self
            .http
            .post(url)
            .header("Content-Type", "application/json; charset=utf-8")
            .header("User-Agent", "seo-audit/1.0")
            .json(body)
            .send()
            .map_err(|e| e.to_string())?;
        let status = resp.status().as_u16();
        let text = resp.text().unwrap_or_default();
        Ok((status, text))
    }
}

// ---------------------------------------------------------------------
// CLI (r39): `main()` in `indexnow.py`. `genkey` / `submit --host ...
// [--url ... | --urls FILE] [--key-location ...] [--json OUT]`.
// ---------------------------------------------------------------------

/// Outcome of a CLI run: exit code plus stdout/stderr text, mirroring
/// `main()`'s `print(...)`/`sys.exit(...)` calls without actually calling
/// `std::process::exit`.
pub struct CliOutcome {
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
    /// `Some((path, contents))` when `--json OUT` was given: mirrors
    /// `with open(a.out, "w") as f: json.dump(res, f, indent=1)`. Writing
    /// the file is left to the caller, matching how the transport and
    /// urls-file reads are also injected rather than performed here.
    pub write_file: Option<(String, String)>,
}

/// Reads `--urls FILE` the way Python's `open(a.urls, encoding="utf-8")`
/// plus [`parse_urls_file`] would: any I/O error is surfaced to the
/// caller, who reports it as a CLI failure.
pub trait UrlsFileReader {
    fn read_to_string(&self, path: &str) -> Result<String, String>;
}

/// `main()`, generalized over a [`Transport`] (for `submit`) and a
/// [`UrlsFileReader`] (for `--urls FILE`). `env_key` stands in for
/// `os.environ.get("INDEXNOW_KEY")`; `out_writer`, when `Some`, is called
/// with the path and contents Python would write to `--json OUT` (I/O is
/// left to the caller so this stays a pure function of its inputs).
#[allow(clippy::too_many_arguments)]
pub fn run<T: Transport, F: UrlsFileReader>(
    args: &[String],
    transport: &T,
    files: &F,
    env_key: Option<&str>,
) -> CliOutcome {
    if args.is_empty() {
        return CliOutcome {
            exit_code: 2,
            stdout: String::new(),
            stderr: "the following arguments are required: command".to_string(),
            write_file: None,
        };
    }
    let command = args[0].as_str();

    if command == "genkey" {
        return CliOutcome {
            exit_code: 0,
            stdout: format!("{}\n", genkey()),
            stderr: String::new(),
            write_file: None,
        };
    }

    if command != "submit" {
        return CliOutcome {
            exit_code: 2,
            stdout: String::new(),
            stderr: format!("unknown command '{command}'"),
            write_file: None,
        };
    }

    let mut host: Option<String> = None;
    let mut url: Option<String> = None;
    let mut urls_file: Option<String> = None;
    let mut key_location: Option<String> = None;
    let mut out: Option<String> = None;

    let rest = &args[1..];
    let mut i = 0;
    while i < rest.len() {
        match rest[i].as_str() {
            "--host" => {
                i += 1;
                match rest.get(i) {
                    Some(v) => host = Some(v.clone()),
                    None => return arg_error("--host: expected one argument"),
                }
            }
            "--url" => {
                i += 1;
                match rest.get(i) {
                    Some(v) => url = Some(v.clone()),
                    None => return arg_error("--url: expected one argument"),
                }
            }
            "--urls" => {
                i += 1;
                match rest.get(i) {
                    Some(v) => urls_file = Some(v.clone()),
                    None => return arg_error("--urls: expected one argument"),
                }
            }
            "--key-location" => {
                i += 1;
                match rest.get(i) {
                    Some(v) => key_location = Some(v.clone()),
                    None => return arg_error("--key-location: expected one argument"),
                }
            }
            "--json" => {
                i += 1;
                match rest.get(i) {
                    Some(v) => out = Some(v.clone()),
                    None => return arg_error("--json: expected one argument"),
                }
            }
            other => return arg_error(&format!("unrecognized arguments: {other}")),
        }
        i += 1;
    }

    let key = match env_key {
        Some(k) if !k.is_empty() => k.to_string(),
        _ => {
            return CliOutcome {
                exit_code: 2,
                stdout: String::new(),
                stderr: "Error: INDEXNOW_KEY not set. Run 'python indexnow.py genkey', set the \
value as INDEXNOW_KEY, and host it at https://<host>/<key>.txt. See references/free-data-sources.md."
                    .to_string(),
                write_file: None,
            }
        }
    };

    let host = match host {
        Some(h) => h,
        None => return arg_error("submit needs --host"),
    };

    let mut urls = Vec::new();
    if let Some(u) = &url {
        urls.push(u.clone());
    }
    if let Some(path) = &urls_file {
        match files.read_to_string(path) {
            Ok(contents) => urls.extend(parse_urls_file(&contents)),
            Err(e) => {
                return CliOutcome {
                    exit_code: 2,
                    stdout: String::new(),
                    stderr: e,
                    write_file: None,
                }
            }
        }
    }
    if urls.is_empty() {
        return arg_error("submit needs --url or --urls");
    }

    let loc = key_location.unwrap_or_else(|| default_key_location(&host, &key));
    let result = submit_with(transport, &host, &urls, &key, Some(&loc));
    let json_out = serde_json::to_string_pretty(&submit_result_json(&result)).unwrap_or_default();

    let mut stdout = String::new();
    stdout.push_str(&json_out);
    stdout.push('\n');

    let write_file = out.map(|path| (path, json_out));

    CliOutcome {
        exit_code: if is_accepted(&result) { 0 } else { 1 },
        stdout,
        stderr: String::new(),
        write_file,
    }
}

fn arg_error(msg: &str) -> CliOutcome {
    CliOutcome {
        exit_code: 2,
        stdout: String::new(),
        stderr: msg.to_string(),
        write_file: None,
    }
}

/// `res` dict shape as printed by `json.dumps(res, indent=1)`.
pub fn submit_result_json(result: &SubmitResult) -> Value {
    let mut v = json!({
        "status": result.status,
        "submitted": result.submitted,
        "host": result.host,
    });
    if let Some(e) = &result.error {
        v["error"] = json!(e);
    }
    if let Some(d) = &result.detail {
        v["detail"] = json!(d);
    }
    v
}
