//! Port of `skills/seo/scripts/indexnow.py`.
//!
//! IndexNow lets you ping search engines the moment a URL changes; Bing,
//! Yandex, Seznam, Naver (and others) honor it. Google does NOT — it
//! ignores IndexNow — so this COMPLEMENTS Google Search Console, it does
//! not replace it. Submitting a URL to one participating engine shares it
//! with all of them.
//!
//! This module ports the pure request-shaping/response-classification core:
//! key generation, submit-body construction, and status-code-to-result
//! mapping. The actual HTTPS POST (`urllib.request.urlopen` in Python) is
//! left behind the [`Transport`] trait: this crate does not currently
//! depend on an HTTP client (see the w2_031 report for the `reqwest`
//! `Cargo.toml` addition needed to wire a real transport), so callers
//! supply their own `Transport` impl (e.g. backed by `reqwest::blocking`)
//! to actually submit. `submit_with` reproduces `submit()`'s exact
//! success/error result shape from whatever status/body the transport
//! returns, matching Python's 200/202 = success, else error branches.

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
