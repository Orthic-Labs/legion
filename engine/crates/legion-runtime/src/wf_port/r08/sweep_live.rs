//! wf_port packet r08 (area `skills/designer/engine/scripts/detector/engines/
//! site/sweep.mjs`, target crate `legion-runtime`).
//!
//! Completes the gap `wf_port::w2_012::sweep`'s module doc left open:
//! `checkStatus`'s HEAD/GET-retry status check and `sweepSite`'s page fetch
//! + link fan-out + finding assembly. Network I/O sits behind the
//!   [`PageFetcher`] trait so the orchestration (`sweep_site`) is unit-tested
//!   with fakes, per this packet's brief; [`ReqwestFetcher`] is the real
//!   `reqwest`-backed implementation.

use std::collections::BTreeMap;

use super::super::w2_012::sweep::{extract_links, missing_required_pages, profiles_for};

/// A same-origin-page fetch result: response status, or `None` on a
/// network failure/timeout (mirrors JS `checkStatus`'s `0` sentinel, kept
/// as `Option` here since `0` isn't a valid HTTP status).
pub trait PageFetcher {
    /// Fetch `url`'s body as text (JS: `fetch(url)` + `res.text()`).
    /// `Err` carries a message equivalent to JS's caught `e.message`.
    fn fetch_text(&self, url: &str) -> Result<String, String>;

    /// Port of `checkStatus(url, timeoutMs)`: HEAD first, GET retry on any
    /// non-404 4xx/5xx, `None` on network failure/abort (JS status `0`).
    fn check_status(&self, url: &str) -> Option<u16>;
}

/// One sweep finding: antipattern id + detail message (the JS `finding()`
/// call's `snippet`; `file`/`line` mirror the JS args — `file` is always
/// the swept `url`, `line` is always the JS default `0`).
#[derive(Debug, Clone, PartialEq)]
pub struct SweepFinding {
    pub antipattern: &'static str,
    pub file: String,
    pub detail: String,
}

fn f(antipattern: &'static str, file: &str, detail: String) -> SweepFinding {
    SweepFinding {
        antipattern,
        file: file.to_string(),
        detail,
    }
}

/// Port of `sweepSite(url, options)`. `site_type` mirrors
/// `options.siteType`; request fan-out is sequential rather than
/// `Promise.all`-concurrent (the trait boundary makes both equally
/// deterministic to a fake — order matches the JS `results` array either
/// way since `Promise.all` preserves input order).
pub fn sweep_site(
    fetcher: &dyn PageFetcher,
    url: &str,
    site_type: Option<&str>,
) -> Vec<SweepFinding> {
    let mut findings = Vec::new();

    let html = match fetcher.fetch_text(url) {
        Ok(h) => h,
        Err(e) => {
            findings.push(f(
                "broken-internal-link",
                url,
                format!("Sweep could not fetch the page itself: {e}"),
            ));
            return findings;
        }
    };

    let base_origin = match url_origin(url) {
        Some(o) => o,
        None => return findings,
    };

    let links = extract_links(&html, url);
    let internal: Vec<_> = links
        .into_iter()
        .filter(|l| url_origin(&l.resolved).as_deref() == Some(base_origin.as_str()))
        .collect();

    if internal.is_empty() {
        findings.push(f(
            "missing-required-page",
            url,
            "No same-origin links found in the static HTML — either the page has no internal navigation (a finding in itself) or the nav is rendered client-side and this sweep cannot see it. Verify manually.".to_string(),
        ));
        return findings;
    }

    // Dedupe by resolved URL with fragment stripped, cap at 80, preserving
    // first-seen order (mirrors `[...new Map(...).values()]`).
    let mut seen = BTreeMap::new();
    let mut order = Vec::new();
    for l in &internal {
        let key = strip_fragment(&l.resolved);
        if !seen.contains_key(&key) {
            order.push(key.clone());
        }
        // JS `new Map([...].map(...))` keeps insertion position from the
        // first occurrence but the value from the LAST occurrence.
        seen.insert(key, l.clone());
    }
    let unique: Vec<_> = order
        .into_iter()
        .take(80)
        .map(|k| seen.remove(&k).unwrap())
        .collect();

    for l in &unique {
        // Fragments are never sent over the wire, so the status check
        // (JS `fetch`) is keyed on the fragment-stripped URL.
        let status = fetcher.check_status(&strip_fragment(&l.resolved));
        let bad = match status {
            None => true,
            Some(s) => s >= 400,
        };
        if bad {
            let label = if l.text.is_empty() {
                l.href.as_str()
            } else {
                l.text.as_str()
            };
            let path = url_path(&l.resolved);
            let status_str = status
                .map(|s| s.to_string())
                .unwrap_or_else(|| "network error".to_string());
            findings.push(f(
                "broken-internal-link",
                url,
                format!("\"{label}\" \u{2192} {path} responds {status_str}"),
            ));
        }
    }

    let profiles = profiles_for(site_type);
    for (profile, page) in missing_required_pages(&profiles, &internal) {
        let suffix = if profile == "universal" {
            String::new()
        } else {
            format!(" (required for site-type \"{}\")", site_type.unwrap_or(""))
        };
        findings.push(f(
            "missing-required-page",
            url,
            format!("No link to a {} page found on this page{suffix}", page.name),
        ));
    }

    findings
}

/// Minimal `scheme://host[:port]` extraction — enough to decide
/// same-origin, mirroring `new URL(x).origin`. Returns `None` for a
/// non-absolute or unparsable URL.
fn url_origin(u: &str) -> Option<String> {
    let idx = u.find("://")?;
    let after = &u[idx + 3..];
    let end = after.find(['/', '?', '#']).unwrap_or(after.len());
    Some(format!("{}://{}", &u[..idx], &after[..end]))
}

/// Minimal path extraction (`new URL(x).pathname`): everything after the
/// origin, up to `?`/`#`, defaulting to `/`.
fn url_path(u: &str) -> String {
    let Some(idx) = u.find("://") else {
        return u.to_string();
    };
    let after = &u[idx + 3..];
    let path_start = after.find('/');
    match path_start {
        None => "/".to_string(),
        Some(p) => {
            let rest = &after[p..];
            let end = rest.find(['?', '#']).unwrap_or(rest.len());
            rest[..end].to_string()
        }
    }
}

fn strip_fragment(u: &str) -> String {
    match u.find('#') {
        Some(i) => u[..i].to_string(),
        None => u.to_string(),
    }
}

// ---------------------------------------------------------------------------
// reqwest-backed PageFetcher
// ---------------------------------------------------------------------------

/// Real `PageFetcher`: blocking `reqwest` client, HEAD-then-GET-retry
/// status checks, 15s timeout (matching `checkStatus`'s `timeoutMs = 15000`
/// default).
pub struct ReqwestFetcher {
    client: reqwest::blocking::Client,
}

impl ReqwestFetcher {
    pub fn new() -> Self {
        Self {
            client: reqwest::blocking::Client::builder()
                .timeout(std::time::Duration::from_millis(15_000))
                .build()
                .expect("reqwest client"),
        }
    }
}

impl Default for ReqwestFetcher {
    fn default() -> Self {
        Self::new()
    }
}

impl PageFetcher for ReqwestFetcher {
    fn fetch_text(&self, url: &str) -> Result<String, String> {
        let resp = self.client.get(url).send().map_err(|e| e.to_string())?;
        resp.text().map_err(|e| e.to_string())
    }

    fn check_status(&self, url: &str) -> Option<u16> {
        let head = self.client.head(url).send();
        match head {
            Ok(res) => {
                let status = res.status().as_u16();
                if status >= 400 && status != 404 {
                    match self.client.get(url).send() {
                        Ok(res2) => Some(res2.status().as_u16()),
                        Err(_) => None,
                    }
                } else {
                    Some(status)
                }
            }
            Err(_) => None,
        }
    }
}
