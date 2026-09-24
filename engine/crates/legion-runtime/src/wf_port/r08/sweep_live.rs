//! wf_port packet r08 (area `skills/designer/engine/scripts/detector/engines/
//! site/sweep.mjs`, target crate `legion-runtime`).
//!
//! Completes the gap `wf_port::w2_012::sweep`'s module doc left open:
//! `checkStatus`'s HEAD/GET-retry status check and `sweepSite`'s page fetch
//! + link fan-out + finding assembly. Network I/O sits behind the
//! [`PageFetcher`] trait so the orchestration (`sweep_site`) is unit-tested
//! with fakes, per this packet's brief; [`ReqwestFetcher`] is the real
//! `reqwest`-backed implementation.

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
    SweepFinding { antipattern, file: file.to_string(), detail }
}

/// Port of `sweepSite(url, options)`. `site_type` mirrors
/// `options.siteType`; request fan-out is sequential rather than
/// `Promise.all`-concurrent (the trait boundary makes both equally
/// deterministic to a fake — order matches the JS `results` array either
/// way since `Promise.all` preserves input order).
pub fn sweep_site(fetcher: &dyn PageFetcher, url: &str, site_type: Option<&str>) -> Vec<SweepFinding> {
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
    let unique: Vec<_> = order.into_iter().take(80).map(|k| seen.remove(&k).unwrap()).collect();

    for l in &unique {
        // Fragments are never sent over the wire, so the status check
        // (JS `fetch`) is keyed on the fragment-stripped URL.
        let status = fetcher.check_status(&strip_fragment(&l.resolved));
        let bad = match status {
            None => true,
            Some(s) => s >= 400,
        };
        if bad {
            let label = if l.text.is_empty() { l.href.as_str() } else { l.text.as_str() };
            let path = url_path(&l.resolved);
            let status_str = status.map(|s| s.to_string()).unwrap_or_else(|| "network error".to_string());
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
    let Some(idx) = u.find("://") else { return u.to_string() };
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    struct FakeFetcher {
        pages: HashMap<String, String>,
        statuses: HashMap<String, Option<u16>>,
    }

    impl PageFetcher for FakeFetcher {
        fn fetch_text(&self, url: &str) -> Result<String, String> {
            self.pages.get(url).cloned().ok_or_else(|| "not found".to_string())
        }
        fn check_status(&self, url: &str) -> Option<u16> {
            *self.statuses.get(url).unwrap_or(&Some(200))
        }
    }

    #[test]
    fn fetch_failure_yields_single_broken_link_finding() {
        let fetcher = FakeFetcher { pages: HashMap::new(), statuses: HashMap::new() };
        let findings = sweep_site(&fetcher, "https://example.com/", None);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].antipattern, "broken-internal-link");
        assert!(findings[0].detail.contains("could not fetch"));
    }

    #[test]
    fn no_internal_links_yields_missing_required_page_finding() {
        let mut pages = HashMap::new();
        pages.insert("https://example.com/".to_string(), "<html><a href=\"https://other.com/\">x</a></html>".to_string());
        let fetcher = FakeFetcher { pages, statuses: HashMap::new() };
        let findings = sweep_site(&fetcher, "https://example.com/", None);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].antipattern, "missing-required-page");
        assert!(findings[0].detail.contains("Verify manually"));
    }

    #[test]
    fn broken_internal_link_is_reported_with_path_and_status() {
        let mut pages = HashMap::new();
        pages.insert(
            "https://example.com/".to_string(),
            "<html><a href=\"/privacy\">Privacy</a><a href=\"/terms\">Terms</a><a href=\"/dead\">Dead link</a></html>".to_string(),
        );
        let mut statuses = HashMap::new();
        statuses.insert("https://example.com/dead".to_string(), Some(404));
        let fetcher = FakeFetcher { pages, statuses };
        let findings = sweep_site(&fetcher, "https://example.com/", None);
        let broken: Vec<_> = findings.iter().filter(|f| f.antipattern == "broken-internal-link").collect();
        assert_eq!(broken.len(), 1);
        assert!(broken[0].detail.contains("\"Dead link\""));
        assert!(broken[0].detail.contains("/dead"));
        assert!(broken[0].detail.contains("404"));
    }

    #[test]
    fn network_error_status_reports_network_error_text() {
        let mut pages = HashMap::new();
        pages.insert(
            "https://example.com/".to_string(),
            "<html><a href=\"/privacy\">Privacy</a><a href=\"/terms\">Terms</a><a href=\"/flaky\">Flaky</a></html>".to_string(),
        );
        let mut statuses = HashMap::new();
        statuses.insert("https://example.com/flaky".to_string(), None);
        let fetcher = FakeFetcher { pages, statuses };
        let findings = sweep_site(&fetcher, "https://example.com/", None);
        let broken = findings.iter().find(|f| f.detail.contains("/flaky")).unwrap();
        assert!(broken.detail.contains("network error"));
    }

    #[test]
    fn missing_universal_pages_are_flagged() {
        let mut pages = HashMap::new();
        pages.insert(
            "https://example.com/".to_string(),
            "<html><a href=\"/about\">About</a></html>".to_string(),
        );
        let fetcher = FakeFetcher { pages, statuses: HashMap::new() };
        let findings = sweep_site(&fetcher, "https://example.com/", None);
        let missing: Vec<_> = findings.iter().filter(|f| f.antipattern == "missing-required-page").collect();
        assert_eq!(missing.len(), 2); // privacy + terms
    }

    #[test]
    fn site_type_profile_adds_its_required_pages() {
        let mut pages = HashMap::new();
        pages.insert(
            "https://example.com/".to_string(),
            "<html><a href=\"/privacy\">Privacy</a><a href=\"/terms\">Terms</a></html>".to_string(),
        );
        let fetcher = FakeFetcher { pages, statuses: HashMap::new() };
        let findings = sweep_site(&fetcher, "https://example.com/", Some("app"));
        let missing: Vec<_> = findings
            .iter()
            .filter(|f| f.antipattern == "missing-required-page" && f.detail.contains("site-type \"app\""))
            .collect();
        assert_eq!(missing.len(), 2); // pricing + download
    }

    #[test]
    fn found_required_page_by_href_is_not_flagged() {
        let mut pages = HashMap::new();
        pages.insert(
            "https://example.com/".to_string(),
            "<html><a href=\"/privacy-policy\">Legal</a><a href=\"/terms-of-service\">Legal2</a></html>".to_string(),
        );
        let fetcher = FakeFetcher { pages, statuses: HashMap::new() };
        let findings = sweep_site(&fetcher, "https://example.com/", None);
        assert!(findings.iter().all(|f| f.antipattern != "missing-required-page"));
    }

    #[test]
    fn dedupes_by_url_ignoring_fragment_and_caps_at_80() {
        let mut html = String::from("<html>");
        html.push_str("<a href=\"/privacy\">P</a><a href=\"/terms\">T</a>");
        html.push_str("<a href=\"/x#a\">X</a><a href=\"/x#b\">X2</a>");
        for i in 0..90 {
            html.push_str(&format!("<a href=\"/page{i}\">L{i}</a>"));
        }
        html.push_str("</html>");
        let mut pages = HashMap::new();
        pages.insert("https://example.com/".to_string(), html);
        let mut statuses = HashMap::new();
        statuses.insert("https://example.com/x".to_string(), Some(500));
        let fetcher = FakeFetcher { pages, statuses };
        let findings = sweep_site(&fetcher, "https://example.com/", None);
        // "/x" is deduped to one broken-link finding despite two anchors.
        let x_findings: Vec<_> = findings.iter().filter(|f| f.detail.contains("/x")).collect();
        assert_eq!(x_findings.len(), 1);
    }
}
