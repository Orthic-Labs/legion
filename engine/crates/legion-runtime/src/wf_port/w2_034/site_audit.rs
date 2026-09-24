//! Rust port of `skills/seo/scripts/site_audit.py`: a deterministic owned-site SEO
//! crawler.
//!
//! `site_audit.py` is a live HTTP crawler: it fetches robots.txt, sitemaps, and pages
//! over the network, then reduces the crawl into a mechanical issues/severity report.
//! Every pure string/data transform is ported and independently testable: URL
//! normalization, HTML signal extraction (`parse()`), sitemap-URL discovery from
//! `robots.txt` text (`discover_sitemaps()`), the asset-URL filter (`ASSET_RE`), and the
//! issue/severity reduction that `audit()` runs once the crawl data is in hand
//! ([`build_report`]). The network IO (`get`, `status_only`, the `audit()` crawl loop's
//! fetch-and-enqueue step) is ported too, behind the [`Fetcher`] trait — [`ReqwestFetcher`]
//! is the real `reqwest::blocking` implementation, tests use a fake — so [`audit`]
//! reproduces the full crawl driver, and [`run`] ports the `main()` CLI.

use regex::Regex;
use serde::Serialize;
use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::sync::OnceLock;

fn asset_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?i)\.(css|js|mjs|svg|png|jpe?g|webp|gif|woff2?|ttf|ico|xml|txt|json|pdf|zip|mp4|webm|avif)(\?|$)")
            .expect("static asset regex")
    })
}

/// Port of `ASSET_RE.search(url)` used to skip non-page link targets.
pub fn is_asset_url(url: &str) -> bool {
    asset_re().is_match(url)
}

/// Port of `normalize(url)`: drops the fragment and appends a trailing `/` to a bare
/// path or an extensionless, query-less path.
pub fn normalize(url: &str) -> String {
    let without_frag = url.split_once('#').map(|(base, _)| base).unwrap_or(url);
    let (before_query, query) = match without_frag.split_once('?') {
        Some((b, q)) => (b, Some(q)),
        None => (without_frag, None),
    };

    // Recover the path component the way Python's `urllib.parse.urlsplit` would give it:
    // strip `scheme://netloc` if present, leaving the path.
    let path = if let Some(idx) = before_query.find("://") {
        let rest = &before_query[idx + 3..];
        match rest.find('/') {
            Some(slash) => &rest[slash..],
            None => "",
        }
    } else {
        before_query
    };

    if path.is_empty() {
        return format!("{before_query}/");
    }
    let last_segment = path.rsplit('/').next().unwrap_or("");
    let has_dot = last_segment.contains('.');
    let ends_with_slash = before_query.ends_with('/');
    if !has_dot && !ends_with_slash && query.is_none() {
        format!("{before_query}/")
    } else {
        without_frag.to_string()
    }
}

/// The mechanical signals `parse(html)` extracts from a fetched HTML page.
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct PageSignals {
    pub title: String,
    pub meta_desc: String,
    pub h1: Vec<String>,
    pub canonical: Option<String>,
    pub words: usize,
    pub imgs: usize,
    pub img_no_alt: usize,
    pub viewport: bool,
    pub noindex: bool,
    pub mixed_content: bool,
}

fn strip_tags(s: &str) -> String {
    static TAG: OnceLock<Regex> = OnceLock::new();
    let re = TAG.get_or_init(|| Regex::new(r"<[^>]+>").expect("static tag regex"));
    re.replace_all(s, " ").to_string()
}

fn collapse_ws(s: &str) -> String {
    static WS: OnceLock<Regex> = OnceLock::new();
    let re = WS.get_or_init(|| Regex::new(r"\s+").expect("static ws regex"));
    re.replace_all(s, " ").trim().to_string()
}

/// Finds the `content="..."` value of the first `<meta ...>` tag whose `name` attribute
/// equals `name`, order-independent within the tag. Ported semantics of the Python
/// lookahead `<meta(?=[^>]*\bname=["']description["'])[^>]*\bcontent=["'](.*?)["']`; the
/// `regex` crate has no lookahead support, so this scans whole `<meta ...>` tags first
/// and then inspects each one's attributes instead.
fn find_meta_content(html: &str, name: &str) -> Option<String> {
    static META_TAG: OnceLock<Regex> = OnceLock::new();
    let meta_tag_re = META_TAG.get_or_init(|| Regex::new(r"(?is)<meta\b[^>]*>").unwrap());
    let name_re = Regex::new(&format!(r#"(?is)\bname\s*=\s*["']{}["']"#, regex::escape(name))).unwrap();
    let content_re = Regex::new(r#"(?is)\bcontent\s*=\s*["'](.*?)["']"#).unwrap();
    for m in meta_tag_re.find_iter(html) {
        let tag = m.as_str();
        if name_re.is_match(tag) {
            if let Some(c) = content_re.captures(tag) {
                return Some(c[1].trim().to_string());
            }
        }
    }
    None
}

/// Finds the `href="..."` value of the first `<link ...>` tag whose `rel` attribute
/// contains `canonical`. Ported semantics of the Python lookahead
/// `<link(?=[^>]*\brel=["'][^"']*canonical[^"']*["'])[^>]*\bhref=["']([^"']+)`; see
/// [`find_meta_content`] for why this scans whole tags instead of using lookahead.
fn find_canonical_href(html: &str) -> Option<String> {
    static LINK_TAG: OnceLock<Regex> = OnceLock::new();
    static REL_CANONICAL: OnceLock<Regex> = OnceLock::new();
    static HREF: OnceLock<Regex> = OnceLock::new();
    let link_tag_re = LINK_TAG.get_or_init(|| Regex::new(r"(?is)<link\b[^>]*>").unwrap());
    let rel_canonical_re =
        REL_CANONICAL.get_or_init(|| Regex::new(r#"(?is)\brel\s*=\s*["'][^"']*canonical[^"']*["']"#).unwrap());
    let href_re = HREF.get_or_init(|| Regex::new(r#"(?is)\bhref\s*=\s*["']([^"']+)"#).unwrap());
    for m in link_tag_re.find_iter(html) {
        let tag = m.as_str();
        if rel_canonical_re.is_match(tag) {
            if let Some(c) = href_re.captures(tag) {
                return Some(c[1].trim().to_string());
            }
        }
    }
    None
}

/// Port of `parse(html)`. Returns the signals plus the raw `<img ...>` tags (matching
/// the Python function's `(sig, imgs)` return, where callers only need `imgs` for its
/// length / alt-attribute scan, both already folded into `PageSignals`).
pub fn parse(html: &str) -> PageSignals {
    static TITLE: OnceLock<Regex> = OnceLock::new();
    static H1: OnceLock<Regex> = OnceLock::new();
    static SCRIPT_STYLE_COMMENT: OnceLock<Regex> = OnceLock::new();
    static IMG: OnceLock<Regex> = OnceLock::new();
    static IMG_ALT: OnceLock<Regex> = OnceLock::new();
    static VIEWPORT: OnceLock<Regex> = OnceLock::new();
    static ROBOTS_NOINDEX: OnceLock<Regex> = OnceLock::new();
    static MIXED_CONTENT: OnceLock<Regex> = OnceLock::new();

    let title_re = TITLE.get_or_init(|| Regex::new(r"(?is)<title[^>]*>(.*?)</title>").unwrap());
    let h1_re = H1.get_or_init(|| Regex::new(r"(?is)<h1\b[^>]*>(.*?)</h1>").unwrap());
    let script_style_comment_re = SCRIPT_STYLE_COMMENT.get_or_init(|| {
        Regex::new(r"(?is)<script\b.*?</script>|<style\b.*?</style>|<!--.*?-->").unwrap()
    });
    let img_re = IMG.get_or_init(|| Regex::new(r"(?is)<img\b[^>]*>").unwrap());
    let img_alt_re = IMG_ALT.get_or_init(|| Regex::new(r#"(?is)\balt\s*=\s*["'][^"']*["']"#).unwrap());
    let viewport_re =
        VIEWPORT.get_or_init(|| Regex::new(r#"(?is)<meta[^>]+name\s*=\s*["']viewport["']"#).unwrap());
    let robots_noindex_re = ROBOTS_NOINDEX.get_or_init(|| {
        Regex::new(r#"(?is)<meta[^>]+name\s*=\s*["']robots["'][^>]+content\s*=\s*["'][^"']*noindex"#).unwrap()
    });
    let mixed_content_re =
        MIXED_CONTENT.get_or_init(|| Regex::new(r#"(?is)\b(?:src|href)\s*=\s*["']http://"#).unwrap());

    let title = title_re
        .captures(html)
        .map(|c| collapse_ws(&strip_tags(&c[1])))
        .unwrap_or_default();
    let meta_desc = find_meta_content(html, "description").unwrap_or_default();
    let h1: Vec<String> = h1_re.captures_iter(html).map(|c| c[1].to_string()).collect();
    let canonical = find_canonical_href(html);

    let body = script_style_comment_re.replace_all(html, " ");
    let words = collapse_ws(&strip_tags(&body)).split(' ').filter(|w| !w.is_empty()).count();

    let img_tags: Vec<&str> = img_re.find_iter(html).map(|m| m.as_str()).collect();
    let imgs = img_tags.len();
    let img_no_alt = img_tags.iter().filter(|t| !img_alt_re.is_match(t)).count();

    PageSignals {
        title,
        meta_desc,
        h1,
        canonical,
        words,
        imgs,
        img_no_alt,
        viewport: viewport_re.is_match(html),
        noindex: robots_noindex_re.is_match(html),
        mixed_content: mixed_content_re.is_match(html),
    }
}

/// Port of `discover_sitemaps(origin, robots_text)`. `robots_text` mirrors the Python
/// `robots_text or ''` fallback for a `None`/failed fetch.
pub fn discover_sitemaps(origin: &str, robots_text: Option<&str>) -> Vec<String> {
    static SITEMAP_LINE: OnceLock<Regex> = OnceLock::new();
    let re = SITEMAP_LINE
        .get_or_init(|| Regex::new(r"(?im)^\s*Sitemap\s*:\s*(\S+)\s*$").unwrap());
    let text = robots_text.unwrap_or("");
    let mut found: Vec<String> = re.captures_iter(text).map(|c| c[1].trim().to_string()).collect();
    if found.is_empty() {
        found = vec![format!("{origin}/sitemap.xml")];
    }
    // `dict.fromkeys` dedupes while preserving first-seen order.
    let mut seen = HashSet::new();
    found.retain(|u| seen.insert(u.clone()));
    found
}

/// Extracts `<loc>` URLs from already-fetched sitemap XML bodies, matching the
/// `sitemap_urls()` regex scan and recursive `<sitemapindex>` handling. The recursive
/// HTTP fetch itself is host IO: this function takes the already-fetched
/// `url -> (status, xml_body)` map for every sitemap URL discovered so far (the caller
/// resolves nested `<sitemapindex>` entries by fetching and adding them to the map, up
/// to the Python `[:50]` cap per level) and returns the normalized page URL set.
pub fn extract_sitemap_locs(xml: &str) -> Vec<String> {
    static LOC: OnceLock<Regex> = OnceLock::new();
    let re = LOC.get_or_init(|| Regex::new(r"(?i)<loc>\s*([^<\s]+)").unwrap());
    re.captures_iter(xml).map(|c| c[1].trim().to_string()).collect()
}

/// Port of the `'<sitemapindex' in xml.lower()` check.
pub fn is_sitemap_index(xml: &str) -> bool {
    xml.to_lowercase().contains("<sitemapindex")
}

/// One already-fetched page, matching the fields `audit()` reads off `pages[url]` /
/// `sig` before running the issue checks (`status`, `x_robots_tag`, and — for a
/// successfully fetched HTML page — the `PageSignals`).
#[derive(Debug, Clone)]
pub struct FetchedPage {
    pub status: i32,
    pub x_robots_tag: Option<String>,
    pub signals: Option<PageSignals>,
}

/// Port of the issue/severity half of `audit()`: given the already-crawled pages, the
/// sitemap URL set, the site host, per-normalized-URL inlink counts, and the broken /
/// redirect link classifications the host already computed from `checked`/`status_only`,
/// produces the same `issues` and `severity` structure as the Python `audit()` return
/// value (`pages`/`sitemap_urls`/`robots_sitemaps`/`broken_links_all` are the caller's
/// own crawl-state and are not reconstructed here).
pub struct BrokenLink {
    pub status: i32,
    pub inlinks: usize,
}

pub struct RedirectLink {
    pub status: i32,
    pub to: Option<String>,
    pub inlinks: usize,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct Severity {
    pub errors: Vec<&'static str>,
    pub warnings: Vec<&'static str>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct IssuesReport {
    pub issues: BTreeMap<&'static str, Vec<String>>,
    pub severity: Severity,
}

const ERROR_KEYS: &[&str] = &[
    "broken_internal_links",
    "redirect_in_sitemap",
    "4xx_in_sitemap",
    "missing_title",
    "multiple_h1",
    "noindex_in_sitemap",
];
const WARNING_KEYS: &[&str] = &[
    "duplicate_title",
    "duplicate_meta_desc",
    "missing_h1",
    "missing_canonical",
    "canonical_points_elsewhere",
    "missing_meta_desc",
    "orphan_in_sitemap",
    "mixed_content",
    "thin_content",
    "img_missing_alt",
    "missing_viewport",
];

/// Port of the `ok`/`issues` reduction loop plus the sitemap-status and
/// `broken_internal_links` steps at the end of `audit()`.
#[allow(clippy::too_many_arguments)]
pub fn build_report(
    pages: &HashMap<String, FetchedPage>,
    sitemap: &HashSet<String>,
    host: &str,
    inlinks: &HashMap<String, usize>,
    broken: &HashMap<String, BrokenLink>,
    redirects: &HashMap<String, RedirectLink>,
    // Host part of each broken/redirect target URL, matching
    // `urllib.parse.urlsplit(u).netloc`; the caller supplies this since URL parsing to
    // this depth is otherwise duplicated wholesale.
    target_host: impl Fn(&str) -> String,
) -> IssuesReport {
    let mut issues: BTreeMap<&'static str, Vec<String>> = BTreeMap::new();
    let mut push = |issues: &mut BTreeMap<&'static str, Vec<String>>, key: &'static str, v: String| {
        issues.entry(key).or_default().push(v);
    };

    // `ok = {u: s for u, s in pages.items() if s.get('status') == 200 and 'title' in s}`
    let ok: Vec<(&String, &PageSignals)> = pages
        .iter()
        .filter(|(_, p)| p.status == 200)
        .filter_map(|(u, p)| p.signals.as_ref().map(|s| (u, s)))
        .collect();

    let mut titles: HashMap<&str, usize> = HashMap::new();
    let mut metas: HashMap<&str, usize> = HashMap::new();
    for (_, sig) in &ok {
        if !sig.title.is_empty() {
            *titles.entry(sig.title.as_str()).or_insert(0) += 1;
        }
        if !sig.meta_desc.is_empty() {
            *metas.entry(sig.meta_desc.as_str()).or_insert(0) += 1;
        }
    }

    // Iterate in a stable order (sorted by URL) for deterministic output.
    let mut ok_sorted = ok;
    ok_sorted.sort_by(|a, b| a.0.cmp(b.0));

    for (url, sig) in &ok_sorted {
        if sig.title.is_empty() {
            push(&mut issues, "missing_title", (*url).clone());
        } else {
            if titles.get(sig.title.as_str()).copied().unwrap_or(0) > 1 {
                push(&mut issues, "duplicate_title", (*url).clone());
            }
            let len = sig.title.chars().count();
            if len > 60 {
                push(&mut issues, "title_too_long", format!("{url} ({len})"));
            } else if len < 15 {
                push(&mut issues, "title_too_short", format!("{url} ({len})"));
            }
        }
        if sig.meta_desc.is_empty() {
            push(&mut issues, "missing_meta_desc", (*url).clone());
        } else {
            if metas.get(sig.meta_desc.as_str()).copied().unwrap_or(0) > 1 {
                push(&mut issues, "duplicate_meta_desc", (*url).clone());
            }
            let len = sig.meta_desc.chars().count();
            if len > 160 {
                push(&mut issues, "meta_desc_too_long", format!("{url} ({len})"));
            } else if len < 50 {
                push(&mut issues, "meta_desc_too_short", format!("{url} ({len})"));
            }
        }
        if sig.h1.is_empty() {
            push(&mut issues, "missing_h1", (*url).clone());
        } else if sig.h1.len() > 1 {
            push(&mut issues, "multiple_h1", format!("{url} ({})", sig.h1.len()));
        }
        match &sig.canonical {
            None => push(&mut issues, "missing_canonical", (*url).clone()),
            Some(canon) => {
                if normalize(canon) != normalize(url) && target_host(canon) == host {
                    push(&mut issues, "canonical_points_elsewhere", format!("{url} -> {canon}"));
                }
            }
        }
        let page = pages.get(*url);
        let x_robots_noindex = page
            .and_then(|p| p.x_robots_tag.as_deref())
            .map(|h| h.to_lowercase().contains("noindex"))
            .unwrap_or(false);
        let noindex = sig.noindex || x_robots_noindex;
        if sig.words < 200 && !noindex {
            push(&mut issues, "thin_content", format!("{url} ({}w)", sig.words));
        }
        if sig.img_no_alt > 0 {
            push(
                &mut issues,
                "img_missing_alt",
                format!("{url} ({}/{})", sig.img_no_alt, sig.imgs),
            );
        }
        if !sig.viewport {
            push(&mut issues, "missing_viewport", (*url).clone());
        }
        if url.starts_with("https://") && sig.mixed_content {
            push(&mut issues, "mixed_content", (*url).clone());
        }
        let norm_url = normalize(url);
        let inlink_count = inlinks.get(&norm_url).copied().unwrap_or(0);
        if sitemap.contains(&norm_url) && inlink_count == 0 {
            push(&mut issues, "orphan_in_sitemap", (*url).clone());
        }
        if noindex && sitemap.contains(&norm_url) {
            push(&mut issues, "noindex_in_sitemap", (*url).clone());
        }
    }

    let mut sitemap_sorted: Vec<&String> = sitemap.iter().collect();
    sitemap_sorted.sort();
    for loc in sitemap_sorted {
        let status = redirects.get(loc).map(|r| r.status).or_else(|| {
            pages.get(loc).map(|p| p.status)
        }).or_else(|| broken.get(loc).map(|b| b.status));
        if let Some(status) = status {
            if (300..400).contains(&status) {
                push(&mut issues, "redirect_in_sitemap", format!("{loc} ({status})"));
            } else if status >= 400 {
                push(&mut issues, "4xx_in_sitemap", format!("{loc} ({status})"));
            }
        }
    }

    let mut broken_internal: Vec<(&String, &BrokenLink)> = broken
        .iter()
        .filter(|(u, v)| target_host(u) == host && v.inlinks > 0)
        .collect();
    broken_internal.sort_by(|a, b| a.0.cmp(b.0));
    for (u, v) in broken_internal {
        push(
            &mut issues,
            "broken_internal_links",
            format!("[{}] {u} (from {} pages)", v.status, v.inlinks),
        );
    }

    let severity = Severity {
        errors: ERROR_KEYS.iter().copied().filter(|k| issues.contains_key(k)).collect(),
        warnings: WARNING_KEYS.iter().copied().filter(|k| issues.contains_key(k)).collect(),
    };

    IssuesReport { issues, severity }
}

/// Port of `UA = 'Mozilla/5.0 ...'`.
pub const USER_AGENT: &str =
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/121 Safari/537.36";

/// Splits `scheme://netloc/path...` into `(scheme, netloc, path_and_after)`, matching
/// `urllib.parse.urlsplit` closely enough for this module's needs (no query/fragment
/// separation here — callers that need those already split them beforehand).
fn urlsplit3(url: &str) -> (String, String, String) {
    match url.find("://") {
        Some(idx) => {
            let scheme = url[..idx].to_string();
            let rest = &url[idx + 3..];
            match rest.find('/') {
                Some(slash) => (scheme, rest[..slash].to_string(), rest[slash..].to_string()),
                None => (scheme, rest.to_string(), String::new()),
            }
        }
        None => (String::new(), String::new(), url.to_string()),
    }
}

/// Port of `urllib.parse.urlsplit(url).netloc`.
pub fn netloc_of(url: &str) -> String {
    urlsplit3(url).1
}

/// Port of `urllib.parse.urljoin(base, href)`, covering the cases `site_audit.py`
/// actually exercises: an absolute URL, a protocol-relative `//host/...` URL, an
/// absolute path, a query-only reference, and a relative path (including `.`/`..`
/// segments) resolved against the base URL's directory.
pub fn urljoin(base: &str, href: &str) -> String {
    if href.is_empty() {
        return base.to_string();
    }
    if href.contains("://") {
        return href.to_string();
    }
    let (base_scheme, base_netloc, base_path) = urlsplit3(base);
    if let Some(rest) = href.strip_prefix("//") {
        return format!("{base_scheme}://{rest}");
    }
    let origin = format!("{base_scheme}://{base_netloc}");
    if let Some(query) = href.strip_prefix('?') {
        let path = base_path.split(['?', '#']).next().unwrap_or("");
        return format!("{origin}{path}?{query}");
    }
    if href.starts_with('#') {
        return format!("{base}{href}").split('#').next().unwrap_or(base).to_string();
    }
    if let Some(stripped) = href.strip_prefix('/') {
        return format!("{origin}/{}", resolve_dot_segments(stripped));
    }
    // Relative path: resolve against the base path's directory.
    let base_dir = match base_path.rsplit_once('/') {
        Some((dir, _)) => dir,
        None => "",
    };
    let combined = format!("{base_dir}/{href}");
    let combined = combined.trim_start_matches('/');
    format!("{origin}/{}", resolve_dot_segments(combined))
}

fn resolve_dot_segments(path: &str) -> String {
    let mut out: Vec<&str> = Vec::new();
    for seg in path.split('/') {
        match seg {
            "." | "" => {}
            ".." => {
                out.pop();
            }
            other => out.push(other),
        }
    }
    out.join("/")
}

/// A single crawl fetch: mirrors the tuple Python's `get(url)` returns.
pub struct GetResponse {
    pub status: i32,
    pub final_url: String,
    pub body: String,
    /// Header names lowercased (HTTP headers are case-insensitive; Python's
    /// `http.client.HTTPMessage` is looked up case-insensitively via `.get()`).
    pub headers: HashMap<String, String>,
}

/// Behind-a-trait network IO, matching `get(url)` and `status_only(url)`. Real traffic
/// goes through [`ReqwestFetcher`]; tests supply a fake.
pub trait Fetcher {
    fn get(&self, url: &str) -> GetResponse;
    /// Mirrors `status_only(url)`: HEAD then GET, redirects NOT followed (matches the
    /// Python `NoRedirect` handler), returning `(status, location_header)`.
    fn status_only(&self, url: &str) -> (i32, Option<String>);
}

/// Real HTTP implementation of [`Fetcher`] using `reqwest::blocking`.
pub struct ReqwestFetcher {
    get_client: reqwest::blocking::Client,
    no_redirect_client: reqwest::blocking::Client,
}

impl ReqwestFetcher {
    pub fn new() -> Self {
        Self {
            get_client: reqwest::blocking::Client::builder()
                .timeout(std::time::Duration::from_secs(20))
                .user_agent(USER_AGENT)
                .build()
                .unwrap_or_else(|_| reqwest::blocking::Client::new()),
            no_redirect_client: reqwest::blocking::Client::builder()
                .timeout(std::time::Duration::from_secs(15))
                .user_agent(USER_AGENT)
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .unwrap_or_else(|_| reqwest::blocking::Client::new()),
        }
    }
}

impl Default for ReqwestFetcher {
    fn default() -> Self {
        Self::new()
    }
}

impl Fetcher for ReqwestFetcher {
    fn get(&self, url: &str) -> GetResponse {
        match self.get_client.get(url).send() {
            Ok(resp) => {
                let status = resp.status().as_u16() as i32;
                let final_url = resp.url().to_string();
                let mut headers = HashMap::new();
                for (name, value) in resp.headers() {
                    if let Ok(v) = value.to_str() {
                        headers.insert(name.as_str().to_lowercase(), v.to_string());
                    }
                }
                let body = resp.text().unwrap_or_default();
                GetResponse { status, final_url, body, headers }
            }
            Err(e) => GetResponse {
                status: 0,
                final_url: url.to_string(),
                body: e.to_string(),
                headers: HashMap::new(),
            },
        }
    }

    fn status_only(&self, url: &str) -> (i32, Option<String>) {
        for method in [reqwest::Method::HEAD, reqwest::Method::GET] {
            match self.no_redirect_client.request(method, url).send() {
                Ok(resp) => {
                    let status = resp.status().as_u16() as i32;
                    let location = resp
                        .headers()
                        .get(reqwest::header::LOCATION)
                        .and_then(|v| v.to_str().ok())
                        .map(str::to_string);
                    return (status, location);
                }
                Err(_) => continue,
            }
        }
        (0, None)
    }
}

fn href_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r#"(?is)<a\b[^>]*\bhref\s*=\s*["']([^"'#]+)"#).unwrap())
}

/// Port of `sitemap_urls(url, seen)`: recursively fetches a sitemap (or sitemap index,
/// capped at the Python `[:50]` nested entries per level) and returns the normalized page
/// URL set.
fn sitemap_urls(fetcher: &dyn Fetcher, url: &str, seen: &mut HashSet<String>) -> HashSet<String> {
    if seen.contains(url) {
        return HashSet::new();
    }
    seen.insert(url.to_string());
    let resp = fetcher.get(url);
    if resp.status != 200 {
        return HashSet::new();
    }
    let locs = extract_sitemap_locs(&resp.body);
    if is_sitemap_index(&resp.body) {
        let mut out = HashSet::new();
        for loc in locs.iter().take(50) {
            out.extend(sitemap_urls(fetcher, loc, seen));
        }
        out
    } else {
        locs.iter().map(|l| normalize(l)).collect()
    }
}

/// The full audit report, matching the JSON shape `audit()` returns / `--json` writes.
#[derive(Debug, Serialize)]
pub struct AuditReport {
    pub url: String,
    pub crawled: usize,
    pub sitemap_urls: usize,
    pub robots_sitemaps: Vec<String>,
    pub broken_links_all: BTreeMap<String, serde_json::Value>,
    pub redirects: BTreeMap<String, serde_json::Value>,
    pub pages: BTreeMap<String, serde_json::Value>,
    #[serde(flatten)]
    pub report: IssuesReport,
}

/// Port of `audit(start, maxpages)`: the full crawl driver. Fetches robots.txt and
/// sitemaps, BFS-crawls up to `maxpages` same-host URLs, checks every discovered link
/// target's status, and reduces the crawl into the issues/severity report via
/// [`build_report`].
pub fn audit(fetcher: &dyn Fetcher, start: &str, maxpages: usize) -> AuditReport {
    let start = start.trim_end_matches('/');
    let (scheme, netloc, _) = urlsplit3(start);
    let origin = format!("{scheme}://{netloc}");
    let host = netloc;

    let robots_resp = fetcher.get(&format!("{origin}/robots.txt"));
    let robots_text = if robots_resp.status == 200 { Some(robots_resp.body.as_str()) } else { None };
    let sitemap_roots = discover_sitemaps(&origin, robots_text);

    let mut sitemap: HashSet<String> = HashSet::new();
    let mut sitemap_seen: HashSet<String> = HashSet::new();
    for sm in &sitemap_roots {
        sitemap.extend(sitemap_urls(fetcher, sm, &mut sitemap_seen));
    }

    let mut queue: VecDeque<String> = VecDeque::new();
    queue.push_back(normalize(start));
    let mut sitemap_sorted: Vec<String> = sitemap.iter().cloned().collect();
    sitemap_sorted.sort();
    queue.extend(sitemap_sorted);

    let mut seen: HashSet<String> = HashSet::new();
    let mut pages: HashMap<String, FetchedPage> = HashMap::new();
    let mut pages_json: HashMap<String, serde_json::Value> = HashMap::new();
    let mut inlinks: HashMap<String, HashSet<String>> = HashMap::new();
    let mut link_targets: HashSet<String> = HashSet::new();

    while let Some(url) = queue.pop_front() {
        if pages.len() >= maxpages {
            break;
        }
        if seen.contains(&url) || netloc_of(&url) != host {
            continue;
        }
        seen.insert(url.clone());
        let resp = fetcher.get(&url);
        let x_robots_tag = resp.headers.get("x-robots-tag").cloned();
        let mut sig_json = serde_json::json!({
            "status": resp.status,
            "final": resp.final_url,
            "x_robots_tag": x_robots_tag,
        });
        let mut signals: Option<PageSignals> = None;
        if resp.status == 200 && resp.body.to_lowercase().contains("<html") {
            let mut parsed = parse(&resp.body);
            if let Some(canon) = &parsed.canonical {
                parsed.canonical = Some(urljoin(&resp.final_url, canon));
            }
            if let Some(obj) = sig_json.as_object_mut() {
                obj.insert("title".into(), serde_json::json!(parsed.title));
                obj.insert("meta_desc".into(), serde_json::json!(parsed.meta_desc));
                obj.insert("h1".into(), serde_json::json!(parsed.h1));
                obj.insert("canonical".into(), serde_json::json!(parsed.canonical));
                obj.insert("words".into(), serde_json::json!(parsed.words));
                obj.insert("imgs".into(), serde_json::json!(parsed.imgs));
                obj.insert("img_no_alt".into(), serde_json::json!(parsed.img_no_alt));
                obj.insert("viewport".into(), serde_json::json!(parsed.viewport));
                obj.insert("noindex".into(), serde_json::json!(parsed.noindex));
                obj.insert("mixed_content".into(), serde_json::json!(parsed.mixed_content));
            }

            for cap in href_re().captures_iter(&resp.body) {
                let href = cap[1].trim();
                if href.starts_with("mailto:")
                    || href.starts_with("tel:")
                    || href.starts_with("javascript:")
                    || href.starts_with("data:")
                {
                    continue;
                }
                let absolute = urljoin(&resp.final_url, href);
                let (a_scheme, a_netloc, a_path) = urlsplit3(&absolute);
                if (a_scheme != "http" && a_scheme != "https") || is_asset_url(&absolute) || a_path.contains("/cdn-cgi/") {
                    continue;
                }
                link_targets.insert(absolute.clone());
                if a_netloc == host {
                    let normalized = normalize(&absolute);
                    inlinks.entry(normalized.clone()).or_default().insert(url.clone());
                    if !seen.contains(&normalized) {
                        queue.push_back(normalized);
                    }
                }
            }
            signals = Some(parsed);
        }
        pages.insert(
            url.clone(),
            FetchedPage { status: resp.status, x_robots_tag, signals },
        );
        pages_json.insert(url.clone(), sig_json);
    }

    let mut broken: HashMap<String, BrokenLink> = HashMap::new();
    let mut redirects: HashMap<String, RedirectLink> = HashMap::new();
    for target in &link_targets {
        let base = normalize(target);
        let (status, location) = if netloc_of(target) == host {
            match pages.get(&base) {
                Some(p) => (p.status, None),
                None => fetcher.status_only(target),
            }
        } else {
            fetcher.status_only(target)
        };
        let inlink_count = inlinks.get(&normalize(target)).map(HashSet::len).unwrap_or(0);
        if status >= 400 || status == 0 {
            broken.insert(target.clone(), BrokenLink { status, inlinks: inlink_count });
        } else if matches!(status, 301 | 302 | 303 | 307 | 308) {
            redirects.insert(target.clone(), RedirectLink { status, to: location, inlinks: inlink_count });
        }
    }

    let inlink_counts: HashMap<String, usize> =
        inlinks.iter().map(|(k, v)| (k.clone(), v.len())).collect();
    let report = build_report(&pages, &sitemap, &host, &inlink_counts, &broken, &redirects, netloc_of);

    let robots_sitemaps = discover_sitemaps(&origin, robots_text);

    AuditReport {
        url: start.to_string(),
        crawled: pages.len(),
        sitemap_urls: sitemap.len(),
        robots_sitemaps,
        broken_links_all: broken
            .into_iter()
            .map(|(k, v)| (k, serde_json::json!({"status": v.status, "inlinks": v.inlinks})))
            .collect(),
        redirects: redirects
            .into_iter()
            .map(|(k, v)| (k, serde_json::json!({"status": v.status, "to": v.to, "inlinks": v.inlinks})))
            .collect(),
        pages: pages_json.into_iter().collect(),
        report,
    }
}

/// Port of the `main()` CLI: `--url`, `--max` (default 300), `--json FILE`, `--summary`.
/// `args` excludes the program name. Returns the same exit code as Python: `1` if any
/// error-severity issue was found, else `0`.
pub fn run(fetcher: &dyn Fetcher, args: &[String]) -> i32 {
    let mut url: Option<String> = None;
    let mut max: usize = 300;
    let mut json_path: Option<String> = None;
    let mut summary = false;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--url" if i + 1 < args.len() => {
                url = Some(args[i + 1].clone());
                i += 2;
            }
            "--max" if i + 1 < args.len() => {
                max = args[i + 1].parse().unwrap_or(300);
                i += 2;
            }
            "--json" if i + 1 < args.len() => {
                json_path = Some(args[i + 1].clone());
                i += 2;
            }
            "--summary" => {
                summary = true;
                i += 1;
            }
            _ => i += 1,
        }
    }
    let Some(url) = url else {
        eprintln!("error: --url is required");
        return 2;
    };
    let result = audit(fetcher, &url, max);

    if let Some(path) = &json_path {
        let body = serde_json::to_string_pretty(&result).unwrap_or_default();
        if let Err(e) = std::fs::write(path, body) {
            eprintln!("error writing {path}: {e}");
            return 1;
        }
    }
    if summary || json_path.is_none() {
        println!("{} — crawled {} pages, sitemap {} urls", result.url, result.crawled, result.sitemap_urls);
        for (band, keys) in [("ERRORS", &result.report.severity.errors), ("WARNINGS", &result.report.severity.warnings)] {
            if !keys.is_empty() {
                println!("  {band}:");
                for key in keys.iter() {
                    let values = result.report.issues.get(key).cloned().unwrap_or_default();
                    println!("    {key}: {}", values.len());
                    for value in values.iter().take(6) {
                        println!("        {value}");
                    }
                }
            }
        }
    }
    if result.report.severity.errors.is_empty() {
        0
    } else {
        1
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_appends_slash_to_bare_and_extensionless_paths() {
        assert_eq!(normalize("https://example.com"), "https://example.com/");
        assert_eq!(normalize("https://example.com/about"), "https://example.com/about/");
        assert_eq!(normalize("https://example.com/about/"), "https://example.com/about/");
        assert_eq!(normalize("https://example.com/img.png"), "https://example.com/img.png");
        assert_eq!(normalize("https://example.com/about?x=1"), "https://example.com/about?x=1");
        assert_eq!(normalize("https://example.com/about#frag"), "https://example.com/about/");
    }

    #[test]
    fn is_asset_url_matches_known_extensions() {
        assert!(is_asset_url("https://example.com/app.js"));
        assert!(is_asset_url("https://example.com/img.png?v=2"));
        assert!(!is_asset_url("https://example.com/about"));
    }

    #[test]
    fn parse_extracts_core_signals() {
        let html = r#"<html><head>
            <title>  Hello   World </title>
            <meta name="description" content="A great page.">
            <link rel="canonical" href="https://example.com/canon">
            <meta name="viewport" content="width=device-width">
        </head><body>
            <h1>Heading</h1>
            <img src="a.png">
            <img src="b.png" alt="b">
            <p>Some words here for content length checking purposes only really.</p>
            <a href="http://insecure.example.com">x</a>
        </body></html>"#;
        let sig = parse(html);
        assert_eq!(sig.title, "Hello World");
        assert_eq!(sig.meta_desc, "A great page.");
        assert_eq!(sig.h1, vec!["Heading".to_string()]);
        assert_eq!(sig.canonical.as_deref(), Some("https://example.com/canon"));
        assert!(sig.viewport);
        assert_eq!(sig.imgs, 2);
        assert_eq!(sig.img_no_alt, 1);
        assert!(sig.mixed_content);
        assert!(!sig.noindex);
    }

    #[test]
    fn parse_detects_noindex() {
        let html = r#"<meta name="robots" content="noindex, nofollow">"#;
        assert!(parse(html).noindex);
    }

    #[test]
    fn discover_sitemaps_reads_robots_or_falls_back() {
        let robots = "User-agent: *\nSitemap: https://example.com/sitemap-a.xml\nSitemap: https://example.com/sitemap-b.xml\n";
        assert_eq!(
            discover_sitemaps("https://example.com", Some(robots)),
            vec!["https://example.com/sitemap-a.xml", "https://example.com/sitemap-b.xml"]
        );
        assert_eq!(
            discover_sitemaps("https://example.com", None),
            vec!["https://example.com/sitemap.xml"]
        );
        assert_eq!(
            discover_sitemaps("https://example.com", Some("")),
            vec!["https://example.com/sitemap.xml"]
        );
    }

    #[test]
    fn extract_sitemap_locs_and_index_detection() {
        let xml = "<urlset><url><loc>https://example.com/a</loc></url><url><loc>https://example.com/b</loc></url></urlset>";
        assert_eq!(
            extract_sitemap_locs(xml),
            vec!["https://example.com/a", "https://example.com/b"]
        );
        assert!(!is_sitemap_index(xml));
        assert!(is_sitemap_index("<sitemapindex><sitemap><loc>x</loc></sitemap></sitemapindex>"));
    }

    fn host_of(u: &str) -> String {
        u.split("://").nth(1).and_then(|r| r.split('/').next()).unwrap_or("").to_string()
    }

    #[test]
    fn build_report_flags_missing_title_and_thin_content() {
        let mut pages = HashMap::new();
        pages.insert(
            "https://example.com/".to_string(),
            FetchedPage {
                status: 200,
                x_robots_tag: None,
                signals: Some(PageSignals {
                    title: String::new(),
                    meta_desc: "d".repeat(60),
                    h1: vec!["H".to_string()],
                    canonical: Some("https://example.com/".to_string()),
                    words: 10,
                    imgs: 0,
                    img_no_alt: 0,
                    viewport: true,
                    noindex: false,
                    mixed_content: false,
                }),
            },
        );
        let sitemap = HashSet::new();
        let inlinks = HashMap::new();
        let broken = HashMap::new();
        let redirects = HashMap::new();
        let report = build_report(&pages, &sitemap, "example.com", &inlinks, &broken, &redirects, host_of);
        assert!(report.issues["missing_title"].contains(&"https://example.com/".to_string()));
        assert!(report.issues["thin_content"][0].starts_with("https://example.com/ (10w)"));
        assert!(report.severity.errors.contains(&"missing_title"));
        assert!(report.severity.warnings.contains(&"thin_content"));
    }

    #[test]
    fn build_report_flags_broken_internal_links_and_orphans() {
        let mut pages = HashMap::new();
        pages.insert(
            "https://example.com/ok".to_string(),
            FetchedPage {
                status: 200,
                x_robots_tag: None,
                signals: Some(PageSignals {
                    title: "T".repeat(20),
                    meta_desc: "d".repeat(60),
                    h1: vec!["H".to_string()],
                    canonical: Some("https://example.com/ok".to_string()),
                    words: 500,
                    imgs: 0,
                    img_no_alt: 0,
                    viewport: true,
                    noindex: false,
                    mixed_content: false,
                }),
            },
        );
        let mut sitemap = HashSet::new();
        sitemap.insert("https://example.com/ok/".to_string());
        let inlinks = HashMap::new(); // zero inlinks -> orphan_in_sitemap
        let mut broken = HashMap::new();
        broken.insert(
            "https://example.com/dead".to_string(),
            BrokenLink { status: 404, inlinks: 3 },
        );
        let redirects = HashMap::new();
        let report = build_report(&pages, &sitemap, "example.com", &inlinks, &broken, &redirects, host_of);
        assert!(report.issues["orphan_in_sitemap"].contains(&"https://example.com/ok".to_string()));
        assert_eq!(
            report.issues["broken_internal_links"][0],
            "[404] https://example.com/dead (from 3 pages)"
        );
        assert!(report.severity.errors.contains(&"broken_internal_links"));
    }

    struct FakeFetcher {
        routes: HashMap<String, GetResponse>,
    }

    impl FakeFetcher {
        fn html(status: i32, url: &str, body: &str) -> GetResponse {
            GetResponse {
                status,
                final_url: url.to_string(),
                body: body.to_string(),
                headers: HashMap::new(),
            }
        }
        fn text(status: i32, url: &str, body: &str) -> GetResponse {
            Self::html(status, url, body)
        }
    }

    impl Fetcher for FakeFetcher {
        fn get(&self, url: &str) -> GetResponse {
            self.routes.get(url).map(|r| GetResponse {
                status: r.status,
                final_url: r.final_url.clone(),
                body: r.body.clone(),
                headers: r.headers.clone(),
            }).unwrap_or(GetResponse { status: 404, final_url: url.to_string(), body: String::new(), headers: HashMap::new() })
        }
        fn status_only(&self, url: &str) -> (i32, Option<String>) {
            self.routes.get(url).map(|r| (r.status, None)).unwrap_or((404, None))
        }
    }

    #[test]
    fn urljoin_resolves_relative_absolute_and_protocol_relative() {
        assert_eq!(urljoin("https://example.com/dir/page", "sub"), "https://example.com/dir/sub");
        assert_eq!(urljoin("https://example.com/dir/page", "/root"), "https://example.com/root");
        assert_eq!(urljoin("https://example.com/dir/page", "https://other.com/x"), "https://other.com/x");
        assert_eq!(urljoin("https://example.com/dir/page", "//cdn.example.com/x"), "https://cdn.example.com/x");
        assert_eq!(urljoin("https://example.com/a/b/", "../c"), "https://example.com/a/c");
    }

    #[test]
    fn audit_crawls_two_pages_and_detects_thin_content() {
        let mut routes = HashMap::new();
        routes.insert(
            "https://example.com/robots.txt".to_string(),
            FakeFetcher::text(404, "https://example.com/robots.txt", ""),
        );
        routes.insert(
            "https://example.com/sitemap.xml".to_string(),
            FakeFetcher::text(404, "https://example.com/sitemap.xml", ""),
        );
        routes.insert(
            "https://example.com/".to_string(),
            FakeFetcher::html(
                200,
                "https://example.com/",
                r#"<html><head><title>Home Page Title Here</title>
                <meta name="description" content="A reasonably long description for the home page.">
                <link rel="canonical" href="https://example.com/">
                <meta name="viewport" content="width=device-width"></head>
                <body><h1>Home</h1><a href="/about">About</a>
                <p>short</p></body></html>"#,
            ),
        );
        routes.insert(
            "https://example.com/about/".to_string(),
            FakeFetcher::html(
                200,
                "https://example.com/about/",
                r#"<html><head><title>About Us Page Title</title>
                <meta name="description" content="A reasonably long description for the about page too.">
                <link rel="canonical" href="https://example.com/about/">
                <meta name="viewport" content="width=device-width"></head>
                <body><h1>About</h1><p>Plenty of words here to avoid the thin content warning for this page, really.</p></body></html>"#,
            ),
        );
        let fetcher = FakeFetcher { routes };
        let report = audit(&fetcher, "https://example.com", 10);
        assert_eq!(report.crawled, 2);
        assert!(report.pages.contains_key("https://example.com/"));
        assert!(report.pages.contains_key("https://example.com/about/"));
        assert!(report
            .report
            .issues
            .get("thin_content")
            .map(|v| v.iter().any(|s| s.starts_with("https://example.com/ ")))
            .unwrap_or(false));
    }

    #[test]
    fn run_returns_2_without_url_and_1_when_errors_found() {
        let fetcher = FakeFetcher { routes: HashMap::new() };
        assert_eq!(run(&fetcher, &[]), 2);

        let mut routes = HashMap::new();
        routes.insert(
            "https://example.com/robots.txt".to_string(),
            FakeFetcher::text(404, "https://example.com/robots.txt", ""),
        );
        routes.insert(
            "https://example.com/sitemap.xml".to_string(),
            FakeFetcher::text(404, "https://example.com/sitemap.xml", ""),
        );
        routes.insert(
            "https://example.com/".to_string(),
            FakeFetcher::html(200, "https://example.com/", "<html><body>no title here</body></html>"),
        );
        let fetcher = FakeFetcher { routes };
        let args: Vec<String> = ["--url", "https://example.com", "--summary"].iter().map(|s| s.to_string()).collect();
        assert_eq!(run(&fetcher, &args), 1);
    }
}
