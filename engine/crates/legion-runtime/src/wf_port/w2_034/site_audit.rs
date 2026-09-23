//! Rust port of the pure, deterministic core of `skills/seo/scripts/site_audit.py`.
//!
//! `site_audit.py` is a live HTTP crawler: it fetches robots.txt, sitemaps, and pages
//! over the network, then reduces the crawl into a mechanical issues/severity report.
//! The network IO (`get`, `status_only`, the `audit()` crawl loop's `while queue`
//! fetch-and-enqueue step) is not ported — it belongs to a host HTTP client. What is
//! ported verbatim, and is independently testable, is every pure string/data
//! transform: URL normalization, HTML signal extraction (`parse()`), sitemap-URL
//! discovery from `robots.txt` text (`discover_sitemaps()`), the asset-URL filter
//! (`ASSET_RE`), and the issue/severity reduction that `audit()` runs once the crawl
//! data is in hand. A host wrapper performs the fetches and hands the resulting pages,
//! sitemap set, and link graph to [`build_report`].

use regex::Regex;
use serde::Serialize;
use std::collections::{BTreeMap, HashMap, HashSet};
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
    /// Host part of each broken/redirect target URL, matching
    /// `urllib.parse.urlsplit(u).netloc`; the caller supplies this since URL parsing to
    /// this depth is otherwise duplicated wholesale.
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
}
