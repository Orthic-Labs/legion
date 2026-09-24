//! Port of `skills/seo/scripts/parse_html.py` (packet `r42` closes the DOM-parsing
//! gap this module used to defer, using `scraper` — already a `legion-runtime`
//! dependency, see `w2_013::detect_html`).
//!
//! Everything in `parse_html.py`'s `parse_html()` is now ported: title, meta
//! description/robots, canonical, hreflang, h1-h3, images (with `src` resolved
//! against `base_url` when given), internal/external links, JSON-LD schema blocks,
//! Open Graph / Twitter Card meta, and the visible-text word count (script/style/
//! nav/footer/header stripped first, matching the Python's `element.decompose()`
//! loop). [`parse_html`] is the full port of the Python function of the same name;
//! [`run`] ports the CLI (`main()`): file/`--url`/stdin input, `--json` vs. the
//! human-readable summary, and the `os.path.realpath` + `os.path.isfile` file-not-found
//! check.
//!
//! The lower-level pure helpers below ([`word_count`], [`resolve_href`],
//! [`classify_link`], [`parse_json_ld`], [`extract_open_graph`],
//! [`extract_twitter_card`]) remain as the building blocks [`parse_html`] is built
//! from.

use std::collections::BTreeMap;
use std::io::Read as _;
use std::path::Path;

use regex::Regex;
use scraper::{Html, Selector};
use serde::Serialize;
use serde_json::Value;

/// Mirrors the word-count tail of `parse_html`: `re.findall(r"\b\w+\b", text)` over
/// the page's visible text (script/style/nav/footer/header already removed).
pub fn word_count(text: &str) -> usize {
    let re = Regex::new(r"\b\w+\b").unwrap();
    re.find_iter(text).count()
}

#[derive(Debug, Clone, PartialEq)]
pub enum LinkClass {
    Internal,
    External,
}

/// Minimal RFC-3986-ish URL join, sufficient for `urljoin(base_url, href)` on the
/// href shapes `parse_html.py` actually resolves (scheme-relative, absolute-path,
/// relative-path, and already-absolute hrefs). Query strings and fragments on `href`
/// are preserved; full dot-segment (`../`) resolution is not attempted.
pub fn resolve_href(base_url: &str, href: &str) -> String {
    if href.contains("://") {
        return href.to_string();
    }
    let (base_scheme, base_rest) = match base_url.find("://") {
        Some(idx) => (&base_url[..idx], &base_url[idx + 3..]),
        None => return href.to_string(),
    };
    let base_authority_end = base_rest.find(['/', '?', '#']).unwrap_or(base_rest.len());
    let base_authority = &base_rest[..base_authority_end];

    if let Some(rest) = href.strip_prefix("//") {
        return format!("{base_scheme}://{rest}");
    }
    if href.starts_with('/') {
        return format!("{base_scheme}://{base_authority}{href}");
    }
    // Relative path: join against the base's directory (everything up to the last '/'
    // in its path, or the authority root if the base has no path).
    let base_path = &base_rest[base_authority_end..];
    let base_dir = match base_path.rfind('/') {
        Some(idx) => &base_path[..=idx],
        None => "/",
    };
    format!("{base_scheme}://{base_authority}{base_dir}{href}")
}

fn hostname_of(url: &str) -> Option<String> {
    let idx = url.find("://")?;
    let rest = &url[idx + 3..];
    let authority_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let authority = &rest[..authority_end];
    let host_port = match authority.rfind('@') {
        Some(at) => &authority[at + 1..],
        None => authority,
    };
    Some(host_port.to_string())
}

/// Mirrors the link-classification loop in `parse_html`: resolves `href` against
/// `base_url`, skips `#`/`javascript:` hrefs, and classifies by netloc match. Returns
/// `None` for hrefs the Python loop also skips.
pub fn classify_link(base_url: &str, href: &str) -> Option<(String, LinkClass)> {
    if href.is_empty() || href.starts_with('#') || href.starts_with("javascript:") {
        return None;
    }
    let full_url = resolve_href(base_url, href);
    let base_netloc = hostname_of(base_url).unwrap_or_default();
    let link_netloc = hostname_of(&full_url).unwrap_or_default();
    let class = if link_netloc == base_netloc {
        LinkClass::Internal
    } else {
        LinkClass::External
    };
    Some((full_url, class))
}

/// Mirrors the JSON-LD extraction loop: parses each `<script type="application/ld+json">`
/// body, silently skipping ones that fail to parse (matching the Python's
/// `except (json.JSONDecodeError, TypeError): pass`).
pub fn parse_json_ld<'a, I: IntoIterator<Item = &'a str>>(script_bodies: I) -> Vec<Value> {
    script_bodies
        .into_iter()
        .filter_map(|body| serde_json::from_str::<Value>(body).ok())
        .collect()
}

/// Mirrors the Open Graph half of the meta-tag loop: keeps `property` values starting
/// with `og:` (case-insensitive), keyed by the lowercased property name.
pub fn extract_open_graph<'a, I>(meta_props: I) -> BTreeMap<String, String>
where
    I: IntoIterator<Item = (&'a str, &'a str)>,
{
    let mut out = BTreeMap::new();
    for (property, content) in meta_props {
        let p = property.to_lowercase();
        if p.starts_with("og:") {
            out.insert(p, content.to_string());
        }
    }
    out
}

/// Mirrors the Twitter Card half of the meta-tag loop: keeps `name` values starting
/// with `twitter:` (case-insensitive), keyed by the lowercased name.
pub fn extract_twitter_card<'a, I>(meta_names: I) -> BTreeMap<String, String>
where
    I: IntoIterator<Item = (&'a str, &'a str)>,
{
    let mut out = BTreeMap::new();
    for (name, content) in meta_names {
        let n = name.to_lowercase();
        if n.starts_with("twitter:") {
            out.insert(n, content.to_string());
        }
    }
    out
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ImageInfo {
    pub src: String,
    pub alt: Option<String>,
    pub width: Option<String>,
    pub height: Option<String>,
    pub loading: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct LinkInfo {
    pub href: String,
    pub text: String,
    pub rel: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Default)]
pub struct Links {
    pub internal: Vec<LinkInfo>,
    pub external: Vec<LinkInfo>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct HreflangEntry {
    pub lang: String,
    pub href: Option<String>,
}

/// Full port of `parse_html(html, base_url)`: the whole `result` dict.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ParseResult {
    pub title: Option<String>,
    pub meta_description: Option<String>,
    pub meta_robots: Option<String>,
    pub canonical: Option<String>,
    pub h1: Vec<String>,
    pub h2: Vec<String>,
    pub h3: Vec<String>,
    pub images: Vec<ImageInfo>,
    pub links: Links,
    pub schema: Vec<Value>,
    pub open_graph: BTreeMap<String, String>,
    pub twitter_card: BTreeMap<String, String>,
    pub word_count: usize,
    pub hreflang: Vec<HreflangEntry>,
}

fn text_of(el: scraper::ElementRef) -> String {
    el.text().collect::<Vec<_>>().join("").trim().to_string()
}

fn attr(el: &scraper::ElementRef, name: &str) -> Option<String> {
    el.value().attr(name).map(|s| s.to_string())
}

/// Full port of `parse_html(html, base_url)`.
pub fn parse_html(html: &str, base_url: Option<&str>) -> ParseResult {
    let doc = Html::parse_document(html);

    let sel = |s: &str| Selector::parse(s).unwrap();

    // `soup.find("title")` returns `None` only when there is no `<title>` tag at all;
    // an empty/whitespace-only title still yields `Some("")` via `get_text(strip=True)`.
    let title = doc.select(&sel("title")).next().map(text_of);

    let mut meta_description = None;
    let mut meta_robots = None;
    let mut open_graph = BTreeMap::new();
    let mut twitter_card = BTreeMap::new();
    for meta in doc.select(&sel("meta")) {
        let name = attr(&meta, "name").unwrap_or_default().to_lowercase();
        let property = attr(&meta, "property").unwrap_or_default().to_lowercase();
        let content = attr(&meta, "content").unwrap_or_default();
        if name == "description" {
            meta_description = Some(content.clone());
        } else if name == "robots" {
            meta_robots = Some(content.clone());
        }
        if property.starts_with("og:") {
            open_graph.insert(property.clone(), content.clone());
        }
        if name.starts_with("twitter:") {
            twitter_card.insert(name.clone(), content.clone());
        }
    }

    let mut canonical = None;
    let mut hreflang = Vec::new();
    for link in doc.select(&sel("link")) {
        let rel = attr(&link, "rel").unwrap_or_default();
        let rel_tokens: Vec<&str> = rel.split_whitespace().collect();
        if rel_tokens.contains(&"canonical") && canonical.is_none() {
            canonical = attr(&link, "href");
        }
        if rel_tokens.contains(&"alternate") {
            if let Some(hl) = attr(&link, "hreflang") {
                hreflang.push(HreflangEntry {
                    lang: hl,
                    href: attr(&link, "href"),
                });
            }
        }
    }

    let mut h1 = Vec::new();
    let mut h2 = Vec::new();
    let mut h3 = Vec::new();
    for (tag, out) in [("h1", &mut h1), ("h2", &mut h2), ("h3", &mut h3)] {
        for heading in doc.select(&sel(tag)) {
            let text = text_of(heading);
            if !text.is_empty() {
                out.push(text);
            }
        }
    }

    let mut images = Vec::new();
    for img in doc.select(&sel("img")) {
        let mut src = attr(&img, "src").unwrap_or_default();
        if let Some(base) = base_url {
            if !src.is_empty() {
                src = resolve_href(base, &src);
            }
        }
        images.push(ImageInfo {
            src,
            alt: attr(&img, "alt"),
            width: attr(&img, "width"),
            height: attr(&img, "height"),
            loading: attr(&img, "loading"),
        });
    }

    let mut links = Links::default();
    if let Some(base) = base_url {
        for a in doc.select(&sel("a")) {
            let href = match attr(&a, "href") {
                Some(h) if !h.is_empty() => h,
                _ => continue,
            };
            let Some((full_url, class)) = classify_link(base, &href) else {
                continue;
            };
            let mut text = text_of(a);
            if text.len() > 100 {
                text = text.chars().take(100).collect();
            }
            let rel = attr(&a, "rel")
                .map(|r| r.split_whitespace().map(|s| s.to_string()).collect())
                .unwrap_or_default();
            let info = LinkInfo {
                href: full_url,
                text,
                rel,
            };
            match class {
                LinkClass::Internal => links.internal.push(info),
                LinkClass::External => links.external.push(info),
            }
        }
    }

    let schema_bodies: Vec<String> = doc
        .select(&sel(r#"script[type="application/ld+json"]"#))
        .map(|s| s.text().collect::<Vec<_>>().join(""))
        .collect();
    let schema = parse_json_ld(schema_bodies.iter().map(|s| s.as_str()));

    // Word count: visible text with script/style/nav/footer/header excluded, matching
    // the Python's `element.decompose()` loop before `soup.get_text()`.
    let strip = sel("script, style, nav, footer, header");
    let strip_set: std::collections::HashSet<_> = doc.select(&strip).map(|e| e.id()).collect();
    // `Html::parse_document` always synthesizes an `<html>` root (html5ever's tree
    // construction), so this always finds one, even for fragment input.
    let mut text_parts = Vec::new();
    if let Some(root) = doc.select(&sel("html")).next() {
        for node in root.descendants() {
            if let Some(el) = scraper::ElementRef::wrap(node) {
                if strip_set.contains(&el.id()) {
                    continue;
                }
            }
            if let Some(t) = node.value().as_text() {
                let parent_stripped = node
                    .parent()
                    .and_then(scraper::ElementRef::wrap)
                    .map(|p| strip_set.contains(&p.id()))
                    .unwrap_or(false);
                if !parent_stripped {
                    text_parts.push(t.to_string());
                }
            }
        }
    }
    let text = text_parts.join(" ");
    let word_count = word_count(&text);

    ParseResult {
        title,
        meta_description,
        meta_robots,
        canonical,
        h1,
        h2,
        h3,
        images,
        links,
        schema,
        open_graph,
        twitter_card,
        word_count,
        hreflang,
    }
}

/// Port of `main()`: reads HTML from `file` (or `--url`-relative stdin when `file` is
/// `None`), parses it, and returns `(exit_code, stdout, stderr)` so a thin `fn main`
/// can print/exit without this function doing process-global IO itself. Mirrors the
/// `os.path.realpath` + `os.path.isfile` file-not-found check exactly.
pub fn run(file: Option<&str>, base_url: Option<&str>, json_output: bool) -> (i32, String, String) {
    let html = match file {
        Some(path) => {
            let real_path = std::fs::canonicalize(path).unwrap_or_else(|_| Path::new(path).to_path_buf());
            if !real_path.is_file() {
                return (1, String::new(), format!("Error: File not found: {path}\n"));
            }
            match std::fs::read_to_string(&real_path) {
                Ok(s) => s,
                Err(e) => return (1, String::new(), format!("Error: {e}\n")),
            }
        }
        None => {
            let mut buf = String::new();
            if std::io::stdin().read_to_string(&mut buf).is_err() {
                return (1, String::new(), "Error: failed to read stdin\n".to_string());
            }
            buf
        }
    };

    let result = parse_html(&html, base_url);

    if json_output {
        let stdout = serde_json::to_string_pretty(&result).unwrap_or_default();
        return (0, stdout, String::new());
    }

    let mut out = String::new();
    out.push_str(&format!("Title: {}\n", result.title.as_deref().unwrap_or("None")));
    out.push_str(&format!(
        "Meta Description: {}\n",
        result.meta_description.as_deref().unwrap_or("None")
    ));
    out.push_str(&format!(
        "Canonical: {}\n",
        result.canonical.as_deref().unwrap_or("None")
    ));
    out.push_str(&format!("H1 Tags: {}\n", result.h1.len()));
    out.push_str(&format!("H2 Tags: {}\n", result.h2.len()));
    out.push_str(&format!("Images: {}\n", result.images.len()));
    out.push_str(&format!("Internal Links: {}\n", result.links.internal.len()));
    out.push_str(&format!("External Links: {}\n", result.links.external.len()));
    out.push_str(&format!("Schema Blocks: {}\n", result.schema.len()));
    out.push_str(&format!("Word Count: {}\n", result.word_count));
    (0, out, String::new())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn word_count_matches_word_boundary_regex() {
        assert_eq!(word_count("Hello, world! This is SEO-101."), 6);
        assert_eq!(word_count(""), 0);
    }

    #[test]
    fn resolve_href_absolute_passthrough() {
        assert_eq!(
            resolve_href("https://example.com/blog/", "https://other.com/x"),
            "https://other.com/x"
        );
    }

    #[test]
    fn resolve_href_absolute_path() {
        assert_eq!(
            resolve_href("https://example.com/blog/post", "/about"),
            "https://example.com/about"
        );
    }

    #[test]
    fn resolve_href_relative_path_joins_directory() {
        assert_eq!(
            resolve_href("https://example.com/blog/post", "next"),
            "https://example.com/blog/next"
        );
    }

    #[test]
    fn resolve_href_scheme_relative() {
        assert_eq!(
            resolve_href("https://example.com/", "//cdn.example.com/a.js"),
            "https://cdn.example.com/a.js"
        );
    }

    #[test]
    fn classify_link_skips_fragment_and_js_hrefs() {
        assert_eq!(classify_link("https://example.com", "#top"), None);
        assert_eq!(classify_link("https://example.com", "javascript:void(0)"), None);
        assert_eq!(classify_link("https://example.com", ""), None);
    }

    #[test]
    fn classify_link_internal_vs_external() {
        let (url, class) = classify_link("https://example.com/a", "/b").unwrap();
        assert_eq!(url, "https://example.com/b");
        assert_eq!(class, LinkClass::Internal);

        let (url, class) = classify_link("https://example.com/a", "https://other.com/c").unwrap();
        assert_eq!(url, "https://other.com/c");
        assert_eq!(class, LinkClass::External);
    }

    #[test]
    fn parse_json_ld_skips_invalid_and_keeps_valid() {
        let scripts = vec![r#"{"@type": "Organization"}"#, "not json", r#"[1, 2, 3]"#];
        let parsed = parse_json_ld(scripts);
        assert_eq!(parsed.len(), 2);
    }

    #[test]
    fn extract_open_graph_filters_and_lowercases() {
        let props = vec![("OG:Title", "Hello"), ("twitter:card", "summary"), ("og:image", "x.png")];
        let og = extract_open_graph(props);
        assert_eq!(og.len(), 2);
        assert_eq!(og.get("og:title").map(|s| s.as_str()), Some("Hello"));
    }

    #[test]
    fn extract_twitter_card_filters_and_lowercases() {
        let names = vec![("Twitter:Card", "summary"), ("description", "x")];
        let tw = extract_twitter_card(names);
        assert_eq!(tw.len(), 1);
        assert_eq!(tw.get("twitter:card").map(|s| s.as_str()), Some("summary"));
    }

    const SAMPLE_HTML: &str = r##"<!DOCTYPE html>
<html>
<head>
<title>Example Page</title>
<meta name="description" content="An example page for tests">
<meta name="robots" content="index,follow">
<link rel="canonical" href="/canonical-page">
<link rel="alternate" hreflang="fr" href="/fr/">
<meta property="og:title" content="OG Title">
<meta name="twitter:card" content="summary">
<script type="application/ld+json">{"@type": "Organization", "name": "Acme"}</script>
<script type="application/ld+json">not json</script>
</head>
<body>
<nav>Skip this nav text</nav>
<h1>Main Heading</h1>
<h2>Sub Heading</h2>
<img src="/img/a.png" alt="A" width="10" height="20" loading="lazy">
<a href="/internal">Internal link</a>
<a href="https://other.example/x">External link</a>
<a href="#top">Skip fragment</a>
<p>Some visible body text here.</p>
<footer>Skip footer text</footer>
</body>
</html>"##;

    #[test]
    fn parse_html_extracts_full_result() {
        let result = parse_html(SAMPLE_HTML, Some("https://example.com/page"));
        assert_eq!(result.title.as_deref(), Some("Example Page"));
        assert_eq!(
            result.meta_description.as_deref(),
            Some("An example page for tests")
        );
        assert_eq!(result.meta_robots.as_deref(), Some("index,follow"));
        assert_eq!(
            result.canonical.as_deref(),
            Some("/canonical-page")
        );
        assert_eq!(result.hreflang.len(), 1);
        assert_eq!(result.hreflang[0].lang, "fr");
        assert_eq!(result.h1, vec!["Main Heading".to_string()]);
        assert_eq!(result.h2, vec!["Sub Heading".to_string()]);
        assert_eq!(result.images.len(), 1);
        assert_eq!(result.images[0].src, "https://example.com/img/a.png");
        assert_eq!(result.images[0].alt.as_deref(), Some("A"));
        assert_eq!(result.links.internal.len(), 1);
        assert_eq!(result.links.internal[0].href, "https://example.com/internal");
        assert_eq!(result.links.external.len(), 1);
        assert_eq!(result.links.external[0].href, "https://other.example/x");
        assert_eq!(result.schema.len(), 1);
        assert_eq!(result.open_graph.get("og:title").map(|s| s.as_str()), Some("OG Title"));
        assert_eq!(
            result.twitter_card.get("twitter:card").map(|s| s.as_str()),
            Some("summary")
        );
        // Visible text excludes nav/footer, matching the Python's `element.decompose()`.
        assert!(result.word_count > 0);
        assert!(result.word_count < 20);
    }

    #[test]
    fn parse_html_without_base_url_skips_links() {
        let result = parse_html(SAMPLE_HTML, None);
        assert!(result.links.internal.is_empty());
        assert!(result.links.external.is_empty());
    }

    #[test]
    fn run_missing_file_matches_python_error() {
        let (code, stdout, stderr) = run(Some("/nonexistent/path/for/r42/test.html"), None, false);
        assert_eq!(code, 1);
        assert!(stdout.is_empty());
        assert!(stderr.contains("File not found"));
    }
}
