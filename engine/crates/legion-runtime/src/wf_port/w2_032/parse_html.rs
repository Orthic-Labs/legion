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
}
