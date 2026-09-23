//! Port of `skills/designer/engine/scripts/detector/engines/site/sweep.mjs`'s
//! pure logic: `extractLinks` and the `REQUIRED_PAGES` profile match. The
//! live-network pieces (`checkStatus`'s `fetch`, `sweepSite`'s page fetch and
//! request fan-out) are not ported — no return-value contract without a real
//! network stack, and the decision logic they wrap around is what's ported
//! here.

use std::sync::OnceLock;

use regex::Regex;

/// One extracted `<a href="...">` link: the raw href, the URL resolved
/// against a base (when resolution succeeds), and the flattened anchor
/// text. Mirrors `extractLinks`'s `{ href, url, text }` shape; `resolved`
/// is `None` for hrefs `new URL(href, baseUrl)` would throw on (matches the
/// JS `try { resolved = new URL(...) } catch { continue; }` — such links
/// are dropped entirely in JS, so `resolved` is never actually `None` here;
/// it exists only so a caller can observe why a link failed if it wants to).
#[derive(Debug, Clone, PartialEq)]
pub struct ExtractedLink {
    pub href: String,
    pub resolved: String,
    pub text: String,
}

fn anchor_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r#"(?is)<a\b[^>]*href\s*=\s*("([^"]*)"|'([^']*)')[^>]*>(.*?)</a>"#).unwrap()
    })
}

fn tag_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"<[^>]+>").unwrap())
}

fn ws_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\s+").unwrap())
}

fn skip_protocol_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?i)^(mailto|tel|javascript):").unwrap())
}

/// Very small "resolve href against base" used only to decide whether a
/// link is same-origin later. It is not a full URL resolver: it handles
/// absolute URLs, protocol-relative (`//host/...`), and root-relative
/// (`/path`) hrefs, which is what `extractLinks`'s output is actually used
/// for downstream (`l.url.origin === base.origin`, `l.url.pathname`).
/// Anything else (bare relative paths, `../..`) is resolved against the
/// base's directory the same way `new URL` would.
fn resolve_href(href: &str, base: &str) -> Option<String> {
    if href.starts_with("http://") || href.starts_with("https://") {
        return Some(href.to_string());
    }
    let scheme_end = base.find("://")?;
    let scheme = &base[..scheme_end];
    let rest = &base[scheme_end + 3..];
    let (authority, path_and_more) = match rest.find('/') {
        Some(idx) => (&rest[..idx], &rest[idx..]),
        None => (rest, "/"),
    };
    if let Some(stripped) = href.strip_prefix("//") {
        return Some(format!("{scheme}://{stripped}"));
    }
    if let Some(root) = href.strip_prefix('/') {
        return Some(format!("{scheme}://{authority}/{root}"));
    }
    // Relative href: resolve against the base path's directory.
    let dir = match path_and_more.rfind('/') {
        Some(idx) => &path_and_more[..=idx],
        None => "/",
    };
    Some(format!("{scheme}://{authority}{dir}{href}"))
}

/// Origin (`scheme://authority`) of a resolved URL string, as
/// `new URL(...).origin` would report it (ignoring the default-port
/// normalization `URL` does, which this chunk's callers never rely on).
pub fn url_origin(url: &str) -> Option<String> {
    let scheme_end = url.find("://")?;
    let rest = &url[scheme_end + 3..];
    let authority_end = rest.find('/').unwrap_or(rest.len());
    Some(format!("{}://{}", &url[..scheme_end], &rest[..authority_end]))
}

/// Path portion of a resolved URL string, as `new URL(...).pathname` would
/// report it (query/fragment stripped).
pub fn url_pathname(url: &str) -> String {
    let scheme_end = match url.find("://") {
        Some(i) => i,
        None => return url.to_string(),
    };
    let rest = &url[scheme_end + 3..];
    let path_start = rest.find('/').unwrap_or(rest.len());
    let path = &rest[path_start..];
    let path = path.split(['?', '#']).next().unwrap_or("");
    if path.is_empty() {
        "/".to_string()
    } else {
        path.to_string()
    }
}

/// Port of `extractLinks(html, baseUrl)`: same-document `<a href>` scrape,
/// skipping empty/`#`-only/`mailto:`/`tel:`/`javascript:` hrefs and
/// Cloudflare's `/cdn-cgi/` obfuscation endpoints, and dropping any href
/// that fails to resolve against `baseUrl`.
pub fn extract_links(html: &str, base_url: &str) -> Vec<ExtractedLink> {
    let mut links = Vec::new();
    for caps in anchor_re().captures_iter(html) {
        let href_raw = caps
            .get(2)
            .or_else(|| caps.get(3))
            .map(|m| m.as_str())
            .unwrap_or("")
            .trim()
            .to_string();
        let inner = caps.get(4).map(|m| m.as_str()).unwrap_or("");
        let text = ws_re()
            .replace_all(&tag_re().replace_all(inner, " "), " ")
            .trim()
            .to_string();

        if href_raw.is_empty() || href_raw.starts_with('#') {
            continue;
        }
        if skip_protocol_re().is_match(&href_raw) {
            continue;
        }
        if href_raw.contains("/cdn-cgi/") {
            continue;
        }
        let resolved = match resolve_href(&href_raw, base_url) {
            Some(r) => r,
            None => continue,
        };
        links.push(ExtractedLink {
            href: href_raw,
            resolved,
            text,
        });
    }
    links
}

/// One required-page rule: a display name plus the pattern its href
/// path/anchor text must match for the page to count as "present".
/// `pattern` is a case-insensitive regex source string, mirroring the `/i`
/// JS `RegExp` literals in `REQUIRED_PAGES`.
#[derive(Debug, Clone, Copy)]
pub struct RequiredPage {
    pub name: &'static str,
    pub pattern: &'static str,
}

pub const UNIVERSAL_PAGES: &[RequiredPage] = &[
    RequiredPage { name: "privacy policy", pattern: "privacy" },
    RequiredPage { name: "terms / T&C", pattern: "terms|conditions|tos\\b" },
];

pub const APP_PAGES: &[RequiredPage] = &[
    RequiredPage { name: "pricing", pattern: "pricing|price" },
    RequiredPage { name: "download", pattern: "download" },
];

pub const ECOMMERCE_PAGES: &[RequiredPage] = &[
    RequiredPage { name: "returns/refunds", pattern: "return|refund" },
    RequiredPage { name: "shipping", pattern: "shipping|delivery" },
    RequiredPage { name: "contact", pattern: "contact" },
    RequiredPage { name: "about", pattern: "about" },
];

pub const CONTENT_PAGES: &[RequiredPage] = &[
    RequiredPage { name: "about", pattern: "about" },
];

/// Port of the `REQUIRED_PAGES` lookup by site-type key (`"universal"` is
/// always available; the rest match `siteType`). Returns `None` for an
/// unknown key, mirroring `REQUIRED_PAGES[siteType]` being `undefined`.
pub fn required_pages_for(site_type: &str) -> Option<&'static [RequiredPage]> {
    match site_type {
        "universal" => Some(UNIVERSAL_PAGES),
        "app" => Some(APP_PAGES),
        "ecommerce" => Some(ECOMMERCE_PAGES),
        "content" => Some(CONTENT_PAGES),
        _ => None,
    }
}

/// Port of the profile list `sweepSite` builds: `["universal", ...(siteType
/// present in REQUIRED_PAGES ? [siteType] : [])]`.
pub fn profiles_for(site_type: Option<&str>) -> Vec<&'static str> {
    let mut out = vec!["universal"];
    if let Some(st) = site_type {
        if required_pages_for(st).is_some() && st != "universal" {
            out.push(match st {
                "app" => "app",
                "ecommerce" => "ecommerce",
                "content" => "content",
                _ => unreachable!(),
            });
        }
    }
    out
}

/// Port of the `found` test inside `sweepSite`'s required-pages loop:
/// `page.pattern.test(l.url.pathname) || page.pattern.test(l.text)`,
/// case-insensitive.
pub fn page_is_linked(page: &RequiredPage, links: &[ExtractedLink]) -> bool {
    let re = Regex::new(&format!("(?i){}", page.pattern)).expect("valid REQUIRED_PAGES pattern");
    links.iter().any(|l| {
        let pathname = url_pathname(&l.resolved);
        re.is_match(&pathname) || re.is_match(&l.text)
    })
}

/// Port of the "missing required page" scan across the given profiles:
/// returns the `RequiredPage`s (and the profile they came from) that have
/// no matching link among `internal` (same-origin) links. Callers turn
/// each miss into a `missing-required-page` finding.
pub fn missing_required_pages(
    profiles: &[&'static str],
    internal: &[ExtractedLink],
) -> Vec<(&'static str, RequiredPage)> {
    let mut out = Vec::new();
    for &profile in profiles {
        let Some(pages) = required_pages_for(profile) else { continue };
        for &page in pages {
            if !page_is_linked(&page, internal) {
                out.push((profile, page));
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_links_skips_hash_mailto_tel_js_and_cdn_cgi() {
        let html = r#"
            <a href="#top">Top</a>
            <a href="mailto:a@b.com">Mail</a>
            <a href="tel:+1234">Call</a>
            <a href="javascript:void(0)">JS</a>
            <a href="/cdn-cgi/l/email-protection">Protected</a>
            <a href="/pricing">Pricing</a>
        "#;
        let links = extract_links(html, "https://example.com/");
        assert_eq!(links.len(), 1);
        assert_eq!(links[0].href, "/pricing");
        assert_eq!(links[0].text, "Pricing");
    }

    #[test]
    fn extract_links_resolves_root_relative_and_strips_tags_from_text() {
        let html = r#"<a href="/about"><strong>About</strong> Us</a>"#;
        let links = extract_links(html, "https://example.com/blog/post");
        assert_eq!(links.len(), 1);
        assert_eq!(links[0].resolved, "https://example.com/about");
        assert_eq!(links[0].text, "About Us");
    }

    #[test]
    fn extract_links_resolves_relative_against_base_directory() {
        let html = r#"<a href="sibling">Sibling</a>"#;
        let links = extract_links(html, "https://example.com/blog/post");
        assert_eq!(links[0].resolved, "https://example.com/blog/sibling");
    }

    #[test]
    fn url_origin_and_pathname_match_new_url_semantics() {
        assert_eq!(
            url_origin("https://example.com/a/b?x=1#y").unwrap(),
            "https://example.com"
        );
        assert_eq!(url_pathname("https://example.com/a/b?x=1#y"), "/a/b");
        assert_eq!(url_pathname("https://example.com"), "/");
    }

    #[test]
    fn profiles_for_always_includes_universal() {
        assert_eq!(profiles_for(None), vec!["universal"]);
        assert_eq!(profiles_for(Some("ecommerce")), vec!["universal", "ecommerce"]);
        // Unknown site type: universal only, same as REQUIRED_PAGES[siteType] undefined.
        assert_eq!(profiles_for(Some("unknown")), vec!["universal"]);
    }

    #[test]
    fn page_is_linked_matches_pathname_or_text_case_insensitively() {
        let links = extract_links(
            r#"<a href="/PRIVACY-policy">Legal</a>"#,
            "https://example.com/",
        );
        let page = UNIVERSAL_PAGES[0]; // privacy policy
        assert!(page_is_linked(&page, &links));

        let links2 = extract_links(r#"<a href="/legal">Privacy Policy</a>"#, "https://example.com/");
        assert!(page_is_linked(&page, &links2));

        let links3 = extract_links(r#"<a href="/legal">Legal</a>"#, "https://example.com/");
        assert!(!page_is_linked(&page, &links3));
    }

    #[test]
    fn missing_required_pages_reports_every_unmatched_page_in_profile_order() {
        let links = extract_links(r#"<a href="/pricing">Pricing</a>"#, "https://example.com/");
        let profiles = profiles_for(Some("app"));
        let missing = missing_required_pages(&profiles, &links);
        // universal: privacy + terms both missing; app: download missing (pricing present).
        assert_eq!(missing.len(), 3);
        assert!(missing.iter().any(|(p, pg)| *p == "universal" && pg.name == "privacy policy"));
        assert!(missing.iter().any(|(p, pg)| *p == "universal" && pg.name == "terms / T&C"));
        assert!(missing.iter().any(|(p, pg)| *p == "app" && pg.name == "download"));
        assert!(!missing.iter().any(|(_, pg)| pg.name == "pricing"));
    }
}
