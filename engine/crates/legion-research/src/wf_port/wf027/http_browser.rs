//! Port of `src/lib/research-core/providers/http_browser.py`.
//!
//! Network access (`_request`) is isolated behind the `HttpTransport` trait
//! below so the rest of the port (URL validation, HTML text extraction, RSS
//! parsing, search/open/find orchestration) is unit testable with a fake
//! transport and needs no network access to compile or test.
//! [`ReqwestTransport`] is the real implementation, backed by
//! `reqwest`'s blocking client (an allowed new dependency for this crate,
//! added to `Cargo.toml` as `reqwest = { workspace = true, features =
//! ["blocking"] }`, mirroring how `legion-runtime` already depends on it).

use std::io::Read;
use std::net::IpAddr;

use regex::Regex;
use serde_json::Map;

use super::support::{data_only_envelope, locate_text, publisher_from_url, seed_id, stable_hit_id, today, WfError};
use super::types::{LocatedPassage, OpenedSource, Provider, SearchHit};

pub const USER_AGENT: &str = "LegionResearch/1.0 (+https://github.com/orthic-labs/legion)";
pub const MAX_BODY_BYTES: usize = 5 * 1024 * 1024;

/// A fetched response: raw bytes, the final (post-redirect) URL, and the
/// response's content type (mirrors `urllib`'s `response.geturl()` /
/// `response.headers.get_content_type()`).
#[derive(Clone, Debug)]
pub struct HttpResponse {
    pub body: Vec<u8>,
    pub final_url: String,
    pub content_type: String,
}

/// Injected transport. Implementations own the actual network call; this
/// module owns URL validation, body-size bounds, and response parsing.
pub trait HttpTransport {
    fn get(&self, url: &str, accept: &str, timeout_s: u64) -> Result<HttpResponse, WfError>;
}

/// Real transport, backed by `reqwest`'s blocking client. Mirrors
/// `urllib.request.urlopen(...)` with a bounded read (`MAX_BODY_BYTES + 1`,
/// so an oversized body is detected and rejected rather than silently
/// truncated) and the same `User-Agent`/`Accept`/`Accept-Encoding: identity`
/// headers the Python sends.
pub struct ReqwestTransport {
    client: reqwest::blocking::Client,
}

impl Default for ReqwestTransport {
    fn default() -> Self {
        Self::new()
    }
}

impl ReqwestTransport {
    pub fn new() -> Self {
        Self {
            client: reqwest::blocking::Client::new(),
        }
    }
}

impl HttpTransport for ReqwestTransport {
    fn get(&self, url: &str, accept: &str, timeout_s: u64) -> Result<HttpResponse, WfError> {
        validate_public_url(url)?;
        let resp = self
            .client
            .get(url)
            .timeout(std::time::Duration::from_secs(timeout_s))
            .header("User-Agent", USER_AGENT)
            .header("Accept", accept)
            .header("Accept-Encoding", "identity")
            .send()
            .map_err(|e| WfError::Provider(e.to_string()))?;
        let final_url = resp.url().to_string();
        let content_type = resp
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .map(|v| v.split(';').next().unwrap_or(v).trim().to_string())
            .unwrap_or_default();
        let mut reader = std::io::Read::take(resp, (MAX_BODY_BYTES + 1) as u64);
        let mut buf = Vec::new();
        reader
            .read_to_end(&mut buf)
            .map_err(|e| WfError::Io(e.to_string()))?;
        if buf.len() > MAX_BODY_BYTES {
            return Err(WfError::Provider(format!(
                "provider response exceeds {MAX_BODY_BYTES} bytes"
            )));
        }
        Ok(HttpResponse {
            body: buf,
            final_url,
            content_type,
        })
    }
}

/// Port of `providers/scholarly.py`'s `_get_json`/`_get_text` and of
/// `retraction.py`'s `_openalex`/`_crossref`, all reusing the same
/// [`ReqwestTransport`] client (this crate has one HTTP client dependency,
/// not one per provider). These are additive `impl`s of sibling packets'
/// already-ported transport traits (`wf028::scholarly::ScholarlyTransport`,
/// `wf028::retraction::RetractionTransport`) for the type this file (wf027,
/// `http_browser.py`'s port) owns, closing the "no HTTP client crate is a
/// workspace dependency" gap those modules' doc comments note.
impl crate::wf_port::wf028::scholarly::ScholarlyTransport for ReqwestTransport {
    fn get_json(
        &self,
        url: &str,
        timeout_secs: u64,
    ) -> Result<serde_json::Value, crate::wf_port::wf028::scholarly::TransportError> {
        let resp = self
            .client
            .get(url)
            .timeout(std::time::Duration::from_secs(timeout_secs))
            .header("User-Agent", scholarly_user_agent())
            .header("Accept", "application/json")
            .send()
            .map_err(|e| crate::wf_port::wf028::scholarly::TransportError(e.to_string()))?;
        resp.json::<serde_json::Value>()
            .map_err(|e| crate::wf_port::wf028::scholarly::TransportError(e.to_string()))
    }

    fn get_text(
        &self,
        url: &str,
        timeout_secs: u64,
    ) -> Result<(String, String), crate::wf_port::wf028::scholarly::TransportError> {
        let resp = self
            .client
            .get(url)
            .timeout(std::time::Duration::from_secs(timeout_secs))
            .header("User-Agent", scholarly_user_agent())
            .header("Accept", "text/html,application/xhtml+xml,text/plain")
            .send()
            .map_err(|e| crate::wf_port::wf028::scholarly::TransportError(e.to_string()))?;
        let final_url = resp.url().to_string();
        let body = resp
            .text()
            .map_err(|e| crate::wf_port::wf028::scholarly::TransportError(e.to_string()))?;
        Ok((body, final_url))
    }
}

fn scholarly_user_agent() -> String {
    let email = std::env::var("RESEARCH_CONTACT_EMAIL").ok();
    crate::wf_port::wf028::scholarly::user_agent(email.as_deref().filter(|s| !s.is_empty()))
}

fn retraction_user_agent() -> String {
    match std::env::var("RESEARCH_CONTACT_EMAIL") {
        Ok(email) if !email.is_empty() => format!("ResearchCore/2.0 (mailto:{email})"),
        _ => "ResearchCore/2.0".to_string(),
    }
}

impl crate::wf_port::wf028::retraction::RetractionTransport for ReqwestTransport {
    fn openalex(
        &self,
        doi: &str,
    ) -> Result<serde_json::Value, crate::wf_port::wf028::retraction::TransportError> {
        let url = format!(
            "https://api.openalex.org/works/{}",
            quote_keep_colon_slash(&format!("https://doi.org/{doi}"))
        );
        let resp = self
            .client
            .get(&url)
            .timeout(std::time::Duration::from_secs(25))
            .header("User-Agent", retraction_user_agent())
            .header("Accept", "application/json")
            .send()
            .map_err(|e| crate::wf_port::wf028::retraction::TransportError(e.to_string()))?;
        resp.json::<serde_json::Value>()
            .map_err(|e| crate::wf_port::wf028::retraction::TransportError(e.to_string()))
    }

    fn crossref(
        &self,
        doi: &str,
    ) -> Result<serde_json::Value, crate::wf_port::wf028::retraction::TransportError> {
        let url = format!("https://api.crossref.org/works/{}", urlencode_path(doi));
        let resp = self
            .client
            .get(&url)
            .timeout(std::time::Duration::from_secs(25))
            .header("User-Agent", retraction_user_agent())
            .header("Accept", "application/json")
            .send()
            .map_err(|e| crate::wf_port::wf028::retraction::TransportError(e.to_string()))?;
        resp.json::<serde_json::Value>()
            .map_err(|e| crate::wf_port::wf028::retraction::TransportError(e.to_string()))
    }
}

/// `urllib.parse.quote(doi, safe='')`: percent-encode everything outside
/// the small "always safe" set.
fn urlencode_path(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => out.push(b as char),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// `urllib.parse.quote(value, safe=':/')`: like [`urlencode_path`] but also
/// leaves `:` and `/` unescaped (used to build the OpenAlex DOI-URL path
/// segment, which is itself a full `https://doi.org/...` URL).
fn quote_keep_colon_slash(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' | b':' | b'/' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// Port of `_public_url`: only http(s), only a resolvable hostname, and
/// refuses `localhost`/`.local`/non-global IP-literal hosts.
pub fn validate_public_url(url: &str) -> Result<(), WfError> {
    let idx = url
        .find("://")
        .ok_or_else(|| WfError::Invalid("browser provider accepts only http(s) URLs".into()))?;
    let scheme = &url[..idx];
    if scheme != "http" && scheme != "https" {
        return Err(WfError::Invalid(
            "browser provider accepts only http(s) URLs".into(),
        ));
    }
    let rest = &url[idx + 3..];
    let authority_end = rest
        .find(|c| c == '/' || c == '?' || c == '#')
        .unwrap_or(rest.len());
    let authority = &rest[..authority_end];
    let hostport = authority.rsplit('@').next().unwrap_or("");
    let host = if let Some(stripped) = hostport.strip_prefix('[') {
        stripped.split(']').next().unwrap_or("")
    } else {
        hostport.split(':').next().unwrap_or("")
    };
    if host.is_empty() {
        return Err(WfError::Invalid(
            "browser provider accepts only http(s) URLs".into(),
        ));
    }
    let host_lower = host.to_ascii_lowercase();
    if host_lower == "localhost" || host_lower.ends_with(".local") {
        return Err(WfError::Invalid(
            "browser provider refuses local hosts".into(),
        ));
    }
    if let Ok(addr) = host_lower.parse::<IpAddr>() {
        if !is_global_ip(&addr) {
            return Err(WfError::Invalid(
                "browser provider refuses non-public addresses".into(),
            ));
        }
    }
    Ok(())
}

/// Approximates Python's `ipaddress.IPv4Address.is_global` /
/// `IPv6Address.is_global` (private/loopback/link-local/multicast/etc. are
/// non-global).
fn is_global_ip(addr: &IpAddr) -> bool {
    match addr {
        IpAddr::V4(v4) => {
            !(v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.is_documentation()
                || v4.is_unspecified()
                || v4.is_multicast())
        }
        IpAddr::V6(v6) => {
            !(v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || (v6.segments()[0] & 0xfe00) == 0xfc00)
        }
    }
}

/// Port of `_document_text`.
pub fn document_text(raw: &[u8], content_type: &str) -> (String, String) {
    let decoded = String::from_utf8_lossy(raw).to_string();
    let head: String = decoded.chars().take(1000).collect::<String>().to_ascii_lowercase();
    let looks_html = content_type == "text/html"
        || content_type == "application/xhtml+xml"
        || head.contains("<html");
    if !looks_html {
        return (decoded, String::new());
    }
    extract_visible_text(&decoded)
}

fn extract_visible_text(html: &str) -> (String, String) {
    // The `regex` crate does not support backreferences, so the single
    // Python pattern `<(script|style|noscript|svg)\b[^>]*>.*?</\1>` is
    // expanded into one non-backreferenced alternative per tag name.
    let mut without_skipped = html.to_string();
    for tag in ["script", "style", "noscript", "svg"] {
        let skip_re = Regex::new(&format!(r"(?is)<{tag}\b[^>]*>.*?</{tag}>")).expect("static regex");
        without_skipped = skip_re.replace_all(&without_skipped, " ").into_owned();
    }
    let title_re = Regex::new(r"(?is)<title[^>]*>(.*?)</title>").expect("static regex");
    let title = title_re
        .captures(&without_skipped)
        .map(|c| collapse_ws(&html_unescape(&strip_tags(&c[1]))))
        .unwrap_or_default();
    let tag_re = Regex::new(r"(?is)<[^>]+>").expect("static regex");
    let text = tag_re.replace_all(&without_skipped, "\n");
    let text = html_unescape(&text);
    let lines: Vec<String> = text
        .lines()
        .map(collapse_ws)
        .filter(|l| !l.is_empty())
        .collect();
    (lines.join("\n"), title)
}

fn strip_tags(s: &str) -> String {
    Regex::new(r"(?is)<[^>]+>")
        .expect("static regex")
        .replace_all(s, "")
        .to_string()
}

fn collapse_ws(s: &str) -> String {
    Regex::new(r"\s+")
        .expect("static regex")
        .replace_all(s.trim(), " ")
        .to_string()
}

fn html_unescape(s: &str) -> String {
    s.replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
        .replace("&apos;", "'")
        .replace("&nbsp;", " ")
}

fn strip_cdata(s: &str) -> String {
    let t = s.trim();
    if let Some(inner) = t.strip_prefix("<![CDATA[").and_then(|r| r.strip_suffix("]]>")) {
        inner.trim().to_string()
    } else {
        t.to_string()
    }
}

/// Port of `_rss_hits`.
pub fn rss_hits(
    raw: &[u8],
    provider: &str,
    query: &str,
    limit: usize,
    seed_chain: &[String],
) -> Vec<SearchHit> {
    let text = String::from_utf8_lossy(raw).to_string();
    let item_re = Regex::new(r"(?is)<item\b[^>]*>(.*?)</item>").expect("static regex");
    let link_re = Regex::new(r"(?is)<link[^>]*>(.*?)</link>").expect("static regex");
    let title_re = Regex::new(r"(?is)<title[^>]*>(.*?)</title>").expect("static regex");
    let desc_re = Regex::new(r"(?is)<description[^>]*>(.*?)</description>").expect("static regex");
    let tag_re = Regex::new(r"(?is)<[^>]+>").expect("static regex");

    let seed = seed_id(query);
    let mut chain = seed_chain.to_vec();
    chain.push(seed.clone());
    let mut hits = Vec::new();
    for cap in item_re.captures_iter(&text) {
        let item = &cap[1];
        let url = link_re
            .captures(item)
            .map(|c| strip_cdata(&c[1]))
            .unwrap_or_default();
        if url.is_empty() {
            continue;
        }
        if validate_public_url(&url).is_err() {
            continue;
        }
        let title_raw = title_re
            .captures(item)
            .map(|c| strip_cdata(&c[1]))
            .unwrap_or_else(|| url.clone());
        let title = html_unescape(&title_raw);
        let desc_raw = desc_re.captures(item).map(|c| strip_cdata(&c[1])).unwrap_or_default();
        let desc_stripped = tag_re.replace_all(&desc_raw, " ").to_string();
        let snippet = html_unescape(&collapse_ws(&desc_stripped));
        let mut metadata = Map::new();
        metadata.insert("search_engine".into(), "bing-rss".into());
        hits.push(SearchHit {
            id: stable_hit_id(provider, &url),
            url: url.clone(),
            title,
            publisher: publisher_from_url(&url),
            snippet,
            suggested_by: seed.clone(),
            seed_chain: chain.clone(),
            provider: provider.to_string(),
            metadata,
        });
        if hits.len() >= limit {
            break;
        }
    }
    hits
}

fn urlencode(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            b' ' => out.push('+'),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// Port of `HttpBrowserProvider`, generic over the injected transport.
pub struct HttpBrowserProvider<T: HttpTransport> {
    transport: T,
}

impl<T: HttpTransport> HttpBrowserProvider<T> {
    pub const NAME: &'static str = "browser";
    pub const EXTERNAL_OPS: [&'static str; 2] = ["search", "open"];

    pub fn new(transport: T) -> Self {
        Self { transport }
    }
}

impl<T: HttpTransport> Provider for HttpBrowserProvider<T> {
    fn name(&self) -> &str {
        Self::NAME
    }

    fn search(
        &self,
        query: &str,
        limit: usize,
        seed_chain: &[String],
    ) -> Result<Vec<SearchHit>, WfError> {
        let query = query.trim();
        let is_direct_url = query
            .find("://")
            .map(|idx| {
                let scheme = &query[..idx];
                (scheme == "http" || scheme == "https") && !query.contains(char::is_whitespace)
            })
            .unwrap_or(false);
        if is_direct_url {
            validate_public_url(query)?;
            let seed = seed_id(query);
            let mut chain = seed_chain.to_vec();
            chain.push(seed.clone());
            let mut metadata = Map::new();
            metadata.insert("discovery".into(), "direct-url".into());
            return Ok(vec![SearchHit {
                id: stable_hit_id(Self::NAME, query),
                url: query.to_string(),
                title: query.to_string(),
                publisher: publisher_from_url(query),
                snippet: String::new(),
                suggested_by: seed,
                seed_chain: chain,
                provider: Self::NAME.to_string(),
                metadata,
            }]);
        }
        let count = limit.clamp(1, 50);
        let endpoint =
            format!("https://www.bing.com/search?q={}&format=rss&count={count}", urlencode(query));
        let resp = self
            .transport
            .get(&endpoint, "application/rss+xml,application/xml,text/xml", 45)?;
        Ok(rss_hits(&resp.body, Self::NAME, query, limit, seed_chain))
    }

    fn open(&self, url: &str) -> Result<OpenedSource, WfError> {
        let resp = self.transport.get(
            url,
            "text/html,application/xhtml+xml,text/plain,application/json",
            45,
        )?;
        let (body, title) = document_text(&resp.body, &resp.content_type);
        let (envelope, digest) = data_only_envelope(&body);
        let mut metadata = Map::new();
        metadata.insert("requested_url".into(), url.into());
        metadata.insert("content_type".into(), resp.content_type.clone().into());
        Ok(OpenedSource {
            url: resp.final_url.clone(),
            title: if title.is_empty() {
                resp.final_url.clone()
            } else {
                title
            },
            publisher: publisher_from_url(&resp.final_url),
            retrieved_at: today(),
            content: envelope,
            content_sha256: digest,
            instruction_policy: "data_only".into(),
            provider: Self::NAME.to_string(),
            metadata,
        })
    }

    fn find(&self, opened: &OpenedSource, pattern: &str) -> Result<Option<LocatedPassage>, WfError> {
        Ok(locate_text(&opened.content, pattern, 300).map(|(locator, text)| LocatedPassage {
            url: opened.url.clone(),
            locator,
            text,
            is_paraphrase: false,
            provider: Self::NAME.to_string(),
            metadata: Map::new(),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    struct FakeTransport {
        response: RefCell<Option<HttpResponse>>,
    }

    impl HttpTransport for FakeTransport {
        fn get(&self, _url: &str, _accept: &str, _timeout_s: u64) -> Result<HttpResponse, WfError> {
            self.response
                .borrow_mut()
                .take()
                .ok_or_else(|| WfError::Provider("no fake response queued".into()))
        }
    }

    #[test]
    fn validate_public_url_rejects_non_http_scheme() {
        assert!(validate_public_url("ftp://example.test/x").is_err());
    }

    #[test]
    fn validate_public_url_rejects_localhost_and_local_suffix() {
        assert!(validate_public_url("http://localhost/x").is_err());
        assert!(validate_public_url("http://box.local/x").is_err());
    }

    #[test]
    fn validate_public_url_rejects_private_ip_literals() {
        assert!(validate_public_url("http://127.0.0.1/x").is_err());
        assert!(validate_public_url("http://10.0.0.5/x").is_err());
        assert!(validate_public_url("http://192.168.1.1/x").is_err());
    }

    #[test]
    fn validate_public_url_accepts_public_host() {
        assert!(validate_public_url("https://example.com/x").is_ok());
    }

    #[test]
    fn document_text_strips_script_and_extracts_title() {
        let html = b"<html><head><title>Hi &amp; Bye</title><script>evil()</script></head><body><p>Hello  world</p></body></html>";
        let (text, title) = document_text(html, "text/html");
        assert_eq!(title, "Hi & Bye");
        assert!(text.contains("Hello world"));
        assert!(!text.contains("evil()"));
    }

    #[test]
    fn document_text_passthrough_for_non_html() {
        let (text, title) = document_text(b"{\"a\":1}", "application/json");
        assert_eq!(text, "{\"a\":1}");
        assert_eq!(title, "");
    }

    #[test]
    fn rss_hits_parses_items_and_skips_non_public_links() {
        let rss = br#"<rss><channel>
            <item><link>https://example.test/a</link><title>A &amp; B</title><description>&lt;p&gt;snip  pet&lt;/p&gt;</description></item>
            <item><link>http://localhost/skip</link><title>Skip</title></item>
        </channel></rss>"#;
        let hits = rss_hits(rss, "browser", "q", 10, &[]);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].url, "https://example.test/a");
        assert_eq!(hits[0].title, "A & B");
        assert!(hits[0].snippet.contains("snip pet"));
    }

    #[test]
    fn search_direct_url_returns_single_hit_without_network() {
        let provider = HttpBrowserProvider::new(FakeTransport {
            response: RefCell::new(None),
        });
        let hits = provider
            .search("https://example.test/page", 10, &[])
            .unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].metadata.get("discovery").unwrap(), "direct-url");
    }

    #[test]
    fn open_uses_transport_and_normalizes_body() {
        let provider = HttpBrowserProvider::new(FakeTransport {
            response: RefCell::new(Some(HttpResponse {
                body: b"<html><title>T</title><body>hello</body></html>".to_vec(),
                final_url: "https://example.test/page".into(),
                content_type: "text/html".into(),
            })),
        });
        let opened = provider.open("https://example.test/page").unwrap();
        assert_eq!(opened.title, "T");
        assert_eq!(opened.instruction_policy, "data_only");
        assert!(opened.content.contains("hello"));
    }

    #[test]
    fn find_delegates_to_locate_text() {
        let provider = HttpBrowserProvider::new(FakeTransport {
            response: RefCell::new(None),
        });
        let opened = OpenedSource {
            url: "https://example.test/page".into(),
            title: "T".into(),
            publisher: "example.test".into(),
            retrieved_at: "2026-01-01".into(),
            content: "some passage with keyword here".into(),
            content_sha256: "digest".into(),
            instruction_policy: "data_only".into(),
            provider: "browser".into(),
            metadata: Map::new(),
        };
        let found = provider.find(&opened, "keyword").unwrap().unwrap();
        assert!(found.text.contains("keyword"));
    }
}
