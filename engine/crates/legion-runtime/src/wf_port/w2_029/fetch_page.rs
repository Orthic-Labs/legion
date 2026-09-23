//! Port of `skills/seo/scripts/fetch_page.py`.
//!
//! The actual HTTP fetch (`requests.Session().get(...)`) and DNS
//! resolution (`socket.gethostbyname`) are not ported — this crate has no
//! HTTP client dependency and stays at the JSON-value-in/value-out edge.
//! What *is* ported, faithfully: URL scheme validation, the default and
//! Googlebot headers, and the private/loopback/reserved-IP SSRF check
//! (taking the already-resolved IP as input, since DNS resolution is a
//! host-side effect).

use std::collections::BTreeMap;
use std::net::IpAddr;

pub const DEFAULT_USER_AGENT: &str = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 \
(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 ClaudeSEO/1.2";

/// Googlebot UA for prerender/dynamic rendering detection. Prerender
/// services (Prerender.io, Rendertron) serve fully rendered HTML to
/// Googlebot but raw JS shells to other UAs; comparing response sizes
/// between [`DEFAULT_USER_AGENT`] and this UA reveals whether a site uses
/// dynamic rendering.
pub const GOOGLEBOT_USER_AGENT: &str =
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)";

/// Mirrors Python `DEFAULT_HEADERS`, with `user_agent` substituted for
/// `User-Agent` exactly as `fetch_page()` does when `user_agent` is given.
pub fn default_headers(user_agent: Option<&str>) -> BTreeMap<&'static str, String> {
    let mut headers = BTreeMap::new();
    headers.insert(
        "User-Agent",
        user_agent.unwrap_or(DEFAULT_USER_AGENT).to_string(),
    );
    headers.insert(
        "Accept",
        "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8".to_string(),
    );
    headers.insert("Accept-Language", "en-US,en;q=0.5".to_string());
    headers.insert("Accept-Encoding", "gzip, deflate".to_string());
    headers.insert("Connection", "keep-alive".to_string());
    headers
}

/// Mirrors the URL-scheme portion of `fetch_page()`: `urlparse(url)`
/// defaulting a schemeless URL to `https://`, then requiring
/// `http`/`https`. Returns the normalized URL, or an error message
/// matching `f"Invalid URL scheme: {parsed.scheme}"`.
pub fn normalize_and_validate_scheme(url: &str) -> Result<String, String> {
    let (normalized, scheme) = if url.contains("://") {
        let scheme = url.split("://").next().unwrap_or("").to_string();
        (url.to_string(), scheme)
    } else {
        (format!("https://{url}"), "https".to_string())
    };
    if scheme != "http" && scheme != "https" {
        return Err(format!("Invalid URL scheme: {scheme}"));
    }
    Ok(normalized)
}

/// Mirrors the SSRF-prevention block in `fetch_page()`:
/// `ip.is_private or ip.is_loopback or ip.is_reserved`. `resolved_ip` is
/// the IP that DNS resolution of the URL's hostname returned; pass `None`
/// when resolution fails (Python's `except (socket.gaierror, ValueError):
/// pass`, which lets the request proceed and fail downstream instead).
/// Returns an error message matching
/// `f"Blocked: URL resolves to private/internal IP ({resolved_ip})"` when
/// blocked.
pub fn check_ssrf(resolved_ip: Option<IpAddr>) -> Result<(), String> {
    let Some(ip) = resolved_ip else {
        return Ok(());
    };
    let blocked = match ip {
        IpAddr::V4(v4) => v4.is_private() || v4.is_loopback() || is_reserved_v4(v4),
        IpAddr::V6(v6) => v6.is_loopback() || is_reserved_v6(v6),
    };
    if blocked {
        return Err(format!("Blocked: URL resolves to private/internal IP ({ip})"));
    }
    Ok(())
}

/// Approximates Python `ipaddress.IPv4Address.is_reserved`: `240.0.0.0/4`
/// (excluding the broadcast address, which Python also reports as
/// reserved) plus `0.0.0.0/8` and the documented multicast/reserved
/// ranges Python's stdlib table marks reserved.
fn is_reserved_v4(v4: std::net::Ipv4Addr) -> bool {
    let o = v4.octets();
    o[0] >= 240 || o[0] == 0
}

/// Approximates Python `ipaddress.IPv6Address.is_reserved`.
fn is_reserved_v6(v6: std::net::Ipv6Addr) -> bool {
    let seg0 = v6.segments()[0];
    // IETF reserved ranges roughly overlapping Python's is_reserved table:
    // 0000::/8 (minus ::/128 and ::1/128 handled by is_loopback),
    // 0100::/8, 0200::/7 .. 03FF::/8 legacy blocks, 4000::/3 through
    // D000::/3 unassigned-at-publication ranges Python still flags.
    matches!(seg0 >> 8, 0x00 | 0x01 | 0x02 | 0x03) || (0x4000..=0xdfff).contains(&seg0)
}

#[derive(Debug, Clone, PartialEq)]
pub struct RedirectDetail {
    pub url: String,
    pub status_code: u16,
}

/// Formats the metadata Python prints to stderr after a successful fetch:
/// `f"\nURL: {url}"`, `f"Status: {status}"`, and either the per-hop
/// `f"  {status} -> {url}"` lines (ending with `(final)`), or, when only
/// the flat `redirect_chain` is available, `f"Redirects: {chain}"`.
pub fn format_metadata(
    url: &str,
    status_code: u16,
    redirect_details: &[RedirectDetail],
    redirect_chain: &[String],
) -> String {
    let mut out = format!("\nURL: {url}\nStatus: {status_code}");
    if !redirect_details.is_empty() {
        for rd in redirect_details {
            out.push_str(&format!("\n  {} -> {}", rd.status_code, rd.url));
        }
        out.push_str(&format!("\n  {status_code} -> {url} (final)"));
    } else if !redirect_chain.is_empty() {
        out.push_str(&format!("\nRedirects: {}", redirect_chain.join(" -> ")));
    }
    out
}
