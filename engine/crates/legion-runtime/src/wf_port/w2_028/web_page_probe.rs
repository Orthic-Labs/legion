//! Port of the shared pure logic in `skills/seo/scripts/capture_screenshot.py`
//! and `skills/seo/scripts/analyze_visual.py`.
//!
//! Both scripts are thin CLIs around Playwright (launch headless Chromium,
//! navigate, screenshot/query the DOM). This crate has no browser-automation
//! dependency, so none of the actual page capture/analysis is ported — that
//! is the remaining gap for both files. What both scripts do first, before
//! ever touching a browser, is pure and is ported here: URL scheme
//! normalization/validation (`normalize_url`), the viewport preset table,
//! and the SSRF guard that rejects a hostname resolving to a private,
//! loopback, or reserved IP. `capture_screenshot.py`'s output-path
//! traversal guard (`must be within current directory or home directory`)
//! is also ported, since it is pure path logic with no browser dependency.
//!
//! `capture_screenshot.py`'s viewport table, `analyze_visual.py`'s result
//! shape (`above_fold`/`mobile`/`layout`/`fonts`), and every DOM query
//! (`h1`, CTA selectors, hero image selectors, viewport meta, scroll width,
//! computed font size) are not ported — they require a live rendered page.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, ToSocketAddrs};

/// Mirrors `VIEWPORTS` in `capture_screenshot.py` (used identically for the
/// desktop/mobile splits in `analyze_visual.py`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Viewport {
    pub name: &'static str,
    pub width: u32,
    pub height: u32,
}

pub const VIEWPORTS: &[Viewport] = &[
    Viewport { name: "desktop", width: 1920, height: 1080 },
    Viewport { name: "laptop", width: 1366, height: 768 },
    Viewport { name: "tablet", width: 768, height: 1024 },
    Viewport { name: "mobile", width: 375, height: 812 },
];

pub fn viewport_by_name(name: &str) -> Option<Viewport> {
    VIEWPORTS.iter().copied().find(|v| v.name == name)
}

/// The pieces of `urlparse` this port needs: scheme and hostname (userinfo
/// and port are stripped from the host the way `parsed.hostname` does in
/// Python).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedUrl {
    pub scheme: String,
    pub hostname: Option<String>,
}

fn parse_url_minimal(url: &str) -> ParsedUrl {
    match url.find("://") {
        Some(idx) => {
            let scheme = url[..idx].to_string();
            let rest = &url[idx + 3..];
            let authority_end = rest
                .find(['/', '?', '#'])
                .unwrap_or(rest.len());
            let authority = &rest[..authority_end];
            // Drop userinfo (before the last '@' in the authority).
            let host_port = match authority.rfind('@') {
                Some(at) => &authority[at + 1..],
                None => authority,
            };
            // IPv6 literal in brackets: hostname is inside the brackets.
            let hostname = if host_port.starts_with('[') {
                host_port
                    .find(']')
                    .map(|end| host_port[1..end].to_string())
            } else {
                let host = match host_port.rfind(':') {
                    Some(colon) => &host_port[..colon],
                    None => host_port,
                };
                if host.is_empty() { None } else { Some(host.to_string()) }
            };
            ParsedUrl { scheme, hostname }
        }
        None => ParsedUrl {
            scheme: String::new(),
            hostname: None,
        },
    }
}

/// Mirrors `normalize_url`: prefix `https://` when there is no scheme,
/// then validate scheme is `http`/`https` and a hostname is present.
/// Returns `(normalized_url, parsed)` on success, or the same error message
/// Python's `ValueError` carried on failure.
pub fn normalize_url(url: &str) -> Result<(String, ParsedUrl), String> {
    let mut parsed = parse_url_minimal(url);
    let mut effective_url = url.to_string();
    if parsed.scheme.is_empty() {
        effective_url = format!("https://{url}");
        parsed = parse_url_minimal(&effective_url);
    }
    if parsed.scheme != "http" && parsed.scheme != "https" {
        return Err(format!("Invalid URL scheme: {}", parsed.scheme));
    }
    if parsed.hostname.is_none() {
        return Err("Invalid URL: missing hostname".to_string());
    }
    Ok((effective_url, parsed))
}

/// Mirrors the SSRF guard: resolve `hostname` and reject a private,
/// loopback, or reserved address. Python swallows `socket.gaierror`
/// (unresolvable host) and lets the request proceed to fail later; this
/// port does the same, returning `Ok(None)` when resolution fails.
///
/// Returns `Ok(Some(ip))` when resolution succeeded and the IP is safe,
/// `Err(message)` matching Python's `Blocked: URL resolves to
/// private/internal IP (<ip>)` when it is not, and `Ok(None)` when the
/// hostname could not be resolved at all.
pub fn check_ssrf(hostname: &str) -> Result<Option<IpAddr>, String> {
    let resolved = (hostname, 0u16).to_socket_addrs();
    let ip = match resolved {
        Ok(mut addrs) => match addrs.next() {
            Some(addr) => addr.ip(),
            None => return Ok(None),
        },
        Err(_) => return Ok(None),
    };
    if is_blocked_ip(ip) {
        return Err(format!(
            "Blocked: URL resolves to private/internal IP ({ip})"
        ));
    }
    Ok(Some(ip))
}

/// Mirrors `ip.is_private or ip.is_loopback or ip.is_reserved` from
/// Python's `ipaddress` module.
pub fn is_blocked_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_private_v4(v4) || v4.is_loopback() || is_reserved_v4(v4),
        IpAddr::V6(v6) => is_loopback_or_private_v6(v6),
    }
}

fn is_private_v4(ip: Ipv4Addr) -> bool {
    // Matches Python ipaddress.IPv4Address.is_private for the common RFC
    // 1918 + link-local + CGNAT ranges (mirrors Ipv4Addr::is_private plus
    // link-local, matching Python's broader definition).
    ip.is_private() || ip.is_link_local()
}

fn is_reserved_v4(ip: Ipv4Addr) -> bool {
    // Python's is_reserved covers 240.0.0.0/4 (class E) among others; this
    // is the practically relevant subset for an SSRF guard.
    let o = ip.octets();
    o[0] >= 240 || ip.is_broadcast() || ip.is_unspecified()
}

fn is_loopback_or_private_v6(ip: Ipv6Addr) -> bool {
    ip.is_loopback() || ip.is_unspecified() || (ip.segments()[0] & 0xfe00) == 0xfc00
}

/// Mirrors `capture_screenshot.py`'s output-path traversal guard: the
/// resolved output directory must start with either the current directory
/// or the home directory.
pub fn output_dir_allowed(resolved_output_dir: &str, cwd: &str, home: &str) -> bool {
    resolved_output_dir.starts_with(cwd) || resolved_output_dir.starts_with(home)
}

/// Mirrors the filename Python builds from the parsed URL's netloc:
/// `{netloc.replace('.', '_')}_{viewport}.png`. `netloc` here is taken as
/// `hostname` (the scripts never pass a URL with userinfo/port through this
/// path), matching the common case.
pub fn screenshot_filename(hostname: &str, viewport: &str) -> String {
    format!("{}_{}.png", hostname.replace('.', "_"), viewport)
}
