//! Port of `skills/seo/scripts/fetch_page.py`, packet r34.
//!
//! URL scheme validation, the default and Googlebot headers, the
//! private/loopback/reserved-IP SSRF check, and the metadata formatting
//! were ported first (pure, no I/O). This packet closes the remaining
//! gap: the actual HTTP fetch and the CLI entry point, both behind a
//! [`PageFetcher`] trait so tests never touch the network. DNS resolution
//! for the SSRF check is done via `std::net::ToSocketAddrs`, mirroring
//! Python's `socket.gethostbyname` (first resolved address).

use std::collections::BTreeMap;
use std::io::Write;
use std::net::{IpAddr, ToSocketAddrs};
use std::time::Duration;

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

/// Result of one fetch, mirroring the Python `result` dict shape used by
/// `fetch_page()` / `main()`.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct FetchOutcome {
    pub url: String,
    pub status_code: Option<u16>,
    pub content: Option<String>,
    pub redirect_chain: Vec<String>,
    pub redirect_details: Vec<RedirectDetail>,
    pub error: Option<String>,
}

/// Behind-a-trait I/O boundary for the real GET request, so `run()` is
/// testable with a fake. Mirrors `session.get(url, headers=..., timeout=...,
/// allow_redirects=...)`.
pub trait PageFetcher {
    fn get(
        &self,
        url: &str,
        headers: &BTreeMap<&'static str, String>,
        timeout: Duration,
        follow_redirects: bool,
    ) -> FetchOutcome;
}

/// Real `reqwest::blocking` implementation of [`PageFetcher`].
pub struct ReqwestFetcher;

impl PageFetcher for ReqwestFetcher {
    fn get(
        &self,
        url: &str,
        headers: &BTreeMap<&'static str, String>,
        timeout: Duration,
        follow_redirects: bool,
    ) -> FetchOutcome {
        let policy = if follow_redirects {
            reqwest::redirect::Policy::limited(5)
        } else {
            reqwest::redirect::Policy::none()
        };
        let client = match reqwest::blocking::Client::builder()
            .timeout(timeout)
            .redirect(policy)
            .build()
        {
            Ok(c) => c,
            Err(e) => {
                return FetchOutcome {
                    url: url.to_string(),
                    error: Some(format!("Request failed: {e}")),
                    ..Default::default()
                }
            }
        };
        let mut req = client.get(url);
        for (k, v) in headers {
            req = req.header(*k, v.as_str());
        }
        match req.send() {
            Ok(resp) => {
                let final_url = resp.url().to_string();
                let status = resp.status().as_u16();
                let content = resp.text().unwrap_or_default();
                FetchOutcome {
                    url: final_url,
                    status_code: Some(status),
                    content: Some(content),
                    redirect_chain: Vec::new(),
                    redirect_details: Vec::new(),
                    error: None,
                }
            }
            Err(e) => {
                let msg = if e.is_timeout() {
                    format!("Request timed out after {} seconds", timeout.as_secs())
                } else if e.is_redirect() {
                    "Too many redirects (max 5)".to_string()
                } else if e.is_connect() {
                    format!("Connection error: {e}")
                } else {
                    format!("Request failed: {e}")
                };
                FetchOutcome {
                    url: url.to_string(),
                    error: Some(msg),
                    ..Default::default()
                }
            }
        }
    }
}

/// Mirrors `socket.gethostbyname(hostname)`: resolves `hostname` and
/// returns the first address, or `None` on failure (matching Python's
/// `except (socket.gaierror, ValueError): pass`, which lets the request
/// proceed).
pub fn resolve_hostname(hostname: &str) -> Option<IpAddr> {
    (hostname, 0)
        .to_socket_addrs()
        .ok()
        .and_then(|mut it| it.next())
        .map(|addr| addr.ip())
}

/// End-to-end port of `fetch_page()`: validates the URL, runs the SSRF
/// check, builds headers, and calls the fetcher. `output` is written when
/// `Some`, mirroring `--output`; both cases return the process exit code.
#[allow(clippy::too_many_arguments)]
pub fn fetch_page(
    fetcher: &dyn PageFetcher,
    url: &str,
    timeout: Duration,
    follow_redirects: bool,
    user_agent: Option<&str>,
) -> FetchOutcome {
    let normalized = match normalize_and_validate_scheme(url) {
        Ok(u) => u,
        Err(e) => {
            return FetchOutcome {
                url: url.to_string(),
                error: Some(e),
                ..Default::default()
            }
        }
    };

    let hostname = normalized
        .split("://")
        .nth(1)
        .and_then(|rest| rest.split(['/', '?', '#']).next())
        .and_then(|authority| authority.rsplit_once('@').map_or(Some(authority), |(_, h)| Some(h)))
        .and_then(|host_port| {
            if let Some(stripped) = host_port.strip_prefix('[') {
                stripped.split(']').next()
            } else {
                host_port.split(':').next()
            }
        })
        .unwrap_or("");

    if let Some(ip) = resolve_hostname(hostname) {
        if let Err(e) = check_ssrf(Some(ip)) {
            return FetchOutcome {
                url: normalized,
                error: Some(e),
                ..Default::default()
            };
        }
    }

    let headers = default_headers(user_agent);
    fetcher.get(&normalized, &headers, timeout, follow_redirects)
}

/// CLI arg bundle mirroring `argparse` in `fetch_page.py`'s `main()`.
#[derive(Debug, Clone, Default)]
struct Args {
    url: Option<String>,
    output: Option<String>,
    timeout: u64,
    no_redirects: bool,
    user_agent: Option<String>,
    googlebot: bool,
}

fn parse_args(args: &[String]) -> Result<Args, String> {
    let mut out = Args {
        timeout: 30,
        ..Default::default()
    };
    let mut i = 0;
    while i < args.len() {
        let a = args[i].as_str();
        match a {
            "--output" | "-o" => {
                i += 1;
                out.output = Some(args.get(i).ok_or("--output requires a value")?.clone());
            }
            "--timeout" | "-t" => {
                i += 1;
                out.timeout = args
                    .get(i)
                    .ok_or("--timeout requires a value")?
                    .parse()
                    .map_err(|_| "--timeout must be an integer".to_string())?;
            }
            "--no-redirects" => out.no_redirects = true,
            "--user-agent" => {
                i += 1;
                out.user_agent = Some(args.get(i).ok_or("--user-agent requires a value")?.clone());
            }
            "--googlebot" => out.googlebot = true,
            other if !other.starts_with('-') => out.url = Some(other.to_string()),
            other => return Err(format!("unrecognized argument: {other}")),
        }
        i += 1;
    }
    out.url.clone().ok_or("the following arguments are required: url")?;
    Ok(out)
}

/// Port of `fetch_page.py`'s `main()`, parameterized over the fetcher and
/// stdout/stderr sinks so it is testable without touching real I/O.
/// Returns the process exit code, matching `sys.exit(1)` on error and the
/// implicit `0` otherwise.
pub fn run(
    args: &[String],
    fetcher: &dyn PageFetcher,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> i32 {
    let parsed = match parse_args(args) {
        Ok(p) => p,
        Err(e) => {
            let _ = writeln!(stderr, "{e}");
            return 2;
        }
    };

    let ua = if parsed.googlebot {
        Some(GOOGLEBOT_USER_AGENT.to_string())
    } else {
        parsed.user_agent.clone()
    };

    let result = fetch_page(
        fetcher,
        parsed.url.as_deref().unwrap_or(""),
        Duration::from_secs(parsed.timeout),
        !parsed.no_redirects,
        ua.as_deref(),
    );

    if let Some(err) = &result.error {
        let _ = writeln!(stderr, "Error: {err}");
        return 1;
    }

    let content = result.content.clone().unwrap_or_default();
    if let Some(path) = &parsed.output {
        if let Err(e) = std::fs::write(path, &content) {
            let _ = writeln!(stderr, "Error: {e}");
            return 1;
        }
        let _ = writeln!(stdout, "Saved to {path}");
    } else {
        let _ = writeln!(stdout, "{content}");
    }

    let meta = format_metadata(
        &result.url,
        result.status_code.unwrap_or(0),
        &result.redirect_details,
        &result.redirect_chain,
    );
    let _ = writeln!(stderr, "{meta}");

    0
}
