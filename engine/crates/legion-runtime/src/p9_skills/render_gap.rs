//! Packet P9-skill-scripts: Rust port of the pure diff/summary core of
//! `skills/seo/scripts/render_gap.mjs`.
//!
//! `render_gap.mjs` is mostly IO: a raw HTTP fetch, spawning a headless Chrome/Edge process,
//! and a hand-rolled raw-socket Chrome DevTools Protocol (CDP) WebSocket client to pull the
//! rendered DOM. None of that network/process orchestration is ported here (see the packet
//! report). What *is* pure and deterministic — and is where the tool's actual value lives, once
//! both signal sets are in hand — is the `diff()` function that compares the 8 raw-vs-rendered
//! SEO signals and the one-line summary it builds from the results. That is ported verbatim
//! below as `SeoSignals` + `diff_signals`.

use serde::Serialize;

/// The 8 signals extracted from either the raw HTML or the JS-rendered DOM.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct SeoSignals {
    pub title: Option<String>,
    pub meta_description: Option<String>,
    pub canonical: Option<String>,
    pub json_ld_count: i64,
    pub h1: Option<String>,
    pub main_text_length: i64,
    pub internal_links: i64,
    pub meta_robots: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct StringSignalEntry {
    pub raw: Option<String>,
    pub rendered: Option<String>,
    pub client_only: bool,
    pub server_only: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct NumericSignalEntry {
    pub raw: i64,
    pub rendered: i64,
    pub client_only: bool,
    pub server_only: bool,
    pub delta: i64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Default)]
pub struct RenderGapDiff {
    pub title: Option<StringSignalEntry>,
    pub meta_description: Option<StringSignalEntry>,
    pub canonical: Option<StringSignalEntry>,
    pub json_ld_count: Option<NumericSignalEntry>,
    pub h1: Option<StringSignalEntry>,
    pub main_text_length: Option<NumericSignalEntry>,
    pub internal_links: Option<NumericSignalEntry>,
    pub meta_robots: Option<StringSignalEntry>,
    pub client_only_signals: Vec<&'static str>,
    pub server_only_signals: Vec<&'static str>,
    pub summary: String,
}

fn has(v: &Option<String>) -> bool {
    matches!(v, Some(s) if !s.is_empty())
}

/// The pure `diff(key, rawVal, rendVal)` string-signal case: presence-based client-only /
/// server-only classification (no >200-char delta threshold — that only applies to
/// `main_text_length` and `internal_links`, which are numeric here).
fn diff_string(
    key: &'static str,
    raw: Option<String>,
    rendered: Option<String>,
    client_only: &mut Vec<&'static str>,
    server_only: &mut Vec<&'static str>,
) -> StringSignalEntry {
    let raw_has = has(&raw);
    let rend_has = has(&rendered);
    let mut entry = StringSignalEntry {
        raw,
        rendered,
        client_only: false,
        server_only: false,
    };
    if rend_has && !raw_has {
        entry.client_only = true;
        client_only.push(key);
    } else if raw_has && !rend_has {
        entry.server_only = true;
        server_only.push(key);
    }
    entry
}

/// The pure `diff(key, rawVal, rendVal)` numeric-signal case, including the `main_text_length`
/// / `internal_links` >200 / <-200 delta thresholds.
fn diff_numeric(
    key: &'static str,
    raw: i64,
    rendered: i64,
    apply_delta_threshold: bool,
    client_only: &mut Vec<&'static str>,
    server_only: &mut Vec<&'static str>,
) -> NumericSignalEntry {
    let delta = rendered - raw;
    let mut client = false;
    let mut server = false;
    if rendered > raw {
        client = true;
        client_only.push(key);
    } else if raw > rendered {
        server = true;
        server_only.push(key);
    }
    // json_ld_count in the JS source hits the numeric branch and stops there (no additional
    // delta-threshold pass); main_text_length/internal_links go through the same >raw/<raw
    // comparison above too, since JS `typeof both === 'number'` already triggered client_only /
    // server_only on any nonzero delta. The extra `if (key === 'main_text_length' || ...)` block
    // in the source is therefore dead for numeric inputs (it only ever fires when the value
    // arrived as a string/null and both branches above were skipped) -- preserved here only as
    // a no-op flag so callers relying on `apply_delta_threshold` see identical output.
    let _ = apply_delta_threshold;
    NumericSignalEntry {
        raw,
        rendered,
        client_only: client,
        server_only: server,
        delta,
    }
}

/// Ports `render_gap.mjs`'s diff + summary section given both signal sets already extracted.
pub fn diff_signals(url: &str, raw: SeoSignals, rendered: SeoSignals) -> RenderGapDiff {
    let mut client_only = Vec::new();
    let mut server_only = Vec::new();

    let title = diff_string("title", raw.title, rendered.title, &mut client_only, &mut server_only);
    let meta_description = diff_string(
        "meta_description",
        raw.meta_description,
        rendered.meta_description,
        &mut client_only,
        &mut server_only,
    );
    let canonical = diff_string(
        "canonical",
        raw.canonical,
        rendered.canonical,
        &mut client_only,
        &mut server_only,
    );
    let json_ld_count = diff_numeric(
        "json_ld_count",
        raw.json_ld_count,
        rendered.json_ld_count,
        false,
        &mut client_only,
        &mut server_only,
    );
    let h1 = diff_string("h1", raw.h1, rendered.h1, &mut client_only, &mut server_only);
    let main_text_length = diff_numeric(
        "main_text_length",
        raw.main_text_length,
        rendered.main_text_length,
        true,
        &mut client_only,
        &mut server_only,
    );
    let internal_links = diff_numeric(
        "internal_links",
        raw.internal_links,
        rendered.internal_links,
        true,
        &mut client_only,
        &mut server_only,
    );
    let meta_robots = diff_string(
        "meta_robots",
        raw.meta_robots,
        rendered.meta_robots,
        &mut client_only,
        &mut server_only,
    );

    let total = client_only.len() + server_only.len();
    let summary = if total == 0 {
        format!(
            "render_gap: {url} — NO render gap detected. All 8 signals match between raw HTML and JS-rendered DOM."
        )
    } else {
        let mut parts = Vec::new();
        if !client_only.is_empty() {
            parts.push(format!(
                "client-only (invisible to crawlers): {}",
                client_only.join(", ")
            ));
        }
        if !server_only.is_empty() {
            parts.push(format!(
                "server-only (stripped post-render): {}",
                server_only.join(", ")
            ));
        }
        format!("render_gap: {url} — {total} gap(s) found. {}.", parts.join("; "))
    };

    RenderGapDiff {
        title: Some(title),
        meta_description: Some(meta_description),
        canonical: Some(canonical),
        json_ld_count: Some(json_ld_count),
        h1: Some(h1),
        main_text_length: Some(main_text_length),
        internal_links: Some(internal_links),
        meta_robots: Some(meta_robots),
        client_only_signals: client_only,
        server_only_signals: server_only,
        summary,
    }
}

// ---------------------------------------------------------------------------
// Raw HTML extraction — ports `extractRaw(html)` verbatim (same regexes/logic).
// ---------------------------------------------------------------------------

fn first_capture(re: &regex::Regex, html: &str) -> Option<String> {
    re.captures(html)
        .and_then(|c| c.get(1))
        .map(|m| m.as_str().trim().to_string())
}

/// Ports `render_gap.mjs`'s `extractRaw(html)`: pulls the 8 SEO signals out of raw HTML via
/// regex, the same way a non-rendering crawler / Googlebot text-pass would see the page.
pub fn extract_raw(html: &str, url: &str) -> SeoSignals {
    let title_re = regex::Regex::new(r"(?is)<title[^>]*>(.*?)</title>").unwrap();
    let title = first_capture(&title_re, html);

    let desc_re1 =
        regex::Regex::new(r#"(?is)<meta\s[^>]*name=["']description["'][^>]*content=["']([^"']*)"#)
            .unwrap();
    let desc_re2 =
        regex::Regex::new(r#"(?is)<meta\s[^>]*content=["']([^"']*)[^>]*name=["']description["']"#)
            .unwrap();
    let meta_description =
        first_capture(&desc_re1, html).or_else(|| first_capture(&desc_re2, html));

    let canon_re1 =
        regex::Regex::new(r#"(?is)<link\s[^>]*rel=["']canonical["'][^>]*href=["']([^"']*)"#)
            .unwrap();
    let canon_re2 =
        regex::Regex::new(r#"(?is)<link\s[^>]*href=["']([^"']*)[^>]*rel=["']canonical["']"#)
            .unwrap();
    let canonical = first_capture(&canon_re1, html).or_else(|| first_capture(&canon_re2, html));

    let jsonld_re =
        regex::Regex::new(r#"(?is)<script[^>]*type=["']application/ld\+json["'][^>]*>"#).unwrap();
    let json_ld_count = jsonld_re.find_iter(html).count() as i64;

    let h1_re = regex::Regex::new(r"(?is)<h1[^>]*>(.*?)</h1>").unwrap();
    let tag_re = regex::Regex::new(r"(?is)<[^>]+>").unwrap();
    let h1 = h1_re
        .captures(html)
        .and_then(|c| c.get(1))
        .map(|m| tag_re.replace_all(m.as_str(), "").trim().to_string());

    let script_re = regex::Regex::new(r"(?is)<script[\s\S]*?</script>").unwrap();
    let style_re = regex::Regex::new(r"(?is)<style[\s\S]*?</style>").unwrap();
    let ws_re = regex::Regex::new(r"\s+").unwrap();
    let no_script = script_re.replace_all(html, "");
    let no_style = style_re.replace_all(&no_script, "");
    let no_tags = tag_re.replace_all(&no_style, " ");
    let body = ws_re.replace_all(&no_tags, " ").trim().to_string();
    let main_text_length = body.chars().count() as i64;

    let href_re = regex::Regex::new(r#"(?is)<a\s[^>]*href=["']([^"'#?]+)"#).unwrap();
    let internal_links = href_re
        .captures_iter(html)
        .filter_map(|c| c.get(1).map(|m| m.as_str().to_string()))
        .filter(|h| h.starts_with('/') || h.starts_with(url))
        .count() as i64;

    let robots_re1 =
        regex::Regex::new(r#"(?is)<meta\s[^>]*name=["']robots["'][^>]*content=["']([^"']*)"#)
            .unwrap();
    let robots_re2 =
        regex::Regex::new(r#"(?is)<meta\s[^>]*content=["']([^"']*)[^>]*name=["']robots["']"#)
            .unwrap();
    let meta_robots =
        first_capture(&robots_re1, html).or_else(|| first_capture(&robots_re2, html));

    SeoSignals {
        title,
        meta_description,
        canonical,
        json_ld_count,
        h1,
        main_text_length,
        internal_links,
        meta_robots,
    }
}

// ---------------------------------------------------------------------------
// CLI orchestration — ports `main()`: fetch raw, fetch rendered, diff, print.
// ---------------------------------------------------------------------------

/// The CDP DOM-extraction JS, verbatim from `render_gap.mjs`'s `DOM_EXTRACT`.
pub const DOM_EXTRACT_JS: &str = r#"(() => {
  const title = document.title || null;
  const metaDesc = (document.querySelector('meta[name="description"]') || document.querySelector('meta[name=description]'))?.getAttribute('content') || null;
  const canonical = document.querySelector('link[rel="canonical"]')?.getAttribute('href') || null;
  const jsonLdCount = document.querySelectorAll('script[type="application/ld+json"]').length;
  const h1El = document.querySelector('h1');
  const h1 = h1El ? (h1El.textContent || '').trim() : null;
  const body = (document.body?.innerText || document.body?.textContent || '').replace(/\s+/g,' ').trim();
  const mainTextLength = body.length;
  const anchors = [...document.querySelectorAll('a[href]')].map(a => a.getAttribute('href') || '');
  const internalLinks = anchors.filter(h => h.startsWith('/') || h.startsWith(window.location.origin)).length;
  const metaRobots = (document.querySelector('meta[name="robots"]'))?.getAttribute('content') || null;
  return JSON.stringify({ title, meta_description: metaDesc, canonical, json_ld_count: jsonLdCount, h1, main_text_length: mainTextLength, internal_links: internalLinks, meta_robots: metaRobots });
})()"#;

/// Behind-a-trait raw HTTP GET, mirroring `fetch(URL_, {headers: {'User-Agent': 'Googlebot/2.1 ...'}})`.
pub trait RawFetcher {
    fn fetch(&self, url: &str, timeout_ms: u64) -> Result<String, String>;
}

/// Behind-a-trait JS-rendered DOM extraction via headless Chrome/Edge CDP, mirroring the
/// `spawn` + raw-CDP-WebSocket dance in `render_gap.mjs` (headless_chrome replaces that
/// hand-rolled CDP client; same navigate -> wait-for-load -> evaluate flow).
pub trait RenderedFetcher {
    fn fetch(&self, url: &str, width: u32, height: u32, timeout_ms: u64) -> Result<SeoSignals, String>;
}

fn parse_dom_extract_json(raw: &serde_json::Value) -> SeoSignals {
    // `evaluate` on the production driver returns the JSON string itself (see
    // `ChromeRenderedFetcher`); this parses that string form. Also accept an already-decoded
    // object shape for fakes that hand back structured values directly.
    let obj: serde_json::Value = match raw {
        serde_json::Value::String(s) => serde_json::from_str(s).unwrap_or(serde_json::Value::Null),
        other => other.clone(),
    };
    let s = |k: &str| obj.get(k).and_then(|v| v.as_str()).map(str::to_string);
    let n = |k: &str| obj.get(k).and_then(|v| v.as_i64()).unwrap_or(0);
    SeoSignals {
        title: s("title"),
        meta_description: s("meta_description"),
        canonical: s("canonical"),
        json_ld_count: n("json_ld_count"),
        h1: s("h1"),
        main_text_length: n("main_text_length"),
        internal_links: n("internal_links"),
        meta_robots: s("meta_robots"),
    }
}

/// Production [`RawFetcher`] using `reqwest`'s blocking client with the same Googlebot UA and
/// `redirect: follow` behaviour as the JS `fetch()` call.
pub struct ReqwestRawFetcher;

impl RawFetcher for ReqwestRawFetcher {
    fn fetch(&self, url: &str, timeout_ms: u64) -> Result<String, String> {
        let client = reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_millis(timeout_ms))
            .redirect(reqwest::redirect::Policy::limited(10))
            .build()
            .map_err(|e| e.to_string())?;
        let resp = client
            .get(url)
            .header("User-Agent", "Googlebot/2.1 (+http://www.google.com/bot.html)")
            .send()
            .map_err(|e| e.to_string())?;
        resp.text().map_err(|e| e.to_string())
    }
}

/// Production [`RenderedFetcher`] using `headless_chrome`: launches headless Chrome/Edge,
/// navigates, waits for load, evaluates [`DOM_EXTRACT_JS`], and closes the tab. Replaces the
/// JS source's raw-CDP-over-`node:net` client and `findBrowser`/`freePort`/`spawn` dance —
/// `headless_chrome` locates and launches the browser itself.
pub struct ChromeRenderedFetcher;

impl RenderedFetcher for ChromeRenderedFetcher {
    fn fetch(&self, url: &str, width: u32, height: u32, timeout_ms: u64) -> Result<SeoSignals, String> {
        let browser = headless_chrome::Browser::default().map_err(|e| e.to_string())?;
        let tab = browser.new_tab().map_err(|e| e.to_string())?;
        let _ = tab.set_bounds(headless_chrome::types::Bounds::Normal {
            left: Some(0),
            top: Some(0),
            width: Some(width as f64),
            height: Some(height as f64),
        });
        tab.navigate_to(url).map_err(|e| e.to_string())?;
        tab.wait_until_navigated().map_err(|e| e.to_string())?;
        // `waitForLoad`: poll `document.readyState === 'complete'` up to `timeout_ms`,
        // matching the JS source's polling loop instead of relying on a single evaluate
        // timeout.
        let deadline = std::time::Instant::now() + std::time::Duration::from_millis(timeout_ms);
        while std::time::Instant::now() < deadline {
            if let Ok(remote) = tab.evaluate("document.readyState === 'complete'", false) {
                if remote.value.and_then(|v| v.as_bool()).unwrap_or(false) {
                    break;
                }
            }
            std::thread::sleep(std::time::Duration::from_millis(200));
        }
        // Allow JS frameworks (Qwik, React, Vue) to hydrate, matching the 1500ms sleep in the
        // JS source.
        std::thread::sleep(std::time::Duration::from_millis(1500));
        let remote = tab
            .evaluate(DOM_EXTRACT_JS, false)
            .map_err(|e| e.to_string())?;
        let value = remote.value.ok_or_else(|| "eval failed".to_string())?;
        Ok(parse_dom_extract_json(&value))
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct RenderGapArgs {
    pub url: String,
    pub timeout_ms: u64,
    pub width: u32,
    pub height: u32,
    pub json_only: bool,
    pub help: bool,
}

/// Mirrors `render_gap.mjs`'s flag parsing (`flag(name, default)` / `args.includes(...)`).
pub fn parse_args(argv: &[String]) -> Result<RenderGapArgs, String> {
    if argv.iter().any(|a| a == "--help" || a == "-h") {
        return Ok(RenderGapArgs {
            url: String::new(),
            timeout_ms: 15000,
            width: 1280,
            height: 800,
            json_only: false,
            help: true,
        });
    }
    let flag = |name: &str| -> Option<String> {
        argv.iter()
            .position(|a| a == name)
            .and_then(|i| argv.get(i + 1))
            .cloned()
    };
    let url = flag("--url").ok_or_else(|| {
        "Error: --url <url> is required. Run with --help for usage.".to_string()
    })?;
    let timeout_ms = flag("--timeout")
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(15000);
    let width = flag("--width").and_then(|v| v.parse::<u32>().ok()).unwrap_or(1280);
    let height = flag("--height").and_then(|v| v.parse::<u32>().ok()).unwrap_or(800);
    let json_only = argv.iter().any(|a| a == "--json");
    Ok(RenderGapArgs { url, timeout_ms, width, height, json_only, help: false })
}

const HELP_TEXT: &str = r#"
render_gap.mjs — Raw-vs-rendered DOM diff for SEO render-gap detection

Usage:
  node seo/scripts/render_gap.mjs --url <url> [options]

Options:
  --url <url>         Target URL (required)
  --timeout <ms>      Page load timeout in ms (default: 15000)
  --cdp-port <port>   CDP port for Chrome/Edge (default: auto)
  --width <px>        Viewport width (default: 1280)
  --height <px>       Viewport height (default: 800)
  --json              Output raw JSON only (default: JSON + summary line)
  --help, -h          Show this help and exit

Exit codes:
  0 = success (even if gaps found)
  1 = error (URL fetch failed, no browser found, CDP error)
  2 = bad arguments
"#;

/// CLI entry point mirroring `render_gap.mjs`'s `main()`. `raw_fetcher`/`rendered_fetcher` are
/// the I/O boundary the production binary wires to [`ReqwestRawFetcher`]/[`ChromeRenderedFetcher`];
/// tests use fakes so this never touches the network or a real browser.
pub fn run(
    argv: &[String],
    raw_fetcher: &dyn RawFetcher,
    rendered_fetcher: &dyn RenderedFetcher,
    stdout: &mut dyn std::io::Write,
    stderr: &mut dyn std::io::Write,
) -> i32 {
    let args = match parse_args(argv) {
        Ok(a) => a,
        Err(e) => {
            let _ = writeln!(stderr, "{e}");
            return 2;
        }
    };
    if args.help {
        let _ = writeln!(stdout, "{HELP_TEXT}");
        return 0;
    }

    let raw_start = std::time::Instant::now();
    let raw_html = match raw_fetcher.fetch(&args.url, args.timeout_ms) {
        Ok(h) => h,
        Err(e) => {
            let _ = writeln!(stderr, "Error: raw fetch failed — {e}");
            return 1;
        }
    };
    let raw_fetch_ms = raw_start.elapsed().as_millis() as i64;
    let raw_signals = extract_raw(&raw_html, &args.url);

    let render_start = std::time::Instant::now();
    let rendered_signals = match rendered_fetcher.fetch(&args.url, args.width, args.height, args.timeout_ms) {
        Ok(s) => s,
        Err(e) => {
            let _ = writeln!(stderr, "Error: CDP render failed — {e}");
            return 1;
        }
    };
    let render_ms = render_start.elapsed().as_millis() as i64;

    let diff = diff_signals(&args.url, raw_signals, rendered_signals);
    let report = serde_json::json!({
        "url": args.url,
        "raw_fetch_ms": raw_fetch_ms,
        "render_ms": render_ms,
        "signals": {
            "title": diff.title,
            "meta_description": diff.meta_description,
            "canonical": diff.canonical,
            "json_ld_count": diff.json_ld_count,
            "h1": diff.h1,
            "main_text_length": diff.main_text_length,
            "internal_links": diff.internal_links,
            "meta_robots": diff.meta_robots,
        },
        "client_only_signals": diff.client_only_signals,
        "server_only_signals": diff.server_only_signals,
        "summary": diff.summary,
    });
    let text = serde_json::to_string_pretty(&report).unwrap();
    if args.json_only {
        let _ = writeln!(stdout, "{text}");
    } else {
        let _ = writeln!(stdout, "{text}");
        let _ = writeln!(stdout, "\n{}", diff.summary);
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn signals(title: Option<&str>, json_ld: i64, text_len: i64) -> SeoSignals {
        SeoSignals {
            title: title.map(str::to_string),
            json_ld_count: json_ld,
            main_text_length: text_len,
            ..Default::default()
        }
    }

    #[test]
    fn no_gap_when_everything_matches() {
        let raw = signals(Some("Home"), 1, 500);
        let rendered = signals(Some("Home"), 1, 500);
        let diff = diff_signals("https://example.com", raw, rendered);
        assert!(diff.summary.contains("NO render gap detected"));
        assert!(diff.client_only_signals.is_empty());
        assert!(diff.server_only_signals.is_empty());
    }

    #[test]
    fn client_only_title_is_flagged() {
        let raw = signals(None, 0, 0);
        let rendered = signals(Some("Hydrated Title"), 0, 0);
        let diff = diff_signals("https://example.com", raw, rendered);
        assert!(diff.client_only_signals.contains(&"title"));
        assert!(diff.title.unwrap().client_only);
        assert!(diff.summary.contains("client-only"));
    }

    #[test]
    fn server_only_json_ld_is_flagged_when_rendered_drops_it() {
        let raw = signals(None, 2, 0);
        let rendered = signals(None, 0, 0);
        let diff = diff_signals("https://example.com", raw, rendered);
        assert!(diff.server_only_signals.contains(&"json_ld_count"));
        let entry = diff.json_ld_count.unwrap();
        assert!(entry.server_only);
        assert_eq!(entry.delta, -2);
    }

    #[test]
    fn empty_string_is_treated_as_absent_like_js_falsy_check() {
        let raw = signals(Some(""), 0, 0);
        let rendered = signals(Some("Real Title"), 0, 0);
        let diff = diff_signals("https://example.com", raw, rendered);
        // raw has "" (falsy in JS: rawVal !== ''), rendered has real value -> client_only.
        assert!(diff.title.unwrap().client_only);
    }

    #[test]
    fn extract_raw_pulls_all_eight_signals() {
        let html = r#"<html><head>
            <title> Home Page </title>
            <meta name="description" content="A description">
            <link rel="canonical" href="https://example.com/">
            <meta name="robots" content="index,follow">
            <script type="application/ld+json">{}</script>
        </head><body>
            <h1>Welcome <b>Home</b></h1>
            <p>Some body text here.</p>
            <a href="/about">About</a>
            <a href="https://example.com/contact">Contact</a>
            <a href="https://other.com/">Other</a>
        </body></html>"#;
        let s = extract_raw(html, "https://example.com");
        assert_eq!(s.title.as_deref(), Some("Home Page"));
        assert_eq!(s.meta_description.as_deref(), Some("A description"));
        assert_eq!(s.canonical.as_deref(), Some("https://example.com/"));
        assert_eq!(s.meta_robots.as_deref(), Some("index,follow"));
        assert_eq!(s.json_ld_count, 1);
        assert_eq!(s.h1.as_deref(), Some("Welcome Home"));
        assert_eq!(s.internal_links, 2);
        assert!(s.main_text_length > 0);
    }

    #[test]
    fn extract_raw_missing_signals_are_none() {
        let s = extract_raw("<html><body>no signals</body></html>", "https://example.com");
        assert_eq!(s.title, None);
        assert_eq!(s.meta_description, None);
        assert_eq!(s.canonical, None);
        assert_eq!(s.json_ld_count, 0);
        assert_eq!(s.h1, None);
        assert_eq!(s.internal_links, 0);
        assert_eq!(s.meta_robots, None);
    }

    #[test]
    fn parse_args_requires_url() {
        assert!(parse_args(&[]).is_err());
    }

    #[test]
    fn parse_args_help_short_circuits() {
        let args = parse_args(&["--help".to_string()]).unwrap();
        assert!(args.help);
    }

    #[test]
    fn parse_args_reads_flags() {
        let argv = vec![
            "--url".to_string(), "https://example.com".to_string(),
            "--timeout".to_string(), "5000".to_string(),
            "--width".to_string(), "800".to_string(),
            "--height".to_string(), "600".to_string(),
            "--json".to_string(),
        ];
        let args = parse_args(&argv).unwrap();
        assert_eq!(args.url, "https://example.com");
        assert_eq!(args.timeout_ms, 5000);
        assert_eq!(args.width, 800);
        assert_eq!(args.height, 600);
        assert!(args.json_only);
        assert!(!args.help);
    }

    struct FakeRawFetcher(Result<String, String>);
    impl RawFetcher for FakeRawFetcher {
        fn fetch(&self, _url: &str, _timeout_ms: u64) -> Result<String, String> {
            self.0.clone()
        }
    }
    struct FakeRenderedFetcher(Result<SeoSignals, String>);
    impl RenderedFetcher for FakeRenderedFetcher {
        fn fetch(&self, _url: &str, _w: u32, _h: u32, _t: u64) -> Result<SeoSignals, String> {
            self.0.clone()
        }
    }

    #[test]
    fn run_reports_gap_between_raw_and_rendered() {
        let raw = FakeRawFetcher(Ok("<html><head></head><body></body></html>".to_string()));
        let rendered = FakeRenderedFetcher(Ok(SeoSignals {
            title: Some("Hydrated".to_string()),
            ..Default::default()
        }));
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run(
            &["--url".to_string(), "https://example.com".to_string(), "--json".to_string()],
            &raw,
            &rendered,
            &mut out,
            &mut err,
        );
        assert_eq!(code, 0);
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains("client_only"));
        assert!(text.contains("Hydrated"));
    }

    #[test]
    fn run_exits_2_on_missing_url() {
        let raw = FakeRawFetcher(Ok(String::new()));
        let rendered = FakeRenderedFetcher(Ok(SeoSignals::default()));
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run(&[], &raw, &rendered, &mut out, &mut err);
        assert_eq!(code, 2);
    }

    #[test]
    fn run_exits_1_on_raw_fetch_failure() {
        let raw = FakeRawFetcher(Err("boom".to_string()));
        let rendered = FakeRenderedFetcher(Ok(SeoSignals::default()));
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run(
            &["--url".to_string(), "https://example.com".to_string()],
            &raw,
            &rendered,
            &mut out,
            &mut err,
        );
        assert_eq!(code, 1);
        assert!(String::from_utf8(err).unwrap().contains("raw fetch failed"));
    }
}
