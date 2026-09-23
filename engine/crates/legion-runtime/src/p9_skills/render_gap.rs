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
}
