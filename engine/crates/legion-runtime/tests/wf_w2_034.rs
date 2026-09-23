//! Integration tests for the w2_034 port of `skills/seo/scripts/{site_audit,
//! source_freshness, templated_metadata, youtube_search}.py`.
//!
//! NOTE: requires the integrator to wire `pub mod wf_port;` (if not already present)
//! and `pub mod w2_034;` into `legion_runtime::wf_port`
//! (see `engine/crates/legion-runtime/src/wf_port/mod.rs`) before this file will
//! compile/run.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::PathBuf;

use serde_json::Value;

use legion_runtime::wf_port::w2_034::date_math::Date;
use legion_runtime::wf_port::w2_034::site_audit::{
    build_report, discover_sitemaps, extract_sitemap_locs, is_asset_url, is_sitemap_index,
    normalize, parse, BrokenLink, FetchedPage, PageSignals,
};
use legion_runtime::wf_port::w2_034::source_freshness::{assess, exit_code};
use legion_runtime::wf_port::w2_034::templated_metadata::{analyze, rows_from_payload};
use legion_runtime::wf_port::w2_034::youtube_search::{
    classify_search_error, clamp_max_results, shape_channel_info, shape_comment,
    shape_search_video, shape_video_details, video_stats_from_item, VideoStats,
};

fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/wf_w2_034")
}

fn load_fixture(name: &str) -> Value {
    let path = fixtures_dir().join(name);
    let text = fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {path:?}: {e}"));
    serde_json::from_str(&text).unwrap_or_else(|e| panic!("parse {path:?}: {e}"))
}

// ---------------------------------------------------------------------------
// site_audit.py
// ---------------------------------------------------------------------------

#[test]
fn site_audit_normalize_matches_python_semantics() {
    assert_eq!(normalize("https://example.com"), "https://example.com/");
    assert_eq!(normalize("https://example.com/a"), "https://example.com/a/");
    assert_eq!(normalize("https://example.com/a/"), "https://example.com/a/");
    assert_eq!(normalize("https://example.com/a.html"), "https://example.com/a.html");
    assert_eq!(normalize("https://example.com/a?x=1"), "https://example.com/a?x=1");
}

#[test]
fn site_audit_asset_regex_matches_python_asset_re() {
    for u in [
        "https://example.com/x.css",
        "https://example.com/x.js?v=1",
        "https://example.com/x.PNG",
        "https://example.com/x.woff2",
    ] {
        assert!(is_asset_url(u), "{u} should be an asset URL");
    }
    assert!(!is_asset_url("https://example.com/page"));
}

#[test]
fn site_audit_parse_extracts_signals_from_fixture_html() {
    let html = fs::read_to_string(fixtures_dir().join("sample_page.html")).unwrap();
    let sig = parse(&html);
    assert_eq!(sig.title, "Fixture Page Title");
    assert_eq!(sig.meta_desc, "A fixture meta description for testing.");
    assert_eq!(sig.h1, vec!["Fixture Heading".to_string()]);
    assert_eq!(sig.canonical.as_deref(), Some("https://example.com/fixture"));
    assert!(sig.viewport);
    assert!(!sig.noindex);
    assert_eq!(sig.imgs, 2);
    assert_eq!(sig.img_no_alt, 1);
}

#[test]
fn site_audit_discover_and_parse_sitemap_locs() {
    let sitemaps = discover_sitemaps(
        "https://example.com",
        Some("User-agent: *\nSitemap: https://example.com/sm1.xml\n"),
    );
    assert_eq!(sitemaps, vec!["https://example.com/sm1.xml".to_string()]);

    let xml = fs::read_to_string(fixtures_dir().join("sample_sitemap.xml")).unwrap();
    assert!(!is_sitemap_index(&xml));
    let locs = extract_sitemap_locs(&xml);
    assert_eq!(
        locs,
        vec![
            "https://example.com/".to_string(),
            "https://example.com/about/".to_string(),
        ]
    );
}

#[test]
fn site_audit_build_report_flags_expected_issues_end_to_end() {
    let mut pages = HashMap::new();
    pages.insert(
        "https://example.com/thin".to_string(),
        FetchedPage {
            status: 200,
            x_robots_tag: None,
            signals: Some(PageSignals {
                title: "Short Page".to_string(),
                meta_desc: "d".repeat(60),
                h1: vec!["H".to_string()],
                canonical: Some("https://example.com/thin".to_string()),
                words: 50,
                imgs: 1,
                img_no_alt: 1,
                viewport: true,
                noindex: false,
                mixed_content: false,
            }),
        },
    );
    let sitemap: HashSet<String> = HashSet::new();
    let inlinks = HashMap::new();
    let mut broken = HashMap::new();
    broken.insert("https://example.com/dead".to_string(), BrokenLink { status: 404, inlinks: 2 });
    let redirects = HashMap::new();

    let report = build_report(&pages, &sitemap, "example.com", &inlinks, &broken, &redirects, |u| {
        u.split("://").nth(1).and_then(|r| r.split('/').next()).unwrap_or("").to_string()
    });

    assert!(report.issues["thin_content"][0].contains("(50w)"));
    assert!(report.issues["img_missing_alt"][0].contains("(1/1)"));
    assert_eq!(
        report.issues["broken_internal_links"][0],
        "[404] https://example.com/dead (from 2 pages)"
    );
    assert!(report.severity.errors.contains(&"broken_internal_links"));
    assert!(report.severity.warnings.contains(&"thin_content"));
}

// ---------------------------------------------------------------------------
// source_freshness.py
// ---------------------------------------------------------------------------

#[test]
fn source_freshness_assess_from_fixture_register() {
    let register = load_fixture("official_sources.json");
    let as_of = Date::parse("2026-09-23").unwrap();
    let report = assess(&register, as_of);
    assert_eq!(report.status, "fail");
    assert_eq!(exit_code(&report), 1);
    assert_eq!(report.due.iter().map(|r| r.id.as_str()).collect::<Vec<_>>(), vec!["stale-source"]);
    assert_eq!(report.invalid.len(), 1);
    assert_eq!(report.invalid[0].id.as_deref(), Some("bad-row"));
    assert_eq!(report.current_count, 1);
}

// ---------------------------------------------------------------------------
// templated_metadata.py
// ---------------------------------------------------------------------------

#[test]
fn templated_metadata_analyzes_fixture_pages() {
    let payload = load_fixture("templated_pages.json");
    let rows = rows_from_payload(&payload).unwrap();
    let result = analyze(&rows);
    assert_eq!(result.pages_checked, 4);
    assert_eq!(result.templated_pages, 3);
    assert_eq!(result.site_risk, "high");
    assert!(result.shared_cta_phrases.iter().any(|(phrase, _)| phrase == "learn more"));
}

// ---------------------------------------------------------------------------
// youtube_search.py
// ---------------------------------------------------------------------------

#[test]
fn youtube_search_shapes_fixture_api_responses() {
    let payload = load_fixture("youtube_video_item.json");
    let stats = video_stats_from_item(&payload);
    assert_eq!(stats.views, 12345);
    assert_eq!(stats.duration, "PT4M13S");

    let snippet = payload.get("snippet").cloned().unwrap();
    let shaped = shape_search_video("dQw4w9WgXcQ", &snippet, Some(&stats));
    assert_eq!(shaped.url, "https://www.youtube.com/watch?v=dQw4w9WgXcQ");
    assert_eq!(shaped.views, 12345);

    let details = shape_video_details("dQw4w9WgXcQ", &payload);
    assert_eq!(details.caption, "false");
    assert!(details.tags.contains(&"seo".to_string()));

    let default_stats = VideoStats::default();
    assert_eq!(default_stats.views, 0);

    let channel_payload = load_fixture("youtube_channel_item.json");
    let channel = shape_channel_info(&channel_payload);
    assert_eq!(channel.title, "Fixture Channel");

    let comment_payload = load_fixture("youtube_comment_thread.json");
    let comment = shape_comment(&comment_payload);
    assert_eq!(comment.author, "Fixture Commenter");

    assert_eq!(clamp_max_results(75), 50);
    assert!(classify_search_error("403 Forbidden").contains("access denied"));
}
