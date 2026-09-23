//! Integration tests for the ported `wf_port::w2_032` module, mirroring
//! `skills/seo/scripts/{pagespeed_check,parse_html,provider_registry,
//! query_ownership,question_inventory}.py`.
//!
//! Fixtures live under `tests/fixtures/wf_w2_032/`.

use std::collections::HashSet;
use std::fs;
use std::path::PathBuf;

use legion_runtime::wf_port::w2_032::pagespeed_check::{
    crux_target_is_origin, parse_crux_response, parse_psi_response, rate_metric, validate_url,
};
use legion_runtime::wf_port::w2_032::parse_html::{
    classify_link, extract_open_graph, extract_twitter_card, parse_json_ld, resolve_href,
    word_count, LinkClass,
};
use legion_runtime::wf_port::w2_032::provider_registry::{choose, discover, load_registry, ChooseResult};
use legion_runtime::wf_port::w2_032::query_ownership::{build_report as ownership_report, rows_from_payload as ownership_rows};
use legion_runtime::wf_port::w2_032::question_inventory::{build_report as inventory_report, rows_from_payload as inventory_rows};

fn fixture(name: &str) -> serde_json::Value {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("tests/fixtures/wf_w2_032");
    p.push(name);
    let text = fs::read_to_string(&p).unwrap_or_else(|e| panic!("reading {p:?}: {e}"));
    serde_json::from_str(&text).unwrap_or_else(|e| panic!("parsing {p:?}: {e}"))
}

// ---------------------------------------------------------------------------
// pagespeed_check.py
// ---------------------------------------------------------------------------

#[test]
fn pagespeed_rate_metric_and_url_validation() {
    assert_eq!(rate_metric("interaction_to_next_paint", 150.0), "good");
    assert_eq!(rate_metric("interaction_to_next_paint", 600.0), "poor");
    assert!(validate_url("https://example.com/"));
    assert!(!validate_url("http://192.168.0.1/"));
    assert!(crux_target_is_origin("https://example.com"));
    assert!(!crux_target_is_origin("https://example.com/page?x=1"));
}

#[test]
fn pagespeed_parses_fixture_psi_response() {
    let data = fixture("psi_response.json");
    let result = parse_psi_response(&data, "https://example.com", "mobile");

    assert_eq!(result.lighthouse_scores.get("performance"), Some(&76));
    assert_eq!(result.lighthouse_scores.get("seo"), Some(&90));

    // Two opportunities, sorted by savings_ms descending.
    assert_eq!(result.opportunities.len(), 2);
    assert_eq!(result.opportunities[0].id, "unused-javascript");
    assert_eq!(result.opportunities[1].id, "render-blocking-resources");

    // color-contrast scored 0.5 (<0.9) and is an accessibility auditRef.
    assert_eq!(result.accessibility_audits.len(), 1);
    assert_eq!(result.accessibility_audits[0].id, "color-contrast");

    // Both SEO audit refs passed (score 1.0 >= 0.9).
    assert_eq!(result.seo_audits.len(), 2);
    assert!(result.seo_audits.iter().all(|a| a.pass));

    // color-contrast (score 0.5, not an opportunity) lands in failed_audits.
    assert!(result.failed_audits.iter().any(|a| a.id == "color-contrast"));
    // unused-javascript is an opportunity, so it must NOT also appear in failed_audits.
    assert!(!result.failed_audits.iter().any(|a| a.id == "unused-javascript"));

    let (cls_val, cls_rating, _) = result.field_metrics.get("url_cumulative_layout_shift").unwrap();
    assert_eq!(*cls_val, 0.09);
    assert_eq!(cls_rating, "fast");
}

#[test]
fn pagespeed_parses_crux_record_with_string_cls() {
    let record = serde_json::json!({
        "collectionPeriod": {
            "firstDate": {"year": 2026, "month": 2, "day": 1},
            "lastDate": {"year": 2026, "month": 2, "day": 28}
        },
        "metrics": {
            "cumulative_layout_shift": {"percentiles": {"p75": "0.22"}},
            "interaction_to_next_paint": {"percentiles": {"p75": 550}}
        }
    });
    let result = parse_crux_response(&record, "https://example.com", Some("PHONE"));
    assert_eq!(result.form_factor, "PHONE");
    let cls = result.metrics.get("cumulative_layout_shift").unwrap();
    assert_eq!(cls.p75, 0.22);
    assert_eq!(cls.rating, "needs-improvement");
    let inp = result.metrics.get("interaction_to_next_paint").unwrap();
    assert_eq!(inp.rating, "poor");
}

// ---------------------------------------------------------------------------
// parse_html.py
// ---------------------------------------------------------------------------

#[test]
fn parse_html_word_count_and_link_resolution() {
    assert_eq!(word_count("The quick brown fox jumps."), 5);
    assert_eq!(resolve_href("https://example.com/blog/post", "../about"), "https://example.com/blog/../about");
    let (url, class) = classify_link("https://example.com/blog/", "/pricing").unwrap();
    assert_eq!(url, "https://example.com/pricing");
    assert_eq!(class, LinkClass::Internal);
    assert!(classify_link("https://example.com", "#section").is_none());
}

#[test]
fn parse_html_json_ld_and_meta_extraction() {
    let schema = parse_json_ld(vec![r#"{"@type":"WebPage","name":"Home"}"#, "{broken"]);
    assert_eq!(schema.len(), 1);

    let og = extract_open_graph(vec![("og:title", "Home"), ("description", "skip me")]);
    assert_eq!(og.get("og:title").unwrap(), "Home");

    let tw = extract_twitter_card(vec![("twitter:card", "summary_large_image")]);
    assert_eq!(tw.get("twitter:card").unwrap(), "summary_large_image");
}

// ---------------------------------------------------------------------------
// provider_registry.py
// ---------------------------------------------------------------------------

#[test]
fn provider_registry_discover_and_choose_from_fixture() {
    let text = fs::read_to_string(
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/wf_w2_032/provider_registry.json"),
    )
    .unwrap();
    let registry = load_registry(&text).unwrap();

    std::env::remove_var("WF_W2_032_GSC_TOKEN");
    std::env::remove_var("WF_W2_032_PAID_KEY");

    let discovery = discover(&registry, &HashSet::new());
    assert_eq!(discovery.providers.len(), 4);
    assert_eq!(discovery.providers["local_parser"].availability, "available");
    assert_eq!(discovery.providers["gsc_api"].availability, "unavailable");

    // No first-party evidence available, paid disallowed, manual allowed -> manual export.
    let result = choose(&registry, "queries", &HashSet::new(), false, true);
    match result {
        ChooseResult::Selected { provider, .. } => assert_eq!(provider, "manual_gsc_export"),
        other => panic!("expected manual_gsc_export selection, got {other:?}"),
    }

    // Set the first-party token: it now outranks the manual export.
    std::env::set_var("WF_W2_032_GSC_TOKEN", "1");
    let result = choose(&registry, "queries", &HashSet::new(), false, true);
    match result {
        ChooseResult::Selected { provider, .. } => assert_eq!(provider, "gsc_api"),
        other => panic!("expected gsc_api selection, got {other:?}"),
    }
    std::env::remove_var("WF_W2_032_GSC_TOKEN");
}

// ---------------------------------------------------------------------------
// query_ownership.py
// ---------------------------------------------------------------------------

#[test]
fn query_ownership_classifies_fixture_rows() {
    let payload = fixture("gsc_rows.json");
    let rows = ownership_rows(&payload).unwrap();
    let report = ownership_report(&rows);
    assert_eq!(report.query_count, 4);

    let seo = report
        .ownership
        .iter()
        .find(|o| o.query == "how does seo work")
        .unwrap();
    assert_eq!(seo.stability, "high");
    assert_eq!(seo.classification, "stable owner");

    let tool = report
        .ownership
        .iter()
        .find(|o| o.query == "best seo tool")
        .unwrap();
    // 40/(40+5) ~ 0.888 -> benign overlap.
    assert_eq!(tool.classification, "benign overlap");
    assert_eq!(tool.dominant_url.as_deref(), Some("/tools/a"));
}

// ---------------------------------------------------------------------------
// question_inventory.py
// ---------------------------------------------------------------------------

#[test]
fn question_inventory_builds_from_fixture_rows() {
    let payload = fixture("gsc_rows.json");
    let rows = inventory_rows(&payload).unwrap();
    let report = inventory_report(&rows, &["Is there a free trial?".to_string()]);

    // "how does seo work" is a question; "seo pricing", "best seo tool", "site login"
    // are not (no leading interrogative, no trailing '?'). Plus the supplied extra.
    assert_eq!(report.count, 2);
    let q = report
        .questions
        .iter()
        .find(|q| q.question == "How does seo work?")
        .unwrap();
    assert_eq!(q.source, "gsc");
    assert_eq!(q.clicks, Some(20.0));
    assert_eq!(q.intended_page.as_deref(), Some("/guides/seo"));

    let extra = report
        .questions
        .iter()
        .find(|q| q.question == "Is there a free trial?")
        .unwrap();
    assert_eq!(extra.source, "supplied");
    assert_eq!(extra.intent, "transactional");
}
