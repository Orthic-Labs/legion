//! Integration tests for the ported `wf_port::w2_028` module, mirroring
//! `skills/seo/scripts/{ai_visibility_import,analyze_visual,
//! bing_webmaster,capture_screenshot,checklist_compiler}.py`.

use legion_runtime::wf_port::w2_028::ai_visibility_import::{
    bing, google, load_rows_from_csv, load_rows_from_json, num, value,
};
use legion_runtime::wf_port::w2_028::bing_webmaster::{
    build_request_url, http_error_result, parse_response_body, require_key, resolve_dispatch,
    subcommand_method, url_encode_query_component, Dispatch, MISSING_KEY_MESSAGE,
};
use legion_runtime::wf_port::w2_028::checklist_compiler::{
    compile_text, digest, semantic_diff, slug, verify,
};
use legion_runtime::wf_port::w2_028::web_page_probe::{
    check_ssrf, is_blocked_ip, normalize_url, output_dir_allowed, screenshot_filename,
    viewport_by_name, VIEWPORTS,
};

use serde_json::json;

// ---------------------------------------------------------------------------
// ai_visibility_import.py
// ---------------------------------------------------------------------------

#[test]
fn value_is_case_insensitive_and_returns_first_match() {
    let row = json!({"Date": "2026-01-01", "Page": "/x"}).as_object().unwrap().clone();
    assert_eq!(
        value(&row, &["date", "day"]).unwrap().as_str().unwrap(),
        "2026-01-01"
    );
    assert!(value(&row, &["missing"]).is_none());
}

#[test]
fn num_strips_commas_and_percent_and_rejects_junk() {
    let v = json!("1,234");
    assert_eq!(num(Some(&v)), Some(1234.0));
    let v = json!("12.5%");
    assert_eq!(num(Some(&v)), Some(12.5));
    let v = json!("");
    assert_eq!(num(Some(&v)), None);
    let v = json!("not-a-number");
    assert_eq!(num(Some(&v)), None);
    assert_eq!(num(None), None);
}

#[test]
fn google_maps_rows_and_carries_limitations() {
    let rows = vec![json!({
        "Date": "2026-01-01",
        "Page": "/pricing",
        "Country": "us",
        "Device": "MOBILE",
        "AI Impressions": "42",
    })
    .as_object()
    .unwrap()
    .clone()];
    let result = google(&rows, "export.csv");
    assert_eq!(result.provider, "google");
    assert_eq!(result.surface, "search_console_generative_ai");
    assert_eq!(result.measurement, "impressions");
    assert_eq!(result.rows.len(), 1);
    assert_eq!(result.rows[0].page.as_deref(), Some("/pricing"));
    assert_eq!(result.rows[0].impressions, Some(42.0));
    assert_eq!(result.limitations.len(), 2);
}

#[test]
fn bing_maps_rows_with_cited_page_alias() {
    let rows = vec![json!({
        "Cited Page": "/docs",
        "Grounding Query": "how to x",
        "Citations": "7",
        "Citation Share": "3.5%",
    })
    .as_object()
    .unwrap()
    .clone()];
    let result = bing(&rows, "export.json");
    assert_eq!(result.provider, "bing");
    assert_eq!(result.measurement, "citations");
    assert_eq!(result.rows[0].page.as_deref(), Some("/docs"));
    assert_eq!(result.rows[0].citations, Some(7.0));
    assert_eq!(result.rows[0].citation_share, Some(3.5));
    assert_eq!(result.limitations.len(), 3);
}

#[test]
fn load_rows_from_json_accepts_bare_array() {
    let rows = load_rows_from_json(r#"[{"a": 1}, {"a": 2}]"#).unwrap();
    assert_eq!(rows.len(), 2);
}

#[test]
fn load_rows_from_json_accepts_wrapped_rows_key() {
    let rows = load_rows_from_json(r#"{"rows": [{"a": 1}]}"#).unwrap();
    assert_eq!(rows.len(), 1);
}

#[test]
fn load_rows_from_json_rejects_bad_shape() {
    let err = load_rows_from_json(r#"{"nope": 1}"#).unwrap_err();
    assert!(err.contains("rows/data/items"));
}

#[test]
fn load_rows_from_csv_matches_dict_reader_behavior() {
    let csv = "Date,Page,Impressions\n2026-01-01,/a,10\n2026-01-02,/b,20\n";
    let rows = load_rows_from_csv(csv);
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0].get("Page").unwrap().as_str().unwrap(), "/a");
    assert_eq!(rows[1].get("Impressions").unwrap().as_str().unwrap(), "20");
}

#[test]
fn load_rows_from_csv_handles_quoted_commas() {
    let csv = "Page,Note\n\"/a, with comma\",\"quote \"\"inside\"\"\"\n";
    let rows = load_rows_from_csv(csv);
    assert_eq!(rows.len(), 1);
    assert_eq!(
        rows[0].get("Page").unwrap().as_str().unwrap(),
        "/a, with comma"
    );
    assert_eq!(
        rows[0].get("Note").unwrap().as_str().unwrap(),
        "quote \"inside\""
    );
}

// ---------------------------------------------------------------------------
// bing_webmaster.py
// ---------------------------------------------------------------------------

#[test]
fn subcommand_method_matches_python_dict() {
    assert_eq!(subcommand_method("traffic"), Some("GetRankAndTrafficStats"));
    assert_eq!(subcommand_method("queries"), Some("GetQueryStats"));
    assert_eq!(subcommand_method("pages"), Some("GetPageStats"));
    assert_eq!(subcommand_method("links"), Some("GetUrlLinks"));
    assert_eq!(subcommand_method("crawl"), Some("GetCrawlIssues"));
    assert_eq!(subcommand_method("submit"), None);
}

#[test]
fn require_key_reports_missing_key_message() {
    assert_eq!(require_key(Some("abc123")).unwrap(), "abc123");
    let err = require_key(None).unwrap_err();
    assert_eq!(err, MISSING_KEY_MESSAGE);
    let err = require_key(Some("")).unwrap_err();
    assert_eq!(err, MISSING_KEY_MESSAGE);
}

#[test]
fn url_encode_query_component_matches_urlencode_defaults() {
    assert_eq!(url_encode_query_component("https://example.com/"), "https%3A%2F%2Fexample.com%2F");
    assert_eq!(url_encode_query_component("a b"), "a+b");
    assert_eq!(url_encode_query_component("abc_-.~123"), "abc_-.~123");
}

#[test]
fn build_request_url_drops_none_params_and_orders_apikey_first() {
    let url = build_request_url(
        "GetQueryStats",
        "KEY1",
        &[("siteUrl", Some("https://example.com/")), ("extra", None)],
    );
    assert_eq!(
        url,
        "https://ssl.bing.com/webmaster/api.svc/json/GetQueryStats?apikey=KEY1&siteUrl=https%3A%2F%2Fexample.com%2F"
    );
}

#[test]
fn parse_response_body_unwraps_d_envelope() {
    let result = parse_response_body("GetPageStats", r#"{"d": [1, 2, 3]}"#);
    assert_eq!(result.error, None);
    assert_eq!(result.d, Some(json!([1, 2, 3])));
}

#[test]
fn parse_response_body_passes_through_missing_d() {
    let result = parse_response_body("GetPageStats", r#"{"other": 1}"#);
    assert_eq!(result.d, Some(json!({"other": 1})));
}

#[test]
fn parse_response_body_reports_non_json() {
    let result = parse_response_body("GetPageStats", "not json");
    assert_eq!(result.error.as_deref(), Some("non-JSON response"));
    assert!(result.is_error());
}

#[test]
fn http_error_result_matches_python_shape() {
    let result = http_error_result("SubmitUrl", 401, "unauthorized body");
    assert_eq!(result.error.as_deref(), Some("HTTP 401"));
    assert_eq!(result.detail.as_deref(), Some("unauthorized body"));
    assert!(result.is_error());
}

#[test]
fn resolve_dispatch_submit_needs_site_and_url() {
    let err = resolve_dispatch("submit", None, Some("https://example.com/"), None).unwrap_err();
    assert_eq!(err, "submit needs --site and --url");

    let d = resolve_dispatch(
        "submit",
        None,
        Some("https://example.com/"),
        Some("https://example.com/new-page/"),
    )
    .unwrap();
    match d {
        Dispatch::Post { method, body } => {
            assert_eq!(method, "SubmitUrl");
            assert_eq!(body.get("siteUrl").unwrap(), "https://example.com/");
            assert_eq!(body.get("url").unwrap(), "https://example.com/new-page/");
        }
        _ => panic!("expected Post"),
    }
}

#[test]
fn resolve_dispatch_raw_needs_method_name() {
    let err = resolve_dispatch("raw", None, Some("https://example.com/"), None).unwrap_err();
    assert_eq!(err, "raw needs a method name");

    let d = resolve_dispatch("raw", Some("GetSomething"), Some("https://x/"), None).unwrap();
    match d {
        Dispatch::Get { method, params } => {
            assert_eq!(method, "GetSomething");
            assert_eq!(params.get("siteUrl").unwrap(), "https://x/");
        }
        _ => panic!("expected Get"),
    }
}

#[test]
fn resolve_dispatch_known_subcommand_needs_site() {
    let err = resolve_dispatch("traffic", None, None, None).unwrap_err();
    assert_eq!(err, "traffic needs --site");

    let d = resolve_dispatch("traffic", None, Some("https://x/"), None).unwrap();
    match d {
        Dispatch::Get { method, params } => {
            assert_eq!(method, "GetRankAndTrafficStats");
            assert_eq!(params.get("siteUrl").unwrap(), "https://x/");
        }
        _ => panic!("expected Get"),
    }
}

#[test]
fn resolve_dispatch_unknown_command_errors() {
    let err = resolve_dispatch("bogus", None, None, None).unwrap_err();
    assert_eq!(err, "unknown command 'bogus'");
}

// ---------------------------------------------------------------------------
// checklist_compiler.py
// ---------------------------------------------------------------------------

#[test]
fn digest_matches_known_sha256() {
    // sha256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
    assert_eq!(
        digest(""),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
}

#[test]
fn slug_collapses_and_defaults_to_control() {
    assert_eq!(slug("Hello, World!", 56), "hello-world");
    assert_eq!(slug("!!!", 56), "control");
    assert_eq!(slug("aaaaaaaaaa", 5), "aaaaa");
}

#[test]
fn compile_text_assigns_phase_scoped_ids_and_heading_path() {
    let text = "\
# Site\n\
## PHASE 1: Foundations\n\
### Crawlability\n\
- [ ] Submit sitemap\n\
- [ ] Fix robots.txt\n\
## PHASE 2: Content\n\
- [ ] Submit sitemap\n";
    let out = compile_text(text, "checklist.md");
    assert_eq!(out.candidate_count, 3);
    assert_eq!(out.line_count, text.lines().count());
    assert_eq!(out.sha256, digest(text));

    let first = &out.candidates[0];
    assert_eq!(first.candidate_id, "phase-01.submit-sitemap");
    assert_eq!(first.phase, Some(1));
    assert_eq!(
        first.heading_path,
        vec!["Site".to_string(), "PHASE 1: Foundations".to_string(), "Crawlability".to_string()]
    );
    assert_eq!(first.promotion_state, "candidate");

    // Same text under a different phase gets a distinct id (no -2 suffix
    // needed since the base differs by phase).
    let third = &out.candidates[2];
    assert_eq!(third.candidate_id, "phase-02.submit-sitemap");
}

#[test]
fn compile_text_dedupes_repeated_text_within_same_scope() {
    let text = "\
## PHASE 1: X\n\
- [ ] Do the thing\n\
- [ ] Do the thing\n";
    let out = compile_text(text, "c.md");
    assert_eq!(out.candidates[0].candidate_id, "phase-01.do-the-thing");
    assert_eq!(out.candidates[1].candidate_id, "phase-01.do-the-thing-2");
}

#[test]
fn verify_reports_pass_and_fail() {
    let text = "line one\nline two\n";
    let sha = digest(text);
    let (ok, got_sha, got_lines) = verify(text, &sha, 2);
    assert!(ok);
    assert_eq!(got_sha, sha);
    assert_eq!(got_lines, 2);

    let (ok, _, _) = verify(text, &sha, 3);
    assert!(!ok);
}

#[test]
fn semantic_diff_reports_added_removed_and_changed() {
    let old_text = "## PHASE 1: X\n- [ ] Keep me\n- [ ] Remove me\n";
    let new_text = "## PHASE 1: X\n- [ ] Keep me\n- [ ] Add me\n";
    let old = compile_text(old_text, "c.md");
    let new = compile_text(new_text, "c.md");
    let d = semantic_diff(&old, &new);
    assert_eq!(d.added.len(), 1);
    assert_eq!(d.added[0].text, "Add me");
    assert_eq!(d.removed.len(), 1);
    assert_eq!(d.removed[0].text, "Remove me");
    assert_eq!(d.changed.len(), 0);
}

#[test]
fn semantic_diff_reports_changed_heading_path() {
    let old_text = "## PHASE 1: X\n- [ ] Keep me\n";
    let new_text = "## PHASE 1: Y\n- [ ] Keep me\n";
    // Different heading text keeps the same slug base (phase-01.keep-me).
    let old = compile_text(old_text, "c.md");
    let new = compile_text(new_text, "c.md");
    let d = semantic_diff(&old, &new);
    assert_eq!(d.changed.len(), 1);
    assert_eq!(d.changed[0].id, "phase-01.keep-me");
}

// ---------------------------------------------------------------------------
// capture_screenshot.py / analyze_visual.py (web_page_probe)
// ---------------------------------------------------------------------------

#[test]
fn viewport_table_matches_python_presets() {
    assert_eq!(VIEWPORTS.len(), 4);
    let mobile = viewport_by_name("mobile").unwrap();
    assert_eq!((mobile.width, mobile.height), (375, 812));
    let desktop = viewport_by_name("desktop").unwrap();
    assert_eq!((desktop.width, desktop.height), (1920, 1080));
    assert!(viewport_by_name("ultrawide").is_none());
}

#[test]
fn normalize_url_adds_https_scheme_when_missing() {
    let (url, parsed) = normalize_url("example.com/page").unwrap();
    assert_eq!(url, "https://example.com/page");
    assert_eq!(parsed.scheme, "https");
    assert_eq!(parsed.hostname.as_deref(), Some("example.com"));
}

#[test]
fn normalize_url_keeps_explicit_scheme_and_strips_port() {
    let (url, parsed) = normalize_url("http://example.com:8080/x").unwrap();
    assert_eq!(url, "http://example.com:8080/x");
    assert_eq!(parsed.hostname.as_deref(), Some("example.com"));
}

#[test]
fn normalize_url_rejects_bad_scheme() {
    let err = normalize_url("ftp://example.com/").unwrap_err();
    assert_eq!(err, "Invalid URL scheme: ftp");
}

#[test]
fn normalize_url_rejects_missing_hostname() {
    let err = normalize_url("https:///path").unwrap_err();
    assert_eq!(err, "Invalid URL: missing hostname");
}

#[test]
fn is_blocked_ip_flags_private_loopback_and_reserved() {
    assert!(is_blocked_ip("127.0.0.1".parse().unwrap()));
    assert!(is_blocked_ip("10.0.0.5".parse().unwrap()));
    assert!(is_blocked_ip("192.168.1.1".parse().unwrap()));
    assert!(is_blocked_ip("169.254.1.1".parse().unwrap()));
    assert!(is_blocked_ip("::1".parse().unwrap()));
    assert!(!is_blocked_ip("8.8.8.8".parse().unwrap()));
    assert!(!is_blocked_ip("1.1.1.1".parse().unwrap()));
}

#[test]
fn check_ssrf_blocks_localhost() {
    let result = check_ssrf("localhost");
    match result {
        Ok(Some(ip)) => assert!(is_blocked_ip(ip), "localhost should resolve to a blocked ip"),
        Err(_) => {}
        Ok(None) => panic!("localhost should resolve in a normal test environment"),
    }
}

#[test]
fn output_dir_allowed_matches_cwd_or_home_prefix() {
    assert!(output_dir_allowed("/home/user/project/out", "/home/user/project", "/home/user"));
    assert!(output_dir_allowed("/home/user/out", "/home/user/project", "/home/user"));
    assert!(!output_dir_allowed("/etc/passwd", "/home/user/project", "/home/user"));
}

#[test]
fn screenshot_filename_matches_python_netloc_replace() {
    assert_eq!(screenshot_filename("example.com", "mobile"), "example_com_mobile.png");
}
