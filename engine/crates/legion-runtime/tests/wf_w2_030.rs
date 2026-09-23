//! Cross-module integration tests for wf_port chunk w2_030 (`skills/seo/scripts`), exercising the
//! ported entry points end to end across `google_auth`, `gsc_query_v2`, `gsc_inspect`, and
//! `date_util` together, rather than the per-function unit tests already inline in each
//! submodule. See `legion_runtime::wf_port::w2_030` for the chunk's scope and documented gaps.
//!
//! NOTE for the integrator: this file assumes `pub mod wf_port;` (in `legion-runtime`'s
//! `lib.rs`) and `pub mod w2_030;` (in `wf_port::mod`) are wired per the w2_030 chunk assignment;
//! see `engine/crates/legion-runtime/src/wf_port/w2_030/mod.rs`'s module doc for the exact patch.

use std::collections::BTreeMap;

use legion_runtime::wf_port::w2_030::date_util::default_date_range;
use legion_runtime::wf_port::w2_030::google_auth::{
    check_credentials, detect_tier, merge_config, validate_url, CredentialState, GoogleApiConfig,
    ServiceAccountState,
};
use legion_runtime::wf_port::w2_030::gsc_inspect::{
    apply_daily_limit, parse_inspection_result, tally_batch_summary,
};
use legion_runtime::wf_port::w2_030::gsc_query_v2::{build_filters, normalize_result, NormalizeParams};
use serde_json::{json, Value};

#[test]
fn google_auth_full_credential_lifecycle() {
    // Config loaded purely from environment (no file present), matching a fresh dev machine.
    let mut env = BTreeMap::new();
    env.insert("GOOGLE_API_KEY".to_string(), "AIzaTest".to_string());
    env.insert("GA4_PROPERTY_ID".to_string(), "properties/12345".to_string());
    let cfg = merge_config(None, &env);
    assert_eq!(cfg.api_key.as_deref(), Some("AIzaTest"));

    // Tier -1 -> 0: only the API key is set so far, no GSC/indexing/GA4 auth.
    let no_auth = CredentialState::default();
    let tier0 = detect_tier(&cfg, &no_auth);
    assert_eq!(tier0.tier, 0);

    let psi_check = check_credentials("psi", &cfg, &no_auth);
    assert!(psi_check.available);

    let gsc_check = check_credentials("gsc", &cfg, &no_auth);
    assert!(!gsc_check.available);

    // A service account appears: tier climbs to 2 because ga4_property_id is already configured.
    let authenticated = CredentialState {
        service_account: Some(ServiceAccountState {
            exists: true,
            has_required_fields: true,
            client_email: Some("svc@project.iam.gserviceaccount.com".to_string()),
            path: "/home/user/.config/claude-seo/sa.json".to_string(),
        }),
        ..Default::default()
    };
    let tier2 = detect_tier(&cfg, &authenticated);
    assert_eq!(tier2.tier, 2);
    assert!(tier2.missing.is_none());

    let gsc_check2 = check_credentials("gsc", &cfg, &authenticated);
    assert!(gsc_check2.available);
    assert_eq!(gsc_check2.client_email.as_deref(), Some("svc@project.iam.gserviceaccount.com"));

    let ga4_check = check_credentials("ga4", &cfg, &authenticated);
    assert!(ga4_check.available);
}

#[test]
fn google_auth_config_default_property_feeds_gsc_query_defaults() {
    let mut env = BTreeMap::new();
    env.insert("GSC_PROPERTY".to_string(), "sc-domain:example.com".to_string());
    let cfg = merge_config(None, &env);
    let prop = cfg.default_property.expect("default_property from env");
    assert_eq!(prop, "sc-domain:example.com");
    assert!(validate_url("https://example.com/"));
}

#[test]
fn gsc_query_v2_pipeline_end_to_end() {
    // Same shape gsc_query.py's main() builds before delegating to gsc_query_v2.query().
    let (start, end) = default_date_range((2026, 8, 31), 28, None, None);
    assert_eq!((start.as_str(), end.as_str()), ("2026-08-03", "2026-08-28"));

    let filters = build_filters(Some("mobile"), Some("gb"));
    assert_eq!(filters[0]["expression"], "MOBILE");
    assert_eq!(filters[1]["expression"], "GB");

    let dims = vec!["query".to_string(), "page".to_string()];
    let rows = vec![json!({
        "clicks": 42, "impressions": 1000, "ctr": 0.042, "position": 2.5,
        "keys": ["rust seo port", "/blog/rust-seo"],
    })];
    let aggregate_row = json!({"clicks": 42, "impressions": 1000, "ctr": 0.042, "position": 2.5});
    let params = NormalizeParams {
        site_url: "sc-domain:example.com",
        start_date: &start,
        end_date: &end,
        dimensions: &dims,
        search_type: "web",
        aggregate_row: &aggregate_row,
        rows: &rows,
        max_rows: 100_000,
        hit_cap: false,
        data_state: "final",
    };
    let result = normalize_result(&params);
    assert_eq!(result["date_range"]["start"], "2026-08-03");
    assert_eq!(result["date_range"]["end"], "2026-08-28");
    assert_eq!(result["rows"][0]["query"], "rust seo port");
    assert_eq!(result["coverage"]["query_click_coverage"], 1.0);
    assert_eq!(result["error"], Value::Null);
}

#[test]
fn gsc_inspect_single_and_batch_pipeline() {
    let raw_pass = json!({
        "indexStatusResult": {
            "verdict": "PASS",
            "coverageState": "Submitted and indexed",
            "googleCanonical": "https://example.com/a",
            "userCanonical": "https://example.com/a",
        }
    });
    let raw_fail = json!({
        "indexStatusResult": {
            "verdict": "FAIL",
            "coverageState": "Crawled - currently not indexed",
            "googleCanonical": Value::Null,
            "userCanonical": "https://example.com/b",
        }
    });

    let a = parse_inspection_result("https://example.com/a", "sc-domain:example.com", &raw_pass);
    let b = parse_inspection_result("https://example.com/b", "sc-domain:example.com", &raw_fail);

    assert_eq!(a["verdict"], "PASS");
    assert_eq!(a["canonical"]["match"], true);
    assert_eq!(b["verdict"], "FAIL");
    assert_eq!(b["canonical"]["match"], Value::Null);

    let summary = tally_batch_summary(&[a, b]);
    assert_eq!(summary.pass_count, 1);
    assert_eq!(summary.fail_count, 1);
    assert_eq!(summary.error_count, 0);

    let urls: Vec<String> = (0..2005).map(|i| format!("https://example.com/{i}")).collect();
    let (truncated, warning) = apply_daily_limit(urls);
    assert_eq!(truncated.len(), 2000);
    assert!(warning.unwrap().contains("2005"));
}

#[test]
fn google_auth_validate_url_blocks_metadata_and_link_local() {
    assert!(!validate_url("http://metadata.google.internal/computeMetadata/v1/"));
    assert!(!validate_url("https://169.254.169.254/latest/meta-data"));
    assert!(validate_url("https://searchconsole.googleapis.com/v1/"));
}

#[test]
fn google_auth_config_default_object_has_no_credentials() {
    let cfg = GoogleApiConfig::default();
    assert!(cfg.api_key.is_none());
    let state = CredentialState::default();
    let tier = detect_tier(&cfg, &state);
    assert_eq!(tier.tier, -1);
}
