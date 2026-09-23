//! Tests for the w2_029 port of `skills/seo/scripts/{contracts,coverage,
//! crux_history,fetch_page,ga4_report}.py`.
//!
//! Assertions are ported from the behaviour implied by the Python source
//! (these scripts carry no `tests/` files of their own upstream); each
//! test documents the Python call it mirrors.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use legion_runtime::wf_port::w2_029::contracts::{config, validate, validate_bundle};
use legion_runtime::wf_port::w2_029::coverage::{calculate, rows};
use legion_runtime::wf_port::w2_029::crux_history::{
    detect_trends, parse_history_record, validate_url,
};
use legion_runtime::wf_port::w2_029::fetch_page::{
    check_ssrf, default_headers, format_metadata, normalize_and_validate_scheme, RedirectDetail,
    DEFAULT_USER_AGENT, GOOGLEBOT_USER_AGENT,
};
use legion_runtime::wf_port::w2_029::ga4_report::{
    compute_totals, date_range, resolve_property, slim_to_top_pages, CivilDate,
};
use serde_json::json;

// ---------------------------------------------------------------------
// contracts.py -> contracts
// ---------------------------------------------------------------------

#[test]
fn config_matches_contracts_json() {
    let cfg = config();
    assert_eq!(
        cfg.statuses,
        &["pass", "partial", "fail", "na", "not_testable"]
    );
    assert_eq!(cfg.evidence_tiers.len(), 6);
    assert!(cfg.claim_states.contains(&"causal_supported"));
}

#[test]
fn validate_unknown_kind() {
    // Mirrors `validate('bogus', {})`.
    let errors = validate("bogus", &json!({}));
    assert_eq!(errors, vec!["unknown contract kind: bogus".to_string()]);
}

#[test]
fn validate_evidence_missing_required_and_bad_tier() {
    let obj = json!({"id": "e1", "coverage_state": "pass", "tier": "nonsense"});
    let errors = validate("evidence", &obj);
    // Missing: source_identity, collected_at, market, subject, raw_locator.
    assert!(errors.contains(&"evidence.source_identity is required".to_string()));
    assert!(errors.contains(&"evidence.collected_at is required".to_string()));
    assert!(errors
        .iter()
        .any(|e| e.starts_with("evidence.tier must be one of")));
}

#[test]
fn validate_evidence_empty_string_counts_as_missing() {
    // Mirrors Python `obj.get(key) in (None, '')`.
    let obj = json!({
        "id": "",
        "source_identity": "s",
        "collected_at": "t",
        "market": "US",
        "tier": "static",
        "subject": "sub",
        "raw_locator": "loc",
        "coverage_state": "pass",
    });
    let errors = validate("evidence", &obj);
    assert_eq!(errors, vec!["evidence.id is required".to_string()]);
}

#[test]
fn validate_finding_partial_requires_scopes() {
    let obj = json!({
        "id": "f1", "subject": "s", "evidence_ids": ["e1"], "market": "US",
        "confidence": "high", "coverage_state": "partial", "claim_state": "observed",
        "observed_condition": "x",
    });
    let errors = validate("finding", &obj);
    assert!(errors.contains(
        &"partial finding requires tested_scope and untested_scope".to_string()
    ));
}

#[test]
fn validate_finding_not_testable_requires_reason() {
    let obj = json!({
        "id": "f1", "subject": "s", "evidence_ids": ["e1"], "market": "US",
        "confidence": "high", "coverage_state": "not_testable", "claim_state": "observed",
        "observed_condition": "x",
    });
    let errors = validate("finding", &obj);
    assert!(errors.contains(&"not_testable finding requires reason".to_string()));
}

#[test]
fn validate_finding_empty_evidence_ids_list_is_invalid() {
    let obj = json!({
        "id": "f1", "subject": "s", "evidence_ids": [], "market": "US",
        "confidence": "high", "coverage_state": "pass", "claim_state": "observed",
        "observed_condition": "x",
    });
    let errors = validate("finding", &obj);
    assert!(errors.contains(&"finding.evidence_ids must be a non-empty list".to_string()));
}

#[test]
fn validate_action_executed_requires_effect_receipt() {
    let base = json!({
        "id": "a1", "recommendation_id": "r1", "authorized_capability": "cap",
        "target": "t", "exact_change": "c", "baseline_ref": "b",
        "idempotency_key": "k", "rollback": "r", "status": "executed",
    });
    let errors = validate("action", &base);
    assert!(errors.contains(
        &"executed/verified action requires host-observed effect_receipt".to_string()
    ));

    let mut with_receipt = base.clone();
    with_receipt["effect_receipt"] = json!("receipt-1");
    assert!(validate("action", &with_receipt).is_empty());
}

#[test]
fn validate_action_invalid_status() {
    let obj = json!({
        "id": "a1", "recommendation_id": "r1", "authorized_capability": "cap",
        "target": "t", "exact_change": "c", "baseline_ref": "b",
        "idempotency_key": "k", "rollback": "r", "status": "bogus",
    });
    let errors = validate("action", &obj);
    assert!(errors.contains(&"action.status invalid".to_string()));
}

#[test]
fn validate_outcome_invalid_verdict_and_causal_strength() {
    let obj = json!({
        "id": "o1", "action_id": "a1", "recorded_at": "t", "metric": "m",
        "baseline_ref": "b", "observation": "obs", "verdict": "bogus",
        "causal_strength": "bogus", "confounders": [],
    });
    let errors = validate("outcome", &obj);
    assert!(errors.contains(&"outcome.verdict invalid".to_string()));
    assert!(errors.contains(&"outcome.causal_strength invalid".to_string()));
}

#[test]
fn validate_bundle_pass_on_empty_payload() {
    let result = validate_bundle(&json!({}));
    assert_eq!(result["status"], "pass");
    assert_eq!(result["errors"], json!([]));
}

#[test]
fn validate_bundle_flags_dangling_references() {
    let payload = json!({
        "findings": [
            {
                "id": "f1", "subject": "s", "evidence_ids": ["missing-e"], "market": "US",
                "confidence": "high", "coverage_state": "pass", "claim_state": "observed",
                "observed_condition": "x",
            }
        ],
        "actions": [
            {
                "id": "a1", "recommendation_id": "missing-r", "authorized_capability": "cap",
                "target": "t", "exact_change": "c", "baseline_ref": "b",
                "idempotency_key": "k", "rollback": "r", "status": "proposed",
            }
        ],
    });
    let result = validate_bundle(&payload);
    assert_eq!(result["status"], "fail");
    let errors: Vec<String> = result["errors"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect();
    assert!(errors.iter().any(|e| e.contains("missing evidence IDs")));
    assert!(errors
        .iter()
        .any(|e| e == "actions[0] references missing recommendation: missing-r"));
}

// ---------------------------------------------------------------------
// coverage.py -> coverage
// ---------------------------------------------------------------------

#[test]
fn rows_accepts_list_or_controls_object() {
    assert_eq!(rows(&json!([{"id": "1"}])).unwrap().len(), 1);
    assert_eq!(
        rows(&json!({"controls": [{"id": "1"}, {"id": "2"}]}))
            .unwrap()
            .len(),
        2
    );
    assert!(rows(&json!("nope")).is_err());
}

#[test]
fn calculate_na_without_rationale_forces_fail() {
    let controls = vec![json!({"id": "c1", "status": "na"})];
    let result = calculate(&controls);
    assert_eq!(result.status, "fail");
    assert_eq!(
        result.validation_errors,
        vec!["c1: N/A requires rationale".to_string()]
    );
    // N/A rows are excluded from the applicable/coverage denominator.
    assert_eq!(result.applicable_controls, 0);
    assert_eq!(result.evidence_coverage, 1.0);
}

#[test]
fn calculate_not_testable_reduces_coverage_and_reports_critical_gate() {
    let controls = vec![
        json!({"id": "c1", "status": "pass"}),
        json!({"id": "c2", "status": "not_testable", "reason": "no access", "critical": true}),
    ];
    let result = calculate(&controls);
    assert_eq!(result.applicable_controls, 2);
    assert_eq!(result.tested_controls, 1);
    assert_eq!(result.evidence_coverage, 0.5);
    assert_eq!(result.critical_gate, "partial");
    assert_eq!(result.critical_unknown, vec!["c2".to_string()]);
}

#[test]
fn calculate_critical_failure_gates_fail_even_with_high_coverage() {
    let controls = vec![
        json!({"id": "c1", "status": "pass"}),
        json!({"id": "c2", "status": "pass"}),
        json!({"id": "c3", "status": "fail", "critical": true}),
    ];
    let result = calculate(&controls);
    assert_eq!(result.critical_gate, "fail");
    assert_eq!(result.status, "fail");
    assert_eq!(result.critical_failures, vec!["c3".to_string()]);
}

#[test]
fn calculate_partial_requires_scopes() {
    let controls = vec![json!({"id": "c1", "status": "partial"})];
    let result = calculate(&controls);
    assert!(result
        .validation_errors
        .contains(&"c1: Partial requires tested_scope and untested_scope".to_string()));
}

#[test]
fn calculate_missing_id_defaults_to_row_index() {
    let controls = vec![json!({"status": "bogus-status"})];
    let result = calculate(&controls);
    assert_eq!(
        result.validation_errors,
        vec!["row-0: invalid status 'bogus-status'".to_string()]
    );
}

// ---------------------------------------------------------------------
// crux_history.py (+ google_auth.validate_url) -> crux_history
// ---------------------------------------------------------------------

#[test]
fn validate_url_rejects_non_http_scheme() {
    assert!(!validate_url("ftp://example.com/"));
}

#[test]
fn validate_url_rejects_blocked_hostnames() {
    assert!(!validate_url("http://localhost/"));
    assert!(!validate_url("http://127.0.0.1/"));
    assert!(!validate_url("http://metadata.google.internal/"));
}

#[test]
fn validate_url_rejects_private_ip_literals() {
    assert!(!validate_url("http://10.0.0.5/"));
    assert!(!validate_url("http://192.168.1.1/"));
    assert!(!validate_url("http://169.254.1.1/"));
}

#[test]
fn validate_url_accepts_public_url() {
    assert!(validate_url("https://example.com/page?q=1"));
}

#[test]
fn detect_trends_insufficient_data_below_8_points() {
    let record = json!({
        "collectionPeriods": [],
        "metrics": {
            "largest_contentful_paint": {
                "percentilesTimeseries": {"p75s": [1000, 1100, 1200]},
                "histogramTimeseries": [],
            }
        }
    });
    let (_periods, metrics) = parse_history_record(&record);
    let trends = detect_trends(&metrics);
    assert_eq!(
        trends["largest_contentful_paint"].direction,
        "insufficient_data"
    );
}

#[test]
fn detect_trends_improving_when_p75_drops() {
    let p75s: Vec<i64> = vec![4000, 4000, 4000, 4000, 2000, 2000, 2000, 2000];
    let record = json!({
        "collectionPeriods": [
            {"firstDate": {"year": 2026, "month": 1, "day": 1}, "lastDate": {"year": 2026, "month": 1, "day": 7}},
        ],
        "metrics": {
            "largest_contentful_paint": {
                "percentilesTimeseries": {"p75s": p75s},
                "histogramTimeseries": [],
            }
        }
    });
    let (periods, metrics) = parse_history_record(&record);
    assert_eq!(periods[0].first, "2026-01-01");
    let trends = detect_trends(&metrics);
    let trend = &trends["largest_contentful_paint"];
    assert_eq!(trend.direction, "improving");
    assert_eq!(trend.change_pct, Some(-50.0));
    assert_eq!(trend.label, "LCP");
}

#[test]
fn detect_trends_degrading_when_p75_rises() {
    let p75s: Vec<f64> = vec![0.05, 0.05, 0.05, 0.05, 0.2, 0.2, 0.2, 0.2];
    let record = json!({
        "collectionPeriods": [],
        "metrics": {
            "cumulative_layout_shift": {
                "percentilesTimeseries": {"p75s": p75s.iter().map(|v| v.to_string()).collect::<Vec<_>>()},
                "histogramTimeseries": [],
            }
        }
    });
    let (_p, metrics) = parse_history_record(&record);
    assert_eq!(
        metrics["cumulative_layout_shift"].p75_values,
        vec![Some(0.05), Some(0.05), Some(0.05), Some(0.05), Some(0.2), Some(0.2), Some(0.2), Some(0.2)]
    );
    let trends = detect_trends(&metrics);
    let trend = &trends["cumulative_layout_shift"];
    assert_eq!(trend.direction, "degrading");
    // unit == "" -> averages rounded to 3 places.
    assert_eq!(trend.earliest_avg, Some(0.05));
    assert_eq!(trend.latest_avg, Some(0.2));
}

#[test]
fn parse_history_record_ignores_unknown_metrics_and_parses_histogram() {
    let record = json!({
        "collectionPeriods": [],
        "metrics": {
            "unknown_metric": {"percentilesTimeseries": {"p75s": [1]}},
            "first_contentful_paint": {
                "percentilesTimeseries": {"p75s": [1500, null]},
                "histogramTimeseries": [
                    {"densities": [0.7, "NaN"]},
                    {"densities": [0.2, 0.1]},
                    {"densities": [0.1, 0.2]},
                ],
            }
        }
    });
    let (_p, metrics) = parse_history_record(&record);
    assert!(!metrics.contains_key("unknown_metric"));
    let fcp = &metrics["first_contentful_paint"];
    assert_eq!(fcp.p75_values, vec![Some(1500.0), None]);
    assert_eq!(fcp.good_percentages, vec![Some(70.0), None]);
    assert_eq!(fcp.latest_p75, None); // last value is None -> latest_p75 None.
    assert_eq!(fcp.label, "FCP");
}

// ---------------------------------------------------------------------
// fetch_page.py -> fetch_page
// ---------------------------------------------------------------------

#[test]
fn default_headers_use_default_ua_when_none_given() {
    let headers = default_headers(None);
    assert_eq!(headers["User-Agent"], DEFAULT_USER_AGENT);
    assert_eq!(headers["Accept-Encoding"], "gzip, deflate");
}

#[test]
fn default_headers_override_with_googlebot_ua() {
    let headers = default_headers(Some(GOOGLEBOT_USER_AGENT));
    assert_eq!(headers["User-Agent"], GOOGLEBOT_USER_AGENT);
}

#[test]
fn normalize_and_validate_scheme_defaults_to_https() {
    assert_eq!(
        normalize_and_validate_scheme("example.com").unwrap(),
        "https://example.com"
    );
}

#[test]
fn normalize_and_validate_scheme_rejects_non_http() {
    let err = normalize_and_validate_scheme("ftp://example.com").unwrap_err();
    assert_eq!(err, "Invalid URL scheme: ftp");
}

#[test]
fn check_ssrf_blocks_private_and_loopback() {
    assert!(check_ssrf(Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)))).is_err());
    assert!(check_ssrf(Some(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)))).is_err());
    assert!(check_ssrf(Some(IpAddr::V6(Ipv6Addr::LOCALHOST))).is_err());
}

#[test]
fn check_ssrf_allows_public_ip_and_unresolved() {
    assert!(check_ssrf(Some(IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)))).is_ok());
    // Mirrors Python's `except (socket.gaierror, ValueError): pass`.
    assert!(check_ssrf(None).is_ok());
}

#[test]
fn format_metadata_with_redirect_details() {
    let out = format_metadata(
        "https://example.com/final",
        200,
        &[RedirectDetail {
            url: "https://example.com/old".to_string(),
            status_code: 301,
        }],
        &[],
    );
    assert!(out.contains("301 -> https://example.com/old"));
    assert!(out.contains("200 -> https://example.com/final (final)"));
}

#[test]
fn format_metadata_without_redirects() {
    let out = format_metadata("https://example.com", 200, &[], &[]);
    assert_eq!(out, "\nURL: https://example.com\nStatus: 200");
}

// ---------------------------------------------------------------------
// ga4_report.py -> ga4_report
// ---------------------------------------------------------------------

#[test]
fn resolve_property_adds_prefix() {
    assert_eq!(resolve_property("123456789"), "properties/123456789");
    assert_eq!(
        resolve_property("properties/123456789"),
        "properties/123456789"
    );
    assert_eq!(resolve_property(""), "");
}

#[test]
fn date_range_matches_python_timedelta() {
    // today = 2026-01-10; days=28 -> start = today - 28 days, end = today - 1 day.
    let today = CivilDate::new(2026, 1, 10);
    let dr = date_range(today, 28);
    assert_eq!(dr.start, "2025-12-13");
    assert_eq!(dr.end, "2026-01-09");
}

#[test]
fn date_range_crosses_month_and_year_boundaries() {
    let today = CivilDate::new(2026, 3, 1);
    let dr = date_range(today, 1);
    assert_eq!(dr.start, "2026-02-28");
    assert_eq!(dr.end, "2026-02-28");

    let jan1 = CivilDate::new(2026, 1, 1);
    let dr2 = date_range(jan1, 5);
    assert_eq!(dr2.start, "2025-12-27");
}

#[test]
fn civil_date_round_trips_through_days() {
    for (y, m, d) in [(2024, 2, 29), (2000, 1, 1), (1999, 12, 31), (2026, 9, 23)] {
        let date = CivilDate::new(y, m, d);
        let back = date.minus_days(0);
        assert_eq!(date, back);
    }
}

#[test]
fn compute_totals_none_when_no_daily_data() {
    assert!(compute_totals(&[], &[], &[]).is_none());
}

#[test]
fn compute_totals_sums_and_averages() {
    let totals = compute_totals(&[10, 20, 30], &[5, 5, 5], &[100, 100, 100]).unwrap();
    assert_eq!(totals.sessions, 60);
    assert_eq!(totals.users, 15);
    assert_eq!(totals.pageviews, 300);
    assert_eq!(totals.avg_daily_sessions, 20.0);
}

#[test]
fn slim_to_top_pages_extracts_fields() {
    let report = json!({
        "date_range": {"start": "2026-01-01", "end": "2026-01-28"},
        "top_pages": [{"landing_page": "/a", "sessions": 5}],
        "totals": {"sessions": 42},
        "quota_tokens_used": null,
        "error": null,
    });
    let slim = slim_to_top_pages("123456789", &report);
    assert_eq!(slim["report"], "top_organic_pages");
    assert_eq!(slim["total_organic_sessions"], 42);
    assert_eq!(slim["pages"][0]["landing_page"], "/a");
}

#[test]
fn slim_to_top_pages_defaults_when_totals_missing() {
    let report = json!({"error": "boom"});
    let slim = slim_to_top_pages("p", &report);
    assert_eq!(slim["total_organic_sessions"], 0);
    assert_eq!(slim["pages"], json!([]));
    assert_eq!(slim["error"], "boom");
}
