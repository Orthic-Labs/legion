//! Tests for packet r35: the GA4 `runReport` HTTP surface and CLI added
//! to `wf_port::w2_029::ga4_report` (full port of
//! `skills/seo/scripts/ga4_report.py`).

use std::cell::RefCell;

use legion_runtime::wf_port::w2_029::ga4_report::{
    classify_error, country_breakdown, device_breakdown, organic_traffic_report, parse_args,
    run, top_pages_report, CivilDate, CliArgs, Ga4Http, Ga4HttpError,
};
use serde_json::{json, Value};

/// Fake `Ga4Http`: returns canned responses keyed by call order, or an
/// error, so tests avoid real network/browser I/O per the port brief.
struct FakeGa4Http {
    responses: RefCell<Vec<Result<Value, Ga4HttpError>>>,
    calls: RefCell<Vec<(String, Value)>>,
}

impl FakeGa4Http {
    fn new(responses: Vec<Result<Value, Ga4HttpError>>) -> Self {
        Self {
            responses: RefCell::new(responses),
            calls: RefCell::new(Vec::new()),
        }
    }
}

impl Ga4Http for FakeGa4Http {
    fn run_report(&self, property: &str, body: &Value) -> Result<Value, Ga4HttpError> {
        self.calls.borrow_mut().push((property.to_string(), body.clone()));
        let mut r = self.responses.borrow_mut();
        if r.is_empty() {
            return Ok(json!({"rows": []}));
        }
        r.remove(0)
    }
}

fn today() -> CivilDate {
    CivilDate::new(2026, 9, 24)
}

// ---------------------------------------------------------------------
// classify_error
// ---------------------------------------------------------------------

#[test]
fn classify_error_permission_denied() {
    let e = Ga4HttpError { status: 403, message: "PERMISSION_DENIED".into() };
    let msg = classify_error("123", &e);
    assert!(msg.contains("Permission denied for property '123'"));
}

#[test]
fn classify_error_not_found() {
    let e = Ga4HttpError { status: 404, message: "not found".into() };
    let msg = classify_error("123", &e);
    assert!(msg.contains("Property '123' not found"));
}

#[test]
fn classify_error_generic() {
    let e = Ga4HttpError { status: 500, message: "boom".into() };
    let msg = classify_error("123", &e);
    assert_eq!(msg, "GA4 API error: boom");
}

// ---------------------------------------------------------------------
// organic_traffic_report
// ---------------------------------------------------------------------

#[test]
fn organic_traffic_report_happy_path() {
    let daily = json!({
        "rows": [
            {"dimensionValues": [{"value": "20260901"}], "metricValues": [
                {"value": "100"}, {"value": "80"}, {"value": "200"}, {"value": "0.5"}, {"value": "45.2"}, {"value": "0.6"}
            ]}
        ],
        "propertyQuota": {
            "tokensPerDay": {"consumed": 10, "remaining": 990},
            "tokensPerHour": {"consumed": 1, "remaining": 99}
        }
    });
    let pages = json!({
        "rows": [
            {"dimensionValues": [{"value": "/blog/a"}], "metricValues": [
                {"value": "60"}, {"value": "50"}, {"value": "70"}, {"value": "0.4"}, {"value": "0.7"}
            ]}
        ]
    });
    let client = FakeGa4Http::new(vec![Ok(daily), Ok(pages)]);
    let result = organic_traffic_report(&client, "123", 28, 50, today());

    assert_eq!(result["property"], "123");
    assert_eq!(result["totals"]["sessions"], 100);
    assert_eq!(result["totals"]["avg_daily_sessions"], 100.0);
    assert_eq!(result["daily_data"][0]["bounce_rate"], 50.0);
    assert_eq!(result["top_pages"][0]["landing_page"], "/blog/a");
    assert_eq!(result["quota_tokens_used"]["daily_remaining"], 990);
    assert!(result["error"].is_null());

    // Property passed to the HTTP layer is resolved ("properties/123").
    let calls = client.calls.borrow();
    assert_eq!(calls[0].0, "properties/123");
}

#[test]
fn organic_traffic_report_daily_error_short_circuits() {
    let client = FakeGa4Http::new(vec![Err(Ga4HttpError { status: 403, message: "PERMISSION_DENIED".into() })]);
    let result = organic_traffic_report(&client, "999", 28, 50, today());
    assert!(result["error"].as_str().unwrap().contains("Permission denied"));
    assert_eq!(result["daily_data"], json!([]));
    assert_eq!(result["totals"], json!({}));
    // Only the daily request should have been attempted.
    assert_eq!(client.calls.borrow().len(), 1);
}

#[test]
fn organic_traffic_report_pages_error_is_nonfatal() {
    let daily = json!({"rows": []});
    let client = FakeGa4Http::new(vec![Ok(daily), Err(Ga4HttpError { status: 500, message: "down".into() })]);
    let result = organic_traffic_report(&client, "123", 28, 50, today());
    assert!(result["error"].is_null());
    assert_eq!(result["pages_error"], "Error fetching top pages: down");
    // Empty daily_data -> totals stays {} (Python's `if result["daily_data"]:` guard).
    assert_eq!(result["totals"], json!({}));
}

#[test]
fn top_pages_report_slims_correctly() {
    let daily = json!({"rows": [{"dimensionValues": [{"value": "20260901"}], "metricValues": [
        {"value": "5"}, {"value": "4"}, {"value": "3"}, {"value": "0.1"}, {"value": "10.0"}, {"value": "0.2"}
    ]}]});
    let pages = json!({"rows": []});
    let client = FakeGa4Http::new(vec![Ok(daily), Ok(pages)]);
    let result = top_pages_report(&client, "123", 7, 10, today());
    assert_eq!(result["report"], "top_organic_pages");
    assert_eq!(result["total_organic_sessions"], 5);
    assert_eq!(result["pages"], json!([]));
}

#[test]
fn device_breakdown_happy_path() {
    let resp = json!({"rows": [{"dimensionValues": [{"value": "mobile"}], "metricValues": [
        {"value": "40"}, {"value": "30"}, {"value": "0.3"}, {"value": "0.5"}
    ]}]});
    let client = FakeGa4Http::new(vec![Ok(resp)]);
    let result = device_breakdown(&client, "123", 28, today());
    assert_eq!(result["devices"][0]["category"], "mobile");
    assert_eq!(result["devices"][0]["sessions"], 40);
    assert_eq!(result["devices"][0]["bounce_rate"], 30.0);
}

#[test]
fn country_breakdown_happy_path() {
    let resp = json!({"rows": [{"dimensionValues": [{"value": "US"}], "metricValues": [
        {"value": "12"}, {"value": "9"}
    ]}]});
    let client = FakeGa4Http::new(vec![Ok(resp)]);
    let result = country_breakdown(&client, "123", 28, 20, today());
    assert_eq!(result["countries"][0]["country"], "US");
    assert_eq!(result["countries"][0]["sessions"], 12);
}

// ---------------------------------------------------------------------
// parse_args / run (CLI)
// ---------------------------------------------------------------------

#[test]
fn parse_args_defaults() {
    let parsed = parse_args(&[]).unwrap();
    assert_eq!(parsed, CliArgs::default());
}

#[test]
fn parse_args_full() {
    let args: Vec<String> = ["--property", "42", "--days", "7", "--report", "top-pages", "--limit", "5", "--json"]
        .iter().map(|s| s.to_string()).collect();
    let parsed = parse_args(&args).unwrap();
    assert_eq!(parsed.property, Some("42".to_string()));
    assert_eq!(parsed.days, 7);
    assert_eq!(parsed.report, "top-pages");
    assert_eq!(parsed.limit, 5);
    assert!(parsed.json);
}

#[test]
fn parse_args_bad_report_choice() {
    let args: Vec<String> = ["--report", "bogus"].iter().map(|s| s.to_string()).collect();
    let err = parse_args(&args).unwrap_err();
    assert!(err.contains("invalid choice"));
}

#[test]
fn run_no_property_errors() {
    let client = FakeGa4Http::new(vec![]);
    let out = run(&[], &client, today(), None);
    assert_eq!(out.exit_code, 1);
    assert!(out.stderr.contains("No GA4 property specified"));
}

#[test]
fn run_uses_config_property_stripping_prefix() {
    let daily = json!({"rows": []});
    let pages = json!({"rows": []});
    let client = FakeGa4Http::new(vec![Ok(daily), Ok(pages)]);
    let out = run(&[], &client, today(), Some("properties/555"));
    assert_eq!(out.exit_code, 0);
    assert!(out.stdout.contains("Property: 555"));
    assert_eq!(client.calls.borrow()[0].0, "properties/555");
}

#[test]
fn run_json_output_on_error_does_not_exit_nonzero() {
    let client = FakeGa4Http::new(vec![Err(Ga4HttpError { status: 404, message: "NOT_FOUND".into() })]);
    let args: Vec<String> = ["--property", "1", "--json"].iter().map(|s| s.to_string()).collect();
    let out = run(&args, &client, today(), None);
    // Mirrors: `if not args.json: sys.exit(1)` — json mode stays exit 0.
    assert_eq!(out.exit_code, 0);
    assert!(out.stdout.contains("\"error\""));
    assert!(out.stderr.contains("not found"));
}

#[test]
fn run_top_pages_text_output() {
    let daily = json!({"rows": [{"dimensionValues": [{"value": "20260901"}], "metricValues": [
        {"value": "5"}, {"value": "4"}, {"value": "3"}, {"value": "0.1"}, {"value": "10.0"}, {"value": "0.2"}
    ]}]});
    let pages = json!({"rows": [{"dimensionValues": [{"value": "/x"}], "metricValues": [
        {"value": "5"}, {"value": "4"}, {"value": "3"}, {"value": "0.1"}, {"value": "0.2"}
    ]}]});
    let client = FakeGa4Http::new(vec![Ok(daily), Ok(pages)]);
    let args: Vec<String> = ["--property", "1", "--report", "top-pages"].iter().map(|s| s.to_string()).collect();
    let out = run(&args, &client, today(), None);
    assert_eq!(out.exit_code, 0);
    assert!(out.stdout.contains("Top Organic Landing Pages"));
    assert!(out.stdout.contains("/x"));
    assert!(out.stdout.contains("Total organic sessions: 5"));
}
