//! Packet r38 integration tests: the live-HTTP-transport-boundary functions added to
//! `wf_port::w2_030::{gsc_inspect, gsc_query, gsc_query_v2}` to close the "live googleapiclient
//! calls" gap documented in `wf_port::w2_030::mod` for `gsc_inspect.py`, `gsc_query.py`, and
//! `gsc_query_v2.py`. Each transport trait is driven by an in-process fake here — no network
//! access, matching the packet's "must not hit the network" rule.

use serde_json::{json, Value};

use legion_runtime::wf_port::w2_030::gsc_inspect::{
    batch_inspect_with, inspect_url_with, InspectionTransport,
};
use legion_runtime::wf_port::w2_030::gsc_query::{list_sitemaps_with, list_sites_with, SitesTransport};
use legion_runtime::wf_port::w2_030::gsc_query_v2::{encode_path_segment, query_with, SearchAnalyticsTransport};

struct FakeInspection {
    status: u16,
    body: Value,
}

impl InspectionTransport for FakeInspection {
    fn post_json(&self, _url: &str, bearer: &str, body: &Value) -> Result<(u16, String), String> {
        assert_eq!(bearer, "test-bearer");
        assert!(body.get("inspectionUrl").is_some());
        Ok((self.status, self.body.to_string()))
    }
}

#[test]
fn gsc_inspect_url_inspection_end_to_end() {
    let transport = FakeInspection {
        status: 200,
        body: json!({
            "inspectionResult": {
                "indexStatusResult": {
                    "verdict": "PASS",
                    "coverageState": "Submitted and indexed",
                    "googleCanonical": "https://example.com/",
                    "userCanonical": "https://example.com/",
                }
            }
        }),
    };
    let out = inspect_url_with(&transport, "test-bearer", "https://example.com/", "sc-domain:example.com", "en");
    assert_eq!(out["verdict"], "PASS");
    assert_eq!(out["canonical"]["match"], true);
    assert_eq!(out["error"], Value::Null);
}

#[test]
fn gsc_inspect_batch_reports_total_before_truncation() {
    struct AlwaysNeutral;
    impl InspectionTransport for AlwaysNeutral {
        fn post_json(&self, _url: &str, _bearer: &str, _body: &Value) -> Result<(u16, String), String> {
            Ok((200, json!({"inspectionResult": {}}).to_string()))
        }
    }
    let urls: Vec<String> = (0..2005).map(|i| format!("https://example.com/{i}")).collect();
    let out = batch_inspect_with(&AlwaysNeutral, "test-bearer", urls, "sc-domain:example.com", "en");
    // python's batch_inspect() sets result['total'] = len(urls) BEFORE the DAILY_LIMIT truncation.
    assert_eq!(out["total"], 2005);
    assert_eq!(out["summary"]["neutral"], 2000);
    assert!(out["error"].as_str().unwrap().contains("exceeds daily limit"));
}

struct FakeSearchAnalytics {
    // one canned (status, body) response per call, in order: aggregate call first, then pages.
    responses: std::cell::RefCell<std::collections::VecDeque<Value>>,
}

impl SearchAnalyticsTransport for FakeSearchAnalytics {
    fn post_json(&self, url: &str, bearer: &str, _body: &Value) -> Result<(u16, String), String> {
        assert_eq!(bearer, "test-bearer");
        assert!(url.contains(&encode_path_segment("sc-domain:example.com")));
        assert!(url.ends_with("/searchAnalytics/query"));
        let body = self.responses.borrow_mut().pop_front().expect("no more fake responses");
        Ok((200, body.to_string()))
    }
}

#[test]
fn gsc_query_v2_query_with_end_to_end() {
    let transport = FakeSearchAnalytics {
        responses: std::cell::RefCell::new(
            vec![
                json!({"rows": [{"clicks": 42, "impressions": 1000, "ctr": 0.042, "position": 2.5}]}),
                json!({"rows": [{
                    "clicks": 42, "impressions": 1000, "ctr": 0.042, "position": 2.5,
                    "keys": ["rust seo port", "/blog/rust-seo"],
                }]}),
            ]
            .into(),
        ),
    };
    let dims = vec!["query".to_string(), "page".to_string()];
    let result = query_with(
        &transport,
        "test-bearer",
        "sc-domain:example.com",
        "2026-08-03",
        "2026-08-28",
        &dims,
        "web",
        25_000,
        100_000,
        None,
        "final",
    );
    assert_eq!(result["rows"][0]["query"], "rust seo port");
    assert_eq!(result["coverage"]["query_click_coverage"], 1.0);
    assert_eq!(result["error"], Value::Null);
}

struct FakeSites {
    status: u16,
    body: Value,
}

impl SitesTransport for FakeSites {
    fn get_json(&self, _url: &str, bearer: &str) -> Result<(u16, String), String> {
        assert_eq!(bearer, "test-bearer");
        Ok((self.status, self.body.to_string()))
    }
}

#[test]
fn gsc_query_sites_and_sitemaps_end_to_end() {
    let sites = FakeSites {
        status: 200,
        body: json!({"siteEntry": [{"siteUrl": "sc-domain:example.com", "permissionLevel": "siteOwner"}]}),
    };
    let sites_result = list_sites_with(&sites, "test-bearer");
    assert_eq!(sites_result["sites"][0]["url"], "sc-domain:example.com");

    let sitemaps = FakeSites {
        status: 200,
        body: json!({"sitemap": [{
            "path": "https://example.com/sitemap.xml",
            "lastSubmitted": "2026-08-01T00:00:00Z",
            "isPending": false,
            "isSitemapsIndex": false,
            "type": "sitemap",
            "warnings": 0,
            "errors": 0,
        }]}),
    };
    let sitemaps_result = list_sitemaps_with(&sitemaps, "test-bearer", "sc-domain:example.com");
    assert_eq!(sitemaps_result["property"], "sc-domain:example.com");
    assert_eq!(sitemaps_result["sitemaps"][0]["path"], "https://example.com/sitemap.xml");
    assert_eq!(sitemaps_result["error"], Value::Null);
}
