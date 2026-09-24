//! Faithful port of `skills/seo/scripts/gsc_query.py`, packet r38.
//!
//! `gsc_query.py` is a thin compatibility CLI: its `query` command delegates entirely to
//! `gsc_query_v2.query()` (already ported as [`super::gsc_query_v2::query_with`]/
//! [`super::gsc_query_v2::run`]); `sites`/`sitemaps` are simple GSC `sites().list()`/
//! `sitemaps().list()` wrappers. This module ports those two live calls
//! ([`list_sites_with`]/[`list_sitemaps_with`], generalized over [`SitesTransport`] and backed
//! for real by [`ReqwestSitesTransport`]) plus `main()`'s three-way command dispatch ([`run`]).
//!
//! Bearer-token resolution reuses [`super::gsc_query_v2::resolve_bearer_token`] (see that
//! module's header for the documented service-account-JWT-signing gap it shares).

use std::io::Write;

use serde_json::{json, Value};

use super::gsc_query_v2::{encode_path_segment, resolve_bearer_token};

const WEBMASTERS_ENDPOINT: &str = "https://www.googleapis.com/webmasters/v3";

/// Boundary a caller plugs a real `sites`/`sitemaps` HTTP transport behind, so
/// [`list_sites_with`]/[`list_sitemaps_with`]/tests never need live credentials or network
/// access.
pub trait SitesTransport {
    fn get_json(&self, url: &str, bearer: &str) -> Result<(u16, String), String>;
}

/// Real transport backed by `reqwest::blocking`.
pub struct ReqwestSitesTransport;

impl SitesTransport for ReqwestSitesTransport {
    fn get_json(&self, url: &str, bearer: &str) -> Result<(u16, String), String> {
        let client = reqwest::blocking::Client::new();
        let resp = client.get(url).bearer_auth(bearer).send().map_err(|e| e.to_string())?;
        let status = resp.status().as_u16();
        let text = resp.text().map_err(|e| e.to_string())?;
        Ok((status, text))
    }
}

/// Faithful port of `list_sites()`.
pub fn list_sites_with<T: SitesTransport>(transport: &T, bearer: &str) -> Value {
    let url = format!("{WEBMASTERS_ENDPOINT}/sites");
    let (status, body) = match transport.get_json(&url, bearer) {
        Ok(ok) => ok,
        Err(e) => return json!({"sites": [], "error": e}),
    };
    if !(200..300).contains(&status) {
        return json!({"sites": [], "error": format!("{status} {body}")});
    }
    let parsed: Value = match serde_json::from_str(&body) {
        Ok(v) => v,
        Err(e) => return json!({"sites": [], "error": e.to_string()}),
    };
    let sites: Vec<Value> = parsed
        .get("siteEntry")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
        .iter()
        .map(|s| {
            json!({
                "url": s.get("siteUrl").cloned().unwrap_or(Value::Null),
                "permission": s.get("permissionLevel").cloned().unwrap_or(Value::Null),
            })
        })
        .collect();
    json!({"sites": sites, "error": Value::Null})
}

/// Faithful port of `list_sitemaps()`.
pub fn list_sitemaps_with<T: SitesTransport>(transport: &T, bearer: &str, site_url: &str) -> Value {
    let url = format!("{WEBMASTERS_ENDPOINT}/sites/{}/sitemaps", encode_path_segment(site_url));
    let (status, body) = match transport.get_json(&url, bearer) {
        Ok(ok) => ok,
        Err(e) => return json!({"property": site_url, "sitemaps": [], "error": e}),
    };
    if !(200..300).contains(&status) {
        return json!({"property": site_url, "sitemaps": [], "error": format!("{status} {body}")});
    }
    let parsed: Value = match serde_json::from_str(&body) {
        Ok(v) => v,
        Err(e) => return json!({"property": site_url, "sitemaps": [], "error": e.to_string()}),
    };
    let sitemaps: Vec<Value> = parsed
        .get("sitemap")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
        .iter()
        .map(|sm| {
            json!({
                "path": sm.get("path").cloned().unwrap_or(Value::Null),
                "last_submitted": sm.get("lastSubmitted").cloned().unwrap_or(Value::Null),
                "is_pending": sm.get("isPending").cloned().unwrap_or(Value::Null),
                "is_index": sm.get("isSitemapsIndex").cloned().unwrap_or(Value::Null),
                "type": sm.get("type").cloned().unwrap_or(Value::Null),
                "warnings": sm.get("warnings").cloned().unwrap_or(json!(0)),
                "errors": sm.get("errors").cloned().unwrap_or(json!(0)),
                "contents": sm.get("contents").cloned().unwrap_or(json!([])),
            })
        })
        .collect();
    json!({"property": site_url, "sitemaps": sitemaps, "error": Value::Null})
}

/// Faithful port of `gsc_query.py`'s `main()`: parses the `command` positional
/// (`query`/`sitemaps`/`sites`, default `query`) plus the shared flag set, and dispatches to
/// [`list_sites_with`]/[`list_sitemaps_with`] or delegates to
/// [`super::gsc_query_v2::query_with`] (mirroring the python script's own delegation to
/// `gsc_query_v2.query()`). Always prints `json.dumps(result, indent=2, ensure_ascii=False)` and
/// returns 1 if `result["error"]` is set (else 0).
pub fn run(args: &[String], out: &mut dyn std::io::Write, err: &mut dyn std::io::Write) -> i32 {
    let mut command = "query".to_string();
    let mut property: Option<String> = None;
    let mut days: i64 = 28;
    let mut start_date: Option<String> = None;
    let mut end_date: Option<String> = None;
    let mut dimensions = "query,page".to_string();
    let mut search_type = "web".to_string();
    let mut limit: i64 = 100_000;
    let mut page_size: i64 = 25_000;
    let mut device: Option<String> = None;
    let mut country: Option<String> = None;
    let mut command_given = false;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--property" | "-p" => {
                i += 1;
                property = args.get(i).cloned();
            }
            "--days" | "-d" => {
                i += 1;
                if let Some(v) = args.get(i) {
                    days = v.parse().unwrap_or(28);
                }
            }
            "--start-date" => {
                i += 1;
                start_date = args.get(i).cloned();
            }
            "--end-date" => {
                i += 1;
                end_date = args.get(i).cloned();
            }
            "--dimensions" => {
                i += 1;
                dimensions = args.get(i).cloned().unwrap_or(dimensions);
            }
            "--type" => {
                i += 1;
                search_type = args.get(i).cloned().unwrap_or(search_type);
            }
            "--limit" => {
                i += 1;
                if let Some(v) = args.get(i) {
                    limit = v.parse().unwrap_or(100_000);
                }
            }
            "--page-size" => {
                i += 1;
                if let Some(v) = args.get(i) {
                    page_size = v.parse().unwrap_or(25_000);
                }
            }
            "--device" => {
                i += 1;
                device = args.get(i).cloned();
            }
            "--country" => {
                i += 1;
                country = args.get(i).cloned();
            }
            other if !other.starts_with('-') && !command_given => {
                command = other.to_string();
                command_given = true;
            }
            _ => {}
        }
        i += 1;
    }

    let cfg = super::google_auth::load_config();
    let prop = property.or(cfg.default_property);
    if command != "sites" && prop.is_none() {
        let _ = writeln!(err, "--property required unless configured");
        return 2;
    }

    let bearer = match resolve_bearer_token() {
        Ok(b) => b,
        Err(e) => {
            let result = json!({"error": e});
            let _ = writeln!(out, "{}", serde_json::to_string_pretty(&result).unwrap_or_default());
            return 1;
        }
    };

    let result = match command.as_str() {
        "sites" => list_sites_with(&ReqwestSitesTransport, &bearer),
        "sitemaps" => list_sitemaps_with(&ReqwestSitesTransport, &bearer, prop.as_deref().unwrap_or_default()),
        _ => {
            let now = super::date_util::civil_now();
            let (start, end) =
                super::date_util::default_date_range(now, days, start_date.as_deref(), end_date.as_deref());
            let filters = super::gsc_query_v2::build_filters(device.as_deref(), country.as_deref());
            let dims: Vec<String> =
                dimensions.split(',').map(str::trim).filter(|s| !s.is_empty()).map(str::to_string).collect();
            super::gsc_query_v2::query_with(
                &super::gsc_query_v2::ReqwestSearchAnalyticsTransport,
                &bearer,
                prop.as_deref().unwrap_or_default(),
                &start,
                &end,
                &dims,
                &search_type,
                page_size,
                limit,
                if filters.is_empty() { None } else { Some(filters.as_slice()) },
                "final",
            )
        }
    };

    let _ = writeln!(out, "{}", serde_json::to_string_pretty(&result).unwrap_or_default());
    if result.get("error").map(|e| !e.is_null()).unwrap_or(false) { 1 } else { 0 }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct FakeSitesTransport {
        status: u16,
        body: Value,
    }

    impl SitesTransport for FakeSitesTransport {
        fn get_json(&self, _url: &str, _bearer: &str) -> Result<(u16, String), String> {
            Ok((self.status, self.body.to_string()))
        }
    }

    #[test]
    fn list_sites_with_maps_site_entries() {
        let transport = FakeSitesTransport {
            status: 200,
            body: json!({"siteEntry": [{"siteUrl": "sc-domain:example.com", "permissionLevel": "siteOwner"}]}),
        };
        let out = list_sites_with(&transport, "tok");
        assert_eq!(out["sites"][0]["url"], "sc-domain:example.com");
        assert_eq!(out["sites"][0]["permission"], "siteOwner");
        assert_eq!(out["error"], Value::Null);
    }

    #[test]
    fn list_sites_with_reports_http_error() {
        let transport = FakeSitesTransport { status: 403, body: json!("nope") };
        let out = list_sites_with(&transport, "tok");
        assert!(out["error"].as_str().unwrap().contains("403"));
        assert_eq!(out["sites"].as_array().unwrap().len(), 0);
    }

    #[test]
    fn list_sitemaps_with_maps_sitemap_entries() {
        let transport = FakeSitesTransport {
            status: 200,
            body: json!({"sitemap": [{"path": "https://example.com/sitemap.xml", "isPending": false, "warnings": 0, "errors": 0}]}),
        };
        let out = list_sitemaps_with(&transport, "tok", "sc-domain:example.com");
        assert_eq!(out["sitemaps"][0]["path"], "https://example.com/sitemap.xml");
        assert_eq!(out["property"], "sc-domain:example.com");
    }
}
