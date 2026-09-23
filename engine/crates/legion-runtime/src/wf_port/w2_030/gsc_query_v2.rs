//! Faithful port of `skills/seo/scripts/gsc_query_v2.py`'s pure, replayable normalization:
//! `normalize_result()`. The live `query()`/`service()` functions perform Google API I/O and are
//! NOT ported here (see the module gap note in `wf_port::w2_030::mod`); `normalize_result` is the
//! deterministic core the docstring calls out as "replayable so recorded provider fixtures can
//! verify semantics without credentials", so it is the part worth having in Rust.

use serde_json::{json, Value};

#[derive(Debug, Clone)]
pub struct NormalizeParams<'a> {
    pub site_url: &'a str,
    pub start_date: &'a str,
    pub end_date: &'a str,
    pub dimensions: &'a [String],
    pub search_type: &'a str,
    /// The single dimensionless aggregate row (or an empty object if the API returned none).
    pub aggregate_row: &'a Value,
    pub rows: &'a [Value],
    pub max_rows: i64,
    pub hit_cap: bool,
    pub data_state: &'a str,
}

fn num(v: &Value, key: &str) -> f64 {
    v.get(key).and_then(|x| x.as_f64()).unwrap_or(0.0)
}

fn round4(x: f64) -> f64 {
    (x * 10_000.0).round() / 10_000.0
}

fn round3(x: f64) -> f64 {
    (x * 1_000.0).round() / 1_000.0
}

/// Port of `normalize_result()`. Faithful to field names, rounding (`round(x, 4)` / `round(x,
/// 3)`), and the `query_click_coverage` / `query_impression_coverage` divide-by-zero -> `null`
/// behavior.
pub fn normalize_result(p: &NormalizeParams) -> Value {
    let mut processed: Vec<Value> = Vec::with_capacity(p.rows.len());
    for row in p.rows {
        let mut item = serde_json::Map::new();
        item.insert("clicks".to_string(), row.get("clicks").cloned().unwrap_or(json!(0)));
        item.insert(
            "impressions".to_string(),
            row.get("impressions").cloned().unwrap_or(json!(0)),
        );
        item.insert("ctr".to_string(), json!(round4(num(row, "ctr") * 100.0)));
        item.insert("position".to_string(), json!(round3(num(row, "position"))));
        let keys = row.get("keys").and_then(|k| k.as_array()).cloned().unwrap_or_default();
        for (i, dim) in p.dimensions.iter().enumerate() {
            item.insert(dim.clone(), keys.get(i).cloned().unwrap_or(Value::Null));
        }
        processed.push(Value::Object(item));
    }

    let dim_clicks: f64 = p.rows.iter().map(|r| num(r, "clicks")).sum();
    let dim_impressions: f64 = p.rows.iter().map(|r| num(r, "impressions")).sum();
    let agg_clicks = num(p.aggregate_row, "clicks");
    let agg_impressions = num(p.aggregate_row, "impressions");

    let query_click_coverage = if agg_clicks != 0.0 {
        json!(round4(dim_clicks / agg_clicks))
    } else {
        Value::Null
    };
    let query_impression_coverage = if agg_impressions != 0.0 {
        json!(round4(dim_impressions / agg_impressions))
    } else {
        Value::Null
    };

    json!({
        "property": p.site_url,
        "date_range": {"start": p.start_date, "end": p.end_date},
        "search_type": p.search_type,
        "data_state": p.data_state,
        "dimensions": p.dimensions,
        "rows": processed,
        "aggregate": {
            "clicks": agg_clicks,
            "impressions": agg_impressions,
            "ctr": round4(num(p.aggregate_row, "ctr") * 100.0),
            "position": round3(num(p.aggregate_row, "position")),
            "provenance": "dimensionless Search Analytics query",
        },
        "dimension_sum": {
            "clicks": dim_clicks,
            "impressions": dim_impressions,
            "provenance": "sum of returned dimension rows; not authoritative property total",
        },
        "coverage": {
            "returned_rows": processed.len(),
            "max_rows": p.max_rows,
            "hit_client_cap": p.hit_cap,
            "query_click_coverage": query_click_coverage,
            "query_impression_coverage": query_impression_coverage,
            "complete": if p.hit_cap { json!(false) } else { Value::Null },
            "note": "Dimensioned Search Console data can omit anonymized/low-volume rows. Aggregate totals are intentionally separate; absence of a cap does not prove dimension-row completeness.",
        },
        "error": Value::Null,
    })
}

/// Port of `main()`'s pure filter-building: `--device`/`--country` become GSC
/// `dimensionFilterGroups` filters, uppercased, same as the python CLI.
pub fn build_filters(device: Option<&str>, country: Option<&str>) -> Vec<Value> {
    let mut filters = Vec::new();
    if let Some(d) = device {
        filters.push(json!({"dimension": "device", "operator": "equals", "expression": d.to_uppercase()}));
    }
    if let Some(c) = country {
        filters.push(json!({"dimension": "country", "operator": "equals", "expression": c.to_uppercase()}));
    }
    filters
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_result_matches_python_shape() {
        let dims = vec!["query".to_string(), "page".to_string()];
        let rows = vec![
            json!({"clicks": 10, "impressions": 200, "ctr": 0.05, "position": 3.456, "keys": ["seo tips", "/blog"]}),
            json!({"clicks": 5, "impressions": 100, "ctr": 0.05, "position": 4.2, "keys": ["seo", "/"]}),
        ];
        let aggregate_row = json!({"clicks": 20, "impressions": 500, "ctr": 0.04, "position": 3.9});
        let params = NormalizeParams {
            site_url: "sc-domain:example.com",
            start_date: "2026-08-01",
            end_date: "2026-08-28",
            dimensions: &dims,
            search_type: "web",
            aggregate_row: &aggregate_row,
            rows: &rows,
            max_rows: 100000,
            hit_cap: false,
            data_state: "final",
        };
        let out = normalize_result(&params);
        assert_eq!(out["property"], "sc-domain:example.com");
        assert_eq!(out["rows"][0]["query"], "seo tips");
        assert_eq!(out["rows"][0]["page"], "/blog");
        assert_eq!(out["rows"][0]["ctr"], 5.0);
        assert_eq!(out["aggregate"]["clicks"], 20.0);
        assert_eq!(out["dimension_sum"]["clicks"], 15.0);
        // 15/20 = 0.75
        assert_eq!(out["coverage"]["query_click_coverage"], 0.75);
        assert_eq!(out["coverage"]["complete"], Value::Null);
        assert_eq!(out["error"], Value::Null);
    }

    #[test]
    fn normalize_result_zero_aggregate_coverage_is_null() {
        let dims = vec!["query".to_string()];
        let rows: Vec<Value> = vec![];
        let aggregate_row = json!({});
        let params = NormalizeParams {
            site_url: "sc-domain:example.com",
            start_date: "2026-08-01",
            end_date: "2026-08-28",
            dimensions: &dims,
            search_type: "web",
            aggregate_row: &aggregate_row,
            rows: &rows,
            max_rows: 100,
            hit_cap: true,
            data_state: "final",
        };
        let out = normalize_result(&params);
        assert_eq!(out["coverage"]["query_click_coverage"], Value::Null);
        assert_eq!(out["coverage"]["hit_client_cap"], true);
        assert_eq!(out["coverage"]["complete"], false);
    }

    #[test]
    fn build_filters_uppercases_device_and_country() {
        let filters = build_filters(Some("mobile"), Some("us"));
        assert_eq!(filters.len(), 2);
        assert_eq!(filters[0]["expression"], "MOBILE");
        assert_eq!(filters[1]["expression"], "US");
    }

    #[test]
    fn build_filters_empty_when_none() {
        assert!(build_filters(None, None).is_empty());
    }
}
