//! Port of `google_report.py`'s "Chart Functions" section
//! (`chart_lighthouse_gauges`, `chart_cwv_distributions`, `chart_cwv_timeline`,
//! `chart_top_queries`, `chart_index_status`).
//!
//! Format note (deliberate, not a gap): the Python originals render PNGs with
//! matplotlib. This packet's allowed-crate list has no charting library, so
//! each function here renders the *same selected data* as a hand-built SVG
//! string instead of a PNG -- same inputs, same data-selection/sort/filter
//! logic (ported verbatim below), different output image format. Callers
//! write the returned string to a `.svg` file where the Python wrote a `.png`;
//! `_chart_html`/`_img_tag` (ported in `sections.rs`) embed either equally via
//! `<img src="file://...">`, and `headless_chrome`'s `print_to_pdf` rasterizes
//! inline SVG into the PDF exactly like it would a PNG `<img>`.

use serde_json::Value;

use super::colors::{score_color, BRAND};
use super::jget::{arr, get_f64_or, get_str_or, obj};

fn svg_open(width: u32, height: u32) -> String {
    format!(
        r#"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width} {height}" width="{width}" height="{height}" font-family="DejaVu Serif, Georgia, serif"><rect width="{width}" height="{height}" fill="white"/>"#
    )
}

/// Port of `chart_lighthouse_gauges`: 2x2 gauge grid for
/// performance/accessibility/best-practices/seo. Returns `None` where Python
/// returned `""` (no `lighthouse_scores` data).
pub fn chart_lighthouse_gauges(mobile_data: &Value) -> Option<String> {
    let scores = obj(mobile_data, "lighthouse_scores");
    if scores.as_object().map(|m| m.is_empty()).unwrap_or(true) {
        return None;
    }

    let categories = [
        ("performance", "Performance"),
        ("accessibility", "Accessibility"),
        ("best-practices", "Best Practices"),
        ("seo", "SEO"),
    ];

    let (w, h) = (800u32, 400u32);
    let mut svg = svg_open(w, h);
    let cell_w = w as f64 / 2.0;
    let cell_h = h as f64 / 2.0;

    for (i, (key, label)) in categories.iter().enumerate() {
        let score = get_f64_or(scores, key, 0.0);
        let cx = cell_w * (i % 2) as f64 + cell_w / 2.0;
        let cy = cell_h * (i / 2) as f64 + cell_h / 2.0;
        let r = cell_h.min(cell_w) * 0.32;
        let color = score_color(score);

        // Background half-circle arc (0..180deg), then the filled portion for `score`.
        svg.push_str(&gauge_arc(cx, cy, r, 180.0, "#e2e8f0", 14.0));
        let sweep = (score / 100.0) * 180.0;
        if sweep > 0.0 {
            svg.push_str(&gauge_arc(cx, cy, r, sweep, color, 14.0));
        }

        svg.push_str(&format!(
            r#"<text x="{cx}" y="{ty}" text-anchor="middle" font-size="28" font-weight="bold" fill="{dark}">{score:.0}</text>"#,
            cx = cx,
            ty = cy + 6.0,
            dark = BRAND.dark,
            score = score
        ));
        svg.push_str(&format!(
            r#"<text x="{cx}" y="{ty}" text-anchor="middle" font-size="12" fill="{muted}">{label}</text>"#,
            cx = cx,
            ty = cy + r + 22.0,
            muted = BRAND.muted,
            label = label
        ));
    }

    svg.push_str("</svg>");
    Some(svg)
}

/// One half-circle arc from angle 180deg (left) sweeping clockwise by `sweep_deg`,
/// drawn as a stroked path (mirrors matplotlib's polar `ax.plot` gauge trick).
fn gauge_arc(cx: f64, cy: f64, r: f64, sweep_deg: f64, color: &str, stroke: f64) -> String {
    let start_deg = 180.0_f64;
    let end_deg = 180.0 - sweep_deg;
    let (sx, sy) = polar(cx, cy, r, start_deg);
    let (ex, ey) = polar(cx, cy, r, end_deg);
    let large_arc = if sweep_deg > 180.0 { 1 } else { 0 };
    format!(
        r#"<path d="M {sx:.2} {sy:.2} A {r:.2} {r:.2} 0 {large_arc} 1 {ex:.2} {ey:.2}" fill="none" stroke="{color}" stroke-width="{stroke}" stroke-linecap="round"/>"#
    )
}

fn polar(cx: f64, cy: f64, r: f64, deg: f64) -> (f64, f64) {
    let rad = deg.to_radians();
    (cx + r * rad.cos(), cy - r * rad.sin())
}

/// Port of `chart_cwv_distributions`: stacked horizontal bars over the fixed
/// `cwv_order` metric list, each split into good/needs-improvement/poor.
pub fn chart_cwv_distributions(data_with_crux: &Value) -> Option<String> {
    let crux = obj(data_with_crux, "crux");
    let metrics = obj(crux, "metrics");
    let metrics_obj = metrics.as_object()?;
    if metrics_obj.is_empty() {
        return None;
    }

    let cwv_order = [
        "largest_contentful_paint",
        "interaction_to_next_paint",
        "cumulative_layout_shift",
        "first_contentful_paint",
        "experimental_time_to_first_byte",
    ];

    struct Row {
        label: String,
        good: f64,
        ni: f64,
        poor: f64,
    }
    let mut rows = Vec::new();
    for name in cwv_order {
        let Some(m) = metrics.get(name) else { continue };
        if m.get("distribution").is_none() {
            continue;
        }
        let d = obj(m, "distribution");
        rows.push(Row {
            label: get_str_or(m, "label", name),
            good: get_f64_or(d, "good", 0.0),
            ni: get_f64_or(d, "needs_improvement", 0.0),
            poor: get_f64_or(d, "poor", 0.0),
        });
    }
    if rows.is_empty() {
        return None;
    }

    let w = 800u32;
    let row_h = 46.0;
    let top = 20.0;
    let left = 220.0;
    let chart_w = 500.0;
    let h = (top * 2.0 + row_h * rows.len() as f64) as u32;
    let mut svg = svg_open(w, h);

    for (i, row) in rows.iter().enumerate() {
        let y = top + row_h * i as f64;
        let bar_h = 22.0;
        let scale = chart_w / 100.0;
        let good_w = row.good * scale;
        let ni_w = row.ni * scale;
        let poor_w = row.poor * scale;

        svg.push_str(&format!(
            r#"<text x="{lx}" y="{ty}" font-size="12" text-anchor="end" fill="#1e293b">{label}</text>"#,
            lx = left - 10.0,
            ty = y + bar_h / 2.0 + 4.0,
            label = xml_escape(&row.label)
        ));
        svg.push_str(&format!(
            r#"<rect x="{left}" y="{y}" width="{good_w:.1}" height="{bar_h}" fill="{good_c}"/>"#,
            left = left,
            y = y,
            good_c = BRAND.success
        ));
        svg.push_str(&format!(
            r#"<rect x="{x:.1}" y="{y}" width="{ni_w:.1}" height="{bar_h}" fill="{ni_c}"/>"#,
            x = left + good_w,
            y = y,
            ni_c = BRAND.warning
        ));
        svg.push_str(&format!(
            r#"<rect x="{x:.1}" y="{y}" width="{poor_w:.1}" height="{bar_h}" fill="{poor_c}"/>"#,
            x = left + good_w + ni_w,
            y = y,
            poor_c = BRAND.danger
        ));
    }
    svg.push_str("</svg>");
    Some(svg)
}

/// Port of `chart_cwv_timeline`: one line-panel per CWV metric present in
/// `metrics` (from the fixed 3-metric list), each plotting `p75_values` over
/// `collection_periods`, skipping `null` samples, with good/poor threshold bands.
pub fn chart_cwv_timeline(history_data: &Value) -> Option<String> {
    let metrics = obj(history_data, "metrics");
    let periods = arr(history_data, "collection_periods");
    if metrics.as_object().map(|m| m.is_empty()).unwrap_or(true) || periods.is_empty() {
        return None;
    }

    let cwv_metrics = [
        "largest_contentful_paint",
        "interaction_to_next_paint",
        "cumulative_layout_shift",
    ];
    let available: Vec<&str> = cwv_metrics
        .iter()
        .copied()
        .filter(|m| metrics.get(*m).is_some())
        .collect();
    if available.is_empty() {
        return None;
    }

    let w = 900u32;
    let panel_h = 220.0;
    let h = (panel_h * available.len() as f64) as u32;
    let mut svg = svg_open(w, h);
    let left = 70.0;
    let right = 30.0;
    let plot_w = w as f64 - left - right;

    for (panel_i, metric_name) in available.iter().enumerate() {
        let m = obj(metrics, metric_name);
        let p75s = arr(m, "p75_values");
        let label = get_str_or(m, "label", metric_name);
        let good_t = get_f64_or(m, "good_threshold", 0.0);
        let poor_t = get_f64_or(m, "poor_threshold", 0.0);

        let valid: Vec<(usize, f64)> = p75s
            .iter()
            .enumerate()
            .filter_map(|(i, v)| v.as_f64().map(|f| (i, f)))
            .collect();
        if valid.is_empty() {
            continue;
        }

        let panel_top = panel_h * panel_i as f64;
        let plot_top = panel_top + 30.0;
        let plot_h = panel_h - 60.0;
        let max_y = valid
            .iter()
            .map(|(_, v)| *v)
            .fold(poor_t.max(0.0), f64::max)
            .max(1.0);

        svg.push_str(&format!(
            r#"<text x="{left}" y="{ty}" font-size="14" font-weight="bold" fill="{dark}">{label}</text>"#,
            ty = panel_top + 18.0,
            dark = BRAND.dark,
            label = xml_escape(&label)
        ));

        if good_t > 0.0 && poor_t > 0.0 {
            let good_y = plot_top + plot_h * (1.0 - (good_t / max_y));
            let poor_y = plot_top + plot_h * (1.0 - (poor_t / max_y));
            svg.push_str(&format!(
                r#"<rect x="{left}" y="{good_y:.1}" width="{plot_w}" height="{gh:.1}" fill="{success}" opacity="0.1"/>"#,
                gh = (plot_top + plot_h - good_y).max(0.0),
                success = BRAND.success
            ));
            svg.push_str(&format!(
                r#"<rect x="{left}" y="{poor_y:.1}" width="{plot_w}" height="{ph:.1}" fill="{warning}" opacity="0.1"/>"#,
                ph = (good_y - poor_y).max(0.0),
                warning = BRAND.warning
            ));
        }

        let n = periods.len().max(1);
        let mut points = String::new();
        for (i, v) in &valid {
            let x = left + plot_w * (*i as f64 / (n.saturating_sub(1).max(1)) as f64);
            let y = plot_top + plot_h * (1.0 - (*v / max_y));
            points.push_str(&format!("{x:.1},{y:.1} "));
        }
        svg.push_str(&format!(
            r#"<polyline points="{points}" fill="none" stroke="{primary}" stroke-width="2"/>"#,
            primary = BRAND.primary
        ));
    }

    svg.push_str("</svg>");
    Some(svg)
}

/// Port of `chart_top_queries`: top 12 rows by impressions (impressions > 0),
/// suppressed entirely when the max impressions value is below 3 -- matching
/// the Python's `if not impressions or max(impressions) < 3: return ""` gate.
pub fn chart_top_queries(gsc_data: &Value) -> Option<String> {
    let rows = arr(gsc_data, "rows");
    if rows.is_empty() {
        return None;
    }

    let mut sorted: Vec<&Value> = rows;
    sorted.sort_by(|a, b| {
        get_f64_or(b, "impressions", 0.0)
            .partial_cmp(&get_f64_or(a, "impressions", 0.0))
            .unwrap()
    });
    sorted.truncate(12);
    let top: Vec<&Value> = sorted
        .into_iter()
        .filter(|r| get_f64_or(r, "impressions", 0.0) > 0.0)
        .collect();
    if top.is_empty() {
        return None;
    }

    let impressions: Vec<f64> = top.iter().map(|r| get_f64_or(r, "impressions", 0.0)).collect();
    let max_impr = impressions.iter().cloned().fold(0.0_f64, f64::max);
    if max_impr < 3.0 {
        return None;
    }
    let clicks: Vec<f64> = top.iter().map(|r| get_f64_or(r, "clicks", 0.0)).collect();

    let labels: Vec<String> = top
        .iter()
        .map(|r| {
            let q = r
                .get("query")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string())
                .unwrap_or_else(|| {
                    arr(r, "keys")
                        .first()
                        .and_then(|v| v.as_str())
                        .unwrap_or("?")
                        .to_string()
                });
            q.chars().take(35).collect::<String>()
        })
        .collect();

    let w = 700u32;
    let row_h = 24.0;
    let top_pad = 20.0;
    let left = 250.0;
    let chart_w = 380.0;
    let h = (top_pad * 2.0 + row_h * labels.len() as f64) as u32;
    let mut svg = svg_open(w, h);
    let scale = if max_impr > 0.0 { chart_w / max_impr } else { 0.0 };

    for (i, (label, impr)) in labels.iter().zip(impressions.iter()).enumerate() {
        let y = top_pad + row_h * i as f64;
        let bar_h = 14.0;
        let bar_w = impr * scale;
        svg.push_str(&format!(
            r#"<text x="{lx}" y="{ty}" font-size="10" text-anchor="end" fill="#1e293b">{label}</text>"#,
            lx = left - 8.0,
            ty = y + bar_h / 2.0 + 3.0,
            label = xml_escape(label)
        ));
        svg.push_str(&format!(
            r#"<rect x="{left}" y="{y}" width="{bar_w:.1}" height="{bar_h}" fill="{primary}"/>"#,
            primary = BRAND.primary
        ));
        let c = clicks[i];
        if c > 0.0 {
            svg.push_str(&format!(
                r#"<rect x="{left}" y="{y}" width="{cw:.1}" height="{bar_h}" fill="{success}"/>"#,
                cw = c * scale,
                success = BRAND.success
            ));
        }
    }
    svg.push_str("</svg>");
    Some(svg)
}

/// Port of `chart_index_status`: donut chart of pass/fail/neutral/error counts,
/// only including nonzero buckets, in the Python's fixed key/label/color order.
pub fn chart_index_status(inspect_data: &Value) -> Option<String> {
    let summary = obj(inspect_data, "summary");
    if summary.as_object().map(|m| m.is_empty()).unwrap_or(true) {
        return None;
    }

    let buckets = [
        ("pass", "Indexed", BRAND.success),
        ("fail", "Not Indexed", BRAND.danger),
        ("neutral", "Neutral", BRAND.grid),
        ("error", "Error", BRAND.muted),
    ];
    let mut sizes: Vec<(String, f64, &str)> = Vec::new();
    for (key, label, color) in buckets {
        let val = get_f64_or(summary, key, 0.0);
        if val > 0.0 {
            sizes.push((format!("{label} ({val:.0})"), val, color));
        }
    }
    if sizes.is_empty() {
        return None;
    }
    let total: f64 = sizes.iter().map(|(_, v, _)| v).sum();

    let (w, h) = (450u32, 350u32);
    let (cx, cy, r) = (w as f64 / 2.0, h as f64 / 2.0, 130.0);
    let mut svg = svg_open(w, h);

    let mut start_deg = -90.0_f64;
    for (_label, val, color) in &sizes {
        let sweep = (val / total) * 360.0;
        svg.push_str(&donut_wedge(cx, cy, r, start_deg, sweep, color));
        start_deg += sweep;
    }
    // Inner circle punches the donut hole, mirroring the matplotlib `Circle` overlay.
    svg.push_str(&format!(
        r#"<circle cx="{cx}" cy="{cy}" r="{ir}" fill="white"/>"#,
        ir = r * 0.5
    ));
    svg.push_str(&format!(
        r#"<text x="{cx}" y="{ty1}" text-anchor="middle" font-size="20" font-weight="bold" fill="{dark}">{total:.0}</text>"#,
        ty1 = cy - 2.0,
        dark = BRAND.dark
    ));
    svg.push_str(&format!(
        r#"<text x="{cx}" y="{ty2}" text-anchor="middle" font-size="12" fill="{dark}">URLs</text>"#,
        ty2 = cy + 16.0,
        dark = BRAND.dark
    ));

    svg.push_str("</svg>");
    Some(svg)
}

fn donut_wedge(cx: f64, cy: f64, r: f64, start_deg: f64, sweep_deg: f64, color: &str) -> String {
    let (sx, sy) = polar_std(cx, cy, r, start_deg);
    let (ex, ey) = polar_std(cx, cy, r, start_deg + sweep_deg);
    let large_arc = if sweep_deg > 180.0 { 1 } else { 0 };
    format!(
        r#"<path d="M {cx} {cy} L {sx:.2} {sy:.2} A {r} {r} 0 {large_arc} 1 {ex:.2} {ey:.2} Z" fill="{color}"/>"#
    )
}

fn polar_std(cx: f64, cy: f64, r: f64, deg: f64) -> (f64, f64) {
    let rad = deg.to_radians();
    (cx + r * rad.cos(), cy + r * rad.sin())
}

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

// `rating_color` is re-exported for callers that want a per-metric color
// (Python's chart functions don't use it directly today, but `sections.rs`
// does; keep the `use` above from going unused across cfg(test) builds).
#[allow(dead_code)]
fn _uses_rating_color(r: &str) -> &'static str {
    rating_color(r)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn lighthouse_gauges_none_when_empty() {
        assert!(chart_lighthouse_gauges(&json!({})).is_none());
    }

    #[test]
    fn lighthouse_gauges_renders_all_four_labels() {
        let data = json!({"lighthouse_scores": {"performance": 42, "accessibility": 91, "best-practices": 80, "seo": 100}});
        let svg = chart_lighthouse_gauges(&data).unwrap();
        for label in ["Performance", "Accessibility", "Best Practices", "SEO"] {
            assert!(svg.contains(label), "missing {label}");
        }
    }

    #[test]
    fn distributions_none_without_metrics() {
        assert!(chart_cwv_distributions(&json!({"crux": {}})).is_none());
    }

    #[test]
    fn distributions_skips_metrics_without_distribution() {
        let data = json!({"crux": {"metrics": {
            "largest_contentful_paint": {"label": "LCP", "distribution": {"good": 80.0, "needs_improvement": 15.0, "poor": 5.0}},
            "first_contentful_paint": {"label": "FCP"}
        }}});
        let svg = chart_cwv_distributions(&data).unwrap();
        assert!(svg.contains("LCP"));
        assert!(!svg.contains("FCP"));
    }

    #[test]
    fn top_queries_suppressed_below_max_three() {
        let data = json!({"rows": [{"query": "a", "impressions": 2, "clicks": 0}]});
        assert!(chart_top_queries(&data).is_none());
    }

    #[test]
    fn top_queries_sorted_and_truncated_to_twelve() {
        let rows: Vec<Value> = (0..20)
            .map(|i| json!({"query": format!("q{i}"), "impressions": i, "clicks": 0}))
            .collect();
        let data = json!({"rows": rows});
        let svg = chart_top_queries(&data).unwrap();
        assert!(svg.contains("q19</text>"));
        assert!(!svg.contains("q6</text>"));
    }

    #[test]
    fn index_status_only_nonzero_buckets() {
        let data = json!({"summary": {"pass": 5, "fail": 0, "neutral": 2, "error": 0}});
        let svg = chart_index_status(&data).unwrap();
        assert!(svg.contains("Indexed (5)"));
        assert!(svg.contains("Neutral (2)"));
        assert!(!svg.contains("Not Indexed"));
        assert!(!svg.contains("Error ("));
    }

    #[test]
    fn timeline_none_without_periods() {
        let data = json!({"metrics": {"largest_contentful_paint": {}}, "collection_periods": []});
        assert!(chart_cwv_timeline(&data).is_none());
    }

    #[test]
    fn timeline_skips_null_p75_samples() {
        let data = json!({
            "collection_periods": [{"last": "2024-01-01"}, {"last": "2024-01-08"}],
            "metrics": {"largest_contentful_paint": {"label": "LCP", "p75_values": [null, 2500.0], "good_threshold": 2500.0, "poor_threshold": 4000.0}}
        });
        let svg = chart_cwv_timeline(&data).unwrap();
        assert!(svg.contains("LCP"));
        assert!(svg.contains("polyline"));
    }
}
