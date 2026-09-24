//! Port of `google_report.py`'s HTML helpers and section builders:
//! `_img_tag`, `_chart_html`, `_metric_card`, `_build_title_page`, `_build_toc`,
//! `_build_executive_summary`, `_build_cwv_section`, `_build_gsc_section`,
//! `_build_indexation_section`, `_build_recommendations`, `_build_methodology_footer`.
//!
//! Every builder takes `&serde_json::Value` in place of Python's `dict` and
//! returns the same HTML-fragment `String` the Python function returned,
//! built with the same field lookups, defaults, and conditional branches.
//! `chart_paths` is a `HashMap<&str, String>` mapping the same keys the
//! Python `dict` used (`"gauges_path"`, `"distributions_path"`, etc).
//!
//! Deliberate gap: `_build_title_page`'s Google-logo lookup
//! (`Path(__file__).parent.parent / "charts" / "google_logo.png"`) resolves a
//! path relative to the *installed skill's own directory*, not report input
//! data. Porting it verbatim would hardcode a developer-local skill-tree
//! layout into the crate. Ported as a parameter (`google_logo_path: Option<&Path>`)
//! the caller supplies from its own skill-root resolution instead.

use std::collections::HashMap;
use std::path::Path;

use serde_json::Value;

use super::colors::{rating_css_class, score_class, score_color, BRAND};
use super::jget::{arr, get_f64, get_f64_or, get_str, get_str_or, obj, pct0, thousands};

pub type ChartPaths<'a> = HashMap<&'a str, String>;

// ─── HTML Helpers ────────────────────────────────────────────────────────────

/// Port of `_img_tag`.
pub fn img_tag(path: &str, alt: &str) -> String {
    if path.is_empty() {
        return String::new();
    }
    format!(r#"<img src="file://{path}" style="max-width: 100%;" alt="{alt}">"#)
}

/// Port of `_chart_html`.
pub fn chart_html(path: &str, caption: &str, fig_num: u32, alt: &str) -> String {
    if path.is_empty() {
        return String::new();
    }
    format!(
        "    <div class=\"chart-container\">\n      <img src=\"file://{path}\" style=\"width: 85%;\" alt=\"{alt}\">\n      <div class=\"chart-caption\">Figure {fig_num}: {caption}</div>\n    </div>\n"
    )
}

/// Port of `_metric_card`. `value` is pre-formatted by the caller (Python
/// interpolates whatever type it's handed, `int`/`str`/formatted string alike).
pub fn metric_card(value: &str, label: &str, color: Option<&str>) -> String {
    let style = color
        .map(|c| format!(r#" style="color: {c};""#))
        .unwrap_or_default();
    format!(
        "      <div class=\"metric-card\">\n        <div class=\"value\"{style}>{value}</div>\n        <div class=\"label\">{label}</div>\n      </div>\n"
    )
}

// ─── Section Builders ────────────────────────────────────────────────────────

/// Port of `_build_title_page`.
pub fn build_title_page(
    domain: &str,
    report_title: &str,
    _subtitle: &str,
    score: Option<&str>,
    score_label: Option<&str>,
    meta_items: &[String],
    google_logo_path: Option<&Path>,
) -> String {
    let mut score_html = String::new();
    if let Some(score) = score {
        score_html = format!(
            "  <div class=\"score-box\">\n    <div class=\"score-number\">{score}<span style=\"font-size: 20pt; color: #94a3b8;\">/100</span></div>\n    <div class=\"score-label\">{}</div>\n  </div>\n",
            score_label.unwrap_or("Lighthouse Performance Score")
        );
    }

    let mut meta_html = String::new();
    if !meta_items.is_empty() {
        let spans = meta_items
            .iter()
            .map(|item| format!("<span>{item}</span>"))
            .collect::<Vec<_>>()
            .join("\n    ");
        meta_html = format!("  <div class=\"meta\">\n    {spans}\n  </div>\n");
    }

    let mut google_logo_html = String::new();
    if let Some(p) = google_logo_path {
        if p.exists() {
            google_logo_html = format!(
                "  <div style=\"margin-top: 8mm;\">\n    <img src=\"file://{}\" style=\"height: 20px; opacity: 0.7;\" alt=\"Google\">\n    <div style=\"font-size: 7pt; color: #6b7280; margin-top: 2mm;\">Powered by Google APIs</div>\n  </div>\n",
                p.display()
            );
        }
    }

    format!(
        "\n<!-- {bar} TITLE PAGE {tri} -->\n<div class=\"title-page\">\n  <div class=\"badge\">{report_title}</div>\n  <h1>{domain}</h1>\n  <div class=\"subtitle\">Prepared by Claude SEO</div>\n{score_html}{meta_html}{google_logo_html}</div>\n",
        bar = "=".repeat(55),
        tri = "=".repeat(3),
    )
}

pub struct TocSection {
    pub num: u32,
    pub title: String,
    pub score: Option<f64>,
    pub subs: Vec<String>,
}

/// Port of `_build_toc`.
pub fn build_toc(sections: &[TocSection]) -> String {
    let mut items = Vec::new();
    for sec in sections {
        let score_html = sec
            .score
            .map(|s| {
                let cls = score_class(s);
                format!(r#" <span class="toc-score {cls}">{s:.0}</span>"#)
            })
            .unwrap_or_default();
        items.push(format!(
            r#"    <li class="toc-section"><span>{}. {}</span>{score_html}</li>"#,
            sec.num, sec.title
        ));
        for sub in &sec.subs {
            items.push(format!(r#"    <li class="toc-sub"><span>{sub}</span></li>"#));
        }
    }
    let items_html = items.join("\n");
    format!(
        "\n<!-- {bar} TABLE OF CONTENTS {tri} -->\n<div class=\"toc-page\">\n  <h2>Table of Contents</h2>\n  <ul class=\"toc-list\">\n{items_html}\n  </ul>\n</div>\n",
        bar = "=".repeat(55),
        tri = "=".repeat(3),
    )
}

/// Resolves `data.psi.psi.mobile` falling back to `data.psi` itself, mirroring
/// `psi.get("psi", {}).get("mobile", psi)` (`mobile = psi` when either hop is missing).
fn resolve_mobile(psi: &Value) -> Value {
    if !psi.is_object() {
        return Value::Object(Default::default());
    }
    let inner_psi = obj(psi, "psi");
    inner_psi.get("mobile").cloned().unwrap_or_else(|| psi.clone())
}

/// Port of `_build_executive_summary`.
pub fn build_executive_summary(domain: &str, timestamp: &str, data: &Value) -> String {
    let mut lines: Vec<String> = Vec::new();
    lines.push(format!(
        "\n<!-- {} 1. EXECUTIVE SUMMARY {} -->",
        "=".repeat(55),
        "=".repeat(3)
    ));
    lines.push("<div class=\"section\">".into());
    lines.push("  <div class=\"section-header\">".into());
    lines.push("    <h2>1. Executive Summary</h2>".into());
    lines.push("  </div>".into());
    lines.push(String::new());

    lines.push(format!(
        "  <p>This report presents a comprehensive Google SEO analysis of <strong>{domain}</strong>, generated on {timestamp}. Data was collected from Google PageSpeed Insights, Chrome User Experience Report (CrUX), Google Search Console, and the URL Inspection API as available.</p>"
    ));
    lines.push(String::new());

    let psi = obj(data, "psi");
    let mobile = resolve_mobile(psi);
    let mobile = &mobile;
    let lighthouse = obj(mobile, "lighthouse_scores");

    struct Card {
        value: String,
        label: &'static str,
        color: String,
    }
    let mut cards: Vec<Card> = Vec::new();

    if let Some(perf) = get_f64(lighthouse, "performance") {
        cards.push(Card {
            value: format!("{perf:.0}/100"),
            label: "Lighthouse Performance",
            color: score_color(perf).to_string(),
        });
    }
    if let Some(seo) = get_f64(lighthouse, "seo") {
        cards.push(Card {
            value: format!("{seo:.0}/100"),
            label: "Lighthouse SEO",
            color: score_color(seo).to_string(),
        });
    }

    let gsc = obj(data, "gsc");
    let totals = obj(gsc, "totals");
    if !totals.as_object().map(|m| m.is_empty()).unwrap_or(true) {
        cards.push(Card {
            value: thousands(totals.get("clicks").and_then(|v| v.as_i64()).unwrap_or(0)),
            label: "Total Clicks",
            color: BRAND.primary.to_string(),
        });
        cards.push(Card {
            value: thousands(totals.get("impressions").and_then(|v| v.as_i64()).unwrap_or(0)),
            label: "Impressions",
            color: BRAND.secondary.to_string(),
        });
    }

    let inspection = obj(data, "inspection");
    let summary = obj(inspection, "summary");
    if !summary.as_object().map(|m| m.is_empty()).unwrap_or(true) {
        let indexed = get_f64_or(summary, "pass", 0.0);
        let total = get_f64_or(inspection, "total", 0.0);
        cards.push(Card {
            value: format!("{indexed:.0}/{total:.0}"),
            label: "Indexed URLs",
            color: BRAND.success.to_string(),
        });
    }

    if !cards.is_empty() {
        let col_class = if cards.len() >= 4 { "four-col" } else { "two-col" };
        lines.push(format!("  <div class=\"{col_class}\">"));
        for c in cards.iter().take(5) {
            lines.push("    <div class=\"col\">".into());
            lines.push(metric_card(&c.value, c.label, Some(&c.color)));
            lines.push("    </div>".into());
        }
        lines.push("  </div>".into());
        lines.push(String::new());
    }

    // Critical issues box.
    let mut issues: Vec<String> = Vec::new();
    let failed_audits = arr(mobile, "failed_audits");
    if !failed_audits.is_empty() {
        let mut sorted = failed_audits.clone();
        sorted.sort_by(|a, b| {
            get_f64_or(a, "score", 1.0)
                .partial_cmp(&get_f64_or(b, "score", 1.0))
                .unwrap()
        });
        for a in sorted.iter().take(3) {
            issues.push(format!(
                "<strong>{}</strong> (score: {})",
                get_str_or(a, "title", "Unknown"),
                pct0(get_f64_or(a, "score", 0.0))
            ));
        }
    }

    let seo_audits = arr(mobile, "seo_audits");
    let seo_failed: Vec<&Value> = seo_audits
        .iter()
        .filter(|a| !a.get("pass").and_then(|v| v.as_bool()).unwrap_or(false))
        .copied()
        .collect();
    for a in seo_failed.iter().take(2) {
        issues.push(format!(
            "<strong>SEO:</strong> {}",
            get_str_or(a, "title", "Unknown")
        ));
    }

    let inspect_fails = get_f64_or(summary, "fail", 0.0);
    if inspect_fails > 0.0 {
        issues.push(format!("<strong>{inspect_fails:.0} URL(s)</strong> not indexed"));
    }

    if !issues.is_empty() {
        let issue_items = issues
            .iter()
            .take(5)
            .map(|i| format!("      <li>{i}</li>"))
            .collect::<Vec<_>>()
            .join("\n");
        lines.push("  <div class=\"critical-box\">".into());
        lines.push("    <strong>Critical Issues Found:</strong>".into());
        lines.push("    <ol>".into());
        lines.push(issue_items);
        lines.push("    </ol>".into());
        lines.push("  </div>".into());
        lines.push(String::new());
    }

    // Quick wins box.
    let mut wins: Vec<String> = Vec::new();
    let qw = arr(gsc, "quick_wins");
    if !qw.is_empty() {
        wins.push(format!(
            "{} search queries at positions 4-10 with high impressions (small ranking bump = significant traffic)",
            qw.len()
        ));
    }
    let opps = arr(mobile, "opportunities");
    for o in opps.iter().take(3) {
        let savings = get_f64_or(o, "savings_ms", 0.0);
        if savings != 0.0 {
            wins.push(format!(
                "{}: save ~{savings:.0}ms",
                get_str_or(o, "title", "Optimization")
            ));
        }
    }
    if !wins.is_empty() {
        let win_items = wins
            .iter()
            .take(5)
            .map(|w| format!("      <li>{w}</li>"))
            .collect::<Vec<_>>()
            .join("\n");
        lines.push("  <div class=\"success-box\">".into());
        lines.push("    <strong>Quick Wins:</strong>".into());
        lines.push("    <ol>".into());
        lines.push(win_items);
        lines.push("    </ol>".into());
        lines.push("  </div>".into());
        lines.push(String::new());
    }

    lines.push("</div>".into());
    lines.join("\n")
}

/// Port of `_build_cwv_section`. Returns `(html, next_fig_num)` mirroring the
/// Python's `(html, fig_counter[0])` return.
pub fn build_cwv_section(
    psi_data: &Value,
    crux_data: &Value,
    chart_paths: &ChartPaths,
    history_data: Option<&Value>,
    section_num: u32,
) -> (String, u32) {
    let mut fig = 1u32;
    let mut lines: Vec<String> = Vec::new();
    lines.push(format!(
        "\n<!-- {} {section_num}. CORE WEB VITALS {} -->",
        "=".repeat(55),
        "=".repeat(3)
    ));
    lines.push("<div class=\"section\">".into());
    lines.push("  <div class=\"section-header\">".into());
    lines.push(format!(
        "    <h2>{section_num}. Core Web Vitals &amp; Performance</h2>"
    ));

    let mobile = resolve_mobile(psi_data);
    let mobile = &mobile;
    let scores = obj(mobile, "lighthouse_scores");
    if let Some(perf) = get_f64(scores, "performance") {
        let color = score_color(perf);
        lines.push(format!(
            "    <div class=\"section-score\" style=\"color: {color};\">{perf:.0}/100</div>"
        ));
    }
    lines.push("  </div>".into());
    lines.push(String::new());

    // 2.1 Lighthouse Scores.
    let has_scores = !scores.as_object().map(|m| m.is_empty()).unwrap_or(true);
    if has_scores {
        lines.push(format!("  <h3>{section_num}.1 Lighthouse Scores</h3>"));
        lines.push(String::new());
        let gauges_path = chart_paths.get("gauges_path").cloned().unwrap_or_default();
        lines.push(chart_html(
            &gauges_path,
            "Lighthouse audit scores across Performance, Accessibility, Best Practices, and SEO.",
            { let f = fig; fig += 1; f },
            "Lighthouse gauge scores",
        ));

        lines.push("  <table>".into());
        lines.push("    <thead>".into());
        lines.push("      <tr><th>Category</th><th>Score</th><th>Rating</th></tr>".into());
        lines.push("    </thead>".into());
        lines.push("    <tbody>".into());
        for (key, label) in [
            ("performance", "Performance"),
            ("accessibility", "Accessibility"),
            ("best-practices", "Best Practices"),
            ("seo", "SEO"),
        ] {
            if let Some(s) = get_f64(scores, key) {
                let cls = if s >= 90.0 {
                    "status-pass"
                } else if s >= 50.0 {
                    "status-warn"
                } else {
                    "status-fail"
                };
                let rating = if s >= 90.0 {
                    "Good"
                } else if s >= 50.0 {
                    "Needs Work"
                } else {
                    "Poor"
                };
                lines.push(format!(
                    "      <tr><td>{label}</td><td class=\"{cls}\">{s:.0}</td><td>{rating}</td></tr>"
                ));
            }
        }
        lines.push("    </tbody>".into());
        lines.push("  </table>".into());
        lines.push(String::new());
    }

    lines.push("  <hr class=\"divider\">".into());

    // 2.2 Lab Metrics.
    let lab = obj(mobile, "lab_metrics");
    if let Some(lab_obj) = lab.as_object() {
        if !lab_obj.is_empty() {
            lines.push(format!("  <h3>{section_num}.2 Lab Metrics (Simulated)</h3>"));
            lines.push("  <table>".into());
            lines.push("    <thead>".into());
            lines.push(
                "      <tr><th>Metric</th><th>Value</th><th>Score</th><th>Threshold</th></tr>"
                    .into(),
            );
            lines.push("    </thead>".into());
            lines.push("    <tbody>".into());
            let labels: HashMap<&str, &str> = HashMap::from([
                ("first-contentful-paint", "First Contentful Paint (FCP)"),
                ("largest-contentful-paint", "Largest Contentful Paint (LCP)"),
                ("total-blocking-time", "Total Blocking Time (TBT)"),
                ("cumulative-layout-shift", "Cumulative Layout Shift (CLS)"),
                ("speed-index", "Speed Index"),
                ("interactive", "Time to Interactive (TTI)"),
            ]);
            let thresholds: HashMap<&str, &str> = HashMap::from([
                ("first-contentful-paint", "\u{2264} 1.8s"),
                ("largest-contentful-paint", "\u{2264} 2.5s"),
                ("total-blocking-time", "\u{2264} 200ms"),
                ("cumulative-layout-shift", "\u{2264} 0.1"),
                ("speed-index", "\u{2264} 3.4s"),
                ("interactive", "\u{2264} 3.8s"),
            ]);
            for (k, v) in lab_obj {
                let score_val = v.get("score").and_then(|s| s.as_f64());
                let score_pct = score_val.map(pct0).unwrap_or_else(|| "N/A".into());
                let cls = match score_val {
                    Some(s) if s >= 0.9 => "status-pass",
                    Some(s) if s >= 0.5 => "status-warn",
                    _ => "status-fail",
                };
                let label = labels
                    .get(k.as_str())
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| title_case(&k.replace('-', " ")));
                let threshold = thresholds.get(k.as_str()).copied().unwrap_or("\u{2014}");
                let display = get_str(v, "display");
                lines.push(format!(
                    "      <tr><td>{label}</td><td>{display}</td><td class=\"{cls}\">{score_pct}</td><td>{threshold}</td></tr>"
                ));
            }
            lines.push("    </tbody>".into());
            lines.push("  </table>".into());
            lines.push(String::new());
        }
    }

    // 2.3 CrUX Field Data.
    let crux_metrics = obj(crux_data, "metrics");
    let has_crux_history_metric = history_data.map(|h| h.get("error").is_none()).unwrap_or(false);
    if let Some(cm) = crux_metrics.as_object() {
        if !cm.is_empty() {
            lines.push(format!(
                "  <h3>{section_num}.3 CrUX Field Data (28-day Rolling Average)</h3>"
            ));
            lines.push(String::new());
            let dist_path = chart_paths
                .get("distributions_path")
                .cloned()
                .unwrap_or_default();
            lines.push(chart_html(
                &dist_path,
                "Core Web Vitals field data distribution across Good, Needs Improvement, and Poor buckets.",
                { let f = fig; fig += 1; f },
                "CWV distribution chart",
            ));

            lines.push("  <table>".into());
            lines.push("    <thead>".into());
            lines.push(
                "      <tr><th>Metric</th><th>p75</th><th>Rating</th><th>Good %</th><th>NI %</th><th>Poor %</th></tr>"
                    .into(),
            );
            lines.push("    </thead>".into());
            lines.push("    <tbody>".into());
            for (name, m) in cm {
                let rating = get_str_or(m, "rating", "?");
                let dist = obj(m, "distribution");
                let unit = get_str(m, "unit");
                let p75 = m.get("p75");
                let display_val = if name == "cumulative_layout_shift" {
                    p75.and_then(|v| v.as_f64())
                        .map(|v| format!("{v:.3}"))
                        .unwrap_or_else(|| "?".into())
                } else {
                    format!(
                        "{}{unit}",
                        p75.map(json_display).unwrap_or_else(|| "?".into())
                    )
                };
                let cls = rating_css_class(&rating);
                lines.push(format!(
                    "      <tr><td>{}</td><td>{display_val}</td>",
                    get_str_or(m, "label", name)
                ));
                lines.push(format!("      <td class=\"{cls}\">{}</td>", rating.to_uppercase()));
                lines.push(format!(
                    "      <td>{}%</td><td>{}%</td><td>{}%</td></tr>",
                    dist.get("good").map(json_display).unwrap_or_else(|| "N/A".into()),
                    dist.get("needs_improvement").map(json_display).unwrap_or_else(|| "N/A".into()),
                    dist.get("poor").map(json_display).unwrap_or_else(|| "N/A".into()),
                ));
            }
            lines.push("    </tbody>".into());
            lines.push("  </table>".into());

            let cp = obj(crux_data, "collection_period");
            if !cp.as_object().map(|m| m.is_empty()).unwrap_or(true) {
                lines.push(format!(
                    "  <p class=\"data-freshness\">Collection period: {} to {}. CrUX data is a 28-day rolling average updated daily ~04:00 UTC.</p>",
                    get_str_or(cp, "first", "?"),
                    get_str_or(cp, "last", "?"),
                ));
            }
            lines.push(String::new());
        }
    } else if crux_data.get("error").is_some() {
        lines.push(format!("  <h3>{section_num}.3 CrUX Field Data</h3>"));
        lines.push(format!(
            "  <div class=\"highlight\"><strong>CrUX Field Data:</strong> {}</div>",
            get_str(crux_data, "error")
        ));
        lines.push(String::new());
    }

    // CrUX History timeline.
    if let Some(history) = history_data {
        if has_crux_history_metric {
            lines.push(format!(
                "  <h3>{section_num}.4 Core Web Vitals Trends (25-week)</h3>"
            ));
            let timeline_path = chart_paths.get("timeline_path").cloned().unwrap_or_default();
            lines.push(chart_html(
                &timeline_path,
                "CrUX p75 values over 25 weeks with Good/Poor threshold bands.",
                { let f = fig; fig += 1; f },
                "CWV timeline trends",
            ));

            let trends = obj(history, "trends");
            if let Some(t_obj) = trends.as_object() {
                if !t_obj.is_empty() {
                    lines.push("  <table>".into());
                    lines.push("    <thead>".into());
                    lines.push(
                        "      <tr><th>Metric</th><th>Direction</th><th>Change</th><th>Earliest Avg</th><th>Latest Avg</th></tr>"
                            .into(),
                    );
                    lines.push("    </thead>".into());
                    lines.push("    <tbody>".into());
                    for (name, t) in t_obj {
                        let direction = get_str_or(t, "direction", "?");
                        let cls = match direction.as_str() {
                            "improving" => "status-pass",
                            "degrading" => "status-fail",
                            _ => "",
                        };
                        let change = get_f64_or(t, "change_pct", 0.0);
                        let sign = if change >= 0.0 { "+" } else { "" };
                        lines.push(format!(
                            "      <tr><td>{}</td><td class=\"{cls}\">{}</td>",
                            get_str_or(t, "label", name),
                            direction.to_uppercase()
                        ));
                        lines.push(format!(
                            "      <td>{sign}{change:.1}%</td><td>{}</td><td>{}</td></tr>",
                            t.get("earliest_avg").map(json_display).unwrap_or_else(|| "?".into()),
                            t.get("latest_avg").map(json_display).unwrap_or_else(|| "?".into()),
                        ));
                    }
                    lines.push("    </tbody>".into());
                    lines.push("  </table>".into());
                }
            }
            lines.push(String::new());
        }
    }

    // Failed audits.
    let failed = arr(mobile, "failed_audits");
    if !failed.is_empty() {
        let sub = if has_crux_history_metric {
            format!("{section_num}.5")
        } else {
            format!("{section_num}.4")
        };
        lines.push(format!("  <h3>{sub} Failed / Warning Audits ({})</h3>", failed.len()));
        lines.push("  <table>".into());
        lines.push("    <thead>".into());
        lines.push("      <tr><th>Audit</th><th>Score</th><th>Details</th></tr>".into());
        lines.push("    </thead>".into());
        lines.push("    <tbody>".into());
        for a in failed.iter().take(20) {
            let score_pct = get_f64(a, "score").map(pct0).unwrap_or_else(|| "?".into());
            lines.push(format!(
                "      <tr><td>{}</td><td class=\"status-fail\">{score_pct}</td><td>{}</td></tr>",
                get_str(a, "title"),
                get_str(a, "display"),
            ));
        }
        lines.push("    </tbody>".into());
        lines.push("  </table>".into());
        lines.push(String::new());
    }

    // SEO audit checks.
    let seo_audits = arr(mobile, "seo_audits");
    if !seo_audits.is_empty() {
        let seo_failed: Vec<&Value> = seo_audits
            .iter()
            .filter(|a| !a.get("pass").and_then(|v| v.as_bool()).unwrap_or(false))
            .copied()
            .collect();
        if !seo_failed.is_empty() {
            lines.push(format!("  <h3>SEO Audit Issues ({})</h3>", seo_failed.len()));
            for a in &seo_failed {
                lines.push("  <div class=\"action-item critical\">".into());
                lines.push(format!("    <h4>{}</h4>", get_str(a, "title")));
                lines.push("  </div>".into());
            }
        } else {
            lines.push(format!(
                "  <div class=\"success-box\"><strong>SEO:</strong> All {} Lighthouse SEO checks passed.</div>",
                seo_audits.len()
            ));
        }
        lines.push(String::new());
    }

    // Accessibility issues.
    let a11y = arr(mobile, "accessibility_audits");
    if !a11y.is_empty() {
        lines.push(format!("  <h3>Accessibility Issues ({})</h3>", a11y.len()));
        lines.push("  <table>".into());
        lines.push("    <thead>".into());
        lines.push("      <tr><th>Issue</th><th>Score</th></tr>".into());
        lines.push("    </thead>".into());
        lines.push("    <tbody>".into());
        for a in &a11y {
            lines.push(format!(
                "      <tr><td>{}</td><td class=\"status-fail\">{}</td></tr>",
                get_str(a, "title"),
                pct0(get_f64_or(a, "score", 0.0)),
            ));
        }
        lines.push("    </tbody>".into());
        lines.push("  </table>".into());
        lines.push(String::new());
    }

    // Opportunities.
    let opps = arr(mobile, "opportunities");
    if !opps.is_empty() {
        lines.push(format!("  <h3>Optimization Opportunities ({})</h3>", opps.len()));
        lines.push("  <table>".into());
        lines.push("    <thead>".into());
        lines.push("      <tr><th>Opportunity</th><th>Estimated Savings</th></tr>".into());
        lines.push("    </thead>".into());
        lines.push("    <tbody>".into());
        for o in &opps {
            lines.push(format!(
                "      <tr><td>{}</td><td>{:.0}ms</td></tr>",
                get_str(o, "title"),
                get_f64_or(o, "savings_ms", 0.0)
            ));
        }
        lines.push("    </tbody>".into());
        lines.push("  </table>".into());
        lines.push(String::new());
    }

    lines.push("</div>".into());
    (lines.join("\n"), fig)
}

/// Port of `_build_gsc_section`.
pub fn build_gsc_section(
    gsc_data: &Value,
    chart_paths: &ChartPaths,
    section_num: u32,
    fig_start: u32,
) -> (String, u32) {
    let mut fig = fig_start;
    let mut lines: Vec<String> = Vec::new();
    lines.push(format!(
        "\n<!-- {} {section_num}. SEARCH PERFORMANCE {} -->",
        "=".repeat(55),
        "=".repeat(3)
    ));
    lines.push("<div class=\"section\">".into());
    lines.push("  <div class=\"section-header\">".into());
    lines.push(format!("    <h2>{section_num}. Search Console Performance</h2>"));
    lines.push("  </div>".into());
    lines.push(String::new());

    let totals = obj(gsc_data, "totals");
    let dr = obj(gsc_data, "date_range");

    if !totals.as_object().map(|m| m.is_empty()).unwrap_or(true) {
        let domain = get_str_or(gsc_data, "property", "?");
        lines.push(format!(
            "  <p>Period: {} to {} | Property: {domain}</p>",
            get_str_or(dr, "start", "?"),
            get_str_or(dr, "end", "?"),
        ));
        let queries_count = get_f64_or(gsc_data, "row_count", 0.0);
        let impr_total = totals.get("impressions").and_then(|v| v.as_i64()).unwrap_or(0);
        lines.push(format!(
            "  <p><strong>{domain}</strong> appeared in <strong>{queries_count:.0}</strong> unique search queries with <strong>{}</strong> total impressions during this period.</p>",
            thousands(impr_total)
        ));
        lines.push(String::new());

        let clicks_val = thousands(totals.get("clicks").and_then(|v| v.as_i64()).unwrap_or(0));
        let impr_val = thousands(impr_total);
        let ctr_val = format!("{}%", totals.get("ctr").map(json_display).unwrap_or_else(|| "0".into()));
        let rows_val = format!("{:.0}", get_f64_or(gsc_data, "row_count", 0.0));

        lines.push(format!("  <h3>{section_num}.1 Key Metrics</h3>"));
        lines.push("  <div class=\"four-col\">".into());
        lines.push(format!(
            "    <div class=\"col\">{}</div>",
            metric_card(&clicks_val, "Total Clicks", Some(BRAND.primary))
        ));
        lines.push(format!(
            "    <div class=\"col\">{}</div>",
            metric_card(&impr_val, "Total Impressions", Some(BRAND.secondary))
        ));
        lines.push(format!(
            "    <div class=\"col\">{}</div>",
            metric_card(&ctr_val, "Average CTR", Some(BRAND.accent))
        ));
        lines.push(format!(
            "    <div class=\"col\">{}</div>",
            metric_card(&rows_val, "Queries Found", Some(BRAND.dark))
        ));
        lines.push("  </div>".into());
        lines.push("  <hr class=\"divider\">".into());
        lines.push(String::new());
    }

    let queries_path = chart_paths.get("top_queries_path").cloned().unwrap_or_default();
    if !queries_path.is_empty() {
        lines.push(format!("  <h3>{section_num}.2 Top Queries by Impressions</h3>"));
        lines.push(chart_html(
            &queries_path,
            "Top search queries ranked by impression volume from Google Search Console (28-day period).",
            { let f = fig; fig += 1; f },
            "Top queries bar chart",
        ));
    }

    let rows = arr(gsc_data, "rows");
    if !rows.is_empty() {
        lines.push(format!("  <h3>{section_num}.3 Query Detail Table</h3>"));
        lines.push("  <table>".into());
        lines.push("    <thead>".into());
        lines.push(
            "      <tr><th>#</th><th>Query</th><th>Clicks</th><th>Impressions</th><th>CTR</th><th>Position</th></tr>"
                .into(),
        );
        lines.push("    </thead>".into());
        lines.push("    <tbody>".into());
        let mut sorted = rows.clone();
        sorted.sort_by(|a, b| {
            get_f64_or(b, "impressions", 0.0)
                .partial_cmp(&get_f64_or(a, "impressions", 0.0))
                .unwrap()
        });
        for (i, r) in sorted.iter().take(15).enumerate() {
            let query = r
                .get("query")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string())
                .unwrap_or_else(|| {
                    arr(r, "keys").first().and_then(|v| v.as_str()).unwrap_or("?").to_string()
                });
            let pos = get_f64_or(r, "position", 0.0);
            let pos_cls = if pos <= 3.0 {
                "status-pass"
            } else if pos <= 10.0 {
                "status-warn"
            } else {
                "status-fail"
            };
            lines.push(format!(
                "      <tr><td>{}</td><td>{query}</td><td>{:.0}</td><td>{}</td>",
                i + 1,
                get_f64_or(r, "clicks", 0.0),
                thousands(get_f64_or(r, "impressions", 0.0) as i64),
            ));
            lines.push(format!(
                "      <td>{}%</td><td class=\"{pos_cls}\">{pos:.1}</td></tr>",
                r.get("ctr").map(json_display).unwrap_or_else(|| "0".into())
            ));
        }
        lines.push("    </tbody>".into());
        lines.push("  </table>".into());
        lines.push(String::new());
    }

    if !rows.is_empty() {
        let top3 = rows.iter().filter(|r| get_f64_or(r, "position", 99.0) <= 3.0).count();
        let top10 = rows.iter().filter(|r| get_f64_or(r, "position", 99.0) <= 10.0).count();
        let beyond = rows.iter().filter(|r| get_f64_or(r, "position", 99.0) > 10.0).count();
        lines.push(format!("  <h3>{section_num}.4 Query Position Analysis</h3>"));
        lines.push("  <div class=\"two-col\">".into());
        lines.push("    <div class=\"col\">".into());
        lines.push(metric_card(&top3.to_string(), "Queries in Top 3", Some(BRAND.success)));
        lines.push("    </div>".into());
        lines.push("    <div class=\"col\">".into());
        lines.push(metric_card(&top10.to_string(), "Queries in Top 10", Some(BRAND.warning)));
        lines.push("    </div>".into());
        lines.push("  </div>".into());
        if beyond > 0 {
            lines.push(format!(
                "  <p>{beyond} queries rank beyond position 10 and may benefit from content optimization.</p>"
            ));
        }
        lines.push(String::new());
    }

    let qw = arr(gsc_data, "quick_wins");
    if !qw.is_empty() {
        lines.push(format!("  <h3>{section_num}.5 Quick Wins ({} opportunities)</h3>", qw.len()));
        lines.push("  <div class=\"highlight\">These queries rank at position 4-10 with high impressions. A small ranking improvement could yield significant traffic gains.</div>".into());
        lines.push("  <table>".into());
        lines.push("    <thead>".into());
        lines.push(
            "      <tr><th>Query</th><th>Position</th><th>Impressions</th><th>Clicks</th></tr>".into(),
        );
        lines.push("    </thead>".into());
        lines.push("    <tbody>".into());
        for w in &qw {
            let keys = arr(w, "keys");
            let query = if !keys.is_empty() {
                keys[0].as_str().unwrap_or("?").to_string()
            } else {
                get_str_or(w, "query", "?")
            };
            lines.push(format!(
                "      <tr><td>{query}</td><td>{:.1}</td><td>{}</td><td>{:.0}</td></tr>",
                get_f64_or(w, "position", 0.0),
                thousands(get_f64_or(w, "impressions", 0.0) as i64),
                get_f64_or(w, "clicks", 0.0),
            ));
        }
        lines.push("    </tbody>".into());
        lines.push("  </table>".into());
        lines.push(String::new());
    }

    lines.push("  <p class=\"data-freshness\">Search Analytics data has a 2-3 day lag. Data available for ~16 months.</p>".into());
    lines.push("</div>".into());
    (lines.join("\n"), fig)
}

/// Port of `_build_indexation_section`.
pub fn build_indexation_section(
    inspect_data: &Value,
    chart_paths: &ChartPaths,
    section_num: u32,
    fig_start: u32,
) -> (String, u32) {
    let mut fig = fig_start;
    let mut lines: Vec<String> = Vec::new();
    lines.push(format!(
        "\n<!-- {} {section_num}. INDEXATION STATUS {} -->",
        "=".repeat(55),
        "=".repeat(3)
    ));
    lines.push("<div class=\"section\">".into());
    lines.push("  <div class=\"section-header\">".into());
    lines.push(format!("    <h2>{section_num}. Indexation Status</h2>"));
    lines.push("  </div>".into());
    lines.push(String::new());

    let summary = obj(inspect_data, "summary");
    let total = get_f64_or(inspect_data, "total", 0.0);

    if !summary.as_object().map(|m| m.is_empty()).unwrap_or(true) {
        let idx_path = chart_paths.get("index_status_path").cloned().unwrap_or_default();
        if !idx_path.is_empty() {
            let fig_n = { let f = fig; fig += 1; f };
            lines.push(format!("  <h3>{section_num}.1 Index Coverage Overview</h3>"));
            lines.push("    <div class=\"chart-container\">".into());
            lines.push(format!(
                "      <img src=\"file://{idx_path}\" style=\"width: 70%;\" alt=\"Index status donut chart\">"
            ));
            lines.push(format!(
                "      <div class=\"chart-caption\">Figure {fig_n}: URL indexation status distribution from Google URL Inspection API.</div>"
            ));
            lines.push("    </div>".into());
        }

        lines.push(format!("  <p>Total URLs inspected: <strong>{total:.0}</strong></p>"));
        lines.push("  <div class=\"two-col\">".into());
        lines.push("    <div class=\"col\">".into());
        lines.push(metric_card(
            &format!("{:.0}", get_f64_or(summary, "pass", 0.0)),
            "Indexed",
            Some(BRAND.success),
        ));
        lines.push("    </div>".into());
        lines.push("    <div class=\"col\">".into());
        lines.push(metric_card(
            &format!("{:.0}", get_f64_or(summary, "fail", 0.0)),
            "Not Indexed",
            Some(BRAND.danger),
        ));
        lines.push("    </div>".into());
        lines.push("  </div>".into());
        lines.push(String::new());

        let indexed = get_f64_or(summary, "pass", 0.0);
        if total > 0.0 {
            let rate = ((indexed / total) * 100.0 * 10.0).round() / 10.0;
            lines.push(format!(
                "  <p><strong>Index Rate:</strong> {rate}% of inspected URLs are indexed by Google.</p>"
            ));
        }
        if total > 0.0 && indexed > 0.0 {
            let pct = (indexed / total) * 100.0;
            let cls = if pct >= 90.0 {
                "success-box"
            } else if pct >= 70.0 {
                "highlight"
            } else {
                "critical-box"
            };
            lines.push(format!(
                "  <div class=\"{cls}\"><strong>Index Rate:</strong> {pct:.0}% of inspected URLs are indexed.</div>"
            ));
            lines.push(String::new());
        }
    }

    let results = arr(inspect_data, "results");
    if !results.is_empty() {
        lines.push(format!("  <h3>{section_num}.2 Per-URL Results</h3>"));
        lines.push("  <table>".into());
        lines.push("    <thead>".into());
        lines.push(
            "      <tr><th>URL</th><th>Verdict</th><th>Coverage State</th><th>Last Crawl</th></tr>"
                .into(),
        );
        lines.push("    </thead>".into());
        lines.push("    <tbody>".into());
        for r in &results {
            let verdict = get_str_or(r, "verdict", "?");
            let cls = match verdict.as_str() {
                "PASS" => "status-pass",
                "FAIL" => "status-fail",
                _ => "",
            };
            let idx = obj(r, "index_status");
            let cov = idx
                .get("coverage_state")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string())
                .unwrap_or_else(|| get_str_or(r, "error", "N/A"));
            let mut crawl = get_str_or(idx, "last_crawl_time", "N/A");
            if crawl != "N/A" {
                crawl = crawl.chars().take(10).collect();
            }
            let url_display = get_str_or(r, "url", "?");
            lines.push(format!(
                "      <tr><td style=\"word-break:break-all;font-size:8pt;\">{url_display}</td>"
            ));
            lines.push(format!(
                "      <td class=\"{cls}\">{verdict}</td><td>{cov}</td><td>{crawl}</td></tr>"
            ));
        }
        lines.push("    </tbody>".into());
        lines.push("  </table>".into());
        lines.push(String::new());
    }

    let rich = arr(inspect_data, "rich_results");
    if !rich.is_empty() {
        lines.push(format!("  <h3>{section_num}.3 Rich Results Detected</h3>"));
        lines.push("  <table>".into());
        lines.push("    <thead>".into());
        lines.push("      <tr><th>URL</th><th>Rich Result Type</th></tr>".into());
        lines.push("    </thead>".into());
        lines.push("    <tbody>".into());
        for rr in &rich {
            lines.push(format!(
                "      <tr><td style=\"word-break:break-all;font-size:8pt;\">{}</td><td>{}</td></tr>",
                get_str_or(rr, "url", "?"),
                get_str_or(rr, "type", "?"),
            ));
        }
        lines.push("    </tbody>".into());
        lines.push("  </table>".into());
        lines.push(String::new());
    }

    lines.push("  <p class=\"data-freshness\">URL Inspection API: 2,000 inspections/day per property.</p>".into());
    lines.push("</div>".into());
    (lines.join("\n"), fig)
}

/// Port of `_build_recommendations`.
pub fn build_recommendations(data: &Value, section_num: u32) -> String {
    let mut lines: Vec<String> = Vec::new();
    lines.push(format!(
        "\n<!-- {} {section_num}. RECOMMENDATIONS {} -->",
        "=".repeat(55),
        "=".repeat(3)
    ));
    lines.push("<div class=\"section\">".into());
    lines.push("  <div class=\"section-header\">".into());
    lines.push(format!("    <h2>{section_num}. Recommendations</h2>"));
    lines.push("  </div>".into());
    lines.push(String::new());
    lines.push("  <p>Prioritized action items based on the data collected. Items are ranked by expected impact on search visibility and user experience.</p>".into());
    lines.push(String::new());

    let mut item_num = 0u32;

    let psi = obj(data, "psi");
    let mobile = resolve_mobile(psi);
    let mobile = &mobile;

    let mut critical_items: Vec<(String, &'static str, String)> = Vec::new();
    let perf = get_f64(obj(mobile, "lighthouse_scores"), "performance");
    if let Some(perf) = perf {
        if perf < 50.0 {
            critical_items.push((
                "Improve Lighthouse Performance Score".into(),
                "Medium (2-4 hrs)",
                format!(
                    "Current score is {perf:.0}/100. Focus on reducing Largest Contentful Paint and Total Blocking Time. Defer non-critical JavaScript and optimize images."
                ),
            ));
        }
    }

    let seo_audits = arr(mobile, "seo_audits");
    let seo_failed: Vec<&Value> = seo_audits
        .iter()
        .filter(|a| !a.get("pass").and_then(|v| v.as_bool()).unwrap_or(false))
        .copied()
        .collect();
    for a in seo_failed.iter().take(2) {
        critical_items.push((
            format!("Fix SEO Issue: {}", get_str_or(a, "title", "Unknown")),
            "Low (30 min)",
            "This Lighthouse SEO check is failing. Address it to ensure proper crawling and indexing by search engines.".into(),
        ));
    }

    let inspect = obj(data, "inspection");
    let not_indexed = get_f64_or(obj(inspect, "summary"), "fail", 0.0) as i64;
    if not_indexed != 0 {
        critical_items.push((
            format!("Resolve {not_indexed} Non-Indexed URL(s)"),
            "Medium (2-4 hrs)",
            "These pages are not appearing in Google's index. Review coverage state, fix crawl errors, and request re-indexing via Search Console.".into(),
        ));
    }

    if !critical_items.is_empty() {
        lines.push("  <h3><span class=\"priority-tag priority-critical\">CRITICAL</span> Fix Immediately</h3>".into());
        for (title, effort, desc) in &critical_items {
            item_num += 1;
            lines.push("  <div class=\"action-item critical\">".into());
            lines.push(format!(
                "    <h4>{item_num}. {title} <span class=\"effort\">Effort: {effort}</span></h4>"
            ));
            lines.push(format!("    <p>{desc}</p>"));
            lines.push("  </div>".into());
        }
        lines.push(String::new());
    }

    let mut high_items: Vec<(String, &'static str, String)> = Vec::new();
    let failed_audits = arr(mobile, "failed_audits");
    let mut sorted = failed_audits.clone();
    sorted.sort_by(|a, b| {
        get_f64_or(a, "score", 1.0)
            .partial_cmp(&get_f64_or(b, "score", 1.0))
            .unwrap()
    });
    for a in sorted.iter().take(5) {
        let score = get_f64_or(a, "score", 1.0);
        if score < 0.5 {
            high_items.push((
                format!("Address: {}", get_str_or(a, "title", "Unknown")),
                "Medium (1-2 hrs)",
                format!(
                    "Score: {}. {}",
                    pct0(score),
                    get_str_or(a, "display", "Review and optimize this audit.")
                ),
            ));
        }
    }

    let opps = arr(mobile, "opportunities");
    for o in opps.iter().take(3) {
        let savings = get_f64_or(o, "savings_ms", 0.0);
        if savings != 0.0 {
            high_items.push((
                get_str_or(o, "title", "Optimization"),
                "Medium (2-4 hrs)",
                format!("Potential savings of ~{savings:.0}ms. Implement this to improve page load speed."),
            ));
        }
    }

    let gsc = obj(data, "gsc");
    let qw = arr(gsc, "quick_wins");
    if !qw.is_empty() {
        high_items.push((
            format!("Optimize {} Quick-Win Queries", qw.len()),
            "Medium (2-4 hrs)",
            "These queries rank at positions 4-10 with high impressions. Improve on-page SEO and content depth to push them into top 3.".into(),
        ));
    }

    if !high_items.is_empty() {
        lines.push("  <h3><span class=\"priority-tag priority-high\">HIGH</span> Fix Within 1 Week</h3>".into());
        for (title, effort, desc) in &high_items {
            item_num += 1;
            lines.push("  <div class=\"action-item high\">".into());
            lines.push(format!(
                "    <h4>{item_num}. {title} <span class=\"effort\">Effort: {effort}</span></h4>"
            ));
            lines.push(format!("    <p>{desc}</p>"));
            lines.push("  </div>".into());
        }
        lines.push(String::new());
    }

    let mut medium_items: Vec<(String, &'static str, String)> = Vec::new();
    let a11y = arr(mobile, "accessibility_audits");
    if !a11y.is_empty() {
        medium_items.push((
            format!("Fix {} Accessibility Issue(s)", a11y.len()),
            "Low (30 min)",
            "Accessibility improvements benefit SEO (Lighthouse score) and user experience. Address failing accessibility audits.".into(),
        ));
    }

    let acc_score = get_f64(obj(mobile, "lighthouse_scores"), "accessibility");
    if let Some(acc) = acc_score {
        if acc < 90.0 && a11y.is_empty() {
            medium_items.push((
                "Improve Accessibility Score".into(),
                "Medium (2-4 hrs)",
                format!("Current score: {acc:.0}/100. Run a detailed accessibility audit and address any violations."),
            ));
        }
    }

    let bp_score = get_f64(obj(mobile, "lighthouse_scores"), "best-practices");
    if let Some(bp) = bp_score {
        if bp < 90.0 {
            medium_items.push((
                "Address Best Practices Issues".into(),
                "Low (30 min)",
                format!("Current score: {bp:.0}/100. Review browser console for errors, update deprecated APIs, and ensure HTTPS for all resources."),
            ));
        }
    }

    if !medium_items.is_empty() {
        lines.push("  <h3><span class=\"priority-tag priority-medium\">MEDIUM</span> Fix Within 1 Month</h3>".into());
        for (title, effort, desc) in &medium_items {
            item_num += 1;
            lines.push("  <div class=\"action-item medium\">".into());
            lines.push(format!(
                "    <h4>{item_num}. {title} <span class=\"effort\">Effort: {effort}</span></h4>"
            ));
            lines.push(format!("    <p>{desc}</p>"));
            lines.push("  </div>".into());
        }
        lines.push(String::new());
    }

    if item_num == 0 {
        lines.push("  <div class=\"success-box\"><strong>No critical issues detected.</strong> Continue monitoring Core Web Vitals and search performance regularly.</div>".into());
        lines.push(String::new());
    }

    lines.push("  <hr class=\"divider\">".into());
    lines.push("  <h3>Implementation Roadmap</h3>".into());
    lines.push("  <div class=\"roadmap-phase\">".into());
    lines.push("    <h4>Week 1 &mdash; Quick Wins</h4>".into());
    lines.push("    <ul>".into());
    if !seo_failed.is_empty() {
        lines.push("      <li>Fix failing Lighthouse SEO checks</li>".into());
    }
    if !a11y.is_empty() {
        lines.push(format!("      <li>Address {} accessibility issue(s)</li>", a11y.len()));
    }
    let bp_score_val = bp_score;
    if let Some(bp) = bp_score_val {
        if bp < 90.0 {
            lines.push("      <li>Review and fix Best Practices issues</li>".into());
        }
    }
    if seo_failed.is_empty()
        && a11y.is_empty()
        && bp_score_val.map(|v| v >= 90.0).unwrap_or(true)
    {
        lines.push("      <li>Verify all monitoring dashboards are active</li>".into());
    }
    lines.push("    </ul>".into());
    lines.push("  </div>".into());
    lines.push("  <div class=\"roadmap-phase\">".into());
    lines.push("    <h4>Week 2&ndash;3 &mdash; Performance &amp; Indexation</h4>".into());
    lines.push("    <ul>".into());
    if perf.map(|p| p < 50.0).unwrap_or(false) {
        lines.push("      <li>Optimize Largest Contentful Paint and Total Blocking Time</li>".into());
    }
    if not_indexed != 0 {
        lines.push(format!("      <li>Resolve {not_indexed} non-indexed URL(s)</li>"));
    }
    if !opps.is_empty() {
        lines.push(format!("      <li>Implement {} performance optimization(s)</li>", opps.len()));
    }
    if perf.map(|p| p >= 50.0).unwrap_or(true) && not_indexed == 0 && opps.is_empty() {
        lines.push("      <li>Maintain current performance levels and monitor trends</li>".into());
    }
    lines.push("    </ul>".into());
    lines.push("  </div>".into());
    lines.push("  <div class=\"roadmap-phase\">".into());
    lines.push("    <h4>Week 4 &mdash; Content &amp; Search Optimization</h4>".into());
    lines.push("    <ul>".into());
    if !qw.is_empty() {
        lines.push(format!("      <li>Optimize {} quick-win queries for top-3 rankings</li>", qw.len()));
    }
    lines.push("      <li>Review and improve content depth for underperforming pages</li>".into());
    lines.push("      <li>Set up ongoing monitoring and reporting cadence</li>".into());
    lines.push("    </ul>".into());
    lines.push("  </div>".into());
    lines.push(String::new());

    lines.push("</div>".into());
    lines.join("\n")
}

/// Port of `_build_methodology_footer`. `domain` is accepted (matching the
/// Python signature `_build_methodology_footer(domain, timestamp)`) but, like
/// the Python original, never referenced in the body -- the footer's table is
/// static and only `timestamp` is interpolated.
pub fn build_methodology_footer(_domain: &str, timestamp: &str) -> String {
    format!(
        "\n<!-- {bar} DATA SOURCES & METHODOLOGY {tri} -->\n<div class=\"section\" style=\"text-align: center; padding-top: 15mm;\">\n  <hr class=\"divider\">\n  <h3 style=\"text-align: left;\">Data Sources &amp; Methodology</h3>\n  <table>\n    <thead>\n      <tr><th>Source</th><th>Description</th><th>Update Frequency</th></tr>\n    </thead>\n    <tbody>\n      <tr><td>PageSpeed Insights API</td>\n          <td>Lighthouse lab audit (mobile emulation, Moto G Power, slow 4G)</td>\n          <td>Real-time</td></tr>\n      <tr><td>Chrome UX Report (CrUX)</td>\n          <td>28-day rolling field data from real Chrome users</td>\n          <td>Daily ~04:00 UTC</td></tr>\n      <tr><td>CrUX History API</td>\n          <td>25-week p75 trend data per metric</td>\n          <td>Weekly</td></tr>\n      <tr><td>Google Search Console</td>\n          <td>Search Analytics (clicks, impressions, CTR, position)</td>\n          <td>2-3 day lag</td></tr>\n      <tr><td>URL Inspection API</td>\n          <td>Per-URL index status, coverage state, crawl info</td>\n          <td>Real-time (2,000/day)</td></tr>\n    </tbody>\n  </table>\n  <p style=\"color: #94a3b8; font-size: 9pt; margin-top: 5mm;\">\n    Report generated by Claude SEO &mdash; Google SEO Intelligence Skill &mdash; {domain_ts}<br>\n    Methodology based on Google Web Vitals thresholds, Search Console documentation, and Lighthouse scoring algorithms.\n  </p>\n</div>\n",
        bar = "=".repeat(55),
        tri = "=".repeat(3),
        domain_ts = timestamp,
    )
}

/// `str.title()`-equivalent for a space-joined lowercase phrase (`"total blocking time"` ->
/// `"Total Blocking Time"`), used by the lab-metrics fallback label.
fn title_case(s: &str) -> String {
    s.split(' ')
        .map(|w| {
            let mut c = w.chars();
            match c.next() {
                None => String::new(),
                Some(f) => f.to_uppercase().collect::<String>() + c.as_str(),
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// Renders a `serde_json::Value` the way Python's f-string interpolation would
/// display the equivalent `int`/`float`/`str` (no quotes, no trailing `.0` for
/// whole floats where the source value came in as an int).
fn json_display(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Number(n) => n.to_string(),
        Value::Bool(b) => b.to_string(),
        Value::Null => "None".to_string(),
        other => other.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn img_tag_empty_path_is_empty_string() {
        assert_eq!(img_tag("", "x"), "");
    }

    #[test]
    fn metric_card_includes_color_style_only_when_given() {
        assert!(metric_card("5", "Label", Some("#fff")).contains("style=\"color: #fff;\""));
        assert!(!metric_card("5", "Label", None).contains("style="));
    }

    #[test]
    fn toc_renders_section_and_sub_items_with_score_badge() {
        let secs = vec![TocSection {
            num: 1,
            title: "Exec".into(),
            score: Some(92.0),
            subs: vec!["Sub A".into()],
        }];
        let html = build_toc(&secs);
        assert!(html.contains("1. Exec"));
        assert!(html.contains("score-good"));
        assert!(html.contains("Sub A"));
    }

    #[test]
    fn executive_summary_shows_critical_and_quickwin_boxes() {
        let data = json!({
            "psi": {"lighthouse_scores": {"performance": 40, "seo": 95},
                     "failed_audits": [{"title": "Slow LCP", "score": 0.2}],
                     "seo_audits": [{"title": "Missing meta", "pass": false}],
                     "opportunities": [{"title": "Defer JS", "savings_ms": 500}]},
            "gsc": {"totals": {"clicks": 120, "impressions": 5000}, "quick_wins": [{}]},
            "inspection": {"summary": {"pass": 8, "fail": 2}}
        });
        let html = build_executive_summary("example.com", "Jan 1, 2026", &data);
        assert!(html.contains("Critical Issues Found"));
        assert!(html.contains("Quick Wins"));
        assert!(html.contains("40/100"));
        assert!(html.contains("120"));
    }

    #[test]
    fn cwv_section_handles_missing_data_without_panicking() {
        let (html, fig) = build_cwv_section(&json!({}), &json!({}), &ChartPaths::new(), None, 2);
        assert!(html.contains("2. Core Web Vitals"));
        assert_eq!(fig, 1);
    }

    #[test]
    fn recommendations_reports_no_critical_issues_when_clean() {
        let html = build_recommendations(&json!({}), 5);
        assert!(html.contains("No critical issues detected"));
    }

    #[test]
    fn recommendations_counts_critical_items_sequentially() {
        let data = json!({
            "psi": {"lighthouse_scores": {"performance": 30}},
            "inspection": {"summary": {"fail": 3}}
        });
        let html = build_recommendations(&data, 5);
        assert!(html.contains("1. Improve Lighthouse Performance Score"));
        assert!(html.contains("2. Resolve 3 Non-Indexed URL(s)"));
    }

    #[test]
    fn indexation_section_computes_index_rate() {
        let data = json!({"summary": {"pass": 9, "fail": 1}, "total": 10});
        let (html, _) = build_indexation_section(&data, &ChartPaths::new(), 4, 1);
        assert!(html.contains("90% of inspected URLs are indexed"));
        assert!(html.contains("success-box"));
    }
}
