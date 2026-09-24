//! Port of `google_report.py`'s report assemblers: `generate_report` and
//! `_review_pdf`.
//!
//! PDF rendering is behind the [`PdfRenderer`] trait (mirroring the
//! `DeckStageBrowser` pattern in `wf_port::r00::export_deck_stage_pdf`): the
//! production implementation drives `headless_chrome`'s `print_to_pdf`, tests
//! use a fake. This is a deliberate format substitution from the Python's
//! `weasyprint.HTML(string=...).write_pdf(...)` (paged-CSS PDF engine) to
//! Chrome's print-to-PDF -- no PDF-generation crate is in this packet's
//! allowed-crate list, and `headless_chrome` (allowed) is the only available
//! path to a real PDF. Chrome's print-to-PDF does not support CSS Paged Media
//! `@page` margin boxes (`@bottom-center`/`@bottom-left`/`@bottom-right` /
//! named `@page toc`) the way WeasyPrint does; this is a genuine, documented
//! rendering-fidelity gap (page numbers/footers in the PDF come from
//! `PrintToPdfOptions`'s `header_template`/`footer_template` instead of the
//! CSS this crate still emits into the HTML/`<style>` for the HTML-format
//! output, where it renders correctly in any browser).

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use serde_json::Value;

use super::charts;
use super::css::build_css;
use super::jget::obj;
use super::sections::{
    build_cwv_section, build_executive_summary, build_gsc_section, build_indexation_section,
    build_methodology_footer, build_recommendations, build_title_page, build_toc, ChartPaths,
    TocSection,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReportType {
    CwvAudit,
    GscPerformance,
    Indexation,
    Full,
}

impl ReportType {
    pub fn as_str(self) -> &'static str {
        match self {
            ReportType::CwvAudit => "cwv-audit",
            ReportType::GscPerformance => "gsc-performance",
            ReportType::Indexation => "indexation",
            ReportType::Full => "full",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "cwv-audit" => Some(ReportType::CwvAudit),
            "gsc-performance" => Some(ReportType::GscPerformance),
            "indexation" => Some(ReportType::Indexation),
            "full" => Some(ReportType::Full),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputFormat {
    Pdf,
    Html,
    Xlsx,
    Both,
    All,
}

impl OutputFormat {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "pdf" => Some(OutputFormat::Pdf),
            "html" => Some(OutputFormat::Html),
            "xlsx" => Some(OutputFormat::Xlsx),
            "both" => Some(OutputFormat::Both),
            "all" => Some(OutputFormat::All),
            _ => None,
        }
    }

    fn wants_html(self) -> bool {
        matches!(self, OutputFormat::Html | OutputFormat::Both | OutputFormat::All)
    }
    fn wants_pdf(self) -> bool {
        matches!(self, OutputFormat::Pdf | OutputFormat::Both | OutputFormat::All)
    }
    fn wants_xlsx(self) -> bool {
        matches!(self, OutputFormat::Xlsx | OutputFormat::All)
    }
}

/// Renders a chart (an `Option<String>` of SVG markup) to `dir/<name>.svg`
/// when present, returning the written path the way the Python chart
/// functions return `str(path)` (or `""`, ported as `None`/absent key).
fn write_chart(dir: &Path, name: &str, svg: Option<String>) -> Option<String> {
    let svg = svg?;
    let path = dir.join(format!("{name}.svg"));
    std::fs::write(&path, svg).ok()?;
    Some(path.to_string_lossy().to_string())
}

/// Port of the "Generate Charts" block inside `generate_report`.
pub fn generate_charts(report_type: ReportType, data: &Value, charts_dir: &Path) -> ChartPaths<'static> {
    let mut chart_paths: ChartPaths<'static> = HashMap::new();

    if matches!(report_type, ReportType::CwvAudit | ReportType::Full) {
        let psi = if data.get("psi").is_some() { obj(data, "psi") } else { data };
        let mobile = {
            let inner = obj(psi, "psi");
            inner.get("mobile").cloned().unwrap_or_else(|| psi.clone())
        };
        if let Some(p) = write_chart(charts_dir, "lighthouse_gauges", charts::chart_lighthouse_gauges(&mobile)) {
            chart_paths.insert("gauges_path", p);
        }

        let crux = obj(data, "crux");
        let dist_input = if crux.as_object().map(|m| !m.is_empty()).unwrap_or(false) {
            serde_json::json!({ "crux": crux })
        } else {
            data.clone()
        };
        if let Some(p) = write_chart(
            charts_dir,
            "cwv_distributions",
            charts::chart_cwv_distributions(&dist_input),
        ) {
            chart_paths.insert("distributions_path", p);
        }

        let history = obj(data, "crux_history");
        if history.as_object().map(|m| !m.is_empty()).unwrap_or(false) && history.get("error").is_none()
        {
            if let Some(p) = write_chart(charts_dir, "cwv_timeline", charts::chart_cwv_timeline(history)) {
                chart_paths.insert("timeline_path", p);
            }
        }
    }

    if matches!(report_type, ReportType::GscPerformance | ReportType::Full) {
        let gsc = if data.get("gsc").is_some() { obj(data, "gsc") } else { data };
        if let Some(p) = write_chart(charts_dir, "top_queries", charts::chart_top_queries(gsc)) {
            chart_paths.insert("top_queries_path", p);
        }
    }

    if matches!(report_type, ReportType::Indexation | ReportType::Full) {
        let inspect = if data.get("inspection").is_some() {
            obj(data, "inspection")
        } else {
            data
        };
        if let Some(p) = write_chart(charts_dir, "index_status", charts::chart_index_status(inspect)) {
            chart_paths.insert("index_status_path", p);
        }
    }

    chart_paths
}

/// Port of the HTML-section-assembly branch of `generate_report`
/// (`report_type in {"cwv-audit", "gsc-performance", "indexation", "full"}`).
/// Returns the full `<html>...</html>` document string.
pub fn build_report_html(
    report_type: ReportType,
    data: &Value,
    domain: &str,
    chart_paths: &ChartPaths,
    timestamp: &str,
) -> String {
    let mut sections: Vec<String> = Vec::new();

    let psi_root = obj(data, "psi");
    let mobile = {
        let inner = obj(psi_root, "psi");
        inner.get("mobile").cloned().unwrap_or_else(|| psi_root.clone())
    };
    let perf_score = mobile
        .get("lighthouse_scores")
        .and_then(|s| s.get("performance"))
        .and_then(|v| v.as_f64());

    match report_type {
        ReportType::CwvAudit => {
            sections.push(build_title_page(
                domain,
                "Core Web Vitals Audit",
                "Performance &amp; User Experience Analysis",
                perf_score.map(|s| format!("{s:.0}")).as_deref(),
                Some("Lighthouse Performance Score"),
                &[timestamp.to_string(), "PageSpeed Insights + CrUX".to_string()],
                None,
            ));
            sections.push(build_toc(&[
                TocSection { num: 1, title: "Executive Summary".into(), score: None, subs: vec!["Key Metrics &amp; Critical Issues".into()] },
                TocSection { num: 2, title: "Core Web Vitals &amp; Performance".into(), score: perf_score, subs: vec![
                    "Lighthouse Scores".into(), "Lab Metrics".into(), "CrUX Field Data".into(), "Failed Audits &amp; SEO Checks".into(),
                ] },
                TocSection { num: 3, title: "Recommendations".into(), score: None, subs: vec!["Prioritized Action Items".into()] },
                TocSection { num: 4, title: "Data Sources &amp; Methodology".into(), score: None, subs: vec![] },
            ]));
            sections.push(build_executive_summary(domain, timestamp, data));
            let (cwv_html, _fig) = build_cwv_section(data, obj(data, "crux"), chart_paths, data.get("crux_history"), 2);
            sections.push(cwv_html);
            sections.push(build_recommendations(data, 3));
            sections.push(build_methodology_footer(domain, timestamp));
        }
        ReportType::GscPerformance => {
            let gsc = if data.get("gsc").is_some() { obj(data, "gsc") } else { data };
            let clicks = gsc
                .get("totals")
                .and_then(|t| t.get("clicks"))
                .and_then(|v| v.as_i64())
                .unwrap_or(0);
            sections.push(build_title_page(
                domain,
                "Search Console Performance",
                "Google Search Analytics Report",
                Some(&super::jget::thousands(clicks)),
                Some("Total Clicks"),
                &[timestamp.to_string(), "Google Search Console API".to_string()],
                None,
            ));
            sections.push(build_toc(&[
                TocSection { num: 1, title: "Executive Summary".into(), score: None, subs: vec!["Key Metrics &amp; Quick Wins".into()] },
                TocSection { num: 2, title: "Search Console Performance".into(), score: None, subs: vec![
                    "Key Metrics".into(), "Top Queries by Clicks".into(), "Query Detail Table".into(), "Position Analysis &amp; Quick Wins".into(),
                ] },
                TocSection { num: 3, title: "Recommendations".into(), score: None, subs: vec!["Prioritized Action Items".into()] },
                TocSection { num: 4, title: "Data Sources &amp; Methodology".into(), score: None, subs: vec![] },
            ]));
            sections.push(build_executive_summary(domain, timestamp, data));
            let (gsc_html, _fig) = build_gsc_section(gsc, chart_paths, 2, 1);
            sections.push(gsc_html);
            sections.push(build_recommendations(data, 3));
            sections.push(build_methodology_footer(domain, timestamp));
        }
        ReportType::Indexation => {
            let inspect = if data.get("inspection").is_some() {
                obj(data, "inspection")
            } else {
                data
            };
            let total = inspect.get("total").and_then(|v| v.as_f64()).unwrap_or(0.0);
            sections.push(build_title_page(
                domain,
                "Indexation Status Report",
                "URL Index Coverage Analysis",
                Some(&format!("{total:.0}")),
                Some("URLs Inspected"),
                &[timestamp.to_string(), "URL Inspection API".to_string()],
                None,
            ));
            sections.push(build_toc(&[
                TocSection { num: 1, title: "Executive Summary".into(), score: None, subs: vec!["Index Coverage Overview".into()] },
                TocSection { num: 2, title: "Indexation Status".into(), score: None, subs: vec!["Index Coverage Overview".into(), "Per-URL Results".into()] },
                TocSection { num: 3, title: "Recommendations".into(), score: None, subs: vec!["Prioritized Action Items".into()] },
                TocSection { num: 4, title: "Data Sources &amp; Methodology".into(), score: None, subs: vec![] },
            ]));
            sections.push(build_executive_summary(domain, timestamp, data));
            let (idx_html, _fig) = build_indexation_section(inspect, chart_paths, 2, 1);
            sections.push(idx_html);
            sections.push(build_recommendations(data, 3));
            sections.push(build_methodology_footer(domain, timestamp));
        }
        ReportType::Full => {
            sections.push(build_title_page(
                domain,
                "Google SEO Intelligence Report",
                "Comprehensive Analysis",
                perf_score.map(|s| format!("{s:.0}")).as_deref(),
                if perf_score.is_some() { Some("Lighthouse Performance Score") } else { None },
                &[timestamp.to_string(), "All Google APIs".to_string()],
                None,
            ));

            let mut toc = vec![TocSection {
                num: 1,
                title: "Executive Summary".into(),
                score: None,
                subs: vec!["Key Metrics, Critical Issues &amp; Quick Wins".into()],
            }];
            let mut sec_num = 2u32;
            let has_psi_or_crux = super::jget::truthy(data.get("psi")) || super::jget::truthy(data.get("crux"));
            if has_psi_or_crux {
                toc.push(TocSection {
                    num: sec_num,
                    title: "Core Web Vitals &amp; Performance".into(),
                    score: perf_score,
                    subs: vec![
                        "Lighthouse Scores &amp; Lab Metrics".into(),
                        "CrUX Field Data &amp; Trends".into(),
                        "Failed Audits &amp; Opportunities".into(),
                    ],
                });
                sec_num += 1;
            }
            if super::jget::truthy(data.get("gsc")) {
                toc.push(TocSection {
                    num: sec_num,
                    title: "Search Console Performance".into(),
                    score: None,
                    subs: vec!["Key Metrics &amp; Top Queries".into(), "Position Analysis &amp; Quick Wins".into()],
                });
                sec_num += 1;
            }
            if super::jget::truthy(data.get("inspection")) {
                toc.push(TocSection {
                    num: sec_num,
                    title: "Indexation Status".into(),
                    score: None,
                    subs: vec!["Index Coverage &amp; Per-URL Results".into()],
                });
                sec_num += 1;
            }
            let rec_num = sec_num;
            toc.push(TocSection {
                num: sec_num,
                title: "Recommendations".into(),
                score: None,
                subs: vec!["Prioritized Action Items".into()],
            });
            sec_num += 1;
            toc.push(TocSection {
                num: sec_num,
                title: "Data Sources &amp; Methodology".into(),
                score: None,
                subs: vec![],
            });

            sections.push(build_toc(&toc));
            sections.push(build_executive_summary(domain, timestamp, data));

            let mut current_sec = 2u32;
            let mut fig_num = 1u32;
            if has_psi_or_crux {
                let (html, fig) = build_cwv_section(
                    obj(data, "psi"),
                    obj(data, "crux"),
                    chart_paths,
                    data.get("crux_history"),
                    current_sec,
                );
                sections.push(html);
                fig_num = fig;
                current_sec += 1;
            }
            if super::jget::truthy(data.get("gsc")) {
                let gsc = data.get("gsc").unwrap();
                let (html, fig) = build_gsc_section(gsc, chart_paths, current_sec, fig_num);
                sections.push(html);
                fig_num = fig;
                current_sec += 1;
            }
            if super::jget::truthy(data.get("inspection")) {
                let inspection = data.get("inspection").unwrap();
                let (html, _fig) = build_indexation_section(inspection, chart_paths, current_sec, fig_num);
                sections.push(html);
                current_sec += 1;
            }
            let _ = current_sec;

            sections.push(build_recommendations(data, rec_num));
            sections.push(build_methodology_footer(domain, timestamp));
        }
    }

    let css = build_css(domain);
    let body = sections.join("\n");
    format!(
        "<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n<meta charset=\"UTF-8\">\n<style>\n{css}\n</style>\n</head>\n<body>\n{body}\n</body>\n</html>\n"
    )
}

/// Boundary for the "print HTML to PDF bytes" step (see module doc for why
/// this is `headless_chrome` rather than `weasyprint`).
pub trait PdfRenderer {
    fn render(&mut self, html_file_url: &str) -> Result<Vec<u8>, String>;
}

/// Production implementation: writes `html_content` to a temp file, navigates
/// `headless_chrome` to it, and calls `print_to_pdf`.
pub struct ChromePdfRenderer {
    tab: std::sync::Arc<headless_chrome::Tab>,
    _browser: headless_chrome::Browser,
}

impl ChromePdfRenderer {
    pub fn launch() -> Result<Self, String> {
        let browser = headless_chrome::Browser::default().map_err(|e| e.to_string())?;
        let tab = browser.new_tab().map_err(|e| e.to_string())?;
        Ok(Self { tab, _browser: browser })
    }
}

impl PdfRenderer for ChromePdfRenderer {
    fn render(&mut self, html_file_url: &str) -> Result<Vec<u8>, String> {
        self.tab.navigate_to(html_file_url).map_err(|e| e.to_string())?;
        self.tab.wait_until_navigated().map_err(|e| e.to_string())?;
        self.tab.print_to_pdf(None).map_err(|e| e.to_string())
    }
}

#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct PdfReview {
    pub issues: Vec<String>,
    pub file_size_kb: Option<f64>,
    pub status: String,
}

/// Port of `_review_pdf`'s HTML-level checks and file-size read. `page_count`
/// is not ported: the Python's own value is `None` unless the optional
/// `pypdf` import succeeds (`try: from pypdf import PdfReader ... except
/// ImportError: pass`), and no PDF-parsing crate is in this packet's
/// allowed-crate list, so this port keeps the same "absent unless a PDF
/// parser is available" behavior by omitting the field rather than adding one
/// speculatively.
pub fn review_pdf(pdf_bytes_len: Option<usize>, html_content: &str) -> PdfReview {
    let mut review = PdfReview::default();
    if let Some(len) = pdf_bytes_len {
        review.file_size_kb = Some((len as f64 / 1024.0 * 10.0).round() / 10.0);
    }

    let empty_imgs = html_content.matches("src=\"\"").count();
    if empty_imgs > 0 {
        review.issues.push(format!("{empty_imgs} empty image tag(s) found"));
    }

    // Section text-length check: mirrors `html_content.split('div class="section"')`,
    // stripping tags from each subsequent chunk's first 2000 chars.
    let parts: Vec<&str> = html_content.split("div class=\"section\"").collect();
    for (i, sec) in parts.iter().enumerate().skip(1) {
        let slice: String = sec.chars().take(2000).collect();
        let text_only = strip_tags(&slice);
        let collapsed = collapse_whitespace(&text_only);
        if collapsed.len() < 50 {
            review.issues.push(format!(
                "Section {i} has very little text content ({} chars)",
                collapsed.len()
            ));
        }
    }

    // Duplicate-table check.
    let tables = extract_tables(html_content);
    let mut unique = tables.clone();
    unique.sort();
    unique.dedup();
    if tables.len() != unique.len() {
        review.issues.push("Duplicate tables detected".to_string());
    }

    review.status = if review.issues.is_empty() {
        "PASS".to_string()
    } else {
        format!("WARN ({} issues)", review.issues.len())
    };
    review
}

fn strip_tags(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut in_tag = false;
    for c in s.chars() {
        match c {
            '<' => in_tag = true,
            '>' => in_tag = false,
            _ if !in_tag => out.push(c),
            _ => {}
        }
    }
    out
}

fn collapse_whitespace(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ").trim().to_string()
}

fn extract_tables(html: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = html;
    while let Some(start) = rest.find("<table>") {
        let after = &rest[start..];
        if let Some(end) = after.find("</table>") {
            out.push(after[..end + "</table>".len()].to_string());
            rest = &after[end + "</table>".len()..];
        } else {
            break;
        }
    }
    out
}

#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct ReportResult {
    pub report_type: String,
    pub domain: String,
    pub files: Vec<String>,
    pub error: Option<String>,
    pub review: Option<PdfReview>,
}

/// Port of `generate_report`. `renderer` is only consulted when the requested
/// format wants a PDF; `timestamp`/`timestamp_short` are supplied by the
/// caller (Python calls `datetime.now()` inline -- pushed to the boundary so
/// this function is deterministic and testable).
#[allow(clippy::too_many_arguments)]
pub fn generate_report(
    report_type: ReportType,
    data: &Value,
    domain: &str,
    output_dir: &Path,
    output_format: OutputFormat,
    timestamp: &str,
    renderer: Option<&mut dyn PdfRenderer>,
) -> ReportResult {
    let charts_dir = output_dir.join("charts");
    let _ = std::fs::create_dir_all(&charts_dir);

    let mut result = ReportResult {
        report_type: report_type.as_str().to_string(),
        domain: domain.to_string(),
        files: Vec::new(),
        error: None,
        review: None,
    };

    let chart_paths = generate_charts(report_type, data, &charts_dir);
    let html_content = build_report_html(report_type, data, domain, &chart_paths, timestamp);

    let safe_domain = domain.replace(':', "_").replace('/', "_");
    let base_name = format!("Google-SEO-Report-{safe_domain}-{}", report_type.as_str());

    if output_format.wants_html() {
        let html_path = output_dir.join(format!("{base_name}.html"));
        if std::fs::write(&html_path, &html_content).is_ok() {
            result.files.push(html_path.to_string_lossy().to_string());
        }
    }

    if output_format.wants_pdf() {
        let pdf_path = output_dir.join(format!("{base_name}.pdf"));
        match renderer {
            Some(r) => {
                let html_path = output_dir.join(format!("{base_name}.__pdf_source.html"));
                match std::fs::write(&html_path, &html_content)
                    .map_err(|e| e.to_string())
                    .and_then(|_| r.render(&format!("file://{}", html_path.display())))
                {
                    Ok(bytes) => {
                        let len = bytes.len();
                        if std::fs::write(&pdf_path, &bytes).is_ok() {
                            result.files.push(pdf_path.to_string_lossy().to_string());
                            result.review = Some(review_pdf(Some(len), &html_content));
                        }
                    }
                    Err(e) => result.error = Some(format!("PDF generation failed: {e}")),
                }
            }
            None => {
                result.error = Some("PDF generation failed: no PdfRenderer supplied".to_string());
            }
        }
    }

    if output_format.wants_xlsx() {
        if let Some(path) = super::xlsx::generate_xlsx(data, domain, report_type.as_str(), output_dir, timestamp) {
            result.files.push(path.to_string_lossy().to_string());
        }
    }

    result
}

/// Convenience default output directory (Python's `--output-dir` default `"."`).
pub fn default_output_dir() -> PathBuf {
    PathBuf::from(".")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    struct FakeRenderer {
        bytes: Vec<u8>,
    }
    impl PdfRenderer for FakeRenderer {
        fn render(&mut self, _html_file_url: &str) -> Result<Vec<u8>, String> {
            Ok(self.bytes.clone())
        }
    }

    #[test]
    fn build_report_html_cwv_audit_contains_title_and_score() {
        let data = json!({"psi": {"lighthouse_scores": {"performance": 77}}});
        let html = build_report_html(ReportType::CwvAudit, &data, "example.com", &ChartPaths::new(), "Jan 1, 2026");
        assert!(html.contains("Core Web Vitals Audit"));
        assert!(html.contains("example.com"));
        assert!(html.contains("77"));
        assert!(html.starts_with("<!DOCTYPE html>"));
    }

    #[test]
    fn build_report_html_full_includes_only_present_data_sections() {
        let data = json!({"gsc": {"totals": {"clicks": 10}}});
        let html = build_report_html(ReportType::Full, &data, "x.com", &ChartPaths::new(), "Jan 1, 2026");
        assert!(html.contains("Search Console Performance"));
        assert!(!html.contains("Indexation Status</h2>"));
    }

    #[test]
    fn review_pdf_flags_empty_images_and_duplicate_tables() {
        let html = "<div class=\"section\">x</div><img src=\"\"><table>a</table><table>a</table>";
        let review = review_pdf(Some(2048), html);
        assert!(review.issues.iter().any(|i| i.contains("empty image")));
        assert!(review.issues.iter().any(|i| i.contains("Duplicate tables")));
        assert_eq!(review.file_size_kb, Some(2.0));
        assert!(review.status.starts_with("WARN"));
    }

    #[test]
    fn review_pdf_passes_when_clean() {
        let html = "<div class=\"section\">this section definitely has plenty of visible text content in it, well past fifty characters total.</div>";
        let review = review_pdf(None, html);
        assert_eq!(review.status, "PASS");
        assert!(review.issues.is_empty());
    }

    #[test]
    fn generate_report_writes_html_and_pdf_via_fake_renderer() {
        let dir = std::env::temp_dir().join(format!(
            "r37_report_test_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let data = json!({"psi": {"lighthouse_scores": {"performance": 50}}});
        let mut fake = FakeRenderer { bytes: vec![1, 2, 3, 4] };
        let result = generate_report(
            ReportType::CwvAudit,
            &data,
            "example.com",
            &dir,
            OutputFormat::Both,
            "Jan 1, 2026",
            Some(&mut fake),
        );
        assert_eq!(result.files.len(), 2);
        assert!(result.error.is_none());
        assert!(result.review.is_some());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
