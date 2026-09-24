//! Cross-module integration tests for wf_port packet r37 (`google_report.py`),
//! exercising chart generation, HTML/CSS assembly, xlsx export, and the CLI
//! argument/data-loading path together. See `legion_runtime::wf_port::r37`
//! for the packet's scope and documented gaps.
//!
//! NOTE for the integrator: this file assumes `pub mod wf_port;` (in
//! `legion-runtime`'s `lib.rs`) and `pub mod r37;` (in `wf_port::mod`) are
//! wired; see `engine/crates/legion-runtime/src/wf_port/r37/mod.rs`'s module
//! doc for the exact patch.

use serde_json::json;

use legion_runtime::wf_port::r37::cli::{parse_args, DataSource};
use legion_runtime::wf_port::r37::report::{
    build_report_html, generate_charts, generate_report, OutputFormat, PdfRenderer, ReportType,
};
use legion_runtime::wf_port::r37::sections::ChartPaths;

fn tmp_dir(tag: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "r37_it_{tag}_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

struct FakeRenderer;
impl PdfRenderer for FakeRenderer {
    fn render(&mut self, _html_file_url: &str) -> Result<Vec<u8>, String> {
        Ok(b"%PDF-1.4 fake".to_vec())
    }
}

#[test]
fn full_report_writes_html_pdf_and_xlsx_with_charts() {
    let dir = tmp_dir("full");
    let data = json!({
        "psi": {"lighthouse_scores": {"performance": 61, "accessibility": 95, "best-practices": 88, "seo": 100},
                 "failed_audits": [{"title": "Unused JS", "score": 0.3, "display": "1.2s"}],
                 "opportunities": [{"title": "Defer offscreen images", "savings_ms": 300}]},
        "crux": {"metrics": {
            "largest_contentful_paint": {"label": "LCP", "rating": "needs_improvement", "p75": 3200, "unit": "ms",
                                          "distribution": {"good": 55.0, "needs_improvement": 30.0, "poor": 15.0}}
        }, "collection_period": {"first": "2026-01-01", "last": "2026-01-28"}},
        "gsc": {"totals": {"clicks": 342, "impressions": 9821, "ctr": 3.5}, "row_count": 40,
                "rows": [{"query": "widgets for sale", "clicks": 12, "impressions": 300, "ctr": 4.0, "position": 6.5}],
                "quick_wins": [{"keys": ["buy widgets"], "position": 7.0, "impressions": 500, "clicks": 5}]},
        "inspection": {"summary": {"pass": 18, "fail": 2}, "total": 20,
                        "results": [{"url": "https://example.com/", "verdict": "PASS",
                                      "index_status": {"coverage_state": "Submitted and indexed"}}]}
    });

    let mut renderer = FakeRenderer;
    let result = generate_report(
        ReportType::Full,
        &data,
        "example.com",
        &dir,
        OutputFormat::All,
        "January 01, 2026",
        Some(&mut renderer),
    );

    assert!(result.error.is_none(), "unexpected error: {:?}", result.error);
    assert_eq!(result.files.len(), 3, "expected html+pdf+xlsx: {:?}", result.files);
    assert!(result.files.iter().any(|f| f.ends_with(".html")));
    assert!(result.files.iter().any(|f| f.ends_with(".pdf")));
    assert!(result.files.iter().any(|f| f.ends_with(".xlsx")));
    assert!(result.review.is_some());

    // Charts referenced by the HTML must exist on disk (written under charts/).
    let html_path = result.files.iter().find(|f| f.ends_with(".html")).unwrap();
    let html = std::fs::read_to_string(html_path).unwrap();
    assert!(html.contains("Core Web Vitals"));
    assert!(html.contains("Search Console Performance"));
    assert!(html.contains("Indexation Status"));
    assert!(html.contains("lighthouse_gauges.svg"));
    assert!(dir.join("charts/lighthouse_gauges.svg").exists());

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn cwv_audit_report_omits_absent_sections() {
    let data = json!({"psi": {"lighthouse_scores": {"performance": 42}}});
    let chart_paths = ChartPaths::new();
    let html = build_report_html(ReportType::CwvAudit, &data, "site.com", &chart_paths, "Jan 1, 2026");
    assert!(html.contains("Core Web Vitals Audit"));
    assert!(!html.contains("Search Console Performance"));
}

#[test]
fn generate_charts_only_produces_requested_report_types_charts() {
    let dir = tmp_dir("charts");
    let data = json!({"rows": [{"query": "a", "impressions": 50, "clicks": 5}]});
    let paths = generate_charts(ReportType::GscPerformance, &data, &dir);
    assert!(paths.contains_key("top_queries_path"));
    assert!(!paths.contains_key("gauges_path"));
    let _ = std::fs::remove_dir_all(&dir);
}

struct StdinFreeSource;
impl DataSource for StdinFreeSource {
    fn read_file(&self, path: &std::path::Path) -> Result<String, String> {
        std::fs::read_to_string(path).map_err(|e| e.to_string())
    }
    fn read_stdin(&self) -> Option<Result<String, String>> {
        None
    }
}

#[test]
fn cli_parse_and_missing_data_source_errors_cleanly() {
    let argv: Vec<String> = ["--type", "indexation", "--domain", "x.com"]
        .iter()
        .map(|s| s.to_string())
        .collect();
    let args = parse_args(&argv).unwrap();
    let err = legion_runtime::wf_port::r37::cli::load_data(&args, &StdinFreeSource).unwrap_err();
    assert!(err.contains("Provide --data file or pipe JSON"));
}
