#![forbid(unsafe_code)]

use legion_contracts::{Finding, ReportV1};

pub mod error;
pub mod escape;
pub mod html;
pub mod json;
pub mod markdown;
pub mod sarif;

pub use error::ReportError;

pub fn render_json(report: &ReportV1) -> Result<String, ReportError> {
    json::render(report)
}
pub fn render_sarif(report: &ReportV1) -> Result<String, ReportError> {
    sarif::render(report)
}
pub fn render_markdown(report: &ReportV1) -> Result<String, ReportError> {
    markdown::render(report)
}
pub fn render_html(report: &ReportV1) -> Result<String, ReportError> {
    html::render(report)
}

pub(crate) fn ordered_findings(report: &ReportV1) -> Vec<&Finding> {
    let mut findings: Vec<_> = report.findings.iter().collect();
    findings.sort_by(|left, right| {
        left.id
            .as_str()
            .cmp(right.id.as_str())
            .then_with(|| first_location(left).cmp(&first_location(right)))
            .then_with(|| left.message.cmp(&right.message))
    });
    findings
}

fn first_location(finding: &Finding) -> (String, u64, u64) {
    finding
        .locations
        .iter()
        .map(|location| {
            let normalized = location.replace('\\', "/");
            let (path, span) = normalized
                .rsplit_once(':')
                .unwrap_or((normalized.as_str(), ""));
            let (start, end) = span.split_once('-').map_or((span, span), |range| range);
            let start = start.parse::<u64>().unwrap_or(0);
            let end = end.parse::<u64>().unwrap_or(start);
            (path.to_string(), start, end)
        })
        .min()
        .unwrap_or_else(|| (String::new(), 0, 0))
}
