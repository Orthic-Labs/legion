#![forbid(unsafe_code)]

use legion_contracts::{Finding, ReportStatus, ReportV1};

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

pub(crate) fn status_label(status: ReportStatus) -> &'static str {
    match status {
        ReportStatus::Clean => "clean",
        ReportStatus::Findings => "findings",
        ReportStatus::Incomplete => "incomplete",
        ReportStatus::Failed => "failed",
        ReportStatus::Blocked => "blocked",
    }
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
            let (start, end) = span.split_once('-').unwrap_or((span, span));
            let start = start.parse::<u64>().unwrap_or(0);
            let end = end.parse::<u64>().unwrap_or(start);
            (path.to_string(), start, end)
        })
        .min()
        .unwrap_or_else(|| (String::new(), 0, 0))
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use legion_contracts::{FindingId, ReportId};
    use serde_json::json;

    use super::*;

    fn report(status: ReportStatus, findings: Vec<Finding>) -> ReportV1 {
        ReportV1 {
            schema_version: 1,
            report_id: ReportId::new("report-1").unwrap(),
            status,
            findings,
            gaps: vec!["provider denominator unavailable".into()],
            claims: BTreeMap::from([("coverage".into(), json!({"examined": 0}))]),
            targets: vec!["src/lib.rs".into()],
            extensions: BTreeMap::new(),
        }
    }

    fn finding(id: &str, title: &str) -> Finding {
        Finding {
            id: FindingId::new(id).unwrap(),
            severity: "high".into(),
            title: title.into(),
            message: "message".into(),
            provider: Some("rules".into()),
            locations: vec!["src/lib.rs:12-14".into()],
            evidence: BTreeMap::from([("source".into(), json!("fixture"))]),
        }
    }

    #[test]
    fn rejects_invalid_contract_before_rendering() {
        let mut invalid = report(ReportStatus::Clean, Vec::new());
        invalid.schema_version = 2;
        for rendered in [
            render_json(&invalid).map(|_| ()),
            render_sarif(&invalid).map(|_| ()),
            render_markdown(&invalid).map(|_| ()),
            render_html(&invalid).map(|_| ()),
        ] {
            assert!(matches!(rendered, Err(ReportError::Contract(_))));
        }
    }

    #[test]
    fn json_is_canonical_and_finding_order_is_stable() {
        let first = report(
            ReportStatus::Findings,
            vec![finding("z", "last"), finding("a", "first")],
        );
        let second = report(
            ReportStatus::Findings,
            vec![finding("a", "first"), finding("z", "last")],
        );
        let rendered = render_json(&first).unwrap();
        assert_eq!(rendered, render_json(&second).unwrap());
        assert!(rendered.starts_with("{\"claims\":"));
        let value: serde_json::Value = serde_json::from_str(&rendered).unwrap();
        assert_eq!(value["findings"][0]["id"], "a");
        assert_eq!(value["status"], "findings");
    }

    #[test]
    fn empty_incomplete_report_does_not_claim_clean() {
        let report = report(ReportStatus::Incomplete, Vec::new());
        let json = render_json(&report).unwrap();
        let sarif = render_sarif(&report).unwrap();
        let markdown = render_markdown(&report).unwrap();
        let html = render_html(&report).unwrap();
        for rendered in [json, sarif, markdown, html] {
            assert!(rendered.contains("incomplete"));
            assert!(rendered.contains("provider denominator unavailable"));
        }
    }

    #[test]
    fn sarif_contains_identity_status_gaps_targets_claims_and_ordered_results() {
        let report = report(
            ReportStatus::Findings,
            vec![finding("z", "last"), finding("a", "first")],
        );
        let value: serde_json::Value =
            serde_json::from_str(&render_sarif(&report).unwrap()).unwrap();
        let run = &value["runs"][0];
        assert_eq!(run["properties"]["reportId"], "report-1");
        assert_eq!(run["properties"]["status"], "findings");
        assert_eq!(
            run["properties"]["gaps"][0],
            "provider denominator unavailable"
        );
        assert_eq!(run["properties"]["targets"][0], "src/lib.rs");
        assert_eq!(run["properties"]["claims"]["coverage"]["examined"], 0);
        assert_eq!(run["results"][0]["ruleId"], "a");
        assert_eq!(
            run["results"][0]["locations"][0]["physicalLocation"]["region"]["startLine"],
            12
        );
    }

    #[test]
    fn html_and_markdown_escape_untrusted_fields_and_show_provider() {
        let mut item = finding("bad`<id>", "<script>alert(1)</script>");
        item.message = "<img src=x> ` | [link]".into();
        item.provider = Some("<provider>".into());
        item.locations = vec!["file`<x>.rs:1".into()];
        let report = report(ReportStatus::Findings, vec![item]);
        let html = render_html(&report).unwrap();
        let markdown = render_markdown(&report).unwrap();
        assert!(!html.contains("<script>") && html.contains("&lt;script&gt;"));
        assert!(html.contains("&lt;provider&gt;") && html.contains("&lt;img src=x&gt;"));
        assert!(!markdown.contains("<script>") && markdown.contains("\\<script\\>"));
        assert!(markdown.contains("\\<provider\\>"));
        assert!(markdown.contains("bad\\`\\<id\\>"));
    }
}
