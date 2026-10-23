#![forbid(unsafe_code)]

use legion_contracts::{Finding, ReportStatus, ReportV1, ReportV2};

pub mod error;
pub mod escape;
pub mod html;
pub mod json;
pub mod markdown;
pub mod ponytail;
pub mod review;
pub mod sarif;
pub mod trend;

pub use error::ReportError;

pub fn render_json(report: &ReportV1) -> Result<String, ReportError> {
    json::render(report)
}
/// Renders a v2 report as schema 2 (native) or schema 1 (projection).
pub fn render_json_schema(report: &ReportV2, schema: u32) -> Result<String, ReportError> {
    json::render_schema(report, schema)
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

/// Renders an evidence-preserving source review from a schema-v2 report.
pub fn render_review(report: &ReportV2) -> Result<String, ReportError> {
    report
        .validate()
        .map_err(|error| ReportError::Contract(error.to_string()))?;
    Ok(review::render(report))
}

/// Renders the canonical Ponytail five-tag finding projection from a v2 report.
pub fn render_ponytail(report: &ReportV2) -> Result<String, ReportError> {
    report
        .validate()
        .map_err(|error| ReportError::Contract(error.to_string()))?;
    Ok(ponytail::render(report))
}

/// Renders GitHub's review-file JSON shape. This only creates a local payload;
/// it never posts a review or comment.
pub fn render_github_review(report: &ReportV2) -> Result<String, ReportError> {
    report
        .validate()
        .map_err(|error| ReportError::Contract(error.to_string()))?;
    review::render_github_review(report)
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

    #[test]
    fn native_minimize_projection_reaches_json_review_comments_and_ponytail() {
        // Native ingest copies action into title, failureScenario into message,
        // & canonical lens fields into evidence. Lift against actual bytes as
        // audit's report writer does; supplied model confidence is not proof.
        let action = "inline the only implementation";
        let case = "wrapper delegates to its sole implementation";
        let item = Finding {
            id: FindingId::new("minimize-1").unwrap(),
            severity: "medium".into(),
            title: action.into(),
            message: case.into(),
            provider: Some("reasoning.minimize".into()),
            locations: vec!["src/lib.rs:2".into()],
            evidence: BTreeMap::from([
                ("lens".into(), json!("minimize")),
                ("confidence".into(), json!("likely")),
                ("verifyStatus".into(), json!("unverified")),
                ("ponytailTag".into(), json!("yagni")),
                ("action".into(), json!(action)),
                ("failureScenario".into(), json!(case)),
            ]),
        };
        let native = report(ReportStatus::Incomplete, vec![item]);
        let resolve = |path: &str| {
            (path == "src/lib.rs")
                .then(|| b"pub fn wrapper() {\n    implementation();\n}\n".to_vec())
        };
        let diff = |_: &str, _: u32, _: u32| legion_contracts::DiffTag::InDiff;
        let mut context =
            legion_contracts::LiftContext::new(legion_contracts::ReportScope::legacy(), &resolve);
        context.diff_tag = Some(&diff);
        let lifted = ReportV2::from_v1_with(&native, &context).unwrap();
        assert_eq!(
            lifted.findings[0].confidence,
            legion_contracts::Confidence::Likely
        );
        let json: serde_json::Value =
            serde_json::from_str(&render_json_schema(&lifted, 2).unwrap()).unwrap();
        assert_eq!(json["findings"][0]["evidence"]["action"], action);
        assert_eq!(json["findings"][0]["evidence"]["failureScenario"], case);
        let review = render_review(&lifted).unwrap();
        assert!(review.contains(&format!("Supplied fix: {action}")));
        let payload: serde_json::Value =
            serde_json::from_str(&render_github_review(&lifted).unwrap()).unwrap();
        let comments = payload["comments"].as_array().unwrap();
        assert_eq!(comments.len(), 1);
        assert_eq!(comments[0]["path"], "src/lib.rs");
        assert_eq!(comments[0]["line"], 2);
        let body = comments[0]["body"].as_str().unwrap();
        assert!(body.contains(&format!("Supplied fix: {action}")));
        assert!(body.contains(&format!("Case: {case}")));
        assert!(body.contains("Confidence: `likely`"));
        assert!(!body.contains("proven"));
        let ponytail = render_ponytail(&lifted).unwrap();
        assert!(ponytail.contains(&format!("yagni {case}. {action}. [src/lib.rs:2]")));
        assert!(ponytail.contains("net: unavailable"));
        assert!(ponytail.contains("inspired by Ponytail"));
        assert!(review.contains("inspired by CodeRabbit"));
        assert!(ponytail.contains("provider denominator unavailable"));

        let mut missing = lifted.clone();
        missing.findings[0].evidence.remove("failureScenario");
        let missing_ponytail = render_ponytail(&missing).unwrap();
        assert!(missing_ponytail.contains("Case: unavailable"));
        let mut outside_diff = lifted;
        outside_diff.findings[0].anchor.as_mut().unwrap().state =
            legion_contracts::AnchorState::BeyondDiff;
        let outside: serde_json::Value =
            serde_json::from_str(&render_github_review(&outside_diff).unwrap()).unwrap();
        assert_eq!(outside["comments"].as_array().unwrap().len(), 0);
        assert!(outside["body"].as_str().unwrap().contains(action));
    }
}
