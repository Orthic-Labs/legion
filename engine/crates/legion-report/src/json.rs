use legion_contracts::{canonical_json_bytes, ReportV1, ReportV2};

use crate::{
    error::{validate, ReportError},
    ordered_findings,
};

pub fn render(report: &ReportV1) -> Result<String, ReportError> {
    validate(report)?;
    let mut value = serde_json::to_value(report)?;
    if let Some(findings) = value
        .get_mut("findings")
        .and_then(serde_json::Value::as_array_mut)
    {
        let ordered = ordered_findings(report)
            .into_iter()
            .map(|finding| serde_json::to_value(finding).map_err(ReportError::from))
            .collect::<Result<Vec<_>, _>>()?;
        *findings = ordered;
    }
    let bytes = canonical_json_bytes(&value)
        .map_err(|error| ReportError::Serialization(error.to_string()))?;
    String::from_utf8(bytes).map_err(|_| ReportError::InvalidUtf8)
}

pub fn to_json(report: &ReportV1) -> Result<String, ReportError> {
    render(report)
}

/// Renders a v2 report at the requested schema: `2` natively, `1` as the
/// compatible projection (`--report-schema 1`). Findings are ordered like
/// [`render`].
pub fn render_schema(report: &ReportV2, schema: u32) -> Result<String, ReportError> {
    let mut ordered = report.clone();
    ordered.findings.sort_by(|left, right| {
        let key = |finding: &legion_contracts::FindingV2| {
            let core = finding.v1_core();
            (
                core.id.as_str().to_owned(),
                crate::first_location(&core),
                core.message,
            )
        };
        key(left).cmp(&key(right))
    });
    let value = ordered
        .to_value_for_schema(schema)
        .map_err(|error| ReportError::Contract(error.to_string()))?;
    let bytes = canonical_json_bytes(&value)
        .map_err(|error| ReportError::Serialization(error.to_string()))?;
    String::from_utf8(bytes).map_err(|_| ReportError::InvalidUtf8)
}

#[cfg(test)]
mod schema_tests {
    use super::*;
    use legion_contracts::{Finding, FindingId, LiftContext, ReportId, ReportScope, ReportStatus};
    use std::collections::BTreeMap;

    #[test]
    fn schema_flag_selects_v2_or_v1_projection_with_same_status() {
        let v1 = ReportV1 {
            schema_version: 1,
            report_id: ReportId::new("r").unwrap(),
            status: ReportStatus::Findings,
            findings: vec![Finding {
                id: FindingId::new("f-1").unwrap(),
                severity: "high".into(),
                title: "t".into(),
                message: "m".into(),
                provider: Some("rules".into()),
                locations: vec!["a.rs:1".into()],
                evidence: BTreeMap::new(),
            }],
            gaps: Vec::new(),
            claims: BTreeMap::new(),
            targets: vec!["repo".into()],
            extensions: BTreeMap::new(),
        };
        let resolve = |_: &str| -> Option<Vec<u8>> { Some(b"x\n".to_vec()) };
        let scope = ReportScope::legacy();
        let v2 = ReportV2::from_v1_with(&v1, &LiftContext::new(scope, &resolve)).unwrap();
        let native: serde_json::Value =
            serde_json::from_str(&render_schema(&v2, 2).unwrap()).unwrap();
        let projected: serde_json::Value =
            serde_json::from_str(&render_schema(&v2, 1).unwrap()).unwrap();
        assert_eq!(native["schema_version"], 2);
        assert_eq!(projected["schema_version"], 1);
        assert_eq!(native["status"], projected["status"]);
        assert!(projected["findings"][0]["evidence"]["legionV2"].is_object());
        assert!(render_schema(&v2, 3).is_err());
    }
}
