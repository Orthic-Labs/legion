use legion_contracts::{canonical_json_bytes, ReportV1};

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
