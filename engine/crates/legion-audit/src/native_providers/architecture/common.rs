use legion_contracts::{Coverage, FindingRef, ProviderId, ProviderResult, ProviderStatus};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::collections::BTreeMap;

/// JSON-shaped result emitted by one ported source provider.  Keeping this
/// shape close to Node's result makes parity checks straightforward.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Analysis {
    pub status: String,
    pub complete: bool,
    pub denominator: Value,
    pub findings: Vec<Value>,
    pub coverage_gaps: Vec<Value>,
    pub extras: Map<String, Value>,
    #[serde(skip)]
    pub include_findings: bool,
}

impl Analysis {
    pub fn new(status: impl Into<String>, complete: bool, denominator: Value) -> Self {
        Self {
            status: status.into(),
            complete,
            denominator,
            findings: Vec::new(),
            coverage_gaps: Vec::new(),
            extras: Map::new(),
            include_findings: true,
        }
    }

    pub fn output(&self) -> Value {
        let mut output = Map::new();
        output.insert("status".into(), Value::String(self.status.clone()));
        output.insert("complete".into(), Value::Bool(self.complete));
        if !self.denominator.is_null() {
            output.insert("denominator".into(), self.denominator.clone());
        }
        if self.include_findings {
            output.insert("findings".into(), Value::Array(self.findings.clone()));
        }
        output.insert(
            "coverageGaps".into(),
            Value::Array(self.coverage_gaps.clone()),
        );
        output.extend(self.extras.clone());
        Value::Object(output)
    }
}

pub fn object_input(input: &Value) -> Result<&Map<String, Value>, String> {
    input
        .as_object()
        .ok_or_else(|| "provider input must be an object".to_owned())
}

pub fn array_or_empty<'a>(object: &'a Map<String, Value>, key: &str) -> Vec<&'a Value> {
    object
        .get(key)
        .and_then(Value::as_array)
        .map(|values| values.iter().collect())
        .unwrap_or_default()
}

pub fn truthy(value: Option<&Value>) -> bool {
    match value {
        None | Some(Value::Null) | Some(Value::Bool(false)) => false,
        Some(Value::Bool(true)) => true,
        Some(Value::String(value)) => !value.is_empty(),
        Some(Value::Number(value)) => value.as_f64().is_some_and(|number| number != 0.0),
        Some(Value::Array(value)) => !value.is_empty(),
        Some(Value::Object(_)) => true,
    }
}

pub fn gap(kind: &str) -> Value {
    serde_json::json!({ "kind": kind })
}

pub fn string_gap(value: &Value) -> String {
    value
        .get("kind")
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| value.to_string())
}

pub fn provider_result(
    provider: &str,
    required: bool,
    denominator_digest: String,
    expected: usize,
    analysis: &Analysis,
    input: Value,
    errors: Vec<Value>,
    denominator_paths: &[String],
) -> Result<ProviderResult, String> {
    let provider_id = ProviderId::new(provider).map_err(|error| error.to_string())?;
    let mut details = BTreeMap::new();
    details.insert("nativeInput".into(), input);
    details.insert("nativeAnalysis".into(), analysis.output());
    if !errors.is_empty() {
        details.insert("nativeErrors".into(), Value::Array(errors));
    }

    let mut finding_refs = Vec::with_capacity(analysis.findings.len());
    let mut evidence = Map::new();
    let mut locations = Map::new();
    for (index, finding) in analysis.findings.iter().enumerate() {
        let id = finding
            .get("id")
            .and_then(Value::as_str)
            .filter(|id| !id.is_empty())
            .map(ToOwned::to_owned)
            .unwrap_or_else(|| format!("{provider}:{index}"));
        let severity = finding
            .get("severity")
            .and_then(Value::as_str)
            .unwrap_or("warning")
            .to_owned();
        let finding_id =
            legion_contracts::FindingId::new(id.clone()).map_err(|error| error.to_string())?;
        finding_refs.push(FindingRef {
            id: finding_id,
            severity,
        });
        evidence.insert(id.clone(), finding.clone());
        let location = finding
            .get("path")
            .or_else(|| finding.get("evidencePath"))
            .and_then(Value::as_str)
            .map(|path| serde_json::json!([path]))
            .or_else(|| {
                denominator_paths
                    .first()
                    .map(|path| serde_json::json!([path]))
            })
            .unwrap_or_else(|| serde_json::json!([]));
        locations.insert(id, location);
    }
    details.insert("findingEvidence".into(), Value::Object(evidence));
    details.insert("findingLocations".into(), Value::Object(locations));

    let gaps = analysis
        .coverage_gaps
        .iter()
        .map(string_gap)
        .collect::<Vec<_>>();
    let status = match analysis.status.as_str() {
        "pass" | "measured" => ProviderStatus::Complete,
        "fail" => ProviderStatus::Failed,
        _ => ProviderStatus::Partial,
    };
    let complete = analysis.complete;
    // ProviderResult coverage is bound to frozen repository selector scope;
    // the original analyzer denominator remains losslessly available under
    // `nativeAnalysis.denominator`.
    let examined = if complete {
        expected
    } else {
        analysis
            .denominator
            .get("examined")
            .and_then(Value::as_u64)
            .unwrap_or(0)
            .min(expected as u64) as usize
    };
    let result = ProviderResult {
        schema_version: 1,
        provider: provider_id,
        applicable: true,
        required,
        status,
        complete,
        coverage: Some(Coverage {
            denominator_digest,
            expected: expected as u64,
            examined: examined as u64,
            gaps: gaps.clone(),
        }),
        findings: finding_refs,
        coverage_gaps: gaps.clone(),
        degradation: gaps,
        details,
    };
    result.validate().map_err(|error| error.to_string())?;
    Ok(result)
}
