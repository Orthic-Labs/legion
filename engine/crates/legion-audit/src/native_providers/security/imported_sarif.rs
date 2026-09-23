use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use super::common::{array, digest};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ImportedSarif {
    pub schema_version: u32,
    pub digest: String,
    pub tool_identity: Value,
    pub raw_immutable: bool,
    pub raw_bytes: usize,
    pub results: Vec<Value>,
}

pub fn ingest_sarif(
    artifact: Option<&Value>,
    raw_bytes: Option<&[u8]>,
    binding: &Value,
    expected_digest: Option<&str>,
    tool_identity: &Value,
) -> Result<ImportedSarif, String> {
    let parsed = match artifact {
        Some(value) => value.clone(),
        None => {
            let raw_bytes = raw_bytes.ok_or_else(|| "unsupported SARIF schema".to_string())?;
            serde_json::from_slice(raw_bytes).map_err(|e| format!("invalid SARIF JSON: {e}"))?
        }
    };
    if let Some(schema) = parsed.get("schemaVersion") {
        let supported = schema.as_str() == Some("2.1.0") || schema.as_u64() == Some(2);
        if !supported {
            return Err("unsupported SARIF schema".into());
        }
    }
    if parsed.get("revision") != binding.get("revision")
        || parsed.get("baseUri") != binding.get("root")
    {
        return Err("imported artifact binding mismatch".into());
    }
    let Some(raw_bytes) = raw_bytes else {
        return Err("immutable SARIF raw bytes required".into());
    };
    let actual_digest = digest(raw_bytes);
    if expected_digest.is_none_or(|expected| expected != actual_digest) {
        return Err("imported artifact digest mismatch".into());
    }
    if tool_identity
        .get("name")
        .and_then(Value::as_str)
        .is_none_or(str::is_empty)
        || tool_identity
            .get("version")
            .and_then(Value::as_str)
            .is_none_or(str::is_empty)
    {
        return Err("bound tool identity required".into());
    }
    Ok(ImportedSarif {
        schema_version: 1,
        digest: actual_digest,
        tool_identity: tool_identity.clone(),
        raw_immutable: true,
        raw_bytes: raw_bytes.len(),
        results: array(parsed.get("results")),
    })
}

pub fn analyze(input: &Value) -> Value {
    let supplied = array(input.get("artifacts").and_then(|a| a.get("importedSarif")));
    let mut normalized = Vec::new();
    let mut gaps = Vec::new();
    for item in &supplied {
        let raw = item.get("rawBytes").and_then(Value::as_str).map(str::as_bytes);
        let binding = item
            .get("binding")
            .or_else(|| input.get("plan").and_then(|p| p.get("repositoryBinding")))
            .unwrap_or(&Value::Null);
        let expected = item.get("expectedDigest").and_then(Value::as_str);
        let tool = item.get("toolIdentity").unwrap_or(&Value::Null);
        match ingest_sarif(item.get("artifact"), raw, binding, expected, tool) {
            Ok(result) => normalized.push(result),
            Err(reason) => gaps.push(json!({"kind":"imported-sarif-invalid","reason":reason})),
        }
    }
    if supplied.is_empty() {
        gaps.push(json!({"kind":"imported-sarif-not-supplied"}));
    }
    let findings = normalized
        .iter()
        .flat_map(|item| item.results.clone())
        .collect::<Vec<_>>();
    json!({"applicable":!supplied.is_empty(),"status":if gaps.is_empty(){"pass"}else{"unproven"},"complete":!supplied.is_empty()&&gaps.is_empty(),"denominator":{"kind":"supplied-sarif-artifacts","expected":supplied.len(),"examined":normalized.len()},"findings":findings,"coverageGaps":gaps})
}
