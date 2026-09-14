//! Shared, read-only plumbing for providers migrated from the historical
//! JavaScript audit surface.  This module deliberately contains no process,
//! shell, or interpreter boundary.

use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};

use legion_contracts::{
    Coverage, FindingId, FindingRef, ProviderId, ProviderResult, ProviderStatus,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::{
    error::AuditError,
    execution::ProviderExecutor,
    inventory::{InventoryDenominator, InventoryEntry, InventoryEnvelope},
    plan::AuditProvider,
};

/// Input available to one native legacy provider.
///
/// `artifacts` is intentionally opaque JSON: provider-specific artifact
/// schemas belong to their source modules, while this adapter preserves them
/// without making the Rust audit core depend on a source-language runtime.
#[derive(Clone, Debug)]
pub struct ProviderInput<'a> {
    pub provider: &'a AuditProvider,
    pub inventory: &'a InventoryEnvelope,
    pub root: &'a Path,
    pub artifacts: &'a Value,
    pub now: Option<&'a str>,
}

pub fn provider_id(provider: &AuditProvider) -> Result<ProviderId, AuditError> {
    ProviderId::new(&provider.id).map_err(AuditError::from)
}

pub fn selector(provider: &AuditProvider) -> Result<&Value, AuditError> {
    provider
        .configuration
        .get("selector")
        .ok_or_else(|| AuditError::Provider(format!("provider {} has no selector", provider.id)))
}

pub fn denominator(input: &ProviderInput<'_>) -> Result<InventoryDenominator, AuditError> {
    input
        .inventory
        .denominator_entries(selector(input.provider)?)
}

pub fn digest_text(value: &str) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(value.as_bytes())))
}

pub fn digest_bytes(value: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(value)))
}

pub fn finding(rule_id: &str, severity: &str, file: &str, line: usize) -> FindingRef {
    let id = digest_text(&format!("{rule_id}\0{file}\0{line}"));
    FindingRef {
        id: FindingId::new(id).expect("sha256 finding id is valid"),
        severity: severity.to_owned(),
    }
}

pub fn result(
    input: &ProviderInput<'_>,
    status: ProviderStatus,
    complete: bool,
    denominator: &InventoryDenominator,
    examined: usize,
    findings: Vec<FindingRef>,
    gaps: Vec<String>,
    degradation: Vec<String>,
    details: BTreeMap<String, Value>,
) -> Result<ProviderResult, AuditError> {
    let provider = provider_id(input.provider)?;
    let mut gaps = gaps;
    gaps.sort();
    gaps.dedup();
    let mut degradation = degradation;
    degradation.sort();
    degradation.dedup();
    let mut details = details;
    details
        .entry("selector".into())
        .or_insert_with(|| selector(input.provider).cloned().unwrap_or(Value::Null));
    // Every ProviderResult finding must carry a typed evidence/location map
    // for the audit boundary.  Provider-specific analysis remains in details;
    // this fallback keeps artifact findings visible without inventing source
    // files when a denominator is empty.
    let fallback_path = denominator
        .entries
        .first()
        .map(|entry| entry.path.clone())
        .unwrap_or_else(|| "provider-artifacts".into());
    let mut evidence = match details.remove("findingEvidence") {
        Some(Value::Object(value)) => value,
        _ => Default::default(),
    };
    let mut locations = match details.remove("findingLocations") {
        Some(Value::Object(value)) => value,
        _ => Default::default(),
    };
    for item in &findings {
        let id = item.id.to_string();
        evidence
            .entry(id.clone())
            .or_insert_with(|| json!({"provider": input.provider.id.clone()}));
        locations
            .entry(id)
            .or_insert_with(|| json!([fallback_path.clone()]));
    }
    details.insert("findingEvidence".into(), Value::Object(evidence));
    details.insert("findingLocations".into(), Value::Object(locations));
    let mut result = ProviderResult {
        schema_version: 1,
        provider,
        applicable: true,
        required: input.provider.required,
        status,
        complete,
        coverage: Some(Coverage {
            denominator_digest: denominator.digest.clone(),
            expected: denominator.entries.len() as u64,
            examined: examined as u64,
            gaps: gaps.clone(),
        }),
        findings,
        coverage_gaps: gaps,
        degradation,
        details,
    };
    result.validate().map_err(AuditError::from)?;
    Ok(result)
}

pub fn source_files(
    input: &ProviderInput<'_>,
    denominator: &InventoryDenominator,
) -> (Vec<(InventoryEntry, String)>, Vec<String>) {
    let mut files = Vec::new();
    let mut gaps = Vec::new();
    for entry in &denominator.entries {
        let path = input.root.join(&entry.path);
        match std::fs::read_to_string(&path) {
            Ok(text) => files.push((entry.clone(), text)),
            Err(error) => gaps.push(format!("source-unavailable:{}:{error}", entry.path)),
        }
    }
    (files, gaps)
}

pub fn line_at(text: &str, offset: usize) -> usize {
    text[..offset.min(text.len())]
        .bytes()
        .filter(|byte| *byte == b'\n')
        .count()
        + 1
}

pub fn occurrences(text: &str, needle: &str) -> Vec<usize> {
    if needle.is_empty() {
        return Vec::new();
    }
    let mut out = Vec::new();
    let mut offset = 0;
    while let Some(index) = text[offset..].find(needle) {
        let absolute = offset + index;
        out.push(absolute);
        offset = absolute + needle.len();
        if offset >= text.len() {
            break;
        }
    }
    out
}

pub fn occurrences_ascii_case_insensitive(text: &str, needle: &str) -> Vec<usize> {
    let text = text.to_ascii_lowercase();
    let needle = needle.to_ascii_lowercase();
    occurrences(&text, &needle)
}

pub fn has_ascii_case_insensitive(text: &str, needle: &str) -> bool {
    !occurrences_ascii_case_insensitive(text, needle).is_empty()
}

pub fn details_for_findings(
    findings: &[FindingRef],
    files: &BTreeMap<String, (String, usize)>,
) -> BTreeMap<String, Value> {
    let mut evidence = serde_json::Map::new();
    let mut locations = serde_json::Map::new();
    for finding in findings {
        if let Some((file, line)) = files.get(finding.id.as_str()) {
            evidence.insert(finding.id.to_string(), json!({"path": file, "line": line}));
            locations.insert(finding.id.to_string(), json!([format!("{file}:{line}")]));
        }
    }
    BTreeMap::from([
        ("findingEvidence".into(), Value::Object(evidence)),
        ("findingLocations".into(), Value::Object(locations)),
    ])
}

/// In-process adapter used by the audit executor.  Callers may inject source
/// artifacts and clock explicitly; omitted values stay omitted and therefore
/// produce the same typed unproven outcomes as the legacy providers.
#[derive(Clone, Debug)]
pub struct ProviderExecutorAdapter {
    root: PathBuf,
    artifacts: Value,
    now: Option<String>,
}

/// Stable aliases used by integration owners while composing the package's
/// public native-provider module.
pub type LegacyProviderExecutor = ProviderExecutorAdapter;
pub type NativeLegacyProviderExecutor = ProviderExecutorAdapter;

impl ProviderExecutorAdapter {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self {
            root: root.into(),
            artifacts: Value::Object(Default::default()),
            now: None,
        }
    }

    pub fn with_artifacts(mut self, artifacts: Value) -> Self {
        self.artifacts = artifacts;
        self
    }

    pub fn with_now(mut self, now: impl Into<String>) -> Self {
        self.now = Some(now.into());
        self
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn input<'a>(
        &'a self,
        provider: &'a AuditProvider,
        inventory: &'a InventoryEnvelope,
    ) -> ProviderInput<'a> {
        ProviderInput {
            provider,
            inventory,
            root: &self.root,
            artifacts: &self.artifacts,
            now: self.now.as_deref(),
        }
    }
}

impl ProviderExecutor for ProviderExecutorAdapter {
    fn execute(
        &self,
        provider: &AuditProvider,
        inventory: &InventoryEnvelope,
    ) -> Result<ProviderResult, AuditError> {
        let input = self.input(provider, inventory);
        match provider.id.as_str() {
            "governance.policy" => super::governance::execute(&input),
            "legacy.accessibility.internal-suite" => super::accessibility::execute(&input),
            "legacy.framework.major-suite" => super::framework::execute(&input),
            "legacy.visual.core" => super::visual::execute(&input),
            _ => Err(AuditError::Provider(format!(
                "unsupported native legacy provider {}",
                provider.id
            ))),
        }
    }
}
