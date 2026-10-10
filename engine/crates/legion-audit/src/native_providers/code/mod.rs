pub mod c_family;
pub mod common;
pub mod dotnet;
pub mod evidence;
pub mod go;
pub mod javascript;
pub mod jvm;
pub mod long_tail;
pub mod mobile;
pub mod php_ruby;
pub mod python;
pub mod rust;

use crate::{AuditError, AuditProvider, InventoryEnvelope, ProviderExecutor};
use legion_contracts::{
    Coverage, FindingId, FindingRef, ProviderId, ProviderResult, ProviderStatus,
};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::path::PathBuf;

/// Executes the `code.*` providers.
///
/// Input precedence: host-injected input (`provider.configuration["input"]` or
/// `with_input`) is analyzed as given. Absent that, the adapter self-sources
/// its input from the provider's frozen denominator under `root` (see
/// [`evidence`]); with no `root` it falls back to the process working
/// directory, and any file whose bytes do not match the inventory digest is
/// reported as a skip rather than examined.
#[derive(Clone, Debug, Default)]
pub struct ProviderExecutorAdapter {
    root: Option<PathBuf>,
    inputs: BTreeMap<String, Value>,
    limits: evidence::EvidenceLimits,
}

impl ProviderExecutorAdapter {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_root(mut self, root: impl Into<PathBuf>) -> Self {
        self.root = Some(root.into());
        self
    }

    pub fn with_input(mut self, provider: impl Into<String>, input: Value) -> Self {
        self.inputs.insert(provider.into(), input);
        self
    }

    pub fn with_limits(mut self, limits: evidence::EvidenceLimits) -> Self {
        self.limits = limits;
        self
    }
}

fn analyze(provider_id: &str, input: &Value) -> Result<Value, AuditError> {
    Ok(match provider_id {
        "code.c-family" => c_family::analyze(input),
        "code.dotnet" => dotnet::analyze(input),
        "code.go" => go::analyze(input),
        "code.javascript" => javascript::analyze(input),
        "code.jvm" => jvm::analyze(input),
        "code.long-tail" => long_tail::analyze(input),
        "code.mobile" => mobile::analyze(input),
        "code.php-ruby" => php_ruby::analyze(input),
        "code.python" => python::analyze(input),
        "code.rust" => rust::analyze(input),
        other => {
            return Err(AuditError::Provider(format!(
                "unsupported native code provider: {other}"
            )))
        }
    })
}

fn finding_ref(
    provider: &str,
    finding: &evidence::NativeFinding,
) -> Result<FindingRef, AuditError> {
    let id = format!(
        "sha256:{}",
        hex::encode(Sha256::digest(
            format!(
                "{provider}\0{}\0{}\0{}",
                finding.rule, finding.path, finding.line
            )
            .as_bytes()
        ))
    );
    Ok(FindingRef {
        id: FindingId::new(id)?,
        severity: finding.severity.into(),
    })
}

impl ProviderExecutor for ProviderExecutorAdapter {
    fn execute(
        &self,
        provider: &AuditProvider,
        inventory: &InventoryEnvelope,
    ) -> Result<ProviderResult, AuditError> {
        let config = evidence::config_for(&provider.id).ok_or_else(|| {
            AuditError::Provider(format!("unsupported native code provider: {}", provider.id))
        })?;
        let injected = provider
            .configuration
            .get("input")
            .cloned()
            .or_else(|| self.inputs.get(&provider.id).cloned());

        // Host-supplied input wins and keeps the original accounting: the
        // analyzer sees exactly what the host gave it (files default to the
        // whole inventory) and no native evidence is claimed.
        let mut produced = None;
        let mut denominator_digest = inventory.digest.clone();
        let mut expected = inventory.entries.len() as u64;
        let mut examined = expected;
        let input = match injected {
            Some(mut input) => {
                let files = Value::Array(
                    inventory
                        .entries
                        .iter()
                        .map(|e| json!({"path": e.path}))
                        .collect(),
                );
                match &mut input {
                    Value::Object(object) => {
                        object.entry("files").or_insert(files);
                    }
                    other => *other = json!({ "files": files }),
                }
                input
            }
            None => {
                let selector = provider
                    .configuration
                    .get("selector")
                    .cloned()
                    .unwrap_or_else(|| json!({"op": "always"}));
                let denominator = inventory.denominator_entries(&selector)?;
                let root = self.root.clone().or_else(|| std::env::current_dir().ok());
                let made = evidence::produce(
                    &provider.id,
                    config,
                    root.as_deref(),
                    &denominator.entries,
                    &self.limits,
                )?;
                denominator_digest = denominator.digest;
                expected = made.expected;
                examined = made.examined;
                let input = made.input.clone();
                produced = Some(made);
                input
            }
        };

        let mut analysis = analyze(&provider.id, &input)?;
        if let Some(made) = &produced {
            if let Some(denominator) = analysis
                .get_mut("denominator")
                .and_then(Value::as_object_mut)
            {
                denominator.insert("examined".into(), json!(made.examined));
            }
        }
        let id = ProviderId::new(provider.id.clone())?;
        let mut complete = analysis
            .get("complete")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        // Carry the analyzer's own gaps into the result instead of dropping
        // them: a language analyzer given only file paths has no tool
        // evidence, and that must read as a gap, not as silent partial.
        let mut gaps = analysis
            .get("coverageGaps")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .map(|gap| {
                let kind = gap.get("kind").and_then(Value::as_str).unwrap_or("gap");
                let detail = ["tool", "context", "language"]
                    .iter()
                    .find_map(|key| gap.get(*key).and_then(Value::as_str));
                match detail {
                    Some(detail) => format!("{}:{kind}:{detail}", provider.id),
                    None => format!("{}:{kind}", provider.id),
                }
            })
            .collect::<Vec<_>>();
        let tool_evidence_missing = analysis
            .get("coverageGaps")
            .and_then(Value::as_array)
            .is_some_and(|items| {
                items
                    .iter()
                    .any(|gap| gap.get("kind").and_then(Value::as_str) == Some("tool-evidence-gap"))
            });

        let mut findings = Vec::new();
        let mut details = BTreeMap::new();
        if let Some(made) = &produced {
            // Every file the producer could not read is a named gap, and a
            // provider that did not read its whole scope is never complete.
            gaps.extend(
                made.skips
                    .iter()
                    .map(|skip| format!("{}:file-skipped:{skip}", provider.id)),
            );
            if made.findings_truncated > 0 {
                gaps.push(format!(
                    "{}:findings-truncated:{}",
                    provider.id, made.findings_truncated
                ));
            }
            if made.duplicate_detection_truncated {
                gaps.push(format!("{}:duplicate-detection-truncated", provider.id));
            }
            if made.examined != made.expected {
                complete = false;
            }
            let mut evidence_items = Map::new();
            let mut locations = Map::new();
            for finding in &made.findings {
                let reference = finding_ref(&provider.id, finding)?;
                let key = reference.id.to_string();
                if evidence_items.contains_key(&key) {
                    continue;
                }
                evidence_items.insert(
                    key.clone(),
                    json!({
                        "provider": provider.id,
                        "ruleId": finding.rule,
                        "path": finding.path,
                        "line": finding.line,
                        "message": finding.message,
                    }),
                );
                locations.insert(key, json!([format!("{}:{}", finding.path, finding.line)]));
                findings.push(reference);
            }
            details.insert("findingEvidence".into(), Value::Object(evidence_items));
            details.insert("findingLocations".into(), Value::Object(locations));
            details.insert(
                "nativeProducer".into(),
                json!({
                    "mode": "self-sourced",
                    "filesExpected": made.expected,
                    "filesRead": made.examined,
                    "bytesRead": made.bytes_read,
                    "rules": made.rule_ids,
                    "limits": {
                        "maxFileBytes": self.limits.max_file_bytes,
                        "maxTotalBytes": self.limits.max_total_bytes,
                        "maxFindings": self.limits.max_findings,
                    },
                    "toolDiscovery": made.tool_discovery,
                }),
            );
        }
        gaps.sort();
        gaps.dedup();
        let status = if complete {
            ProviderStatus::Complete
        } else {
            ProviderStatus::Partial
        };
        details.insert("nativeAnalysis".into(), analysis);
        let mut result = ProviderResult {
            schema_version: 1,
            provider: id,
            applicable: true,
            required: provider.required,
            status,
            complete,
            coverage: Some(Coverage {
                denominator_digest,
                expected,
                examined,
                gaps: gaps.clone(),
            }),
            findings,
            coverage_gaps: gaps,
            degradation: Vec::new(),
            details,
        };
        match &produced {
            // Self-sourced: no tool was run, so each tool is either missing
            // (typed gap) or present but without a receipt. Neither is a pass.
            Some(made) => {
                if made.expected > 0 {
                    for tool in config.tools {
                        let reason = if made.unrun_tools.contains(tool) {
                            format!("tool-not-run:{tool}")
                        } else {
                            format!("tool-missing:{tool}")
                        };
                        super::availability::mark_unavailable(&mut result, &reason);
                    }
                }
            }
            None => {
                if tool_evidence_missing {
                    super::availability::mark_unavailable(
                        &mut result,
                        &format!("tool-evidence-not-produced:{}", provider.id),
                    );
                }
            }
        }
        Ok(result)
    }
}
