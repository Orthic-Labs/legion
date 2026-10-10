//! Rust-owned adapters for security-family provider records.
//!
//! The adapter analyses artifacts; it never spawns a tool itself. Artifacts come
//! from the host (`new`) or, when none were injected and a root was supplied
//! (`with_root`), from the self-sourcing [`ArtifactProducer`]. A missing
//! artifact or receipt is never turned into success.

use std::collections::BTreeMap;

use legion_contracts::{
    Coverage, FindingId, FindingRef, ProviderId, ProviderResult, ProviderStatus,
};
use serde_json::{json, Value};

use crate::{
    error::AuditError, execution::ProviderExecutor, inventory::InventoryEnvelope,
    plan::AuditProvider,
};

use super::{
    ast_grep, container_iac, dependency_osv, imported_sarif, opengrep,
    producer::{ArtifactProducer, Production},
    secrets, supply_chain,
};

#[derive(Clone, Debug, Default)]
pub struct SecurityProviderExecutor {
    /// Keyed by provider id; values are immutable host-produced projections.
    pub artifacts: BTreeMap<String, Value>,
    /// Used only for providers with no injected artifact.
    pub producer: Option<ArtifactProducer>,
}

impl SecurityProviderExecutor {
    pub fn new(artifacts: BTreeMap<String, Value>) -> Self {
        Self {
            artifacts,
            producer: None,
        }
    }

    /// Source artifacts for the audited `root` when the host injected none.
    pub fn with_root(self, root: impl Into<std::path::PathBuf>) -> Self {
        self.with_producer(ArtifactProducer::new(root))
    }

    pub fn with_producer(mut self, producer: ArtifactProducer) -> Self {
        self.producer = Some(producer);
        self
    }

    pub fn analyze(&self, provider: &AuditProvider) -> Option<Value> {
        let input = self
            .artifacts
            .get(&provider.id)
            .cloned()
            .unwrap_or_else(|| json!({}));
        Self::analyze_input(provider, &input)
    }

    fn analyze_input(provider: &AuditProvider, input: &Value) -> Option<Value> {
        let input = input.clone();
        Some(match provider.id.as_str() {
            "container.iac" => container_iac::analyze(&input),
            "dependency.osv" => dependency_osv::analyze(&input),
            "secrets.current-history" => secrets::analyze(&input),
            "security.opengrep" => opengrep::analyze(&input),
            "structural.ast-grep" => ast_grep::analyze(&input),
            "supply-chain.license-sbom-provenance" => supply_chain::analyze(&input),
            "imported.sarif" => imported_sarif::analyze(&input),
            _ => return None,
        })
    }
}

impl ProviderExecutor for SecurityProviderExecutor {
    fn execute(
        &self,
        provider: &AuditProvider,
        inventory: &InventoryEnvelope,
    ) -> Result<ProviderResult, AuditError> {
        let mut unavailable_reason = None;
        let mut produced = None;
        if !self.artifacts.contains_key(&provider.id) {
            if let Some(producer) = &self.producer {
                match producer.produce(provider, inventory) {
                    Production::Artifact(value) => produced = Some(value),
                    Production::Unavailable(reason) => unavailable_reason = Some(reason),
                }
            }
        }
        let input = self.artifacts.get(&provider.id).or(produced.as_ref());
        let Some(analysis) =
            Self::analyze_input(provider, input.unwrap_or(&json!({})))
        else {
            return Err(AuditError::Provider(format!(
                "unsupported security provider {}",
                provider.id
            )));
        };
        let provider_id = ProviderId::new(provider.id.clone())?;
        let expected = analysis
            .get("denominator")
            .and_then(|d| d.get("expected"))
            .and_then(Value::as_u64)
            .unwrap_or(0);
        let examined = analysis
            .get("denominator")
            .and_then(|d| d.get("examined"))
            .and_then(Value::as_u64)
            .unwrap_or(0);
        let gaps = analysis
            .get("coverageGaps")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        let complete = analysis.get("complete").and_then(Value::as_bool) == Some(true)
            && expected == examined
            && expected > 0
            && gaps.is_empty();
        let status_text = analysis
            .get("status")
            .and_then(Value::as_str)
            .unwrap_or("unproven");
        let applicable = analysis
            .get("applicable")
            .and_then(Value::as_bool)
            .unwrap_or(true);
        let status = if complete {
            ProviderStatus::Complete
        } else if matches!(status_text, "pass" | "candidates") {
            ProviderStatus::Partial
        } else {
            ProviderStatus::Failed
        };
        let denominator_digest = provider
            .configuration
            .get("denominatorDigest")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned();
        let coverage = (expected > 0).then_some(Coverage {
            denominator_digest,
            expected,
            examined,
            gaps: gaps
                .iter()
                .map(|gap| serde_json::to_string(gap).unwrap_or_else(|_| "coverage-gap".into()))
                .collect(),
        });
        let findings = analysis
            .get("findings")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(|finding| {
                let id = finding
                    .get("id")
                    .or_else(|| finding.get("ruleId"))
                    .and_then(Value::as_str)?;
                Some(FindingRef {
                    id: FindingId::new(id).ok()?,
                    severity: finding
                        .get("severity")
                        .and_then(Value::as_str)
                        .unwrap_or("warning")
                        .into(),
                })
            })
            .collect::<Vec<_>>();
        let candidates = analysis
            .get("candidates")
            .cloned()
            .unwrap_or_else(|| json!([]));
        let mut details = BTreeMap::from([
            (String::from("analysis"), analysis.clone()),
            (String::from("candidates"), candidates),
        ]);
        // Preserve terminal receipts at the contract boundary. The generic
        // Audit executor validates this projection before accepting results.
        if let Some(receipt) = input
            .and_then(|value| value.get("executionReceipt"))
            .or_else(|| analysis.get("executionReceipt"))
        {
            details.insert("executionReceipt".into(), receipt.clone());
        }
        // How the artifact was sourced: `tool` (receipt-bound scanner run),
        // `native-fallback`, or `file` (repository SARIF).
        if let Some(producer) = input.and_then(|value| value.get("producer")) {
            details.insert("producer".into(), producer.clone());
        }
        // With no host-supplied artifact there is nothing to analyze: the
        // plan selected this provider, so it is applicable but unavailable.
        let artifact_supplied = input.is_some();
        let mut result = ProviderResult {
            schema_version: 1,
            provider: provider_id,
            applicable: applicable || !artifact_supplied,
            required: provider.required,
            status,
            complete,
            coverage,
            findings,
            coverage_gaps: gaps
                .iter()
                .map(|gap| serde_json::to_string(gap).unwrap_or_else(|_| "coverage-gap".into()))
                .collect(),
            degradation: Vec::new(),
            details,
        };
        if !artifact_supplied {
            crate::native_providers::availability::mark_unavailable(
                &mut result,
                &unavailable_reason
                    .unwrap_or_else(|| format!("artifact-not-produced:{}", provider.id)),
            );
        }
        Ok(result)
    }
}
