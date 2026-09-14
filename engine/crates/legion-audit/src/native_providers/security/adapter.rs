//! Rust-owned adapters for security-family provider records.
//!
//! This adapter consumes host-published artifacts only. It intentionally does
//! not spawn tools, invoke a runtime, or turn a missing receipt into success.

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
    ast_grep, container_iac, dependency_osv, imported_sarif, opengrep, secrets, supply_chain,
};

#[derive(Clone, Debug, Default)]
pub struct SecurityProviderExecutor {
    /// Keyed by provider id; values are immutable host-produced projections.
    pub artifacts: BTreeMap<String, Value>,
}

impl SecurityProviderExecutor {
    pub fn new(artifacts: BTreeMap<String, Value>) -> Self {
        Self { artifacts }
    }

    pub fn analyze(&self, provider: &AuditProvider) -> Option<Value> {
        let input = self
            .artifacts
            .get(&provider.id)
            .cloned()
            .unwrap_or_else(|| json!({}));
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
        _inventory: &InventoryEnvelope,
    ) -> Result<ProviderResult, AuditError> {
        let Some(analysis) = self.analyze(provider) else {
            return Err(AuditError::Provider(format!(
                "unsupported security provider {}",
                provider.id
            )));
        };
        let input = self.artifacts.get(&provider.id);
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
        Ok(ProviderResult {
            schema_version: 1,
            provider: provider_id,
            applicable,
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
        })
    }
}
