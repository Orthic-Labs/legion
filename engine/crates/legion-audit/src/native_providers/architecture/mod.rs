//! Native Rust ports of source audit providers whose Node implementations are
//! pure analyzers.  This module intentionally does not load or invoke JS.

pub mod backend;
pub mod common;
pub mod compatibility;
pub mod core;
pub mod data;
pub mod docs;
pub mod docs_contract;
pub mod evidence;
pub mod framework;
pub mod frontend;
pub mod requirements;
pub mod test_quality;

pub use common::Analysis;

use crate::{AuditError, AuditProvider, InventoryEnvelope, ProviderExecutor};
use legion_contracts::ProviderResult;
use serde_json::Value;
use std::{collections::BTreeMap, path::PathBuf};

/// Inputs are supplied as frozen provider configuration (`input`) so the
/// executor remains process-free and deterministic.  `with_input` is useful
/// for hosts that keep artifact projections outside the provider plan.
#[derive(Clone, Debug, Default)]
pub struct ProviderExecutorAdapter {
    root: Option<PathBuf>,
    inputs: BTreeMap<String, Value>,
    now: Option<String>,
}

pub type NativeAuditProviderExecutor = ProviderExecutorAdapter;

impl ProviderExecutorAdapter {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_root(mut self, root: impl Into<PathBuf>) -> Self {
        self.root = Some(root.into());
        self
    }

    pub fn with_now(mut self, now: impl Into<String>) -> Self {
        self.now = Some(now.into());
        self
    }

    pub fn with_input(mut self, provider: impl Into<String>, input: Value) -> Self {
        self.inputs.insert(provider.into(), input);
        self
    }

    pub fn input_for(&self, provider: &AuditProvider) -> Value {
        provider
            .configuration
            .get("input")
            .cloned()
            .or_else(|| self.inputs.get(&provider.id).cloned())
            .unwrap_or_else(|| serde_json::json!({}))
    }

    pub fn execute_provider(
        &self,
        provider: &AuditProvider,
        inventory: &InventoryEnvelope,
    ) -> Result<ProviderResult, AuditError> {
        let input = self.input_for(provider);
        let original_input = input.clone();
        let mut input_object = input.clone();
        if let Value::Object(object) = &mut input_object {
            if let Some(root) = &self.root {
                object
                    .entry("root")
                    .or_insert_with(|| Value::String(root.to_string_lossy().into_owned()));
            }
            if let Some(now) = &self.now {
                object
                    .entry("now")
                    .or_insert_with(|| Value::String(now.clone()));
            }
        }
        let analysis = match provider.id.as_str() {
            "architecture.core" => core::analyze(&input_object),
            "compatibility.core" => compatibility::analyze(&input_object),
            "docs.contract" => docs::analyze(&input_object),
            "framework.backend" => framework::analyze_backend(&input_object),
            "framework.data" => data::analyze(&input_object),
            "framework.frontend" => framework::analyze_frontend(&input_object),
            "requirements.traceability" => requirements::analyze(&input_object),
            "test-quality.core" => test_quality::analyze(&input_object),
            other => {
                return Err(AuditError::Provider(format!(
                    "unsupported native provider: {other}"
                )))
            }
        }
        .map_err(AuditError::Provider)?;
        let selector = provider
            .configuration
            .get("selector")
            .cloned()
            .unwrap_or_else(|| serde_json::json!({"op":"always"}));
        let denominator = inventory.denominator_entries(&selector)?;
        let paths = denominator
            .entries
            .iter()
            .map(|entry| entry.path.clone())
            .collect::<Vec<_>>();
        common::provider_result(
            &provider.id,
            provider.required,
            denominator.digest,
            denominator.entries.len(),
            &analysis,
            original_input,
            Vec::new(),
            &paths,
        )
        .map_err(AuditError::Provider)
    }
}

impl ProviderExecutor for ProviderExecutorAdapter {
    fn execute(
        &self,
        provider: &AuditProvider,
        inventory: &InventoryEnvelope,
    ) -> Result<ProviderResult, AuditError> {
        self.execute_provider(provider, inventory)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn architecture_defaults_and_validation_match_node() {
        let value = serde_json::json!({"dependencyPath":["a","b"],"scenario":"s","affectedConsumers":["c"]});
        let output = core::architecture_finding(&value).unwrap();
        assert_eq!(output["schemaVersion"], 1);
        assert_eq!(output["edgeConfidence"], "observed");
        assert!(core::architecture_finding(&serde_json::json!({})).is_err());
    }

    #[test]
    fn analyzers_report_zero_denominators_as_unproven() {
        for (id, input) in [
            ("architecture.core", serde_json::json!({"projection":{}})),
            ("compatibility.core", serde_json::json!({"artifacts":{}})),
            ("docs.contract", serde_json::json!({"artifacts":{}})),
            ("framework.data", serde_json::json!({"artifacts":{}})),
            ("framework.frontend", serde_json::json!({"artifacts":{}})),
            ("framework.backend", serde_json::json!({"artifacts":{}})),
            (
                "requirements.traceability",
                serde_json::json!({"artifacts":{}}),
            ),
            ("test-quality.core", serde_json::json!({"artifacts":{}})),
        ] {
            let analysis = match id {
                "architecture.core" => core::analyze(&input),
                "compatibility.core" => compatibility::analyze(&input),
                "docs.contract" => docs::analyze(&input),
                "framework.data" => data::analyze(&input),
                "framework.frontend" => framework::analyze_frontend(&input),
                "framework.backend" => framework::analyze_backend(&input),
                "requirements.traceability" => requirements::analyze(&input),
                _ => test_quality::analyze(&input),
            }
            .unwrap();
            assert!(!analysis.complete, "{id}");
            assert_eq!(analysis.status, "unproven", "{id}");
        }
    }
}
