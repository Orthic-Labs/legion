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
pub mod nginx;
pub mod postgres;
pub mod producer;
pub mod report_compatibility;
pub mod requirements;
pub mod structure;
pub mod test_quality;

pub use common::Analysis;

use crate::{AuditError, AuditProvider, InventoryEntry, InventoryEnvelope, ProviderExecutor};
use legion_contracts::ProviderResult;
use serde_json::Value;
use std::{collections::BTreeMap, path::PathBuf, sync::Arc};

/// Inputs are supplied as frozen provider configuration (`input`) so the
/// executor remains process-free and deterministic.  `with_input` is useful
/// for hosts that keep artifact projections outside the provider plan.
#[derive(Clone, Debug, Default)]
pub struct ProviderExecutorAdapter {
    root: Option<PathBuf>,
    inputs: BTreeMap<String, Value>,
    now: Option<String>,
    producer: producer::ProducerCache,
    report_observation: Option<Arc<report_compatibility::NativeReportObservation>>,
    observation_verdicts: Vec<crate::artifact_evidence::ObservationVerdict>,
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

    /// Opaque native report-protocol observation; caller JSON cannot mint this.
    /// Generic runtime compatibility remains unproven.
    pub fn with_report_compatibility(
        mut self,
        observation: report_compatibility::NativeReportObservation,
    ) -> Self {
        self.report_observation = Some(Arc::new(observation));
        self
    }

    /// Verdicts from `verify_runtime_observation`. Only a verified observation
    /// can satisfy a named probe; rejected ones keep the obligation unknown.
    pub fn with_observation_verdicts(
        mut self,
        verdicts: Vec<crate::artifact_evidence::ObservationVerdict>,
    ) -> Self {
        self.observation_verdicts = verdicts;
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
        // Host-injected input (provider configuration or `with_input`) keeps
        // precedence. Absent that, the producer derives input from the frozen
        // denominator; an input it cannot derive stays unavailable.
        let input_supplied =
            provider.configuration.contains_key("input") || self.inputs.contains_key(&provider.id);
        let selector = provider
            .configuration
            .get("selector")
            .cloned()
            .unwrap_or_else(|| serde_json::json!({"op":"always"}));
        let denominator = inventory.denominator_entries(&selector)?;
        if matches!(
            provider.id.as_str(),
            producer::assurance::STRUCTURE_PROVIDER_ID | producer::assurance::NGINX_PROVIDER_ID
        ) {
            return self.execute_fact_provider(
                provider,
                inventory,
                &denominator.entries,
                &denominator.digest,
            );
        }
        if provider.id == "compatibility.core" && !input_supplied {
            if let Some((observation, root)) =
                self.report_observation.as_ref().zip(self.root.as_ref())
            {
                let analysis = observation.analyze(root, provider, inventory);
                let paths = denominator
                    .entries
                    .iter()
                    .map(|entry| entry.path.clone())
                    .collect::<Vec<_>>();
                return common::provider_result(
                    &provider.id,
                    provider.required,
                    provider
                        .configuration
                        .get("denominatorDigest")
                        .and_then(Value::as_str)
                        .unwrap_or(&denominator.digest)
                        .to_owned(),
                    provider
                        .configuration
                        .get("denominatorCount")
                        .and_then(Value::as_u64)
                        .map_or(denominator.entries.len(), |v| v as usize),
                    &analysis,
                    serde_json::json!({}),
                    vec![],
                    &paths,
                )
                .map_err(AuditError::Provider);
            }
        }
        let mut facts = None;
        let mut unavailable = None;
        let input = if input_supplied {
            self.input_for(provider)
        } else if let Some(root) = &self.root {
            let scanned = self
                .producer
                .facts(root, &denominator.digest, &denominator.entries);
            // A framework with no detection and no inventory file that could
            // carry it is not applicable. An empty inventory was never scanned
            // and keeps its own accounting.
            if let Some(reason) = scanned
                .framework_absence(&provider.id)
                .filter(|_| !inventory.entries.is_empty())
            {
                let subject = provider.id.trim_start_matches("framework.");
                return crate::native_providers::code::applicability::not_applicable_result(
                    &provider.id,
                    provider.required,
                    subject,
                    reason,
                );
            }
            let produced = producer::produce(&scanned, &provider.id);
            facts = Some(scanned);
            match produced {
                producer::Production::Input(value) => value,
                producer::Production::Unavailable(reason) => {
                    unavailable = Some(reason);
                    serde_json::json!({})
                }
            }
        } else {
            unavailable = Some(format!("input-not-produced:{}", provider.id));
            serde_json::json!({})
        };
        // This typed capability exists only for self-sourced frontend/data.
        // A JSON input (including copied native diagnostics) cannot acquire it.
        let native_source = if matches!(
            provider.id.as_str(),
            "framework.frontend" | "framework.data"
        ) && !input_supplied
            && unavailable.is_none()
        {
            self.root
                .as_deref()
                .zip(facts.as_ref())
                .map(|(root, facts)| {
                    evidence::NativeSourceEvidence::new(
                        root,
                        inventory,
                        &denominator,
                        provider,
                        &facts.sources,
                    )
                })
        } else {
            None
        };
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
            "framework.data" => data::analyze_with_source(&input_object, native_source.as_ref()),
            "framework.frontend" => {
                framework::analyze_frontend_with_source(&input_object, native_source.as_ref())
            }
            "requirements.traceability" => requirements::analyze(&input_object),
            "test-quality.core" => test_quality::analyze(&input_object),
            other => {
                return Err(AuditError::Provider(format!(
                    "unsupported native provider: {other}"
                )));
            }
        }
        .map_err(AuditError::Provider)?;
        let mut analysis = analysis;
        if unavailable.is_none() {
            if let Some(facts) = &facts {
                producer::reconcile(facts, &provider.id, &mut analysis);
            }
        }
        // Runs even when the source-only input is unavailable: compatibility
        // runtime evidence never comes from source, only from a verified
        // observation, which then replaces the not-derivable refusal.
        producer::apply_observations(&provider.id, &mut analysis, &self.observation_verdicts);
        if provider.id == "compatibility.core"
            && self.observation_verdicts.iter().any(|verdict| {
                verdict.kind == crate::artifact_evidence::ObservationKind::CompatibilityRun
                    && verdict.satisfies_obligation()
            })
        {
            unavailable = None;
        }
        // PostgreSQL migration/config facts ride on the data provider: only a
        // self-sourced run reads them, and only a detected PostgreSQL project
        // contributes findings or gaps.
        if provider.id == "framework.data" && !input_supplied {
            let declared =
                producer::assurance::load_declared_context(self.root.as_deref(), inventory);
            if let Some(found) = producer::assurance::analyze_postgres_denominator_with(
                self.root.as_deref(),
                &denominator.entries,
                &declared,
            ) {
                producer::assurance::merge_postgres(&mut analysis, found);
            }
            producer::assurance::attach_runtime_obligations(
                &mut analysis,
                &declared,
                crate::runtime_obligations::Stack::Postgres,
            );
        }
        let paths = denominator
            .entries
            .iter()
            .map(|entry| entry.path.clone())
            .collect::<Vec<_>>();
        // Coverage is bound to the frozen plan: its recorded digest/count win
        // over the recomputed ones.
        let frozen_digest = provider
            .configuration
            .get("denominatorDigest")
            .and_then(Value::as_str)
            .map_or(denominator.digest.clone(), str::to_owned);
        let frozen_count = provider
            .configuration
            .get("denominatorCount")
            .and_then(Value::as_u64)
            .map_or(denominator.entries.len(), |count| count as usize);
        let mut result = common::provider_result(
            &provider.id,
            provider.required,
            frozen_digest,
            frozen_count,
            &analysis,
            original_input,
            Vec::new(),
            &paths,
        )
        .map_err(AuditError::Provider)?;
        if let Some(source) = native_source {
            result
                .details
                .insert("nativeSourceEvidence".into(), source.summary());
        }
        if let Some(reason) = unavailable {
            super::availability::mark_unavailable(&mut result, &reason);
        }
        Ok(result)
    }
}

impl ProviderExecutorAdapter {
    /// Self-sourced fact providers (`architecture.structure`,
    /// `framework.nginx`). Host-injected analyzer input is not an input to
    /// these: they read the frozen denominator, or report the gap. A
    /// denominator with no file is not-applicable, never a pass.
    fn execute_fact_provider(
        &self,
        provider: &AuditProvider,
        inventory: &InventoryEnvelope,
        entries: &[InventoryEntry],
        digest: &str,
    ) -> Result<ProviderResult, AuditError> {
        if entries.is_empty() {
            let (subject, reason) = if provider.id == producer::assurance::NGINX_PROVIDER_ID {
                ("nginx", "no-nginx-files-in-inventory")
            } else {
                ("structure", "no-structure-files-in-inventory")
            };
            return crate::native_providers::code::applicability::not_applicable_result(
                &provider.id,
                provider.required,
                subject,
                reason,
            );
        }
        let input = self.input_for(provider);
        let root = self.root.as_deref();
        let analysis = if provider.id == producer::assurance::NGINX_PROVIDER_ID {
            let declared = producer::assurance::load_declared_context(root, inventory);
            producer::assurance::produce_nginx_with(root, entries, &input, &declared)
        } else {
            producer::assurance::produce_structure_with(
                root,
                entries,
                producer::assurance::blueprint_from_configuration(&provider.configuration).as_ref(),
            )
        };
        let paths = entries
            .iter()
            .map(|entry| entry.path.clone())
            .collect::<Vec<_>>();
        let frozen_digest = provider
            .configuration
            .get("denominatorDigest")
            .and_then(Value::as_str)
            .map_or(digest.to_owned(), str::to_owned);
        let frozen_count = provider
            .configuration
            .get("denominatorCount")
            .and_then(Value::as_u64)
            .map_or(entries.len(), |count| count as usize);
        common::provider_result(
            &provider.id,
            provider.required,
            frozen_digest,
            frozen_count,
            &analysis,
            serde_json::json!({"producer": {"kind": "self-sourced", "mode": "frozen-denominator"}}),
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
