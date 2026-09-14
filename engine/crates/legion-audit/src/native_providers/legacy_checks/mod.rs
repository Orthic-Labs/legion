//! Dispatcher for all registry `legacy-check` providers.
//!
//! The dispatcher is deliberately independent from the shared native-provider
//! module.  Integrators can expose it from their chosen registry composition
//! without changing this contract surface.

mod contracts;
mod registry;

pub use contracts::{
    CommandShape, LegacyCheckError, LegacyCheckExecution, LegacyCheckInput, LegacyCheckOutput,
    LegacyCheckProcessRequest, LegacyCheckProcessState, LegacyCheckSpec, CONTRACT_SCHEMA_VERSION,
    REQUEST_KIND,
};
pub use registry::{spec, specs, LEGACY_CHECK_SPECS};

use serde_json::Value;
use std::path::{Path, PathBuf};

use legion_contracts::{Coverage, ProviderId, ProviderResult, ProviderStatus};

use crate::{inventory::InventoryEnvelope, plan::AuditProvider};

/// Stateless registry dispatcher.  A host owns execution; this type only
/// builds an immutable typed request from frozen audit inputs.
#[derive(Clone, Copy, Debug, Default)]
pub struct LegacyCheckDispatcher;

impl LegacyCheckDispatcher {
    pub const fn new() -> Self {
        Self
    }

    pub fn contains(&self, provider_id: &str) -> bool {
        spec(provider_id).is_some()
    }

    pub fn contract(&self, provider_id: &str) -> Option<&'static LegacyCheckSpec> {
        spec(provider_id)
    }

    pub fn request(
        &self,
        provider: &AuditProvider,
        inventory: &InventoryEnvelope,
        root: impl Into<PathBuf>,
        binding: Option<&Value>,
        projection: Option<&Value>,
        artifacts: &Value,
    ) -> Result<LegacyCheckProcessRequest, LegacyCheckError> {
        let contract = spec(&provider.id).ok_or_else(|| LegacyCheckError {
            provider_id: provider.id.clone(),
            check: provider.id.clone(),
            state: LegacyCheckProcessState::Failed,
            message: "provider is not one of the frozen legacy-check contracts".into(),
        })?;
        contracts::validate_provider(provider, contract)?;
        let root = root.into();
        if !root.is_absolute() {
            return Err(LegacyCheckError {
                provider_id: provider.id.clone(),
                check: contract.check.into(),
                state: LegacyCheckProcessState::Failed,
                message: "legacy-check cwd must be absolute".into(),
            });
        }
        let selector = provider
            .configuration
            .get("selector")
            .ok_or_else(|| LegacyCheckError {
                provider_id: provider.id.clone(),
                check: contract.check.into(),
                state: LegacyCheckProcessState::Failed,
                message: "provider selector is missing".into(),
            })?;
        let denominator =
            inventory
                .denominator_entries(selector)
                .map_err(|error| LegacyCheckError {
                    provider_id: provider.id.clone(),
                    check: contract.check.into(),
                    state: LegacyCheckProcessState::Failed,
                    message: error.to_string(),
                })?;
        Ok(LegacyCheckProcessRequest {
            schema_version: CONTRACT_SCHEMA_VERSION,
            kind: REQUEST_KIND,
            provider_id: provider.id.clone(),
            check: contract.check.into(),
            cwd: root,
            binding: binding.cloned(),
            denominator,
            projection: projection.cloned(),
            artifacts: artifacts.clone(),
            command: contract.command,
        })
    }

    pub fn input(
        &self,
        provider: &AuditProvider,
        inventory: &InventoryEnvelope,
        root: impl Into<PathBuf>,
        binding: Option<&Value>,
        projection: Option<&Value>,
        artifacts: &Value,
    ) -> Result<LegacyCheckInput, LegacyCheckError> {
        let request = self.request(provider, inventory, root, binding, projection, artifacts)?;
        Ok(LegacyCheckInput {
            provider_id: request.provider_id,
            check: request.check,
            root: request.cwd,
            inventory_generation: inventory.generation.clone(),
            inventory_digest: inventory.digest.clone(),
            denominator: request.denominator,
            binding: request.binding,
            projection: request.projection,
            artifacts: request.artifacts,
        })
    }

    pub fn request_for_path(
        &self,
        provider: &AuditProvider,
        inventory: &InventoryEnvelope,
        root: &Path,
    ) -> Result<LegacyCheckProcessRequest, LegacyCheckError> {
        self.request(provider, inventory, root, None, None, &Value::Null)
    }

    /// Project host execution into the common provider-result contract.  A
    /// process or parser failure remains a typed incomplete result, retaining
    /// error metadata and captured output instead of becoming an empty pass.
    pub fn project_result(
        &self,
        provider: &AuditProvider,
        input: &LegacyCheckInput,
        execution: LegacyCheckExecution,
    ) -> Result<ProviderResult, LegacyCheckError> {
        let contract = spec(&provider.id).ok_or_else(|| LegacyCheckError {
            provider_id: provider.id.clone(),
            check: provider.id.clone(),
            state: LegacyCheckProcessState::Failed,
            message: "provider is not one of the frozen legacy-check contracts".into(),
        })?;
        contracts::validate_provider(provider, contract)?;
        let provider_id = ProviderId::new(&provider.id).map_err(|error| LegacyCheckError {
            provider_id: provider.id.clone(),
            check: contract.check.into(),
            state: LegacyCheckProcessState::Failed,
            message: error.to_string(),
        })?;
        let mut output = execution.output.unwrap_or_default();
        let process_ok = execution.state == LegacyCheckProcessState::Completed;
        let mut gaps = output.coverage_gaps.clone();
        let mut degradation = output.degradation.clone();
        if !process_ok {
            gaps.push(format!("external-process:{}", execution.state.as_str()));
            degradation.push(format!("external-process:{}", execution.state.as_str()));
        }
        if let Some(error) = &execution.error {
            gaps.push(format!("external-error:{}", error.message));
            degradation.push(format!("external-error:{}", error.message));
        }
        let coverage = output.coverage.take().unwrap_or_else(|| Coverage {
            denominator_digest: input.denominator.digest.clone(),
            expected: input.denominator.entries.len() as u64,
            examined: 0,
            gaps: gaps.clone(),
        });
        if coverage.denominator_digest != input.denominator.digest {
            gaps.push("denominator-digest-mismatch".into());
        }
        gaps.extend(coverage.gaps.iter().cloned());
        gaps.sort();
        gaps.dedup();
        degradation.sort();
        degradation.dedup();
        let complete = process_ok && output.complete && gaps.is_empty() && coverage.complete();
        output
            .details
            .insert("check".into(), Value::String(contract.check.into()));
        output
            .details
            .insert("tool".into(), Value::String(contract.tool.into()));
        output.details.insert(
            "processState".into(),
            Value::String(execution.state.as_str().into()),
        );
        output.details.insert(
            "exitCode".into(),
            execution.exit_code.map(Value::from).unwrap_or(Value::Null),
        );
        output.details.insert(
            "stdoutBytes".into(),
            Value::from(execution.stdout.len() as u64),
        );
        output.details.insert(
            "stderrBytes".into(),
            Value::from(execution.stderr.len() as u64),
        );
        let candidates = std::mem::take(&mut output.candidates);
        output
            .details
            .insert("candidates".into(), Value::Array(candidates));
        output.details.insert(
            "commandShape".into(),
            Value::String(command_name(contract.command).into()),
        );
        if let Some(receipt_id) = execution.receipt_id {
            output
                .details
                .insert("receiptId".into(), Value::String(receipt_id));
        }
        if let Some(error) = execution.error {
            output.details.insert(
                "executionError".into(),
                serde_json::json!({"state": error.state.as_str(), "message": error.message}),
            );
        }
        let status = if complete {
            if matches!(output.status, ProviderStatus::Ok) {
                ProviderStatus::Ok
            } else {
                ProviderStatus::Complete
            }
        } else if process_ok {
            output.status
        } else {
            ProviderStatus::Failed
        };
        let result = ProviderResult {
            schema_version: 1,
            provider: provider_id,
            applicable: true,
            required: provider.required,
            status,
            complete,
            coverage: Some(Coverage {
                denominator_digest: coverage.denominator_digest,
                expected: coverage.expected,
                examined: coverage.examined,
                gaps: gaps.clone(),
            }),
            findings: output.findings,
            coverage_gaps: gaps,
            degradation,
            details: output.details,
        };
        result.validate().map_err(|error| LegacyCheckError {
            provider_id: provider.id.clone(),
            check: contract.check.into(),
            state: LegacyCheckProcessState::Failed,
            message: error.to_string(),
        })?;
        Ok(result)
    }
}

fn command_name(command: CommandShape) -> &'static str {
    match command {
        CommandShape::Native { .. } => "native",
        CommandShape::Fixed { .. } => "fixed",
        CommandShape::Named { .. } => "named",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_has_exactly_32_unique_provider_and_check_ids() {
        let ids = specs()
            .iter()
            .map(|item| item.provider_id)
            .collect::<std::collections::BTreeSet<_>>();
        let checks = specs()
            .iter()
            .map(|item| item.check)
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(specs().len(), 32);
        assert_eq!(ids.len(), 32);
        assert_eq!(checks.len(), 32);
    }

    #[test]
    fn every_contract_is_argv_or_native_and_contains_no_shell_shape() {
        for item in specs() {
            match item.command {
                CommandShape::Native { .. } => {}
                CommandShape::Fixed { executable, args }
                | CommandShape::Named {
                    tool: executable,
                    args,
                } => {
                    assert!(!executable.is_empty());
                    assert!(args.iter().all(|arg| !arg.contains('\0')));
                }
            }
        }
    }
}
