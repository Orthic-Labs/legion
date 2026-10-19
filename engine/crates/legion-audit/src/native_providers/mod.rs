//! Unified dispatch for Rust-ported Audit providers.
pub mod architecture;
pub mod availability;
pub mod code;
pub mod legacy;
pub mod legacy_checks;
pub mod p11d_quality;
pub mod reasoning;
pub mod security;

use crate::{
    execution::ExecutionContext, AuditError, AuditProvider, InventoryEnvelope, ProviderExecutor,
};
use legion_contracts::ProviderResult;
use legion_provider_sdk::ExternalProjectTool;
use std::sync::Arc;
use tokio_util::sync::CancellationToken;

/// Dispatches every provider family whose implementation is native. Host
/// reasoning remains receipt-gated; the legacy-check adapter owns its
/// argv-only process receipts so callers cannot claim an unexecuted check.
#[derive(Clone)]
pub struct NativeProviderRegistry {
    pub root: std::path::PathBuf,
    pub architecture: architecture::ProviderExecutorAdapter,
    pub code: code::ProviderExecutorAdapter,
    pub security: security::SecurityProviderExecutor,
    pub legacy: legacy::ProviderExecutorAdapter,
    pub legacy_checks: legacy_checks::NativeLegacyCheckExecutor,
    pub reasoning: reasoning::ReasoningProviderExecutor,
    pub external_project_tool: Option<Arc<dyn ExternalProjectTool>>,
    ownership_owner: Option<legacy::ownership_sdk::NativeOwner>,
}

impl NativeProviderRegistry {
    fn runtime_visual_capture<'a>(
        &'a self,
        plan: &crate::FrozenPlan,
        provider: &AuditProvider,
        context: &'a ExecutionContext<'_>,
    ) -> Option<legacy::visual::RuntimeVisualCapture> {
        let source = provider
            .configuration
            .get("runner")?
            .get("visual")?
            .get("captureSource")?;
        if source.get("kind")?.as_str()? != "runtime-provider"
            || source.get("providerId")?.as_str()? != "legacy.runtime.app"
        {
            return None;
        }
        let source_provider_id = source.get("providerId")?.as_str()?.to_owned();
        let runtime = plan
            .providers()
            .iter()
            .find(|candidate| candidate.id == source_provider_id)?;
        let runtime_inputs = runtime.configuration.get("runner")?.get("runtime")?.clone();
        let artifact_dir = runtime_inputs
            .get("artifactDir")
            .and_then(serde_json::Value::as_str)
            .map(std::path::PathBuf::from);
        let prior_execution = context
            .prior_results
            .iter()
            .find(|execution| execution.provider == source_provider_id)
            .cloned();
        Some(legacy::visual::RuntimeVisualCapture {
            plan_digest: context.plan_digest.to_owned(),
            inventory_digest: plan.plan().inventory_digest.clone(),
            source_provider_id,
            runtime_inputs,
            prior_execution,
            artifact_dir,
            scratch_tmp_dir: self
                .legacy_checks
                .scratch()
                .ok()
                .map(|scratch| scratch.tmp_dir()),
        })
    }

    pub fn new(root: impl Into<std::path::PathBuf>) -> Self {
        let root = root.into();
        Self {
            architecture: architecture::ProviderExecutorAdapter::new().with_root(root.clone()),
            code: code::ProviderExecutorAdapter::new().with_root(root.clone()),
            security: security::SecurityProviderExecutor::default().with_root(root.clone()),
            legacy: legacy::ProviderExecutorAdapter::new(root.clone()),
            legacy_checks: legacy_checks::NativeLegacyCheckExecutor::new(root.clone()),
            reasoning: reasoning::ReasoningProviderExecutor::unavailable(root.clone()),
            external_project_tool: None,
            ownership_owner: None,
            root,
        }
    }

    /// The application owner supplies an authenticated host; absence remains
    /// an explicit unavailable result rather than a locally manufactured pass.
    pub fn with_reasoning(mut self, executor: reasoning::ReasoningProviderExecutor) -> Self {
        self.reasoning = executor;
        self
    }

    /// Route legacy-check scratch (sandbox profiles, artifacts, reports, temp
    /// and cache files) into a directory outside the audited root. The
    /// external tool's artifact sink must be rooted at the same
    /// `scratch.artifacts_dir()`.
    pub fn with_scratch(mut self, scratch: Arc<legacy_checks::AuditScratch>) -> Self {
        self.legacy_checks = self.legacy_checks.clone().with_scratch(scratch);
        self
    }

    /// Replace the `code.*` adapter (search path, sandbox policy and tool
    /// bounds for its tool runs). The root is re-applied.
    pub fn with_code(mut self, code: code::ProviderExecutorAdapter) -> Self {
        self.code = code.with_root(self.root.clone());
        self
    }

    /// Enroll a pinned native owner transport. The frozen plan must independently
    /// bind its identity; the injected SDK authorizer still decides every effect.
    pub fn with_ownership_owner(mut self, owner: legacy::ownership_sdk::NativeOwner) -> Self {
        self.ownership_owner = Some(owner);
        self
    }

    pub fn with_external_project_tool(mut self, tool: Arc<dyn ExternalProjectTool>) -> Self {
        self.legacy_checks = self
            .legacy_checks
            .clone()
            .with_external_project_tool(tool.clone());
        self.external_project_tool = Some(tool);
        self
    }

    /// Pin the installed RustRight host runtime used for managed test runs.
    pub fn with_attested_runs(mut self, enrollment: legacy_checks::AttestedRunsEnrollment) -> Self {
        self.legacy_checks = self.legacy_checks.clone().with_attested_runs(enrollment);
        self
    }
}

#[async_trait::async_trait]
impl ProviderExecutor for NativeProviderRegistry {
    fn execute(
        &self,
        provider: &AuditProvider,
        inventory: &InventoryEnvelope,
    ) -> Result<ProviderResult, AuditError> {
        if provider.id.starts_with("architecture.")
            || provider.id.starts_with("compatibility.")
            || provider.id.starts_with("docs.")
            || provider.id.starts_with("framework.")
            || provider.id.starts_with("requirements.")
            || provider.id.starts_with("test-quality.")
        {
            return self.architecture.execute(provider, inventory);
        }
        if provider.id.starts_with("code.") {
            return self.code.execute(provider, inventory);
        }
        if provider.id.starts_with("security.")
            || provider.id.starts_with("structural.")
            || provider.id.starts_with("container.")
            || provider.id.starts_with("dependency.")
            || provider.id.starts_with("secrets.")
            || provider.id.starts_with("supply-chain.")
            || provider.id.starts_with("imported.")
        {
            return self.security.execute(provider, inventory);
        }
        // The frozen legacy-check IDs are exact dispatch entries.  They must
        // not fall through to the older four-provider compatibility adapter.
        if legacy_checks::spec(&provider.id).is_some() {
            return self.legacy_checks.execute(provider, inventory);
        }
        if provider.id.starts_with("legacy.")
            || provider.id == "governance.policy"
            || provider.id == "governance.capability-ownership"
        {
            return self.legacy.execute(provider, inventory);
        }
        Err(AuditError::Provider(format!(
            "provider {} requires typed host executor",
            provider.id
        )))
    }
    fn execute_bound(
        &self,
        plan: &crate::FrozenPlan,
        provider: &AuditProvider,
        inventory: &InventoryEnvelope,
    ) -> Result<ProviderResult, AuditError> {
        if reasoning::REASONING_PROVIDER_IDS.contains(&provider.id.as_str()) {
            return self.reasoning.execute_bound(plan, provider, inventory);
        }
        if provider.id == "governance.capability-ownership" {
            return self
                .legacy
                .execute_ownership_bound(plan, provider, inventory);
        }
        self.execute(provider, inventory)
    }

    fn execute_with_context(
        &self,
        plan: &crate::FrozenPlan,
        provider: &AuditProvider,
        inventory: &InventoryEnvelope,
        context: &ExecutionContext<'_>,
    ) -> Result<ProviderResult, AuditError> {
        if provider.id == legacy::visual::VISUAL_PROVIDER_ID {
            let capture = self.runtime_visual_capture(plan, provider, context);
            return self.legacy.execute_with_runtime_visual_capture(
                provider,
                inventory,
                capture.as_ref(),
            );
        }
        self.execute_bound(plan, provider, inventory)
    }

    async fn execute_async(
        &self,
        plan: &crate::FrozenPlan,
        provider: &AuditProvider,
        inventory: &InventoryEnvelope,
        cancellation: CancellationToken,
    ) -> Result<ProviderResult, AuditError> {
        if provider.id == "governance.capability-ownership" {
            if let (Some(owner), Some(tool)) = (&self.ownership_owner, &self.external_project_tool)
            {
                let scratch = self.legacy_checks.scratch()?;
                return self
                    .legacy
                    .execute_ownership_async(
                        plan,
                        provider,
                        inventory,
                        owner,
                        tool.as_ref(),
                        &scratch.artifacts_dir(),
                        cancellation,
                    )
                    .await;
            }
        }
        if legacy_checks::spec(&provider.id).is_some() {
            return self
                .legacy_checks
                .execute_async(plan, provider, inventory, cancellation)
                .await;
        }
        // With an authorized external-tool route the `code.*` providers run
        // their read-only verification tools through it; scratch is the run's
        // `AuditScratch`, shared with the legacy checks. Without the route
        // they keep the discovery-only synchronous accounting.
        if provider.id.starts_with("code.") {
            if let Some(tool) = &self.external_project_tool {
                let scratch = self.legacy_checks.scratch()?;
                return self
                    .code
                    .execute_async(
                        plan,
                        provider,
                        inventory,
                        tool.clone(),
                        scratch,
                        cancellation,
                    )
                    .await;
            }
        }
        self.execute_bound(plan, provider, inventory)
    }

    async fn execute_async_with_context(
        &self,
        plan: &crate::FrozenPlan,
        provider: &AuditProvider,
        inventory: &InventoryEnvelope,
        cancellation: CancellationToken,
        context: &ExecutionContext<'_>,
    ) -> Result<ProviderResult, AuditError> {
        if provider.id == legacy::visual::VISUAL_PROVIDER_ID {
            let capture = self.runtime_visual_capture(plan, provider, context);
            return self.legacy.execute_with_runtime_visual_capture(
                provider,
                inventory,
                capture.as_ref(),
            );
        }
        self.execute_async(plan, provider, inventory, cancellation)
            .await
    }
}
