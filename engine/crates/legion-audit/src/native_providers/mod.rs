//! Unified dispatch for Rust-ported Audit providers.
pub mod architecture;
pub mod code;
pub mod legacy;
pub mod legacy_checks;
pub mod reasoning;
pub mod security;
pub mod p10_runtime;
pub mod p11_frameworks;
pub mod p11b_frameworks;
pub mod p11c_experience;
pub mod p11d_quality;

use crate::{AuditError, AuditProvider, InventoryEnvelope, ProviderExecutor};
use legion_contracts::ProviderResult;
use legion_provider_sdk::ExternalProjectTool;
use tokio_util::sync::CancellationToken;
use std::sync::Arc;

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
}

impl NativeProviderRegistry {
    pub fn new(root: impl Into<std::path::PathBuf>) -> Self {
        let root = root.into();
        Self {
            architecture: architecture::ProviderExecutorAdapter::new().with_root(root.clone()),
            code: Default::default(),
            security: Default::default(),
            legacy: legacy::ProviderExecutorAdapter::new(root.clone()),
            legacy_checks: legacy_checks::NativeLegacyCheckExecutor::new(root.clone()),
            reasoning: reasoning::ReasoningProviderExecutor::unavailable(root.clone()),
            external_project_tool: None,
            root,
        }
    }

    /// The application owner supplies an authenticated host; absence remains
    /// an explicit unavailable result rather than a locally manufactured pass.
    pub fn with_reasoning(mut self, executor: reasoning::ReasoningProviderExecutor) -> Self {
        self.reasoning = executor;
        self
    }

    pub fn with_external_project_tool(mut self, tool: Arc<dyn ExternalProjectTool>) -> Self {
        self.legacy_checks = self.legacy_checks.clone().with_external_project_tool(tool.clone());
        self.external_project_tool = Some(tool);
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
        if provider.id.starts_with("legacy.") || provider.id == "governance.policy" {
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
        self.execute(provider, inventory)
    }

    async fn execute_async(
        &self,
        plan: &crate::FrozenPlan,
        provider: &AuditProvider,
        inventory: &InventoryEnvelope,
        cancellation: CancellationToken,
    ) -> Result<ProviderResult, AuditError> {
        if legacy_checks::spec(&provider.id).is_some() {
            return self.legacy_checks.execute_async(plan, provider, inventory, cancellation).await;
        }
        self.execute_bound(plan, provider, inventory)
    }

}
