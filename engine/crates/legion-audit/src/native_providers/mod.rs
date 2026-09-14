//! Unified dispatch for Rust-ported Audit providers.
pub mod architecture;
pub mod code;
pub mod legacy;
pub mod legacy_checks;
pub mod security;

use crate::{AuditError, AuditProvider, InventoryEnvelope, ProviderExecutor};
use legion_contracts::ProviderResult;

/// Dispatches every provider family whose implementation is native. Host
/// reasoning and typed external providers are deliberately rejected here so
/// callers cannot accidentally claim they ran without receipts.
#[derive(Clone, Debug)]
pub struct NativeProviderRegistry {
    pub root: std::path::PathBuf,
    pub architecture: architecture::ProviderExecutorAdapter,
    pub code: code::ProviderExecutorAdapter,
    pub security: security::SecurityProviderExecutor,
    pub legacy: legacy::ProviderExecutorAdapter,
}

impl NativeProviderRegistry {
    pub fn new(root: impl Into<std::path::PathBuf>) -> Self {
        let root = root.into();
        Self {
            architecture: architecture::ProviderExecutorAdapter::new().with_root(root.clone()),
            code: Default::default(),
            security: Default::default(),
            legacy: legacy::ProviderExecutorAdapter::new(root.clone()),
            root,
        }
    }
}

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
            || provider.id.starts_with("supply-chain.")
            || provider.id.starts_with("imported.")
        {
            return self.security.execute(provider, inventory);
        }
        if provider.id.starts_with("legacy.") || provider.id == "governance.policy" {
            return self.legacy.execute(provider, inventory);
        }
        Err(AuditError::Provider(format!(
            "provider {} requires typed host executor",
            provider.id
        )))
    }
}
