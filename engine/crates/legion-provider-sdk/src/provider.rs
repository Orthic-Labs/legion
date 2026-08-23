use std::sync::Arc;

use async_trait::async_trait;
use legion_contracts::ProviderId;
use serde::{Deserialize, Serialize};

use crate::{context::ProviderContext, error::ProviderError, result::ProviderResult};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProviderDefinition {
    pub schema_version: u32,
    pub id: ProviderId,
    pub provider_version: String,
    pub implementation_key: String,
    pub capabilities: Vec<String>,
    pub depends_on: Vec<ProviderId>,
    pub required: bool,
    pub permissions: Vec<String>,
    pub source_provenance: std::collections::BTreeMap<String, String>,
}

pub type ProviderMetadata = ProviderDefinition;

impl ProviderDefinition {
    pub fn validate(&self) -> Result<(), ProviderError> {
        if self.schema_version != 1 {
            return Err(ProviderError::new(
                crate::error::ProviderErrorKind::IncompatibleVersion,
                "provider definition schema version is unsupported",
            ));
        }
        for (field, value) in [
            ("providerVersion", self.provider_version.as_str()),
            ("implementationKey", self.implementation_key.as_str()),
        ] {
            if value.trim().is_empty() {
                return Err(ProviderError::new(
                    crate::error::ProviderErrorKind::InvalidRegistry,
                    format!("{field} must be non-empty"),
                ));
            }
        }
        if self
            .capabilities
            .iter()
            .any(|value| value.trim().is_empty())
            || self.permissions.iter().any(|value| value.trim().is_empty())
        {
            return Err(ProviderError::new(
                crate::error::ProviderErrorKind::InvalidRegistry,
                "capabilities and permissions must be non-empty strings",
            ));
        }
        Ok(())
    }
}

#[async_trait]
pub trait Provider: Send + Sync {
    fn definition(&self) -> &ProviderDefinition;

    async fn execute(&self, context: &ProviderContext) -> Result<ProviderResult, ProviderError>;
}

pub trait ProviderFactory: Send + Sync {
    fn implementation_key(&self) -> &str;
    fn supports_version(&self, provider_version: &str) -> bool;
    fn create(&self, definition: &ProviderDefinition) -> Result<Arc<dyn Provider>, ProviderError>;
}

pub struct FunctionProviderFactory<F> {
    key: String,
    version: String,
    create_fn: F,
}

impl<F> FunctionProviderFactory<F> {
    pub fn new(key: impl Into<String>, version: impl Into<String>, create_fn: F) -> Self {
        Self {
            key: key.into(),
            version: version.into(),
            create_fn,
        }
    }
}

impl<F> ProviderFactory for FunctionProviderFactory<F>
where
    F: Fn(&ProviderDefinition) -> Result<Arc<dyn Provider>, ProviderError> + Send + Sync,
{
    fn implementation_key(&self) -> &str {
        &self.key
    }

    fn supports_version(&self, provider_version: &str) -> bool {
        self.version == "*" || self.version == provider_version
    }

    fn create(&self, definition: &ProviderDefinition) -> Result<Arc<dyn Provider>, ProviderError> {
        (self.create_fn)(definition)
    }
}
