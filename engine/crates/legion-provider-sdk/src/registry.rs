use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use legion_contracts::ProviderId;
use serde::{Deserialize, Serialize};

use crate::{
    error::{ProviderError, ProviderErrorKind},
    provider::{FunctionProviderFactory, Provider, ProviderDefinition, ProviderFactory},
};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProviderRegistryDocument {
    pub schema_version: u32,
    pub providers: Vec<ProviderDefinition>,
}

impl ProviderRegistryDocument {
    pub fn from_json(input: &str) -> Result<Self, ProviderError> {
        serde_json::from_str(input).map_err(|error| {
            ProviderError::new(ProviderErrorKind::InvalidRegistry, error.to_string())
        })
    }

    pub fn validate(&self) -> Result<(), ProviderError> {
        if self.schema_version != 1 {
            return Err(ProviderError::new(
                ProviderErrorKind::IncompatibleVersion,
                "provider registry schema version is unsupported",
            ));
        }
        let mut ids = BTreeSet::new();
        for definition in &self.providers {
            definition.validate()?;
            if !ids.insert(definition.id.clone()) {
                return Err(ProviderError::new(
                    ProviderErrorKind::DuplicateProvider,
                    format!("duplicate provider id: {}", definition.id),
                ));
            }
            let mut dependencies = BTreeSet::new();
            for dependency in &definition.depends_on {
                if !dependencies.insert(dependency) {
                    return Err(ProviderError::new(
                        ProviderErrorKind::InvalidRegistry,
                        format!("duplicate dependency for provider {}", definition.id),
                    ));
                }
            }
        }
        Ok(())
    }
}

pub struct ImplementationRegistry {
    factories: BTreeMap<String, Arc<dyn ProviderFactory>>,
}

impl Default for ImplementationRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl ImplementationRegistry {
    pub fn new() -> Self {
        Self {
            factories: BTreeMap::new(),
        }
    }

    pub fn register_factory(
        &mut self,
        factory: Arc<dyn ProviderFactory>,
    ) -> Result<(), ProviderError> {
        let key = factory.implementation_key().to_owned();
        if self.factories.contains_key(&key) {
            return Err(ProviderError::new(
                ProviderErrorKind::DuplicateProvider,
                format!("duplicate implementation key: {key}"),
            ));
        }
        self.factories.insert(key, factory);
        Ok(())
    }

    pub fn register<F>(
        &mut self,
        key: impl Into<String>,
        version: impl Into<String>,
        create: F,
    ) -> Result<(), ProviderError>
    where
        F: Fn(&ProviderDefinition) -> Result<Arc<dyn Provider>, ProviderError>
            + Send
            + Sync
            + 'static,
    {
        self.register_factory(Arc::new(FunctionProviderFactory::new(key, version, create)))
    }

    pub fn get(&self, key: &str) -> Option<&Arc<dyn ProviderFactory>> {
        self.factories.get(key)
    }
    pub fn is_empty(&self) -> bool {
        self.factories.is_empty()
    }
}

pub struct ProviderRegistry {
    definitions: BTreeMap<ProviderId, ProviderDefinition>,
    providers: BTreeMap<ProviderId, Arc<dyn Provider>>,
    order: Vec<ProviderId>,
}

impl ProviderRegistry {
    pub fn load(
        document: ProviderRegistryDocument,
        implementations: &ImplementationRegistry,
    ) -> Result<Self, ProviderError> {
        document.validate()?;
        let by_id: BTreeMap<_, _> = document
            .providers
            .into_iter()
            .map(|definition| (definition.id.clone(), definition))
            .collect();
        for definition in by_id.values() {
            let factory = implementations
                .get(&definition.implementation_key)
                .ok_or_else(|| {
                    ProviderError::new(
                        ProviderErrorKind::UnknownImplementation,
                        format!(
                            "unknown implementation key: {}",
                            definition.implementation_key
                        ),
                    )
                })?;
            if !factory.supports_version(&definition.provider_version) {
                return Err(ProviderError::new(
                    ProviderErrorKind::IncompatibleVersion,
                    format!(
                        "implementation {} does not support provider version {}",
                        definition.implementation_key, definition.provider_version
                    ),
                ));
            }
            for dependency in &definition.depends_on {
                if !by_id.contains_key(dependency) {
                    return Err(ProviderError::new(
                        ProviderErrorKind::MissingDependency,
                        format!(
                            "provider {} depends on missing {}",
                            definition.id, dependency
                        ),
                    ));
                }
            }
        }
        let order = topological_order(&by_id)?;
        let mut providers = BTreeMap::new();
        for id in &order {
            let definition = &by_id[id];
            let factory = implementations
                .get(&definition.implementation_key)
                .expect("validated implementation key");
            let provider = factory.create(definition)?;
            if provider.definition().id != definition.id
                || provider.definition().implementation_key != definition.implementation_key
            {
                return Err(ProviderError::new(
                    ProviderErrorKind::InvalidRegistry,
                    format!(
                        "implementation returned mismatched metadata for {}",
                        definition.id
                    ),
                ));
            }
            providers.insert(id.clone(), provider);
        }
        Ok(Self {
            definitions: by_id,
            providers,
            order,
        })
    }

    pub fn load_json(
        input: &str,
        implementations: &ImplementationRegistry,
    ) -> Result<Self, ProviderError> {
        Self::load(ProviderRegistryDocument::from_json(input)?, implementations)
    }

    pub fn order(&self) -> &[ProviderId] {
        &self.order
    }
    pub fn get(&self, id: &ProviderId) -> Option<&Arc<dyn Provider>> {
        self.providers.get(id)
    }
    pub fn definition(&self, id: &ProviderId) -> Option<&ProviderDefinition> {
        self.definitions.get(id)
    }
    pub fn providers(&self) -> impl Iterator<Item = (&ProviderId, &Arc<dyn Provider>)> {
        self.providers.iter()
    }
}

fn topological_order(
    definitions: &BTreeMap<ProviderId, ProviderDefinition>,
) -> Result<Vec<ProviderId>, ProviderError> {
    let mut remaining: BTreeSet<_> = definitions.keys().cloned().collect();
    let mut done = BTreeSet::new();
    let mut order = Vec::with_capacity(remaining.len());
    while !remaining.is_empty() {
        let next = remaining
            .iter()
            .find(|id| {
                definitions[*id]
                    .depends_on
                    .iter()
                    .all(|dependency| done.contains(dependency))
            })
            .cloned();
        let Some(next) = next else {
            return Err(ProviderError::new(
                ProviderErrorKind::DependencyCycle,
                "provider dependency graph contains a cycle",
            ));
        };
        remaining.remove(&next);
        done.insert(next.clone());
        order.push(next);
    }
    Ok(order)
}

pub fn topological_provider_ids(
    document: &ProviderRegistryDocument,
) -> Result<Vec<ProviderId>, ProviderError> {
    document.validate()?;
    let definitions = document
        .providers
        .iter()
        .cloned()
        .map(|definition| (definition.id.clone(), definition))
        .collect();
    topological_order(&definitions)
}
