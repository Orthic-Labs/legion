use std::collections::{BTreeMap, BTreeSet};

use crate::{error::AuditError, plan::AuditProvider};

/// Optional ordering-only prerequisite declared by the frozen visual runner.
/// It deliberately does not enter `dependencies`, whose execution semantics
/// require successful completion.
pub(crate) fn capture_source_provider(
    provider: &AuditProvider,
) -> Result<Option<&str>, AuditError> {
    let visual = provider
        .configuration
        .get("runner")
        .and_then(|runner| runner.get("visual"));
    let Some(source) = visual.and_then(|visual| visual.get("captureSource")) else {
        return Ok(None);
    };
    if provider.id != "legacy.visual.core"
        || source.get("kind").and_then(serde_json::Value::as_str) != Some("runtime-provider")
    {
        return Err(AuditError::Invalid(format!(
            "provider {} has an invalid visual capture source",
            provider.id
        )));
    }
    let provider_id = source
        .get("providerId")
        .and_then(serde_json::Value::as_str)
        .filter(|id| *id == "legacy.runtime.app")
        .ok_or_else(|| {
            AuditError::Invalid("visual capture source must name legacy.runtime.app".into())
        })?;
    Ok(Some(provider_id))
}

pub fn topological(providers: &[AuditProvider]) -> Result<Vec<String>, AuditError> {
    let by_id: BTreeMap<_, _> = providers
        .iter()
        .map(|provider| (provider.id.as_str(), provider))
        .collect();
    if by_id.len() != providers.len() {
        return Err(AuditError::Invalid("duplicate provider id".into()));
    }
    let capture_sources = providers
        .iter()
        .map(|provider| {
            Ok::<_, AuditError>((provider.id.as_str(), capture_source_provider(provider)?))
        })
        .collect::<Result<BTreeMap<_, _>, _>>()?;
    for source in capture_sources.values().flatten() {
        if !by_id.contains_key(source) {
            return Err(AuditError::Invalid(format!(
                "visual capture source provider {source} is missing"
            )));
        }
    }
    let mut remaining: BTreeSet<&str> = by_id.keys().copied().collect();
    let mut done = BTreeSet::new();
    let mut order = Vec::with_capacity(providers.len());
    while !remaining.is_empty() {
        let next = remaining
            .iter()
            .find(|id| {
                by_id[*id]
                    .dependencies
                    .iter()
                    .all(|dep| by_id.contains_key(dep.as_str()) && done.contains(dep.as_str()))
                    && capture_sources[*id].map_or(true, |source| done.contains(source))
            })
            .copied();
        let Some(id) = next else {
            return Err(AuditError::Invalid(
                "provider dependency cycle or missing dependency".into(),
            ));
        };
        remaining.remove(id);
        done.insert(id);
        order.push(id.to_owned());
    }
    Ok(order)
}
