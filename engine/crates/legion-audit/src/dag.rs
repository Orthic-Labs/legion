use std::collections::{BTreeMap, BTreeSet};

use crate::{error::AuditError, plan::AuditProvider};

pub fn topological(providers: &[AuditProvider]) -> Result<Vec<String>, AuditError> {
    let by_id: BTreeMap<_, _> = providers
        .iter()
        .map(|provider| (provider.id.as_str(), provider))
        .collect();
    if by_id.len() != providers.len() {
        return Err(AuditError::Invalid("duplicate provider id".into()));
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
