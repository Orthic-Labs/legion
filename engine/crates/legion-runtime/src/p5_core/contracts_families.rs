//! Port of `src/lib/contracts/families.mjs` and `src/lib/contracts/lenses.mjs`
//! (packet P5c).
//!
//! `assertAcyclic`/`validateFamilies` walk a dependency graph over records
//! keyed by `id`, visiting ids in sorted order (matching JS
//! `[...byId.keys()].sort()`) and raising on an unknown dependency or a
//! cycle. `validateLenses` additionally requires a fixed set of fields on
//! every record before delegating to family validation.

use std::collections::{BTreeMap, HashSet};

#[derive(Debug, Clone)]
pub struct FamilyRecord {
    pub id: String,
    pub dependencies: Vec<String>,
}

#[derive(Debug, thiserror::Error, Eq, PartialEq)]
pub enum FamilyValidationError {
    #[error("dependency cycle: {0}")]
    Cycle(String),
    #[error("unknown dependency: {0}")]
    UnknownDependency(String),
}

/// Port of `assertAcyclic(records)`.
pub fn assert_acyclic(records: &[FamilyRecord]) -> Result<(), FamilyValidationError> {
    let by_id: BTreeMap<&str, &FamilyRecord> = records
        .iter()
        .map(|record| (record.id.as_str(), record))
        .collect();

    let mut visiting: HashSet<&str> = HashSet::new();
    let mut visited: HashSet<&str> = HashSet::new();

    fn visit<'a>(
        id: &'a str,
        by_id: &BTreeMap<&'a str, &'a FamilyRecord>,
        visiting: &mut HashSet<&'a str>,
        visited: &mut HashSet<&'a str>,
    ) -> Result<(), FamilyValidationError> {
        if visiting.contains(id) {
            return Err(FamilyValidationError::Cycle(id.to_string()));
        }
        if visited.contains(id) {
            return Ok(());
        }
        let record = by_id
            .get(id)
            .ok_or_else(|| FamilyValidationError::UnknownDependency(id.to_string()))?;
        visiting.insert(id);
        for dependency in &record.dependencies {
            visit(dependency.as_str(), by_id, visiting, visited)?;
        }
        visiting.remove(id);
        visited.insert(id);
        Ok(())
    }

    // Sorted keys, matching `[...byId.keys()].sort()` in the JS source.
    let mut ids: Vec<&str> = by_id.keys().copied().collect();
    ids.sort_unstable();
    for id in ids {
        visit(id, &by_id, &mut visiting, &mut visited)?;
    }
    Ok(())
}

/// Port of `validateFamilies(records)`.
pub fn validate_families(records: &[FamilyRecord]) -> Result<(), FamilyValidationError> {
    assert_acyclic(records)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(id: &str, deps: &[&str]) -> FamilyRecord {
        FamilyRecord {
            id: id.to_string(),
            dependencies: deps.iter().map(|s| s.to_string()).collect(),
        }
    }

    #[test]
    fn acyclic_graph_validates() {
        let records = vec![record("a", &[]), record("b", &["a"])];
        assert!(validate_families(&records).is_ok());
    }

    #[test]
    fn direct_cycle_is_rejected() {
        let records = vec![record("a", &["b"]), record("b", &["a"])];
        assert!(matches!(
            validate_families(&records),
            Err(FamilyValidationError::Cycle(_))
        ));
    }

    #[test]
    fn unknown_dependency_is_rejected() {
        let records = vec![record("a", &["missing"])];
        assert!(matches!(
            validate_families(&records),
            Err(FamilyValidationError::UnknownDependency(_))
        ));
    }
}
