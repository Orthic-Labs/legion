//! Port of `src/lib/contracts/lenses.mjs` (packet P5c).
//!
//! `validateLenses` requires seven fields to be present (non-null) on every
//! lens record, then delegates cycle/unknown-dependency validation to
//! `validateFamilies`. Field values are treated as opaque JSON — this module
//! only checks presence, exactly like the JS `item[key] == null` check.
//!
//! Needs `serde_json` as a `legion-runtime` dependency (not currently
//! declared in `engine/crates/legion-runtime/Cargo.toml` — see the packet
//! report for the exact patch).

use serde_json::Value;

use super::contracts_families::{validate_families, FamilyRecord, FamilyValidationError};

const REQUIRED_FIELDS: [&str; 7] = [
    "family",
    "denominatorKind",
    "evidence",
    "cleanClaim",
    "decisionMode",
    "reasoning",
    "benchmark",
];

#[derive(Debug, Clone)]
pub struct LensRecord {
    pub id: String,
    pub dependencies: Vec<String>,
    /// Arbitrary lens fields, keyed by the JS property name (e.g.
    /// `denominatorKind`). Only presence/non-null-ness is checked here.
    pub fields: std::collections::BTreeMap<String, Value>,
}

#[derive(Debug, thiserror::Error)]
pub enum LensValidationError {
    #[error("lens {0} missing {1}")]
    MissingField(String, &'static str),
    #[error(transparent)]
    Family(#[from] FamilyValidationError),
}

/// Port of `validateLenses(records)`.
pub fn validate_lenses(records: &[LensRecord]) -> Result<(), LensValidationError> {
    for item in records {
        for key in REQUIRED_FIELDS {
            let present = item
                .fields
                .get(key)
                .map(|value| !value.is_null())
                .unwrap_or(false);
            if !present {
                return Err(LensValidationError::MissingField(item.id.clone(), key));
            }
        }
    }
    let family_records: Vec<FamilyRecord> = records
        .iter()
        .map(|item| FamilyRecord {
            id: item.id.clone(),
            dependencies: item.dependencies.clone(),
        })
        .collect();
    validate_families(&family_records)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn full_lens(id: &str, deps: &[&str]) -> LensRecord {
        let mut fields = std::collections::BTreeMap::new();
        for key in REQUIRED_FIELDS {
            fields.insert(key.to_string(), json!("x"));
        }
        LensRecord {
            id: id.to_string(),
            dependencies: deps.iter().map(|s| s.to_string()).collect(),
            fields,
        }
    }

    #[test]
    fn complete_lens_validates() {
        let records = vec![full_lens("l1", &[])];
        assert!(validate_lenses(&records).is_ok());
    }

    #[test]
    fn missing_field_is_rejected() {
        let mut lens = full_lens("l1", &[]);
        lens.fields.remove("benchmark");
        assert!(matches!(
            validate_lenses(&[lens]),
            Err(LensValidationError::MissingField(_, "benchmark"))
        ));
    }

    #[test]
    fn null_field_counts_as_missing() {
        let mut lens = full_lens("l1", &[]);
        lens.fields.insert("evidence".to_string(), Value::Null);
        assert!(matches!(
            validate_lenses(&[lens]),
            Err(LensValidationError::MissingField(_, "evidence"))
        ));
    }

    #[test]
    fn family_cycle_still_surfaces_through_lenses() {
        let a = full_lens("a", &["b"]);
        let b = full_lens("b", &["a"]);
        assert!(matches!(
            validate_lenses(&[a, b]),
            Err(LensValidationError::Family(FamilyValidationError::Cycle(_)))
        ));
    }
}
