//! Port of the four symbols `providers/sdk/index.mjs` re-exports from
//! `src/registry/provider-contracts.mjs`: `PROVIDER_PHASES`,
//! `PROVIDER_ROLES`, `PROVIDER_STATUS`, `assertEnum`.

/// Mirrors `PROVIDER_STATUS`. Closed set, order matches JS exactly.
pub const PROVIDER_STATUS: &[&str] = &[
    "pass",
    "fail",
    "partial",
    "unproven",
    "skipped",
    "error",
    "pending",
    "missing",
    "candidates",
    "blocked",
];

/// Mirrors `PROVIDER_ROLES`.
pub const PROVIDER_ROLES: &[&str] = &[
    "deterministic",
    "model-builder",
    "candidate-generator",
    "hypothesis-generator",
    "adjudicator",
    "variant-analyzer",
    "evidence-synthesizer",
];

/// Mirrors `PROVIDER_PHASES`.
pub const PROVIDER_PHASES: &[&str] = &[
    "facts",
    "model",
    "runtime",
    "hypothesis",
    "reasoning",
    "variants",
    "synthesis",
];

/// Port of `assertEnum(name, value, allowed)`: `Err` carries the same
/// message shape as the thrown JS `Error`.
pub fn assert_enum<'a>(name: &str, value: &'a str, allowed: &[&str]) -> Result<&'a str, String> {
    if !allowed.contains(&value) {
        return Err(format!(
            "{name} must be one of {}; got {:?}",
            allowed.join(", "),
            value
        ));
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn assert_enum_accepts_member() {
        assert_eq!(assert_enum("status", "pass", PROVIDER_STATUS).unwrap(), "pass");
    }

    #[test]
    fn assert_enum_rejects_non_member_with_js_shaped_message() {
        let err = assert_enum("status", "bogus", PROVIDER_STATUS).unwrap_err();
        assert!(err.starts_with("status must be one of "));
        assert!(err.ends_with("got \"bogus\""));
    }

    #[test]
    fn enum_tables_match_js_length_and_order() {
        assert_eq!(PROVIDER_STATUS.len(), 10);
        assert_eq!(PROVIDER_ROLES.len(), 7);
        assert_eq!(PROVIDER_PHASES.len(), 7);
        assert_eq!(PROVIDER_ROLES[0], "deterministic");
        assert_eq!(PROVIDER_PHASES[0], "facts");
    }
}
