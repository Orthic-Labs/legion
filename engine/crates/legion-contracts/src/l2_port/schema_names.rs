//! Rust port of the `SCHEMA_NAMES` half of `src/packages/contracts/index.mjs`.
//!
//! `index.mjs` also exports `SCHEMA_PATHS`, a logical-name -> absolute
//! filesystem path map resolved via `import.meta.url` relative to the JS
//! package's own `schemas/` directory. That resolution is inherently tied to
//! the JS module's location on disk; hardcoding an equivalent path here
//! would silently drift from the JS package's actual layout (or point at
//! the wrong checkout in a workspace-relative Rust build). See the L2 port
//! report's "remaining" section — `SCHEMA_PATHS` is intentionally left to a
//! caller that knows its own schema-directory root, e.g. via
//! `schema_names::SCHEMA_NAMES.iter().map(|name| root.join(format!("{name}.schema.json")))`.

/// Logical schema names, in the same order as `SCHEMA_NAMES` in index.mjs.
pub const SCHEMA_NAMES: &[&str] = &[
    "execution-contract-v1",
    "execution-task-v1",
    "worker-capsule-v1",
    "artifact-v1",
    "effect-request-v1",
    "effect-receipt-v1",
    "evidence-capability-receipt-v1",
    "blocker-v1",
    "amendment-v1",
    "claim-v1",
    "covenant-request-v1",
    "covenant-record-v1",
    "operation-envelope-v1",
    "legion-result-v1",
    "run-identity-v1",
    "legacy-envelope-v1",
    "authority-dispatch-v1",
    "oracle-completion-validation-v1",
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn eighteen_names_no_duplicates() {
        assert_eq!(SCHEMA_NAMES.len(), 18);
        let unique: std::collections::HashSet<_> = SCHEMA_NAMES.iter().collect();
        assert_eq!(unique.len(), SCHEMA_NAMES.len());
    }
}
