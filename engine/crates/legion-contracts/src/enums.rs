//! Port of the code-owned contract enums consumed by
//! `scripts/generate-schemas.mjs`:
//! `src/registry/provider-contracts.mjs`, `src/providers/security/contracts.mjs`
//! (which re-exports `src/lib/contracts/enums.mjs`'s `PROVIDER_STATUS`), and
//! `src/lib/contracts/enums.mjs` itself.
//!
//! Only the enum arrays these generators read are ported here (`assertEnum`
//! / `assertSchemaVersion` are call-site validation helpers with no
//! generated-output role and are not ported).

/// `src/registry/provider-contracts.mjs` — `PROVIDER_STATUS`. Also the
/// value `src/lib/contracts/enums.mjs` exports under the same name and that
/// `security/contracts.mjs` re-exports; all three lists are identical in
/// the current source.
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

/// `src/registry/provider-contracts.mjs` — `PROVIDER_ROLES`.
pub const PROVIDER_ROLES: &[&str] = &[
    "deterministic",
    "model-builder",
    "candidate-generator",
    "hypothesis-generator",
    "adjudicator",
    "variant-analyzer",
    "evidence-synthesizer",
];

/// `src/registry/provider-contracts.mjs` — `PROVIDER_PHASES`.
pub const PROVIDER_PHASES: &[&str] = &[
    "facts",
    "model",
    "runtime",
    "hypothesis",
    "reasoning",
    "variants",
    "synthesis",
];

/// `src/lib/contracts/enums.mjs` — `PROVIDER_ROLE` (singular; distinct
/// vocabulary from `PROVIDER_ROLES` above — not consumed by
/// `generate-schemas.mjs`, ported for completeness since other T2 modules
/// import `src/lib/contracts/enums.mjs`).
pub const PROVIDER_ROLE: &[&str] = &[
    "deterministic",
    "candidate-generator",
    "adjudicator",
    "variant-analysis",
    "renderer",
];

/// `src/lib/contracts/enums.mjs` — `EVIDENCE_CLASS`.
pub const EVIDENCE_CLASS: &[&str] = &["deterministic", "measured", "interpretive", "external", "human"];

/// `src/lib/contracts/enums.mjs` — `JUDGMENT_VERDICT`.
pub const JUDGMENT_VERDICT: &[&str] = &["confirmed", "rejected", "unproven", "needs-human"];

/// `src/lib/contracts/enums.mjs` — `REASONING_REQUIREMENT`.
pub const REASONING_REQUIREMENT: &[&str] =
    &["none", "bounded-review", "independent-adjudication", "human-decision"];

/// `src/providers/security/contracts.mjs` — `EVIDENCE_STRENGTH`.
pub const EVIDENCE_STRENGTH: &[&str] = &["possible", "strong-inference", "verified"];

/// `src/providers/security/contracts.mjs` — `SECURITY_VERDICTS`
/// (`PRIMITIVE_VERDICTS` is an alias of this same list in the JS).
pub const SECURITY_VERDICTS: &[&str] = &[
    "TRUE_POSITIVE",
    "LIKELY_TRUE_POSITIVE",
    "LIKELY_FALSE_POSITIVE",
    "FALSE_POSITIVE",
    "OUT_OF_SCOPE",
    "HARDENING_GAP",
    "MISUSE_HAZARD",
];

/// `src/providers/security/contracts.mjs` — `FACT_KINDS`.
pub const FACT_KINDS: &[&str] = &[
    "attacker-position",
    "knowledge",
    "capability",
    "credential-possession",
    "principal-access",
    "network-reachability",
    "data-access",
    "object-access",
    "code-execution",
    "workflow-state",
    "control-bypass",
    "persistence",
    "availability-impact",
    "integrity-impact",
    "confidentiality-impact",
];
