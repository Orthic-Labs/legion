//! Rust port of `src/packages/contracts/enums.mjs` (L2 packet).
//!
//! This module is the single code-owned source of truth for every enumerated
//! wire value used by the JSON Schemas in `src/packages/contracts/schemas/`.
//! It mirrors the JS module's arrays and helper functions exactly; if you
//! change an enum here, change `enums.mjs` first (or in lockstep) so the two
//! runtimes stay set-equal, then update the schema(s).
//!
//! docs/LEGION-CANONICAL-SSOT.md owns semantics; this module projects only
//! current contract/runtime vocabulary.

/// Runtime identities permitted in authority-bearing contract fields. Covenant is advisory.
pub const AUTHORITY_ID: &[&str] = &["legion", "sage", "alchemist", "oracle", "arcane", "kernel"];

/// Decision latitude on an artifact/task.
pub const LATITUDE: &[&str] = &["EXACT", "BOUNDED", "OPEN"];

/// Alchemist terminal/intermediate execution states, reused as domain outcome.
pub const ALCHEMIST_STATE: &[&str] = &[
    "REPAIR",
    "BLOCKED_DECISION",
    "NEEDS_AMENDMENT",
    "OUT_OF_SCOPE",
    "BUDGET_STOP",
    "FAILED_CONTRACT",
    "COMPLETE",
];

/// Domain outcome of an operation/run — reuses `ALCHEMIST_STATE` (see above).
pub const DOMAIN_OUTCOME: &[&str] = ALCHEMIST_STATE;

/// Runtime invocation lifecycle, orthogonal to domain outcome & claim boundary.
pub const INVOCATION_STATE: &[&str] = &[
    "ACCEPTED",
    "RUNNING",
    "INPUT_REQUIRED",
    "CANCELLED",
    "EXPIRED",
    "FAILED_INVOCATION",
    "COMPLETED",
];

/// Claim boundary is distinct from invocation state & domain outcome.
pub const CLAIM_BOUNDARY: &[&str] = &[
    "CLEAN_WITHIN_DECLARED_SCOPE",
    "PARTIALLY_PROVEN",
    "UNPROVEN",
    "EVIDENCE_INSUFFICIENT",
    "NOT_APPLICABLE",
];

/// Sage claims are limited to actual exceptional adjudication.
pub const SAGE_CLAIM: &[&str] = &[
    "ADJUDICATION_MADE",
    "SEMANTIC_CONFLICT_RESOLVED",
    "ACCEPTANCE_SEMANTICS_SEALED",
    "ADJUDICATED_CONTRACT_SEALED",
];

/// Alchemist-owned transformation claims.
pub const ALCHEMIST_CLAIM: &[&str] = &[
    "EFFECT_APPLIED",
    "CANDIDATE_READY",
    "DECLARED_CHECKS_PASSED",
    "IMPLEMENTATION_MATCHES_CONTRACT",
    "LOCAL_EXECUTION_VERIFIED",
];

/// Oracle claims are limited to independent Completion Validation.
pub const ORACLE_CLAIM: &[&str] = &[
    "COMPLETION_VALIDATED",
    "COMPLETION_BLOCKED",
    "UNKNOWN",
    "NOT_APPLICABLE",
    "EVIDENCE_INSUFFICIENT",
];

/// Authority context supplied by an explicit Covenant caller.
pub const CALLER_AUTHORITY: &[&str] = &["SAGE", "ALCHEMIST", "USER_OVERRIDE"];

/// Covenant advisory modes. `DISPUTE_REVIEW` is exceptional; its presence
/// does not make Covenant a routine Oracle route or release gate.
pub const COVENANT_MODE: &[&str] = &[
    "DECISION_CHALLENGE",
    "BLOCKER_CONSULT",
    "PACKET_ONLY",
    "DISPUTE_REVIEW",
];

/// Covenant outcomes across all modes. Not every value applies to every
/// mode; see ids.md / schema descriptions.
pub const COVENANT_OUTCOME: &[&str] = &[
    "SUPPORTED",
    "REVISE",
    "UNRESOLVED",
    "CONTRACT_SAFE",
    "AMENDMENT_REQUIRED",
    "INSUFFICIENT_EVIDENCE",
];

/// Originating decision owner disposition of a Covenant finding.
pub const DISPOSITION_VALUE: &[&str] = &[
    "ACCEPT",
    "REJECT",
    "DEFER_TO_PHASE",
    "NEEDS_EVIDENCE",
    "SUPERSEDED",
];

/// Covenant finding scope classification.
pub const FINDING_SCOPE_CLASS: &[&str] = &[
    "IN_SCOPE_DEFECT",
    "LATER_PHASE",
    "OUT_OF_SCOPE",
    "MISSING_EVIDENCE",
    "OPTIONAL_VALUE",
];

/// Runtime effect classes Arcane authorizes & gates. Canonical semantic
/// effect classes remain owned by docs/LEGION-CANONICAL-SSOT.md; this is a
/// deliberately narrower compatibility vocabulary at the enforcement
/// boundary.
pub const EFFECT_CLASS: &[&str] = &[
    "FILE_WRITE",
    "FILE_DELETE",
    "FILE_MOVE",
    "COMMAND_EXEC",
    "NETWORK_EGRESS",
    "PROCESS_SPAWN",
    "CREDENTIAL_ACCESS",
    "DEPENDENCY_INSTALL",
    "VCS_COMMIT",
    "VCS_PUSH",
    "PUBLISH",
    "EXTERNAL_SIDE_EFFECT",
];

/// Abstract runtime model tiers. Role identity sources own tier selection;
/// generated host projections may map them to host-specific model names.
pub const MODEL_TIER: &[&str] = &["FRONTIER", "MID", "CHEAP_STRICT", "NONE"];

/// Worker execution profiles.
pub const WORKER_PROFILE: &[&str] = &["strict", "standard", "advanced"];

/// Effect/evidence authentication method. Imported historical records
/// remain explicitly unauthenticated; connection trust never masquerades as
/// per-message proof.
pub const AUTHENTICATION_METHOD: &[&str] =
    &["host-connection-trust", "capability-signature", "unauthenticated"];

/// Advisory contract-safety outcome from Covenant blocker challenge.
pub const BLOCKER_CONSULT_OUTCOME: &[&str] =
    &["CONTRACT_SAFE", "AMENDMENT_REQUIRED", "INSUFFICIENT_EVIDENCE"];

/// Whether a blocker is clearly semantic or possibly contract-safe.
pub const BLOCKER_CLASS: &[&str] = &["CLEARLY_SEMANTIC", "POSSIBLY_CONTRACT_SAFE"];

/// Blocker lifecycle status.
pub const BLOCKER_STATUS: &[&str] = &["OPEN", "COVENANT_CONSULTED", "AMENDED", "RESOLVED"];

/// Claim object lifecycle status; Arcane owns validation transitions.
pub const CLAIM_STATUS: &[&str] = &["PENDING", "VALIDATED", "REJECTED"];

/// Evidence class for an evidence-capability receipt. Values are duplicated
/// inline (not imported) from legion's existing EVIDENCE_CLASS convention
/// (lib/contracts, providers/security/contracts.mjs) to avoid this package
/// taking a runtime dependency on legion's internal provider pipeline.
/// Judgment call J-5, see FREEZE.md.
pub const EVIDENCE_CLASS: &[&str] = &["deterministic", "measured", "interpretive", "external", "human"];

/// Every claim name across all authorities; Arcane validates but does not
/// invent them. Built at call time (not const) because `&[&str]` concat
/// needs an allocation; callers that need a static view should use
/// `claims_by_authority` per-authority instead.
pub fn claim_name() -> Vec<&'static str> {
    SAGE_CLAIM
        .iter()
        .chain(ALCHEMIST_CLAIM.iter())
        .chain(ORACLE_CLAIM.iter())
        .copied()
        .collect()
}

/// Which claim names a given authority is permitted to assert. Mirrors
/// `CLAIMS_BY_AUTHORITY` in enums.mjs. Returns `None` for an authority with
/// no claim vocabulary (e.g. `legion`, `arcane`, `kernel`).
pub fn claims_by_authority(authority: &str) -> Option<&'static [&'static str]> {
    match authority {
        "sage" => Some(SAGE_CLAIM),
        "alchemist" => Some(ALCHEMIST_CLAIM),
        "oracle" => Some(ORACLE_CLAIM),
        _ => None,
    }
}

/// Port of `assertEnum(label, values, value)`: returns the value unchanged
/// if it is a member of `values`, otherwise an error naming the label and
/// offending value (mirrors the JS `TypeError` message).
pub fn assert_enum<'a>(label: &str, values: &[&str], value: &'a str) -> Result<&'a str, String> {
    if values.contains(&value) {
        Ok(value)
    } else {
        Err(format!("unknown {label}: {value}"))
    }
}

/// Port of `assertSchemaVersion(label, version, supported = [1])`.
pub fn assert_schema_version(label: &str, version: u32, supported: &[u32]) -> Result<u32, String> {
    if supported.contains(&version) {
        Ok(version)
    } else {
        Err(format!("{label} unsupported schema version: {version}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn claim_name_matches_union() {
        let all = claim_name();
        assert_eq!(all.len(), SAGE_CLAIM.len() + ALCHEMIST_CLAIM.len() + ORACLE_CLAIM.len());
        assert!(all.contains(&"ADJUDICATION_MADE"));
        assert!(all.contains(&"EFFECT_APPLIED"));
        assert!(all.contains(&"COMPLETION_VALIDATED"));
    }

    #[test]
    fn claims_by_authority_matches_per_role_arrays() {
        assert_eq!(claims_by_authority("sage"), Some(SAGE_CLAIM));
        assert_eq!(claims_by_authority("alchemist"), Some(ALCHEMIST_CLAIM));
        assert_eq!(claims_by_authority("oracle"), Some(ORACLE_CLAIM));
        assert_eq!(claims_by_authority("legion"), None);
    }

    #[test]
    fn assert_enum_ok_and_err() {
        assert_eq!(assert_enum("latitude", LATITUDE, "EXACT"), Ok("EXACT"));
        assert!(assert_enum("latitude", LATITUDE, "NOPE").is_err());
    }

    #[test]
    fn assert_schema_version_default_supported() {
        assert_eq!(assert_schema_version("x", 1, &[1]), Ok(1));
        assert!(assert_schema_version("x", 2, &[1]).is_err());
    }
}
