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
pub const EVIDENCE_CLASS: &[&str] = &[
    "deterministic",
    "measured",
    "interpretive",
    "external",
    "human",
];

/// `src/lib/contracts/enums.mjs` — `JUDGMENT_VERDICT`.
pub const JUDGMENT_VERDICT: &[&str] = &["confirmed", "rejected", "unproven", "needs-human"];

/// `src/lib/contracts/enums.mjs` — `REASONING_REQUIREMENT`.
pub const REASONING_REQUIREMENT: &[&str] = &[
    "none",
    "bounded-review",
    "independent-adjudication",
    "human-decision",
];

/// `src/providers/security/contracts.mjs` — `EVIDENCE_STRENGTH`.
pub const EVIDENCE_STRENGTH: &[&str] = &["possible", "strong-inference", "verified"];

/// Legacy spellings accepted on read and mapped to the canonical value.
/// `observed` came from the pre-v2 adjudication ranking; `candidate` from
/// unadjudicated generator output. Neither is ever emitted.
pub const EVIDENCE_STRENGTH_LEGACY: &[(&str, &str)] =
    &[("observed", "strong-inference"), ("candidate", "possible")];

/// The one canonical evidence-strength vocabulary. Deserialization accepts the
/// canonical wire spellings plus [`EVIDENCE_STRENGTH_LEGACY`]; serialization
/// always emits the canonical spelling. Unknown spellings are rejected.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub enum EvidenceStrength {
    #[default]
    Possible,
    StrongInference,
    Verified,
}

impl EvidenceStrength {
    /// Legacy `observed` alias for source compatibility; it is
    /// [`EvidenceStrength::StrongInference`] and serializes as such.
    #[allow(non_upper_case_globals)]
    pub const Observed: EvidenceStrength = EvidenceStrength::StrongInference;

    pub fn as_str(self) -> &'static str {
        match self {
            EvidenceStrength::Possible => "possible",
            EvidenceStrength::StrongInference => "strong-inference",
            EvidenceStrength::Verified => "verified",
        }
    }

    /// Ordering rank: possible 0, strong-inference 1, verified 2.
    pub fn rank(self) -> u8 {
        match self {
            EvidenceStrength::Possible => 0,
            EvidenceStrength::StrongInference => 1,
            EvidenceStrength::Verified => 2,
        }
    }

    /// Canonical or legacy spelling to the canonical value; `None` if unknown.
    pub fn from_wire(text: &str) -> Option<Self> {
        match text {
            "possible" | "candidate" => Some(EvidenceStrength::Possible),
            "strong-inference" | "observed" => Some(EvidenceStrength::StrongInference),
            "verified" => Some(EvidenceStrength::Verified),
            _ => None,
        }
    }

    /// True when `text` is a legacy (non-canonical) spelling.
    pub fn is_legacy_spelling(text: &str) -> bool {
        EVIDENCE_STRENGTH_LEGACY.iter().any(|(old, _)| *old == text)
    }
}

impl serde::Serialize for EvidenceStrength {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> serde::Deserialize<'de> for EvidenceStrength {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = <String as serde::Deserialize>::deserialize(deserializer)?;
        EvidenceStrength::from_wire(&text).ok_or_else(|| {
            serde::de::Error::custom(format!(
                "unknown evidenceStrength {text:?}; expected possible, strong-inference, or verified"
            ))
        })
    }
}

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
