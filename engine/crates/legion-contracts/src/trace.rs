//! Route/outcome telemetry trace (tracker P1.6).
//!
//! Automatic, content-light, structured trace emitted once per routed
//! request. It carries no agent-authored prose — every field is a
//! mechanically recorded classification, count, or flag — so the four
//! Bounded Falsification metrics defined in
//! `docs/provenance/migrations/2026-08-29-pending/ARCANE-COGNITIVE-CONTROL-PLANE-2026-08-29-REV3.md` §30
//! ("Telemetry (feeds Section 29 / tracker P1.6)") are computable as pure
//! functions over recorded traces, with no human judgment required at
//! measurement time. See `schemas/route-outcome-trace.v1.md` for the exact
//! metric formulas over this schema.
//!
//! v0 is schema-only: this module defines and validates the record shape.
//! No collector/emitter pipeline is implemented here; recording sites are
//! wired in a later change.

use serde::{Deserialize, Serialize};

use crate::{
    canonical_digest,
    id::{RequestId, TaskId, TraceId},
    require_version, ContractError,
};

/// Cognition axis (Arcane §5): direct answer, deliberate thinking, or
/// grounding. Decomposition is represented via multiple child traces
/// rather than a fourth route value, matching tracker P1.6's field list.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Route {
    Direct,
    Deliberate,
    Grounded,
}

/// Semantic requirement tri-state (Arcane §7). Governs model vs no-model
/// execution and is a shared Arcane -> Legion concept.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[allow(non_camel_case_types)]
pub enum SemanticRequirement {
    FORBIDDEN,
    CONDITIONAL,
    REQUIRED,
}

/// Which shared authority role attached to this request (Arcane §13), if
/// any. Absence is represented by `None` on the containing field, not by a
/// variant, so "no authority attached" never needs a placeholder string.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthorityKind {
    Sage,
    Alchemist,
    Oracle,
}

/// Compute posture (Arcane §5/§9/§18): whether a model runs at all, and if
/// so which tier.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ComputePosture {
    NoModel,
    Tiny,
    Strong,
}

/// Terminal outcome of the routed request.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OutcomeResult {
    Success,
    Repair,
    UserCorrection,
    Blocked,
}

/// Bounded Falsification level (Arcane §30 "Three levels").
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum ChallengeLevel {
    L0,
    L1,
    L2,
}

/// L1 trigger vocabulary, verbatim from Arcane §30 "L1 triggers".
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ChallengeTrigger {
    /// Recommendation resting on assumed rather than inspected implementation.
    AssumedImplementation,
    /// Diagnosis from symptoms while decisive evidence is cheaply available.
    DiagnosisFromAvailableEvidence,
    /// Architectural recommendation materially dependent on checkable
    /// implementation assumptions (conceptual design work alone does not
    /// trigger).
    ArchitecturalAssumptionDependency,
    /// Consequential extrapolation in the answer.
    ConsequentialExtrapolation,
    /// About to contradict a canonical source.
    ContradictsCanonicalSource,
    /// Confidence materially dependent on 1-3 checkable assumptions.
    CheckableAssumptionConfidence,
    /// Explicit user challenge ("are you sure?", "check that").
    ExplicitUserChallenge,
    /// The previous answer was challenged or corrected.
    PriorAnswerChallenged,
}

/// KEEP / NARROW / REVISE (Arcane §30 "The primitive"). Only present when
/// a challenge pass was invoked.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ChallengeOutcome {
    Keep,
    Narrow,
    Revise,
}

/// Context sources and total retrieved size for this request (Attention
/// axis, Arcane §5).
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContextUsage {
    pub sources: Vec<String>,
    pub size_bytes: u64,
}

/// Capabilities/skills considered vs the ones actually selected (Expertise
/// axis, Arcane §5).
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilityUsage {
    pub considered: Vec<String>,
    pub selected: Vec<String>,
}

/// Token and cost accounting. Cost is recorded in integer micro-USD
/// (1 unit = 1e-6 USD) to keep the record float-free, matching the
/// integer-units convention already used for cost/risk/rework in
/// `schemas/goal-route.v1.schema.json`.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CostUsage {
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub cost_usd_micros: u64,
}

/// Bounded Falsification (Challenge Pass) fields. These, plus
/// `assumption_dependent_conclusion`, `evidence_available_at_first_answer`,
/// and `user_challenge_event`, are exactly the recorded fields the four
/// Arcane §30 telemetry formulas are built from.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChallengePass {
    /// Whether a challenge pass (L1 self-challenge or L2 independent
    /// review) was invoked for this request at all.
    pub invoked: bool,
    /// Level of the pass. `L0` when `invoked` is false.
    pub level: ChallengeLevel,
    /// Which L1 trigger (if any) fired the pass. `None` when `invoked` is
    /// false, and may be `None` even when invoked (e.g. an L2 pass invoked
    /// for reasons outside the L1 trigger vocabulary).
    pub trigger: Option<ChallengeTrigger>,
    /// KEEP / NARROW / REVISE. `None` exactly when `invoked` is false.
    pub outcome: Option<ChallengeOutcome>,
    /// Whether the committed conclusion was materially assumption-dependent
    /// (denominator of `user_challenge_rate` and
    /// `avoidable_user_challenge_rate`), independent of whether a pass ran.
    pub assumption_dependent_conclusion: bool,
    /// Whether decisive evidence for the checked assumptions was already
    /// available at the time of the first answer, before any challenge.
    /// Used by `avoidable_user_challenge_rate`.
    pub evidence_available_at_first_answer: bool,
    /// Distinct from `assumption_dependent_conclusion`: whether the user
    /// explicitly challenged a prior answer in this turn (e.g. "are you
    /// sure?"). Numerator of `user_challenge_rate`.
    pub user_challenge_event: bool,
}

impl ChallengePass {
    fn validate(&self) -> Result<(), ContractError> {
        if self.invoked {
            if self.level == ChallengeLevel::L0 {
                return Err(ContractError::InvalidContract {
                    path: "challenge.level".into(),
                    reason: "invoked challenge pass must be L1 or L2, not L0".into(),
                });
            }
            if self.outcome.is_none() {
                return Err(ContractError::InvalidContract {
                    path: "challenge.outcome".into(),
                    reason: "invoked challenge pass must record KEEP/NARROW/REVISE".into(),
                });
            }
        } else {
            if self.level != ChallengeLevel::L0 {
                return Err(ContractError::InvalidContract {
                    path: "challenge.level".into(),
                    reason: "level must be L0 when no challenge pass was invoked".into(),
                });
            }
            if self.outcome.is_some() {
                return Err(ContractError::InvalidContract {
                    path: "challenge.outcome".into(),
                    reason: "outcome must be absent when no challenge pass was invoked".into(),
                });
            }
            if self.trigger.is_some() {
                return Err(ContractError::InvalidContract {
                    path: "challenge.trigger".into(),
                    reason: "trigger must be absent when no challenge pass was invoked".into(),
                });
            }
        }
        Ok(())
    }
}

/// One automatic, content-light route/outcome trace record (tracker P1.6).
///
/// Emitted per routed request. Carries no agent-authored artifact content —
/// only mechanical classifications, counts, and flags — so it can be
/// recorded on every request without a review step, and so the Arcane §30
/// metrics can be computed over a corpus of these traces without
/// re-deriving their definitions.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteOutcomeTrace {
    #[serde(deserialize_with = "crate::deserialize_schema_version_1")]
    pub schema_version: u32,
    pub trace_id: TraceId,
    pub request_id: RequestId,
    pub task_id: Option<TaskId>,
    /// Content-addressed identity of the Arcane cognitive profile that
    /// produced this route, when provenance was available.
    #[serde(default, rename = "arcaneProfileDigest")]
    pub arcane_profile_digest: Option<String>,
    /// Content-addressed identity of the Legion canonical rules that were
    /// in force when this route was produced, when provenance was available.
    #[serde(default, rename = "legionCanonDigest")]
    pub legion_canon_digest: Option<String>,
    /// Content-addressed identity of the installed skill catalog used for
    /// this route, when provenance was available.
    #[serde(default, rename = "skillCatalogDigest")]
    pub skill_catalog_digest: Option<String>,
    /// Content-addressed identity of the Guard policy used for this route or
    /// verdict, when provenance was available.
    #[serde(default, rename = "guardPolicyDigest")]
    pub guard_policy_digest: Option<String>,
    pub route: Route,
    pub semantic_requirement: SemanticRequirement,
    pub context: ContextUsage,
    pub capabilities: CapabilityUsage,
    pub authority_attached: Option<AuthorityKind>,
    pub compute_posture: ComputePosture,
    pub result: OutcomeResult,
    pub latency_ms: u64,
    pub cost: CostUsage,
    pub challenge: ChallengePass,
}

impl RouteOutcomeTrace {
    pub fn validate(&self) -> Result<(), ContractError> {
        require_version(self.schema_version, 1)?;
        self.challenge.validate()?;
        Ok(())
    }

    pub fn digest(&self) -> Result<String, crate::canonical::CanonicalError> {
        canonical_digest(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> RouteOutcomeTrace {
        RouteOutcomeTrace {
            schema_version: 1,
            trace_id: TraceId::new("trace-1").unwrap(),
            request_id: RequestId::new("request-1").unwrap(),
            task_id: Some(TaskId::new("task-1").unwrap()),
            arcane_profile_digest: Some("arcane-profile-digest-1".into()),
            legion_canon_digest: Some("legion-canon-digest-1".into()),
            skill_catalog_digest: Some("skill-catalog-digest-1".into()),
            guard_policy_digest: Some("guard-policy-digest-1".into()),
            route: Route::Deliberate,
            semantic_requirement: SemanticRequirement::REQUIRED,
            context: ContextUsage {
                sources: vec!["docs/provenance/migrations/2026-08-29-pending/PENDING-WORK-2026-08-29.md".into()],
                size_bytes: 4096,
            },
            capabilities: CapabilityUsage {
                considered: vec!["architect".into(), "debugger".into()],
                selected: vec!["architect".into()],
            },
            authority_attached: Some(AuthorityKind::Sage),
            compute_posture: ComputePosture::Strong,
            result: OutcomeResult::Success,
            latency_ms: 4200,
            cost: CostUsage {
                input_tokens: 12_000,
                output_tokens: 900,
                cost_usd_micros: 154_000,
            },
            challenge: ChallengePass {
                invoked: true,
                level: ChallengeLevel::L1,
                trigger: Some(ChallengeTrigger::CheckableAssumptionConfidence),
                outcome: Some(ChallengeOutcome::Narrow),
                assumption_dependent_conclusion: true,
                evidence_available_at_first_answer: true,
                user_challenge_event: false,
            },
        }
    }

    #[test]
    fn round_trips_through_json() {
        let trace = sample();
        trace.validate().expect("sample trace is valid");
        let json = serde_json::to_string(&trace).expect("serialize");
        let parsed: RouteOutcomeTrace = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(trace, parsed);
        parsed.validate().expect("round-tripped trace is valid");
        assert!(trace.digest().is_ok());
    }

    #[test]
    fn missing_provenance_digests_still_deserialize() {
        let mut json = serde_json::to_value(sample()).expect("serialize");
        let object = json.as_object_mut().expect("trace is an object");
        object.remove("arcaneProfileDigest");
        object.remove("legionCanonDigest");
        object.remove("skillCatalogDigest");
        object.remove("guardPolicyDigest");

        let parsed: RouteOutcomeTrace = serde_json::from_value(json).expect("deserialize");
        assert_eq!(parsed.arcane_profile_digest, None);
        assert_eq!(parsed.legion_canon_digest, None);
        assert_eq!(parsed.skill_catalog_digest, None);
        assert_eq!(parsed.guard_policy_digest, None);
        parsed.validate().expect("trace without provenance is valid");
    }

    #[test]
    fn rejects_wrong_schema_version() {
        let mut trace = sample();
        trace.schema_version = 2;
        let json = serde_json::to_string(&trace).expect("serialize");
        let parsed: Result<RouteOutcomeTrace, _> = serde_json::from_str(&json);
        assert!(parsed.is_err());
    }

    #[test]
    fn rejects_outcome_without_invocation() {
        let mut trace = sample();
        trace.challenge.invoked = false;
        assert!(trace.validate().is_err());
    }

    #[test]
    fn rejects_invoked_without_outcome() {
        let mut trace = sample();
        trace.challenge.outcome = None;
        assert!(trace.validate().is_err());
    }

    #[test]
    fn allows_no_challenge_pass() {
        let mut trace = sample();
        trace.challenge = ChallengePass {
            invoked: false,
            level: ChallengeLevel::L0,
            trigger: None,
            outcome: None,
            assumption_dependent_conclusion: false,
            evidence_available_at_first_answer: false,
            user_challenge_event: false,
        };
        trace.validate().expect("L0 trace is valid");
    }
}
