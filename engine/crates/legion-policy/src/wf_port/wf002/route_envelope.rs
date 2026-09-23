//! Rust port of `src/lib/cognitive/arcane/route-envelope.mjs`.
//!
//! Faithful behavioural port. `digestValue` in the JS source is
//! `sha256:<hex of canonical JSON>`, which is exactly
//! `legion_contracts::canonical::canonical_digest`.
//!
//! Adaptation note: the JS source carries evidence as arbitrary JSON. This
//! crate has no `serde_json` dependency (only `legion-contracts`, which uses
//! it privately, does) and this port owner may not edit `Cargo.toml` to add
//! one — see the wf002 report's shared-file patch. `run_falsification_pass`
//! therefore takes `evidence: &[String]` (pre-serialized evidence items)
//! rather than arbitrary JSON values; behaviour (arity/emptiness checks,
//! digesting, freezing) is otherwise identical.

use legion_contracts::canonical::canonical_digest;
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};

pub const ROUTE_STAGES: [&str; 7] = [
    "context",
    "cognition",
    "grounding",
    "compute",
    "challenge",
    "verification",
    "response",
];

/// Availability of each cognitive stage. Absence (no entry) means available;
/// only an explicit `false` degrades a stage — mirrors `availability?.[stage]
/// !== false` in the JS source.
pub type Availability = BTreeMap<String, bool>;

#[derive(Clone, Debug, Default)]
pub struct RouteInput {
    pub prompt: Option<String>,
    pub trivial: bool,
    pub effect: bool,
    pub uncertain: bool,
    pub claims: Vec<String>,
    pub required_stages: BTreeSet<String>,
    pub stage_policy: BTreeMap<String, String>,
    pub model_tier: Option<String>,
    pub model_calls: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "state")]
pub enum StageState {
    /// `{ state: "ACTIVE", policy }`
    #[serde(rename = "ACTIVE")]
    Active { policy: String },
    /// `{ state: "DEGRADED", reason }`
    #[serde(rename = "DEGRADED")]
    Degraded { reason: String },
}

#[derive(Clone, Debug, Serialize)]
pub struct Degradation {
    pub stage: String,
    pub reason: String,
}

#[derive(Clone, Debug)]
pub struct RouteEnvelope {
    pub schema_version: u32,
    pub kind: &'static str,
    pub route_id: String,
    pub mode: &'static str,
    pub model_calls: u64,
    pub selected_model_tier: Option<String>,
    pub stages: BTreeMap<String, StageState>,
    pub degradation: Vec<Degradation>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RouteEnvelopeJson {
    schema_version: u32,
    kind: String,
    route_id: String,
    mode: String,
    model_calls: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    selected_model_tier: Option<String>,
    stages: BTreeMap<String, StageState>,
    degradation: Vec<Degradation>,
}

#[derive(Debug, thiserror::Error)]
pub enum ArcaneRouteError {
    #[error("required Arcane stage unavailable: {stage}")]
    StageUnavailable { stage: String },
    #[error("failed to compute route digest: {0}")]
    Digest(#[from] legion_contracts::canonical::CanonicalError),
}

fn available(availability: &Availability, stage: &str) -> bool {
    availability.get(stage).copied() != Some(false)
}

fn required(input: &RouteInput, stage: &str) -> bool {
    input.required_stages.contains(stage)
}

/// `isTrivialArcaneRoute`.
pub fn is_trivial_arcane_route(input: &RouteInput) -> bool {
    let prompt = input.prompt.as_deref().unwrap_or("").trim();
    input.trivial
        || (prompt.chars().count() <= 80
            && !input.effect
            && !input.uncertain
            && input.claims.is_empty()
            && input.required_stages.is_empty())
}

#[derive(Serialize)]
struct TrivialDigestInput {
    trivial: bool,
    prompt: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct DirectDigestInput {
    prompt: Option<String>,
    uncertain: bool,
    requested_tier: String,
    stages: BTreeMap<String, StageState>,
}

fn stronger_tier(tier: &str) -> &'static str {
    match tier {
        "fast" => "balanced",
        "balanced" => "strong",
        "strong" => "strong",
        _ => "strong",
    }
}

/// Compile one ephemeral, minimum-sufficient cognitive route.
/// Port of `compileArcaneRoute`.
pub fn compile_arcane_route(
    input: &RouteInput,
    availability: &Availability,
) -> Result<RouteEnvelope, ArcaneRouteError> {
    let has_explicit_degradation = availability.values().any(|state| !*state);
    let trivial = is_trivial_arcane_route(input) && !has_explicit_degradation;

    if trivial {
        let prompt = input.prompt.as_deref().unwrap_or("").trim().to_string();
        let route_id = canonical_digest(&TrivialDigestInput {
            trivial: true,
            prompt: prompt.clone(),
        })?;
        let mut stages = BTreeMap::new();
        stages.insert(
            "response".to_string(),
            StageState::Active {
                policy: "direct".to_string(),
            },
        );
        return Ok(RouteEnvelope {
            schema_version: 1,
            kind: "arcane-route-envelope",
            route_id,
            mode: "TRIVIAL",
            model_calls: 0,
            selected_model_tier: None,
            stages,
            degradation: Vec::new(),
        });
    }

    let mut degradation = Vec::new();
    let mut stages = BTreeMap::new();
    for stage in ROUTE_STAGES {
        if available(availability, stage) {
            let policy = input
                .stage_policy
                .get(stage)
                .cloned()
                .unwrap_or_else(|| "proportional".to_string());
            stages.insert(stage.to_string(), StageState::Active { policy });
            continue;
        }
        if required(input, stage) {
            return Err(ArcaneRouteError::StageUnavailable {
                stage: stage.to_string(),
            });
        }
        stages.insert(
            stage.to_string(),
            StageState::Degraded {
                reason: "optional-stage-unavailable".to_string(),
            },
        );
        degradation.push(Degradation {
            stage: stage.to_string(),
            reason: "optional-stage-unavailable".to_string(),
        });
    }

    let uncertain = input.uncertain;
    let requested_tier = input.model_tier.clone().unwrap_or_else(|| "balanced".to_string());

    let route_id = canonical_digest(&DirectDigestInput {
        prompt: input.prompt.clone(),
        uncertain,
        requested_tier: requested_tier.clone(),
        stages: stages.clone(),
    })?;

    let selected_model_tier = if uncertain {
        Some(stronger_tier(&requested_tier).to_string())
    } else {
        Some(requested_tier.clone())
    };
    let model_calls = if uncertain { 1 } else { input.model_calls.unwrap_or(0) };

    Ok(RouteEnvelope {
        schema_version: 1,
        kind: "arcane-route-envelope",
        route_id,
        mode: if uncertain { "UNCERTAINTY_ESCALATION" } else { "DIRECT" },
        model_calls,
        selected_model_tier,
        stages,
        degradation,
    })
}

#[derive(Debug, thiserror::Error)]
pub enum ChallengeError {
    #[error("challenge result must be KEEP, NARROW or REVISE")]
    InvalidResult,
    #[error("falsification pass already consumed")]
    Recursion,
    #[error("claim, evidence & evaluator are required")]
    InvalidInput,
    #[error("failed to compute evidence digest: {0}")]
    Digest(#[from] legion_contracts::canonical::CanonicalError),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ChallengeResult {
    Keep,
    Narrow,
    Revise,
}

impl ChallengeResult {
    fn parse(value: &str) -> Option<Self> {
        match value {
            "KEEP" => Some(Self::Keep),
            "NARROW" => Some(Self::Narrow),
            "REVISE" => Some(Self::Revise),
            _ => None,
        }
    }
}

#[derive(Clone, Debug)]
pub struct ChallengeOutcome {
    pub result: String,
    pub reason: Option<String>,
}

#[derive(Clone, Debug)]
pub struct FinalizedChallenge {
    pub result: ChallengeResult,
    pub reason: String,
    pub evidence_digest: String,
    pub pass_count: u32,
    pub recursive: bool,
}

fn finalize_challenge(
    outcome: &ChallengeOutcome,
    evidence: &[String],
) -> Result<FinalizedChallenge, ChallengeError> {
    let result = ChallengeResult::parse(&outcome.result).ok_or(ChallengeError::InvalidResult)?;
    let evidence_digest = canonical_digest(&evidence.to_vec())?;
    Ok(FinalizedChallenge {
        result,
        reason: outcome.reason.clone().unwrap_or_default(),
        evidence_digest,
        pass_count: 1,
        recursive: false,
    })
}

/// One evidence-directed falsification pass. No recursive pass is
/// representable. Port of `runFalsificationPass`; the JS version's
/// `evaluate` may be async — the Rust port takes a synchronous evaluator and
/// leaves the async variant to the caller.
pub fn run_falsification_pass<F>(
    claim: &str,
    evidence: &[String],
    pass_count: u32,
    evaluate: F,
) -> Result<FinalizedChallenge, ChallengeError>
where
    F: FnOnce(&str, &[String]) -> ChallengeOutcome,
{
    if pass_count != 0 {
        return Err(ChallengeError::Recursion);
    }
    if claim.trim().is_empty() || evidence.is_empty() {
        return Err(ChallengeError::InvalidInput);
    }
    let outcome = evaluate(claim, evidence);
    finalize_challenge(&outcome, evidence)
}

/// Port of `routeEnvelopeContext`: `ARCANE_ROUTE:<json>` when `envelope` is a
/// genuine route envelope, else `None`.
pub fn route_envelope_context(envelope: &RouteEnvelope) -> Result<Option<String>, ArcaneRouteError> {
    if envelope.kind != "arcane-route-envelope" {
        return Ok(None);
    }
    let json = RouteEnvelopeJson {
        schema_version: envelope.schema_version,
        kind: envelope.kind.to_string(),
        route_id: envelope.route_id.clone(),
        mode: envelope.mode.to_string(),
        model_calls: envelope.model_calls,
        selected_model_tier: envelope.selected_model_tier.clone(),
        stages: envelope.stages.clone(),
        degradation: envelope.degradation.clone(),
    };
    let bytes = legion_contracts::canonical::canonical_json_bytes(&json)?;
    let text = String::from_utf8(bytes).expect("canonical JSON is always valid UTF-8");
    Ok(Some(format!("ARCANE_ROUTE:{text}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trivial_route_short_prompt_no_effect() {
        let input = RouteInput {
            prompt: Some("hi".into()),
            ..Default::default()
        };
        let envelope = compile_arcane_route(&input, &Availability::new()).unwrap();
        assert_eq!(envelope.mode, "TRIVIAL");
        assert_eq!(envelope.model_calls, 0);
        assert_eq!(envelope.stages.len(), 1);
        assert!(matches!(
            envelope.stages.get("response"),
            Some(StageState::Active { policy }) if policy == "direct"
        ));
    }

    #[test]
    fn explicit_trivial_flag_wins_even_with_effect() {
        let input = RouteInput {
            trivial: true,
            effect: true,
            ..Default::default()
        };
        let envelope = compile_arcane_route(&input, &Availability::new()).unwrap();
        assert_eq!(envelope.mode, "TRIVIAL");
    }

    #[test]
    fn explicit_degradation_defeats_triviality() {
        let mut availability = Availability::new();
        availability.insert("compute".to_string(), false);
        let input = RouteInput {
            prompt: Some("hi".into()),
            ..Default::default()
        };
        let envelope = compile_arcane_route(&input, &availability).unwrap();
        assert_ne!(envelope.mode, "TRIVIAL");
        assert_eq!(envelope.stages.len(), ROUTE_STAGES.len());
    }

    #[test]
    fn non_trivial_route_covers_all_stages_and_degrades_unavailable_ones() {
        let mut availability = Availability::new();
        availability.insert("challenge".to_string(), false);
        let input = RouteInput {
            prompt: Some(
                "a very long and detailed prompt describing a lot of work to do here".into(),
            ),
            effect: true,
            ..Default::default()
        };
        let envelope = compile_arcane_route(&input, &availability).unwrap();
        assert_eq!(envelope.mode, "DIRECT");
        assert_eq!(envelope.degradation.len(), 1);
        assert_eq!(envelope.degradation[0].stage, "challenge");
        assert!(matches!(
            envelope.stages.get("challenge"),
            Some(StageState::Degraded { .. })
        ));
    }

    #[test]
    fn required_but_unavailable_stage_errors() {
        let mut availability = Availability::new();
        availability.insert("compute".to_string(), false);
        let mut input = RouteInput {
            prompt: Some("do the thing".into()),
            ..Default::default()
        };
        input.required_stages.insert("compute".to_string());
        let err = compile_arcane_route(&input, &availability).unwrap_err();
        assert!(matches!(err, ArcaneRouteError::StageUnavailable { stage } if stage == "compute"));
    }

    #[test]
    fn uncertain_input_escalates_tier_and_forces_one_model_call() {
        let input = RouteInput {
            prompt: Some(
                "a very long and detailed prompt describing a lot of work to do here".into(),
            ),
            uncertain: true,
            model_tier: Some("fast".into()),
            ..Default::default()
        };
        let envelope = compile_arcane_route(&input, &Availability::new()).unwrap();
        assert_eq!(envelope.mode, "UNCERTAINTY_ESCALATION");
        assert_eq!(envelope.model_calls, 1);
        assert_eq!(envelope.selected_model_tier.as_deref(), Some("balanced"));
    }

    #[test]
    fn strong_tier_stays_strong_under_uncertainty() {
        let input = RouteInput {
            prompt: Some(
                "a very long and detailed prompt describing a lot of work to do here".into(),
            ),
            uncertain: true,
            model_tier: Some("strong".into()),
            ..Default::default()
        };
        let envelope = compile_arcane_route(&input, &Availability::new()).unwrap();
        assert_eq!(envelope.selected_model_tier.as_deref(), Some("strong"));
    }

    #[test]
    fn route_ids_are_stable_for_identical_input() {
        let input = RouteInput {
            prompt: Some("stable prompt text right here for determinism".into()),
            ..Default::default()
        };
        let a = compile_arcane_route(&input, &Availability::new()).unwrap();
        let b = compile_arcane_route(&input, &Availability::new()).unwrap();
        assert_eq!(a.route_id, b.route_id);
    }

    #[test]
    fn falsification_pass_rejects_bad_result() {
        let evidence = vec!["e1".to_string()];
        let err = run_falsification_pass("claim", &evidence, 0, |_claim, _evidence| ChallengeOutcome {
            result: "MAYBE".into(),
            reason: None,
        })
        .unwrap_err();
        assert!(matches!(err, ChallengeError::InvalidResult));
    }

    #[test]
    fn falsification_pass_rejects_reuse() {
        let evidence = vec!["e1".to_string()];
        let err = run_falsification_pass("claim", &evidence, 1, |_claim, _evidence| ChallengeOutcome {
            result: "KEEP".into(),
            reason: None,
        })
        .unwrap_err();
        assert!(matches!(err, ChallengeError::Recursion));
    }

    #[test]
    fn falsification_pass_rejects_empty_claim_or_evidence() {
        let err = run_falsification_pass("", &["e".to_string()], 0, |_c, _e| ChallengeOutcome {
            result: "KEEP".into(),
            reason: None,
        })
        .unwrap_err();
        assert!(matches!(err, ChallengeError::InvalidInput));

        let err = run_falsification_pass("claim", &[], 0, |_c, _e| ChallengeOutcome {
            result: "KEEP".into(),
            reason: None,
        })
        .unwrap_err();
        assert!(matches!(err, ChallengeError::InvalidInput));
    }

    #[test]
    fn falsification_pass_succeeds_and_freezes_evidence_digest() {
        let evidence = vec!["e1".to_string(), "e2".to_string()];
        let outcome = run_falsification_pass("claim text", &evidence, 0, |claim, evidence| {
            assert_eq!(claim, "claim text");
            assert_eq!(evidence.len(), 2);
            ChallengeOutcome {
                result: "NARROW".into(),
                reason: Some("scope too wide".into()),
            }
        })
        .unwrap();
        assert_eq!(outcome.result, ChallengeResult::Narrow);
        assert_eq!(outcome.reason, "scope too wide");
        assert_eq!(outcome.pass_count, 1);
        assert!(!outcome.recursive);
        assert!(outcome.evidence_digest.starts_with("sha256:"));
    }

    #[test]
    fn route_envelope_context_wraps_json_with_prefix() {
        let input = RouteInput {
            prompt: Some("hi".into()),
            ..Default::default()
        };
        let envelope = compile_arcane_route(&input, &Availability::new()).unwrap();
        let context = route_envelope_context(&envelope).unwrap().unwrap();
        assert!(context.starts_with("ARCANE_ROUTE:"));
        assert!(context.contains("\"kind\":\"arcane-route-envelope\""));
    }
}
