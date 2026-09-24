//! Port of `buildSealedPlan` from `src/lib/core/build-plan.mjs` (packet
//! r44), closing part of the gap w2_039 left open.
//!
//! Ported in full: the claim-ranking table (`CLAIMS`/`CLAIM_RANK`), the
//! `requiredForClaim` check, and the entire `buildSealedPlan` stage loop —
//! run each stage in order, collect gaps for incomplete stages, restrict to
//! `requiredStageIds` for the requested claim level, assemble and digest the
//! sealed plan. Stages are modeled as the [`PlanStage`] trait (`id`,
//! `required_for`, `run`) exactly as JS takes `{id, requiredFor, run}`
//! objects, so the loop is generic over whatever stage implementations a
//! caller supplies.
//!
//! NOT ported: `DEFAULT_STAGES`'s concrete stage bodies
//! (`product-portfolio` → `productTopologyStage.run` →
//! `./plan-stages/product-topology.mjs` → `inspectProduct` from
//! `../inspect-product.mjs`; `control-baseline` → `controlBaselineStage.run`
//! → `./plan-stages/control-baseline.mjs` → `../../controls/baseline/compile.mjs`
//! + `../../controls/evidence/{capabilities,impacts}.mjs`). Those pull in
//! the `inspectProduct` 13-collaborator pipeline and the `controls/**`
//! subsystem, neither in this packet and neither owned by it (confirmed:
//! `git grep -l "buildPortfolio\|extractComponents\|compileBaseline"
//! engine/` has no hits). The `blueprint-packet` default stage is also
//! dropped outright per the Membrane/Blueprint retirement (`options[key] ??
//! options.artifacts?.[id]` reading a Membrane projection). A caller with
//! real stage implementations can supply them as [`PlanStage`] impls and
//! get a byte-faithful `buildSealedPlan` today; only the specific
//! `DEFAULT_STAGES` bodies remain to be ported once their dependency trees
//! land.

use std::collections::BTreeMap;

use serde_json::{json, Value};

use super::binding::digest;

/// Mirrors `const CLAIMS = new Set([...])` / `CLAIM_RANK`.
pub const CLAIMS: [&str; 5] = ["inventory", "source", "runtime", "product", "release"];

pub fn claim_rank(claim: &str) -> Option<u8> {
    match claim {
        "inventory" => Some(0),
        "source" => Some(1),
        "runtime" => Some(2),
        "product" => Some(3),
        "release" => Some(4),
        _ => None,
    }
}

/// Result of running one stage, mirroring `{complete, status, artifact,
/// detail}`.
#[derive(Clone, Debug, Default)]
pub struct StageResult {
    pub complete: bool,
    pub status: String,
    pub artifact: Option<Value>,
    pub detail: Option<String>,
}

/// Mirrors one `{id, requiredFor, run}` stage object.
pub trait PlanStage {
    fn id(&self) -> &str;
    /// Mirrors `stage.requiredFor ?? 'inventory'`.
    fn required_for(&self) -> &str {
        "inventory"
    }
    fn run(&self, options: &PlanOptions, artifacts: &BTreeMap<String, Value>) -> StageResult;
}

/// Mirrors the `options` object `buildSealedPlan` threads through every
/// stage (`{...options, artifacts}`), restricted to the fields the loop
/// itself (not individual stage bodies) reads.
#[derive(Clone, Debug, Default)]
pub struct PlanOptions {
    pub root: Option<String>,
    pub profile: Option<String>,
    pub claim_level: Option<String>,
    pub binding: Option<Value>,
    pub repository_binding: Option<Value>,
    pub providers: Vec<Value>,
    pub config: Option<Value>,
}

/// Error mirroring `buildSealedPlan`'s `throw new Error(...)` sites.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum BuildPlanError {
    #[error("unknown claim level: {0}")]
    UnknownClaimLevel(String),
    #[error("stage {0} requires id and run")]
    StageMissingIdOrRun(String),
    #[error("duplicate plan stage: {0}")]
    DuplicateStage(String),
    #[error("stage {0} has unknown required claim level")]
    UnknownRequiredClaim(String),
}

/// One gap entry, mirrors `{stage, status, detail}`.
#[derive(Clone, Debug, PartialEq)]
pub struct PlanGap {
    pub stage: String,
    pub status: String,
    pub detail: Option<String>,
}

/// The sealed plan `buildSealedPlan` returns.
#[derive(Clone, Debug)]
pub struct SealedPlan {
    pub schema_version: u32,
    pub kind: String,
    pub root: Option<String>,
    pub profile: String,
    pub requested_claim: String,
    pub binding: Option<Value>,
    pub stages: Vec<(String, String)>, // (id, requiredFor)
    pub artifacts: BTreeMap<String, Value>,
    pub providers: Vec<Value>,
    pub gaps: Vec<PlanGap>,
    pub required_stage_ids: Vec<String>,
    pub claim_gaps: Vec<PlanGap>,
    pub complete_for_requested_claim: bool,
    pub config: Value,
    pub generated_at: String,
    pub plan_digest: String,
}

impl SealedPlan {
    /// Renders the same JSON shape `buildSealedPlan`'s return value has
    /// once JS's `deepFreeze` (a freeze, not a transform) has run.
    pub fn to_json(&self) -> Value {
        json!({
            "schemaVersion": self.schema_version,
            "kind": self.kind,
            "root": self.root,
            "profile": self.profile,
            "requestedClaim": self.requested_claim,
            "binding": self.binding.clone().unwrap_or(Value::Null),
            "stages": self.stages.iter().map(|(id, rf)| json!({"id": id, "requiredFor": rf})).collect::<Vec<_>>(),
            "artifacts": self.artifacts,
            "providers": self.providers,
            "gaps": self.gaps.iter().map(|g| json!({"stage": g.stage, "status": g.status, "detail": g.detail})).collect::<Vec<_>>(),
            "requiredStageIds": self.required_stage_ids,
            "claimGaps": self.claim_gaps.iter().map(|g| json!({"stage": g.stage, "status": g.status, "detail": g.detail})).collect::<Vec<_>>(),
            "completeForRequestedClaim": self.complete_for_requested_claim,
            "config": self.config,
            "generatedAt": self.generated_at,
            "planDigest": self.plan_digest,
        })
    }
}

/// Mirrors `requiredForClaim(stage, requestedClaim)`.
fn required_for_claim(required_for: &str, requested_claim: &str) -> Result<bool, BuildPlanError> {
    if !CLAIMS.contains(&required_for) {
        return Err(BuildPlanError::UnknownRequiredClaim(required_for.to_string()));
    }
    let requested_rank = claim_rank(requested_claim).expect("requested_claim validated by caller");
    let stage_rank = claim_rank(required_for).expect("checked above");
    Ok(requested_rank >= stage_rank)
}

/// Mirrors `buildSealedPlan(options, host)`. `stages` mirrors
/// `options.stages ?? DEFAULT_STAGES` — callers pass their own stage list
/// (there is no ported `DEFAULT_STAGES`, see module docs); `now` mirrors
/// `host.clock.now().toISOString()`.
pub fn build_sealed_plan(
    options: &PlanOptions,
    stages: &[&dyn PlanStage],
    now: &str,
) -> Result<SealedPlan, BuildPlanError> {
    let profile = options.profile.clone().unwrap_or_else(|| "standard".to_string());
    let requested_claim = options.claim_level.clone().unwrap_or_else(|| {
        match profile.as_str() {
            "release" => "release",
            "full" => "product",
            _ => "source",
        }
        .to_string()
    });
    if !CLAIMS.contains(&requested_claim.as_str()) {
        return Err(BuildPlanError::UnknownClaimLevel(requested_claim));
    }

    let mut seen_ids = std::collections::HashSet::new();
    for stage in stages {
        let id = stage.id();
        if id.is_empty() {
            return Err(BuildPlanError::StageMissingIdOrRun(id.to_string()));
        }
        if !seen_ids.insert(id.to_string()) {
            return Err(BuildPlanError::DuplicateStage(id.to_string()));
        }
    }

    let mut artifacts: BTreeMap<String, Value> = BTreeMap::new();
    let mut gaps: Vec<PlanGap> = Vec::new();
    for stage in stages {
        let result = stage.run(options, &artifacts);
        if !result.complete {
            gaps.push(PlanGap {
                stage: stage.id().to_string(),
                status: if result.status.is_empty() { "missing".to_string() } else { result.status.clone() },
                detail: result.detail.clone(),
            });
        }
        if let Some(artifact) = result.artifact {
            artifacts.insert(stage.id().to_string(), artifact);
        }
    }

    let mut required_stage_ids = Vec::new();
    for stage in stages {
        if required_for_claim(stage.required_for(), &requested_claim)? {
            required_stage_ids.push(stage.id().to_string());
        }
    }
    let claim_gaps: Vec<PlanGap> = gaps
        .iter()
        .filter(|g| required_stage_ids.contains(&g.stage))
        .cloned()
        .collect();

    let stage_list: Vec<(String, String)> = stages
        .iter()
        .map(|s| (s.id().to_string(), s.required_for().to_string()))
        .collect();

    let config = options.config.clone().unwrap_or_else(|| json!({}));
    let binding = options.binding.clone().or_else(|| options.repository_binding.clone());

    let mut plan = SealedPlan {
        schema_version: 1,
        kind: "legion-sealed-plan".to_string(),
        root: options.root.clone(),
        profile,
        requested_claim,
        binding,
        stages: stage_list,
        artifacts,
        providers: options.providers.clone(),
        gaps,
        required_stage_ids,
        claim_gaps: claim_gaps.clone(),
        complete_for_requested_claim: claim_gaps.is_empty(),
        config,
        generated_at: now.to_string(),
        plan_digest: String::new(),
    };
    // Mirrors `digest({...plan, generatedAt: undefined, planDigest: undefined})`:
    // both fields are dropped from the digested value.
    let mut digest_value = plan.to_json();
    if let Value::Object(obj) = &mut digest_value {
        obj.remove("generatedAt");
        obj.remove("planDigest");
    }
    plan.plan_digest = digest(&digest_value);
    Ok(plan)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct FixedStage {
        id: &'static str,
        required_for: &'static str,
        result: StageResult,
    }
    impl PlanStage for FixedStage {
        fn id(&self) -> &str {
            self.id
        }
        fn required_for(&self) -> &str {
            self.required_for
        }
        fn run(&self, _options: &PlanOptions, _artifacts: &BTreeMap<String, Value>) -> StageResult {
            self.result.clone()
        }
    }

    #[test]
    fn unknown_claim_level_is_rejected() {
        let options = PlanOptions {
            claim_level: Some("bogus".to_string()),
            ..Default::default()
        };
        let err = build_sealed_plan(&options, &[], "2024-01-01T00:00:00.000Z").unwrap_err();
        assert_eq!(err, BuildPlanError::UnknownClaimLevel("bogus".to_string()));
    }

    #[test]
    fn duplicate_stage_ids_are_rejected() {
        let a = FixedStage { id: "x", required_for: "inventory", result: StageResult { complete: true, status: "pass".into(), artifact: None, detail: None } };
        let b = FixedStage { id: "x", required_for: "inventory", result: StageResult { complete: true, status: "pass".into(), artifact: None, detail: None } };
        let stages: Vec<&dyn PlanStage> = vec![&a, &b];
        let err = build_sealed_plan(&PlanOptions::default(), &stages, "now").unwrap_err();
        assert_eq!(err, BuildPlanError::DuplicateStage("x".to_string()));
    }

    #[test]
    fn complete_stage_produces_no_gap_and_stores_artifact() {
        let stage = FixedStage {
            id: "repository-binding",
            required_for: "inventory",
            result: StageResult { complete: true, status: "pass".into(), artifact: Some(json!({"rev": "abc"})), detail: None },
        };
        let stages: Vec<&dyn PlanStage> = vec![&stage];
        let plan = build_sealed_plan(&PlanOptions::default(), &stages, "now").unwrap();
        assert!(plan.gaps.is_empty());
        assert_eq!(plan.artifacts.get("repository-binding"), Some(&json!({"rev": "abc"})));
        assert!(plan.complete_for_requested_claim);
    }

    #[test]
    fn incomplete_required_stage_produces_claim_gap() {
        let stage = FixedStage {
            id: "component-graph",
            required_for: "source",
            result: StageResult { complete: false, status: "missing".into(), artifact: None, detail: Some("x".into()) },
        };
        let stages: Vec<&dyn PlanStage> = vec![&stage];
        let options = PlanOptions { claim_level: Some("source".to_string()), ..Default::default() };
        let plan = build_sealed_plan(&options, &stages, "now").unwrap();
        assert_eq!(plan.gaps.len(), 1);
        assert_eq!(plan.claim_gaps.len(), 1);
        assert!(!plan.complete_for_requested_claim);
    }

    #[test]
    fn incomplete_stage_above_requested_claim_is_not_a_claim_gap() {
        let stage = FixedStage {
            id: "provider-dag",
            required_for: "runtime",
            result: StageResult { complete: false, status: "missing".into(), artifact: None, detail: None },
        };
        let stages: Vec<&dyn PlanStage> = vec![&stage];
        let options = PlanOptions { claim_level: Some("inventory".to_string()), ..Default::default() };
        let plan = build_sealed_plan(&options, &stages, "now").unwrap();
        assert_eq!(plan.gaps.len(), 1);
        assert!(plan.claim_gaps.is_empty());
        assert!(plan.complete_for_requested_claim);
    }

    #[test]
    fn profile_release_defaults_claim_to_release() {
        let options = PlanOptions { profile: Some("release".to_string()), ..Default::default() };
        let plan = build_sealed_plan(&options, &[], "now").unwrap();
        assert_eq!(plan.requested_claim, "release");
    }

    #[test]
    fn digest_is_stable_for_identical_plans() {
        let options = PlanOptions::default();
        let plan_a = build_sealed_plan(&options, &[], "same-time").unwrap();
        let plan_b = build_sealed_plan(&options, &[], "same-time").unwrap();
        assert_eq!(plan_a.plan_digest, plan_b.plan_digest);
    }

    #[test]
    fn digest_ignores_generated_at() {
        let options = PlanOptions::default();
        let plan_a = build_sealed_plan(&options, &[], "time-a").unwrap();
        let plan_b = build_sealed_plan(&options, &[], "time-b").unwrap();
        assert_eq!(plan_a.plan_digest, plan_b.plan_digest);
    }
}
