//! Rust port of the pure state-machine core of `skills/seo/scripts/search_ops.py`.
//!
//! `search_ops.py` persists intervention/run state as JSON on disk. The load/save-to-disk
//! IO is not ported; what is ported verbatim is the schema-v1→v2 migration and the
//! `start`/`deploy`/`verify`/`outcome`/`run`/`brief` state transitions, which are pure
//! functions over an in-memory state value. A host wrapper is responsible for reading the
//! JSON file into `SearchOpsState`, calling these functions, and writing the result back.

use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const SCHEMA_VERSION: u32 = 2;

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct Deployment {
    pub recorded_at: String,
    pub identity: String,
    pub authorized_capability: String,
    pub idempotency_key: String,
    pub effect_receipt: String,
    pub evidence: Option<String>,
    pub rollback: String,
    /// Only present after a v1→v2 migration backfill.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verified: Option<bool>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct Verification {
    pub recorded_at: String,
    pub result: String,
    pub evidence: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct Outcome {
    pub recorded_at: String,
    pub verdict: String,
    pub metrics: Value,
    pub evidence: Option<String>,
    pub confounders: Vec<String>,
    pub causal_strength: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct Evaluation {
    pub earliest_date: String,
    pub maturity_condition: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct Intervention {
    pub id: String,
    pub created_at: String,
    pub target: String,
    pub query_or_topic: Option<String>,
    pub hypothesis: String,
    pub proposed_action: String,
    pub primary_metric: String,
    pub evaluation: Evaluation,
    pub guardrails: Vec<String>,
    pub baseline: Value,
    pub status: String,
    pub deployment: Option<Deployment>,
    pub verification: Option<Verification>,
    pub outcomes: Vec<Outcome>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct Run {
    pub recorded_at: String,
    pub cadence: String,
    pub property: String,
    pub market: Option<String>,
    pub primary_action: Option<String>,
    pub critical: Vec<String>,
    pub watch: Vec<String>,
    pub evidence: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct SearchOpsState {
    pub schema_version: u32,
    pub interventions: Vec<Intervention>,
    pub runs: Vec<Run>,
}

#[derive(Debug, Clone, PartialEq, thiserror::Error)]
pub enum SearchOpsError {
    #[error("unsupported state schema: {0}")]
    UnsupportedSchema(u32),
    #[error("intervention already exists: {0}")]
    AlreadyExists(String),
    #[error("unknown intervention: {0}")]
    UnknownIntervention(String),
    #[error("cannot deploy intervention in state {0}")]
    CannotDeploy(String),
    #[error("verification requires a deployed intervention")]
    VerificationRequiresDeployed,
    #[error("outcome cannot be recorded before deployment")]
    OutcomeRequiresDeployment,
}

/// Port of `load_state`'s schema v1 → v2 migration, applied to a state value already
/// parsed from JSON (whatever its `schema_version`). Returns an error for any schema other
/// than 1 or 2, matching `raise SystemExit(f'unsupported state schema: {version}')`.
pub fn migrate(mut state: SearchOpsState) -> Result<SearchOpsState, SearchOpsError> {
    if state.schema_version == 1 {
        state.schema_version = SCHEMA_VERSION;
        for row in state.interventions.iter_mut() {
            match row.status.as_str() {
                "planned" => row.status = "proposed".to_string(),
                "deployed_verified" | "deployed_unverified" => {
                    let verified = row.status == "deployed_verified";
                    row.status = if verified { "verified" } else { "deployed" }.to_string();
                    if let Some(dep) = row.deployment.as_mut() {
                        dep.verified = Some(verified);
                    }
                }
                _ => {}
            }
        }
        return Ok(state);
    }
    if state.schema_version != SCHEMA_VERSION {
        return Err(SearchOpsError::UnsupportedSchema(state.schema_version));
    }
    Ok(state)
}

fn find_mut<'a>(
    state: &'a mut SearchOpsState,
    id: &str,
) -> Result<&'a mut Intervention, SearchOpsError> {
    state
        .interventions
        .iter_mut()
        .find(|x| x.id == id)
        .ok_or_else(|| SearchOpsError::UnknownIntervention(id.to_string()))
}

/// Port of `cmd_start`.
pub fn start(
    state: &mut SearchOpsState,
    intervention: Intervention,
) -> Result<(), SearchOpsError> {
    if state.interventions.iter().any(|x| x.id == intervention.id) {
        return Err(SearchOpsError::AlreadyExists(intervention.id));
    }
    let mut row = intervention;
    row.status = "proposed".to_string();
    row.deployment = None;
    row.verification = None;
    row.outcomes = Vec::new();
    state.interventions.push(row);
    Ok(())
}

/// Port of `cmd_deploy`.
pub fn deploy(
    state: &mut SearchOpsState,
    id: &str,
    deployment: Deployment,
) -> Result<(), SearchOpsError> {
    let row = find_mut(state, id)?;
    if row.status != "proposed" && row.status != "deployed" {
        return Err(SearchOpsError::CannotDeploy(row.status.clone()));
    }
    row.status = "deployed".to_string();
    row.deployment = Some(deployment);
    Ok(())
}

/// Port of `cmd_verify`.
pub fn verify(
    state: &mut SearchOpsState,
    id: &str,
    result: &str,
    evidence: String,
    recorded_at: String,
) -> Result<(), SearchOpsError> {
    let row = find_mut(state, id)?;
    if row.status != "deployed" && row.status != "verified" {
        return Err(SearchOpsError::VerificationRequiresDeployed);
    }
    row.verification = Some(Verification {
        recorded_at,
        result: result.to_string(),
        evidence,
    });
    row.status = if result == "pass" { "verified" } else { "deployed" }.to_string();
    Ok(())
}

/// Port of `cmd_outcome`.
pub fn outcome(
    state: &mut SearchOpsState,
    id: &str,
    outcome: Outcome,
) -> Result<(), SearchOpsError> {
    let row = find_mut(state, id)?;
    if row.deployment.is_none() {
        return Err(SearchOpsError::OutcomeRequiresDeployment);
    }
    let is_immature = outcome.verdict == "immature";
    row.outcomes.push(outcome);
    if !is_immature {
        row.status = "outcome_recorded".to_string();
    }
    Ok(())
}

/// Port of `cmd_run`.
pub fn run(state: &mut SearchOpsState, run: Run) {
    state.runs.push(run);
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct BriefOpenIntervention {
    pub id: String,
    pub target: String,
    pub status: String,
    pub evaluation: Evaluation,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct Brief {
    pub run: Run,
    pub open_interventions: Vec<BriefOpenIntervention>,
}

/// Port of `cmd_brief`. Returns `None` for `{'status': 'no_runs'}`.
pub fn brief(state: &SearchOpsState) -> Option<Brief> {
    let run = state.runs.last()?.clone();
    let open_interventions = state
        .interventions
        .iter()
        .filter(|x| x.status != "outcome_recorded" && x.status != "cancelled")
        .map(|x| BriefOpenIntervention {
            id: x.id.clone(),
            target: x.target.clone(),
            status: x.status.clone(),
            evaluation: x.evaluation.clone(),
        })
        .collect();
    Some(Brief {
        run,
        open_interventions,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn iv(id: &str) -> Intervention {
        Intervention {
            id: id.to_string(),
            target: "https://example.com/page".to_string(),
            hypothesis: "h".to_string(),
            proposed_action: "a".to_string(),
            primary_metric: "m".to_string(),
            evaluation: Evaluation {
                earliest_date: "2026-02-01".to_string(),
                maturity_condition: None,
            },
            ..Default::default()
        }
    }

    #[test]
    fn migrate_v1_maps_legacy_statuses() {
        let mut state = SearchOpsState {
            schema_version: 1,
            interventions: vec![
                Intervention {
                    status: "planned".to_string(),
                    ..iv("a")
                },
                Intervention {
                    status: "deployed_verified".to_string(),
                    deployment: Some(Deployment::default()),
                    ..iv("b")
                },
            ],
            runs: vec![],
        };
        state = migrate(state).unwrap();
        assert_eq!(state.schema_version, SCHEMA_VERSION);
        assert_eq!(state.interventions[0].status, "proposed");
        assert_eq!(state.interventions[1].status, "verified");
        assert_eq!(state.interventions[1].deployment.as_ref().unwrap().verified, Some(true));
    }

    #[test]
    fn migrate_rejects_unknown_schema() {
        let state = SearchOpsState {
            schema_version: 3,
            ..Default::default()
        };
        assert_eq!(
            migrate(state).unwrap_err(),
            SearchOpsError::UnsupportedSchema(3)
        );
    }

    #[test]
    fn full_lifecycle_start_deploy_verify_outcome() {
        let mut state = SearchOpsState {
            schema_version: SCHEMA_VERSION,
            ..Default::default()
        };
        start(&mut state, iv("x1")).unwrap();
        assert_eq!(
            start(&mut state, iv("x1")).unwrap_err(),
            SearchOpsError::AlreadyExists("x1".to_string())
        );

        deploy(
            &mut state,
            "x1",
            Deployment {
                recorded_at: "t".into(),
                identity: "op".into(),
                authorized_capability: "cap".into(),
                idempotency_key: "k1".into(),
                effect_receipt: "r1".into(),
                evidence: None,
                rollback: "revert".into(),
                verified: None,
            },
        )
        .unwrap();
        assert_eq!(state.interventions[0].status, "deployed");

        verify(&mut state, "x1", "pass", "ev".into(), "t2".into()).unwrap();
        assert_eq!(state.interventions[0].status, "verified");

        outcome(
            &mut state,
            "x1",
            Outcome {
                recorded_at: "t3".into(),
                verdict: "improved".into(),
                metrics: serde_json::json!({}),
                evidence: None,
                confounders: vec![],
                causal_strength: "observational".into(),
            },
        )
        .unwrap();
        assert_eq!(state.interventions[0].status, "outcome_recorded");

        // No runs recorded yet: brief is None until `run()` is called.
        assert!(brief(&state).is_none());

        run(
            &mut state,
            Run {
                recorded_at: "t4".into(),
                cadence: "weekly".into(),
                property: "example.com".into(),
                ..Default::default()
            },
        );
        // The single intervention is already outcome_recorded, so it is not "open".
        assert!(brief(&state).unwrap().open_interventions.is_empty());
    }

    #[test]
    fn outcome_before_deployment_errors() {
        let mut state = SearchOpsState::default();
        start(&mut state, iv("y1")).unwrap();
        let err = outcome(
            &mut state,
            "y1",
            Outcome {
                verdict: "improved".into(),
                metrics: serde_json::json!({}),
                causal_strength: "observational".into(),
                ..Default::default()
            },
        )
        .unwrap_err();
        assert_eq!(err, SearchOpsError::OutcomeRequiresDeployment);
    }

    #[test]
    fn brief_with_no_runs_is_none() {
        assert!(brief(&SearchOpsState::default()).is_none());
    }
}
