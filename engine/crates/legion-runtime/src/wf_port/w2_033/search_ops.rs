//! Rust port of `skills/seo/scripts/search_ops.py` (packet `r42` closes the
//! load/save-to-disk and CLI gap this module used to defer).
//!
//! `search_ops.py` persists intervention/run state as JSON on disk. The schema-v1→v2
//! migration and the `start`/`deploy`/`verify`/`outcome`/`run`/`brief` state transitions
//! are pure functions over an in-memory state value, ported verbatim below.
//! [`load_state`]/[`save_state`] port the atomic-rename-on-write persistence (matching
//! `save_state`'s `tmp.replace(path)`), and [`run_cli`] ports the `argparse` CLI dispatch
//! (`main()`), including which subcommands persist state (every one but `brief`).

use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

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
    #[error("{0}")]
    Io(String),
}

pub const DEFAULT_STATE_PATH: &str = ".legion/seo/interventions/search-ops.json";

/// Same dependency-free UTC formatter used by `rank_tracker::now` (pure integer
/// civil-from-days conversion; no external crate).
pub fn utc_now() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    let (hh, mm, ss) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{y:04}-{m:02}-{d:02}T{hh:02}:{mm:02}:{ss:02}Z")
}

/// Port of `load_state(path)`: returns a fresh empty state (schema v2) for a missing file,
/// otherwise parses and migrates it.
pub fn load_state(path: &Path) -> Result<SearchOpsState, SearchOpsError> {
    if !path.exists() {
        return Ok(SearchOpsState {
            schema_version: SCHEMA_VERSION,
            interventions: Vec::new(),
            runs: Vec::new(),
        });
    }
    let text = std::fs::read_to_string(path).map_err(|e| SearchOpsError::Io(e.to_string()))?;
    let state: SearchOpsState =
        serde_json::from_str(&text).map_err(|e| SearchOpsError::Io(e.to_string()))?;
    migrate(state)
}

/// Port of `save_state(path, state)`: write-to-temp-then-rename, matching
/// `tmp.write_text(...); tmp.replace(path)` (atomic on POSIX and Windows alike).
pub fn save_state(path: &Path, state: &SearchOpsState) -> Result<(), SearchOpsError> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| SearchOpsError::Io(e.to_string()))?;
    }
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(".tmp");
    let tmp_path = PathBuf::from(tmp);
    let text = serde_json::to_string_pretty(state).map_err(|e| SearchOpsError::Io(e.to_string()))? + "\n";
    std::fs::write(&tmp_path, text).map_err(|e| SearchOpsError::Io(e.to_string()))?;
    std::fs::rename(&tmp_path, path).map_err(|e| SearchOpsError::Io(e.to_string()))?;
    Ok(())
}

/// A parsed CLI invocation, mirroring `search_ops.py`'s `argparse` subcommands.
pub enum Command {
    Start(Intervention),
    Deploy { id: String, deployment: Deployment },
    Verify { id: String, result: String, evidence: String },
    Outcome { id: String, outcome: Outcome },
    Run(Run),
    Brief,
}

/// Port of `main()`: loads state from `path` (or [`DEFAULT_STATE_PATH`]), dispatches the
/// command, saves state back for every command but `brief`, and returns
/// `(exit_code, pretty_json)` — `main()` always returns `0` on success (errors are
/// `SystemExit(message)`, i.e. exit code 1 with the message on stderr in Python's
/// convention, mirrored here as `Err`).
pub fn run_cli(path: &Path, command: Command) -> Result<(i32, String), SearchOpsError> {
    let mut state = load_state(path)?;
    let now = utc_now();

    if let Command::Brief = command {
        let out = brief(&state);
        let text = match &out {
            Some(b) => serde_json::to_string_pretty(b).map_err(|e| SearchOpsError::Io(e.to_string()))?,
            None => serde_json::to_string_pretty(&serde_json::json!({"status": "no_runs"}))
                .map_err(|e| SearchOpsError::Io(e.to_string()))?,
        };
        return Ok((0, text));
    }

    let result_json: Value = match command {
        Command::Start(mut intervention) => {
            intervention.created_at = now;
            let id = intervention.id.clone();
            start(&mut state, intervention)?;
            let row = state.interventions.iter().find(|x| x.id == id).unwrap();
            serde_json::to_value(row).map_err(|e| SearchOpsError::Io(e.to_string()))?
        }
        Command::Deploy { id, mut deployment } => {
            deployment.recorded_at = now;
            deploy(&mut state, &id, deployment)?;
            let row = state.interventions.iter().find(|x| x.id == id).unwrap();
            serde_json::to_value(row).map_err(|e| SearchOpsError::Io(e.to_string()))?
        }
        Command::Verify { id, result, evidence } => {
            verify(&mut state, &id, &result, evidence, now)?;
            let row = state.interventions.iter().find(|x| x.id == id).unwrap();
            serde_json::to_value(&row.verification).map_err(|e| SearchOpsError::Io(e.to_string()))?
        }
        Command::Outcome { id, outcome: mut out } => {
            out.recorded_at = now;
            outcome(&mut state, &id, out.clone())?;
            serde_json::to_value(&out).map_err(|e| SearchOpsError::Io(e.to_string()))?
        }
        Command::Run(mut r) => {
            r.recorded_at = now;
            let value = serde_json::to_value(&r).map_err(|e| SearchOpsError::Io(e.to_string()))?;
            crate::wf_port::w2_033::search_ops::run(&mut state, r);
            value
        }
        Command::Brief => unreachable!("handled above"),
    };

    save_state(path, &state)?;
    let text = serde_json::to_string_pretty(&result_json).map_err(|e| SearchOpsError::Io(e.to_string()))?;
    Ok((0, text))
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

/// Minimal option-scanner shared by the `run_argv` subcommand parsers below: walks
/// `args` from `idx`, collecting `--flag value` pairs (last one wins, matching
/// argparse) and `--flag` used with `action='append'` into a `Vec`.
struct ArgScanner<'a> {
    args: &'a [String],
    idx: usize,
}

impl<'a> ArgScanner<'a> {
    fn new(args: &'a [String], idx: usize) -> Self {
        Self { args, idx }
    }

    fn next_flag(&mut self) -> Option<(&'a str, Option<&'a str>)> {
        let flag = self.args.get(self.idx)?.as_str();
        self.idx += 1;
        let value = self.args.get(self.idx).map(|s| s.as_str());
        Some((flag, value))
    }

    fn take_value(&mut self) -> Option<String> {
        let v = self.args.get(self.idx).cloned();
        if v.is_some() {
            self.idx += 1;
        }
        v
    }
}

/// Port of `main()`'s `argparse` surface for `search_ops.py`: `--state` global flag,
/// then one of `start`/`deploy`/`verify`/`outcome`/`run`/`brief` with that subcommand's
/// flags. Prints the same pretty-JSON `run_cli` produces and returns the same exit
/// code (`0` on success, `1` on any parse or state error).
pub fn run_argv(args: &[String]) -> i32 {
    let mut state_path = PathBuf::from(DEFAULT_STATE_PATH);
    let mut idx = 0;
    while idx < args.len() {
        if args[idx] == "--state" {
            match args.get(idx + 1) {
                Some(v) => {
                    state_path = PathBuf::from(v);
                    idx += 2;
                }
                None => {
                    eprintln!("Error: --state requires a value");
                    return 1;
                }
            }
        } else {
            break;
        }
    }
    let Some(sub) = args.get(idx) else {
        eprintln!("Error: a command is required");
        return 1;
    };
    idx += 1;
    let rest = &args[idx..];

    macro_rules! err {
        ($msg:expr) => {{
            eprintln!("Error: {}", $msg);
            return 1;
        }};
    }

    let command = match sub.as_str() {
        "brief" => Command::Brief,
        "start" => {
            let mut id = None;
            let mut target = None;
            let mut query_or_topic = None;
            let mut hypothesis = None;
            let mut action = None;
            let mut metric = None;
            let mut evaluate_after = None;
            let mut maturity_condition = None;
            let mut guardrails = Vec::new();
            let mut baseline = Value::Null;
            let mut scan = ArgScanner::new(rest, 0);
            while let Some((flag, _)) = scan.next_flag() {
                match flag {
                    "--id" => id = scan.take_value(),
                    "--target" => target = scan.take_value(),
                    "--query-or-topic" => query_or_topic = scan.take_value(),
                    "--hypothesis" => hypothesis = scan.take_value(),
                    "--action" => action = scan.take_value(),
                    "--metric" => metric = scan.take_value(),
                    "--evaluate-after" => evaluate_after = scan.take_value(),
                    "--maturity-condition" => maturity_condition = scan.take_value(),
                    "--guardrail" => {
                        if let Some(v) = scan.take_value() {
                            guardrails.push(v);
                        }
                    }
                    "--baseline" => {
                        if let Some(v) = scan.take_value() {
                            baseline = serde_json::from_str(&v).unwrap_or(Value::Null);
                        }
                    }
                    other => err!(format!("unrecognized argument: {other}")),
                }
            }
            let (Some(id), Some(target), Some(hypothesis), Some(action), Some(metric), Some(evaluate_after)) =
                (id, target, hypothesis, action, metric, evaluate_after)
            else {
                err!("start requires --id --target --hypothesis --action --metric --evaluate-after");
            };
            Command::Start(Intervention {
                id,
                target,
                query_or_topic,
                hypothesis,
                proposed_action: action,
                primary_metric: metric,
                evaluation: Evaluation {
                    earliest_date: evaluate_after,
                    maturity_condition,
                },
                guardrails,
                baseline,
                status: "proposed".to_string(),
                ..Default::default()
            })
        }
        "deploy" => {
            let mut id = None;
            let mut identity = None;
            let mut authorized_capability = None;
            let mut idempotency_key = None;
            let mut effect_receipt = None;
            let mut rollback = None;
            let mut evidence = None;
            let mut scan = ArgScanner::new(rest, 0);
            while let Some((flag, _)) = scan.next_flag() {
                match flag {
                    "--id" => id = scan.take_value(),
                    "--identity" => identity = scan.take_value(),
                    "--authorized-capability" => authorized_capability = scan.take_value(),
                    "--idempotency-key" => idempotency_key = scan.take_value(),
                    "--effect-receipt" => effect_receipt = scan.take_value(),
                    "--rollback" => rollback = scan.take_value(),
                    "--evidence" => evidence = scan.take_value(),
                    other => err!(format!("unrecognized argument: {other}")),
                }
            }
            let (Some(id), Some(identity), Some(authorized_capability), Some(idempotency_key), Some(effect_receipt), Some(rollback)) =
                (id, identity, authorized_capability, idempotency_key, effect_receipt, rollback)
            else {
                err!("deploy requires --id --identity --authorized-capability --idempotency-key --effect-receipt --rollback");
            };
            Command::Deploy {
                id,
                deployment: Deployment {
                    identity,
                    authorized_capability,
                    idempotency_key,
                    effect_receipt,
                    rollback,
                    evidence,
                    ..Default::default()
                },
            }
        }
        "verify" => {
            let mut id = None;
            let mut result = None;
            let mut evidence = None;
            let mut scan = ArgScanner::new(rest, 0);
            while let Some((flag, _)) = scan.next_flag() {
                match flag {
                    "--id" => id = scan.take_value(),
                    "--result" => result = scan.take_value(),
                    "--evidence" => evidence = scan.take_value(),
                    other => err!(format!("unrecognized argument: {other}")),
                }
            }
            let (Some(id), Some(result), Some(evidence)) = (id, result, evidence) else {
                err!("verify requires --id --result --evidence");
            };
            if result != "pass" && result != "fail" {
                err!("--result must be pass or fail");
            }
            Command::Verify { id, result, evidence }
        }
        "outcome" => {
            let mut id = None;
            let mut verdict = None;
            let mut metrics = Value::Null;
            let mut evidence = None;
            let mut confounders = Vec::new();
            let mut causal_strength = "observational".to_string();
            let mut scan = ArgScanner::new(rest, 0);
            while let Some((flag, _)) = scan.next_flag() {
                match flag {
                    "--id" => id = scan.take_value(),
                    "--verdict" => verdict = scan.take_value(),
                    "--metrics" => {
                        if let Some(v) = scan.take_value() {
                            metrics = serde_json::from_str(&v).unwrap_or(Value::Null);
                        }
                    }
                    "--evidence" => evidence = scan.take_value(),
                    "--confounder" => {
                        if let Some(v) = scan.take_value() {
                            confounders.push(v);
                        }
                    }
                    "--causal-strength" => {
                        if let Some(v) = scan.take_value() {
                            causal_strength = v;
                        }
                    }
                    other => err!(format!("unrecognized argument: {other}")),
                }
            }
            let (Some(id), Some(verdict)) = (id, verdict) else {
                err!("outcome requires --id --verdict");
            };
            Command::Outcome {
                id,
                outcome: Outcome {
                    verdict,
                    metrics,
                    evidence,
                    confounders,
                    causal_strength,
                    ..Default::default()
                },
            }
        }
        "run" => {
            let mut cadence = None;
            let mut property = None;
            let mut market = None;
            let mut primary_action = None;
            let mut critical = Vec::new();
            let mut watch = Vec::new();
            let mut evidence = Vec::new();
            let mut scan = ArgScanner::new(rest, 0);
            while let Some((flag, _)) = scan.next_flag() {
                match flag {
                    "--cadence" => cadence = scan.take_value(),
                    "--property" => property = scan.take_value(),
                    "--market" => market = scan.take_value(),
                    "--primary-action" => primary_action = scan.take_value(),
                    "--critical" => {
                        if let Some(v) = scan.take_value() {
                            critical.push(v);
                        }
                    }
                    "--watch" => {
                        if let Some(v) = scan.take_value() {
                            watch.push(v);
                        }
                    }
                    "--evidence" => {
                        if let Some(v) = scan.take_value() {
                            evidence.push(v);
                        }
                    }
                    other => err!(format!("unrecognized argument: {other}")),
                }
            }
            let (Some(cadence), Some(property)) = (cadence, property) else {
                err!("run requires --cadence --property");
            };
            Command::Run(Run {
                cadence,
                property,
                market,
                primary_action,
                critical,
                watch,
                evidence,
                ..Default::default()
            })
        }
        other => err!(format!("unknown command: {other}")),
    };

    match run_cli(&state_path, command) {
        Ok((code, text)) => {
            println!("{text}");
            code
        }
        Err(e) => {
            eprintln!("Error: {e}");
            1
        }
    }
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

    static TEST_COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    fn temp_state_path() -> PathBuf {
        let id = TEST_COUNTER.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!("r42-search-ops-{}-{}", std::process::id(), id));
        std::fs::create_dir_all(&dir).unwrap();
        dir.join("search-ops.json")
    }

    #[test]
    fn load_state_missing_file_returns_fresh_v2() {
        let path = temp_state_path();
        let state = load_state(&path).unwrap();
        assert_eq!(state.schema_version, SCHEMA_VERSION);
        assert!(state.interventions.is_empty());
    }

    #[test]
    fn save_then_load_round_trips() {
        let path = temp_state_path();
        let mut state = SearchOpsState {
            schema_version: SCHEMA_VERSION,
            ..Default::default()
        };
        start(&mut state, iv("z1")).unwrap();
        save_state(&path, &state).unwrap();
        let reloaded = load_state(&path).unwrap();
        assert_eq!(reloaded.interventions.len(), 1);
        assert_eq!(reloaded.interventions[0].id, "z1");
    }

    #[test]
    fn run_cli_start_then_deploy_persist_across_calls() {
        let path = temp_state_path();
        let (code, out) = run_cli(&path, Command::Start(iv("cli1"))).unwrap();
        assert_eq!(code, 0);
        assert!(out.contains("\"proposed\""));

        let (code, out) = run_cli(
            &path,
            Command::Deploy {
                id: "cli1".into(),
                deployment: Deployment {
                    identity: "op".into(),
                    authorized_capability: "cap".into(),
                    idempotency_key: "k".into(),
                    effect_receipt: "r".into(),
                    rollback: "revert".into(),
                    ..Default::default()
                },
            },
        )
        .unwrap();
        assert_eq!(code, 0);
        assert!(out.contains("\"deployed\""));

        // State persisted to disk between calls, matching the Python's load/save-per-invocation.
        let state = load_state(&path).unwrap();
        assert_eq!(state.interventions[0].status, "deployed");
    }

    #[test]
    fn run_cli_brief_does_not_persist_state() {
        let path = temp_state_path();
        let (code, out) = run_cli(&path, Command::Brief).unwrap();
        assert_eq!(code, 0);
        assert!(out.contains("no_runs"));
        assert!(!path.exists());
    }

    #[test]
    fn run_cli_unknown_intervention_errors() {
        let path = temp_state_path();
        let err = run_cli(
            &path,
            Command::Verify {
                id: "missing".into(),
                result: "pass".into(),
                evidence: "ev".into(),
            },
        )
        .unwrap_err();
        assert_eq!(err, SearchOpsError::UnknownIntervention("missing".into()));
    }

    #[test]
    fn run_argv_start_deploy_verify_outcome_brief() {
        let path = temp_state_path();
        let path_str = path.to_string_lossy().to_string();
        let code = run_argv(&[
            "--state".into(), path_str.clone(), "start".into(),
            "--id".into(), "argv1".into(), "--target".into(), "/page".into(),
            "--hypothesis".into(), "h".into(), "--action".into(), "a".into(),
            "--metric".into(), "m".into(), "--evaluate-after".into(), "2026-01-01".into(),
        ]);
        assert_eq!(code, 0);

        let code = run_argv(&[
            "--state".into(), path_str.clone(), "deploy".into(),
            "--id".into(), "argv1".into(), "--identity".into(), "op".into(),
            "--authorized-capability".into(), "cap".into(), "--idempotency-key".into(), "k".into(),
            "--effect-receipt".into(), "r".into(), "--rollback".into(), "revert".into(),
        ]);
        assert_eq!(code, 0);

        let code = run_argv(&[
            "--state".into(), path_str.clone(), "verify".into(),
            "--id".into(), "argv1".into(), "--result".into(), "pass".into(), "--evidence".into(), "ev".into(),
        ]);
        assert_eq!(code, 0);

        let code = run_argv(&[
            "--state".into(), path_str.clone(), "outcome".into(),
            "--id".into(), "argv1".into(), "--verdict".into(), "win".into(),
        ]);
        assert_eq!(code, 0);

        let code = run_argv(&["--state".into(), path_str, "brief".into()]);
        assert_eq!(code, 0);
    }

    #[test]
    fn run_argv_missing_command_errors() {
        assert_eq!(run_argv(&[]), 1);
    }

    #[test]
    fn run_argv_start_missing_required_errors() {
        let path = temp_state_path();
        let code = run_argv(&["--state".into(), path.to_string_lossy().into_owned(), "start".into()]);
        assert_eq!(code, 1);
    }
}
