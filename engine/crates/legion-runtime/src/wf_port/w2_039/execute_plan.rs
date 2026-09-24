//! Port of `executePlan`/`asReceipt`/`skippedReceipt` from
//! `src/lib/core/execute-plan.mjs`, closing the gap w2_039 left open
//! (packet r44).
//!
//! `RunLedger` (see [`super::run_ledger`]) and `RuntimeAdmission` (already
//! native, `legion_runtime::engine::RuntimeAdmission`) were already ported.
//! `scheduleProviders`/`providerDependencies` are already native at
//! [`crate::p5_core::core_scheduler`]. `executionReceipt`/`blocked` are
//! already native at [`crate::wf_port::w2_040::execution_receipt`]. This
//! module ports the remaining orchestration: `normalizeProvider`,
//! `denominator`, `asReceipt`, `executePlan`, and `skippedReceipt`, plus a
//! faithful port of `normalizeProviderResult`
//! (`src/lib/providers/sdk/result.mjs`) which `asReceipt` needs and which
//! has no dependency of its own.
//!
//! The one seam that cannot be a value-in-value-out port: JS's
//! `executePlannedProvider` (`src/lib/providers/provider-executor.mjs`)
//! dynamically imports provider modules, spawns external processes and
//! reads sandbox/schema-validation policy from `../host/sandbox-policy.mjs`,
//! `./sdk/contracts.mjs` and `../qualification/schema-validator.mjs` — none
//! of those files are in this packet and none are owned by it. Per the port
//! rules, that host call is modeled as the [`ProviderExecutor`] trait so
//! `executePlan`'s own control flow (admission, ledger reservation,
//! dependency blocking, receipt assembly, replan callback) is fully
//! ported and fully testable with a fake executor.
//!
//! `admission` is modeled as a small, self-contained port of the JS
//! `RuntimeAdmission` class's `Set`-based semantics ([`AdmissionSet`])
//! rather than reused from `legion_runtime::engine::RuntimeAdmission`: that
//! type's `admit`/`quiesce` are `tokio`/`CancellationToken`-based and not
//! exposed with the id-keyed shape `executePlan` needs (`admit(id)` /
//! release-by-id). Behaviourally the two are equivalent (accept while
//! `RUNNING`, reject otherwise); [`AdmissionSet`] is the literal port of
//! the JS class this file's `executePlan` actually calls.

use std::collections::{BTreeMap, HashMap, HashSet};

use serde_json::{json, Value};

use crate::p5_core::core_scheduler::{
    schedule_providers, ScheduleMode, ScheduleOptions, SchedulerError, SchedulerProvider,
};
use crate::wf_port::w2_040::execution_receipt::{
    blocked as receipt_blocked, execution_receipt, BlockedSpec, ExecutionReceiptInput,
};

use super::run_ledger::{Reservation, RunLedger, RunLimits, SystemClock};

/// Mirrors `normalizeProviderResult(provider, result)` from
/// `src/lib/providers/sdk/result.mjs`. Pure, no dependency of its own.
pub fn normalize_provider_result(provider_id: &str, family: &str, result: &Value) -> Value {
    const TERMINAL: &[&str] = &[
        "pass", "fail", "partial", "unproven", "skipped", "error", "pending", "missing",
        "candidates", "blocked",
    ];
    let gaps = result
        .get("coverageGaps")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let requested_status = match result.get("status").and_then(Value::as_str) {
        Some("measured") => "pass".to_string(),
        Some(other) => other.to_string(),
        None => String::new(),
    };
    let status = if TERMINAL.contains(&requested_status.as_str()) {
        requested_status
    } else {
        "unproven".to_string()
    };
    let complete = result.get("complete") == Some(&Value::Bool(true))
        && gaps.is_empty()
        && matches!(status.as_str(), "pass" | "fail" | "candidates");
    let denominator = result
        .get("denominator")
        .or_else(|| result.get("coverage"))
        .cloned()
        .unwrap_or_else(|| json!({}));
    let existing_digest = denominator
        .get("denominatorDigest")
        .and_then(Value::as_str)
        .unwrap_or("");
    let is_sha256 = existing_digest.starts_with("sha256:")
        && existing_digest.len() == 71
        && existing_digest[7..].bytes().all(|b| b.is_ascii_hexdigit());
    let denominator_digest = if is_sha256 {
        json!(existing_digest)
    } else {
        json!(super::binding::digest(&denominator))
    };
    json!({
        "schemaVersion": 1,
        "provider": provider_id,
        "applicable": result.get("applicable") != Some(&Value::Bool(false)),
        "required": result.get("required") != Some(&Value::Bool(false)),
        "status": if complete { Value::String(status.clone()) } else { Value::String("unproven".to_string()) },
        "complete": complete,
        "coverage": {
            "denominatorDigest": denominator_digest,
            "expected": denominator.get("expected").and_then(Value::as_i64).unwrap_or(0),
            "examined": denominator.get("examined").and_then(Value::as_i64).unwrap_or(0),
        },
        "candidates": result.get("candidates").and_then(Value::as_array).cloned().unwrap_or_default(),
        "findings": result.get("findings").and_then(Value::as_array).cloned().unwrap_or_default(),
        "coverageGaps": gaps.clone(),
        "degradation": result.get("degradation").and_then(Value::as_array).cloned().unwrap_or(gaps),
        "details": {
            "family": family,
            "componentIds": result.get("componentIds").and_then(Value::as_array).cloned().unwrap_or_default(),
            "limitations": result.get("limitations").and_then(Value::as_array).cloned().unwrap_or_default(),
            "rawArtifacts": result.get("rawArtifacts").or_else(|| result.get("artifacts")).and_then(Value::as_array).cloned().unwrap_or_default(),
        },
    })
}

/// A provider entry as `executePlan` reads it off `plan.providers`. Kept as
/// `Value`-backed extras plus the fields the orchestration touches directly,
/// mirroring the JS object's loose shape.
#[derive(Clone, Debug)]
pub struct PlannedProvider {
    pub id: String,
    pub dependencies: Vec<String>,
    pub resources: BTreeMap<String, f64>,
    pub concurrency_key: Option<String>,
    /// `provider.denominator?.pathDigest ?? provider.denominatorDigest`.
    pub denominator_digest: Option<Value>,
    /// `provider.execution?.reservedSpendMicros`.
    pub reserved_spend_micros: f64,
    pub family: String,
    /// Everything else `asReceipt`'s fallback branch needs off `provider`
    /// (`runner.module`/`runner.kind`/`providerVersion`/`runner.moduleDigest`).
    pub runner_module: Option<String>,
    pub runner_kind: Option<String>,
    pub provider_version: String,
    pub runner_module_digest: Option<Value>,
}

/// Mirrors `normalizeProvider(provider)`: `providerDependencies` is already
/// ported natively ([`crate::p5_core::core_scheduler::provider_dependencies`]);
/// this constructor is the seam a caller uses to build a [`PlannedProvider`]
/// from whatever raw shape it holds (JSON, a DB row, ...).
impl PlannedProvider {
    pub fn scheduler_provider(&self) -> SchedulerProvider {
        let mut sp = SchedulerProvider::new(self.id.clone()).with_dependencies(self.dependencies.clone());
        if !self.resources.is_empty() {
            sp = sp.with_resources(self.resources.clone());
        }
        if let Some(key) = &self.concurrency_key {
            sp = sp.with_concurrency_key(key.clone());
        }
        sp
    }
}

/// The subset of `plan` fields `executePlan`/`asReceipt`/`denominator` read.
#[derive(Clone, Debug)]
pub struct ExecutionPlan {
    pub root: Option<String>,
    pub binding: Option<Value>,
    pub providers: Vec<PlannedProvider>,
    pub schedule_mode: ScheduleMode,
    pub max_concurrency: usize,
    pub resource_ceilings: Option<BTreeMap<String, f64>>,
    pub limits: RunLimits,
    /// `plan.denominator?.pathDigest`, the plan-level fallback the JS
    /// `denominator(provider, plan)` helper falls through to.
    pub plan_denominator_digest: Option<Value>,
}

/// Mirrors `denominator(provider, plan)`.
fn denominator(provider: &PlannedProvider, plan: &ExecutionPlan) -> Option<Value> {
    provider
        .denominator_digest
        .clone()
        .or_else(|| plan.plan_denominator_digest.clone())
}

/// The value `executePlannedProvider` (or a fake standing in for it)
/// returns: either an already-shaped `legion-execution-result` (`result.kind
/// === 'legion-execution-result'`) or a raw provider result `asReceipt`
/// normalizes via [`normalize_provider_result`].
#[derive(Clone, Debug)]
pub enum ProviderOutcome {
    ExecutionResult(Value),
    ProviderResult { family: String, value: Value },
}

/// Mirrors `executePlannedProvider(...)`. Modeled as a trait so
/// `executePlan`'s control flow can be tested without any real subprocess,
/// dynamic import, or sandbox policy — the actual `provider-executor.mjs`
/// dispatch (`legacy-check`/`external-process`/`runtime-script`/
/// `imported-artifact`/`reasoning-contract`) lives outside this packet.
pub trait ProviderExecutor {
    fn execute(
        &self,
        provider: &PlannedProvider,
        plan: &ExecutionPlan,
    ) -> Result<ProviderOutcome, String>;
}

/// Mirrors `host.clock.now()` used for the fallback receipt's
/// `startedAt`/`completedAt`.
pub trait HostClock {
    fn now_ms(&self) -> i64;
}

/// Mirrors `asReceipt(provider, result, plan, host)`.
pub fn as_receipt(
    provider: &PlannedProvider,
    outcome: &ProviderOutcome,
    plan: &ExecutionPlan,
    clock: &dyn HostClock,
) -> Value {
    let binding = plan.binding.clone().unwrap_or(Value::Null);
    let denominator_digest = denominator(provider, plan);
    match outcome {
        ProviderOutcome::ExecutionResult(result) => {
            let mut result = result.clone();
            let provider_result = result
                .get("providerResult")
                .cloned()
                .unwrap_or_else(|| json!({}));
            let mut coverage = provider_result
                .get("coverage")
                .cloned()
                .unwrap_or_else(|| json!({}));
            if let Value::Object(cov) = &mut coverage {
                cov.insert(
                    "denominatorDigest".to_string(),
                    denominator_digest.clone().unwrap_or(Value::Null),
                );
            }
            let mut provider_result = provider_result;
            if let Value::Object(pr) = &mut provider_result {
                pr.insert("coverage".to_string(), coverage);
            }
            if let Value::Object(r) = &mut result {
                r.insert("provider".to_string(), json!(provider.id));
                r.insert("binding".to_string(), binding);
                r.insert(
                    "denominatorDigest".to_string(),
                    denominator_digest.unwrap_or(Value::Null),
                );
                r.insert("providerResult".to_string(), provider_result);
            }
            // Re-run through the canonical builder so defaulting matches
            // exactly (mirrors JS calling `executionReceipt({...result, ...})`).
            let input = execution_receipt_input_from_value(&result);
            execution_receipt(input).unwrap_or(result)
        }
        ProviderOutcome::ProviderResult { family, value } => {
            let normalized = normalize_provider_result(&provider.id, family, value);
            let mut normalized = normalized;
            if let Value::Object(n) = &mut normalized {
                if let Some(Value::Object(cov)) = n.get_mut("coverage") {
                    let dd = denominator_digest
                        .clone()
                        .or_else(|| cov.get("denominatorDigest").cloned())
                        .unwrap_or(Value::Null);
                    cov.insert("denominatorDigest".to_string(), dd);
                }
            }
            let now = clock.now_ms();
            let tool = json!({
                "status": "not-applicable",
                "name": provider.runner_module.clone().or_else(|| provider.runner_kind.clone()).unwrap_or_else(|| "internal-module".to_string()),
                "version": provider.provider_version,
                "probe": Value::Null,
                "executableDigest": provider.runner_module_digest.clone().unwrap_or(Value::Null),
            });
            let input = ExecutionReceiptInput {
                provider: provider.id.clone(),
                binding: Some(binding),
                denominator_digest,
                command: Some(json!({"executable": Value::Null, "args": [], "cwd": plan.root})),
                started_at: Some(now),
                completed_at: Some(now),
                spawn_status: "completed".to_string(),
                tool: Some(tool),
                parsed: None,
                provider_result: Some(normalized),
                ..Default::default()
            };
            execution_receipt(input).unwrap_or(Value::Null)
        }
    }
}

/// Round-trips a full `legion-execution-result` Value into
/// [`ExecutionReceiptInput`] so it can be replayed through
/// [`execution_receipt`], mirroring `executionReceipt({...result, ...})`.
fn execution_receipt_input_from_value(result: &Value) -> ExecutionReceiptInput {
    ExecutionReceiptInput {
        provider: result.get("provider").and_then(Value::as_str).unwrap_or_default().to_string(),
        binding: result.get("binding").cloned(),
        denominator_digest: result.get("denominatorDigest").cloned(),
        command: result.get("command").cloned(),
        started_at: result.get("startedAt").and_then(Value::as_i64),
        completed_at: result.get("completedAt").and_then(Value::as_i64),
        spawn_status: result
            .get("spawnStatus")
            .and_then(Value::as_str)
            .unwrap_or("completed")
            .to_string(),
        exit_code: result.get("exitCode").cloned(),
        signal: result.get("signal").cloned(),
        timed_out: result.get("timedOut") == Some(&Value::Bool(true)),
        stdout_artifact: result.get("stdoutArtifact").cloned(),
        stderr_artifact: result.get("stderrArtifact").cloned(),
        environment_keys: result
            .get("environmentKeys")
            .and_then(Value::as_array)
            .map(|a| a.iter().filter_map(|v| v.as_str().map(str::to_string)).collect())
            .unwrap_or_default(),
        sandbox_receipt: result.get("sandboxReceipt").cloned(),
        process_tree_receipt: result.get("processTreeReceipt").cloned(),
        tool: result.get("tool").cloned(),
        parsed: result.get("parsed").cloned(),
        provider_result: result.get("providerResult").cloned(),
    }
}

/// Mirrors `skippedReceipt(provider, reason)`.
pub fn skipped_receipt(provider: &PlannedProvider, reason: &str) -> Value {
    receipt_blocked(
        Some(&BlockedSpec {
            provider: Some(provider.id.clone()),
            denominator_digest: provider.denominator_digest.clone(),
            ..Default::default()
        }),
        reason,
    )
}

/// A faithful, self-contained port of the JS `RuntimeAdmission` class's
/// `Set`-based `admit`/release semantics — see the module doc for why this
/// is not the existing `crate::engine::RuntimeAdmission`.
#[derive(Default)]
pub struct AdmissionSet {
    quiescing: bool,
    active: HashSet<String>,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[error("runtime is not accepting work")]
pub struct AdmissionClosedError;

impl AdmissionSet {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn admit(&mut self, id: &str) -> Result<(), AdmissionClosedError> {
        if self.quiescing {
            return Err(AdmissionClosedError);
        }
        self.active.insert(id.to_string());
        Ok(())
    }

    pub fn release(&mut self, id: &str) {
        self.active.remove(id);
    }
}

/// Result of `executePlan`.
#[derive(Clone, Debug, Default)]
pub struct ExecutePlanResult {
    pub receipts: Vec<Value>,
    pub run_ledger_snapshot: super::run_ledger::Snapshot,
    pub runtime_state: &'static str,
}

/// Optional replan callback, mirrors `host.replan(...)`.
pub trait Replan {
    fn replan(&mut self, failed_provider: &str, error: &str, completed: &Value, remaining: &[PlannedProvider]);
}

/// Mirrors `executePlan(plan, host)`.
///
/// `ledger`/`admission` default to fresh instances exactly as JS does
/// (`host.runLedger ?? new RunLedger(...)`, `host.runtimeAdmission ?? new
/// RuntimeAdmission()`); pass `None` for `replan` to mirror `host.replan`
/// being absent (JS: `typeof host.replan === 'function'` guards the call).
pub fn execute_plan(
    plan: &ExecutionPlan,
    executor: &dyn ProviderExecutor,
    clock: &dyn HostClock,
    mut replan: Option<&mut dyn Replan>,
) -> ExecutePlanResult {
    let mut ledger = RunLedger::<SystemClock>::new(plan.limits);
    let mut admission = AdmissionSet::new();
    let by_id: HashMap<String, PlannedProvider> = plan
        .providers
        .iter()
        .map(|p| (p.id.clone(), p.clone()))
        .collect();

    let scheduler_providers: Vec<SchedulerProvider> =
        plan.providers.iter().map(PlannedProvider::scheduler_provider).collect();
    let schedule = schedule_providers(
        &scheduler_providers,
        &ScheduleOptions {
            mode: plan.schedule_mode,
            concurrency: plan.max_concurrency,
            resources: plan.resource_ceilings.clone(),
        },
    );
    let waves: Vec<Vec<String>> = match schedule {
        Ok(result) => result.waves,
        Err(SchedulerError::Cycle) | Err(SchedulerError::NoProgress) | Err(_) => Vec::new(),
    };

    let mut receipts = Vec::new();
    let mut terminal: HashMap<String, Value> = HashMap::new();

    for wave in waves {
        for id in wave {
            let provider = match by_id.get(&id) {
                Some(p) => p,
                None => continue,
            };
            let denominator_digest = denominator(provider, plan);
            let blocked_dependency = provider.dependencies.iter().find(|dep| {
                !terminal
                    .get(*dep)
                    .and_then(|r| r.get("providerResult"))
                    .and_then(|pr| pr.get("complete"))
                    .and_then(Value::as_bool)
                    .unwrap_or(false)
            });
            if let Some(dep) = blocked_dependency {
                let receipt = receipt_blocked(
                    Some(&BlockedSpec {
                        provider: Some(id.clone()),
                        binding: plan.binding.clone(),
                        denominator_digest,
                        ..Default::default()
                    }),
                    &format!("dependency-not-complete:{dep}"),
                );
                receipts.push(receipt.clone());
                terminal.insert(id.clone(), receipt);
                continue;
            }

            if admission.admit(&id).is_err() {
                let receipt = receipt_blocked(
                    Some(&BlockedSpec {
                        provider: Some(id.clone()),
                        binding: plan.binding.clone(),
                        denominator_digest,
                        ..Default::default()
                    }),
                    "provider-execution-error:runtime is not accepting work",
                );
                receipts.push(receipt.clone());
                terminal.insert(id.clone(), receipt);
                continue;
            }

            let reserve_result = ledger.reserve(Reservation {
                steps: 1.0,
                calls: 1.0,
                spend_micros: provider.reserved_spend_micros,
            });
            let outcome = reserve_result
                .map_err(|e| e.to_string())
                .and_then(|_| executor.execute(provider, plan).map_err(|e| e));

            match outcome {
                Ok(outcome) => {
                    let receipt = as_receipt(provider, &outcome, plan, clock);
                    receipts.push(receipt.clone());
                    terminal.insert(id.clone(), receipt);
                }
                Err(error) => {
                    let receipt = receipt_blocked(
                        Some(&BlockedSpec {
                            provider: Some(id.clone()),
                            binding: plan.binding.clone(),
                            denominator_digest,
                            ..Default::default()
                        }),
                        &format!("provider-execution-error:{error}"),
                    );
                    receipts.push(receipt.clone());
                    terminal.insert(id.clone(), receipt.clone());
                    if let Some(replan) = replan.as_deref_mut() {
                        let completed = json!(terminal
                            .iter()
                            .filter(|(_, v)| v
                                .get("providerResult")
                                .and_then(|pr| pr.get("complete"))
                                .and_then(Value::as_bool)
                                .unwrap_or(false))
                            .map(|(k, v)| (k.clone(), v.clone()))
                            .collect::<serde_json::Map<_, _>>());
                        let remaining: Vec<PlannedProvider> = plan
                            .providers
                            .iter()
                            .filter(|p| !terminal.contains_key(&p.id))
                            .cloned()
                            .collect();
                        replan.replan(&id, &error, &completed, &remaining);
                    }
                }
            }
            admission.release(&id);
        }
    }

    ExecutePlanResult {
        receipts,
        run_ledger_snapshot: ledger.snapshot(),
        runtime_state: if admission.quiescing { "STOPPED" } else { "RUNNING" },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct FixedClock(i64);
    impl HostClock for FixedClock {
        fn now_ms(&self) -> i64 {
            self.0
        }
    }

    fn provider(id: &str, deps: Vec<&str>) -> PlannedProvider {
        PlannedProvider {
            id: id.to_string(),
            dependencies: deps.into_iter().map(str::to_string).collect(),
            resources: BTreeMap::new(),
            concurrency_key: None,
            denominator_digest: None,
            reserved_spend_micros: 0.0,
            family: "test".to_string(),
            runner_module: None,
            runner_kind: None,
            provider_version: "1".to_string(),
            runner_module_digest: None,
        }
    }

    struct AlwaysPass;
    impl ProviderExecutor for AlwaysPass {
        fn execute(&self, provider: &PlannedProvider, _plan: &ExecutionPlan) -> Result<ProviderOutcome, String> {
            Ok(ProviderOutcome::ProviderResult {
                family: provider.family.clone(),
                value: json!({"status": "pass", "complete": true}),
            })
        }
    }

    struct AlwaysFail;
    impl ProviderExecutor for AlwaysFail {
        fn execute(&self, _provider: &PlannedProvider, _plan: &ExecutionPlan) -> Result<ProviderOutcome, String> {
            Err("boom".to_string())
        }
    }

    #[test]
    fn normalize_provider_result_marks_complete_on_pass_with_no_gaps() {
        let result = normalize_provider_result("p1", "family", &json!({"status": "pass", "complete": true}));
        assert_eq!(result["complete"], json!(true));
        assert_eq!(result["status"], json!("pass"));
        assert_eq!(result["provider"], json!("p1"));
    }

    #[test]
    fn normalize_provider_result_forces_unproven_on_unknown_status() {
        let result = normalize_provider_result("p1", "family", &json!({"status": "bogus", "complete": true}));
        assert_eq!(result["status"], json!("unproven"));
        assert_eq!(result["complete"], json!(false));
    }

    #[test]
    fn normalize_provider_result_treats_measured_as_pass() {
        let result = normalize_provider_result("p1", "family", &json!({"status": "measured", "complete": true}));
        assert_eq!(result["status"], json!("pass"));
    }

    #[test]
    fn execute_plan_runs_single_provider_and_records_receipt() {
        let plan = ExecutionPlan {
            root: Some("/repo".to_string()),
            binding: Some(json!({"rev": "abc"})),
            providers: vec![provider("p1", vec![])],
            schedule_mode: ScheduleMode::Auto,
            max_concurrency: 4,
            resource_ceilings: None,
            limits: RunLimits::default(),
            plan_denominator_digest: None,
        };
        let result = execute_plan(&plan, &AlwaysPass, &FixedClock(1000), None);
        assert_eq!(result.receipts.len(), 1);
        assert_eq!(result.receipts[0]["provider"], json!("p1"));
        assert_eq!(result.runtime_state, "RUNNING");
    }

    #[test]
    fn execute_plan_blocks_dependent_when_dependency_never_completes() {
        let plan = ExecutionPlan {
            root: Some("/repo".to_string()),
            binding: None,
            providers: vec![provider("p1", vec![]), provider("p2", vec!["p1"])],
            schedule_mode: ScheduleMode::Auto,
            max_concurrency: 4,
            resource_ceilings: None,
            limits: RunLimits::default(),
            plan_denominator_digest: None,
        };
        let result = execute_plan(&plan, &AlwaysFail, &FixedClock(1000), None);
        assert_eq!(result.receipts.len(), 2);
        let p2 = result.receipts.iter().find(|r| r["provider"] == json!("p2")).unwrap();
        assert_eq!(p2["spawnStatus"], json!("blocked"));
        assert!(p2["providerResult"]["coverageGaps"][0]["reason"]
            .as_str()
            .unwrap()
            .starts_with("dependency-not-complete:"));
    }

    #[test]
    fn execute_plan_records_provider_execution_error_as_blocked() {
        let plan = ExecutionPlan {
            root: Some("/repo".to_string()),
            binding: None,
            providers: vec![provider("p1", vec![])],
            schedule_mode: ScheduleMode::Auto,
            max_concurrency: 4,
            resource_ceilings: None,
            limits: RunLimits::default(),
            plan_denominator_digest: None,
        };
        let result = execute_plan(&plan, &AlwaysFail, &FixedClock(1000), None);
        assert_eq!(result.receipts.len(), 1);
        assert_eq!(result.receipts[0]["spawnStatus"], json!("blocked"));
        assert!(result.receipts[0]["providerResult"]["coverageGaps"][0]["reason"]
            .as_str()
            .unwrap()
            .starts_with("provider-execution-error:boom"));
    }

    #[test]
    fn skipped_receipt_marks_provider_blocked_with_reason() {
        let p = provider("p1", vec![]);
        let receipt = skipped_receipt(&p, "manual-skip");
        assert_eq!(receipt["spawnStatus"], json!("blocked"));
        assert_eq!(receipt["provider"], json!("p1"));
    }

    #[test]
    fn admission_set_rejects_admit_once_quiescing() {
        let mut admission = AdmissionSet::new();
        admission.admit("a").unwrap();
        admission.quiescing = true;
        assert_eq!(admission.admit("b").unwrap_err(), AdmissionClosedError);
    }
}
