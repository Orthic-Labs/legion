//! Frozen execution policy enforcement: deterministic waves, resource and
//! concurrency-key limits, bounded retry, breakers, frozen fallbacks with
//! declared proof equivalence, least context, and proof-state serde compat.

use std::{
    collections::BTreeMap,
    fs,
    path::PathBuf,
    sync::{
        atomic::{AtomicU64, AtomicUsize, Ordering},
        Mutex,
    },
    thread::sleep,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use legion_audit::{
    execute, execute_scheduled, execute_with_cancellation_scheduled, scheduler::SchedulerConfig,
    AuditError, AuditPlan, AuditProvider, ExecutionContext, ExecutionReport,
    FilesystemInventorySource, FrozenPlan, InventoryEnvelope, InventorySource, ProofState,
    ProviderExecutor, RunState,
};
use legion_contracts::{Coverage, ProviderId, ProviderResult, ProviderSpec, ProviderStatus};
use serde_json::{json, Value};
use tokio_util::sync::CancellationToken;

const KEY: &[u8] = b"execution-policy-enforcement-key";

fn temp_dir(name: &str) -> PathBuf {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!(
        "legion-exec-policy-{name}-{}-{nanos}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir_all(&dir).unwrap();
    fs::canonicalize(dir).unwrap()
}

fn parallel_safe() -> Value {
    json!({
        "scheduleClass": "parallel-safe",
        "resourceClaims": {"cpu": 1, "memoryMb": 64, "io": 1},
        "concurrencyKey": null,
        "maxParallelism": null,
        "failurePolicy": "block-dependents"
    })
}

fn with(mut base: Value, patch: Value) -> Value {
    for (key, value) in patch.as_object().unwrap() {
        base[key] = value.clone();
    }
    base
}

fn spec(id: &str, execution: Value, depends_on: &[&str]) -> ProviderSpec {
    ProviderSpec {
        schema_version: 2,
        id: ProviderId::new(id).unwrap(),
        provider_version: "1.0.0".into(),
        family: "fixture".into(),
        lens_ids: Vec::new(),
        role: "deterministic".into(),
        phase: "source".into(),
        depends_on: depends_on
            .iter()
            .map(|dependency| ProviderId::new(*dependency).unwrap())
            .collect(),
        consumes: vec!["repository-inventory".into()],
        produces: vec!["provider-result".into()],
        selector: json!({"op":"always"}),
        denominator_kind: "first-party-source-files".into(),
        runner: json!({"kind":"built-in"}),
        host_capabilities: Vec::new(),
        execution,
        reasoning: json!({}),
        benchmark: json!({
            "status": "qualified",
            "requiredForCleanClaim": false,
            "qualificationDigest": format!("sha256:{}", "a".repeat(64)),
        }),
        clean_claim: "evidence-only".into(),
        control_ids: Vec::new(),
        scopes: Vec::new(),
        selectable: true,
    }
}

fn freeze(specs: &[ProviderSpec]) -> (FrozenPlan, InventoryEnvelope) {
    let root = temp_dir("plan");
    fs::create_dir_all(root.join("src")).unwrap();
    fs::write(root.join("src/lib.rs"), "pub fn f() {}\n").unwrap();
    let inventory = FilesystemInventorySource::new(&root)
        .unwrap()
        .inventory(&root.to_string_lossy())
        .unwrap();
    let plan = AuditPlan::compile(&inventory, specs)
        .unwrap()
        .freeze(Some(KEY))
        .unwrap();
    (plan, inventory)
}

/// Records every observable interaction; failure and latency are per id.
#[derive(Default)]
struct Probe {
    sleep_ms: BTreeMap<String, u64>,
    /// Remaining failures per id; `u32::MAX` fails forever.
    failures: Mutex<BTreeMap<String, u32>>,
    calls: Mutex<BTreeMap<String, u32>>,
    live: AtomicUsize,
    peak: AtomicUsize,
    key_live: Mutex<BTreeMap<String, usize>>,
    key_peak: Mutex<BTreeMap<String, usize>>,
    contexts: Mutex<BTreeMap<String, Vec<String>>>,
}

impl Probe {
    fn failing(self, id: &str, times: u32) -> Self {
        self.failures.lock().unwrap().insert(id.into(), times);
        self
    }

    fn sleeping(mut self, id: &str, ms: u64) -> Self {
        self.sleep_ms.insert(id.into(), ms);
        self
    }

    fn calls(&self, id: &str) -> u32 {
        self.calls.lock().unwrap().get(id).copied().unwrap_or(0)
    }

    fn key_peak(&self, key: &str) -> usize {
        self.key_peak.lock().unwrap().get(key).copied().unwrap_or(0)
    }

    fn run(&self, provider: &AuditProvider) -> Result<ProviderResult, AuditError> {
        *self
            .calls
            .lock()
            .unwrap()
            .entry(provider.id.clone())
            .or_insert(0) += 1;
        let live = self.live.fetch_add(1, Ordering::SeqCst) + 1;
        self.peak.fetch_max(live, Ordering::SeqCst);
        let key = provider.configuration["execution"]["concurrencyKey"]
            .as_str()
            .map(str::to_owned);
        if let Some(key) = &key {
            let mut keys = self.key_live.lock().unwrap();
            let now = keys.entry(key.clone()).or_insert(0);
            *now += 1;
            let now = *now;
            let mut peaks = self.key_peak.lock().unwrap();
            let peak = peaks.entry(key.clone()).or_insert(0);
            *peak = (*peak).max(now);
        }
        sleep(Duration::from_millis(
            self.sleep_ms.get(&provider.id).copied().unwrap_or(15),
        ));
        if let Some(key) = &key {
            *self.key_live.lock().unwrap().get_mut(key).unwrap() -= 1;
        }
        self.live.fetch_sub(1, Ordering::SeqCst);
        let fail = {
            let mut failures = self.failures.lock().unwrap();
            match failures.get_mut(&provider.id) {
                Some(left) if *left == u32::MAX => true,
                Some(left) if *left > 0 => {
                    *left -= 1;
                    true
                }
                _ => false,
            }
        };
        if fail {
            return Err(AuditError::Provider(format!("boom {}", provider.id)));
        }
        let count = provider.configuration["denominatorCount"].as_u64().unwrap();
        Ok(ProviderResult {
            schema_version: 1,
            provider: ProviderId::new(&provider.id).unwrap(),
            applicable: true,
            required: provider.required,
            status: ProviderStatus::Complete,
            complete: true,
            coverage: Some(Coverage {
                denominator_digest: provider.configuration["denominatorDigest"]
                    .as_str()
                    .unwrap()
                    .to_owned(),
                expected: count,
                examined: count,
                gaps: Vec::new(),
            }),
            findings: Vec::new(),
            coverage_gaps: Vec::new(),
            degradation: Vec::new(),
            details: BTreeMap::new(),
        })
    }
}

impl ProviderExecutor for Probe {
    fn execute(
        &self,
        provider: &AuditProvider,
        _: &InventoryEnvelope,
    ) -> Result<ProviderResult, AuditError> {
        self.run(provider)
    }

    fn execute_with_context(
        &self,
        _: &FrozenPlan,
        provider: &AuditProvider,
        _: &InventoryEnvelope,
        context: &ExecutionContext<'_>,
    ) -> Result<ProviderResult, AuditError> {
        self.contexts.lock().unwrap().insert(
            provider.id.clone(),
            context
                .prior_results
                .iter()
                .map(|execution| execution.provider.clone())
                .collect(),
        );
        self.run(provider)
    }
}

fn ids(report: &ExecutionReport) -> Vec<String> {
    report
        .results
        .iter()
        .map(|execution| execution.provider.clone())
        .collect()
}

fn record<'a>(report: &'a ExecutionReport, id: &str) -> &'a legion_audit::ProviderRecord {
    report
        .provider_records
        .iter()
        .find(|record| record.provider == id)
        .unwrap_or_else(|| panic!("no record for {id}"))
}

fn four(execution: Value) -> Vec<ProviderSpec> {
    ["fixture.a", "fixture.b", "fixture.c", "fixture.d"]
        .iter()
        .map(|id| spec(id, execution.clone(), &[]))
        .collect()
}

#[test]
fn parallel_results_follow_frozen_plan_order_and_match_sequential_bytes() {
    let (plan, inventory) = freeze(&four(parallel_safe()));
    // The first planned provider finishes last.
    let slow_first = |probe: Probe| {
        plan.providers()
            .iter()
            .enumerate()
            .fold(probe, |probe, (position, provider)| {
                probe.sleeping(&provider.id, 120 - 30 * position as u64)
            })
    };
    let sequential_probe = slow_first(Probe::default());
    let sequential = execute(&plan, &inventory, &sequential_probe).unwrap();
    let parallel_probe = slow_first(Probe::default());
    let parallel = execute_scheduled(
        &plan,
        &inventory,
        &parallel_probe,
        &SchedulerConfig::parallel(4),
    )
    .unwrap();

    assert_eq!(sequential_probe.peak.load(Ordering::SeqCst), 1);
    assert!(
        parallel_probe.peak.load(Ordering::SeqCst) > 1,
        "wave members must actually overlap"
    );
    let planned: Vec<String> = plan.providers().iter().map(|p| p.id.clone()).collect();
    assert_eq!(ids(&parallel), planned);
    assert_eq!(parallel.planned_providers, planned);
    assert_eq!(sequential, parallel);
    assert_eq!(
        serde_json::to_vec(&sequential).unwrap(),
        serde_json::to_vec(&parallel).unwrap()
    );

    let async_probe = slow_first(Probe::default());
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let asynchronous = runtime
        .block_on(execute_with_cancellation_scheduled(
            &plan,
            &inventory,
            &async_probe,
            CancellationToken::new(),
            &SchedulerConfig::parallel(4),
        ))
        .unwrap();
    assert_eq!(
        serde_json::to_vec(&sequential).unwrap(),
        serde_json::to_vec(&asynchronous).unwrap()
    );
}

#[test]
fn concurrency_key_serialises_members_while_unkeyed_providers_overlap() {
    let keyed = with(parallel_safe(), json!({"concurrencyKey": "shared-tool"}));
    let specs = vec![
        spec("fixture.a", keyed.clone(), &[]),
        spec("fixture.b", keyed.clone(), &[]),
        spec("fixture.c", keyed, &[]),
        spec("fixture.d", parallel_safe(), &[]),
        spec("fixture.e", parallel_safe(), &[]),
    ];
    let (plan, inventory) = freeze(&specs);
    let probe = Probe::default();
    let report =
        execute_scheduled(&plan, &inventory, &probe, &SchedulerConfig::parallel(5)).unwrap();
    assert!(report.gaps.is_empty(), "{:?}", report.gaps);
    assert_eq!(probe.key_peak("shared-tool"), 1);
    assert!(probe.peak.load(Ordering::SeqCst) > 1);
}

#[test]
fn serial_class_and_per_provider_parallelism_cap_bound_concurrency() {
    let serial = with(parallel_safe(), json!({"scheduleClass": "serial"}));
    let (plan, inventory) = freeze(&four(serial));
    let probe = Probe::default();
    execute_scheduled(&plan, &inventory, &probe, &SchedulerConfig::parallel(4)).unwrap();
    assert_eq!(probe.peak.load(Ordering::SeqCst), 1);

    let capped = with(parallel_safe(), json!({"maxParallelism": 2}));
    let (plan, inventory) = freeze(&four(capped));
    let probe = Probe::default();
    execute_scheduled(&plan, &inventory, &probe, &SchedulerConfig::parallel(4)).unwrap();
    assert!(probe.peak.load(Ordering::SeqCst) <= 2);
}

#[test]
fn resource_claims_respect_capacity_and_oversized_claims_become_gaps() {
    let heavy = with(
        parallel_safe(),
        json!({"resourceClaims": {"cpu": 2, "memoryMb": 64, "io": 1}}),
    );
    let (plan, inventory) = freeze(&four(heavy));
    let probe = Probe::default();
    let config = SchedulerConfig::parallel(4).with_capacity("cpu", 2);
    let report = execute_scheduled(&plan, &inventory, &probe, &config).unwrap();
    assert!(report.gaps.is_empty(), "{:?}", report.gaps);
    assert_eq!(
        probe.peak.load(Ordering::SeqCst),
        1,
        "two cpu-2 claims cannot share capacity 2"
    );

    // A claim larger than the whole host can never be scheduled: explicit gap,
    // never invoked, never validated.
    let oversized = with(
        parallel_safe(),
        json!({"resourceClaims": {"cpu": 1, "simulator": 2}}),
    );
    let (plan, inventory) = freeze(&[spec("fixture.sim", oversized, &[])]);
    let probe = Probe::default();
    let report =
        execute_scheduled(&plan, &inventory, &probe, &SchedulerConfig::parallel(2)).unwrap();
    assert_eq!(probe.calls("fixture.sim"), 0);
    assert!(report
        .gaps
        .contains(&"resource-claim-exceeds-capacity:fixture.sim:simulator".to_owned()));
    let record = record(&report, "fixture.sim");
    assert_eq!(record.run_state, RunState::Skipped);
    assert_eq!(record.proof_state, ProofState::Unproven);
}

#[test]
fn breaker_trip_turns_remaining_group_members_into_explicit_gaps() {
    let group = with(
        parallel_safe(),
        json!({"breakerGroup": "transport-x", "breakerThreshold": 2}),
    );
    let (plan, inventory) = freeze(&four(group));
    let order: Vec<String> = plan.providers().iter().map(|p| p.id.clone()).collect();
    let mut probe = Probe::default();
    probe = probe
        .failing(&order[0], u32::MAX)
        .failing(&order[1], u32::MAX);
    let report = execute(&plan, &inventory, &probe).unwrap();
    assert_eq!(probe.calls(&order[0]), 1);
    assert_eq!(probe.calls(&order[1]), 1);
    for open in &order[2..] {
        assert_eq!(probe.calls(open), 0, "breaker-open member must not run");
        assert!(report
            .gaps
            .contains(&format!("breaker-open:transport-x:{open}")));
        let rec = record(&report, open);
        assert_eq!(rec.run_state, RunState::Skipped);
        assert_eq!(rec.proof_state, ProofState::Unproven);
        assert_eq!(rec.attempts, 0);
    }
    assert_eq!(record(&report, &order[0]).proof_state, ProofState::Failed);
}

#[test]
fn effectful_providers_are_never_retried_but_idempotent_ones_retry_within_bound() {
    let retrying = json!({"retry": {"maxAttempts": 3}});
    let effectful = with(
        parallel_safe(),
        json!({
            "resourceClaims": {"cpu": 1, "projectExecution": 1},
            "retry": {"maxAttempts": 3}
        }),
    );
    let specs = vec![
        spec("fixture.effect", effectful, &[]),
        spec(
            "fixture.flaky",
            with(parallel_safe(), retrying.clone()),
            &[],
        ),
        spec(
            "fixture.hopeless",
            with(parallel_safe(), json!({"retry": {"maxAttempts": 9}})),
            &[],
        ),
    ];
    let (plan, inventory) = freeze(&specs);
    let probe = Probe::default()
        .failing("fixture.effect", u32::MAX)
        .failing("fixture.flaky", 2)
        .failing("fixture.hopeless", u32::MAX);
    let report = execute(&plan, &inventory, &probe).unwrap();

    assert_eq!(probe.calls("fixture.effect"), 1, "effect must not repeat");
    assert!(record(&report, "fixture.effect").effectful);
    assert!(report
        .coverage_notes
        .contains(&"retry-denied-effectful:fixture.effect".to_owned()));

    assert_eq!(probe.calls("fixture.flaky"), 3);
    let flaky = record(&report, "fixture.flaky");
    assert_eq!(flaky.attempts, 3);
    assert_eq!(flaky.proof_state, ProofState::Validated);

    assert_eq!(
        probe.calls("fixture.hopeless"),
        3,
        "retry is capped by the engine, not the plan"
    );
    assert_eq!(
        record(&report, "fixture.hopeless").proof_state,
        ProofState::Failed
    );
}

fn fallback_plan(equivalence: &str) -> Vec<ProviderSpec> {
    vec![
        spec(
            "fixture.primary",
            with(
                parallel_safe(),
                json!({"fallback": {"provider": "fixture.backup", "equivalence": equivalence}}),
            ),
            &[],
        ),
        spec("fixture.backup", parallel_safe(), &[]),
    ]
}

#[test]
fn degraded_fallback_never_counts_as_equivalent_coverage() {
    let (plan, inventory) = freeze(&fallback_plan("degraded"));
    let probe = Probe::default().failing("fixture.primary", u32::MAX);
    let report = execute(&plan, &inventory, &probe).unwrap();
    assert_eq!(probe.calls("fixture.backup"), 1);
    assert!(
        report
            .gaps
            .iter()
            .any(|gap| gap.contains("boom fixture.primary")),
        "primary failure stays a gap: {:?}",
        report.gaps
    );
    assert!(report
        .coverage_notes
        .contains(&"fallback-degraded:fixture.primary:fixture.backup".to_owned()));
    let primary = record(&report, "fixture.primary");
    assert_eq!(primary.proof_state, ProofState::Failed);
    assert_eq!(
        primary.fallback.as_ref().unwrap().outcome,
        "covered-degraded"
    );
    assert_eq!(
        record(&report, "fixture.backup").proof_state,
        ProofState::Validated
    );
}

#[test]
fn equivalent_fallback_retires_only_the_declared_primary_gap() {
    let (plan, inventory) = freeze(&fallback_plan("equivalent"));
    let probe = Probe::default().failing("fixture.primary", u32::MAX);
    let report = execute(&plan, &inventory, &probe).unwrap();
    assert!(report.gaps.is_empty(), "{:?}", report.gaps);
    assert!(report
        .coverage_notes
        .contains(&"fallback-equivalent:fixture.primary:fixture.backup".to_owned()));
    assert_eq!(
        record(&report, "fixture.primary")
            .fallback
            .as_ref()
            .unwrap()
            .outcome,
        "covered-equivalent"
    );

    // Unfrozen substitution does not exist: without a declared fallback the
    // same failure is a plain gap.
    let (plan, inventory) = freeze(&[
        spec("fixture.primary", parallel_safe(), &[]),
        spec("fixture.backup", parallel_safe(), &[]),
    ]);
    let probe = Probe::default().failing("fixture.primary", u32::MAX);
    let report = execute(&plan, &inventory, &probe).unwrap();
    assert!(!report.gaps.is_empty());
    assert!(record(&report, "fixture.primary").fallback.is_none());
}

#[test]
fn fallback_that_also_fails_leaves_the_gap_and_is_marked_unavailable() {
    let (plan, inventory) = freeze(&fallback_plan("equivalent"));
    let probe = Probe::default()
        .failing("fixture.primary", u32::MAX)
        .failing("fixture.backup", u32::MAX);
    let report = execute(&plan, &inventory, &probe).unwrap();
    assert!(!report.gaps.is_empty());
    assert_eq!(
        record(&report, "fixture.primary")
            .fallback
            .as_ref()
            .unwrap()
            .outcome,
        "unavailable"
    );
}

#[test]
fn providers_receive_only_declared_dependency_context() {
    let specs = vec![
        spec("fixture.a", parallel_safe(), &[]),
        spec("fixture.b", parallel_safe(), &[]),
        spec("fixture.c", parallel_safe(), &["fixture.a"]),
        spec(
            "fixture.d",
            with(parallel_safe(), json!({"contextProviders": ["fixture.b"]})),
            &[],
        ),
    ];
    let (plan, inventory) = freeze(&specs);
    for config in [SchedulerConfig::sequential(), SchedulerConfig::parallel(4)] {
        let probe = Probe::default();
        execute_scheduled(&plan, &inventory, &probe, &config).unwrap();
        let seen = probe.contexts.lock().unwrap();
        assert_eq!(seen["fixture.a"], Vec::<String>::new());
        assert_eq!(seen["fixture.b"], Vec::<String>::new());
        assert_eq!(seen["fixture.c"], vec!["fixture.a".to_owned()]);
        assert_eq!(seen["fixture.d"], vec!["fixture.b".to_owned()]);
    }
}

#[test]
fn dependency_failure_still_blocks_dependents_with_explicit_gap() {
    let specs = vec![
        spec("fixture.a", parallel_safe(), &[]),
        spec("fixture.c", parallel_safe(), &["fixture.a"]),
    ];
    let (plan, inventory) = freeze(&specs);
    let probe = Probe::default().failing("fixture.a", u32::MAX);
    let report =
        execute_scheduled(&plan, &inventory, &probe, &SchedulerConfig::parallel(2)).unwrap();
    assert_eq!(probe.calls("fixture.c"), 0);
    assert!(report
        .gaps
        .contains(&"dependency-failed:fixture.c".to_owned()));
    assert_eq!(
        record(&report, "fixture.c").proof_state,
        ProofState::Unproven
    );
}

#[test]
fn proof_state_is_separate_from_run_state_and_old_reports_still_deserialize() {
    let (plan, inventory) = freeze(&four(parallel_safe()));
    let report = execute(&plan, &inventory, &Probe::default()).unwrap();
    assert_eq!(report.provider_records.len(), 4);
    for rec in &report.provider_records {
        assert_eq!(rec.run_state, RunState::Ran);
        assert_eq!(rec.proof_state, ProofState::Validated);
    }

    let mut value = serde_json::to_value(&report).unwrap();
    assert_eq!(value["providerRecords"][0]["proofState"], "validated");
    assert_eq!(value["providerRecords"][0]["runState"], "ran");

    // A report written before scheduler enforcement has no records at all.
    value.as_object_mut().unwrap().remove("providerRecords");
    let legacy: ExecutionReport = serde_json::from_value(value).unwrap();
    assert!(legacy.provider_records.is_empty());
    assert_eq!(legacy.results, report.results);

    // Absence of a record must never read as proven.
    assert!(!legacy
        .provider_records
        .iter()
        .any(|rec| rec.proof_state == ProofState::Validated));
    assert_eq!(ProofState::default(), ProofState::Unproven);

    // An empty record list is omitted from the serialised form.
    let bytes = serde_json::to_string(&legacy).unwrap();
    assert!(!bytes.contains("providerRecords"));
}
