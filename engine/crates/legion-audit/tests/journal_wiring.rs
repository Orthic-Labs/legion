//! Journal, signed receipts, resume and scheduler wiring through the execution
//! engine. The engine is driven through the ambient run (the seam the CLI uses)
//! so library callers without a run directory stay unaffected.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex,
    },
    time::{SystemTime, UNIX_EPOCH},
};

use legion_audit::{
    execute,
    journal::{
        verify_dir, AuditEvent, EventKind, Expectation, Journal, JournalAnchor, ANCHOR_FILE,
        EVENTS_FILE,
    },
    resume::{
        install_ambient, load_receipts, read_verified_receipt, receipt_path, resume, AmbientRun,
        ProviderSeed, ResumeDecision, ResumeInput, RunRecorder, RECEIPT_DIR,
    },
    scheduler::{ProviderPolicy, SchedulerConfig},
    AuditError, AuditPlan, AuditProvider, ExecutionReport, FilesystemInventorySource, FrozenPlan,
    InventoryEnvelope, InventorySource, ProofState, ProviderExecutor,
};
use legion_contracts::{Coverage, ProviderId, ProviderResult, ProviderSpec, ProviderStatus};
use serde_json::{json, Value};

const KEY: &[u8] = b"journal-wiring-plan-key";

/// The ambient run is process-wide; tests in this binary take turns.
static AMBIENT_LOCK: Mutex<()> = Mutex::new(());

fn temp_dir(name: &str) -> PathBuf {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!(
        "legion-journal-wiring-{name}-{}-{nanos}-{}",
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

fn effectful() -> Value {
    with(
        parallel_safe(),
        json!({"resourceClaims": {"cpu": 1, "projectExecution": 1}}),
    )
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

/// Counts calls; failure counts are per id (`u32::MAX` fails forever).
#[derive(Default)]
struct Probe {
    failures: Mutex<BTreeMap<String, u32>>,
    calls: Mutex<BTreeMap<String, u32>>,
}

impl Probe {
    fn failing(self, id: &str, times: u32) -> Self {
        self.failures.lock().unwrap().insert(id.into(), times);
        self
    }

    fn calls(&self, id: &str) -> u32 {
        self.calls.lock().unwrap().get(id).copied().unwrap_or(0)
    }
}

impl ProviderExecutor for Probe {
    fn execute(
        &self,
        provider: &AuditProvider,
        _: &InventoryEnvelope,
    ) -> Result<ProviderResult, AuditError> {
        *self
            .calls
            .lock()
            .unwrap()
            .entry(provider.id.clone())
            .or_insert(0) += 1;
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

fn recorder(plan: &FrozenPlan, dir: &Path) -> Arc<RunRecorder> {
    Arc::new(RunRecorder::create(dir, plan.digest(), KEY.to_vec()).unwrap())
}

fn run_with(
    plan: &FrozenPlan,
    inventory: &InventoryEnvelope,
    probe: &Probe,
    config: SchedulerConfig,
    recorder: Option<Arc<RunRecorder>>,
    seeds: BTreeMap<String, ProviderSeed>,
) -> ExecutionReport {
    let _turn = AMBIENT_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let _guard = install_ambient(AmbientRun {
        config,
        recorder,
        seeds,
    });
    execute(plan, inventory, probe).unwrap()
}

fn kinds(events: &[AuditEvent], subject: &str) -> Vec<EventKind> {
    events
        .iter()
        .filter(|event| event.subject == subject)
        .map(|event| event.kind)
        .collect()
}

fn count(events: &[AuditEvent], kind: EventKind) -> usize {
    events.iter().filter(|event| event.kind == kind).count()
}

fn ids(plan: &FrozenPlan) -> Vec<String> {
    plan.providers().iter().map(|p| p.id.clone()).collect()
}

#[test]
fn run_is_journaled_receipted_finalized_and_anchored() {
    let (plan, inventory) = freeze(&[
        spec("fixture.a", parallel_safe(), &[]),
        spec("fixture.b", parallel_safe(), &["fixture.a"]),
        spec("fixture.c", parallel_safe(), &[]),
    ]);
    let dir = temp_dir("lifecycle");
    let run = recorder(&plan, &dir);
    let probe = Probe::default();
    run_with(
        &plan,
        &inventory,
        &probe,
        SchedulerConfig::default(),
        Some(run.clone()),
        BTreeMap::new(),
    );
    let pre_final = run.head().unwrap();
    let finalized = run.finalize("sha256:report").unwrap();
    assert_eq!(finalized.sequence, pre_final.sequence + 1);

    let anchor = JournalAnchor::read(&dir).unwrap().expect("anchor written");
    assert!(anchor.verify(KEY));
    assert!(!anchor.verify(b"some-other-key"));

    let verification = verify_dir(
        &dir,
        plan.digest(),
        &Expectation {
            require_finalized: true,
            expected_head: Some(pre_final),
            final_plan_digest: Some(plan.digest().to_owned()),
        },
    );
    assert!(verification.is_valid(), "{:?}", verification.defects);
    assert!(verification.finalized);

    for id in ids(&plan) {
        assert_eq!(
            kinds(&verification.events, &id),
            vec![EventKind::ProviderStarted, EventKind::ProviderFinished],
            "{id}"
        );
        // The finish event vouches for exactly the signed receipt on disk.
        let finished = verification
            .events
            .iter()
            .find(|e| e.subject == id && e.kind == EventKind::ProviderFinished)
            .unwrap();
        let receipt = read_verified_receipt(&dir, &id, KEY).unwrap();
        assert_eq!(receipt.digest, finished.payload_digest);
        assert_eq!(receipt.body.plan_digest, plan.digest());
    }
    assert!(read_verified_receipt(&dir, "fixture.a", b"wrong-key").is_err());
    assert_eq!(
        verification.events.last().unwrap().kind,
        EventKind::ReportFinalized
    );

    // A forged receipt (content edited, signature kept) never verifies.
    let path = receipt_path(&dir, "fixture.a").unwrap();
    let forged = fs::read_to_string(&path)
        .unwrap()
        .replace("\"attempts\":1", "\"attempts\":7");
    fs::write(&path, forged).unwrap();
    assert!(read_verified_receipt(&dir, "fixture.a", KEY).is_err());
    let records = load_receipts(&dir, KEY).unwrap();
    assert!(records
        .iter()
        .any(|r| r.provider == "fixture.a" && !r.verified));
}

#[test]
fn tampered_event_or_dropped_anchor_is_detected() {
    let (plan, inventory) = freeze(&[spec("fixture.a", parallel_safe(), &[])]);
    let dir = temp_dir("tamper");
    let run = recorder(&plan, &dir);
    run_with(
        &plan,
        &inventory,
        &Probe::default(),
        SchedulerConfig::default(),
        Some(run.clone()),
        BTreeMap::new(),
    );
    run.finalize("sha256:report").unwrap();
    let text = fs::read_to_string(dir.join(EVENTS_FILE)).unwrap();
    fs::write(
        dir.join(EVENTS_FILE),
        text.replace("fixture.a", "fixture.z"),
    )
    .unwrap();
    let verification = verify_dir(&dir, plan.digest(), &Expectation::default());
    assert!(!verification.is_valid());
    fs::remove_file(dir.join(ANCHOR_FILE)).unwrap();
    assert!(JournalAnchor::read(&dir).unwrap().is_none());
}

#[test]
fn retry_breaker_skip_and_fallback_events_are_journaled() {
    // Retry: two failures then success.
    let (plan, inventory) = freeze(&[spec(
        "fixture.flaky",
        with(parallel_safe(), json!({"retry": {"maxAttempts": 3}})),
        &[],
    )]);
    let dir = temp_dir("retry");
    let run = recorder(&plan, &dir);
    run_with(
        &plan,
        &inventory,
        &Probe::default().failing("fixture.flaky", 2),
        SchedulerConfig::default(),
        Some(run.clone()),
        BTreeMap::new(),
    );
    let events = run.events().unwrap();
    assert_eq!(count(&events, EventKind::RetryScheduled), 2);
    assert_eq!(
        kinds(&events, "fixture.flaky").last(),
        Some(&EventKind::ProviderFinished)
    );

    // Breaker: two infrastructure failures trip the group, the rest are skipped.
    let group = with(
        parallel_safe(),
        json!({"breakerGroup": "transport-x", "breakerThreshold": 2}),
    );
    let specs: Vec<ProviderSpec> = ["fixture.a", "fixture.b", "fixture.c", "fixture.d"]
        .iter()
        .map(|id| spec(id, group.clone(), &[]))
        .collect();
    let (plan, inventory) = freeze(&specs);
    let order = ids(&plan);
    let dir = temp_dir("breaker");
    let run = recorder(&plan, &dir);
    run_with(
        &plan,
        &inventory,
        &Probe::default()
            .failing(&order[0], u32::MAX)
            .failing(&order[1], u32::MAX),
        SchedulerConfig::default(),
        Some(run.clone()),
        BTreeMap::new(),
    );
    let events = run.events().unwrap();
    assert_eq!(count(&events, EventKind::BreakerTripped), 1);
    assert_eq!(count(&events, EventKind::ProviderSkipped), 2);
    assert_eq!(
        kinds(&events, &order[0]),
        vec![EventKind::ProviderStarted, EventKind::ProviderFailed]
    );
    assert_eq!(kinds(&events, &order[2]), vec![EventKind::ProviderSkipped]);
    run.finalize("sha256:report").unwrap();
    assert!(verify_dir(&dir, plan.digest(), &Expectation::default()).is_valid());

    // Fallback: the primary fails, the declared backup covers it.
    let (plan, inventory) = freeze(&[
        spec(
            "fixture.primary",
            with(
                parallel_safe(),
                json!({"fallback": {"provider": "fixture.backup", "equivalence": "equivalent"}}),
            ),
            &[],
        ),
        spec("fixture.backup", parallel_safe(), &[]),
    ]);
    let dir = temp_dir("fallback");
    let run = recorder(&plan, &dir);
    run_with(
        &plan,
        &inventory,
        &Probe::default().failing("fixture.primary", u32::MAX),
        SchedulerConfig::default(),
        Some(run.clone()),
        BTreeMap::new(),
    );
    assert_eq!(count(&run.events().unwrap(), EventKind::FallbackUsed), 1);
}

#[test]
fn parallel_journaled_output_is_byte_identical_to_sequential() {
    let specs: Vec<ProviderSpec> = ["fixture.a", "fixture.b", "fixture.c", "fixture.d"]
        .iter()
        .map(|id| spec(id, parallel_safe(), &[]))
        .collect();
    let (plan, inventory) = freeze(&specs);
    let plain = {
        let _turn = AMBIENT_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        execute(&plan, &inventory, &Probe::default()).unwrap()
    };
    let dir_seq = temp_dir("seq");
    let sequential = run_with(
        &plan,
        &inventory,
        &Probe::default(),
        SchedulerConfig::parallel(1),
        Some(recorder(&plan, &dir_seq)),
        BTreeMap::new(),
    );
    let dir_par = temp_dir("par");
    let parallel_run = recorder(&plan, &dir_par);
    let parallel = run_with(
        &plan,
        &inventory,
        &Probe::default(),
        SchedulerConfig::parallel(4),
        Some(parallel_run.clone()),
        BTreeMap::new(),
    );
    assert_eq!(
        serde_json::to_vec(&plain).unwrap(),
        serde_json::to_vec(&sequential).unwrap(),
        "recording must not change the report"
    );
    assert_eq!(
        serde_json::to_vec(&sequential).unwrap(),
        serde_json::to_vec(&parallel).unwrap()
    );
    parallel_run.finalize("sha256:report").unwrap();
    let verification = verify_dir(&dir_par, plan.digest(), &Expectation::default());
    assert!(verification.is_valid(), "{:?}", verification.defects);
    assert_eq!(count(&verification.events, EventKind::ProviderFinished), 4);
}

/// Build the journal a crash would leave: `a` finished with a signed receipt,
/// `b` (idempotent) and `c` (effectful) started and never finished.
fn interrupted(plan: &FrozenPlan, inventory: &InventoryEnvelope) -> (PathBuf, ExecutionReport) {
    let full_dir = temp_dir("full");
    let full = run_with(
        plan,
        inventory,
        &Probe::default(),
        SchedulerConfig::default(),
        Some(recorder(plan, &full_dir)),
        BTreeMap::new(),
    );
    let dir = temp_dir("interrupted");
    fs::create_dir_all(dir.join(RECEIPT_DIR)).unwrap();
    fs::copy(
        receipt_path(&full_dir, "fixture.a").unwrap(),
        receipt_path(&dir, "fixture.a").unwrap(),
    )
    .unwrap();
    let receipt = read_verified_receipt(&dir, "fixture.a", KEY).unwrap();
    let mut journal = Journal::create(&dir, plan.digest(), 1_000).unwrap();
    journal
        .append(EventKind::ProviderStarted, "fixture.a", "sha256:x", 1_010)
        .unwrap();
    journal
        .append(
            EventKind::ProviderFinished,
            "fixture.a",
            &receipt.digest,
            1_020,
        )
        .unwrap();
    journal
        .append(EventKind::ProviderStarted, "fixture.b", "sha256:x", 1_030)
        .unwrap();
    journal
        .append(EventKind::ProviderStarted, "fixture.c", "sha256:x", 1_040)
        .unwrap();
    (dir, full)
}

fn resume_input(plan: &FrozenPlan, dir: &Path) -> ResumeInput {
    ResumeInput {
        plan_digest: plan.digest().to_owned(),
        effective_plan_digest: None,
        planned_providers: ids(plan),
        receipts: load_receipts(dir, KEY).unwrap(),
        idempotent: plan
            .providers()
            .iter()
            .filter(|p| ProviderPolicy::from_provider(p).idempotent())
            .map(|p| p.id.clone())
            .collect::<BTreeSet<_>>(),
        retry_allowed: BTreeSet::new(),
        expected_head: None,
    }
}

fn resume_plan_fixture() -> (FrozenPlan, InventoryEnvelope) {
    freeze(&[
        spec("fixture.a", parallel_safe(), &[]),
        spec("fixture.b", parallel_safe(), &[]),
        spec("fixture.c", effectful(), &[]),
    ])
}

#[test]
fn resume_reuses_verified_reruns_idempotent_and_gaps_effectful() {
    let (plan, inventory) = resume_plan_fixture();
    let (dir, full) = interrupted(&plan, &inventory);
    let input = resume_input(&plan, &dir);
    let (journal, resume_plan) = resume(&dir, &input, 2_000).unwrap();
    assert!(matches!(
        resume_plan.decisions["fixture.a"],
        ResumeDecision::Reuse { .. }
    ));
    assert!(matches!(
        resume_plan.decisions["fixture.b"],
        ResumeDecision::Rerun { .. }
    ));
    assert!(matches!(
        resume_plan.decisions["fixture.c"],
        ResumeDecision::Gap { .. }
    ));

    let mut seeds = BTreeMap::new();
    for (provider, decision) in &resume_plan.decisions {
        match decision {
            ResumeDecision::Reuse { .. } => {
                let stored = read_verified_receipt(&dir, provider, KEY).unwrap();
                seeds.insert(
                    provider.clone(),
                    ProviderSeed::Reuse {
                        execution: stored.body.execution,
                        attempts: stored.body.attempts,
                    },
                );
            }
            ResumeDecision::Gap { reason } => {
                seeds.insert(
                    provider.clone(),
                    ProviderSeed::Failed {
                        reason: format!("resume-gap:{provider}: {reason}"),
                    },
                );
            }
            _ => {}
        }
    }
    let run = Arc::new(RunRecorder::from_journal(
        journal,
        &dir,
        plan.digest(),
        KEY.to_vec(),
    ));
    let probe = Probe::default();
    let report = run_with(
        &plan,
        &inventory,
        &probe,
        SchedulerConfig::default(),
        Some(run.clone()),
        seeds,
    );
    // Reused: not executed again. Idempotent interrupted: executed once.
    // Effectful interrupted: never executed, an explicit gap instead.
    assert_eq!(probe.calls("fixture.a"), 0);
    assert_eq!(probe.calls("fixture.b"), 1);
    assert_eq!(probe.calls("fixture.c"), 0);
    let a = report
        .results
        .iter()
        .find(|e| e.provider == "fixture.a")
        .unwrap();
    let full_a = full
        .results
        .iter()
        .find(|e| e.provider == "fixture.a")
        .unwrap();
    assert_eq!(a, full_a, "reused result is exactly the receipted one");
    assert!(report.gaps.iter().any(|gap| gap.contains("resume-gap")));
    let record = |id: &str| {
        report
            .provider_records
            .iter()
            .find(|r| r.provider == id)
            .unwrap()
            .proof_state
    };
    assert_eq!(record("fixture.a"), ProofState::Validated);
    assert_eq!(record("fixture.b"), ProofState::Validated);
    assert_ne!(record("fixture.c"), ProofState::Validated);

    run.finalize("sha256:report").unwrap();
    let verification = verify_dir(
        &dir,
        plan.digest(),
        &Expectation {
            require_finalized: true,
            ..Expectation::default()
        },
    );
    assert!(verification.is_valid(), "{:?}", verification.defects);
    assert_eq!(count(&verification.events, EventKind::RunResumed), 1);
    // `a` was not started a second time; `b` was closed then restarted.
    assert_eq!(
        kinds(&verification.events, "fixture.a"),
        vec![EventKind::ProviderStarted, EventKind::ProviderFinished]
    );
    assert_eq!(
        kinds(&verification.events, "fixture.b"),
        vec![
            EventKind::ProviderStarted,
            EventKind::ProviderFailed,
            EventKind::ProviderStarted,
            EventKind::ProviderFinished
        ]
    );
    assert_eq!(
        kinds(&verification.events, "fixture.c"),
        vec![EventKind::ProviderStarted, EventKind::ProviderFailed]
    );
}

#[test]
fn resume_refuses_forged_receipts_wrong_plans_and_finalized_runs() {
    let (plan, inventory) = resume_plan_fixture();

    // Receipt content edited after signing.
    let (dir, _) = interrupted(&plan, &inventory);
    let path = receipt_path(&dir, "fixture.a").unwrap();
    let forged = fs::read_to_string(&path)
        .unwrap()
        .replace("\"attempts\":1", "\"attempts\":9");
    fs::write(&path, forged).unwrap();
    let refusal = resume(&dir, &resume_input(&plan, &dir), 2_000)
        .err()
        .expect("forged receipt must refuse");
    assert!(
        refusal
            .reasons
            .iter()
            .any(|reason| reason.contains("failed verification")),
        "{refusal}"
    );

    // Receipt signed with a different key (valid structure, wrong custody).
    let (dir, _) = interrupted(&plan, &inventory);
    let wrong = load_receipts(&dir, b"not-the-plan-key").unwrap();
    let mut input = resume_input(&plan, &dir);
    input.receipts = wrong;
    assert!(resume(&dir, &input, 2_000).is_err());

    // A plan that is not the journal's plan.
    let (dir, _) = interrupted(&plan, &inventory);
    let mut input = resume_input(&plan, &dir);
    input.plan_digest = format!("sha256:{}", "b".repeat(64));
    assert!(resume(&dir, &input, 2_000).is_err());

    // A finalized run has nothing to resume.
    let dir = temp_dir("finalized");
    let run = recorder(&plan, &dir);
    run_with(
        &plan,
        &inventory,
        &Probe::default(),
        SchedulerConfig::default(),
        Some(run.clone()),
        BTreeMap::new(),
    );
    run.finalize("sha256:report").unwrap();
    drop(run);
    let refusal = resume(&dir, &resume_input(&plan, &dir), 2_000)
        .err()
        .expect("finalized run must refuse");
    assert!(refusal
        .reasons
        .iter()
        .any(|reason| reason.contains("already finalized")));
}
