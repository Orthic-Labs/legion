//! Scaled audit coverage (design 2026-10-15): frozen review sets, bundled
//! seats and waves, run-budget refusal, sampled ingest completeness, and the
//! sampled quality gate.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};

use legion_audit::native_providers::reasoning::{
    coverage_plan::FrozenCoverage,
    ingest::{
        create_epoch, ingest_lens_result, lens_dispatch_plan, load_epoch, recompute_run,
        write_lens_packets, DispatchLimits, EPOCH_KEY_FILE, LENS_PACKET_DIR,
    },
    pending_lens_work, PendingLensWork, ReasoningProviderExecutor,
};
use legion_audit::{
    canonical_report, execute, AuditError, AuditPlan, AuditProvider, FilesystemInventorySource,
    FrozenPlan, InventoryEnvelope, InventorySource, ProviderExecutor, ProviderKind,
};
use legion_contracts::{
    canonical_digest, Coverage, ProviderId, ProviderResult, ProviderSpec, ProviderStatus,
    ReportStatus,
};
use serde_json::{json, Value};

fn temp_dir(name: &str) -> PathBuf {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!(
        "legion-scaled-{name}-{}-{nanos}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir_all(&dir).unwrap();
    fs::canonicalize(dir).unwrap()
}

fn spec(id: &str, runner: Value, role: &str, lenses: &[&str], reasoning: Value) -> ProviderSpec {
    ProviderSpec {
        schema_version: 2,
        id: ProviderId::new(id).unwrap(),
        provider_version: "1.0.0".into(),
        family: "fixture".into(),
        lens_ids: lenses.iter().map(|lens| (*lens).to_owned()).collect(),
        role: role.into(),
        phase: "source".into(),
        depends_on: Vec::new(),
        consumes: vec!["repository-inventory".into()],
        produces: vec!["provider-result".into()],
        selector: json!({"op":"always"}),
        denominator_kind: "first-party-source-files".into(),
        runner,
        host_capabilities: Vec::new(),
        execution: json!({}),
        reasoning,
        benchmark: json!({"status":"unproven","requiredForCleanClaim":false}),
        clean_claim: "evidence-only".into(),
        control_ids: Vec::new(),
        scopes: Vec::new(),
        selectable: true,
    }
}

struct Fixture {
    reasoning: ReasoningProviderExecutor,
}

impl ProviderExecutor for Fixture {
    fn execute(
        &self,
        provider: &AuditProvider,
        _: &InventoryEnvelope,
    ) -> Result<ProviderResult, AuditError> {
        let digest = provider.configuration["denominatorDigest"]
            .as_str()
            .unwrap()
            .to_owned();
        let count = provider.configuration["denominatorCount"].as_u64().unwrap();
        Ok(ProviderResult {
            schema_version: 1,
            provider: ProviderId::new(&provider.id).unwrap(),
            applicable: true,
            required: provider.required,
            status: ProviderStatus::Complete,
            complete: true,
            coverage: Some(Coverage {
                denominator_digest: digest,
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

    fn execute_bound(
        &self,
        plan: &FrozenPlan,
        provider: &AuditProvider,
        inventory: &InventoryEnvelope,
    ) -> Result<ProviderResult, AuditError> {
        if provider.kind == ProviderKind::HostService {
            return self.reasoning.execute_bound(plan, provider, inventory);
        }
        self.execute(provider, inventory)
    }
}

struct Env {
    run: PathBuf,
    plan: FrozenPlan,
    work: Vec<PendingLensWork>,
}

fn coverage_reasoning(mode: &str, run_token_budget: u64) -> Value {
    json!({"coverageRequest": {"mode": mode, "runTokenBudget": run_token_budget}})
}

/// A run directory shaped like `legion audit --out`: the plan is signed with
/// the run's epoch key and persisted as `nativePlan`, so ingest and
/// `recompute_run` see the frozen coverage plan.
fn build_env(
    name: &str,
    providers: &[(&'static str, &'static str)],
    reasoning: Value,
    files: &[(String, Vec<u8>)],
) -> Env {
    let root = temp_dir(name);
    for (path, content) in files {
        let full = root.join(path);
        fs::create_dir_all(full.parent().unwrap()).unwrap();
        fs::write(full, content).unwrap();
    }
    let repository = root.to_string_lossy().into_owned();
    let inventory = FilesystemInventorySource::new(&root)
        .unwrap()
        .inventory(&repository)
        .unwrap();
    let run = root.join(".audit").join("run");
    fs::create_dir_all(run.join(LENS_PACKET_DIR)).unwrap();
    let epoch = create_epoch(&run).unwrap();
    let (key, _) = load_epoch(&run).unwrap();
    let mut specs = vec![spec(
        "fixture.a",
        json!({"kind":"built-in"}),
        "deterministic",
        &[],
        json!({}),
    )];
    for (provider, lens) in providers {
        specs.push(spec(
            provider,
            json!({"kind":"reasoning-contract","contract":"fixture-reasoning-v1"}),
            "adjudicator",
            &[lens],
            reasoning.clone(),
        ));
    }
    let plan = AuditPlan::compile_with_root(Some(&root), &inventory, &specs)
        .unwrap()
        .freeze(Some(key.as_slice()))
        .unwrap();
    let executor = Fixture {
        reasoning: ReasoningProviderExecutor::unavailable(&root),
    };
    let execution = execute(&plan, &inventory, &executor).unwrap();
    let report = canonical_report(&repository, &execution).unwrap();
    let work = pending_lens_work(&root, &plan, &inventory).unwrap();
    let write = |file: &str, value: Value| {
        fs::write(run.join(file), serde_json::to_vec_pretty(&value).unwrap()).unwrap()
    };
    write(
        "plan.json",
        json!({
            "schemaVersion": 1,
            "kind": "audit-provider-plan",
            "repository": root,
            "binding": {
                "repositoryRevision": execution.generation,
                "inventoryDigest": execution.inventory_digest,
            },
            "seal": {"digest": execution.plan_digest, "authenticity": "hmac-sha256", "signature": execution.plan_signature},
            "providers": execution.planned_providers,
            "nativePlan": {
                "schemaVersion": 1,
                "plan": serde_json::to_value(plan.plan()).unwrap(),
                "digest": plan.digest(),
                "signature": plan.signature(),
            },
            "epoch": {"digest": epoch, "keyFile": EPOCH_KEY_FILE},
        }),
    );
    write("report.json", serde_json::to_value(&report).unwrap());
    write("execution.json", serde_json::to_value(&execution).unwrap());
    write_lens_packets(&run.join(LENS_PACKET_DIR), &work).unwrap();
    Env { run, plan, work }
}

fn filler_file(file: usize, bytes: usize) -> Vec<u8> {
    let mut out = String::new();
    let mut line = 0usize;
    while out.len() < bytes {
        if line % 40 == 0 {
            out.push_str(&format!("pub fn f_{file}_{line}() {{\n"));
        } else {
            out.push_str(&format!("    let value_{file}_{line} = compute({line}); // padding padding\n"));
        }
        line += 1;
    }
    out.into_bytes()
}

fn plain_files(count: usize, bytes: usize) -> Vec<(String, Vec<u8>)> {
    (0..count)
        .map(|index| (format!("src/a{index:04}.rs"), filler_file(index, bytes)))
        .collect()
}

fn lens_result(item: &PendingLensWork) -> Value {
    json!({
        "schemaVersion": 1,
        "kind": "legion-lens-result",
        "provider": item.provider_id,
        "packetDigest": canonical_digest(&item.request.packet).unwrap(),
        "planDigest": item.request.plan_digest,
        "complete": true,
        "findings": [],
        "withdrawn": [],
    })
}

fn frozen_coverage(env: &Env, provider: &str) -> FrozenCoverage {
    let plan = env.plan.plan();
    let found = plan
        .providers
        .iter()
        .find(|candidate| candidate.id == provider)
        .unwrap();
    FrozenCoverage::from_value(&found.configuration["coverage"]).expect("frozen coverage")
}

const PERFORMANCE: (&str, &str) = ("reasoning.performance", "performance");

#[test]
fn sampled_lens_is_complete_once_its_review_set_is_ingested_and_the_gate_is_sampled() {
    let files = plain_files(150, 25_000);
    let env = build_env(
        "sampled-complete",
        &[PERFORMANCE],
        coverage_reasoning("risk-sampled", 400_000),
        &files,
    );
    let frozen = frozen_coverage(&env, PERFORMANCE.0);
    assert!(frozen.is_sampled());
    assert!(
        frozen.review_set.len() >= 30 && frozen.review_set.len() < 150,
        "review set {}",
        frozen.review_set.len()
    );
    // Packets carry only review-set paths and home every one of them.
    let mut homed: BTreeSet<String> = BTreeSet::new();
    for item in &env.work {
        for excerpt in item.request.packet["excerpts"].as_array().unwrap() {
            assert!(frozen
                .review_set
                .contains(excerpt["path"].as_str().unwrap()));
            assert_eq!(excerpt["mode"], "regions");
        }
        let coverage = &item.request.packet["excerptCoverage"];
        assert_eq!(coverage["coverageMode"], "risk-sampled");
        assert_eq!(coverage["reviewSetDigest"], json!(frozen.review_set_digest));
        assert_eq!(
            coverage["declaredUnsampledCount"],
            json!(150 - frozen.review_set.len())
        );
        let paths = item.request.packet["part"]["paths"]
            .as_array()
            .cloned()
            .unwrap_or_else(|| {
                coverage["examinedPaths"].as_array().unwrap().clone()
            });
        homed.extend(paths.iter().map(|p| p.as_str().unwrap().to_owned()));
    }
    assert_eq!(homed, frozen.review_set);

    let total = env.work.len();
    let mut last = None;
    for item in &env.work {
        last = Some(ingest_lens_result(&env.run, item.provider_id.as_str(), &lens_result(item)).unwrap());
    }
    let last = last.unwrap();
    assert!(last.complete, "{:?}", last.coverage_gaps);
    // The numeric coverage keeps the frozen denominator binding.
    assert_eq!((last.examined, last.expected), (150, 150));
    assert!(total >= 1);

    let done = recompute_run(&env.run).unwrap();
    assert_eq!(done.report.status, ReportStatus::Clean, "{:?}", done.report.gaps);
    assert_eq!(done.report.claims["auditStatus"], "pass");
    // A clean sampled run is `sampled`, never `proven`.
    assert_eq!(done.report.claims["qualityGate"], "sampled");
    assert_eq!(done.report.claims["coverageMode"], "sampled");
    assert_eq!(
        done.report.claims["auditLabel"],
        "whole-repository risk-sampled audit"
    );
    let claim = &done.report.claims["lensCoverage"][PERFORMANCE.0];
    assert_eq!(claim["mode"], "risk-sampled");
    assert_eq!(claim["denominator"], 150);
    assert_eq!(claim["reviewSet"], json!(frozen.review_set.len()));
    assert_eq!(claim["examined"], json!(frozen.review_set.len()));
    assert_eq!(claim["status"], "ingested");
    let remainder = claim["strata"]
        .as_array()
        .unwrap()
        .iter()
        .find(|stratum| stratum["name"] == "remainder")
        .unwrap();
    assert_eq!(remainder["confidence"]["method"], "rule-of-three");
}

#[test]
fn a_review_set_path_that_could_not_be_examined_is_still_a_gap() {
    let mut files = plain_files(120, 25_000);
    // `auth` paths are mandatory, so this path is always in the review set; a
    // NUL byte makes it unexcerptable (omitted: binary).
    files.push(("src/auth/blob.rs".to_owned(), b"fn a() {}\0\0\0".to_vec()));
    let env = build_env(
        "sampled-gap",
        &[PERFORMANCE],
        coverage_reasoning("risk-sampled", 400_000),
        &files,
    );
    let frozen = frozen_coverage(&env, PERFORMANCE.0);
    assert!(frozen.review_set.contains("src/auth/blob.rs"));
    let mut last = None;
    for item in &env.work {
        last = Some(ingest_lens_result(&env.run, item.provider_id.as_str(), &lens_result(item)).unwrap());
    }
    let last = last.unwrap();
    assert!(!last.complete);
    assert!(
        last.coverage_gaps
            .iter()
            .any(|gap| gap.starts_with("reasoning-excerpt-coverage:") && gap.contains("review-set")),
        "{:?}",
        last.coverage_gaps
    );
    let done = recompute_run(&env.run).unwrap();
    assert_eq!(done.report.status, ReportStatus::Incomplete);
    assert_eq!(done.report.claims["qualityGate"], "unproven");
    assert_eq!(done.report.claims["coverageMode"], "sampled");
    assert_eq!(
        done.report.claims["lensCoverage"][PERFORMANCE.0]["status"],
        "ingested-partial"
    );
}

#[test]
fn a_packet_for_a_different_review_set_is_refused() {
    let env = build_env(
        "sampled-tamper",
        &[PERFORMANCE],
        coverage_reasoning("risk-sampled", 400_000),
        &plain_files(150, 25_000),
    );
    let item = &env.work[0];
    let mut forged = item.clone();
    forged.request.packet["excerptCoverage"]["reviewSetDigest"] = json!("sha256:forged");
    let name = format!("{}.json", item.packet_file_stem());
    fs::write(
        env.run.join(LENS_PACKET_DIR).join(&name),
        serde_json::to_vec_pretty(&forged).unwrap(),
    )
    .unwrap();
    // The forged packet no longer matches its request id first, but even a
    // consistent forgery would fail the frozen review-set check; either way it
    // is refused.
    let result = ingest_lens_result(&env.run, item.provider_id.as_str(), &lens_result(&forged));
    assert!(result.is_err());
}

#[test]
fn lenses_of_one_bundle_share_seats_and_waves_follow_the_tier_order() {
    let providers = [
        ("reasoning.performance", "performance"),
        ("reasoning.correctness", "correctness"),
        ("reasoning.security", "security"),
    ];
    let env = build_env(
        "bundles",
        &providers,
        coverage_reasoning("exhaustive", 6_000_000),
        &plain_files(60, 25_000),
    );
    let limits = DispatchLimits {
        seat_token_budget: 200_000,
        ..DispatchLimits::default()
    };
    let plan = lens_dispatch_plan(&env.work, &limits);
    let parts_of = |provider: &str| {
        env.work
            .iter()
            .filter(|item| item.provider_id == provider)
            .count() as u64
    };
    // security + correctness (bundle J1) read each part once; performance (S1)
    // is its own bundle.
    let expected_seats = parts_of("reasoning.performance") + parts_of("reasoning.security");
    assert_eq!(plan["requiredSeats"], json!(expected_seats));
    let seats = plan["seats"].as_array().unwrap();
    assert_eq!(seats[0]["tier"], "judgment", "judgment seats are scheduled first");
    assert!(seats
        .iter()
        .any(|seat| seat["providers"].as_array().unwrap().len() == 2));
    assert_eq!(plan["waves"], json!(expected_seats.div_ceil(16)));
    assert_eq!(plan["withinLimits"], true, "{:?}", plan["violations"]);
}

fn big_fixture_files() -> Vec<(String, Vec<u8>)> {
    let mut files = Vec::new();
    for index in 0..1100usize {
        let path = match index % 10 {
            0 => format!("src/auth/mod_{index:04}.rs"),
            1 => format!("src/commands/cmd_{index:04}.rs"),
            _ => format!("src/lib/file_{index:04}.rs"),
        };
        files.push((path, filler_file(index, 10_000)));
    }
    files
}

#[test]
fn eleven_hundred_files_fit_the_run_budget_sampled_and_exhaustive_refuses() {
    let providers = [
        ("reasoning.security", "security"),
        ("reasoning.architecture", "architecture"),
        ("reasoning.performance", "performance"),
    ];
    let files = big_fixture_files();
    let limits = DispatchLimits {
        seat_token_budget: 200_000,
        ..DispatchLimits::default()
    };

    let auto = build_env(
        "big-auto",
        &providers,
        coverage_reasoning("auto", 6_000_000),
        &files,
    );
    let plan = lens_dispatch_plan(&auto.work, &limits);
    assert_eq!(plan["coverageMode"], "risk-sampled");
    assert_eq!(plan["withinLimits"], true, "{:?}", plan["violations"]);
    assert!(plan["requiredSeats"].as_u64().unwrap() <= 48);
    assert!(plan["estimatedTokens"].as_u64().unwrap() <= 6_000_000);

    let exhaustive = build_env(
        "big-exhaustive",
        &providers,
        coverage_reasoning("exhaustive", 6_000_000),
        &files,
    );
    let refused = lens_dispatch_plan(&exhaustive.work, &limits);
    assert_eq!(refused["coverageMode"], "exhaustive");
    assert_eq!(refused["withinLimits"], false);
    assert!(
        refused["violations"]
            .as_array()
            .unwrap()
            .iter()
            .any(|violation| violation.as_str().unwrap().contains("over the run budget")),
        "{:?}",
        refused["violations"]
    );
}
