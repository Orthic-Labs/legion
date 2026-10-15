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
    coverage_plan::{effective_review_set_digest, FrozenCoverage},
    ingest::{
        create_epoch, ingest_lens_result, lens_dispatch_plan, load_epoch,
        merge_adjudication_results, recompute_run, write_lens_packets, DispatchLimits,
        EPOCH_KEY_FILE, LENS_PACKET_DIR,
    },
    pending_lens_work, pending_lens_work_with_candidates, PendingLensWork,
    ReasoningProviderExecutor, ScannerCandidate, INVENTORY_SNAPSHOT_FILE,
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
    root: PathBuf,
    run: PathBuf,
    plan: FrozenPlan,
    inventory: InventoryEnvelope,
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
    Env {
        root,
        run,
        plan,
        inventory,
        work,
    }
}

fn filler_file(file: usize, bytes: usize) -> Vec<u8> {
    let mut out = String::new();
    let mut line = 0usize;
    while out.len() < bytes {
        if line % 40 == 0 {
            out.push_str(&format!("pub fn f_{file}_{line}() {{\n"));
        } else {
            out.push_str(&format!(
                "    let value_{file}_{line} = compute({line}); // padding padding\n"
            ));
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
    // Semantic-axis lenses must report their semantic review with a verbatim
    // source line (first line of `src/a0000.rs`, see `filler_file`).
    let details = match item.provider_id.as_str() {
        "reasoning.correctness" => json!({"semanticReview": {
            "axis": "spec", "status": "pass", "reason": "fixture source reviewed",
            "sources": [{"location": "src/a0000.rs:1", "quote": "pub fn f_0_0() {"}]
        }}),
        "reasoning.ai-slop" => json!({"semanticReview": {
            "axis": "standards", "status": "pass", "reason": "fixture source reviewed",
            "sources": [{"location": "src/a0000.rs:1", "quote": "pub fn f_0_0() {"}]
        }}),
        _ => Value::Null,
    };
    json!({
        "details": details,
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
            .unwrap_or_else(|| coverage["examinedPaths"].as_array().unwrap().clone());
        homed.extend(paths.iter().map(|p| p.as_str().unwrap().to_owned()));
    }
    assert_eq!(homed, frozen.review_set);

    let total = env.work.len();
    let mut last = None;
    for item in &env.work {
        last = Some(
            ingest_lens_result(&env.run, item.provider_id.as_str(), &lens_result(item)).unwrap(),
        );
    }
    let last = last.unwrap();
    assert!(last.complete, "{:?}", last.coverage_gaps);
    // The numeric coverage keeps the frozen denominator binding.
    assert_eq!((last.examined, last.expected), (150, 150));
    assert!(total >= 1);

    let done = recompute_run(&env.run).unwrap();
    assert_eq!(
        done.report.status,
        ReportStatus::Clean,
        "{:?}",
        done.report.gaps
    );
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
        last = Some(
            ingest_lens_result(&env.run, item.provider_id.as_str(), &lens_result(item)).unwrap(),
        );
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
    assert_eq!(
        seats[0]["tier"], "judgment",
        "judgment seats are scheduled first"
    );
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

/// About 1,070 files of mixed sizes with a large mandatory (security-sensitive)
/// stratum, shaped like the Ember baseline that refused to freeze.
fn ember_like_files() -> Vec<(String, Vec<u8>)> {
    const SIZES: [usize; 6] = [1_000, 2_000, 4_000, 8_000, 12_000, 24_000];
    let mut files = Vec::new();
    for index in 0..200usize {
        files.push((
            format!("src/auth/guard_{index:04}.rs"),
            filler_file(index, 10_000),
        ));
    }
    for index in 200..1070usize {
        files.push((
            format!("src/lib/file_{index:04}.rs"),
            filler_file(index, SIZES[index % SIZES.len()]),
        ));
    }
    files
}

const EMBER_PROVIDERS: [(&str, &str); 11] = [
    ("reasoning.security", "security"),
    ("reasoning.correctness", "correctness"),
    ("reasoning.schema", "schema"),
    ("reasoning.architecture", "architecture"),
    ("reasoning.doc-drift", "doc-drift"),
    ("reasoning.performance", "performance"),
    ("reasoning.resilience", "resilience"),
    ("reasoning.minimize", "minimize"),
    ("reasoning.ai-slop", "ai-slop"),
    ("reasoning.naming", "naming"),
    ("reasoning.dead-file", "dead-file"),
];

#[test]
fn ember_like_auto_plan_freezes_with_every_seat_within_budget() {
    let env = build_env(
        "ember-auto",
        &EMBER_PROVIDERS,
        coverage_reasoning("auto", 6_000_000),
        &ember_like_files(),
    );
    let limits = DispatchLimits::default();
    let plan = lens_dispatch_plan(&env.work, &limits);
    assert_eq!(plan["coverageMode"], "risk-sampled");
    assert_eq!(plan["withinLimits"], true, "{:?}", plan["violations"]);
    assert!(plan["requiredSeats"].as_u64().unwrap() <= 48, "{plan:#}");
    assert!(plan["estimatedTokens"].as_u64().unwrap() <= 6_000_000);
    for seat in plan["seats"].as_array().unwrap() {
        assert!(
            seat["estimatedTokens"].as_u64().unwrap() <= limits.seat_token_budget,
            "seat over the per-seat budget: {seat:#}"
        );
    }

    // Mandatory coverage never shrinks, even for the Raw minimize bundle whose
    // mandatory stratum exceeds its share: it borrows instead of refusing.
    let frozen = frozen_coverage(&env, "reasoning.minimize");
    assert!(frozen.is_sampled());
    let mandatory = frozen
        .strata
        .as_array()
        .unwrap()
        .iter()
        .find(|stratum| stratum["name"] == "mandatory")
        .unwrap();
    assert_eq!(mandatory["N"], mandatory["n"], "mandatory stratum shrank");
    assert!(mandatory["N"].as_u64().unwrap() >= 200, "{mandatory:#}");
    let s3 = plan["bundles"]
        .as_array()
        .unwrap()
        .iter()
        .find(|bundle| bundle["bundle"] == "S3")
        .unwrap();
    assert!(
        s3["overBy"].as_u64().unwrap() > 0,
        "the fixture must overrun the S3 share: {s3:#}"
    );

    // Byte accounting: per-lens packets carry their own copy of the shared
    // excerpts, seats read them once; the report states both.
    let seat_read = plan["seatReadBytes"].as_u64().unwrap();
    let per_lens = plan["perLensPacketBytes"].as_u64().unwrap();
    let unique = plan["uniqueExcerptBytes"].as_u64().unwrap();
    let saved = plan["sharedExcerptBytesSaved"].as_u64().unwrap();
    assert_eq!(plan["packetBytes"].as_u64().unwrap(), seat_read);
    assert_eq!(per_lens, seat_read + saved);
    assert!(saved > 0, "bundled lenses share excerpts");
    assert!(unique <= seat_read && seat_read <= per_lens);
    let lens_sum: u64 = plan["lenses"]
        .as_array()
        .unwrap()
        .iter()
        .map(|lens| lens["packetBytes"].as_u64().unwrap())
        .sum();
    assert_eq!(lens_sum, per_lens);
}

#[test]
fn ember_like_plan_still_refuses_when_the_run_budget_is_genuinely_exceeded() {
    let env = build_env(
        "ember-tight",
        &EMBER_PROVIDERS,
        coverage_reasoning("auto", 1_000_000),
        &ember_like_files(),
    );
    let limits = DispatchLimits {
        run_token_budget: 1_000_000,
        ..DispatchLimits::default()
    };
    let plan = lens_dispatch_plan(&env.work, &limits);
    assert_eq!(plan["withinLimits"], false);
    assert!(
        plan["violations"]
            .as_array()
            .unwrap()
            .iter()
            .any(|violation| violation.as_str().unwrap().contains("over the run budget")),
        "{:?}",
        plan["violations"]
    );
}

// ---------------------------------------------------------------------------
// Findings promotion stays inside the frozen run budget; packets reference the
// inventory instead of embedding it; batched ingest equals sequential ingest.
// ---------------------------------------------------------------------------

fn candidate(path: &str, severity: &str, number: usize) -> ScannerCandidate {
    ScannerCandidate {
        finding_id: format!("sc-{number:04}"),
        provider: "legacy.security.scanner".into(),
        rule: "fixture-rule".into(),
        severity: severity.into(),
        path: Some(path.into()),
        line: Some(3),
        message: "fixture".into(),
        evidence_excerpt: None,
    }
}

fn promotion_fixture_files() -> Vec<(String, Vec<u8>)> {
    let mut files = plain_files(150, 25_000);
    // Security-sensitive paths are mandatory: promotion must never shrink them.
    files.push(("src/security/guard.rs".into(), filler_file(900, 25_000)));
    files.push(("src/security/verify.rs".into(), filler_file(901, 25_000)));
    files
}

fn outside_review_set(files: &[(String, Vec<u8>)], frozen: &FrozenCoverage) -> Vec<String> {
    let mut outside: Vec<String> = files
        .iter()
        .map(|(path, _)| path.clone())
        .filter(|path| !frozen.review_set.contains(path))
        .collect();
    outside.sort();
    outside
}

fn string_list(value: &Value) -> Vec<String> {
    value
        .as_array()
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(ToOwned::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

fn carried_paths(work: &[PendingLensWork]) -> BTreeSet<String> {
    let mut paths = BTreeSet::new();
    for item in work {
        for excerpt in item.request.packet["excerpts"].as_array().unwrap() {
            paths.insert(excerpt["path"].as_str().unwrap().to_owned());
        }
    }
    paths
}

/// Diagnostic split of packet bytes: per part, total bytes, excerpt bytes,
/// excerpt count, distinct paths, and the bytes of each non-excerpt field.
fn packet_breakdown(work: &[PendingLensWork]) -> String {
    let mut lines = Vec::new();
    for item in work {
        let packet = &item.request.packet;
        let total = serde_json::to_vec(packet).unwrap().len();
        let excerpts = packet["excerpts"].as_array().cloned().unwrap_or_default();
        let excerpt_bytes = serde_json::to_vec(&excerpts).unwrap().len();
        let paths: BTreeSet<&str> = excerpts
            .iter()
            .filter_map(|excerpt| excerpt["path"].as_str())
            .collect();
        let mut fields: Vec<String> = packet
            .as_object()
            .map(|object| {
                object
                    .iter()
                    .filter(|(key, _)| key.as_str() != "excerpts")
                    .map(|(key, value)| {
                        format!("{key}={}", serde_json::to_vec(value).unwrap().len())
                    })
                    .collect()
            })
            .unwrap_or_default();
        fields.sort();
        let mut per_excerpt: Vec<String> = excerpts
            .iter()
            .map(|excerpt| {
                format!(
                    "{}:{}",
                    excerpt["path"].as_str().unwrap_or("?"),
                    serde_json::to_vec(excerpt).unwrap().len()
                )
            })
            .collect();
        per_excerpt.sort();
        lines.push(format!(
            "[{} total={total} excerpts={excerpt_bytes} n={} paths={} fields: {} | each: {}]",
            item.provider_id,
            excerpts.len(),
            paths.len(),
            fields.join(","),
            per_excerpt.join(",")
        ));
    }
    lines.join("\n")
}

fn within_frozen_dispatch(baseline: &Value, after: &Value) {
    let before_tokens = baseline["estimatedTokens"].as_u64().unwrap();
    let after_tokens = after["estimatedTokens"].as_u64().unwrap();
    // Promoted files replace sampled files of the same estimated cost, so the
    // executed dispatch stays at the frozen plan's size (5% for estimate noise).
    assert!(
        after_tokens * 100 <= before_tokens * 105,
        "promotion grew the dispatch from {before_tokens} to {after_tokens} tokens"
    );
    assert!(
        after["requiredSeats"].as_u64().unwrap() <= baseline["requiredSeats"].as_u64().unwrap(),
        "promotion added seats: {} -> {}",
        baseline["requiredSeats"],
        after["requiredSeats"]
    );
}

#[test]
fn promotion_displaces_lowest_ranked_sampled_files_within_the_frozen_budget() {
    let files = promotion_fixture_files();
    let env = build_env(
        "promotion-within-budget",
        &[PERFORMANCE],
        coverage_reasoning("risk-sampled", 400_000),
        &files,
    );
    let frozen = frozen_coverage(&env, PERFORMANCE.0);
    assert!(frozen.is_sampled());
    assert!(
        !frozen.mandatory.is_empty(),
        "fixture needs mandatory paths"
    );
    let sampled = frozen.review_set.len() - frozen.mandatory.len();
    let outside = outside_review_set(&files, &frozen);
    let wanted = 3usize;
    assert!(sampled >= wanted && outside.len() >= wanted);
    let promoted_paths: Vec<String> = outside[..wanted].to_vec();
    let candidates: Vec<ScannerCandidate> = promoted_paths
        .iter()
        .enumerate()
        .map(|(index, path)| candidate(path, "high", index))
        .collect();

    let limits = DispatchLimits::default();
    let baseline = lens_dispatch_plan(&env.work, &limits);
    let work =
        pending_lens_work_with_candidates(&env.root, &env.plan, &env.inventory, Some(&candidates))
            .unwrap();
    let after = lens_dispatch_plan(&work, &limits);
    within_frozen_dispatch(&baseline, &after);

    let coverage = &work[0].request.packet["excerptCoverage"];
    // Packets carry counts, the digest and a reference, never the lists.
    assert!(coverage.get("promotedPaths").is_none());
    assert!(coverage.get("displacedPaths").is_none());
    let promotion = work[0].promotion.as_ref().expect("promotion document");
    assert_eq!(
        coverage["promotionRef"],
        json!("promotion.reasoning.performance.json")
    );
    assert_eq!(coverage["promotionDigest"], promotion["digest"]);
    assert_eq!(string_list(&promotion["promoted"]), promoted_paths);
    assert_eq!(coverage["promotedCount"], json!(promoted_paths.len()));
    assert_eq!(coverage["unpromotedCount"], json!(0));
    let displaced = string_list(&promotion["displaced"]);
    assert_eq!(coverage["displacedCount"], json!(displaced.len()));
    // Displaced files are frozen sampled files, reported, never mandatory.
    // A promoted file carries its finding's window, so it costs more than the
    // skeleton sampled file it replaces: at least one file is displaced.
    assert!(!displaced.is_empty());
    for path in &displaced {
        assert!(frozen.review_set.contains(path), "{path}");
        assert!(!frozen.mandatory.contains(path), "{path}");
    }
    // The packets carry exactly (frozen review set - displaced) + promoted.
    let mut expected = frozen.review_set.clone();
    for path in &displaced {
        expected.remove(path);
    }
    expected.extend(promoted_paths.iter().cloned());
    let carried = carried_paths(&work);
    assert_eq!(carried, expected);
    assert!(frozen.mandatory.is_subset(&carried), "mandatory shrank");
    // The promotion binds to the frozen plan and is verifiable from it.
    assert_eq!(
        coverage["effectiveReviewSetDigest"],
        json!(
            effective_review_set_digest(&frozen.review_set, &displaced, &promoted_paths).unwrap()
        )
    );
    assert!(coverage["promotionDigest"].is_string());
    assert_eq!(coverage["reviewSetDigest"], json!(frozen.review_set_digest));

    // Ingest accepts the promoted packets and completes without a cap gap.
    write_lens_packets(&env.run.join(LENS_PACKET_DIR), &work).unwrap();
    let mut last = None;
    for item in &work {
        last = Some(
            ingest_lens_result(&env.run, item.provider_id.as_str(), &lens_result(item)).unwrap(),
        );
    }
    let last = last.unwrap();
    assert!(last.complete, "{:?}", last.coverage_gaps);
    assert!(!last
        .coverage_gaps
        .iter()
        .any(|gap| gap.starts_with("lens-promotion-capped")));
}

#[test]
fn promotion_beyond_the_budget_is_capped_by_severity_and_named_as_a_gap() {
    let files = promotion_fixture_files();
    let env = build_env(
        "promotion-capped",
        &[PERFORMANCE],
        coverage_reasoning("risk-sampled", 100_000),
        &files,
    );
    let frozen = frozen_coverage(&env, PERFORMANCE.0);
    let sampled = frozen.review_set.len() - frozen.mandatory.len();
    let outside = outside_review_set(&files, &frozen);
    assert!(
        outside.len() > sampled,
        "fixture must raise more candidates ({}) than the sampled budget ({sampled})",
        outside.len()
    );
    // Severity falls with path order, so the cap must keep a path prefix.
    let candidates: Vec<ScannerCandidate> = outside
        .iter()
        .enumerate()
        .map(|(index, path)| {
            let severity = match index {
                0..=4 => "critical",
                5..=19 => "high",
                _ => "low",
            };
            candidate(path, severity, index)
        })
        .collect();

    let limits = DispatchLimits::default();
    let baseline = lens_dispatch_plan(&env.work, &limits);
    let work =
        pending_lens_work_with_candidates(&env.root, &env.plan, &env.inventory, Some(&candidates))
            .unwrap();
    let after = lens_dispatch_plan(&work, &limits);
    let before_tokens = baseline["estimatedTokens"].as_u64().unwrap();
    let after_tokens = after["estimatedTokens"].as_u64().unwrap();
    if after_tokens * 100 > before_tokens * 105 {
        panic!(
            "promotion grew the dispatch from {before_tokens} to {after_tokens} tokens\nbefore: {}\nafter: {}",
            packet_breakdown(&env.work),
            packet_breakdown(&work)
        );
    }
    within_frozen_dispatch(&baseline, &after);

    let coverage = &work[0].request.packet["excerptCoverage"];
    assert!(coverage.get("promotedPaths").is_none());
    let promotion = work[0].promotion.as_ref().expect("promotion document");
    let promoted = string_list(&promotion["promoted"]);
    let unpromoted = coverage["unpromotedCount"].as_u64().unwrap() as usize;
    assert!(unpromoted > 0);
    assert_eq!(promoted.len() + unpromoted, outside.len());
    assert!(promoted.len() <= sampled);
    // Every critical candidate is promoted before any lower severity.
    assert_eq!(promoted, outside[..promoted.len()].to_vec());
    assert!(promoted.len() >= 5);
    let displaced = string_list(&promotion["displaced"]);
    // Equal-cost files: one displaced file per promoted file, give or take a byte of estimate.
    assert!(
        displaced.len() + 1 >= promoted.len(),
        "{} displaced for {} promoted",
        displaced.len(),
        promoted.len()
    );
    assert!(frozen.mandatory.is_subset(&carried_paths(&work)));

    write_lens_packets(&env.run.join(LENS_PACKET_DIR), &work).unwrap();
    // Ingest fails closed on a missing or altered promotion file.
    let promotion_path = env.run.join("promotion.reasoning.performance.json");
    let original = std::fs::read(&promotion_path).unwrap();
    std::fs::remove_file(&promotion_path).unwrap();
    assert!(
        ingest_lens_result(&env.run, PERFORMANCE.0, &lens_result(&work[0])).is_err(),
        "missing promotion file must reject the packet"
    );
    let mut altered: serde_json::Value = serde_json::from_slice(&original).unwrap();
    altered["promoted"] = json!([]);
    std::fs::write(&promotion_path, serde_json::to_vec(&altered).unwrap()).unwrap();
    assert!(
        ingest_lens_result(&env.run, PERFORMANCE.0, &lens_result(&work[0])).is_err(),
        "altered promotion file must reject the packet"
    );
    std::fs::write(&promotion_path, &original).unwrap();
    let mut last = None;
    for item in &work {
        last = Some(
            ingest_lens_result(&env.run, item.provider_id.as_str(), &lens_result(item)).unwrap(),
        );
    }
    let last = last.unwrap();
    let gap = format!("lens-promotion-capped:{unpromoted}");
    assert!(
        last.coverage_gaps.contains(&gap),
        "{:?}",
        last.coverage_gaps
    );
    assert!(!last.complete);
}

#[test]
fn lens_packets_reference_the_inventory_instead_of_embedding_it() {
    let files = plain_files(40, 4_000);
    let env = build_env(
        "inventory-ref",
        &[PERFORMANCE],
        coverage_reasoning("exhaustive", 6_000_000),
        &files,
    );
    let rebuilt = pending_lens_work(&env.root, &env.plan, &env.inventory).unwrap();
    assert_eq!(env.work.len(), rebuilt.len());
    let inventory_bytes = serde_json::to_vec(&env.inventory).unwrap().len();
    let expected_keys: BTreeSet<&str> = [
        "schemaVersion",
        "kind",
        "provider",
        "contract",
        "binding",
        "lensPlan",
        "excerpts",
        "excerptCoverage",
        "scannerCandidates",
        "triggerEvidence",
        "reportSchemaBody",
        "semanticReviewContract",
        "changeRiskContract",
        "reviewContext",
        "inventoryRef",
        "artifactIds",
        "part",
    ]
    .into_iter()
    .collect();
    for (item, again) in env.work.iter().zip(&rebuilt) {
        let packet = &item.request.packet;
        // Deterministic: a rebuild is byte-equal.
        assert_eq!(
            serde_json::to_vec(packet).unwrap(),
            serde_json::to_vec(&again.request.packet).unwrap()
        );
        assert!(packet.get("projection").is_none());
        assert_eq!(
            packet["inventoryRef"],
            json!({
                "inventoryDigest": env.inventory.digest,
                "snapshotRef": INVENTORY_SNAPSHOT_FILE,
            })
        );
        // Only the inventory field changed shape.
        for key in packet.as_object().unwrap().keys() {
            assert!(expected_keys.contains(key.as_str()), "unexpected key {key}");
        }
        let without_ref = {
            let mut copy = packet.clone();
            copy.as_object_mut().unwrap().remove("inventoryRef");
            serde_json::to_vec(&copy).unwrap().len()
        };
        assert!(serde_json::to_vec(packet).unwrap().len() - without_ref < inventory_bytes);
    }
}

#[test]
fn a_frozen_plan_executes_with_the_digest_it_was_frozen_with() {
    let files = plain_files(12, 2_000);
    let env = build_env(
        "single-build",
        &[PERFORMANCE],
        coverage_reasoning("exhaustive", 6_000_000),
        &files,
    );
    // The CLI builds the plan once and executes that frozen plan against a
    // fresh inventory: a clone of it must execute under the same digest.
    let reused = env.plan.clone();
    assert_eq!(reused.digest(), env.plan.digest());
    assert_eq!(reused.signature(), env.plan.signature());
    let executor = Fixture {
        reasoning: ReasoningProviderExecutor::unavailable(&env.root),
    };
    let fresh = FilesystemInventorySource::new(&env.root)
        .unwrap()
        .inventory(&env.root.to_string_lossy())
        .unwrap();
    assert_eq!(fresh.digest, env.inventory.digest);
    let execution = execute(&reused, &env.inventory, &executor).unwrap();
    assert_eq!(execution.plan_digest, env.plan.digest());
}

#[test]
fn batched_ingest_matches_sequential_ingest() {
    let providers = [PERFORMANCE, ("reasoning.correctness", "correctness")];
    let files = plain_files(20, 3_000);
    let build = |name: &str| {
        build_env(
            name,
            &providers,
            coverage_reasoning("exhaustive", 6_000_000),
            &files,
        )
    };
    let sequential = build("ingest-sequential");
    for item in &sequential.work {
        ingest_lens_result(
            &sequential.run,
            item.provider_id.as_str(),
            &lens_result(item),
        )
        .unwrap();
        recompute_run(&sequential.run).unwrap();
    }
    let batched = build("ingest-batched");
    for item in &batched.work {
        ingest_lens_result(&batched.run, item.provider_id.as_str(), &lens_result(item)).unwrap();
    }
    let one = recompute_run(&batched.run).unwrap();
    let many = recompute_run(&sequential.run).unwrap();
    assert_eq!(one.report.status, many.report.status);
    assert_eq!(one.report.gaps, many.report.gaps);
    assert_eq!(one.report.findings.len(), many.report.findings.len());
    assert_eq!(one.ingested, many.ingested);
    assert_eq!(one.pending, many.pending);
}

fn adjudication_result(verdicts: Value, findings: Value) -> Value {
    json!({
        "schemaVersion": 1,
        "kind": "legion-lens-result",
        "provider": "legacy.security.adjudication",
        "packetDigest": "sha256:aaaa",
        "planDigest": "sha256:bbbb",
        "complete": true,
        "findings": findings,
        "withdrawn": [],
        "verdicts": verdicts,
    })
}

#[test]
fn staged_adjudication_results_merge_into_one_cumulative_result() {
    let batch_rows = json!([
        {"stage": "batch", "batchId": "b1", "candidateId": "c1", "workItemId": "w-b1-c1", "verdict": "confirmed"},
        {"stage": "batch", "batchId": "b1", "candidateId": "c2", "workItemId": "w-b1-c2", "verdict": "dismissed"},
    ]);
    let confirmation_rows = json!([
        {"stage": "confirmation", "candidateId": "c1", "workItemId": "w-b1-c1", "verdict": "confirmed"},
    ]);
    let finding = json!({"id": "adjudicated:c1", "title": "t"});
    let batch = adjudication_result(batch_rows.clone(), json!([]));
    let confirmation = adjudication_result(confirmation_rows.clone(), json!([finding.clone()]));

    // The same workItemId in two stages is two rows; the merge is their union.
    let merged = merge_adjudication_results(&[batch.clone(), confirmation.clone()]).unwrap();
    let single = adjudication_result(
        json!([batch_rows[0], batch_rows[1], confirmation_rows[0]]),
        json!([finding.clone()]),
    );
    assert_eq!(merged, single);

    // Order of the files does not change the verdict set.
    let reversed = merge_adjudication_results(&[confirmation.clone(), batch.clone()]).unwrap();
    let mut rows: Vec<Value> = reversed["verdicts"].as_array().unwrap().clone();
    rows.sort_by_key(|row| row.to_string());
    let mut expected: Vec<Value> = single["verdicts"].as_array().unwrap().clone();
    expected.sort_by_key(|row| row.to_string());
    assert_eq!(rows, expected);

    // A repeated (workItemId, stage) is refused, duplicate or conflicting.
    assert!(merge_adjudication_results(&[batch.clone(), batch.clone()]).is_err());
    let conflicting = adjudication_result(
        json!([{"stage": "batch", "batchId": "b1", "candidateId": "c1", "workItemId": "w-b1-c1", "verdict": "dismissed"}]),
        json!([]),
    );
    assert!(merge_adjudication_results(&[batch.clone(), conflicting]).is_err());
    // Differently bound results never merge.
    let mut other = confirmation;
    other["packetDigest"] = json!("sha256:cccc");
    assert!(merge_adjudication_results(&[batch, other]).is_err());
}
