//! Security variant-analysis follow-up: a confirmed adjudication verdict leaves
//! `security-variant-analysis-pending` on the parent run; the follow-up plan
//! (`<run>/followup/`) runs `legacy.security.variant-analysis` over exactly the
//! confirmed paths, and the gap clears only when the variant result is ingested
//! and the follow-up's digest chain verifies against the parent.

use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use legion_audit::native_providers::reasoning::{
    followup::{compile_followup, FOLLOWUP_DIR, FROZEN_PLAN_FILE, VARIANT_PROVIDER_ID},
    ingest::{create_epoch, ingest_lens_result, recompute_run, EPOCH_KEY_FILE},
    pending_lens_work_with_candidates, scanner_candidates_from_execution, PendingLensWork,
    ReasoningProviderExecutor, ADJUDICATOR_PROVIDER_ID,
};
use legion_audit::{
    canonical_report, execute, AuditError, AuditPlan, AuditProvider, FilesystemInventorySource,
    FrozenPlan, InventoryEnvelope, InventorySource, ProviderExecutor, ProviderKind,
};
use legion_contracts::{
    canonical_digest, Coverage, ProviderId, ProviderResult, ProviderSpec, ProviderStatus,
};
use serde_json::{json, Value};

const SCANNER_PROVIDER_ID: &str = "fixture.scanner";
const KEY: &[u8] = b"variant-followup-fixture-signing-key";
const DB_SOURCE: &str = "fn run(q: &str) {\n    db.execute(&format!(\"select {q}\"));\n}\n";
const DB_ANCHOR: &str = "db.execute(&format!(\"select {q}\"));";

fn temp_dir(name: &str) -> PathBuf {
    static NEXT: ::std::sync::atomic::AtomicU64 = ::std::sync::atomic::AtomicU64::new(0);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!(
        "legion-variant-{name}-{}-{nanos}-{}",
        std::process::id(),
        NEXT.fetch_add(1, ::std::sync::atomic::Ordering::Relaxed)
    ));
    fs::create_dir_all(&dir).unwrap();
    fs::canonicalize(dir).unwrap()
}

/// A hand-built candidate generator. Every non-deterministic provider must name
/// its lenses (`reasoning providers require explicit lens identifiers`), so it
/// carries `security` like the registry's security scanners do.
fn scanner_spec() -> ProviderSpec {
    ProviderSpec {
        schema_version: 2,
        id: ProviderId::new(SCANNER_PROVIDER_ID).unwrap(),
        provider_version: "1.0.0".into(),
        family: "fixture".into(),
        lens_ids: vec!["security".into()],
        role: "candidate-generator".into(),
        phase: "source".into(),
        depends_on: Vec::new(),
        consumes: vec!["repository-inventory".into()],
        produces: vec!["security-candidates".into()],
        selector: json!({"op":"always"}),
        denominator_kind: "first-party-source-files".into(),
        runner: json!({"kind":"built-in"}),
        host_capabilities: Vec::new(),
        execution: json!({}),
        reasoning: json!({}),
        benchmark: json!({"status":"unproven","requiredForCleanClaim":false}),
        clean_claim: "evidence-only".into(),
        control_ids: Vec::new(),
        scopes: Vec::new(),
        selectable: true,
    }
}

/// The shipped registry entry for `id`, exactly as production freezes it.
fn registry_spec(id: &str) -> ProviderSpec {
    let raw = fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../src/registry/providers.json"
    ))
    .unwrap();
    let registry: Value = serde_json::from_str(&raw).unwrap();
    let entry = registry["providers"]
        .as_array()
        .unwrap()
        .iter()
        .find(|provider| provider["id"] == id)
        .unwrap_or_else(|| panic!("{id} is not in the shipped registry"))
        .clone();
    serde_json::from_value(entry).unwrap()
}

fn adjudication_spec() -> ProviderSpec {
    registry_spec(ADJUDICATOR_PROVIDER_ID)
}

/// The registry's variant provider: frozen with an empty `confirmedSecurityFinding`
/// denominator in the parent plan.
fn variant_spec() -> ProviderSpec {
    registry_spec(VARIANT_PROVIDER_ID)
}

/// Candidate generators may not emit findings; they raise candidates under
/// `details.candidates` ({id, ruleId, claim, severityHint, evidence:[{file,line}]}).
fn scanner_details(provider: &str) -> BTreeMap<String, Value> {
    let mut details = BTreeMap::new();
    if provider == SCANNER_PROVIDER_ID {
        details.insert(
            "candidates".into(),
            json!([
                {
                    "id": "cand-sql",
                    "ruleId": "sql-concat",
                    "claim": "query built by interpolation",
                    "severityHint": "high",
                    "evidence": [{"file": "src/db.rs", "line": 2}],
                },
                {
                    "id": "cand-doc",
                    "ruleId": "todo-marker",
                    "claim": "marker",
                    "severityHint": "low",
                    "evidence": [{"file": "src/other.rs", "line": 1}],
                },
            ]),
        );
    }
    details
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
            details: scanner_details(&provider.id),
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

struct Run {
    run: PathBuf,
    adjudication: PendingLensWork,
}

fn write_json(path: &Path, value: &Value) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, serde_json::to_vec_pretty(value).unwrap()).unwrap();
}

fn read_json(path: &Path) -> Value {
    serde_json::from_slice(&fs::read(path).unwrap()).unwrap()
}

/// What `legion audit --out` leaves behind for a signed plan whose adjudication
/// lens is pending, with two scanner candidates (one in `src/db.rs`, one in
/// `src/other.rs`).
fn setup(name: &str) -> Run {
    let root = temp_dir(name);
    fs::create_dir_all(root.join("src")).unwrap();
    fs::write(root.join("src/db.rs"), DB_SOURCE).unwrap();
    fs::write(root.join("src/other.rs"), "pub fn other() {}\n").unwrap();
    let repository = root.to_string_lossy().into_owned();
    let inventory = FilesystemInventorySource::new(&root)
        .unwrap()
        .inventory(&repository)
        .unwrap();
    let specs = [scanner_spec(), adjudication_spec(), variant_spec()];
    let plan = AuditPlan::compile_with_root(Some(&root), &inventory, &specs)
        .unwrap()
        .freeze(Some(KEY))
        .unwrap();
    let executor = Fixture {
        reasoning: ReasoningProviderExecutor::unavailable(&root),
    };
    let execution = execute(&plan, &inventory, &executor).unwrap();
    // The variant provider's frozen denominator is empty, so it is not applicable.
    assert_eq!(execution.pending_host, vec![ADJUDICATOR_PROVIDER_ID]);
    let report = canonical_report(&repository, &execution).unwrap();

    let candidates = scanner_candidates_from_execution(&root, &plan, &execution);
    assert_eq!(candidates.len(), 2, "{candidates:?}");
    assert_eq!(candidates[1].evidence_excerpt.as_deref(), Some(DB_ANCHOR));
    let adjudication =
        pending_lens_work_with_candidates(&root, &plan, &inventory, Some(&candidates))
            .unwrap()
            .into_iter()
            .find(|work| work.provider_id == ADJUDICATOR_PROVIDER_ID)
            .unwrap();

    let run = root.join(".audit").join("run");
    fs::create_dir_all(run.join("lens-packets")).unwrap();
    let epoch = create_epoch(&run).unwrap();
    write_json(
        &run.join("plan.json"),
        &json!({
            "schemaVersion": 1,
            "kind": "audit-provider-plan",
            "repository": root,
            "binding": {
                "repositoryRevision": execution.generation,
                "inventoryDigest": execution.inventory_digest,
            },
            "seal": {"digest": execution.plan_digest, "authenticity": "hmac-sha256", "signature": execution.plan_signature},
            "providers": execution.planned_providers,
            "epoch": {"digest": epoch, "keyFile": EPOCH_KEY_FILE},
        }),
    );
    write_json(
        &run.join("report.json"),
        &serde_json::to_value(&report).unwrap(),
    );
    write_json(
        &run.join("execution.json"),
        &serde_json::to_value(&execution).unwrap(),
    );
    write_json(
        &run.join(format!("lens-packets/{ADJUDICATOR_PROVIDER_ID}.json")),
        &serde_json::to_value(&adjudication).unwrap(),
    );
    Run { run, adjudication }
}

fn verdict(id: &str, confirmed: bool) -> Value {
    if confirmed {
        json!({
            "candidateId": id,
            "verdict": "TRUE_POSITIVE",
            "evidenceStrength": "observed",
            "severity": "high",
            "threatModel": "remote unauthenticated attacker",
            "attackerControl": "full",
            "reachability": "reachable from a public handler",
            "proof": "trace from handler to execute",
            "impact": "data exfiltration",
            "rationale": "user input is interpolated into the query text",
            "sink": "db.execute",
            "evidence": [{"file": "src/db.rs", "line": 2}],
            "devilsAdvocate": "no parameterization found"
        })
    } else {
        json!({
            "candidateId": id,
            "verdict": "FALSE_POSITIVE",
            "threatModel": "marker comment in a helper, not attacker reachable",
            "reachability": "documentation only; no runtime sink is reachable",
            "impact": "no security impact because nothing executes"
        })
    }
}

fn adjudication_result(run: &Run, confirm_sql: bool) -> Value {
    let findings = if confirm_sql {
        json!([{
            "id": "adjudicated:cand-sql",
            "severity": "high",
            "evidence": ["src/db.rs:2"],
            "anchor": {"path": "src/db.rs", "line": 2, "text": DB_ANCHOR},
        }])
    } else {
        json!([])
    };
    json!({
        "schemaVersion": 1,
        "kind": "legion-lens-result",
        "provider": ADJUDICATOR_PROVIDER_ID,
        "packetDigest": canonical_digest(&run.adjudication.request.packet).unwrap(),
        "planDigest": run.adjudication.request.plan_digest,
        "complete": true,
        "findings": findings,
        "withdrawn": [],
        "verdicts": [verdict("cand-sql", confirm_sql), verdict("cand-doc", false)],
    })
}

fn variant_packet(run: &Run) -> PendingLensWork {
    serde_json::from_value(read_json(
        &run.run
            .join(FOLLOWUP_DIR)
            .join(format!("lens-packets/{VARIANT_PROVIDER_ID}.json")),
    ))
    .unwrap()
}

fn variant_result(run: &Run, findings: Value) -> Value {
    let work = variant_packet(run);
    json!({
        "schemaVersion": 1,
        "kind": "legion-lens-result",
        "provider": VARIANT_PROVIDER_ID,
        "packetDigest": canonical_digest(&work.request.packet).unwrap(),
        "planDigest": work.request.plan_digest,
        "complete": true,
        "findings": findings,
        "withdrawn": [],
    })
}

fn variant_finding() -> Value {
    json!({
        "id": "variant-1",
        "lens": "variant-analysis",
        "severity": "high",
        "confidence": "likely",
        "evidence": ["src/db.rs:2"],
        "failureScenario": "the same interpolated query shape recurs",
        "action": "parameterize the query",
        "verifyStatus": "unverified",
        "parentFindingId": "adjudicated:cand-sql",
        "anchor": {"path": "src/db.rs", "line": 2, "text": DB_ANCHOR},
    })
}

fn has_pending_gap(gaps: &[String]) -> bool {
    gaps.iter()
        .any(|gap| gap.starts_with("security-variant-analysis-pending:"))
}

/// A run whose adjudication lens is ingested with `src/db.rs` confirmed.
fn confirmed_run(name: &str) -> Run {
    let run = setup(name);
    ingest_lens_result(
        &run.run,
        ADJUDICATOR_PROVIDER_ID,
        &adjudication_result(&run, true),
    )
    .unwrap();
    run
}

#[test]
fn confirmed_verdict_leaves_the_pending_gap_and_compiles_a_scoped_followup() {
    let run = confirmed_run("scope");
    let before = recompute_run(&run.run).unwrap();
    assert_eq!(before.confirmed_security.len(), 1);
    assert!(
        has_pending_gap(&before.report.gaps),
        "{:?}",
        before.report.gaps
    );

    let planned = compile_followup(&run.run, &variant_spec())
        .unwrap()
        .expect("a confirmed finding needs a follow-up");
    assert!(!planned.reused);
    assert_eq!(planned.confirmed_paths, vec!["src/db.rs".to_owned()]);
    assert_eq!(planned.seeds, 1);
    assert_eq!(planned.provider, VARIANT_PROVIDER_ID);

    // The follow-up plan holds exactly the variant provider over exactly the
    // confirmed paths, signed and bound to the parent plan digest.
    let dir = run.run.join(FOLLOWUP_DIR);
    let frozen: AuditPlan = serde_json::from_value(read_json(&dir.join(FROZEN_PLAN_FILE))).unwrap();
    assert_eq!(frozen.providers.len(), 1);
    assert_eq!(frozen.providers[0].id, VARIANT_PROVIDER_ID);
    assert_eq!(frozen.providers[0].configuration["denominatorCount"], 1);
    let parent_digest = read_json(&run.run.join("plan.json"))["seal"]["digest"].clone();
    assert_eq!(
        frozen.followup_binding().unwrap()["parentPlanDigest"],
        parent_digest
    );
    assert_eq!(planned.parent_plan_digest, parent_digest.as_str().unwrap());
    assert_ne!(
        read_json(&dir.join("plan.json"))["seal"]["digest"],
        parent_digest
    );

    // The packet scopes the denominator to the confirmed file and seeds the
    // lens with the confirmed finding.
    let work = variant_packet(&run);
    assert_eq!(work.request.denominator_paths, vec!["src/db.rs".to_owned()]);
    let seeds = work.request.packet["variantSeeds"].as_array().unwrap();
    assert_eq!(seeds.len(), 1);
    assert_eq!(seeds[0]["rule"], "sql-concat");
    assert_eq!(seeds[0]["path"], "src/db.rs");
    assert_eq!(seeds[0]["line"], 2);
    assert_eq!(seeds[0]["verdict"], "TRUE_POSITIVE");
    assert_eq!(
        seeds[0]["rationale"],
        "user input is interpolated into the query text"
    );
    assert_eq!(seeds[0]["parentFindingId"], "adjudicated:cand-sql");

    // Compiling again is idempotent and keeps the same plan.
    let again = compile_followup(&run.run, &variant_spec())
        .unwrap()
        .unwrap();
    assert!(again.reused);
    assert_eq!(again.plan_digest, planned.plan_digest);

    // Not yet run: the gap stays and the claim says pending.
    let pending = recompute_run(&run.run).unwrap();
    assert!(has_pending_gap(&pending.report.gaps));
    assert_eq!(
        pending.report.claims["securityVariantFollowup"]["status"],
        "pending"
    );
}

#[test]
fn ingesting_the_variant_result_clears_the_parent_gap() {
    let run = confirmed_run("clears");
    compile_followup(&run.run, &variant_spec())
        .unwrap()
        .unwrap();
    let ingested = ingest_lens_result(
        &run.run.join(FOLLOWUP_DIR),
        VARIANT_PROVIDER_ID,
        &variant_result(&run, json!([variant_finding()])),
    )
    .unwrap();
    assert!(ingested.complete);
    assert_eq!((ingested.examined, ingested.expected), (1, 1));

    let after = recompute_run(&run.run).unwrap();
    assert!(
        !has_pending_gap(&after.report.gaps),
        "{:?}",
        after.report.gaps
    );
    assert_eq!(
        after.report.claims["securityVariantFollowup"]["status"],
        "complete"
    );
    // The variant finding joins the parent report next to the adjudicated one.
    let ids: Vec<&str> = after
        .report
        .findings
        .iter()
        .map(|finding| finding.id.as_str())
        .collect();
    assert!(ids.contains(&"adjudicated:cand-sql"), "{ids:?}");
    assert!(ids.contains(&"variant-1"), "{ids:?}");
}

#[test]
fn a_variant_result_with_no_variants_also_clears_the_gap() {
    let run = confirmed_run("none-found");
    compile_followup(&run.run, &variant_spec())
        .unwrap()
        .unwrap();
    ingest_lens_result(
        &run.run.join(FOLLOWUP_DIR),
        VARIANT_PROVIDER_ID,
        &variant_result(&run, json!([])),
    )
    .unwrap();
    let after = recompute_run(&run.run).unwrap();
    assert!(
        !has_pending_gap(&after.report.gaps),
        "{:?}",
        after.report.gaps
    );
}

#[test]
fn omitting_the_variant_result_keeps_the_gap() {
    let run = confirmed_run("omitted");
    compile_followup(&run.run, &variant_spec())
        .unwrap()
        .unwrap();
    // A follow-up that was planned but never ingested is not completion.
    let recomputed = recompute_run(&run.run).unwrap();
    assert!(has_pending_gap(&recomputed.report.gaps));

    // Neither is a follow-up whose ingested receipt has gone missing.
    ingest_lens_result(
        &run.run.join(FOLLOWUP_DIR),
        VARIANT_PROVIDER_ID,
        &variant_result(&run, json!([])),
    )
    .unwrap();
    assert!(!has_pending_gap(
        &recompute_run(&run.run).unwrap().report.gaps
    ));
    fs::remove_dir_all(run.run.join(FOLLOWUP_DIR).join("lens-receipts")).unwrap();
    assert!(has_pending_gap(
        &recompute_run(&run.run).unwrap().report.gaps
    ));
}

#[test]
fn tampering_with_the_parent_digest_keeps_the_gap() {
    // (1) The parent plan.json seal no longer matches the executed parent plan.
    let run = confirmed_run("tamper-parent");
    compile_followup(&run.run, &variant_spec())
        .unwrap()
        .unwrap();
    ingest_lens_result(
        &run.run.join(FOLLOWUP_DIR),
        VARIANT_PROVIDER_ID,
        &variant_result(&run, json!([])),
    )
    .unwrap();
    assert!(!has_pending_gap(
        &recompute_run(&run.run).unwrap().report.gaps
    ));
    let mut plan = read_json(&run.run.join("plan.json"));
    plan["seal"]["digest"] = json!(format!("sha256:{}", "0".repeat(64)));
    write_json(&run.run.join("plan.json"), &plan);
    let tampered = recompute_run(&run.run).unwrap();
    assert!(has_pending_gap(&tampered.report.gaps));
    assert_eq!(
        tampered.report.claims["securityVariantFollowup"]["status"],
        "invalid"
    );

    // (2) The follow-up plan is rebound to a different parent digest.
    let run = confirmed_run("tamper-binding");
    compile_followup(&run.run, &variant_spec())
        .unwrap()
        .unwrap();
    ingest_lens_result(
        &run.run.join(FOLLOWUP_DIR),
        VARIANT_PROVIDER_ID,
        &variant_result(&run, json!([])),
    )
    .unwrap();
    let frozen_path = run.run.join(FOLLOWUP_DIR).join(FROZEN_PLAN_FILE);
    let mut frozen = read_json(&frozen_path);
    frozen["bounds"]["followup"]["parentPlanDigest"] = json!(format!("sha256:{}", "1".repeat(64)));
    write_json(&frozen_path, &frozen);
    let tampered = recompute_run(&run.run).unwrap();
    assert!(has_pending_gap(&tampered.report.gaps));
    assert_eq!(
        tampered.report.claims["securityVariantFollowup"]["status"],
        "invalid"
    );
}

#[test]
fn a_follow_up_scoped_to_other_paths_does_not_clear_the_gap() {
    let run = confirmed_run("rescoped");
    compile_followup(&run.run, &variant_spec())
        .unwrap()
        .unwrap();
    ingest_lens_result(
        &run.run.join(FOLLOWUP_DIR),
        VARIANT_PROVIDER_ID,
        &variant_result(&run, json!([])),
    )
    .unwrap();
    let frozen_path = run.run.join(FOLLOWUP_DIR).join(FROZEN_PLAN_FILE);
    let mut frozen = read_json(&frozen_path);
    frozen["bounds"]["followup"]["confirmedPaths"] = json!(["src/other.rs"]);
    write_json(&frozen_path, &frozen);
    assert!(has_pending_gap(
        &recompute_run(&run.run).unwrap().report.gaps
    ));
}

#[test]
fn no_confirmed_findings_means_no_followup_and_no_gap() {
    let run = setup("unconfirmed");
    ingest_lens_result(
        &run.run,
        ADJUDICATOR_PROVIDER_ID,
        &adjudication_result(&run, false),
    )
    .unwrap();
    let recomputed = recompute_run(&run.run).unwrap();
    assert!(recomputed.confirmed_security.is_empty());
    assert!(!has_pending_gap(&recomputed.report.gaps));
    assert!(compile_followup(&run.run, &variant_spec())
        .unwrap()
        .is_none());
    assert!(!run.run.join(FOLLOWUP_DIR).exists());
}
