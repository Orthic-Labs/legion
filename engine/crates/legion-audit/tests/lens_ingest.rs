//! Trusted lens ingest: packet -> subagent result -> `ingest_lens_result` ->
//! recomputed verdict. Reasoning lenses count as ran only through ingested,
//! MAC-verified receipts, and every finding needs a verbatim code anchor that
//! matches the file bytes at the frozen revision.

use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use legion_audit::native_providers::reasoning::{
    ingest::{create_epoch, ingest_lens_result, load_epoch, recompute_run, EPOCH_KEY_FILE},
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

const KEY: &[u8] = b"lens-ingest-fixture-signing-key";
const PROVIDER: &str = "reasoning.naming";

fn temp_dir(name: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!(
        "legion-ingest-{name}-{}-{nanos}-{}",
        std::process::id(),
        { static NEXT: ::std::sync::atomic::AtomicU64 = ::std::sync::atomic::AtomicU64::new(0); NEXT.fetch_add(1, ::std::sync::atomic::Ordering::Relaxed) }
    ));
    fs::create_dir_all(&dir).unwrap();
    fs::canonicalize(dir).unwrap()
}

fn spec(id: &str, runner: Value, role: &str, lenses: &[&str], benchmark: Value) -> ProviderSpec {
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
        reasoning: json!({}),
        benchmark,
        clean_claim: "evidence-only".into(),
        control_ids: Vec::new(),
        scopes: Vec::new(),
        selectable: true,
    }
}

fn deterministic(id: &str, benchmark: Value) -> ProviderSpec {
    spec(
        id,
        json!({"kind":"built-in"}),
        "deterministic",
        &[],
        benchmark,
    )
}

fn reasoning_naming() -> ProviderSpec {
    spec(
        PROVIDER,
        json!({"kind":"reasoning-contract","contract":"fixture-reasoning-v1"}),
        "adjudicator",
        &["naming"],
        json!({"status":"unproven","requiredForCleanClaim":false}),
    )
}

/// Completes deterministic providers with exact frozen coverage and leaves
/// reasoning providers to an unavailable host (`pending-host`).
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

struct Run {
    root: PathBuf,
    run: PathBuf,
    work: PendingLensWork,
}

/// Mirrors what `legion audit --out` leaves behind for a signed plan with one
/// pending reasoning lens.
fn setup(name: &str) -> Run {
    let root = temp_dir(name);
    fs::create_dir_all(root.join("src")).unwrap();
    fs::write(
        root.join("src/lib.rs"),
        "pub fn add(a: i32, b: i32) -> i32 {\n    a - b\n}\n",
    )
    .unwrap();
    let repository = root.to_string_lossy().into_owned();
    let inventory = FilesystemInventorySource::new(&root)
        .unwrap()
        .inventory(&repository)
        .unwrap();
    let specs = [
        deterministic(
            "fixture.a",
            json!({"status":"unproven","requiredForCleanClaim":false}),
        ),
        reasoning_naming(),
    ];
    let plan = AuditPlan::compile_with_root(Some(&root), &inventory, &specs)
        .unwrap()
        .freeze(Some(KEY))
        .unwrap();
    let executor = Fixture {
        reasoning: ReasoningProviderExecutor::unavailable(&root),
    };
    let execution = execute(&plan, &inventory, &executor).unwrap();
    assert_eq!(execution.pending_host, vec![PROVIDER]);
    let report = canonical_report(&repository, &execution).unwrap();
    assert_eq!(report.status, ReportStatus::Incomplete);
    let work = pending_lens_work(&root, &plan, &inventory)
        .unwrap()
        .into_iter()
        .next()
        .unwrap();

    let run = root.join(".audit").join("run");
    fs::create_dir_all(run.join("lens-packets")).unwrap();
    let epoch = create_epoch(&run).unwrap();
    let write = |name: &str, value: Value| {
        fs::write(run.join(name), serde_json::to_vec_pretty(&value).unwrap()).unwrap()
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
            "epoch": {"digest": epoch, "keyFile": EPOCH_KEY_FILE},
        }),
    );
    write("report.json", serde_json::to_value(&report).unwrap());
    write("execution.json", serde_json::to_value(&execution).unwrap());
    write(
        &format!("lens-packets/{PROVIDER}.json"),
        serde_json::to_value(&work).unwrap(),
    );
    Run { root, run, work }
}

fn lens_result(run: &Run, findings: Value, withdrawn: Value) -> Value {
    json!({
        "schemaVersion": 1,
        "kind": "legion-lens-result",
        "provider": PROVIDER,
        "packetDigest": canonical_digest(&run.work.request.packet).unwrap(),
        "planDigest": run.work.request.plan_digest,
        "complete": true,
        "findings": findings,
        "withdrawn": withdrawn,
    })
}

fn finding(anchor_text: &str, line: u64) -> Value {
    json!({
        "id": "naming-1",
        "lens": "naming",
        "severity": "medium",
        "confidence": "likely",
        "evidence": ["src/lib.rs:2"],
        "failureScenario": "add subtracts instead of adding",
        "action": "use +",
        "verifyStatus": "unverified",
        "anchor": {"path": "src/lib.rs", "line": line, "text": anchor_text},
    })
}

#[test]
fn before_ingest_the_lens_is_pending_and_the_run_is_not_clean() {
    let run = setup("pending");
    let recomputed = recompute_run(&run.run).unwrap();
    assert_eq!(recomputed.report.status, ReportStatus::Incomplete);
    assert!(recomputed.ingested.is_empty());
    assert_eq!(recomputed.pending, vec![PROVIDER]);
    assert_eq!(recomputed.report.claims["lensesRan"], json!([]));
}

#[test]
fn ingest_round_trip_counts_the_lens_as_ran_and_clean_is_reachable() {
    let run = setup("roundtrip");
    let ingested =
        ingest_lens_result(&run.run, PROVIDER, &lens_result(&run, json!([]), json!([]))).unwrap();
    assert_eq!(ingested.provider, PROVIDER);
    assert!(run
        .run
        .join("lens-receipts")
        .join(format!("{PROVIDER}.json"))
        .is_file());

    let recomputed = recompute_run(&run.run).unwrap();
    assert_eq!(recomputed.ingested, vec![PROVIDER]);
    assert!(recomputed.pending.is_empty());
    assert_eq!(recomputed.report.claims["lensesRan"], json!(["naming"]));
    assert_eq!(
        recomputed.report.claims["reasoningLensesRan"],
        json!(["naming"])
    );
    assert!(
        recomputed.report.gaps.is_empty(),
        "unexpected gaps: {:?}",
        recomputed.report.gaps
    );
    assert_eq!(recomputed.report.status, ReportStatus::Clean);
    // The unqualified deterministic provider completed: a note, not a gap.
    assert_eq!(
        recomputed.execution.coverage_notes,
        vec!["unqualified:fixture.a"]
    );
}

#[test]
fn ingested_findings_with_valid_anchors_become_report_findings() {
    let run = setup("findings");
    let result = lens_result(&run, json!([finding("a - b", 2)]), json!([]));
    let ingested = ingest_lens_result(&run.run, PROVIDER, &result).unwrap();
    assert_eq!(ingested.findings, 1);
    assert_eq!(ingested.anchors_verified, 1);
    let recomputed = recompute_run(&run.run).unwrap();
    assert_eq!(recomputed.report.status, ReportStatus::Findings);
    assert_eq!(recomputed.report.findings.len(), 1);
    assert_eq!(recomputed.report.findings[0].id.as_str(), "naming-1");
    assert!(recomputed.report.gaps.is_empty());
}

#[test]
fn ingest_rejects_an_anchor_whose_text_does_not_match_the_file() {
    let run = setup("anchor-text");
    let result = lens_result(&run, json!([finding("a + b", 2)]), json!([]));
    let error = ingest_lens_result(&run.run, PROVIDER, &result)
        .unwrap_err()
        .to_string();
    assert!(error.contains("verbatim"), "{error}");
    assert!(!run.run.join("lens-receipts").exists());
    assert_eq!(
        recompute_run(&run.run).unwrap().report.status,
        ReportStatus::Incomplete
    );
}

#[test]
fn ingest_rejects_an_anchor_on_the_wrong_line_or_without_an_anchor() {
    let run = setup("anchor-line");
    let wrong_line = lens_result(&run, json!([finding("a - b", 1)]), json!([]));
    assert!(ingest_lens_result(&run.run, PROVIDER, &wrong_line).is_err());
    let mut unanchored = finding("a - b", 2);
    unanchored.as_object_mut().unwrap().remove("anchor");
    let unanchored = lens_result(&run, json!([unanchored]), json!([]));
    let error = ingest_lens_result(&run.run, PROVIDER, &unanchored)
        .unwrap_err()
        .to_string();
    assert!(error.contains("anchor"), "{error}");
}

#[test]
fn ingest_rejects_withdrawals_without_a_disproving_line() {
    let run = setup("withdrawn");
    let bare = lens_result(
        &run,
        json!([]),
        json!([{"id": "naming-9", "reason": "not a bug"}]),
    );
    assert!(ingest_lens_result(&run.run, PROVIDER, &bare).is_err());
    let forged = lens_result(
        &run,
        json!([]),
        json!([{"id": "naming-9", "reason": "not a bug", "disproof": {"path": "src/lib.rs", "line": 2, "text": "a * b"}}]),
    );
    assert!(ingest_lens_result(&run.run, PROVIDER, &forged).is_err());
    let proven = lens_result(
        &run,
        json!([]),
        json!([{"id": "naming-9", "reason": "not a bug", "disproof": {"path": "src/lib.rs", "line": 2, "text": "a - b"}}]),
    );
    assert_eq!(
        ingest_lens_result(&run.run, PROVIDER, &proven)
            .unwrap()
            .withdrawn,
        1
    );
}

#[test]
fn ingest_rejects_results_not_bound_to_the_packet_or_plan() {
    let run = setup("binding");
    let mut wrong_packet = lens_result(&run, json!([]), json!([]));
    wrong_packet["packetDigest"] = json!(format!("sha256:{}", "0".repeat(64)));
    assert!(ingest_lens_result(&run.run, PROVIDER, &wrong_packet).is_err());
    let mut wrong_plan = lens_result(&run, json!([]), json!([]));
    wrong_plan["planDigest"] = json!(format!("sha256:{}", "1".repeat(64)));
    assert!(ingest_lens_result(&run.run, PROVIDER, &wrong_plan).is_err());
    let mut incomplete = lens_result(&run, json!([]), json!([]));
    incomplete["complete"] = json!(false);
    assert!(ingest_lens_result(&run.run, PROVIDER, &incomplete).is_err());
    assert!(ingest_lens_result(
        &run.run,
        "reasoning.nonexistent",
        &lens_result(&run, json!([]), json!([]))
    )
    .is_err());
}

#[test]
fn ingest_rejects_a_working_tree_that_drifted_from_the_frozen_revision() {
    let run = setup("drift");
    fs::write(
        run.root.join("src/lib.rs"),
        "pub fn add(a: i32, b: i32) -> i32 {\n    a + b\n}\n",
    )
    .unwrap();
    let result = lens_result(&run, json!([]), json!([]));
    let error = ingest_lens_result(&run.run, PROVIDER, &result)
        .unwrap_err()
        .to_string();
    assert!(error.contains("SOURCE_DRIFT"), "{error}");
}

#[test]
fn a_tampered_or_foreign_receipt_is_not_counted() {
    let run = setup("tamper");
    ingest_lens_result(&run.run, PROVIDER, &lens_result(&run, json!([]), json!([]))).unwrap();
    let receipt_path = run
        .run
        .join("lens-receipts")
        .join(format!("{PROVIDER}.json"));
    let original = fs::read_to_string(&receipt_path).unwrap();

    // Result altered after the MAC was minted.
    let mut altered: Value = serde_json::from_str(&original).unwrap();
    altered["result"]["details"]["lensFindings"] = json!([{"id": "injected"}]);
    fs::write(&receipt_path, serde_json::to_vec(&altered).unwrap()).unwrap();
    assert!(recompute_run(&run.run).is_err());
    fs::write(&receipt_path, &original).unwrap();
    assert!(recompute_run(&run.run).is_ok());

    // A receipt minted under another epoch key is rejected.
    let other = temp_dir("tamper-other").join("run");
    create_epoch(&other).unwrap();
    fs::copy(other.join(EPOCH_KEY_FILE), run.run.join(EPOCH_KEY_FILE)).ok();
    assert!(recompute_run(&run.run).is_err());
}

#[test]
fn a_hand_set_lenses_ran_claim_is_not_an_ingested_lens() {
    let run = setup("handedit");
    // Without a receipt the recomputed verdict ignores whatever report.json claims.
    let mut report: Value =
        serde_json::from_slice(&fs::read(run.run.join("report.json")).unwrap()).unwrap();
    report["claims"]["lensesRan"] = json!(["naming"]);
    report["status"] = json!("clean");
    report["gaps"] = json!([]);
    fs::write(
        run.run.join("report.json"),
        serde_json::to_vec(&report).unwrap(),
    )
    .unwrap();
    let recomputed = recompute_run(&run.run).unwrap();
    assert_eq!(recomputed.report.status, ReportStatus::Incomplete);
    assert_eq!(recomputed.report.claims["lensesRan"], json!([]));
}

#[cfg(unix)]
#[test]
fn epoch_key_is_private_and_loose_permissions_are_refused() {
    use std::os::unix::fs::PermissionsExt;
    let dir = temp_dir("epoch").join("run");
    let digest = create_epoch(&dir).unwrap();
    let mode = fs::metadata(dir.join(EPOCH_KEY_FILE))
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o600);
    assert_eq!(load_epoch(&dir).unwrap().1, digest);
    fs::set_permissions(dir.join(EPOCH_KEY_FILE), fs::Permissions::from_mode(0o644)).unwrap();
    assert!(load_epoch(&dir).is_err());
}

// --- qualification ---------------------------------------------------------

fn run_deterministic(benchmark: Value) -> legion_audit::ExecutionReport {
    let root = temp_dir("qualification");
    fs::create_dir_all(root.join("src")).unwrap();
    fs::write(root.join("src/lib.rs"), "pub fn f() {}\n").unwrap();
    let inventory = FilesystemInventorySource::new(&root)
        .unwrap()
        .inventory(&root.to_string_lossy())
        .unwrap();
    let plan = AuditPlan::compile(&inventory, &[deterministic("fixture.q", benchmark)])
        .unwrap()
        .freeze(Some(KEY))
        .unwrap();
    let executor = Fixture {
        reasoning: ReasoningProviderExecutor::unavailable(Path::new(".")),
    };
    execute(&plan, &inventory, &executor).unwrap()
}

#[test]
fn unqualified_provider_blocks_clean_only_when_required_for_clean_claim() {
    let required = run_deterministic(json!({"status":"unproven","requiredForCleanClaim":true}));
    assert!(required
        .gaps
        .iter()
        .any(|gap| gap == "provider-unqualified:fixture.q"));
    assert!(required.coverage_notes.is_empty());

    let optional = run_deterministic(json!({"status":"unproven","requiredForCleanClaim":false}));
    assert!(optional.gaps.is_empty(), "{:?}", optional.gaps);
    assert_eq!(optional.coverage_notes, vec!["unqualified:fixture.q"]);
    let report = canonical_report("fixture", &optional).unwrap();
    assert_eq!(report.status, ReportStatus::Clean);
    assert_eq!(
        report.claims["coverageNotes"],
        json!(["unqualified:fixture.q"])
    );

    let qualified = run_deterministic(json!({
        "status": "qualified",
        "requiredForCleanClaim": true,
        "qualificationDigest": format!("sha256:{}", "a".repeat(64)),
    }));
    assert!(qualified.gaps.is_empty());
    assert!(qualified.coverage_notes.is_empty());
}

#[test]
fn shipped_registry_qualifies_bench_providers_and_never_requires_an_unqualified_one() {
    let raw = fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../src/registry/providers.json"
    ))
    .unwrap();
    let registry: Value = serde_json::from_str(&raw).unwrap();
    let bench = [
        "legacy.security.secrets",
        "legacy.security.node-dependencies",
        "legacy.quality.dead-code",
        "legacy.quality.duplication",
        "legacy.quality.types",
    ];
    let mut qualified = 0;
    for provider in registry["providers"].as_array().unwrap() {
        let id = provider["id"].as_str().unwrap();
        let benchmark = &provider["benchmark"];
        let is_qualified = benchmark["status"] == "qualified";
        if bench.contains(&id) {
            assert!(
                is_qualified,
                "{id} must be qualified by its passing bench class"
            );
            let record = &benchmark["qualification"];
            assert_eq!(record["basis"], "bench-class", "{id}");
            assert_eq!(record["ciJob"], "bench", "{id}");
            assert_eq!(
                benchmark["qualificationDigest"],
                json!(canonical_digest(record).unwrap()),
                "{id} qualification digest must cover its record"
            );
            qualified += 1;
        }
        if benchmark["requiredForCleanClaim"] == json!(true) {
            assert!(
                is_qualified,
                "{id} blocks a clean claim but has no qualification"
            );
        }
    }
    assert_eq!(qualified, bench.len());
}
