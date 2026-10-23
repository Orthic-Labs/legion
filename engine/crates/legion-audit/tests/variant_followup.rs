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
    ingest::{
        create_epoch, ingest_lens_result, load_epoch, recompute_run, write_lens_dispatch,
        DispatchLimits, EPOCH_KEY_FILE, LENS_PACKET_DIR,
    },
    pending_lens_work_with_candidates, scanner_candidates_from_execution,
    security_adjudication::{build_adjudication_plan, required_items, TriageContext},
    PendingLensWork, ReasoningProviderExecutor, ScannerCandidate, ADJUDICATOR_PROVIDER_ID,
};
use legion_audit::{
    canonical_report, execute, AuditError, AuditPlan, AuditProvider, FilesystemInventorySource,
    FrozenPlan, InventoryEnvelope, InventorySource, ProviderExecutor, ProviderKind,
};
use legion_contracts::{
    canonical_digest, Coverage, ProviderId, ProviderResult, ProviderSpec, ProviderStatus,
};
use serde_json::{json, Value};

mod common;
use common::{authenticate, record_budget_usage, verify, FindingDisposition};

const SCANNER_PROVIDER_ID: &str = "fixture.scanner";
const DB_SOURCE: &str = "fn run(q: &str) {\n    db.execute(&format!(\"select {q}\"));\n}\n";
const DB_ANCHOR: &str = "db.execute(&format!(\"select {q}\"));";
const ALT_ANCHOR: &str = "pub fn other_query(q: &str) { db.execute(&format!(\"select {q}\")); }";

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

/// Fixture Git effects stay inside this newly-created temporary repository.
fn fixture_git(root: &Path, args: &[&str]) {
    let mut command = rightkit_child_process::OwnedCommand::new("git");
    command
        .command_mut()
        .current_dir(root)
        .args([
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "commit.gpgsign=false",
        ])
        .args(args)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    let mut child = command.spawn().unwrap();
    assert!(child
        .wait_timeout(std::time::Duration::from_secs(10))
        .unwrap()
        .unwrap()
        .success());
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
                    "domain": "security",
                    "ruleId": "sql-concat",
                    "claim": "query built by interpolation",
                    "severityHint": "high",
                    "evidence": [{"file": "src/db.rs", "line": 2}],
                },
                {
                    "id": "cand-doc",
                    "domain": "security",
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
    setup_with_source(name, DB_SOURCE)
}

/// As `setup`, with `src/db.rs` holding `db_source` (its candidate anchor stays
/// on line 2).
fn setup_with_source(name: &str, db_source: &str) -> Run {
    setup_with_source_and_limits(name, db_source, &DispatchLimits::default())
}

fn setup_with_source_and_limits(name: &str, db_source: &str, limits: &DispatchLimits) -> Run {
    let root = temp_dir(name);
    fs::create_dir_all(root.join("src")).unwrap();
    fs::write(root.join("src/db.rs"), db_source).unwrap();
    fs::write(root.join("src/other.rs"), "pub fn other() {}\n").unwrap();
    fs::create_dir_all(root.join("src/callers")).unwrap();
    fs::write(
        root.join("src/callers/queries.rs"),
        "pub fn query() { db::run(); }\n",
    )
    .unwrap();
    fs::create_dir_all(root.join("src/alternate")).unwrap();
    fs::write(
        root.join("src/alternate/db_access.rs"),
        "pub fn other_query(q: &str) { db.execute(&format!(\"select {q}\")); }\n",
    )
    .unwrap();
    fs::create_dir_all(root.join("src/unrelated")).unwrap();
    fs::write(
        root.join("src/unrelated/else.rs"),
        "pub fn independent() {}\n",
    )
    .unwrap();
    fixture_git(&root, &["init", "-q"]);
    fixture_git(&root, &["config", "user.name", "Audit Fixture"]);
    fixture_git(&root, &["config", "user.email", "audit@example.invalid"]);
    fixture_git(&root, &["add", "src"]);
    fixture_git(&root, &["commit", "-qm", "fixture source"]);
    let source_root = root;
    let snapshot = legion_audit::snapshot::FrozenSnapshot::capture(
        legion_audit::scope::ResolvedScope::resolve(
            &source_root,
            legion_audit::scope::ScopeSpec::Repo,
            None,
        )
        .unwrap(),
    )
    .unwrap();
    let root = snapshot.manifest.execution_root.clone();
    let repository = root.to_string_lossy().into_owned();
    let inventory = FilesystemInventorySource::new(&root)
        .unwrap()
        .inventory(&repository)
        .unwrap();
    let run = source_root.join(".audit").join("run");
    let epoch = create_epoch(&run).unwrap();
    let (key, _) = load_epoch(&run).unwrap();
    let review_context = json!({
        "snapshotManifest": snapshot.manifest_path,
        "snapshotKey": snapshot.manifest.key,
        "sourceRepository": source_root,
    });
    let mut specs = [scanner_spec(), adjudication_spec(), variant_spec()];
    for spec in &mut specs {
        spec.reasoning["reviewContext"] = review_context.clone();
    }
    let plan = AuditPlan::compile_with_root(Some(&root), &inventory, &specs)
        .unwrap()
        .freeze(Some(key.as_slice()))
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

    fs::create_dir_all(run.join("lens-packets")).unwrap();
    write_lens_dispatch(&run, std::slice::from_ref(&adjudication), limits).unwrap();
    write_json(
        &run.join("plan.json"),
        &json!({
            "schemaVersion": 1,
            "kind": "audit-provider-plan",
            "repository": root,
            "reviewContext": review_context,
            "snapshotManifest": snapshot.manifest_path,
            "nativePlan": {"schemaVersion": 1, "digest": plan.digest(), "signature": plan.signature(), "plan": plan.plan()},
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
            "negativeControl": {
                "hypothesis": "a parameterized query removes the injection path",
                "method": "same handler with the input bound as a query parameter",
                "outcome": "the input no longer reaches the query text"
            },
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
            "threatModel": format!("{id}: marker comment in a helper, not attacker reachable"),
            "reachability": format!("{id}: documentation only; no runtime sink is reachable"),
            "impact": format!("{id}: no security impact because nothing executes")
        })
    }
}

/// Every stage of the batched protocol, driven to a fixed point: one batch
/// verdict per cluster representative, then the confirmations, spot-checks and
/// individual reviews the earlier verdicts require.
fn staged_verdicts(run: &Run, confirm_sql: bool) -> Vec<Value> {
    let packet = &run.adjudication.request.packet;
    let candidates: Vec<ScannerCandidate> =
        serde_json::from_value(packet["scannerCandidates"].clone()).unwrap();
    let plan = build_adjudication_plan(
        &candidates,
        &TriageContext::default(),
        packet["candidateWorkItems"]["parentPacketDigest"]
            .as_str()
            .unwrap(),
    )
    .unwrap();
    let survives = |id: &str| id == "cand-sql" && confirm_sql;
    let mut submitted = Vec::new();
    for batch in &plan.batches {
        for cluster_id in &batch.cluster_ids {
            let cluster = plan
                .clusters
                .iter()
                .find(|cluster| &cluster.cluster_id == cluster_id)
                .unwrap();
            let mut verdict = verdict(
                &cluster.representative_id,
                survives(&cluster.representative_id),
            );
            verdict["stage"] = json!("batch");
            verdict["batchId"] = json!(batch.batch_id);
            verdict["clusterId"] = json!(cluster.cluster_id);
            verdict["workItemId"] = json!(batch.item_id);
            verdict["workPacketDigest"] = json!(canonical_digest(&batch.packet).unwrap());
            verdict["contextId"] = json!(batch.context_id);
            submitted.push(verdict);
        }
    }
    for _ in 0..6 {
        let pending = required_items(&plan, &candidates, &submitted)
            .unwrap()
            .into_iter()
            .filter(|item| !item.satisfied)
            .collect::<Vec<_>>();
        if pending.is_empty() {
            break;
        }
        for item in pending {
            let id = item.item.packet.candidate.id.clone();
            let mut verdict = verdict(&id, survives(&id));
            verdict["stage"] = json!(item.stage);
            verdict["workItemId"] = json!(item.item.item_id);
            verdict["workPacketDigest"] = json!(canonical_digest(&item.item.packet).unwrap());
            verdict["contextId"] = json!(item.item.context_id);
            submitted.push(verdict);
        }
    }
    submitted
}

fn mint_stage_receipts(run: &Run, verdicts: &[Value]) {
    use legion_audit::native_providers::reasoning::{
        ingest::mint_runtime_adjudication,
        security_adjudication::{stage_observation, stage_work_item},
    };

    let request = &run.adjudication.request;
    let candidates: Vec<ScannerCandidate> =
        serde_json::from_value(request.packet["scannerCandidates"].clone()).unwrap();
    let parent_digest = request.packet["candidateWorkItems"]["parentPacketDigest"]
        .as_str()
        .unwrap();
    let plan =
        build_adjudication_plan(&candidates, &TriageContext::default(), parent_digest).unwrap();
    let delivered_excerpts = request
        .packet
        .get("excerpts")
        .cloned()
        .unwrap_or_else(|| json!([]));
    let mut ordinal = 0u64;
    let mut mint = |stage_packet: Value, rows: Vec<Value>| {
        ordinal += 1;
        let host = json!({
            "sent": true,
            "processCreated": true,
            "error": null,
            "contextId": format!("fixture-stage-context-{ordinal}"),
            "processId": 20_000 + ordinal,
            "responseDigest": format!("fixture-stage-response-{ordinal}"),
            "deliveredExcerpts": delivered_excerpts,
        });
        record_budget_usage(
            &run.run,
            request,
            "fixture-adjudication-stage",
            legion_contracts::canonical_json_bytes(&stage_packet)
                .unwrap()
                .len() as u64
                + 256,
        );
        let observation = stage_observation(&stage_packet, &rows, &host, &candidates).unwrap();
        mint_runtime_adjudication(&run.run, request, &stage_packet, &observation).unwrap();
    };

    for batch in &plan.batches {
        let rows = verdicts
            .iter()
            .filter(|row| row["stage"] == "batch" && row["workItemId"] == batch.item_id)
            .cloned()
            .collect::<Vec<_>>();
        if rows.is_empty() {
            continue;
        }
        mint(
            json!({
                "schemaVersion": 1,
                "kind": "legion-audit-adjudication-seat",
                "stage": "batch",
                "round": 1,
                "batchId": batch.batch_id,
                "itemId": batch.item_id,
                "contextId": batch.context_id,
                "parentPacketDigest": parent_digest,
                "packet": batch.packet,
            }),
            rows,
        );
    }

    for row in verdicts.iter().filter(|row| row["stage"] != "batch") {
        let stage = row["stage"].as_str().unwrap();
        let id = row["candidateId"].as_str().unwrap();
        let candidate = candidates
            .iter()
            .find(|candidate| candidate.finding_id == id)
            .unwrap();
        let work = stage_work_item(candidate, parent_digest, stage).unwrap();
        let stage_packet = json!({
            "schemaVersion": 1,
            "kind": "legion-audit-adjudication-seat",
            "stage": stage,
            "round": 1,
            "candidateId": id,
            "itemId": work.item_id,
            "contextId": work.context_id,
            "parentPacketDigest": parent_digest,
            "packet": work.packet,
        });
        mint(stage_packet, vec![row.clone()]);
    }
}

fn authenticated_adjudication_result(run: &Run, confirm_sql: bool) -> Value {
    let mut result = adjudication_result(run, confirm_sql);
    mint_stage_receipts(run, result["verdicts"].as_array().unwrap());
    verify(
        &run.run,
        &run.adjudication.request,
        &mut result,
        FindingDisposition::Upheld,
    );
    result
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
    let verdicts = staged_verdicts(run, confirm_sql);
    json!({
        "schemaVersion": 1,
        "kind": "legion-lens-result",
        "provider": ADJUDICATOR_PROVIDER_ID,
        "packetDigest": canonical_digest(&run.adjudication.request.packet).unwrap(),
        "planDigest": run.adjudication.request.plan_digest,
        "complete": true,
        "findings": findings,
        "withdrawn": [],
        "verdicts": verdicts,
    })
}

fn rewrite_request_id(work: &mut PendingLensWork) {
    let request = &mut work.request;
    let signature = if request.plan_signature.is_empty() {
        Value::Null
    } else {
        Value::String(request.plan_signature.clone())
    };
    request.request_id = canonical_digest(&json!({
        "invocationEpoch": "pending-host",
        "packetDigest": canonical_digest(&request.packet).unwrap(),
        "providerId": request.provider_id,
        "contract": request.contract,
        "planDigest": request.plan_digest,
        "planSignature": signature,
        "repositoryId": request.repository_id,
        "inventoryGeneration": request.inventory_generation,
        "inventoryDigest": request.inventory_digest,
        "denominatorDigest": request.denominator_digest,
        "denominatorCount": request.denominator_count,
        "denominatorPaths": request.denominator_paths,
    }))
    .unwrap();
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
    variant_part_result(&variant_packet(run), findings)
}

/// The variant result for one packet (or one numbered part of it).
fn variant_part_result(work: &PendingLensWork, findings: Value) -> Value {
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

fn ingest_fixture(
    run_dir: &Path,
    work: &PendingLensWork,
    mut result: Value,
    disposition: FindingDisposition,
) -> legion_audit::native_providers::reasoning::ingest::IngestedLens {
    authenticate(run_dir, &work.request, &mut result, disposition);
    ingest_lens_result(run_dir, work.provider_id.as_str(), &result).unwrap()
}

/// The variant lens parts on disk of the follow-up, in part order.
fn variant_parts(run: &Run) -> Vec<PendingLensWork> {
    let lens_dir = run.run.join(FOLLOWUP_DIR).join(LENS_PACKET_DIR);
    let prefix = format!("{VARIANT_PROVIDER_ID}.part-");
    let mut files: Vec<PathBuf> = fs::read_dir(&lens_dir)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with(prefix.as_str()))
        })
        .collect();
    files.sort();
    files
        .iter()
        .map(|path| serde_json::from_value(read_json(path)).unwrap())
        .collect()
}

/// `DB_SOURCE` padded to about 1.2 MB, so the one confirmed path is excerpted
/// into several chunks and the variant denominator needs several packet parts.
fn padded_db_source() -> String {
    let mut source = String::from(DB_SOURCE);
    let mut line = 0usize;
    while source.len() < 1_200_000 {
        line += 1;
        source.push_str(&format!(
            "// padding line {line:06} keeps the file past one excerpt part\n"
        ));
    }
    source
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
    confirmed_run_with_source(name, DB_SOURCE)
}

fn confirmed_run_with_source(name: &str, db_source: &str) -> Run {
    let run = setup_with_source(name, db_source);
    ingest_lens_result(
        &run.run,
        ADJUDICATOR_PROVIDER_ID,
        &authenticated_adjudication_result(&run, true),
    )
    .unwrap();
    run
}

#[test]
fn adjudication_under_derived_context_policy_records_a_gap_not_an_attestation() {
    let run = setup("derived-context");
    let result = adjudication_result(&run, true);
    let mut result = result;
    authenticate(
        &run.run,
        &run.adjudication.request,
        &mut result,
        FindingDisposition::Upheld,
    );
    ingest_lens_result(&run.run, ADJUDICATOR_PROVIDER_ID, &result).unwrap();
    let recomputed = recompute_run(&run.run).unwrap();
    assert!(
        recomputed
            .report
            .gaps
            .iter()
            .any(|gap| gap.starts_with("adjudication-context-derived:")
                && gap.contains("0 naming no context")
                && gap.contains("not a fresh-context attestation")),
        "{:?}",
        recomputed.report.gaps
    );
}

#[test]
fn adjudication_result_must_bind_each_verdict_to_its_isolated_child_packet() {
    let run = setup("child-binding");
    let mut result = adjudication_result(&run, true);
    result["verdicts"][0]["workItemId"] = json!("sha256:forged");
    let error = ingest_lens_result(&run.run, ADJUDICATOR_PROVIDER_ID, &result).unwrap_err();
    assert!(error
        .to_string()
        .contains("not bound to its isolated work item"));
}

#[test]
fn historical_batch_packet_without_child_items_remains_ingestable_as_derived() {
    let mut run = setup("legacy-batch-packet");
    // A historical packet predates stages: one plain verdict per candidate.
    let mut result = adjudication_result(&run, true);
    result["verdicts"] = json!([verdict("cand-sql", true), verdict("cand-doc", false)]);
    run.adjudication
        .request
        .packet
        .as_object_mut()
        .unwrap()
        .remove("candidateWorkItems");
    rewrite_request_id(&mut run.adjudication);
    result["packetDigest"] = json!(canonical_digest(&run.adjudication.request.packet).unwrap());
    write_json(
        &run.run
            .join(format!("{LENS_PACKET_DIR}/{ADJUDICATOR_PROVIDER_ID}.json")),
        &serde_json::to_value(&run.adjudication).unwrap(),
    );

    authenticate(
        &run.run,
        &run.adjudication.request,
        &mut result,
        FindingDisposition::Upheld,
    );
    ingest_lens_result(&run.run, ADJUDICATOR_PROVIDER_ID, &result).unwrap();
    let recomputed = recompute_run(&run.run).unwrap();
    assert!(recomputed.report.gaps.iter().any(|gap| {
        gap.starts_with("adjudication-context-derived:")
            && gap.contains("not a fresh-context attestation")
    }));
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

    // The follow-up plan separates confirmed seeds from deterministic sibling
    // and caller context, signed and bound to the parent plan digest.
    let dir = run.run.join(FOLLOWUP_DIR);
    let frozen: AuditPlan = serde_json::from_value(read_json(&dir.join(FROZEN_PLAN_FILE))).unwrap();
    assert_eq!(frozen.providers.len(), 1);
    assert_eq!(frozen.providers[0].id, VARIANT_PROVIDER_ID);
    assert_eq!(frozen.providers[0].configuration["denominatorCount"], 4);
    let parent_context = read_json(&run.run.join("plan.json"))["reviewContext"].clone();
    let child_plan = read_json(&dir.join("plan.json"));
    assert_eq!(child_plan["reviewContext"], parent_context);
    assert_eq!(
        frozen.providers[0].configuration["reasoning"]["reviewContext"],
        parent_context,
    );
    assert_eq!(
        child_plan["nativePlan"]["digest"],
        child_plan["seal"]["digest"]
    );
    assert!(dir.join("lens-dispatch.json").is_file());
    assert_eq!(
        planned.analysis_paths,
        vec![
            "src/alternate/db_access.rs".to_owned(),
            "src/callers/queries.rs".to_owned(),
            "src/db.rs".to_owned(),
            "src/other.rs".to_owned()
        ]
    );
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

    // The packet scopes analysis to the seed, its sibling, and its caller,
    // while keeping the confirmed finding in a distinct seed list.
    let work = variant_packet(&run);
    assert_eq!(work.request.denominator_paths, planned.analysis_paths);
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
    let scope_paths = work.request.packet["variantScope"]["paths"]
        .as_array()
        .unwrap();
    assert_eq!(scope_paths.len(), 4);
    assert!(scope_paths.iter().any(|path| {
        path["path"] == "src/callers/queries.rs"
            && path["relations"].as_array().is_some_and(|relations| {
                relations
                    .iter()
                    .any(|value| value == "caller-reference:src/db.rs")
            })
    }));
    assert!(scope_paths.iter().any(|path| {
        path["path"] == "src/alternate/db_access.rs"
            && path["relations"].as_array().is_some_and(|relations| {
                relations.iter().any(|value| {
                    value
                        .as_str()
                        .is_some_and(|value| value.starts_with("root-cause-token:src/db.rs:"))
                })
            })
    }));
    assert!(!work
        .request
        .denominator_paths
        .contains(&"src/unrelated/else.rs".to_owned()));

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
    let mut sibling_finding = variant_finding();
    sibling_finding["evidence"] = json!(["src/alternate/db_access.rs:1"]);
    sibling_finding["anchor"] = json!({
        "path": "src/alternate/db_access.rs",
        "line": 1,
        "text": ALT_ANCHOR,
    });
    let ingested = ingest_fixture(
        &run.run.join(FOLLOWUP_DIR),
        &variant_packet(&run),
        variant_result(&run, json!([sibling_finding])),
        FindingDisposition::Upheld,
    );
    assert!(ingested.complete);
    assert_eq!((ingested.examined, ingested.expected), (4, 4));

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
fn variant_findings_cannot_anchor_outside_the_frozen_analysis_scope() {
    let run = confirmed_run("out-of-scope-anchor");
    compile_followup(&run.run, &variant_spec())
        .unwrap()
        .unwrap();
    let mut finding = variant_finding();
    finding["evidence"] = json!(["src/unrelated/else.rs:1"]);
    finding["anchor"] = json!({
        "path": "src/unrelated/else.rs",
        "line": 1,
        "text": "pub fn independent() {}",
    });
    let mut result = variant_result(&run, json!([finding]));
    authenticate(
        &run.run.join(FOLLOWUP_DIR),
        &variant_packet(&run).request,
        &mut result,
        FindingDisposition::Upheld,
    );

    let error = match ingest_lens_result(&run.run.join(FOLLOWUP_DIR), VARIANT_PROVIDER_ID, &result)
    {
        Ok(_) => panic!("an in-inventory path outside frozen variant scope must be rejected"),
        Err(error) => error,
    };
    assert!(error
        .to_string()
        .contains("outside the frozen analysis scope"));
}

#[test]
fn a_variant_result_with_no_variants_also_clears_the_gap() {
    let run = confirmed_run("none-found");
    compile_followup(&run.run, &variant_spec())
        .unwrap()
        .unwrap();
    ingest_fixture(
        &run.run.join(FOLLOWUP_DIR),
        &variant_packet(&run),
        variant_result(&run, json!([])),
        FindingDisposition::Upheld,
    );
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
    ingest_fixture(
        &run.run.join(FOLLOWUP_DIR),
        &variant_packet(&run),
        variant_result(&run, json!([])),
        FindingDisposition::Upheld,
    );
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
    ingest_fixture(
        &run.run.join(FOLLOWUP_DIR),
        &variant_packet(&run),
        variant_result(&run, json!([])),
        FindingDisposition::Upheld,
    );
    assert!(!has_pending_gap(
        &recompute_run(&run.run).unwrap().report.gaps
    ));
    let mut plan = read_json(&run.run.join("plan.json"));
    plan["seal"]["digest"] = json!(format!("sha256:{}", "0".repeat(64)));
    write_json(&run.run.join("plan.json"), &plan);
    let error = match recompute_run(&run.run) {
        Ok(_) => panic!("a parent seal differing from its native plan must be rejected"),
        Err(error) => error,
    };
    assert!(error
        .to_string()
        .contains("nativePlan identity differs from frozen execution"));

    // (2) The follow-up plan is rebound to a different parent digest.
    let run = confirmed_run("tamper-binding");
    compile_followup(&run.run, &variant_spec())
        .unwrap()
        .unwrap();
    ingest_fixture(
        &run.run.join(FOLLOWUP_DIR),
        &variant_packet(&run),
        variant_result(&run, json!([])),
        FindingDisposition::Upheld,
    );
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
    ingest_fixture(
        &run.run.join(FOLLOWUP_DIR),
        &variant_packet(&run),
        variant_result(&run, json!([])),
        FindingDisposition::Upheld,
    );
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
        &authenticated_adjudication_result(&run, false),
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

#[test]
fn a_partitioned_variant_denominator_binds_every_part_and_needs_all_of_them() {
    let source = padded_db_source();
    // This exhaustive denominator intentionally exceeds a bounded audit's
    // default physical allowance. Size a disposable, unexecuted follow-up,
    // then create a fresh fixture with sufficient limits frozen upfront.
    let probe = confirmed_run_with_source("multipart-probe", &source);
    let probe_plan = compile_followup(&probe.run, &variant_spec())
        .unwrap()
        .unwrap();
    let probe_dispatch = read_json(&probe.run.join(FOLLOWUP_DIR).join("lens-dispatch.json"));
    let largest_input = probe_dispatch["seats"]
        .as_array()
        .unwrap()
        .iter()
        .chain(probe_dispatch["deferredWork"].as_array().unwrap())
        .map(|seat| seat["plannedModelInputBytes"].as_u64().unwrap())
        .max()
        .unwrap();
    // Keep the normal 2500-token output & 1500-token admission headroom.
    // Allow another 1500 tokens for temporary path/nonce framing differences;
    // final physical-fit assertions below validate the newly frozen recipe.
    let per_call = largest_input.div_ceil(2) + 2500 + 1500 + 1500;
    // Parent stage receipts & candidate verification already consumed calls.
    // Every logical follow-up part models an author plus fresh verifier.
    let parent_calls = read_json(&probe.run.join("next-state.json"))["issuances"]
        .as_u64()
        .expect("authenticated parent fixture calls recorded");
    let max_calls = (probe_plan.packets.len() as u64)
        .checked_mul(2)
        .and_then(|calls| calls.checked_add(parent_calls))
        .unwrap()
        .max(DispatchLimits::default().max_total_seats);
    let limits = DispatchLimits {
        seat_token_budget: per_call,
        wave_width: 1,
        run_token_budget: per_call.checked_mul(max_calls).unwrap(),
        max_total_seats: max_calls,
    };
    let run = setup_with_source_and_limits("multipart-final", &source, &limits);
    ingest_lens_result(
        &run.run,
        ADJUDICATOR_PROVIDER_ID,
        &authenticated_adjudication_result(&run, true),
    )
    .unwrap();
    let planned = compile_followup(&run.run, &variant_spec())
        .unwrap()
        .expect("a confirmed finding needs a follow-up");
    assert!(planned.packets.len() > 1, "{:?}", planned.packets);
    assert_eq!(planned.packets.len(), planned.packet_digests.len());
    let lens_dir = run.run.join(FOLLOWUP_DIR).join(LENS_PACKET_DIR);
    assert!(!lens_dir
        .join(format!("{VARIANT_PROVIDER_ID}.json"))
        .exists());

    // Every part is a numbered packet of the same denominator, and every part
    // carries the confirmed seeds and the parent binding.
    let parts = variant_parts(&run);
    let total = parts.len();
    assert_eq!(parts.len(), planned.packets.len());
    assert_eq!(total, probe_plan.packets.len());
    let dispatch = read_json(&run.run.join(FOLLOWUP_DIR).join("lens-dispatch.json"));
    assert_eq!(dispatch["withinLimits"], true, "{dispatch}");
    assert_eq!(dispatch["requiredSeats"], total);
    assert_eq!(dispatch["followupReserveCalls"], 1);
    assert_eq!(dispatch["selectedPackets"].as_array().unwrap().len(), total);
    assert_eq!(dispatch["reasoningBudget"]["perCallTokens"], per_call);
    assert_eq!(
        dispatch["reasoningBudget"]["totalTokens"],
        limits.run_token_budget
    );
    assert_eq!(dispatch["reasoningBudget"]["maxSeats"], max_calls);
    assert_eq!(
        dispatch["reasoningBudget"],
        read_json(&run.run.join("lens-dispatch.json"))["reasoningBudget"]
    );
    let parent_digest = read_json(&run.run.join("plan.json"))["seal"]["digest"].clone();
    for (index, part) in parts.iter().enumerate() {
        let meta = part.part().expect("numbered part");
        assert_eq!(
            (meta.number as usize, meta.total as usize),
            (index + 1, total)
        );
        assert_eq!(
            part.request.packet["variantSeeds"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            part.request.packet["followup"]["confirmedPaths"],
            json!(["src/db.rs"])
        );
        assert_eq!(
            part.request.packet["followup"]["parentPlanDigest"],
            parent_digest
        );
    }
    let index = read_json(&lens_dir.join(format!("{VARIANT_PROVIDER_ID}.index.json")));
    assert_eq!(index["parts"].as_array().unwrap().len(), total);

    // A second compile keeps the same multi-part follow-up.
    let again = compile_followup(&run.run, &variant_spec())
        .unwrap()
        .unwrap();
    assert!(again.reused);
    assert_eq!(again.packets.len(), total);

    // One part missing: pending, and the gap names the missing part.
    let dir = run.run.join(FOLLOWUP_DIR);
    for part in &parts[..total - 1] {
        ingest_fixture(
            &dir,
            part,
            variant_part_result(part, json!([])),
            FindingDisposition::Upheld,
        );
    }
    let partial = recompute_run(&run.run).unwrap();
    assert!(
        has_pending_gap(&partial.report.gaps),
        "{:?}",
        partial.report.gaps
    );
    let claim = &partial.report.claims["securityVariantFollowup"];
    assert_eq!(claim["status"], "pending");
    let reason = claim["reason"].as_str().unwrap();
    assert!(
        reason.contains(&format!("part(s) {total} of {total} not yet ingested")),
        "{reason}"
    );

    // Every part ingested: the variant denominator is covered and the gap clears.
    ingest_fixture(
        &dir,
        &parts[total - 1],
        variant_part_result(&parts[total - 1], json!([])),
        FindingDisposition::Upheld,
    );
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
}
