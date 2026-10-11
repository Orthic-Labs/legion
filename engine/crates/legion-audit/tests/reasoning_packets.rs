//! Packet continuation, block-aware redaction and ingest of partitioned
//! reasoning lenses: every denominator path is homed in exactly one packet
//! part, oversized files are chunked rather than truncated, redaction runs
//! before chunking, and a provider completes only when every part is
//! ingested.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};

use legion_audit::native_providers::reasoning::{
    excerpts,
    ingest::{
        create_epoch, ingest_lens_result, recompute_run, write_lens_packets, EPOCH_KEY_FILE,
        LENS_PACKET_DIR,
    },
    lens_plan, pending_lens_work, PendingLensWork, ReasoningProviderExecutor,
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

const KEY: &[u8] = b"reasoning-packets-fixture-signing-key";
const RAW_PROVIDER: &str = "reasoning.performance";
const RAW_LENS: &str = "performance";
const SKELETON_PROVIDER: &str = "reasoning.naming";
const SKELETON_LENS: &str = "naming";

fn temp_dir(name: &str) -> PathBuf {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!(
        "legion-packets-{name}-{}-{nanos}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
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
    provider: &'static str,
    plan: FrozenPlan,
    inventory: InventoryEnvelope,
    work: Vec<PendingLensWork>,
}

/// Fixed-width filler line so byte arithmetic in the tests is exact:
/// 40 characters, 41 bytes with the newline.
fn filler_line(file: usize, line: usize) -> String {
    format!("// {file:03}:{line:04} {}", "x".repeat(28))
}

fn filler_file(file: usize, lines: usize) -> String {
    (1..=lines)
        .map(|line| format!("{}\n", filler_line(file, line)))
        .collect()
}

/// Mirrors what `legion audit --out` leaves behind for a signed plan with one
/// pending reasoning lens, with packets written by `write_lens_packets`.
fn build_env(
    name: &str,
    provider: &'static str,
    lens: &'static str,
    files: &[(String, String)],
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
    let specs = [
        spec(
            "fixture.a",
            json!({"kind":"built-in"}),
            "deterministic",
            &[],
            json!({"status":"unproven","requiredForCleanClaim":false}),
        ),
        spec(
            provider,
            json!({"kind":"reasoning-contract","contract":"fixture-reasoning-v1"}),
            "adjudicator",
            &[lens],
            json!({"status":"unproven","requiredForCleanClaim":false}),
        ),
    ];
    let plan = AuditPlan::compile_with_root(Some(&root), &inventory, &specs)
        .unwrap()
        .freeze(Some(KEY))
        .unwrap();
    let executor = Fixture {
        reasoning: ReasoningProviderExecutor::unavailable(&root),
    };
    let execution = execute(&plan, &inventory, &executor).unwrap();
    assert_eq!(execution.pending_host, vec![provider]);
    let report = canonical_report(&repository, &execution).unwrap();
    assert_eq!(report.status, ReportStatus::Incomplete);
    let work = pending_lens_work(&root, &plan, &inventory).unwrap();

    let run = root.join(".audit").join("run");
    fs::create_dir_all(run.join(LENS_PACKET_DIR)).unwrap();
    let epoch = create_epoch(&run).unwrap();
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
            "epoch": {"digest": epoch, "keyFile": EPOCH_KEY_FILE},
        }),
    );
    write("report.json", serde_json::to_value(&report).unwrap());
    write("execution.json", serde_json::to_value(&execution).unwrap());
    write_lens_packets(&run.join(LENS_PACKET_DIR), &work).unwrap();
    Env {
        root,
        run,
        provider,
        plan,
        inventory,
        work,
    }
}

fn denominator(env: &Env) -> Vec<String> {
    env.work[0].request.denominator_paths.clone()
}

fn homed_paths(item: &PendingLensWork) -> Vec<String> {
    item.request.packet["part"]["paths"]
        .as_array()
        .unwrap()
        .iter()
        .map(|path| path.as_str().unwrap().to_owned())
        .collect()
}

fn part_result(item: &PendingLensWork, findings: Value) -> Value {
    json!({
        "schemaVersion": 1,
        "kind": "legion-lens-result",
        "provider": item.provider_id,
        "packetDigest": canonical_digest(&item.request.packet).unwrap(),
        "planDigest": item.request.plan_digest,
        "complete": true,
        "findings": findings,
        "withdrawn": [],
    })
}

fn finding(id: &str, path: &str, text: &str) -> Value {
    json!({
        "id": id,
        "lens": RAW_LENS,
        "severity": "low",
        "confidence": "likely",
        "evidence": [format!("{path}:1")],
        "failureScenario": "filler line is slow",
        "action": "remove the filler",
        "verifyStatus": "unverified",
        "anchor": {"path": path, "line": 1, "text": text},
    })
}

/// `n` files of 625 filler lines (25,625 bytes each, one chunk apiece).
fn many_files(count: usize) -> Vec<(String, String)> {
    (0..count)
        .map(|index| (format!("src/a{index:03}.rs"), filler_file(index, 625)))
        .collect()
}

#[test]
fn a_three_megabyte_denominator_partitions_exactly_into_parts() {
    let files = many_files(120);
    let total: usize = files.iter().map(|(_, content)| content.len()).sum();
    assert!(total >= 3_000_000, "fixture is {total} bytes");
    let env = build_env("three-mb", RAW_PROVIDER, RAW_LENS, &files);

    assert!(env.work.len() > 1, "expected several parts");
    let denominator = denominator(&env);
    assert_eq!(denominator.len(), 120);
    let mut seen = BTreeSet::new();
    let mut count = 0usize;
    for (index, item) in env.work.iter().enumerate() {
        let part = item.part().expect("numbered part");
        assert_eq!(part.number as usize, index + 1);
        assert_eq!(part.total as usize, env.work.len());
        // Every part carries the full frozen denominator (same binding).
        assert_eq!(item.request.denominator_paths, denominator);
        for path in homed_paths(item) {
            assert!(seen.insert(path.clone()), "{path} homed in two parts");
            count += 1;
        }
        let bytes: usize = item.request.packet["excerpts"]
            .as_array()
            .unwrap()
            .iter()
            .map(|excerpt| excerpt["content"].as_str().unwrap().len())
            .sum();
        assert!(bytes <= excerpts::MAX_TOTAL_EXCERPT_BYTES, "part {index}");
    }
    assert_eq!(count, 120);
    assert_eq!(seen, denominator.iter().cloned().collect::<BTreeSet<_>>());

    // The index file lists every part with its digest and path set.
    let index: Value = serde_json::from_slice(
        &fs::read(
            env.run
                .join(LENS_PACKET_DIR)
                .join(format!("{RAW_PROVIDER}.index.json")),
        )
        .unwrap(),
    )
    .unwrap();
    assert_eq!(index["totalParts"], json!(env.work.len()));
    let listed = index["parts"].as_array().unwrap();
    assert_eq!(listed.len(), env.work.len());
    for (entry, item) in listed.iter().zip(&env.work) {
        assert_eq!(
            entry["packetDigest"],
            json!(canonical_digest(&item.request.packet).unwrap())
        );
        assert_eq!(entry["file"], json!(item.packet_file_name()));
        assert!(env
            .run
            .join(LENS_PACKET_DIR)
            .join(item.packet_file_name())
            .is_file());
    }
    // No un-numbered packet is written for a partitioned provider.
    assert!(!env
        .run
        .join(LENS_PACKET_DIR)
        .join(format!("{RAW_PROVIDER}.json"))
        .exists());
}

#[test]
fn a_single_part_provider_keeps_the_unnumbered_packet() {
    let env = build_env("single", RAW_PROVIDER, RAW_LENS, &many_files(2));
    assert_eq!(env.work.len(), 1);
    assert!(env.work[0].part().is_none());
    assert!(env.work[0].request.packet.get("part").is_none());
    let packets = env.run.join(LENS_PACKET_DIR);
    assert!(packets.join(format!("{RAW_PROVIDER}.json")).is_file());
    assert!(!packets.join(format!("{RAW_PROVIDER}.index.json")).exists());
}

#[test]
fn a_hundred_kib_file_is_chunked_on_line_boundaries_with_full_line_coverage() {
    let lines = 2500;
    let source = filler_file(7, lines);
    assert!(source.len() >= 100 * 1024);
    let env = build_env(
        "chunked",
        RAW_PROVIDER,
        RAW_LENS,
        &[("src/big.rs".to_owned(), source.clone())],
    );
    let original: Vec<&str> = source.lines().collect();
    let mut chunks = Vec::new();
    for item in &env.work {
        for excerpt in item.request.packet["excerpts"].as_array().unwrap() {
            chunks.push(excerpt.clone());
        }
    }
    assert!(chunks.len() >= 4, "{} chunks", chunks.len());
    let mut next = 1u64;
    for (index, chunk) in chunks.iter().enumerate() {
        assert_eq!(chunk["path"], json!("src/big.rs"));
        assert_eq!(chunk["chunk"], json!(index + 1));
        assert_eq!(chunk["chunks"], json!(chunks.len()));
        let start = chunk["startLine"].as_u64().unwrap();
        let end = chunk["endLine"].as_u64().unwrap();
        assert_eq!(start, next, "chunks are contiguous");
        let content = chunk["content"].as_str().unwrap();
        assert!(content.len() <= excerpts::MAX_BYTES_PER_FILE);
        // Whole lines, byte-identical to the source range.
        let expected: String = original[(start as usize - 1)..end as usize]
            .iter()
            .map(|line| format!("{line}\n"))
            .collect();
        assert_eq!(content, expected);
        next = end + 1;
    }
    assert_eq!(next - 1, lines as u64, "every line is covered");

    // Ingesting every part of a split file covers it.
    for item in &env.work {
        ingest_lens_result(&env.run, env.provider, &part_result(item, json!([]))).unwrap();
    }
    let recomputed = recompute_run(&env.run).unwrap();
    assert_eq!(recomputed.report.status, ReportStatus::Clean);
}

#[test]
fn all_parts_ingested_is_complete_and_all_but_one_names_the_outstanding_part() {
    let env = build_env("ingest-parts", RAW_PROVIDER, RAW_LENS, &many_files(60));
    let total = env.work.len();
    assert!(total > 2);

    for item in env.work.iter().take(total - 1) {
        ingest_lens_result(&env.run, env.provider, &part_result(item, json!([]))).unwrap();
    }
    let pending = recompute_run(&env.run).unwrap();
    assert_eq!(pending.report.status, ReportStatus::Incomplete);
    let gap = format!(
        "reasoning-parts-pending:{RAW_PROVIDER}:{}/{total}",
        total - 1
    );
    assert!(
        pending.report.gaps.contains(&gap),
        "missing {gap} in {:?}",
        pending.report.gaps
    );
    assert_eq!(pending.report.claims["lensesRan"], json!([]));
    assert_eq!(pending.pending, vec![RAW_PROVIDER.to_owned()]);
    assert_eq!(pending.lens_parts[RAW_PROVIDER].pending, vec![total as u32]);

    // The last ingest reports the provider-level state.
    let last = &env.work[total - 1];
    let ingested =
        ingest_lens_result(&env.run, env.provider, &part_result(last, json!([]))).unwrap();
    assert!(ingested.complete, "{:?}", ingested.coverage_gaps);
    assert_eq!(ingested.part, Some(total as u32));
    assert_eq!(ingested.parts_ingested, Some(total as u32));
    assert!(ingested.parts_pending.is_empty());
    assert_eq!((ingested.examined, ingested.expected), (60, 60));

    let done = recompute_run(&env.run).unwrap();
    assert_eq!(done.report.status, ReportStatus::Clean);
    assert!(done.report.gaps.is_empty(), "{:?}", done.report.gaps);
    assert_eq!(done.report.claims["lensesRan"], json!([RAW_LENS]));
    assert!(done.pending.is_empty());
    // Each part is MAC-receipted under its own file.
    let receipts = env.run.join("lens-receipts");
    for number in 1..=total {
        assert!(receipts
            .join(format!("{RAW_PROVIDER}.part-{number:04}.json"))
            .is_file());
    }
}

#[test]
fn ingesting_a_single_part_reports_the_provider_level_outstanding_work() {
    let env = build_env("ingest-one", RAW_PROVIDER, RAW_LENS, &many_files(60));
    let total = env.work.len();
    let ingested = ingest_lens_result(
        &env.run,
        env.provider,
        &part_result(&env.work[0], json!([])),
    )
    .unwrap();
    assert!(!ingested.complete);
    assert_eq!(ingested.parts_total, Some(total as u32));
    assert_eq!(ingested.parts_ingested, Some(1));
    assert_eq!(ingested.parts_pending.len(), total - 1);
    assert_eq!(
        ingested.coverage_gaps,
        vec![format!("reasoning-parts-pending:{RAW_PROVIDER}:1/{total}")]
    );
    assert_eq!(ingested.examined as usize, homed_paths(&env.work[0]).len());
}

#[test]
fn a_file_split_across_parts_is_covered_only_when_every_chunk_is_ingested() {
    // 19 files fill most of part 1; the big file's first chunk fits there and
    // its remaining chunks continue into part 2.
    let mut files = many_files(19);
    files.push(("src/z_big.rs".to_owned(), filler_file(99, 3000)));
    let env = build_env("straddle", RAW_PROVIDER, RAW_LENS, &files);
    assert_eq!(env.work.len(), 2);
    assert!(homed_paths(&env.work[0]).contains(&"src/z_big.rs".to_owned()));
    assert!(env.work[1].request.packet["part"]["continuedPaths"]
        .as_array()
        .unwrap()
        .contains(&json!("src/z_big.rs")));

    let first = ingest_lens_result(
        &env.run,
        env.provider,
        &part_result(&env.work[0], json!([])),
    )
    .unwrap();
    // 19 whole files; the split file is not yet covered.
    assert_eq!((first.examined, first.expected), (19, 20));
    assert!(!first.complete);

    let second = ingest_lens_result(
        &env.run,
        env.provider,
        &part_result(&env.work[1], json!([])),
    )
    .unwrap();
    assert_eq!((second.examined, second.expected), (20, 20));
    assert!(second.complete, "{:?}", second.coverage_gaps);

    // Part 2 alone never covers the split file.
    let alone = build_env("straddle-alone", RAW_PROVIDER, RAW_LENS, &files);
    let only_second = ingest_lens_result(
        &alone.run,
        alone.provider,
        &part_result(&alone.work[1], json!([])),
    )
    .unwrap();
    assert_eq!((only_second.examined, only_second.expected), (0, 20));
    assert!(!only_second.complete);
}

#[test]
fn part_building_is_deterministic() {
    let env = build_env("determinism", RAW_PROVIDER, RAW_LENS, &many_files(60));
    let digests = |work: &[PendingLensWork]| -> Vec<(String, String)> {
        work.iter()
            .map(|item| {
                (
                    canonical_digest(&item.request.packet).unwrap(),
                    item.request.request_id.clone(),
                )
            })
            .collect()
    };
    let again = pending_lens_work(&env.root, &env.plan, &env.inventory).unwrap();
    assert_eq!(digests(&env.work), digests(&again));
    assert!(env.work.len() > 1);
}

#[test]
fn finding_ids_must_be_unique_across_parts() {
    let env = build_env("unique-ids", RAW_PROVIDER, RAW_LENS, &many_files(60));
    let in_part = |item: &PendingLensWork| homed_paths(item)[0].clone();
    let first_path = in_part(&env.work[0]);
    let other_path = in_part(&env.work[1]);
    assert_ne!(first_path, other_path);
    let text_for = |path: &str| {
        let index: usize = path
            .trim_start_matches("src/a")
            .trim_end_matches(".rs")
            .parse()
            .unwrap();
        filler_line(index, 1)
    };

    ingest_lens_result(
        &env.run,
        env.provider,
        &part_result(
            &env.work[0],
            json!([finding("p0001-a", &first_path, &text_for(&first_path))]),
        ),
    )
    .unwrap();
    let duplicate = ingest_lens_result(
        &env.run,
        env.provider,
        &part_result(
            &env.work[1],
            json!([finding("p0001-a", &other_path, &text_for(&other_path))]),
        ),
    )
    .unwrap_err()
    .to_string();
    assert!(duplicate.contains("unique across parts"), "{duplicate}");
    ingest_lens_result(
        &env.run,
        env.provider,
        &part_result(
            &env.work[1],
            json!([finding("p0002-a", &other_path, &text_for(&other_path))]),
        ),
    )
    .unwrap();
    let recomputed = recompute_run(&env.run).unwrap();
    let ids: Vec<&str> = recomputed
        .report
        .findings
        .iter()
        .map(|finding| finding.id.as_str())
        .collect();
    assert_eq!(ids, vec!["p0001-a", "p0002-a"]);
    // Triage fields reach the public finding.
    assert_eq!(
        recomputed.report.findings[0].evidence["confidence"],
        json!("likely")
    );
    assert_eq!(
        recomputed.report.findings[0].evidence["verifyStatus"],
        json!("unverified")
    );
}

#[test]
fn a_part_filed_under_the_single_packet_name_is_refused() {
    let env = build_env("misfiled", RAW_PROVIDER, RAW_LENS, &many_files(60));
    let packets = env.run.join(LENS_PACKET_DIR);
    // An old CLI would have overwritten `<provider>.json` with the last part.
    fs::write(
        packets.join(format!("{RAW_PROVIDER}.json")),
        serde_json::to_vec(env.work.last().unwrap()).unwrap(),
    )
    .unwrap();
    let error = ingest_lens_result(
        &env.run,
        env.provider,
        &part_result(env.work.last().unwrap(), json!([])),
    )
    .unwrap_err()
    .to_string();
    assert!(error.contains("ambiguous"), "{error}");
}

#[test]
fn the_provider_ceiling_reports_unscheduled_paths_instead_of_dropping_them() {
    let root = temp_dir("ceiling");
    let paths: Vec<String> = (0..60).map(|index| format!("src/a{index:03}.rs")).collect();
    for (index, path) in paths.iter().enumerate() {
        let full = root.join(path);
        fs::create_dir_all(full.parent().unwrap()).unwrap();
        fs::write(full, filler_file(index, 625)).unwrap();
    }
    let full = excerpts::partition_excerpts(
        &root,
        &paths,
        lens_plan::ExcerptMode::Raw,
        excerpts::DEFAULT_MAX_PARTS,
    );
    assert!(full.required_parts > 1);
    assert!(full.unscheduled_paths.is_empty());

    let capped = excerpts::partition_excerpts(&root, &paths, lens_plan::ExcerptMode::Raw, 1);
    assert_eq!(capped.parts.len(), 1);
    assert_eq!(capped.required_parts, full.required_parts);
    let kept: BTreeSet<&String> = capped.parts[0].paths.iter().collect();
    let dropped: BTreeSet<&String> = capped.unscheduled_paths.iter().collect();
    assert!(!dropped.is_empty());
    assert!(kept.is_disjoint(&dropped));
    assert_eq!(kept.len() + dropped.len(), paths.len());
}

// --- redaction -----------------------------------------------------------

/// A PEM-shaped block assembled from fragments so this repository holds no
/// key-like literal. Body lines carry a unique marker for absence checks.
fn pem_block(marker: &str, body_lines: usize) -> String {
    let dashes = "-".repeat(5);
    let label = ["TEST", " BLOCK", " DATA"].concat();
    let mut out = format!("{dashes}BEGIN {label}{dashes}\n");
    for index in 0..body_lines {
        out.push_str(&format!(
            "{marker}{index:03}QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=\n"
        ));
    }
    out.push_str(&format!("{dashes}END {label}{dashes}\n"));
    out
}

fn assert_absent(work: &[PendingLensWork], needles: &[&str]) {
    for item in work {
        let serialized = serde_json::to_string(item).unwrap();
        for needle in needles {
            assert!(!serialized.contains(needle), "packet leaked {needle:?}");
        }
    }
}

#[test]
fn pem_blocks_and_multiline_secrets_never_reach_any_packet() {
    let pem = pem_block("PEMBODYMARKER", 25);
    let source = format!(
        "fn before() {{}}\n{pem}let api_key = \"MULTILINEFIRST\nMULTILINESECONDLINE\nMULTILINETHIRD\";\nfn after() {{}}\n"
    );
    // Pad so the block lands mid-file and the file still chunks.
    let padding = filler_file(1, 900);
    let files = vec![
        (
            "src/keys.rs".to_owned(),
            format!("{padding}{source}{padding}"),
        ),
        ("src/other.rs".to_owned(), filler_file(2, 10)),
    ];
    let env = build_env("redaction", RAW_PROVIDER, RAW_LENS, &files);
    assert_absent(
        &env.work,
        &[
            "PEMBODYMARKER",
            "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo",
            "MULTILINEFIRST",
            "MULTILINESECONDLINE",
            "MULTILINETHIRD",
        ],
    );
    let chunks: Vec<Value> = env
        .work
        .iter()
        .flat_map(|item| item.request.packet["excerpts"].as_array().unwrap().clone())
        .filter(|excerpt| excerpt["path"] == json!("src/keys.rs"))
        .collect();
    let joined: String = chunks
        .iter()
        .map(|chunk| chunk["content"].as_str().unwrap())
        .collect();
    assert!(joined.contains("[REDACTED PEM BLOCK 27 lines]"));
    assert!(joined.contains("[REDACTED MULTILINE SECRET"));
    assert!(joined.contains("fn before() {}"));
    assert!(joined.contains("fn after() {}"));
    let pem_blocks: u64 = chunks
        .iter()
        .map(|chunk| chunk["redaction"]["pemBlocks"].as_u64().unwrap())
        .sum();
    let multiline: u64 = chunks
        .iter()
        .map(|chunk| chunk["redaction"]["multilineSecrets"].as_u64().unwrap())
        .sum();
    assert_eq!((pem_blocks, multiline), (1, 1));
    assert!(chunks.iter().any(|chunk| chunk["redacted"] == json!(true)));
    // The collapsed ranges are recorded so source line numbers stay usable.
    let ranges: Vec<&str> = chunks
        .iter()
        .flat_map(|chunk| chunk["redactedRanges"].as_array().unwrap())
        .filter_map(Value::as_str)
        .collect();
    assert!(ranges
        .iter()
        .any(|range| range.starts_with("src/keys.rs:902-928")));
}

#[test]
fn a_pem_block_is_redacted_before_chunking_even_across_a_chunk_boundary() {
    // Place the block so a naive 32 KiB cut would land inside it.
    let lines_before = (excerpts::MAX_BYTES_PER_FILE / 41) - 5;
    let source = format!(
        "{}{}{}",
        filler_file(3, lines_before),
        pem_block("BOUNDARYBODY", 40),
        filler_file(4, 50)
    );
    let env = build_env(
        "boundary",
        RAW_PROVIDER,
        RAW_LENS,
        &[("src/edge.rs".to_owned(), source)],
    );
    assert_absent(
        &env.work,
        &["BOUNDARYBODY", "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo"],
    );
    let chunk_count: usize = env
        .work
        .iter()
        .map(|item| item.request.packet["excerpts"].as_array().unwrap().len())
        .sum();
    assert!(chunk_count >= 2, "the file should still be split");
}

#[test]
fn skeleton_excerpts_are_redacted_too() {
    let fake = ["sk", "live", "abcdefghijklmnopqrstuvwxyz"].join("_");
    let pem = pem_block("SKELPEMBODY", 8);
    let source = format!(
        "pub const API_KEY: &str = \"{fake}\";\npub fn run() {{}}\n{pem}pub fn done() {{}}\n"
    );
    let env = build_env(
        "skeleton-redaction",
        SKELETON_PROVIDER,
        SKELETON_LENS,
        &[("src/lib.rs".to_owned(), source)],
    );
    assert_absent(&env.work, &[fake.as_str(), "SKELPEMBODY"]);
    let excerpt = &env.work[0].request.packet["excerpts"][0];
    assert_eq!(excerpt["mode"], json!("skeleton"));
    assert_eq!(excerpt["redacted"], json!(true));
    assert!(excerpt["redaction"]["lines"].as_u64().unwrap() >= 1);
    let content = excerpt["content"].as_str().unwrap();
    assert!(content.contains("pub fn run() {}"));
    assert!(content.contains("pub fn done() {}"));
}
