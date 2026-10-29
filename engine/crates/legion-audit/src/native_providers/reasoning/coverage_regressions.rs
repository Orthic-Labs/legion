//! Source-level regressions for frozen trigger coverage & transport accounting.
use super::*;
use crate::{AuditPlan, FilesystemInventorySource, InventorySource};
use legion_contracts::ProviderSpec;

struct Fixture(PathBuf);

impl Fixture {
    fn new(files: &[(&str, String)]) -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let root = std::env::temp_dir().join(format!(
            "audit-coverage-regression-{}-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
            NEXT.fetch_add(1, Ordering::Relaxed),
        ));
        std::fs::create_dir_all(&root).unwrap();
        for (path, content) in files {
            let full = root.join(path);
            std::fs::create_dir_all(full.parent().unwrap()).unwrap();
            std::fs::write(full, content).unwrap();
        }
        Self(root)
    }

    fn inventory(&self) -> InventoryEnvelope {
        FilesystemInventorySource::new(&self.0)
            .unwrap()
            .inventory("coverage-regressions")
            .unwrap()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn spec(provider: &str, selector: Value) -> ProviderSpec {
    ProviderSpec {
        schema_version: 2,
        id: ProviderId::new(provider).unwrap(),
        provider_version: "1.0.0".into(),
        family: "fixture".into(),
        lens_ids: vec![lens_plan::lens_id_for_provider(provider).unwrap().into()],
        role: "adjudicator".into(),
        phase: "source".into(),
        depends_on: Vec::new(),
        consumes: vec!["repository-inventory".into()],
        produces: vec!["provider-result".into()],
        selector,
        denominator_kind: "first-party-source-files".into(),
        runner: json!({"kind":"reasoning-contract", "contract":"fixture-reasoning-v1"}),
        host_capabilities: Vec::new(),
        execution: json!({}),
        reasoning: json!({"coverageRequest":{"mode":"risk-sampled", "runTokenBudget":100_000, "seatTokenBudget":25_000}}),
        benchmark: json!({"status":"unproven", "requiredForCleanClaim":false}),
        clean_claim: "evidence-only".into(),
        control_ids: Vec::new(),
        scopes: Vec::new(),
        selectable: true,
    }
}

fn release_fixture() -> (Fixture, InventoryEnvelope, FrozenPlan, Vec<PendingLensWork>) {
    let fixture = Fixture::new(&[
        ("ops/release.yml", "publish: false\n".into()),
        ("src/ordinary.rs", "pub fn plain() {}\n".into()),
    ]);
    let inventory = fixture.inventory();
    // Original selector matches nothing. Full frozen inventory still supplies
    // the release witness, which must create actual applicable review work.
    let plan = AuditPlan::compile_with_root(
        Some(&fixture.0),
        &inventory,
        &[spec(
            "reasoning.release-readiness",
            json!({"op":"paths", "paths":["missing.rs"]}),
        )],
    )
    .unwrap()
    .freeze(Some(b"coverage-regression-fixture-key"))
    .unwrap();
    let work = pending_lens_work(&fixture.0, &plan, &inventory).unwrap();
    (fixture, inventory, plan, work)
}

#[test]
fn triggered_release_lens_gets_witness_even_with_empty_original_selector() {
    let (_fixture, inventory, plan, work) = release_fixture();
    assert!(!work.is_empty());
    let provider = &plan.providers()[0];
    assert_eq!(provider.configuration["denominatorCount"], 1);
    assert_eq!(
        provider.configuration["coverage"]["reviewSet"],
        json!(["ops/release.yml"])
    );
    let trigger = &work[0].request.packet["triggerEvidence"];
    assert_eq!(trigger["inventoryDigest"], inventory.digest);
    assert_eq!(trigger["mandatoryWitnessPaths"], json!(["ops/release.yml"]));
    assert!(trigger["checkedPathsDigest"].is_string());
    assert_eq!(
        work[0].request.packet["excerptCoverage"]["materializedPaths"],
        json!(["ops/release.yml"])
    );
}

#[test]
fn removing_frozen_mandatory_witness_cannot_issue_successful_empty_lens() {
    let (fixture, inventory, plan, _) = release_fixture();
    let mut provider = plan.providers()[0].clone();
    provider.configuration.get_mut("coverage").unwrap()["reviewSet"] = json!([]);
    let error = trigger_evidence_for(
        &fixture.0,
        &provider,
        &inventory,
        &["ops/release.yml".into()],
    )
    .unwrap_err();
    assert!(error.to_string().contains("mandatory trigger witness"));
}

#[test]
fn oversized_promotion_does_not_starve_later_affordable_candidate() {
    let fixture = Fixture::new(&[
        ("src/donor.rs", "let donor = 0;\n".repeat(120)),
        ("src/large.rs", "let large = 0;\n".repeat(900)),
        ("src/small.rs", "let small = 0;\n".into()),
    ]);
    let inventory = fixture.inventory();
    let plan = AuditPlan::compile_with_root(
        Some(&fixture.0),
        &inventory,
        &[spec("reasoning.performance", json!({"op":"always"}))],
    )
    .unwrap()
    .freeze(Some(b"coverage-regression-fixture-key"))
    .unwrap();
    let mut provider = plan.providers()[0].clone();
    provider.configuration.insert("coverage".into(), json!({
        "mode":"risk-sampled", "bundle":"fixture", "seed":"fixture",
        "denominator":3, "reviewSet":["src/donor.rs"], "reviewSetDigest":"frozen-fixture",
        "strata":[{"name":"mandatory", "paths":[]}, {"name":"remainder", "paths":["src/donor.rs"]}],
        "excerpt":{"mode":"raw", "mandatoryMode":"raw", "dedup":false},
    }));
    let denominator = inventory
        .denominator_entries(&json!({"op":"always"}))
        .unwrap();
    let candidates = vec![
        ScannerCandidate {
            finding_id: "large".into(),
            path: Some("src/large.rs".into()),
            line: Some(1),
            severity: "high".into(),
            ..Default::default()
        },
        ScannerCandidate {
            finding_id: "small".into(),
            path: Some("src/small.rs".into()),
            line: Some(1),
            severity: "medium".into(),
            ..Default::default()
        },
    ];
    let source = excerpts::SourceReader::new(&fixture.0).unwrap();
    let review = sampled_review(
        &source,
        &provider,
        &denominator,
        Some(&candidates),
        lens_plan::ExcerptMode::Raw,
        &excerpts::ChangedHunks::new(),
        0,
    )
    .unwrap();
    assert_eq!(review.binding.unpromoted, vec!["src/large.rs"]);
    assert_eq!(review.binding.promoted, vec!["src/small.rs"]);
    assert_eq!(review.binding.displaced, vec!["src/donor.rs"]);
}

#[test]
fn materialized_packet_is_not_delivery_or_read_evidence() {
    let (_, _, _, work) = release_fixture();
    let request = &work[0].request;
    let coverage = &request.packet["excerptCoverage"];
    assert_eq!(coverage["examinedPaths"], json!([]));
    assert_eq!(coverage["evidenceState"]["delivery"], "unverified");
    assert_eq!(coverage["evidenceState"]["review"], "unverified");
    assert!(validate_delivery_evidence(request, &json!({})).is_err());
    let mut receipt = json!({
        "schemaVersion":1, "kind":"legion-evidence-delivery", "source":"host-transport",
        "receiptId":"host-receipt", "requestId":request.request_id,
        "packetDigest":canonical_digest(&request.packet).unwrap(),
        "deliveredPacketBytes":canonical_json_bytes(&request.packet).unwrap().len(),
        "complete":true, "truncated":false, "chunks":delivery_chunk_manifest(request).unwrap(),
    });
    assert!(validate_delivery_evidence(request, &receipt).is_ok());
    receipt["truncated"] = json!(true);
    assert!(validate_delivery_evidence(request, &receipt).is_err());
    receipt["truncated"] = json!(false);
    receipt["chunks"] = json!([]);
    assert!(validate_delivery_evidence(request, &receipt).is_err());
}

#[test]
fn partition_homes_each_selected_path_once_with_aliases_and_continuations() {
    let fixture = Fixture::new(&[
        ("src/a.rs", "let line = 0;\n".repeat(6_000)),
        ("src/b.rs", "fn b() {}\n".into()),
    ]);
    let items = vec![
        excerpts::ReviewItem {
            path: "src/a.rs".into(),
            mode: lens_plan::ExcerptMode::Raw,
        },
        excerpts::ReviewItem {
            path: "src/b.rs".into(),
            mode: lens_plan::ExcerptMode::Raw,
        },
    ];
    let aliases = BTreeMap::from([("src/a.rs".into(), vec!["src/copy.rs".into()])]);
    let partition = excerpts::partition_review_set_budgeted(
        &fixture.0,
        &items,
        &aliases,
        20,
        &excerpts::ChangedHunks::new(),
        &excerpts::FlaggedRegions::new(),
        Some(excerpts::PartBudget {
            cap_bytes: 40_000,
            listing_copies: 0,
        }),
    );
    assert!(partition.parts.len() > 1);
    let homes = partition
        .parts
        .iter()
        .flat_map(|part| part.paths.clone())
        .collect::<Vec<_>>();
    assert_eq!(homes.len(), 3);
    assert_eq!(
        homes.into_iter().collect::<BTreeSet<_>>(),
        BTreeSet::from(["src/a.rs".into(), "src/b.rs".into(), "src/copy.rs".into()])
    );
    let chunks = partition
        .parts
        .iter()
        .flat_map(|part| &part.excerpts)
        .filter(|excerpt| excerpt.path == "src/a.rs")
        .collect::<Vec<_>>();
    assert_eq!(chunks.len(), chunks[0].chunks);
    assert_eq!(
        chunks
            .iter()
            .map(|excerpt| excerpt.chunk)
            .collect::<BTreeSet<_>>()
            .len(),
        chunks.len()
    );
}

#[test]
fn every_candidate_has_one_domain_assignment_without_implicit_security_default() {
    let candidates = ["security", "data", "reliability", "release", "other"]
        .into_iter()
        .enumerate()
        .map(|(index, domain)| ScannerCandidate {
            finding_id: format!("candidate-{index}"),
            domain: domain.into(),
            ..Default::default()
        })
        .collect::<Vec<_>>();
    let routing = candidate_domain_partitions(&candidates);
    let ids = routing["partitions"]
        .as_array()
        .unwrap()
        .iter()
        .flat_map(|partition| {
            partition["candidateIds"]
                .as_array()
                .unwrap()
                .iter()
                .map(|id| id.as_str().unwrap())
        })
        .collect::<Vec<_>>();
    assert_eq!(ids.len(), candidates.len());
    assert_eq!(ids.iter().collect::<BTreeSet<_>>().len(), candidates.len());
    assert!(routing["partitions"]
        .as_array()
        .unwrap()
        .iter()
        .any(|partition| partition["domain"] == "unknown"
            && partition["status"] == "domain-review-unavailable"));
}

#[test]
fn conditional_witnesses_do_not_turn_other_bundles_exhaustive() {
    let paths = (0..80)
        .map(|index| format!("src/file_{index}.tsx"))
        .collect::<Vec<_>>();
    let facts = paths
        .iter()
        .map(|path| {
            (
                path.clone(),
                coverage_plan::FileFacts {
                    size: 8_000,
                    ..Default::default()
                },
            )
        })
        .collect();
    let lenses =
        ["reasoning.security", "reasoning.a11y"].map(|provider| coverage_plan::LensInput {
            provider_id: provider.into(),
            paths: paths.clone(),
        });
    let witnesses = BTreeMap::from([("reasoning.a11y".into(), paths.iter().cloned().collect())]);
    let plan = coverage_plan::plan_coverage_with_witnesses(
        &json!({}),
        &facts,
        &lenses,
        &coverage_plan::CoverageRequest {
            mode: coverage_plan::CoverageMode::RiskSampled,
            run_token_budget: 250_000,
            seat_token_budget: 25_000,
            ..Default::default()
        },
        &witnesses,
    )
    .unwrap();
    let conditional = coverage_plan::FrozenCoverage::from_value(&plan["reasoning.a11y"]).unwrap();
    let security = coverage_plan::FrozenCoverage::from_value(&plan["reasoning.security"]).unwrap();
    assert!(conditional.bounded);
    assert!(!conditional.review_set.is_empty());
    assert!(conditional.review_set.len() < paths.len());
    assert_eq!(
        conditional.mandatory_universe,
        paths.iter().cloned().collect::<BTreeSet<_>>()
    );
    assert!(conditional
        .mandatory
        .is_disjoint(&conditional.mandatory_deferred));
    assert_eq!(
        conditional
            .mandatory
            .union(&conditional.mandatory_deferred)
            .cloned()
            .collect::<BTreeSet<_>>(),
        conditional.mandatory_universe
    );
    assert_eq!(plan["reasoning.a11y"]["strata"][0]["N"], paths.len());
    assert_eq!(
        plan["reasoning.a11y"]["strata"][0]["n"],
        conditional.mandatory.len()
    );
    assert_eq!(plan["reasoning.a11y"]["confidence"]["claim"], "none");
    // Sharing source selection does not inherit another lens's witness duty.
    assert!(security.mandatory_universe.is_empty());
    assert!(security.mandatory.is_empty());
    assert!(security.review_set.len() < paths.len());
    assert_eq!(
        plan["reasoning.security"]["declaredUnsampled"],
        paths.len() - security.review_set.len()
    );
}

#[test]
fn shared_delivery_requires_exact_reconstruction_and_distinct_physical_byte_fields() {
    let (_fixture, _, _, work) = release_fixture();
    let request = &work[0].request;
    let shared = json!({"excerpts": request.packet["excerpts"]});
    let mut compact = request.packet.clone();
    compact["excerpts"] = json!({"$sharedContext":"excerpts"});
    let mut receipt = json!({
        "schemaVersion":1,"kind":"legion-evidence-delivery","source":"host-transport",
        "receiptId":"shared-receipt","requestId":request.request_id,
        "packetDigest":canonical_digest(&request.packet).unwrap(),
        "transportEncoding":"shared-context-v1", "reconstructedPacketBytes":canonical_json_bytes(&request.packet).unwrap().len(),
        "physicalRequestBytes":1234,"physicalRequestDigest":format!("sha256:{}", "a".repeat(64)),
        "sharedContextDigest":canonical_digest(&shared).unwrap(),
        "reconstruction":{"sharedContext":shared,"compactPacket":compact},
        "complete":true,"truncated":false,"chunks":delivery_chunk_manifest(request).unwrap()
    });
    assert!(validate_delivery_evidence(request, &receipt).is_ok());
    receipt["deliveredPacketBytes"] = json!(1234);
    assert!(validate_delivery_evidence(request, &receipt).is_err());
    receipt
        .as_object_mut()
        .unwrap()
        .remove("deliveredPacketBytes");
    receipt["reconstruction"]["compactPacket"]["provider"] = json!("different-provider");
    assert!(validate_delivery_evidence(request, &receipt).is_err());
}

#[test]
fn delivery_chunk_identity_cannot_change_source_side() {
    let (_fixture, _, _, work) = release_fixture();
    let mut request = work[0].request.clone();
    request.packet["excerpts"][0]["sourceSide"] = json!("base");
    let manifest = delivery_chunk_manifest(&request).unwrap();
    assert_eq!(manifest[0]["sourceSide"], "base");
    let mut receipt = json!({
        "schemaVersion":1,"kind":"legion-evidence-delivery","source":"host-transport",
        "receiptId":"side-receipt","requestId":request.request_id,
        "packetDigest":canonical_digest(&request.packet).unwrap(),
        "deliveredPacketBytes":canonical_json_bytes(&request.packet).unwrap().len(),
        "complete":true,"truncated":false,"chunks":manifest
    });
    assert!(validate_delivery_evidence(&request, &receipt).is_ok());
    receipt["chunks"][0]["sourceSide"] = json!("selected");
    assert!(validate_delivery_evidence(&request, &receipt).is_err());
}

#[test]
fn unavailable_trigger_checks_keep_bounded_review_without_becoming_witnesses() {
    let evaluation = triggers::TriggerEvaluation {
        lens: "resilience",
        fired: false,
        reason: "unavailable source".into(),
        evidence_paths: Vec::new(),
        unavailable_paths: vec!["src/z.rs".into(), "src/a.rs".into()],
    };
    assert!(evaluation.required_paths().is_empty());
    assert_eq!(evaluation.applicable_paths(), vec!["src/a.rs".to_owned()]);
    let snapshot = evaluation
        .snapshot("inventory", &evaluation.unavailable_paths)
        .unwrap();
    assert_eq!(snapshot["applicability"], "unavailable");
    assert_eq!(snapshot["unavailablePaths"].as_array().unwrap().len(), 2);
    assert!(snapshot["mandatoryWitnessPaths"]
        .as_array()
        .unwrap()
        .is_empty());
}

#[test]
fn final_pretty_envelope_refinement_preserves_every_selected_home() {
    let files = (0..120)
        .map(|index| {
            (
                format!("src/long_module_name_for_packet_overhead_{index:04}.rs"),
                format!("pub fn fixture_{index}() {{ let value = {index}; consume(value); }}\n")
                    .repeat(12),
            )
        })
        .collect::<Vec<_>>();
    let borrowed = files
        .iter()
        .map(|(path, body)| (path.as_str(), body.clone()))
        .collect::<Vec<_>>();
    let fixture = Fixture::new(&borrowed);
    let inventory = fixture.inventory();
    let mut provider = spec("reasoning.performance", json!({"op":"always"}));
    provider.reasoning["coverageRequest"] =
        json!({"mode":"exhaustive","runTokenBudget":1_000_000,"seatTokenBudget":25_000});
    let plan = AuditPlan::compile_with_root(Some(&fixture.0), &inventory, &[provider])
        .unwrap()
        .freeze(Some(b"envelope-refinement-fixture-key"))
        .unwrap();
    let work = pending_lens_work(&fixture.0, &plan, &inventory).unwrap();
    assert!(work.len() > 1);
    let target = ingest::physical_planning_input_bytes(25_000);
    let mut homes = Vec::new();
    for item in &work {
        assert!(
            crate::review_runtime::InitialRequestSizer::default()
                .model_visible_input_bytes(std::slice::from_ref(item))
                .unwrap()
                <= target
        );
        assert!(required_packet_gaps(&item.request).is_empty());
        homes.extend(
            item.request.packet["excerptCoverage"]["selectedPaths"]
                .as_array()
                .unwrap()
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_owned),
        );
    }
    assert_eq!(homes.len(), files.len());
    assert_eq!(
        homes.into_iter().collect::<BTreeSet<_>>(),
        inventory.paths().map(str::to_owned).collect()
    );
}

#[test]
fn tracked_oversize_source_survives_snapshot_inventory_and_planning_as_a_gap() {
    let root = std::env::temp_dir().join(format!(
        "audit-oversize-planning-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos(),
    ));
    std::fs::create_dir_all(&root).unwrap();
    let result = (|| {
        let oversized_path = "src/parser.c";
        std::fs::create_dir_all(root.join("src")).unwrap();
        std::fs::write(root.join("src/lib.rs"), "pub fn stable() {}\n").unwrap();
        std::fs::File::create(root.join(oversized_path))
            .unwrap()
            .set_len(37_337_414)
            .unwrap();
        fn git(root: &Path, args: &[&str]) {
            let mut command = crate::trusted_git::owned_command(root).expect("trusted git");
            command
                .command_mut()
                .current_dir(root)
                .args(args)
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null());
            let mut child = command.spawn().unwrap();
            assert!(child
                .wait_timeout(std::time::Duration::from_secs(30))
                .unwrap()
                .unwrap()
                .success());
        }
        git(&root, &["init", "-q"]);
        git(&root, &["config", "user.name", "Audit Test"]);
        git(&root, &["config", "user.email", "audit@example.invalid"]);
        git(&root, &["add", "src/lib.rs", oversized_path]);
        git(&root, &["commit", "-qm", "fixture"]);

        let live_inventory = FilesystemInventorySource::new(&root)
            .unwrap()
            .inventory("oversize-live-inventory-regression")
            .unwrap();
        assert!(live_inventory.paths().any(|path| path == oversized_path));
        assert!(live_inventory
            .denominator_entries(&json!({"op":"always"}))
            .unwrap()
            .entries
            .iter()
            .all(|entry| entry.path != oversized_path));

        let resolved =
            crate::scope::ResolvedScope::resolve(&root, crate::scope::ScopeSpec::Repo, None)
                .unwrap();
        let snapshot = crate::snapshot::FrozenSnapshot::capture(resolved).unwrap();
        let gap = format!("oversize:{oversized_path}");
        assert!(snapshot.manifest.gaps.contains(&gap));
        let uncovered = snapshot
            .uncovered_metadata(oversized_path, crate::snapshot::SnapshotSide::Selected)
            .unwrap();
        assert_eq!(uncovered.bytes, 37_337_414);
        assert_eq!(
            uncovered.digest,
            crate::snapshot::uncovered_file_digest(oversized_path, uncovered.bytes)
        );
        assert!(!snapshot.manifest.files.contains_key(oversized_path));

        let execution_root = snapshot.manifest.execution_root.clone();
        let inventory = FilesystemInventorySource::new(&execution_root)
            .unwrap()
            .inventory("oversize-planning-regression")
            .unwrap();
        let entry = inventory
            .entries
            .iter()
            .find(|entry| entry.path == oversized_path)
            .unwrap();
        let expected_digest = format!("oversize:{}:{}", uncovered.bytes, uncovered.digest);
        assert_eq!(entry.digest.as_deref(), Some(expected_digest.as_str()));
        assert!(inventory.paths().any(|path| path == oversized_path));
        assert_eq!(
            inventory
                .denominator_entries(&json!({"op":"always"}))
                .unwrap()
                .entries
                .iter()
                .map(|entry| entry.path.as_str())
                .collect::<Vec<_>>(),
            ["src/lib.rs"]
        );

        let plan = AuditPlan::compile_with_root(
            Some(&execution_root),
            &inventory,
            &[spec("reasoning.performance", json!({"op":"always"}))],
        )
        .unwrap()
        .freeze(Some(b"oversize-planning-regression-key"))
        .unwrap();
        let facts =
            super::coverage_plan::gather_facts(&execution_root, &inventory, &BTreeSet::new());
        assert_eq!(facts[oversized_path].size, 37_337_414);
        let work = pending_lens_work(&execution_root, &plan, &inventory).unwrap();
        assert!(!work.is_empty());
        for item in work {
            assert!(!item.request.packet["excerptCoverage"]["selectedPaths"]
                .as_array()
                .unwrap()
                .iter()
                .any(|path| path.as_str() == Some(oversized_path)));
            assert!(!item.request.packet["excerpts"]
                .as_array()
                .unwrap()
                .iter()
                .any(|excerpt| excerpt["path"] == oversized_path));
        }
        std::fs::OpenOptions::new()
            .write(true)
            .open(root.join(oversized_path))
            .unwrap()
            .set_len(1)
            .unwrap();
        let partial_change = crate::snapshot::FrozenSnapshot::capture(
            crate::scope::ResolvedScope::resolve(&root, crate::scope::ScopeSpec::Uncommitted, None)
                .unwrap(),
        )
        .unwrap();
        assert!(partial_change
            .manifest
            .scope
            .changed_paths
            .contains(oversized_path));
        assert!(partial_change
            .uncovered_metadata(oversized_path, crate::snapshot::SnapshotSide::Base)
            .is_some());
        assert!(partial_change
            .changed_source(oversized_path, 2 * 1024 * 1024)
            .unwrap_err()
            .to_string()
            .contains("unavailable:oversize"));
        Ok::<(), crate::AuditError>(())
    })();
    let _ = std::fs::remove_dir_all(&root);
    result.unwrap();
}

#[test]
fn tiny_run_defers_large_mandatory_source_and_keeps_affordable_raw_review() {
    let paths = vec!["src/auth.rs".to_owned(), "src/auth/small.rs".to_owned()];
    let facts = paths
        .iter()
        .enumerate()
        .map(|(index, path)| {
            (
                path.clone(),
                coverage_plan::FileFacts {
                    size: if index == 0 { 10_000_000 } else { 1024 },
                    signal: Some("security-sensitive"),
                    ..Default::default()
                },
            )
        })
        .collect();
    let plan = coverage_plan::plan_coverage(
        &json!({}),
        &facts,
        &[coverage_plan::LensInput {
            provider_id: "reasoning.security".into(),
            paths: paths.clone(),
        }],
        &coverage_plan::CoverageRequest {
            mode: coverage_plan::CoverageMode::RiskSampled,
            run_token_budget: 50_000,
            seat_token_budget: 10_000,
            max_total_seats: 5,
        },
    )
    .unwrap();
    let coverage = &plan["reasoning.security"];
    assert_eq!(coverage["reviewSet"], json!(["src/auth/small.rs"]));
    assert_eq!(coverage["mandatoryUniverse"], json!(paths));
    assert_eq!(coverage["mandatoryDeferred"], json!(["src/auth.rs"]));
    assert_eq!(coverage["strata"][0]["N"], 2);
    assert_eq!(coverage["strata"][0]["n"], 1);
    assert_eq!(coverage["declaredUnsampled"], 1);
    assert_eq!(coverage["confidence"]["claim"], "none");
    assert_eq!(coverage["excerpt"]["mode"], "raw");
    assert_eq!(coverage["followupReserveTokens"], 10_000);
}

#[test]
fn unaffordable_remainder_never_invents_review_or_statistical_confidence() {
    let paths = (0..1000)
        .map(|index| format!("src/file_{index}.rs"))
        .collect::<Vec<_>>();
    let facts = paths
        .iter()
        .map(|path| {
            (
                path.clone(),
                coverage_plan::FileFacts {
                    size: 16_000,
                    ..Default::default()
                },
            )
        })
        .collect();
    let plan = coverage_plan::plan_coverage(
        &json!({}),
        &facts,
        &[coverage_plan::LensInput {
            provider_id: "reasoning.performance".into(),
            paths: paths.clone(),
        }],
        &coverage_plan::CoverageRequest {
            mode: coverage_plan::CoverageMode::RiskSampled,
            run_token_budget: 50_000,
            seat_token_budget: 10_000,
            max_total_seats: 5,
        },
    )
    .unwrap();
    let coverage = &plan["reasoning.performance"];
    let count = coverage["reviewSet"].as_array().unwrap().len();
    assert_eq!(count, 0, "whole raw files exceed bounded source allowance");
    assert_eq!(coverage["strata"][1]["N"], paths.len());
    assert_eq!(coverage["strata"][1]["n"], 0);
    assert_eq!(
        coverage["confidence"],
        json!({"claim":"none", "basis":"bounded-risk-selection"})
    );
    assert_eq!(coverage["sampleFloorMet"], false);
    assert_eq!(coverage["declaredUnsampled"], paths.len() - count);
    assert!(coverage["estimatedTokens"].as_u64().unwrap() <= 30_000);
}

#[test]
fn source_chunks_adapt_to_small_parts_without_losing_source_lines() {
    let source = (0..2000)
        .map(|index| format!("let source_{index} = {index};\n"))
        .collect::<String>();
    let fixture = Fixture::new(&[("src/source.rs", source)]);
    let parts = excerpts::partition_review_set_budgeted(
        &fixture.0,
        &[excerpts::ReviewItem {
            path: "src/source.rs".into(),
            mode: lens_plan::ExcerptMode::Raw,
        }],
        &BTreeMap::new(),
        100,
        &excerpts::ChangedHunks::new(),
        &excerpts::FlaggedRegions::new(),
        Some(excerpts::PartBudget {
            cap_bytes: 4000,
            listing_copies: 0,
        }),
    );
    assert!(parts.parts.len() > 2);
    assert!(parts.unscheduled_paths.is_empty());
    let chunks = parts
        .parts
        .iter()
        .flat_map(|part| &part.excerpts)
        .collect::<Vec<_>>();
    assert_eq!(chunks.len(), chunks[0].chunks);
    let mut next_line = 1;
    for chunk in chunks {
        assert_eq!(chunk.start_line, next_line);
        next_line = chunk.end_line + 1;
        assert!(chunk.content.len() < 4000);
    }
    assert_eq!(next_line, 2001);
}

#[test]
fn shared_seat_transports_exact_common_metadata_once() {
    let (_fixture, _, _, work) = release_fixture();
    let mut first = work[0].clone();
    first.provider_id = "reasoning.security".into();
    first.request.provider_id = first.provider_id.clone();
    first.request.request_id = "security-context".into();
    first.request.packet["reviewContext"] =
        json!({"scopeBasis":"frozen scope metadata\n".repeat(2000)});
    first.request.packet["lensPlan"] =
        json!({"lens":"security", "bundle":{"id":"J1","tier":"judgment"}});
    let mut second = first.clone();
    second.provider_id = "reasoning.correctness".into();
    second.request.provider_id = second.provider_id.clone();
    second.request.request_id = "correctness-context".into();
    second.request.packet["lensPlan"]["lens"] = json!("correctness");
    let works = vec![first, second];
    let payload = ingest::shared_seat_payload(&works).unwrap().unwrap();
    assert_eq!(
        payload["sharedContext"]["reviewContext"],
        works[0].request.packet["reviewContext"]
    );
    assert_eq!(
        payload["lenses"][0]["packet"]["reviewContext"],
        json!({"$sharedContext":"reviewContext"})
    );
    let physical = crate::review_runtime::initial_seat_request_bytes(&works).unwrap();
    let unshared = works
        .iter()
        .map(|work| {
            crate::review_runtime::initial_seat_request_bytes(std::slice::from_ref(work)).unwrap()
        })
        .sum::<u64>();
    assert!(physical + 40_000 < unshared);
    let request = &works[0].request;
    let mut proof = json!({
        "schemaVersion":1,"kind":"legion-evidence-delivery","source":"host-transport",
        "receiptId":"shared-metadata","requestId":request.request_id,
        "packetDigest":canonical_digest(&request.packet).unwrap(),
        "transportEncoding":"shared-context-v1",
        "reconstructedPacketBytes":canonical_json_bytes(&request.packet).unwrap().len(),
        "physicalRequestBytes":physical,"physicalRequestDigest":format!("sha256:{}", "a".repeat(64)),
        "sharedContextDigest":payload["sharedContextDigest"],
        "reconstruction":{"sharedContext":payload["sharedContext"],"compactPacket":payload["lenses"][0]["packet"]},
        "complete":true,"truncated":false,"chunks":delivery_chunk_manifest(request).unwrap(),
    });
    assert!(validate_delivery_evidence(request, &proof).is_ok());
    proof["reconstruction"]["sharedContext"]["reviewContext"] = json!({"scopeBasis":"tampered"});
    proof["sharedContextDigest"] =
        json!(canonical_digest(&proof["reconstruction"]["sharedContext"]).unwrap());
    assert!(validate_delivery_evidence(request, &proof).is_err());
}

#[test]
fn bundle_count_does_not_refuse_compatible_bounded_source_selection() {
    let paths = vec!["src/ordinary.rs".to_owned()];
    let facts = BTreeMap::from([(
        paths[0].clone(),
        coverage_plan::FileFacts {
            size: 1024,
            ..Default::default()
        },
    )]);
    let lenses = [
        "reasoning.security",
        "reasoning.architecture",
        "reasoning.performance",
        "reasoning.minimize",
        "reasoning.naming",
        "reasoning.dead-file",
    ]
    .map(|provider| coverage_plan::LensInput {
        provider_id: provider.into(),
        paths: paths.clone(),
    });
    let plan = coverage_plan::plan_coverage(
        &json!({}),
        &facts,
        &lenses,
        &coverage_plan::CoverageRequest {
            mode: coverage_plan::CoverageMode::RiskSampled,
            run_token_budget: 50_000,
            seat_token_budget: 10_000,
            max_total_seats: 5,
        },
    )
    .unwrap();
    assert_eq!(plan.len(), lenses.len());
    for config in plan.values() {
        assert_eq!(config["reviewSet"], json!(["src/ordinary.rs"]));
        assert_eq!(config["denominator"], 1);
        assert_eq!(config["confidence"]["claim"], "none");
        assert_eq!(config["followupReserveTokens"], 10_000);
    }
    let impossible = coverage_plan::plan_coverage(
        &json!({}),
        &facts,
        &lenses,
        &coverage_plan::CoverageRequest {
            mode: coverage_plan::CoverageMode::RiskSampled,
            run_token_budget: 50_000,
            seat_token_budget: 10_000,
            max_total_seats: 1,
        },
    );
    assert!(matches!(impossible, Err(AuditError::BoundExceeded(_))));
}

fn bounded_request() -> Value {
    json!({"mode":"risk-sampled", "runTokenBudget":50_000,
        "seatTokenBudget":10_000, "maxTotalSeats":5})
}

#[test]
fn rendered_input_allowance_matches_dispatch_token_boundary() {
    for per_call in [1, 10_000, 25_000, 150_000] {
        let bytes = ingest::physical_planning_input_bytes(per_call);
        let output = ingest::minimum_output_tokens(ingest::dispatch_output_tokens(per_call), 1);
        let limit = ingest::physical_planning_limit(per_call);
        assert!(crate::next::estimated_request_tokens(bytes, output) <= limit);
        assert!(crate::next::estimated_request_tokens(bytes + 1, output) > limit);
    }
}

#[test]
fn adaptive_output_chooses_largest_fitting_cap_without_starving_shared_lenses() {
    let ceiling = ingest::dispatch_output_tokens(10_000);
    assert_eq!(ceiling, 2_500);
    let single = ingest::minimum_output_tokens(ceiling, 1);
    assert_eq!(single, 1_000);
    for (bytes, expected) in [
        (12_000, Some(2_500)),
        (14_000, Some(1_500)),
        (15_000, Some(1_000)),
        (15_001, None),
    ] {
        assert_eq!(
            ingest::fitting_output_tokens(10_000, ceiling, bytes, single),
            expected
        );
    }
    let shared = ingest::minimum_output_tokens(ceiling, 2);
    assert_eq!(
        ingest::fitting_output_tokens(10_000, ceiling, 13_000, shared),
        Some(2_000)
    );
    assert_eq!(
        ingest::fitting_output_tokens(10_000, ceiling, 13_001, shared),
        None
    );
    assert_eq!(
        ingest::fitting_output_tokens(
            10_000,
            ceiling,
            0,
            ingest::minimum_output_tokens(ceiling, 3)
        ),
        None
    );
    assert_eq!(ingest::minimum_output_tokens(50, 1), 50);
    assert_eq!(
        ingest::fitting_output_tokens(100, 50, 70, ingest::minimum_output_tokens(50, 1)),
        Some(50)
    );
}

#[test]
fn empirical_allowance_keeps_complete_twelve_line_raw_review_within_frozen_budget() {
    let source = concat!(
        "pub fn display_name(raw: &str) -> String {\n",
        "    let name = raw.trim();\n",
        "    if name.is_empty() {\n",
        "        return String::from(\"Unnamed\");\n",
        "    }\n",
        "    let mut value = String::new();\n",
        "    for word in name.split_whitespace() {\n",
        "        if !value.is_empty() { value.push(' '); }\n",
        "        value.push_str(word);\n",
        "    }\n",
        "    value\n",
        "}\n",
    );
    assert_eq!(source.lines().count(), 12);
    let fixture = Fixture::new(&[("src/display_name.rs", source.into())]);
    let inventory = fixture.inventory();
    let mut provider = spec("reasoning.doc-drift", json!({"op":"always"}));
    provider.reasoning["coverageRequest"] = bounded_request();
    let plan = AuditPlan::compile_with_root(Some(&fixture.0), &inventory, &[provider])
        .unwrap()
        .freeze(Some(b"empirical-input-fixture-key"))
        .unwrap();
    let frozen = serde_json::to_value(plan.plan()).unwrap();
    let work = pending_lens_work(&fixture.0, &plan, &inventory).unwrap();
    let dispatch = ingest::lens_dispatch_plan(
        &work,
        &ingest::DispatchLimits {
            run_token_budget: 50_000,
            seat_token_budget: 10_000,
            max_total_seats: 5,
            wave_width: 1,
        },
    );
    assert_eq!(dispatch["withinLimits"], true, "{dispatch}");
    assert_eq!(dispatch["requiredInitialCalls"], 1, "{dispatch}");
    assert_eq!(dispatch["followupReserveCalls"], 1);
    assert_eq!(dispatch["reasoningBudget"]["outputTokens"], 2_500);
    assert_eq!(dispatch["reasoningBudget"]["totalTokens"], 50_000);
    assert_eq!(dispatch["reasoningBudget"]["perCallTokens"], 10_000);
    assert_eq!(dispatch["reasoningBudget"]["maxSeats"], 5);
    let selected = dispatch["selectedPackets"].as_array().unwrap();
    let item = work
        .iter()
        .find(|item| selected.contains(&json!(item.packet_file_name())))
        .expect("complete source review must remain schedulable");
    let mut expected_lens_plan = lens_plan::lens_plan_packet_value("reasoning.doc-drift").unwrap();
    pattern_cards::bind_packet_cards_to_paths(
        &mut expected_lens_plan,
        &["src/display_name.rs".into()],
    );
    // No domain contracts are declared in this repository: the plan says so.
    pattern_cards::bind_domain_contract(&mut expected_lens_plan, None, None);
    assert_eq!(item.request.packet["lensPlan"], expected_lens_plan);
    assert_eq!(
        item.request.packet["reportSchemaBody"],
        lens_schemas::lens_report_schema("doc-drift").unwrap()
    );
    assert_eq!(
        item.request.packet["semanticReviewContract"],
        json!(lens_plan::semantic_review_contract("doc-drift"))
    );
    assert!(
        item.request.packet["excerpts"]
            .as_array()
            .unwrap()
            .iter()
            .any(|excerpt| {
                excerpt["path"] == "src/display_name.rs"
                    && excerpt["mode"] == "raw"
                    && excerpt["content"] == source
                    && excerpt["startLine"] == 1
                    && excerpt["endLine"] == 12
            }),
        "{dispatch}"
    );
    let bytes = crate::review_runtime::InitialRequestSizer::default()
        .model_visible_input_bytes(std::slice::from_ref(item))
        .unwrap();
    assert_eq!(
        dispatch["seats"][0]["estimatedInputTokens"],
        crate::next::estimated_request_tokens(bytes, 0)
    );
    let output = dispatch["seats"][0]["outputTokenLimit"].as_u64().unwrap();
    assert!((1_000..=2_500).contains(&output), "{dispatch}");
    assert_eq!(dispatch["seats"][0]["outputTokenCeiling"], 2_500);
    assert_eq!(
        dispatch["seats"][0]["estimatedTokens"],
        crate::next::estimated_request_tokens(bytes, output)
    );
    assert!(
        bytes <= ingest::physical_planning_input_bytes(10_000),
        "{bytes}: {dispatch}"
    );
    assert_eq!(serde_json::to_value(plan.plan()).unwrap(), frozen);
}

#[test]
fn bounded_refinement_retains_intermediate_fit_when_final_probe_is_oversized() {
    let mut probes = Vec::new();
    let budget = excerpts::PartBudget {
        cap_bytes: 20_000,
        listing_copies: 3,
    };
    let (selected_cap, measured) = refine_packet_materialization(budget, 23_800, |candidate| {
        assert_eq!(candidate.listing_copies, budget.listing_copies);
        probes.push(candidate.cap_bytes);
        Ok((candidate.cap_bytes, 18_000 + candidate.cap_bytes as u64))
    })
    .unwrap();
    assert!(probes.len() <= 8);
    assert_eq!(&probes[..2], &[20_000, 1]);
    assert!(18_000 + *probes.last().unwrap() as u64 > 23_800);
    assert_eq!(selected_cap, 5_625);
    assert_eq!(measured, 23_625);
    assert!(
        selected_cap / 2 >= 948,
        "complete fixture RAW file fits selected chunk cap"
    );
    let mut probes = 0;
    let (minimum, measured) = refine_packet_materialization(budget, 24_000, |candidate| {
        probes += 1;
        Ok((candidate.cap_bytes, 25_000 + candidate.cap_bytes as u64))
    })
    .unwrap();
    assert_eq!(probes, 2);
    assert_eq!(minimum, 1);
    assert!(
        measured > 24_000,
        "irreducible input remains explicitly unfit"
    );
}

#[test]
fn architecture_docs_are_bounded_context_never_counted_as_coverage() {
    let mut files = vec![
        ("src/lib.rs", "pub fn plain() {}\n".to_owned()),
        (
            "ARCHITECTURE.md",
            "# Rules\nui must not import storage.\n".to_owned(),
        ),
        (
            "docs/architecture/layers.md",
            format!("# Layers\n{}", "core depends on nothing.\n".repeat(600)),
        ),
        (
            "docs/adr/0001-layering.md",
            "# ADR 1\nAccepted.\n".to_owned(),
        ),
        ("docs/guide.md", "# Unrelated guide\n".to_owned()),
        ("docs/provenance/old.md", "# Frozen history\n".to_owned()),
    ];
    let extra: Vec<String> = (2..10)
        .map(|n| format!("docs/decisions/{n:04}.md"))
        .collect();
    for path in &extra {
        files.push((path.as_str(), "# Decision\nbody\n".repeat(300)));
    }
    let fixture = Fixture::new(&files);
    let inventory = fixture.inventory();
    let plan = AuditPlan::compile_with_root(
        Some(&fixture.0),
        &inventory,
        &[
            spec(
                "reasoning.architecture",
                json!({"op":"anyPath","patterns":["src/**"]}),
            ),
            spec(
                "reasoning.correctness",
                json!({"op":"anyPath","patterns":["src/**"]}),
            ),
        ],
    )
    .unwrap()
    .freeze(Some(b"architecture-docs-fixture-key"))
    .unwrap();
    let work = pending_lens_work(&fixture.0, &plan, &inventory).unwrap();
    let architecture = work
        .iter()
        .find(|item| item.provider_id == "reasoning.architecture")
        .unwrap();
    let packet = &architecture.request.packet;
    let docs = &packet["docContext"];
    assert_eq!(docs["countedAsCoverage"], false);
    let documents = docs["documents"].as_array().unwrap();
    let paths: Vec<&str> = documents
        .iter()
        .map(|doc| doc["path"].as_str().unwrap())
        .collect();
    // Rank order: ARCHITECTURE.md, docs/architecture/**, then ADR directories.
    assert_eq!(paths[0], "ARCHITECTURE.md");
    assert_eq!(paths[1], "docs/architecture/layers.md");
    assert!(paths.contains(&"docs/adr/0001-layering.md"));
    assert!(!paths.contains(&"docs/guide.md"));
    assert!(!paths
        .iter()
        .any(|path| path.starts_with("docs/provenance/")));
    assert!(documents[0]["content"]
        .as_str()
        .unwrap()
        .contains("ui must not import storage"));
    // Bounded: count, per-document and total bytes; omission is declared.
    assert!(documents.len() <= packet_context::DOC_CONTEXT_MAX_DOCS);
    let mut total = 0;
    for doc in documents {
        let len = doc["content"].as_str().unwrap().len();
        assert!(len <= packet_context::DOC_CONTEXT_FILE_BYTES);
        total += len;
    }
    assert!(total <= packet_context::DOC_CONTEXT_TOTAL_BYTES);
    assert_eq!(documents[1]["truncated"], true);
    assert_eq!(docs["included"], documents.len());
    assert_eq!(
        docs["omitted"].as_u64().unwrap() + documents.len() as u64,
        docs["available"].as_u64().unwrap()
    );
    assert!(docs["omitted"].as_u64().unwrap() > 0);
    // Not source coverage: neither the denominator, excerpts, nor coverage
    // accounting carry any documentation path.
    let is_doc = |path: &str| path.ends_with(".md");
    assert!(packet["excerpts"]
        .as_array()
        .unwrap()
        .iter()
        .all(|excerpt| !is_doc(excerpt["path"].as_str().unwrap())));
    assert_eq!(packet["binding"]["denominatorCount"], 1);
    assert!(!packet["excerptCoverage"].to_string().contains(".md"));
    // Other lenses never receive it.
    let correctness = work
        .iter()
        .find(|item| item.provider_id == "reasoning.correctness")
        .unwrap();
    assert!(correctness.request.packet.get("docContext").is_none());
}

#[test]
fn architecture_packet_without_docs_omits_doc_context() {
    let fixture = Fixture::new(&[("src/lib.rs", "pub fn plain() {}\n".to_owned())]);
    let inventory = fixture.inventory();
    let plan = AuditPlan::compile_with_root(
        Some(&fixture.0),
        &inventory,
        &[spec("reasoning.architecture", json!({"op":"always"}))],
    )
    .unwrap()
    .freeze(Some(b"architecture-nodocs-fixture-key"))
    .unwrap();
    let work = pending_lens_work(&fixture.0, &plan, &inventory).unwrap();
    assert!(work[0].request.packet.get("docContext").is_none());
}

const LENS_DOC_PAIRS: [(&str, &str); 7] = [
    ("reasoning.minimize", "contracts/pricing.md"),
    ("reasoning.performance", "contracts/order-database.md"),
    ("reasoning.a11y", "contracts/checkout-accessibility.md"),
    ("reasoning.ai-slop", "docs/comment-style.md"),
    ("reasoning.naming", "docs/naming.md"),
    ("reasoning.dead-file", "docs/module-discovery.md"),
    ("reasoning.platform-parity", "contracts/workspace.md"),
];

fn lens_doc_files(with_docs: bool) -> Vec<(&'static str, String)> {
    let mut files = vec![(
        "src/lib.rs",
        "pub fn plain() {}\n// rules: docs/referenced-rules.md\n".to_owned(),
    )];
    if with_docs {
        for (_, path) in LENS_DOC_PAIRS {
            files.push((path, format!("# {path}\n{}", "rule line.\n".repeat(600))));
        }
        files.push(("docs/unrelated-guide.md", "# Unrelated\n".to_owned()));
        files.push((
            "docs/referenced-rules.md",
            "# Referenced\nrule.\n".to_owned(),
        ));
        files.push(("docs/provenance/naming.md", "# Frozen naming\n".to_owned()));
        files.push(("docs/history/naming-old.md", "# Old naming\n".to_owned()));
    }
    files
}

fn lens_doc_work(provider: &str, with_docs: bool) -> Vec<PendingLensWork> {
    let fixture = Fixture::new(&lens_doc_files(with_docs));
    let inventory = fixture.inventory();
    let plan = AuditPlan::compile_with_root(
        Some(&fixture.0),
        &inventory,
        &[spec(
            provider,
            json!({"op":"anyPath","patterns":["src/**"]}),
        )],
    )
    .unwrap()
    .freeze(Some(b"lens-docs-fixture-key"))
    .unwrap();
    pending_lens_work(&fixture.0, &plan, &inventory).unwrap()
}

fn doc_paths(packet: &Value) -> Vec<String> {
    packet["docContext"]["documents"]
        .as_array()
        .map(|docs| {
            docs.iter()
                .map(|doc| doc["path"].as_str().unwrap().to_owned())
                .collect()
        })
        .unwrap_or_default()
}

#[test]
fn each_lens_selects_its_relevant_document_and_never_an_unrelated_one() {
    for (provider, expected) in LENS_DOC_PAIRS {
        let work = lens_doc_work(provider, true);
        let packet = &work[0].request.packet;
        // The explicitly referenced doc ranks first; the lens's own keyword
        // doc follows; unrelated, provenance and history docs never appear.
        assert_eq!(
            doc_paths(packet),
            vec!["docs/referenced-rules.md".to_owned(), expected.to_owned()],
            "{provider}"
        );
        let docs = &packet["docContext"];
        assert_eq!(docs["countedAsCoverage"], false, "{provider}");
        assert_eq!(docs["untrusted"], true, "{provider}");
        assert_eq!(docs["documents"][0]["selection"], "explicit-reference");
        assert_eq!(docs["documents"][1]["selection"], "path-keyword");
        assert!(docs["documents"][1]["digest"].as_str().unwrap().len() > 8);
        let total: usize = docs["documents"]
            .as_array()
            .unwrap()
            .iter()
            .map(|doc| doc["content"].as_str().unwrap().len())
            .sum();
        assert!(total <= packet_context::LENS_DOC_TOTAL_BYTES, "{provider}");
        assert_eq!(docs["documents"][1]["truncated"], true, "{provider}");
        // Docs are never source coverage.
        assert!(!packet["excerptCoverage"].to_string().contains(".md"));
        assert_eq!(packet["binding"]["denominatorCount"], 1);
        assert!(packet["excerpts"]
            .as_array()
            .unwrap()
            .iter()
            .all(|excerpt| !excerpt["path"].as_str().unwrap().ends_with(".md")));
    }
}

#[test]
fn lens_without_reference_or_keyword_match_gets_no_document_filler() {
    // correctness has no keyword row and nothing references a doc: no filler.
    let fixture = Fixture::new(&[
        ("src/lib.rs", "pub fn plain() {}\n".to_owned()),
        ("docs/naming.md", "# Naming\n".to_owned()),
        ("contracts/pricing.md", "# Pricing\n".to_owned()),
    ]);
    let inventory = fixture.inventory();
    let plan = AuditPlan::compile_with_root(
        Some(&fixture.0),
        &inventory,
        &[spec("reasoning.correctness", json!({"op":"always"}))],
    )
    .unwrap()
    .freeze(Some(b"lens-docs-nofiller-key"))
    .unwrap();
    let work = pending_lens_work(&fixture.0, &plan, &inventory).unwrap();
    assert!(work[0].request.packet.get("docContext").is_none());
}

#[test]
fn lens_doc_budget_shrinks_then_omits_with_recorded_status_leaving_source_unchanged() {
    let fixture = Fixture::new(&lens_doc_files(true));
    let inventory = fixture.inventory();
    let plan = AuditPlan::compile_with_root(
        Some(&fixture.0),
        &inventory,
        &[spec(
            "reasoning.naming",
            json!({"op":"anyPath","patterns":["src/**"]}),
        )],
    )
    .unwrap()
    .freeze(Some(b"lens-docs-budget-key"))
    .unwrap();
    let provider = &plan.providers()[0];
    let denominator = reasoning_denominator(&plan, provider, &inventory).unwrap();
    let source = excerpts::SourceReader::new(&fixture.0).unwrap();
    let build = |level| {
        build_invocations_with_docs(
            &plan,
            provider,
            &inventory,
            &denominator,
            "pending-host",
            &source,
            None,
            seat_part_budget(provider),
            level,
        )
        .unwrap()
        .0
    };
    let full = build(packet_context::DocBudget::Full);
    let half = build(packet_context::DocBudget::Half);
    let omitted = build(packet_context::DocBudget::Omitted);
    let doc_bytes = |packet: &Value| -> usize {
        packet["docContext"]["documents"]
            .as_array()
            .map(|docs| {
                docs.iter()
                    .map(|doc| doc["content"].as_str().unwrap().len())
                    .sum()
            })
            .unwrap_or(0)
    };
    assert!(doc_bytes(&full[0].packet) > doc_bytes(&half[0].packet));
    assert!(doc_bytes(&half[0].packet) <= packet_context::LENS_DOC_TOTAL_BYTES / 2);
    assert!(doc_bytes(&half[0].packet) > 0);
    // Omission is recorded, not silent, and carries no document body.
    let status = &omitted[0].packet["docContext"];
    assert_eq!(status["status"], "omitted-seat-budget");
    assert_eq!(status["included"], 0);
    assert_eq!(status["countedAsCoverage"], false);
    assert!(status["omitted"].as_u64().unwrap() >= 2);
    assert_eq!(
        status["omittedPaths"][0], "docs/referenced-rules.md",
        "ranked order is frozen in the omission record"
    );
    // Source excerpts are identical at every documentation budget, and equal
    // to a repository with no documentation at all.
    let without_docs = lens_doc_work("reasoning.naming", false);
    for requests in [&full, &half, &omitted] {
        assert_eq!(requests[0].packet["excerpts"], full[0].packet["excerpts"]);
        assert_eq!(
            requests[0].packet["excerptCoverage"],
            full[0].packet["excerptCoverage"]
        );
    }
    assert_eq!(
        omitted[0].packet["excerpts"],
        without_docs[0].request.packet["excerpts"]
    );
}

#[test]
fn real_repository_graph_context_stays_frozen_without_crowding_out_raw_lenses() {
    let files = (0..23).map(|index| (
        format!("apps/lightcraft-desktop/web/src/components/Control{index:04}.tsx"),
        format!("export function Control{index}() {{ return <button aria-label=\"Open\">Open</button>; }}\n").repeat(12),
    )).collect::<Vec<_>>();
    let fixture = Fixture::new(
        &files
            .iter()
            .map(|(path, body)| (path.as_str(), body.clone()))
            .collect::<Vec<_>>(),
    );
    let inventory = fixture.inventory();
    // Same shape as real CLI whole-repo context: run-wide unresolved imports
    // plus a large blast-radius graph, repeated in every provider's config.
    let edges = (0..160).map(|index| json!({
        "from":files[index % files.len()].0, "to":files[(index + 1) % files.len()].0,
        "kind":"imports", "confidence":"possible", "source":"lexical",
        "evidence":{"path":files[index % files.len()].0, "startLine":index + 1,
            "endLine":index + 1,"sourceDigest":"e181fcf90fd7e7caea463a0acc4022a0d872c15207d3973f096489c3f8346b97"}
    })).collect::<Vec<_>>();
    let unknowns = (0..102)
        .map(|index| {
            json!({
                "path":files[index % files.len()].0,"cause":"lexical-import-unresolved-or-external"
            })
        })
        .collect::<Vec<_>>();
    let graph = json!({"contractVersion":"legion-graph/1", "blueprintVersion":null,
        "scopedBytesDigest":"7f335cbf499c424016cfdd995697ff00737a0ac4a9d3cdf60838674ffaa1ab25",
        "resolverConfigDigest":"sha256:4008bdd4fd0af2333ef8544a6a7251c7f7f7be78509df12ca3d0fb52b19c9124",
        "coverageFloor":"lexical-js-ts-relative-imports-only", "input":"lexical-fallback",
        "freshness":"artifact-absent", "unknowns":unknowns, "truncated":false,
        "blastRadius":{"certain":[],"inferred":edges,"unknowns":unknowns,
            "truncated":false,"provesDeadCode":false}});
    assert!(graph.to_string().len() > 60_000);
    let mut specs = [
        "reasoning.a11y",
        "reasoning.correctness",
        "reasoning.ai-slop",
        "reasoning.architecture",
    ]
    .map(|id| spec(id, json!({"op":"always"})));
    for provider in &mut specs {
        // 12_000-token seats: the whole-file correctness packet (lens plan
        // with its ten pattern cards and applicability accounting, anchored
        // report schema, semantic contract) sits under this envelope. Packet
        // A13's added correctness cards grew that fixed overhead to ~16.8 KB,
        // past the former 10_500-token envelope (16 KB input limit), so the
        // envelope scales with it. The test is about graph context, not wording.
        provider.reasoning["coverageRequest"] = json!({"mode":"risk-sampled", "runTokenBudget":60_000,
            "seatTokenBudget":12_000, "maxTotalSeats":5});
        provider.reasoning["reviewContext"] = json!({"mode":"whole-repo", "type":"all",
            "changedPaths":[], "snapshotKey":"sha256:frozen-fixture", "graphContext":graph});
    }
    let plan = AuditPlan::compile_with_root(Some(&fixture.0), &inventory, &specs)
        .unwrap()
        .freeze(Some(b"real-context-fixture-key"))
        .unwrap();
    let frozen = serde_json::to_value(plan.plan()).unwrap();
    let work = pending_lens_work(&fixture.0, &plan, &inventory).unwrap();
    let dispatch = ingest::lens_dispatch_plan(
        &work,
        &ingest::DispatchLimits {
            run_token_budget: 60_000,
            seat_token_budget: 12_000,
            max_total_seats: 5,
            wave_width: 1,
        },
    );
    let input_limit = ingest::physical_planning_input_bytes(12_000);
    let output_ceiling = ingest::dispatch_output_tokens(12_000);
    // Capacity cannot change physical grouping: the same frozen packets &
    // per-call allowance determine drafts before run/call scheduling. Use
    // their fully schedulable projection only to recover exact shared-group
    // membership; the actual dispatch above keeps its exact 50k/5-call caps.
    let reference_calls = work.len() as u64 + 1;
    let physical_groups = ingest::lens_dispatch_plan(
        &work,
        &ingest::DispatchLimits {
            run_token_budget: reference_calls * 12_000,
            seat_token_budget: 12_000,
            max_total_seats: reference_calls,
            wave_width: 1,
        },
    );
    let requests = work.iter().map(|item| {
        let sizes = crate::review_runtime::InitialRequestSizer::default().request_sizes(std::slice::from_ref(item)).unwrap();
        json!({"provider":item.provider_id,"packet":item.packet_file_name(),
            "parts":item.request.packet.get("part"),"renderedBytes":sizes.host_envelope_bytes,
            "modelVisibleInputBytes":sizes.model_visible_input_bytes,
            "rawBytes":item.request.packet["excerpts"].as_array().unwrap().iter().map(|row|row["content"].as_str().unwrap().len()).sum::<usize>(),
            "estimatedTokens":crate::next::estimated_request_tokens(sizes.model_visible_input_bytes, ingest::dispatch_output_tokens(12_000))})
    }).collect::<Vec<_>>();
    let diagnostics = json!({"inputByteLimit":input_limit,"requests":requests,
        "dispatch":dispatch,"physicalGroups":physical_groups});
    assert_eq!(dispatch["withinLimits"], true, "{diagnostics}");
    assert_eq!(physical_groups["withinLimits"], true, "{diagnostics}");
    assert_eq!(dispatch["followupReserveCalls"], 1);
    assert_eq!(dispatch["gatherCalls"], 0);
    assert!(dispatch["requiredInitialCalls"].as_u64().unwrap() <= 4);
    let selected = dispatch["selectedPackets"].as_array().unwrap();
    let deferred = dispatch["deferredPackets"].as_array().unwrap();
    assert_eq!(selected.len() + deferred.len(), work.len());
    assert!(selected.iter().all(|packet| !deferred.contains(packet)));
    // Validate actual shared/single author envelopes, never add single-call
    // estimates when dispatch has admitted one shared physical request.
    for seat in dispatch["seats"].as_array().unwrap() {
        let packets = seat["packets"].as_array().unwrap();
        let members = work
            .iter()
            .filter(|item| packets.contains(&json!(item.packet_file_name())))
            .cloned()
            .collect::<Vec<_>>();
        let bytes = crate::review_runtime::initial_seat_request_bytes(&members).unwrap();
        let model_bytes = crate::review_runtime::InitialRequestSizer::default()
            .model_visible_input_bytes(&members)
            .unwrap();
        assert_eq!(seat["plannedRequestBytes"], bytes, "{diagnostics}");
        assert_eq!(seat["plannedModelInputBytes"], model_bytes, "{diagnostics}");
        assert_eq!(seat["modelVisibleInputBytes"], model_bytes, "{diagnostics}");
        assert!(model_bytes <= input_limit, "{diagnostics}");
        let output = seat["outputTokenLimit"].as_u64().unwrap();
        assert!(output >= ingest::minimum_output_tokens(output_ceiling, members.len()));
        assert!(output <= output_ceiling);
        assert_eq!(
            seat["estimatedTokens"],
            crate::next::estimated_request_tokens(
                model_bytes,
                seat["outputTokenLimit"].as_u64().unwrap()
            ),
            "{diagnostics}"
        );
    }
    let ledger = json!({"nativePlan":{"plan":plan.plan()}});
    for item in &work {
        let packet = &item.request.packet;
        let local_graph = &packet["reviewContext"]["graphContext"];
        let reference = &local_graph["projection"]["fullContextRef"];
        let full_graph = ledger
            .pointer(reference["pointer"].as_str().unwrap())
            .unwrap();
        assert_eq!(full_graph, &graph);
        assert_eq!(reference["digest"], canonical_digest(full_graph).unwrap());
        assert_eq!(reference["planDigest"], plan.digest());
        assert!(local_graph.to_string().len() < 5000);
        assert_eq!(local_graph["projection"]["incomplete"], true);
        assert_eq!(local_graph["projection"]["provesDeadCode"], false);
        assert_eq!(local_graph["coverageFloor"], graph["coverageFloor"]);
        assert!(!local_graph["blastRadius"]["inferred"]
            .as_array()
            .unwrap()
            .is_empty());
        let selected_paths = packet["excerpts"]
            .as_array()
            .unwrap()
            .iter()
            .map(|excerpt| &excerpt["path"])
            .collect::<Vec<_>>();
        for edge in local_graph["blastRadius"]["inferred"].as_array().unwrap() {
            assert!(
                selected_paths.contains(&&edge["from"]) || selected_paths.contains(&&edge["to"])
            );
        }
        assert_eq!(packet["excerpts"][0]["mode"], "raw");
        assert!(packet["excerpts"][0]["content"]
            .as_str()
            .unwrap()
            .contains("<button"));
        assert_eq!(packet["excerptCoverage"]["examinedPaths"], json!([]));
    }
    // Compacting hints cannot mutate exact full frozen coverage/graph ledgers.
    assert_eq!(serde_json::to_value(plan.plan()).unwrap(), frozen);
    let a11y = plan
        .providers()
        .iter()
        .find(|provider| provider.id == "reasoning.a11y")
        .unwrap();
    assert!(
        !coverage_plan::FrozenCoverage::from_value(&a11y.configuration["coverage"])
            .unwrap()
            .mandatory_deferred
            .is_empty()
    );
    // Useful priority source work must survive graph compaction under this
    // exact envelope. Four author calls are a capacity, not a promise that
    // every lens's possibly partitioned source can run.
    for provider in ["reasoning.correctness", "reasoning.ai-slop"] {
        assert!(
            work.iter().any(|item| item.provider_id == provider
                && selected.contains(&json!(item.packet_file_name()))
                && item.request.packet["excerpts"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|excerpt| {
                        files.iter().any(|(path, body)| {
                            excerpt["path"] == *path
                                && excerpt["mode"] == "raw"
                                && excerpt["content"] == *body
                                && excerpt["startLine"] == 1
                                && excerpt["endLine"] == 12
                        })
                    })),
            "{diagnostics}"
        );
    }
    let deferred_work = dispatch["deferredWork"].as_array().unwrap();
    let mut minimum_by_provider = BTreeMap::new();
    for item in &work {
        let packet_id = json!(item.packet_file_name());
        let rows = deferred_work
            .iter()
            .filter(|row| row["packet"] == packet_id)
            .collect::<Vec<_>>();
        if selected.contains(&packet_id) {
            assert!(rows.is_empty(), "{diagnostics}");
            continue;
        }
        assert_eq!(rows.len(), 1, "{diagnostics}");
        let row = rows[0];
        assert_eq!(row["providerId"], item.provider_id, "{diagnostics}");
        if let Some(group) = physical_groups["seats"]
            .as_array()
            .unwrap()
            .iter()
            .find(|seat| seat["packets"].as_array().unwrap().contains(&packet_id))
        {
            let packets = group["packets"].as_array().unwrap();
            let members = work
                .iter()
                .filter(|member| packets.contains(&json!(member.packet_file_name())))
                .cloned()
                .collect::<Vec<_>>();
            let bytes = crate::review_runtime::initial_seat_request_bytes(&members).unwrap();
            assert_eq!(group["plannedRequestBytes"], bytes, "{diagnostics}");
            let model_bytes = crate::review_runtime::InitialRequestSizer::default()
                .model_visible_input_bytes(&members)
                .unwrap();
            assert_eq!(row["plannedRequestBytes"], bytes, "{diagnostics}");
            assert_eq!(
                group["plannedModelInputBytes"], model_bytes,
                "{diagnostics}"
            );
            assert_eq!(row["plannedModelInputBytes"], model_bytes, "{diagnostics}");
            assert!(model_bytes <= input_limit, "{diagnostics}");
            // In particular, affordable a11y work can defer only after the
            // four author slots are occupied; it cannot be called unfit.
            assert_eq!(row["reason"], "fresh-verification-reserve", "{diagnostics}");
            assert_eq!(dispatch["requiredInitialCalls"], 4, "{diagnostics}");
            for packet in packets {
                assert!(!selected.contains(packet), "{diagnostics}");
                let rows = deferred_work
                    .iter()
                    .filter(|member| member["packet"] == *packet)
                    .collect::<Vec<_>>();
                assert_eq!(rows.len(), 1, "{diagnostics}");
                assert_eq!(rows[0]["plannedRequestBytes"], bytes, "{diagnostics}");
                assert_eq!(
                    rows[0]["plannedModelInputBytes"], model_bytes,
                    "{diagnostics}"
                );
                assert_eq!(rows[0]["reason"], row["reason"], "{diagnostics}");
            }
        } else {
            // Merging is allowed only when its complete shared request fits.
            // Thus any draft still over budget must be a singleton, whose
            // exact bytes remain unchanged when capacity limits are lifted.
            let reference_rows = physical_groups["deferredWork"]
                .as_array()
                .unwrap()
                .iter()
                .filter(|member| member["packet"] == packet_id)
                .collect::<Vec<_>>();
            assert_eq!(reference_rows.len(), 1, "{diagnostics}");
            assert_eq!(reference_rows[0], row, "{diagnostics}");
            let bytes =
                crate::review_runtime::initial_seat_request_bytes(std::slice::from_ref(item))
                    .unwrap();
            let model_bytes = crate::review_runtime::InitialRequestSizer::default()
                .model_visible_input_bytes(std::slice::from_ref(item))
                .unwrap();
            assert!(model_bytes > input_limit, "{diagnostics}");
            assert_eq!(row["plannedModelInputBytes"], model_bytes, "{diagnostics}");
            assert_eq!(row["reason"], "physical-envelope-headroom", "{diagnostics}");
            assert_eq!(row["plannedRequestBytes"], bytes, "{diagnostics}");
            // An unfit contract must already have reached minimum whole-line
            // materialization. Larger-fit source cannot be deferred early.
            let minimum = minimum_by_provider
                .entry(&item.provider_id)
                .or_insert_with(|| {
                    let provider = plan
                        .providers()
                        .iter()
                        .find(|provider| provider.id == item.provider_id)
                        .unwrap();
                    let denominator = reasoning_denominator(&plan, provider, &inventory).unwrap();
                    let budget = seat_part_budget(provider).unwrap();
                    let source = excerpts::SourceReader::new(&fixture.0).unwrap();
                    build_invocations_with_budget(
                        &plan,
                        provider,
                        &inventory,
                        &denominator,
                        "pending-host",
                        &source,
                        None,
                        Some(excerpts::PartBudget {
                            cap_bytes: 1,
                            ..budget
                        }),
                    )
                    .unwrap()
                    .0
                });
            let minimum = minimum
                .iter()
                .find(|request| request.part() == item.part())
                .unwrap();
            assert_eq!(item.request.packet, minimum.packet, "{diagnostics}");
        }
    }
}

#[test]
fn irreducible_sampled_lens_remains_deferred_while_affordable_lens_runs() {
    let fixture = Fixture::new(&[(
        "src/main.tsx",
        "export function App() { return <button>Open</button>; }\n".into(),
    )]);
    let inventory = fixture.inventory();
    let mut expensive = spec("reasoning.a11y", json!({"op":"always"}));
    expensive.runner["contract"] = json!("irreducible-contract-".repeat(3000));
    let affordable = spec("reasoning.ai-slop", json!({"op":"always"}));
    for mode in ["risk-sampled", "exhaustive"] {
        let mut specs = [expensive.clone(), affordable.clone()];
        for provider in &mut specs {
            provider.reasoning["coverageRequest"] = bounded_request();
            provider.reasoning["coverageRequest"]["mode"] = json!(mode);
        }
        let plan = AuditPlan::compile_with_root(Some(&fixture.0), &inventory, &specs)
            .unwrap()
            .freeze(Some(b"irreducible-lens-fixture-key"))
            .unwrap();
        let result = pending_lens_work(&fixture.0, &plan, &inventory);
        if mode == "exhaustive" {
            assert!(matches!(result, Err(AuditError::BoundExceeded(_))));
            continue;
        }
        let work = result.unwrap();
        assert_eq!(work.len(), 2);
        let dispatch = ingest::lens_dispatch_plan(
            &work,
            &ingest::DispatchLimits {
                run_token_budget: 50_000,
                seat_token_budget: 10_000,
                max_total_seats: 5,
                wave_width: 1,
            },
        );
        assert_eq!(dispatch["withinLimits"], true, "{}", dispatch["violations"]);
        assert_eq!(
            dispatch["selectedPackets"],
            json!(["reasoning.ai-slop.json"])
        );
        assert_eq!(dispatch["deferredPackets"], json!(["reasoning.a11y.json"]));
        assert_eq!(
            dispatch["deferredWork"][0]["reason"],
            "physical-envelope-headroom"
        );
        assert_eq!(dispatch["followupReserveCalls"], 1);
        let deferred = work
            .iter()
            .find(|item| item.provider_id == "reasoning.a11y")
            .unwrap();
        assert_eq!(
            deferred.request.packet["excerptCoverage"]["examinedPaths"],
            json!([])
        );
        assert_eq!(deferred.request.denominator_paths, vec!["src/main.tsx"]);
        assert_eq!(deferred.request.packet["excerpts"][0]["mode"], "raw");
    }
}

#[test]
fn sampled_irreducible_source_defers_with_fitting_candidate_continuation() {
    // Keep raw bytes inside bounded selection, but force JSON escaping past
    // physical input capacity. Non-NUL control bytes remain valid UTF-8 source.
    // Whole lines are indivisible; candidate evidence still fits its own call.
    let fixture = Fixture::new(&[
        (
            "src/main.tsx",
            format!(
                "export function App() {{ return <button>{{/*{}*/}}Open</button>; }}\n",
                "\u{0001}".repeat(12_000)
            ),
        ),
        ("src/small.ts", "export const answer = 42;\n".into()),
    ]);
    let inventory = fixture.inventory();
    let candidates = vec![ScannerCandidate {
        finding_id: "small-a11y-candidate".into(),
        provider: "scanner.a11y".into(),
        domain: "a11y".into(),
        rule: "button-label".into(),
        severity: "medium".into(),
        path: Some("src/main.tsx".into()),
        line: Some(1),
        end_line: None,
        location_status: "known".into(),
        message: "Review button label".into(),
        evidence_excerpt: Some("<button>Open</button>".into()),
        evidence_digest: "small-a11y-evidence".into(),
        source_mapping: json!({"domain":"a11y"}),
    }];
    for mode in ["risk-sampled", "exhaustive"] {
        let mut specs = [
            spec(
                "reasoning.a11y",
                json!({"op":"paths", "paths":["src/main.tsx"]}),
            ),
            spec(
                "reasoning.ai-slop",
                json!({"op":"paths", "paths":["src/small.ts"]}),
            ),
        ];
        for provider in &mut specs {
            provider.reasoning["coverageRequest"] = json!({"mode":mode,
                "runTokenBudget":125_000,"seatTokenBudget":25_000,"maxTotalSeats":5});
        }
        let plan = AuditPlan::compile_with_root(Some(&fixture.0), &inventory, &specs)
            .unwrap()
            .freeze(Some(b"irreducible-candidate-lens-fixture-key"))
            .unwrap();
        for (provider_id, path) in [
            ("reasoning.a11y", "src/main.tsx"),
            ("reasoning.ai-slop", "src/small.ts"),
        ] {
            let provider = plan
                .providers()
                .iter()
                .find(|provider| provider.id == provider_id)
                .unwrap();
            assert!(
                provider.configuration["coverage"]["reviewSet"]
                    .as_array()
                    .unwrap()
                    .contains(&json!(path)),
                "source must be selected before physical refinement"
            );
        }
        let result =
            pending_lens_work_with_candidates(&fixture.0, &plan, &inventory, Some(&candidates));
        if mode == "exhaustive" {
            assert!(matches!(result, Err(AuditError::BoundExceeded(_))));
            continue;
        }
        let work = result.unwrap();
        assert_eq!(work.len(), 3);
        let source = work
            .iter()
            .find(|item| {
                item.provider_id == "reasoning.a11y"
                    && !candidate_routing::is_candidate_part(&item.request)
            })
            .unwrap();
        let candidate = work
            .iter()
            .find(|item| candidate_routing::is_candidate_part(&item.request))
            .unwrap();
        let affordable = work
            .iter()
            .find(|item| item.provider_id == "reasoning.ai-slop")
            .unwrap();
        assert!(
            source.request.packet["excerpts"][0]["content"]
                .as_str()
                .unwrap()
                .contains('\u{0001}'),
            "escaped source must survive materialization"
        );
        assert_eq!(
            source.request.packet["excerptCoverage"]["omittedPaths"],
            json!([])
        );
        assert_eq!(source.request.packet["candidateContext"], json!([]));
        assert_eq!(
            candidate.request.packet["candidateContext"],
            json!(candidates)
        );
        assert_eq!(
            candidate.request.packet["excerptCoverage"]["examinedPaths"],
            json!([])
        );
        let provider = plan
            .providers()
            .iter()
            .find(|provider| provider.id == "reasoning.a11y")
            .unwrap();
        let mut sizer = crate::review_runtime::InitialRequestSizer::default();
        assert_eq!(
            measure_invocations(std::slice::from_ref(&source.request), provider, &mut sizer)
                .unwrap(),
            u64::MAX
        );
        assert_ne!(
            measure_invocations(
                std::slice::from_ref(&candidate.request),
                provider,
                &mut sizer
            )
            .unwrap(),
            u64::MAX
        );
        let dispatch = ingest::lens_dispatch_plan(
            &work,
            &ingest::DispatchLimits {
                run_token_budget: 125_000,
                seat_token_budget: 25_000,
                max_total_seats: 5,
                wave_width: 1,
            },
        );
        assert_eq!(dispatch["withinLimits"], true, "{dispatch}");
        let selected = dispatch["selectedPackets"].as_array().unwrap();
        assert_eq!(selected.len(), 2, "{dispatch}");
        assert!(
            selected.contains(&json!(affordable.packet_file_name())),
            "{dispatch}"
        );
        assert!(
            selected.contains(&json!(candidate.packet_file_name())),
            "{dispatch}"
        );
        assert_eq!(
            dispatch["deferredPackets"],
            json!([source.packet_file_name()])
        );
        assert_eq!(
            dispatch["deferredWork"][0]["reason"],
            "physical-envelope-headroom"
        );
        assert_eq!(dispatch["followupReserveCalls"], 1);
    }
}

fn candidate_partition_fixture() -> (
    Fixture,
    InventoryEnvelope,
    FrozenPlan,
    Vec<ScannerCandidate>,
) {
    let paths = (0..169)
        .map(|index| format!("src/schema/record-{index:03}.rs"))
        .collect::<Vec<_>>();
    let files = paths
        .iter()
        .enumerate()
        .map(|(index, path)| {
            (
                path.as_str(),
                format!("pub fn persist_transaction_{index}() {{ /* write data */ }}\n"),
            )
        })
        .collect::<Vec<_>>();
    let fixture = Fixture::new(&files);
    let inventory = fixture.inventory();
    let mut provider = spec("reasoning.data-safety", json!({"op":"always"}));
    provider.reasoning["coverageRequest"] = json!({"mode":"risk-sampled",
        "runTokenBudget":12_000_000,"seatTokenBudget":150_000,"maxTotalSeats":80});
    let plan = AuditPlan::compile_with_root(Some(&fixture.0), &inventory, &[provider])
        .unwrap()
        .freeze(Some(b"candidate-partition-regression-key"))
        .unwrap();
    let candidates = (0..1320)
        .map(|index| {
            let mapping = json!({"originalAdapter":"mixed-data-scanner","domain":"data",
            "rawEvidence":{"message":"full original evidence ".repeat(45),"ordinal":index}});
            ScannerCandidate {
                finding_id: format!("candidate-{index:04}"),
                provider: "scanner.data".into(),
                domain: "data".into(),
                rule: "transaction-safety".into(),
                severity: "medium".into(),
                path: if index < 167 {
                    Some(paths[index].clone())
                } else if index % 2 == 0 {
                    Some(format!("outside/record-{index}.sql"))
                } else {
                    None
                },
                line: (index % 2 == 0).then_some(1),
                end_line: None,
                location_status: if index < 167 { "known" } else { "unknown" }.into(),
                message: format!("scanner record {index} requires data lens review"),
                evidence_excerpt: Some("original full scanner evidence ".repeat(40)),
                evidence_digest: canonical_digest(&mapping).unwrap(),
                source_mapping: mapping,
            }
        })
        .collect();
    (fixture, inventory, plan, candidates)
}

#[test]
fn full_candidate_context_partitions_losslessly_without_source_credit_or_reordering() {
    let (fixture, inventory, plan, candidates) = candidate_partition_fixture();
    let provider = &plan.providers()[0];
    let denominator = reasoning_denominator(&plan, provider, &inventory).unwrap();
    let source = excerpts::SourceReader::new(&fixture.0).unwrap();
    let (original, _) = build_invocations_with_budget(
        &plan,
        provider,
        &inventory,
        &denominator,
        "pending-host",
        &source,
        Some(&candidates),
        seat_part_budget(provider),
    )
    .unwrap();
    let work = pending_lens_work_with_candidates(&fixture.0, &plan, &inventory, Some(&candidates))
        .unwrap();
    assert_eq!(
        candidates
            .iter()
            .filter(|candidate| candidate
                .path
                .as_ref()
                .is_none_or(|path| !denominator.entries.iter().any(|entry| &entry.path == path)))
            .count(),
        1153
    );
    let source_parts = work
        .iter()
        .filter(|item| !candidate_routing::is_candidate_part(&item.request))
        .collect::<Vec<_>>();
    assert_eq!(source_parts.len(), original.len());
    for (actual, before) in source_parts.iter().zip(&original) {
        assert_eq!(actual.request.packet["excerpts"], before.packet["excerpts"]);
        assert_eq!(
            actual.request.packet["excerptCoverage"],
            before.packet["excerptCoverage"]
        );
        assert_eq!(actual.request.packet["candidateContext"], json!([]));
    }
    let mut reconstructed = Vec::new();
    let mut identities = BTreeSet::new();
    let mut sizer = crate::review_runtime::InitialRequestSizer::default();
    for item in &work {
        let sizes = sizer.request_sizes(std::slice::from_ref(item)).unwrap();
        assert!(sizes.host_envelope_bytes <= crate::review_runtime::MAX_REQUEST_BYTES as u64);
        let floor = ingest::minimum_output_tokens(ingest::dispatch_output_tokens(150_000), 1)
            .max(candidate_routing::disposition_output_tokens(&item.request));
        assert!(ingest::fitting_output_tokens(
            150_000,
            ingest::dispatch_output_tokens(150_000),
            sizes.model_visible_input_bytes,
            floor
        )
        .is_some());
        assert_eq!(
            item.request.denominator_paths,
            original[0].denominator_paths
        );
        assert_eq!(
            item.request.denominator_digest,
            original[0].denominator_digest
        );
        assert_eq!(
            item.request.request_id,
            ingest::expected_request_id(item).unwrap()
        );
        if candidate_routing::is_candidate_part(&item.request) {
            assert!(delivery_chunk_manifest(&item.request).unwrap().is_empty());
            assert_eq!(
                item.request.packet["excerptCoverage"]["examinedPaths"],
                json!([])
            );
        }
        for candidate in serde_json::from_value::<Vec<ScannerCandidate>>(
            item.request.packet["candidateContext"].clone(),
        )
        .unwrap()
        {
            assert!(identities.insert((candidate.provider.clone(), candidate.finding_id.clone())));
            reconstructed.push(candidate);
        }
    }
    assert_eq!(reconstructed, candidates);
    assert!(work
        .iter()
        .any(|item| candidate_routing::is_candidate_part(&item.request)));
    let limits = ingest::DispatchLimits {
        run_token_budget: 12_000_000,
        seat_token_budget: 150_000,
        max_total_seats: 80,
        wave_width: 1,
    };
    let dispatch = ingest::lens_dispatch_plan(&work, &limits);
    assert_eq!(dispatch["withinLimits"], true, "{dispatch}");
    assert_eq!(
        dispatch["selectedPackets"].as_array().unwrap().len(),
        work.len()
    );
    for limited in [
        ingest::DispatchLimits {
            max_total_seats: 1,
            ..limits
        },
        ingest::DispatchLimits {
            run_token_budget: 150_000,
            ..limits
        },
    ] {
        let dispatch = ingest::lens_dispatch_plan(&work, &limited);
        assert_eq!(dispatch["withinLimits"], false);
        assert_eq!(
            dispatch["selectedPackets"].as_array().unwrap().len()
                + dispatch["deferredWork"].as_array().unwrap().len(),
            work.len()
        );
    }
}

#[test]
fn candidate_partition_refuses_indivisible_records_duplicates_and_part_exhaustion() {
    let (fixture, inventory, plan, mut candidates) = candidate_partition_fixture();
    let provider = &plan.providers()[0];
    let denominator = reasoning_denominator(&plan, provider, &inventory).unwrap();
    let source = excerpts::SourceReader::new(&fixture.0).unwrap();
    let mut sizer = crate::review_runtime::InitialRequestSizer::default();
    let mut capped = provider.clone();
    capped.bounds.insert("maxReasoningParts".into(), json!(1));
    let error = build_invocations(
        &plan,
        &capped,
        &inventory,
        &denominator,
        "pending-host",
        &source,
        &mut sizer,
        Some(&candidates),
        true,
    )
    .unwrap_err();
    assert!(matches!(error, AuditError::BoundExceeded(_)));
    assert!(error.to_string().contains("maxReasoningParts"));
    candidates.truncate(1);
    candidates[0].evidence_excerpt = Some("indivisible-secret-test-marker ".repeat(100_000));
    let error = pending_lens_work_with_candidates(&fixture.0, &plan, &inventory, Some(&candidates))
        .unwrap_err();
    assert!(matches!(error, AuditError::BoundExceeded(_)));
    assert!(error.to_string().contains("scanner.data:candidate-0000"));
    assert!(!error.to_string().contains("indivisible-secret-test-marker"));
    candidates.push(candidates[0].clone());
    candidates[1].domain = "security".into();
    let error = pending_lens_work_with_candidates(&fixture.0, &plan, &inventory, Some(&candidates))
        .unwrap_err();
    assert!(error
        .to_string()
        .contains("duplicate routed candidate identity"));
}

#[test]
fn fitting_candidate_context_keeps_original_inline_ownership_and_packet_identity() {
    let (fixture, inventory, plan, mut candidates) = candidate_partition_fixture();
    candidates.truncate(3);
    let provider = &plan.providers()[0];
    let denominator = reasoning_denominator(&plan, provider, &inventory).unwrap();
    let source = excerpts::SourceReader::new(&fixture.0).unwrap();
    let (original, _) = build_invocations_with_budget(
        &plan,
        provider,
        &inventory,
        &denominator,
        "pending-host",
        &source,
        Some(&candidates),
        seat_part_budget(provider),
    )
    .unwrap();
    let work = pending_lens_work_with_candidates(&fixture.0, &plan, &inventory, Some(&candidates))
        .unwrap();
    assert_eq!(
        work.iter().map(|item| &item.request).collect::<Vec<_>>(),
        original.iter().collect::<Vec<_>>()
    );
    assert!(!work
        .iter()
        .any(|item| candidate_routing::is_candidate_part(&item.request)));
}

#[test]
fn ordinary_source_overflow_refines_full_context_before_detaching_candidates() {
    // Each file fits bounded selection; JSON escaping makes combined source
    // exceed physical capacity while whole-line refinement can still fit.
    let paths = (0..4)
        .map(|index| format!("src/schema/transaction-{index}.rs"))
        .collect::<Vec<_>>();
    let files = paths
        .iter()
        .enumerate()
        .map(|(index, path)| {
            (
                path.as_str(),
                format!(
                    "pub fn transaction_{index}() {{ /*{}*/ }}\n",
                    "\u{0001}".repeat(500)
                )
                .repeat(6),
            )
        })
        .collect::<Vec<_>>();
    let fixture = Fixture::new(&files);
    let inventory = fixture.inventory();
    let mut provider = spec("reasoning.data-safety", json!({"op":"always"}));
    provider.reasoning["coverageRequest"] = json!({"mode":"risk-sampled",
        "runTokenBudget":12_000_000,"seatTokenBudget":25_000,"maxTotalSeats":80});
    let plan = AuditPlan::compile_with_root(Some(&fixture.0), &inventory, &[provider])
        .unwrap()
        .freeze(Some(b"inline-source-refinement-key"))
        .unwrap();
    let candidates = vec![ScannerCandidate {
        provider: "scanner.data".into(),
        finding_id: "small-context".into(),
        domain: "data".into(),
        evidence_digest: "small-evidence".into(),
        path: Some(paths[0].clone()),
        line: Some(1),
        ..Default::default()
    }];
    let provider = &plan.providers()[0];
    assert_eq!(
        provider.configuration["coverage"]["reviewSet"],
        json!(paths),
        "all source must be selected before physical refinement"
    );
    let denominator = reasoning_denominator(&plan, provider, &inventory).unwrap();
    let source = excerpts::SourceReader::new(&fixture.0).unwrap();
    let mut sizer = crate::review_runtime::InitialRequestSizer::default();
    let (initial, _) = build_invocations_with_budget(
        &plan,
        provider,
        &inventory,
        &denominator,
        "pending-host",
        &source,
        Some(&candidates),
        seat_part_budget(provider),
    )
    .unwrap();
    assert!(
        measure_invocations(&initial, provider, &mut sizer).unwrap()
            > ingest::physical_planning_input_bytes(25_000)
    );
    let work = pending_lens_work_with_candidates(&fixture.0, &plan, &inventory, Some(&candidates))
        .unwrap();
    assert!(!work
        .iter()
        .any(|item| candidate_routing::is_candidate_part(&item.request)));
    assert_eq!(
        work.iter()
            .flat_map(|item| item.request.packet["candidateContext"].as_array().unwrap())
            .count(),
        1
    );
    for item in &work {
        assert!(
            measure_invocations(std::slice::from_ref(&item.request), provider, &mut sizer).unwrap()
                <= ingest::physical_planning_input_bytes(25_000)
        );
    }
}
