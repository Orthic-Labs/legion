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
    let review = sampled_review(
        &fixture.0,
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
    assert_eq!(
        plan["reasoning.a11y"]["reviewSet"]
            .as_array()
            .unwrap()
            .len(),
        paths.len()
    );
    assert!(
        plan["reasoning.security"]["reviewSet"]
            .as_array()
            .unwrap()
            .len()
            < paths.len()
    );
    assert!(
        plan["reasoning.security"]["declaredUnsampled"]
            .as_u64()
            .unwrap()
            > 0
    );
    assert_eq!(plan["reasoning.security"]["strata"][0]["n"], 0);
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
    let target = (25_000 - ingest::dispatch_output_tokens(25_000)) * 4;
    let mut homes = Vec::new();
    for item in &work {
        assert!(
            crate::review_runtime::initial_seat_request_bytes(std::slice::from_ref(item)).unwrap()
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
fn tiny_run_refuses_large_mandatory_source_before_packet_materialization() {
    let paths = vec!["src/auth.rs".to_owned()];
    let facts = BTreeMap::from([(
        paths[0].clone(),
        coverage_plan::FileFacts {
            size: 10_000_000,
            signal: Some("security-sensitive"),
            ..Default::default()
        },
    )]);
    let error = coverage_plan::plan_coverage(
        &json!({}),
        &facts,
        &[coverage_plan::LensInput {
            provider_id: "reasoning.security".into(),
            paths,
        }],
        &coverage_plan::CoverageRequest {
            mode: coverage_plan::CoverageMode::RiskSampled,
            run_token_budget: 50_000,
            seat_token_budget: 10_000,
            max_total_seats: 5,
        },
    )
    .unwrap_err()
    .to_string();
    assert!(error.contains("mandatory coverage alone"), "{error}");
    assert!(error.contains("mandatory coverage was not reduced"));
    assert!(error.len() < 800);
}

#[test]
fn sampled_remainder_target_never_overrides_tiny_run_budget() {
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
    assert!(count > 0 && count < coverage_plan::SAMPLE_FLOOR);
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
fn tiny_call_cap_refuses_before_large_bundle_fanout() {
    let paths = vec!["src/ordinary.rs".to_owned()];
    let facts = BTreeMap::from([(
        paths[0].clone(),
        coverage_plan::FileFacts {
            size: 10_000_000,
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
    let error = coverage_plan::plan_coverage(
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
    .unwrap_err()
    .to_string();
    assert!(error.contains("cheap gathering calls"));
    assert!(error.contains("maxTotalSeats is 5"));
    assert!(error.len() < 800);
}
