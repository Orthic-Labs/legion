//! A13 acceptance coverage for platform, security & production pattern cards.
//! Authored by the packet worker, never run by it: root integration executes.
//! Requires no new exports: `native_providers::reasoning::pattern_cards` is
//! already public. These tests verify card shape, routing and the authored
//! fixture catalog only; they are not behavioral qualification.

use legion_audit::native_providers::reasoning::pattern_cards::{
    bind_domain_contract, bind_packet_cards_to_paths, cards_for_lens, packet_cards_for_lens,
    RuleMaturity, PATTERN_CARDS,
};
use serde_json::{json, Value};
use std::{collections::BTreeSet, fs, path::Path};

fn repo_path(relative: &str) -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .join(relative)
}

fn catalog() -> Value {
    let text = fs::read_to_string(repo_path("skills/audit/evals/patterns/cases.json"))
        .expect("pattern case catalog");
    serde_json::from_str(&text).expect("valid case catalog json")
}

#[test]
fn every_card_has_a_broken_valid_and_unknown_case_with_matching_text() {
    let catalog = catalog();
    let entries = catalog["cases"].as_array().unwrap();
    for card in PATTERN_CARDS {
        let entry = entries
            .iter()
            .find(|entry| entry["card"] == card.id)
            .unwrap_or_else(|| panic!("no cases for {}", card.id));
        assert_eq!(entry["owner_lens"], card.owner_lens, "{}", card.id);
        let cases = entry["cases"].as_array().unwrap();
        let expected = cases
            .iter()
            .map(|case| case["expected"].as_str().unwrap())
            .collect::<BTreeSet<_>>();
        assert_eq!(
            expected,
            BTreeSet::from(["finding", "no-finding", "unknown"]),
            "{}",
            card.id
        );
        for case in cases {
            assert!(!case["scenario"].as_str().unwrap().is_empty());
        }
    }
    let ids = entries
        .iter()
        .map(|entry| entry["card"].as_str().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(ids.len(), ids.iter().collect::<BTreeSet<_>>().len());
    for id in &ids {
        assert!(PATTERN_CARDS.iter().any(|card| card.id == *id), "{id}");
    }
}

#[test]
fn authored_catalog_is_not_presented_as_measured_qualification() {
    let catalog = catalog();
    assert_eq!(
        catalog["qualification"],
        "authored-fixtures-not-yet-benchmarked"
    );
    let text = serde_json::to_string(&catalog).unwrap();
    assert!(!text.contains("\"qualified\""));
    assert!(!text.contains("recall"));
    assert!(!text.contains("precision"));
}

#[test]
fn reference_document_lists_every_card_and_the_deliberate_absences() {
    let document = fs::read_to_string(repo_path("skills/audit/references/pattern-cards.md"))
        .expect("pattern card reference");
    for card in PATTERN_CARDS {
        assert!(
            document.contains(&format!("`{}`", card.id)),
            "reference omits {}",
            card.id
        );
    }
    for phrase in [
        "draft",
        "shadow",
        "qualified",
        "untrusted evidence",
        "certificate-pinning",
        "down-migration",
        "dependency-injection-seam",
    ] {
        assert!(
            document.to_ascii_lowercase().contains(phrase),
            "reference omits {phrase}"
        );
    }
}

#[test]
fn unavailable_context_is_unknown_never_clean_or_confirmed() {
    for card in PATTERN_CARDS {
        let lowered = card.no_evidence.to_ascii_lowercase();
        assert!(lowered.contains("unknown"), "{}", card.id);
        assert!(!lowered.contains("clean"), "{}", card.id);
        assert!(!lowered.contains("confirmed"), "{}", card.id);
    }
    // Empty or unrecognized selection leaves restricted cards unknown.
    for paths in [vec![], vec!["config/app.yaml".to_owned()]] {
        let mut plan = json!({"lens": "security"});
        bind_packet_cards_to_paths(&mut plan, &paths);
        let rows = plan["patternCardApplicability"]["cards"]
            .as_array()
            .unwrap();
        for card in cards_for_lens("security").filter(|card| card.language_applicability.is_some())
        {
            let row = rows.iter().find(|row| row["id"] == card.id).unwrap();
            assert_eq!(row["state"], "unknown", "{}", card.id);
        }
        assert_eq!(
            plan["patternCards"].as_array().unwrap().len(),
            cards_for_lens("security").count()
        );
    }
}

#[test]
fn routing_does_not_promote_maturity_or_add_benchmark_fields() {
    for card in PATTERN_CARDS {
        assert_eq!(card.maturity, RuleMaturity::Draft, "{}", card.id);
    }
    for lens in [
        "correctness",
        "security",
        "data-safety",
        "performance",
        "resilience",
    ] {
        let mut plan = json!({"lens": lens});
        bind_packet_cards_to_paths(&mut plan, &["src/lib.rs".to_owned()]);
        for card in plan["patternCards"].as_array().unwrap() {
            assert_eq!(card["ruleMaturity"], "draft");
            assert!(card.get("benchmark").is_none());
            assert!(card.get("qualification").is_none());
        }
    }
}

#[test]
fn platform_cards_route_by_language_and_changed_surface() {
    let mut swift = json!({"lens": "correctness"});
    bind_packet_cards_to_paths(&mut swift, &["App/Store.swift".to_owned()]);
    let swift_ids = swift["patternCards"]
        .as_array()
        .unwrap()
        .iter()
        .map(|card| card["id"].as_str().unwrap().to_owned())
        .collect::<BTreeSet<_>>();
    assert!(swift_ids.contains("swift-actor-reentrancy-stale-state"));
    assert!(!swift_ids.contains("kotlin-cancellation-swallowed"));
    assert!(!swift_ids.contains("qwik-resumability-closure-capture"));

    let mut tauri = json!({"lens": "security"});
    bind_packet_cards_to_paths(&mut tauri, &["src-tauri/tauri.conf.json".to_owned()]);
    let tauri_ids = tauri["patternCards"]
        .as_array()
        .unwrap()
        .iter()
        .map(|card| card["id"].as_str().unwrap().to_owned())
        .collect::<BTreeSet<_>>();
    assert!(tauri_ids.contains("tauri-capability-scope-breadth"));
    assert!(tauri_ids.contains("tauri-deeplink-and-update-trust"));
}

#[test]
fn no_rule_requires_findings_quotas_or_deliberately_excluded_families() {
    for card in PATTERN_CARDS {
        for forbidden in [
            "pinning",
            "down-migration",
            "di-seam",
            "dependency-injection",
        ] {
            assert!(!card.id.contains(forbidden), "{}", card.id);
        }
        for text in [
            card.trigger_evidence,
            card.required_source_trace,
            card.falsifier,
            card.no_evidence,
        ] {
            let lowered = text.to_ascii_lowercase();
            assert!(!lowered.contains("quota"), "{}", card.id);
            assert!(!lowered.contains("consensus"), "{}", card.id);
        }
    }
    // Card text is serialized for existing lenses only.
    for lens in ["architecture", "naming", "dead-file"] {
        for card in packet_cards_for_lens(lens) {
            assert_eq!(card["ownerLens"], lens);
        }
    }
}

#[test]
fn decomposition_card_requires_responsibilities_state_callers_and_behavior() {
    let card = PATTERN_CARDS
        .iter()
        .find(|card| card.id == "component-decomposition-recommendation-contract")
        .unwrap();
    assert_eq!(card.owner_lens, "architecture");
    let trace = card.required_source_trace.to_ascii_lowercase();
    for needle in ["responsibilit", "state", "callers", "behavior"] {
        assert!(trace.contains(needle), "{needle}");
    }
    assert!(card.falsifier.to_ascii_lowercase().contains("size"));
}

#[test]
fn domain_contract_binding_carries_digest_and_absence_is_explicit() {
    let mut plan = json!({"lens": "data-safety"});
    bind_domain_contract(&mut plan, None, None);
    assert_eq!(plan["domainContract"]["status"], "absent");
    assert_eq!(plan["domainContract"]["executionAuthority"], false);
    let evaluation = json!({"setDigest": "sha256:set", "candidates": []});
    bind_domain_contract(&mut plan, Some(&evaluation), Some("sha256:scoped"));
    assert_eq!(plan["domainContract"]["status"], "bound");
    assert_eq!(
        plan["domainContract"]["domainContractDigest"],
        "sha256:scoped"
    );
    assert_eq!(plan["domainContract"]["evaluation"], evaluation);
    assert_eq!(plan["domainContract"]["executionAuthority"], false);
}

// Totals after the evidence-selected security card groups (issue #114):
// 39 prior cards + 9 new security cards (SSRF/egress, HTTP proxy/cache,
// auth-session state machine, workspace trust, AI memory/RAG, admin workflow,
// smart contracts, embedded/IoT, ICS/OT) = 48. The security lens owns 18: nine
// always-on core cards and nine evidence-selected group cards.
const EXPECTED_TOTAL_CARDS: usize = 48;
const EXPECTED_SECURITY_CARDS: usize = 18;
const EXPECTED_SECURITY_GROUPED_CARDS: usize = 9;

#[test]
fn card_totals_match_the_documented_security_group_expansion() {
    assert_eq!(PATTERN_CARDS.len(), EXPECTED_TOTAL_CARDS);
    assert_eq!(cards_for_lens("security").count(), EXPECTED_SECURITY_CARDS);
    let grouped = cards_for_lens("security")
        .filter(|card| card.domain_evidence.is_some())
        .count();
    assert_eq!(grouped, EXPECTED_SECURITY_GROUPED_CARDS);
    for card in cards_for_lens("security").filter(|card| card.domain_evidence.is_some()) {
        assert_eq!(card.maturity, RuleMaturity::Draft, "{}", card.id);
    }
}

#[test]
fn specialist_groups_need_strong_evidence_and_unknown_never_excludes() {
    let specialists = [
        "smart-contract-reentrancy-access-oracle",
        "embedded-firmware-update-debug-keys",
        "ics-ot-unauthenticated-control-safety",
    ];
    let state = |plan: &Value, id: &str| -> String {
        plan["patternCardApplicability"]["cards"]
            .as_array()
            .unwrap()
            .iter()
            .find(|row| row["id"] == id)
            .unwrap()["state"]
            .as_str()
            .unwrap()
            .to_owned()
    };
    for (paths, expected) in [
        (vec!["src/lib.rs"], "excluded"),
        (vec!["src/lib.rs", "Cargo.toml"], "unknown"),
        (vec![], "unknown"),
        (vec!["config/app.yaml"], "unknown"),
    ] {
        let mut plan = json!({"lens": "security"});
        let owned = paths.iter().map(|p| (*p).to_owned()).collect::<Vec<_>>();
        bind_packet_cards_to_paths(&mut plan, &owned);
        for id in specialists {
            assert_eq!(state(&plan, id), expected, "{paths:?} {id}");
        }
        // Common groups are never excluded by missing path evidence.
        for card in cards_for_lens("security")
            .filter(|card| card.domain_evidence.is_some() && !specialists.contains(&card.id))
        {
            assert_ne!(state(&plan, card.id), "excluded", "{paths:?} {}", card.id);
        }
    }
}

#[test]
fn security_lens_registry_is_truthful_and_has_no_dead_module_paths() {
    let text = fs::read_to_string(repo_path("src/registry/security-lenses.json")).unwrap();
    assert!(!text.contains(".mjs"), "dead module path remains");
    let registry: Value = serde_json::from_str(&text).unwrap();
    let providers: Value = serde_json::from_str(
        &fs::read_to_string(repo_path("src/registry/providers.json")).unwrap(),
    )
    .unwrap();
    let provider_ids = providers["providers"]
        .as_array()
        .unwrap()
        .iter()
        .map(|provider| provider["id"].as_str().unwrap().to_owned())
        .collect::<BTreeSet<_>>();
    let mut ids = BTreeSet::new();
    for lens in registry["lenses"].as_array().unwrap() {
        let id = lens["id"].as_str().unwrap();
        assert!(ids.insert(id), "duplicate lens {id}");
        assert!(lens.get("module").is_none(), "{id} keeps a module path");
        assert_eq!(lens["cleanClaim"], "none", "{id}");
        assert_eq!(lens["mayCloseOwnCandidates"], false, "{id}");
        let providers_backing = lens["backedBy"]["providers"].as_array().unwrap();
        let cards_backing = lens["backedBy"]["patternCards"].as_array().unwrap();
        for provider in providers_backing {
            assert!(
                provider_ids.contains(provider.as_str().unwrap()),
                "{id} names unregistered provider {provider}"
            );
        }
        for card in cards_backing {
            assert!(
                PATTERN_CARDS
                    .iter()
                    .any(|candidate| candidate.id == card.as_str().unwrap()),
                "{id} names missing card {card}"
            );
        }
        match lens["implementationState"].as_str().unwrap() {
            "native-provider" | "partial-native-provider" => {
                assert!(!providers_backing.is_empty(), "{id}")
            }
            "card-only" => {
                assert!(providers_backing.is_empty(), "{id}");
                assert!(!cards_backing.is_empty(), "{id}");
            }
            "not-implemented" => {
                assert!(
                    providers_backing.is_empty() && cards_backing.is_empty(),
                    "{id}"
                );
                assert_eq!(lens["producesSecurityCandidates"], false, "{id}");
            }
            other => panic!("{id} has unknown state {other}"),
        }
        if lens["producesSecurityCandidates"] == true {
            assert!(!providers_backing.is_empty(), "{id}");
        }
    }
    // The catalogue lists every lens id and no dead module path.
    let catalog = fs::read_to_string(repo_path(
        "skills/audit/references/security-lens-catalog.md",
    ))
    .unwrap();
    assert!(!catalog.contains(".mjs"));
    for id in &ids {
        assert!(catalog.contains(&format!("`{id}`")), "catalogue omits {id}");
    }
}

#[test]
fn security_checklist_uses_audit_cues_not_remediation_prompts() {
    let checklist = fs::read_to_string(repo_path("skills/audit/references/security-checklist.md"))
        .unwrap()
        .to_ascii_lowercase();
    for phrase in [
        "tell me which",
        "give me a list",
        "walk me through",
        "describe the design you implemented",
        "my app",
        "summarize what you found and changed",
    ] {
        assert!(!checklist.contains(phrase), "prescriptive phrase: {phrase}");
    }
    assert!(checklist.matches("audit cue:").count() >= 100);
    assert!(checklist.contains("never a clean result"));
}
